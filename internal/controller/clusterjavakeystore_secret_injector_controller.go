/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

// ClusterJavaKeystoreSecretInjectorReconciler is the symmetric counterpart to the
// ConfigMap injector: it propagates the keystore password from the system Secret
// (`<crName>-jks-password` in `Spec.SystemNamespace`) into every Secret cluster-wide
// labeled `jks.kemo.dev/clusterkeystore=<crName>`. Idempotency is by direct byte
// comparison on `Data["password"]`; passwords are byte-stable so no fingerprint
// annotation is required.
type ClusterJavaKeystoreSecretInjectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *ClusterJavaKeystoreSecretInjectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	secretInjectorLog.Info("Reconciling labeled Secret", "NamespacedName", req.NamespacedName)

	target := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, target); err != nil {
		if kapierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	crName := target.Labels[DefaultClusterJavaKeystoreLabel]

	// Cleanup-on-unlabel: previously injected, now unlabeled. Remove only the keys we wrote.
	if crName == "" {
		if target.Annotations[DefaultOwningComponentAnnotationKey] == CJKS_CR_Name &&
			target.Annotations[DefaultOwningInstanceAnnotationKey] != "" {
			return r.cleanupUnlabeled(ctx, target)
		}
		return ctrl.Result{}, nil
	}

	cr := &jksv1alpha1.ClusterJavaKeystore{}
	if err := r.Get(ctx, types.NamespacedName{Name: crName}, cr); err != nil {
		if kapierrors.IsNotFound(err) {
			secretInjectorLog.Info("Referenced ClusterJavaKeystore not found; leaving labeled Secret untouched",
				"ClusterJavaKeystoreName", crName, "SecretName", target.Name, "SecretNamespace", target.Namespace)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if cr.Spec.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(cr.Spec.NamespaceSelector)
		if err != nil {
			secretInjectorLog.Error(err, "Invalid NamespaceSelector on ClusterJavaKeystore", "ClusterJavaKeystoreName", crName)
			return ctrl.Result{}, err
		}
		ns := &corev1.Namespace{}
		if err := r.Get(ctx, types.NamespacedName{Name: target.Namespace}, ns); err != nil {
			return ctrl.Result{RequeueAfter: time.Second * 30}, err
		}
		if !sel.Matches(labels.Set(ns.Labels)) {
			secretInjectorLog.Info("Skipping labeled Secret whose namespace does not match the ClusterJavaKeystore NamespaceSelector",
				"ClusterJavaKeystoreName", crName, "SecretName", target.Name, "SecretNamespace", target.Namespace)
			return ctrl.Result{}, nil
		}
	}

	// Resolve the system Secret name + data key from the CR spec — TargetSecret
	// overrides may have customized either. The same key flows into labeled targets so
	// consumers see one consistent key end-to-end.
	sourceName, sourceKey := resolveClusterTargetSecret(cr)

	// Read the password from the system Secret. The CR controller is responsible for
	// keeping that Secret correct; we copy bytes from it rather than rederiving anything.
	systemSecret := &corev1.Secret{}
	systemSecretName := types.NamespacedName{
		Name:      sourceName,
		Namespace: cr.Spec.SystemNamespace,
	}
	if systemSecretName.Namespace == "" {
		systemSecretName.Namespace = DefaultOperatorNamespace
	}
	if err := r.Get(ctx, systemSecretName, systemSecret); err != nil {
		if kapierrors.IsNotFound(err) {
			secretInjectorLog.Info("System Secret not yet present; will be requeued via watch when ready",
				"ClusterJavaKeystoreName", crName, "SystemSecret", systemSecretName.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	wantPassword := systemSecret.Data[sourceKey]
	if len(wantPassword) == 0 {
		secretInjectorLog.Info("System Secret password key empty; awaiting CR controller",
			"ClusterJavaKeystoreName", crName, "SystemSecret", systemSecretName.String(), "DataKey", sourceKey)
		return ctrl.Result{}, nil
	}

	// If the configured data key changed since last injection (e.g. user updated
	// Spec.TargetSecret.Key), strip the previously injected key so we don't leave stale
	// password bytes under the old name.
	previousKey := target.Annotations[DefaultInjectedDataKeyAnnotation]
	if previousKey != "" && previousKey != sourceKey {
		delete(target.Data, previousKey)
	}

	if existing, ok := target.Data[sourceKey]; ok &&
		bytes.Equal(existing, wantPassword) &&
		hasOwnershipAnnotations(target, CJKS_CR_Name, crName) &&
		target.Annotations[DefaultInjectedDataKeyAnnotation] == sourceKey {
		secretInjectorLog.Info("Labeled Secret already up to date, skipping",
			"ClusterJavaKeystoreName", crName, "SecretName", target.Name, "SecretNamespace", target.Namespace)
		return ctrl.Result{}, nil
	}

	if target.Data == nil {
		target.Data = map[string][]byte{}
	}
	target.Data[sourceKey] = wantPassword
	setOwnershipAnnotations(target, CJKS_CR_Name, crName)
	if target.Annotations == nil {
		target.Annotations = map[string]string{}
	}
	target.Annotations[DefaultInjectedDataKeyAnnotation] = sourceKey

	if err := r.Update(ctx, target); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	secretInjectorLog.Info("Successfully injected password into labeled Secret",
		"ClusterJavaKeystoreName", crName, "SecretName", target.Name, "SecretNamespace", target.Namespace, "DataKey", sourceKey)
	return ctrl.Result{}, nil
}

// cleanupUnlabeled removes the injected password key and our annotations from a Secret
// that was previously injected but is no longer carrying our label. The injected data
// key is read from the DefaultInjectedDataKeyAnnotation we stamped during injection,
// falling back to DefaultJavaKeystorePasswordSecretKey for Secrets injected before that
// annotation was added.
func (r *ClusterJavaKeystoreSecretInjectorReconciler) cleanupUnlabeled(ctx context.Context, s *corev1.Secret) (ctrl.Result, error) {
	dataKey := s.Annotations[DefaultInjectedDataKeyAnnotation]
	if dataKey == "" {
		dataKey = DefaultJavaKeystorePasswordSecretKey
	}
	delete(s.Data, dataKey)
	delete(s.Annotations, DefaultOwningComponentAnnotationKey)
	delete(s.Annotations, DefaultOwningInstanceAnnotationKey)
	delete(s.Annotations, DefaultInjectedDataKeyAnnotation)
	if err := r.Update(ctx, s); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	secretInjectorLog.Info("Cleaned up injected password data from unlabeled Secret",
		"SecretName", s.Name, "SecretNamespace", s.Namespace, "DataKey", dataKey)
	return ctrl.Result{}, nil
}

// isSystemKeystoreSecretPredicate admits Secret events only for Secrets whose
// controller-OwnerReference points at a ClusterJavaKeystore CR.
func isSystemKeystoreSecretPredicate() predicate.Predicate {
	check := func(obj client.Object) bool {
		if obj == nil {
			return false
		}
		for _, ref := range obj.GetOwnerReferences() {
			if ref.Kind == CJKS_CR_Name && ref.Controller != nil && *ref.Controller {
				return true
			}
		}
		return false
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return check(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return check(e.ObjectNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return check(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return check(e.Object) },
	}
}

func (r *ClusterJavaKeystoreSecretInjectorReconciler) mapSystemSecretToLabeledSecrets(ctx context.Context, obj client.Object) []reconcile.Request {
	crName := ""
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == CJKS_CR_Name {
			crName = ref.Name
			break
		}
	}
	if crName == "" {
		return nil
	}
	return r.listLabeledSecretRequests(ctx, crName)
}

func (r *ClusterJavaKeystoreSecretInjectorReconciler) mapCRToLabeledSecrets(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.listLabeledSecretRequests(ctx, obj.GetName())
}

func (r *ClusterJavaKeystoreSecretInjectorReconciler) listLabeledSecretRequests(ctx context.Context, crName string) []reconcile.Request {
	sList := &corev1.SecretList{}
	if err := r.List(ctx, sList, client.MatchingLabels{DefaultClusterJavaKeystoreLabel: crName}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(sList.Items))
	for _, s := range sList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: s.Namespace, Name: s.Name},
		})
	}
	return requests
}

func (r *ClusterJavaKeystoreSecretInjectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}, builder.WithPredicates(clusterKeystoreLabelPredicate())).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSystemSecretToLabeledSecrets),
			builder.WithPredicates(isSystemKeystoreSecretPredicate()),
		).
		Watches(
			&jksv1alpha1.ClusterJavaKeystore{},
			handler.EnqueueRequestsFromMapFunc(r.mapCRToLabeledSecrets),
			builder.WithPredicates(ignoreDeletionPredicate()),
		).
		Named("clusterjavakeystore-secret-injector").
		Complete(r)
}
