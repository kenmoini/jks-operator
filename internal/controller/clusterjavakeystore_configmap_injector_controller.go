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

// ClusterJavaKeystoreConfigMapInjectorReconciler propagates the rendered keystore from
// the system ConfigMap (`<crName>-jks` in `Spec.SystemNamespace`) into every ConfigMap
// across the cluster that opts in via the `jks.kemo.dev/clusterkeystore=<crName>` label.
//
// Lifecycle:
//   - Label added (or labeled CM created): inject the JKS bytes from the system ConfigMap.
//   - Source certs change: the CR controller updates the system ConfigMap, the Watch on
//     that ConfigMap fans out one reconcile per labeled target.
//   - Label removed: the cleanup path strips the injected `keystore.jks` key plus the
//     ownership and cert-hash annotations, leaving the rest of the user's ConfigMap intact.
//   - CR deleted: garbage collection removes the system ConfigMap; we leave the labeled
//     targets' injected data in place per design (user-owned resources we only inject into).
type ClusterJavaKeystoreConfigMapInjectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	configMapInjectorLog.Info("Reconciling labeled ConfigMap", "NamespacedName", req.NamespacedName)

	target := &corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, target); err != nil {
		if kapierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	crName := target.Labels[DefaultClusterJavaKeystoreLabel]

	// Cleanup-on-unlabel: target previously labeled (we stamped ownership) but the label
	// is now gone or empty. Strip what we wrote and exit. Don't touch ConfigMaps that
	// don't bear our ownership stamp — they were never ours to manage.
	if crName == "" {
		if hasOwnershipAnnotations(target, CJKS_CR_Name, target.Annotations[DefaultOwningInstanceAnnotationKey]) &&
			target.Annotations[DefaultOwningComponentAnnotationKey] == CJKS_CR_Name {
			return r.cleanupUnlabeled(ctx, target)
		}
		return ctrl.Result{}, nil
	}

	// Find the CR. If the CR is gone (e.g. just deleted), leave the labeled target's
	// data in place — per design we don't reach across to rewrite user-owned resources
	// when the source-of-truth is no longer present.
	cr := &jksv1alpha1.ClusterJavaKeystore{}
	if err := r.Get(ctx, types.NamespacedName{Name: crName}, cr); err != nil {
		if kapierrors.IsNotFound(err) {
			configMapInjectorLog.Info("Referenced ClusterJavaKeystore not found; leaving labeled ConfigMap untouched",
				"ClusterJavaKeystoreName", crName, "ConfigMapName", target.Name, "ConfigMapNamespace", target.Namespace)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Apply NamespaceSelector when set.
	if cr.Spec.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(cr.Spec.NamespaceSelector)
		if err != nil {
			configMapInjectorLog.Error(err, "Invalid NamespaceSelector on ClusterJavaKeystore", "ClusterJavaKeystoreName", crName)
			return ctrl.Result{}, err
		}
		ns := &corev1.Namespace{}
		if err := r.Get(ctx, types.NamespacedName{Name: target.Namespace}, ns); err != nil {
			return ctrl.Result{RequeueAfter: time.Second * 30}, err
		}
		if !sel.Matches(labels.Set(ns.Labels)) {
			configMapInjectorLog.Info("Skipping labeled ConfigMap whose namespace does not match the ClusterJavaKeystore NamespaceSelector",
				"ClusterJavaKeystoreName", crName, "ConfigMapName", target.Name, "ConfigMapNamespace", target.Namespace)
			return ctrl.Result{}, nil
		}
	}

	// Resolve the system ConfigMap name + data key from the CR spec — TargetConfigMap
	// overrides may have customized either. The same key flows into labeled targets so
	// consumers see one consistent key end-to-end.
	sourceName, sourceKey := resolveClusterTargetConfigMap(cr)

	// Read the system ConfigMap and copy its bytes + cert-hash annotation. The CR
	// controller is responsible for keeping the system ConfigMap correct; we never
	// re-render the keystore here.
	systemCM := &corev1.ConfigMap{}
	systemCMName := types.NamespacedName{
		Name:      sourceName,
		Namespace: cr.Spec.SystemNamespace,
	}
	if systemCMName.Namespace == "" {
		systemCMName.Namespace = DefaultOperatorNamespace
	}
	if err := r.Get(ctx, systemCMName, systemCM); err != nil {
		if kapierrors.IsNotFound(err) {
			// CR exists but its system ConfigMap hasn't been created yet — wait for the
			// CR controller, which will fan out to us via our Watch when it appears.
			configMapInjectorLog.Info("System ConfigMap not yet present; will be requeued via watch when ready",
				"ClusterJavaKeystoreName", crName, "SystemConfigMap", systemCMName.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}

	wantHash := systemCM.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation]
	wantBytes := systemCM.BinaryData[sourceKey]
	if len(wantBytes) == 0 || wantHash == "" {
		configMapInjectorLog.Info("System ConfigMap not yet populated; awaiting CR controller",
			"ClusterJavaKeystoreName", crName, "SystemConfigMap", systemCMName.String(), "DataKey", sourceKey)
		return ctrl.Result{}, nil
	}

	// If the configured data key changed since last injection (e.g. user updated
	// Spec.TargetConfigMap.Key), strip the previously injected key so we don't leave
	// stale data lingering under the old name.
	previousKey := target.Annotations[DefaultInjectedDataKeyAnnotation]
	if previousKey != "" && previousKey != sourceKey {
		delete(target.BinaryData, previousKey)
	}

	// Idempotency.
	if target.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] == wantHash &&
		len(target.BinaryData[sourceKey]) > 0 &&
		hasOwnershipAnnotations(target, CJKS_CR_Name, crName) &&
		target.Annotations[DefaultInjectedDataKeyAnnotation] == sourceKey {
		configMapInjectorLog.Info("Labeled ConfigMap already up to date, skipping",
			"ClusterJavaKeystoreName", crName, "ConfigMapName", target.Name, "ConfigMapNamespace", target.Namespace)
		return ctrl.Result{}, nil
	}

	if target.BinaryData == nil {
		target.BinaryData = map[string][]byte{}
	}
	target.BinaryData[sourceKey] = wantBytes
	setOwnershipAnnotations(target, CJKS_CR_Name, crName)
	target.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = wantHash
	target.Annotations[DefaultInjectedDataKeyAnnotation] = sourceKey

	if err := r.Update(ctx, target); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	configMapInjectorLog.Info("Successfully injected Java Keystore into labeled ConfigMap",
		"ClusterJavaKeystoreName", crName, "ConfigMapName", target.Name, "ConfigMapNamespace", target.Namespace, "DataKey", sourceKey, "CertHash", wantHash)
	return ctrl.Result{}, nil
}

// cleanupUnlabeled removes the injected key and our annotations from a ConfigMap that
// was previously injected but is no longer carrying our label. The rest of the
// ConfigMap (other data keys, other annotations, labels, owner refs) is preserved.
// The injected data key is read from the DefaultInjectedDataKeyAnnotation we stamped
// during injection, falling back to DefaultJavaKeystoreConfigMapKey for ConfigMaps
// injected before that annotation was added.
func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) cleanupUnlabeled(ctx context.Context, cm *corev1.ConfigMap) (ctrl.Result, error) {
	dataKey := cm.Annotations[DefaultInjectedDataKeyAnnotation]
	if dataKey == "" {
		dataKey = DefaultJavaKeystoreConfigMapKey
	}
	delete(cm.BinaryData, dataKey)
	delete(cm.Annotations, DefaultClusterJavaKeystoreCertHashAnnotation)
	delete(cm.Annotations, DefaultOwningComponentAnnotationKey)
	delete(cm.Annotations, DefaultOwningInstanceAnnotationKey)
	delete(cm.Annotations, DefaultInjectedDataKeyAnnotation)
	if err := r.Update(ctx, cm); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	configMapInjectorLog.Info("Cleaned up injected keystore data from unlabeled ConfigMap",
		"ConfigMapName", cm.Name, "ConfigMapNamespace", cm.Namespace, "DataKey", dataKey)
	return ctrl.Result{}, nil
}

// isSystemKeystoreConfigMapPredicate admits ConfigMap events only for ConfigMaps that
// are owned (via controller OwnerReference) by a ClusterJavaKeystore CR — i.e. the
// system ConfigMaps the CR controller writes. Used to scope the system-CM Watch.
func isSystemKeystoreConfigMapPredicate() predicate.Predicate {
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

// mapSystemCMToLabeledConfigMaps fans a system-ConfigMap event out to a reconcile
// request per labeled ConfigMap targeting the same CR. Driven by the controller-OwnerRef
// on the system ConfigMap, which names the CR.
func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) mapSystemCMToLabeledConfigMaps(ctx context.Context, obj client.Object) []reconcile.Request {
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
	return r.listLabeledConfigMapRequests(ctx, crName)
}

// mapCRToLabeledConfigMaps fans a ClusterJavaKeystore event out to one reconcile per
// labeled ConfigMap. Covers two cases the system-CM Watch alone misses:
//   - A labeled ConfigMap was created before the CR existed — when the CR is created,
//     this fan-out re-evaluates it.
//   - The CR's NamespaceSelector changed without changing the system ConfigMap.
func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) mapCRToLabeledConfigMaps(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.listLabeledConfigMapRequests(ctx, obj.GetName())
}

func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) listLabeledConfigMapRequests(ctx context.Context, crName string) []reconcile.Request {
	cmList := &corev1.ConfigMapList{}
	if err := r.List(ctx, cmList, client.MatchingLabels{DefaultClusterJavaKeystoreLabel: crName}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(cmList.Items))
	for _, cm := range cmList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: cm.Namespace, Name: cm.Name},
		})
	}
	return requests
}

func (r *ClusterJavaKeystoreConfigMapInjectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(clusterKeystoreLabelPredicate())).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.mapSystemCMToLabeledConfigMaps),
			builder.WithPredicates(isSystemKeystoreConfigMapPredicate()),
		).
		Watches(
			&jksv1alpha1.ClusterJavaKeystore{},
			handler.EnqueueRequestsFromMapFunc(r.mapCRToLabeledConfigMaps),
			builder.WithPredicates(ignoreDeletionPredicate()),
		).
		Named("clusterjavakeystore-configmap-injector").
		Complete(r)
}
