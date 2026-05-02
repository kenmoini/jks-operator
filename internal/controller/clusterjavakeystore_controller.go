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
	"reflect"
	"time"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterJavaKeystoreReconciler reconciles a ClusterJavaKeystore object
type ClusterJavaKeystoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// getSystemNamespace returns the namespace where the system ConfigMap and Secret should be
// written. Defaults to DefaultOperatorNamespace ("jks-operator") and validates that the
// namespace exists.
func (r *ClusterJavaKeystoreReconciler) getSystemNamespace(clusterJavaKeystore *jksv1alpha1.ClusterJavaKeystore, ctx context.Context, req ctrl.Request) (string, error) {
	if clusterJavaKeystore.Spec.SystemNamespace == "" {
		clusterJavaKeystore.Spec.SystemNamespace = DefaultOperatorNamespace
		globalLog.Info("SystemNamespace not set in ClusterJavaKeystore spec, defaulting to '"+DefaultOperatorNamespace+"'", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	} else {
		globalLog.Info("SystemNamespace is set in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	}

	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: clusterJavaKeystore.Spec.SystemNamespace}, namespace); err != nil {
		globalLog.Error(err, "Failed to fetch SystemNamespace", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
		return "", client.IgnoreNotFound(err)
	}
	globalLog.Info("Successfully fetched SystemNamespace specified in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	return clusterJavaKeystore.Spec.SystemNamespace, nil
}

// resolveKeystorePassword returns the password to use for the generated Java Keystore.
// Precedence: KeyStorePasswordSecretRef[Key] > KeyStorePasswordSecretRef[DefaultJavaKeystorePasswordSecretKey] > DefaultJavaKeystorePassword.
// Any failure to resolve (ref unset, secret fetch error, key missing) falls back to
// DefaultJavaKeystorePassword and logs the cause.
func (r *ClusterJavaKeystoreReconciler) resolveKeystorePassword(cjks *jksv1alpha1.ClusterJavaKeystore, req ctrl.Request) string {
	ref := cjks.Spec.KeyStorePasswordSecretRef
	if ref.Name == "" || ref.Namespace == "" {
		globalLog.Info("KeyStorePasswordSecretRef is not set in ClusterJavaKeystore spec, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName)
		return DefaultJavaKeystorePassword
	}
	globalLog.Info("KeyStorePasswordSecretRef is set in ClusterJavaKeystore spec, attempting to fetch Secret for KeyStore password", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", ref.Namespace)
	secret, err := GetSecret(ref.Name, ref.Namespace, r.Client)
	if err != nil {
		globalLog.Error(err, "Failed to fetch Secret specified in KeyStorePasswordSecretRef for KeyStore password, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", ref.Namespace)
		return DefaultJavaKeystorePassword
	}
	key := ref.Key
	if key == "" {
		key = DefaultJavaKeystorePasswordSecretKey
	}
	password, ok := secret.Data[key]
	if !ok {
		globalLog.Error(nil, "Specified key in KeyStorePasswordSecretRef does not exist in Secret, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", ref.Namespace, "MissingKey", key)
		return DefaultJavaKeystorePassword
	}
	globalLog.Info("Successfully retrieved KeyStore password from Secret specified in KeyStorePasswordSecretRef", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", ref.Namespace, "KeyUsed", key)
	return string(password)
}

// reconcileSystemConfigMap renders the JKS bytes (only when the on-cluster ConfigMap is
// stale per systemConfigMapIsCurrent) and creates or updates the system ConfigMap with
// the rendered bytes, cert-hash annotation, and ownership stamps.
func (r *ClusterJavaKeystoreReconciler) reconcileSystemConfigMap(ctx context.Context, cjks *jksv1alpha1.ClusterJavaKeystore, certificates []CertificateNameMapping, password, systemNamespace, hash string) error {
	name := types.NamespacedName{Name: cjks.Name + "-jks", Namespace: systemNamespace}
	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, name, existing)
	if err != nil && !kapierrors.IsNotFound(err) {
		globalLog.Error(err, "Failed to fetch existing ConfigMap to store generated Java Keystore", "ConfigMapName", name.Name, "ConfigMapNamespace", name.Namespace)
		return err
	}
	cmExists := err == nil

	if cmExists && systemConfigMapIsCurrent(existing, "ClusterJavaKeystore", cjks.Name, hash) {
		globalLog.Info("System ConfigMap already up to date (cert-hash matches), skipping render and update", "ConfigMapName", name.Name, "CertHash", hash)
		return nil
	}

	jksBytes, err := renderKeystoreBytes(certificates, nil, password)
	if err != nil {
		globalLog.Error(err, "Failed to render Java Keystore bytes", "ClusterJavaKeystore", cjks.Name)
		return err
	}
	globalLog.Info("Successfully rendered Java Keystore bytes", "ClusterJavaKeystore", cjks.Name)

	if !cmExists {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name.Name,
				Namespace: name.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(cjks, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
				},
			},
			BinaryData: map[string][]byte{DefaultJavaKeystoreConfigMapKey: jksBytes},
		}
		setOwnershipAnnotations(cm, "ClusterJavaKeystore", cjks.Name)
		cm.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = hash
		if err := r.Create(ctx, cm); err != nil {
			globalLog.Error(err, "Failed to create ConfigMap to store generated Java Keystore", "ConfigMapName", cm.Name, "ConfigMapNamespace", cm.Namespace)
			return err
		}
		globalLog.Info("Successfully created ConfigMap to store generated Java Keystore", "ConfigMapName", cm.Name, "ConfigMapNamespace", cm.Namespace, "CertHash", hash)
		return nil
	}

	if existing.BinaryData == nil {
		existing.BinaryData = map[string][]byte{}
	}
	existing.BinaryData[DefaultJavaKeystoreConfigMapKey] = jksBytes
	setOwnershipAnnotations(existing, "ClusterJavaKeystore", cjks.Name)
	existing.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = hash
	if err := r.Update(ctx, existing); err != nil {
		globalLog.Error(err, "Failed to update ConfigMap to store generated Java Keystore", "ConfigMapName", existing.Name, "ConfigMapNamespace", existing.Namespace)
		return err
	}
	globalLog.Info("Successfully updated ConfigMap to store generated Java Keystore", "ConfigMapName", existing.Name, "ConfigMapNamespace", existing.Namespace, "CertHash", hash)
	return nil
}

// reconcileSystemSecret create-or-updates the password Secret for this CR. Updates only
// fire when the existing Data differs OR ownership annotations are missing/wrong.
func (r *ClusterJavaKeystoreReconciler) reconcileSystemSecret(ctx context.Context, cjks *jksv1alpha1.ClusterJavaKeystore, password, systemNamespace string) error {
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cjks.Name + "-jks-password",
			Namespace: systemNamespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cjks, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
			},
		},
		Data: map[string][]byte{DefaultJavaKeystorePasswordSecretKey: []byte(password)},
	}
	setOwnershipAnnotations(desired, "ClusterJavaKeystore", cjks.Name)

	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing)
	if kapierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			globalLog.Error(err, "Failed to create Secret to store Java Keystore password", "SecretName", desired.Name, "SecretNamespace", desired.Namespace)
			return err
		}
		globalLog.Info("Successfully created Secret to store Java Keystore password", "SecretName", desired.Name, "SecretNamespace", desired.Namespace)
		return nil
	}
	if err != nil {
		globalLog.Error(err, "Failed to fetch existing Secret to store Java Keystore password", "SecretName", desired.Name, "SecretNamespace", desired.Namespace)
		return err
	}

	needsUpdate := !reflect.DeepEqual(existing.Data, desired.Data) || !hasOwnershipAnnotations(existing, "ClusterJavaKeystore", cjks.Name)
	if !needsUpdate {
		globalLog.Info("Secret to store Java Keystore password already exists and is up to date, no update needed", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
		return nil
	}
	existing.Data = desired.Data
	setOwnershipAnnotations(existing, "ClusterJavaKeystore", cjks.Name)
	if err := r.Update(ctx, existing); err != nil {
		globalLog.Error(err, "Failed to update Secret to store Java Keystore password", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
		return err
	}
	globalLog.Info("Successfully updated Secret to store Java Keystore password", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
	return nil
}

// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=clusterjavakeystores,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=clusterjavakeystores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=clusterjavakeystores/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *ClusterJavaKeystoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	globalLog = ctrl.Log.WithName("jks-operator-clusterjks")
	globalLog.Info("Reconciling ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

	clusterJavaKeystore := &jksv1alpha1.ClusterJavaKeystore{}
	if err := r.Get(ctx, req.NamespacedName, clusterJavaKeystore); err != nil {
		globalLog.Error(err, "Failed to fetch ClusterJavaKeystore", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	}
	globalLog.Info("Successfully fetched ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

	systemNamespace, err := r.getSystemNamespace(clusterJavaKeystore, ctx, req)
	if err != nil {
		globalLog.Error(err, "Failed to determine SystemNamespace for ClusterJavaKeystore", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}

	keyStorePassword := r.resolveKeystorePassword(clusterJavaKeystore, req)

	certificates := []CertificateNameMapping{}
	certificates = loadDefaultCACertificatesFromDisk(
		clusterJavaKeystore.Spec.AddDefaultCACertificates,
		clusterJavaKeystore.Spec.DefaultCACertificatesPath,
		certificates,
	)

	certificates, err = collectCertificatesFromConfigMaps(ctx, r.Client, clusterJavaKeystore.Spec.RootCAConfigMaps, certificates)
	if err != nil {
		globalLog.Error(err, "Failed to collect certificates from referenced ConfigMaps", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	}

	if len(certificates) == 0 {
		globalLog.Info("No certificates found in any of the referenced ConfigMaps", "NamespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	for _, certInfo := range certificates {
		globalLog.Info("Certificate found", "CommonName", certInfo.CommonName, "ExpirationDate", certInfo.ExpirationDate)
	}

	// Cert-set hash is the canonical fingerprint of the source-cert set: matching hash means
	// an unchanged keystore even though rendered JKS bytes are non-deterministic (keystore-go
	// salts/timestamps the output). Lets us skip the render when the system ConfigMap already
	// reflects this exact cert set, and lets downstream injector controllers drive their own
	// idempotency off the same hash.
	hash := computeKeystoreSourceHash(certificates, nil)

	if err := r.reconcileSystemConfigMap(ctx, clusterJavaKeystore, certificates, keyStorePassword, systemNamespace, hash); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	if err := r.reconcileSystemSecret(ctx, clusterJavaKeystore, keyStorePassword, systemNamespace); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}

	// Labeled-target injection (ConfigMap and Secret) is handled by the dedicated injector
	// controllers — see clusterjavakeystore_configmap_injector_controller.go and
	// clusterjavakeystore_secret_injector_controller.go. They watch the system ConfigMap/Secret
	// we just wrote above and fan out per-target.
	return ctrl.Result{}, nil
}
