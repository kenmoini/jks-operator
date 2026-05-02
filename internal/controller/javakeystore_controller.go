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

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

// JavaKeystoreReconciler reconciles a JavaKeystore object. The namespaced JavaKeystore
// operates within the namespace its CR lives in: all referenced ConfigMaps/Secrets must
// be in that namespace, and the rendered system ConfigMap and password Secret are written
// there too. The cross-namespace machinery used by ClusterJavaKeystore (system namespace,
// namespace selector, label-based fan-out) does not apply here — owner references handle
// GC cleanly because outputs share scope with the CR.
type JavaKeystoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// resolveKeystorePassword returns the password to use for the generated Java Keystore.
// Precedence: KeyStorePasswordSecretRef[Key] > KeyStorePasswordSecretRef[DefaultJavaKeystorePasswordSecretKey] > DefaultJavaKeystorePassword.
// Any failure to resolve (ref unset, secret fetch error, key missing) falls back to
// DefaultJavaKeystorePassword and logs the cause. The Secret is fetched from the CR's
// own namespace because NamespacedSecretReference has no Namespace field.
func (r *JavaKeystoreReconciler) resolveKeystorePassword(jks *jksv1alpha1.JavaKeystore, req ctrl.Request) string {
	ref := jks.Spec.KeyStorePasswordSecretRef
	if ref.Name == "" {
		globalLog.Info("KeyStorePasswordSecretRef is not set in JavaKeystore spec, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName)
		return DefaultJavaKeystorePassword
	}
	globalLog.Info("KeyStorePasswordSecretRef is set in JavaKeystore spec, attempting to fetch Secret for KeyStore password", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", req.Namespace)
	secret, err := GetSecret(ref.Name, req.Namespace, r.Client)
	if err != nil {
		globalLog.Error(err, "Failed to fetch Secret specified in KeyStorePasswordSecretRef for KeyStore password, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", req.Namespace)
		return DefaultJavaKeystorePassword
	}
	key := ref.Key
	if key == "" {
		key = DefaultJavaKeystorePasswordSecretKey
	}
	password, ok := secret.Data[key]
	if !ok {
		globalLog.Error(nil, "Specified key in KeyStorePasswordSecretRef does not exist in Secret, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", req.Namespace, "MissingKey", key)
		return DefaultJavaKeystorePassword
	}
	globalLog.Info("Successfully retrieved KeyStore password from Secret specified in KeyStorePasswordSecretRef", "NamespacedName", req.NamespacedName, "SecretName", ref.Name, "SecretNamespace", req.Namespace, "KeyUsed", key)
	return string(password)
}

// resolveTargetConfigMap returns the (name, dataKey) pair to use for the output ConfigMap.
// Spec.TargetConfigMap.Name overrides the default suffix-based name "<jks.Name>-jks";
// Spec.TargetConfigMap.Key overrides the default BinaryData key DefaultJavaKeystoreConfigMapKey
// ("keystore.jks"). Either field may be set independently.
func resolveTargetConfigMap(jks *jksv1alpha1.JavaKeystore) (string, string) {
	name := jks.Spec.TargetConfigMap.Name
	if name == "" {
		name = jks.Name + "-jks"
	}
	key := jks.Spec.TargetConfigMap.Key
	if key == "" {
		key = DefaultJavaKeystoreConfigMapKey
	}
	return name, key
}

// resolveTargetSecret returns the (name, dataKey) pair to use for the password Secret.
// Spec.TargetSecret.Name overrides the default suffix-based name "<jks.Name>-jks-password";
// Spec.TargetSecret.Key overrides the default Data key DefaultJavaKeystorePasswordSecretKey
// ("password"). Either field may be set independently.
func resolveTargetSecret(jks *jksv1alpha1.JavaKeystore) (string, string) {
	name := jks.Spec.TargetSecret.Name
	if name == "" {
		name = jks.Name + "-jks-password"
	}
	key := jks.Spec.TargetSecret.Key
	if key == "" {
		key = DefaultJavaKeystorePasswordSecretKey
	}
	return name, key
}

// reconcileSystemConfigMap renders the JKS bytes (only when the on-cluster ConfigMap is
// stale per systemConfigMapIsCurrent) and creates or updates the output ConfigMap with
// the rendered bytes (under dataKey), source-hash annotation, and ownership stamps. The
// output ConfigMap lives in the CR's namespace; targetName + dataKey come from
// resolveTargetConfigMap so user-supplied Spec.TargetConfigMap.Name / .Key override the
// default suffix and key respectively.
func (r *JavaKeystoreReconciler) reconcileSystemConfigMap(ctx context.Context, jks *jksv1alpha1.JavaKeystore, targetName, dataKey string, certificates []CertificateNameMapping, keypairs []KeypairEntry, password, hash string) error {
	name := types.NamespacedName{Name: targetName, Namespace: jks.Namespace}
	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, name, existing)
	if err != nil && !kapierrors.IsNotFound(err) {
		globalLog.Error(err, "Failed to fetch existing ConfigMap to store generated Java Keystore", "ConfigMapName", name.Name, "ConfigMapNamespace", name.Namespace)
		return err
	}
	cmExists := err == nil

	if cmExists && systemConfigMapIsCurrent(existing, JKS_CR_Name, jks.Name, dataKey, hash) {
		globalLog.Info("System ConfigMap already up to date (source-hash matches), skipping render and update", "ConfigMapName", name.Name, "DataKey", dataKey, "SourceHash", hash)
		return nil
	}

	jksBytes, err := renderKeystoreBytes(certificates, keypairs, password)
	if err != nil {
		globalLog.Error(err, "Failed to render Java Keystore bytes", "JavaKeystore", jks.Name)
		return err
	}
	globalLog.Info("Successfully rendered Java Keystore bytes", "JavaKeystore", jks.Name)

	if !cmExists {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name.Name,
				Namespace: name.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(jks, jksv1alpha1.GroupVersion.WithKind(JKS_CR_Name)),
				},
			},
			BinaryData: map[string][]byte{dataKey: jksBytes},
		}
		setOwnershipAnnotations(cm, JKS_CR_Name, jks.Name)
		cm.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = hash
		if err := r.Create(ctx, cm); err != nil {
			globalLog.Error(err, "Failed to create ConfigMap to store generated Java Keystore", "ConfigMapName", cm.Name, "ConfigMapNamespace", cm.Namespace)
			return err
		}
		globalLog.Info("Successfully created ConfigMap to store generated Java Keystore", "ConfigMapName", cm.Name, "ConfigMapNamespace", cm.Namespace, "DataKey", dataKey, "SourceHash", hash)
		return nil
	}

	if existing.BinaryData == nil {
		existing.BinaryData = map[string][]byte{}
	}
	existing.BinaryData[dataKey] = jksBytes
	setOwnershipAnnotations(existing, JKS_CR_Name, jks.Name)
	existing.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = hash
	if err := r.Update(ctx, existing); err != nil {
		globalLog.Error(err, "Failed to update ConfigMap to store generated Java Keystore", "ConfigMapName", existing.Name, "ConfigMapNamespace", existing.Namespace)
		return err
	}
	globalLog.Info("Successfully updated ConfigMap to store generated Java Keystore", "ConfigMapName", existing.Name, "ConfigMapNamespace", existing.Namespace, "DataKey", dataKey, "SourceHash", hash)
	return nil
}

// reconcileSystemSecret create-or-updates the password Secret for this CR. Updates only
// fire when the existing Data differs OR ownership annotations are missing/wrong. The
// output Secret lives in the CR's namespace; targetName + dataKey come from
// resolveTargetSecret so user-supplied Spec.TargetSecret.Name / .Key override the default
// suffix and key respectively.
func (r *JavaKeystoreReconciler) reconcileSystemSecret(ctx context.Context, jks *jksv1alpha1.JavaKeystore, targetName, dataKey, password string) error {
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetName,
			Namespace: jks.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(jks, jksv1alpha1.GroupVersion.WithKind(JKS_CR_Name)),
			},
		},
		Data: map[string][]byte{dataKey: []byte(password)},
	}
	setOwnershipAnnotations(desired, JKS_CR_Name, jks.Name)

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

	needsUpdate := !reflect.DeepEqual(existing.Data, desired.Data) || !hasOwnershipAnnotations(existing, JKS_CR_Name, jks.Name)
	if !needsUpdate {
		globalLog.Info("Secret to store Java Keystore password already exists and is up to date, no update needed", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
		return nil
	}
	existing.Data = desired.Data
	setOwnershipAnnotations(existing, JKS_CR_Name, jks.Name)
	if err := r.Update(ctx, existing); err != nil {
		globalLog.Error(err, "Failed to update Secret to store Java Keystore password", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
		return err
	}
	globalLog.Info("Successfully updated Secret to store Java Keystore password", "SecretName", existing.Name, "SecretNamespace", existing.Namespace)
	return nil
}

// +kubebuilder:rbac:groups=core,resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=javakeystores,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=javakeystores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=jks.kemo.dev,resources=javakeystores/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *JavaKeystoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	globalLog = ctrl.Log.WithName("jks-operator-jks")
	globalLog.Info("Reconciling JavaKeystore", "NamespacedName", req.NamespacedName)

	jks := &jksv1alpha1.JavaKeystore{}
	if err := r.Get(ctx, req.NamespacedName, jks); err != nil {
		globalLog.Error(err, "Failed to fetch JavaKeystore", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	}
	globalLog.Info("Successfully fetched JavaKeystore", "NamespacedName", req.NamespacedName)

	keyStorePassword := r.resolveKeystorePassword(jks, req)

	certificates := loadDefaultCACertificatesFromDisk(
		jks.Spec.AddDefaultCACertificates,
		jks.Spec.DefaultCACertificatesPath,
		nil,
	)

	// NamespacedConfigMapReference omits the Namespace field — every ref is implicitly
	// in the CR's namespace. Stamp it on so the namespace-agnostic helper sees a fully
	// qualified ref.
	normalizedRefs := make([]jksv1alpha1.ConfigMapReference, 0, len(jks.Spec.RootCAConfigMaps))
	for _, ref := range jks.Spec.RootCAConfigMaps {
		normalizedRefs = append(normalizedRefs, jksv1alpha1.ConfigMapReference{
			Name:      ref.Name,
			Namespace: req.Namespace,
			Key:       ref.Key,
		})
	}

	certificates, err := collectCertificatesFromConfigMaps(ctx, r.Client, normalizedRefs, certificates)
	if err != nil {
		globalLog.Error(err, "Failed to collect certificates from referenced ConfigMaps", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	}

	existingAliases := make([]string, 0, len(certificates))
	for _, ci := range certificates {
		existingAliases = append(existingAliases, ci.CommonName)
	}
	keypairs := loadTLSKeypairsFromSecrets(ctx, r.Client, req.Namespace, jks.Spec.TLSCertSecretRef, existingAliases)

	if len(certificates) == 0 && len(keypairs) == 0 {
		globalLog.Info("No certificates or TLS keypairs found in any of the referenced sources, skipping keystore render", "NamespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	for _, certInfo := range certificates {
		globalLog.Info("Certificate found", "CommonName", certInfo.CommonName, "ExpirationDate", certInfo.ExpirationDate)
	}
	for _, ke := range keypairs {
		globalLog.Info("TLS keypair found", "Alias", ke.Alias)
	}

	// Source hash includes both trusted certs and keypair material so any change in either
	// source set triggers a re-render. Rendered JKS bytes are not byte-stable across runs
	// (the keystore library salts/timestamps the output), so we drive idempotency off the
	// canonical input hash, not the output bytes.
	hash := computeKeystoreSourceHash(certificates, keypairs)

	cmName, cmKey := resolveTargetConfigMap(jks)
	secretName, secretKey := resolveTargetSecret(jks)

	if err := r.reconcileSystemConfigMap(ctx, jks, cmName, cmKey, certificates, keypairs, keyStorePassword, hash); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}
	if err := r.reconcileSystemSecret(ctx, jks, secretName, secretKey, keyStorePassword); err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 30}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager. Owns ConfigMap and Secret so
// in-band edits to outputs (e.g. someone wiping the keystore.jks key) re-trigger Reconcile,
// and the shared ignoreDeletionPredicate filters status-only updates so we don't spuriously
// re-render on status writes.
func (r *JavaKeystoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jksv1alpha1.JavaKeystore{}, builder.WithPredicates(ignoreDeletionPredicate())).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		WithEventFilter(ignoreDeletionPredicate()).
		Named("javakeystore").
		Complete(r)
}
