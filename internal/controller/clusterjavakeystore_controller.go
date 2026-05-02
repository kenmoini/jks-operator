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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
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

func (r *ClusterJavaKeystoreReconciler) getSystemNamespace(clusterJavaKeystore *jksv1alpha1.ClusterJavaKeystore, ctx context.Context, req ctrl.Request) (string, error) { // =====================================================================================================================================
	// Check to see if the SystemNamespace is set, if not we will default it to "jks-operator", and if it exists
	// we will log the value for visibility since that is where the Java Keystore ConfigMap and Secret will be created
	if clusterJavaKeystore.Spec.SystemNamespace == "" {
		clusterJavaKeystore.Spec.SystemNamespace = DefaultOperatorNamespace
		globalLog.Info("SystemNamespace not set in ClusterJavaKeystore spec, defaulting to '"+DefaultOperatorNamespace+"'", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	} else {
		globalLog.Info("SystemNamespace is set in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	}

	// Check if the namespace exists, if not error out
	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: clusterJavaKeystore.Spec.SystemNamespace}, namespace); err != nil {
		globalLog.Error(err, "Failed to fetch SystemNamespace", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
		return "", client.IgnoreNotFound(err)
	} else {
		globalLog.Info("Successfully fetched SystemNamespace specified in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
	}
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

// parseAndEncodePEMCertificate parses a PEM block as an X.509 certificate, re-encodes the
// cert.Raw bytes back to a fresh PEM buffer, and returns a CertificateNameMapping ready
// for inclusion in the Java Keystore. Re-encoding (rather than retaining block.Bytes) is
// intentional — it normalises any non-canonical PEM input to a single byte representation
// so byte-equality dedup works deterministically.
func parseAndEncodePEMCertificate(block *pem.Block) (CertificateNameMapping, error) {
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateNameMapping{}, fmt.Errorf("parse certificate: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return CertificateNameMapping{}, fmt.Errorf("encode certificate: %w", err)
	}
	return CertificateNameMapping{
		CommonName:       determineCommonNameForCertificate(cert),
		ExpirationDate:   cert.NotAfter,
		CreationDate:     cert.NotBefore,
		CertificateBytes: buf.Bytes(),
	}, nil
}

// loadDefaultCACertificates appends system CA certificates from disk to certificates when
// Spec.AddDefaultCACertificates is true. File-read failures are logged and swallowed —
// the user may not care if the bundle is unavailable, and we don't want a missing trust
// store to block valid user-supplied certificates.
func (r *ClusterJavaKeystoreReconciler) loadDefaultCACertificates(cjks *jksv1alpha1.ClusterJavaKeystore, req ctrl.Request, certificates []CertificateNameMapping) []CertificateNameMapping {
	if !cjks.Spec.AddDefaultCACertificates {
		globalLog.Info("Not including default CA certificates as specified in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName)
		return certificates
	}
	path := cjks.Spec.DefaultCACertificatesPath
	if path == "" {
		path = DefaultCACertificatesPath
	}
	globalLog.Info("Attempting to read default CA certificates from file", "FilePath", path)
	data, err := os.ReadFile(path)
	if err != nil {
		globalLog.Error(err, "Failed to read default CA certificates from file, continuing without including default CA certificates", "FilePath", path)
		return certificates
	}
	globalLog.Info("Successfully read default CA certificates from file, processing certificates", "FilePath", path)
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			globalLog.Info("PEM block is not a certificate, skipping", "FilePath", path, "PEMBlockType", block.Type)
			continue
		}
		ci, err := parseAndEncodePEMCertificate(block)
		if err != nil {
			globalLog.Error(err, "Failed to parse/encode certificate from default CA bundle, skipping this certificate", "FilePath", path)
			continue
		}
		certificates = appendUniqueCertificate(certificates, ci, "FilePath", path)
	}
	return certificates
}

// collectConfigMapCertificates iterates Spec.RootCAConfigMaps, fetches each ConfigMap, and
// appends every unique certificate found into certificates. Returns the first hard error
// (fetch failure or a missing required key); the caller applies client.IgnoreNotFound.
func (r *ClusterJavaKeystoreReconciler) collectConfigMapCertificates(ctx context.Context, cjks *jksv1alpha1.ClusterJavaKeystore, req ctrl.Request, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	if len(cjks.Spec.RootCAConfigMaps) == 0 {
		globalLog.Info("No ConfigMap references found in ClusterJavaKeystore, skipping certificate enumeration", "NamespacedName", req.NamespacedName)
		return certificates, nil
	}
	for _, ref := range cjks.Spec.RootCAConfigMaps {
		var err error
		certificates, err = r.processConfigMapReference(ctx, ref, certificates)
		if err != nil {
			return certificates, err
		}
	}
	return certificates, nil
}

// processConfigMapReference fetches one referenced ConfigMap and dispatches to per-key
// extraction. If ref.Key is set, only that key is processed (and missing it is a hard error
// that stops reconcile). If ref.Key is empty, every key is attempted and per-key extraction
// failures are logged and skipped.
func (r *ClusterJavaKeystoreReconciler) processConfigMapReference(ctx context.Context, ref jksv1alpha1.ConfigMapReference, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	globalLog.Info("Processing ConfigMap reference", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, configMap); err != nil {
		globalLog.Error(err, "Failed to fetch ConfigMap", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
		return certificates, err
	}
	globalLog.Info("Successfully fetched ConfigMap", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
	if ref.Key != "" {
		if _, ok := configMap.Data[ref.Key]; !ok {
			globalLog.Error(nil, "Specified key does not exist in ConfigMap", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "MissingKey", ref.Key)
			return certificates, fmt.Errorf("ConfigMap %s/%s missing key %q", ref.Namespace, ref.Name, ref.Key)
		}
		globalLog.Info("Specified key exists in ConfigMap", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "Key", ref.Key)
		return r.appendCertsFromConfigMapKey(configMap, ref, certificates)
	}
	globalLog.Info("No specific key specified for ConfigMap reference, all keys will be processed if they contain valid PEM encoded certificates", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
	for key := range configMap.Data {
		perKey := jksv1alpha1.ConfigMapReference{Name: ref.Name, Namespace: ref.Namespace, Key: key}
		var err error
		certificates, err = r.appendCertsFromConfigMapKey(configMap, perKey, certificates)
		if err != nil {
			globalLog.Error(err, "Failed to validate and extract certificates from ConfigMap for specific key", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "Key", key)
			continue
		}
	}
	return certificates, nil
}

// appendCertsFromConfigMapKey extracts all PEM certificates from configMap.Data[ref.Key]
// and appends each unique one to certificates.
func (r *ClusterJavaKeystoreReconciler) appendCertsFromConfigMapKey(configMap *corev1.ConfigMap, ref jksv1alpha1.ConfigMapReference, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	certs, err := r.validateAndExtractCertificatesFromConfigMap(configMap, ref)
	if err != nil {
		return certificates, err
	}
	for _, ci := range certs {
		certificates = appendUniqueCertificate(certificates, ci, "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "Key", ref.Key)
	}
	return certificates, nil
}

// systemConfigMapIsCurrent reports whether the on-cluster system ConfigMap already encodes
// the expected cert-set hash, has non-empty JKS bytes, and carries this CR's ownership
// stamps. When true, the keystore render+update can be skipped entirely.
func systemConfigMapIsCurrent(cm *corev1.ConfigMap, cjks *jksv1alpha1.ClusterJavaKeystore, hash string) bool {
	if cm.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] != hash {
		return false
	}
	if len(cm.BinaryData[DefaultJavaKeystoreConfigMapKey]) == 0 {
		return false
	}
	return hasOwnershipAnnotations(cm, "ClusterJavaKeystore", cjks.Name)
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

	if cmExists && systemConfigMapIsCurrent(existing, cjks, hash) {
		globalLog.Info("System ConfigMap already up to date (cert-hash matches), skipping render and update", "ConfigMapName", name.Name, "CertHash", hash)
		return nil
	}

	jksBytes, err := renderKeystoreBytes(certificates, password)
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
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ClusterJavaKeystore object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
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
	certificates = r.loadDefaultCACertificates(clusterJavaKeystore, req, certificates)

	certificates, err = r.collectConfigMapCertificates(ctx, clusterJavaKeystore, req, certificates)
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
	hash := computeCertSetHash(certificates)

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

func (r *ClusterJavaKeystoreReconciler) validateAndExtractCertificatesFromConfigMap(configMap *corev1.ConfigMap, configMapRef jksv1alpha1.ConfigMapReference) ([]CertificateNameMapping, error) {
	certificates := []CertificateNameMapping{}
	// Validate that the value of the specified key is a valid PEM encoded certificate
	// Multiple certificates can be included in a single PEM block so we look for the "BEGIN CERTIFICATE" header to determine if there is at least one certificate included in the value
	certificateFound := false
	certificateCount := 0
	data := []byte(configMap.Data[configMapRef.Key])
	// Loop through the blocks in the ConfigMap value to find all certificates available
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			// Check if we can parse this as an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				globalLog.Error(err, "Failed to parse certificate from PEM block, skipping this block", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key)
				// Continue processing even if parsing fails to ensure that other valid certificates are still extracted
				continue
			}
			certificateFound = true
			certificateCount++

			// Some root CAs don't have a CommonName in the Subject field so we grab the next best thing(s)
			determinedCommonName := determineCommonNameForCertificate(cert)

			// Encode the certificate back for storage in the Java Keystore
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			var pemBuffer bytes.Buffer
			if err := pem.Encode(&pemBuffer, pemBlock); err != nil {
				globalLog.Error(err, "Failed to encode certificate back to PEM format", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "CertificateCommonName", determinedCommonName)
				// Continue processing even if encoding fails to ensure that other valid certificates are still extracted
				continue
			}
			// Next we check to make sure the determinedCommonName is unique among the certificates we have processed so far. If it is not, we will append a number to the end of it to ensure uniqueness since Common Names are not guaranteed to be unique among different certificates and we want to use the Common Name as part of the alias for the certificate in the Java Keystore.
			originalCommonName := determinedCommonName
			duplicateCount := 1
			for {
				isDuplicate := false
				for _, certInfo := range certificates {
					if certInfo.CommonName == determinedCommonName {
						isDuplicate = true
						break
					}
				}
				if isDuplicate {
					determinedCommonName = originalCommonName + " #" + fmt.Sprint(duplicateCount)
					duplicateCount++
				} else {
					break
				}
			}
			// Double check to ensure there are no duplicate certificates
			for _, existingCert := range certificates {
				if bytes.Equal(existingCert.CertificateBytes, pemBuffer.Bytes()) {
					globalLog.Info("Certificate with identical bytes already exists, skipping to avoid duplicates in Java Keystore", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "ExistingCertificateCommonName", existingCert.CommonName, "CurrentCertificateCommonName", determinedCommonName)
					continue
				}
			}
			// If we made it here, this certificate is valid and not a duplicate, so we can add it to the list of certificates to be added to the Java Keystore
			certificates = append(certificates, CertificateNameMapping{
				CommonName:       determinedCommonName,
				ExpirationDate:   cert.NotAfter,
				CreationDate:     cert.NotBefore,
				CertificateBytes: pemBuffer.Bytes(),
			})
		default:
			globalLog.Info("PEM block is not a certificate, skipping", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "PEMBlockType", block.Type)
		}
	}

	if !certificateFound {
		globalLog.Error(nil, "Value of specified key does not contain a valid PEM encoded certificate", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key)
		// Requeue with an error to trigger retry logic and surface the issue
		return nil, errors.New("value of specified key does not contain a valid PEM encoded certificate")
	} else {
		globalLog.Info("Value of specified key contains valid PEM encoded certificate(s)", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "CertificateCount", certificateCount)
	}

	return certificates, nil
}

// computeCertSetHash returns a stable SHA-256 (hex-encoded) over the source certificate bytes,
// independent of the input order. This is used as an idempotency marker on labeled target
// ConfigMaps because rendered JKS bytes are not byte-stable across runs (the underlying
// keystore library salts/timestamps the output, so a byte-for-byte comparison would always
// show a difference even when the set of certificates is unchanged).
func computeCertSetHash(certificates []CertificateNameMapping) string {
	sorted := make([][]byte, len(certificates))
	for i, c := range certificates {
		// copy so we don't mutate the caller's backing array via sort
		b := make([]byte, len(c.CertificateBytes))
		copy(b, c.CertificateBytes)
		sorted[i] = b
	}
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})
	h := sha256.New()
	for _, b := range sorted {
		h.Write(b)
		h.Write([]byte{0}) // delimiter so adjacent certs can't collide via concatenation
	}
	return hex.EncodeToString(h.Sum(nil))
}
