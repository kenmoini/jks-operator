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
	// _ = logf.FromContext(ctx)

	// =====================================================================================================================================
	clusterJavaKeystore := &jksv1alpha1.ClusterJavaKeystore{}
	certificates := []CertificateNameMapping{}

	// =====================================================================================================================================
	globalLog = ctrl.Log.WithName("jks-operator-clusterjks")
	globalLog.Info("Reconciling ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

	if err := r.Get(ctx, req.NamespacedName, clusterJavaKeystore); err != nil {
		globalLog.Error(err, "Failed to fetch ClusterJavaKeystore", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	} else {
		globalLog.Info("Successfully fetched ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

		// =====================================================================================================================================
		// Next, determine the system namespace
		systemNamespace, err := r.getSystemNamespace(clusterJavaKeystore, ctx, req)
		if err != nil {
			globalLog.Error(err, "Failed to determine SystemNamespace for ClusterJavaKeystore", "NamespacedName", req.NamespacedName)
			return ctrl.Result{RequeueAfter: time.Second * 30}, err
		}

		// =====================================================================================================================================
		keyStorePassword := r.resolveKeystorePassword(clusterJavaKeystore, req)

		// =====================================================================================================================================
		// Check if we're including the default trusted CA store certificates and if so, attempt to read them in and include them in the list of certificates to be added to the Java Keystore. If the default CA certificates file cannot be read for any reason, we will log the error and continue processing without including the default CA certificates since the user may not care about including them and we don't want a failure to read the default CA certificates to prevent any other valid certificates from being added to the Java Keystore.
		if clusterJavaKeystore.Spec.AddDefaultCACertificates {
			systemCACertPath := clusterJavaKeystore.Spec.DefaultCACertificatesPath
			if systemCACertPath == "" {
				// If the user did not specify a custom path for the default CA certificates, we will attempt to read them from the default location in the UBI container since that is the most likely scenario for where this controller will be running. If the file cannot be read from the default location, we will log the error and continue processing without including the default CA certificates since the user may not care about including them and we don't want a failure to read the default CA certificates to prevent any other valid certificates from being added to the Java Keystore.
				systemCACertPath = DefaultCACertificatesPath
			}
			globalLog.Info("Attempting to read default CA certificates from file", "FilePath", systemCACertPath)
			defaultCACertsData, err := os.ReadFile(systemCACertPath)
			if err != nil {
				globalLog.Error(err, "Failed to read default CA certificates from file, continuing without including default CA certificates", "FilePath", systemCACertPath)
			} else {
				globalLog.Info("Successfully read default CA certificates from file, processing certificates", "FilePath", systemCACertPath)
				for block, rest := pem.Decode(defaultCACertsData); block != nil; block, rest = pem.Decode(rest) {
					if block.Type == "CERTIFICATE" {
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							globalLog.Error(err, "Failed to parse certificate from PEM block for default CA certificate, skipping this certificate", "FilePath", systemCACertPath)
							continue
						}
						determinedCommonName := determineCommonNameForCertificate(cert)

						pemBlock := &pem.Block{
							Type:  "CERTIFICATE",
							Bytes: cert.Raw,
						}
						var pemBuffer bytes.Buffer
						if err := pem.Encode(&pemBuffer, pemBlock); err != nil {
							globalLog.Error(err, "Failed to encode certificate back to PEM format for default CA certificate, skipping this certificate", "FilePath", systemCACertPath, "CertificateCommonName", determinedCommonName)
							continue
						}
						// Ensure there are no duplicate certificates being added to the list by comparing the bytes of the certificates since Common Names are not guaranteed to be unique among different certificates. If a duplicate is found, it will be skipped and not added to the list to avoid issues with adding duplicate certificates to the Java Keystore.
						isDuplicate := false
						for _, existingCert := range certificates {
							if bytes.Equal(existingCert.CertificateBytes, pemBuffer.Bytes()) {
								globalLog.Info("Certificate with identical bytes already exists, skipping to avoid duplicates in Java Keystore", "FilePath", systemCACertPath, "CertificateCommonName", determinedCommonName)
								isDuplicate = true
								break
							}
						}
						if !isDuplicate {
							certificates = append(certificates, CertificateNameMapping{
								CommonName:       determinedCommonName,
								ExpirationDate:   cert.NotAfter,
								CreationDate:     cert.NotBefore,
								CertificateBytes: pemBuffer.Bytes(),
							})
						}
					} else {
						globalLog.Info("PEM block is not a certificate, skipping", "FilePath", systemCACertPath, "PEMBlockType", block.Type)
					}
				}
			}
		} else {
			globalLog.Info("Not including default CA certificates as specified in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName)
		}

		// =====================================================================================================================================
		// Enumerate through the ConfigMaps referenced in the ClusterJavaKeystore and map them
		if len(clusterJavaKeystore.Spec.RootCAConfigMaps) > 0 {
			for _, configMapRef := range clusterJavaKeystore.Spec.RootCAConfigMaps {
				globalLog.Info("Processing ConfigMap reference", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace)

				configMap := &corev1.ConfigMap{}
				if err := r.Get(ctx, types.NamespacedName{Name: configMapRef.Name, Namespace: configMapRef.Namespace}, configMap); err != nil {
					globalLog.Error(err, "Failed to fetch ConfigMap", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace)
					return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
				} else {
					globalLog.Info("Successfully fetched ConfigMap", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace)

					// If there was a key specified in the reference, validate that it exists in the ConfigMap
					if configMapRef.Key != "" {
						if _, keyExists := configMap.Data[configMapRef.Key]; !keyExists {
							globalLog.Error(nil, "Specified key does not exist in ConfigMap", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "MissingKey", configMapRef.Key)
							// Requeue with an error to trigger retry logic and surface the issue
							return ctrl.Result{RequeueAfter: time.Second * 30}, nil
						} else {
							globalLog.Info("Specified key exists in ConfigMap", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key)

							certs, err := r.validateAndExtractCertificatesFromConfigMap(configMap, configMapRef)
							if err != nil {
								globalLog.Error(err, "Failed to validate and extract certificates from ConfigMap", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key)
								return ctrl.Result{RequeueAfter: time.Second * 30}, nil
							}
							// Ensure there are no duplicate certificates being added to the list by comparing the bytes of the certificates since Common Names are not guaranteed to be unique among different certificates. If a duplicate is found, it will be skipped and not added to the list to avoid issues with adding duplicate certificates to the Java Keystore.
							for _, certInfo := range certs {
								isDuplicate := false
								for _, existingCert := range certificates {
									if bytes.Equal(existingCert.CertificateBytes, certInfo.CertificateBytes) {
										globalLog.Info("Certificate with identical bytes already exists, skipping to avoid duplicates in Java Keystore", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "ExistingCertificateCommonName", existingCert.CommonName, "CurrentCertificateCommonName", certInfo.CommonName)
										isDuplicate = true
										break
									}
								}
								if !isDuplicate {
									certificates = append(certificates, certInfo)
								}
							}
							// certificates = append(certificates, certs...)

						}
					} else {
						globalLog.Info("No specific key specified for ConfigMap reference, all keys will be processed if they contain valid PEM encoded certificates", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace)

						// If no key was specified in the reference, we will attempt to validate all the keys in the ConfigMap and extract any valid PEM encoded certificates found
						for key := range configMap.Data {
							configMapRefWithKey := jksv1alpha1.ConfigMapReference{
								Name:      configMapRef.Name,
								Namespace: configMapRef.Namespace,
								Key:       key,
							}
							certs, err := r.validateAndExtractCertificatesFromConfigMap(configMap, configMapRefWithKey)
							if err != nil {
								globalLog.Error(err, "Failed to validate and extract certificates from ConfigMap for specific key", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", key)
								// Continue processing the other keys even if one key fails validation to ensure that any valid certificates are still extracted
								continue
							}
							// Ensure there are no duplicate certificates being added to the list by comparing the bytes of the certificates since Common Names are not guaranteed to be unique among different certificates. If a duplicate is found, it will be skipped and not added to the list to avoid issues with adding duplicate certificates to the Java Keystore.
							for _, certInfo := range certs {
								isDuplicate := false
								for _, existingCert := range certificates {
									if bytes.Equal(existingCert.CertificateBytes, certInfo.CertificateBytes) {
										globalLog.Info("Certificate with identical bytes already exists, skipping to avoid duplicates in Java Keystore", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "ExistingCertificateCommonName", existingCert.CommonName, "CurrentCertificateCommonName", certInfo.CommonName)
										isDuplicate = true
										break
									}
								}
								if !isDuplicate {
									certificates = append(certificates, certInfo)
								}
							}
							// certificates = append(certificates, certs...)
						}
					}
				}
			}
		} else {
			globalLog.Info("No ConfigMap references found in ClusterJavaKeystore, skipping certificate enumeration", "NamespacedName", req.NamespacedName)
		}

		// =====================================================================================================================================
		// If we have detected valid certificates, continue to creating the JKS and Secret/ConfigMap
		if len(certificates) > 0 {
			// Log the enumerated certificates for visibility before keystore assembly.
			for _, certInfo := range certificates {
				globalLog.Info("Certificate found", "CommonName", certInfo.CommonName, "ExpirationDate", certInfo.ExpirationDate)
			}

			// Compute the cert-set hash up front. This is the canonical fingerprint of the
			// source-cert set: matching hash means an unchanged keystore, even though the rendered
			// JKS bytes are non-deterministic (the keystore-go library salts/timestamps the output).
			// Two wins: we can skip the JKS render entirely when the system ConfigMap already
			// reflects this exact cert set, and downstream injector controllers can read this hash
			// directly off the system ConfigMap to drive their own idempotency.
			wantHash := computeCertSetHash(certificates)
			systemCMName := types.NamespacedName{
				Name:      clusterJavaKeystore.Name + "-jks",
				Namespace: systemNamespace,
			}

			existingConfigMap := &corev1.ConfigMap{}
			cmGetErr := r.Get(ctx, systemCMName, existingConfigMap)
			if cmGetErr != nil && !kapierrors.IsNotFound(cmGetErr) {
				globalLog.Error(cmGetErr, "Failed to fetch existing ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", systemCMName.Name, "ConfigMapNamespace", systemCMName.Namespace)
				return ctrl.Result{RequeueAfter: time.Second * 30}, cmGetErr
			}
			cmExists := cmGetErr == nil

			if cmExists &&
				existingConfigMap.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] == wantHash &&
				len(existingConfigMap.BinaryData[DefaultJavaKeystoreConfigMapKey]) > 0 &&
				hasOwnershipAnnotations(existingConfigMap, "ClusterJavaKeystore", clusterJavaKeystore.Name) {
				globalLog.Info("System ConfigMap already up to date (cert-hash matches), skipping render and update",
					"NamespacedName", req.NamespacedName, "ConfigMapName", systemCMName.Name, "CertHash", wantHash)
			} else {
				// Render and create-or-update.
				jksBytes, err := renderKeystoreBytes(certificates, keyStorePassword)
				if err != nil {
					globalLog.Error(err, "Failed to render Java Keystore bytes", "NamespacedName", req.NamespacedName)
					return ctrl.Result{RequeueAfter: time.Second * 30}, err
				}
				globalLog.Info("Successfully rendered Java Keystore bytes", "NamespacedName", req.NamespacedName)

				if !cmExists {
					generatedConfigMap := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name:      systemCMName.Name,
							Namespace: systemCMName.Namespace,
							OwnerReferences: []metav1.OwnerReference{
								*metav1.NewControllerRef(clusterJavaKeystore, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
							},
						},
						BinaryData: map[string][]byte{
							DefaultJavaKeystoreConfigMapKey: jksBytes,
						},
					}
					setOwnershipAnnotations(generatedConfigMap, "ClusterJavaKeystore", clusterJavaKeystore.Name)
					generatedConfigMap.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = wantHash
					if err := r.Create(ctx, generatedConfigMap); err != nil {
						globalLog.Error(err, "Failed to create ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", generatedConfigMap.Name, "ConfigMapNamespace", generatedConfigMap.Namespace)
						return ctrl.Result{RequeueAfter: time.Second * 30}, err
					}
					globalLog.Info("Successfully created ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", generatedConfigMap.Name, "ConfigMapNamespace", generatedConfigMap.Namespace, "CertHash", wantHash)
				} else {
					if existingConfigMap.BinaryData == nil {
						existingConfigMap.BinaryData = map[string][]byte{}
					}
					existingConfigMap.BinaryData[DefaultJavaKeystoreConfigMapKey] = jksBytes
					setOwnershipAnnotations(existingConfigMap, "ClusterJavaKeystore", clusterJavaKeystore.Name)
					existingConfigMap.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] = wantHash
					if err := r.Update(ctx, existingConfigMap); err != nil {
						globalLog.Error(err, "Failed to update ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", existingConfigMap.Name, "ConfigMapNamespace", existingConfigMap.Namespace)
						return ctrl.Result{RequeueAfter: time.Second * 30}, err
					}
					globalLog.Info("Successfully updated ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", existingConfigMap.Name, "ConfigMapNamespace", existingConfigMap.Namespace, "CertHash", wantHash)
				}
			}

			// Create or Update a Secret in the system namespace to store the password for the JKS
			generatedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterJavaKeystore.Name + "-jks-password",
					Namespace: systemNamespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(clusterJavaKeystore, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
					},
				},
				Data: map[string][]byte{
					DefaultJavaKeystorePasswordSecretKey: []byte(keyStorePassword),
				},
			}
			setOwnershipAnnotations(generatedSecret, "ClusterJavaKeystore", clusterJavaKeystore.Name)

			existingSecret := &corev1.Secret{}
			err = r.Get(ctx, types.NamespacedName{Name: generatedSecret.Name, Namespace: generatedSecret.Namespace}, existingSecret)
			if err != nil && kapierrors.IsNotFound(err) {
				// If the Secret does not exist, create it
				if err := r.Create(ctx, generatedSecret); err != nil {
					globalLog.Error(err, "Failed to create Secret to store Java Keystore password", "NamespacedName", req.NamespacedName, "SecretName", generatedSecret.Name, "SecretNamespace", generatedSecret.Namespace)
					return ctrl.Result{RequeueAfter: time.Second * 30}, err
				} else {
					globalLog.Info("Successfully created Secret to store Java Keystore password", "NamespacedName", req.NamespacedName, "SecretName", generatedSecret.Name, "SecretNamespace", generatedSecret.Namespace)
				}
			} else if err != nil {
				globalLog.Error(err, "Failed to fetch existing Secret to store Java Keystore password", "NamespacedName", req.NamespacedName, "SecretName", generatedSecret.Name, "SecretNamespace", generatedSecret.Namespace)
				return ctrl.Result{RequeueAfter: time.Second * 30}, err
			} else {
				// Check if the existing Secret's Data differs OR ownership annotations are missing/wrong, and if so, update it
				ownershipNeedsUpdate := !hasOwnershipAnnotations(existingSecret, "ClusterJavaKeystore", clusterJavaKeystore.Name)
				if !reflect.DeepEqual(existingSecret.Data, generatedSecret.Data) || ownershipNeedsUpdate {
					existingSecret.Data = generatedSecret.Data
					setOwnershipAnnotations(existingSecret, "ClusterJavaKeystore", clusterJavaKeystore.Name)
					if err := r.Update(ctx, existingSecret); err != nil {
						globalLog.Error(err, "Failed to update Secret to store Java Keystore password", "NamespacedName", req.NamespacedName, "SecretName", existingSecret.Name, "SecretNamespace", existingSecret.Namespace)
						return ctrl.Result{RequeueAfter: time.Second * 30}, err
					} else {
						globalLog.Info("Successfully updated Secret to store Java Keystore password", "NamespacedName", req.NamespacedName, "SecretName", existingSecret.Name, "SecretNamespace", existingSecret.Namespace)
					}
				} else {
					globalLog.Info("Secret to store Java Keystore password already exists and is up to date, no update needed", "NamespacedName", req.NamespacedName, "SecretName", existingSecret.Name, "SecretNamespace", existingSecret.Namespace)
				}
			}

			// Labeled-target injection (ConfigMap and Secret) is handled by the dedicated
			// injector controllers — see clusterjavakeystore_configmap_injector_controller.go
			// and clusterjavakeystore_secret_injector_controller.go. They watch the system
			// ConfigMap/Secret we just wrote above and fan out per-target.
		} else {
			globalLog.Info("No certificates found in any of the referenced ConfigMaps", "NamespacedName", req.NamespacedName)
		}
	}

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
