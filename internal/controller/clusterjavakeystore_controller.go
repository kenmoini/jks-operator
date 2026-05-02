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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
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
			return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
		} else {
			globalLog.Info("Successfully fetched SystemNamespace specified in ClusterJavaKeystore spec", "NamespacedName", req.NamespacedName, "SystemNamespace", clusterJavaKeystore.Spec.SystemNamespace)
		}

		// =====================================================================================================================================
		// Check if the KeyStorePasswordSecretRef is set, if so grab the Secret, if not set it to a default of "changeit"
		keyStorePassword := DefaultJavaKeystorePassword
		if clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name != "" && clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace != "" {
			globalLog.Info("KeyStorePasswordSecretRef is set in ClusterJavaKeystore spec, attempting to fetch Secret for KeyStore password", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace)
			passwordSecret, err := GetSecret(clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace, r.Client)
			if err != nil {
				globalLog.Error(err, "Failed to fetch Secret specified in KeyStorePasswordSecretRef for KeyStore password, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace)
			} else {
				globalLog.Info("Successfully fetched Secret specified in KeyStorePasswordSecretRef for KeyStore password", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace)
				if clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Key != "" {
					if password, keyExists := passwordSecret.Data[clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Key]; keyExists {
						keyStorePassword = string(password)
						globalLog.Info("Successfully retrieved KeyStore password from Secret specified in KeyStorePasswordSecretRef", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace, "KeyUsed", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Key)
					} else {
						globalLog.Error(nil, "Specified key in KeyStorePasswordSecretRef does not exist in Secret, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace, "MissingKey", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Key)
					}
				} else {
					if password, keyExists := passwordSecret.Data["password"]; keyExists {
						keyStorePassword = string(password)
						globalLog.Info("Successfully retrieved KeyStore password from Secret specified in KeyStorePasswordSecretRef using default key 'password'", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace, "KeyUsed", "password")
					} else {
						globalLog.Error(nil, "Default key 'password' does not exist in Secret specified in KeyStorePasswordSecretRef, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName, "SecretName", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Name, "SecretNamespace", clusterJavaKeystore.Spec.KeyStorePasswordSecretRef.Namespace, "MissingKey", "password")
					}
				}
			}
		} else {
			globalLog.Info("KeyStorePasswordSecretRef is not set in ClusterJavaKeystore spec, defaulting to '"+DefaultJavaKeystorePassword+"'", "NamespacedName", req.NamespacedName)
		}

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
			// Create a new Keystore object
			ks, err := createJavaKeystore()
			if err != nil {
				globalLog.Error(err, "Failed to create Java Keystore object")
				return ctrl.Result{RequeueAfter: time.Second * 30}, err
			}

			// =====================================================================================================================================
			// Loop through the enumerated certificates and log their Common Names and Expiration Dates
			for _, certInfo := range certificates {
				globalLog.Info("Certificate found", "CommonName", certInfo.CommonName, "ExpirationDate", certInfo.ExpirationDate)
				// Create TCE
				aliase, tce := createTrustedCertificateEntry(certInfo)
				// Add the TCE to the Keystore
				if err := ks.SetTrustedCertificateEntry(aliase, tce); err != nil {
					globalLog.Error(err, "Failed to add Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
				} else {
					globalLog.Info("Successfully added Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
				}
			}

			// Create a ConfigMap in the system namespace with binaryData to store the JKS
			generatedConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterJavaKeystore.Name + "-jks",
					Namespace: clusterJavaKeystore.Spec.SystemNamespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(clusterJavaKeystore, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
					},
				},
				BinaryData: map[string][]byte{},
			}

			// Store the JKS in a buffer and then set the buffer bytes to the BinaryData of the ConfigMap
			// We have to store it in a buffer first because the keystore library writes the JKS to an io.Writer and does not return the bytes directly, so we use a bytes.Buffer as the io.Writer to capture the bytes of the generated JKS.
			var jksBuffer bytes.Buffer
			if err := ks.Store(&jksBuffer, []byte(keyStorePassword)); err != nil {
				globalLog.Error(err, "Failed to store Java Keystore to buffer", "NamespacedName", req.NamespacedName)
				return ctrl.Result{RequeueAfter: time.Second * 30}, err
			} else {
				globalLog.Info("Successfully stored Java Keystore to buffer", "NamespacedName", req.NamespacedName)
			}

			// Set the bytes of the generated JKS to the BinaryData of the ConfigMap under the key "keystore.jks" by default
			generatedConfigMap.BinaryData[DefaultJavaKeystoreConfigMapKey] = jksBuffer.Bytes()

			// Check if the ConfigMap already exists
			existingConfigMap := &corev1.ConfigMap{}
			err = r.Get(ctx, types.NamespacedName{Name: generatedConfigMap.Name, Namespace: generatedConfigMap.Namespace}, existingConfigMap)
			if err != nil && kapierrors.IsNotFound(err) {
				// If the ConfigMap does not exist, create it
				if err := r.Create(ctx, generatedConfigMap); err != nil {
					globalLog.Error(err, "Failed to create ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", generatedConfigMap.Name, "ConfigMapNamespace", generatedConfigMap.Namespace)
					return ctrl.Result{RequeueAfter: time.Second * 30}, err
				} else {
					globalLog.Info("Successfully created ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", generatedConfigMap.Name, "ConfigMapNamespace", generatedConfigMap.Namespace)
				}
			} else if err != nil {
				globalLog.Error(err, "Failed to fetch existing ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", generatedConfigMap.Name, "ConfigMapNamespace", generatedConfigMap.Namespace)
				return ctrl.Result{RequeueAfter: time.Second * 30}, err
			} else {
				// Check if the existing ConfigMap's BinaryData is different from the generated ConfigMap's BinaryData, and if so, update it
				// TODO/NOTE: Tecnically this comparison will always show a difference because of how the JKS is generated with a password, the hash will always be different thus creating a different byte array even if the certificates included are the same.
				if !reflect.DeepEqual(existingConfigMap.BinaryData, generatedConfigMap.BinaryData) {
					existingConfigMap.BinaryData = generatedConfigMap.BinaryData
					if err := r.Update(ctx, existingConfigMap); err != nil {
						globalLog.Error(err, "Failed to update ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", existingConfigMap.Name, "ConfigMapNamespace", existingConfigMap.Namespace)
						return ctrl.Result{RequeueAfter: time.Second * 30}, err
					} else {
						globalLog.Info("Successfully updated ConfigMap to store generated Java Keystore", "NamespacedName", req.NamespacedName, "ConfigMapName", existingConfigMap.Name, "ConfigMapNamespace", existingConfigMap.Namespace)
					}
				} else {
					globalLog.Info("ConfigMap to store generated Java Keystore already exists and is up to date, no update needed", "NamespacedName", req.NamespacedName, "ConfigMapName", existingConfigMap.Name, "ConfigMapNamespace", existingConfigMap.Namespace)
				}
			}

			// Create or Update a Secret in the system namespace to store the password for the JKS
			generatedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterJavaKeystore.Name + "-jks-password",
					Namespace: clusterJavaKeystore.Spec.SystemNamespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(clusterJavaKeystore, jksv1alpha1.GroupVersion.WithKind("ClusterJavaKeystore")),
					},
				},
				Data: map[string][]byte{
					"password": []byte(keyStorePassword),
				},
			}

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
				// Check if the existing Secret's Data is different from the generated Secret's Data, and if so, update it
				if !reflect.DeepEqual(existingSecret.Data, generatedSecret.Data) {
					existingSecret.Data = generatedSecret.Data
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
