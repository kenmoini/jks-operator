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
	"time"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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
	globalLog = ctrl.Log.WithName("jks-operator-clusterjks")

	clusterJavaKeystore := &jksv1alpha1.ClusterJavaKeystore{}
	// enumeratedCertificates := make(map[string]CertificateNameMapping)
	certificates := []CertificateNameMapping{}
	globalLog.Info("Reconciling ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

	if err := r.Get(ctx, req.NamespacedName, clusterJavaKeystore); err != nil {
		globalLog.Error(err, "Failed to fetch ClusterJavaKeystore", "NamespacedName", req.NamespacedName)
		return ctrl.Result{RequeueAfter: time.Second * 30}, client.IgnoreNotFound(err)
	} else {
		globalLog.Info("Successfully fetched ClusterJavaKeystore", "NamespacedName", req.NamespacedName)

		// Enumerate through the ConfigMaps referenced in the ClusterJavaKeystore and map them
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
						certificates = append(certificates, certs...)

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
						certificates = append(certificates, certs...)
					}
				}
			}
		}

		// Loop through the enumerated certificates and log their Common Names and Expiration Dates
		if len(certificates) > 0 {
			for _, certInfo := range certificates {
				globalLog.Info("Certificate found", "CommonName", certInfo.CommonName, "ExpirationDate", certInfo.ExpirationDate)
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
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}
			certificateFound = true
			certificateCount++

			// Some root CAs don't have a CommonName in the Subject field so we grab the next best things
			determinedCommonName := ""
			if len(cert.Subject.CommonName) > 0 {
				determinedCommonName = cert.Subject.CommonName
			} else {
				if len(cert.Subject.OrganizationalUnit) > 0 {
					determinedCommonName = cert.Subject.OrganizationalUnit[0]
				} else {
					if len(cert.Subject.Organization) > 0 {
						determinedCommonName = cert.Subject.Organization[0]
					} else {
						determinedCommonName = "Unknown Common Name # " + fmt.Sprint(certificateCount)
					}
				}
			}
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
			for _, existingCert := range certificates {
				if bytes.Equal(existingCert.CertificateBytes, pemBuffer.Bytes()) {
					globalLog.Info("Certificate with identical bytes already exists, skipping to avoid duplicates in Java Keystore", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "ExistingCertificateCommonName", existingCert.CommonName, "CurrentCertificateCommonName", determinedCommonName)
					continue
				}
			}
			certificates = append(certificates, CertificateNameMapping{
				CommonName:       determinedCommonName,
				ExpirationDate:   cert.NotAfter.Format(time.RFC3339),
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
