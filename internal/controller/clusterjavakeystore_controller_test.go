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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

var _ = Describe("ClusterJavaKeystore Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		clusterjavakeystore := &jksv1alpha1.ClusterJavaKeystore{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind ClusterJavaKeystore")
			err := k8sClient.Get(ctx, typeNamespacedName, clusterjavakeystore)
			if err != nil && errors.IsNotFound(err) {
				resource := &jksv1alpha1.ClusterJavaKeystore{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &jksv1alpha1.ClusterJavaKeystore{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance ClusterJavaKeystore")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &ClusterJavaKeystoreReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})

	Context("When a referenced ConfigMap holds a PEM certificate", func() {
		const (
			resourceName    = "char-test"
			sourceCMName    = "char-test-ca-source"
			sourceCMKey     = "ca.crt"
			systemNamespace = "jks-operator"
		)

		ctx := context.Background()

		var pemCert []byte

		BeforeEach(func() {
			By("generating a self-signed PEM certificate")
			pemCert = mustGenerateSelfSignedPEMCertificate("char-test-ca")

			By("ensuring the system namespace exists")
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: systemNamespace}}
			err := k8sClient.Create(ctx, ns)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			By("creating the source ConfigMap with the PEM certificate")
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: "default"},
				Data:       map[string]string{sourceCMKey: string(pemCert)},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			By("creating the ClusterJavaKeystore CR referencing the source ConfigMap")
			cjks := &jksv1alpha1.ClusterJavaKeystore{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName},
				Spec: jksv1alpha1.ClusterJavaKeystoreSpec{
					RootCAConfigMaps: []jksv1alpha1.ConfigMapReference{
						{Name: sourceCMName, Namespace: "default", Key: sourceCMKey},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cjks)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the ClusterJavaKeystore CR")
			cjks := &jksv1alpha1.ClusterJavaKeystore{ObjectMeta: metav1.ObjectMeta{Name: resourceName}}
			_ = k8sClient.Delete(ctx, cjks)

			By("cleaning up the source ConfigMap")
			srcCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: "default"}}
			_ = k8sClient.Delete(ctx, srcCM)

			// envtest does not run the GC controller, so child ConfigMap/Secret are not auto-cleaned.
			By("cleaning up the system ConfigMap")
			sysCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks", Namespace: systemNamespace}}
			_ = k8sClient.Delete(ctx, sysCM)

			By("cleaning up the password Secret")
			sysSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks-password", Namespace: systemNamespace}}
			_ = k8sClient.Delete(ctx, sysSecret)
		})

		It("produces a system ConfigMap and password Secret with correct ownership and cert-hash", func() {
			By("Reconciling the resource")
			r := &ClusterJavaKeystoreReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the system ConfigMap exists with JKS bytes and cert-hash annotation")
			sysCM := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks", Namespace: systemNamespace}, sysCM)).To(Succeed())
			Expect(sysCM.BinaryData[DefaultJavaKeystoreConfigMapKey]).NotTo(BeEmpty())
			Expect(sysCM.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation]).NotTo(BeEmpty())
			Expect(sysCM.Annotations[DefaultOwningComponentAnnotationKey]).To(Equal("ClusterJavaKeystore"))
			Expect(sysCM.Annotations[DefaultOwningInstanceAnnotationKey]).To(Equal(resourceName))

			By("verifying the cert-hash matches computeCertSetHash over the input cert")
			normalized := mustReencodePEM(pemCert)
			expectedHash := computeCertSetHash([]CertificateNameMapping{{CertificateBytes: normalized}})
			Expect(sysCM.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation]).To(Equal(expectedHash))

			By("verifying the password Secret exists with the default password")
			sysSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks-password", Namespace: systemNamespace}, sysSecret)).To(Succeed())
			Expect(sysSecret.Data[DefaultJavaKeystorePasswordSecretKey]).To(Equal([]byte(DefaultJavaKeystorePassword)))
			Expect(sysSecret.Annotations[DefaultOwningComponentAnnotationKey]).To(Equal("ClusterJavaKeystore"))
			Expect(sysSecret.Annotations[DefaultOwningInstanceAnnotationKey]).To(Equal(resourceName))
		})
	})
})

// mustGenerateSelfSignedPEMCertificate returns a PEM-encoded self-signed X.509 certificate
// suitable for use as a root CA in characterization tests.
func mustGenerateSelfSignedPEMCertificate(cn string) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	Expect(err).NotTo(HaveOccurred())
	var buf bytes.Buffer
	Expect(pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})).To(Succeed())
	return buf.Bytes()
}

// mustReencodePEM parses then re-encodes a PEM certificate, matching the normalisation the
// controller applies before storing CertificateBytes (see parseAndEncodePEMCertificate /
// the inline parse+encode in the controller). Tests that compare cert-hashes must use this
// representation, not the raw input PEM.
func mustReencodePEM(in []byte) []byte {
	block, _ := pem.Decode(in)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	var out bytes.Buffer
	Expect(pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})).To(Succeed())
	return out.Bytes()
}
