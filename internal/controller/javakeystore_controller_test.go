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
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

var _ = Describe("JavaKeystore Controller", func() {
	Context("When reconciling a CA-only resource", func() {
		const (
			resourceName = "char-jks-ca"
			sourceCMName = "char-jks-ca-source"
			sourceCMKey  = "ca.crt"
			testNS       = "default"
		)

		ctx := context.Background()
		var pemCert []byte

		BeforeEach(func() {
			By("generating a self-signed PEM certificate")
			pemCert = mustGenerateSelfSignedPEMCertificate("char-jks-ca")

			By("creating the source ConfigMap with the PEM certificate")
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: testNS},
				Data:       map[string]string{sourceCMKey: string(pemCert)},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			By("creating the JavaKeystore CR referencing the source ConfigMap")
			jks := &jksv1alpha1.JavaKeystore{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS},
				Spec: jksv1alpha1.JavaKeystoreSpec{
					RootCAConfigMaps: []jksv1alpha1.NamespacedConfigMapReference{
						{Name: sourceCMName, Key: sourceCMKey},
					},
				},
			}
			Expect(k8sClient.Create(ctx, jks)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the JavaKeystore CR")
			jks := &jksv1alpha1.JavaKeystore{ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, jks)

			By("cleaning up the source ConfigMap")
			srcCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, srcCM)

			// envtest does not run the GC controller, so child ConfigMap/Secret are not auto-cleaned.
			By("cleaning up the system ConfigMap")
			sysCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks", Namespace: testNS}}
			_ = k8sClient.Delete(ctx, sysCM)

			By("cleaning up the password Secret")
			sysSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks-password", Namespace: testNS}}
			_ = k8sClient.Delete(ctx, sysSecret)
		})

		It("produces a system ConfigMap and password Secret in the CR's namespace with correct ownership and source-hash", func() {
			By("Reconciling the resource")
			r := &JavaKeystoreReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: testNS},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the system ConfigMap exists with JKS bytes and source-hash annotation")
			sysCM := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks", Namespace: testNS}, sysCM)).To(Succeed())
			Expect(sysCM.BinaryData[DefaultJavaKeystoreConfigMapKey]).NotTo(BeEmpty())
			Expect(sysCM.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation]).NotTo(BeEmpty())
			Expect(sysCM.Annotations[DefaultOwningComponentAnnotationKey]).To(Equal(JKS_CR_Name))
			Expect(sysCM.Annotations[DefaultOwningInstanceAnnotationKey]).To(Equal(resourceName))

			By("verifying the OwnerReference points back to the JavaKeystore CR")
			Expect(sysCM.OwnerReferences).To(HaveLen(1))
			Expect(sysCM.OwnerReferences[0].Kind).To(Equal(JKS_CR_Name))
			Expect(sysCM.OwnerReferences[0].Name).To(Equal(resourceName))

			By("verifying the source-hash matches computeKeystoreSourceHash over the input cert")
			normalized := mustReencodePEM(pemCert)
			expectedHash := computeKeystoreSourceHash([]CertificateNameMapping{{CertificateBytes: normalized}}, nil)
			Expect(sysCM.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation]).To(Equal(expectedHash))

			By("verifying the password Secret exists with the default password")
			sysSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks-password", Namespace: testNS}, sysSecret)).To(Succeed())
			Expect(sysSecret.Data[DefaultJavaKeystorePasswordSecretKey]).To(Equal([]byte(DefaultJavaKeystorePassword)))
			Expect(sysSecret.Annotations[DefaultOwningComponentAnnotationKey]).To(Equal(JKS_CR_Name))
			Expect(sysSecret.Annotations[DefaultOwningInstanceAnnotationKey]).To(Equal(resourceName))
			Expect(sysSecret.OwnerReferences).To(HaveLen(1))
			Expect(sysSecret.OwnerReferences[0].Kind).To(Equal(JKS_CR_Name))
		})

		It("is idempotent — a second Reconcile with no source change leaves outputs untouched", func() {
			r := &JavaKeystoreReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

			By("first Reconcile")
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: testNS},
			})
			Expect(err).NotTo(HaveOccurred())

			cm1 := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks", Namespace: testNS}, cm1)).To(Succeed())
			rv1 := cm1.ResourceVersion

			By("second Reconcile")
			_, err = r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: testNS},
			})
			Expect(err).NotTo(HaveOccurred())

			cm2 := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks", Namespace: testNS}, cm2)).To(Succeed())
			Expect(cm2.ResourceVersion).To(Equal(rv1), "system ConfigMap should not be updated when the source-hash is unchanged")
		})
	})

	Context("When reconciling a resource with a TLS Secret reference", func() {
		const (
			resourceName  = "char-jks-tls"
			tlsSecretName = "char-jks-tls-source"
			tlsCN         = "char-jks-tls-leaf"
			testNS        = "default"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("generating a self-signed TLS keypair and creating it as a kubernetes.io/tls Secret")
			certPEM, keyPEM := mustGenerateSelfSignedTLSKeypair(tlsCN)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: testNS},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": certPEM,
					"tls.key": keyPEM,
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating the JavaKeystore CR referencing the TLS Secret")
			jks := &jksv1alpha1.JavaKeystore{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS},
				Spec: jksv1alpha1.JavaKeystoreSpec{
					TLSCertSecretRef: []jksv1alpha1.NamespacedSecretReference{
						{Name: tlsSecretName},
					},
				},
			}
			Expect(k8sClient.Create(ctx, jks)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the JavaKeystore CR")
			jks := &jksv1alpha1.JavaKeystore{ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, jks)

			By("cleaning up the source TLS Secret")
			src := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, src)

			By("cleaning up the system ConfigMap")
			sysCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks", Namespace: testNS}}
			_ = k8sClient.Delete(ctx, sysCM)

			By("cleaning up the password Secret")
			sysSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-jks-password", Namespace: testNS}}
			_ = k8sClient.Delete(ctx, sysSecret)
		})

		It("produces a keystore containing a PrivateKeyEntry for the leaf cert's CommonName", func() {
			By("Reconciling the resource")
			r := &JavaKeystoreReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: testNS},
			})
			Expect(err).NotTo(HaveOccurred())

			By("decoding the rendered keystore bytes")
			sysCM := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-jks", Namespace: testNS}, sysCM)).To(Succeed())
			jksBytes := sysCM.BinaryData[DefaultJavaKeystoreConfigMapKey]
			Expect(jksBytes).NotTo(BeEmpty())

			ks := keystore.New()
			Expect(ks.Load(bytes.NewReader(jksBytes), []byte(DefaultJavaKeystorePassword))).To(Succeed())

			By("asserting the leaf CN appears as a PrivateKeyEntry alias")
			Expect(ks.IsPrivateKeyEntry(tlsCN)).To(BeTrue(), "expected PrivateKeyEntry alias %q in rendered keystore; aliases were %v", tlsCN, ks.Aliases())
		})
	})

	Context("When reconciling a resource with custom targetConfigMap and targetSecret", func() {
		const (
			resourceName     = "char-jks-targets"
			sourceCMName     = "char-jks-targets-source"
			sourceCMKey      = "ca.crt"
			customCMName     = "my-custom-keystore-cm"
			customCMKey      = "my-truststore.jks"
			customSecretName = "my-custom-keystore-secret"
			customSecretKey  = "STORE_PASS"
			testNS           = "default"
			defaultCMSuffix  = "-jks"
			defaultSecretSfx = "-jks-password"
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("creating the source ConfigMap with a self-signed PEM cert")
			pemCert := mustGenerateSelfSignedPEMCertificate("char-jks-targets-ca")
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: testNS},
				Data:       map[string]string{sourceCMKey: string(pemCert)},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			By("creating the JavaKeystore CR with custom targetConfigMap and targetSecret")
			jks := &jksv1alpha1.JavaKeystore{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS},
				Spec: jksv1alpha1.JavaKeystoreSpec{
					RootCAConfigMaps: []jksv1alpha1.NamespacedConfigMapReference{
						{Name: sourceCMName, Key: sourceCMKey},
					},
					TargetConfigMap: jksv1alpha1.NamespacedConfigMapReference{
						Name: customCMName,
						Key:  customCMKey,
					},
					TargetSecret: jksv1alpha1.NamespacedSecretReference{
						Name: customSecretName,
						Key:  customSecretKey,
					},
				},
			}
			Expect(k8sClient.Create(ctx, jks)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the JavaKeystore CR")
			jks := &jksv1alpha1.JavaKeystore{ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, jks)

			By("cleaning up the source ConfigMap")
			src := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: sourceCMName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, src)

			By("cleaning up the custom-named ConfigMap")
			customCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: customCMName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, customCM)

			By("cleaning up the custom-named Secret")
			customSec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: customSecretName, Namespace: testNS}}
			_ = k8sClient.Delete(ctx, customSec)
		})

		It("writes the keystore + password to the user-specified names and keys, and not to the defaults", func() {
			By("Reconciling the resource")
			r := &JavaKeystoreReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: testNS},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the custom-named ConfigMap exists with bytes under the custom key")
			customCM := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: customCMName, Namespace: testNS}, customCM)).To(Succeed())
			Expect(customCM.BinaryData[customCMKey]).NotTo(BeEmpty())
			Expect(customCM.BinaryData[DefaultJavaKeystoreConfigMapKey]).To(BeEmpty(), "default key should not be populated when a custom Key is set")

			By("verifying the custom-named Secret exists with the password under the custom key")
			customSec := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: customSecretName, Namespace: testNS}, customSec)).To(Succeed())
			Expect(customSec.Data[customSecretKey]).To(Equal([]byte(DefaultJavaKeystorePassword)))
			Expect(customSec.Data[DefaultJavaKeystorePasswordSecretKey]).To(BeEmpty(), "default key should not be populated when a custom Key is set")

			By("verifying the default-named ConfigMap was NOT created")
			defaultCM := &corev1.ConfigMap{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + defaultCMSuffix, Namespace: testNS}, defaultCM)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "default-named ConfigMap should not exist when targetConfigMap is set; got err=%v", err)

			By("verifying the default-named Secret was NOT created")
			defaultSec := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + defaultSecretSfx, Namespace: testNS}, defaultSec)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "default-named Secret should not exist when targetSecret is set; got err=%v", err)
		})
	})
})

// mustGenerateSelfSignedTLSKeypair returns a PEM-encoded leaf certificate and PEM-encoded
// PKCS8 private key suitable for stuffing into a kubernetes.io/tls Secret. The cert is
// self-signed (issuer == subject) so it works as both leaf and root inside the test
// keystore — sufficient to exercise the PrivateKeyEntry path.
func mustGenerateSelfSignedTLSKeypair(cn string) (certPEM, keyPEM []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	Expect(err).NotTo(HaveOccurred())

	var certBuf bytes.Buffer
	Expect(pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})).To(Succeed())

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	Expect(err).NotTo(HaveOccurred())
	var keyBuf bytes.Buffer
	Expect(pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})).To(Succeed())

	return certBuf.Bytes(), keyBuf.Bytes()
}
