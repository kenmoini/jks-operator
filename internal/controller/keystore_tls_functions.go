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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

// Standard Kubernetes TLS Secret data keys. These are fixed by the corev1.SecretTypeTLS
// contract and are NOT taken from NamespacedSecretReference.Key — that field is reserved
// for password Secrets where the user names the key explicitly.
const (
	tlsSecretCertKey = "tls.crt"
	tlsSecretKeyKey  = "tls.key"
)

// KeypairEntry holds the parsed leaf cert + chain + normalised PKCS8 private key for a
// single TLS Secret reference, ready to drop into the rendered Java Keystore as a
// PrivateKeyEntry. CertificateChain[0] is the leaf; subsequent entries are intermediates.
// PrivateKeyPKCS8 is always normalised to PKCS#8 DER regardless of the source key format
// so the keystore-go library can serialise it without ambiguity.
type KeypairEntry struct {
	Alias            string
	CertificateChain [][]byte // each entry is DER-encoded cert (leaf first, then intermediates)
	PrivateKeyPKCS8  []byte   // normalized PKCS8 DER
	CreationDate     time.Time
}

// parseTLSSecret extracts cert chain and private key from a Kubernetes TLS Secret.
// The Secret must contain `tls.crt` (PEM-encoded chain) and `tls.key` (PEM-encoded
// private key in PKCS1 / PKCS8 / SEC1 EC format). The returned alias derives from the
// leaf cert's CommonName via the existing OU/O fallback chain; per-keystore uniqueness
// is the caller's job.
func parseTLSSecret(secret *corev1.Secret) (KeypairEntry, error) {
	certPEM, ok := secret.Data[tlsSecretCertKey]
	if !ok || len(certPEM) == 0 {
		return KeypairEntry{}, fmt.Errorf("TLS Secret %s/%s missing %q", secret.Namespace, secret.Name, tlsSecretCertKey)
	}
	keyPEM, ok := secret.Data[tlsSecretKeyKey]
	if !ok || len(keyPEM) == 0 {
		return KeypairEntry{}, fmt.Errorf("TLS Secret %s/%s missing %q", secret.Namespace, secret.Name, tlsSecretKeyKey)
	}

	chain, leaf, err := parseCertChain(certPEM)
	if err != nil {
		return KeypairEntry{}, fmt.Errorf("TLS Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	keyDER, err := parsePrivateKeyToPKCS8(keyPEM)
	if err != nil {
		return KeypairEntry{}, fmt.Errorf("TLS Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return KeypairEntry{
		Alias:            determineCommonNameForCertificate(leaf),
		CertificateChain: chain,
		PrivateKeyPKCS8:  keyDER,
		CreationDate:     leaf.NotBefore,
	}, nil
}

// parseCertChain decodes every CERTIFICATE PEM block in pemData into a DER chain plus the
// parsed leaf cert (chain[0]). Non-CERTIFICATE blocks are skipped. An empty chain is an
// error.
func parseCertChain(pemData []byte) ([][]byte, *x509.Certificate, error) {
	var chain [][]byte
	var leaf *x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemBlockTypeCertificate {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate in chain: %w", err)
		}
		chain = append(chain, cert.Raw)
		if leaf == nil {
			leaf = cert
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("tls.crt contained no CERTIFICATE PEM blocks")
	}
	return chain, leaf, nil
}

// parsePrivateKeyToPKCS8 decodes the first private-key PEM block in pemData and returns
// the key as PKCS8 DER. Tries PKCS8 first (the modern, most common encoding for k8s TLS
// secrets), then PKCS1 (RSA-only), then SEC1 (EC-only) so we accept any of the three
// standard k8s TLS key formats.
func parsePrivateKeyToPKCS8(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("tls.key contained no PEM block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return x509.MarshalPKCS8PrivateKey(key)
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return x509.MarshalPKCS8PrivateKey(rsaKey)
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return x509.MarshalPKCS8PrivateKey(ecKey)
	}
	return nil, errors.New("tls.key is not a recognised PKCS8, PKCS1, or SEC1 EC private key")
}

// createPrivateKeyEntry builds the alias + keystore.PrivateKeyEntry pair to insert into the
// rendered Java Keystore. The keystore-go library encrypts the private-key bytes with the
// keystore password at SetPrivateKeyEntry time (passed in renderKeystoreBytes) — standard
// Java idiom of the keystore password also protecting individual keys.
func createPrivateKeyEntry(ke KeypairEntry) (string, keystore.PrivateKeyEntry) {
	chain := make([]keystore.Certificate, 0, len(ke.CertificateChain))
	for _, der := range ke.CertificateChain {
		chain = append(chain, keystore.Certificate{Type: "X509", Content: der})
	}
	return ke.Alias, keystore.PrivateKeyEntry{
		CreationTime:     ke.CreationDate,
		PrivateKey:       ke.PrivateKeyPKCS8,
		CertificateChain: chain,
	}
}

// loadTLSKeypairsFromSecrets fetches each NamespacedSecretReference in the CR's namespace
// and parses it as a TLS keypair. Per-Secret failures are logged and skipped — they should
// not block reconciliation of other valid keypairs. Aliases are de-duplicated via numeric
// suffix; existingAliases lets the caller seed the dedup namespace with already-claimed
// trusted-cert aliases so a TLS keypair never collides with a CA bundle entry.
func loadTLSKeypairsFromSecrets(ctx context.Context, c client.Client, namespace string, refs []jksv1alpha1.NamespacedSecretReference, existingAliases []string) []KeypairEntry {
	if len(refs) == 0 {
		return nil
	}

	keypairs := make([]KeypairEntry, 0, len(refs))
	claimed := make(map[string]struct{}, len(existingAliases)+len(refs))
	for _, a := range existingAliases {
		claimed[a] = struct{}{}
	}

	for _, ref := range refs {
		if ref.Name == "" {
			globalLog.Error(nil, "TLSCertSecretRef entry has empty name, skipping", "Namespace", namespace)
			continue
		}
		secret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
			globalLog.Error(err, "Failed to fetch TLS Secret, skipping", "SecretName", ref.Name, "SecretNamespace", namespace)
			continue
		}
		if secret.Type != corev1.SecretTypeTLS {
			globalLog.Info("Referenced Secret is not type kubernetes.io/tls; attempting to parse anyway because tls.crt and tls.key keys may still be present", "SecretName", ref.Name, "SecretNamespace", namespace, "ActualType", secret.Type)
		}
		ke, err := parseTLSSecret(secret)
		if err != nil {
			globalLog.Error(err, "Failed to parse TLS Secret, skipping", "SecretName", ref.Name, "SecretNamespace", namespace)
			continue
		}
		ke.Alias = uniquifyAlias(ke.Alias, claimed)
		claimed[ke.Alias] = struct{}{}
		keypairs = append(keypairs, ke)
		globalLog.Info("Loaded TLS keypair from Secret", "SecretName", ref.Name, "SecretNamespace", namespace, "Alias", ke.Alias)
	}
	return keypairs
}

// uniquifyAlias returns base if it isn't already in claimed; otherwise appends " #N"
// (matching the trusted-cert dedup convention in validateAndExtractCertificatesFromConfigMap).
func uniquifyAlias(base string, claimed map[string]struct{}) string {
	if _, taken := claimed[base]; !taken {
		return base
	}
	for i := 1; ; i++ {
		candidate := base + " #" + fmt.Sprint(i)
		if _, taken := claimed[candidate]; !taken {
			return candidate
		}
	}
}
