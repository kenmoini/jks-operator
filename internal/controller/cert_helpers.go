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
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

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
	if err := pem.Encode(&buf, &pem.Block{Type: pemBlockTypeCertificate, Bytes: cert.Raw}); err != nil {
		return CertificateNameMapping{}, fmt.Errorf("encode certificate: %w", err)
	}
	return CertificateNameMapping{
		CommonName:       determineCommonNameForCertificate(cert),
		ExpirationDate:   cert.NotAfter,
		CreationDate:     cert.NotBefore,
		CertificateBytes: buf.Bytes(),
	}, nil
}

// loadDefaultCACertificatesFromDisk appends system CA certificates from disk to certificates
// when addDefaults is true. File-read failures are logged and swallowed — the user may not
// care if the bundle is unavailable, and we don't want a missing trust store to block valid
// user-supplied certificates. customPath, if empty, falls back to DefaultCACertificatesPath.
func loadDefaultCACertificatesFromDisk(addDefaults bool, customPath string, certificates []CertificateNameMapping) []CertificateNameMapping {
	if !addDefaults {
		globalLog.Info("Not including default CA certificates as specified in CR spec")
		return certificates
	}
	path := customPath
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
		if block.Type != pemBlockTypeCertificate {
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

// collectCertificatesFromConfigMaps iterates refs, fetches each ConfigMap, and appends every
// unique certificate found into certificates. Returns the first hard error (fetch failure or
// a missing required key); the caller applies client.IgnoreNotFound. Each ref must already
// carry its full Namespace — namespaced callers should stamp the CR's namespace onto each
// NamespacedConfigMapReference before normalising into ConfigMapReference.
func collectCertificatesFromConfigMaps(ctx context.Context, c client.Client, refs []jksv1alpha1.ConfigMapReference, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	if len(refs) == 0 {
		globalLog.Info("No ConfigMap references found in CR, skipping certificate enumeration")
		return certificates, nil
	}
	for _, ref := range refs {
		var err error
		certificates, err = processConfigMapReference(ctx, c, ref, certificates)
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
func processConfigMapReference(ctx context.Context, c client.Client, ref jksv1alpha1.ConfigMapReference, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	globalLog.Info("Processing ConfigMap reference", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, configMap); err != nil {
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
		return appendCertsFromConfigMapKey(configMap, ref, certificates)
	}
	globalLog.Info("No specific key specified for ConfigMap reference, all keys will be processed if they contain valid PEM encoded certificates", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace)
	for key := range configMap.Data {
		perKey := jksv1alpha1.ConfigMapReference{Name: ref.Name, Namespace: ref.Namespace, Key: key}
		var err error
		certificates, err = appendCertsFromConfigMapKey(configMap, perKey, certificates)
		if err != nil {
			globalLog.Error(err, "Failed to validate and extract certificates from ConfigMap for specific key", "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "Key", key)
			continue
		}
	}
	return certificates, nil
}

// appendCertsFromConfigMapKey extracts all PEM certificates from configMap.Data[ref.Key]
// and appends each unique one to certificates.
func appendCertsFromConfigMapKey(configMap *corev1.ConfigMap, ref jksv1alpha1.ConfigMapReference, certificates []CertificateNameMapping) ([]CertificateNameMapping, error) {
	certs, err := validateAndExtractCertificatesFromConfigMap(configMap, ref)
	if err != nil {
		return certificates, err
	}
	for _, ci := range certs {
		certificates = appendUniqueCertificate(certificates, ci, "ConfigMapName", ref.Name, "ConfigMapNamespace", ref.Namespace, "Key", ref.Key)
	}
	return certificates, nil
}

// validateAndExtractCertificatesFromConfigMap parses every PEM block in
// configMap.Data[ref.Key] and returns CertificateNameMappings for the X.509 certificates
// found. Returns an error if no certificate is found in the value at all. CommonName
// uniqueness within the returned slice is enforced via a numeric suffix; full byte-equality
// dedup against an existing running list is the caller's job (via appendUniqueCertificate).
func validateAndExtractCertificatesFromConfigMap(configMap *corev1.ConfigMap, configMapRef jksv1alpha1.ConfigMapReference) ([]CertificateNameMapping, error) {
	certificates := []CertificateNameMapping{}
	certificateFound := false
	certificateCount := 0
	data := []byte(configMap.Data[configMapRef.Key])
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case pemBlockTypeCertificate:
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				globalLog.Error(err, "Failed to parse certificate from PEM block, skipping this block", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key)
				continue
			}
			certificateFound = true
			certificateCount++

			determinedCommonName := determineCommonNameForCertificate(cert)

			pemBlock := &pem.Block{Type: pemBlockTypeCertificate, Bytes: cert.Raw}
			var pemBuffer bytes.Buffer
			if err := pem.Encode(&pemBuffer, pemBlock); err != nil {
				globalLog.Error(err, "Failed to encode certificate back to PEM format", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "CertificateCommonName", determinedCommonName)
				continue
			}
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
		return nil, errors.New("value of specified key does not contain a valid PEM encoded certificate")
	}
	globalLog.Info("Value of specified key contains valid PEM encoded certificate(s)", "ConfigMapName", configMapRef.Name, "ConfigMapNamespace", configMapRef.Namespace, "Key", configMapRef.Key, "CertificateCount", certificateCount)
	return certificates, nil
}

// computeKeystoreSourceHash returns a stable SHA-256 (hex-encoded) over the source-material
// fingerprint of the rendered keystore: trusted-cert bytes first (sorted, order-independent),
// then keypair material (sorted by alias, then by per-keypair concatenation of cert chain
// + private key). This is the idempotency marker stored on the system ConfigMap because
// rendered JKS bytes are not byte-stable across runs (the underlying keystore library
// salts/timestamps the output, so a byte-for-byte comparison would always show a difference
// even when the set of source material is unchanged). keypairs may be nil for the
// cluster-scoped reconciler, which never produces TLS keypair entries.
func computeKeystoreSourceHash(certificates []CertificateNameMapping, keypairs []KeypairEntry) string {
	sortedCerts := make([][]byte, len(certificates))
	for i, c := range certificates {
		// copy so we don't mutate the caller's backing array via sort
		b := make([]byte, len(c.CertificateBytes))
		copy(b, c.CertificateBytes)
		sortedCerts[i] = b
	}
	sort.Slice(sortedCerts, func(i, j int) bool {
		return bytes.Compare(sortedCerts[i], sortedCerts[j]) < 0
	})

	type kpDigest struct {
		alias string
		blob  []byte
	}
	sortedKeypairs := make([]kpDigest, 0, len(keypairs))
	for _, ke := range keypairs {
		var blob bytes.Buffer
		for _, der := range ke.CertificateChain {
			blob.Write(der)
			blob.WriteByte(0x02) // intra-chain delimiter, distinct from the inter-cert delimiter (0x00)
		}
		blob.WriteByte(0x03) // chain/key delimiter
		blob.Write(ke.PrivateKeyPKCS8)
		sortedKeypairs = append(sortedKeypairs, kpDigest{alias: ke.Alias, blob: blob.Bytes()})
	}
	sort.Slice(sortedKeypairs, func(i, j int) bool {
		if sortedKeypairs[i].alias != sortedKeypairs[j].alias {
			return sortedKeypairs[i].alias < sortedKeypairs[j].alias
		}
		return bytes.Compare(sortedKeypairs[i].blob, sortedKeypairs[j].blob) < 0
	})

	h := sha256.New()
	for _, b := range sortedCerts {
		h.Write(b)
		h.Write([]byte{0x00}) // inter-cert delimiter
	}
	h.Write([]byte{0x01}) // section delimiter between certs and keypairs
	for _, kp := range sortedKeypairs {
		h.Write([]byte(kp.alias))
		h.Write([]byte{0x04}) // alias/blob delimiter
		h.Write(kp.blob)
		h.Write([]byte{0x05}) // inter-keypair delimiter
	}
	return hex.EncodeToString(h.Sum(nil))
}

// systemConfigMapIsCurrent reports whether the on-cluster system ConfigMap already encodes
// the expected hash under the given dataKey, has non-empty JKS bytes there, and carries
// the expected ownership stamps. When true, the keystore render+update can be skipped
// entirely. ownerKind is the literal component string used in setOwnershipAnnotations
// ("ClusterJavaKeystore" or "JavaKeystore"); dataKey is the BinaryData key the keystore
// bytes live under (the cluster controller always passes DefaultJavaKeystoreConfigMapKey;
// the namespaced controller may pass a user-overridden key from Spec.TargetConfigMap.Key).
func systemConfigMapIsCurrent(cm *corev1.ConfigMap, ownerKind, instanceName, dataKey, hash string) bool {
	if cm.Annotations[DefaultClusterJavaKeystoreCertHashAnnotation] != hash {
		return false
	}
	if len(cm.BinaryData[dataKey]) == 0 {
		return false
	}
	return hasOwnershipAnnotations(cm, ownerKind, instanceName)
}
