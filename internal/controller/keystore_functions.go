package controller

import (
	"bytes"
	"fmt"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func createJavaKeystore() keystore.KeyStore {
	ks := keystore.New()
	return ks
}

func createTrustedCertificateEntry(certInfo CertificateNameMapping) (string, keystore.TrustedCertificateEntry) {
	return certInfo.CommonName, keystore.TrustedCertificateEntry{
		CreationTime: certInfo.CreationDate,
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: certInfo.CertificateBytes,
		},
	}
}

// renderKeystoreBytes builds a Java Keystore from the provided certificates and TLS keypairs
// and serializes it to a byte slice using the given password. Per-entry add errors are
// logged via globalLog but do not abort the overall render — this preserves the prior
// behavior of the Reconcile flow, which logged and continued past SetTrustedCertificateEntry
// failures. The same password is used to encrypt each PrivateKeyEntry (standard Java idiom
// of the store password also protecting individual keys). keypairs may be nil for the
// cluster-scoped reconciler, which never produces TLS keypair entries.
func renderKeystoreBytes(certificates []CertificateNameMapping, keypairs []KeypairEntry, password string) ([]byte, error) {
	ks := createJavaKeystore()

	for _, certInfo := range certificates {
		alias, tce := createTrustedCertificateEntry(certInfo)
		if err := ks.SetTrustedCertificateEntry(alias, tce); err != nil {
			globalLog.Error(err, "Failed to add Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
			continue
		}
		globalLog.Info("Successfully added Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
	}

	for _, ke := range keypairs {
		alias, pke := createPrivateKeyEntry(ke)
		if err := ks.SetPrivateKeyEntry(alias, pke, []byte(password)); err != nil {
			globalLog.Error(err, "Failed to add Private Key Entry to Java Keystore", "Alias", alias)
			continue
		}
		globalLog.Info("Successfully added Private Key Entry to Java Keystore", "Alias", alias)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("failed to store Java Keystore to buffer: %w", err)
	}
	return buf.Bytes(), nil
}
