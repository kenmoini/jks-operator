package controller

import (
	"bytes"
	"fmt"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func createJavaKeystore() (keystore.KeyStore, error) {
	ks := keystore.New()
	return ks, nil
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

// renderKeystoreBytes builds a Java Keystore from the provided certificates and serializes it
// to a byte slice using the given password. Per-certificate add errors are logged via globalLog
// but do not abort the overall render — this preserves the prior behavior of the Reconcile flow,
// which logged and continued past SetTrustedCertificateEntry failures.
func renderKeystoreBytes(certificates []CertificateNameMapping, password string) ([]byte, error) {
	ks, err := createJavaKeystore()
	if err != nil {
		return nil, fmt.Errorf("failed to create Java Keystore: %w", err)
	}

	for _, certInfo := range certificates {
		alias, tce := createTrustedCertificateEntry(certInfo)
		if err := ks.SetTrustedCertificateEntry(alias, tce); err != nil {
			globalLog.Error(err, "Failed to add Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
			continue
		}
		globalLog.Info("Successfully added Trusted Certificate Entry to Java Keystore", "CertificateCommonName", certInfo.CommonName)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("failed to store Java Keystore to buffer: %w", err)
	}
	return buf.Bytes(), nil
}
