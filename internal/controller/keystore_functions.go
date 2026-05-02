package controller

import (
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
