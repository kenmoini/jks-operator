package controller

type CertificateNameMapping struct {
	CommonName       string
	ExpirationDate   string
	CertificateBytes []byte
}
