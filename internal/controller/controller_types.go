package controller

import "time"

type CertificateNameMapping struct {
	CommonName       string
	ExpirationDate   time.Time
	CreationDate     time.Time
	CertificateBytes []byte
}
