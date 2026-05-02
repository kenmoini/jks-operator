package controller

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetSecret returns a single Secret by name in a given Namespace
func GetSecret(name string, namespace string, clnt client.Client) (*corev1.Secret, error) {
	targetSecret := &corev1.Secret{}
	err := clnt.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, targetSecret)

	if err != nil {
		globalLog.Error(err, "Failed to get secret/"+name+" in namespace/"+namespace)
		return targetSecret, err
	}
	return targetSecret, nil
}

// GetConfigMap returns a single ConfigMap by name in a given Namespace
func GetConfigMap(name string, namespace string, clnt client.Client) (*corev1.ConfigMap, error) {
	targetConfigMap := &corev1.ConfigMap{}
	err := clnt.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, targetConfigMap)

	if err != nil {
		globalLog.Error(err, "Failed to get configmap/"+name+" in namespace/"+namespace)
		return targetConfigMap, err
	}
	return targetConfigMap, nil
}

// determineCommonNameForCertificate is a helper function to determine the Common Name to use for a certificate based on the Subject field of the certificate.
// Since some certificates may not have a Common Name in the Subject, we will attempt to determine the best Common Name to use based on the available fields in the Subject.
// The order of precedence is Common Name, Organizational Unit, Organization, and if none of those fields are available, we will generate a unique Common Name using a timestamp to ensure it is unique among any other certificates that also do not have any of those fields available. This is important because we want to use the Common Name as part of the alias for the certificate in the Java Keystore and aliases must be unique within a Keystore.
func determineCommonNameForCertificate(cert *x509.Certificate) string {
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
				determinedCommonName = "Unknown Common Name # " + fmt.Sprint(time.Now().UnixNano())
			}
		}
	}
	return determinedCommonName
}
