package controller

import (
	"context"

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
