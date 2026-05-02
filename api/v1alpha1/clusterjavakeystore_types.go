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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterJavaKeystoreSpec defines the desired state of ClusterJavaKeystore.
type ClusterJavaKeystoreSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// RootCAConfigMaps is a list of ConfigMaps that contain Root CA Certificates.
	RootCAConfigMaps []ConfigMapReference `json:"rootCAConfigMaps,omitempty"`

	// AddDefaultCACertificates indicates whether to include the default CA certificates in the Java Keystore.  Defaults to false.
	AddDefaultCACertificates bool `json:"addDefaultCACertificates,omitempty"`

	// DefaultCACertificatesPath is the path to the default CA certificates file - in the UBI container it is at /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem. This field is optionally and typically only used when the controller is running in a non-UBI container or externally.
	DefaultCACertificatesPath string `json:"defaultCACertificatesPath,omitempty"`

	// KeystorePasswordSecretRef is a reference to a Secret that contains the password for the Java Keystore. This field is optional and if omitted will use the default password "changeit".
	KeyStorePasswordSecretRef SecretReference `json:"keyStorePasswordSecretRef,omitempty"`

	// NamespaceSelector is a selector for the namespaces that are allowed to reference this ClusterJavaKeystore. If left absent, all namespaces will be allowed to reference this ClusterJavaKeystore.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// SystemNamespace is the namespace the operator is running in and where the Java Keystore ConfigMap and Secret will be created.  If left absent, it will default to "jks-operator".
	SystemNamespace string `json:"systemNamespace,omitempty"`

	// TargetConfigMap
}

// ConfigMapReference defines a reference to a ConfigMap that contains a Certificate.
type ConfigMapReference struct {
	// Name of the ConfigMap.
	Name string `json:"name"`

	// Namespace of the ConfigMap.
	Namespace string `json:"namespace"`

	// Key in the ConfigMap that contains the Certificate.  If left absent, all the keys in the ConfigMap will be used that match a PEM encoded certificate.
	Key string `json:"key,omitempty"`
}

// SecretReference defines a reference to a Secret that contains the password for the Java Keystore.
type SecretReference struct {
	// Name of the Secret.
	Name string `json:"name"`

	// Namespace of the Secret.
	Namespace string `json:"namespace"`

	// Key in the Secret that contains the password.  If left absent, the key "password" will be used by default.
	Key string `json:"key,omitempty"`
}

// ClusterJavaKeystoreStatus defines the observed state of ClusterJavaKeystore.
type ClusterJavaKeystoreStatus struct {
	// Conditions represents the latest available observations of the ClusterJavaKeystore's state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Generated is a boolean that indicates whether the Java Keystore has been generated successfully.
	Generated bool `json:"generated,omitempty"`

	// ErrorMessage contains any error message related to the generation of the Java Keystore.
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ClusterJavaKeystore is the Schema for the clusterjavakeystores API.
type ClusterJavaKeystore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterJavaKeystoreSpec   `json:"spec,omitempty"`
	Status ClusterJavaKeystoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterJavaKeystoreList contains a list of ClusterJavaKeystore.
type ClusterJavaKeystoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterJavaKeystore `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterJavaKeystore{}, &ClusterJavaKeystoreList{})
}
