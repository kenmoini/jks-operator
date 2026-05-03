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

	// TargetConfigMap is a reference to the ConfigMap where the generated Java Keystore will be stored. The ConfigMap is created in the SystemNamespace. Both fields are optional: Name defaults to "<java-keystore-name>-jks" and Key defaults to "keystore.jks".
	TargetConfigMap NamespacedConfigMapReference `json:"targetConfigMap,omitempty"`

	// TargetSecret is a reference to the Secret where the password for the Java Keystore will be stored. The Secret is created in the SystemNamespace. Both fields are optional: Name defaults to "<java-keystore-name>-jks-password" and Key defaults to "password".
	TargetSecret NamespacedSecretReference `json:"targetSecret,omitempty"`
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

// ClusterJavaKeystore is a cluster-scoped resource that defines the desired state and observed state of a Java Keystore that is generated from a set of Root CA certificates and an optional TLS certificate. The generated Java Keystore is stored in a ConfigMap and the password for the Java Keystore is stored in a Secret. Namespaces can reference this ClusterJavaKeystore to use the generated Java Keystore.
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
