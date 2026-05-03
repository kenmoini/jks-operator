package v1alpha1

// ConfigMapReference defines a reference to a ConfigMap that contains a Certificate.
type ConfigMapReference struct {
	// Name of the ConfigMap.
	Name string `json:"name,omitempty"`

	// Namespace of the ConfigMap.
	Namespace string `json:"namespace,omitempty"`

	// Key in the ConfigMap that contains the Certificate.  If left absent, all the keys in the ConfigMap will be used that match a PEM encoded certificate.
	Key string `json:"key,omitempty"`
}

// SecretReference defines a reference to a Secret that contains the password for the Java Keystore.
type SecretReference struct {
	// Name of the Secret.
	Name string `json:"name,omitempty"`

	// Namespace of the Secret.
	Namespace string `json:"namespace,omitempty"`

	// Key in the Secret that contains the password.  If left absent, the key "password" will be used by default.
	Key string `json:"key,omitempty"`
}

// NamespacedConfigMapReference defines a reference to a ConfigMap that contains a Certificate.
type NamespacedConfigMapReference struct {
	// Name of the ConfigMap.
	Name string `json:"name,omitempty"`

	// Key in the ConfigMap that contains the Certificate.
	// If left absent, all the keys in the ConfigMap will be used that match a PEM encoded certificate.
	Key string `json:"key,omitempty"`
}

// NamespacedSecretReference defines a reference to a Secret that contains the password for the Java Keystore or TLS Secret to include in the Java Keystore.
type NamespacedSecretReference struct {
	// Name of the Secret.
	Name string `json:"name,omitempty"`

	// Key in the Secret that contains the password.
	// If left absent, the key "password" will be used by default.
	Key string `json:"key,omitempty"`
}
