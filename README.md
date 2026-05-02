# jks-operator

[![Lint](https://github.com/kenmoini/jks-operator/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/kenmoini/jks-operator/actions/workflows/lint.yml) [![Tests](https://github.com/kenmoini/jks-operator/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/kenmoini/jks-operator/actions/workflows/test.yml) [![Operator - Build](https://github.com/kenmoini/jks-operator/actions/workflows/build-container.yml/badge.svg)](https://github.com/kenmoini/jks-operator/actions/workflows/build-container.yml) [![Bundle - Build](https://github.com/kenmoini/jks-operator/actions/workflows/build-bundle.yml/badge.svg)](https://github.com/kenmoini/jks-operator/actions/workflows/build-bundle.yml)

> This is a community operator, unsupported by Red Hat. Support is tired of hearing about me.

The Java Keystore Operator creates Java Keystore files from PEM bundles or TLS Secrets.

## Description

The JKS Operator operates in a Cluster or Namespace scoped mode, offering cluster admins the ability to easily distribute Root Certificate Bundles via JKS blobs, or to distribute JKS blobs generated from TLS-type Secrets.

### ClusterJavaKeystore

The goal of the ClusterJavaKeystore is to operate similarly to OpenShift Cluster Network Operator which has the ability to inject the trusted CA bundle into ConfigMaps with a certain label.

The ClusterJavaKeystore takes in PEM-formatted CA certificates from ConfigMaps and creates a Java Keystore file in another ConfigMap.  This way you can easily mount additional trusted Root CAs to your Java workloads.

The general workflow of the ClusterJavaKeystore follows:

- A list of ConfigMaps that hold PEM encoded certificates is defined in the ClusterJavaKeystore, in addition to some optional parameters.
- Enumerates the Certificates found in the ConfigMap(s), determining the CommonName as an alias to inject in JKS Trust Bundle.
- Optionally takes all the default system CA Certificates included with the manager container and enumerates them as well for inclusion (default: false)
- With the Root CAs enumerated, will create a ConfigMap and Secret containing the JKS binary data and password in the namespace the operator was installed to.
- When a ConfigMap or Secret in the cluster is created with the annotation `jks.kemo.dev/clusterkeystore` with a value that matches the name of the ClusterJavaKeystore, the Operator will inject the created JKS into it with the key `keystore.jks` if it is a ConfigMap and the JKS password into the key `password` if it is a labeled Secret.

### JavaKeystore

The JavaKeystore operates similarly to the ClusterJavaKeystore, however its referenced and resulting resources are bound to the Namespace that the JavaKeystore is created in.

The JavaKeystore has an additional component to it's API spec that allows adding TLS-type Secrets to the generated Java Keystore, optionally in addition to the trusted CA bundle.

## Getting Started

### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/jks-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/jks-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/jks-operator:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/jks-operator/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
operator-sdk edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

