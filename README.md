# jks-operator

[![Lint](https://github.com/kenmoini/jks-operator/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/kenmoini/jks-operator/actions/workflows/lint.yml) [![Tests](https://github.com/kenmoini/jks-operator/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/kenmoini/jks-operator/actions/workflows/test.yml) [![Operator - Build](https://github.com/kenmoini/jks-operator/actions/workflows/build-container.yml/badge.svg)](https://github.com/kenmoini/jks-operator/actions/workflows/build-container.yml) [![Bundle - Build](https://github.com/kenmoini/jks-operator/actions/workflows/build-bundle.yml/badge.svg)](https://github.com/kenmoini/jks-operator/actions/workflows/build-bundle.yml) [![Latest Release](https://github.com/kenmoini/jks-operator/actions/workflows/versioned-release.yml/badge.svg)](https://github.com/kenmoini/jks-operator/actions/workflows/versioned-release.yml)

> This is a community operator, unsupported by Red Hat. Support is tired of hearing about me.

The **Java Keystore Operator** creates Java Keystore files from PEM bundles and/or TLS Secrets.

## Description

The JKS Operator operates in a Cluster or Namespace scoped mode, offering cluster admins the ability to easily distribute Root Certificate Bundles via JKS blobs, and/or to distribute JKS blobs generated from TLS-type Secrets.

### Problem Statement

Things like OpenShift's Cluster Network Operator give you a very easy way to add your own Root Certificates to the cluster trust store, simply by defining them in a ConfigMap named `user-ca-certs` in the `openshift-config` Namespace.  Then you can easily mount those trusted certificates as well as all the default certificates in the system trust store by creating an empty ConfigMap with a special label:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: all-root-trusted-ca
  labels:
    config.openshift.io/inject-trusted-cabundle: 'true'
```

That `config.openshift.io/inject-trusted-cabundle: 'true'` label will make OpenShift's CNO to populate the ConfigMap's `.data[ca-bundle.crt]` with all the PEMs that are trusted.

- While this is great for *normal* applications that need an appended Trust Store mounted to their containers, Java applications are *special*.  Java applications need a Java Keystore file that has all the same things in a different way.  This is what the JKS Operator aims to solve.

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

---

## Contributing

A good way to contribute to this project is to check out the current open Issues and Pull Requests for anything that is currently in-flight.

Any bugs, enhancements, etc should be started with an Issue first to make discussion available over the impact of the request.

Once an Issue is open to track the discussion, you can optionally provide contributions with Pull Requests.

To do so, fork this repo, then make a new branch in your fork to track changes.  Commit them to that branch, push to your fork, and then open a Pull Request from there to merge into `main` which is the primary branch.

Once changes have been merged into main, a versioned release can occur to distribute it and other changes.

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

