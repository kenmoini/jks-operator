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

package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// hasClusterKeystoreLabel reports whether the object carries the
// jks.kemo.dev/clusterkeystore label with a non-empty value.
func hasClusterKeystoreLabel(obj client.Object) bool {
	if obj == nil {
		return false
	}
	v, ok := obj.GetLabels()[DefaultClusterJavaKeystoreLabel]
	return ok && v != ""
}

// clusterKeystoreLabelPredicate returns a predicate that admits events for objects
// whose label `jks.kemo.dev/clusterkeystore` is (or was) set.
//
// Update events are admitted whenever EITHER the old or new object carries the label,
// which catches both label-add ("opt-in") and label-remove ("opt-out") transitions —
// the latter is what drives the injector controllers' cleanup-on-unlabel path.
func clusterKeystoreLabelPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasClusterKeystoreLabel(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return hasClusterKeystoreLabel(e.ObjectOld) || hasClusterKeystoreLabel(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasClusterKeystoreLabel(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasClusterKeystoreLabel(e.Object)
		},
	}
}
