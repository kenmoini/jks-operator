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
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	jksv1alpha1 "github.com/kenmoini/jks-operator/api/v1alpha1"
)

// ignoreDeletionPredicate filters out CR status-only updates (no Generation change)
// and confirmed-deletion delete events for the ClusterJavaKeystore CR.
func ignoreDeletionPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !e.DeleteStateUnknown
		},
	}
}

// SetupWithManager sets up the CR controller with the Manager. This controller is
// responsible for the ClusterJavaKeystore CR and the system ConfigMap/Secret it owns.
// Labeled-target injection lives in separate controllers (configmap_injector and
// secret_injector) so a label or data edit on a single labeled target only triggers a
// scoped per-target reconcile, never a full CR re-derivation.
func (r *ClusterJavaKeystoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jksv1alpha1.ClusterJavaKeystore{}, builder.WithPredicates(ignoreDeletionPredicate())).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		WithEventFilter(ignoreDeletionPredicate()).
		Named("clusterjavakeystore").
		Complete(r)
}
