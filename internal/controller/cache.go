package controller

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
)

// CacheOptions restricts the informer cache to Secrets this operator manages.
// Caching every Secret in a large cluster costs memory proportional to all
// Secret data and widens the blast radius of a compromised operator pod.
// The reconciler falls back to an uncached read for unlabelled Secrets.
func CacheOptions() cache.Options {
	managed := labels.SelectorFromSet(labels.Set{rotationv1alpha1.LabelManagedBy: rotationv1alpha1.ManagedByValue})
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Label: managed},
		},
	}
}
