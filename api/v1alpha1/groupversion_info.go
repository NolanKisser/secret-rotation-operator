// Package v1alpha1 contains API Schema definitions for the rotation v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=rotation.nolankisser.github.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "rotation.nolankisser.github.io", Version: "v1alpha1"}

	// SchemeBuilder registers this package's types. It depends only on
	// apimachinery so that clients can import the API without pulling in
	// controller-runtime.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &SecretRotation{}, &SecretRotationList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
