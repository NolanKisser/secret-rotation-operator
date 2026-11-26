package v1alpha1

// Well-known annotations, labels, and condition types.
const (
	// Prefix shared by every annotation the operator owns.
	annotationPrefix = "rotation.nolankisser.github.io/"

	// AnnotationRotateNow on a SecretRotation requests an immediate rotation.
	// Any new value triggers exactly one rotation; the value is recorded so
	// re-applying the same manifest does not rotate again.
	AnnotationRotateNow = annotationPrefix + "rotate-now"

	// AnnotationVersion on the managed Secret records the rotation counter.
	AnnotationVersion = annotationPrefix + "version"
	// AnnotationRotatedAt on the managed Secret records the RFC3339 rotation time.
	AnnotationRotatedAt = annotationPrefix + "rotated-at"
	// AnnotationTrigger on the managed Secret records the last consumed
	// rotate-now value.
	AnnotationTrigger = annotationPrefix + "trigger"

	// AnnotationRestartedFor is written on workload pod templates. Changing it
	// causes a rolling restart.
	AnnotationRestartedFor = annotationPrefix + "secret-version"

	// LabelManagedBy marks Secrets created by this operator.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value of LabelManagedBy.
	ManagedByValue = "secret-rotation-operator"

	// Finalizer guarantees cleanup (e.g. orphaning a Retained Secret) before
	// the SecretRotation is removed.
	Finalizer = annotationPrefix + "finalizer"

	// PreviousSuffix is appended to keys holding the prior value.
	PreviousSuffix = ".previous"

	ConditionReady              = "Ready"
	ConditionWorkloadsRestarted = "WorkloadsRestarted"
	ConditionSinksSynced        = "SinksSynced"
)
