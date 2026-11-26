package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GeneratorType selects how a secret value is produced.
// +kubebuilder:validation:Enum=Password;RandomBytes;RSAKey
type GeneratorType string

const (
	// GeneratorPassword produces a random password drawn from an alphanumeric
	// (optionally symbol-extended) alphabet.
	GeneratorPassword GeneratorType = "Password"
	// GeneratorRandomBytes produces cryptographically random bytes, encoded as
	// base64 or hex.
	GeneratorRandomBytes GeneratorType = "RandomBytes"
	// GeneratorRSAKey produces a PEM-encoded PKCS#8 RSA private key.
	GeneratorRSAKey GeneratorType = "RSAKey"
)

// Encoding is the textual encoding used by the RandomBytes generator.
// +kubebuilder:validation:Enum=base64;hex
type Encoding string

const (
	// EncodingBase64 is standard padded base64 (RFC 4648).
	EncodingBase64 Encoding = "base64"
	// EncodingHex is lowercase hexadecimal.
	EncodingHex Encoding = "hex"
)

// GeneratorSpec configures how a single key's value is generated.
// +kubebuilder:validation:XValidation:rule="self.type != 'RSAKey' || has(self.bits)",message="bits is required for RSAKey"
type GeneratorSpec struct {
	// Type of generator.
	Type GeneratorType `json:"type"`

	// Length is the number of characters (Password) or bytes (RandomBytes).
	// +kubebuilder:validation:Minimum=8
	// +kubebuilder:validation:Maximum=1024
	// +kubebuilder:default=32
	// +optional
	Length int32 `json:"length,omitempty"`

	// Symbols adds punctuation characters to the Password alphabet.
	// +optional
	Symbols bool `json:"symbols,omitempty"`

	// Encoding of the RandomBytes output.
	// +kubebuilder:default=base64
	// +optional
	Encoding Encoding `json:"encoding,omitempty"`

	// Bits is the RSA modulus size.
	// +kubebuilder:validation:Enum=2048;3072;4096
	// +optional
	Bits int32 `json:"bits,omitempty"`
}

// KeySpec describes one key inside the managed Secret.
type KeySpec struct {
	// Name of the key in Secret.data.
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	// +kubebuilder:validation:MaxLength=200
	Name string `json:"name"`

	// Generator used to produce this key's value.
	Generator GeneratorSpec `json:"generator"`
}

// WorkloadRef points at a workload in the same namespace whose pods consume the
// Secret. After each rotation the operator bumps an annotation on the pod
// template, triggering a standard rolling restart.
type WorkloadRef struct {
	// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet
	Kind string `json:"kind"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// AWSSecretsManagerSink mirrors the rotated Secret into AWS Secrets Manager as a
// JSON document, so workloads outside the cluster see the same credentials.
type AWSSecretsManagerSink struct {
	// SecretID is the name or ARN of the Secrets Manager secret. It is created
	// if it does not exist.
	// +kubebuilder:validation:MinLength=1
	SecretID string `json:"secretId"`

	// Region overrides the region from the operator's AWS configuration.
	// +optional
	Region string `json:"region,omitempty"`
}

// SinkSpec lists external systems that receive each new Secret version.
type SinkSpec struct {
	// +optional
	AWSSecretsManager *AWSSecretsManagerSink `json:"awsSecretsManager,omitempty"`
}

// DeletionPolicy controls what happens to the managed Secret when the
// SecretRotation is deleted.
// +kubebuilder:validation:Enum=Delete;Retain
type DeletionPolicy string

const (
	// DeletionPolicyDelete garbage collects the Secret with its owner.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyRetain orphans the Secret so it outlives its owner.
	DeletionPolicyRetain DeletionPolicy = "Retain"
)

// SecretRotationSpec defines the desired state of SecretRotation.
type SecretRotationSpec struct {
	// SecretName is the name of the Secret (in the same namespace) that this
	// resource manages. Immutable.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="secretName is immutable"
	SecretName string `json:"secretName"`

	// RotationInterval is how often the Secret is regenerated, e.g. "720h".
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m')",message="rotationInterval must be at least 1m"
	RotationInterval metav1.Duration `json:"rotationInterval"`

	// Keys to generate in the Secret.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	Keys []KeySpec `json:"keys"`

	// KeepPrevious stores the prior value of every key under "<key>.previous"
	// so consumers can accept both credentials during a rollout.
	// +optional
	KeepPrevious bool `json:"keepPrevious,omitempty"`

	// RestartTargets are rolled after every rotation.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	RestartTargets []WorkloadRef `json:"restartTargets,omitempty"`

	// Sinks receive a copy of each new Secret version.
	// +optional
	Sinks SinkSpec `json:"sinks,omitempty"`

	// Suspend pauses scheduled rotation. Manual triggers are also ignored.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// DeletionPolicy decides whether the Secret is garbage collected together
	// with this resource.
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// SecretRotationStatus defines the observed state of SecretRotation.
type SecretRotationStatus struct {
	// ObservedGeneration is the most recent generation acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// CurrentVersion is a counter incremented on every rotation.
	// +optional
	CurrentVersion int64 `json:"currentVersion,omitempty"`

	// LastRotationTime is when the Secret was last regenerated.
	// +optional
	LastRotationTime *metav1.Time `json:"lastRotationTime,omitempty"`

	// NextRotationTime is when the next scheduled rotation is due.
	// +optional
	NextRotationTime *metav1.Time `json:"nextRotationTime,omitempty"`

	// SinkSyncedVersion is the latest version successfully pushed to every sink.
	// +optional
	SinkSyncedVersion int64 `json:"sinkSyncedVersion,omitempty"`

	// Conditions: Ready, WorkloadsRestarted, SinksSynced.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SecretRotation manages a Kubernetes Secret whose contents are regenerated on a
// schedule, optionally rolling dependent workloads and mirroring to AWS.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sr;srot,categories=secrets
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretName`
// +kubebuilder:printcolumn:name="Interval",type=string,JSONPath=`.spec.rotationInterval`
// +kubebuilder:printcolumn:name="Version",type=integer,JSONPath=`.status.currentVersion`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Next Rotation",type=date,JSONPath=`.status.nextRotationTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SecretRotation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretRotationSpec   `json:"spec,omitempty"`
	Status SecretRotationStatus `json:"status,omitempty"`
}

// SecretRotationList contains a list of SecretRotation.
// +kubebuilder:object:root=true
type SecretRotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretRotation `json:"items"`
}
