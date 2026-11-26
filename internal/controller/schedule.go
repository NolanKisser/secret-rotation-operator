package controller

import (
	"maps"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
)

// rotationReason explains why a rotation happens. It is used as the Event
// reason and as a metric label, so values are CamelCase and low-cardinality.
type rotationReason string

const (
	reasonNone        rotationReason = ""
	reasonCreated     rotationReason = "Created"
	reasonScheduled   rotationReason = "Scheduled"
	reasonManual      rotationReason = "ManualTrigger"
	reasonKeysMissing rotationReason = "KeysMissing"
	reasonAdopted     rotationReason = "Adopted"
)

// fullRotation reports whether every key is regenerated, as opposed to only
// filling in keys that are missing.
func (r rotationReason) fullRotation() bool {
	return r != reasonNone && r != reasonKeysMissing
}

// secretState is rotation bookkeeping stored on the Secret itself.
//
// Keeping it on the Secret (not only in .status) makes the write atomic: the
// new data and the record that it was rotated land in a single API call. If
// the operator crashes before updating status, the next reconcile still sees
// the correct version and does not rotate twice.
type secretState struct {
	Version   int64
	RotatedAt time.Time
	Trigger   string
}

func readState(s *corev1.Secret) secretState {
	if s == nil {
		return secretState{}
	}
	var st secretState
	st.Version, _ = strconv.ParseInt(s.Annotations[rotationv1alpha1.AnnotationVersion], 10, 64)
	st.RotatedAt, _ = time.Parse(time.RFC3339, s.Annotations[rotationv1alpha1.AnnotationRotatedAt])
	st.Trigger = s.Annotations[rotationv1alpha1.AnnotationTrigger]
	return st
}

func writeState(s *corev1.Secret, st secretState) {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[rotationv1alpha1.AnnotationVersion] = strconv.FormatInt(st.Version, 10)
	s.Annotations[rotationv1alpha1.AnnotationRotatedAt] = st.RotatedAt.UTC().Format(time.RFC3339)
	if st.Trigger != "" {
		s.Annotations[rotationv1alpha1.AnnotationTrigger] = st.Trigger
	}
}

// decide determines whether the Secret must be (re)generated now. secret is
// nil when it does not exist.
func decide(sr *rotationv1alpha1.SecretRotation, secret *corev1.Secret, now time.Time) (rotationReason, []string) {
	if secret == nil {
		return reasonCreated, nil
	}
	st := readState(secret)
	if st.RotatedAt.IsZero() {
		// A pre-existing Secret we have never rotated: take it over.
		return reasonAdopted, nil
	}
	if token := sr.Annotations[rotationv1alpha1.AnnotationRotateNow]; token != "" && token != st.Trigger {
		return reasonManual, nil
	}
	if !now.Before(nextRotation(sr, st)) {
		return reasonScheduled, nil
	}
	var missing []string
	for _, k := range sr.Spec.Keys {
		if _, ok := secret.Data[k.Name]; !ok {
			missing = append(missing, k.Name)
		}
	}
	if len(missing) > 0 {
		return reasonKeysMissing, missing
	}
	return reasonNone, nil
}

func nextRotation(sr *rotationv1alpha1.SecretRotation, st secretState) time.Time {
	return st.RotatedAt.Add(sr.Spec.RotationInterval.Duration)
}

// valueGenerator abstracts generator.Generator for testability.
type valueGenerator interface {
	Generate(rotationv1alpha1.GeneratorSpec) ([]byte, error)
}

// buildData computes the new Secret payload.
//
// A full rotation regenerates every key and drops keys no longer in the spec;
// with KeepPrevious, the old value of each key moves to "<key>.previous". A
// partial rotation keeps existing values and only fills missing keys.
func buildData(sr *rotationv1alpha1.SecretRotation, old map[string][]byte, reason rotationReason, missing []string, gen valueGenerator) (map[string][]byte, error) {
	if !reason.fullRotation() {
		out := maps.Clone(old)
		if out == nil {
			out = map[string][]byte{}
		}
		for _, k := range sr.Spec.Keys {
			for _, m := range missing {
				if k.Name != m {
					continue
				}
				v, err := gen.Generate(k.Generator)
				if err != nil {
					return nil, err
				}
				out[k.Name] = v
			}
		}
		return out, nil
	}

	out := make(map[string][]byte, len(sr.Spec.Keys)*2)
	for _, k := range sr.Spec.Keys {
		v, err := gen.Generate(k.Generator)
		if err != nil {
			return nil, err
		}
		out[k.Name] = v
		if prev, ok := old[k.Name]; ok && sr.Spec.KeepPrevious {
			out[k.Name+rotationv1alpha1.PreviousSuffix] = prev
		}
	}
	return out, nil
}

// sinkPayload strips ".previous" keys; external systems only receive the
// current credential.
func sinkPayload(sr *rotationv1alpha1.SecretRotation, data map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(sr.Spec.Keys))
	for _, k := range sr.Spec.Keys {
		if v, ok := data[k.Name]; ok {
			out[k.Name] = v
		}
	}
	return out
}
