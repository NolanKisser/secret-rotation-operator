package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
)

func managedSecret(version int64, rotatedAt time.Time, trigger string, data map[string][]byte) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-creds"}, Data: data}
	writeState(s, secretState{Version: version, RotatedAt: rotatedAt, Trigger: trigger})
	return s
}

func TestDecide(t *testing.T) {
	full := map[string][]byte{"password": []byte("x"), "token": []byte("y")}
	tests := []struct {
		name        string
		annotations map[string]string
		secret      *corev1.Secret
		now         time.Time
		want        rotationReason
	}{
		{"no secret", nil, nil, t0, reasonCreated},
		{"unmanaged secret", nil, &corev1.Secret{Data: full}, t0, reasonAdopted},
		{"fresh", nil, managedSecret(1, t0, "", full), t0.Add(time.Minute), reasonNone},
		{"exactly due", nil, managedSecret(1, t0, "", full), t0.Add(time.Hour), reasonScheduled},
		{"overdue", nil, managedSecret(1, t0, "", full), t0.Add(30 * time.Hour), reasonScheduled},
		{"new trigger", map[string]string{rotationv1alpha1.AnnotationRotateNow: "a"}, managedSecret(1, t0, "", full), t0, reasonManual},
		{"consumed trigger", map[string]string{rotationv1alpha1.AnnotationRotateNow: "a"}, managedSecret(2, t0, "a", full), t0, reasonNone},
		{"missing key", nil, managedSecret(1, t0, "", map[string][]byte{"password": []byte("x")}), t0, reasonKeysMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := newSR()
			sr.Annotations = tt.annotations
			got, _ := decide(sr, tt.secret, tt.now)
			if got != tt.want {
				t.Errorf("decide() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateRoundTrip(t *testing.T) {
	s := &corev1.Secret{}
	in := secretState{Version: 7, RotatedAt: t0, Trigger: "tok"}
	writeState(s, in)
	if out := readState(s); out != in {
		t.Errorf("round trip: got %+v, want %+v", out, in)
	}
}

func TestRestartAnnotationKeyIsValid(t *testing.T) {
	sr := newSR()
	sr.Name = "a-very-long-secret-rotation-name-that-goes-on-and-on-and-on-for-quite-a-while"
	key, _ := restartAnnotation(sr, 1)
	name := key[len("rotation.nolankisser.github.io/"):]
	if len(name) > 63 {
		t.Errorf("annotation name %q exceeds 63 characters", name)
	}
	other := newSR()
	k2, _ := restartAnnotation(other, 1)
	if key == k2 {
		t.Error("different SecretRotations must use different keys")
	}
}
