package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
	"github.com/NolanKisser/secret-rotation-operator/internal/generator"
	"github.com/NolanKisser/secret-rotation-operator/internal/sink"
)

const ns = "default"

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	c     client.Client
	r     *SecretRotationReconciler
	clock *clocktesting.FakeClock
	sm    *fakeSM
}

func newHarness(t *testing.T, objs ...client.Object) *harness {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rotationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&rotationv1alpha1.SecretRotation{}).
		Build()
	h := &harness{t: t, c: c, clock: clocktesting.NewFakeClock(t0), sm: &fakeSM{}}
	h.r = &SecretRotationReconciler{
		Client:    c,
		APIReader: c,
		Scheme:    scheme,
		Recorder:  events.NewFakeRecorder(100),
		Clock:     h.clock,
		Generator: generator.New(),
		SecretsManager: func(context.Context, string) (sink.SecretsManagerAPI, error) {
			return h.sm, nil
		},
	}
	return h
}

func (h *harness) reconcile(name string) (ctrl.Result, error) {
	h.t.Helper()
	return h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
}

func (h *harness) mustReconcile(name string) ctrl.Result {
	h.t.Helper()
	res, err := h.reconcile(name)
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (h *harness) secret(name string) *corev1.Secret {
	h.t.Helper()
	s := &corev1.Secret{}
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, s); err != nil {
		h.t.Fatalf("get secret: %v", err)
	}
	return s
}

func (h *harness) sr(name string) *rotationv1alpha1.SecretRotation {
	h.t.Helper()
	sr := &rotationv1alpha1.SecretRotation{}
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, sr); err != nil {
		h.t.Fatalf("get secretrotation: %v", err)
	}
	return sr
}

func newSR(mutate ...func(*rotationv1alpha1.SecretRotation)) *rotationv1alpha1.SecretRotation {
	sr := &rotationv1alpha1.SecretRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns, UID: "11111111-2222-3333-4444-555555555555", Generation: 1},
		Spec: rotationv1alpha1.SecretRotationSpec{
			SecretName:       "db-creds",
			RotationInterval: metav1.Duration{Duration: time.Hour},
			Keys: []rotationv1alpha1.KeySpec{
				{Name: "password", Generator: rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword, Length: 24}},
				{Name: "token", Generator: rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRandomBytes, Length: 16, Encoding: rotationv1alpha1.EncodingHex}},
			},
			DeletionPolicy: rotationv1alpha1.DeletionPolicyDelete,
		},
	}
	for _, m := range mutate {
		m(sr)
	}
	return sr
}

func condition(sr *rotationv1alpha1.SecretRotation, typ string) *metav1.Condition {
	return meta.FindStatusCondition(sr.Status.Conditions, typ)
}

func TestCreatesSecretOnFirstReconcile(t *testing.T) {
	h := newHarness(t, newSR())
	res := h.mustReconcile("db")

	s := h.secret("db-creds")
	if len(s.Data["password"]) != 24 || len(s.Data["token"]) != 32 {
		t.Fatalf("unexpected data lengths: password=%d token=%d", len(s.Data["password"]), len(s.Data["token"]))
	}
	if got := readState(s); got.Version != 1 || !got.RotatedAt.Equal(t0) {
		t.Fatalf("state = %+v", got)
	}
	if s.Labels[rotationv1alpha1.LabelManagedBy] != rotationv1alpha1.ManagedByValue {
		t.Error("missing managed-by label")
	}
	if owner := metav1.GetControllerOf(s); owner == nil || owner.Name != "db" {
		t.Error("secret is not controlled by the SecretRotation")
	}

	sr := h.sr("db")
	if !containsString(sr.Finalizers, rotationv1alpha1.Finalizer) {
		t.Error("finalizer not added")
	}
	if c := condition(sr, rotationv1alpha1.ConditionReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Ready condition = %+v", c)
	}
	if sr.Status.CurrentVersion != 1 || !sr.Status.NextRotationTime.Time.Equal(t0.Add(time.Hour)) {
		t.Errorf("status = %+v", sr.Status)
	}
	if res.RequeueAfter != time.Hour {
		t.Errorf("RequeueAfter = %v, want 1h", res.RequeueAfter)
	}
}

func TestRotatesOnlyWhenDue(t *testing.T) {
	h := newHarness(t, newSR())
	h.mustReconcile("db")
	first := h.secret("db-creds").Data["password"]

	h.clock.Step(59 * time.Minute)
	res := h.mustReconcile("db")
	if !bytes.Equal(h.secret("db-creds").Data["password"], first) {
		t.Fatal("rotated before the interval elapsed")
	}
	if res.RequeueAfter != time.Minute {
		t.Errorf("RequeueAfter = %v, want 1m", res.RequeueAfter)
	}

	h.clock.Step(time.Minute)
	h.mustReconcile("db")
	s := h.secret("db-creds")
	if bytes.Equal(s.Data["password"], first) {
		t.Fatal("did not rotate once due")
	}
	if v := readState(s).Version; v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if _, ok := s.Data["password"+rotationv1alpha1.PreviousSuffix]; ok {
		t.Error("previous value kept although keepPrevious=false")
	}
}

func TestKeepPrevious(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) { sr.Spec.KeepPrevious = true }))
	h.mustReconcile("db")
	first := h.secret("db-creds").Data["password"]

	h.clock.Step(time.Hour)
	h.mustReconcile("db")
	s := h.secret("db-creds")
	if !bytes.Equal(s.Data["password.previous"], first) {
		t.Fatal("password.previous does not hold the prior value")
	}
}

func TestManualTriggerRotatesExactlyOnce(t *testing.T) {
	h := newHarness(t, newSR())
	h.mustReconcile("db")

	sr := h.sr("db")
	sr.Annotations = map[string]string{rotationv1alpha1.AnnotationRotateNow: "incident-42"}
	if err := h.c.Update(context.Background(), sr); err != nil {
		t.Fatal(err)
	}
	h.mustReconcile("db")
	if v := readState(h.secret("db-creds")).Version; v != 2 {
		t.Fatalf("version after trigger = %d, want 2", v)
	}
	// Re-applying the same annotation value must not rotate again.
	h.mustReconcile("db")
	if v := readState(h.secret("db-creds")).Version; v != 2 {
		t.Fatalf("version after second reconcile = %d, want 2", v)
	}
}

func TestAddedKeyIsFilledWithoutRotatingOthers(t *testing.T) {
	h := newHarness(t, newSR())
	h.mustReconcile("db")
	before := h.secret("db-creds")

	sr := h.sr("db")
	sr.Spec.Keys = append(sr.Spec.Keys, rotationv1alpha1.KeySpec{
		Name: "api-key", Generator: rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword},
	})
	if err := h.c.Update(context.Background(), sr); err != nil {
		t.Fatal(err)
	}
	h.clock.Step(10 * time.Minute)
	h.mustReconcile("db")

	after := h.secret("db-creds")
	if len(after.Data["api-key"]) == 0 {
		t.Fatal("new key not generated")
	}
	if !bytes.Equal(before.Data["password"], after.Data["password"]) {
		t.Error("existing key was rotated")
	}
	if st := readState(after); !st.RotatedAt.Equal(t0) || st.Version != 2 {
		t.Errorf("state = %+v; schedule should be unchanged and version bumped", st)
	}
}

func TestRepairsDeletedSecret(t *testing.T) {
	h := newHarness(t, newSR())
	h.mustReconcile("db")
	if err := h.c.Delete(context.Background(), h.secret("db-creds")); err != nil {
		t.Fatal(err)
	}
	h.mustReconcile("db")
	h.secret("db-creds") // fails the test if absent
}

// Regression: recreating a deleted Secret used to restart the counter at 1,
// which matched the workload's existing "v1" marker and skipped the rollout
// even though the credentials had changed.
func TestRecreatedSecretKeepsVersionMonotonic(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns}}
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.RestartTargets = []rotationv1alpha1.WorkloadRef{{Kind: "Deployment", Name: "api"}}
	}), dep)
	h.mustReconcile("db")
	if err := h.c.Delete(context.Background(), h.secret("db-creds")); err != nil {
		t.Fatal(err)
	}
	h.mustReconcile("db")

	if v := readState(h.secret("db-creds")).Version; v != 2 {
		t.Fatalf("version after recreate = %d, want 2", v)
	}
	key, want := restartAnnotation(h.sr("db"), 2)
	got := &appsv1.Deployment{}
	_ = h.c.Get(context.Background(), client.ObjectKeyFromObject(dep), got)
	if got.Spec.Template.Annotations[key] != want {
		t.Errorf("workload not rolled after recreate: annotation = %q, want %q", got.Spec.Template.Annotations[key], want)
	}
}

func TestRestartsWorkloadsIdempotently(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns}}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: ns}}
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.RestartTargets = []rotationv1alpha1.WorkloadRef{{Kind: "Deployment", Name: "api"}, {Kind: "StatefulSet", Name: "worker"}}
	}), dep, sts)
	h.mustReconcile("db")

	key, want := restartAnnotation(h.sr("db"), 1)
	got := &appsv1.Deployment{}
	_ = h.c.Get(context.Background(), client.ObjectKeyFromObject(dep), got)
	if got.Spec.Template.Annotations[key] != want {
		t.Fatalf("deployment annotation = %q, want %q", got.Spec.Template.Annotations[key], want)
	}
	rv := got.ResourceVersion

	h.mustReconcile("db")
	_ = h.c.Get(context.Background(), client.ObjectKeyFromObject(dep), got)
	if got.ResourceVersion != rv {
		t.Error("deployment patched again although already at the current version")
	}

	h.clock.Step(time.Hour)
	h.mustReconcile("db")
	_ = h.c.Get(context.Background(), client.ObjectKeyFromObject(dep), got)
	if _, want2 := restartAnnotation(h.sr("db"), 2); got.Spec.Template.Annotations[key] != want2 {
		t.Errorf("deployment not rolled for version 2")
	}
	if c := condition(h.sr("db"), rotationv1alpha1.ConditionWorkloadsRestarted); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("WorkloadsRestarted = %+v", c)
	}
}

func TestMissingWorkloadDoesNotBlockRotation(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.RestartTargets = []rotationv1alpha1.WorkloadRef{{Kind: "Deployment", Name: "ghost"}}
	}))
	if _, err := h.reconcile("db"); err == nil {
		t.Fatal("expected an error so the request is retried with backoff")
	}
	if readState(h.secret("db-creds")).Version != 1 {
		t.Fatal("secret should still be rotated")
	}
	sr := h.sr("db")
	if c := condition(sr, rotationv1alpha1.ConditionWorkloadsRestarted); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("WorkloadsRestarted = %+v", c)
	}
	// Retrying must not rotate again.
	_, _ = h.reconcile("db")
	if readState(h.secret("db-creds")).Version != 1 {
		t.Fatal("retry caused a second rotation")
	}
}

func TestSinkPushRetriesUntilSynced(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.KeepPrevious = true
		sr.Spec.Sinks.AWSSecretsManager = &rotationv1alpha1.AWSSecretsManagerSink{SecretID: "prod/db"}
	}))
	h.sm.fail = errors.New("throttled")
	if _, err := h.reconcile("db"); err == nil {
		t.Fatal("expected sink error")
	}
	if c := condition(h.sr("db"), rotationv1alpha1.ConditionSinksSynced); c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("SinksSynced = %+v", c)
	}

	h.sm.fail = nil
	h.mustReconcile("db")
	h.mustReconcile("db") // already synced: must not push again
	if len(h.sm.puts) != 1 {
		t.Fatalf("pushes = %d, want 1", len(h.sm.puts))
	}
	var payload map[string]string
	_ = json.Unmarshal([]byte(h.sm.puts[0]), &payload)
	if payload["password"] != string(h.secret("db-creds").Data["password"]) {
		t.Error("sink payload does not match the Secret")
	}
	if sr := h.sr("db"); sr.Status.SinkSyncedVersion != 1 {
		t.Errorf("SinkSyncedVersion = %d", sr.Status.SinkSyncedVersion)
	}
}

func TestAWSSinkDisabled(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.Sinks.AWSSecretsManager = &rotationv1alpha1.AWSSecretsManagerSink{SecretID: "x"}
	}))
	h.r.SecretsManager = nil
	if _, err := h.reconcile("db"); err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestOwnershipConflict(t *testing.T) {
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "db-creds", Namespace: ns,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: "999", Controller: ptr.To(true)}},
	}, Data: map[string][]byte{"password": []byte("untouched")}}
	h := newHarness(t, newSR(), foreign)
	res := h.mustReconcile("db")

	if string(h.secret("db-creds").Data["password"]) != "untouched" {
		t.Fatal("overwrote a Secret controlled by someone else")
	}
	if c := condition(h.sr("db"), rotationv1alpha1.ConditionReady); c == nil || c.Reason != "OwnershipConflict" {
		t.Errorf("Ready = %+v", c)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected a slow requeue")
	}
}

func TestAdoptsUnownedSecret(t *testing.T) {
	existing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: ns}, Data: map[string][]byte{"password": []byte("legacy")}}
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) { sr.Spec.KeepPrevious = true }), existing)
	h.mustReconcile("db")
	s := h.secret("db-creds")
	if string(s.Data["password.previous"]) != "legacy" || string(s.Data["password"]) == "legacy" {
		t.Fatalf("adoption should rotate and keep the legacy value as previous, got %v", s.Data)
	}
	if !metav1.IsControlledBy(s, h.sr("db")) {
		t.Error("adopted secret has no controller reference")
	}
}

func TestSuspend(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) { sr.Spec.Suspend = true }))
	h.mustReconcile("db")
	err := h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "db-creds"}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("suspended rotation created a secret (err=%v)", err)
	}
	if c := condition(h.sr("db"), rotationv1alpha1.ConditionReady); c == nil || c.Reason != "Suspended" {
		t.Errorf("Ready = %+v", c)
	}
}

func TestDeletionPolicyRetainOrphansSecret(t *testing.T) {
	h := newHarness(t, newSR(func(sr *rotationv1alpha1.SecretRotation) {
		sr.Spec.DeletionPolicy = rotationv1alpha1.DeletionPolicyRetain
	}))
	h.mustReconcile("db")
	if err := h.c.Delete(context.Background(), h.sr("db")); err != nil {
		t.Fatal(err)
	}
	h.mustReconcile("db")

	s := h.secret("db-creds")
	if len(s.OwnerReferences) != 0 {
		t.Errorf("owner references not removed: %v", s.OwnerReferences)
	}
	if _, ok := s.Labels[rotationv1alpha1.LabelManagedBy]; ok {
		t.Error("managed-by label not removed")
	}
	err := h.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "db"}, &rotationv1alpha1.SecretRotation{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("SecretRotation still present after finalizer removal (err=%v)", err)
	}
}

func TestDeletionPolicyDeleteKeepsOwnerRef(t *testing.T) {
	h := newHarness(t, newSR())
	h.mustReconcile("db")
	if err := h.c.Delete(context.Background(), h.sr("db")); err != nil {
		t.Fatal(err)
	}
	h.mustReconcile("db")
	// The fake client has no garbage collector; assert the owner reference
	// that lets the real one delete the Secret is still in place.
	if len(h.secret("db-creds").OwnerReferences) != 1 {
		t.Error("owner reference should remain for garbage collection")
	}
}

func TestNotFoundIsNoop(t *testing.T) {
	h := newHarness(t)
	if res := h.mustReconcile("missing"); res.RequeueAfter != 0 {
		t.Errorf("unexpected requeue %v", res)
	}
}

// fakeSM records SecretString writes and can be told to fail.
type fakeSM struct {
	puts []string
	fail error
}

func (f *fakeSM) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.puts = append(f.puts, aws.ToString(in.SecretString))
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeSM) CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return &secretsmanager.CreateSecretOutput{}, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
