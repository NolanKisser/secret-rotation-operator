// Package controller implements the SecretRotation reconciler.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
	"github.com/NolanKisser/secret-rotation-operator/internal/sink"
)

// SecretRotationReconciler reconciles SecretRotation objects.
type SecretRotationReconciler struct {
	client.Client
	// APIReader bypasses the informer cache. The cache only holds Secrets
	// labelled as managed by this operator (to bound memory on clusters with
	// many Secrets), so pre-existing Secrets and workloads are read directly.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	Clock     clock.PassiveClock
	Generator valueGenerator
	// SecretsManager builds AWS clients. Nil disables the AWS sink.
	SecretsManager sink.SecretsManagerClientFactory
	// MaxConcurrentReconciles bounds parallel reconciles.
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=rotation.nolankisser.github.io,resources=secretrotations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=rotation.nolankisser.github.io,resources=secretrotations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rotation.nolankisser.github.io,resources=secretrotations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile drives one SecretRotation toward its desired state. It is
// level-triggered: every decision is recomputed from the current state of the
// SecretRotation and its Secret, so missed or duplicated events are harmless.
func (r *SecretRotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	sr := &rotationv1alpha1.SecretRotation{}
	if err := r.Get(ctx, req.NamespacedName, sr); err != nil {
		if apierrors.IsNotFound(err) {
			forgetMetrics(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !sr.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, sr)
	}
	if controllerutil.AddFinalizer(sr, rotationv1alpha1.Finalizer) {
		if err := r.Update(ctx, sr); err != nil {
			return ctrl.Result{}, err
		}
	}

	base := sr.DeepCopy()
	sr.Status.ObservedGeneration = sr.Generation

	if sr.Spec.Suspend {
		r.setCondition(sr, rotationv1alpha1.ConditionReady, metav1.ConditionFalse, "Suspended", "Rotation is suspended")
		return ctrl.Result{}, r.patchStatus(ctx, sr, base)
	}

	secret, err := r.getSecret(ctx, sr)
	if err != nil {
		return ctrl.Result{}, err
	}
	if secret != nil {
		if owner := metav1.GetControllerOf(secret); owner != nil && owner.UID != sr.UID {
			msg := fmt.Sprintf("Secret %q is controlled by %s %q", secret.Name, owner.Kind, owner.Name)
			r.setCondition(sr, rotationv1alpha1.ConditionReady, metav1.ConditionFalse, "OwnershipConflict", msg)
			r.Recorder.Eventf(sr, secret, corev1.EventTypeWarning, "OwnershipConflict", "Reconcile", msg)
			// Not retried with backoff: only a human can resolve this.
			return ctrl.Result{RequeueAfter: 5 * time.Minute}, r.patchStatus(ctx, sr, base)
		}
	}

	now := r.Clock.Now()
	reason, missing := decide(sr, secret, now)
	if reason != reasonNone {
		secret, err = r.rotate(ctx, sr, secret, reason, missing, now)
		if err != nil {
			r.setCondition(sr, rotationv1alpha1.ConditionReady, metav1.ConditionFalse, "RotationFailed", err.Error())
			return ctrl.Result{}, errors.Join(err, r.patchStatus(ctx, sr, base))
		}
		log.Info("rotated secret", "secret", secret.Name, "reason", reason, "version", readState(secret).Version)
	}

	state := readState(secret)
	next := nextRotation(sr, state)
	sr.Status.CurrentVersion = state.Version
	sr.Status.LastRotationTime = &metav1.Time{Time: state.RotatedAt}
	sr.Status.NextRotationTime = &metav1.Time{Time: next}
	r.recordGauges(sr, state, next)

	// Downstream propagation. Both steps are idempotent and gated on the
	// version, so a failure in one never causes a re-rotation; it is simply
	// retried until it converges.
	restartErr := r.restartWorkloads(ctx, sr, state.Version)
	sinkErr := r.syncSinks(ctx, sr, secret, state.Version)

	if err := errors.Join(restartErr, sinkErr); err != nil {
		r.setCondition(sr, rotationv1alpha1.ConditionReady, metav1.ConditionFalse, "PropagationFailed", err.Error())
		return ctrl.Result{}, errors.Join(err, r.patchStatus(ctx, sr, base))
	}

	r.setCondition(sr, rotationv1alpha1.ConditionReady, metav1.ConditionTrue, "Rotated",
		fmt.Sprintf("Secret %q at version %d; next rotation %s", sr.Spec.SecretName, state.Version, next.UTC().Format(time.RFC3339)))
	if err := r.patchStatus(ctx, sr, base); err != nil {
		return ctrl.Result{}, err
	}

	// Sleep until the next rotation is due. Any spec change or Secret event
	// wakes the controller earlier.
	return ctrl.Result{RequeueAfter: max(next.Sub(r.Clock.Now()), time.Second)}, nil
}

// getSecret reads the managed Secret, returning nil if it does not exist.
func (r *SecretRotationReconciler) getSecret(ctx context.Context, sr *rotationv1alpha1.SecretRotation) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: sr.Namespace, Name: sr.Spec.SecretName}
	secret := &corev1.Secret{}
	err := r.Get(ctx, key, secret)
	if apierrors.IsNotFound(err) {
		// Cache miss may just mean the Secret is not labelled yet.
		err = r.APIReader.Get(ctx, key, secret)
	}
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return secret, err
}

// rotate writes new Secret data in a single create/update.
func (r *SecretRotationReconciler) rotate(ctx context.Context, sr *rotationv1alpha1.SecretRotation, existing *corev1.Secret, reason rotationReason, missing []string, now time.Time) (*corev1.Secret, error) {
	secret := existing
	if secret == nil {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: sr.Spec.SecretName, Namespace: sr.Namespace},
			Type:       corev1.SecretTypeOpaque,
		}
	} else {
		secret = existing.DeepCopy()
	}

	data, err := buildData(sr, secret.Data, reason, missing, r.Generator)
	if err != nil {
		errorsTotal.WithLabelValues(sr.Namespace, sr.Name, "generate").Inc()
		return nil, fmt.Errorf("generating secret data: %w", err)
	}
	secret.Data = data

	prev := readState(existing)
	// The Secret is the source of truth, but if it was deleted (or replaced)
	// its counter is gone. Never let the version go backwards: restart
	// markers on workloads compare by version, so reusing "v1" for new
	// credentials would silently skip the rollout.
	st := secretState{Version: max(prev.Version, sr.Status.CurrentVersion) + 1, RotatedAt: now, Trigger: prev.Trigger}
	if reason.fullRotation() {
		st.Trigger = sr.Annotations[rotationv1alpha1.AnnotationRotateNow]
	} else {
		// Filling in missing keys does not reset the schedule.
		st.RotatedAt = prev.RotatedAt
	}
	writeState(secret, st)
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	secret.Labels[rotationv1alpha1.LabelManagedBy] = rotationv1alpha1.ManagedByValue
	if err := controllerutil.SetControllerReference(sr, secret, r.Scheme); err != nil {
		return nil, err
	}

	if existing == nil {
		err = r.Create(ctx, secret)
	} else {
		// Update carries resourceVersion: a concurrent writer causes a
		// Conflict and a retry from fresh state, never a lost update.
		err = r.Update(ctx, secret)
	}
	if err != nil {
		errorsTotal.WithLabelValues(sr.Namespace, sr.Name, "write").Inc()
		return nil, fmt.Errorf("writing Secret %q: %w", secret.Name, err)
	}

	rotationsTotal.WithLabelValues(sr.Namespace, sr.Name, string(reason)).Inc()
	r.Recorder.Eventf(sr, secret, corev1.EventTypeNormal, string(reason), "Rotate",
		"Rotated Secret %q to version %d", secret.Name, st.Version)
	return secret, nil
}

// restartWorkloads stamps each target's pod template with the current version.
// Workloads already at that version are left alone, so this is safe to call on
// every reconcile.
func (r *SecretRotationReconciler) restartWorkloads(ctx context.Context, sr *rotationv1alpha1.SecretRotation, version int64) error {
	if len(sr.Spec.RestartTargets) == 0 {
		meta.RemoveStatusCondition(&sr.Status.Conditions, rotationv1alpha1.ConditionWorkloadsRestarted)
		return nil
	}
	key, value := restartAnnotation(sr, version)
	var errs []error
	for _, t := range sr.Spec.RestartTargets {
		if err := r.restartOne(ctx, sr.Namespace, t, key, value); err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", t.Kind, t.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		errorsTotal.WithLabelValues(sr.Namespace, sr.Name, "restart").Inc()
		r.setCondition(sr, rotationv1alpha1.ConditionWorkloadsRestarted, metav1.ConditionFalse, "RestartFailed", err.Error())
		return err
	}
	r.setCondition(sr, rotationv1alpha1.ConditionWorkloadsRestarted, metav1.ConditionTrue, "UpToDate",
		fmt.Sprintf("%d workload(s) at version %d", len(sr.Spec.RestartTargets), version))
	return nil
}

func (r *SecretRotationReconciler) restartOne(ctx context.Context, namespace string, t rotationv1alpha1.WorkloadRef, key, value string) error {
	var obj client.Object
	switch t.Kind {
	case "Deployment":
		obj = &appsv1.Deployment{}
	case "StatefulSet":
		obj = &appsv1.StatefulSet{}
	case "DaemonSet":
		obj = &appsv1.DaemonSet{}
	default:
		return fmt.Errorf("unsupported kind %q", t.Kind)
	}
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: t.Name}, obj); err != nil {
		return err
	}
	tmpl := podTemplate(obj)
	if tmpl.Annotations[key] == value {
		return nil
	}
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	if tmpl.Annotations == nil {
		tmpl.Annotations = map[string]string{}
	}
	tmpl.Annotations[key] = value
	return r.Patch(ctx, obj, patch)
}

func podTemplate(obj client.Object) *corev1.PodTemplateSpec {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return &o.Spec.Template
	case *appsv1.StatefulSet:
		return &o.Spec.Template
	case *appsv1.DaemonSet:
		return &o.Spec.Template
	}
	return nil
}

// restartAnnotation returns the pod-template annotation for this
// SecretRotation. The key embeds a short hash of the name so several
// SecretRotations can target one workload without overwriting each other,
// while staying inside the 63-character annotation name limit.
func restartAnnotation(sr *rotationv1alpha1.SecretRotation, version int64) (string, string) {
	sum := sha256.Sum256([]byte(sr.Name))
	key := rotationv1alpha1.AnnotationRestartedFor + "-" + hex.EncodeToString(sum[:4])
	return key, fmt.Sprintf("%s/v%d", sr.Name, version)
}

// syncSinks pushes the current version to external sinks that are behind.
func (r *SecretRotationReconciler) syncSinks(ctx context.Context, sr *rotationv1alpha1.SecretRotation, secret *corev1.Secret, version int64) error {
	sinks, err := r.sinksFor(ctx, sr)
	if err != nil {
		r.setCondition(sr, rotationv1alpha1.ConditionSinksSynced, metav1.ConditionFalse, "SinkConfigError", err.Error())
		return err
	}
	if len(sinks) == 0 {
		meta.RemoveStatusCondition(&sr.Status.Conditions, rotationv1alpha1.ConditionSinksSynced)
		return nil
	}
	if sr.Status.SinkSyncedVersion == version {
		return nil
	}
	req := sink.PushRequest{OwnerUID: string(sr.UID), Version: version, Data: sinkPayload(sr, secret.Data)}
	for _, s := range sinks {
		if err := s.Push(ctx, req); err != nil {
			errorsTotal.WithLabelValues(sr.Namespace, sr.Name, "sink").Inc()
			r.setCondition(sr, rotationv1alpha1.ConditionSinksSynced, metav1.ConditionFalse, "PushFailed", fmt.Sprintf("%s: %v", s.Name(), err))
			r.Recorder.Eventf(sr, nil, corev1.EventTypeWarning, "SinkPushFailed", "Sync", "%s: %v", s.Name(), err)
			return err
		}
	}
	sr.Status.SinkSyncedVersion = version
	r.setCondition(sr, rotationv1alpha1.ConditionSinksSynced, metav1.ConditionTrue, "Synced", fmt.Sprintf("Version %d pushed to %d sink(s)", version, len(sinks)))
	return nil
}

func (r *SecretRotationReconciler) sinksFor(ctx context.Context, sr *rotationv1alpha1.SecretRotation) ([]sink.Sink, error) {
	var out []sink.Sink
	if cfg := sr.Spec.Sinks.AWSSecretsManager; cfg != nil {
		if r.SecretsManager == nil {
			return nil, errors.New("AWS Secrets Manager sink requested but the operator was started with --enable-aws-sink=false")
		}
		c, err := r.SecretsManager(ctx, cfg.Region)
		if err != nil {
			return nil, fmt.Errorf("building AWS client: %w", err)
		}
		out = append(out, &sink.AWSSecretsManager{Client: c, SecretID: cfg.SecretID})
	}
	return out, nil
}

// finalize runs before the SecretRotation disappears. With DeletionPolicy
// Retain, it detaches the Secret so garbage collection keeps it.
func (r *SecretRotationReconciler) finalize(ctx context.Context, sr *rotationv1alpha1.SecretRotation) error {
	if !controllerutil.ContainsFinalizer(sr, rotationv1alpha1.Finalizer) {
		return nil
	}
	if sr.Spec.DeletionPolicy == rotationv1alpha1.DeletionPolicyRetain {
		secret, err := r.getSecret(ctx, sr)
		if err != nil {
			return err
		}
		if secret != nil && metav1.IsControlledBy(secret, sr) {
			patch := client.MergeFrom(secret.DeepCopy())
			if err := controllerutil.RemoveOwnerReference(sr, secret, r.Scheme); err != nil {
				return err
			}
			delete(secret.Labels, rotationv1alpha1.LabelManagedBy)
			if err := r.Patch(ctx, secret, patch); err != nil {
				return fmt.Errorf("orphaning Secret %q: %w", secret.Name, err)
			}
			r.Recorder.Eventf(sr, secret, corev1.EventTypeNormal, "Retained", "Finalize", "Secret %q retained after deletion", secret.Name)
		}
	}
	forgetMetrics(sr.Namespace, sr.Name)
	controllerutil.RemoveFinalizer(sr, rotationv1alpha1.Finalizer)
	return r.Update(ctx, sr)
}

func (r *SecretRotationReconciler) setCondition(sr *rotationv1alpha1.SecretRotation, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&sr.Status.Conditions, metav1.Condition{
		Type:               typ,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: sr.Generation,
	})
}

func (r *SecretRotationReconciler) patchStatus(ctx context.Context, sr, base *rotationv1alpha1.SecretRotation) error {
	return client.IgnoreNotFound(r.Status().Patch(ctx, sr, client.MergeFrom(base)))
}

func (r *SecretRotationReconciler) recordGauges(sr *rotationv1alpha1.SecretRotation, st secretState, next time.Time) {
	lastRotationTimestamp.WithLabelValues(sr.Namespace, sr.Name).Set(float64(st.RotatedAt.Unix()))
	nextRotationTimestamp.WithLabelValues(sr.Namespace, sr.Name).Set(float64(next.Unix()))
	secretVersion.WithLabelValues(sr.Namespace, sr.Name).Set(float64(st.Version))
}

// SetupWithManager registers the controller.
func (r *SecretRotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	// Ignore status-only updates (which we cause ourselves); react to spec
	// changes, the rotate-now annotation, and deletion.
	srPredicate := predicate.Or(
		predicate.GenerationChangedPredicate{},
		predicate.AnnotationChangedPredicate{},
		predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
			return !e.ObjectNew.GetDeletionTimestamp().IsZero()
		}},
	)
	return ctrl.NewControllerManagedBy(mgr).
		For(&rotationv1alpha1.SecretRotation{}, builder.WithPredicates(srPredicate)).
		// Owning the Secret means deleting or editing it externally triggers
		// an immediate repair.
		Owns(&corev1.Secret{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: max(r.MaxConcurrentReconciles, 1)}).
		Named("secretrotation").
		Complete(r)
}
