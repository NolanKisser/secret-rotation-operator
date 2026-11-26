// Package integration runs the controller against a real kube-apiserver and
// etcd (controller-runtime envtest). It covers what the fake client cannot:
// CRD schema and CEL validation, the label-filtered informer cache, owner
// watches, and finalizer handling by the API server.
//
// Requires KUBEBUILDER_ASSETS (see `make test-integration`); skipped otherwise.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
	"github.com/NolanKisser/secret-rotation-operator/internal/controller"
	"github.com/NolanKisser/secret-rotation-operator/internal/generator"
)

var k8s client.Client

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		fmt.Println("KUBEBUILDER_ASSETS not set; skipping envtest integration tests")
		os.Exit(0)
	}
	logf.SetLogger(zap.New(zap.WriteTo(os.Stderr), zap.UseDevMode(true)))

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = rotationv1alpha1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   controller.CacheOptions(),
	})
	if err != nil {
		panic(err)
	}
	if err := (&controller.SecretRotationReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    scheme,
		Recorder:  mgr.GetEventRecorder("test"),
		Generator: generator.New(),
	}).SetupWithManager(mgr); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()

	// Tests use a direct client so they observe the API server, not the
	// operator's filtered cache.
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}

	code := m.Run()
	cancel()
	_ = env.Stop()
	os.Exit(code)
}

func namespace(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	name = strings.ReplaceAll(name, "/", "-")
	if len(name) > 50 {
		name = name[:50]
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8s.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	return name
}

func eventually(t *testing.T, desc string, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := cond()
		if ok {
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (last error: %v)", desc, lastErr)
}

func sr(ns string) *rotationv1alpha1.SecretRotation {
	return &rotationv1alpha1.SecretRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns},
		Spec: rotationv1alpha1.SecretRotationSpec{
			SecretName:       "db-creds",
			RotationInterval: metav1.Duration{Duration: 24 * time.Hour},
			Keys: []rotationv1alpha1.KeySpec{
				{Name: "password", Generator: rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorPassword}},
			},
		},
	}
}

func getSecret(ns string) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	return s, k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db-creds"}, s)
}

func TestValidation(t *testing.T) {
	ns := namespace(t)
	ctx := context.Background()
	cases := map[string]func(*rotationv1alpha1.SecretRotation){
		"interval below minimum": func(s *rotationv1alpha1.SecretRotation) {
			s.Spec.RotationInterval = metav1.Duration{Duration: 30 * time.Second}
		},
		"rsa without bits": func(s *rotationv1alpha1.SecretRotation) {
			s.Spec.Keys[0].Generator = rotationv1alpha1.GeneratorSpec{Type: rotationv1alpha1.GeneratorRSAKey}
		},
		"bad key name": func(s *rotationv1alpha1.SecretRotation) { s.Spec.Keys[0].Name = "has space" },
		"no keys":      func(s *rotationv1alpha1.SecretRotation) { s.Spec.Keys = nil },
		"duplicate keys": func(s *rotationv1alpha1.SecretRotation) {
			s.Spec.Keys = append(s.Spec.Keys, s.Spec.Keys[0])
		},
		"weak password": func(s *rotationv1alpha1.SecretRotation) { s.Spec.Keys[0].Generator.Length = 4 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			obj := sr(ns)
			obj.Name = "invalid"
			mutate(obj)
			if err := k8s.Create(ctx, obj); !apierrors.IsInvalid(err) {
				t.Fatalf("expected Invalid, got %v", err)
			}
		})
	}

	t.Run("secretName is immutable", func(t *testing.T) {
		obj := sr(ns)
		obj.Name = "immutable"
		obj.Spec.Suspend = true
		if err := k8s.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
		obj.Spec.SecretName = "other"
		if err := k8s.Update(ctx, obj); !apierrors.IsInvalid(err) {
			t.Fatalf("expected Invalid, got %v", err)
		}
	})
}

func TestEndToEnd(t *testing.T) {
	ns := namespace(t)
	ctx := context.Background()

	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api", Image: "nginx"}}},
			},
		},
	}
	if err := k8s.Create(ctx, dep); err != nil {
		t.Fatal(err)
	}

	obj := sr(ns)
	obj.Spec.RestartTargets = []rotationv1alpha1.WorkloadRef{{Kind: "Deployment", Name: "api"}}
	if err := k8s.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}

	// Secret created, owned, and status Ready.
	eventually(t, "Ready condition", func() (bool, error) {
		cur := &rotationv1alpha1.SecretRotation{}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			return false, err
		}
		return meta.IsStatusConditionTrue(cur.Status.Conditions, rotationv1alpha1.ConditionReady) && cur.Status.CurrentVersion == 1, nil
	})
	s, err := getSecret(ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data["password"]) != 32 {
		t.Fatalf("password length = %d", len(s.Data["password"]))
	}
	original := string(s.Data["password"])

	// Workload rolled.
	eventually(t, "deployment annotated", func() (bool, error) {
		d := &appsv1.Deployment{}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(dep), d); err != nil {
			return false, err
		}
		for k, v := range d.Spec.Template.Annotations {
			if strings.HasPrefix(k, rotationv1alpha1.AnnotationRestartedFor) && v == "db/v1" {
				return true, nil
			}
		}
		return false, nil
	})

	// External deletion is repaired via the owner watch.
	if err := k8s.Delete(ctx, s); err != nil {
		t.Fatal(err)
	}
	eventually(t, "secret recreated", func() (bool, error) {
		s, err := getSecret(ns)
		return err == nil && s.DeletionTimestamp == nil, err
	})

	// Manual trigger.
	cur := &rotationv1alpha1.SecretRotation{}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
		t.Fatal(err)
	}
	cur.Annotations = map[string]string{rotationv1alpha1.AnnotationRotateNow: "now"}
	if err := k8s.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	eventually(t, "manual rotation", func() (bool, error) {
		s, err := getSecret(ns)
		if err != nil {
			return false, err
		}
		return s.Annotations[rotationv1alpha1.AnnotationTrigger] == "now" && string(s.Data["password"]) != original, nil
	})
}

func TestAdoptsPreExistingSecret(t *testing.T) {
	ns := namespace(t)
	ctx := context.Background()
	// Unlabelled, so invisible to the operator's filtered cache.
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: ns},
		Data:       map[string][]byte{"password": []byte("legacy")},
	}
	if err := k8s.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	obj := sr(ns)
	obj.Spec.KeepPrevious = true
	if err := k8s.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	eventually(t, "adoption", func() (bool, error) {
		s, err := getSecret(ns)
		if err != nil {
			return false, err
		}
		return string(s.Data["password.previous"]) == "legacy" &&
			s.Labels[rotationv1alpha1.LabelManagedBy] == rotationv1alpha1.ManagedByValue, nil
	})
}

// TestSamplesAreValid server-side dry-runs every manifest in config/samples so
// documented examples cannot drift from the CRD schema.
func TestSamplesAreValid(t *testing.T) {
	ns := namespace(t)
	files, err := filepath.Glob(filepath.Join("..", "..", "config", "samples", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no samples found: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, doc := range strings.Split(string(raw), "\n---") {
			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				t.Fatalf("%s[%d]: %v", f, i, err)
			}
			if obj.GetKind() != "SecretRotation" {
				continue
			}
			obj.SetNamespace(ns)
			if err := k8s.Create(context.Background(), obj, client.DryRunAll); err != nil {
				t.Errorf("%s[%d] %s rejected: %v", filepath.Base(f), i, obj.GetName(), err)
			}
		}
	}
}

func TestRetainOnDelete(t *testing.T) {
	ns := namespace(t)
	ctx := context.Background()
	obj := sr(ns)
	obj.Spec.DeletionPolicy = rotationv1alpha1.DeletionPolicyRetain
	if err := k8s.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	eventually(t, "secret created", func() (bool, error) {
		_, err := getSecret(ns)
		return err == nil, nil
	})
	if err := k8s.Delete(ctx, obj); err != nil {
		t.Fatal(err)
	}
	eventually(t, "SecretRotation gone", func() (bool, error) {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(obj), &rotationv1alpha1.SecretRotation{})
		return apierrors.IsNotFound(err), nil
	})
	s, err := getSecret(ns)
	if err != nil {
		t.Fatalf("secret should be retained: %v", err)
	}
	if len(s.OwnerReferences) != 0 {
		t.Errorf("secret still has owner references: %v", s.OwnerReferences)
	}
}
