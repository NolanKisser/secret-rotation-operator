// Command manager runs the secret-rotation-operator.
package main

import (
	"crypto/tls"
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	rotationv1alpha1 "github.com/NolanKisser/secret-rotation-operator/api/v1alpha1"
	"github.com/NolanKisser/secret-rotation-operator/internal/controller"
	"github.com/NolanKisser/secret-rotation-operator/internal/generator"
	"github.com/NolanKisser/secret-rotation-operator/internal/sink"
)

var (
	// version is set at build time via -ldflags "-X main.version=...".
	version  = "dev"
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(rotationv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		secureMetrics        bool
		enableLeaderElection bool
		enableAWSSink        bool
		concurrency          int
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443", "Address the metrics endpoint binds to. Use 0 to disable.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address the health probe endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics over HTTPS with Kubernetes authn/authz.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election so only one replica reconciles at a time.")
	flag.BoolVar(&enableAWSSink, "enable-aws-sink", false, "Allow SecretRotations to mirror into AWS Secrets Manager.")
	flag.IntVar(&concurrency, "max-concurrent-reconciles", 4, "Maximum SecretRotations reconciled in parallel.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	metricsOpts := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		// Disable HTTP/2 to avoid the Rapid Reset class of CVEs.
		TLSOpts: []func(*tls.Config){func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }},
	}
	if secureMetrics {
		metricsOpts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOpts,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "secret-rotation-operator.rotation.nolankisser.github.io",
		// Released on SIGTERM so a rolling update of the operator hands over
		// leadership immediately instead of waiting for lease expiry.
		LeaderElectionReleaseOnCancel: true,
		Cache:                         controller.CacheOptions(),
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	var smFactory sink.SecretsManagerClientFactory
	if enableAWSSink {
		smFactory = sink.NewSecretsManagerClientFactory()
	}

	if err := (&controller.SecretRotationReconciler{
		Client:                  mgr.GetClient(),
		APIReader:               mgr.GetAPIReader(),
		Scheme:                  mgr.GetScheme(),
		Recorder:                mgr.GetEventRecorder("secret-rotation-operator"),
		Clock:                   clock.RealClock{},
		Generator:               generator.New(),
		SecretsManager:          smFactory,
		MaxConcurrentReconciles: concurrency,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecretRotation")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "version", version, "awsSink", enableAWSSink)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
