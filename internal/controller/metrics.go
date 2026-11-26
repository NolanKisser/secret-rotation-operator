package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const metricsNamespace = "secret_rotation"

var (
	rotationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "rotations_total",
		Help:      "Number of successful Secret rotations, by reason.",
	}, []string{"namespace", "name", "reason"})

	errorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "errors_total",
		Help:      "Number of reconcile failures, by stage (generate, write, restart, sink).",
	}, []string{"namespace", "name", "stage"})

	lastRotationTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "last_rotation_timestamp_seconds",
		Help:      "Unix time of the most recent rotation.",
	}, []string{"namespace", "name"})

	nextRotationTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "next_rotation_timestamp_seconds",
		Help:      "Unix time the next rotation is due. Alert when time() exceeds this by a margin: rotation is stuck.",
	}, []string{"namespace", "name"})

	secretVersion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "secret_version",
		Help:      "Current rotation counter of the managed Secret.",
	}, []string{"namespace", "name"})
)

func init() {
	metrics.Registry.MustRegister(rotationsTotal, errorsTotal, lastRotationTimestamp, nextRotationTimestamp, secretVersion)
}

// forgetMetrics removes per-object series so deleted resources do not linger
// as stale time series.
func forgetMetrics(namespace, name string) {
	labels := prometheus.Labels{"namespace": namespace, "name": name}
	rotationsTotal.DeletePartialMatch(labels)
	errorsTotal.DeletePartialMatch(labels)
	lastRotationTimestamp.Delete(labels)
	nextRotationTimestamp.Delete(labels)
	secretVersion.Delete(labels)
}
