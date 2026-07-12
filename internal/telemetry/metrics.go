package telemetry

import "github.com/prometheus/client_golang/prometheus"

var (
	Scans           = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cortasentry_scans_total", Help: "Discovery scans by terminal result."}, []string{"result"})
	Probes          = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cortasentry_probes_total", Help: "Authorized probes by result."}, []string{"result"})
	Errors          = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cortasentry_errors_total", Help: "Errors by subsystem."}, []string{"subsystem"})
	Observations    = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cortasentry_observations_total", Help: "Persisted observations by source."}, []string{"source"})
	Assets          = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cortasentry_assets_created_total", Help: "Assets created by resolver outcome."}, []string{"outcome"})
	Findings        = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cortasentry_findings", Help: "Current findings by state and severity."}, []string{"state", "severity"})
	QueueDepth      = prometheus.NewGauge(prometheus.GaugeOpts{Name: "cortasentry_job_queue_depth", Help: "Jobs accepted and not terminal in this process."})
	JobDuration     = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "cortasentry_job_duration_seconds", Help: "Job durations.", Buckets: prometheus.DefBuckets}, []string{"type", "result"})
	RuleEvaluations = prometheus.NewCounter(prometheus.CounterOpts{Name: "cortasentry_rule_evaluations_total", Help: "Fingerprint rule evaluations."})
)

func init() {
	prometheus.MustRegister(Scans, Probes, Errors, Observations, Assets, Findings, QueueDepth, JobDuration, RuleEvaluations)
}
