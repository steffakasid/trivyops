package internal

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
	"github.com/steffakasid/eslog"
)

var (
	registeredGauges []prometheus.Gauge
	reg              *prometheus.Registry
)

type Metrics struct {
	scan         *Scan
	trivyResults TrivyResults
}

func NewMetrics(s *Scan) *Metrics {
	return &Metrics{
		scan: s,
	}
}

func (m *Metrics) StartDaemon() {
	reg = prometheus.NewRegistry()
	m.initCron()
	m.fetchResults()
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", promHandler)

	eslog.InfoLn("Starting metrics daemon...")
	err := http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt(METRICS_PORT)), nil)
	if err != nil {
		eslog.Fatal(err)
	}
}

func (m *Metrics) fetchResults() {
	projs, err := m.scan.GitLabClient.GetProjects(m.scan.ID)
	if err != nil {
		eslog.Errorf("failed getting projects: %v", err)
	}
	m.trivyResults, err = m.scan.ScanProjects(projs)
	if err != nil {
		eslog.Errorf("failed scan projects: %v", err)
	}
	m.updateRegister()
}

func (m *Metrics) updateRegister() {
	m.unregisterOldGauges()
	registeredGauges = []prometheus.Gauge{}
	for _, trivy := range m.trivyResults {

		var trivyIgnore string
		if len(trivy.Ignore) > 0 {
			trivyIgnore = "true"
		} else {
			trivyIgnore = "false"
		}

		labels := map[string]string{
			"project":          trivy.ProjName,
			"id":               strconv.FormatInt(trivy.ProjId, 10),
			"scanned_job_name": viper.GetString(JOB_NAME),
			"trivyignore":      trivyIgnore,
		}

		labels["type"] = "total"
		gaugeTotal := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "trivy",
			Subsystem:   "exporter",
			Name:        "findings",
			Help:        "this is a cached result and will updated every hour",
			ConstLabels: labels,
		})
		labels["type"] = "critical"
		gaugeCritical := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "trivy",
			Subsystem:   "exporter",
			Name:        "findings",
			Help:        "this is a cached result and will updated every hour",
			ConstLabels: labels,
		})
		labels["type"] = "high"
		gaugeHigh := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "trivy",
			Subsystem:   "exporter",
			Name:        "findings",
			Help:        "this is a cached result and will updated every hour",
			ConstLabels: labels,
		})
		gaugeTotal.Set(float64(trivy.Vulnerabilities.Count))
		gaugeCritical.Set(float64(trivy.Vulnerabilities.Critical))
		gaugeHigh.Set(float64(trivy.Vulnerabilities.High))
		registeredGauges = append(registeredGauges, gaugeTotal, gaugeCritical, gaugeHigh)
		reg.MustRegister(gaugeTotal)
		reg.MustRegister(gaugeCritical)
		reg.MustRegister(gaugeHigh)
	}
}

func (m *Metrics) unregisterOldGauges() {
	for _, gauge := range registeredGauges {
		reg.Unregister(gauge)
	}
}

func (m *Metrics) initCron() {
	c := cron.New()
	_, err := c.AddFunc(viper.GetString(METRICS_CRON), m.fetchResults)
	if err != nil {
		eslog.Fatal(err)
	}
	c.Start()
}
