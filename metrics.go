package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/internal"
	"net/http"
	"strconv"
)

var (
	registeredGauges []prometheus.Gauge
	trivyResults     internal.TrivyResults
	reg              *prometheus.Registry
)

func startDaemon() {
	reg = prometheus.NewRegistry()
	initCron()
	fetchResults()
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	http.Handle("/metrics", promHandler)

	logger.Infoln("Starting metrics daemon...")
	err := http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt(internal.METRICS_PORT)), nil)
	if err != nil {
		logger.Fatal(err)
	}
}

func fetchResults() {
	projs, err := scan.GitLabClient.GetProjects(scan.ID)
	if err != nil {
		logger.Errorf("failed getting projects: %v", err)
	}
	trivyResults, err = scan.ScanProjects(projs)
	if err != nil {
		logger.Errorf("failed scan projects: %v", err)
	}
	updateRegister()
}

func updateRegister() {
	unregisterOldGauges()
	registeredGauges = []prometheus.Gauge{}
	for _, trivy := range trivyResults {

		var trivyIgnore string
		if len(trivy.Ignore) > 0 {
			trivyIgnore = "true"
		} else {
			trivyIgnore = "false"
		}

		labels := map[string]string{
			"Project":         trivy.ProjName,
			"Id":              strconv.Itoa(trivy.ProjId),
			"Vulnerabilities": strconv.Itoa(trivy.Vulnerabilities.Count),
			"High":            strconv.Itoa(trivy.Vulnerabilities.High),
			"Critical":        strconv.Itoa(trivy.Vulnerabilities.Critical),
			"ScannedJobName":  viper.GetString(internal.JOB_NAME),
			"JobState":        trivy.State,
			"trivyignore":     trivyIgnore,
		}

		gauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "trivy",
			Subsystem:   "exporter",
			Name:        "findings",
			Help:        "this is a cached result and will updated every hour",
			ConstLabels: labels,
		})
		gauge.Set(float64(trivy.Vulnerabilities.Count))
		registeredGauges = append(registeredGauges, gauge)
		reg.MustRegister(gauge)
	}
}

func unregisterOldGauges() {
	for _, gauge := range registeredGauges {
		reg.Unregister(gauge)
	}
}

func initCron() {
	c := cron.New()
	_, err := c.AddFunc(viper.GetString(internal.METRICS_CRON), fetchResults)
	if err != nil {
		logger.Fatal(err)
	}
	c.Start()
}
