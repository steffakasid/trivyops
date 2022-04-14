package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/internal"
)

func startDaemon() {
	logger.Debug("Starting metrics daemon...")
	c := cron.New()
	recordMetrics()
	_, err := c.AddFunc("@every 6h", recordMetrics)
	if err != nil {
		logger.Fatal(err)
	}
	http.Handle("/metrics", promhttp.Handler())
	err = http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt(internal.METRICS_PORT)), nil)

	if err != nil {
		logger.Fatal(err)
	}
}

func recordMetrics() {
	projs, err := scan.GitLabClient.GetProjects(scan.ID)
	if err != nil {
		logger.Errorf("failed getting projects: %v", err)
	}

	trivyResults, err := scan.ScanProjects(projs)

	if err != nil {
		logger.Error(err)
	} else {
		for _, trivy := range trivyResults {
			var trivyIgnore string
			if len(trivy.Ignore) > 0 {
				trivyIgnore = "true"
			} else {
				trivyIgnore = "false"
			}
			projectName := strings.ReplaceAll(trivy.ProjName, "-", "_")
			projectName = projectName + "_" + strconv.Itoa(trivy.ProjId)

			logger.Debugf("Add Prjoect %s\n", projectName)

			labels := map[string]string{
				"Project":         trivy.ProjName,
				"Id":              strconv.Itoa(trivy.ProjId),
				"Vulnerabilities": strconv.Itoa(trivy.Vulnerabilities.Count),
				"High":            strconv.Itoa(trivy.Vulnerabilities.High),
				"Critical":        strconv.Itoa(trivy.Vulnerabilities.Critical),
				"JobState":        trivy.State,
				"trivyignore":     trivyIgnore,
			}
			opts := prometheus.GaugeOpts{
				Namespace:   "trivy",
				Subsystem:   "exporter",
				Name:        "findings",
				Help:        "this is a cached result updated every 2 hours",
				ConstLabels: labels,
			}
			logger.Debugf("Register metrics collector for %s", projectName)
			promauto.NewGauge(opts).Set(1)
		}
	}
}
