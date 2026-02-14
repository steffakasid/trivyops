/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/steffakasid/eslog"
	"github.com/steffakasid/trivy-scanner/internal"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts a server daemon scanning a GitLab group periodically.",
	Long: `Starts a server daemon scanning a GitLab groupperiodically (based on a cron string definition).
The scan results are published as a prometheus metric which can then be made visible via prometheus or with
alert rules and AlertManager.

Variables:
  - METRICS_PORT		- the metrics endpoint when running in daemon mode [Default: 2112]
  - METRICS_CRON		- the cron string used to define how often metrics results are gathered from GitLab [Default: @every 6h]
  
Examples:
  trivyops server		- start the server`,
	Run: func(cmd *cobra.Command, args []string) {
		scan, err := initScanClient()
		eslog.LogIfError(err, eslog.Fatal)

		metrics := internal.NewMetrics(scan)

		metrics.StartDaemon()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
