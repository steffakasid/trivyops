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
	"fmt"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/steffakasid/eslog"
	"github.com/steffakasid/trivy-scanner/internal"
	"github.com/steffakasid/trivy-scanner/output"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	V           = "v"
	VV          = "vv"
	VVV         = "vvv"
	OUTPUT      = "output"
	OUTPUT_FILE = "output-file"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a group in cli mode",
	Long: `This command starts the scan in cli mode and prints the results. The scan does the following:
1. Get all projects. 
    a) If no GroupID is defined, get all user projects where the user has at least developer rights
	b) Get all subprojects including those of subgroups from the given GroupID.
	NOTE: archived projects are never returned
2. Get the latest pipeline for each project.
3. Find the trivy job from the pipeline.
4. Download the job artifact (trivy result json).
5. Check if a .trivyignore file exists in the default branch.
6. Print the results

xamples:
  trivyops scan							- scan all user projects with at least developer permissions.
  trivyops scan 1234    				- get all trivy results from 1234
  trivyops scan 1234 --filter ^blub.*	- get all trivy results from 1234 where name starts with blub
  trivyops scan 1234 -o table			- output results as table (works well with less results)
  trivyops scan 1234 -v					- get more details`,
	Run: func(cmd *cobra.Command, args []string) {

		scan, err := initScanClient()
		eslog.LogIfError(err, eslog.Fatal)

		doScanWithOutput(scan)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	flag := scanCmd.Flags()

	flag.Bool(V, false, "Get details")
	flag.Bool(VV, false, "Get more details")
	flag.Bool(VVV, false, "Get even more details")
	flag.StringP(OUTPUT, "o", "text", "Define how to output results [text, table, json]")
	flag.String(OUTPUT_FILE, "", "Define a file to output the result json")
}

func doScanWithOutput(scan *internal.Scan) {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()

	var (
		projs []*gitlab.Project
		err   error
	)

	projs, err = scan.GitLabClient.GetProjects(scan.ID)

	if err != nil {
		eslog.Fatal(err)
	}
	trivyResults, err := scan.ScanProjects(projs)
	if err != nil {
		eslog.Fatalf("Failed to scan trivy results: %s!", err)
	}
	trivyResults.Check()
	s.Stop()
	fmt.Println()
	if strings.ToLower(viper.GetString(OUTPUT)) == "table" {
		output.Table(trivyResults, viper.GetBool(V), viper.GetBool(VV), viper.GetBool(VVV))
	} else if strings.ToLower(viper.GetString(OUTPUT)) == "json" {
		output.Json(trivyResults, viper.GetString(OUTPUT_FILE))
	} else {
		output.Text(trivyResults, viper.GetBool(V), viper.GetBool(VV), viper.GetBool(VVV))
	}
}
