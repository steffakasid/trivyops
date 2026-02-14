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
	"flag"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/steffakasid/eslog"
	"github.com/steffakasid/trivy-scanner/internal"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	FILTER = "filter"
)

var cfgFile string

var version = "0.1-dev"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cmd",
	Short: "This tool can be used to receive all trivy results from GitLab projects.",
	Long: `This tool can be used to receive all trivy results from all GitLab projects of a GitLab group. To do so
the tool searches for defined GitLab-CI job which ran the trivytool and exposed the result as JSON in the jobs artifacts.
The tool scans all subgroups and prints out a result a GitLab CI trivy scan job downloads and parses the result json and checks
if there is a .trivyignore defined in the default branch. It can either be used as a cli tool
or run in server mode. When run as server it publishes the result as prometheus metrics.

Variables:
  - JOB_NAME  			- The gitlab ci jobname to check [Default "scan_oci_image_trivy"]
  - ARTIFACT		    - The artifact filename of the trivy result [Default: "trivy-results.json"]
  - GITLAB_TOKEN		- the GitLab token to access the Gitlab instance
  - GITLAB_HOST			- the GitLab host which should be accessed [Default: https://gitlab.com]
  - GITLAB_GROUP_ID		- the GitLab group ID to scan (only be used if not given per argument)
  - LOG_LEVEL			- the log level to use [Default: info]

Examples:
  trivyops scan 1234    			- get all trivy results from 1234
  trivyops server					- starts the server mode`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	Version: version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(internal.InitConfig, internal.SetLogLevel)

	persistentFlags := rootCmd.PersistentFlags()
	persistentFlags.StringP(FILTER, "f", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	persistentFlags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cmd.yaml)")
	err := viper.BindPFlags(persistentFlags)
	eslog.LogIfError(err, eslog.Fatal)
}

func validateArgsNEnv() ([]string, string, string) {
	args := flag.Args()

	if len(args) > 1 {
		log.Printf("More then one argument provided: %s\n", args)
		flag.Usage()
		os.Exit(1)
	}

	gitToken := viper.GetString("GITLAB_TOKEN")
	if gitToken == "" {
		eslog.Fatal("no GITLAB_TOKEN env var set!")
	}

	gitHost := viper.GetString("GITLAB_HOST")
	return args, gitToken, gitHost
}

func initScanClient() (*internal.Scan, error) {
	args, gitToken, gitHost := validateArgsNEnv()

	eslog.Debugf("Creating client for host %s", gitHost)
	git, err := gitlab.NewClient(gitToken, gitlab.WithBaseURL(gitHost))
	if err != nil {
		eslog.Fatalf("failed to create GitLab client: %v", err)
	}

	client := &internal.GitLabClient{
		GroupsClient:    git.Groups,
		ProjectsClient:  git.Projects,
		JobsClient:      git.Jobs,
		PipelinesClient: git.Pipelines,
		RepositoryFiles: git.RepositoryFiles,
	}

	groupId := ""
	if len(args) == 1 {
		groupId = args[0]
	} else {
		groupId = viper.GetString(internal.GITLAB_GROUP_ID)
	}
	return internal.InitScanner(groupId,
		viper.GetString(internal.JOB_NAME),
		viper.GetString(internal.ARTIFACT),
		viper.GetString(FILTER),
		client)
}
