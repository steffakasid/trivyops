package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/pkg"
)

var version = "0.1-dev"

func init() {
	flag.StringP("job-name", "j", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringP("artifact-name", "a", "trivy-results.json", "The artifact filename of the trivy result")
	flag.StringP("filter", "f", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	flag.StringP("output", "o", "text", "Define how to output results [text, table, json]")
	flag.BoolP("daemon", "d", false, "Set trivyops to deamon mode to be able to publish prometheus metrics")
	flag.Bool("v", false, "Get details")
	flag.Bool("vv", false, "Get more details")
	flag.Bool("vvv", false, "Get even more details")
	flag.Bool("help", false, "Print help message")
	flag.Bool("version", false, "Print version information")

	flag.Usage = func() {
		w := os.Stderr

		fmt.Fprintf(w, "Usage of %s: \n", os.Args[0])
		fmt.Fprintln(w, `
This tool can be used to receive all trivy results from a GitLab group. The tool
scans all subgroups and prints out a result a GitLab CI trivy scan job and checks
if there is a .trivyignore defined in the default branch.

Usage:
  trivyops [flags] GITLAB_GROUP_ID

Variables:
  - GITLAB_TOKEN		- the GitLab token to access the Gitlab instance
  - GITLAB_HOST			- the GitLab host which should be accessed [Default: https://gitlab.com]
  - LOG_LEVEL			- the log level to use [Default: info]

Examples:
  trivyops 1234    				- get all trivy results from 1234
  trivyops 1234 --filter ^blub.*	- get all trivy results from 1234 where name starts with blub
  trivyops 1234 -o table			- output results as table (works well with less results)
  trivyops 1234 -v					- get more details

Flags:`)

		flag.PrintDefaults()
	}
	flag.Parse()

	viper.BindPFlags(flag.CommandLine)

	viper.BindEnv("GITLAB_TOKEN")
	viper.SetDefault("GITLAB_HOST", "https://gitlab.com")
	viper.SetDefault("LOG_LEVEL", "info")

	viper.SetConfigName(".trivyops")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	viper.AddConfigPath("$HOME/")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err)
	}
}

var scan pkg.Scan

func main() {
	if viper.GetBool("version") {
		fmt.Printf("Trivyops version: %s\n", version)
	} else if viper.GetBool("help") {
		flag.Usage()
	} else {
		args := flag.Args()

		if len(args) > 1 {
			log.Printf("More then one argument provided: %s\n", args)
			flag.Usage()
			os.Exit(1)
		}

		groupId := ""
		if len(args) > 0 {
			groupId = args[0]
		}
		scan = pkg.InitScanner(groupId, viper.GetString("job-name"), viper.GetString("artifact-name"), viper.GetString("filter"))

		if viper.GetBool("daemon") {
			doScanWithOutput()
		} else {
			startDaemon()
		}
	}
}

func doScanWithOutput() {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()

	trivyResults, err := scan.ScanGroup()
	if err != nil {
		log.Fatalf("Failed to scan trivy results: %s!", err)
	}
	trivyResults.Check()
	s.Stop()
	fmt.Println()
	if strings.ToLower(viper.GetString("output")) == "table" {
		printResultTbl(trivyResults)
	} else if strings.ToLower(viper.GetString("output")) == "json" {
		printResultJson(trivyResults)
	} else {
		printResultTxt(trivyResults)
	}
}
