package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	logger "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/pkg"
)

var version = "0.1-dev"

const (
	JOB_NAME    = "job-name"
	ARTIFACT    = "artifact-name"
	FILTER      = "filter"
	OUTPUT      = "output"
	OUTPUT_FILE = "output-file"
	DAEMON      = "daemon"
	V           = "v"
	VV          = "vv"
	VVV         = "vvv"
	HELP        = "help"
	VERSION     = "version"
)

func init() {
	flag.StringP(JOB_NAME, "j", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringP(ARTIFACT, "a", "trivy-results.json", "The artifact filename of the trivy result")
	flag.StringP(FILTER, "f", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	flag.StringP(OUTPUT, "o", "text", "Define how to output results [text, table, json]")
	flag.String(OUTPUT_FILE, "", "Define a file to output the result json")
	flag.BoolP(DAEMON, "d", false, "Set trivyops to deamon mode to be able to publish prometheus metrics")
	flag.Bool(V, false, "Get details")
	flag.Bool(VV, false, "Get more details")
	flag.Bool(VVV, false, "Get even more details")
	flag.Bool(HELP, false, "Print help message")
	flag.Bool(VERSION, false, "Print version information")

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
  - METRICS_PORT		- the metrics endpoint when running in daemon mode [Default: 2112]

Examples:
  trivyops 1234    				- get all trivy results from 1234
  trivyops 1234 --filter ^blub.*	- get all trivy results from 1234 where name starts with blub
  trivyops 1234 -o table			- output results as table (works well with less results)
  trivyops 1234 -v					- get more details

Flags:`)

		flag.PrintDefaults()
	}
	flag.Parse()

	err := viper.BindPFlags(flag.CommandLine)
	if err != nil {
		logger.Error(err)
	}

	pkg.InitConfig()
}

var scan pkg.Scan

func main() {
	lvl, err := logger.ParseLevel(viper.GetString(pkg.LOG_LEVEL))

	if err != nil {
		logger.Error(err)
		lvl = logger.InfoLevel
	}
	logger.SetLevel(lvl)

	if viper.GetBool(VERSION) {
		fmt.Printf("Trivyops version: %s\n", version)
	} else if viper.GetBool(HELP) {
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
		scan = pkg.InitScanner(groupId, viper.GetString(JOB_NAME), viper.GetString(ARTIFACT), viper.GetString(FILTER), viper.GetString(pkg.GTILAB_TOKEN), viper.GetString(pkg.GITLAB_HOST), viper.GetString(pkg.LOG_LEVEL))

		if viper.GetBool(DAEMON) {
			startDaemon()
		} else {
			doScanWithOutput()
		}
	}
}

func doScanWithOutput() {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.Start()

	trivyResults, err := scan.ScanGroup()
	if err != nil {
		logger.Fatalf("Failed to scan trivy results: %s!", err)
	}
	trivyResults.Check()
	s.Stop()
	fmt.Println()
	if strings.ToLower(viper.GetString(OUTPUT)) == "table" {
		printResultTbl(trivyResults)
	} else if strings.ToLower(viper.GetString(OUTPUT)) == "json" {
		printResultJson(trivyResults)
	} else {
		printResultTxt(trivyResults)
	}
}
