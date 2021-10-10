package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/steffakasid/trivy-scanner/pkg"
)

var (
	trivyJobName, trivyFileName, output, filter string
	help, v, vv, vvv, vers                      bool
)

const maxNameLen = 50
const maxTitleLen = 50

var version = "0.1-dev"

func init() {
	flag.StringVar(&trivyJobName, "job-name", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringVar(&trivyFileName, "artifact-name", "trivy-results.json", "The artifact filename of the trivy result")
	flag.StringVar(&filter, "filter", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	flag.StringVar(&output, "o", "text", "Define how to output results [text, table]")
	flag.BoolVar(&v, "v", false, "Get details")
	flag.BoolVar(&vv, "vv", false, "Get more details")
	flag.BoolVar(&vvv, "vvv", false, "Get even more details")
	flag.BoolVar(&help, "help", false, "Print help message")
	flag.BoolVar(&vers, "version", false, "Print version information")

	flag.Usage = func() {
		w := flag.CommandLine.Output() // may be os.Stderr - but not necessarily

		fmt.Fprintf(w, "Usage of %s: \n", os.Args[0])
		fmt.Fprintln(w, `
This tool can be used to receive all trivy results from a GitLab group. The tool
scans all subgroups and prints out a result a GitLab CI trivy scan job and checks
if there is a .trivyignore defined in the default branch.

Usage:
  trivyops [flags] GITLAB_GROUP_ID

Variables:
  - GITLAB_TOKEN		- the GitLab token to access the Gitlab instance
  - GITLAB_HOST		- the GitLab host which should be accessed [Default: https://gitlab.com]
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
}

func main() {
	if vers {
		fmt.Printf("Trivyops version: %s\n", version)
	} else if help {
		flag.Usage()
	} else {
		args := flag.Args()

		if len(args) > 1 {
			log.Printf("More then one argument provided: %s\n", args)
			flag.Usage()
			os.Exit(1)
		}

		s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
		s.Start()

		groupId := ""
		if len(args) > 0 {
			groupId = args[0]
		}

		scan := pkg.InitScanner(groupId, trivyJobName, trivyFileName, filter)

		trivyResults, err := scan.ScanGroup()
		if err != nil {
			log.Fatalf("Failed to scan trivy results: %s!", err)
		}
		trivyResults.Check()
		s.Stop()
		if strings.ToLower(output) == "table" {
			printResultTbl(trivyResults)
		} else {
			printResultTxt(trivyResults)
		}

	}
}

func printResultTxt(results pkg.TrivyResults) {
	maxProjNLen := maxProjNameLen(results)
	for i, projResult := range results {
		fmt.Printf("[%s]: %s | Job State: %s | Scanned Packages: %s | Vulnerabilities found: %s | .trivyignore: %t\n",
			padInt(i, 4, "0"),
			padString(projResult.ProjName, maxProjNLen),
			padString(projResult.State, 7),
			padInt(len(projResult.ReportResult), 3, " "),
			padInt(projResult.Vulnerabilities.Count, 3, " "),
			(len(projResult.Ignore) > 0))
		if v || vv || vvv {
			printResultDetailsTxt(projResult.ReportResult)
		}
	}
}

func printResultDetailsTxt(res report.Results) {
	maxTgtNLen := maxTgtNameLen(res)
	lvl1 := strings.Repeat(" ", 2)
	lvl2 := strings.Repeat(" ", 4)
	for _, tgt := range res {
		if v {
			crit, hi, med, lo, un := pkg.GetSummary(tgt.Vulnerabilities)
			fmt.Printf("%s%s| Critical %s | High %s | Medium %s | Low %s | Unkown %s\n",
				lvl1,
				padString(tgt.Target, maxTgtNLen),
				padInt(crit, 3, " "),
				padInt(hi, 3, " "),
				padInt(med, 3, " "),
				padInt(lo, 3, " "),
				padInt(un, 3, " "))
		} else {
			fmt.Printf("%s%s:\n", lvl1, tgt.Target)
			maxVuNLen := maxPckNameLen(tgt.Vulnerabilities)
			if len(tgt.Vulnerabilities) > 0 {
				// TODO: Add header here
				for _, vulli := range tgt.Vulnerabilities {
					fmt.Printf("%s%s | Severity: %s | Title: %s | IsFixable: %t",
						lvl2,
						padString(vulli.PkgName, maxVuNLen),
						vulli.Severity,
						cut(vulli.Title, maxTitleLen),
						(vulli.FixedVersion != ""))
					if vvv {
						fmt.Printf(" | InstalledVersion: %s | FixedVersion %s", vulli.InstalledVersion, vulli.FixedVersion)
					}
					fmt.Println()
				}
			} else {
				fmt.Printf("%s No vulnerabilities found!\n", lvl2)
			}
		}
	}
}

func printResultTbl(results pkg.TrivyResults) {

	tw := newLightTableWriter()
	tw.SetAutoIndex(true)
	tw.AppendHeader(table.Row{"Vulnerable Projects"})
	for _, projResult := range results {
		projectTbl := newLightTableWriter()
		projectTbl.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 30},
			{Number: 2, WidthMin: 20, WidthMax: 150},
		})
		projectTbl.AppendHeader(table.Row{projResult.ProjName, projResult.ProjName})
		projectTbl.AppendRow(table.Row{".trivyignore", projResult.Ignore})
		projectTbl.AppendSeparator()

		summaryTable := newLightTableWriter()
		summaryTable.AppendHeader(table.Row{"Job", "Status", "Scanned Packages", "Vulnerabilities"})
		summaryTable.AppendRow(table.Row{trivyJobName, projResult.State, len(projResult.ReportResult), projResult.Vulnerabilities.Count})
		projectTbl.AppendRow(table.Row{"Summary", summaryTable.Render()})
		projectTbl.AppendSeparator()

		if v || vv || vvv {
			printResultDetailsTbl(projectTbl, projResult.ReportResult)
		}
		tw.AppendRow(table.Row{projectTbl.Render()})
		tw.AppendSeparator()
	}

	fmt.Println(tw.Render())
}

func printResultDetailsTbl(projTbl table.Writer, res report.Results) {
	for _, tgt := range res {
		detailsLvl2 := table.NewWriter()
		detailsLvl2.SetStyle(table.StyleLight)
		if (vv || vvv) && len(tgt.Vulnerabilities) > 0 {
			detailsLvl2.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 30},
				{Number: 2, WidthMax: 30},
				{Number: 3, WidthMax: 30},
				{Number: 4, WidthMax: 40},
				{Number: 5, WidthMax: 30},
				{Number: 6, WidthMin: 17, WidthMax: 17},
				{Number: 7, WidthMin: 15, WidthMax: 15},
			})
			headerRow := table.Row{"Pkg", "ID", "Severity", "Title", "IsFixable"}
			if vvv {
				headerRow = append(headerRow, "InstalledVersion", "FixedVersion")
			}
			detailsLvl2.AppendHeader(headerRow)
			for _, pkg := range tgt.Vulnerabilities {
				row := table.Row{pkg.PkgName, pkg.VulnerabilityID, pkg.Severity, pkg.Title, (pkg.FixedVersion != "")}
				if vvv {
					row = append(row, pkg.InstalledVersion, pkg.FixedVersion)
				}
				detailsLvl2.AppendRow(row)
			}
			projTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
		} else if len(tgt.Vulnerabilities) == 0 {
			projTbl.AppendRow(table.Row{tgt.Target, "No vulnerabilities found"})
		} else {
			detailsLvl2.AppendHeader(table.Row{"Critical", "High", "Medium", "Low", "Unkown"})
			crit, hi, med, lo, un := pkg.GetSummary(tgt.Vulnerabilities)
			detailsLvl2.AppendRow(table.Row{crit, hi, med, lo, un})
			detailsLvl2.AppendFooter(table.Row{"", "", "", "Sum", crit + hi + med + lo + un})
			projTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
		}
		projTbl.AppendSeparator()
	}
}

func newLightTableWriter() table.Writer {
	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	return tw
}

func maxProjNameLen(projs pkg.TrivyResults) int {
	maxLen := 0
	for _, proj := range projs {
		projNLen := len(proj.ProjName)
		if projNLen > maxNameLen {
			return maxNameLen
		} else if projNLen > maxLen {
			maxLen = projNLen
		}
	}
	return maxLen
}

func maxTgtNameLen(results report.Results) int {
	maxLen := 0
	for _, res := range results {
		targetLen := len(res.Target)
		if targetLen > maxNameLen {
			return maxNameLen
		} else if targetLen > maxLen {
			maxLen = targetLen
		}
	}
	return maxLen
}

func maxPckNameLen(vullies []types.DetectedVulnerability) int {
	maxLen := 0
	for _, vul := range vullies {
		pkgNameLen := len(vul.PkgName)
		if pkgNameLen > maxNameLen {
			return maxNameLen
		} else if pkgNameLen > maxLen {
			maxLen = pkgNameLen
		}
	}
	return maxLen
}

func padString(name string, maxLen int) string {
	nameLen := len(name)
	if nameLen < maxLen {
		name += strings.Repeat(" ", maxLen-nameLen)
		return name
	} else if nameLen > maxLen {
		name = name[0:maxLen-3] + "..."
	}
	return name
}

func padInt(num int, length int, padStr string) string {
	numStr := strconv.Itoa(num)
	lenNum := len(numStr)
	if lenNum < length {
		return strings.Repeat(padStr, length-lenNum) + numStr
	}
	return numStr
}

func cut(t string, length int) string {
	if len(t) <= length {
		return t
	} else {
		return t[0:length-3] + "..."
	}
}
