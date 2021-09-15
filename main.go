package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/steffakasid/trivy-scanner/pkg"
)

var (
	groupId          string
	trivyJobName     string
	trivyFileName    string
	output           string
	filter           string
	help, v, vv, vvv bool
)

const maxNameLen = 50

func init() {
	flag.StringVar(&groupId, "group-id", "", "Set group-id to scan for trivy results")
	flag.StringVar(&trivyJobName, "job-name", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringVar(&trivyFileName, "artifact-name", "trivy-results.json", "The artifact filename of the trivy result")
	flag.StringVar(&filter, "filter", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	flag.StringVar(&output, "o", "text", "Define how to output results [text, table]")
	flag.BoolVar(&v, "v", false, "Get details")
	flag.BoolVar(&vv, "vv", false, "Get more details")
	flag.BoolVar(&vvv, "vvv", false, "Get even more details")
	flag.BoolVar(&help, "help", false, "Print help message")

	flag.Usage = func() {
		w := flag.CommandLine.Output() // may be os.Stderr - but not necessarily

		fmt.Fprintf(w, "Usage of %s: \n", os.Args[0])
		fmt.Fprintln(w, `
This tool can be used to receive all trivy results from a GitLab group. The tool
scans all subgroups and prints out a result a GitLab CI trivy scan job and checks
if there is a .trivyignore defined in the default branch.

Variables:
  - GITLAB_TOKEN		- the GitLab token to access the Gitlab instance
  - GITLAB_HOST		- the GitLab host which should be accessed [Default: https://gitlab.com]
  - LOG_LEVEL			- the log level to use [Default: info]

Examples:
  trivyops --group-id 1234    				- get all trivy results from 1234
  trivyops --group-id 1234 --filter ^blub.*	- get all trivy results from 1234 where name starts with blub
  trivyops --group-id 1234 -o table			- output results as table (works well with less results)
  trivyops --group-id 1234 -v					- get more details

Flags:`)

		flag.PrintDefaults()
	}
	flag.Parse()
}

func main() {
	if help {
		flag.Usage()
	} else {
		scan := pkg.Scan{ID: groupId, JobName: trivyJobName, ArtifactFileName: trivyFileName}
		if filter != "" {
			scan.Filter = filter
		}
		trivyResults, err := scan.ScanGroup()
		if err != nil {
			log.Fatalf("Failed to scan trivy results: %s!", err)
		}
		trivyResults.Check()
		if strings.ToLower(output) == "table" {
			printResult(trivyResults)
		} else {
			printResultTxt(trivyResults)
		}
	}
}

func printResultTxt(results pkg.TrivyResults) {
	maxProjNLen := maxProjNameLen(results)
	for i, projResult := range results {
		if projResult.Vulnerabilities.Count > 0 || len(projResult.Ignore) > 0 {
			fmt.Printf("[%s]: %s | Job State: %s | Scanned Packages: %s | Vulnerabilities found: %s | .trivyignore: %t\n",
				padInt(i, 4, "0"),
				padName(projResult.ProjName, maxProjNLen),
				projResult.State,
				padInt(len(projResult.ReportResult), 3, " "),
				padInt(projResult.Vulnerabilities.Count, 3, " "),
				(len(projResult.Ignore) > 0))
			if v || vv || vvv {
				maxTgtNLen := maxTgtNameLen(projResult.ReportResult)
				for _, tgt := range projResult.ReportResult {
					if v {
						crit, hi, med, lo, un := results.GetSummary(tgt.Vulnerabilities)
						fmt.Printf("\t%s| Critical %s | High %s | Medium %s | Low %s | Unkown %s\n",
							padName(tgt.Target, maxTgtNLen),
							padInt(crit, 3, " "),
							padInt(hi, 3, " "),
							padInt(med, 3, " "),
							padInt(lo, 3, " "),
							padInt(un, 3, " "))
					} else {
						fmt.Printf("\t%s:\n", tgt.Target)
						maxVuNLen := maxPckNameLen(tgt.Vulnerabilities)
						if len(tgt.Vulnerabilities) > 0 {
							for _, vulli := range tgt.Vulnerabilities {
								fmt.Printf("\t\t%s | Severity: %s | Title: %s | IsFixable: %t",
									padName(vulli.PkgName, maxVuNLen),
									vulli.Severity,
									cut(vulli.Title, 150),
									(vulli.FixedVersion != ""))
								if vvv {
									fmt.Printf(" | InstalledVersion: %s | FixedVersion %s", vulli.InstalledVersion, vulli.FixedVersion)
								}
								fmt.Println()
							}
						} else {
							fmt.Println("\t\tNo vulnerabilities found!")
						}
					}
				}
			}
		}
	}
}

func printResult(results pkg.TrivyResults) {
	rowConfigAutoMerge := table.RowConfig{AutoMerge: true}
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Vulnerable Projects"}, rowConfigAutoMerge)
	for _, projResult := range results {
		if projResult.Vulnerabilities.Count > 0 || len(projResult.Ignore) > 0 {
			projectTbl := table.NewWriter()
			projectTbl.SetStyle(table.StyleLight)
			projectTbl.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 30},
				{Number: 2, WidthMin: 20, WidthMax: 150},
			})
			projectTbl.AppendHeader(table.Row{projResult.ProjName, projResult.ProjName}, rowConfigAutoMerge)
			projectTbl.AppendRow(table.Row{".trivyignore", projResult.Ignore}, rowConfigAutoMerge)
			projectTbl.AppendSeparator()

			summaryTable := table.NewWriter()
			summaryTable.SetStyle(table.StyleLight)
			summaryTable.AppendHeader(table.Row{"Job", "Status", "Scanned Packages", "Vulnerabilities"})
			summaryTable.AppendRow(table.Row{trivyJobName, projResult.State, len(projResult.ReportResult), projResult.Vulnerabilities.Count})
			projectTbl.AppendRow(table.Row{"Summary", summaryTable.Render()}, rowConfigAutoMerge)
			projectTbl.AppendSeparator()
			if v || vv || vvv {
				for _, tgt := range projResult.ReportResult {
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
						projectTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
					} else if len(tgt.Vulnerabilities) == 0 {
						projectTbl.AppendRow(table.Row{tgt.Target, "No vulnerabilities found"})
					} else {
						detailsLvl2.AppendHeader(table.Row{"Critical", "High", "Medium", "Low", "Unkown"})
						crit, hi, med, lo, un := results.GetSummary(tgt.Vulnerabilities)
						detailsLvl2.AppendRow(table.Row{crit, hi, med, lo, un})
						detailsLvl2.AppendFooter(table.Row{"", "", "", "Sum", crit + hi + med + lo + un})
						projectTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
					}
					projectTbl.AppendSeparator()
				}
			}
			tw.AppendRow(table.Row{projectTbl.Render()})
			tw.AppendSeparator()
		}
	}
	tw.SetAutoIndex(true)
	tw.SetStyle(table.StyleLight)
	fmt.Println(tw.Render())
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

func padName(name string, maxLen int) string {
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
