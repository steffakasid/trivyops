package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

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

func main() {
	flag.StringVar(&groupId, "group-id", "", "Set group-id to scan for trivy results")
	flag.StringVar(&trivyJobName, "job-name", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringVar(&trivyFileName, "artifact-name", "trivy-results.json", "The artifact filename of the trivy result")
	flag.StringVar(&filter, "filter", "", "A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))")
	flag.StringVar(&output, "o", "text", "Define how to output results [text, table]")
	flag.BoolVar(&v, "v", false, "Get details")
	flag.BoolVar(&vv, "vv", false, "Get more details")
	flag.BoolVar(&vvv, "vvv", false, "Get even more details")
	flag.BoolVar(&help, "help", false, "Print help message")
	flag.Parse()
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
	for i, projResult := range results {
		if projResult.Vulnerabilities.Count > 0 || len(projResult.Ignore) > 0 {
			fmt.Printf("%d: %s Job State %s Scanned Packages: %d Vulnerabilities found: %d .trivyignore: %s\n", i, projResult.ProjName, projResult.State, len(projResult.ReportResult), projResult.Vulnerabilities.Count, projResult.Ignore)
			if v || vv || vvv {
				for _, tgt := range projResult.ReportResult {
					if v {
						crit, hi, med, lo, un := results.GetSummary(tgt.Vulnerabilities)
						fmt.Printf("\t%s - Critical %d High %d Medium %d Low %d Unkown %d\n", tgt.Target, crit, hi, med, lo, un)
					} else {
						fmt.Printf("\t%s:\n", tgt.Target)
						for j, vulli := range tgt.Vulnerabilities {
							fmt.Printf("\t\t%d - %s Severity: %s Title: %s IsFixable: %T", j, vulli.PkgName, vulli.Severity, vulli.Title, (vulli.FixedVersion != ""))
							if vvv {
								fmt.Printf("InstalledVersion: %s FixedVersion %s", vulli.InstalledVersion, vulli.FixedVersion)
							}
							fmt.Println()
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
