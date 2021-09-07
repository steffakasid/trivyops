package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/steffakasid/trivy-scanner/pkg"
)

var (
	groupId          string
	trivyJobName     string
	trivyFileName    string
	help, v, vv, vvv bool
)

func main() {
	flag.StringVar(&groupId, "group-id", "", "Set group-id to scan for trivy results")
	flag.StringVar(&trivyJobName, "job-name", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringVar(&trivyFileName, "artifact-name", "trivy-results.json", "The artifact filename of the trivy result")
	flag.BoolVar(&v, "v", false, "Get details")
	flag.BoolVar(&vv, "vv", false, "Get more details")
	flag.BoolVar(&vvv, "vvv", false, "Get even more details")
	flag.BoolVar(&help, "help", false, "Print help message")
	flag.Parse()
	if help {
		flag.Usage()
	} else {
		scan := pkg.Scan{ID: groupId, JobName: trivyJobName, ArtifactFileName: trivyFileName}
		trivyResults, err := scan.ScanGroup()
		if err != nil {
			log.Fatalf("Failed to scan trivy results: %s!", err)
		}
		printResult(trivyResults)
	}
}

func printResult(results pkg.TrivyResults) {
	results.Check()
	rowConfigAutoMerge := table.RowConfig{AutoMerge: true}
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Vulnerable Projects"}, rowConfigAutoMerge)
	for _, projResult := range results {
		if projResult.Vulnerabilities > 0 {
			projectTbl := table.NewWriter()
			projectTbl.SetStyle(table.StyleLight)
			projectTbl.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 30},
				{Number: 2, WidthMin: 20},
			})
			projectTbl.AppendHeader(table.Row{projResult.ProjName, projResult.ProjName}, rowConfigAutoMerge)
			projectTbl.AppendRow(table.Row{".trivyignore", projResult.Ignore}, rowConfigAutoMerge)
			projectTbl.AppendSeparator()

			summaryTable := table.NewWriter()
			summaryTable.SetStyle(table.StyleLight)
			summaryTable.AppendHeader(table.Row{"Job", "Status", "Scanned Packages", "Vulnerabilities"})
			summaryTable.AppendRow(table.Row{trivyJobName, projResult.State, len(projResult.ReportResult), projResult.Vulnerabilities})
			projectTbl.AppendRow(table.Row{"Summary", summaryTable.Render()}, rowConfigAutoMerge)
			projectTbl.AppendSeparator()
			if v || vv || vvv {
				for _, tgt := range projResult.ReportResult {
					if (vv || vvv) && len(tgt.Vulnerabilities) > 0 {
						detailsLvl2 := table.NewWriter()
						detailsLvl2.SetStyle(table.StyleLight)
						detailsLvl2.SetColumnConfigs([]table.ColumnConfig{
							{Number: 1, WidthMax: 30},
							{Number: 2, WidthMax: 30},
							{Number: 3, WidthMax: 40},
							{Number: 4, WidthMax: 30},
							{Number: 5, WidthMin: 17, WidthMax: 17},
							{Number: 6, WidthMin: 15, WidthMax: 15},
						})
						headerRow := table.Row{"ID", "Severity", "Title", "IsFixable"}
						if vvv {
							headerRow = append(headerRow, "InstalledVersion", "FixedVersion")
							detailsLvl2.AppendHeader(headerRow)
						}
						for _, pkg := range tgt.Vulnerabilities {
							row := table.Row{pkg.VulnerabilityID, pkg.Severity, pkg.Title, (pkg.FixedVersion != "")}
							if vvv {
								row = append(row, pkg.InstalledVersion, pkg.FixedVersion)
							}
							detailsLvl2.AppendRow(row)
						}
						projectTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
					} else {
						projectTbl.AppendRow(table.Row{tgt.Target, fmt.Sprintf("Found %d vulnerabilities", len(tgt.Vulnerabilities))})
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
