package main

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/internal"
)

func printResultTbl(results internal.TrivyResults) {

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
		summaryTable.AppendRow(table.Row{viper.GetString(internal.JOB_NAME), projResult.State, len(projResult.ReportResult), projResult.Vulnerabilities.Count})
		projectTbl.AppendRow(table.Row{"Summary", summaryTable.Render()})
		projectTbl.AppendSeparator()

		if viper.GetBool(V) || viper.GetBool(VV) || viper.GetBool(VVV) {
			printResultDetailsTbl(projectTbl, projResult.ReportResult)
		}
		tw.AppendRow(table.Row{projectTbl.Render()})
		tw.AppendSeparator()
	}

	fmt.Println(tw.Render())
}

func printResultDetailsTbl(projTbl table.Writer, res types.Results) {
	for _, tgt := range res {
		detailsLvl2 := table.NewWriter()
		detailsLvl2.SetStyle(table.StyleLight)
		if (viper.GetBool(VV) || viper.GetBool(VVV)) && len(tgt.Vulnerabilities) > 0 {
			detailsLvl2.SetColumnConfigs([]table.ColumnConfig{
				{Number: 1, WidthMax: 30},
				{Number: 2, WidthMax: 30},
				{Number: 3, WidthMax: 30},
				{Number: 4, WidthMax: 40},
				{Number: 5, WidthMax: 30},
				{Number: 6, WidthMin: 17, WidthMax: 17},
				{Number: 7, WidthMin: 15, WidthMax: 15},
			})
			headerRow := table.Row{"internal", "ID", "Severity", "Title", "IsFixable"}
			if viper.GetBool(VVV) {
				headerRow = append(headerRow, "InstalledVersion", "FixedVersion")
			}
			detailsLvl2.AppendHeader(headerRow)
			for _, internal := range tgt.Vulnerabilities {
				row := table.Row{internal.PkgName, internal.VulnerabilityID, internal.Severity, internal.Title, (internal.FixedVersion != "")}
				if viper.GetBool(VVV) {
					row = append(row, internal.InstalledVersion, internal.FixedVersion)
				}
				detailsLvl2.AppendRow(row)
			}
			projTbl.AppendRow(table.Row{tgt.Target, detailsLvl2.Render()})
		} else if len(tgt.Vulnerabilities) == 0 {
			projTbl.AppendRow(table.Row{tgt.Target, "No vulnerabilities found"})
		} else {
			detailsLvl2.AppendHeader(table.Row{"Critical", "High", "Medium", "Low", "Unkown"})
			crit, hi, med, lo, un := internal.GetSummary(tgt.Vulnerabilities)
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
