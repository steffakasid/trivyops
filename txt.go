package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/internal"
)

const (
	maxNameLen  = 50
	maxTitleLen = 50
)

func printResultTxt(results internal.TrivyResults) {
	maxProjNLen := maxProjNameLen(results)
	for i, projResult := range results {
		fmt.Printf("[%s]: %s | Job State: %s | Scanned Packages: %s | Vulnerabilities found: %s | .trivyignore: %t\n",
			padInt(i, 4, "0"),
			padString(projResult.ProjName, maxProjNLen),
			padString(projResult.State, 7),
			padInt(len(projResult.ReportResult), 3, " "),
			padInt(projResult.Vulnerabilities.Count, 3, " "),
			(len(projResult.Ignore) > 0))
		if viper.GetBool(V) || viper.GetBool(VV) || viper.GetBool(VVV) {
			printResultDetailsTxt(projResult.ReportResult)
		}
	}
}

func printResultDetailsTxt(res types.Results) {
	maxTgtNLen := maxTgtNameLen(res)
	lvl1 := strings.Repeat(" ", 2)
	lvl2 := strings.Repeat(" ", 4)
	for _, tgt := range res {
		if viper.GetBool(V) {
			crit, hi, med, lo, un := internal.GetSummary(tgt.Vulnerabilities)
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
					if viper.GetBool(VVV) {
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

func maxProjNameLen(projs internal.TrivyResults) int {
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

func maxTgtNameLen(results types.Results) int {
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
		internalNameLen := len(vul.PkgName)
		if internalNameLen > maxNameLen {
			return maxNameLen
		} else if internalNameLen > maxLen {
			maxLen = internalNameLen
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
