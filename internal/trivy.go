package internal

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

type trivy struct {
	ProjId          int
	ProjName        string
	Vulnerabilities vulnerabilities
	Ignore          []string
	ReportResult    types.Results
}

type vulnerabilities struct {
	Count    int
	High     int
	Critical int
}

type TrivyResults []*trivy

func (t *TrivyResults) Check() {
	for _, result := range *t {
		result.check()
	}
}

func (r *trivy) check() {
	vullies := vulnerabilities{}
	for _, pkgResult := range r.ReportResult {
		vullies.Count += len(pkgResult.Misconfigurations)
		vullies.Count += len(pkgResult.Vulnerabilities)
		vullies.Count += len(pkgResult.Secrets)
		for _, v := range pkgResult.Vulnerabilities {
			if v.Severity == "CRITICAL" {
				vullies.Critical++
			} else if v.Severity == "HIGH" {
				vullies.High++
			}
		}
	}
	r.Vulnerabilities = vullies
}

func GetSummary(dv []types.DetectedVulnerability) (critical, high, medium, low, unkown int) {
	for _, v := range dv {
		if v.Severity == "CRITICAL" {
			critical++
		} else if v.Severity == "HIGH" {
			high++
		} else if v.Severity == "MEDIUM" {
			medium++
		} else if v.Severity == "LOW" {
			low++
		} else {
			unkown++
		}
	}
	return critical, high, medium, low, unkown
}
