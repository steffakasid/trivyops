package pkg

import (
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/xanzy/go-gitlab"
)

var git *gitlab.Client

type trivy struct {
	ProjName        string
	State           string
	Vulnerabilities vulnerabilities
	Ignore          []string
	ReportResult    report.Results
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
		vullies.Count += len(pkgResult.Vulnerabilities)
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

func (t TrivyResults) GetSummary(dv []types.DetectedVulnerability) (critical, high, medium, low, unkown int) {
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
