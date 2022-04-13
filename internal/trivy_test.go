package internal

import (
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	trivyResults := &TrivyResults{
		&trivy{
			ProjId: 1,
			ReportResult: types.Results{
				types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							Vulnerability: dbtypes.Vulnerability{Severity: "CRITICAL"},
						},
						{
							Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"},
						},
					},
				},
			},
		},
		&trivy{
			ProjId: 2,
			ReportResult: types.Results{
				types.Result{
					Vulnerabilities: []types.DetectedVulnerability{
						{
							Vulnerability: dbtypes.Vulnerability{Severity: "LOW"},
						},
						{
							Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"},
						},
					},
				},
			},
		},
	}
	trivyResults.Check()
	assert.Equal(t, 2, (*trivyResults)[0].Vulnerabilities.Count)
	assert.Equal(t, 1, (*trivyResults)[0].Vulnerabilities.Critical)
	assert.Equal(t, 1, (*trivyResults)[0].Vulnerabilities.High)
	assert.Equal(t, 2, (*trivyResults)[1].Vulnerabilities.Count)
	assert.Equal(t, 0, (*trivyResults)[1].Vulnerabilities.Critical)
	assert.Equal(t, 1, (*trivyResults)[1].Vulnerabilities.High)
}

func TestSummary(t *testing.T) {
	vullies := []types.DetectedVulnerability{
		{
			Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"},
		},
		{
			Vulnerability: dbtypes.Vulnerability{Severity: "LOW"},
		},
		{
			Vulnerability: dbtypes.Vulnerability{Severity: "CRITICAL"},
		},
		{
			Vulnerability: dbtypes.Vulnerability{Severity: "OTHER"},
		},
		{
			Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"},
		},
	}
	crit, high, med, low, other := GetSummary(vullies)
	assert.Equal(t, 1, crit)
	assert.Equal(t, 2, high)
	assert.Equal(t, 0, med)
	assert.Equal(t, 1, low)
	assert.Equal(t, 1, other)
}
