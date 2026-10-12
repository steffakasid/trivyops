package internal

import (
	"testing"

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
							Severity: "CRITICAL",
						},
						{
							Severity: "HIGH",
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
							Severity: "LOW",
						},
						{
							Severity: "HIGH",
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
			Severity: "HIGH",
		},
		{
			Severity: "LOW",
		},
		{
			Severity: "CRITICAL",
		},
		{
			Severity: "OTHER",
		},
		{
			Severity: "HIGH",
		},
	}
	crit, high, med, low, other := GetSummary(vullies)
	assert.Equal(t, 1, crit)
	assert.Equal(t, 2, high)
	assert.Equal(t, 0, med)
	assert.Equal(t, 1, low)
	assert.Equal(t, 1, other)
}
