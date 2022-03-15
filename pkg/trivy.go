package pkg

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/xanzy/go-gitlab"
)

type trivy struct {
	ProjId          int
	ProjName        string
	State           string
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

type GitLabJobs interface {
	ListProjectJobs(pid interface{}, opts *gitlab.ListJobsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Job, *gitlab.Response, error)
	DownloadArtifactsFile(pid interface{}, refName string, opt *gitlab.DownloadArtifactsFileOptions, options ...gitlab.RequestOptionFunc) (*bytes.Reader, *gitlab.Response, error)
}

func (t *trivy) getTrivyJobState(jobName string, gitlabJobs GitLabJobs) error {
	jobs, _, err := gitlabJobs.ListProjectJobs(t.ProjId, &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)})
	if err != nil {
		return err
	}

	for _, job := range jobs {
		if jobName == job.Name {
			t.State = job.Status
			break
		}
	}
	return nil
}

func (t *trivy) getTrivyResult(branch, jobName, fileName string, gitlabJobs GitLabJobs) error {

	rdr, res, err := gitlabJobs.DownloadArtifactsFile(t.ProjId, branch, &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(jobName)})
	if err != nil {
		if res != nil && res.StatusCode == 404 {
			return nil
		} else {
			return err
		}
	}

	bt, err := unzipFromReader(rdr, fileName)
	if err != nil {
		return err
	}

	err = t.reportFromFile(bt)
	if err != nil {
		return err
	}

	return nil
}

func (t *trivy) reportFromFile(bt []byte) error {
	jsonReport := &types.Report{}
	err := json.Unmarshal(bt, jsonReport)
	if err != nil {
		jsonResult := &types.Results{}
		if err = json.Unmarshal(bt, jsonResult); err != nil {
			return err
		} else {
			t.ReportResult = *jsonResult
			return nil
		}
	}

	t.ReportResult = jsonReport.Results
	return nil
}

func (t *trivy) getTrivyIgnore(branch string, gitlabRepoFiles GitLabRepositoryFiles) error {
	bt, res, err := gitlabRepoFiles.GetRawFile(t.ProjId, ".trivyignore", &gitlab.GetRawFileOptions{Ref: gitlab.String(branch)})
	if err != nil {
		if res.StatusCode == 404 {
			return nil
		} else {
			return err
		}
	}
	var ignores []string
	for _, str := range strings.Split(string(bt), "\n") {
		if !strings.HasPrefix(str, "#") {
			ignores = append(ignores, str)
		}
	}
	t.Ignore = ignores
	return nil
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
