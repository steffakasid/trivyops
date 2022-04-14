package internal

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/types"
	logger "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
)

const (
	chunkSize = 10
)

type Scan struct {
	ID               string
	GitLabClient     *GitLabClient
	JobName          string
	ArtifactFileName string
	Filter           *regexp.Regexp
}

func InitScanner(id, jobname, artifactFileName, filter string, gitLabClient *GitLabClient) (*Scan, error) {

	var reFilter *regexp.Regexp
	var err error
	if filter != "" {
		reFilter, err = regexp.Compile(filter)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid regex: %v", filter, err)
		}
	}

	return &Scan{ID: id, GitLabClient: gitLabClient, JobName: jobname, ArtifactFileName: artifactFileName, Filter: reFilter}, nil
}

func (s Scan) ScanProjects(projs []*gitlab.Project) (TrivyResults, error) {

	var wg sync.WaitGroup
	projectResults := make(chan *trivy)
	for i := 0; i < len(projs); i += chunkSize {
		if (i + chunkSize) > len(projs) {
			go s.scanProjects(projs[i:len(projs)-1], projectResults, &wg)
		} else {
			go s.scanProjects(projs[i:i+chunkSize], projectResults, &wg)
		}
		wg.Add(1)
	}
	resultsChannel := make(chan TrivyResults)
	go s.processResults(projectResults, resultsChannel)
	wg.Wait()
	close(projectResults)
	results := <-resultsChannel
	return results, nil
}

func (s Scan) scanProjects(projs []*gitlab.Project, channel chan *trivy, wg *sync.WaitGroup) {

	for _, proj := range projs {
		if s.Filter == nil || len(s.Filter.FindAllString(proj.NameWithNamespace, -1)) > 0 {
			logger.Infof("Scan project %s for trivy results\n", proj.NameWithNamespace)

			projResult := &trivy{
				ProjId:   proj.ID,
				ProjName: proj.Name,
			}
			jobState, err := s.getTrivyJobState(s.JobName, projResult.ProjId)
			logIfError(proj.Name, err)
			if jobState != nil {
				projResult.State = *jobState
			}

			results, err := s.getTrivyResult(proj.DefaultBranch, s.JobName, s.ArtifactFileName, projResult.ProjId)
			logIfError(proj.Name, err)
			if results != nil {
				projResult.ReportResult = results
			}

			trivyIgnore, err := s.getTrivyIgnore(projResult.ProjId, proj.DefaultBranch)
			logIfError(proj.Name, err)
			if trivyIgnore != nil {
				projResult.Ignore = trivyIgnore
			}

			channel <- projResult
		} else {
			logger.WithField("Project", proj.Name).Debugln("Filtered out")
		}
	}
	wg.Done()
}

func (s Scan) processResults(projResults chan *trivy, resultsChannel chan TrivyResults) {
	results := TrivyResults{}
	for scanResult := range projResults {
		scanResult.check()
		if scanResult.Ignore != nil || (scanResult.ReportResult != nil && scanResult.Vulnerabilities.Count > 0) {
			results = append(results, scanResult)
		}
	}
	resultsChannel <- results
	close(resultsChannel)
}

func (s Scan) getTrivyJobState(jobName string, projId int) (*string, error) {
	jobs, _, err := s.GitLabClient.JobsClient.ListProjectJobs(projId, &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)})
	if err != nil {
		return nil, err
	}

	for _, job := range jobs {
		if jobName == job.Name {
			return &job.Status, nil
		}
	}
	return nil, fmt.Errorf("job %s wasn't found in job list from project", jobName)
}

func (s Scan) getTrivyResult(branch, jobName, fileName string, projId int) (types.Results, error) {

	rdr, res, err := s.GitLabClient.JobsClient.DownloadArtifactsFile(projId, branch, &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(jobName)})
	if err != nil {
		if res != nil && res.StatusCode == 404 {
			return nil, nil
		} else {
			return nil, err
		}
	}

	bt, err := unzipFromReader(rdr, fileName)
	if err != nil {
		return nil, err
	}

	return s.reportFromFile(bt)
}

func (s Scan) reportFromFile(bt []byte) (types.Results, error) {
	jsonReport := &types.Report{}
	err := json.Unmarshal(bt, jsonReport)
	if err != nil {
		jsonResult := &types.Results{}
		if err = json.Unmarshal(bt, jsonResult); err != nil {
			return nil, err
		} else {
			return *jsonResult, nil
		}
	}

	return jsonReport.Results, nil
}

func (s Scan) getTrivyIgnore(projId int, branch string) ([]string, error) {

	bt, res, err := s.GitLabClient.RepositoryFiles.GetRawFile(projId, ".trivyignore", &gitlab.GetRawFileOptions{Ref: gitlab.String(branch)})
	if err != nil {
		if res.StatusCode == 404 {
			return nil, nil
		} else {
			return nil, err
		}
	}
	var ignores []string
	for _, str := range strings.Split(string(bt), "\n") {
		if !strings.HasPrefix(str, "#") {
			ignores = append(ignores, str)
		}
	}
	return ignores, nil
}

func logIfError(projectName string, err error) {
	if err != nil {
		logger.WithField("Project", projectName).Error(err)
	}
}
