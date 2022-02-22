package pkg

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/report"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/xanzy/go-gitlab"
)

func InitScanner(id, jobname, artifactFileName, filter string) Scan {
	gitToken := viper.GetString("GITLAB_TOKEN")
	if gitToken == "" {
		logger.Fatal("No GITLAB_TOKEN env var set!")
	}

	gitHost := viper.GetString("GITLAB_HOST")

	logLvl := viper.GetString("LOG_LEVEL")

	lvl, err := logger.ParseLevel(logLvl)

	if err != nil {
		logger.Error(err)
		lvl = logger.InfoLevel
	}
	logger.SetLevel(lvl)

	logger.Debugf("Creating client for host %s", gitHost)
	git, err = gitlab.NewClient(gitToken, gitlab.WithBaseURL(gitHost))
	if err != nil {
		logger.Fatalf("Failed to create client: %v", err)
	}

	return Scan{ID: id, JobName: jobname, ArtifactFileName: artifactFileName, Filter: filter}
}

type Scan struct {
	ID               string
	JobName          string
	ArtifactFileName string
	Filter           string
}

var wg sync.WaitGroup

const (
	chunkSize = 10
)

func (s Scan) ScanGroup() (TrivyResults, error) {
	var (
		projs []*gitlab.Project
		err   error
	)
	if s.ID == "" {
		projs, err = getAllUserProjects()
	} else {
		projs, err = getAllGroupProjects(s.ID)
	}

	if err != nil {
		return nil, err
	}

	projectResults := make(chan *trivy)
	for i := 0; i < len(projs); i += chunkSize {
		if (i + chunkSize) > len(projs) {
			go s.scanProjects(projs[i:len(projs)-1], projectResults)
		} else {
			go s.scanProjects(projs[i:i+chunkSize], projectResults)
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

func (s Scan) scanProjects(projs []*gitlab.Project, channel chan *trivy) {
	var re *regexp.Regexp
	if s.Filter != "" {
		re = regexp.MustCompile(s.Filter)
	}

	for _, proj := range projs {
		if s.Filter == "" || len(re.FindAllString(proj.NameWithNamespace, -1)) > 0 {
			var err error

			logger.Infof("Scan project %s for trivy results\n", proj.NameWithNamespace)
			projResult, err := s.getTrivyJobResult(proj.ID, proj.DefaultBranch)
			projResult.ProjId = proj.ID
			projResult.ProjName = proj.Name

			if err != nil {
				logger.WithField("Project", projResult.ProjName).Errorln(err)
			} else if projResult.ReportResult == nil {
				logger.WithField("Project", projResult.ProjName).Infoln("No trivyresult found!")
			} else {
				logger.WithField("Project", projResult.ProjName).Debugln("Result", projResult)
			}
			projResult.Ignore, err = s.getTrivyIgnore(proj.ID, proj.DefaultBranch)
			if err != nil {
				logger.WithField("Project", proj.Name).Errorln(err)
			} else if projResult.Ignore == nil {
				logger.WithField("Project", proj.Name).Infoln("No trivyignore file found!")
			} else {
				logger.WithField("Project", proj.Name).Debugln("Ignore", projResult.Ignore)
			}

			channel <- &projResult
		} else {
			logger.WithField("Project", proj.Name).Debugln("Filter out")
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

func (s Scan) getTrivyJobResult(pid int, ref string) (trivy, error) {
	projResult := trivy{}
	jobs, _, err := git.Jobs.ListProjectJobs(pid, &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)})
	if err != nil {
		return projResult, err
	}

	for _, job := range jobs {
		if job.Name == s.JobName {
			projResult.State = job.Status
			break
		}
	}

	rdr, res, err := git.Jobs.DownloadArtifactsFile(pid, ref, &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(s.JobName)})
	if err != nil {
		if res != nil && res.StatusCode == 404 {
			return projResult, nil
		} else {
			return projResult, err
		}
	}

	bt, err := s.unzipFromReader(rdr)
	if err != nil {
		return projResult, err
	}

	jsonReport := &report.Report{}
	err = json.Unmarshal(bt, jsonReport)
	if err != nil {
		jsonResult := &report.Results{}
		if err = json.Unmarshal(bt, jsonResult); err != nil {
			return projResult, err
		} else {
			projResult.ReportResult = *jsonResult
			return projResult, nil
		}
	}

	projResult.ReportResult = jsonReport.Results
	return projResult, err
}

func (s Scan) getTrivyIgnore(pid int, ref string) ([]string, error) {
	bt, res, err := git.RepositoryFiles.GetRawFile(pid, ".trivyignore", &gitlab.GetRawFileOptions{Ref: gitlab.String(ref)})
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

func (s Scan) unzipFromReader(rdr *bytes.Reader) ([]byte, error) {
	unzip, err := zip.NewReader(rdr, rdr.Size())
	if err != nil {
		logger.Error("Error unzip")
		return nil, err
	}

	for _, file := range unzip.File {
		if file.Name == s.ArtifactFileName {
			rc, err := file.Open()

			if err != nil {
				logger.Error("Error file open")
				return nil, err
			}

			bt, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, err
			}
			logger.Debugf("read %d byte", len(bt))
			rc.Close()
			return bt, nil
		}
	}
	return nil, fmt.Errorf("didn't find %s in zip", s.ArtifactFileName)
}
