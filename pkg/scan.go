package pkg

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/report"
	logger "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
)

const NoNextPage = -1

func init() {
	gitToken := os.Getenv("GITLAB_TOKEN")
	if gitToken == "" {
		logger.Fatal("No GITLAB_TOKEN env var set!")
	}

	gitHost := os.Getenv("GITLAB_HOST")
	if gitHost == "" {
		gitHost = "https://gitlab.com"
	}

	logLvl := os.Getenv("LOG_LEVEL")
	if logLvl != "" {
		lvl, err := logger.ParseLevel(logLvl)

		if err != nil {
			logger.Error(err)
			lvl = logger.InfoLevel
		}
		logger.SetLevel(lvl)
	}

	var err error
	logger.Debugf("Creating client for host %s", gitHost)
	git, err = gitlab.NewClient(gitToken, gitlab.WithBaseURL(gitHost))
	if err != nil {
		logger.Fatalf("Failed to create client: %v", err)
	}
}

type Scan struct {
	ID               string
	JobName          string
	ArtifactFileName string
}

func (s Scan) ScanGroup() (TrivyResults, error) {
	if s.ID == "" {
		return nil, errors.New("no group id set")
	}

	results := TrivyResults{}
	projs, err := s.getAllGroupProjects(NoNextPage)
	if err != nil {
		return nil, err
	}

	for _, proj := range projs {
		logger.Infof("Scan project %s for trivy results\n", proj.NameWithNamespace)
		projResult := &trivy{ProjName: proj.Name}
		projResult.ReportResult, projResult.State, err = s.getTrivyResult(proj.ID, proj.DefaultBranch)
		if err != nil {
			logger.Warn(err)
		} else {
			logger.Debugln("Result", projResult)
		}
		projResult.Ignore, err = s.getTrivyIgnore(proj.ID, proj.DefaultBranch)
		if err != nil {
			logger.Warn(err)
		} else {
			logger.Debugln("Ignore", projResult.Ignore)
		}
		results = append(results, projResult)
	}
	return results, nil
}

func (s Scan) getAllGroupProjects(nextPage int) ([]*gitlab.Project, error) {
	var (
		projs []*gitlab.Project
		resp  *gitlab.Response
		err   error
	)
	options := &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}
	projs, resp, err = git.Groups.ListGroupProjects(s.ID, options)
	if err != nil {
		return projs, err
	}
	if resp != nil && resp.NextPage > 0 {
		projsR, err := s.getAllGroupProjects(resp.NextPage)
		if err != nil {
			return projs, err
		}
		projs = append(projs, projsR...)
	}
	return projs, nil
}

func (s Scan) getTrivyResult(pid int, ref string) (report.Results, string, error) {
	jobs, _, err := git.Jobs.ListProjectJobs(pid, &gitlab.ListJobsOptions{IncludeRetried: *gitlab.Bool(false)})
	if err != nil {
		return nil, "", err
	}

	var state string
	for _, job := range jobs {
		if job.Name == s.JobName {
			state = job.Status
			break
		}
	}

	rdr, res, err := git.Jobs.DownloadArtifactsFile(pid, ref, &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(s.JobName)})
	if err != nil {
		if res != nil && res.StatusCode == 404 {
			return nil, state, fmt.Errorf("no %s job result", s.JobName)
		} else {
			return nil, state, err
		}
	}

	bt, err := s.unzipFromReader(rdr)
	if err != nil {
		return nil, state, err
	}

	jsonResult := &report.Results{}
	err = json.Unmarshal(bt, jsonResult)
	if err != nil {
		return nil, state, err
	}

	return *jsonResult, state, err
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
			logger.Debug("read %d byte", len(bt))
			rc.Close()
			return bt, nil
		}
	}
	return nil, fmt.Errorf("didn't find %s in zip", s.ArtifactFileName)
}

func (s Scan) getTrivyIgnore(pid int, ref string) ([]string, error) {
	bt, res, err := git.RepositoryFiles.GetRawFile(pid, ".trivyignore", &gitlab.GetRawFileOptions{Ref: gitlab.String(ref)})
	if err != nil {
		if res.StatusCode == 404 {
			return nil, errors.New("no .trivyignore file found")
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
