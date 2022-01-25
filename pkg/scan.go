package pkg

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy/pkg/report"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/xanzy/go-gitlab"
)

func InitScanner(id, jobname, artifactFileName, filter string) scan {
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

	return scan{ID: id, JobName: jobname, ArtifactFileName: artifactFileName, Filter: filter}
}

type scan struct {
	ID               string
	JobName          string
	ArtifactFileName string
	Filter           string
}

func (s scan) ScanGroup() (TrivyResults, error) {
	var (
		projs []*gitlab.Project
		err   error
	)
	if s.ID == "" {
		projs, err = s.getAllUserProjects()
	} else {
		projs, err = s.getAllGroupProjects()
	}

	results := TrivyResults{}

	if err != nil {
		return nil, err
	}
	var re *regexp.Regexp
	if s.Filter != "" {
		re = regexp.MustCompile(s.Filter)
	}

	for _, proj := range projs {
		if s.Filter == "" || len(re.FindAllString(proj.NameWithNamespace, -1)) > 0 {
			logger.Infof("Scan project %s for trivy results\n", proj.NameWithNamespace)
			projResult := &trivy{ProjName: proj.Name}
			projResult.ReportResult, projResult.State, err = s.getTrivyResult(proj.ID, proj.DefaultBranch)
			if err != nil {
				logger.WithField("Project", proj.Name).Errorln(err)
			} else if projResult == nil {
				logger.WithField("Project", proj.Name).Infoln("No trivyresult found!")
			} else {
				logger.WithField("Project", proj.Name).Debugln("Result", projResult)
			}
			projResult.Ignore, err = s.getTrivyIgnore(proj.ID, proj.DefaultBranch)
			if err != nil {
				logger.WithField("Project", proj.Name).Errorln(err)
			} else if projResult.Ignore == nil {
				logger.WithField("Project", proj.Name).Infoln("No trivyignore file found!")
			} else {
				logger.WithField("Project", proj.Name).Debugln("Ignore", projResult.Ignore)
			}
			projResult.check()
			if projResult.Ignore != nil || (projResult.ReportResult != nil && projResult.Vulnerabilities.Count > 0) {
				results = append(results, projResult)
			}
		} else {
			logger.WithField("Project", proj.Name).Debugln("Filter out")
		}
	}
	return results, nil
}

func (s scan) getAllGroupProjects() ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	options := &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}

	for {
		projs, resp, err := git.Groups.ListGroupProjects(s.ID, options)
		if err != nil {
			return allProjs, err
		}

		allProjs = append(allProjs, projs...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		options.Page = resp.NextPage
	}
	return allProjs, nil
}

func (s scan) getAllUserProjects() ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	options := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:       gitlab.Bool(false),
		MinAccessLevel: gitlab.AccessLevel(gitlab.DeveloperPermissions),
	}

	for {
		projs, resp, err := git.Projects.ListProjects(options)
		if err != nil {
			return allProjs, err
		}

		allProjs = append(allProjs, projs...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		options.Page = resp.NextPage
	}
	return allProjs, nil
}

func (s scan) getTrivyResult(pid int, ref string) (report.Results, string, error) {
	jobs, _, err := git.Jobs.ListProjectJobs(pid, &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)})
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
			return nil, state, nil
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

func (s scan) unzipFromReader(rdr *bytes.Reader) ([]byte, error) {
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

func (s scan) getTrivyIgnore(pid int, ref string) ([]string, error) {
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
