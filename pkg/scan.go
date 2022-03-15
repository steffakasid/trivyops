package pkg

import (
	"regexp"
	"sync"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/xanzy/go-gitlab"
)

type GitLabRepositoryFiles interface {
	GetRawFile(pid interface{}, fileName string, opt *gitlab.GetRawFileOptions, options ...gitlab.RequestOptionFunc) ([]byte, *gitlab.Response, error)
}

func InitScanner(id, jobname, artifactFileName, filter, token, host, logLevel string) Scan {
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
	git, err := gitlab.NewClient(gitToken, gitlab.WithBaseURL(gitHost))
	if err != nil {
		logger.Fatalf("Failed to create client: %v", err)
	}

	return Scan{ID: id, GitLabClient: git, JobName: jobname, ArtifactFileName: artifactFileName, Filter: filter}
}

type Scan struct {
	ID               string
	GitLabClient     *gitlab.Client
	JobName          string
	ArtifactFileName string
	Filter           string
}

const (
	chunkSize = 10
)

func (s Scan) ScanGroup() (TrivyResults, error) {
	var (
		projs []*gitlab.Project
		err   error
	)
	if s.ID == "" {
		projs, err = getAllUserProjects(s.GitLabClient.Projects)
	} else {
		projs, err = getAllGroupProjects(s.ID, s.GitLabClient.Groups)
	}

	if err != nil {
		return nil, err
	}

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
	var re *regexp.Regexp
	if s.Filter != "" {
		re = regexp.MustCompile(s.Filter)
	}

	for _, proj := range projs {
		if s.Filter == "" || len(re.FindAllString(proj.NameWithNamespace, -1)) > 0 {
			logger.Infof("Scan project %s for trivy results\n", proj.NameWithNamespace)

			projResult := &trivy{
				ProjId:   proj.ID,
				ProjName: proj.Name,
			}
			err := projResult.getTrivyJobState(s.JobName, s.GitLabClient.Jobs)
			logIfError(proj.Name, err)

			err = projResult.getTrivyResult(proj.DefaultBranch, s.JobName, s.ArtifactFileName, s.GitLabClient.Jobs)
			logIfError(proj.Name, err)

			err = projResult.getTrivyIgnore(proj.DefaultBranch, s.GitLabClient.RepositoryFiles)
			logIfError(proj.Name, err)

			channel <- projResult
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

func logIfError(projectName string, err error) {
	if err != nil {
		logger.WithField("Project", projectName).Error(err)
	}
}
