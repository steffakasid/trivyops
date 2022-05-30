package internal

import (
	"bytes"
	"sync"

	logger "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
)

type GitLabClient struct {
	GroupsClient    GitLabGroups
	ProjectsClient  GitLabProjects
	JobsClient      GitLabJobs
	RepositoryFiles GitLabRepositoryFiles
}

type GitLabGroups interface {
	ListGroupProjects(gid interface{}, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
}

type GitLabProjects interface {
	ListProjects(opt *gitlab.ListProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
}

type GitLabJobs interface {
	ListProjectJobs(pid interface{}, opts *gitlab.ListJobsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Job, *gitlab.Response, error)
	DownloadArtifactsFile(pid interface{}, refName string, opt *gitlab.DownloadArtifactsFileOptions, options ...gitlab.RequestOptionFunc) (*bytes.Reader, *gitlab.Response, error)
}

type GitLabRepositoryFiles interface {
	GetRawFile(pid interface{}, fileName string, opt *gitlab.GetRawFileOptions, options ...gitlab.RequestOptionFunc) ([]byte, *gitlab.Response, error)
}

type wrapper struct {
	projs []*gitlab.Project
	err   error
}

func (c GitLabClient) GetProjects(groupId string) ([]*gitlab.Project, error) {
	if groupId == "" {
		return c.GetAllUserProjects()
	} else {
		return c.GetAllGroupProjects(groupId)
	}
}

func (c GitLabClient) GetAllGroupProjects(groupId string) ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	var options *gitlab.ListGroupProjectsOptions = &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubGroups: gitlab.Bool(true),
	}
	var wg sync.WaitGroup

	projs, resp, err := c.GroupsClient.ListGroupProjects(groupId, options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 2; i <= resp.TotalPages; i++ {
		options.Page = i
		wg.Add(1)
		go c.listGroupProjectsWrapper(groupId, *options, projChannel, &wg)
	}
	wg.Wait()
	close(projChannel)

	for result := range projChannel {
		if result.err != nil {
			logger.Error(result.err)
		}

		allProjs = append(allProjs, result.projs...)
	}

	return allProjs, nil
}

func (c GitLabClient) listGroupProjectsWrapper(grpId string, options gitlab.ListGroupProjectsOptions, resultChannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := c.GroupsClient.ListGroupProjects(grpId, &options)
	resultChannel <- wrapper{projs, err}
	wg.Done()
}

func (c GitLabClient) GetAllUserProjects() ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	options := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:       gitlab.Bool(false),
		MinAccessLevel: gitlab.AccessLevel(gitlab.DeveloperPermissions),
	}
	var wg sync.WaitGroup

	projs, resp, err := c.ProjectsClient.ListProjects(options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 2; i <= resp.TotalPages; i++ {
		options.ListOptions.Page = i
		wg.Add(1)
		go c.listProjectsWrapper(*options, projChannel, &wg)
	}
	wg.Wait()
	close(projChannel)

	for result := range projChannel {
		if result.err != nil {
			logger.Error(err)
		}

		allProjs = append(allProjs, result.projs...)
	}

	return allProjs, nil
}

func (c GitLabClient) listProjectsWrapper(options gitlab.ListProjectsOptions, resultCHannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := c.ProjectsClient.ListProjects(&options)
	resultCHannel <- wrapper{projs, err}
	wg.Done()
}
