package pkg

import (
	"sync"

	logger "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
)

type GitLabGroups interface {
	ListGroupProjects(gid interface{}, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
}

type GitLabProjects interface {
	ListProjects(opt *gitlab.ListProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
}

type wrapper struct {
	projs []*gitlab.Project
	err   error
}

func getAllGroupProjects(groupId string, gitlabGroups GitLabGroups) ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	var options *gitlab.ListGroupProjectsOptions = &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}
	var wg sync.WaitGroup

	projs, resp, err := gitlabGroups.ListGroupProjects(groupId, options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 2; i <= resp.TotalPages; i++ {
		options.Page = i
		wg.Add(1)
		go listGroupProjectsWrapper(groupId, gitlabGroups, *options, projChannel, &wg)
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

func listGroupProjectsWrapper(grpId string, gitlabGroups GitLabGroups, options gitlab.ListGroupProjectsOptions, resultChannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := gitlabGroups.ListGroupProjects(grpId, &options)
	resultChannel <- wrapper{projs, err}
	wg.Done()
}

func getAllUserProjects(gitlabProjects GitLabProjects) ([]*gitlab.Project, error) {
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

	projs, resp, err := gitlabProjects.ListProjects(options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 2; i <= resp.TotalPages; i++ {
		options.ListOptions.Page = i
		wg.Add(1)
		go listProjectsWrapper(*options, gitlabProjects, projChannel, &wg)
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

func listProjectsWrapper(options gitlab.ListProjectsOptions, gitlabProjects GitLabProjects, resultCHannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := gitlabProjects.ListProjects(&options)
	resultCHannel <- wrapper{projs, err}
	wg.Done()
}
