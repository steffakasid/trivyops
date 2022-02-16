package pkg

import (
	"sync"

	logger "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
)

type wrapper struct {
	projs []*gitlab.Project
	err   error
}

func getAllGroupProjects(groupId string) ([]*gitlab.Project, error) {
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

	projs, resp, err := git.Groups.ListGroupProjects(groupId, options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 2; i <= resp.TotalPages; i++ {
		options.Page = i
		wg.Add(1)
		go listGroupProjectsWrapper(groupId, *options, projChannel, &wg)
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

func listGroupProjectsWrapper(grpId string, options gitlab.ListGroupProjectsOptions, resultChannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := git.Groups.ListGroupProjects(grpId, &options)
	resultChannel <- wrapper{projs, err}
	wg.Done()
}

func getAllUserProjects() ([]*gitlab.Project, error) {
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

	projs, resp, err := git.Projects.ListProjects(options)
	if err != nil {
		return nil, err
	}
	projChannel := make(chan wrapper, resp.TotalPages)
	allProjs = append(allProjs, projs...)

	for i := 1; i <= resp.TotalPages; i++ {
		options.ListOptions.Page = i
		wg.Add(1)
		go listProjectsWrapper(*options, projChannel, &wg)
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

func listProjectsWrapper(options gitlab.ListProjectsOptions, resultCHannel chan wrapper, wg *sync.WaitGroup) {
	projs, _, err := git.Projects.ListProjects(&options)
	resultCHannel <- wrapper{projs, err}
	wg.Done()
}
