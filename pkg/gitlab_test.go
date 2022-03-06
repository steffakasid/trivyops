package pkg

import (
	"testing"

	"github.com/steffakasid/trivy-scanner/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func TestGetAllGroupProjects(t *testing.T) {
	mockGitGroups := mocks.GitLabGroups{}
	var options *gitlab.ListGroupProjectsOptions = &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}
	projects := []*gitlab.Project{
		{
			ID: 1,
		},
		{
			ID: 2,
		},
	}
	response := &gitlab.Response{
		TotalPages: 2,
	}
	mockGitGroups.EXPECT().ListGroupProjects("unittest", options).Return(projects, response, nil).Once()
	var options2 *gitlab.ListGroupProjectsOptions = &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    2,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}
	projects2 := []*gitlab.Project{
		{
			ID: 3,
		},
		{
			ID: 4,
		},
	}
	response2 := &gitlab.Response{}
	mockGitGroups.EXPECT().ListGroupProjects("unittest", options2).Return(projects2, response2, nil).Once()

	projs, err := getAllGroupProjects("unittest", &mockGitGroups)
	assert.NoError(t, err)
	assert.ElementsMatch(t, projs, append(projects, projects2...))
}

func TestGetAllUserProjects(t *testing.T) {
	mockGitProjects := mocks.GitLabProjects{}
	options := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:       gitlab.Bool(false),
		MinAccessLevel: gitlab.AccessLevel(gitlab.DeveloperPermissions),
	}
	projects := []*gitlab.Project{
		{
			ID: 1,
		},
		{
			ID: 2,
		},
	}
	response := &gitlab.Response{
		TotalPages: 2,
	}
	mockGitProjects.EXPECT().ListProjects(options).Return(projects, response, nil).Once()
	options2 := &gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    2,
		},
		Archived:       gitlab.Bool(false),
		MinAccessLevel: gitlab.AccessLevel(gitlab.DeveloperPermissions),
	}
	projects2 := []*gitlab.Project{
		{
			ID: 3,
		},
		{
			ID: 4,
		},
	}
	response2 := &gitlab.Response{}
	mockGitProjects.EXPECT().ListProjects(options2).Return(projects2, response2, nil).Once()

	projs, err := getAllUserProjects(&mockGitProjects)
	assert.NoError(t, err)
	assert.ElementsMatch(t, projs, append(projects, projects2...))
}
