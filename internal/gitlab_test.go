package internal

import (
	"testing"

	"github.com/steffakasid/trivy-scanner/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func TestGetAllGroupProjects(t *testing.T) {
	gitLabClient := InitMock()

	expectedProjs := mockListGroupProjects(gitLabClient.GroupsClient.(*mocks.GitLabGroups), 2, "unittest")

	projs, err := gitLabClient.GetAllGroupProjects("unittest")
	assert.NoError(t, err)
	assert.ElementsMatch(t, projs, expectedProjs)
	gitLabClient.GroupsClient.(*mocks.GitLabGroups).AssertExpectations(t)
}

func TestGetAllUserProjects(t *testing.T) {
	gitLabClient := InitMock()

	expectedProjs := mockListProjects(gitLabClient.ProjectsClient.(*mocks.GitLabProjects), 2)

	projs, err := gitLabClient.GetAllUserProjects()
	assert.NoError(t, err)
	assert.ElementsMatch(t, projs, expectedProjs)
}

func mockListGroupProjects(mock *mocks.GitLabGroups, numCalls int, grpId string) []*gitlab.Project {
	expectedProjs := []*gitlab.Project{}
	for i := 1; i <= numCalls; i++ {
		options := &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    i,
			},
			Archived:         gitlab.Bool(false),
			IncludeSubgroups: gitlab.Bool(true),
		}
		projects := []*gitlab.Project{
			{
				ID: 10 * i,
			},
			{
				ID: 10*i + 1,
			},
		}
		expectedProjs = append(expectedProjs, projects...)
		response := &gitlab.Response{
			TotalPages: numCalls,
		}
		mock.EXPECT().ListGroupProjects(grpId, options).Return(projects, response, nil).Once()
	}
	return expectedProjs
}

func mockListProjects(mock *mocks.GitLabProjects, numCalls int) []*gitlab.Project {
	expectedProjs := []*gitlab.Project{}
	for i := 1; i <= numCalls; i++ {
		options := &gitlab.ListProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    i,
			},
			Archived:       gitlab.Bool(false),
			MinAccessLevel: gitlab.AccessLevel(gitlab.DeveloperPermissions),
		}
		projects := []*gitlab.Project{
			{
				ID: 10 * i,
			},
			{
				ID: 10*i + 1,
			},
		}
		expectedProjs = append(expectedProjs, projects...)
		response := &gitlab.Response{
			TotalPages: numCalls,
		}
		mock.EXPECT().ListProjects(options).Return(projects, response, nil).Once()
	}
	return expectedProjs
}
