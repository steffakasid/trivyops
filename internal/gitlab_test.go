package internal

import (
	"testing"

	"github.com/steffakasid/trivy-scanner/internal/mocks"
	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
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

func mockListGroupProjects(mock *mocks.GitLabGroups, numCalls int64, grpId string) []*gitlab.Project {
	expectedProjs := []*gitlab.Project{}
	for i := int64(1); i <= numCalls; i++ {
		options := &gitlab.ListGroupProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    i,
			},
			Archived:         gitlab.Ptr(false),
			IncludeSubGroups: gitlab.Ptr(true),
		}
		projects := []*gitlab.Project{
			{
				ID: int64(10 * i),
			},
			{
				ID: int64(10*i + 1),
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

func mockListProjects(mock *mocks.GitLabProjects, numCalls int64) []*gitlab.Project {
	expectedProjs := []*gitlab.Project{}
	for i := int64(1); i <= numCalls; i++ {
		options := &gitlab.ListProjectsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    i,
			},
			Archived:       gitlab.Ptr(false),
			MinAccessLevel: gitlab.Ptr(gitlab.DeveloperPermissions),
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
