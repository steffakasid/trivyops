package pkg

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/steffakasid/trivy-scanner/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func InitMock() GitLabClient {
	groupMock := &mocks.GitLabGroups{}
	jobMock := &mocks.GitLabJobs{}
	projectMock := &mocks.GitLabProjects{}
	repoFilesMock := &mocks.GitLabRepositoryFiles{}
	return GitLabClient{
		GroupsClient:    groupMock,
		JobsClient:      jobMock,
		ProjectsClient:  projectMock,
		RepositoryFiles: repoFilesMock,
	}
}

func TestGetTrivyJobState(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
		GitLabClient:     InitMock(),
	}
	projId := 1123

	listProjsOpts := &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)}
	scan.GitLabClient.JobsClient.(*mocks.GitLabJobs).EXPECT().ListProjectJobs(projId, listProjsOpts).Return([]*gitlab.Job{{ID: 1, Name: scan.JobName, Status: "success"}}, &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()

	state, err := scan.getTrivyJobState(scan.JobName, projId)
	assert.NoError(t, err)
	assert.Equal(t, "success", *state)
}

func TestGetTrivyResult(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
		GitLabClient:     InitMock(),
	}
	projId := 1123

	downloadOpts := &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(scan.JobName)}
	artifactsFile, err := os.ReadFile("../test/result.zip")
	assert.NoError(t, err)

	scan.GitLabClient.JobsClient.(*mocks.GitLabJobs).EXPECT().DownloadArtifactsFile(projId, "main", downloadOpts).Return(bytes.NewReader(artifactsFile), &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()

	results, err := scan.getTrivyResult("main", scan.JobName, scan.ArtifactFileName, projId)
	assert.NoError(t, err)
	assert.Len(t, results, 6)
}

func TestGetTrivyIgnore(t *testing.T) {
	branch := "main"
	opts := &gitlab.GetRawFileOptions{Ref: gitlab.String(branch)}

	t.Run("success", func(t *testing.T) {
		scan := Scan{
			GitLabClient: InitMock(),
		}
		projId := 1123

		bt, err := os.ReadFile("../test/.trivyignore")
		assert.NoError(t, err)

		scan.GitLabClient.RepositoryFiles.(*mocks.GitLabRepositoryFiles).EXPECT().GetRawFile(projId, ".trivyignore", opts).Return(bt, &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()

		trivyIgnore, err := scan.getTrivyIgnore(projId, branch)
		assert.NoError(t, err)
		assert.Len(t, trivyIgnore, 3)
	})

	t.Run("NoSuchFile", func(t *testing.T) {
		scan := Scan{
			GitLabClient: InitMock(),
		}
		projId := 1123

		scan.GitLabClient.RepositoryFiles.(*mocks.GitLabRepositoryFiles).EXPECT().GetRawFile(projId, ".trivyignore", opts).Return([]byte{}, &gitlab.Response{Response: &http.Response{StatusCode: 404}, TotalItems: 1, TotalPages: 1}, errors.New("No such file")).Once()
		trivyIgnore, err := scan.getTrivyIgnore(projId, branch)
		assert.Len(t, trivyIgnore, 0)
		assert.Nil(t, err)
	})
}
