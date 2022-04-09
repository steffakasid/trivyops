package internal

import (
	"bytes"
	"errors"
	"math/rand"
	"net/http"
	"os"
	"testing"

	"github.com/steffakasid/trivy-scanner/internal/mocks"
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

func TestInitScanner(t *testing.T) {

}

func TestScanGroup(t *testing.T) {

}

func TestGetTrivyJobState(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
		GitLabClient:     InitMock(),
	}
	projId := 1123

	t.Run("success", func(t *testing.T) {
		mockListProjectJobs(t, projId, scan.JobName, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs))

		state, err := scan.getTrivyJobState(scan.JobName, projId)
		assert.NoError(t, err)
		assert.Equal(t, "success", *state)
	})

	t.Run("error", func(t *testing.T) {
		mockListProjectJobs(t, projId, scan.JobName, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs), 1)

		state, err := scan.getTrivyJobState(scan.JobName, projId)
		assert.Error(t, err)
		assert.EqualError(t, err, "Fail")
		assert.Nil(t, state)
	})

}

func TestGetTrivyResult(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
		GitLabClient:     InitMock(),
	}
	projId := 1123
	branch := "main"

	t.Run("success", func(t *testing.T) {
		mockDownloadArtifactsFile(t, projId, branch, scan.JobName, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs))

		results, err := scan.getTrivyResult("main", scan.JobName, scan.ArtifactFileName, projId)
		assert.NoError(t, err)
		assert.Len(t, results, 6)
	})

	t.Run("error", func(t *testing.T) {
		mockDownloadArtifactsFile(t, projId, branch, scan.JobName, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs), 1)

		results, err := scan.getTrivyResult("main", scan.JobName, scan.ArtifactFileName, projId)
		assert.Error(t, err)
		assert.EqualError(t, err, "Fail")
		assert.Nil(t, results)
	})

}

func TestGetTrivyIgnore(t *testing.T) {
	branch := "main"
	projId := 1123

	t.Run("success", func(t *testing.T) {
		scan := Scan{
			GitLabClient: InitMock(),
		}

		mockGetRawFile(t, projId, branch, 1, scan.GitLabClient.RepositoryFiles.(*mocks.GitLabRepositoryFiles))

		trivyIgnore, err := scan.getTrivyIgnore(projId, branch)
		assert.NoError(t, err)
		assert.Len(t, trivyIgnore, 3)
	})

	t.Run("NoSuchFile", func(t *testing.T) {
		scan := Scan{
			GitLabClient: InitMock(),
		}

		mockGetRawFile(t, projId, branch, 1, scan.GitLabClient.RepositoryFiles.(*mocks.GitLabRepositoryFiles), 1)
		trivyIgnore, err := scan.getTrivyIgnore(projId, branch)
		assert.Len(t, trivyIgnore, 0)
		assert.Error(t, err)
		assert.EqualError(t, err, "No such file")
	})
}

func mockListProjectJobs(t *testing.T, projId int, jobName string, numCalls int, mock *mocks.GitLabJobs, errCall ...int) {
	listProjsOpts := &gitlab.ListJobsOptions{
		IncludeRetried: gitlab.Bool(false),
	}

	resp := &gitlab.Response{
		TotalItems: 1,
		TotalPages: 1,
		Response: &http.Response{
			Status: "200",
		},
	}

	for i := 1; i <= numCalls; i++ {
		if isErrorCall(errCall, i) {
			resp.Response = &http.Response{
				Status: "500",
			}
			mock.EXPECT().ListProjectJobs(projId, listProjsOpts).Return(nil, resp, errors.New("Fail")).Once()
		} else {
			mock.EXPECT().ListProjectJobs(projId, listProjsOpts).Return([]*gitlab.Job{{ID: rand.Int(), Name: jobName, Status: "success"}}, resp, nil).Once()
		}
	}
}

func mockDownloadArtifactsFile(t *testing.T, projId int, branch string, jobName string, numCalls int, mock *mocks.GitLabJobs, errCall ...int) {
	downloadOpts := &gitlab.DownloadArtifactsFileOptions{
		Job: gitlab.String(jobName),
	}
	resp := &gitlab.Response{
		TotalItems: 1,
		TotalPages: 1,
		Response: &http.Response{
			Status: "200",
		},
	}
	artifactsFile, err := os.ReadFile("../test/result.zip")
	assert.NoError(t, err)
	for i := 1; i <= numCalls; i++ {
		if isErrorCall(errCall, i) {
			resp.Response = &http.Response{
				Status: "500",
			}
			mock.EXPECT().DownloadArtifactsFile(projId, branch, downloadOpts).Return(nil, resp, errors.New("Fail")).Once()
		} else {
			mock.EXPECT().DownloadArtifactsFile(projId, branch, downloadOpts).Return(bytes.NewReader(artifactsFile), resp, nil).Once()
		}
	}
}

func mockGetRawFile(t *testing.T, projId int, branch string, numCalls int, mock *mocks.GitLabRepositoryFiles, errCall ...int) {
	opts := &gitlab.GetRawFileOptions{
		Ref: gitlab.String(branch),
	}
	resp := &gitlab.Response{
		TotalItems: 1,
		TotalPages: 1,
		Response: &http.Response{
			Status: "200",
		},
	}
	bt, err := os.ReadFile("../test/.trivyignore")
	assert.NoError(t, err)
	for i := 1; i <= numCalls; i++ {
		if isErrorCall(errCall, i) {
			resp.Response = &http.Response{
				Status: "500",
			}
			mock.EXPECT().GetRawFile(projId, ".trivyignore", opts).Return([]byte{}, resp, errors.New("No such file")).Once()
		} else {
			mock.EXPECT().GetRawFile(projId, ".trivyignore", opts).Return(bt, resp, nil).Once()
		}
	}
}

func isErrorCall(errCalls []int, callNo int) bool {
	for _, errCall := range errCalls {
		if errCall == callNo {
			return true
		}
	}
	return false
}
