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

func TestGetTrivyJobState(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
	}
	result := trivy{
		ProjId: 1123,
	}

	mock := &mocks.GitLabJobs{}
	listProjsOpts := &gitlab.ListJobsOptions{IncludeRetried: gitlab.Bool(false)}
	mock.EXPECT().ListProjectJobs(result.ProjId, listProjsOpts).Return([]*gitlab.Job{{ID: 1, Name: scan.JobName, Status: "success"}}, &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()

	err := result.getTrivyJobState(scan.JobName, mock)
	assert.NoError(t, err)
	assert.Equal(t, "success", result.State)
}

func TestGetTrivyResult(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
	}
	result := trivy{
		ProjId: 1123,
	}

	mock := &mocks.GitLabJobs{}
	downloadOpts := &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(scan.JobName)}
	artifactsFile, err := os.ReadFile("../test/result.zip")
	assert.NoError(t, err)
	mock.EXPECT().DownloadArtifactsFile(result.ProjId, "main", downloadOpts).Return(bytes.NewReader(artifactsFile), &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()

	err = result.getTrivyResult("main", scan.JobName, scan.ArtifactFileName, mock)
	assert.NoError(t, err)
	assert.Len(t, result.ReportResult, 6)
}

func TestGetTrivyIgnore(t *testing.T) {
	branch := "main"
	opts := &gitlab.GetRawFileOptions{Ref: gitlab.String(branch)}

	t.Run("success", func(t *testing.T) {
		result := trivy{
			ProjId: 1234,
		}

		mock := &mocks.GitLabRepositoryFiles{}
		bt, err := os.ReadFile("../test/.trivyignore")
		assert.NoError(t, err)
		mock.EXPECT().GetRawFile(result.ProjId, ".trivyignore", opts).Return(bt, &gitlab.Response{TotalItems: 1, TotalPages: 1}, nil).Once()
		err = result.getTrivyIgnore(branch, mock)
		assert.NoError(t, err)
		assert.Len(t, result.Ignore, 3)
	})

	t.Run("NoSuchFile", func(t *testing.T) {
		result := trivy{
			ProjId: 1234,
		}

		mock := &mocks.GitLabRepositoryFiles{}
		mock.EXPECT().GetRawFile(result.ProjId, ".trivyignore", opts).Return([]byte{}, &gitlab.Response{Response: &http.Response{StatusCode: 404}, TotalItems: 1, TotalPages: 1}, errors.New("No such file")).Once()
		err := result.getTrivyIgnore(branch, mock)
		assert.Len(t, result.Ignore, 0)
		assert.Nil(t, err)
	})
}
