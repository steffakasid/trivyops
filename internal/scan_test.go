package internal

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"testing"

	"github.com/steffakasid/trivy-scanner/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func InitMock() *GitLabClient {
	groupMock := &mocks.GitLabGroups{}
	jobMock := &mocks.GitLabJobs{}
	projectMock := &mocks.GitLabProjects{}
	repoFilesMock := &mocks.GitLabRepositoryFiles{}
	pipeMock := &mocks.GitLabPipelines{}
	return &GitLabClient{
		GroupsClient:    groupMock,
		JobsClient:      jobMock,
		ProjectsClient:  projectMock,
		RepositoryFiles: repoFilesMock,
		PipelinesClient: pipeMock,
	}
}

func TestInitScanner(t *testing.T) {

	grpID := "123"
	jobName := "unittest_job"
	artifactFilename := "artifact_file"

	t.Run("success without filter", func(t *testing.T) {
		scan, err := InitScanner(grpID, jobName, artifactFilename, "", InitMock())
		assert.NoError(t, err)
		assert.NotNil(t, scan)
		assert.Equal(t, "123", scan.ID)
	})

	t.Run("success with filter", func(t *testing.T) {
		scan, err := InitScanner(grpID, jobName, artifactFilename, ".*th.*", InitMock())
		assert.NoError(t, err)
		assert.NotNil(t, scan)
		assert.Equal(t, "123", scan.ID)
		assert.True(t, scan.Filter.MatchString("something"))
	})

	t.Run("error with filter", func(t *testing.T) {
		scan, err := InitScanner(grpID, jobName, artifactFilename, "[", InitMock())
		assert.Error(t, err)
		assert.EqualError(t, err, "[ is not a valid regex: error parsing regexp: missing closing ]: `[`")
		assert.Nil(t, scan)
	})
}

func TestScanGroup(t *testing.T) {

	grpID := "123"
	jobName := "unittest_job"
	artifactFilename := "trivy-result.json"
	branch := "unittest"

	t.Run("success with filter", func(t *testing.T) {
		projs := generateProjects(50, branch)
		mockGit := InitMock()

		mockListProjectJobsForProject(t, projs, jobName, mockGit.JobsClient.(*mocks.GitLabJobs), 10, 15)
		mockDownloadArtifactsFileForProjects(t, projs, branch, jobName, mockGit.JobsClient.(*mocks.GitLabJobs), 25, 30)
		mockGetRawFileForProjects(t, projs, branch, mockGit.RepositoryFiles.(*mocks.GitLabRepositoryFiles), 44, 45, 46)
		scan, err := InitScanner(grpID, jobName, artifactFilename, ".*ro.*", mockGit)

		assert.NoError(t, err)
		result, err := scan.ScanProjects(projs)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 50)
		assertProjNoResult(t, result, 25)
		assertProjNoResult(t, result, 30)
		assertProjNoIgnore(t, result, 44)
		assertProjNoIgnore(t, result, 45)
		assertProjNoIgnore(t, result, 46)
	})

	t.Run("success without filter", func(t *testing.T) {
		projs := generateProjects(50, branch)
		mockGit := InitMock()
		mockListProjectJobsForProject(t, projs, jobName, mockGit.JobsClient.(*mocks.GitLabJobs), 10, 15)
		mockDownloadArtifactsFileForProjects(t, projs, branch, jobName, mockGit.JobsClient.(*mocks.GitLabJobs), 25, 30)
		mockGetRawFileForProjects(t, projs, branch, mockGit.RepositoryFiles.(*mocks.GitLabRepositoryFiles), 44, 45, 46)
		scan, err := InitScanner(grpID, jobName, artifactFilename, "", mockGit)

		assert.NoError(t, err)
		result, err := scan.ScanProjects(projs)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 50)
		assertProjNoResult(t, result, 25)
		assertProjNoResult(t, result, 30)
		assertProjNoIgnore(t, result, 44)
		assertProjNoIgnore(t, result, 45)
		assertProjNoIgnore(t, result, 46)
	})
}

func TestGetTrivyResult(t *testing.T) {
	scan := Scan{
		JobName:          "unittest-job",
		ArtifactFileName: "trivy-result.json",
		GitLabClient:     InitMock(),
	}
	projId := 1123

	t.Run("success", func(t *testing.T) {
		mockDownloadArtifactsFile(t, projId, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs))

		job := gitlab.Job{ID: 1, Project: &gitlab.Project{ID: 1}}
		results, err := scan.getTrivyResult(scan.ArtifactFileName, job)
		assert.NoError(t, err)
		assert.Len(t, results, 6)
	})

	t.Run("error", func(t *testing.T) {
		mockDownloadArtifactsFile(t, projId, 1, scan.GitLabClient.JobsClient.(*mocks.GitLabJobs), 1)

		job := gitlab.Job{ID: 1, Project: &gitlab.Project{ID: 1}}
		results, err := scan.getTrivyResult(scan.ArtifactFileName, job)
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

func assertProjNoResult(t *testing.T, result TrivyResults, id int) {
	for _, res := range result {
		if res.ProjId == id {
			assert.Len(t, res.ReportResult, 0)
		}
	}
}

func assertProjNoIgnore(t *testing.T, result TrivyResults, id int) {
	for _, res := range result {
		if res.ProjId == id {
			assert.Len(t, res.Ignore, 0)
		}
	}
}

func generateProjects(number int, branch string) []*gitlab.Project {
	projs := []*gitlab.Project{}

	for i := 0; i < number; i++ {
		projs = append(projs, &gitlab.Project{
			ID:                i,
			Name:              fmt.Sprintf("proj%d", i),
			NameWithNamespace: fmt.Sprintf("namespace/proj%d", i),
			DefaultBranch:     branch,
		})
	}
	return projs
}

func mockListProjectJobsForProject(t *testing.T, projs []*gitlab.Project, jobName string, mock *mocks.GitLabJobs, errProj ...int) {
	for _, proj := range projs {
		if isErrorCall(errProj, proj.ID) {
			mockListProjectJobs(t, proj.ID, jobName, 1, mock, 1)
		} else {
			mockListProjectJobs(t, proj.ID, jobName, 1, mock)
		}
	}
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

func mockDownloadArtifactsFileForProjects(t *testing.T, projs []*gitlab.Project, branch string, jobName string, mock *mocks.GitLabJobs, errProj ...int) {
	for _, proj := range projs {
		if isErrorCall(errProj, proj.ID) {
			mockDownloadArtifactsFile(t, proj.ID, 1, mock, 1)
		} else {
			mockDownloadArtifactsFile(t, proj.ID, 1, mock)
		}
	}
}

func mockDownloadArtifactsFile(t *testing.T, projId int, numCalls int, mock *mocks.GitLabJobs, errCall ...int) {

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
			mock.EXPECT().GetJobArtifacts(projId, 123).Return(nil, resp, errors.New("Fail")).Once()
		} else {
			mock.EXPECT().GetJobArtifacts(projId, 123).Return(bytes.NewReader(artifactsFile), resp, nil).Once()
		}
	}
}

func mockGetRawFileForProjects(t *testing.T, projs []*gitlab.Project, branch string, mock *mocks.GitLabRepositoryFiles, errProj ...int) {
	for _, proj := range projs {
		if isErrorCall(errProj, proj.ID) {
			mockGetRawFile(t, proj.ID, branch, 1, mock, 1)
		} else {
			mockGetRawFile(t, proj.ID, branch, 1, mock)
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
