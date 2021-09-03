package pkg

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/xanzy/go-gitlab"
)

var git *gitlab.Client

const (
	trivyJob      = "trivy-scan"
	trivyArtifact = "trivy-result.json"
)

type trivy struct {
	ignore []byte
	result []byte
}

type trivyResults []trivy

func init() {
	gitToken := os.Getenv("GITLAB_TOKEN")
	if gitToken == "" {
		log.Fatal("No GITLAB_TOKEN env var set!")
	}

	var err error
	git, err = gitlab.NewClient(gitToken)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
}

func ScanGroup(id string) (trivyResults, error) {
	if id == "" {
		return nil, errors.New("no group id set")
	}

	results := trivyResults{}
	projs, _, err := git.Groups.ListGroupProjects(id, &gitlab.ListGroupProjectsOptions{Archived: gitlab.Bool(false), IncludeSubgroups: gitlab.Bool(true)})
	if err != nil {
		return nil, err
	}
	fmt.Println()
	for _, proj := range projs {
		fmt.Printf("Scan project %s for trivy results\n", proj.NameWithNamespace)
		projResult := trivy{}
		projResult.result, err = getTrivyResult(proj.ID, proj.DefaultBranch)
		if err != nil {
			log.Println(err)
		}
		projResult.ignore, err = getTrivyIgnore(proj.ID, proj.DefaultBranch)
		if err != nil {
			log.Println(err)
		}
		results = append(results, projResult)
		fmt.Println()
	}
	return results, nil
}

func getTrivyResult(pid int, ref string) ([]byte, error) {
	rdr, res, err := git.Jobs.DownloadArtifactsFile(pid, ref, &gitlab.DownloadArtifactsFileOptions{Job: gitlab.String(trivyJob)})
	if err != nil {
		if res.StatusCode == 404 {
			return nil, fmt.Errorf("intentionally ignored 404 not found when trying to get %s job results", trivyJob)
		} else {
			return nil, err
		}
	}
	unzip, err := zip.NewReader(rdr, rdr.Size())
	if err != nil {
		return nil, err
	}

	for _, file := range unzip.File {
		if file.Name == trivyArtifact {
			// TODO: read file
		}
	}

	return ioutil.ReadAll(rdr)
}

func getTrivyIgnore(pid int, ref string) ([]byte, error) {
	bt, res, err := git.RepositoryFiles.GetRawFile(pid, ".trivyignore", &gitlab.GetRawFileOptions{Ref: gitlab.String(ref)})
	if err != nil {
		if res.StatusCode == 404 {
			return nil, errors.New("intentionally ignored 404 not found when getting .trivyignore")
		} else {
			return nil, err
		}
	}
	return bt, nil
}
