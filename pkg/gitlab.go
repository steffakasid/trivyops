package pkg

import "github.com/xanzy/go-gitlab"

func getAllGroupProjects(groupId string) ([]*gitlab.Project, error) {
	allProjs := []*gitlab.Project{}
	options := &gitlab.ListGroupProjectsOptions{
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
			Page:    1,
		},
		Archived:         gitlab.Bool(false),
		IncludeSubgroups: gitlab.Bool(true),
	}

	for {
		projs, resp, err := git.Groups.ListGroupProjects(groupId, options)
		if err != nil {
			return allProjs, err
		}

		allProjs = append(allProjs, projs...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		options.Page = resp.NextPage
	}
	return allProjs, nil
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

	for {
		projs, resp, err := git.Projects.ListProjects(options)
		if err != nil {
			return allProjs, err
		}

		allProjs = append(allProjs, projs...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		options.Page = resp.NextPage
	}
	return allProjs, nil
}
