# trivy-project-svanner


This tool can be used to receive all trivy results from a GitLab group. The tool
scans all subgroups and prints out a result a GitLab CI trivy scan job and checks
if there is a .trivyignore defined in the default branch.

## Usage:
  `trivyops [flags] GITLAB_GROUP_ID`

## Variables:
  - `GITLAB_TOKEN`                - the GitLab token to access the Gitlab instance
  - `GITLAB_HOST`         - the GitLab host which should be accessed [Default: https://gitlab.com]
  - `LOG_LEVEL`                   - the log level to use [Default: info]

## Examples:
`trivyops 1234` - get all trivy results from 1234

`trivyops 1234 --filter ^blub.*` - get all trivy results from 1234 where name starts with blub

`trivyops 1234 -o table` - output results as table (works well with less results)

`trivyops 1234 -v` - get more details

## Flags:

`[-a]`, `[--artifact-name]` **string** The artifact filename of the trivy result (*default* "trivy-results.json")

`[-f]`, `[--filter]` **string** A golang regular expression to filter project name with namespace (e.g. (^.*/groupprefix.+$)|(^.*otherprefix.*))

`[--help]`                   Print help message

`[-j]`, `[--job-name]` **string** The gitlab ci jobname to check (*default* "scan_oci_image_trivy")

`-o`, `[--output]` **string** Define how to output results [text, table, json] (*default* "text")

`[--v]` Get details

`[--vv]` Get more details

`[--vvv]` Get even more details

`[--version]` Print version information

# Configuration

```yaml
---
GITLAB_TOKEN: a;lsdkfya9s8df879
GITLAB_HOST: https://gitlab.com
LOG_LEVEL: warn
FILTER: ^dbs-businesshub\/(!smartlocker)|(bizhub.+)$
```

`GITLAB_TOKEN` - the GitLab token to access the Gitlab instance

`GITLAB_HOST` - the GitLab host which should be accessed [Default: https://gitlab.com]

`LOG_LEVEL` - the log level to use [Default: info]

All other flags can also be set via config file
