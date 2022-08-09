# trivyops

This tool can be used to receive all trivy results from a GitLab group. As docker container it runs in daemon mode and provides a [Prometheus](https://prometheus.io/) metrics endpoint.

## Variables:
  - `GITLAB_TOKEN`  - the GitLab token to access the Gitlab instance
  - `GITLAB_HOST`   - the GitLab host which should be accessed [Default: https://gitlab.com]
  - `GITLAB_GROUP_ID`		  - the GitLab group ID to scan (only be used if not given per argument)
  - `LOG_LEVEL`     - the log level to use [Default: info]
  - `METRICS_PORT`  - the metrics endpoint when running in daemon mode [Default: 2112]
  - `METRICS_CRON`  - the cron string used to define how often metrics results are gathered from GitLab [Default: @every 6h]

## How to run

Just provide a GitLab Token with `read_api` scope and run the container: `podman run --env GITLAB_TOKEN=<your GitLab token> steffakasid/trivyops`