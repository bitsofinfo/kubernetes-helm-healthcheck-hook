# kubernetes-helm-healthcheck-hook

This project provides a simple health checking script that can interrogate multiple
URI paths for a given target FQDN, evaluate the responses, optionally send one
or more alerts via Slack and then `exit` with an exit code of your choice if any
of the checks fail.

## Background

This project came to be out of a need to cause Helm chart installs & upgrades against
Kubernetes to fail and appropriately alert DevOps when the installed/upgraded Chart
yields a "non-healthy" result.

It can be easily adapted to existing Helm charts via a combination of a `ConfigMap` and
and `Job` annotated as a `helm.sh/hook` of type `post-install` or `post-upgrade` (or both)

You can also use it independently of Kubernetes / Helm as just a standalone utility.

# Requirements

**Python 3.6+**

Dependencies: See [Dockerfile](Dockerfile)

## How it works

The main script is `checker.py`, which requires you to specify a `--target-root-url`
plus at least one check defined in a *checks db YAML file* (example: [example/checksdb.yaml](example/checksdb.yaml)).
Each check definition `path` gets invoked against the target root url.

Optionally if you specify `--slack-config-filename`, each `alert` you define in the
slack YAML file, will be executed per `checker.py` run. Example: (example: [example/slackconfig.yaml](example/slackconfig.yaml))
Each alert you configure will be passed a Jinja2 context object that contains the full details of the `checker.py` invocation
that you can use to render about any message content you'd like. (To see a dump of what the context object looks like in STDOUT provide the `--debug-slack-jinja2-context` flag).

This can be run many ways such as:
* a direct Python script invocation on your local (i.e. `./checker.py -h`)
* via `docker run` using the [bitsofinfo/kubernetes-helm-healthcheck-hook](https://cloud.docker.com/repository/docker/bitsofinfo/kubernetes-helm-healthcheck-hook) image
* as a Kubernetes `Job` configured as Helm post upgrade/install hook
* ... or any other way you wish!

## Simple Example

The examples below use the sample config files located under [example](example/)

```
git clone https://github.com/bitsofinfo/kubernetes-helm-healthcheck-hook.git

cd kubernetes-helm-healthcheck-hook
```

Lets process all the *checks* defined in [example/checksdb.yaml](example/checksdb.yaml)
This will exit with a `1` because ONE of the checks fails (i.e. GET to `/status/500`),
it also sends 2 alerts as defined in the [example/checksdb.yaml](example/slackconfig.yaml)
https://bitsofinfo.slack.com/messages/CE46Z3TJA/ to the `#bitsofinfo-dev` channel
```
docker run -v `pwd`/example:/configs \
  bitsofinfo/kubernetes-helm-healthcheck-hook:0.1.0 checker.py \
  --target-root-url https://postman-echo.com \
  --any-check-fail-exit-code 1 \
  --checksdb-filename /configs/checksdb.yaml \
  --slack-config-filename /configs/slackconfig.yaml

echo "Exit code was: $?"
```

Now lets process all the *checks* defined in [example/checksdb.yaml](example/checksdb.yaml)
EXCEPT those tagged with `fail`. This will exit with a `0` because none of the evaluated checks
failed. It will also only send 1 alert (success only), because the 2nd alert configured in
[example/checksdb.yaml](example/slackconfig.yaml) only fires when a check in in failed state.
```
docker run -v `pwd`/example:/configs \
  bitsofinfo/kubernetes-helm-healthcheck-hook:0.1.0 checker.py \
  --target-root-url https://postman-echo.com \
  --any-check-fail-exit-code 1 \
  --checksdb-filename /configs/checksdb.yaml \
  --slack-config-filename /configs/slackconfig.yaml \
  --tags-disqualifier fail

echo "Exit code was: $?"
```

Lets process them all again with much more verbose debug output printed to STDOUT
to let you start customizing your slack alert config and or refine your checks.
```
docker run -v `pwd`/example:/configs \
  bitsofinfo/kubernetes-helm-healthcheck-hook:0.1.0 checker.py \
  --target-root-url https://postman-echo.com \
  --any-check-fail-exit-code 1 \
  --checksdb-filename /configs/checksdb.yaml \
  --slack-config-filename /configs/slackconfig.yaml \
  --verbose-output \
  --debug-slack-jinja2-context

echo "Exit code was: $?"
```

## Kubernetes Helm Hook Example

Lets say you deploy some custom app of your's with Helm and you'd like to follow
it up with an immediate check to validate its working or not and alert on that. Well
lets just use this project for that.

1. Modify your app's Helm chart to generate an appropriate `ConfigMap` and `Job`
properly annotated as a Helm `helm.sh/hook` of type `post-install` or `post-upgrade` (or both).

2. Now when you upgrade/install an app with your chart, your Helm status will properly
reflect success or failure based on the exit code of the `checker.py` job as well as
send you any alerts.

i.e. your chart could now generate something like this that interrogates anything you
wish that points to the app your chart just deployed (i.e. via an `Ingress` pointing
to the app your chart created.

```
...
generate your app's Deployment...
generate your app's Service...
generate your app's version specific Ingress...
...

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ my-app-name }}-healthcheck-config
  namespace: "{{ my-namespace }}"
data:
  healthchecks.config.yaml: |
    - path: "/health"
      method: "GET"
      timeout: 5
      retries: 3
  slackalerts.config.yaml: |
    - name: "Deployment Result"
      webhook_url: https://hooks.slack.com/services/xxxxxxxxx
      template: >
        {
          "text":"*Deployment result: {{ target_root_url }}* {{ overall_result }}"
        }

---
apiVersion: batch/v1
kind: Job
metadata:
  name: "{{ my-app-name }}--healthcheck"
  namespace: "{{ my-namespace }}"
  annotations:
    "helm.sh/hook": post-install,post-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation
spec:
  template:
    metadata:
      name: "{{ my-namespace }}-healthcheck"
    spec:
      backoffLimit: 10 # retry 10 times
      activeDeadlineSeconds: 600 # max run for 10 minutes (i.e. inclusive of retries)
      restartPolicy: Never
      volumes:
        - name: hc-config-volume
          configMap:
            name: {{ my-namespace }}-healthcheck-config
      containers:
        - name: {{ my-namespace }}-healthcheck
          image: "bitsofinfo/kubernetes-helm-healthcheck-hook:0.1.1"
          volumeMounts:
            - name: hc-config-volume
              mountPath: /etc/checker
          command:
            - "checker.py"
          args:
            - "--target-root-url"
            - "https://{{ my-app-ingress-fqdn }}"
            - "--max-retries"
            - "30"
            - "--sleep-seconds"
            - "10"
            - "--any-check-fail-exit-code"
            - "1"
            - "--checksdb-filename"
            - "/etc/checker/healthchecks.config.yaml"
            - "--slack-config-filename"
            - "/etc/checker/slackalerts.config.yaml"

```

## Usage

For config formats needed for `--checksdb-filename` and `--slack-config-filename`
see the `Configuration` section following `Usage`

```
$>./checker.py -h

usage: checker.py [-h] [-u TARGET_ROOT_URL] [-i CHECKSDB_FILENAME]
                  [-a SLACK_CONFIG_FILENAME] [-o OUTPUT_FILENAME]
                  [-f OUTPUT_FORMAT] [-v] [-q TAGS_QUALIFIER]
                  [-d TAGS_DISQUALIFIER] [-r MAX_RETRIES] [-n CHECK_NAME]
                  [-t THREADS] [-s SLEEP_SECONDS] [-l LOG_LEVEL] [-b LOG_FILE]
                  [-z] [-x ANY_CHECK_FAIL_EXIT_CODE] [-D]

optional arguments:
  -h, --help            show this help message and exit
  -u TARGET_ROOT_URL, --target-root-url TARGET_ROOT_URL
                        Required Target root URL (i.e. http[s]://whatever.com)
                        where all checks defined in --checksdb-filename will
                        execute against. Each check 'path' defined in
                        --checksdb-filename will be APPENDED to this value.
  -i CHECKSDB_FILENAME, --checksdb-filename CHECKSDB_FILENAME
                        Required: Filename (YAML) of checks database that will
                        be executed against the --target-root-url, default:
                        'checksdb.yaml'
  -a SLACK_CONFIG_FILENAME, --slack-config-filename SLACK_CONFIG_FILENAME
                        Optional: Filename (YAML) containing the slack alert
                        configuration. default: None
  -o OUTPUT_FILENAME, --output-filename OUTPUT_FILENAME
                        Optional: The result of the checks will be written to
                        this output filename, default: None
  -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Output format: json or yaml, default 'json'
  -v, --verbose-output  The result output will be in verbose mode, containing
                        much more detail helpful in debugging. Default OFF
  -q TAGS_QUALIFIER, --tags-qualifier TAGS_QUALIFIER
                        Optional, only include 'checks' loaded in --checksdb-
                        filename whos 'tags' attribute contains ONE or MORE
                        values this comma delimited list of tags
  -d TAGS_DISQUALIFIER, --tags-disqualifier TAGS_DISQUALIFIER
                        Inverse of --tags-qualifier. Exclude 'checks' loaded
                        in --checksdb-filename whos 'tags' attribute contains
                        ONE or MORE values this comma delimited list of tags
  -r MAX_RETRIES, --max-retries MAX_RETRIES
                        Maximum retries per check, overrides those provided in
                        --checksdb-filename, default 100
  -n CHECK_NAME, --check-name CHECK_NAME
                        Optional descriptive name for this invocation, default
                        'no --job-name specified'
  -t THREADS, --threads THREADS
                        max threads for processing checks listed in
                        --checksdb-filename, default 1, higher = faster
                        completion, adjust as necessary to avoid DOSing...
  -s SLEEP_SECONDS, --sleep-seconds SLEEP_SECONDS
                        The MAX amount of time to sleep between all attempts
                        for each service check; if > 0, the actual sleep will
                        be a RANDOM time from 0 to this value. Default 0
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        log level, default DEBUG
  -b LOG_FILE, --log-file LOG_FILE
                        Path to log file, default None, STDOUT
  -z, --stdout-result   Print check results to STDOUT in addition to --output-
                        filename on disk (if specified)
  -x ANY_CHECK_FAIL_EXIT_CODE, --any-check-fail-exit-code ANY_CHECK_FAIL_EXIT_CODE
                        If ANY single check defined in --checksdb-filename
                        fails or a general program error occurs, force a
                        sys.exit(your-provided-exit-code). If all checks are
                        successful the exit code will be 0. Default 1
  -D, --debug-slack-jinja2-context
                        Dumps a JSON debug output of the jinja2 object passed
                        to the Slack jinja2 template
```
