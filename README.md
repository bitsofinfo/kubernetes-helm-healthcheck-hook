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

## Example

The examples below use the sample config files located under [example](example/)

```
git clone https://github.com/bitsofinfo/kubernetes-helm-healthcheck-hook.git

cd kubernetes-helm-healthcheck-hook
```


```
docker run -v `pwd`/example:/configs \
  bitsofinfo/kubernetes-helm-healthcheck-hook:0.1.0 checker.py \
  --target-root-url https://postman-echo.com \
  --any-check-fail-exit-code 1 \
  --checksdb-filename /configs/checksdb.yaml \
  --slack-config-filename /configs/slackconfig.yaml \
  --tags-disqualifier fail
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
