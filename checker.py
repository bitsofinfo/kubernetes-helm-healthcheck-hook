#!/usr/bin/env python

__author__ = "bitsofinfo"

import urllib.request
import urllib.error
from urllib.parse import urlparse
import ssl
import datetime
import logging
import socket
import base64
import time
import random
import copy
import json
import requests
import pprint
import argparse
import sys
import yaml
from multiprocessing import Pool
from jinja2 import Template, Environment

# De-deuplicates a list of objects, where the value is the same
def dedup(list_of_objects):
    to_return = []
    seen = set()
    for obj in list_of_objects:
        asjson = json.dumps(obj, sort_keys=True)
        if asjson not in seen:
            to_return.append(obj)
            seen.add(asjson)
    return to_return;

# for max max_retries
max_retries = None

sslcontext = ssl.create_default_context()
sslcontext.check_hostname = False
sslcontext.verify_mode = ssl.CERT_NONE

def listContainsTokenIn(token_list,at_least_one_must_exist_in):
    found = False
    for token in token_list:
        if token in at_least_one_must_exist_in:
            found = True
    return found

def readHTTPResponse(response):
    response_data = {'as_string':None,'as_object':None}
    try:
        response_str = response.read().decode('utf-8')
        response_data['as_string'] = response_str
        try:
            response_obj = json.loads(response_str)
            response_data['as_object'] = response_obj
        except:
            response_data['as_string'] = response_str
    except Exception as e:
        response_data['as_string'] = "body read failed: " + str(sys.exc_info())
        logging.exception("readHTTPResponse() Exception parsing body")

    return response_data

def calcHealthRating(total_fail,total_ok):
    if (total_ok == 0):
        return 0

    return 100-((total_fail/(total_fail+total_ok))*100)

def calcRetryPercentage(total_attempts,total_fail,total_ok):
    if (total_ok == 0 and total_fail == 0):
        return 0

    total = (total_fail+total_ok)
    diff = abs(total_attempts-total)

    return ((diff/total)*100)

def calcFailPercentage(total_fail,total_ok):
    if (total_ok == 0 and total_fail == 0):
        return 0

    total = (total_fail+total_ok)
    return ((total_fail/total)*100)

def processResponse(check_def,
                    ms,
                    response,
                    attempts_failed,
                    distinct_failure_codes,
                    distinct_failure_errors,
                    attempt_count,
                    dns_lookup_result):

    # hc/service_check (health check for short)
    hc = check_def

    # attempt to parse the response
    response_data = readHTTPResponse(response)

    # what is "success"?!
    success_status_codes = [200]
    success_body_evaluator = None
    if 'is_healthy' in hc and 'response_codes' in 'is_healthy':
        success_status_codes = hc['is_healthy']['response_codes']
        if 'body_evaluator' in hc['is_healthy']:
            success_body_evaluator = hc['is_healthy']['body_evaluator']

    # what is failure? (optional, but takes precedence)
    failure_status_codes = None
    if 'is_not_healthy' in hc:
        failure_status_codes = hc['is_not_healthy']['response_codes']

    # lets actually check if the response is legit...
    response_is_healthy = False
    response_unhealthy_reason = None

    # is_not_healthy takes precedence over any is_healthy which is ignored
    if failure_status_codes is not None:
        if response.getcode() not in failure_status_codes:
            response_is_healthy = True
        else:
            response_unhealthy_reason = "response status code:" + str(response.getcode()) + ", is in 'failure_status_codes'"

    elif response.getcode() in success_status_codes:

        # handle evaluator..
        if success_body_evaluator is not None:

            if success_body_evaluator['type'] == "contains":
                if success_body_evaluator["value"] in response_data['as_string']:
                    response_is_healthy = True
                else:
                    response_unhealthy_reason = "body_evaluator[contains] failed, did not find: '"+success_body_evaluator["value"]+"' in resp. body"

            elif success_body_evaluator['type'] == "jinja2":
                t = Template(success_body_evaluator["template"])
                x = t.render(check_def=check_def,response_data=response_data,response_code=response.getcode())
                if '1' in x:
                    response_is_healthy = True
                else:
                    response_unhealthy_reason = "body_evaluator[jinja2] failed, template returned 0 (expected 1)"

        else:
            response_is_healthy = True

    # status code invalid
    else:
        response_unhealthy_reason = "response status code:" + str(response.getcode()) + ", is not in 'success_status_codes'"

    # formulate our result object
    if response_is_healthy:
        hc['result'] = { "success":True,
                         "code":response.getcode(),
                         "ms":ms,
                         "attempts":attempt_count,
                         "response": response_data,
                         "headers": response.getheaders(),
                         "dns":dns_lookup_result,
                         "attempts_failed":attempts_failed}
        return

    # failed...
    else:
        # create base result object
        hc['result'] = { "success":False,
                         "attempts": attempt_count}

        # attributes specific to the attempt
        attempt_entry = { "ms":ms,
                          "response": response_data,
                          "headers": response.getheaders(),
                          "dns":dns_lookup_result,
                          "error":response_unhealthy_reason,
                          "code":response.getcode()}

        # record in attempts_failed
        attempts_failed.append(attempt_entry)
        distinct_failure_codes.append(response.getcode())
        distinct_failure_codes = dedup(distinct_failure_codes)
        distinct_failure_errors.append(response_unhealthy_reason)
        distinct_failure_errors = dedup(distinct_failure_errors)

        # merge the attempt_entry props into result object
        # as we always store the most recent one at the top level
        hc['result'].update(attempt_entry)

        # add the current list of attempt errors to result object
        hc['result']['attempts_failed'] = attempts_failed
        hc['result']['distinct_failure_codes'] = distinct_failure_codes
        hc['result']['distinct_failure_errors'] = distinct_failure_errors


def isResultErrorActuallySuccess(hc):
    if 'is_healthy' in hc and hc['result']['error'] and 'error_msg_reasons' in hc['is_healthy']:
        for error_reason in hc['is_healthy']['error_msg_reasons']:
            if error_reason.lower() in hc['result']['error'].lower():
                logging.debug("isErrorMessageActuallySuccess() HTTP request failed w/ error: '" + hc['result']['error'] + \
                    "' However error message is in 'is_healthy.error_msg_reasons' so result actually successful")
                return True
    return False

def execServiceCheck(config):

    max_retries = config['max_retries']

    hc = config['check_def']
    sleep_seconds = int(config['sleep_seconds'])

    hc['result'] = { "success":False }

    hc['url'] = config['target_root_url'] + hc['path']

    # build request
    response = None
    try:
        retries = hc['retries']
        if max_retries is not None:
            if retries is not None and int(max_retries) < retries:
                retries = int(max_retries)

        headers = {}
        curl_header = ""

        # seed to blank if not already there
        if not 'headers' in hc or hc['headers'] is None:
            hc['headers'] = []

        # handle specific host header
        host_header_val_4log = "none"
        if 'host_header' in hc and hc['host_header'] is not None and hc['host_header'] != '':
            headers = {'Host':hc['host_header']}
            host_header_val_4log = hc['host_header']
            curl_header = "--header 'Host: "+hc['host_header']+"' "

        # handle basic auth
        if 'basic_auth' in hc:
            baheader = "Authorization: Basic: "+ base64.urlsafe_b64encode(hc['basic_auth'].strip().encode("UTF-8")).decode('ascii')
            hc['headers'].append(baheader)

        # handle other headers
        for header in hc['headers']:
            parts = header.split(":")
            key = parts[0].strip()
            val = ''.join(parts[1:]).strip()
            headers[key] = val
            curl_header += "--header '"+key+": "+val+"' "

        # body?
        body_bytes = None
        body_text = None
        curl_data = ""
        if 'body' in hc:
            body_text = hc['body']
            body_bytes = body_text.encode("UTF-8")
            curl_body = body_text.replace("'","\\'")
            curl_data = "-d '"+curl_body+"' "


        logging.debug("Checking: " + hc['method'] + " > "+ hc['url'] + " hh:" + host_header_val_4log)

        request = urllib.request.Request(hc['url'],headers=headers,method=hc['method'],data=body_bytes)

        curl_cmd = "curl -v --retry "+str(retries)+" -k -m " + str(hc['timeout']) + " -X "+hc['method']+" " + curl_header + curl_data +  hc['url']
        hc['curl'] = curl_cmd

    except Exception as e:
        logging.exception("execServiceCheck() exception:")
        hc['result'] = { "success":False,
                         "ms":0,
                         "attempts":0,
                         "error": str(sys.exc_info()[:2])}
        return config

    # ok now do the attempts based on configured retries
    attempt_count = 0
    attempts_failed = []
    distinct_failure_codes = []
    distinct_failure_errors = []
    dns_lookup_result = None
    while (attempt_count < retries):

        try:
            attempt_count += 1
            hc['result'] = { "success":False }

            if attempt_count > 1:
                logging.debug("retrying: " + hc['url'])

            # log what it resolves to...
            dns_lookup_result = None
            try:
                parsed = urlparse(hc['url'])
                lookup = parsed.netloc.split(":")[0]
                dns_lookup_result = socket.gethostbyname(lookup)
            except Exception as e:
                dns_lookup_result = str(sys.exc_info()[:2])


            # do the request
            try:
                start = datetime.datetime.now()
                response = urllib.request.urlopen(request,timeout=hc['timeout'],context=sslcontext)

            except urllib.error.HTTPError as httperror:
                response = httperror

            ms = round((datetime.datetime.now() - start).total_seconds() * 1000,0)

            # process the response
            processResponse(hc,ms,response,
                            attempts_failed,
                            distinct_failure_codes,
                            distinct_failure_errors,
                            attempt_count,
                            dns_lookup_result)



            # if response NOT successful, lets check if an error
            # message if its in list of 'is_healthy.error_msg_reasons'
            # will will invert the result
            if not hc['result']['success'] and isResultErrorActuallySuccess(hc):
                hc['result']['success'] = True


            # if it was successful, exit loop
            if hc['result']['success']:
                break


        except Exception as e:
            ms = (datetime.datetime.now() - start).total_seconds() * 1000

            hc['result'] = { "success":False,
                             "attempts":attempt_count }

            # attributes specific to the attempt
            attempt_entry = { "ms":ms,
                              "dns":dns_lookup_result,
                              "error":str(sys.exc_info()[:2])}

            distinct_failure_errors.append(attempt_entry['error'])
            distinct_failure_errors = dedup(distinct_failure_errors)

            # record in attempts_failed
            attempts_failed.append(attempt_entry)

            # merge the attempt_entry props into result object
            # as we always store the most recent one at the top level
            hc['result'].update(attempt_entry)

            # add the current list of attempt errors to result object
            hc['result']['attempts_failed'] = attempts_failed
            hc['result']['distinct_failure_codes'] = distinct_failure_codes
            hc['result']['distinct_failure_errors'] = distinct_failure_errors

            # finally... lets invert the result if necessary...
            if isResultErrorActuallySuccess(hc):
                hc['result']['success'] = True
                break


        # finally, sleep after every attempt IF configured to do so...
        finally:
            if sleep_seconds > 0:
                tmp_sleep = random.randint(0,sleep_seconds)
                time.sleep(int(tmp_sleep))

    return config


# Does the bulk of the work
def execute(target_root_url, \
            checksdb_filename, \
            output_filename, \
            output_format,\
            maximum_retries, \
            check_name, \
            threads, \
            stdout_result, \
            sleep_seconds, \
            any_check_fail_exit_code, \
            verbose_output, \
            slack_config_filename, \
            tags_qualifier, \
            tags_disqualifier, \
            debug_slack_jinja2_context, \
            extra_slack_context_props, \
            all_args):

    # if any checks failed
    has_check_failures = False

    # thread pool to exec tasks
    exec_pool = None

    try:
        # seed max retries override
        max_retries = int(maximum_retries)

        # mthreaded...
        if (isinstance(threads,str)):
            threads = int(threads)

        # init pool
        exec_pool = Pool(threads)

        # instantiate the client
        logging.debug("Reading checks db from: " + checksdb_filename)

        # open layer check database
        checks_db = []
        with open(checksdb_filename) as f:
            if '.yaml' in checksdb_filename:
                checks_db = yaml.load(f, Loader=yaml.FullLoader)
            elif 'json' in checksdb_filename:
                checks_db = json.load(f)


        executable_service_checks = [] # note this is array of dicts
        finalized_checks_db = []

        if len(checks_db) == 0:
            logging.info(checksdb_filename + " contains ZERO checks to perform!")

        # process it all
        for checkdef in checks_db:

            # for future filtering possibilities
            hc_executable = True
            no_match_reason = None

            # check tags qualifiers
            if tags_qualifier is not None and len(tags_qualifier) > 0 and 'tags' not in checkdef:
                hc_executable = False
                no_match_reason = "'tags_qualifier' present but check has no 'tags' attribute"
            if tags_qualifier is not None and len(tags_qualifier) > 0 and 'tags' in checkdef:
                for tag_qualifier in tags_qualifier:
                    if tag_qualifier not in checkdef['tags']:
                        hc_executable = False
                        no_match_reason = "No 'tags' matched provided 'tags_qualifier'"

            # check tags disqualifiers
            if tags_disqualifier is not None and len(tags_disqualifier) > 0 and 'tags' in checkdef:
                for tag_disqualifier in tags_disqualifier:
                    if tag_disqualifier     in checkdef['tags']:
                        hc_executable = False
                        no_match_reason = "One or more 'tags' matched provided 'tag_disqualifier'"

            if hc_executable:
                executable_service_checks.append({'target_root_url':target_root_url, \
                                                  'check_def':checkdef, \
                                                  'max_retries':max_retries, \
                                                  'sleep_seconds':sleep_seconds})
            else:
                checkdef['result'] = { "success":True, \
                                      "ms":0, \
                                      "attempts":0, \
                                      "skipped":True, \
                                      "msg":"does not match " + str(no_match_reason)}

                # only include skipped on verbose
                if verbose_output:
                    finalized_checks_db.append(checkdef)

        # ok here we dump all the service check records
        # to be executed concurrently in the pool
        # which returns a copy...
        executable_service_checks = exec_pool.map(execServiceCheck, \
                                                  executable_service_checks)


        for config in executable_service_checks:
            check_def = config['check_def']

            finalized_checks_db.append(check_def)
            if not check_def['result']['success']:
                has_check_failures = True

        finalized_checks_db_for_output = copy.deepcopy(finalized_checks_db)

        # simplify output if not in verbose mode
        for check_def in finalized_checks_db_for_output:
            if not verbose_output:
                check_def.pop("curl",None)
                check_def.pop("classifiers",None)
                check_def.pop("path",None)
                check_def.pop("tags",None)
                check_def.pop("body",None)
                check_def.pop("headers",None)
                check_def.pop("ports",None)
                check_def.pop("is_healthy",None)
                check_def.pop("is_not_healthy",None)
                check_def.pop("retries",None)
                check_def.pop("timeout",None)
                cd_result = check_def['result']
                cd_result.pop("headers",None)
                cd_result.pop("response",None)
                cd_result.pop("attempts_failed",None)
                cd_result.pop("code",None)
                cd_result.pop("ms",None)
                cd_result.pop("attempts",None)
                cd_result.pop("dns",None)
                cd_result.pop("distinct_failure_codes",None)
                cd_result.pop("distinct_failure_errors",None)


        # to json
        if output_filename is not None:
            with open(output_filename, 'w') as outfile:
                if output_format == 'json':
                    json.dump(finalized_checks_db_for_output, outfile, indent=4)
                else:
                    yaml.dump(finalized_checks_db_for_output, outfile, default_flow_style=False)

                logging.debug("Output written to: " + output_filename)


        # also to stdout?
        if stdout_result:
            print()
            if output_format == 'json':
                print(json.dumps(finalized_checks_db_for_output,indent=4))
            else:
                print(yaml.dump(finalized_checks_db_for_output, default_flow_style=False))
            print()


        #-------------------------------------
        # Slack Alert
        #-------------------------------------

        # Create an Jinja2 Environment
        # and register a new filter for the exec_objectpath methods
        env = Environment()

        # Create out standard header text and attachment
        slack_alert_configs = {}

        try:
            with open(slack_config_filename) as f:
                slack_alert_configs = yaml.load(f, Loader=yaml.FullLoader)

            for slack_alert_config in slack_alert_configs:
                try:
                    # parse extra_slack_context_props if provided (k=v,k2=v2,...)
                    extra_props = None
                    if extra_slack_context_props and extra_slack_context_props != "":
                        extra_props = dict(x.split("=") for x in extra_slack_context_props.split(","))

                    slack_jinja2_context = {
                        'check_name':check_name,
                        'overall_result': (True if not has_check_failures else False),
                        'target_root_url':target_root_url,
                        'checks':finalized_checks_db,
                        'checker_args':vars(all_args),
                        'slack_alert_config':slack_alert_config,
                        'extra_props':extra_props
                    }

                    if debug_slack_jinja2_context:
                        logging.debug("debug_slack_jinja2_context=True, the JSON that follows is the jinj2_context object that is available to your Jinja2 templates in your --slack-config-filename")
                        print(json.dumps(slack_jinja2_context,indent=2))

                    # alert condition?
                    can_send_alert = True
                    if 'alert_condition' in slack_alert_config and slack_alert_config['alert_condition']:
                        t = Template(slack_alert_config["alert_condition"])
                        x = t.render(slack_jinja2_context)
                        if '1' in x:
                            can_send_alert = True
                        else:
                            can_send_alert = False

                    if not can_send_alert:
                        logging.info("Skipping sending alert '%s', alert_condition returned 0 (zero)",slack_alert_config['name'])
                        continue

                    # ok we can proceed, render the template
                    slack_template = env.from_string(slack_alert_config['template'])
                    rendered_template = slack_template.render(slack_jinja2_context)

                    # Convert to an object we can now append trigger results to
                    slack_data = json.loads(rendered_template)

                    logging.debug("Sending Slack alert [%s]",slack_alert_config['name'])
                    response = requests.post(
                        slack_alert_config['webhook_url'], data=json.dumps(slack_data),
                        headers={'Content-Type': 'application/json'}
                    )
                    if response.status_code != 200:
                        raise ValueError(
                            'Request to slack returned an error %s, the response is:\n%s'
                            % (response.status_code, response.text)
                        )
                # end per slack alert config loop
                except Exception as e:
                    logging.exception("Error in slack alert processing of slack_alert_config: " + slack_alert_config['name'])

        # end main slack alerting block
        except Exception as e:
            logging.exception("Error in slack alert processing")

    # end main method try block
    except Exception as e:
        logging.exception("Error in checker.execute()")
        has_check_failures = True # force a failure if we have a program failure

    # always cleanup!
    finally:
        try:
            if exec_pool is not None:
                exec_pool.close()
                exec_pool.terminate()
                exec_pool = None
                logging.debug("Pool closed and terminated")
        except:
            logging.exception("Error terminating, closing pool")

        # any failures? exit according to code
        if has_check_failures and any_check_fail_exit_code:
            logging.error("Execution complete. has_check_failures=True, one or more checks FAILED, exiting with exit code: %s", any_check_fail_exit_code)
            sys.exit(any_check_fail_exit_code)
        else:
            logging.info("Execution complete. has_check_failures=%s",has_check_failures)

###########################
# Main program
##########################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--target-root-url', dest='target_root_url', \
        help="Required Target root URL (i.e. http[s]://whatever.com) where all checks defined in --checksdb-filename will execute against. Each check 'path' defined in --checksdb-filename will be APPENDED to this value.")
    parser.add_argument('-i', '--checksdb-filename', dest='checksdb_filename', \
        help="Required: Filename (YAML) of checks database that will be executed against the --target-root-url, default: 'checksdb.yaml'")
    parser.add_argument('-a', '--slack-config-filename', dest='slack_config_filename', default=None, \
        help="Optional: Filename (YAML) containing the slack alert configuration. default: None")
    parser.add_argument('-o', '--output-filename', dest='output_filename', default=None, \
        help="Optional: The result of the checks will be written to this output filename, default: None")
    parser.add_argument('-f', '--output-format', dest='output_format', default="json", \
        help="Output format: json or yaml, default 'json'")
    parser.add_argument('-v', '--verbose-output', action='store_true', default=False, \
        help="The result output will be in verbose mode, containing much more detail helpful in debugging. Default OFF")
    parser.add_argument('-q', '--tags-qualifier', dest='tags_qualifier', default=None, \
        help="Optional, only include 'checks' loaded in --checksdb-filename whos 'tags' attribute contains ONE or MORE values this comma delimited list of tags")
    parser.add_argument('-d', '--tags-disqualifier', dest='tags_disqualifier', default=None, \
        help="Inverse of --tags-qualifier. Exclude 'checks' loaded in --checksdb-filename whos 'tags' attribute contains ONE or MORE values this comma delimited list of tags")
    parser.add_argument('-r', '--max-retries', dest='max_retries', default=100, \
        help="Maximum retries per check, overrides those provided in --checksdb-filename, default 100")
    parser.add_argument('-n', '--check-name', dest='check_name', default="no --check-name specified", \
        help="Optional descriptive name for this invocation, default 'no --job-name specified'")
    parser.add_argument('-t', '--threads', dest='threads', default=1, \
        help="max threads for processing checks listed in --checksdb-filename, default 1, higher = faster completion, adjust as necessary to avoid DOSing...")
    parser.add_argument('-s', '--sleep-seconds', dest='sleep_seconds', default=0, \
        help="The MAX amount of time to sleep between all attempts for each service check; if > 0, the actual sleep will be a RANDOM time from 0 to this value. Default 0")
    parser.add_argument('-l', '--log-level', dest='log_level', default="DEBUG", \
        help="log level, default DEBUG ")
    parser.add_argument('-b', '--log-file', dest='log_file', default=None, \
        help="Path to log file, default None, STDOUT")
    parser.add_argument('-z', '--stdout-result', action='store_true', default=True, \
        help="Print check results to STDOUT in addition to --output-filename on disk (if specified)")
    parser.add_argument('-x', '--any-check-fail-exit-code', dest='any_check_fail_exit_code', default=1, \
        help="If ANY single check defined in --checksdb-filename fails or a general program error occurs, force a sys.exit(your-provided-exit-code). If all checks are successful the exit code will be 0. Default 1")
    parser.add_argument('-D', '--debug-slack-jinja2-context', action='store_true', default=False, \
        help="Dumps a JSON debug output of the jinja2 object passed to the Slack jinja2 template")
    parser.add_argument('-e', '--extra-slack-context-props', dest="extra_slack_context_props", default=None, \
        help="Optional comma delimited of key=value,key2=value pairs that will be added to the 'context' object passed to the Slack Alert jinja2 templates under the key 'extra_props'")


    args = parser.parse_args()


    dump_help = False
    if args.target_root_url is None:
        print('--target-root-url is required')
        dump_help = True
    if args.checksdb_filename is None:
        print('--checksdb-filename is required')
        dump_help = True
    if dump_help:
        parser.print_help()
        sys.exit(1)

    logging.basicConfig(level=logging.getLevelName(args.log_level),
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        filename=args.log_file,filemode='w')
    logging.Formatter.converter = time.gmtime

    max_retries = int(args.max_retries)

    tags_qualifier_arr = []
    if args.tags_qualifier is not None:
        tags_qualifier_arr = args.tags_qualifier.split(",")

    tags_disqualifier_arr = []
    if args.tags_disqualifier is not None:
        tags_disqualifier_arr = args.tags_disqualifier.split(",")

    # invoke!
    execute(args.target_root_url, \
            args.checksdb_filename, \
            args.output_filename, \
            args.output_format, \
            max_retries, \
            args.check_name, \
            args.threads, \
            args.stdout_result, \
            args.sleep_seconds, \
            args.any_check_fail_exit_code, \
            args.verbose_output, \
            args.slack_config_filename, \
            tags_qualifier_arr, \
            tags_disqualifier_arr, \
            args.debug_slack_jinja2_context, \
            args.extra_slack_context_props, \
            args)
