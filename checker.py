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
import json
import pprint
import argparse
import sys
import yaml
from multiprocessing import Pool
from jinja2 import Template

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
    if 'is_healthy' in hc:
        success_status_codes = hc['is_healthy']['response_codes']
        if 'body_evaluator' in hc['is_healthy']:
            success_body_evaluator = hc['is_healthy']['body_evaluator']


    # lets actually check if the response is legit...
    response_is_healthy = False
    response_unhealthy_reason = None
    if response.getcode() in success_status_codes:

        # handle evaluator..
        if success_body_evaluator is not None:

            if success_body_evaluator['type'] == "contains":
                if success_body_evaluator["value"] in response_data['as_string']:
                    response_is_healthy = True
                else:
                    response_unhealthy_reason = "body_evaluator[contains] failed, did not find: '"+success_body_evaluator["value"]+"' in resp. body"

            elif success_body_evaluator['type'] == "jinja2":
                t = Template(success_body_evaluator["template"])
                x = t.render(response_data=response_data,response_code=response.getcode())
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
            job_name, \
            threads, \
            stdout_result, \
            sleep_seconds, \
            any_check_fail_exit_code, \
            ports_qualifier, \
            verbose_output):

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

        # process it all
        for checkdef in checks_db:

            # for future filtering possibilities
            hc_executable = True
            no_match_reason = None

            # check port qualifiers
            if ports_qualifier is not None and 'ports' in checkdef:
                for port_qualifier in ports_qualifier:
                    if int(port_qualifier) not in checkdef['ports']:
                        hc_executable = False
                        no_match_reason = "No 'ports' matching in provided 'ports_qualifier'"

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
                if verbose_output:
                    finalized_checks_db.append(checkdef)

        # ok here we dump all the service check records
        # to be executed concurrently in the pool
        # which returns a copy...
        executable_service_checks = exec_pool.map(execServiceCheck, \
                                                  executable_service_checks)

        has_failures = False
        for config in executable_service_checks:
            check_def = config['check_def']

            finalized_checks_db.append(check_def)
            if not check_def['result']['success']:
                has_failures = True


        # simplify output if not in verbose mode
        for check_def in finalized_checks_db:
            if not verbose_output:
                check_def.pop("curl",None)
                check_def.pop("classifiers",None)
                check_def.pop("tags",None)
                check_def.pop("body",None)
                check_def.pop("headers",None)
                check_def.pop("ports",None)
                check_def.pop("is_healthy",None)
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
                    json.dump(finalized_checks_db, outfile, indent=4)
                else:
                    yaml.dump(finalized_checks_db, outfile, default_flow_style=False)

                logging.debug("Output written to: " + output_filename)


        # also to stdout?
        if stdout_result:
            print()
            if output_format == 'json':
                print(json.dumps(finalized_checks_db,indent=4))
            else:
                yaml.dump(finalized_checks_db, outfile, default_flow_style=False)

        print()

        # any failures? exit according to code
        if has_failures and any_check_fail_exit_code:
            sys.exit(any_check_fail_exit_code)


    # end main wrapping try
    except Exception as e:
        logging.exception("Error in checker.execute()")

    finally:
        try:
            if exec_pool is not None:
                exec_pool.close()
                exec_pool.terminate()
                exec_pool = None
                logging.debug("Pool closed and terminated")
        except:
            logging.exception("Error terminating, closing pool")

###########################
# Main program
##########################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--target-root-url', dest='target_root_url', \
        help="Target root URL where all checks defined in --checksdb-filename will execute against. Each check 'path' defined in --checksdb-filename will be APPENDED to this value.")
    parser.add_argument('-i', '--checksdb-filename', dest='checksdb_filename', default="checksdb.yaml", \
        help="Filename (YAML or JSON) of checks database that will be executed against the --target-root-url, default: 'checksdb.yml'")
    parser.add_argument('-o', '--output-filename', dest='output_filename', default=None, \
        help="Output filename, default: None")
    parser.add_argument('-f', '--output-format', dest='output_format', default="json", \
        help="json or yaml, default 'json'")
    parser.add_argument('-v', '--verbose-output', action='store_true', default=False, \
        help="Output check result details with extra verbosity")
    parser.add_argument('-p', '--ports-qualifier', dest='ports_qualifier', default=None, \
        help="Optional comma delimited list of port qualifiers to limit checks in --checksdb-filename, i.e. if specified only checks defined with 'ports' matching one or more of these will be executed")
    parser.add_argument('-r', '--max-retries', dest='max_retries', default=3, \
        help="maximum retries per check, overrides service-state service check configs, default 3")
    parser.add_argument('-n', '--job-name', dest='job_name', default="no --job-name specified", \
        help="descriptive name for this execution job, default 'no --job-name specified'")
    parser.add_argument('-t', '--threads', dest='threads', default=1, \
        help="max threads for processing checks, default 30, higher = faster completion, adjust as necessary to avoid DOSing...")
    parser.add_argument('-s', '--sleep-seconds', dest='sleep_seconds', default=0, \
        help="The max amount of time to sleep between all attempts for each service check; if > 0, the actual sleep will be a random time from 0 to this value. Default 0")
    parser.add_argument('-l', '--log-level', dest='log_level', default="DEBUG", \
        help="log level, default DEBUG ")
    parser.add_argument('-b', '--log-file', dest='log_file', default=None, \
        help="Path to log file, default None, STDOUT")
    parser.add_argument('-z', '--stdout-result', action='store_true', default=True, \
        help="print results to STDOUT in addition to --output-filename on disk (if specified)")
    parser.add_argument('-x', '--any-check-fail-exit-code', dest='any_check_fail_exit_code', default=1, \
        help="If any check defined in --checksdb-filename fails, force an exit code. Default 1")

    args = parser.parse_args()

    if args.target_root_url is None:
        print('--target-root-url is required')
        sys.exit(1)

    logging.basicConfig(level=logging.getLevelName(args.log_level),
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        filename=args.log_file,filemode='w')
    logging.Formatter.converter = time.gmtime

    max_retries = int(args.max_retries)

    ports_qualifier_arr = []
    if args.ports_qualifier is not None:
        ports_qualifier_arr = args.ports_qualifier.split(",")

    execute(args.target_root_url,args.checksdb_filename,args.output_filename, \
        args.output_format,max_retries,args.job_name,args.threads,args.stdout_result, \
        args.sleep_seconds,args.any_check_fail_exit_code,ports_qualifier_arr,args.verbose_output)
