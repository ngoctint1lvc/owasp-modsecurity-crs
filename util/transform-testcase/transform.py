import glob
import os
import yaml
import sys
import re
import sys

def transform(host = "tin.acbpro.com", port=80, forbiden_check=True, log_check=True):
    global testcases
    for testcase in testcases:
        print(f" [+] Transform testcase {testcase}")
        data = ''
        with open(testcase, 'r') as stream:
            try:
                data = yaml.safe_load(stream)
                for test in data["tests"]:
                    for stage in test["stages"]:
                        # update destination address to polaris waf
                        if "dest_addr" in stage["stage"]["input"].keys():
                            stage["stage"]["input"]["dest_addr"] = host

                        # update host header
                        if "headers" in stage["stage"]["input"].keys() and "Host" in stage["stage"]["input"]["headers"].keys():
                            stage["stage"]["input"]["headers"]["Host"] = host

                        # add 403 forbiden check
                        if forbiden_check:
                            if "response_contains" not in stage["stage"]["output"].keys() and \
                                "status" not in stage["stage"]["output"].keys() and \
                                "no_log_contains" not in stage["stage"]["output"].keys():
                                stage["stage"]["output"]["response_contains"] = "403 Forbidden"
                        else:
                            if "response_contains" in stage["stage"]["output"].keys() and stage["stage"]["output"]["response_contains"] == "403 Forbidden":
                                del stage["stage"]["output"]["response_contains"]

                        if log_check:
                            # change id format
                            if "log_contains" in stage["stage"]["output"].keys():
                                check_log_msg = stage["stage"]["output"]["log_contains"]
                                try:
                                    stage["stage"]["output"]["log_contains"] = re.sub("id (?=['\"])", "\"id\":", check_log_msg)
                                except:
                                    print(f"[x] Error in {testcase}: {stage}")
                        else:
                            if "log_contains" in stage["stage"]["output"].keys():
                                del stage["stage"]["output"]["log_contains"]

                        # change port
                        if "port" in stage["stage"]["input"].keys():
                            stage["stage"]["input"]["port"] = port

            except yaml.YAMLError as err:
                print(err)
        
        with open(testcase, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False, allow_unicode=True)

test_regression_dir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), "../../tests/regression"))
version = 'polaris-pro-tests' if os.getenv("PRO") else 'polaris-tests'

print("[+] Sync testcases from modsecurity")
os.chdir(test_regression_dir)
if len(sys.argv) < 2:
    os.system(f"rsync -avh tests/POLARIS-CUSTOM-RULES/ {version}/POLARIS-CUSTOM-RULES")
else:
    os.system(f"rsync -avh tests/* {version}")

print("[+] Transform testcase for polaris waf")
if len(sys.argv) < 2:
    testcases = glob.glob(os.path.join(test_regression_dir, f"{version}/POLARIS-CUSTOM-RULES/*.yaml"))
else:
    testcases = glob.glob(os.path.join(test_regression_dir, f"{version}/**/*.yaml"))

host = os.getenv('HOST') or ('verichains.tech' if os.getenv('PRO') else 'tin.acbpro.com')

if os.getenv('PRO'):
    transform(host, forbiden_check=True, log_check=False)
else:
    transform(host, forbiden_check=False, log_check=True)