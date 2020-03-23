import glob
import os
import yaml
import sys
import re
import sys

curdir = os.getcwd()
fileDir = os.path.dirname(sys.argv[0])

print("[+] Sync testcases from modsecurity")
os.chdir(fileDir)
os.system("rsync -avh ../../regression/tests/* ../../regression/polaris-tests")
os.chdir(curdir)

print("[+] Transform testcase for polaris waf")
testcases = glob.glob(os.path.join(fileDir, "../../regression/polaris-tests/**/*.yaml")) if len(sys.argv) < 2 else sys.argv[1:]

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
                        stage["stage"]["input"]["dest_addr"] = "tin.acbpro.com"

                    # update host header
                    if "headers" in stage["stage"]["input"].keys() and "Host" in stage["stage"]["input"]["headers"].keys():
                        stage["stage"]["input"]["headers"]["Host"] = "tin.acbpro.com"

                    # change id format
                    if "log_contains" in stage["stage"]["output"].keys():
                        check_log_msg = stage["stage"]["output"]["log_contains"]
                        result = re.search(r"\"(\d+)\"", check_log_msg)

                        if result:
                            ruleId = result.group(1)
                            stage["stage"]["output"]["log_contains"] = f'"id":"{ruleId}"'
                        else:
                            print(f"[x] Error in {testcase}: {stage}")

                    # change id format
                    if "no_log_contains" in stage["stage"]["output"].keys():
                        check_log_msg = stage["stage"]["output"]["no_log_contains"]
                        result = re.search(r"\"(\d+)\"", check_log_msg)

                        if result:
                            ruleId = result.group(1)
                            stage["stage"]["output"]["no_log_contains"] = f'"id":"{ruleId}"'
                        else:
                            print(f"[x] Error in {testcase}: {stage}")

                    # change port to 80
                    if "port" in stage["stage"]["input"].keys():
                        stage["stage"]["input"]["port"] = 80

        except yaml.YAMLError as err:
            print(err)
    
    with open(testcase, 'w') as stream:
        yaml.dump(data, stream, default_flow_style=False, allow_unicode=True)