import glob
import os
import yaml
import re

forbiden_message = 'Your request has been blocked'

def transform(host="dvwa.test", port=80, id_regex='"id":"\\1"', pattern='sqli', cookies=''):
    current_dir = os.getcwd()

    print("[+] Sync testcases from modsecurity")
    test_regression_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "../../tests/regression"))
    os.chdir(test_regression_dir)
    os.system("rsync -avh tests/* transformed-tests")

    print("[+] Transform testcase for polaris waf")
    testcases = glob.glob(os.path.join(
        test_regression_dir, f"transformed-tests/*{pattern.upper()}*/*.yaml"))
    for testcase in testcases:
        print(f" [+] Transform testcase {testcase}")
        data = ''
        with open(testcase, 'r') as stream:
            try:
                data = yaml.safe_load(stream)

                # skip empty testcase
                if not data:
                    continue

                for test in data["tests"]:
                    for stage in test["stages"]:
                        # update destination address to polaris waf
                        if "dest_addr" in stage["stage"]["input"].keys():
                            stage["stage"]["input"]["dest_addr"] = host

                        # update host header
                        if "headers" in stage["stage"]["input"].keys() and "Host" in stage["stage"]["input"]["headers"].keys():
                            stage["stage"]["input"]["headers"]["Host"] = host
                            # update cookies
                            _cookies = stage["stage"]["input"]["headers"].get("Cookie", "")
                            if len(_cookies.strip()) > 0:
                                _cookies += "; " + cookies
                            else:
                                _cookies = cookies
                            stage["stage"]["input"]["headers"]["Cookie"] = _cookies

                        # add 403 forbiden check
                        # stage["stage"]["output"]["response_contains"] = forbiden_message
                        # stage["stage"]["output"]["status"] = 403
                        if "response_contains" in stage["stage"]["output"].keys():
                            del stage["stage"]["output"]["response_contains"]

                        # check rule id in header
                        rule_id = test["test_title"].split("-")[0]
                        stage["stage"]["output"]["header_contains"] = 'x-match-rules: .*?"id":' + rule_id

                        if "log_contains" in stage["stage"]["output"].keys():
                            del stage["stage"]["output"]["log_contains"]

                        if "no_log_contains" in stage["stage"]["output"].keys():
                            test["to_be_removed"] = True

                        # change port
                        if "port" in stage["stage"]["input"].keys():
                            stage["stage"]["input"]["port"] = port

                data["tests"] = [item for item in data["tests"]
                                 if not "to_be_removed" in item.keys()]

            except Exception:
                import traceback
                traceback.print_exc()
                stream.close()
                continue

        with open(testcase, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False,
                      allow_unicode=True)

        os.chdir(current_dir)
