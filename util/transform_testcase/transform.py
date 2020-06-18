import glob
import os
import yaml
import re


def transform(host="tin.acbpro.com", port=80, forbiden_check=True, log_check=True, remove_normal_tests=False, id_regex='"id":"\\1"', pattern='polaris-custom-rules'):
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
                                    stage["stage"]["output"]["log_contains"] = re.sub(
                                        "id ['\"](\\d+)['\"]", id_regex, check_log_msg)
                                except:
                                    print(f"[x] Error in {testcase}: {stage}")

                            if "no_log_contains" in stage["stage"]["output"].keys():
                                check_log_msg = stage["stage"]["output"]["no_log_contains"]
                                try:
                                    stage["stage"]["output"]["no_log_contains"] = re.sub(
                                        "id ['\"](\\d+)['\"]", id_regex, check_log_msg)
                                except:
                                    print(f"[x] Error in {testcase}: {stage}")
                        else:
                            if "log_contains" in stage["stage"]["output"].keys():
                                del stage["stage"]["output"]["log_contains"]

                            if "no_log_contains" in stage["stage"]["output"].keys():
                                del stage["stage"]["output"]["no_log_contains"]
                                if remove_normal_tests:
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
