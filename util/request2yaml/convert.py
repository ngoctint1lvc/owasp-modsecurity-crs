import yaml
import re

with open("./input.txt", "r") as fd:
    input_request = fd.read()

print(input_request)

def get_request_info():
    global input_request
    data = re.search("^(\\w+)\\s+([^\\s]+)\\s+(HTTP.*)$", input_request, re.M)

    return data.group(1), data.group(3), data.group(2)

def get_method():
    global input_request
    return re.search("^(\\w+)\\s", input_request, re.M).group(1)

def get_version():
    global input_request
    return re.search("(HTTP.*)$", input_request, re.M).group(1)

def get_header(header):
    global input_request
    # header = header.replace("-", "\\-")
    # print(f"^{header}: (.*)$")
    result = re.search(f"^{header}: (.*)$", input_request, re.I + re.M)
    if result:
        return result.group(1)

    return ""

def get_body():
    global input_request
    return re.search("\n\n(.*)", input_request, re.M).group(1)

method, version, uri = get_request_info()
request = {}
request["test_title"] = "title"
request["desc"] = "desc"
request["stages"] = [
    {
        "stage": {
            "input": {
                "dest_addr": "localhost",
                "port": 80,
                "headers": {
                    "Host": "localhost",
                    "User-Agent": get_header("User-Agent"),
                    "Accept": get_header("Accept"),
                    "Accept-Encoding": get_header("Accept-Encoding"),
                    "Accept-Language": get_header("Accept-Language"),
                    "Content-Type": get_header("Content-Type"),
                    "Cookie": get_header("Cookie")
                },
                "method": method,
                "version": version,
                "uri": uri,
                "data": get_body()
            },
            "output": {
                "log_contains": 'id "9000000"',
                "response_contains": "403 Forbiden",
                "status": 403
            }
        }
    }
]

data = {
    "meta": {
        "author": "ngoctin",
        "description": "Polaris false positive test",
        "enabled": True,
        "name": "polaris-false-positive"
    },
    "tests": request
}

with open("output.yaml", 'w') as stream:
    yaml.dump(data, stream, default_flow_style=False, allow_unicode=True)