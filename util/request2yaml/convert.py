import yaml
import re
import xml.etree.ElementTree as ET
import base64
import sys

rule_id = sys.argv[1]

tree = ET.parse("/home/nt/Downloads/requests.xml")
root = tree.getroot()

requests = []
for item in root.findall('item'):
    requests.append(base64.b64decode(item.find('request').text))

def get_request_info(input_request):
    data = re.search(b"^(\\w+)\\s+([^\\s]+)\\s+(HTTP.*?)\r?$", input_request, re.M)

    return data.group(1), data.group(3), data.group(2)

def get_method(input_request):
    return re.search(b"^(\\w+)\\s", input_request, re.M).group(1)

def get_version(input_request):
    return re.search(b"(HTTP.*)$", input_request, re.M).group(1)

def get_headers(input_request):
    # header = header.replace("-", "\\-")
    # print(f"^{header}: (.*)$")
    headers = {x.group(1).decode(): x.group(2).decode() for x in re.finditer(rb"^([\w-]+):\s+(.*?)\r?$", input_request, re.M)}
    print(headers)
    return headers

def get_body(input_request):
    return re.search(b"\r?\n\r?\n(.*)", input_request, re.M).group(1)

def parse_requests(requests, rule_id):
    result = []
    i = 1
    for r in requests:
        print('Parsing request')
        print(r.decode())
        method, version, uri = get_request_info(r)
        request = {}
        request["test_title"] = rule_id + "-" + str(i)
        i += 1
        request["desc"] = "desc"
        request["stages"] = [
            {
                "stage": {
                    "input": {
                        "dest_addr": "localhost",
                        "port": 80,
                        "headers": get_headers(r),
                        "method": method.decode(),
                        "version": version.decode(),
                        "uri": uri.decode(),
                        "data": get_body(r)
                    },
                    "output": {
                        "status": 403
                    }
                }
            }
        ]

        if not request["stages"][0]["stage"]["input"]["data"]:
            del request["stages"][0]["stage"]["input"]["data"]
        
        result.append(request)
    return result

data = {
    "meta": {
        "author": "ngoctin",
        "description": "Polaris Comodo WAF test",
        "enabled": True,
        "name": "polaris-comodo-waf-test"
    },
    "tests": parse_requests(requests, rule_id)
}

with open("../../tests/regression/tests/COMODO-CVE-RULES/" + rule_id + ".yaml", 'w') as stream:
    yaml.dump(data, stream, default_flow_style=False, allow_unicode=True)