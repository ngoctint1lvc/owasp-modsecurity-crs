# from BaseHTTPServer import BaseHTTPRequestHandler
# from StringIO import StringIO
# from ruamel.yaml import YAML


# class HTTPRequest(BaseHTTPRequestHandler):
#     def __init__(self, request_text):
#         self.rfile = StringIO(request_text)
#         self.raw_requestline = self.rfile.readline()
#         self.error_code = self.error_message = None
#         self.parse_request()

#     def send_error(self, code, message):
#         self.error_code = code
#         self.error_message = message


def stringEscape(payload):
    return '"' + payload.replace("\n", "\\r\\n").replace("\t", "\\t").replace('"', '\\"') + '"'


inFile = open("./in.txt", "r")
payload = inFile.read()
# request = HTTPRequest(rawRequest)

# contentLength = int(request.headers["Content-length"])
# body = request.rfile.read(contentLength)
# parsedRequest = {
#     'dest_addr': '127.0.0.1',
#     'port': '80',
#     'headers': request.headers.dict,
#     "method": request.command,
#     "version": request.request_version,
#     "uri": request.path,
#     "data": body
# }

outFile = open("./out.txt", "w")
outFile.write(stringEscape(payload))

inFile.close()
outFile.close()
