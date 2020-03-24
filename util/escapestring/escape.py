#!python

def stringEscape(payload):
    return '"' + payload.replace("\n", "\\r\\n").replace("\t", "\\t").replace('"', '\\"') + '"'

inFile = open("./in.txt", "r")
payload = inFile.read()

outFile = open("./out.txt", "w")
outFile.write(stringEscape(payload))

inFile.close()
outFile.close()
