from pprint import pformat

def debug(msg, tag=None):
    with open("/tmp/debug.txt", "r+") as fd:
        fd.write("[DEBUG] " + (f"[{tag}] " if tag else "") + pformat(msg))