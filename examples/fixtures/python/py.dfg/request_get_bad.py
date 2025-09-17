import os
from flask import request

def handler():
    command = request.args.get("cmd")
    os.execv("/bin/sh", ["/bin/sh", "-c", command])
