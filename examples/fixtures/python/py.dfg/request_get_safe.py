from flask import request

def handler():
    command = request.args.get("cmd")
    if not command:
        return "no command"
    return command.strip()
