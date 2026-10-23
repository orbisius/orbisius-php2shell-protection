# Orbisius PHP Security — php2shell Stopgap (Apache & Nginx)

Drop-in web-server rules that block the **php2shell** remote-code-execution attack
(**CVE-2026-109618** and **CVE-2026-109619**) *before* the request reaches PHP —
for servers running a PHP version you **cannot patch right now**.

| Server | File | Allowlist | Body-size cap |
|--------|------|-----------|---------------|
| Apache **2.4** | [`apache/php2shell-2.4.conf`](apache/php2shell-2.4.conf) | single IP **or** CIDR range (`expr -R`) | **per-IP** (admins exempt) |
| Apache **2.2** | [`apache/php2shell-2.2.conf`](apache/php2shell-2.2.conf) | single IP, or a regex prefix for a range | global only (optional) |
| **Nginx** | [`nginx/php2shell.conf`](nginx/php2shell.conf) | single IP **or** CIDR range (`geo`) | global only (optional) |

---

## ⚠️ Disclaimer — read this first

- **For educational purposes.** Provided **as-is, with no warranty** of any kind.
- **You are solely responsible** for anything you deploy on your own systems and
  for any consequence of using (or not using) these rules. Review them, understand
  what they do, and **test on a staging copy first**.
- This is a **stopgap, not a fix.** It blocks the *known* attack shapes; it is
  **not** a substitute for updating PHP. In PHP's own words about these CVEs:
  *"There are no complete mitigations, updating is the only safe choice."*
- It is deliberately **blunt** — while active it also blocks legitimate large
  uploads and multipart posts from anyone not in your allowlist. That is the
  trade-off of buying time. **Remove it once you have patched or migrated.**

---

## Why this exists

CVE-2026-109618 and CVE-2026-109619 (nicknamed *php2shell*) are a pair of flaws in
how PHP parses request bodies. An attacker can reach remote code execution by
sending a crafted **`multipart/form-data`** body, or a **large (>1 MB)
url-encoded** body carrying a ~1 MiB field name. Public proof-of-concept exploits
and mass scanners send exactly these shapes.

These rules make the web server **reject those request shapes with a silent `404`**
before PHP ever parses the body, so the vulnerable code path is never reached.

**Update PHP — that is the real fix:**

- PHP security info: <https://www.php.net/security>
- PHP downloads: <https://www.php.net/downloads>
- Patched versions: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**, plus distro backports
  for **7.4 / 8.1** (e.g. Debian/Ubuntu `ondrej/php`, or your vendor's package).
- Look up the CVEs: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618)
  · [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619) (also on
  [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)). *Verify against php.net's
  own bulletin for your version — the canonical source is the release announcement
  for the patched build above.*

### When to use it

This is for the gap between *disclosure* and *being patched* — specifically:

- **Servers you cannot upgrade at the moment** (change freeze, dependency pin,
  legacy app that breaks on a newer PHP, no maintenance window).
- **Servers awaiting migration** off an old host or PHP version.
- **End-of-life PHP** that will never get a patch.

Deploy it, buy yourself time, patch/migrate, then take it back out.

---

## What it blocks

For every client **not** in your allowlist, on any method that carries a body
(POST — and PUT / PATCH / DELETE, whose bodies PHP 8.4+ parses with the same code;
GET and HEAD are left alone):

- a **`multipart/form-data`** body — the parser out-of-memory path of
  CVE-2026-109618 and the upload-progress chain of CVE-2026-109619;
- any body with **`Content-Length` ≥ ~1 MB** — the url-encoded CVE-2026-109618
  variant (a >1 MB body with a ~1 MiB field name);
- a large body sent **chunked** (no `Content-Length`) — caught by the body-size cap
  (it counts the actual bytes). **Per-IP** on Apache 2.4; **global-only** on Apache
  2.2 and Nginx.

On **Apache with mod_php**, the config also switches PHP's `session.upload_progress`
feature **off outright** (the CVE-2026-109619 vector) for every client — the
`<IfModule php_*>` block overrides php.ini even if it wasn't disabled there, and a
server/vhost deploy locks it so an app can't `ini_set()` it back on. (Under PHP-FPM
those directives don't apply — disable it in the FPM pool or php.ini.)

## What it does NOT block

- CVE-2026-109619 triggers that are **not** multipart (a bad per-request INI
  directive; any request that just exhausts `memory_limit` or `max_execution_time`).
- Requests the rule never sees — it is below another app's rewrite rules, in a scope
  the request doesn't pass through, or the rewrite module isn't loaded. **The
  placement and the "prove it" steps below matter.**
- On **Apache mod_php**, the part only `LimitRequestBody` would stop when PHP runs
  via **PHP-FPM over `mod_proxy_fcgi`** (Apache doesn't apply the cap to a proxied
  body). The rewrite rule still stops multipart and `Content-Length ≥ ~1 MB`.

---

## Pick your server + edition

```bash
apachectl -v     # Apache: "Apache/2.4.x" -> apache/php2shell-2.4.conf ; "Apache/2.2.x" -> apache/php2shell-2.2.conf
nginx -v         # Nginx:  any recent version -> nginx/php2shell.conf
```

The Apache 2.4 edition uses `<If>` and `expr -R` (real CIDR + per-IP cap), which 2.2
does not have. Nginx uses `geo` + `map`.

---

## Install — Apache

### 0. Make sure `mod_rewrite` is loaded

```bash
apachectl -M | grep rewrite        # must print: rewrite_module
# Debian/Ubuntu, if missing:  a2enmod rewrite && systemctl reload apache2
```

Without it, the `<IfModule mod_rewrite.c>` wrapper **skips the rule silently** — the
site keeps working, unprotected.

### 1. Set your admin IPs (the allowlist)

Replace the placeholders `203.0.113.5` / `198.51.100.7` (they match nobody) with
your office / VPN / admin addresses. Leave them to block everyone (no exemption).

**Apache 2.4** — edit **both** the `RewriteCond expr` line and the `<If>` line
(they share one allowlist). `-R` matches a single IP **or** a CIDR range:

```apache
RewriteCond expr "! (-R '203.0.113.5' || -R '198.51.100.0/24')"
...
<If "! (-R '203.0.113.5' || -R '198.51.100.0/24')">
```
Use the `! ( -R a || -R b )` spelling **exactly** — the natural-looking
`! -R a && ! -R b` does **not** behave the same and can leave admins blocked.

**Apache 2.2** — one `RewriteCond` per IP; for a range use a regex prefix:

```apache
RewriteCond %{REMOTE_ADDR} !=203.0.113.5
RewriteCond %{REMOTE_ADDR} !^192\.168\.
```

**Behind a CDN / load balancer / reverse proxy,** Apache sees the *proxy's* address
— never allowlist it (it exempts everyone). On 2.4 restore the visitor's IP with
`mod_remoteip`, trusting **only** your proxy (server/vhost config, not `.htaccess`):

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.0.0.5        # or RemoteIPTrustedProxy for public ranges
```
(Cloudflare: `RemoteIPHeader CF-Connecting-IP` with their published ranges.) On 2.2
there is no `mod_remoteip` — block at the proxy/CDN instead. **Never** test
`X-Forwarded-For` in a `RewriteCond` yourself: any client can forge it.

### 2. Deploy — pick the one that matches your access

#### Root access (you can edit Apache's config and reload it)

**Global — protect EVERY site on the box at once.** Adding the rules to the server
configuration applies them to **every virtual host / every site this Apache instance
serves** — one place, no per-site edits, nothing to repeat when you add a site later.
`Include` the repo file in place (works on any distro):
```bash
# add this line in httpd.conf / apache2.conf, or any file it already includes:
Include /path/to/orbisius-php2shell-protection/apache/php2shell-2.4.conf
```
or use your distro's drop-in directory (same effect — both just `Include` the file):
```bash
# Debian / Ubuntu:
cp apache/php2shell-2.4.conf /etc/apache2/conf-available/orbisius-php2shell.conf
a2enconf orbisius-php2shell
# RHEL / Alma / Rocky:
cp apache/php2shell-2.4.conf /etc/httpd/conf.d/orbisius-php2shell.conf
```

**One site only — paste it into that site's `<VirtualHost>`.** Put the blocks at vhost
level in the `:80` **and** the `:443` block. (Survives any `.htaccess` the site has.)

Either way, test the config and reload (`httpd` instead of `apache2` on RHEL):
```bash
apachectl -t && systemctl reload apache2
```
**Caveat for virtual-host setups:** the body cap is inherited by every vhost, but Apache
does **not** inherit server-level `mod_rewrite` rules into a `<VirtualHost>`, so the
global 404 rule reaches only vhosts that pull it in. On Apache 2.4.8+ add, at server
level, `RewriteOptions InheritDownBefore` (each vhost still needs its own
`RewriteEngine On`); otherwise paste it into each `<VirtualHost>` as above.

#### No root access (shared hosting — `.htaccess`)

Drop the rules into the document root's `.htaccess` — it takes effect on the next
request, no reload. Needs `AllowOverride FileInfo` (most shared hosts allow it; don't
widen to `All` just for this).
- No `.htaccess` there yet → save the edition as `.htaccess`.
- One already exists (WordPress, Laravel…) → **do not overwrite it**; paste this file's
  contents at the **very top**, above the app's own rules. Patch every other `.htaccess`
  under the docroot that has rewrite rules too
  (`find docroot -name .htaccess -exec grep -il rewrite {} +`).
- **Omit the `<IfModule php_*>` block at the end** — `php_admin_flag` is not allowed in
  `.htaccess` and 500s the site. The rewrite rule already blocks the multipart
  upload-progress delivery for non-allowlisted clients; with root, disable the feature
  via method B/C or php.ini instead.

### 3. Prove it (don't skip — every failure above is silent)

```bash
# from a machine NOT in your allowlist, against a real PHP URL (on WP also /wp-json/):
curl -s -o /dev/null -w '%{http_code}\n' -F probe=1 https://example.com/index.php   # want 404
curl -s -o /dev/null -w '%{http_code}\n' -d probe=1 https://example.com/index.php   # want 200 (as before)
```
`200` on the first = **not protected**; recheck step 2.

---

## Install — Nginx

Nginx evaluates the rule in **two contexts**, so `nginx/php2shell.conf` has two parts.

**Part 1 — the maps (`http {}` context).** Drop the file in `/etc/nginx/conf.d/`
(that directory is included inside `http {}` on stock installs):

```bash
cp nginx/php2shell.conf /etc/nginx/conf.d/orbisius-php2shell.conf
```

**Part 2 — the block (`server {}` context).** Add this inside **each** `server {}`
that serves the site (or its PHP `location`):

```nginx
if ($orb_block) { return 404; }
# client_max_body_size 512k;   # optional global cap — see below
```

Then test and reload:

```bash
nginx -t && systemctl reload nginx
```

**Allowlist:** edit the `geo $orb_allow { … }` block — one `IP 1;` or `CIDR 1;` per
admin. **Behind a CDN/proxy**, nginx sees the proxy IP, so restore the real client
IP first, trusting only your proxy:

```nginx
set_real_ip_from 10.0.0.0/8;      # your proxy's address(es) ONLY
real_ip_header X-Forwarded-For;   # or CF-Connecting-IP behind Cloudflare
```
Never allowlist the proxy's own IP — it exempts every client.

**Body cap:** `client_max_body_size` is **not** per-IP (nginx can't take a variable
there), so it is **global** and would cap admins too. Set it to close the chunked
case, or leave it off and rely on the multipart + `Content-Length` block.

**PHP-FPM:** nginx always proxies to FPM, and this rule runs *before* `fastcgi_pass`,
so it applies cleanly — none of the Apache `.htaccess` / `ProxyPassMatch` caveats.

**Prove it:** same two `curl` commands as Apache step 3, against a real PHP URL.

---

## The body-size cap

Closes the chunked / no-`Content-Length` case by counting actual bytes. Keep it
**under ~1 MiB** so a ~1 MiB field name can't fit — **512 KB (`524288`)** is a safe
default.

- **Apache 2.4** — **active and per-IP**: the `<If "! (-R …)">` applies the cap only
  to non-allowlisted clients; your admin IPs get no cap.
- **Apache 2.2 / Nginx** — can only be **global** (no per-IP form), so it would cap
  admins too. Ships **off**; enable it (`LimitRequestBody 524288` /
  `client_max_body_size 512k`) only if you accept that, or use `mod_security` (Apache)
  for a true per-IP cap.

---

## Seeing blocked requests

Blocks appear in the access log as a `404` on a request that has a body (ordinary
404s are GETs for missing files); a ≥1 MB body logs as `413`. On Apache, for a
blocks-only log inside a `<VirtualHost>`:

```apache
CustomLog ${APACHE_LOG_DIR}/cve_block.log common env=ORBISIUS_CVE_MULTIPART_BLOCK
```
(Use an **absolute** path where `${APACHE_LOG_DIR}` isn't defined.)

## Why a silent `404` (not `403` or `503`)

A bare `404` reveals nothing. A `403`, or a `503` with `Retry-After`, tells an
attacker a rule rejected their specific request shape — useful feedback for crafting
a bypass. The rules set an internal flag for your logs but send the client **no**
block-revealing header.

## Remove it after patching

Once PHP is patched or the site migrated, **take the rules back out** — delete the
`.htaccess` block, `a2disconf`/remove the Apache file, or remove the nginx file and
the `if` line, then reload. It has done its job.

---

## How it works

**Apache** (2.4 shown):
```apache
RewriteCond %{REQUEST_METHOD} !^(GET|HEAD)$                       # only methods with a body
RewriteCond expr "! (-R '203.0.113.5' || -R '198.51.100.7')"     # …from a NON-allowlisted client
RewriteCond %{HTTP:Content-Type} multipart/form-data [NC,OR]     # …that is multipart …
RewriteCond %{HTTP:Content-Length} [0-9]{7,}$                    # … OR a body >= ~1 MB
RewriteRule ^ - [R=404,L,E=ORBISIUS_CVE_MULTIPART_BLOCK:1]       # → silent 404 + log flag
```

**Nginx** computes the same decision with `map`/`geo` in `http {}`, then one `if`:
```nginx
# $orb_allow (geo) · $orb_has_body · $orb_multipart · $orb_large  → combined into $orb_block
if ($orb_block) { return 404; }
```

Notes that apply to both:
- `Content-Type` / `Content-Length` are read from the **request** headers.
- The `Content-Length` pattern is anchored only at the **end** (`[0-9]{7,}$`): some
  stacks read `Content-Length: +1100000` as a number, which a start-anchored pattern
  would let slip.
- The logic is *not-GET/HEAD **AND** not-allowlisted **AND** (multipart **OR** large)*.
- `GET`/`HEAD` are skipped so the site's own `ErrorDocument`/error page (served as an
  internal GET) isn't blocked too.

---

## Credits & license

Made by [Orbisius](https://orbisius.com). Share it freely with anyone who needs to
buy time against php2shell.

**License:** [MIT](LICENSE) — provided as-is, **without warranty**. See the
disclaimer at the top: you are responsible for what you deploy.
