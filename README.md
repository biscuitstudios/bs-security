# Biscuit Security

Biscuit's site security in one plugin. Sends the response security headers
that managed WordPress hosts and WordPress itself leave off, and closes the
three doors attackers try first: usernames, login error wording, and the file
editor. Replaces Biscuit Security Headers (`bs-security-headers`).

Built and maintained by [Biscuit Studios](https://biscuitstudios.com/) for our
own client sites. Published because it may be useful to others, not because it
is a supported product. See [Support](#support).

## What switches on by itself

Activating the plugin is the whole setup. Three headers start sending
immediately, and none of them can break a normal site:

| Header | Value | What it does |
|---|---|---|
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Stops the full address of the page a visitor was on travelling with them to other sites. Sends the domain name only. |
| `Permissions-Policy` | camera, microphone and the three motion sensors blocked | Refuses those features outright, so nothing that reaches a page can prompt a visitor for them. |
| `X-Frame-Options` | `SAMEORIGIN` | Stops another site displaying these pages in a frame, which is how clickjacking works. |

Four more are available and start switched off, because each one can break
something, is already handled elsewhere, or is a trial:

| Header | Why it is off |
|---|---|
| `Strict-Transport-Security` | Cannot be undone. See below. |
| `Content-Security-Policy` | Has to be written against what a particular site actually loads. |
| `X-Content-Type-Options` | Kinsta and xCloud already send it. Here for portability. |
| `Content-Security-Policy-Report-Only` | A trial policy that blocks nothing. See below. |

## CSP report-only

A Content-Security-Policy is the strongest header here and the easiest to get
wrong: a policy that misses one script source breaks that script quietly. The
report-only mode is how to find out what a policy would break before it is
enforced.

Switch it on under **Settings → Security**, paste a candidate policy, and the
plugin sends it as `Content-Security-Policy-Report-Only`. Visitors' browsers
block nothing. They report what they would have blocked to
`/wp-json/bssec/v1/csp-report`, and the plugin folds those reports into one row
per directive and blocked site, with a count. After a few weeks of normal
traffic, the real policy is written from that list.

- **It is separate from the enforced policy**, so a site can run a loose
  enforced policy and a strict candidate side by side.
- **It reaches WooCommerce's Checkout and My Account pages.** WooCommerce
  replaces any enforced `Content-Security-Policy` there with its own one-line
  policy, but it never touches the report-only header, so this is how to see
  what a policy would do on the payment page.
- **Collection ends on its own**, 30 days after it is switched on unless a
  later date is set. Then the header stops and the report address closes.
- **What is stored:** the directive, the blocked site's address (never the full
  URL), the page's path, and counts. Never a query string or fragment, and
  WooCommerce order numbers in paths become `{n}`. No IP address and no user
  agent.
- **The report address is public, by necessity.** Browsers send reports with no
  login. It refuses bodies over 16 KB, takes at most 10 reports per request,
  adds at most 50 new rows an hour and 500 in all, and counts everything it
  refuses. A known row always keeps counting, so junk cannot push a real row
  out. Because anyone can send a report, a site seen once is not evidence that
  it belongs in the policy.
- **While it is switched on**, the plugin has a database table, a daily
  WP-Cron clean-up, and that REST route. A site that never switches it on has
  none of them.
- If Perfmatters' **Disable REST API** setting is on, the report address is
  added to its exceptions while collection runs.
- On a host with a page cache, purge it after changing the setting. Cached
  pages keep the headers they were stored with.

## Hardening

Four switches, none of which write to a file. Logged-in users see no change.

| Setting | Default | What it does |
|---|---|---|
| Hide usernames from logged-out visitors | On | Closes the REST API users routes, the `?author=1` lookup, the users list in WordPress's own sitemap, and the author name in oEmbed data. The rest of the REST API keeps working, so features that load content for visitors are unaffected. |
| One login error for every mistake | On | A failed login always reads "The username, email address or password is incorrect". The lost-password form on `wp-login.php` shows the same "check your email" screen whether the account exists or not, and sends nothing to an address with no account. Error codes are kept for lockout and logging plugins. |
| Switch off the file editor | On | Refuses the same three capabilities `DISALLOW_FILE_EDIT` does, without editing `wp-config.php`. Updates are unaffected. |
| Send author pages to the home page | Off | For sites that do not use author archives. Off by default because some do. |

Not here on purpose, because Biscuit's sites already do them elsewhere and two
things doing one job cannot be told apart: XML-RPC and the version tag
(Perfmatters), two-factor (WP 2FA).

## What it deliberately does not do

**No `.htaccess` or `wp-config.php` edits.** Nothing is written to disk. The
plugin sets headers from PHP and that is all, so deactivating it removes every
trace of it from a response immediately, and there is no file left behind on a
server it was never meant to touch.

**No `X-XSS-Protection` and no `Expect-CT`.** Both are dead. `X-XSS-Protection`
was removed from Chrome and Edge, and the filter it switched on was itself an
attack vector; the correct modern value is `0`, which is the same as not sending
it. `Expect-CT` was deprecated in 2021 and removed. Plugins still offering these
are offering a green tick, not a defence. The check screen reports them if
something else on the site is sending them, so you can go and turn that off.

**No HSTS `includeSubDomains`, and no `preload`.** Not as a default, as a
capability. There is no setting for either and the code cannot assemble the
tokens. `includeSubDomains` takes down any subdomain still served over plain
HTTP; `preload` puts the domain on a list compiled into the browsers themselves,
which takes months and a browser release to leave. Neither belongs behind a
checkbox on a site you manage for somebody else.

**Nothing in wp-admin that WordPress already does.** Core sends
`X-Frame-Options`, `Referrer-Policy` and a `frame-ancestors` policy on admin and
login screens. The plugin stays out of the way for those three and sends only
what core leaves out. In particular it never sends your site's CSP inside
wp-admin, because PHP replaces headers rather than merging them, and doing so
would quietly delete core's protection against the dashboard being framed.

## HSTS, and why it starts at five minutes

HSTS is a note the site hands a visitor's browser saying "only ever talk to me
over the secure connection, and remember that". The browser obeys for as long as
the note says, and **nothing can reach back and tell it to forget sooner.** If
the certificate later breaks, those visitors get a hard wall with no way past.

Your host's "Force HTTPS" setting is a different thing. That is a redirect, run
on the server, for everybody, every time. HSTS sits on top of it and closes the
one gap a redirect cannot: the very first request, which still leaves the
visitor's device before the redirect comes back.

So the duration dropdown starts at five minutes. Switch it on, check the site,
come back and lengthen it. Only a duration you have already lived with is safe
to keep.

## Seeing what is actually being sent

Once several things can set a header, you cannot tell from a response which one
did. The **Check what this site sends** button fetches two URLs and shows them
side by side:

- **A stylesheet**, which the web server hands over without ever starting
  WordPress. Anything on that response came from your host.
- **The home page**, which is what a visitor receives.

Anything in the first column is your host's, and applies to every file it
serves. Anything that appears only in the second column is set by WordPress:
this plugin, the theme, or another plugin. Where the two differ, WordPress is
replacing your host's value.

That difference is also the plugin's main limit, made visible. **A header set
from PHP reaches HTML pages and nothing else.** Your scripts, stylesheets and
images are served by the web server directly and carry only what the server
puts on them. Where you can configure headers at the server, that is strictly
better. This plugin is the portable version that behaves the same everywhere.

## Requirements

- WordPress 6.3 or later
- PHP 8.2 or later

## Installation

Download the zip from
[Releases](https://github.com/biscuitstudios/bs-security/releases), then
**Plugins → Add New → Upload Plugin**. Settings live under **Settings → Security**.

**Replacing Biscuit Security Headers:** activate this plugin first. On its first
activation it copies the old plugin's header settings. Then deactivate and delete
Biscuit Security Headers. The other order loses the settings, because the old
plugin's uninstall deletes them.

## Uninstalling

Deactivating stops every header immediately, because the hooks stop firing.
Deleting the plugin removes its settings, and on a site that used CSP
report-only, its reports table, its scheduled clean-up and its two options.
Nothing was written to a file, so there is nothing else to clean up.

## Support

None, in the usual sense. This is published as-is, and we make changes when our
own client work calls for them.

You are welcome to fork it. If you find a genuine security problem, please
report it privately using the **Security** tab on this repository rather than
opening it in public.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
