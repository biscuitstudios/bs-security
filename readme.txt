=== Biscuit Security ===
Contributors: biscuitstudios
Tags: security, security headers, hardening, user enumeration, login
Requires at least: 6.3
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 0.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Biscuit's site security in one plugin: the response headers managed hosts leave off, plus hiding usernames, one generic login error, and no file editor.

== Description ==

See the README on GitHub for the full description, requirements, and known
limitations: https://github.com/biscuitstudios/bs-security

Built and maintained by Biscuit Studios for our own client sites. Published
as-is, with no support. Forks welcome.

== Installation ==

1. Download the zip from the Releases page on GitHub.
2. Plugins > Add New > Upload Plugin.
3. Activate. The three safe headers start sending and three hardening settings switch on straight away.

Replacing Biscuit Security Headers: activate this plugin first, so it copies the
old header settings, then deactivate and delete Biscuit Security Headers.

== Changelog ==

= 0.4.0 =
* New: the collected CSP reports are listed on the settings screen: one row
  per directive and blocked source, with how many reports, when it was first
  and last seen, and a sample page. Most reported first. A source reported
  only once is greyed, because anyone can send a report. The list stays
  after collection is switched off or ends.
* New: "Send a test report". Sends one report the way a visitor's browser
  does, with no login, and says whether it got through and was stored, or
  what stopped it: collection off, a REST API lockdown, or a firewall.
* New: "Clear reports" deletes every collected report and restarts the
  refused counts.
* New: a warning if the daily clean-up of old reports stops running.
* Change: update offers now carry "Tested up to" and a one-line upgrade
  notice that says whether the release changes the headers this plugin
  sends. Both were empty before, so an update report could see that the
  version changed but not what changed. Starts with this release.
* Change: the Settings menu entry and the screen's heading are now
  "Biscuit Security", not "Security", so they cannot be mistaken for another
  plugin's.
* Fix: update-check failures are logged as [BSSEC], this plugin's tag. They
  were logged as [BSM], so searching a PHP log for [BSSEC] missed them.

= 0.3.2 =
* Fix: CSP reports from Safari were all refused as unreadable. Safari sends
  each report on its own, labeled as the older report format but written in
  the newer one. Reports are now read by their shape rather than their label,
  so the older format, a newer-format list (Chrome) and a single newer-format
  report (Safari) are all accepted.
* Fix: Safari writes the default port into addresses (https://example.com:443)
  where Chrome does not. Default ports are now dropped, so one site is one
  source whichever browser reported it.

= 0.3.1 =
* Fix: CSP reports from Chrome were mostly refused. Chrome bundles every
  report from about the last minute into one request, and 0.3.0 kept only the
  first ten reports of a request and refused the rest. Repeats are now folded
  together first, so forty reports of the same blocked image are one row with
  a count of forty, and the limit applies to ten different sources per
  request rather than ten reports.
* Fix: a request can now be up to 256 KB, up from 16 KB. Every report repeats
  the whole policy, so with a real policy 16 KB held only about a dozen
  reports and a bigger bundle was refused whole. At most 200 reports are read
  from one request; any beyond that are refused and counted.
* Change: the status line now says why reports were refused, largest count
  first, for example "8 refused: 6 over the per-request limits, 1 from
  another site, 1 too large". Refusals counted by 0.3.0 show their reasons
  too.

= 0.3.0 =
* New: CSP report-only. A second policy, separate from the enforced one, that
  blocks nothing. Each visitor's browser checks pages against it and reports
  what it would have blocked, so a real policy can be written from what a site
  actually loads before anything is enforced. Off by default. Under
  Settings > Security, "CSP report-only".
* New: reports are folded into one row per directive and blocked site, with a
  count and the time of the last report. Only the blocked site's address and
  the page's path are kept. Query strings and fragments are never stored, and
  order numbers in WooCommerce paths are replaced with {n}.
* New: collection ends on its own, 30 days after it is switched on unless a
  later date is set. After that the header stops and the report address
  closes.
* Note: while report-only is switched on, the plugin has its first database
  table (wp_bssec_csp_reports, capped at 500 rows, with rows not reported for
  30 days removed daily), its first scheduled task (that daily clean-up, on
  WP-Cron), and a public address browsers send reports to,
  /wp-json/bssec/v1/csp-report, with limits on size, batch and new rows per
  hour. None of the three exists on a site that never switches it on.
  Deleting the plugin removes all three.
* Note: this policy also reaches the WooCommerce Checkout and My Account
  pages, where WooCommerce replaces the enforced Content-Security-Policy with
  its own one-line policy.
* Note: if Perfmatters' "Disable REST API" setting is on, the report address
  is added to its exceptions while collection runs, or every report would be
  refused.
* Note: on Kinsta, purge the site cache after changing these settings. Cached
  pages keep the headers they were stored with.

= 0.2.0 =
* Change: this is Biscuit Security Headers under a new name, folder and
  repository: Biscuit Security, bs-security. It now covers site hardening as
  well as headers, so the old name no longer described it. WordPress sees it
  as a different plugin, so it does not update in place. Activate this one
  first, which copies the old plugin's header settings across, then deactivate
  and delete Biscuit Security Headers.
* New: hide usernames from logged-out visitors. Closes the REST API users
  routes, the ?author=1 lookup, the users list in WordPress's own sitemap, and
  the author name in oEmbed data. The rest of the REST API keeps working. On by
  default.
* New: one login error for every mistake, and the lost-password form shows the
  same "check your email" screen whether the account exists or not. Error codes
  are kept, so lockout and logging plugins still see what happened. On by
  default.
* New: switch off the theme and plugin file editor, the same three capabilities
  DISALLOW_FILE_EDIT removes, without editing wp-config.php. Plugin updates are
  not affected. On by default.
* New: optional redirect of author pages to the home page for logged-out
  visitors. Off by default, because some sites use author pages on purpose.
* Change: the settings screen moves to Settings > Security.

= 0.1.3 =
* Change: the plugin is now listed as "Biscuit Security Headers" on the Plugins screen,
  so Biscuit's own plugins sort together. It was "Security Headers". Nothing else
  changed. The Settings menu still reads "Security Headers", and every setting
  carries over.

= 0.1.2 =
* Security hardening: the updater now pins its download URL to this plugin's
  own GitHub repository. find_zip_asset() used to hand the WordPress upgrader
  whatever browser_download_url the GitHub API returned, and that URL becomes
  code the upgrader installs. Not a reachable bug, because GitHub only ever
  returns repo-hosted asset URLs, but it is the one path where a wrong
  assumption about a response would be arbitrary code. The fallback branch is
  pinned too, because it was a second way in.
* sslverify is now explicit on the GitHub API call. WordPress defaults it to
  true, so nothing changes today, but a filter on a site could flip it and
  nothing here would notice.

= 0.1.1 =
* Fix: the check screen now says plainly when it has been run against a local
  development site. Local serves none of these headers, so every one reads as
  missing there even where the live host sends it, and the screen presented that
  as an authoritative reading of what "your server" does.
* Change: the X-Content-Type-Options help no longer says to switch it on if the
  check shows the header missing. That is only sound advice when the check was
  run against the live site, and it now says so.

= 0.1.0 =
* New: sends Referrer-Policy, Permissions-Policy and X-Frame-Options from the
  moment the plugin is activated, with no configuration. None of the three can
  break a normal site, so installing the plugin is the whole rollout.
* New: optional Strict-Transport-Security, with a duration that starts at five
  minutes so it can be switched on and checked before it is lengthened. There is
  no setting for includeSubDomains or preload, and the code cannot assemble
  either token. Both are effectively permanent once a browser has seen them.
* New: optional Content-Security-Policy, off by default, entered per site. There
  is no fleet-wide default because a policy has to be written against what a
  particular site actually loads.
* New: optional X-Content-Type-Options, off by default because Kinsta and xCloud
  already send it. Included so the plugin still does the right thing if a site
  moves to a host that does not.
* New: a check that fetches a static file and the home page and reports the
  headers side by side. The static file never starts WordPress, so anything on
  it came from the server, which is what separates "the host does this" from
  "we do this".
* Note: the plugin stays out of WordPress's way in wp-admin and on the login
  screen, where core already sends X-Frame-Options, Referrer-Policy and a
  frame-ancestors policy. The site's own CSP is never sent there, because PHP
  replaces headers rather than merging them and doing so would delete core's
  protection against the dashboard being framed.
* Note: X-XSS-Protection and Expect-CT are not implemented. Both are dead, and
  the filter the first one enabled was itself an attack vector. The check screen
  reports them if something else on the site is still sending them.

== Upgrade Notice ==

= 0.4.0 =
Headers: unchanged. Adds a list of collected CSP reports, a test report button and Clear reports to Settings > Biscuit Security. Nothing changes on a site that has never switched CSP report-only on.
