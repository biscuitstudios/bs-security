<?php
/**
 * Smoke tests for Bssec_Headers::build(), the one function in this plugin with
 * real failure potential.
 *
 * What is being pinned down:
 *
 *   - which headers go out in which context. Sending the site's CSP inside
 *     wp-admin would silently delete core's frame-ancestors protection, and
 *     nothing about the resulting page would look wrong.
 *   - that HSTS never grows includeSubDomains or preload. That is a promise
 *     made to Jason on September 20, 2026, and a promise in a comment is worth
 *     less than one a test enforces.
 *   - that a header value cannot carry a newline, however it reached the
 *     option.
 *
 * Plain PHP rather than PHPUnit so this runs with no composer install, matching
 * the other Biscuit plugins. Run:
 *
 *   php tests/test-headers.php
 */

define( 'ABSPATH', '/fake/' );

// --- WP stubs: only what the code under test actually touches ---------------

function __( $text, $domain = '' ) { return $text; }

$GLOBALS['is_ssl'] = false;
function is_ssl() { return (bool) $GLOBALS['is_ssl']; }

require_once __DIR__ . '/../includes/class-bssec-plugin.php';
require_once __DIR__ . '/../includes/class-bssec-headers.php';

// --- harness ---------------------------------------------------------------

$fails = 0;
$ran   = 0;

function it( string $label, bool $ok ): void {
    global $fails, $ran;
    $ran++;
    if ( ! $ok ) $fails++;
    printf( "%-6s %s\n", $ok ? '  ok' : 'FAIL', $label );
}

/** Settings with everything switched on, so a context test has something to hide. */
function all_on( array $overrides = [] ): array {
    return array_merge( Bssec_Plugin::defaults(), [
        'hsts'                 => true,
        'hsts_max_age'         => 31536000,
        'content_type_options' => true,
        'csp'                  => true,
        'csp_value'            => "default-src 'self'",
    ], $overrides );
}

function build( array $settings, bool $https = true, string $context = Bssec_Headers::CONTEXT_FRONTEND, string $report_url = '' ): array {
    return Bssec_Headers::build( $settings, $https, $context, $report_url );
}

// --- the out-of-the-box set ------------------------------------------------

echo "\n== defaults ==\n";
$d = build( Bssec_Plugin::defaults() );

it( 'three headers on a fresh install', 3 === count( $d ) );
it( 'Referrer-Policy is on',    isset( $d['Referrer-Policy'] ) );
it( 'Permissions-Policy is on', isset( $d['Permissions-Policy'] ) );
it( 'X-Frame-Options is on',    isset( $d['X-Frame-Options'] ) );
it( 'HSTS is off',              ! isset( $d['Strict-Transport-Security'] ) );
it( 'CSP is off',               ! isset( $d['Content-Security-Policy'] ) );
it( 'X-Content-Type-Options is off, the hosts already send it',
    ! isset( $d['X-Content-Type-Options'] ) );
it( 'the default Referrer-Policy is the modern one',
    'strict-origin-when-cross-origin' === $d['Referrer-Policy'] );
it( 'the default frame policy is SAMEORIGIN',
    'SAMEORIGIN' === $d['X-Frame-Options'] );
it( 'the default Permissions-Policy blocks exactly the five agreed features',
    'camera=(), microphone=(), accelerometer=(), gyroscope=(), magnetometer=()' === $d['Permissions-Policy'] );
it( 'payment is NOT blocked by default — it is how Apple Pay works',
    false === strpos( $d['Permissions-Policy'], 'payment' ) );
it( 'fullscreen is NOT blocked by default',
    false === strpos( $d['Permissions-Policy'], 'fullscreen' ) );

// --- HSTS: the promise that cannot be broken -------------------------------

echo "\n== HSTS never grows a subdomain or preload directive ==\n";
foreach ( Bssec_Plugin::HSTS_MAX_AGES as $max_age ) {
    $h = build( all_on( [ 'hsts_max_age' => $max_age ] ) );
    it( "max-age $max_age emits exactly 'max-age=$max_age'",
        ( $h['Strict-Transport-Security'] ?? '' ) === 'max-age=' . $max_age );
}

$src = file_get_contents( __DIR__ . '/../includes/class-bssec-headers.php' );
$emitted = preg_match( "/'Strict-Transport-Security'\]\s*=\s*'max-age=' \. \\\$max_age;/", $src );
it( 'the emitter builds the value from max_age alone', 1 === $emitted );

/**
 * Every string literal in a file, comments excluded.
 *
 * Searching the raw source would match the comment that explains why these two
 * directives are absent, which is how this check first passed by failing. What
 * matters is whether a token can reach an emitted value, so look only at the
 * strings the code can actually build from.
 *
 * @return string[]
 */
function string_literals( string $php ): array {
    $out = [];
    foreach ( token_get_all( $php ) as $token ) {
        if ( ! is_array( $token ) ) continue;
        if ( in_array( $token[0], [ T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_INLINE_HTML ], true ) ) {
            $out[] = $token[1];
        }
    }
    return $out;
}

$literals = implode( "\n", string_literals( $src ) );
it( 'no includeSubDomains token appears in any string the emitter can build',
    false === stripos( $literals, 'includeSubDomains' ) );
it( 'no preload token appears in any string the emitter can build',
    false === stripos( $literals, 'preload' ) );
it( 'the scan itself works — it finds a token that IS there',
    false !== stripos( $literals, 'max-age=' ) );

echo "\n== HSTS only over a secure connection ==\n";
it( 'absent over plain HTTP',
    ! isset( build( all_on(), false )['Strict-Transport-Security'] ) );
it( 'present over HTTPS',
    isset( build( all_on(), true )['Strict-Transport-Security'] ) );
it( 'absent when the duration is zero',
    ! isset( build( all_on( [ 'hsts_max_age' => 0 ] ) )['Strict-Transport-Security'] ) );

// --- context rules ---------------------------------------------------------

echo "\n== wp-admin and wp-login.php ==\n";
$a = build( all_on(), true, Bssec_Headers::CONTEXT_ADMIN );

it( 'the CSP is NEVER sent in admin — it would delete core frame-ancestors',
    ! isset( $a['Content-Security-Policy'] ) );
it( 'X-Frame-Options is left to core in admin',
    ! isset( $a['X-Frame-Options'] ) );
it( 'Referrer-Policy is left to core in admin',
    ! isset( $a['Referrer-Policy'] ) );
it( 'Permissions-Policy IS sent in admin — core sends none',
    isset( $a['Permissions-Policy'] ) );
it( 'HSTS IS sent in admin — the login screen wants it most',
    isset( $a['Strict-Transport-Security'] ) );
it( 'X-Content-Type-Options IS sent in admin when switched on',
    isset( $a['X-Content-Type-Options'] ) );

echo "\n== the Customizer preview iframe ==\n";
$p = build( all_on(), true, Bssec_Headers::CONTEXT_PREVIEW );

it( 'X-Frame-Options is dropped, or the preview panel is blank',
    ! isset( $p['X-Frame-Options'] ) );
it( 'the CSP is dropped for the same reason',
    ! isset( $p['Content-Security-Policy'] ) );
it( 'Referrer-Policy survives — it cannot break a frame',
    isset( $p['Referrer-Policy'] ) );
it( 'Permissions-Policy survives', isset( $p['Permissions-Policy'] ) );
it( 'HSTS survives',               isset( $p['Strict-Transport-Security'] ) );

// --- header injection ------------------------------------------------------
//
// These bypass sanitize() on purpose. The option could have been written by a
// database restore, a migration, or wp-cli, and the emitter is the last line.

echo "\n== a value carrying a newline cannot split the response ==\n";
$evil = build( all_on( [
    'csp_value' => "default-src 'self'\r\nSet-Cookie: admin=1",
] ) );
it( 'CR and LF are stripped at emit time',
    false === strpos( $evil['Content-Security-Policy'], "\r" )
    && false === strpos( $evil['Content-Security-Policy'], "\n" ) );
it( 'the injected header name is left inert on one line',
    'default-src \'self\'Set-Cookie: admin=1' === $evil['Content-Security-Policy'] );

$nul = build( all_on( [ 'csp_value' => "default-src 'self'\0evil" ] ) );
it( 'NUL is stripped too',
    false === strpos( $nul['Content-Security-Policy'], "\0" ) );

// --- values that are not on the list ---------------------------------------

echo "\n== unknown values are dropped, not emitted ==\n";
it( 'a Referrer-Policy value off the list is not sent',
    ! isset( build( all_on( [ 'referrer_policy_value' => 'unsafe-url' ] ) )['Referrer-Policy'] ) );
it( 'an X-Frame-Options value off the list is not sent',
    ! isset( build( all_on( [ 'frame_options_value' => 'ALLOW-FROM https://evil.test' ] ) )['X-Frame-Options'] ) );
it( 'a lowercase frame value is accepted and normalized',
    'SAMEORIGIN' === build( all_on( [ 'frame_options_value' => 'sameorigin' ] ) )['X-Frame-Options'] );
it( 'an empty CSP sends no header even when switched on',
    ! isset( build( all_on( [ 'csp_value' => '   ' ] ) )['Content-Security-Policy'] ) );

// --- Permissions-Policy assembly -------------------------------------------

echo "\n== Permissions-Policy value ==\n";
it( 'an empty block list sends no header at all',
    ! isset( build( all_on( [ 'permissions_policy_block' => [] ] ) )['Permissions-Policy'] ) );
it( 'an unknown feature token is dropped',
    'camera=()' === Bssec_Headers::permissions_policy_value( [ 'camera', 'not-a-feature' ] ) );
it( 'a duplicate feature appears once',
    'camera=()' === Bssec_Headers::permissions_policy_value( [ 'camera', 'camera' ] ) );
it( 'a token carrying a newline is dropped rather than cleaned into validity',
    '' === Bssec_Headers::permissions_policy_value( [ "camera\r\nX-Evil: 1" ] ) );
it( 'each feature gets an empty allowlist',
    'camera=(), payment=()' === Bssec_Headers::permissions_policy_value( [ 'camera', 'payment' ] ) );
it( 'every offered feature is a legal token',
    count( Bssec_Plugin::POLICY_FEATURES ) === count( array_filter(
        Bssec_Plugin::POLICY_FEATURES,
        fn( $f ) => (bool) preg_match( '/^[a-z][a-z0-9-]*$/', $f )
    ) ) );
it( 'every default-blocked feature is one the UI offers',
    [] === array_diff( Bssec_Plugin::POLICY_FEATURES_DEFAULT, Bssec_Plugin::POLICY_FEATURES ) );
it( 'every risky feature is one the UI offers',
    [] === array_diff( array_keys( Bssec_Plugin::risky_features() ), Bssec_Plugin::POLICY_FEATURES ) );
it( 'no dead directive is offered',
    ! in_array( 'interest-cohort', Bssec_Plugin::POLICY_FEATURES, true ) );

// --- CSP report-only -------------------------------------------------------
//
// What is pinned: the candidate goes out only on the front end and only when
// the caller hands over a report address; it never replaces or alters the
// enforced policy; a reporting directive pasted into the candidate cannot
// redirect this site's reports; and the address cannot break either header.

const REPORT_URL = 'https://biscuit.test/wp-json/bssec/v1/csp-report';

function report_only( array $overrides = [] ): array {
    return all_on( array_merge( [
        'csp_report_only'       => true,
        'csp_report_only_value' => "default-src 'self'; img-src 'self'",
        'csp_report_only_until' => '2026-12-09',
    ], $overrides ) );
}

echo "\n== report-only: what goes out ==\n";
$r = build( report_only(), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL );
it( 'off out of the box',
    ! isset( $d['Content-Security-Policy-Report-Only'] ) && ! isset( $d['Reporting-Endpoints'] ) );
it( 'the candidate goes out with both reporting directives appended',
    "default-src 'self'; img-src 'self'; report-uri " . REPORT_URL . '; report-to bssec'
    === ( $r['Content-Security-Policy-Report-Only'] ?? '' ) );
it( 'Reporting-Endpoints names the same group and address',
    'bssec="' . REPORT_URL . '"' === ( $r['Reporting-Endpoints'] ?? '' ) );
it( 'the enforced CSP still goes out, unchanged, beside it',
    "default-src 'self'" === ( $r['Content-Security-Policy'] ?? '' ) );
it( 'report-only does not need the enforced CSP switched on',
    isset( build( report_only( [ 'csp' => false ] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL )['Content-Security-Policy-Report-Only'] ) );
it( 'and switching it on adds nothing to the enforced CSP',
    false === strpos( $r['Content-Security-Policy'], 'report' ) );

echo "\n== report-only: when it stays off ==\n";
it( 'no report address from the caller means no header (collection ended)',
    ! isset( build( report_only(), true )['Content-Security-Policy-Report-Only'] ) );
it( 'and no Reporting-Endpoints either',
    ! isset( build( report_only(), true )['Reporting-Endpoints'] ) );
it( 'switched off, an address alone sends nothing',
    ! isset( build( report_only( [ 'csp_report_only' => false ] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL )['Content-Security-Policy-Report-Only'] ) );
it( 'an empty candidate sends nothing',
    ! isset( build( report_only( [ 'csp_report_only_value' => '  ' ] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL )['Content-Security-Policy-Report-Only'] ) );
it( 'a candidate that was only reporting directives sends nothing',
    ! isset( build( report_only( [ 'csp_report_only_value' => 'report-uri https://x.test/; report-to x' ] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL )['Content-Security-Policy-Report-Only'] ) );
it( 'plain HTTP does not stop it (unlike HSTS)',
    isset( build( report_only(), false, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL )['Content-Security-Policy-Report-Only'] ) );

echo "\n== report-only: context rules ==\n";
$ra = build( report_only(), true, Bssec_Headers::CONTEXT_ADMIN, REPORT_URL );
it( 'NEVER in admin, even handed an address',
    ! isset( $ra['Content-Security-Policy-Report-Only'] ) && ! isset( $ra['Reporting-Endpoints'] ) );
$rp = build( report_only(), true, Bssec_Headers::CONTEXT_PREVIEW, REPORT_URL );
it( 'never in the Customizer preview',
    ! isset( $rp['Content-Security-Policy-Report-Only'] ) && ! isset( $rp['Reporting-Endpoints'] ) );

echo "\n== report-only: a pasted reporting directive cannot redirect reports ==\n";
$hijack = build( report_only( [
    'csp_report_only_value' => "default-src 'self'; report-uri https://evil.test/r; REPORT-TO evil; img-src 'self'",
] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL );
it( 'the pasted address is gone',
    false === strpos( $hijack['Content-Security-Policy-Report-Only'], 'evil' ) );
it( 'exactly one report-uri and one report-to remain, ours',
    1 === substr_count( $hijack['Content-Security-Policy-Report-Only'], 'report-uri' )
    && 1 === substr_count( strtolower( $hijack['Content-Security-Policy-Report-Only'] ), 'report-to' ) );
it( 'the directives around it survive in order',
    0 === strpos( $hijack['Content-Security-Policy-Report-Only'], "default-src 'self'; img-src 'self'; report-uri " ) );

it( 'strip: uppercase directive names go',
    "a b" === Bssec_Headers::strip_reporting_directives( "a b; REPORT-URI https://x.test" ) );
it( 'strip: doubled and trailing semicolons collapse',
    "a; b" === Bssec_Headers::strip_reporting_directives( "a;; b ;" ) );
it( 'strip: a directive merely starting with the name is kept',
    "report-urix y" === Bssec_Headers::strip_reporting_directives( "report-urix y" ) );
it( 'strip: a policy with no reporting directive is only normalized',
    "default-src 'self'; img-src data:" === Bssec_Headers::strip_reporting_directives( "default-src 'self';img-src data:" ) );

echo "\n== report-only: neither header can be split or broken ==\n";
$rinj = build( report_only( [
    'csp_report_only_value' => "default-src 'self'\r\nSet-Cookie: admin=1",
] ), true, Bssec_Headers::CONTEXT_FRONTEND, REPORT_URL );
it( 'CR and LF are stripped from the candidate at emit time',
    ! preg_match( '/[\r\n\0]/', $rinj['Content-Security-Policy-Report-Only'] ) );

foreach ( [
    'a quote'          => 'https://x.test/r"; evil="https://evil.test',
    'a newline'        => "https://x.test/r\r\nX-Evil: 1",
    'a space'          => 'https://x.test/r evil',
    'a semicolon'      => 'https://x.test/r;script-src *',
    'a comma'          => 'https://x.test/r,evil="https://evil.test"',
    'no scheme'        => '//x.test/r',
    'a javascript URL' => 'javascript:alert(1)',
] as $what => $bad ) {
    $h = build( report_only(), true, Bssec_Headers::CONTEXT_FRONTEND, $bad );
    it( "an address carrying $what sends neither header",
        ! isset( $h['Content-Security-Policy-Report-Only'] ) && ! isset( $h['Reporting-Endpoints'] ) );
}
it( 'an address with a quote is refused outright',
    '' === Bssec_Headers::clean_report_url( 'https://x.test/r"' ) );
it( 'an address with a space is refused outright',
    '' === Bssec_Headers::clean_report_url( 'https://x.test/a b' ) );
it( 'a plain-permalink REST address is accepted',
    'https://x.test/?rest_route=/bssec/v1/csp-report'
    === Bssec_Headers::clean_report_url( 'https://x.test/?rest_route=/bssec/v1/csp-report' ) );
it( 'an ordinary REST address is accepted', REPORT_URL === Bssec_Headers::clean_report_url( REPORT_URL ) );

echo "\n== report-only: is collection running today? ==\n";
$tz  = new DateTimeZone( 'America/New_York' );
$day = fn( string $ymd ) => new DateTimeImmutable( $ymd . ' 12:00:00', $tz );
$on  = report_only( [ 'csp_report_only_until' => '2026-12-09' ] );
it( 'before the end date: running',  Bssec_Plugin::report_only_active( $on, $day( '2026-11-09' ) ) );
it( 'on the end date: still running, the date is inclusive',
    Bssec_Plugin::report_only_active( $on, $day( '2026-12-09' ) ) );
it( 'the day after: ended',          ! Bssec_Plugin::report_only_active( $on, $day( '2026-12-10' ) ) );
it( 'late on the end date, site time: still running',
    Bssec_Plugin::report_only_active( $on, new DateTimeImmutable( '2026-12-09 23:59:00', $tz ) ) );
it( 'switched off: not running',     ! Bssec_Plugin::report_only_active( report_only( [ 'csp_report_only' => false ] ), $day( '2026-11-09' ) ) );
it( 'empty candidate: not running',  ! Bssec_Plugin::report_only_active( report_only( [ 'csp_report_only_value' => ' ' ] ), $day( '2026-11-09' ) ) );
it( 'no end date: not running, fails toward off',
    ! Bssec_Plugin::report_only_active( report_only( [ 'csp_report_only_until' => '' ] ), $day( '2026-11-09' ) ) );
it( 'an impossible end date: not running',
    ! Bssec_Plugin::report_only_active( report_only( [ 'csp_report_only_until' => '2026-02-31' ] ), $day( '2026-01-09' ) ) );
it( 'a malformed end date: not running',
    ! Bssec_Plugin::report_only_active( report_only( [ 'csp_report_only_until' => '12/09/2026' ] ), $day( '2026-11-09' ) ) );

echo "\n== headers are sent from one place, never on template_redirect ==\n";
// WooCommerce swaps the enforced CSP on template_redirect. What the plugin sends
// there today is decided: nothing but the hardening's redirects. Enforcing on
// Checkout is an open question, so a header sent on that hook, or a second
// place calling header(), should fail here and start that conversation rather
// than arrive quietly.
//
// The first version of this check asserted no template_redirect anywhere in
// the plugin, and failed on the hardening's author redirects, which are
// legitimately there. That was the premise being wrong, not the code.

/** Files that call PHP's header() as a function, not a method or a comment. */
function files_calling_header( array $files ): array {
    $hits = [];
    foreach ( $files as $file ) {
        $tokens = array_values( array_filter(
            token_get_all( file_get_contents( $file ) ),
            fn( $t ) => ! is_array( $t ) || ! in_array( $t[0], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true )
        ) );
        foreach ( $tokens as $i => $t ) {
            if ( ! is_array( $t ) || T_STRING !== $t[0] || 'header' !== strtolower( $t[1] ) ) continue;
            $next = $tokens[ $i + 1 ] ?? null;
            $prev = $tokens[ $i - 1 ] ?? null;
            if ( '(' !== $next ) continue;
            if ( is_array( $prev ) && in_array( $prev[0], [ T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NULLSAFE_OBJECT_OPERATOR ], true ) ) continue;
            $hits[] = basename( $file );
        }
    }
    return array_values( array_unique( $hits ) );
}

$plugin_root = dirname( __DIR__ );
$php_files   = array_merge(
    [ $plugin_root . '/bs-security.php', $plugin_root . '/uninstall.php' ],
    glob( $plugin_root . '/includes/*.php' ),
    glob( $plugin_root . '/admin/*.php' ),
    glob( $plugin_root . '/admin/views/*.php' )
);
it( 'the scan covered the whole plugin', count( $php_files ) > 8 );
it( 'only the emitter calls header()',
    [ 'class-bssec-headers.php' ] === files_calling_header( $php_files ) );
it( 'the header() scan works: it finds a call planted in a scratch file',
    ( function () {
        $tmp = tempnam( sys_get_temp_dir(), 'bssec' );
        file_put_contents( $tmp, "<?php\n// header( 'no' );\n\$o->header( 'no' );\nheader( 'X-Planted: 1' );\n" );
        $found = files_calling_header( [ $tmp ] );
        unlink( $tmp );
        return [ basename( $tmp ) ] === $found;
    } )() );

$emitter_literals = implode( "\n", string_literals( $src ) );
it( 'the emitter hooks nothing on template_redirect',
    false === strpos( $emitter_literals, 'template_redirect' ) );
it( 'the scan works: it finds send_headers, which the emitter does hook',
    false !== strpos( $emitter_literals, 'send_headers' ) );

// --- is_https --------------------------------------------------------------

echo "\n== is_https() behind an edge that terminates TLS ==\n";
$GLOBALS['is_ssl'] = false;
unset( $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_PORT'] );
it( 'plain HTTP with no forwarding headers is not HTTPS', ! Bssec_Headers::is_https() );

$GLOBALS['is_ssl'] = true;
it( 'is_ssl() alone is enough', Bssec_Headers::is_https() );

$GLOBALS['is_ssl'] = false;
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
it( 'X-Forwarded-Proto: https is honoured — without this HSTS never ships on Kinsta',
    Bssec_Headers::is_https() );

$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https, http';
it( 'only the first hop of a chained X-Forwarded-Proto is read',
    Bssec_Headers::is_https() );

$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http';
it( 'X-Forwarded-Proto: http is not HTTPS', ! Bssec_Headers::is_https() );

unset( $_SERVER['HTTP_X_FORWARDED_PROTO'] );
$_SERVER['HTTP_X_FORWARDED_PORT'] = '443';
it( 'a load balancer reporting port 443 counts', Bssec_Headers::is_https() );

$_SERVER['HTTP_X_FORWARDED_PORT'] = '80';
it( 'port 80 does not', ! Bssec_Headers::is_https() );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
