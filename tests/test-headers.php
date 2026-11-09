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

function build( array $settings, bool $https = true, string $context = Bssec_Headers::CONTEXT_FRONTEND ): array {
    return Bssec_Headers::build( $settings, $https, $context );
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
