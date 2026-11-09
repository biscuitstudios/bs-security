<?php
/**
 * Smoke tests for the input side: Bssec_Plugin::sanitize(), sanitize_csp() and
 * clean_header_value().
 *
 * The emitter has its own tests. These cover the other half of the same
 * promise: that nothing reaches the option which the emitter would then have
 * to defend against. Both layers are tested because both exist on purpose —
 * see the note in clean_header_value().
 *
 * Plain PHP rather than PHPUnit so this runs with no composer install. Run:
 *
 *   php tests/test-sanitize.php
 */

define( 'ABSPATH', '/fake/' );

function __( $text, $domain = '' ) { return $text; }
function is_ssl() { return true; }

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

function clean( array $raw ): array {
    return Bssec_Plugin::sanitize( $raw );
}

// --- an empty POST ---------------------------------------------------------
//
// This is what an unchecked checkbox looks like: absent, not false. A settings
// form that posts nothing must switch everything off rather than silently keep
// the previous state.

echo "\n== an empty POST switches everything off ==\n";
$empty = clean( [] );

foreach ( array_merge( [ 'referrer_policy', 'permissions_policy', 'frame_options', 'content_type_options', 'hsts', 'csp' ], Bssec_Plugin::HARDENING_KEYS ) as $key ) {
    it( "$key is off", false === $empty[ $key ] );
}
it( 'the block list is emptied too', [] === $empty['permissions_policy_block'] );
it( 'and that produces no headers at all',
    [] === Bssec_Headers::build( $empty, true ) );

// --- values that are not on the list ---------------------------------------

echo "\n== a value off the list falls back to the default ==\n";
it( 'an invented Referrer-Policy is refused',
    'strict-origin-when-cross-origin' === clean( [ 'referrer_policy_value' => 'unsafe-url' ] )['referrer_policy_value'] );
it( 'a legitimate one is kept',
    'no-referrer' === clean( [ 'referrer_policy_value' => 'no-referrer' ] )['referrer_policy_value'] );

it( 'the removed ALLOW-FROM frame syntax is refused',
    'SAMEORIGIN' === clean( [ 'frame_options_value' => 'ALLOW-FROM https://evil.test' ] )['frame_options_value'] );
it( 'DENY is kept',
    'DENY' === clean( [ 'frame_options_value' => 'DENY' ] )['frame_options_value'] );
it( 'case and padding are normalized',
    'DENY' === clean( [ 'frame_options_value' => '  deny  ' ] )['frame_options_value'] );

it( 'an off-list HSTS duration falls back to five minutes',
    300 === clean( [ 'hsts_max_age' => 99999999 ] )['hsts_max_age'] );
it( 'a listed duration is kept',
    31536000 === clean( [ 'hsts_max_age' => '31536000' ] )['hsts_max_age'] );
it( 'a negative duration is refused',
    300 === clean( [ 'hsts_max_age' => -1 ] )['hsts_max_age'] );

// --- the Permissions-Policy block list -------------------------------------

echo "\n== the feature list is intersected, never trusted ==\n";
$features = clean( [ 'permissions_policy_block' => [ 'camera', 'not-a-feature', 'payment' ] ] )['permissions_policy_block'];
it( 'known features survive', in_array( 'camera', $features, true ) && in_array( 'payment', $features, true ) );
it( 'an invented feature is dropped', ! in_array( 'not-a-feature', $features, true ) );

it( 'a feature carrying a header separator is dropped',
    [] === clean( [ 'permissions_policy_block' => [ "camera\r\nX-Evil: 1" ] ] )['permissions_policy_block'] );
it( 'duplicates collapse',
    [ 'camera' ] === clean( [ 'permissions_policy_block' => [ 'camera', 'camera' ] ] )['permissions_policy_block'] );
it( 'a non-array block list does not fatal',
    [] === clean( [ 'permissions_policy_block' => 'camera' ] )['permissions_policy_block'] );
it( 'the stored order follows the canonical list, not the POST order',
    [ 'camera', 'payment' ] === clean( [ 'permissions_policy_block' => [ 'payment', 'camera' ] ] )['permissions_policy_block'] );
it( 'the keys are renumbered, so the option stores a list and not a map',
    array_is_list( clean( [ 'permissions_policy_block' => [ 'payment', 'camera' ] ] )['permissions_policy_block'] ) );

// --- the CSP box -----------------------------------------------------------

echo "\n== the CSP box ==\n";
it( 'a policy pasted across several lines folds into one',
    "default-src 'self'; script-src 'self'"
    === Bssec_Plugin::sanitize_csp( "default-src 'self';\nscript-src 'self'" ) );
it( 'Windows line endings fold too',
    "a b" === Bssec_Plugin::sanitize_csp( "a\r\nb" ) );
it( 'tabs fold as well',
    "a b" === Bssec_Plugin::sanitize_csp( "a\tb" ) );
it( 'runs of spaces collapse',
    "a b" === Bssec_Plugin::sanitize_csp( "a     b" ) );
it( 'angle brackets are stripped — no policy legally contains one',
    "default-src 'self' foo" === Bssec_Plugin::sanitize_csp( "default-src 'self' <foo>" ) );
it( 'no angle bracket survives a hostile paste',
    ! preg_match( '/[<>]/', Bssec_Plugin::sanitize_csp( "</script><script>alert(1)</script>" ) ) );
it( 'the quotes a policy actually needs survive',
    "default-src 'self' 'unsafe-inline'" === Bssec_Plugin::sanitize_csp( "default-src 'self' 'unsafe-inline'" ) );
it( 'a wildcard host survives',
    "img-src *.example.com data:" === Bssec_Plugin::sanitize_csp( "img-src *.example.com data:" ) );
it( 'leading and trailing space goes',
    "a" === Bssec_Plugin::sanitize_csp( "   a   " ) );
it( 'an all-whitespace policy becomes empty',
    '' === Bssec_Plugin::sanitize_csp( "  \n\t " ) );

// --- clean_header_value ----------------------------------------------------

echo "\n== clean_header_value ==\n";
it( 'a carriage return goes',  "ab" === Bssec_Plugin::clean_header_value( "a\rb" ) );
it( 'a line feed goes',        "ab" === Bssec_Plugin::clean_header_value( "a\nb" ) );
it( 'a NUL goes',              "ab" === Bssec_Plugin::clean_header_value( "a\0b" ) );
it( 'surrounding space goes',  "ab" === Bssec_Plugin::clean_header_value( "  ab  " ) );
it( 'an ordinary value is untouched',
    "max-age=31536000" === Bssec_Plugin::clean_header_value( 'max-age=31536000' ) );

// --- the two layers together -----------------------------------------------

echo "\n== nothing sanitize() passes can produce a multi-line header ==\n";
$hostile = clean( [
    'referrer_policy'          => '1',
    'permissions_policy'       => '1',
    'frame_options'            => '1',
    'content_type_options'     => '1',
    'hsts'                     => '1',
    'hsts_max_age'             => '31536000',
    'csp'                      => '1',
    'csp_value'                => "default-src 'self'\r\nSet-Cookie: a=1\nX-Evil: 2\0",
    'permissions_policy_block' => [ "camera\n", 'microphone' ],
    'referrer_policy_value'    => "no-referrer\r\nX-Evil: 3",
    'frame_options_value'      => "DENY\r\nX-Evil: 4",
] );

$sent = Bssec_Headers::build( $hostile, true );
it( 'headers are still produced', count( $sent ) > 0 );

$clean_values = true;
foreach ( $sent as $name => $value ) {
    if ( preg_match( '/[\r\n\0]/', $name . $value ) ) $clean_values = false;
}
it( 'not one name or value contains CR, LF or NUL', $clean_values );
it( 'the poisoned Referrer-Policy fell back rather than shipping',
    'strict-origin-when-cross-origin' === $sent['Referrer-Policy'] );
it( 'the poisoned frame value fell back rather than shipping',
    'SAMEORIGIN' === $sent['X-Frame-Options'] );
it( 'the poisoned feature token was dropped, the clean one kept',
    'microphone=()' === $sent['Permissions-Policy'] );

// --- CSP report-only -------------------------------------------------------

echo "\n== report-only settings ==\n";
$today = new DateTimeImmutable( '2026-11-09 09:00:00', new DateTimeZone( 'America/New_York' ) );
$ro    = fn( array $raw ) => Bssec_Plugin::sanitize( $raw, $today );

it( 'an empty POST leaves report-only off', false === $empty['csp_report_only'] );
it( 'and stores no end date',               '' === $empty['csp_report_only_until'] );

it( 'switched on with no date: ends 30 days out',
    '2026-12-09' === $ro( [ 'csp_report_only' => '1' ] )['csp_report_only_until'] );
it( 'a real future date is kept',
    '2027-01-15' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => '2027-01-15' ] )['csp_report_only_until'] );
it( 'today is kept (the end date is inclusive)',
    '2026-11-09' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => '2026-11-09' ] )['csp_report_only_until'] );
it( 'a past date renews to 30 days out rather than saving an ended window',
    '2026-12-09' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => '2026-11-08' ] )['csp_report_only_until'] );
it( 'an impossible date (February 31) is refused, not rolled into March',
    '2026-12-09' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => '2027-02-31' ] )['csp_report_only_until'] );
it( 'an American-format date is refused',
    '2026-12-09' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => '01/15/2027' ] )['csp_report_only_until'] );
it( 'a date carrying a header separator is refused',
    '2026-12-09' === $ro( [ 'csp_report_only' => '1', 'csp_report_only_until' => "2027-01-15\r\nX-Evil: 1" ] )['csp_report_only_until'] );
it( 'switched off, a posted date is dropped',
    '' === $ro( [ 'csp_report_only_until' => '2027-01-15' ] )['csp_report_only_until'] );
it( 'switched off, the candidate is still kept, so it is not lost while paused',
    "img-src 'self'" === $ro( [ 'csp_report_only_value' => "img-src 'self'" ] )['csp_report_only_value'] );
it( 'the candidate gets the same cleaning as the enforced CSP',
    "default-src 'self'; img-src data:" === $ro( [ 'csp_report_only_value' => "default-src 'self';\n<img-src> data:" ] )['csp_report_only_value'] );
it( 'the candidate and the enforced policy are stored separately',
    ( fn( $s ) => "a" === $s['csp_value'] && "b" === $s['csp_report_only_value'] )(
        $ro( [ 'csp_value' => 'a', 'csp_report_only_value' => 'b' ] ) ) );
it( 'a fresh window, saved, is running today',
    Bssec_Plugin::report_only_active( $ro( [ 'csp_report_only' => '1', 'csp_report_only_value' => "img-src 'self'" ] ), $today ) );

echo "\n== report-only through both layers ==\n";
$ro_hostile = $ro( [
    'csp_report_only'       => '1',
    'csp_report_only_value' => "default-src 'self'\r\nSet-Cookie: a=1; report-uri https://evil.test\0",
] );
$ro_sent = Bssec_Headers::build( $ro_hostile, true, Bssec_Headers::CONTEXT_FRONTEND, 'https://x.test/wp-json/bssec/v1/csp-report' );
it( 'the hostile candidate still produces a report-only header',
    isset( $ro_sent['Content-Security-Policy-Report-Only'] ) );
it( 'with no CR, LF or NUL in it',
    ! preg_match( '/[\r\n\0]/', $ro_sent['Content-Security-Policy-Report-Only'] ) );
it( 'and no trace of the pasted report address',
    false === strpos( $ro_sent['Content-Security-Policy-Report-Only'], 'evil' ) );

echo "\n== sanitize() is idempotent ==\n";
$once  = clean( [ 'csp' => '1', 'csp_value' => "a\nb", 'permissions_policy_block' => [ 'payment', 'camera' ] ] );
$twice = clean( $once );
it( 'running it over its own output changes nothing', $once === $twice );

$ro_once  = $ro( [ 'csp_report_only' => '1', 'csp_report_only_value' => "a\nb", 'csp_report_only_until' => '2027-01-15' ] );
$ro_twice = $ro( $ro_once );
it( 'nor with report-only on and a date set', $ro_once === $ro_twice );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
