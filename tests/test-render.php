<?php
/**
 * Renders the settings screen against stubs.
 *
 * The view is the largest file here and the only one nothing else executes. A
 * typo in it is a white screen on a client's dashboard, and neither `php -l`
 * nor the other two suites would notice: lint parses, it does not run, and an
 * undefined array key or a misspelled static call only fails when the line
 * actually executes.
 *
 * So this runs it, twice — once with no probe result parked and once with one —
 * and asserts on the markup. Not a substitute for looking at the screen, but it
 * is what catches the fatal before the screen exists.
 *
 * Plain PHP with hand-rolled stubs, so there is nothing to install. Run:
 *
 *   php tests/test-render.php
 */

define( 'ABSPATH', '/fake/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'BSSEC_VERSION', '0.1.0' );
define( 'BSSEC_DIR', __DIR__ . '/../' );
define( 'BSSEC_URL', 'https://example.test/wp-content/plugins/bs-security/' );
define( 'BSSEC_BASENAME', 'bs-security/bs-security.php' );

// --- WP stubs: only what the view and its helpers actually touch ------------

function __( $t, $d = '' )            { return $t; }
function esc_html( $t )               { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $t )               { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
function esc_textarea( $t )           { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
function esc_url( $u )                { return htmlspecialchars( (string) $u, ENT_QUOTES, 'UTF-8' ); }
function esc_html__( $t, $d = '' )    { return esc_html( $t ); }
function esc_html_e( $t, $d = '' )    { echo esc_html( $t ); }
function esc_attr_e( $t, $d = '' )    { echo esc_attr( $t ); }
function _n( $s, $p, $n, $d = '' )    { return 1 === (int) $n ? $s : $p; }
function sanitize_text_field( $v )    { return trim( strip_tags( (string) $v ) ); }
function wp_unslash( $v )             { return is_string( $v ) ? stripslashes( $v ) : $v; }
function is_ssl()                     { return $GLOBALS['is_ssl'] ?? true; }
function get_current_user_id()        { return 1; }
function admin_url( $p = '' )         { return 'https://example.test/wp-admin/' . $p; }
function home_url( $p = '' )          { return ( $GLOBALS['home'] ?? 'https://example.test' ) . $p; }
function wp_parse_url( $u, $c = -1 )  { return parse_url( $u, $c ); }
function human_time_diff( $from, $to = 0 ) { return '2 minutes'; }
function wp_nonce_field( $a )         { echo '<input type="hidden" name="_wpnonce" value="stub">'; }
function wp_nonce_url( $u, $a )       { return $u . '&_wpnonce=stub'; }
function checked( $a, $b = true, $e = true )  { $r = ( $a == $b ) ? ' checked' : ''; if ( $e ) echo $r; return $r; }
function selected( $a, $b = true, $e = true ) { $r = ( $a == $b ) ? ' selected' : ''; if ( $e ) echo $r; return $r; }
function get_transient( $k )          { return $GLOBALS['transients'][ $k ] ?? false; }
function get_option( $k, $d = false ) { return $GLOBALS['options'][ $k ] ?? $d; }
function rest_url( $p = '' )          { return 'https://example.test/wp-json/' . ltrim( $p, '/' ); }
function wp_timezone()                { return new DateTimeZone( 'America/New_York' ); }
function wp_create_nonce( $a )        { return 'stubnonce'; }
function absint( $v )                 { return abs( (int) $v ); }
function wp_next_scheduled( $h )      { return $GLOBALS['next_scheduled'] ?? false; }
define( 'ARRAY_A', 'ARRAY_A' );
define( 'HOUR_IN_SECONDS', 3600 );

/**
 * Just enough $wpdb for the report card to render. It answers the queries
 * summary() and rows() make from canned values; it proves the view renders
 * each state, not that the SQL is right. The SQL was run against Local's
 * MySQL (docs/NOTES.md, "Build order", steps 2 and 4).
 *
 * Starts with no table, which is what a fresh install has.
 */
class Fake_Wpdb {
    public $prefix    = 'wp_';
    public $table     = false;
    public $count     = 0;
    public $last      = null;
    public $test_last = null;
    public $rows      = [];
    public function esc_like( $t ) { return $t; }
    public function prepare( $q, ...$a ) { return vsprintf( str_replace( '%s', "'%s'", $q ), $a ); }
    public function get_var( $q ) {
        if ( 0 === strpos( $q, 'SHOW TABLES' ) ) return $this->table ? 'wp_bssec_csp_reports' : null;
        if ( false !== strpos( $q, 'COUNT(*)' ) )  return (string) $this->count;
        if ( false !== strpos( $q, 'MAX(last_seen)' ) && false !== strpos( $q, 'directive = ' ) )  return $this->test_last;
        if ( false !== strpos( $q, 'MAX(last_seen)' ) && false !== strpos( $q, 'directive <> ' ) ) return $this->last;
        throw new RuntimeException( "Fake_Wpdb was asked something it does not know: $q" );
    }
    public function get_results( $q, $out = null ) {
        if ( false !== strpos( $q, 'ORDER BY hits DESC' ) ) return $this->rows;
        throw new RuntimeException( "Fake_Wpdb was asked something it does not know: $q" );
    }
}
$GLOBALS['wpdb']    = new Fake_Wpdb();
$GLOBALS['options'] = [];

function add_query_arg( $args, $url = '' ) {
    if ( ! is_array( $args ) ) { $args = [ $args => func_get_arg( 1 ) ]; $url = func_get_arg( 2 ) ?? ''; }
    return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $args );
}

$GLOBALS['transients'] = [];

require_once __DIR__ . '/../includes/class-bssec-plugin.php';
require_once __DIR__ . '/../includes/class-bssec-headers.php';
require_once __DIR__ . '/../includes/class-bssec-server-check.php';
require_once __DIR__ . '/../includes/class-bssec-csp-reports.php';
require_once __DIR__ . '/../includes/trait-bssec-guards.php';
require_once __DIR__ . '/../admin/class-bssec-admin.php';

// --- harness ---------------------------------------------------------------

$fails = 0;
$ran   = 0;

function it( string $label, bool $ok ): void {
    global $fails, $ran;
    $ran++;
    if ( ! $ok ) $fails++;
    printf( "%-6s %s\n", $ok ? '  ok' : 'FAIL', $label );
}

/**
 * Run the view and hand back its markup.
 *
 * Every diagnostic is promoted to an exception, so a notice about an undefined
 * key fails the test instead of being swallowed into the output buffer. That is
 * the whole reason this file exists.
 */
function render( array $settings ): string {
    set_error_handler( function ( $no, $str, $file, $line ) {
        throw new ErrorException( $str, 0, $no, $file, $line );
    } );
    ob_start();
    try {
        include __DIR__ . '/../admin/views/page-settings.php';
        return (string) ob_get_clean();
    } finally {
        restore_error_handler();
    }
}

// --- a fresh install -------------------------------------------------------

echo "\n== the screen renders on a fresh install ==\n";
$html = '';
try {
    $html = render( Bssec_Plugin::defaults() );
    it( 'no fatal, no notice, no warning', true );
} catch ( Throwable $e ) {
    it( 'no fatal, no notice, no warning — ' . $e->getMessage(), false );
}

it( 'something was actually output', strlen( $html ) > 4000 );
it( 'the save action is posted',        false !== strpos( $html, 'name="action" value="bssec_save_settings"' ) );
it( 'a nonce field is present',         false !== strpos( $html, '_wpnonce' ) );
it( 'the probe button links to the probe action', false !== strpos( $html, 'bssec_probe_server' ) );

echo "\n== every setting has a control ==\n";
foreach ( [
    'referrer_policy', 'referrer_policy_value', 'permissions_policy',
    'permissions_policy_block[]', 'frame_options', 'frame_options_value',
    'content_type_options', 'hsts', 'hsts_max_age', 'csp', 'csp_value',
    'block_user_enumeration', 'redirect_author_archives', 'mask_login_errors', 'disable_file_editor',
    'csp_report_only', 'csp_report_only_value', 'csp_report_only_until',
] as $field ) {
    it( "$field has an input", false !== strpos( $html, 'name="' . $field . '"' ) );
}

echo "\n== every offered feature has a checkbox ==\n";
$missing = [];
foreach ( Bssec_Plugin::POLICY_FEATURES as $feature ) {
    if ( false === strpos( $html, 'value="' . $feature . '"' ) ) $missing[] = $feature;
}
it( 'none are missing from the list: ' . ( $missing ? implode( ', ', $missing ) : 'ok' ), [] === $missing );

echo "\n== defaults are reflected in the markup ==\n";
it( 'the five default-blocked features are ticked',
    5 === preg_match_all( '/name="permissions_policy_block\[\]"[^>]*checked/', $html ) );
it( 'HSTS renders unticked',
    (bool) preg_match( '/name="hsts"(?![^>]*checked)/', $html ) );
it( 'the HSTS options block starts hidden',
    (bool) preg_match( '/id="bssec-hsts-opts"[^>]*hidden/', $html ) );
it( 'the CSP box starts hidden',
    (bool) preg_match( '/id="bssec-csp-opts"[^>]*hidden/', $html ) );
it( 'the Referrer-Policy block starts visible',
    ! preg_match( '/id="bssec-referrer"[^>]*hidden/', $html ) );

it( 'the three default hardening switches render ticked',
    3 === preg_match_all( '/name="(?:block_user_enumeration|mask_login_errors|disable_file_editor)"[^>]*checked/', $html ) );
it( 'author-page redirect renders unticked',
    (bool) preg_match( '/name="redirect_author_archives"(?![^>]*checked)/', $html ) );
it( 'the hardening pill counts three of four', false !== strpos( $html, '3 of 4 hardening on' ) );

echo "\n== the generated preview shows the real header set ==\n";

/**
 * Just the generated-headers block.
 *
 * Searching the whole page is useless here: 'Strict-Transport-Security' also
 * appears in the HSTS toggle label, so a whole-page search can never show that
 * the header is absent from the preview. Scope it.
 */
function preview_block( string $html ): string {
    return preg_match( '#<pre class="bssec-preview">(.*?)</pre>#s', $html, $m ) ? $m[1] : '';
}

$pre = preview_block( $html );
it( 'the preview block was found',  '' !== $pre );
it( 'Referrer-Policy is listed',    false !== strpos( $pre, 'Referrer-Policy: strict-origin-when-cross-origin' ) );
it( 'X-Frame-Options is listed',    false !== strpos( $pre, 'X-Frame-Options: SAMEORIGIN' ) );
it( 'Permissions-Policy is listed', false !== strpos( $pre, 'Permissions-Policy: camera=(), microphone=()' ) );
it( 'HSTS is NOT listed',           false === strpos( $pre, 'Strict-Transport-Security' ) );
it( 'the CSP is NOT listed',        false === strpos( $pre, 'Content-Security-Policy' ) );
it( 'the preview has exactly three lines', 3 === count( array_filter( explode( "\n", trim( $pre ) ) ) ) );
it( 'the pill counts three headers', false !== strpos( $html, '3 headers on' ) );

// --- everything on, with a probe result parked -----------------------------

echo "\n== the screen renders with everything on and a probe result ==\n";

$GLOBALS['transients'][ Bssec_Admin::probe_key() ] = [
    'ok'         => true,
    'static_url' => 'https://example.test/wp-content/plugins/bs-security/assets/css/bssec-admin.css',
    'page_url'   => 'https://example.test/',
    'static'     => [
        'x-content-type-options' => 'nosniff',
        // Present on both, with a different value on the page: the host sets
        // one policy and PHP replaces it. This is the override case.
        'referrer-policy'        => 'no-referrer-when-downgrade',
    ],
    'page'       => [
        'x-content-type-options' => 'nosniff',
        'referrer-policy'        => 'strict-origin-when-cross-origin',
        // Page only: added by PHP.
        'x-frame-options'        => 'DENY',
    ],
    'errors'     => [ 'a sample error line' ],
    'checked_at' => time() - 120,
];

$on = array_merge( Bssec_Plugin::defaults(), [
    'hsts'                 => true,
    'hsts_max_age'         => 31536000,
    'content_type_options' => true,
    'csp'                  => true,
    'csp_value'            => "default-src 'self'; script-src 'self' https://example.test",
    'frame_options_value'  => 'DENY',
] );

$html2 = '';
try {
    $html2 = render( $on );
    it( 'no fatal, no notice, no warning', true );
} catch ( Throwable $e ) {
    it( 'no fatal, no notice, no warning — ' . $e->getMessage(), false );
}

it( 'the probe table rendered',      false !== strpos( $html2, 'bssec-table' ) );
it( 'a server-only header is shown', false !== strpos( $html2, 'x-content-type-options' ) );
it( 'a PHP-added header is tagged',  false !== strpos( $html2, 'added by WordPress' ) );
it( 'a differing value is flagged as an override', false !== strpos( $html2, 'overriding the server' ) );
it( 'the override row is the one present on both with different values',
    (bool) preg_match( '#<tr class="is-overridden">\s*<th scope="row"><code>referrer-policy</code>#', $html2 ) );
it( 'the page-only row is classed as PHP-added',
    (bool) preg_match( '#<tr class="is-php">\s*<th scope="row"><code>x-frame-options</code>#', $html2 ) );
it( 'the matching row is classed as the server\'s',
    (bool) preg_match( '#<tr class="is-server">\s*<th scope="row"><code>x-content-type-options</code>#', $html2 ) );
it( 'a header nobody sends is classed absent',
    (bool) preg_match( '#<tr class="is-absent">\s*<th scope="row"><code>permissions-policy</code>#', $html2 ) );
// X-XSS-Protection and Expect-CT were reported until 0.4.1. Browsers ignore
// both, so they only ever added two "not sent" rows; removed November 10, 2026.
it( 'the retired headers are not on the reported list',
    ! in_array( 'x-xss-protection', Bssec_Server_Check::REPORTED, true )
    && ! in_array( 'expect-ct', Bssec_Server_Check::REPORTED, true ) );
it( 'the table has one row per header this plugin can send, and no others',
    count( Bssec_Server_Check::REPORTED ) === preg_match_all( '#<tr class="is-(?:absent|php|overridden|server)">#', $html2 )
    && 6 === count( Bssec_Server_Check::REPORTED ) );
it( 'neither retired header has a row',
    false === strpos( $html2, '<code>x-xss-protection</code>' ) && false === strpos( $html2, '<code>expect-ct</code>' ) );
it( 'the probe error line is shown', false !== strpos( $html2, 'a sample error line' ) );
it( 'the check time is shown',       false !== strpos( $html2, '2 minutes ago' ) );

it( 'the HSTS block is now visible',
    ! preg_match( '/id="bssec-hsts-opts"[^>]*hidden/', $html2 ) );
it( 'the CSP box is now visible',
    ! preg_match( '/id="bssec-csp-opts"[^>]*hidden/', $html2 ) );
it( 'the saved CSP is in the textarea',
    false !== strpos( $html2, "default-src &#039;self&#039;; script-src &#039;self&#039; https://example.test" ) );
it( 'the preview shows HSTS at a year',
    false !== strpos( $html2, 'Strict-Transport-Security: max-age=31536000' ) );
it( 'the preview shows the CSP',
    false !== strpos( $html2, "Content-Security-Policy: default-src &#039;self&#039;" ) );
it( 'the pill counts six headers', false !== strpos( $html2, '6 headers on' ) );

echo "\n== a CSP carrying markup cannot escape the textarea ==\n";
$xss = array_merge( Bssec_Plugin::defaults(), [
    'csp'       => true,
    'csp_value' => '"></textarea><script>alert(1)</script>',
] );
$html3 = render( $xss );
it( 'no live script tag reaches the page', false === strpos( $html3, '<script>alert(1)' ) );
// This used to search the whole page for the literal "></textarea>, which an
// empty textarea after a quoted attribute also prints. The report-only box
// made that false positive real, November 9, 2026. Check what it means: every
// textarea closes exactly once, and the payload sits inside one, escaped.
it( 'no textarea is closed early',
    substr_count( $html3, '<textarea' ) === substr_count( $html3, '</textarea>' )
    && false !== strpos( $html3, '&quot;&gt;&lt;/textarea&gt;&lt;script&gt;alert(1)' ) );

echo "\n== CSP report-only ==\n";

/** Just the report-only card, so a phrase elsewhere on the page cannot pass a check. */
function report_only_card( string $html ): string {
    return preg_match( '#<div class="bssec-card" id="bssec-report-only">(.*?)<div class="bssec-actions">#s', $html, $m ) ? $m[1] : '';
}

it( 'off by default: the options start hidden',
    (bool) preg_match( '/id="bssec-report-only-opts"[^>]*hidden/', $html ) );
it( 'off by default: no status line',
    false === strpos( report_only_card( $html ), 'bssec-report-only-status' ) );
it( 'the card was found, so the check above is real', '' !== report_only_card( $html ) );

$future = ( new DateTimeImmutable( '+10 days', wp_timezone() ) )->format( 'Y-m-d' );
$past   = ( new DateTimeImmutable( '-3 days', wp_timezone() ) )->format( 'Y-m-d' );
$ro     = array_merge( Bssec_Plugin::defaults(), [
    'csp_report_only'       => true,
    'csp_report_only_value' => "img-src 'self'",
    'csp_report_only_until' => $future,
] );

$GLOBALS['wpdb']->table = true;
$GLOBALS['wpdb']->count = 7;
$GLOBALS['next_scheduled'] = time() + 3600;
$GLOBALS['wpdb']->last = gmdate( 'Y-m-d H:i:s', time() - 300 );
// Smaller count first on purpose, so the "largest first" check below can fail.
$GLOBALS['options']['bssec_csp_stats'] = [ 'since' => '2026-11-09 12:00:00', 'dropped' => [ 'over_budget' => 1, 'wrong_host' => 2, 'not_a_reason' => 9 ] ];

$h_ro = '';
try {
    $h_ro = render( $ro );
    it( 'collecting: no fatal, no notice, no warning', true );
} catch ( Throwable $e ) {
    it( 'collecting: no fatal, no notice, no warning: ' . $e->getMessage(), false );
}
$card = report_only_card( $h_ro );
it( 'collecting: the options are visible', ! preg_match( '/id="bssec-report-only-opts"[^>]*hidden/', $h_ro ) );
it( 'collecting: the end date is in the date field', false !== strpos( $card, 'value="' . $future . '"' ) );
it( 'collecting: the status names the end date in words',
    false !== strpos( $card, 'Collecting until ' . ( new DateTimeImmutable( $future ) )->format( 'F j, Y' ) ) );
it( 'collecting: the row count is shown', false !== strpos( $card, '7 sources reported so far.' ) );
it( 'collecting: the last report time is shown', false !== strpos( $card, 'Last report 2 minutes ago.' ) );
it( 'collecting: refusals are added up and broken down by reason, largest first',
    false !== strpos( $card, '3 refused: 2 from another site, 1 over 50 new sources in an hour.' ) );
it( 'collecting: the report address is shown',
    false !== strpos( $card, 'https://example.test/wp-json/bssec/v1/csp-report' ) );
$pre_ro = preview_block( $h_ro );
it( 'collecting: the preview shows the report-only header with our address',
    false !== strpos( $pre_ro, 'Content-Security-Policy-Report-Only: img-src &#039;self&#039;; report-uri https://example.test/wp-json/bssec/v1/csp-report; report-to bssec' ) );
it( 'collecting: the preview shows Reporting-Endpoints',
    false !== strpos( $pre_ro, 'Reporting-Endpoints: bssec=&quot;https://example.test/wp-json/bssec/v1/csp-report&quot;' ) );

$GLOBALS['wpdb']->count = 0;
$GLOBALS['wpdb']->last = null;
$GLOBALS['options']    = [];
$card0 = report_only_card( render( $ro ) );
it( 'no reports yet: says so', false !== strpos( $card0, '0 sources reported so far. No reports yet.' ) );
it( 'no reports yet: no refusal line', false === strpos( $card0, 'refused' ) );

$GLOBALS['wpdb']->table = false;
$cardm = report_only_card( render( $ro ) );
it( 'table missing: says nothing is being stored', false !== strpos( $cardm, 'The reports table is missing' ) );
it( 'table missing: no row count pretending to be zero', false === strpos( $cardm, 'sources reported' ) );
$GLOBALS['wpdb']->table = true;

$ended = array_merge( $ro, [ 'csp_report_only_until' => $past ] );
$h_end = render( $ended );
it( 'ended: the status says so and how to restart',
    false !== strpos( report_only_card( $h_end ), 'Collection ended on ' . ( new DateTimeImmutable( $past ) )->format( 'F j, Y' ) . '. Save with a later date to start again.' ) );
it( 'ended: no report address offered', false === strpos( report_only_card( $h_end ), 'Reports go to' ) );
it( 'ended: the preview sends no report-only header',
    false === strpos( preview_block( $h_end ), 'Report-Only' ) );

$h_ro_xss = render( array_merge( $ro, [ 'csp_report_only_value' => '"></textarea><script>alert(2)</script>' ] ) );
it( 'a candidate carrying markup cannot escape its textarea',
    false === strpos( $h_ro_xss, '<script>alert(2)' )
    && substr_count( $h_ro_xss, '<textarea' ) === substr_count( $h_ro_xss, '</textarea>' )
    && false !== strpos( $h_ro_xss, '&quot;&gt;&lt;/textarea&gt;&lt;script&gt;alert(2)' ) );

echo "\n== the report table (step 4) ==\n";

$now_utc = fn( int $ago ) => gmdate( 'Y-m-d H:i:s', time() - $ago );
$GLOBALS['wpdb']->table     = true;
$GLOBALS['wpdb']->count     = 3;
$GLOBALS['wpdb']->last      = $now_utc( 120 );
$GLOBALS['wpdb']->test_last = $now_utc( 30 );
$GLOBALS['wpdb']->rows      = [
    // As $wpdb hands them back: every value a string.
    [ 'directive' => 'img-src', 'blocked' => 'https://example.test', 'sample_page' => 'https://example.test/work/', 'sample_source' => '', 'hits' => '1240', 'first_seen' => '2026-11-09 18:00:00', 'last_seen' => $now_utc( 120 ) ],
    [ 'directive' => 'bssec-test', 'blocked' => 'https://example.test', 'sample_page' => 'https://example.test/', 'sample_source' => '', 'hits' => '2', 'first_seen' => '2026-11-10 12:00:00', 'last_seen' => $now_utc( 30 ) ],
    [ 'directive' => 'script-src-elem', 'blocked' => 'https://evil.test', 'sample_page' => 'https://example.test/<script>alert(3)</script>/', 'sample_source' => '', 'hits' => '1', 'first_seen' => '2026-11-10 09:00:00', 'last_seen' => $now_utc( 600 ) ],
];
$GLOBALS['next_scheduled'] = time() + 3600;

$h4    = render( $ro );
$card4 = report_only_card( $h4 );
it( 'the table rendered', false !== strpos( $card4, 'class="bssec-table bssec-reports"' ) );
it( 'it has a row per real source, and the test report is not one of them',
    2 === substr_count( $card4, '<tr class="' ) && false === strpos( $card4, '<code>bssec-test</code>' ) );
it( 'the most reported source comes first, with its count formatted',
    (bool) preg_match( '#<code>img-src</code>.*?1,240.*?<code>script-src-elem</code>#s', $card4 ) );
it( 'first seen is a day in words', false !== strpos( $card4, 'November 9, 2026' ) );
it( 'last seen is a time ago', false !== strpos( $card4, '2 minutes ago' ) );
it( 'a source reported once is greyed',
    (bool) preg_match( '#<tr class="is-faint">\s*<th scope="row"><code>script-src-elem</code>#', $card4 ) );
it( 'a source reported many times is not',
    (bool) preg_match( '#<tr class="">\s*<th scope="row"><code>img-src</code>#', $card4 ) );
it( 'the greyed rows are explained', false !== strpos( $card4, 'a source reported only once is not evidence' ) );
it( 'a stored value carrying markup is escaped, not run',
    false === strpos( $h4, '<script>alert(3)' ) && false !== strpos( $card4, '&lt;script&gt;alert(3)' ) );
it( 'the test report has its own line', false !== strpos( $card4, 'Last test report 2 minutes ago.' ) );

echo "\n== the test button ==\n";
it( 'is offered while collecting', false !== strpos( $card4, 'Send a test report' ) );
it( 'carries the report address',
    false !== strpos( $card4, 'data-bssec-test-url="https://example.test/wp-json/bssec/v1/csp-report"' ) );
it( 'and a page on this site, so the host check passes',
    false !== strpos( $card4, 'data-bssec-test-page="https://example.test/"' ) );
it( 'is a plain button, so it can never submit the settings form',
    (bool) preg_match( '#<button type="button" class="button"\s+data-bssec-test-url#', $card4 ) );
it( 'has a place for its answer that screen readers announce',
    false !== strpos( $card4, 'id="bssec-test-result" role="status" aria-live="polite" hidden' ) );
it( 'is not offered once collection has ended',
    false === strpos( report_only_card( render( $ended ) ), 'Send a test report' ) );

$_GET['bssec-tested'] = '1';
it( 'after a test, a report stored in the last two minutes reads as stored',
    false !== strpos( report_only_card( render( $ro ) ), 'Test report received and stored.' ) );
$GLOBALS['wpdb']->rows[1]['last_seen'] = $now_utc( 900 );
it( 'after a test, an old test row reads as not stored',
    false !== strpos( report_only_card( render( $ro ) ), 'accepted the test report but did not store it' ) );
unset( $_GET['bssec-tested'] );
$GLOBALS['wpdb']->rows[1]['last_seen'] = $now_utc( 30 );

echo "\n== Clear reports ==\n";
it( 'the button submits its own form, not the settings form',
    (bool) preg_match( '#<button type="submit" form="bssec-clear-form" class="button" data-bssec-clear>#', $card4 ) );
it( 'that form exists, outside the settings form, posting the clear action',
    (bool) preg_match( '#</form>\s*.*?<form id="bssec-clear-form" method="post" action="https://example.test/wp-admin/admin-post.php">\s*<input type="hidden" name="action" value="bssec_clear_reports">#s', $h4 ) );
it( 'with a nonce for that action',
    false !== strpos( $h4, '<input type="hidden" name="_wpnonce" value="stubnonce">' ) );
$_GET['bssec-cleared'] = '12';
it( 'after clearing, says how many and that counts restart',
    false !== strpos( render( $ro ), 'CSP reports cleared: 12 rows deleted. The refused counts start again from now.' ) );
// The case Local caught: off, and nothing left after the clear. The card has
// nothing to show, and the first version put the message inside it.
$GLOBALS['wpdb']->rows  = [];
$GLOBALS['wpdb']->count = 0;
$GLOBALS['options']     = [];
it( 'the message still shows when the clear left nothing and collection is off',
    false !== strpos( render( array_merge( $ro, [ 'csp_report_only' => false ] ) ), 'CSP reports cleared: 12 rows deleted.' ) );
unset( $_GET['bssec-cleared'] );
$GLOBALS['wpdb']->rows = [
    [ 'directive' => 'img-src', 'blocked' => 'https://example.test', 'sample_page' => 'https://example.test/work/', 'sample_source' => '', 'hits' => '1240', 'first_seen' => '2026-11-09 18:00:00', 'last_seen' => $now_utc( 120 ) ],
];

echo "\n== switched off, with reports kept ==\n";
$off_kept = array_merge( $ro, [ 'csp_report_only' => false ] );
$card_off = report_only_card( render( $off_kept ) );
it( 'the table still shows', false !== strpos( $card_off, 'class="bssec-table bssec-reports"' ) );
it( 'and says collection is off', false !== strpos( $card_off, 'Collection is off. The reports below were collected earlier.' ) );
it( 'Clear is still offered', false !== strpos( $card_off, 'data-bssec-clear' ) );
it( 'no test button', false === strpos( $card_off, 'Send a test report' ) );
it( 'no clean-up warning while off', false === strpos( $card_off, 'daily clean-up' ) );

echo "\n== the clean-up canary ==\n";
$GLOBALS['next_scheduled'] = false;
it( 'not scheduled while collecting: says so',
    false !== strpos( report_only_card( render( $ro ) ), 'The daily clean-up is not scheduled.' ) );
$GLOBALS['next_scheduled'] = time() - 2 * 86400;
it( 'two days overdue: says so, and that the cap still holds',
    (bool) preg_match( '#overdue by 2 minutes, so WP-Cron may not be running.*?500-row limit still holds#s', report_only_card( render( $ro ) ) ) );
$GLOBALS['next_scheduled'] = time() - 600;
it( 'ten minutes late is not a warning (WP-Cron runs on traffic)',
    false === strpos( report_only_card( render( $ro ) ), 'overdue' ) );
$GLOBALS['next_scheduled'] = time() + 3600;
it( 'scheduled ahead: no warning', false === strpos( report_only_card( render( $ro ) ), 'daily clean-up' ) );

echo "\n== a fresh install shows none of it ==\n";
$GLOBALS['wpdb'] = new Fake_Wpdb();
$GLOBALS['options'] = [];
$card_fresh = report_only_card( render( Bssec_Plugin::defaults() ) );
it( 'no status block, no table, no Clear',
    false === strpos( $card_fresh, 'bssec-report-only-status' ) && false === strpos( $card_fresh, 'data-bssec-clear' ) );

$_GET['bssec-notice'] = 'noreportonly';
it( 'the empty-candidate notice renders',
    false !== strpos( render( Bssec_Plugin::defaults() ), 'Report-only was left off' ) );
unset( $_GET['bssec-notice'] );

echo "\n== tabs ==\n";

/** One tab panel's markup, by its slug. Panels are siblings, never nested. */
function panel( string $html, string $slug ): string {
    return preg_match( '#<div class="bssec-panel" id="bssec-panel-' . $slug . '"[^>]*>(.*?)</div><!-- /Tab:#s', $html, $m ) ? $m[1] : '';
}
/** The opening tag of one panel, to read its hidden state. */
function panel_tag( string $html, string $slug ): string {
    return preg_match( '#<div class="bssec-panel" id="bssec-panel-' . $slug . '"[^>]*>#', $html, $m ) ? $m[0] : '';
}
/** The settings form, from its opening tag to its own close. */
function settings_form( string $html ): string {
    return preg_match( '#<form method="post"[^>]*>\s*<input type="hidden" name="action" value="bssec_save_settings">(.*?)</form>#s', $html, $m ) ? $m[1] : '';
}

$h_tabs = render( Bssec_Plugin::defaults() );
it( 'four tabs, in order',
    (bool) preg_match( '#id="bssec-tab-hardening".*?id="bssec-tab-headers".*?id="bssec-tab-csp".*?id="bssec-tab-check"#s', $h_tabs ) );
it( 'each tab links to its own page load, for when the script fails',
    false !== strpos( $h_tabs, 'href="https://example.test/wp-admin/options-general.php?page=bssec-security&amp;bssec-tab=headers"' ) );
foreach ( Bssec_Admin::TABS as $slug ) {
    it( "the $slug panel was found", '' !== panel( $h_tabs, $slug ) );
}
it( 'Hardening is open by default and the others are hidden',
    false === strpos( panel_tag( $h_tabs, 'hardening' ), 'hidden' )
    && false !== strpos( panel_tag( $h_tabs, 'headers' ), 'hidden' )
    && false !== strpos( panel_tag( $h_tabs, 'csp' ), 'hidden' )
    && false !== strpos( panel_tag( $h_tabs, 'check' ), 'hidden' ) );
it( 'only the open tab is marked active',
    1 === substr_count( $h_tabs, 'nav-tab-active' )
    && (bool) preg_match( '#class="nav-tab nav-tab-active"\s+id="bssec-tab-hardening"#', $h_tabs ) );

// The trap the single form exists to avoid: sanitize() reads a missing
// checkbox as off, so a setting outside the form would be switched off by
// every save. Every control, on every tab, must be inside the one form.
$form = settings_form( $h_tabs );
it( 'the settings form was found', '' !== $form );
$outside = [];
foreach ( [
    'block_user_enumeration', 'redirect_author_archives', 'mask_login_errors', 'disable_file_editor',
    'referrer_policy', 'referrer_policy_value', 'permissions_policy', 'permissions_policy_block[]',
    'frame_options', 'frame_options_value', 'content_type_options', 'hsts', 'hsts_max_age',
    'csp', 'csp_value', 'csp_report_only', 'csp_report_only_value', 'csp_report_only_until',
] as $field ) {
    if ( false === strpos( $form, 'name="' . $field . '"' ) ) $outside[] = $field;
}
it( 'every setting is inside the one form: ' . ( $outside ? implode( ', ', $outside ) : 'ok' ), [] === $outside );

// And each on the tab it belongs to.
$where = [
    'hardening' => [ 'block_user_enumeration', 'redirect_author_archives', 'mask_login_errors', 'disable_file_editor' ],
    'headers'   => [ 'referrer_policy', 'permissions_policy', 'frame_options', 'content_type_options', 'hsts', 'hsts_max_age' ],
    'csp'       => [ 'csp', 'csp_value', 'csp_report_only', 'csp_report_only_value', 'csp_report_only_until' ],
];
foreach ( $where as $slug => $fields ) {
    $miss = array_filter( $fields, fn( $f ) => false === strpos( panel( $h_tabs, $slug ), 'name="' . $f . '"' ) );
    it( "the $slug tab holds its settings" . ( $miss ? ': missing ' . implode( ', ', $miss ) : '' ), [] === $miss );
}
it( 'the Check tab holds no settings', false === strpos( panel( $h_tabs, 'check' ), 'name="' ) );
it( 'the Check tab holds the probe and the preview',
    false !== strpos( panel( $h_tabs, 'check' ), 'id="bssec-server-check"' )
    && false !== strpos( panel( $h_tabs, 'check' ), 'class="bssec-preview"' ) );
it( 'the Check tab sits outside the settings form', false === strpos( $form, 'id="bssec-panel-check"' ) );

it( 'the form carries the open tab, so Save comes back to it',
    false !== strpos( $form, '<input type="hidden" name="bssec-tab" value="hardening">' ) );
it( 'Save says it saves every tab', false !== strpos( $h_tabs, 'Saves the settings on every tab' ) );
it( 'Save shows on a settings tab', (bool) preg_match( '#<div class="bssec-actions">#', $h_tabs ) );

$_GET['bssec-tab'] = 'check';
$h_check = render( Bssec_Plugin::defaults() );
it( 'asking for Check opens it and hides Hardening',
    false === strpos( panel_tag( $h_check, 'check' ), 'hidden' )
    && false !== strpos( panel_tag( $h_check, 'hardening' ), 'hidden' ) );
it( 'Save is hidden on the Check tab', (bool) preg_match( '#<div class="bssec-actions" hidden>#', $h_check ) );
it( 'the form still carries the open tab',
    false !== strpos( $h_check, '<input type="hidden" name="bssec-tab" value="check">' ) );

$_GET['bssec-tab'] = '"><script>alert(4)</script>';
$h_bad = render( Bssec_Plugin::defaults() );
it( 'an unknown tab falls back to Hardening',
    false === strpos( panel_tag( $h_bad, 'hardening' ), 'hidden' ) );
it( 'and is never printed', false === strpos( $h_bad, 'alert(4)' ) );
unset( $_GET['bssec-tab'] );

echo "\n== tab_from and the save redirect ==\n";
it( 'a known tab is kept',           'csp' === Bssec_Admin::tab_from( 'csp' ) );
it( 'an empty value is the first',   'hardening' === Bssec_Admin::tab_from( '' ) );
it( 'an unknown value is the first', 'hardening' === Bssec_Admin::tab_from( 'settings' ) );
it( 'case counts',                   'hardening' === Bssec_Admin::tab_from( 'CSP' ) );
it( 'an array is the first',         'hardening' === Bssec_Admin::tab_from( [ 'csp' ] ) );
it( 'null is the first',             'hardening' === Bssec_Admin::tab_from( null ) );

$args = Bssec_Admin::save_redirect_args( [], 'headers' );
it( 'Save returns to the tab it was sent from',
    'headers' === ( $args['bssec-tab'] ?? '' ) && '1' === ( $args['bssec-updated'] ?? '' ) && ! isset( $args['bssec-notice'] ) );
$args = Bssec_Admin::save_redirect_args( [ 'nocsp' ], 'hardening' );
it( 'a refused CSP switch opens the CSP tab, whatever tab saved',
    'csp' === ( $args['bssec-tab'] ?? '' ) && 'nocsp' === ( $args['bssec-notice'] ?? '' ) );
$args = Bssec_Admin::save_redirect_args( [], 'nonsense' );
it( 'a forged tab returns to the first', 'hardening' === ( $args['bssec-tab'] ?? '' ) );

echo "\n== no text points at a card on another tab ==\n";
it( 'X-Content-Type-Options names the Check tab, not "the check below"',
    false !== strpos( panel( $h_tabs, 'headers' ), 'only if the Check tab' )
    && false === strpos( $h_tabs, 'the check below' ) );
it( 'the preview no longer says "the saved settings above"',
    false === strpos( $h_tabs, 'The saved settings above' ) );
it( 'report-only still says "above", and the policy it means is above it on the same tab',
    (bool) preg_match( '#name="csp_value".*?write the real policy above#s', panel( $h_tabs, 'csp' ) ) );

echo "\n== the Settings menu entry ==\n";
// "Biscuit Security" since 0.4.0, Jason's call on November 10, 2026. The slug
// is an identifier and must not move with the label.
function add_options_page( ...$args ) { $GLOBALS['options_page'] = $args; return 'hook'; }
( new Bssec_Admin() )->register_menu();
it( 'the menu label is Biscuit Security', 'Biscuit Security' === ( $GLOBALS['options_page'][1] ?? '' ) );
it( 'and so is the browser tab title', 'Biscuit Security' === ( $GLOBALS['options_page'][0] ?? '' ) );
it( 'the page slug is unchanged', 'bssec-security' === ( $GLOBALS['options_page'][3] ?? '' ) );
it( 'and still behind manage_options', 'manage_options' === ( $GLOBALS['options_page'][2] ?? '' ) );
it( 'the screen heading matches the menu',
    (bool) preg_match( '#<div class="bssec-header">\s*<h1>Biscuit Security</h1>#', $html ) );

echo "\n== the local development warning ==\n";

// The reading that prompted this: on Local the server column is empty for every
// header, which reads as "your host sends nothing" and invites switching things
// on that the real host already handles.
$GLOBALS['transients'][ Bssec_Admin::probe_key() ] = [
    'ok' => true, 'static_url' => 'x', 'page_url' => 'y', 'local' => true,
    'static' => [], 'page' => [], 'errors' => [], 'checked_at' => time(),
];
it( 'shows when the probe ran against a local site',
    false !== strpos( render( Bssec_Plugin::defaults() ), 'This is a local development site' ) );

$GLOBALS['transients'][ Bssec_Admin::probe_key() ]['local'] = false;
it( 'hides on a real host',
    false === strpos( render( Bssec_Plugin::defaults() ), 'This is a local development site' ) );

// A result parked by 0.1.0 has no 'local' key at all.
unset( $GLOBALS['transients'][ Bssec_Admin::probe_key() ]['local'] );
it( 'a probe result saved by an older version does not fatal',
    false === strpos( render( Bssec_Plugin::defaults() ), 'This is a local development site' ) );
$GLOBALS['transients'] = [];

echo "\n== is_local_host ==\n";
foreach ( [ 'https://biscuit-bootstrap-dev.local' => true, 'https://foo.test' => true,
            'http://localhost' => true, 'https://127.0.0.1' => true,
            'https://georgiatrust.org' => false, 'https://notlocal.com' => false ] as $url => $want ) {
    $GLOBALS['home'] = $url;
    it( sprintf( '%-38s %s', $url, $want ? 'is local' : 'is not local' ),
        $want === Bssec_Server_Check::is_local_host() );
}
$GLOBALS['home'] = 'https://example.test';

echo "\n== the not-HTTPS warning ==\n";
$GLOBALS['is_ssl'] = false;
unset( $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_PORT'] );
it( 'shows when the site is not on HTTPS',
    false !== strpos( render( Bssec_Plugin::defaults() ), 'not being served over HTTPS' ) );
$GLOBALS['is_ssl'] = true;
it( 'hides when it is',
    false === strpos( render( Bssec_Plugin::defaults() ), 'not being served over HTTPS' ) );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
