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

/**
 * Just enough $wpdb for Bssec_Csp_Reports::summary() to run. It answers the
 * three queries that method makes from canned values; it proves the view
 * renders each state, not that the SQL is right. The SQL was run against
 * Local's MySQL (docs/NOTES.md, "Build order", step 2).
 */
class Fake_Wpdb {
    public $prefix = 'wp_';
    public $table  = true;
    public $rows   = 0;
    public $last   = null;
    public function esc_like( $t ) { return $t; }
    public function prepare( $q, ...$a ) { return vsprintf( str_replace( '%s', "'%s'", $q ), $a ); }
    public function get_var( $q ) {
        if ( 0 === strpos( $q, 'SHOW TABLES' ) ) return $this->table ? 'wp_bssec_csp_reports' : null;
        if ( false !== strpos( $q, 'COUNT(*)' ) )  return (string) $this->rows;
        if ( false !== strpos( $q, 'MAX(last_seen)' ) ) return $this->last;
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
        'x-xss-protection'       => '1; mode=block',
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
it( 'a dead header still on the site is reported', false !== strpos( $html2, 'x-xss-protection' ) );
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

$GLOBALS['wpdb']->rows = 7;
$GLOBALS['wpdb']->last = gmdate( 'Y-m-d H:i:s', time() - 300 );
$GLOBALS['options']['bssec_csp_stats'] = [ 'since' => '2026-11-09 12:00:00', 'dropped' => [ 'wrong_host' => 2, 'over_budget' => 1 ] ];

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
it( 'collecting: refusals are added up and shown', false !== strpos( $card, '3 reports refused.' ) );
it( 'collecting: the report address is shown',
    false !== strpos( $card, 'https://example.test/wp-json/bssec/v1/csp-report' ) );
$pre_ro = preview_block( $h_ro );
it( 'collecting: the preview shows the report-only header with our address',
    false !== strpos( $pre_ro, 'Content-Security-Policy-Report-Only: img-src &#039;self&#039;; report-uri https://example.test/wp-json/bssec/v1/csp-report; report-to bssec' ) );
it( 'collecting: the preview shows Reporting-Endpoints',
    false !== strpos( $pre_ro, 'Reporting-Endpoints: bssec=&quot;https://example.test/wp-json/bssec/v1/csp-report&quot;' ) );

$GLOBALS['wpdb']->rows = 0;
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

$_GET['bssec-notice'] = 'noreportonly';
it( 'the empty-candidate notice renders',
    false !== strpos( render( Bssec_Plugin::defaults() ), 'Report-only was left off' ) );
unset( $_GET['bssec-notice'] );

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
