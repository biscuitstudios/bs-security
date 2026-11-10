<?php
/**
 * Tests for the pure half of Bssec_Csp_Reports: parsing a browser's report,
 * cutting it down to what is stored, and deciding whether a row may be added.
 *
 * What is being pinned:
 *
 *   - nothing a WooCommerce order page puts in a URL reaches a stored column:
 *     not the order key in the query, not the order number in the path.
 *   - a forged or junk report cannot put arbitrary text in the directive or
 *     blocked columns.
 *   - the batch limit, the row cap and the hourly budget refuse what they
 *     should and nothing else, and a known pair always counts.
 *
 * The storage half (SQL) is not covered here. A stand-in for $wpdb would only
 * prove the stand-in, so that half was run against Local's MySQL instead; see
 * docs/NOTES.md, "Build order", step 2.
 *
 *   php tests/test-csp-reports.php
 */

define( 'ABSPATH', '/fake/' );
function __( $text, $domain = '' ) { return $text; }

require_once __DIR__ . '/../includes/class-bssec-plugin.php';
require_once __DIR__ . '/../includes/class-bssec-headers.php';
require_once __DIR__ . '/../includes/class-bssec-csp-reports.php';

$fails = 0;
$ran   = 0;

function it( string $label, bool $ok ): void {
    global $fails, $ran;
    $ran++;
    if ( ! $ok ) $fails++;
    printf( "%-6s %s\n", $ok ? '  ok' : 'FAIL', $label );
}

const SITE = 'shop.test';
const LEGACY = Bssec_Csp_Reports::TYPE_LEGACY;
const BATCH  = Bssec_Csp_Reports::TYPE_REPORTING;

function legacy( array $report ): string {
    return json_encode( [ 'csp-report' => array_merge( [
        'document-uri'       => 'https://shop.test/about/',
        'referrer'           => '',
        'violated-directive' => 'img-src',
        'effective-directive'=> 'img-src',
        'original-policy'    => "img-src 'self'; report-uri /wp-json/bssec/v1/csp-report",
        'disposition'        => 'report',
        'blocked-uri'        => 'https://cdn.example.com/a.png',
        'status-code'        => 200,
    ], $report ) ] );
}

function item( array $body ): array {
    return [
        'type'       => 'csp-violation',
        'age'        => 3,
        'url'        => 'https://shop.test/about/',
        'user_agent' => 'Mozilla/5.0',
        'body'       => array_merge( [
            'documentURL'        => 'https://shop.test/about/',
            'blockedURL'         => 'https://cdn.example.com/a.png',
            'effectiveDirective' => 'img-src',
            'disposition'        => 'report',
            'originalPolicy'     => "img-src 'self'",
            'statusCode'         => 200,
        ], $body ),
    ];
}

function parse( string $body, string $type = LEGACY ): ?array {
    return Bssec_Csp_Reports::parse( $body, $type, SITE );
}

/** Every value of every stored row, joined, for "this must not appear" checks. */
function stored_text( ?array $parsed ): string {
    $out = '';
    foreach ( $parsed['rows'] ?? [] as $row ) $out .= implode( "\n", $row ) . "\n";
    return $out;
}

// --- wiring ------------------------------------------------------------------

echo "\n== the route the header names is the route registered ==\n";
it( 'namespace and path add up to Bssec_Headers::REPORT_ROUTE',
    Bssec_Headers::REPORT_ROUTE === Bssec_Csp_Reports::ROUTE_NAMESPACE . Bssec_Csp_Reports::ROUTE_PATH );

$uninstall = file_get_contents( __DIR__ . '/../uninstall.php' );
it( 'uninstall drops the table this class creates',
    false !== strpos( $uninstall, 'prefix}' . Bssec_Csp_Reports::TABLE ) );
it( 'uninstall clears the prune event',
    false !== strpos( $uninstall, "'" . Bssec_Csp_Reports::PRUNE_HOOK . "'" ) );
it( 'uninstall deletes the stats option',
    false !== strpos( $uninstall, "'" . Bssec_Csp_Reports::STATS_OPTION . "'" ) );
it( 'uninstall deletes the schema version option',
    false !== strpos( $uninstall, "'" . Bssec_Csp_Reports::DB_VERSION_OPTION . "'" ) );

// --- the two formats ---------------------------------------------------------

echo "\n== a legacy report-uri report ==\n";
$p = parse( legacy( [] ) );
it( 'parses to one row', 1 === count( $p['rows'] ?? [] ) );
$row = $p['rows'][0];
it( 'directive', 'img-src' === $row['directive'] );
it( 'blocked is the origin only', 'https://cdn.example.com' === $row['blocked'] );
it( 'sample page is origin and path', 'https://shop.test/about/' === $row['sample_page'] );
it( 'no source file means an empty sample source', '' === $row['sample_source'] );
it( 'the key is the directive and blocked origin', sha1( "img-src\nhttps://cdn.example.com" ) === $row['report_key'] );
it( 'nothing dropped', [] === $p['dropped'] );

echo "\n== a Reporting API batch ==\n";
$p = parse( json_encode( [
    item( [] ),
    item( [ 'effectiveDirective' => 'script-src-elem', 'blockedURL' => 'https://js.stripe.com/v3/', 'sourceFile' => 'https://shop.test/wp-includes/js/jquery.js?ver=3.7' ] ),
] ), BATCH );
it( 'parses to two rows', 2 === count( $p['rows'] ?? [] ) );
it( 'the second is the Stripe script', 'https://js.stripe.com' === $p['rows'][1]['blocked'] );
it( 'its source is the origin only, no path or version',
    'https://shop.test' === $p['rows'][1]['sample_source'] );

it( 'a batch item that is not a CSP report is skipped and counted',
    ( fn( $r ) => 1 === count( $r['rows'] ) && 1 === ( $r['dropped']['not_csp'] ?? 0 ) )(
        parse( json_encode( [ item( [] ), [ 'type' => 'deprecation', 'body' => [ 'id' => 'x' ] ] ] ), BATCH ) ) );
it( 'Reporting API without documentURL falls back to the item url',
    'https://shop.test/about/' === ( parse( json_encode( [ ( fn( $i ) => ( function () use ( $i ) { unset( $i['body']['documentURL'] ); return $i; } )() )( item( [] ) ) ] ), BATCH )['rows'][0]['sample_page'] ?? '' ) );

// --- the planted order key ------------------------------------------------------
//
// Every field a report carries a URL in gets an order page URL with the key in
// the query, the order number in the path, and a fragment. None of it may
// reach a stored column.

echo "\n== a WooCommerce order key planted everywhere never reaches storage ==\n";
$key   = 'wc_order_Zq8XkP3mT7rLs';
$order = '48213';
$planted = parse( legacy( [
    'document-uri' => "https://shop.test/checkout/order-received/$order/?key=$key&utm_source=x#top",
    'blocked-uri'  => "https://pixel.example.net/collect/t.gif?ord=$order&key=$key",
    'source-file'  => "https://shop.test/wp-content/plugins/x/app.js?key=$key",
    'referrer'     => "https://shop.test/checkout/?key=$key",
] ) );
$text = stored_text( $planted );
it( 'the report was stored, so the check below has something to search', 1 === count( $planted['rows'] ?? [] ) );
it( 'the order key appears in no stored column',   false === stripos( $text, $key ) );
it( 'nor the wc_order prefix',                      false === stripos( $text, 'wc_order' ) );
it( 'the order number appears in no stored column', false === strpos( $text, $order ) );
it( 'no query string survives',                     false === strpos( $text, '?' ) );
it( 'no fragment survives',                         false === strpos( $text, '#' ) );
it( 'no path on another site survives',             false === strpos( $text, 't.gif' ) && false === strpos( $text, 'collect' ) );
it( 'no script path survives',                      false === strpos( $text, 'app.js' ) );
it( 'the order page is stored as a pattern',
    'https://shop.test/checkout/order-received/{n}/' === $planted['rows'][0]['sample_page'] );
it( 'the search is real: the same text without redaction would contain the key',
    false !== stripos( json_encode( json_decode( legacy( [ 'document-uri' => "https://shop.test/x/?key=$key" ] ), true ) ), $key ) );

$batch_planted = parse( json_encode( [ item( [
    'documentURL' => "https://shop.test/my-account/view-order/$order/?key=$key",
    'blockedURL'  => "https://pixel.example.net/p?key=$key",
    'sourceFile'  => "https://shop.test/a.js?key=$key",
    'sample'      => "var order = '$key';",
] ) ] ), BATCH );
$btext = stored_text( $batch_planted );
it( 'Reporting API format: stored', 1 === count( $batch_planted['rows'] ?? [] ) );
it( 'Reporting API format: no key, no order number, no script sample',
    false === stripos( $btext, $key ) && false === strpos( $btext, $order ) && false === strpos( $btext, 'var order' ) );
it( 'view-order is stored as a pattern',
    'https://shop.test/my-account/view-order/{n}/' === $batch_planted['rows'][0]['sample_page'] );

echo "\n== redact_page ==\n";
foreach ( [
    'https://shop.test/'                                                     => 'https://shop.test/',
    'https://shop.test'                                                      => 'https://shop.test/',
    'https://shop.test/my-account/lost-password/?key=abc123&login=jason'     => 'https://shop.test/my-account/lost-password/',
    'https://shop.test/checkout/order-pay/77/?pay_for_order=true&key=wc_x'   => 'https://shop.test/checkout/order-pay/{n}/',
    'https://shop.test/download/a1B2c3D4e5F6g7H8i9J0k/'                      => 'https://shop.test/download/{token}/',
    'https://shop.test/a-short-slug/'                                        => 'https://shop.test/a-short-slug/',
    'https://shop.test/product/force-blue-logo-tee-black-2026/'              => 'https://shop.test/product/force-blue-logo-tee-black-2026/',
    'https://shop.test/x/3f2b9c1e-7d4a-4e8b-9a6f-0c1d2e3f4a5b/'              => 'https://shop.test/x/{token}/',
    'https://shop.test/x/abcdefghijklmnopqrstuvwxyz/'                        => 'https://shop.test/x/abcdefghijklmnopqrstuvwxyz/',
    'https://SHOP.test:8443/Shop/'                                           => 'https://shop.test:8443/Shop/',
    'javascript:alert(1)'                                                    => '',
    'not a url'                                                              => '',
    ''                                                                       => '',
] as $in => $want ) {
    it( "'$in' -> '$want'", $want === Bssec_Csp_Reports::redact_page( $in ) );
}
it( 'a very long path is cut to 255 characters',
    255 === strlen( Bssec_Csp_Reports::redact_page( 'https://shop.test/' . str_repeat( 'ab-cd/', 80 ) ) ) );

// --- what gets refused ----------------------------------------------------------

echo "\n== reports refused, and why ==\n";
$drop = fn( string $body, string $type = LEGACY ) => array_keys( parse( $body, $type )['dropped'] ?? [] );

it( 'another site\'s page: wrong_host',
    [ 'wrong_host' ] === $drop( legacy( [ 'document-uri' => 'https://staging.shop.test/about/' ] ) ) );
it( 'the host check ignores case',
    1 === count( parse( legacy( [ 'document-uri' => 'https://SHOP.TEST/about/' ] ) )['rows'] ) );
it( 'no page at all: wrong_host',
    [ 'wrong_host' ] === $drop( legacy( [ 'document-uri' => '' ] ) ) );
it( 'an enforced-policy report: not_report',
    [ 'not_report' ] === $drop( legacy( [ 'disposition' => 'enforce' ] ) ) );
it( 'no disposition at all (older browsers): accepted',
    1 === count( parse( json_encode( [ 'csp-report' => [ 'document-uri' => 'https://shop.test/', 'violated-directive' => 'img-src', 'blocked-uri' => 'https://x.example/' ] ] ) )['rows'] ) );
it( 'an invented directive: unknown_directive',
    [ 'unknown_directive' ] === $drop( legacy( [ 'effective-directive' => 'evil-src' ] ) ) );
it( 'a directive carrying markup: unknown_directive',
    [ 'unknown_directive' ] === $drop( legacy( [ 'effective-directive' => '<script>alert(1)</script>' ] ) ) );
it( 'violated-directive with its value, from an older browser: the name is used',
    'img-src' === ( parse( json_encode( [ 'csp-report' => [ 'document-uri' => 'https://shop.test/', 'violated-directive' => "img-src 'self' data:", 'blocked-uri' => 'https://x.example/' ] ] ) )['rows'][0]['directive'] ?? '' ) );
foreach ( [ 'chrome-extension://abcdef/inject.js', 'moz-extension://1234/x.js', 'safari-web-extension://AB-CD/c.js' ] as $ext ) {
    it( "browser extension noise is dropped: $ext", [ 'extension' ] === $drop( legacy( [ 'blocked-uri' => $ext ] ) ) );
}
it( 'an empty blocked-uri: unrecognized_source',
    [ 'unrecognized_source' ] === $drop( legacy( [ 'blocked-uri' => '' ] ) ) );
it( 'a blocked-uri that is not a URL: unrecognized_source',
    [ 'unrecognized_source' ] === $drop( legacy( [ 'blocked-uri' => 'some words' ] ) ) );
it( 'a blocked-uri that is an array: unrecognized_source, not a fatal',
    [ 'unrecognized_source' ] === $drop( json_encode( [ 'csp-report' => [ 'document-uri' => 'https://shop.test/', 'effective-directive' => 'img-src', 'blocked-uri' => [ 'x' ] ] ] ) ) );

echo "\n== bodies that are not reports at all ==\n";
it( 'not JSON',                          null === parse( 'not json' ) );
it( 'JSON but not an object',            null === parse( '"a string"' ) );
it( 'legacy without csp-report',         null === parse( json_encode( [ 'something' => [] ] ) ) );
// Until 0.3.2 this said a lone object must be refused. Safari sends exactly
// that, so a lone object is now one report; with no body it counts as not_csp.
it( 'a lone report object with no body is read as one report and counted not_csp',
    ( fn( $p ) => is_array( $p ) && [] === $p['rows'] && 1 === ( $p['dropped']['not_csp'] ?? 0 ) )(
        parse( json_encode( [ 'type' => 'csp-violation' ] ), BATCH ) ) );
it( 'nested deeper than any report is', null === parse( str_repeat( '[', 20 ) . str_repeat( ']', 20 ), BATCH ) );
it( 'the shape decides, not the label: a legacy body under the batch type is read',
    1 === count( parse( legacy( [] ), BATCH )['rows'] ?? [] ) );
it( 'an object that is neither a legacy report nor a report is still refused',
    null === parse( json_encode( [ 'hello' => 'world' ] ), BATCH ) );

echo "\n== Safari 27: one Reporting API report alone, labeled as legacy ==\n";
// Captured from Safari 27.0.1 on Local Biscuit Dev, November 9, 2026, with the
// host changed. All 67 of its requests looked like this, and 0.3.1 refused
// every one as unreadable because it read by the label.
$safari_data = '{"type":"csp-violation","url":"https://shop.test/","body":{"documentURL":"https://shop.test/","disposition":"report","referrer":"","effectiveDirective":"img-src","blockedURL":"data","originalPolicy":"img-src \'none\'; report-uri https://shop.test/wp-json/bssec/v1/csp-report; report-to bssec","statusCode":200,"sample":""}}';
$safari_url  = '{"type":"csp-violation","url":"https://shop.test/work/","body":{"documentURL":"https://shop.test/work/","disposition":"report","referrer":"","effectiveDirective":"img-src","blockedURL":"https://shop.test:443/wp-content/uploads/2026/10/hero.jpg","originalPolicy":"img-src \'none\'","statusCode":200,"sample":""}}';
$sd = parse( $safari_data, LEGACY );
it( 'is read', 1 === count( $sd['rows'] ?? [] ) );
it( 'its bare "data" becomes data:', 'data:' === ( $sd['rows'][0]['blocked'] ?? '' ) );
it( 'its directive is img-src', 'img-src' === ( $sd['rows'][0]['directive'] ?? '' ) );
$su = parse( $safari_url, LEGACY );
it( 'a Safari address with :443 is stored without it',
    'https://shop.test' === ( $su['rows'][0]['blocked'] ?? '' ) );
it( 'so Safari and Chrome reporting the same image give the same key',
    ( $su['rows'][0]['report_key'] ?? 'a' ) === ( parse( json_encode( [ item( [ 'blockedURL' => 'https://shop.test/wp-content/uploads/2026/10/hero.jpg' ] ) ] ), BATCH )['rows'][0]['report_key'] ?? 'b' ) );
it( 'the same body under the batch type reads the same',
    $sd['rows'] === ( parse( $safari_data, BATCH )['rows'] ?? null ) );

echo "\n== default ports are dropped, others kept ==\n";
foreach ( [
    'https://a.test:443/x' => 'https://a.test',
    'http://a.test:80/x'   => 'http://a.test',
    'wss://a.test:443/x'   => 'wss://a.test',
    'ws://a.test:80/x'     => 'ws://a.test',
    'https://a.test:80/x'  => 'https://a.test:80',
    'http://a.test:443/x'  => 'http://a.test:443',
    'https://a.test:8443/' => 'https://a.test:8443',
] as $in => $want ) {
    it( "'$in' -> '$want'", $want === Bssec_Csp_Reports::origin_of( $in ) );
}

echo "\n== the batch limit ==\n";
$big = parse( json_encode( array_map( fn( $i ) => item( [ 'blockedURL' => "https://h$i.example/" ] ), range( 1, 14 ) ) ), BATCH );
it( 'at most ten sources from one request', Bssec_Csp_Reports::MAX_PER_REQUEST === count( $big['rows'] ) );
it( 'the other four are counted as over_batch', 4 === ( $big['dropped']['over_batch'] ?? 0 ) );
it( 'and they are the last four, not a random four', 'https://h10.example' === end( $big['rows'] )['blocked'] );

echo "\n== repeats fold before the limit (0.3.1) ==\n";
// The bundle Chrome sends: one report per image, nearly all the same pair.
// On biscuitstudios.com, 0.3.0 refused 153 against 2 kept.
$same = parse( json_encode( array_map(
    fn( $i ) => item( [ 'documentURL' => "https://shop.test/page-$i/", 'blockedURL' => "https://shop.test/img/$i.jpg" ] ),
    range( 1, 40 )
) ), BATCH );
it( 'forty reports of one pair are one row', 1 === count( $same['rows'] ) );
it( 'carrying all forty in its count', 40 === ( $same['rows'][0]['hits'] ?? 0 ) );
it( 'with nothing refused', [] === $same['dropped'] );
it( 'and the latest page as its sample', 'https://shop.test/page-40/' === $same['rows'][0]['sample_page'] );

$mixed = [];
foreach ( range( 1, 3 ) as $round ) {
    foreach ( range( 1, 12 ) as $i ) {
        $mixed[] = item( [ 'blockedURL' => "https://h$i.example/x-$round.png" ] );
    }
}
$m = parse( json_encode( $mixed ), BATCH );
it( 'twelve pairs, each three times, interleaved: ten rows kept', 10 === count( $m['rows'] ) );
it( 'each kept row counts all three of its reports',
    [ 3 ] === array_values( array_unique( array_column( $m['rows'], 'hits' ) ) ) );
it( 'the two pairs over the limit count as six refused reports, not two',
    6 === ( $m['dropped']['over_batch'] ?? 0 ) );
it( 'the kept ten are the first ten seen',
    'https://h1.example' === $m['rows'][0]['blocked'] && 'https://h10.example' === $m['rows'][9]['blocked'] );

$src = parse( json_encode( [
    item( [ 'sourceFile' => 'https://shop.test/a.js' ] ),
    item( [] ),
] ), BATCH );
it( 'a later repeat with no source does not blank the source already seen',
    'https://shop.test' === $src['rows'][0]['sample_source'] && 2 === $src['rows'][0]['hits'] );

$ext = parse( json_encode( array_merge(
    array_map( fn( $i ) => item( [ 'blockedURL' => "chrome-extension://abc/$i.js" ] ), range( 1, 5 ) ),
    [ item( [] ) ]
) ), BATCH );
it( 'refusals are still counted per report, folded or not',
    5 === ( $ext['dropped']['extension'] ?? 0 ) && 1 === count( $ext['rows'] ) );
it( 'a single legacy report is one row with a count of one',
    1 === ( parse( legacy( [] ) )['rows'][0]['hits'] ?? 0 ) );

echo "\n== every refusal has words on the screen ==\n";
$labels = Bssec_Csp_Reports::drop_labels();
it( 'every drop reason has a label',
    [] === array_diff( Bssec_Csp_Reports::DROP_REASONS, array_keys( $labels ) ) );
it( 'and no label is for a reason that does not exist',
    [] === array_diff( array_keys( $labels ), Bssec_Csp_Reports::DROP_REASONS ) );

// --- the blocked column -----------------------------------------------------------

echo "\n== what the blocked column can hold ==\n";
foreach ( [
    'inline'                                   => 'inline',
    'eval'                                     => 'eval',
    'wasm-eval'                                => 'wasm-eval',
    'INLINE'                                   => 'inline',
    'data'                                     => 'data:',
    'data:image/png;base64,iVBORw0KGgoAAAANSU' => 'data:',
    'blob'                                     => 'blob:',
    'blob:https://shop.test/2b8c-44e1'         => 'blob:',
    'about:blank'                              => 'about:',
    'https://Fonts.GSTATIC.com/s/x.woff2'      => 'https://fonts.gstatic.com',
    'http://insecure.example/x.js'             => 'http://insecure.example',
    'wss://chat.example:8443/socket?t=secret'  => 'wss://chat.example:8443',
    'https://user:pass@host.example/'          => 'https://host.example',
    'https://bad host.example/'                => '',
    'https://'                                 => '',
] as $in => $want ) {
    it( "'$in' -> '$want'", $want === Bssec_Csp_Reports::normalize_blocked( $in ) );
}

echo "\n== deduplication ==\n";
$a = parse( legacy( [ 'document-uri' => 'https://shop.test/one/', 'blocked-uri' => 'https://cdn.example.com/a.png' ] ) )['rows'][0];
$b = parse( legacy( [ 'document-uri' => 'https://shop.test/two/', 'blocked-uri' => 'https://cdn.example.com/b.png?v=2' ] ) )['rows'][0];
$c = parse( legacy( [ 'effective-directive' => 'script-src-elem', 'blocked-uri' => 'https://cdn.example.com/a.js' ] ) )['rows'][0];
it( 'the same origin under the same directive from two pages is one key', $a['report_key'] === $b['report_key'] );
it( 'the same origin under a different directive is a different key', $a['report_key'] !== $c['report_key'] );

// --- the limits ------------------------------------------------------------------

echo "\n== decide(): a known pair always counts, a new one needs room ==\n";
$cap    = Bssec_Csp_Reports::ROW_CAP;
$budget = Bssec_Csp_Reports::NEW_ROWS_PER_HOUR;
it( 'a known pair is updated',                         'update' === Bssec_Csp_Reports::decide( true, 10, 0 ) );
it( 'a known pair is updated even at the row cap',     'update' === Bssec_Csp_Reports::decide( true, $cap, $budget ) );
it( 'a new pair with room is inserted',                'insert' === Bssec_Csp_Reports::decide( false, $cap - 1, $budget - 1 ) );
it( 'a new pair at the row cap is refused',            'over_cap' === Bssec_Csp_Reports::decide( false, $cap, 0 ) );
it( 'a new pair over the hourly budget is refused',    'over_budget' === Bssec_Csp_Reports::decide( false, 10, $budget ) );
it( 'every refusal decide() can return is a counted drop reason',
    in_array( 'over_cap', Bssec_Csp_Reports::DROP_REASONS, true ) && in_array( 'over_budget', Bssec_Csp_Reports::DROP_REASONS, true ) );
it( 'the numbers are the ones Jason approved',
    500 === $cap && 50 === $budget && 30 === Bssec_Csp_Reports::KEEP_DAYS
    && 262144 === Bssec_Csp_Reports::MAX_BODY_BYTES && 10 === Bssec_Csp_Reports::MAX_PER_REQUEST
    && 200 === Bssec_Csp_Reports::MAX_REPORTS_PARSED );

echo "\n== the request size limit fits a real Chrome bundle (0.3.1) ==\n";
// 16 KB in 0.3.0 refused a 40-report bundle whole on Local's MySQL. Build a
// bundle the way Chrome does, with a realistic store policy repeated in every
// report and a real user agent, and check it fits.
$policy = "default-src 'self'; script-src 'self' 'unsafe-inline' https://use.typekit.net https://www.googletagmanager.com https://js.stripe.com; style-src 'self' 'unsafe-inline' https://use.typekit.net https://p.typekit.net; img-src 'self' data: https://images.printify.com; font-src 'self' https://use.typekit.net; frame-src https://js.stripe.com https://forceblue.givecloud.co; connect-src 'self' https://api.stripe.com; report-uri https://shop.test/wp-json/bssec/v1/csp-report; report-to bssec";
$chrome = json_encode( array_map( fn( $i ) => array_merge( item( [
    'blockedURL'     => "https://cdn.example.com/wp-content/uploads/2026/10/product-photo-$i-1536x1024.jpg",
    'documentURL'    => "https://shop.test/product/force-blue-logo-tee-black-$i/",
    'originalPolicy' => $policy,
    'referrer'       => 'https://shop.test/shop/',
    'sample'         => '',
    'lineNumber'     => 0,
    'columnNumber'   => 0,
] ), [ 'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36' ] ), range( 1, 100 ) ) );
it( 'a 100-report bundle with a realistic policy is over the old 16 KB', strlen( $chrome ) > 16384 );
it( 'and inside the new limit', strlen( $chrome ) <= Bssec_Csp_Reports::MAX_BODY_BYTES );
it( 'and parses to one folded row of 100',
    ( fn( $p ) => 1 === count( $p['rows'] ) && 100 === $p['rows'][0]['hits'] && [] === $p['dropped'] )( parse( $chrome, BATCH ) ) );

echo "\n== at most 200 reports are parsed from one request ==\n";
$flood = parse( json_encode( array_map( fn( $i ) => item( [] ), range( 1, 250 ) ) ), BATCH );
it( 'the first 200 are parsed and folded', 200 === ( $flood['rows'][0]['hits'] ?? 0 ) );
it( 'the other 50 are refused unread and counted', 50 === ( $flood['dropped']['over_batch'] ?? 0 ) );
$flood_mixed = parse( json_encode( array_merge(
    array_map( fn( $i ) => item( [] ), range( 1, 205 ) ),
    array_map( fn( $i ) => item( [ 'blockedURL' => "https://late-$i.example/" ] ), range( 1, 3 ) )
) ), BATCH );
it( 'a new source past the 200th report is not stored',
    1 === count( $flood_mixed['rows'] ) && 8 === ( $flood_mixed['dropped']['over_batch'] ?? 0 ) );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
