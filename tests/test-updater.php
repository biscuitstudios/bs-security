<?php
/**
 * Tests for what the updater tells a site about a new release, beyond the zip:
 * "Tested up to" and the upgrade notice.
 *
 * Until 0.4.0 the update offer carried neither, so the session that tracks
 * plugin updates could see that Biscuit Security changed but not what changed.
 * Both now travel in the release body as two plain lines that release.yml
 * writes from readme.txt, and Bssec_Updater::release_meta() reads them back.
 *
 * Also guards the readme itself: the version in the plugin header must have an
 * upgrade notice that says whether it touches the headers. release.yml refuses
 * to publish without one; this catches it on the push before the tag.
 *
 *   php tests/test-updater.php
 */

define( 'ABSPATH', '/fake/' );
define( 'HOUR_IN_SECONDS', 3600 );
function __( $t, $d = '' ) { return $t; }
function plugin_basename( $f ) { return 'bs-security/bs-security.php'; }

require_once __DIR__ . '/../includes/class-bssec-updater.php';

$fails = 0;
$ran   = 0;

function it( string $label, bool $ok ): void {
    global $fails, $ran;
    $ran++;
    if ( ! $ok ) $fails++;
    printf( "%-6s %s\n", $ok ? '  ok' : 'FAIL', $label );
}

// A release body as release.yml builds it and GitHub then publishes it: the
// readme changelog, the two lines, and GitHub's generated notes underneath.
$body = "* New: the collected CSP reports are listed on the settings screen.\n"
      . "* New: \"Send a test report\".\n"
      . "\n"
      . "Tested up to: 7.1\n"
      . "\n"
      . "Upgrade notice: Headers: unchanged. Adds a list of collected CSP reports.\n"
      . "\n"
      . "## What's Changed\n"
      . "\n"
      . "**Full Changelog**: https://github.com/biscuitstudios/bs-security/compare/v0.3.2...v0.4.0";

echo "\n== reading the two lines back ==\n";
$m = Bssec_Updater::release_meta( $body );
it( 'tested up to', '7.1' === $m['tested'] );
it( 'the upgrade notice, whole', 'Headers: unchanged. Adds a list of collected CSP reports.' === $m['upgrade_notice'] );
it( 'a three-part version is read too',
    '7.1.4' === Bssec_Updater::release_meta( "Tested up to: 7.1.4\n" )['tested'] );
it( 'a body from before 0.4.0 gives two empty fields, not a guess',
    [ 'tested' => '', 'upgrade_notice' => '' ] === Bssec_Updater::release_meta( "* Fix: something.\n\n**Full Changelog**: https://x" ) );
it( 'a version that is not a version is left empty',
    '' === Bssec_Updater::release_meta( "Tested up to: latest\n" )['tested'] );
it( 'the label is only read at the start of a line',
    '' === Bssec_Updater::release_meta( "* Note: see Tested up to: 7.1 in the readme\n" )['tested'] );
it( 'an empty notice line is empty',
    '' === Bssec_Updater::release_meta( "Upgrade notice:   \n" )['upgrade_notice'] );
it( 'markup in a notice is reduced to its text (strip_tags keeps what was between tags)',
    'Headers: changed. Bold.x' === Bssec_Updater::release_meta( "Upgrade notice: Headers: changed. <b>Bold</b>.<script>x</script>\n" )['upgrade_notice'] );
it( 'no tag survives in a notice',
    ! preg_match( '/[<>]/', Bssec_Updater::release_meta( "Upgrade notice: <img src=x onerror=alert(1)> hi\n" )['upgrade_notice'] ) );
$long = Bssec_Updater::release_meta( 'Upgrade notice: Headers: unchanged. ' . str_repeat( 'word ', 100 ) . "\n" )['upgrade_notice'];
it( 'a notice over 300 characters is cut to 300', 300 === strlen( $long ) && '...' === substr( $long, -3 ) );
it( 'Windows line endings do not leak into the notice',
    'Headers: unchanged. X.' === Bssec_Updater::release_meta( "Upgrade notice: Headers: unchanged. X.\r\n" )['upgrade_notice'] );

echo "\n== the modal does not repeat them ==\n";
$notes = Bssec_Updater::strip_meta_lines( $body );
it( 'both lines are gone from the notes', false === stripos( $notes, 'Tested up to:' ) && false === stripos( $notes, 'Upgrade notice:' ) );
it( 'the changelog itself is untouched', 0 === strpos( $notes, '* New: the collected CSP reports are listed' ) );
it( 'and so is GitHub\'s section', false !== strpos( $notes, "## What's Changed" ) );

echo "\n== readme.txt carries a notice for the version being released ==\n";
$main   = file_get_contents( __DIR__ . '/../bs-security.php' );
$readme = file_get_contents( __DIR__ . '/../readme.txt' );
preg_match( '/^\s*\*\s*Version:\s*([0-9.]+)/m', $main, $vm );
$version = $vm[1] ?? '';
it( 'the plugin header has a version', '' !== $version );

/** One section of readme.txt, as release.yml reads it: "== Name ==" to the next. */
function readme_entry( string $readme, string $section, string $version ): string {
    $in = false; $copy = false; $out = [];
    foreach ( preg_split( '/\R/', $readme ) as $line ) {
        $line = rtrim( $line );
        if ( preg_match( '/^== /', $line ) ) { $in = ( "== $section ==" === $line ); $copy = false; continue; }
        if ( ! $in ) continue;
        if ( "= $version =" === $line ) { $copy = true; continue; }
        if ( preg_match( '/^= [0-9]/', $line ) ) { $copy = false; }
        if ( $copy && '' !== $line ) $out[] = $line;
    }
    return implode( ' ', $out );
}

$notice = readme_entry( $readme, 'Upgrade Notice', $version );
it( "an upgrade notice exists for $version", '' !== $notice );
it( 'it says whether the release touches the headers',
    (bool) preg_match( '/^Headers: (?:changed|unchanged)\./', $notice ) );
it( 'it fits in 300 characters', strlen( $notice ) <= 300 );
it( "a changelog entry exists for $version", '' !== readme_entry( $readme, 'Changelog', $version ) );
it( 'the changelog entry does not swallow the notice',
    false === strpos( readme_entry( $readme, 'Changelog', $version ), 'Headers:' ) );
it( 'Tested up to is a version', (bool) preg_match( '/^Tested up to:\s*[0-9]+\.[0-9]+(?:\.[0-9]+)?\s*$/m', $readme ) );

echo "\n== the modal's own changelog reader skips the notice section ==\n";
$updater = new Bssec_Updater( __DIR__ . '/../bs-security.php' );
$reader  = new ReflectionMethod( Bssec_Updater::class, 'readme_changelog' );
$reader->setAccessible( true );
$shipped = $reader->invoke( $updater );
it( "the shipped changelog has $version", isset( $shipped[ $version ] ) );
it( 'and it is the changelog, not the notice',
    // A bullet, not "* New:" as it was until 0.4.1: a release can lead with a
    // Change or a Fix, and the notice is never a bullet, which is the point.
    isset( $shipped[ $version ] ) && false === strpos( $shipped[ $version ], 'Headers:' ) && 0 === strpos( $shipped[ $version ], '* ' ) );

echo "\n== every log line carries this plugin's tag ==\n";
// The updater was copied from bs-maintenance and logged as [BSM] until 0.4.0,
// so a search of a PHP log for [BSSEC] missed every update failure.
$log_calls = [];
foreach ( array_merge( glob( __DIR__ . '/../includes/*.php' ), glob( __DIR__ . '/../admin/*.php' ), [ __DIR__ . '/../bs-security.php' ] ) as $file ) {
    preg_match_all( '/error_log\(\s*([\'"])(.*?)\1/', file_get_contents( $file ), $mm );
    foreach ( $mm[2] as $first ) $log_calls[] = basename( $file ) . ': ' . $first;
}
it( 'the scan found the log calls (six when this was written)', count( $log_calls ) >= 6 );
$untagged = array_filter( $log_calls, fn( $c ) => ! preg_match( '/: \[BSSEC\] /', $c ) );
it( 'every one starts with [BSSEC]' . ( $untagged ? ': ' . implode( '; ', $untagged ) : '' ), [] === $untagged );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
