<?php
/**
 * Smoke tests for Bssec_Hardening's decisions and the settings migration.
 *
 * What is being pinned down:
 *
 *   - which REST routes are closed, and that the rest of the API is not. The
 *     whole reason this exists instead of Perfmatters' "Disable REST API when
 *     logged out" is that Ajax Load More needs the API for visitors.
 *   - that masking a login error keeps the error code. Lockout and logging
 *     plugins read the code, so changing it would blind them.
 *   - that the lost-password screen only fakes success for "no such account",
 *     and only on wp-login.php.
 *   - that the file editor is refused with the same three capabilities core
 *     uses for DISALLOW_FILE_EDIT, and nothing else.
 *   - that a site moving from Biscuit Security Headers keeps its header
 *     settings and gets the hardening defaults.
 *
 * Plain PHP with hand-rolled stubs, so there is nothing to install. Run:
 *
 *   php tests/test-hardening.php
 */

define( 'ABSPATH', '/fake/' );

// --- WP stubs: only what the code under test actually touches ---------------

function __( $t, $d = '' )         { return $t; }
function esc_html__( $t, $d = '' ) { return htmlspecialchars( (string) $t, ENT_QUOTES, 'UTF-8' ); }
function esc_url( $u )             { return htmlspecialchars( (string) $u, ENT_QUOTES, 'UTF-8' ); }
function wp_lostpassword_url()     { return 'https://example.test/wp-login.php?action=lostpassword'; }
function is_ssl()                  { return true; }

/** Enough of WP_Error for codes, messages and data, in insertion order. */
class WP_Error {
    public $errors = [];
    public $error_data = [];
    public function __construct( $code = '', $message = '', $data = '' ) {
        if ( '' !== $code ) $this->add( $code, $message, $data );
    }
    public function add( $code, $message, $data = '' ) {
        $this->errors[ $code ][] = $message;
        if ( '' !== $data && null !== $data ) $this->error_data[ $code ] = $data;
    }
    public function get_error_codes()             { return array_keys( $this->errors ); }
    public function get_error_messages( $code )   { return $this->errors[ $code ] ?? []; }
    public function get_error_data( $code = '' )  { return $this->error_data[ $code ] ?? null; }
}

require_once __DIR__ . '/../includes/class-bssec-plugin.php';
require_once __DIR__ . '/../includes/class-bssec-headers.php';
require_once __DIR__ . '/../includes/class-bssec-hardening.php';
require_once __DIR__ . '/../includes/class-bssec-activator.php';

// --- harness ---------------------------------------------------------------

$fails = 0;
$ran   = 0;

function it( string $label, bool $ok ): void {
    global $fails, $ran;
    $ran++;
    if ( ! $ok ) $fails++;
    printf( "%-6s %s\n", $ok ? '  ok' : 'FAIL', $label );
}

// --- REST users routes -----------------------------------------------------

echo "\n== the users routes are closed to logged-out visitors ==\n";
foreach ( [
    '/wp/v2/users',
    '/wp/v2/users/',
    '/wp/v2/users/1',
    '/wp/v2/users/me',
    '/WP/V2/USERS',          // core matches routes case-insensitively
    '//wp/v2/users',
] as $route ) {
    it( sprintf( '%-18s blocked when logged out', $route ), Bssec_Hardening::should_block_rest( $route, false ) );
}

echo "\n== and only those ==\n";
foreach ( [
    '/wp/v2/posts',
    '/wp/v2/pages/12',
    '/wp/v2/usersettings',   // a different route that merely starts the same
    '/ajaxloadmore/posts',
    '/wp/v2/search',
    '/',
] as $route ) {
    it( sprintf( '%-20s left alone', $route ), ! Bssec_Hardening::should_block_rest( $route, false ) );
}

echo "\n== logged-in users keep the users routes ==\n";
it( 'the block editor author list still loads', ! Bssec_Hardening::should_block_rest( '/wp/v2/users', true ) );
it( 'a logged-in /users/me still works',        ! Bssec_Hardening::should_block_rest( '/wp/v2/users/me', true ) );

// --- ?author=N -------------------------------------------------------------

echo "\n== ?author= lookups ==\n";
it( '?author=1 is blocked when logged out',       Bssec_Hardening::should_block_author_query( [ 'author' => '1' ], false ) );
it( '?author[]=1 is blocked too',                 Bssec_Hardening::should_block_author_query( [ 'author' => [ '1' ] ], false ) );
it( 'logged in, it is left alone',               ! Bssec_Hardening::should_block_author_query( [ 'author' => '1' ], true ) );
it( 'no author parameter, nothing happens',      ! Bssec_Hardening::should_block_author_query( [ 's' => 'hello' ], false ) );
it( 'an empty ?author= is ignored, as core does', ! Bssec_Hardening::should_block_author_query( [ 'author' => '' ], false ) );

// --- sitemap and oEmbed ----------------------------------------------------

echo "\n== sitemap and oEmbed ==\n";
it( 'the users sitemap provider is dropped', false === Bssec_Hardening::drop_user_sitemap( 'provider', 'users' ) );
it( 'the posts provider is kept',            'provider' === Bssec_Hardening::drop_user_sitemap( 'provider', 'posts' ) );

$embed = Bssec_Hardening::strip_oembed_author( [
    'title' => 'A post', 'author_name' => 'Jason', 'author_url' => 'https://example.test/author/jason/',
] );
it( 'oEmbed loses the author name', ! isset( $embed['author_name'] ) );
it( 'oEmbed loses the author URL',  ! isset( $embed['author_url'] ) );
it( 'oEmbed keeps everything else', 'A post' === $embed['title'] );
it( 'a non-array oEmbed value passes through', false === Bssec_Hardening::strip_oembed_author( false ) );

// --- login errors ----------------------------------------------------------

echo "\n== login errors ==\n";
$generic = 'GENERIC';

$bad_user = new WP_Error( 'invalid_username', 'Unknown username jason.' );
$masked   = Bssec_Hardening::mask_error( $bad_user, $generic );
it( 'an unknown username gets the generic message', [ $generic ] === $masked->get_error_messages( 'invalid_username' ) );
it( 'and keeps its code', [ 'invalid_username' ] === $masked->get_error_codes() );

$bad_pass = new WP_Error( 'incorrect_password', 'The password you entered for the username jason is incorrect.' );
$masked   = Bssec_Hardening::mask_error( $bad_pass, $generic );
it( 'a wrong password gets the same message', [ $generic ] === $masked->get_error_messages( 'incorrect_password' ) );
it( 'the username is no longer in any message',
    false === strpos( implode( ' ', $masked->get_error_messages( 'incorrect_password' ) ), 'jason' ) );

$bad_email = new WP_Error( 'invalid_email', 'Unknown email address.' );
it( 'an unknown email gets the same message',
    [ $generic ] === Bssec_Hardening::mask_error( $bad_email, $generic )->get_error_messages( 'invalid_email' ) );

$empty = new WP_Error( 'empty_password', 'The password field is empty.' );
it( 'an empty-field error is returned untouched', $empty === Bssec_Hardening::mask_error( $empty, $generic ) );

$mixed = new WP_Error( 'incorrect_password', 'leaky', [ 'status' => 403 ] );
$mixed->add( 'too_many_retries', 'Locked out for 20 minutes.' );
$mixed->add( 'invalid_username', 'also leaky' );
$masked = Bssec_Hardening::mask_error( $mixed, $generic );
it( 'another plugin\'s error keeps its own wording',
    [ 'Locked out for 20 minutes.' ] === $masked->get_error_messages( 'too_many_retries' ) );
it( 'two masked codes print the message once',
    1 === substr_count( implode( '|', array_merge( ...array_map( [ $masked, 'get_error_messages' ], $masked->get_error_codes() ) ) ), $generic ) );
it( 'error data travels with the code', [ 'status' => 403 ] === $masked->get_error_data( 'incorrect_password' ) );

$user = new stdClass();
it( 'a successful login passes straight through', $user === Bssec_Hardening::mask_error( $user, $generic ) );
it( 'null passes straight through',              null === Bssec_Hardening::mask_error( null, $generic ) );

$message = Bssec_Hardening::generic_login_message();
it( 'the real message links to lost password', false !== strpos( $message, 'action=lostpassword' ) );
it( 'and names neither the username nor the password as the problem',
    false !== strpos( $message, 'username, email address or password is incorrect' ) );

// --- lost password ---------------------------------------------------------

echo "\n== lost password ==\n";
it( 'an unknown username on wp-login.php fakes success',
    Bssec_Hardening::should_fake_reset( new WP_Error(), false, 'wp-login.php' ) );
it( 'an unknown email on wp-login.php fakes success',
    Bssec_Hardening::should_fake_reset( new WP_Error( 'invalid_email', 'x' ), false, 'wp-login.php' ) );
it( 'a real account is left to core, which sends the email',
    ! Bssec_Hardening::should_fake_reset( new WP_Error(), new stdClass(), 'wp-login.php' ) );
it( 'an empty field still shows its error',
    ! Bssec_Hardening::should_fake_reset( new WP_Error( 'empty_username', 'x' ), false, 'wp-login.php' ) );
$captcha = new WP_Error( 'invalid_email', 'x' );
$captcha->add( 'captcha_failed', 'y' );
it( 'another plugin\'s error (a CAPTCHA) still shows',
    ! Bssec_Hardening::should_fake_reset( $captcha, false, 'wp-login.php' ) );
it( 'off wp-login.php (WooCommerce, the admin) nothing changes',
    ! Bssec_Hardening::should_fake_reset( new WP_Error(), false, 'index.php' ) );
it( 'a non-WP_Error is never treated as "no account"',
    ! Bssec_Hardening::should_fake_reset( null, false, 'wp-login.php' ) );

// --- file editor -----------------------------------------------------------

echo "\n== file editor ==\n";
foreach ( [ 'edit_files', 'edit_plugins', 'edit_themes' ] as $cap ) {
    it( "$cap is refused", in_array( 'do_not_allow', Bssec_Hardening::deny_file_edit( [ $cap ], $cap ), true ) );
}
foreach ( [ 'update_plugins', 'install_plugins', 'activate_plugins', 'edit_theme_options', 'edit_posts' ] as $cap ) {
    it( "$cap is untouched", [ $cap ] === Bssec_Hardening::deny_file_edit( [ $cap ], $cap ) );
}
it( 'a non-array caps value does not fatal', [ 'do_not_allow' ] === Bssec_Hardening::deny_file_edit( null, 'edit_themes' ) );

// --- settings --------------------------------------------------------------

echo "\n== defaults ==\n";
$d = Bssec_Plugin::defaults();
it( 'user enumeration blocking is on',  true === $d['block_user_enumeration'] );
it( 'login errors are masked',          true === $d['mask_login_errors'] );
it( 'the file editor is off',           true === $d['disable_file_editor'] );
it( 'author-page redirect is off',      false === $d['redirect_author_archives'] );
it( 'every hardening key has a default', [] === array_diff( Bssec_Plugin::HARDENING_KEYS, array_keys( $d ) ) );

echo "\n== moving from Biscuit Security Headers ==\n";
$legacy = [
    'referrer_policy'          => true,
    'referrer_policy_value'    => 'no-referrer',
    'permissions_policy'       => true,
    'permissions_policy_block' => [ 'camera' ],
    'frame_options'            => false,
    'frame_options_value'      => 'DENY',
    'content_type_options'     => true,
    'hsts'                     => true,
    'hsts_max_age'             => 86400,
    'csp'                      => true,
    'csp_value'                => "default-src 'self'",
    'some_key_from_elsewhere'  => 'x',
];
$moved = Bssec_Activator::initial_settings( $legacy );
foreach ( array_keys( $legacy ) as $key ) {
    if ( 'some_key_from_elsewhere' === $key ) continue;
    it( "$key carries over", $legacy[ $key ] === $moved[ $key ] );
}
it( 'an unknown key from the old row is not carried', ! isset( $moved['some_key_from_elsewhere'] ) );
foreach ( Bssec_Plugin::HARDENING_KEYS as $key ) {
    it( "$key takes its default", $d[ $key ] === $moved[ $key ] );
}
it( 'no old settings: a fresh install gets the defaults', $d === Bssec_Activator::initial_settings( false ) );
it( 'a corrupt old row is ignored, not merged',           $d === Bssec_Activator::initial_settings( 'garbage' ) );
it( 'the old option name is the one bs-security-headers used', 'bssh_settings' === Bssec_Activator::LEGACY_OPTION );
it( 'and differs from this plugin\'s', Bssec_Activator::LEGACY_OPTION !== Bssec_Plugin::OPTION );

echo "\n" . ( $fails
    ? "$fails of $ran checks FAILED\n"
    : "all $ran checks passed\n" );
exit( $fails ? 1 : 0 );
