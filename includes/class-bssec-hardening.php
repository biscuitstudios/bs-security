<?php
/**
 * Hardening: the protections that are not headers.
 *
 * Three settings, each a handful of WordPress hooks. Nothing is written to
 * .htaccess, wp-config.php or any file on disk, so deactivating the plugin
 * removes every one of them at once, the same as the headers.
 *
 * Every decision lives in a static method that takes plain values, so
 * tests/test-hardening.php can pin it down without WordPress. The instance
 * methods only read the request and hand over to those.
 *
 * Deliberately not here, because something else on Biscuit's sites already
 * does it and two things doing one job cannot be told apart:
 *
 *   - XML-RPC and the WordPress version tag: Perfmatters.
 *   - X-Content-Type-Options: Kinsta and xCloud.
 *   - Two-factor: WP 2FA.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Hardening {

    /**
     * Login error codes whose wording says whether an account exists.
     *
     * Core's messages name the username back ("The password you entered for
     * the username jason is incorrect") or say there is no such user, which
     * turns the login form into a lookup service.
     */
    public const MASKED_LOGIN_CODES = [ 'invalid_username', 'invalid_email', 'incorrect_password' ];

    /**
     * The capabilities core's map_meta_cap() refuses when DISALLOW_FILE_EDIT is
     * set. The same three and nothing more, so this behaves exactly like the
     * constant without touching wp-config.php, and without colliding with a
     * site that already defines it.
     */
    public const FILE_EDIT_CAPS = [ 'edit_files', 'edit_plugins', 'edit_themes' ];

    public function init(): void {
        $settings = Bssec_Plugin::settings();

        if ( ! empty( $settings['block_user_enumeration'] ) ) {
            add_filter( 'rest_pre_dispatch', [ $this, 'block_rest_users' ], 10, 3 );
            // Priority 1, ahead of redirect_canonical() at 10, which is what
            // turns ?author=1 into /author/jason/ and hands over the username.
            add_action( 'template_redirect', [ $this, 'block_author_query' ], 1 );
            add_filter( 'wp_sitemaps_add_provider', [ self::class, 'drop_user_sitemap' ], 10, 2 );
            add_filter( 'oembed_response_data', [ self::class, 'strip_oembed_author' ] );
        }

        if ( ! empty( $settings['redirect_author_archives'] ) ) {
            add_action( 'template_redirect', [ $this, 'redirect_author_archive' ], 1 );
        }

        if ( ! empty( $settings['mask_login_errors'] ) ) {
            // Late, so every core and plugin authenticator has had its say.
            add_filter( 'authenticate', [ $this, 'mask_login_error' ], 999 );
            add_action( 'lostpassword_post', [ $this, 'mask_lostpassword' ], 999, 2 );
        }

        if ( ! empty( $settings['disable_file_editor'] ) ) {
            add_filter( 'map_meta_cap', [ self::class, 'deny_file_edit' ], 10, 2 );
        }
    }

    // ------------------------------------------------------ user enumeration

    /**
     * Answer the users routes with "no route" for anyone not logged in.
     *
     * Runs after REST authentication, so a logged-in editor (the block editor's
     * author dropdown) and an application password both still get through.
     * Only the users routes: Ajax Load More and other front-end features use
     * the REST API for logged-out visitors, which is why Perfmatters' "Disable
     * REST API when logged out" is the wrong tool for this.
     *
     * @param mixed            $result  Null unless something already answered.
     * @param WP_REST_Server   $server
     * @param WP_REST_Request  $request
     * @return mixed
     */
    public function block_rest_users( $result, $server, $request ) {
        if ( null !== $result ) return $result;
        if ( ! self::should_block_rest( (string) $request->get_route(), is_user_logged_in() ) ) return $result;

        return new WP_Error(
            'rest_no_route',
            __( 'No route was found matching the URL and request method.', 'bs-security' ),
            [ 'status' => 404 ]
        );
    }

    /**
     * Core matches routes case-insensitively, so /WP/V2/USERS reaches the
     * same handler and has to be caught by the same test.
     */
    public static function is_user_route( string $route ): bool {
        return (bool) preg_match( '#^/+wp/v2/users(?:/|$)#i', $route );
    }

    public static function should_block_rest( string $route, bool $logged_in ): bool {
        return ! $logged_in && self::is_user_route( $route );
    }

    /** ?author=N, for anyone not logged in, goes to the home page. */
    public function block_author_query(): void {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only, nothing is changed
        if ( ! self::should_block_author_query( $_GET, is_user_logged_in() ) ) return;
        wp_safe_redirect( home_url( '/' ), 302 );
        exit;
    }

    /**
     * Present and non-empty, in any shape. An array (?author[]=1) is still an
     * attempt, and core ignores an empty value anyway.
     */
    public static function should_block_author_query( array $get, bool $logged_in ): bool {
        if ( $logged_in || ! array_key_exists( 'author', $get ) ) return false;
        return '' !== $get['author'] && [] !== $get['author'];
    }

    /**
     * WordPress's own sitemap lists every author's archive URL, slug included.
     * A site where SEOPress or another SEO plugin owns the sitemap has its own
     * setting for this; this only reaches core's.
     *
     * @param mixed  $provider
     * @param string $name
     * @return mixed
     */
    public static function drop_user_sitemap( $provider, $name ) {
        return 'users' === $name ? false : $provider;
    }

    /**
     * oEmbed responses carry the post author's name and archive URL, which is
     * the username again. Nothing that embeds a Biscuit page needs either.
     *
     * @param mixed $data
     * @return mixed
     */
    public static function strip_oembed_author( $data ) {
        if ( is_array( $data ) ) {
            unset( $data['author_name'], $data['author_url'] );
        }
        return $data;
    }

    /**
     * Separate from enumeration and off by default: some sites use author
     * archives on purpose, and this takes them away from every visitor.
     */
    public function redirect_author_archive(): void {
        if ( is_user_logged_in() || ! is_author() ) return;
        wp_safe_redirect( home_url( '/' ), 302 );
        exit;
    }

    // ------------------------------------------------------- login errors

    /**
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function mask_login_error( $user ) {
        return self::mask_error( $user, self::generic_login_message() );
    }

    /**
     * Swap the wording of the account-revealing errors for one message.
     *
     * The error codes are kept. Lockout and logging plugins read the code, and
     * changing it would blind them; only the words a visitor sees change. Every
     * other error passes through untouched.
     *
     * @param mixed $user
     * @return mixed
     */
    public static function mask_error( $user, string $message ) {
        if ( ! $user instanceof WP_Error ) return $user;

        $codes = $user->get_error_codes();
        if ( ! array_intersect( $codes, self::MASKED_LOGIN_CODES ) ) return $user;

        $masked = new WP_Error();
        $said   = false;
        foreach ( $codes as $code ) {
            if ( in_array( $code, self::MASKED_LOGIN_CODES, true ) ) {
                // One message however many masked codes there were, or the
                // login screen would print the same sentence twice.
                if ( $said ) continue;
                $masked->add( $code, $message, $user->get_error_data( $code ) );
                $said = true;
                continue;
            }
            foreach ( $user->get_error_messages( $code ) as $text ) {
                $masked->add( $code, $text, $user->get_error_data( $code ) );
            }
        }
        return $masked;
    }

    public static function generic_login_message(): string {
        return sprintf(
            '<strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a>',
            esc_html__( 'Error:', 'bs-security' ),
            esc_html__( 'The username, email address or password is incorrect.', 'bs-security' ),
            esc_url( wp_lostpassword_url() ),
            esc_html__( 'Lost your password?', 'bs-security' )
        );
    }

    /**
     * On wp-login.php, an unknown username or email gets the same "check your
     * email" screen a real one does, and no email is sent.
     *
     * Core says "There is no account with that username or email address"
     * otherwise, which answers the question the login form now refuses to.
     *
     * @param WP_Error      $errors
     * @param WP_User|false $user_data
     */
    public function mask_lostpassword( $errors, $user_data ): void {
        if ( ! self::should_fake_reset( $errors, $user_data, (string) ( $GLOBALS['pagenow'] ?? '' ) ) ) return;

        // The same destination core uses on success, including its honoring
        // of redirect_to, so the two cases cannot be told apart by where they
        // land. wp_safe_redirect() keeps redirect_to on this site.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- core reads it the same way
        $raw = $_REQUEST['redirect_to'] ?? '';
        $to  = is_string( $raw ) && '' !== $raw ? wp_unslash( $raw ) : 'wp-login.php?checkemail=confirm';
        wp_safe_redirect( $to );
        exit;
    }

    /**
     * Only the "no such account" case, and only on wp-login.php.
     *
     * An empty field, or any error another plugin added (a CAPTCHA, a rate
     * limit), still shows. Other callers of retrieve_password(), such as the
     * admin's "Send password reset" or WooCommerce's own form, are left alone.
     *
     * @param mixed $errors
     * @param mixed $user_data
     */
    public static function should_fake_reset( $errors, $user_data, string $pagenow ): bool {
        if ( 'wp-login.php' !== $pagenow ) return false;
        if ( $user_data ) return false;
        if ( ! $errors instanceof WP_Error ) return false;
        return [] === array_diff( $errors->get_error_codes(), [ 'invalid_email' ] );
    }

    // ------------------------------------------------------- file editor

    /**
     * @param string[] $caps
     * @param string   $cap
     * @return string[]
     */
    public static function deny_file_edit( $caps, $cap ) {
        $caps = is_array( $caps ) ? $caps : [];
        if ( in_array( $cap, self::FILE_EDIT_CAPS, true ) ) {
            $caps[] = 'do_not_allow';
        }
        return $caps;
    }
}
