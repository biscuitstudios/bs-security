<?php
/**
 * Admin menu, settings screen, and form handlers.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Admin {

    use Bssec_Guards;

    public const SLUG = 'bssec-security';

    public function init(): void {
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );
        add_action( 'admin_post_' . Bssec_Plugin::SAVE_ACTION, [ $this, 'handle_save' ] );
        add_action( 'admin_post_' . Bssec_Plugin::PROBE_ACTION, [ $this, 'handle_probe' ] );
        add_filter( 'plugin_action_links_' . BSSEC_BASENAME, [ $this, 'action_links' ] );
        add_action( 'admin_notices', [ $this, 'legacy_notice' ] );
    }

    /** The plugin this one replaces. Same headers, so only one should run. */
    public const LEGACY_PLUGIN = 'bs-security-headers/bs-security-headers.php';

    /**
     * Say so while Biscuit Security Headers is still active.
     *
     * Running both does no harm, because they send identical headers and PHP
     * keeps the last one, but it is two things doing one job, and a settings
     * change on one screen would be quietly overruled by the other.
     */
    public function legacy_notice(): void {
        if ( ! current_user_can( 'activate_plugins' ) ) return;
        if ( ! function_exists( 'is_plugin_active' ) || ! is_plugin_active( self::LEGACY_PLUGIN ) ) return;

        printf(
            '<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a> %4$s <a href="%5$s">%6$s</a></p></div>',
            esc_html__( 'Biscuit Security replaces Biscuit Security Headers, which is still active.', 'bs-security' ),
            esc_url( admin_url( 'options-general.php?page=' . self::SLUG ) ),
            esc_html__( 'Check Settings → Security,', 'bs-security' ),
            esc_html__( 'then deactivate and delete Biscuit Security Headers on the', 'bs-security' ),
            esc_url( admin_url( 'plugins.php' ) ),
            esc_html__( 'Plugins screen.', 'bs-security' )
        );
    }

    /**
     * Settings submenu rather than a top-level menu.
     *
     * This is configured once and then left alone, which is what Settings is
     * for, and it puts the screen in the same place WP Force SSL used.
     */
    public function register_menu(): void {
        add_options_page(
            __( 'Security', 'bs-security' ),
            __( 'Security', 'bs-security' ),
            Bssec_Plugin::CAPABILITY,
            self::SLUG,
            [ $this, 'render_page' ]
        );
    }

    /** @param string[] $links */
    public function action_links( $links ): array {
        $links = is_array( $links ) ? $links : [];
        array_unshift( $links, sprintf(
            '<a href="%s">%s</a>',
            esc_url( admin_url( 'options-general.php?page=' . self::SLUG ) ),
            esc_html__( 'Settings', 'bs-security' )
        ) );
        return $links;
    }

    public function enqueue( string $hook ): void {
        if ( 'settings_page_' . self::SLUG !== $hook ) return;

        wp_enqueue_style( 'bssec-admin', BSSEC_URL . 'assets/css/bssec-admin.css', [], BSSEC_VERSION );

        // Match the admin color scheme the user picked in their profile.
        wp_add_inline_style(
            'bssec-admin',
            '.bssec-wrap{--bssec-accent:' . $this->admin_accent_color() . ';}'
        );

        wp_enqueue_script( 'bssec-admin', BSSEC_URL . 'assets/js/bssec-admin.js', [], BSSEC_VERSION, true );
        wp_localize_script( 'bssec-admin', 'bssecAdmin', [
            'hstsConfirm' => __(
                "Switching HSTS on cannot be fully undone.\n\nBrowsers that see it will refuse to load this site over an insecure connection for as long as the duration you chose, and there is no way to tell them to forget sooner.\n\nStart with 5 minutes unless you have already run this site at a shorter duration without trouble.",
                'bs-security'
            ),
        ] );
    }

    /**
     * The accent color from the current user's admin color scheme.
     *
     * Core registers each scheme with a four-color palette; index 2 is the
     * accent in every bundled scheme (#2271b1 in the default "fresh"). Falls
     * back through the palette, then to the WP admin blue, so an unregistered
     * or malformed custom scheme can never break the stylesheet.
     */
    private function admin_accent_color(): string {
        $fallback = '#2271b1';

        $scheme = get_user_option( 'admin_color' );
        if ( ! $scheme ) return $fallback;

        $schemes = $GLOBALS['_wp_admin_css_colors'] ?? [];
        $colors  = $schemes[ $scheme ]->colors ?? null;
        if ( ! is_array( $colors ) ) return $fallback;

        foreach ( [ 2, 3, 1, 0 ] as $i ) {
            $candidate = $colors[ $i ] ?? '';
            // Validate before it reaches a stylesheet — this ends up in CSS.
            if ( is_string( $candidate ) && preg_match( '/^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i', $candidate ) ) {
                return $candidate;
            }
        }
        return $fallback;
    }

    public function render_page(): void {
        $settings = Bssec_Plugin::settings();
        require BSSEC_DIR . 'admin/views/page-settings.php';
    }

    // -------------------------------------------------------------- handlers

    public function handle_save(): void {
        $this->guard_post( Bssec_Plugin::SAVE_ACTION, 'save', 2 );

        $raw      = wp_unslash( $_POST );  // phpcs:ignore WordPress.Security.NonceVerification -- guard_post above
        $settings = Bssec_Plugin::sanitize( is_array( $raw ) ? $raw : [] );

        $notices = [];

        // Refuse to switch the CSP on with nothing in the box. An empty policy
        // would send no header at all while the screen said it was enabled,
        // which is the kind of quiet disagreement this plugin exists to end.
        if ( $settings['csp'] && '' === $settings['csp_value'] ) {
            $settings['csp'] = false;
            $notices[]       = 'nocsp';
        }

        Bssec_Plugin::save( $settings );

        // The parked probe describes the site as it was a moment ago. Showing
        // it beside settings that just changed would claim the site is sending
        // something it no longer sends, so drop it and let them re-run.
        delete_transient( self::probe_key() );

        $args = [ 'page' => self::SLUG, 'bssec-updated' => '1' ];
        if ( $notices ) $args['bssec-notice'] = implode( ',', $notices );

        wp_safe_redirect( add_query_arg( $args, admin_url( 'options-general.php' ) ) );
        exit;
    }

    /**
     * Measure what this site is actually sending.
     *
     * Throttled harder than the save handler because it makes two outbound HTTP
     * requests to the site's own public URL.
     */
    public function handle_probe(): void {
        $this->guard_post( Bssec_Plugin::PROBE_ACTION, 'probe', 10 );

        set_transient( self::probe_key(), Bssec_Server_Check::run(), 15 * MINUTE_IN_SECONDS );

        wp_safe_redirect( add_query_arg(
            [ 'page' => self::SLUG, 'bssec-checked' => '1' ],
            admin_url( 'options-general.php' )
        ) . '#bssec-server-check' );
        exit;
    }

    /** Probe results are per-user, so two people looking at once do not fight. */
    public static function probe_key(): string {
        return Bssec_Server_Check::TRANSIENT . '_' . get_current_user_id();
    }
}
