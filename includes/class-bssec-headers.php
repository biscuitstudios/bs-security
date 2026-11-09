<?php
/**
 * Builds and sends the response headers.
 *
 * build() is a pure function of (settings, https, context) so the header set
 * can be asserted in tests/ without WordPress. send() is the only part that
 * touches global state. Keep it that way — the interesting bugs here are in
 * which headers go out in which context, and that is exactly what a pure
 * function lets a test pin down.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Headers {

    /** A normal front-end page view. WordPress core sends nothing here. */
    public const CONTEXT_FRONTEND = 'frontend';

    /**
     * wp-admin and wp-login.php.
     *
     * Core already sends three headers in both, hooked on `admin_init` and
     * `login_init` in default-filters.php / admin-filters.php:
     *
     *   X-Frame-Options: SAMEORIGIN
     *   Content-Security-Policy: frame-ancestors 'self';
     *   Referrer-Policy: strict-origin-when-cross-origin
     *
     * So this plugin stays out of the way for those three, and sends only what
     * core leaves out.
     *
     * The CSP is the one that matters. PHP's header() replaces by default, so
     * emitting a site policy here would silently delete core's
     * `frame-ancestors 'self'` and leave the dashboard and the login form
     * frameable by anyone, unless the site's own policy happened to include a
     * frame-ancestors directive. A CSP written for the public site almost
     * never does. Never send the CSP in this context.
     */
    public const CONTEXT_ADMIN = 'admin';

    /**
     * A front-end page being rendered inside the Customizer's preview iframe.
     *
     * Same as a front-end view, minus the two headers whose whole job is to
     * stop the page being framed. Without this, opening the Customizer on a
     * site with X-Frame-Options: DENY, or with a CSP carrying a restrictive
     * frame-ancestors, shows a blank preview panel and no error that points
     * anywhere near this plugin.
     */
    public const CONTEXT_PREVIEW = 'preview';

    /** The REST route browsers send CSP reports to. Registered in build step 2. */
    public const REPORT_ROUTE = 'bssec/v1/csp-report';

    /** The Reporting API group name, shared by report-to and Reporting-Endpoints. */
    public const REPORT_GROUP = 'bssec';

    public function init(): void {
        // Front end. Fires inside WP::send_headers(), before any output.
        add_action( 'send_headers', [ $this, 'send_frontend' ] );

        // Admin and login. Priority 20 so core's own header functions, both at
        // 10, have already run; we send a disjoint set, but being explicitly
        // after them means a future overlap fails in our favour rather than
        // deleting one of theirs.
        add_action( 'admin_init', [ $this, 'send_admin' ], 20 );
        add_action( 'login_init', [ $this, 'send_admin' ], 20 );
    }

    public function send_frontend(): void {
        $preview = function_exists( 'is_customize_preview' ) && is_customize_preview();
        $this->send( $preview ? self::CONTEXT_PREVIEW : self::CONTEXT_FRONTEND );
    }

    public function send_admin(): void {
        $this->send( self::CONTEXT_ADMIN );
    }

    private function send( string $context ): void {
        // Something has already written output, so it is too late and header()
        // would only emit a warning into the middle of the page.
        if ( headers_sent() ) return;

        $settings = Bssec_Plugin::settings();

        // The report address is decided here, not in build(), because whether
        // collection is still running depends on today's date, and build()
        // stays a pure function with no clock. Never computed in admin, where
        // build() would discard it anyway.
        $report_url = '';
        if ( self::CONTEXT_ADMIN !== $context
            && Bssec_Plugin::report_only_active( $settings, Bssec_Plugin::today() ) ) {
            $report_url = rest_url( self::REPORT_ROUTE );
        }

        $headers = self::build( $settings, self::is_https(), $context, $report_url );

        foreach ( $headers as $name => $value ) {
            header( $name . ': ' . $value );
        }
    }

    /**
     * The header set for a given configuration.
     *
     * Every value goes through clean_header_value() here rather than only on
     * save, so a value that reached the option some other way — a database
     * restore, a migration, wp-cli, a stale row from an older version — still
     * cannot split the response.
     *
     * @param array  $settings   Full settings array, already merged with defaults.
     * @param bool   $is_https   Whether the visitor's connection is secure.
     * @param string $context    One of the CONTEXT_* constants.
     * @param string $report_url Where browsers send CSP reports. Empty means
     *                           report-only collection is not running today,
     *                           and no report-only header is sent. The caller
     *                           decides, because that depends on the date.
     *
     * @return array<string,string> Header name => value, in emission order.
     */
    public static function build( array $settings, bool $is_https, string $context = self::CONTEXT_FRONTEND, string $report_url = '' ): array {
        $headers = [];

        $is_admin   = self::CONTEXT_ADMIN === $context;
        $is_preview = self::CONTEXT_PREVIEW === $context;

        // --- Strict-Transport-Security -------------------------------------
        //
        // Sent everywhere, because a browser records it from whatever response
        // carries it and the login screen is the page you least want reached
        // over plain HTTP.
        //
        // Only over HTTPS: the spec requires browsers to ignore HSTS received
        // over an insecure connection, so sending it there is noise that also
        // makes a local dev site look configured when it is not.
        //
        // includeSubDomains and preload are absent, and there is no setting to
        // add them. That is the decision, made with Jason on September 20, 2026,
        // expressed as code rather than as a default someone can flip.
        // includeSubDomains takes down any subdomain still on plain HTTP, and
        // preload puts the domain in a list compiled into the browsers
        // themselves. Neither can be undone for a browser that already cached
        // it. If a site genuinely needs them, that is a conversation and a
        // server-level config, not a checkbox on 62 client sites.
        if ( ! empty( $settings['hsts'] ) && $is_https ) {
            $max_age = (int) ( $settings['hsts_max_age'] ?? 0 );
            if ( $max_age > 0 ) {
                $headers['Strict-Transport-Security'] = 'max-age=' . $max_age;
            }
        }

        // --- Referrer-Policy -----------------------------------------------
        // Skipped in admin: core's wp_admin_headers() already sends it.
        if ( ! empty( $settings['referrer_policy'] ) && ! $is_admin ) {
            $value = Bssec_Plugin::clean_header_value( (string) ( $settings['referrer_policy_value'] ?? '' ) );
            if ( in_array( $value, Bssec_Plugin::REFERRER_POLICIES, true ) ) {
                $headers['Referrer-Policy'] = $value;
            }
        }

        // --- Permissions-Policy ---------------------------------------------
        // Sent everywhere. Core sends this nowhere, and nothing in wp-admin
        // asks for a camera or a compass.
        if ( ! empty( $settings['permissions_policy'] ) ) {
            $value = self::permissions_policy_value( (array) ( $settings['permissions_policy_block'] ?? [] ) );
            // An empty block list would otherwise emit a bare header with no
            // value, which is not a valid policy and reads as configured.
            if ( '' !== $value ) {
                $headers['Permissions-Policy'] = $value;
            }
        }

        // --- X-Frame-Options -------------------------------------------------
        // Skipped in admin (core sends it) and in the Customizer preview.
        if ( ! empty( $settings['frame_options'] ) && ! $is_admin && ! $is_preview ) {
            $value = strtoupper( Bssec_Plugin::clean_header_value( (string) ( $settings['frame_options_value'] ?? '' ) ) );
            if ( in_array( $value, Bssec_Plugin::FRAME_OPTIONS, true ) ) {
                $headers['X-Frame-Options'] = $value;
            }
        }

        // --- X-Content-Type-Options ------------------------------------------
        // Off by default because Kinsta and xCloud both already send it.
        if ( ! empty( $settings['content_type_options'] ) ) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }

        // --- Content-Security-Policy ------------------------------------------
        // Front end only. See CONTEXT_ADMIN above for why this must never be
        // sent in wp-admin, and CONTEXT_PREVIEW for the Customizer.
        if ( ! empty( $settings['csp'] ) && ! $is_admin && ! $is_preview ) {
            $value = Bssec_Plugin::clean_header_value( (string) ( $settings['csp_value'] ?? '' ) );
            if ( '' !== $value ) {
                $headers['Content-Security-Policy'] = $value;
            }
        }

        // --- Content-Security-Policy-Report-Only ------------------------------
        // The candidate policy. The browser blocks nothing and reports what it
        // would have blocked. Same context rules as the enforced CSP: front end
        // only, for the same two reasons.
        //
        // This header reaches WooCommerce's Checkout and My Account, where the
        // enforced one does not: wc_send_frame_options_header() makes core send
        // its own Content-Security-Policy there, replacing ours, and core never
        // sends the Report-Only header. This class sends nothing on
        // template_redirect, and no other file in the plugin calls header(),
        // and a test holds both. (The hardening class does hook
        // template_redirect, for the author redirects, but sets no header
        // there beyond the redirect itself.)
        //
        // Both reporting mechanisms are named. Firefox and Safari read
        // report-uri; Chrome and Edge read report-to when it is present and
        // ignore report-uri. Any reporting directive already in the pasted
        // policy is removed first, so a policy copied from another site cannot
        // send this site's reports there.
        if ( ! empty( $settings['csp_report_only'] ) && ! $is_admin && ! $is_preview ) {
            $url    = self::clean_report_url( $report_url );
            $policy = self::strip_reporting_directives(
                Bssec_Plugin::clean_header_value( (string) ( $settings['csp_report_only_value'] ?? '' ) )
            );
            if ( '' !== $url && '' !== $policy ) {
                $headers['Content-Security-Policy-Report-Only'] =
                    $policy . '; report-uri ' . $url . '; report-to ' . self::REPORT_GROUP;
                $headers['Reporting-Endpoints'] = self::REPORT_GROUP . '="' . $url . '"';
            }
        }

        return $headers;
    }

    /**
     * Remove report-uri and report-to directives from a policy.
     *
     * Directive names are case-insensitive in CSP, so REPORT-URI goes too.
     * Empty directives (a doubled or trailing semicolon) are dropped, and the
     * rest are rejoined with "; ", which is also what the browser sees.
     */
    public static function strip_reporting_directives( string $policy ): string {
        $kept = [];
        foreach ( explode( ';', $policy ) as $directive ) {
            $directive = trim( $directive );
            if ( '' === $directive ) continue;
            $name = strtolower( (string) strtok( $directive, " \t" ) );
            if ( 'report-uri' === $name || 'report-to' === $name ) continue;
            $kept[] = $directive;
        }
        return implode( '; ', $kept );
    }

    /**
     * A report address safe to put in both headers, or '' if it is not.
     *
     * It lands bare in the CSP, where a space or semicolon would start a new
     * token or directive, and inside double quotes in Reporting-Endpoints,
     * where a quote or comma would end the value. So those are refused
     * outright rather than cleaned. rest_url() never produces them; this is for
     * a filter or a broken home URL that might.
     */
    public static function clean_report_url( string $url ): string {
        $url = Bssec_Plugin::clean_header_value( $url );
        return preg_match( '#^https?://[^\s"\';,<>\\\\]+$#i', $url ) ? $url : '';
    }

    /**
     * Turn a list of blocked features into a Permissions-Policy value.
     *
     * `feature=()` is an empty allowlist: denied to this document and to every
     * frame it embeds. Features that are not named are left at the browser
     * default, which is what lets Apple Pay and fullscreen keep working while
     * the camera is shut off.
     *
     * Unknown tokens are dropped rather than passed through. One malformed
     * directive invalidates nothing else in the header on paper, but browsers
     * differ on how much of a policy they discard, and a token that reached
     * here from outside sanitize() has no business being emitted.
     *
     * @param string[] $blocked
     */
    public static function permissions_policy_value( array $blocked ): string {
        $directives = [];

        foreach ( $blocked as $feature ) {
            $feature = Bssec_Plugin::clean_header_value( (string) $feature );
            if ( ! in_array( $feature, Bssec_Plugin::POLICY_FEATURES, true ) ) continue;
            $directives[ $feature ] = $feature . '=()';
        }

        return implode( ', ', $directives );
    }

    /**
     * Is the visitor actually on HTTPS?
     *
     * is_ssl() alone answers no on Kinsta, xCloud, and every other host that
     * terminates TLS at an edge and talks plain HTTP to PHP behind it. Without
     * the forwarded-protocol check, HSTS would be configured, appear switched
     * on, and never once be sent.
     *
     * Trusting a client-supplied X-Forwarded-Proto is normally a mistake. It is
     * safe for this one decision: the worst a spoofed header achieves is making
     * us send HSTS over plain HTTP, which browsers are required to ignore. It
     * cannot downgrade anything, because a spoofed `http` only withholds a
     * header the connection could not have used anyway.
     */
    public static function is_https(): bool {
        if ( is_ssl() ) return true;

        $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
        if ( is_string( $proto ) && 'https' === strtolower( trim( explode( ',', $proto )[0] ) ) ) {
            return true;
        }

        // Some load balancers report the port instead of the protocol.
        $port = $_SERVER['HTTP_X_FORWARDED_PORT'] ?? '';
        return '443' === (string) $port;
    }
}
