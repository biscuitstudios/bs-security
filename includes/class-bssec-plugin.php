<?php
/**
 * Shared constants, settings access, and input sanitizing.
 *
 * Every capability check, nonce action, and option read in this plugin routes
 * through here, so there is exactly one place to change any of them.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

final class Bssec_Plugin {

    public const CAPABILITY   = 'manage_options';
    public const OPTION       = 'bssec_settings';
    public const SAVE_ACTION  = 'bssec_save_settings';
    public const PROBE_ACTION = 'bssec_probe_server';

    /**
     * Referrer-Policy values offered, strictest last.
     *
     * A short list rather than a free text field. The header has fifteen legal
     * values, most of which are traps: `unsafe-url` leaks the full path to
     * every third party, and `no-referrer-when-downgrade` is the old browser
     * default that these three all improve on. Offering only values worth
     * choosing removes a class of mistake rather than documenting it.
     */
    public const REFERRER_POLICIES = [
        'strict-origin-when-cross-origin',
        'strict-origin',
        'same-origin',
        'no-referrer',
    ];

    /** X-Frame-Options values. SAMEORIGIN matches what xCloud already sends. */
    public const FRAME_OPTIONS = [ 'SAMEORIGIN', 'DENY' ];

    /**
     * HSTS durations offered, in seconds.
     *
     * The short ones exist because they are the only safe way to switch HSTS
     * on. A browser holds the instruction for whatever `max-age` said, and
     * nothing can reach back and shorten it, so the first value has to be one
     * you would not mind being stuck with. Start at five minutes, confirm
     * nothing broke, then walk it up.
     */
    public const HSTS_MAX_AGES = [
        300,        // 5 minutes
        86400,      // 1 day
        604800,     // 1 week
        2592000,    // 30 days
        31536000,   // 1 year
    ];

    /**
     * Permissions-Policy features that can be blocked, in display order.
     *
     * Blocking a feature here sends `feature=()`, an empty allowlist, which
     * denies it to the page and to everything the page embeds. Every token is
     * one browsers currently implement; deprecated ones (`interest-cohort`)
     * are deliberately absent, because shipping a dead directive is noise that
     * reads as protection.
     */
    public const POLICY_FEATURES = [
        'camera',
        'microphone',
        'geolocation',
        'accelerometer',
        'gyroscope',
        'magnetometer',
        'payment',
        'fullscreen',
        'display-capture',
        'usb',
        'midi',
        'autoplay',
        'screen-wake-lock',
        'browsing-topics',
    ];

    /**
     * Blocked out of the box: the features no Biscuit site has ever used.
     *
     * Settled with Jason on September 20, 2026. Payment, fullscreen and
     * geolocation are deliberately NOT here — see risky_features().
     */
    public const POLICY_FEATURES_DEFAULT = [
        'camera',
        'microphone',
        'accelerometer',
        'gyroscope',
        'magnetometer',
    ];

    /**
     * Features that break something real when blocked, and what they break.
     *
     * Surfaced in the UI next to the checkbox. `payment` is the one that
     * matters most: it is how Apple Pay and Google Pay buttons work, including
     * the ones the WooCommerce Stripe gateway puts on a checkout, and blocking
     * it fails quietly with no console error pointing at this plugin.
     *
     * @return array<string,string>
     */
    public static function risky_features(): array {
        return [
            'geolocation'      => __( 'Breaks "find your nearest" maps and anything that offers to locate the visitor.', 'bs-security' ),
            'payment'          => __( 'Breaks Apple Pay and Google Pay buttons, including the ones the WooCommerce Stripe gateway adds to a checkout.', 'bs-security' ),
            'fullscreen'       => __( 'Breaks the fullscreen button on YouTube, Vimeo and self-hosted video.', 'bs-security' ),
            'autoplay'         => __( 'Stops background and hero videos playing on their own.', 'bs-security' ),
            'display-capture'  => __( 'Breaks screen sharing, if anything on the site offers it.', 'bs-security' ),
        ];
    }

    /** @return array<string,string> token => human label */
    public static function feature_labels(): array {
        return [
            'camera'           => __( 'Camera', 'bs-security' ),
            'microphone'       => __( 'Microphone', 'bs-security' ),
            'geolocation'      => __( 'Location', 'bs-security' ),
            'accelerometer'    => __( 'Motion sensor (accelerometer)', 'bs-security' ),
            'gyroscope'        => __( 'Motion sensor (gyroscope)', 'bs-security' ),
            'magnetometer'     => __( 'Compass (magnetometer)', 'bs-security' ),
            'payment'          => __( 'Payment handlers', 'bs-security' ),
            'fullscreen'       => __( 'Fullscreen', 'bs-security' ),
            'display-capture'  => __( 'Screen sharing', 'bs-security' ),
            'usb'              => __( 'USB devices', 'bs-security' ),
            'midi'             => __( 'MIDI devices', 'bs-security' ),
            'autoplay'         => __( 'Autoplaying media', 'bs-security' ),
            'screen-wake-lock' => __( 'Keeping the screen awake', 'bs-security' ),
            'browsing-topics'  => __( 'Google ad topics', 'bs-security' ),
        ];
    }

    public static function defaults(): array {
        return [
            // On out of the box. None of these three can break a normal site,
            // and the point of the plugin is that installing it is the whole
            // rollout. See README, "What switches on by itself".
            'referrer_policy'          => true,
            'referrer_policy_value'    => 'strict-origin-when-cross-origin',
            'permissions_policy'       => true,
            'permissions_policy_block' => self::POLICY_FEATURES_DEFAULT,
            'frame_options'            => true,
            'frame_options_value'      => 'SAMEORIGIN',

            // Off out of the box. Kinsta and xCloud both already send this one,
            // so it is here for portability rather than for today.
            'content_type_options'     => false,

            // Off out of the box, and switched on per site. Both of these can
            // break something, and HSTS cannot be taken back.
            'hsts'                     => false,
            'hsts_max_age'             => 300,
            'csp'                      => false,
            'csp_value'                => '',

            // CSP report-only. A candidate policy the browser checks and
            // reports against without blocking anything, kept apart from the
            // enforced one above so a site can run both at once. Collection
            // ends on its own at csp_report_only_until, so an endpoint nobody
            // is reading does not keep collecting. Approved by Jason on
            // November 9, 2026; design in docs/NOTES.md.
            'csp_report_only'          => false,
            'csp_report_only_value'    => '',
            'csp_report_only_until'    => '',

            // Hardening. The first three are on out of the box for the same
            // reason the safe headers are: none of them can break a normal
            // site, and installing the plugin is the rollout. Settled with
            // Jason on November 9, 2026.
            'block_user_enumeration'   => true,
            'mask_login_errors'        => true,
            'disable_file_editor'      => true,

            // Off out of the box. A site can use its author archives on
            // purpose, and this takes them away from every visitor.
            'redirect_author_archives' => false,
        ];
    }

    /**
     * How long report-only collection runs when switched on without a date.
     *
     * Renewable by saving a later date. Decision C in docs/NOTES.md, settled
     * with Jason on November 9, 2026.
     */
    public const REPORT_ONLY_DAYS = 30;

    /** The hardening switches, in display order. All plain on/off. */
    public const HARDENING_KEYS = [
        'block_user_enumeration',
        'redirect_author_archives',
        'mask_login_errors',
        'disable_file_editor',
    ];

    public static function settings(): array {
        $stored = get_option( self::OPTION, [] );
        return wp_parse_args( is_array( $stored ) ? $stored : [], self::defaults() );
    }

    /** @return mixed */
    public static function get( string $key ) {
        $settings = self::settings();
        return $settings[ $key ] ?? null;
    }

    /**
     * Autoloaded, unlike the other Biscuit plugins' settings.
     *
     * This option is read on every single front-end request to build the
     * headers. Autoloading means it arrives with the rest of core's options in
     * one query instead of costing a second one per page view.
     */
    public static function save( array $settings ): void {
        update_option( self::OPTION, $settings, true );
    }

    /**
     * Strip everything that could break out of an HTTP header value.
     *
     * This is the whole defense against response splitting, and it runs at the
     * point of output as well as on save. A carriage return or newline inside a
     * header value ends the header early, and whatever follows is read by the
     * browser as further headers and then as a body. NUL is stripped for the
     * same reason a NUL is stripped anywhere: it truncates in C and does not in
     * PHP, so the two disagree about where the value ends.
     *
     * PHP's own header() has rejected bare newlines since 5.1.2, but that is a
     * fatal-ish warning rather than a defense, and it has never covered every
     * separator. Do not rely on it, and do not remove this because the input is
     * behind manage_options — the settings could equally arrive from a restored
     * database or a migration.
     */
    public static function clean_header_value( string $value ): string {
        return trim( str_replace( [ "\r", "\n", "\0" ], '', $value ) );
    }

    /**
     * Validate and normalize a raw settings POST.
     *
     * Sanitizes by input type. Anything unrecognized falls back to the default
     * rather than being stored, so a hand-crafted POST cannot park a junk value
     * in the option and have it emitted later.
     *
     * @param DateTimeImmutable|null $today The site's today, for the report-only
     *                                      end date. Passed in by the tests; the
     *                                      clock is only read when report-only is
     *                                      switched on.
     */
    public static function sanitize( array $raw, ?DateTimeImmutable $today = null ): array {
        $out = self::defaults();

        $out['referrer_policy']      = ! empty( $raw['referrer_policy'] );
        $out['permissions_policy']   = ! empty( $raw['permissions_policy'] );
        $out['frame_options']        = ! empty( $raw['frame_options'] );
        $out['content_type_options'] = ! empty( $raw['content_type_options'] );
        $out['hsts']                 = ! empty( $raw['hsts'] );
        $out['csp']                  = ! empty( $raw['csp'] );

        foreach ( self::HARDENING_KEYS as $key ) {
            $out[ $key ] = ! empty( $raw[ $key ] );
        }

        $referrer = (string) ( $raw['referrer_policy_value'] ?? '' );
        if ( in_array( $referrer, self::REFERRER_POLICIES, true ) ) {
            $out['referrer_policy_value'] = $referrer;
        }

        $frame = strtoupper( trim( (string) ( $raw['frame_options_value'] ?? '' ) ) );
        if ( in_array( $frame, self::FRAME_OPTIONS, true ) ) {
            $out['frame_options_value'] = $frame;
        }

        $max_age = (int) ( $raw['hsts_max_age'] ?? 0 );
        if ( in_array( $max_age, self::HSTS_MAX_AGES, true ) ) {
            $out['hsts_max_age'] = $max_age;
        }

        // Intersect rather than accept: an unknown token would be emitted
        // verbatim into the header, and array_intersect also throws away
        // duplicates and preserves our display order.
        $blocked = $raw['permissions_policy_block'] ?? [];
        $blocked = is_array( $blocked ) ? array_map( 'strval', $blocked ) : [];
        $out['permissions_policy_block'] = array_values( array_intersect( self::POLICY_FEATURES, $blocked ) );

        $out['csp_value'] = self::sanitize_csp( (string) ( $raw['csp_value'] ?? '' ) );

        $out['csp_report_only']       = ! empty( $raw['csp_report_only'] );
        $out['csp_report_only_value'] = self::sanitize_csp( (string) ( $raw['csp_report_only_value'] ?? '' ) );
        $out['csp_report_only_until'] = $out['csp_report_only']
            ? self::sanitize_until( (string) ( $raw['csp_report_only_until'] ?? '' ), $today ?? self::today() )
            : '';

        return $out;
    }

    /** The site's today, in the site's own timezone. */
    public static function today(): DateTimeImmutable {
        return new DateTimeImmutable( 'now', wp_timezone() );
    }

    /**
     * The date report-only collection stops, as Y-m-d.
     *
     * A real date from today onward is kept. Anything else (empty, malformed,
     * an impossible date such as February 31, or a date already past) becomes
     * REPORT_ONLY_DAYS from today. Switching collection on therefore always
     * yields a working window, and saving the screen on an expired one renews
     * it rather than silently leaving it off.
     *
     * Parsed with createFromFormat() in the site's timezone rather than
     * strtotime(), which would read it as UTC (PLUGIN_PRIMER.md, antipatterns).
     */
    public static function sanitize_until( string $raw, DateTimeImmutable $today ): string {
        $raw     = trim( $raw );
        $parsed  = DateTimeImmutable::createFromFormat( '!Y-m-d', $raw, $today->getTimezone() );
        $is_real = $parsed && $parsed->format( 'Y-m-d' ) === $raw;

        if ( $is_real && $raw >= $today->format( 'Y-m-d' ) ) {
            return $raw;
        }
        return $today->modify( '+' . self::REPORT_ONLY_DAYS . ' days' )->format( 'Y-m-d' );
    }

    /**
     * Should the report-only header go out today?
     *
     * Fails toward off. A missing, malformed or past end date means no header,
     * because the option can be written by a restore or wp-cli as well as by
     * sanitize(), and the safe reading of a date nobody can parse is "ended".
     * The end date is inclusive: collection runs through that whole day.
     */
    public static function report_only_active( array $settings, DateTimeImmutable $today ): bool {
        if ( empty( $settings['csp_report_only'] ) ) return false;
        if ( '' === trim( (string) ( $settings['csp_report_only_value'] ?? '' ) ) ) return false;

        $until = (string) ( $settings['csp_report_only_until'] ?? '' );
        $parsed = DateTimeImmutable::createFromFormat( '!Y-m-d', $until, $today->getTimezone() );
        if ( ! $parsed || $parsed->format( 'Y-m-d' ) !== $until ) return false;

        return $today->format( 'Y-m-d' ) <= $until;
    }

    /**
     * A Content-Security-Policy, typed by hand into a textarea.
     *
     * Not sanitize_text_field(): that would encode characters a policy legally
     * contains and silently corrupt the value. What a policy can never contain
     * is a header separator or an angle bracket, so those go, and a multi-line
     * paste collapses to single spaces rather than being rejected, because
     * pasting a policy across several lines is the obvious thing to do.
     *
     * What survives is an arbitrary policy string, which is the same trust
     * level as core's Additional CSS box. The field is behind manage_options,
     * which already implies the ability to install a plugin that could send any
     * header it liked.
     */
    public static function sanitize_csp( string $csp ): string {
        $csp = str_replace( [ "\r\n", "\r", "\n", "\t" ], ' ', $csp );
        $csp = str_replace( [ '<', '>', "\0" ], '', $csp );
        $csp = preg_replace( '/ {2,}/', ' ', $csp );
        return trim( (string) $csp );
    }
}
