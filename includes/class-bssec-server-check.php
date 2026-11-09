<?php
/**
 * Ask the site, over HTTP, which of these headers it is actually sending, and
 * which of them come from the server rather than from PHP.
 *
 * The problem this solves: once the plugin is active you cannot tell, by
 * looking at a response, whether a header came from Kinsta, from xCloud, from
 * the theme, from another plugin, or from here. PHP's header() replaces
 * silently, so the plugin can be overriding the host's own configuration and
 * nothing anywhere says so.
 *
 * The trick is the first probe. It fetches a static file — this plugin's own
 * stylesheet — which nginx serves straight off disk without ever starting PHP.
 * Any header on that response is the server's, because there was nothing else
 * to produce it. The second probe fetches the home page, which is what a
 * visitor actually receives. Comparing the two separates "the host does this"
 * from "we do this".
 *
 * That difference is also the plugin's main limitation made visible: a header
 * set from PHP reaches HTML pages and nothing else. Scripts, stylesheets and
 * images are served by the web server directly, so the static probe is also an
 * honest picture of what your CSS and JS responses carry.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Server_Check {

    /** Where the last result is parked for the settings screen to render. */
    public const TRANSIENT = 'bssec_server_check';

    /**
     * The headers worth reporting on, lowercased.
     *
     * Everything this plugin can send, plus the two dead ones, so a site still
     * carrying them from an older tool shows up here rather than staying
     * invisible.
     */
    public const REPORTED = [
        'strict-transport-security',
        'referrer-policy',
        'permissions-policy',
        'x-frame-options',
        'x-content-type-options',
        'content-security-policy',
        'x-xss-protection',
        'expect-ct',
    ];

    /**
     * Run both probes.
     *
     * @return array{
     *     ok:bool,
     *     static_url:string,
     *     page_url:string,
     *     static:array<string,string>,
     *     page:array<string,string>,
     *     errors:string[],
     *     checked_at:int
     * }
     */
    public static function run(): array {
        $result = [
            'ok'         => false,
            'static_url' => '',
            'page_url'   => home_url( '/' ),
            // Recorded so the screen can say plainly that a reading taken on a
            // Local or staging box describes that box and not the client's
            // host. Without it the server column reads as authoritative
            // everywhere, and on Local it reports nothing at all, which invites
            // exactly the wrong conclusion.
            'local'      => self::is_local_host(),
            'static'     => [],
            'page'       => [],
            'errors'     => [],
            'checked_at' => time(),
        ];

        // --- Probe 1: a file the web server hands over without running PHP.
        //
        // This plugin's own stylesheet is used rather than something in
        // wp-includes, because it is guaranteed to exist wherever this code is
        // running, and because hardened sites sometimes deny direct access to
        // wp-includes and would make the probe look like a server failure.
        $static_url = BSSEC_URL . 'assets/css/bssec-admin.css';
        $result['static_url'] = $static_url;

        $static = self::fetch( $static_url );
        if ( is_wp_error( $static ) ) {
            $result['errors'][] = sprintf(
                /* translators: 1: URL, 2: error message */
                __( 'Could not fetch %1$s — %2$s', 'bs-security' ),
                $static_url,
                $static->get_error_message()
            );
        } elseif ( 200 !== (int) wp_remote_retrieve_response_code( $static ) ) {
            $result['errors'][] = sprintf(
                /* translators: 1: URL, 2: HTTP status code */
                __( 'Fetched %1$s but the server answered %2$d, so the server-only column cannot be trusted.', 'bs-security' ),
                $static_url,
                (int) wp_remote_retrieve_response_code( $static )
            );
        } else {
            $result['static'] = self::extract( $static );
        }

        // --- Probe 2: the home page, as a visitor receives it.
        $page = self::fetch( home_url( '/' ) );
        if ( is_wp_error( $page ) ) {
            $result['errors'][] = sprintf(
                /* translators: 1: URL, 2: error message */
                __( 'Could not fetch %1$s — %2$s', 'bs-security' ),
                home_url( '/' ),
                $page->get_error_message()
            );
        } else {
            $result['page'] = self::extract( $page );
            $result['ok']   = true;
        }

        if ( $result['errors'] ) {
            error_log( '[BSSEC] server check: ' . implode( ' | ', $result['errors'] ) );
        }

        return $result;
    }

    /**
     * Which headers are present on the page but absent from the static file.
     *
     * Those are the ones PHP is adding — this plugin, the theme, or another
     * plugin. Used by the settings screen to say where each header comes from.
     *
     * @param array{static:array<string,string>,page:array<string,string>} $result
     * @return string[] lowercased header names
     */
    public static function from_php( array $result ): array {
        $static = $result['static'] ?? [];
        $page   = $result['page'] ?? [];
        return array_values( array_diff( array_keys( $page ), array_keys( $static ) ) );
    }

    // ------------------------------------------------------------- internals

    /** @return array|WP_Error */
    private static function fetch( string $url ) {
        return wp_remote_get( $url, [
            'timeout'     => 12,
            // Follow a www or trailing-slash redirect so the headers read are
            // the ones on the page a visitor ends up looking at.
            'redirection' => 2,
            // The probe targets this site's own public address. A self-signed
            // certificate on a Local or staging box should not fail the check.
            'sslverify'   => ! self::is_local_host(),
            'headers'     => [
                // Ask for an uncached copy where the host honours it, so the
                // reading is of the site as it is now and not as it was.
                'Cache-Control' => 'no-cache',
            ],
        ] );
    }

    /**
     * Pull the reported headers out of a response.
     *
     * @return array<string,string> lowercased name => value
     */
    private static function extract( $response ): array {
        $found = [];

        foreach ( self::REPORTED as $name ) {
            $value = wp_remote_retrieve_header( $response, $name );

            // A header sent more than once arrives as an array. Join rather
            // than take the first, because seeing both values is the point:
            // two Content-Security-Policy headers intersect in the browser
            // rather than one winning, which is a real way to break a site
            // while every individual value looks correct.
            if ( is_array( $value ) ) {
                $value = implode( ' || ', array_map( 'strval', $value ) );
            }

            $value = trim( (string) $value );
            if ( '' !== $value ) {
                $found[ $name ] = $value;
            }
        }

        return $found;
    }

    /**
     * Local development hostnames.
     *
     * Two callers, for two reasons: certificate checks are noise here, and a
     * reading taken here says nothing about the production host.
     */
    public static function is_local_host(): bool {
        $host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
        foreach ( [ '.local', '.test', '.localhost', 'localhost', '127.0.0.1' ] as $suffix ) {
            if ( $host === $suffix || substr( $host, -strlen( $suffix ) ) === $suffix ) return true;
        }
        return false;
    }
}
