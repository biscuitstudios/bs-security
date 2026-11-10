<?php
/**
 * CSP report-only collection: the report endpoint, its table, and pruning.
 *
 * Browsers POST a report here each time a page breaks the candidate policy.
 * Each report is cut down to the directive, the blocked origin and a redacted
 * sample page, then folded into one row per directive and blocked origin, so
 * one broken embed on a busy page is one row with a count.
 *
 * Everything here exists only while report-only is switched on. The route is
 * registered only while collection is running (switch on, end date not past),
 * the table is created the first time the switch goes on, and the prune event
 * is scheduled only while the switch is on. On a site that never uses it, this
 * class adds three hooks and nothing else: no table, no cron, no route.
 *
 * The parsing half is pure (parse(), normalize_report(), redact_page(),
 * origin_of(), decide()) so it can be tested without WordPress. The storage
 * half is the only part that touches $wpdb.
 *
 * Design and limits: docs/NOTES.md, "Report-only mode". Approved by Jason on
 * November 9, 2026.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Csp_Reports {

    /** Table name, after $wpdb->prefix. */
    public const TABLE = 'bssec_csp_reports';

    /** Bumped whenever the CREATE TABLE below changes, so dbDelta reruns. */
    public const DB_VERSION        = '1';
    public const DB_VERSION_OPTION = 'bssec_db_version';

    /** Drop counts and the last prune. Not autoloaded; never the settings row. */
    public const STATS_OPTION = 'bssec_csp_stats';

    public const PRUNE_HOOK = 'bssec_prune_csp_reports';

    /** Together these must equal Bssec_Headers::REPORT_ROUTE. A test holds that. */
    public const ROUTE_NAMESPACE = 'bssec/v1';
    public const ROUTE_PATH      = '/csp-report';

    // The limits, decision D in docs/NOTES.md.
    //
    // MAX_BODY_BYTES was 16 KB in 0.3.0, set assuming one report per request.
    // Chrome bundles reports, and every report repeats the whole policy: one
    // is about 1,350 bytes with a realistic store policy, so 16 KB held about
    // twelve and a bigger bundle was refused whole. Raised to 256 KB by Jason,
    // November 9, 2026. PHP has read the body before this check runs anyway,
    // so the limit bounds parsing, not reading. MAX_REPORTS_PARSED bounds the
    // number of reports looked at in one request, however small each is.
    public const MAX_BODY_BYTES     = 262144;
    public const MAX_REPORTS_PARSED = 200;
    public const MAX_PER_REQUEST    = 10;
    public const ROW_CAP           = 500;
    public const NEW_ROWS_PER_HOUR = 50;
    public const KEEP_DAYS         = 30;

    /** The two report formats. Legacy report-uri, and the Reporting API batch. */
    public const TYPE_LEGACY    = 'application/csp-report';
    public const TYPE_REPORTING = 'application/reports+json';

    /**
     * Directives a report may name. Anything else is dropped, so a forged
     * report cannot put arbitrary text in the directive column.
     */
    public const DIRECTIVES = [
        'default-src', 'child-src', 'connect-src', 'font-src', 'frame-src',
        'fenced-frame-src', 'img-src', 'manifest-src', 'media-src', 'object-src',
        'prefetch-src', 'script-src', 'script-src-elem', 'script-src-attr',
        'style-src', 'style-src-elem', 'style-src-attr', 'worker-src',
        'base-uri', 'form-action', 'frame-ancestors', 'navigate-to',
        'require-trusted-types-for', 'trusted-types', 'webrtc',
    ];

    /**
     * The directive the screen's "Send a test report" button uses.
     *
     * Not a CSP directive, so no browser ever sends it. Kept out of the
     * source count and the main table, and shown on its own line, so a test
     * never reads as a violation. Anyone can forge it, as they can any
     * report; it is one row with a count, under the same limits.
     */
    public const TEST_DIRECTIVE = 'bssec-test';

    /** What browsers report in place of a URL for inline code and the like. */
    public const KEYWORDS = [ 'inline', 'eval', 'wasm-eval', 'trusted-types-policy', 'trusted-types-sink' ];

    /** Schemes stored as the scheme alone, the way a policy names them: `data:`. */
    public const SCHEME_SOURCES = [ 'data', 'blob', 'filesystem', 'mediastream' ];

    /** Every reason a report can be refused, for the stats and the screen. */
    public const DROP_REASONS = [
        'too_large', 'bad_type', 'unparseable', 'not_csp', 'over_batch',
        'wrong_host', 'not_report', 'extension', 'unknown_directive',
        'unrecognized_source', 'over_cap', 'over_budget', 'no_table',
    ];

    /**
     * How each refusal reads on the settings screen, after "N refused:".
     *
     * Three reasons refuse a whole request rather than a report (too large,
     * wrong content type, not a report at all), and say so, because a request
     * can hold many reports and the screen cannot tell how many.
     *
     * @return array<string,string> reason => label
     */
    public static function drop_labels(): array {
        return [
            'too_large'           => __( 'too large (whole requests, any number of reports each)', 'bs-security' ),
            'bad_type'            => __( 'the wrong type (whole requests)', 'bs-security' ),
            'unparseable'         => __( 'not readable as a report (whole requests)', 'bs-security' ),
            'not_csp'             => __( 'not CSP reports', 'bs-security' ),
            'over_batch'          => __( 'over the per-request limits (10 sources, 200 reports)', 'bs-security' ),
            'wrong_host'          => __( 'from another site', 'bs-security' ),
            'not_report'          => __( 'from an enforced policy', 'bs-security' ),
            'extension'           => __( 'from browser extensions', 'bs-security' ),
            'unknown_directive'   => __( 'naming an unknown directive', 'bs-security' ),
            'unrecognized_source' => __( 'with an unrecognized source', 'bs-security' ),
            'over_cap'            => __( 'new sources with the table full', 'bs-security' ),
            'over_budget'         => __( 'over 50 new sources in an hour', 'bs-security' ),
            'no_table'            => __( 'with the table missing', 'bs-security' ),
        ];
    }

    public function init(): void {
        add_action( 'rest_api_init', [ $this, 'register_route' ] );
        add_action( self::PRUNE_HOOK, [ $this, 'run_prune' ] );
        add_filter( 'perfmatters_rest_api_exceptions', [ $this, 'perfmatters_exception' ] );

        // The switch going on creates the table and schedules pruning; going
        // off unschedules. Hooked on the option itself rather than the save
        // handler, so a change made through wp-cli takes the same path.
        add_action( 'add_option_' . Bssec_Plugin::OPTION, [ $this, 'on_settings_added' ], 10, 2 );
        add_action( 'update_option_' . Bssec_Plugin::OPTION, [ $this, 'on_settings_updated' ], 10, 2 );

        // An upload-and-replace update never runs the activation hook, and a
        // restore can drop the table, so admin checks once per request while
        // the switch is on. Costs nothing while it is off: the settings row is
        // autoloaded.
        add_action( 'admin_init', [ $this, 'self_heal' ] );
    }

    // --- wiring ------------------------------------------------------------

    /** Is collection running right now? */
    public static function collecting(): bool {
        return Bssec_Plugin::report_only_active( Bssec_Plugin::settings(), Bssec_Plugin::today() );
    }

    public function register_route(): void {
        if ( ! self::collecting() ) return;

        register_rest_route( self::ROUTE_NAMESPACE, self::ROUTE_PATH, [
            'methods'  => 'POST',
            'callback' => [ $this, 'handle' ],
            // Public by design, and the one handler in this plugin that does
            // not run through guard_rest(). Browsers send CSP reports with no
            // login and no nonce; there is nothing to check them against. The
            // limits in handle() and store() are what bound it instead.
            'permission_callback' => '__return_true',
        ] );
    }

    /**
     * Let reports past Perfmatters' "Disable REST API" setting.
     *
     * That setting refuses REST requests from logged-out users or non-admins
     * with a 401, and a browser's report carries no login. Perfmatters matches
     * these strings as substrings of the requested route.
     */
    public function perfmatters_exception( $exceptions ) {
        if ( ! self::collecting() ) return $exceptions;
        $exceptions   = is_array( $exceptions ) ? $exceptions : [];
        $exceptions[] = self::ROUTE_NAMESPACE . self::ROUTE_PATH;
        return $exceptions;
    }

    public function on_settings_added( $option, $value ): void {
        self::sync( is_array( $value ) ? $value : [] );
    }

    public function on_settings_updated( $old, $new ): void {
        self::sync( is_array( $new ) ? $new : [] );
    }

    public static function sync( array $settings ): void {
        if ( ! empty( $settings['csp_report_only'] ) ) {
            self::install_table();
            self::ensure_schedule();
        } else {
            self::unschedule();
        }
    }

    public function self_heal(): void {
        if ( empty( Bssec_Plugin::settings()['csp_report_only'] ) ) return;
        if ( self::DB_VERSION !== get_option( self::DB_VERSION_OPTION ) || ! self::table_exists() ) {
            self::install_table();
        }
        self::ensure_schedule();
    }

    // --- the endpoint --------------------------------------------------------

    /**
     * Take one POST from a browser.
     *
     * Refusals cost no table write, cheapest check first. Everything that
     * parsed gets a 204, stored or not, so a caller learns nothing about what
     * was kept. Browsers ignore the response either way.
     */
    public function handle( WP_REST_Request $request ): WP_REST_Response {
        $body = (string) $request->get_body();
        if ( strlen( $body ) > self::MAX_BODY_BYTES ) {
            self::count_drops( [ 'too_large' => 1 ] );
            return new WP_REST_Response( null, 413 );
        }

        $type = $request->get_content_type();
        $type = is_array( $type ) ? strtolower( (string) ( $type['value'] ?? '' ) ) : '';
        if ( self::TYPE_LEGACY !== $type && self::TYPE_REPORTING !== $type ) {
            self::count_drops( [ 'bad_type' => 1 ] );
            return new WP_REST_Response( null, 415 );
        }

        $parsed = self::parse( $body, $type, self::site_host() );
        if ( null === $parsed ) {
            self::count_drops( [ 'unparseable' => 1 ] );
            return new WP_REST_Response( null, 400 );
        }

        $drops = $parsed['dropped'];
        if ( $parsed['rows'] ) {
            if ( ! self::table_exists() ) {
                $drops['no_table'] = ( $drops['no_table'] ?? 0 ) + count( $parsed['rows'] );
            } else {
                $now = time();
                foreach ( $parsed['rows'] as $row ) {
                    $outcome = self::store( $row, $now );
                    if ( in_array( $outcome, self::DROP_REASONS, true ) ) {
                        $drops[ $outcome ] = ( $drops[ $outcome ] ?? 0 ) + 1;
                    }
                }
            }
        }

        self::count_drops( $drops );
        return new WP_REST_Response( null, 204 );
    }

    // --- parsing: pure, no WordPress ------------------------------------------

    /**
     * Turn a request body into rows ready to store.
     *
     * @return array{rows: array[], dropped: array<string,int>}|null
     *         null when the body is not a report at all.
     */
    public static function parse( string $body, string $type, string $site_host ): ?array {
        $data = json_decode( $body, true, 8 );
        if ( ! is_array( $data ) ) return null;

        $dropped = [];
        $raw     = [];

        // The body's shape decides how it is read, not the Content-Type. The
        // label and the shape do not match in practice: Safari 27 sends each
        // report alone, labeled application/csp-report, in the Reporting API
        // shape ({"type":"csp-violation","body":{...}}) with no csp-report
        // wrapper and no list around it. Reading by label refused every one of
        // them as unreadable: 215 requests on biscuitstudios.com, and all 67
        // Safari sent to Local, November 9, 2026. Three shapes are accepted,
        // under either content type:
        //   {"csp-report": {...}}             the legacy report-uri format
        //   [ {"type": ..., "body": {...}} ]  a Reporting API batch (Chrome)
        //   {"type": ..., "body": {...}}      one Reporting API report alone (Safari)
        if ( array_key_exists( 'csp-report', $data ) ) {
            $r = $data['csp-report'];
            if ( ! is_array( $r ) ) return null;
            $raw[] = [
                'document'    => $r['document-uri'] ?? '',
                'blocked'     => $r['blocked-uri'] ?? '',
                // Older browsers send only violated-directive, which can carry
                // the directive's whole value after the name.
                'directive'   => $r['effective-directive'] ?? ( $r['violated-directive'] ?? '' ),
                'disposition' => $r['disposition'] ?? 'report',
                'source'      => $r['source-file'] ?? '',
            ];
        } else {
            if ( ! array_is_list( $data ) ) {
                // A single report object, as Safari sends it. Anything else
                // that is neither a list nor a report is not a report.
                if ( ! array_key_exists( 'type', $data ) && ! array_key_exists( 'body', $data ) ) return null;
                $data = [ $data ];
            }
            foreach ( $data as $item ) {
                if ( ! is_array( $item ) || 'csp-violation' !== ( $item['type'] ?? '' ) || ! is_array( $item['body'] ?? null ) ) {
                    $dropped['not_csp'] = ( $dropped['not_csp'] ?? 0 ) + 1;
                    continue;
                }
                $b     = $item['body'];
                $raw[] = [
                    'document'    => $b['documentURL'] ?? ( $item['url'] ?? '' ),
                    'blocked'     => $b['blockedURL'] ?? '',
                    'directive'   => $b['effectiveDirective'] ?? '',
                    'disposition' => $b['disposition'] ?? 'report',
                    'source'      => $b['sourceFile'] ?? '',
                ];
            }
        }

        // Fold first, then limit. Chrome's Reporting API bundles every report
        // from about the last minute, across pages, into one request, and
        // most of a bundle is the same pair repeated: "an image from this
        // site" once per image. 0.3.0 cut the raw list at ten before folding,
        // so a bundle of forty lost thirty counts and could drop a genuinely
        // new pair that happened to sit eleventh. On biscuitstudios.com that
        // showed as 153 refused against 2 kept, November 9, 2026.
        //
        // Up to MAX_REPORTS_PARSED reports are parsed; any beyond that are
        // refused unread and counted. The per-request limit then bounds what
        // it was for, the rows written, at ten distinct pairs.
        if ( count( $raw ) > self::MAX_REPORTS_PARSED ) {
            $dropped['over_batch'] = ( $dropped['over_batch'] ?? 0 ) + count( $raw ) - self::MAX_REPORTS_PARSED;
            $raw = array_slice( $raw, 0, self::MAX_REPORTS_PARSED );
        }

        $rows = [];
        foreach ( $raw as $r ) {
            $out = self::normalize_report( $r, $site_host );
            if ( isset( $out['drop'] ) ) {
                $dropped[ $out['drop'] ] = ( $dropped[ $out['drop'] ] ?? 0 ) + 1;
                continue;
            }
            $row = $out['row'];
            $key = $row['report_key'];
            if ( ! isset( $rows[ $key ] ) ) {
                $rows[ $key ] = $row;
                continue;
            }
            // A repeat: count it, and keep the latest sample page and the
            // latest source that was actually given.
            $rows[ $key ]['hits']++;
            $rows[ $key ]['sample_page'] = $row['sample_page'];
            if ( '' !== $row['sample_source'] ) {
                $rows[ $key ]['sample_source'] = $row['sample_source'];
            }
        }
        $rows = array_values( $rows );

        if ( count( $rows ) > self::MAX_PER_REQUEST ) {
            // Counted in reports, not pairs, so the refusal total means the
            // same thing whatever the reason.
            $over = array_slice( $rows, self::MAX_PER_REQUEST );
            $dropped['over_batch'] = ( $dropped['over_batch'] ?? 0 ) + array_sum( array_column( $over, 'hits' ) );
            $rows = array_slice( $rows, 0, self::MAX_PER_REQUEST );
        }

        return [ 'rows' => $rows, 'dropped' => $dropped ];
    }

    /**
     * One report, cut down to what is stored, or the reason it is refused.
     *
     * Stored: the directive, the blocked origin or keyword, a redacted sample
     * page, and the origin of the script that triggered it. Never stored: any
     * query string, any fragment, any path on another site, script samples,
     * line numbers, the original policy, the user agent, the IP.
     *
     * @return array{row: array}|array{drop: string}
     */
    public static function normalize_report( array $r, string $site_host ): array {
        $str = fn( $v ) => is_scalar( $v ) ? trim( (string) $v ) : '';

        if ( 'report' !== strtolower( $str( $r['disposition'] ?? 'report' ) ) ) {
            return [ 'drop' => 'not_report' ];
        }

        $directive = strtolower( (string) strtok( $str( $r['directive'] ?? '' ), " \t" ) );
        if ( ! in_array( $directive, self::DIRECTIVES, true ) && self::TEST_DIRECTIVE !== $directive ) {
            return [ 'drop' => 'unknown_directive' ];
        }

        // A noise filter, not a control: the field is the browser's word, and
        // anyone can forge it. Stops a staging copy or a mirror reporting here.
        $document = $str( $r['document'] ?? '' );
        $page     = self::redact_page( $document );
        $host     = strtolower( (string) parse_url( self::origin_of( $document ), PHP_URL_HOST ) );
        if ( '' === $page || '' === $site_host || $host !== strtolower( $site_host ) ) {
            return [ 'drop' => 'wrong_host' ];
        }

        $blocked_raw = $str( $r['blocked'] ?? '' );
        if ( self::is_extension_scheme( self::scheme_of( $blocked_raw ) ) ) {
            return [ 'drop' => 'extension' ];
        }
        $blocked = self::normalize_blocked( $blocked_raw );
        if ( '' === $blocked ) {
            return [ 'drop' => 'unrecognized_source' ];
        }

        return [ 'row' => [
            'report_key'    => sha1( $directive . "\n" . $blocked ),
            'directive'     => $directive,
            'blocked'       => $blocked,
            'sample_page'   => $page,
            'sample_source' => self::origin_of( $str( $r['source'] ?? '' ) ),
            'hits'          => 1,
        ] ];
    }

    /**
     * What was blocked, as a keyword, a scheme, or an origin. Never a path.
     *
     * Returns '' when it is none of those, which the caller drops.
     */
    public static function normalize_blocked( string $blocked ): string {
        $lower = strtolower( trim( $blocked ) );
        if ( '' === $lower ) return '';

        if ( in_array( $lower, self::KEYWORDS, true ) ) return $lower;

        // Some browsers report a bare scheme name for data: and blob:.
        if ( in_array( $lower, self::SCHEME_SOURCES, true ) ) return $lower . ':';

        $scheme = self::scheme_of( $lower );
        if ( '' === $scheme ) return '';

        if ( in_array( $scheme, [ 'http', 'https', 'ws', 'wss' ], true ) ) {
            return self::origin_of( $lower );
        }

        // Any other scheme (data:, blob:, about:) is stored as the scheme
        // alone. What follows the colon can be a whole inline image or a
        // document, and is never needed to write a policy.
        return $scheme . ':';
    }

    /** `scheme://host[:port]` for a web URL, or ''. Lowercased. */
    public static function origin_of( string $url ): string {
        $parts = parse_url( trim( $url ) );
        if ( ! is_array( $parts ) ) return '';

        $scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
        $host   = strtolower( (string) ( $parts['host'] ?? '' ) );
        if ( ! in_array( $scheme, [ 'http', 'https', 'ws', 'wss' ], true ) ) return '';
        if ( '' === $host || strlen( $host ) > 253 || ! preg_match( '/^[a-z0-9.-]+$/', $host ) ) return '';

        // Drop a port that is the scheme's default. Safari 27 writes
        // https://example.com:443/... where Chrome writes https://example.com/...,
        // and keeping it would store one site as two sources.
        $port     = isset( $parts['port'] ) ? (int) $parts['port'] : 0;
        $defaults = [ 'http' => 80, 'https' => 443, 'ws' => 80, 'wss' => 443 ];
        $port     = ( $port && $port !== $defaults[ $scheme ] ) ? ':' . $port : '';
        return $scheme . '://' . $host . $port;
    }

    /**
     * The page a report came from, safe to store.
     *
     * Origin and path only. The query and fragment always go, because
     * WooCommerce puts the order key there (`?key=wc_order_...`). And the path
     * is not safe as it stands either: WooCommerce puts the order number in it
     * (`/checkout/order-received/1234/`, `/my-account/view-order/1234/`). So
     * any all-digit segment becomes `{n}`, and any segment that looks like a
     * generated token becomes `{token}`: a UUID, or 20 or more letters, digits
     * and underscores with no hyphen and at least one of each of a letter and
     * a digit. That also makes every order page one sample rather than one
     * per order.
     *
     * The token rule deliberately leaves hyphenated slugs alone. The first
     * version took any 20-character run including hyphens, which turned
     * `/product/force-blue-logo-tee-black/` into `{token}` and would have made
     * the sample page useless on exactly the pages a store has most of.
     */
    public static function redact_page( string $url ): string {
        $origin = self::origin_of( $url );
        if ( '' === $origin ) return '';

        $path = parse_url( trim( $url ), PHP_URL_PATH );
        $path = is_string( $path ) && '' !== $path ? $path : '/';

        $segments = explode( '/', $path );
        foreach ( $segments as $i => $segment ) {
            if ( '' === $segment ) continue;
            if ( ctype_digit( $segment ) ) {
                $segments[ $i ] = '{n}';
            } elseif ( self::looks_like_token( $segment ) ) {
                $segments[ $i ] = '{token}';
            }
        }

        return substr( $origin . implode( '/', $segments ), 0, 255 );
    }

    /** A UUID, or a long unhyphenated run mixing letters and digits. */
    public static function looks_like_token( string $segment ): bool {
        if ( preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $segment ) ) return true;
        return (bool) preg_match( '/^[A-Za-z0-9_]{20,}$/', $segment )
            && (bool) preg_match( '/[0-9]/', $segment )
            && (bool) preg_match( '/[A-Za-z]/', $segment );
    }

    /** The scheme of a URL-ish string, lowercased, or ''. */
    public static function scheme_of( string $value ): string {
        return preg_match( '/^([a-z][a-z0-9+.-]*):/i', trim( $value ), $m ) ? strtolower( $m[1] ) : '';
    }

    /** chrome-extension:, moz-extension:, safari-web-extension: and the rest. */
    public static function is_extension_scheme( string $scheme ): bool {
        return '' !== $scheme && str_ends_with( $scheme, '-extension' );
    }

    /**
     * Insert, update, or refuse, from what the table holds now.
     *
     * A pair already in the table always counts, so a flood of one pair moves
     * a counter and nothing else. A new pair needs room under the row cap and
     * under the hourly budget. Nothing is ever evicted to make room, so junk
     * cannot push a real row out.
     */
    public static function decide( bool $exists, int $rows, int $new_last_hour ): string {
        if ( $exists ) return 'update';
        if ( $rows >= self::ROW_CAP ) return 'over_cap';
        if ( $new_last_hour >= self::NEW_ROWS_PER_HOUR ) return 'over_budget';
        return 'insert';
    }

    // --- storage: the only part that touches the database --------------------

    public static function table(): string {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public static function site_host(): string {
        return strtolower( (string) parse_url( home_url(), PHP_URL_HOST ) );
    }

    public static function table_exists(): bool {
        global $wpdb;
        $table = self::table();
        return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
    }

    /**
     * Create or update the table.
     *
     * dbDelta's format rules are strict: one column per line, two spaces after
     * PRIMARY KEY, KEY rather than INDEX. The version is written only once the
     * table is confirmed to exist, so a failed create is retried next time.
     */
    public static function install_table(): void {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table   = self::table();
        $charset = $wpdb->get_charset_collate();

        dbDelta( "CREATE TABLE $table (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  report_key char(40) NOT NULL,
  directive varchar(64) NOT NULL,
  blocked varchar(255) NOT NULL,
  sample_page varchar(255) NOT NULL DEFAULT '',
  sample_source varchar(255) NOT NULL DEFAULT '',
  hits bigint(20) unsigned NOT NULL DEFAULT 0,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY report_key (report_key),
  KEY first_seen (first_seen),
  KEY last_seen (last_seen)
) $charset;" );

        if ( self::table_exists() ) {
            update_option( self::DB_VERSION_OPTION, self::DB_VERSION, false );
        }

        // Start the drop counters' clock the first time the table exists, so
        // the screen can say "dropped since" with a real date.
        if ( false === get_option( self::STATS_OPTION, false ) ) {
            // 'no' rather than false: add_option() took only the string form
            // before WordPress 6.6, and the floor here is 6.3.
            add_option( self::STATS_OPTION, self::stats(), '', 'no' );
        }
    }

    /**
     * Store one row. Returns 'inserted', 'updated', or a drop reason.
     *
     * The write is a single INSERT ... ON DUPLICATE KEY UPDATE on the unique
     * report_key, so two reports of a new pair arriving together cannot race
     * into two rows. The reads before it only decide whether a new pair is
     * allowed in; they never decide whether an existing one counts.
     */
    public static function store( array $row, int $now ): string {
        global $wpdb;
        $table = self::table();
        $ts    = gmdate( 'Y-m-d H:i:s', $now );

        $exists = (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM $table WHERE report_key = %s", $row['report_key']
        ) );

        $rows = $recent = 0;
        if ( ! $exists ) {
            $rows   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
            $recent = (int) $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM $table WHERE first_seen > %s", gmdate( 'Y-m-d H:i:s', $now - HOUR_IN_SECONDS )
            ) );
        }

        $decision = self::decide( $exists, $rows, $recent );
        if ( 'update' !== $decision && 'insert' !== $decision ) return $decision;

        // A folded row carries how many reports it stands for; still one write.
        $hits = max( 1, (int) ( $row['hits'] ?? 1 ) );

        $wpdb->query( $wpdb->prepare(
            "INSERT INTO $table
                (report_key, directive, blocked, sample_page, sample_source, hits, first_seen, last_seen)
             VALUES (%s, %s, %s, %s, %s, %d, %s, %s)
             ON DUPLICATE KEY UPDATE
                hits = hits + %d,
                last_seen = %s,
                sample_page = %s,
                sample_source = IF(%s = '', sample_source, %s)",
            $row['report_key'], $row['directive'], $row['blocked'], $row['sample_page'], $row['sample_source'], $hits, $ts, $ts,
            $hits, $ts, $row['sample_page'], $row['sample_source'], $row['sample_source']
        ) );

        return 'update' === $decision ? 'updated' : 'inserted';
    }

    /**
     * Add to the drop counters. One option write, only when something dropped.
     *
     * Read, add, write, without a lock: two refusals at the same instant can
     * lose one count. The counts are there to show that dropping happens and
     * roughly how much, not to be exact.
     */
    public static function count_drops( array $drops ): void {
        $drops = array_filter( array_intersect_key( $drops, array_flip( self::DROP_REASONS ) ) );
        if ( ! $drops ) return;

        $stats = self::stats();
        foreach ( $drops as $reason => $n ) {
            $stats['dropped'][ $reason ] = (int) ( $stats['dropped'][ $reason ] ?? 0 ) + (int) $n;
        }
        update_option( self::STATS_OPTION, $stats, false );
    }

    /**
     * The settings screen's one-line status.
     *
     * "No reports yet" and "nothing can reach the endpoint" look identical
     * from a row count alone, so this also says whether the table exists and
     * how much has been refused.
     *
     * `dropped_by` is reason => count, largest first, known reasons only.
     * `rows` and `last` leave out the screen's test reports, which have their
     * own `test_last`, so pressing the test button never reads as traffic.
     *
     * @return array{table: bool, rows: int, last: string, test_last: string, dropped: int, dropped_by: array<string,int>, since: string, last_prune: string}
     */
    public static function summary(): array {
        global $wpdb;
        $out = [ 'table' => false, 'rows' => 0, 'last' => '', 'test_last' => '', 'dropped' => 0, 'dropped_by' => [], 'since' => '', 'last_prune' => '' ];
        if ( ! self::table_exists() ) return $out;

        $table = self::table();
        $stats = self::stats();

        $by = array_filter( array_map( 'intval', array_intersect_key( $stats['dropped'], array_flip( self::DROP_REASONS ) ) ) );
        arsort( $by );

        $out['table']      = true;
        $out['rows']       = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE directive <> %s", self::TEST_DIRECTIVE ) );
        $out['last']       = (string) $wpdb->get_var( $wpdb->prepare( "SELECT MAX(last_seen) FROM $table WHERE directive <> %s", self::TEST_DIRECTIVE ) );
        $out['test_last']  = (string) $wpdb->get_var( $wpdb->prepare( "SELECT MAX(last_seen) FROM $table WHERE directive = %s", self::TEST_DIRECTIVE ) );
        $out['dropped']    = array_sum( $by );
        $out['dropped_by'] = $by;
        $out['since']      = $stats['since'];
        $out['last_prune'] = $stats['last_prune'];
        return $out;
    }

    /**
     * Every stored row, most reported first, for the settings screen.
     *
     * Bounded by the row cap, so there is never more than ROW_CAP to render.
     * Test reports are included; the screen shows them apart.
     *
     * @return array<int,array{directive:string,blocked:string,sample_page:string,sample_source:string,hits:int,first_seen:string,last_seen:string}>
     */
    public static function rows(): array {
        global $wpdb;
        if ( ! self::table_exists() ) return [];

        $table = self::table();
        $rows  = $wpdb->get_results( $wpdb->prepare(
            "SELECT directive, blocked, sample_page, sample_source, hits, first_seen, last_seen
             FROM $table ORDER BY hits DESC, last_seen DESC LIMIT %d",
            self::ROW_CAP
        ), ARRAY_A );

        // Cast once where the rows are read: $wpdb hands back strings, and an
        // empty column can come back as null (THEME-RULES.md, get_col()).
        return array_map( fn( $r ) => [
            'directive'     => (string) ( $r['directive'] ?? '' ),
            'blocked'       => (string) ( $r['blocked'] ?? '' ),
            'sample_page'   => (string) ( $r['sample_page'] ?? '' ),
            'sample_source' => (string) ( $r['sample_source'] ?? '' ),
            'hits'          => (int) ( $r['hits'] ?? 0 ),
            'first_seen'    => (string) ( $r['first_seen'] ?? '' ),
            'last_seen'     => (string) ( $r['last_seen'] ?? '' ),
        ], is_array( $rows ) ? $rows : [] );
    }

    /**
     * Empty the table and restart the refusal counts. Returns rows removed.
     *
     * DELETE rather than TRUNCATE: TRUNCATE needs the DROP privilege, which a
     * host's database user does not always have, and on 500 rows the
     * difference is nothing. The counts restart with a new "since" date, so
     * the screen never shows refusals from before the reports it lists. The
     * last prune time is kept, because it is about the cron, not the data.
     */
    public static function clear(): int {
        global $wpdb;
        $removed = 0;
        if ( self::table_exists() ) {
            $table   = self::table();
            $removed = (int) $wpdb->query( "DELETE FROM $table" );
        }

        $stats = self::stats();
        update_option( self::STATS_OPTION, [
            'since'      => gmdate( 'Y-m-d H:i:s' ),
            'dropped'    => [],
            'last_prune' => $stats['last_prune'],
        ], false );

        return $removed;
    }

    /** When the prune event will next fire, or 0 if it is not scheduled. */
    public static function next_prune(): int {
        return (int) wp_next_scheduled( self::PRUNE_HOOK );
    }

    /** @return array{since: string, dropped: array<string,int>, last_prune: string} */
    public static function stats(): array {
        $stats = get_option( self::STATS_OPTION, [] );
        $stats = is_array( $stats ) ? $stats : [];
        return [
            'since'      => (string) ( $stats['since'] ?? gmdate( 'Y-m-d H:i:s' ) ),
            'dropped'    => is_array( $stats['dropped'] ?? null ) ? $stats['dropped'] : [],
            'last_prune' => (string) ( $stats['last_prune'] ?? '' ),
        ];
    }

    // --- pruning --------------------------------------------------------------

    /**
     * WP-Cron, one single event that reschedules itself after each run, per
     * PLUGIN_PRIMER.md. Not Action Scheduler: decision 2, no WooCommerce.
     */
    public static function ensure_schedule(): void {
        if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
            wp_schedule_single_event( time() + DAY_IN_SECONDS, self::PRUNE_HOOK );
        }
    }

    public static function unschedule(): void {
        wp_clear_scheduled_hook( self::PRUNE_HOOK );
    }

    public function run_prune(): void {
        self::prune( time() );
        if ( ! empty( Bssec_Plugin::settings()['csp_report_only'] ) ) {
            self::ensure_schedule();
        }
    }

    /**
     * Delete rows not reported for KEEP_DAYS.
     *
     * The row cap, not this, is what bounds the table. If WP-Cron never fires
     * the table goes stale, never unbounded.
     */
    public static function prune( int $now ): int {
        global $wpdb;
        if ( ! self::table_exists() ) return 0;

        $table   = self::table();
        $deleted = (int) $wpdb->query( $wpdb->prepare(
            "DELETE FROM $table WHERE last_seen < %s",
            gmdate( 'Y-m-d H:i:s', $now - self::KEEP_DAYS * DAY_IN_SECONDS )
        ) );

        $stats               = self::stats();
        $stats['last_prune'] = gmdate( 'Y-m-d H:i:s', $now );
        update_option( self::STATS_OPTION, $stats, false );

        return $deleted;
    }
}
