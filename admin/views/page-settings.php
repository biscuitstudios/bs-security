<?php
/**
 * Settings screen.
 *
 * @var array $settings Current settings, from Bssec_Admin::render_page().
 */

if ( ! defined( 'ABSPATH' ) ) exit;

$notices = isset( $_GET['bssec-notice'] )
    ? explode( ',', sanitize_text_field( wp_unslash( $_GET['bssec-notice'] ) ) )
    : [];
$updated = isset( $_GET['bssec-updated'] );

$probe = get_transient( Bssec_Admin::probe_key() );
$probe = is_array( $probe ) ? $probe : null;

$probe_url = wp_nonce_url(
    add_query_arg( 'action', Bssec_Plugin::PROBE_ACTION, admin_url( 'admin-post.php' ) ),
    Bssec_Plugin::PROBE_ACTION
);

// Report-only: whether collection is running today, and where reports go.
// The same two values send() uses, so the preview below matches the wire.
$ro_on      = ! empty( $settings['csp_report_only'] );
$ro_active  = Bssec_Plugin::report_only_active( $settings, Bssec_Plugin::today() );
$report_url = $ro_active ? rest_url( Bssec_Headers::REPORT_ROUTE ) : '';
$ro_until   = (string) ( $settings['csp_report_only_until'] ?? '' );
$ro_until_d = DateTimeImmutable::createFromFormat( '!Y-m-d', $ro_until );
$ro_until_h = $ro_until_d ? $ro_until_d->format( 'F j, Y' ) : '';
$ro_summary = $ro_on ? Bssec_Csp_Reports::summary() : null;

// What build() would emit for a normal front-end page view right now. Shown
// verbatim so the screen never describes something different from what ships.
$preview_headers = Bssec_Headers::build( $settings, true, Bssec_Headers::CONTEXT_FRONTEND, $report_url );

$labels   = Bssec_Plugin::feature_labels();
$risky    = Bssec_Plugin::risky_features();
$blocked  = (array) ( $settings['permissions_policy_block'] ?? [] );

$durations = [
    300      => __( '5 minutes — start here', 'bs-security' ),
    86400    => __( '1 day', 'bs-security' ),
    604800   => __( '1 week', 'bs-security' ),
    2592000  => __( '30 days', 'bs-security' ),
    31536000 => __( '1 year — the usual end state', 'bs-security' ),
];

$on_count = count( $preview_headers );

$hardening_on = count( array_filter(
    Bssec_Plugin::HARDENING_KEYS,
    fn( $key ) => ! empty( $settings[ $key ] )
) );
?>
<div class="wrap bssec-wrap">

    <div class="bssec-header">
        <h1><?php esc_html_e( 'Security', 'bs-security' ); ?></h1>
        <span class="bssec-pill <?php echo $on_count ? 'is-on' : 'is-off'; ?>">
            <?php
            printf(
                /* translators: %d: number of headers being sent */
                esc_html( _n( '%d header on', '%d headers on', $on_count, 'bs-security' ) ),
                (int) $on_count
            );
            ?>
        </span>
        <span class="bssec-pill <?php echo $hardening_on ? 'is-on' : 'is-off'; ?>">
            <?php
            printf(
                /* translators: 1: hardening switches on, 2: hardening switches in total */
                esc_html__( '%1$d of %2$d hardening on', 'bs-security' ),
                (int) $hardening_on,
                count( Bssec_Plugin::HARDENING_KEYS )
            );
            ?>
        </span>
    </div>
    <?php // Core moves admin notices to just after this marker. Without it they land inside the header row. ?>
    <hr class="wp-header-end">

    <?php if ( $updated ) : ?>
        <div class="bssec-notice is-success"><p><?php esc_html_e( 'Settings saved.', 'bs-security' ); ?></p></div>
    <?php endif; ?>

    <?php if ( in_array( 'nocsp', $notices, true ) ) : ?>
        <div class="bssec-notice is-error">
            <p><?php esc_html_e( 'The Content-Security-Policy was left off: write a policy in the box first. An empty policy sends no header at all.', 'bs-security' ); ?></p>
        </div>
    <?php endif; ?>

    <?php if ( in_array( 'noreportonly', $notices, true ) ) : ?>
        <div class="bssec-notice is-error">
            <p><?php esc_html_e( 'Report-only was left off: write a candidate policy in the box first.', 'bs-security' ); ?></p>
        </div>
    <?php endif; ?>

    <?php if ( ! Bssec_Headers::is_https() ) : ?>
        <div class="bssec-notice is-warning">
            <p><?php esc_html_e( 'This site is not being served over HTTPS right now, so HSTS will not be sent even if it is switched on. Browsers are required to ignore it on an insecure connection. Everything else on this screen works normally.', 'bs-security' ); ?></p>
        </div>
    <?php endif; ?>

    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <input type="hidden" name="action" value="<?php echo esc_attr( Bssec_Plugin::SAVE_ACTION ); ?>">
        <?php wp_nonce_field( Bssec_Plugin::SAVE_ACTION ); ?>

        <!-- Hardening ------------------------------------------------------->
        <div class="bssec-card">
            <div class="bssec-card-header"><h2><?php esc_html_e( 'Hardening', 'bs-security' ); ?></h2></div>
            <div class="bssec-card-body">

                <p class="bssec-help bssec-lede">
                    <?php esc_html_e( 'Closes the doors attackers try first. Three are on as soon as the plugin is activated, because none of them can break a normal site. Logged-in users see the site exactly as before.', 'bs-security' ); ?>
                </p>

                <!-- Block user enumeration -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="block_user_enumeration" value="1" <?php checked( ! empty( $settings['block_user_enumeration'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Hide usernames from logged-out visitors', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'A login attack starts with a list of usernames, and a stock WordPress site hands them out four ways. This closes all four for anyone not logged in: the REST API users list, the ?author=1 lookup that redirects to an author page, the author list in WordPress\'s own sitemap, and the author name in embed data. The rest of the REST API keeps working, so features that load content for visitors are not affected.', 'bs-security' ); ?>
                    </p>
                </div>

                <!-- Author archives -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="redirect_author_archives" value="1" <?php checked( ! empty( $settings['redirect_author_archives'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Send author pages to the home page', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'An author page\'s address carries the username, for example /author/jason/. Switch this on for a site that does not use author pages, and logged-out visitors who reach one land on the home page instead. Off by default, because some sites list posts by author on purpose. If the site uses an SEO plugin\'s sitemap, switch off its author sitemap there too.', 'bs-security' ); ?>
                    </p>
                </div>

                <!-- Login errors -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="mask_login_errors" value="1" <?php checked( ! empty( $settings['mask_login_errors'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'One login error for every mistake', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'WordPress tells a visitor whether the username or the password was wrong, and the lost-password form says when there is no such account. Both confirm which accounts exist. With this on, a failed login always reads "The username, email address or password is incorrect", and the lost-password form shows the same "check your email" screen whether the account exists or not. No email goes to an address that has no account.', 'bs-security' ); ?>
                    </p>
                </div>

                <!-- File editor -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="disable_file_editor" value="1" <?php checked( ! empty( $settings['disable_file_editor'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Switch off the theme and plugin file editor', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Removes the code editor under Appearance and Plugins, so a stolen administrator login cannot be turned into code running on the server in two clicks. Plugin and theme updates are not affected. This does the same job as DISALLOW_FILE_EDIT in wp-config.php, without editing that file.', 'bs-security' ); ?>
                    </p>
                </div>

            </div>
        </div>

        <!-- Standard headers ------------------------------------------------>
        <div class="bssec-card">
            <div class="bssec-card-header"><h2><?php esc_html_e( 'Standard headers', 'bs-security' ); ?></h2></div>
            <div class="bssec-card-body">

                <p class="bssec-help bssec-lede">
                    <?php esc_html_e( 'These are on as soon as the plugin is activated. None of them can break a normal site. They apply to front-end pages only, because WordPress already sends its own versions inside the dashboard and on the login screen.', 'bs-security' ); ?>
                </p>

                <!-- Referrer-Policy -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="referrer_policy" value="1" data-bssec-controls="bssec-referrer" <?php checked( ! empty( $settings['referrer_policy'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Referrer-Policy', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Controls how much of the current address is handed to another site when a visitor clicks a link out. Without it, the full URL of the page they were on travels with them, which on a search results or account page can leak more than anyone intended.', 'bs-security' ); ?>
                    </p>
                    <div class="bssec-dependent" id="bssec-referrer" <?php echo empty( $settings['referrer_policy'] ) ? 'hidden' : ''; ?>>
                        <label for="bssec-referrer-value" class="bssec-sublabel"><?php esc_html_e( 'How much to send', 'bs-security' ); ?></label>
                        <select name="referrer_policy_value" id="bssec-referrer-value">
                            <?php foreach ( Bssec_Plugin::REFERRER_POLICIES as $policy ) : ?>
                                <option value="<?php echo esc_attr( $policy ); ?>" <?php selected( $settings['referrer_policy_value'] ?? '', $policy ); ?>>
                                    <?php echo esc_html( $policy ); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="bssec-help">
                            <strong>strict-origin-when-cross-origin</strong>
                            <?php esc_html_e( 'sends the full address within this site, and only the domain name to anyone else. It is the modern browser default and the right answer almost always. The stricter options send less and can break analytics or an affiliate link that expects a referrer.', 'bs-security' ); ?>
                        </p>
                    </div>
                </div>

                <!-- Permissions-Policy -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="permissions_policy" value="1" data-bssec-controls="bssec-permissions" <?php checked( ! empty( $settings['permissions_policy'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Permissions-Policy', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Tells the browser which features this site is allowed to ask for. Anything ticked below is refused outright, so nothing that finds its way onto a page can prompt a visitor for it. Anything left unticked carries on working exactly as it does now.', 'bs-security' ); ?>
                    </p>
                    <div class="bssec-dependent" id="bssec-permissions" <?php echo empty( $settings['permissions_policy'] ) ? 'hidden' : ''; ?>>
                        <fieldset class="bssec-checklist">
                            <legend class="bssec-sublabel"><?php esc_html_e( 'Features to block', 'bs-security' ); ?></legend>
                            <?php foreach ( Bssec_Plugin::POLICY_FEATURES as $feature ) : ?>
                                <label class="bssec-check <?php echo isset( $risky[ $feature ] ) ? 'is-risky' : ''; ?>">
                                    <input type="checkbox" name="permissions_policy_block[]" value="<?php echo esc_attr( $feature ); ?>" <?php checked( in_array( $feature, $blocked, true ) ); ?>>
                                    <span class="bssec-check-text">
                                        <span class="bssec-check-label"><?php echo esc_html( $labels[ $feature ] ?? $feature ); ?></span>
                                        <code><?php echo esc_html( $feature ); ?></code>
                                        <?php if ( isset( $risky[ $feature ] ) ) : ?>
                                            <span class="bssec-check-warn"><?php echo esc_html( $risky[ $feature ] ); ?></span>
                                        <?php endif; ?>
                                    </span>
                                </label>
                            <?php endforeach; ?>
                        </fieldset>
                    </div>
                </div>

                <!-- X-Frame-Options -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="frame_options" value="1" data-bssec-controls="bssec-frame" <?php checked( ! empty( $settings['frame_options'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'X-Frame-Options', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Stops another website displaying these pages inside a frame on their own site, which is how a clickjacking attack gets someone to click something they cannot see. Switch this off for a site that is deliberately embedded somewhere else.', 'bs-security' ); ?>
                    </p>
                    <div class="bssec-dependent" id="bssec-frame" <?php echo empty( $settings['frame_options'] ) ? 'hidden' : ''; ?>>
                        <label for="bssec-frame-value" class="bssec-sublabel"><?php esc_html_e( 'Who may frame this site', 'bs-security' ); ?></label>
                        <select name="frame_options_value" id="bssec-frame-value">
                            <option value="SAMEORIGIN" <?php selected( $settings['frame_options_value'] ?? '', 'SAMEORIGIN' ); ?>>
                                <?php esc_html_e( 'SAMEORIGIN — this site only', 'bs-security' ); ?>
                            </option>
                            <option value="DENY" <?php selected( $settings['frame_options_value'] ?? '', 'DENY' ); ?>>
                                <?php esc_html_e( 'DENY — nobody at all, including this site', 'bs-security' ); ?>
                            </option>
                        </select>
                        <p class="bssec-help">
                            <?php esc_html_e( 'SAMEORIGIN is what xCloud already sends and what WordPress uses in the dashboard. DENY is stricter but blocks this site framing its own pages, which some page builders and preview tools rely on.', 'bs-security' ); ?>
                        </p>
                    </div>
                </div>

                <!-- X-Content-Type-Options -->
                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="content_type_options" value="1" <?php checked( ! empty( $settings['content_type_options'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'X-Content-Type-Options', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Stops the browser guessing at a file type and running something as a script that was not meant to be one. Off by default because Kinsta and xCloud both already send it, and there is no point two things sending the same header. Switch it on only if the check below, run on the live site, shows it missing.', 'bs-security' ); ?>
                    </p>
                </div>

            </div>
        </div>

        <!-- HSTS ------------------------------------------------------------>
        <div class="bssec-card">
            <div class="bssec-card-header"><h2><?php esc_html_e( 'HSTS', 'bs-security' ); ?></h2></div>
            <div class="bssec-card-body">

                <div class="bssec-callout is-warning">
                    <p><strong><?php esc_html_e( 'This is the one setting here that cannot be taken back.', 'bs-security' ); ?></strong></p>
                    <p><?php esc_html_e( 'HSTS is a note the site hands a visitor\'s browser saying "only ever talk to me over the secure connection, and remember that". The browser obeys for however long the note says, and nothing can reach back and tell it to forget sooner. If the certificate later breaks, those visitors get a hard wall with no way past it.', 'bs-security' ); ?></p>
                    <p><?php esc_html_e( 'That is why the duration starts at five minutes. Switch it on, check the site, then come back and lengthen it. Only the duration you have already lived with is safe to keep.', 'bs-security' ); ?></p>
                </div>

                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="hsts" value="1" id="bssec-hsts" data-bssec-controls="bssec-hsts-opts" data-bssec-confirm="1" <?php checked( ! empty( $settings['hsts'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Send Strict-Transport-Security', 'bs-security' ); ?></span>
                    </label>
                    <p class="bssec-help">
                        <?php esc_html_e( 'Your host already redirects insecure requests to the secure address. HSTS closes the sliver that redirect cannot: the very first request, which still leaves the visitor\'s device before the redirect comes back.', 'bs-security' ); ?>
                    </p>
                    <div class="bssec-dependent" id="bssec-hsts-opts" <?php echo empty( $settings['hsts'] ) ? 'hidden' : ''; ?>>
                        <label for="bssec-hsts-max-age" class="bssec-sublabel"><?php esc_html_e( 'How long browsers should remember', 'bs-security' ); ?></label>
                        <select name="hsts_max_age" id="bssec-hsts-max-age">
                            <?php foreach ( $durations as $seconds => $label ) : ?>
                                <option value="<?php echo esc_attr( (string) $seconds ); ?>" <?php selected( (int) ( $settings['hsts_max_age'] ?? 0 ), $seconds ); ?>>
                                    <?php echo esc_html( $label ); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="bssec-field">
                    <p class="bssec-help">
                        <strong><?php esc_html_e( 'Subdomains and preloading are not offered, on purpose.', 'bs-security' ); ?></strong>
                        <?php esc_html_e( 'Covering subdomains takes down any that still run on an insecure connection, and preloading puts the domain on a list built into the browsers themselves that takes months and a browser release to leave. Neither belongs on a checkbox on a client site. If one is genuinely needed, it is a server configuration and a conversation.', 'bs-security' ); ?>
                    </p>
                </div>

            </div>
        </div>

        <!-- CSP ------------------------------------------------------------->
        <div class="bssec-card">
            <div class="bssec-card-header"><h2><?php esc_html_e( 'Content-Security-Policy', 'bs-security' ); ?></h2></div>
            <div class="bssec-card-body">

                <p class="bssec-help bssec-lede">
                    <?php esc_html_e( 'The strongest protection on this screen and the easiest to get wrong. A policy lists where the browser is allowed to load scripts, styles, fonts and images from, and refuses everything else. Get it wrong and something stops working quietly, often somewhere nobody looks for weeks.', 'bs-security' ); ?>
                </p>
                <p class="bssec-help">
                    <?php esc_html_e( 'There is no fleet-wide default here because there cannot be one. A policy has to be written against what a particular site actually loads: its fonts, its analytics, its embeds, its payment scripts. Leave this off until that audit has been done.', 'bs-security' ); ?>
                </p>
                <p class="bssec-help">
                    <strong><?php esc_html_e( 'Front-end pages only.', 'bs-security' ); ?></strong>
                    <?php esc_html_e( 'WordPress sends its own policy in the dashboard and on the login screen to stop those being framed. This one is never sent there, because replacing it would leave the dashboard less protected than before.', 'bs-security' ); ?>
                </p>

                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="csp" value="1" data-bssec-controls="bssec-csp-opts" <?php checked( ! empty( $settings['csp'] ) ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Send a Content-Security-Policy', 'bs-security' ); ?></span>
                    </label>
                    <div class="bssec-dependent" id="bssec-csp-opts" <?php echo empty( $settings['csp'] ) ? 'hidden' : ''; ?>>
                        <label for="bssec-csp-value" class="bssec-sublabel"><?php esc_html_e( 'The policy', 'bs-security' ); ?></label>
                        <textarea name="csp_value" id="bssec-csp-value" class="bssec-code" rows="6" spellcheck="false" placeholder="default-src 'self'; script-src 'self' https://www.googletagmanager.com; ..."><?php echo esc_textarea( (string) ( $settings['csp_value'] ?? '' ) ); ?></textarea>
                        <p class="bssec-help">
                            <?php esc_html_e( 'Paste the policy without the header name. Line breaks are fine and get folded into spaces when it is sent.', 'bs-security' ); ?>
                        </p>
                    </div>
                </div>

            </div>
        </div>

        <!-- CSP report-only ------------------------------------------------->
        <div class="bssec-card" id="bssec-report-only">
            <div class="bssec-card-header"><h2><?php esc_html_e( 'CSP report-only', 'bs-security' ); ?></h2></div>
            <div class="bssec-card-body">

                <p class="bssec-help bssec-lede">
                    <?php esc_html_e( 'Tries out a candidate policy without blocking anything. Each visitor\'s browser checks the page against it and reports what it would have blocked. Run it for a few weeks of normal traffic, then write the real policy above from what was reported.', 'bs-security' ); ?>
                </p>
                <p class="bssec-help">
                    <?php esc_html_e( 'Unlike the policy above, this one also reaches the WooCommerce Checkout and My Account pages, so it shows what a policy would break on the payment page before anything is blocked there.', 'bs-security' ); ?>
                </p>

                <div class="bssec-field bssec-field-toggle">
                    <label class="bssec-toggle">
                        <input type="checkbox" name="csp_report_only" value="1" data-bssec-controls="bssec-report-only-opts" <?php checked( $ro_on ); ?>>
                        <span class="bssec-toggle-track"><span class="bssec-toggle-thumb"></span></span>
                        <span class="bssec-toggle-label"><?php esc_html_e( 'Collect reports against a candidate policy', 'bs-security' ); ?></span>
                    </label>
                    <div class="bssec-dependent" id="bssec-report-only-opts" <?php echo $ro_on ? '' : 'hidden'; ?>>

                        <label for="bssec-report-only-value" class="bssec-sublabel"><?php esc_html_e( 'The candidate policy', 'bs-security' ); ?></label>
                        <textarea name="csp_report_only_value" id="bssec-report-only-value" class="bssec-code" rows="6" spellcheck="false" placeholder="default-src 'self'; script-src 'self' https://js.stripe.com; ..."><?php echo esc_textarea( (string) ( $settings['csp_report_only_value'] ?? '' ) ); ?></textarea>
                        <p class="bssec-help">
                            <?php esc_html_e( 'Paste the policy without the header name. Any report-uri or report-to in it is removed, and this plugin adds its own report address.', 'bs-security' ); ?>
                        </p>

                        <label for="bssec-report-only-until" class="bssec-sublabel"><?php esc_html_e( 'Collect until', 'bs-security' ); ?></label>
                        <input type="date" name="csp_report_only_until" id="bssec-report-only-until" value="<?php echo esc_attr( $ro_until ); ?>">
                        <p class="bssec-help">
                            <?php
                            printf(
                                /* translators: %d: number of days */
                                esc_html__( 'Collection stops at the end of this day: the header stops and the report address closes. Left empty or in the past, it is set to %d days from today when you save.', 'bs-security' ),
                                (int) Bssec_Plugin::REPORT_ONLY_DAYS
                            );
                            ?>
                        </p>

                        <div class="bssec-callout is-warning">
                            <p><?php esc_html_e( 'On Kinsta, purge the site cache after saving. Cached pages keep the headers they were stored with, so a change here does not reach visitors until the cache is cleared.', 'bs-security' ); ?></p>
                        </div>

                    </div>
                </div>

                <?php if ( $ro_on && $ro_summary ) : ?>
                    <div class="bssec-field bssec-report-only-status">
                        <p class="bssec-help">
                            <strong>
                            <?php
                            if ( $ro_active ) {
                                /* translators: %s: a date such as December 9, 2026 */
                                printf( esc_html__( 'Collecting until %s.', 'bs-security' ), esc_html( $ro_until_h ) );
                            } else {
                                /* translators: %s: a date such as December 9, 2026 */
                                printf( esc_html__( 'Collection ended on %s. Save with a later date to start again.', 'bs-security' ), esc_html( $ro_until_h ) );
                            }
                            ?>
                            </strong>
                        </p>
                        <?php if ( ! $ro_summary['table'] ) : ?>
                            <p class="bssec-help"><?php esc_html_e( 'The reports table is missing, so nothing is being stored. Save this screen to create it.', 'bs-security' ); ?></p>
                        <?php else : ?>
                            <p class="bssec-help">
                                <?php
                                printf(
                                    /* translators: %d: number of distinct directive and source pairs */
                                    esc_html( _n( '%d source reported so far.', '%d sources reported so far.', $ro_summary['rows'], 'bs-security' ) ),
                                    (int) $ro_summary['rows']
                                );
                                echo ' ';
                                if ( '' === $ro_summary['last'] ) {
                                    esc_html_e( 'No reports yet.', 'bs-security' );
                                } else {
                                    $last_ts = ( new DateTimeImmutable( $ro_summary['last'], new DateTimeZone( 'UTC' ) ) )->getTimestamp();
                                    /* translators: %s: a span of time such as 5 minutes */
                                    printf( esc_html__( 'Last report %s ago.', 'bs-security' ), esc_html( human_time_diff( $last_ts ) ) );
                                }
                                if ( $ro_summary['dropped'] > 0 ) {
                                    // "153 refused: 150 over the ... limit, 3 from browser
                                    // extensions." A total alone cannot say which rule is
                                    // doing the refusing, which is what 0.3.0 showed.
                                    $drop_labels = Bssec_Csp_Reports::drop_labels();
                                    $drop_parts  = [];
                                    foreach ( $ro_summary['dropped_by'] as $reason => $n ) {
                                        $drop_parts[] = (int) $n . ' ' . ( $drop_labels[ $reason ] ?? $reason );
                                    }
                                    echo ' ';
                                    printf(
                                        /* translators: 1: number refused, 2: comma-separated list of counts and reasons */
                                        esc_html__( '%1$d refused: %2$s.', 'bs-security' ),
                                        (int) $ro_summary['dropped'],
                                        esc_html( implode( ', ', $drop_parts ) )
                                    );
                                }
                                ?>
                            </p>
                        <?php endif; ?>
                        <?php if ( $ro_active ) : ?>
                            <p class="bssec-help"><?php esc_html_e( 'Reports go to', 'bs-security' ); ?> <code><?php echo esc_html( $report_url ); ?></code></p>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

            </div>
        </div>

        <div class="bssec-actions">
            <button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save changes', 'bs-security' ); ?></button>
        </div>

    </form>

    <!-- What this site sends now --------------------------------------------->
    <div class="bssec-card" id="bssec-server-check">
        <div class="bssec-card-header"><h2><?php esc_html_e( 'What this site sends now', 'bs-security' ); ?></h2></div>
        <div class="bssec-card-body">

            <p class="bssec-help bssec-lede">
                <?php esc_html_e( 'Fetches two things: a stylesheet, which the web server hands over without ever starting WordPress, and the home page. Any header on the stylesheet came from the server itself, so the two columns together show what your host does on its own and what this plugin is adding or overriding.', 'bs-security' ); ?>
            </p>

            <?php // A link rather than a form: nested forms are dropped by the browser. ?>
            <p><a class="button" rel="nofollow" href="<?php echo esc_url( $probe_url ); ?>"><?php esc_html_e( 'Check what this site sends', 'bs-security' ); ?></a></p>

            <?php if ( $probe ) : ?>

                <?php if ( ! empty( $probe['local'] ) ) : ?>
                    <div class="bssec-callout is-warning">
                        <p><strong><?php esc_html_e( 'This is a local development site.', 'bs-security' ); ?></strong>
                        <?php esc_html_e( 'The server column below describes whatever is serving this site on your machine, not the host the client site runs on. Local sends none of these headers, so every one reads as missing here even where Kinsta or xCloud would send it. Do not use this reading to decide what to switch on for a live site.', 'bs-security' ); ?></p>
                    </div>
                <?php endif; ?>

                <?php foreach ( (array) $probe['errors'] as $line ) : ?>
                    <div class="bssec-callout is-error"><p><?php echo esc_html( $line ); ?></p></div>
                <?php endforeach; ?>

                <?php if ( $probe['ok'] || $probe['static'] ) : ?>
                    <?php
                    $php_only = Bssec_Server_Check::from_php( $probe );
                    $rows     = array_unique( array_merge(
                        Bssec_Server_Check::REPORTED,
                        array_keys( $probe['static'] ),
                        array_keys( $probe['page'] )
                    ) );
                    ?>
                    <table class="bssec-table">
                        <thead>
                            <tr>
                                <th scope="col"><?php esc_html_e( 'Header', 'bs-security' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'From the server alone', 'bs-security' ); ?></th>
                                <th scope="col"><?php esc_html_e( 'What a visitor gets', 'bs-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ( $rows as $name ) : ?>
                            <?php
                            $from_server = $probe['static'][ $name ] ?? '';
                            $from_page   = $probe['page'][ $name ] ?? '';
                            if ( '' === $from_server && '' === $from_page ) {
                                $state = 'is-absent';
                            } elseif ( in_array( $name, $php_only, true ) ) {
                                $state = 'is-php';
                            } elseif ( '' !== $from_server && '' !== $from_page && $from_server !== $from_page ) {
                                $state = 'is-overridden';
                            } else {
                                $state = 'is-server';
                            }
                            ?>
                            <tr class="<?php echo esc_attr( $state ); ?>">
                                <th scope="row"><code><?php echo esc_html( $name ); ?></code></th>
                                <td>
                                    <?php if ( '' === $from_server ) : ?>
                                        <span class="bssec-muted"><?php esc_html_e( 'not sent', 'bs-security' ); ?></span>
                                    <?php else : ?>
                                        <code><?php echo esc_html( $from_server ); ?></code>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( '' === $from_page ) : ?>
                                        <span class="bssec-muted"><?php esc_html_e( 'not sent', 'bs-security' ); ?></span>
                                    <?php else : ?>
                                        <code><?php echo esc_html( $from_page ); ?></code>
                                        <?php if ( 'is-php' === $state ) : ?>
                                            <span class="bssec-tag"><?php esc_html_e( 'added by WordPress', 'bs-security' ); ?></span>
                                        <?php elseif ( 'is-overridden' === $state ) : ?>
                                            <span class="bssec-tag is-warning"><?php esc_html_e( 'overriding the server', 'bs-security' ); ?></span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>

                    <p class="bssec-help">
                        <strong><?php esc_html_e( 'Reading this:', 'bs-security' ); ?></strong>
                        <?php esc_html_e( 'anything in the first column is set by your host and applies to every file it serves, including scripts, stylesheets and images. Anything that appears only in the second column is set by WordPress, which means this plugin, the theme, or another plugin, and it reaches HTML pages only. Where both columns differ, WordPress is replacing the host\'s value.', 'bs-security' ); ?>
                    </p>
                <?php endif; ?>

                <p class="bssec-result-meta">
                    <?php
                    printf(
                        /* translators: 1: time since the check ran, 2: the static file URL used */
                        esc_html__( 'Checked %1$s ago, using %2$s for the server-only reading.', 'bs-security' ),
                        esc_html( human_time_diff( (int) $probe['checked_at'] ) ),
                        esc_html( (string) $probe['static_url'] )
                    );
                    ?>
                </p>
            <?php endif; ?>

        </div>
    </div>

    <!-- Exactly what goes out ------------------------------------------------>
    <div class="bssec-card">
        <div class="bssec-card-header"><h2><?php esc_html_e( 'Exactly what this plugin sends', 'bs-security' ); ?></h2></div>
        <div class="bssec-card-body">
            <p class="bssec-help bssec-lede">
                <?php esc_html_e( 'The saved settings above, rendered as the headers they produce on a front-end page over HTTPS. This is generated by the same code that sends them, so it cannot drift from what actually ships.', 'bs-security' ); ?>
            </p>
            <?php if ( $preview_headers ) : ?>
                <pre class="bssec-preview"><?php
                    foreach ( $preview_headers as $name => $value ) {
                        echo esc_html( $name . ': ' . $value ) . "\n";
                    }
                ?></pre>
            <?php else : ?>
                <p class="bssec-help"><em><?php esc_html_e( 'Nothing. Every header is switched off.', 'bs-security' ); ?></em></p>
            <?php endif; ?>
        </div>
    </div>

</div>
