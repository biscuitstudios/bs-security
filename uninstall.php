<?php
/**
 * Uninstall — remove settings and any parked probe results.
 *
 * The headers themselves need no cleanup: they were only ever sent by hooks
 * that stopped firing the moment the plugin was deactivated. Nothing was
 * written to .htaccess, to wp-config.php, or to any file on disk. That is
 * deliberate, and the reason this file is short.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) exit;

delete_option( 'bssec_settings' );

// The per-user probe results and the guard throttles are option-backed
// transients, one row per user, so there is no single key to delete.
global $wpdb;
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '\_transient\_bssec\_%'
        OR option_name LIKE '\_transient\_timeout\_bssec\_%'"
);

// CSP report-only: the reports table, its prune event, its two options. All
// present only on a site where report-only was ever switched on; harmless to
// clear everywhere else. Names written out rather than read from
// Bssec_Csp_Reports, because uninstall runs without the plugin loaded.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}bssec_csp_reports" );
wp_clear_scheduled_hook( 'bssec_prune_csp_reports' );
delete_option( 'bssec_csp_stats' );
delete_option( 'bssec_db_version' );
