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
