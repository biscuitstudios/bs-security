<?php
/**
 * Plugin Name:       Biscuit Security
 * Plugin URI:        https://github.com/biscuitstudios/bs-security
 * Description:       Biscuit's site security in one plugin. Sends the response security headers managed hosts and WordPress leave off, hides usernames from logged-out visitors, gives one generic login error, and switches off the theme and plugin file editor. Replaces Biscuit Security Headers.
 * Version:           0.4.1
 * Requires at least: 6.3
 * Requires PHP:      8.2
 * Author:            Biscuit Studios
 * Author URI:        https://biscuitstudios.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bs-security
 * Update URI:        https://github.com/biscuitstudios/bs-security
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'BSSEC_VERSION',  '0.4.1' );
define( 'BSSEC_FILE',     __FILE__ );
define( 'BSSEC_DIR',      plugin_dir_path( __FILE__ ) );
define( 'BSSEC_URL',      plugin_dir_url( __FILE__ ) );
define( 'BSSEC_BASENAME', plugin_basename( __FILE__ ) );

spl_autoload_register( function ( $class ) {
    if ( 0 !== strpos( $class, 'Bssec_' ) ) return;
    $base = strtolower( str_replace( '_', '-', $class ) );
    foreach ( [ 'includes/', 'admin/' ] as $dir ) {
        foreach ( [ "class-$base.php", "trait-$base.php" ] as $file ) {
            $path = BSSEC_DIR . $dir . $file;
            if ( file_exists( $path ) ) { require_once $path; return; }
        }
    }
} );

register_activation_hook( __FILE__, [ 'Bssec_Activator', 'activate' ] );

// Updates are served from the repo's GitHub Releases. Without this the plugin's
// Update URI header points at GitHub and nothing ever answers, so the plugins
// screen silently never offers a new version.
( new Bssec_Updater( __FILE__ ) )->init();

add_action( 'plugins_loaded', function () {
    // The emitter must init outside is_admin() — its main job is front-end
    // responses, and it also hooks login_init, which is neither admin nor a
    // normal front-end request.
    ( new Bssec_Headers() )->init();

    // Hardening hooks REST, login, front-end template redirects and
    // capabilities, so it also has to run in every context, not only admin.
    ( new Bssec_Hardening() )->init();

    // CSP report-only collection. REST and WP-Cron, so it runs outside
    // is_admin() too. Adds hooks only; the route, table and cron event exist
    // only while report-only is switched on.
    ( new Bssec_Csp_Reports() )->init();

    if ( is_admin() ) {
        ( new Bssec_Admin() )->init();
    }
} );
