<?php
/**
 * Activation.
 *
 * Writing the defaults here is what makes "install it and the safe settings
 * are on" true. Without it the option would not exist until someone visited
 * the settings screen and pressed Save, and a plugin rolled out across 62
 * sites would be doing nothing on all of them.
 *
 * Existing settings are never overwritten, so reactivating after an update, or
 * after a deactivate while debugging something, does not silently reset a site
 * that had been configured by hand.
 *
 * On a site that ran Biscuit Security Headers, the plugin this one replaces,
 * its header settings are copied across on first activation. Copied, not
 * moved: the old row is left alone, so going back to the old plugin still
 * works, and the old plugin's own uninstall removes it when it is deleted.
 * That is also why the order matters on a live site: activate this one first,
 * then delete the old one.
 *
 * There is no deactivation hook and no capability to strip. Deactivating stops
 * the headers and the hardening by itself, because the hooks stop firing.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Bssec_Activator {

    /** The option Biscuit Security Headers (bs-security-headers) stored its settings in. */
    public const LEGACY_OPTION = 'bssh_settings';

    public static function activate(): void {
        if ( false !== get_option( Bssec_Plugin::OPTION, false ) ) return;

        Bssec_Plugin::save( self::initial_settings( get_option( self::LEGACY_OPTION, false ) ) );
    }

    /**
     * The settings a first activation starts from.
     *
     * Only keys this plugin knows are taken from the old row, and anything it
     * did not have (all of the hardening) comes from the defaults. The values
     * themselves are not re-sanitized here: the old plugin sanitized them on
     * save with the same code, and the emitter cleans every value again at the
     * moment it is sent, whatever wrote the option.
     *
     * @param mixed $legacy The old option, or false when there was none.
     */
    public static function initial_settings( $legacy ): array {
        $defaults = Bssec_Plugin::defaults();
        if ( ! is_array( $legacy ) ) return $defaults;
        return array_merge( $defaults, array_intersect_key( $legacy, $defaults ) );
    }
}
