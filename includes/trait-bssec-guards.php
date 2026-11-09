<?php
/**
 * Shared auth guards.
 *
 * Three contexts, three failure modes: AJAX must always answer with JSON,
 * admin-post must render WP's own death screen, REST must return WP_Error.
 * One capability check and one throttle underneath all three.
 *
 * This plugin currently only uses guard_post(); the other two are kept so the
 * audit rule stays the same across every plugin built from PLUGIN_PRIMER.md.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

trait Bssec_Guards {

    protected function guard_ajax( ?string $throttle = null, int $secs = 5 ): void {
        // $stop = false: return a bool rather than dying with a bare "-1".
        if ( ! check_ajax_referer( Bssec_Plugin::SAVE_ACTION, false, false ) ) {
            wp_send_json_error( [ 'message' => 'Security check failed. Reload the page and try again.' ], 403 );
        }
        if ( ! current_user_can( Bssec_Plugin::CAPABILITY ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized.' ], 403 );
        }
        if ( $throttle && ! $this->throttle( $throttle, $secs ) ) {
            wp_send_json_error( [ 'message' => 'Please wait a moment and try again.' ], 429 );
        }
    }

    protected function guard_post( string $action, ?string $throttle = null, int $secs = 5 ): void {
        check_admin_referer( $action );  // dies on failure
        if ( ! current_user_can( Bssec_Plugin::CAPABILITY ) ) {
            wp_die(
                esc_html__( 'You do not have permission to do that.', 'bs-security' ),
                esc_html__( 'Forbidden', 'bs-security' ),
                [ 'response' => 403 ]
            );
        }
        if ( $throttle && ! $this->throttle( $throttle, $secs ) ) {
            wp_die( 'Please wait…', 'Too Many Requests', [ 'response' => 429 ] );
        }
    }

    /** @return true|WP_Error */
    protected function guard_rest( ?string $throttle = null, int $secs = 5 ) {
        if ( ! current_user_can( Bssec_Plugin::CAPABILITY ) ) {
            return new WP_Error( 'bssec_forbidden', 'Unauthorized.', [ 'status' => 403 ] );
        }
        if ( $throttle && ! $this->throttle( $throttle, $secs ) ) {
            return new WP_Error( 'bssec_throttled', 'Please wait a moment.', [ 'status' => 429 ] );
        }
        return true;
    }

    /** Per-user throttle. Returns false when the caller should be refused. */
    private function throttle( string $key, int $secs ): bool {
        $t = 'bssec_throttle_' . $key . '_' . get_current_user_id();
        if ( get_transient( $t ) ) return false;
        set_transient( $t, 1, $secs );
        return true;
    }
}
