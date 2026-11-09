/**
 * Biscuit Security — admin screen behaviour.
 *
 * Two jobs: show the options belonging to a switch only while that switch is
 * on, and make turning HSTS on take one deliberate extra step.
 *
 * No jQuery. Nothing here is required for the form to work — every dependent
 * block renders with its correct hidden state from PHP, and the fields inside
 * a hidden block still submit — so a scripting failure degrades to "everything
 * is visible" rather than to a broken screen.
 */
( function () {
    'use strict';

    var strings = window.bssecAdmin || {};

    /** Show or hide the block a checkbox controls. */
    function sync( input ) {
        var target = document.getElementById( input.getAttribute( 'data-bssec-controls' ) );
        if ( ! target ) return;
        target.hidden = ! input.checked;
    }

    var controllers = document.querySelectorAll( '[data-bssec-controls]' );

    Array.prototype.forEach.call( controllers, function ( input ) {
        // Re-assert on load. A browser restoring form state after a back
        // navigation sets the checkbox without firing change, which would
        // otherwise leave the panel and its switch disagreeing.
        sync( input );

        input.addEventListener( 'change', function () {
            // Confirm before switching on, never before switching off. Turning
            // it off is always safe and always allowed; it is turning it on
            // that cannot be taken back.
            if (
                input.checked &&
                '1' === input.getAttribute( 'data-bssec-confirm' ) &&
                strings.hstsConfirm &&
                ! window.confirm( strings.hstsConfirm )
            ) {
                input.checked = false;
            }

            sync( input );
        } );
    } );
}() );
