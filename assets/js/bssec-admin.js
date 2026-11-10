/**
 * Biscuit Security — admin screen behaviour.
 *
 * Four jobs: show the options belonging to a switch only while that switch is
 * on, make turning HSTS on take one deliberate extra step, confirm before
 * clearing CSP reports, and send a test CSP report the way a browser would.
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

    // Clear reports: one confirmation, because it cannot be undone.
    var clearButton = document.querySelector( '[data-bssec-clear]' );
    if ( clearButton ) {
        clearButton.addEventListener( 'click', function ( event ) {
            if ( strings.clearConfirm && ! window.confirm( strings.clearConfirm ) ) {
                event.preventDefault();
            }
        } );
    }

    // Send a test report, the way a visitor's browser would.
    //
    // credentials: 'omit' is the point: no login cookie, so the request meets
    // the same Cloudflare rules and REST lockdowns a real report does, rather
    // than sailing through as a signed-in administrator. A 204 reloads the
    // page, and the screen says whether the report was stored, which a 204
    // alone cannot (the endpoint answers 204 for refused reports too). Any
    // other answer is explained here. Messages go in with textContent only.
    var testButton = document.querySelector( '[data-bssec-test-url]' );
    var testResult = document.getElementById( 'bssec-test-result' );
    if ( testButton && testResult && window.fetch ) {
        var say = function ( text ) {
            testResult.textContent = text;
            testResult.hidden = false;
        };

        testButton.addEventListener( 'click', function () {
            var page = testButton.getAttribute( 'data-bssec-test-page' );
            testButton.disabled = true;
            say( strings.testSending || '' );

            fetch( testButton.getAttribute( 'data-bssec-test-url' ), {
                method: 'POST',
                credentials: 'omit',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/csp-report' },
                body: JSON.stringify( { 'csp-report': {
                    'document-uri':        page,
                    'effective-directive': 'bssec-test',
                    'blocked-uri':         new URL( page ).origin,
                    'disposition':         'report'
                } } )
            } ).then( function ( response ) {
                if ( 204 === response.status ) {
                    var next = new URL( window.location.href );
                    next.searchParams.delete( 'bssec-updated' );
                    next.searchParams.delete( 'bssec-cleared' );
                    next.searchParams.set( 'bssec-tested', String( Date.now() ) );
                    next.hash = 'bssec-report-only';
                    window.location.assign( next.toString() );
                    return;
                }
                testButton.disabled = false;
                if ( 404 === response.status ) return say( strings.test404 );
                if ( 401 === response.status ) return say( strings.test401 );
                if ( 403 === response.status ) {
                    return say( response.headers.get( 'cf-mitigated' ) ? strings.test403cf : strings.test403 );
                }
                say( ( strings.testOther || '%s' ).replace( '%s', String( response.status ) ) );
            } ).catch( function ( error ) {
                testButton.disabled = false;
                say( ( strings.testNetwork || '%s' ).replace( '%s', String( error && error.message || error ) ) );
            } );
        } );
    }
}() );
