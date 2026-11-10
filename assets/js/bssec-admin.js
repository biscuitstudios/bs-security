/**
 * Biscuit Security — admin screen behaviour.
 *
 * Five jobs: switch tabs without a reload, show the options belonging to a
 * switch only while that switch is on, make turning HSTS on take one
 * deliberate extra step, confirm before clearing CSP reports, and send a test
 * CSP report the way a browser would.
 *
 * No jQuery. Nothing here is required for the form to work — every dependent
 * block renders with its correct hidden state from PHP, and the fields inside
 * a hidden block still submit — so a scripting failure degrades to "everything
 * is visible" rather than to a broken screen. The tabs degrade to plain links,
 * one page load per tab, with the open tab chosen by PHP.
 */
( function () {
    'use strict';

    var strings = window.bssecAdmin || {};

    // Tabs. PHP has already hidden every panel but the open one; this only
    // swaps which one shows, and keeps three things in step with it: the URL,
    // so a reload stays put; the form's tab field, so Save comes back here;
    // and the Save button, which the Check tab has no use for. Hidden panels
    // stay inside the form, so their fields still submit.
    var tabList = document.querySelector( '[data-bssec-tabs]' );
    if ( tabList ) {
        var tabs     = Array.prototype.slice.call( tabList.querySelectorAll( '[data-bssec-tab]' ) );
        var tabField = document.querySelector( 'input[name="bssec-tab"]' );
        var actions  = document.querySelector( '.bssec-actions' );

        var panelFor = function ( tab ) {
            return document.getElementById( 'bssec-panel-' + tab.getAttribute( 'data-bssec-tab' ) );
        };

        var select = function ( tab, focus ) {
            var name = tab.getAttribute( 'data-bssec-tab' );
            tabs.forEach( function ( other ) {
                var on    = other === tab;
                var panel = panelFor( other );
                other.classList.toggle( 'nav-tab-active', on );
                other.setAttribute( 'aria-selected', on ? 'true' : 'false' );
                other.tabIndex = on ? 0 : -1;
                if ( panel ) panel.hidden = ! on;
            } );
            if ( tabField ) tabField.value = name;
            if ( actions ) actions.hidden = 'check' === name;
            if ( window.history && window.history.replaceState ) {
                // The hash belonged to the tab being left (#bssec-report-only
                // after a test report, say), so it goes too.
                var url = new URL( window.location.href );
                url.searchParams.set( 'bssec-tab', name );
                url.hash = '';
                window.history.replaceState( null, '', url.toString() );
            }
            if ( focus ) tab.focus();
        };

        tabList.setAttribute( 'role', 'tablist' );
        tabs.forEach( function ( tab ) {
            var panel = panelFor( tab );
            var on    = tab.classList.contains( 'nav-tab-active' );
            tab.setAttribute( 'role', 'tab' );
            tab.removeAttribute( 'aria-current' );
            tab.setAttribute( 'aria-selected', on ? 'true' : 'false' );
            tab.tabIndex = on ? 0 : -1;
            if ( panel ) {
                tab.setAttribute( 'aria-controls', panel.id );
                panel.setAttribute( 'role', 'tabpanel' );
                panel.setAttribute( 'aria-labelledby', tab.id );
            }
            tab.addEventListener( 'click', function ( event ) {
                event.preventDefault();
                select( tab, false );
            } );
        } );

        // Arrow keys move between tabs and open them, Home and End jump to
        // the ends: the keyboard pattern screen reader users expect of a
        // tablist. Tab itself moves on into the open panel.
        tabList.addEventListener( 'keydown', function ( event ) {
            var at = tabs.indexOf( document.activeElement );
            if ( at < 0 ) return;
            var to = null;
            if ( 'ArrowRight' === event.key ) to = ( at + 1 ) % tabs.length;
            if ( 'ArrowLeft' === event.key )  to = ( at - 1 + tabs.length ) % tabs.length;
            if ( 'Home' === event.key )       to = 0;
            if ( 'End' === event.key )        to = tabs.length - 1;
            if ( null === to ) return;
            event.preventDefault();
            select( tabs[ to ], true );
        } );
    }

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
                    next.searchParams.set( 'bssec-tab', 'csp' );
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
