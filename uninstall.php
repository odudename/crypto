<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package    Crypto
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// 1. Clear all transients
$cache_keys = get_option( 'crypto_active_caches', array() );
if ( is_array( $cache_keys ) ) {
	foreach ( $cache_keys as $key ) {
		// WordPress delete_transient expects key without prefix
		$clean_key = str_replace( 'crypto_price_', '', $key );
		delete_transient( $clean_key );

		// Delete corresponding fallback option
		// Key format is crypto_price_{SYMBOL}_{CONVERT} -> fallback key is crypto_fallback_{SYMBOL}_{CONVERT}
		$fallback_key = str_replace( 'crypto_price_', 'crypto_fallback_', $key );
		delete_option( $fallback_key );
	}
}

// 2. Delete configuration options
delete_option( 'crypto_api_key' );
delete_option( 'crypto_default_currency' );
delete_option( 'crypto_cache_duration' );
delete_option( 'crypto_api_status' );
delete_option( 'crypto_active_caches' );
