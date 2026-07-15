<?php
/**
 * CoinMarketCap API handler class.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_API {

	/**
	 * CoinMarketCap API Endpoint.
	 */
	const API_URL = 'https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest';

	/**
	 * Fetch quote for a specific symbol converted to a currency.
	 *
	 * @param string $symbol  Token symbol (e.g., BTC).
	 * @param string $convert Currency to convert to (e.g., USD).
	 * @return array|WP_Error Array of price info or WP_Error on failure.
	 */
	public static function get_price( $symbol, $convert = 'USD' ) {
		$symbol  = strtoupper( sanitize_text_field( $symbol ) );
		$convert = strtoupper( sanitize_text_field( $convert ) );

		if ( empty( $symbol ) ) {
			return new WP_Error( 'invalid_symbol', __( 'Cryptocurrency symbol is required.', 'crypto' ) );
		}

		$transient_key = 'crypto_price_' . $symbol . '_' . $convert;

		// 1. Check transient cache
		$cached_data = get_transient( $transient_key );
		if ( false !== $cached_data ) {
			return $cached_data;
		}

		// 2. Fetch API Key
		$api_key = get_option( 'crypto_api_key' );
		if ( empty( $api_key ) ) {
			return new WP_Error( 'missing_api_key', __( 'CoinMarketCap API Key is not configured.', 'crypto' ) );
		}

		// 3. Query the API
		$url = add_query_arg(
			array(
				'symbol'  => $symbol,
				'convert' => $convert,
			),
			self::API_URL
		);

		$response = wp_remote_get(
			$url,
			array(
				'headers' => array(
					'X-CMC_PRO_API_KEY' => $api_key,
					'Accept'            => 'application/json',
					'User-Agent'        => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
				),
				'timeout' => 15,
			) );

		// 4. Handle HTTP or Connection Error
		if ( is_wp_error( $response ) ) {
			return self::handle_fallback( $symbol, $convert, $response->get_error_message() );
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body          = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $response_code ) {
			// translators: %d: HTTP response status code.
			$error_msg = isset( $body['status']['error_message'] ) ? $body['status']['error_message'] : sprintf( __( 'API returned HTTP code %d', 'crypto' ), $response_code );
			return self::handle_fallback( $symbol, $convert, $error_msg );
		}

		// 5. Verify Data Structure
		if ( ! isset( $body['data'][ $symbol ] ) ) {
			// translators: %s: cryptocurrency symbol (e.g. BTC).
			return new WP_Error( 'api_error', sprintf( __( 'No data returned for symbol: %s', 'crypto' ), $symbol ) );
		}

		$data = $body['data'][ $symbol ];
		if ( ! isset( $data['quote'][ $convert ] ) ) {
			// translators: %s: fiat currency symbol (e.g. USD).
			return new WP_Error( 'api_error', sprintf( __( 'No quote returned for currency: %s', 'crypto' ), $convert ) );
		}

		$quote = $data['quote'][ $convert ];

		// 6. Structure Success Data
		$formatted_data = array(
			'id'                 => $data['id'],
			'name'               => $data['name'],
			'symbol'             => $data['symbol'],
			'price'              => floatval( $quote['price'] ),
			'percent_change_1h'  => isset( $quote['percent_change_1h'] ) ? floatval( $quote['percent_change_1h'] ) : 0.0,
			'percent_change_24h' => isset( $quote['percent_change_24h'] ) ? floatval( $quote['percent_change_24h'] ) : 0.0,
			'percent_change_7d'  => isset( $quote['percent_change_7d'] ) ? floatval( $quote['percent_change_7d'] ) : 0.0,
			'market_cap'         => isset( $quote['market_cap'] ) ? floatval( $quote['market_cap'] ) : 0.0,
			'volume_24h'         => isset( $quote['volume_24h'] ) ? floatval( $quote['volume_24h'] ) : 0.0,
			'last_updated'       => time(),
			'is_fallback'        => false,
		);

		// 7. Store in Cache and Fallback option
		$cache_duration_mins = (int) get_option( 'crypto_cache_duration', 10 );
		$cache_duration      = $cache_duration_mins * MINUTE_IN_SECONDS;

		set_transient( $transient_key, $formatted_data, $cache_duration );
		update_option( 'crypto_fallback_' . $symbol . '_' . $convert, $formatted_data );

		// Register the cache key to track for clearing
		self::register_active_cache( $transient_key );

		return $formatted_data;
	}

	/**
	 * Handle API failure by falling back to the last successfully stored value.
	 */
	private static function handle_fallback( $symbol, $convert, $error_msg ) {
		$fallback_data = get_option( 'crypto_fallback_' . $symbol . '_' . $convert );

		if ( ! empty( $fallback_data ) && is_array( $fallback_data ) ) {
			$fallback_data['is_fallback'] = true;
			$fallback_data['fallback_error'] = $error_msg;

			// Store in transient for 1 minute to avoid API hammering during downtime
			set_transient( 'crypto_price_' . $symbol . '_' . $convert, $fallback_data, MINUTE_IN_SECONDS );
			self::register_active_cache( 'crypto_price_' . $symbol . '_' . $convert );

			return $fallback_data;
		}

		// translators: %s: error message.
		return new WP_Error( 'api_connection_failed', sprintf( __( 'API connection failed: %s', 'crypto' ), $error_msg ) );
	}

	/**
	 * Register active transient key in settings option.
	 */
	private static function register_active_cache( $transient_key ) {
		$cache_keys = get_option( 'crypto_active_caches', array() );
		if ( ! in_array( $transient_key, $cache_keys, true ) ) {
			$cache_keys[] = $transient_key;
			update_option( 'crypto_active_caches', $cache_keys );
		}
	}

	/**
	 * Clear all tracked transients and options.
	 */
	public static function clear_all_caches() {
		$cache_keys = get_option( 'crypto_active_caches', array() );
		if ( is_array( $cache_keys ) ) {
			foreach ( $cache_keys as $key ) {
				// Strip '_transient_' if it somehow contains it, but WordPress delete_transient expects key without prefix
				$clean_key = str_replace( '_transient_', '', $key );
				delete_transient( $clean_key );
			}
		}
		delete_option( 'crypto_active_caches' );
	}

	/**
	 * Test API Key validity.
	 *
	 * @param string $api_key API key to test.
	 * @return bool|string True if valid, error message string if invalid/error.
	 */
	public static function test_api_key( $api_key ) {
		if ( empty( $api_key ) ) {
			return __( 'API Key is empty.', 'crypto' );
		}

		$url = add_query_arg( array( 'symbol' => 'BTC' ), self::API_URL );
		$response = wp_remote_get(
			$url,
			array(
				'headers' => array(
					'X-CMC_PRO_API_KEY' => $api_key,
					'Accept'            => 'application/json',
					'User-Agent'        => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
				),
				'timeout' => 10,
			) );

		if ( is_wp_error( $response ) ) {
			return $response->get_error_message();
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body          = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $response_code ) {
			// translators: %d: HTTP response status code.
			return isset( $body['status']['error_message'] ) ? $body['status']['error_message'] : sprintf( __( 'API returned HTTP code %d', 'crypto' ), $response_code );
		}

		return true;
	}
}
