<?php
/**
 * The plugin bootstrap file.
 *
 * @link              https://odude.com/
 * @since             3.0.0
 * @package           Crypto
 *
 * @wordpress-plugin
 * Plugin Name:       Crypto
 * Plugin URI:        https://odude.com/
 * Description:       Crypto - Live prices for BTC and other cryptocurrency tokens using CoinMarketCap API. Displayed via a customizable shortcode with premium glassmorphic and dark layouts.
 * Version:           3.0.0
 * Author:            ODude
 * Author URI:        https://odude.com/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       crypto
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

// Define Plugin Constants
define( 'CRYPTO_VERSION', '3.0.0' );
define( 'CRYPTO_PATH', plugin_dir_path( __FILE__ ) );
define( 'CRYPTO_URL', plugin_dir_url( __FILE__ ) );

/**
 * Load plugin dependencies.
 */
require_once CRYPTO_PATH . 'includes/class-crypto-api.php';
require_once CRYPTO_PATH . 'includes/class-crypto-admin.php';
require_once CRYPTO_PATH . 'includes/class-crypto-shortcode.php';
require_once CRYPTO_PATH . 'includes/class-crypto-block.php';
require_once CRYPTO_PATH . 'includes/class-crypto-elementor.php';

/**
 * Plugin Activation Hook.
 * Set default settings.
 */
function crypto_activate() {
	add_option( 'crypto_default_currency', 'USD' );
	add_option( 'crypto_cache_duration', 10 );
}
register_activation_hook( __FILE__, 'crypto_activate' );

/**
 * Initialize Plugin Components.
 */
function crypto_run() {
	if ( is_admin() ) {
		new Crypto_Admin();
	}
	new Crypto_Shortcode();
	new Crypto_Block();
	new Crypto_Elementor();
}
crypto_run();
