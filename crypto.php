<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://odude.com/
 * @since             2.22
 * @package           Crypto
 *
 * @wordpress-plugin
 * Plugin Name:       Crypto
 * Plugin URI:        http://odude.com/
 * Description:       Crypto - Price widget, Metamask Login, Block content. 
 * Version:           2.22
 * Author:            ODude
 * Author URI:        https://odude.com/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       crypto
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

define('CRYPTO_VERSION', '2.22');
define('CRYPTO_FOLDER', dirname(plugin_basename(__FILE__)));
define('CRYPTO_PLUGIN_URL', content_url('/plugins/' . CRYPTO_FOLDER));
define('CRYPTO_BASE_DIR', WP_CONTENT_DIR . '/plugins/' . CRYPTO_FOLDER . '/');
define('CRYPTO_ROOT_URL', plugin_dir_url(__FILE__));
define('CRYPTO_POLYGON_URL', 'https://polygonscan.com/token/0x3325229F15fe0Cee4148C1e395b080C8A51353Dd?a=');
define('CRYPTO_FILECOIN_URL', 'https://explorer.glif.io/address/0x732dC8d0c7388c3E60e70776D0a1e663166cfCBD/?');

// Path to the plugin directory
if (!defined('CRYPTO_PLUGIN_DIR')) {
    define('CRYPTO_PLUGIN_DIR', plugin_dir_path(dirname(__FILE__)) . '' . CRYPTO_FOLDER . '/');
}

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-crypto-activator.php
 */
function activate_crypto()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-crypto-activator.php';
    Crypto_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-crypto-deactivator.php
 */
function deactivate_crypto()
{
    require_once plugin_dir_path(__FILE__) . 'includes/class-crypto-deactivator.php';
    Crypto_Deactivator::deactivate();
}

register_activation_hook(__FILE__, 'activate_crypto');
register_deactivation_hook(__FILE__, 'deactivate_crypto');

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path(__FILE__) . 'includes/class-crypto.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function run_crypto()
{

    $plugin = new Crypto();
    $plugin->run();
}
run_crypto();
