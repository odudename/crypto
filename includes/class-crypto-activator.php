<?php

/**
 * Fired during plugin activation
 *
 * @link       https://odude.com/
 * @since      1.0.0
 *
 * @package    Crypto
 * @subpackage Crypto/includes
 */

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    Crypto
 * @subpackage Crypto/includes
 * @author     ODude <navneet@odude.com>
 */
class Crypto_Activator
{

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function activate()
	{
		global $wpdb;

		$table_name = $wpdb->prefix . 'custom_users';
		$charset_collate = $wpdb->get_charset_collate();

		// SQL to create table
		$sql = "CREATE TABLE $table_name (
            ID BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_login VARCHAR(191) NOT NULL UNIQUE,
            user_registered DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_status TINYINT(1) NOT NULL DEFAULT 0,
            user_block TINYINT(1) NOT NULL DEFAULT 0,
			domain_count TINYINT(1) NOT NULL DEFAULT 0,
			domain_names TEXT NOT NULL,
            PRIMARY KEY (ID)
        ) $charset_collate;";

		// Log SQL for debugging
		//error_log($sql);

		// Include WordPress upgrade script
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// Run SQL
		dbDelta($sql);

		// Verify if table was created
		$table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
		/*
		if ($table_exists) {
			error_log("Table $table_name created successfully.");
		} else {
			error_log("Failed to create table $table_name.");
		}
			*/

		// Create the "Check Web3 Name" page if it doesn't exist
		if (null === $wpdb->get_row("SELECT post_name FROM {$wpdb->prefix}posts WHERE post_name = 'check-domain'", 'ARRAY_A')) {
			$current_user = wp_get_current_user();

			// Create post object
			$page = array(
				'post_title'  => __('Check Web3 Name'),
				'post_status' => 'publish',
				'post_author' => $current_user->ID,
				'post_type'   => 'page',
				'post_content' => '<!-- wp:shortcode -->
				 [crypto-connect label="Connect Wallet" class="fl-button fl-is-info fl-is-light"]
				<!-- /wp:shortcode -->
				
				<!-- wp:shortcode -->
				 [crypto-access-domain]
				<!-- /wp:shortcode -->'
			);

			// Insert the post into the database
			$aid = wp_insert_post($page);

			crypto_set_option('restrict_page', 'crypto_access_settings', $aid);
		}

		// Set default options
		crypto_set_option('chainid', 'crypto_login_metamask', '0');
		flush_rewrite_rules();
	}
}
