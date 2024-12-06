<?php

class Crypto_User
{

	public function __construct()
	{
		add_action("wp_ajax_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
		add_action("wp_ajax_nopriv_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
	}


	/**
	 * Register a custom user.
	 *
	 * @param string $user_login Wallet address as the username.
	 * @return bool True on success, false on failure.
	 */
	public static function register_custom_user($user_login)
	{
		global $wpdb;

		// Sanitize the input wallet address
		$user_login = sanitize_text_field($user_login);

		// Check if the user already exists
		$table_name = $wpdb->prefix . 'custom_users';
		$existing_user = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM $table_name WHERE user_login = %s",
			$user_login
		));

		// If user already exists, return false
		if ($existing_user) {
			return false; // User already exists
		}

		// Insert new user into the custom_users table
		$current_time = current_time('mysql'); // Get current date and time
		$insert_data = array(
			'user_login'     => $user_login,
			'user_registered' => $current_time,
			'user_status'     => 0, // Default status is 0 (not logged in)
			'user_block'      => 0  // Default block status is 0 (not blocked)
		);

		// Insert the user into the database
		$inserted = $wpdb->insert($table_name, $insert_data);

		// Check if the insertion was successful
		if ($inserted) {
			// Start the session if not already started
			if (!session_id()) {
				session_start();
			}

			// Set session variable for user login
			$_SESSION['custom_user'] = $user_login;

			// Trigger WordPress action for custom user registration
			do_action('custom_user_registered', $user_login);

			return true; // Successfully registered and logged in
		} else {
			return false; // Failed to register
		}
	}

	/**
	 * Log in a custom user.
	 *
	 * @param string $user_login Wallet address as the username.
	 * @return bool True on success, false on failure.
	 */
	public static function login_custom_user($user_login)
	{
		global $wpdb;

		// Sanitize the input wallet address
		$user_login = sanitize_text_field($user_login);

		// Check if user exists
		$table_name = $wpdb->prefix . 'custom_users';
		$user = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM $table_name WHERE user_login = %s",
			$user_login
		));

		// If user does not exist, return false
		if (empty($user)) {
			return false; // User does not exist
		}

		// If user is blocked, return false
		if ($user->user_block == 1) {
			return false; // User is blocked
		}

		// Start the session if not already started
		if (!session_id()) {
			session_start();
		}

		// Set session variable for user login
		$_SESSION['custom_user'] = $user_login;

		// Trigger WordPress action for custom user login
		do_action('custom_user_logged_in', $user_login);

		return true; // Successfully logged in
	}

	/**
	 * Log out the custom user.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function logout_custom_user()
	{
		// Check if the user is logged in
		if (!isset($_SESSION['custom_user'])) {
			return false; // No user logged in
		}

		// Get the wallet address from the session
		$user_login = sanitize_text_field($_SESSION['custom_user']);

		// Clear the session
		unset($_SESSION['custom_user']);

		// Trigger WordPress action for custom user logout
		do_action('custom_user_logged_out', $user_login);

		return true; // Successfully logged out
	}

	/**
	 * Check if a custom user is logged in.
	 *
	 * @return bool True if the user is logged in, false otherwise.
	 */
	public static function if_custom_user_logged_in()
	{
		// Start the session if it's not already started
		if (!session_id()) {
			session_start();
		}

		// Check if the custom user is logged in via session
		if (isset($_SESSION['custom_user']) && !empty($_SESSION['custom_user'])) {
			return true; // User is logged in
		}

		return false; // User is not logged in
	}

	/**
	 * Check if a custom user exists.
	 *
	 * @param string $username The username (wallet address).
	 * @return bool True if user exists, false otherwise.
	 */
	public static function if_custom_user_exists($username)
	{
		global $wpdb;

		// Sanitize the username input to avoid SQL injection
		$username = sanitize_text_field($username);

		// Query to check if the user exists in the custom users table
		$user = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT ID FROM {$wpdb->prefix}custom_users WHERE user_login = %s",
				$username
			)
		);

		// If user exists, return true; otherwise, return false
		return $user ? true : false;
	}

	// Function to set custom user status (like user_status or user_block)
	public static function set_custom_user_value($user_login, $column, $value)
	{
		global $wpdb;

		// Sanitize input parameters
		$user_login = sanitize_text_field($user_login);
		$column = sanitize_text_field($column);

		// Serialize the value if it is an array
		if (is_array($value)) {
			$value = maybe_serialize($value);
		} else {
			$value = sanitize_text_field($value); // Sanitize non-array values as text
		}

		// Ensure the column is valid
		$valid_columns = ['user_status', 'user_block', 'domain_count', 'domain_names']; // Add more valid columns if needed
		if (!in_array($column, $valid_columns)) {
			return false; // Invalid column name
		}

		// Update the user data in the custom_users table
		$table_name = $wpdb->prefix . 'custom_users';
		$updated = $wpdb->update(
			$table_name,
			[$column => $value], // The data to update
			['user_login' => $user_login], // The WHERE condition (user_login)
			['%s'], // Format for the value (string)
			['%s'] // Format for user_login (string)
		);

		// Check if the update was successful
		if ($updated !== false) {
			// Trigger WordPress action for custom user status update
			do_action('custom_user_status_updated', $user_login, $column, $value);
			return true; // Successfully updated
		}

		return false; // Failed to update
	}



	// Function to get custom user status (like user_status or user_block)
	public static function get_custom_user_value($user_login, $column)
	{
		global $wpdb;

		// Sanitize input parameters
		$user_login = sanitize_text_field($user_login);
		$column = sanitize_text_field($column);

		// Ensure the column is valid
		$valid_columns = ['user_status', 'user_block', 'domain_count', 'domain_names']; // Add more valid columns if needed
		if (!in_array($column, $valid_columns)) {
			return false; // Invalid column name
		}

		// Query to get the value of the specified column for the given user
		$table_name = $wpdb->prefix . 'custom_users';
		$value = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT $column FROM $table_name WHERE user_login = %s",
				$user_login
			)
		);

		// If the value is found, return it; otherwise, return false
		if ($value !== null) {
			return $value;
		}

		return false; // No value found (user doesn't exist or column is invalid)
	}

	public static function get_current_custom_user_login()
	{
		// Start the session if not already started
		if (!session_id()) {
			session_start();
		}

		// Check if a custom user is logged in
		if (isset($_SESSION['custom_user']) && !empty($_SESSION['custom_user'])) {
			// Sanitize and return the user_login stored in the session
			return sanitize_text_field($_SESSION['custom_user']);
		}

		return false; // No custom user is logged in
	}
}
