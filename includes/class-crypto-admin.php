<?php
/**
 * Admin settings and dashboard class.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_Admin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'admin_init', array( $this, 'handle_clear_cache' ) );
	}

	/**
	 * Add Crypto settings submenu page under Settings.
	 */
	public function add_settings_page() {
		add_options_page(
			__( 'Crypto Price Settings', 'crypto' ),
			__( 'Crypto Settings', 'crypto' ),
			'manage_options',
			'crypto-settings',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Register settings, sections, and fields.
	 */
	public function register_settings() {
		register_setting( 'crypto_settings_group', 'crypto_api_key', array(
			'type'              => 'string',
			'sanitize_callback' => 'sanitize_text_field',
			'default'           => '',
		) );

		register_setting( 'crypto_settings_group', 'crypto_default_currency', array(
			'type'              => 'string',
			'sanitize_callback' => 'sanitize_text_field',
			'default'           => 'USD',
		) );

		register_setting( 'crypto_settings_group', 'crypto_cache_duration', array(
			'type'              => 'integer',
			'sanitize_callback' => 'absint',
			'default'           => 10,
		) );

		// Validate API Key and update status when settings are saved
		add_filter( 'pre_update_option_crypto_api_key', array( $this, 'validate_api_key_on_save' ), 10, 2 );
	}

	/**
	 * Hook to validate API Key when it is saved.
	 */
	public function validate_api_key_on_save( $new_value, $old_value ) {
		if ( empty( $new_value ) ) {
			delete_option( 'crypto_api_status' );
			return $new_value;
		}

		$test = Crypto_API::test_api_key( $new_value );
		if ( true === $test ) {
			update_option( 'crypto_api_status', 'valid' );
			add_settings_error(
				'crypto_settings_group',
				'crypto_api_success',
				__( 'API connection successful! CoinMarketCap API key is valid.', 'crypto' ),
				'updated'
			);
		} else {
			update_option( 'crypto_api_status', $test );
			add_settings_error(
				'crypto_settings_group',
				'crypto_api_error',
				sprintf( __( 'API connection failed: %s', 'crypto' ), $test ),
				'error'
			);
		}

		return $new_value;
	}

	/**
	 * Handle request to clear cache.
	 */
	public function handle_clear_cache() {
		if ( ! isset( $_POST['crypto_clear_cache_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST['crypto_clear_cache_nonce'], 'crypto_clear_cache_action' ) ) {
			wp_die( __( 'Security check failed.', 'crypto' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'You do not have permission to manage options.', 'crypto' ) );
		}

		Crypto_API::clear_all_caches();

		add_settings_error(
			'crypto_settings_group',
			'crypto_cache_cleared',
			__( 'All cached prices have been successfully cleared.', 'crypto' ),
			'updated'
		);
	}

	/**
	 * Enqueue admin styles and scripts.
	 */
	public function enqueue_admin_assets( $hook ) {
		if ( 'settings_page_crypto-settings' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'crypto-admin-style',
			plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/crypto-admin.css',
			array(),
			CRYPTO_VERSION
		);
	}

	/**
	 * Render the settings page HTML.
	 */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$api_key          = get_option( 'crypto_api_key', '' );
		$default_currency = get_option( 'crypto_default_currency', 'USD' );
		$api_status       = get_option( 'crypto_api_status', '' );
		$cache_duration   = get_option( 'crypto_cache_duration', 10 );

		// If key is present but status is not valid, verify the connection on page load
		if ( ! empty( $api_key ) && 'valid' !== $api_status ) {
			$test = Crypto_API::test_api_key( $api_key );
			if ( true === $test ) {
				$api_status = 'valid';
				update_option( 'crypto_api_status', 'valid' );
			} else {
				$api_status = $test;
				update_option( 'crypto_api_status', $test );
			}
		}

		$currencies = array(
			'USD' => __( 'USD - US Dollar ($)', 'crypto' ),
			'EUR' => __( 'EUR - Euro (€)', 'crypto' ),
			'GBP' => __( 'GBP - British Pound (£)', 'crypto' ),
			'JPY' => __( 'JPY - Japanese Yen (¥)', 'crypto' ),
			'CAD' => __( 'CAD - Canadian Dollar ($)', 'crypto' ),
			'AUD' => __( 'AUD - Australian Dollar ($)', 'crypto' ),
			'INR' => __( 'INR - Indian Rupee (₹)', 'crypto' ),
			'CNY' => __( 'CNY - Chinese Yuan (¥)', 'crypto' ),
			'RUB' => __( 'RUB - Russian Ruble (₽)', 'crypto' ),
			'BTC' => __( 'BTC - Bitcoin (₿)', 'crypto' ),
			'ETH' => __( 'ETH - Ethereum (Ξ)', 'crypto' ),
		);

		$cache_intervals = array(
			1   => __( '1 Minute (Developer/Testing)', 'crypto' ),
			5   => __( '5 Minutes', 'crypto' ),
			10  => __( '10 Minutes (Recommended)', 'crypto' ),
			30  => __( '30 Minutes', 'crypto' ),
			60  => __( '1 Hour', 'crypto' ),
			180 => __( '3 Hours', 'crypto' ),
		);

		// Output settings errors
		settings_errors();
		?>
		<div class="wrap crypto-settings-wrap">
			<div class="crypto-settings-header">
				<h1><?php esc_html_e( 'Crypto Price Settings', 'crypto' ); ?></h1>
				<p class="description">
					<?php esc_html_e( 'Configure your CoinMarketCap API integration and customize how crypto prices are cached and displayed on your site.', 'crypto' ); ?>
				</p>
			</div>

			<div class="crypto-dashboard-grid">
				<!-- Settings Form Card -->
				<div class="crypto-card settings-card">
					<h2><span class="dashicons dashicons-admin-generic"></span> <?php esc_html_e( 'Configuration', 'crypto' ); ?></h2>
					<form method="post" action="options.php">
						<?php settings_fields( 'crypto_settings_group' ); ?>

						<table class="form-table" role="presentation">
							<tbody>
								<tr>
									<th scope="row"><label for="crypto_api_key"><?php esc_html_e( 'CoinMarketCap API Key', 'crypto' ); ?></label></th>
									<td>
										<input type="text" id="crypto_api_key" name="crypto_api_key" value="<?php echo esc_attr( $api_key ); ?>" class="regular-text code" placeholder="xxxx-xxxx-xxxx-xxxx" />
										<p class="description">
											<?php esc_html_e( 'Enter your CoinMarketCap Professional API key. You can get a free key from ', 'crypto' ); ?>
											<a href="https://pro.coinmarketcap.com/" target="_blank" rel="noopener">pro.coinmarketcap.com</a>.
										</p>
										<?php if ( ! empty( $api_key ) ) : ?>
											<div class="api-status-badge <?php echo 'valid' === $api_status ? 'status-valid' : 'status-invalid'; ?>">
												<strong><?php esc_html_e( 'Connection Status: ', 'crypto' ); ?></strong>
												<?php if ( 'valid' === $api_status ) : ?>
													<span class="status-text text-success"><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Active & Verified', 'crypto' ); ?></span>
												<?php else : ?>
													<span class="status-text text-danger"><span class="dashicons dashicons-warning"></span> <?php echo esc_html( $api_status ? $api_status : __( 'Unverified', 'crypto' ) ); ?></span>
												<?php endif; ?>
											</div>
										<?php endif; ?>
									</td>
								</tr>

								<tr>
									<th scope="row"><label for="crypto_default_currency"><?php esc_html_e( 'Default Currency', 'crypto' ); ?></label></th>
									<td>
										<select id="crypto_default_currency" name="crypto_default_currency">
											<?php foreach ( $currencies as $code => $label ) : ?>
												<option value="<?php echo esc_attr( $code ); ?>" <?php selected( $default_currency, $code ); ?>>
													<?php echo esc_html( $label ); ?>
												</option>
											<?php endforeach; ?>
										</select>
										<p class="description"><?php esc_html_e( 'Prices will be converted to this currency by default if not specified in the shortcode.', 'crypto' ); ?></p>
									</td>
								</tr>

								<tr>
									<th scope="row"><label for="crypto_cache_duration"><?php esc_html_e( 'Cache Duration', 'crypto' ); ?></label></th>
									<td>
										<select id="crypto_cache_duration" name="crypto_cache_duration">
											<?php foreach ( $cache_intervals as $minutes => $label ) : ?>
												<option value="<?php echo esc_attr( $minutes ); ?>" <?php selected( $cache_duration, $minutes ); ?>>
													<?php echo esc_html( $label ); ?>
												</option>
											<?php endforeach; ?>
										</select>
										<p class="description"><?php esc_html_e( 'How long to cache price data locally. Higher cache durations drastically reduce API credit usage.', 'crypto' ); ?></p>
									</td>
								</tr>
							</tbody>
						</table>

						<?php submit_button( __( 'Save Configuration', 'crypto' ), 'primary', 'submit', true ); ?>
					</form>

					<?php if ( ! empty( $api_key ) ) : ?>
						<hr class="crypto-hr" />
						<div class="cache-action-box">
							<h3><?php esc_html_e( 'Cache Management', 'crypto' ); ?></h3>
							<p class="description"><?php esc_html_e( 'If you need to instantly refresh the prices on your website, you can clear the locally cached price transients.', 'crypto' ); ?></p>
							<form method="post" action="">
								<?php wp_nonce_field( 'crypto_clear_cache_action', 'crypto_clear_cache_nonce' ); ?>
								<input type="submit" name="crypto_clear_cache" id="crypto_clear_cache" class="button button-secondary" value="<?php esc_attr_e( 'Clear Cached Prices', 'crypto' ); ?>" />
							</form>
						</div>
					<?php endif; ?>
				</div>

				<!-- Documentation Card -->
				<div class="crypto-card doc-card">
					<h2><span class="dashicons dashicons-editor-code"></span> <?php esc_html_e( 'Shortcode Guide', 'crypto' ); ?></h2>
					<p><?php esc_html_e( 'Use the shortcode anywhere in your pages, posts, or widgets to display beautiful, responsive price badges and cards.', 'crypto' ); ?></p>

					<div class="doc-section">
						<h4><?php esc_html_e( 'Standard Shortcode Usage', 'crypto' ); ?></h4>
						<div class="shortcode-example">
							<code>[crypto_price symbol="BTC"]</code>
							<button class="button button-small copy-btn" onclick="navigator.clipboard.writeText('[crypto_price symbol=\'BTC\']'); alert('Copied!');"><?php esc_html_e( 'Copy', 'crypto' ); ?></button>
						</div>
						<p class="description"><?php esc_html_e( 'Displays a beautiful glassmorphic price card for Bitcoin in your default currency.', 'crypto' ); ?></p>
					</div>

					<div class="doc-section">
						<h4><?php esc_html_e( 'Customizing Currency', 'crypto' ); ?></h4>
						<div class="shortcode-example">
							<code>[crypto_price symbol="ETH" convert="EUR"]</code>
							<button class="button button-small copy-btn" onclick="navigator.clipboard.writeText('[crypto_price symbol=\'ETH\' convert=\'EUR\']'); alert('Copied!');"><?php esc_html_e( 'Copy', 'crypto' ); ?></button>
						</div>
						<p class="description"><?php esc_html_e( 'Displays Ethereum price converted to Euros.', 'crypto' ); ?></p>
					</div>

					<div class="doc-section">
						<h4><?php esc_html_e( 'Layout & Theme Customization', 'crypto' ); ?></h4>
						<div class="shortcode-example">
							<code>[crypto_price symbol="SOL" layout="badge" theme="dark"]</code>
							<button class="button button-small copy-btn" onclick="navigator.clipboard.writeText('[crypto_price symbol=\'SOL\' layout=\'badge\' theme=\'dark\']'); alert('Copied!');"><?php esc_html_e( 'Copy', 'crypto' ); ?></button>
						</div>
						<p class="description"><?php esc_html_e( 'Layout options: "card", "badge". Theme options: "glass", "dark", "light".', 'crypto' ); ?></p>
					</div>

					<div class="doc-section">
						<h4><?php esc_html_e( 'Attribute Reference', 'crypto' ); ?></h4>
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Attribute', 'crypto' ); ?></th>
									<th><?php esc_html_e( 'Description', 'crypto' ); ?></th>
									<th><?php esc_html_e( 'Default', 'crypto' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><strong>symbol</strong></td>
									<td><?php esc_html_e( 'Token symbol (BTC, ETH, SOL, etc.)', 'crypto' ); ?></td>
									<td><code>BTC</code></td>
								</tr>
								<tr>
									<td><strong>convert</strong></td>
									<td><?php esc_html_e( 'Target fiat currency (USD, EUR, GBP, etc.)', 'crypto' ); ?></td>
									<td><em><?php esc_html_e( 'Default setting', 'crypto' ); ?></em></td>
								</tr>
								<tr>
									<td><strong>layout</strong></td>
									<td><code>card</code>, <code>badge</code></td>
									<td><code>card</code></td>
								</tr>
								<tr>
									<td><strong>theme</strong></td>
									<td><code>glass</code>, <code>dark</code>, <code>light</code></td>
									<td><code>glass</code></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
		<?php
	}
}
