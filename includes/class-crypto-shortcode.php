<?php
/**
 * Frontend shortcode renderer class.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_Shortcode {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Register the stylesheet so we can enqueue it on-demand
		add_action( 'wp_enqueue_scripts', array( $this, 'register_assets' ) );

		// Register shortcodes
		add_shortcode( 'crypto_price', array( $this, 'render_shortcode' ) );
		add_shortcode( 'crypto', array( $this, 'render_shortcode' ) ); // alias
	}

	/**
	 * Register frontend stylesheet.
	 */
	public function register_assets() {
		wp_register_style(
			'crypto-public-style',
			plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/crypto-public.css',
			array(),
			CRYPTO_VERSION
		);
	}

	/**
	 * Render the shortcode.
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string HTML output.
	 */
	public function render_shortcode( $atts ) {
		// Enqueue the stylesheet on-demand
		wp_enqueue_style( 'crypto-public-style' );

		$default_currency = get_option( 'crypto_default_currency', 'USD' );

		$attributes = shortcode_atts(
			array(
				'symbol'  => 'BTC',
				'convert' => $default_currency,
				'layout'  => 'card', // card, badge
				'theme'   => 'glass', // glass, dark, light
			),
			$atts,
			'crypto_price'
		);

		$symbol  = strtoupper( sanitize_text_field( $attributes['symbol'] ) );
		$convert = strtoupper( sanitize_text_field( $attributes['convert'] ) );
		$layout  = sanitize_html_class( $attributes['layout'] );
		$theme   = sanitize_html_class( $attributes['theme'] );

		// Retrieve data
		$data = Crypto_API::get_price( $symbol, $convert );

		// Handle error
		if ( is_wp_error( $data ) ) {
			if ( current_user_can( 'manage_options' ) ) {
				return sprintf(
					'<div class="crypto-error-notice">%s: %s</div>',
					esc_html__( 'Crypto Price Error', 'crypto' ),
					esc_html( $data->get_error_message() )
				);
			}
			// Fallback string for regular visitors
			return sprintf(
				'<span class="crypto-price-unavailable" title="%s">%s</span>',
				esc_attr( $data->get_error_message() ),
				// translators: %s: cryptocurrency symbol (e.g. BTC).
				esc_html( sprintf( __( '[%s Price Unavailable]', 'crypto' ), $symbol ) )
			);
		}

		// Calculate relative time
		$time_diff = human_time_diff( $data['last_updated'], time() );

		// Format price and metrics
		$formatted_price      = self::format_price( $data['price'], $convert );
		$formatted_market_cap = self::format_large_number( $data['market_cap'], $convert );
		$currency_symbol      = self::get_currency_symbol( $convert );

		// 24h change details
		$change_24h      = $data['percent_change_24h'];
		$change_class    = $change_24h >= 0 ? 'crypto-up' : 'crypto-down';
		$change_arrow    = $change_24h >= 0 ? '▲' : '▼';
		$formatted_change = number_format( abs( $change_24h ), 2 ) . '%';

		// Generate HTML based on layout
		ob_start();

		if ( 'badge' === $layout ) {
			?>
			<span class="crypto-price-badge crypto-theme-<?php echo esc_attr( $theme ); ?>">
				<img class="crypto-badge-logo" src="https://s2.coinmarketcap.com/static/img/coins/64x64/<?php echo esc_attr( $data['id'] ); ?>.png" alt="<?php echo esc_attr( $data['name'] ); ?>">
				<span class="crypto-badge-symbol"><?php echo esc_html( $data['symbol'] ); ?></span>
				<span class="crypto-badge-price"><?php echo esc_html( $currency_symbol . $formatted_price ); ?></span>
				<span class="crypto-badge-change <?php echo esc_attr( $change_class ); ?>">
					<?php echo esc_html( $change_arrow . ' ' . $formatted_change ); ?>
				</span>
				<?php if ( ! empty( $data['is_fallback'] ) ) : ?>
					<span class="crypto-badge-fallback-dot" title="<?php esc_attr_e( 'Displaying last known price. Connection is currently offline.', 'crypto' ); ?>">!</span>
				<?php endif; ?>
			</span>
			<?php
		} else {
			// Card layout
			?>
			<div class="crypto-price-card crypto-theme-<?php echo esc_attr( $theme ); ?>">
				<div class="crypto-card-header">
					<div class="crypto-coin-info">
						<img class="crypto-coin-logo" src="https://s2.coinmarketcap.com/static/img/coins/64x64/<?php echo esc_attr( $data['id'] ); ?>.png" alt="<?php echo esc_attr( $data['name'] ); ?>">
						<div class="crypto-coin-meta">
							<div class="crypto-coin-name"><?php echo esc_html( $data['name'] ); ?></div>
							<div class="crypto-coin-symbol"><?php echo esc_html( $data['symbol'] ); ?></div>
						</div>
					</div>
					<div class="crypto-change-badge <?php echo esc_attr( $change_class ); ?>">
						<span class="crypto-arrow"><?php echo esc_html( $change_arrow ); ?></span> <?php echo esc_html( $formatted_change ); ?>
					</div>
				</div>

				<div class="crypto-card-body">
					<div class="crypto-price-display">
						<span class="crypto-currency-symbol"><?php echo esc_html( $currency_symbol ); ?></span><?php echo esc_html( $formatted_price ); ?>
					</div>
					<?php if ( ! empty( $data['is_fallback'] ) ) : ?>
						<div class="crypto-fallback-warning" title="<?php echo esc_attr( isset( $data['fallback_error'] ) ? $data['fallback_error'] : '' ); ?>">
							<span class="dashicons dashicons-warning"></span> <?php esc_html_e( 'Offline Fallback', 'crypto' ); ?>
						</div>
					<?php endif; ?>
				</div>

				<div class="crypto-card-footer">
					<div class="crypto-footer-metric">
						<span class="crypto-label"><?php esc_html_e( 'Market Cap:', 'crypto' ); ?></span>
						<span class="crypto-value"><?php echo esc_html( $currency_symbol . $formatted_market_cap ); ?></span>
					</div>
					<div class="crypto-footer-updated">
						<?php
						// translators: %s: human-readable time difference (e.g. 5 minutes).
						printf( esc_html__( 'Updated %s ago', 'crypto' ), esc_html( $time_diff ) );
						?>
					</div>
				</div>
			</div>
			<?php
		}

		return ob_get_clean();
	}

	/**
	 * Map currency ISO to symbol.
	 */
	public static function get_currency_symbol( $currency ) {
		$symbols = array(
			'USD' => '$',
			'EUR' => '€',
			'GBP' => '£',
			'JPY' => '¥',
			'CAD' => '$',
			'AUD' => '$',
			'INR' => '₹',
			'CNY' => '¥',
			'RUB' => '₽',
			'BTC' => '₿',
			'ETH' => 'Ξ',
		);

		return isset( $symbols[ $currency ] ) ? $symbols[ $currency ] : $currency . ' ';
	}

	/**
	 * Format price based on size to ensure micro-caps show enough precision.
	 */
	public static function format_price( $price, $currency ) {
		$price = floatval( $price );

		if ( $price >= 1000 ) {
			return number_format( $price, 2 );
		} elseif ( $price >= 1 ) {
			return number_format( $price, 2 );
		} elseif ( $price >= 0.01 ) {
			return number_format( $price, 4 );
		} elseif ( $price >= 0.0001 ) {
			return number_format( $price, 6 );
		} else {
			return number_format( $price, 8 );
		}
	}

	/**
	 * Format large numbers for Market Cap / Volume.
	 */
	public static function format_large_number( $number, $currency ) {
		$number = floatval( $number );

		if ( $number >= 1000000000000 ) {
			return number_format( $number / 1000000000000, 2 ) . ' T';
		} elseif ( $number >= 1000000000 ) {
			return number_format( $number / 1000000000, 2 ) . ' B';
		} elseif ( $number >= 1000000 ) {
			return number_format( $number / 1000000, 2 ) . ' M';
		} else {
			return number_format( $number, 0 );
		}
	}
}
