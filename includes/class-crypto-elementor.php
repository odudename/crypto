<?php
/**
 * Elementor Integration Loader.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_Elementor {

	/**
	 * Constructor.
	 */
	public function __construct() {
		// Hook into Elementor widget registration
		add_action( 'elementor/widgets/register', array( $this, 'register_widgets' ) );
		add_action( 'elementor/frontend/after_enqueue_styles', array( $this, 'enqueue_widget_styles' ) );
	}

	/**
	 * Register the widget.
	 *
	 * @param \Elementor\Widgets_Manager $widgets_manager Elementor widgets manager.
	 */
	public function register_widgets( $widgets_manager ) {
		require_once CRYPTO_PATH . 'includes/class-crypto-elementor-widget.php';
		$widgets_manager->register( new Crypto_Elementor_Widget() );
	}

	/**
	 * Enqueue styles in Elementor editor and frontend.
	 */
	public function enqueue_widget_styles() {
		// Register the stylesheet if not registered yet
		if ( ! wp_style_is( 'crypto-public-style', 'registered' ) ) {
			wp_register_style(
				'crypto-public-style',
				plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/crypto-public.css',
				array(),
				CRYPTO_VERSION
			);
		}
		wp_enqueue_style( 'crypto-public-style' );
	}
}
