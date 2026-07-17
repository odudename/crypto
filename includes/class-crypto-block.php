<?php
/**
 * Gutenberg Block Integration.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_Block {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'register_block' ) );
	}

	/**
	 * Register Gutenberg block.
	 */
	public function register_block() {
		// Register public stylesheet if not already registered
		if ( ! wp_style_is( 'crypto-public-style', 'registered' ) ) {
			wp_register_style(
				'crypto-public-style',
				plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/crypto-public.css',
				array(),
				CRYPTO_VERSION
			);
		}

		// Register block script
		wp_register_script(
			'crypto-block-editor',
			plugin_dir_url( dirname( __FILE__ ) ) . 'assets/js/crypto-block.js',
			array( 'wp-blocks', 'wp-element', 'wp-block-editor', 'wp-components', 'wp-server-side-render' ),
			CRYPTO_VERSION
		);

		register_block_type(
			'crypto/price',
			array(
				'editor_script'   => 'crypto-block-editor',
				'editor_style'    => 'crypto-public-style',
				'style'           => 'crypto-public-style',
				'render_callback' => array( $this, 'render_block' ),
				'attributes'      => array(
					'symbol'  => array(
						'type'    => 'string',
						'default' => 'BTC',
					),
					'convert' => array(
						'type'    => 'string',
						'default' => get_option( 'crypto_default_currency', 'USD' ),
					),
					'layout'  => array(
						'type'    => 'string',
						'default' => 'card',
					),
					'theme'   => array(
						'type'    => 'string',
						'default' => 'glass',
					),
				),
			)
		);
	}

	/**
	 * Render Gutenberg block on frontend and inside block editor.
	 *
	 * @param array $attributes Block attributes.
	 * @return string HTML output.
	 */
	public function render_block( $attributes ) {
		if ( class_exists( 'Crypto_Shortcode' ) ) {
			$shortcode = new Crypto_Shortcode();
			return $shortcode->render_shortcode( $attributes );
		}
		return '';
	}
}
