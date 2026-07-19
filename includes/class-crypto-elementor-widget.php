<?php
/**
 * Elementor Widget for Crypto Price.
 *
 * @package Crypto
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Crypto_Elementor_Widget extends \Elementor\Widget_Base {

	/**
	 * Retrieve the widget name.
	 *
	 * @return string Widget name.
	 */
	public function get_name() {
		return 'crypto_price';
	}

	/**
	 * Retrieve the widget title.
	 *
	 * @return string Widget title.
	 */
	public function get_title() {
		return esc_html__( 'Crypto Price', 'crypto' );
	}

	/**
	 * Retrieve the widget icon.
	 *
	 * @return string Widget icon.
	 */
	public function get_icon() {
		return 'eicon-price-list';
	}

	/**
	 * Retrieve the list of categories the widget belongs to.
	 *
	 * @return array Widget categories.
	 */
	public function get_categories() {
		return array( 'general' );
	}

	/**
	 * Retrieve the list of style dependencies.
	 *
	 * @return array Widget styles.
	 */
	public function get_style_depends() {
		return array( 'crypto-public-style' );
	}

	/**
	 * Register the widget controls.
	 */
	protected function register_controls() {
		$this->start_controls_section(
			'section_content',
			array(
				'label' => esc_html__( 'Crypto Settings', 'crypto' ),
				'tab'   => \Elementor\Controls_Manager::TAB_CONTENT,
			)
		);

		$this->add_control(
			'symbol',
			array(
				'label'       => esc_html__( 'Cryptocurrency Symbol', 'crypto' ),
				'type'        => \Elementor\Controls_Manager::TEXT,
				'default'     => 'BTC',
				'placeholder' => esc_html__( 'e.g. BTC, ETH, SOL', 'crypto' ),
			)
		);

		$this->add_control(
			'convert',
			array(
				'label'   => esc_html__( 'Currency / Convert To', 'crypto' ),
				'type'    => \Elementor\Controls_Manager::SELECT,
				'default' => get_option( 'crypto_default_currency', 'USD' ),
				'options' => array(
					'USD' => 'USD ($)',
					'EUR' => 'EUR (€)',
					'GBP' => 'GBP (£)',
					'JPY' => 'JPY (¥)',
					'CAD' => 'CAD ($)',
					'AUD' => 'AUD ($)',
					'INR' => 'INR (₹)',
					'CNY' => 'CNY (¥)',
					'RUB' => 'RUB (₽)',
					'BTC' => 'BTC (₿)',
					'ETH' => 'ETH (Ξ)',
				),
			)
		);

		$this->add_control(
			'layout',
			array(
				'label'   => esc_html__( 'Layout', 'crypto' ),
				'type'    => \Elementor\Controls_Manager::SELECT,
				'default' => 'card',
				'options' => array(
					'card'  => esc_html__( 'Card', 'crypto' ),
					'badge' => esc_html__( 'Badge', 'crypto' ),
				),
			)
		);

		$this->add_control(
			'theme',
			array(
				'label'   => esc_html__( 'Theme', 'crypto' ),
				'type'    => \Elementor\Controls_Manager::SELECT,
				'default' => 'glass',
				'options' => array(
					'glass' => esc_html__( 'Glassmorphism', 'crypto' ),
					'dark'  => esc_html__( 'Dark', 'crypto' ),
					'light' => esc_html__( 'Light', 'crypto' ),
				),
			)
		);

		$this->end_controls_section();
	}

	/**
	 * Render the widget output on the frontend.
	 */
	protected function render() {
		$settings = $this->get_settings_for_display();

		if ( class_exists( 'Crypto_Shortcode' ) ) {
			$shortcode = new Crypto_Shortcode();
			echo wp_kses_post(
				$shortcode->render_shortcode(
					array(
						'symbol'  => $settings['symbol'],
						'convert' => $settings['convert'],
						'layout'  => $settings['layout'],
						'theme'   => $settings['theme'],
					)
				)
			);
		}
	}
}
