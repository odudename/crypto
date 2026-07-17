=== Crypto ===
Contributors: odude
Donate link: https://odude.com
Tags: crypto, bitcoin, cryptocurrency, price, coinmarketcap
Requires at least: 5.0
Requires PHP: 5.6
Tested up to: 7.0
Stable tag: 3.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Live crypto prices using CoinMarketCap API. Displayed via a customizable shortcode, native Gutenberg Block, or Elementor Widget with premium glassmorphic and dark layouts.

== Description ==

Display the latest cryptocurrency prices on your WordPress site dynamically and beautifully using the CoinMarketCap API. High-performance design features local transient caching to reduce API requests and credit usage. Fully integrated with both the Gutenberg Block Editor and Elementor Page Builder for easy drag-and-drop visual editing.

=== Features ===
* **CoinMarketCap API Integration:** Real-time cryptocurrency price data direct from the leading data provider.
* **Gutenberg Block Support:** Native WordPress Block Editor block featuring full GUI side panel configurations and live server-side rendering previews.
* **Elementor Widget Support:** Drag-and-drop Elementor widget with options panel and live editor preview.
* **Premium Themes:** Includes three layout themes: Glassmorphism (Glass), Sleek Dark (Dark), and Clean Light (Light).
* **Multiple Layouts:** Choose between full detailed price Cards or compact inline Badges.
* **Local Transient Caching:** Extremely efficient local caching that significantly reduces API rate limits and credits.
* **Fallback Mode:** Keeps displaying the last known prices if the connection/API is temporarily unavailable.
* **Shortcode Support:** Easy to use `[crypto_price]` shortcode with customizable parameters.

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload the `crypto` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to **Settings > Crypto Settings** to input your CoinMarketCap API key and set defaults.
4. Use the "Crypto Price" Gutenberg block, the Elementor widget, or add the `[crypto_price]` shortcode.

== Page Builders & Editors ==

This plugin provides native integration with popular page builders and editors:

=== WordPress Block Editor (Gutenberg) ===
1. Open the Block Editor on any Post or Page.
2. Click the `+` icon and search for "Crypto Price".
3. Add the block and use the settings sidebar to configure:
   * **Cryptocurrency Symbol:** Type any supported coin symbol (e.g. BTC, ETH).
   * **Currency / Convert To:** Select your target currency.
   * **Layout:** Switch between Card and Badge.
   * **Theme:** Choose Glassmorphism, Dark, or Light.
   * *A live server-side preview will automatically render in the editor.*

=== Elementor Page Builder ===
1. Edit any page with Elementor.
2. In the widget panel, search for "Crypto Price".
3. Drag and drop the widget into your section.
4. Customize the widget using the Content Panel options.

== Shortcode Guide ==

Use the shortcode anywhere in your pages, posts, or widgets.

=== Standard Usage ===
`[crypto_price symbol="BTC"]`
Displays a premium glassmorphic price card for Bitcoin in your default currency.

=== Customizing Currency ===
`[crypto_price symbol="ETH" convert="EUR"]`
Displays the price of Ethereum converted to Euros.

=== Layout & Theme Customization ===
`[crypto_price symbol="SOL" layout="badge" theme="dark"]`
Displays Solana price in a compact badge format with the dark theme.

=== Attribute Reference ===
* `symbol` - Token symbol (e.g. BTC, ETH, SOL). Default is `BTC`.
* `convert` - Target fiat or crypto currency for conversion (e.g. USD, EUR, GBP, BTC). Default is your default currency settings.
* `layout` - Display layout options: `card` (detailed card format) or `badge` (compact inline badge). Default is `card`.
* `theme` - Layout theme options: `glass`, `dark`, or `light`. Default is `glass`.

== Frequently Asked Questions ==

= Where do I get a CoinMarketCap API key? =
You can sign up for a free developer account and obtain your API key at [pro.coinmarketcap.com](https://pro.coinmarketcap.com/).

= What happens if the CoinMarketCap API is down or rates are exceeded? =
The plugin will enter Offline Fallback mode, safely displaying the last retrieved cache value and showing a subtle indicator for administrators without breaking your page layout.

= How do I clear the cached prices? =
You can manually clear all cached transients at any time from the plugin's settings page under the "Cache Management" section.

== Screenshots ==

1. Premium Glassmorphic and Dark Price Cards
2. Compact Price Badges
3. Plugin Settings page under Options/Settings

== Changelog ==

= 3.0.0 =
* Complete redesign and code refactoring.
* Added live price display for any CoinMarketCap token.
* Introduced premium glassmorphic, dark, and light layouts/themes.
* Built-in local transient caching and robust offline fallback system.
* Fixed settings page save and connection verification issue.

= 2.22 =
* Minor updates and bug fixes.