<div class="wrap about-wrap">
    <h1><?php echo esc_html(__('Welcome to', 'crypto')) . ' ' . esc_html(__('Crypto', 'crypto')) . ' ' . esc_html(CRYPTO_VERSION); ?>
    </h1>
    <div class="crypto-badge-logo"></div>
    <nav class="nav-tab-wrapper">
        <?php
        // Get the active tab from the $_GET param
        $default_tab = 'intro';
        $get_tab = isset($_GET['tab']) ? sanitize_text_field(wp_unslash($_GET['tab'])) : $default_tab;

        $tabs = array();
        $tabs = apply_filters('crypto_dashboard_tab', $tabs);

        foreach ($tabs as $key => $val) {

            $active_tab = ($key === $get_tab) ? 'nav-tab-active' : '';
            
            echo '<a href="' . esc_url(add_query_arg(array('page' => 'crypto', 'tab' => $key))) . '" class="nav-tab ' . esc_attr($active_tab) . '">' . esc_html($val) . '</a>';
        }
        ?>
    </nav>
    <div class="tab-content">
        <?php do_action('crypto_dashboard_tab_content'); ?>
    </div>
</div>