<?php
class Crypto_Access
{
    private $domain_name;
    private $default_access;
    private $crypto_network;
    private $mint_page;

    public function __construct()
    {
        $this->default_access = crypto_get_option('select_access_control', 'crypto_access_settings_start', 'web3domain');
        $this->domain_name = crypto_get_option('domain_name', 'crypto_access_settings', 'yak');
        $this->mint_page = crypto_get_option('mint_page', 'crypto_access_settings', 'https://app.web3yak.com/');
        add_shortcode('crypto-access-domain', array($this, 'crypto_access_box'));
        add_filter('crypto_settings_tabs', array($this, 'add_tabs'));
        add_filter('crypto_settings_sections', array($this, 'add_section_extension'));
        add_filter('crypto_settings_sections', array($this, 'add_section'));
        add_filter('crypto_settings_fields', array($this, 'add_fields'));
        $this->crypto_network = crypto_get_option('crypto_network', 'crypto_marketplace_settings', '137');


        add_filter('crypto_settings_fields', array($this, 'add_extension'));
        //add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
    }

    public function enqueue_scripts()
    {
        wp_enqueue_script('crypto_web3domain', plugin_dir_url(__DIR__) . 'public/js/web3domain.js', array('jquery'), '', false);
    }


    //add_filter flexi_settings_tabs
    public function add_tabs($new)
    {

        $tabs = array(
            'access'   => __('Access Control', 'crypto'),

        );
        $new  = array_merge($new, $tabs);

        return $new;
    }



    public function add_section($new)
    {

        $sections = array(
            array(
                'id' => 'crypto_access_settings',
                'title' => __('ODude Name Access', 'crypto'),
                'description' => __('Limit access to specific areas of the website based on the availability of a ODude Name (Web3Domain)', 'crypto') . "<br>Get Top Level Name (TLN) from <a href='" . esc_url('https://web3domain.org/') . "' target='_blank'>Web3Domain.org</a><br><br>" . "<b>Shortcode for limiting access to content</b><br>The shortcode should be written as <code>[crypto-block] for private information or content between the shortcode. [/crypto-block]</code><b><br><br>To limit access to the entire page.</b><br><code>Edit the desired page, and use the option from the setting panel to limit access.</code>",
                'tab' => 'access',
            ),
        );
        $new = array_merge($new, $sections);

        return $new;
    }

    public function add_section_extension($new)
    {

        $sections = array(
            array(
                'id' => 'crypto_access_settings_start',
                'title' => __('Access Control Configuration', 'crypto'),
                'description' => __('You can only use one access control setting at a time. Choose your preferred option.', 'crypto'),
                'tab' => 'access',
            ),
        );
        $new = array_merge($new, $sections);

        return $new;
    }

    //Add section fields
    public function add_fields($new)
    {
        $fields = array(
            'crypto_access_settings' => array(

                array(
                    'name' => 'domain_name',
                    'label' => __('TLN of ODude Name', 'crypto'),
                    'description' => __('Enter the Top Level Domain Name (TLN). Access to selected page will only be granted to users who have a sub-name of this TLN in their wallet.', 'crypto'),
                    'type' => 'text',
                    'sanitize_callback' => 'sanitize_key',
                ),

                array(
                    'name' => 'restrict_page',
                    'label' => __('Limit access to the page', 'crypto'),
                    'description' => __('Select a page with the [crypto-connect label="Connect Wallet" class="fl-button fl-is-info fl-is-light"] [crypto-access-domain] shortcode to determine a member\'s status based on the presence of a specified ODude Name in their wallet.', 'crypto'),
                    'type' => 'pages',
                    'sanitize_callback' => 'sanitize_key',
                ),

                array(
                    'name' => 'mint_page',
                    'label' => __('URL to Mint', 'crypto'),
                    'description' => __('Enter URL to Mint sub-name of TLN. Get free application at <code>https://web3yak.com/</code>', 'crypto'),
                    'type' => 'url',
                    'sanitize_callback' => 'sanitize_url',
                ),

            ),
        );
        $new = array_merge($new, $fields);

        return $new;
    }

    public function add_extension($new)
    {

        $fields = array('crypto_access_settings_start' => array(
            array(
                'name' => 'select_access_control',
                'label' => __('Choose Access Control', 'crypto'),
                'description' => '',
                'type' => 'radio',
                'options' => array(
                    'web3domain' => __('ODude Name Access', 'crypto'),
                    'nft' => __('Cryptocurrency & Non-Fungible Token (NFT) Access', 'crypto'),
                ),
                'sanitize_callback' => 'sanitize_key',
            ),
        ));
        $new = array_merge_recursive($new, $fields);

        return $new;
    }

    public function crypto_access_box()
    {
        $put = "";
        ob_start();
        $nonce = wp_create_nonce('crypto_ajax');
        if (Crypto_User::if_custom_user_logged_in()) {
            $default_access = crypto_get_option('select_access_control', 'crypto_access_settings_start', 'web3domain');
            $current_user = Crypto_User::get_current_custom_user_login();
            if ($this->default_access == 'web3domain') {
                $saved_array = Crypto_User::get_custom_user_value($current_user,  'domain_names');
                // crypto_log($saved_array);
                $check = new crypto_connect_ajax_process();
                $check->checknft($current_user,  $saved_array);
?>

                <script>
                    crypto_is_metamask_Connected().then(acc => {
                        if (acc.addr == '') {
                            console.log("Metamask is not connected. Please connect to it first.");
                        } else {
                            console.log("Connected to:" + acc.addr + "\n Network:" + acc.network);

                            if ((acc.network != '<?php echo esc_js($this->crypto_network); ?>')) {
                                var msg =
                                    "Please change your network to Polygon (MATIC). Your currently connected network is " +
                                    acc.network;
                                jQuery("[id=crypto_msg_ul]").empty();
                                jQuery("[id=crypto_msg_ul]").append(msg).fadeIn("normal");
                            } else {
                                //  crypto_init();
                                web3 = new Web3(window.ethereum);

                                const connectWallet = async () => {
                                    const accounts = await ethereum.request({
                                        method: "eth_requestAccounts"
                                    });
                                    var persons = [];
                                    account = accounts[0];
                                    //console.log(`Connectedxxxxxxx account...........: ${account}`);
                                    // getBalance(account);
                                    await crypto_sleep(1000);
                                    var domain_count = await balanceOf(account);
                                    console.log(domain_count);
                                    crypto_process_domain_count(domain_count, account);

                                    console.log(contract);
                                    persons.length = 0;
                                    for (let i = 0; i < domain_count; i++) {
                                        try {
                                            const nft = await contract.methods.tokenOfOwnerByIndex(account, i).call();
                                            //console.log(nft);
                                            var domain_name = await titleOf(nft);
                                            console.log(nft + ' = ' + domain_name);
                                            jQuery("[id=crypto_msg_ul]").append("<li>" + domain_name + "</li>").fadeIn(
                                                "normal");
                                            persons.push(domain_name);
                                            // console.log(i + " *** " + domain_count);
                                            if (i + 1 == domain_count) {
                                                console.log(persons);
                                                // console.log("sssss");
                                                process_login_savenft(account, persons, domain_count);
                                            }
                                        } catch (error) {
                                            console.log(error.message);
                                        }
                                    }
                                };

                                connectWallet();
                                connectContract(contractAbi, contractAddress);

                                function process_login_savenft(curr_user, persons, count) {


                                    create_link_crypto_connect_login('<?php echo sanitize_key($nonce); ?>', '', 'savenft',
                                        curr_user,
                                        persons, count);
                                    //  console.log(persons);
                                    setTimeout(function() {
                                        //alert("hi");
                                        jQuery('#crypto_connect_ajax_process').trigger('click');
                                    }, 1000);

                                }

                                function crypto_process_domain_count(count, account) {
                                    if (count == 0) {
                                        console.log("zero domain");
                                        jQuery("[id=crypto_msg_ul]").append(
                                                "<li>Your wallet do not have <?php echo "." . esc_html($this->domain_name); ?> Domain. <strong>Account restricted.</strong> </li>"
                                            )
                                            .fadeIn("normal");
                                        create_link_crypto_connect_login('<?php echo sanitize_key($nonce); ?>', '', 'savenft',
                                            account, '', count);

                                        setTimeout(function() {
                                            jQuery('#crypto_connect_ajax_process').trigger('click');
                                        }, 1000);
                                    }

                                }


                            }
                        }
                    });
                </script>
                <?php
                $check_access = new Crypto_Block();
                $current_user = Crypto_User::get_current_custom_user_login();
                if ($check_access->crypto_can_user_view()) {

                ?>

                    <div class="fl-tags fl-has-addons">
                        <span class="fl-tag">Account Status (<?php echo esc_html($current_user); ?>)</span>
                        <span class="fl-tag fl-is-primary"><?php echo esc_html("." . $this->domain_name); ?> sub-name holder</span>
                    </div>
                <?php
                } else {
                ?>

                    <div class="fl-tags fl-has-addons">
                        <span class="fl-tag">Account Status (<?php echo esc_html($current_user);  ?>)</span>
                        <span class="fl-tag fl-is-danger"><?php echo esc_html("." . $this->domain_name); ?> sub-domain required</span>
                    </div>
                <?php
                }
                ?>


                <div class="fl-message fl-is-dark">
                    <div class="fl-message-body">

                        Some content or pages on the site are exclusively available to members who possess a sub-name of the
                        <b><?php echo esc_html("." . $this->domain_name); ?></b> primary ODude<br>
                        <?php if ($this->mint_page != "") {
                            echo '<a href="' . esc_url($this->mint_page) . '" target="_blank">' . esc_html($this->mint_page) . '</a>';
                        }
                        ?>
                    </div>
                </div>

                <div class="fl-message" id="crypto_msg">
                    <div class="fl-message-header">
                        <p>Available domains/name into polygon chain</p>
                    </div>
                    <div class="fl-message-body" id="crypto_msg_body">
                        <ul id="crypto_msg_ul"></ul>
                    </div>
                </div>

                <div>
                    <a href="#" id="check_domain" onclick="location.reload();" class="fl-button fl-is-link fl-is-light">Verify the
                        presence of the
                        <?php echo esc_html("." . $this->domain_name); ?> ODude Name in your wallet</a>
                </div>
            <?php
            } else {
                echo '<div class="fl-message-body">Web3Domain access is disabled. Enable it from settings</div>';
            }
        } else {
            ?>

            <div class="fl-message">
                <div class="fl-message-header">
                    <p>Please login</p>

                </div>
                <div class="fl-message-body">
                    After login you can check your wallet for eligibility.
                </div>
            </div>
<?php
        }
        $put = ob_get_clean();

        return $put;
    }
}
$price_page = new Crypto_Access();
