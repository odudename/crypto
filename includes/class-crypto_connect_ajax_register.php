<?php
class crypto_connect_ajax_process
{
    private $user;

    public function __construct()
    {
        add_action("wp_ajax_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
        add_action("wp_ajax_nopriv_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
        add_filter('body_class', array($this, 'add_custom_user_logged_in_class'));
    }

    public function crypto_connect_ajax_process()
    {
        $id = $_REQUEST["id"];
        $nonce = $_REQUEST["nonce"];
        $param1 = $_REQUEST["param1"];
        $param2 = $_REQUEST["param2"];
        $param3 = $_REQUEST["param3"];
        $method_name = $_REQUEST["method_name"];

        $response = array(
            'error' => false,
            'msg' => 'No Message',
            'count' => '0',
        );


        // Validate nonce
        if (!wp_verify_nonce($nonce, 'crypto_ajax')) {
            $response['error'] = true;
            $response['msg'] = 'Invalid nonce';
            echo wp_json_encode($response);
            wp_die();
        }



        // Define a whitelist of allowed methods
        $allowed_methods = ['check', 'register', 'savenft', 'logout', 'crypto_delete_json'];

        // Check if method_name is in the whitelist
        if (in_array($method_name, $allowed_methods) && method_exists($this, $method_name)) {
            try {
                $msg = $this->$method_name($id, $param1, $param2, $param3, $nonce);
                $response['msg'] = $msg;
            } catch (Exception $e) {
                $response['error'] = true;
                $response['msg'] = 'Action failed: ' . $e->getMessage();
            }
        } else {
            $response['error'] = true;
            $response['msg'] = 'Invalid method';
        }

        echo wp_json_encode($response);
        wp_die();
    }

    public function check($id, $param1, $param2, $param3, $nonce)
    {
        // crypto_log("Check Function called : " . $param1);
        return "done";
    }

    public function register($id, $param1, $param2, $param3, $nonce)
    {
        //  crypto_log("register function called");
        if (!Crypto_User::if_custom_user_logged_in()) {
            $user_login = trim($param1);

            $existing_user_id = Crypto_User::if_custom_user_exists($user_login);

            if ($existing_user_id) {
                //crypto_log("Username already exists " . $user_login);
                Crypto_User::login_custom_user($user_login);
                $this->log_in($user_login);
            } else {
                //  crypto_log("New User " . $user_login);
                Crypto_User::register_custom_user($user_login);
                $this->log_in($user_login);
            }
        }
    }

    public function log_in($username)
    {
        if (Crypto_User::if_custom_user_logged_in()) {
            // crypto_log("User already logged in " . $username);
            return "success";
        } else {
            return "fail";
        }
    }

    public function savenft($id, $param1, $param2, $param3, $nonce)
    {
        // crypto_log("Save nft now check login");
        if (Crypto_User::if_custom_user_logged_in()) {
            // crypto_log("savenft function called");
            $current_user = Crypto_User::get_current_custom_user_login();
            $str_arr = preg_split("/,/", $param2);
            Crypto_User::set_custom_user_value($current_user, 'domain_names', $str_arr);
            Crypto_User::set_custom_user_value($current_user, 'domain_count', $param3);
            // crypto_log($str_arr);
            $saved_array = Crypto_User::get_custom_user_value($current_user, 'domain_names');
            //crypto_log($saved_array);
            $this->checknft($current_user, $saved_array);
        }
    }

    public function checknft($user_id, $saved_array)
    {
        // crypto_log("checknft function called");
        $saved_array = maybe_unserialize($saved_array);
        $default_access = crypto_get_option('select_access_control', 'crypto_access_settings_start', 'web3domain');
        if ($default_access == 'web3domain') {
            $check = crypto_get_option('domain_name', 'crypto_access_settings', 'yak');
            // crypto_log($saved_array);
            if (is_array($saved_array) && !empty($saved_array)) {
                $matches = preg_grep('/\.' . preg_quote($check, '/') . '$/', $saved_array);
                //  crypto_log("Count of matches " . count($matches) . " user :" . $user_id);
                Crypto_User::set_custom_user_value($user_id, 'user_status', count($matches) > 0 ? '1' : '0');
            } else {
                // crypto_log("Saved array is empty or not an array.");
            }
        } else {
            $nft_count = Crypto_User::get_custom_user_value($user_id, 'domain_count');
            $system_nft_count_value = crypto_get_option('nft_count', 'crypto_access_other', '1');
            // crypto_log("nft_count " . $nft_count . " system_nft_count_value " . $system_nft_count_value);
            Crypto_User::set_custom_user_value($user_id, 'user_status', $nft_count >= $system_nft_count_value ? '0' : '1');
        }
    }

    public function crypto_delete_json($id, $param1, $param2, $param3)
    {
        $uploaddir = wp_upload_dir();
        $base_path = $uploaddir['basedir'] . "/yak/" . basename($param1) . '_pending.json';
        if (file_exists($base_path)) {
            unlink($base_path);
        }
    }

    public function logout($id, $param1, $param2, $param3, $nonce)
    {
        Crypto_User::logout_custom_user();
    }

    // Add custom class to body if custom user is logged in
    public function add_custom_user_logged_in_class($classes)
    {
        // Check if the custom user is logged in
        if (isset($_SESSION['custom_user']) && !empty($_SESSION['custom_user'])) {
            // Add a class to the body tag
            $classes[] = 'custom-user-logged-in';
        } else {
            // Remove the class from the body tag
            $classes[] = 'custom-user-logged-out';
        }
        return $classes;
    }
}

$process = new crypto_connect_ajax_process();
