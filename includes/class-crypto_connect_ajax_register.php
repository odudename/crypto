<?php
class crypto_connect_ajax_process
{
    private $user;

    public function __construct()
    {
        add_action("wp_ajax_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
        add_action("wp_ajax_nopriv_crypto_connect_ajax_process", array($this, "crypto_connect_ajax_process"));
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

        if (method_exists($this, $method_name)) {
            // Call the method dynamically and handle any exceptions
            try {
                $msg = $this->$method_name($id, $param1, $param2, $param3);
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

    public function get_userid_by_meta($key, $value)
    {
        if ($user = get_user_by('login', $value)) {
            return $user->ID;
        } else {
            global $wpdb;
            $users = $wpdb->get_results($wpdb->prepare("SELECT user_id FROM $wpdb->usermeta WHERE meta_key = %s AND meta_value = %s", $key, $value));
            if ($users) {
                foreach ($users as $user) {
                    return $user->user_id;
                }
            } else {
                return 0;
            }
        }
    }

    public function check($id, $param1, $param2, $param3)
    {
        if (is_user_logged_in()) {
            $the_user_id = $this->get_userid_by_meta('crypto_wallet', trim($param1));
            if ($the_user_id != 0) {
                delete_user_meta($the_user_id, 'crypto_wallet');
                update_user_meta(get_current_user_id(), 'crypto_wallet', trim($param1));
            } else {
                update_user_meta(get_current_user_id(), 'crypto_wallet', trim($param1));
            }
        }
        return "done";
    }

    public function register($id, $param1, $param2, $param3)
    {
        if (!is_user_logged_in()) {
            $user_login = trim($param1);
            $the_user_id = $this->get_userid_by_meta('crypto_wallet', trim($param1));

            if ($the_user_id != 0) {
                $user = get_user_by('id', $the_user_id);
                return $this->log_in($user->user_login);
            } else {
                $existing_user_id = username_exists($user_login);

                if ($existing_user_id) {
                    return $this->log_in($user_login);
                } else {
                    $user_id = wp_create_user($user_login, wp_generate_password());
                    if (is_wp_error($user_id)) {
                        return 'User creation failed';
                    }
                    update_user_meta($user_id, 'crypto_wallet', trim($param1));
                    return $this->log_in($user_login);
                }
            }
        }
    }

    public function log_in($username)
    {
        if (!is_user_logged_in()) {
            if ($user = get_user_by('login', $username)) {
                clean_user_cache($user->ID);
                wp_clear_auth_cookie();
                wp_set_current_user($user->ID);
                wp_set_auth_cookie($user->ID, true, is_ssl());
                do_action('wp_login', $user->user_login, $user);
                return is_user_logged_in() ? "success" : "fail";
            }
        }
        return "wrong";
    }

    public function savenft($id, $param1, $param2, $param3)
    {
        if (is_user_logged_in()) {
            $str_arr = preg_split("/,/", $param2);
            update_user_meta(get_current_user_id(), 'domain_names', $str_arr);
            update_user_meta(get_current_user_id(), 'domain_count', $param3);
            $saved_array = get_user_meta(get_current_user_id(), 'domain_names');
            $this->checknft(get_current_user_id(), $saved_array);
        }
    }

    public function checknft($user_id, $saved_array)
    {
        $default_access = crypto_get_option('select_access_control', 'crypto_access_settings_start', 'web3domain');
        if ($default_access == 'web3domain') {
            $check = crypto_get_option('domain_name', 'crypto_access_settings', 'yak');
            if (is_array($saved_array) && !empty($saved_array[0])) {
                $matches = preg_grep('/.' . $check . '$/', $saved_array[0]);
                update_user_meta(get_current_user_id(), 'domain_block', count($matches) > 0 ? 'false' : 'true');
            }
        } else {
            $nft_count = get_user_meta(get_current_user_id(), 'domain_count')[0];
            $system_nft_count_value = crypto_get_option('nft_count', 'crypto_access_other', '1');
            update_user_meta(get_current_user_id(), 'domain_block', $nft_count >= $system_nft_count_value ? 'false' : 'true');
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

    public function logout($id, $param1, $param2, $param3)
    {
        wp_logout();
    }
}

$process = new crypto_connect_ajax_process();
