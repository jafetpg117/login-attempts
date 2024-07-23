<?php
/*
Plugin Name: Limit Login Attempts
Plugin URI: https://www.jafetdev.com/
Description: Limit the number of login attempts and handle IP blocking for security.
Version: 2.0
Author: Jafet Prieto
Author URI: https://www.jafetdev.com/
*/

function limit_login_attempts() {
    $max_attempts = get_option('limit_login_attempts', 5); // Maximum number of attempts
    $lockout_time = get_option('limit_login_duration', 24) * 3600; // Lockout time in seconds, configurable
    $permanent_block_limit = get_option('permanent_block_limit', 3); // Limit of temporary blocks before permanent block

    $user_ip = $_SERVER['REMOTE_ADDR'];
    $blocked_ips = get_option('blocked_ips', []);
    $login_attempts = get_option('login_attempts', []);
    $permanent_blocked_ips = get_option('permanent_blocked_ips', []);

    if (isset($permanent_blocked_ips[$user_ip])) {
        wp_die('Your IP has been permanently blocked due to repeated login failures.');
    }

    if (isset($blocked_ips[$user_ip]) && time() < $blocked_ips[$user_ip]) {
        wp_die('You have exceeded the login attempt limit. Your access has been blocked.');
    }

    add_action('wp_login_failed', function ($username) use ($user_ip, $max_attempts, $lockout_time, &$login_attempts, &$blocked_ips, $permanent_block_limit, &$permanent_blocked_ips) {
        $login_attempts[$user_ip] = ($login_attempts[$user_ip] ?? 0) + 1;

        if ($login_attempts[$user_ip] >= $max_attempts) {
            if (isset($blocked_ips[$user_ip . '_count']) && ++$blocked_ips[$user_ip . '_count'] >= $permanent_block_limit) {
                $permanent_blocked_ips[$user_ip] = true;
                update_option('permanent_blocked_ips', $permanent_blocked_ips);
                wp_die('Your IP has been permanently blocked due to repeated login failures.');
            } else {
                $blocked_ips[$user_ip] = time() + $lockout_time;
                $blocked_ips[$user_ip . '_count'] = ($blocked_ips[$user_ip . '_count'] ?? 0) + 1;
                update_option('blocked_ips', $blocked_ips);
            }
            $login_attempts[$user_ip] = 0;
        }
        update_option('login_attempts', $login_attempts);
    });

    add_action('wp_login', function ($user_login, $user) use ($user_ip, &$login_attempts) {
        if (isset($login_attempts[$user_ip])) {
            unset($login_attempts[$user_ip]);
            update_option('login_attempts', $login_attempts);
        }
    }, 10, 2);
}

add_action('init', 'limit_login_attempts');

function limit_login_menu() {
    add_menu_page(
        'Limit Login Attempts', 
        'Limit Login Attempts', 
        'manage_options',       
        'limit_login_attempts_menu', 
        'limit_login_settings_page', 
        'dashicons-shield',     
        99                      
    );
}

add_action('admin_menu', 'limit_login_menu');

function limit_login_settings_page() {
    ?>
    <div class="wrap">
        <h2><?php echo esc_html(get_admin_page_title()); ?></h2>
        <form action="options.php" method="post">
            <?php
            settings_fields('limit_login_options');
            do_settings_sections('limit_login_attempts');
            submit_button('Save Changes');
            ?>
        </form>
        <h2>Blocked IPs</h2>
        <table class="widefat fixed" cellspacing="0">
            <thead>
                <tr>
                    <th class="manage-column column-columnname" scope="col">IP Address</th>
                    <th class="manage-column column-columnname" scope="col">Remaining Lockout Time</th>
                    <th class="manage-column column-columnname" scope="col">Block Count</th>
                    <th class="manage-column column-columnname" scope="col">Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $blocked_ips = get_option('blocked_ips', []);
            foreach ($blocked_ips as $ip => $expiry) {
                if (!strpos($ip, '_count')) {
                    echo "<tr id='ip-". esc_attr($ip) ."'><td>" . esc_html($ip) . "</td><td class='remaining-time' data-expiry='{$expiry}'>" . calculate_time_left($expiry) . "</td><td>" . esc_html($blocked_ips[$ip . '_count'] ?? 0) . "</td><td><button class='button delete-ip' data-ip='". esc_attr($ip) ."'>Delete</button></td></tr>";
                }
            }
            ?>
            </tbody>
        </table>
    </div>
    <script>
document.addEventListener('DOMContentLoaded', function() {
    // Update the blocked IPs table in real-time
    function updateRemainingTimes() {
        var times = document.querySelectorAll('.remaining-time');
        times.forEach(function(time) {
            var expiry = parseInt(time.getAttribute('data-expiry'), 10);
            var now = Math.floor(Date.now() / 1000);
            var remainingSeconds = expiry - now;
            if (remainingSeconds > 0) {
                var hours = Math.floor(remainingSeconds / 3600);
                var minutes = Math.floor((remainingSeconds % 3600) / 60);
                time.textContent = hours + ' hours ' + minutes + ' minutes';
            } else {
                time.textContent = 'Unblocked';
            }
        });
    }
    setInterval(updateRemainingTimes, 1000);
    updateRemainingTimes();

    // Handle the click event to delete IPs
    document.querySelectorAll('.delete-ip').forEach(button => {
        button.addEventListener('click', function() {
            var ip = this.getAttribute('data-ip');
            if (confirm('Are you sure you want to delete this IP: ' + ip + '?')) { // pop up confirmation to remove IP
                fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=delete_blocked_ip&ip=' + encodeURIComponent(ip)
                }).then(response => response.json())
                .then(data => {
                    if(data.success) {
                        document.getElementById('ip-' + ip).remove();
                        var notice = document.createElement('div');
                        notice.className = 'notice notice-success is-dismissible';
                        notice.innerHTML = '<p>IP ' + ip + ' has been successfully deleted from the blocked IPs list.</p>';
                        document.querySelector('.wrap').insertBefore(notice, document.querySelector('.wrap').firstChild);
                    } else {
                        alert('Error deleting IP: ' + data.error);
                    }
                });
            }
        });
    });
});
</script>

    <?php
}


add_action('wp_ajax_delete_blocked_ip', 'handle_delete_blocked_ip');
function handle_delete_blocked_ip() {
    if (!current_user_can('manage_options')) {
        wp_send_json(['success' => false, 'error' => 'Unauthorized']);
        return;
    }

    $ip = sanitize_text_field($_POST['ip']);
    $blocked_ips = get_option('blocked_ips', []);
    $permanent_blocked_ips = get_option('permanent_blocked_ips', []);

    // Remove the IP from both temporary and permanent block lists
    if (isset($blocked_ips[$ip])) {
        unset($blocked_ips[$ip]);
        unset($blocked_ips[$ip . '_count']);  // Ensure to remove count as well
        update_option('blocked_ips', $blocked_ips);
    }

    if (isset($permanent_blocked_ips[$ip])) {
        unset($permanent_blocked_ips[$ip]);
        update_option('permanent_blocked_ips', $permanent_blocked_ips);
    }

    wp_send_json(['success' => true]);
}


// Calculate remaining blocking time and display status

function calculate_time_left($expiry) {
    $remainingSeconds = $expiry - time();
    if ($remainingSeconds <= 0) {
        return 'Unblocked';
    }
    $hours = floor($remainingSeconds / 3600);
    $minutes = floor(($remainingSeconds % 3600) / 60);
    return $hours . ' hours ' . $minutes . ' minutes'; 
}



function limit_login_settings_init() {
    register_setting('limit_login_options', 'limit_login_attempts');
    register_setting('limit_login_options', 'limit_login_duration');
    register_setting('limit_login_options', 'permanent_block_limit');

    add_settings_section('limit_login_section', 'Settings', 'limit_login_section_callback', 'limit_login_attempts');

    add_settings_field('limit_login_field_attempts', 'Maximum Login Attempts', 'limit_login_field_attempts_callback', 'limit_login_attempts', 'limit_login_section');
    add_settings_field('limit_login_field_duration', 'Lockout Duration (Hours)', 'limit_login_field_duration_callback', 'limit_login_attempts', 'limit_login_section');
    add_settings_field('limit_login_field_permanent_limit', 'Permanent Block Limit', 'limit_login_field_permanent_limit_callback', 'limit_login_attempts', 'limit_login_section');
}

add_action('admin_init', 'limit_login_settings_init');

function limit_login_section_callback() {
    echo '<p>Set the maximum number of allowed login attempts and lockout duration.</p>';
}

function limit_login_field_attempts_callback() {
    $value = get_option('limit_login_attempts', 5);
    echo '<input type="number" name="limit_login_attempts" value="' . esc_attr($value) . '" min="1" />';
}

function limit_login_field_duration_callback() {
    $value = get_option('limit_login_duration', 24);
    echo '<input type="number" name="limit_login_duration" value="' . esc_attr($value) . '" min="1" />';
}

function limit_login_field_permanent_limit_callback() {
    $value = get_option('permanent_block_limit', 3);
    echo '<input type="number" name="permanent_block_limit" value="' . esc_attr($value) . '" min="1" />';
}
?>
