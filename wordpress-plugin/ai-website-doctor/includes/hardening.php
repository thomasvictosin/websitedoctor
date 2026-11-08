<?php
/**
 * Site protection ("hardening"). Each measure can be switched on and off,
 * is reversible, and reports whether it is actually effective on this server:
 *
 *  - block_php_uploads: uploads/.htaccess denies executing PHP (verified by
 *    requesting a harmless probe file through the site).
 *  - protect_sensitive_files: root .htaccess denies wp-config.php, logs,
 *    backups, dotfiles, readme/license files and direct wp-includes PHP.
 *  - disable_file_editor: removes the built-in plugin/theme code editor.
 *  - disable_xmlrpc: turns off XML-RPC (refused while Jetpack is active).
 *  - block_user_enumeration: hides usernames from ?author= and the REST API.
 *  - security_headers: nosniff, frame, referrer and permissions headers.
 *  - verified_crawlers: blocks attack-tool user agents everywhere, and on
 *    login, XML-RPC, admin and REST requests blocks empty user agents and
 *    "search crawlers" that fail reverse-DNS verification.
 *
 * .htaccess changes live only between our own markers, and the integrity
 * scan trusts that block only when it matches the digest this plugin wrote.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_HARDENING_OPTION', 'ai_website_doctor_hardening');
define('AWD_HARDENING_BEGIN', '# BEGIN AI Website Doctor hardening');
define('AWD_HARDENING_END', '# END AI Website Doctor hardening');
define('AWD_CRAWLER_CACHE_PREFIX', 'awd_crawler_');

add_action('admin_post_awd_hardening', 'awd_hardening_from_admin');
add_action('admin_post_awd_enable_all', 'awd_enable_all_from_admin');

function awd_hardening_measures(): array
{
    return array(
        'block_php_uploads' => array('title' => 'Block PHP in uploads', 'description' => 'Files in the uploads folder can never run as code. This stops the most common way attackers run dropped files.'),
        'protect_sensitive_files' => array('title' => 'Protect sensitive files', 'description' => 'Deny direct access to wp-config.php, logs, backups, hidden files, readme/license files and PHP files inside wp-includes.'),
        'disable_file_editor' => array('title' => 'Turn off the code editor', 'description' => 'Removes Appearance → Theme File Editor and Plugins → Plugin File Editor, so a stolen admin login cannot edit code.'),
        'disable_xmlrpc' => array('title' => 'Turn off XML-RPC', 'description' => 'Closes a common password-guessing and pingback abuse route. Not available while Jetpack is active.'),
        'block_user_enumeration' => array('title' => 'Hide usernames', 'description' => 'Stops visitors from listing administrator usernames through ?author= links or the REST API.'),
        'security_headers' => array('title' => 'Security headers', 'description' => 'Sends headers that stop content-type sniffing, framing by other sites and unnecessary browser features.'),
        'verified_crawlers' => array('title' => 'Block fake crawlers and attack tools', 'description' => 'Blocks known attack tools everywhere, and blocks fake Googlebot/Bingbot and requests without a browser identity on login, XML-RPC, admin and API requests. Real search engines are verified by reverse DNS and keep full access.'),
    );
}

function awd_hardening_state(): array
{
    $state = get_option(AWD_HARDENING_OPTION, array());
    return is_array($state) ? $state : array();
}

function awd_hardening_enabled(string $measure): bool
{
    $state = awd_hardening_state();
    return !empty($state[$measure]['enabled']);
}

function awd_hardening_save(string $measure, array $values): void
{
    $state = awd_hardening_state();
    $state[$measure] = array_merge((array) ($state[$measure] ?? array()), $values);
    update_option(AWD_HARDENING_OPTION, $state, true);
}

/** Digests of .htaccess blocks this plugin wrote; the injection detector skips only these exact blocks. */
function awd_hardening_trusted_block_hashes(): array
{
    if (!function_exists('get_option')) return array();
    $hashes = array();
    foreach (awd_hardening_state() as $entry) {
        if (is_array($entry) && !empty($entry['blockSha256'])) $hashes[] = (string) $entry['blockSha256'];
    }
    return $hashes;
}

function awd_hardening_block(array $lines): string
{
    return AWD_HARDENING_BEGIN . "\n" . implode("\n", $lines) . "\n" . AWD_HARDENING_END;
}

/** Replace (or remove, with null) our marked block in an .htaccess body. */
function awd_hardening_set_block(string $content, ?string $block, bool $prepend): string
{
    $pattern = '/\n?' . preg_quote(AWD_HARDENING_BEGIN, '/') . '.*?' . preg_quote(AWD_HARDENING_END, '/') . '\n?/s';
    $content = (string) preg_replace($pattern, "\n", $content);
    $content = trim($content, "\n") === '' ? '' : trim($content, "\n") . "\n";
    if ($block === null) return $content;
    return $prepend ? $block . "\n\n" . $content : $content . ($content === '' ? '' : "\n") . $block . "\n";
}

function awd_hardening_uploads_block(): string
{
    return awd_hardening_block(array(
        '<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|inc)$">',
        '  <IfModule mod_authz_core.c>',
        '    Require all denied',
        '  </IfModule>',
        '  <IfModule !mod_authz_core.c>',
        '    Order allow,deny',
        '    Deny from all',
        '  </IfModule>',
        '</FilesMatch>',
    ));
}

function awd_hardening_root_block(bool $multisite, string $base = '/'): string
{
    $lines = array(
        '<FilesMatch "^(?:wp-config\.php|readme\.html|license\.txt|wp-config-sample\.php|\.user\.ini|php\.ini|error_log|debug\.log)$|\.(?:log|sql|bak|old|orig|swp)$|^\.">',
        '  <IfModule mod_authz_core.c>',
        '    Require all denied',
        '  </IfModule>',
        '  <IfModule !mod_authz_core.c>',
        '    Order allow,deny',
        '    Deny from all',
        '  </IfModule>',
        '</FilesMatch>',
    );
    if (!$multisite) {
        // From the WordPress hardening guide; not compatible with multisite.
        array_push($lines,
            '<IfModule mod_rewrite.c>',
            'RewriteEngine On',
            'RewriteBase ' . $base,
            'RewriteRule ^wp-admin/includes/ - [F,L]',
            'RewriteRule !^wp-includes/ - [S=3]',
            'RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]',
            'RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]',
            'RewriteRule ^wp-includes/theme-compat/ - [F,L]',
            '</IfModule>'
        );
    }
    return awd_hardening_block($lines);
}

function awd_hardening_uploads_dir(): string
{
    $uploads = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : array();
    return is_array($uploads) && !empty($uploads['basedir']) ? rtrim((string) $uploads['basedir'], '/\\') : rtrim(WP_CONTENT_DIR, '/\\') . '/uploads';
}

/** Write our block into an .htaccess file, keeping everything else. Returns the block digest or an error. */
function awd_hardening_write_htaccess(string $path, ?string $block, bool $prepend)
{
    if (is_link($path)) return new WP_Error('awd_hardening_link', basename(dirname($path)) . '/.htaccess is a symbolic link; it was left unchanged.');
    $current = is_file($path) ? (string) file_get_contents($path) : '';
    $updated = awd_hardening_set_block($current, $block, $prepend);
    if ($updated === $current) return $block === null ? '' : hash('sha256', $block);
    $perms = is_file($path) ? @fileperms($path) : 0644;
    if (!awd_cleanup_atomic_write($path, $updated, $perms === false ? 0644 : $perms)) return new WP_Error('awd_hardening_write', 'Could not write ' . $path . ' (check file permissions).');
    return $block === null ? '' : hash('sha256', $block);
}

/** Request a URL through the site and return [status, body] (null status when unreachable). */
function awd_hardening_fetch(string $url): array
{
    $response = wp_remote_get($url, array('timeout' => 15, 'redirection' => 0, 'sslverify' => apply_filters('https_local_ssl_verify', false), 'headers' => array('Cache-Control' => 'no-cache')));
    if (is_wp_error($response)) return array(null, '');
    return array((int) wp_remote_retrieve_response_code($response), (string) wp_remote_retrieve_body($response));
}

/** Prove PHP in uploads cannot run: create a harmless probe, request it, delete it. */
function awd_hardening_verify_uploads(): array
{
    $dir = awd_hardening_uploads_dir();
    $name = 'awd-probe-' . strtolower(wp_generate_password(16, false, false)) . '.php';
    $path = $dir . '/' . $name;
    if (@file_put_contents($path, "<?php echo 'AWD-PROBE-' . (40 + 2);\n") === false) return array('verified' => null, 'detail' => 'Could not create the probe file to test the rule.');
    $uploads = wp_upload_dir(null, false);
    list($status, $body) = awd_hardening_fetch(rtrim((string) $uploads['baseurl'], '/') . '/' . $name);
    @unlink($path);
    if ($status === null) return array('verified' => null, 'detail' => 'The site could not request itself, so the rule could not be tested.');
    if (strpos($body, 'AWD-PROBE-42') !== false) return array('verified' => false, 'detail' => 'PHP still runs in uploads. This server ignores .htaccess (for example nginx); ask your host to deny *.php under wp-content/uploads.');
    return array('verified' => true, 'detail' => 'Confirmed: a PHP file in uploads returned HTTP ' . $status . ' without running.');
}

function awd_hardening_verify_sensitive(): array
{
    list($status) = awd_hardening_fetch(site_url('/wp-config.php'));
    if ($status === null) return array('verified' => null, 'detail' => 'The site could not request itself, so the rule could not be tested.');
    if ($status !== 403 && $status !== 404) return array('verified' => false, 'detail' => 'wp-config.php still answers HTTP ' . $status . '. This server may ignore .htaccess (for example nginx).');
    return array('verified' => true, 'detail' => 'Confirmed: wp-config.php answers HTTP ' . $status . '.');
}

/** Turn a measure on or off. Returns ['ok' => bool, 'message' => string]. */
function awd_hardening_apply(string $measure, bool $enable): array
{
    $measures = awd_hardening_measures();
    if (!isset($measures[$measure])) return array('ok' => false, 'message' => 'Unknown protection measure.');
    $now = gmdate('c');
    if ($measure === 'disable_xmlrpc' && $enable && function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        if (is_plugin_active('jetpack/jetpack.php')) return array('ok' => false, 'message' => 'Jetpack needs XML-RPC; turn Jetpack off first or leave XML-RPC on.');
    }
    if ($measure === 'block_php_uploads' || $measure === 'protect_sensitive_files') {
        $uploads = $measure === 'block_php_uploads';
        $path = $uploads ? awd_hardening_uploads_dir() . '/.htaccess' : ABSPATH . '.htaccess';
        $base = '/' . trim((string) wp_parse_url(home_url('/'), PHP_URL_PATH), '/');
        $base = $base === '/' ? '/' : $base . '/';
        $block = $enable ? ($uploads ? awd_hardening_uploads_block() : awd_hardening_root_block(function_exists('is_multisite') && is_multisite(), $base)) : null;
        $written = awd_hardening_write_htaccess($path, $block, true);
        if (is_wp_error($written)) return array('ok' => false, 'message' => $written->get_error_message());
        $check = $enable ? ($uploads ? awd_hardening_verify_uploads() : awd_hardening_verify_sensitive()) : array('verified' => null, 'detail' => 'Off.');
        if ($enable && !$uploads) {
            // A rule that breaks the home page is removed again immediately.
            list($home_status) = awd_hardening_fetch(home_url('/'));
            if ($home_status !== null && $home_status >= 500) {
                awd_hardening_write_htaccess($path, null, true);
                return array('ok' => false, 'message' => 'The server rejected the rules (home page HTTP ' . $home_status . '); they were removed again.');
            }
        }
        awd_hardening_save($measure, array('enabled' => $enable, 'changedAt' => $now, 'blockSha256' => $enable ? $written : '', 'verified' => $check['verified'], 'detail' => $check['detail']));
        return array('ok' => !$enable || $check['verified'] !== false, 'message' => $measures[$measure]['title'] . ($enable ? ' is on. ' . $check['detail'] : ' is off.'));
    }
    awd_hardening_save($measure, array('enabled' => $enable, 'changedAt' => $now, 'verified' => $enable ? true : null, 'detail' => $enable ? 'Active while this plugin is active.' : 'Off.'));
    return array('ok' => true, 'message' => $measures[$measure]['title'] . ($enable ? ' is on.' : ' is off.'));
}

/** Status for diagnostics and the admin page. */
function awd_hardening_report(): array
{
    $state = awd_hardening_state();
    $report = array();
    foreach (awd_hardening_measures() as $id => $measure) {
        $entry = (array) ($state[$id] ?? array());
        $report[] = array(
            'id' => $id,
            'enabled' => !empty($entry['enabled']),
            'verified' => array_key_exists('verified', $entry) ? $entry['verified'] : null,
            'detail' => substr((string) ($entry['detail'] ?? ''), 0, 300),
            'changedAt' => isset($entry['changedAt']) ? (string) $entry['changedAt'] : null,
        );
    }
    return $report;
}

// ---- Runtime measures -------------------------------------------------------

if (function_exists('add_filter') && function_exists('get_option')) {
    if (awd_hardening_enabled('disable_file_editor')) {
        add_filter('map_meta_cap', static function ($caps, $cap) {
            return in_array($cap, array('edit_files', 'edit_plugins', 'edit_themes'), true) ? array('do_not_allow') : $caps;
        }, 10, 2);
    }
    if (awd_hardening_enabled('disable_xmlrpc')) {
        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('xmlrpc_methods', static function ($methods) { return array(); });
        add_filter('wp_headers', static function ($headers) { unset($headers['X-Pingback']); return $headers; });
        add_filter('pings_open', '__return_false', 9999);
    }
    if (awd_hardening_enabled('block_user_enumeration')) {
        add_action('template_redirect', static function () {
            if (!is_user_logged_in() && isset($_GET['author']) && !is_admin()) { wp_safe_redirect(home_url('/'), 301); exit; }
        }, 1);
        add_filter('rest_endpoints', static function ($endpoints) {
            if (is_user_logged_in()) return $endpoints;
            foreach (array_keys($endpoints) as $route) {
                if (preg_match('#^/wp/v2/users(?:/|$)#', (string) $route)) unset($endpoints[$route]);
            }
            return $endpoints;
        });
    }
    if (awd_hardening_enabled('security_headers')) {
        add_action('send_headers', static function () {
            if (headers_sent()) return;
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: SAMEORIGIN');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header('Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()');
        });
    }
    if (awd_hardening_enabled('verified_crawlers')) {
        // init runs before WordPress handles login, XML-RPC, admin and REST requests, and after the auth API loads.
        add_action('init', 'awd_crawler_gate', 0);
    }
}

/** Search crawlers and the reverse-DNS domains they must resolve to. */
function awd_crawler_domains(): array
{
    return array(
        'googlebot|google-inspectiontool|googleother|adsbot-google|mediapartners-google|storebot-google' => array('googlebot.com', 'google.com', 'googleusercontent.com'),
        'bingbot|msnbot|adidxbot|bingpreview' => array('search.msn.com'),
        'yandex' => array('yandex.ru', 'yandex.net', 'yandex.com'),
        'baiduspider' => array('baidu.com', 'baidu.jp'),
        'applebot' => array('applebot.apple.com'),
    );
}

/** Whether an IP really belongs to the crawler's operator (reverse DNS + forward confirmation), cached for a day. */
function awd_crawler_verified(string $ip, array $domains): bool
{
    $key = AWD_CRAWLER_CACHE_PREFIX . md5($ip . '|' . implode(',', $domains));
    $cached = get_transient($key);
    if ($cached === 'yes' || $cached === 'no') return $cached === 'yes';
    $host = @gethostbyaddr($ip);
    $verified = false;
    if (is_string($host) && $host !== $ip) {
        $host = strtolower(rtrim($host, '.'));
        foreach ($domains as $domain) {
            if ($host === $domain || substr($host, -strlen('.' . $domain)) === '.' . $domain) { $verified = true; break; }
        }
        if ($verified) {
            $forward = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
                ? array_column((array) @dns_get_record($host, DNS_AAAA), 'ipv6')
                : (array) @gethostbynamel($host);
            $normalize = static function ($value) { $packed = @inet_pton((string) $value); return $packed === false ? '' : $packed; };
            $verified = in_array($normalize($ip), array_map($normalize, $forward), true);
        }
    }
    set_transient($key, $verified ? 'yes' : 'no', DAY_IN_SECONDS);
    return $verified;
}

/** Classify a request for the crawler gate. Returns null to allow, or a reason to block. */
function awd_crawler_decision(string $user_agent, string $path, string $method, string $ip, callable $verify): ?string
{
    $ua = strtolower($user_agent);
    if (preg_match('/sqlmap|nikto|wpscan|acunetix|netsparker|nessus|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|openvas|jorgee|wp-?login-?brute|fuzz faster/', $ua)) return 'attack tool';
    $sensitive = $method === 'POST' || (bool) preg_match('#(?:^|/)(?:wp-login\.php|xmlrpc\.php|wp-admin(?:/|$)|wp-json(?:/|$))#', $path);
    if (!$sensitive || strpos($path, 'admin-ajax.php') !== false) return null;
    if (trim($user_agent) === '') return 'no user agent';
    foreach (awd_crawler_domains() as $pattern => $domains) {
        if (preg_match('/' . $pattern . '/', $ua)) return $verify($ip, $domains) ? null : 'unverified crawler';
    }
    return null;
}

function awd_crawler_gate(): void
{
    if ((defined('DOING_CRON') && DOING_CRON) || (defined('WP_CLI') && WP_CLI) || PHP_SAPI === 'cli') return;
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    if ($ip === '' || $ip === (string) ($_SERVER['SERVER_ADDR'] ?? '') || in_array($ip, array('127.0.0.1', '::1'), true)) return;
    if (function_exists('is_user_logged_in') && is_user_logged_in()) return;
    $reason = awd_crawler_decision((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH), strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')), $ip, 'awd_crawler_verified');
    if ($reason === null) return;
    $counts = get_option('ai_website_doctor_blocked_requests', array());
    $counts = is_array($counts) ? $counts : array();
    $day = gmdate('Y-m-d');
    $counts[$day][$reason] = (int) ($counts[$day][$reason] ?? 0) + 1;
    update_option('ai_website_doctor_blocked_requests', array_slice($counts, -7, null, true), false);
    status_header(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Forbidden';
    exit;
}

function awd_hardening_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to change protection settings.', 'ai-website-doctor'), 403);
    $measure = isset($_POST['measure']) ? sanitize_key(wp_unslash($_POST['measure'])) : '';
    check_admin_referer('awd_hardening_' . $measure);
    $enable = isset($_POST['state']) && $_POST['state'] === 'on';
    $result = awd_hardening_apply($measure, $enable);
    $GLOBALS['awd_force_integrity_scan'] = true;
    awd_send_diagnostics();
    awd_redirect($result['message'], $result['ok'] ? 'success' : 'warning');
}

/**
 * Turns on every protection measure and/or speed fix that is still off, in one click.
 * Each one is applied and tested exactly as its own button would; a measure that
 * fails its test is switched back off and reported, the others stay on.
 */
function awd_enable_all(string $scope): array
{
    if (function_exists('set_time_limit')) @set_time_limit(180);
    $on = array();
    $failed = array();
    if ($scope === 'all' || $scope === 'protection') {
        $measures = awd_hardening_measures();
        foreach ($measures as $id => $measure) {
            if (awd_hardening_enabled($id)) continue;
            $result = awd_hardening_apply($id, true);
            if (!empty($result['ok'])) $on[] = $measure['title'];
            else $failed[] = $measure['title'] . ' (' . (string) ($result['message'] ?? 'not applied') . ')';
        }
    }
    if (($scope === 'all' || $scope === 'speed') && function_exists('awd_performance_measures')) {
        foreach (awd_performance_measures() as $id => $measure) {
            if (awd_performance_enabled($id)) continue;
            // Page caching needs a cache plugin; the app installs one (Speed tab), so skip it here when none is active.
            if ($id === 'page_cache' && function_exists('awd_performance_cache_plugins') && !awd_performance_cache_plugins()) {
                $failed[] = $measure['title'] . ' (no cache plugin is active yet; use Apply recommended fixes in the app, which installs one)';
                continue;
            }
            $result = awd_performance_apply($id, true);
            if (!empty($result['ok'])) $on[] = $measure['title'];
            else $failed[] = $measure['title'] . ' (' . (string) ($result['message'] ?? 'not applied') . ')';
        }
    }
    if (!$on && !$failed) return array('ok' => true, 'message' => 'Everything is already on.');
    $message = $on ? 'Turned on: ' . implode(', ', $on) . '.' : '';
    if ($failed) $message .= ($message ? ' ' : '') . 'Not turned on: ' . implode('; ', $failed) . '.';
    return array('ok' => !$failed, 'message' => $message);
}

function awd_enable_all_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to change protection settings.', 'ai-website-doctor'), 403);
    check_admin_referer('awd_enable_all');
    $scope = isset($_POST['scope']) ? sanitize_key(wp_unslash($_POST['scope'])) : '';
    if (!in_array($scope, array('all', 'protection', 'speed'), true)) wp_die('Unknown scope.', 400);
    $result = awd_enable_all($scope);
    $GLOBALS['awd_force_integrity_scan'] = true;
    awd_send_diagnostics();
    awd_redirect($result['message'], $result['ok'] ? 'success' : 'warning');
}

/** Number of protection measures and speed fixes that are still off. */
function awd_enable_all_counts(): array
{
    $protection = 0;
    foreach (array_keys(awd_hardening_measures()) as $id) if (!awd_hardening_enabled($id)) $protection++;
    $speed = 0;
    if (function_exists('awd_performance_measures')) foreach (array_keys(awd_performance_measures()) as $id) if (!awd_performance_enabled($id)) $speed++;
    return array('protection' => $protection, 'speed' => $speed);
}

function awd_render_enable_all_button(string $scope, string $label): void
{
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:8px 0 12px"><input type="hidden" name="action" value="awd_enable_all"><input type="hidden" name="scope" value="' . esc_attr($scope) . '">';
    wp_nonce_field('awd_enable_all');
    submit_button($label, 'primary', 'submit', false);
    echo '</form>';
}

function awd_render_enable_all_card(): void
{
    $counts = awd_enable_all_counts();
    $total = $counts['protection'] + $counts['speed'];
    echo '<div class="awd-card"><h2>Turn everything on</h2>';
    if ($total === 0) {
        echo '<p>All protection measures and speed fixes are on.</p></div>';
        return;
    }
    echo '<p>' . esc_html(sprintf('%d protection measure(s) and %d speed fix(es) are off. One click turns them all on. Each is tested on this server exactly like its own button, and anything that breaks the home page is switched back off automatically.', $counts['protection'], $counts['speed'])) . '</p>';
    awd_render_enable_all_button('all', sprintf('Turn on all protection and speed fixes (%d)', $total));
    echo '</div>';
}

function awd_render_hardening_section(): void
{
    echo '<h2>Protection</h2><p>Each measure is reversible. Rules that change .htaccess are tested on this server after they are applied.</p>';
    $off = awd_enable_all_counts()['protection'];
    if ($off > 0) awd_render_enable_all_button('protection', sprintf('Turn on all protection (%d)', $off));
    echo '<table class="widefat striped"><tbody>';
    $state = awd_hardening_state();
    foreach (awd_hardening_measures() as $id => $measure) {
        $entry = (array) ($state[$id] ?? array());
        $on = !empty($entry['enabled']);
        $status = !$on ? 'Off' : (($entry['verified'] ?? null) === false ? 'On, NOT effective' : (($entry['verified'] ?? null) === true ? 'On, verified' : 'On'));
        echo '<tr><td><strong>' . esc_html($measure['title']) . '</strong><br><span class="awd-muted">' . esc_html($measure['description']) . '</span>';
        if (!empty($entry['detail']) && $on) echo '<br><em>' . esc_html((string) $entry['detail']) . '</em>';
        echo '</td><td>' . esc_html($status) . '</td><td><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_hardening"><input type="hidden" name="measure" value="' . esc_attr($id) . '"><input type="hidden" name="state" value="' . ($on ? 'off' : 'on') . '">';
        wp_nonce_field('awd_hardening_' . $id);
        submit_button($on ? 'Turn off' : 'Turn on', $on ? 'secondary' : 'primary', 'submit', false);
        echo '</form></td></tr>';
    }
    echo '</tbody></table>';
    $blocked = get_option('ai_website_doctor_blocked_requests', array());
    if (is_array($blocked) && $blocked) {
        $total = 0;
        foreach ($blocked as $day) foreach ((array) $day as $count) $total += (int) $count;
        echo '<p class="awd-muted">' . esc_html(sprintf('%d request(s) blocked by the crawler and attack-tool filter in the last 7 days.', $total)) . '</p>';
    }
}
