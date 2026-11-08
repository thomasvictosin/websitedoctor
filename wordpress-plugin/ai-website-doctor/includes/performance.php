<?php
/**
 * Speed measures that address the most common PageSpeed findings. Each one
 * is reversible, switched through the approved executor (set_performance)
 * or this plugin's admin page, and checked after it is switched on: the home
 * page must still load, and server rules are confirmed with a real request.
 *
 *  - page_cache: uses the active cache plugin (LiteSpeed Cache's own switch
 *    is turned on; others are reported); the app installs one first if none.
 *  - compression / browser_caching: .htaccess rules between our own markers
 *    (Apache and LiteSpeed; nginx ignores them and the check says so).
 *  - defer_scripts: front-end footer scripts load with WordPress's "defer"
 *    strategy; header scripts and jQuery stay as they are (plugins print inline
 *    header code that calls them at once), and WordPress keeps order-sensitive
 *    scripts blocking.
 *  - font_display_swap: display=swap on Google Fonts plus early connections.
 *  - trim_extras: no emoji script, embed script or dashicons for visitors.
 *  - lazy_load: native lazy loading for images and iframes stays on.
 *  - webp_uploads: new JPEG/PNG uploads are saved as WebP when supported.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_PERFORMANCE_OPTION', 'ai_website_doctor_performance');
define('AWD_PERFORMANCE_BEGIN', '# BEGIN AI Website Doctor performance');
define('AWD_PERFORMANCE_END', '# END AI Website Doctor performance');

add_action('admin_post_awd_performance', 'awd_performance_from_admin');

function awd_performance_measures(): array
{
    return array(
        'page_cache' => array('title' => 'Page caching', 'description' => 'Serves ready-made pages instead of building every page with PHP.'),
        'compression' => array('title' => 'Text compression', 'description' => 'Compresses HTML, CSS and JavaScript (gzip/Brotli) on Apache and LiteSpeed servers.'),
        'browser_caching' => array('title' => 'Browser caching', 'description' => 'Lets returning visitors reuse images, CSS, JavaScript and fonts.'),
        'defer_scripts' => array('title' => 'Defer non-critical JavaScript', 'description' => 'Theme and plugin scripts at the end of the page load after the page is shown; header scripts and jQuery stay as they are.'),
        'font_display_swap' => array('title' => 'Show text while fonts load', 'description' => 'font-display: swap for Google Fonts and an early connection to the font server.'),
        'trim_extras' => array('title' => 'Remove unused WordPress extras', 'description' => 'No emoji script, embed script or dashicons for visitors who are not logged in.'),
        'lazy_load' => array('title' => 'Lazy-load images and videos', 'description' => 'Images and embedded videos below the first screen load when scrolled to.'),
        'webp_uploads' => array('title' => 'WebP for new uploads', 'description' => 'New JPEG and PNG uploads are saved as WebP (existing images are unchanged).'),
    ) + (function_exists('awd_a11y_measures') ? awd_a11y_measures() : array());
}

function awd_performance_state(): array
{
    $state = get_option(AWD_PERFORMANCE_OPTION, array());
    return is_array($state) ? $state : array();
}

function awd_performance_enabled(string $measure): bool
{
    $state = awd_performance_state();
    return !empty($state[$measure]['enabled']);
}

function awd_performance_save(string $measure, array $values): void
{
    $state = awd_performance_state();
    $state[$measure] = array_merge((array) ($state[$measure] ?? array()), $values);
    update_option(AWD_PERFORMANCE_OPTION, $state, true);
}

/** Active cache plugins this plugin recognises (slug => name). */
function awd_performance_cache_plugins(): array
{
    $active_plugins = (array) get_option('active_plugins', array());
    $known = array(
        'litespeed-cache/litespeed-cache.php' => 'LiteSpeed Cache', 'wp-rocket/wp-rocket.php' => 'WP Rocket', 'w3-total-cache/w3-total-cache.php' => 'W3 Total Cache',
        'wp-super-cache/wp-cache.php' => 'WP Super Cache', 'wp-fastest-cache/wpFastestCache.php' => 'WP Fastest Cache', 'cache-enabler/cache-enabler.php' => 'Cache Enabler',
        'breeze/breeze.php' => 'Breeze', 'sg-cachepress/sg-cachepress.php' => 'SiteGround Speed Optimizer', 'hummingbird-performance/wp-hummingbird.php' => 'Hummingbird',
        'wp-optimize/wp-optimize.php' => 'WP-Optimize', 'nitropack/main.php' => 'NitroPack', 'swift-performance-lite/performance.php' => 'Swift Performance',
    );
    $active = array();
    foreach ($known as $file => $name) {
        if (in_array($file, $active_plugins, true)) $active[dirname($file)] = $name;
    }
    return $active;
}

function awd_performance_htaccess_block(): ?string
{
    $lines = array();
    if (awd_performance_enabled('compression')) {
        array_push($lines,
            '<IfModule mod_brotli.c>',
            '  AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/css text/xml text/javascript application/javascript application/json application/xml image/svg+xml font/ttf font/otf',
            '</IfModule>',
            '<IfModule mod_deflate.c>',
            '  AddOutputFilterByType DEFLATE text/html text/plain text/css text/xml text/javascript application/javascript application/x-javascript application/json application/xml application/rss+xml image/svg+xml font/ttf font/otf',
            '</IfModule>'
        );
    }
    if (awd_performance_enabled('browser_caching')) {
        array_push($lines,
            '<IfModule mod_expires.c>',
            '  ExpiresActive On',
            '  ExpiresByType image/jpeg "access plus 1 year"',
            '  ExpiresByType image/png "access plus 1 year"',
            '  ExpiresByType image/gif "access plus 1 year"',
            '  ExpiresByType image/webp "access plus 1 year"',
            '  ExpiresByType image/avif "access plus 1 year"',
            '  ExpiresByType image/svg+xml "access plus 1 year"',
            '  ExpiresByType image/x-icon "access plus 1 year"',
            '  ExpiresByType video/mp4 "access plus 1 year"',
            '  ExpiresByType font/woff2 "access plus 1 year"',
            '  ExpiresByType font/woff "access plus 1 year"',
            '  ExpiresByType font/ttf "access plus 1 year"',
            '  ExpiresByType text/css "access plus 1 year"',
            '  ExpiresByType text/javascript "access plus 1 year"',
            '  ExpiresByType application/javascript "access plus 1 year"',
            '</IfModule>',
            '<IfModule mod_headers.c>',
            '  <FilesMatch "\.(?i:jpe?g|png|gif|webp|avif|svg|ico|mp4|woff2?|ttf|otf|css|js)$">',
            '    Header set Cache-Control "public, max-age=31536000"',
            '  </FilesMatch>',
            '</IfModule>'
        );
    }
    return $lines ? AWD_PERFORMANCE_BEGIN . "\n" . implode("\n", $lines) . "\n" . AWD_PERFORMANCE_END : null;
}

function awd_performance_write_htaccess(): ?string
{
    $path = ABSPATH . '.htaccess';
    if (is_link($path)) return 'The .htaccess file is a symbolic link; it was left unchanged.';
    $current = is_file($path) ? (string) file_get_contents($path) : '';
    $pattern = '/\n?' . preg_quote(AWD_PERFORMANCE_BEGIN, '/') . '.*?' . preg_quote(AWD_PERFORMANCE_END, '/') . '\n?/s';
    $content = trim((string) preg_replace($pattern, "\n", $current), "\n");
    $block = awd_performance_htaccess_block();
    $updated = $block === null ? ($content === '' ? '' : $content . "\n") : ($content === '' ? $block . "\n" : $content . "\n\n" . $block . "\n");
    if ($updated === $current) return null;
    $perms = is_file($path) ? @fileperms($path) : 0644;
    return awd_cleanup_atomic_write($path, $updated, $perms === false ? 0644 : $perms) ? null : 'Could not write .htaccess (check file permissions).';
}

/** Request a URL through the site and return the response (or null). */
function awd_performance_fetch(string $url, array $headers = array())
{
    $response = wp_remote_get($url, array('timeout' => 15, 'redirection' => 2, 'sslverify' => apply_filters('https_local_ssl_verify', false), 'headers' => $headers + array('Cache-Control' => 'no-cache'), 'decompress' => false));
    return is_wp_error($response) ? null : $response;
}

function awd_performance_verify(string $measure): array
{
    if ($measure === 'compression') {
        $response = awd_performance_fetch(add_query_arg('awd_perf', (string) time(), home_url('/')), array('Accept-Encoding' => 'gzip, deflate, br'));
        if ($response === null) return array('verified' => null, 'detail' => 'The site could not request itself, so compression could not be tested.');
        $encoding = strtolower((string) wp_remote_retrieve_header($response, 'content-encoding'));
        return $encoding !== '' ? array('verified' => true, 'detail' => 'Confirmed: pages are sent ' . $encoding . '-compressed.') : array('verified' => false, 'detail' => 'Pages are still sent uncompressed. This server ignores .htaccess (for example nginx) or lacks mod_deflate; ask your host to enable gzip or Brotli.');
    }
    if ($measure === 'browser_caching') {
        $asset = includes_url('js/wp-embed.min.js');
        if (!is_file(ABSPATH . WPINC . '/js/wp-embed.min.js')) $asset = includes_url('css/dashicons.min.css');
        $response = awd_performance_fetch(add_query_arg('ver', (string) time(), $asset));
        if ($response === null) return array('verified' => null, 'detail' => 'The site could not request itself, so caching headers could not be tested.');
        $cache = (string) wp_remote_retrieve_header($response, 'cache-control');
        $expires = (string) wp_remote_retrieve_header($response, 'expires');
        return preg_match('/max-age=(\d+)/', $cache, $match) && (int) $match[1] >= 2592000 || ($expires !== '' && strtotime($expires) > time() + 2592000)
            ? array('verified' => true, 'detail' => 'Confirmed: static files are cached by browsers (' . ($cache ?: 'Expires ' . $expires) . ').')
            : array('verified' => false, 'detail' => 'Static files still have no long cache lifetime. This server ignores .htaccess (for example nginx) or lacks mod_expires/mod_headers; ask your host to add cache headers.');
    }
    if ($measure === 'page_cache') {
        $plugins = awd_performance_cache_plugins();
        if (!$plugins) return array('verified' => false, 'detail' => 'No cache plugin is active.');
        return array('verified' => true, 'detail' => 'Page caching is provided by ' . implode(', ', $plugins) . '.');
    }
    if ($measure === 'webp_uploads') {
        if (!function_exists('wp_image_editor_supports')) require_once ABSPATH . WPINC . '/media.php';
        return wp_image_editor_supports(array('mime_type' => 'image/webp'))
            ? array('verified' => true, 'detail' => 'New JPEG and PNG uploads are saved as WebP.')
            : array('verified' => false, 'detail' => 'This server\'s image library cannot write WebP; ask your host to enable WebP in GD or Imagick.');
    }
    return array('verified' => true, 'detail' => 'Active while this plugin is active.');
}

/** Turn a measure on or off. Returns ['ok' => bool, 'message' => string]. */
function awd_performance_apply(string $measure, bool $enable): array
{
    $measures = awd_performance_measures();
    if (!isset($measures[$measure])) return array('ok' => false, 'message' => 'Unknown performance measure.');
    $was = awd_performance_enabled($measure);
    $baseline = function_exists('awd_plugin_site_health') ? awd_plugin_site_health() : array('ok' => true);
    if ($measure === 'page_cache' && $enable) {
        $plugins = awd_performance_cache_plugins();
        if (!$plugins) return array('ok' => false, 'message' => 'No cache plugin is active. Install LiteSpeed Cache (LiteSpeed servers) or Cache Enabler first; the app does this for you.');
        if (isset($plugins['litespeed-cache']) && !get_option('litespeed.conf.cache')) update_option('litespeed.conf.cache', 1);
    }
    awd_performance_save($measure, array('enabled' => $enable, 'changedAt' => gmdate('c')));
    if (in_array($measure, array('compression', 'browser_caching'), true)) {
        $error = awd_performance_write_htaccess();
        if ($error !== null) {
            awd_performance_save($measure, array('enabled' => $was));
            return array('ok' => false, 'message' => $error);
        }
    }
    if ($enable) {
        $after = function_exists('awd_plugin_site_health') ? awd_plugin_site_health() : array('ok' => true);
        if (!empty($baseline['ok']) && empty($after['ok'])) {
            awd_performance_save($measure, array('enabled' => $was));
            if (in_array($measure, array('compression', 'browser_caching'), true)) awd_performance_write_htaccess();
            return array('ok' => false, 'message' => $measures[$measure]['title'] . ' broke the home page (' . ($after['reason'] ?? 'error') . '); it was switched off again.');
        }
    }
    $check = $enable ? awd_performance_verify($measure) : array('verified' => null, 'detail' => 'Off.');
    awd_performance_save($measure, array('verified' => $check['verified'], 'detail' => $check['detail']));
    if (function_exists('awd_cleanup_op_purge_page_cache')) awd_cleanup_op_purge_page_cache(array(), array());
    return array('ok' => !$enable || $check['verified'] !== false, 'message' => $measures[$measure]['title'] . ($enable ? ' is on. ' . $check['detail'] : ' is off.'));
}

function awd_performance_report(): array
{
    $state = awd_performance_state();
    $measures = array();
    foreach (awd_performance_measures() as $id => $measure) {
        $entry = (array) ($state[$id] ?? array());
        $measures[] = array('id' => $id, 'enabled' => !empty($entry['enabled']), 'verified' => array_key_exists('verified', $entry) ? $entry['verified'] : null, 'detail' => substr((string) ($entry['detail'] ?? ''), 0, 300));
    }
    return array(
        'measures' => $measures,
        'server' => substr(sanitize_text_field((string) ($_SERVER['SERVER_SOFTWARE'] ?? '')), 0, 80),
        'cachePlugins' => array_values(awd_performance_cache_plugins()),
    );
}

function awd_cleanup_op_set_performance(array $params, array $context): array
{
    $was = awd_performance_enabled($params['measure']);
    $enable = $params['state'] === 'on';
    if ($was === $enable && $params['measure'] !== 'page_cache') return awd_cleanup_result('skipped', 'Already ' . $params['state'] . '.');
    $result = awd_performance_apply($params['measure'], $enable);
    return awd_cleanup_result($result['ok'] ? 'applied' : 'failed', $result['message'], array('measure' => $params['measure'], 'wasEnabled' => $was));
}

function awd_performance_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die('Not allowed.');
    check_admin_referer('awd_performance');
    $measure = sanitize_key((string) ($_POST['measure'] ?? ''));
    $result = awd_performance_apply($measure, ($_POST['state'] ?? '') === 'on');
    awd_redirect($result['message'], $result['ok'] ? 'success' : 'warning');
}

function awd_render_performance_section(): void
{
    $state = awd_performance_state();
    echo '<div class="awd-card"><h2>Speed</h2><p>Switch on the fixes for common PageSpeed findings. Each one is checked after it is switched on and switched off again if the home page breaks. The app shows your PageSpeed scores and recommends which ones to use.</p>';
    $off = function_exists('awd_enable_all_counts') ? awd_enable_all_counts()['speed'] : 0;
    if ($off > 0) awd_render_enable_all_button('speed', sprintf('Turn on all speed fixes (%d)', $off));
    echo '<table class="widefat striped"><tbody>';
    awd_render_performance_rows($state, 'speed');
    echo '</tbody></table></div>';
    $off = function_exists('awd_enable_all_counts') ? awd_enable_all_counts()['accessibility'] : 0;
    echo '<div class="awd-card"><h2>Accessibility</h2><p>Fixes added to each page as it is sent to visitors; theme and plugin files are not edited and nothing visible changes. Colour contrast and small tap targets are design changes and are not fixed automatically.</p>';
    if ($off > 0) awd_render_enable_all_button('accessibility', sprintf('Turn on all accessibility fixes (%d)', $off));
    echo '<table class="widefat striped"><tbody>';
    awd_render_performance_rows($state, 'accessibility');
    echo '</tbody></table></div>';
}

function awd_render_performance_rows(array $state, string $group): void
{
    foreach (awd_performance_measures() as $id => $measure) {
        if (($measure['group'] ?? 'speed') !== $group) continue;
        $entry = (array) ($state[$id] ?? array());
        $on = !empty($entry['enabled']);
        $status = !$on ? 'Off' : ((($entry['verified'] ?? null) === false) ? 'On, not effective' : 'On');
        echo '<tr><td><strong>' . esc_html($measure['title']) . '</strong><br><span class="description">' . esc_html($measure['description']) . ($on && !empty($entry['detail']) ? '<br>' . esc_html((string) $entry['detail']) : '') . '</span></td><td style="width:140px">' . esc_html($status) . '</td><td style="width:120px"><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('awd_performance');
        echo '<input type="hidden" name="action" value="awd_performance"><input type="hidden" name="measure" value="' . esc_attr($id) . '"><input type="hidden" name="state" value="' . ($on ? 'off' : 'on') . '"><button class="button' . ($on ? '' : ' button-primary') . '">' . ($on ? 'Turn off' : 'Turn on') . '</button></form></td></tr>';
    }
}

// ---- Runtime measures -------------------------------------------------------

if (function_exists('add_filter') && function_exists('get_option')) {
    // A new plugin version can change what the switched-on measures do to pages (0.9.1 stopped deferring
    // header scripts). Cached pages still carry the old markup, so purge them once after an upgrade.
    add_action('init', static function () {
        if (get_option('awd_runtime_version') === AWD_VERSION) return;
        update_option('awd_runtime_version', AWD_VERSION, true);
        $any = false;
        foreach (awd_performance_state() as $entry) if (!empty($entry['enabled'])) $any = true;
        if ($any && function_exists('awd_cleanup_op_purge_page_cache')) awd_cleanup_op_purge_page_cache(array(), array());
    }, 99);
    if (awd_performance_enabled('defer_scripts')) {
        add_action('wp_enqueue_scripts', static function () {
            if (is_admin() || is_customize_preview()) return;
            $scripts = wp_scripts();
            $keep = array('jquery', 'jquery-core', 'jquery-migrate', 'wp-hooks', 'wp-i18n', 'wp-polyfill', 'regenerator-runtime');
            foreach ((array) $scripts->queue as $handle) {
                if (in_array($handle, $keep, true) || !isset($scripts->registered[$handle]) || $scripts->get_data($handle, 'strategy')) continue;
                // Only footer scripts. Plugins often echo inline code into the page header that calls their
                // header script straight away (the Meta Pixel's FacebookSignal.init, for example); WordPress
                // cannot see that code, so deferring a header script breaks it on every page.
                if ((int) $scripts->get_data($handle, 'group') !== 1) continue;
                // WordPress (6.3+) downgrades this to blocking when a dependent or inline script needs the original order.
                $scripts->add_data($handle, 'strategy', 'defer');
            }
        }, PHP_INT_MAX);
    }
    if (awd_performance_enabled('font_display_swap')) {
        add_filter('style_loader_src', static function ($src) {
            if (is_string($src) && strpos($src, 'fonts.googleapis.com') !== false && strpos($src, 'display=') === false) $src = add_query_arg('display', 'swap', $src);
            return $src;
        });
        add_filter('wp_resource_hints', static function ($urls, $relation) {
            if ($relation === 'preconnect') $urls[] = array('href' => 'https://fonts.gstatic.com', 'crossorigin');
            return $urls;
        }, 10, 2);
    }
    if (awd_performance_enabled('trim_extras')) {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');
        add_filter('emoji_svg_url', '__return_false');
        add_action('wp_footer', static function () { wp_dequeue_script('wp-embed'); });
        add_action('wp_enqueue_scripts', static function () { if (!is_user_logged_in()) { wp_dequeue_style('dashicons'); } }, 100);
    }
    if (awd_performance_enabled('lazy_load')) {
        add_filter('wp_lazy_loading_enabled', '__return_true', 99);
    }
    if (awd_performance_enabled('webp_uploads')) {
        add_filter('image_editor_output_format', static function ($formats) {
            if (function_exists('wp_image_editor_supports') && wp_image_editor_supports(array('mime_type' => 'image/webp'))) {
                $formats['image/jpeg'] = 'image/webp';
                $formats['image/png'] = 'image/webp';
            }
            return $formats;
        });
    }
}
