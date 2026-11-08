<?php
/**
 * WordPress.org plugin integrity and maintenance.
 *
 * - Integrity: compares each installed WordPress.org plugin with the official
 *   per-file checksums for its version, so tampered plugin code is detected.
 * - Operations (run through the approved cleanup/maintenance executor):
 *   update_plugin, reinstall_plugin and install_plugin. Packages come only
 *   from downloads.wordpress.org, every installed file is verified against
 *   the official checksums, and the site is loaded afterwards. If any check
 *   fails, the previous plugin directory is put back automatically.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_PLUGIN_INTEGRITY_OPTION', 'ai_website_doctor_plugin_integrity');
define('AWD_PLUGIN_INTEGRITY_BUDGET', 20.0);
define('AWD_PLUGIN_INTEGRITY_MAX_AGE', 6 * 3600);

function awd_plugin_slug(string $plugin_file): ?string
{
    $slug = dirname($plugin_file);
    return $slug !== '.' && preg_match('/^[a-z0-9][a-z0-9-]{0,99}$/', $slug) ? $slug : null;
}

/** Official checksums for one plugin version: relative path => list of accepted md5 values. */
function awd_plugin_official_checksums(string $slug, string $version)
{
    if (!preg_match('/^[a-z0-9][a-z0-9-]{0,99}$/', $slug) || !preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $version)) {
        return new WP_Error('awd_plugin_checksum_input', 'Invalid plugin slug or version.');
    }
    $url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json';
    $response = wp_remote_get($url, array('timeout' => 20, 'redirection' => 0, 'limit_response_size' => 8 * 1024 * 1024));
    if (is_wp_error($response)) return $response;
    $status = (int) wp_remote_retrieve_response_code($response);
    if ($status === 404) return new WP_Error('awd_plugin_not_wporg', 'WordPress.org has no checksums for ' . $slug . ' ' . $version . '.');
    if ($status !== 200) return new WP_Error('awd_plugin_checksum_fetch', 'WordPress.org returned HTTP ' . $status . ' for the ' . $slug . ' checksums.');
    $body = json_decode((string) wp_remote_retrieve_body($response), true);
    if (!is_array($body) || !isset($body['files']) || !is_array($body['files'])) return new WP_Error('awd_plugin_checksum_format', 'The WordPress.org checksum response was not understood.');
    $checksums = array();
    foreach ($body['files'] as $path => $hashes) {
        if (!is_string($path) || !is_array($hashes)) continue;
        $md5 = array_values(array_filter((array) ($hashes['md5'] ?? array()), static function ($value) { return is_string($value) && preg_match('/^[a-f0-9]{32}$/', $value); }));
        if ($md5) $checksums[$path] = $md5;
    }
    return $checksums ?: new WP_Error('awd_plugin_checksum_empty', 'WordPress.org returned no checksums for ' . $slug . ' ' . $version . '.');
}

/** Compare a plugin directory with official checksums. */
function awd_plugin_compare_directory(string $dir, array $checksums): array
{
    $modified = array();
    $missing = 0;
    foreach ($checksums as $relative => $accepted) {
        $path = $dir . '/' . $relative;
        if (!is_file($path)) { $missing++; continue; }
        if (!in_array((string) @md5_file($path), $accepted, true)) $modified[] = $relative;
    }
    $added = array();
    if (is_dir($dir)) {
        try {
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->isLink() || !$file->isFile() || !awd_integrity_is_executable_name($file->getFilename())) continue;
                $relative = ltrim(str_replace('\\', '/', substr($file->getPathname(), strlen($dir))), '/');
                if (!isset($checksums[$relative])) $added[] = $relative;
                if (count($added) >= 50) break;
            }
        } catch (Throwable $error) {
            // An unreadable subdirectory leaves the added-file list partial.
        }
    }
    return array('modified' => $modified, 'missing' => $missing, 'addedPhp' => $added);
}

/** Integrity of installed WordPress.org plugins, cached per plugin version. */
function awd_plugin_integrity_report(array $plugins, bool $force = false): array
{
    $cache = $force ? array() : (array) get_option(AWD_PLUGIN_INTEGRITY_OPTION, array());
    $deadline = microtime(true) + AWD_PLUGIN_INTEGRITY_BUDGET;
    $results = array();
    $fresh_cache = array();
    foreach ($plugins as $plugin) {
        if (!is_array($plugin) || ($plugin['source'] ?? '') !== 'wordpress.org') continue;
        $file = (string) ($plugin['file'] ?? '');
        $slug = awd_plugin_slug($file);
        $version = (string) ($plugin['version'] ?? '');
        if ($slug === null || $slug === 'ai-website-doctor') continue;
        $key = $slug . '@' . $version;
        if (isset($cache[$key]) && is_array($cache[$key]) && strtotime((string) ($cache[$key]['checkedAt'] ?? '')) > time() - AWD_PLUGIN_INTEGRITY_MAX_AGE) {
            $results[] = $cache[$key];
            $fresh_cache[$key] = $cache[$key];
            continue;
        }
        if (microtime(true) > $deadline) {
            $results[] = array('plugin' => $file, 'version' => $version, 'status' => 'not_checked', 'modified' => array(), 'addedPhp' => array(), 'missing' => 0, 'checkedAt' => gmdate('c'));
            continue;
        }
        $checksums = awd_plugin_official_checksums($slug, $version);
        if (is_wp_error($checksums)) {
            $result = array('plugin' => $file, 'version' => $version, 'status' => $checksums->get_error_code() === 'awd_plugin_not_wporg' ? 'no_checksums' : 'not_checked', 'modified' => array(), 'addedPhp' => array(), 'missing' => 0, 'checkedAt' => gmdate('c'));
        } else {
            $comparison = awd_plugin_compare_directory(rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $slug, $checksums);
            $result = array(
                'plugin' => $file,
                'version' => $version,
                'status' => $comparison['modified'] || $comparison['addedPhp'] ? 'modified' : 'verified',
                'modified' => array_slice($comparison['modified'], 0, 10),
                'addedPhp' => array_slice($comparison['addedPhp'], 0, 10),
                'missing' => (int) $comparison['missing'],
                'checkedAt' => gmdate('c'),
            );
        }
        $results[] = $result;
        if ($result['status'] !== 'not_checked') $fresh_cache[$key] = $result;
    }
    update_option(AWD_PLUGIN_INTEGRITY_OPTION, $fresh_cache, false);
    return array_slice($results, 0, 60);
}

function awd_plugin_integrity_issues(array $results): array
{
    $issues = array();
    foreach ($results as $result) {
        if (($result['status'] ?? '') !== 'modified') continue;
        $slug = awd_plugin_slug((string) $result['plugin']) ?? 'plugin';
        $files = array_merge((array) $result['modified'], array_map(static function ($path) { return $path . ' (added)'; }, (array) $result['addedPhp']));
        $issues[] = array(
            'fingerprint' => 'integrity:plugin-modified:' . substr($slug, 0, 70),
            'title' => 'Plugin code differs from the official release: ' . $slug . ' ' . (string) $result['version'],
            'description' => 'These files do not match the WordPress.org checksums for this version: ' . awd_integrity_list_preview($files) . '. Plugin code is never edited by WordPress itself; reinstall the plugin from WordPress.org.',
            'severity' => $result['addedPhp'] ? 'critical' : 'high',
        );
    }
    return $issues;
}

/** Load the home page through the site itself; used to detect an update that breaks the site. */
function awd_plugin_site_health(): array
{
    if (!function_exists('home_url')) return array('ok' => true, 'status' => null, 'reason' => 'unavailable');
    $response = wp_remote_get(add_query_arg('awd_health', (string) time(), home_url('/')), array(
        'timeout' => 20, 'redirection' => 3, 'sslverify' => apply_filters('https_local_ssl_verify', false), 'headers' => array('Cache-Control' => 'no-cache'),
    ));
    if (is_wp_error($response)) return array('ok' => false, 'status' => null, 'reason' => $response->get_error_message());
    $status = (int) wp_remote_retrieve_response_code($response);
    $body = (string) wp_remote_retrieve_body($response);
    $fatal = stripos($body, 'There has been a critical error') !== false || (bool) preg_match('/<b>(?:Fatal|Parse) error<\/b>/i', $body);
    return array('ok' => $status < 500 && !$fatal, 'status' => $status, 'reason' => $fatal ? 'PHP fatal error on the home page' : ($status >= 500 ? 'HTTP ' . $status : 'ok'));
}

function awd_plugin_load_upgrader()
{
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/misc.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    if (get_filesystem_method() !== 'direct') return new WP_Error('awd_filesystem', 'WordPress cannot write plugin files directly on this server (it would need FTP credentials); update the plugin from the Plugins screen instead.');
    if (!WP_Filesystem()) return new WP_Error('awd_filesystem', 'The WordPress filesystem could not be initialized.');
    return true;
}

/** Install a WordPress.org package into an empty plugin directory and verify every file. */
function awd_plugin_install_verified(string $slug, string $version, array $checksums)
{
    $loaded = awd_plugin_load_upgrader();
    if (is_wp_error($loaded)) return $loaded;
    $package = 'https://downloads.wordpress.org/plugin/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip';
    $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());
    $installed = $upgrader->install($package, array('overwrite_package' => false, 'clear_update_cache' => true));
    if (is_wp_error($installed)) return $installed;
    if ($installed !== true) {
        $errors = $upgrader->skin->get_errors();
        return new WP_Error('awd_plugin_install', is_wp_error($errors) && $errors->has_errors() ? $errors->get_error_message() : 'WordPress could not install the package.');
    }
    $dir = rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $slug;
    if (!is_dir($dir)) return new WP_Error('awd_plugin_install', 'The package did not install into the expected ' . $slug . ' directory.');
    $comparison = awd_plugin_compare_directory($dir, $checksums);
    if ($comparison['modified'] || $comparison['missing']) {
        return new WP_Error('awd_plugin_verify', sprintf('The installed files do not match the official checksums (%d modified, %d missing).', count($comparison['modified']), $comparison['missing']));
    }
    return $dir;
}

/**
 * Replace (update or reinstall) an installed WordPress.org plugin. The old
 * directory is moved into the run's quarantine first and moved back on any
 * failure, including a broken home page after the change.
 */
function awd_cleanup_op_replace_plugin(array $params, array $context, string $target_version): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $plugin = $params['plugin'];
    $slug = awd_plugin_slug($plugin);
    if ($slug === null || $slug === 'ai-website-doctor') return awd_cleanup_result('failed', 'Only WordPress.org plugins in their own directory can be updated this way.');
    $plugins = get_plugins();
    if (!isset($plugins[$plugin])) return awd_cleanup_result('skipped', 'The plugin is no longer installed.');
    $installed_version = (string) ($plugins[$plugin]['Version'] ?? '');
    if ($installed_version === $target_version && $params['operation'] === 'update_plugin') return awd_cleanup_result('skipped', 'The plugin is already at version ' . $target_version . '.');
    if ($installed_version !== $params['expectedVersion']) return awd_cleanup_result('failed', 'The installed version changed after approval (now ' . $installed_version . ').');
    $checksums = awd_plugin_official_checksums($slug, $target_version);
    if (is_wp_error($checksums)) return awd_cleanup_result('failed', $checksums->get_error_message() . ' No change was made.');
    $loaded = awd_plugin_load_upgrader();
    if (is_wp_error($loaded)) return awd_cleanup_result('failed', $loaded->get_error_message());
    $baseline = awd_plugin_site_health();
    $dir = rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $slug;
    if (is_link($dir) || !is_dir($dir)) return awd_cleanup_result('failed', 'The plugin directory is missing or is a symbolic link.');
    $was_active = is_plugin_active($plugin);
    $stored = $context['index'] . '.plugin';
    // If PHP dies before this step finishes (memory or time limit), the shutdown guard puts the original back.
    $GLOBALS['awd_cleanup_pending_move'] = array('dir' => $dir, 'stored' => $context['runDir'] . '/' . $stored);
    if (!awd_cleanup_move($dir, $context['runDir'] . '/' . $stored)) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        return awd_cleanup_result('failed', 'The current plugin files could not be moved into the quarantine (check file permissions). No change was made.');
    }
    $put_back = static function () use ($dir, $context, $stored) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        if (is_dir($dir)) awd_cleanup_remove_tree($dir);
        return awd_cleanup_move($context['runDir'] . '/' . $stored, $dir);
    };
    $installed = awd_plugin_install_verified($slug, $target_version, $checksums);
    if (is_wp_error($installed)) {
        $restored = $put_back();
        return awd_cleanup_result('failed', $installed->get_error_message() . ($restored ? ' The previous version was put back.' : ' The previous version could not be put back automatically; restore this run from the plugin.'));
    }
    $after = awd_plugin_site_health();
    if ($baseline['ok'] && !$after['ok']) {
        $restored = $put_back();
        return awd_cleanup_result('failed', 'The site broke after the change (' . $after['reason'] . ').' . ($restored ? ' The previous version was put back automatically.' : ' The previous version could not be put back; restore this run from the plugin.'));
    }
    unset($GLOBALS['awd_cleanup_pending_move']);
    if ($was_active && !is_plugin_active($plugin)) activate_plugin($plugin, '', false, true);
    return awd_cleanup_result('applied', sprintf('%s %s → %s installed from WordPress.org; all files match the official checksums and the site still loads.', $slug, $installed_version, $target_version), array(
        'plugin' => $plugin, 'source' => $slug, 'stored' => $stored, 'versionBefore' => $installed_version, 'versionAfter' => $target_version, 'wasActive' => $was_active,
    ));
}

function awd_cleanup_op_update_plugin(array $params, array $context): array
{
    return awd_cleanup_op_replace_plugin($params + array('operation' => 'update_plugin'), $context, $params['targetVersion']);
}

function awd_cleanup_op_reinstall_plugin(array $params, array $context): array
{
    return awd_cleanup_op_replace_plugin($params + array('operation' => 'reinstall_plugin'), $context, $params['expectedVersion']);
}

function awd_cleanup_op_install_plugin(array $params, array $context): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $slug = $params['slug'];
    $dir = rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $slug;
    if (file_exists($dir)) return awd_cleanup_result('skipped', 'A plugin directory named ' . $slug . ' already exists.');
    $checksums = awd_plugin_official_checksums($slug, $params['version']);
    if (is_wp_error($checksums)) return awd_cleanup_result('failed', $checksums->get_error_message());
    $baseline = awd_plugin_site_health();
    $installed = awd_plugin_install_verified($slug, $params['version'], $checksums);
    if (is_wp_error($installed)) {
        if (is_dir($dir)) awd_cleanup_remove_tree($dir);
        return awd_cleanup_result('failed', $installed->get_error_message());
    }
    $plugin_file = null;
    foreach (array_keys(get_plugins('/' . $slug)) as $file) { $plugin_file = $slug . '/' . $file; break; }
    if ($plugin_file === null) { awd_cleanup_remove_tree($dir); return awd_cleanup_result('failed', 'The installed package has no plugin header.'); }
    $recovery = array('slug' => $slug, 'plugin' => $plugin_file, 'activated' => false);
    if ($params['activate'] === 'yes') {
        $activated = activate_plugin($plugin_file, '', false, true);
        if (is_wp_error($activated)) {
            awd_cleanup_remove_tree($dir);
            return awd_cleanup_result('failed', 'The plugin could not be activated: ' . $activated->get_error_message() . ' It was removed again.');
        }
        $recovery['activated'] = true;
        $after = awd_plugin_site_health();
        if ($baseline['ok'] && !$after['ok']) {
            deactivate_plugins($plugin_file, true);
            awd_cleanup_remove_tree($dir);
            return awd_cleanup_result('failed', 'The site broke after activation (' . $after['reason'] . '); the plugin was removed again.');
        }
    }
    return awd_cleanup_result('applied', sprintf('Installed %s %s from WordPress.org%s; all files match the official checksums.', $slug, $params['version'], $recovery['activated'] ? ' and activated it' : ''), $recovery);
}

/** Undo a replace: put the previous version back if the plugin still has the version the run installed. */
function awd_plugin_restore_replace(array $recovery, string $dir_base, string $run_dir): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $plugins = get_plugins();
    $current = (string) ($plugins[(string) $recovery['plugin']]['Version'] ?? '');
    if ($current !== (string) $recovery['versionAfter']) return array('conflict', 'The plugin changed after the run (now ' . ($current ?: 'removed') . '); it was kept.');
    $dir = rtrim($dir_base, '/\\') . '/' . $recovery['source'];
    $aside = $run_dir . '/' . $recovery['stored'] . '.replaced-' . time();
    if (!awd_cleanup_move($dir, $aside)) return array('failed', 'The current plugin files could not be moved aside.');
    if (!awd_cleanup_move($run_dir . '/' . $recovery['stored'], $dir)) { awd_cleanup_move($aside, $dir); return array('failed', 'The previous version could not be moved back.'); }
    if (!empty($recovery['wasActive']) && !is_plugin_active((string) $recovery['plugin'])) activate_plugin((string) $recovery['plugin'], '', false, true);
    return array('restored', 'Version ' . $recovery['versionBefore'] . ' was put back.');
}

function awd_plugin_restore_install(array $recovery, string $dir_base, string $run_dir): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $dir = rtrim($dir_base, '/\\') . '/' . $recovery['slug'];
    if (!is_dir($dir)) return array('conflict', 'The plugin was already removed.');
    if (!empty($recovery['activated'])) deactivate_plugins((string) $recovery['plugin'], true);
    if (!awd_cleanup_move($dir, $run_dir . '/installed-' . $recovery['slug'])) return array('failed', 'The installed plugin could not be moved into the quarantine.');
    return array('restored', 'The installed plugin was deactivated and moved into the quarantine.');
}
