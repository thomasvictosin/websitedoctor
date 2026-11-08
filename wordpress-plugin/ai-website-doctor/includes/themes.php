<?php
/**
 * Theme coverage: inventory and updates, integrity, and maintenance.
 *
 * - Inventory: every installed theme with version, parent, active state,
 *   whether WordPress.org hosts it, and any available update.
 * - Integrity: WordPress.org publishes no per-file theme checksums, so the
 *   active theme and its parent (when hosted on WordPress.org) are compared
 *   file by file with the official package for their exact version. Every
 *   installed theme, including premium and custom ones, has all its PHP files
 *   scanned for malware patterns.
 * - Operations (approved executor): update_theme, reinstall_theme (from
 *   downloads.wordpress.org, previous directory kept in the quarantine and
 *   put back automatically if the site breaks), quarantine_theme (only
 *   inactive themes that are not the active theme's parent) and
 *   quarantine_theme_file (one file with a matching digest).
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_THEME_INTEGRITY_OPTION', 'ai_website_doctor_theme_integrity');
define('AWD_THEME_INTEGRITY_MAX_AGE', 6 * 3600);
define('AWD_THEME_SCAN_BUDGET', 15.0);

function awd_theme_slug_is_valid(string $slug): bool
{
    return (bool) preg_match('/^[a-z0-9][a-z0-9_-]{0,99}$/', $slug);
}

/** Installed themes with update and source information. */
function awd_theme_inventory(): array
{
    if (!function_exists('wp_get_themes')) return array();
    $updates = get_site_transient('update_themes');
    $response = is_object($updates) && isset($updates->response) && is_array($updates->response) ? $updates->response : array();
    $current = is_object($updates) && isset($updates->no_update) && is_array($updates->no_update) ? $updates->no_update : array();
    $active = function_exists('get_stylesheet') ? (string) get_stylesheet() : '';
    $active_parent = function_exists('get_template') ? (string) get_template() : '';
    $themes = array();
    foreach (wp_get_themes() as $stylesheet => $theme) {
        $stylesheet = (string) $stylesheet;
        $update = isset($response[$stylesheet]) ? (array) $response[$stylesheet] : null;
        $known = $update ?? (isset($current[$stylesheet]) ? (array) $current[$stylesheet] : null);
        $package = is_array($known) ? (string) ($known['package'] ?? '') : '';
        $entry = array(
            'stylesheet' => substr(sanitize_key($stylesheet), 0, 100),
            'name' => substr(sanitize_text_field((string) $theme->get('Name')), 0, 200),
            'version' => substr(sanitize_text_field((string) $theme->get('Version')), 0, 40),
            'parent' => $theme->get_template() !== $stylesheet ? substr(sanitize_key((string) $theme->get_template()), 0, 100) : null,
            'active' => $stylesheet === $active,
            'parentOfActive' => $stylesheet === $active_parent && $stylesheet !== $active,
            'updateAvailable' => $update !== null,
            'source' => $known !== null && ($package === '' || str_starts_with($package, 'https://downloads.wordpress.org/theme/')) ? 'wordpress.org' : 'other',
        );
        if ($update !== null && preg_match('/^[0-9A-Za-z.+-]{1,40}$/', (string) ($update['new_version'] ?? ''))) $entry['newVersion'] = (string) $update['new_version'];
        $themes[] = $entry;
    }
    return array_slice($themes, 0, 50);
}

function awd_theme_dir(string $stylesheet): string
{
    $root = function_exists('get_theme_root') ? (string) get_theme_root($stylesheet) : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/themes' : ABSPATH . 'wp-content/themes');
    return rtrim($root, '/\\') . '/' . $stylesheet;
}

/** md5 of every file in the official WordPress.org package for this theme version (relative path => md5). */
function awd_theme_official_files(string $slug, string $version)
{
    if (!awd_theme_slug_is_valid($slug) || !preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $version)) return new WP_Error('awd_theme_input', 'Invalid theme slug or version.');
    if (!class_exists('ZipArchive')) return new WP_Error('awd_theme_zip', 'PHP ZipArchive is not available, so the theme cannot be compared with the official package.');
    if (!function_exists('download_url')) require_once ABSPATH . 'wp-admin/includes/file.php';
    $file = download_url('https://downloads.wordpress.org/theme/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip', 60);
    if (is_wp_error($file)) return $file;
    $zip = new ZipArchive();
    if ($zip->open($file) !== true) { @unlink($file); return new WP_Error('awd_theme_zip', 'The official theme package could not be opened.'); }
    $files = array();
    $prefix = $slug . '/';
    for ($index = 0; $index < $zip->numFiles; $index++) {
        $name = (string) $zip->getNameIndex($index);
        if (substr($name, -1) === '/' || strpos($name, $prefix) !== 0) continue;
        $content = $zip->getFromIndex($index);
        if ($content !== false) $files[substr($name, strlen($prefix))] = md5($content);
    }
    $zip->close();
    @unlink($file);
    return $files ?: new WP_Error('awd_theme_zip', 'The official theme package was empty.');
}

/** Compare a theme directory with the official package listing. */
function awd_theme_compare(string $dir, array $official): array
{
    $modified = array();
    $missing = 0;
    foreach ($official as $relative => $md5) {
        $path = $dir . '/' . $relative;
        if (!is_file($path)) { $missing++; continue; }
        if ((string) @md5_file($path) !== $md5) $modified[] = $relative;
    }
    $added = array();
    foreach (awd_theme_php_files($dir, microtime(true) + 10, 5000) as $path) {
        $relative = ltrim(str_replace('\\', '/', substr($path, strlen($dir))), '/');
        if (!isset($official[$relative])) $added[] = $relative;
        if (count($added) >= 50) break;
    }
    return array('modified' => $modified, 'missing' => $missing, 'addedPhp' => $added);
}

/** PHP files beneath a theme (bounded, no symlinks). */
function awd_theme_php_files(string $dir, float $deadline, int $limit): array
{
    $files = array();
    if (!is_dir($dir) || is_link($dir)) return $files;
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (microtime(true) > $deadline || count($files) >= $limit) break;
            if ($file->isLink() || !$file->isFile() || !awd_integrity_is_executable_name($file->getFilename())) continue;
            $files[] = $file->getPathname();
        }
    } catch (Throwable $error) {
        // An unreadable directory leaves the list partial.
    }
    return $files;
}

/**
 * Per-theme integrity: official-package comparison for the active theme and
 * its parent when they come from WordPress.org, and a malware-pattern scan of
 * every installed theme's PHP files.
 */
function awd_theme_integrity_report(array $themes, bool $force = false): array
{
    $cache = $force ? array() : (array) get_option(AWD_THEME_INTEGRITY_OPTION, array());
    $fresh = array();
    $deadline = microtime(true) + AWD_THEME_SCAN_BUDGET;
    $results = array();
    foreach ($themes as $theme) {
        if (!is_array($theme) || !awd_theme_slug_is_valid((string) ($theme['stylesheet'] ?? ''))) continue;
        $slug = (string) $theme['stylesheet'];
        $version = (string) ($theme['version'] ?? '');
        $dir = awd_theme_dir($slug);
        $key = $slug . '@' . $version;
        if (isset($cache[$key]) && strtotime((string) ($cache[$key]['checkedAt'] ?? '')) > time() - AWD_THEME_INTEGRITY_MAX_AGE) {
            $results[] = $cache[$key];
            $fresh[$key] = $cache[$key];
            continue;
        }
        $result = array('stylesheet' => $slug, 'version' => $version, 'status' => 'not_checked', 'modified' => array(), 'addedPhp' => array(), 'suspicious' => array(), 'checkedAt' => gmdate('c'));
        if (microtime(true) < $deadline) {
            $suspicious = array();
            foreach (awd_theme_php_files($dir, $deadline, 3000) as $path) {
                $signatures = awd_integrity_scan_file($path);
                if ($signatures) $suspicious[] = array('path' => ltrim(str_replace('\\', '/', substr($path, strlen($dir))), '/'), 'signatures' => $signatures, 'sha256' => (string) hash_file('sha256', $path));
                if (count($suspicious) >= 20) break;
            }
            $result['suspicious'] = $suspicious;
            $result['status'] = $suspicious ? 'suspicious' : 'scanned';
            $compare = ($theme['source'] ?? '') === 'wordpress.org' && (!empty($theme['active']) || !empty($theme['parentOfActive']));
            if ($compare) {
                $official = awd_theme_official_files($slug, $version);
                if (is_wp_error($official)) {
                    $result['officialCheck'] = 'unavailable';
                } else {
                    $comparison = awd_theme_compare($dir, $official);
                    $result['officialCheck'] = $comparison['modified'] || $comparison['addedPhp'] ? 'modified' : 'verified';
                    $result['modified'] = array_slice($comparison['modified'], 0, 10);
                    $result['addedPhp'] = array_slice($comparison['addedPhp'], 0, 10);
                    if ($result['officialCheck'] === 'modified') $result['status'] = 'modified';
                }
            }
            $fresh[$key] = $result;
        }
        $results[] = $result;
    }
    update_option(AWD_THEME_INTEGRITY_OPTION, $fresh, false);
    return array_slice($results, 0, 50);
}

/** Issues from the theme inventory and integrity results. */
function awd_theme_issues(array $themes, array $integrity): array
{
    $issues = array();
    foreach ($integrity as $result) {
        if (!is_array($result)) continue;
        $slug = (string) $result['stylesheet'];
        if (($result['status'] ?? '') === 'modified') {
            $files = array_merge((array) $result['modified'], array_map(static function ($path) { return $path . ' (added)'; }, (array) $result['addedPhp']));
            $issues[] = array('fingerprint' => 'integrity:theme-modified:' . substr($slug, 0, 70), 'title' => 'Theme files differ from the official release: ' . $slug . ' ' . (string) $result['version'], 'description' => 'These files do not match the official WordPress.org package for this version: ' . awd_integrity_list_preview($files) . '. Reinstall the theme from WordPress.org.', 'severity' => $result['addedPhp'] ? 'critical' : 'high');
        }
        if (!empty($result['suspicious'])) {
            $issues[] = array('fingerprint' => 'integrity:theme-malware:' . substr($slug, 0, 70), 'title' => sprintf('Malware code patterns in the %s theme (%d file(s))', $slug, count($result['suspicious'])), 'description' => 'Code patterns used by backdoors and SEO-spam loaders were found in: ' . awd_integrity_list_preview(array_map(static function ($item) { return $item['path'] . ' [' . implode(', ', $item['signatures']) . ']'; }, (array) $result['suspicious'])) . '. Premium themes sometimes contain obfuscated licence code; check each file, and reinstall the theme from its vendor if in doubt.', 'severity' => 'critical');
        }
    }
    $unused = array_filter($themes, static function ($theme) { return empty($theme['active']) && empty($theme['parentOfActive']); });
    if (count($unused) > 1) {
        $issues[] = array('fingerprint' => 'integrity:unused-themes', 'title' => sprintf('%d unused themes are installed', count($unused)), 'description' => 'Inactive themes still contain code an attacker can use: ' . awd_integrity_list_preview(array_column($unused, 'stylesheet')) . '. Keep at most one default theme as a fallback and remove the rest.', 'severity' => 'low');
    }
    foreach ($themes as $theme) {
        if (empty($theme['updateAvailable'])) continue;
        $issues[] = array('fingerprint' => 'theme-update:' . substr(hash('sha256', (string) $theme['stylesheet']), 0, 20), 'title' => 'Theme update available: ' . (string) $theme['name'], 'description' => sprintf('%s %s can be updated%s. %s', (string) $theme['name'], (string) $theme['version'], isset($theme['newVersion']) ? ' to ' . $theme['newVersion'] : '', !empty($theme['active']) ? 'This is the active theme.' : (!empty($theme['parentOfActive']) ? 'This is the parent of the active theme.' : 'This theme is not active.')), 'severity' => !empty($theme['active']) || !empty($theme['parentOfActive']) ? 'medium' : 'low');
    }
    return $issues;
}

// ---- Operations -----------------------------------------------------------

function awd_theme_find(string $stylesheet): ?array
{
    foreach (awd_theme_inventory() as $theme) if ($theme['stylesheet'] === $stylesheet) return $theme;
    return null;
}

function awd_theme_load_upgrader()
{
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/misc.php';
    require_once ABSPATH . 'wp-admin/includes/theme.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    if (get_filesystem_method() !== 'direct') return new WP_Error('awd_filesystem', 'WordPress cannot write theme files directly on this server (it would need FTP credentials); update the theme from Appearance → Themes instead.');
    if (!WP_Filesystem()) return new WP_Error('awd_filesystem', 'The WordPress filesystem could not be initialized.');
    return true;
}

/** Replace (update or reinstall) a WordPress.org theme; the previous directory is put back on any failure. */
function awd_cleanup_op_replace_theme(array $params, array $context, string $target_version): array
{
    $slug = $params['stylesheet'];
    $theme = awd_theme_find($slug);
    if (!$theme) return awd_cleanup_result('skipped', 'The theme is no longer installed.');
    if ($theme['source'] !== 'wordpress.org') return awd_cleanup_result('failed', 'This theme is not hosted on WordPress.org; update it from its vendor.');
    if ($theme['version'] !== $params['expectedVersion']) return awd_cleanup_result('failed', 'The installed theme version changed after approval (now ' . $theme['version'] . ').');
    if ($theme['version'] === $target_version && isset($params['targetVersion'])) return awd_cleanup_result('skipped', 'The theme is already at version ' . $target_version . '.');
    $official = awd_theme_official_files($slug, $target_version);
    if (is_wp_error($official)) return awd_cleanup_result('failed', $official->get_error_message() . ' No change was made.');
    $loaded = awd_theme_load_upgrader();
    if (is_wp_error($loaded)) return awd_cleanup_result('failed', $loaded->get_error_message());
    $baseline = awd_plugin_site_health();
    $dir = awd_theme_dir($slug);
    if (is_link($dir) || !is_dir($dir)) return awd_cleanup_result('failed', 'The theme directory is missing or is a symbolic link.');
    $stored = $context['index'] . '.theme';
    $GLOBALS['awd_cleanup_pending_move'] = array('dir' => $dir, 'stored' => $context['runDir'] . '/' . $stored);
    if (!awd_cleanup_move($dir, $context['runDir'] . '/' . $stored)) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        return awd_cleanup_result('failed', 'The current theme files could not be moved into the quarantine (check file permissions). No change was made.');
    }
    $put_back = static function () use ($dir, $context, $stored) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        if (is_dir($dir)) awd_cleanup_remove_tree($dir);
        return awd_cleanup_move($context['runDir'] . '/' . $stored, $dir);
    };
    $upgrader = new Theme_Upgrader(new Automatic_Upgrader_Skin());
    $installed = $upgrader->install('https://downloads.wordpress.org/theme/' . rawurlencode($slug) . '.' . rawurlencode($target_version) . '.zip', array('overwrite_package' => false, 'clear_update_cache' => true));
    if ($installed !== true || !is_dir($dir)) {
        $restored = $put_back();
        return awd_cleanup_result('failed', 'WordPress could not install the official package.' . ($restored ? ' The previous version was put back.' : ' Restore this run from the plugin.'));
    }
    $comparison = awd_theme_compare($dir, $official);
    if ($comparison['modified'] || $comparison['missing']) {
        $restored = $put_back();
        return awd_cleanup_result('failed', 'The installed theme does not match the official package.' . ($restored ? ' The previous version was put back.' : ''));
    }
    $after = awd_plugin_site_health();
    if ($baseline['ok'] && !$after['ok']) {
        $restored = $put_back();
        return awd_cleanup_result('failed', 'The site broke after the change (' . $after['reason'] . ').' . ($restored ? ' The previous version was put back automatically.' : ' Restore this run from the plugin.'));
    }
    unset($GLOBALS['awd_cleanup_pending_move']);
    return awd_cleanup_result('applied', sprintf('%s %s → %s installed from WordPress.org; every file matches the official package and the site still loads.', $slug, $theme['version'], $target_version), array(
        'kind' => 'theme', 'source' => $slug, 'stored' => $stored, 'versionBefore' => $theme['version'], 'versionAfter' => $target_version,
    ));
}

function awd_cleanup_op_update_theme(array $params, array $context): array
{
    return awd_cleanup_op_replace_theme($params, $context, $params['targetVersion']);
}

function awd_cleanup_op_reinstall_theme(array $params, array $context): array
{
    return awd_cleanup_op_replace_theme($params, $context, $params['expectedVersion']);
}

/** Move an unused theme into the quarantine (never the active theme or its parent). */
function awd_cleanup_op_quarantine_theme(array $params, array $context): array
{
    $theme = awd_theme_find($params['stylesheet']);
    if (!$theme) return awd_cleanup_result('skipped', 'The theme is no longer installed.');
    if (!empty($theme['active']) || !empty($theme['parentOfActive'])) return awd_cleanup_result('failed', 'The active theme and its parent are never removed.');
    if ($theme['version'] !== $params['expectedVersion']) return awd_cleanup_result('failed', 'The theme version changed after approval.');
    $dir = awd_theme_dir($params['stylesheet']);
    if (is_link($dir) || !is_dir($dir)) return awd_cleanup_result('failed', 'The theme directory is missing or is a symbolic link.');
    $stored = $context['index'] . '.theme';
    if (!awd_cleanup_move($dir, $context['runDir'] . '/' . $stored)) return awd_cleanup_result('failed', 'The theme could not be moved into the quarantine (check file permissions).');
    if (function_exists('wp_clean_themes_cache')) wp_clean_themes_cache();
    return awd_cleanup_result('applied', 'Moved the unused theme into the quarantine.', array('kind' => 'theme_removed', 'source' => $params['stylesheet'], 'stored' => $stored));
}

/** Quarantine one file inside a theme (for premium/custom themes that cannot be reinstalled from WordPress.org). */
function awd_cleanup_op_quarantine_theme_file(array $params, array $context): array
{
    $dir = awd_theme_dir($params['stylesheet']);
    $root = rtrim(str_replace('\\', '/', (string) realpath($dir)), '/') . '/';
    if ($root === '/' || !is_dir($dir)) return awd_cleanup_result('skipped', 'The theme is no longer installed.');
    $path = awd_cleanup_resolve($params['path'], $root);
    if ($path === null || !is_file($path)) return awd_cleanup_result('skipped', 'The file no longer exists or is outside the theme.');
    if (in_array($params['path'], array('style.css', 'functions.php', 'index.php'), true)) return awd_cleanup_result('failed', 'Required theme files are not quarantined; reinstall the theme from its vendor instead.');
    if (!hash_equals($params['expectedSha256'], (string) hash_file('sha256', $path))) return awd_cleanup_result('failed', 'The file changed after approval; it was left in place.');
    $stored = $context['index'] . '.bin';
    if (!awd_cleanup_move($path, $context['runDir'] . '/' . $stored)) return awd_cleanup_result('failed', 'The file could not be moved into the quarantine.');
    return awd_cleanup_result('applied', 'Moved to quarantine.', array('kind' => 'theme_file', 'theme' => $params['stylesheet'], 'path' => $params['path'], 'stored' => $stored));
}

/** Undo a theme operation if nothing changed it since. */
function awd_theme_restore(array $step, array $recovery, string $run_dir): array
{
    $kind = (string) ($recovery['kind'] ?? '');
    if ($kind === 'theme_file') {
        $dir = awd_theme_dir((string) $recovery['theme']);
        $target = $dir . '/' . $recovery['path'];
        if (file_exists($target)) return array('conflict', 'A file now exists at the original path; it was kept.');
        return awd_cleanup_move($run_dir . '/' . $recovery['stored'], $target) ? array('restored', 'Restored.') : array('failed', 'The file could not be moved back.');
    }
    $dir = awd_theme_dir((string) $recovery['source']);
    if ($kind === 'theme_removed') {
        if (file_exists($dir)) return array('conflict', 'The theme was reinstalled since; the current copy was kept.');
        return awd_cleanup_move($run_dir . '/' . $recovery['stored'], $dir) ? array('restored', 'The theme was moved back.') : array('failed', 'The theme could not be moved back.');
    }
    $theme = awd_theme_find((string) $recovery['source']);
    if (!$theme || $theme['version'] !== (string) $recovery['versionAfter']) return array('conflict', 'The theme changed after the run; it was kept.');
    $aside = $run_dir . '/' . $recovery['stored'] . '.replaced-' . time();
    if (!awd_cleanup_move($dir, $aside)) return array('failed', 'The current theme files could not be moved aside.');
    if (!awd_cleanup_move($run_dir . '/' . $recovery['stored'], $dir)) { awd_cleanup_move($aside, $dir); return array('failed', 'The previous version could not be moved back.'); }
    return array('restored', 'Version ' . $recovery['versionBefore'] . ' was put back.');
}
