<?php
/**
 * Install an owner-supplied plugin or theme zip (premium plugins, vendor
 * fixes) over the installed copy, safely:
 *  - from the app (install_package): the zip is downloaded in pieces with
 *    this site's signed credentials and must match the approved size and
 *    SHA-256; or from this plugin's admin page (upload form);
 *  - the zip must hold one folder with the installed plugin/theme's name,
 *    the same main file, and the expected version;
 *  - every PHP file is scanned with the integrity signatures: one strong
 *    malware match stops the install;
 *  - the installed copy moves into the quarantine first and comes back
 *    automatically if anything fails or the home page breaks afterwards.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('admin_post_awd_package_upload', 'awd_package_upload_from_admin');

/** Download an approved package from the central app into $destination. */
function awd_package_download(array $params, string $destination)
{
    $settings = get_option(AWD_OPTION, array());
    if (!is_array($settings)) return new WP_Error('awd_package_settings', 'This site is not connected to the central app.');
    $handle = @fopen($destination, 'xb');
    if (!$handle) return new WP_Error('awd_package_write', 'Could not create a temporary file for the package.');
    $chunks = (int) $params['chunks'];
    for ($index = 0; $index < $chunks; $index++) {
        $response = awd_authenticated_request($settings, '/packages/' . rawurlencode($params['packageId']) . '/' . $index, 'GET', array(), array('timeout' => 90, 'limit_response_size' => 4 * 1024 * 1024, 'headers' => array('Accept' => 'application/octet-stream')));
        if (is_wp_error($response)) { fclose($handle); @unlink($destination); return new WP_Error('awd_package_download', 'Downloading piece ' . ($index + 1) . ' of ' . $chunks . ' failed: ' . $response->get_error_message()); }
        $body = (string) wp_remote_retrieve_body($response);
        $expected_piece = (string) wp_remote_retrieve_header($response, 'x-awd-sha256');
        if ($expected_piece !== '' && !hash_equals($expected_piece, hash('sha256', $body))) { fclose($handle); @unlink($destination); return new WP_Error('awd_package_piece', 'Piece ' . ($index + 1) . ' arrived damaged.'); }
        fwrite($handle, $body);
    }
    fclose($handle);
    if ((string) filesize($destination) !== $params['size']) { @unlink($destination); return new WP_Error('awd_package_size', 'The downloaded package has the wrong size.'); }
    if (!hash_equals($params['sha256'], (string) hash_file('sha256', $destination))) { @unlink($destination); return new WP_Error('awd_package_hash', 'The downloaded package does not match the approved checksum.'); }
    return $destination;
}

/** Strong malware matches in a directory's PHP files (relative path => signatures). */
function awd_package_scan_dir(string $dir): array
{
    $hits = array();
    $weak = awd_integrity_weak_signatures();
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->isLink()) { $hits[awd_integrity_relative($file->getPathname(), $dir)] = array('symbolic_link'); continue; }
            if (!$file->isFile() || !awd_integrity_is_executable_name($file->getFilename())) continue;
            $matches = awd_integrity_scan_file($file->getPathname());
            if (array_diff($matches, $weak)) $hits[awd_integrity_relative($file->getPathname(), $dir)] = $matches;
            if (count($hits) >= 10) break;
        }
    } catch (Throwable $error) {
        $hits['(scan)'] = array('unreadable');
    }
    return $hits;
}

/**
 * Unpack, check and install $zip over the installed plugin (target "slug/file.php")
 * or theme (target "stylesheet"). Returns an awd_cleanup_result array.
 */
function awd_package_install_zip(string $zip, string $kind, string $target, string $expected_version, string $version, array $context): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $loaded = awd_plugin_load_upgrader();
    if (is_wp_error($loaded)) return awd_cleanup_result('failed', $loaded->get_error_message());
    $slug = $kind === 'plugin' ? dirname($target) : $target;
    if ($kind === 'plugin') {
        $plugins = get_plugins();
        if (!isset($plugins[$target])) return awd_cleanup_result('failed', 'The plugin is no longer installed.');
        $installed_version = (string) ($plugins[$target]['Version'] ?? '');
        $dir = rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $slug;
    } else {
        $theme = awd_theme_find($target);
        if (!$theme) return awd_cleanup_result('failed', 'The theme is no longer installed.');
        $installed_version = (string) $theme['version'];
        $dir = awd_theme_dir($target);
    }
    if ($expected_version !== 'none' && $installed_version !== $expected_version) return awd_cleanup_result('failed', 'The installed version changed after approval (now ' . $installed_version . ').');
    if (is_link($dir) || !is_dir($dir)) return awd_cleanup_result('failed', 'The installed directory is missing or is a symbolic link.');

    $work = $context['runDir'] . '/' . $context['index'] . '.package-new';
    $unzipped = unzip_file($zip, $work);
    if (is_wp_error($unzipped)) { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', 'The package could not be unpacked: ' . $unzipped->get_error_message()); }
    $entries = array_values(array_diff((array) scandir($work), array('.', '..', '__MACOSX')));
    if ($entries !== array($slug) || !is_dir($work . '/' . $slug)) { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', 'The zip must contain exactly one folder named "' . $slug . '".'); }
    $new_dir = $work . '/' . $slug;
    $main = $kind === 'plugin' ? $new_dir . '/' . basename($target) : $new_dir . '/style.css';
    if (!is_file($main)) { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', basename($main) . ' is missing from the package.'); }
    $headers = get_file_data($main, array('name' => $kind === 'plugin' ? 'Plugin Name' : 'Theme Name', 'version' => 'Version'));
    if ($headers['name'] === '') { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', 'The package\'s main file has no name header.'); }
    if ($version !== '' && $headers['version'] !== $version) { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', 'The package declares version ' . $headers['version'] . ', not the approved ' . $version . '.'); }
    $hits = awd_package_scan_dir($new_dir);
    if ($hits) { awd_cleanup_remove_tree($work); return awd_cleanup_result('failed', 'Malware patterns were found in the package (' . implode(', ', array_slice(array_keys($hits), 0, 3)) . '); nothing was installed. Download a fresh copy from the vendor.'); }

    $baseline = awd_plugin_site_health();
    $was_active = $kind === 'plugin' && is_plugin_active($target);
    $stored = $context['index'] . '.' . $kind;
    $GLOBALS['awd_cleanup_pending_move'] = array('dir' => $dir, 'stored' => $context['runDir'] . '/' . $stored);
    if (!awd_cleanup_move($dir, $context['runDir'] . '/' . $stored)) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        awd_cleanup_remove_tree($work);
        return awd_cleanup_result('failed', 'The installed files could not be moved into the quarantine (check file permissions). No change was made.');
    }
    $put_back = static function () use ($dir, $context, $stored) {
        unset($GLOBALS['awd_cleanup_pending_move']);
        if (is_dir($dir)) awd_cleanup_remove_tree($dir);
        return awd_cleanup_move($context['runDir'] . '/' . $stored, $dir);
    };
    if (!awd_cleanup_move($new_dir, $dir)) {
        $restored = $put_back();
        awd_cleanup_remove_tree($work);
        return awd_cleanup_result('failed', 'The new files could not be moved into place.' . ($restored ? ' The previous version was put back.' : ' Restore this run from the plugin.'));
    }
    awd_cleanup_remove_tree($work);
    if ($kind === 'plugin') {
        wp_clean_plugins_cache(false);
        if ($was_active && !is_plugin_active($target)) {
            $activated = activate_plugin($target, '', false, true);
            if (is_wp_error($activated)) {
                $restored = $put_back();
                return awd_cleanup_result('failed', 'The new version could not be activated: ' . $activated->get_error_message() . ($restored ? ' The previous version was put back.' : ''));
            }
        }
    } elseif (function_exists('wp_clean_themes_cache')) {
        wp_clean_themes_cache();
    }
    $after = awd_plugin_site_health();
    if ($baseline['ok'] && !$after['ok']) {
        $restored = $put_back();
        if ($was_active && !is_plugin_active($target)) activate_plugin($target, '', false, true);
        return awd_cleanup_result('failed', 'The site broke after the change (' . $after['reason'] . ').' . ($restored ? ' The previous version was put back automatically.' : ' Restore this run from the plugin.'));
    }
    unset($GLOBALS['awd_cleanup_pending_move']);
    $recovery = $kind === 'plugin'
        ? array('kind' => 'plugin', 'plugin' => $target, 'source' => $slug, 'stored' => $stored, 'versionBefore' => $installed_version, 'versionAfter' => $headers['version'], 'wasActive' => $was_active)
        : array('kind' => 'theme', 'source' => $slug, 'stored' => $stored, 'versionBefore' => $installed_version, 'versionAfter' => $headers['version']);
    return awd_cleanup_result('applied', sprintf('%s %s → %s installed from the uploaded package; no malware patterns were found and the site still loads.', $slug, $installed_version, $headers['version']), $recovery);
}

function awd_cleanup_op_install_package(array $params, array $context): array
{
    $zip = $context['localZip'] ?? null;
    if (!is_string($zip) || $zip === '') {
        $zip = $context['runDir'] . '/' . $context['index'] . '.package.zip';
        $downloaded = awd_package_download($params, $zip);
        if (is_wp_error($downloaded)) return awd_cleanup_result('failed', $downloaded->get_error_message() . ' No change was made.');
    }
    $result = awd_package_install_zip($zip, $params['kind'], $params['target'], $params['expectedVersion'], $params['version'], $context);
    @unlink($zip);
    return $result;
}

/** Upload form on this plugin's admin page: same checks, recorded as a run that can be restored. */
function awd_package_upload_from_admin(): void
{
    if (!current_user_can('install_plugins') || !current_user_can('update_plugins')) wp_die('Not allowed.');
    check_admin_referer('awd_package_upload');
    $target = sanitize_text_field(wp_unslash((string) ($_POST['target'] ?? '')));
    $kind = strpos($target, 'theme:') === 0 ? 'theme' : 'plugin';
    $target = $kind === 'theme' ? substr($target, 6) : $target;
    $valid = $kind === 'theme' ? awd_theme_slug_is_valid($target) : (bool) preg_match('#^[a-z0-9][a-z0-9-]{0,99}/[A-Za-z0-9._-]+\.php$#', $target);
    if (!$valid || strpos($target, 'ai-website-doctor') === 0) awd_redirect('Choose the plugin or theme to replace.', 'error');
    $file = $_FILES['package'] ?? null;
    if (!is_array($file) || (int) ($file['error'] ?? 1) !== 0 || !is_uploaded_file((string) $file['tmp_name'])) awd_redirect('The upload failed. Check the file size limit of this server (upload_max_filesize).', 'error');
    if (!preg_match('/\.zip$/i', (string) $file['name'])) awd_redirect('Upload a .zip file.', 'error');
    $quarantine = awd_cleanup_quarantine_dir();
    if (is_wp_error($quarantine)) awd_redirect($quarantine->get_error_message(), 'error');
    $zip = rtrim($quarantine, '/') . '/upload-' . wp_generate_password(12, false, false) . '.zip';
    if (!move_uploaded_file((string) $file['tmp_name'], $zip)) awd_redirect('The uploaded file could not be stored.', 'error');
    $run_id = 'local-' . strtolower(wp_generate_password(12, false, false));
    $step = array('description' => 'Install an uploaded package over ' . $target . '.', 'operation' => 'install_package', 'parameters' => array('packageId' => 'local', 'kind' => $kind, 'target' => $target, 'expectedVersion' => 'none', 'version' => '', 'sha256' => (string) hash_file('sha256', $zip), 'size' => (string) filesize($zip), 'chunks' => '1'));
    $results = awd_cleanup_execute_steps($run_id, 'local-upload', array($step), array('localZip' => $zip));
    @unlink($zip);
    $result = $results[0] ?? array('status' => 'failed', 'message' => 'Nothing happened.');
    awd_redirect((string) $result['message'] . ($result['status'] === 'applied' ? ' The previous version is in the Quarantine section if you need it back.' : ''), $result['status'] === 'applied' ? 'success' : 'error');
}

function awd_render_package_section(): void
{
    if (!current_user_can('install_plugins')) return;
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    echo '<div class="awd-card"><h2>Install a new version from a zip</h2><p>For premium plugins and themes, or a fixed version from the vendor. The zip is checked (same folder and main file, a version number) and every PHP file is scanned for malware before anything changes. The current version is kept in the quarantine and comes back automatically if the site breaks. The app can do the same from its Plugins &amp; themes tab.</p>';
    echo '<form method="post" enctype="multipart/form-data" action="' . esc_url(admin_url('admin-post.php')) . '">';
    wp_nonce_field('awd_package_upload');
    echo '<input type="hidden" name="action" value="awd_package_upload"><p><label>Replace <select name="target" required><option value="">Choose…</option><optgroup label="Plugins">';
    foreach (get_plugins() as $file => $plugin) {
        if (strpos($file, '/') === false || strpos($file, 'ai-website-doctor/') === 0) continue;
        echo '<option value="' . esc_attr($file) . '">' . esc_html($plugin['Name'] . ' ' . $plugin['Version']) . '</option>';
    }
    echo '</optgroup><optgroup label="Themes">';
    foreach (wp_get_themes() as $stylesheet => $theme) {
        echo '<option value="' . esc_attr('theme:' . $stylesheet) . '">' . esc_html($theme->get('Name') . ' ' . $theme->get('Version')) . '</option>';
    }
    echo '</optgroup></select></label> <input type="file" name="package" accept=".zip" required> <button class="button button-primary">Scan and install</button></p></form></div>';
}
