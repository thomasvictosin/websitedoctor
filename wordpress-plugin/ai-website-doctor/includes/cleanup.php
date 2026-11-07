<?php
/**
 * Compromise cleanup executor.
 *
 * Runs a cleanup playbook approved in the central app (or by a local
 * administrator) as an ordered list of allowlisted operations. Each operation:
 *   1. re-validates its exact target (path confinement, content digest) just
 *      before changing it,
 *   2. stores everything needed to undo it in a private quarantine directory,
 *   3. changes the site through a temp-file-and-rename write or a WordPress API,
 *   4. verifies the result.
 * Quarantined files are moved, not deleted, and kept until an explicitly
 * approved purge_quarantine step. Restoring a run reverses its steps only
 * where the target still has the state the cleanup left, so later edits are
 * never overwritten.
 *
 * There is no code, SQL, shell, or arbitrary-path operation here.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_CLEANUP_OPTION', 'ai_website_doctor_cleanup_runs');
define('AWD_CLEANUP_DIR_OPTION', 'ai_website_doctor_quarantine_dir');
define('AWD_CLEANUP_MAX_STEPS', 120);
define('AWD_CLEANUP_STEP_BUDGET_SECONDS', 150);
define('AWD_CLEANUP_MAX_RUNS', 10);
define('AWD_CLEANUP_SALT_KEYS', 'AUTH_KEY,SECURE_AUTH_KEY,LOGGED_IN_KEY,NONCE_KEY,AUTH_SALT,SECURE_AUTH_SALT,LOGGED_IN_SALT,NONCE_SALT');

add_action('admin_post_awd_cleanup_run', 'awd_cleanup_run_from_admin');
add_action('admin_post_awd_cleanup_restore', 'awd_cleanup_restore_from_admin');
add_action('admin_post_awd_fix_issue', 'awd_fix_issue_from_admin');

function awd_cleanup_operations(): array
{
    return array('quarantine_file', 'restore_core_file', 'remove_htaccess_rules', 'quarantine_plugin', 'demote_user', 'rotate_salts', 'purge_page_cache', 'purge_quarantine', 'update_plugin', 'reinstall_plugin', 'install_plugin', 'set_hardening');
}

function awd_cleanup_root(): string
{
    $real = realpath(ABSPATH);
    return rtrim(str_replace('\\', '/', $real !== false ? $real : ABSPATH), '/') . '/';
}

function awd_cleanup_relative_path_is_valid(string $path): bool
{
    return $path !== '' && strlen($path) <= 300 && strpos($path, "\0") === false && strpos($path, '\\') === false
        && $path[0] !== '/' && !preg_match('#(^|/)\.\.?(/|$)#', $path)
        && (bool) preg_match('#^[A-Za-z0-9._@+\- /]+$#', $path);
}

/** Absolute path for a relative target, or null when it escapes the root or crosses a symlink. */
function awd_cleanup_resolve(string $relative, string $root): ?string
{
    if (!awd_cleanup_relative_path_is_valid($relative)) return null;
    $current = rtrim($root, '/');
    foreach (explode('/', $relative) as $component) {
        $current .= '/' . $component;
        if (is_link($current)) return null;
    }
    $parent = realpath(dirname($current));
    if ($parent === false) return null;
    $parent = rtrim(str_replace('\\', '/', $parent), '/') . '/';
    return strpos($parent, $root) === 0 ? $current : null;
}

function awd_cleanup_uploads_relative(string $root): string
{
    $uploads = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : array();
    $base = is_array($uploads) && !empty($uploads['basedir']) ? (string) $uploads['basedir'] : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : $root . 'wp-content') . '/uploads';
    return trim(awd_integrity_relative($base, $root), '/') . '/';
}

/**
 * Whether a file may be quarantined. Core files are restored instead; plugin
 * and theme code is handled by reinstalling or by quarantine_plugin.
 */
function awd_cleanup_quarantine_denial(string $relative, string $root, ?array $checksums): ?string
{
    if (is_array($checksums) && isset($checksums[$relative])) return 'This is a WordPress core file; restore it with restore_core_file instead.';
    if (in_array($relative, array('wp-config.php', '.htaccess', 'wp-settings.php', 'wp-load.php', 'index.php'), true)) return 'This file is required by WordPress and cannot be quarantined.';
    $content = trim(awd_integrity_relative(defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : $root . 'wp-content', $root), '/') . '/';
    $uploads = awd_cleanup_uploads_relative($root);
    $mu = trim(awd_integrity_relative(defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : $content . 'mu-plugins', $root), '/') . '/';
    $quarantine = (string) get_option(AWD_CLEANUP_DIR_OPTION, '');
    if ($quarantine !== '' && strpos($root . $relative, rtrim($quarantine, '/') . '/') === 0) return 'Files inside the quarantine cannot be quarantined again.';
    if (strpos($relative, $content . 'plugins/') === 0 || strpos($relative, $content . 'themes/') === 0) return 'Plugin and theme files are restored by reinstalling the component, not by quarantining single files.';
    if (strpos($relative, '/') === false) return null;
    $executable = awd_integrity_is_executable_name($relative);
    if ((strpos($relative, 'wp-admin/') === 0 || strpos($relative, 'wp-includes/') === 0) && $executable) return null;
    if (strpos($relative, $uploads) === 0 && $executable) return null;
    if (strpos($relative, $mu) === 0) return null;
    if (strpos($relative, $content) === 0 && substr_count(substr($relative, strlen($content)), '/') === 0 && $executable) return null;
    return 'Only unknown files in the site root, executable files in wp-admin, wp-includes, uploads or directly in wp-content, and must-use plugins can be quarantined.';
}

/** Validate a step's shape and parameters (central validation is repeated here, never trusted). */
function awd_cleanup_step_is_valid($step): bool
{
    if (!is_array($step) || array_diff(array_keys($step), array('description', 'operation', 'parameters')) !== array()
        || !isset($step['operation'], $step['parameters']) || !is_string($step['operation']) || !is_array($step['parameters'])
        || !in_array($step['operation'], awd_cleanup_operations(), true)) return false;
    if (isset($step['description']) && (!is_string($step['description']) || strlen($step['description']) > 500)) return false;
    $params = $step['parameters'];
    foreach ($params as $key => $value) {
        if (!is_string($key) || !is_string($value) || strlen($value) > 500) return false;
    }
    $keys = array_keys($params);
    sort($keys);
    $sha = static function ($value) { return is_string($value) && (bool) preg_match('/^[a-f0-9]{64}$/', $value); };
    switch ($step['operation']) {
        case 'quarantine_file':
            return $keys === array('expectedSha256', 'path') && awd_cleanup_relative_path_is_valid($params['path']) && $sha($params['expectedSha256']);
        case 'restore_core_file':
            return $keys === array('expectedCurrentSha256', 'officialMd5', 'path') && awd_cleanup_relative_path_is_valid($params['path'])
                && (bool) preg_match('/^[a-f0-9]{32}$/', $params['officialMd5'])
                && ($params['expectedCurrentSha256'] === 'missing' || $sha($params['expectedCurrentSha256']));
        case 'remove_htaccess_rules':
            return $keys === array('expectedSha256', 'lines') && $sha($params['expectedSha256']) && (bool) preg_match('/^[1-9][0-9]{0,5}(,[1-9][0-9]{0,5}){0,9}$/', $params['lines']);
        case 'quarantine_plugin':
            return $keys === array('expectedVersion', 'plugin') && (bool) preg_match('/^(?!\/)(?!.*(?:^|\/)\.\.?\/)[a-z0-9._\/-]+\.php$/i', $params['plugin'])
                && strpos($params['plugin'], 'ai-website-doctor/') !== 0 && strlen($params['expectedVersion']) <= 40;
        case 'demote_user':
            return $keys === array('expectedRole', 'login') && $params['expectedRole'] === 'administrator' && (bool) preg_match('/^[A-Za-z0-9._@ -]{1,60}$/', $params['login']);
        case 'rotate_salts':
        case 'purge_page_cache':
            return $keys === array();
        case 'purge_quarantine':
            return $keys === array('runId') && (bool) preg_match('/^[a-z0-9-]{8,64}$/', $params['runId']);
        case 'update_plugin':
            return $keys === array('expectedVersion', 'plugin', 'targetVersion') && awd_plugin_slug($params['plugin']) !== null
                && strpos($params['plugin'], 'ai-website-doctor/') !== 0 && (bool) preg_match('#^[a-z0-9-]+/[A-Za-z0-9._-]+\.php$#', $params['plugin'])
                && (bool) preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $params['expectedVersion']) && (bool) preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $params['targetVersion']);
        case 'reinstall_plugin':
            return $keys === array('expectedVersion', 'plugin') && awd_plugin_slug($params['plugin']) !== null
                && strpos($params['plugin'], 'ai-website-doctor/') !== 0 && (bool) preg_match('#^[a-z0-9-]+/[A-Za-z0-9._-]+\.php$#', $params['plugin'])
                && (bool) preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $params['expectedVersion']);
        case 'set_hardening':
            return $keys === array('measure', 'state') && in_array($params['state'], array('on', 'off'), true)
                && function_exists('awd_hardening_measures') && array_key_exists($params['measure'], awd_hardening_measures());
        case 'install_plugin':
            return $keys === array('activate', 'slug', 'version') && (bool) preg_match('/^[a-z0-9][a-z0-9-]{0,99}$/', $params['slug']) && $params['slug'] !== 'ai-website-doctor'
                && (bool) preg_match('/^[0-9A-Za-z.+-]{1,40}$/', $params['version']) && in_array($params['activate'], array('yes', 'no'), true);
    }
    return false;
}

function awd_cleanup_task_is_valid($task): bool
{
    if (!is_array($task) || empty($task['repairId']) || !is_string($task['repairId']) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $task['repairId'])
        || empty($task['authorizationGrantId']) || !is_string($task['authorizationGrantId'])
        || empty($task['authorizationExpiresAt']) || strtotime((string) $task['authorizationExpiresAt']) <= time()
        || empty($task['steps']) || !is_array($task['steps']) || count($task['steps']) > AWD_CLEANUP_MAX_STEPS) return false;
    foreach ($task['steps'] as $step) {
        if (!awd_cleanup_step_is_valid($step)) return false;
    }
    return true;
}

/** Private storage for undo data: outside the web root when possible, never executable. */
function awd_cleanup_quarantine_dir()
{
    $existing = (string) get_option(AWD_CLEANUP_DIR_OPTION, '');
    if ($existing !== '' && is_dir($existing) && is_writable($existing)) return $existing;
    $candidates = array();
    $above_root = dirname(rtrim(ABSPATH, '/\\'));
    if (@is_writable($above_root)) $candidates[] = $above_root . '/awd-quarantine-' . substr(hash('sha256', ABSPATH . wp_salt('auth')), 0, 12);
    $candidates[] = (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content') . '/awd-quarantine-' . wp_generate_password(16, false, false);
    foreach ($candidates as $dir) {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) continue;
        if (!is_writable($dir)) continue;
        @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
        @file_put_contents($dir . '/index.php', "<?php\n// Silence is golden.\n");
        @file_put_contents($dir . '/web.config', '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>');
        update_option(AWD_CLEANUP_DIR_OPTION, $dir, false);
        return $dir;
    }
    return new WP_Error('awd_quarantine_unavailable', 'No writable private directory is available for the quarantine; no change was made.');
}

function awd_cleanup_atomic_write(string $path, string $content, ?int $perms = null): bool
{
    $tmp = dirname($path) . '/.awd-' . wp_generate_password(12, false, false) . '.tmp';
    $handle = @fopen($tmp, 'xb');
    if (!$handle) return false;
    $written = fwrite($handle, $content) === strlen($content) && fflush($handle);
    fclose($handle);
    if (!$written) { @unlink($tmp); return false; }
    if ($perms !== null) @chmod($tmp, $perms & 0777);
    if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
    return true;
}

/** Move a file or directory (rename, falling back to copy + delete for files). */
function awd_cleanup_move(string $from, string $to): bool
{
    if (@rename($from, $to)) return true;
    if (is_file($from) && @copy($from, $to) && hash_file('sha256', $from) === hash_file('sha256', $to)) return @unlink($from);
    return false;
}

function awd_cleanup_remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) { @unlink($path); return; }
    if (!is_dir($path)) return;
    foreach ((array) @scandir($path) as $entry) {
        if ($entry === '.' || $entry === '..' || !is_string($entry)) continue;
        awd_cleanup_remove_tree($path . '/' . $entry);
    }
    @rmdir($path);
}

function awd_cleanup_result(string $status, string $message, array $recovery = array()): array
{
    return array('status' => $status, 'message' => substr($message, 0, 500), 'recovery' => $recovery);
}

function awd_cleanup_op_quarantine_file(array $params, array $context): array
{
    $root = $context['root'];
    $path = awd_cleanup_resolve($params['path'], $root);
    if ($path === null || !is_file($path)) return awd_cleanup_result('skipped', 'The file no longer exists or is outside the site root.');
    $denial = awd_cleanup_quarantine_denial($params['path'], $root, $context['checksums']);
    if ($denial !== null) return awd_cleanup_result('failed', $denial);
    if (!hash_equals($params['expectedSha256'], (string) hash_file('sha256', $path))) return awd_cleanup_result('failed', 'The file changed after the cleanup was approved; it was left in place. Rescan and approve again.');
    $stored = $context['runDir'] . '/' . $context['index'] . '.bin';
    $perms = @fileperms($path);
    if (!awd_cleanup_move($path, $stored)) return awd_cleanup_result('failed', 'The file could not be moved into the quarantine (check file permissions).');
    if (file_exists($path)) return awd_cleanup_result('failed', 'The file reappeared immediately after quarantine; something on the server is rewriting it.', array('path' => $params['path'], 'stored' => basename($stored), 'sha256' => $params['expectedSha256'], 'perms' => $perms));
    return awd_cleanup_result('applied', 'Moved to quarantine.', array('path' => $params['path'], 'stored' => basename($stored), 'sha256' => $params['expectedSha256'], 'perms' => $perms));
}

function awd_cleanup_fetch_core_file(string $version, string $relative)
{
    $url = 'https://core.svn.wordpress.org/tags/' . rawurlencode($version) . '/' . implode('/', array_map('rawurlencode', explode('/', $relative)));
    $response = wp_remote_get($url, array('timeout' => 20, 'redirection' => 0, 'limit_response_size' => 8 * 1024 * 1024, 'sslverify' => true));
    if (is_wp_error($response)) return $response;
    if ((int) wp_remote_retrieve_response_code($response) !== 200) return new WP_Error('awd_core_fetch', 'WordPress.org returned HTTP ' . (int) wp_remote_retrieve_response_code($response) . ' for ' . $relative . '.');
    return (string) wp_remote_retrieve_body($response);
}

function awd_cleanup_op_restore_core_file(array $params, array $context): array
{
    $root = $context['root'];
    $relative = $params['path'];
    if (strpos($relative, 'wp-content/') === 0) return awd_cleanup_result('failed', 'wp-content is not part of the core release.');
    if (!is_array($context['checksums']) || !isset($context['checksums'][$relative])) return awd_cleanup_result('failed', 'This path is not in the WordPress.org checksum list for the installed version.');
    if (!hash_equals($params['officialMd5'], (string) $context['checksums'][$relative])) return awd_cleanup_result('failed', 'The central app and this site disagree on the official checksum; no change was made.');
    $path = awd_cleanup_resolve($relative, $root);
    if ($path === null) return awd_cleanup_result('failed', 'The path is outside the site root or crosses a symbolic link.');
    $exists = is_file($path);
    if ($exists && md5_file($path) === $params['officialMd5']) return awd_cleanup_result('skipped', 'The file already matches the official release.');
    $current = $exists ? (string) hash_file('sha256', $path) : 'missing';
    if (!hash_equals($params['expectedCurrentSha256'], $current)) return awd_cleanup_result('failed', 'The file changed after the cleanup was approved; it was left in place.');
    $official = call_user_func($context['fetchCoreFile'], $context['wpVersion'], $relative);
    if (is_wp_error($official)) return awd_cleanup_result('failed', $official->get_error_message());
    if (md5($official) !== $params['officialMd5']) return awd_cleanup_result('failed', 'The downloaded file does not match the official checksum (locale build or download problem); no change was made.');
    $stored = $context['index'] . '.bin';
    $perms = $exists ? @fileperms($path) : 0644;
    if ($exists && !@copy($path, $context['runDir'] . '/' . $stored)) return awd_cleanup_result('failed', 'The current file could not be saved to the quarantine; no change was made.');
    if (!is_dir(dirname($path)) && !@mkdir(dirname($path), 0755, true)) return awd_cleanup_result('failed', 'The core directory could not be created.');
    if (!awd_cleanup_atomic_write($path, $official, $perms === false ? null : $perms)) return awd_cleanup_result('failed', 'The official file could not be written (check file permissions).');
    $recovery = array('path' => $relative, 'stored' => $exists ? $stored : null, 'sha256Before' => $current, 'md5After' => $params['officialMd5'], 'perms' => $perms);
    if (md5_file($path) !== $params['officialMd5']) return awd_cleanup_result('failed', 'The file was overwritten again right after the restore; something on the server is rewriting it.', $recovery);
    return awd_cleanup_result('applied', 'Restored from the official WordPress ' . $context['wpVersion'] . ' release.', $recovery);
}

/** Expand flagged .htaccess lines to whole rewrite rules (conditions plus their rule). */
function awd_cleanup_htaccess_removal(array $lines, array $flagged): ?array
{
    $protected = array();
    $in_block = false;
    foreach ($lines as $index => $line) {
        $trimmed = trim($line);
        if (preg_match('/^#\s*BEGIN WordPress/i', $trimmed)) $in_block = true;
        if ($in_block) $protected[$index] = true;
        if (preg_match('/^#\s*END WordPress/i', $trimmed)) $in_block = false;
    }
    $is = static function (int $i, string $directive) use ($lines): bool {
        return isset($lines[$i]) && (bool) preg_match('/^' . $directive . '\b/i', trim($lines[$i]));
    };
    $remove = array();
    foreach ($flagged as $number) {
        $i = $number - 1;
        if (!isset($lines[$i])) return null;
        $start = $i;
        $end = $i;
        if ($is($i, 'RewriteCond') || $is($i, 'RewriteRule')) {
            while ($start > 0 && $is($start - 1, 'RewriteCond')) $start--;
            if ($is($i, 'RewriteCond')) {
                while ($is($end + 1, 'RewriteCond')) $end++;
                if ($is($end + 1, 'RewriteRule')) $end++;
            }
        }
        for ($k = $start; $k <= $end; $k++) {
            if (isset($protected[$k])) return null;
            $remove[$k] = true;
        }
    }
    ksort($remove);
    return array_keys($remove);
}

function awd_cleanup_op_remove_htaccess_rules(array $params, array $context): array
{
    $path = $context['root'] . '.htaccess';
    if (!is_file($path) || is_link($path)) return awd_cleanup_result('skipped', '.htaccess no longer exists.');
    $content = (string) file_get_contents($path);
    if (!hash_equals($params['expectedSha256'], hash('sha256', $content))) return awd_cleanup_result('failed', '.htaccess changed after the cleanup was approved; it was left unchanged.');
    $requested = array_map('intval', explode(',', $params['lines']));
    sort($requested);
    $flagged = array_column(awd_integrity_htaccess_analysis($content), 'line');
    sort($flagged);
    if ($requested !== array_map('intval', $flagged)) return awd_cleanup_result('failed', 'The approved lines no longer match the suspicious rules detected in .htaccess.');
    $lines = preg_split('/\r\n|\r|\n/', $content);
    $removal = awd_cleanup_htaccess_removal($lines, $requested);
    if ($removal === null) return awd_cleanup_result('failed', 'A flagged rule is attached to the WordPress-managed block; edit .htaccess manually.');
    $removed_text = array();
    foreach ($removal as $index) { $removed_text[] = $lines[$index]; unset($lines[$index]); }
    $new_content = implode("\n", $lines);
    $stored = $context['index'] . '.bin';
    if (@file_put_contents($context['runDir'] . '/' . $stored, $content) !== strlen($content)) return awd_cleanup_result('failed', 'The current .htaccess could not be saved to the quarantine; no change was made.');
    $perms = @fileperms($path);
    if (!awd_cleanup_atomic_write($path, $new_content, $perms === false ? null : $perms)) return awd_cleanup_result('failed', '.htaccess could not be written (check file permissions).');
    $after = hash('sha256', (string) file_get_contents($path));
    $recovery = array('stored' => $stored, 'sha256Before' => $params['expectedSha256'], 'sha256After' => $after, 'perms' => $perms);
    if (!hash_equals(hash('sha256', $new_content), $after)) return awd_cleanup_result('failed', '.htaccess was rewritten again right after the change; something on the server is restoring it.', $recovery);
    return awd_cleanup_result('applied', sprintf('Removed %d line(s): %s', count($removed_text), substr(implode(' | ', array_map('trim', $removed_text)), 0, 300)), $recovery);
}

function awd_cleanup_op_quarantine_plugin(array $params, array $context): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $plugins = get_plugins();
    $plugin = $params['plugin'];
    if (!isset($plugins[$plugin])) return awd_cleanup_result('skipped', 'The plugin is no longer installed.');
    if ((string) ($plugins[$plugin]['Version'] ?? '') !== $params['expectedVersion']) return awd_cleanup_result('failed', 'The installed plugin version changed after approval.');
    $plugin_dir = rtrim(WP_PLUGIN_DIR, '/\\');
    $slug = dirname($plugin);
    $source = $slug === '.' ? $plugin_dir . '/' . $plugin : $plugin_dir . '/' . $slug;
    if (is_link($source) || !file_exists($source)) return awd_cleanup_result('failed', 'The plugin directory is missing or is a symbolic link.');
    $was_active = is_plugin_active($plugin);
    if ($was_active) deactivate_plugins($plugin, true);
    $stored = $context['index'] . '.plugin';
    if (!awd_cleanup_move($source, $context['runDir'] . '/' . $stored)) {
        if ($was_active) activate_plugin($plugin, '', false, true);
        return awd_cleanup_result('failed', 'The plugin files could not be moved into the quarantine (check file permissions).');
    }
    return awd_cleanup_result('applied', 'Deactivated and moved to quarantine.', array('plugin' => $plugin, 'source' => $slug === '.' ? $plugin : $slug, 'stored' => $stored, 'wasActive' => $was_active));
}

function awd_cleanup_op_demote_user(array $params, array $context): array
{
    $user = get_user_by('login', $params['login']);
    if (!$user) return awd_cleanup_result('skipped', 'The account no longer exists.');
    if (!in_array('administrator', (array) $user->roles, true)) return awd_cleanup_result('skipped', 'The account is no longer an administrator.');
    if (function_exists('get_current_user_id') && get_current_user_id() === (int) $user->ID) return awd_cleanup_result('failed', 'You cannot demote the account you are signed in with.');
    $admins = get_users(array('role' => 'administrator', 'fields' => 'ID', 'number' => 2));
    if (count((array) $admins) < 2) return awd_cleanup_result('failed', 'This is the only administrator; it was left unchanged.');
    global $wpdb;
    $hash = (string) $wpdb->get_var($wpdb->prepare("SELECT user_pass FROM {$wpdb->users} WHERE ID = %d", $user->ID));
    $recovery = array('userId' => (int) $user->ID, 'login' => $params['login'], 'roles' => array_values((array) $user->roles), 'passHash' => $hash);
    $user->set_role('subscriber');
    wp_set_password(wp_generate_password(40, true, true), (int) $user->ID);
    if (class_exists('WP_Session_Tokens')) WP_Session_Tokens::get_instance((int) $user->ID)->destroy_all();
    $check = get_user_by('id', (int) $user->ID);
    if (!$check || in_array('administrator', (array) $check->roles, true)) return awd_cleanup_result('failed', 'The administrator role could not be removed.', $recovery);
    return awd_cleanup_result('applied', 'Demoted to subscriber, password replaced with a random one, and all sessions signed out.', $recovery);
}

function awd_cleanup_config_path(): ?string
{
    if (is_file(ABSPATH . 'wp-config.php')) return ABSPATH . 'wp-config.php';
    $above = dirname(rtrim(ABSPATH, '/\\'));
    if (is_file($above . '/wp-config.php') && !is_file($above . '/wp-settings.php')) return $above . '/wp-config.php';
    return null;
}

function awd_cleanup_random_salt(): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%&()*+,-./:;<=>?@[]^_`{|}~ ';
    $salt = '';
    for ($i = 0; $i < 64; $i++) $salt .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    return $salt;
}

/** Replace the eight secret-key defines, or null when they are not each defined exactly once. */
function awd_cleanup_rotate_salts_content(string $config, callable $random): ?string
{
    foreach (explode(',', AWD_CLEANUP_SALT_KEYS) as $key) {
        $pattern = '/define\s*\(\s*([\'"])' . $key . '\1\s*,\s*([\'"])((?:(?!\2).)*)\2\s*\)\s*;/';
        if (preg_match_all($pattern, $config) !== 1) return null;
        $value = $random();
        $config = preg_replace_callback($pattern, static function () use ($key, $value) {
            return "define( '" . $key . "', '" . $value . "' );";
        }, $config);
    }
    return $config;
}

function awd_cleanup_op_rotate_salts(array $params, array $context): array
{
    $path = awd_cleanup_config_path();
    if ($path === null || is_link($path)) return awd_cleanup_result('failed', 'wp-config.php was not found in a supported location; rotate the salts manually.');
    $config = (string) file_get_contents($path);
    $updated = awd_cleanup_rotate_salts_content($config, 'awd_cleanup_random_salt');
    if ($updated === null) return awd_cleanup_result('failed', 'wp-config.php does not define each secret key exactly once; rotate the salts manually from https://api.wordpress.org/secret-key/1.1/salt/.');
    $stored = $context['index'] . '.bin';
    if (@file_put_contents($context['runDir'] . '/' . $stored, $config) !== strlen($config)) return awd_cleanup_result('failed', 'The current wp-config.php could not be saved to the quarantine; no change was made.');
    $perms = @fileperms($path);
    if (!awd_cleanup_atomic_write($path, $updated, $perms === false ? null : $perms)) return awd_cleanup_result('failed', 'wp-config.php is not writable; rotate the salts manually.');
    $after = (string) hash_file('sha256', $path);
    $recovery = array('path' => $path, 'stored' => $stored, 'sha256Before' => hash('sha256', $config), 'sha256After' => $after, 'perms' => $perms);
    if (!hash_equals(hash('sha256', $updated), $after)) return awd_cleanup_result('failed', 'wp-config.php was rewritten again right after the change.', $recovery);
    return awd_cleanup_result('applied', 'All eight secret keys and salts were replaced; every user, including you, must sign in again.', $recovery);
}

function awd_cleanup_op_purge_page_cache(array $params, array $context): array
{
    $purged = array();
    if (has_action('litespeed_purge_all')) { do_action('litespeed_purge_all'); $purged[] = 'LiteSpeed Cache'; }
    if (function_exists('rocket_clean_domain')) { rocket_clean_domain(); $purged[] = 'WP Rocket'; }
    if (function_exists('w3tc_flush_all')) { w3tc_flush_all(); $purged[] = 'W3 Total Cache'; }
    if (function_exists('wp_cache_clear_cache')) { wp_cache_clear_cache(); $purged[] = 'WP Super Cache'; }
    if (function_exists('wpo_cache_flush')) { wpo_cache_flush(); $purged[] = 'WP-Optimize'; }
    if (function_exists('wp_cache_flush')) { wp_cache_flush(); $purged[] = 'object cache'; }
    return awd_cleanup_result('applied', $purged ? 'Purged: ' . implode(', ', $purged) . '.' : 'No supported page cache was found.');
}

function awd_cleanup_op_purge_quarantine(array $params, array $context): array
{
    $runs = awd_cleanup_runs();
    $run = $runs[$params['runId']] ?? null;
    if (!is_array($run) || empty($run['dir'])) return awd_cleanup_result('skipped', 'That cleanup run has no stored quarantine.');
    $base = (string) get_option(AWD_CLEANUP_DIR_OPTION, '');
    $dir = (string) $run['dir'];
    if ($base === '' || strpos($dir, rtrim($base, '/') . '/') !== 0 || basename($dir) !== $params['runId']) return awd_cleanup_result('failed', 'The stored quarantine location is not valid.');
    awd_cleanup_remove_tree($dir);
    $runs[$params['runId']]['purgedAt'] = gmdate('c');
    awd_cleanup_save_runs($runs);
    return awd_cleanup_result('applied', 'Quarantined files from that cleanup were permanently deleted; it can no longer be restored.');
}

function awd_cleanup_runs(): array
{
    $runs = get_option(AWD_CLEANUP_OPTION, array());
    return is_array($runs) ? $runs : array();
}

function awd_cleanup_save_runs(array $runs): void
{
    if (count($runs) > AWD_CLEANUP_MAX_RUNS) $runs = array_slice($runs, -AWD_CLEANUP_MAX_RUNS, null, true);
    update_option(AWD_CLEANUP_OPTION, $runs, false);
}

/**
 * Run steps in order and return per-step results. $context overrides are for
 * tests (root, checksums, fetchCoreFile). Progress is saved after every step,
 * so an interrupted run can still be restored.
 */
function awd_cleanup_execute_steps(string $run_id, string $repair_id, array $steps, array $context = array()): array
{
    $started = microtime(true);
    $root = $context['root'] ?? awd_cleanup_root();
    $needs_storage = (bool) array_diff(array_column($steps, 'operation'), array('purge_page_cache', 'purge_quarantine'));
    $quarantine = $needs_storage ? ($context['quarantineDir'] ?? awd_cleanup_quarantine_dir()) : null;
    if (is_wp_error($quarantine)) {
        return array_map(static function ($step, $index) use ($quarantine) {
            return array('index' => $index, 'operation' => $step['operation'], 'status' => 'not_attempted', 'message' => $quarantine->get_error_message());
        }, $steps, array_keys($steps));
    }
    $run_dir = $quarantine !== null ? rtrim($quarantine, '/') . '/' . $run_id : null;
    if ($run_dir !== null && !is_dir($run_dir) && !@mkdir($run_dir, 0700, true)) {
        return array(array('index' => 0, 'operation' => $steps[0]['operation'], 'status' => 'failed', 'message' => 'The quarantine directory for this run could not be created.'));
    }
    $runs = awd_cleanup_runs();
    $runs[$run_id] = array('id' => $run_id, 'repairId' => $repair_id, 'createdAt' => gmdate('c'), 'dir' => $run_dir, 'steps' => array());
    awd_cleanup_save_runs($runs);
    $base_context = array(
        'root' => $root,
        'checksums' => array_key_exists('checksums', $context) ? $context['checksums'] : awd_integrity_core_checksums(),
        'wpVersion' => $context['wpVersion'] ?? (string) get_bloginfo('version'),
        'fetchCoreFile' => $context['fetchCoreFile'] ?? 'awd_cleanup_fetch_core_file',
        'runDir' => $run_dir,
    );
    $handlers = array(
        'quarantine_file' => 'awd_cleanup_op_quarantine_file',
        'restore_core_file' => 'awd_cleanup_op_restore_core_file',
        'remove_htaccess_rules' => 'awd_cleanup_op_remove_htaccess_rules',
        'quarantine_plugin' => 'awd_cleanup_op_quarantine_plugin',
        'demote_user' => 'awd_cleanup_op_demote_user',
        'rotate_salts' => 'awd_cleanup_op_rotate_salts',
        'purge_page_cache' => 'awd_cleanup_op_purge_page_cache',
        'purge_quarantine' => 'awd_cleanup_op_purge_quarantine',
        'update_plugin' => 'awd_cleanup_op_update_plugin',
        'reinstall_plugin' => 'awd_cleanup_op_reinstall_plugin',
        'install_plugin' => 'awd_cleanup_op_install_plugin',
        'set_hardening' => 'awd_cleanup_op_set_hardening',
    );
    $results = array();
    foreach (array_values($steps) as $index => $step) {
        if (microtime(true) - $started > ($context['budgetSeconds'] ?? AWD_CLEANUP_STEP_BUDGET_SECONDS)) {
            $result = awd_cleanup_result('not_attempted', 'Time budget reached; run the cleanup again for the remaining steps.');
        } else {
            try {
                $result = call_user_func($handlers[$step['operation']], $step['parameters'], $base_context + array('index' => $index));
            } catch (Throwable $error) {
                $result = awd_cleanup_result('failed', 'Unexpected error: ' . substr($error->getMessage(), 0, 300));
            }
        }
        $runs = awd_cleanup_runs();
        $runs[$run_id]['steps'][$index] = array('operation' => $step['operation'], 'parameters' => $step['parameters'], 'status' => $result['status'], 'message' => $result['message'], 'recovery' => $result['recovery']);
        awd_cleanup_save_runs($runs);
        $results[] = array('index' => $index, 'operation' => $step['operation'], 'status' => $result['status'], 'message' => $result['message']);
    }
    $runs = awd_cleanup_runs();
    $runs[$run_id]['completedAt'] = gmdate('c');
    awd_cleanup_save_runs($runs);
    return $results;
}

/** Undo a run's applied steps in reverse order, skipping targets that changed since. */
function awd_cleanup_restore_run(string $run_id, array $context = array()): array
{
    $runs = awd_cleanup_runs();
    $run = $runs[$run_id] ?? null;
    if (!is_array($run)) return array(array('index' => -1, 'status' => 'failed', 'message' => 'Unknown cleanup run.'));
    if (!empty($run['purgedAt'])) return array(array('index' => -1, 'status' => 'failed', 'message' => 'This run was purged; its quarantine no longer exists.'));
    $root = $context['root'] ?? awd_cleanup_root();
    $dir = (string) $run['dir'];
    $results = array();
    foreach (array_reverse((array) $run['steps'], true) as $index => $step) {
        if (($step['status'] ?? '') !== 'applied' && empty($step['recovery'])) continue;
        if (!empty($step['restoredAt'])) continue;
        $recovery = (array) ($step['recovery'] ?? array());
        $status = 'restored';
        $message = 'Restored.';
        switch ($step['operation']) {
            case 'quarantine_file':
                $target = awd_cleanup_resolve((string) $recovery['path'], $root);
                if ($target === null || file_exists($target)) { $status = 'conflict'; $message = 'A file now exists at the original path; it was kept.'; break; }
                if (!awd_cleanup_move($dir . '/' . $recovery['stored'], $target)) { $status = 'failed'; $message = 'The file could not be moved back.'; break; }
                if (!empty($recovery['perms'])) @chmod($target, (int) $recovery['perms'] & 0777);
                break;
            case 'restore_core_file':
                $target = awd_cleanup_resolve((string) $recovery['path'], $root);
                if ($target === null || !is_file($target) || md5_file($target) !== $recovery['md5After']) { $status = 'conflict'; $message = 'The file changed after the cleanup; it was kept.'; break; }
                if (empty($recovery['stored'])) { @unlink($target); break; }
                if (!awd_cleanup_atomic_write($target, (string) file_get_contents($dir . '/' . $recovery['stored']), empty($recovery['perms']) ? null : (int) $recovery['perms'])) { $status = 'failed'; $message = 'The previous file could not be written back.'; }
                break;
            case 'remove_htaccess_rules':
            case 'rotate_salts':
                $target = $step['operation'] === 'rotate_salts' ? (string) $recovery['path'] : $root . '.htaccess';
                if (!is_file($target) || !hash_equals((string) $recovery['sha256After'], (string) hash_file('sha256', $target))) { $status = 'conflict'; $message = 'The file changed after the cleanup; it was kept.'; break; }
                if (!awd_cleanup_atomic_write($target, (string) file_get_contents($dir . '/' . $recovery['stored']), empty($recovery['perms']) ? null : (int) $recovery['perms'])) { $status = 'failed'; $message = 'The previous file could not be written back.'; }
                break;
            case 'quarantine_plugin':
                $target = rtrim(WP_PLUGIN_DIR, '/\\') . '/' . $recovery['source'];
                if (file_exists($target)) { $status = 'conflict'; $message = 'The plugin was reinstalled since; the current copy was kept.'; break; }
                if (!awd_cleanup_move($dir . '/' . $recovery['stored'], $target)) { $status = 'failed'; $message = 'The plugin files could not be moved back.'; break; }
                if (!empty($recovery['wasActive'])) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; activate_plugin((string) $recovery['plugin'], '', false, true); }
                break;
            case 'demote_user':
                $user = get_user_by('id', (int) $recovery['userId']);
                if (!$user || array_values((array) $user->roles) !== array('subscriber')) { $status = 'conflict'; $message = 'The account changed after the cleanup; it was kept.'; break; }
                $user->set_role('');
                foreach ((array) $recovery['roles'] as $role) $user->add_role((string) $role);
                global $wpdb;
                $wpdb->update($wpdb->users, array('user_pass' => (string) $recovery['passHash']), array('ID' => (int) $recovery['userId']));
                clean_user_cache((int) $recovery['userId']);
                break;
            case 'update_plugin':
            case 'reinstall_plugin':
                list($status, $message) = awd_plugin_restore_replace($recovery, WP_PLUGIN_DIR, $dir);
                break;
            case 'install_plugin':
                list($status, $message) = awd_plugin_restore_install($recovery, WP_PLUGIN_DIR, $dir);
                break;
            case 'set_hardening':
                $undo = awd_hardening_apply((string) $recovery['measure'], !empty($recovery['wasEnabled']));
                $status = $undo['ok'] ? 'restored' : 'failed';
                $message = $undo['message'];
                break;
            default:
                continue 2;
        }
        $runs = awd_cleanup_runs();
        if ($status === 'restored') $runs[$run_id]['steps'][$index]['restoredAt'] = gmdate('c');
        awd_cleanup_save_runs($runs);
        $results[] = array('index' => $index, 'operation' => $step['operation'], 'status' => $status, 'message' => $message);
    }
    return $results;
}

/** Execute a central cleanup task end to end and report the outcome. */
function awd_cleanup_execute_task(array $settings, array $task): array
{
    if (!awd_cleanup_task_is_valid($task)) return array('ok' => false, 'message' => 'The cleanup task failed local validation; nothing was changed.');
    $lock = 'awd_cleanup_lock';
    if (get_option($lock) && (int) get_option($lock) < time() - 900) delete_option($lock);
    if (!add_option($lock, time(), '', false)) return array('ok' => false, 'message' => 'A cleanup is already running.');
    try {
        if (function_exists('set_time_limit')) @set_time_limit(300);
        $run_id = strtolower(wp_generate_password(20, false, false));
        $started_at = gmdate('c');
        $results = awd_cleanup_execute_steps($run_id, (string) $task['repairId'], array_values($task['steps']));
        $GLOBALS['awd_force_integrity_scan'] = true;
        $sync = awd_send_diagnostics();
        $report = awd_authenticated_request($settings, '/cleanup-executions', 'POST', array(
            'event' => 'executed',
            'repairId' => (string) $task['repairId'],
            'authorizationGrantId' => (string) $task['authorizationGrantId'],
            'runId' => $run_id,
            'startedAt' => $started_at,
            'completedAt' => gmdate('c'),
            'diagnosticsSynced' => !is_wp_error($sync),
            'steps' => $results,
        ));
        $applied = count(array_filter($results, static function ($result) { return $result['status'] === 'applied'; }));
        $failed = count(array_filter($results, static function ($result) { return $result['status'] === 'failed'; }));
        $message = sprintf('Cleanup finished: %d applied, %d failed, %d skipped or not attempted.', $applied, $failed, count($results) - $applied - $failed);
        if (is_wp_error($report)) $message .= ' The result could not be reported centrally: ' . $report->get_error_message();
        return array('ok' => $failed === 0, 'message' => $message, 'runId' => $run_id, 'results' => $results);
    } finally {
        delete_option($lock);
    }
}

function awd_cleanup_run_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to run a cleanup.', 'ai-website-doctor'), 403);
    check_admin_referer('awd_cleanup_run');
    $settings = awd_settings();
    $digest = isset($_POST['plan_digest']) ? sanitize_text_field(wp_unslash($_POST['plan_digest'])) : '';
    $include = isset($_POST['include']) && is_array($_POST['include']) ? array_values(array_filter(array_map('sanitize_text_field', wp_unslash($_POST['include'])), static function ($id) { return (bool) preg_match('/^[a-z0-9:_-]{1,120}$/i', $id); })) : array();
    if (!preg_match('/^[a-f0-9]{64}$/', $digest)) awd_redirect('The cleanup plan was not recognized; reload the page.', 'error');
    $response = awd_authenticated_request($settings, '/cleanup', 'POST', array('planDigest' => $digest, 'include' => array_slice($include, 0, 60), 'confirm' => true));
    if (is_wp_error($response)) awd_redirect('The central app did not approve the cleanup: ' . $response->get_error_message(), 'error');
    $body = json_decode(wp_remote_retrieve_body($response), true);
    if (!is_array($body) || empty($body['task']) || !is_array($body['task'])) awd_redirect(is_array($body) && !empty($body['error']) ? (string) $body['error'] : 'The central app did not return an approved cleanup.', 'error');
    $outcome = awd_cleanup_execute_task($settings, $body['task']);
    awd_redirect($outcome['message'], $outcome['ok'] ? 'success' : 'warning');
}

function awd_cleanup_restore_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to restore a cleanup.', 'ai-website-doctor'), 403);
    $run_id = isset($_POST['run_id']) ? sanitize_text_field(wp_unslash($_POST['run_id'])) : '';
    check_admin_referer('awd_cleanup_restore_' . $run_id);
    $runs = awd_cleanup_runs();
    if (!isset($runs[$run_id])) awd_redirect('Unknown cleanup run.', 'error');
    $results = awd_cleanup_restore_run($run_id);
    awd_authenticated_request(awd_settings(), '/cleanup-executions', 'POST', array(
        'event' => 'restored', 'repairId' => (string) $runs[$run_id]['repairId'], 'runId' => $run_id, 'completedAt' => gmdate('c'), 'steps' => $results,
    ));
    $restored = count(array_filter($results, static function ($result) { return $result['status'] === 'restored'; }));
    awd_redirect(sprintf('Restore finished: %d step(s) restored, %d kept because they changed since the cleanup.', $restored, count($results) - $restored), $restored === count($results) ? 'success' : 'warning');
}

/** Plugin admin section: the central cleanup plan with one approval button, and earlier runs. */
function awd_render_cleanup_section(array $settings): void
{
    if (empty($settings['agent_id'])) return;
    $response = awd_authenticated_request($settings, '/cleanup', 'GET');
    $plan = !is_wp_error($response) ? json_decode(wp_remote_retrieve_body($response), true) : null;
    echo '<h2>Compromise cleanup</h2>';
    if (!is_array($plan) || !isset($plan['steps'])) {
        echo '<p>The cleanup plan is unavailable: ' . esc_html(is_wp_error($response) ? $response->get_error_message() : (string) ($plan['error'] ?? 'unexpected response')) . '</p>';
    } elseif (!empty($plan['blockers'])) {
        echo '<p><strong>Cleanup cannot start yet:</strong></p><ul>';
        foreach ((array) $plan['blockers'] as $blocker) echo '<li>' . esc_html((string) $blocker) . '</li>';
        echo '</ul>';
    } elseif (empty($plan['steps']) && empty($plan['optional'])) {
        echo '<p>No cleanup is needed: the latest outside check and integrity scan found nothing this cleanup can fix.</p>';
    } else {
        echo '<p>' . esc_html((string) ($plan['summary'] ?? '')) . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_cleanup_run">';
        wp_nonce_field('awd_cleanup_run');
        echo '<input type="hidden" name="plan_digest" value="' . esc_attr((string) $plan['planDigest']) . '"><ol>';
        foreach ((array) $plan['steps'] as $step) echo '<li>' . esc_html((string) ($step['description'] ?? $step['operation'])) . '</li>';
        echo '</ol>';
        if (!empty($plan['optional'])) {
            echo '<p><strong>Optional (not included unless ticked):</strong></p><ul>';
            foreach ((array) $plan['optional'] as $item) {
                echo '<li><label><input type="checkbox" name="include[]" value="' . esc_attr((string) $item['id']) . '"> ' . esc_html((string) $item['description']) . '</label></li>';
            }
            echo '</ul>';
        }
        foreach ((array) ($plan['warnings'] ?? array()) as $warning) echo '<p><em>' . esc_html((string) $warning) . '</em></p>';
        submit_button('Approve & run cleanup now', 'primary', 'submit', false);
        echo '</form>';
    }
    $runs = array_reverse(awd_cleanup_runs(), true);
    if ($runs) {
        echo '<h3>Earlier cleanup runs</h3><ul>';
        foreach ($runs as $run_id => $run) {
            $steps = (array) ($run['steps'] ?? array());
            $applied = count(array_filter($steps, static function ($step) { return ($step['status'] ?? '') === 'applied'; }));
            echo '<li>' . esc_html(sprintf('%s · %d of %d steps applied%s', (string) ($run['createdAt'] ?? ''), $applied, count($steps), !empty($run['purgedAt']) ? ' · quarantine purged' : '')) . ' ';
            if (empty($run['purgedAt']) && $applied > 0) {
                echo '<form class="awd-inline-form" method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_cleanup_restore"><input type="hidden" name="run_id" value="' . esc_attr((string) $run_id) . '">';
                wp_nonce_field('awd_cleanup_restore_' . $run_id);
                submit_button('Restore this run', 'secondary', 'submit', false);
                echo '</form>';
            }
            echo '</li>';
        }
        echo '</ul>';
    }
}

/** Findings the central app can fix with one approved maintenance step. */
function awd_issue_is_fixable(array $issue): bool
{
    $fingerprint = (string) ($issue['fingerprint'] ?? '');
    return ($issue['status'] ?? '') !== 'resolved'
        && (str_starts_with($fingerprint, 'wp:plugin-update:') || str_starts_with($fingerprint, 'wp:integrity:plugin-modified:') || str_starts_with($fingerprint, 'vuln:plugin-'));
}

function awd_render_fix_button(array $issue): void
{
    if (!awd_issue_is_fixable($issue) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/', (string) ($issue['id'] ?? ''))) return;
    $update = str_starts_with((string) $issue['fingerprint'], 'wp:plugin-update:');
    $vulnerable = str_starts_with((string) $issue['fingerprint'], 'vuln:plugin-');
    echo '<form class="awd-inline-form" method="post" action="' . esc_url(admin_url('admin-post.php')) . '" onsubmit="return confirm(' . esc_attr(wp_json_encode($vulnerable
        ? 'Fix this vulnerable plugin now? If a fixed version is available it is installed and verified (the old version is put back if the site breaks); if no fix exists yet, the plugin is deactivated and moved to the quarantine.'
        : ($update
        ? 'Update this plugin now? The current version is kept in the quarantine and put back automatically if the update fails its checks or breaks the site.'
        : 'Reinstall this plugin from WordPress.org? The current files are kept in the quarantine and can be restored.'))) . ');">';
    echo '<input type="hidden" name="action" value="awd_fix_issue"><input type="hidden" name="issue_id" value="' . esc_attr((string) $issue['id']) . '">';
    wp_nonce_field('awd_fix_issue_' . $issue['id']);
    submit_button($vulnerable ? 'Fix vulnerability now' : ($update ? 'Fix: update plugin now' : 'Fix: reinstall plugin now'), 'primary', 'submit', false);
    echo '</form>';
}

function awd_fix_issue_from_admin(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to fix issues.', 'ai-website-doctor'), 403);
    $issue_id = isset($_POST['issue_id']) ? sanitize_text_field(wp_unslash($_POST['issue_id'])) : '';
    check_admin_referer('awd_fix_issue_' . $issue_id);
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $issue_id)) awd_redirect('Invalid issue.', 'error');
    $settings = awd_settings();
    $response = awd_authenticated_request($settings, '/fix', 'POST', array('issueId' => $issue_id, 'confirm' => true));
    if (is_wp_error($response)) awd_redirect('The central app did not approve the fix: ' . $response->get_error_message(), 'error');
    $body = json_decode(wp_remote_retrieve_body($response), true);
    if (!is_array($body) || empty($body['task']) || !is_array($body['task'])) awd_redirect('The central app did not return an approved fix.', 'error');
    $outcome = awd_cleanup_execute_task($settings, $body['task']);
    $detail = '';
    foreach ((array) ($outcome['results'] ?? array()) as $result) $detail .= ' ' . (string) $result['message'];
    awd_redirect(trim($outcome['message'] . $detail), $outcome['ok'] ? 'success' : 'warning');
}

function awd_cleanup_op_set_hardening(array $params, array $context): array
{
    $was = awd_hardening_enabled($params['measure']);
    $enable = $params['state'] === 'on';
    if ($was === $enable) return awd_cleanup_result('skipped', 'Already ' . $params['state'] . '.');
    $result = awd_hardening_apply($params['measure'], $enable);
    return awd_cleanup_result($result['ok'] ? 'applied' : 'failed', $result['message'], array('measure' => $params['measure'], 'wasEnabled' => $was));
}
