<?php
/**
 * Read-only compromise evidence: WordPress core checksum comparison, unknown
 * executable files in places WordPress never writes PHP, malware code
 * signatures, injected .htaccess rules, a physical robots.txt advertising
 * spam sitemaps, and recently created administrators.
 *
 * Nothing in this file changes the site. Results are cached because hashing
 * core takes about a second; the central app receives only bounded paths,
 * signature names, and counts, never file contents.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_INTEGRITY_OPTION', 'ai_website_doctor_integrity_report');
// Core and file scans repeat hourly; WordPress.org plugin checksums are cached longer (see plugin-maintenance.php).
define('AWD_INTEGRITY_MAX_AGE', 3600);
define('AWD_INTEGRITY_LIST_LIMIT', 50);
define('AWD_INTEGRITY_TIME_BUDGET', 12.0);
define('AWD_INTEGRITY_MAX_SCAN_BYTES', 1048576);

/** Signature name => pattern. Matched against file contents; only names are reported. */
function awd_integrity_signatures(): array
{
    return array(
        'eval_encoded_payload' => '/\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/i',
        'request_code_execution' => '/\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open|create_function)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/i',
        'request_value_called_as_function' => '/\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,80}\]\s*\(/i',
        'request_file_write' => '/\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\([^;]{0,300}\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b/i',
        'preg_replace_eval_modifier' => '/preg_replace\s*\(\s*([\'"])[^\'"]{1,200}\/[a-z]*e[a-z]*\1\s*,/i',
        'remote_code_include' => '/\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:https?|ftp|php|data):/i',
        'crawler_cloaking' => '/HTTP_USER_AGENT[\s\S]{0,600}(?:googlebot|bingbot|baiduspider|yandex|slurp)|(?:googlebot|bingbot|baiduspider|yandex)[\s\S]{0,600}HTTP_USER_AGENT/i',
        'search_referrer_check' => '/HTTP_REFERER[\s\S]{0,300}(?:google\.|bing\.|yahoo\.)/i',
        'long_encoded_blob' => '/[\'"][A-Za-z0-9+\/=]{4000,}[\'"]/',
        'hex_escaped_code' => '/(?:\\\\x[0-9a-f]{2}){40,}/i',
        'variable_function_obfuscation' => '/\$\w+\s*=\s*[\'"](?:ba|bas|base)[\'"]\s*\.\s*[\'"]/i',
    );
}

function awd_integrity_relative(string $path, string $root): string
{
    $root = rtrim(str_replace('\\', '/', $root), '/') . '/';
    $path = str_replace('\\', '/', $path);
    return strpos($path, $root) === 0 ? substr($path, strlen($root)) : $path;
}

function awd_integrity_is_executable_name(string $name): bool
{
    return (bool) preg_match('/\.(?:php[0-9]?|phtml|pht|phar|phps|inc)$/i', $name);
}

function awd_integrity_push(array &$list, $value, bool &$truncated): void
{
    if (count($list) >= AWD_INTEGRITY_LIST_LIMIT) {
        $truncated = true;
        return;
    }
    $list[] = $value;
}

/**
 * Patterns that legitimate code also uses occasionally. A file is reported only
 * for one strong signature or at least two weak ones.
 */
function awd_integrity_weak_signatures(): array
{
    return array('crawler_cloaking', 'search_referrer_check', 'long_encoded_blob', 'hex_escaped_code', 'variable_function_obfuscation');
}

/** Return matching signature names for one file (empty unless the file qualifies as suspicious). */
function awd_integrity_scan_file(string $path): array
{
    if (!is_file($path) || is_link($path) || !is_readable($path)) return array();
    $content = @file_get_contents($path, false, null, 0, AWD_INTEGRITY_MAX_SCAN_BYTES);
    if (!is_string($content) || $content === '') return array();
    $matches = array();
    foreach (awd_integrity_signatures() as $name => $pattern) {
        if (@preg_match($pattern, $content) === 1) $matches[] = $name;
    }
    $weak = array_intersect($matches, awd_integrity_weak_signatures());
    return count($matches) > count($weak) || count($weak) >= 2 ? $matches : array();
}

/** Lines of .htaccess outside the WordPress-managed block that are typical of injected rules. */
function awd_integrity_htaccess_analysis(string $content): array
{
    $suspicious = array();
    $in_wordpress_block = false;
    // Our own hardening block is skipped only when it is byte-identical to the block this plugin wrote.
    $trusted_lines = array();
    if (function_exists('awd_hardening_trusted_block_hashes') && preg_match_all('/# BEGIN AI Website Doctor hardening\n.*?\n# END AI Website Doctor hardening/s', str_replace(array("\r\n", "\r"), "\n", $content), $blocks, PREG_OFFSET_CAPTURE)) {
        $normalized = str_replace(array("\r\n", "\r"), "\n", $content);
        foreach ($blocks[0] as $block) {
            if (!in_array(hash('sha256', $block[0]), awd_hardening_trusted_block_hashes(), true)) continue;
            $first = substr_count(substr($normalized, 0, $block[1]), "\n");
            for ($i = $first; $i <= $first + substr_count($block[0], "\n"); $i++) $trusted_lines[$i] = true;
        }
    }
    foreach (preg_split('/\r\n|\r|\n/', $content) as $number => $line) {
        if (isset($trusted_lines[$number])) continue;
        $trimmed = trim($line);
        if (preg_match('/^#\s*BEGIN WordPress/i', $trimmed)) { $in_wordpress_block = true; continue; }
        if (preg_match('/^#\s*END WordPress/i', $trimmed)) { $in_wordpress_block = false; continue; }
        if ($trimmed === '' || $trimmed[0] === '#') continue;
        $reason = null;
        if (preg_match('/RewriteCond\s+%\{HTTP_USER_AGENT\}.*(?:google|bing|yahoo|baidu|yandex|bot|crawl|spider)/i', $trimmed)) $reason = 'crawler_condition';
        elseif (preg_match('/RewriteCond\s+%\{HTTP_REFERER\}.*(?:google|bing|yahoo|baidu|yandex)/i', $trimmed)) $reason = 'search_referrer_condition';
        elseif (preg_match('/\b(?:php_value|php_flag)\s+auto_(?:prepend|append)_file/i', $trimmed)) $reason = 'auto_prepend_file';
        elseif (preg_match('/\b(?:AddHandler|AddType|SetHandler)\b.*(?:php|x-httpd)/i', $trimmed) && !preg_match('/\.php[0-9]?\s*$/i', $trimmed)) $reason = 'php_handler_for_other_extensions';
        elseif (preg_match('/RewriteRule\s+.*\s+https?:\/\//i', $trimmed)) $reason = 'external_redirect_rule';
        elseif (preg_match('/RewriteRule\s+.*\.(?:php|html?)\b.*\[.*L/i', $trimmed) && !$in_wordpress_block && !preg_match('/index\.php/i', $trimmed)) $reason = 'rewrite_to_non_wordpress_script';
        if ($reason !== null) {
            $suspicious[] = array('line' => $number + 1, 'reason' => $reason, 'text' => substr($trimmed, 0, 200));
            if (count($suspicious) >= 10) break;
        }
    }
    return $suspicious;
}

/** Recursively list executable files beneath a directory (bounded, never follows symlinks). */
function awd_integrity_find_executables(string $dir, float $deadline, int $max_entries, bool &$truncated): array
{
    $found = array();
    if (!is_dir($dir) || is_link($dir)) return $found;
    $seen = 0;
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($iterator as $file) {
            if (++$seen > $max_entries || microtime(true) > $deadline) { $truncated = true; break; }
            if ($file->isLink() || !$file->isFile()) continue;
            if (awd_integrity_is_executable_name($file->getFilename())) {
                $found[] = $file->getPathname();
                if (count($found) >= 500) { $truncated = true; break; }
            }
        }
    } catch (Throwable $error) {
        $truncated = true;
    }
    return $found;
}

/**
 * Pure scan of a WordPress tree. $checksums maps relative core paths to md5
 * hashes (null when WordPress.org checksums are unavailable).
 */
function awd_integrity_scan(string $root, ?array $checksums, array $context = array()): array
{
    $started = microtime(true);
    $deadline = $started + (float) ($context['timeBudget'] ?? AWD_INTEGRITY_TIME_BUDGET);
    $root = rtrim($root, '/\\') . '/';
    $content_dir = rtrim((string) ($context['contentDir'] ?? $root . 'wp-content'), '/\\');
    $uploads_dir = rtrim((string) ($context['uploadsDir'] ?? $content_dir . '/uploads'), '/\\');
    $mu_dir = rtrim((string) ($context['muPluginsDir'] ?? $content_dir . '/mu-plugins'), '/\\');
    $theme_dirs = array_values(array_unique(array_filter((array) ($context['themeDirs'] ?? array()), 'is_string')));
    $truncated = false;
    $partial = false;

    $modified = array();
    $missing = array();
    $unknown_php = array();
    $checked = 0;
    $to_scan = array();

    if (is_array($checksums)) {
        foreach ($checksums as $relative => $expected) {
            $relative = (string) $relative;
            if (strpos($relative, 'wp-content/') === 0) continue;
            if (microtime(true) > $deadline) { $partial = true; break; }
            $path = $root . $relative;
            if (!file_exists($path)) {
                // Commonly removed by hardening guides; reported but not treated as compromise.
                if (!in_array($relative, array('wp-config-sample.php', 'readme.html', 'license.txt', 'wp-admin/install.php'), true)) {
                    awd_integrity_push($missing, $relative, $truncated);
                }
                continue;
            }
            $checked++;
            if (!is_link($path) && @md5_file($path) !== (string) $expected) {
                awd_integrity_push($modified, $relative, $truncated);
                if (awd_integrity_is_executable_name($relative)) $to_scan[] = $path;
            }
        }
        foreach (array('', 'wp-admin', 'wp-includes') as $area) {
            $dir = $root . $area;
            $candidates = $area === ''
                ? array_filter((array) @glob($root . '*'), 'is_file')
                : awd_integrity_find_executables($dir, $deadline, 20000, $partial);
            foreach ($candidates as $path) {
                $relative = awd_integrity_relative((string) $path, $root);
                if (!awd_integrity_is_executable_name($relative) || isset($checksums[$relative])) continue;
                if ($area === '' && $relative === 'wp-config.php') continue;
                awd_integrity_push($unknown_php, $relative, $truncated);
                $to_scan[] = (string) $path;
            }
        }
    }

    $root_files = array();
    $known_root = array('wp-config.php', '.htaccess', '.user.ini', 'php.ini', 'robots.txt', 'favicon.ico', 'error_log', '.maintenance', 'ads.txt', 'web.config');
    foreach ((array) @scandir($root) as $name) {
        if (!is_string($name) || $name === '.' || $name === '..' || is_dir($root . $name)) continue;
        if (is_array($checksums) && isset($checksums[$name])) continue;
        if (in_array($name, $known_root, true) || preg_match('/^google[0-9a-f]+\.html$/i', $name)) continue;
        awd_integrity_push($root_files, $name, $truncated);
    }
    // index.php and wp-config.php are where loaders are usually injected.
    foreach (array('index.php', 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php') as $entry) {
        if (is_file($root . $entry)) $to_scan[] = $root . $entry;
    }

    $uploads_php = array();
    foreach (awd_integrity_find_executables($uploads_dir, $deadline, 100000, $partial) as $path) {
        // An index.php containing only a "silence is golden" comment is a common, harmless directory guard.
        if (basename($path) === 'index.php' && @filesize($path) !== false && @filesize($path) < 100) continue;
        awd_integrity_push($uploads_php, awd_integrity_relative($path, $root), $truncated);
        $to_scan[] = $path;
    }

    $mu_plugins = array();
    if (is_dir($mu_dir)) {
        foreach (awd_integrity_find_executables($mu_dir, $deadline, 2000, $partial) as $path) {
            awd_integrity_push($mu_plugins, awd_integrity_relative($path, $root), $truncated);
            $to_scan[] = $path;
        }
    }
    $dropins = array('advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'index.php');
    $content_root_php = array();
    foreach ((array) @glob($content_dir . '/*') as $path) {
        if (!is_string($path) || !is_file($path) || !awd_integrity_is_executable_name($path)) continue;
        if (!in_array(basename($path), $dropins, true)) awd_integrity_push($content_root_php, awd_integrity_relative($path, $root), $truncated);
        $to_scan[] = $path;
    }
    foreach ($theme_dirs as $theme_dir) {
        foreach ((array) @glob(rtrim($theme_dir, '/\\') . '/*.php') as $path) {
            if (is_string($path)) $to_scan[] = $path;
        }
    }

    $suspicious = array();
    foreach (array_unique($to_scan) as $path) {
        if (microtime(true) > $deadline) { $partial = true; break; }
        $signatures = awd_integrity_scan_file($path);
        if ($signatures) awd_integrity_push($suspicious, array('path' => awd_integrity_relative($path, $root), 'signatures' => $signatures), $truncated);
    }

    $htaccess = array('present' => false);
    if (is_file($root . '.htaccess') && is_readable($root . '.htaccess')) {
        $content = (string) @file_get_contents($root . '.htaccess', false, null, 0, 262144);
        $htaccess = array(
            'present' => true,
            'bytes' => strlen($content),
            'sha256' => hash('sha256', $content),
            'hasWordPressBlock' => (bool) preg_match('/#\s*BEGIN WordPress/i', $content),
            'suspiciousLines' => awd_integrity_htaccess_analysis($content),
        );
    }

    $robots = array('present' => false);
    if (is_file($root . 'robots.txt') && is_readable($root . 'robots.txt')) {
        $content = (string) @file_get_contents($root . 'robots.txt', false, null, 0, 65536);
        preg_match_all('/^\s*sitemap\s*:\s*(\S+)/im', $content, $matches);
        $robots = array('present' => true, 'bytes' => strlen($content), 'sitemapEntries' => count($matches[1] ?? array()));
    }

    // Content digests bind a later cleanup approval to the exact file that was reviewed.
    $file_hashes = array();
    $hash_paths = array_merge(
        array_column($suspicious, 'path'), $modified, $unknown_php, $uploads_php, $mu_plugins, $content_root_php, $root_files,
        is_file($root . 'robots.txt') ? array('robots.txt') : array()
    );
    foreach (array_unique($hash_paths) as $relative) {
        if (count($file_hashes) >= 150) { $truncated = true; break; }
        $path = $root . $relative;
        if (is_file($path) && !is_link($path) && is_readable($path)) {
            $digest = @hash_file('sha256', $path);
            if (is_string($digest)) $file_hashes[$relative] = $digest;
        }
    }

    return array(
        'scannedAt' => gmdate('c'),
        'status' => !is_array($checksums) ? 'checksums_unavailable' : ($partial ? 'partial' : 'complete'),
        'durationMs' => (int) round((microtime(true) - $started) * 1000),
        'core' => array(
            'version' => substr((string) ($context['version'] ?? ''), 0, 40),
            'locale' => substr((string) ($context['locale'] ?? ''), 0, 20),
            'checksumsAvailable' => is_array($checksums),
            'checkedFiles' => $checked,
            'modified' => $modified,
            'missing' => $missing,
            'unknownPhp' => $unknown_php,
        ),
        'rootUnknownFiles' => $root_files,
        'uploadsPhp' => $uploads_php,
        'muPlugins' => $mu_plugins,
        'contentRootPhp' => $content_root_php,
        'suspiciousFiles' => $suspicious,
        'htaccess' => $htaccess,
        'robotsFile' => $robots,
        'admins' => $context['admins'] ?? array('count' => 0, 'recent' => array()),
        'fileHashes' => (object) $file_hashes,
        'truncated' => $truncated,
    );
}

function awd_integrity_core_checksums(): ?array
{
    $version = (string) get_bloginfo('version');
    $cached = get_option(AWD_INTEGRITY_OPTION . '_checksums');
    if (is_array($cached) && ($cached['version'] ?? '') === $version && is_array($cached['checksums'] ?? null)) {
        return $cached['checksums'];
    }
    if (!function_exists('get_core_checksums')) {
        if (!file_exists(ABSPATH . 'wp-admin/includes/update.php')) return null;
        require_once ABSPATH . 'wp-admin/includes/update.php';
    }
    if (!function_exists('get_core_checksums')) return null;
    $locale = function_exists('get_locale') ? (string) get_locale() : 'en_US';
    $checksums = get_core_checksums($version, $locale ?: 'en_US');
    if (!is_array($checksums) && $locale !== 'en_US') $checksums = get_core_checksums($version, 'en_US');
    if (!is_array($checksums) || !$checksums) return null;
    update_option(AWD_INTEGRITY_OPTION . '_checksums', array('version' => $version, 'checksums' => $checksums), false);
    return $checksums;
}

function awd_integrity_admins(): array
{
    if (!function_exists('get_users')) return array('count' => 0, 'recent' => array());
    $admins = get_users(array('role' => 'administrator', 'fields' => array('user_login', 'user_registered'), 'number' => 200));
    $recent = array();
    $cutoff = time() - 30 * 86400;
    foreach ((array) $admins as $admin) {
        $registered = strtotime((string) ($admin->user_registered ?? '') . ' UTC');
        if ($registered !== false && $registered >= $cutoff) {
            $recent[] = array('login' => substr(sanitize_text_field((string) $admin->user_login), 0, 60), 'registeredAt' => gmdate('c', $registered));
        }
    }
    return array('count' => count((array) $admins), 'recent' => array_slice($recent, 0, 20));
}

/** Cached integrity report for this site; $force reruns the scan. $plugins enables WordPress.org plugin checksum checks. */
function awd_integrity_report(bool $force = false, array $plugins = array()): array
{
    $cached = get_option(AWD_INTEGRITY_OPTION);
    if (!$force && is_array($cached) && isset($cached['scannedAt']) && strtotime((string) $cached['scannedAt']) > time() - AWD_INTEGRITY_MAX_AGE) {
        return $cached;
    }
    $theme_dirs = array();
    if (function_exists('get_stylesheet_directory')) $theme_dirs[] = (string) get_stylesheet_directory();
    if (function_exists('get_template_directory')) $theme_dirs[] = (string) get_template_directory();
    $uploads = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : array();
    $report = awd_integrity_scan(ABSPATH, awd_integrity_core_checksums(), array(
        'contentDir' => defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content',
        'uploadsDir' => is_array($uploads) && !empty($uploads['basedir']) ? (string) $uploads['basedir'] : null,
        'muPluginsDir' => defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : null,
        'themeDirs' => $theme_dirs,
        'admins' => awd_integrity_admins(),
        'version' => (string) get_bloginfo('version'),
        'locale' => function_exists('get_locale') ? (string) get_locale() : 'en_US',
    ));
    if (function_exists('awd_plugin_integrity_report') && $plugins) $report['pluginIntegrity'] = awd_plugin_integrity_report($plugins, $force);
    update_option(AWD_INTEGRITY_OPTION, $report, false);
    return $report;
}

function awd_integrity_list_preview(array $items, int $limit = 5): string
{
    $names = array_map(static function ($item) { return is_array($item) ? (string) ($item['path'] ?? '') : (string) $item; }, array_slice($items, 0, $limit));
    return implode(', ', $names) . (count($items) > $limit ? sprintf(' and %d more', count($items) - $limit) : '');
}

/** Issues derived from an integrity report, most severe first. */
function awd_integrity_issues(array $report): array
{
    $issues = array();
    $suspicious = (array) ($report['suspiciousFiles'] ?? array());
    if ($suspicious) {
        $issues[] = array(
            'fingerprint' => 'integrity:malware-signatures',
            'title' => sprintf('Malware code patterns found in %d file(s)', count($suspicious)),
            'description' => 'Code patterns used by web shells, backdoors, and SEO-spam loaders were found in: ' . awd_integrity_list_preview(array_map(static function ($item) { return $item['path'] . ' [' . implode(', ', $item['signatures']) . ']'; }, $suspicious)) . '. Treat the site as compromised; quarantine the files after taking a backup and replace core files from an official release.',
            'severity' => 'critical',
        );
    }
    $modified = (array) ($report['core']['modified'] ?? array());
    if ($modified) {
        $issues[] = array(
            'fingerprint' => 'integrity:core-modified',
            'title' => sprintf('%d WordPress core file(s) differ from the official release', count($modified)),
            'description' => 'These files do not match the WordPress.org checksums for this version: ' . awd_integrity_list_preview($modified) . '. Core files should never be edited; a modified index.php or wp-includes file usually means an injected loader. Restore them from the official release.',
            'severity' => 'critical',
        );
    }
    $htaccess_lines = (array) ($report['htaccess']['suspiciousLines'] ?? array());
    if ($htaccess_lines) {
        $reasons = array_values(array_unique(array_column($htaccess_lines, 'reason')));
        $cloaking = (bool) array_intersect($reasons, array('crawler_condition', 'search_referrer_condition', 'auto_prepend_file'));
        $issues[] = array(
            'fingerprint' => 'integrity:htaccess',
            'title' => '.htaccess contains rules typical of an injection',
            'description' => sprintf('%d rule(s) outside the WordPress block look injected (%s), for example line %d: %s', count($htaccess_lines), implode(', ', $reasons), (int) $htaccess_lines[0]['line'], (string) $htaccess_lines[0]['text']),
            'severity' => $cloaking ? 'critical' : 'high',
        );
    }
    $unknown = (array) ($report['core']['unknownPhp'] ?? array());
    if ($unknown) {
        $issues[] = array(
            'fingerprint' => 'integrity:unknown-core-php',
            'title' => sprintf('%d unknown PHP file(s) in WordPress core directories', count($unknown)),
            'description' => 'These PHP files are not part of WordPress ' . (string) get_bloginfo('version') . ' but sit in the site root, wp-admin or wp-includes: ' . awd_integrity_list_preview($unknown) . '. Attackers drop loaders here because these directories are rarely inspected.',
            'severity' => 'high',
        );
    }
    $uploads = (array) ($report['uploadsPhp'] ?? array());
    if ($uploads) {
        $issues[] = array(
            'fingerprint' => 'integrity:uploads-php',
            'title' => sprintf('%d executable file(s) in the uploads directory', count($uploads)),
            'description' => 'The uploads directory should contain media only, but holds: ' . awd_integrity_list_preview($uploads) . '. Executable files here are a common web-shell location.',
            'severity' => 'high',
        );
    }
    $content_root = (array) ($report['contentRootPhp'] ?? array());
    if ($content_root) {
        $issues[] = array(
            'fingerprint' => 'integrity:content-root-php',
            'title' => sprintf('%d unexpected PHP file(s) directly in wp-content', count($content_root)),
            'description' => 'These files are not WordPress drop-ins: ' . awd_integrity_list_preview($content_root) . '. Confirm each one belongs to a known plugin or host tool.',
            'severity' => 'medium',
        );
    }
    if (!empty($report['robotsFile']['present']) && (int) ($report['robotsFile']['sitemapEntries'] ?? 0) >= 5) {
        $issues[] = array(
            'fingerprint' => 'integrity:robots-file',
            'title' => 'A physical robots.txt advertises many sitemaps',
            'description' => sprintf('robots.txt in the site root lists %d sitemaps. WordPress generates robots.txt virtually; a physical file listing many numbered sitemaps is typical of SEO-spam injection.', (int) $report['robotsFile']['sitemapEntries']),
            'severity' => 'high',
        );
    }
    if (function_exists('awd_plugin_integrity_issues')) {
        foreach (awd_plugin_integrity_issues((array) ($report['pluginIntegrity'] ?? array())) as $plugin_issue) $issues[] = $plugin_issue;
    }
    $recent_admins = (array) ($report['admins']['recent'] ?? array());
    if ($recent_admins) {
        $issues[] = array(
            'fingerprint' => 'integrity:recent-admin',
            'title' => sprintf('%d administrator account(s) created in the last 30 days', count($recent_admins)),
            'description' => 'Recently created administrators: ' . implode(', ', array_map(static function ($admin) { return $admin['login'] . ' (' . substr((string) $admin['registeredAt'], 0, 10) . ')'; }, $recent_admins)) . '. Confirm each account was created intentionally; attackers add administrators to keep access after a cleanup.',
            'severity' => 'medium',
        );
    }
    return $issues;
}
