<?php

define('ABSPATH', __DIR__ . '/fixtures/wordpress/');
define('WP_CONTENT_DIR', __DIR__ . '/fixtures/wordpress/wp-content');
define('WP_PLUGIN_DIR', __DIR__ . '/fixtures/problematic-wordpress');
define('WP_DEBUG', true);
define('DISABLE_WP_CRON', true);
define('HOUR_IN_SECONDS', 3600);

function add_action(...$arguments): void {}
function add_filter(...$arguments): void {}
function register_activation_hook(...$arguments): void {}
function register_deactivation_hook(...$arguments): void {}
function sanitize_text_field(string $value): string { return trim(strip_tags($value)); }
function sanitize_textarea_field(string $value): string { return trim(strip_tags($value)); }
function sanitize_key(string $value): string { return strtolower(preg_replace('/[^a-z0-9_-]/', '', $value)); }
function wp_json_encode($value, int $flags = 0): string|false { return json_encode($value, $flags); }
function get_option(string $name, $default = false) { return $GLOBALS['awd_fixture_options'][$name] ?? $default; }
function update_option(string $name, $value, $autoload = null): bool { $GLOBALS['awd_fixture_options'][$name] = $value; return true; }
function wp_generate_uuid4(): string { static $counter = 0; return 'fixture-recovery-point-' . ++$counter; }
function wp_get_environment_type(): string { return $GLOBALS['awd_fixture_environment_type'] ?? 'production'; }
function wp_get_custom_css(string $stylesheet = ''): string { return $GLOBALS['awd_fixture_custom_css'] ?? ''; }
function wp_update_custom_css_post(string $css, array $args = array()): object { $GLOBALS['awd_fixture_custom_css'] = $css; return (object) array('post_name' => $args['stylesheet'] ?? 'fixture-theme'); }
class WP_Error
{
    public function __construct(public string $code = '', public string $message = '') {}
}
function is_wp_error($value): bool { return $value instanceof WP_Error; }
function get_plugins(): array { return $GLOBALS['awd_fixture_plugins']; }
function get_posts(array $args = array()): array { return array(); }
function get_site_transient(string $name) { return (object) array('response' => $GLOBALS['awd_fixture_updates']); }
function get_bloginfo(string $name): string { return $name === 'version' ? '6.8' : 'Fixture WordPress'; }
function wp_get_theme() { return new class {
    public function get(string $key): string { return array('Name' => 'Fixture theme', 'Version' => '1.0', 'stylesheet' => 'fixture-theme')[$key] ?? ''; }
    public function get_stylesheet(): string { return 'fixture-theme'; }
}; }
function _get_cron_array(): array { return array($GLOBALS['awd_fixture_cron_time'] => array('fixture_failed_task' => array(array('schedule' => 'hourly', 'args' => array())))); }
function esc_url_raw(string $url, array $protocols = array()): string { return $url; }
function wp_parse_url(string $url): array|false { return parse_url($url); }
function untrailingslashit(string $url): string { return rtrim($url, '/'); }
function wp_generate_password(int $length = 12, bool $special = true, bool $extra = false): string { return substr(bin2hex(random_bytes(32)), 0, $length); }
function wp_upload_dir($time = null, bool $create = true): array { return $GLOBALS['awd_fixture_uploads'] ?? array(); }

require dirname(__DIR__) . '/ai-website-doctor.php';

function awd_test_assert(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$manifest = json_decode((string) file_get_contents(dirname(__DIR__) . '/composer.json'), true);
$readme = (string) file_get_contents(dirname(__DIR__) . '/readme.txt');
awd_test_assert(is_array($manifest) && ($manifest['version'] ?? null) === AWD_VERSION, 'plugin header and Composer versions must match');
awd_test_assert((bool) preg_match('/^Stable tag: ' . preg_quote(AWD_VERSION, '/') . '$/m', $readme), 'plugin header and readme stable tag must match');

$valid_operations = array(
    array('operation' => 'disable_plugin', 'parameters' => array('plugin' => 'hello/hello.php')),
    array('operation' => 'update_setting', 'parameters' => array('option' => 'blogname', 'expectedCurrentValue' => 'Old', 'value' => 'Example')),
    array('operation' => 'switch_theme', 'parameters' => array('stylesheet' => 'theme_2025')),
    array('operation' => 'add_scoped_css_rule', 'parameters' => array('selector' => 'body.page-id-42 #wide-image')),
);
foreach ($valid_operations as $operation) {
    $operation['description'] = 'Test allowlisted operation';
    awd_test_assert(awd_step_is_allowed($operation), 'expected supported operation to be allowed');
}

$invalid_operations = array(
    array('operation' => 'run_shell', 'parameters' => array('command' => 'id')),
    array('operation' => 'clear_cache', 'parameters' => array()),
    array('operation' => 'disable_plugin', 'parameters' => array('plugin' => '../../wp-config.php')),
    array('operation' => 'disable_plugin', 'parameters' => array('plugin' => 'plugin/../wp-config.php')),
    array('operation' => 'update_setting', 'parameters' => array('option' => 'admin_email', 'expectedCurrentValue' => 'old@example.com', 'value' => 'attacker@example.com')),
    array('operation' => 'clear_cache', 'parameters' => array('all' => 'true')),
    array('operation' => 'switch_theme', 'parameters' => array('stylesheet' => '../theme')),
    array('operation' => 'add_scoped_css_rule', 'parameters' => array('selector' => 'body.page-id-42 #wide-image; body { display:none }')),
);
foreach ($invalid_operations as $operation) {
    $operation['description'] = 'Test invalid operation';
    awd_test_assert(!awd_step_is_allowed($operation), 'unsafe or unsupported operation was allowed');
}
awd_test_assert(awd_css_selector_is_allowed('body.postid-42 .hero-image'), 'a page-scoped simple CSS selector should be accepted');
awd_test_assert(!awd_css_selector_is_allowed('body.page-id-42 img'), 'unscoped element selectors should not be accepted');
awd_test_assert(
    awd_agent_request_signature(
        'per-installation-secret',
        'POST',
        '/api/agents/agent-1/diagnostics',
        '1793640000',
        '0123456789abcdef0123456789abcdef',
        '{"ok":true}'
    ) === '204aeb006ba4dda7c697614ea8839f6b58ed85bf2f39fb714f8e490210d5ff25',
    'PHP and central request-signing formats must remain compatible'
);
awd_test_assert(!awd_step_is_allowed(array(
    'description' => 'Clear cache',
    'operation' => 'disable_plugin',
    'parameters' => array('plugin' => 'hello/hello.php'),
    'code' => 'arbitrary PHP',
)), 'unknown operation fields must be rejected');
awd_test_assert(!awd_step_is_allowed(array(
    'description' => str_repeat('x', 501),
    'operation' => 'disable_plugin',
    'parameters' => array('plugin' => 'hello/hello.php'),
)), 'oversized operation descriptions must be rejected');

$GLOBALS['awd_fixture_options'] = array(
    'active_plugins' => array('fixture-conflict/fixture-conflict.php'),
    'stylesheet' => 'fixture-theme',
    'blogname' => 'Fixture site',
    'blogdescription' => 'Diagnostic fixture',
    AWD_FATAL_OPTION => array(array('id' => 'fatal-fixture', 'observedAt' => gmdate('c'), 'type' => 'E_ERROR', 'message' => 'Undefined function in [PATH]', 'file' => 'fatal-plugin.php', 'line' => 17)),
);
$GLOBALS['awd_fixture_cron_time'] = time() - HOUR_IN_SECONDS - 60;
$GLOBALS['awd_fixture_options'][AWD_CRON_HISTORY_OPTION] = array(array(
    'id' => substr(hash('sha256', 'fixture_failed_task:' . $GLOBALS['awd_fixture_cron_time'] . ':0'), 0, 32),
    'hook' => 'fixture_failed_task',
    'scheduledAt' => gmdate('c', $GLOBALS['awd_fixture_cron_time']),
    'status' => 'failed',
    'startedAt' => gmdate('c', time() - 50),
    'completedAt' => gmdate('c', time() - 49),
    'failure' => array('type' => 'E_ERROR', 'message' => 'fixture task failed'),
));
$GLOBALS['awd_fixture_plugins'] = array(
    'fixture-conflict/fixture-conflict.php' => array('Name' => 'Fixture conflict plugin', 'Version' => '1.0'),
);
$GLOBALS['awd_fixture_updates'] = array('fixture-conflict/fixture-conflict.php' => (object) array('new_version' => '1.1'));
$fixture_log = WP_CONTENT_DIR . '/debug.log';
awd_test_assert(copy(__DIR__ . '/fixtures/wordpress/wp-content/debug-log.fixture', $fixture_log), 'fatal log fixture must be available');
$diagnostics = awd_collect_diagnostics(array('collect_logs' => true));
$detected_fingerprints = array_column($diagnostics['issues'], 'fingerprint');
foreach (array('wp-debug-enabled', 'wp-cron-disabled', 'overdue-wp-cron', 'plugin-update:' . substr(hash('sha256', 'fixture-conflict/fixture-conflict.php'), 0, 20)) as $fingerprint) {
    awd_test_assert(in_array($fingerprint, $detected_fingerprints, true), 'WordPress diagnostics should detect fixture finding ' . $fingerprint);
}
foreach (array('php-fatal:fatal-fixture', 'cron-failed:' . substr(hash('sha256', 'fixture_failed_task:' . $GLOBALS['awd_fixture_cron_time'] . ':0'), 0, 32)) as $fingerprint) {
    awd_test_assert(in_array($fingerprint, $detected_fingerprints, true), 'structured diagnostics should report ' . $fingerprint);
}
awd_test_assert(($diagnostics['scheduledTasks'][0]['status'] ?? '') === 'failed', 'a failed cron outcome must be distinct from overdue state');
awd_test_assert(($diagnostics['scheduledTasks'][0]['overdue'] ?? false) === true, 'cron overdue state must be separately recorded');
awd_test_assert(($diagnostics['conflictTesting']['status'] ?? '') === 'not_run', 'live diagnostics must not claim a conflict test was run');
awd_test_assert(($diagnostics['conflictTesting']['liveDeactivationPerformed'] ?? true) === false, 'live diagnostics must not deactivate components');
$GLOBALS['awd_fixture_environment_type'] = 'staging';
$GLOBALS['awd_fixture_custom_css'] = 'body { color: #222; }';
$css_step = array(
    'description' => 'Constrain a measured overflowing element on staging.',
    'operation' => 'add_scoped_css_rule',
    'parameters' => array('selector' => 'body.page-id-42 #wide-image'),
);
$css_backup = awd_create_recovery_point('Staging responsive layout repair', array($css_step));
awd_test_assert(awd_recovery_point_exists($css_backup), 'staging CSS operation must save a complete recovery point');
$css_apply = awd_apply_steps(array($css_step), $css_backup);
awd_test_assert($css_apply === true, 'approved scoped CSS operation should apply on staging');
awd_test_assert(str_contains($GLOBALS['awd_fixture_custom_css'], 'body.page-id-42 #wide-image { max-width: 100%; }'), 'staging operation should add only the bounded max-width declaration');
awd_test_assert(awd_restore_recovery_point($css_backup) === true, 'scoped CSS operation should restore its exact prior value');
awd_test_assert($GLOBALS['awd_fixture_custom_css'] === 'body { color: #222; }', 'CSS rollback should restore the exact prior stylesheet');
$GLOBALS['awd_fixture_environment_type'] = 'production';
$production_backup = awd_create_recovery_point('Production CSS repair must be blocked', array($css_step));
awd_test_assert(!awd_recovery_point_exists($production_backup), 'CSS repair recovery points must not be created outside staging');
awd_test_assert(is_wp_error(awd_apply_steps(array($css_step), $production_backup)), 'CSS repair execution must be rejected outside staging');
awd_test_assert($GLOBALS['awd_fixture_custom_css'] === 'body { color: #222; }', 'a production CSS operation must leave custom CSS unchanged');
$GLOBALS['awd_fixture_environment_type'] = 'staging';
$stale_css_backup = awd_create_recovery_point('Stale staging CSS must be preserved', array($css_step));
awd_test_assert(awd_apply_steps(array($css_step), $stale_css_backup) === true, 'second staging CSS repair should apply');
$GLOBALS['awd_fixture_custom_css'] .= '.newer-change { color: red; }';
$css_with_newer_change = $GLOBALS['awd_fixture_custom_css'];
awd_test_assert(is_wp_error(awd_restore_recovery_point($stale_css_backup)), 'CSS rollback must refuse to overwrite a newer edit');
awd_test_assert($GLOBALS['awd_fixture_custom_css'] === $css_with_newer_change, 'a newer CSS edit must remain untouched after rollback is refused');
$GLOBALS['awd_current_cron_event'] = array('id' => 'application-failure-test', 'hook' => 'fixture_task', 'scheduledAt' => gmdate('c'), 'status' => 'running', 'startedAt' => gmdate('c'));
awd_report_scheduled_task_failure('Caught exception: fixture failure', 'fixture_exception');
$reported_failure = end($GLOBALS['awd_fixture_options'][AWD_CRON_HISTORY_OPTION]);
awd_test_assert(($reported_failure['status'] ?? '') === 'failed', 'explicit task reporting should preserve caught/application failures');
awd_test_assert(($reported_failure['failure']['source'] ?? '') === 'application_report', 'explicit failures should identify their reporting source');
awd_test_assert(($reported_failure['failure']['type'] ?? '') === 'fixture_exception', 'explicit failures should preserve a safe error code');
awd_test_assert(str_contains($diagnostics['authorizedLogExcerpt'] ?? '', 'PHP Fatal error'), 'opted-in log evidence should include the fixture fatal error');
awd_test_assert(count($diagnostics['phpErrors'] ?? array()) === 2, 'opted-in diagnostics should parse bounded fatal and warning records');
awd_test_assert(($diagnostics['phpErrorLog']['status'] ?? '') === 'readable', 'opted-in diagnostics should report a readable log control');
awd_test_assert(in_array('php-log:' . ($diagnostics['phpErrors'][1]['id'] ?? ''), $detected_fingerprints, true), 'parsed PHP warnings should become structured WordPress findings');
awd_test_assert(($diagnostics['phpErrors'][1]['file'] ?? '') === 'plugin.php' && ($diagnostics['phpErrors'][1]['line'] ?? 0) === 42, 'PHP log evidence should retain only the basename and line number');
awd_test_assert(!str_contains($diagnostics['authorizedLogExcerpt'] ?? '', 'fixture-secret'), 'opted-in log evidence must redact the fixture credential');
unlink($fixture_log);
$task = array(
    'issueFingerprint' => 'wp:wp-cron-disabled',
    'baselineHighSeverityIssues' => array('existing-fatal'),
);
$passed = awd_verify_repair_diagnostics($task, array('issues' => array()));
awd_test_assert($passed['status'] === 'passed', 'resolved original issue and clean diagnostics should pass');
$failed = awd_verify_repair_diagnostics($task, array('issues' => array(
    array('fingerprint' => 'wp-cron-disabled', 'severity' => 'medium'),
)));
awd_test_assert($failed['status'] === 'failed', 'original issue remaining must fail verification');
$regression = awd_verify_repair_diagnostics($task, array('issues' => array(
    array('fingerprint' => 'new-fatal', 'severity' => 'critical'),
)));
awd_test_assert($regression['status'] === 'failed', 'new severe diagnostic must fail verification');
$inconclusive = awd_verify_repair_diagnostics($task, array());
awd_test_assert($inconclusive['status'] === 'inconclusive', 'missing diagnostics must be inconclusive');

$valid_urls = array('https://doctor.example', 'https://doctor.example:8443/', 'http://localhost:3000', 'http://127.0.0.1:3000');
foreach ($valid_urls as $url) {
    awd_test_assert(awd_safe_central_url($url) !== null, 'expected valid central URL to be allowed');
}

$invalid_urls = array('http://doctor.example', 'https://user@doctor.example', 'https://doctor.example/path', 'https://doctor.example/?query=1');
foreach ($invalid_urls as $url) {
    awd_test_assert(awd_safe_central_url($url) === null, 'unsafe central URL was allowed');
}

// Integrity scan against an inert compromised fixture tree.
$compromised_root = __DIR__ . '/fixtures/compromised-wordpress/';
$fixture_checksums = array(
    'index.php' => md5('original WordPress index.php'),
    'wp-includes/version.php' => md5_file($compromised_root . 'wp-includes/version.php'),
    'wp-admin/about.php' => md5_file($compromised_root . 'wp-admin/about.php'),
    'wp-load.php' => md5('missing'),
    'wp-content/index.php' => md5('ignored'),
);
$integrity = awd_integrity_scan($compromised_root, $fixture_checksums, array(
    'themeDirs' => array($compromised_root . 'wp-content/themes/fixture'),
    'admins' => array('count' => 2, 'recent' => array(array('login' => 'wpsupport', 'registeredAt' => gmdate('c')))),
));
awd_test_assert($integrity['status'] === 'complete', 'integrity scan should complete on the fixture tree');
awd_test_assert($integrity['core']['modified'] === array('index.php'), 'modified core index.php must be detected');
awd_test_assert($integrity['core']['missing'] === array('wp-load.php'), 'missing core file must be reported');
awd_test_assert(in_array('wp-includes/class-wp-cache-loader.php', $integrity['core']['unknownPhp'], true), 'unknown PHP in wp-includes must be detected');
awd_test_assert(!in_array('wp-admin/about.php', $integrity['core']['unknownPhp'], true), 'known core files must not be unknown');
awd_test_assert($integrity['uploadsPhp'] === array('wp-content/uploads/2026/11/thumb.php'), 'PHP in uploads must be detected; a tiny index.php guard is ignored');
$suspicious_paths = array_column($integrity['suspiciousFiles'], 'signatures', 'path');
awd_test_assert(isset($suspicious_paths['index.php']) && in_array('eval_encoded_payload', $suspicious_paths['index.php'], true), 'encoded eval loader must be flagged');
awd_test_assert(isset($suspicious_paths['wp-includes/class-wp-cache-loader.php']), 'request-called function must be flagged');
awd_test_assert(isset($suspicious_paths['wp-content/uploads/2026/11/thumb.php']) && in_array('request_code_execution', $suspicious_paths['wp-content/uploads/2026/11/thumb.php'], true), 'uploads web shell must be flagged');
awd_test_assert(!isset($suspicious_paths['wp-content/themes/fixture/functions.php']), 'a single weak pattern in a theme must not be flagged');
awd_test_assert(!isset($suspicious_paths['wp-admin/about.php']), 'clean core files must not be flagged');
$htaccess_reasons = array_column($integrity['htaccess']['suspiciousLines'], 'reason');
awd_test_assert(in_array('crawler_condition', $htaccess_reasons, true) && in_array('auto_prepend_file', $htaccess_reasons, true), 'injected .htaccess rules must be detected');
awd_test_assert(count($integrity['htaccess']['suspiciousLines']) === 3, 'WordPress-managed .htaccess rules must not be reported');
awd_test_assert($integrity['robotsFile']['sitemapEntries'] === 6, 'physical robots.txt sitemaps must be counted');
awd_test_assert(in_array('sitemap-1.xml', $integrity['rootUnknownFiles'], true), 'unknown root files must be listed');
$integrity_fingerprints = array_column(awd_integrity_issues($integrity), 'severity', 'fingerprint');
foreach (array('integrity:malware-signatures' => 'critical', 'integrity:core-modified' => 'critical', 'integrity:htaccess' => 'critical', 'integrity:unknown-core-php' => 'high', 'integrity:uploads-php' => 'high', 'integrity:robots-file' => 'high', 'integrity:recent-admin' => 'medium') as $fingerprint => $severity) {
    awd_test_assert(($integrity_fingerprints[$fingerprint] ?? null) === $severity, "integrity issue {$fingerprint} must be {$severity}");
}
$clean = awd_integrity_scan(__DIR__ . '/fixtures/wordpress/', null);
awd_test_assert($clean['status'] === 'checksums_unavailable' && awd_integrity_issues($clean) === array(), 'without checksums the scan must not invent core findings');
awd_test_assert(isset($diagnostics['integrity']['status']), 'diagnostics must include the integrity report');

// Cleanup operations against a temporary copy of the compromised fixture.
function awd_test_copy_tree(string $from, string $to): void
{
    @mkdir($to, 0755, true);
    foreach (scandir($from) as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        is_dir("$from/$entry") ? awd_test_copy_tree("$from/$entry", "$to/$entry") : copy("$from/$entry", "$to/$entry");
    }
}
$work = sys_get_temp_dir() . '/awd-cleanup-test-' . bin2hex(random_bytes(4));
awd_test_copy_tree(rtrim($compromised_root, '/'), $work . '/site');
$site = realpath($work . '/site') . '/';
mkdir($work . '/quarantine', 0700);
$GLOBALS['awd_fixture_uploads'] = array('basedir' => $site . 'wp-content/uploads');
$official_index = "<?php\ndefine('WP_USE_THEMES', true);\nrequire __DIR__ . '/wp-blog-header.php';\n";
$checksums = array('index.php' => md5($official_index), 'wp-includes/version.php' => md5_file($site . 'wp-includes/version.php'), 'wp-admin/about.php' => md5_file($site . 'wp-admin/about.php'));
$scan = awd_integrity_scan($site, $checksums);
$hashes = (array) $scan['fileHashes'];
awd_test_assert(isset($hashes['index.php'], $hashes['wp-includes/class-wp-cache-loader.php'], $hashes['robots.txt']), 'integrity report must hash listed files');
awd_test_assert($scan['core']['locale'] === '' && array_key_exists('version', $scan['core']), 'integrity report must carry version and locale fields');
$htaccess_lines = implode(',', array_column($scan['htaccess']['suspiciousLines'], 'line'));
$steps = array(
    array('operation' => 'quarantine_file', 'parameters' => array('path' => 'wp-includes/class-wp-cache-loader.php', 'expectedSha256' => $hashes['wp-includes/class-wp-cache-loader.php'])),
    array('operation' => 'quarantine_file', 'parameters' => array('path' => 'wp-content/uploads/2026/11/thumb.php', 'expectedSha256' => $hashes['wp-content/uploads/2026/11/thumb.php'])),
    array('operation' => 'quarantine_file', 'parameters' => array('path' => 'robots.txt', 'expectedSha256' => $hashes['robots.txt'])),
    array('operation' => 'quarantine_file', 'parameters' => array('path' => 'sitemap-1.xml', 'expectedSha256' => str_repeat('0', 64))),
    array('operation' => 'restore_core_file', 'parameters' => array('path' => 'index.php', 'officialMd5' => md5($official_index), 'expectedCurrentSha256' => $hashes['index.php'])),
    array('operation' => 'remove_htaccess_rules', 'parameters' => array('expectedSha256' => $scan['htaccess']['sha256'], 'lines' => $htaccess_lines)),
);
foreach ($steps as $step) awd_test_assert(awd_cleanup_step_is_valid($step), 'cleanup step must validate: ' . $step['operation']);
foreach (array(
    array('operation' => 'quarantine_file', 'parameters' => array('path' => '../etc/passwd', 'expectedSha256' => str_repeat('a', 64))),
    array('operation' => 'quarantine_file', 'parameters' => array('path' => '/etc/passwd', 'expectedSha256' => str_repeat('a', 64))),
    array('operation' => 'quarantine_file', 'parameters' => array('path' => 'x.php', 'expectedSha256' => 'short')),
    array('operation' => 'run_php', 'parameters' => array()),
    array('operation' => 'quarantine_plugin', 'parameters' => array('plugin' => 'ai-website-doctor/ai-website-doctor.php', 'expectedVersion' => '0.3.0')),
    array('operation' => 'rotate_salts', 'parameters' => array('extra' => 'x')),
    array('operation' => 'demote_user', 'parameters' => array('login' => 'x', 'expectedRole' => 'editor')),
) as $bad) awd_test_assert(!awd_cleanup_step_is_valid($bad), 'unsafe cleanup step must be rejected: ' . $bad['operation']);
$fetches = 0;
$results = awd_cleanup_execute_steps('fixture-run-0001', 'repair-1', $steps, array(
    'root' => $site, 'quarantineDir' => $work . '/quarantine', 'checksums' => $checksums, 'wpVersion' => '9.9',
    'fetchCoreFile' => static function ($version, $path) use ($official_index, &$fetches) { $fetches++; return $official_index; },
));
$statuses = array_column($results, 'status');
awd_test_assert($statuses === array('applied', 'applied', 'applied', 'failed', 'applied', 'applied'), 'cleanup statuses must match: ' . implode(',', $statuses));
awd_test_assert(!file_exists($site . 'wp-includes/class-wp-cache-loader.php') && !file_exists($site . 'robots.txt'), 'quarantined files must leave the site');
awd_test_assert(file_exists($site . 'sitemap-1.xml'), 'a file whose digest changed must be left in place');
awd_test_assert(file_get_contents($site . 'index.php') === $official_index && $fetches === 1, 'core index.php must be restored from the official copy');
$clean_htaccess = file_get_contents($site . '.htaccess');
awd_test_assert(!str_contains($clean_htaccess, 'HTTP_USER_AGENT') && !str_contains($clean_htaccess, 'wp-cache.php') && !str_contains($clean_htaccess, 'auto_prepend_file'), 'injected rewrite rule groups must be removed');
awd_test_assert(str_contains($clean_htaccess, '# BEGIN WordPress') && str_contains($clean_htaccess, 'RewriteRule . /index.php [L]'), 'WordPress block must be preserved');
$rescan = awd_integrity_scan($site, $checksums);
awd_test_assert($rescan['core']['modified'] === array() && $rescan['suspiciousFiles'] === array() && $rescan['uploadsPhp'] === array() && $rescan['htaccess']['suspiciousLines'] === array(), 'rescan after cleanup must be clean');
// Quarantine contents are inert copies outside the site.
awd_test_assert(count(glob($work . '/quarantine/fixture-run-0001/*.bin')) === 5, 'every change must leave an undo copy in the quarantine');
// Restore with a conflict: a new robots.txt was written after the cleanup.
file_put_contents($site . 'robots.txt', "User-agent: *\n");
$restored = awd_cleanup_restore_run('fixture-run-0001', array('root' => $site));
$restore_status = array_column($restored, 'status', 'operation');
awd_test_assert(file_get_contents($site . '.htaccess') === file_get_contents($compromised_root . '.htaccess'), 'restore must put back the exact previous .htaccess');
awd_test_assert(file_exists($site . 'wp-includes/class-wp-cache-loader.php') && file_get_contents($site . 'index.php') === file_get_contents($compromised_root . 'index.php'), 'restore must put back quarantined and replaced files');
awd_test_assert(file_get_contents($site . 'robots.txt') === "User-agent: *\n", 'restore must not overwrite a file created after the cleanup');
awd_test_assert(in_array('conflict', array_column($restored, 'status'), true), 'restore must report the conflict');
$second_restore = awd_cleanup_restore_run('fixture-run-0001', array('root' => $site));
awd_test_assert(!in_array('restored', array_column($second_restore, 'status'), true), 'a restore must not be applied twice');
// Denials.
awd_test_assert(awd_cleanup_quarantine_denial('index.php', $site, $checksums) !== null, 'core files cannot be quarantined');
awd_test_assert(awd_cleanup_quarantine_denial('wp-content/themes/fixture/functions.php', $site, $checksums) !== null, 'theme files are not quarantined');
awd_test_assert(awd_cleanup_quarantine_denial('wp-includes/class-wp-cache-loader.php', $site, $checksums) === null, 'unknown core-directory PHP can be quarantined');
awd_test_assert(awd_cleanup_quarantine_denial('wp-content/uploads/2026/11/photo.jpg', $site, $checksums) !== null, 'media in uploads cannot be quarantined');
// Salt rotation rewrites exactly the eight keys.
$config = "<?php\n";
foreach (explode(',', AWD_CLEANUP_SALT_KEYS) as $key) $config .= "define( '$key', 'old-$key' );\n";
$config .= "define('DB_NAME', 'keep');\n";
$counter = 0;
$rotated = awd_cleanup_rotate_salts_content($config, static function () use (&$counter) { return 'new-' . (++$counter); });
awd_test_assert($rotated !== null && !str_contains($rotated, 'old-') && str_contains($rotated, "define('DB_NAME', 'keep');") && $counter === 8, 'salt rotation must replace exactly the eight keys');
awd_test_assert(awd_cleanup_rotate_salts_content($config . "define('AUTH_KEY', 'dup');\n", static function () { return 'x'; }) === null, 'duplicate salt defines must refuse rotation');
// Purge removes the run's quarantine permanently.
update_option(AWD_CLEANUP_DIR_OPTION, $work . '/quarantine');
$purge = awd_cleanup_op_purge_quarantine(array('runId' => 'fixture-run-0001'), array());
awd_test_assert($purge['status'] === 'applied' && !is_dir($work . '/quarantine/fixture-run-0001'), 'purge must delete the run quarantine');
awd_cleanup_remove_tree($work);

// WordPress.org plugin checksum comparison and maintenance step validation.
$plugin_fixture = sys_get_temp_dir() . '/awd-plugin-fixture-' . bin2hex(random_bytes(4));
mkdir($plugin_fixture . '/inc', 0755, true);
file_put_contents($plugin_fixture . '/fixture.php', "<?php\n// official\n");
file_put_contents($plugin_fixture . '/readme.txt', "official readme\n");
file_put_contents($plugin_fixture . '/inc/backdoor.php', "<?php return;\n");
$official_plugin = array('fixture.php' => array(md5("<?php\n// official\n")), 'readme.txt' => array(md5('changed upstream'), md5("official readme\n")), 'inc/gone.php' => array(md5('x')));
$comparison = awd_plugin_compare_directory($plugin_fixture, $official_plugin);
awd_test_assert($comparison['modified'] === array() && $comparison['missing'] === 1 && $comparison['addedPhp'] === array('inc/backdoor.php'), 'plugin checksum comparison must accept any listed md5 and report added PHP');
file_put_contents($plugin_fixture . '/fixture.php', "<?php\n// tampered\n");
$comparison = awd_plugin_compare_directory($plugin_fixture, $official_plugin);
awd_test_assert($comparison['modified'] === array('fixture.php'), 'a tampered plugin file must be reported');
awd_cleanup_remove_tree($plugin_fixture);
$plugin_issues = awd_plugin_integrity_issues(array(array('plugin' => 'fixture/fixture.php', 'version' => '1.0', 'status' => 'modified', 'modified' => array('fixture.php'), 'addedPhp' => array('inc/backdoor.php'), 'missing' => 0)));
awd_test_assert(($plugin_issues[0]['fingerprint'] ?? '') === 'integrity:plugin-modified:fixture' && $plugin_issues[0]['severity'] === 'critical', 'a plugin with added PHP must be a critical integrity issue');
awd_test_assert(awd_plugin_slug('elementor/elementor.php') === 'elementor' && awd_plugin_slug('hello.php') === null, 'plugin slug must come from its directory');
foreach (array(
    array('operation' => 'update_plugin', 'parameters' => array('plugin' => 'elementor/elementor.php', 'expectedVersion' => '4.3.5', 'targetVersion' => '4.3.6')),
    array('operation' => 'reinstall_plugin', 'parameters' => array('plugin' => 'wordpress-seo/wp-seo.php', 'expectedVersion' => '28.8')),
    array('operation' => 'install_plugin', 'parameters' => array('slug' => 'wordfence', 'version' => '9.0.2', 'activate' => 'yes')),
) as $step) awd_test_assert(awd_cleanup_step_is_valid($step), 'maintenance step must validate: ' . $step['operation']);
foreach (array(
    array('operation' => 'update_plugin', 'parameters' => array('plugin' => 'ai-website-doctor/ai-website-doctor.php', 'expectedVersion' => '1', 'targetVersion' => '2')),
    array('operation' => 'update_plugin', 'parameters' => array('plugin' => 'hello.php', 'expectedVersion' => '1', 'targetVersion' => '2')),
    array('operation' => 'install_plugin', 'parameters' => array('slug' => '../x', 'version' => '1', 'activate' => 'yes')),
    array('operation' => 'reinstall_plugin', 'parameters' => array('plugin' => 'a/b.php', 'expectedVersion' => '1', 'extra' => 'x')),
) as $bad) awd_test_assert(!awd_cleanup_step_is_valid($bad), 'unsafe maintenance step must be rejected');

// Protection: crawler gate decisions, .htaccess block handling, trusted-block detection, alert de-duplication.
$verify_yes = static function () { return true; };
$verify_no = static function () { return false; };
$googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
awd_test_assert(awd_crawler_decision('sqlmap/1.7', '/', 'GET', '1.2.3.4', $verify_yes) === 'attack tool', 'attack tools must be blocked everywhere');
awd_test_assert(awd_crawler_decision($googlebot, '/', 'GET', '1.2.3.4', $verify_no) === null, 'public pages stay open to any crawler identity');
awd_test_assert(awd_crawler_decision($googlebot, '/wp-login.php', 'GET', '1.2.3.4', $verify_no) === 'unverified crawler', 'fake Googlebot must be blocked on login');
awd_test_assert(awd_crawler_decision($googlebot, '/wp-login.php', 'POST', '66.249.66.1', $verify_yes) === null, 'verified Googlebot must not be blocked');
awd_test_assert(awd_crawler_decision('', '/xmlrpc.php', 'POST', '1.2.3.4', $verify_yes) === 'no user agent', 'empty user agents must be blocked on XML-RPC');
awd_test_assert(awd_crawler_decision('', '/wp-admin/admin-ajax.php', 'POST', '1.2.3.4', $verify_yes) === null, 'admin-ajax must stay reachable');
awd_test_assert(awd_crawler_decision('Mozilla/5.0 Chrome/130', '/wp-json/wp/v2/posts', 'GET', '1.2.3.4', $verify_no) === null, 'browsers are not gated');
$base_htaccess = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
$root_block = awd_hardening_root_block(false, '/');
$with_block = awd_hardening_set_block($base_htaccess, $root_block, true);
awd_test_assert(str_starts_with($with_block, AWD_HARDENING_BEGIN) && str_contains($with_block, '# BEGIN WordPress'), 'hardening block must be prepended and keep the WordPress block');
awd_test_assert(awd_hardening_set_block($with_block, $root_block, true) === $with_block, 'reapplying the block must be idempotent');
awd_test_assert(trim(awd_hardening_set_block($with_block, null, true)) === trim($base_htaccess), 'removing the block must restore the original content');
awd_test_assert(count(awd_integrity_htaccess_analysis($with_block)) > 0, 'an untrusted hardening block is analyzed like any other rule');
update_option(AWD_HARDENING_OPTION, array('protect_sensitive_files' => array('enabled' => true, 'blockSha256' => hash('sha256', $root_block))));
awd_test_assert(awd_integrity_htaccess_analysis($with_block) === array(), 'our exact block must not be reported as an injection');
$tampered = str_replace('RewriteRule ^wp-admin/includes/ - [F,L]', "RewriteRule ^wp-admin/includes/ - [F,L]\nRewriteCond %{HTTP_USER_AGENT} google\nRewriteRule ^(.*)$ spam.php [L]", $with_block);
awd_test_assert(count(awd_integrity_htaccess_analysis($tampered)) > 0, 'a modified hardening block must be analyzed again');
update_option(AWD_HARDENING_OPTION, array());
$alert_state = array();
$first = awd_alerts_select(array(array('fingerprint' => 'integrity:core-modified', 'severity' => 'critical', 'title' => 'x'), array('fingerprint' => 'plugin-update:x', 'severity' => 'low', 'title' => 'y')), $alert_state, 100);
$repeat = awd_alerts_select(array(array('fingerprint' => 'integrity:core-modified', 'severity' => 'critical', 'title' => 'x')), $alert_state, 200);
awd_alerts_select(array(), $alert_state, 300);
$returned = awd_alerts_select(array(array('fingerprint' => 'integrity:core-modified', 'severity' => 'critical', 'title' => 'x')), $alert_state, 400);
awd_test_assert(count($first) === 1 && $repeat === array() && count($returned) === 1, 'alerts must fire once per finding and again when it returns');
awd_test_assert(awd_cleanup_step_is_valid(array('operation' => 'set_hardening', 'parameters' => array('measure' => 'block_php_uploads', 'state' => 'on'))), 'set_hardening must validate');
awd_test_assert(!awd_cleanup_step_is_valid(array('operation' => 'set_hardening', 'parameters' => array('measure' => 'run_code', 'state' => 'on'))), 'unknown hardening measures must be rejected');

echo "WordPress plugin tests passed.\n";
