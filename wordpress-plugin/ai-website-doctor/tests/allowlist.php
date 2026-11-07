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

echo "WordPress plugin tests passed.\n";
