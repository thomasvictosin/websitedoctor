<?php
/**
 * Plugin Name: AI Website Doctor
 * Description: Connects this WordPress site to a locally hosted AI Website Doctor for diagnostics and explicitly approved repairs.
 * Version: 0.5.0
 * Requires at least: 6.2
 * Requires PHP: 8.0
 * License: GPL-2.0-or-later
 * Text Domain: ai-website-doctor
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_VERSION', '0.5.0');
define('AWD_OPTION', 'ai_website_doctor_settings');
define('AWD_RECOVERY_OPTION', 'ai_website_doctor_recovery_points');
define('AWD_SYNC_OPTION', 'ai_website_doctor_sync_state');
define('AWD_MAX_RECOVERY_POINTS', 25);
define('AWD_FATAL_OPTION', 'ai_website_doctor_fatal_events');
define('AWD_CRON_HISTORY_OPTION', 'ai_website_doctor_cron_history');
define('AWD_CONFLICT_REPORT_OPTION', 'ai_website_doctor_staging_conflict_report');

require_once __DIR__ . '/includes/integrity.php';
require_once __DIR__ . '/includes/cleanup.php';
require_once __DIR__ . '/includes/plugin-maintenance.php';
require_once __DIR__ . '/includes/hardening.php';
require_once __DIR__ . '/includes/alerts.php';

// Observe task outcomes without invoking or disabling customer callbacks.
add_action('init', 'awd_register_cron_observers', PHP_INT_MAX);
add_filter('schedule_event', 'awd_watch_scheduled_event');
add_filter('pre_unschedule_event', 'awd_capture_cron_unschedule', 10, 5);
add_filter('pre_reschedule_event', 'awd_capture_cron_reschedule', 10, 3);
register_shutdown_function('awd_record_shutdown_fatal');

add_action('admin_menu', 'awd_add_admin_menu');
add_action('admin_post_awd_save_settings', 'awd_save_settings');
add_action('admin_post_awd_pair', 'awd_pair_site');
add_action('admin_post_awd_disconnect', 'awd_disconnect_site');
add_action('admin_post_awd_sync', 'awd_sync_diagnostics');
add_action('admin_post_awd_execute', 'awd_execute_repair');
add_action('admin_post_awd_rollback', 'awd_rollback_repair');
add_action('admin_post_awd_central_rollback', 'awd_execute_central_rollback');
add_action('admin_post_awd_analyze_issue', 'awd_analyze_issue');
add_action('admin_post_awd_propose_repair', 'awd_propose_repair');
add_action('admin_post_awd_decide_repair', 'awd_decide_repair');
add_filter('cron_schedules', 'awd_cron_schedules');
add_action('awd_poll_central', 'awd_poll_central');
register_activation_hook(__FILE__, 'awd_activate');
register_deactivation_hook(__FILE__, 'awd_deactivate');

function awd_settings(): array
{
    $settings = get_option(AWD_OPTION, array());
    return is_array($settings) ? $settings : array();
}

function awd_add_admin_menu(): void
{
    add_menu_page(
        'AI Website Doctor',
        'Website Doctor',
        'manage_options',
        'ai-website-doctor',
        'awd_render_admin_page',
        'dashicons-heart',
        81
    );
}

function awd_cron_schedules(array $schedules): array
{
    $schedules['awd_five_minutes'] = array(
        'interval' => 300,
        'display' => 'Every five minutes (AI Website Doctor)',
    );
    return $schedules;
}

function awd_activate(): void
{
    if (!wp_next_scheduled('awd_poll_central')) {
        wp_schedule_event(time() + 60, 'awd_five_minutes', 'awd_poll_central');
    }
}

function awd_deactivate(): void
{
    wp_clear_scheduled_hook('awd_poll_central');
}

function awd_watch_scheduled_event($event)
{
    if (is_object($event) && isset($event->hook) && is_string($event->hook)) {
        awd_watch_cron_hook($event->hook);
    }
    return $event;
}

function awd_capture_cron_unschedule($pre, $timestamp, $hook, $args, $wp_error)
{
    if (function_exists('wp_doing_cron') && wp_doing_cron() && is_string($hook)) {
        awd_set_current_cron_candidate((string) $hook, (int) $timestamp, (array) $args);
    }
    return $pre;
}

function awd_capture_cron_reschedule($pre, $event, $wp_error)
{
    if (function_exists('wp_doing_cron') && wp_doing_cron() && is_object($event)
        && isset($event->hook, $event->timestamp, $event->args)) {
        awd_set_current_cron_candidate((string) $event->hook, (int) $event->timestamp, (array) $event->args);
    }
    return $pre;
}

function awd_set_current_cron_candidate(string $hook, int $timestamp, array $args): void
{
    $GLOBALS['awd_current_cron_candidate'] = array(
        'id' => substr(hash('sha256', $hook . ':' . $timestamp . ':' . md5(serialize($args))), 0, 32),
        'hook' => substr(sanitize_text_field($hook), 0, 200),
        'scheduledAt' => gmdate('c', $timestamp),
    );
}

function awd_register_cron_observers(): void
{
    $cron = _get_cron_array();
    if (!is_array($cron)) return;
    foreach ($cron as $events) {
        foreach ((array) $events as $hook => $_instances) awd_watch_cron_hook((string) $hook);
    }
}

function awd_watch_cron_hook(string $hook): void
{
    if ($hook === '' || str_starts_with($hook, 'awd_internal_')) return;
    static $watched = array();
    if (isset($watched[$hook])) return;
    $watched[$hook] = true;
    add_action($hook, 'awd_cron_event_started', PHP_INT_MIN, 99);
    add_action($hook, 'awd_cron_event_completed', PHP_INT_MAX, 99);
}

function awd_cron_event_started(...$args): void
{
    if (!function_exists('wp_doing_cron') || !wp_doing_cron()) return;
    $hook = function_exists('current_filter') ? current_filter() : '';
    $candidate = $GLOBALS['awd_current_cron_candidate'] ?? null;
    if (is_array($candidate) && ($candidate['hook'] ?? '') === $hook) {
        $event = $candidate;
        unset($GLOBALS['awd_current_cron_candidate']);
    } else {
        $event = awd_find_due_cron_event($hook, $args);
    }
    if (!$event) return;
    $GLOBALS['awd_current_cron_event'] = $event;
    $event['status'] = 'running';
    $event['startedAt'] = gmdate('c');
    awd_store_cron_outcome($event);
}

function awd_cron_event_completed(...$args): void
{
    if (empty($GLOBALS['awd_current_cron_event'])) return;
    $event = $GLOBALS['awd_current_cron_event'];
    unset($GLOBALS['awd_current_cron_event']);
    if (($event['status'] ?? '') !== 'failed') {
        $event['status'] = 'completed';
        $event['completedAt'] = gmdate('c');
    }
    awd_store_cron_outcome($event);
}

/**
 * Let scheduled-task owners report caught exceptions and application-level failures.
 * Call from inside the WP-Cron callback after handling the failure.
 */
function awd_report_scheduled_task_failure(string $message, string $code = 'application_error'): void
{
    $event = $GLOBALS['awd_current_cron_event'] ?? null;
    if (!is_array($event)) return;
    $event['status'] = 'failed';
    $event['completedAt'] = gmdate('c');
    $event['failure'] = array(
        'type' => substr(sanitize_key($code) ?: 'application_error', 0, 40),
        'message' => substr(awd_redact_error_text($message), 0, 500),
        'source' => 'application_report',
    );
    $GLOBALS['awd_current_cron_event'] = $event;
    awd_store_cron_outcome($event);
}

function awd_find_due_cron_event(string $hook, array $args = array()): ?array
{
    if ($hook === '') return null;
    $now = time();
    foreach ((array) _get_cron_array() as $timestamp => $hooks) {
        if ((int) $timestamp > $now || empty($hooks[$hook]) || !is_array($hooks[$hook])) continue;
        foreach ($hooks[$hook] as $key => $instance) {
            if (!is_array($instance)) continue;
            if (isset($instance['args']) && serialize((array) $instance['args']) !== serialize($args)) continue;
            return array(
                'id' => substr(hash('sha256', $hook . ':' . (string) $timestamp . ':' . (string) $key), 0, 32),
                'hook' => substr(sanitize_text_field($hook), 0, 200),
                'scheduledAt' => gmdate('c', (int) $timestamp),
                'status' => 'running',
            );
        }
    }
    return null;
}

function awd_store_cron_outcome(array $outcome): void
{
    $history = get_option(AWD_CRON_HISTORY_OPTION, array());
    $history = is_array($history) ? $history : array();
    $replaced = false;
    foreach ($history as $index => $existing) {
        if (is_array($existing) && ($existing['id'] ?? null) === ($outcome['id'] ?? null)) {
            $history[$index] = $outcome;
            $replaced = true;
            break;
        }
    }
    if (!$replaced) $history[] = $outcome;
    update_option(AWD_CRON_HISTORY_OPTION, array_slice($history, -100), false);
}

function awd_record_shutdown_fatal(): void
{
    $error = error_get_last();
    if (!is_array($error) || !in_array($error['type'] ?? 0, array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR), true)) return;
    $message = awd_redact_error_text((string) ($error['message'] ?? 'PHP fatal error'));
    $error_file = (string) ($error['file'] ?? 'unknown');
    $file = basename($error_file);
    $plugin_file = awd_plugin_file_for_error_path($error_file);
    $fatal = array(
        'id' => substr(hash('sha256', $file . ':' . (int) ($error['line'] ?? 0) . ':' . $message), 0, 32),
        'observedAt' => gmdate('c'),
        'type' => awd_php_error_name((int) $error['type']),
        'message' => substr($message, 0, 500),
        'file' => substr(sanitize_text_field($file), 0, 200),
        'plugin' => $plugin_file,
        'line' => max(0, (int) ($error['line'] ?? 0)),
    );
    $fatals = get_option(AWD_FATAL_OPTION, array());
    $fatals = is_array($fatals) ? $fatals : array();
    $fatals[] = $fatal;
    update_option(AWD_FATAL_OPTION, array_slice($fatals, -20), false);
    if (!empty($GLOBALS['awd_current_cron_event'])) {
        $event = $GLOBALS['awd_current_cron_event'];
        $event['status'] = 'failed';
        $event['completedAt'] = gmdate('c');
        $event['failure'] = array('type' => $fatal['type'], 'message' => $fatal['message'], 'source' => 'fatal_error');
        awd_store_cron_outcome($event);
    }
}

/** Return the registered plugin entry only when an error path maps unambiguously to one plugin. */
function awd_plugin_file_for_error_path(string $error_path): ?string
{
    $plugin_root = realpath(WP_PLUGIN_DIR);
    $resolved_error = realpath($error_path);
    if ($plugin_root === false || $resolved_error === false || !str_starts_with($resolved_error, $plugin_root . DIRECTORY_SEPARATOR)) return null;
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $relative_error = str_replace(DIRECTORY_SEPARATOR, '/', substr($resolved_error, strlen($plugin_root) + 1));
    $matches = array();
    foreach (get_plugins() as $plugin_file => $metadata) {
        $plugin_file = str_replace(DIRECTORY_SEPARATOR, '/', (string) $plugin_file);
        $directory = dirname($plugin_file);
        if ($relative_error === $plugin_file || ($directory !== '.' && str_starts_with($relative_error, rtrim($directory, '/') . '/'))) {
            $matches[$plugin_file] = $directory === '.' ? 0 : strlen($directory);
        }
    }
    if (!$matches) return null;
    arsort($matches, SORT_NUMERIC);
    $longest = reset($matches);
    $winners = array_keys(array_filter($matches, static function ($length) use ($longest) { return $length === $longest; }));
    return count($winners) === 1 ? $winners[0] : null;
}

function awd_php_error_name(int $type): string
{
    foreach (array('E_ERROR', 'E_PARSE', 'E_CORE_ERROR', 'E_COMPILE_ERROR', 'E_USER_ERROR', 'E_RECOVERABLE_ERROR') as $name) {
        if (defined($name) && constant($name) === $type) return $name;
    }
    return 'PHP_FATAL';
}

function awd_redact_error_text(string $message): string
{
    $message = preg_replace('/(authorization|password|passwd|secret|token|api[_-]?key|cookie)\s*[:=]\s*[^;\s,]+/i', '$1=[REDACTED]', $message);
    $message = preg_replace('~(?:[A-Z]:)?[/\\\\][^\s:]+(?:[/\\\\][^\s:]+)+~', '[PATH]', (string) $message);
    return sanitize_text_field((string) $message);
}

function awd_find_cron_outcome(string $id): ?array
{
    $history = get_option(AWD_CRON_HISTORY_OPTION, array());
    if (!is_array($history)) return null;
    foreach (array_reverse($history) as $outcome) {
        if (is_array($outcome) && ($outcome['id'] ?? null) === $id) return $outcome;
    }
    return null;
}

function awd_conflict_testing_report(array $plugins, $theme): array
{
    $report = get_option(AWD_CONFLICT_REPORT_OPTION, null);
    if (is_array($report) && ($report['environment'] ?? '') === 'disposable_staging') {
        return $report;
    }
    return array(
        'status' => 'not_run',
        'environment' => 'live_site_observation',
        'stagingRequired' => true,
        'liveDeactivationPerformed' => false,
        'testedAt' => null,
        'activePlugins' => array_values(array_map(static fn($plugin) => (string) $plugin['file'], array_filter($plugins, static fn($plugin) => !empty($plugin['active'])))),
        'activeTheme' => sanitize_key($theme->get_stylesheet()),
        'findings' => array(),
    );
}

function awd_record_staging_conflict_report(array $report): bool
{
    $is_staging = function_exists('wp_get_environment_type') && wp_get_environment_type() === 'staging';
    $is_disposable = defined('AIWD_DISPOSABLE_STAGING') && AIWD_DISPOSABLE_STAGING === true;
    $is_authorized_context = (function_exists('current_user_can') && current_user_can('manage_options'))
        || (defined('WP_CLI') && WP_CLI);
    if (!$is_staging || !$is_disposable || !$is_authorized_context) return false;
    $validated = array(
        'status' => in_array($report['status'] ?? '', array('completed', 'failed'), true) ? $report['status'] : 'failed',
        'environment' => 'disposable_staging',
        'stagingRequired' => true,
        'liveDeactivationPerformed' => false,
        'testedAt' => gmdate('c'),
        'activePlugins' => array_slice(array_values(array_filter(array_map('sanitize_text_field', (array) ($report['activePlugins'] ?? array())), static fn($item) => $item !== '')), 0, 100),
        'activeTheme' => substr(sanitize_key((string) ($report['activeTheme'] ?? '')), 0, 100),
        'findings' => array(),
    );
    foreach (array_slice((array) ($report['findings'] ?? array()), 0, 100) as $finding) {
        if (!is_array($finding)) continue;
        $components = array_slice(array_values(array_filter(array_map('sanitize_text_field', (array) ($finding['components'] ?? array())), static fn($item) => $item !== '')), 0, 3);
        $result = in_array($finding['result'] ?? '', array('conflict', 'no_conflict', 'inconclusive'), true) ? $finding['result'] : 'inconclusive';
        if (!$components) continue;
        $validated['findings'][] = array(
            'components' => $components,
            'result' => $result,
            'evidence' => substr(awd_redact_error_text((string) ($finding['evidence'] ?? '')), 0, 1000),
            'baselineFindings' => awd_validate_conflict_finding_summaries($finding['baselineFindings'] ?? array()),
            'probeFindings' => awd_validate_conflict_finding_summaries($finding['probeFindings'] ?? array()),
        );
    }
    update_option(AWD_CONFLICT_REPORT_OPTION, $validated, false);
    return true;
}

function awd_validate_conflict_finding_summaries($findings): array
{
    if (!is_array($findings)) return array();
    $validated = array();
    foreach (array_slice($findings, 0, 100) as $finding) {
        if (!is_array($finding) || !isset($finding['fingerprint'], $finding['severity']) || !is_string($finding['fingerprint'])) continue;
        $severity = in_array($finding['severity'], array('low', 'medium', 'high'), true) ? $finding['severity'] : 'low';
        $validated[] = array('fingerprint' => substr(sanitize_text_field($finding['fingerprint']), 0, 160), 'severity' => $severity);
    }
    return $validated;
}

function awd_admin_notice(string $message, string $type = 'success'): void
{
    $allowed = array('success', 'error', 'warning', 'info');
    $type = in_array($type, $allowed, true) ? $type : 'info';
    echo '<div class="notice notice-' . esc_attr($type) . '"><p>' . esc_html($message) . '</p></div>';
}

function awd_render_admin_page(): void
{
    if (!current_user_can('manage_options')) {
        return;
    }

    $settings = awd_settings();
    $agent_id = isset($settings['agent_id']) ? (string) $settings['agent_id'] : '';
    $connected = $agent_id !== '' && !empty($settings['agent_token']);
    $sync_state = get_option(AWD_SYNC_OPTION, array());
    $queued_snapshot = get_option('ai_website_doctor_diagnostic_queue', null);
    $central_dashboard = $connected ? awd_get_central_dashboard($settings) : null;
    $dashboard_is_live = is_array($central_dashboard);
    if ($dashboard_is_live) {
        update_option('ai_website_doctor_dashboard_cache', $central_dashboard, false);
    } else {
        $central_dashboard = get_option('ai_website_doctor_dashboard_cache', null);
        if ($connected) {
            $offline_snapshot = awd_collect_diagnostics($settings);
            update_option('ai_website_doctor_last_local_diagnostics', $offline_snapshot, false);
            update_option('ai_website_doctor_diagnostic_queue', $offline_snapshot, false);
            $sync_state = is_array($sync_state) ? $sync_state : array();
            $sync_state['queued_at'] = gmdate('c');
            update_option(AWD_SYNC_OPTION, $sync_state, false);
        }
    }
    $queued_snapshot = get_option('ai_website_doctor_diagnostic_queue', null);
    $message = isset($_GET['awd_message']) ? sanitize_text_field(wp_unslash($_GET['awd_message'])) : '';
    $notice_type = isset($_GET['awd_type']) ? sanitize_key($_GET['awd_type']) : 'success';
    ?>
    <div class="wrap">
        <h1>AI Website Doctor</h1>
        <?php if ($message !== '') : ?>
            <?php awd_admin_notice($message, $notice_type); ?>
        <?php endif; ?>

        <h2>Central application connection</h2>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="awd_save_settings">
            <?php wp_nonce_field('awd_save_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="awd-central-url">Central application URL</label></th>
                    <td>
                        <input id="awd-central-url" class="regular-text" type="url" name="central_url"
                            value="<?php echo esc_attr($settings['central_url'] ?? ''); ?>" placeholder="https://doctor.example">
                        <p class="description">HTTPS is required, except for loopback development addresses. Requests do not follow redirects.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Authorized log collection</th>
                    <td>
                        <label><input type="checkbox" name="collect_logs" value="1" <?php checked(!empty($settings['collect_logs'])); ?>>
                            Allow sending a short, redacted excerpt from wp-content/debug.log with manual diagnostics.</label>
                        <p class="description">Disabled by default. Log contents can still contain private information; review your debug log before enabling.</p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Save connection settings'); ?>
        </form>

        <?php if (!$connected) : ?>
            <h2>Pair this site</h2>
            <p>Create a one-time pairing code in the central app, then enter it here. Codes expire after ten minutes.</p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_pair">
                <?php wp_nonce_field('awd_pair'); ?>
                <label for="awd-pair-code">One-time pairing code</label>
                <input id="awd-pair-code" class="regular-text" type="password" name="pairing_code" autocomplete="off" required>
                <?php submit_button('Connect to central app'); ?>
            </form>
        <?php else : ?>
            <div class="awd-summary-grid">
                <div class="awd-summary"><span>Connection</span><strong class="<?php echo $dashboard_is_live ? 'awd-good' : 'awd-warn'; ?>"><?php echo $dashboard_is_live ? 'Connected' : 'Temporarily offline'; ?></strong><small><?php echo esc_html($settings['central_url']); ?></small></div>
                <div class="awd-summary"><span>Website health</span><strong><?php echo esc_html(awd_plugin_health_label($central_dashboard)); ?></strong><small><?php echo esc_html(awd_plugin_issue_count($central_dashboard)); ?> active central findings</small></div>
                <div class="awd-summary"><span>Last scan</span><strong><?php echo esc_html(awd_plugin_scan_time($central_dashboard)); ?></strong><small>WordPress diagnostics</small></div>
                <div class="awd-summary"><span>Synchronization</span><strong class="<?php echo is_array($queued_snapshot) ? 'awd-warn' : 'awd-good'; ?>"><?php echo is_array($queued_snapshot) ? 'Retry queued' : (!empty($sync_state['last_success']) ? 'Synchronized' : 'Ready'); ?></strong><small><?php echo is_array($queued_snapshot) ? 'Queued ' . esc_html(awd_plugin_time($sync_state['queued_at'] ?? null)) : (!empty($sync_state['last_success']) ? 'Last synced ' . esc_html(awd_plugin_time($sync_state['last_success'])) : 'No successful sync recorded'); ?></small></div>
            </div>
            <?php if (!$dashboard_is_live) : ?><div class="notice notice-warning inline"><p>Central service is unreachable. A bounded local diagnostic snapshot is queued for the next scheduled or manual sync; displayed central findings may be out of date.</p></div><?php endif; ?>
            <?php awd_render_critical_notices($central_dashboard); ?>
            <p><strong>Central connection:</strong> <?php echo esc_html($settings['central_url']); ?> · Agent <code><?php echo esc_html($agent_id); ?></code></p>
            <p>Diagnostics sync automatically every five minutes while WP-Cron runs. Scans and proposals are recorded centrally. Repairs require review and explicit local confirmation before execution.</p>

            <form class="awd-inline-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_sync">
                <?php wp_nonce_field('awd_sync'); ?>
                <?php submit_button('Collect and sync diagnostics', 'primary', 'submit', false); ?>
            </form>
            <form class="awd-inline-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_disconnect">
                <?php wp_nonce_field('awd_disconnect'); ?>
                <?php submit_button('Disconnect agent', 'delete', 'submit', false); ?>
            </form>

            <?php awd_render_cleanup_section($settings); ?>
            <?php awd_render_hardening_section(); ?>
            <h2>Approved repair proposals</h2>
            <?php awd_render_pending_repairs($settings); ?>
            <h2>Central issues, AI analysis, and repair history</h2>
            <?php awd_render_central_issues($settings, $central_dashboard); ?>
            <h2>Local recovery points</h2>
            <?php awd_render_recovery_points(); ?>
        <?php endif; ?>

        <h2>Local diagnostics</h2>
        <?php awd_render_diagnostics(awd_collect_diagnostics($settings)); ?>
        <p>Reports PHP fatal events and observed scheduled task outcomes. Overdue means a task is more than one hour past its scheduled time; failed means a fatal error was observed while its callback was running. Live conflict checks never deactivate plugins or themes; use the disposable staging runner to compare component states.</p>
    </div>
    <style>
        .awd-inline-form { display: inline-block; margin: 0 8px 0 0; }
        .awd-repair { max-width: 900px; margin: 14px 0; padding: 14px; border: 1px solid #ccd0d4; background: #fff; }
        .awd-repair li { margin-left: 20px; }
        .awd-diagnostics { max-width: 900px; padding: 14px; background: #fff; border: 1px solid #ccd0d4; }
        .awd-diagnostics code { word-break: break-word; }
        .awd-summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; max-width:1200px; margin:18px 0; }
        .awd-summary { display:grid; gap:7px; padding:15px; border:1px solid #dcdcde; border-radius:6px; background:#fff; }
        .awd-summary span,.awd-summary small { color:#646970; font-size:12px; }
        .awd-summary strong { color:#1d2327; font-size:18px; }
        .awd-good { color:#16845b !important; }.awd-warn { color:#a56a00 !important; }
        .awd-issue { max-width:1100px; margin:12px 0; padding:16px; border:1px solid #dcdcde; border-left:4px solid #8c8f94; border-radius:4px; background:#fff; }
        .awd-issue-critical,.awd-issue-high { border-left-color:#d63638; }.awd-issue-medium { border-left-color:#dba617; }.awd-issue-low { border-left-color:#00a32a; }
        .awd-issue details { margin:10px 0; }.awd-issue pre { overflow:auto; max-height:340px; padding:10px; background:#f6f7f7; }
        .awd-issue form { display:inline-block; margin:4px 6px 0 0; }
        .awd-muted { color:#646970; }
    </style>
    <?php
}

function awd_safe_central_url(string $raw_url): ?string
{
    $url = esc_url_raw(trim($raw_url), array('http', 'https'));
    $parts = wp_parse_url($url);
    if (!$parts || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
        return null;
    }
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = strtolower(trim((string) $parts['host'], '[]'));
    $is_loopback = in_array($host, array('localhost', '127.0.0.1', '::1'), true);
    if (!empty($parts['user']) || !empty($parts['pass']) || !empty($parts['query']) || !empty($parts['fragment'])
        || !in_array((string) ($parts['path'] ?? ''), array('', '/'), true)
        || ($scheme !== 'https' && !($scheme === 'http' && $is_loopback))) {
        return null;
    }
    return untrailingslashit($url);
}

function awd_save_settings(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to change these settings.', 'ai-website-doctor'), 403);
    }
    check_admin_referer('awd_save_settings');
    $settings = awd_settings();
    $central_url = awd_safe_central_url(isset($_POST['central_url']) ? wp_unslash($_POST['central_url']) : '');
    if ($central_url === null) {
        awd_redirect('Use a valid HTTPS URL. HTTP is allowed only for localhost/loopback.', 'error');
    }
    $settings['central_url'] = $central_url;
    $settings['collect_logs'] = isset($_POST['collect_logs']);
    update_option(AWD_OPTION, $settings, false);
    awd_redirect('Settings saved.');
}

function awd_pair_site(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to pair this site.', 'ai-website-doctor'), 403);
    }
    check_admin_referer('awd_pair');
    $settings = awd_settings();
    $base = awd_safe_central_url((string) ($settings['central_url'] ?? ''));
    $code = isset($_POST['pairing_code']) ? sanitize_text_field(wp_unslash($_POST['pairing_code'])) : '';
    if ($base === null || !preg_match('/^[A-Za-z0-9_-]{40,64}$/', $code)) {
        awd_redirect('Save a valid central URL and enter an unexpired pairing code.', 'error');
    }
    $response = awd_central_request($base . '/api/agents/register', 'POST', array(
        'code' => $code,
        'siteUrl' => home_url('/'),
        'siteName' => get_bloginfo('name'),
        'wpVersion' => get_bloginfo('version'),
        'phpVersion' => PHP_VERSION,
        'pluginVersion' => AWD_VERSION,
    ));
    if (is_wp_error($response)) {
        awd_redirect($response->get_error_message(), 'error');
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    if (!is_array($body) || empty($body['agentId']) || empty($body['token'])) {
        awd_redirect('Central application returned an invalid pairing response.', 'error');
    }
    $settings['agent_id'] = sanitize_text_field($body['agentId']);
    $settings['agent_token'] = sanitize_text_field($body['token']);
    update_option(AWD_OPTION, $settings, false);
    awd_redirect('WordPress site connected. The secret token is stored locally in the WordPress database.');
}

function awd_disconnect_site(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to disconnect this site.', 'ai-website-doctor'), 403);
    }
    check_admin_referer('awd_disconnect');
    $settings = awd_settings();
    if (!empty($settings['central_url']) && !empty($settings['agent_id']) && !empty($settings['agent_token'])) {
        $response = awd_central_request(
            trailingslashit($settings['central_url']) . 'api/agents/' . rawurlencode($settings['agent_id']),
            'DELETE',
            array(),
            (string) $settings['agent_token']
        );
        if (is_wp_error($response)) {
            awd_redirect('Could not revoke the central agent: ' . $response->get_error_message() . ' Credentials were retained.', 'error');
        }
    }
    unset($settings['agent_id'], $settings['agent_token']);
    update_option(AWD_OPTION, $settings, false);
    awd_redirect('Agent disconnected and local credentials removed.');
}

function awd_redirect(string $message, string $type = 'success'): void
{
    if (!empty($GLOBALS['awd_background_repair_id'])) {
        throw new RuntimeException($message);
    }
    $url = add_query_arg(
        array('page' => 'ai-website-doctor', 'awd_message' => rawurlencode($message), 'awd_type' => $type),
        admin_url('admin.php')
    );
    wp_safe_redirect($url);
    exit;
}

function awd_central_request(string $url, string $method, array $payload, string $token = '')
{
    $body = '';
    $args = array(
        'method' => $method,
        'timeout' => preg_match('#/(?:executions|cleanup-executions)$#', (string) wp_parse_url($url, PHP_URL_PATH)) ? 180 : (preg_match('#/(?:cleanup|fix)$#', (string) wp_parse_url($url, PHP_URL_PATH)) ? 60 : 15),
        'redirection' => 0,
        'reject_unsafe_urls' => true,
        'sslverify' => true,
        'headers' => array('Content-Type' => 'application/json', 'Accept' => 'application/json'),
        // Generous ceiling: a truncated body fails to parse and would look like an outage.
        'limit_response_size' => 1048576,
    );
    if (in_array($method, array('POST', 'PUT', 'PATCH'), true)) {
        $body = wp_json_encode($payload);
        if (!is_string($body)) {
            return new WP_Error('awd_request_encode_failed', 'Could not encode the central API request.');
        }
        $args['body'] = $body;
    }
    if ($token !== '') {
        $args['headers']['Authorization'] = 'Bearer ' . $token;
        try {
            $timestamp = (string) time();
            $nonce = bin2hex(random_bytes(16));
        } catch (Throwable $error) {
            return new WP_Error('awd_request_sign_failed', 'Could not securely sign the central API request.');
        }
        $path = (string) wp_parse_url($url, PHP_URL_PATH);
        $query = wp_parse_url($url, PHP_URL_QUERY);
        $request_target = $path . (is_string($query) && $query !== '' ? '?' . $query : '');
        $args['headers']['X-AWD-Timestamp'] = $timestamp;
        $args['headers']['X-AWD-Nonce'] = $nonce;
        $args['headers']['X-AWD-Signature'] = awd_agent_request_signature(
            $token,
            $method,
            $request_target,
            $timestamp,
            $nonce,
            $body
        );
    }
    $response = wp_remote_request($url, $args);
    if (is_wp_error($response)) {
        return new WP_Error('awd_connection_failed', 'Could not reach the central app: ' . $response->get_error_message());
    }
    $status = wp_remote_retrieve_response_code($response);
    if ($status < 200 || $status >= 300) {
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $message = is_array($body) && isset($body['error']) ? sanitize_text_field($body['error']) : 'Central app returned HTTP ' . $status . '.';
        return new WP_Error('awd_remote_error', $message);
    }
    return $response;
}

function awd_agent_request_signature(
    string $token,
    string $method,
    string $request_target,
    string $timestamp,
    string $nonce,
    string $body
): string {
    $canonical = implode("\n", array(
        strtoupper($method),
        $request_target,
        $timestamp,
        $nonce,
        hash('sha256', $body),
    ));
    return hash_hmac('sha256', $canonical, $token);
}

function awd_authenticated_request(array $settings, string $path, string $method, array $payload = array())
{
    if (empty($settings['central_url']) || empty($settings['agent_id']) || empty($settings['agent_token'])) {
        return new WP_Error('awd_not_connected', 'Connect this site to the central app first.');
    }
    $base = awd_safe_central_url((string) $settings['central_url']);
    if ($base === null) {
        return new WP_Error('awd_invalid_url', 'Central app URL is invalid. Update the connection settings.');
    }
    $url = $base . '/api/agents/' . rawurlencode((string) $settings['agent_id']) . $path;
    return awd_central_request($url, $method, $payload, (string) $settings['agent_token']);
}

function awd_sync_diagnostics(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to sync diagnostics.', 'ai-website-doctor'), 403);
    }
    check_admin_referer('awd_sync');
    $GLOBALS['awd_force_integrity_scan'] = true;
    $result = awd_send_diagnostics();
    if (is_wp_error($result)) {
        awd_redirect($result->get_error_message(), 'error');
    }
    awd_redirect('Diagnostics were sent to the central app.');
}

function awd_send_diagnostics()
{
    $settings = awd_settings();
    $diagnostics = awd_collect_diagnostics($settings);
    update_option('ai_website_doctor_last_local_diagnostics', $diagnostics, false);
    awd_alerts_process_findings((array) ($diagnostics['issues'] ?? array()));
    $result = awd_authenticated_request($settings, '/diagnostics', 'POST', $diagnostics);
    $state = get_option(AWD_SYNC_OPTION, array());
    $state = is_array($state) ? $state : array();
    if (is_wp_error($result)) {
        // Keep only the latest bounded snapshot; older snapshots can become misleading when replayed out of order.
        update_option('ai_website_doctor_diagnostic_queue', $diagnostics, false);
        $state['last_error'] = sanitize_text_field($result->get_error_message());
        $state['queued_at'] = gmdate('c');
        update_option(AWD_SYNC_OPTION, $state, false);
        return $result;
    }
    delete_option('ai_website_doctor_diagnostic_queue');
    unset($state['last_error'], $state['queued_at']);
    $state['last_success'] = gmdate('c');
    update_option(AWD_SYNC_OPTION, $state, false);
    return $result;
}

function awd_get_central_dashboard(array $settings)
{
    $response = awd_authenticated_request($settings, '/dashboard', 'GET');
    if (is_wp_error($response)) {
        $state = get_option(AWD_SYNC_OPTION, array());
        $state = is_array($state) ? $state : array();
        $state['last_error'] = sanitize_text_field($response->get_error_message());
        update_option(AWD_SYNC_OPTION, $state, false);
        return null;
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    return is_array($body) ? $body : null;
}

function awd_plugin_time($value): string
{
    if (!is_string($value) || $value === '') return 'Not recorded';
    $timestamp = strtotime($value);
    return $timestamp ? wp_date(get_option('date_format') . ' ' . get_option('time_format'), $timestamp) : 'Not recorded';
}

function awd_plugin_scan_time($dashboard): string
{
    if (!is_array($dashboard)) return 'Unavailable';
    $scan = $dashboard['latestScan'] ?? null;
    $time = is_array($scan) ? ($scan['completedAt'] ?? $scan['startedAt'] ?? null) : null;
    if (!$time && is_array($dashboard['diagnostics'] ?? null)) $time = $dashboard['diagnostics']['collectedAt'] ?? null;
    return awd_plugin_time($time);
}

function awd_plugin_issue_count($dashboard): int
{
    return is_array($dashboard) && is_array($dashboard['issues'] ?? null)
        ? count(array_filter($dashboard['issues'], static function ($issue) { return is_array($issue) && ($issue['status'] ?? '') !== 'resolved'; }))
        : 0;
}

function awd_plugin_health_label($dashboard): string
{
    if (!is_array($dashboard)) return 'Not synchronized';
    $check = $dashboard['latestCheck'] ?? null;
    if (is_array($check) && empty($check['available'])) return 'Unavailable';
    $active = array_filter($dashboard['issues'] ?? array(), static function ($issue) { return is_array($issue) && ($issue['status'] ?? '') !== 'resolved'; });
    foreach ($active as $issue) if (in_array($issue['severity'] ?? '', array('critical', 'high'), true)) return 'Critical findings';
    if (count($active) > 0) return 'Needs attention';
    return is_array($check) ? 'Healthy' : 'Awaiting availability check';
}

function awd_render_critical_notices($dashboard): void
{
    if (!is_array($dashboard)) return;
    foreach ($dashboard['issues'] ?? array() as $issue) {
        if (!is_array($issue) || ($issue['status'] ?? '') === 'resolved' || !in_array($issue['severity'] ?? '', array('critical', 'high'), true)) continue;
        echo '<div class="notice notice-error inline"><p><strong>' . esc_html(strtoupper((string) $issue['severity']) . ': ' . (string) ($issue['title'] ?? 'Critical website finding')) . '</strong> ' . esc_html((string) ($issue['description'] ?? '')) . '</p></div>';
    }
}

function awd_render_central_issues(array $settings, $dashboard): void
{
    if (!is_array($dashboard) || !is_array($dashboard['issues'] ?? null)) {
        echo '<p class="awd-muted">Central issue history is unavailable until the connected service responds.</p>';
        return;
    }
    if (!$dashboard['issues']) { echo '<p>No centrally recorded WordPress findings.</p>'; return; }
    foreach ($dashboard['issues'] as $issue) {
        if (!is_array($issue)) continue;
        $severity = sanitize_html_class((string) ($issue['severity'] ?? 'medium'));
        $diagnosis = is_array($issue['diagnosis'] ?? null) ? $issue['diagnosis'] : array();
        $repairs = is_array($issue['repairs'] ?? null) ? $issue['repairs'] : array();
        echo '<article class="awd-issue awd-issue-' . esc_attr($severity) . '">';
        echo '<h3>' . esc_html((string) ($issue['title'] ?? 'Issue')) . ' <span class="awd-muted">' . esc_html(strtoupper($severity)) . ' · ' . esc_html((string) ($issue['status'] ?? 'open')) . '</span></h3>';
        echo '<p>' . esc_html((string) ($issue['description'] ?? '')) . '</p>';
        echo '<p class="awd-muted">Last detected ' . esc_html(awd_plugin_time($issue['lastSeenAt'] ?? null)) . '</p>';
        awd_render_fix_button($issue);
        if (!empty($diagnosis['diagnosis']) && is_array($diagnosis['diagnosis'])) {
            $result = $diagnosis['diagnosis'];
            echo '<h4>Central AI diagnosis</h4><p><strong>' . esc_html((string) ($result['probableRootCause']['claim'] ?? $result['description'] ?? 'Diagnosis recorded')) . '</strong></p>';
            if (!empty($result['recommendedFix']['description'])) echo '<p><strong>Recommended fix:</strong> ' . esc_html((string) $result['recommendedFix']['description']) . '</p>';
            echo '<details><summary>Full central diagnosis and evidence</summary><pre>' . esc_html(wp_json_encode($result, JSON_PRETTY_PRINT)) . '</pre></details>';
        } elseif (($diagnosis['status'] ?? '') === 'unavailable') {
            echo '<p class="awd-muted">Central AI analysis unavailable: ' . esc_html((string) ($diagnosis['error'] ?? 'No model response was recorded.')) . '</p>';
        } else {
            echo '<p class="awd-muted">No central AI diagnosis has been recorded for this finding.</p>';
        }
        foreach ($repairs as $repair) {
            if (!is_array($repair)) continue;
            $proposal = is_array($repair['proposal'] ?? null) ? $repair['proposal'] : array();
            echo '<div class="awd-repair"><h4>Repair ' . esc_html((string) ($repair['status'] ?? '')) . ' · ' . esc_html((string) ($repair['risk'] ?? 'unknown')) . ' risk</h4>';
            if (!empty($proposal['rationale'])) echo '<p>' . esc_html((string) $proposal['rationale']) . '</p>';
            if (!empty($proposal['proposedChanges']) && is_array($proposal['proposedChanges'])) echo '<ul><li>' . implode('</li><li>', array_map('esc_html', $proposal['proposedChanges'])) . '</li></ul>';
            if (!empty($proposal['manualGuidance']) && is_array($proposal['manualGuidance'])) echo '<p><strong>Manual remediation guidance · no changes will be executed</strong></p><ol><li>' . implode('</li><li>', array_map('esc_html', $proposal['manualGuidance'])) . '</li></ol>';
            if (!empty($proposal['instructions']['steps']) && is_array($proposal['instructions']['steps'])) echo '<details><summary>Inspect proposed operations before approval</summary><pre>' . esc_html(wp_json_encode($proposal['instructions']['steps'], JSON_PRETTY_PRINT)) . '</pre></details>';
            echo '<p>Approval: ' . esc_html((string) ($repair['approvalStatus'] ?? 'pending')) . ' · Execution: ' . esc_html((string) ($repair['executionStatus'] ?? 'not started')) . ' · Verification: ' . esc_html((string) ($repair['verificationStatus'] ?? 'not started')) . ' · Rollback: ' . esc_html((string) ($repair['rollbackStatus'] ?? 'not requested')) . '</p>';
            if (!empty($repair['approvals']) && is_array($repair['approvals'])) echo '<details><summary>Shared approval records</summary><ol><li>' . implode('</li><li>', array_map(static function ($approval) { return esc_html((string) ($approval['decision'] ?? 'decision') . ' · ' . awd_plugin_time($approval['createdAt'] ?? null) . (!empty($approval['comment']) ? ' · ' . (string) $approval['comment'] : '')); }, $repair['approvals'])) . '</li></ol></details>';
            if (!empty($repair['verificationResults']) && is_array($repair['verificationResults'])) {
                echo '<details><summary>Central verification results</summary>';
                foreach ($repair['verificationResults'] as $verification) if (is_array($verification)) echo '<p><strong>' . esc_html((string) ($verification['status'] ?? 'unknown')) . '</strong> via ' . esc_html((string) ($verification['method'] ?? 'verification')) . ' · ' . esc_html(awd_plugin_time($verification['createdAt'] ?? null)) . '</p><pre>' . esc_html(wp_json_encode($verification['result'] ?? null, JSON_PRETTY_PRINT)) . '</pre>';
                echo '</details>';
            }
            if (!empty($repair['events']) && is_array($repair['events'])) echo '<details><summary>Shared repair history (' . count($repair['events']) . ' events)</summary><ol><li>' . implode('</li><li>', array_map(static function ($event) { return esc_html(str_replace('_', ' ', (string) ($event['eventType'] ?? 'event')) . ' · ' . awd_plugin_time($event['createdAt'] ?? null) . ' · ' . (string) ($event['actor'] ?? '')); }, $repair['events'])) . '</li></ol></details>';
            if (($repair['status'] ?? '') === 'pending_approval') {
                if (!empty($repair['operationIds'])) {
                    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_execute"><input type="hidden" name="repair_id" value="' . esc_attr((string) $repair['id']) . '">';
                    wp_nonce_field('awd_execute_' . $repair['id']);
                    submit_button('Approve & apply now', 'primary', 'submit', false);
                    echo '</form>';
                }
                foreach (array('approve' => 'Acknowledge manual plan', 'reject' => 'Reject proposal') as $decision => $label) {
                    if ($decision === 'approve' && !empty($repair['operationIds'])) continue;
                    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_decide_repair"><input type="hidden" name="repair_id" value="' . esc_attr((string) $repair['id']) . '"><input type="hidden" name="decision" value="' . esc_attr($decision) . '">';
                    wp_nonce_field('awd_decide_repair_' . $repair['id']);
                    submit_button($label, $decision === 'approve' ? 'primary' : 'secondary', 'submit', false);
                    echo '</form>';
                }
            }
            echo '</div>';
        }
        if (($issue['status'] ?? '') !== 'resolved' && !array_filter($repairs, static function ($repair) { return is_array($repair) && in_array($repair['status'] ?? '', array('pending_approval', 'approved', 'executing', 'in_progress'), true); })) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_propose_repair"><input type="hidden" name="issue_id" value="' . esc_attr((string) ($issue['id'] ?? '')) . '">';
            wp_nonce_field('awd_propose_repair_' . (string) ($issue['id'] ?? ''));
            submit_button('Request central remediation plan', 'secondary', 'submit', false);
            echo '</form>';
        }
        if (empty($diagnosis['diagnosis'])) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="awd_analyze_issue"><input type="hidden" name="issue_id" value="' . esc_attr((string) ($issue['id'] ?? '')) . '">';
            wp_nonce_field('awd_analyze_issue_' . (string) ($issue['id'] ?? ''));
            submit_button('Analyze with central AI', 'secondary', 'submit', false);
            echo '</form>';
        }
        echo '</article>';
    }
}

function awd_analyze_issue(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to request an analysis.', 'ai-website-doctor'), 403);
    $issue_id = isset($_POST['issue_id']) ? sanitize_text_field(wp_unslash($_POST['issue_id'])) : '';
    check_admin_referer('awd_analyze_issue_' . $issue_id);
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $issue_id)) awd_redirect('Invalid issue identifier.', 'error');
    $response = awd_authenticated_request(awd_settings(), '/analysis', 'POST', array('issueId' => $issue_id));
    if (is_wp_error($response)) awd_redirect($response->get_error_message(), 'error');
    $body = json_decode(wp_remote_retrieve_body($response), true);
    awd_redirect(is_array($body) && ($body['aiStatus'] ?? '') === 'unavailable' ? 'Central AI is unavailable. The stored evidence remains available.' : 'Central AI analysis recorded and shared with the application.');
}

function awd_propose_repair(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to request repairs.', 'ai-website-doctor'), 403);
    $issue_id = isset($_POST['issue_id']) ? sanitize_text_field(wp_unslash($_POST['issue_id'])) : '';
    check_admin_referer('awd_propose_repair_' . $issue_id);
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $issue_id)) awd_redirect('Invalid issue identifier.', 'error');
    $response = awd_authenticated_request(awd_settings(), '/repairs', 'POST', array('issueId' => $issue_id));
    awd_redirect(is_wp_error($response) ? $response->get_error_message() : 'Central repair proposal created. Review its exact operations in either interface before approving.', is_wp_error($response) ? 'error' : 'success');
}

function awd_decide_repair(): void
{
    if (!current_user_can('manage_options')) wp_die(esc_html__('You are not allowed to approve repairs.', 'ai-website-doctor'), 403);
    $repair_id = isset($_POST['repair_id']) ? sanitize_text_field(wp_unslash($_POST['repair_id'])) : '';
    $decision = isset($_POST['decision']) ? sanitize_key(wp_unslash($_POST['decision'])) : '';
    check_admin_referer('awd_decide_repair_' . $repair_id);
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $repair_id) || !in_array($decision, array('approve', 'reject'), true)) awd_redirect('Invalid repair decision.', 'error');
    $response = awd_authenticated_request(awd_settings(), '/repairs/' . rawurlencode($repair_id), 'PATCH', array('decision' => $decision));
    awd_redirect(is_wp_error($response) ? $response->get_error_message() : ($decision === 'approve' ? 'Approval recorded centrally. A local administrator must still separately confirm execution.' : 'Proposal rejected.'), is_wp_error($response) ? 'error' : 'success');
}

function awd_poll_central(): void
{
    $settings = awd_settings();
    if (empty($settings['agent_id']) || empty($settings['agent_token'])) {
        return;
    }
    $result = awd_send_diagnostics();
    if (is_wp_error($result)) {
        error_log('[AI Website Doctor] Diagnostics sync failed: ' . $result->get_error_message());
    }
    $response = awd_authenticated_request($settings, '/tasks', 'GET');
    if (is_wp_error($response)) {
        error_log('[AI Website Doctor] Approved task polling failed: ' . $response->get_error_message());
        return;
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    $tasks = is_array($body) && isset($body['tasks']) && is_array($body['tasks']) ? $body['tasks'] : array();
    if (is_array($body) && isset($body['alerts']) && is_array($body['alerts'])) awd_alerts_process_central($body['alerts']);
    // A queued compromise cleanup takes precedence and runs alone in this poll.
    $cleanup_tasks = is_array($body) && isset($body['cleanupTasks']) && is_array($body['cleanupTasks']) ? $body['cleanupTasks'] : array();
    foreach ($cleanup_tasks as $cleanup_task) {
        if (!is_array($cleanup_task) || empty($cleanup_task['executeOnPoll'])) continue;
        $outcome = awd_cleanup_execute_task($settings, $cleanup_task);
        error_log('[AI Website Doctor] Cleanup ' . sanitize_text_field((string) ($cleanup_task['repairId'] ?? '')) . ': ' . $outcome['message']);
        return;
    }
    foreach ($tasks as $task) {
        if (!is_array($task) || empty($task['executeOnPoll']) || empty($task['repairId']) || empty($task['authorizationGrantId'])) {
            continue;
        }
        // Only tasks returned by this authenticated, site-scoped endpoint can enter this worker.
        // Process one task per poll to bound site load and keep execution serialized.
        $GLOBALS['awd_background_repair_id'] = (string) $task['repairId'];
        $_POST['repair_id'] = (string) $task['repairId'];
        try {
            awd_execute_repair();
        } catch (RuntimeException $exception) {
            error_log('[AI Website Doctor] Queued repair ' . sanitize_text_field((string) $task['repairId']) . ': ' . $exception->getMessage());
        } finally {
            unset($GLOBALS['awd_background_repair_id'], $_POST['repair_id']);
        }
        break;
    }
}

function awd_collect_diagnostics(array $settings): array
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $all_plugins = get_plugins();
    $active_plugins = (array) get_option('active_plugins', array());
    $updates = get_site_transient('update_plugins');
    $available_updates = is_object($updates) && isset($updates->response) && is_array($updates->response)
        ? $updates->response
        : array();
    $plugins = array();

    $up_to_date = is_object($updates) && isset($updates->no_update) && is_array($updates->no_update) ? $updates->no_update : array();
    foreach ($all_plugins as $file => $plugin) {
        $update = $available_updates[$file] ?? null;
        $known = $update ?? ($up_to_date[$file] ?? null);
        $entry = array(
            'name' => substr(sanitize_text_field($plugin['Name'] ?? basename($file)), 0, 200),
            'version' => substr(sanitize_text_field($plugin['Version'] ?? ''), 0, 40),
            'file' => substr(sanitize_text_field($file), 0, 200),
            'active' => in_array($file, $active_plugins, true),
            'updateAvailable' => isset($available_updates[$file]),
            // WordPress.org-hosted plugins can be installed and verified against official checksums.
            'source' => is_object($known) && isset($known->id) && str_starts_with((string) $known->id, 'w.org/plugins/') ? 'wordpress.org' : 'other',
        );
        if (is_object($update) && isset($update->new_version) && preg_match('/^[0-9A-Za-z.+-]{1,40}$/', (string) $update->new_version)) {
            $entry['newVersion'] = (string) $update->new_version;
        }
        $plugins[] = $entry;
    }

    $theme = wp_get_theme();
    $editable_pages = array();
    $public_posts = get_posts(array(
        'post_type' => array('post', 'page'),
        'post_status' => 'publish',
        'numberposts' => 250,
        'orderby' => 'ID',
        'order' => 'ASC',
        'suppress_filters' => true,
        'no_found_rows' => true,
    ));
    foreach ($public_posts as $public_post) {
        if (!is_object($public_post) || !isset($public_post->ID, $public_post->post_type)) continue;
        $type = get_post_type_object((string) $public_post->post_type);
        if (!$type || empty($type->public) || !$type->show_in_rest || !post_type_supports($type->name, 'editor')) continue;
        $permalink = get_permalink($public_post);
        if (!is_string($permalink) || $permalink === '') continue;
        $editable_pages[] = array(
            'id' => (int) $public_post->ID,
            'url' => esc_url_raw($permalink),
            'postType' => sanitize_key($type->name),
            'contentSha256' => hash('sha256', (string) $public_post->post_content),
        );
    }
    $cron = _get_cron_array();
    $overdue = 0;
    $scheduled_tasks = array();
    if (is_array($cron)) {
        $cutoff = time() - HOUR_IN_SECONDS;
        foreach (array_keys($cron) as $timestamp) {
            if ((int) $timestamp < $cutoff) {
                $overdue += count((array) $cron[$timestamp]);
            }
        }
        foreach ($cron as $timestamp => $hooks) {
            foreach ((array) $hooks as $hook => $instances) {
                foreach ((array) $instances as $key => $instance) {
                    $id = substr(hash('sha256', (string) $hook . ':' . (string) $timestamp . ':' . (string) $key), 0, 32);
                    $outcome = awd_find_cron_outcome($id);
                    $scheduled_tasks[] = array(
                        'id' => $id,
                        'hook' => substr(sanitize_text_field((string) $hook), 0, 200),
                        'scheduledAt' => gmdate('c', (int) $timestamp),
                        'overdue' => (int) $timestamp < $cutoff,
                        'status' => $outcome['status'] ?? 'pending',
                        'lastStartedAt' => $outcome['startedAt'] ?? null,
                        'lastCompletedAt' => $outcome['completedAt'] ?? null,
                        'failure' => $outcome['failure'] ?? null,
                    );
                    if (count($scheduled_tasks) >= 100) break 3;
                }
            }
        }
    }

    $fatal_events = get_option(AWD_FATAL_OPTION, array());
    $fatal_events = is_array($fatal_events) ? array_slice($fatal_events, -20) : array();
    $cron_history = get_option(AWD_CRON_HISTORY_OPTION, array());
    $cron_history = is_array($cron_history) ? array_slice($cron_history, -100) : array();
    $conflict_testing = awd_conflict_testing_report($plugins, $theme);
    $authorized_log_excerpt = !empty($settings['collect_logs']) ? awd_authorized_log_excerpt() : '';
    $php_log_errors = $authorized_log_excerpt !== '' ? awd_parse_php_log_errors($authorized_log_excerpt) : array();

    $integrity = awd_integrity_report(!empty($GLOBALS['awd_force_integrity_scan']), $plugins);
    // Compromise findings come first so payload truncation never drops them.
    $issues = awd_integrity_issues($integrity);
    if (version_compare(PHP_VERSION, '8.0', '<')) {
        $issues[] = array('fingerprint' => 'php-version-low', 'title' => 'PHP version is outdated', 'description' => 'This site runs PHP ' . PHP_VERSION . '. Upgrade to a currently supported PHP release after checking theme and plugin compatibility.', 'severity' => 'high');
    }
    if (defined('WP_DEBUG') && WP_DEBUG) {
        $issues[] = array('fingerprint' => 'wp-debug-enabled', 'title' => 'WordPress debug mode is enabled', 'description' => 'WP_DEBUG is enabled. Ensure debug output is not exposed to visitors and disable it on production sites when troubleshooting is complete.', 'severity' => 'medium');
    }
    if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
        $issues[] = array('fingerprint' => 'wp-cron-disabled', 'title' => 'WP-Cron is disabled', 'description' => 'DISABLE_WP_CRON is enabled. Confirm a system scheduler is configured to run wp-cron.php.', 'severity' => 'medium');
    }
    if ($overdue > 0) {
        $issues[] = array('fingerprint' => 'overdue-wp-cron', 'title' => 'Overdue scheduled WordPress events', 'description' => sprintf('%d scheduled event(s) are more than one hour overdue. Check the site traffic and configured system cron.', $overdue), 'severity' => 'medium');
    }
    foreach ($fatal_events as $fatal) {
        if (!is_array($fatal)) continue;
        $issues[] = array(
            'fingerprint' => 'php-fatal:' . substr((string) ($fatal['id'] ?? hash('sha256', wp_json_encode($fatal))), 0, 32),
            'title' => 'PHP fatal error detected',
            'description' => substr((string) ($fatal['type'] ?? 'PHP_FATAL') . ': ' . (string) ($fatal['message'] ?? 'Fatal error'), 0, 2000),
            'severity' => 'critical',
        );
    }
    foreach ($php_log_errors as $php_error) {
        $issues[] = array(
            'fingerprint' => 'php-log:' . $php_error['id'],
            'title' => 'PHP ' . ucfirst(str_replace('_', ' ', $php_error['level'])) . ' recorded in WordPress debug log',
            'description' => substr($php_error['message'] . ($php_error['file'] !== '' ? ' (' . $php_error['file'] . ($php_error['line'] > 0 ? ':' . $php_error['line'] : '') . ')' : ''), 0, 2000),
            'severity' => in_array($php_error['level'], array('fatal', 'parse_error'), true) ? 'critical' : (in_array($php_error['level'], array('warning', 'uncaught_exception'), true) ? 'high' : 'medium'),
        );
        if (count($issues) >= 50) break;
    }
    foreach ($cron_history as $outcome) {
        if (!is_array($outcome) || ($outcome['status'] ?? '') !== 'failed') continue;
        $issues[] = array(
            'fingerprint' => 'cron-failed:' . substr((string) ($outcome['id'] ?? ''), 0, 32),
            'title' => 'Scheduled task failed: ' . substr((string) ($outcome['hook'] ?? 'unknown task'), 0, 150),
            'description' => substr((string) (($outcome['failure']['type'] ?? 'Task failure') . ': ' . ($outcome['failure']['message'] ?? 'The scheduled callback ended with a fatal error.')), 0, 2000),
            'severity' => 'high',
        );
    }
    foreach ((array) ($conflict_testing['findings'] ?? array()) as $finding) {
        if (!is_array($finding) || ($finding['result'] ?? '') !== 'conflict') continue;
        $components = array_values(array_filter((array) ($finding['components'] ?? array()), 'is_string'));
        $issues[] = array(
            'fingerprint' => 'staging-conflict:' . substr(hash('sha256', implode('|', $components)), 0, 32),
            'title' => 'Component conflict observed in disposable staging',
            'description' => substr(implode(', ', $components) . ': ' . (string) ($finding['evidence'] ?? 'Browser findings changed when this component state changed.'), 0, 2000),
            'severity' => 'medium',
        );
    }
    foreach ($available_updates as $file => $update) {
        if (count($issues) >= 50) {
            break;
        }
        // The update cache can outlive a plugin that was removed.
        if (!isset($all_plugins[$file])) continue;
        $issues[] = array(
            'fingerprint' => 'plugin-update:' . substr(hash('sha256', (string) $file), 0, 20),
            'title' => 'Plugin update available: ' . sanitize_text_field($all_plugins[$file]['Name'] ?? basename((string) $file)),
            'description' => 'An update is available. Review its release notes and create a backup before updating.',
            'severity' => 'low',
        );
    }

    $diagnostics = array(
        'collectedAt' => gmdate('c'),
        'site' => array(
            'wpVersion' => (string) get_bloginfo('version'),
            'phpVersion' => PHP_VERSION,
            'memoryLimit' => defined('WP_MEMORY_LIMIT') ? (string) WP_MEMORY_LIMIT : (string) ini_get('memory_limit'),
            'environmentType' => function_exists('wp_get_environment_type') ? wp_get_environment_type() : 'production',
            'pluginVersion' => AWD_VERSION,
            'customCssSha256' => function_exists('wp_get_custom_css')
                ? hash('sha256', (string) wp_get_custom_css((string) $theme->get_stylesheet()))
                : null,
            'debugMode' => defined('WP_DEBUG') && WP_DEBUG,
            'cronDisabled' => defined('DISABLE_WP_CRON') && DISABLE_WP_CRON,
            'overdueCronCount' => min(1000, $overdue),
            'scheduledTaskCount' => min(1000, count($scheduled_tasks)),
            'activeTheme' => array(
            'name' => substr(sanitize_text_field($theme->get('Name')), 0, 200),
            'version' => substr(sanitize_text_field($theme->get('Version')), 0, 40),
                'stylesheet' => sanitize_key($theme->get_stylesheet()),
            ),
        ),
        'settings' => array(
            'blogname' => (string) get_option('blogname', ''),
            'blogdescription' => (string) get_option('blogdescription', ''),
        ),
        'plugins' => array_slice($plugins, 0, 100),
        'editablePages' => $editable_pages,
        'fatalErrors' => $fatal_events,
        'phpErrors' => $php_log_errors,
        'phpErrorLog' => array(
            'collectionEnabled' => !empty($settings['collect_logs']),
            'status' => empty($settings['collect_logs']) ? 'disabled' : ($authorized_log_excerpt !== '' ? 'readable' : awd_authorized_log_status()),
            'observedCount' => count($php_log_errors),
            'limit' => 20,
        ),
        'scheduledTasks' => $scheduled_tasks,
        'cronHistory' => $cron_history,
        'conflictTesting' => $conflict_testing,
        'integrity' => $integrity,
        'hardening' => awd_hardening_report(),
        'issues' => array_slice($issues, 0, 50),
    );
    if ($authorized_log_excerpt !== '') $diagnostics['authorizedLogExcerpt'] = $authorized_log_excerpt;
    $encoded = wp_json_encode($diagnostics);
    if (is_string($encoded) && strlen($encoded) > 90000) {
        $diagnostics['plugins'] = array_slice($diagnostics['plugins'], 0, 50);
        $diagnostics['issues'] = array_slice($diagnostics['issues'], 0, 30);
        if (isset($diagnostics['authorizedLogExcerpt'])) $diagnostics['authorizedLogExcerpt'] = substr($diagnostics['authorizedLogExcerpt'], -4000);
        foreach (array('rootUnknownFiles', 'uploadsPhp', 'muPlugins', 'contentRootPhp', 'suspiciousFiles') as $key) {
            $diagnostics['integrity'][$key] = array_slice((array) ($diagnostics['integrity'][$key] ?? array()), 0, 20);
        }
        $diagnostics['integrity']['truncated'] = true;
    }
    return $diagnostics;
}

function awd_parse_php_log_errors(string $excerpt): array
{
    $errors = array();
    foreach (preg_split('/\r?\n/', $excerpt) ?: array() as $line) {
        if (!preg_match('/\bPHP\s+(Warning|Notice|Deprecated|Fatal error|Parse error|Recoverable fatal error|Uncaught (?:Error|TypeError|Exception))\s*:\s*(.*)$/i', $line, $match)) continue;
        $level_text = strtolower($match[1]);
        $level = str_contains($level_text, 'fatal') ? 'fatal' : (str_contains($level_text, 'parse') ? 'parse_error' : (str_contains($level_text, 'uncaught') ? 'uncaught_exception' : $level_text));
        $message = trim($match[2]);
        $file = '';
        $line_number = 0;
        if (preg_match('/^(.*)\s+in\s+(.+?)\s+on line\s+(\d+)\s*$/i', $message, $location)) {
            $message = trim($location[1]);
            $file = basename(str_replace('\\', '/', $location[2]));
            $line_number = min(2_147_483_647, (int) $location[3]);
        }
        $message = substr(awd_redact_error_text($message), 0, 500);
        $identity = $level . ':' . $message . ':' . $file . ':' . $line_number;
        $errors[] = array(
            'id' => substr(hash('sha256', $identity), 0, 32),
            'level' => $level,
            'message' => $message,
            'file' => substr(sanitize_text_field($file), 0, 200),
            'plugin' => isset($location[2]) ? awd_plugin_file_for_error_path((string) $location[2]) : null,
            'line' => $line_number,
        );
        if (count($errors) >= 20) break;
    }
    return array_values(array_map('unserialize', array_unique(array_map('serialize', $errors))));
}

function awd_authorized_log_status(): string
{
    $content_root = realpath(WP_CONTENT_DIR);
    $log_path = realpath(WP_CONTENT_DIR . '/debug.log');
    if ($content_root === false || $log_path === false || dirname($log_path) !== $content_root || !is_file($log_path)) return 'not_found';
    if (!is_readable($log_path)) return 'unreadable';
    $size = filesize($log_path);
    return is_int($size) && $size > 0 ? 'unavailable' : 'empty';
}

function awd_authorized_log_excerpt(): string
{
    $content_root = realpath(WP_CONTENT_DIR);
    $log_path = realpath(WP_CONTENT_DIR . '/debug.log');
    if ($content_root === false || $log_path === false || dirname($log_path) !== $content_root) {
        return '';
    }
    if (!is_file($log_path) || !is_readable($log_path)) {
        return '';
    }
    $size = filesize($log_path);
    if (!is_int($size) || $size <= 0) {
        return '';
    }
    $handle = fopen($log_path, 'rb');
    if ($handle === false) {
        return '';
    }
    fseek($handle, max(0, $size - 16384));
    $content = fread($handle, 16384);
    fclose($handle);
    if (!is_string($content)) {
        return '';
    }
    $content = preg_replace('/(authorization|password|passwd|secret|token|api[_-]?key|cookie)\s*[:=]\s*[^;\s,]+/i', '$1=[REDACTED]', $content);
    $content = preg_replace('/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/', '[REDACTED_AWS_KEY]', (string) $content);
    $content = preg_replace('/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/i', '[REDACTED_GITHUB_TOKEN]', (string) $content);
    $content = preg_replace('/\bAIza[0-9A-Za-z_-]{35}\b/', '[REDACTED_API_KEY]', (string) $content);
    $content = preg_replace('/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/', '[REDACTED_API_KEY]', (string) $content);
    $content = preg_replace('/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/', '[REDACTED_JWT]', (string) $content);
    $content = preg_replace('/\b[A-Za-z0-9+\/_-]{40,}={0,2}\b/', '[REDACTED_TOKEN]', (string) $content);
    return substr(sanitize_textarea_field((string) $content), -12000);
}

function awd_render_diagnostics(array $diagnostics): void
{
    $site = $diagnostics['site'];
    ?>
    <div class="awd-diagnostics">
        <p><strong>WordPress:</strong> <?php echo esc_html($site['wpVersion']); ?> ·
            <strong>PHP:</strong> <?php echo esc_html($site['phpVersion']); ?> ·
            <strong>Theme:</strong> <?php echo esc_html($site['activeTheme']['name'] . ' ' . $site['activeTheme']['version']); ?></p>
        <p><strong>Active plugins:</strong> <?php echo esc_html((string) count(array_filter($diagnostics['plugins'], static function ($plugin) { return $plugin['active']; }))); ?> /
            <?php echo esc_html((string) count($diagnostics['plugins'])); ?> ·
            <strong>Overdue WP-Cron:</strong> <?php echo esc_html((string) $site['overdueCronCount']); ?> ·
            <strong>Failed task outcomes:</strong> <?php echo esc_html((string) count(array_filter($diagnostics['cronHistory'], static function ($event) { return ($event['status'] ?? '') === 'failed'; }))); ?> ·
            <strong>Fatal events:</strong> <?php echo esc_html((string) count($diagnostics['fatalErrors'])); ?> ·
            <strong>PHP log errors:</strong> <?php echo esc_html((string) count($diagnostics['phpErrors'] ?? array())); ?> ·
            <strong>Detected issues:</strong> <?php echo esc_html((string) count($diagnostics['issues'])); ?></p>
        <?php $integrity = is_array($diagnostics['integrity'] ?? null) ? $diagnostics['integrity'] : array(); ?>
        <p><strong>Integrity scan:</strong> <?php echo esc_html(sprintf(
            '%s at %s · %d core files checked · %d modified · %d unknown core PHP · %d PHP in uploads · %d files with malware patterns · %d suspicious .htaccess rules',
            (string) ($integrity['status'] ?? 'not run'),
            (string) ($integrity['scannedAt'] ?? '—'),
            (int) ($integrity['core']['checkedFiles'] ?? 0),
            count((array) ($integrity['core']['modified'] ?? array())),
            count((array) ($integrity['core']['unknownPhp'] ?? array())),
            count((array) ($integrity['uploadsPhp'] ?? array())),
            count((array) ($integrity['suspiciousFiles'] ?? array())),
            count((array) ($integrity['htaccess']['suspiciousLines'] ?? array()))
        )); ?>. Read-only; <em>Collect and sync diagnostics</em> reruns it (otherwise every 6 hours).</p>
        <p><strong>PHP log evidence:</strong> <?php echo esc_html(($diagnostics['phpErrorLog']['status'] ?? 'disabled') . ' · ' . (string) count($diagnostics['phpErrors'] ?? array()) . ' parsed entries, maximum 20'); ?>. Only the explicitly authorized, bounded WordPress debug.log excerpt is inspected; system PHP-FPM/web-server logs are not accessible to this plugin.</p>
        <?php if ($diagnostics['issues']) : ?>
            <ul>
                <?php foreach ($diagnostics['issues'] as $issue) : ?>
                    <li><strong><?php echo esc_html(strtoupper($issue['severity'])); ?>:</strong>
                        <?php echo esc_html($issue['title'] . ' — ' . $issue['description']); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php else : ?>
            <p>No issues were detected by these basic checks.</p>
        <?php endif; ?>
    </div>
    <?php
}

function awd_render_pending_repairs(array $settings): void
{
    $response = awd_authenticated_request($settings, '/tasks', 'GET');
    if (is_wp_error($response)) {
        echo '<p>' . esc_html($response->get_error_message()) . '</p>';
        return;
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    $tasks = is_array($body) && isset($body['tasks']) && is_array($body['tasks']) ? $body['tasks'] : array();
    $rollback_requests = is_array($body) && isset($body['rollbackRequests']) && is_array($body['rollbackRequests'])
        ? $body['rollbackRequests']
        : array();
    $manual_recovery_requests = is_array($body) && isset($body['manualRecoveryRequests']) && is_array($body['manualRecoveryRequests'])
        ? $body['manualRecoveryRequests']
        : array();
    if (!$tasks && !$rollback_requests && !$manual_recovery_requests) {
        if (!empty($body['diagnosticsRequired'])) {
            echo '<p>Sync diagnostics before approved repairs can be made available.</p>';
        } else {
            echo '<p>No eligible centrally approved repairs are waiting.</p>';
        }
        return;
    }
    foreach ($tasks as $task) {
        if (!is_array($task) || empty($task['repairId']) || empty($task['steps']) || !is_array($task['steps'])) {
            continue;
        }
        ?>
        <div class="awd-repair">
            <p><strong><?php echo esc_html($task['issue'] ?? 'Approved repair'); ?></strong>
                · Risk: <?php echo esc_html($task['risk'] ?? 'unknown'); ?></p>
            <p>Required permission: <?php echo esc_html(implode(', ', array_filter((array) ($task['requiredPermissions'] ?? array()), 'is_string'))); ?>.
                The plugin saves a small undo record for the exact target and previous value before applying.</p>
            <p><?php echo esc_html($task['rationale'] ?? ''); ?></p>
            <ul>
                <?php foreach ($task['steps'] as $step) : ?>
                    <?php if (is_array($step) && isset($step['description'])) : ?>
                        <li><?php echo esc_html((string) $step['description']); ?> <code><?php echo esc_html((string) ($step['operation'] ?? '')); ?></code></li>
                    <?php endif; ?>
                <?php endforeach; ?>
            </ul>
            <?php if (!empty($task['executeOnPoll'])) : ?>
                <p><strong>Queued for this site's next WordPress poll.</strong> You can also apply it immediately below.</p>
            <?php else : ?>
                <p><strong>Central approval is recorded. Choose below to apply it on this site.</strong></p>
            <?php endif; ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_execute">
                <input type="hidden" name="repair_id" value="<?php echo esc_attr($task['repairId']); ?>">
                <?php wp_nonce_field('awd_execute_' . $task['repairId']); ?>
                <?php submit_button(!empty($task['executeOnPoll']) ? 'Apply now' : 'Apply this repair', 'primary', 'submit', false); ?>
            </form>
        </div>
        <?php
    }
    foreach ($rollback_requests as $rollback) {
        if (!is_array($rollback) || empty($rollback['repairId']) || empty($rollback['backupId'])) {
            continue;
        }
        ?>
        <div class="awd-repair">
            <p><strong>Central verification recommends rollback:</strong> <?php echo esc_html($rollback['issue'] ?? 'Repair verification'); ?></p>
            <p><?php echo esc_html($rollback['reason'] ?? 'Review the recovery point before restoring it.'); ?></p>
            <p><strong>A local administrator must confirm this recovery action.</strong></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_central_rollback">
                <input type="hidden" name="repair_id" value="<?php echo esc_attr($rollback['repairId']); ?>">
                <input type="hidden" name="backup_id" value="<?php echo esc_attr($rollback['backupId']); ?>">
                <?php wp_nonce_field('awd_central_rollback_' . $rollback['repairId']); ?>
                <?php submit_button('Restore this recovery point', 'delete', 'submit', false); ?>
            </form>
        </div>
        <?php
    }
    foreach ($manual_recovery_requests as $recovery) {
        if (!is_array($recovery) || empty($recovery['repairId']) || empty($recovery['backupId'])) continue;
        ?>
        <div class="awd-repair">
            <p><strong>Restore requested from the central app:</strong> <?php echo esc_html($recovery['issue'] ?? 'Repair recovery point'); ?></p>
            <p><?php echo esc_html(($recovery['operation'] ?? 'repair') . (!empty($recovery['target']) ? ' · ' . $recovery['target'] : '')); ?></p>
            <p><?php echo esc_html($recovery['reason'] ?? 'A website administrator requested restoration.'); ?></p>
            <p><strong>This restores only the saved operation state; review and confirm locally.</strong></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="awd_central_rollback">
                <input type="hidden" name="repair_id" value="<?php echo esc_attr($recovery['repairId']); ?>">
                <input type="hidden" name="backup_id" value="<?php echo esc_attr($recovery['backupId']); ?>">
                <input type="hidden" name="manual_restore" value="1">
                <?php wp_nonce_field('awd_central_rollback_' . $recovery['repairId']); ?>
                <?php submit_button('Restore this Drive recovery point', 'delete', 'submit', false); ?>
            </form>
        </div>
        <?php
    }
}

function awd_render_recovery_points(): void
{
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points) || !$points) {
        echo '<p>No recovery points have been created.</p>';
        return;
    }
    echo '<ul>';
    foreach (array_reverse($points) as $point) {
        if (!is_array($point) || empty($point['id'])) {
            continue;
        }
        echo '<li>' . esc_html(($point['created_at'] ?? '') . ' · ' . ($point['description'] ?? 'Recovery point')) . ' ';
        if (($point['complete'] ?? false) !== true || !isset($point['operations']) || !is_array($point['operations'])) {
        echo '<span>' . esc_html__('This entry has no complete operation-specific undo record and cannot be restored safely.', 'ai-website-doctor') . '</span></li>';
            continue;
        }
        if (!empty($point['drive_backup_id'])) {
            echo '<small>' . esc_html__('Synced to the central app’s website-specific Google Drive backup.', 'ai-website-doctor') . '</small> ';
        } else {
            echo '<small>' . esc_html__('Stored locally in WordPress only; not synced to Google Drive.', 'ai-website-doctor') . '</small> ';
        }
        ?>
        <form class="awd-inline-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="awd_rollback">
            <input type="hidden" name="backup_id" value="<?php echo esc_attr($point['id']); ?>">
            <?php wp_nonce_field('awd_rollback_' . $point['id']); ?>
            <?php submit_button('Restore', 'secondary', 'submit', false); ?>
        </form></li>
        <?php
    }
    echo '</ul>';
}

function awd_execute_repair(): void
{
    $background = !empty($GLOBALS['awd_background_repair_id']);
    if (!$background && !current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to execute repairs.', 'ai-website-doctor'), 403);
    }
    $repair_id = isset($_POST['repair_id']) ? sanitize_text_field(wp_unslash($_POST['repair_id'])) : '';
    if (!$background) {
        check_admin_referer('awd_execute_' . $repair_id);
    } elseif (!hash_equals((string) $GLOBALS['awd_background_repair_id'], $repair_id)) {
        return;
    }
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $repair_id)) {
        awd_redirect('Invalid repair identifier.', 'error');
    }
    $settings = awd_settings();
    $response = awd_authenticated_request($settings, '/tasks', 'GET');
    if (is_wp_error($response)) {
        awd_redirect($response->get_error_message(), 'error');
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    $tasks = is_array($body) && isset($body['tasks']) && is_array($body['tasks']) ? $body['tasks'] : array();
    $task = null;
    foreach ($tasks as $candidate) {
        if (is_array($candidate) && ($candidate['repairId'] ?? '') === $repair_id) {
            $task = $candidate;
            break;
        }
    }
    if (!$task) {
        $approval = awd_authenticated_request($settings, '/repairs/' . rawurlencode($repair_id), 'PATCH', array('decision' => 'approve'));
        $response = awd_authenticated_request($settings, '/tasks', 'GET');
        if (!is_wp_error($response)) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $tasks = is_array($body) && isset($body['tasks']) && is_array($body['tasks']) ? $body['tasks'] : array();
            foreach ($tasks as $candidate) {
                if (is_array($candidate) && ($candidate['repairId'] ?? '') === $repair_id) {
                    $task = $candidate;
                    break;
                }
            }
        }
        if (!$task && is_wp_error($approval)) {
            awd_redirect('Could not approve and load this repair: ' . $approval->get_error_message(), 'error');
        }
    }
    if (!$task || empty($task['steps']) || !is_array($task['steps'])
        || empty($task['authorizationGrantId']) || empty($task['authorizationExpiresAt'])
        || strtotime((string) $task['authorizationExpiresAt']) <= time()
        || empty($task['issueFingerprint']) || !is_string($task['issueFingerprint'])
        || (!str_starts_with($task['issueFingerprint'], 'wp:') && !str_starts_with($task['issueFingerprint'], 'browser:link-redirect:') && !str_starts_with($task['issueFingerprint'], 'browser:broken-link:'))) {
        awd_redirect('This repair is not currently approved by the central application.', 'error');
    }
    if (!$background && !current_user_can('manage_options')) {
        wp_die(esc_html__('The required repair permission is not available.', 'ai-website-doctor'), 403);
    }

    $lock_option = 'awd_repair_lock_' . substr(hash('sha256', $repair_id), 0, 32);
    if (get_option($lock_option) && (int) get_option($lock_option) < time() - 900) {
        delete_option($lock_option);
    }
    if (!add_option($lock_option, time(), '', false)) {
        awd_redirect('This repair is already being applied. Wait and refresh before retrying.', 'warning');
    }
    $execution_started_at = gmdate('c');
    $requires_central_browser_retest = str_starts_with((string) $task['issueFingerprint'], 'wp:staging-conflict:')
        || str_starts_with((string) $task['issueFingerprint'], 'browser:link-redirect:')
        || str_starts_with((string) $task['issueFingerprint'], 'browser:broken-link:');
    $before_settings = $settings;
    $before_settings['collect_logs'] = false;
    $before_diagnostics = awd_collect_diagnostics($before_settings);
    $backup_id = awd_create_recovery_point('Approved repair ' . $repair_id, (array) $task['steps']);
    $local_recovery_available = awd_recovery_point_exists($backup_id);
    if (!$local_recovery_available) {
        $after_settings = $settings;
        $after_settings['collect_logs'] = false;
        $diagnostics = awd_collect_diagnostics($after_settings);
        $report = awd_authenticated_request($settings, '/executions', 'POST', array(
            'repairId' => $repair_id,
            'authorizationGrantId' => (string) $task['authorizationGrantId'],
            'status' => 'failed',
            'result' => array(
                'message' => 'A complete operation-specific undo record could not be saved; no change was made.',
                'startedAt' => $execution_started_at,
                'backupStatus' => 'unavailable',
                'executionStatus' => 'failed',
                'verificationStatus' => 'inconclusive',
                'verificationReason' => 'The exact target and previous value could not be saved for every operation.',
                'verified' => false,
                'rollbackApplied' => false,
                'beforeEvidence' => $before_diagnostics,
                'afterEvidence' => $diagnostics,
            ),
        ));
        delete_option($lock_option);
        if (is_wp_error($report)) {
            awd_redirect('No repair was executed. Recovery-point failure could not be recorded centrally: ' . $report->get_error_message(), 'error');
        }
        awd_redirect('No change was made because an exact operation-specific undo record could not be saved.', 'error');
    }
    $after_settings = $settings;
    $after_settings['collect_logs'] = false;
    if (!empty($task['requireCloudBackup'])) {
        $recovery_point = awd_find_recovery_point($backup_id);
        if (!$recovery_point) {
            $diagnostics = awd_collect_diagnostics($after_settings);
            $report = awd_authenticated_request($settings, '/executions', 'POST', array(
                'repairId' => $repair_id,
                'authorizationGrantId' => (string) $task['authorizationGrantId'],
                'status' => 'failed',
                'result' => array(
                    'message' => 'No change was made because the saved recovery point could not be loaded.',
                    'startedAt' => $execution_started_at,
                    'backupId' => $backup_id,
                    'backupStatus' => 'failed',
                    'executionStatus' => 'failed',
                    'verificationStatus' => 'inconclusive',
                    'verificationReason' => 'The exact recovery point could not be loaded before the repair.',
                    'verified' => false,
                    'rollbackApplied' => false,
                    'beforeEvidence' => $before_diagnostics,
                    'afterEvidence' => $diagnostics,
                ),
            ));
            delete_option($lock_option);
            awd_redirect(is_wp_error($report)
                ? 'No change was made because the saved recovery point could not be loaded. The failure could not be recorded centrally: ' . $report->get_error_message()
                : 'No change was made because the saved recovery point could not be loaded.', 'error');
        }
        $cloud_backup = awd_authenticated_request($settings, '/backups', 'POST', array(
            'repairId' => $repair_id,
            'backupId' => $backup_id,
            'recoveryPoint' => $recovery_point,
        ));
        if (is_wp_error($cloud_backup)) {
            $after_diagnostics = awd_collect_diagnostics($after_settings);
            $report = awd_authenticated_request($settings, '/executions', 'POST', array(
                'repairId' => $repair_id,
                'authorizationGrantId' => (string) $task['authorizationGrantId'],
                'status' => 'failed',
                'result' => array(
                    'message' => 'No change was made because the recovery point could not be synced to Google Drive: ' . $cloud_backup->get_error_message(),
                    'startedAt' => $execution_started_at,
                    'backupId' => $backup_id,
                    'backupStatus' => 'failed',
                    'executionStatus' => 'failed',
                    'verificationStatus' => 'inconclusive',
                    'verificationReason' => 'A website-scoped Google Drive recovery point is required before this repair can run.',
                    'verified' => false,
                    'rollbackApplied' => false,
                    'beforeEvidence' => $before_diagnostics,
                    'afterEvidence' => $after_diagnostics,
                ),
            ));
            delete_option($lock_option);
            if (is_wp_error($report)) {
                awd_redirect('No change was made because Google Drive backup failed. The execution failure could not be recorded centrally: ' . $report->get_error_message(), 'error');
            }
            awd_redirect('No change was made because the recovery point could not be synced to Google Drive: ' . $cloud_backup->get_error_message(), 'error');
        }
        $cloud_backup_body = json_decode(wp_remote_retrieve_body($cloud_backup), true);
        if (!is_array($cloud_backup_body) || ($cloud_backup_body['backupId'] ?? '') !== $backup_id || ($cloud_backup_body['status'] ?? '') !== 'created') {
            $after_diagnostics = awd_collect_diagnostics($after_settings);
            $report = awd_authenticated_request($settings, '/executions', 'POST', array(
                'repairId' => $repair_id,
                'authorizationGrantId' => (string) $task['authorizationGrantId'],
                'status' => 'failed',
                'result' => array(
                    'message' => 'No change was made because Google Drive did not confirm the recovery point.',
                    'startedAt' => $execution_started_at,
                    'backupId' => $backup_id,
                    'backupStatus' => 'failed',
                    'executionStatus' => 'failed',
                    'verificationStatus' => 'inconclusive',
                    'verificationReason' => 'A website-scoped Google Drive recovery point must be confirmed before the repair can run.',
                    'verified' => false,
                    'rollbackApplied' => false,
                    'beforeEvidence' => $before_diagnostics,
                    'afterEvidence' => $after_diagnostics,
                ),
            ));
            delete_option($lock_option);
            awd_redirect(is_wp_error($report)
                ? 'No change was made because Google Drive did not confirm the recovery point. The failure could not be recorded centrally: ' . $report->get_error_message()
                : 'No change was made because Google Drive did not confirm the recovery point.', 'error');
        }
        awd_mark_recovery_point_cloud_synced($backup_id, (string) $cloud_backup_body['backupId']);
    }
    $result = awd_apply_steps($task['steps'], $backup_id);
    $rollback_applied = false;
    $execution_status = is_wp_error($result) ? 'failed' : 'completed';
    $after_diagnostics = awd_collect_diagnostics($after_settings);
    $verification = is_wp_error($result)
        ? array('status' => 'inconclusive', 'reason' => 'Repair operation did not complete.')
        : ($requires_central_browser_retest
            ? array('status' => 'inconclusive', 'reason' => 'Central browser verification is required for this staging-derived repair.')
            : awd_verify_repair_diagnostics(array_merge($task, array('executionStartedAt' => $execution_started_at)), $after_diagnostics));
    if (is_wp_error($result) || (!$requires_central_browser_retest && $verification['status'] !== 'passed')) {
        $rollback = $local_recovery_available
            ? awd_restore_recovery_point($backup_id)
            : new WP_Error('awd_no_local_recovery', 'No complete operation-specific undo record was available; use the site backup you maintain if restoration is needed.');
        $rollback_applied = $local_recovery_available && !is_wp_error($rollback);
        $failure = is_wp_error($result)
            ? $result->get_error_message()
            : $verification['reason'];
        $result = new WP_Error('awd_repair_failed', $failure . (is_wp_error($rollback) ? ' Automatic rollback also failed: ' . $rollback->get_error_message() : ' Changes were rolled back.'));
        if ($rollback_applied) {
            $after_diagnostics = awd_collect_diagnostics($after_settings);
        }
    }
    $message = is_wp_error($result)
        ? $result->get_error_message()
        : 'The original WordPress finding is absent and no new high-severity findings were detected.';
    $report = awd_authenticated_request($settings, '/executions', 'POST', array(
        'repairId' => $repair_id,
        'authorizationGrantId' => (string) $task['authorizationGrantId'],
        'authorizationGrantId' => (string) ($task['authorizationGrantId'] ?? ''),
        'status' => is_wp_error($result) ? 'failed' : 'completed',
        'result' => array(
            'message' => $message,
            'startedAt' => $execution_started_at,
            'backupId' => $local_recovery_available ? $backup_id : null,
            'backupStatus' => $local_recovery_available ? 'created' : 'unavailable',
            'executionStatus' => $execution_status,
            'verificationStatus' => $verification['status'],
            'verificationReason' => $verification['reason'],
            'verified' => !is_wp_error($result) && $verification['status'] === 'passed',
                'rollbackApplied' => $rollback_applied,
                'localStateRestoreApplied' => $rollback_applied,
                'beforeEvidence' => $before_diagnostics,
                'afterEvidence' => $after_diagnostics,
        ),
    ));
    delete_option($lock_option);
    if (is_wp_error($report)) {
        if ($requires_central_browser_retest) {
            $rollback = $local_recovery_available
                ? awd_restore_recovery_point($backup_id)
                : new WP_Error('awd_no_local_recovery', 'No complete operation-specific undo record is available.');
            $rollback_message = is_wp_error($rollback) ? 'Central verification was unavailable and local rollback failed: ' . $rollback->get_error_message() : 'Central verification was unavailable, so the change was automatically rolled back.';
            awd_redirect($rollback_message . ' Execution history could not be updated: ' . $report->get_error_message(), 'warning');
        }
        awd_redirect($message . ' Central execution history could not be updated: ' . $report->get_error_message(), 'warning');
    }
    $central_result = json_decode(wp_remote_retrieve_body($report), true);
    if (!is_array($central_result) || empty($central_result['status'])) {
        $rollback = $local_recovery_available ? awd_restore_recovery_point($backup_id) : new WP_Error('awd_no_local_recovery', 'No operation-specific undo record is available.');
        $rollback_recorded = awd_report_local_rollback($settings, $repair_id, $backup_id, $rollback);
        awd_redirect((is_wp_error($rollback) ? 'The app could not verify the change and local undo failed: ' . $rollback->get_error_message() : 'The app returned no verifiable status, so the exact operation target was restored.')
            . (is_wp_error($rollback_recorded) ? ' Central rollback history could not be confirmed: ' . $rollback_recorded->get_error_message() : ''), 'warning');
    }
    if ($central_result['status'] === 'rollback_required') {
        $rollback = $local_recovery_available
            ? awd_restore_recovery_point($backup_id)
            : new WP_Error('awd_no_local_recovery', 'No complete operation-specific undo record is available. Restore from the site backup you maintain.');
        $rollback_settings = $settings;
        $rollback_settings['collect_logs'] = false;
        $rollback_diagnostics = awd_collect_diagnostics($rollback_settings);
        $rollback_report = awd_authenticated_request($settings, '/executions', 'POST', array(
            'repairId' => $repair_id,
            'status' => is_wp_error($rollback) ? 'rollback_failed' : 'rolled_back',
            'result' => array(
                'message' => is_wp_error($rollback) ? $rollback->get_error_message() : 'Verification failed or was inconclusive; the recovery point was restored automatically.',
                'startedAt' => gmdate('c'),
                'backupId' => $local_recovery_available ? $backup_id : null,
                'backupStatus' => $local_recovery_available ? 'created' : 'unavailable',
                'executionStatus' => is_wp_error($rollback) ? 'failed' : 'completed',
                'verificationStatus' => is_wp_error($rollback) ? 'failed' : 'passed',
                'verificationReason' => is_wp_error($rollback) ? $rollback->get_error_message() : 'Saved plugin/theme/settings state was restored.',
                'verified' => !is_wp_error($rollback),
                'rollbackApplied' => !is_wp_error($rollback),
                'localStateRestoreApplied' => !is_wp_error($rollback),
                'afterEvidence' => $rollback_diagnostics,
            ),
        ));
        if (is_wp_error($rollback_report)) {
                awd_redirect((is_wp_error($rollback) ? 'Operation-specific undo failed: ' . $rollback->get_error_message() : 'The exact operation target was restored.') . ' Use your separate site recovery process if other effects remain. Central history could not be updated: ' . $rollback_report->get_error_message(), 'warning');
        }
        $rollback_result = json_decode(wp_remote_retrieve_body($rollback_report), true);
        if (is_wp_error($rollback) || !is_array($rollback_result) || !in_array(($rollback_result['status'] ?? ''), array('rolled_back', 'rollback_required'), true) || empty($rollback_result['ok'])) {
            awd_redirect('Operation-specific undo could not be confirmed centrally. Use your separate site recovery process if needed. Undo record: ' . $backup_id, 'error');
        }
        awd_redirect('Verification failed or was inconclusive. The WordPress recovery point was restored: ' . $backup_id, 'warning');
    }
    if ($central_result['status'] === 'rolled_back') {
        awd_redirect('The repair was not verified and the recovery point was restored: ' . $backup_id, 'warning');
    }
    if ($central_result['status'] !== 'verified') {
        $rollback = $local_recovery_available ? awd_restore_recovery_point($backup_id) : new WP_Error('awd_no_local_recovery', 'No operation-specific undo record is available.');
        $rollback_recorded = awd_report_local_rollback($settings, $repair_id, $backup_id, $rollback);
        awd_redirect((is_wp_error($rollback) ? 'The central app did not verify the repair and local undo failed: ' . $rollback->get_error_message() : 'The central app did not verify the repair, so the exact operation target was restored.')
            . (is_wp_error($rollback_recorded) ? ' Central rollback history could not be confirmed: ' . $rollback_recorded->get_error_message() : ''), 'warning');
    }
    awd_redirect($message . ' Recovery point: ' . $backup_id, 'success');
}

function awd_execute_central_rollback(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to restore recovery points.', 'ai-website-doctor'), 403);
    }
    $repair_id = isset($_POST['repair_id']) ? sanitize_text_field(wp_unslash($_POST['repair_id'])) : '';
    $backup_id = isset($_POST['backup_id']) ? sanitize_text_field(wp_unslash($_POST['backup_id'])) : '';
    $manual_restore = isset($_POST['manual_restore']) && sanitize_text_field(wp_unslash($_POST['manual_restore'])) === '1';
    check_admin_referer('awd_central_rollback_' . $repair_id);
    if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $repair_id) || !wp_is_uuid($backup_id)) {
        awd_redirect('Invalid repair or recovery point identifier.', 'error');
    }

    $settings = awd_settings();
    $response = awd_authenticated_request($settings, '/tasks', 'GET');
    if (is_wp_error($response)) {
        awd_redirect($response->get_error_message(), 'error');
    }
    $body = json_decode(wp_remote_retrieve_body($response), true);
    $requests = is_array($body) && isset($body['rollbackRequests']) && is_array($body['rollbackRequests'])
        ? $body['rollbackRequests']
        : array();
    $manual_requests = is_array($body) && isset($body['manualRecoveryRequests']) && is_array($body['manualRecoveryRequests'])
        ? $body['manualRecoveryRequests']
        : array();
    $authorized = false;
    foreach ($manual_restore ? $manual_requests : $requests as $rollback) {
        if (is_array($rollback) && ($rollback['repairId'] ?? '') === $repair_id && ($rollback['backupId'] ?? '') === $backup_id) {
            $authorized = true;
            break;
        }
    }
    if (!$authorized) {
        awd_redirect('Central rollback request is no longer active.', 'error');
    }

    $lock_option = 'awd_repair_lock_' . substr(hash('sha256', $repair_id), 0, 32);
    if (!add_option($lock_option, time(), '', false)) {
        awd_redirect('This repair is already being applied. Wait and refresh before retrying.', 'warning');
    }
    if ($manual_restore) {
        $download = awd_authenticated_request($settings, '/backups/' . rawurlencode($backup_id), 'GET');
        if (is_wp_error($download)) {
            $restore = $download;
        } else {
            $downloaded = json_decode(wp_remote_retrieve_body($download), true);
            $restore = is_array($downloaded) && ($downloaded['backupId'] ?? '') === $backup_id
                && is_array($downloaded['recoveryPoint'] ?? null)
                ? awd_import_recovery_point($downloaded['recoveryPoint'], $backup_id)
                : new WP_Error('awd_drive_backup_invalid', 'The central app returned an invalid Google Drive recovery point.');
            if (!is_wp_error($restore)) $restore = awd_restore_recovery_point($backup_id);
        }
    } else {
        $restore = awd_restore_recovery_point($backup_id);
    }
    $after_settings = $settings;
    $after_settings['collect_logs'] = false;
    $message = is_wp_error($restore) ? $restore->get_error_message() : 'Central rollback request was applied and verified.';
    $report = $manual_restore
        ? awd_authenticated_request($settings, '/backups/' . rawurlencode($backup_id) . '/restore-result', 'POST', array(
            'status' => is_wp_error($restore) ? 'failed' : 'restored',
            'message' => $message,
        ))
        : awd_authenticated_request($settings, '/executions', 'POST', array(
            'repairId' => $repair_id,
            'status' => is_wp_error($restore) ? 'rollback_failed' : 'rolled_back',
            'result' => array(
                'message' => $message,
                'startedAt' => gmdate('c'),
                'backupId' => $backup_id,
                'backupStatus' => 'created',
                'executionStatus' => is_wp_error($restore) ? 'failed' : 'completed',
                'verificationStatus' => is_wp_error($restore) ? 'failed' : 'passed',
                'verificationReason' => $message,
                'verified' => !is_wp_error($restore),
                'rollbackApplied' => !is_wp_error($restore),
                'afterEvidence' => awd_collect_diagnostics($after_settings),
            ),
        ));
    delete_option($lock_option);
    if (is_wp_error($report)) {
        awd_redirect($message . ' Central execution history could not be updated: ' . $report->get_error_message(), 'warning');
    }
    $central_result = json_decode(wp_remote_retrieve_body($report), true);
    if (!is_array($central_result)) {
        awd_redirect('Local recovery was attempted, but the central app could not record the result.', 'warning');
    }
    if ($manual_restore) {
        $expected_restore_status = is_wp_error($restore) ? 'failed' : 'restored';
        if (($central_result['status'] ?? '') !== $expected_restore_status) {
            awd_redirect('Local recovery was attempted, but the central app could not confirm the restore result.', 'warning');
        }
        awd_redirect(is_wp_error($restore) ? 'The Drive recovery point could not be restored: ' . $message : 'The Drive recovery point was restored.', is_wp_error($restore) ? 'error' : 'success');
    }
    if (empty($central_result['ok']) || ($central_result['status'] ?? '') !== 'rolled_back') {
        awd_redirect('Local recovery was attempted, but the central app could not verify the restored state.', 'warning');
    }
    awd_redirect($message, 'success');
}

function awd_create_recovery_point(string $description, array $steps = array()): string
{
    $id = wp_generate_uuid4();
    $operations = array();
    $complete = count($steps) === 1;
    foreach ($steps as $step) {
        if (!is_array($step) || !is_array($step['parameters'] ?? null)) { $complete = false; $operations[] = array(); continue; }
        $params = $step['parameters'];
        switch ($step['operation'] ?? '') {
            case 'disable_plugin':
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
                $plugin = (string) ($params['plugin'] ?? '');
                if ($plugin === '' || !array_key_exists($plugin, get_plugins()) || $plugin === plugin_basename(__FILE__) || !is_plugin_active($plugin)
                    || (is_multisite() && is_plugin_active_for_network($plugin))) { $complete = false; $operations[] = array(); break; }
                $operations[] = array('operation' => 'disable_plugin', 'target' => $plugin,
                    'before' => is_plugin_active($plugin), 'after' => false, 'applied' => false);
                break;
            case 'switch_theme':
                $next = (string) ($params['stylesheet'] ?? '');
                $themes = wp_get_themes();
                if ($next === '' || !isset($themes[$next]) || !$themes[$next]->exists()) { $complete = false; $operations[] = array(); break; }
                $operations[] = array('operation' => 'switch_theme', 'target' => $next,
                    'before' => array('stylesheet' => (string) get_option('stylesheet'), 'template' => (string) get_option('template')),
                    'after' => array('stylesheet' => $next, 'template' => (string) ($themes[$next]->get_template() ?: $next)), 'applied' => false);
                break;
            case 'update_setting':
                $option = (string) ($params['option'] ?? '');
                $before = get_option($option, null);
                if (!in_array($option, array('blogname', 'blogdescription'), true) || !is_string($before)
                    || $before !== (string) ($params['expectedCurrentValue'] ?? "\0")) { $complete = false; $operations[] = array(); break; }
                $operations[] = array('operation' => 'update_setting', 'target' => $option,
                    'before' => $before, 'after' => (string) ($params['value'] ?? ''), 'applied' => false);
                break;
            case 'replace_post_link':
                $post_id = isset($params['postId']) ? absint($params['postId']) : 0;
                $post = $post_id > 0 ? get_post($post_id) : null;
                if (!$post || $post->post_status !== 'publish' || strlen((string) $post->post_content) > 200000
                    || !awd_post_matches_repair_page($post, (string) ($params['pageUrl'] ?? ''))
                    || awd_count_post_link((string) $post->post_content, (string) ($params['pageUrl'] ?? ''), (string) ($params['linkUrl'] ?? '')) !== 1) {
                    $complete = false; $operations[] = array(); break;
                }
                $content = (string) $post->post_content;
                $updated_content = awd_replace_exact_post_link($content, (string) ($params['pageUrl'] ?? ''), (string) ($params['linkUrl'] ?? ''), (string) ($params['replacementUrl'] ?? ''));
                if (is_wp_error($updated_content)) { $complete = false; $operations[] = array(); break; }
                $operations[] = array('operation' => 'replace_post_link', 'target' => $post_id,
                    'before' => $content, 'before_sha256' => hash('sha256', $content), 'after' => $updated_content,
                    'after_sha256' => hash('sha256', $updated_content), 'applied_sha256' => null, 'applied' => false);
                break;
            case 'add_scoped_css_rule':
                $selector = (string) ($params['selector'] ?? '');
                $stylesheet = (string) get_option('stylesheet', '');
                if (!function_exists('wp_get_environment_type') || wp_get_environment_type() !== 'staging'
                    || !awd_css_selector_is_allowed($selector) || $stylesheet === ''
                    || !function_exists('wp_get_custom_css') || !function_exists('wp_update_custom_css_post')) {
                    $complete = false; $operations[] = array(); break;
                }
                $before = wp_get_custom_css($stylesheet);
                $after = is_string($before) ? awd_append_scoped_css_rule($before, $selector) : null;
                if (!is_string($before) || strlen($before) > 200000 || !is_string($after) || strlen($after) > 200000) {
                    $complete = false; $operations[] = array(); break;
                }
                $operations[] = array('operation' => 'add_scoped_css_rule', 'target' => $stylesheet, 'selector' => $selector,
                    'before' => $before, 'before_sha256' => hash('sha256', $before), 'after' => $after,
                    'after_sha256' => hash('sha256', $after), 'applied' => false);
                break;
            default:
                $complete = false;
                $operations[] = array();
        }
    }
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points)) {
        $points = array();
    }
    $points[] = array(
        'id' => $id,
        'created_at' => gmdate('c'),
        'description' => sanitize_text_field($description),
        'complete' => $complete,
        'operations' => $operations,
    );
    $points = array_slice($points, -AWD_MAX_RECOVERY_POINTS);
    update_option(AWD_RECOVERY_OPTION, $points, false);
    return $id;
}

function awd_recovery_point_exists(string $backup_id): bool
{
    $points = get_option(AWD_RECOVERY_OPTION, array());
    foreach ($points as $point) {
        if (is_array($point) && isset($point['id']) && is_string($point['id']) && hash_equals($point['id'], $backup_id)) {
            return ($point['complete'] ?? false) === true && isset($point['operations']) && is_array($point['operations']);
        }
    }
    return false;
}

function awd_import_recovery_point(array $point, string $backup_id)
{
    $operation = $point['operations'][0] ?? null;
    if (!isset($point['id'], $point['complete'], $point['operations'])
        || !is_string($point['id']) || !hash_equals($backup_id, $point['id'])
        || $point['complete'] !== true || !is_array($point['operations'])
        || count($point['operations']) !== 1 || !is_array($operation)
        || !in_array($operation['operation'] ?? '', array('disable_plugin', 'switch_theme', 'update_setting', 'replace_post_link', 'add_scoped_css_rule'), true)
        || !array_key_exists('target', $operation) || !array_key_exists('before', $operation)
        || !array_key_exists('after', $operation)) {
        return new WP_Error('awd_drive_backup_invalid', 'The downloaded recovery point is incomplete or does not match this backup.');
    }
    if ($operation['operation'] === 'add_scoped_css_rule'
        && (!isset($operation['selector']) || !is_string($operation['selector']) || !awd_css_selector_is_allowed($operation['selector'])
            || !is_string($operation['before']) || !is_string($operation['after'])
            || strlen($operation['before']) > 200000 || strlen($operation['after']) > 200000
            || !hash_equals((string) ($operation['before_sha256'] ?? ''), hash('sha256', $operation['before']))
            || !hash_equals((string) ($operation['after_sha256'] ?? ''), hash('sha256', $operation['after'])))) {
        return new WP_Error('awd_drive_backup_invalid', 'The downloaded CSS recovery point failed its integrity check.');
    }
    $serialized = wp_json_encode($point);
    if (!is_string($serialized) || strlen($serialized) > 512000) {
        return new WP_Error('awd_drive_backup_oversized', 'The downloaded recovery point exceeds the allowed size.');
    }
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points)) $points = array();
    $points = array_values(array_filter($points, static function ($existing) use ($backup_id): bool {
        return !is_array($existing) || !isset($existing['id']) || !is_string($existing['id']) || !hash_equals($backup_id, $existing['id']);
    }));
    $point['drive_backup_id'] = $backup_id;
    $points[] = $point;
    update_option(AWD_RECOVERY_OPTION, array_slice($points, -AWD_MAX_RECOVERY_POINTS), false);
    return true;
}

function awd_find_recovery_point(string $backup_id): ?array
{
    foreach ((array) get_option(AWD_RECOVERY_OPTION, array()) as $point) {
        if (is_array($point) && isset($point['id']) && is_string($point['id'])
            && hash_equals($point['id'], $backup_id)
            && ($point['complete'] ?? false) === true
            && isset($point['operations']) && is_array($point['operations'])) {
            return $point;
        }
    }
    return null;
}

function awd_mark_recovery_point_cloud_synced(string $backup_id, string $cloud_backup_id): void
{
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points)) return;
    foreach ($points as &$point) {
        if (!is_array($point) || !isset($point['id']) || !is_string($point['id'])
            || !hash_equals($point['id'], $backup_id)) continue;
        $point['drive_backup_id'] = sanitize_text_field($cloud_backup_id);
        $point['drive_synced_at'] = gmdate('c');
        update_option(AWD_RECOVERY_OPTION, $points, false);
        return;
    }
}

function awd_apply_steps(array $steps, string $backup_id = '')
{
    if (count($steps) !== 1) {
        return new WP_Error('awd_invalid_steps', 'An approved repair must contain exactly one reversible operation.');
    }
    foreach ($steps as $index => $step) {
        if (!is_array($step) || !awd_step_is_allowed($step)) {
            return new WP_Error('awd_operation_not_allowed', 'Repair contains an unsupported operation or parameters.');
        }
        $snapshot = awd_find_recovery_operation($backup_id, (int) $index);
        if (!$snapshot) return new WP_Error('awd_operation_not_recoverable', 'The exact target and previous value were not saved; no change was made.');
        $params = $step['parameters'];
        switch ($step['operation']) {
            case 'disable_plugin':
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
                $plugin = $params['plugin'];
                if ($plugin === plugin_basename(__FILE__) || !array_key_exists($plugin, get_plugins())) {
                    return new WP_Error('awd_plugin_not_allowed', 'The requested plugin cannot be disabled by this operation.');
                }
                if (is_multisite() && is_plugin_active_for_network($plugin)) {
                    return new WP_Error('awd_network_plugin_not_supported', 'Network-activated plugins cannot be disabled by this site-level repair.');
                }
                if (($snapshot['operation'] ?? '') !== 'disable_plugin' || ($snapshot['target'] ?? '') !== $plugin
                    || ($snapshot['before'] ?? null) !== is_plugin_active($plugin)) {
                    return new WP_Error('awd_plugin_changed', 'The target plugin state changed after its undo record was saved; no change was made.');
                }
                deactivate_plugins($plugin, false, false);
                if (is_plugin_active($plugin)) {
                    return new WP_Error('awd_plugin_disable_failed', 'Plugin remained active after the requested change.');
                }
                awd_mark_recovery_operation_applied($backup_id, (int) $index, false);
                break;
            case 'update_setting':
                if (($snapshot['operation'] ?? '') !== 'update_setting' || ($snapshot['target'] ?? '') !== $params['option']
                    || ($snapshot['before'] ?? null) !== $params['expectedCurrentValue']
                    || ($snapshot['after'] ?? null) !== $params['value']
                    || (string) get_option($params['option']) !== $params['expectedCurrentValue']) {
                    return new WP_Error('awd_setting_changed', 'The setting no longer has the expected current value; no update was applied.');
                }
                update_option($params['option'], $params['value']);
                if ((string) get_option($params['option']) !== $params['value']) {
                    return new WP_Error('awd_setting_update_failed', 'The requested setting did not match after update.');
                }
                awd_mark_recovery_operation_applied($backup_id, (int) $index, $params['value']);
                break;
            case 'switch_theme':
                $themes = wp_get_themes();
                $stylesheet = $params['stylesheet'];
                if (!isset($themes[$stylesheet]) || !$themes[$stylesheet]->exists()) {
                    return new WP_Error('awd_theme_not_found', 'The requested theme is not installed and valid.');
                }
                $current_theme = array('stylesheet' => (string) get_option('stylesheet'), 'template' => (string) get_option('template'));
                if (($snapshot['operation'] ?? '') !== 'switch_theme' || ($snapshot['target'] ?? '') !== $stylesheet
                    || ($snapshot['before'] ?? null) !== $current_theme) {
                    return new WP_Error('awd_theme_changed', 'The active theme changed after its undo record was saved; no change was made.');
                }
                switch_theme($stylesheet);
                $saved_theme = array('stylesheet' => (string) get_option('stylesheet'), 'template' => (string) get_option('template'));
                if ($saved_theme !== ($snapshot['after'] ?? null)) {
                    return new WP_Error('awd_theme_switch_failed', 'The requested theme did not become active.');
                }
                awd_mark_recovery_operation_applied($backup_id, (int) $index, $saved_theme);
                break;
            case 'replace_post_link':
                $post_id = absint($params['postId']);
                $post = get_post($post_id);
                if (($snapshot['operation'] ?? '') !== 'replace_post_link' || (int) ($snapshot['target'] ?? 0) !== $post_id || !$post || $post->post_status !== 'publish') {
                    return new WP_Error('awd_post_not_recoverable', 'The published post is missing or its exact content was not saved for undo; no link was changed.');
                }
                if (!hash_equals((string) $snapshot['before_sha256'], hash('sha256', (string) $post->post_content))) {
                    return new WP_Error('awd_post_changed', 'The post changed after its recovery point was saved; no link was changed.');
                }
                if (!awd_post_matches_repair_page($post, $params['pageUrl'])) {
                    return new WP_Error('awd_post_page_mismatch', 'The post ID no longer maps to the scanned source page; no link was changed.');
                }
                $updated_content = awd_replace_exact_post_link((string) $post->post_content, $params['pageUrl'], $params['linkUrl'], $params['replacementUrl']);
                if (is_wp_error($updated_content)) return $updated_content;
                if (!is_string($snapshot['after'] ?? null) || !hash_equals((string) $snapshot['after_sha256'], hash('sha256', $updated_content))
                    || !hash_equals((string) $snapshot['after_sha256'], hash('sha256', (string) $snapshot['after']))) {
                    return new WP_Error('awd_post_expected_change_mismatch', 'The exact prepared post change no longer matches its undo record; no content was changed.');
                }
                $updated = wp_update_post(array('ID' => $post_id, 'post_content' => $updated_content), true);
                if (is_wp_error($updated) || (int) $updated !== $post_id) {
                    return is_wp_error($updated) ? $updated : new WP_Error('awd_post_update_failed', 'WordPress did not save the updated post link.');
                }
                $saved_post = get_post($post_id);
                if ($saved_post) awd_mark_recovery_operation_applied($backup_id, (int) $index, (string) $saved_post->post_content);
                if (!$saved_post || !hash_equals((string) $snapshot['after_sha256'], hash('sha256', (string) $saved_post->post_content))
                    || awd_count_post_link((string) $saved_post->post_content, $params['pageUrl'], $params['linkUrl']) !== 0
                    || awd_count_post_link((string) $saved_post->post_content, $params['pageUrl'], $params['replacementUrl']) < 1) {
                    return new WP_Error('awd_post_update_unverified', 'The saved post did not contain the expected replacement link.');
                }
                break;
            case 'add_scoped_css_rule':
                $stylesheet = (string) ($params['selector'] ?? '') === '' ? '' : (string) ($snapshot['target'] ?? '');
                $expected_css = $snapshot['after'] ?? null;
                $current_css = $stylesheet !== '' && function_exists('wp_get_custom_css') ? wp_get_custom_css($stylesheet) : null;
                if (!function_exists('wp_get_environment_type') || wp_get_environment_type() !== 'staging'
                    || !awd_css_selector_is_allowed((string) ($params['selector'] ?? ''))
                    || ($snapshot['operation'] ?? '') !== 'add_scoped_css_rule'
                    || ($snapshot['selector'] ?? '') !== ($params['selector'] ?? '')
                    || $stylesheet !== (string) get_option('stylesheet', '')
                    || !is_string($snapshot['before'] ?? null) || !is_string($expected_css)
                    || !hash_equals((string) ($snapshot['before_sha256'] ?? ''), hash('sha256', (string) $snapshot['before']))
                    || !hash_equals((string) ($snapshot['after_sha256'] ?? ''), hash('sha256', $expected_css))
                    || $expected_css !== awd_append_scoped_css_rule((string) $snapshot['before'], (string) $params['selector'])
                    || !is_string($current_css) || !hash_equals((string) $snapshot['before_sha256'], hash('sha256', $current_css))) {
                    return new WP_Error('awd_css_changed', 'The staging CSS or active theme changed after its recovery record was saved; no CSS was changed.');
                }
                $updated_css = wp_update_custom_css_post($expected_css, array('stylesheet' => $stylesheet));
                if (is_wp_error($updated_css)) return $updated_css;
                if (!is_object($updated_css) || !is_string(wp_get_custom_css($stylesheet))
                    || !hash_equals((string) $snapshot['after_sha256'], hash('sha256', wp_get_custom_css($stylesheet)))) {
                    return new WP_Error('awd_css_update_failed', 'The scoped staging CSS rule could not be confirmed.');
                }
                awd_mark_recovery_operation_applied($backup_id, (int) $index, $expected_css);
                break;
            default:
                return new WP_Error('awd_operation_not_allowed', 'Unsupported repair operation.');
        }
    }
    return true;
}

function awd_step_is_allowed(array $step): bool
{
    if (array_diff(array_keys($step), array('description', 'operation', 'parameters')) !== array()
        || !isset($step['description'], $step['operation'], $step['parameters'])
        || !is_string($step['description']) || $step['description'] === '' || strlen($step['description']) > 500
        || !is_string($step['operation']) || !is_array($step['parameters'])) {
        return false;
    }
    $params = $step['parameters'];
    $max_parameter_length = $step['operation'] === 'replace_post_link' ? 2000 : 500;
    foreach ($params as $value) {
        if (!is_string($value) || strlen($value) > $max_parameter_length) {
            return false;
        }
    }
    if ($step['operation'] === 'disable_plugin') {
        return count($params) === 1 && isset($params['plugin'])
            && preg_match('/^(?!\/)(?!.*(?:^|\/)\.\.?\/)[a-z0-9._\/-]+\.php$/i', $params['plugin']);
    }
    if ($step['operation'] === 'update_setting') {
        return count($params) === 3 && isset($params['option'], $params['expectedCurrentValue'], $params['value'])
            && in_array($params['option'], array('blogname', 'blogdescription'), true);
    }
    if ($step['operation'] === 'switch_theme') {
        return count($params) === 1 && isset($params['stylesheet'])
            && preg_match('/^[a-z0-9_-]+$/i', $params['stylesheet']);
    }
    if ($step['operation'] === 'replace_post_link') {
        if (count($params) !== 4 || !isset($params['postId'], $params['pageUrl'], $params['linkUrl'], $params['replacementUrl'])
            || !preg_match('/^[1-9][0-9]{0,9}$/', $params['postId'])) return false;
        $page = awd_normalize_repair_url($params['pageUrl']);
        $link = awd_normalize_repair_url($params['linkUrl']);
        $replacement = awd_normalize_repair_url($params['replacementUrl']);
        return $page !== null && $link !== null && $replacement !== null
            && awd_repair_url_origin($page) === awd_repair_url_origin($link)
            && awd_repair_url_origin($page) === awd_repair_url_origin($replacement);
    }
    if ($step['operation'] === 'add_scoped_css_rule') {
        return count($params) === 1 && isset($params['selector']) && awd_css_selector_is_allowed($params['selector']);
    }
    return false;
}

function awd_css_selector_is_allowed(string $selector): bool
{
    return strlen($selector) <= 200
        && (bool) preg_match('/^body\.(?:page-id|postid)-[1-9][0-9]{0,9}\s+(?:#[A-Za-z_][A-Za-z0-9_-]*|\.[A-Za-z_][A-Za-z0-9_-]*)$/', $selector);
}

function awd_append_scoped_css_rule(string $css, string $selector): ?string
{
    if (!awd_css_selector_is_allowed($selector) || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $css)) return null;
    $rule = "\n/* AI Website Doctor approved staging width repair */\n" . $selector . " { max-width: 100%; }\n";
    if (str_contains($css, $rule)) return null;
    return $css . $rule;
}

function awd_normalize_repair_url(string $url): ?string
{
    $parts = wp_parse_url($url);
    if (!is_array($parts) || !in_array(strtolower((string) ($parts['scheme'] ?? '')), array('http', 'https'), true)
        || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) return null;
    $scheme = strtolower((string) $parts['scheme']);
    $host = strtolower((string) $parts['host']);
    $port = isset($parts['port']) && !(($scheme === 'https' && (int) $parts['port'] === 443) || ($scheme === 'http' && (int) $parts['port'] === 80))
        ? ':' . (int) $parts['port'] : '';
    $path = (string) ($parts['path'] ?? '/');
    if ($path === '') $path = '/';
    if ($path !== '/') $path = untrailingslashit($path);
    return $scheme . '://' . $host . $port . $path . (isset($parts['query']) ? '?' . $parts['query'] : '');
}

function awd_repair_url_origin(string $url): string
{
    $parts = wp_parse_url($url);
    return strtolower((string) ($parts['scheme'] ?? '')) . '://' . strtolower((string) ($parts['host'] ?? '')) . (isset($parts['port']) ? ':' . (int) $parts['port'] : '');
}

function awd_post_matches_repair_page($post, string $page_url): bool
{
    if (!is_object($post) || $post->post_status !== 'publish' || !in_array($post->post_type, array('post', 'page'), true)
        || url_to_postid($page_url) !== (int) $post->ID) return false;
    $type = get_post_type_object($post->post_type);
    if (!$type || empty($type->public) || !$type->show_in_rest || !post_type_supports($post->post_type, 'editor')) return false;
    $permalink = get_permalink($post);
    return is_string($permalink) && awd_normalize_repair_url($permalink) === awd_normalize_repair_url($page_url);
}

function awd_count_post_link(string $content, string $page_url, string $target_url): int
{
    if (!class_exists('WP_HTML_Tag_Processor')) return -1;
    $processor = new WP_HTML_Tag_Processor($content);
    $count = 0;
    while ($processor->next_tag('A')) {
        $href = $processor->get_attribute('href');
        if (!is_string($href) || $href === '') continue;
        $absolute = WP_Http::make_absolute_url($href, $page_url);
        if (is_string($absolute) && awd_normalize_repair_url($absolute) === awd_normalize_repair_url($target_url)) $count++;
    }
    return $count;
}

function awd_replace_exact_post_link(string $content, string $page_url, string $link_url, string $replacement_url)
{
    if (!class_exists('WP_HTML_Tag_Processor')) return new WP_Error('awd_html_processor_missing', 'This WordPress version cannot safely parse the post links; no content was changed.');
    $processor = new WP_HTML_Tag_Processor($content);
    $matches = 0;
    while ($processor->next_tag('A')) {
        $href = $processor->get_attribute('href');
        if (!is_string($href) || $href === '') continue;
        $absolute = WP_Http::make_absolute_url($href, $page_url);
        if (!is_string($absolute) || awd_normalize_repair_url($absolute) !== awd_normalize_repair_url($link_url)) continue;
        $matches++;
        if ($matches > 1) return new WP_Error('awd_post_link_ambiguous', 'More than one matching link exists in this post; no content was changed.');
        $processor->set_attribute('href', $replacement_url);
    }
    if ($matches !== 1) return new WP_Error('awd_post_link_missing', 'The exact scanned link is not present exactly once in this post; no content was changed.');
    return $processor->get_updated_html();
}

function awd_find_recovery_operation(string $backup_id, int $index): ?array
{
    foreach ((array) get_option(AWD_RECOVERY_OPTION, array()) as $point) {
        if (!is_array($point) || !hash_equals((string) ($point['id'] ?? ''), $backup_id) || ($point['complete'] ?? false) !== true) continue;
        $operation = $point['operations'][$index] ?? null;
        if (is_array($operation) && isset($operation['operation'], $operation['target'], $operation['before']) && array_key_exists('after', $operation)) return $operation;
    }
    return null;
}

function awd_mark_recovery_operation_applied(string $backup_id, int $index, $after): void
{
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points)) return;
    foreach ($points as &$point) {
        if (!is_array($point) || !hash_equals((string) ($point['id'] ?? ''), $backup_id)) continue;
        if (!isset($point['operations'][$index]) || !is_array($point['operations'][$index])) return;
        $point['operations'][$index]['applied'] = true;
        if (($point['operations'][$index]['operation'] ?? '') === 'replace_post_link') {
            $point['operations'][$index]['after'] = $after;
            $point['operations'][$index]['applied_sha256'] = hash('sha256', (string) $after);
        } elseif (($point['operations'][$index]['operation'] ?? '') === 'add_scoped_css_rule') {
            $point['operations'][$index]['applied_after'] = hash('sha256', (string) $after);
        } else {
            $point['operations'][$index]['applied_after'] = $after;
        }
        update_option(AWD_RECOVERY_OPTION, $points, false);
        return;
    }
}

function awd_verify_repair_diagnostics(array $task, array $diagnostics): array
{
    $issues = isset($diagnostics['issues']) && is_array($diagnostics['issues'])
        ? $diagnostics['issues']
        : null;
    if ($issues === null || empty($task['issueFingerprint']) || !is_string($task['issueFingerprint'])) {
        return array('status' => 'inconclusive', 'reason' => 'Comparable post-repair diagnostics are unavailable.');
    }

    if (str_starts_with($task['issueFingerprint'], 'wp:php-fatal:')) {
        $plugin_file = '';
        foreach ((array) ($task['steps'] ?? array()) as $step) {
            if (is_array($step) && ($step['operation'] ?? '') === 'disable_plugin') {
                $plugin_file = (string) ($step['parameters']['plugin'] ?? '');
                break;
            }
        }
        $plugin_active = false;
        foreach ((array) ($diagnostics['plugins'] ?? array()) as $plugin) {
            if (is_array($plugin) && ($plugin['file'] ?? '') === $plugin_file && ($plugin['active'] ?? false) === true) {
                $plugin_active = true;
                break;
            }
        }
        $fatal_id = substr($task['issueFingerprint'], strlen('wp:php-fatal:'));
        foreach ((array) ($diagnostics['fatalErrors'] ?? array()) as $fatal) {
            if (is_array($fatal) && ($fatal['id'] ?? '') === $fatal_id
                && is_string($fatal['observedAt'] ?? null)
                && strtotime($fatal['observedAt']) >= strtotime((string) ($task['executionStartedAt'] ?? 'now'))) {
                return array('status' => 'failed', 'reason' => 'The same PHP fatal error was observed again after the repair began.');
            }
        }
        if ($plugin_file !== '' && !$plugin_active) {
            // This verifies containment, not a permanent fix; the fatal event is historical evidence.
            return awd_verify_no_new_high_severity_findings($task, $issues, 'The implicated plugin is inactive and the same fatal error has not recurred in fresh diagnostics.');
        }
        return array('status' => 'failed', 'reason' => 'The implicated plugin is still active, so the fatal-error containment did not take effect.');
    }

    $original_fingerprint = substr($task['issueFingerprint'], 3);
    foreach ($issues as $issue) {
        if (is_array($issue) && ($issue['fingerprint'] ?? null) === $original_fingerprint) {
            return array('status' => 'failed', 'reason' => 'The original diagnostic finding is still present.');
        }
    }

    return awd_verify_no_new_high_severity_findings($task, $issues, 'The original diagnostic finding is absent and no new high-severity findings were detected.');
}

function awd_verify_no_new_high_severity_findings(array $task, array $issues, string $success_reason): array
{
    $baseline_high = isset($task['baselineHighSeverityIssues']) && is_array($task['baselineHighSeverityIssues'])
        ? array_filter($task['baselineHighSeverityIssues'], 'is_string')
        : array();
    $regressions = array();
    foreach ($issues as $issue) {
        if (!is_array($issue) || !in_array($issue['severity'] ?? '', array('high', 'critical'), true)) {
            continue;
        }
        $fingerprint = $issue['fingerprint'] ?? null;
        if (is_string($fingerprint) && !in_array($fingerprint, $baseline_high, true)) {
            $regressions[] = $fingerprint;
        }
    }
    if ($regressions !== array()) {
        return array(
            'status' => 'failed',
            'reason' => 'Post-repair diagnostics found new high-severity issues: ' . implode(', ', $regressions),
        );
    }
    return array(
        'status' => 'passed',
        'reason' => $success_reason,
    );
}

function awd_rollback_repair(): void
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to restore recovery points.', 'ai-website-doctor'), 403);
    }
    $backup_id = isset($_POST['backup_id']) ? sanitize_text_field(wp_unslash($_POST['backup_id'])) : '';
    check_admin_referer('awd_rollback_' . $backup_id);
    $result = awd_restore_recovery_point($backup_id);
    if (is_wp_error($result)) {
        awd_redirect($result->get_error_message(), 'error');
    }
    awd_redirect('Recovery point restored and verified.');
}

function awd_restore_recovery_point(string $backup_id)
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $points = get_option(AWD_RECOVERY_OPTION, array());
    if (!is_array($points)) {
        return new WP_Error('awd_backup_missing', 'Recovery point was not found.');
    }
    $selected = null;
    foreach ($points as $point) {
        if (is_array($point) && hash_equals((string) ($point['id'] ?? ''), $backup_id)) {
            $selected = $point;
            break;
        }
    }
    if (!$selected || ($selected['complete'] ?? false) !== true || !isset($selected['operations']) || !is_array($selected['operations'])) {
        return new WP_Error('awd_backup_invalid', 'The operation-specific undo record is missing or incomplete.');
    }
    $operations = array_reverse($selected['operations'], true);
    foreach ($operations as $operation) {
        if (!is_array($operation) || !isset($operation['operation'], $operation['target'], $operation['before']) || !array_key_exists('after', $operation)) return new WP_Error('awd_backup_invalid', 'An operation-specific undo entry is invalid; no values were restored.');
        $kind = (string) $operation['operation'];
        $target = $operation['target'];
        $before = $operation['before'];
        $after = $operation['applied_after'] ?? $operation['after'];
        if ($kind === 'disable_plugin') {
            if (!is_string($target) || !isset(get_plugins()[$target]) || !is_bool($before) || !is_bool($after)) return new WP_Error('awd_backup_plugin_missing', 'The saved plugin target is invalid or no longer installed.');
            $current = is_plugin_active($target);
            if ($current !== $before && $current !== $after) return new WP_Error('awd_backup_plugin_changed', 'The plugin changed again after this repair; no values were restored.');
        } elseif ($kind === 'switch_theme') {
            if (!is_string($target) || !is_array($before) || !is_array($after)) return new WP_Error('awd_backup_theme_invalid', 'The saved theme target is invalid.');
            $themes = wp_get_themes();
            if (!isset($themes[(string) ($before['stylesheet'] ?? '')]) || !$themes[(string) ($before['stylesheet'] ?? '')]->exists()) return new WP_Error('awd_backup_theme_missing', 'The previous theme is no longer installed; no values were restored.');
            $current = array('stylesheet' => (string) get_option('stylesheet'), 'template' => (string) get_option('template'));
            if ($current !== $before && $current !== $after) return new WP_Error('awd_backup_theme_changed', 'The active theme changed again after this repair; no values were restored.');
        } elseif ($kind === 'update_setting') {
            if (!in_array($target, array('blogname', 'blogdescription'), true) || !is_string($before) || !is_string($after)) return new WP_Error('awd_backup_setting_invalid', 'The saved setting target is invalid.');
            $current = (string) get_option($target);
            if ($current !== $before && $current !== $after) return new WP_Error('awd_backup_setting_changed', 'The setting changed again after this repair; no values were restored.');
        } elseif ($kind === 'replace_post_link') {
            $post_id = absint($target);
            $post = $post_id > 0 ? get_post($post_id) : null;
            if (!$post || !is_string($before) || !hash_equals((string) ($operation['before_sha256'] ?? ''), hash('sha256', $before))) return new WP_Error('awd_backup_post_invalid', 'The saved post target or original content is invalid; no values were restored.');
            $current_hash = hash('sha256', (string) $post->post_content);
            $expected_after = is_string($operation['applied_sha256'] ?? null) ? $operation['applied_sha256'] : (string) ($operation['after_sha256'] ?? '');
            if (!hash_equals((string) $operation['before_sha256'], $current_hash) && ($expected_after === '' || !hash_equals($expected_after, $current_hash))) return new WP_Error('awd_backup_post_changed', 'The post changed again after this repair; no values were restored.');
        } elseif ($kind === 'add_scoped_css_rule') {
            if (!is_string($target) || !preg_match('/^[a-z0-9_-]{1,100}$/i', $target)
                || !isset($operation['selector']) || !is_string($operation['selector']) || !awd_css_selector_is_allowed($operation['selector'])
                || !is_string($before) || !is_string($operation['after'])
                || strlen($before) > 200000 || strlen($operation['after']) > 200000
                || !hash_equals((string) ($operation['before_sha256'] ?? ''), hash('sha256', $before))
                || !hash_equals((string) ($operation['after_sha256'] ?? ''), hash('sha256', $operation['after']))
                || !function_exists('wp_get_custom_css')) return new WP_Error('awd_backup_css_invalid', 'The saved staging CSS recovery data is invalid.');
            $current_css = wp_get_custom_css($target);
            $current_hash = hash('sha256', (string) $current_css);
            $expected_after = is_string($operation['applied_after'] ?? null) ? $operation['applied_after'] : (string) ($operation['after_sha256'] ?? '');
            if (!hash_equals((string) $operation['before_sha256'], $current_hash) && !hash_equals($expected_after, $current_hash)) return new WP_Error('awd_backup_css_changed', 'The custom CSS changed again after this repair; no CSS was restored.');
        } else {
            return new WP_Error('awd_backup_operation_unknown', 'The recovery record contains an unsupported operation; no values were restored.');
        }
    }
    foreach ($operations as $operation) {
        if (!is_array($operation) || !isset($operation['operation'], $operation['target'], $operation['before']) || !array_key_exists('after', $operation)) {
            return new WP_Error('awd_backup_invalid', 'An operation-specific undo entry is invalid; no values were restored.');
        }
        $kind = (string) $operation['operation'];
        $target = $operation['target'];
        $before = $operation['before'];
        $after = $operation['after'];
        if ($kind === 'disable_plugin') {
            $plugins = get_plugins();
            if (!is_string($target) || !isset($plugins[$target]) || !is_bool($before) || !is_bool($after)) return new WP_Error('awd_backup_plugin_missing', 'The saved plugin target is invalid or no longer installed.');
            $current = is_plugin_active($target);
            if ($current === $before) continue;
            if ($current !== ($operation['applied_after'] ?? $after)) return new WP_Error('awd_backup_plugin_changed', 'The plugin changed again after this repair; undo stopped to preserve newer state.');
            if ($before) activate_plugin($target, '', false, true);
            else deactivate_plugins($target, false, false);
            if (is_plugin_active($target) !== $before) return new WP_Error('awd_backup_plugin_restore_failed', 'The saved plugin activation state could not be restored.');
        } elseif ($kind === 'switch_theme') {
            if (!is_string($target) || !is_array($before) || !is_array($after)) return new WP_Error('awd_backup_theme_invalid', 'The saved theme target is invalid.');
            $themes = wp_get_themes();
            $old_stylesheet = (string) ($before['stylesheet'] ?? '');
            if (!isset($themes[$old_stylesheet]) || !$themes[$old_stylesheet]->exists()) return new WP_Error('awd_backup_theme_missing', 'The previous theme is no longer installed.');
            $current = array('stylesheet' => (string) get_option('stylesheet'), 'template' => (string) get_option('template'));
            if ($current === $before) continue;
            if ($current !== ($operation['applied_after'] ?? $after)) return new WP_Error('awd_backup_theme_changed', 'The active theme changed again after this repair; undo stopped to preserve newer state.');
            switch_theme($old_stylesheet, (string) ($before['template'] ?? $old_stylesheet));
            if ((string) get_option('stylesheet') !== $old_stylesheet || (string) get_option('template') !== (string) ($before['template'] ?? '')) return new WP_Error('awd_backup_theme_restore_failed', 'The previous theme state could not be restored.');
        } elseif ($kind === 'update_setting') {
            if (!in_array($target, array('blogname', 'blogdescription'), true) || !is_string($before) || !is_string($after)) return new WP_Error('awd_backup_setting_invalid', 'The saved setting target is invalid.');
            $current = (string) get_option($target);
            if ($current === $before) continue;
            if ($current !== (string) ($operation['applied_after'] ?? $after)) return new WP_Error('awd_backup_setting_changed', 'The setting changed again after this repair; undo stopped to preserve the newer value.');
            update_option($target, $before);
            if ((string) get_option($target) !== $before) return new WP_Error('awd_backup_setting_restore_failed', 'The previous setting value could not be restored.');
        } elseif ($kind === 'replace_post_link') {
            $post_id = absint($target);
            $post = $post_id > 0 ? get_post($post_id) : null;
            if (!$post || !is_string($before) || !hash_equals((string) ($operation['before_sha256'] ?? ''), hash('sha256', $before))) return new WP_Error('awd_backup_post_invalid', 'The saved post target or original content is invalid.');
            $current_hash = hash('sha256', (string) $post->post_content);
            if (hash_equals((string) $operation['before_sha256'], $current_hash)) continue;
            $expected_after = is_string($operation['applied_sha256'] ?? null) ? $operation['applied_sha256'] : (string) ($operation['after_sha256'] ?? '');
            if ($expected_after === '' || !hash_equals($expected_after, $current_hash)) return new WP_Error('awd_backup_post_changed', 'The post changed again after this repair; undo stopped to preserve the newer edit.');
            $restored = wp_update_post(array('ID' => $post_id, 'post_content' => $before), true);
            if (is_wp_error($restored) || (int) $restored !== $post_id) return is_wp_error($restored) ? $restored : new WP_Error('awd_backup_post_restore_failed', 'WordPress did not restore the original post content.');
            $restored_post = get_post($post_id);
            if (!$restored_post || !hash_equals((string) $operation['before_sha256'], hash('sha256', (string) $restored_post->post_content))) return new WP_Error('awd_backup_post_restore_unverified', 'Restored post content did not match its exact saved value.');
        } elseif ($kind === 'add_scoped_css_rule') {
            if (!is_string($target) || !is_string($before) || !is_string($after)
                || !isset($operation['selector']) || !is_string($operation['selector']) || !awd_css_selector_is_allowed($operation['selector'])
                || !function_exists('wp_get_custom_css') || !function_exists('wp_update_custom_css_post')) return new WP_Error('awd_backup_css_invalid', 'The saved staging CSS recovery data is invalid.');
            $current_css = wp_get_custom_css($target);
            $current_hash = hash('sha256', (string) $current_css);
            if (hash_equals((string) $operation['before_sha256'], $current_hash)) continue;
            $expected_after = is_string($operation['applied_after'] ?? null) ? $operation['applied_after'] : (string) $operation['after_sha256'];
            if (!hash_equals($expected_after, $current_hash)) return new WP_Error('awd_backup_css_changed', 'The custom CSS changed again after this repair; undo stopped to preserve newer styling.');
            $restored_css = wp_update_custom_css_post($before, array('stylesheet' => $target));
            if (is_wp_error($restored_css)) return $restored_css;
            if (!is_object($restored_css) || !hash_equals((string) $operation['before_sha256'], hash('sha256', (string) wp_get_custom_css($target)))) return new WP_Error('awd_backup_css_restore_failed', 'The previous custom CSS could not be restored exactly.');
        } else {
            return new WP_Error('awd_backup_operation_unknown', 'The recovery record contains an unsupported operation.');
        }
    }
    return true;
}

function awd_report_local_rollback(array $settings, string $repair_id, string $backup_id, $rollback)
{
    $after_settings = $settings;
    $after_settings['collect_logs'] = false;
    $report = awd_authenticated_request($settings, '/executions', 'POST', array(
        'repairId' => $repair_id,
        'status' => is_wp_error($rollback) ? 'rollback_failed' : 'rolled_back',
        'result' => array(
            'message' => is_wp_error($rollback) ? $rollback->get_error_message() : 'The operation-specific undo record was restored.',
            'startedAt' => gmdate('c'),
            'backupId' => $backup_id,
            'backupStatus' => 'created',
            'executionStatus' => is_wp_error($rollback) ? 'failed' : 'completed',
            'verificationStatus' => is_wp_error($rollback) ? 'failed' : 'passed',
            'verificationReason' => is_wp_error($rollback) ? $rollback->get_error_message() : 'The saved operation target and previous value were restored.',
            'verified' => !is_wp_error($rollback),
            'rollbackApplied' => !is_wp_error($rollback),
            'localStateRestoreApplied' => !is_wp_error($rollback),
            'afterEvidence' => awd_collect_diagnostics($after_settings),
        ),
    ));
    if (is_wp_error($report)) return $report;
    $body = json_decode(wp_remote_retrieve_body($report), true);
    if (!is_array($body) || empty($body['ok']) || !in_array(($body['status'] ?? ''), array('rolled_back', 'rollback_required'), true)) {
        return new WP_Error('awd_central_rollback_unverified', 'Central execution history did not confirm the local undo.');
    }
    return true;
}
