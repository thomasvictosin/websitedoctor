<?php
/**
 * Controlled plugin/theme conflict probe. Run only inside a disposable WP staging clone:
 * AIWD_DISPOSABLE_STAGING=true wp eval-file bin/staging-conflict-check.php
 */

if (!defined('WP_CLI') || !WP_CLI) {
    fwrite(STDERR, "This diagnostic requires WP-CLI.\n");
    exit(2);
}
if (!function_exists('wp_get_environment_type') || wp_get_environment_type() !== 'staging'
    || getenv('AIWD_DISPOSABLE_STAGING') !== 'true'
    || !defined('AIWD_DISPOSABLE_STAGING') || AIWD_DISPOSABLE_STAGING !== true) {
    fwrite(STDERR, "Refusing conflict tests: this WordPress install is not explicitly marked as disposable staging.\n");
    exit(2);
}

require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/theme.php';

$active_plugins = array_values((array) get_option('active_plugins', array()));
$stylesheet = get_stylesheet();
$results = array();
$baseline = awd_staging_probe();
$components = array_slice($active_plugins, 0, 15);
$alternate_themes = array();
foreach (wp_get_themes() as $theme_slug => $_theme_object) {
    if ((string) $theme_slug !== $stylesheet) $alternate_themes[(string) $theme_slug] = true;
    if (count($alternate_themes) >= 5) break;
}

try {
    foreach ($components as $plugin) {
        deactivate_plugins($plugin, true, false);
        $probe = awd_staging_probe();
        activate_plugin($plugin, '', false, true);
        $results[] = array(
            'components' => array($plugin),
            'result' => awd_staging_interpret($baseline, $probe),
            'evidence' => awd_staging_evidence($baseline, $probe),
            'baselineFindings' => awd_staging_finding_summary($baseline),
            'probeFindings' => awd_staging_finding_summary($probe),
        );
    }
    foreach (array_keys($alternate_themes) as $theme_slug) {
        switch_theme($theme_slug);
        $theme_baseline = awd_staging_probe();
        $results[] = array(
            'components' => array('theme:' . $stylesheet, 'theme:' . $theme_slug),
            'result' => awd_staging_interpret($baseline, $theme_baseline),
            'evidence' => awd_staging_evidence($baseline, $theme_baseline),
            'baselineFindings' => awd_staging_finding_summary($baseline),
            'probeFindings' => awd_staging_finding_summary($theme_baseline),
        );
        foreach (array_slice($active_plugins, 0, 2) as $plugin) {
            deactivate_plugins($plugin, true, false);
            $combination_probe = awd_staging_probe();
            activate_plugin($plugin, '', false, true);
            $results[] = array(
                'components' => array((string) $plugin, 'theme:' . $theme_slug),
                'result' => awd_staging_interpret($theme_baseline, $combination_probe),
                'evidence' => awd_staging_evidence($theme_baseline, $combination_probe),
                'baselineFindings' => awd_staging_finding_summary($theme_baseline),
                'probeFindings' => awd_staging_finding_summary($combination_probe),
            );
        }
        switch_theme($stylesheet);
    }
} finally {
    foreach (array_values((array) get_option('active_plugins', array())) as $plugin) {
        if (!in_array($plugin, $active_plugins, true)) deactivate_plugins($plugin, true, false);
    }
    foreach ($active_plugins as $plugin) {
        if (!is_plugin_active($plugin)) activate_plugin($plugin, '', false, true);
    }
    if (get_stylesheet() !== $stylesheet) switch_theme($stylesheet);
}

$report = array(
    'status' => 'completed',
    'activePlugins' => $active_plugins,
    'activeTheme' => $stylesheet,
    'findings' => $results,
);
if (function_exists('awd_record_staging_conflict_report') && !awd_record_staging_conflict_report($report)) {
    fwrite(STDERR, "Tests ran but the plugin refused to store a staging report; check staging markers and administrator context.\n");
    exit(3);
}
WP_CLI::line(wp_json_encode($report, JSON_PRETTY_PRINT));

function awd_staging_probe(): array
{
    $script = getenv('AIWD_BROWSER_PROBE_SCRIPT');
    $node = getenv('AIWD_NODE_BINARY') ?: 'node';
    $real_script = is_string($script) ? realpath($script) : false;
    if ($real_script === false || basename($real_script) !== 'staging-browser-probe.mjs' || !is_readable($real_script)) {
        return array('status' => 'unavailable', 'error' => 'Configure AIWD_BROWSER_PROBE_SCRIPT to the trusted staging-browser-probe.mjs runner.');
    }
    if (!function_exists('proc_open')) return array('status' => 'unavailable', 'error' => 'PHP proc_open is unavailable for the staging browser runner.');
    $command = array($node, '--experimental-strip-types', $real_script, home_url('/'));
    $stdout = tmpfile();
    $stderr = tmpfile();
    if ($stdout === false || $stderr === false) return array('status' => 'unavailable', 'error' => 'Could not allocate browser probe output.');
    $process = proc_open($command, array(0 => array('pipe', 'r'), 1 => $stdout, 2 => $stderr), $pipes, dirname($real_script));
    if (!is_resource($process)) return array('status' => 'unavailable', 'error' => 'Could not start the Playwright browser probe.');
    fclose($pipes[0]);
    $deadline = time() + 150;
    do {
        $state = proc_get_status($process);
        if (!$state['running']) break;
        usleep(100000);
    } while (time() < $deadline);
    if (!empty($state['running'])) {
        proc_terminate($process, 9);
        proc_close($process);
        return array('status' => 'unavailable', 'error' => 'Playwright browser probe exceeded its 150-second limit.');
    }
    $reported_exit_code = is_array($state) ? (int) ($state['exitcode'] ?? -1) : -1;
    $closed_exit_code = proc_close($process);
    $exit_code = $reported_exit_code >= 0 ? $reported_exit_code : $closed_exit_code;
    rewind($stdout);
    $output = stream_get_contents($stdout, 500000);
    fclose($stdout);
    fclose($stderr);
    $result = json_decode((string) $output, true);
    if ($exit_code !== 0 || !is_array($result)) return array('status' => 'unavailable', 'error' => 'Playwright browser probe failed or returned invalid evidence.');
    return $result;
}

function awd_staging_interpret(array $baseline, array $probe): string
{
    if (!in_array($baseline['status'] ?? '', array('passed', 'issues_found', 'partial'), true)
        || !in_array($probe['status'] ?? '', array('passed', 'issues_found', 'partial'), true)) return 'inconclusive';
    $baseline_findings = array_fill_keys(array_map(static fn($finding) => (string) ($finding['fingerprint'] ?? ''), (array) ($baseline['findings'] ?? array())), true);
    $probe_findings = array_fill_keys(array_map(static fn($finding) => (string) ($finding['fingerprint'] ?? ''), (array) ($probe['findings'] ?? array())), true);
    if (array_diff_key($baseline_findings, $probe_findings)) return 'conflict';
    if (($baseline['status'] ?? '') === 'partial' || ($probe['status'] ?? '') === 'partial'
        || !empty($baseline['crawlIncomplete']) || !empty($probe['crawlIncomplete'])) return 'inconclusive';
    return 'no_conflict';
}

function awd_staging_evidence(array $baseline, array $probe): string
{
    $baseline_ids = array_slice(array_map(static fn($finding) => (string) ($finding['fingerprint'] ?? ''), (array) ($baseline['findings'] ?? array())), 0, 30);
    $probe_ids = array_slice(array_map(static fn($finding) => (string) ($finding['fingerprint'] ?? ''), (array) ($probe['findings'] ?? array())), 0, 30);
    return substr(sanitize_text_field(sprintf(
        'Disposable staging browser scan: baseline=%s (%d findings, %d pages); probe=%s (%d findings, %d pages); baseline findings=%s; probe findings=%s%s.',
        (string) ($baseline['status'] ?? 'unavailable'), count((array) ($baseline['findings'] ?? array())), count((array) ($baseline['pages'] ?? array())),
        (string) ($probe['status'] ?? 'unavailable'), count((array) ($probe['findings'] ?? array())), count((array) ($probe['pages'] ?? array())),
        implode(',', $baseline_ids), implode(',', $probe_ids),
        isset($probe['errors'][0]) ? ' error=' . (string) $probe['errors'][0] : ''
    )), 0, 1000);
}

function awd_staging_finding_summary(array $scan): array
{
    $findings = array();
    foreach ((array) ($scan['findings'] ?? array()) as $finding) {
        if (!is_array($finding) || !isset($finding['fingerprint'], $finding['severity'])) continue;
        $findings[] = array(
            'fingerprint' => substr((string) $finding['fingerprint'], 0, 160),
            'severity' => in_array($finding['severity'], array('low', 'medium', 'high'), true) ? $finding['severity'] : 'low',
        );
        if (count($findings) >= 100) break;
    }
    return $findings;
}
