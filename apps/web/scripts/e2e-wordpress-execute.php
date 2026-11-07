<?php
if (!defined('WP_CLI') || !WP_CLI || !function_exists('awd_apply_steps')) {
    fwrite(STDERR, "Run this script with WP-CLI after installing AI Website Doctor.\n");
    exit(2);
}
$payload = json_decode((string) getenv('AIWD_E2E_EXECUTION'), true);
if (!is_array($payload) || !is_array($payload['steps'] ?? null)) {
    fwrite(STDERR, "Invalid test execution payload.\n");
    exit(2);
}
$backup = awd_create_recovery_point('Disposable E2E repair', $payload['steps']);
$result = awd_apply_steps($payload['steps'], $backup);
echo wp_json_encode(array(
    'backupId' => $backup,
    'executionStatus' => is_wp_error($result) ? 'failed' : 'completed',
    'message' => is_wp_error($result) ? $result->get_error_message() : 'Approved allowlisted operation applied.',
    'diagnostics' => awd_collect_diagnostics(array()),
));
