<?php
if (!defined('WP_CLI') || !WP_CLI || !function_exists('awd_restore_recovery_point')) {
    fwrite(STDERR, "Run this script with WP-CLI after installing AI Website Doctor.\n");
    exit(2);
}
$backup_id = (string) getenv('AIWD_E2E_BACKUP_ID');
$result = awd_restore_recovery_point($backup_id);
echo wp_json_encode(array(
    'executionStatus' => is_wp_error($result) ? 'failed' : 'completed',
    'message' => is_wp_error($result) ? $result->get_error_message() : 'Recovery point restored.',
    'diagnostics' => awd_collect_diagnostics(array()),
));
