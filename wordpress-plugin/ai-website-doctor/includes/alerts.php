<?php
/**
 * Email alerts sent by the site itself (wp_mail to the administrator address),
 * so a compromise is reported even when nobody is watching the dashboards.
 * New critical/high findings alert once; a finding that disappears and later
 * returns alerts again. Central alerts (outside checks, self-healing results)
 * arrive with the task poll and are sent once each.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AWD_ALERTS_OPTION', 'ai_website_doctor_alerts_sent');

function awd_alert_recipient(): string
{
    $email = (string) get_option('admin_email', '');
    return function_exists('is_email') && is_email($email) ? $email : '';
}

function awd_alert_send(string $subject, string $body): bool
{
    $to = awd_alert_recipient();
    if ($to === '' || !function_exists('wp_mail')) return false;
    $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
    $admin = admin_url('admin.php?page=ai-website-doctor');
    return (bool) wp_mail($to, '[' . $site . '] ' . $subject, $body . "\n\nReview it in WordPress: " . $admin . "\n\nSent by AI Website Doctor.");
}

/** Which issues need a new alert; updates the sent-state in place. Pure apart from the state array. */
function awd_alerts_select(array $issues, array &$state, int $now): array
{
    $current = array();
    $new = array();
    foreach ($issues as $issue) {
        if (!is_array($issue) || !in_array($issue['severity'] ?? '', array('critical', 'high'), true)) continue;
        $fingerprint = (string) ($issue['fingerprint'] ?? '');
        if (!preg_match('/^(?:integrity:|php-fatal:)/', $fingerprint)) continue;
        $current[$fingerprint] = true;
        if (!isset($state['findings'][$fingerprint])) $new[] = $issue;
        $state['findings'][$fingerprint] = $state['findings'][$fingerprint] ?? $now;
    }
    foreach (array_keys((array) ($state['findings'] ?? array())) as $fingerprint) {
        if (!isset($current[$fingerprint])) unset($state['findings'][$fingerprint]);
    }
    return $new;
}

function awd_alerts_process_findings(array $issues): void
{
    $state = get_option(AWD_ALERTS_OPTION, array());
    $state = is_array($state) ? $state : array();
    $new = awd_alerts_select($issues, $state, time());
    update_option(AWD_ALERTS_OPTION, $state, false);
    if (!$new) return;
    $lines = array_map(static function ($issue) {
        return '- ' . strtoupper((string) $issue['severity']) . ': ' . (string) $issue['title'] . "\n  " . substr((string) ($issue['description'] ?? ''), 0, 600);
    }, array_slice($new, 0, 10));
    awd_alert_send(sprintf('Security alert: %d new finding(s)', count($new)), "AI Website Doctor found new problems on this site:\n\n" . implode("\n\n", $lines));
}

/** Central alerts delivered with the task poll: [{id, title, body}], each sent once. */
function awd_alerts_process_central(array $alerts): void
{
    $state = get_option(AWD_ALERTS_OPTION, array());
    $state = is_array($state) ? $state : array();
    $sent = (array) ($state['central'] ?? array());
    foreach (array_slice($alerts, 0, 10) as $alert) {
        if (!is_array($alert) || empty($alert['id']) || !is_string($alert['id']) || isset($sent[$alert['id']])) continue;
        awd_alert_send(substr(sanitize_text_field((string) ($alert['title'] ?? 'Security alert')), 0, 150), substr(sanitize_textarea_field((string) ($alert['body'] ?? '')), 0, 4000));
        $sent[$alert['id']] = time();
    }
    $state['central'] = array_slice($sent, -200, null, true);
    update_option(AWD_ALERTS_OPTION, $state, false);
}
