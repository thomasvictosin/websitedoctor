<?php
/**
 * Plugin Name: E2E Repair Target B
 * Version: 1.0.0
 */
add_action('wp_footer', static function () {
    echo '<a href="#awd-e2e-repair-target-b-missing-anchor">E2E repair target B conflict</a>';
    echo '<script>console.error("E2E repair target B error");fetch("/awd-e2e-repair-target-b-missing.js").catch(() => {});</script>';
});
