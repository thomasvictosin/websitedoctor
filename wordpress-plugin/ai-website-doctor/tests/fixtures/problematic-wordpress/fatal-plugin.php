<?php
// Deliberate PHP fatal-error fixture. Do not activate outside a disposable test site.
add_action('init', static function () {
    fixture_missing_boot_function();
});
