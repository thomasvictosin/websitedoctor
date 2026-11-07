<?php
// Deliberately failing scheduled callback, for a disposable WordPress integration target.
add_action('awd_fixture_failing_cron', static function () {
    throw new RuntimeException('Deliberate scheduled task failure.');
});
