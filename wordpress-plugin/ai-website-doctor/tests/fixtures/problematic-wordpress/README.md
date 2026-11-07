# Deliberately broken WordPress test snippets

These snippets model a fatal error, duplicate plugin declarations, a plugin/theme declaration conflict, and a scheduled task that throws. They are not loaded by the plugin unit tests. Install them only in a disposable WordPress staging clone.

The plugin now records structured fatal events on PHP shutdown, and observes scheduled callbacks with timestamps. A task can be overdue while pending; it is marked failed only when a fatal error is observed during its callback. Non-fatal exceptions that are caught by another plugin may not be visible. Live scans never deactivate components. The staging conflict runner is limited to HTTP status regressions and does not validate browser-side symptoms.
