Inert fixture of a compromised WordPress tree for `tests/allowlist.php`. Every
"malicious" PHP file starts with `return;`, so it does nothing if executed; the
integrity scanner only reads the files and matches code patterns.
