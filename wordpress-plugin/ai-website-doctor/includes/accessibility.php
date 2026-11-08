<?php
/**
 * Automatic accessibility fixes, applied to the HTML of public pages as they
 * are sent (theme and plugin files are never edited). Each one is a speed-style
 * measure (awd_performance_measures, group "accessibility"), switched through
 * the same approved executor, health-checked, and reversible.
 *
 * - a11y_zoom: removes user-scalable=no and maximum-scale from the viewport tag.
 * - a11y_names: gives icon-only links and buttons an aria-label derived from
 *   where they point (social networks, email, phone, a page of this site) or
 *   from their icon class (menu, search, close, cart…). Unknown ones are left alone.
 *   Embedded frames without a title get one from their address (Map, YouTube video…).
 * - a11y_form_labels: gives form fields without any label an aria-label from
 *   their placeholder or field name.
 */

if (!defined('ABSPATH')) {
    exit;
}

function awd_a11y_measures(): array
{
    return array(
        'a11y_zoom' => array('title' => 'Allow zooming on phones', 'description' => 'Removes the setting that stops visitors from pinch-zooming, so people with low vision can enlarge text.', 'group' => 'accessibility'),
        'a11y_names' => array('title' => 'Name icon-only links and buttons', 'description' => 'Icon links and buttons (social icons, menu, search, close) and embedded maps and videos get a spoken name for screen readers, taken from where they point or what the icon is. Nothing visible changes.', 'group' => 'accessibility'),
        'a11y_form_labels' => array('title' => 'Label form fields', 'description' => 'Form fields without a label get one for screen readers, taken from their placeholder or field name. Nothing visible changes.', 'group' => 'accessibility'),
    );
}

const AWD_A11Y_SOCIAL = array(
    'facebook' => 'Facebook', 'fb.com' => 'Facebook', 'twitter' => 'X (Twitter)', 'x.com' => 'X (Twitter)', 'instagram' => 'Instagram',
    'linkedin' => 'LinkedIn', 'youtube' => 'YouTube', 'youtu.be' => 'YouTube', 'tiktok' => 'TikTok', 'pinterest' => 'Pinterest',
    'whatsapp' => 'WhatsApp', 'wa.me' => 'WhatsApp', 't.me' => 'Telegram', 'telegram' => 'Telegram', 'threads.net' => 'Threads',
    'github' => 'GitHub', 'behance' => 'Behance', 'dribbble' => 'Dribbble', 'vimeo' => 'Vimeo', 'snapchat' => 'Snapchat',
    'spotify' => 'Spotify', 'soundcloud' => 'SoundCloud', 'medium.com' => 'Medium', 'reddit' => 'Reddit', 'discord' => 'Discord', 'tumblr' => 'Tumblr',
);

const AWD_A11Y_ICON_WORDS = array(
    'hamburger' => 'Menu', 'menu-toggle' => 'Menu', 'nav-toggle' => 'Menu', 'navbar-toggle' => 'Menu', 'toggle-menu' => 'Menu', 'menu' => 'Menu', 'bars' => 'Menu',
    'search' => 'Search', 'close' => 'Close', 'times' => 'Close', 'xmark' => 'Close', 'cart' => 'Cart', 'basket' => 'Cart', 'shopping-bag' => 'Cart',
    'back-to-top' => 'Back to top', 'scroll-top' => 'Back to top', 'scroll-to-top' => 'Back to top', 'totop' => 'Back to top', 'go-top' => 'Back to top',
    'chevron-right' => 'Next', 'arrow-right' => 'Next', 'angle-right' => 'Next', 'next' => 'Next',
    'chevron-left' => 'Previous', 'arrow-left' => 'Previous', 'angle-left' => 'Previous', 'prev' => 'Previous',
    'play' => 'Play', 'pause' => 'Pause', 'phone' => 'Call us', 'envelope' => 'Email', 'mail' => 'Email', 'user' => 'Account', 'account' => 'Account', 'login' => 'Log in',
);

function awd_a11y_attr(string $attributes, string $name): ?string
{
    if (!preg_match('/(?:^|\s)' . preg_quote($name, '/') . '\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $attributes, $match)) return null;
    $value = ($match[1] ?? '') !== '' ? $match[1] : ((($match[2] ?? '') !== '') ? $match[2] : ($match[3] ?? ''));
    return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function awd_a11y_has_name(string $attributes): bool
{
    foreach (array('aria-label', 'aria-labelledby', 'title') as $name) {
        $value = awd_a11y_attr($attributes, $name);
        if ($value !== null && trim($value) !== '') return true;
    }
    return false;
}

function awd_a11y_humanize(string $value): string
{
    $value = preg_replace('/\.[a-z0-9]{2,5}$/i', '', $value);
    $value = trim((string) preg_replace('/[\s_\-\[\]]+/', ' ', (string) $value));
    if ($value === '' || strlen($value) > 60 || !preg_match('/[a-z]/i', $value)) return '';
    return ucfirst(strtolower($value));
}

/** A spoken name for an icon-only link or button, or '' when none can be derived safely. */
function awd_a11y_name_for(string $tag, string $attributes, string $inner): string
{
    if ($tag === 'a') {
        $href = (string) awd_a11y_attr($attributes, 'href');
        if (stripos($href, 'mailto:') === 0) return 'Send an email';
        if (stripos($href, 'tel:') === 0) return 'Call us';
        $parsed = wp_parse_url($href);
        $host = strtolower((string) (is_array($parsed) ? ($parsed['host'] ?? '') : ''));
        if ($host !== '') {
            foreach (AWD_A11Y_SOCIAL as $needle => $label) if (strpos($host, $needle) !== false) return $label;
        }
    }
    // Class names on the element and its icon, e.g. <i class="fab fa-instagram">, <svg class="icon-search">.
    preg_match_all('/class\s*=\s*(?:"([^"]*)"|\'([^\']*)\')/i', $attributes . ' ' . $inner, $classes);
    $tokens = strtolower(implode(' ', array_merge($classes[1], $classes[2])));
    if ($tokens !== '') {
        foreach (AWD_A11Y_SOCIAL as $needle => $label) if (strpos($needle, '.') === false && preg_match('/(?:^|[\s_-])' . preg_quote($needle, '/') . '(?:$|[\s_-])/', $tokens)) return $label;
        // The icon word must end the class (fa-bars, icon-search), so menu-item or next-post never match.
        foreach (AWD_A11Y_ICON_WORDS as $needle => $label) if (preg_match('/(?:^|[\s_])(?:[a-z0-9]+-)*' . preg_quote($needle, '/') . '(?:$|\s)/', $tokens)) return $label;
    }
    if ($tag === 'a') {
        $href = (string) awd_a11y_attr($attributes, 'href');
        $home = (array) wp_parse_url(home_url('/'));
        $target = (array) wp_parse_url($href);
        $same = $href !== '' && $href[0] !== '#' && (empty($target['host']) || strtolower((string) $target['host']) === strtolower((string) ($home['host'] ?? '')));
        if ($same) {
            $path = trim((string) ($target['path'] ?? ''), '/');
            $homePath = trim((string) ($home['path'] ?? ''), '/');
            if ($path === $homePath) return 'Home';
            $label = awd_a11y_humanize(basename($path));
            if ($label !== '') return $label;
        }
    }
    return '';
}

function awd_a11y_visible_text(string $inner): bool
{
    $text = trim(html_entity_decode(wp_strip_all_tags($inner), ENT_QUOTES | ENT_HTML5, 'UTF-8'), " \t\n\r\0\x0B\xC2\xA0");
    if ($text !== '') return true;
    // An image with alternative text, or an element labelled for screen readers, already names it.
    if (preg_match('/<img\b[^>]*\balt\s*=\s*(["\'])\s*[^"\'\s][^"\']*\1/i', $inner)) return true;
    if (preg_match('/\baria-label(?:ledby)?\s*=\s*(["\'])\s*[^"\'\s]/i', $inner)) return true;
    return false;
}

function awd_a11y_add_attribute(string $tag, string $openTag, string $name, string $value): string
{
    return (string) preg_replace('/^<' . $tag . '\b/i', '<' . $tag . ' ' . $name . '="' . esc_attr($value) . '"', $openTag, 1);
}

function awd_a11y_name_controls(string $html): string
{
    // Scripts, styles, templates and text areas are copied unchanged (their contents are not markup).
    return (string) preg_replace_callback(
        '/<(script|style|template|textarea|noscript)\b.*?<\/\1\s*>|<(a|button)\b([^>]*)>(.{0,3000}?)<\/\2\s*>/is',
        static function (array $m): string {
            if (($m[1] ?? '') !== '') return $m[0];
            $tag = strtolower($m[2]);
            $attributes = $m[3];
            $inner = $m[4];
            if (awd_a11y_has_name($attributes) || awd_a11y_visible_text($inner)) return $m[0];
            if ($tag === 'a' && awd_a11y_attr($attributes, 'href') === null) return $m[0];
            if (preg_match('/\baria-hidden\s*=\s*["\']?true/i', $attributes)) return $m[0];
            $label = awd_a11y_name_for($tag, $attributes, $inner);
            if ($label === '') return $m[0];
            $open = '<' . $m[2] . $attributes . '>';
            return awd_a11y_add_attribute($m[2], $open, 'aria-label', $label) . $inner . substr($m[0], strlen($open) + strlen($inner));
        },
        $html
    );
}

/** A title for an embedded frame (map, video, booking widget) taken from where it points. */
function awd_a11y_frame_title(string $attributes): string
{
    $src = '';
    foreach (array('src', 'data-src', 'data-lazy-src') as $name) {
        $value = trim((string) awd_a11y_attr($attributes, $name));
        if ($value !== '' && stripos($value, 'about:') !== 0 && stripos($value, 'data:') !== 0) { $src = $value; break; }
    }
    if ($src === '') return 'Embedded content';
    $parsed = (array) wp_parse_url(strpos($src, '//') === 0 ? 'https:' . $src : $src);
    $host = strtolower((string) ($parsed['host'] ?? ''));
    $path = strtolower((string) ($parsed['path'] ?? ''));
    if ($host === '') return 'Embedded content';
    if (preg_match('/(^|\.)google\.[a-z.]+$/', $host) && strpos($path, '/maps') === 0) return 'Map';
    if (strpos($host, 'maps.') === 0 || strpos($host, 'openstreetmap') !== false) return 'Map';
    if (strpos($host, 'youtube') !== false || $host === 'youtu.be') return 'YouTube video';
    if (strpos($host, 'vimeo') !== false) return 'Vimeo video';
    if (strpos($host, 'calendly') !== false) return 'Booking calendar';
    if (preg_match('/(^|\.)google\.com$/', $host) && strpos($path, '/forms') !== false) return 'Form';
    foreach (AWD_A11Y_SOCIAL as $needle => $label) if (strpos($host, $needle) !== false) return $label . ' content';
    return 'Embedded content from ' . preg_replace('/^www\./', '', $host);
}

function awd_a11y_name_frames(string $html): string
{
    return (string) preg_replace_callback(
        '/<(script|style|template|textarea|noscript)\b.*?<\/\1\s*>|<iframe\b([^>]*)>/is',
        static function (array $m): string {
            if (($m[1] ?? '') !== '') return $m[0];
            $attributes = $m[2];
            if (awd_a11y_has_name($attributes)) return $m[0];
            if (preg_match('/\baria-hidden\s*=\s*["\']?true|\brole\s*=\s*["\']?(?:none|presentation)\b/i', $attributes)) return $m[0];
            return awd_a11y_add_attribute('iframe', $m[0], 'title', awd_a11y_frame_title($attributes));
        },
        $html
    );
}

function awd_a11y_label_fields(string $html): string
{
    preg_match_all('/<label\b[^>]*\bfor\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^\s>]+))/i', $html, $for);
    $labelled = array_flip(array_filter(array_merge($for[1], $for[2], $for[3])));
    return (string) preg_replace_callback(
        '/<(script|style|template)\b.*?<\/\1\s*>|<(input|select|textarea)\b([^>]*)>/is',
        static function (array $match) use ($labelled, $html): string {
            $m = array_map(static fn ($group) => $group[0], $match);
            if (($m[1] ?? '') !== '') return $m[0];
            // A field inside <label>…</label> is already named by that visible label.
            $before = substr($html, max(0, $match[0][1] - 3000), min(3000, $match[0][1]));
            $open = strripos($before, '<label');
            if ($open !== false && $open > (int) strripos($before, '</label')) return $m[0];
            $attributes = $m[3];
            if (awd_a11y_has_name($attributes)) return $m[0];
            $type = strtolower((string) awd_a11y_attr($attributes, 'type'));
            if (strtolower($m[2]) === 'input' && in_array($type, array('hidden', 'submit', 'button', 'reset', 'image'), true)) return $m[0];
            $id = awd_a11y_attr($attributes, 'id');
            if ($id !== null && isset($labelled[$id])) return $m[0];
            $label = trim((string) awd_a11y_attr($attributes, 'placeholder'));
            if ($label === '') $label = awd_a11y_humanize((string) preg_replace('/^.*\[([^\]]+)\]$/', '$1', (string) awd_a11y_attr($attributes, 'name')));
            if ($label === '' && $type === 'search') $label = 'Search';
            if ($label === '') return $m[0];
            return awd_a11y_add_attribute($m[2], $m[0], 'aria-label', substr($label, 0, 120));
        },
        $html,
        -1,
        $count,
        PREG_OFFSET_CAPTURE
    );
}

function awd_a11y_allow_zoom(string $html): string
{
    return (string) preg_replace_callback('/<meta\b[^>]*\bname\s*=\s*["\']viewport["\'][^>]*>/i', static function (array $m): string {
        return (string) preg_replace_callback('/\bcontent\s*=\s*(["\'])(.*?)\1/i', static function (array $c): string {
            $parts = array_filter(array_map('trim', explode(',', $c[2])), static function ($part) {
                return $part !== '' && !preg_match('/^(?:user-scalable\s*=\s*(?:no|0)|maximum-scale\s*=\s*[\d.]+)$/i', $part);
            });
            return 'content=' . $c[1] . implode(', ', $parts) . $c[1];
        }, $m[0], 1);
    }, $html);
}

/** Applies the switched-on accessibility fixes to one HTML document. */
function awd_a11y_filter_html(string $html, array $enabled): string
{
    if ($html === '' || stripos($html, '<html') === false || strlen($html) > 5000000) return $html;
    $original = $html;
    if (!empty($enabled['a11y_zoom'])) $html = awd_a11y_allow_zoom($html);
    if (!empty($enabled['a11y_names'])) $html = awd_a11y_name_frames(awd_a11y_name_controls($html));
    if (!empty($enabled['a11y_form_labels'])) $html = awd_a11y_label_fields($html);
    // A regex failure (backtrack limit on unusual markup) returns '' — never send a blank page.
    return $html !== '' ? $html : $original;
}

if (function_exists('add_action') && function_exists('get_option')) {
    add_action('template_redirect', static function () {
        if (is_admin() || wp_doing_ajax() || is_feed() || (defined('REST_REQUEST') && REST_REQUEST) || is_customize_preview()) return;
        $enabled = array();
        foreach (array_keys(awd_a11y_measures()) as $id) if (function_exists('awd_performance_enabled') && awd_performance_enabled($id)) $enabled[$id] = true;
        if (!$enabled) return;
        ob_start(static function ($buffer) use ($enabled) {
            if (!is_string($buffer)) return $buffer;
            foreach (headers_list() as $header) {
                if (stripos($header, 'content-type:') === 0 && stripos($header, 'text/html') === false) return $buffer;
            }
            return awd_a11y_filter_html($buffer, $enabled);
        });
    }, 0);
}
