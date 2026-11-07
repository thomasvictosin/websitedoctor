<?php
/**
 * Plugin Name: E2E Repair Target A
 * Version: 1.0.0
 */
add_action('wp_footer', static function () {
    echo '<style>
      html{min-width:1100px!important}
      .awd-e2e-too-wide{width:1100px;min-height:90px;background:#eee}
      .awd-e2e-low-contrast{color:#aaa;background:#fff}
      #awd-e2e-menu[aria-controls="awd-e2e-nav"]{display:block}
      #awd-e2e-nav{display:none}
      @media(min-width:601px){#awd-e2e-menu{display:none}}
    </style>';
    echo '<button id="awd-e2e-menu" type="button" aria-controls="awd-e2e-nav" aria-expanded="false">Menu</button>';
    echo '<nav id="awd-e2e-nav"><a href="/">Home</a></nav>';
    echo '<div class="awd-e2e-too-wide">Deliberately overflowing staging fixture.</div>';
    echo '<p class="awd-e2e-low-contrast">Deliberately low contrast.</p>';
    echo '<img src="/awd-e2e-missing-image.png">';
    echo '<form><input type="email" placeholder="Email"><button>Submit</button></form>';
    echo '<script>throw new Error("E2E repair target A error");</script>';
});
