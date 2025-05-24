<?php
namespace decMuc\SvgSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use decMuc\SvgSanitizer\SvgSanitizer;

final class SvgSanitizerTest extends TestCase
{
    public function testSafeSvgIsDetectedAsSafe(): void
    {
        $svg = '<svg><circle cx="10" cy="10" r="5" fill="red"/></svg>';
        $this->assertTrue(SvgSanitizer::isSafe($svg));
    }

    public function testScriptTagIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><script>alert("XSS")</script></svg>';
        $this->assertFalse(SvgSanitizer::isSafe($svg));
    }

    public function testJavascriptHrefIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><a xlink:href="javascript:evil()"></a></svg>';
        $this->assertFalse(SvgSanitizer::isSafe($svg));
    }

    public function testOnloadAttributeIsDetectedAsUnsafe(): void
    {
        $svg = '<svg onload="doEvil()"></svg>';
        $this->assertFalse(SvgSanitizer::isSafe($svg));
    }

    public function testDataUriInjectionIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><image href="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=" /></svg>';
        $this->assertFalse(SvgSanitizer::isSafe($svg));
    }

    public function testShellCommandInjectionIsDetectedAsUnsafe(): void
    {
        $str = 'some text; rm -rf /';
        $this->assertFalse(SvgSanitizer::isSafe($str));
    }
}
