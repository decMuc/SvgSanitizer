<?php
namespace decMuc\SvgSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use decMuc\SvgSanitizer\SvgSanitizer;

final class SvgSanitizerTest extends TestCase
{
    public function testSafeSvgIsDetectedAsSafe(): void
    {
        $svg = '<svg><circle cx="10" cy="10" r="5" fill="red"/></svg>';
        $result = SvgSanitizer::isSafe($svg);
        $this->assertTrue($result['status']);
    }

    public function testScriptTagIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><script>alert("XSS")</script></svg>';
        $result = SvgSanitizer::isSafe($svg);
        $this->assertFalse($result['status']);
    }

    public function testJavascriptHrefIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><a xlink:href="javascript:evil()"></a></svg>';
        $result = SvgSanitizer::isSafe($svg);
        $this->assertFalse($result['status']);
    }

    public function testOnloadAttributeIsDetectedAsUnsafe(): void
    {
        $svg = '<svg onload="doEvil()"></svg>';
        $result = SvgSanitizer::isSafe($svg);
        $this->assertFalse($result['status']);
    }

    public function testDataUriInjectionIsDetectedAsUnsafe(): void
    {
        $svg = '<svg><image href="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=" /></svg>';
        $result = SvgSanitizer::isSafe($svg);
        $this->assertFalse($result['status']);
    }

    public function testShellCommandInjectionIsDetectedAsUnsafe(): void
    {
        $str = 'some text; rm -rf /';
        $result = SvgSanitizer::isSafe($str);
        $this->assertFalse($result['status']);
    }
}
