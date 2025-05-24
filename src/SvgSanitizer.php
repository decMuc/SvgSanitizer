<?php
namespace decMuc\SvgSanitizer;

final class SvgSanitizer
{
    /**
     * Prüft einen SVG- oder Textinhalt auf potenziell gefährliche Muster
     * Gibt false zurück, wenn Exploitverdacht besteht
     *
     * @param string $content
     * @return bool
     */
    public static function isSafe(string $content): bool
    {
        // Normalisieren (kleinschreibung, whitespaces entfernen)
        $str = strtolower(preg_replace('/\s+/', '', $content));

        // Exploit-Muster (JavaScript, XSS, SVG-Manipulation, Kommandoinjektion)
        $dangerousPatterns = [
            // XSS & JS
            '/<script.*?>/i',
            '/javascript:/i',
            '/xlink:href=["\']\s*javascript:/i',
            '/on[a-z]+\s*=\s*["\']?/i', // z.B. onclick, onload
            '/data:(text\/html|application\/javascript|image\/svg\+xml);base64/i',
            '/<!entity/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i',
            '/style=["\'].*?expression\(/i',
            '/eval\(/i',
            '/settimeout\(/i',
            '/setinterval\(/i',

            // Obfuscated oder encoded
            '/\\x[0-9a-f]{2}/i',
            '/&#x[0-9a-f]{2,};/i',
            '/&#\d{2,};/i',

            // Shell-Control-Zeichen und Wrapper
            '/[`$|><&;]/',
            '/\b(cat|curl|wget|nc|bash|sh|cmd|powershell|ftp|telnet)\b/i',
            '/\b(exec|passthru|system|shell_exec|proc_open|popen)\b/i',
            '/(?:file|php|zlib|data|glob|phar|ssh2|rar|ogg|expect):/i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $str)) {
                return false;
            }
        }

        return true;
    }
}
