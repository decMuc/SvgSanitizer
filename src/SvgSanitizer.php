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

        // Exploit-Muster (JavaScript, XSS, SVG-Manipulation)
        $dangerousPatterns = [
            // Klartext
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

            // Hex escapes
            '/\\\\x[0-9a-f]{2}/i',        // z.B. \x3C = <
            '/&#x[0-9a-f]{2,};/i',        // z.B. &#x3C;
            '/&#\d{2,};/i',               // z.B. &#60;

            // Verdächtige Codierung (Hex für "script", "onload" etc.)
            '/(?:\x73\x63\x72\x69\x70\x74)/i', // "script"
            '/(?:\x6f\x6e\x6c\x6f\x61\x64)/i', // "onload"
            '/(?:\x65\x76\x61\x6c)/i',         // "eval"
            '/(?:\x64\x6f\x63\x75\x6d\x65\x6e\x74)/i', // "document"
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $str)) {
                return false;
            }
        }

        return true;
    }
}
