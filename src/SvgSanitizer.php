<?php
namespace decMuc\SvgSanitizer;

final class SvgSanitizer
{
    /**
     * Prüft einen SVG- oder Textinhalt auf potenziell gefährliche Muster,
     * filtert das SVG auf erlaubte Tags/Attribute, Farben, hrefs usw.
     * Gibt false zurück, wenn Exploitverdacht oder unsauberes SVG.
     *
     * @param string $content
     * @return bool
     */
    public static function isSafe(string $content): bool
    {
        // 1. Schnelle Exploit-Pattern-Prüfung (Blacklist)
        $str = strtolower(preg_replace('/\s+/', '', $content));
        $dangerousPatterns = [
            '/<script.*?>/i',
            '/javascript:/i',
            '/xlink:href=["\']\s*javascript:/i',
            '/href=["\']\s*javascript:/i',
            '/on[a-z]+\s*=\s*["\']?/i',
            '/data:(text\/html|application\/javascript|image\/svg\+xml);base64/i',
            '/<!entity/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i',
            '/style=["\'].*?expression\(/i',
            '/eval\(/i',
            '/settimeout\(/i',
            '/setinterval\(/i',
            '/\\\\x[0-9a-f]{2}/i',
            '/&#x[0-9a-f]{2,};/i',
            '/&#\d{2,};/i',
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

        // 2. Jetzt DOM-Whitelist-Prüfung und -Filterung
        $cleanSvg = self::sanitizeSvg($content);
        if (!$cleanSvg) return false;
        return true;
    }

    /**
     * Gibt ein Whitelist-gefiltertes SVG zurück oder leeres String, wenn nicht möglich.
     */
    public static function sanitizeSvg(string $svg): string
    {
        libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        // Encoding erzwingen, Entities und Netzwerkeffekte verhindern!
        if (!$doc->loadXML($svg, LIBXML_NONET | LIBXML_NOENT | LIBXML_NOWARNING | LIBXML_NOERROR)) {
            return '';
        }

        // Erlaubte Tags & Attribute (erweiterbar!)
        $allowedTags = [
            'svg', 'g', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'path', 'text',
            'defs', 'mask', 'stop', 'linearGradient', 'radialGradient', 'image'
        ];
        $allowedAttrs = [
            // SVG Standardattribute
            'x', 'y', 'width', 'height', 'rx', 'ry', 'cx', 'cy', 'r', 'points', 'd',
            'fill', 'fill-opacity', 'stroke', 'stroke-width', 'opacity', 'font-size', 'font-family',
            'transform', 'viewBox', 'style',
            // image & gradient
            'xlink:href', 'href', 'gradientUnits', 'gradientTransform', 'offset', 'stop-color', 'stop-opacity'
        ];

        // Rekursiv filtern
        self::sanitizeNode($doc->documentElement, $allowedTags, $allowedAttrs);

        // Rückgabe als XML-String
        $cleanSvg = $doc->saveXML($doc->documentElement);
        if (empty($cleanSvg)) return '';
        return $cleanSvg;
    }

    /**
     * Rekursive Whitelist-Filterung, inklusive Attributprüfung und spezieller href/style-Kontrollen.
     */
    private static function sanitizeNode($node, $allowedTags, $allowedAttrs)
    {
        // Kindelemente (Tags) filtern
        if ($node->hasChildNodes()) {
            foreach (iterator_to_array($node->childNodes) as $child) {
                if ($child->nodeType === XML_ELEMENT_NODE) {
                    if (!in_array($child->localName, $allowedTags)) {
                        $node->removeChild($child);
                    } else {
                        self::sanitizeNode($child, $allowedTags, $allowedAttrs);
                    }
                }
            }
        }
        // Attribute prüfen
        if ($node->hasAttributes()) {
            foreach (iterator_to_array($node->attributes) as $attr) {
                $name = $attr->nodeName;
                $val = $attr->nodeValue;

                // --- Spezialsicherheit: style ---
                if ($name === 'style') {
                    $filtered = self::filterSvgStyle($val);
                    if ($filtered) {
                        $attr->value = $filtered;
                    } else {
                        $node->removeAttribute($name);
                    }
                }
                // --- Spezialsicherheit: href/xlink:href ---
                elseif ($name === 'href' || $name === 'xlink:href') {
                    // Erlaube nur Base64-Images und relative URLs
                    if (!self::isSafeHref($val)) {
                        $node->removeAttribute($name);
                    }
                }
                // --- Optional: Stoppe böse data: URIs auf image-Elementen ---
                elseif (($node->localName === 'image') && ($name === 'href' || $name === 'xlink:href')) {
                    if (!self::isSafeImageDataUri($val)) {
                        $node->removeAttribute($name);
                    }
                }
                // --- Normale Attribute ---
                elseif (!in_array($name, $allowedAttrs)) {
                    $node->removeAttribute($name);
                }
            }
        }
    }

    /**
     * Whitelist-Filterung für style-Attribute.
     * Erlaubt nur fill, stroke, color mit HEX oder rgba(), Semikolon am Ende optional.
     */
    private static function filterSvgStyle($style)
    {
        $allowed = [];
        if (preg_match_all('/(fill|stroke|color)\s*:\s*([#][0-9a-fA-F]{3,8}|rgba?\(\s*(\d{1,3}\s*,\s*){2,3}\d?\.?\d*\s*\))\s*;?\s*/i', $style, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                // HEX prüfen
                if (strpos($m[2], '#') === 0 && !preg_match('/^#[0-9a-fA-F]{3}([0-9a-fA-F]{1})?$|^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$/', $m[2])) {
                    continue; // ungültiges Hex, überspringen!
                }
                // rgba prüfen
                if (stripos($m[2], 'rgb') === 0 && !preg_match('/^rgba?\(\s*(\d{1,3}\s*,\s*){2,3}\d?\.?\d*\s*\)$/', $m[2])) {
                    continue; // ungültig, überspringen!
                }
                $allowed[] = "{$m[1]}: {$m[2]};";
            }
        }
        return implode(' ', $allowed);
    }

    /**
     * Prüft, ob ein href/xlink:href safe ist.
     * Erlaubt: data:image/png|jpeg|gif;base64,... ODER relative URLs.
     * Verbietet: javascript:, data:image/svg+xml, http(s)://...
     */
    private static function isSafeHref($href)
    {
        $href = trim($href);

        // Base64 nur für sichere Bildformate erlauben
        if (preg_match('#^data:image/(png|jpeg|jpg|gif|webp|avif);base64,#i', $href)) {
            return true;
        }

        // Keine anderen data:-URIs!
        if (stripos($href, 'data:') === 0) {
            return false;
        }

        // Relative URLs: erlauben (kein Protokoll, kein // am Anfang)
        if (preg_match('#^[a-zA-Z0-9_\-./]+$#', $href)) {
            return true;
        }

        // explizit verbieten: javascript:, http:, https:, file:, etc.
        if (preg_match('#^(javascript|http|https|file|ftp|mailto):#i', $href)) {
            return false;
        }

        // Alles andere (z.B. //domain...) lieber verbieten
        if (strpos($href, '//') === 0) {
            return false;
        }

        // Sonst: unsicher
        return false;
    }

    /**
     * Spezielle Prüfung für image mit data: URI:
     * Nur PNG/JPEG/GIF als base64, keine SVG/HTML.
     */
    private static function isSafeImageDataUri($val)
    {
        return preg_match('#^data:image/(png|jpeg|jpg|gif|webp|avif);base64,#i', $val);
    }
}
