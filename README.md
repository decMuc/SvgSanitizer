# SvgSanitizer

![PHP](https://img.shields.io/badge/PHP-%3E=7.4-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**SvgSanitizer** is a lightweight PHP library that validates SVG files or fragments and blocks potentially harmful code like JavaScript, embedded objects, inline event handlers, or suspicious Base64 payloads. It helps protect your application from XSS and injection attacks via SVG uploads.

---

**SvgSanitizer** ist eine kompakte PHP-Bibliothek zur Prüfung von SVG-Dateien oder -Inhalten. Sie erkennt und blockiert potenziell schadhaften Code wie JavaScript, eingebettete Objekte, Inline-Handler oder verdächtige Base64-Payloads. Damit schützt sie deine Anwendung vor XSS- oder Injektionsangriffen durch manipulierte SVGs.

---

## 📦 Installation

### English

Use Composer to add the package:

```bash
composer require decMuc/SvgSanitizer
```

### Deutsch

Füge die Bibliothek über Composer hinzu:

```bash
composer require decMuc/SvgSanitizer
```

## ⚙️ Autoloading

### English

Make sure Composer's autoload is enabled:

### Deutsch

Stelle sicher, dass Composer's Autoload aktiviert ist:`

```php
require_once 'vendor/autoload.php';
```

## 🚀 Usage / Nutzung

### English

Use the `SvgSanitizer` class to check if an SVG is safe. Example:

### Deutsch

Verwende die Klasse `SvgSanitizer`, um zu prüfen, ob ein SVG sicher ist. Beispiel:

```php
<?php
require_once 'vendor/autoload.php';

use decMuc\SvgSanitizer\SvgSanitizer;

// SVG-Datei einlesen
$svg = file_get_contents('upload/logo.svg');

// Sicherheitsprüfung & Reinigung durchführen
$result = SvgSanitizer::isSafe($svg);
if ($result['status']) {
    // SVG kann sicher weiterverarbeitet werden
    file_put_contents("cleaned.svg", $result['svg']);
    echo 'SVG ist sicher!';
} else {
    // Datei ablehnen oder protokollieren
    echo $result['msg'];
}
```

## 🔧 Methods / Methoden

* **English**: 
* `SvgSanitizer::isSafe(string $svg): array` –  
  Returns `['status' => true, 'svg' => cleaned SVG, 'msg' => '']` if the SVG is clean, or `['status' => false, 'svg' => '', 'msg' => error message]` if suspicious patterns or errors are found.

* **Deutsch**: 
* `SvgSanitizer::isSafe(string $svg): array` –
  Gibt ein Array zurück: `['status' => true, 'svg' => bereinigtes SVG, 'msg' => '']` wenn das SVG sauber ist,
  oder `['status' => false, 'svg' => '', 'msg' => Fehlermeldung]` wenn verdächtige Patterns oder Fehler gefunden wurden.
 
## ⚠️ Example Error Handling / Beispielhafte Fehlermeldungen

### English

SvgSanitizer checks SVG content on three levels:
First, known exploit patterns are reliably detected and immediately blocked using a blacklist. Next, the SVG is validated and cleaned based on a strict whitelist of allowed tags and attributes. Finally, special rules are applied to styles and embedded data to eliminate hidden risks.

Only SVGs that pass all checks are accepted and returned.

### Deutsch

SvgSanitizer prüft SVG-Inhalte auf drei Ebenen:
Zunächst werden bekannte Exploit-Muster mit einer Blacklist zuverlässig erkannt und sofort blockiert. Anschließend wird das SVG anhand einer strengen Whitelist zulässiger Tags und Attribute geprüft und bereinigt. Abschließend werden spezielle Regeln auf Styles und eingebettete Daten angewendet, um auch versteckte Gefahrenquellen auszuschließen.

Nur SVGs, die alle Prüfungen bestehen, werden akzeptiert und ausgegeben.

## 📝 License / Lizenz

### English

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

### Deutsch

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Siehe [LICENSE](LICENSE) für Details.
