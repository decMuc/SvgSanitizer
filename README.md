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
composer require decmuc/svg-sanitizer
```

### Deutsch

Füge die Bibliothek über Composer hinzu:

```bash
composer require decmuc/svg-sanitizer
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

// Sicherheitsprüfung durchführen
if (SvgSanitizer::isSafe($svg)) {
    // SVG kann sicher weiterverarbeitet werden
    echo 'SVG ist sicher!';
} else {
    // Datei ablehnen oder protokollieren
    echo 'Verdächtiger SVG-Inhalt erkannt!';
}
```

## 🔧 Methods / Methoden

* **English**: `SvgSanitizer::isSafe(string $svg): bool` – Returns `true` if the SVG contains no potentially harmful elements.
* **Deutsch**: `SvgSanitizer::isSafe(string $svg): bool` – Gibt `true` zurück, wenn das SVG keine potenziell schädlichen Elemente enthält.

## ⚠️ Example Error Handling / Beispielhafte Fehlermeldungen

### English

If the check fails, you can reject the SVG, log the incident, or sanitize the content.

### Deutsch

Sollte die Prüfung fehlschlagen, kann man das SVG ablehnen, protokollieren oder bereinigen.

## 📝 License / Lizenz

### English

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

### Deutsch

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Siehe [LICENSE](LICENSE) für Details.
