from __future__ import annotations

import unittest

from worker import language_detection


class WorkerLanguageDetectionTests(unittest.TestCase):
    def test_detects_english_spanish_and_three_other_languages(self) -> None:
        cases = (
            (
                "en",
                "hello world this document recovery image language confidence and the scanned document",
            ),
            (
                "es",
                "hola mundo este documento de recuperación imagen idioma confianza y documento escaneado",
            ),
            (
                "fr",
                "bonjour monde document numérisé récupération image langue confiance avec le document",
            ),
            ("de", "hallo welt dokument gescannt bild sprache vertrauen und die wiederherstellung"),
            (
                "pt",
                "olá mundo documento digitalizado recuperação imagem idioma confiança com documento",
            ),
        )
        for expected, text in cases:
            with self.subTest(expected=expected):
                result = language_detection.detect_text_language(text)

            self.assertEqual("complete", result.status)
            self.assertEqual(expected, result.primary_language)
            self.assertGreaterEqual(result.confidence, 0.35)
            self.assertEqual(expected, result.scores[0].language)
            self.assertTrue(result.scores[0].matched_terms)

    def test_mixed_language_is_visible_without_hiding_primary_scores(self) -> None:
        result = language_detection.detect_text_language(
            "hello world this document recovery image language confidence "
            "hola mundo este documento recuperación imagen idioma confianza"
        )

        self.assertEqual("mixed", result.primary_language)
        self.assertIn("mixed_language:", result.warnings[0])
        self.assertEqual({"en", "es"}, {score.language for score in result.scores[:2]})

    def test_short_numeric_and_gibberish_samples_are_unknown(self) -> None:
        short = language_detection.detect_text_language("hello")
        numeric = language_detection.detect_text_language("123 456 789 000 111 222 abc def ghi")
        gibberish = language_detection.detect_text_language(
            "@@@ ### $$$ !!! ??? abc def ghi jkl mno pqr"
        )

        self.assertEqual("unknown", short.primary_language)
        self.assertIn("short_text", short.warnings)
        self.assertEqual("unknown", numeric.primary_language)
        self.assertIn("low_language_signal", numeric.warnings)
        self.assertEqual("unknown", gibberish.primary_language)

    def test_ocr_noise_is_tolerated_and_sample_size_threshold_is_configurable(self) -> None:
        result = language_detection.detect_text_language(
            "OCR confidence 0.72 hello world this scanned document image language recovery"
        )

        self.assertEqual("en", result.primary_language)
        self.assertIn("ocr_noise_tolerated", result.warnings)

        with self.assertRaises(ValueError):
            language_detection.detect_text_language("text", min_alpha_chars=0)


if __name__ == "__main__":
    unittest.main()
