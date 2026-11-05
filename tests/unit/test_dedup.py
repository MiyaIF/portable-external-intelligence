import unittest
from unittest.mock import patch

import ei.dedup as dedup

from ei.dedup import (
    claim_fingerprint,
    classify_polarity,
    content_fingerprint,
    is_independent,
    jaccard,
    normalize_claim,
    similarity,
    tokenize_similarity,
)
from ei.models import ProvenanceRef


class DedupTests(unittest.TestCase):
    # Keep cases independent even when the module is run repeatedly in-process.
    def setUp(self):
        dedup._normalize_claim_cached.cache_clear()

    def tearDown(self):
        dedup._normalize_claim_cached.cache_clear()

    def test_normalize_claim_reuses_the_result_for_repeated_plain_string(self):
        claim = "  ＣＡＣＨＥ   repeated result 8a6d4f "
        with patch.object(dedup.unicodedata, "normalize", wraps=dedup.unicodedata.normalize) as normalizer:
            self.assertEqual(normalize_claim(claim), "cache repeated result 8a6d4f")
            self.assertEqual(normalize_claim(claim), "cache repeated result 8a6d4f")
        self.assertEqual(normalizer.call_count, 1)

    def test_normalize_claim_recomputes_after_bounded_cache_eviction(self):
        first = "dedup-eviction-sentinel-7f1c"
        with patch.object(dedup.unicodedata, "normalize", wraps=dedup.unicodedata.normalize) as normalizer:
            self.assertEqual(normalize_claim(first), first)
            for index in range(8192):
                normalize_claim(f"dedup-eviction-filler-{index}")
            self.assertEqual(normalizer.call_count, 8193)
            self.assertEqual(normalize_claim(first), first)
        self.assertEqual(normalizer.call_count, 8194)

    def test_normalize_claim_keeps_validation_before_cache_keying(self):
        with self.assertRaisesRegex(TypeError, "^CLAIM_TEXT_REQUIRED$"):
            normalize_claim(["mutable", "invalid"])

    def test_normalize_claim_preserves_unhashable_str_subclass_behavior(self):
        class UnhashableText(str):
            __hash__ = None

        claim = UnhashableText("  ＣＡＣＨＥ   subclass  ")
        self.assertEqual(normalize_claim(claim), "cache subclass")
        self.assertEqual(normalize_claim(claim), "cache subclass")

    def test_normalization_is_unicode_line_ending_spacing_and_ascii_case_stable(self):
        left = normalize_claim(" ＡＢＣ\r\n  test ： value ")
        right = normalize_claim("abc\n test: value")
        self.assertEqual(left, "abc test:value")
        self.assertEqual(left, right)

    def test_canonical_fingerprint_is_stable_over_normalized_forms(self):
        self.assertEqual(
            claim_fingerprint("書込後に再読込する\r\n"),
            claim_fingerprint("書込後に再読込する"),
        )
        self.assertEqual(content_fingerprint("same"), claim_fingerprint("same"))
        self.assertEqual(len(claim_fingerprint("same")), 64)

    def test_similarity_uses_japanese_bigrams_and_ascii_words(self):
        japanese = similarity("東京駅で荷物を確認する", "東京駅で荷物を保管する")
        ascii_score = similarity("Alpha beta gamma", "alpha beta delta")
        self.assertGreater(japanese, 0.0)
        self.assertGreater(ascii_score, 0.0)
        left = tokenize_similarity("書込後に対象範囲を再読込して数式を確認する")
        right = tokenize_similarity("数式を書いたらシートを読み直して反映を検証する")
        self.assertGreaterEqual(jaccard(left, right), 0.72)

    def test_polarity_is_three_valued(self):
        self.assertEqual(classify_polarity("書込後に再読込して検証する"), "SUPPORTS")
        self.assertEqual(classify_polarity("書込後に再読込してはいけない"), "CONTRADICTS")
        self.assertEqual(classify_polarity("検証するが、禁止される場合は実施しない"), "MIXED")

    def test_independence_collapses_same_session_and_requires_scope_difference(self):
        same_session_left = ProvenanceRef("sha256:a", session_id_hash="sha256:s1", cwd_hash="cwd:a", domain="x")
        same_session_right = ProvenanceRef("sha256:b", session_id_hash="sha256:s1", cwd_hash="cwd:b", domain="x")
        self.assertFalse(is_independent(same_session_left, same_session_right))
        same_scope_left = ProvenanceRef("sha256:a", cwd_hash="cwd:a", domain="x")
        same_scope_right = ProvenanceRef("sha256:b", cwd_hash="cwd:a", domain="x")
        self.assertFalse(is_independent(same_scope_left, same_scope_right))
        independent = ProvenanceRef("sha256:b", cwd_hash="cwd:b", domain="x")
        self.assertTrue(is_independent(same_scope_left, independent))


if __name__ == "__main__":
    unittest.main()
