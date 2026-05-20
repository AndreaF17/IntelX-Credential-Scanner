import unittest

from custom.credential_extractor import (
    EXTRACTION_MODES,
    build_target_context,
    candidate_mentions_target,
    extract_credentials_from_line,
)


class CredentialExtractorTests(unittest.TestCase):
    def test_parses_scheme_less_host_format(self):
        line = 'stage.ivsanbernard.it/:stage.ivsanbernard.it:Nonmelaricordo1'
        candidates = extract_credentials_from_line(line, mode='balanced')

        self.assertTrue(candidates)
        best = candidates[0]
        self.assertEqual(best['identity'], 'stage.ivsanbernard.it')
        self.assertEqual(best['password'], 'Nonmelaricordo1')
        self.assertIn('stage.ivsanbernard.it', best['url'])

    def test_parses_kv_with_quoted_password(self):
        line = 'url=portal.example.com user=admin password="my secret pass"'
        candidates = extract_credentials_from_line(line, mode='balanced')

        self.assertTrue(candidates)
        kv = next((item for item in candidates if item['pattern'] == 'kv_pairs'), None)
        self.assertIsNotNone(kv)
        self.assertEqual(kv['password'], 'my secret pass')
        self.assertEqual(kv['identity'], 'admin')

    def test_extracts_multiple_credentials_in_one_line(self):
        line = 'site1.example.com:user1:Pass123! || site2.example.com:user2:Pass456!'
        candidates = extract_credentials_from_line(line, mode='balanced')
        canonicals = {item['canonical'] for item in candidates}

        self.assertGreaterEqual(len(canonicals), 2)

    def test_target_matching_with_obfuscation(self):
        line = 'hxxps://stage[.]ivsanbernard[.]it/login:admin:StrongPass1'
        candidates = extract_credentials_from_line(line, mode='balanced')
        target_context = build_target_context('stage.ivsanbernard.it')

        self.assertTrue(candidates)
        self.assertTrue(candidate_mentions_target(candidates[0], line, target_context))

    def test_target_matching_with_punycode(self):
        line = 'http://xn--mnich-kva.com/login:admin:StrongPass1'
        candidates = extract_credentials_from_line(line, mode='balanced')
        target_context = build_target_context('münich.com')

        self.assertTrue(candidates)
        self.assertTrue(candidate_mentions_target(candidates[0], line, target_context))

    def test_mode_difference_strict_vs_aggressive(self):
        line = 'stage.ivsanbernard.it ; admin ; abc123'

        strict_candidates = [
            item
            for item in extract_credentials_from_line(line, mode='strict')
            if item['confidence'] >= EXTRACTION_MODES['strict']['min_confidence']
        ]
        aggressive_candidates = [
            item
            for item in extract_credentials_from_line(line, mode='aggressive')
            if item['confidence'] >= EXTRACTION_MODES['aggressive']['min_confidence']
        ]

        self.assertEqual(strict_candidates, [])
        self.assertTrue(aggressive_candidates)


if __name__ == '__main__':
    unittest.main()
