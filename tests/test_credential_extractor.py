import unittest

from custom.credential_extractor import (
    EXTRACTION_MODES,
    build_person_email_context,
    build_search_terms,
    build_target_context,
    candidate_mentions_person_email,
    candidate_mentions_target,
    extract_credentials_from_line,
    is_email_target,
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

    def test_email_target_search_terms_include_person_variants(self):
        terms = build_search_terms(
            'john.doe@example.com',
            include_email_pattern=True,
            person_name='John Doe',
        )
        lowered_terms = {item.lower() for item in terms}

        self.assertIn('john.doe@example.com', lowered_terms)
        self.assertIn('@example.com', lowered_terms)
        self.assertIn('john doe', lowered_terms)
        self.assertNotIn('john.doe', lowered_terms)

    def test_email_target_default_uses_exact_email_only(self):
        terms = build_search_terms('info@example.it', include_email_pattern=False, person_name=None)
        self.assertEqual(terms, ['info@example.it'])

    def test_malformed_ipv6_url_in_kv_does_not_raise(self):
        line = 'url=http://[2001:db8::1 user=admin password=Pass123!'

        try:
            candidates = extract_credentials_from_line(line, mode='aggressive')
        except ValueError as exc:
            self.fail(f'extract_credentials_from_line raised ValueError: {exc}')

        self.assertTrue(candidates)
        self.assertTrue(any(item['url'].startswith('http://[2001') for item in candidates))

    def test_person_email_matching_is_not_domain_only(self):
        context = build_person_email_context('john.doe@example.com')

        non_matching_candidate = {
            'identity': 'random.user@example.com',
            'url': 'example.com/login',
            'canonical': 'example.com/login:random.user@example.com:Pass123!',
        }
        matching_candidate = {
            'identity': 'john.doe@example.com',
            'url': 'example.com/login',
            'canonical': 'example.com/login:john.doe@example.com:Pass123!',
        }

        self.assertTrue(is_email_target('john.doe@example.com'))
        self.assertFalse(candidate_mentions_person_email(non_matching_candidate, non_matching_candidate['canonical'], context))
        self.assertTrue(candidate_mentions_person_email(matching_candidate, matching_candidate['canonical'], context))


if __name__ == '__main__':
    unittest.main()
