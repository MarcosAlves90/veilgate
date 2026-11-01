import unittest
import tempfile
from pathlib import Path

from veilgate.privacy import RejectedInput, Sanitizer, sanitize_request
from veilgate.server import read_private_terms, validate_upstream


class PrivacyTests(unittest.TestCase):
    def test_common_identifiers(self):
        sanitizer = Sanitizer()
        raw = 'joao@example.com CPF 529.982.247-25 CNPJ 04.252.011/0001-10 fone (11) 98765-4321 /Users/marcos/Documents'
        clean = sanitizer.clean(raw)
        for text in ('joao@example.com', '529.982.247-25', '04.252.011/0001-10', '98765-4321', '/Users/marcos'):
            self.assertNotIn(text, clean)
        self.assertIn('[REDACTED_EMAIL_1]', clean)
        self.assertIn('[REDACTED_CPF_1]', clean)
        self.assertIn('[REDACTED_CNPJ_1]', clean)
        self.assertIn('[REDACTED_PHONE_1]', clean)
        self.assertIn('/Users/[REDACTED_USER_1]', clean)

    def test_repeated_values_are_consistent_within_request(self):
        sanitized = Sanitizer().clean('a@example.com then a@example.com')
        self.assertEqual(sanitized.count('[REDACTED_EMAIL_1]'), 2)

    def test_invalid_cpf_is_not_masked(self):
        self.assertIn('123.456.789-00', Sanitizer().clean('123.456.789-00'))

    def test_custom_terms_case_insensitive(self):
        s = Sanitizer(private_terms=('Projeto Arara',))
        self.assertEqual(s.clean('PROJETO ARARA'), '[REDACTED_CUSTOM_1]')

    def test_secrets_blocked(self):
        for text in ('ghp_' + 'a' * 30, 'sk-' + 'a' * 25,
                     'password=superSecretValue999', '-----BEGIN PRIVATE KEY-----'):
            with self.subTest(text=text[:8]), self.assertRaises(RejectedInput):
                Sanitizer().clean(text)

    def test_nested_messages_and_tool_arguments(self):
        payload = {
            'model': 'auto',
            'messages': [
                {'role': 'user', 'content': [{'type': 'text', 'text': 'email me at a@example.com'}]},
                {'role': 'assistant', 'tool_calls': [{'id': 'call_1', 'type': 'function', 'function': {'name': 'search', 'arguments': '{"query":"a@example.com"}'}}]},
            ],
            'tools': [{'type': 'function', 'function': {'name': 'search', 'description': 'Look up a@example.com', 'parameters': {'type': 'object'}}}],
            'stream': True,
        }
        result = sanitize_request(payload, Sanitizer())
        self.assertNotIn('a@example.com', str(result))
        self.assertEqual(result['stream'], True)
        self.assertEqual(result['tools'][0]['function']['name'], 'search')

    def test_unknown_top_level_rejected(self):
        with self.assertRaises(RejectedInput):
            sanitize_request({'model': 'auto', 'messages': [{'role': 'user', 'content': 'hi'}], 'image': 'x'}, Sanitizer())

    def test_multimodal_rejected(self):
        with self.assertRaises(RejectedInput):
            sanitize_request({'model': 'auto', 'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': {'url': 'data:abc'}}]}]}, Sanitizer())

    def test_structural_identifiers_with_pii_rejected(self):
        with self.assertRaises(RejectedInput):
            sanitize_request({'model': 'a@example.com', 'messages': [{'role': 'user', 'content': 'hi'}]}, Sanitizer())

    def test_local_only_upstream(self):
        self.assertEqual(validate_upstream('http://127.0.0.1:3001'), ('127.0.0.1', 3001))
        for uri in ('https://127.0.0.1:3001', 'http://google.com', 'http://127.0.0.1:3001/foo', 'http://127.0.0.1:3001@evil.com', 'http://127.0.0.1:3001?x=y'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                validate_upstream(uri)

    def test_invalid_private_terms_fail_before_proxy_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'terms.txt'
            path.write_text('# comment\nPRIVATE PROJECT\n', encoding='utf-8')
            self.assertEqual(read_private_terms(str(path)), ('PRIVATE PROJECT',))
            path.write_text('ab\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                read_private_terms(str(path))
        self.assertEqual(read_private_terms(None), ())
        with self.assertRaises(FileNotFoundError):
            read_private_terms(str(path))

    def test_invalid_input_structures_rejected(self):
        base = {'model': 'auto', 'messages': [{'role': 'user', 'content': 'hi'}]}
        cases = [
            None,
            [],
            {'model': '', 'messages': base['messages']},
            {'model': 'auto', 'messages': []},
            {'model': 'auto', 'messages': 'hi'},
            {**base, 'stream': 'true'},
            {'model': 'auto', 'messages': ['text']},
            {'model': 'auto', 'messages': [{'role': 'unknown', 'content': 'hi'}]},
            {'model': 'auto', 'messages': [{'role': 'user', 'content': 12}]},
            {'model': 'auto', 'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 12}]}]},
            {**base, 'metadata': {'a@example.com': 'value'}},
            {**base, 'metadata': {'image_url': {'url': 'data:image/jpeg'}}},
            {**base, 'metadata': {'safe': object()}},
        ]
        for payload in cases:
            with self.subTest(payload=repr(payload)), self.assertRaises(RejectedInput):
                sanitize_request(payload, Sanitizer())

    def test_nested_secret_blocked_even_in_tool_arguments(self):
        payload = {'model': 'auto', 'messages': [{'role': 'assistant', 'content': None,
            'tool_calls': [{'type': 'function', 'function': {'name': 'lookup',
                'arguments': 'password=superSecretValue999'}}]}]}
        with self.assertRaises(RejectedInput):
            sanitize_request(payload, Sanitizer())

    def test_deep_payload_rejected(self):
        nested = 'hi'
        for _ in range(40):
            nested = [nested]
        with self.assertRaises(RejectedInput):
            sanitize_request({'model': 'auto', 'messages': [{'role': 'user', 'content': 'hi'}],
                              'metadata': {'nested': nested}}, Sanitizer())

    def test_unicode_and_custom_term_masking(self):
        sanitizer = Sanitizer(private_terms=('Projeto Arara', 'Arara'))
        text = sanitizer.clean('Projeto Arara, projeto arara, a@example.com')
        self.assertEqual(text.count('[REDACTED_CUSTOM_1]'), 2)
        self.assertNotIn('a@example.com', text)


if __name__ == '__main__':
    unittest.main()
