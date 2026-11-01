import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from veilgate.server import handler_factory


class MockUpstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.captured.append((self.path, {}, b''))
        data = b'{"data":[]}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        self.server.captured.append((self.path, dict(self.headers), data))
        body = json.loads(data)
        if body.get('stream'):
            response = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\ndata: [DONE]\n\n'
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        else:
            response = b'{"choices":[{"message":{"content":"ok"}}]}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)


def start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(('127.0.0.1', 0), MockUpstream)
        cls.upstream.captured = []
        cls.t1 = start(cls.upstream)
        cls.proxy = ThreadingHTTPServer(('127.0.0.1', 0), handler_factory(('127.0.0.1', cls.upstream.server_port), ('Projeto Secreto',)))
        cls.t2 = start(cls.proxy)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.upstream.shutdown()
        cls.proxy.server_close()
        cls.upstream.server_close()
        cls.t1.join(timeout=3)
        cls.t2.join(timeout=3)

    def post(self, payload, headers=None):
        con = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=5)
        data = json.dumps(payload).encode()
        con.request('POST', '/v1/chat/completions', body=data, headers={'Content-Type': 'application/json', 'Authorization': 'Bearer freellmapi-test-key', 'X-Personal-Trace': 'private-info', **(headers or {})})
        resp = con.getresponse()
        content = resp.read()
        status, ctype = resp.status, resp.getheader('Content-Type')
        con.close()
        return status, ctype, content

    def test_health(self):
        con = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port)
        con.request('GET', '/healthz')
        resp = con.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.read())['status'], 'ok')
        con.close()

    def test_outbound_scrub_with_credentials_forwarded_only_locally(self):
        before = len(self.upstream.captured)
        status, _, response = self.post({'model': 'auto', 'messages': [
            {'role': 'system', 'content': 'Projeto Secreto is the codename'},
            {'role': 'user', 'content': 'Contact me joao@example.com and /Users/marcos/private'},
        ]})
        self.assertEqual(status, 200)
        self.assertIn(b'ok', response)
        self.assertEqual(len(self.upstream.captured), before + 1)
        route, headers, outbound = self.upstream.captured[-1]
        self.assertEqual(route, '/v1/chat/completions')
        self.assertEqual(headers['Authorization'], 'Bearer freellmapi-test-key')
        self.assertNotIn('X-Personal-Trace', headers)
        for sensitive in (b'joao@example.com', b'marcos', b'Projeto Secreto'):
            self.assertNotIn(sensitive, outbound)
        self.assertIn(b'[REDACTED_EMAIL_1]', outbound)

    def test_secret_blocks_without_upstream_call(self):
        before = len(self.upstream.captured)
        status, _, _ = self.post({'model': 'auto', 'messages': [{'role': 'user', 'content': 'my token ghp_' + 'a' * 35}]})
        self.assertEqual(status, 422)
        self.assertEqual(before, len(self.upstream.captured))

    def test_stream_pass_through(self):
        status, ctype, data = self.post({'model': 'auto', 'stream': True, 'messages': [{'role': 'user', 'content': 'hi a@example.com'}]})
        self.assertEqual((status, ctype), (200, 'text/event-stream'))
        self.assertIn(b'data: [DONE]', data)
        self.assertNotIn(b'a@example.com', self.upstream.captured[-1][2])

    def test_unsupported_media_blocks(self):
        before = len(self.upstream.captured)
        status, _, _ = self.post({'model': 'auto', 'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': {'url': 'data:abcd'}}]}]})
        self.assertEqual(status, 422)
        self.assertEqual(len(self.upstream.captured), before)

    def test_unknown_endpoint_blocks(self):
        con = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port)
        con.request('POST', '/v1/responses', '{}', headers={'Content-Type': 'application/json'})
        resp = con.getresponse()
        self.assertEqual(resp.status, 404)
        resp.read()
        con.close()

    def test_models_list(self):
        con = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port)
        con.request('GET', '/v1/models')
        resp = con.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.read()), {'data': []})
        con.close()


if __name__ == '__main__':
    unittest.main()
