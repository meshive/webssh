import asyncio
import json
import socket
import threading
from http.cookies import SimpleCookie
from unittest.mock import patch
from urllib.parse import urlencode

from tornado import websocket
from tornado.httpclient import HTTPError, HTTPRequest
from tornado.locks import Event
from tornado.options import options
from tornado.testing import AsyncHTTPTestCase, gen_test

from webssh.handler import IndexHandler
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings, get_server_settings
from webssh.worker import Worker


POST_IP = '192.0.2.10'
WEBSOCKET_IP = '192.0.2.20'
BANNER = b'Meshive SSH test shell\n'


def forwarded_headers(ip, scheme, x_scheme):
    headers = {'X-Real-Ip': ip, 'X-Forwarded-Proto': scheme}
    if x_scheme is not None:
        headers['X-Scheme'] = x_scheme
    return headers


class TestWebsocketAttachment(AsyncHTTPTestCase):
    def setUp(self):
        self.workers = []
        self.peers = {}
        self.dial_targets = []
        self.dial_started = Event()
        self.release_dial = threading.Event()
        self.release_dial.set()

        settings = dict(debug=False, delay=2.0, maxconn=3, policy='warning',
                        hostfile='', syshostfile='', tdstream='', origin='same',
                        xheaders=True, xsrf=True)
        for name, value in settings.items():
            previous_value = getattr(options, name)
            if name == 'delay':
                previous_value = float(previous_value)
            self.addCleanup(setattr, options, name, previous_value)
            setattr(options, name, value)

        dial = patch.object(IndexHandler, 'ssh_connect', autospec=True,
                            side_effect=self.ssh_connect)
        dial.start()
        self.addCleanup(dial.stop)
        super().setUp()

    def tearDown(self):
        self.release_dial.set()
        try:
            for worker in self.workers:
                worker.close(reason='test finished')
        finally:
            for peer in self.peers.values():
                peer.close()
            super().tearDown()

    def get_app(self):
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def get_httpserver_options(self):
        return get_server_settings(options)

    def ssh_connect(self, index_handler, args):
        self.dial_targets.append(args[:2])
        if args[3] != 'test-password':
            raise ValueError('Authentication failed.')
        if not self.release_dial.is_set():
            self.io_loop.add_callback(self.dial_started.set)
            if not self.release_dial.wait(3):
                raise ValueError('Test SSH connection timed out.')

        channel, peer = socket.socketpair()
        peer.setblocking(False)
        worker = Worker(index_handler.loop, channel, channel, args[:2])
        worker.encoding = 'utf-8'
        self.workers.append(worker)
        self.peers[worker.id] = peer
        peer.sendall(BANNER)
        return worker

    async def post(self, password='test-password', ip=POST_IP, scheme='https',
                   x_scheme=None):
        body = urlencode(dict(hostname='fixture.invalid', port=2200,
                              username='gateway', password=password,
                              _xsrf='fixture'))
        headers = forwarded_headers(ip, scheme, x_scheme)
        headers['Cookie'] = '_xsrf=fixture'
        return await self.http_client.fetch(
            self.get_url('/'), method='POST', body=body, headers=headers,
            raise_error=False, request_timeout=4)

    def credentials(self, response):
        self.assertEqual(response.code, 200)
        data = json.loads(response.body)
        worker_id = data['id']
        self.assertTrue(worker_id)
        self.assertEqual(data, dict(id=worker_id, status=None, encoding='utf-8'))
        cookies = SimpleCookie()
        for header in response.headers.get_list('Set-Cookie'):
            cookies.load(header)
        cookie = cookies['__Host-meshive-ws-' + worker_id]
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'].lower(), 'strict')
        self.assertEqual(cookie['path'], '/')
        self.assertFalse(cookie['domain'])
        self.assertGreater(int(cookie['max-age']), 0)
        self.assertNotEqual(cookie.value, worker_id)
        self.assertNotIn(cookie.value.encode(), response.body)
        return worker_id, f'{cookie.key}={cookie.value}'

    async def open(self, worker_id, cookie=None, ip=WEBSOCKET_IP, origin=None,
                   scheme='https', x_scheme=None):
        origin_scheme = {'ws': 'http', 'wss': 'https'}.get(scheme, scheme)
        default_origin = self.get_url('/').rstrip('/').replace(
            'http:', origin_scheme + ':', 1)
        headers = forwarded_headers(ip, scheme, x_scheme)
        headers['Origin'] = origin or default_origin
        if cookie:
            headers['Cookie'] = cookie
        url = self.get_url('/ws?' + urlencode({'id': worker_id}))
        request = HTTPRequest(url.replace('http', 'ws', 1), headers=headers,
                              request_timeout=4)
        return await websocket.websocket_connect(request)

    async def assert_rejected(self, worker_id, cookie=None, **request_options):
        connection = await self.open(worker_id, cookie, **request_options)
        try:
            self.assertIsNone(await connection.read_message())
            self.assertTrue(connection.close_reason)
        finally:
            connection.close()

    async def wait_until_ssh_closed(self, worker_id):
        peer = self.peers[worker_id]
        try:
            received = await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(peer, 1), timeout=2)
        except ConnectionResetError:
            # Closing a pending socket with unread shell output can reset it.
            return
        self.assertEqual(received, b'')

    @gen_test
    async def test_cookie_attaches_across_ip_change_only_once(self):
        worker_id, cookie = self.credentials(await self.post())
        self.assertEqual(self.dial_targets, [('127.0.0.1', 2222)])

        await self.assert_rejected(worker_id, ip=POST_IP)
        wrong_cookie = cookie.split('=', 1)[0] + '=wrong'
        await self.assert_rejected(worker_id, wrong_cookie, ip=POST_IP)
        with self.assertRaises(HTTPError) as denied:
            await self.open(worker_id, cookie, origin='https://other.example')
        self.assertEqual(denied.exception.code, 403)

        connection = await self.open(worker_id, cookie)
        self.assertEqual(await connection.read_message(), BANNER)
        await self.assert_rejected(worker_id, cookie)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

    @gen_test
    async def test_plaintext_compatibility_requires_same_ip_and_protocol(self):
        response = await self.post(scheme='http')
        self.assertEqual(response.code, 200)
        worker_id = json.loads(response.body)['id']
        self.assertTrue(worker_id)
        self.assertFalse(response.headers.get_list('Set-Cookie'))

        await self.assert_rejected(worker_id, scheme='ws')
        await self.assert_rejected(worker_id, ip=POST_IP)
        connection = await self.open(worker_id, ip=POST_IP, scheme='ws')
        self.assertEqual(await connection.read_message(), BANNER)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

        worker_id, cookie = self.credentials(await self.post())
        await self.assert_rejected(worker_id, ip=POST_IP, scheme='http')
        await self.assert_rejected(worker_id, cookie, ip=POST_IP, scheme='http')
        connection = await self.open(worker_id, cookie)
        self.assertEqual(await connection.read_message(), BANNER)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

    @gen_test
    async def test_forwarded_https_cannot_be_downgraded_by_x_scheme_header(self):
        worker_id, cookie = self.credentials(await self.post(x_scheme='http'))
        await self.assert_rejected(worker_id, ip=POST_IP, x_scheme='http')
        connection = await self.open(worker_id, cookie, x_scheme='http')
        self.assertEqual(await connection.read_message(), BANNER)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

    @gen_test
    async def test_traefik_forwarded_wss_attaches_across_ip_change(self):
        worker_id, cookie = self.credentials(await self.post())
        await self.assert_rejected(worker_id, ip=POST_IP, scheme='wss')
        await self.assert_rejected(worker_id, cookie, ip=POST_IP, scheme='ws')

        connection = await self.open(worker_id, cookie, scheme='wss')
        self.assertEqual(await connection.read_message(), BANNER)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

    @gen_test
    async def test_expiry_closes_ssh_and_releases_connection_quota(self):
        options.maxconn = 1
        options.delay = 0.1
        worker_id, cookie = self.credentials(await self.post())
        await self.wait_until_ssh_closed(worker_id)
        await self.assert_rejected(worker_id, cookie)

        options.delay = 2.0
        next_id, next_cookie = self.credentials(await self.post())
        connection = await self.open(next_id, next_cookie)
        self.assertEqual(await connection.read_message(), BANNER)
        connection.close()
        await self.wait_until_ssh_closed(next_id)

    @gen_test
    async def test_parallel_posts_get_independent_cookies(self):
        responses = await asyncio.gather(self.post(), self.post())
        first_id, first_cookie = self.credentials(responses[0])
        second_id, second_cookie = self.credentials(responses[1])
        self.assertNotEqual(first_id, second_id)
        self.assertNotEqual(first_cookie.split('=', 1)[1],
                            second_cookie.split('=', 1)[1])
        await self.assert_rejected(first_id, second_cookie)

        browser_cookies = first_cookie + '; ' + second_cookie
        for worker_id in (first_id, second_id):
            connection = await self.open(worker_id, browser_cookies)
            self.assertEqual(await connection.read_message(), BANNER)
            connection.close()
            await self.wait_until_ssh_closed(worker_id)

    @gen_test
    async def test_inflight_and_attached_workers_both_count_toward_post_ip_quota(self):
        options.maxconn = 1
        self.release_dial.clear()
        first_request = asyncio.create_task(self.post())
        await asyncio.wait_for(self.dial_started.wait(), timeout=2)
        try:
            second_response = await self.post()
            self.assertIn(b'Too many live connections', second_response.body)
            self.assertEqual(len(self.dial_targets), 1)
        finally:
            self.release_dial.set()
            first_response = await first_request

        worker_id, cookie = self.credentials(first_response)
        connection = await self.open(worker_id, cookie)
        self.assertEqual(await connection.read_message(), BANNER)
        blocked = await self.post()
        self.assertIn(b'Too many live connections', blocked.body)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)

        next_id, next_cookie = self.credentials(await self.post())
        next_connection = await self.open(next_id, next_cookie)
        next_connection.close()
        await self.wait_until_ssh_closed(next_id)

    @gen_test
    async def test_ssh_authentication_failure_releases_quota_without_setting_cookie(self):
        options.maxconn = 1
        failure = await self.post(password='invalid')
        self.assertEqual(json.loads(failure.body),
                         dict(id=None, status='Authentication failed.', encoding=None))
        self.assertFalse(failure.headers.get_list('Set-Cookie'))

        worker_id, cookie = self.credentials(await self.post())
        connection = await self.open(worker_id, cookie)
        connection.close()
        await self.wait_until_ssh_closed(worker_id)
