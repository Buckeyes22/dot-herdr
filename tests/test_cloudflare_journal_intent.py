import asyncio
import json
import subprocess
import unittest
from unittest.mock import patch

from dot_herdr import cloudflare as cf
from dot_herdr.core import Rejected
import test_cloudflare as fixtures


class Crash(BaseException):
    pass


class JournalIntentTests(unittest.TestCase):
    setUp = fixtures.CloudflareTests.setUp
    journal_value = fixtures.CloudflareTests.journal_value

    def expose(self, api):
        return asyncio.run(cf.expose_api(self.config, 'herdr.example.com', 8000, 'x', api=api))

    def login_run(self, args, **kwargs):
        if 'list' in args:
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(self.login_tunnels))
        if 'create' in args:
            self.login_tunnels.append({'id': self.tid, 'name': args[-1]})
            self.creds.write_text('{}')
            if self.crash_create:
                raise Crash()
            return subprocess.CompletedProcess(args, 0, stdout='Created tunnel ' + self.tid)
        return subprocess.CompletedProcess(args, 0, stdout='')

    def login_setup(self):
        self.tid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.creds = self.home / '.cloudflared' / (self.tid + '.json')
        self.creds.parent.mkdir(parents=True)
        (self.creds.parent / 'cert.pem').write_text('cert')
        self.login_tunnels = []
        self.crash_create = True

    def login(self, run=None):
        return cf.expose_login(self.config, 'herdr.example.com', 8000,
                               cloudflared=str(self.binary), home=self.home,
                               run=run or self.login_run, say=lambda _: None)

    def test_F1_api_lost_create_response_resumes(self):
        fake = fixtures.FakeCloudflare()
        api = fake.api()
        create = api.create_tunnel
        async def lost(*args):
            await create(*args)
            raise Crash()
        with patch.object(api, 'create_tunnel', side_effect=lost), self.assertRaises(Crash):
            self.expose(api)
        self.assertIsNotNone(cf.Journal(self.config).read())
        self.expose(api)
        self.assertEqual(len(fake.tunnels), 1)

    def test_F1_login_lost_create_response_resumes(self):
        self.login_setup()
        with self.assertRaises(Crash):
            self.login()
        self.assertIsNotNone(cf.Journal(self.config, home=self.home).read())
        self.crash_create = False
        self.login()
        self.assertEqual(len(self.login_tunnels), 1)

    def test_F1_pending_api_create_can_be_removed(self):
        fake = fixtures.FakeCloudflare()
        api = fake.api()
        create = api.create_tunnel
        async def lost(*args):
            await create(*args)
            raise Crash()
        with patch.object(api, 'create_tunnel', side_effect=lost), self.assertRaises(Crash):
            self.expose(api)
        asyncio.run(cf.remove(self.config, api=api))
        self.assertEqual(fake.tunnels, [])
        self.assertIsNone(cf.Journal(self.config).read())

    def test_F2_api_lost_dns_response_resumes(self):
        fake = fixtures.FakeCloudflare()
        value = self.journal_value()
        fake.tunnels.append(value['tunnel'])
        cf.Journal(self.config).write(value)
        api = fake.api()
        create = api.create_dns
        async def lost(*args):
            await create(*args)
            raise Crash()
        with patch.object(api, 'create_dns', side_effect=lost), self.assertRaises(Crash):
            self.expose(api)
        self.expose(api)
        self.assertEqual(len(fake.dns), 1)

    def test_F2_api_lost_dns_response_remove_cleans_owned_only(self):
        fake = fixtures.FakeCloudflare()
        value = self.journal_value()
        fake.tunnels.append(value['tunnel'])
        cf.Journal(self.config).write(value)
        api = fake.api()
        create = api.create_dns
        async def lost(*args):
            await create(*args)
            raise Crash()
        with patch.object(api, 'create_dns', side_effect=lost), self.assertRaises(Crash):
            self.expose(api)
        foreign = {'id': 'foreign', 'name': value['hostname'], 'type': 'CNAME', 'content': 'foreign'}
        fake.dns.append(foreign)
        asyncio.run(cf.remove(self.config, api=api))
        self.assertEqual(fake.dns, [foreign])

    def test_F2_login_route_interruption_preserves_cleanup_evidence(self):
        self.login_setup()
        self.crash_create = False
        fake = fixtures.FakeCloudflare()
        def lost(args, **kwargs):
            if 'route' in args:
                fake.dns.append({'id': 'owned', 'name': args[-1], 'type': 'CNAME',
                                 'content': args[-2] + '.cfargotunnel.com'})
                raise Crash()
            return self.login_run(args, **kwargs)
        with self.assertRaises(Crash):
            self.login(lost)
        journal = cf.Journal(self.config, home=self.home)
        self.assertIsNotNone(journal.read())
        asyncio.run(cf.remove(self.config, api=fake.api(), run=self.login_run,
                              home=self.home, say=lambda _: None))
        self.assertEqual(fake.dns, [])
        self.assertIsNone(journal.read())

    def test_F3_login_deleted_before_journal_commit_finishes_cleanup(self):
        self.login_setup()
        self.crash_create = False
        self.login()
        journal = cf.Journal(self.config, home=self.home)
        value = journal.read()
        value['dns'] = None
        journal.write(value)
        deleted = []
        def crash_delete(args, **kwargs):
            if 'delete' in args:
                deleted.append(args[-1])
                self.login_tunnels.clear()
                raise Crash()
            return self.login_run(args, **kwargs)
        with self.assertRaises(Crash):
            asyncio.run(cf.remove(self.config, run=crash_delete, home=self.home))
        self.assertFalse(journal.read()['tunnel_removed'])
        asyncio.run(cf.remove(self.config, run=self.login_run, home=self.home, say=lambda _: None))
        self.assertEqual(deleted, [self.tid])
        self.assertIsNone(journal.read())
        self.assertFalse(self.creds.exists())
        self.assertFalse((self.base / 'cloudflare' / 'config.yml').exists())

    def test_F1_pending_tunnel_refuses_ambiguous_names(self):
        fake = fixtures.FakeCloudflare()
        journal = cf.Journal(self.config)
        zone = {'id': 'zone1', 'name': 'example.com', 'account_id': 'acct1'}
        value = cf._record(journal, 'api', 'herdr.example.com', None, str(self.binary), zone=zone)
        journal.write(value)
        fake.tunnels = [dict(value['tunnel'], id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
                        dict(value['tunnel'], id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')]
        before = journal.path.read_bytes()
        with self.assertRaisesRegex(Rejected, 'cloudflare_tunnel_ownership_unavailable'):
            self.expose(fake.api())
        self.assertEqual(journal.path.read_bytes(), before)
        self.assertFalse(any(method != 'GET' for method, _, _ in fake.calls))

    def test_F2_login_dns_commit_gap_resumes_without_overwriting_foreign(self):
        self.login_setup()
        self.crash_create = False
        routes = []
        def route(args, **kwargs):
            if 'route' in args:
                target = args[-2] + '.cfargotunnel.com'
                if routes and routes[0] != target:
                    return subprocess.CompletedProcess(args, 1, stdout='conflicting DNS')
                if not routes:
                    routes.append(target)
            return self.login_run(args, **kwargs)
        write = cf.Journal.write
        def crash_commit(journal, value):
            if value['phase'] == 'dns_routed':
                raise Crash()
            write(journal, value)
        with patch.object(cf.Journal, 'write', crash_commit), self.assertRaises(Crash):
            self.login(route)
        self.assertEqual(cf.Journal(self.config).read()['phase'], 'dns_pending')
        self.login(route)
        self.assertEqual(routes, [self.tid + '.cfargotunnel.com'])
        value = cf.Journal(self.config).read()
        value['phase'] = 'dns_pending'
        value['dns'] = None
        cf.Journal(self.config).write(value)
        routes[:] = ['foreign.cfargotunnel.com']
        with self.assertRaises(Rejected):
            self.login(route)
        self.assertEqual(routes, ['foreign.cfargotunnel.com'])
        self.assertEqual(cf.Journal(self.config).read()['phase'], 'dns_pending')

    def test_F3_pending_delete_rejects_incomplete_listing(self):
        self.login_setup()
        value = self.journal_value('login', tid=self.tid, home=self.home)
        value['deletion_pending'] = True
        journal = cf.Journal(self.config, home=self.home)
        journal.write(value)
        before = journal.path.read_bytes()
        for output, rc in (('not json', 0), ('[{}]', 0), ('{}', 0), ('[]', 1)):
            calls = []
            def invalid(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, rc, stdout=output)
            with self.subTest(output=output, rc=rc), self.assertRaises(Rejected):
                asyncio.run(cf.remove(self.config, run=invalid, home=self.home))
            self.assertEqual(journal.path.read_bytes(), before)
            self.assertFalse(any('delete' in args for args in calls))

    def test_F3_delete_commit_gap_retains_pending_dns_until_api_cleanup(self):
        self.login_setup()
        self.crash_create = False
        self.login()
        journal = cf.Journal(self.config, home=self.home)
        value = journal.read()
        value['phase'] = 'dns_pending'
        value['dns'] = None
        journal.write(value)
        write = cf.Journal.write
        def crash_commit(journal, value):
            if value['tunnel_removed']:
                raise Crash()
            write(journal, value)
        def deleted(args, **kwargs):
            if 'delete' in args:
                self.login_tunnels.clear()
            return self.login_run(args, **kwargs)
        with patch.object(cf.Journal, 'write', crash_commit), self.assertRaises(Crash):
            asyncio.run(cf.remove(self.config, run=deleted, home=self.home, say=lambda _: None))
        asyncio.run(cf.remove(self.config, run=deleted, home=self.home, say=lambda _: None))
        self.assertTrue(journal.read()['tunnel_removed'])
        self.assertIsNotNone(journal.read()['dns'])
        self.assertFalse(self.creds.exists())
        fake = fixtures.FakeCloudflare()
        fake.dns.append({'id': 'owned', 'name': 'herdr.example.com', 'type': 'CNAME',
                         'content': self.tid + '.cfargotunnel.com'})
        asyncio.run(cf.remove(self.config, api=fake.api(), run=deleted, home=self.home, say=lambda _: None))
        self.assertEqual(fake.dns, [])
        self.assertIsNone(journal.read())
