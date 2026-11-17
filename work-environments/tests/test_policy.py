#!/usr/bin/env python3
import hashlib, importlib.machinery, importlib.util, io, json, os, pathlib, re, subprocess, sys, unicodedata, unittest, tempfile
from unittest.mock import patch, Mock

path = pathlib.Path(__file__).resolve().parents[1] / 'bin/nc-work'
loader = importlib.machinery.SourceFileLoader('launcher', str(path))
spec = importlib.util.spec_from_loader('launcher', loader)
mod = importlib.util.module_from_spec(spec); loader.exec_module(mod)
# Never the owner's real ~/.nc/overlay: the tests see only the fixture profiles and no overlay unless a test sets one.
FIXTURES = pathlib.Path(__file__).resolve().parent / 'fixtures'
mod.OVERLAY = FIXTURES / 'no-overlay'
mod.PROFILE_DIRS = (FIXTURES / 'profiles',)

_NO = object()

def policy_json(deny=(), standard='openrouter/acme/big-1', cheap='openrouter/acme/small-1', standard_allowed=True, cheap_allowed=True, require=_NO):
    """Stdout of `nc models --json --path …` as far as nc-work reads it (synthetic models). Without `require` the
    output of an older harness."""
    policy = {'path': '/x', 'match': '**', 'deny_classes': list(deny)}
    if require is not _NO: policy['require'] = require
    return json.dumps({'policy': policy,
                       'classes': {'standard': {'runtime': 'opencode', 'model': standard, 'allowed': standard_allowed},
                                   'cheap': {'runtime': 'opencode', 'model': cheap, 'allowed': cheap_allowed},
                                   'free': {'runtime': 'opencode', 'model': 'openrouter/acme/tiny-1:free', 'allowed': 'free' not in deny}}}).encode()

def is_policy_call(cmd):
    return list(cmd[1:4]) == ['models', '--json', '--path'] and str(cmd[0]).endswith('/bin/nc')

def online(m):
    """A task record with the network and egress proxy that create gives every task without --offline."""
    return {'network': 'ncw-' + m['id'], 'proxy': 'ncw-' + m['id'] + '-egress', **m}

class KeyProxyFakes:
    """Stand-ins for the key proxy in tests about something else: never a real docker run. started holds
    (task, key, run id) per start, events the order of start, wait, stop and sweep."""
    def __init__(self, test):
        self.started, self.events = [], []
        def start(m, key, run_id, started):
            self.started.append((m['id'], key, run_id)); self.events.append('start'); started.append(Mock()); return started[-1]
        for name, fn in [('keyproxy_start', start), ('keyproxy_wait', lambda *a: self.events.append('wait')),
                         ('keyproxy_stop', lambda *a: self.events.append('stop')),
                         ('keyproxy_sweep', lambda *a, **k: self.events.append(('sweep', a, k))),
                         ('keyproxy_lock', lambda name, run_id: Mock())]:
            patcher = patch.object(mod, name, side_effect=fn); patcher.start(); test.addCleanup(patcher.stop)

class PolicyTests(unittest.TestCase):
    def test_names_cannot_escape_task_namespace(self):
        for name in ['../host', '-v', 'a/b', '$(id)', 'a b', 'main:main', 'a'*41]:
            with self.assertRaises(ValueError): mod.valid(name)
        self.assertEqual(mod.valid('acme-task-2'), 'acme-task-2')

    def test_proxy_targets_are_literal_dns_names(self):
        for target in ['*', '.supabase.co', 'foo\nhttp_access allow all', 'https://x.com', 'x.com:443']:
            with self.assertRaises(ValueError): mod.proxy_config([target], own=['192.0.2.1/32'])

    def test_private_targets_denied_before_allowlist(self):
        config = mod.proxy_config(['registry.npmjs.org'], own=['192.0.2.1/32', '2001:db8:1::/64'])
        self.assertLess(config.index('http_access deny blocked_dst'), config.index('http_access allow allowed_domains'))
        self.assertIn('100.64.0.0/10', config)
        self.assertIn('acl this_server dst 192.0.2.1/32 2001:db8:1::/64\n', config)
        self.assertLess(config.index('http_access deny this_server'), config.index('http_access allow allowed_domains'))
        self.assertTrue(config.rstrip().endswith('via off'))

    def test_own_addresses_come_from_ip_not_from_the_code(self):
        source = path.read_text()
        self.assertNotRegex(source, r'acl this_server dst \d')  # no fixed address left in the config
        # public example addresses: documentation ranges (192.0.2.0/24, 2001:db8::/32) are not is_global
        ip_json = json.dumps([
            {'ifname': 'lo', 'addr_info': []},
            {'ifname': 'eth0', 'addr_info': [
                {'family': 'inet', 'local': '81.2.69.142', 'prefixlen': 22},
                {'family': 'inet6', 'local': '2a00:1450:4001:80b:e8e7:d6ff:fef6:38d6', 'prefixlen': 64},
                {'local': '81.2.69.142', 'prefixlen': 22}]},  # duplicate: once
            {'ifname': 'docker0', 'addr_info': [{'local': '172.17.0.1', 'prefixlen': 16}]},      # private: left out
            {'ifname': 'tailscale0', 'addr_info': [{'local': '100.101.102.103', 'prefixlen': 32},
                                                   {'local': 'fd7a:115c:a1e0::1', 'prefixlen': 128}]},
            {'ifname': 'evil', 'addr_info': [
                {'local': '1.2.3.4\nhttp_access allow all', 'prefixlen': 32},  # never reaches squid
                {'local': 'not-an-ip', 'prefixlen': 32}, {'prefixlen': 64}, 'not a dict', None]},
            'not a dict', {'ifname': 'odd', 'addr_info': 'not a list'},
        ])
        self.assertEqual(mod.own_addresses(ip_json), ['81.2.69.142/32', '2a00:1450:4001:80b::/64'])
        with patch.object(mod, 'output', return_value=ip_json):
            self.assertIn('acl this_server dst 81.2.69.142/32 2a00:1450:4001:80b::/64\n', mod.proxy_config(['example.com']))

    def test_own_ipv6_is_never_narrower_than_a_64(self):
        for plen, want in [(128, '2a00:1450:4001:80b::/64'), (56, '2a00:1450:4001:800::/56')]:
            ip_json = json.dumps([{'ifname': 'eth0', 'addr_info': [{'local': '2a00:1450:4001:80b::200e', 'prefixlen': plen}]}])
            self.assertEqual(mod.own_addresses(ip_json), [want])

    def test_no_own_address_means_no_proxy_config(self):
        only_private = json.dumps([  # public address missing (lost lease, NAT): bridges and Tailscale must not count
            {'ifname': 'docker0', 'addr_info': [{'local': '172.17.0.1', 'prefixlen': 16}]},
            {'ifname': 'tailscale0', 'addr_info': [{'local': '100.101.102.103', 'prefixlen': 32}]}])
        for ip_json in ['[]', '[{"ifname": "eth0", "addr_info": []}]', 'not json', '{}', '["x", 1, null]', only_private]:
            with self.assertRaises(ValueError): mod.own_addresses(ip_json)
        with patch.object(mod, 'output', side_effect=FileNotFoundError('ip')):
            with self.assertRaises(ValueError): mod.proxy_config(['example.com'])

    def test_shipped_and_fixture_profiles_have_separate_identity_and_pending_services(self):
        for folder in [mod.ROOT / 'profiles', FIXTURES / 'profiles']:
            with patch.object(mod, 'PROFILE_DIRS', (folder,)):
                profiles = mod.all_profiles()
            self.assertGreaterEqual(len(profiles), 3)
            self.assertEqual(len({p['path'] for p in profiles}), len(profiles))
            for p in profiles:
                self.assertEqual(p['external_services'], [])
                self.assertIn('main', p['protected_branches'])
                self.assertIn('staging', p['protected_branches'])
                self.assertEqual(p['git_allowed_branch_prefix'], 'nc-work/')
                for port in p['preview_ports']: self.assertTrue(1024 <= port <= 65535)


    def test_repository_is_fixed_not_an_arbitrary_transport(self):
        for target in ['https://evil/repo', '../repo', 'org/repo:main', 'org/repo\nother']:
            with self.assertRaises(ValueError): mod.github_remote({'github': target})
        self.assertEqual(mod.github_remote({'github': 'example-org/example-site'}),
                         'git@github.com:example-org/example-site.git')

    def test_claude_token_is_not_in_arguments_or_persistent_container_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp); (state / 'auth').mkdir()
            token = state / 'auth/example.token'; token.write_text('synthetic-test-token'); token.chmod(0o600)
            with patch.object(mod, 'dex'), patch.object(mod, 'STATE', state), patch.object(mod.sys.stdin, 'isatty', return_value=True), patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0)) as call:
                mod.claude({'project': 'example', 'id': 'example-task'})
                args, kwargs = call.call_args
                self.assertNotIn('synthetic-test-token', ' '.join(args[0]))
                self.assertEqual(args[0][:2], ['docker', 'exec'])
                self.assertEqual(kwargs['env']['CLAUDE_CODE_OAUTH_TOKEN'], 'synthetic-test-token')
            token.chmod(0o644)
            with patch.object(mod, 'STATE', state):
                with self.assertRaises(ValueError): mod.claude({'project': 'example', 'id': 'example-task'})

    def test_browser_login_captures_token_and_preserves_old_value_on_failure(self):
        import pty
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp)
            def fake_spawn(argv, master_read):
                master_read(99)
                return 0
            with patch.object(mod, 'STATE', state), patch.object(mod, 'profile'), patch.object(mod.sys.stdin, 'isatty', return_value=True), patch.object(mod.fcntl, 'ioctl'), patch.object(mod.os, 'read', return_value=b"Token: sk-ant-oat01-synthetic-only\r\n"), patch.object(pty, 'spawn', side_effect=fake_spawn):
                mod.auth_login('example')
                token = state / 'auth/example.token'
                self.assertEqual(token.read_text(), 'sk-ant-oat01-synthetic-only')
                self.assertEqual(token.stat().st_mode & 0o777, 0o600)
            with patch.object(mod, 'STATE', state), patch.object(mod, 'profile'), patch.object(mod.sys.stdin, 'isatty', return_value=True), patch.object(pty, 'spawn', return_value=256):
                with self.assertRaises(ValueError): mod.auth_login('example')
                self.assertEqual(token.read_text(), 'sk-ant-oat01-synthetic-only')

    def test_shared_default_future_projects_overrides_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, 'STATE', pathlib.Path(tmp)):
            mod.store_token(None, 'synthetic-shared-one')
            for project in ['example-site', 'example-app', 'future-project']:
                self.assertEqual(mod.token_path_for(project).read_text(), 'synthetic-shared-one')
            mod.store_token('example-app', 'synthetic-own')
            mod.store_token(None, 'synthetic-shared-two')
            self.assertEqual(mod.token_path_for('example-app').read_text(), 'synthetic-own')
            self.assertEqual(mod.token_path_for('future-project').read_text(), 'synthetic-shared-two')
            mod.token_path_for('example-app').chmod(0o644)
            with self.assertRaises(ValueError): mod.token_path_for('example-app')
            with self.assertRaises(ValueError): mod.token_path_for('../escape')

class OpenCodeTests(unittest.TestCase):
    """`nc-work opencode`: the OpenRouter key goes into the OpenCode process only, like the Claude token."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.secrets = pathlib.Path(self.tmp.name) / 'secrets.env'
        for p in [patch.object(mod, 'SECRETS', self.secrets), patch.object(mod, 'STATE', pathlib.Path(self.tmp.name) / 'state')]:
            p.start(); self.addCleanup(p.stop)
        self.kp = KeyProxyFakes(self)

    def key(self):
        """The key the last run handed to its key proxy."""
        return self.kp.started[-1][1]

    def write(self, text, mode=0o600):
        self.secrets.write_text(text); self.secrets.chmod(mode)

    def run_opencode(self, args=(), stdin_tty=False, stdout_tty=False, ready=True, main_effect=None, stdin=False,
                     state='running', reap_code=0, during=None, policy=(0, policy_json(), b''), m=None):
        calls = []
        def fake(cmd, **kw):
            calls.append((cmd, kw))
            if is_policy_call(cmd):
                if isinstance(policy, BaseException): raise policy
                return Mock(returncode=policy[0], stdout=policy[1], stderr=policy[2])
            if cmd[-1] == mod.OPENCODE_READY: return Mock(returncode=0 if ready else 1)
            if '/usr/local/bin/opencode' in cmd:
                if during: during()
                if main_effect: raise main_effect
            if mod.OPENCODE_REAP in cmd: return Mock(returncode=reap_code)
            return Mock(returncode=0)
        with patch.object(mod.sys.stdin, 'isatty', return_value=stdin_tty), \
             patch.object(mod.sys.stdout, 'isatty', return_value=stdout_tty), \
             patch.object(mod, 'container_state', return_value=state), \
             patch.object(mod.subprocess, 'run', side_effect=fake):
            try: mod.opencode(online(m or {'project': 'example-site', 'id': 'site-task'}), args, stdin)
            finally: self.calls = calls
        return self.main()

    def main(self):
        return next((c for c in self.calls if '/usr/local/bin/opencode' in c[0]), (None, None))

    def reaped(self):
        return [c[0] for c in self.calls if mod.OPENCODE_REAP in c[0]]

    def test_key_is_not_in_arguments_or_persistent_container_configuration(self):
        self.write('# comment\nOTHER_SECRET=synthetic-other\nOPENROUTER_API_KEY=sk-or-synthetic-test\n')
        argv, kwargs = self.run_opencode(['run', '--model', 'openrouter/x/y', 'hello'])
        self.assertEqual(argv[:2], ['docker', 'exec'])
        self.assertNotIn('sk-or-synthetic-test', ' '.join(argv))
        self.assertIn('OPENROUTER_API_KEY', argv)                                   # passed by name only
        self.assertEqual(kwargs['env']['OPENROUTER_API_KEY'], 'nc-keyproxy')        # only the placeholder
        self.assertNotIn('sk-or-synthetic-test', ' '.join(kwargs['env'].values()))
        self.assertEqual(self.key(), 'sk-or-synthetic-test')                      # the key goes to the proxy only
        self.assertNotIn('synthetic-other', ' '.join(kwargs['env'].values()))
        self.assertEqual(argv[argv.index('ncw-site-task') + 1:], ['/usr/local/bin/opencode', 'run', '--model', 'openrouter/x/y', 'hello'])
        self.assertNotIn('-i', argv); self.assertNotIn('-it', argv)                 # no input unless asked for

    def test_piped_input_only_on_request(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        argv, _ = self.run_opencode(['run', 'x'], stdin=True)
        self.assertIn('-i', argv); self.assertNotIn('-it', argv)

    def test_stopped_task_is_not_called_missing_opencode_and_gets_no_key(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        with self.assertRaisesRegex(ValueError, 'is not running: nc-work start site-task'): self.run_opencode(state='stopped')
        self.assertEqual(self.main(), (None, None)); self.assertEqual(self.reaped(), []); self.assertEqual(self.kp.started, [])

    def test_ignored_sighup_stays_ignored(self):
        import signal as sg
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        old = sg.signal(sg.SIGHUP, sg.SIG_IGN); self.addCleanup(sg.signal, sg.SIGHUP, old)
        seen = {}
        self.run_opencode(['run', 'x'], during=lambda: seen.update(hup=sg.getsignal(sg.SIGHUP), term=sg.getsignal(sg.SIGTERM)))
        self.assertIs(seen['hup'], sg.SIG_IGN)                  # nohup keeps working
        self.assertNotIn(seen['term'], (sg.SIG_DFL, sg.SIG_IGN)) # SIGTERM still ends the run cleanly
        self.assertIs(sg.getsignal(sg.SIGHUP), sg.SIG_IGN)

    def test_failed_clean_up_is_reported_unless_the_container_stopped(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        with patch('sys.stderr', new_callable=io.StringIO) as err:
            self.run_opencode(['run', 'x'], reap_code=1)
        self.assertIn('maybe not ended', err.getvalue())
        with patch('sys.stderr', new_callable=io.StringIO) as err, \
             patch.object(mod, 'container_state', side_effect=['running', 'stopped']):
            calls = []
            def fake(cmd, **kw):
                calls.append(cmd)
                if is_policy_call(cmd): return Mock(returncode=0, stdout=policy_json(), stderr=b'')
                return Mock(returncode=1 if mod.OPENCODE_REAP in cmd else 0)
            with patch.object(mod.sys.stdin, 'isatty', return_value=False), patch.object(mod.subprocess, 'run', side_effect=fake):
                mod.opencode(online({'project': 'example-site', 'id': 'site-task'}), ['run', 'x'])
        self.assertEqual(err.getvalue(), '')

    def test_terminal_flags(self):
        self.write('OPENROUTER_API_KEY="sk-or-quoted"\n')
        argv, kwargs = self.run_opencode(stdin_tty=True, stdout_tty=True)
        self.assertIn('-it', argv); self.assertEqual(self.key(), 'sk-or-quoted')
        argv, _ = self.run_opencode(['run', 'x'], stdin_tty=True, stdout_tty=False)   # output redirected
        self.assertNotIn('-it', argv); self.assertNotIn('-i', argv); self.assertNotIn('-t', argv)

    def test_every_run_is_marked_and_cleaned_up_even_when_the_client_dies(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        argv, _ = self.run_opencode(['run', 'x'])
        marker = next(a for a in argv if a.startswith('NC_OPENCODE_RUN='))
        reap = self.reaped()
        self.assertEqual(len(reap), 1)
        self.assertEqual(reap[0][:3], ['docker', 'exec', 'ncw-site-task'])
        self.assertEqual(reap[0][-1], marker.split('=', 1)[1])
        for dying in (KeyboardInterrupt(), SystemExit(143)):
            with self.assertRaises(type(dying)): self.run_opencode(['run', 'x'], main_effect=dying)
            self.assertEqual(len(self.reaped()), 1)

    def test_reaper_ends_only_marked_processes(self):
        import subprocess as sp, time
        marked = sp.Popen(['sleep', '60'], env=dict(mod.os.environ, NC_OPENCODE_RUN='abc123')); self.addCleanup(marked.kill)
        other = sp.Popen(['sleep', '60'], env=dict(mod.os.environ, NC_OPENCODE_RUN='zzz999')); self.addCleanup(other.kill)
        sp.run(['python3', '-I', '-B', '-c', mod.OPENCODE_REAP, 'abc123'], check=True, timeout=30)
        time.sleep(0.2)
        self.assertIsNotNone(marked.poll()); self.assertIsNone(other.poll())

    def test_refuses_tasks_without_opencode_before_passing_the_key(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n')
        with self.assertRaisesRegex(ValueError, 'has no OpenCode'): self.run_opencode(ready=False)
        self.assertEqual(self.main(), (None, None)); self.assertEqual(self.reaped(), []); self.assertEqual(self.kp.started, [])

    def test_refuses_loose_permissions_symlinks_missing_or_empty_keys(self):
        self.write('OPENROUTER_API_KEY=sk-or-x\n', 0o644)
        with self.assertRaisesRegex(ValueError, 'owner-only'): mod.openrouter_key()
        self.write('OPENROUTER_API_KEY=sk-or-x\n', 0o700)
        self.assertEqual(mod.openrouter_key(), 'sk-or-x')                          # same rule as nc-harness
        self.secrets.unlink()
        with self.assertRaisesRegex(ValueError, 'secrets.env is missing'): mod.openrouter_key()
        target = pathlib.Path(self.tmp.name) / 'real.env'; target.write_text('OPENROUTER_API_KEY=sk-or-x\n'); target.chmod(0o600)
        self.secrets.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'owner-only'): mod.openrouter_key()

    def test_same_parsing_rule_as_nc_harness(self):
        # Same table as nc-harness tests/smoke.sh (test 14). None = refused.
        cases = [('OPENROUTER_API_KEY=sk-a', 'sk-a'), ('OPENROUTER_API_KEY=sk-a   ', 'sk-a'),
                 ('OPENROUTER_API_KEY="sk-a" ', 'sk-a'), ("OPENROUTER_API_KEY='sk-a'", 'sk-a'),
                 ('OPENROUTER_API_KEY= sk-a', 'sk-a'), ('  OPENROUTER_API_KEY=sk-a', 'sk-a'),
                 ('export OPENROUTER_API_KEY=sk-a', 'sk-a'), ('export\tOPENROUTER_API_KEY=sk-a', 'sk-a'),
                 ('OPENROUTER_API_KEY=sk-a\r', 'sk-a'), ('\ufeffOPENROUTER_API_KEY=sk-a', 'sk-a'),
                 ('OPENROUTER_API_KEY=old\nOPENROUTER_API_KEY=sk-new', 'sk-new'),
                 ('OPENROUTER_API_KEY=sk-a # comment', None), ('OPENROUTER_API_KEY=sk-a\u00a0', None),
                 ('OPENROUTER_API_KEY=sk-\u00e4', None), ('OPENROUTER_API_KEY=" "', None),
                 ('OPENROUTER_API_KEY=', None), ('OTHER=1', None)]
        for content, expected in cases:
            with self.subTest(content=content):
                self.secrets.write_bytes((content + '\n').encode()); self.secrets.chmod(0o600)
                if expected is None:
                    with self.assertRaises(ValueError) as caught: mod.openrouter_key()
                    self.assertNotIn('sk-a', str(caught.exception))
                else:
                    self.assertEqual(mod.openrouter_key(), expected)

    def test_failure_does_not_print_the_key(self):
        self.write('OPENROUTER_API_KEY=sk-or-synthetic-test\n')
        def fake(cmd, **kw):
            if is_policy_call(cmd): return Mock(returncode=0, stdout=policy_json(), stderr=b'')
            if '/usr/bin/mkdir' in cmd: return Mock(returncode=0, stdout=b'', stderr=b'')
            return Mock(returncode=0 if cmd[-1] == mod.OPENCODE_READY or mod.OPENCODE_REAP in cmd else 1)
        with patch.object(mod.sys.stdin, 'isatty', return_value=False), patch.object(mod, 'container_state', return_value='running'), \
             patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaises(ValueError) as caught: mod.opencode(online({'project': 'example-site', 'id': 't'}))
        self.assertNotIn('sk-or-synthetic-test', str(caught.exception))

    # --- the key by the project's policy, default and title model
    BOTH = 'OPENROUTER_API_KEY=sk-or-default-synthetic\nOPENROUTER_API_KEY_CLIENTS=sk-or-clients-synthetic\n'
    CLIENT = {'project': 'example-client', 'id': 'acme-task', 'project_path': 'clients/acme/website'}
    FREE_DENIED = (0, policy_json(deny=['free']), b'')

    def docker_calls(self):
        return [c for c, _ in self.calls if c[0] == 'docker']

    def test_policy_call_is_the_host_checkout_with_the_project_folder(self):
        self.write(self.BOTH)
        self.run_opencode(['run', 'x'], m=self.CLIENT, policy=self.FREE_DENIED)
        cmd, kw = next((c, kw) for c, kw in self.calls if is_policy_call(c))
        self.assertEqual(cmd, [str(mod.HARNESS / 'bin/nc'), 'models', '--json', '--path', str(mod.pathlib.Path.home() / 'projects' / 'clients/acme/website')])
        self.assertEqual((kw['cwd'], kw['timeout'], kw['stdout'], kw['stderr']), ('/', 60, mod.subprocess.PIPE, mod.subprocess.PIPE))

    def test_a_project_denying_free_gets_only_the_clients_key(self):
        for content in [self.BOTH, 'OPENROUTER_API_KEY_CLIENTS=sk-or-clients-synthetic\nOPENROUTER_API_KEY=sk-or-default-synthetic\n']:
            self.write(content)
            argv, kwargs = self.run_opencode(['run', 'x'], m=self.CLIENT, policy=self.FREE_DENIED)
            self.assertEqual(self.key(), 'sk-or-clients-synthetic')
            self.assertEqual(kwargs['env']['OPENROUTER_API_KEY'], 'nc-keyproxy')
            self.assertNotIn('sk-or-', ' '.join(kwargs['env'].values()))
            self.assertNotIn('OPENROUTER_API_KEY_CLIENTS', kwargs['env'])
            for c in self.docker_calls(): self.assertFalse(any('sk-or-' in a for a in c), c)
            self.assertIn('OPENROUTER_API_KEY', argv)

    def test_a_project_without_the_denial_gets_the_default_key(self):
        self.write(self.BOTH)
        argv, kwargs = self.run_opencode(['run', 'x'])
        self.assertEqual(self.key(), 'sk-or-default-synthetic')
        self.assertNotIn('sk-or-', ' '.join(kwargs['env'].values()))

    def test_denial_without_a_usable_clients_key_never_falls_back(self):
        for content in ['OPENROUTER_API_KEY=sk-or-default-synthetic\n',
                        'OPENROUTER_API_KEY=sk-or-default-synthetic\nOPENROUTER_API_KEY_CLIENTS=\n',
                        'OPENROUTER_API_KEY=sk-or-default-synthetic\nOPENROUTER_API_KEY_CLIENTS=sk-or-clients # x\n']:
            with self.subTest(content=content):
                self.write(content)
                with self.assertRaises(ValueError) as caught: self.run_opencode(['run', 'x'], m=self.CLIENT, policy=self.FREE_DENIED)
                self.assertTrue(str(caught.exception).startswith(mod.KEY_CLIENTS + ' '), caught.exception)
                self.assertIn('OpenRouter workspace "clients"', str(caught.exception))
                self.assertNotIn('sk-or-', str(caught.exception))
                self.assertEqual(self.docker_calls(), [])

    # --- require: no-training also means the clients key
    def test_require_no_training_alone_gets_the_clients_key(self):
        self.write(self.BOTH)
        self.run_opencode(['run', 'x'], m=self.CLIENT, policy=(0, policy_json(deny=[], require=['no-training']), b''))
        self.assertEqual(self.key(), 'sk-or-clients-synthetic')
        with self.assertRaises(ValueError) as caught:  # and never a fallback to the default key
            self.write('OPENROUTER_API_KEY=sk-or-default-synthetic\n')
            self.run_opencode(['run', 'x'], m=self.CLIENT, policy=(0, policy_json(deny=[], require=['no-training']), b''))
        self.assertIn('OPENROUTER_API_KEY_CLIENTS missing', str(caught.exception))

    def test_missing_or_empty_require_is_the_default_key(self):
        for policy in [policy_json(), policy_json(require=[]), policy_json(require=['something-else'])]:
            with self.subTest(policy=policy):
                self.write(self.BOTH)
                self.run_opencode(['run', 'x'], policy=(0, policy, b''))
                self.assertEqual(self.key(), 'sk-or-default-synthetic')

    def test_require_that_is_not_a_list_of_texts_starts_nothing(self):
        self.write(self.BOTH)
        for require in ['no-training', [1], None, {'no-training': True}]:
            with self.subTest(require=require):
                with self.assertRaises(ValueError) as caught:
                    self.run_opencode(['run', 'x'], m=self.CLIENT, policy=(0, policy_json(require=require), b''))
                self.assertIn('policy.require is not a list of strings', str(caught.exception))
                self.assertIn('OpenCode does not start', str(caught.exception))
                self.assertEqual(self.docker_calls(), [])

    def test_an_unreadable_policy_starts_nothing(self):
        self.write(self.BOTH)
        broken = [(2, policy_json(), b'nc models: models.yaml: not valid YAML\n'),  # valid JSON: only the exit code refuses
                  mod.subprocess.TimeoutExpired('nc', 60),
                  OSError(2, 'No such file or directory'), (0, b'{"policy": ', b''), (0, b'{"policy": {}}', b''),
                  (0, b'{"policy": {"deny_classes": "free"}}', b''), (0, b'[]', b'')]
        for policy in broken:
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError) as caught: self.run_opencode(['run', 'x'], m=self.CLIENT, policy=policy)
                self.assertRegex(str(caught.exception), r'^policy for ~/projects/clients/acme/website not read \(.+\) – OpenCode does not start$')
                self.assertNotIn('sk-or-', str(caught.exception))
                self.assertEqual(self.docker_calls(), [])

    def test_an_old_task_without_project_path_uses_its_profile(self):
        self.write(self.BOTH)
        self.run_opencode(['run', 'x'], m={'project': 'example-client', 'id': 'old'}, policy=self.FREE_DENIED)
        cmd = next(c for c, _ in self.calls if is_policy_call(c))
        self.assertEqual(cmd[-1], str(mod.pathlib.Path.home() / 'projects/clients/acme/website'))
        with self.assertRaisesRegex(ValueError, 'project path unknown'):
            self.run_opencode(['run', 'x'], m={'project': 'no-such-profile', 'id': 'old'})
        self.assertEqual(self.docker_calls(), [])

    def test_default_and_title_model_go_in_by_name_only(self):
        self.write(self.BOTH)
        cases = [(policy_json(), {'model': 'openrouter/acme/big-1', 'small_model': 'openrouter/acme/small-1'}),
                 (policy_json(cheap_allowed=False), {'model': 'openrouter/acme/big-1'}),
                 (policy_json(cheap=None), {'model': 'openrouter/acme/big-1'}),
                 (policy_json(standard_allowed=False, cheap_allowed=False), None),
                 (policy_json(standard=None, cheap=None), None)]
        for stdout, expected in cases:
            with self.subTest(expected=expected), patch.dict(mod.os.environ, {'OPENCODE_CONFIG_CONTENT': '{"model":"from-the-caller"}'}):
                argv, kwargs = self.run_opencode(['run', 'x'], policy=(0, stdout, b''))
                run_id = self.kp.started[-1][2]
                expected = dict(expected or {}, provider={'openrouter': {'options': {'baseURL': f'http://key-{run_id}:8080/api/v1'}}})
                self.assertEqual(argv[argv.index('OPENCODE_CONFIG_CONTENT') - 1], '-e')
                self.assertEqual(json.loads(kwargs['env']['OPENCODE_CONFIG_CONTENT']), expected)
                self.assertEqual(kwargs['env']['OPENCODE_CONFIG_CONTENT'], json.dumps(expected, separators=(',', ':')))
                self.assertFalse(any('openrouter/acme' in a for a in argv))
                self.assertEqual(argv[argv.index('ncw-site-task') + 1:], ['/usr/local/bin/opencode', 'run', 'x'])

    def test_tmpdir_is_an_executable_folder_made_before_the_start(self):
        self.write(self.BOTH)
        with patch.dict(mod.os.environ, {'TMPDIR': '/tmp/from-the-caller'}):
            argv, kwargs = self.run_opencode(['run', 'x'])
        made = [i for i, (c, _) in enumerate(self.calls) if '/usr/bin/mkdir' in c]
        started = next(i for i, (c, _) in enumerate(self.calls) if '/usr/local/bin/opencode' in c)
        self.assertEqual(len(made), 1)
        self.assertLess(made[0], started)
        self.assertEqual(self.calls[made[0]][0], ['docker', 'exec', '--user', '1000:1000', 'ncw-site-task',
                                                  '/usr/bin/mkdir', '-p', '-m', '700', '/home/agent/.cache/nc-tmp'])
        self.assertEqual(argv[argv.index('TMPDIR') - 1], '-e')                       # by name, like the key
        self.assertEqual(kwargs['env']['TMPDIR'], '/home/agent/.cache/nc-tmp')
        self.assertFalse(any('nc-tmp' in a for a in argv))
        def failing(cmd, **kw):
            if is_policy_call(cmd): return Mock(returncode=0, stdout=policy_json(), stderr=b'')
            if '/usr/bin/mkdir' in cmd: return Mock(returncode=1, stdout=b'', stderr=b'mkdir: cannot create directory\n')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        with patch.object(mod, 'container_state', return_value='running'), patch.object(mod.subprocess, 'run', side_effect=failing) as call:
            with self.assertRaisesRegex(ValueError, '^/home/agent/.cache/nc-tmp not created in task site-task \\(mkdir: cannot create directory\\) – OpenCode does not start$'):
                mod.opencode(online({'project': 'example-site', 'id': 'site-task'}), ['run', 'x'])
        self.assertFalse(any('/usr/local/bin/opencode' in a.args[0] for a in call.call_args_list))

    def test_same_parsing_rule_for_the_clients_key(self):
        # The table of test_same_parsing_rule_as_nc_harness, for OPENROUTER_API_KEY_CLIENTS.
        rows = [('{N}=sk-a', 'sk-a'), ('{N}=sk-a   ', 'sk-a'), ('{N}="sk-a" ', 'sk-a'), ("{N}='sk-a'", 'sk-a'),
                ('{N}= sk-a', 'sk-a'), ('  {N}=sk-a', 'sk-a'), ('export {N}=sk-a', 'sk-a'), ('export\t{N}=sk-a', 'sk-a'),
                ('{N}=sk-a\r', 'sk-a'), ('\ufeff{N}=sk-a', 'sk-a'), ('{N}=old\n{N}=sk-new', 'sk-new'),
                ('{N}=sk-a # comment', None), ('{N}=sk-a\u00a0', None), ('{N}=sk-\u00e4', None), ('{N}=" "', None),
                ('{N}=', None), ('OPENROUTER_API_KEY=sk-a', None), ('OTHER=1', None)]
        for row, expected in rows:
            content = row.replace('{N}', mod.KEY_CLIENTS)
            with self.subTest(content=content):
                self.secrets.write_bytes((content + '\n').encode()); self.secrets.chmod(0o600)
                if expected is None:
                    with self.assertRaises(ValueError) as caught: mod.openrouter_key(mod.KEY_CLIENTS)
                    self.assertNotIn('sk-a', str(caught.exception))
                    self.assertTrue(str(caught.exception).startswith(mod.KEY_CLIENTS + ' '), caught.exception)
                else:
                    self.assertEqual(mod.openrouter_key(mod.KEY_CLIENTS), expected)

    def test_each_name_gets_its_own_line_in_either_order(self):
        for content in ['OPENROUTER_API_KEY=sk-d\nOPENROUTER_API_KEY_CLIENTS=sk-k\n', 'OPENROUTER_API_KEY_CLIENTS=sk-k\nOPENROUTER_API_KEY=sk-d\n']:
            self.write(content)
            self.assertEqual((mod.openrouter_key(), mod.openrouter_key(mod.KEY_CLIENTS)), ('sk-d', 'sk-k'))
        self.write('OPENROUTER_API_KEY_CLIENTS=sk-k\n')
        with self.assertRaisesRegex(ValueError, '^OPENROUTER_API_KEY missing'): mod.openrouter_key()

    def test_every_profile_allows_openrouter(self):
        with patch.object(mod, 'PROFILE_DIRS', (mod.ROOT / 'profiles', FIXTURES / 'profiles')):
            profiles = mod.all_profiles()
        for p in profiles:
            self.assertIn('openrouter.ai', p['allowed_domains'], p['id'])
            self.assertIn('acl allowed_domains dstdomain', mod.proxy_config(p['allowed_domains'], own=['192.0.2.1/32']))

class KeyProxyLaunchTests(unittest.TestCase):
    """Every nc-work opencode starts a key proxy of its own; OpenCode gets the placeholder only."""
    KEY = 'sk-or-v1-synthetic-launch-key'
    RUN_A, RUN_B, RUN_C = 'a' * 16, 'b' * 16, 'c' * 16

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.state = root / 'state'; (self.state / 'tasks').mkdir(parents=True)
        secrets = root / 'secrets.env'; secrets.write_text(f'OPENROUTER_API_KEY={self.KEY}\n'); secrets.chmod(0o600)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'SECRETS', secrets)]:
            p.start(); self.addCleanup(p.stop)
        self.m = online({'project': 'example-site', 'id': 'site-task'})

    def launch(self, main=0, popen_effect=None, exits=False, ready=True, proxies='', live='', during=None, m=None):
        """nc-work opencode with Docker faked at the subprocess level. Sets self.calls (('run'|'popen', argv, kw)),
        self.popen (the fake docker run -i) and self.at_popen (SIGTERM handler when the proxy started)."""
        self.calls, self.popen, self.at_popen = [], None, None
        test = self
        class Stdin:
            def __init__(s): s.data, s.closed = b'', False
            def write(s, b): s.data += b
            def close(s): s.closed = True
        class FakePopen:
            def __init__(s, argv, **kw):
                test.calls.append(('popen', list(argv), kw)); test.popen = s
                test.at_popen = mod.signal.getsignal(mod.signal.SIGTERM)
                s.argv, s.kw, s.stdin, s.killed = list(argv), kw, Stdin(), False
                if popen_effect: raise popen_effect
            def poll(s): return 1 if exits else None
            def kill(s): s.killed = True
            def wait(s, timeout=None): return 0
        def fake(cmd, **kw):
            cmd = list(cmd); self.calls.append(('run', cmd, kw))
            if is_policy_call(cmd): return Mock(returncode=0, stdout=policy_json(), stderr=b'')
            if cmd[-1] == mod.OPENCODE_READY: return Mock(returncode=0)
            if cmd[:3] == ['docker', 'ps', '-a']: return Mock(returncode=0, stdout=proxies.encode(), stderr=b'')
            if mod.OPENCODE_LIVE in cmd: return Mock(returncode=0, stdout=live.encode(), stderr=b'')
            if mod.KEYPROXY_PING in cmd: return Mock(returncode=0 if ready else 1)
            if cmd[:3] == ['docker', 'inspect', '--format']: return Mock(returncode=0, stdout=b'sha256:taskimage\n', stderr=b'')
            if '/usr/local/bin/opencode' in cmd:
                if during: during()
                if isinstance(main, BaseException): raise main
                return Mock(returncode=main)
            return Mock(returncode=0, stdout=b'', stderr=b'')
        clock = iter(range(0, 10_000))
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.subprocess, 'Popen', FakePopen), \
             patch.object(mod, 'container_state', return_value='running'), \
             patch.object(mod.sys.stdin, 'isatty', return_value=False), patch.object(mod.sys.stdout, 'isatty', return_value=False), \
             patch.object(mod.time, 'sleep'), patch.object(mod.time, 'monotonic', side_effect=lambda: next(clock)):
            mod.opencode(m or self.m, ['run', 'x'])

    def runs(self): return [c for kind, c, _ in self.calls if kind == 'run']
    def main_call(self): return next(((c, kw) for kind, c, kw in self.calls if '/usr/local/bin/opencode' in c), (None, None))
    def removed(self): return [c[3] for c in self.runs() if c[:3] == ['docker', 'rm', '-f']]
    def own(self): return self.popen.argv[self.popen.argv.index('--name') + 1]

    def test_every_docker_exec_starts_its_program_by_absolute_path(self):
        # ~/.local/bin comes first on the container's PATH and the agent writes there: a python3 of its own must not
        # answer the live search or the clean-up.
        self.launch(proxies=f'ncw-site-task-key-{self.RUN_A} {self.RUN_A}\n')
        live = next(c for c in self.runs() if mod.OPENCODE_LIVE in c)
        reap = next(c for c in self.runs() if mod.OPENCODE_REAP in c)
        self.assertEqual(live[:4], ['docker', 'exec', 'ncw-site-task', '/usr/bin/python3'])
        self.assertEqual(reap[:4], ['docker', 'exec', 'ncw-site-task', '/usr/bin/python3'])
        execs = [c for c in self.runs() if c[:2] == ['docker', 'exec']]
        self.assertGreaterEqual(len(execs), 5)                                     # ready, mkdir, live, ping, opencode, reap
        for c in execs:
            program = c[next(i for i, a in enumerate(c) if a.startswith('ncw-')) + 1]
            self.assertTrue(program.startswith('/'), c[:8])
        source = path.read_text()
        python = [l for l in source.splitlines() if "'/usr/bin/python3'" in l]
        self.assertEqual(len(python), 8)
        for l in python: self.assertIn("'-I', '-B'", l)                            # no /workspace or user site on sys.path
        self.assertNotIn("'python3'", source)
        self.assertNotRegex(source, r"'docker', 'exec'[^\n]*'ncw-[^\n]*?, '(python3|sh|git|mkdir|rm|cat|bash)'")
        self.assertNotRegex(source, r"dex\([^,]+, '(python3|sh|git|mkdir|rm|cat|bash)'")

    def test_handlers_first_then_the_proxy_with_name_alias_labels_limits_and_mount(self):
        self.launch()
        self.assertNotIn(self.at_popen, (mod.signal.SIG_DFL, mod.signal.SIG_IGN, None))  # installed before the start
        argv = self.popen.argv
        run_id = self.own()[-16:]
        self.assertRegex(run_id, '^[0-9a-f]{16}$')
        self.assertEqual(argv[:3], ['docker', 'run', '-i'])
        self.assertEqual(self.own(), f'ncw-site-task-key-{run_id}')
        def after(flag): return [argv[i + 1] for i, a in enumerate(argv) if a == flag]
        self.assertEqual(after('--label'), [f'{mod.LABEL}.kind=keyproxy', f'{mod.LABEL}.project=example-site',
                                            f'{mod.LABEL}.task=site-task', f'{mod.LABEL}.run={run_id}'])
        self.assertEqual((after('--network'), after('--network-alias')), (['ncw-site-task'], [f'key-{run_id}']))
        for flag, value in [('--user', '1000:1000'), ('--cap-drop', 'ALL'), ('--security-opt', 'no-new-privileges'),
                            ('--memory', '256m'), ('--pids-limit', '64'), ('--ulimit', 'core=0'), ('--entrypoint', '/usr/bin/python3')]:
            self.assertEqual(after(flag), [value], flag)
        self.assertIn('--read-only', argv); self.assertIn('--init', argv)
        self.assertTrue(after('--tmpfs')[0].startswith('/tmp:'))
        self.assertNotIn('-p', argv); self.assertNotIn('--publish', argv)        # no ports to the outside
        folder = self.state / 'keyproxy'
        self.assertEqual(after('--mount'), [f'type=bind,src={folder},dst=/opt/nc-keyproxy,readonly'])
        self.assertEqual(argv[-4:], ['sha256:taskimage', '-I', '-B', '/opt/nc-keyproxy/keyproxy.py'])  # the task's image
        self.assertEqual(folder.stat().st_mode & 0o777, 0o755)
        self.assertEqual((folder / 'keyproxy.py').stat().st_mode & 0o777, 0o644)
        self.assertEqual((folder / 'keyproxy.py').read_bytes(), (mod.ROOT / 'keyproxy/keyproxy.py').read_bytes())
        self.assertIn(self.own(), self.removed())                                  # and gone after the run

    def test_the_key_goes_only_over_stdin_of_docker_run(self):
        self.launch()
        self.assertEqual(self.popen.stdin.data, (self.KEY + '\n').encode()); self.assertTrue(self.popen.stdin.closed)
        self.assertEqual(self.popen.kw['stdin'], mod.subprocess.PIPE)
        self.assertNotIn('env', self.popen.kw)                                     # Docker's own environment: unchanged
        self.assertFalse(any(self.KEY in a for a in self.popen.argv))
        self.assertNotIn('-e', self.popen.argv); self.assertNotIn('--env', self.popen.argv)
        for kind, c, kw in self.calls:
            self.assertFalse(any(self.KEY in str(a) for a in c), c)
            self.assertNotIn(self.KEY, ' '.join(str(v) for v in (kw.get('env') or {}).values()), c)

    def test_opencode_gets_the_placeholder_the_proxy_address_and_the_alias_in_no_proxy(self):
        self.launch()
        argv, kw = self.main_call()
        run_id = self.own()[-16:]
        env = kw['env']
        self.assertEqual(env['OPENROUTER_API_KEY'], 'nc-keyproxy')
        config = json.loads(env['OPENCODE_CONFIG_CONTENT'])
        self.assertEqual(config['provider'], {'openrouter': {'options': {'baseURL': f'http://key-{run_id}:8080/api/v1'}}})
        self.assertEqual(config['model'], 'openrouter/acme/big-1')
        for name in ('NO_PROXY', 'no_proxy'):
            self.assertEqual(env[name], f'localhost,127.0.0.1,key-{run_id}'); self.assertEqual(argv[argv.index(name) - 1], '-e')
        self.assertIn(f'NC_OPENCODE_RUN={run_id}', argv)
        order = [i for i, (kind, c, _) in enumerate(self.calls) if kind == 'popen' or mod.KEYPROXY_PING in c or '/usr/local/bin/opencode' in c]
        self.assertEqual([self.calls[i][0] if self.calls[i][0] == 'popen' else ('ping' if mod.KEYPROXY_PING in self.calls[i][1] else 'opencode') for i in order],
                         ['popen', 'ping', 'opencode'])
        ping = next(c for c in self.runs() if mod.KEYPROXY_PING in c)
        self.assertEqual(ping[:3], ['docker', 'exec', self.own()])                # asked inside the proxy container

    def test_the_proxy_goes_when_opencode_fails_a_signal_comes_or_docker_run_is_cut_short(self):
        def term(): raise SystemExit(143)
        before = {s: mod.signal.getsignal(s) for s in (mod.signal.SIGTERM, mod.signal.SIGHUP, mod.signal.SIGINT)}
        cases = [('opencode fails', dict(main=1), ValueError), ('signal', dict(during=term), SystemExit),
                 ('Ctrl-C', dict(main=KeyboardInterrupt()), KeyboardInterrupt),
                 ('docker run cut short', dict(popen_effect=KeyboardInterrupt()), KeyboardInterrupt)]
        for label, kw, raised in cases:
            with self.subTest(label):
                with self.assertRaises(raised): self.launch(**kw)
                name = self.own()
                self.assertIn(name, self.removed())                                 # by its fixed name
                reaped = [i for i, c in enumerate(self.runs()) if mod.OPENCODE_REAP in c]
                removed = [i for i, c in enumerate(self.runs()) if c[:4] == ['docker', 'rm', '-f', name]]
                self.assertLess(removed[0], reaped[0])                              # the proxy first, then the processes
                self.assertFalse((self.state / 'keyproxy-runs' / f'site-task.{name[-16:]}.lock').exists())
        self.assertEqual({s: mod.signal.getsignal(s) for s in before}, before)    # handlers restored

    def test_a_signal_right_after_docker_run_still_ends_it_and_a_failed_removal_is_reported(self):
        with patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err:
            with self.assertRaises(KeyboardInterrupt): self._signal_launch()   # the signal arrives while the key is written
        self.assertTrue(self.popen.killed)                                          # docker run ended by the caller
        self.assertEqual(self.removed().count(self.own()), 2)                       # removed before and after
        self.assertIn('maybe not removed', err.getvalue())                      # docker ps still lists it (fake)

    def _signal_launch(self):
        test = self
        class Gone:
            def write(s, b): raise KeyboardInterrupt()
            def close(s): pass
        class FakePopen:
            def __init__(s, argv, **kw): s.argv, s.stdin, s.killed = list(argv), Gone(), False; test.popen = s; test.calls.append(('popen', s.argv, kw))
            def poll(s): return None
            def kill(s): s.killed = True
            def wait(s, timeout=None): return 0
        self.calls = []
        def fake(cmd, **kw):
            cmd = list(cmd); self.calls.append(('run', cmd, kw))
            if is_policy_call(cmd): return Mock(returncode=0, stdout=policy_json(), stderr=b'')
            if cmd[:3] == ['docker', 'ps', '-aq']: return Mock(returncode=0, stdout=b'abc123\n', stderr=b'')  # still there
            if cmd[:3] == ['docker', 'inspect', '--format']: return Mock(returncode=0, stdout=b'sha256:taskimage\n', stderr=b'')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.subprocess, 'Popen', FakePopen), \
             patch.object(mod, 'container_state', return_value='running'), patch.object(mod.time, 'sleep'), \
             patch.object(mod.sys.stdin, 'isatty', return_value=False), patch.object(mod.sys.stdout, 'isatty', return_value=False):
            mod.opencode(self.m, ['run', 'x'])

    def test_no_proxy_no_opencode(self):
        for label, kw in [('docker run ended', dict(exits=True)), ('no answer within 15 seconds', dict(ready=False))]:
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, 'key proxy for site-task not ready – OpenCode does not start'): self.launch(**kw)
                self.assertEqual(self.main_call(), (None, None))
                self.assertIn(self.own(), self.removed())
        pings = [c for c in self.runs() if mod.KEYPROXY_PING in c]
        self.assertTrue(1 < len(pings) <= 16)                                       # retried until the deadline, not beyond

    def test_offline_tasks_get_no_opencode_and_no_key_is_read(self):
        for m in [{'project': 'example-site', 'id': 'site-off', 'network': 'none', 'proxy': None},
                  {'project': 'example-site', 'id': 'site-off'}]:
            with self.subTest(m=m), patch.object(mod, 'openrouter_key') as key:
                with self.assertRaisesRegex(ValueError, '^offline: no OpenCode'): self.launch(m=m)
                key.assert_not_called(); self.assertEqual(self.calls, [])

    def test_orphans_go_at_the_start_but_not_the_proxy_of_a_live_run(self):
        lock_dir = self.state / 'keyproxy-runs'; lock_dir.mkdir(parents=True)
        held = (lock_dir / f'site-task.{self.RUN_C}.lock').open('a'); self.addCleanup(held.close)
        mod.fcntl.flock(held, mod.fcntl.LOCK_EX)                                    # a run whose OpenCode is not up yet
        proxies = ''.join(f'ncw-site-task-key-{r} {r}\n' for r in (self.RUN_A, self.RUN_B, self.RUN_C))
        self.launch(proxies=proxies, live=self.RUN_B + '\n')
        removed = self.removed()
        self.assertEqual(removed[0], f'ncw-site-task-key-{self.RUN_A}')              # no process, no lock: orphan
        self.assertNotIn(f'ncw-site-task-key-{self.RUN_B}', removed)                # live process with its marker
        self.assertNotIn(f'ncw-site-task-key-{self.RUN_C}', removed)                # nc-work of that run still holds its lock
        sweep = next(c for c in self.runs() if c[:3] == ['docker', 'ps', '-a'])
        self.assertIn(f'label={mod.LABEL}.task=site-task', sweep); self.assertIn(f'label={mod.LABEL}.kind=keyproxy', sweep)
        live = next(c for c in self.runs() if mod.OPENCODE_LIVE in c)
        self.assertEqual(live[:3], ['docker', 'exec', 'ncw-site-task'])
        idx = {kind: i for i, (kind, c, _) in enumerate(self.calls) if kind == 'popen' or c[:3] == ['docker', 'ps', '-a']}
        self.assertLess(idx['run'], idx['popen'])                                  # swept before the own proxy starts

    def test_unknown_liveness_keeps_every_proxy(self):
        proxies = f'ncw-site-task-key-{self.RUN_A} {self.RUN_A}\n'
        def fake(cmd, **kw):
            if cmd[:3] == ['docker', 'ps', '-a']: return Mock(returncode=0, stdout=proxies.encode())
            return Mock(returncode=1, stdout=b'')                                   # the live search fails
        with patch.object(mod.subprocess, 'run', side_effect=fake) as call, patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err:
            mod.keyproxy_sweep('site-task', orphans_only=True)
        self.assertFalse(any(c.args[0][:2] == ['docker', 'rm'] for c in call.call_args_list))
        self.assertIn('not checked', err.getvalue())

    def test_live_search_is_the_reapers_search(self):
        import subprocess as sp
        one = sp.Popen(['sleep', '60'], env=dict(mod.os.environ, NC_OPENCODE_RUN=self.RUN_A)); self.addCleanup(one.kill)
        out = sp.run(['python3', '-I', '-B', '-c', mod.OPENCODE_LIVE], stdout=sp.PIPE, check=True, timeout=30).stdout.decode()
        self.assertIn(self.RUN_A, out.split())
        self.assertTrue(mod.OPENCODE_REAP.startswith(mod.OPENCODE_RUNS)); self.assertTrue(mod.OPENCODE_LIVE.startswith(mod.OPENCODE_RUNS))

    def sweep_all(self, call):
        proxies = f'ncw-site-task-key-{self.RUN_A} {self.RUN_A}\nncw-site-task-key-{self.RUN_B} {self.RUN_B}\n'
        calls = []
        def fake(cmd, **kw):
            calls.append(list(map(str, cmd)))
            if cmd[:3] == ['docker', 'ps', '-a']: return Mock(returncode=0, stdout=proxies.encode(), stderr=b'')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        with patch.object(mod.subprocess, 'run', side_effect=fake): call()
        return [c[3] for c in calls if c[:3] == ['docker', 'rm', '-f']], calls

    def test_stop_and_make_room_remove_every_proxy_of_the_task(self):
        mod.save(self.state / 'tasks/site-task.json', dict(self.m, status='ready'))
        with patch.object(mod.sys, 'argv', ['nc-work', 'stop', 'site-task']):
            removed, calls = self.sweep_all(mod.main)
        self.assertEqual(removed, [f'ncw-site-task-key-{self.RUN_A}', f'ncw-site-task-key-{self.RUN_B}'])
        self.assertFalse(any(mod.OPENCODE_LIVE in c for c in calls))               # all of them, no live search
        with patch.object(mod, 'running_agents', return_value=['site-task', 'b', 'c']), patch('builtins.input', return_value='1'), \
             patch.object(mod.sys, 'stdout', new_callable=io.StringIO):
            removed, _ = self.sweep_all(mod.make_room)
        self.assertEqual(removed, [f'ncw-site-task-key-{self.RUN_A}', f'ncw-site-task-key-{self.RUN_B}'])

    def test_remove_takes_the_proxies_through_the_task_label(self):
        mod.save(self.state / 'tasks/site-task.json', dict(self.m, status='ready'))
        calls = []
        def fake(cmd, **kw):
            cmd = list(map(str, cmd)); calls.append(cmd)
            if cmd[:3] == ['docker', 'ps', '-aq'] and f'label={mod.LABEL}.task=site-task' in cmd:
                return Mock(returncode=0, stdout=b'agentid\nproxyid\n', stderr=b'')
            if cmd[:2] == ['docker', 'version']: return Mock(returncode=0, stdout=b'', stderr=b'')
            return Mock(returncode=1, stdout=b'', stderr=b'')
        locks = self.state / 'keyproxy-runs'; locks.mkdir()
        for n in (f'site-task.{self.RUN_A}.lock', f'other.{self.RUN_B}.lock'): (locks / n).touch()  # one left after a SIGKILL
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'stdout', new_callable=io.StringIO):
            mod.remove('site-task', force=True)
        self.assertEqual(sorted(c[3] for c in calls if c[:3] == ['docker', 'rm', '-f']), ['agentid', 'proxyid'])
        self.assertEqual([p.name for p in locks.iterdir()], [f'other.{self.RUN_B}.lock'])  # only this task's lock files go

class HereTests(unittest.TestCase):
    """`nc-work here`: herdr starts it in a space's folder; it picks or creates a task."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.home, self.state = root / 'home', root / 'state'
        for p in ['sites/example-site/src', 'clients/acme/app/packages/shared', 'clients/acme/website']:
            (self.home / 'projects' / p).mkdir(parents=True)
        (self.state / 'tasks').mkdir(parents=True)
        self.patches = [patch.object(mod.pathlib.Path, 'home', return_value=self.home),
                        patch.object(mod, 'STATE', self.state),
                        patch.object(mod.sys.stdin, 'isatty', return_value=True)]
        for p in self.patches: p.start()
        self.kp = KeyProxyFakes(self)

    def tearDown(self):
        for p in self.patches: p.stop()
        self.tmp.cleanup()

    def add_task(self, name, project, **extra):
        meta = {'id': name, 'project': project, 'status': 'ready', 'base': 'b' * 40, 'branch': 'nc-work/' + name,
                'network': 'ncw-' + name, 'proxy': 'ncw-' + name + '-egress',
                'volumes': ['ncw-' + name + '-work', 'ncw-' + name + '-home'], **extra}
        mod.save(self.state / 'tasks' / (name + '.json'), meta)
        return meta

    def test_folder_maps_to_the_profile_that_contains_it(self):
        projects = self.home / 'projects'
        self.assertEqual(mod.project_for(projects / 'sites/example-site')['id'], 'example-site')
        self.assertEqual(mod.project_for(projects / 'sites/example-site/src')['id'], 'example-site')
        self.assertEqual(mod.project_for(projects / 'clients/acme/app/packages/shared')['id'], 'example-app')
        self.assertIsNone(mod.project_for(projects / 'clients/acme'))
        self.assertIsNone(mod.project_for(projects))
        self.assertIsNone(mod.project_for(self.home))

    def test_folder_without_profile_is_refused(self):
        with patch.object(mod.os, 'getcwd', return_value=str(self.home / 'projects')):
            with self.assertRaisesRegex(ValueError, 'No nc-work profile'): mod.here()

    def run_here(self, answers, states=None, running=(), dirty='', runtime='claude', policy=None):
        states = states or {}
        with patch.object(mod.os, 'getcwd', return_value=str(self.home / 'projects/sites/example-site/src')), \
             patch('builtins.input', side_effect=list(answers)), \
             patch.object(mod, 'container_state', side_effect=lambda n: states.get(n, 'missing')), \
             patch.object(mod, 'running_agents', return_value=list(running)), \
             patch.object(mod, 'output', return_value=dirty), \
             patch.object(mod, 'run') as run, \
             patch.object(mod, 'create', side_effect=lambda p, n, quiet: self.add_task(n, p['id'])) as create, \
             patch.object(mod, 'claude') as claude, patch.object(mod, 'opencode') as opencode, \
             patch.object(mod, 'opencode_policy', return_value=policy or json.loads(policy_json())) as asked, \
             patch.object(mod, 'openrouter_key', return_value='synthetic'), patch.object(mod, 'report'):
            mod.here(runtime=runtime)
        self.policy_asked = asked
        self.opencode = opencode
        return run, create, claude

    def test_existing_running_task_is_reused_without_new_container(self):
        self.add_task('site-layout', 'example-site')
        self.add_task('other', 'example-client')
        run, create, claude = self.run_here(['1'], states={'site-layout': 'running', 'other': 'running'})
        create.assert_not_called(); run.assert_not_called()
        self.assertEqual(claude.call_args[0][0]['id'], 'site-layout')

    def test_runtime_opencode_starts_opencode_instead_of_claude(self):
        self.add_task('site-layout', 'example-site', opencode=True)
        run, create, claude = self.run_here(['1'], states={'site-layout': 'running'}, runtime='opencode')
        claude.assert_not_called()
        self.assertEqual(self.opencode.call_args[0][0]['id'], 'site-layout')

    def test_runtime_opencode_does_not_offer_tasks_without_opencode(self):
        self.add_task('old-task', 'example-site')                     # older image/snapshot, no flag
        self.add_task('new-task', 'example-site', opencode=True)
        run, create, claude = self.run_here(['1'], states={'old-task': 'stopped', 'new-task': 'running'}, runtime='opencode')
        run.assert_not_called()                                           # old task not started, nothing stopped
        self.assertEqual(self.opencode.call_args[0][0]['id'], 'new-task')

    def test_runtime_opencode_does_not_offer_offline_tasks(self):
        self.add_task('off-task', 'example-site', opencode=True, network='none', proxy=None)
        self.add_task('new-task', 'example-site', opencode=True)
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            self.run_here(['1'], states={'off-task': 'running', 'new-task': 'running'}, runtime='opencode')
        self.assertEqual(self.opencode.call_args[0][0]['id'], 'new-task')
        self.assertRegex(out.getvalue(), r'off-task +offline \(no OpenCode\)')

    def test_runtime_opencode_new_task_needs_a_snapshot_with_opencode(self):
        with self.assertRaisesRegex(ValueError, 'snapshot has no adapters/opencode'):
            self.run_here(['n'], runtime='opencode')                  # no harness-current.json in this state
        commit = 'c' * 40
        mod.save(self.state / 'harness-current.json', {'commit': commit})
        folder = self.state / 'harness' / commit / 'adapters/opencode'; folder.mkdir(parents=True)
        (folder / 'opencode.json').write_text('{}'); (folder / 'service.json').write_text('{"disabled": true}')
        run, create, claude = self.run_here(['', ''], runtime='opencode')
        create.assert_called_once(); claude.assert_not_called()

    def test_runtime_opencode_without_key_refuses_before_creating_a_task(self):
        with patch.object(mod.os, 'getcwd', return_value=str(self.home / 'projects/sites/example-site')), \
             patch.object(mod, 'opencode_policy', return_value=json.loads(policy_json())), \
             patch.object(mod, 'openrouter_key', side_effect=ValueError('OPENROUTER_API_KEY missing')), \
             patch.object(mod, 'create') as create:
            with self.assertRaisesRegex(ValueError, 'OPENROUTER_API_KEY missing'): mod.here(runtime='opencode')
        create.assert_not_called()

    def test_runtime_opencode_in_a_project_denying_free_needs_the_clients_key_before_any_question(self):
        secrets_file = pathlib.Path(self.tmp.name) / 'secrets.env'
        secrets_file.write_text('OPENROUTER_API_KEY=sk-or-default-synthetic\n'); secrets_file.chmod(0o600)
        with patch.object(mod.os, 'getcwd', return_value=str(self.home / 'projects/clients/acme/website')), \
             patch.object(mod, 'SECRETS', secrets_file), \
             patch.object(mod, 'opencode_policy', return_value=json.loads(policy_json(deny=['free']))) as asked, \
             patch('builtins.input') as typed, patch.object(mod, 'create') as create, patch.object(mod, 'opencode') as started:
            with self.assertRaisesRegex(ValueError, 'OPENROUTER_API_KEY_CLIENTS missing'): mod.here(runtime='opencode')
        asked.assert_called_once_with('clients/acme/website')
        typed.assert_not_called(); create.assert_not_called(); started.assert_not_called()

    def test_runtime_opencode_asks_the_policy_of_the_chosen_profile(self):
        self.add_task('site-layout', 'example-site', opencode=True)
        self.run_here(['1'], states={'site-layout': 'running'}, runtime='opencode')
        self.policy_asked.assert_called_once_with('sites/example-site')

    def test_stopped_task_is_started_with_its_proxy(self):
        self.add_task('site-layout', 'example-site')
        run, create, claude = self.run_here(['1'], states={'site-layout': 'stopped'})
        started = [c.args for c in run.call_args_list]
        self.assertEqual(started, [('docker', 'start', 'ncw-site-layout-egress'), ('docker', 'start', 'ncw-site-layout')])
        self.assertEqual(claude.call_args[0][0]['id'], 'site-layout')

    def test_enter_twice_creates_a_task_with_the_suggested_name(self):
        run, create, claude = self.run_here(['', ''])
        name = create.call_args[0][1]
        self.assertTrue(name.startswith('example-site-'))
        mod.valid(name)
        self.assertEqual(claude.call_args[0][0]['id'], name)

    def test_new_task_refused_when_checkout_has_local_changes(self):
        with self.assertRaisesRegex(ValueError, 'has local changes'):
            self.run_here(['n'], dirty=' M index.html')

    def test_failed_tasks_are_listed_but_not_selectable(self):
        self.add_task('broken', 'example-site', status='failed')
        with self.assertRaisesRegex(ValueError, 'No valid choice'):
            self.run_here(['1'], states={'broken': 'stopped'})

    def test_full_server_asks_which_task_to_stop(self):
        for n in ['a1', 'a2', 'a3']: self.add_task(n, 'example-client')
        run, create, claude = self.run_here(['n', 'site-new', '2'], running=['a1', 'a2', 'a3'])
        stopped = [c.args for c in run.call_args_list]
        self.assertEqual(stopped, [('docker', 'stop', 'ncw-a2'), ('docker', 'stop', 'ncw-a2-egress')])
        self.assertEqual(create.call_args[0][1], 'site-new')

class FeedTests(unittest.TestCase):
    """`nc-work feed`: herdr's usage cards find the isolated session behind a terminal."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.state = pathlib.Path(self.tmp.name)
        p = patch.object(mod, 'STATE', self.state); p.start(); self.addCleanup(p.stop)

    def test_claude_marks_its_session_and_cleans_up(self):
        token = self.state / 'auth/.default.token'; token.parent.mkdir(); token.write_text('synthetic'); token.chmod(0o600)
        seen = {}
        def fake_run(cmd, **kw):
            seen['cmd'] = cmd
            seen['marker'] = json.loads((self.state / f'sessions/{mod.os.getpid()}.json').read_text())
            return Mock(returncode=0)
        with patch.object(mod, 'dex'), patch.object(mod.sys.stdin, 'isatty', return_value=True), \
             patch.object(mod.subprocess, 'run', side_effect=fake_run):
            mod.claude({'project': 'example-site', 'id': 'site-task'})
        self.assertIn(f'NC_HOST_PID={mod.os.getpid()}', seen['cmd'])
        self.assertEqual(seen['marker']['task'], 'site-task')
        self.assertFalse((self.state / f'sessions/{mod.os.getpid()}.json').exists())

    def test_session_found_from_the_shell_above_or_the_process_below(self):
        import subprocess as sp
        mod.save(self.state / f'sessions/{mod.os.getpid()}.json', {'task': 'site-task'})
        child = sp.Popen(['sleep', '30']); self.addCleanup(child.kill)
        self.assertEqual(mod.session_of(child.pid), ('site-task', mod.os.getpid()))        # docker child
        self.assertEqual(mod.session_of(mod.os.getppid()), ('site-task', mod.os.getpid())) # starting shell
        self.assertEqual(mod.session_of(mod.os.getpid()), ('site-task', mod.os.getpid()))  # nc-work itself

    def test_unrelated_process_and_dead_markers(self):
        import subprocess as sp
        other = sp.Popen(['sleep', '30'], start_new_session=True); self.addCleanup(other.kill)
        dead = sp.Popen(['true']); dead.wait()
        mod.save(self.state / f'sessions/{dead.pid}.json', {'task': 'gone'})
        self.assertEqual(mod.session_of(other.pid), (None, None))
        self.assertFalse((self.state / f'sessions/{dead.pid}.json').exists())

    def test_feed_runs_the_script_inside_the_task_container_only(self):
        mod.save(self.state / f'sessions/{mod.os.getpid()}.json', {'task': 'site-task'})
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'{"v": 1}', stderr=b'')) as run, \
             patch('sys.stdout', new_callable=io.StringIO) as out:
            mod.feed(mod.os.getpid(), 'print(1)', ['--since', 'abc'])
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:3], ['docker', 'exec', 'ncw-site-task'])
        self.assertEqual(cmd[-4:], [str(mod.os.getpid()), 'print(1)', '--since', 'abc'])
        self.assertNotIn('-it', cmd)
        self.assertEqual(out.getvalue(), '{"v": 1}')

    def test_feed_passes_orch_before_since(self):
        for extra, want in [(['--orch'], ['--orch', '--since', 'abc']), ([], ['--since', 'abc'])]:
            with patch.object(mod, 'session_of', return_value=('site-task', 4242)), \
                 patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'{}', stderr=b'')) as run, \
                 patch.object(mod.sys, 'argv', ['nc-work', 'feed', '--pid', '7', '--script=print(1)', *extra, '--since=abc']), \
                 patch('sys.stdout', new_callable=io.StringIO):
                mod.main()
            self.assertEqual(run.call_args[0][0][-len(want) - 2:], ['4242', 'print(1)', *want])

    def test_feed_without_isolated_session_says_so(self):
        with patch.object(mod.subprocess, 'run') as run, patch('sys.stdout', new_callable=io.StringIO) as out:
            mod.feed(mod.os.getpid(), 'print(1)', [])
        run.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())['error'], 'not-isolated')

    def test_boot_picks_the_claude_process_with_the_marker(self):
        import subprocess as sp, shutil
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / 'claude'; shutil.copy('/bin/sleep', fake)
            env = dict(mod.os.environ, NC_HOST_PID='4242')
            decoy = sp.Popen(['sleep', '30'], env=env); self.addCleanup(decoy.kill)
            target = sp.Popen([str(fake), '30'], env=env); self.addCleanup(target.kill)
            script = 'import sys, json; print(json.dumps(sys.argv))'
            r = sp.run(['python3', '-I', '-B', '-c', mod.FEED_BOOT, '4242', script, '--since', 'x'], stdout=sp.PIPE, check=True)
            self.assertEqual(json.loads(r.stdout), ['usage.py', '--pid', str(target.pid), '--since', 'x'])
            r = sp.run(['python3', '-I', '-B', '-c', mod.FEED_BOOT, '9999', script], stdout=sp.PIPE, check=True)
            self.assertEqual(json.loads(r.stdout)['error'], 'no-session')

class RemoveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.state = pathlib.Path(self.tmp.name)
        (self.state / 'tasks').mkdir()
        mod_patch = patch.object(mod, 'STATE', self.state); mod_patch.start(); self.addCleanup(mod_patch.stop)
        self.meta = {'id': 't1', 'project': 'example-site', 'base': 'b' * 40, 'branch': 'nc-work/t1',
                     'proxy': 'ncw-t1-egress', 'volumes': ['ncw-t1-work', 'ncw-t1-home']}
        mod.save(self.state / 'tasks/t1.json', self.meta)

    def fake_docker(self, head, dirty='', remote=''):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            out = b''
            if cmd[:2] == ['docker', 'run'] and 'rev-parse' in cmd: out = head.encode()
            elif cmd[:2] == ['docker', 'run'] and 'status' in cmd: out = dirty.encode()
            elif cmd[:2] == ['git', '-c'] and 'ls-remote' in cmd: out = remote.encode()
            elif 'inspect' in cmd and '{{.Id}}' in cmd: out = ('id-' + cmd[-1]).encode()
            elif cmd[:3] == ['docker', 'ps', '-aq']: out = b'id-ncw-t1\nid-ncw-t1-egress'
            elif cmd[:3] == ['docker', 'network', 'ls']: out = b'id-ncw-t1'
            return Mock(returncode=0, stdout=out)
        return calls, fake

    def test_unpublished_commits_block_removal(self):
        calls, fake = self.fake_docker(head='c' * 40)
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaisesRegex(ValueError, 'not on GitHub'): mod.remove('t1')
        self.assertFalse(any(c[:3] == ['docker', 'rm', '-f'] for c in calls))
        self.assertTrue((self.state / 'tasks/t1.json').exists())

    def test_uncommitted_changes_block_removal(self):
        calls, fake = self.fake_docker(head='b' * 40, dirty=' M a.txt')
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaisesRegex(ValueError, 'uncommitted'): mod.remove('t1')

    def test_published_or_untouched_tasks_are_removed(self):
        for head, remote in [('b' * 40, ''), ('c' * 40, 'c' * 40 + '\trefs/heads/nc-work/t1')]:
            mod.save(self.state / 'tasks/t1.json', self.meta)
            calls, fake = self.fake_docker(head=head, remote=remote)
            with patch.object(mod.subprocess, 'run', side_effect=fake):
                mod.remove('t1')
            self.assertEqual(sorted(c[-1] for c in calls if c[:3] == ['docker', 'rm', '-f']), ['id-ncw-t1', 'id-ncw-t1-egress'])
            self.assertEqual([c[-1] for c in calls if c[:3] == ['docker', 'network', 'rm']], ['id-ncw-t1'])
            self.assertIn(['docker', 'volume', 'rm', 'ncw-t1-work'], calls)
            self.assertFalse((self.state / 'tasks/t1.json').exists())
            # the workspace is only ever mounted read-only and offline for the check
            check = next(c for c in calls if c[:2] == ['docker', 'run'])
            self.assertIn('none', check); self.assertTrue(any(a.endswith(',readonly') for a in check))

    def test_both_reasons_are_named_and_requests_can_be_dropped_without_losing_commits(self):
        outbox = mod.memory_outbox('t1'); (outbox / 'r.json').write_text('{}'); (outbox / 'r.json.reason').write_text('x\n')
        calls, fake = self.fake_docker(head='c' * 40)  # an unpublished commit and a rejected request
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaises(ValueError) as both: mod.remove('t1')
            with self.assertRaises(ValueError) as work: mod.remove('t1', discard_memory=True)
        self.assertIn('not on GitHub', str(both.exception)); self.assertIn('1 memory request', str(both.exception))
        self.assertIn('--discard-memory', str(both.exception))
        self.assertIn('not on GitHub', str(work.exception)); self.assertNotIn('memory', str(work.exception))
        self.assertFalse(any(c[:3] == ['docker', 'rm', '-f'] for c in calls))
        self.assertTrue((outbox / 'r.json').exists()); self.assertTrue((self.state / 'tasks/t1.json').exists())
        calls, fake = self.fake_docker(head='c' * 40, remote='c' * 40 + '\trefs/heads/nc-work/t1')  # now published
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch('builtins.print'):
            with self.assertRaisesRegex(ValueError, 'memory request'): mod.remove('t1')
            mod.remove('t1', discard_memory=True)
        self.assertTrue(any(c[:2] == ['docker', 'run'] for c in calls))  # the work check still ran
        self.assertFalse((self.state / 'memory/t1').exists()); self.assertFalse((self.state / 'tasks/t1.json').exists())

    def test_no_docker_means_no_removal_without_force(self):
        def fake(cmd, **kw):
            return Mock(returncode=1, stdout=b'')  # docker does not answer: every volume looks absent
        with patch.object(mod.subprocess, 'run', side_effect=fake) as call:
            for kw in [{}, {'discard_memory': True}]:
                with self.assertRaisesRegex(ValueError, 'Docker does not answer – work check not possible'): mod.remove('t1', **kw)
        self.assertTrue((self.state / 'tasks/t1.json').exists())
        self.assertFalse(any(c.args[0][:3] == ['docker', 'volume', 'rm'] for c in call.call_args_list))

    def test_failed_memory_cleanup_keeps_the_task_record(self):
        mod.memory_outbox('t1')
        calls, fake = self.fake_docker(head='b' * 40)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.shutil, 'rmtree', side_effect=OSError('busy')):
            with self.assertRaises(OSError): mod.remove('t1')
        self.assertTrue((self.state / 'tasks/t1.json').exists())  # remove can run again

    def test_force_skips_the_check(self):
        calls, fake = self.fake_docker(head='c' * 40)
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            mod.remove('t1', force=True)
        self.assertFalse(any(c[:2] == ['docker', 'run'] for c in calls))
        self.assertIn(['docker', 'rm', '-f', 'id-ncw-t1'], calls)

class MemoryTests(unittest.TestCase):
    """The task's memory: a read-only view of MEMORY.md, global/ and the own project, a writable outbox, and
    nc-harness applying the outbox with the project from the task record."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.state, self.memory = root / 'state', root / 'memory'
        (self.state / 'tasks').mkdir(parents=True)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'MEMORY', self.memory)]:
            p.start(); self.addCleanup(p.stop)
        m = self.memory
        (m / 'global/sub').mkdir(parents=True); (m / 'projects').mkdir(); (m / 'journal').mkdir()
        (m / 'MEMORY.md').write_text('# Index\n')
        (m / 'global/tools.md').write_text('tools\n')
        (m / 'global/sub/more.md').write_text('more\n')
        (m / 'global/notes.txt').write_text('not markdown\n')
        (m / 'projects/example-site.md').write_text('own\n')
        (m / 'projects/example-app.md').write_text('foreign\n')
        (m / 'journal/2026-11-13.md').write_text('journal\n')
        (m / 'global/leak.md').symlink_to(m / 'projects/example-app.md')
        (m / 'global/leakdir').symlink_to(m / 'projects', target_is_directory=True)

    def files(self, root):
        return sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())

    def test_view_holds_only_index_shared_files_and_the_own_project(self):
        view = mod.memory_view('t1', 'example-site')
        self.assertEqual(self.files(view), ['MEMORY.md', 'global/sub/more.md', 'global/tools.md', 'projects/example-site.md'])
        self.assertFalse(any(p.is_symlink() for p in view.rglob('*')))
        self.assertEqual((view / 'MEMORY.md').stat().st_mode & 0o777, 0o644)

    def test_refresh_rewrites_the_view_in_place(self):
        view = mod.memory_view('t1', 'example-site')
        inode = view.stat().st_ino
        (self.memory / 'projects/example-site.md').write_text('own, newer\n')
        (self.memory / 'global/tools.md').unlink()
        mod.memory_view('t1', 'example-site')
        self.assertEqual(view.stat().st_ino, inode)  # the running container's bind mount keeps seeing it
        self.assertEqual((view / 'projects/example-site.md').read_text(), 'own, newer\n')
        self.assertFalse((view / 'global/tools.md').exists())

    def test_missing_memory_gives_an_empty_view_and_a_warning(self):
        mod.shutil.rmtree(self.memory)
        with patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err:
            view = mod.memory_view('t1', 'example-site')
        self.assertEqual(self.files(view), [])
        self.assertIn('is missing or empty', err.getvalue())

    def test_view_is_mounted_read_only_and_the_outbox_writable(self):
        view, outbox = mod.memory_view('t1', 'example-site'), mod.memory_outbox('t1')
        args = mod.memory_mounts(view, outbox)
        mounts = [args[i + 1] for i, a in enumerate(args) if a == '--mount']
        self.assertEqual(mounts, [f'type=bind,src={view},dst=/opt/nc-memory,readonly',
                                  f'type=bind,src={outbox},dst=/opt/nc-memory-outbox'])
        self.assertIn('NC_MEMORY_DIR=/opt/nc-memory', args)
        self.assertIn('NC_MEMORY_OUTBOX=/opt/nc-memory-outbox', args)
        self.assertEqual(outbox.stat().st_mode & 0o777, 0o777)
        self.assertEqual(view.parent.stat().st_mode & 0o777, 0o700)

    def test_apply_takes_the_project_from_the_task_record_not_the_request(self):
        mod.memory_view('t1', 'example-site'); outbox = mod.memory_outbox('t1')
        (outbox / 'r.json').write_text(json.dumps({'v': 1, 'ts': '2026-11-13T10:00:00Z', 'text': 'x', 'project': 'example-app'}))
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0)) as call, patch('builtins.print'):
            self.assertTrue(mod.memory_apply({'id': 't1', 'project': 'example-site', 'memory': True}))
        args = call.call_args[0][0]
        self.assertEqual(args[0], str(mod.HARNESS / 'bin/nc'))
        self.assertEqual(args[1:], ['memory', 'apply', '--outbox', str(outbox), '--project', 'example-site'])
        with self.assertRaisesRegex(ValueError, 'without memory'):
            mod.memory_apply({'id': 't1', 'project': 'example-site'})

    def test_create_refuses_a_leftover_memory_folder(self):
        (self.state / 'memory/t2/outbox').mkdir(parents=True)
        (self.state / 'memory/t2/outbox/r.json').write_text('{}')
        with patch.object(mod.subprocess, 'run') as call:
            with self.assertRaisesRegex(ValueError, 'memory folder of an earlier task t2'): mod.create({'id': 'example-app'}, 't2')
        call.assert_not_called()

    def test_report_mentions_pending_requests(self):
        mod.memory_outbox('t1').joinpath('r.json').write_text('{}')
        with patch.object(mod, 'dex', side_effect=mod.subprocess.CalledProcessError(1, 'git')), \
             patch('sys.stdout', new_callable=io.StringIO) as out:
            mod.report({'id': 't1', 'base': 'b' * 40, 'branch': 'nc-work/t1'})
        self.assertIn('1 memory request(s) in the outbox', out.getvalue())
        self.assertIn('nc-work memory-apply t1', out.getvalue())

    def test_pending_requests_block_removal_and_force_cleans_up(self):
        mod.memory_view('t1', 'example-site'); outbox = mod.memory_outbox('t1')
        (outbox / 'r.json').write_text('{}'); (outbox / '.r.json.tmp').write_text('')
        self.assertEqual(mod.memory_pending('t1'), 1)
        mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-site'})
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=1, stdout=b'')), patch('builtins.print'):
            with self.assertRaisesRegex(ValueError, 'memory request'): mod.remove('t1')
            self.assertTrue(outbox.exists())
            mod.remove('t1', force=True)
        self.assertFalse((self.state / 'memory/t1').exists())

class AgentsTests(unittest.TestCase):
    """Per task STATE/agents/<task>/{claude,opencode}, mounted read-only, generated by the host's
    harness checkout before every session start; the orchestrator setting for nc-work claude."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.state, self.home, self.harness = root / 'state', root / 'home', root / 'harness'
        (self.state / 'tasks').mkdir(parents=True); (self.state / 'auth').mkdir()
        token = self.state / 'auth/.default.token'; token.write_text('synthetic-test-token'); token.chmod(0o600)
        self.secrets = root / 'secrets.env'
        self.secrets.write_text('OPENROUTER_API_KEY=sk-or-v1-synthetic\nOPENROUTER_API_KEY_CLIENTS=sk-or-v1-clients-synthetic\n'); self.secrets.chmod(0o600)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'HARNESS', self.harness),
                  patch.object(mod, 'SECRETS', self.secrets), patch.object(mod, 'MEMORY', root / 'no-memory'),
                  patch.object(mod.pathlib.Path, 'home', return_value=self.home)]:
            p.start(); self.addCleanup(p.stop)
        self.m = online({'id': 't1', 'project': 'example-client', 'project_path': 'clients/acme/website', 'agents': True})
        self.nc = str(self.harness / 'bin/nc')
        self.kp = KeyProxyFakes(self)

    def base(self, name='t1'): return self.state / 'agents' / name

    def session(self, runtime, m=None, generate=(0, b'', b''), orchestrator=(0, b'opus high\n', b''), during=None,
                stdin_tty=None, stderr_tty=False, policy=(0, policy_json(deny=['free']), b'')):
        """Start claude or opencode with stubbed Docker and harness calls; returns (calls, stderr). Sets self.sleeps
        (time.sleep calls) and self.at_exec (sleeps so far, whether the task lock was free) at the runtime's exec."""
        calls = []; self.sleeps = []; self.at_exec = None
        class Err(io.StringIO):
            def isatty(self): return stderr_tty
        def lock_free():
            if not (self.base() / '.lock').exists(): return None
            with (self.base() / '.lock').open('a') as other:
                try: mod.fcntl.flock(other, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB); return True
                except BlockingIOError: return False
        def answer(spec):
            if isinstance(spec, BaseException) or (isinstance(spec, type) and issubclass(spec, BaseException)): raise spec
            code, out, err = spec
            return Mock(returncode=code, stdout=out, stderr=err)
        def fake(cmd, **kw):
            calls.append((list(cmd), kw))
            if cmd[:2] == [self.nc, 'generate']:
                if during: during()
                return answer(generate)
            if cmd[:3] == [self.nc, 'models', '--json']: return answer(policy)  # the task is example-client
            if cmd[:2] == [self.nc, 'models']: return answer(orchestrator)
            if cmd[-1] == mod.OPENCODE_READY: return Mock(returncode=0)
            if cmd[:2] == ['docker', 'exec'] and any(c.startswith('/usr/local/bin/') for c in cmd):
                self.at_exec = (len(self.sleeps), lock_free())
            return Mock(returncode=0, stdout=b'', stderr=b'')
        with patch.object(mod, 'dex'), patch.object(mod, 'container_state', return_value='running'), \
             patch.object(mod.sys.stdin, 'isatty', return_value=runtime == 'claude' if stdin_tty is None else stdin_tty), \
             patch.object(mod.sys.stdout, 'isatty', return_value=False), \
             patch.object(mod.subprocess, 'run', side_effect=fake), \
             patch.object(mod.time, 'sleep', side_effect=self.sleeps.append), \
             patch.object(mod.sys, 'stderr', new=Err()) as err:
            if runtime == 'claude': mod.claude(m or self.m)
            else: mod.opencode(m or self.m)
        return calls, err.getvalue()

    def started(self, calls, binary):
        return next((c for c, _ in calls if c[:2] == ['docker', 'exec'] and binary in c), None)

    def fill(self):
        mod.agents_folders('t1')
        for sub in ['claude', 'opencode']: (self.base() / sub / 'tester.md').write_text('old\n')

    def test_generate_call_is_the_host_checkout_with_absolute_paths(self):
        calls, err = self.session('claude')
        gen = [(c, kw) for c, kw in calls if c[:2] == [self.nc, 'generate']]
        self.assertEqual(len(gen), 1)
        cmd, kw = gen[0]
        self.assertEqual(cmd, [self.nc, 'generate', '--out', str(self.base()), '--path', str(self.home / 'projects/clients/acme/website')])
        self.assertTrue(pathlib.Path(cmd[3]).is_absolute() and pathlib.Path(cmd[5]).is_absolute())
        self.assertEqual((kw['cwd'], kw['timeout']), ('/', 60))
        self.assertEqual((kw['stdout'], kw['stderr']), (mod.subprocess.PIPE, mod.subprocess.PIPE))  # not before the start
        self.assertEqual(err, '')

    def test_folders_are_0755_whatever_the_umask(self):
        old = mod.os.umask(0o077)
        try: self.assertTrue(mod.agents_folders('t1'))
        finally: mod.os.umask(old)
        for sub in ['claude', 'opencode']: self.assertEqual((self.base() / sub).stat().st_mode & 0o777, 0o755)

    TAG = 'c' * 40 + '-0123456789ab'  # a snapshot with overlay files

    def create(self, name='t2'):
        calls = []; self.at_run = None
        def fake(cmd, **kw):
            cmd = [str(c) for c in cmd]; calls.append(cmd)
            if cmd[:3] == ['docker', 'run', '-d'] and 'ncw-' + name in cmd:
                self.at_run = ((self.base(name) / 'claude').is_dir(), (self.base(name) / 'opencode').is_dir())
            if cmd[:3] == ['git', '-C', cmd[2]] and 'bundle' in cmd: pathlib.Path(cmd[-2]).write_bytes(b'bundle')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        mod.save(self.state / 'harness-current.json', {'commit': self.TAG})
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'stderr', new_callable=io.StringIO):
            mod.create(mod.profile('example-site'), name, offline=True, quiet=True)
        return calls

    def test_create_mounts_folders_sets_environment_prepares_home_and_records_the_task(self):
        calls = self.create()
        helper = next(c for c in calls if c[:2] == ['docker', 'run'] and '0:0' in c)
        self.assertIn('chown 1000:1000 /workspace /home/agent && mkdir -p /home/agent/.claude/agents '
                      '&& chown 1000:1000 /home/agent/.claude /home/agent/.claude/agents', helper[-1])
        agent = next(c for c in calls if c[:3] == ['docker', 'run', '-d'] and 'ncw-t2' in c)
        mounts = [agent[i + 1] for i, a in enumerate(agent) if a == '--mount']
        claude_dir, opencode_dir = self.base('t2') / 'claude', self.base('t2') / 'opencode'
        self.assertEqual(mounts[-4:-2], [f'type=bind,src={claude_dir},dst=/home/agent/.claude/agents,readonly',
                                         f'type=bind,src={opencode_dir},dst=/etc/opencode/agents,readonly'])
        self.assertLess(mounts.index(next(x for x in mounts if 'nc-memory-outbox' in x)), mounts.index(mounts[-4]))
        self.assertIn('NC_AGENTS=/home/agent/.claude/agents:/etc/opencode/agents', agent)
        self.assertIn('NC_PROJECT_PATH=sites/example-site', agent)
        self.assertIn(f'type=bind,src={self.state / "harness" / self.TAG},dst=/opt/nc-harness,readonly', mounts)
        self.assertIn('NC_HARNESS_VERSION=' + self.TAG, agent)
        self.assertIn(['/usr/bin/git', 'config', 'user.name', 'nc-work'], [c[-4:] for c in calls])
        for d in [claude_dir, opencode_dir]: self.assertEqual(d.stat().st_mode & 0o777, 0o755)
        meta = mod.task('t2')
        self.assertEqual((meta['agents'], meta['project_path']), (True, 'sites/example-site'))
        self.assertFalse(any(c[:2] == [self.nc, 'generate'] for c in calls))  # the first session start generates
        self.assertEqual(self.at_run, (True, True))  # a missing bind source would stop docker run

    def test_create_refuses_a_leftover_agents_folder(self):
        self.base('t2').mkdir(parents=True)
        with patch.object(mod.subprocess, 'run') as call:
            with self.assertRaisesRegex(ValueError, 'agents folder of an earlier task t2.*nc-work remove t2'):
                mod.create(mod.profile('example-site'), 't2')
        call.assert_not_called()

    def test_create_without_own_addresses_creates_nothing(self):
        with patch.object(mod, 'own_addresses', side_effect=ValueError('no global address found')), \
             patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'', stderr=b'')) as call:
            with self.assertRaisesRegex(ValueError, 'no global address found'):
                mod.create(mod.profile('example-site'), 't3')
        made = [c.args[0] for c in call.call_args_list if c.args and 'docker' in c.args[0][:1]]
        self.assertFalse([m for m in made if 'create' in m or 'run' in m], made)  # no volume, network or container

    def test_offline_create_does_not_need_own_addresses(self):
        with patch.object(mod, 'own_addresses', side_effect=ValueError('no public address found')) as own:
            calls = self.create('t4')
        own.assert_not_called()
        self.assertTrue(any(c[:3] == ['docker', 'run', '-d'] and 'ncw-t4' in c for c in calls))

    def remove_fake(self, cmd, **kw):
        return Mock(returncode=0 if 'version' in cmd else 1, stdout=b'', stderr=b'')

    def test_remove_deletes_the_folder_also_without_a_task_record(self):
        self.fill()
        with patch.object(mod.subprocess, 'run', side_effect=self.remove_fake), patch('builtins.print'):
            mod.remove('t1')
        self.assertFalse(self.base().exists())

    def test_remove_reports_a_failure_in_one_line(self):
        self.fill()
        with patch.object(mod.subprocess, 'run', side_effect=self.remove_fake), patch.object(mod.shutil, 'rmtree', side_effect=PermissionError(13, 'Permission denied')), \
             patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err, patch('sys.stdout', new_callable=io.StringIO):
            mod.remove('t1')
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertIn('agents folder', err.getvalue())

    def test_start_and_here_create_missing_folders_before_docker_start(self):
        mod.save(self.state / 'tasks/t1.json', {**self.m, 'status': 'ready', 'proxy': None, 'base': 'b' * 40, 'branch': 'nc-work/t1'})
        seen = []
        def fake(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[:2] == ['docker', 'start']: seen.append((self.base() / 'claude').is_dir() and (self.base() / 'opencode').is_dir())
            return Mock(returncode=0, stdout=b'', stderr=b'')
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'argv', ['nc-work', 'start', 't1']):
            mod.main()
        self.assertEqual(seen, [True])
        mod.shutil.rmtree(self.base()); seen.clear()
        (self.home / 'projects/clients/acme/website').mkdir(parents=True)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod, 'container_state', return_value='stopped'), \
             patch.object(mod, 'ask', return_value='1'), patch.object(mod, 'make_room'), patch.object(mod, 'claude'), patch.object(mod, 'report'), \
             patch.object(mod.sys.stdin, 'isatty', return_value=True), patch('builtins.print'):
            mod.here('example-client')
        self.assertEqual(seen, [True])

    def test_start_of_a_task_without_agents_makes_no_agents_folder(self):
        mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-site', 'status': 'ready', 'proxy': None,
                                                'base': 'b' * 40, 'branch': 'nc-work/t1'})
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'', stderr=b'')) as call, \
             patch.object(mod.sys, 'argv', ['nc-work', 'start', 't1']):
            mod.main()
        self.assertTrue(any([str(c) for c in a.args[0]][:2] == ['docker', 'start'] for a in call.call_args_list))
        self.assertFalse((self.state / 'agents').exists())

    def test_a_linked_task_folder_is_never_emptied(self):
        elsewhere = pathlib.Path(self.tmp.name) / 'config'; (elsewhere / 'opencode').mkdir(parents=True)
        keep = elsewhere / 'opencode/keep.json'; keep.write_text('{}')
        (self.state / 'agents').mkdir(); self.base().symlink_to(elsewhere)
        calls, err = self.session('opencode')
        self.assertTrue(keep.exists())
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertIn('is a link or not a folder', err)
        self.assertIsNotNone(self.started(calls, '/usr/local/bin/opencode'))
        mod.agents_clear(self.base() / 'opencode')  # also called directly
        self.assertTrue(keep.exists())

    def test_a_linked_subfolder_is_neither_changed_nor_emptied(self):
        mod.agents_folders('t1')
        elsewhere = pathlib.Path(self.tmp.name) / 'elsewhere'; elsewhere.mkdir(mode=0o700); (elsewhere / 'keep.md').write_text('x')
        (self.base() / 'opencode').rmdir(); (self.base() / 'opencode').symlink_to(elsewhere)
        with patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err:
            mod.agents_folders('t1')
        self.assertIn('is a link or not a folder', err.getvalue())
        self.session('opencode', generate=(2, b'', b'nc generate: is a link\n'))
        self.assertEqual(elsewhere.stat().st_mode & 0o777, 0o700)
        self.assertTrue((elsewhere / 'keep.md').exists())

    def test_claude_gets_model_and_effort_at_the_end(self):
        calls, err = self.session('claude')
        self.assertEqual(self.started(calls, '/usr/local/bin/claude')[-5:], ['/usr/local/bin/claude', '--model', 'opus', '--effort', 'high'])
        orch = next(kw for c, kw in calls if c[:2] == [self.nc, 'models'])
        self.assertEqual((orch['cwd'], orch['timeout'], orch['stdout'], orch['stderr']), ('/', 60, mod.subprocess.PIPE, mod.subprocess.PIPE))
        self.assertEqual(err, '')

    def test_orchestrator_not_set_means_no_parameters_and_no_message(self):
        calls, err = self.session('claude', orchestrator=(1, b'', b'nc models: claude_code.orchestrator is not set in models.yaml\n'))
        self.assertEqual(self.started(calls, '/usr/local/bin/claude')[-1], '/usr/local/bin/claude')
        self.assertEqual(err, '')

    def test_an_unusable_orchestrator_answer_with_exit_0_warns_once(self):
        calls, err = self.session('claude', orchestrator=(0, b'sonnet high\n', b''))
        self.assertEqual(self.started(calls, '/usr/local/bin/claude')[-1], '/usr/local/bin/claude')
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertIn('orchestrator setting not read (nc models orchestrator: Exit 0, sonnet high)', err)

    def test_old_checkout_warns_once_per_call_without_the_help_text(self):
        help_text = b'nc generate: unknown argument "--out" (nc generate [--check])\n\nUsage:\n  nc generate [--check]\n'
        old_models = b'\nnc models: unknown command orchestrator\n\nUsage:\n  nc models show\n'
        calls, err = self.session('claude', generate=(2, b'', help_text), orchestrator=(2, b'', old_models))
        lines = err.strip().splitlines()
        self.assertEqual(len(lines), 2, err)
        self.assertIn('agents not generated (nc generate: Exit 2, nc generate: unknown argument "--out" (nc generate [--check])) – the roles of the last start stay', lines[0])
        self.assertIn('orchestrator setting not read (nc models orchestrator: Exit 2, nc models: unknown command orchestrator) – Claude starts without --model and --effort', lines[1])
        self.assertNotIn('Usage', err)
        self.assertEqual(self.started(calls, '/usr/local/bin/claude')[-1], '/usr/local/bin/claude')
        calls, err = self.session('opencode', generate=(2, b'', help_text))
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertIn('– OpenCode starts without roles', err)
        self.assertIsNotNone(self.started(calls, '/usr/local/bin/opencode'))

    def test_os_error_and_timeout_still_start_the_session(self):
        for failure, text in [(OSError(2, 'No such file or directory'), 'No such file or directory'),
                              (mod.subprocess.TimeoutExpired('nc', 60), 'timeout')]:
            calls, err = self.session('claude', generate=failure, orchestrator=failure)
            self.assertEqual(len(err.strip().splitlines()), 2, err)
            self.assertIn(text, err)
            self.assertEqual(self.started(calls, '/usr/local/bin/claude')[-1], '/usr/local/bin/claude')
            calls, err = self.session('opencode', generate=failure)
            self.assertEqual(len(err.strip().splitlines()), 1, err)
            self.assertIsNotNone(self.started(calls, '/usr/local/bin/opencode'))

    def test_failed_generation_empties_opencode_in_place_before_opencode_only(self):
        self.fill()
        inode = (self.base() / 'opencode').stat().st_ino
        self.session('claude', generate=(2, b'', b'nc generate: models.yaml: not valid YAML\n'))
        for sub in ['claude', 'opencode']: self.assertEqual((self.base() / sub / 'tester.md').read_text(), 'old\n')
        self.session('opencode', generate=(2, b'', b'nc generate: models.yaml: not valid YAML\n'))
        self.assertEqual(list((self.base() / 'opencode').iterdir()), [])
        self.assertEqual((self.base() / 'opencode').stat().st_ino, inode)
        self.assertEqual((self.base() / 'claude' / 'tester.md').read_text(), 'old\n')

    def test_the_lock_is_held_while_generating_and_released_before_the_session(self):
        held = []
        def probe():
            with (self.base() / '.lock').open('a') as other:
                try: mod.fcntl.flock(other, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB); held.append(False)
                except BlockingIOError: held.append(True)
        self.session('claude', during=probe)
        self.assertEqual(held, [True])
        with (self.base() / '.lock').open('a') as other:
            mod.fcntl.flock(other, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)  # free again

    def test_the_lock_is_free_at_docker_exec(self):
        for runtime in ['claude', 'opencode']:
            self.session(runtime)
            self.assertEqual(self.at_exec[1], True, runtime)
            self.session(runtime, generate=(2, b'', b'nc generate: broken\n'))
            self.assertEqual(self.at_exec[1], True, runtime)

    def test_warning_lines_stay_three_seconds_before_the_start_in_a_terminal(self):
        broken = (2, b'', b'nc generate: models.yaml: not valid YAML\n')
        for runtime in ['claude', 'opencode']:
            _, err = self.session(runtime, generate=broken, stdin_tty=True, stderr_tty=True)
            self.assertIn('warning', err)
            self.assertEqual((self.sleeps, self.at_exec[0]), ([3], 1), runtime)  # waited before docker exec
            _, err = self.session(runtime, stdin_tty=True, stderr_tty=True)
            self.assertEqual((err, self.sleeps), ('', []), runtime)              # no warning: no wait
            for stdin_tty, stderr_tty in [(True, False), (False, True)]:         # no terminal: no wait
                if runtime == 'claude' and not stdin_tty: continue               # Claude needs one on stdin anyway
                _, err = self.session(runtime, generate=broken, stdin_tty=stdin_tty, stderr_tty=stderr_tty)
                self.assertIn('warning', err)
                self.assertEqual(self.sleeps, [], (runtime, stdin_tty, stderr_tty))
        _, err = self.session('claude', orchestrator=(2, b'', b'broken\n'), stdin_tty=True, stderr_tty=True)
        self.assertEqual((len(err.strip().splitlines()), self.sleeps), (1, [3]))  # the orchestrator warning alone too

    def test_a_task_without_agents_calls_none_of_it(self):
        old = online({'id': 't1', 'project': 'example-site'})
        for runtime in ['claude', 'opencode']:
            calls, err = self.session(runtime, m=old)
            # no nc generate; nc models --json belongs to every OpenCode start (the key depends on the policy)
            self.assertEqual([c[1:3] for c, _ in calls if c[0] == self.nc], [] if runtime == 'claude' else [['models', '--json']])
            self.assertEqual(err, '')
            self.assertEqual(self.started(calls, f'/usr/local/bin/{runtime}')[-1], f'/usr/local/bin/{runtime}')
        self.assertFalse((self.state / 'agents').exists())

class WorkerTests(unittest.TestCase):
    """Worker tasks for nc delegate (profiles --json, create --worker, export, remove --delivered)."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(self.tmp.name))
        self.state, self.home, self.harness = self.root / 'state', self.root / 'home', self.root / 'harness'
        (self.state / 'tasks').mkdir(parents=True)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'HARNESS', self.harness),
                  patch.object(mod, 'MEMORY', self.root / 'no-memory'), patch.object(mod.pathlib.Path, 'home', return_value=self.home)]:
            p.start(); self.addCleanup(p.stop)

    def test_profiles_json_is_one_sorted_line_and_the_text_stays(self):
        for flag, check in [(['--json'], True), ([], False)]:
            with patch.object(mod.sys, 'argv', ['nc-work', 'profiles', *flag]), patch('sys.stdout', new_callable=io.StringIO) as out:
                mod.main()
            if check:
                self.assertEqual(len(out.getvalue().splitlines()), 1)
                data = json.loads(out.getvalue())
                self.assertEqual([p['id'] for p in data], ['example-app', 'example-client', 'example-site'])
                self.assertEqual([p['id'] for p in data], sorted(p['id'] for p in data))
                for p in data:
                    self.assertEqual(set(p), {'id', 'path', 'github'}); self.assertEqual(p['path'], mod.profile(p['id'])['path'])
            else:
                self.assertTrue(out.getvalue().startswith(data[0]['id'] + ' Node '))

    def create(self, name='w1', worker=True):
        calls = []
        def fake(cmd, **kw):
            cmd = [str(c) for c in cmd]; calls.append(cmd)
            if cmd[:3] == ['git', '-C', cmd[2]] and 'bundle' in cmd: pathlib.Path(cmd[-2]).write_bytes(b'bundle')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        mod.save(self.state / 'harness-current.json', {'commit': 'c' * 40})
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'stderr', new_callable=io.StringIO):
            mod.create(mod.profile('example-site'), name, offline=True, quiet=True, worker=worker)
        return calls

    def test_create_worker_records_it_and_mounts_no_memory(self):
        calls = self.create()
        agent = next(c for c in calls if c[:3] == ['docker', 'run', '-d'] and 'ncw-w1' in c)
        self.assertFalse(any('nc-memory' in a or a.startswith('NC_MEMORY_') for a in agent))
        mounts = [agent[i + 1] for i, a in enumerate(agent) if a == '--mount']
        self.assertTrue(any(m.endswith('dst=/home/agent/.claude/agents,readonly') for m in mounts))
        self.assertTrue(any(m.endswith('dst=/etc/opencode/agents,readonly') for m in mounts))
        self.assertIn('NC_PROJECT_PATH=sites/example-site', agent)
        self.assertFalse((self.state / 'memory/w1').exists())
        meta = mod.task('w1')
        self.assertEqual((meta['worker'], meta['memory'], meta['agents']), (True, False, True))
        self.create('t2', worker=False)  # a normal task is unchanged: memory mounted, no worker field
        self.assertNotIn('worker', mod.task('t2')); self.assertTrue(mod.task('t2')['memory'])
        self.assertTrue((self.state / 'memory/t2/outbox').is_dir())

    def test_three_running_tasks_refuse_before_saving(self):
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'a\nb\nc\n')):
            with self.assertRaisesRegex(mod.TooManyTasks, '^3 tasks are already running; stop one first \\(nc-work stop <task>\\)$'):
                mod.create(mod.profile('example-site'), 'w1', worker=True)
        self.assertTrue(issubclass(mod.TooManyTasks, ValueError))
        self.assertFalse((self.state / 'tasks/w1.json').exists())

    def test_three_running_tasks_exit_3(self):
        bin_dir = self.root / 'bin'; bin_dir.mkdir()
        docker = bin_dir / 'docker'
        docker.write_text('#!/bin/sh\nif [ "$1" = ps ]; then printf "a\\nb\\nc\\n"; exit 0; fi\nexit 99\n'); docker.chmod(0o755)
        env = {**os.environ, 'HOME': str(self.home), 'PATH': f'{bin_dir}:{os.environ["PATH"]}'}
        for extra in [['--worker'], []]:
            r = subprocess.run([sys.executable, str(path), 'create', 'example-site', 'w1', *extra], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn('nc-work: 3 tasks are already running', r.stderr.decode())
        self.assertFalse((self.home / '.local/share/nc-work/tasks/w1.json').exists())

    # --- export -------------------------------------------------------------------------------------------------

    def fixture(self):
        """A source repo with base, the worker branch (one commit more) and an unrelated branch."""
        src = self.root / 'src'
        g = ['git', '-C', str(src), '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', '-c', 'core.hooksPath=/dev/null']
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(src)], check=True)
        (src / 'a.txt').write_text('a\n'); subprocess.run([*g, 'add', 'a.txt'], check=True)
        subprocess.run([*g, 'commit', '-qm', 'base'], check=True)
        base = subprocess.run([*g, 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
        subprocess.run([*g, 'switch', '-qc', 'other'], check=True)
        (src / 'o.txt').write_text('o\n'); subprocess.run([*g, 'add', 'o.txt'], check=True); subprocess.run([*g, 'commit', '-qm', 'o'], check=True)
        subprocess.run([*g, 'switch', '-q', 'main'], check=True); subprocess.run([*g, 'switch', '-qc', 'nc-work/w1'], check=True)
        (src / 'b.txt').write_text('b\n'); subprocess.run([*g, 'add', 'b.txt'], check=True); subprocess.run([*g, 'commit', '-qm', 'work'], check=True)
        head = subprocess.run([*g, 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
        return src, base, head

    def export(self, meta=None, state='running', result=b'STATUS: done\n', dirty='', stat_size=None, out=None, bad=False):
        """mod.export with a fake container: docker exec runs against the fixture repo and a RESULT.md in a temp
        folder (the real RESULT_READ script); host git runs for real. Returns (export.json or exception, calls)."""
        src, self.base_sha, self.head_sha = self.fixture()
        if bad:  # the worker branch gets a commit with a malformed author line on top
            g = ['git', '-C', str(src)]
            tree = subprocess.run([*g, 'rev-parse', 'HEAD^{tree}'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
            raw = f'tree {tree}\nparent {self.head_sha}\nauthor bad <x 1 +0000\ncommitter t <t@t.invalid> 1 +0000\n\nbad\n'
            bad_sha = subprocess.run([*g, 'hash-object', '-t', 'commit', '--literally', '-w', '--stdin'], input=raw.encode(),
                                     check=True, stdout=subprocess.PIPE).stdout.decode().strip()
            subprocess.run([*g, 'update-ref', 'refs/heads/nc-work/w1', bad_sha], check=True)
        cbundle = self.root / 'container-bundle'
        cres = self.root / 'container-home/.nc'; cres.mkdir(parents=True)
        if result is not None: (cres / 'RESULT.md').write_bytes(result)
        self.rm_called = False
        calls, real_run, real_popen = [], subprocess.run, subprocess.Popen
        def fake_run(cmd, **kw):
            cmd = [str(c) for c in cmd]; calls.append(cmd)
            if cmd[0] != 'docker': return real_run(cmd, **kw)
            if 'bundle' in cmd and 'create' in cmd:  # a container that bundles more than asked for
                real_run(['git', '-C', str(src), 'bundle', 'create', '-q', str(cbundle), 'refs/heads/nc-work/w1', 'refs/heads/other'], check=True)
                return Mock(returncode=0, stdout=b'', stderr=b'')
            if '/usr/bin/stat' in cmd:
                return Mock(returncode=0, stdout=str(stat_size if stat_size is not None else cbundle.stat().st_size).encode(), stderr=b'')
            if '/bin/rm' in cmd: self.rm_called = True; return Mock(returncode=0, stdout=b'', stderr=b'')
            if 'status' in cmd: return Mock(returncode=0, stdout=dirty.encode(), stderr=b'')
            return Mock(returncode=1, stdout=b'', stderr=b'unexpected')
        def fake_popen(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[0] != 'docker': return real_popen(cmd, **kw)
            calls.append(cmd)
            if '/bin/cat' in cmd: return real_popen(['cat', str(cbundle)], **kw)
            if '/usr/bin/python3' in cmd:
                i = cmd.index('-c')
                self.assertEqual(cmd[i + 2], mod.RESULT_PATH)
                return real_popen([sys.executable, '-I', '-B', '-c', cmd[i + 1], str(cres / 'RESULT.md'), cmd[i + 3]], **kw)
            raise AssertionError(cmd)
        meta = meta or {'id': 'w1', 'project': 'example-site', 'worker': True, 'memory': False, 'base': self.base_sha}
        self.out = out or self.root / 'run/export'; self.out.parent.mkdir(exist_ok=True)
        with patch.object(mod.subprocess, 'run', side_effect=fake_run), patch.object(mod.subprocess, 'Popen', side_effect=fake_popen), \
             patch.object(mod, 'container_state', return_value=state), \
             patch('sys.stdout', new_callable=io.StringIO) as stdout:
            try: mod.export(meta, self.out)
            except ValueError as exc: return exc, calls
        self.stdout = stdout.getvalue()
        return json.loads((self.out / 'export.json').read_text()), calls

    def refs(self):
        r = subprocess.run(['git', '-C', str(self.out / 'repo.git'), 'for-each-ref', '--format=%(refname)'], stdout=subprocess.PIPE, check=True)
        return r.stdout.decode().split()

    def test_export_takes_only_the_one_branch_with_fsck_and_writes_json(self):
        data, calls = self.export()
        self.assertEqual(data, {'task': 'w1', 'branch': 'nc-work/w1', 'base': self.base_sha, 'head': self.head_sha, 'commits': 1,
                                'dirty': False, 'base_is_ancestor': True, 'result_file': 'present'})
        self.assertEqual(json.loads(self.stdout), data); self.assertEqual(len(self.stdout.splitlines()), 1)
        self.assertEqual(self.refs(), ['refs/heads/nc-work/w1'])  # 'other' was in the bundle, not fetched
        self.assertEqual((self.out / 'RESULT.raw').read_bytes(), b'STATUS: done\n')
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ['RESULT.raw', 'export.json', 'repo.git'])
        fetch = next(c for c in calls if 'fetch' in c)
        for opt in ['transfer.fsckObjects=true', 'core.hooksPath=/dev/null', 'core.fsmonitor=false', 'gc.auto=0', '--no-tags']: self.assertIn(opt, fetch)
        self.assertEqual(fetch[-1], 'refs/heads/nc-work/w1:refs/heads/nc-work/w1')
        self.assertTrue(any('verify' in c and 'bundle' in c for c in calls if c[0] == 'git'))
        create = next(c for c in calls if c[0] == 'docker' and 'create' in c)
        for opt in ['core.hooksPath=/dev/null', 'core.fsmonitor=false', 'refs/heads/nc-work/w1', '/usr/bin/git']: self.assertIn(opt, create)
        status = next(c for c in calls if c[0] == 'docker' and 'status' in c)
        self.assertIn('core.fsmonitor=false', status); self.assertIn('--no-optional-locks', status)
        for c in calls:
            if c[0] == 'docker': self.assertEqual(c[1:4], ['exec', '--user', '1000:1000'])
        self.assertTrue(self.rm_called)

    def test_export_refuses_a_bundle_with_malformed_objects(self):
        exc, calls = self.export(bad=True)  # git 2.43 lets this through a bundle fetch despite transfer.fsckObjects
        self.assertIsInstance(exc, ValueError); self.assertIn('bundle contains broken objects', str(exc))
        self.assertFalse((self.out / 'export.json').exists())
        self.assertTrue(any('fsck' in c for c in calls if c[0] == 'git'))

    def test_export_states_of_result_md_dirty_and_foreign_base(self):
        data, _ = self.export(result=None, dirty=' M b.txt\n')
        self.assertEqual((data['result_file'], data['dirty']), ('missing', True)); self.assertFalse((self.out / 'RESULT.raw').exists())
        self.tearDown_fixture()
        data, _ = self.export(result=b'x' * (70 * 1024))
        self.assertEqual(data['result_file'], 'truncated'); self.assertEqual((self.out / 'RESULT.raw').read_bytes(), b'x' * mod.RESULT_MAX)
        self.tearDown_fixture()
        data, _ = self.export(meta={'id': 'w1', 'project': 'example-site', 'worker': True, 'base': 'f' * 40})
        self.assertEqual((data['base_is_ancestor'], data['commits']), (False, None))
        self.assertFalse(any(p.name.startswith('.') for p in self.out.iterdir()))

    def tearDown_fixture(self):
        for name in ['src', 'container-bundle', 'container-home', 'run']:
            p = self.root / name
            if p.is_dir(): mod.shutil.rmtree(p)
            elif p.exists(): p.unlink()

    def test_export_only_for_running_workers_and_a_new_folder(self):
        for meta, state, msg in [({'id': 'w1', 'project': 'example-site', 'base': 'b' * 40}, 'running', 'not a worker task'),
                                 (None, 'stopped', 'is not running – export does not start it')]:
            exc, calls = self.export(meta=meta, state=state)
            self.assertIsInstance(exc, ValueError); self.assertIn(msg, str(exc))
            self.assertFalse(any(c[0] == 'docker' for c in calls)); self.assertFalse(self.out.exists())
            self.tearDown_fixture()
        out = self.root / 'exists'; out.mkdir()
        exc, calls = self.export(out=out)
        self.assertIn('already exists', str(exc)); self.assertFalse(any(c[0] == 'docker' for c in calls))

    def test_export_size_limits(self):
        exc, calls = self.export(stat_size=mod.EXPORT_MAX + 1)
        self.assertIn('larger than 200 MiB', str(exc))
        self.assertTrue(self.rm_called); self.assertFalse(any('fetch' in c for c in calls)); self.assertFalse(any('/bin/cat' in c for c in calls))
        self.tearDown_fixture()
        with patch.object(mod, 'EXPORT_MAX', 64):  # stat says small, but the copy brings more: capped while copying
            exc, calls = self.export(stat_size=10)
        self.assertIn('larger than', str(exc)); self.assertTrue(self.rm_called); self.assertFalse(any('fetch' in c for c in calls))

    def test_result_reader_follows_no_link_and_caps(self):
        home = self.root / 'h/.nc'; home.mkdir(parents=True)
        target = home / 'RESULT.md'
        def read(p=target, limit=mod.RESULT_MAX):
            r = subprocess.run([sys.executable, '-I', '-B', '-c', mod.RESULT_READ, str(p), str(limit)], stdout=subprocess.PIPE, timeout=10)
            return r.returncode, r.stdout
        self.assertEqual(read()[0], mod.RESULT_MISSING)
        target.write_bytes(b'STATUS: done\n'); self.assertEqual(read(), (0, b'STATUS: done\n'))
        target.write_bytes(b'y' * (70 * 1024)); code, out = read()
        self.assertEqual((code, len(out)), (mod.RESULT_TRUNCATED, mod.RESULT_MAX))
        target.unlink(); secret = self.root / 'secret'; secret.write_text('host secret\n'); target.symlink_to(secret)
        self.assertEqual(read(), (mod.RESULT_MISSING, b''))
        target.unlink(); os.mkfifo(target); self.assertEqual(read(), (mod.RESULT_MISSING, b''))  # no hang on a FIFO
        target.unlink(); target.mkdir(); self.assertEqual(read()[0], mod.RESULT_MISSING)
        target.rmdir(); other = self.root / 'h2'; other.mkdir(); (other / 'RESULT.md').write_text('x\n')
        mod.shutil.rmtree(home); home.symlink_to(other)  # a linked .nc folder resolves elsewhere
        self.assertEqual(read(), (mod.RESULT_MISSING, b''))
        home.unlink(); home.mkdir(); target.write_text('x\n'); target.chmod(0)
        if os.geteuid() != 0: self.assertEqual(read()[0], mod.RESULT_ERROR)

    def test_capped_exec_stops_at_the_limit_and_the_timeout(self):
        with tempfile.TemporaryFile() as f:
            code, over = mod.exec_capped(['head', '-c', '100000', '/dev/zero'], f, 1000, 10)
            self.assertTrue(over); f.seek(0); self.assertEqual(len(f.read()), 1000)
        with tempfile.TemporaryFile() as f:
            self.assertEqual(mod.exec_capped(['printf', 'abc'], f, 1000, 10), (0, False))
        with tempfile.TemporaryFile() as f:
            started = mod.time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired): mod.exec_capped(['sleep', '5'], f, 10, 0.3)
            self.assertLess(mod.time.monotonic() - started, 3)

    # --- remove --delivered, memory-apply -----------------------------------------------------------------------

    def delivered(self, meta, head='d' * 40, dirty='', docker=True, sha='d' * 40, volume=True, readable=True):
        mod.save(self.state / 'tasks/w1.json', meta)
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            if not docker: return Mock(returncode=1, stdout=b'')
            if cmd[:3] == ['docker', 'volume', 'inspect'] and not volume: return Mock(returncode=1, stdout=b'')
            if cmd[:2] == ['docker', 'run'] and 'rev-parse' in cmd and not readable: return Mock(returncode=1, stdout=b'')
            out = b''
            if cmd[:2] == ['docker', 'run'] and 'rev-parse' in cmd: out = head.encode()
            elif cmd[:2] == ['docker', 'run'] and 'status' in cmd: out = dirty.encode()
            return Mock(returncode=0, stdout=out)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch('sys.stdout', new_callable=io.StringIO):
            try: mod.remove('w1', delivered=sha)
            except ValueError as exc: return str(exc), calls
        return None, calls

    def test_remove_delivered_checks_worker_branch_workspace_and_docker(self):
        worker = {'id': 'w1', 'project': 'example-site', 'base': 'b' * 40, 'branch': 'nc-work/w1', 'worker': True,
                  'memory': False, 'proxy': 'ncw-w1-egress', 'volumes': ['ncw-w1-work', 'ncw-w1-home']}
        normal = {k: v for k, v in worker.items() if k != 'worker'}
        for meta, kw, reason in [(normal, {}, 'not a worker task'), (worker, {'head': 'e' * 40}, 'branch is at ' + 'e' * 40),
                                 (worker, {'dirty': '?? x'}, 'uncommitted changes'),
                                 (worker, {'docker': False}, 'Docker does not answer'),
                                 (worker, {'volume': False}, 'workspace not readable'),
                                 (worker, {'readable': False}, 'workspace not readable')]:
            err, calls = self.delivered(meta, **kw)
            self.assertIsNotNone(err, reason); self.assertIn('w1: not deleted – ' , err); self.assertIn(reason, err)
            self.assertFalse(any(c[:3] in (['docker', 'rm', '-f'], ['docker', 'volume', 'rm']) for c in calls))
            self.assertTrue((self.state / 'tasks/w1.json').exists())
        err, calls = self.delivered(worker)
        self.assertIsNone(err)
        self.assertFalse(any('ls-remote' in c for c in calls))  # no GitHub check
        check = next(c for c in calls if c[:2] == ['docker', 'run'])
        self.assertIn('none', check); self.assertTrue(any(a.endswith(',readonly') for a in check))
        self.assertIn(['docker', 'volume', 'rm', 'ncw-w1-work'], calls)
        self.assertFalse((self.state / 'tasks/w1.json').exists())

    def test_remove_delivered_wrong_calls(self):
        for argv in [['w1', '--delivered', 'd' * 40, '--force'], ['w1', '--delivered', 'd' * 40, '--discard-memory'],
                     ['w1', 'w2', '--delivered', 'd' * 40], ['w1', '--delivered', 'D' * 40], ['w1', '--delivered', 'd' * 39]]:
            with patch.object(mod.sys, 'argv', ['nc-work', 'remove', *argv]), patch.object(mod.subprocess, 'run') as call:
                with self.assertRaisesRegex(ValueError, 'wrong call'): mod.main()
            call.assert_not_called()

    def test_memory_apply_without_names_skips_workers(self):
        for name, extra in [('t1', {'memory': True}), ('w1', {'memory': True, 'worker': True}), ('w2', {'memory': False, 'worker': True})]:
            mod.save(self.state / f'tasks/{name}.json', {'id': name, 'project': 'example-site', **extra})
        with patch.object(mod.sys, 'argv', ['nc-work', 'memory-apply']), patch.object(mod, 'memory_apply', return_value=True) as apply:
            mod.main()
        self.assertEqual([c.args[0]['id'] for c in apply.call_args_list], ['t1'])
        with patch.object(mod.subprocess, 'run') as call:
            with self.assertRaisesRegex(ValueError, 'worker task without memory'):
                mod.memory_apply({'id': 'w1', 'project': 'example-site', 'memory': True, 'worker': True})
        call.assert_not_called()

class MailboxTests(unittest.TestCase):
    """The mailbox of a task (requests writable, inbox read-only) for nc delegate, and what remove does with it."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(self.tmp.name))
        self.state, self.home, self.harness = self.root / 'state', self.root / 'home', self.root / 'harness'
        (self.state / 'tasks').mkdir(parents=True)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'HARNESS', self.harness),
                  patch.object(mod, 'MEMORY', self.root / 'no-memory'), patch.object(mod.pathlib.Path, 'home', return_value=self.home)]:
            p.start(); self.addCleanup(p.stop)

    def create(self, name='t1', worker=False):
        calls = []
        def fake(cmd, **kw):
            cmd = [str(c) for c in cmd]; calls.append(cmd)
            if cmd[:3] == ['git', '-C', cmd[2]] and 'bundle' in cmd: pathlib.Path(cmd[-2]).write_bytes(b'bundle')
            return Mock(returncode=0, stdout=b'', stderr=b'')
        mod.save(self.state / 'harness-current.json', {'commit': 'c' * 40})
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'stderr', new_callable=io.StringIO):
            mod.create(mod.profile('example-site'), name, offline=True, quiet=True, worker=worker)
        return calls

    def test_create_mounts_requests_writable_and_inbox_read_only_with_their_modes(self):
        calls = self.create()
        agent = next(c for c in calls if c[:3] == ['docker', 'run', '-d'] and 'ncw-t1' in c)
        base = self.state / 'broker/t1'
        mounts = [agent[i + 1] for i, a in enumerate(agent) if a == '--mount']
        self.assertIn(f'type=bind,src={base / "requests"},dst=/opt/nc-requests', mounts)
        self.assertIn(f'type=bind,src={base / "inbox"},dst=/opt/nc-inbox,readonly', mounts)
        self.assertIn('NC_REQUESTS=/opt/nc-requests', agent); self.assertIn('NC_INBOX=/opt/nc-inbox', agent)
        self.assertEqual([d.stat().st_mode & 0o777 for d in [base, base / 'requests', base / 'inbox']], [0o700, 0o777, 0o755])
        meta = mod.task('t1')
        self.assertIs(meta['broker'], True); self.assertRegex(meta['broker_token'], r'^[0-9a-f]{32}$')
        self.create('t2'); self.assertNotEqual(mod.task('t2')['broker_token'], meta['broker_token'])

    def test_a_worker_gets_no_mailbox_and_no_token(self):
        calls = self.create('w1', worker=True)
        agent = next(c for c in calls if c[:3] == ['docker', 'run', '-d'] and 'ncw-w1' in c)
        self.assertFalse(any('nc-requests' in a or 'nc-inbox' in a or a.startswith('NC_REQUESTS') or a.startswith('NC_INBOX') for a in agent))
        self.assertFalse((self.state / 'broker/w1').exists())
        meta = mod.task('w1'); self.assertNotIn('broker', meta); self.assertNotIn('broker_token', meta)

    def test_a_leftover_mailbox_folder_refuses_before_anything_happens(self):
        for leftover in ['folder', 'link']:
            base = self.state / 'broker/t1'; base.parent.mkdir(exist_ok=True)
            if leftover == 'folder': base.mkdir()
            else: base.symlink_to(self.root)
            with patch.object(mod.subprocess, 'run') as call:
                with self.assertRaisesRegex(ValueError, 'mailbox folder of an earlier task t1.*nc-work remove t1'):
                    mod.create(mod.profile('example-site'), 't1')
            call.assert_not_called()
            if leftover == 'folder': base.rmdir()
            else: base.unlink()

    def test_start_and_here_make_missing_folders_only_for_mailbox_tasks(self):
        base = self.state / 'broker/t1'
        for extra, expect in [({'broker': True}, True), ({}, False)]:
            mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-site', 'status': 'ready', 'proxy': None,
                                                    'base': 'b' * 40, 'branch': 'nc-work/t1', **extra})
            seen = []
            def fake(cmd, **kw):
                if list(cmd[:2]) == ['docker', 'start']: seen.append((base / 'requests').is_dir() and (base / 'inbox').is_dir())
                return Mock(returncode=0, stdout=b'', stderr=b'')
            with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.sys, 'argv', ['nc-work', 'start', 't1']):
                mod.main()
            self.assertEqual(seen, [expect]); self.assertEqual(base.exists(), expect)
            if base.exists(): mod.shutil.rmtree(base)
        (self.home / 'projects/clients/acme/website').mkdir(parents=True)
        mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-client', 'status': 'ready', 'proxy': None, 'broker': True,
                                                'base': 'b' * 40, 'branch': 'nc-work/t1'})
        seen.clear()
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod, 'container_state', return_value='stopped'), \
             patch.object(mod, 'ask', return_value='1'), patch.object(mod, 'make_room'), patch.object(mod, 'claude'), patch.object(mod, 'report'), \
             patch.object(mod.sys.stdin, 'isatty', return_value=True), patch('builtins.print'):
            mod.here('example-client')
        self.assertEqual(seen, [True])
        link = self.root / 'elsewhere'; link.mkdir(); mod.shutil.rmtree(base); base.symlink_to(link)  # a linked folder is not touched
        with patch.object(mod.sys, 'stderr', new_callable=io.StringIO) as err: self.assertFalse(mod.broker_folders('t1'))
        self.assertIn('is a link or not a folder', err.getvalue()); self.assertEqual(list(link.iterdir()), [])

    # --- remove -------------------------------------------------------------------------------------------------

    def remove_fake(self, head='b' * 40, remote=''):
        calls = []
        def fake(cmd, **kw):
            calls.append(list(cmd)); out = b''
            if cmd[:2] == ['docker', 'run'] and 'rev-parse' in cmd: out = head.encode()
            elif cmd[:2] == ['docker', 'run'] and 'status' in cmd: out = b''
            elif cmd[:2] == ['git', '-c'] and 'ls-remote' in cmd: out = remote.encode()
            return Mock(returncode=0, stdout=out)
        return calls, fake

    def task_with_request(self, requests=('r1.json',)):
        mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-site', 'status': 'ready', 'base': 'b' * 40,
                                                'branch': 'nc-work/t1', 'proxy': None, 'volumes': ['ncw-t1-work', 'ncw-t1-home'], 'broker': True})
        mod.broker_folders('t1')
        _, req, inbox = mod.broker_paths('t1')
        for r in requests: (req / r).write_text('{}')
        (req / '.r2.json.tmp').write_text('{}'); (req / 'sub').mkdir(); (inbox / 'r0').mkdir()  # not requests
        return req

    def test_remove_deletes_the_mailbox_and_refuses_while_requests_wait(self):
        req = self.task_with_request(); calls, fake = self.remove_fake()
        self.assertEqual(mod.broker_pending('t1'), 1)
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaises(ValueError) as e: mod.remove('t1')
        self.assertIn('1 request(s) in the mailbox', str(e.exception)); self.assertIn('--discard-requests', str(e.exception))
        self.assertTrue(req.exists()); self.assertFalse(any(c[:3] == ['docker', 'rm', '-f'] for c in calls))
        (req / 'r1.json').unlink(); (self.state / 'broker-runs/staging/t1').mkdir(parents=True)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch('builtins.print'):
            mod.remove('t1')  # only a folder and a dot entry: nothing waits
        self.assertFalse((self.state / 'broker/t1').exists()); self.assertFalse((self.state / 'broker-runs/staging/t1').exists())
        self.assertFalse((self.state / 'tasks/t1.json').exists())

    def test_discard_requests_drops_them_but_keeps_the_work_check_and_force_deletes_all(self):
        req = self.task_with_request(); calls, fake = self.remove_fake(head='c' * 40)  # unpublished commit and a waiting request
        with patch.object(mod.subprocess, 'run', side_effect=fake):
            with self.assertRaises(ValueError) as both: mod.remove('t1')
            with self.assertRaises(ValueError) as work: mod.remove('t1', discard_requests=True)
        self.assertIn('not on GitHub', str(both.exception)); self.assertIn('mailbox', str(both.exception))
        self.assertIn('not on GitHub', str(work.exception)); self.assertNotIn('mailbox', str(work.exception))
        self.assertTrue((req / 'r1.json').exists()); self.assertFalse(any(c[:3] == ['docker', 'rm', '-f'] for c in calls))
        calls, fake = self.remove_fake(head='c' * 40, remote='c' * 40 + '\trefs/heads/nc-work/t1')  # published now
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch('builtins.print'):
            with self.assertRaisesRegex(ValueError, '--discard-requests'): mod.remove('t1')
            mod.remove('t1', discard_requests=True)
        self.assertTrue(any(c[:2] == ['docker', 'run'] for c in calls)); self.assertFalse((self.state / 'broker/t1').exists())
        req = self.task_with_request(); calls, fake = self.remove_fake(head='c' * 40)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch('builtins.print'):
            mod.remove('t1', force=True)
        self.assertFalse((self.state / 'broker/t1').exists()); self.assertFalse(any(c[:2] == ['docker', 'run'] for c in calls))

    def test_files_of_a_subuid_are_removed_as_container_root(self):
        self.task_with_request(); calls, fake = self.remove_fake(); real = mod.shutil.rmtree; tries = []
        def rmtree(path, *a, **kw):
            tries.append(str(path))
            if len(tries) == 1: raise PermissionError(13, 'Permission denied')
            return real(path, *a, **kw)
        with patch.object(mod.subprocess, 'run', side_effect=fake), patch.object(mod.shutil, 'rmtree', side_effect=rmtree), patch('builtins.print'):
            mod.remove('t1', discard_requests=True)
        helper = next(c for c in calls if c[:2] == ['docker', 'run'] and '0:0' in c)
        self.assertEqual(helper[-3:], ['-rf', '/m/requests', '/m/inbox']); self.assertIn('none', helper)
        self.assertIn(f'type=bind,src={self.state / "broker/t1"},dst=/m', helper)
        self.assertFalse((self.state / 'broker/t1').exists())

    def test_delivered_is_not_combined_with_discard_requests(self):
        with patch.object(mod.sys, 'argv', ['nc-work', 'remove', 'w1', '--delivered', 'd' * 40, '--discard-requests']), patch.object(mod.subprocess, 'run') as call:
            with self.assertRaisesRegex(ValueError, 'wrong call'): mod.main()
        call.assert_not_called()

class FromTaskTests(unittest.TestCase):
    """create --worker --from-task: the worker starts from the last commit of a mailbox task, after checks that leave nothing behind."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(self.tmp.name))
        self.state, self.home, self.harness = self.root / 'state', self.root / 'home', self.root / 'harness'
        (self.state / 'tasks').mkdir(parents=True)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'HARNESS', self.harness),
                  patch.object(mod, 'MEMORY', self.root / 'no-memory'), patch.object(mod.pathlib.Path, 'home', return_value=self.home)]:
            p.start(); self.addCleanup(p.stop)
        mod.save(self.state / 'harness-current.json', {'commit': 'c' * 40})

    def source(self, changed='b.txt'):
        """The requester's workspace: an old base commit, then one with `changed` on top. Returns (repo, old base, head)."""
        src = self.root / 'src'
        g = ['git', '-C', str(src), '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', '-c', 'core.hooksPath=/dev/null']
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(src)], check=True)
        def commit(path, msg):
            (src / path).parent.mkdir(parents=True, exist_ok=True); (src / path).write_text(msg + '\n')
            subprocess.run([*g, 'add', path], check=True); subprocess.run([*g, 'commit', '-qm', msg], check=True)
            return subprocess.run([*g, 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
        old = commit('a.txt', 'base')
        return src, old, commit(changed, 'work')

    def go(self, changed='b.txt', meta=None, state='running', dirty='', stat_size=None, worker_head=None, from_task='req', worker=True, project='example-site', fault=None):
        """create with a fake docker (the requester's container is the fixture repo, the worker's is a recorder); host git runs for real.
        Returns (exception or None, calls)."""
        src, self.old, self.head = self.source(changed)
        cbundle = self.root / 'container-bundle'
        entry = {'id': 'req', 'project': 'example-site', 'status': 'ready', 'broker': True, 'broker_token': 'a' * 32, 'base': self.old,
                 'branch': 'nc-work/req', 'proxy': None, 'volumes': [], 'project_path': 'sites/example-site'}
        mod.save(self.state / 'tasks/req.json', meta(entry) if meta else entry)
        calls, real_run, real_popen = [], subprocess.run, subprocess.Popen
        self.removed = False; self.worker_bundle = self.root / 'worker.bundle'; self.exec_timeouts = []
        def fake_run(cmd, **kw):
            cmd = [str(c) for c in cmd]; calls.append(cmd)
            if cmd[0] != 'docker': return real_run(cmd, **kw)
            ok = lambda out=b'': Mock(returncode=0, stdout=out, stderr=b'')
            if cmd[:3] == ['docker', 'exec', '-i']:
                self.worker_bundle.write_bytes(kw['stdin'].read()); return ok()
            if cmd[:2] == ['docker', 'exec'] and 'ncw-w1' in cmd:
                return ok((worker_head or self.head).encode()) if 'rev-parse' in cmd else ok()
            if cmd[:2] == ['docker', 'exec']:
                self.assertEqual(cmd[2:4], ['--user', '1000:1000'])
                self.exec_timeouts.append(kw.get('timeout'))
                step = 'status' if 'status' in cmd else 'bundle' if 'bundle' in cmd and 'create' in cmd else None
                if fault == step + '-timeout' if step else False: raise subprocess.TimeoutExpired(cmd, kw.get('timeout'))
                if fault == step + '-fail' if step else False: return Mock(returncode=128, stdout=b'', stderr=b'fatal: broken\n')
                if fault == 'broken-bundle' and step == 'bundle': cbundle.write_bytes(b'not a bundle\n'); return ok()
                if 'bundle' in cmd and 'create' in cmd:
                    real_run(['git', '-C', str(src), 'bundle', 'create', '-q', str(cbundle), *cmd[cmd.index('create') + 2:]], check=True); return ok()
                if '/usr/bin/stat' in cmd: return ok(str(stat_size if stat_size is not None else cbundle.stat().st_size).encode())
                if '/bin/rm' in cmd: self.removed = True; return ok()
                if 'status' in cmd: return ok(dirty.encode())
                return Mock(returncode=1, stdout=b'', stderr=b'unexpected')
            return ok()
        def fake_popen(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[0] != 'docker': return real_popen(cmd, **kw)
            calls.append(cmd); self.assertIn('/bin/cat', cmd)
            return real_popen(['cat', str(cbundle)], **kw)
        real_bare = mod.bare_git
        def bare(repo, *cmd):  # head-not-commit: the fetched HEAD does not resolve to a commit
            if fault == 'head-not-commit' and cmd[:1] == ('rev-parse',): return Mock(returncode=0, stdout=b'4b825dc642cb6eb9a060e54bf8d69288fbee4904 tree\n', stderr=b'')
            return real_bare(repo, *cmd)
        try:
            with patch.object(mod.subprocess, 'run', side_effect=fake_run), patch.object(mod.subprocess, 'Popen', side_effect=fake_popen), \
                 patch.object(mod, 'bare_git', side_effect=bare), \
                 patch.object(mod, 'container_state', return_value=state), patch.object(mod.sys, 'stderr', new_callable=io.StringIO), \
                 patch('sys.stdout', new_callable=io.StringIO) as out:
                mod.create(mod.profile(project), 'w1', offline=True, worker=worker, from_task=from_task)
            self.stdout = out.getvalue()
        except ValueError as exc: return exc, calls
        return None, calls

    # --- faults while fetching the requester's HEAD are faults (exit 1), never refusals
    def test_faults_of_status_bundle_and_head_are_value_errors_that_leave_nothing(self):
        cases = ['status-timeout', 'status-fail', 'bundle-timeout', 'bundle-fail', 'broken-bundle', 'head-not-commit']
        for fault in cases:
            with self.subTest(fault=fault):
                for f in (self.root / 'src', self.root / 'container-bundle'):
                    if f.is_dir(): mod.shutil.rmtree(f)
                    elif f.exists(): f.unlink()
                exc, calls = self.go(fault=fault)
                self.assertIsInstance(exc, ValueError); self.assertNotIsInstance(exc, mod.Refused)
                self.assertFalse((self.state / 'tasks/w1.json').exists())
                self.assertFalse(any(c[:2] == ['docker', 'volume'] for c in calls))      # nothing was made
                if fault.startswith('status'): self.assertFalse(any('bundle' in c for c in calls if c[0] == 'docker'))
                else: self.assertTrue(self.removed)                                     # the bundle in the container goes
                self.assertTrue(all(t == 120 for t in self.exec_timeouts), self.exec_timeouts)  # create --from-task: 120 s

    def test_bare_git_turns_a_timeout_into_a_value_error(self):
        with patch.object(mod.subprocess, 'run', side_effect=subprocess.TimeoutExpired('git', 300)):
            with self.assertRaisesRegex(ValueError, '^timeout in git fetch$'):
                mod.bare_git(self.root, '-c', 'transfer.fsckObjects=true', 'fetch', 'x')

    def test_the_worker_starts_from_the_requesters_head_and_the_record_says_so(self):
        exc, calls = self.go()
        self.assertIsNone(exc)
        meta = mod.task('w1')
        self.assertEqual((meta['base'], meta['from_task'], meta['from_token'], meta['worker'], meta['status']), (self.head, 'req', 'a' * 32, True, 'ready'))
        self.assertNotIn('broker', meta); self.assertEqual(json.loads(self.stdout), meta)  # the whole record, nothing else on stdout
        # the host bundle: HEAD and nc-from-task, both on the checked commit; bundle, fetch and fsck as for export
        heads = subprocess.run(['git', 'bundle', 'list-heads', str(self.worker_bundle)], check=True, stdout=subprocess.PIPE).stdout.decode()
        self.assertEqual(sorted(line.split()[1] for line in heads.splitlines()), ['HEAD', 'refs/heads/nc-from-task'])
        self.assertTrue(all(line.split()[0] == self.head for line in heads.splitlines()))
        fetch = next(c for c in calls if c[0] == 'git' and 'fetch' in c)
        for opt in ['transfer.fsckObjects=true', 'core.hooksPath=/dev/null', 'core.fsmonitor=false', '--no-tags']: self.assertIn(opt, fetch)
        self.assertEqual(fetch[-1], 'HEAD:refs/heads/nc-from-task')
        self.assertTrue(any(c[0] == 'git' and 'fsck' in c for c in calls)); self.assertTrue(any('verify' in c for c in calls if c[0] == 'git'))
        create = next(c for c in calls if c[0] == 'docker' and 'create' in c)
        for opt in ['core.hooksPath=/dev/null', 'core.fsmonitor=false', 'HEAD', '/usr/bin/git']: self.assertIn(opt, create)
        status = next(c for c in calls if c[0] == 'docker' and 'status' in c)
        for opt in ['--no-optional-locks', 'core.fsmonitor=false', 'core.hooksPath=/dev/null']: self.assertIn(opt, status)
        self.assertTrue(self.removed)  # the bundle in the requester's container is deleted
        for c in calls:
            if c[0] == 'docker' and 'ncw-req' in c: self.assertEqual(c[1:4], ['exec', '--user', '1000:1000'])
        self.assertFalse(any(str(self.home / 'projects') in a for c in calls for a in c))  # the checkout is never looked at
        self.assertFalse(any(c[:3] == ['docker', 'run', '-d'] and any('nc-requests' in a for a in c) for c in calls))
        # the worker clones the bundle, checks HEAD and only then drops the remote
        order = [c for c in calls if c[:2] == ['docker', 'exec'] and 'ncw-w1' in c]
        kinds = [next(w for w in ('clone', 'switch', 'rev-parse', 'remove') if w in c) for c in order if any(w in c for w in ('clone', 'switch', 'rev-parse', 'remove'))]
        self.assertEqual(kinds, ['clone', 'switch', 'rev-parse', 'remove'])
        # the request can be a clone of that bundle: exactly the commit
        clone = self.root / 'clone'
        subprocess.run(['git', 'clone', '-q', str(self.worker_bundle), str(clone)], check=True)
        self.assertEqual(subprocess.run(['git', '-C', str(clone), 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE).stdout.decode().strip(), self.head)

    # --- the worker takes the requester's project path, not the profile's current one
    def test_the_worker_takes_the_requesters_project_path(self):
        exc, calls = self.go(meta=lambda t: {**t, 'project_path': 'personal/old-site'})
        self.assertIsNone(exc)
        self.assertNotEqual(mod.profile('example-site')['path'], 'personal/old-site')
        self.assertEqual(mod.task('w1')['project_path'], 'personal/old-site')
        run = next(c for c in calls if c[:3] == ['docker', 'run', '-d'] and 'ncw-w1' in c)
        self.assertIn('NC_PROJECT_PATH=personal/old-site', run)
        self.assertNotIn('NC_PROJECT_PATH=' + mod.profile('example-site')['path'], run)

    def test_a_requester_without_a_valid_project_path_is_refused(self):
        """Refused: nc-work exits 4 (__main__), no fallback to the profile's path."""
        def drop(t): t.pop('project_path'); return t
        for meta in [drop, lambda t: {**t, 'project_path': ''}, lambda t: {**t, 'project_path': '../clients/acme/website'},
                     lambda t: {**t, 'project_path': 'personal/../clients'}, lambda t: {**t, 'project_path': '/home/x'},
                     lambda t: {**t, 'project_path': ['sites/example-site']}]:
            exc, calls = self.go(meta=meta)
            self.assertIsInstance(exc, mod.Refused); self.assertIn('no valid project path', str(exc))
            self.assertFalse((self.state / 'tasks/w1.json').exists())
            self.assertFalse(any(c[:3] in (['docker', 'volume', 'create'], ['docker', 'run', '-d']) for c in calls))
            mod.shutil.rmtree(self.root / 'src', ignore_errors=True)

    def test_the_worker_must_stand_on_the_checked_commit(self):
        exc, _ = self.go(worker_head='f' * 40)
        self.assertIsInstance(exc, ValueError); self.assertNotIsInstance(exc, mod.Refused); self.assertIn('not on the checked commit', str(exc))
        self.assertEqual(mod.task('w1')['status'], 'provisioning')  # main() makes it failed, as for every failed create

    def test_every_refusal_is_refused_and_leaves_nothing(self):
        def no_token(t): t.pop('broker'); t.pop('broker_token'); return t
        cases = [('another project', {'project': 'example-client'}), ('not a mailbox task', {'meta': no_token}),
                 ('is not running', {'state': 'stopped'}), ('is not ready', {'meta': lambda t: {**t, 'status': 'failed'}}),
                 ('the requesting task has uncommitted changes – commit first', {'dirty': ' M a.txt\n'}),
                 ('changed the OpenCode project configuration', {'changed': 'opencode.json'}),
                 ('changed the OpenCode project configuration', {'changed': 'opencode.jsonc'}),
                 ('changed the OpenCode project configuration', {'changed': '.opencode/agents/x.md'}),
                 ('history rewritten', {'meta': lambda t: {**t, 'base': 'e' * 40}}),
                 ('larger than 200 MiB', {'stat_size': mod.EXPORT_MAX + 1}), ('does not exist', {'from_task': 'nobody'})]
        for msg, kw in cases:
            project = kw.pop('project', 'example-site')
            if project != 'example-site': kw['meta'] = lambda t: {**t, 'project': project}
            exc, calls = self.go(**kw)
            self.assertIsInstance(exc, mod.Refused, msg); self.assertIn(msg, str(exc))
            self.assertFalse((self.state / 'tasks/w1.json').exists(), msg)
            self.assertFalse(any(c[:3] in (['docker', 'volume', 'create'], ['docker', 'run', '-d']) for c in calls), msg)
            self.assertFalse(any(str(self.home / 'projects') in a for c in calls for a in c), msg)
            if kw.get('stat_size'): self.assertTrue(self.removed)
            mod.shutil.rmtree(self.root / 'src', ignore_errors=True)
        self.assertEqual(len(str(exc).splitlines()), 1)

    def test_an_unrelated_change_and_a_changed_file_elsewhere_pass_the_lock(self):
        for changed in ['README.md', 'docs/opencode.json', 'src/.opencode/x']:  # only the root files and the root folder count
            exc, _ = self.go(changed=changed); self.assertIsNone(exc, changed)
            for f in (self.state / 'tasks/w1.json', self.state / 'tasks/req.json'): f.unlink()
            mod.shutil.rmtree(self.root / 'src'); mod.shutil.rmtree(self.state / 'agents/w1')

    def test_from_task_only_with_worker_and_a_missing_requester_is_a_fault_of_the_call_not_a_state(self):
        with patch.object(mod.subprocess, 'run') as call:
            with self.assertRaisesRegex(ValueError, 'wrong call: --from-task only together with --worker'):
                mod.create(mod.profile('example-site'), 'w1', from_task='req')
            with patch.object(mod.sys, 'argv', ['nc-work', 'create', 'example-site', 'w1', '--from-task', 'req']):
                with self.assertRaisesRegex(ValueError, 'wrong call'): mod.main()
        call.assert_not_called(); self.assertFalse(any((self.state / 'tasks').iterdir()))
        self.assertTrue(issubclass(mod.Refused, ValueError)); self.assertFalse(issubclass(mod.Refused, mod.TooManyTasks))

    def test_refusals_exit_4_and_faults_exit_1_through_main(self):
        bin_dir = self.root / 'bin'; bin_dir.mkdir()
        docker = bin_dir / 'docker'
        docker.write_text('#!/bin/sh\nif [ "$1" = ps ]; then exit 0; fi\nif [ "$1" = inspect ]; then echo true; exit 0; fi\nexit 99\n'); docker.chmod(0o755)
        env = {**os.environ, 'HOME': str(self.home), 'PATH': f'{bin_dir}:{os.environ["PATH"]}'}
        tasks = self.home / '.local/share/nc-work/tasks'; tasks.mkdir(parents=True)
        mod.save(tasks / 'plain.json', {'id': 'plain', 'project': 'example-site', 'status': 'ready', 'base': 'b' * 40})
        def call(*args): return subprocess.run([sys.executable, str(path), 'create', 'example-site', 'w1', *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for who, text in [('nobody', 'does not exist'), ('plain', 'not a mailbox task')]:
            r = call('--worker', '--from-task', who)
            self.assertEqual(r.returncode, 4, r.stderr); self.assertIn('nc-work: requesting task ' + who, r.stderr.decode()); self.assertIn(text, r.stderr.decode())
            self.assertEqual(r.stdout, b''); self.assertFalse((tasks / 'w1.json').exists())
        r = call('--from-task', 'plain'); self.assertEqual(r.returncode, 1); self.assertIn('wrong call', r.stderr.decode())

def secrets_hex(name): return hashlib.sha256(name.encode()).hexdigest()[:32]

class FakeClock:
    def __init__(self): self.now = 1_800_000_000.0
    def __call__(self): return self.now
    def advance(self, seconds): self.now += seconds

class FakeProc:
    """A harness call: the events 'timeout' (a second passes), 'int' (Ctrl-C) and 'done' are played one per communicate()."""
    pid = 4242
    def __init__(self, out=b'', err=b'', code=0, events=(), clock=None, on_wait=None):
        self.out, self.err, self.returncode, self.events, self.clock, self.on_wait = out, err, code, list(events), clock, on_wait
    def communicate(self, timeout=None):
        if self.on_wait: self.on_wait()
        event = self.events.pop(0) if self.events else 'done'
        if event == 'timeout': self.clock.advance(timeout or 1); raise subprocess.TimeoutExpired('x', timeout)
        if event == 'int': raise KeyboardInterrupt()
        return self.out, self.err

def line(**fields): return (json.dumps(fields) + '\n').encode()
TID, TID2 = 'd1115-1432-ab12', 'd1115-1500-cd34'

class BrokerTests(unittest.TestCase):
    """nc-work broker: one round per call, a fake harness and a fake clock; nothing runs and nothing is waited for."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(self.tmp.name))
        self.state, self.home, self.harness = self.root / 'state', self.root / 'home', self.root / 'harness'
        (self.state / 'tasks').mkdir(parents=True); self.home.mkdir()
        self.memory = self.root / 'memory'; (self.memory / 'global').mkdir(parents=True); (self.memory / 'projects').mkdir()
        (self.memory / 'MEMORY.md').write_text('# Index\n'); (self.memory / 'projects/example-site.md').write_text('# example-site\n')
        self.clock = FakeClock(); self.ctx = mod.Broker(clock=self.clock, sleep=self.clock.advance)
        self.calls, self.script, self.killed = [], None, []
        real_popen = subprocess.Popen
        def popen(cmd, **kw):
            if cmd[0] == sys.executable: return real_popen(cmd, **kw)  # subprocess.run in a test, not the harness
            self.calls.append((cmd, kw, [(f, pathlib.Path(f).read_bytes()) for f in cmd if f.startswith(str(self.state / 'broker-runs/staging'))]))
            return self.script(cmd)
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod, 'HARNESS', self.harness), patch.object(mod.pathlib.Path, 'home', return_value=self.home),
                  patch.object(mod.subprocess, 'Popen', side_effect=popen), patch.object(mod.os, 'killpg', side_effect=lambda *a: self.killed.append(a)),
                  patch('sys.stdout', new_callable=io.StringIO), patch.object(mod.sys, 'stderr', new_callable=io.StringIO),
                  patch.object(mod, 'MEMORY', self.memory), patch.object(mod, 'MEMORY_LOCK_WAIT', 0.2)]:
            p.start(); self.addCleanup(p.stop)
        self.token = {}
        self.add('t1')

    def add(self, name, project='example-site', token=None, memory=True, worker=None):
        self.token[name] = token or secrets_hex(name)
        mod.save(self.state / f'tasks/{name}.json', {'id': name, 'project': project, 'status': 'ready', 'broker': True, 'broker_token': self.token[name],
                                                      'project_path': 'sites/example-site', 'base': 'b' * 40, 'memory': memory, 'worker': worker})
        mod.broker_folders(name)

    def dirs(self, name='t1'): return mod.broker_paths(name)[1:]
    def put(self, name, data=None, task='t1', **obj):
        data = data if data is not None else json.dumps(obj or {'v': 1, 'type': 'delegate', 'role': 'tester', 'task': 'x', 'model': None, 'timeout': 20}).encode()
        (self.dirs(task)[0] / name).write_bytes(data); return self.dirs(task)[0] / name
    def answer(self, stem, task='t1'): return json.loads((self.dirs(task)[1] / stem / 'response.json').read_text())
    def round(self, harness=None, seconds=0):
        self.clock.advance(seconds)
        if harness: self.script = harness
        mod.broker_round(self.ctx)
    def started(self, tid=TID, **kw): return FakeProc(line(state='started', task_id=tid, timeout_min=20, started='2026-11-15T14:32:00Z', **kw), code=0)
    def pane(self): return sys.stdout.getvalue()

    def test_the_harness_gets_requester_token_project_and_path_from_the_record_never_from_the_request(self):
        self.add('t2', project='example-client'); mod.save(self.state / 'tasks/t2.json', {**mod.task('t2'), 'project_path': 'clients/acme/website'})
        request = json.dumps({'v': 1, 'type': 'delegate', 'requester': 't1', 'token': 'f' * 32, 'project': 'x', 'task': 'SECRET TASK'}).encode()
        self.put('r1.json', request, task='t2'); self.round(lambda cmd: self.started())
        cmd, kw, staged = self.calls[0]
        staged_path = str(self.state / 'broker-runs/staging/t2/r1.json')
        self.assertEqual(cmd, [str(self.harness / 'bin/nc'), 'delegate', '--broker', '--requester', 't2', '--token', self.token['t2'], '--profile', 'example-client',
                               '--project-path', 'clients/acme/website', '--request', staged_path, '--request-name', 'r1.json'])
        self.assertEqual((kw['cwd'], kw['start_new_session']), ('/', True)); self.assertEqual(staged, [(staged_path, request)])
        self.assertFalse((self.state / 'broker-runs/staging/t2/r1.json').exists()); self.assertFalse((self.dirs('t2')[0] / 'r1.json').exists())
        self.assertEqual(self.answer('r1', 't2'), {'v': 1, 'request': 'r1', 'state': 'started', 'reason': None, 'task_id': TID, 'timeout_min': 20,
                                                   'started': '2026-11-15T14:32:00Z', 'result': None})
        folder = self.dirs('t2')[1] / 'r1'
        self.assertEqual((folder.stat().st_mode & 0o777, (folder / 'response.json').stat().st_mode & 0o777), (0o755, 0o644))
        self.assertEqual(sorted(p.name for p in folder.iterdir()), ['response.json'])  # no .tmp left
        run = json.loads((self.state / f'broker-runs/{TID}.json').read_text())
        self.assertEqual((run['requester'], run['token'], run['request'], run['timeout_min']), ('t2', self.token['t2'], 'r1', 20))
        self.assertEqual(run['deadline'], mod.broker_epoch('2026-11-15T14:32:00Z', 0) + 1200)
        self.assertEqual((self.state / f'broker-runs/{TID}.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in self.dirs('t1')[1].iterdir()], ['.broker'])  # the other task's inbox: only the sign of life
        # the pane line has time, task, kind, result and id – no task text; the same as JSON in the log
        self.assertRegex(self.pane(), rf'^\d\d:\d\d:\d\d t2 delegate started {TID}\n$'); self.assertNotIn('SECRET', self.pane())
        log = self.home / '.nc/log/broker.jsonl'
        self.assertEqual(json.loads(log.read_text().splitlines()[0])['id'], TID)
        self.assertEqual((log.stat().st_mode & 0o777, log.parent.stat().st_mode & 0o777), (0o600, 0o700))

    def test_refused_error_and_unusable_answers_of_the_harness(self):
        cases = [(b'refused', line(state='refused', reason='role\x1b[31m "x"\n does not exist ' + 'z' * 500), 1, 'refused'),
                 (b'error', line(state='error', reason='broken'), 2, 'error'),
                 (b'a', b'not json\n', 0, 'unusable'), (b'b', line(state='refused', reason='x') + line(state='refused', reason='y'), 1, 'unusable'),
                 (b'c', line(state='refused', reason='x'), 0, 'unusable'), (b'd', line(state='started', task_id='x1', timeout_min=5, started='2026-11-15T14:32:00Z'), 0, 'unusable'),
                 (b'e', line(state='started', task_id=TID, timeout_min=True, started='2026-11-15T14:32:00Z'), 0, 'unusable'),
                 (b'f', line(state='started', task_id=TID, timeout_min=21, started='2026-11-15T14:32:00Z'), 0, 'unusable'),
                 (b'g', line(state='started', task_id=TID, timeout_min=5, started='2026-11-15\x00T14:32:00Z'), 0, 'unusable'),
                 (b'h', b'\xff\xfe\n', 0, 'unusable'), (b'i', b'', 3, 'unusable')]
        for stem, out, code, kind in cases:
            self.put(stem.decode() + '.json'); self.round(lambda cmd: FakeProc(out, b'nc delegate: some reason\n', code), seconds=16)  # 4 answers a minute
            a = self.answer(stem.decode())
            if kind == 'unusable': self.assertEqual((a['state'], a['task_id']), ('error', None)); self.assertIn('the harness gave no usable answer', a['reason'])
            else: self.assertEqual(a['state'], kind)
        self.assertEqual(self.answer('refused')['reason'], 'role[31m "x" does not exist ' + 'z' * (400 - len('role[31m "x" does not exist ')))
        self.assertEqual(self.answer('error')['reason'], 'broken'); self.assertEqual(list((self.state / 'broker-runs').glob('d*.json')), [])
        self.assertEqual(list((self.state / 'broker-runs/staging/t1').iterdir()), [])

    def test_links_folders_fifos_and_wrong_names_are_handled_without_following_and_reported_once(self):
        req = self.dirs()[0]; secret = self.root / 'secret'; secret.write_text('host secret\n')
        (req / 'link.json').symlink_to(secret); (req / 'dir.json').mkdir(); os.mkfifo(req / 'fifo.json')
        (req / 'Bad Name.json').write_text('{}'); (req / 'x.txt').write_text('{}'); (req / '.hidden.json').write_text('{}'); (req / 'a\nb.json').write_text('{}')
        self.round(lambda cmd: self.fail(cmd))
        self.assertEqual(sorted(p.name for p in req.iterdir()), ['.hidden.json', 'dir.json'])
        self.assertEqual(secret.read_text(), 'host secret\n'); self.assertEqual(self.calls, [])
        for text in ['link.json', 'fifo.json', 'Bad Name.json', 'x.txt', 'a\\u{a}b.json']: self.assertIn(text, self.pane())
        self.assertNotIn('a\nb.json', self.pane())  # shown with a visible escape
        self.assertTrue(any(json.loads(l)['id'] == 'a\\u{a}b.json' for l in (self.home / '.nc/log/broker.jsonl').read_text().splitlines()))
        before = self.pane(); (req / 'link.json').symlink_to(secret); self.round(seconds=3)
        self.assertEqual(self.pane(), before)  # the same finding is not reported again in this run
        self.assertFalse((req / 'link.json').exists() or (req / 'link.json').is_symlink())

    def test_requests_over_64_kib_are_refused_and_exactly_64_kib_is_handed_over(self):
        self.put('big.json', b'{"x":"' + b'a' * (64 * 1024) + b'"}'); self.round()
        a = self.answer('big'); self.assertEqual((a['state'], a['reason']), ('refused', 'request larger than 64 KiB'))
        self.assertEqual(self.calls, []); self.assertFalse((self.dirs()[0] / 'big.json').exists())
        data = b'{"x":"' + b'a' * (64 * 1024 - 8) + b'"}'; self.assertEqual(len(data), 64 * 1024)
        self.put('edge.json', data); self.round(lambda cmd: FakeProc(line(state='refused', reason='role'), code=1)); self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][2][0][1], data)

    def test_the_mailbox_keeps_eight_files_and_four_requests_are_read_per_round(self):
        for i in range(12): self.put(f'r{i:02d}.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': f'd0000-0000-{i:04x}'}).encode())
        self.round(lambda cmd: self.fail(cmd))  # none of these ids is the task's own: refused, the harness is not called
        self.assertEqual(sorted(p.name for p in self.dirs()[0].iterdir()), [f'r{i:02d}.json' for i in range(4, 8)])  # 8 kept, 4 read
        self.assertEqual(sorted(p.name for p in self.dirs()[1].iterdir() if p.is_dir()), [f'r{i:02d}' for i in range(4)])
        self.assertIn('4 file(s) over 8 deleted without an answer', self.pane()); self.assertFalse((self.dirs()[1] / 'r09').exists())
        self.round(seconds=59); self.assertEqual(len([p for p in self.dirs()[0].iterdir()]), 4)  # four answers in this minute already
        self.round(seconds=2); self.assertEqual(sorted(p.name for p in self.dirs()[0].iterdir()), [])
        self.assertEqual(len([p for p in self.dirs()[1].iterdir() if p.is_dir()]), 8)

    def test_a_second_delegate_within_ten_seconds_is_not_even_read(self):
        self.put('r1.json'); self.put('r2.json')
        self.round(lambda cmd: FakeProc(line(state='refused', reason='no'), code=1))
        self.assertEqual(len(self.calls), 1); self.assertTrue((self.dirs()[0] / 'r2.json').exists())  # stays in the mailbox
        self.round(seconds=5); self.assertEqual(len(self.calls), 1); self.assertTrue((self.dirs()[0] / 'r2.json').exists())
        self.round(seconds=6); self.assertEqual(len(self.calls), 2); self.assertFalse((self.dirs()[0] / 'r2.json').exists())
        self.add('t2'); self.put('o1.json', task='t2'); self.round(); self.assertEqual(len(self.calls), 3)  # the gap is per task

    def test_an_existing_answer_folder_or_staged_copy_is_never_overwritten(self):
        old = self.dirs()[1] / 'r1'; old.mkdir(); (old / 'response.json').write_text('old')
        self.put('r1.json'); (self.state / 'broker-runs/staging/t1').mkdir(parents=True); (self.state / 'broker-runs/staging/t1/r2.json').write_text('s')
        self.put('r2.json'); self.round(lambda cmd: self.fail(cmd))
        self.assertEqual((old / 'response.json').read_text(), 'old'); self.assertFalse((self.dirs()[1] / 'r2').exists())
        self.assertEqual(list(self.dirs()[0].iterdir()), []); self.assertEqual((self.state / 'broker-runs/staging/t1/r2.json').read_text(), 's')
        self.assertEqual(self.pane().count('duplicate, deleted'), 2)

    def test_a_task_without_an_inbox_is_skipped_and_nothing_is_made(self):
        mod.shutil.rmtree(self.dirs()[1]); self.put('r1.json'); self.round(lambda cmd: self.fail(cmd))
        self.assertFalse(self.dirs()[1].exists()); self.assertTrue((self.dirs()[0] / 'r1.json').exists()); self.assertIn('skipped', self.pane())

    def test_cleanup_is_checked_strictly_and_a_malformed_one_never_reaches_the_harness(self):
        bad = [{'v': 1, 'type': 'cleanup', 'task_id': TID, 'x': 1}, {'v': True, 'type': 'cleanup', 'task_id': TID}, {'v': '1', 'type': 'cleanup', 'task_id': TID},
               {'v': 1.0, 'type': 'cleanup', 'task_id': TID}, {'v': 1, 'type': 'cleanup', 'task_id': 'D1115-1432-ab12'}, {'v': 1, 'type': 'cleanup'},
               {'v': 1, 'type': 'cleanup', 'task_id': TID + '\n'}]
        for i, obj in enumerate(bad): self.put(f'bad{i}.json', json.dumps(obj).encode())
        self.put('badutf.json', b'{"v":1,"type":"cleanup","task_id":"' + b'\xff' + b'"}')  # not UTF-8: not a cleanup, the harness decides
        self.round(lambda cmd: FakeProc(line(state='refused', reason='no'), code=1))
        self.assertEqual([self.answer(f'bad{i}')['reason'] for i in range(4)], ['request invalid'] * 4); self.assertEqual(self.calls, [])  # four per round
        self.round(seconds=61)  # four answers per minute
        self.assertEqual([self.answer(f'bad{i}')['reason'] for i in range(7)], ['request invalid'] * 7)
        self.assertEqual(len(self.calls), 1); self.assertEqual(self.calls[0][0][1], 'delegate')  # only the non-UTF-8 one went on, as a request for the harness
        self.assertEqual(self.answer('badutf')['reason'], 'no')
        for text in ['not json', '[1]', '{"type":"delegate"}', '{"type":["cleanup"]}']:
            self.put('other.json', text.encode()); self.round(seconds=61); self.assertEqual(self.calls[-1][0][1], 'delegate'); mod.shutil.rmtree(self.dirs()[1] / 'other')
        self.assertEqual(len(self.calls), 5)

    def test_cleanup_only_for_the_tasks_own_delegations_never_on_the_requests_word(self):
        mod.broker_respond(self.dirs()[1], 'old', 'started', task_id=TID)  # a delegation of t1: its own inbox says so
        self.add('t2'); mod.broker_respond(self.dirs('t2')[1], 'theirs', 'started', task_id=TID2)
        mod.broker_run_save({'id': 'd1115-1600-ef56', 'requester': 't2', 'token': self.token['t2'], 'request': 'x', 'timeout_min': 5, 'started': 's', 'deadline': 1.0, 'errored': False})
        mod.broker_run_save({'id': 'd1115-1700-0a1b', 'requester': 't1', 'token': 'f' * 32, 'request': 'x', 'timeout_min': 5, 'started': 's', 'deadline': 1.0, 'errored': False})  # an older t1
        for i, tid in enumerate([TID2, 'd1115-1600-ef56', 'd1115-1700-0a1b', 'd1999-9999-ffff']):
            self.put(f'foreign{i}.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': tid}).encode())
        self.round(lambda cmd: self.fail(cmd))
        for i in range(4):
            a = self.answer(f'foreign{i}'); self.assertEqual((a['state'], a['reason']), ('refused', 'the delegation does not belong to this task'))
        self.assertEqual(self.calls, [])

    def test_cleanup_of_an_own_delegation_goes_to_the_harness_and_removes_its_answer_folder(self):
        self.worker()  # the worker task is there: the harness cleans up
        mod.broker_respond(self.dirs()[1], 'old', 'done', task_id=TID); mod.broker_respond(self.dirs()[1], 'keep', 'done', task_id=TID2)
        self.put('ok1.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': TID}).encode())
        self.round(lambda cmd: FakeProc(b'', b'', 0))
        self.assertEqual(self.calls[0][0], [str(self.harness / 'bin/nc'), 'delegate', '--cleanup', TID])
        self.assertFalse((self.dirs()[1] / 'old').exists()); self.assertTrue((self.dirs()[1] / 'keep').exists())
        self.assertEqual({k: self.answer('ok1')[k] for k in ('state', 'task_id', 'reason')}, {'state': 'cleaned', 'task_id': TID, 'reason': None})
        for code, state, err in [(1, 'refused', 'nc delegate: worker still running\n'.encode()), (2, 'error', 'x\nnc delegate: Docker does not answer\n'.encode())]:
            mod.broker_respond(self.dirs()[1], 'old', 'done', task_id=TID); self.put(f'c{code}.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': TID}).encode())
            self.round(lambda cmd: FakeProc(b'', err, code), seconds=11)
            a = self.answer(f'c{code}'); self.assertEqual((a['state'], a['reason'].startswith('nc delegate')), (state, False))
        self.assertEqual(self.answer('c1')['reason'], 'worker still running'); self.assertEqual(self.answer('c2')['reason'], 'Docker does not answer')
        self.assertTrue((self.dirs()[1] / 'old').exists())  # a failed cleanup keeps the delegation

    def delivery(self, tid=TID, bundle=b'BUNDLE', result_md=b'# done\n', result=None, link=False):
        d = self.home / '.nc/delegate' / tid / 'delivery'; d.mkdir(parents=True)
        (d / 'result.bundle').write_bytes(bundle)
        if result_md is not None:
            if link: (d / 'RESULT.md').symlink_to(self.root / 'secret')
            else: (d / 'RESULT.md').write_bytes(result_md)
        (d / 'result.json').write_text(json.dumps(result or {'status': 'done', 'commits': 1}))

    def run_entry(self, tid=TID, task='t1', token=None, request='r1', deadline=None, **extra):
        mod.broker_run_save({'id': tid, 'requester': task, 'token': token or self.token[task], 'request': request, 'timeout_min': 20,
                             'started': '2026-11-15T14:32:00Z', 'deadline': deadline or self.clock() + 1200, 'errored': False, **extra})
        mod.broker_respond(self.dirs(task)[1], request, 'started', task_id=TID, timeout_min=20, started='2026-11-15T14:32:00Z')

    def worker(self, tid=TID): mod.save(self.state / 'tasks' / (tid + '.json'), {'id': tid, 'worker': True, 'status': 'ready'})

    def poll(self, code, out=b'', err=b'', seconds=11):
        self.clock.advance(seconds); self.script = lambda cmd: FakeProc(out, err, code); mod.broker_poll(self.ctx)

    def test_a_finished_delegation_is_copied_as_real_files_with_limits_and_modes(self):
        self.run_entry(); self.poll(0, line(status='running'))
        self.assertEqual(self.calls[0][0], [str(self.harness / 'bin/nc'), 'delegate', '--result', TID])  # asked without --wait
        self.assertEqual(self.answer('r1')['state'], 'started'); self.assertTrue((self.state / f'broker-runs/{TID}.json').exists())
        self.delivery(result_md=b'x' * (70 * 1024)); self.poll(0, line(status='done'))
        folder = self.dirs()[1] / 'r1'
        self.assertEqual(sorted(p.name for p in folder.iterdir()), ['RESULT.md', 'response.json', 'result.bundle'])
        self.assertEqual((folder / 'RESULT.md').read_bytes(), b'x' * mod.RESULT_MAX); self.assertEqual((folder / 'result.bundle').read_bytes(), b'BUNDLE')
        for f in folder.iterdir(): self.assertEqual(f.stat().st_mode & 0o777, 0o644, f)
        a = self.answer('r1'); self.assertEqual((a['state'], a['task_id'], a['timeout_min'], a['started'], a['result']),
                                               ('done', TID, 20, '2026-11-15T14:32:00Z', {'status': 'done', 'commits': 1}))
        self.assertFalse((self.state / f'broker-runs/{TID}.json').exists()); self.assertIn(f'done: done {TID}', self.pane())

    def test_links_and_too_large_files_in_the_delivery_are_not_copied(self):
        (self.root / 'secret').write_text('host secret\n'); self.run_entry(); self.delivery(link=True); self.poll(0, line(status='done'))
        self.assertEqual(sorted(p.name for p in (self.dirs()[1] / 'r1').iterdir()), ['response.json', 'result.bundle']); self.assertEqual(self.answer('r1')['state'], 'done')
        mod.shutil.rmtree(self.dirs()[1] / 'r1'); self.run_entry(); mod.shutil.rmtree(self.home / '.nc/delegate'); self.delivery(bundle=b'x' * 100)
        with patch.object(mod, 'BROKER_BUNDLE_MAX', 64): self.poll(0, line(status='done'))
        a = self.answer('r1'); self.assertEqual((a['state'], a['task_id']), ('error', TID)); self.assertIn('result.bundle is larger than', a['reason'])
        self.assertFalse((self.dirs()[1] / 'r1/result.bundle').exists()); self.assertFalse(any(p.name.startswith('.') for p in (self.dirs()[1] / 'r1').iterdir()))
        self.assertFalse((self.state / f'broker-runs/{TID}.json').exists())

    def test_a_new_task_with_an_old_name_gets_no_old_results(self):
        self.run_entry(); self.add('t1', token='9' * 32)  # t1 was removed and made again: another token
        self.delivery(); self.poll(0, line(status='done'))
        self.assertEqual(self.answer('r1')['state'], 'started')  # untouched; and no result files in the new inbox
        self.assertFalse((self.dirs()[1] / 'r1/result.bundle').exists())
        self.assertIn(f'the result is in ~/.nc/delegate/{TID}', self.pane()); self.assertFalse((self.state / f'broker-runs/{TID}.json').exists())
        self.run_entry(tid=TID2, token='8' * 32); self.delivery(TID2); self.poll(0, line(status='done'))
        self.assertFalse(list(self.dirs()[1].glob('*/result.bundle')))

    def test_the_task_is_checked_only_when_the_result_is_there(self):
        self.run_entry(); (self.state / 'tasks/t1.json').unlink()  # the task is gone, the worker may still run: keep asking
        self.poll(0, line(status='running')); self.assertTrue((self.state / f'broker-runs/{TID}.json').exists()); self.assertEqual(len(self.calls), 1)
        self.poll(0, line(status='stopped')); self.assertFalse((self.state / f'broker-runs/{TID}.json').exists())
        self.assertIn('requesting task gone', self.pane())

    def test_failed_asking_is_reported_once_then_an_error_after_the_deadline_plus_five_minutes_and_a_late_success_wins(self):
        deadline = self.clock() + 1200; self.run_entry(deadline=deadline); self.worker()
        for _ in range(3): self.poll(2, b'', b'nc delegate: worker stuck (nc-work start d1115-1432-ab12)\n')
        self.assertEqual(self.pane().count('result not available: worker stuck'), 1)
        self.assertEqual(self.answer('r1')['state'], 'started')
        self.clock.now = deadline + 5 * 60 + 1; self.poll(2, b'', b'nc delegate: worker stuck (nc-work start d1115-1432-ab12)\n', seconds=0)
        a = self.answer('r1'); self.assertEqual((a['state'], a['task_id'], a['timeout_min']), ('error', TID, 20)); self.assertIn('nc-work start', a['reason'])
        self.assertTrue(mod.broker_runs()[0]['errored'])
        calls = len(self.calls); self.poll(2, b'', b'x', seconds=11); self.assertEqual(len(self.calls), calls)  # now every five minutes
        self.poll(2, b'', b'x', seconds=5 * 60); self.assertEqual(len(self.calls), calls + 1)
        self.delivery(); self.poll(0, line(status='done'), seconds=5 * 60); self.assertEqual(self.answer('r1')['state'], 'done')
        self.assertEqual(mod.broker_runs(), [])

    def test_a_restart_answers_staged_requests_with_error_and_runs_nothing_again(self):
        staging = self.state / 'broker-runs/staging/t1'; staging.mkdir(parents=True)
        for n in ['r1.json', 'r2.json', 'bad name.json']: (staging / n).write_text('{}')
        (self.dirs()[1] / 'r2').mkdir(); (self.dirs()[1] / 'r2/response.json').write_text('x')
        gone = self.state / 'broker-runs/staging/gone'; gone.mkdir(); (gone / 'r1.json').write_text('{}')
        (staging / 'm1.json').write_text(json.dumps({'v': 1, 'type': 'memory', 'text': 'note'}))
        self.harness_run(request='m1.json')                                     # even a harness run for its name is never taken over
        self.script = lambda cmd: self.fail(cmd); mod.broker_start(self.ctx)
        a = self.answer('r1'); self.assertEqual((a['state'], a['reason']), ('error', 'broker stopped during hand-over – submit the request again. ' + mod.BROKER_HALF))
        a = self.answer('m1'); self.assertEqual((a['state'], a['reason']), ('error', 'broker stopped during hand-over – submit the note again'))
        self.assertNotIn(mod.BROKER_HALF, a['reason']); self.assertEqual(mod.broker_runs(), [])
        self.assertFalse(mod.broker_memory_counter('t1').exists())              # the daily count is left as it was
        self.assertEqual((self.dirs()[1] / 'r2/response.json').read_text(), 'x'); self.assertEqual(list(staging.iterdir()), []); self.assertEqual(list(gone.iterdir()), [])
        self.assertEqual(self.calls, [])

    def test_a_fault_with_one_task_does_not_stop_the_round(self):
        self.add('t2'); self.put('r1.json'); self.put('r1.json', task='t2')
        with patch.object(mod, 'broker_handle', side_effect=[OSError('disk full'), None]) as handle: self.round()
        self.assertEqual([c.args[1]['id'] for c in handle.call_args_list], ['t1', 't2']); self.assertIn('t1 error OSError: disk full', self.pane())

    def test_the_sign_of_life_is_renewed_while_a_slow_harness_call_runs(self):
        seen = []
        def look():
            f = self.dirs()[1] / '.broker'
            if f.exists(): seen.append((json.loads(f.read_text())['ts'], self.clock()))
        self.put('r1.json'); self.round(lambda cmd: FakeProc(line(state='refused', reason='x'), code=1, events=['timeout'] * 120, clock=self.clock, on_wait=look))
        stamps = sorted({ts for ts, _ in seen}); self.assertGreaterEqual(len(stamps), 120 // 10)
        times = [mod.broker_epoch(ts, 0) for ts in stamps]; self.assertLessEqual(max(b - a for a, b in zip(times, times[1:])), 10)
        f = self.dirs()[1] / '.broker'
        self.assertRegex(f.read_text(), r'^\{"v":1,"ts":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"\}$'); self.assertEqual(f.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.answer('r1')['state'], 'refused')

    def test_ctrl_c_waits_for_the_call_once_and_ends_the_group_the_second_time_or_at_the_limit(self):
        self.put('r1.json'); self.round(lambda cmd: FakeProc(self.started().out, events=['timeout', 'int', 'timeout', 'done'], clock=self.clock))
        self.assertTrue(self.ctx.interrupted); self.assertEqual(self.killed, []); self.assertEqual(self.answer('r1')['state'], 'started')  # waited, answered
        self.assertIn('Ctrl-C: waiting for the running call', sys.stderr.getvalue())
        self.put('r2.json'); self.round(seconds=11); self.assertEqual(len(self.calls), 1)  # nothing new after the first Ctrl-C
        self.ctx = mod.Broker(clock=self.clock, sleep=self.clock.advance)
        self.script = lambda cmd: FakeProc(b'', events=['int', 'int'], clock=self.clock)
        self.clock.advance(11)
        with self.assertRaises(mod.BrokerStop): mod.broker_round(self.ctx)
        self.assertEqual(self.killed[0], (4242, mod.signal.SIGTERM))
        a = self.answer('r2'); self.assertEqual(a['state'], 'error'); self.assertIn('nc-work list', a['reason']); self.assertIn('nc-work remove <task> --force', a['reason'])
        self.ctx = mod.Broker(clock=self.clock, sleep=self.clock.advance); self.killed.clear(); self.put('r4.json'); self.clock.advance(11)
        self.script = lambda cmd: FakeProc(b'', events=['timeout'] * 5000, clock=self.clock)
        started = self.clock(); mod.broker_round(self.ctx)
        self.assertTrue(20 * 60 <= self.clock() - started < 20 * 60 + 30); self.assertEqual(self.killed[0][0], 4242)
        a = self.answer('r4'); self.assertIn('timeout (20 minutes)', a['reason']); self.assertIn('nc-work list', a['reason'])

    def test_the_loop_ends_after_the_first_ctrl_c_when_idle_and_a_second_instance_is_refused(self):
        with patch.object(mod, 'broker_round', side_effect=KeyboardInterrupt), patch.object(mod, 'broker_start'):
            mod.broker_main()
        self.assertIn('Broker stopped.', self.pane())
        with (self.state / 'broker.lock').open('a') as lock:
            mod.fcntl.flock(lock, mod.fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError, 'broker is already running'): mod.broker_main()
            env = {**os.environ, 'HOME': str(self.home)}; (self.home / '.local/share').mkdir(parents=True); (self.home / '.local/share/nc-work').symlink_to(self.state)
            r = subprocess.run([sys.executable, str(path), 'broker'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(r.returncode, 1); self.assertIn('nc-work: broker is already running', r.stderr.decode())

    def test_answers_that_are_over_are_swept_after_24_hours_but_not_while_a_delegation_runs(self):
        old = self.clock() - 25 * 3600
        for stem, state in [('refused', 'refused'), ('failed', 'error'), ('cleaned', 'cleaned'), ('fine', 'done'), ('running', 'error'), ('young', 'refused')]:
            mod.broker_respond(self.dirs()[1], stem, state, reason='x')
            if stem != 'young': os.utime(self.dirs()[1] / stem / 'response.json', (old, old))
            else: os.utime(self.dirs()[1] / stem / 'response.json', (self.clock() - 3600,) * 2)
        for stem, age in [('stored-old', 2 * 3600), ('stored-young', 30 * 60)]:  # stored (memory) goes after an hour
            mod.broker_respond(self.dirs()[1], stem, 'stored', result={'outcome': 'new', 'pushed': True})
            os.utime(self.dirs()[1] / stem / 'response.json', (self.clock() - age,) * 2)
        self.run_entry(request='running'); os.utime(self.dirs()[1] / 'running/response.json', (old, old))
        mod.broker_sweep(self.ctx)
        self.assertEqual(sorted(p.name for p in self.dirs()[1].iterdir() if p.is_dir()), ['fine', 'running', 'stored-young', 'young'])
        self.assertIn('cleaned up (1 hour) stored-old', self.pane())

    # --- broker edge cases: staging, signals, timeouts
    def staged(self, name='r1.json'): return self.state / 'broker-runs/staging/t1' / name

    def test_sigterm_or_sighup_during_a_hand_over_ends_the_group_answers_error_and_drops_the_staged_copy(self):
        def closed(): self.ctx.terminated = True                                # what the handler does while a call runs
        self.put('r1.json')
        with self.assertRaises(mod.BrokerStop):
            self.round(lambda cmd: FakeProc(b'', events=['timeout', 'done'], clock=self.clock, on_wait=closed))
        self.assertEqual(self.killed[0], (4242, mod.signal.SIGTERM))
        a = self.answer('r1'); self.assertEqual(a['state'], 'error')
        self.assertIn('broker stopped', a['reason']); self.assertIn(mod.BROKER_HALF, a['reason'])
        self.assertFalse(self.staged().exists())                                # answered: the copy goes

    def test_a_signal_while_asking_for_a_result_answers_nothing_and_keeps_the_run(self):
        self.run_entry(); self.worker()
        def closed(): self.ctx.terminated = True
        self.clock.advance(11); self.script = lambda cmd: FakeProc(b'', events=['timeout'], clock=self.clock, on_wait=closed)
        with self.assertRaises(mod.BrokerStop): mod.broker_poll(self.ctx)
        self.assertEqual(self.killed[0], (4242, mod.signal.SIGTERM))
        self.assertEqual(self.answer('r1')['state'], 'started'); self.assertEqual([r['id'] for r in mod.broker_runs()], [TID])

    def test_no_ctrl_c_escapes_the_wait_or_the_kill_loop(self):
        self.put('r1.json')
        # first Ctrl-C announced, second ends the call, a third one during the kill loop only skips to SIGKILL
        self.script = lambda cmd: FakeProc(b'', events=['int', 'int', 'int', 'done'], clock=self.clock)
        with self.assertRaises(mod.BrokerStop): mod.broker_round(self.ctx)
        self.assertEqual([k[1] for k in self.killed], [mod.signal.SIGTERM, mod.signal.SIGKILL])
        self.assertEqual(self.answer('r1')['state'], 'error')

    def test_the_handlers_only_set_flags_during_a_call_and_end_the_broker_otherwise(self):
        previous = mod.broker_signals(self.ctx)
        self.addCleanup(lambda: [mod.signal.signal(s, h) for s, h in previous.items()])
        self.ctx.calling = True
        for sig in (mod.signal.SIGHUP, mod.signal.SIGTERM): os.kill(os.getpid(), sig)
        os.kill(os.getpid(), mod.signal.SIGINT)
        self.assertTrue(self.ctx.terminated); self.assertEqual(self.ctx.sigints, 1)
        self.assertEqual(mod.broker_signalled(self.ctx), 'signal')
        self.ctx.calling = False
        for sig in (mod.signal.SIGHUP, mod.signal.SIGINT):
            with self.assertRaises(KeyboardInterrupt): os.kill(os.getpid(), sig)

    def test_a_closed_pane_does_not_stop_the_lines_or_the_log(self):
        class Gone(io.StringIO):
            def write(self, s): raise OSError(5, 'Input/output error')
        with patch('sys.stdout', new=Gone()):
            mod.broker_say(self.ctx, 't1', 'delegate', 'started', TID)
        self.assertIn('"result": "started"', (self.home / '.nc/log/broker.jsonl').read_text())

    def test_the_staged_copy_stays_until_an_answer_is_written_and_a_restart_answers_it(self):
        self.put('r1.json')
        real = mod.broker_respond
        with patch.object(mod, 'broker_respond', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.round(lambda cmd: FakeProc(line(state='refused', reason='no'), code=1))
        self.assertTrue(self.staged().exists()); self.assertFalse((self.dirs()[1] / 'r1').exists())
        self.assertIs(mod.broker_respond, real)
        mod.broker_start(mod.Broker(clock=self.clock))
        self.assertEqual(self.answer('r1')['state'], 'error'); self.assertFalse(self.staged().exists())

    def write_staged(self, name='r1.json'):
        self.staged(name).parent.mkdir(parents=True, exist_ok=True); self.staged(name).write_text('{}')

    def harness_run(self, tid=TID, token=None, request='r1.json', result=False, **extra):
        folder = self.home / '.nc/delegate' / tid; folder.mkdir(parents=True)
        (folder / 'request.json').write_text(json.dumps({'task_id': tid, 'origin': 'broker', 'requester': 't1', 'requester_token': token or self.token['t1'],
                                                         'request_name': request, 'timeout_min': 15, 'started': '2026-11-15T14:32:00Z', **extra}))
        if result: (folder / 'result.json').write_text('{}')

    def test_a_restart_answers_started_from_broker_runs_or_takes_over_an_unrecorded_run(self):
        self.write_staged(); mod.broker_run_save({'id': TID, 'requester': 't1', 'token': self.token['t1'], 'request': 'r1', 'timeout_min': 20,
                                                  'started': '2026-11-15T14:32:00Z', 'deadline': self.clock() + 1200, 'errored': False})
        mod.broker_start(self.ctx)
        a = self.answer('r1'); self.assertEqual((a['state'], a['task_id'], a['timeout_min']), ('started', TID, 20)); self.assertFalse(self.staged().exists())
        mod.broker_run_drop(self.ctx, TID); mod.shutil.rmtree(self.dirs()[1] / 'r1')
        self.write_staged(); self.harness_run()
        mod.broker_start(self.ctx)
        a = self.answer('r1'); self.assertEqual((a['state'], a['task_id'], a['timeout_min'], a['started']), ('started', TID, 15, '2026-11-15T14:32:00Z'))
        run = mod.broker_runs()[0]
        self.assertEqual((run['id'], run['requester'], run['token'], run['request'], run['errored']), (TID, 't1', self.token['t1'], 'r1', False))
        self.assertEqual(run['deadline'], mod.broker_epoch('2026-11-15T14:32:00Z', 0) + 15 * 60)
        self.assertIn('run taken over', self.pane()); self.assertEqual(self.calls, [])

    def test_a_restart_takes_over_nothing_that_is_not_the_requests_own_run(self):
        for label, kw in [('other token', dict(token='f' * 32)), ('other request', dict(request='r2.json')), ('fetched', dict(result=True)),
                          ('not from the broker', dict(origin=None)), ('bad timeout', dict(timeout_min=99))]:
            with self.subTest(label):
                self.write_staged(); self.harness_run(**kw)
                mod.broker_start(self.ctx)
                a = self.answer('r1'); self.assertEqual(a['state'], 'error')
                self.assertEqual(a['reason'], 'broker stopped during hand-over – submit the request again. ' + mod.BROKER_HALF)
                self.assertEqual(mod.broker_runs(), [])
                mod.shutil.rmtree(self.dirs()[1] / 'r1'); mod.shutil.rmtree(self.home / '.nc/delegate')

    def test_a_slow_result_call_past_five_minutes_is_not_cut_off(self):
        self.run_entry(); self.worker()
        self.clock.advance(11); self.script = lambda cmd: FakeProc(line(status='running'), events=['timeout'] * 400, clock=self.clock)
        mod.broker_poll(self.ctx)
        self.assertEqual(self.killed, []); self.assertEqual(self.answer('r1')['state'], 'started')
        self.assertNotIn('not available', self.pane())

    def test_the_timeout_names_the_limit_that_ran_out(self):
        self.assertTrue(mod.broker_killed('timeout', 20 * 60).startswith('timeout (20 minutes)'))
        self.assertTrue(mod.broker_killed('timeout', 5 * 60).startswith('timeout (5 minutes)'))
        self.worker(); mod.broker_respond(self.dirs()[1], 'old', 'done', task_id=TID)
        self.put('c1.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': TID}).encode())
        self.round(lambda cmd: FakeProc(b'', events=['timeout'] * 400, clock=self.clock))
        self.assertEqual(self.answer('c1')['reason'], 'timeout (5 minutes) in the harness call')

    def test_an_error_run_goes_on_without_its_requester_and_is_dropped_when_the_worker_is_gone(self):
        deadline = self.clock() + 1200; self.run_entry(deadline=deadline); self.worker()
        mod.save(self.state / 'tasks/t1.json', {**mod.task('t1'), 'broker_token': 'f' * 32})  # the requester was replaced
        self.clock.now = deadline + 5 * 60 + 1; self.poll(2, b'', b'nc delegate: worker stuck\n', seconds=0)
        self.assertTrue(mod.broker_runs()[0]['errored'])                         # kept: asked again every five minutes
        self.assertEqual(self.answer('r1')['state'], 'started')                  # nothing written into a foreign inbox
        self.poll(2, b'', b'x', seconds=5 * 60); self.assertEqual(len(mod.broker_runs()), 1)
        (self.state / f'tasks/{TID}.json').unlink()
        self.poll(2, b'', b'x', seconds=5 * 60)
        self.assertEqual(mod.broker_runs(), []); self.assertIn('worker task is gone', self.pane())

    def test_an_error_with_a_task_id_stays_while_its_run_folder_exists(self):
        old = self.clock() - 25 * 3600
        mod.broker_respond(self.dirs()[1], 'live', 'error', reason='x', task_id=TID)
        mod.broker_respond(self.dirs()[1], 'over', 'error', reason='x', task_id=TID2)
        for stem in ('live', 'over'): os.utime(self.dirs()[1] / stem / 'response.json', (old, old))
        (self.home / '.nc/delegate' / TID).mkdir(parents=True)
        mod.broker_sweep(self.ctx)
        self.assertEqual(sorted(p.name for p in self.dirs()[1].iterdir() if p.is_dir()), ['live'])

    def test_cleanup_of_a_run_that_is_gone_everywhere_answers_cleaned_with_gone(self):
        mod.broker_respond(self.dirs()[1], 'old', 'done', task_id=TID)          # the task's own delegation
        self.put('c1.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': TID}).encode())
        self.round(lambda cmd: self.fail(cmd))
        a = self.answer('c1'); self.assertEqual((a['state'], a['task_id'], a.get('gone')), ('cleaned', TID, True))
        self.assertFalse((self.dirs()[1] / 'old').exists())
        self.put('c2.json', json.dumps({'v': 1, 'type': 'cleanup', 'task_id': TID2}).encode())  # not its own: still refused
        self.round(lambda cmd: self.fail(cmd), seconds=11)
        self.assertEqual(self.answer('c2')['state'], 'refused')

    def test_a_full_inbox_takes_no_new_requests_and_folders_in_the_mailbox_are_reported_once(self):
        for i in range(mod.BROKER_MAX_ANSWERS): (self.dirs()[1] / f'a{i:03d}').mkdir()
        (self.dirs()[0] / 'folder').mkdir()
        self.put('r1.json'); self.put('r2.json')
        self.round(lambda cmd: self.fail(cmd)); self.round(seconds=11)
        self.assertEqual(sorted(p.name for p in self.dirs()[0].iterdir()), ['folder'])
        self.assertFalse((self.dirs()[1] / 'r1').exists())
        self.assertEqual(len([p for p in self.dirs()[1].iterdir() if p.is_dir()]), mod.BROKER_MAX_ANSWERS)
        self.assertEqual([e['request'] for e in self.dropped()], ['r2', 'r1'])
        self.assertEqual(self.dropped()[0]['reason'], mod.BROKER_FULL)
        self.assertEqual(self.pane().count('inbox full: 200 answers'), 2)
        self.assertEqual(self.pane().count('folder, left alone'), 1)
        mod.shutil.rmtree(self.dirs()[1] / 'a000'); self.put('r3.json')
        self.round(lambda cmd: FakeProc(line(state='refused', reason='no'), code=1), seconds=11)
        self.assertEqual(self.answer('r3')['state'], 'refused')

    def test_a_full_inbox_still_answers_cleanup_judged_by_content_not_by_name(self):
        mod.broker_respond(self.dirs()[1], 'a000', 'done', task_id=TID)
        for i in range(1, mod.BROKER_MAX_ANSWERS): mod.broker_respond(self.dirs()[1], f'a{i:03d}', 'done', task_id=f'd1115-1432-{i:04x}')
        self.put('c1.json', v=1, type='cleanup', task_id=TID)
        self.put('c2.json')                                                     # named like a cleanup, but a delegate request
        self.put('r1.json')
        self.round(lambda cmd: self.fail(cmd))                                  # run folder and worker are gone: no harness call
        a = self.answer('c1'); self.assertEqual((a['state'], a['task_id'], a.get('gone')), ('cleaned', TID, True))
        self.assertFalse((self.dirs()[1] / 'a000').exists())                    # the delegation's answer went with it
        self.assertFalse((self.dirs()[1] / 'c2').exists()); self.assertFalse((self.dirs()[1] / 'r1').exists())
        self.assertEqual(sorted(p.name for p in self.dirs()[0].iterdir()), [])
        self.assertEqual(self.pane().count('inbox full: 200 answers'), 2)
        self.assertEqual(sorted(e['request'] for e in self.dropped()), ['c2', 'r1'])

    def full(self):
        mod.broker_respond(self.dirs()[1], 'a000', 'done', task_id=TID)
        for i in range(1, mod.BROKER_MAX_ANSWERS): mod.broker_respond(self.dirs()[1], f'a{i:03d}', 'done', task_id=f'd1115-1432-{i:04x}')
    def folders(self): return sorted(p.name for p in self.dirs()[1].iterdir() if p.is_dir())

    def test_a_full_inbox_drops_cleanup_requests_that_would_only_be_refused(self):
        self.full(); before = self.folders()
        self.put('c1.json', v=1, type='cleanup', task_id=TID2)                  # a delegation that is not this task's
        self.put('c2.json', v=1, type='cleanup', task_id='../x')                # malformed: broker_cleanup_id gives ''
        self.put('c3.json', v=1, type='cleanup', task_id=TID, extra=1)          # malformed too
        self.round(lambda cmd: self.fail(cmd))
        self.assertEqual(self.folders(), before)                               # no new answer folder
        self.assertEqual(sorted(p.name for p in self.dirs()[0].iterdir()), [])
        self.assertEqual(self.pane().count('inbox full: 200 answers'), 3)
        self.assertEqual(sorted(e['request'] for e in self.dropped()), ['c1', 'c2', 'c3'])
        self.assertEqual(self.ctx.answered.get('t1', []), [])                   # nothing counted against the rate either

    def test_a_cleanup_makes_room_in_a_full_inbox(self):
        self.full()
        self.put('c1.json', v=1, type='cleanup', task_id=TID)
        self.round(lambda cmd: self.fail(cmd))                                  # run folder and worker gone: cleaned without a call
        self.assertEqual(self.answer('c1')['state'], 'cleaned')
        self.assertEqual(len(self.folders()), mod.BROKER_MAX_ANSWERS)           # one done went, one cleaned came
        self.assertEqual(mod.broker_answer_count(self.dirs()[1]), mod.BROKER_MAX_ANSWERS - 1)
        self.put('r1.json')
        self.round(lambda cmd: self.started(TID2), seconds=11)
        self.assertEqual(len(self.calls), 1); self.assertEqual(self.answer('r1')['state'], 'started')
        self.put('r2.json')                                                     # full again: 199 + started
        self.round(lambda cmd: self.fail(cmd), seconds=11)
        self.assertFalse((self.dirs()[1] / 'r2').exists())

    def test_a_signal_in_a_call_that_still_ends_normally_ends_the_broker_after_its_answer(self):
        self.add('t2')
        for flag in ('terminated', 'sigints'):
            with self.subTest(flag=flag):
                self.ctx = mod.Broker(clock=self.clock, sleep=self.clock.advance); self.calls.clear(); self.killed.clear()
                for stem in ('r1', 'r2'): mod.shutil.rmtree(self.dirs('t1' if stem == 'r1' else 't2')[1] / stem, ignore_errors=True)
                self.put('r1.json'); self.put('r2.json', task='t2')
                def flagged():                                                  # what the handler does while the call runs
                    if flag == 'terminated': self.ctx.terminated = True
                    else: self.ctx.sigints += 1
                self.script = lambda cmd: FakeProc(line(state='refused', reason='no'), code=1, on_wait=flagged)
                slept = []
                with patch.object(mod, 'Broker', return_value=self.ctx), patch.object(mod, 'broker_start'), \
                     patch.object(self.ctx, 'sleep', side_effect=slept.append):
                    mod.broker_main()
                self.assertEqual(len(self.calls), 1); self.assertEqual(self.killed, []); self.assertEqual(slept, [])
                self.assertEqual(self.answer('r1')['state'], 'refused')         # the call that ended is answered
                self.assertTrue((self.dirs('t2')[0] / 'r2.json').exists())      # nothing new is handed over
                self.assertIn('Broker stopped.', self.pane())
                with (self.state / 'broker.lock').open('a') as lock: mod.fcntl.flock(lock, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)
                mod.os.unlink(self.dirs('t2')[0] / 'r2.json')
        self.assertIn('Ctrl-C: waiting for the running call', sys.stderr.getvalue())

    def test_text_with_control_and_invisible_characters(self):
        self.assertEqual(mod.broker_esc('a\x1b[0m\u202e b\n\udcff'), 'a\\u{1b}[0m\\u{202e} b\\u{a}\\u{dcff}')
        self.assertEqual(mod.broker_clean('a\x1b[0m\u202e\n b\t\u00a0c'), 'a[0m b c')
        self.assertEqual(len(mod.broker_clean('x' * 900)), 400)

    # --- memory requests through the broker, .dropped
    def dropped(self, task='t1'):
        f = self.dirs(task)[1] / '.dropped'
        return json.loads(f.read_text())['entries'] if f.exists() else []
    def mreq(self, name='m1.json', text='note', task='t1', **extra): return self.put(name, task=task, v=1, type='memory', text=text, **extra)
    def stored(self, outcome='new', pushed=True, note='note', write=None):
        def harness(cmd):
            if write: (self.memory / 'projects/example-site.md').write_text(write)  # what the real harness commits
            return FakeProc(line(state='stored', outcome=outcome, pushed=pushed, note=note), code=0)
        return harness
    def view(self, task='t1'): return mod.memory_paths(task)[0]
    def counter(self, task='t1'): return mod.broker_memory_counter(task)

    def test_memory_goes_to_the_harness_with_the_project_from_the_record_and_stored_refreshes_the_view(self):
        self.mreq(project='example-app')                                     # the request's project is never used (the harness refuses it)
        note = 'note \x1b[31mwith\u202e colour ' + 'x' * 200
        self.round(self.stored(note=note, write='# example-site\n- 2026-11-16: note\n'))
        cmd, kw, staged = self.calls[0]
        staged_path = str(self.state / 'broker-runs/staging/t1/m1.json')
        self.assertEqual(cmd, [str(self.harness / 'bin/nc'), 'memory', 'apply', '--broker', '--project', 'example-site', '--request', staged_path, '--requester', 't1'])
        self.assertEqual((kw['cwd'], kw['start_new_session']), ('/', True)); self.assertEqual(staged[0][0], staged_path)
        self.assertEqual(self.answer('m1'), {'v': 1, 'request': 'm1', 'state': 'stored', 'reason': None, 'task_id': None, 'timeout_min': None,
                                             'started': None, 'result': {'outcome': 'new', 'pushed': True}})
        self.assertIn('- 2026-11-16: note', (self.view() / 'projects/example-site.md').read_text())
        shown = mod.broker_clean(note, 120)
        self.assertEqual(len(shown), 120); self.assertNotIn('\x1b', shown); self.assertNotIn('\u202e', shown)
        self.assertIn(f't1 memory stored (new): {shown} m1\n', self.pane())
        self.assertFalse((self.state / 'broker-runs/staging/t1/m1.json').exists()); self.assertEqual(list(self.dirs()[0].iterdir()), [])
        self.assertEqual(self.ctx.last_handover, {})                          # the 10 s gap is a rule for delegate only
        self.mreq('m2.json'); self.round(self.stored(outcome='replaced', pushed=False), seconds=1)
        self.assertEqual(self.answer('m2')['result'], {'outcome': 'replaced', 'pushed': False}); self.assertIn('stored (replaced, not pushed)', self.pane())

    def test_the_view_is_refreshed_before_the_answer_is_written(self):
        seen, real = [], mod.broker_respond
        def respond(inbox, stem, state, **fields):
            seen.append((state, (self.view() / 'projects/example-site.md').read_text())); real(inbox, stem, state, **fields)
        self.mreq()
        with patch.object(mod, 'broker_respond', side_effect=respond):
            self.round(self.stored(write='# example-site\n- 2026-11-16: new\n'))
        self.assertEqual(seen, [('stored', '# example-site\n- 2026-11-16: new\n')])

    def test_unusable_memory_answers_of_the_harness_are_errors(self):
        cases = [('exit', line(state='stored', outcome='new', pushed=True, note='n'), 1), ('outcome', line(state='stored', outcome='deleted', pushed=True, note='n'), 0),
                 ('pushed', line(state='stored', outcome='new', pushed='yes', note='n'), 0), ('note', line(state='stored', outcome='new', pushed=True, note=5), 0),
                 ('two', line(state='stored', outcome='new', pushed=True, note='n') * 2, 0), ('refexit', line(state='refused', reason='no'), 2),
                 ('refused', line(state='refused', reason='note \x1b[31mtoo long'), 1), ('error', line(state='error', reason='broken'), 2)]
        for stem, out, code in cases:
            self.mreq(stem + '.json'); self.round(lambda cmd: FakeProc(out, b'nc memory: some reason\n', code), seconds=16)
        for stem in ('exit', 'outcome', 'pushed', 'note', 'two', 'refexit'):
            a = self.answer(stem); self.assertEqual(a['state'], 'error', stem); self.assertIn('the harness gave no usable answer', a['reason'])
        self.assertEqual((self.answer('refused')['state'], self.answer('refused')['reason']), ('refused', 'note [31mtoo long'))
        self.assertEqual((self.answer('error')['state'], self.answer('error')['reason']), ('error', 'broken'))
        self.assertIn('stderr: some reason', self.pane()); self.assertFalse(self.counter().exists())
        self.assertFalse((self.view() / 'MEMORY.md').exists())                 # no view without stored

    def test_every_outcome_is_stored_and_only_new_and_replaced_are_counted(self):
        # each outcome passes through unchanged; the daily counter grows only for new and replaced
        cases = [('new', 1), ('refreshed', 1), ('unchanged', 1), ('replaced', 2)]
        for i, (outcome, count) in enumerate(cases):
            self.mreq(f'm{i}.json'); self.round(self.stored(outcome=outcome), seconds=16)
            a = self.answer(f'm{i}'); self.assertEqual((a['state'], a['result']), ('stored', {'outcome': outcome, 'pushed': True}), outcome)
            self.assertEqual(json.loads(self.counter().read_text())['count'], count, outcome)

    def test_a_worker_or_a_task_without_memory_is_refused_without_a_harness_call(self):
        self.add('w1', worker=True); self.add('old', memory=None)
        self.mreq(task='w1'); self.mreq(task='old'); self.round(lambda cmd: self.fail(cmd))
        self.assertEqual(self.answer('m1', 'w1')['reason'], 'w1: worker task without memory (nc delegate)')
        self.assertEqual(self.answer('m1', 'old')['reason'], 'old: task without memory (created by an older nc-work)')
        self.assertEqual((self.answer('m1', 'w1')['state'], self.answer('m1', 'old')['state']), ('refused', 'refused')); self.assertEqual(self.calls, [])

    def test_at_most_twenty_new_or_replaced_notes_per_task_and_utc_day(self):
        outcomes = ['new'] * 10 + ['refreshed', 'unchanged'] + ['replaced'] * 10
        for i, outcome in enumerate(outcomes):
            self.mreq(f'm{i:02d}.json'); self.round(self.stored(outcome=outcome), seconds=16)
            self.assertEqual(self.answer(f'm{i:02d}')['state'], 'stored')
        self.assertEqual(json.loads(self.counter().read_text()), {'token': self.token['t1'], 'day': '2027-01-15', 'count': 20})
        self.assertEqual((self.counter().stat().st_mode & 0o777, self.counter().parent.stat().st_mode & 0o777), (0o600, 0o700))
        calls = len(self.calls); self.mreq('m99.json'); self.round(lambda cmd: self.fail(cmd), seconds=16)
        a = self.answer('m99'); self.assertEqual((a['state'], a['reason']), ('refused', 'at most 20 new or replaced notes per task and day'))
        self.assertEqual(len(self.calls), calls)
        self.clock.now = 1_800_028_800.0 + 86400                              # the next UTC day
        self.mreq('n1.json'); self.round(self.stored()); self.assertEqual(self.answer('n1')['state'], 'stored')
        self.assertEqual(json.loads(self.counter().read_text())['count'], 1)
        mod.save(self.counter(), {'token': self.token['t1'], 'day': '2027-01-16', 'count': 20})
        self.add('t1', token='9' * 32)                                          # removed and made again: another token starts at 0
        self.mreq('n2.json'); self.round(self.stored(), seconds=16); self.assertEqual(self.answer('n2')['state'], 'stored')
        self.assertEqual(json.loads(self.counter().read_text())['token'], '9' * 32)
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=1, stdout=b'')): mod.remove('t1', force=True)
        self.assertFalse(self.counter().exists())

    def test_two_hundred_stored_answers_do_not_fill_the_inbox(self):
        for i in range(mod.BROKER_MAX_ANSWERS): mod.broker_respond(self.dirs()[1], f'm{i:03d}', 'stored', result={'outcome': 'new', 'pushed': True})
        self.assertEqual(mod.broker_answer_count(self.dirs()[1]), 0)
        self.put('r1.json'); self.round(lambda cmd: self.started())
        self.assertEqual(self.answer('r1')['state'], 'started')

    def test_a_full_inbox_still_takes_memory_and_drops_refusals_and_failed_cleanups_into_dot_dropped(self):
        self.full(); self.worker()
        self.mreq('m1.json'); self.round(self.stored())
        self.assertEqual(self.answer('m1')['state'], 'stored'); self.assertEqual(len(self.folders()), mod.BROKER_MAX_ANSWERS + 1)
        self.assertEqual(mod.broker_answer_count(self.dirs()[1]), mod.BROKER_MAX_ANSWERS)
        before = self.folders()
        self.mreq('m2.json'); self.round(lambda cmd: FakeProc(line(state='refused', reason='note too long'), code=1), seconds=16)
        for i, (code, err, events) in enumerate([(1, b'nc delegate: worker still running\n', ()), (2, b'nc delegate: Docker gone\n', ()), (0, b'', ['timeout'] * 400)]):
            self.put(f'c{i}.json', v=1, type='cleanup', task_id=TID)
            self.round(lambda cmd: FakeProc(b'', err, code, events=events, clock=self.clock), seconds=16)
        self.assertEqual(self.folders(), before)
        reasons = {e['request']: e['reason'] for e in self.dropped()}
        self.assertEqual(reasons, {'m2': 'note too long', 'c0': 'worker still running', 'c1': 'Docker gone', 'c2': 'timeout (5 minutes) in the harness call'})
        f = self.dirs()[1] / '.dropped'; self.assertEqual(f.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in self.dirs()[1].iterdir() if p.name.startswith('.')), ['.broker', '.dropped'])

    def test_dot_dropped_keeps_eight_entries_newest_first_and_stays_under_8_kib(self):
        self.full(); before = self.folders()
        for i in range(10):
            self.put(f'r{i}.json'); self.round(lambda cmd: self.fail(cmd), seconds=1)
        self.assertEqual(self.folders(), before)
        self.assertEqual([e['request'] for e in self.dropped()], [f'r{i}' for i in range(9, 1, -1)])
        self.assertRegex(self.dropped()[0]['ts'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        for i in range(8): mod.broker_dropped(self.dirs()[1], f'w{i}', '\U0001d538' * 300)  # four bytes each, cut to 200
        raw = (self.dirs()[1] / '.dropped').read_bytes(); self.assertLess(len(raw), 8 * 1024)
        doc = json.loads(raw.decode('utf-8')); self.assertEqual(len(doc['entries']), 8); self.assertEqual(doc['entries'][0]['request'], 'w7')
        self.assertEqual(doc['entries'][0]['reason'], '\U0001d538' * 200); self.assertIn('\U0001d538', raw.decode('utf-8'))  # not escaped
        with patch.object(mod, 'BROKER_DROPPED_MAX', 2000): mod.broker_dropped(self.dirs()[1], 'w8', 'x')
        self.assertLessEqual(len((self.dirs()[1] / '.dropped').read_bytes()), 2000); self.assertEqual(self.dropped()[0]['request'], 'w8')

    def test_dot_dropped_never_follows_a_link_and_starts_over_when_it_is_broken(self):
        host = self.root / 'host.json'; host.write_text('host file\n')
        f = self.dirs()[1] / '.dropped'; f.symlink_to(host)
        mod.broker_dropped(self.dirs()[1], 'r1', 'x')
        self.assertEqual(host.read_text(), 'host file\n'); self.assertFalse(f.is_symlink()); self.assertEqual([e['request'] for e in self.dropped()], ['r1'])
        for broken in [b'{"v":1,"entries":[', b'{"v":2,"entries":[{"request":"a","reason":"b","ts":"c"}]}', b'x' * (40 * 1024)]:
            f.write_bytes(broken); mod.broker_dropped(self.dirs()[1], 'r2', 'y')
            self.assertEqual([e['request'] for e in self.dropped()], ['r2'])

    def test_a_delegate_request_named_like_a_memory_request_is_a_delegate_request(self):
        self.put('m20261115-0000.json'); self.round(lambda cmd: self.started())
        self.assertEqual(self.calls[0][0][1:3], ['delegate', '--broker']); self.assertEqual(self.answer('m20261115-0000')['state'], 'started')

    def test_broker_type_decides_by_the_content_only(self):
        table = [(b'{"v":1,"type":"memory","text":"x"}', ('memory', None)), (b'{"type":"memory"}', ('memory', None)),
                 (b'{"v":1,"type":"memory","text":"x","project":"acme"}', ('memory', None)),
                 (b'{"v":1,"type":"cleanup","task_id":"d1115-1432-ab12"}', ('cleanup', TID)), (b'{"v":1,"type":"cleanup"}', ('cleanup', '')),
                 (b'{"v":1,"type":"delegate"}', ('delegate', None)), (b'{"type":["memory"]}', ('delegate', None)), (b'["memory"]', ('delegate', None)),
                 (b'"memory"', ('delegate', None)), (b'not json', ('delegate', None)), (b'{"type":"memory\xff"}', ('delegate', None)), (b'', ('delegate', None))]
        for data, want in table:
            with self.subTest(data=data): self.assertEqual(mod.broker_type(data), want)

    def test_a_timeout_or_a_signal_in_the_memory_call_is_an_error_without_the_half_worker_text(self):
        self.mreq(); self.round(lambda cmd: FakeProc(b'', events=['timeout'] * 400, clock=self.clock))
        a = self.answer('m1'); self.assertEqual(a['state'], 'error'); self.assertIn('timeout (5 minutes)', a['reason'])
        self.assertNotIn(mod.BROKER_HALF, a['reason']); self.assertEqual(self.killed[0], (4242, mod.signal.SIGTERM))
        def closed(): self.ctx.terminated = True
        self.mreq('m2.json'); self.clock.advance(16)
        self.script = lambda cmd: FakeProc(b'', events=['timeout', 'done'], clock=self.clock, on_wait=closed)
        with self.assertRaises(mod.BrokerStop): mod.broker_round(self.ctx)
        a = self.answer('m2'); self.assertEqual(a['state'], 'error'); self.assertIn('broker stopped', a['reason']); self.assertNotIn(mod.BROKER_HALF, a['reason'])
        self.assertFalse(self.staged('m2.json').exists()); self.assertFalse(self.counter().exists())

    def test_cutting_the_mailbox_to_eight_writes_dot_dropped_once_per_round(self):
        for i in range(12): self.mreq(f'm{i:02d}.json')
        real, writes = mod.broker_put, []
        def put(folder, name, write, mode=0o644):
            if name == '.dropped': writes.append(name)
            return real(folder, name, write, mode)
        with patch.object(mod, 'broker_put', side_effect=put): self.round(self.stored())
        self.assertEqual(writes, ['.dropped'])
        self.assertEqual([e['request'] for e in self.dropped()], ['m11', 'm10', 'm09', 'm08'])
        self.assertEqual(self.dropped()[0]['reason'], 'mailbox full (more than 8 requests)')
        (self.dirs()[0] / 'zz bad.json').write_text('{}')                     # sorts last: cut, but no entry for a wrong name
        for i in range(12, 21): self.mreq(f'm{i:02d}.json')                    # 4 left + 9 + a wrong name: only valid names get entries
        self.round(seconds=61)
        self.assertNotIn('zz bad', [e['request'] for e in self.dropped()]); self.assertEqual(self.dropped()[0]['request'], 'm20')

    def test_memory_view_waits_briefly_for_a_held_lock_and_always_closes_its_fd(self):
        fd = os.open(self.memory, os.O_RDONLY | os.O_DIRECTORY); self.addCleanup(os.close, fd)
        mod.fcntl.flock(fd, mod.fcntl.LOCK_EX)                                # nc memory writes
        t0 = mod.time.monotonic(); mod.memory_view('t1', 'example-site')
        self.assertGreaterEqual(mod.time.monotonic() - t0, 0.2); self.assertIn('has been locked', sys.stderr.getvalue())
        self.assertEqual((self.view() / 'MEMORY.md').read_text(), '# Index\n')
        mod.fcntl.flock(fd, mod.fcntl.LOCK_UN)
        mod.memory_view('t1', 'example-site')
        mod.fcntl.flock(fd, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)            # memory_view closed its fd: nothing holds the lock
        mod.fcntl.flock(fd, mod.fcntl.LOCK_UN)
        with patch.object(mod, 'MEMORY', self.root / 'no-memory'): mod.memory_view('t1', 'example-site')
        self.assertTrue((self.view() / 'projects').is_dir()); self.assertFalse((self.view() / 'MEMORY.md').exists())

    def test_memory_view_replaces_files_in_place_and_removes_only_what_no_longer_belongs(self):
        (self.memory / 'global/a.md').write_text('a\n'); mod.memory_view('t1', 'example-site')
        inode = (self.view() / 'MEMORY.md').stat().st_ino
        (self.memory / 'global/a.md').unlink(); (self.memory / 'MEMORY.md').write_text('# Index 2\n')
        (self.view() / 'stray.md').write_text('x'); (self.view() / 'old').mkdir()
        mod.memory_view('t1', 'example-site')
        self.assertEqual(sorted(str(p.relative_to(self.view())) for p in self.view().rglob('*')), ['MEMORY.md', 'projects', 'projects/example-site.md'])
        self.assertEqual((self.view() / 'MEMORY.md').read_text(), '# Index 2\n'); self.assertNotEqual((self.view() / 'MEMORY.md').stat().st_ino, inode)

    def test_a_second_memory_view_for_the_same_task_waits_for_the_first(self):
        import threading
        (self.memory / 'global/a.md').write_text('a\n')
        real, entered, release, copied, errors = mod.shutil.copyfile, threading.Event(), threading.Event(), [], []
        def copyfile(src, dst):
            copied.append(threading.current_thread().name)
            if threading.current_thread().name == 'first' and not entered.is_set():
                entered.set(); release.wait(5)                                 # the first run stops halfway through
            return real(src, dst)
        def view():
            try: mod.memory_view('t1', 'example-site')
            except Exception as exc: errors.append(exc)
        with patch.object(mod.shutil, 'copyfile', side_effect=copyfile):
            first, second = threading.Thread(target=view, name='first'), threading.Thread(target=view, name='second')
            first.start(); self.assertTrue(entered.wait(5))
            second.start(); second.join(0.3)
            self.assertTrue(second.is_alive()); self.assertNotIn('second', copied)  # waits on the task folder's lock
            release.set(); first.join(5); second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive()); self.assertEqual(errors, [])
        self.assertEqual(sorted(str(p.relative_to(self.view())) for p in self.view().rglob('*')),
                         ['MEMORY.md', 'global', 'global/a.md', 'projects', 'projects/example-site.md'])
        self.assertEqual(((self.view() / 'MEMORY.md').read_text(), (self.view() / 'global/a.md').read_text()), ('# Index\n', 'a\n'))
        fd = os.open(self.view().parent, os.O_RDONLY | os.O_DIRECTORY); self.addCleanup(os.close, fd)
        mod.fcntl.flock(fd, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)            # both runs closed their fd on the task folder

    def failing_put(self, which):
        real = mod.broker_put
        def put(folder, name, write, mode=0o644):
            if name == which: raise OSError(28, 'No space left on device')
            return real(folder, name, write, mode)
        return patch.object(mod, 'broker_put', side_effect=put)

    def test_a_host_fault_after_stored_still_answers_or_says_so_in_dot_dropped_and_removes_the_staged_copy(self):
        self.mreq('m1.json')
        with self.failing_put('t1.json'): self.round(self.stored())           # the daily counter
        self.assertEqual(self.answer('m1')['result'], {'outcome': 'new', 'pushed': True}); self.assertFalse(self.counter().exists())
        self.assertIn('t1 memory counter not saved: [Errno 28] No space left on device m1', self.pane())
        self.assertFalse(self.staged('m1.json').exists()); self.assertEqual(self.dropped(), [])
        self.mreq('m2.json')
        with self.failing_put('response.json'): self.round(self.stored(), seconds=16)
        self.assertFalse((self.dirs()[1] / 'm2/response.json').exists())
        self.assertEqual([(e['request'], e['reason']) for e in self.dropped()],
                         [('m2', 'stored, answer not written – the note is in the memory')])
        self.assertIn('t1 memory answer not written', self.pane()); self.assertIn('stored (new): note m2', self.pane())
        self.assertFalse(self.staged('m2.json').exists()); self.assertEqual(json.loads(self.counter().read_text())['count'], 1)
        # After a restart m2 is never answered again ("submit the note again" for a stored note), even if its staged copy had
        # survived: broker_start leaves a request with an answer folder alone and drops the copy.
        self.staged('m2.json').write_text(json.dumps({'v': 1, 'type': 'memory', 'text': 'note m2'}))
        pane = self.pane(); mod.broker_start(self.ctx)
        self.assertFalse((self.dirs()[1] / 'm2/response.json').exists()); self.assertEqual(self.pane(), pane)
        self.assertFalse(self.staged('m2.json').exists())

    def test_a_memory_request_the_client_took_back_between_reading_and_deleting_is_never_applied(self):
        self.mreq(); real = mod.broker_read
        def read(path, limit):
            data = real(path, limit)
            if pathlib.Path(path).parent == self.dirs()[0]: os.unlink(path)     # the client takes it back right after the broker read it
            return data
        with patch.object(mod, 'broker_read', side_effect=read): self.round(lambda cmd: self.fail(cmd))
        self.assertEqual(self.calls, []); self.assertFalse((self.dirs()[1] / 'm1').exists())
        self.assertFalse(self.staged('m1.json').exists()); self.assertIn('taken back by the task', self.pane())
        self.assertEqual(self.ctx.answered['t1'], [])
        self.put('r1.json')                                                     # delegate is answered all the same (as before)
        with patch.object(mod, 'broker_read', side_effect=read): self.round(lambda cmd: FakeProc(line(state='refused', reason='no'), code=1), seconds=1)
        self.assertEqual(self.answer('r1')['state'], 'refused')

FAKE_NC_WORK = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
with open(os.environ['FAKE_LOG'], 'a') as log: log.write(json.dumps(['nc-work', *sys.argv[1:]]) + '\n')
cmd = sys.argv[1]
if cmd == 'create':
    print(json.dumps({'id': sys.argv[3], 'worker': True, 'from_task': sys.argv[sys.argv.index('--from-task') + 1],
                      'from_token': os.environ['FAKE_TOKEN'], 'base': os.environ['FAKE_BASE']}, indent=2))
elif cmd == 'export':
    tid, out = sys.argv[2], pathlib.Path(sys.argv[sys.argv.index('--out') + 1])
    out.mkdir(mode=0o700)
    subprocess.run(['git', 'init', '-q', '--bare', str(out / 'repo.git')], check=True)
    subprocess.run(['git', '-C', os.environ['FAKE_SRC'], 'push', '-q', str(out / 'repo.git'), 'HEAD:refs/heads/nc-work/' + tid], check=True)
    (out / 'RESULT.raw').write_bytes(b'STATUS: done\nfinished\n')
    head = subprocess.run(['git', '-C', os.environ['FAKE_SRC'], 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
    data = {'task': tid, 'branch': 'nc-work/' + tid, 'base': os.environ['FAKE_BASE'], 'head': head, 'base_is_ancestor': True,
            'commits': 1, 'dirty': False, 'result_file': 'present'}
    (out / 'export.json').write_text(json.dumps(data)); print(json.dumps(data))
'''
FAKE_HC = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_LOG'], 'a') as log: log.write(json.dumps(['hc', *sys.argv[1:]]) + '\n')
print(json.dumps({'name': 'x'}))
'''

class BrokerContractTests(unittest.TestCase):
    """The broker against the real harness (bin/nc delegate of the checkout in HARNESS), with a fake nc-work and hc on the PATH, a
    temporary HOME and bun on the PATH. Skipped without the checkout or bun. The memory test checks the outcome, the commit
    subject and the refusal reason of the harness."""
    def setUp(self):
        import shutil
        self.bun = shutil.which('bun')
        if not (mod.HARNESS / 'bin/nc').is_file(): self.skipTest(f'no harness checkout in {mod.HARNESS}')
        if not self.bun: self.skipTest('bun not found')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(os.path.realpath(self.tmp.name))
        self.state, self.home, fake = root / 'state', root / 'home', root / 'bin'
        for d in (self.state / 'tasks', self.home / 'projects/sites/example-site', fake): d.mkdir(parents=True)
        for name, text in [('nc-work', FAKE_NC_WORK), ('hc', FAKE_HC)]: (fake / name).write_text(text); (fake / name).chmod(0o755)
        src = root / 'src'; g = ['git', '-C', str(src), '-c', 'user.name=t', '-c', 'user.email=t@t.invalid']
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(src)], check=True)
        for n in ('base', 'work'):
            (src / n).write_text(n); subprocess.run([*g, 'add', n], check=True); subprocess.run([*g, 'commit', '-qm', n], check=True)
        self.base = subprocess.run([*g, 'rev-parse', 'HEAD~1'], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        self.head = subprocess.run([*g, 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        self.log, self.token = root / 'calls.jsonl', 'a' * 32
        env = {'HOME': str(self.home), 'PATH': f'{fake}:{os.path.dirname(self.bun)}:/usr/bin:/bin', 'FAKE_LOG': str(self.log),
               'FAKE_TOKEN': self.token, 'FAKE_BASE': self.base, 'FAKE_SRC': str(src)}
        for p in [patch.object(mod, 'STATE', self.state), patch.object(mod.pathlib.Path, 'home', return_value=self.home),
                  patch.dict(os.environ, env), patch('sys.stdout', new_callable=io.StringIO), patch.object(mod.sys, 'stderr', new_callable=io.StringIO)]:
            p.start(); self.addCleanup(p.stop)
        for k in ('NC_HARNESS_VERSION', 'NC_REQUESTS', 'NC_INBOX', 'NC_DELEGATE_LOCKED'): os.environ.pop(k, None)
        mod.save(self.state / 'tasks/t1.json', {'id': 't1', 'project': 'example-site', 'status': 'ready', 'broker': True, 'broker_token': self.token,
                                                'project_path': 'sites/example-site', 'base': self.base})
        mod.broker_folders('t1')
        self.ctx = mod.Broker()

    def calls(self): return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_one_round_then_the_result_through_the_real_harness(self):
        requests, inbox = mod.broker_paths('t1')[1:]
        (requests / 'r1.json').write_text(json.dumps({'v': 1, 'type': 'delegate', 'role': 'tester', 'task': 'write a test', 'model': None, 'timeout': 20}))
        mod.broker_round(self.ctx)
        answer = json.loads((inbox / 'r1/response.json').read_text())
        self.assertEqual(answer['state'], 'started', (answer, sys.stdout.getvalue()))
        tid = answer['task_id']; self.assertRegex(tid, mod.BROKER_ID.pattern)
        self.assertEqual(answer['timeout_min'], 20); self.assertRegex(answer['started'], r'^\d{4}-\d\d-\d\dT')
        calls = self.calls()
        self.assertEqual(calls[0], ['nc-work', 'create', 'example-site', tid, '--worker', '--from-task', 't1'])
        runner = str(mod.HARNESS.resolve() / 'cli/delegate-run.sh')
        self.assertEqual(calls[1], ['hc', 'run', '--bg', '--no-notify', '--outlive-parent', '--name', tid, '--', 'bash', '-lc', f"'{runner}' {tid}"])
        self.assertEqual(len(calls), 2)
        run = mod.broker_runs()[0]; self.assertEqual((run['id'], run['requester'], run['token'], run['request']), (tid, 't1', self.token, 'r1'))
        folder = self.home / '.nc/delegate' / tid
        req = json.loads((folder / 'request.json').read_text())
        self.assertEqual((req['origin'], req['requester'], req['requester_token'], req['request_name'], req['base']), ('broker', 't1', self.token, 'r1.json', self.base))

        (folder / 'status.json').write_text(json.dumps({'exit': 0, 'ended': '2026-11-15T15:00:00Z'}))
        self.ctx.due[tid] = 0
        mod.broker_poll(self.ctx)
        self.assertIn(['nc-work', 'export', tid, '--out', str(folder / 'export')], self.calls())
        delivery = folder / 'delivery'
        self.assertEqual(sorted(p.name for p in delivery.iterdir()), ['RESULT.md', 'result.bundle', 'result.json'])
        self.assertEqual((delivery / 'RESULT.md').read_text(), 'STATUS: done\nfinished\n')
        result = json.loads((delivery / 'result.json').read_text())
        self.assertEqual((result['status'], result['task_id'], result['head'], result['result']), ('done', tid, self.head, '/opt/nc-inbox/r1/RESULT.md'))
        heads = subprocess.run(['git', 'bundle', 'list-heads', str(delivery / 'result.bundle')], stdout=subprocess.PIPE, check=True).stdout.decode()
        self.assertEqual(heads.split(), [self.head, f'refs/heads/nc-work/{tid}'])
        done = json.loads((inbox / 'r1/response.json').read_text())
        self.assertEqual((done['state'], done['result']), ('done', result))
        self.assertEqual((inbox / 'r1/result.bundle').read_bytes(), (delivery / 'result.bundle').read_bytes())
        self.assertEqual(mod.broker_runs(), [])

    def test_a_note_through_the_real_harness_is_committed_pushed_and_in_the_view(self):
        import shutil
        if not shutil.which('flock', path=os.environ['PATH']): self.skipTest('flock not in the PATH of the test')
        root = self.home.parent; remote, memory = root / 'memory.git', self.home / '.nc/memory'
        seed = root / 'seed'; (seed / 'projects').mkdir(parents=True); (seed / 'global').mkdir()
        (seed / 'MEMORY.md').write_text('# Index\n'); (seed / 'projects/example-site.md').write_text('# example-site\n')
        g = lambda d, *a: subprocess.run(['git', '-C', str(d), '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', *a], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['git', 'init', '-q', '--bare', '-b', 'main', str(remote)], check=True)
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(seed)], check=True); g(seed, 'add', '-A'); g(seed, 'commit', '-qm', 'seed'); g(seed, 'push', '-q', str(remote), 'main')
        subprocess.run(['git', 'clone', '-q', str(remote), str(memory)], check=True)
        g(memory, 'config', 'user.name', 'test'); g(memory, 'config', 'user.email', 'test@invalid')
        with patch.object(mod, 'MEMORY', memory):
            mod.save(self.state / 'tasks/t1.json', {**mod.task('t1'), 'memory': True})
            requests, inbox = mod.broker_paths('t1')[1:]
            (requests / 'm1.json').write_text(json.dumps({'v': 1, 'type': 'memory', 'text': 'contract test note'}))
            mod.broker_round(self.ctx)
            answer = json.loads((inbox / 'm1/response.json').read_text())
            self.assertEqual(answer['state'], 'stored', (answer, sys.stdout.getvalue()))
            self.assertEqual(answer['result'], {'outcome': 'new', 'pushed': True})
            subject = subprocess.run(['git', '-C', str(remote), 'log', '-1', '--format=%s', 'main'], stdout=subprocess.PIPE, check=True).stdout.decode()
            self.assertEqual(subject.strip(), 'nc memory apply: example-site (task t1, new)')
            self.assertIn('contract test note', (mod.memory_paths('t1')[0] / 'projects/example-site.md').read_text())
            commits = subprocess.run(['git', '-C', str(remote), 'rev-list', '--count', 'main'], stdout=subprocess.PIPE, check=True).stdout.decode()
            (requests / 'm2.json').write_text(json.dumps({'v': 1, 'type': 'memory', 'text': 'with a project', 'project': 'example-site'}))
            self.ctx.answered.clear(); mod.broker_round(self.ctx)
            answer = json.loads((inbox / 'm2/response.json').read_text())
            self.assertEqual(answer['state'], 'refused', answer)
            self.assertIn('contains a project field – the host sets the project, not the request', answer['reason'])
            self.assertEqual(subprocess.run(['git', '-C', str(remote), 'rev-list', '--count', 'main'], stdout=subprocess.PIPE, check=True).stdout.decode(), commits)

keyproxy_path = pathlib.Path(__file__).resolve().parents[1] / 'keyproxy/keyproxy.py'
keyproxy_spec = importlib.util.spec_from_file_location('keyproxy', keyproxy_path)
keyproxy = importlib.util.module_from_spec(keyproxy_spec); keyproxy_spec.loader.exec_module(keyproxy)

class KeyProxyTests(unittest.TestCase):
    """keyproxy.py against a fake target: a local plain HTTP server, no TLS, no tunnel."""
    KEY = 'sk-or-v1-synthetic-proxy-key'
    PATH = b'/api/v1/chat/completions'

    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.seen, self.mode, self.release = [], {'kind': 'ok'}, threading.Event()
        test = self
        class Target(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *a): pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                test.seen.append((self.command, self.path, list(self.headers.items()), body))
                kind = test.mode['kind']
                if kind == 'redirect':
                    self.send_response(302); self.send_header('Location', 'https://elsewhere.example/steal')
                    self.send_header('Content-Length', '0'); self.end_headers(); return
                self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Set-Cookie', 'a=b'); self.send_header('X-Upstream-Secret', 'internal')
                self.send_header('Connection', 'close'); self.end_headers()
                self.wfile.write(b'data: first\n\n'); self.wfile.flush()
                if kind == 'stream': test.release.wait(10)
                self.wfile.write(b'data: second\n\n'); self.wfile.flush()
                self.close_connection = True
        self.target = ThreadingHTTPServer(('127.0.0.1', 0), Target); self.target.daemon_threads = True
        threading.Thread(target=self.target.serve_forever, daemon=True).start()
        self.addCleanup(self.target.server_close); self.addCleanup(self.target.shutdown)
        self.start_proxy()

    def start_proxy(self, read_timeout=5):
        import threading
        if getattr(self, 'proxy', None): self.proxy.shutdown(); self.proxy.server_close()
        self.log = io.StringIO()
        self.proxy = keyproxy.serve(self.KEY, port=0, host='127.0.0.1', upstream=self.target.server_address, tls=False,
                                    tunnel=False, read_timeout=read_timeout, log=self.log)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.addCleanup(self.proxy.server_close); self.addCleanup(self.proxy.shutdown)
        self.port = self.proxy.server_address[1]
        self.answers = []

    def raw(self, data, timeout=10):
        import socket
        s = socket.create_connection(('127.0.0.1', self.port), timeout=timeout)
        try:
            s.sendall(data); chunks = []
            while (c := s.recv(65536)): chunks.append(c)
        finally: s.close()
        answer = b''.join(chunks); self.answers.append(answer)
        return answer

    def request(self, method=b'POST', target=PATH, headers=(), body=b'{"model":"x"}', length=True):
        head = [method + b' ' + target + b' HTTP/1.1', b'Host: key-test:8080']
        head += [k + b': ' + v for k, v in headers]
        if length: head.append(b'Content-Length: ' + str(len(body)).encode())
        return self.raw(b'\r\n'.join(head) + b'\r\n\r\n' + body)

    def status(self, answer): return int(answer.split(b' ', 2)[1])

    def tearDown(self):
        for text in self.answers + [self.log.getvalue().encode()]:
            self.assertNotIn(self.KEY.encode(), text)                           # never in an answer or a log line

    def test_an_allowed_path_is_forwarded_with_the_key_the_host_and_the_constant_path(self):
        answer = self.request(headers=[(b'Content-Type', b'application/json'), (b'X-Title', b'opencode'),
                                       (b'Authorization', b'Bearer nc-keyproxy'), (b'Cookie', b'session=1'),
                                       (b'Proxy-Authorization', b'Basic x'), (b'X-Opencode-Session', b's1'), (b'Accept-Encoding', b'gzip')])
        self.assertEqual(self.status(answer), 200)
        self.assertIn(b'data: first', answer); self.assertIn(b'data: second', answer)
        method, path, headers, body = self.seen[-1]
        self.assertEqual((method, path, body), ('POST', '/api/v1/chat/completions', b'{"model":"x"}'))
        got = {}
        for k, v in headers: got.setdefault(k.lower(), []).append(v)
        self.assertEqual(got['authorization'], ['Bearer ' + self.KEY])           # exactly the proxy's own, once
        self.assertEqual(got['host'], ['openrouter.ai'])
        self.assertEqual(got['content-type'], ['application/json']); self.assertEqual(got['x-title'], ['opencode'])
        self.assertEqual(set(got), {'authorization', 'host', 'content-type', 'x-title', 'content-length', 'connection'})
        head = answer.split(b'\r\n\r\n', 1)[0].lower()
        self.assertNotIn(b'set-cookie', head); self.assertNotIn(b'x-upstream-secret', head)
        self.assertIn(b'content-type: text/event-stream', head)
        self.assertRegex(self.log.getvalue(), r'^\S+Z POST /api/v1/chat/completions 200 \d+\n$')
        self.assertNotIn('refused', self.log.getvalue())  # the label is for refusals only

    def test_everything_else_ends_with_404_or_405_and_reaches_nothing(self):
        cases = [(b'POST', b'http://openrouter.ai/api/v1/chat/completions', 404), (b'POST', self.PATH + b'?x=1', 404),
                 (b'POST', b'/api/v1/x/../chat/completions', 404), (b'POST', b'/api/v1/chat/%63ompletions', 404),
                 (b'POST', b'/api/v1/%2e%2e/v1/chat/completions', 404), (b'POST', b'//api/v1/chat/completions', 404),
                 (b'POST', b'/api/v1/chat/completions/', 404), (b'POST', b'/api/v1/models', 404), (b'POST', b'/API/v1/chat/completions', 404),
                 (b'GET', self.PATH, 404), (b'CONNECT', b'openrouter.ai:443', 405), (b'OPTIONS', self.PATH, 405), (b'PUT', self.PATH, 405),
                 (b'DELETE', self.PATH, 405)]
        for method, target, expected in cases:
            with self.subTest(method=method, target=target):
                self.assertEqual(self.status(self.request(method, target)), expected)
        self.assertEqual(self.seen, [])
        self.assertEqual(self.log.getvalue().count(' refused '), len(cases))
        for method, target, _ in cases: self.assertNotIn(target.decode(), self.log.getvalue())  # no text of the client

    def test_ready_answers_locally(self):
        self.assertEqual(self.status(self.raw(b'GET /__ready HTTP/1.1\r\nHost: x\r\n\r\n')), 200)
        self.assertEqual(self.seen, [])

    def test_body_rules(self):
        big = str(keyproxy.BODY_MAX + 1).encode()
        cases = [([(b'Content-Length', big)], False, 413), ([], False, 411),
                 ([(b'Content-Length', b'2'), (b'Content-Length', b'2')], False, 400), ([(b'Content-Length', b'+2')], False, 400),
                 ([(b'Content-Length', b'2 ')], False, 200),  # optional whitespace around the value is not part of it
                 ([(b'Content-Length', b'0x2')], False, 400), ([(b'Content-Length', b'')], False, 400),
                 ([(b'Transfer-Encoding', b'chunked')], True, 400), ([(b'transfer-encoding', b'identity')], True, 400),
                 ([(b'TRANSFER-ENCODING', b'chunked')], True, 400), ([(b'Transfer_Encoding', b'chunked')], True, 400),
                 ([(b'Transfer-Encoding ', b'chunked')], True, 400), ([(b'Content_Length', b'2')], True, 400)]
        for headers, length, expected in cases:
            with self.subTest(headers=headers):
                self.assertEqual(self.status(self.request(headers=headers, body=b'{}', length=length)), expected)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.status(self.request(body=b'x' * keyproxy.BODY_MAX)), 200)  # exactly the limit passes

    def test_a_redirect_is_not_followed_and_comes_back_without_location(self):
        self.mode['kind'] = 'redirect'
        answer = self.request()
        self.assertEqual(self.status(answer), 302)
        self.assertNotIn(b'location', answer.lower()); self.assertNotIn(b'elsewhere', answer)
        self.assertEqual(len(self.seen), 1)

    def test_a_stream_arrives_in_pieces(self):
        import socket
        self.mode['kind'] = 'stream'
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10); self.addCleanup(s.close)
        s.sendall(b'POST /api/v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}')
        got = b''
        while b'data: first' not in got: got += s.recv(65536)
        self.assertNotIn(b'second', got)                                          # the target is not done yet
        self.release.set()
        while (c := s.recv(65536)): got += c
        self.assertIn(b'data: second', got)

    def test_slow_clients_hold_no_slot_past_the_timeout(self):
        import socket, time
        self.start_proxy(read_timeout=2)
        slow = []
        for _ in range(keyproxy.SLOTS):
            s = socket.create_connection(('127.0.0.1', self.port), timeout=10); self.addCleanup(s.close)
            s.sendall(b'POST /api/v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n{'); slow.append(s)
        until = time.monotonic() + 1.5
        while self.proxy.slots._value and time.monotonic() < until: time.sleep(0.02)
        self.assertEqual(self.status(self.request()), 503)                       # all eight slots taken
        begin = time.monotonic()
        for s in slow: self.assertEqual(s.recv(100), b'')                        # cut off, nothing forwarded
        self.assertLess(time.monotonic() - begin, 3)
        self.assertEqual(self.status(self.request()), 200)                       # the slots are free again
        trickle = socket.create_connection(('127.0.0.1', self.port), timeout=10); self.addCleanup(trickle.close)
        trickle.sendall(b'POST /api/v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n')
        begin = time.monotonic()
        try:
            for _ in range(9): trickle.sendall(b'x'); time.sleep(0.5)             # one byte every 0.5 s: under the
        except OSError: pass                                                      # socket timeout, over the deadline
        try: end = trickle.recv(100)
        except ConnectionResetError: end = b''                                    # bytes after the close: a reset
        self.assertEqual(end, b''); self.assertLess(time.monotonic() - begin, 5)
        self.assertEqual(len([s for s in self.seen]), 1)

    def test_too_many_or_too_long_headers_are_refused_and_slow_headers_are_cut_off(self):
        import socket, time
        self.assertEqual(self.status(self.request(headers=[(b'X-Long', b'x' * 20000)])), 431)
        self.assertEqual(self.status(self.request(headers=[(b'X-%d' % i, b'1') for i in range(70)])), 431)
        self.assertEqual(self.seen, [])
        self.start_proxy(read_timeout=1)
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10); self.addCleanup(s.close)
        s.sendall(b'POST /api/v1/chat/completions HTTP/1.1\r\n')
        begin = time.monotonic()
        try:
            for _ in range(12): s.sendall(b'X'); time.sleep(0.3)   # one header byte every 0.3 s: under the socket timeout
        except OSError: pass
        try: end = s.recv(100)
        except ConnectionResetError: end = b''
        self.assertEqual(end, b''); self.assertLess(time.monotonic() - begin, 5)

    def test_an_unreachable_target_is_a_502_without_detail(self):
        self.target.shutdown(); self.target.server_close()
        answer = self.request()
        self.assertEqual(self.status(answer), 502)
        self.assertNotIn(b'127.0.0.1', answer); self.assertNotIn(b'Connection refused', answer)

    def test_the_container_values_are_fixed(self):
        self.assertEqual((keyproxy.UPSTREAM, keyproxy.EGRESS), (('openrouter.ai', 443), ('egress', 3128)))
        self.assertEqual(keyproxy.ROUTES, {(b'POST', b'/api/v1/chat/completions'): '/api/v1/chat/completions'})
        source = keyproxy_path.read_text()
        for used in ('urllib', 'os.environ', 'getenv', 'sys.argv', 'import os', 'import requests'): self.assertNotIn(used, source)

    def test_the_key_comes_on_stdin_and_a_bad_one_stops_the_proxy(self):
        r = subprocess.run([sys.executable, '-I', '-B', str(keyproxy_path)], input=b'not a key\n', capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 2); self.assertNotIn(b'not a key', r.stdout + r.stderr)

class CheckLeakTests(unittest.TestCase):
    """check-leak: counts the real keys in files or stdin, prints only counts. Each name is read on its own."""
    script = pathlib.Path(__file__).resolve().parents[1] / 'keyproxy/check-leak'
    DEFAULT, CLIENTS = 'sk-or-v1-synthetic-default-leak', 'sk-or-v1-synthetic-clients-leak'
    NAMES = ('OPENROUTER_API_KEY', 'OPENROUTER_API_KEY_CLIENTS')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home = pathlib.Path(self.tmp.name)
        folder = self.home / '.config/nc-harness'; folder.mkdir(parents=True)
        self.secrets = folder / 'secrets.env'
        self.secrets.write_text(f'OPENROUTER_API_KEY={self.DEFAULT}\nOPENROUTER_API_KEY_CLIENTS={self.CLIENTS}\n'); self.secrets.chmod(0o600)

    def check(self, *args, data=b''):
        r = subprocess.run([sys.executable, '-I', '-B', str(self.script), *args], input=data, capture_output=True, timeout=60,
                           env={'HOME': str(self.home), 'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
        for key in (self.DEFAULT, self.CLIENTS): self.assertNotIn(key.encode(), r.stdout + r.stderr)
        return r.returncode, r.stdout.decode()

    def out(self, *counts): return ''.join(f'{n}: {c}\n' for n, c in zip(self.NAMES, counts))

    def test_counts_every_key_raw_and_json_escaped_never_the_value(self):
        f = self.home / 'dump.txt'
        f.write_text(f'a {self.DEFAULT} b {self.DEFAULT}\n{json.dumps({"k": self.CLIENTS})}\n')
        self.assertEqual(self.check(str(f)), (1, self.out(2, 1)))
        self.assertEqual(self.check('-', data=f'x{self.CLIENTS}x'.encode()), (1, self.out(0, 1)))
        self.assertEqual(self.check('-', data=b'nc-keyproxy and nothing else'), (0, self.out(0, 0)))

    def test_a_missing_key_is_named_and_none_at_all_checks_nothing(self):
        self.secrets.write_text(f'OPENROUTER_API_KEY={self.DEFAULT}\n'); self.secrets.chmod(0o600)
        self.assertEqual(self.check('-', data=b'x'), (0, self.out(0, 'not set (not checked)')))
        self.secrets.write_text(f'OPENROUTER_API_KEY_CLIENTS={self.CLIENTS}\n'); self.secrets.chmod(0o600)
        self.assertEqual(self.check('-', data=self.CLIENTS.encode()), (1, self.out('not set (not checked)', 1)))
        self.secrets.write_text('OTHER=1\n'); self.secrets.chmod(0o600)
        self.assertEqual(self.check('-', data=b'x')[0], 2)
        self.assertEqual(self.check()[0], 2)                                      # no input named

class OverlayTests(unittest.TestCase):
    """~/.nc/overlay: its profiles win over the shipped ones, and its AGENTS.md and models.yaml go into the harness snapshot."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.ov, self.harness, self.state = root / 'overlay', root / 'harness', root / 'state'
        for p in [patch.object(mod, 'OVERLAY', self.ov), patch.object(mod, 'HARNESS', self.harness), patch.object(mod, 'STATE', self.state),
                  patch.object(mod, 'PROFILE_DIRS', (self.ov / 'profiles', FIXTURES / 'profiles'))]:
            p.start(); self.addCleanup(p.stop)
        self.git(self.harness, 'init', '-q')
        (self.harness / 'AGENTS.md').write_text('public rules\n'); (self.harness / 'models.yaml').write_text('public: true\n')
        (self.harness / 'README.md').write_text('readme\n')
        self.commit = self.commit_all(self.harness)

    def git(self, folder, *args):
        folder.mkdir(parents=True, exist_ok=True)
        return subprocess.run(['git', '-C', str(folder), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', *args],
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def commit_all(self, folder):
        self.git(folder, 'add', '-A'); self.git(folder, 'commit', '-q', '-m', 'x'); return self.git(folder, 'rev-parse', 'HEAD')

    def overlay(self, agents=b'private rules\n', models=b'private: true\n'):
        self.ov.mkdir(parents=True, exist_ok=True)
        if agents is not None: (self.ov / 'AGENTS.md').write_bytes(agents)
        if models is not None: (self.ov / 'models.yaml').write_bytes(models)
        (self.ov / 'docs').mkdir(exist_ok=True); (self.ov / 'docs/CONTEXT.md').write_text('private context\n')

    def write_profile(self, name, **change):
        data = {**json.loads((FIXTURES / 'profiles/example-site.json').read_text()), 'id': name, **change}
        (self.ov / 'profiles').mkdir(parents=True, exist_ok=True)
        (self.ov / 'profiles' / (name + '.json')).write_text(json.dumps(data))

    def test_an_overlay_profile_wins_on_the_same_id(self):
        self.write_profile('example-site', path='private/site', github='private-org/site')
        self.assertEqual(mod.profile('example-site')['path'], 'private/site')
        self.assertEqual(mod.project_for(pathlib.Path.home() / 'projects/private/site')['id'], 'example-site')
        with self.assertRaises(ValueError): mod.profile('../example-site')

    def test_listing_is_the_union_of_both_folders(self):
        self.write_profile('private-one', path='private/one')
        self.write_profile('example-site', path='private/site')
        (self.ov / 'profiles/.hidden.json').write_text('not json')
        self.assertEqual([p['id'] for p in mod.all_profiles()], ['example-app', 'example-client', 'example-site', 'private-one'])
        with patch.object(mod.sys, 'argv', ['nc-work', 'profiles', '--json']), patch('sys.stdout', new_callable=io.StringIO) as out:
            mod.main()
        data = {p['id']: p['path'] for p in json.loads(out.getvalue())}
        self.assertEqual((data['private-one'], data['example-site'], data['example-app']), ('private/one', 'private/site', 'clients/acme/app'))
        with patch.object(mod.sys, 'argv', ['nc-work', 'profiles']), patch('sys.stdout', new_callable=io.StringIO) as out:
            mod.main()
        self.assertIn('private-one Node 24 private/one\n', out.getvalue())

    def test_no_overlay_or_a_dangling_one_is_fine_for_profiles(self):
        self.assertEqual(len(mod.all_profiles()), 3)
        self.ov.symlink_to(self.harness.parent / 'gone')
        self.assertEqual(len(mod.all_profiles()), 3)
        self.assertEqual(mod.profile('example-site')['path'], 'sites/example-site')

    def test_snapshot_without_overlay_is_the_plain_commit(self):
        self.assertEqual(mod.snapshot(), self.commit)
        self.assertEqual((self.state / 'harness' / self.commit / 'AGENTS.md').read_text(), 'public rules\n')
        self.assertEqual(json.loads((self.state / 'harness-current.json').read_text()), {'commit': self.commit})
        self.overlay(agents=None, models=None)  # an overlay without models.yaml refuses, as nc models does on the host
        with self.assertRaisesRegex(ValueError, 'no models.yaml'): mod.snapshot()

    def test_snapshot_bakes_in_the_overlay_files_and_nothing_else(self):
        self.overlay(); self.write_profile('private-one')
        tag = mod.snapshot()
        self.assertRegex(tag, '^' + self.commit + '-[0-9a-f]{12}$')
        target = self.state / 'harness' / tag
        self.assertEqual((target / 'AGENTS.md').read_text(), 'private rules\n')
        self.assertEqual((target / 'models.yaml').read_text(), 'private: true\n')
        self.assertEqual(sorted(f.name for f in target.iterdir()), ['AGENTS.md', 'README.md', 'models.yaml'])
        self.assertEqual(sorted(f.name for f in (self.state / 'harness').iterdir()), [tag])  # no .tmp left
        self.assertEqual(json.loads((self.state / 'harness-current.json').read_text()), {'commit': tag})
        self.assertEqual(mod.snapshot(), tag)                                    # same content, same tag
        (self.ov / 'models.yaml').write_text('private: changed\n')
        self.assertNotEqual(mod.snapshot(), tag)
        (self.ov / 'models.yaml').unlink()                                      # AGENTS.md alone never falls back to the public policy
        with self.assertRaisesRegex(ValueError, 'no models.yaml'): mod.snapshot()

    def test_a_stale_tmp_folder_is_replaced(self):
        self.overlay()
        tag = mod.snapshot()
        import shutil; shutil.rmtree(self.state / 'harness' / tag)
        stale = self.state / 'harness' / (tag + '.tmp'); (stale / 'sub').mkdir(parents=True); (stale / 'junk').write_text('x')
        self.assertEqual(mod.snapshot(), tag)
        self.assertFalse(stale.exists()); self.assertFalse((self.state / 'harness' / tag / 'junk').exists())

    def test_links_other_files_and_oversized_files_are_refused(self):
        secret = self.harness.parent / 'secrets.env'; secret.write_text('KEY=x\n')
        cases = []
        def link(): self.overlay(agents=None); (self.ov / 'AGENTS.md').symlink_to(secret)
        def dangling_file(): self.overlay(agents=None); (self.ov / 'AGENTS.md').symlink_to(self.ov / 'gone')
        def folder(): self.overlay(models=None); (self.ov / 'models.yaml').mkdir()
        def fifo(): self.overlay(models=None); os.mkfifo(self.ov / 'models.yaml')
        def big(): self.overlay(models=b'x' * (mod.OVERLAY_MAX + 1))
        def dangling_overlay(): self.ov.symlink_to(self.harness.parent / 'gone')
        def plain_file(): self.ov.write_text('not a folder')
        for make, text in [(link, 'not a readable regular file'), (dangling_file, 'not a readable regular file'), (folder, 'not a regular file'),
                           (fifo, 'not a regular file'), (big, 'larger than'), (dangling_overlay, 'not a folder'), (plain_file, 'not a folder')]:
            with self.subTest(make.__name__):
                if self.ov.is_symlink() or self.ov.is_file(): self.ov.unlink()
                elif self.ov.exists(): import shutil; shutil.rmtree(self.ov)
                make()
                with self.assertRaisesRegex(ValueError, text): mod.snapshot()
                self.assertFalse((self.state / 'harness-current.json').exists())
        self.ov.unlink()
        self.overlay(models=b'x' * mod.OVERLAY_MAX)                             # exactly the cap is fine
        self.assertTrue(mod.snapshot().startswith(self.commit + '-'))

    def test_uncommitted_overlay_files_are_refused_like_the_harness(self):
        self.overlay(); self.git(self.ov, 'init', '-q')
        with self.assertRaisesRegex(ValueError, 'uncommitted changes'): mod.snapshot()  # untracked
        self.commit_all(self.ov)
        tag = mod.snapshot()
        (self.ov / 'docs/CONTEXT.md').write_text('changed, never copied\n')     # other files do not matter
        self.assertEqual(mod.snapshot(), tag)
        (self.ov / 'AGENTS.md').write_text('edited\n')
        with self.assertRaisesRegex(ValueError, 'uncommitted changes'): mod.snapshot()
        (self.harness / 'README.md').write_text('dirty harness\n')
        with self.assertRaisesRegex(ValueError, 'Harness has uncommitted changes'): mod.snapshot()

    def test_memory_follows_nc_home_like_nc_memory(self):
        def load(env):
            fresh = importlib.util.module_from_spec(spec)
            with patch.dict(os.environ, env, clear=False):
                if not env.get('NC_HOME'): os.environ.pop('NC_HOME', None)
                loader.exec_module(fresh)
            return fresh
        self.assertEqual(load({'NC_HOME': '/srv/nc'}).MEMORY, pathlib.Path('/srv/nc/memory'))
        self.assertEqual(load({'NC_HOME': ''}).MEMORY, pathlib.Path.home() / '.nc/memory')
        fresh = load({'NC_HOME': '/srv/nc'})
        self.assertEqual(fresh.OVERLAY, pathlib.Path.home() / '.nc/overlay')    # the overlay never moves with NC_HOME

# --- english-only: no German in any tracked file of work-environments/
def _plain(text): return text.replace('0', '')  # the guard's words carry a 0, so its own source does not match them

LANG_CHARS = '[\u00e4\u00f6\u00fc\u00c4\u00d6\u00dc\u00df\u201e\u201c]'
LANG_PREFIXES = _plain('auf0tr ver0mittler schl\u00fc0ssel schlu0essel ged\u00e40chtnis an0frage no0tiz post0fach ein0gang ab0gelehnt '
                       'ab0gebrochen ge0startet ge0speichert feh0ler feh0lt un0gueltig gue0ltig zu0rueck').split()
LANG_WORDS = _plain('u0nd ni0cht o0der wi0rd i0st er0st no0ch sch0on d0er d0as d0em z0u b0ei a0uf n0ur we0nn ke0in ke0ine e0in ei0ne '
                    'ei0nen si0ch au0ch w0ir fer0tig ne0in schr0eibe oh0ne fal0scher or0dner da0tei la0uf te0il').split()
# From nc-harness tests/language.ts: whole words, case-insensitive; none of them is an English word.
LANG_HARNESS_WORDS = _plain('dir0ekt iso0liert unbe0kannt aufge0frischt er0setzt projekt0pfad bei0spiel pa0ket ent0fernt').split()
LANG_CASED = [_plain('m0it')]  # lowercase only: "Mit" is not counted
LANG_SUBSTRINGS = _plain('kun0den ver0trieb').split()  # no word boundary
# Never add die, den, an, in, so, was, will, bin, man, hat, also or war: they are English words too.
LANG_PATTERNS = [re.compile(LANG_CHARS), re.compile(r'\b(?:' + '|'.join(LANG_PREFIXES) + ')', re.I),
                 re.compile(r'\b(?:' + '|'.join(LANG_WORDS + LANG_HARNESS_WORDS) + r')\b', re.I), re.compile(r'\b(?:' + '|'.join(LANG_CASED) + r')\b'),
                 re.compile('|'.join(LANG_SUBSTRINGS), re.I)]
LANG_MARKER = '# lang-guard: ' + 'patterns'  # fallback: one marked line in the whole tree is skipped, no more
_W = 'work-environments/'
# (file, literal): the literal is cut out of its lines before matching. Every entry must still occur in its file.
LANG_ALLOWED = []

def lang_hit(line):
    """The first German match in one line, or None. The line is NFC-normalized first, so a decomposed umlaut (a + U+0308)
    counts. Escape sequences \\n, \\t and \\r count as a space."""
    line = unicodedata.normalize('NFC', line).replace('\\n', ' ').replace('\\t', ' ').replace('\\r', ' ')
    for pattern in LANG_PATTERNS:
        if (found := pattern.search(line)): return found.group(0)
    return None

def lang_classify(raw):
    """What the scan does with a file, from its raw bytes: 'skip' when they contain a NUL (binary, checked before decoding),
    'fail' when they are not valid UTF-8, 'text' otherwise."""
    if b'\0' in raw: return 'skip'
    try: raw.decode('utf-8')
    except UnicodeDecodeError: return 'fail'
    return 'text'

class LanguageGuardTests(unittest.TestCase):
    """Fails on German in any file that `git ls-files work-environments/` lists, apart from LANG_ALLOWED, and on a file that is
    not valid UTF-8. A file with a NUL byte is binary and skipped; a file that cannot be read is skipped and named on stderr."""
    repo = pathlib.Path(__file__).resolve().parents[2]

    def test_the_patterns_catch_german_and_spare_english(self):
        for text in [_plain('Au0ftrag'), 'gr\u00f6\u00dfer', _plain('x ni0cht y'), _plain('"\\nni0cht"'), _plain('m0it'), _plain('KUN0DENLISTE'),
                     _plain('x-ver0trieb'), _plain('\u201eZitat\u201c'), _plain('Ged\u00e40chtnis'), _plain('fe0hlt'),
                     _plain('mode: dir0ekt'), _plain('ISO0LIERT'), _plain('unbe0kannt'), _plain('aufge0frischt'), _plain('er0setzt'),
                     _plain('PROJEKT0PFAD'), _plain('Bei0spiel'), _plain('Pa0ket'), _plain('ent0fernt'), _plain('\u00fcber u0nd'), _plain('a_b u0nd'),
                     'Ma\u0308rz', _plain('Auf0tragsliste'), _plain('"\\tni0cht"'), _plain('"\\rni0cht"'), '\u201c']:
            self.assertIsNotNone(lang_hit(text), text)
        for text in ['die den an in so was will bin man hat also war', 'Mit', 'the broker stopped during hand-over', 'refused (too large)',
                     'en dash \u2013 and ellipsis \u2026 are fine', 'start, inbox, notice, auction, disturb', 'direct isolated unknown replaced refreshed',
                     'example package removed PROJECT_PATH', _plain('und0efined un0done x_i0st_y mitigate'), _plain('xauf0tragsliste')]:
            self.assertIsNone(lang_hit(text), text)

    def test_the_byte_rule_skips_binary_and_fails_on_bytes_that_are_not_utf8(self):
        for raw, want in [(b'a\x00\xff', 'skip'), (b'caf\xe9\n', 'fail'), (b'plain ASCII\n', 'text')]:
            self.assertEqual(lang_classify(raw), want, raw)

    def test_no_german_in_tracked_files(self):
        listed = subprocess.run(['git', 'ls-files', 'work-environments/'], cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        files = listed.stdout.decode().split('\n') if listed.returncode == 0 else []
        files = [f for f in files if f]
        self.assertEqual(listed.returncode, 0, listed.stderr.decode()); self.assertTrue(files, 'git ls-files lists nothing')  # never a skip
        allowed = {}
        for f, literal in LANG_ALLOWED: allowed.setdefault(f, []).append(literal)
        hits, binary, invalid, unreadable, used, marked = [], [], [], [], set(), []
        for f in files:
            try: raw = (self.repo / f).read_bytes()
            except OSError: unreadable.append(f); continue  # a folder (a gitlink), no permission: named, not a failure
            kind = lang_classify(raw)
            if kind == 'skip': binary.append(f); continue
            if kind == 'fail': invalid.append(f); continue
            for number, line in enumerate(raw.decode('utf-8').split('\n'), 1):
                if LANG_MARKER in line: marked.append(f'{f}:{number}'); continue
                line = unicodedata.normalize('NFC', line)
                for literal in allowed.get(f, []):
                    if literal in line: used.add((f, literal)); line = line.replace(literal, ' ')
                if (word := lang_hit(line)): hits.append(f'{f}:{number}: {word!r}')
        if binary: print(f'\nlanguage guard: binary (NUL byte), skipped: {", ".join(binary)}', file=sys.__stderr__)
        if unreadable: print(f'\nlanguage guard: not readable, skipped: {", ".join(unreadable)}', file=sys.__stderr__)
        self.assertEqual(invalid, [], 'not valid UTF-8:\n' + '\n'.join(invalid))
        self.assertEqual(hits, [], 'German text:\n' + '\n'.join(hits))
        self.assertEqual([e for e in LANG_ALLOWED if e not in used], [], 'allow-list entries that match nothing any more')
        self.assertLessEqual(len(marked), 1, f'more than one line marked {LANG_MARKER!r}: {marked}')

if __name__ == '__main__': unittest.main()
