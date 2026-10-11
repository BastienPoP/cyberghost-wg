"""Offline tests for cyberghost-wg (no network, no account). Run: python3 -m unittest discover -s tests"""

import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("cyberghost_wg", os.path.join(HERE, "..", "cyberghost-wg"))
_spec = importlib.util.spec_from_loader("cyberghost_wg", _loader)
cg = importlib.util.module_from_spec(_spec)
_loader.exec_module(cg)

KEY = base64.b64encode(bytes(32)).decode()
CRED_VARS = ("CG_USERNAME", "CG_PASSWORD", "CG_USERNAME_FILE", "CG_PASSWORD_FILE", "CREDENTIALS_DIRECTORY")


class FakeStdin(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


def args(**kw):
    return mock.Mock(spec=["username", "password_stdin"], **{"username": None, "password_stdin": False, **kw})


class X25519(unittest.TestCase):
    def test_rfc7748_vectors(self):
        vectors = {  # RFC 7748, section 6.1
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a":
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb":
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        }
        for private, public in vectors.items():
            self.assertEqual(cg.x25519_public(bytes.fromhex(private)).hex(), public)

    def test_generated_keys_are_clamped_unique_and_consistent(self):
        seen = set()
        for _ in range(3):
            private, public = cg.generate_keypair()
            raw = base64.b64decode(private)
            self.assertEqual(len(raw), 32)
            self.assertEqual(raw[0] & 7, 0)
            self.assertEqual(raw[31] & 0xC0, 0x40)
            self.assertEqual(base64.b64encode(cg.x25519_public(raw)).decode(), public)
            seen.add(private)
        self.assertEqual(len(seen), 3)


class ParseAddKey(unittest.TestCase):
    def test_valid_answer(self):
        peer = cg.parse_addkey({"status": "OK", "peer_ip": "10.5.1.2", "server_key": KEY,
                                "server_port": "51820", "dns_servers": ["10.101.0.243", "38.132.106.139"]})
        self.assertEqual(peer, {"address": "10.5.1.2/32", "server_key": KEY, "port": 51820,
                                "dns": ["10.101.0.243", "38.132.106.139"]})

    def test_dns_as_string_and_fallback(self):
        base = {"peer_ip": "10.5.1.2/32", "server_key": KEY, "server_port": 1}
        self.assertEqual(cg.parse_addkey({**base, "dns_servers": "1.1.1.1, 9.9.9.9"})["dns"], ["1.1.1.1", "9.9.9.9"])
        self.assertEqual(cg.parse_addkey(base)["dns"], [cg.DEFAULT_DNS])

    def test_rejects_invalid_or_injected_values(self):
        base = {"peer_ip": "10.0.0.1", "server_key": KEY, "server_port": 1}
        for bad in ({**base, "peer_ip": "10.0.0.1\nPostUp = touch /tmp/pwned"},
                    {**base, "peer_ip": "fd00::1"},
                    {**base, "server_key": "AAAA"},
                    {**base, "server_key": KEY + "\nPostUp = x"},
                    {**base, "server_port": 70000},
                    {**base, "dns_servers": ["1.1.1.1; rm -rf /"]},
                    {}):
            with self.assertRaises(cg.CgError, msg=bad):
                cg.parse_addkey(bad)

    def test_rendered_config(self):
        peer = {"address": "10.5.1.2/32", "server_key": KEY, "port": 1337, "dns": ["10.101.0.243"]}
        conf = cg.render_conf("x", "PRIV", peer, "84.17.52.96")
        self.assertIn("[Interface]\nPrivateKey = PRIV\nAddress = 10.5.1.2/32\nDNS = 10.101.0.243\n", conf)
        self.assertIn(f"[Peer]\nPublicKey = {KEY}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 84.17.52.96:1337\n", conf)
        self.assertIn("AllowedIPs = 10.0.0.0/8\n", cg.render_conf("x", "PRIV", peer, "192.0.2.1", "10.0.0.0/8"))

    def test_allowed_ips(self):
        self.assertEqual(cg.parse_allowed_ips(" 0.0.0.0/0 ,::/0"), "0.0.0.0/0, ::/0")
        self.assertEqual(cg.parse_allowed_ips("192.168.1.7/24, 10.1.2.3"), "192.168.1.0/24, 10.1.2.3/32")
        for bad in ("", " , ", "10.0.0.0/33", "0.0.0.0/0\nPostUp = x", "example.com"):
            with self.assertRaises(cg.CgError, msg=bad):
                cg.parse_allowed_ips(bad)


class ListInstances(unittest.TestCase):
    ACCOUNT = {"id": 1, "location": {"latitude": 1, "longitude": 2}, "activeProduct": {"plan": {"id": 7}}}

    def run_list(self, rows, code=200, **kw):
        answers = iter([(200, self.ACCOUNT), (code, rows)])
        with mock.patch.object(cg, "api", side_effect=lambda *a, **k: next(answers)) as api:
            return cg.list_instances("jwt", "CH", kw.pop("server_type", "torrent"), **kw), api

    def test_sorted_by_load_with_names_cleaned(self):
        rows = [{"displayName": "Zurich-S404-I02", "city": "Zurich", "totalusers": 50, "Max_Users": 100},
                {"displayName": "NospyproxyZurich-S404-I01", "city": "Zurich", "totalusers": 10, "Max_Users": 100},
                {"displayName": "Huenenberg-S409-I05", "city": "Huenenberg", "totalusers": 1, "Max_Users": 0},
                {"displayName": "", "city": "Zurich"}, "junk"]
        instances, api = self.run_list(rows)
        self.assertEqual(instances, [{"instance": "zurich-s404-i01", "city": "zurich", "load": 10},
                                     {"instance": "zurich-s404-i02", "city": "zurich", "load": 50},
                                     {"instance": "huenenberg-s409-i05", "city": "huenenberg", "load": 100}])
        self.assertIn("/my/servers/filters/71?filter_protocol=wireguard&filter_country=CH&filter_user_plans_id=7",
                      api.call_args_list[1].args[1])

    def test_city_filter_and_all_filter(self):
        rows = [{"displayName": "a", "city": "Zurich", "totalusers": 1, "Max_Users": 2},
                {"displayName": "b", "city": "Geneva", "totalusers": 1, "Max_Users": 2}]
        instances, api = self.run_list(rows, server_type="all", city="ZURICH")
        self.assertEqual([i["instance"] for i in instances], ["a"])
        self.assertIn("/my/servers/filters/74?filter_protocol=wireguard&filter_country=CH&filter_user_id=1",
                      api.call_args_list[1].args[1])

    def test_country_without_servers(self):
        self.assertEqual(self.run_list(None, code=204)[0], [])

    def test_api_error(self):
        with self.assertRaisesRegex(cg.CgError, "listing servers: HTTP 500 - E boom"):
            self.run_list({"errorCode": "E", "errorMessage": "boom"}, code=500)


class ListCountries(unittest.TestCase):
    def test_codes_deduplicated_and_sorted_by_name(self):
        rows = [{"countrycode": "ch", "name": "Switzerland"}, {"countrycode": "DE", "name": "Germany"},
                {"countrycode": "CH", "name": "Switzerland"}, {"countrycode": "XYZ"}, {"countrycode": "NL"}, "junk"]
        answers = iter([(200, ListInstances.ACCOUNT), (200, rows)])
        with mock.patch.object(cg, "api", side_effect=lambda *a, **k: next(answers)) as api:
            countries = cg.list_countries("jwt", "torrent")
        self.assertEqual(countries, [{"code": "DE", "name": "Germany"}, {"code": "NL", "name": "Netherlands"},
                                     {"code": "CH", "name": "Switzerland"}])
        self.assertIn("/my/servers/filters/75?filter_protocol=wireguard&filter_user_plans_id=7",
                      api.call_args_list[1].args[1])

    def test_all_filter(self):
        answers = iter([(200, ListInstances.ACCOUNT), (204, None)])
        with mock.patch.object(cg, "api", side_effect=lambda *a, **k: next(answers)) as api:
            self.assertEqual(cg.list_countries("jwt", "all"), [])
        self.assertIn("/my/servers/filters/73?filter_protocol=wireguard&filter_user_plans_id=7&filter_user_id=1",
                      api.call_args_list[1].args[1])


class FakeTty(io.StringIO):
    def isatty(self):
        return True


@mock.patch.dict(os.environ, {})
class Interactive(unittest.TestCase):
    COUNTRIES = [{"countrycode": "CH", "name": "Switzerland"}, {"countrycode": "DE", "name": "Germany"}]
    SERVERS = [{"displayName": f"Zurich-S1-I{n}", "city": "Zurich", "totalusers": n, "Max_Users": 100}
               for n in range(1, 13)] + [{"displayName": "Geneva-S2-I1", "city": "Geneva",
                                          "totalusers": 50, "Max_Users": 100}]
    ANSWER = {"status": "OK", "peer_ip": "10.5.1.2", "server_key": KEY, "server_port": 1337}

    def setUp(self):
        for var in ("CG_COUNTRY", "CG_TYPE"):
            os.environ.pop(var, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state.json")
        jwt_payload = base64.urlsafe_b64encode(json.dumps({"exp": 4102444800}).encode()).decode()
        cg.save_state(self.state, {"jwt": f"h.{jwt_payload}.s", "device": {"token": "t", "secret": "s"}})

    def run_cli(self, answers, *argv):
        def api(method, path, jwt=None, body=None):
            if path.startswith("/my/account"):
                return 200, ListInstances.ACCOUNT
            return 200, self.COUNTRIES if "/filters/75" in path or "/filters/73" in path else self.SERVERS
        err, out = FakeTty(), io.StringIO()
        with mock.patch.object(cg, "api", side_effect=api), \
                mock.patch.object(cg, "add_key", return_value=self.ANSWER) as add_key, \
                mock.patch.object(cg, "resolve_ipv4", return_value="192.0.2.1"), \
                mock.patch.object(sys, "stdin", FakeStdin("".join(a + "\n" for a in answers), tty=True)), \
                mock.patch.object(sys, "stderr", err), mock.patch.object(sys, "stdout", out):
            code = cg.main(["--state", self.state, "conf", "-i", *argv])
        return code, err.getvalue(), out.getvalue(), add_key

    def test_full_menu_by_numbers(self):
        target = os.path.join(self.tmp.name, "wg.conf")
        # torrent, country #2 (Switzerland, sorted by name), city zurich, server #3, file, confirm
        code, err, _, add_key = self.run_cli(["2", "2", "2", "4", target, ""])
        self.assertEqual(code, 0, err)
        self.assertEqual(add_key.call_args.args[0], "zurich-s1-i3.cg-dialup.net")
        self.assertIn("the 10 least loaded of 12", err)
        self.assertEqual(err.count(cg.KEY_WARNING), 2)  # before the menus and before generating
        self.assertRegex(err, r"Bring the tunnel up before \d\d:\d\d")
        with open(target, encoding="utf-8") as f:
            self.assertIn("# CyberGhost zurich-s1-i3 (torrent, load 3%)", f.read())
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)

    def test_defaults_and_country_code(self):
        # type all (default), country typed as code, any city, automatic server, print it
        code, err, out, add_key = self.run_cli(["", "de", "", "", "-", "y"])
        self.assertEqual(code, 0, err)
        self.assertEqual(add_key.call_args.args[0], "zurich-s1-i1.cg-dialup.net")
        self.assertIn("[Interface]", out)
        self.assertNotIn("Choice", out)  # prompts never reach stdout
        self.assertNotIn("Written to", err)  # the configuration itself says where it went

    def test_given_options_are_not_asked(self):
        code, err, out, _ = self.run_cli(["", "-", ""], "--type", "torrent", "--country", "CH", "--city", "geneva")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Server type", err)
        self.assertNotIn("Country", err)
        self.assertIn("geneva-s2-i1", out)

    def test_declining_generates_nothing(self):
        code, err, out, add_key = self.run_cli(["1", "1", "", "", "-", "n"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("cancelled", err)
        add_key.assert_not_called()

    def test_end_of_input_cancels(self):
        code, err, _, add_key = self.run_cli(["1"])
        self.assertEqual(code, 1)
        self.assertIn("cancelled", err)
        add_key.assert_not_called()

    def test_invalid_answers_are_asked_again(self):
        code, err, _, _ = self.run_cli(["9", "x", "1", "ZZ", "0", "ch", "", "", "-", ""])
        self.assertEqual(code, 0, err)
        self.assertIn(f"Type a number from 1 to {len(cg.SERVER_TYPES)}", err)
        self.assertIn("Type a number or a 2-letter code", err)

    def test_needs_a_terminal(self):
        with mock.patch.object(sys, "stdin", FakeStdin()), mock.patch.object(sys, "stderr", io.StringIO()) as err:
            self.assertEqual(cg.main(["--state", self.state, "conf", "-i"]), 1)
        self.assertIn("--interactive needs a terminal", err.getvalue())


@mock.patch.dict(os.environ, {})
class Credentials(unittest.TestCase):
    def setUp(self):
        for var in CRED_VARS:
            os.environ.pop(var, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def file(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def resolve(self, a=None, stdin=None):
        with mock.patch.object(sys, "stdin", stdin or FakeStdin()):
            return cg.get_credentials(a or args())

    def test_environment(self):
        os.environ.update(CG_USERNAME="alice", CG_PASSWORD="p w ")
        self.assertEqual(self.resolve(), ("alice", "p w "))

    def test_files_keep_inner_spaces_and_drop_one_newline(self):
        os.environ["CG_USERNAME_FILE"] = self.file("u", "alice\n")
        os.environ["CG_PASSWORD_FILE"] = self.file("p", " s3cr et \r\n")
        self.assertEqual(self.resolve(), ("alice", " s3cr et "))

    def test_file_and_variable_together_is_an_error(self):
        os.environ.update(CG_USERNAME="alice", CG_PASSWORD="x", CG_PASSWORD_FILE=self.file("p", "y"))
        with self.assertRaisesRegex(cg.CgError, "both set"):
            self.resolve()

    def test_missing_file_is_an_error(self):
        os.environ.update(CG_USERNAME="alice", CG_PASSWORD_FILE=os.path.join(self.tmp.name, "nope"))
        with self.assertRaisesRegex(cg.CgError, "cannot read the password"):
            self.resolve()

    def test_systemd_credentials(self):
        self.file("cg-username", "alice")
        self.file("cg-password", "secret\n")
        os.environ["CREDENTIALS_DIRECTORY"] = self.tmp.name
        self.assertEqual(self.resolve(), ("alice", "secret"))

    def test_password_stdin(self):
        self.assertEqual(self.resolve(args(username="alice", password_stdin=True), FakeStdin("secret\n")),
                         ("alice", "secret"))

    def test_password_stdin_needs_a_username(self):
        with self.assertRaisesRegex(cg.CgError, "needs --username"):
            self.resolve(args(password_stdin=True), FakeStdin("secret\n"))

    def test_username_flag_beats_environment(self):
        os.environ.update(CG_USERNAME="env", CG_PASSWORD="secret")
        self.assertEqual(self.resolve(args(username="flag")), ("flag", "secret"))

    def test_no_terminal_and_nothing_set(self):
        with self.assertRaisesRegex(cg.CgError, "credentials needed"):
            self.resolve()

    def test_prompt_in_a_terminal(self):
        with mock.patch.object(cg.getpass, "getpass", return_value="secret"), \
                mock.patch.object(sys, "stderr", io.StringIO()) as err, \
                mock.patch.object(sys, "stdout", io.StringIO()) as out:
            self.assertEqual(self.resolve(stdin=FakeStdin(" alice \n", tty=True)), ("alice", "secret"))
        self.assertEqual((err.getvalue(), out.getvalue()), ("CyberGhost username: ", ""))

    def test_empty_password_stdin(self):
        with self.assertRaisesRegex(cg.CgError, "credentials needed"):
            self.resolve(args(username="alice", password_stdin=True), FakeStdin(""))


class StateAndJwt(unittest.TestCase):
    def test_state_file_is_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "state.json")
            cg.save_state(path, {"device": {"token": "t"}})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
            self.assertEqual(cg.load_state(path), {"device": {"token": "t"}})
            self.assertEqual(os.listdir(os.path.dirname(path)), ["state.json"])
            self.assertEqual(cg.load_state(os.path.join(tmp, "missing.json")), {})

    def test_jwt_expiry(self):
        payload = base64.urlsafe_b64encode(json.dumps({"exp": 1900000000}).encode()).decode().rstrip("=")
        self.assertEqual(cg.jwt_expiry(f"h.{payload}.s"), 1900000000)
        for bad in ("", "abc", "h.!!!.s", None):
            self.assertEqual(cg.jwt_expiry(bad), 0)


class Cli(unittest.TestCase):
    def run_cli(self, *argv, env=None):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env or {}), \
                mock.patch.object(sys, "stderr", err), mock.patch.object(sys, "stdin", FakeStdin()):
            for var in CRED_VARS:
                os.environ.pop(var, None)
            try:
                code = cg.main(["--state", os.path.join(tmp, "s.json"), *argv])
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def test_conf_without_device(self):
        self.assertEqual(self.run_cli("conf", "--country", "CH"), (1, "cyberghost-wg: error: no device registered, run "
                                                                      "'cyberghost-wg login' first\n"))

    def test_bad_country_fails_before_authenticating(self):
        for argv in (("servers",), ("servers", "--country", "CHE"), ("servers", "--country", "C1")):
            code, err = self.run_cli(*argv)
            self.assertEqual(code, 1)
            self.assertIn("2-letter country code", err)

    def test_bad_type_from_environment(self):
        code, err = self.run_cli("servers", "--country", "CH", env={"CG_TYPE": "p2p"})
        self.assertEqual(code, 2)
        self.assertIn("invalid server type", err)

    def test_login_without_credentials(self):
        code, err = self.run_cli("login")
        self.assertEqual(code, 1)
        self.assertIn("credentials needed", err)

    def test_interactive_with_instance(self):
        code, err = self.run_cli("conf", "-i", "--instance", "x")
        self.assertEqual(code, 2)
        self.assertIn("cannot be used together", err)

    def test_bad_allowed_ips(self):
        code, err = self.run_cli("conf", "--instance", "x", "--allowed-ips", "nope", env={})
        self.assertEqual(code, 1)
        self.assertIn("invalid --allowed-ips", err)  # refused before anything else

    def test_logout_without_device(self):
        self.assertEqual(self.run_cli("logout"), (0, "No device registered.\n"))


def fake_systemd_creds(action, name, data):
    """Stands in for systemd-creds: a reversible encoding bound to the credential name."""
    if action == "encrypt":
        return b"ENC:" + name.encode() + b":" + base64.b64encode(data)
    prefix = b"ENC:" + name.encode() + b":"
    if not data.startswith(prefix):
        raise cg.CgError("decrypt failed: Name in credential doesn't match expectations.")
    return base64.b64decode(data[len(prefix):])


@mock.patch.dict(os.environ, {})
@mock.patch.object(cg, "systemd_creds", side_effect=fake_systemd_creds)
@mock.patch.object(cg, "can_remember", return_value=True)
class Login(unittest.TestCase):
    def setUp(self):
        for var in CRED_VARS:
            os.environ.pop(var, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "cfg", "state.json")
        self.logins = []
        self.devices = []

    def api(self, method, path, jwt=None, body=None):
        if path.startswith("/my/account/jwt"):
            self.logins.append((body["userName"], body["password"]))
            ok = body["password"] != "wrong"
            return (200, {"jwt": "h.e30.s"}) if ok else (401, {"errorCode": 2101, "errorMessage": "login wrong"})
        if path.startswith("/my/account"):
            return 200, ListInstances.ACCOUNT
        if method == "POST":
            self.device_name = body["machineName"]
            self.devices.append({"id": 5 + len(self.devices), "name": body["machineName"]})
            return 201, {"id": self.devices[-1]["id"], "token": "t", "tokenSecret": "s"}
        if path == "/my/devices":
            return 200, self.devices
        return 200, {}

    def run_cli(self, stdin, *argv, env=None):
        with mock.patch.object(cg, "api", side_effect=self.api), mock.patch.dict(os.environ, env or {}), \
                mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stderr", io.StringIO()) as err, \
                mock.patch.object(sys, "stdout", io.StringIO()):
            code = cg.main(["--state", self.state, *argv])
        return code, err.getvalue()

    def cred(self, what):
        return os.path.join(os.path.dirname(self.state), f"cg-{what}.cred")

    def test_name_and_remember_asked_in_a_terminal(self, *_):
        code, err = self.run_cli(FakeStdin("nas\n\n", tty=True), "login", env={"CG_USERNAME": "alice",
                                                                               "CG_PASSWORD": "secret"})
        self.assertEqual((code, self.device_name), (0, "nas"), err)
        self.assertIn("Device name", err)
        self.assertIn("Remember the credentials", err)
        for what, value in (("username", b"alice"), ("password", b"secret")):
            with open(self.cred(what), "rb") as f:
                content = f.read()
            self.assertNotIn(value, content)  # never in clear
            self.assertEqual(stat.S_IMODE(os.stat(self.cred(what)).st_mode), 0o600)

    def test_enter_keeps_the_default_name(self, *_):
        self.run_cli(FakeStdin("\nn\n", tty=True), "login", env={"CG_USERNAME": "a", "CG_PASSWORD": "b"})
        self.assertEqual(self.device_name, cg.default_device_name())
        self.assertFalse(os.path.exists(self.cred("password")))

    def test_no_question_without_terminal(self, *_):
        code, err = self.run_cli(FakeStdin(), "login", env={"CG_USERNAME": "a", "CG_PASSWORD": "b"})
        self.assertEqual(code, 0)
        self.assertNotIn("Device name", err)
        self.assertNotIn("Remember", err)
        self.assertFalse(os.path.exists(self.cred("password")))

    def test_remembered_credentials_are_used_when_the_jwt_expires(self, *_):
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        self.assertTrue(os.path.exists(self.cred("password")))
        state = cg.load_state(self.state)
        state["jwt"] = "expired"
        cg.save_state(self.state, state)
        with mock.patch.object(cg, "list_countries", return_value=[{"code": "CH", "name": ""}]):
            code, err = self.run_cli(FakeStdin(), "countries")  # no terminal, nothing set: only the remembered ones
        self.assertEqual(code, 0, err)
        self.assertEqual(self.logins[-1], ("alice", "secret"))

    def test_explicit_sources_win_over_remembered(self, *_):
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        cg.save_state(self.state, {**cg.load_state(self.state), "jwt": "expired"})
        with mock.patch.object(cg, "list_countries", return_value=[{"code": "CH", "name": ""}]):
            self.run_cli(FakeStdin(), "countries", env={"CG_USERNAME": "bob", "CG_PASSWORD": "other"})
        self.assertEqual(self.logins[-1], ("bob", "other"))

    def test_login_ignores_remembered_credentials(self, *_):
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        code, err = self.run_cli(FakeStdin(), "login")
        self.assertEqual(code, 1)
        self.assertIn("credentials needed", err)

    def test_wrong_remembered_password_says_how_to_fix(self, *_):
        self.run_cli(FakeStdin("wrong\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        self.assertFalse(os.path.exists(self.cred("password")))  # a refused login remembers nothing
        cg.remember(self.state, "alice", "wrong")
        cg.save_state(self.state, {"jwt": "expired", "device": {"id": 5, "token": "t", "secret": "s"}})
        code, err = self.run_cli(FakeStdin(), "countries")
        self.assertEqual(code, 1)
        self.assertIn("If your password changed, run 'cyberghost-wg login' again", err)

    def test_tampered_file_is_refused(self, *_):
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        os.replace(self.cred("username"), self.cred("password"))  # swapped files: names no longer match
        with self.assertRaisesRegex(cg.CgError, "cannot read the remembered password"):
            cg.remembered(self.state, "password")

    def test_no_remember_and_logout_forget(self, *_):
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        code, err = self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin",
                                 "--no-remember")
        self.assertIn("Previously remembered credentials removed", err)
        self.assertFalse(os.path.exists(self.cred("password")))
        self.run_cli(FakeStdin("secret\n"), "login", "--username", "alice", "--password-stdin", "--remember")
        code, err = self.run_cli(FakeStdin(), "logout")
        self.assertEqual(code, 0, err)
        self.assertIn("Remembered credentials removed", err)
        self.assertEqual(os.listdir(os.path.dirname(self.state)), [])


@mock.patch.dict(os.environ, {"CG_USERNAME": "alice", "CG_PASSWORD": "secret"})
class WithoutSystemdCreds(unittest.TestCase):
    """systemd-creds is optional: everything but remembering works without it."""

    def run_cli(self, stdin, *argv):
        def api(method, path, jwt=None, body=None):
            return (200, {"jwt": "h.e30.s"}) if path.startswith("/my/account/jwt") else \
                (201, {"id": 5, "token": "t", "tokenSecret": "s"})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(cg, "api", side_effect=api), \
                mock.patch.object(cg.shutil, "which", return_value=None), \
                mock.patch.object(cg.subprocess, "run", side_effect=FileNotFoundError), \
                mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stderr", io.StringIO()) as err:
            code = cg.main(["--state", os.path.join(tmp, "s.json"), "login", "--name", "n", *argv])
            files = sorted(os.listdir(tmp))
        return code, err.getvalue(), files

    def test_terminal_login_does_not_offer_to_remember(self):
        code, err, files = self.run_cli(FakeStdin(tty=True))
        self.assertEqual((code, files), (0, ["s.json"]), err)
        self.assertNotIn("Remember the credentials", err)
        self.assertIn("systemd-creds is not installed", err)

    def test_explicit_remember_fails_clearly(self):
        code, err, files = self.run_cli(FakeStdin(), "--remember")
        self.assertEqual((code, files), (1, []))  # refused before anything is created
        self.assertIn("systemd-creds is not installed", err)


@unittest.skipUnless(cg.can_remember(), "systemd-creds not installed")
class RealSystemdCreds(unittest.TestCase):
    """Round trip through the real systemd-creds, where it works (systemd 256+ for non-root)."""

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "state.json")
            try:
                cg.remember(state, "alice@example.com", " p@ss w\\rd ")
            except cg.CgError as e:
                self.skipTest(f"systemd-creds unusable here: {e}")
            for what in ("username", "password"):
                with open(cg.remembered_path(state, what), "rb") as f:
                    self.assertNotIn(b"p@ss", f.read())
            self.assertEqual(cg.remembered(state, "username"), "alice@example.com")
            self.assertEqual(cg.remembered(state, "password"), " p@ss w\\rd ")


class X25519Rfc(unittest.TestCase):
    def test_scalar_multiplication_vectors(self):
        # RFC 7748, section 5.2
        self.assertEqual(cg.x25519(
            bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex(),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        nine = (9).to_bytes(32, "little")
        self.assertEqual(cg.x25519(nine, nine).hex(),
                         "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")


class ServerNames(unittest.TestCase):
    def test_unexpected_names_are_skipped_and_full_servers_last(self):
        rows = [{"displayName": "zurich-s1-i1\nPostUp = x", "city": "Zurich", "totalusers": 1, "Max_Users": 10},
                {"displayName": "evil.example/x?", "city": "Zurich", "totalusers": 1, "Max_Users": 10},
                {"displayName": "zurich-s1-i2", "city": "Zurich", "totalusers": 1, "Max_Users": 10, "full": "1"},
                {"displayName": "zurich-s1-i3", "city": "Zurich", "totalusers": 9, "Max_Users": 10, "full": "0"},
                {"displayName": "a-Nospyproxy-b", "city": "Zurich", "totalusers": 5, "Max_Users": 10}]
        instances, _ = ListInstances().run_list(rows)
        self.assertEqual([i["instance"] for i in instances], ["a-nospyproxy-b", "zurich-s1-i3", "zurich-s1-i2"])

    def test_invalid_instance_option(self):
        code, err = Cli().run_cli("conf", "--instance", "evil.example/x?")
        self.assertEqual(code, 2)
        self.assertIn("invalid --instance", err)


def cert(*names, san=()):
    return {"subject": tuple(((("commonName", n),) for n in names)), "subjectAltName": tuple(("DNS", n) for n in san)}


class NodeCertificate(unittest.TestCase):
    def test_rack_of_the_instance(self):
        cg.check_node_cert(cert("zurich-rack404.nodes.gen4.ninja"), "zurich-s404-i06")
        cg.check_node_cert(cert("x", san=["newyork-rack422.nodes.gen4.ninja"]), "newyork-s422-i06")
        for bad in (cert("zurich-rack402.nodes.gen4.ninja"), cert("berlin-rack404.nodes.gen4.ninja"),
                    cert("zurich-rack404.nodes.gen4.ninja.evil"), cert(), {}, None):
            with self.assertRaises(cg.CgError, msg=bad):
                cg.check_node_cert(bad, "zurich-s404-i06")

    def test_other_names_only_need_the_domain(self):
        cg.check_node_cert(cert("blade6.hong-kong.nodes.gen4.ninja"), "hong-kong-1")
        with self.assertRaisesRegex(cg.CgError, r"expected \*\.nodes\.gen4\.ninja"):
            cg.check_node_cert(cert("example.com"), "hong-kong-1")


class FakeConnection:
    """Stands in for http.client.HTTPSConnection."""
    instances = []

    def __init__(self, host, port, timeout=None, context=None, peer=None, status=200, body=b""):
        self.host, self.requests = host, []
        self.sock = mock.Mock(getpeercert=mock.Mock(return_value=peer))
        self.status, self.body = status, body
        FakeConnection.instances.append(self)

    def connect(self):
        pass

    def request(self, method, url, headers=None):
        self.requests.append((method, url, headers))

    def getresponse(self):
        return mock.Mock(status=self.status, read=mock.Mock(return_value=self.body))

    def close(self):
        pass


class AddKey(unittest.TestCase):
    DEVICE = {"token": "t", "secret": "s"}

    def call(self, peer, status=200, body=b'{"status": "OK"}'):
        FakeConnection.instances = []
        factory = lambda *a, **k: FakeConnection(*a, **k, peer=peer, status=status, body=body)  # noqa: E731
        with mock.patch.object(cg.http.client, "HTTPSConnection", side_effect=factory):
            try:
                return cg.add_key("zurich-s404-i06.cg-dialup.net", self.DEVICE, "PUB")
            finally:
                self.conn = FakeConnection.instances[0]

    def test_success(self):
        self.assertEqual(self.call(cert("zurich-rack404.nodes.gen4.ninja")), {"status": "OK"})
        method, url, headers = self.conn.requests[0]
        self.assertEqual((method, url), ("GET", "/addKey?pubkey=PUB"))
        self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(b"t:s").decode())

    def test_wrong_certificate_sends_nothing(self):
        with self.assertRaisesRegex(cg.CgError, "certificate issued to zurich-rack402"):
            self.call(cert("zurich-rack402.nodes.gen4.ninja"))
        self.assertEqual(self.conn.requests, [])

    def test_deleted_device(self):
        with self.assertRaises(cg.DeviceRefused):
            self.call(cert("zurich-rack404.nodes.gen4.ninja"), status=401)

    def test_device_refused_everywhere_suggests_login(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state = os.path.join(tmp.name, "s.json")
        cg.save_state(state, {"device": {"token": "t", "secret": "s"}})
        refused = cg.DeviceRefused("refused the device")
        with mock.patch.object(cg, "session", return_value=("jwt", ListInstances.ACCOUNT)), \
                mock.patch.object(cg, "list_instances", return_value=[
                    {"instance": f"a-s1-i{n}", "city": "a", "load": n} for n in range(3)]), \
                mock.patch.object(cg, "add_key", side_effect=refused) as add_key, \
                mock.patch.object(sys, "stderr", io.StringIO()) as err:
            code = cg.main(["--state", state, "conf", "--country", "CH", "-o", os.path.join(tmp.name, "x")])
        self.assertEqual((code, add_key.call_count), (1, 3))  # one server refusing says nothing of the others
        self.assertIn("every server refused the device: if it was removed from the account, 'cyberghost-wg login'",
                      err.getvalue())


class Api(unittest.TestCase):
    def http_error(self, code, headers=None):
        return cg.urllib.error.HTTPError("u", code, "x", headers or {}, io.BytesIO(b""))

    def ok(self):
        r = mock.MagicMock(status=200, headers={})
        r.read.return_value = b'{"a": 1}'
        r.__enter__.return_value = r
        return r

    def call(self, *answers):
        with mock.patch.object(cg.urllib.request, "urlopen", side_effect=list(answers)) as urlopen, \
                mock.patch.object(cg.time, "sleep") as sleep, mock.patch.object(sys, "stderr", io.StringIO()):
            result = cg.api("GET", "/x")
        return result, urlopen.call_count, [c.args[0] for c in sleep.call_args_list]

    def test_rate_limit_waits_once(self):
        self.assertEqual(self.call(self.http_error(429, {"Retry-After": "7"}), self.ok()), ((200, {"a": 1}), 2, [7]))
        result, calls, sleeps = self.call(self.http_error(429), self.http_error(429))
        self.assertEqual((result[0], calls, sleeps), (429, 2, [cg.RATE_LIMIT_WAIT]))
        self.assertIn("wait a minute", str(cg.api_error("listing servers", 429, None)))

    def test_network_down_is_tried_again(self):
        down = cg.urllib.error.URLError("down")
        self.assertEqual(self.call(down, down, self.ok()), ((200, {"a": 1}), 3, list(cg.NETWORK_RETRIES)))
        with self.assertRaisesRegex(cg.CgError, "API unreachable"):
            self.call(down, down, down)


@mock.patch.dict(os.environ, {})
class LoginDevice(unittest.TestCase):
    def setUp(self):
        for var in CRED_VARS:
            os.environ.pop(var, None)
        os.environ.update(CG_USERNAME="alice", CG_PASSWORD="secret")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.login = Login("test_no_question_without_terminal")
        self.login.state, self.login.logins, self.login.devices = os.path.join(self.tmp.name, "s.json"), [], []

    def run_login(self):
        with mock.patch.object(cg, "can_remember", return_value=True):
            return self.login.run_cli(FakeStdin(), "login", "--name", "nas")

    def test_device_deleted_from_the_account_is_replaced(self):
        self.run_login()
        self.assertEqual(cg.load_state(self.login.state)["device"]["id"], 5)
        code, err = self.run_login()
        self.assertIn("Keeping the existing device", err)
        self.login.devices.clear()  # removed on the CyberGhost website
        code, err = self.run_login()
        self.assertEqual(code, 0, err)
        self.assertIn("no longer on the account, registering a new one", err)
        self.assertEqual(cg.load_state(self.login.state)["device"]["id"], 5)
        self.assertEqual(self.login.device_name, "nas")


@mock.patch.dict(os.environ, {})
class CredentialsAndRemembered(unittest.TestCase):
    def setUp(self):
        for var in CRED_VARS:
            os.environ.pop(var, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state.json")
        with mock.patch.object(cg, "systemd_creds", side_effect=fake_systemd_creds):
            cg.remember(self.state, "alice", "secret")

    def resolve(self, **kw):
        a = mock.Mock(spec=["username", "password_stdin", "state"],
                      **{"username": None, "password_stdin": False, "state": self.state, **kw})
        with mock.patch.object(cg, "systemd_creds", side_effect=fake_systemd_creds), \
                mock.patch.object(sys, "stdin", FakeStdin()):
            return cg.get_credentials(a, use_remembered=True)

    def test_remembered_pair(self):
        self.assertEqual(self.resolve(), ("alice", "secret"))
        self.assertEqual(self.resolve(username="alice"), ("alice", "secret"))

    def test_other_username_never_gets_the_remembered_password(self):
        with self.assertRaisesRegex(cg.CgError, "credentials needed"):
            self.resolve(username="bob")

    def test_network_error_gives_no_password_hint(self):
        a = mock.Mock(state=self.state, username=None, password_stdin=False)
        with mock.patch.object(cg, "systemd_creds", side_effect=fake_systemd_creds), \
                mock.patch.object(cg, "request_jwt", side_effect=cg.CgError("API unreachable")), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(cg.CgError) as ctx:
                cg.ensure_jwt({}, a)
        self.assertNotIn("password changed", str(ctx.exception))


class RememberAvailability(unittest.TestCase):
    def check(self, version, root):
        out = mock.Mock(stdout=f"systemd {version} ({version}.1-1)\n+PAM +AUDIT\n")
        with mock.patch.object(cg.shutil, "which", return_value="/usr/bin/systemd-creds"), \
                mock.patch.object(cg.subprocess, "run", return_value=out), \
                mock.patch.object(cg, "is_root", return_value=root):
            return cg.remember_unavailable()

    def test_versions(self):
        self.assertIn("systemd 255 is too old", self.check(255, False))  # Ubuntu 24.04
        self.assertIsNone(self.check(256, False))
        self.assertIsNone(self.check(252, True))
        self.assertIn("needs 250", self.check(249, True))


class ConfOutput(unittest.TestCase):
    PEER = {"address": "10.5.1.2/32", "server_key": KEY, "port": 1337, "dns": ["10.0.0.243"]}

    def test_no_dns(self):
        conf = cg.render_conf("x", "PRIV", self.PEER, "192.0.2.1", "0.0.0.0/0", dns=False)
        self.assertNotIn("DNS", conf)
        self.assertIn("DNS = 10.0.0.243\n", cg.render_conf("x", "PRIV", self.PEER, "192.0.2.1"))

    def test_private_key_never_goes_to_the_journal(self):
        with tempfile.TemporaryFile("w") as out:
            st = os.fstat(out.fileno())
            with mock.patch.dict(os.environ, {"JOURNAL_STREAM": f"{st.st_dev}:{st.st_ino}"}), \
                    mock.patch.object(sys, "stdout", out):
                self.assertTrue(cg.stdout_is_journal())
                code, err = Cli().run_cli("conf", "--instance", "zurich-s1-i1")
        self.assertEqual(code, 1)
        self.assertIn("use -o FILE", err)
        self.assertFalse(cg.stdout_is_journal())  # JOURNAL_STREAM unset


@mock.patch.dict(os.environ, {})
class Listings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "s.json")
        jwt_payload = base64.urlsafe_b64encode(json.dumps({"exp": 4102444800}).encode()).decode()
        cg.save_state(self.state, {"jwt": f"h.{jwt_payload}.s"})
        self.paths = []

    def run_cli(self, *argv):
        def api(method, path, jwt=None, body=None):
            self.paths.append(path)
            if path.startswith("/my/account"):
                return 200, ListInstances.ACCOUNT
            if "/filters/73" in path:
                return 200, [{"countrycode": "CH"}, {"countrycode": "DE"}]
            return 200, [{"displayName": "newyork-s1-i1", "city": "New York", "totalusers": 1, "Max_Users": 4}]
        with mock.patch.object(cg, "api", side_effect=api), mock.patch.object(sys, "stdout", io.StringIO()) as out, \
                mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(cg.main(["--state", self.state, *argv]), 0)
        return out.getvalue()

    def test_country_names_and_json(self):
        self.assertEqual(self.run_cli("countries"), "CODE  COUNTRY\nDE    Germany\nCH    Switzerland\n")
        self.assertEqual(json.loads(self.run_cli("countries", "--json"))[0], {"code": "DE", "name": "Germany"})

    def test_servers_city_last_and_json(self):
        self.assertEqual(self.run_cli("servers", "--country", "US").splitlines()[1].split(),
                         ["newyork-s1-i1", "25%", "new", "york"])
        self.assertEqual(json.loads(self.run_cli("servers", "--country", "US", "--json")),
                         [{"instance": "newyork-s1-i1", "city": "new york", "load": 25}])

    def test_account_is_cached_with_the_session(self):
        self.run_cli("countries")
        self.run_cli("servers", "--country", "US")
        self.assertEqual(sum(p.startswith("/my/account") for p in self.paths), 1)


class Logout(unittest.TestCase):
    def test_local_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "s.json")
            cg.save_state(state, {"device": {"id": 5, "name": "nas", "token": "t", "secret": "s"}})
            with mock.patch.object(cg, "api") as api, mock.patch.object(sys, "stderr", io.StringIO()) as err:
                self.assertEqual(cg.main(["--state", state, "logout", "--local"]), 0)
            api.assert_not_called()
            self.assertFalse(os.path.exists(state))
            self.assertIn("left on the account", err.getvalue())



SERVICES = [{"countrycode": "GB", "content_id": "104", "name": "Netflix UK"},
            {"countrycode": "GB", "content_id": "30", "name": "BBC iPlayer"},
            {"countrycode": "US", "content_id": "46", "name": "Hulu US"},
            {"countrycode": "US", "content_id": "1", "name": "Netflix US"},
            {"countrycode": "US", "content_id": "1", "name": "Netflix US"},
            {"countrycode": "US", "content_id": "x", "name": "bad id"}, "junk"]
STREAMING_SERVERS = [{"displayName": "london-s470-i03", "city": "London", "totalusers": 103, "Max_Users": 400},
                     {"displayName": "london-s417-i21", "city": "London", "totalusers": 14, "Max_Users": 63}]


def streaming_api(paths):
    def api(method, path, jwt=None, body=None):
        paths.append(path)
        if path.startswith("/my/account"):
            return 200, ListInstances.ACCOUNT
        if "/filters/76" in path:
            return 200, SERVICES
        if "/filters/72" in path:
            return 200, STREAMING_SERVERS
        return 404, None
    return api


class Streaming(unittest.TestCase):
    def services(self):
        with mock.patch.object(cg, "api", side_effect=streaming_api([])):
            return cg.list_services("jwt")

    def test_services_parsed_deduplicated_and_sorted(self):
        self.assertEqual(self.services(), [{"id": "30", "name": "BBC iPlayer", "country": "GB"},
                                           {"id": "104", "name": "Netflix UK", "country": "GB"},
                                           {"id": "46", "name": "Hulu US", "country": "US"},
                                           {"id": "1", "name": "Netflix US", "country": "US"}])

    def test_find_service(self):
        services = self.services()
        self.assertEqual(cg.find_service(services, "netflix uk")["id"], "104")
        self.assertEqual(cg.find_service(services, "iplayer")["id"], "30")
        self.assertEqual(cg.find_service(services, "netflix", "US")["id"], "1")
        self.assertEqual(cg.find_service(services, "104")["name"], "Netflix UK")
        with self.assertRaisesRegex(cg.CgError, "matches several services: Netflix UK \\(GB\\), Netflix US"):
            cg.find_service(services, "netflix")
        with self.assertRaisesRegex(cg.CgError, "no streaming service matches 'hulu' in GB"):
            cg.find_service(services, "hulu", "GB")

    def test_streaming_servers_path(self):
        paths = []
        with mock.patch.object(cg, "api", side_effect=streaming_api(paths)):
            instances = cg.list_instances("jwt", None, "streaming", service="104")
        self.assertEqual([i["instance"] for i in instances], ["london-s417-i21", "london-s470-i03"])
        self.assertIn("/my/servers/filters/72?filter_protocol=wireguard&filter_content_id=104&filter_user_plans_id=7",
                      paths[-1])

    def test_streaming_countries(self):
        with mock.patch.object(cg, "api", side_effect=streaming_api([])):
            self.assertEqual(cg.list_countries("jwt", "streaming"),
                             [{"code": "GB", "name": "United Kingdom"}, {"code": "US", "name": "United States"}])

    def test_command_line(self):
        listings = Listings("test_country_names_and_json")
        listings.setUp()
        self.addCleanup(listings.tmp.cleanup)
        with mock.patch.object(cg, "api", side_effect=streaming_api(listings.paths)), \
                mock.patch.object(sys, "stdout", io.StringIO()) as out, mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(cg.main(["--state", listings.state, "services", "--country", "GB"]), 0)
            self.assertEqual(cg.main(["--state", listings.state, "servers", "--service", "netflix uk"]), 0)
        self.assertEqual(out.getvalue().splitlines()[:3], ["CODE  SERVICE", "GB    BBC iPlayer", "GB    Netflix UK"])
        self.assertIn("london-s417-i21", out.getvalue())

    def test_conf_label(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state, target = os.path.join(tmp.name, "s.json"), os.path.join(tmp.name, "wg.conf")
        jwt_payload = base64.urlsafe_b64encode(json.dumps({"exp": 4102444800}).encode()).decode()
        cg.save_state(state, {"jwt": f"h.{jwt_payload}.s", "device": {"token": "t", "secret": "s"}})
        with mock.patch.object(cg, "api", side_effect=streaming_api([])), \
                mock.patch.object(cg, "add_key", return_value=Interactive.ANSWER), \
                mock.patch.object(cg, "resolve_ipv4", return_value="192.0.2.1"), \
                mock.patch.object(sys, "stderr", io.StringIO()) as err:
            self.assertEqual(cg.main(["--state", state, "conf", "--service", "BBC iPlayer", "-o", target]), 0,
                             err.getvalue())
        with open(target, encoding="utf-8") as f:
            self.assertIn("# CyberGhost london-s417-i21 (streaming BBC iPlayer, load 22%)", f.read())

    def test_options_checked_before_signing_in(self):
        code, err = Cli().run_cli("servers", "--type", "streaming")
        self.assertEqual(code, 1)
        self.assertIn("--service 'Netflix UK'", err)
        code, err = Cli().run_cli("servers", "--type", "torrent", "--service", "x")
        self.assertEqual(code, 2)
        self.assertIn("--service is for streaming servers", err)


@mock.patch.dict(os.environ, {})
class InteractiveStreaming(unittest.TestCase):
    setUp, ANSWER = Interactive.setUp, Interactive.ANSWER

    def run_cli(self, answers, *argv):
        err, out = FakeTty(), io.StringIO()
        with mock.patch.object(cg, "api", side_effect=streaming_api([])), \
                mock.patch.object(cg, "add_key", return_value=self.ANSWER) as add_key, \
                mock.patch.object(cg, "resolve_ipv4", return_value="192.0.2.1"), \
                mock.patch.object(sys, "stdin", FakeStdin("".join(a + "\n" for a in answers), tty=True)), \
                mock.patch.object(sys, "stderr", err), mock.patch.object(sys, "stdout", out):
            code = cg.main(["--state", self.state, "conf", "-i", *argv])
        return code, err.getvalue(), out.getvalue(), add_key

    def test_streaming_menus(self):
        # streaming, country #1 (United Kingdom), service #2 (Netflix UK), city: only London, server auto, print
        code, err, out, add_key = self.run_cli(["3", "1", "2", "", "-", ""])
        self.assertEqual(code, 0, err)
        self.assertIn("Streaming service", err)
        self.assertIn("streaming Netflix UK", out)
        self.assertEqual(add_key.call_args.args[0], "london-s417-i21.cg-dialup.net")

    def test_service_given(self):
        code, err, out, _ = self.run_cli(["", "-", ""], "--service", "hulu")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Server type", err)
        self.assertIn("streaming Hulu US", out)



class NoSpy(unittest.TestCase):
    ROWS = [{"name": "Nospybucharest-S409-i01", "total_users": "49", "max_users": "50", "online": "1", "enabled": "1"},
            {"name": "Nospybucharest-S409-i02", "total_users": "10", "max_users": "50", "online": "1", "enabled": "1"},
            {"name": "Nospybucharest-S409-i03", "total_users": "0", "max_users": "50", "online": "0", "enabled": "1"},
            {"name": "Nospybucharest-S409-i04", "total_users": "0", "max_users": "50", "online": "1", "enabled": "0"}]

    def test_nospy_servers(self):
        instances, api = ListInstances().run_list(self.ROWS, server_type="nospy")
        self.assertEqual(instances, [{"instance": "bucharest-s409-i02", "city": "bucharest", "load": 20},
                                     {"instance": "bucharest-s409-i01", "city": "bucharest", "load": 98}])
        self.assertIn("/my/servers/filters/95?filter_protocol=wireguard", api.call_args_list[1].args[1])

    def test_nospy_names_in_the_country_lists(self):
        rows = [{"displayName": "Nospybucharest-S409-i01", "city": "Bucharest", "totalusers": 1, "Max_Users": 2},
                {"displayName": "NospyproxyBucharest-S1-i01", "city": "Bucharest", "totalusers": 1, "Max_Users": 2}]
        self.assertEqual([i["instance"] for i in ListInstances().run_list(rows)[0]],
                         ["bucharest-s1-i01", "bucharest-s409-i01"])

    def test_no_country_needed(self):
        listings = Listings("test_country_names_and_json")
        listings.setUp()
        self.addCleanup(listings.tmp.cleanup)

        def api(method, path, jwt=None, body=None):
            return (200, ListInstances.ACCOUNT) if path.startswith("/my/account") else (200, self.ROWS)
        with mock.patch.object(cg, "api", side_effect=api), mock.patch.object(sys, "stdout", io.StringIO()) as out, \
                mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(cg.main(["--state", listings.state, "servers", "--type", "nospy"]), 0)
            self.assertEqual(cg.main(["--state", listings.state, "countries", "--type", "nospy"]), 0)
        self.assertIn("bucharest-s409-i02", out.getvalue())
        self.assertIn("RO    Romania", out.getvalue())



class Gaming(unittest.TestCase):
    GROUPS = [{"countrycode": "DE", "available": "1", "name": "Gaming servers", "url": "19-DE.cg-dialup.net"},
              {"countrycode": "RO", "available": "1", "name": "NoSpy Servers", "url": "8-RO.cg-dialup.net"},
              {"countrycode": "FR", "available": "1", "name": "Gaming servers", "url": "19-FR.cg-dialup.net"},
              {"countrycode": "GB", "available": "0", "name": "Gaming servers", "url": "19-GB.cg-dialup.net"},
              {"countrycode": "US", "available": "1", "name": "Gaming servers", "url": "evil.example"},
              {"countrycode": "IT", "available": "1", "name": "Premium Servers", "url": "1-IT.cg-dialup.net"}]
    SERVERS = [{"displayName": "Frankfurt-S410-i11", "city": "Frankfurt", "ip": "192.0.2.11", "totalusers": 3, "Max_Users": 10},
               {"displayName": "Frankfurt-S410-i12", "city": "Frankfurt", "ip": "192.0.2.12", "totalusers": 1, "Max_Users": 10},
               {"displayName": "Frankfurt-S470-i45", "city": "Frankfurt", "ip": "192.0.2.45", "totalusers": 0, "Max_Users": 10}]

    def api(self, method, path, jwt=None, body=None):
        if path.startswith("/my/account"):
            return 200, ListInstances.ACCOUNT
        return 200, self.GROUPS if "/filters/86" in path else self.SERVERS

    def run_with_dns(self, func, *a, **kw):
        answers = [[(2, 1, 6, "", ("192.0.2.11", 0))], [(2, 1, 6, "", ("192.0.2.12", 0))]] * 3
        with mock.patch.object(cg, "api", side_effect=self.api), \
                mock.patch.object(cg.socket, "getaddrinfo", side_effect=answers) as dns:
            return func(*a, **kw), dns

    def test_gaming_countries(self):
        countries, _ = self.run_with_dns(cg.list_countries, "jwt", "gaming")
        self.assertEqual([c["code"] for c in countries], ["FR", "DE"])  # by name: France, Germany

    def test_gaming_servers_are_the_group_addresses(self):
        instances, dns = self.run_with_dns(cg.list_instances, "jwt", "DE", "gaming")
        self.assertEqual([i["instance"] for i in instances], ["frankfurt-s410-i12", "frankfurt-s410-i11"])
        self.assertEqual(dns.call_args.args[0], "19-DE.cg-dialup.net")
        self.assertEqual(dns.call_count, 5)  # round-robin answers are merged

    def test_country_without_gaming_servers(self):
        self.assertEqual(self.run_with_dns(cg.list_instances, "jwt", "IT", "gaming")[0], [])

    def test_message_points_to_the_countries(self):
        a = mock.Mock(service=None, type="gaming", country="CH")
        self.assertEqual(str(cg.no_server(a)), "no gaming server matches in CH: see 'cyberghost-wg countries --type gaming'")


if __name__ == "__main__":
    unittest.main()
