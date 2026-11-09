import json
import os
import tempfile
import unittest

from layerghost.core import analyze, parse_dockerfile, is_secret_name, is_secret_path
from layerghost.cli import main


def rules(fs):
    return sorted((f.rule, f.severity) for f in fs)


class TestParse(unittest.TestCase):
    def test_continuation_and_flags(self):
        ins = parse_dockerfile("FROM a\nRUN --mount=type=secret,id=x \\\n  echo hi\n# c\nCOPY --from=b /x /y\n")
        self.assertEqual([i.cmd for i in ins], ["FROM", "RUN", "COPY"])
        self.assertEqual(ins[1].flags["mount"], "type=secret,id=x")
        self.assertEqual(ins[2].flags["from"], "b")

    def test_heredoc(self):
        ins = parse_dockerfile("FROM a\nRUN <<EOF\necho k > /k.pem\nrm /k.pem\nEOF\n")
        self.assertEqual(len(ins), 2)
        self.assertIn("rm /k.pem", ins[1].args)

    def test_names(self):
        self.assertTrue(is_secret_name("NPM_TOKEN"))
        self.assertFalse(is_secret_name("TOKEN_URL"))
        self.assertTrue(is_secret_path("/root/.ssh/id_rsa"))
        self.assertFalse(is_secret_path("/root/.ssh/id_rsa.pub"))


class TestRules(unittest.TestCase):
    def test_delete_in_later_layer_final(self):
        fs, _ = analyze("FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nRUN rm /root/.ssh/id_rsa\n")
        self.assertEqual(rules(fs), [("LG001", "high")])

    def test_same_layer_delete_is_clean(self):
        fs, _ = analyze("FROM alpine\nRUN curl -o /tmp/key.pem https://x && use /tmp/key.pem && rm /tmp/key.pem\n")
        self.assertEqual(fs, [])

    def test_run_created_then_removed_later(self):
        fs, _ = analyze("FROM alpine\nRUN echo t > /root/.netrc\nRUN rm -f /root/.netrc\n")
        self.assertEqual(rules(fs), [("LG001", "high")])

    def test_directory_rm_and_glob(self):
        fs, _ = analyze("FROM a\nCOPY secrets/ /tmp/s/\nCOPY k.pem /tmp/k.pem\nRUN rm -rf /tmp/s /tmp/*.pem\n",
                        context=None)
        self.assertEqual(rules(fs), [("LG001", "high"), ("LG001", "high")])

    def test_intermediate_stage_is_low(self):
        fs, _ = analyze("FROM a AS b\nCOPY id_rsa /k/id_rsa\nRUN rm /k/id_rsa\nFROM a\nRUN true\n")
        self.assertEqual(rules(fs), [("LG001", "low")])

    def test_from_stage_inherits_ghost(self):
        fs, _ = analyze("FROM a AS b\nCOPY id_rsa /k/id_rsa\nRUN rm /k/id_rsa\nFROM b AS final\nRUN true\n")
        self.assertEqual(rules(fs), [("LG001", "high")])
        self.assertEqual(fs[0].stage, "final")

    def test_copy_from_carries_live_secret(self):
        fs, _ = analyze("FROM a AS b\nWORKDIR /src\nCOPY .env .env\nFROM a\nCOPY --from=b /src /app\n")
        self.assertIn(("LG005", "high"), rules(fs))
        self.assertEqual([f.path for f in fs if f.rule == "LG005"], ["/app/.env"])

    def test_copy_from_after_builder_deleted_is_clean(self):
        fs, _ = analyze("FROM a AS b\nRUN echo x > /src/.env && make && rm /src/.env\nFROM a\nCOPY --from=b /src /app\n")
        self.assertEqual(fs, [])

    def test_carried_then_deleted(self):
        fs, _ = analyze("FROM a AS b\nCOPY .npmrc /src/.npmrc\nFROM a\nCOPY --from=b /src /app\nRUN rm /app/.npmrc\n")
        self.assertEqual(rules(fs), [("LG001", "high")])

    def test_arg_secret_used(self):
        fs, _ = analyze("FROM a\nARG GH_TOKEN\nRUN git clone https://$GH_TOKEN@github.com/x/y\n")
        self.assertEqual(rules(fs), [("LG002", "high")])

    def test_arg_default(self):
        fs, _ = analyze("FROM a\nARG API_KEY=abc123\n")
        self.assertEqual(rules(fs), [("LG002", "high")])

    def test_secret_mount_clean(self):
        fs, _ = analyze("FROM a\nRUN --mount=type=secret,id=t T=$(cat /run/secrets/t) ./go\n")
        self.assertEqual(fs, [])

    def test_env_secret(self):
        fs, _ = analyze("FROM a\nENV DB_PASSWORD=hunter2 APP_URL=http://x\n")
        self.assertEqual(rules(fs), [("LG003", "high")])

    def test_target(self):
        df = "FROM a AS dev\nENV TOKEN=x\nFROM a AS prod\nRUN true\n"
        self.assertEqual(rules(analyze(df)[0]), [("LG003", "low")])
        self.assertEqual(rules(analyze(df, target="dev")[0]), [("LG003", "high")])

    def test_bloat_flag(self):
        df = "FROM a\nCOPY big.tar /tmp/big.tar\nRUN rm /tmp/big.tar\n"
        self.assertEqual(analyze(df)[0], [])
        self.assertEqual(rules(analyze(df, include_bloat=True)[0]), [("LG001", "info")])


class TestContext(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        for name in (".env", "app.py", "certs/server.key"):
            p = os.path.join(self.d, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write("x")

    def test_copy_dot_live_secret(self):
        fs, _ = analyze("FROM a\nWORKDIR /app\nCOPY . .\n", context=self.d)
        self.assertEqual(sorted(f.path for f in fs), ["/app/.env", "/app/certs/server.key"])
        self.assertTrue(all(f.rule == "LG004" for f in fs))

    def test_dockerignore_excludes(self):
        open(os.path.join(self.d, ".dockerignore"), "w").write(".env\ncerts/\n")
        fs, _ = analyze("FROM a\nWORKDIR /app\nCOPY . .\n", context=self.d)
        self.assertEqual(fs, [])

    def test_cli_json_and_fail_on(self):
        df = os.path.join(self.d, "Dockerfile")
        open(df, "w").write("FROM a\nCOPY .env /x/.env\nRUN rm /x/.env\n")
        self.assertEqual(main([df, "--format", "json", "--fail-on", "high"]), 1)
        self.assertEqual(main([df, "--format", "md"]), 0)


if __name__ == "__main__":
    unittest.main()
