"""网页端版本检查 / 在线更新的测试。

覆盖：
  * collect_app_version()（本地读取、远端检查 via 本地 bare origin）
  * perform_app_update()（有更新、已是最新、本地领先需强制、强制更新）
  * HTTP 接口 GET /api/app_version(?check=1) 与 POST /api/update_app

所有 git 操作都在临时目录中完成，不会改动当前安装目录。
运行： python3 -m unittest discover -s tests -p "*_test.py" -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TMP_ROOT = Path(tempfile.mkdtemp(prefix="aimilivpn-update-test-"))
os.environ["VPNGATE_DATA_DIR"] = str(TMP_ROOT / "data")
(TMP_ROOT / "data").mkdir(parents=True, exist_ok=True)

import vpngate_manager as vm  # noqa: E402  (import 需要在上面的环境变量之后)

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "AimiliVPN Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "AimiliVPN Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )
    return proc.stdout.strip()


def git_init(cwd: Path) -> None:
    cwd.mkdir(parents=True, exist_ok=True)
    git(cwd, "init", "-q", "-b", "main")


def commit_file(repo: Path, name: str, content: str, message: str) -> str:
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class GitSandbox:
    """origin.git (bare) + seed 克隆 + app 工作副本。"""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="repo-", dir=TMP_ROOT))
        self.origin = self.root / "origin.git"
        self.seed = self.root / "seed"
        self.app = self.root / "app"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True, env=GIT_ENV)
        git_init(self.seed)
        commit_file(self.seed, "vpngate_manager.py", "# v1\n", "feat: 初始版本")
        git(self.seed, "remote", "add", "origin", str(self.origin))
        git(self.seed, "push", "-q", "-u", "origin", "main")
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.app)], check=True, env=GIT_ENV)
        git(self.app, "config", "user.name", "AimiliVPN Test")
        git(self.app, "config", "user.email", "test@example.com")

    def publish(self, content: str, message: str) -> str:
        sha = commit_file(self.seed, "vpngate_manager.py", content, message)
        git(self.seed, "push", "-q", "origin", "main")
        return sha

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class CollectVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = GitSandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()

    def test_local_only(self) -> None:
        info = vm.collect_app_version(repo_dir=self.sb.app)
        self.assertTrue(info["ok"], info)
        self.assertTrue(info["git_available"])
        self.assertTrue(info["is_git_repo"])
        self.assertEqual(info["branch"], "main")
        self.assertEqual(len(info["current_commit"]), 7)
        self.assertEqual(info["current_message"], "feat: 初始版本")
        self.assertTrue(info["current_date"].startswith("20"))
        self.assertFalse(info["checked_remote"])
        self.assertFalse(info["has_update"])
        self.assertEqual(info["commits_behind"], 0)
        self.assertEqual(info["error"], "")
        # 本地读取不应触碰远端
        self.assertEqual(git(self.sb.origin, "rev-parse", "main"), git(self.sb.app, "rev-parse", "HEAD"))

    def test_check_remote_reports_new_commits(self) -> None:
        sha = self.sb.publish("# v2\n", "fix: 第二个提交")
        info = vm.collect_app_version(check_remote=True, repo_dir=self.sb.app)
        self.assertTrue(info["ok"], info)
        self.assertTrue(info["checked_remote"])
        self.assertTrue(info["has_update"])
        self.assertEqual(info["commits_behind"], 1)
        self.assertEqual(info["commits_ahead"], 0)
        self.assertEqual(info["remote_commit"], sha[:7])
        self.assertEqual(info["remote_message"], "fix: 第二个提交")
        # 只是 fetch，不应修改工作区
        self.assertNotEqual(git(self.sb.app, "rev-parse", "HEAD"), sha)
        self.assertEqual((self.sb.app / "vpngate_manager.py").read_text(encoding="utf-8"), "# v1\n")

    def test_up_to_date_after_check(self) -> None:
        info = vm.collect_app_version(check_remote=True, repo_dir=self.sb.app)
        self.assertTrue(info["ok"], info)
        self.assertTrue(info["checked_remote"])
        self.assertFalse(info["has_update"])
        self.assertEqual(info["remote_commit"], info["current_commit"])

    def test_non_git_directory(self) -> None:
        plain = self.sb.root / "plain"
        plain.mkdir()
        info = vm.collect_app_version(repo_dir=plain)
        self.assertFalse(info["ok"])
        self.assertFalse(info["is_git_repo"])
        self.assertIn("不是 Git 仓库", info["error"])


class PerformUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = GitSandbox()

    def tearDown(self) -> None:
        self.sb.cleanup()

    def test_update_applies_new_commit(self) -> None:
        sha = self.sb.publish("# v2 content\n", "feat: 网页端更新功能")
        result = vm.perform_app_update(repo_dir=self.sb.app)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["updated"])
        self.assertTrue(result["restart_needed"])
        self.assertEqual(result["new_commit"], sha[:7])
        self.assertEqual(result["commits_behind"], 1)
        self.assertIn("更新成功", result["message"])
        self.assertEqual(git(self.sb.app, "rev-parse", "HEAD"), sha)
        self.assertEqual((self.sb.app / "vpngate_manager.py").read_text(encoding="utf-8"), "# v2 content\n")
        # 运行数据目录不受影响
        self.assertTrue((TMP_ROOT / "data").exists())

    def test_update_cleans_pycache(self) -> None:
        cache = self.sb.app / "__pycache__"
        cache.mkdir()
        (cache / "stale.pyc").write_bytes(b"stale")
        self.sb.publish("# v2\n", "chore: 触发更新")
        result = vm.perform_app_update(repo_dir=self.sb.app)
        self.assertTrue(result["updated"], result)
        self.assertFalse(cache.exists())

    def test_already_up_to_date(self) -> None:
        result = vm.perform_app_update(repo_dir=self.sb.app)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["updated"])
        self.assertFalse(result["restart_needed"])
        self.assertEqual(result["message"], "当前已是最新版本")

    def test_local_ahead_needs_force(self) -> None:
        local_sha = commit_file(self.sb.app, "local.txt", "local only\n", "wip: 本地改动")
        result = vm.perform_app_update(repo_dir=self.sb.app)
        self.assertFalse(result["ok"])
        self.assertTrue(result["needs_force"])
        self.assertFalse(result["updated"])
        # 未强制时绝不覆盖本地提交
        self.assertEqual(git(self.sb.app, "rev-parse", "HEAD"), local_sha)

    def test_force_aligns_with_remote(self) -> None:
        commit_file(self.sb.app, "local.txt", "local only\n", "wip: 本地改动")
        sha = self.sb.publish("# v2\n", "feat: 远端更新")
        result = vm.perform_app_update(force=True, repo_dir=self.sb.app)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["updated"])
        self.assertTrue(result["forced"])
        self.assertEqual(git(self.sb.app, "rev-parse", "HEAD"), sha)

    def test_update_keeps_untracked_runtime_data(self) -> None:
        data_dir = self.sb.app / "vpngate_data"
        data_dir.mkdir()
        (data_dir / "ui_auth.json").write_text('{"username": "admin"}', encoding="utf-8")
        self.sb.publish("# v2\n", "feat: 更新")
        result = vm.perform_app_update(repo_dir=self.sb.app)
        self.assertTrue(result["updated"], result)
        self.assertTrue((data_dir / "ui_auth.json").exists())

    def test_non_git_directory(self) -> None:
        plain = self.sb.root / "plain"
        plain.mkdir()
        result = vm.perform_app_update(repo_dir=plain)
        self.assertFalse(result["ok"])
        self.assertFalse(result["updated"])
        self.assertIn("不是 Git 仓库", result["error"])


class HttpApiTests(unittest.TestCase):
    SECRET = "testsecret"
    USER = "admin"
    PASSWORD = "test-password"

    @classmethod
    def setUpClass(cls) -> None:
        cls.sb = GitSandbox()
        cls.data_dir = Path(tempfile.mkdtemp(prefix="api-data-", dir=TMP_ROOT))
        (cls.data_dir / "ui_auth.json").write_text(
            json.dumps(
                {
                    "username": cls.USER,
                    "password": cls.PASSWORD,
                    "secret_path": cls.SECRET,
                    "host": "127.0.0.1",
                    "port": 8787,
                    "proxy_port": 7928,
                }
            ),
            encoding="utf-8",
        )
        # 让 handler 使用测试用的运行数据目录与代码目录
        cls._orig_data_dir = vm.DATA_DIR
        cls._orig_repo_dir = vm.APP_REPO_DIR
        cls._orig_restart = vm.schedule_app_restart
        vm.DATA_DIR = cls.data_dir
        vm.APP_REPO_DIR = cls.sb.app
        cls.restart_calls: list[str] = []
        vm.schedule_app_restart = lambda reason="", delay=0: cls.restart_calls.append(reason)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), vm.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.cookie = cls._login()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        vm.DATA_DIR = cls._orig_data_dir
        vm.APP_REPO_DIR = cls._orig_repo_dir
        vm.schedule_app_restart = cls._orig_restart
        cls.sb.cleanup()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    @classmethod
    def _login(cls) -> str:
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}/{cls.SECRET}/api/login",
            data=json.dumps({"username": cls.USER, "password": cls.PASSWORD}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            assert body.get("ok"), body
            raw = resp.headers.get("Set-Cookie", "")
        return raw.split(";")[0]

    def request(self, path: str, method: str = "GET", payload: dict | None = None, auth: bool = True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Cookie"] = self.cookie
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/{self.SECRET}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode() or "{}")

    def test_requires_auth(self) -> None:
        status, body = self.request("/api/app_version", auth=False)
        self.assertEqual(status, 401)
        self.assertIn("error", body)

    def test_version_without_check(self) -> None:
        status, body = self.request("/api/app_version")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["branch"], "main")
        self.assertEqual(len(body["current_commit"]), 7)
        self.assertFalse(body["checked_remote"])
        self.assertFalse(body["has_update"])
        self.assertFalse(body["updating"])

    def test_version_with_check_and_update_flow(self) -> None:
        sha = self.sb.publish("# v2\n", "feat: 通过网页更新")
        status, body = self.request("/api/app_version?check=1")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)
        self.assertTrue(body["checked_remote"])
        self.assertTrue(body["has_update"])
        self.assertGreaterEqual(body["commits_behind"], 1)
        self.assertEqual(body["remote_commit"], sha[:7])

        status, updated = self.request("/api/update_app", method="POST", payload={})
        self.assertEqual(status, 200)
        self.assertTrue(updated["ok"], updated)
        self.assertTrue(updated["updated"])
        self.assertTrue(updated["restart_needed"])
        self.assertEqual(updated["new_commit"], sha[:7])
        self.assertEqual(git(self.sb.app, "rev-parse", "HEAD"), sha)
        self.assertEqual(len(self.restart_calls), 1, self.restart_calls)
        self.assertIn(sha[:7], self.restart_calls[0])

        # 再次更新：已是最新，不再触发重启
        status, again = self.request("/api/update_app", method="POST", payload={})
        self.assertEqual(status, 200)
        self.assertTrue(again["ok"], again)
        self.assertFalse(again["updated"])
        self.assertEqual(len(self.restart_calls), 1, self.restart_calls)

    def test_update_rejects_concurrent_request(self) -> None:
        self.sb.publish("# v3\n", "feat: 并发测试")
        self.assertTrue(vm.app_update_lock.acquire(blocking=False))
        try:
            status, body = self.request("/api/update_app", method="POST", payload={})
        finally:
            vm.app_update_lock.release()
        self.assertEqual(status, 409)
        self.assertFalse(body["ok"])
        self.assertIn("正在进行", body["error"])


class RestartScheduleTests(unittest.TestCase):
    def test_falls_back_to_process_exit_without_service_manager(self) -> None:
        recorded: list[int] = []
        orig_cmd = vm.service_restart_command
        orig_exit = vm._exit_process
        vm.service_restart_command = lambda: None
        vm._exit_process = lambda: recorded.append(0)
        try:
            vm.schedule_app_restart("测试重启兜底", delay=0.01)
            deadline = time.time() + 5
            while not recorded and time.time() < deadline:
                time.sleep(0.02)
        finally:
            vm.service_restart_command = orig_cmd
            vm._exit_process = orig_exit
        self.assertEqual(recorded, [0], "没有服务管理器时应退化为进程退出")


if __name__ == "__main__":
    unittest.main(verbosity=2)
