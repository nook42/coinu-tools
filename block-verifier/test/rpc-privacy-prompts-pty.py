#!/usr/bin/env python3
"""block-verifierの実promptsをPTY・ジョブ制御シェル・teeで検査する。"""
import errno, json, os, re, select, shlex, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path
import pty, termios
ROOT = Path(__file__).resolve().parents[2]
PROMPT = b"PTY_SHELL_READY$ "
SECRET = b"FAKE-AFTER-FG"
PARTIAL = b"FAKE-PARTIAL"
class Job:
    def __init__(self, shell, work):
        # 親側で termios も観測する。子では初期化ファイルを読まない対話シェルだけを起動。
        try:
            self.pid, self.fd = pty.fork()
        except OSError as error:
            raise RuntimeError(f"PTYが使えない: {error}") from error
        if self.pid == 0:
            env = {"PATH": os.environ["PATH"], "HOME": str(work), "TERM": "xterm",
                   "PS1": PROMPT.decode(), "PROMPT": PROMPT.decode(), "LC_ALL": "C"}
            if os.environ.get("NODE_OPTIONS"):
                env["NODE_OPTIONS"] = os.environ["NODE_OPTIONS"]
            if os.environ.get("RPC_PRIVACY_SRC"):
                env["RPC_PRIVACY_SRC"] = os.environ["RPC_PRIVACY_SRC"]
            os.chdir(ROOT)
            flags = ["--noprofile", "--norc", "--noediting", "-i"] if shell == "bash" else ["-f", "-i"]
            os.execve(shutil.which(shell), [shell] + flags, env)
        self.output = b""
        self.owned = {self.pid}
        self.groups = set()
        try:
            self.pump_until(lambda: PROMPT in self.output, "シェルの起動")
            if shell == "zsh":
                mark = len(self.output)
                self.send(b"unsetopt zle\r")
                self.wait_text(PROMPT, mark, "シェルの行編集を無効化")
            self.initial = self.flags()
            assert self.initial == {"echo": True, "canonical": True}, "シェルの基準端末設定がcookedでない"
        except (AssertionError, OSError) as error:
            self.close()
            raise RuntimeError(f"PTYが使えない: {error}") from error

    def flags(self):
        mode = termios.tcgetattr(self.fd)[3]
        return {"echo": bool(mode & termios.ECHO), "canonical": bool(mode & termios.ICANON)}

    def pump_until(self, condition, description, timeout=5):
        deadline = time.monotonic() + timeout
        while not condition():
            if time.monotonic() >= deadline:
                raise AssertionError(f"{description}: timeout（停止・復帰または受理に失敗）")
            ready, _, _ = select.select([self.fd], [], [], .02)
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b""
                if not data:
                    raise AssertionError(f"{description}: シェルまたは読み手が早期終了")
                self.output += data

    def send(self, data):
        os.write(self.fd, data)

    def wait_text(self, text, start, description):
        self.pump_until(lambda: text in self.output[start:], description)

    def drain(self):
        ready, _, _ = select.select([self.fd], [], [], .02)
        if ready:
            try:
                self.output += os.read(self.fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise

    def close(self):
        # setParamのPTYと同じく、終了中もmasterを読み、blocking waitpidは使わない。
        def kill_group(group):
            if group > 0:
                assert group != os.getpgrp(), "試験の親のグループを終了しない"
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        def alive(pid):
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False

        def group_alive(group):
            try:
                os.killpg(group, 0)
                return True
            except ProcessLookupError:
                return False

        try:
            self.owned |= {int(pid) for pid in re.findall(rb'PROBE_PID=(\d+)', self.output)}
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            reaped = bool(done)
            if not reaped:
                foreground = os.tcgetpgrp(self.fd)
                if foreground != self.pid:
                    self.groups.add(foreground)
                for group in self.groups:
                    kill_group(group)
                self.send(b"\x03kill -KILL %1 2>/dev/null\rexit\r")
                for grace in [1, 2]:
                    deadline = time.monotonic() + grace
                    while time.monotonic() < deadline:
                        done, _ = os.waitpid(self.pid, os.WNOHANG)
                        if done:
                            reaped = True
                            break
                        self.drain()
                    if reaped:
                        break
                    os.kill(self.pid, signal.SIGKILL)
                if not reaped:
                    raise RuntimeError("後始末: timeout（SIGKILL後も子を回収できない）")
            deadline = time.monotonic() + 2
            while any(alive(pid) for pid in self.owned) or any(group_alive(group) for group in self.groups):
                if time.monotonic() >= deadline:
                    raise RuntimeError("後始末: timeout（所有する子プロセスが残った）")
                self.drain()
        finally:
            os.close(self.fd)


def run(shell, output, action, cycles, work):
    tee = work / f"{shell}-{output}-{action}.tee"
    command = shlex.join([shutil.which("node"), str(ROOT / "block-verifier/test/rpc-privacy-prompt-probe.mjs")])
    if output == "pipe": command += " | tee " + shlex.quote(str(tee))
    job = Job(shell, work)
    try:
        mark = len(job.output)
        job.send(command.encode() + b"\r")
        job.wait_text(b"RPC_SECRET> ", mark, "秘密の問い")
        mark = len(job.output)
        assert job.flags() == {"echo": False, "canonical": False}, "stdoutパイプでもstdinはraw"
        job.groups.add(os.tcgetpgrp(job.fd))
        for cycle in range(cycles):
            job.send(PARTIAL + b"\x1a")
            job.wait_text(PROMPT, mark, "Ctrl-Zでパイプ全体を停止")
            assert job.flags() == job.initial, "停止中の端末設定を戻す"
            fgmark = len(job.output)
            job.send(b"fg\r")
            job.pump_until(lambda: os.tcgetpgrp(job.fd) != job.pid, "fgで前景に復帰")
            job.pump_until(lambda: job.flags() == {"echo": False, "canonical": False}, "fgでrawに復帰")
            job.send(b"\x15")
            mark = fgmark
        job.send(SECRET + (b"\x03" if action == "ctrl-c" else b"\r"))
        job.wait_text(b"PROBE_CLOSED", mark, "同じ問いを受理しclose")
        assert (b"PROBE_ABORTED" if action == "ctrl-c" else b"PROBE_ACCEPTED") in job.output[mark:]
        assert SECRET not in job.output and PARTIAL not in job.output, "秘密が画面に出た"
        assert job.flags() == job.initial, "close後の端末設定を戻す"
        mark = len(job.output)
        job.send(b"\r")
        job.wait_text(PROMPT, mark, "シェルに復帰")
        job.send(b"printf '\nPROBE_EXIT=%s\n' $?\r")
        expected = 3 if action == "ctrl-c" and output == "tty" else 0
        job.wait_text(f"PROBE_EXIT={expected}\r\n".encode(), mark, "終了値")
        if tee.exists(): assert SECRET not in tee.read_bytes() and PARTIAL not in tee.read_bytes()
        return {"shell": shell, "stdout": output, "action": action, "cycles": cycles,
                "hidden": True, "stopRestored": True, "resumeRaw": True, "closeRestored": True}
    finally: job.close()

def save_from_cli(value, work):
    directory = work / ("cli-" + str(len(list(work.iterdir()))))
    directory.mkdir()
    src = Path(os.environ.get("RPC_PRIVACY_SRC", ROOT / "block-verifier/src"))
    cli = (src / "index.js").read_text().replace(
        "import { createChain } from './chain.js';",
        "const createChain = () => ({ chainId: async () => { throw new Error('fake offline connection failure'); } });")
    cli = re.sub(r"from '(\.[^']+)'", lambda m: "from '" + (src / m[1]).resolve().as_uri() + "'", cli)
    entry = directory / "cli.mjs"
    entry.write_text(cli)
    master, slave = pty.openpty()
    initial = termios.tcgetattr(slave)
    proc = subprocess.Popen([shutil.which("node"), str(entry), '--lang', 'en'],
                            stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=directory)
    output, echo = b"", b""
    def pump_until(condition):
        nonlocal output, echo
        deadline = time.monotonic() + 10
        while not condition():
            assert time.monotonic() < deadline and proc.poll() is None, "実CLIの入力・保存が終わらない"
            ready, _, _ = select.select([master, proc.stdout, proc.stderr], [], [], .02)
            for fd in ready:
                chunk = os.read(fd if isinstance(fd, int) else fd.fileno(), 65536)
                if fd == master: echo += chunk
                else: output += chunk
    try:
        pump_until(lambda: b'> ' in output)
        option = re.search(rb'(\d+)\) Enter another custom RPC URL', output)[1]
        os.write(master, option + b'\r')
        pump_until(lambda: b'RPC URL: ' in output)
        assert not termios.tcgetattr(slave)[3] & termios.ECHO, "実CLIも秘密の問いでエコーを止める"
        echo = b""
        os.write(master, value.encode() + b'\r')
        pump_until(lambda: output.count(b'Choose an Ethereum RPC') == 2)
        assert json.loads((directory / 'verifier-config.json').read_text())['customRpcs'] == [value], "HEADどおり入力を保存する"
        assert not echo, "秘密の入力が端末のエコーに出た"
        if len(value) >= 16: assert value.encode() not in output, "URLまたは不正入力が接続失敗で漏れた"
        assert termios.tcgetattr(slave) == initial, "stdoutパイプの実CLIで入力後に端末設定を戻す"
        os.write(master, b'\x04')
        proc.communicate(timeout=10)
        assert proc.returncode in (0, 3), f"EOF後の終了: {proc.returncode}"
        return {"cliSaved": value if len(value) < 16 else "synthetic URL/invalid value", "hidden": True, "restored": True, "exit": proc.returncode}
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
                deadline = time.monotonic() + 3
                while proc.poll() is None:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("実CLIの後始末: timeout")
                    ready, _, _ = select.select([master, proc.stdout, proc.stderr], [], [], .02)
                    for fd in ready:
                        try:
                            os.read(fd if isinstance(fd, int) else fd.fileno(), 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
        finally:
            os.close(master); os.close(slave)
            proc.stdout.close(); proc.stderr.close()

if __name__ == '__main__':
    def overall_timeout(_signum, _frame):
        raise RuntimeError("全体の上限50秒: timeout")
    signal.signal(signal.SIGALRM, overall_timeout)
    signal.alarm(50)
    try:
        rows = []
        with tempfile.TemporaryDirectory(prefix="rpc-privacy-pty-") as directory:
            for shell in ["bash", "zsh"]:
                if not shutil.which(shell): continue
                for output in ["tty", "pipe"]:
                    for action in ["enter", "ctrl-c"]:
                        for cycles in [0, 2]:
                            row = run(shell, output, action, cycles, Path(directory))
                            rows.append(row)
                            print(json.dumps(row), flush=True)
            for value in ['1', 'e', 'l', '123456789012345', 'FAKE-INVALID-INPUT-OVER-16', 'https://rpc.example.test/v2/FAKE-CLI-SAVED-KEY']:
                print(json.dumps(save_from_cli(value, Path(directory))), flush=True)
        assert len(rows) >= 8, "ジョブ制御シェルが必要"
        print(f"RPC privacy PTY: PASS ({len(rows)} cases)")
    except (AssertionError, RuntimeError, OSError) as error:
        sys.exit(f"RPC privacy PTY: FAIL: {error}")
