Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its functionality, relate it to reverse engineering, and identify system-level interactions, logical reasoning, potential user errors, and how a user reaches this code.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for familiar keywords and patterns. Things that jump out:

* `import`:  Standard Python imports. `argparse`, `os`, `platform`, `re`, `signal`, `sys`, `threading`, `time`, `colorama`, `frida`, `frida._frida`. These suggest command-line argument parsing, OS interaction, regular expressions, signal handling, system interaction, threading, time management, colored terminal output, and crucially, the `frida` library itself.
* `class ConsoleApplication`: This is the core of the code. It seems to be a base class for Frida tools.
* Methods like `_initialize_arguments_parser`, `_add_options`, `run`, `_start`, `_stop`, `_attach`, `_spawn`. These strongly hint at the lifecycle and core operations of a command-line tool that interacts with processes.
* References to "device", "target", "pid", "spawn", "attach", "session". These are central concepts in dynamic instrumentation and Frida.
* Functions like `input_with_cancellable`, `await_enter`, `await_ctrl_c`. These point to user interaction and handling of cancellation or interruption.
* Regular expressions like `AUX_OPTION_PATTERN`. This indicates parsing of string-based options.
* Conditional logic based on `platform.system()`. This shows awareness of operating system differences (Windows vs. others).

**2. Deconstructing the Core Class (`ConsoleApplication`):**

The name itself suggests a command-line application. The docstring confirms it's a base class for Frida tools. We can infer that specific Frida tools will inherit from this class and implement their specific logic in methods like `_start`.

* **`__init__`:** This method sets up the application. It handles argument parsing using `argparse`, initializes the `Reactor` (likely for event handling), and sets up signal handlers. The logic for handling different device connection types (-D, -U, -R, -H) is important. The initialization of target arguments (-f, -n, -p, -W) also stands out.
* **`run`:** This is the main execution loop. It initializes the Frida device manager, sets up listeners for device changes, and calls the `_try_start` method to initiate the connection and instrumentation process. It also handles signals (SIGTERM) and performs cleanup.
* **`_try_start`:** This method attempts to connect to a Frida device based on the provided arguments (or environment variables).
* **`_attach_and_instrument`:** This is the heart of the target interaction. It handles different ways of specifying the target (by file, name, identifier, PID, or waiting for a spawn). It uses `frida` functions like `spawn`, `attach`, and `get_frontmost_application`.
* **`_attach`:**  This method actually performs the Frida attachment to a process using `self._device.attach()`.
* **`_spawn`:** Though not explicitly a separate method here (the spawning logic is within `_attach_and_instrument`), the code clearly handles process spawning.
* **`_start` and `_stop`:** These are intended to be overridden by subclasses to implement the tool's specific logic.
* **Event Handlers (`_on_device_lost`, `_on_session_detached`, `_on_spawn_added`, `_on_output`):** These methods handle asynchronous events from Frida, such as a device disconnecting, a session detaching, a new process spawning (when using `--await`), and output from the target process.

**3. Connecting to Reverse Engineering Concepts:**

As we analyze the methods, connections to reverse engineering become clear:

* **Dynamic Instrumentation:** The core purpose of Frida. The code manages connecting to processes (`attach`), spawning processes (`spawn`), and interacting with them through the `frida` library.
* **Process Attachment:** The `-n`, `-N`, and `-p` options directly relate to attaching to existing processes, a common reverse engineering task.
* **Process Spawning:** The `-f` option enables spawning a process, allowing for instrumentation from the very beginning. This is crucial for analyzing application startup or bypassing anti-debugging techniques.
* **Interception and Monitoring:** The `_on_output` method shows how the tool captures the standard output and standard error of the target process, allowing for monitoring of its behavior.
* **Bypassing Detection:** While not explicitly coded *here*, the ability to attach and inject scripts (which this code facilitates) is a key aspect of bypassing security measures in reverse engineering.
* **Understanding Program Behavior:** By attaching and potentially injecting scripts (which this base class prepares for), reverse engineers can gain deep insights into the inner workings of an application.

**4. Identifying System-Level Interactions:**

The code interacts with the underlying OS:

* **Process Management:**  Spawning (`self._device.spawn`), attaching (`self._device.attach`), killing (`self._device.kill`), and resuming processes (`self._device.resume`).
* **Signal Handling:**  Using the `signal` module to handle `SIGTERM`, allowing for graceful shutdown.
* **File System Access:** Reading options from files (`--options-file`).
* **Environment Variables:**  Checking environment variables like `TERM`, `NO_COLOR`, `FRIDA_DEVICE`, `FRIDA_HOST`, etc.
* **Platform-Specific Code:**  The `platform.system()` checks indicate different handling for Windows, macOS, and Linux (e.g., for input and getting Frida directories).
* **Kernel Interaction (Implicit):** The `frida` library itself, which this code uses, interacts with the OS kernel to perform the dynamic instrumentation.

**5. Logical Reasoning and Assumptions:**

* **Target Specification:** The code assumes the user will provide a valid target through command-line arguments.
* **Device Availability:** It assumes a Frida server is running on the specified device (or locally).
* **Frida Library Functionality:**  It relies on the correct behavior and availability of the `frida` library.
* **User Intent:**  The code is designed to be a flexible base class, assuming the inheriting tools will have specific use cases.

**6. Potential User Errors:**

* **Incorrect Target Specification:** Providing an invalid PID, process name, or file path.
* **Frida Server Issues:**  The Frida server not running or being unreachable.
* **Permissions Problems:**  Not having sufficient permissions to attach to or spawn a process.
* **Conflicting Options:**  Specifying incompatible command-line arguments (e.g., multiple device connection types).
* **Typos in Arguments:**  Simple errors in typing command-line options.
* **Incorrect Relay Configuration:**  Errors in the `--relay` argument format.

**7. Tracing User Operations:**

A user reaches this code by:

1. **Installing Frida and Frida-tools:** This ensures the `frida-tools` package is available.
2. **Running a Frida tool:** Executing a command-line tool that inherits from `ConsoleApplication` (e.g., `frida-ps`, `frida-trace`). The Python interpreter will load and execute the tool's code.
3. **Providing Command-Line Arguments:** The user provides arguments specifying the target, device, and other options. These arguments are parsed by the `argparse` logic in `ConsoleApplication.__init__`.
4. **The tool's `run()` method is invoked:** This starts the core logic of the tool, including connecting to a device and target.
5. **The `_attach_and_instrument()` method is called:** Based on the provided target information, this method attempts to connect to or spawn the target process.

**8. Functionality Summary (for Part 1):**

The `ConsoleApplication` class in `application.py` provides the foundational structure and common functionality for Frida command-line tools. Its primary responsibilities are:

* **Command-Line Argument Parsing:**  Defining and processing standard arguments for connecting to devices and specifying target processes.
* **Device Management:**  Handling connections to local and remote Frida servers, including USB and remote devices.
* **Target Process Management:**  Supporting various ways to specify a target process (by name, PID, identifier, or by spawning a new process).
* **Asynchronous Event Handling:**  Using the `Reactor` to manage events like device connection/disconnection, session detachment, and process output.
* **Basic UI:** Providing basic terminal output and status messages.
* **Error Handling:**  Catching and reporting errors during device connection and target attachment.
* **Signal Handling:**  Gracefully handling termination signals.
* **Configuration Management:**  Providing methods for accessing Frida configuration and data directories.

In essence, it's a reusable base class that handles the boilerplate of creating a Frida command-line tool, allowing specific tools to focus on their core instrumentation logic within methods like `_start`.

This detailed breakdown covers the instructions and provides a comprehensive understanding of the code's function.
```python
"""
import argparse
import codecs
import errno
import numbers
import os
import platform
import re
import select
import shlex
import signal
import sys
import threading
import time
from types import FrameType
from typing import Any, Callable, List, Optional, Tuple, TypeVar, Union

if platform.system() == "Windows":
    import msvcrt

import colorama
import frida
import frida._frida as _frida

from frida_tools.reactor import Reactor

AUX_OPTION_PATTERN = re.compile(r"(.+)=\((string|bool|int)\)(.+)")

T = TypeVar("T")
TargetType = Union[List[str], re.Pattern, int, str]
TargetTypeTuple = Tuple[str, TargetType]

def input_with_cancellable(cancellable: frida.Cancellable) -> str:
    if platform.system() == "Windows":
        result = ""
        done = False

        while not done:
            while msvcrt.kbhit():
                c = msvcrt.getwche()
                if c in ("\x00", "\xe0"):
                    msvcrt.getwche()
                    continue

                result += c

                if c == "\n":
                    done = True
                    break

            cancellable.raise_if_cancelled()
            time.sleep(0.05)

        return result
    elif platform.system() in ["Darwin", "FreeBSD"]:
        while True:
            try:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
            except OSError as e:
                if e.args[0] != errno.EINTR:
                    raise e

            cancellable.raise_if_cancelled()

            if sys.stdin in rlist:
                return sys.stdin.readline()
    else:
        with cancellable.get_pollfd() as cancellable_fd:
            try:
                rlist, _, _ = select.select([sys.stdin, cancellable_fd], [], [])
            except OSError as e:
                if e.args[0] != errno.EINTR:
                    raise e

        cancellable.raise_if_cancelled()

        return sys.stdin.readline()

def await_enter(reactor: Reactor) -> None:
    try:
        input_with_cancellable(reactor.ui_cancellable)
    except frida.OperationCancelledError:
        pass
    except KeyboardInterrupt:
        print("")

def await_ctrl_c(reactor: Reactor) -> None:
    while True:
        try:
            input_with_cancellable(reactor.ui_cancellable)
        except frida.OperationCancelledError:
            break
        except KeyboardInterrupt:
            break

def deserialize_relay(value: str) -> frida.Relay:
    address, username, password, kind = value.split(",")
    return frida.Relay(address, username, password, kind)

def create_target_parser(target_type: str) -> Callable[[str], TargetTypeTuple]:
    def parse_target(value: str) -> TargetTypeTuple:
        if target_type == "file":
            return (target_type, [value])
        if target_type == "gated":
            return (target_type, re.compile(value))
        if target_type == "pid":
            return (target_type, int(value))
        return (target_type, value)

    return parse_target

class ConsoleState:
    EMPTY = 1
    STATUS = 2
    TEXT = 3

class ConsoleApplication:
    """
    ConsoleApplication is the base class for all of Frida tools, which contains
    the common arguments of the tools. Each application can implement one or
    more of several methods that can be inserted inside the flow of the
    application.

    The subclass should not expose any additional methods aside from __init__
    and run methods that are defined by this class. These methods should not be
    overridden without calling the super method.
    """

    _target: Optional[TargetTypeTuple] = None

    def __init__(
        self,
        run_until_return: Callable[["Reactor"], None] = await_enter,
        on_stop: Optional[Callable[[], None]] = None,
        args: Optional[List[str]] = None,
    ):
        plain_terminal = os.environ.get("TERM", "").lower() == "none"

        # Windows doesn't have SIGPIPE
        if hasattr(signal, "SIGPIPE"):
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)

        # If true, emit text without colors. https://no-color.org/
        no_color = plain_terminal or bool(os.environ.get("NO_COLOR"))

        colorama.init(strip=True if no_color else None)

        parser = self._initialize_arguments_parser()
        real_args = compute_real_args(parser, args=args)
        options = parser.parse_args(real_args)

        # handle scripts that don't need a target
        if not hasattr(options, "args"):
            options.args = []

        self._initialize_device_arguments(parser, options)
        self._initialize_target_arguments(parser, options)

        self._reactor = Reactor(run_until_return, on_stop)
        self._device: Optional[frida.core.Device] = None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._spawned_pid: Optional[int] = None
        self._spawned_argv = None
        self._selected_spawn: Optional[_frida.Spawn] = None
        self._target_pid: Optional[int] = None
        self._session: Optional[frida.core.Session] = None
        self._schedule_on_session_detached = lambda reason, crash: self._reactor.schedule(
            lambda: self._on_session_detached(reason, crash)
        )
        self._started = False
        self._resumed = False
        self._exit_status: Optional[int] = None
        self._console_state = ConsoleState.EMPTY
        self._have_terminal = sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("TERM", "") == "dumb"
        self._plain_terminal = plain_terminal
        self._quiet = False
        if sum(map(lambda v: int(v is not None), (self._device_id, self._device_type, self._host))) > 1:
            parser.error("Only one of -D, -U, -R, and -H may be specified")

        self._initialize_target(parser, options)

        try:
            self._initialize(parser, options, options.args)
        except Exception as e:
            parser.error(str(e))

    def _initialize_device_arguments(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_device():
            self._device_id = options.device_id
            self._device_type = options.device_type
            self._host = options.host
            if all([x is None for x in [self._device_id, self._device_type, self._host]]):
                self._device_id = os.environ.get("FRIDA_DEVICE")
                if self._device_id is None:
                    self._host = os.environ.get("FRIDA_HOST")
            self._certificate = options.certificate or os.environ.get("FRIDA_CERTIFICATE")
            self._origin = options.origin or os.environ.get("FRIDA_ORIGIN")
            self._token = options.token or os.environ.get("FRIDA_TOKEN")
            self._keepalive_interval = options.keepalive_interval
            self._session_transport = options.session_transport
            self._stun_server = options.stun_server
            self._relays = options.relays
        else:
            self._device_id = None
            self._device_type = None
            self._host = None
            self._certificate = None
            self._origin = None
            self._token = None
            self._keepalive_interval = None
            self._session_transport = "multiplexed"
            self._stun_server = None
            self._relays = None

    def _initialize_target_arguments(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_target():
            self._stdio = options.stdio
            self._aux = options.aux
            self._realm = options.realm
            self._runtime = options.runtime
            self._enable_debugger = options.enable_debugger
            self._squelch_crash = options.squelch_crash
        else:
            self._stdio = "inherit"
            self._aux = []
            self._realm = "native"
            self._runtime = "qjs"
            self._enable_debugger = False
            self._squelch_crash = False

    def _initialize_target(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_target():
            target = getattr(options, "target", None)
            if target is None:
                if len(options.args) < 1:
                    parser.error("target must be specified")
                target = infer_target(options.args[0])
                options.args.pop(0)
            target = expand_target(target)
            if target[0] == "file":
                if not isinstance(target[1], list):
                    raise ValueError("file target must be a list of strings")
                argv = target[1]
                argv.extend(options.args)
                options.args = []
            self._target = target
        else:
            self._target = None

    def _initialize_arguments_parser(self) -> argparse.ArgumentParser:
        parser = self._initialize_base_arguments_parser()
        self._add_options(parser)
        return parser

    def _initialize_base_arguments_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(usage=self._usage())

        if self._needs_device():
            self._add_device_arguments(parser)

        if self._needs_target():
            self._add_target_arguments(parser)

        parser.add_argument(
            "-O", "--options-file", help="text file containing additional command line options", metavar="FILE"
        )
        parser.add_argument("--version", action="version", version=frida.__version__)

        return parser

    def _add_device_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-D", "--device", help="connect to device with the given ID", metavar="ID", dest="device_id"
        )
        parser.add_argument(
            "-U", "--usb", help="connect to USB device", action="store_const", const="usb", dest="device_type"
        )
        parser.add_argument(
            "-R",
            "--remote",
            help="connect to remote frida-server",
            action="store_const",
            const="remote",
            dest="device_type",
        )
        parser.add_argument("-H", "--host", help="connect to remote frida-server on HOST")
        parser.add_argument("--certificate", help="speak TLS with HOST, expecting CERTIFICATE")
        parser.add_argument("--origin", help="connect to remote server with “Origin” header set to ORIGIN")
        parser.add_argument("--token", help="authenticate with HOST using TOKEN")
        parser.add_argument(
            "--keepalive-interval",
            help="set keepalive interval in seconds, or 0 to disable (defaults to -1 to auto-select based on transport)",
            metavar="INTERVAL",
            type=int,
        )
        parser.add_argument(
            "--p2p",
            help="establish a peer-to-peer connection with target",
            action="store_const",
            const="p2p",
            dest="session_transport",
            default="multiplexed",
        )
        parser.add_argument("--stun-server", help="set STUN server ADDRESS to use with --p2p", metavar="ADDRESS")
        parser.add_argument(
            "--relay",
            help="add relay to use with --p2p",
            metavar="address,username,password,turn-{udp,tcp,tls}",
            dest="relays",
            action="append",
            type=deserialize_relay,
        )

    def _add_target_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("-f", "--file", help="spawn FILE", dest="target", type=create_target_parser("file"))
        parser.add_argument(
            "-F",
            "--attach-frontmost",
            help="attach to frontmost application",
            dest="target",
            action="store_const",
            const=("frontmost", None),
        )
        parser.add_argument(
            "-n",
            "--attach-name",
            help="attach to NAME",
            metavar="NAME",
            dest="target",
            type=create_target_parser("name"),
        )
        parser.add_argument(
            "-N",
            "--attach-identifier",
            help="attach to IDENTIFIER",
            metavar="IDENTIFIER",
            dest="target",
            type=create_target_parser("identifier"),
        )
        parser.add_argument(
            "-p", "--attach-pid", help="attach to PID", metavar="PID", dest="target", type=create_target_parser("pid")
        )
        parser.add_argument(
            "-W",
            "--await",
            help="await spawn matching PATTERN",
            metavar="PATTERN",
            dest="target",
            type=create_target_parser("gated"),
        )
        parser.add_argument(
            "--stdio",
            help="stdio behavior when spawning (defaults to “inherit”)",
            choices=["inherit", "pipe"],
            default="inherit",
        )
        parser.add_argument(
            "--aux",
            help="set aux option when spawning, such as “uid=(int)42” (supported types are: string, bool, int)",
            metavar="option",
            action="append",
            dest="aux",
            default=[],
        )
        parser.add_argument("--realm", help="realm to attach in", choices=["native", "emulated"], default="native")
        parser.add_argument("--runtime", help="script runtime to use", choices=["qjs", "v8"])
        parser.add_argument(
            "--debug",
            help="enable the Node.js compatible script debugger",
            action="store_true",
            dest="enable_debugger",
            default=False,
        )
        parser.add_argument(
            "--squelch-crash",
            help="if enabled, will not dump crash report to console",
            action="store_true",
            default=False,
        )
        parser.add_argument("args", help="extra arguments and/or target", nargs="*")

    def run(self) -> None:
        mgr = frida.get_device_manager()

        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on("changed", on_devices_changed)

        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=1)

        signal.signal(signal.SIGTERM, self._on_sigterm)

        self._reactor.run()

        if self._started:
            try:
                self._perform_on_background_thread(self._stop)
            except frida.OperationCancelledError:
                pass

        if self._session is not None:
            self._session.off("detached", self._schedule_on_session_detached)
            try:
                self._perform_on_background_thread(self._session.detach)
            except frida.OperationCancelledError:
                pass
            self._session = None

        if self._device is not None:
            self._device.off("output", self._schedule_on_output)
            self._device.off("lost", self._schedule_on_device_lost)

        mgr.off("changed", on_devices_changed)

        frida.shutdown()
        sys.exit(self._exit_status)

    def _respawn(self) -> None:
        self._session.off("detached", self._schedule_on_session_detached)
        self._stop()
        self._session = None

        self._device.kill(self._spawned_pid)
        self._spawned_pid = None
        self._spawned_argv = None
        self._resumed = False

        self._attach_and_instrument()
        self._resume()

    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        """
        override this method if you want to add custom arguments to your
        command. The parser command is an argparse object, you should add the
        options to him.
        """

    def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
        """
        override this method if you need to have additional initialization code
        before running, maybe to use your custom options from the `_add_options`
        method.
        """

    def _usage(self) -> str:
        """
        override this method if to add a custom usage message
        """

        return "%(prog)s [options]"

    def _needs_device(self) -> bool:
        """
        override this method if your command need to get a device from the user.
        """

        return True

    def _needs_target(self) -> bool:
        """
        override this method if your command does not need to get a target
        process from the user.
        """

        return False

    def _start(self) -> None:
        """
        override this method with the logic of your command, it will run after
        the class is fully initialized with a connected device/target if you
        required one.
        """

    def _stop(self) -> None:
        """
        override this method if you have something you need to do at the end of
        your command, maybe cleaning up some objects.
        """

    def _resume(self) -> None:
        if self._resumed:
            return
        if self._spawned_pid is not None:
            assert self._device is not None
            self._device.resume(self._spawned_pid)
            assert self._target is not None
            if self._target[0] == "gated":
                self._device.disable_spawn_gating()
                self._device.off("spawn-added", self._on_spawn_added)
        self._resumed = True

    def _exit(self, exit_status: int) -> None:
        self._exit_status = exit_status
        self._reactor.stop()

    def _try_start(self) -> None:
        if self._device is not None:
            return
        if self._device_id is not None:
            try:
                self._device = frida.get_device(self._device_id)
            except:
                self._update_status(f"Device '{self._device_id}' not found")
                self._exit(1)
                return
        elif (self._host is not None) or (self._device_type == "remote"):
            host = self._host

            options = {}
            if self._certificate is not None:
                options["certificate"] = self._certificate
            if self._origin is not None:
                options["origin"] = self._origin
            if self._token is not None:
                options["token"] = self._token
            if self._keepalive_interval is not None:
                options["keepalive_interval"] = self._keepalive_interval

            if host is None and len(options) == 0:
                self._device = frida.get_remote_device()
            else:
                self._device = frida.get_device_manager().add_remote_device(
                    host if host is not None else "127.0.0.1", **options
                )
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        else:
            self._device = frida.get_local_device()
        self._on_device_found()
        self._device.on("output", self._schedule_on_output)
        self._device.on("lost", self._schedule_on_device_lost)
        self._attach_and_instrument()

    def _attach_and_instrument(self) -> None:
        if self._target is not None:
            target_type, target_value = self._target

            if target_type == "gated":
                self._device.on("spawn-added", self._on_spawn_added)
                try:
                    self._device.enable_spawn_gating()
                except Exception as e:
                    self._update_status(f"Failed to enable spawn gating: {e}")
                    self._exit(1)
                    return
                self._update_status("Waiting for spawn to appear...")
                return

            spawning = True
            try:
                if target_type == "frontmost":
                    try:
                        app = self._device.get_frontmost_application()
                    except Exception as e:
                        self._update_status(f"Unable to get frontmost application on {self._device.name}: {e}")
                        self._exit(1)
                        return
                    if app is None:
                        self._update_status(f"No frontmost application on {self._device.name}")
                        self._exit(1)
                        return
                    self._target = ("name", app.name)
                    attach_target = app.pid
                elif target_type == "identifier":
                    spawning = False
                    app_list = self._device.enumerate_applications()
                    app_identifier_lc = target_value.lower()
                    matching = [app for app in app_list if app.identifier.lower() == app_identifier_lc]
                    if len(matching) == 1 and matching[0].pid != 0:
                        attach_target = matching[0].pid
                    elif len(matching) > 1:
                        raise frida.ProcessNotFoundError(
                            "ambiguous identifier; it matches: %s"
                            % ", ".join([f"{process.identifier} (pid: {process.pid})" for process in matching])
                        )
                    else:
                        raise frida.ProcessNotFoundError("unable to find process with identifier '%s'" % target_value)
                elif target_type == "file":
                    argv = target_value
                    if not self._quiet:
                        self._update_status(f"Spawning `{' '.join(argv)}`...")

                    aux_kwargs = {}
                    if self._aux is not None:
                        aux_kwargs = dict([parse_aux_option(o) for o in self._aux])

                    self._spawned_pid = self._device.spawn(argv, stdio=self._stdio, **aux_kwargs)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    if not isinstance(attach_target, numbers.Number):
                        attach_target = self._device.get_process(attach_target).pid
                    if not self._quiet:
                        self._update_status("Attaching...")
                spawning = False
                self._attach(attach_target)
            except frida.OperationCancelledError:
                self._exit(0)
                return
            except Exception as e:
                if spawning:
                    self._update_status(f"Failed to spawn: {e}")
                else:
                    self._update_status(f"Failed to attach: {e}")
                self._exit(1)
                return
        self._start()
        self._started = True

    def _pick_worker_pid(self) -> int:
        try:
            frontmost = self._device.get_frontmost_application()
            if frontmost is not None and frontmost.identifier == "re.frida.Gadget":
                return frontmost.pid
        except:
            pass
        return 0

    def _attach(self, pid: int) -> None:
        self._target_pid = pid

        assert self._device is not None
        self._session = self._device.attach(pid, realm=self._realm)
        self._session.on("detached", self._schedule_on_session_detached)

        if self._session_transport == "p2p":
            peer_options = {}
            if self._stun_server is not None:
                peer_options["stun_server"] = self._stun_server
            if self._relays is not None:
                peer_options["relays"] = self._relays
            self._session.setup_peer_connection(**peer_options)

    def _on_script_created(self, script: frida.core.Script) -> None:
        if self._enable_debugger:
            script.enable_debugger()
            self._print("Chrome Inspector server listening on port 9229\n")

    def _show_message_if_no_device(self) -> None:
        if self._device is None:
            self._print("Waiting for USB device to appear...")

    def _on_sigterm(self, n: int, f: Optional[FrameType]) -> None:
        self._reactor.
Prompt: 
```
这是目录为frida/subprojects/frida-tools/frida_tools/application.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
import argparse
import codecs
import errno
import numbers
import os
import platform
import re
import select
import shlex
import signal
import sys
import threading
import time
from types import FrameType
from typing import Any, Callable, List, Optional, Tuple, TypeVar, Union

if platform.system() == "Windows":
    import msvcrt

import colorama
import frida
import frida._frida as _frida

from frida_tools.reactor import Reactor

AUX_OPTION_PATTERN = re.compile(r"(.+)=\((string|bool|int)\)(.+)")

T = TypeVar("T")
TargetType = Union[List[str], re.Pattern, int, str]
TargetTypeTuple = Tuple[str, TargetType]


def input_with_cancellable(cancellable: frida.Cancellable) -> str:
    if platform.system() == "Windows":
        result = ""
        done = False

        while not done:
            while msvcrt.kbhit():
                c = msvcrt.getwche()
                if c in ("\x00", "\xe0"):
                    msvcrt.getwche()
                    continue

                result += c

                if c == "\n":
                    done = True
                    break

            cancellable.raise_if_cancelled()
            time.sleep(0.05)

        return result
    elif platform.system() in ["Darwin", "FreeBSD"]:
        while True:
            try:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
            except OSError as e:
                if e.args[0] != errno.EINTR:
                    raise e

            cancellable.raise_if_cancelled()

            if sys.stdin in rlist:
                return sys.stdin.readline()
    else:
        with cancellable.get_pollfd() as cancellable_fd:
            try:
                rlist, _, _ = select.select([sys.stdin, cancellable_fd], [], [])
            except OSError as e:
                if e.args[0] != errno.EINTR:
                    raise e

        cancellable.raise_if_cancelled()

        return sys.stdin.readline()


def await_enter(reactor: Reactor) -> None:
    try:
        input_with_cancellable(reactor.ui_cancellable)
    except frida.OperationCancelledError:
        pass
    except KeyboardInterrupt:
        print("")


def await_ctrl_c(reactor: Reactor) -> None:
    while True:
        try:
            input_with_cancellable(reactor.ui_cancellable)
        except frida.OperationCancelledError:
            break
        except KeyboardInterrupt:
            break


def deserialize_relay(value: str) -> frida.Relay:
    address, username, password, kind = value.split(",")
    return frida.Relay(address, username, password, kind)


def create_target_parser(target_type: str) -> Callable[[str], TargetTypeTuple]:
    def parse_target(value: str) -> TargetTypeTuple:
        if target_type == "file":
            return (target_type, [value])
        if target_type == "gated":
            return (target_type, re.compile(value))
        if target_type == "pid":
            return (target_type, int(value))
        return (target_type, value)

    return parse_target


class ConsoleState:
    EMPTY = 1
    STATUS = 2
    TEXT = 3


class ConsoleApplication:
    """
    ConsoleApplication is the base class for all of Frida tools, which contains
    the common arguments of the tools. Each application can implement one or
    more of several methods that can be inserted inside the flow of the
    application.

    The subclass should not expose any additional methods aside from __init__
    and run methods that are defined by this class. These methods should not be
    overridden without calling the super method.
    """

    _target: Optional[TargetTypeTuple] = None

    def __init__(
        self,
        run_until_return: Callable[["Reactor"], None] = await_enter,
        on_stop: Optional[Callable[[], None]] = None,
        args: Optional[List[str]] = None,
    ):
        plain_terminal = os.environ.get("TERM", "").lower() == "none"

        # Windows doesn't have SIGPIPE
        if hasattr(signal, "SIGPIPE"):
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)

        # If true, emit text without colors.  https://no-color.org/
        no_color = plain_terminal or bool(os.environ.get("NO_COLOR"))

        colorama.init(strip=True if no_color else None)

        parser = self._initialize_arguments_parser()
        real_args = compute_real_args(parser, args=args)
        options = parser.parse_args(real_args)

        # handle scripts that don't need a target
        if not hasattr(options, "args"):
            options.args = []

        self._initialize_device_arguments(parser, options)
        self._initialize_target_arguments(parser, options)

        self._reactor = Reactor(run_until_return, on_stop)
        self._device: Optional[frida.core.Device] = None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._spawned_pid: Optional[int] = None
        self._spawned_argv = None
        self._selected_spawn: Optional[_frida.Spawn] = None
        self._target_pid: Optional[int] = None
        self._session: Optional[frida.core.Session] = None
        self._schedule_on_session_detached = lambda reason, crash: self._reactor.schedule(
            lambda: self._on_session_detached(reason, crash)
        )
        self._started = False
        self._resumed = False
        self._exit_status: Optional[int] = None
        self._console_state = ConsoleState.EMPTY
        self._have_terminal = sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("TERM", "") == "dumb"
        self._plain_terminal = plain_terminal
        self._quiet = False
        if sum(map(lambda v: int(v is not None), (self._device_id, self._device_type, self._host))) > 1:
            parser.error("Only one of -D, -U, -R, and -H may be specified")

        self._initialize_target(parser, options)

        try:
            self._initialize(parser, options, options.args)
        except Exception as e:
            parser.error(str(e))

    def _initialize_device_arguments(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_device():
            self._device_id = options.device_id
            self._device_type = options.device_type
            self._host = options.host
            if all([x is None for x in [self._device_id, self._device_type, self._host]]):
                self._device_id = os.environ.get("FRIDA_DEVICE")
                if self._device_id is None:
                    self._host = os.environ.get("FRIDA_HOST")
            self._certificate = options.certificate or os.environ.get("FRIDA_CERTIFICATE")
            self._origin = options.origin or os.environ.get("FRIDA_ORIGIN")
            self._token = options.token or os.environ.get("FRIDA_TOKEN")
            self._keepalive_interval = options.keepalive_interval
            self._session_transport = options.session_transport
            self._stun_server = options.stun_server
            self._relays = options.relays
        else:
            self._device_id = None
            self._device_type = None
            self._host = None
            self._certificate = None
            self._origin = None
            self._token = None
            self._keepalive_interval = None
            self._session_transport = "multiplexed"
            self._stun_server = None
            self._relays = None

    def _initialize_target_arguments(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_target():
            self._stdio = options.stdio
            self._aux = options.aux
            self._realm = options.realm
            self._runtime = options.runtime
            self._enable_debugger = options.enable_debugger
            self._squelch_crash = options.squelch_crash
        else:
            self._stdio = "inherit"
            self._aux = []
            self._realm = "native"
            self._runtime = "qjs"
            self._enable_debugger = False
            self._squelch_crash = False

    def _initialize_target(self, parser: argparse.ArgumentParser, options: argparse.Namespace) -> None:
        if self._needs_target():
            target = getattr(options, "target", None)
            if target is None:
                if len(options.args) < 1:
                    parser.error("target must be specified")
                target = infer_target(options.args[0])
                options.args.pop(0)
            target = expand_target(target)
            if target[0] == "file":
                if not isinstance(target[1], list):
                    raise ValueError("file target must be a list of strings")
                argv = target[1]
                argv.extend(options.args)
                options.args = []
            self._target = target
        else:
            self._target = None

    def _initialize_arguments_parser(self) -> argparse.ArgumentParser:
        parser = self._initialize_base_arguments_parser()
        self._add_options(parser)
        return parser

    def _initialize_base_arguments_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(usage=self._usage())

        if self._needs_device():
            self._add_device_arguments(parser)

        if self._needs_target():
            self._add_target_arguments(parser)

        parser.add_argument(
            "-O", "--options-file", help="text file containing additional command line options", metavar="FILE"
        )
        parser.add_argument("--version", action="version", version=frida.__version__)

        return parser

    def _add_device_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-D", "--device", help="connect to device with the given ID", metavar="ID", dest="device_id"
        )
        parser.add_argument(
            "-U", "--usb", help="connect to USB device", action="store_const", const="usb", dest="device_type"
        )
        parser.add_argument(
            "-R",
            "--remote",
            help="connect to remote frida-server",
            action="store_const",
            const="remote",
            dest="device_type",
        )
        parser.add_argument("-H", "--host", help="connect to remote frida-server on HOST")
        parser.add_argument("--certificate", help="speak TLS with HOST, expecting CERTIFICATE")
        parser.add_argument("--origin", help="connect to remote server with “Origin” header set to ORIGIN")
        parser.add_argument("--token", help="authenticate with HOST using TOKEN")
        parser.add_argument(
            "--keepalive-interval",
            help="set keepalive interval in seconds, or 0 to disable (defaults to -1 to auto-select based on transport)",
            metavar="INTERVAL",
            type=int,
        )
        parser.add_argument(
            "--p2p",
            help="establish a peer-to-peer connection with target",
            action="store_const",
            const="p2p",
            dest="session_transport",
            default="multiplexed",
        )
        parser.add_argument("--stun-server", help="set STUN server ADDRESS to use with --p2p", metavar="ADDRESS")
        parser.add_argument(
            "--relay",
            help="add relay to use with --p2p",
            metavar="address,username,password,turn-{udp,tcp,tls}",
            dest="relays",
            action="append",
            type=deserialize_relay,
        )

    def _add_target_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("-f", "--file", help="spawn FILE", dest="target", type=create_target_parser("file"))
        parser.add_argument(
            "-F",
            "--attach-frontmost",
            help="attach to frontmost application",
            dest="target",
            action="store_const",
            const=("frontmost", None),
        )
        parser.add_argument(
            "-n",
            "--attach-name",
            help="attach to NAME",
            metavar="NAME",
            dest="target",
            type=create_target_parser("name"),
        )
        parser.add_argument(
            "-N",
            "--attach-identifier",
            help="attach to IDENTIFIER",
            metavar="IDENTIFIER",
            dest="target",
            type=create_target_parser("identifier"),
        )
        parser.add_argument(
            "-p", "--attach-pid", help="attach to PID", metavar="PID", dest="target", type=create_target_parser("pid")
        )
        parser.add_argument(
            "-W",
            "--await",
            help="await spawn matching PATTERN",
            metavar="PATTERN",
            dest="target",
            type=create_target_parser("gated"),
        )
        parser.add_argument(
            "--stdio",
            help="stdio behavior when spawning (defaults to “inherit”)",
            choices=["inherit", "pipe"],
            default="inherit",
        )
        parser.add_argument(
            "--aux",
            help="set aux option when spawning, such as “uid=(int)42” (supported types are: string, bool, int)",
            metavar="option",
            action="append",
            dest="aux",
            default=[],
        )
        parser.add_argument("--realm", help="realm to attach in", choices=["native", "emulated"], default="native")
        parser.add_argument("--runtime", help="script runtime to use", choices=["qjs", "v8"])
        parser.add_argument(
            "--debug",
            help="enable the Node.js compatible script debugger",
            action="store_true",
            dest="enable_debugger",
            default=False,
        )
        parser.add_argument(
            "--squelch-crash",
            help="if enabled, will not dump crash report to console",
            action="store_true",
            default=False,
        )
        parser.add_argument("args", help="extra arguments and/or target", nargs="*")

    def run(self) -> None:
        mgr = frida.get_device_manager()

        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on("changed", on_devices_changed)

        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=1)

        signal.signal(signal.SIGTERM, self._on_sigterm)

        self._reactor.run()

        if self._started:
            try:
                self._perform_on_background_thread(self._stop)
            except frida.OperationCancelledError:
                pass

        if self._session is not None:
            self._session.off("detached", self._schedule_on_session_detached)
            try:
                self._perform_on_background_thread(self._session.detach)
            except frida.OperationCancelledError:
                pass
            self._session = None

        if self._device is not None:
            self._device.off("output", self._schedule_on_output)
            self._device.off("lost", self._schedule_on_device_lost)

        mgr.off("changed", on_devices_changed)

        frida.shutdown()
        sys.exit(self._exit_status)

    def _respawn(self) -> None:
        self._session.off("detached", self._schedule_on_session_detached)
        self._stop()
        self._session = None

        self._device.kill(self._spawned_pid)
        self._spawned_pid = None
        self._spawned_argv = None
        self._resumed = False

        self._attach_and_instrument()
        self._resume()

    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        """
        override this method if you want to add custom arguments to your
        command. The parser command is an argparse object, you should add the
        options to him.
        """

    def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
        """
        override this method if you need to have additional initialization code
        before running, maybe to use your custom options from the `_add_options`
        method.
        """

    def _usage(self) -> str:
        """
        override this method if to add a custom usage message
        """

        return "%(prog)s [options]"

    def _needs_device(self) -> bool:
        """
        override this method if your command need to get a device from the user.
        """

        return True

    def _needs_target(self) -> bool:
        """
        override this method if your command does not need to get a target
        process from the user.
        """

        return False

    def _start(self) -> None:
        """
        override this method with the logic of your command, it will run after
        the class is fully initialized with a connected device/target if you
        required one.
        """

    def _stop(self) -> None:
        """
        override this method if you have something you need to do at the end of
        your command, maybe cleaning up some objects.
        """

    def _resume(self) -> None:
        if self._resumed:
            return
        if self._spawned_pid is not None:
            assert self._device is not None
            self._device.resume(self._spawned_pid)
            assert self._target is not None
            if self._target[0] == "gated":
                self._device.disable_spawn_gating()
                self._device.off("spawn-added", self._on_spawn_added)
        self._resumed = True

    def _exit(self, exit_status: int) -> None:
        self._exit_status = exit_status
        self._reactor.stop()

    def _try_start(self) -> None:
        if self._device is not None:
            return
        if self._device_id is not None:
            try:
                self._device = frida.get_device(self._device_id)
            except:
                self._update_status(f"Device '{self._device_id}' not found")
                self._exit(1)
                return
        elif (self._host is not None) or (self._device_type == "remote"):
            host = self._host

            options = {}
            if self._certificate is not None:
                options["certificate"] = self._certificate
            if self._origin is not None:
                options["origin"] = self._origin
            if self._token is not None:
                options["token"] = self._token
            if self._keepalive_interval is not None:
                options["keepalive_interval"] = self._keepalive_interval

            if host is None and len(options) == 0:
                self._device = frida.get_remote_device()
            else:
                self._device = frida.get_device_manager().add_remote_device(
                    host if host is not None else "127.0.0.1", **options
                )
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        else:
            self._device = frida.get_local_device()
        self._on_device_found()
        self._device.on("output", self._schedule_on_output)
        self._device.on("lost", self._schedule_on_device_lost)
        self._attach_and_instrument()

    def _attach_and_instrument(self) -> None:
        if self._target is not None:
            target_type, target_value = self._target

            if target_type == "gated":
                self._device.on("spawn-added", self._on_spawn_added)
                try:
                    self._device.enable_spawn_gating()
                except Exception as e:
                    self._update_status(f"Failed to enable spawn gating: {e}")
                    self._exit(1)
                    return
                self._update_status("Waiting for spawn to appear...")
                return

            spawning = True
            try:
                if target_type == "frontmost":
                    try:
                        app = self._device.get_frontmost_application()
                    except Exception as e:
                        self._update_status(f"Unable to get frontmost application on {self._device.name}: {e}")
                        self._exit(1)
                        return
                    if app is None:
                        self._update_status(f"No frontmost application on {self._device.name}")
                        self._exit(1)
                        return
                    self._target = ("name", app.name)
                    attach_target = app.pid
                elif target_type == "identifier":
                    spawning = False
                    app_list = self._device.enumerate_applications()
                    app_identifier_lc = target_value.lower()
                    matching = [app for app in app_list if app.identifier.lower() == app_identifier_lc]
                    if len(matching) == 1 and matching[0].pid != 0:
                        attach_target = matching[0].pid
                    elif len(matching) > 1:
                        raise frida.ProcessNotFoundError(
                            "ambiguous identifier; it matches: %s"
                            % ", ".join([f"{process.identifier} (pid: {process.pid})" for process in matching])
                        )
                    else:
                        raise frida.ProcessNotFoundError("unable to find process with identifier '%s'" % target_value)
                elif target_type == "file":
                    argv = target_value
                    if not self._quiet:
                        self._update_status(f"Spawning `{' '.join(argv)}`...")

                    aux_kwargs = {}
                    if self._aux is not None:
                        aux_kwargs = dict([parse_aux_option(o) for o in self._aux])

                    self._spawned_pid = self._device.spawn(argv, stdio=self._stdio, **aux_kwargs)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    if not isinstance(attach_target, numbers.Number):
                        attach_target = self._device.get_process(attach_target).pid
                    if not self._quiet:
                        self._update_status("Attaching...")
                spawning = False
                self._attach(attach_target)
            except frida.OperationCancelledError:
                self._exit(0)
                return
            except Exception as e:
                if spawning:
                    self._update_status(f"Failed to spawn: {e}")
                else:
                    self._update_status(f"Failed to attach: {e}")
                self._exit(1)
                return
        self._start()
        self._started = True

    def _pick_worker_pid(self) -> int:
        try:
            frontmost = self._device.get_frontmost_application()
            if frontmost is not None and frontmost.identifier == "re.frida.Gadget":
                return frontmost.pid
        except:
            pass
        return 0

    def _attach(self, pid: int) -> None:
        self._target_pid = pid

        assert self._device is not None
        self._session = self._device.attach(pid, realm=self._realm)
        self._session.on("detached", self._schedule_on_session_detached)

        if self._session_transport == "p2p":
            peer_options = {}
            if self._stun_server is not None:
                peer_options["stun_server"] = self._stun_server
            if self._relays is not None:
                peer_options["relays"] = self._relays
            self._session.setup_peer_connection(**peer_options)

    def _on_script_created(self, script: frida.core.Script) -> None:
        if self._enable_debugger:
            script.enable_debugger()
            self._print("Chrome Inspector server listening on port 9229\n")

    def _show_message_if_no_device(self) -> None:
        if self._device is None:
            self._print("Waiting for USB device to appear...")

    def _on_sigterm(self, n: int, f: Optional[FrameType]) -> None:
        self._reactor.cancel_io()
        self._exit(0)

    def _on_spawn_added(self, spawn: _frida.Spawn) -> None:
        thread = threading.Thread(target=self._handle_spawn, args=(spawn,))
        thread.start()

    def _handle_spawn(self, spawn: _frida.Spawn) -> None:
        pid = spawn.pid

        pattern = self._target[1]
        if pattern.match(spawn.identifier) is None or self._selected_spawn is not None:
            self._print(
                colorama.Fore.YELLOW + colorama.Style.BRIGHT + "Ignoring: " + str(spawn) + colorama.Style.RESET_ALL
            )
            try:
                if self._device is not None:
                    self._device.resume(pid)
            except:
                pass
            return

        self._selected_spawn = spawn

        self._print(colorama.Fore.GREEN + colorama.Style.BRIGHT + "Handling: " + str(spawn) + colorama.Style.RESET_ALL)
        try:
            self._attach(pid)
            self._reactor.schedule(lambda: self._on_spawn_handled(spawn))
        except Exception as e:
            error = e
            self._reactor.schedule(lambda: self._on_spawn_unhandled(spawn, error))

    def _on_spawn_handled(self, spawn: _frida.Spawn) -> None:
        self._spawned_pid = spawn.pid
        self._start()
        self._started = True

    def _on_spawn_unhandled(self, spawn: _frida.Spawn, error: Exception) -> None:
        self._update_status(f"Failed to handle spawn: {error}")
        self._exit(1)

    def _on_output(self, pid: int, fd: int, data: Optional[bytes]) -> None:
        if pid != self._target_pid or data is None:
            return
        if fd == 1:
            prefix = "stdout> "
            stream = sys.stdout
        else:
            prefix = "stderr> "
            stream = sys.stderr
        encoding = stream.encoding or "UTF-8"
        text = data.decode(encoding, errors="replace")
        if text.endswith("\n"):
            text = text[:-1]
        lines = text.split("\n")
        self._print(prefix + ("\n" + prefix).join(lines))

    def _on_device_found(self) -> None:
        pass

    def _on_device_lost(self) -> None:
        if self._exit_status is not None:
            return
        self._print("Device disconnected.")
        self._exit(1)

    def _on_session_detached(self, reason: str, crash) -> None:
        if crash is None:
            message = reason[0].upper() + reason[1:].replace("-", " ")
        else:
            message = "Process crashed: " + crash.summary
        self._print(colorama.Fore.RED + colorama.Style.BRIGHT + message + colorama.Style.RESET_ALL)
        if crash is not None:
            if self._squelch_crash is True:
                self._print("\n*** Crash report was squelched due to user setting. ***")
            else:
                self._print("\n***\n{}\n***".format(crash.report.rstrip("\n")))
        self._exit(1)

    def _clear_status(self) -> None:
        if self._console_state == ConsoleState.STATUS:
            print(colorama.Cursor.UP() + (80 * " "))

    def _update_status(self, message: str) -> None:
        if self._have_terminal:
            if self._console_state == ConsoleState.STATUS:
                cursor_position = colorama.Cursor.UP()
            else:
                cursor_position = ""
            print("%-80s" % (cursor_position + colorama.Style.BRIGHT + message + colorama.Style.RESET_ALL,))
            self._console_state = ConsoleState.STATUS
        else:
            print(colorama.Style.BRIGHT + message + colorama.Style.RESET_ALL)

    def _print(self, *args: Any, **kwargs: Any) -> None:
        encoded_args: List[Any] = []
        encoding = sys.stdout.encoding or "UTF-8"
        if encoding == "UTF-8":
            encoded_args = list(args)
        else:
            for arg in args:
                if isinstance(arg, str):
                    encoded_args.append(arg.encode(encoding, errors="backslashreplace").decode(encoding))
                else:
                    encoded_args.append(arg)
        print(*encoded_args, **kwargs)
        self._console_state = ConsoleState.TEXT

    def _log(self, level: str, text: str) -> None:
        if level == "info":
            self._print(text)
        else:
            color = colorama.Fore.RED if level == "error" else colorama.Fore.YELLOW
            text = color + colorama.Style.BRIGHT + text + colorama.Style.RESET_ALL
            if level == "error":
                self._print(text, file=sys.stderr)
            else:
                self._print(text)

    def _perform_on_reactor_thread(self, f: Callable[[], T]) -> T:
        completed = threading.Event()
        result = [None, None]

        def work() -> None:
            try:
                result[0] = f()
            except Exception as e:
                result[1] = e
            completed.set()

        self._reactor.schedule(work)

        while not completed.is_set():
            try:
                completed.wait()
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                continue

        error = result[1]
        if error is not None:
            raise error

        return result[0]

    def _perform_on_background_thread(self, f: Callable[[], T], timeout: Optional[float] = None) -> T:
        result = [None, None]

        def work() -> None:
            with self._reactor.io_cancellable:
                try:
                    result[0] = f()
                except Exception as e:
                    result[1] = e

        worker = threading.Thread(target=work)
        worker.start()

        try:
            worker.join(timeout)
        except KeyboardInterrupt:
            self._reactor.cancel_io()

        if timeout is not None and worker.is_alive():
            self._reactor.cancel_io()
            while worker.is_alive():
                try:
                    worker.join()
                except KeyboardInterrupt:
                    pass

        error = result[1]
        if error is not None:
            raise error

        return result[0]

    def _get_default_frida_dir(self) -> str:
        return os.path.join(os.path.expanduser("~"), ".frida")

    def _get_windows_frida_dir(self) -> str:
        appdata = os.environ["LOCALAPPDATA"]
        return os.path.join(appdata, "frida")

    def _get_or_create_config_dir(self) -> str:
        config_dir = os.path.join(self._get_default_frida_dir(), "config")
        if platform.system() == "Linux":
            xdg_config_home = os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
            config_dir = os.path.join(xdg_config_home, "frida")
        elif platform.system() == "Windows":
            config_dir = os.path.join(self._get_windows_frida_dir(), "Config")
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        return config_dir

    def _get_or_create_data_dir(self) -> str:
        data_dir = os.path.join(self._get_default_frida_dir(), "data")
        if platform.system() == "Linux":
            xdg_data_home = os.getenv("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
            data_dir = os.path.join(xdg_data_home, "frida")
        elif platform.system() == "Windows":
            data_dir = os.path.join(self._get_windows_frida_dir(), "Data")
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        return data_dir

    def _get_or_create_state_dir(self) -> str:
        state_dir = os.path.join(self._get_default_frida_dir(), "state")
        if platform.system() == "Linux":
            xdg_state_home = os.getenv("XDG_STATE_HOME", os.path.expanduser("~/.local/state"))
            state_dir = os.path.join(xdg_state_home, "frida")
        elif platform.system() == "Windows":
            appdata = os.environ["LOCALAPPDATA"]
            state_dir = os.path.join(appdata, "frida", "State")
        if not os.path.exists(state_dir):
            os.makedirs(state_dir)
        return state_dir


def compute_real_args(parser: argparse.ArgumentParser, args: Optional[List[str]] = None) -> List[str]:
    if args is None:
        args = sys.argv[1:]
    real_args = normalize_options_file_args(args)

    files_processed = set()
    while True:
        offset = find_options_file_offset(real_args, parser)
        if offset == -1:
            break

        file_path = os.path.abspath(real_args[offset + 1])
        if file_path in files_processed:
            parser.error(f"File '{file_path}' given twice as -O argument")

        if os.path.isfile(file_path):
            with codecs.open(file_path, "r", 
"""


```