Response:
The user wants a summary of the functionality of the provided Python code for `frida_tools/repl.py`, a part of the Frida dynamic instrumentation tool. The request also asks for specific examples relating to reverse engineering, low-level concepts (like kernel interaction), logical inference, common user errors, and how a user might reach this code.

Here's a breakdown of the thought process to achieve the summarized functionality:

1. **Identify the Core Purpose:** The filename `repl.py` and the import of `prompt_toolkit` strongly suggest this file implements the Read-Eval-Print Loop (REPL) interface for Frida. This is the primary function.

2. **Analyze Class Structure:** The code defines a `REPLApplication` class inheriting from `ConsoleApplication`. This confirms the REPL aspect and hints at a command-line application structure.

3. **Examine `__init__`:** The constructor initializes various attributes:
    * `_script`: Likely holds the Frida script being executed.
    * `_ready`, `_stopping`:  Synchronization primitives for controlling the REPL's lifecycle.
    * `_completer`: Enables tab completion in the REPL.
    * `_cli`:  The `prompt_toolkit` session for user interaction.
    * `_compilers`:  Manages compilation of scripts, likely for TypeScript or other compile-to-JS languages.
    * `_monitored_files`:  Handles automatic reloading of scripts upon file changes.
    * Flags like `_autoperform`, `_autoreload`, `_quiet_start`: Configure REPL behavior.

4. **Analyze Key Methods:**
    * `_add_options`: Uses `argparse` to define command-line arguments. These arguments reveal many functionalities, like loading scripts (`-l`), evaluating code (`-e`), connecting to processes, and configuring behavior (quiet mode, timeouts, etc.).
    * `_initialize`: Processes the command-line arguments and sets up the application state.
    * `_start`:  Initializes the Frida script and displays startup messages.
    * `_on_stop`, `_stop`: Handles the shutdown process, including unloading scripts and potentially killing the target process.
    * `_load_script`, `_unload_script`, `_eternalize_script`: Manage the Frida script lifecycle.
    * `_monitor_all`, `_demonitor_all`, `_monitor`:  Implement the file monitoring for auto-reloading.
    * `_process_input`:  The main REPL loop, responsible for reading user input, handling commands (magic commands, quick commands), and evaluating JavaScript code.
    * `_do_magic`, `_do_quick_command`:  Handle special REPL commands.
    * `_evaluate_expression`, `_evaluate_quick_command`: Execute JavaScript code within the Frida environment.
    * `_process_message`: Handles messages received from the Frida script (e.g., `console.log`).
    * `_create_repl_script`: Constructs the JavaScript code that gets injected into the target process. This involves wrapping user scripts and including the REPL runtime environment.

5. **Identify Key Functionalities based on Method Analysis:**
    * **Interactive JavaScript Execution:** The core feature of a REPL.
    * **Loading and Unloading Scripts:** Enables injecting custom JavaScript code.
    * **Command-Line Options:**  Provides flexibility in how Frida connects to targets and behaves.
    * **Auto-Reloading:**  Improves development workflow.
    * **Magic Commands:**  Offer shortcuts for common Frida actions (e.g., `%resume`).
    * **Quick Commands:**  Likely a mechanism for more specialized commands within the JavaScript environment.
    * **Code Compilation:**  Supports using TypeScript or other compiled languages.
    * **CModule Support:**  Allows loading native code modules.
    * **Integration with Frida Core:** Relies heavily on the `frida` library for instrumentation.

6. **Categorize Functionalities:** Group the identified features into logical categories for a clear summary.

7. **Formulate the Summary:** Write a concise summary of the REPL's primary purpose and list its key functionalities, drawing from the analysis of the code. Use clear and understandable language.
好的，根据你提供的 `frida/subprojects/frida-tools/frida_tools/repl.py` 文件的部分源代码，我可以归纳一下它的功能：

**核心功能：实现 Frida 的交互式 REPL (Read-Eval-Print Loop) 环境。**

更具体来说，这个文件实现了以下功能：

1. **提供一个交互式的 JavaScript 执行环境:**
   - 用户可以在终端中输入 JavaScript 代码，这些代码会被发送到目标进程中的 Frida Agent 执行。
   - 执行结果会返回到终端并显示。
   - 这使得用户能够实时地与目标进程进行交互，例如查看内存、调用函数、修改数据等。

2. **管理 Frida Script 的生命周期:**
   - **加载脚本 (`-l`, `--load`):**  允许用户加载外部的 JavaScript 脚本文件到目标进程中执行。
   - **重新加载脚本 (`reload` magic command):**  支持在修改脚本后重新加载，方便开发调试。
   - **卸载脚本 (`unload` magic command):**  可以将已加载的脚本从目标进程中卸载。
   - **持久化脚本 (`--eternalize`):**  可以在 Frida 退出后仍然保持脚本在目标进程中运行。

3. **处理用户输入和命令:**
   - **读取用户输入:**  使用 `prompt_toolkit` 库提供带语法高亮、自动补全和历史记录的交互式输入体验（如果可用）。
   - **执行 JavaScript 代码:** 将用户输入的代码发送到 Frida Agent 执行。
   - **处理特殊命令（Magic Commands，以 `%` 开头）:**  例如 `%resume` (恢复进程执行), `%load` (加载脚本) 等，用于控制 Frida 或目标进程的行为。
   - **处理快速命令（Quick Commands，以 `.` 开头）:**  允许用户执行更简洁的表达式。

4. **集成 Frida 的其他功能:**
   - **连接到目标进程 (`target`参数):** 可以连接到正在运行的进程 (通过 PID) 或启动一个新的进程。
   - **加载 C 模块 (`-C`, `--cmodule`):**  支持加载编译好的 C 模块到 Frida Agent 中。
   - **加载 CodeShare 脚本 (`-c`, `--codeshare`):**  允许用户加载并执行 Frida CodeShare 上的脚本。
   - **设置参数 (`-P`, `--parameters`):**  可以向 Frida Agent 传递 JSON 格式的参数。
   - **静默模式 (`-q`):**  在非交互式模式下执行脚本并退出。
   - **超时控制 (`-t`, `--timeout`):**  在静默模式下设置超时时间。
   - **控制进程状态 (`--pause`):**  可以在启动目标进程后暂停其主线程。
   - **日志输出 (`-o`, `--output`):**  可以将 Frida 的输出保存到日志文件中。
   - **错误处理 (`--exit-on-error`):**  在脚本发生错误时退出 Frida。
   - **进程清理 (`--kill-on-exit`):**  在 Frida 退出时杀死启动的目标进程。

5. **提供辅助功能:**
   - **自动 `Java.perform` (`--auto-perform`):**  在 Android 环境下，可以自动将输入的代码包裹在 `Java.perform` 中。
   - **自动重载 (`--auto-reload`, `--no-auto-reload`):**  当加载的脚本或 C 模块文件发生更改时，自动重新加载它们。
   - **代码补全:**  基于 Frida 的 API 和当前上下文提供代码补全建议。
   - **帮助系统:**  可以通过 `help` 命令或 `object?` 的方式查看帮助信息。

**与逆向方法的关系举例说明：**

- **动态查看和修改内存:** 逆向工程师可以使用 REPL 连接到目标进程，然后使用 JavaScript 代码读取和修改内存中的数据。例如，可以使用 `Process.getRangeByAddress(address).readByteArray(size)` 读取指定地址的内存，或者使用 `ptr(address).writeByteArray(data)` 修改内存中的值，从而绕过一些安全检查或修改程序行为。
- **Hook 函数并查看参数和返回值:**  可以使用 Frida 的 `Interceptor.attach()` API Hook 目标进程中的函数，并在函数调用前后执行自定义的 JavaScript 代码。这可以用来查看函数的参数、返回值，或者修改其行为。例如，可以 Hook 一个登录验证函数，打印出用户名和密码，或者强制其返回成功。
- **动态分析 Android 应用:**  在 Android 逆向中，可以使用 REPL 连接到 Dalvik/ART 虚拟机，并利用 `Java.use()` 等 API 操作 Java 对象，调用 Java 方法，查看和修改字段，从而分析应用的逻辑。
- **绕过反调试机制:**  一些反调试技术会检测调试器的存在。通过 Frida REPL，逆向工程师可以编写脚本来修改内存或 Hook 相关函数，从而绕过这些检测。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例说明：**

- **C 模块加载 (`-C`, `--cmodule`):**  加载 C 模块需要理解目标平台的 ABI (Application Binary Interface)，以及如何将 C 代码编译成目标平台可执行的二进制文件。这涉及到对底层二进制格式和链接过程的理解。
- **内存操作:**  使用 `Process.getRangeByAddress()` 和 `Memory.read*`/`Memory.write*` 系列 API 需要理解进程的内存布局、虚拟地址空间、不同内存区域的权限等底层概念，这与操作系统 (Linux, Android) 的内存管理机制密切相关。
- **Hook Native 函数:**  使用 `Interceptor.attach()` Hook Native 函数需要理解函数调用约定 (如 x86 的 cdecl, stdcall, ARM 的 AAPCS 等)，以及如何找到目标函数的地址。在 Android 环境下，可能需要了解 `linker` 的工作原理和动态链接库的加载过程。
- **Android Framework 交互:**  在 Android 环境下，可以使用 Frida 的 Java API 与 Android Framework 进行交互，例如调用 `Context.getSystemService()` 获取系统服务，或者操作 `ActivityManager` 等组件。这需要了解 Android Framework 的架构和相关 API。
- **内核交互 (通过 Native 代码):**  虽然 Frida 主要在用户空间工作，但通过加载 C 模块，可以调用底层的系统调用，从而与 Linux 或 Android 内核进行交互。这需要对内核 API 和系统调用机制有深入的了解。

**逻辑推理的假设输入与输出举例：**

假设用户输入以下代码并执行：

```javascript
var address = Module.findExportByName("libc.so", "open");
console.log("open 函数地址:", address);
```

**假设输入:**  用户在 Frida REPL 中输入上述 JavaScript 代码，并且当前 Frida 连接到一个运行中的进程，该进程加载了 `libc.so` 库。

**逻辑推理:**
1. `Module.findExportByName("libc.so", "open")` 会在 `libc.so` 模块中查找名为 "open" 的导出符号（函数）。
2. 如果找到该符号，`address` 变量将被赋值为该函数的内存地址。
3. `console.log()` 函数会将字符串 "open 函数地址:" 和 `address` 的值打印到 Frida REPL 的输出。

**预期输出:**  Frida REPL 会显示类似以下的信息：

```
open 函数地址: 0xb6f2e494
```

（实际地址会因系统和库的版本而异）

**涉及用户或者编程常见的使用错误举例说明：**

1. **语法错误:** 用户输入的 JavaScript 代码存在语法错误，例如拼写错误、缺少分号、括号不匹配等。
   - **例子:** `consle.log("Hello")` (拼写错误)。
   - **错误信息:** Frida 会返回 JavaScript 解释器的错误信息，例如 `SyntaxError: Unexpected identifier 'consle'. Expected either a ')' or a ',' but got 'log'`。

2. **运行时错误:** 用户尝试访问不存在的对象或属性，或者执行了非法操作。
   - **例子:** 尝试访问一个未定义的变量 `unknownVariable`。
   - **错误信息:** Frida 会返回类似 `ReferenceError: unknownVariable is not defined` 的错误。

3. **Frida API 使用错误:** 用户错误地使用了 Frida 的 API，例如传递了错误的参数类型或数量。
   - **例子:** `Interceptor.attach(0x1234, { onEnter: function(args) {} })` (传递了一个数字地址，而不是 `NativePointer`)。
   - **错误信息:** Frida 可能会抛出 `TypeError` 或其他异常，指示参数类型不匹配。

4. **目标进程状态问题:**  尝试操作目标进程中不存在的模块或函数。
   - **例子:**  在一个没有加载 `libssl.so` 的进程中执行 `Module.findExportByName("libssl.so", "SSL_CTX_new")`。
   - **错误信息:**  `null` 或抛出异常，取决于具体的 Frida API。

5. **权限问题:**  尝试执行需要更高权限的操作，例如在没有 root 权限的 Android 设备上进行某些系统级别的 Hook。
   - **现象:**  操作可能失败，并显示权限相关的错误信息。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户安装 Frida 和 Frida Tools:**  这是使用 Frida REPL 的前提。
2. **用户打开终端或命令提示符:** 用于启动 Frida REPL。
3. **用户输入 `frida` 命令，并指定目标:**
   - 连接到正在运行的进程: `frida <进程名称或 PID>`
   - 启动新的进程并附加: `frida -n <应用名称>` 或 `frida -f <可执行文件路径>`
4. **Frida 建立与目标进程的连接:**  Frida Core 会将 Agent 注入到目标进程中。
5. **`frida_tools/repl.py` 被执行:**  `frida` 命令会调用 `frida-tools` 中的相关模块，其中 `repl.py` 负责启动交互式 REPL 环境。
6. **REPL 启动，显示提示符:** 用户看到类似 `[Local::PID::1234]-> ` 的提示符，表示可以输入 JavaScript 代码了。
7. **用户输入 JavaScript 代码或 Magic 命令:**  例如输入 `console.log("Hello")` 或 `%help`。
8. **`_process_input` 方法接收用户输入:**  这个方法负责读取用户的输入。
9. **判断输入类型 (JavaScript 或 Magic Command):**  根据输入的前缀判断是 JavaScript 代码还是 Magic Command。
10. **执行相应的处理逻辑:**
    - **JavaScript 代码:** 调用 `_evaluate_expression` 或 `_evaluate_quick_command` 将代码发送到 Agent 执行。
    - **Magic Command:** 调用 `_do_magic` 方法处理。
11. **Agent 执行代码并将结果返回:**  目标进程中的 Frida Agent 执行 JavaScript 代码。
12. **`_process_message` 方法接收来自 Agent 的消息:**  包括执行结果、错误信息等。
13. **REPL 将结果打印到终端:**  用户看到 JavaScript 代码的执行结果或错误信息。

**总结一下 `frida_tools/repl.py` 的功能：**

`frida_tools/repl.py` 是 Frida 工具集中实现交互式 JavaScript REPL 环境的关键组件。它负责处理用户输入，管理 Frida 脚本的生命周期，集成 Frida 的各种功能，并提供便捷的调试和逆向分析能力。它允许用户在运行时动态地与目标进程进行交互，执行 JavaScript 代码，Hook 函数，查看和修改内存，从而实现强大的动态分析功能。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/frida_tools/repl.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
import argparse
import codecs
import hashlib
import json
import os
import platform
import re
import shlex
import signal
import string
import sys
import threading
import time
from timeit import default_timer as timer
from typing import Any, AnyStr, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, TypeVar, Union
from urllib.request import build_opener

import frida
from colorama import Fore, Style
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.shortcuts import prompt
from prompt_toolkit.styles import Style as PromptToolkitStyle
from pygments.lexers.javascript import JavascriptLexer
from pygments.token import Token

from frida_tools import _repl_magic
from frida_tools.application import ConsoleApplication
from frida_tools.cli_formatting import format_compiled, format_compiling, format_diagnostic
from frida_tools.reactor import Reactor

T = TypeVar("T")


class REPLApplication(ConsoleApplication):
    def __init__(self) -> None:
        self._script = None
        self._ready = threading.Event()
        self._stopping = threading.Event()
        self._errors = 0
        self._completer = FridaCompleter(self)
        self._cli = None
        self._last_change_id = 0
        self._compilers: Dict[str, CompilerContext] = {}
        self._monitored_files: MutableMapping[Union[str, bytes], frida.FileMonitor] = {}
        self._autoperform = False
        self._autoperform_option = False
        self._autoreload = True
        self._quiet_start: Optional[float] = None

        super().__init__(self._process_input, self._on_stop)

        if self._have_terminal and not self._plain_terminal:
            style = PromptToolkitStyle(
                [
                    ("completion-menu", "bg:#3d3d3d #ef6456"),
                    ("completion-menu.completion.current", "bg:#ef6456 #3d3d3d"),
                ]
            )
            history = FileHistory(self._get_or_create_history_file())
            self._cli = PromptSession(
                lexer=PygmentsLexer(JavascriptLexer),
                style=style,
                history=history,
                completer=self._completer,
                complete_in_thread=True,
                enable_open_in_editor=True,
                tempfile_suffix=".js",
            )
            self._dumb_stdin_reader = None
        else:
            self._cli = None
            self._dumb_stdin_reader = DumbStdinReader(valid_until=self._stopping.is_set)

        if not self._have_terminal:
            self._rpc_complete_server = start_completion_thread(self)

    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-l", "--load", help="load SCRIPT", metavar="SCRIPT", dest="user_scripts", action="append", default=[]
        )
        parser.add_argument(
            "-P",
            "--parameters",
            help="parameters as JSON, same as Gadget",
            metavar="PARAMETERS_JSON",
            dest="user_parameters",
        )
        parser.add_argument("-C", "--cmodule", help="load CMODULE", dest="user_cmodule")
        parser.add_argument(
            "--toolchain",
            help="CModule toolchain to use when compiling from source code",
            choices=["any", "internal", "external"],
            default="any",
        )
        parser.add_argument(
            "-c", "--codeshare", help="load CODESHARE_URI", metavar="CODESHARE_URI", dest="codeshare_uri"
        )
        parser.add_argument("-e", "--eval", help="evaluate CODE", metavar="CODE", action="append", dest="eval_items")
        parser.add_argument(
            "-q",
            help="quiet mode (no prompt) and quit after -l and -e",
            action="store_true",
            dest="quiet",
            default=False,
        )
        parser.add_argument(
            "-t", "--timeout", help="seconds to wait before terminating in quiet mode", dest="timeout", default=0
        )
        parser.add_argument(
            "--pause",
            help="leave main thread paused after spawning program",
            action="store_const",
            const="pause",
            dest="on_spawn_complete",
            default="resume",
        )
        parser.add_argument("-o", "--output", help="output to log file", dest="logfile")
        parser.add_argument(
            "--eternalize",
            help="eternalize the script before exit",
            action="store_true",
            dest="eternalize",
            default=False,
        )
        parser.add_argument(
            "--exit-on-error",
            help="exit with code 1 after encountering any exception in the SCRIPT",
            action="store_true",
            dest="exit_on_error",
            default=False,
        )
        parser.add_argument(
            "--kill-on-exit",
            help="kill the spawned program when Frida exits",
            action="store_true",
            dest="kill_on_exit",
            default=False,
        )
        parser.add_argument(
            "--auto-perform",
            help="wrap entered code with Java.perform",
            action="store_true",
            dest="autoperform",
            default=False,
        )
        parser.add_argument(
            "--auto-reload",
            help="Enable auto reload of provided scripts and c module (on by default, will be required in the future)",
            action="store_true",
            dest="autoreload",
            default=True,
        )
        parser.add_argument(
            "--no-auto-reload",
            help="Disable auto reload of provided scripts and c module",
            action="store_false",
            dest="autoreload",
            default=True,
        )

    def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
        self._user_scripts = list(map(os.path.abspath, options.user_scripts))
        for user_script in self._user_scripts:
            with open(user_script, "r"):
                pass

        if options.user_parameters is not None:
            try:
                params = json.loads(options.user_parameters)
            except Exception as e:
                raise ValueError(f"failed to parse parameters argument as JSON: {e}")
            if not isinstance(params, dict):
                raise ValueError("failed to parse parameters argument as JSON: not an object")
            self._user_parameters = params
        else:
            self._user_parameters = {}

        if options.user_cmodule is not None:
            self._user_cmodule = os.path.abspath(options.user_cmodule)
            with open(self._user_cmodule, "rb"):
                pass
        else:
            self._user_cmodule = None
        self._toolchain = options.toolchain

        self._codeshare_uri = options.codeshare_uri
        self._codeshare_script: Optional[str] = None

        self._pending_eval = options.eval_items

        self._quiet = options.quiet
        self._quiet_timeout = float(options.timeout)
        self._on_spawn_complete = options.on_spawn_complete
        self._eternalize = options.eternalize
        self._exit_on_error = options.exit_on_error
        self._kill_on_exit = options.kill_on_exit
        self._autoperform_option = options.autoperform
        self._autoreload = options.autoreload

        self._logfile: Optional[codecs.StreamReaderWriter] = None
        if options.logfile is not None:
            self._logfile = codecs.open(options.logfile, "w", "utf-8")

    def _log(self, level: str, text: str) -> None:
        ConsoleApplication._log(self, level, text)
        if self._logfile is not None:
            self._logfile.write(text + "\n")

    def _usage(self) -> str:
        return "%(prog)s [options] target"

    def _needs_target(self) -> bool:
        return True

    def _start(self) -> None:
        self._set_autoperform(self._autoperform_option)
        self._refresh_prompt()

        if self._codeshare_uri is not None:
            self._codeshare_script = self._load_codeshare_script(self._codeshare_uri)
            if self._codeshare_script is None:
                self._print("Exiting!")
                self._exit(1)
                return

        try:
            self._load_script()
        except Exception as e:
            self._update_status(f"Failed to load script: {e}")
            self._exit(1)
            return

        if self._spawned_argv is not None or self._selected_spawn is not None:
            command = (
                " ".join(self._spawned_argv) if self._spawned_argv is not None else self._selected_spawn.identifier
            )
            if self._on_spawn_complete == "resume":
                self._update_status(f"Spawned `{command}`. Resuming main thread!")
                self._do_magic("resume")
            else:
                self._update_status(
                    "Spawned `{command}`. Use %resume to let the main thread start executing!".format(command=command)
                )
        else:
            self._clear_status()
        self._ready.set()

    def _on_stop(self) -> None:
        self._stopping.set()

        if self._cli is not None:
            try:
                self._cli.app.exit()
            except:
                pass

    def _stop(self) -> None:
        if self._eternalize:
            self._eternalize_script()
        else:
            self._unload_script()

        with frida.Cancellable():
            self._demonitor_all()

        if self._logfile is not None:
            self._logfile.close()

        if self._kill_on_exit and self._spawned_pid is not None:
            if self._session is not None:
                self._session.detach()
            self._device.kill(self._spawned_pid)

        if not self._quiet:
            self._print("\nThank you for using Frida!")

    def _load_script(self) -> None:
        if self._autoreload:
            self._monitor_all()

        is_first_load = self._script is None

        assert self._session is not None
        script = self._session.create_script(name="repl", source=self._create_repl_script(), runtime=self._runtime)
        script.set_log_handler(self._log)
        self._unload_script()
        self._script = script

        def on_message(message: Mapping[Any, Any], data: Any) -> None:
            self._reactor.schedule(lambda: self._process_message(message, data))

        script.on("message", on_message)
        self._on_script_created(script)
        script.load()

        cmodule_code = self._load_cmodule_code()
        if cmodule_code is not None:
            # TODO: Remove this hack once RPC implementation supports passing binary data in both directions.
            if isinstance(cmodule_code, bytes):
                script.post({"type": "frida:cmodule-payload"}, data=cmodule_code)
                cmodule_code = None
            script.exports_sync.frida_load_cmodule(cmodule_code, self._toolchain)

        stage = "early" if self._target[0] == "file" and is_first_load else "late"
        try:
            script.exports_sync.init(stage, self._user_parameters)
        except:
            pass

    def _get_script_name(self, path: str) -> str:
        return os.path.splitext(os.path.basename(path))[0]

    def _eternalize_script(self) -> None:
        if self._script is None:
            return

        try:
            self._script.eternalize()
        except:
            pass
        self._script = None

    def _unload_script(self) -> None:
        if self._script is None:
            return

        try:
            self._script.unload()
        except:
            pass
        self._script = None

    def _monitor_all(self) -> None:
        for path in self._user_scripts + [self._user_cmodule]:
            self._monitor(path)

    def _demonitor_all(self) -> None:
        for monitor in self._monitored_files.values():
            monitor.disable()
        self._monitored_files = {}

    def _monitor(self, path: AnyStr) -> None:
        if path is None or path in self._monitored_files or script_needs_compilation(path):
            return

        monitor = frida.FileMonitor(path)
        monitor.on("change", self._on_change)
        monitor.enable()
        self._monitored_files[path] = monitor

    def _process_input(self, reactor: Reactor) -> None:
        if not self._quiet:
            self._print_startup_message()

        try:
            while self._ready.wait(0.5) != True:
                if not reactor.is_running():
                    return
        except KeyboardInterrupt:
            self._reactor.cancel_io()
            return

        while True:
            expression = ""
            line = ""
            while len(expression) == 0 or line.endswith("\\"):
                if not reactor.is_running():
                    return

                prompt = f"[{self._prompt_string}]" + "-> " if len(expression) == 0 else "... "

                pending_eval = self._pending_eval
                if pending_eval is not None:
                    if len(pending_eval) > 0:
                        expression = pending_eval.pop(0)
                        if not self._quiet:
                            self._print(prompt + expression)
                    else:
                        self._pending_eval = None
                else:
                    if self._quiet:
                        if self._quiet_timeout > 0:
                            if self._quiet_start is None:
                                self._quiet_start = time.time()
                            passed_time = time.time() - self._quiet_start
                            while self._quiet_timeout > passed_time and reactor.is_running():
                                sleep_time = min(1, self._quiet_timeout - passed_time)
                                if self._stopping.wait(sleep_time):
                                    break
                                if self._dumb_stdin_reader is not None:
                                    with self._dumb_stdin_reader._lock:
                                        if self._dumb_stdin_reader._saw_sigint:
                                            break
                                passed_time = time.time() - self._quiet_start

                        self._exit_status = 0 if self._errors == 0 else 1
                        return

                    try:
                        if self._cli is not None:
                            line = self._cli.prompt(prompt)
                            if line is None:
                                return
                        else:
                            assert self._dumb_stdin_reader is not None
                            line = self._dumb_stdin_reader.read_line(prompt)
                            self._print(line)
                    except EOFError:
                        if not self._have_terminal and os.environ.get("TERM", "") != "dumb":
                            while not self._stopping.wait(1):
                                pass
                        return
                    except KeyboardInterrupt:
                        line = ""
                        if not self._have_terminal:
                            sys.stdout.write("\n" + prompt)
                        continue
                    if len(line.strip()) > 0:
                        if len(expression) > 0:
                            expression += "\n"
                        expression += line.rstrip("\\")

            if expression.endswith("?"):
                try:
                    self._print_help(expression)
                except JavaScriptError as e:
                    error = e.error
                    self._print(Style.BRIGHT + error["name"] + Style.RESET_ALL + ": " + error["message"])
                except frida.InvalidOperationError:
                    return
            elif expression == "help":
                self._do_magic("help")
            elif expression in ("exit", "quit", "q"):
                return
            else:
                try:
                    if expression.startswith("%"):
                        self._do_magic(expression[1:].rstrip())
                    elif expression.startswith("."):
                        self._do_quick_command(expression[1:].rstrip())
                    else:
                        if self._autoperform:
                            expression = f"Java.performNow(() => {{ return {expression}\n/**/ }});"
                        if not self._exec_and_print(self._evaluate_expression, expression):
                            self._errors += 1
                except frida.OperationCancelledError:
                    return

    def _get_confirmation(self, question: str, default_answer: bool = False) -> bool:
        if default_answer:
            prompt_string = question + " [Y/n] "
        else:
            prompt_string = question + " [y/N] "

        if self._have_terminal and not self._plain_terminal:
            answer = prompt(prompt_string)
        else:
            answer = self._dumb_stdin_reader.read_line(prompt_string)
            self._print(answer)

        if answer.lower() not in ("y", "yes", "n", "no", ""):
            return self._get_confirmation(question, default_answer=default_answer)

        if default_answer:
            return answer.lower() != "n" and answer.lower() != "no"

        return answer.lower() == "y" or answer.lower() == "yes"

    def _exec_and_print(self, exec: Callable[[T], Tuple[str, bytes]], arg: T) -> bool:
        success = False
        try:
            (t, value) = self._perform_on_reactor_thread(lambda: exec(arg))
            if t in ("function", "undefined", "null"):
                output = t
            elif t == "binary":
                output = hexdump(value).rstrip("\n")
            else:
                output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
            success = True
        except JavaScriptError as e:
            error = e.error

            output = Fore.RED + Style.BRIGHT + error["name"] + Style.RESET_ALL + ": " + error["message"]

            stack = error.get("stack", None)
            if stack is not None:
                message_len = len(error["message"].split("\n"))
                trim_amount = 6 if self._runtime == "v8" else 7
                trimmed_stack = stack.split("\n")[message_len:-trim_amount]
                if len(trimmed_stack) > 0:
                    output += "\n" + "\n".join(trimmed_stack)
        except frida.InvalidOperationError:
            return success
        if output != "undefined":
            self._print(output)
        return success

    def _print_startup_message(self) -> None:
        self._print(
            """\
     ____
    / _  |   Frida {version} - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/""".format(
                version=frida.__version__
            )
        )

    def _print_help(self, expression: str) -> None:
        # TODO: Figure out docstrings and implement here. This is real jankaty right now.
        help_text = ""
        if expression.endswith(".?"):
            expression = expression[:-2] + "?"

        obj_to_identify = [x for x in expression.split(" ") if x.endswith("?")][0][:-1]
        (obj_type, obj_value) = self._evaluate_expression(obj_to_identify)

        if obj_type == "function":
            signature = self._evaluate_expression("%s.toString()" % obj_to_identify)[1].decode()
            clean_signature = signature.split("{")[0][:-1].split("function ")[-1]

            if "[native code]" in signature:
                help_text += "Type:      Function (native)\n"
            else:
                help_text += "Type:      Function\n"

            help_text += f"Signature: {clean_signature}\n"
            help_text += "Docstring: #TODO :)"

        elif obj_type == "object":
            help_text += "Type:      Object\n"
            help_text += "Docstring: #TODO :)"

        elif obj_type == "boolean":
            help_text += "Type:      Boolean\n"
            help_text += "Docstring: #TODO :)"

        elif obj_type == "string":
            bool_text = self._evaluate_expression(obj_to_identify + ".toString()")[1]
            help_text += "Type:      Boolean\n"
            help_text += f"Text:      {bool_text.decode()}\n"
            help_text += "Docstring: #TODO :)"

        self._print(help_text)

    # Negative means at least abs(val) - 1
    _magic_command_args = {
        "resume": _repl_magic.Resume(),
        "load": _repl_magic.Load(),
        "reload": _repl_magic.Reload(),
        "unload": _repl_magic.Unload(),
        "autoperform": _repl_magic.Autoperform(),
        "autoreload": _repl_magic.Autoreload(),
        "exec": _repl_magic.Exec(),
        "time": _repl_magic.Time(),
        "help": _repl_magic.Help(),
    }

    def _do_magic(self, statement: str) -> None:
        tokens = shlex.split(statement)
        command = tokens[0]
        args = tokens[1:]

        magic_command = self._magic_command_args.get(command)
        if magic_command is None:
            self._print(f"Unknown command: {command}")
            self._print("Valid commands: {}".format(", ".join(self._magic_command_args.keys())))
            return

        required_args = magic_command.required_args_count
        atleast_args = False
        if required_args < 0:
            atleast_args = True
            required_args = abs(required_args) - 1

        if (not atleast_args and len(args) != required_args) or (atleast_args and len(args) < required_args):
            self._print(
                "{cmd} command expects {atleast}{n} argument{s}".format(
                    cmd=command,
                    atleast="atleast " if atleast_args else "",
                    n=required_args,
                    s="" if required_args == 1 else " ",
                )
            )
            return

        magic_command.execute(self, args)

    def _do_quick_command(self, statement: str) -> None:
        tokens = shlex.split(statement)
        if len(tokens) == 0:
            self._print("Invalid quick command")
            return

        if not self._exec_and_print(self._evaluate_quick_command, tokens):
            self._errors += 1

    def _autoperform_command(self, state_argument: str) -> None:
        if state_argument not in ("on", "off"):
            self._print("autoperform only accepts on and off as parameters")
            return
        self._set_autoperform(state_argument == "on")

    def _set_autoperform(self, state: bool) -> None:
        if self._is_java_available():
            self._autoperform = state
            self._refresh_prompt()
        elif state:
            self._print("autoperform is only available in Java processes")

    def _is_java_available(self) -> bool:
        assert self._session is not None
        script = None
        try:
            script = self._session.create_script(
                name="java_check", source="rpc.exports.javaAvailable = () => Java.available;", runtime=self._runtime
            )
            script.load()
            return script.exports_sync.java_available()
        except:
            return False
        finally:
            if script is not None:
                script.unload()

    def _refresh_prompt(self) -> None:
        self._prompt_string = self._create_prompt()

    def _create_prompt(self) -> str:
        assert self._device is not None
        device_type = self._device.type
        type_name = self._target[0]
        if type_name == "pid":
            if self._target[1] == 0:
                target = "SystemSession"
            else:
                target = "PID::%u" % self._target[1]
        elif type_name == "file":
            target = os.path.basename(self._target[1][0])
        else:
            target = self._target[1]

        suffix = ""
        if self._autoperform:
            suffix = "(ap)"

        if device_type in ("local", "remote"):
            prompt_string = "%s::%s %s" % (device_type.title(), target, suffix)
        else:
            prompt_string = "%s::%s %s" % (self._device.name, target, suffix)

        return prompt_string

    def _evaluate_expression(self, expression: str) -> Tuple[str, bytes]:
        assert self._script is not None
        result = self._script.exports_sync.frida_evaluate_expression(expression)
        return self._parse_evaluate_result(result)

    def _evaluate_quick_command(self, tokens: List[str]) -> Tuple[str, bytes]:
        assert self._script is not None
        result = self._script.exports_sync.frida_evaluate_quick_command(tokens)
        return self._parse_evaluate_result(result)

    def _parse_evaluate_result(self, result: Union[bytes, Mapping[Any, Any], Tuple[str, bytes]]) -> Tuple[str, bytes]:
        if isinstance(result, bytes):
            return ("binary", result)
        elif isinstance(result, dict):
            return ("binary", bytes())
        elif result[0] == "error":
            raise JavaScriptError(result[1])
        return (result[0], result[1])

    def _process_message(self, message: Mapping[Any, Any], data: Any) -> None:
        message_type = message["type"]
        if message_type == "error":
            text = message.get("stack", message["description"])
            self._log("error", text)
            self._errors += 1
            if self._exit_on_error:
                self._exit(1)
        else:
            self._print("message:", message, "data:", data)

    def _on_change(self, changed_file, other_file, event_type) -> None:
        if event_type == "changes-done-hint":
            return
        self._last_change_id += 1
        change_id = self._last_change_id
        self._reactor.schedule(lambda: self._process_change(change_id), delay=0.05)

    def _process_change(self, change_id: int) -> None:
        if change_id != self._last_change_id:
            return
        self._try_load_script()

    def _try_load_script(self) -> None:
        try:
            self._load_script()
        except Exception as e:
            self._print(f"Failed to load script: {e}")

    def _create_repl_script(self) -> str:
        raw_fragments = []

        raw_fragments.append(self._make_repl_runtime())

        if self._codeshare_script is not None:
            raw_fragments.append(
                self._wrap_user_script(f"/codeshare.frida.re/{self._codeshare_uri}.js", self._codeshare_script)
            )

        for user_script in self._user_scripts:
            if script_needs_compilation(user_script):
                compilation_started = None

                context = self._compilers.get(user_script, None)
                if context is None:
                    context = CompilerContext(user_script, self._autoreload, self._on_bundle_updated)
                    context.compiler.on("diagnostics", self._on_compiler_diagnostics)
                    self._compilers[user_script] = context
                    self._update_status(format_compiling(user_script, os.getcwd()))
                    compilation_started = timer()

                raw_fragments.append(context.get_bundle())

                if compilation_started is not None:
                    compilation_finished = timer()
                    self._update_status(
                        format_compiled(user_script, os.getcwd(), compilation_started, compilation_finished)
                    )
            else:
                with codecs.open(user_script, "rb", "utf-8") as f:
                    raw_fragments.append(self._wrap_user_script(user_script, f.read()))

        fragments = []
        next_script_id = 1
        for raw_fragment in raw_fragments:
            if raw_fragment.startswith("📦\n"):
                fragments.append(raw_fragment[2:])
            else:
                script_id = next_script_id
                next_script_id += 1
                size = len(raw_fragment.encode("utf-8"))
                fragments.append(f"{size} /frida/repl-{script_id}.js\n✄\n{raw_fragment}")

        return "📦\n" + "\n✄\n".join(fragments)

    def _wrap_user_script(self, name, script):
        if script.startswith("📦\n"):
            return script
        return f"Script.evaluate({json.dumps(name)}, {json.dumps(script)});"

    def _on_bundle_updated(self) -> None:
        self._reactor.schedule(lambda: self._try_load_script())

    def _on_compiler_diagnostics(self, diagnostics) -> None:
        self._reactor.schedule(lambda: self._print_compiler_diagnostics(diagnostics))

    def _print_compiler_diagnostics(self, diagnostics) -> None:
        cwd = os.getcwd()
        for diag in diagnostics:
            self._print(format_diagnostic(diag, cwd))

    def _make_repl_runtime(self) -> str:
        return """\
global.cm = null;
global.cs = {};

class REPL {
#quickCommands;
constructor() {
    this.#quickCommands = new Map();
}
registerQuickCommand(name, handler) {
    this.#quickCommands.set(name, handler);
}
unregisterQuickCommand(name) {
    this.#quickCommands.delete(name);
}
_invokeQuickCommand(tokens) {
    const name = tokens[0];
    const handler = this.#quickCommands.get(name);
    if (handler !== undefined) {
        const { minArity, onInvoke } = handler;
        if (tokens.length - 1 < minArity) {
            throw Error(`${name} needs at least ${minArity} arg${(minArity === 1) ? '' : 's'}`);
        }
        return onInvoke(...tokens.slice(1));
    } else {
        throw Error(`Unknown command ${name}`);
    }
}
}
const repl = new REPL();
global.REPL = repl;

const rpcExports = {
fridaEvaluateExpression(expression) {
    return evaluate(() => (1, eval)(expression));
},
fridaEvaluateQuickCommand(tokens) {
    return evaluate(() => repl._invokeQuickCommand(tokens));
},
fridaLoadCmodule(code, toolchain) {
    const cs = global.cs;

    if (cs._frida_log === undefined)
        cs._frida_log = new NativeCallback(onLog, 'void', ['pointer']);

    if (code === null) {
        recv('frida:cmodule-payload', (message, data) => {
            code = data;
        });
    }

    global.cm = new CModule(code, cs, { toolchain });
},
};

function evaluate(func) {
try {
    const result = func();
    if (result instanceof ArrayBuffer) {
        return result;
    } else {
        const type = (result === null) ? 'null' : typeof result;
        return [type, result];
    }
} catch (e) {
    return ['error', {
        name: e.name,
        message: e.message,
        stack: e.stack
    }];
}
}

Object.defineProperty(rpc, 'exports', {
    get() {
        return rpcExports;
    },
    set(value) {
        for (const [k, v] of Object.entries(value)) {
            rpcExports[k] = v;
        }
    }
});

function onLog(messagePtr) {
    const message = messagePtr.readUtf8String();
    console.log(message);
}
"""

    def _load_cmodule_code(self) -> Union[str, bytes, None]:
        if self._user_cmodule is None:
            return None

        with open(self._user_cmodule, "rb") as f:
            code = f.read()
        if code_is_native(code):
            return code
        source = code.decode("utf-8")

        name = os.path.basename(self._user_cmodule)

        return (
            """static void frida_log (const char * format, ...);\n#line 1 "{name}"\n""".format(name=name)
            + source
            + """\
#line 1 "frida-repl-builtins.c"
#include <glib.h>

extern void _frida_log (const gchar * message);

static void
frida_log (const char * format,
           ...)
{
  gchar * message;
  va_list args;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  _frida_log (message);

  g_free (message);
}
"""
        )

    def _load_codeshare_script(self, uri: str) -> Optional[str]:
        trust_store = self._get_or_create_truststore()

        project_url = f"https://codeshare.frida.re/api/project/{uri}/"
        response_json = None
        try:
            request = build_opener()
            request.addheaders = [("User-Agent", f"Frida v{frida.__version__} | {platform.platform()}")]
            response = request.open(project_url)
            response_content = response.read().decode("utf-8")
            response_json = json.loads(response_content)
        except Exception as e:
            self._print(f"Got an unhandled exception while trying to
"""


```