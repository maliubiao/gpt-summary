Response:
The user wants a summary of the Python code provided. I need to identify the core functionalities of the `tracer.py` file, explain its relationship to reverse engineering, its interaction with low-level systems, any logical deductions made, potential user errors, and how a user might reach this code in a debugging scenario.

Here's a breakdown of my thought process:

1. **Identify the main class:** The core of the functionality appears to reside within the `TracerApplication` class, which inherits from `ConsoleApplication` and a custom `UI` class. This suggests it's a command-line tool with a user interface aspect.

2. **Analyze the command-line arguments:** The `_add_options` method reveals the tool's primary purpose: tracing function calls. Arguments like `--include`, `--exclude`, `--include-module`, etc., clearly point towards filtering and selecting functions for tracing. This directly relates to dynamic analysis in reverse engineering.

3. **Examine the core workflow:** The `_start` method initializes a `Tracer` object and calls `start_trace`. The `Tracer` class seems responsible for interacting with Frida's core API to inject instrumentation logic.

4. **Trace the event handling:** Methods like `on_trace_progress`, `on_trace_events`, `on_trace_handler_create`, and `on_trace_handler_load` indicate that the tool receives events from the traced process. The `on_trace_events` method specifically handles the formatted output of trace data.

5. **Recognize the UI component:** The presence of `websockets` and methods like `_run_ui_server`, `_handle_websocket_connection`, and `_handle_asset_request` clearly indicate a web-based user interface. This allows users to interact with the tracer beyond the command line.

6. **Identify interactions with Frida:** The code imports `frida` and uses its API for session management (`frida.core.Session`), script creation (`script = session.create_script`), and message passing (`script.on("message", ...)`).

7. **Look for low-level interactions:**  The `--add` option, which takes a "MODULE!OFFSET", suggests direct interaction with memory addresses. The `_on_memory_read` method further confirms this.

8. **Consider the configuration:** The `TracerProfileBuilder` and `TracerProfile` classes handle the configuration of which functions to trace, which is a crucial aspect of controlling the tracing process.

9. **Pinpoint potential user errors:** Incorrectly formatted command-line arguments (e.g., invalid module or function names) or issues with the initialization scripts are likely sources of user errors.

10. **Describe the user journey:** A user would typically start the `frida-tracer` command with specific options targeting a process or application. The tool would then inject a script and start reporting trace events. The web UI provides an alternative way to manage and view these events.

11. **Structure the summary:** Organize the findings into functional categories (Tracing, Reverse Engineering Relation, Low-Level Aspects, Logical Inference, User Errors, Debugging Journey) for clarity.

12. **Refine the language:**  Ensure the explanation is clear, concise, and uses appropriate technical terminology. For example, instead of saying "it watches functions," use "tracing function calls."

By following this thought process, I can systematically analyze the code and generate a comprehensive summary of its functionality, addressing all the user's requirements.
好的，让我们来分析一下 `frida/subprojects/frida-tools/frida_tools/tracer.py` 文件的源代码，并归纳其功能。

**功能归纳（第 1 部分）**

这个 Python 文件定义了一个名为 `frida-tracer` 的 Frida 动态插桩工具。它的主要功能是**跟踪目标进程或应用程序中指定函数的执行情况**。  具体来说，它可以：

1. **配置跟踪目标：**
   - **包含/排除模块：** 允许用户指定要跟踪或忽略的特定模块（例如动态链接库 `.so` 文件，或 Windows 的 `.dll` 文件）。
   - **包含/排除函数：**  允许用户指定要跟踪或忽略的特定函数，可以指定模块名和函数名（例如 `libc!open`）。
   - **按偏移地址添加跟踪点：** 允许用户在指定模块的特定偏移地址处设置跟踪点。
   - **包含模块导入的函数：** 自动包含目标程序或指定模块导入的函数。
   - **包含/排除特定类型的函数：**  支持 Objective-C 方法、Swift 函数和 Java 方法的包含和排除。
   - **包含调试符号：**  允许根据调试符号名称包含函数。

2. **自定义跟踪行为：**
   - **静默模式：**  可以选择不格式化输出消息，只显示原始跟踪信息。
   - **装饰输出：**  可以在 `onEnter` 日志语句中添加模块名，方便识别函数来源。
   - **初始化脚本：**  允许用户指定 JavaScript 文件来初始化 Frida 会话，执行自定义操作。
   - **传递参数：**  允许用户以 JSON 格式传递参数到 Frida 脚本中。
   - **输出到文件：**  可以将跟踪消息输出到指定的文件中。

3. **提供 Web 用户界面：**
   -  内置了一个 Web 服务器，允许用户通过浏览器与 `frida-tracer` 交互。
   -  Web UI 可以用于查看和管理跟踪目标、配置跟踪选项，以及实时查看跟踪事件。

4. **处理跟踪事件：**
   -  接收并处理来自 Frida Agent (注入到目标进程中的 JavaScript 代码) 发送的跟踪事件。
   -  格式化并输出跟踪信息，包括时间戳、线程 ID、调用深度、调用者信息、回溯信息和自定义消息。

5. **自动生成和加载处理程序 (Handlers)：**
   -  对于每个被跟踪的目标（函数或地址），`frida-tracer` 可以自动生成一个 JavaScript 处理程序文件。
   -  用户可以修改这些处理程序文件，自定义在函数入口 (`onEnter`) 和/或出口 (`onLeave`) 时执行的操作，例如记录参数、修改返回值等。

6. **管理处理程序代码：**
   -  提供加载、保存和配置处理程序的功能，方便用户修改和管理跟踪逻辑。

7. **内存操作：**
   -  允许用户读取目标进程的内存。

8. **符号解析：**
   -  允许用户解析内存地址对应的符号名称。

**与逆向方法的关系及举例说明：**

`frida-tracer` 是一个强大的动态逆向工具。它通过动态地监控目标程序的执行流程，帮助逆向工程师理解程序的行为、查找漏洞、分析恶意代码等。

* **函数调用跟踪：**  这是最核心的逆向方法之一。通过跟踪关键函数的调用，逆向工程师可以了解程序的执行路径、数据流向以及组件之间的交互。
    * **举例：** 逆向一个恶意软件，可以使用 `-i "kernel32!CreateFileW"` 来跟踪文件创建操作，从而了解恶意软件可能创建哪些文件，用于什么目的。
    * **举例：** 逆向一个加密算法的实现，可以跟踪加密函数（例如 `-i "libcrypto!AES_encrypt"`）的参数和返回值，从而分析其加密逻辑。

* **参数和返回值分析：** 通过修改自动生成的处理程序，逆向工程师可以查看被跟踪函数的参数和返回值，这对于理解函数的功能至关重要。
    * **举例：**  跟踪网络通信函数 `socket`，可以在处理程序的 `onEnter` 中记录其参数，如协议类型、地址族等，从而了解程序的网络行为。
    * **举例：** 跟踪解密函数，可以在处理程序的 `onLeave` 中查看其返回值，即解密后的数据。

* **控制流分析：** 通过观察函数调用的顺序和条件，逆向工程师可以分析程序的控制流程。
    * **举例：**  跟踪多个关键函数，观察它们的调用顺序，可以了解程序的功能模块和执行逻辑。

* **漏洞挖掘：** 通过跟踪敏感函数（例如处理用户输入的函数），可以发现潜在的漏洞，如缓冲区溢出等。
    * **举例：** 跟踪字符串处理函数 `strcpy`，观察其参数，如果发现源字符串长度不受控制，可能存在缓冲区溢出漏洞。

* **动态调试辅助：** `frida-tracer` 可以作为动态调试器（如 gdb 或 lldb）的补充，提供更高级的跟踪和监控功能。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

`frida-tracer` 的工作原理和功能涉及到多个底层的知识领域：

* **二进制底层：**
    * **指令跟踪：** 使用 `-a` 选项按偏移地址跟踪，直接操作二进制代码的地址。
    * **内存读取：** `_on_memory_read` 方法直接读取进程的内存，需要理解内存布局、地址空间等概念.
    * **符号解析：** 将内存地址映射到函数名，需要理解程序的符号表和链接过程。

* **Linux 内核：**
    * **模块（.so 文件）：** 通过 `-I` 和 `-X` 选项操作 Linux 的动态链接库，需要理解 Linux 的共享库机制。
    * **进程和线程：** 跟踪不同线程的执行，涉及到 Linux 的进程和线程管理。

* **Android 内核及框架：**
    * **Java 方法跟踪：** 使用 `-j` 和 `-J` 选项跟踪 Android 应用的 Java 代码，需要理解 Android 的 Dalvik/ART 虚拟机和 Java Native Interface (JNI)。
    * **Objective-C 方法跟踪：** 使用 `-m` 和 `-M` 选项跟踪 iOS/macOS 应用的 Objective-C 代码，需要理解 Objective-C 的消息传递机制。
    * **Swift 函数跟踪：** 使用 `-y` 和 `-Y` 选项跟踪 iOS/macOS 应用的 Swift 代码，需要理解 Swift 的命名空间和函数调用约定。

* **Frida 的工作原理：**  `frida-tracer` 是基于 Frida 框架构建的，需要理解 Frida 如何注入代码到目标进程、拦截函数调用、发送和接收消息等。

**逻辑推理及假设输入与输出：**

`frida-tracer` 本身做了很多逻辑推理来确定要跟踪的目标，例如：

* **通配符匹配：** 在使用 `-i` 或 `-I` 等选项时，可以使用通配符 `*` 来匹配多个函数或模块名。
    * **假设输入：**  `frida-tracer -i "libc!str*"`  target_process
    * **逻辑推理：**  `frida-tracer` 会查找 `libc` 模块中所有以 "str" 开头的函数，例如 `strcpy`, `strlen`, `strcmp` 等。
    * **预期输出：** 将会跟踪 `libc` 模块中匹配到的所有 "str" 开头的函数。

* **模块名和函数名解析：**  当使用 `MODULE!FUNCTION` 格式指定跟踪目标时，`frida-tracer` 需要解析模块名和函数名。
    * **假设输入：** `frida-tracer -i "my_library.so!my_function"` target_process
    * **逻辑推理：** `frida-tracer` 会尝试找到名为 `my_library.so` 的模块，并在该模块中查找名为 `my_function` 的函数。
    * **预期输出：** 如果找到该函数，将会跟踪该函数的调用。如果找不到，可能会输出警告或错误信息。

* **导入函数跟踪：**  使用 `-T` 或 `-t` 选项时，需要分析目标程序或模块的导入表。
    * **假设输入：** `frida-tracer -T` target_process
    * **逻辑推理：** `frida-tracer` 会解析 `target_process` 的可执行文件，读取其导入表，列出所有被导入的函数。
    * **预期输出：** 将会跟踪目标进程导入的所有函数。

**涉及用户或编程常见的使用错误及举例说明：**

* **拼写错误：**  在指定模块名或函数名时，如果存在拼写错误，`frida-tracer` 将无法找到目标。
    * **举例：** `frida-tracer -i "libct!open"` (正确的是 `libc!open`)
    * **错误信息：** `frida-tracer` 可能会报告找不到该函数。

* **模块名不正确：**  指定的模块名与实际加载的模块名不符。
    * **举例：** 在 Android 上，系统库可能不是简单的 "libc.so"，而是带有版本号或其他后缀。
    * **错误信息：** `frida-tracer` 可能会报告找不到该模块。

* **函数签名不匹配：**  虽然 `frida-tracer` 会生成默认的处理程序，但用户修改处理程序时，可能会导致代码错误，例如参数类型不匹配。
    * **举例：**  修改处理程序时，假设被跟踪函数的第一个参数是整数，但处理程序中将其作为字符串处理。
    * **错误信息：** Frida Agent 可能会抛出 JavaScript 异常。

* **参数 JSON 格式错误：**  使用 `-P` 选项传递参数时，如果 JSON 格式不正确，会导致解析失败。
    * **举例：** `frida-tracer -P "{invalid json}"` target_process
    * **错误信息：** `frida-tracer` 会报告无法解析 JSON 参数。

* **Web UI 端口冲突：**  如果指定的 Web UI 端口已被其他程序占用。
    * **错误信息：** `frida-tracer` 可能会无法启动 Web 服务器。

**用户操作是如何一步步到达这里的，作为调试线索：**

一个用户想要使用 `frida-tracer` 来调试程序，可能会执行以下步骤：

1. **安装 Frida 和 frida-tools：**  这是使用 `frida-tracer` 的前提。
2. **确定目标进程或应用程序：**  用户需要知道要跟踪哪个进程或启动哪个应用程序。
3. **使用 `frida-tracer` 命令：**  用户在终端输入 `frida-tracer` 命令，并带上相应的选项和目标。
    * 例如：`frida-tracer -i "main"` my_program
    * 例如：`frida-tracer -I "com.example.app"` com.example.app
4. **`TracerApplication` 初始化：**  `main()` 函数创建 `TracerApplication` 实例。
5. **解析命令行参数：**  `_add_options` 和 `_initialize` 方法解析用户提供的命令行参数，构建 `TracerProfile` 对象。
6. **连接到 Frida 会话：**  `ConsoleApplication` 基类负责连接到 Frida 会话，如果目标是正在运行的进程，则附加到该进程；如果目标是启动新的进程，则 spawn 该进程。
7. **启动跟踪：** `_start` 方法创建 `Tracer` 实例，加载 Frida Agent (JavaScript 代码) 到目标进程。
8. **Frida Agent 工作：**  Frida Agent 根据 `TracerProfile` 的配置，在目标进程中设置 hook 点，当被跟踪的函数被调用时，会收集信息并通过消息发送回 `frida-tracer`。
9. **处理跟踪事件：** `TracerApplication` 的 `on_trace_events` 方法接收并格式化来自 Frida Agent 的跟踪事件，并输出到终端或文件。
10. **Web UI 交互 (可选)：** 如果用户使用了 `--ui-port` 选项，则可以通过浏览器访问 Web UI，查看和管理跟踪配置。
11. **修改处理程序 (可选)：** 用户可以在生成的处理程序文件中修改 JavaScript 代码，自定义跟踪逻辑。

作为调试线索，如果用户在使用 `frida-tracer` 时遇到问题，可以检查以下方面：

* **命令行参数是否正确？**  是否存在拼写错误、格式错误等。
* **目标进程或应用程序是否正确？**
* **Frida 版本是否匹配？**
* **是否有足够的权限来注入到目标进程？**
* **如果使用了 Web UI，端口是否被占用？**
* **如果修改了处理程序，JavaScript 代码是否存在错误？**

希望以上分析能够帮助你理解 `frida/subprojects/frida-tools/frida_tools/tracer.py` 文件的功能。接下来，请提供第二部分的内容，我将继续进行分析。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/frida_tools/tracer.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
from __future__ import annotations

import argparse
import asyncio
import binascii
import codecs
import email.utils
import gzip
import http
import mimetypes
import re
import shlex
import subprocess
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator, List, Optional, Set
from zipfile import ZipFile

import frida
import websockets.asyncio.server
import websockets.datastructures
import websockets.exceptions
import websockets.http11

from frida_tools.reactor import Reactor

MANPAGE_CONTROL_CHARS = re.compile(r"\.[a-zA-Z]*(\s|$)|\s?\"")
MANPAGE_FUNCTION_PROTOTYPE = re.compile(r"([a-zA-Z_]\w+)\(([^\)]+)")


def main() -> None:
    import json
    import traceback

    from colorama import Fore, Style

    from frida_tools.application import ConsoleApplication, await_ctrl_c

    class TracerApplication(ConsoleApplication, UI):
        def __init__(self) -> None:
            super().__init__(await_ctrl_c)
            self._handlers = OrderedDict()
            self._ui_zip = ZipFile(Path(__file__).parent / "tracer_ui.zip", "r")
            self._ui_socket_handlers: Set[UISocketHandler] = set()
            self._ui_worker = None
            self._asyncio_loop = None
            self._palette = ["cyan", "magenta", "yellow", "green", "red", "blue"]
            self._next_color = 0
            self._style_by_thread_id = {}
            self._last_event_tid = -1

        def _add_options(self, parser: argparse.ArgumentParser) -> None:
            pb = TracerProfileBuilder()
            parser.add_argument(
                "-I", "--include-module", help="include MODULE", metavar="MODULE", type=pb.include_modules
            )
            parser.add_argument(
                "-X", "--exclude-module", help="exclude MODULE", metavar="MODULE", type=pb.exclude_modules
            )
            parser.add_argument(
                "-i", "--include", help="include [MODULE!]FUNCTION", metavar="FUNCTION", type=pb.include
            )
            parser.add_argument(
                "-x", "--exclude", help="exclude [MODULE!]FUNCTION", metavar="FUNCTION", type=pb.exclude
            )
            parser.add_argument(
                "-a", "--add", help="add MODULE!OFFSET", metavar="MODULE!OFFSET", type=pb.include_relative_address
            )
            parser.add_argument("-T", "--include-imports", help="include program's imports", type=pb.include_imports)
            parser.add_argument(
                "-t",
                "--include-module-imports",
                help="include MODULE imports",
                metavar="MODULE",
                type=pb.include_imports,
            )
            parser.add_argument(
                "-m",
                "--include-objc-method",
                help="include OBJC_METHOD",
                metavar="OBJC_METHOD",
                type=pb.include_objc_method,
            )
            parser.add_argument(
                "-M",
                "--exclude-objc-method",
                help="exclude OBJC_METHOD",
                metavar="OBJC_METHOD",
                type=pb.exclude_objc_method,
            )
            parser.add_argument(
                "-y",
                "--include-swift-func",
                help="include SWIFT_FUNC",
                metavar="SWIFT_FUNC",
                type=pb.include_swift_func,
            )
            parser.add_argument(
                "-Y",
                "--exclude-swift-func",
                help="exclude SWIFT_FUNC",
                metavar="SWIFT_FUNC",
                type=pb.exclude_swift_func,
            )
            parser.add_argument(
                "-j",
                "--include-java-method",
                help="include JAVA_METHOD",
                metavar="JAVA_METHOD",
                type=pb.include_java_method,
            )
            parser.add_argument(
                "-J",
                "--exclude-java-method",
                help="exclude JAVA_METHOD",
                metavar="JAVA_METHOD",
                type=pb.exclude_java_method,
            )
            parser.add_argument(
                "-s",
                "--include-debug-symbol",
                help="include DEBUG_SYMBOL",
                metavar="DEBUG_SYMBOL",
                type=pb.include_debug_symbol,
            )
            parser.add_argument(
                "-q", "--quiet", help="do not format output messages", action="store_true", default=False
            )
            parser.add_argument(
                "-d",
                "--decorate",
                help="add module name to generated onEnter log statement",
                action="store_true",
                default=False,
            )
            parser.add_argument(
                "-S",
                "--init-session",
                help="path to JavaScript file used to initialize the session",
                metavar="PATH",
                action="append",
                default=[],
            )
            parser.add_argument(
                "-P",
                "--parameters",
                help="parameters as JSON, exposed as a global named 'parameters'",
                metavar="PARAMETERS_JSON",
            )
            parser.add_argument("-o", "--output", help="dump messages to file", metavar="OUTPUT")
            parser.add_argument("--ui-port", help="the TCP port to serve the UI on")
            self._profile_builder = pb

        def _usage(self) -> str:
            return "%(prog)s [options] target"

        def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
            self._repo: Optional[FileRepository] = None
            self._tracer: Optional[Tracer] = None
            self._profile = self._profile_builder.build()
            self._quiet: bool = options.quiet
            self._decorate: bool = options.decorate
            self._output: Optional[OutputFile] = None
            self._output_path: str = options.output
            self._ui_port: Optional[int] = options.ui_port

            self._init_scripts = []
            for path in options.init_session:
                with codecs.open(path, "rb", "utf-8") as f:
                    source = f.read()
                self._init_scripts.append(InitScript(path, source))

            if options.parameters is not None:
                try:
                    params = json.loads(options.parameters)
                except Exception as e:
                    raise ValueError(f"failed to parse parameters argument as JSON: {e}")
                if not isinstance(params, dict):
                    raise ValueError("failed to parse parameters argument as JSON: not an object")
                self._parameters = params
            else:
                self._parameters = {}

        def _needs_target(self) -> bool:
            return True

        def _start(self) -> None:
            if self._ui_worker is None:
                worker = threading.Thread(target=self._run_ui_server, name="ui-server", daemon=True)
                worker.start()
                self._ui_worker = worker

            if self._output_path is not None:
                self._output = OutputFile(self._output_path)

            stage = "early" if self._target[0] == "file" else "late"

            self._repo = FileRepository(self._reactor, self._decorate)
            self._tracer = Tracer(
                self._reactor,
                self._repo,
                self._profile,
                self._init_scripts,
                log_handler=self._log,
            )
            try:
                self._tracer.start_trace(self._session, stage, self._parameters, self._runtime, self)
            except Exception as e:
                self._update_status(f"Failed to start tracing: {e}")
                self._exit(1)
                return

        def _stop(self) -> None:
            self._tracer.stop()
            self._tracer = None
            if self._output is not None:
                self._output.close()
            self._output = None

            self._handlers.clear()
            self._next_color = 0
            self._style_by_thread_id.clear()
            self._last_event_tid = -1

        def on_script_created(self, script: frida.core.Script) -> None:
            self._on_script_created(script)

        def on_trace_progress(self, status: str, *params) -> None:
            if status == "initializing":
                self._update_status("Instrumenting...")
            elif status == "initialized":
                self._resume()
            elif status == "started":
                (count,) = params
                if count == 1:
                    plural = ""
                else:
                    plural = "s"
                self._update_status(
                    f"Started tracing {count} function{plural}. Web UI available at http://localhost:{self._ui_port}/"
                )

        def on_trace_warning(self, message: str) -> None:
            self._print(Fore.RED + Style.BRIGHT + "Warning" + Style.RESET_ALL + ": " + message)

        def on_trace_error(self, message: str) -> None:
            self._print(Fore.RED + Style.BRIGHT + "Error" + Style.RESET_ALL + ": " + message)
            self._exit(1)

        def on_trace_events(self, raw_events) -> None:
            events = [
                (target_id, timestamp, thread_id, depth, caller, backtrace, message, self._get_style(thread_id))
                for target_id, timestamp, thread_id, depth, caller, backtrace, message in raw_events
            ]
            self._asyncio_loop.call_soon_threadsafe(
                lambda: self._asyncio_loop.create_task(self._broadcast_trace_events(events))
            )

            no_attributes = Style.RESET_ALL
            for target_id, timestamp, thread_id, depth, caller, backtrace, message, style in events:
                if self._output is not None:
                    self._output.append(message + "\n")
                elif self._quiet:
                    self._print(message)
                else:
                    indent = depth * "   | "
                    attributes = getattr(Fore, style[0].upper())
                    if len(style) > 1:
                        attributes += getattr(Style, style[1].upper())
                    if thread_id != self._last_event_tid:
                        self._print("%s           /* TID 0x%x */%s" % (attributes, thread_id, Style.RESET_ALL))
                        self._last_event_tid = thread_id
                    self._print("%6d ms  %s%s%s%s" % (timestamp, attributes, indent, message, no_attributes))

        def on_trace_handler_create(self, target: TraceTarget, handler: str, source: Path) -> None:
            self._register_handler(target, source)
            if self._quiet:
                return
            self._print(f'{target}: Auto-generated handler at "{source}"')

        def on_trace_handler_load(self, target: TraceTarget, handler: str, source: Path) -> None:
            self._register_handler(target, source)
            if self._quiet:
                return
            self._print(f'{target}: Loaded handler at "{source}"')

        def _register_handler(self, target: TraceTarget, source: str) -> None:
            config = {"muted": False, "capture_backtraces": False}
            self._handlers[target.identifier] = (target, source, config)

        def _get_style(self, thread_id):
            style = self._style_by_thread_id.get(thread_id, None)
            if style is None:
                color = self._next_color
                self._next_color += 1
                style = [self._palette[color % len(self._palette)]]
                if (1 + int(color / len(self._palette))) % 2 == 0:
                    style.append("bright")
                self._style_by_thread_id[thread_id] = style
            return style

        def _run_ui_server(self):
            asyncio.run(self._handle_ui_requests())

        async def _handle_ui_requests(self):
            self._asyncio_loop = asyncio.get_running_loop()
            async with websockets.asyncio.server.serve(
                self._handle_websocket_connection,
                "localhost",
                self._ui_port,
                process_request=self._handle_asset_request,
            ) as server:
                self._ui_port = server.sockets[0].getsockname()[1]
                await asyncio.get_running_loop().create_future()

        async def _handle_websocket_connection(self, websocket: websockets.asyncio.server.ServerConnection):
            if self._tracer is None:
                return

            handler = UISocketHandler(self, websocket)
            self._ui_socket_handlers.add(handler)
            try:
                await handler.process_messages()
            except:
                traceback.print_exc()
                # pass
            finally:
                self._ui_socket_handlers.remove(handler)

        async def _broadcast_trace_events(self, events):
            for handler in self._ui_socket_handlers:
                await handler.post(
                    {
                        "type": "events:add",
                        "events": events,
                    }
                )

        def _handle_asset_request(
            self, connection: websockets.asyncio.server.ServerConnection, request: websockets.asyncio.server.Request
        ):
            origin = request.headers.get("Origin")
            if origin is not None and origin not in self._compute_allowed_ui_origins():
                self._print(
                    Fore.RED
                    + Style.BRIGHT
                    + "Warning"
                    + Style.RESET_ALL
                    + f": Cross-origin request from {origin} denied"
                )
                return connection.respond(http.HTTPStatus.FORBIDDEN, "Cross-origin request denied\n")

            connhdr = request.headers.get("Connection")
            if connhdr is not None:
                directives = [d.strip().lower() for d in connhdr.split(",")]
                if "upgrade" in directives:
                    return

            raw_path = request.path.split("?", maxsplit=1)[0]

            filename = raw_path[1:]
            if filename == "":
                filename = "index.html"

            try:
                body = self._ui_zip.read(filename)
            except KeyError:
                return connection.respond(http.HTTPStatus.NOT_FOUND, "File not found\n")

            status = http.HTTPStatus(http.HTTPStatus.OK)

            content_type, content_encoding = mimetypes.guess_type(filename)
            if content_type is None:
                content_type = "application/octet-stream"

            headers = websockets.datastructures.Headers(
                [
                    ("Connection", "close"),
                    ("Content-Length", str(len(body))),
                    ("Content-Type", content_type),
                    ("Date", email.utils.formatdate(usegmt=True)),
                ]
            )
            if content_encoding is not None:
                headers.update({"Content-Encoding": content_encoding})

            response = websockets.http11.Response(status.value, status.phrase, headers, body)
            connection.protocol.handshake_exc = websockets.exceptions.InvalidStatus(response)

            return response

        def _compute_allowed_ui_origins(self):
            return [f"http://localhost:{port}" for port in (self._ui_port, self._ui_port + 1)]

    class UISocketHandler:
        def __init__(self, app: TracerApplication, socket: websockets.asyncio.server.ServerConnection) -> None:
            self.app = app
            self.socket = socket

        async def process_messages(self) -> None:
            app = self.app

            await self.post(
                {
                    "type": "tracer:sync",
                    "spawned_program": app._spawned_argv[0] if app._spawned_argv is not None else None,
                    "process": app._tracer.process,
                    "handlers": [self._handler_entry_to_json(entry) for entry in app._handlers.values()],
                }
            )

            while True:
                request = json.loads(await self.socket.recv())
                request_id = request.get("id")

                try:
                    handle_request = getattr(self, "_on_" + request["type"].replace(":", "_").replace("-", "_"), None)
                    if handle_request is None:
                        raise NameError("unsupported request type")
                    result = await handle_request(request["payload"])
                except Exception as e:
                    if request_id is not None:
                        await self.post(
                            {
                                "type": "request:error",
                                "id": request_id,
                                "payload": {
                                    "message": str(e),
                                    "stack": traceback.format_exc(),
                                },
                            }
                        )
                    continue

                if request_id is not None:
                    await self.post({"type": "request:result", "id": request_id, "payload": result})

        async def post(self, message: dict) -> None:
            await self.socket.send(json.dumps(message))

        async def _on_tracer_respawn(self, _: dict) -> None:
            self.app._reactor.schedule(self.app._respawn)

        async def _on_handler_load(self, payload: dict) -> None:
            target, source, config = self.app._handlers[payload["id"]]
            return {"code": self.app._repo.ensure_handler(target), "config": config}

        async def _on_handler_save(self, payload: dict) -> None:
            target, _, _ = self.app._handlers[payload["id"]]
            self.app._repo.update_handler(target, payload["code"])

        async def _on_handler_configure(self, payload: dict) -> None:
            identifier = payload["id"]
            _, _, config = self.app._handlers[identifier]
            for k, v in payload["parameters"].items():
                config[k] = v
            self.app._tracer.update_handler_config(identifier, config)

        async def _on_targets_stage(self, payload: dict) -> None:
            profile = TracerProfile(list(map(tuple, payload["profile"]["spec"])))
            items = self.app._tracer.stage_targets(profile)
            return {
                "items": items,
            }

        async def _on_targets_commit(self, payload: dict) -> None:
            result = self.app._tracer.commit_targets(payload["id"])
            target_ids = result["ids"]

            await self.post(
                {
                    "type": "handlers:add",
                    "handlers": [
                        self._handler_entry_to_json(self.app._handlers[target_id]) for target_id in target_ids
                    ],
                }
            )

            return result

        async def _on_memory_read(self, payload: dict) -> None:
            data = self.app._tracer.read_memory(payload["address"], payload["size"])
            return list(data) if data is not None else None

        async def _on_symbols_resolve_addresses(self, payload: dict) -> None:
            names = self.app._tracer.resolve_addresses(payload["addresses"])
            return {"names": names}

        @staticmethod
        def _handler_entry_to_json(entry: tuple[str, str, str]) -> dict:
            target, _source, config = entry
            return {**target.to_json(), "config": config}

    app = TracerApplication()
    app.run()


class TracerProfileBuilder:
    def __init__(self) -> None:
        self._spec = []

    def include_modules(self, *module_name_globs: str) -> "TracerProfileBuilder":
        for m in module_name_globs:
            self._spec.append(("include", "module", m))
        return self

    def exclude_modules(self, *module_name_globs: str) -> "TracerProfileBuilder":
        for m in module_name_globs:
            self._spec.append(("exclude", "module", m))
        return self

    def include(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("include", "function", f))
        return self

    def exclude(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("exclude", "function", f))
        return self

    def include_relative_address(self, *address_rel_offsets: str) -> "TracerProfileBuilder":
        for f in address_rel_offsets:
            self._spec.append(("include", "relative-function", f))
        return self

    def include_imports(self, *module_name_globs: str) -> "TracerProfileBuilder":
        for m in module_name_globs:
            self._spec.append(("include", "imports", m))
        return self

    def include_objc_method(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("include", "objc-method", f))
        return self

    def exclude_objc_method(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("exclude", "objc-method", f))
        return self

    def include_swift_func(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("include", "swift-func", f))
        return self

    def exclude_swift_func(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("exclude", "swift-func", f))
        return self

    def include_java_method(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("include", "java-method", f))
        return self

    def exclude_java_method(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("exclude", "java-method", f))
        return self

    def include_debug_symbol(self, *function_name_globs: str) -> "TracerProfileBuilder":
        for f in function_name_globs:
            self._spec.append(("include", "debug-symbol", f))
        return self

    def build(self) -> "TracerProfile":
        return TracerProfile(self._spec)


class TracerProfile:
    def __init__(self, spec) -> None:
        self.spec = spec


class Tracer:
    def __init__(
        self,
        reactor: Reactor,
        repository: "Repository",
        profile: TracerProfile,
        init_scripts=[],
        log_handler: Callable[[str, str], None] = None,
    ) -> None:
        self.main_module = None
        self._reactor = reactor
        self._repository = repository
        self._profile = profile
        self._script: Optional[frida.core.Script] = None
        self._schedule_on_message = None
        self._agent = None
        self._init_scripts = init_scripts
        self._log_handler = log_handler

    def start_trace(self, session: frida.core.Session, stage, parameters, runtime, ui: UI) -> None:
        def on_create(*args) -> None:
            ui.on_trace_handler_create(*args)

        self._repository.on_create(on_create)

        def on_load(*args) -> None:
            ui.on_trace_handler_load(*args)

        self._repository.on_load(on_load)

        def on_update(target, handler, source) -> None:
            self._agent.update_handler_code(target.identifier, target.display_name, handler)

        self._repository.on_update(on_update)

        self._schedule_on_message = lambda message, data: self._reactor.schedule(
            lambda: self._on_message(message, data, ui)
        )

        ui.on_trace_progress("initializing")
        data_dir = Path(__file__).parent
        source = (data_dir / "tracer_agent.js").read_text(encoding="utf-8")
        script = session.create_script(name="tracer", source=source, runtime=runtime)

        self._script = script
        script.set_log_handler(self._log_handler)
        script.on("message", self._schedule_on_message)
        ui.on_script_created(script)
        script.load()

        self._agent = script.exports_sync

        raw_init_scripts = [{"filename": script.filename, "source": script.source} for script in self._init_scripts]
        self.process = self._agent.init(stage, parameters, raw_init_scripts, self._profile.spec)

    def stop(self) -> None:
        self._repository.close()

        if self._script is not None:
            self._script.off("message", self._schedule_on_message)
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def update_handler_config(self, identifier: int, config: dict) -> None:
        return self._agent.update_handler_config(identifier, config)

    def stage_targets(self, profile: TracerProfile) -> List:
        return self._agent.stage_targets(profile.spec)

    def commit_targets(self, identifier: Optional[int]) -> dict:
        return self._agent.commit_targets(identifier)

    def read_memory(self, address: str, size: int) -> bytes:
        return self._agent.read_memory(address, size)

    def resolve_addresses(self, addresses: List[str]) -> List[str]:
        return self._agent.resolve_addresses(addresses)

    def _on_message(self, message, data, ui) -> None:
        handled = False

        if message["type"] == "send":
            try:
                payload = message["payload"]
                mtype = payload["type"]
                params = (mtype, payload, data, ui)
            except:
                # As user scripts may use send() we need to be prepared for this.
                params = None
            if params is not None:
                handled = self._try_handle_message(*params)

        if not handled:
            print(message)

    def _try_handle_message(self, mtype, params, data, ui) -> False:
        if mtype == "events:add":
            events = [
                (target_id, timestamp, thread_id, depth, caller, backtrace, message)
                for target_id, timestamp, thread_id, depth, caller, backtrace, message in params["events"]
            ]
            ui.on_trace_events(events)
            return True

        if mtype == "handlers:get":
            flavor = params["flavor"]
            base_id = params["baseId"]

            scripts = []
            response = {"type": f"reply:{base_id}", "scripts": scripts}

            repo = self._repository
            next_id = base_id
            for scope in params["scopes"]:
                scope_name = scope["name"]
                addresses = scope.get("addresses")
                i = 0
                for member_name in scope["members"]:
                    if isinstance(member_name, list):
                        name, display_name = member_name
                    else:
                        name = member_name
                        display_name = member_name
                    address = int(addresses[i], 16) if addresses is not None else None
                    target = TraceTarget(next_id, flavor, scope_name, name, display_name, address)
                    next_id += 1
                    handler = repo.ensure_handler(target)
                    scripts.append(handler)
                    i += 1

            self._script.post(response)

            return True

        if mtype == "agent:initialized":
            ui.on_trace_progress("initialized")
            return True

        if mtype == "agent:started":
            self._repository.commit_handlers()
            ui.on_trace_progress("started", params["count"])
            return True

        if mtype == "agent:warning":
            ui.on_trace_warning(params["message"])
            return True

        if mtype == "agent:error":
            ui.on_trace_error(params["message"])
            return True

        return False


@dataclass
class TraceTarget:
    identifier: int
    flavor: str
    scope: str
    name: str
    display_name: str
    address: Optional[int]

    def to_json(self) -> dict:
        return {
            "id": self.identifier,
            "flavor": self.flavor,
            "scope": self.scope,
            "display_name": self.display_name,
            "address": hex(self.address) if self.address is not None else None,
        }

    def __str__(self) -> str:
        return self.display_name


class Repository:
    def __init__(self) -> None:
        self._on_create_callback: Optional[Callable[[TraceTarget, str, str], None]] = None
        self._on_load_callback: Optional[Callable[[TraceTarget, str, str], None]] = None
        self._on_update_callback: Optional[Callable[[TraceTarget, str, str], None]] = None
        self._decorate = False
        self._manpages = None

    def close(self) -> None:
        self._on_create_callback = None
        self._on_load_callback = None
        self._on_update_callback = None

    def ensure_handler(self, target: TraceTarget):
        raise NotImplementedError("not implemented")

    def commit_handlers(self) -> None:
        pass

    def on_create(self, callback: Callable[[TraceTarget, str, str], None]) -> None:
        self._on_create_callback = callback

    def on_load(self, callback: Callable[[TraceTarget, str, str], None]) -> None:
        self._on_load_callback = callback

    def on_update(self, callback: Callable[[TraceTarget, str, str], None]) -> None:
        self._on_update_callback = callback

    def _notify_create(self, target: TraceTarget, handler: str, source: str) -> None:
        if self._on_create_callback is not None:
            self._on_create_callback(target, handler, source)

    def _notify_load(self, target: TraceTarget, handler: str, source: str) -> None:
        if self._on_load_callback is not None:
            self._on_load_callback(target, handler, source)

    def _notify_update(self, target: TraceTarget, handler: str, source: str) -> None:
        if self._on_update_callback is not None:
            self._on_update_callback(target, handler, source)

    def _create_stub_handler(self, target: TraceTarget, decorate: bool) -> str:
        if target.flavor == "insn":
            return self._create_stub_instruction_handler(target, decorate)
        if target.flavor == "java":
            return self._create_stub_java_handler(target, decorate)
        return self._create_stub_native_handler(target, decorate)

    def _create_stub_instruction_handler(self, target: TraceTarget, decorate: bool) -> str:
        return """\
/*
 * Auto-generated by Frida.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler(function (log, args, state) {
  log(`%(display_name)s hit! sp=${this.context.sp}`);
});
""" % {
            "display_name": target.display_name
        }

    def _create_stub_native_handler(self, target: TraceTarget, decorate: bool) -> str:
        if target.flavor == "objc":
            log_str = self._create_objc_logging_code(target)
        elif target.flavor == "swift":
            log_str = self._create_swift_logging_code(target, decorate)
        else:
            log_str = self._create_cstyle_logging_code(target, decorate)

        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(display_name)s.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(%(log_str)s);
  },

  onLeave(log, retval, state) {
  }
});
""" % {
            "display_name": target.display_name,
            "log_str": log_str,
        }

    def _create_cstyle_logging_code(self, target: TraceTarget, decorate: bool) -> str:
        if decorate:
            module_string = f" [{Path(target.scope).name}]"
        else:
            module_string = ""

        args = self._generate_cstyle_argument_logging_code(target)
        if len(args) == 0:
            code = "'%(name)s()%(module_string)s'" % {"name": target.name, "module_string": module_string}
        else:
            code = "`%(name)s(%(args)s)%(module_string)s`" % {
                "name": target.name,
                "args": ", ".join(args),
                "module_string": module_string,
            }

        return code

    def _create_objc_logging_code(self, target: TraceTarget) -> str:
        state = {"index": 2}

        def obj
"""


```