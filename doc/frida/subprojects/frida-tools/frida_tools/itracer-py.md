Response:
Let's break down the thought process for analyzing the `itracer.py` code.

1. **Understand the Goal:** The first step is to recognize that this is a Frida-based tool for *instruction tracing*. The filename and the import of `frida` immediately suggest this. The "itracer" name is also a strong clue.

2. **High-Level Structure:** Quickly scan the code to identify the main components:
    * Imports:  See external libraries used (like `frida`, `prompt_toolkit`, `json`, `os`, `struct`).
    * `main()` function: This is the entry point, setting up argument parsing and running the application.
    * `InstructionTracerApplication`:  Looks like the main application class, handling user interaction.
    * `InstructionTracerUI`: An abstract base class for the user interface.
    * `InstructionTracer`: The core logic for interacting with the Frida agent and handling tracing.
    * Helper functions: Functions like `parse_thread_id`, `parse_range`, `human_readable_size`, and `radiolist_prompt`.
    * `RecordType`: An enum-like class for data recording.

3. **Functionality Identification (Top-Down and Bottom-Up):**

    * **User Interaction (UI):** Look at `InstructionTracerApplication` and `InstructionTracerUI`. Notice methods related to:
        * Command-line arguments (`_add_options`).
        * Starting and stopping the tracer (`_start`, `_stop`).
        * Processing user input (`_process_input`, prompting for trace strategy and output path).
        * Providing feedback (`on_trace_started`, `on_trace_stopped`, `on_trace_progress`).
    * **Frida Integration:**  Focus on `InstructionTracer`. Look for:
        * Script creation (`session.create_script`).
        * Message handling (`on_message`, `_on_message`).
        * Communication with the agent (`tracer_script.exports_sync`, `reader_script.exports_sync`).
        * Starting the tracing on the agent (`tracer_script.exports_sync.launch_trace_session`).
        * Buffer management (`tracer_api.create_buffer`, `reader_api.open_buffer`, `reader_api.launch_buffer_reader`).
    * **Data Handling:**  Examine how tracing data is captured and stored. Notice:
        * Writing to a file (`self._outfile`).
        * Using a specific file format (`FILE_MAGIC`, `RecordType.MESSAGE`, `RecordType.CHUNK`, `struct.pack`).
        * Handling chunks and messages.
    * **Configuration:**  How is the tracing configured? Observe the parsing of command-line arguments and the prompts for trace strategy (thread ID, thread index, address range).

4. **Relating to Concepts (The Prompt's Specific Questions):**

    * **Reversing:** Instruction tracing is a fundamental dynamic analysis technique used in reverse engineering. It helps understand the execution flow of a program. The example provided (tracing a function like `sleep`) directly illustrates this.
    * **Binary/Low-Level:** The code deals with:
        * Memory addresses (hexadecimal).
        * Module names and offsets.
        * Basic blocks (mentioned in `on_trace_progress`).
        * The concept of threads.
        * The file format with magic numbers and structured data.
    * **Linux/Android Kernel/Framework:**  While the Python code itself is cross-platform, the *target* being traced often runs on these systems. Frida's ability to hook into processes on these platforms is key. The example of tracing within `libc.so` (a standard C library often used in these environments) is a direct link. The mention of thread IDs and indices is also relevant to operating system concepts.
    * **Logic and Assumptions:** Look for conditional statements, loops, and data processing. The input parsing functions (`parse_thread_id`, `parse_range`, `parse_code_location`) are prime examples of logical processing based on input formats. The file writing logic also makes assumptions about the order and structure of the data.
    * **User Errors:** Think about common mistakes a user might make. Typos in addresses or module names, incorrect ranges, forgetting to specify an output file, or interrupting the process are all possibilities.
    * **User Steps to Reach the Code:** Imagine the user running the `frida-tools` and selecting the `itracer` tool. The command-line arguments they provide will directly influence which parts of the code are executed.

5. **Example Construction:** For each of the prompt's questions, create concrete examples. Don't just say "it handles ranges"; show an example of a range being specified.

6. **Review and Refine:** After the initial analysis, go back and review the code to catch anything missed. Ensure the explanations are clear and concise. Check for consistency between the identified functionalities and the examples. For instance, after noticing the buffer management in Frida, make sure to explain *why* this might be done (efficiency).

7. **Structure the Output:** Organize the information clearly using headings and bullet points to make it easy to read and understand. Match the structure to the specific questions asked in the prompt.

By following these steps, a comprehensive analysis like the example provided can be generated. The key is to combine a high-level understanding of the tool's purpose with a detailed examination of the code's implementation.
这是一个名为 `itracer.py` 的 Python 源代码文件，它是 `frida-tools` 工具集中的一个组件，专门用于**动态指令跟踪 (Instruction Tracing)**。它允许用户在程序运行时记录程序执行的指令序列，这对于理解程序行为、逆向工程和调试非常有用。

下面我们分点列举其功能，并根据你的要求进行说明：

**1. 功能列举:**

* **指定跟踪目标:** 用户可以通过命令行参数指定要跟踪的目标进程。这可以是正在运行的进程的名称或进程 ID。
* **多种跟踪策略:**
    * **按线程 ID 跟踪:** 可以指定跟踪特定线程 ID 的指令执行。
    * **按线程索引跟踪:** 可以指定跟踪特定线程索引的指令执行。
    * **按地址范围跟踪:** 可以指定跟踪特定内存地址范围内的指令执行。这个范围可以是绝对地址，也可以是模块名加偏移量或导出函数名。
* **交互式配置 (如果未提供策略):** 如果用户没有在命令行指定跟踪策略，该工具会提供一个交互式界面，让用户选择要跟踪的线程或地址范围。
* **输出到文件:** 跟踪结果可以输出到一个文件中，方便后续分析。
* **实时显示跟踪进度:** 在跟踪过程中，会实时显示已收集的基本块和数据量。
* **基于 Frida 的实现:**  它利用 Frida 提供的 API 来注入 JavaScript 代码到目标进程，并利用该 JavaScript 代码来捕获指令执行信息。
* **处理跟踪数据:**  它负责接收来自 Frida agent 的跟踪数据，并将其写入输出文件。
* **用户友好的命令行界面:** 使用 `argparse` 提供清晰的命令行选项，使用 `prompt_toolkit` 提供交互式提示。

**2. 与逆向方法的关系及举例:**

`itracer.py` 提供的指令跟踪功能是逆向工程中一种非常重要的**动态分析**技术。

* **理解程序执行流程:**  通过跟踪指令执行，逆向工程师可以清晰地了解程序在运行时的具体操作，包括函数调用顺序、条件分支走向、循环执行次数等。
    * **举例:** 假设你想逆向一个恶意软件，怀疑其使用了某种加密算法。你可以使用 `itracer.py` 跟踪该进程，并指定跟踪加密函数（例如 `CryptEncrypt` 或自定义的加密函数）的地址范围。输出的跟踪日志会显示该函数内部执行的每一条指令，帮助你分析其加密逻辑。
* **定位关键代码:** 当程序行为复杂时，直接阅读静态代码可能难以理解。指令跟踪可以帮助逆向工程师快速定位到与特定行为相关的代码片段。
    * **举例:**  你正在逆向一个程序，想知道它是如何处理用户输入的。你可以先运行程序并进行一些输入操作，然后使用 `itracer.py` 跟踪程序执行。通过分析跟踪日志，你可以找到处理用户输入的相关函数和代码块。
* **发现隐藏的功能或逻辑:**  有些代码可能在静态分析中难以发现，例如通过动态加载或反射调用的代码。指令跟踪可以揭示这些代码的执行。
    * **举例:** 某些恶意软件可能会在运行时动态解密并加载额外的代码。静态分析可能无法直接看到这些解密后的代码，但 `itracer.py` 可以记录这些动态加载的代码的执行过程。
* **理解混淆代码:**  对于经过代码混淆的程序，指令跟踪可以帮助理解其真实的执行逻辑，即使代码难以阅读。
    * **举例:** 经过控制流平坦化混淆的代码会使静态分析变得困难。但指令跟踪可以记录实际的执行路径，绕过混淆带来的干扰。

**3. 涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

`itracer.py` 本身是一个 Python 工具，但它依赖于 Frida，而 Frida 在底层与目标进程进行交互，因此涉及到以下方面的知识：

* **二进制指令:** 指令跟踪的核心是记录 CPU 执行的二进制指令。理解不同架构（如 x86, ARM）的指令格式和含义对于分析跟踪结果至关重要。
    * **举例:**  跟踪日志中会显示指令的地址和机器码。例如，你可能会看到类似 `0x7ffff7a00b60:  mov    rax, qword ptr [rip + 0x2a339]` 的信息。这需要理解汇编语言和 CPU 指令集。
* **内存地址和布局:**  跟踪涉及到内存地址的读取和写入。了解进程的内存布局（代码段、数据段、堆、栈）对于理解指令的上下文至关重要。
    * **举例:**  在跟踪日志中，你会看到指令操作的内存地址。理解这些地址所属的段可以帮助你判断指令操作的是代码、数据还是栈上的变量。
* **进程和线程:**  `itracer.py` 可以针对特定的线程进行跟踪。理解操作系统中进程和线程的概念，以及它们如何调度执行是必要的。
    * **举例:**  你可以使用 `-t` 或 `-i` 参数来指定要跟踪的线程。理解线程 ID 和线程索引的区别对于正确选择跟踪目标至关重要。
* **动态链接库 (DLL/Shared Object):**  程序通常会加载多个动态链接库。`itracer.py` 可以指定跟踪特定模块（例如 `libc.so` 或 `kernel32.dll`）的代码。
    * **举例:**  使用 `-r libc.so!sleep` 可以跟踪 `libc.so` 库中 `sleep` 函数的执行。这需要了解动态链接和函数导出的概念.
* **系统调用:**  程序与操作系统内核交互通常通过系统调用。虽然 `itracer.py` 主要关注指令级别的跟踪，但跟踪结果可以揭示程序执行的系统调用序列。
    * **举例:**  如果程序执行了 `open` 系统调用打开文件，跟踪日志可能会显示 `open` 系统调用相关的指令执行。
* **Android 框架 (对于 Android 应用):** 如果跟踪的是 Android 应用，理解 Android 运行时 (ART) 和 Dalvik 虚拟机的指令执行方式（dex 代码）会很有帮助。
    * **举例:**  在跟踪 Android 应用时，你可能会看到与 Dalvik 字节码执行相关的指令。
* **内核知识:**  虽然 `itracer.py` 主要在用户态工作，但它跟踪的用户态代码最终会与内核交互。了解内核的一些基本概念（如进程管理、内存管理）可以更深入地理解程序的行为。

**4. 逻辑推理、假设输入与输出:**

* **假设输入:** 用户在命令行中输入以下命令：
    ```bash
    frida -o trace.log -r "my_app!0x1000..my_app!0x1010" my_app
    ```
* **逻辑推理:**
    * `frida` 是 Frida 的命令行工具。
    * `-o trace.log` 表示将跟踪结果输出到 `trace.log` 文件。
    * `-r "my_app!0x1000..my_app!0x1010"` 指定了跟踪范围：从模块 `my_app` 的地址 `0x1000` 到 `0x1010` 的指令。
    * `my_app` 是要跟踪的目标进程。
    * `itracer.py` 会被 Frida 调用来执行指令跟踪。
    * `itracer.py` 会连接到 `my_app` 进程。
    * `itracer.py` 会在 `my_app` 进程中注入 Frida agent。
    * Frida agent 会监控 `my_app` 进程，并记录地址在 `0x1000` 到 `0x1010` 范围内的指令执行。
    * 跟踪到的指令信息（例如指令地址、机器码、操作数等）会被发送回 `itracer.py`。
    * `itracer.py` 将接收到的跟踪数据格式化并写入 `trace.log` 文件。
* **预期输出 (trace.log 文件的部分内容示例):**
    ```
    { "type": "send", "payload": { "type": "itrace:compile", "address": 4096, "size": 4, "threadId": 1234 } }
    { "type": "send", "payload": { "type": "itrace:chunk", "threadId": 1234 }, "data": "...\x00\xb8\x05\x00\x00\x00" }
    { "type": "send", "payload": { "type": "itrace:compile", "address": 4100, "size": 2, "threadId": 1234 } }
    { "type": "send", "payload": { "type": "itrace:chunk", "threadId": 1234 }, "data": "...\x89\xc3" }
    ...
    ```
    *  `"itrace:compile"`  表示跟踪到一个新的基本块的开始。
    * `"itrace:chunk"` 包含实际跟踪到的指令数据 (二进制形式)。
    * `"address"` 是指令的内存地址。
    * `"threadId"` 是执行指令的线程 ID。
    * `data` 字段是实际执行的指令的字节码。

**5. 用户或编程常见的使用错误及举例:**

* **错误的地址范围:** 用户可能输入了不存在或不可访问的地址范围，导致跟踪失败或产生大量无意义的跟踪数据.
    * **举例:** `frida -r "my_app!0x99999999..my_app!0x9999999A" my_app` (这个地址很可能无效).
* **错误的模块名或函数名:**  如果用户指定的模块名或函数名拼写错误，`itracer.py` 可能无法找到对应的地址，导致无法跟踪。
    * **举例:** `frida -r "libcs.so!sleep" my_app` (正确的模块名可能是 `libc.so`).
* **没有权限进行跟踪:**  用户可能没有足够的权限附加到目标进程并进行跟踪。
    * **举例:**  尝试跟踪属于 root 用户的进程，但当前用户不是 root 或没有使用 `sudo`。
* **目标进程崩溃或退出:** 如果目标进程在跟踪过程中崩溃或退出，`itracer.py` 会停止跟踪，并可能丢失部分跟踪数据。
* **跟踪范围过大:**  跟踪非常大的地址范围或长时间运行的程序会产生巨大的跟踪日志，难以分析且可能影响系统性能。
* **忘记指定输出文件:**  如果没有使用 `-o` 参数，跟踪结果会输出到标准输出，如果数据量很大，可能会刷屏。
* **在不兼容的架构上使用:**  Frida 和其工具链需要与目标进程的架构兼容。尝试在不兼容的架构上进行跟踪会失败。
* **Frida agent 加载失败:**  由于各种原因（例如版本不兼容、环境问题），Frida agent 可能无法成功注入到目标进程。

**6. 用户操作如何一步步到达这里 (作为调试线索):**

假设用户想要跟踪一个名为 `vulnerable_app` 的程序中 `login` 函数的执行：

1. **安装 Frida 和 frida-tools:** 用户首先需要在他们的系统上安装 Frida 和 `frida-tools`。这通常通过 `pip install frida frida-tools` 命令完成。
2. **运行目标程序:** 用户运行他们想要分析的目标程序 `vulnerable_app`。
3. **确定跟踪策略:** 用户想要跟踪 `login` 函数，因此需要确定该函数在 `vulnerable_app` 模块中的地址或导出名。他们可以使用其他工具（如 `readelf`, `objdump` 或其他 Frida 工具）来获取 `login` 函数的信息。假设他们找到了 `login` 函数的导出名。
4. **使用 frida 命令启动跟踪:** 用户打开终端，输入类似以下的命令：
   ```bash
   frida -o trace.log -r "vulnerable_app!login" vulnerable_app
   ```
   * `frida`:  调用 Frida 的命令行工具。
   * `-o trace.log`:  指定将跟踪结果输出到 `trace.log` 文件。
   * `-r "vulnerable_app!login"`:  告诉 `itracer.py` 跟踪 `vulnerable_app` 模块中的 `login` 函数。
   * `vulnerable_app`:  指定要附加到的目标进程。
5. **Frida 解析命令并调用 itracer.py:** Frida 工具解析命令行参数，识别出用户使用了 `-r` 参数，这表明需要进行范围跟踪。Frida 内部会将这个请求传递给 `frida-tools` 中的 `itracer.py` 脚本来处理。
6. **itracer.py 初始化:** `itracer.py` 脚本开始执行，解析命令行参数，并尝试连接到目标进程 `vulnerable_app`。
7. **注入 Frida agent:** `itracer.py` 使用 Frida 的 API 将 JavaScript agent 注入到 `vulnerable_app` 进程中。
8. **设置跟踪点:** 注入的 agent 根据用户提供的跟踪策略（`vulnerable_app!login`）找到 `login` 函数的入口地址，并设置指令跟踪点。
9. **开始跟踪:**  当 `vulnerable_app` 进程执行到 `login` 函数内部的指令时，Frida agent 会捕获这些指令的信息。
10. **数据传输:**  捕获到的指令信息通过 Frida 的消息机制发送回运行 `itracer.py` 的 Python 进程。
11. **数据处理和输出:** `itracer.py` 接收到指令信息，将其格式化，并写入到 `trace.log` 文件中。
12. **用户分析跟踪结果:** 用户可以使用文本编辑器或其他分析工具打开 `trace.log` 文件，查看 `login` 函数内部的指令执行序列，从而理解其具体实现逻辑。

通过以上步骤，用户的操作最终会触发 `itracer.py` 的执行，并利用 Frida 的功能实现指令级别的动态跟踪。`itracer.py` 在这个过程中扮演着配置跟踪策略、启动跟踪、接收和处理跟踪数据的关键角色。

### 提示词
```
这是目录为frida/subprojects/frida-tools/frida_tools/itracer.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import json
import os
import struct
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, TypeVar, Union

import frida
from frida.core import RPCException

from frida_tools.reactor import Reactor

CodeLocation = Union[
    Tuple[str, str],
    Tuple[str, Tuple[str, str]],
    Tuple[str, Tuple[str, int]],
]

TraceThreadStrategy = Tuple[str, Tuple[str, int]]
TraceRangeStrategy = Tuple[str, Tuple[CodeLocation, Optional[CodeLocation]]]
TraceStrategy = Union[TraceThreadStrategy, TraceRangeStrategy]


def main() -> None:
    import argparse
    import threading

    from prompt_toolkit import PromptSession, prompt
    from prompt_toolkit.application import Application
    from prompt_toolkit.formatted_text import AnyFormattedText, FormattedText
    from prompt_toolkit.key_binding.defaults import load_key_bindings
    from prompt_toolkit.key_binding.key_bindings import KeyBindings, merge_key_bindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit
    from prompt_toolkit.styles import BaseStyle
    from prompt_toolkit.widgets import Label, RadioList

    from frida_tools.application import ConsoleApplication

    class InstructionTracerApplication(ConsoleApplication, InstructionTracerUI):
        _itracer: Optional[InstructionTracer]

        def __init__(self) -> None:
            self._state = "starting"
            self._ready = threading.Event()
            self._cli = PromptSession()
            super().__init__(self._process_input)

        def _add_options(self, parser: argparse.ArgumentParser) -> None:
            parser.add_argument(
                "-t", "--thread-id", help="trace THREAD_ID", metavar="THREAD_ID", dest="strategy", type=parse_thread_id
            )
            parser.add_argument(
                "-i",
                "--thread-index",
                help="trace THREAD_INDEX",
                metavar="THREAD_INDEX",
                dest="strategy",
                type=parse_thread_index,
            )
            parser.add_argument(
                "-r",
                "--range",
                help="trace RANGE, e.g.: 0x1000..0x1008, libc.so!sleep, libc.so!0x1234, recv..memcpy",
                metavar="RANGE",
                dest="strategy",
                type=parse_range,
            )
            parser.add_argument("-o", "--output", help="output to file", dest="outpath")

        def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
            self._itracer = None
            self._strategy = options.strategy
            self._outpath = options.outpath

        def _usage(self) -> str:
            return "%(prog)s [options] target"

        def _needs_target(self) -> bool:
            return True

        def _start(self) -> None:
            self._update_status("Injecting script...")
            self._itracer = InstructionTracer(self._reactor)
            self._itracer.start(self._device, self._session, self._runtime, self)
            self._ready.set()

        def _stop(self) -> None:
            assert self._itracer is not None
            self._itracer.dispose()
            self._itracer = None

            try:
                self._cli.app.exit()
            except:
                pass

        def _process_input(self, reactor: Reactor) -> None:
            try:
                while self._ready.wait(0.5) != True:
                    if not reactor.is_running():
                        return
            except KeyboardInterrupt:
                reactor.cancel_io()
                return

            if self._state != "started":
                return

            try:
                self._cli.prompt()
            except:
                pass

        def get_trace_strategy(self) -> Optional[TraceStrategy]:
            return self._strategy

        def prompt_for_trace_strategy(self, threads: List[dict]) -> Optional[TraceStrategy]:
            kind = radiolist_prompt(
                title="Tracing strategy:",
                values=[
                    ("thread", "Thread"),
                    ("range", "Range"),
                ],
            )
            if kind is None:
                raise KeyboardInterrupt

            if kind == "thread":
                thread_id = radiolist_prompt(
                    title="Running threads:", values=[(t["id"], json.dumps(t)) for t in threads]
                )
                if thread_id is None:
                    raise KeyboardInterrupt
                return ("thread", ("id", thread_id))

            while True:
                try:
                    text = prompt("Start address: ").strip()
                    if len(text) == 0:
                        continue
                    start = parse_code_location(text)
                    break
                except Exception as e:
                    print(str(e))
                    continue

            while True:
                try:
                    text = prompt("End address (optional): ").strip()
                    if len(text) > 0:
                        end = parse_code_location(text)
                    else:
                        end = None
                    break
                except Exception as e:
                    print(str(e))
                    continue

            return ("range", (start, end))

        def get_trace_output_path(self, suggested_name: Optional[str] = None) -> os.PathLike:
            return self._outpath

        def prompt_for_trace_output_path(self, suggested_name: str) -> Optional[os.PathLike]:
            while True:
                outpath = prompt("Output filename: ", default=suggested_name).strip()
                if len(outpath) != 0:
                    break
            return outpath

        def on_trace_started(self) -> None:
            self._state = "started"

        def on_trace_stopped(self, error_message: Optional[str] = None) -> None:
            self._state = "stopping"

            if error_message is not None:
                self._log(level="error", text=error_message)
                self._exit(1)
            else:
                self._exit(0)

            try:
                self._cli.app.exit()
            except:
                pass

        def on_trace_progress(self, total_blocks: int, total_bytes: int) -> None:
            blocks_suffix = "s" if total_blocks != 1 else ""
            self._cli.message = FormattedText(
                [
                    ("bold", "Tracing!"),
                    ("", " Collected "),
                    ("fg:green bold", human_readable_size(total_bytes)),
                    ("", f" from {total_blocks} basic block{blocks_suffix}"),
                ]
            )
            self._cli.app.invalidate()

    def parse_thread_id(value: str) -> TraceThreadStrategy:
        return ("thread", ("id", int(value)))

    def parse_thread_index(value: str) -> TraceThreadStrategy:
        return ("thread", ("index", int(value)))

    def parse_range(value: str) -> TraceRangeStrategy:
        tokens = value.split("..", 1)
        start = tokens[0]
        end = tokens[1] if len(tokens) == 2 else None
        return ("range", (parse_code_location(start), parse_code_location(end)))

    def parse_code_location(value: Optional[str]) -> CodeLocation:
        if value is None:
            return None

        if value.startswith("0x"):
            return ("address", value)

        tokens = value.split("!", 1)
        if len(tokens) == 2:
            name = tokens[0]
            subval = tokens[1]
            if subval.startswith("0x"):
                return ("module-offset", (name, int(subval, 16)))
            return ("module-export", (name, subval))

        return ("symbol", tokens[0])

    # Based on https://stackoverflow.com/a/43690506
    def human_readable_size(size):
        for unit in ["B", "KiB", "MiB", "GiB"]:
            if size < 1024.0 or unit == "GiB":
                break
            size /= 1024.0
        return f"{size:.2f} {unit}"

    T = TypeVar("T")

    # Based on https://github.com/prompt-toolkit/python-prompt-toolkit/issues/756#issuecomment-1294742392
    def radiolist_prompt(
        title: str = "",
        values: Sequence[Tuple[T, AnyFormattedText]] = None,
        default: Optional[T] = None,
        cancel_value: Optional[T] = None,
        style: Optional[BaseStyle] = None,
    ) -> T:
        radio_list = RadioList(values, default)
        radio_list.control.key_bindings.remove("enter")

        bindings = KeyBindings()

        @bindings.add("enter")
        def exit_with_value(event):
            radio_list._handle_enter()
            event.app.exit(result=radio_list.current_value)

        @bindings.add("c-c")
        def backup_exit_with_value(event):
            event.app.exit(result=cancel_value)

        application = Application(
            layout=Layout(HSplit([Label(title), radio_list])),
            key_bindings=merge_key_bindings([load_key_bindings(), bindings]),
            mouse_support=True,
            style=style,
            full_screen=False,
        )
        return application.run()

    app = InstructionTracerApplication()
    app.run()


class InstructionTracerUI(ABC):
    @abstractmethod
    def get_trace_strategy(self) -> Optional[TraceStrategy]:
        raise NotImplementedError

    def prompt_for_trace_strategy(self, threads: List[dict]) -> Optional[TraceStrategy]:
        return None

    @abstractmethod
    def get_trace_output_path(self) -> Optional[os.PathLike]:
        raise NotImplementedError

    def prompt_for_trace_output_path(self, suggested_name: str) -> Optional[os.PathLike]:
        return None

    @abstractmethod
    def on_trace_started(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_trace_stopped(self, error_message: Optional[str] = None) -> None:
        raise NotImplementedError

    def on_trace_progress(self, total_blocks: int, total_bytes: int) -> None:
        pass

    def _on_script_created(self, script: frida.core.Script) -> None:
        pass


class InstructionTracer:
    FILE_MAGIC = b"ITRC"

    def __init__(self, reactor: Reactor) -> None:
        self._reactor = reactor
        self._outfile = None
        self._ui: Optional[InstructionTracerUI] = None
        self._total_blocks = 0
        self._tracer_script: Optional[frida.core.Script] = None
        self._reader_script: Optional[frida.core.Script] = None
        self._reader_api = None

    def dispose(self) -> None:
        if self._reader_api is not None:
            try:
                self._reader_api.stop_buffer_reader()
            except:
                pass
            self._reader_api = None

        if self._reader_script is not None:
            try:
                self._reader_script.unload()
            except:
                pass
            self._reader_script = None

        if self._tracer_script is not None:
            try:
                self._tracer_script.unload()
            except:
                pass
            self._tracer_script = None

    def start(
        self, device: frida.core.Device, session: frida.core.Session, runtime: str, ui: InstructionTracerUI
    ) -> None:
        def on_message(message, data) -> None:
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._ui = ui

        agent_source = (Path(__file__).parent / "itracer_agent.js").read_text(encoding="utf-8")

        try:
            tracer_script = session.create_script(name="itracer", source=agent_source, runtime=runtime)
            self._tracer_script = tracer_script
            self._ui._on_script_created(tracer_script)
            tracer_script.on("message", on_message)
            tracer_script.load()

            tracer_api = tracer_script.exports_sync

            outpath = ui.get_trace_output_path()
            if outpath is None:
                outpath = ui.prompt_for_trace_output_path(suggested_name=tracer_api.query_program_name() + ".itrace")
                if outpath is None:
                    ui.on_trace_stopped("Missing output path")
                    return

            self._outfile = open(outpath, "wb")
            self._outfile.write(self.FILE_MAGIC)

            strategy = ui.get_trace_strategy()
            if strategy is None:
                strategy = ui.prompt_for_trace_strategy(threads=tracer_api.list_threads())
                if strategy is None:
                    ui.on_trace_stopped("Missing strategy")
                    return

            buffer_location = tracer_api.create_buffer()

            try:
                system_session = device.attach(0)

                reader_script = system_session.create_script(name="itracer", source=agent_source, runtime=runtime)
                self._reader_script = reader_script
                self._ui._on_script_created(reader_script)
                reader_script.on("message", on_message)
                reader_script.load()

                reader_script.exports_sync.open_buffer(buffer_location)
            except:
                if self._reader_script is not None:
                    self._reader_script.unload()
                    self._reader_script = None
                reader_script = None

            if reader_script is not None:
                reader_api = reader_script.exports_sync
            else:
                reader_api = tracer_script.exports_sync
            self._reader_api = reader_api
            reader_api.launch_buffer_reader()

            tracer_script.exports_sync.launch_trace_session(strategy)

            ui.on_trace_started()
        except RPCException as e:
            ui.on_trace_stopped(f"Unable to start: {e.args[0]}")
        except Exception as e:
            ui.on_trace_stopped(str(e))
        except KeyboardInterrupt:
            ui.on_trace_stopped()

    def _on_message(self, message, data) -> None:
        handled = False

        if message["type"] == "send":
            try:
                payload = message["payload"]
                mtype = payload["type"]
                params = (mtype, payload, data)
            except:
                params = None
            if params is not None:
                handled = self._try_handle_message(*params)

        if not handled:
            print(message)

    def _try_handle_message(self, mtype, message, data) -> bool:
        if not mtype.startswith("itrace:"):
            return False

        if mtype == "itrace:chunk":
            self._write_chunk(data)
        else:
            self._write_message(message, data)

            if mtype == "itrace:compile":
                self._total_blocks += 1

        self._update_progress()

        if mtype == "itrace:end":
            self._ui.on_trace_stopped()

        return True

    def _update_progress(self) -> None:
        self._ui.on_trace_progress(self._total_blocks, self._outfile.tell())

    def _write_message(self, message, data) -> None:
        f = self._outfile

        raw_message = json.dumps(message).encode("utf-8")
        f.write(struct.pack(">II", RecordType.MESSAGE, len(raw_message)))
        f.write(raw_message)

        data_size = len(data) if data is not None else 0
        f.write(struct.pack(">I", data_size))
        if data_size != 0:
            f.write(data)

        f.flush()

    def _write_chunk(self, chunk) -> None:
        f = self._outfile
        f.write(struct.pack(">II", RecordType.CHUNK, len(chunk)))
        f.write(chunk)
        f.flush()


class RecordType:
    MESSAGE = 1
    CHUNK = 2


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
```