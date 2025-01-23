Response:
My thought process to analyze the `mtest.py` code and generate the summary goes like this:

1. **Understand the Goal:** The primary goal of `mtest.py` is to execute tests within the Frida build system (which uses Meson). It needs to handle different test types, report results, and provide various options for controlling the test execution.

2. **High-Level Structure Scan:** I quickly scanned the code to identify major sections: imports, global constants, helper functions, enums, and classes. This gives a roadmap of the file's organization.

3. **Identify Key Classes:**  The classes stand out as the core components:
    * `TAPParser`: Deals with parsing TAP (Test Anything Protocol) output.
    * `TestLogger` (and its subclasses): Handles outputting test results to the console and log files in different formats.
    * `TestFileLogger`: Base class for file-based loggers.
    * `ConsoleLogger`:  Manages real-time console output with progress updates.
    * `TextLogfileBuilder`, `JsonLogfileBuilder`, `JunitBuilder`: Implement specific log file formats.

4. **Analyze Function by Function (or Group of Related Functions):** I started going through the code section by section, paying attention to the purpose of each function and class.

    * **Imports:**  These immediately indicate the dependencies and functionalities involved (path manipulation, collections, concurrency, etc.). The presence of `frida` in the directory path provided in the prompt confirms the context.
    * **Global Constants:**  These define important values like return codes for skipping/erroring tests, Ctrl+C handling, and XML encoding restrictions.
    * **Helper Functions:** Functions like `is_windows`, `uniwidth`, `determine_worker_count`, `add_arguments`, `print_safe`, `returncode_to_status`, `env_tuple_to_str` provide utility functionalities for platform detection, string manipulation, argument parsing, and result formatting. `add_arguments` hints at command-line options.
    * **Enums:** `ConsoleUser` and `TestResult` define distinct states and categories related to test execution. `TestResult` is particularly important for understanding how test outcomes are classified.
    * **`TAPParser`:** This class is crucial for handling test output in the TAP format, a common standard. I looked at its methods (`parse`, `parse_line`, `parse_async`) and inner classes (`Plan`, `Bailout`, `Test`, etc.) to understand how it processes TAP output and extracts meaningful information.
    * **`TestLogger` and its subclasses:**  I focused on the methods related to starting, logging, and finishing tests (`start`, `start_test`, `log`, `finish`). The different logger subclasses (`ConsoleLogger`, `TextLogfileBuilder`, `JsonLogfileBuilder`, `JunitBuilder`) clearly indicate the ability to produce logs in various formats. The `ConsoleLogger`'s complexity suggested it's responsible for the interactive display during test runs.

5. **Connect to the Prompt's Questions:**  As I analyzed the code, I actively looked for connections to the specific questions in the prompt:

    * **Functionality:** This was the primary goal of the analysis. I tried to describe what each part of the code *does*.
    * **Relationship to Reversing:** I looked for aspects that might be used in dynamic analysis or inspecting the behavior of running code. The ability to run tests under `gdb` and the handling of test output are relevant here.
    * **Binary/Kernel/Framework Knowledge:** I searched for interactions with the operating system, processes, and output streams. The handling of return codes, signals, and the mention of Linux and Android in the prompt context suggested these were relevant.
    * **Logical Inference:**  I examined parts of the code that involve decision-making, such as the `TAPParser`'s state machine and the `TestResult` enum. While specific input/output examples weren't immediately obvious without more context on the actual tests, I noted the parsing logic.
    * **User/Programming Errors:** I looked for error handling within the code and how invalid inputs or unexpected situations are dealt with (e.g., invalid `MESON_TESTTHREADS`, malformed TAP output).
    * **User Operation and Debugging:** The command-line arguments (`add_arguments`) provided clues about how a user might interact with the script. The logging mechanisms also serve as debugging aids.

6. **Synthesize and Summarize:** Finally, I organized my findings into a concise summary that addressed the prompt's requirements. I grouped related functionalities and used clear, descriptive language. I made sure to specifically call out the connections to reverse engineering, binary/kernel knowledge, and potential user errors, as requested. The decomposition into different aspects of functionality and the overall purpose helped create a structured summary.

7. **Review and Refine:** I reread the generated summary and compared it with my understanding of the code to ensure accuracy and completeness. I made minor edits for clarity and conciseness. For example, I double-checked that I had captured the different logging formats and the purpose of the `TAPParser`.

This iterative process of scanning, analyzing, connecting, and summarizing allowed me to break down the complex code into understandable components and address the specific questions in the prompt effectively.
这是 frida 动态 instrumentation 工具的一部分，位于 `frida/releng/meson/mesonbuild/mtest.py` 文件中。这个文件的主要功能是**提供一个灵活的测试运行工具**，用于执行 Frida 项目的测试套件。它允许开发者以多种方式运行测试，并生成不同格式的测试报告。

以下是该文件功能的详细列表：

**核心测试执行功能：**

1. **发现和加载测试:**  它能够读取 Meson 构建系统的输出信息，识别并加载项目中定义的测试用例和基准测试。
2. **多线程并行测试:**  支持使用多进程并行执行测试，以加速测试过程。可以通过命令行参数 `-j` 或环境变量 `MESON_TESTTHREADS` 控制并发进程数。
3. **测试过滤:**  允许用户通过命令行参数指定要运行的测试名称、子项目或测试套件，以便只运行特定的测试子集。
4. **测试重复运行:**  可以通过 `--repeat` 参数多次运行测试，用于检测间歇性故障。
5. **设置测试超时:**  可以为测试设置超时时间，防止测试无限期运行。可以通过 `--timeout-multiplier` 参数调整超时时间。
6. **处理测试返回值:**  能够理解测试程序返回的不同代码，例如 77 表示跳过测试，99 表示测试运行前就发生错误。
7. **捕获和记录测试输出:**  捕获测试的标准输出 (stdout) 和标准错误 (stderr)，并可以配置是否将它们合并到一起。
8. **生成多种格式的测试报告:**  支持生成纯文本、JSON 和 JUnit XML 格式的测试报告，方便集成到不同的持续集成系统中。

**与逆向方法的关系：**

`mtest.py` 作为 Frida 的测试工具，其存在和功能直接支持 Frida 的逆向工程能力。以下是几个例子：

*   **测试 Frida 的 API:**  Frida 提供了丰富的 API 用于动态代码插桩、hook 函数等逆向操作。`mtest.py` 会运行测试用例来验证这些 API 的功能是否正常，例如测试某个 hook 是否成功拦截了目标函数的调用，或者测试修改内存是否产生了预期的效果。
*   **测试 Frida 对不同平台的支持:**  Frida 需要在不同的操作系统（如 Linux、macOS、Windows、Android）和架构上工作。`mtest.py` 可以在这些平台上运行测试，确保 Frida 的核心功能在各种环境下都能正常工作。这对于逆向针对特定平台的软件至关重要。
*   **测试 Frida 的 Agent 功能:**  Frida 的 Agent 允许用户编写 JavaScript 代码来与目标进程交互。`mtest.py` 可以运行测试来验证 Agent 的加载、执行以及与 Frida Core 的通信是否正常。这对于动态分析和修改目标应用的行为非常重要。

**举例说明：**

假设 Frida 有一个功能是 hook `open` 系统调用，并打印打开的文件名。`mtest.py` 中可能存在一个测试用例，它的步骤如下：

1. **启动一个测试目标程序:**  这个程序会调用 `open` 函数打开一个文件。
2. **使用 Frida 加载一个 Agent:**  这个 Agent 会使用 Frida 的 API hook `open` 函数，并在 `open` 被调用时打印文件名到控制台。
3. **运行目标程序:**
4. **检查 `mtest.py` 捕获的输出:**  `mtest.py` 会检查 Agent 是否成功 hook 了 `open` 函数，并且打印的文件名是否与预期的一致。

**涉及到二进制底层，Linux, Android 内核及框架的知识：**

`mtest.py` 本身是一个 Python 脚本，不直接涉及二进制操作或内核交互。然而，它所测试的 Frida 代码却深入到这些领域。`mtest.py` 通过执行 Frida 的测试用例，间接地验证了 Frida 在以下方面的能力：

*   **二进制底层操作:** Frida 能够读取和修改目标进程的内存，包括代码段、数据段等。`mtest.py` 运行的测试会验证这些内存操作的正确性。例如，测试修改函数指令是否真的改变了函数的行为。
*   **Linux 内核交互:** Frida 需要与 Linux 内核进行交互来实现进程注入、内存访问、系统调用拦截等功能。`mtest.py` 运行的测试会验证 Frida 与内核交互的正确性，例如测试 hook 系统调用是否真的拦截了内核调用。
*   **Android 内核及框架:**  Frida 在 Android 平台上需要与 Android 的内核和框架进行交互，例如与 Dalvik/ART 虚拟机交互、访问系统服务等。`mtest.py` 在 Android 环境下运行的测试会验证 Frida 在这些方面的功能，例如测试 hook Java 方法是否成功。

**举例说明：**

*   **二进制底层:**  一个测试可能会使用 Frida 修改目标进程中某个函数的返回值为固定值，然后验证目标程序后续的行为是否符合预期。
*   **Linux 内核:**  一个测试可能会使用 Frida hook `read` 系统调用，并在 `read` 被调用时记录读取的字节数，然后验证记录的字节数是否正确。
*   **Android 内核及框架:**  一个测试可能会使用 Frida hook Android 系统框架中的 `Activity.onCreate()` 方法，并在该方法被调用时打印 Activity 的名称，然后验证打印的名称是否正确。

**如果做了逻辑推理，请给出假设输入与输出：**

`mtest.py` 本身主要负责执行测试，其逻辑推理体现在如何根据用户提供的参数（如测试名称、套件）来选择和执行相应的测试用例。

**假设输入：**

*   `args`: `["my_test"]`  (用户只想运行名为 "my_test" 的测试)
*   测试用例列表包含: `["test_a", "my_test", "another_test"]`

**逻辑推理：**

`mtest.py` 会遍历测试用例列表，并将每个测试用例的名称与用户提供的参数进行匹配。它会判断 "my_test" 是否在用户提供的 `args` 列表中。

**假设输出：**

`mtest.py` 只会执行名为 "my_test" 的测试用例。其他测试用例 "test_a" 和 "another_test" 将被跳过。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **错误的测试名称:** 用户在命令行中指定了一个不存在的测试名称，例如 `python mtest.py non_existent_test`。`mtest.py` 会报告找不到该测试。
2. **错误的套件名称:** 用户指定了一个不存在的测试套件，例如 `python mtest.py --suite invalid_suite`。`mtest.py` 会报告找不到该套件。
3. **无效的并发进程数:** 用户提供了非法的并发进程数，例如 `python mtest.py -j 0` 或 `python mtest.py -j abc`。`mtest.py` 可能会使用默认值或报错。
4. **测试超时时间过短:** 用户设置的测试超时时间过短，导致一些正常的测试被误判为超时失败。
5. **环境依赖问题:** 测试用例可能依赖特定的环境变量或外部程序，如果环境配置不正确，会导致测试失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

通常，开发者会通过命令行来运行 `mtest.py`。以下是一个典型的操作流程：

1. **切换到 Frida 的构建目录:**  开发者通常会在 Frida 的构建目录中执行测试，因为 `mtest.py` 需要访问构建生成的相关文件（例如测试可执行文件）。
2. **执行 `mtest.py` 脚本:** 开发者在终端输入 `python frida/releng/meson/mesonbuild/mtest.py`，这会启动测试运行工具。
3. **添加命令行参数 (可选):** 开发者可以根据需要添加各种命令行参数来控制测试行为，例如指定要运行的测试、设置并发数、选择报告格式等。例如：
    *   `python frida/releng/meson/mesonbuild/mtest.py --list` (列出所有可用的测试)
    *   `python frida/releng/meson/mesonbuild/mtest.py my_test` (运行名为 "my_test" 的测试)
    *   `python frida/releng/meson/mesonbuild/mtest.py --suite core` (运行属于 "core" 套件的测试)
    *   `python frida/releng/meson/mesonbuild/mtest.py -j 4` (使用 4 个进程并行运行测试)
4. **查看测试输出和报告:** `mtest.py` 会在终端输出测试运行的进度和结果。如果指定了报告格式，还会生成相应的报告文件。

**作为调试线索：**

当测试失败时，开发者会检查 `mtest.py` 的输出和生成的日志文件，以获取调试信息：

*   **失败的测试名称:** 确定哪个测试用例失败了。
*   **错误信息和堆栈跟踪:** 查看测试输出中是否有相关的错误信息或堆栈跟踪，这有助于定位问题所在。
*   **标准输出和标准错误:**  检查测试的标准输出和标准错误，看是否有额外的调试信息或错误提示。
*   **测试命令:**  `mtest.py` 会记录执行的测试命令，开发者可以手动执行该命令来进一步调试。
*   **日志文件:**  查看生成的日志文件，了解更详细的测试运行过程和输出信息。

**总结 `mtest.py` 的功能 (第 1 部分)：**

`frida/releng/meson/mesonbuild/mtest.py` 的主要功能是作为一个**灵活且可配置的测试运行工具**，用于执行 Frida 项目的测试套件。它能够**发现、加载和执行测试用例**，支持**多线程并行**，允许**测试过滤和重复运行**，并能生成**多种格式的测试报告**。这个工具对于确保 Frida 项目的质量和稳定性至关重要，特别是考虑到 Frida 涉及到底层二进制操作和跨平台支持等复杂性。它通过运行各种测试用例来验证 Frida 的核心功能，例如 API 的正确性、平台兼容性以及 Agent 功能的有效性。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2017 The Meson development team

# A tool to run tests in many different ways.
from __future__ import annotations

from pathlib import Path
from collections import deque
from contextlib import suppress
from copy import deepcopy
from fnmatch import fnmatch
import argparse
import asyncio
import datetime
import enum
import json
import multiprocessing
import os
import pickle
import platform
import random
import re
import signal
import subprocess
import shlex
import sys
import textwrap
import time
import typing as T
import unicodedata
import xml.etree.ElementTree as et

from . import build
from . import environment
from . import mlog
from .coredata import MesonVersionMismatchException, major_versions_differ
from .coredata import version as coredata_version
from .mesonlib import (MesonException, OptionKey, OrderedSet, RealPathAction,
                       get_wine_shortpath, join_args, split_args, setup_vsenv)
from .mintro import get_infodir, load_info_file
from .programs import ExternalProgram
from .backend.backends import TestProtocol, TestSerialisation

if T.TYPE_CHECKING:
    TYPE_TAPResult = T.Union['TAPParser.Test',
                             'TAPParser.Error',
                             'TAPParser.Version',
                             'TAPParser.Plan',
                             'TAPParser.UnknownLine',
                             'TAPParser.Bailout']


# GNU autotools interprets a return code of 77 from tests it executes to
# mean that the test should be skipped.
GNU_SKIP_RETURNCODE = 77

# GNU autotools interprets a return code of 99 from tests it executes to
# mean that the test failed even before testing what it is supposed to test.
GNU_ERROR_RETURNCODE = 99

# Exit if 3 Ctrl-C's are received within one second
MAX_CTRLC = 3

# Define unencodable xml characters' regex for replacing them with their
# printable representation
UNENCODABLE_XML_UNICHRS: T.List[T.Tuple[int, int]] = [
    (0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F), (0x7F, 0x84),
    (0x86, 0x9F), (0xFDD0, 0xFDEF), (0xFFFE, 0xFFFF)]
# Not narrow build
if sys.maxunicode >= 0x10000:
    UNENCODABLE_XML_UNICHRS.extend([
        (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF),
        (0x3FFFE, 0x3FFFF), (0x4FFFE, 0x4FFFF),
        (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF),
        (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF),
        (0x9FFFE, 0x9FFFF), (0xAFFFE, 0xAFFFF),
        (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF),
        (0xDFFFE, 0xDFFFF), (0xEFFFE, 0xEFFFF),
        (0xFFFFE, 0xFFFFF), (0x10FFFE, 0x10FFFF)])
UNENCODABLE_XML_CHR_RANGES = [fr'{chr(low)}-{chr(high)}' for (low, high) in UNENCODABLE_XML_UNICHRS]
UNENCODABLE_XML_CHRS_RE = re.compile('([' + ''.join(UNENCODABLE_XML_CHR_RANGES) + '])')


def is_windows() -> bool:
    platname = platform.system().lower()
    return platname == 'windows'

def is_cygwin() -> bool:
    return sys.platform == 'cygwin'

UNIWIDTH_MAPPING = {'F': 2, 'H': 1, 'W': 2, 'Na': 1, 'N': 1, 'A': 1}
def uniwidth(s: str) -> int:
    result = 0
    for c in s:
        w = unicodedata.east_asian_width(c)
        result += UNIWIDTH_MAPPING[w]
    return result

def determine_worker_count() -> int:
    varname = 'MESON_TESTTHREADS'
    if varname in os.environ:
        try:
            num_workers = int(os.environ[varname])
        except ValueError:
            print(f'Invalid value in {varname}, using 1 thread.')
            num_workers = 1
    else:
        try:
            # Fails in some weird environments such as Debian
            # reproducible build.
            num_workers = multiprocessing.cpu_count()
        except Exception:
            num_workers = 1
    return num_workers

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--maxfail', default=0, type=int,
                        help='Number of failing tests before aborting the '
                        'test run. (default: 0, to disable aborting on failure)')
    parser.add_argument('--repeat', default=1, dest='repeat', type=int,
                        help='Number of times to run the tests.')
    parser.add_argument('--no-rebuild', default=False, action='store_true',
                        help='Do not rebuild before running tests.')
    parser.add_argument('--gdb', default=False, dest='gdb', action='store_true',
                        help='Run test under gdb.')
    parser.add_argument('--gdb-path', default='gdb', dest='gdb_path',
                        help='Path to the gdb binary (default: gdb).')
    parser.add_argument('--list', default=False, dest='list', action='store_true',
                        help='List available tests.')
    parser.add_argument('--wrapper', default=None, dest='wrapper', type=split_args,
                        help='wrapper to run tests with (e.g. Valgrind)')
    parser.add_argument('-C', dest='wd', action=RealPathAction,
                        help='directory to cd into before running')
    parser.add_argument('--suite', default=[], dest='include_suites', action='append', metavar='SUITE',
                        help='Only run tests belonging to the given suite.')
    parser.add_argument('--no-suite', default=[], dest='exclude_suites', action='append', metavar='SUITE',
                        help='Do not run tests belonging to the given suite.')
    parser.add_argument('--no-stdsplit', default=True, dest='split', action='store_false',
                        help='Do not split stderr and stdout in test logs.')
    parser.add_argument('--print-errorlogs', default=False, action='store_true',
                        help="Whether to print failing tests' logs.")
    parser.add_argument('--benchmark', default=False, action='store_true',
                        help="Run benchmarks instead of tests.")
    parser.add_argument('--logbase', default='testlog',
                        help="Base name for log file.")
    parser.add_argument('-j', '--num-processes', default=determine_worker_count(), type=int,
                        help='How many parallel processes to use.')
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
                        help='Do not redirect stdout and stderr')
    parser.add_argument('-q', '--quiet', default=False, action='store_true',
                        help='Produce less output to the terminal.')
    parser.add_argument('-t', '--timeout-multiplier', type=float, default=None,
                        help='Define a multiplier for test timeout, for example '
                        ' when running tests in particular conditions they might take'
                        ' more time to execute. (<= 0 to disable timeout)')
    parser.add_argument('--setup', default=None, dest='setup',
                        help='Which test setup to use.')
    parser.add_argument('--test-args', default=[], type=split_args,
                        help='Arguments to pass to the specified test(s) or all tests')
    parser.add_argument('args', nargs='*',
                        help='Optional list of test names to run. "testname" to run all tests with that name, '
                        '"subprojname:testname" to specifically run "testname" from "subprojname", '
                        '"subprojname:" to run all tests defined by "subprojname".')


def print_safe(s: str) -> None:
    end = '' if s[-1] == '\n' else '\n'
    try:
        print(s, end=end)
    except UnicodeEncodeError:
        s = s.encode('ascii', errors='backslashreplace').decode('ascii')
        print(s, end=end)

def join_lines(a: str, b: str) -> str:
    if not a:
        return b
    if not b:
        return a
    return a + '\n' + b

def dashes(s: str, dash: str, cols: int) -> str:
    if not s:
        return dash * cols
    s = ' ' + s + ' '
    width = uniwidth(s)
    first = (cols - width) // 2
    s = dash * first + s
    return s + dash * (cols - first - width)

def returncode_to_status(retcode: int) -> str:
    # Note: We can't use `os.WIFSIGNALED(result.returncode)` and the related
    # functions here because the status returned by subprocess is munged. It
    # returns a negative value if the process was killed by a signal rather than
    # the raw status returned by `wait()`. Also, If a shell sits between Meson
    # the actual unit test that shell is likely to convert a termination due
    # to a signal into an exit status of 128 plus the signal number.
    if retcode < 0:
        signum = -retcode
        try:
            signame = signal.Signals(signum).name
        except ValueError:
            signame = 'SIGinvalid'
        return f'killed by signal {signum} {signame}'

    if retcode <= 128:
        return f'exit status {retcode}'

    signum = retcode - 128
    try:
        signame = signal.Signals(signum).name
    except ValueError:
        signame = 'SIGinvalid'
    return f'(exit status {retcode} or signal {signum} {signame})'

# TODO for Windows
sh_quote: T.Callable[[str], str] = lambda x: x
if not is_windows():
    sh_quote = shlex.quote

def env_tuple_to_str(env: T.Iterable[T.Tuple[str, str]]) -> str:
    return ''.join(["{}={} ".format(k, sh_quote(v)) for k, v in env])


class TestException(MesonException):
    pass


@enum.unique
class ConsoleUser(enum.Enum):

    # the logger can use the console
    LOGGER = 0

    # the console is used by gdb
    GDB = 1

    # the console is used to write stdout/stderr
    STDOUT = 2


@enum.unique
class TestResult(enum.Enum):

    PENDING = 'PENDING'
    RUNNING = 'RUNNING'
    OK = 'OK'
    TIMEOUT = 'TIMEOUT'
    INTERRUPT = 'INTERRUPT'
    SKIP = 'SKIP'
    FAIL = 'FAIL'
    EXPECTEDFAIL = 'EXPECTEDFAIL'
    UNEXPECTEDPASS = 'UNEXPECTEDPASS'
    ERROR = 'ERROR'

    @staticmethod
    def maxlen() -> int:
        return 14  # len(UNEXPECTEDPASS)

    def is_ok(self) -> bool:
        return self in {TestResult.OK, TestResult.EXPECTEDFAIL}

    def is_bad(self) -> bool:
        return self in {TestResult.FAIL, TestResult.TIMEOUT, TestResult.INTERRUPT,
                        TestResult.UNEXPECTEDPASS, TestResult.ERROR}

    def is_finished(self) -> bool:
        return self not in {TestResult.PENDING, TestResult.RUNNING}

    def was_killed(self) -> bool:
        return self in (TestResult.TIMEOUT, TestResult.INTERRUPT)

    def colorize(self, s: str) -> mlog.AnsiDecorator:
        if self.is_bad():
            decorator = mlog.red
        elif self in (TestResult.SKIP, TestResult.EXPECTEDFAIL):
            decorator = mlog.yellow
        elif self.is_finished():
            decorator = mlog.green
        else:
            decorator = mlog.blue
        return decorator(s)

    def get_text(self, colorize: bool) -> str:
        result_str = '{res:{reslen}}'.format(res=self.value, reslen=self.maxlen())
        return self.colorize(result_str).get_text(colorize)

    def get_command_marker(self) -> str:
        return str(self.colorize('>>> '))


class TAPParser:
    class Plan(T.NamedTuple):
        num_tests: int
        late: bool
        skipped: bool
        explanation: T.Optional[str]

    class Bailout(T.NamedTuple):
        message: str

    class Test(T.NamedTuple):
        number: int
        name: str
        result: TestResult
        explanation: T.Optional[str]

        def __str__(self) -> str:
            return f'{self.number} {self.name}'.strip()

    class Error(T.NamedTuple):
        message: str

    class UnknownLine(T.NamedTuple):
        message: str
        lineno: int

    class Version(T.NamedTuple):
        version: int

    _MAIN = 1
    _AFTER_TEST = 2
    _YAML = 3

    _RE_BAILOUT = re.compile(r'Bail out!\s*(.*)')
    _RE_DIRECTIVE = re.compile(r'(?:\s*\#\s*([Ss][Kk][Ii][Pp]\S*|[Tt][Oo][Dd][Oo])\b\s*(.*))?')
    _RE_PLAN = re.compile(r'1\.\.([0-9]+)' + _RE_DIRECTIVE.pattern)
    _RE_TEST = re.compile(r'((?:not )?ok)\s*(?:([0-9]+)\s*)?([^#]*)' + _RE_DIRECTIVE.pattern)
    _RE_VERSION = re.compile(r'TAP version ([0-9]+)')
    _RE_YAML_START = re.compile(r'(\s+)---.*')
    _RE_YAML_END = re.compile(r'\s+\.\.\.\s*')

    found_late_test = False
    bailed_out = False
    plan: T.Optional[Plan] = None
    lineno = 0
    num_tests = 0
    yaml_lineno: T.Optional[int] = None
    yaml_indent = ''
    state = _MAIN
    version = 12

    def parse_test(self, ok: bool, num: int, name: str, directive: T.Optional[str], explanation: T.Optional[str]) -> \
            T.Generator[T.Union['TAPParser.Test', 'TAPParser.Error'], None, None]:
        name = name.strip()
        explanation = explanation.strip() if explanation else None
        if directive is not None:
            directive = directive.upper()
            if directive.startswith('SKIP'):
                if ok:
                    yield self.Test(num, name, TestResult.SKIP, explanation)
                    return
            elif directive == 'TODO':
                yield self.Test(num, name, TestResult.UNEXPECTEDPASS if ok else TestResult.EXPECTEDFAIL, explanation)
                return
            else:
                yield self.Error(f'invalid directive "{directive}"')

        yield self.Test(num, name, TestResult.OK if ok else TestResult.FAIL, explanation)

    async def parse_async(self, lines: T.AsyncIterator[str]) -> T.AsyncIterator[TYPE_TAPResult]:
        async for line in lines:
            for event in self.parse_line(line):
                yield event
        for event in self.parse_line(None):
            yield event

    def parse(self, io: T.Iterator[str]) -> T.Iterator[TYPE_TAPResult]:
        for line in io:
            yield from self.parse_line(line)
        yield from self.parse_line(None)

    def parse_line(self, line: T.Optional[str]) -> T.Iterator[TYPE_TAPResult]:
        if line is not None:
            self.lineno += 1
            line = line.rstrip()

            # YAML blocks are only accepted after a test
            if self.state == self._AFTER_TEST:
                if self.version >= 13:
                    m = self._RE_YAML_START.match(line)
                    if m:
                        self.state = self._YAML
                        self.yaml_lineno = self.lineno
                        self.yaml_indent = m.group(1)
                        return
                self.state = self._MAIN

            elif self.state == self._YAML:
                if self._RE_YAML_END.match(line):
                    self.state = self._MAIN
                    return
                if line.startswith(self.yaml_indent):
                    return
                yield self.Error(f'YAML block not terminated (started on line {self.yaml_lineno})')
                self.state = self._MAIN

            assert self.state == self._MAIN
            if not line or line.startswith('#'):
                return

            m = self._RE_TEST.match(line)
            if m:
                if self.plan and self.plan.late and not self.found_late_test:
                    yield self.Error('unexpected test after late plan')
                    self.found_late_test = True
                self.num_tests += 1
                num = self.num_tests if m.group(2) is None else int(m.group(2))
                if num != self.num_tests:
                    yield self.Error('out of order test numbers')
                yield from self.parse_test(m.group(1) == 'ok', num,
                                           m.group(3), m.group(4), m.group(5))
                self.state = self._AFTER_TEST
                return

            m = self._RE_PLAN.match(line)
            if m:
                if self.plan:
                    yield self.Error('more than one plan found')
                else:
                    num_tests = int(m.group(1))
                    skipped = num_tests == 0
                    if m.group(2):
                        if m.group(2).upper().startswith('SKIP'):
                            if num_tests > 0:
                                yield self.Error('invalid SKIP directive for plan')
                            skipped = True
                        else:
                            yield self.Error('invalid directive for plan')
                    self.plan = self.Plan(num_tests=num_tests, late=(self.num_tests > 0),
                                          skipped=skipped, explanation=m.group(3))
                    yield self.plan
                return

            m = self._RE_BAILOUT.match(line)
            if m:
                yield self.Bailout(m.group(1))
                self.bailed_out = True
                return

            m = self._RE_VERSION.match(line)
            if m:
                # The TAP version is only accepted as the first line
                if self.lineno != 1:
                    yield self.Error('version number must be on the first line')
                    return
                self.version = int(m.group(1))
                if self.version < 13:
                    yield self.Error('version number should be at least 13')
                else:
                    yield self.Version(version=self.version)
                return

            # unknown syntax
            yield self.UnknownLine(line, self.lineno)
        else:
            # end of file
            if self.state == self._YAML:
                yield self.Error(f'YAML block not terminated (started on line {self.yaml_lineno})')

            if not self.bailed_out and self.plan and self.num_tests != self.plan.num_tests:
                if self.num_tests < self.plan.num_tests:
                    yield self.Error(f'Too few tests run (expected {self.plan.num_tests}, got {self.num_tests})')
                else:
                    yield self.Error(f'Too many tests run (expected {self.plan.num_tests}, got {self.num_tests})')

class TestLogger:
    def flush(self) -> None:
        pass

    def start(self, harness: 'TestHarness') -> None:
        pass

    def start_test(self, harness: 'TestHarness', test: 'TestRun') -> None:
        pass

    def log_subtest(self, harness: 'TestHarness', test: 'TestRun', s: str, res: TestResult) -> None:
        pass

    def log(self, harness: 'TestHarness', result: 'TestRun') -> None:
        pass

    async def finish(self, harness: 'TestHarness') -> None:
        pass

    def close(self) -> None:
        pass


class TestFileLogger(TestLogger):
    def __init__(self, filename: str, errors: str = 'replace') -> None:
        self.filename = filename
        self.file = open(filename, 'w', encoding='utf-8', errors=errors)

    def close(self) -> None:
        if self.file:
            self.file.close()
            self.file = None


class ConsoleLogger(TestLogger):
    ASCII_SPINNER = ['..', ':.', '.:']
    SPINNER = ["\U0001f311", "\U0001f312", "\U0001f313", "\U0001f314",
               "\U0001f315", "\U0001f316", "\U0001f317", "\U0001f318"]

    SCISSORS = "\u2700 "
    HLINE = "\u2015"
    RTRI = "\u25B6 "

    def __init__(self) -> None:
        self.running_tests: OrderedSet['TestRun'] = OrderedSet()
        self.progress_test: T.Optional['TestRun'] = None
        self.progress_task: T.Optional[asyncio.Future] = None
        self.max_left_width = 0
        self.stop = False
        # TODO: before 3.10 this cannot be created immediately, because
        # it will create a new event loop
        self.update: asyncio.Event
        self.should_erase_line = ''
        self.test_count = 0
        self.started_tests = 0
        self.spinner_index = 0
        try:
            self.cols, _ = os.get_terminal_size(1)
            self.is_tty = True
        except OSError:
            self.cols = 80
            self.is_tty = False

        self.output_start = dashes(self.SCISSORS, self.HLINE, self.cols - 2)
        self.output_end = dashes('', self.HLINE, self.cols - 2)
        self.sub = self.RTRI
        self.spinner = self.SPINNER
        try:
            self.output_start.encode(sys.stdout.encoding or 'ascii')
        except UnicodeEncodeError:
            self.output_start = dashes('8<', '-', self.cols - 2)
            self.output_end = dashes('', '-', self.cols - 2)
            self.sub = '| '
            self.spinner = self.ASCII_SPINNER

    def flush(self) -> None:
        if self.should_erase_line:
            print(self.should_erase_line, end='')
            self.should_erase_line = ''

    def print_progress(self, line: str) -> None:
        print(self.should_erase_line, line, sep='', end='\r')
        self.should_erase_line = '\x1b[K'

    def request_update(self) -> None:
        self.update.set()

    def emit_progress(self, harness: 'TestHarness') -> None:
        if self.progress_test is None:
            self.flush()
            return

        if len(self.running_tests) == 1:
            count = f'{self.started_tests}/{self.test_count}'
        else:
            count = '{}-{}/{}'.format(self.started_tests - len(self.running_tests) + 1,
                                      self.started_tests, self.test_count)

        left = '[{}] {} '.format(count, self.spinner[self.spinner_index])
        self.spinner_index = (self.spinner_index + 1) % len(self.spinner)

        right = '{spaces} {dur:{durlen}}'.format(
            spaces=' ' * TestResult.maxlen(),
            dur=int(time.time() - self.progress_test.starttime),
            durlen=harness.duration_max_len)
        if self.progress_test.timeout:
            right += '/{timeout:{durlen}}'.format(
                timeout=self.progress_test.timeout,
                durlen=harness.duration_max_len)
        right += 's'
        details = self.progress_test.get_details()
        if details:
            right += '   ' + details

        line = harness.format(self.progress_test, colorize=True,
                              max_left_width=self.max_left_width,
                              left=left, right=right)
        self.print_progress(line)

    def start(self, harness: 'TestHarness') -> None:
        async def report_progress() -> None:
            loop = asyncio.get_running_loop()
            next_update = 0.0
            self.request_update()
            while not self.stop:
                await self.update.wait()
                self.update.clear()
                # We may get here simply because the progress line has been
                # overwritten, so do not always switch.  Only do so every
                # second, or if the printed test has finished
                if loop.time() >= next_update:
                    self.progress_test = None
                    next_update = loop.time() + 1
                    loop.call_at(next_update, self.request_update)

                if (self.progress_test and
                        self.progress_test.res is not TestResult.RUNNING):
                    self.progress_test = None

                if not self.progress_test:
                    if not self.running_tests:
                        continue
                    # Pick a test in round robin order
                    self.progress_test = self.running_tests.pop(last=False)
                    self.running_tests.add(self.progress_test)

                self.emit_progress(harness)
            self.flush()

        self.update = asyncio.Event()
        self.test_count = harness.test_count
        self.cols = max(self.cols, harness.max_left_width + 30)

        if self.is_tty and not harness.need_console:
            # Account for "[aa-bb/cc] OO " in the progress report
            self.max_left_width = 3 * len(str(self.test_count)) + 8
            self.progress_task = asyncio.ensure_future(report_progress())

    def start_test(self, harness: 'TestHarness', test: 'TestRun') -> None:
        if test.verbose and test.cmdline:
            self.flush()
            print(harness.format(test, mlog.colorize_console(),
                                 max_left_width=self.max_left_width,
                                 right=test.res.get_text(mlog.colorize_console())))
            print(test.res.get_command_marker() + test.cmdline)
            if test.direct_stdout:
                print(self.output_start, flush=True)
            elif not test.needs_parsing:
                print(flush=True)

        self.started_tests += 1
        self.running_tests.add(test)
        self.running_tests.move_to_end(test, last=False)
        self.request_update()

    def shorten_log(self, harness: 'TestHarness', result: 'TestRun') -> str:
        if not result.verbose and not harness.options.print_errorlogs:
            return ''

        log = result.get_log(mlog.colorize_console(),
                             stderr_only=result.needs_parsing)
        if result.verbose:
            return log

        lines = log.splitlines()
        if len(lines) < 100:
            return log
        else:
            return str(mlog.bold('Listing only the last 100 lines from a long log.\n')) + '\n'.join(lines[-100:])

    def print_log(self, harness: 'TestHarness', result: 'TestRun') -> None:
        if not result.verbose:
            cmdline = result.cmdline
            if not cmdline:
                print(result.res.get_command_marker() + result.stdo)
                return
            print(result.res.get_command_marker() + cmdline)

        log = self.shorten_log(harness, result)
        if log:
            print(self.output_start)
            print_safe(log)
            print(self.output_end)

    def log_subtest(self, harness: 'TestHarness', test: 'TestRun', s: str, result: TestResult) -> None:
        if test.verbose or (harness.options.print_errorlogs and result.is_bad()):
            self.flush()
            print(harness.format(test, mlog.colorize_console(), max_left_width=self.max_left_width,
                                 prefix=self.sub,
                                 middle=s,
                                 right=result.get_text(mlog.colorize_console())), flush=True)

            self.request_update()

    def log(self, harness: 'TestHarness', result: 'TestRun') -> None:
        self.running_tests.remove(result)
        if result.res is TestResult.TIMEOUT and (result.verbose or
                                                 harness.options.print_errorlogs):
            self.flush()
            print(f'{result.name} time out (After {result.timeout} seconds)')

        if not harness.options.quiet or not result.res.is_ok():
            self.flush()
            if result.cmdline and result.direct_stdout:
                print(self.output_end)
                print(harness.format(result, mlog.colorize_console(), max_left_width=self.max_left_width))
            else:
                print(harness.format(result, mlog.colorize_console(), max_left_width=self.max_left_width),
                      flush=True)
                if result.verbose or result.res.is_bad():
                    self.print_log(harness, result)
            if result.warnings:
                print(flush=True)
                for w in result.warnings:
                    print(w, flush=True)
                print(flush=True)
            if result.verbose or result.res.is_bad():
                print(flush=True)

        self.request_update()

    async def finish(self, harness: 'TestHarness') -> None:
        self.stop = True
        self.request_update()
        if self.progress_task:
            await self.progress_task

        if harness.collected_failures and \
                (harness.options.print_errorlogs or harness.options.verbose):
            print("\nSummary of Failures:\n")
            for i, result in enumerate(harness.collected_failures, 1):
                print(harness.format(result, mlog.colorize_console()))

        print(harness.summary())


class TextLogfileBuilder(TestFileLogger):
    def start(self, harness: 'TestHarness') -> None:
        self.file.write(f'Log of Meson test suite run on {datetime.datetime.now().isoformat()}\n\n')
        inherit_env = env_tuple_to_str(os.environ.items())
        self.file.write(f'Inherited environment: {inherit_env}\n\n')

    def log(self, harness: 'TestHarness', result: 'TestRun') -> None:
        title = f'{result.num}/{harness.test_count}'
        self.file.write(dashes(title, '=', 78) + '\n')
        self.file.write('test:         ' + result.name + '\n')
        starttime_str = time.strftime("%H:%M:%S", time.gmtime(result.starttime))
        self.file.write('start time:   ' + starttime_str + '\n')
        self.file.write('duration:     ' + '%.2fs' % result.duration + '\n')
        self.file.write('result:       ' + result.get_exit_status() + '\n')
        if result.cmdline:
            self.file.write('command:      ' + result.cmdline + '\n')
        if result.stdo:
            name = 'stdout' if harness.options.split else 'output'
            self.file.write(dashes(name, '-', 78) + '\n')
            self.file.write(result.stdo)
        if result.stde:
            self.file.write(dashes('stderr', '-', 78) + '\n')
            self.file.write(result.stde)
        self.file.write(dashes('', '=', 78) + '\n\n')

    async def finish(self, harness: 'TestHarness') -> None:
        if harness.collected_failures:
            self.file.write("\nSummary of Failures:\n\n")
            for i, result in enumerate(harness.collected_failures, 1):
                self.file.write(harness.format(result, False) + '\n')
        self.file.write(harness.summary())

        print(f'Full log written to {self.filename}')


class JsonLogfileBuilder(TestFileLogger):
    def log(self, harness: 'TestHarness', result: 'TestRun') -> None:
        jresult: T.Dict[str, T.Any] = {
            'name': result.name,
            'stdout': result.stdo,
            'result': result.res.value,
            'starttime': result.starttime,
            'duration': result.duration,
            'returncode': result.returncode,
            'env': result.env,
            'command': result.cmd,
        }
        if result.stde:
            jresult['stderr'] = result.stde
        self.file.write(json.dumps(jresult) + '\n')


class JunitBuilder(TestLogger):

    """Builder for Junit test results.

    Junit is impossible to stream out, it requires attributes counting the
    total number of tests, failures, skips, and errors in the root element
    and in each test suite. As such, we use a builder class to track each
    test case, and calculate all metadata before writing it out.

    For tests with multiple results (like from a TAP test), we record the
    test as a suite with the project_name.test_name. This allows us to track
    each result separately. For tests with only one result (such as exit-code
    tests) we record each one into a suite with the name project_name. The use
    of the project_name allows us to sort subproject tests separately from
    the root project.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.root = et.Element(
            'testsuites', tests='0', errors='0', failures='0')
        self.suites: T.Dict[str, et.Element] = {}

    def log(self, harness: 'TestHarness', test: 'TestRun') -> None:
        """Log a single test case."""
        if test.junit is not None:
            for suite in test.junit.findall('.//testsuite'):
                # Assume that we don't need to merge anything here...
                suite.attrib['name'] = '{}.{}.{}'.format(test.project, test.name, suite.attrib['name'])

                # GTest can inject invalid attributes
                for case in suite.findall('.//testcase[@result]'):
                    del case.attrib['result']
                for case in suite.findall('.//testcase[@timestamp]'):
                    del case.attrib['timestamp']
                for case in suite.findall('.//testcase[@file]'):
                    del case.attrib['file']
                for case in suite.findall('.//testcase[@line]'):
                    del case.attrib['line']
                self.root.append(suite)
            return

        # In this case we have a test binary with multiple results.
        # We want to record this so that each result is recorded
        # separately
        if test.results:
            suitename = f'{test.project}.{test.name}'
            assert suitename not in self.suites or harness.options.repeat > 1, 'duplicate suite'

            suite = self.suites[suitename] = et.Element(
                'testsuite',
                name=suitename,
                tests=str(len(test.results)),
                errors=str(sum(1 for r in test.results if r.result in
                               {TestResult.INTERRUPT, TestResult.ERROR})),
                failures=str(sum(1 for r in test.results if r.result in
                                 {TestResult.FAIL, TestResult.UNEXPECTEDPASS, TestResult.TIMEOUT})),
                skipped=str
```