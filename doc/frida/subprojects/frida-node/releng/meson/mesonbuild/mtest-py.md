Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding - What is this?**

The first line is crucial: "这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件". This immediately tells us several things:

* **Project:**  This code belongs to the `frida` project.
* **Subproject:** It's specifically part of the `frida-node` subproject.
* **Location:** The file path `releng/meson/mesonbuild/mtest.py` gives context about its role in the build process. `releng` often suggests release engineering or related tasks, and `meson` indicates the build system used. `mtest.py` strongly suggests it's related to *testing*.
* **Tool Type:** It's described as a "dynamic instrumentation tool," linking it to Frida's core functionality.

**2. Code Structure - Skimming for Key Components**

I'd quickly skim through the code, looking for major sections and keywords. I see:

* **Imports:** A wide variety of standard Python libraries (`pathlib`, `collections`, `argparse`, `asyncio`, `os`, `subprocess`, `re`, etc.) and some internal `mesonbuild` modules. This hints at the complexity and scope of the script.
* **Constants:**  `GNU_SKIP_RETURNCODE`, `GNU_ERROR_RETURNCODE`, `MAX_CTRLC`, `UNENCODABLE_XML_UNICHRS`. These suggest interactions with external processes and specific handling of return codes, as well as dealing with different character encodings.
* **Functions:**  Lots of functions like `is_windows`, `determine_worker_count`, `add_arguments`, `print_safe`, `returncode_to_status`, `env_tuple_to_str`. These suggest utility functions for platform detection, argument parsing, output formatting, and handling process results.
* **Enums:** `ConsoleUser`, `TestResult`. Enums are used for defining distinct states or categories. `TestResult` is a strong indicator of the script's core purpose.
* **Classes:** `TAPParser`, `TestLogger`, `TestFileLogger`, `ConsoleLogger`, `TextLogfileBuilder`, `JsonLogfileBuilder`, `JunitBuilder`. The presence of multiple classes related to logging and parsing (especially `TAPParser`) reinforces the idea of a testing framework.
* **Argument Parsing:** The `add_arguments` function clearly defines command-line options, which is a standard practice for tools.

**3. Identifying Core Functionality - The Testing Angle**

The name `mtest.py`, the `TestResult` enum, the logging classes, and the `TAPParser` class strongly point to this script being a *test runner*. It likely:

* **Discovers tests:**  Although not explicitly shown in this snippet, it will eventually get a list of tests to run.
* **Executes tests:**  The use of `subprocess` strongly suggests it runs external test programs.
* **Tracks test status:**  The `TestResult` enum and logging mechanisms are key for this.
* **Reports results:**  The different logger classes (console, text file, JSON, JUnit) indicate various reporting formats.
* **Handles test outcomes:**  The return code constants and logic in `returncode_to_status` show how it interprets test failures, skips, etc.

**4. Connecting to Reverse Engineering**

With the understanding that it's a test runner for Frida, the connection to reverse engineering becomes clearer:

* **Testing Frida's capabilities:** Frida is a dynamic instrumentation tool used for reverse engineering and security analysis. This script is likely used to test Frida's core features by running tests that exercise its ability to inject code, hook functions, intercept API calls, etc.
* **Testing Frida's interaction with target processes:** The tests likely involve running actual applications or system components and using Frida to interact with them.

**5. Identifying Binary/Kernel/Framework Connections**

The code contains several hints of interaction with lower-level aspects:

* **`subprocess`:**  Executing external programs inherently involves interacting with the operating system.
* **Return Codes:**  Understanding return codes is crucial for interpreting the success or failure of executed binaries. The handling of specific GNU return codes further emphasizes this.
* **Signal Handling:** The `signal` import and the logic for interpreting negative return codes (signals) indicate awareness of process termination mechanisms.
* **Platform Detection:** `is_windows`, `is_cygwin` suggest platform-specific behavior.
* **Environment Variables:**  The handling of `MESON_TESTTHREADS` and the logging of the inherited environment are relevant to how processes are launched and configured.

**6. Logical Reasoning (Hypothetical Input/Output)**

Without seeing how tests are defined and discovered, it's hard to give precise input/output examples. However, we can infer:

* **Input:** Command-line arguments (test names, suites, options like `--verbose`), configuration files (if any), and the actual test executables.
* **Output:**  Console output (progress, summaries), log files in various formats (text, JSON, JUnit). The output will vary depending on the test results. A successful run would show "OK" for all tests; failures would be reported with details.

**7. Common User Errors**

Based on the command-line arguments and the nature of testing, potential user errors include:

* **Incorrect test names:** Typos in test names passed as arguments.
* **Invalid suite names:** Specifying suites that don't exist.
* **Resource contention:** Running too many tests in parallel (`-j`) might lead to timeouts or failures in resource-constrained environments.
* **Environment issues:**  Tests might rely on specific environment variables or configurations that are not set up correctly.

**8. User Operations Leading Here (Debugging Clues)**

A developer might end up looking at this code when:

* **Debugging test failures:**  Understanding *how* tests are run is essential for diagnosing problems.
* **Adding new tests:**  They might need to understand the testing framework to integrate new tests.
* **Modifying the test infrastructure:**  Changes to the test runner itself would require working with this code.
* **Investigating build system issues:**  Since this script is part of the Meson build process, build failures related to testing could lead here.

**9. Summarizing Functionality (Part 1)**

Based on the analysis above, the core function of `mtest.py` (in this first part of the code) is to **provide a framework for running and reporting the results of tests for the Frida dynamic instrumentation tool**. It handles:

* **Parsing command-line arguments** to control test execution.
* **Defining and managing the state of test execution** (e.g., pending, running, success, failure).
* **Formatting output** to the console in a user-friendly way, including progress updates.
* **Providing different logging mechanisms** for saving test results in various formats (text, JSON, JUnit).
* **Interacting with external test processes** and interpreting their results (return codes, signals).
* **Providing a TAP (Test Anything Protocol) parser** for handling test output in that format.

This first part lays the groundwork for the test execution logic, defining data structures, output mechanisms, and basic control flow. The subsequent parts likely build upon this foundation to handle the actual test discovery, execution, and result aggregation.
这是 Frida 动态 instrumentation 工具的测试运行器 `mtest.py` 的一部分源代码。 它的主要功能是 **构建和管理 Frida 项目的测试执行过程，并提供多种方式来呈现测试结果**。

以下是对其功能的详细归纳，并结合您提出的问题进行说明：

**核心功能:**

1. **测试执行控制:**
    *   **选择要运行的测试:**  允许用户通过命令行参数指定要运行的测试套件 (`--suite`) 或排除特定的测试套件 (`--no-suite`)，还可以直接指定要运行的测试名称 (`args`)。
    *   **重复运行测试:**  支持多次重复运行测试 (`--repeat`)，这对于检测间歇性故障非常有用。
    *   **跳过重建:**  可以选择在运行测试前不进行重建 (`--no-rebuild`)。
    *   **设置超时:**  可以定义测试超时时间的倍数 (`--timeout-multiplier`)，以适应不同环境下的测试需求。
    *   **传递参数给测试:** 允许用户向被测试的程序传递额外的参数 (`--test-args`)。
    *   **设置测试环境:** 可以指定要使用的测试设置 (`--setup`)。

2. **测试环境管理:**
    *   **切换工作目录:**  允许用户在运行测试前切换到指定的工作目录 (`-C`)。
    *   **使用包装器运行测试:**  支持使用外部包装器（例如 Valgrind）来运行测试 (`--wrapper`)。
    *   **并行执行:**  可以指定并行执行测试的进程数量 (`-j`, `--num-processes`)。

3. **测试结果处理和报告:**
    *   **跟踪测试状态:**  使用 `TestResult` 枚举来表示测试的不同状态（PENDING, RUNNING, OK, FAIL, SKIP 等）。
    *   **TAP (Test Anything Protocol) 解析:** 包含 `TAPParser` 类，用于解析符合 TAP 协议的测试输出，这在处理一些测试框架的输出时非常有用。
    *   **多种日志输出格式:**  支持多种日志记录方式，包括控制台输出 (`ConsoleLogger`)、文本文件输出 (`TextLogfileBuilder`)、JSON 文件输出 (`JsonLogfileBuilder`) 和 JUnit XML 格式输出 (`JunitBuilder`)。
    *   **详细和简洁输出:**  用户可以选择详细输出 (`-v`, `--verbose`) 或简洁输出 (`-q`, `--quiet`)。
    *   **打印错误日志:**  可以配置在测试失败时打印错误日志 (`--print-errorlogs`).
    *   **记录基准测试:**  支持运行和记录基准测试 (`--benchmark`).
    *   **设置日志基础名称:** 可以自定义日志文件的基础名称 (`--logbase`).
    *   **遇到失败时提前终止:** 可以设置最大失败次数 (`--maxfail`)，当失败次数达到阈值时终止测试运行。

4. **调试支持:**
    *   **GDB 调试:**  支持在 GDB 调试器下运行测试 (`--gdb`)，并可以指定 GDB 的路径 (`--gdb-path`)。
    *   **列出可用测试:**  可以列出所有可用的测试 (`--list`)。

**与逆向方法的关系及举例说明:**

Frida 本身是一个动态插桩工具，广泛应用于逆向工程。 `mtest.py` 作为 Frida 的测试运行器，其测试用例很可能包含了对 Frida 各种逆向功能的测试。

*   **举例:**  假设有一个测试用例旨在验证 Frida 是否能成功 hook 目标进程中的某个函数。这个测试用例可能会：
    1. 启动一个简单的目标进程。
    2. 使用 Frida 连接到该目标进程。
    3. 使用 Frida 的 API hook 目标进程的特定函数。
    4. 调用被 hook 的函数。
    5. 验证 Frida 的 hook 是否生效（例如，检查 Frida 是否执行了预期的代码，或者修改了函数的返回值）。
    `mtest.py` 负责执行这个测试用例，收集其输出，并根据预期的结果判断测试是否通过。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

Frida 作为一个底层的动态插桩工具，其测试必然会涉及到这些知识。

*   **二进制底层:**  测试可能涉及到对二进制代码的分析和操作，例如测试 Frida 是否能正确解析和修改目标进程的指令。
*   **Linux 内核:**  Frida 在 Linux 上运行时会与内核进行交互，测试可能涉及到验证 Frida 与内核的交互是否正常，例如测试 Frida 能否正确地获取进程信息或注入代码。
*   **Android 内核及框架:**  Frida 在 Android 上被广泛使用，测试可能包括：
    *   **系统调用 hook:** 测试 Frida 是否能 hook Android 系统调用的能力。
    *   **ART (Android Runtime) hook:** 测试 Frida 是否能 hook ART 虚拟机中的方法。
    *   **Java 层 hook:** 测试 Frida 是否能 hook Android 应用程序的 Java 代码。
    *   **Native 层 hook:** 测试 Frida 是否能 hook Android 应用程序的 Native 代码（C/C++ 代码）。
    *   **框架组件交互:** 测试 Frida 与 Android 框架中各种组件（例如 ActivityManager、PackageManager 等）的交互。

**逻辑推理及假设输入与输出:**

假设我们有以下测试用例：

*   **测试名称:** `test_hook_function`
*   **预期结果:**  Hook 成功，被 hook 函数执行后返回特定值。

**假设输入:**

```bash
python mtest.py test_hook_function
```

**可能的输出 (部分):**

```
[1/1] test_hook_function: OK (0.12s)
```

如果测试失败，输出可能会是：

```
[1/1] test_hook_function: FAIL (0.15s)
>>> Command: /path/to/test_hook_function_binary
>>> stdout:
[INFO] Target process started.
[INFO] Frida hook attempt...
[ERROR] Hook failed! Expected return value was '123', got '456'.
```

**涉及用户或编程常见的使用错误及举例说明:**

*   **未安装 Frida 或依赖:**  如果用户尝试运行测试，但系统未安装 Frida 或其依赖项，可能会导致测试运行失败，并显示相关的错误信息。
*   **目标进程权限不足:**  某些测试可能需要 root 权限才能运行，如果用户没有足够的权限，测试可能会失败。
*   **测试配置错误:**  如果测试用例的配置不正确（例如，指定了错误的目标进程名称或 hook 地址），则测试很可能失败。
*   **环境依赖问题:**  某些测试可能依赖特定的环境配置，如果环境不满足要求，测试可能会失败。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **开发者修改了 Frida 的代码。**
2. **为了验证代码的正确性，开发者需要运行测试。**
3. **开发者打开终端，进入 Frida 项目的 `frida-node` 子目录。**
4. **开发者找到 `releng/meson/mesonbuild/mtest.py` 文件所在的目录。**
5. **开发者使用命令 `python mtest.py` 或 `python releng/meson/mesonbuild/mtest.py` 来运行测试。**  他们可能会添加各种选项，例如指定要运行的测试、使用 GDB 调试等。
6. **如果测试失败，开发者可能会查看 `mtest.py` 的源代码，了解测试是如何执行的，以及如何收集和报告结果的，以便找到失败的原因。**  他们可能会阅读 `TAPParser` 的实现来理解如何解析测试输出，或者查看日志记录相关的代码来了解如何查看更详细的测试信息。

**归纳一下它的功能 (第 1 部分):**

这部分 `mtest.py` 的代码主要负责 **定义测试运行的框架和基础设施**。 它包括：

*   **命令行参数解析:**  定义了用户可以使用的各种命令行选项来控制测试运行。
*   **测试结果的枚举类型:**  定义了 `TestResult` 枚举，用于表示测试的不同状态。
*   **TAP 协议解析器:**  实现了 `TAPParser` 类，用于解析 TAP 格式的测试输出。
*   **测试日志记录器的基类和实现:**  定义了 `TestLogger` 基类以及多种具体的日志记录器实现（控制台、文本文件、JSON、JUnit）。这些类负责格式化和输出测试结果。
*   **辅助函数:**  提供了一些辅助函数，例如用于判断操作系统类型、获取 CPU 核心数、格式化输出等。

总而言之，这部分代码是 `mtest.py` 的核心，为 Frida 的测试提供了一个灵活、可配置且可扩展的运行和报告机制。它为后续的测试发现、执行和结果聚合奠定了基础。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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
"""


```