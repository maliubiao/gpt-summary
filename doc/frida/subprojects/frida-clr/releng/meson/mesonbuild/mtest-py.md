Response:
The user wants me to analyze a Python file that is part of the Frida dynamic instrumentation tool. The file is located at `frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py`.

I need to identify the functionalities of this Python script and relate them to concepts like reverse engineering, binary internals, Linux/Android kernel/framework knowledge, logical reasoning, and common user errors.

**Plan:**

1. **Understand the Purpose:** Analyze the imports, class definitions, and function names to determine the primary function of the script. Based on the name `mtest.py` and the context of Frida, it likely deals with running and managing tests.
2. **Identify Key Functionalities:** Break down the code into logical sections and describe what each part does. Look for classes like `TestResult`, `TAPParser`, `TestLogger`, `TestHarness`, etc.
3. **Relate to Reverse Engineering:** Consider how test execution and result analysis can be used in reverse engineering scenarios. For example, running tests against a target application or library can reveal its behavior and identify vulnerabilities.
4. **Connect to Binary/Kernel Knowledge:** Look for code that interacts with the operating system, executes external commands, or handles process execution. This might involve concepts related to process control, signals, and potentially debugging.
5. **Analyze Logical Reasoning:** Identify parts of the code that make decisions or inferences based on test results or configurations. The `TAPParser` seems to perform logical analysis of test output.
6. **Identify Potential User Errors:** Think about how users might misuse the script or provide incorrect inputs, and how the script handles such cases. Command-line arguments are a potential source of errors.
7. **Describe User Path:** Explain how a user might interact with Frida and reach the execution of this script. This involves understanding Frida's build system and testing流程.
8. **Summarize Functionalities (Part 1):**  Provide a concise overview of the script's main tasks based on the analysis.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py` 文件的第一部分代码，它是一个用于运行测试的工具，主要功能是：

1. **定义测试状态和结果:**
    *   定义了 `TestResult` 枚举类，用于表示测试的不同状态，如 `PENDING`（等待）、`RUNNING`（运行中）、`OK`（通过）、`FAIL`（失败）、`TIMEOUT`（超时）等。
    *   提供了方法来判断测试结果是成功、失败、完成，以及对结果进行颜色化处理以便在终端显示。

2. **解析 TAP (Test Anything Protocol) 输出:**
    *   实现了 `TAPParser` 类，用于解析 TAP 格式的测试输出。TAP 是一种简单的文本协议，用于描述测试结果。
    *   `TAPParser` 可以解析 TAP 输出中的版本信息、测试计划（tests数量）、单个测试的结果（通过/失败/跳过）、错误信息和 `Bail out!` 指令（指示测试提前终止）。

3. **定义测试日志记录器接口:**
    *   定义了 `TestLogger` 抽象基类，规定了测试日志记录器的通用接口，包括 `start`（开始测试）、`start_test`（开始单个测试）、`log_subtest`（记录子测试结果）、`log`（记录测试结果）和 `finish`（完成测试）等方法。

4. **实现控制台日志记录器:**
    *   实现了 `ConsoleLogger` 类，继承自 `TestLogger`，用于将测试结果输出到控制台。
    *   `ConsoleLogger` 能够显示测试的进度、运行时间、单个测试的结果，并能根据需要显示测试的详细输出（stdout 和 stderr）。
    *   使用了 Unicode 字符来增强控制台输出的可读性，例如使用月亮图案作为加载指示器。

5. **实现文本文件日志记录器:**
    *   实现了 `TextLogfileBuilder` 类，继承自 `TestFileLogger`，用于将测试结果写入到文本文件中。
    *   记录了测试的开始时间、执行时间、返回码、执行命令以及 stdout 和 stderr 输出。

6. **实现 JSON 文件日志记录器:**
    *   实现了 `JsonLogfileBuilder` 类，继承自 `TestFileLogger`，用于将测试结果以 JSON 格式写入到文件中。

7. **处理命令行参数:**
    *   使用 `argparse` 模块定义了命令行参数，例如：
        *   `--maxfail`: 设置最大失败次数，超过则终止测试。
        *   `--repeat`: 设置测试重复运行的次数。
        *   `--no-rebuild`:  不进行重新构建就运行测试。
        *   `--gdb`: 在 gdb 调试器下运行测试。
        *   `--list`: 列出可用的测试。
        *   `--wrapper`: 使用指定的包装器运行测试（例如 Valgrind）。
        *   `--suite`/`--no-suite`:  包含或排除特定测试套件的测试。
        *   `--benchmark`: 运行基准测试而不是普通测试。
        *   `-j`/`--num-processes`: 设置并行运行的测试进程数。
        *   `--timeout-multiplier`: 设置测试超时时间的倍数。
        *   `args`:  指定要运行的测试名称。

8. **提供辅助函数:**
    *   `is_windows()` 和 `is_cygwin()`:  判断当前操作系统类型。
    *   `uniwidth()`: 计算字符串在终端中占用的宽度，考虑了全角字符。
    *   `determine_worker_count()`:  自动确定用于并行测试的进程数量。
    *   `print_safe()`: 安全地打印字符串，避免 Unicode 编码错误。
    *   `join_lines()`: 连接两个字符串，并在中间添加换行符。
    *   `dashes()`:  生成由指定字符组成的虚线，用于分隔控制台输出。
    *   `returncode_to_status()`: 将进程返回码转换为可读的状态描述。
    *   `env_tuple_to_str()`: 将环境变量元组转换为字符串。

**与逆向方法的关系举例说明:**

这个脚本本身是测试工具，通常不直接参与逆向分析。然而，它可以用于验证逆向分析的结果。

*   **例子:** 假设你逆向了一个使用了 .NET CLR 的程序，并修改了其中的某些逻辑。你可以编写针对该修改后程序的测试用例，并使用 `mtest.py` 运行这些测试。如果测试通过，则可以验证你的逆向修改是否按预期工作，并且没有引入新的错误。这些测试可能包括检查特定的函数返回值、程序状态或者侧信道行为。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

*   **二进制底层:**  虽然此文件本身是 Python 代码，但它最终执行的测试可能涉及到与底层二进制代码的交互。例如，测试用例可能会启动被测试的二进制程序，并检查其输出、返回值或通过系统调用产生的副作用。`--gdb` 参数允许在 gdb 调试器下运行测试，这直接关联到二进制程序的调试。
*   **Linux 内核:**  脚本中使用了 `multiprocessing` 模块来并行运行测试，这依赖于 Linux 的进程管理机制。测试用例可能会涉及到文件系统操作、网络通信等，这些都与 Linux 内核提供的接口有关。
*   **Android 框架:**  如果 Frida 的目标是 Android 平台，那么测试用例可能需要与 Android 框架进行交互。例如，测试可以启动 Android 组件（Activity、Service 等），并验证其行为。虽然这个脚本本身不直接操作 Android 框架，但它执行的测试可以间接地涉及到。`frida-clr` 目录暗示了可能涉及到 .NET CLR 在 Android 上的使用，这会与 Android 的运行时环境和 Dalvik/ART 虚拟机交互。

**逻辑推理的假设输入与输出:**

假设我们有以下测试定义（简化示例，实际的定义会通过 Meson 构建系统生成）：

```python
tests = [
    {'name': 'test_add', 'cmd': ['./test_program', 'add', '1', '2'], 'should_fail': False},
    {'name': 'test_subtract', 'cmd': ['./test_program', 'subtract', '5', '3'], 'should_fail': False},
    {'name': 'test_divide_by_zero', 'cmd': ['./test_program', 'divide', '10', '0'], 'should_fail': True},
]
```

并且用户执行命令： `python mtest.py test_add test_divide_by_zero`

*   **假设输入:** 用户指定了运行 `test_add` 和 `test_divide_by_zero` 两个测试。
*   **逻辑推理:**
    *   脚本会过滤出 `test_add` 和 `test_divide_by_zero` 对应的测试配置。
    *   会执行命令 `./test_program add 1 2`。假设 `test_program` 返回码为 0，输出为 "3"，并且 `should_fail` 为 `False`，则 `test_add` 测试通过。
    *   会执行命令 `./test_program divide 10 0`。假设 `test_program` 因为除零错误返回非零码（例如 1），并且 `should_fail` 为 `True`，则 `test_divide_by_zero` 测试被认为是 `EXPECTEDFAIL`。
*   **预期输出 (简化):** 控制台上会显示 `test_add` 通过，`test_divide_by_zero` 预期失败。

**涉及用户或者编程常见的使用错误举例说明:**

1. **错误的测试名称:** 用户可能在命令行中输入不存在的测试名称，例如 `python mtest.py non_existent_test`。脚本需要能够处理这种情况，可能输出警告或错误信息。
2. **不正确的命令行参数:** 用户可能提供了错误的命令行参数，例如将非整数值传递给 `--maxfail`。脚本应该能够进行参数校验并给出提示。
3. **环境依赖问题:** 测试可能依赖特定的环境变量或外部程序。如果用户的环境不满足测试的依赖，测试可能会失败。例如，某个测试用例依赖 `valgrind`，但用户没有安装，如果使用了 `--wrapper valgrind`，脚本会尝试执行但可能会失败。
4. **测试用例编写错误:**  测试用例本身可能存在逻辑错误，例如断言失败，导致测试失败。`mtest.py` 会报告这些失败，但无法直接修复测试用例的错误。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **开发或修改 Frida CLR 相关代码:** 用户可能正在开发或修改 `frida-clr` 子项目中的代码。
2. **构建 Frida:** 用户使用 Meson 构建系统来编译 Frida，这通常包括在 `frida` 根目录下运行 `meson build` 和 `ninja -C build` 命令。
3. **运行测试:** 为了验证代码的正确性，用户需要在构建目录下运行测试。这通常是通过命令 `meson test -C build` 或直接调用 `build/meson-private/meson_test_setup.py test` 来完成的。
4. **`meson test` 命令:**  `meson test` 命令会调用 Meson 的测试运行器。对于 `frida-clr` 这个子项目，Meson 的测试配置会指向 `frida/subprojects/frida-clr/releng/meson.build` 文件中定义的测试。
5. **`meson_test_setup.py test`:**  这个脚本会加载测试配置信息，并最终调用 `frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py` 脚本来执行测试。
6. **传递参数:**  用户在 `meson test` 后面的参数（例如 `--no-rebuild`, `--verbose`, 指定的测试名称等）会被传递给 `mtest.py` 脚本。

作为调试线索，如果测试失败，用户可以：

*   查看 `mtest.py` 输出的详细日志，包括 stdout 和 stderr。
*   使用 `--verbose` 参数获取更详细的测试执行信息。
*   使用 `--gdb` 参数在调试器下运行失败的测试，以分析其执行过程。
*   检查测试用例的源代码，确定断言失败的原因。

**归纳一下它的功能 (第1部分):**

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py` 脚本是一个灵活的测试运行器，用于执行和管理 Frida CLR 子项目的测试。它能够解析 TAP 输出，提供多种日志记录方式，并支持通过命令行参数进行高度定制化的测试运行，例如选择要运行的测试、设置并行进程数、使用调试器或包装器等。 它的主要目的是自动化测试执行和结果报告，帮助开发者验证代码的正确性。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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