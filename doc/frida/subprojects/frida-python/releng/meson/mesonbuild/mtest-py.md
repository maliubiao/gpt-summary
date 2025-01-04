Response:
The user wants me to analyze the Python code of `mtest.py`, a file within the Frida dynamic instrumentation tool's source code. I need to explain its functionalities, relate them to reverse engineering, describe its interactions with low-level systems, detail logical reasoning within the code, point out potential user errors, and explain how a user might reach this code during debugging. Finally, I need to summarize its functions.

Here's a breakdown of the tasks:

1. **Functionality Listing:**  Identify the core responsibilities and actions performed by the script based on its code.
2. **Relationship to Reverse Engineering:**  Connect the script's capabilities to common tasks and methodologies in reverse engineering.
3. **Binary/Kernel/Framework Interaction:**  Pinpoint parts of the code that interact with low-level aspects of operating systems like Linux and Android.
4. **Logical Reasoning:**  Find conditional statements and algorithms where input and output can be clearly defined.
5. **User Errors:**  Identify common mistakes users might make when interacting with this script.
6. **User Journey to This Code:** Describe a typical debugging scenario where a user would encounter this script.
7. **Functionality Summary:** Concisely summarize the key functionalities of the script.
好的，这是对 `frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py` 文件（Frida 动态 instrumentation 工具的一部分）源代码第一部分的分析：

**文件功能归纳：**

这段代码是 Frida 的测试执行工具，它负责以下主要功能：

1. **测试发现与管理:**  它可以列出可用的测试用例 (`--list`)，并允许用户通过名称或测试套件来选择性地运行测试。
2. **测试执行控制:**  它提供了多种控制测试执行方式的选项，例如：
    *   指定最大失败次数 (`--maxfail`)。
    *   重复运行测试 (`--repeat`)。
    *   跳过构建步骤 (`--no-rebuild`)。
    *   在调试器（gdb）下运行测试 (`--gdb`, `--gdb-path`)。
    *   使用包装器（例如 Valgrind）运行测试 (`--wrapper`)。
    *   设置工作目录 (`-C`)。
    *   包含或排除特定测试套件 (`--suite`, `--no-suite`)。
    *   控制标准输出和标准错误的分割 (`--no-stdsplit`)。
    *   打印失败测试的日志 (`--print-errorlogs`)。
    *   运行基准测试而非普通测试 (`--benchmark`)。
    *   自定义日志文件名 (`--logbase`)。
    *   设置并行执行的进程数 (`-j`, `--num-processes`)。
    *   控制输出的详细程度 (`-v`, `--quiet`)。
    *   调整测试超时时间 (`-t`, `--timeout-multiplier`)。
    *   选择测试设置 (`--setup`)。
    *   传递额外参数给测试用例 (`--test-args`)。
3. **测试结果处理与报告:**  它定义了测试结果的状态 (例如 `PENDING`, `RUNNING`, `OK`, `FAIL`, `TIMEOUT` 等)，并提供了格式化输出测试结果的方式。它还实现了 TAP (Test Anything Protocol) 的解析器，用于处理某些类型的测试输出。
4. **日志记录:**  它支持多种日志记录方式，包括控制台输出、文本日志文件和 JSON 格式的日志文件。
5. **并行执行:**  它支持通过多进程并行执行测试，以提高测试效率。
6. **终端交互:**  它尝试与终端进行友好的交互，例如显示进度、使用彩色输出等。
7. **异常处理:**  定义了 `TestException` 用于处理测试相关的异常。

**与逆向方法的联系及举例说明：**

*   **动态分析和调试:** 该脚本的核心功能是执行测试，而测试通常用于验证代码的行为。在逆向工程中，动态分析是理解未知二进制文件或代码行为的关键方法。通过运行测试，逆向工程师可以观察目标程序在特定输入下的行为，例如：
    *   **Hooking 和 Instrumentation 测试:** Frida 的核心功能是动态 instrumentation。该脚本可能会运行测试来验证 Frida 的 hooking 功能是否正常工作，例如测试一个函数是否被成功 hook，并且在 hook 点执行了预期的代码。例如，可能有一个测试用例，hook 了 `malloc` 函数，并检查每次调用 `malloc` 时是否记录了分配的大小。
    *   **代码覆盖率测试:**  虽然代码中没有直接体现，但测试执行工具通常可以与代码覆盖率工具结合使用。逆向工程师可以使用这些工具来确定测试覆盖了哪些代码路径，从而更好地理解代码的结构和功能。
    *   **模糊测试 (Fuzzing) 的集成:**  虽然脚本本身不直接实现模糊测试，但它可以作为模糊测试框架的一部分，用于执行生成的测试用例，并检查目标程序是否崩溃或产生异常行为。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

*   **进程管理和信号处理:** 代码中使用了 `multiprocessing` 模块来实现并行测试，这涉及到操作系统的进程管理。同时，代码中使用了 `signal` 模块来处理信号，例如捕获 `Ctrl-C` 中断。这在底层与操作系统如何管理进程和传递信号相关。
*   **返回值和退出状态:** 代码中多次提到和处理测试进程的返回值 (return code)。不同的返回值可能代表不同的测试结果（成功、失败、跳过等）。这直接关系到操作系统如何报告进程的执行结果。例如，GNU autotools 定义了特定的返回值含义（77 表示跳过，99 表示错误），该脚本也考虑了这些约定。
*   **环境变量:** 脚本中获取和使用了环境变量 (`os.environ`)，并且可以设置测试执行时的环境变量。这在与操作系统交互的程序中很常见，环境变量可以影响程序的行为。
*   **命令行参数:** 脚本使用 `argparse` 处理命令行参数，这些参数直接影响测试的执行方式。理解命令行参数的处理方式对于理解任何命令行工具都至关重要。
*   **路径操作:** 使用 `pathlib` 模块进行路径操作，这在处理文件系统相关的任务时是基础。
*   **与 Frida 的集成（推测）：** 虽然这段代码是 Frida 测试框架的一部分，但它本身并没有直接体现 Frida 的具体操作。然而，它执行的测试用例很可能涉及到与 Frida Agent 的交互，进而会涉及到进程注入、代码执行、内存读写等与操作系统底层密切相关的操作。在 Android 平台上，这可能涉及到与 ART 虚拟机的交互，以及对 Android Framework 的操作。

**逻辑推理及假设输入与输出：**

*   **`determine_worker_count()` 函数:**
    *   **假设输入:** 环境变量 `MESON_TESTTHREADS` 未设置，`multiprocessing.cpu_count()` 返回 8。
    *   **输出:** 8
    *   **假设输入:** 环境变量 `MESON_TESTTHREADS` 设置为 "4"。
    *   **输出:** 4
    *   **假设输入:** 环境变量 `MESON_TESTTHREADS` 设置为 "abc"。
    *   **输出:** 输出 "Invalid value in MESON\_TESTTHREADS, using 1 thread." 到标准输出，并返回 1。
*   **`returncode_to_status(retcode: int)` 函数:**
    *   **假设输入:** `retcode` 为 0。
    *   **输出:** "exit status 0"
    *   **假设输入:** `retcode` 为 -2 (假设信号 2 为 SIGINT)。
    *   **输出:** "killed by signal 2 SIGINT"
    *   **假设输入:** `retcode` 为 130 (假设信号 2 为 SIGINT)。
    *   **输出:** "(exit status 130 or signal 2 SIGINT)"
*   **TAPParser 的解析过程 (简化):**
    *   **假设输入 (TAP 输出):**
        ```
        1..3
        ok 1 Test A
        not ok 2 Test B # SKIP This test is skipped
        ok 3 Test C # TODO This test needs implementation
        ```
    *   **输出 (TAPParser 解析出的事件):**
        *   `TAPParser.Plan(num_tests=3, late=False, skipped=False, explanation=None)`
        *   `TAPParser.Test(number=1, name='Test A', result=TestResult.OK, explanation=None)`
        *   `TAPParser.Test(number=2, name='Test B', result=TestResult.SKIP, explanation='This test is skipped')`
        *   `TAPParser.Test(number=3, name='Test C', result=TestResult.UNEXPECTEDPASS, explanation='This test needs implementation')` (因为测试通过了，但标记为 TODO)

**涉及用户或者编程常见的使用错误及举例说明：**

*   **错误的 `--maxfail` 值:** 用户可能输入非数字的 `--maxfail` 值，例如 `--maxfail abc`，这会导致 `argparse` 抛出异常。
*   **错误的 `--repeat` 值:** 类似于 `--maxfail`，输入非数字的 `--repeat` 值也会导致错误。
*   **错误的 `--wrapper` 格式:** `--wrapper` 参数期望接收一个可执行命令和可选的参数，如果用户输入的格式不正确，例如只输入一个没有空格的字符串，`split_args` 函数可能无法正确解析。
*   **指定不存在的测试名称:** 用户在命令行中指定的测试名称如果不存在，测试执行器将找不到该测试并可能报错或直接结束。
*   **错误的测试套件名称:**  `--suite` 或 `--no-suite` 参数指定的套件名称如果不存在，将不会有任何测试被包含或排除，用户可能没有意识到这一点。
*   **并发测试冲突:**  如果多个测试同时访问相同的资源（例如文件），可能会导致测试失败。这不是 `mtest.py` 本身的错误，而是测试用例设计的问题，但用户运行并行测试时可能会遇到。
*   **测试超时设置不当:**  如果 `--timeout-multiplier` 设置得过低，一些需要较长时间运行的测试可能会被误判为超时。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发或修改 Frida 的 Python 绑定:**  开发者在开发或修改 Frida 的 Python 绑定 (`frida-python`) 时，需要运行测试来确保代码的正确性。
2. **使用 Meson 构建系统:** Frida 使用 Meson 作为其构建系统。开发者通常会使用 Meson 提供的命令来构建和运行测试。
3. **执行测试命令:** 开发者会在构建目录中执行类似 `meson test` 或 `meson test <specific_test>` 的命令。
4. **Meson 调用 `mtest.py`:** Meson 构建系统会解析 `meson test` 命令，并最终调用 `frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py` 脚本来执行测试。
5. **调试测试失败:**  如果某个测试失败，开发者可能会想要了解更详细的信息。他们可能会使用以下方法来调试：
    *   **查看日志:**  查看 `mtest.py` 生成的日志文件（例如 `testlog.txt`）。
    *   **使用 `--verbose` 参数:**  使用 `meson test -v` 或 `meson test --verbose` 来获取更详细的测试输出，包括执行的命令和实时的标准输出/错误。
    *   **使用 `--print-errorlogs` 参数:** 使用 `meson test --print-errorlogs` 来打印失败测试的完整日志。
    *   **在 gdb 下运行:**  使用 `meson test --gdb <test_name>` 来在 gdb 调试器下运行特定的测试，以便单步执行代码并检查变量。
    *   **修改 `mtest.py` 代码 (作为最后的手段):**  在极少数情况下，为了深入理解测试执行的流程或排查 `mtest.py` 本身的问题，开发者可能会查看或修改 `mtest.py` 的源代码。

**总结:**

总的来说，`frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py` 脚本是 Frida Python 绑定项目的核心测试执行工具。它提供了丰富的功能来管理和控制测试的运行，并生成详细的测试报告。它与逆向工程密切相关，因为测试是验证 Frida 功能的重要手段。同时，它也涉及到操作系统底层的进程管理、信号处理等概念。用户通过 Meson 构建系统来间接调用此脚本，并可以通过多种命令行选项来定制测试行为，以便进行开发、调试和验证。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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