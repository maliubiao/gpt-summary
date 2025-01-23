Response:
My thought process for analyzing the `mtest.py` code and answering the prompt followed these steps:

1. **Understand the Goal:** The primary goal of `mtest.py` is to execute tests within the Frida build system (and likely other Meson-based projects). It needs to handle various test types, reporting, and integration with the build process.

2. **High-Level Scan:**  I started by skimming the entire file, paying attention to imports, class definitions, function names, and overall structure. This gave me a general idea of the components and their interactions. I noticed keywords like "test," "run," "log," "TAP," "JUnit," indicating core functionalities.

3. **Identify Key Classes and Their Roles:** I focused on the major classes:
    * `TAPParser`:  Clearly for parsing TAP (Test Anything Protocol) output, a common format for test results.
    * `TestLogger`, `ConsoleLogger`, `TextLogfileBuilder`, `JsonLogfileBuilder`, `JunitBuilder`: These are different ways of logging and reporting test results, each with a specific format.
    * `TestResult`:  An enumeration defining the possible states of a test execution.

4. **Trace the Test Execution Flow (Mentally):** I imagined how a test would be executed. It would likely involve:
    * Identifying the tests to run.
    * Executing the test command.
    * Capturing the output (stdout and stderr).
    * Parsing the output (especially for TAP tests).
    * Reporting the result.

5. **Look for Interactions with the Build System:**  The imports like `.build`, `.environment`, `.mintro` and the mention of `mesonbuild` in the file path itself suggested tight integration with the Meson build system. The `--no-rebuild` argument further confirmed this.

6. **Analyze Function Arguments and Purpose:**  I examined functions like `add_arguments` to understand the command-line options users can provide. This revealed features like filtering tests, specifying repeat counts, using debuggers, and controlling output.

7. **Identify Low-Level Interactions:**  I looked for keywords and imports related to operating systems and system calls: `subprocess`, `os`, `platform`, `signal`, and mentions of Linux, Android (implicitly through Frida's context, although not explicitly in *this* code snippet).

8. **Focus on Specific Prompt Requirements:** I systematically addressed each part of the prompt:

    * **Functionality:**  Summarize the core tasks.
    * **Relationship to Reverse Engineering:**  Look for clues about how this tool might be used in a reverse engineering context. Frida itself is a dynamic instrumentation tool for reverse engineering, so the testing likely involves verifying the correctness of these instrumentation capabilities. I considered examples like testing hooking, code injection, and memory manipulation.
    * **Binary/Kernel/Framework Knowledge:**  Think about the underlying systems involved. Executing tests often means running binaries, potentially interacting with the operating system kernel (especially for Frida which does system-level hooking), and utilizing frameworks. I looked for code snippets suggesting process execution, output handling, and parsing (like TAP). While this specific snippet doesn't delve deeply into kernel details, the broader context of Frida makes that connection.
    * **Logical Reasoning (Assumptions and Outputs):** Imagine a simple test case and how `mtest.py` would handle it. For example, a test that exits with code 0 should be marked as "OK." A test with a non-zero exit code would be a "FAIL."
    * **Common User Errors:** Consider what mistakes a user might make when using this tool. Examples include incorrect command-line arguments, specifying non-existent tests, or issues with the test environment.
    * **User Path to Execution:**  Trace the steps a user would take to reach this part of the code. This starts with configuring and building the Frida project using Meson, then running the test command.
    * **Summary of Functionality (Part 1):**  Condense the identified functionalities into a concise summary.

9. **Refine and Organize:** I organized my findings into the structure requested by the prompt, providing specific code examples where relevant and making sure to clearly connect the code to the concepts of reverse engineering, low-level details, etc.

10. **Iterative Refinement (Internal):** Throughout the process, I mentally reviewed my understanding and looked for inconsistencies or areas where I needed more clarification from the code. I re-read sections and considered alternative interpretations.

By following this structured approach, I could effectively analyze the code snippet and address all aspects of the prompt, even without executing the code itself. The key was to combine code-level observation with an understanding of the broader context of Frida and software testing.
这是 frida 动态 instrumentation 工具的一个名为 `mtest.py` 的源代码文件，位于 `frida/subprojects/frida-tools/releng/meson/mesonbuild/` 目录下。这个文件是 Meson 构建系统中用于执行测试的工具。

**它的功能可以归纳为以下几点：**

1. **测试执行框架:** `mtest.py` 提供了一个框架，用于执行各种类型的测试，包括单元测试、集成测试等。它可以根据用户的配置和命令行参数，自动化地运行指定的测试。

2. **多种执行模式:** 它支持多种测试执行模式，例如：
    * **串行执行:** 逐个运行测试。
    * **并行执行:** 利用多核 CPU 并行运行测试，提高效率。
    * **重复执行:**  多次运行相同的测试，用于发现间歇性问题。

3. **测试过滤:** 用户可以通过命令行参数指定要运行的测试套件或单个测试用例，也可以排除某些测试套件。这使得用户可以灵活地选择要执行的测试范围。

4. **测试结果收集与报告:** `mtest.py` 负责收集每个测试的执行结果（成功、失败、跳过、超时等），并将结果以不同的格式报告出来，例如：
    * **控制台输出:**  在终端上实时显示测试进度和结果。
    * **文本日志文件:**  将详细的测试执行信息写入文本文件。
    * **JSON 格式日志文件:**  将测试结果以 JSON 格式记录，方便程序分析。
    * **JUnit XML 格式报告:**  生成 JUnit 兼容的 XML 报告，可以集成到持续集成 (CI) 系统中。
    * **TAP (Test Anything Protocol) 解析:**  支持解析符合 TAP 协议的测试输出。

5. **超时控制:**  可以为测试设置超时时间，防止测试无限期运行。

6. **错误处理和中断:**  可以设置最大失败次数，超过该次数后停止测试。支持在测试过程中接收 Ctrl-C 信号并优雅地终止。

7. **调试支持:**  支持在 gdb 调试器下运行测试，方便开发人员调试测试代码或被测试的目标程序。

8. **外部工具包装:**  允许使用外部包装器（例如 Valgrind）来运行测试，用于内存泄漏检测等。

9. **环境变量传递:**  能够将环境变量传递给被执行的测试程序。

10. **与 Meson 构建系统集成:**  作为 Meson 构建系统的一部分，它可以读取 Meson 构建过程中生成的测试信息，例如测试的可执行文件路径、命令行参数等。

**与逆向的方法的关系及举例说明:**

* **测试 Frida 的 instrumentation 能力:** 作为 Frida 的测试工具，`mtest.py` 很可能被用于测试 Frida 的各种 instrumentation 功能是否正常工作。例如，可以编写测试用例来验证 Frida 是否能够成功地 hook 某个函数、修改函数的参数或返回值、注入代码等。
    * **举例:** 假设有一个测试用例，它使用 Frida hook 了目标进程中的 `open()` 函数，并断言当调用 `open()` 打开特定文件时，hook 函数会被执行，并且可以修改打开的文件路径。`mtest.py` 负责运行这个测试用例，并根据测试用例的断言结果来判断 Frida 的 hook 功能是否正常。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **执行二进制程序:** `mtest.py` 需要能够启动和管理底层的二进制可执行文件，这些可执行文件是被测试的目标程序。这涉及到进程的创建、参数传递、标准输入/输出/错误的重定向等操作系统层面的知识。
    * **举例:**  在 Linux 或 Android 上执行一个测试可执行文件时，`mtest.py` 会使用 `subprocess` 模块来创建一个新的进程，并执行该可执行文件。它可能需要处理不同平台下的路径表示、执行权限等问题。

* **处理进程信号:**  `mtest.py` 需要能够处理来自被测试进程的信号，例如测试超时时的 `SIGKILL` 或用户按下 Ctrl-C 时的 `SIGINT`。
    * **举例:** 如果一个测试用例运行时间过长，超过了预设的超时时间，`mtest.py` 会发送一个 `SIGKILL` 信号来强制终止该进程。

* **理解和解析 TAP 协议:** 如果测试用例的输出遵循 TAP 协议，`mtest.py` 中的 `TAPParser` 类会负责解析这些输出，提取测试结果、错误信息等。TAP 协议通常用于描述测试的执行状态和结果。
    * **举例:** 一个测试用例可能会输出类似 `ok 1 This is a test` 的 TAP 行，表示第一个测试通过。`TAPParser` 需要理解这种格式并提取出测试编号、描述和结果。

* **处理不同平台的差异:**  `mtest.py` 需要考虑在不同操作系统（如 Linux、Windows、macOS、Android）上的差异，例如路径分隔符、进程管理方式、环境变量设置等。
    * **举例:** 代码中使用了 `platform.system()` 来判断当前操作系统，并根据不同的平台选择合适的命令执行方式或路径处理方法。`get_wine_shortpath` 函数表明可能需要处理在 Wine 环境下运行测试的情况。

**逻辑推理（假设输入与输出）：**

假设一个简单的测试用例 `test_add.py`，它执行一个加法运算并输出结果，如果结果为 3 则输出 `ok 1 Addition works`，否则输出 `not ok 1 Addition fails`。

* **假设输入:**
    * 命令行参数: `python mtest.py test_add.py`
    * `test_add.py` 内容:
      ```python
      def add(a, b):
          return a + b

      result = add(1, 2)
      if result == 3:
          print("ok 1 Addition works")
      else:
          print("not ok 1 Addition fails")
      ```

* **预期输出 (控制台):**
  ```
  1/1 [  OK  ] test_add
  OK: 1 tests passed, 0 tests failed, 0 tests skipped.
  ```
  或者，如果 `test_add.py` 中的 `add(1, 2)` 改为 `add(1, 1)`，则预期输出为：
  ```
  1/1 [ FAIL ] test_add
  >>> python test_add.py
  not ok 1 Addition fails
  FAIL: 1 tests failed, 0 tests passed, 0 tests skipped.
  ```

**用户或编程常见的使用错误及举例说明:**

* **测试名称拼写错误:** 用户在命令行中指定的测试名称与实际测试名称不符。
    * **举例:** 用户想运行名为 `test_functionality.py` 的测试，但在命令行中输入了 `python mtest.py test_function.py` (缺少了 "ali"). `mtest.py` 会报告找不到该测试。

* **测试依赖的环境未配置:** 某些测试可能依赖特定的环境变量或外部程序，如果这些环境未配置，测试可能会失败。
    * **举例:** 一个测试用例需要访问特定的网络服务，但用户在没有网络连接的情况下运行测试。`mtest.py` 会执行测试，但测试可能会因为无法连接到网络服务而失败。

* **测试用例本身存在 bug:**  测试用例的断言逻辑错误或者被测试的代码本身存在 bug，导致测试失败。
    * **举例:**  测试用例预期某个函数返回特定的值，但由于函数实现错误，返回了错误的值，导致测试失败。

* **使用了不兼容的命令行参数:**  用户使用了 `mtest.py` 不支持的命令行参数或参数格式错误。
    * **举例:** 用户错误地使用了双连字符而不是单连字符，例如 `--max_fail` 而不是 `--maxfail`。`argparse` 模块会报告参数解析错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 项目的开发或维护者:**  开发者在编写、修改或调试 Frida 的代码时，需要运行测试来验证代码的正确性。

2. **配置和构建 Frida:**  开发者使用 Meson 构建系统来配置和构建 Frida 项目。这个过程中，Meson 会读取 `meson.build` 文件中定义的测试信息。

3. **运行测试命令:**  开发者在构建目录中执行类似于 `meson test` 或 `ninja test` 的命令。Meson 或 Ninja 会调用 `mtest.py` 脚本来执行测试。用户可以通过添加额外的参数来控制测试的执行方式，例如：
    * `meson test -C builddir`  指定构建目录。
    * `meson test --verbose`  显示详细的测试输出。
    * `meson test my_test_case`  只运行名为 `my_test_case` 的测试。

4. **`mtest.py` 的执行:** 当执行测试命令时，Meson 会定位到 `frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py` 文件并执行它。

5. **参数解析和测试发现:** `mtest.py` 会解析用户提供的命令行参数，并读取 Meson 生成的测试信息文件 (通常在构建目录的 `meson-info` 目录下)，获取所有可用的测试用例及其相关信息。

6. **测试执行和结果报告:**  `mtest.py` 根据用户的配置和测试用例的信息，启动相应的测试进程，收集测试结果，并按照指定的格式输出报告。

**第一部分功能归纳:**

总而言之，`frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py` 的主要功能是 **为 Frida 项目提供一个灵活且可配置的测试执行框架，能够运行各种类型的测试，收集和报告测试结果，并支持多种执行模式和调试选项，以便开发者能够有效地验证 Frida 代码的正确性。** 它与 Meson 构建系统紧密集成，并能够处理不同平台和测试输出格式的差异。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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