Response:
My thinking process for analyzing the `mtest.py` code and answering the prompt goes like this:

1. **Understand the Goal:** The prompt asks for the functionality of `mtest.py`, its relation to reverse engineering, its use of low-level/kernel concepts, logical inferences, potential user errors, and how a user reaches this code. It also specifically asks for a summary of the functionality in the first part.

2. **Initial Scan and Keyword Spotting:** I quickly scanned the code for keywords and recognizable patterns. Things that stood out:
    * `argparse`: Indicates command-line argument parsing.
    * `--maxfail`, `--repeat`, `--gdb`, `--wrapper`, `--suite`, `--benchmark`, `-j`, `--timeout-multiplier`: These are all command-line options related to running tests.
    * `TestResult` (enum), `TestRun`, `TestLogger`:  Clearly related to test execution and reporting.
    * `subprocess`, `os`:  Interactions with the operating system, likely for running tests.
    * `TAPParser`:  Parsing TAP (Test Anything Protocol) output, a common format for test results.
    * `junit`: Generating JUnit XML reports.
    * Mentions of Linux, Android (though less explicitly in this snippet), and Windows.
    * Imports like `multiprocessing`, `asyncio`.

3. **Deconstruct the Functionality:** Based on the keywords and structure, I started to break down the core responsibilities of the script:
    * **Test Discovery:**  The script needs to know what tests to run. This is likely determined by the build system (Meson, as the path indicates). The `args` argument suggests filtering by test name.
    * **Test Execution:** The script needs to execute the tests. This involves:
        * Potentially rebuilding (though `--no-rebuild` exists).
        * Running the test executables.
        * Handling timeouts.
        * Running tests under debuggers like GDB or with wrappers like Valgrind.
        * Parallel execution using multiple processes.
    * **Test Result Handling:**  The script needs to interpret the results of the tests. This is where `TAPParser` comes in for tests using the TAP protocol. It also seems to handle simple exit codes.
    * **Test Reporting:** The script needs to present the test results in a user-friendly way, including:
        * Console output (with spinners and progress).
        * Log files (text, JSON, JUnit).
        * Summaries of failures.
    * **Configuration:**  Command-line arguments allow users to customize the test run.

4. **Relate to Reverse Engineering (Instruction #2):** I considered how running tests relates to reverse engineering. The connection isn't direct in the *execution* of the script. However, *the tests themselves* are crucial for reverse engineering. Specifically:
    * **Dynamic Analysis:** Running tests *is* a form of dynamic analysis. You're observing the behavior of a program while it's running.
    * **Coverage:** Test suites aim to cover different parts of the code. By running tests and seeing which ones fail, a reverse engineer can gain insights into which parts of the program are behaving unexpectedly or have vulnerabilities.
    * **Understanding Functionality:** Tests often explicitly verify specific functionalities. By analyzing the test code and the program's behavior under test, a reverse engineer can understand the intended purpose of different code sections.

5. **Relate to Binary/Kernel/Framework Concepts (Instruction #3):**  I looked for evidence of interaction with low-level concepts:
    * **Binary Execution:** The script executes binaries. This involves understanding how processes are launched and how return codes work.
    * **Linux/Android Kernel (Implicit):** While not explicitly interacting with kernel APIs in *this specific script*, the *tests themselves* might be interacting with the kernel (system calls, etc.). Frida, the parent project, is heavily involved in dynamic instrumentation, which is closely tied to kernel concepts on both Linux and Android. The mention of `frida-swift` suggests testing Swift code, which might interact with the Android framework if it's an Android app.
    * **Process Management:** Using `subprocess` and `multiprocessing` shows understanding of process creation and management.
    * **Signals:** Handling signals (like Ctrl-C and test timeouts) demonstrates knowledge of OS-level signaling mechanisms.
    * **Environment Variables:** The script respects and potentially manipulates environment variables.

6. **Logical Inference (Instruction #4):**  I tried to identify places where assumptions are made and where different inputs would lead to different outputs. The command-line argument parsing is a prime example:
    * **Input:** `--maxfail 5`. **Output:** The test run will stop after 5 failures.
    * **Input:** `--suite integration`. **Output:** Only tests belonging to the "integration" suite will be run.
    * **Input:** `test_foo`. **Output:** All tests named `test_foo` will be run.
    * **Input:** `subproject:test_bar`. **Output:** Only the `test_bar` test from the `subproject` will be run.

7. **User Errors (Instruction #5):** I thought about common mistakes a user might make:
    * **Invalid Arguments:** Providing incorrect values to command-line options (e.g., a non-integer for `--maxfail`).
    * **Incorrect Test Names:**  Typing test names wrong or not understanding the naming convention (e.g., forgetting the subproject name).
    * **Conflicting Options:** Using options that contradict each other (although the script might have logic to handle some of these).
    * **Environment Issues:**  Assuming the test environment is set up correctly when it isn't (e.g., missing dependencies).

8. **User Path (Instruction #6):**  I outlined the steps a user would take to reach the execution of this script:
    1. **Project Setup:**  The user has a project that uses Meson as its build system.
    2. **Writing Tests:** Developers have written tests for the project.
    3. **Build Process:** The user has configured and built the project using Meson. This generates the necessary test executables and metadata.
    4. **Navigating to the Build Directory:** The user typically goes to the build directory created by Meson (where the `meson` command was run).
    5. **Executing the Test Command:** The user runs a command like `meson test` or `meson test <specific_test>` from the build directory. This command internally calls `mtest.py`.
    6. **Passing Arguments:** The user might add command-line arguments to customize the test run (e.g., `meson test --verbose`).

9. **Summarize Functionality (Instruction #7):** Finally, I condensed the identified functionalities into a concise summary: `mtest.py` is a tool for discovering, executing, and reporting the results of tests within a Meson project. It provides various options to control the test execution environment, reporting formats, and filtering of tests.

By following these steps, I was able to systematically analyze the code snippet and address all aspects of the prompt. The iterative process of scanning, deconstructing, and connecting the code to the broader context (reverse engineering, low-level concepts, user interaction) is key to understanding its purpose and functionality.
这是 frida 动态 instrumentation 工具中负责执行测试的脚本 `mtest.py` 的一部分代码。让我们来归纳一下它的主要功能：

**核心功能：测试执行和管理**

从提供的代码片段来看，`mtest.py` 的主要功能是：

1. **解析命令行参数:** 它使用 `argparse` 模块定义和解析用户提供的命令行参数，例如：
   - `--maxfail`:  设置失败测试的最大数量，超过则终止测试。
   - `--repeat`:  指定测试运行的次数。
   - `--no-rebuild`:  禁止在运行测试前重新构建项目。
   - `--gdb`:  在 GDB 调试器下运行测试。
   - `--wrapper`:  使用指定的包装器（例如 Valgrind）运行测试。
   - `--suite`, `--no-suite`:  包含或排除特定测试套件。
   - `--benchmark`:  运行基准测试而非普通测试。
   - `-j`, `--num-processes`:  设置并行运行测试的进程数量。
   - `--timeout-multiplier`:  调整测试的超时时间。
   - `--test-args`:  传递给被测试程序的额外参数。
   - `args`:  指定要运行的测试名称（可以按名称或子项目+名称过滤）。

2. **加载测试信息:**  虽然代码片段没有直接展示，但结合上下文可以推断，它会从 Meson 构建系统中加载测试的定义和配置信息，例如测试的名称、命令、超时时间、所属的套件等。这可能涉及到与 `build.py`、`environment.py` 和 `mintro.py` 模块的交互。

3. **执行测试:**  `mtest.py` 负责实际运行定义的测试。这可能涉及到：
   - 使用 `subprocess` 模块创建子进程来执行测试命令。
   - 捕获测试程序的标准输出和标准错误。
   - 设置测试的超时时间。
   - 处理测试的返回码，判断测试是否通过、失败或被跳过。
   - 支持在 GDB 下或使用包装器运行测试。
   - 支持并行运行多个测试以提高效率。

4. **结果处理和报告:**  它会收集和处理测试的执行结果，并生成各种形式的报告：
   - **控制台输出:**  在终端显示测试的进度、结果和错误信息。代码中定义了 `ConsoleLogger` 类来负责这部分功能，包括显示测试状态、持续时间、使用动画等。
   - **日志文件:**  生成详细的测试日志文件，例如文本格式 (`TextLogfileBuilder`)、JSON 格式 (`JsonLogfileBuilder`) 和 JUnit XML 格式 (`JunitBuilder`)。
   - **TAP 协议解析:**  如果测试程序使用 TAP (Test Anything Protocol) 输出结果，`TAPParser` 类会负责解析这些输出，提取测试结果、错误信息等。

5. **错误处理:**  处理测试执行过程中遇到的各种错误，例如超时、中断等。

6. **用户交互:**  通过命令行参数接受用户的配置，并根据配置执行测试。

**与逆向方法的关联举例说明：**

虽然 `mtest.py` 本身是一个测试执行工具，并非直接的逆向工具，但它在逆向工程流程中扮演着重要角色：

* **动态分析基础:**  运行测试用例是对目标程序进行动态分析的一种形式。通过观察程序在不同输入下的行为，逆向工程师可以更好地理解程序的逻辑和功能。
* **覆盖率分析:**  测试套件的目标是覆盖程序的各个功能模块和代码路径。运行测试可以帮助逆向工程师了解哪些代码被执行到，哪些代码可能存在漏洞或需要进一步分析。
* **行为验证:**  在逆向分析过程中，逆向工程师可能会对程序的行为做出假设。编写和运行测试用例可以验证这些假设是否正确。例如，如果逆向工程师猜测某个函数处理特定的数据格式，可以编写一个测试用例来验证这个假设。
* **漏洞复现与验证:**  在发现潜在漏洞后，可以编写测试用例来复现该漏洞，并验证修复措施是否有效。

**二进制底层、Linux、Android 内核及框架知识的关联举例说明：**

`mtest.py` 的运行以及它执行的测试用例很可能涉及到以下底层知识：

* **二进制执行:**  脚本需要能够执行编译后的二进制文件。这涉及到操作系统如何加载和运行程序，以及进程管理的相关知识。
* **进程和线程:**  脚本使用 `subprocess` 和 `multiprocessing` 来管理测试进程。理解进程和线程的概念、创建和通信方式是必要的。
* **标准输入/输出/错误流:**  脚本需要捕获测试程序的标准输出和标准错误，这涉及到操作系统提供的 I/O 重定向机制。
* **返回码:**  脚本根据测试程序的返回码判断测试结果。理解不同返回码的含义（例如 0 表示成功，非 0 表示失败，77 和 99 有特殊含义）是很重要的。
* **信号处理:**  脚本需要处理信号，例如用户按下 Ctrl+C 中断测试，以及测试超时时发送的信号。这涉及到操作系统提供的信号机制。
* **Linux/Android 内核:**  如果测试用例涉及到系统调用、设备驱动等，那么测试的执行会直接与 Linux 或 Android 内核交互。例如，测试文件系统操作、网络功能、进程间通信等。
* **Android 框架:**  如果测试的是 Android 应用程序或库，测试用例可能会涉及到与 Android 框架的交互，例如 Activity 的生命周期、Service 的启动和停止、BroadcastReceiver 的接收等。Frida 本身就是一款强大的 Android 和 iOS 动态分析工具，其测试自然会涉及到这些方面。

**逻辑推理的假设输入与输出：**

假设用户执行以下命令：

```bash
python mtest.py --maxfail 3 --repeat 2 my_test
```

**假设输入:**

* 命令行参数：`--maxfail 3`, `--repeat 2`, `my_test`
* Meson 构建系统定义了名为 `my_test` 的测试用例。

**逻辑推理过程:**

1. **解析参数:** `mtest.py` 解析命令行参数，得到：
   - `max_fail = 3`
   - `repeat = 2`
   - 要运行的测试名称包含 `my_test`。
2. **过滤测试:**  根据提供的测试名称 `my_test`，筛选出所有名称包含 `my_test` 的测试用例。
3. **循环执行:**  由于 `repeat` 设置为 2，测试将被执行两次。
4. **失败计数:**  在每次执行中，如果失败的测试数量达到 3，测试将提前终止。
5. **报告生成:**  最终生成包含两次测试运行结果的报告。

**假设输出:**

控制台输出可能如下（简化版）：

```
Running tests:
1/1 my_test  [ RUN ]
1/1 my_test  [ OK  ] (0.123s)
Running tests:
1/1 my_test  [ RUN ]
1/1 my_test  [ FAIL ] (0.234s)
Summary: 1 passed, 1 failed.
```

或者，如果 `my_test` 在第一次执行的前 3 个测试就失败了：

```
Running tests:
1/1 my_test_part1 [ FAIL ] (0.056s)
1/1 my_test_part2 [ FAIL ] (0.078s)
1/1 my_test_part3 [ FAIL ] (0.090s)
Too many failures. Aborting.
Summary: 0 passed, 3 failed.
```

**用户或编程常见的使用错误举例说明：**

1. **拼写错误的测试名称:**  用户在命令行中输入了不存在或拼写错误的测试名称，导致没有测试被执行。
   ```bash
   python mtest.py my_tset  # 正确的是 my_test
   ```
   **结果:**  没有匹配到任何测试，报告显示 0 个测试被运行。

2. **提供了无效的参数值:**  用户为某个参数提供了无效的值。
   ```bash
   python mtest.py --maxfail abc  # --maxfail 应该是一个整数
   ```
   **结果:**  `argparse` 会抛出错误，提示参数类型不匹配。

3. **忘记了子项目名称:**  如果要运行子项目中的测试，需要指定子项目名称。
   ```bash
   python mtest.py test_in_subdir  # 假设 test_in_subdir 在一个名为 subdir 的子项目中
   python mtest.py subdir:test_in_subdir  # 正确的用法
   ```
   **结果:**  第一种情况可能找不到名为 `test_in_subdir` 的顶级测试。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **项目配置和构建:**  用户首先需要有一个使用 Frida 和 Meson 构建系统的项目，并且已经成功配置和构建了该项目。
2. **进入构建目录:**  用户通常会 `cd` 进入 Meson 生成的构建目录（例如 `build`）。
3. **执行测试命令:**  用户在构建目录下运行 Meson 的测试命令，例如：
   ```bash
   meson test
   ```
   或者带有特定参数：
   ```bash
   meson test --verbose --suite integration
   ```
4. **Meson 内部调用 `mtest.py`:**  `meson` 命令会解析用户的请求，并调用相应的后端工具来执行测试。在这种情况下，它会调用 `frida/subprojects/frida-swift/releng/meson/mesonbuild/mtest.py` 脚本。
5. **传递参数:**  用户在 `meson test` 后面添加的参数会被传递给 `mtest.py` 脚本。

作为调试线索，了解用户执行的 `meson test` 命令以及其所在的目录，可以帮助定位问题，例如：

* **测试没有被运行:**  检查用户提供的测试名称或套件是否正确，以及 Meson 的测试配置是否正确。
* **测试执行失败:**  查看 `mtest.py` 生成的日志文件，分析测试的输出和错误信息。
* **构建问题:**  如果 `--no-rebuild` 被使用，但构建存在问题，可能会导致测试执行失败。

**总结 `mtest.py` 的功能 (第 1 部分):**

总而言之，`mtest.py` 的主要功能是作为 Frida 项目的一部分，**提供一个灵活且可配置的测试执行框架**。它负责解析用户提供的命令行参数，加载测试定义，执行测试用例（支持串行和并行执行，以及在调试器或包装器下运行），处理测试结果，并生成多种格式的测试报告，以便开发者验证代码的正确性。 这对于保证 Frida 动态 instrumentation 工具的质量至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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