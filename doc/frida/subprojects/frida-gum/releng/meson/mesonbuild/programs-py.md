Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `programs.py` file within the Frida project (specifically the `frida-gum` subproject). This involves identifying what the code *does*, how it relates to reverse engineering, operating system concepts, and common user errors, and how a user might interact with the code indirectly.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and concepts. Words like "Program", "ExternalProgram", "search", "path", "executable", "version", "Windows", "Linux", "Android", and error messages are strong indicators of the code's purpose. The presence of `mesonlib` imports also suggests this is part of a larger build system.

**3. Core Functionality Identification - `ExternalProgram` Class:**

The `ExternalProgram` class immediately stands out as central. The `__init__` method is the starting point. Observing how it initializes the program's name, command, and path reveals the core responsibility: finding and representing external programs. The logic for searching (including handling shebangs and Windows-specific quirks) is crucial.

**4. Deeper Dive into Key Methods:**

* **`__init__`:** Understands how a program's command is determined (either provided directly or by searching). The Windows shebang handling and path adjustments are important details.
* **`found()`:**  A simple check, but essential for knowing if a program was successfully located.
* **`get_command()` and `get_path()`:**  Basic accessors for program information.
* **`get_version()`:**  This immediately signals a potential interaction with the external program itself, which is relevant to reverse engineering (determining the version of a target program).
* **`_search()` and related methods (`_search_dir`, `_search_windows_special_cases`):**  Crucial for understanding the program discovery process on different operating systems. The Windows-specific logic highlights platform-dependent behavior.
* **`from_bin_list()` and `from_entry()`:** These static methods show alternative ways to create `ExternalProgram` instances, linking it to build configuration files.

**5. Identifying Relationships to Reverse Engineering:**

The ability to find and execute external programs is fundamental to reverse engineering. Tools like debuggers, disassemblers, and static analyzers are external programs. The `get_version()` method is a direct example of interacting with a target program. The flexibility in specifying program paths is also relevant.

**6. Identifying Relationships to OS Concepts:**

The code explicitly deals with:

* **File systems and paths:** The entire program revolves around finding files.
* **Executable files and permissions:** The `_is_executable()` method checks this.
* **Environment variables (PATH):**  The search logic heavily relies on the `PATH` environment variable.
* **Operating system differences (Windows vs. Linux/Unix):**  The Windows-specific methods and checks are clear indicators.
* **Process execution (implicit):** Although not explicitly executing programs in *this* file, the representation of programs is a prerequisite for execution.
* **Shebangs:**  Understanding how scripts are invoked on Unix-like systems.

**7. Considering User Interactions and Errors:**

* **Incorrect program names:**  The search logic can fail.
* **Missing programs:** The `NonExistingExternalProgram` class handles this.
* **Incorrect paths:**  Users might provide wrong paths in configuration.
* **Permissions issues:** The `_is_executable()` check highlights this.
* **Windows-specific path and extension issues:** The code explicitly addresses these common problems.

**8. Logical Inference and Examples:**

Once the core functionality is understood, we can start constructing hypothetical inputs and outputs. For example, providing a program name and seeing how the search progresses. Thinking about how the `get_version()` method would work with a hypothetical program and its `--version` output.

**9. Debugging Clues:**

The file path (`frida/subprojects/frida-gum/releng/meson/mesonbuild/programs.py`) itself suggests it's part of the Frida build system (using Meson). This tells us *when* and *why* this code might be executed – during the build process to find necessary tools.

**10. Structuring the Explanation:**

Finally, the information needs to be organized logically. Start with a general overview, then delve into the key functionalities, and then connect it to the specified domains (reverse engineering, OS concepts, etc.). Use examples to illustrate abstract concepts. The request to cover user errors and debugging clues is addressed at the end.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the details of individual methods. It's important to step back and understand the overall purpose of the file.
*  Realizing the connection to Meson is crucial for understanding the context of this code. It's not just a standalone utility.
*  Ensuring the examples are clear and relevant to the specific points being made.
*  Checking if all aspects of the prompt (functionality, reverse engineering, OS, logic, errors, debugging) are adequately addressed.

By following these steps, combining code analysis with domain knowledge and logical reasoning, we can arrive at a comprehensive explanation like the example provided.
这个 `programs.py` 文件是 Frida Dynamic Instrumentation 工具的构建系统 Meson 的一部分，它定义了如何表示和查找外部程序（系统上已存在的程序）和内部程序（构建过程中生成的程序）。

以下是它的功能以及与你提到的领域的关联：

**主要功能:**

1. **表示外部程序 (`ExternalProgram` 类):**
   - 存储外部程序的名称 (`name`) 和执行命令 (`command`)。
   - 存储程序的可执行文件路径 (`path`)。
   - 缓存程序的版本信息 (`cached_version`)，避免重复获取。
   - 提供方法判断程序是否找到 (`found()`)。
   - 提供获取程序命令 (`get_command()`) 和路径 (`get_path()`) 的方法。
   - 提供获取程序版本的方法 (`get_version()`)，该方法会尝试执行程序并解析其 `--version` 输出。
   - 提供人性化的程序描述 (`description()`).
   - 提供用于摘要输出的值 (`summary_value()`).

2. **查找外部程序:**
   - `__init__` 方法中实现了程序查找的逻辑。它可以接受预定义的命令，或者在系统 `PATH` 环境变量中搜索程序。
   - 考虑了不同操作系统（主要是 Windows 和类 Unix 系统）的路径查找差异，例如 Windows 的可执行文件扩展名 (`.exe`, `.com`, 等) 和 shebang 处理。
   - 实现了 Windows 下的特殊路径处理，例如处理 `USERPROFILE` 和 `WindowsApps` 目录。
   - 提供了通过 shebang (#! 符号) 解析脚本的执行方式，即使脚本没有执行权限也能找到正确的解释器。

3. **处理不存在的外部程序 (`NonExistingExternalProgram` 类):**
   - 提供了一个表示找不到的外部程序的特殊类。

4. **覆盖程序 (`OverrideProgram` 类):**
   - 提供了一个用于表示被覆盖的程序（例如，用自定义脚本替换系统命令）的类。

5. **查找外部程序工具函数 (`find_external_program`):**
   - 提供了一个更高级的函数，用于在构建配置（cross 文件或 machine 文件）中查找指定的外部程序，并提供默认的查找路径。这允许在交叉编译环境中指定不同平台的工具。

**与逆向方法的关联和举例:**

这个文件本身并不直接执行逆向操作，但它为构建 Frida 工具链提供了基础，这些工具链将被用于逆向。

* **查找逆向工具:**  Frida 的构建过程可能需要依赖其他逆向工具，例如 `objdump`（用于查看目标文件的信息）、`lldb` 或 `gdb`（调试器）。`find_external_program` 函数可以用来在构建时查找这些工具。
    * **举例:**  假设 Frida 需要 `objdump` 来处理某些二进制文件。`find_external_program` 可以配置为首先在构建配置文件中查找 `objdump` 的路径，如果没有找到，则在系统的 `PATH` 中搜索 `objdump`。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** `find_external_program(env, MachineChoice.HOST, 'objdump', 'objdump', ['objdump'])`
        * **可能的输出:**  如果系统 `PATH` 中存在 `objdump`，则返回一个 `ExternalProgram` 对象，其 `command` 属性可能是 `['/usr/bin/objdump']`。

* **确定目标程序信息:**  在某些构建步骤中，可能需要获取目标程序的信息，例如其版本。`ExternalProgram` 的 `get_version` 方法就支持这种操作。
    * **举例:**  假设 Frida 的构建脚本需要知道目标 Android 应用程序中某个工具的版本。它可以创建一个 `ExternalProgram` 对象来表示这个工具，并调用 `get_version()` 方法。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 创建一个 `ExternalProgram` 对象，`name` 为 `adb`，并且 `command` 指向 `adb` 的路径。然后调用 `adb_program.get_version()`。
        * **可能的输出:**  如果 `adb` 命令的输出包含版本信息，例如 "Android Debug Bridge version 1.0.41"，则 `get_version()` 方法可能会返回 "1.0.41"。

**涉及到二进制底层，Linux, Android 内核及框架的知识和举例:**

虽然 `programs.py` 本身没有直接操作二进制数据或内核，但它处理的程序是与这些领域紧密相关的。

* **二进制底层:**
    * 该文件处理的是可执行文件，这些文件是二进制形式存在的。
    * `_is_executable` 方法检查文件的执行权限，这与操作系统如何加载和执行二进制文件有关。
    * **举例:** `ExternalProgram` 可以用来表示一个用于分析 ELF 二进制文件的工具，例如 `readelf`。

* **Linux 内核:**
    * 在 Linux 系统上，程序查找依赖于 `PATH` 环境变量，这是 Linux 操作系统的一个基本概念。
    * shebang 的处理与 Linux 内核如何执行脚本有关。
    * **举例:**  在 Linux 上，如果 Frida 需要执行一个 Python 脚本，`ExternalProgram` 会检查脚本的 shebang 行 (`#!/usr/bin/env python3`) 来确定使用哪个 Python 解释器。

* **Android 内核及框架:**
    * 在 Android 开发中，`adb` (Android Debug Bridge) 是一个常用的外部程序。`ExternalProgram` 可以用来查找和表示 `adb`。
    * Frida 本身就常用于 Android 平台的动态分析，因此构建过程中需要处理与 Android 相关的工具。
    * **举例:**  Frida 的构建过程可能需要使用 `adb` 将文件推送到 Android 设备，或者执行设备上的命令。`ExternalProgram` 可以用来确保 `adb` 可用。

**逻辑推理 (假设输入与输出):**

* **假设输入:** `ExternalProgram('my_program')`，并且 `my_program` 不在系统的 `PATH` 中。
* **输出:** `my_program.found()` 返回 `False`。

* **假设输入:** `ExternalProgram('/path/to/my_script.py')`，且该脚本的首行是 `#!/usr/bin/python3`。
* **输出:**  `my_script.get_command()` 可能会返回 `['/usr/bin/python3', '/path/to/my_script.py']` (取决于系统上 `/usr/bin/python3` 是否存在以及是否被 Meson 的配置覆盖)。

**涉及用户或者编程常见的使用错误，请举例说明:**

* **程序名拼写错误:** 用户可能在构建配置文件中错误地拼写了程序名，导致 `find_external_program` 找不到该程序。
    * **举例:**  用户在配置文件中写了 `objdum` 而不是 `objdump`。Meson 构建过程会报错，提示找不到 `objdum`。

* **路径配置错误:** 用户可能在构建配置文件中提供了错误的程序路径。
    * **举例:**  用户指定 `cc = /opt/my_custom_gcc/bin/gcc`，但该路径下实际上没有 `gcc` 可执行文件。

* **依赖的程序未安装:**  构建过程依赖的某些外部程序可能在用户的系统上没有安装。
    * **举例:**  Frida 的构建可能依赖 `pkg-config` 来查找库的路径，如果用户没有安装 `pkg-config`，构建会失败。

* **Windows 下路径分隔符问题:**  在 Windows 上，路径分隔符是反斜杠 `\`，但在配置文件中可能错误地使用了正斜杠 `/`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常用户不会直接操作或修改 `programs.py` 文件。用户与这个文件的交互是通过 Frida 的构建过程间接发生的。以下是一个可能的场景：

1. **用户尝试构建 Frida:** 用户执行命令（例如 `meson setup build` 和 `meson compile -C build`）来构建 Frida。
2. **Meson 解析构建配置:** Meson 读取 Frida 的 `meson.build` 文件以及可能存在的 cross 文件或 machine 文件。
3. **构建配置中定义了外部程序的依赖:** `meson.build` 文件中可能使用了 `find_program()` 函数来查找构建所需的外部程序。在 Frida 的上下文中，这可能发生在 `frida-gum` 子项目的构建过程中。
4. **`find_program()` 调用 `find_external_program()`:**  Meson 的 `find_program()` 函数会调用 `programs.py` 中的 `find_external_program()` 函数来执行实际的程序查找。
5. **`ExternalProgram` 对象被创建和使用:**  `find_external_program()` 可能会创建 `ExternalProgram` 对象来表示找到的程序，并在后续的构建步骤中使用这些对象来执行相关的操作，例如运行编译器、链接器等。

**作为调试线索:**

如果构建过程因为找不到某个程序而失败，用户应该：

1. **检查构建日志:** 查看 Meson 的构建日志，找到关于程序查找失败的错误信息。日志通常会指示哪个程序没有找到。
2. **检查构建配置文件:**  查看 `meson.build` 文件以及相关的 cross 文件或 machine 文件，确认程序名和路径是否正确。
3. **检查 `PATH` 环境变量:**  确认所需的程序是否在系统的 `PATH` 环境变量中，或者是否需要手动指定路径。
4. **确认程序已安装:**  确认所需的外部程序已正确安装在系统中。
5. **特定于 Windows 的问题:**  在 Windows 上，需要特别注意文件扩展名和路径分隔符。

总而言之，`programs.py` 是 Frida 构建系统的一个关键组成部分，它负责管理和查找构建过程中需要的各种外部程序，这对于成功构建 Frida 工具链至关重要，而 Frida 工具链本身又被广泛应用于软件逆向工程。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2020 The Meson development team

from __future__ import annotations

"""Representations and logic for External and Internal Programs."""

import functools
import os
import shutil
import stat
import sys
import re
import typing as T
from pathlib import Path

from . import mesonlib
from . import mlog
from .mesonlib import MachineChoice, OrderedSet

if T.TYPE_CHECKING:
    from .environment import Environment
    from .interpreter import Interpreter


class ExternalProgram(mesonlib.HoldableObject):

    """A program that is found on the system."""

    windows_exts = ('exe', 'msc', 'com', 'bat', 'cmd')
    for_machine = MachineChoice.BUILD

    def __init__(self, name: str, command: T.Optional[T.List[str]] = None,
                 silent: bool = False, search_dir: T.Optional[str] = None,
                 extra_search_dirs: T.Optional[T.List[str]] = None):
        self.name = name
        self.path: T.Optional[str] = None
        self.cached_version: T.Optional[str] = None
        if command is not None:
            self.command = mesonlib.listify(command)
            if mesonlib.is_windows():
                cmd = self.command[0]
                args = self.command[1:]
                # Check whether the specified cmd is a path to a script, in
                # which case we need to insert the interpreter. If not, try to
                # use it as-is.
                ret = self._shebang_to_cmd(cmd)
                if ret:
                    self.command = ret + args
                else:
                    self.command = [cmd] + args
        else:
            all_search_dirs = [search_dir]
            if extra_search_dirs:
                all_search_dirs += extra_search_dirs
            for d in all_search_dirs:
                self.command = self._search(name, d)
                if self.found():
                    break

        if self.found():
            # Set path to be the last item that is actually a file (in order to
            # skip options in something like ['python', '-u', 'file.py']. If we
            # can't find any components, default to the last component of the path.
            for arg in reversed(self.command):
                if arg is not None and os.path.isfile(arg):
                    self.path = arg
                    break
            else:
                self.path = self.command[-1]

        if not silent:
            # ignore the warning because derived classes never call this __init__
            # method, and thus only the found() method of this class is ever executed
            if self.found():  # lgtm [py/init-calls-subclass]
                mlog.log('Program', mlog.bold(name), 'found:', mlog.green('YES'),
                         '(%s)' % ' '.join(self.command))
            else:
                mlog.log('Program', mlog.bold(name), 'found:', mlog.red('NO'))

    def summary_value(self) -> T.Union[str, mlog.AnsiDecorator]:
        if not self.found():
            return mlog.red('NO')
        return self.path

    def __repr__(self) -> str:
        r = '<{} {!r} -> {!r}>'
        return r.format(self.__class__.__name__, self.name, self.command)

    def description(self) -> str:
        '''Human friendly description of the command'''
        return ' '.join(self.command)

    def get_version(self, interpreter: T.Optional['Interpreter'] = None) -> str:
        if not self.cached_version:
            raw_cmd = self.get_command() + ['--version']
            if interpreter:
                res = interpreter.run_command_impl((self, ['--version']),
                                                   {'capture': True,
                                                    'check': True,
                                                    'env': mesonlib.EnvironmentVariables()},
                                                   True)
                o, e = res.stdout, res.stderr
            else:
                p, o, e = mesonlib.Popen_safe(raw_cmd)
                if p.returncode != 0:
                    cmd_str = mesonlib.join_args(raw_cmd)
                    raise mesonlib.MesonException(f'Command {cmd_str!r} failed with status {p.returncode}.')
            output = o.strip()
            if not output:
                output = e.strip()
            match = re.search(r'([0-9][0-9\.]+)', output)
            if not match:
                raise mesonlib.MesonException(f'Could not find a version number in output of {raw_cmd!r}')
            self.cached_version = match.group(1)
        return self.cached_version

    @classmethod
    def from_bin_list(cls, env: 'Environment', for_machine: MachineChoice, name: str) -> 'ExternalProgram':
        # There is a static `for_machine` for this class because the binary
        # always runs on the build platform. (It's host platform is our build
        # platform.) But some external programs have a target platform, so this
        # is what we are specifying here.
        command = env.lookup_binary_entry(for_machine, name)
        if command is None:
            return NonExistingExternalProgram()
        return cls.from_entry(name, command)

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _windows_sanitize_path(path: str) -> str:
        # Ensure that we use USERPROFILE even when inside MSYS, MSYS2, Cygwin, etc.
        if 'USERPROFILE' not in os.environ:
            return path
        # The WindowsApps directory is a bit of a problem. It contains
        # some zero-sized .exe files which have "reparse points", that
        # might either launch an installed application, or might open
        # a page in the Windows Store to download the application.
        #
        # To handle the case where the python interpreter we're
        # running on came from the Windows Store, if we see the
        # WindowsApps path in the search path, replace it with
        # dirname(sys.executable).
        appstore_dir = Path(os.environ['USERPROFILE']) / 'AppData' / 'Local' / 'Microsoft' / 'WindowsApps'
        paths = []
        for each in path.split(os.pathsep):
            if Path(each) != appstore_dir:
                paths.append(each)
            elif 'WindowsApps' in sys.executable:
                paths.append(os.path.dirname(sys.executable))
        return os.pathsep.join(paths)

    @staticmethod
    def from_entry(name: str, command: T.Union[str, T.List[str]]) -> 'ExternalProgram':
        if isinstance(command, list):
            if len(command) == 1:
                command = command[0]
        # We cannot do any searching if the command is a list, and we don't
        # need to search if the path is an absolute path.
        if isinstance(command, list) or os.path.isabs(command):
            if isinstance(command, str):
                command = [command]
            return ExternalProgram(name, command=command, silent=True)
        assert isinstance(command, str)
        # Search for the command using the specified string!
        return ExternalProgram(command, silent=True)

    @staticmethod
    def _shebang_to_cmd(script: str) -> T.Optional[T.List[str]]:
        """
        Check if the file has a shebang and manually parse it to figure out
        the interpreter to use. This is useful if the script is not executable
        or if we're on Windows (which does not understand shebangs).
        """
        try:
            with open(script, encoding='utf-8') as f:
                first_line = f.readline().strip()
            if first_line.startswith('#!'):
                # In a shebang, everything before the first space is assumed to
                # be the command to run and everything after the first space is
                # the single argument to pass to that command. So we must split
                # exactly once.
                commands = first_line[2:].split('#')[0].strip().split(maxsplit=1)
                if mesonlib.is_windows():
                    # Windows does not have UNIX paths so remove them,
                    # but don't remove Windows paths
                    if commands[0].startswith('/'):
                        commands[0] = commands[0].split('/')[-1]
                    if len(commands) > 0 and commands[0] == 'env':
                        commands = commands[1:]
                    # Windows does not ship python3.exe, but we know the path to it
                    if len(commands) > 0 and commands[0] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                elif mesonlib.is_haiku():
                    # Haiku does not have /usr, but a lot of scripts assume that
                    # /usr/bin/env always exists. Detect that case and run the
                    # script with the interpreter after it.
                    if commands[0] == '/usr/bin/env':
                        commands = commands[1:]
                    # We know what python3 is, we're running on it
                    if len(commands) > 0 and commands[0] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                else:
                    # Replace python3 with the actual python3 that we are using
                    if commands[0] == '/usr/bin/env' and commands[1] == 'python3':
                        commands = mesonlib.python_command + commands[2:]
                    elif commands[0].split('/')[-1] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                return commands + [script]
        except Exception as e:
            mlog.debug(str(e))
        mlog.debug(f'Unusable script {script!r}')
        return None

    def _is_executable(self, path: str) -> bool:
        suffix = os.path.splitext(path)[-1].lower()[1:]
        execmask = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        if mesonlib.is_windows():
            if suffix in self.windows_exts:
                return True
        elif os.stat(path).st_mode & execmask:
            return not os.path.isdir(path)
        return False

    def _search_dir(self, name: str, search_dir: T.Optional[str]) -> T.Optional[list]:
        if search_dir is None:
            return None
        trial = os.path.join(search_dir, name)
        if os.path.exists(trial):
            if self._is_executable(trial):
                return [trial]
            # Now getting desperate. Maybe it is a script file that is
            # a) not chmodded executable, or
            # b) we are on windows so they can't be directly executed.
            return self._shebang_to_cmd(trial)
        else:
            if mesonlib.is_windows():
                for ext in self.windows_exts:
                    trial_ext = f'{trial}.{ext}'
                    if os.path.exists(trial_ext):
                        return [trial_ext]
        return None

    def _search_windows_special_cases(self, name: str, command: str) -> T.List[T.Optional[str]]:
        '''
        Lots of weird Windows quirks:
        1. PATH search for @name returns files with extensions from PATHEXT,
           but only self.windows_exts are executable without an interpreter.
        2. @name might be an absolute path to an executable, but without the
           extension. This works inside MinGW so people use it a lot.
        3. The script is specified without an extension, in which case we have
           to manually search in PATH.
        4. More special-casing for the shebang inside the script.
        '''
        if command:
            # On Windows, even if the PATH search returned a full path, we can't be
            # sure that it can be run directly if it's not a native executable.
            # For instance, interpreted scripts sometimes need to be run explicitly
            # with an interpreter if the file association is not done properly.
            name_ext = os.path.splitext(command)[1]
            if name_ext[1:].lower() in self.windows_exts:
                # Good, it can be directly executed
                return [command]
            # Try to extract the interpreter from the shebang
            commands = self._shebang_to_cmd(command)
            if commands:
                return commands
            return [None]
        # Maybe the name is an absolute path to a native Windows
        # executable, but without the extension. This is technically wrong,
        # but many people do it because it works in the MinGW shell.
        if os.path.isabs(name):
            for ext in self.windows_exts:
                command = f'{name}.{ext}'
                if os.path.exists(command):
                    return [command]
        # On Windows, interpreted scripts must have an extension otherwise they
        # cannot be found by a standard PATH search. So we do a custom search
        # where we manually search for a script with a shebang in PATH.
        search_dirs = self._windows_sanitize_path(os.environ.get('PATH', '')).split(';')
        for search_dir in search_dirs:
            commands = self._search_dir(name, search_dir)
            if commands:
                return commands
        return [None]

    def _search(self, name: str, search_dir: T.Optional[str]) -> T.List[T.Optional[str]]:
        '''
        Search in the specified dir for the specified executable by name
        and if not found search in PATH
        '''
        commands = self._search_dir(name, search_dir)
        if commands:
            return commands
        # If there is a directory component, do not look in PATH
        if os.path.dirname(name) and not os.path.isabs(name):
            return [None]
        # Do a standard search in PATH
        path = os.environ.get('PATH', None)
        if mesonlib.is_windows() and path:
            path = self._windows_sanitize_path(path)
        command = shutil.which(name, path=path)
        if mesonlib.is_windows():
            return self._search_windows_special_cases(name, command)
        # On UNIX-like platforms, shutil.which() is enough to find
        # all executables whether in PATH or with an absolute path
        return [command]

    def found(self) -> bool:
        return self.command[0] is not None

    def get_command(self) -> T.List[str]:
        return self.command[:]

    def get_path(self) -> T.Optional[str]:
        return self.path

    def get_name(self) -> str:
        return self.name


class NonExistingExternalProgram(ExternalProgram):  # lgtm [py/missing-call-to-init]
    "A program that will never exist"

    def __init__(self, name: str = 'nonexistingprogram') -> None:
        self.name = name
        self.command = [None]
        self.path = None

    def __repr__(self) -> str:
        r = '<{} {!r} -> {!r}>'
        return r.format(self.__class__.__name__, self.name, self.command)

    def found(self) -> bool:
        return False


class OverrideProgram(ExternalProgram):

    """A script overriding a program."""


def find_external_program(env: 'Environment', for_machine: MachineChoice, name: str,
                          display_name: str, default_names: T.List[str],
                          allow_default_for_cross: bool = True) -> T.Generator['ExternalProgram', None, None]:
    """Find an external program, checking the cross file plus any default options."""
    potential_names = OrderedSet(default_names)
    potential_names.add(name)
    # Lookup in cross or machine file.
    for potential_name in potential_names:
        potential_cmd = env.lookup_binary_entry(for_machine, potential_name)
        if potential_cmd is not None:
            mlog.debug(f'{display_name} binary for {for_machine} specified from cross file, native file, '
                       f'or env var as {potential_cmd}')
            yield ExternalProgram.from_entry(potential_name, potential_cmd)
            # We never fallback if the user-specified option is no good, so
            # stop returning options.
            return
    mlog.debug(f'{display_name} binary missing from cross or native file, or env var undefined.')
    # Fallback on hard-coded defaults, if a default binary is allowed for use
    # with cross targets, or if this is not a cross target
    if allow_default_for_cross or not (for_machine is MachineChoice.HOST and env.is_cross_build(for_machine)):
        for potential_path in default_names:
            mlog.debug(f'Trying a default {display_name} fallback at', potential_path)
            yield ExternalProgram(potential_path, silent=True)
    else:
        mlog.debug('Default target is not allowed for cross use')
```