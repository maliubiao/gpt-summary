Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Request:**

The user wants to understand the functionality of the provided Python code snippet. They're specifically interested in connections to reverse engineering, low-level concepts (binary, kernel, etc.), logical reasoning, common user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and Goal Identification:**

The first step is a quick read-through to get a general sense of what the code does. Keywords like "ExternalProgram," "search," "version," "path," and imports like `os`, `shutil`, and `stat` suggest this code is about finding and managing external executables. The comments mentioning "SPDX-License-Identifier" and "Copyright" confirm it's part of a larger project.

**3. Deeper Dive into Key Classes and Functions:**

Now, go through the code more systematically, focusing on the classes and their methods:

*   **`ExternalProgram`:** This is the core class. Its `__init__` method handles finding the program, either by explicit command or by searching. Other key methods are `get_version`, `found`, `get_command`, and `get_path`. The `_search` and `_search_windows_special_cases` methods are crucial for understanding how the program is located on the system.
*   **`NonExistingExternalProgram`:**  A straightforward subclass to represent a program that wasn't found.
*   **`OverrideProgram`:**  Indicates a way to override the default program.
*   **`find_external_program`:** A utility function to find external programs, considering cross-compilation scenarios.

**4. Connecting to the User's Specific Questions:**

With a good understanding of the code's structure, address each of the user's points:

*   **Reverse Engineering:**  Think about how finding and interacting with external programs could be relevant to reverse engineering. The core idea is *dynamic instrumentation*. Frida allows you to inject code into running processes. Finding the target process's executable is a prerequisite. This connects `ExternalProgram` to the very beginning of a Frida-based reverse engineering workflow. Examples like finding `lldb` or `gdb` for debugging are good concrete illustrations.
*   **Binary/Low-Level, Kernel, Android:**  Focus on the interactions with the operating system. `os.path`, `shutil.which`, `stat`, and the handling of shebangs directly involve OS-level operations. Consider how these operations differ between operating systems (especially Windows vs. Unix-like). The mention of PATH and PATHEXT environment variables is also relevant. For Android, think about how Frida interacts with the Android framework and how finding executables within the Android environment might differ. While this specific file isn't directly *in* the kernel, it's a necessary step in tools that *do* interact with the kernel.
*   **Logical Reasoning (Hypothetical Inputs/Outputs):**  Pick a specific scenario, like searching for `python3`. Walk through the `_search` function, showing how it checks specific directories and the PATH. Illustrate what happens if the program is found or not found, highlighting the different outputs of the `found()` method.
*   **User Errors:** Consider common mistakes users make when specifying program names or paths. Incorrect spelling, forgetting extensions on Windows, or not having the program in the PATH are typical issues. Explain how this code might react to these errors (e.g., returning `NonExistingExternalProgram`).
*   **User Journey (Debugging Clues):** Trace back how a user might end up interacting with this code. They might be defining build dependencies in a `meson.build` file, specifying tools needed for their project. When Meson (the build system) processes this file, it uses this code to locate the specified programs. If a program isn't found, Meson will report an error, providing the user with a debugging clue.

**5. Structuring the Answer:**

Organize the findings logically, using the user's questions as a framework. Use clear headings and bullet points for readability. Provide specific code snippets or examples where appropriate.

**6. Refinement and Clarity:**

Review the answer to ensure accuracy and clarity. Avoid jargon where possible or explain technical terms. Make sure the examples are easy to understand and directly relate to the concepts being explained. For instance, initially I might just say "it searches the PATH", but adding the nuance of Windows PATHEXT and the handling of shebangs makes the explanation more complete. Similarly, just saying "it's used in reverse engineering" is vague; specifying Frida and the concept of dynamic instrumentation provides better context.

This detailed thought process allows for a comprehensive and accurate analysis of the code, directly addressing all aspects of the user's request. It's a combination of understanding the code's mechanics and connecting it to broader concepts and real-world scenarios.
这个 `programs.py` 文件是 Frida 动态 instrumentation 工具中，Meson 构建系统用于处理外部和内部程序定义的模块。它的主要功能是**表示和查找系统中的可执行程序**，并在构建过程中提供对这些程序的访问。

以下是它的功能及其与您提出的各个方面的关联：

**1. 功能列表:**

*   **表示外部程序 (`ExternalProgram` 类):**
    *   封装了关于外部程序的信息，例如程序名称 (`name`)、完整路径 (`path`) 和执行命令 (`command`)。
    *   可以根据程序名在系统路径 (`PATH`) 中搜索程序。
    *   可以处理 Windows 特殊的文件扩展名 (`.exe`, `.com` 等)。
    *   可以解析脚本文件开头的 Shebang (`#!`) 行，以确定正确的解释器。
    *   提供方法 (`found()`) 来判断程序是否找到。
    *   提供方法 (`get_command()`) 获取用于执行程序的完整命令列表。
    *   提供方法 (`get_path()`) 获取程序的可执行文件路径。
    *   提供方法 (`get_version()`) 尝试获取程序的版本信息（通过执行 `program --version`）。
    *   可以从 Meson 的构建配置文件（cross 或 native 文件）中查找程序路径。

*   **表示不存在的外部程序 (`NonExistingExternalProgram` 类):**
    *   `ExternalProgram` 的子类，用于表示未找到的程序。

*   **表示覆盖的程序 (`OverrideProgram` 类):**
    *   `ExternalProgram` 的子类，可能用于表示用户自定义的程序路径覆盖。

*   **查找外部程序 (`find_external_program` 函数):**
    *   提供了一种更高级的方式来查找外部程序，它会优先查找构建配置文件中的定义，然后回退到默认的程序名列表。
    *   考虑了交叉编译的情况，可以为不同的目标机器查找不同的程序。

**2. 与逆向方法的关联 (举例说明):**

这个文件直接支持了 Frida 的核心功能，因为它负责找到将被 Frida 注入的目标进程。

*   **例子:** 当你使用 Frida 连接到一个正在运行的进程时，Frida 内部可能需要找到 `lldb` (在 macOS/iOS 上) 或 `gdb` (在 Linux/Android 上) 这样的调试器，以便进行更底层的操作或者符号解析。`programs.py` 中的 `ExternalProgram` 类会被用来在系统中搜索这些调试器。
*   **例子:**  假设你的 Frida 脚本需要调用一个外部工具来辅助分析，比如一个反汇编器。你可以在你的 `meson.build` 文件中声明这个外部程序，Meson 会使用 `programs.py` 来找到它。然后，你的 Frida 脚本可以通过 Meson 提供的接口来执行这个外部程序。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

*   **二进制底层:**
    *   **可执行文件搜索:**  代码中使用了 `os.path.exists` 和 `os.stat` 来检查文件是否存在以及是否具有执行权限。这直接涉及了操作系统对二进制可执行文件的底层管理。
    *   **Windows 文件扩展名:** 代码特别处理了 Windows 的可执行文件扩展名 (`.exe`, `.com` 等)，这反映了 Windows 系统识别可执行文件的底层机制。
    *   **Shebang 解析:**  解析 Shebang 行 (`#!`) 是理解 Linux 和其他 Unix-like 系统如何执行脚本的关键。`_shebang_to_cmd` 函数模拟了这个过程，这与操作系统加载和执行不同类型二进制文件的方式有关。

*   **Linux:**
    *   **PATH 环境变量:**  代码中使用了 `os.environ.get('PATH')` 来获取系统的路径环境变量，并在这些路径下搜索可执行文件，这是 Linux 系统查找命令的基础。
    *   **执行权限:**  `_is_executable` 函数中使用了 `stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH` 来检查文件的执行权限位，这是 Linux 文件权限模型的一部分。
    *   **`shutil.which`:** 代码使用了 `shutil.which` 函数，这是一个跨平台的工具，用于在 `PATH` 环境变量中查找可执行文件，这在 Linux 环境中非常常见。

*   **Android 内核及框架:**
    *   虽然这个文件本身不直接操作 Android 内核，但它为 Frida 这样的工具提供了基础，而 Frida 可以深入到 Android 框架甚至 native 层进行 instrumentation。例如，Frida 可能需要找到 `app_process` 或 `zygote` 这样的 Android 系统进程。
    *   在 Android 开发中，可能会使用到 NDK (Native Development Kit)，而 `programs.py` 可以用来查找 NDK 提供的工具链（例如编译器、链接器等）。

**4. 逻辑推理 (假设输入与输出):**

*   **假设输入:** 用户在 `meson.build` 文件中定义了一个依赖项 `dependency('my_tool')`，并且 `my_tool` 没有在系统的 `PATH` 环境变量中。
*   **输出:**  `ExternalProgram('my_tool')` 在初始化时，由于无法在 `PATH` 中找到 `my_tool`，`found()` 方法将返回 `False`。如果在构建过程中尝试执行这个程序，Meson 会抛出一个错误，提示找不到 `my_tool`。

*   **假设输入:**  用户在 `meson.build` 文件中通过 `find_program('python3')` 查找 Python 3 解释器。
*   **输出:**  `find_external_program` 函数会尝试在构建配置文件中查找 `python3` 的定义。如果没有找到，它会回退到默认的程序名 `python3`，并使用 `ExternalProgram('python3')` 在系统 `PATH` 中搜索。如果找到，`found()` 返回 `True`，`get_command()` 返回找到的 Python 3 解释器的完整路径。

**5. 涉及用户或者编程常见的使用错误 (举例说明):**

*   **错误的程序名:** 用户在 `meson.build` 文件中输入了错误的程序名，例如 `find_program('pyhton3')` (拼写错误)。
    *   **结果:** `ExternalProgram('pyhton3')` 将无法在系统中找到对应的程序，`found()` 将返回 `False`，构建过程会失败，并提示找不到程序。

*   **忘记 Windows 文件扩展名:** 在 Windows 上，用户可能尝试查找一个可执行文件时忘记添加 `.exe` 扩展名，例如 `find_program('my_app')`，但实际的文件名是 `my_app.exe`。
    *   **结果:**  如果 `my_app` 不在 `PATH` 中，并且没有 `.exe` 扩展名，`ExternalProgram('my_app')` 可能会找不到该程序。代码中的 `_search_windows_special_cases` 函数会尝试添加常见的 Windows 扩展名进行搜索，但这依赖于 `shutil.which` 的行为以及代码中的逻辑。

*   **程序不在 PATH 中:** 用户尝试使用的程序没有添加到系统的 `PATH` 环境变量中。
    *   **结果:** `ExternalProgram` 在默认情况下会搜索 `PATH`，如果程序不在其中，`found()` 将返回 `False`。用户需要在构建配置文件中提供程序的完整路径，或者将程序添加到 `PATH` 环境变量中。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 `meson.build` 文件:** 用户在项目的根目录下创建一个或多个 `meson.build` 文件，用于描述项目的构建过程。
2. **使用 `find_program()` 或 `dependency()`:** 在 `meson.build` 文件中，用户可能会使用 `find_program()` 函数来查找构建所需的外部工具（例如编译器、链接器、代码生成器等），或者使用 `dependency()` 来声明对其他库或工具的依赖。`dependency()` 内部也可能涉及到查找外部程序。
3. **运行 Meson 配置:** 用户在终端中执行 `meson setup builddir` 命令来配置构建。
4. **Meson 解析 `meson.build`:** Meson 在配置阶段会解析 `meson.build` 文件，当遇到 `find_program()` 或 `dependency()` 时，会调用相应的逻辑来查找指定的程序。
5. **调用 `programs.py`:**  Meson 的内部逻辑会使用 `programs.py` 模块中的 `ExternalProgram` 类或 `find_external_program` 函数来执行实际的程序查找操作。
6. **搜索程序:** `programs.py` 中的代码会根据提供的程序名和系统环境（例如 `PATH` 环境变量）来搜索可执行文件。
7. **记录查找结果:** `ExternalProgram` 会记录程序的查找结果（是否找到，以及程序的路径等）。
8. **构建过程使用程序信息:** 如果程序被成功找到，Meson 会将程序的信息存储起来，并在后续的编译、链接等构建步骤中使用。如果程序未找到，Meson 会报错，指示用户缺少必要的工具。

**调试线索:**

如果构建过程中出现与找不到程序相关的错误，用户可以检查以下内容，这与 `programs.py` 的功能直接相关：

*   **`meson.build` 文件中程序名的拼写是否正确。**
*   **对于 Windows 用户，是否需要添加 `.exe` 等扩展名。**
*   **指定的程序是否已经安装在系统中。**
*   **程序的可执行文件路径是否已经添加到系统的 `PATH` 环境变量中。**
*   **如果使用了交叉编译，是否为目标平台配置了正确的工具链。** (这会影响 Meson 在哪里查找程序)
*   **检查 Meson 的配置输出，看是否有关于程序查找的详细日志信息。**

总而言之，`programs.py` 是 Frida 使用 Meson 构建系统的一个基础模块，它负责定位构建和运行时所需的外部程序，这对于 Frida 的正常运行和功能实现至关重要，并且与逆向工程、底层操作系统知识以及常见的用户操作紧密相关。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```