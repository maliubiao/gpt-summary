Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `programs.py` file within the Frida project and relate it to concepts relevant to reverse engineering, low-level operations, and common programming errors. The request also emphasizes debugging and tracing the execution flow.

**2. Initial Code Scan and Core Components Identification:**

The first step is a quick skim of the code to identify the key classes and their responsibilities. We see:

* **`ExternalProgram`:** This is the central class. It seems to represent a program that can be executed, either found on the system or specified explicitly.
* **`NonExistingExternalProgram`:**  A subclass of `ExternalProgram` indicating a program that couldn't be found.
* **`OverrideProgram`:**  Another subclass, likely used for substituting a default program.
* **`find_external_program`:** A function for locating external programs, potentially using configuration files or defaults.

**3. Deep Dive into `ExternalProgram`:**

This is the most important class, so a more detailed examination is needed. Key aspects to analyze:

* **Initialization (`__init__`)**: How is an `ExternalProgram` created?  It takes a `name` and an optional `command`. It searches for the command if not provided. The code handles platform differences (Windows) and shebangs.
* **`found()`**:  Simple check if the program was located.
* **`get_command()`**: Returns the command to execute the program.
* **`get_path()`**: Returns the path to the executable.
* **`get_version()`**:  Crucial for understanding how Meson might interact with external tools. It executes the program with `--version` and parses the output. This immediately connects to reverse engineering scenarios (checking tool versions).
* **`from_bin_list()` and `from_entry()`**:  These are factory methods for creating `ExternalProgram` instances based on configuration. This points to Meson's configuration mechanism.
* **`_shebang_to_cmd()`**:  A vital function for handling scripts on non-Unix systems and even on Unix when executability is an issue.
* **`_is_executable()`**: Platform-specific logic for determining if a file is executable.
* **`_search_dir()` and `_search()`**:  The core logic for finding programs in specified directories and the system's `PATH`. The Windows-specific handling (`_windows_sanitize_path`, `_search_windows_special_cases`) is interesting.

**4. Analyzing Other Components:**

* **`NonExistingExternalProgram`**: Straightforward – represents a failed lookup.
* **`OverrideProgram`**:  Implies a mechanism for replacing default tools.
* **`find_external_program`**:  This function orchestrates the search process, consulting configuration and falling back to defaults.

**5. Connecting to Reverse Engineering Concepts:**

Now, the crucial step is linking the code's functionality to reverse engineering practices. The key connections are:

* **External Tools:**  Reverse engineering often involves using various tools (disassemblers, debuggers, etc.). `ExternalProgram` is the way Meson manages these tools.
* **Tool Versions:**  Compatibility between tools is vital. `get_version()` directly supports this.
* **Scripting:**  Many reverse engineering tasks involve scripting. The shebang handling is relevant here.
* **Platform Differences:** Reverse engineering targets different platforms. The code's platform-specific logic reflects this reality.

**6. Connecting to Low-Level Concepts:**

Think about what's happening under the hood:

* **Binary Execution:** The code ultimately deals with running executables.
* **File System Interaction:** Searching for files, checking executability.
* **Operating System APIs:**  Using `os` and `shutil` modules for interacting with the OS.
* **Process Management:** Implicitly involved when running external commands (though not explicitly coded here, Meson uses other mechanisms).
* **Path Manipulation:** Working with file paths and the `PATH` environment variable.

**7. Considering User Errors and Debugging:**

Think about how users might misuse or encounter issues with this code:

* **Incorrect Tool Names:**  Typing errors in specifying tool names.
* **Missing Tools:** Tools not installed or not in the `PATH`.
* **Incorrect Cross-Compilation Setup:**  Problems finding the right tools for the target architecture.
* **File Permission Issues:**  Scripts not being executable.

**8. Hypothetical Input/Output and Examples:**

Creating concrete examples helps solidify understanding:

* **Successful Tool Location:**  Demonstrating how Meson finds a tool like `objdump`.
* **Failed Tool Location:** Showing what happens when a tool isn't found.
* **Shebang Handling:** Illustrating how a Python script without execute permissions can still be run.

**9. Tracing User Actions:**

Consider how a user's actions in a Meson build file would lead to the execution of this code. This involves understanding the build process and how Meson resolves dependencies and tools.

**10. Structure and Refinement:**

Finally, organize the findings into a clear and structured explanation, using headings, bullet points, and code snippets to illustrate key points. Refine the language and ensure clarity.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about finding executables."
* **Correction:** "No, it's more sophisticated. It handles shebangs, Windows quirks, and versioning, making it more relevant to scripting and toolchain management."
* **Initial thought:** "The reverse engineering connection is weak."
* **Correction:** "Actually, Meson uses this code to manage the external tools *used* in reverse engineering, like compilers and linkers for different architectures, and utilities like `objdump`."

By following this systematic approach, combining code analysis with conceptual understanding, and considering potential use cases and errors, a comprehensive and informative explanation of the code can be generated.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/programs.py` 文件的源代码，它定义了 Meson 构建系统中用于表示和处理外部及内部程序的功能。

以下是该文件的主要功能及其与逆向、底层、内核、用户错误和调试的关联：

**1. 表示和查找外部程序 (`ExternalProgram` 类):**

* **功能:**
    * 封装了对系统上可执行程序的表示，包括程序名、路径和执行命令。
    * 提供了在系统 `PATH` 环境变量以及指定目录中搜索可执行文件的能力。
    * 针对 Windows 平台处理了特殊的可执行文件类型（.exe, .com, .bat, .cmd）和路径查找的逻辑。
    * 支持从脚本文件的 shebang 行中提取解释器信息，以便在无法直接执行脚本时使用正确的解释器。
    * 提供了获取程序版本信息的功能 (`get_version`)。

* **与逆向方法的关联:**
    * **工具依赖:** 逆向工程工作流通常依赖于各种外部工具，例如反汇编器 (如 `objdump`, `ida`), 调试器 (如 `gdb`, `lldb`), 动态分析工具 (如 Frida 本身，但在这里是 Meson 构建系统的一部分，用于构建 Frida 工具)。`ExternalProgram` 类用于查找和管理这些工具的路径和执行方式。
    * **举例:**  假设 Frida 工具的构建过程需要使用 `objdump` 来处理二进制文件。Meson 会使用 `ExternalProgram` 类来查找系统中可用的 `objdump` 程序。

* **涉及二进制底层、Linux, Android 内核及框架的知识:**
    * **二进制文件:**  此类处理的是可执行的二进制文件，这与理解二进制文件的结构和执行方式密切相关。
    * **Linux `PATH` 环境变量:**  程序搜索的核心机制依赖于 Linux 和其他类 Unix 系统中的 `PATH` 环境变量。
    * **Windows 可执行文件类型:**  代码中明确处理了 Windows 特有的可执行文件扩展名。
    * **Shebang 行:**  Shebang 行是 Linux 和类 Unix 系统中用于指定脚本解释器的机制。
    * **举例:**  在构建针对 Android 平台的 Frida 工具时，Meson 可能会使用 `ExternalProgram` 来查找 Android SDK 中的工具，这些工具可能涉及到与 Android 框架交互的二进制文件。

* **逻辑推理:**
    * **假设输入:**  程序名为 `objdump`。
    * **输出:**  如果系统中存在 `objdump` 可执行文件，`ExternalProgram` 实例的 `command` 属性将包含 `['objdump']` 或 `['/usr/bin/objdump']` 等路径。如果找不到，`command` 将包含 `[None]`。

* **用户或编程常见的使用错误:**
    * **工具未安装或不在 PATH 中:**  如果用户没有安装构建 Frida 工具所需的外部程序（如编译器、链接器等）或这些程序没有添加到系统的 `PATH` 环境变量中，Meson 将无法找到这些程序，导致构建失败。
    * **错误的程序名:**  在 Meson 构建文件中指定了错误的外部程序名称，导致查找失败。
    * **Windows 平台文件扩展名问题:**  在 Windows 上，如果用户试图执行一个没有正确扩展名的可执行文件，`ExternalProgram` 可能会找不到它，除非它是一个脚本文件并且 shebang 行正确配置。

* **用户操作是如何一步步的到达这里，作为调试线索:**
    1. **用户尝试构建 Frida 工具:** 用户通常会执行类似 `meson setup build` 或 `ninja` 的命令来启动构建过程。
    2. **Meson 解析构建文件:** Meson 会读取 `meson.build` 文件，其中可能包含对外部程序的依赖。例如，使用 `find_program()` 函数查找编译器或链接器。
    3. **`find_program()` 调用:**  `find_program()` 函数最终会调用 `find_external_program` 函数（也在该文件中），后者会创建 `ExternalProgram` 实例来搜索指定的程序。
    4. **`ExternalProgram` 的初始化和搜索:** `ExternalProgram` 的 `__init__` 方法会被调用，根据提供的程序名，它会在 `PATH` 环境变量和指定的目录中搜索可执行文件。
    5. **搜索失败:** 如果程序未找到，`ExternalProgram` 实例的 `found()` 方法将返回 `False`。
    6. **构建错误:**  Meson 会报告找不到所需程序的错误，并可能终止构建过程。

**2. 表示不存在的外部程序 (`NonExistingExternalProgram` 类):**

* **功能:**  `ExternalProgram` 的子类，用于表示查找失败的外部程序。

**3. 表示覆盖的程序 (`OverrideProgram` 类):**

* **功能:**  `ExternalProgram` 的子类，可能用于在某些情况下替换默认的程序。具体用途需要参考 Frida 工具的构建逻辑。

**4. 查找外部程序的函数 (`find_external_program`):**

* **功能:**
    * 封装了查找外部程序的逻辑，可以从 Meson 的交叉编译配置文件或本机配置文件中查找程序。
    * 支持提供一组默认的程序名称作为查找的后备选项。
    * 区分交叉编译场景和本机编译场景，并根据情况允许使用默认程序。

* **与逆向方法的关联:**
    * **交叉编译环境:** 在逆向工程中，可能需要在宿主机上构建运行在目标设备（如 Android 设备）上的工具。`find_external_program` 能够根据交叉编译配置文件查找目标平台的工具。

* **涉及二进制底层、Linux, Android 内核及框架的知识:**
    * **交叉编译:**  该函数的设计考虑了交叉编译的需求，例如需要查找目标架构的编译器和链接器。

* **逻辑推理:**
    * **假设输入:**  要查找的程序名为 `arm-linux-gnueabi-gcc`，并且在 Meson 的交叉编译配置文件中指定了该程序的路径。
    * **输出:** `find_external_program` 将返回一个 `ExternalProgram` 实例，其 `command` 属性包含了配置文件中指定的 `arm-linux-gnueabi-gcc` 的路径。

* **用户或编程常见的使用错误:**
    * **交叉编译配置文件错误:**  如果交叉编译配置文件中指定的程序路径不正确，`find_external_program` 将无法找到正确的工具。

**总结:**

`programs.py` 文件在 Frida 工具的构建过程中扮演着关键角色，它负责查找和管理构建过程中需要的各种外部程序。这与逆向工程密切相关，因为逆向工作流依赖于各种工具。该文件也涉及到操作系统底层、二进制文件处理以及跨平台构建的知识。理解这个文件的功能有助于理解 Meson 如何管理构建依赖，以及在构建过程中可能出现的与外部程序相关的错误。当构建 Frida 工具遇到 "找不到程序" 类型的错误时，可以从此文件入手，查看 Meson 是如何搜索和处理外部程序的。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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