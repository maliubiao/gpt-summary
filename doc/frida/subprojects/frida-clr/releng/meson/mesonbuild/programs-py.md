Response:
Let's break down the thought process for analyzing the provided Python code.

**1. Understanding the Goal:** The core request is to analyze the functionality of the `programs.py` file from the Frida project and relate it to reverse engineering, low-level concepts, and common user errors.

**2. Initial Reading and Keyword Identification:**  A quick skim reveals key classes: `ExternalProgram`, `NonExistingExternalProgram`, and `OverrideProgram`. The names themselves provide hints. Keywords like "search," "path," "executable," "version," "shebang," and "windows" stand out.

**3. Focus on `ExternalProgram`:** This is the central class. It seems responsible for representing and finding external programs needed by the build system.

**4. Deconstructing `ExternalProgram.__init__`:**  This is crucial for understanding how programs are located.

    * **`command` argument:**  If provided, the program is already known. The code checks for shebangs on Windows.
    * **`search_dir` and `extra_search_dirs`:** If `command` is not given, these are used to search. This immediately suggests a path-searching mechanism.
    * **`_search` method:** This is the core search logic. It checks `search_dir` and then the `PATH` environment variable.
    * **Windows handling:** The `_windows_sanitize_path` and `_search_windows_special_cases` methods highlight specific logic for Windows, indicating awareness of its quirks.

**5. Analyzing Other Methods in `ExternalProgram`:**

    * **`get_version`:**  Executes the program with `--version` and parses the output, relevant for checking tool versions.
    * **`from_bin_list` and `from_entry`:**  Ways to create `ExternalProgram` instances from configuration files or explicit commands.
    * **`_shebang_to_cmd`:**  Crucial for executing scripts without explicit interpreter calls. This ties into how executables are handled on different systems.
    * **`_is_executable`:**  Determines if a file can be executed, with OS-specific logic.
    * **`found`:** A simple check for whether the program was located.

**6. Connecting to Reverse Engineering:**

    * **Finding tools:** Reverse engineering often involves using external tools (debuggers, disassemblers, etc.). This code is about *finding* those tools.
    * **Dynamic Instrumentation (Frida's purpose):**  The context of Frida is important. Finding `frida-server` or other related tools would be managed by this code.
    * **Example:**  Imagine Frida needs `adb` to interact with Android. This code would handle finding the `adb` executable.

**7. Connecting to Binary/Low-Level Concepts:**

    * **Executable bit:** The `_is_executable` method directly deals with file permissions, a low-level operating system concept.
    * **`PATH` environment variable:**  Understanding how the operating system searches for executables is fundamental.
    * **Shebangs:**  A mechanism for specifying the interpreter for a script, directly related to how scripts are executed.
    * **Windows executable extensions (`.exe`, `.com`, etc.):** Platform-specific knowledge is embedded.

**8. Connecting to Linux/Android Kernel and Framework:**

    * **`adb` (again):** A key tool for interacting with Android devices.
    * **Cross-compilation (`for_machine`):**  The code handles scenarios where tools might be different for the build machine versus the target machine (e.g., compiling for Android on a Linux host).

**9. Logical Inference and Examples:**

    * **Assumptions:**  The code assumes a standard structure for version output (containing a number).
    * **Input/Output:** Consider the `get_version` method. Input: an `ExternalProgram` object. Output: a version string.
    * **Example:** If the input `command` is `['gcc']`, the output of `get_version()` might be something like "9.4.0".

**10. Identifying User/Programming Errors:**

    * **Incorrect PATH:** If the required program isn't in the `PATH`, it won't be found.
    * **Typos in program names:**  A simple mistake in the configuration.
    * **Missing executable bit (on Linux):**  A script won't be found if it's not executable.
    * **Shebang issues:** Incorrect or missing shebangs on scripts.
    * **Cross-compilation problems:** Not specifying the correct path for target tools.

**11. Tracing User Actions (Debugging Clues):**

    * **Configuration files:** The user likely configured the build system using Meson's files, specifying dependencies and tool locations.
    * **Command-line invocation:**  The user ran the Meson build command, triggering the program search.
    * **Error messages:** If a program isn't found, Meson will likely output an error message, leading the user to investigate.
    * **Debugging output (`mlog.debug`):** The `mlog.debug` calls within the code are valuable for understanding the search process.

**12. Structuring the Answer:**  Organize the findings into logical sections as requested by the prompt (functionality, reverse engineering, low-level, logic, errors, debugging). Use clear examples and explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on just the `_search` method. Realization: the `__init__` method sets the stage for the search.
* **Overlooking Windows specifics:**  Acknowledge the dedicated Windows logic.
* **Not connecting to Frida directly enough:** Emphasize how this code would be used *within* the Frida project.
* **Vague error examples:**  Make the error examples more concrete and relatable.

By following this detailed thought process, we can thoroughly analyze the code and generate a comprehensive answer that addresses all aspects of the prompt.
这是 Frida 动态 instrumentation 工具中负责处理外部和内部程序定义的 Python 代码文件。它的主要功能是**在构建过程中查找和管理构建、主机和目标平台上需要的各种可执行程序**。

以下是对其功能的详细列举，并结合逆向、底层、内核框架知识以及可能的用户错误进行说明：

**功能列举：**

1. **表示外部程序:**  `ExternalProgram` 类用于表示系统上找到的外部可执行程序。它存储了程序的名称、完整路径（如果找到）、缓存的版本信息以及执行命令（包含程序路径和可能的参数）。

2. **查找外部程序:**  `ExternalProgram.__init__` 方法负责根据给定的名称或命令查找程序。
   - 如果提供了 `command`，则直接使用。对于 Windows，它还会检查脚本文件的 Shebang 并插入相应的解释器。
   - 如果没有提供 `command`，它会在指定的 `search_dir` 和 `PATH` 环境变量中搜索程序。
   - 对于 Windows，它有特殊的处理逻辑，考虑了文件扩展名、绝对路径以及脚本文件的 Shebang。

3. **表示不存在的程序:** `NonExistingExternalProgram` 类用于表示未能找到的程序。

4. **表示覆盖的程序:** `OverrideProgram` 类可能用于表示用户自定义的、覆盖默认行为的程序。

5. **获取程序信息:**
   - `get_command()`: 返回用于执行程序的完整命令列表。
   - `get_path()`: 返回程序的可执行文件路径。
   - `get_name()`: 返回程序的名称。
   - `get_version()`:  尝试执行程序并使用 `--version` 参数来获取程序的版本号。它会解析输出以提取版本信息。

6. **判断程序是否找到:** `found()` 方法返回一个布尔值，指示程序是否被成功找到。

7. **从配置中加载程序:** `ExternalProgram.from_bin_list()` 和 `ExternalProgram.from_entry()` 方法用于从构建配置文件（如 Meson 的 cross 或 machine 文件）中加载程序信息。

8. **查找外部程序工具函数:** `find_external_program()` 函数提供了一种更高级的方式来查找外部程序，它会考虑构建配置文件中的设置以及默认的程序名称。

**与逆向方法的关联及举例说明：**

* **查找逆向工具:**  在构建 Frida 本身或使用 Frida 的项目中，可能需要依赖一些逆向分析工具，例如：
    * **`lldb` 或 `gdb` (调试器):** 用于调试 Frida 自身或 Frida 所 hook 的目标进程。`programs.py` 可以用来查找系统上安装的调试器。
    * **`objdump` 或 `readelf` (二进制分析工具):** 用于分析目标二进制文件的结构。
    * **自定义的脚本或工具:**  用户可能编写了自己的逆向分析脚本，`programs.py` 可以用来查找这些脚本。

   **举例:**  假设 Frida 的构建系统需要确保 `lldb` 调试器可用。Meson 的构建定义可能会调用 `find_external_program` 并传入 `lldb` 作为名称。`programs.py` 会在 `PATH` 环境变量中搜索 `lldb` 可执行文件。

* **查找目标平台的工具:** 当 Frida 被构建为针对 Android 或 iOS 等平台时，可能需要查找这些平台特定的工具，例如：
    * **`adb` (Android 调试桥):**  用于与 Android 设备进行通信。
    * **`codesign` (macOS 代码签名工具):**  用于签名 Frida 的组件。

   **举例:**  在为 Android 构建 Frida Server 时，`programs.py` 可能会查找 `adb` 工具，以便在构建后可以将 Frida Server 推送到 Android 设备上。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **可执行文件属性 (二进制底层/Linux):** `_is_executable()` 方法检查文件的执行权限位 (`stat.S_IXUSR`, `stat.S_IXGRP`, `stat.S_IXOTH`)，这是 Linux 文件系统的重要概念，用于确定用户是否有权限执行该文件。

* **PATH 环境变量 (Linux/Windows):** 代码依赖 `PATH` 环境变量来查找可执行文件。理解 `PATH` 的作用以及操作系统如何使用它来定位程序是至关重要的。`_search()` 方法会根据 `PATH` 中的目录列表进行搜索。

* **文件扩展名 (Windows):**  在 Windows 上，可执行文件通常有特定的扩展名（如 `.exe`, `.com`, `.bat`）。`windows_exts` 变量和相关的搜索逻辑反映了 Windows 下查找可执行文件的特点。

* **Shebang (Linux/脚本执行):** `_shebang_to_cmd()` 方法解析脚本文件（如 Python 或 Shell 脚本）的第一行（Shebang），以确定应该使用哪个解释器来执行该脚本。这涉及到操作系统如何处理脚本执行的底层机制。

* **交叉编译 (内核/框架):**  `for_machine` 参数和 `MachineChoice` 枚举表明代码考虑了交叉编译的场景。在为不同的目标平台（例如 Android）构建时，需要使用针对该平台的工具链，而不是主机平台的工具链。`find_external_program` 可以从 cross 文件中查找目标平台的工具。

   **举例:**  在为 Android 构建 Frida 时，`for_machine` 可能被设置为 `MachineChoice.TARGET`。构建系统可能会使用 `find_external_program` 来查找 Android NDK 中的编译器（例如 `aarch64-linux-android-gcc`）。

* **Android 特定的工具:**  如上面提到的 `adb`，是 Android 开发和逆向中常用的工具，`programs.py` 需要能够找到它。

**逻辑推理及假设输入与输出：**

**假设输入:**
1. 调用 `ExternalProgram('python3')`，并且系统 `PATH` 环境变量中包含 `/usr/bin`，其中 `/usr/bin/python3` 是一个可执行文件。
2. 调用 `ExternalProgram(command=['/opt/my_tool', '--some-option'])`。
3. 调用 `ExternalProgram('myscript.py')`，并且 `myscript.py` 的第一行是 `#!/usr/bin/env python3`，但该文件本身没有执行权限。

**输出:**

1. `ExternalProgram('python3')` 的 `found()` 将返回 `True`，`get_command()` 可能返回 `['/usr/bin/python3']`，`get_path()` 返回 `/usr/bin/python3`.
2. `ExternalProgram(command=['/opt/my_tool', '--some-option'])` 的 `found()` 将返回 `True`，`get_command()` 返回 `['/opt/my_tool', '--some-option']`，`get_path()` 返回 `/opt/my_tool`.
3. `ExternalProgram('myscript.py')` 的 `found()` 将返回 `True`，`get_command()` 在 Linux 上可能返回 `['/usr/bin/python3', 'myscript.py']`（假设 `/usr/bin/env python3` 解析为 `/usr/bin/python3`），在 Windows 上会尝试找到 `python3.exe` 并执行。

**涉及用户或编程常见的使用错误及举例说明：**

1. **`PATH` 环境变量配置错误:** 如果用户没有将所需的程序所在的目录添加到 `PATH` 环境变量中，`programs.py` 将无法找到该程序。
   **举例:** 构建系统需要 `cmake`，但用户没有安装 `cmake` 或者 `cmake` 的安装路径不在 `PATH` 中，Meson 构建会报错提示找不到 `cmake`。

2. **程序名称拼写错误:**  在构建配置文件中或作为参数传递给 `ExternalProgram` 时，如果程序名称拼写错误，将无法找到该程序。
   **举例:**  用户错误地将 `gcc` 写成 `gc`，构建系统会报告找不到名为 `gc` 的程序。

3. **缺少执行权限 (Linux):**  如果需要执行的脚本文件没有设置执行权限，即使 `programs.py` 找到了该文件，也可能无法直接执行。`_shebang_to_cmd` 可以缓解这个问题，因为它会尝试使用解释器来执行脚本。
   **举例:** 用户创建了一个 Python 脚本 `my_util.py`，但忘记了使用 `chmod +x my_util.py` 添加执行权限。如果构建系统尝试直接执行它，可能会失败。

4. **交叉编译配置错误:**  在交叉编译场景下，如果 cross 文件或 machine 文件中指定的目标平台工具路径不正确，`programs.py` 将无法找到正确的工具。
   **举例:**  在为 Android 构建时，cross 文件中 Android NDK 的路径配置错误，导致构建系统找不到 Android 版本的 `gcc`。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户配置构建系统:** 用户会编写或修改 Meson 的构建定义文件 (`meson.build`)，这些文件会声明项目依赖的外部程序。例如，使用 `find_program('cmake')` 或直接使用 `declare_dependency(..., native: find_program('pkg-config'))`。

2. **用户运行 Meson 命令:** 用户在命令行中执行 `meson setup builddir` 或类似的命令来配置构建。

3. **Meson 解析构建定义:** Meson 会解析 `meson.build` 文件，并根据其中的声明，调用 `find_program` 或其他相关的函数。

4. **`find_program` 调用 `find_external_program`:** `find_program` 等函数会调用 `frida/subprojects/frida-clr/releng/meson/mesonbuild/programs.py` 中的 `find_external_program` 函数。

5. **`find_external_program` 创建 `ExternalProgram` 实例:**  `find_external_program` 函数会尝试根据提供的名称和配置创建 `ExternalProgram` 的实例。

6. **`ExternalProgram.__init__` 执行搜索:** 在 `ExternalProgram` 的初始化过程中，会执行查找程序的逻辑，包括检查 `PATH` 环境变量、搜索指定目录、处理 Windows 特殊情况以及解析 Shebang。

7. **记录日志:**  代码中使用了 `mlog.log` 和 `mlog.debug` 来记录查找过程中的信息，这些日志可以作为调试线索，帮助用户了解程序是否被找到以及搜索的路径。

**调试线索:**

* **查看 Meson 的配置输出:** Meson 在配置阶段会输出找到的程序信息。例如，如果成功找到 `cmake`，会显示 "Program cmake found: YES (/usr/bin/cmake)" (路径可能不同)。
* **查看 Meson 的详细日志:**  可以使用 `-Ddebug=true` 运行 Meson，以获取更详细的调试信息，包括 `programs.py` 中的 `mlog.debug` 输出，了解程序查找的具体过程。
* **检查 `PATH` 环境变量:** 用户可以打印出当前的 `PATH` 环境变量，确认需要的程序所在的目录是否在其中。
* **手动测试程序是否可执行:** 用户可以在终端中尝试直接运行被 `programs.py` 搜索的程序，以排除基本的环境问题。

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/programs.py` 是 Frida 构建系统中一个关键的组件，负责在不同的平台上可靠地定位和管理构建所需的外部可执行程序，这对于确保构建过程的顺利进行至关重要。它需要处理各种操作系统特定的细节和用户可能遇到的常见配置错误。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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