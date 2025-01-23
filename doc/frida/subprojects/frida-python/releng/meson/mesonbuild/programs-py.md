Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Goal:**

The user wants a functional breakdown of the `programs.py` file within the Frida project. They are specifically interested in connections to reverse engineering, low-level details (kernel, framework), logical reasoning, common user errors, and debugging context.

**2. Initial Skim and Keyword Spotting:**

I'd first read through the code quickly, looking for key classes, methods, and concepts. Keywords like "ExternalProgram," "search," "shebang," "PATH," "Windows," and "version" jump out. This gives a high-level understanding of what the code does.

**3. Deeper Dive into Classes:**

* **`ExternalProgram`:** This is the core class. It represents a program found on the system. I'd analyze its methods:
    * `__init__`: How is a program initialized?  Looks like it can be given a command directly or searched for.
    * `found()`:  Determines if the program was found.
    * `get_command()`, `get_path()`, `get_name()`:  Basic accessors.
    * `get_version()`: Interesting – attempts to retrieve the program's version.
    * `_search()`: This seems crucial for locating the program. I'd pay close attention to how it handles PATH, Windows extensions, and shebangs.
    * `_shebang_to_cmd()`:  Definitely related to script execution and potentially reverse engineering (understanding how scripts are invoked).
    * `_is_executable()`: Important for deciding if a file is runnable. Notice the platform-specific logic.
    * `from_bin_list()`, `from_entry()`: Alternative ways to create `ExternalProgram` instances.
    * Windows-specific methods (`_windows_sanitize_path`, `_search_windows_special_cases`): Highlight the platform awareness.

* **`NonExistingExternalProgram`:** A simple subclass to represent a program that isn't found.

* **`OverrideProgram`:**  A marker for programs that are intentionally overridden.

**4. Identifying Core Functionality:**

Based on the class analysis, the main function of `programs.py` is to:

* **Represent external programs:** Create objects that hold information about executable programs.
* **Locate programs:** Implement logic to search for programs on the system, considering PATH, extensions, and shebangs.
* **Retrieve program information:** Get the path, command, and potentially the version of a program.

**5. Connecting to Reverse Engineering:**

This is where the "Frida context" becomes important. Frida is a *dynamic instrumentation* tool. This code is part of its setup process. How does finding external programs relate to instrumentation?

* **Target Processes:** Frida needs to interact with other processes. This code might be used to locate the target process's executable.
* **Tools and Utilities:** Frida likely depends on other tools (debuggers, compilers, etc.). This code would find those.
* **Scripting:**  Frida uses scripts (often Python). The shebang logic is directly relevant to executing these scripts.

**6. Identifying Low-Level, Kernel, and Framework Aspects:**

* **Binary Execution:** The entire process of finding and executing programs is inherently low-level. The checks for executability (`_is_executable`), handling of PATH, and platform differences are key.
* **Shebangs:** Shebangs are a Unix/Linux convention. Understanding them demonstrates knowledge of how the kernel launches scripts.
* **Windows Extensions:**  The handling of `.exe`, `.com`, etc., reflects the way Windows executes programs.
* **PATH Environment Variable:** This is a fundamental concept in operating systems for locating executables.

**7. Logical Reasoning and Examples:**

Think about specific scenarios and how the code would behave.

* **Input:**  Trying to find `python3`. The code would search PATH.
* **Input:**  Providing an absolute path to `my_script.py`. The code would check if it exists and potentially parse the shebang.
* **Input:**  A Windows script without an extension. The special Windows search logic would kick in.

**8. User Errors:**

What mistakes could a user make that would lead them to this code or cause issues?

* **Incorrect PATH:**  If the required program isn't in the PATH, Frida won't find it.
* **Missing Shebang:** A Python script without a shebang might not be executed correctly on Windows (or even Linux in some cases if it's not executable).
* **Incorrect Program Name:** Typographical errors when specifying the program name.
* **Cross-Compilation Issues:**  If targeting a different architecture, the correct binaries might not be found.

**9. Debugging Context:**

How does a user end up looking at this code?

* **Frida Setup Failures:** If Frida can't find a required program, the build process might fail, and the user might investigate the build system (Meson) and its components.
* **Custom Tool Integration:**  A user might be trying to integrate a custom tool with Frida and need to understand how Frida locates external programs.
* **Understanding Frida Internals:** A developer debugging Frida itself would likely need to understand this core functionality.

**10. Structuring the Answer:**

Organize the findings logically, using headings and examples to make it clear and easy to understand. Address each part of the user's request explicitly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this code is directly involved in Frida's instrumentation logic.
* **Correction:**  Realize that this is part of the *build system* (Meson) and focuses on *finding* programs needed for the build and potentially for Frida to use later.
* **Initial thought:** Focus solely on the technical aspects of finding programs.
* **Refinement:**  Consider the Frida context and how finding these programs relates to reverse engineering and dynamic instrumentation. Emphasize the "why" not just the "how."

By following this detailed process, systematically analyzing the code, and considering the context of Frida and reverse engineering, a comprehensive and accurate answer can be generated.
这个 `frida/subprojects/frida-python/releng/meson/mesonbuild/programs.py` 文件是 Frida 项目中，用于管理和查找外部及内部程序的一个模块，属于 Meson 构建系统的组成部分。Meson 是一个元构建系统，它读取用户的构建描述文件（`meson.build`），然后生成特定构建工具（如 Ninja 或 Visual Studio）的构建文件。

**主要功能:**

1. **表示外部程序 (`ExternalProgram` 类):**
   -  封装了对系统上可执行程序的表示。
   -  存储了程序的名称、路径以及用于执行该程序的命令（一个字符串列表）。
   -  可以根据程序名在系统路径 (`PATH`) 中搜索程序。
   -  支持在指定的目录下搜索程序。
   -  可以处理 Windows 特有的可执行文件扩展名 (`.exe`, `.com`, `.bat`, `.cmd` 等)。
   -  可以解析脚本文件的 Shebang 行 (`#!`)，以确定执行该脚本所需的解释器。
   -  提供了判断程序是否找到的方法 (`found()`)。
   -  提供了获取程序命令、路径和名称的方法 (`get_command()`, `get_path()`, `get_name()`)。
   -  能够获取程序的版本信息 (`get_version()`)，通常通过执行 `program --version` 命令来获取。
   -  可以根据 Meson 的配置（如 cross-file 或 machine-file）查找特定平台的程序。

2. **表示不存在的外部程序 (`NonExistingExternalProgram` 类):**
   -  继承自 `ExternalProgram`，用于表示未能找到的程序。
   -  `found()` 方法始终返回 `False`。

3. **表示覆盖的程序 (`OverrideProgram` 类):**
   -  继承自 `ExternalProgram`，可能用于表示用户自定义或覆盖的程序路径。

4. **查找外部程序函数 (`find_external_program`):**
   -  提供了一种更高级的方式来查找外部程序。
   -  首先会检查用户在 Meson 的配置中是否指定了该程序的路径。
   -  如果用户未指定，则会尝试使用默认的程序名称在系统路径中查找。
   -  可以根据目标机器类型 (`MachineChoice`) 查找对应的程序，这在交叉编译时非常重要。

**与逆向方法的关系及举例说明:**

这个文件本身并不直接执行逆向操作，但它是 Frida 构建系统的一部分，Frida 是一个强大的动态插桩工具，广泛应用于逆向工程、安全研究和调试。`programs.py` 的功能确保了 Frida 构建过程中所需的各种工具（如编译器、链接器、Python 解释器等）能够被正确找到和使用。

**举例说明:**

假设 Frida 的 Python 绑定需要编译一些 C 代码。Meson 构建系统会使用 `find_external_program` 来查找系统上的 C 编译器（如 `gcc` 或 `clang`）。

```python
# 假设在 meson.build 文件中定义了要查找的 C 编译器
compiler = find_program('cc')
```

在 `programs.py` 中，`find_external_program` 函数会执行以下操作：

1. **检查配置:** 查看 Meson 的配置文件（如 cross-file）中是否明确指定了 C 编译器的路径。
2. **默认搜索:** 如果没有指定，则会在系统的 `PATH` 环境变量中搜索 `cc`、`gcc`、`clang` 等默认的 C 编译器名称。
3. **创建 `ExternalProgram` 对象:** 如果找到编译器，会创建一个 `ExternalProgram` 对象，其中包含了编译器的路径和命令。

在逆向过程中，Frida 可能会依赖一些外部工具来处理二进制文件，例如：

- **`objdump` 或 `readelf`:** 用于查看 ELF 文件的结构信息。
- **`adb`:** 用于与 Android 设备通信。

`programs.py` 可以确保这些工具在 Frida 的构建或运行时环境中可用。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

- **二进制底层:**
    - `_is_executable` 方法检查文件是否具有执行权限，这直接关联到操作系统对二进制文件的处理方式。
    - 处理 Windows 的可执行文件扩展名 (`.exe`, `.com` 等) 反映了 Windows 操作系统的底层机制。
- **Linux:**
    - 解析 Shebang 行 (`#!`) 是 Linux 和其他类 Unix 系统执行脚本的标准方式。`_shebang_to_cmd` 方法就体现了对这种机制的理解。
    - 依赖 `PATH` 环境变量来查找可执行文件是 Linux 及其它 Unix-like 系统的基本概念。
- **Android:**
    - 虽然这个文件本身不直接涉及 Android 内核或框架，但 Frida 作为动态插桩工具，经常用于分析 Android 应用和框架。构建过程中可能需要查找 Android SDK 中的工具（如 `adb`），而 `programs.py` 负责查找这些工具。
- **Windows:**
    - 特殊处理 Windows 的路径和可执行文件扩展名，例如 `windows_exts` 和 `_windows_sanitize_path` 方法，反映了对 Windows 操作系统的了解。

**逻辑推理及假设输入与输出:**

**假设输入:**

```python
# 尝试查找名为 'my_custom_tool' 的程序，但未在 PATH 中
program = ExternalProgram('my_custom_tool')
```

**逻辑推理:**

1. `ExternalProgram` 初始化时，`command` 为 `None`，开始搜索。
2. `_search` 方法被调用，尝试在 `PATH` 中查找 'my_custom_tool'。
3. `shutil.which('my_custom_tool')` 返回 `None`，因为该工具不在 `PATH` 中。
4. `program.found()` 将返回 `False`。

**假设输入（Windows）:**

```python
# 尝试查找一个名为 'myscript' 的 Python 脚本，没有扩展名，但有正确的 Shebang
program = ExternalProgram('myscript')
# 假设 myscript 文件内容如下：
# #!/usr/bin/env python3
# print("Hello")
```

**逻辑推理:**

1. `ExternalProgram` 初始化时，`command` 为 `None`，开始搜索。
2. `_search` 方法被调用。在 Windows 上，`shutil.which('myscript')` 可能返回 `None`，因为没有扩展名。
3. `_search_windows_special_cases` 方法被调用。
4. 遍历 `PATH` 中的目录，查找名为 `myscript` 的文件。
5. 如果找到 `myscript` 文件，调用 `_shebang_to_cmd`。
6. `_shebang_to_cmd` 解析 Shebang 行 `#!/usr/bin/env python3`，并根据系统配置确定 Python 3 的执行命令，例如 `['python3', 'myscript']` 或 `[<python_executable_path>, 'myscript']`。
7. `program.get_command()` 将返回类似 `['python3', 'myscript']` 的列表。

**涉及用户或编程常见的使用错误及举例说明:**

1. **`PATH` 环境变量未正确配置:** 如果用户尝试查找的程序不在系统的 `PATH` 环境变量中，`ExternalProgram` 将无法找到该程序。
   ```python
   # 如果 'my_tool' 不在 PATH 中
   program = ExternalProgram('my_tool')
   if not program.found():
       print("错误：my_tool 未找到，请检查 PATH 环境变量。")
   ```

2. **Windows 上脚本没有正确的文件扩展名或 Shebang:** 在 Windows 上，如果脚本文件没有 `.py` 等扩展名，且没有正确的 Shebang 行，`ExternalProgram` 可能无法确定如何执行该脚本。

3. **在交叉编译时未正确配置 cross-file:** 如果在进行交叉编译，但 Meson 的 cross-file 中没有正确指定目标平台的工具链，`find_external_program` 可能会找到错误的程序。

4. **假设程序一定存在:** 用户可能会直接使用 `program.get_command()` 而不检查 `program.found()`，如果程序未找到，会导致错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 `meson.build` 文件:** 用户首先会编写 `meson.build` 文件，其中会使用 `find_program()` 或直接创建 `ExternalProgram` 对象来查找构建所需的工具。

   ```python
   # meson.build
   python3 = find_program('python3')
   if python3.found():
       message('找到 Python 3: ' + python3.path())
   else:
       error('找不到 Python 3，请确保已安装。')
   ```

2. **运行 `meson setup`:** 用户在命令行运行 `meson setup <build_directory>`，Meson 会解析 `meson.build` 文件。

3. **`find_program` 调用触发 `programs.py`:** 当 Meson 解析到 `find_program('python3')` 时，会调用 `mesonbuild/programs.py` 中的 `find_external_program` 函数。

4. **程序搜索过程:** `find_external_program` 会按照预定的逻辑（检查配置文件，搜索 `PATH` 等）来查找名为 `python3` 的可执行文件。

5. **调试线索:**
   - **构建失败:** 如果构建过程中出现找不到某个程序的错误，用户可能会检查 Meson 的输出日志，其中会包含程序搜索的结果。
   - **查看 `meson-log.txt`:** Meson 的日志文件 `meson-log.txt` 中可能会包含更详细的程序搜索过程信息。
   - **手动检查 `programs.py`:** 为了理解 Meson 如何查找程序，用户可能会查看 `programs.py` 的源代码，特别是 `ExternalProgram` 类的 `__init__` 和 `_search` 方法，以及 `find_external_program` 函数。
   - **使用调试器:** 开发者可以使用 Python 调试器（如 `pdb`）来逐步执行 `programs.py` 的代码，查看程序搜索的每一步，以及环境变量和文件系统的状态。
   - **检查 Meson 配置文件:** 用户可能会检查 `meson_options.txt` 或 cross-file，看是否对程序的查找路径有影响。

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/programs.py` 是 Frida 项目构建过程中至关重要的一个模块，它负责管理和查找所需的外部程序，为后续的编译、链接等构建步骤奠定基础。理解它的功能有助于理解 Frida 的构建流程，并在遇到构建问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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