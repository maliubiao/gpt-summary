Response:
Let's break down the thought process for analyzing this Python code for the `fridaDynamic` instrumentation tool.

**1. Understanding the Request:**

The core request is to understand the functionality of the `programs.py` file within the Frida project and relate it to reverse engineering, low-level operations, and potential user errors. The request also asks how a user might end up interacting with this code (debugging context).

**2. Initial Code Scan & Goal Identification:**

My first step is to quickly read through the code, identify the main classes and functions, and understand their purpose. I see `ExternalProgram`, `NonExistingExternalProgram`, `OverrideProgram`, and `find_external_program`. The comments and docstrings provide valuable clues. The overall goal of this file seems to be about locating and representing external programs used by the build system (Meson).

**3. Deeper Dive into `ExternalProgram`:**

This is the central class. I analyze its attributes and methods:

*   `__init__`:  Handles finding the program either by explicit command or by searching the system's PATH. It also deals with Windows-specific extensions and shebangs.
*   `found()`:  Simple check if the program was located.
*   `get_command()`: Returns the command used to execute the program.
*   `get_path()`: Returns the actual path to the executable.
*   `get_version()`: Attempts to get the program's version by running `--version`.
*   `from_bin_list()`, `from_entry()`: Static factory methods to create `ExternalProgram` instances in different ways.
*   `_shebang_to_cmd()`: Crucial for handling script files on various platforms.
*   `_is_executable()`: Determines if a file is executable.
*   `_search_dir()`, `_search_windows_special_cases()`, `_search()`: Implement the logic for searching for executables on different platforms.

**4. Relating to Reverse Engineering (Instruction 2):**

I consider how the ability to find and execute external programs relates to reverse engineering. Frida itself is a reverse engineering tool. The programs this module manages are likely tools used *during the build process* of Frida. These tools might be involved in:

*   Code generation (e.g., compilers, assemblers).
*   Static analysis.
*   Packaging.
*   Potentially, even running tests that might involve some form of sandboxing or instrumentation.

I formulate examples focusing on tools commonly used in development and potentially relevant to Frida.

**5. Relating to Binary/Kernel/Framework Knowledge (Instruction 3):**

This is where the platform-specific logic becomes important. I look for code that interacts with operating system features:

*   **Binary Level:** The file extensions (`.exe`, etc.) and the execution flags (`stat.S_IXUSR`) directly relate to how binaries are handled by the OS. The concept of a "shebang" is also a low-level detail about how script execution is initiated.
*   **Linux/Android Kernel:** While the code isn't directly interacting with kernel APIs, the concept of the `PATH` environment variable and executable permissions is fundamental to Linux-like systems, including Android.
*   **Android Framework:**  While not explicitly mentioned, Frida targets Android. The tools found by this module *could* be involved in building or packaging components that interact with the Android framework (though the code itself doesn't show direct framework interaction).

**6. Logical Reasoning (Instruction 4):**

I identify functions where the output depends on the input and create simple test cases:

*   `_shebang_to_cmd()`:  Provide a simple shebang line and predict the output.
*   `_is_executable()`: Provide file paths and predict whether they'll be considered executable.
*   `found()`:  Show the difference between a successfully found program and a non-existent one.

**7. User/Programming Errors (Instruction 5):**

I think about common mistakes developers make when dealing with external programs or build systems:

*   Incorrect PATH settings.
*   Typos in program names.
*   Forgetting necessary dependencies.
*   Platform-specific issues (like forgetting `.exe` on Windows).

I create examples illustrating these errors in the context of how this module works.

**8. User Interaction/Debugging (Instruction 6):**

I consider how a developer using Frida might indirectly trigger this code:

*   During the build process using Meson.
*   If there's a problem finding a required tool, Meson's error messages might point to the configuration or the need to install a dependency.
*   Developers contributing to Frida might directly modify the build files or need to debug issues related to finding external dependencies.

**9. Refinement and Structuring:**

Finally, I organize the information clearly, using headings and bullet points to address each part of the request. I ensure the examples are concise and illustrate the specific points. I review the code again to make sure I haven't missed any important details. I focus on clear explanations and avoid unnecessary jargon. For example, instead of just saying "it searches the PATH," I explain *why* that's important for finding executables.

This iterative process of scanning, analyzing, relating to the concepts, creating examples, and refining helps to build a comprehensive understanding of the code's functionality and its implications within the larger Frida project.
The provided code snippet is from `frida/subprojects/frida-node/releng/meson/mesonbuild/programs.py`. This file is part of the Meson build system, specifically within the context of building Frida's Node.js bindings. Its primary responsibility is to **represent and manage external programs (executables) and internal commands** that are required during the build process.

Let's break down its functionalities and connections to the areas you mentioned:

**1. Core Functionality: Managing External and Internal Programs**

*   **Representation:** The code defines classes like `ExternalProgram`, `NonExistingExternalProgram`, and `OverrideProgram` to represent different types of programs.
    *   `ExternalProgram`: Represents a program found on the system (e.g., `gcc`, `python`). It stores the program's name, the command to execute it (including path and arguments), and potentially its version.
    *   `NonExistingExternalProgram`: Represents a program that could not be found.
    *   `OverrideProgram`: Represents a program whose default behavior is overridden, likely by a user-specified script.
*   **Finding Programs:** The `ExternalProgram` class has logic to search for programs on the system. This involves:
    *   Checking explicitly provided paths.
    *   Searching in specific directories.
    *   Searching in the system's `PATH` environment variable.
    *   Handling Windows-specific executable extensions (`.exe`, `.com`, etc.).
    *   Parsing shebang lines (`#!`) in scripts to determine the interpreter.
*   **Version Detection:** The `get_version` method attempts to retrieve the version of an external program by running it with the `--version` flag and parsing the output.
*   **Configuration Integration:** The `find_external_program` function is used to locate programs based on configurations specified in Meson's cross-compilation or native build files. This allows the build system to use different tools depending on the target platform.

**2. Relationship to Reverse Engineering**

This code itself isn't directly performing reverse engineering tasks. However, it plays a crucial role in *building* Frida, which is a dynamic instrumentation toolkit used for reverse engineering. The programs managed by this module are the tools necessary to compile, link, and package Frida's Node.js bindings.

*   **Example:**  When building Frida's Node.js bindings, this module might be used to find the Node.js executable (`node`), the Node.js package manager (`npm` or `yarn`), and compilers like `gcc` or `clang`. These tools are essential for creating the native addon that allows Node.js code to interact with Frida's core functionalities. Reverse engineers will ultimately *use* the built Frida, but this code is about the *process of building* it.

**3. Relationship to Binary底层, Linux, Android内核及框架**

This code interacts with low-level operating system concepts:

*   **Binary 底层 (Binary Low-Level):**
    *   The code deals with the execution of external programs, which are fundamentally binary executables.
    *   It understands platform-specific executable file extensions (e.g., `.exe` on Windows).
    *   The `_is_executable` method checks file permissions, a core concept in operating systems for controlling the execution of binaries.
    *   Parsing shebang lines (`#!`) is a mechanism for specifying how a script (which might not be a compiled binary) should be executed by the kernel.
*   **Linux:**
    *   The code directly interacts with the `PATH` environment variable, a fundamental concept in Linux and other Unix-like systems for locating executables.
    *   File permissions (using `stat.S_IXUSR`, `stat.S_IXGRP`, `stat.S_IXOTH`) are checked, which are Linux file system attributes.
    *   The handling of shebang lines is a standard Linux/Unix feature.
*   **Android Kernel & Framework:** While the code doesn't directly interact with the Android kernel or framework APIs, the programs it manages are used to build software that *will* interact with them. For example:
    *   Compilers found by this module will compile code that uses Android NDK libraries, which provide interfaces to the Android framework.
    *   The built Frida Node.js bindings will be used to instrument applications running on Android, interacting with the Android runtime environment.

**4. Logical Reasoning (Hypothetical Input & Output)**

Let's consider the `_shebang_to_cmd` function:

*   **Hypothetical Input:** The path to a Python script named `my_script.py` with the following content:
    ```python
    #!/usr/bin/env python3
    print("Hello")
    ```
*   **Reasoning:** The function reads the first line, detects the shebang `#!/usr/bin/env python3`, and attempts to determine the Python 3 interpreter to use. Assuming `python3` is in the system's PATH, it will likely resolve to the actual path of the Python 3 executable.
*   **Hypothetical Output (on a Linux system):** A list like `['/usr/bin/python3', 'my_script.py']` (the exact path might vary). On Windows, it might return something like `['python3.exe', 'my_script.py']` if Python 3 is in the PATH. If the interpreter is not found or there are issues, it might return `None`.

Let's consider the `found()` method:

*   **Hypothetical Input:** An `ExternalProgram` object initialized with the name "gcc".
*   **Reasoning:** If `gcc` is found on the system (in the PATH), the `__init__` method will successfully find its path and set `self.command`.
*   **Hypothetical Output:** `True` (because `self.command[0]` will be the path to `gcc`).

*   **Hypothetical Input:** An `ExternalProgram` object initialized with the name "nonexistent_program".
*   **Reasoning:** The `__init__` method will fail to find this program.
*   **Hypothetical Output:** `False` (because `self.command[0]` will be `None`).

**5. User or Programming Common Usage Errors**

*   **Incorrect PATH:** If a user has not configured their `PATH` environment variable correctly, the build system might fail to find necessary programs.
    *   **Example:**  If `gcc` is required for building but is not in the `PATH`, the `ExternalProgram('gcc')` call will result in `found()` returning `False`, and the build process will likely fail with an error indicating that `gcc` could not be found.
*   **Typos in Program Names:** If the Meson build files specify an incorrect program name, the search will fail.
    *   **Example:** If the build file requires "pyhton" instead of "python", the `ExternalProgram('pyhton')` call will fail.
*   **Missing Dependencies:**  The build might require certain external tools that are not installed on the system.
    *   **Example:** If building Frida's Node.js bindings requires `npm` and it's not installed, the `ExternalProgram('npm')` call will fail.
*   **Platform-Specific Issues:**  Users might try to build on a platform where a required tool is named or located differently.
    *   **Example:**  On some Linux distributions, the C++ compiler might be `g++` instead of `gcc`. If the build system expects `gcc`, it might fail on those systems. The code tries to handle some of these differences (like Windows extensions), but not all possibilities.
*   **Permissions Issues:** If a user doesn't have execute permissions for a required program, the build might fail even if the program is found. This isn't directly handled by this code, but the underlying OS will prevent execution.

**6. User Operation Steps to Reach This Code (Debugging Context)**

Users typically don't interact with this specific Python file directly. They interact with the Meson build system, which in turn uses this code. Here's how a user might indirectly reach this code during debugging:

1. **Cloning the Frida Repository:** A developer wants to build Frida's Node.js bindings, so they clone the Frida repository from GitHub.
2. **Running the Meson Build Command:** The developer navigates to the `frida-node` subdirectory and runs the Meson configuration command (e.g., `meson setup build`).
3. **Meson Execution:** Meson starts evaluating the `meson.build` files in the project.
4. **Finding External Programs:** When Meson encounters a requirement for an external program (e.g., a C++ compiler, Node.js), it uses the functions in `programs.py` (like `find_external_program` and the `ExternalProgram` class) to locate these programs on the system.
5. **Error During Configuration:** If a required program is not found (due to incorrect PATH, missing installation, etc.), Meson will raise an error.
6. **Debugging:** The developer might then:
    *   **Examine Meson's Output:** Meson's error messages might indicate which program was not found.
    *   **Check their PATH:** The developer might check their `PATH` environment variable to see if the expected program's directory is included.
    *   **Investigate Meson Build Files:** They might look at the `meson.build` files to see how the external programs are being referenced.
    *   **Potentially Step Through Meson's Code:** If the error is complex, a developer contributing to Frida or deeply familiar with Meson might need to step through Meson's Python code, including `programs.py`, to understand exactly why a program is not being found. They might set breakpoints in `ExternalProgram.__init__` or `find_external_program` to see how the search is being performed and what values are being used.

In essence, this code is a foundational component of Frida's build system. While users don't directly call functions in `programs.py`, its correct functioning is crucial for a successful build. When build errors related to missing external programs occur, this file and its logic become relevant for debugging.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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