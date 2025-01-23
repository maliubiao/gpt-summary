Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the provided Python code, focusing on its functionality, relationship to reverse engineering, low-level details, logical reasoning, potential user errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and High-Level Purpose:**

First, I quickly read through the code to grasp its overall purpose. The imports (os, shutil, stat, sys, re, pathlib), the class names (`ExternalProgram`, `NonExistingExternalProgram`, `OverrideProgram`), and the function names (`get_version`, `_search`, `found`) strongly suggest this code deals with finding and managing external executable programs. The `frida/subprojects/frida-qml/releng/meson/mesonbuild/programs.py` path hints that this is part of a build system (Meson) and related to Frida, a dynamic instrumentation tool.

**3. Deconstructing the `ExternalProgram` Class:**

This is the core of the code. I analyze its methods and attributes:

* **`__init__`:**  Handles initialization. It looks for the program by name or command. It considers search directories and handles shebangs in scripts. The logging suggests this is a critical step where the system determines if a program is available.
* **`found()`:** A simple boolean indicating if the program was found.
* **`get_command()`:** Returns the full command to execute the program.
* **`get_path()`:** Returns the path to the executable.
* **`get_name()`:** Returns the program's name.
* **`get_version()`:** Attempts to get the program's version by running `--version`. This immediately links to reverse engineering scenarios where understanding the tool's version is crucial.
* **`_search()`:** Implements the logic for finding the executable, including PATH environment variable handling and Windows-specific quirks. This is quite complex.
* **`_shebang_to_cmd()`:**  Crucially important for handling script files (like Python scripts) on systems where they might not be directly executable.
* **`_is_executable()`:** Checks if a file is executable.
* **`_search_dir()`:** Searches a specific directory.
* **`_search_windows_special_cases()`:**  Handles the complexities of finding executables on Windows.
* **`from_bin_list()` and `from_entry()`:** Factory methods for creating `ExternalProgram` instances.

**4. Analyzing Subclasses:**

* **`NonExistingExternalProgram`:**  A straightforward class representing a program that wasn't found.
* **`OverrideProgram`:**  A placeholder, indicating a mechanism for overriding default program locations.

**5. Examining `find_external_program`:**

This function provides a higher-level abstraction for finding programs, considering cross-compilation and default names.

**6. Identifying Connections to Reverse Engineering:**

At this stage, the `get_version()` method immediately stands out. Dynamic instrumentation tools like Frida often interact with different versions of target applications or libraries. Knowing the exact version is vital for crafting correct instrumentation scripts. The ability to find and execute arbitrary programs is also a fundamental aspect when performing dynamic analysis.

**7. Identifying Connections to Low-Level Details:**

The code extensively interacts with the operating system:

* **File system operations:** `os.path.exists`, `os.path.isfile`, `os.stat`.
* **Environment variables:** `os.environ['PATH']`.
* **Process execution:** `mesonlib.Popen_safe`.
* **Executable flags:** `stat.S_IXUSR`, etc.
* **Windows-specific executable extensions:** `.exe`, `.com`, etc.
* **Shebang parsing:**  Dealing with the `#!` line in scripts.

The Windows-specific handling is a clear example of operating system-level knowledge.

**8. Considering Logical Reasoning:**

I look for conditional logic and assumptions:

* **Search order:**  The code prioritizes explicitly specified paths over PATH environment variables.
* **Shebang interpretation:**  The code assumes a specific format for shebang lines.
* **Windows executable search:** The code implements Windows-specific search rules.
* **Version extraction:** The code uses regular expressions to extract version numbers, assuming a specific pattern.

**9. Thinking About User Errors:**

Common mistakes a user might make:

* **Incorrect program names:** Typing errors.
* **Program not in PATH:**  The program exists but the system can't find it.
* **Incorrect shebang:**  A script might have a malformed shebang line.
* **Permissions issues:**  The user might not have execute permissions.
* **Windows extensions:**  Forgetting the `.exe` on Windows, though the code tries to mitigate this.

**10. Tracing User Actions to the Code:**

How does a user's action lead to this code being executed?  Since this is part of a build system (Meson), the user likely:

1. **Runs a Meson command:**  `meson setup`, `meson compile`, etc.
2. **Meson needs an external program:**  During the build process, Meson might need tools like compilers, linkers, or in this specific case, potentially other components of Frida or related tools.
3. **Meson uses `find_external_program`:**  This function is called to locate the required external program.
4. **`ExternalProgram` is instantiated:** Based on the search results or configuration.

During debugging, a user might:

1. **Encounter a "program not found" error:** This points to the `found()` method and the search logic.
2. **Investigate why the wrong version is being used:**  This leads to `get_version()`.
3. **Debug issues with executing scripts:**  This involves `_shebang_to_cmd()`.

**11. Structuring the Answer:**

Finally, I organize the findings into the requested categories: functionality, reverse engineering, low-level details, logical reasoning (with examples), user errors (with examples), and the user journey. I use clear headings and bullet points for readability. I try to provide concrete examples where possible to illustrate the points. For the logical reasoning, creating explicit "Input" and "Output" scenarios makes the explanation clearer.
This Python code file, `programs.py`, within the Frida project's Meson build system, is responsible for managing and locating external and internal programs required during the build process. Here's a breakdown of its functionality:

**Functionality:**

1. **Representation of External Programs:** The core of the file is the `ExternalProgram` class. It represents a program that exists outside the current build process. This includes executables like compilers, linkers, or other utilities needed for building Frida.

2. **Program Location:** The class provides mechanisms to locate these external programs on the system. It searches in:
   - Explicitly provided paths.
   - Directories specified in the `PATH` environment variable.
   - Standard system locations.
   - Custom search directories.
   - Cross-compilation configuration files (to find tools for the target architecture).

3. **Handling Different Program Types:** It can handle:
   - Native executables.
   - Script files (like Python scripts) by parsing their shebang lines (`#!`) to determine the interpreter.
   - Programs on Windows with and without extensions (`.exe`, `.com`, etc.).

4. **Version Retrieval:**  The `get_version()` method attempts to retrieve the version of an external program by executing it with the `--version` flag.

5. **Information Storage:**  It stores information about found programs, including:
   - `name`: The name of the program.
   - `path`: The full path to the executable.
   - `command`: The command to execute the program (including the path and potentially interpreter).
   - `cached_version`:  The retrieved version of the program.

6. **Handling Non-Existent Programs:** The `NonExistingExternalProgram` class represents a program that could not be found.

7. **Overriding Program Locations:** The `OverrideProgram` class (though currently empty in terms of specific implementation details in this snippet) likely provides a way to specify alternative locations for programs, overriding the default search behavior.

8. **Finding Programs with Fallbacks:** The `find_external_program` function offers a higher-level way to find external programs. It checks cross-compilation files, machine files, and falls back to default names if the primary name isn't found.

**Relationship to Reverse Engineering:**

This code is directly related to reverse engineering because Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. Here's how:

* **Finding Frida's Dependencies:**  During the build process, this code will be used to locate necessary tools like compilers, linkers, and potentially other Frida components or dependencies. These components are crucial for building the Frida agent and client that will be used for reverse engineering tasks.
* **Version Checking of Tools:** The `get_version()` function could be used to ensure that the correct versions of build tools are being used. This is important because different versions of compilers or linkers might produce different binaries, which could affect Frida's functionality or interaction with the target process being analyzed.
* **Locating Target Binaries (Indirectly):** While this code primarily focuses on *build* dependencies, the principles of finding executables and understanding their paths are fundamental in reverse engineering. When using Frida, you need to know the path to the target application or library you want to instrument. The logic in this file for searching for executables shares concepts with how you might manually locate binaries for analysis.

**Example:**

Imagine Frida needs to compile a small snippet of code on the target device. The build process might use this `programs.py` to find the appropriate compiler (like `gcc` or `clang`) on the build machine. The `get_version()` method might be called to verify the compiler version. This compiler is essential for generating the code that Frida will inject into the target process during reverse engineering.

**Binary底层, Linux, Android 内核及框架知识:**

This code touches upon these areas:

* **Binary 底层:** The concept of executables and how the operating system locates and runs them is fundamental. The code deals with file system paths, executable permissions (implicitly through `os.stat`), and the structure of executable files (in the context of shebangs).
* **Linux:** The handling of the `PATH` environment variable, the usage of `shutil.which`, and the interpretation of shebangs (`#!/bin/bash`, `#!/usr/bin/python3`) are all Linux-specific concepts. The executable permissions checked using `stat.S_IXUSR`, `stat.S_IXGRP`, `stat.S_IXOTH` are also Linux-specific.
* **Android 内核及框架 (Indirectly):** While this specific code runs on the build machine, Frida is often used to instrument Android applications and native libraries. The build process managed by Meson, which uses this `programs.py`, is responsible for building the Frida components that will eventually interact with the Android kernel and framework. The cross-compilation aspects of finding tools for different architectures are relevant here, as Frida needs to be built for the Android target architecture (e.g., ARM, ARM64).
* **Windows Specifics:** The code explicitly handles Windows-specific behaviors like executable extensions (`.exe`, `.com`, etc.) and the `PATHEXT` environment variable (though not explicitly mentioned, the logic caters to it). It also deals with the fact that Windows doesn't inherently understand shebangs.

**Example:**

When searching for an executable on Linux, `shutil.which` is used, which relies on the `PATH` environment variable. This variable is a colon-separated list of directories where the shell looks for executable files. On Windows, the code considers file extensions when searching for executables because the system relies on these extensions to identify executable files. The shebang parsing is crucial for running scripts on Linux, where the first line dictates the interpreter to use.

**逻辑推理 (假设输入与输出):**

**Scenario 1: Finding the `python3` interpreter on a Linux system.**

* **假设输入 (Input):**
    - `name`: "python3"
    - `search_dir`: `None` (let it search the `PATH`)
    - `PATH` environment variable contains `/usr/bin:/usr/local/bin:/opt/bin`
    - `/usr/bin/python3` exists and is executable.

* **逻辑推理:**
    1. `_search` is called with `name="python3"` and `search_dir=None`.
    2. The code checks if there's a directory component in `name` (there isn't).
    3. It gets the `PATH` environment variable.
    4. `shutil.which("python3", path="/usr/bin:/usr/local/bin:/opt/bin")` is called.
    5. `shutil.which` finds `/usr/bin/python3`.
    6. `_search` returns `["/usr/bin/python3"]`.
    7. `ExternalProgram` initializes `self.command` to `["/usr/bin/python3"]` and `self.path` to `/usr/bin/python3`.

* **假设输出 (Output):**
    - `Program python3 found: YES (/usr/bin/python3)` (will be logged if `silent=False`)
    - `external_program.found()` returns `True`.
    - `external_program.get_command()` returns `['/usr/bin/python3']`.
    - `external_program.get_path()` returns `/usr/bin/python3`.

**Scenario 2: Finding a script with a shebang on Windows.**

* **假设输入 (Input):**
    - `name`: "myscript" (without extension)
    - `search_dir`: `None`
    - `PATH` environment variable contains `C:\Windows\system32;C:\mytools`
    - `C:\mytools\myscript` exists, is a text file with the content `#!/usr/bin/env python3`, but is *not* marked as executable.
    - Python 3 is installed and its executable (`python3.exe`) is in the `PATH`.

* **逻辑推理:**
    1. `_search` is called.
    2. `shutil.which("myscript")` returns `None` because `myscript` has no extension and Windows's standard PATH search won't find it.
    3. `_search_windows_special_cases` is called.
    4. Since `command` is `None`, the code checks if `name` is an absolute path (it isn't).
    5. It splits the `PATH` and searches each directory.
    6. In `C:\mytools`, `_search_dir("myscript", "C:\mytools")` is called.
    7. `os.path.exists("C:\mytools\myscript")` is `True`.
    8. `_is_executable("C:\mytools\myscript")` returns `False`.
    9. `_shebang_to_cmd("C:\mytools\myscript")` is called.
    10. The shebang `#!/usr/bin/env python3` is parsed.
    11. Since it's Windows, `/usr/bin/env` is ignored, and `python3` is looked for.
    12. The code assumes `python3.exe` is in the PATH.
    13. `_shebang_to_cmd` returns `['python3', 'C:\\mytools\\myscript']`.
    14. `_search_windows_special_cases` returns `[['python3', 'C:\\mytools\\myscript']]`.
    15. `ExternalProgram` initializes `self.command` to `['python3', 'C:\\mytools\\myscript']` and `self.path` to `C:\\mytools\\myscript`.

* **假设输出 (Output):**
    - `Program myscript found: YES (python3 C:\mytools\myscript)`
    - `external_program.found()` returns `True`.
    - `external_program.get_command()` returns `['python3', 'C:\\mytools\\myscript']`.
    - `external_program.get_path()` returns `C:\\mytools\\myscript`.

**用户或编程常见的使用错误:**

1. **Incorrect Program Name:**
   - **Error:** Providing a typo in the program's name (e.g., `"git"` instead of `"gitt"`).
   - **Consequence:** The `_search` function will likely fail to find the program, and `found()` will return `False`. The build process might halt with an error indicating a missing dependency.

2. **Program Not in PATH:**
   - **Error:** The required program is installed on the system but its directory is not included in the `PATH` environment variable.
   - **Consequence:** Similar to the previous error, `_search` will fail.

3. **Incorrect Shebang in Scripts:**
   - **Error:** A script file has a shebang that points to a non-existent interpreter or has syntax errors.
   - **Consequence:** When this script is encountered, `_shebang_to_cmd` might return `None`, or attempt to execute a wrong interpreter. This could lead to errors during the build process or when Frida tries to execute the script.

4. **Permissions Issues:**
   - **Error:** The user running the build process does not have execute permissions for the found program.
   - **Consequence:** While `_search` might find the program, attempting to execute it (e.g., in `get_version`) will result in a "permission denied" error.

5. **Forgetting Extensions on Windows:**
   - **Error:** On Windows, users might try to specify a program name without its `.exe` extension (e.g., just "mytool" instead of "mytool.exe").
   - **Consequence:**  While the code tries to handle this by checking common extensions, there might be cases where the extension is unusual, and the program is not found.

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **Developer Modifies Frida or its Build System:** A developer working on Frida might modify the build system files (the `meson.build` files or Python scripts like this one) to add a new dependency or change how an existing dependency is handled.

2. **Running the Meson Configuration:** The user executes the command `meson setup builddir` (or a similar command) to configure the build. Meson then parses the `meson.build` files.

3. **Dependency on an External Program:**  A `meson.build` file might contain a statement like `find_program('my_external_tool')`.

4. **`find_program` Invokes `find_external_program`:** Meson's `find_program` function internally calls the `find_external_program` function in this `programs.py` file.

5. **Program Search Begins:** `find_external_program` and the `ExternalProgram` class start their search process, checking configured paths, the `PATH` environment variable, and potentially default locations.

6. **Debugging Scenario:**  If the build fails with an error like "Program 'my_external_tool' not found," the developer would start debugging.

7. **Inspecting Meson Output:** The developer would look at the Meson output, which might indicate where it was searching for the program.

8. **Examining `programs.py`:**  The developer might then look at the `frida/subprojects/frida-qml/releng/meson/mesonbuild/programs.py` file to understand how Meson is trying to find the program. They might:
   - Check the logging statements within `ExternalProgram.__init__` to see which directories were searched.
   - Examine the logic in `_search` and `_search_windows_special_cases` to understand the search order and how different operating systems are handled.
   - Set breakpoints within this Python file (if they are familiar with Meson's internals) to trace the execution flow and see the values of variables like `self.command` and `self.path`.

9. **Verifying Environment:** The developer would then check their system's `PATH` environment variable, ensure the program is installed, and verify that they have the necessary permissions.

10. **Correcting the Issue:** Based on their findings, the developer might:
    - Install the missing program.
    - Add the program's directory to their `PATH`.
    - Correct a typo in the program name in the `meson.build` file.
    - Adjust the search paths configured in the Meson build system.

In essence, this file is a critical part of Frida's build infrastructure. When issues arise related to finding external tools during the build, understanding the logic within this `programs.py` file is essential for diagnosing and resolving the problem.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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