Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - What is the file about?**

The very first line tells us this is `frida/subprojects/frida-qml/releng/meson/mesonbuild/minstall.py`. This immediately suggests a few things:

* **Frida:**  The parent directory indicates this is part of the Frida project, a dynamic instrumentation toolkit.
* **Meson:** The `mesonbuild` directory strongly implies this file is related to the Meson build system.
* **`minstall.py`:** The name suggests this is likely the core installation script within Meson for Frida's QML component. The "min" might indicate a specific, perhaps streamlined, installation process.

**2. High-Level Functionality Scan (Skimming the Code):**

I'd then quickly scan the code looking for key elements:

* **Imports:**  `argparse`, `os`, `shutil`, `subprocess`, `glob`, `pickle`. These point to command-line argument parsing, operating system interactions (file manipulation, processes), and data serialization.
* **Function Definitions:**  Look for major functions like `add_arguments`, `load_install_data`, `Installer.do_install`, `Installer.install_targets`, etc. These reveal the main actions the script performs.
* **Class Definitions:** The `DirMaker` and `Installer` classes are important structures that organize the code and hold state.
* **Global Variables:** `symlink_warning`, `selinux_updates`. These indicate specific behaviors or considerations within the installation process.
* **Conditional Logic:**  Look for `if is_windows()`, `if is_aix()`, etc., which highlight platform-specific actions.

**3. Detailed Analysis of Key Components:**

Now, I'd go back and examine the more significant parts:

* **`add_arguments`:**  Clearly sets up command-line options for the script (e.g., `--no-rebuild`, `--destdir`, `--dry-run`). This tells us how a user might interact with the script.
* **`DirMaker`:** This looks like a utility class to manage directory creation in a way that's aware of dry-run mode and can log created directories. The `__enter__` and `__exit__` methods suggest it's used with `with` statements for resource management.
* **`load_install_data`:** This function uses `pickle_load`, indicating that installation instructions are likely serialized and loaded from a file.
* **`Installer` Class:** This is the heart of the script. I'd go through its methods one by one:
    * **`__init__`:**  Initializes the installer with options and a log file.
    * **Helper Methods (e.g., `remove`, `copy`, `symlink`):** These are wrappers around `os` and `shutil` functions, often checking for `dry_run` mode.
    * **`should_install`:**  Determines if a specific item should be installed based on subproject and tags.
    * **`do_copyfile`, `do_symlink`, `do_copydir`:**  Implement the core file/directory manipulation logic, including handling existing files, symlinks, and exclusions.
    * **`do_install`:** The main entry point for the installation process. It orchestrates the installation of different types of items (subdirs, targets, headers, etc.). It also handles `DESTDIR` and permission elevation.
    * **`install_subdirs`, `install_targets`, etc.:**  These methods iterate through the installation data and call the `do_*` methods to perform the actual installation.
    * **`run_install_script`:**  Handles execution of custom install scripts.
    * **`do_strip`:** Implements stripping of binaries.
* **Platform-Specific Logic:** Pay attention to `is_windows()`, `is_aix()`, `is_osx()`, which show how the script adapts to different operating systems (e.g., handling symlinks, shared libraries on AIX, stripping on macOS).
* **Error Handling:** Look for `try...except` blocks and how the script handles potential issues like permissions errors or missing files.

**4. Connecting to the Prompts (Relating to Reverse Engineering, etc.):**

Now, with a good understanding of the script's functionality, I can address the specific prompts:

* **Reverse Engineering:**  The script installs Frida components. Frida *is* a reverse engineering tool. So, the connection is direct: this script is part of the process of making the reverse engineering tool available.
* **Binary/Low-Level:**  The `strip` functionality, handling of shared libraries (.so, .dll, .a, .lib), and the awareness of SELinux contexts are all related to binary formats and operating system security features.
* **Linux/Android Kernel/Framework:**  While the script itself isn't directly manipulating the kernel, the *things* it installs (Frida components) are used for interacting with processes and potentially the kernel on these platforms. The SELinux handling is a direct Linux security feature.
* **Logic and Assumptions:**  Look at the `should_preserve_existing_file` function. The assumption is that if the source file's modification time is not newer than the destination, it's safe to skip the copy. This is a logic-based optimization.
* **User Errors:** Incorrect `DESTDIR` paths, missing dependencies for custom install scripts, or permission issues are common user errors that the script might encounter or handle.
* **Debugging:** The script's command-line arguments (like `--dry-run`) and the logging mechanism are crucial for debugging the installation process. Understanding the order in which things are installed (subdirs first, then targets, etc.) helps in tracing issues.

**5. Summarization:**

Finally, I would synthesize the information gathered to create a concise summary of the script's functionality, focusing on the key actions and purpose. This involves identifying the main goals and the steps taken to achieve them.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretations:** I might initially think "minstall" is a minimal install with fewer features, but upon closer inspection, it seems to be the standard install script within the Meson build process for this component.
* **Overlooking Details:** I might initially miss the nuances of the `DirMaker` class or the specific platform-dependent behaviors. Reviewing the code more carefully helps catch these details.
* **Connecting the Dots:**  It's important to explicitly link the script's actions to the concepts in the prompts. For example, realizing that `strip` is directly related to binary manipulation and the final size of the installed components.

By following this systematic approach, moving from a high-level overview to detailed analysis and then connecting the findings to the specific prompts, I can effectively understand and explain the functionality of the given Python script.
这是 frida 动态 instrumentation 工具的源代码文件 `frida/subprojects/frida-qml/releng/meson/mesonbuild/minstall.py` 的第一部分，它是一个使用 Meson 构建系统来执行安装任务的 Python 脚本。

**功能归纳：**

这个脚本的主要功能是处理软件的安装过程，它读取由 Meson 构建系统生成的安装数据，并根据这些数据将文件、目录、符号链接等复制到目标位置。它还处理与权限、所有权、SELinux 上下文以及自定义安装脚本相关的任务。

**具体功能点：**

1. **解析命令行参数:** 使用 `argparse` 模块定义和解析命令行参数，例如指定安装目录 (`-C`), 是否重建 (`--no-rebuild`), 只安装更改的文件 (`--only-changed`), 设置 `DESTDIR`, 执行 dry-run (`--dry-run`), 跳过子项目安装 (`--skip-subprojects`),  只安装特定标签的目标 (`--tags`), 以及是否进行 strip 操作 (`--strip`)。

2. **加载安装数据:**  `load_install_data` 函数使用 `pickle` 模块加载由 Meson 构建系统生成的安装信息，这些信息包含了需要安装的文件、目录、目标位置等。

3. **创建目录:**  `DirMaker` 类用于管理目录的创建，它记录了创建的目录，并在 dry-run 模式下也能正常工作。这确保了在安装文件之前，所有必要的父目录都已创建。

4. **文件操作:**  提供了封装了 `os` 和 `shutil` 模块的函数，用于执行文件复制 (`copy`, `copy2`, `copyfile`), 创建符号链接 (`symlink`), 删除文件 (`remove`), 设置权限 (`set_chmod`), 设置所有权 (`set_chown`) 等操作。这些函数会根据 `dry_run` 参数决定是否实际执行操作。

5. **处理权限和所有权:**  `set_mode` 函数用于设置安装文件的权限和所有者/组，它会考虑 `umask` 的设置，并在不支持 `chown` 的平台上进行兼容处理。

6. **处理 SELinux 上下文:** `restore_selinux_contexts` 函数尝试恢复已安装文件的 SELinux 安全上下文，这对于某些 Linux 发行版至关重要。

7. **处理 `DESTDIR`:**  脚本支持 `DESTDIR` 环境变量，允许将文件安装到一个临时的 staging 目录，常用于打包。

8. **安装不同类型的内容:**
    * `install_subdirs`: 安装子目录及其内容。
    * `install_targets`: 安装构建目标（例如可执行文件、库文件）。
    * `install_headers`: 安装头文件。
    * `install_man`: 安装 man 手册页。
    * `install_emptydir`: 创建空目录。
    * `install_data`: 安装普通数据文件。
    * `install_symlinks`: 创建符号链接。

9. **执行自定义安装脚本:** `run_install_script` 函数允许执行在构建时定义的自定义安装脚本，用于执行更复杂的安装逻辑。

10. **文件 strip 操作:** `do_strip` 函数用于对可执行文件和库文件进行 strip 操作，移除符号信息和调试信息，减小文件大小。

11. **Dry-run 模式:** 通过 `--dry-run` 参数，脚本可以在不实际执行安装操作的情况下，打印将会执行的操作，用于预览和调试。

12. **跳过子项目安装:**  `--skip-subprojects` 参数允许用户选择性地跳过特定子项目的安装。

13. **根据标签安装:** `--tags` 参数允许用户只安装带有特定标签的目标。

14. **日志记录:**  脚本会将安装的文件路径记录到日志文件中。

**与逆向的方法的关系及举例说明：**

由于这个脚本是 Frida 工具链的一部分，而 Frida 本身是一个动态 instrumentation 工具，常用于逆向工程、安全分析和调试。`minstall.py` 的功能是部署 Frida 的组件，使得用户能够使用 Frida 进行这些逆向相关的操作。

**举例说明:**

* **安装 Frida 的核心库:**  `minstall.py` 会将 Frida 的核心共享库（例如 `frida-core.so` 或 `frida-core.dylib`）安装到系统的库路径下。这些库是 Frida 动态 instrumentation 功能的基础，逆向工程师需要这些库才能将 Frida attach 到目标进程并进行分析。
* **安装 Frida 的命令行工具:**  像 `frida` 和 `frida-ps` 这样的命令行工具会被安装到系统的可执行文件路径下。逆向工程师会直接使用这些工具来启动 Frida、列出进程等。
* **安装 QML 相关的组件:**  从文件路径来看，这个脚本是 `frida-qml` 子项目的一部分，这意味着它负责安装 Frida 的 QML 桥接组件。这使得逆向工程师可以使用 QML 来编写 Frida 的脚本界面或扩展功能。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    * **Strip 操作:**  `do_strip` 函数直接操作二进制文件，移除其符号信息和调试信息。这涉及到对 ELF (Linux) 或 Mach-O (macOS) 等二进制文件格式的理解。
    * **共享库安装:**  脚本处理共享库的安装，这涉及到操作系统加载共享库的机制，例如 Linux 的 `ld.so` 和环境变量 `LD_LIBRARY_PATH`。
    * **AIX 特殊处理:**  针对 AIX 系统的特殊处理，涉及到 AIX 系统中共享库打包成 archive 的机制。
* **Linux 内核及框架:**
    * **SELinux 上下文:**  `restore_selinux_contexts` 函数表明脚本需要处理 Linux 的安全增强功能 SELinux，确保安装的文件具有正确的安全上下文，这对于某些受保护的系统至关重要。
    * **权限管理:**  脚本使用 `chmod` 和 `chown` 来设置文件的权限和所有者，这直接涉及到 Linux 的用户和权限模型。
* **Android 框架 (间接相关):**  虽然脚本本身不直接操作 Android 内核或框架，但它安装的 Frida 组件会被用于 Android 平台的动态 instrumentation。Frida 可以在 Android 上 attach 到应用进程，hook 函数，修改内存等，这需要深入理解 Android 的进程模型、ART 虚拟机、以及底层的系统调用。

**逻辑推理及假设输入与输出：**

**假设输入:**

* `datafilename`:  一个包含 Meson 生成的安装数据的 pickle 文件，例如 `install.dat`。
* 命令行参数: `--prefix=/usr`, `--dry-run`, `--only-changed`。

**逻辑推理:**

1. 脚本会加载 `install.dat` 文件，从中读取需要安装的文件列表和目标位置。
2. 由于指定了 `--prefix=/usr`，脚本会确定安装前缀为 `/usr`。
3. 由于指定了 `--dry-run`，脚本不会实际执行任何文件操作，只会打印将要执行的操作。
4. 由于指定了 `--only-changed`，脚本在复制文件时，会检查目标文件是否存在，并且源文件的修改时间是否比目标文件新。如果目标文件更新，则跳过复制。

**预期输出 (部分):**

```
Would install subdir source_dir/subdir to /usr/subdir_install_path
Would install target source_dir/my_executable to /usr/bin
Would install data source_dir/config.ini to /usr/etc
Would preserve old file /usr/bin/my_old_executable
```

**用户或编程常见的使用错误及举例说明：**

* **权限不足:** 用户在没有足够权限的情况下运行安装命令，导致无法创建目录或复制文件。
    * **错误信息:** `PermissionError: [Errno 13] Permission denied: '/usr/bin/my_program'`
    * **调试线索:**  检查用户是否使用了 `sudo` 或其他提权方式。脚本会尝试使用 `sudo` 或 `pkexec` 进行提权。
* **错误的 `DESTDIR` 路径:** 用户指定了不存在或不可写的 `DESTDIR` 路径。
    * **错误信息:**  可能在创建目录或复制文件时出现 `FileNotFoundError` 或 `PermissionError`。
    * **调试线索:**  检查 `DESTDIR` 环境变量或命令行参数是否正确。
* **依赖缺失导致自定义安装脚本失败:**  自定义安装脚本依赖于某些外部工具或库，但这些依赖在目标系统上不存在。
    * **错误信息:**  `FAILED: install script 'my_custom_script.sh' failed with exit code 127.` (127 通常表示命令未找到)
    * **调试线索:**  检查自定义安装脚本的内容和目标系统的环境。
* **尝试安装已存在且非文件的路径:**  如果目标位置已经存在一个目录，但要安装的是一个文件，则会报错。
    * **错误信息:** `MesonException: Destination '/usr/bin/mydir' already exists and is not a file`
    * **调试线索:**  检查安装数据和目标系统的文件系统结构。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置构建系统:** 用户首先会使用 Meson 配置 Frida 的构建，例如运行 `meson setup builddir`。
2. **编译 Frida:**  用户会执行编译命令，例如 `ninja -C builddir`。
3. **执行安装命令:** 用户希望将编译好的 Frida 组件安装到系统中，会运行类似于 `meson install -C builddir` 的命令。
4. **`meson install` 的执行:** `meson install` 命令会调用 Meson 内部的安装逻辑。
5. **调用 `minstall.py`:** Meson 会根据构建配置和目标平台的设置，调用 `frida/subprojects/frida-qml/releng/meson/mesonbuild/minstall.py` 脚本来执行实际的安装操作。
6. **脚本读取安装数据:**  `minstall.py` 脚本会读取 `builddir` 下生成的安装数据文件（例如 `meson-info/install.json` 或对应的 pickle 文件）。
7. **执行安装步骤:**  脚本根据读取的安装数据和命令行参数，执行文件复制、目录创建、权限设置等操作。

作为调试线索，了解用户执行的命令和构建配置可以帮助定位问题。例如，如果用户报告安装失败，可以检查他们是否使用了 `--dry-run` 来排除权限问题，或者检查他们是否指定了错误的 `--prefix` 或 `DESTDIR`。查看构建目录下的 `meson-log.txt` 和 `build.ninja` 文件也能提供关于构建过程和安装配置的更多信息。

**总结：**

`frida/subprojects/frida-qml/releng/meson/mesonbuild/minstall.py` 是 Frida 项目中用于执行安装任务的关键脚本，它负责将编译好的 Frida QML 组件部署到目标系统。它处理了文件复制、权限管理、符号链接、自定义脚本执行等多种安装相关的操作，并且考虑了不同平台和用户场景的需求。理解这个脚本的功能对于调试 Frida 的安装过程以及理解 Frida 的部署方式至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/minstall.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2014 The Meson development team

from __future__ import annotations

from glob import glob
import argparse
import errno
import os
import selectors
import shlex
import shutil
import subprocess
import sys
import typing as T
import re

from . import build, environment
from .backend.backends import InstallData
from .mesonlib import (MesonException, Popen_safe, RealPathAction, is_windows,
                       is_aix, setup_vsenv, pickle_load, is_osx, OptionKey)
from .scripts import depfixer, destdir_join
from .scripts.meson_exe import run_exe
try:
    from __main__ import __file__ as main_file
except ImportError:
    # Happens when running as meson.exe which is native Windows.
    # This is only used for pkexec which is not, so this is fine.
    main_file = None

if T.TYPE_CHECKING:
    from .backend.backends import (
            InstallDataBase, InstallEmptyDir,
            InstallSymlinkData, TargetInstallData
    )
    from .mesonlib import FileMode, EnvironOrDict, ExecutableSerialisation

    try:
        from typing import Protocol
    except AttributeError:
        from typing_extensions import Protocol  # type: ignore

    class ArgumentType(Protocol):
        """Typing information for the object returned by argparse."""
        no_rebuild: bool
        only_changed: bool
        profile: bool
        quiet: bool
        wd: str
        destdir: str
        dry_run: bool
        skip_subprojects: str
        tags: str
        strip: bool


symlink_warning = '''\
Warning: trying to copy a symlink that points to a file. This currently copies
the file by default, but will be changed in a future version of Meson to copy
the link instead.  Set follow_symlinks to true to preserve current behavior, or
false to copy the link.'''

selinux_updates: T.List[str] = []

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('-C', dest='wd', action=RealPathAction,
                        help='directory to cd into before running')
    parser.add_argument('--profile-self', action='store_true', dest='profile',
                        help=argparse.SUPPRESS)
    parser.add_argument('--no-rebuild', default=False, action='store_true',
                        help='Do not rebuild before installing.')
    parser.add_argument('--only-changed', default=False, action='store_true',
                        help='Only overwrite files that are older than the copied file.')
    parser.add_argument('--quiet', default=False, action='store_true',
                        help='Do not print every file that was installed.')
    parser.add_argument('--destdir', default=None,
                        help='Sets or overrides DESTDIR environment. (Since 0.57.0)')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Doesn\'t actually install, but print logs. (Since 0.57.0)')
    parser.add_argument('--skip-subprojects', nargs='?', const='*', default='',
                        help='Do not install files from given subprojects. (Since 0.58.0)')
    parser.add_argument('--tags', default=None,
                        help='Install only targets having one of the given tags. (Since 0.60.0)')
    parser.add_argument('--strip', action='store_true',
                        help='Strip targets even if strip option was not set during configure. (Since 0.62.0)')

class DirMaker:
    def __init__(self, lf: T.TextIO, makedirs: T.Callable[..., None]):
        self.lf = lf
        self.dirs: T.List[str] = []
        self.all_dirs: T.Set[str] = set()
        self.makedirs_impl = makedirs

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        dirname = os.path.normpath(path)
        self.all_dirs.add(dirname)
        dirs = []
        while dirname != os.path.dirname(dirname):
            if dirname in self.dirs:
                # In dry-run mode the directory does not exist but we would have
                # created it with all its parents otherwise.
                break
            if not os.path.exists(dirname):
                dirs.append(dirname)
            dirname = os.path.dirname(dirname)
        self.makedirs_impl(path, exist_ok=exist_ok)

        # store the directories in creation order, with the parent directory
        # before the child directories. Future calls of makedir() will not
        # create the parent directories, so the last element in the list is
        # the last one to be created. That is the first one to be removed on
        # __exit__
        dirs.reverse()
        self.dirs += dirs

    def __enter__(self) -> 'DirMaker':
        return self

    def __exit__(self, exception_type: T.Type[Exception], value: T.Any, traceback: T.Any) -> None:
        self.dirs.reverse()
        for d in self.dirs:
            append_to_log(self.lf, d)


def load_install_data(fname: str) -> InstallData:
    return pickle_load(fname, 'InstallData', InstallData)

def is_executable(path: str, follow_symlinks: bool = False) -> bool:
    '''Checks whether any of the "x" bits are set in the source file mode.'''
    return bool(os.stat(path, follow_symlinks=follow_symlinks).st_mode & 0o111)


def append_to_log(lf: T.TextIO, line: str) -> None:
    lf.write(line)
    if not line.endswith('\n'):
        lf.write('\n')
    lf.flush()


def set_chown(path: str, user: T.Union[str, int, None] = None,
              group: T.Union[str, int, None] = None,
              dir_fd: T.Optional[int] = None, follow_symlinks: bool = True) -> None:
    # shutil.chown will call os.chown without passing all the parameters
    # and particularly follow_symlinks, thus we replace it temporary
    # with a lambda with all the parameters so that follow_symlinks will
    # be actually passed properly.
    # Not nice, but better than actually rewriting shutil.chown until
    # this python bug is fixed: https://bugs.python.org/issue18108
    real_os_chown = os.chown

    def chown(path: T.Union[int, str, 'os.PathLike[str]', bytes, 'os.PathLike[bytes]'],
              uid: int, gid: int, *, dir_fd: T.Optional[int] = dir_fd,
              follow_symlinks: bool = follow_symlinks) -> None:
        """Override the default behavior of os.chown

        Use a real function rather than a lambda to help mypy out. Also real
        functions are faster.
        """
        real_os_chown(path, uid, gid, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    try:
        os.chown = chown
        shutil.chown(path, user, group)
    finally:
        os.chown = real_os_chown


def set_chmod(path: str, mode: int, dir_fd: T.Optional[int] = None,
              follow_symlinks: bool = True) -> None:
    try:
        os.chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    except (NotImplementedError, OSError, SystemError):
        if not os.path.islink(path):
            os.chmod(path, mode, dir_fd=dir_fd)


def sanitize_permissions(path: str, umask: T.Union[str, int]) -> None:
    # TODO: with python 3.8 or typing_extensions we could replace this with
    # `umask: T.Union[T.Literal['preserve'], int]`, which would be more correct
    if umask == 'preserve':
        return
    assert isinstance(umask, int), 'umask should only be "preserver" or an integer'
    new_perms = 0o777 if is_executable(path, follow_symlinks=False) else 0o666
    new_perms &= ~umask
    try:
        set_chmod(path, new_perms, follow_symlinks=False)
    except PermissionError as e:
        print(f'{path!r}: Unable to set permissions {new_perms!r}: {e.strerror}, ignoring...')


def set_mode(path: str, mode: T.Optional['FileMode'], default_umask: T.Union[str, int]) -> None:
    if mode is None or all(m is None for m in [mode.perms_s, mode.owner, mode.group]):
        # Just sanitize permissions with the default umask
        sanitize_permissions(path, default_umask)
        return
    # No chown() on Windows, and must set one of owner/group
    if not is_windows() and (mode.owner is not None or mode.group is not None):
        try:
            set_chown(path, mode.owner, mode.group, follow_symlinks=False)
        except PermissionError as e:
            print(f'{path!r}: Unable to set owner {mode.owner!r} and group {mode.group!r}: {e.strerror}, ignoring...')
        except LookupError:
            print(f'{path!r}: Nonexistent owner {mode.owner!r} or group {mode.group!r}: ignoring...')
        except OSError as e:
            if e.errno == errno.EINVAL:
                print(f'{path!r}: Nonexistent numeric owner {mode.owner!r} or group {mode.group!r}: ignoring...')
            else:
                raise
    # Must set permissions *after* setting owner/group otherwise the
    # setuid/setgid bits will get wiped by chmod
    # NOTE: On Windows you can set read/write perms; the rest are ignored
    if mode.perms_s is not None:
        try:
            set_chmod(path, mode.perms, follow_symlinks=False)
        except PermissionError as e:
            print(f'{path!r}: Unable to set permissions {mode.perms_s!r}: {e.strerror}, ignoring...')
    else:
        sanitize_permissions(path, default_umask)


def restore_selinux_contexts() -> None:
    '''
    Restores the SELinux context for files in @selinux_updates

    If $DESTDIR is set, do not warn if the call fails.
    '''
    try:
        subprocess.check_call(['selinuxenabled'])
    except (FileNotFoundError, NotADirectoryError, OSError, PermissionError, subprocess.CalledProcessError):
        # If we don't have selinux or selinuxenabled returned 1, failure
        # is ignored quietly.
        return

    if not shutil.which('restorecon'):
        # If we don't have restorecon, failure is ignored quietly.
        return

    if not selinux_updates:
        # If the list of files is empty, do not try to call restorecon.
        return

    proc, out, err = Popen_safe(['restorecon', '-F', '-f-', '-0'], ('\0'.join(f for f in selinux_updates) + '\0'))
    if proc.returncode != 0:
        print('Failed to restore SELinux context of installed files...',
              'Standard output:', out,
              'Standard error:', err, sep='\n')

def get_destdir_path(destdir: str, fullprefix: str, path: str) -> str:
    if os.path.isabs(path):
        output = destdir_join(destdir, path)
    else:
        output = os.path.join(fullprefix, path)
    return output


def check_for_stampfile(fname: str) -> str:
    '''Some languages e.g. Rust have output files
    whose names are not known at configure time.
    Check if this is the case and return the real
    file instead.'''
    if fname.endswith('.so') or fname.endswith('.dll'):
        if os.stat(fname).st_size == 0:
            (base, suffix) = os.path.splitext(fname)
            files = glob(base + '-*' + suffix)
            if len(files) > 1:
                print("Stale dynamic library files in build dir. Can't install.")
                sys.exit(1)
            if len(files) == 1:
                return files[0]
    elif fname.endswith('.a') or fname.endswith('.lib'):
        if os.stat(fname).st_size == 0:
            (base, suffix) = os.path.splitext(fname)
            files = glob(base + '-*' + '.rlib')
            if len(files) > 1:
                print("Stale static library files in build dir. Can't install.")
                sys.exit(1)
            if len(files) == 1:
                return files[0]
    return fname


class Installer:

    def __init__(self, options: 'ArgumentType', lf: T.TextIO):
        self.did_install_something = False
        self.printed_symlink_error = False
        self.options = options
        self.lf = lf
        self.preserved_file_count = 0
        self.dry_run = options.dry_run
        # [''] means skip none,
        # ['*'] means skip all,
        # ['sub1', ...] means skip only those.
        self.skip_subprojects = [i.strip() for i in options.skip_subprojects.split(',')]
        self.tags = [i.strip() for i in options.tags.split(',')] if options.tags else None

    def remove(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            os.remove(*args, **kwargs)

    def symlink(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            os.symlink(*args, **kwargs)

    def makedirs(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            os.makedirs(*args, **kwargs)

    def copy(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            shutil.copy(*args, **kwargs)

    def copy2(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            shutil.copy2(*args, **kwargs)

    def copyfile(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            shutil.copyfile(*args, **kwargs)

    def copystat(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            shutil.copystat(*args, **kwargs)

    def fix_rpath(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            depfixer.fix_rpath(*args, **kwargs)

    def set_chown(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            set_chown(*args, **kwargs)

    def set_chmod(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            set_chmod(*args, **kwargs)

    def sanitize_permissions(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            sanitize_permissions(*args, **kwargs)

    def set_mode(self, *args: T.Any, **kwargs: T.Any) -> None:
        if not self.dry_run:
            set_mode(*args, **kwargs)

    def restore_selinux_contexts(self, destdir: str) -> None:
        if not self.dry_run and not destdir:
            restore_selinux_contexts()

    def Popen_safe(self, *args: T.Any, **kwargs: T.Any) -> T.Tuple[int, str, str]:
        if not self.dry_run:
            p, o, e = Popen_safe(*args, **kwargs)
            return p.returncode, o, e
        return 0, '', ''

    def run_exe(self, exe: ExecutableSerialisation, extra_env: T.Optional[T.Dict[str, str]] = None) -> int:
        if (not self.dry_run) or exe.dry_run:
            return run_exe(exe, extra_env)
        return 0

    def should_install(self, d: T.Union[TargetInstallData, InstallEmptyDir,
                                        InstallDataBase, InstallSymlinkData,
                                        ExecutableSerialisation]) -> bool:
        if d.subproject and (d.subproject in self.skip_subprojects or '*' in self.skip_subprojects):
            return False
        if self.tags and d.tag not in self.tags:
            return False
        return True

    def log(self, msg: str) -> None:
        if not self.options.quiet:
            print(msg)

    def should_preserve_existing_file(self, from_file: str, to_file: str) -> bool:
        if not self.options.only_changed:
            return False
        # Always replace danging symlinks
        if os.path.islink(from_file) and not os.path.isfile(from_file):
            return False
        from_time = os.stat(from_file).st_mtime
        to_time = os.stat(to_file).st_mtime
        return from_time <= to_time

    def do_copyfile(self, from_file: str, to_file: str,
                    makedirs: T.Optional[T.Tuple[T.Any, str]] = None,
                    follow_symlinks: T.Optional[bool] = None) -> bool:
        outdir = os.path.split(to_file)[0]
        if not os.path.isfile(from_file) and not os.path.islink(from_file):
            raise MesonException(f'Tried to install something that isn\'t a file: {from_file!r}')
        # copyfile fails if the target file already exists, so remove it to
        # allow overwriting a previous install. If the target is not a file, we
        # want to give a readable error.
        if os.path.exists(to_file):
            if not os.path.isfile(to_file):
                raise MesonException(f'Destination {to_file!r} already exists and is not a file')
            if self.should_preserve_existing_file(from_file, to_file):
                append_to_log(self.lf, f'# Preserving old file {to_file}\n')
                self.preserved_file_count += 1
                return False
            self.log(f'Installing {from_file} to {outdir}')
            self.remove(to_file)
        else:
            self.log(f'Installing {from_file} to {outdir}')
            if makedirs:
                # Unpack tuple
                dirmaker, outdir = makedirs
                # Create dirs if needed
                dirmaker.makedirs(outdir, exist_ok=True)
        if os.path.islink(from_file):
            if not os.path.exists(from_file):
                # Dangling symlink. Replicate as is.
                self.copy(from_file, outdir, follow_symlinks=False)
            else:
                if follow_symlinks is None:
                    follow_symlinks = True  # TODO: change to False when removing the warning
                    print(symlink_warning)
                self.copy2(from_file, to_file, follow_symlinks=follow_symlinks)
        else:
            self.copy2(from_file, to_file)
        selinux_updates.append(to_file)
        append_to_log(self.lf, to_file)
        return True

    def do_symlink(self, target: str, link: str, destdir: str, full_dst_dir: str, allow_missing: bool) -> bool:
        abs_target = target
        if not os.path.isabs(target):
            abs_target = os.path.join(full_dst_dir, target)
        elif not os.path.exists(abs_target) and not allow_missing:
            abs_target = destdir_join(destdir, abs_target)
        if not os.path.exists(abs_target) and not allow_missing:
            raise MesonException(f'Tried to install symlink to missing file {abs_target}')
        if os.path.exists(link):
            if not os.path.islink(link):
                raise MesonException(f'Destination {link!r} already exists and is not a symlink')
            self.remove(link)
        if not self.printed_symlink_error:
            self.log(f'Installing symlink pointing to {target} to {link}')
        try:
            self.symlink(target, link, target_is_directory=os.path.isdir(abs_target))
        except (NotImplementedError, OSError):
            if not self.printed_symlink_error:
                print("Symlink creation does not work on this platform. "
                      "Skipping all symlinking.")
                self.printed_symlink_error = True
            return False
        append_to_log(self.lf, link)
        return True

    def do_copydir(self, data: InstallData, src_dir: str, dst_dir: str,
                   exclude: T.Optional[T.Tuple[T.Set[str], T.Set[str]]],
                   install_mode: 'FileMode', dm: DirMaker, follow_symlinks: T.Optional[bool] = None) -> None:
        '''
        Copies the contents of directory @src_dir into @dst_dir.

        For directory
            /foo/
              bar/
                excluded
                foobar
              file
        do_copydir(..., '/foo', '/dst/dir', {'bar/excluded'}) creates
            /dst/
              dir/
                bar/
                  foobar
                file

        Args:
            src_dir: str, absolute path to the source directory
            dst_dir: str, absolute path to the destination directory
            exclude: (set(str), set(str)), tuple of (exclude_files, exclude_dirs),
                     each element of the set is a path relative to src_dir.
        '''
        if not os.path.isabs(src_dir):
            raise ValueError(f'src_dir must be absolute, got {src_dir}')
        if not os.path.isabs(dst_dir):
            raise ValueError(f'dst_dir must be absolute, got {dst_dir}')
        if exclude is not None:
            exclude_files, exclude_dirs = exclude
            exclude_files = {os.path.normpath(x) for x in exclude_files}
            exclude_dirs = {os.path.normpath(x) for x in exclude_dirs}
        else:
            exclude_files = exclude_dirs = set()
        for root, dirs, files in os.walk(src_dir):
            assert os.path.isabs(root)
            for d in dirs[:]:
                abs_src = os.path.join(root, d)
                filepart = os.path.relpath(abs_src, start=src_dir)
                abs_dst = os.path.join(dst_dir, filepart)
                # Remove these so they aren't visited by os.walk at all.
                if filepart in exclude_dirs:
                    dirs.remove(d)
                    continue
                if os.path.isdir(abs_dst):
                    continue
                if os.path.exists(abs_dst):
                    print(f'Tried to copy directory {abs_dst} but a file of that name already exists.')
                    sys.exit(1)
                dm.makedirs(abs_dst)
                self.copystat(abs_src, abs_dst)
                self.sanitize_permissions(abs_dst, data.install_umask)
            for f in files:
                abs_src = os.path.join(root, f)
                filepart = os.path.relpath(abs_src, start=src_dir)
                if filepart in exclude_files:
                    continue
                abs_dst = os.path.join(dst_dir, filepart)
                if os.path.isdir(abs_dst):
                    print(f'Tried to copy file {abs_dst} but a directory of that name already exists.')
                    sys.exit(1)
                parent_dir = os.path.dirname(abs_dst)
                if not os.path.isdir(parent_dir):
                    dm.makedirs(parent_dir)
                    self.copystat(os.path.dirname(abs_src), parent_dir)
                # FIXME: what about symlinks?
                self.do_copyfile(abs_src, abs_dst, follow_symlinks=follow_symlinks)
                self.set_mode(abs_dst, install_mode, data.install_umask)

    def do_install(self, datafilename: str) -> None:
        d = load_install_data(datafilename)

        destdir = self.options.destdir
        if destdir is None:
            destdir = os.environ.get('DESTDIR')
        if destdir and not os.path.isabs(destdir):
            destdir = os.path.join(d.build_dir, destdir)
        # Override in the env because some scripts could use it and require an
        # absolute path.
        if destdir is not None:
            os.environ['DESTDIR'] = destdir
        destdir = destdir or ''
        fullprefix = destdir_join(destdir, d.prefix)

        if d.install_umask != 'preserve':
            assert isinstance(d.install_umask, int)
            os.umask(d.install_umask)

        self.did_install_something = False
        try:
            with DirMaker(self.lf, self.makedirs) as dm:
                self.install_subdirs(d, dm, destdir, fullprefix) # Must be first, because it needs to delete the old subtree.
                self.install_targets(d, dm, destdir, fullprefix)
                self.install_headers(d, dm, destdir, fullprefix)
                self.install_man(d, dm, destdir, fullprefix)
                self.install_emptydir(d, dm, destdir, fullprefix)
                self.install_data(d, dm, destdir, fullprefix)
                self.install_symlinks(d, dm, destdir, fullprefix)
                self.restore_selinux_contexts(destdir)
                self.run_install_script(d, destdir, fullprefix)
                if not self.did_install_something:
                    self.log('Nothing to install.')
                if not self.options.quiet and self.preserved_file_count > 0:
                    self.log('Preserved {} unchanged files, see {} for the full list'
                             .format(self.preserved_file_count, os.path.normpath(self.lf.name)))
        except PermissionError:
            if is_windows() or destdir != '' or not os.isatty(sys.stdout.fileno()) or not os.isatty(sys.stderr.fileno()):
                # can't elevate to root except in an interactive unix environment *and* when not doing a destdir install
                raise
            rootcmd = os.environ.get('MESON_ROOT_CMD') or shutil.which('sudo') or shutil.which('doas')
            pkexec = shutil.which('pkexec')
            if rootcmd is None and pkexec is not None and 'PKEXEC_UID' not in os.environ:
                rootcmd = pkexec

            if rootcmd is not None:
                print('Installation failed due to insufficient permissions.')
                s = selectors.DefaultSelector()
                s.register(sys.stdin, selectors.EVENT_READ)
                ans = None
                for attempt in range(5):
                    print(f'Attempt to use {rootcmd} to gain elevated privileges? [y/n] ', end='', flush=True)
                    if s.select(30):
                        # we waited on sys.stdin *only*
                        ans = sys.stdin.readline().rstrip('\n')
                    else:
                        print()
                        break
                    if ans in {'y', 'n'}:
                        break
                else:
                    if ans is not None:
                        raise MesonException('Answer not one of [y/n]')
                if ans == 'y':
                    os.execlp(rootcmd, rootcmd, sys.executable, main_file, *sys.argv[1:],
                              '-C', os.getcwd(), '--no-rebuild')
            raise

    def do_strip(self, strip_bin: T.List[str], fname: str, outname: str) -> None:
        self.log(f'Stripping target {fname!r}.')
        if is_osx():
            # macOS expects dynamic objects to be stripped with -x maximum.
            # To also strip the debug info, -S must be added.
            # See: https://www.unix.com/man-page/osx/1/strip/
            returncode, stdo, stde = self.Popen_safe(strip_bin + ['-S', '-x', outname])
        else:
            returncode, stdo, stde = self.Popen_safe(strip_bin + [outname])
        if returncode != 0:
            print('Could not strip file.\n')
            print(f'Stdout:\n{stdo}\n')
            print(f'Stderr:\n{stde}\n')
            sys.exit(1)

    def install_subdirs(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for i in d.install_subdirs:
            if not self.should_install(i):
                continue
            self.did_install_something = True
            full_dst_dir = get_destdir_path(destdir, fullprefix, i.install_path)
            self.log(f'Installing subdir {i.path} to {full_dst_dir}')
            dm.makedirs(full_dst_dir, exist_ok=True)
            self.do_copydir(d, i.path, full_dst_dir, i.exclude, i.install_mode, dm,
                            follow_symlinks=i.follow_symlinks)

    def install_data(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for i in d.data:
            if not self.should_install(i):
                continue
            fullfilename = i.path
            outfilename = get_destdir_path(destdir, fullprefix, i.install_path)
            outdir = os.path.dirname(outfilename)
            if self.do_copyfile(fullfilename, outfilename, makedirs=(dm, outdir), follow_symlinks=i.follow_symlinks):
                self.did_install_something = True
            self.set_mode(outfilename, i.install_mode, d.install_umask)

    def install_symlinks(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for s in d.symlinks:
            if not self.should_install(s):
                continue
            full_dst_dir = get_destdir_path(destdir, fullprefix, s.install_path)
            full_link_name = get_destdir_path(destdir, fullprefix, s.name)
            dm.makedirs(full_dst_dir, exist_ok=True)
            if self.do_symlink(s.target, full_link_name, destdir, full_dst_dir, s.allow_missing):
                self.did_install_something = True

    def install_man(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for m in d.man:
            if not self.should_install(m):
                continue
            full_source_filename = m.path
            outfilename = get_destdir_path(destdir, fullprefix, m.install_path)
            outdir = os.path.dirname(outfilename)
            if self.do_copyfile(full_source_filename, outfilename, makedirs=(dm, outdir)):
                self.did_install_something = True
            self.set_mode(outfilename, m.install_mode, d.install_umask)

    def install_emptydir(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for e in d.emptydir:
            if not self.should_install(e):
                continue
            self.did_install_something = True
            full_dst_dir = get_destdir_path(destdir, fullprefix, e.path)
            self.log(f'Installing new directory {full_dst_dir}')
            if os.path.isfile(full_dst_dir):
                print(f'Tried to create directory {full_dst_dir} but a file of that name already exists.')
                sys.exit(1)
            dm.makedirs(full_dst_dir, exist_ok=True)
            self.set_mode(full_dst_dir, e.install_mode, d.install_umask)

    def install_headers(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for t in d.headers:
            if not self.should_install(t):
                continue
            fullfilename = t.path
            fname = os.path.basename(fullfilename)
            outdir = get_destdir_path(destdir, fullprefix, t.install_path)
            outfilename = os.path.join(outdir, fname)
            if self.do_copyfile(fullfilename, outfilename, makedirs=(dm, outdir),
                                follow_symlinks=t.follow_symlinks):
                self.did_install_something = True
            self.set_mode(outfilename, t.install_mode, d.install_umask)

    def run_install_script(self, d: InstallData, destdir: str, fullprefix: str) -> None:
        env = {'MESON_SOURCE_ROOT': d.source_dir,
               'MESON_BUILD_ROOT': d.build_dir,
               'MESONINTROSPECT': ' '.join([shlex.quote(x) for x in d.mesonintrospect]),
               }
        if self.options.quiet:
            env['MESON_INSTALL_QUIET'] = '1'
        if self.dry_run:
            env['MESON_INSTALL_DRY_RUN'] = '1'

        for i in d.install_scripts:
            if not self.should_install(i):
                continue

            if i.installdir_map is not None:
                mapp = i.installdir_map
            else:
                mapp = {'prefix': d.prefix}
            localenv = env.copy()
            localenv.update({'MESON_INSTALL_'+k.upper(): os.path.join(d.prefix, v) for k, v in mapp.items()})
            localenv.update({'MESON_INSTALL_DESTDIR_'+k.upper(): get_destdir_path(destdir, fullprefix, v) for k, v in mapp.items()})

            name = ' '.join(i.cmd_args)
            if i.skip_if_destdir and destdir:
                self.log(f'Skipping custom install script because DESTDIR is set {name!r}')
                continue
            self.did_install_something = True  # Custom script must report itself if it does nothing.
            self.log(f'Running custom install script {name!r}')
            try:
                rc = self.run_exe(i, localenv)
            except OSError:
                print(f'FAILED: install script \'{name}\' could not be run.')
                # POSIX shells return 127 when a command could not be found
                sys.exit(127)
            if rc != 0:
                print(f'FAILED: install script \'{name}\' failed with exit code {rc}.')
                sys.exit(rc)

    def install_targets(self, d: InstallData, dm: DirMaker, destdir: str, fullprefix: str) -> None:
        for t in d.targets:
            # In AIX, we archive our shared libraries.  When we install any package in AIX we need to
            # install the archive in which the shared library exists. The below code does the same.
            # We change the .so files having lt_version or so_version to archive file install.
            # If .so does not exist then it means it is in the archive. Otherwise it is a .so that exists.
            if is_aix():
                if not os.path.exists(t.fname) and '.so' in t.fname:
                    t.fname = re.sub('[.][a]([.]?([0-9]+))*([.]?([a-z]+))*', '.a', t.fname.replace('.so', '.a'))
            if not self.should_install(t):
                continue
            if not os.path.exists(t.fname):
                # For example, import libraries of shared modules are optional
                if t.optional:
                    self.log(f'File {t.fname!r} not found, skipping')
                    continue
                else:
                    raise MesonException(f'File {t.fname!r} could not be found')
            file_copied = False # not set when a directory is copied
            fname = check_for_stampfile(t.fname)
            outdir = get_destdir_path(destdir, fullprefix, t.outdir)
            ou
"""


```