Response:
My thinking process to analyze the `minstall.py` file goes through several stages:

1. **Understand the Context:** The first and most crucial step is recognizing that this file is part of the `frida` project, specifically within the build system (`meson`) and responsible for the *installation* process. The path `frida/subprojects/frida-python/releng/meson/mesonbuild/minstall.py` clearly points to this. Knowing it's for installation immediately tells me the core function: copying built artifacts to their destination directories.

2. **Identify Key Imports:**  I quickly scan the imports at the beginning of the file. These provide hints about the functionalities used:
    * `glob`:  File pattern matching (likely for finding files).
    * `argparse`: Handling command-line arguments (`--destdir`, `--dry-run`, etc.).
    * `errno`, `os`, `shutil`, `subprocess`, `sys`: Core operating system interactions (file operations, process execution).
    * `typing`: Type hinting for better code clarity and maintainability.
    * `.`: Local imports suggest interaction with other parts of the Meson build system (like `build`, `environment`, `backend`).
    * `pickle`: Serializing and deserializing Python objects (likely for loading installation instructions).

3. **Analyze Top-Level Definitions:** I look for global variables and function definitions declared early in the file.
    * `symlink_warning`:  Highlights potential future behavior changes regarding symlink handling.
    * `selinux_updates`:  Suggests support for SELinux context restoration.
    * `add_arguments`:  This function is a strong indicator of command-line argument processing. I'd pay attention to the arguments it defines (`-C`, `--destdir`, `--dry-run`, etc.). These directly control the installation behavior.
    * `DirMaker`:  A context manager for creating directories, ensuring they are created and potentially cleaned up in a specific order.
    * `load_install_data`:  Confirms that installation instructions are loaded from a file.
    * Helper functions (`is_executable`, `append_to_log`, `set_chown`, `set_chmod`, etc.): These indicate common file system operations performed during installation.

4. **Focus on the `Installer` Class:** This class is the core of the installation logic. I'd examine its methods:
    * `__init__`: Initializes the installer with options and a log file. The `dry_run` and `skip_subprojects` options are important.
    * Methods for file system operations (`remove`, `symlink`, `copy`, etc.):  These are wrappers around standard library functions, potentially with `dry_run` logic.
    * `should_install`:  Determines if an item should be installed based on subproject and tags.
    * `log`:  Handles logging of installation actions.
    * `should_preserve_existing_file`: Implements the `--only-changed` logic.
    * `do_copyfile`, `do_symlink`, `do_copydir`: The main logic for copying files, creating symlinks, and copying directories. These methods handle potential errors and logging.
    * `do_install`: The central function that orchestrates the installation process, loading the install data and calling the other installation methods.
    * `do_strip`: Handles stripping of executables.
    * Installation methods for different types of artifacts (`install_subdirs`, `install_data`, `install_symlinks`, `install_man`, `install_emptydir`, `install_headers`, `install_targets`, `run_install_script`): These methods iterate through the installation data and perform the appropriate actions.

5. **Identify Interactions with External Systems:** I look for places where the script interacts with the operating system or other tools:
    * `subprocess.check_call(['selinuxenabled'])` and `Popen_safe(['restorecon', ...])`:  SELinux integration.
    * `os.execlp(rootcmd, ...)`:  Attempting to gain root privileges using `sudo` or similar tools.
    * Calls to `depfixer.fix_rpath`:  Indicates handling of shared library dependencies (rpaths).
    * Calls to `run_exe`: Executing custom installation scripts.

6. **Look for Conditional Logic and Error Handling:** I examine `if` statements and `try...except` blocks to understand how the script handles different scenarios (e.g., `dry_run`, missing files, permissions errors, platform differences).

7. **Connect to Reverse Engineering and Low-Level Concepts:**  At this point, I can start to make connections to reverse engineering:
    * **Binary Stripping:** The `do_strip` function directly relates to making binaries harder to reverse engineer by removing symbols and debug information.
    * **Shared Libraries and RPATH:** The `fix_rpath` function is crucial for ensuring that installed binaries can find their shared library dependencies. Understanding how RPATH works is essential in reverse engineering shared libraries.
    * **SELinux Contexts:** While not directly reverse engineering, understanding how SELinux affects permissions can be important when analyzing installed software.
    * **Installation Locations:** The entire process of copying files to specific directories is fundamental to understanding where software components reside, which is crucial for reverse engineering.
    * **Custom Install Scripts:** These scripts can perform arbitrary actions, potentially including steps that obfuscate or protect software.

8. **Consider User Errors and Debugging:** I think about how a user might end up running this script and what could go wrong:
    * Incorrect command-line arguments.
    * Insufficient permissions.
    * Missing dependencies.
    * Errors in the `InstallData` file.

9. **Synthesize and Summarize:** Finally, I combine all the information gathered to create a concise summary of the file's functionality, highlighting its role in the installation process and its connections to reverse engineering and low-level concepts.

By following these steps, I can systematically analyze the provided Python code and understand its purpose, functionality, and relevance to the broader context of software installation and reverse engineering. The key is to break down the code into smaller, manageable parts and then connect those parts to the overall goal.
这是frida动态 instrumentation工具的安装脚本的一部分，主要负责将构建好的文件和目录复制到最终的安装目标位置。以下是其功能的归纳总结：

**核心功能：文件和目录安装**

该脚本的核心功能是将构建好的 frida 相关的文件和目录从构建目录复制到系统中的安装位置。它读取一个名为 "InstallData" 的数据结构，其中包含了需要安装的各种信息，如目标文件、安装路径、权限设置等。

**详细功能点：**

1. **处理命令行参数：**  使用 `argparse` 模块解析命令行参数，例如：
    * `-C`:  切换工作目录。
    * `--no-rebuild`:  不重新构建。
    * `--only-changed`:  只覆盖已更改的文件。
    * `--quiet`:  静默模式，不打印安装的每个文件。
    * `--destdir`:  设置 DESTDIR 环境变量，用于将文件安装到临时目录，通常用于打包。
    * `--dry-run`:  模拟安装，不执行实际操作，只打印日志。
    * `--skip-subprojects`:  跳过指定子项目的安装。
    * `--tags`:  只安装带有特定标签的目标。
    * `--strip`:  即使配置时未设置，也强制剥离目标文件中的符号信息。

2. **加载安装数据：**  使用 `pickle` 模块加载名为 "InstallData" 的文件，该文件包含了要安装的所有目标、文件、目录以及它们的安装位置和权限信息。

3. **创建目录：**  使用 `os.makedirs` 创建目标安装目录，并处理可能存在的父目录缺失的情况。`DirMaker` 类用于管理目录创建，并记录创建的目录，方便在 `dry-run` 模式下模拟和清理。

4. **复制文件：**  使用 `shutil.copy2` 复制文件，保留元数据（如时间戳）。`do_copyfile` 函数封装了文件复制的逻辑，包括检查文件是否存在、是否需要覆盖、记录日志等。

5. **创建符号链接：** 使用 `os.symlink` 创建符号链接。`do_symlink` 函数处理符号链接的创建，包括检查目标是否存在，处理平台不支持符号链接的情况。

6. **复制目录：**  `do_copydir` 函数递归地复制整个目录的内容，并支持排除特定的文件或子目录。

7. **设置文件权限和所有者：**  使用 `os.chmod` 和 `shutil.chown` 设置已安装文件的权限（读、写、执行）和所有者（用户和组）。`set_mode` 函数根据 `InstallData` 中指定的模式进行设置。

8. **处理 SELinux 上下文：**  如果系统支持 SELinux，脚本会记录已安装的文件，并在安装完成后尝试使用 `restorecon` 命令恢复其 SELinux 上下文。

9. **运行自定义安装脚本：**  `run_install_script` 函数执行在构建系统中定义的自定义安装脚本，可以用于执行额外的安装步骤。

10. **剥离二进制文件符号信息：**  `do_strip` 函数使用 `strip` 命令移除可执行文件和库文件中的符号信息，减小文件大小，但也使得逆向工程更困难。

11. **处理 DESTDIR：**  如果设置了 `DESTDIR` 环境变量，脚本会将文件安装到该目录下，这对于创建软件包非常有用。

12. **Dry-run 模式：**  通过 `--dry-run` 参数，脚本可以模拟安装过程，只打印将要执行的操作，而不实际修改文件系统。

13. **跳过子项目安装：**  通过 `--skip-subprojects` 参数，可以排除特定子项目的安装。

14. **基于标签安装：**  通过 `--tags` 参数，可以只安装带有特定标签的目标。

15. **权限提升：**  如果安装失败是因为权限不足，并且是在交互式 Unix 环境下，脚本会尝试使用 `sudo` 或 `doas` 或 `pkexec` 等工具来提升权限重新执行安装。

**与逆向方法的关系：**

* **二进制剥离 (Stripping):**  `do_strip` 函数直接影响逆向工程的难度。剥离操作会移除符号信息（如函数名、变量名），使得反汇编代码更难理解。逆向工程师需要花费更多精力来分析代码的功能。
    * **举例:**  在安装 frida-server 或包含 native 库的 frida python 绑定时，如果使用了 `--strip` 参数，最终安装的 frida-server 或 native 库文件将被剥离符号信息，使用诸如 `objdump -t` 或 `readelf -s` 等工具将无法看到符号表。

* **安装位置:** 脚本决定了 frida 相关文件最终安装在系统的哪个位置。了解这些位置对于逆向分析至关重要，因为逆向工程师需要找到目标文件才能进行分析。
    * **举例:**  frida 的 Python 模块通常安装在 Python 的 site-packages 目录下，frida-server 可能安装在 `/usr/local/bin` 或其他系统路径下。逆向工程师需要知道这些路径才能找到 frida 的组件。

* **自定义安装脚本：**  自定义安装脚本可能会执行一些额外的操作，例如加密某些文件或执行特定的配置。这可能会增加逆向分析的复杂性。
    * **举例:**  一个自定义安装脚本可能会使用 `chmod` 修改某些文件的权限，限制普通用户访问，这可能会影响逆向工程师进行动态分析。

**涉及到的二进制底层，Linux, Android 内核及框架的知识：**

* **二进制底层：**
    * **剥离符号信息：**  理解二进制文件中符号表的概念，以及剥离操作对二进制文件结构的影响。
    * **可执行文件和库文件结构：**  了解不同平台（Linux, macOS, Windows）上可执行文件（如 ELF, Mach-O, PE）和库文件（如 .so, .dylib, .dll）的基本结构。

* **Linux：**
    * **文件系统权限：**  理解 Linux 文件系统的权限模型（读、写、执行权限，用户、组和其他用户），以及 `chmod` 和 `chown` 命令的作用。
    * **符号链接：**  理解符号链接的概念和使用场景。
    * **环境变量：**  了解环境变量的作用，如 `DESTDIR`。
    * **进程管理：**  理解 `subprocess` 模块如何创建和管理子进程。
    * **SELinux：**  了解 SELinux 的安全上下文机制，以及 `restorecon` 命令的作用。

* **Android 内核及框架：**  虽然该脚本本身不直接操作 Android 内核，但 frida 作为一款动态 instrumentation 工具，其应用场景通常涉及到 Android 应用和框架的逆向和分析。理解 Android 的 APK 包结构、ART 虚拟机、系统服务等知识，有助于理解 frida 的工作原理和安装过程中的相关文件。

**逻辑推理 (假设输入与输出):**

假设 `InstallData` 文件包含以下信息：

* **data:**  一个文件 `/path/to/my_script.py` 将安装到 `/usr/local/bin/my_script.py`。
* **targets:** 一个可执行文件 `/build/my_program` 将安装到 `/usr/local/bin/my_program`。
* **symlinks:**  创建一个符号链接 `/usr/local/bin/mylink` 指向 `/usr/local/bin/my_program`。

**假设输入：**

运行命令： `python minstall.py --destdir=/tmp/install`

**预期输出（在 `/tmp/install` 目录下）：**

* 创建目录 `/tmp/install/usr/local/bin/`。
* 复制 `/path/to/my_script.py` 到 `/tmp/install/usr/local/bin/my_script.py`。
* 复制 `/build/my_program` 到 `/tmp/install/usr/local/bin/my_program`。
* 创建符号链接 `/tmp/install/usr/local/bin/mylink` 指向 `my_program`。
* 终端输出类似：
  ```
  Installing /path/to/my_script.py to /tmp/install/usr/local/bin
  Installing /build/my_program to /tmp/install/usr/local/bin
  Installing symlink pointing to my_program to /tmp/install/usr/local/bin/mylink
  ```

**用户或编程常见的使用错误：**

1. **权限不足：**  用户在没有足够权限的情况下运行安装脚本，导致无法创建目录或复制文件。
    * **举例:** 用户尝试将文件安装到 `/usr/bin` 目录下，但没有 root 权限。终端会显示 `PermissionError` 相关的错误信息。

2. **目标目录已存在且不是目录：**  要安装到的目标路径已经存在一个同名的文件，导致无法创建目录。
    * **举例:**  `InstallData` 中指定安装目录为 `/usr/local/bin/my_program`，但该路径已经存在一个名为 `my_program` 的普通文件。脚本会抛出 `MesonException`。

3. **指定的安装文件不存在：** `InstallData` 中指定要安装的文件在构建目录中不存在。
    * **举例:** `InstallData` 中指定安装 `/build/non_existent_file`，但该文件实际上没有被构建出来。脚本会抛出 `MesonException`。

4. **错误的命令行参数：**  用户传递了错误的命令行参数，例如拼写错误或使用了不存在的选项。
    * **举例:** 用户输入 `python minstall.py --dstdirr=/tmp/install`，由于 `--dstdirr` 拼写错误，`argparse` 会报错。

5. **DESTDIR 设置错误：**  用户设置了 `DESTDIR` 环境变量，但其路径不是绝对路径。
    * **举例:** 用户在终端输入 `export DESTDIR=tmp_install`，然后运行安装脚本，脚本会报错，因为 `DESTDIR` 必须是绝对路径。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置构建系统：** 用户首先使用 `meson` 命令配置 frida 的构建系统，生成构建文件。这个过程会读取 `meson.build` 文件，其中定义了安装规则和目标。

2. **构建项目：** 用户使用 `ninja` 或 `meson compile` 命令编译 frida 项目，生成需要安装的二进制文件、库文件、脚本等。

3. **执行安装命令：** 用户在构建目录下执行 `meson install` 命令。

4. **`meson install` 内部调用 `minstall.py`：**  `meson install` 命令会解析构建目录下的信息，并调用 `minstall.py` 脚本来执行实际的安装操作。`meson` 会将必要的参数（例如构建目录、安装前缀等）以及生成的 `install.dat` 文件路径传递给 `minstall.py` 脚本。`install.dat` 文件就是被 `load_install_data` 函数加载的 "InstallData" 文件。

5. **`minstall.py` 执行安装逻辑：** `minstall.py` 脚本根据加载的 `InstallData` 和命令行参数，执行上述的各种安装操作，将文件复制到目标位置。

**调试线索：**

* **检查 `meson.build`：**  查看 frida 项目的 `meson.build` 文件，确认安装规则是否正确定义。
* **查看 `install.dat`：**  检查构建目录下的 `install.dat` 文件，确认其中包含了需要安装的正确的文件和路径信息。
* **运行带 `--dry-run` 的安装命令：**  使用 `meson install --dry-run -v` 命令可以查看详细的模拟安装过程，了解哪些文件会被复制到哪里。
* **检查环境变量：**  确认 `DESTDIR` 等环境变量的设置是否符合预期。
* **查看日志输出：**  如果安装过程中出现错误，查看终端的错误信息和脚本的日志输出，可以帮助定位问题。

**总结：**

`minstall.py` 是 frida 安装过程中的关键组件，负责将构建产物部署到系统中。它处理各种命令行选项，执行文件复制、符号链接创建、权限设置等操作，并支持自定义安装脚本和二进制剥离。理解其功能对于理解 frida 的安装过程、进行问题排查以及进行与安装相关的逆向工程任务都非常重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/minstall.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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