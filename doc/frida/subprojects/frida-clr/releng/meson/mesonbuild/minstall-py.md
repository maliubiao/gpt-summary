Response:
My thought process for analyzing the `minstall.py` script went something like this:

1. **Understand the Context:** The filename `minstall.py` within a `mesonbuild` directory strongly suggests this script is part of the Meson build system and is responsible for the installation step of a build process. The mention of Frida reinforces this, indicating this particular instance is used within the Frida project.

2. **High-Level Overview (Skimming):**  I first skimmed the code to get a general idea of its structure and the types of operations it performs. I noticed imports like `os`, `shutil`, `subprocess`, and the presence of functions related to copying, creating directories, setting permissions, and running external commands. This confirmed my initial hypothesis about its role in installation.

3. **Identify Key Functions and Classes:** I looked for the main entry points and important data structures. The `add_arguments` function clearly handles command-line arguments. The `Installer` class encapsulates the core installation logic. The `DirMaker` class manages directory creation. The `load_install_data` function hints at the existence of a data file containing installation instructions.

4. **Analyze Core Functionality (Deep Dive):**  I then went through the code more systematically, focusing on the key functions and the `Installer` class methods. I broke down the functionalities into categories:

    * **Argument Parsing:**  The `add_arguments` function defines the command-line options, revealing common installation flags like `--destdir`, `--dry-run`, `--strip`, etc.

    * **Directory Management:** The `DirMaker` class efficiently handles directory creation, preventing redundant operations and ensuring proper order for cleanup.

    * **File Operations:** The `Installer` class has methods for copying files (`do_copyfile`, `do_copydir`), creating symlinks (`do_symlink`), and removing files. It also handles checks for existing files and the `--only-changed` option.

    * **Permissions and Ownership:**  The functions `set_chown`, `set_chmod`, and `sanitize_permissions` deal with setting file ownership and permissions. The handling of `umask` is also important.

    * **External Command Execution:** The `Popen_safe` and `run_exe` methods allow the script to execute external commands, which is crucial for tasks like stripping binaries or running post-install scripts.

    * **SELinux Context Handling:** The `restore_selinux_contexts` function indicates awareness of SELinux and attempts to restore file contexts.

    * **Filtering and Skipping:** The `should_install` method enables selective installation based on subprojects and tags.

    * **Installation Logic:** The `do_install` method orchestrates the entire installation process, calling the other methods in the correct sequence. It loads the installation data and iterates through different types of installables (subdirs, targets, headers, etc.).

    * **Stripping Binaries:** The `do_strip` method handles the removal of debugging symbols from executable files.

5. **Connect to Reverse Engineering and System Knowledge:**  As I analyzed the functions, I looked for connections to reverse engineering concepts and system-level knowledge:

    * **Binary Stripping:**  This is directly related to reverse engineering, as stripping removes debug symbols that are useful for analysis.

    * **File Permissions and Ownership:** Understanding file permissions is crucial in security analysis and reverse engineering, especially when dealing with exploits or malware.

    * **Symlinks:** Recognizing how symlinks are handled is important for understanding file system structures, which can be relevant in malware analysis or system debugging.

    * **`DESTDIR`:**  Understanding the purpose of `DESTDIR` is essential for packaging and distribution, often relevant in reverse engineering for setting up controlled environments.

    * **SELinux:** Awareness of SELinux context is valuable for security analysis on Linux systems.

    * **Installation Scripts:** Recognizing that arbitrary scripts can be executed during installation is important from a security perspective.

6. **Identify Logic and Assumptions:** I looked for conditional logic and assumptions made by the script:

    * **`only_changed`:** This option makes assumptions about file modification times.

    * **Symlink Handling:** The warning about future changes in symlink handling indicates a current implementation detail.

    * **Error Handling:** The script includes `try...except` blocks for handling potential errors during file operations and command execution.

7. **User Errors and Debugging:** I considered common mistakes users might make:

    * **Incorrect `DESTDIR`:** Setting an invalid or unintended `DESTDIR`.

    * **Permissions Issues:**  Lack of write permissions in the installation directory.

    * **Missing Dependencies:** If install scripts rely on external tools not being present.

    * **Conflicting Installations:**  Trying to install over existing files with incompatible types.

    * **Incorrect Tags or Skip Subprojects:**  Mistakes in specifying tags or subprojects to skip.

8. **Trace User Operations:** I imagined the steps a user would take to reach this script:

    * Running a Meson build.
    * Executing the `ninja install` command (or similar).
    * Meson then invokes this `minstall.py` script with appropriate arguments.

9. **Summarize Functionality:** Finally, I synthesized my observations into a concise summary of the script's core functions.

This iterative process of skimming, deep diving, connecting concepts, identifying assumptions, and considering user interactions allowed me to gain a comprehensive understanding of the `minstall.py` script and its role within the Frida build process.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/minstall.py` 文件的第一部分，主要负责 Meson 构建系统中软件的安装过程。它定义了如何将构建生成的文件和目录复制到最终的安装目标位置。以下是其主要功能的归纳：

**核心功能：安装文件和目录**

* **处理命令行参数:** `add_arguments` 函数定义了 `meson install` 命令可以接受的各种命令行参数，例如：
    * `-C`:  指定运行命令前要切换到的目录。
    * `--no-rebuild`:  在安装前不重新构建。
    * `--only-changed`:  仅覆盖比复制文件旧的文件。
    * `--quiet`:  不打印每个安装的文件。
    * `--destdir`:  设置或覆盖 `DESTDIR` 环境变量，用于指定安装的根目录。
    * `--dry-run`:  模拟安装过程，但不实际执行任何操作。
    * `--skip-subprojects`:  跳过指定子项目的安装。
    * `--tags`:  仅安装具有指定标签的目标。
    * `--strip`:  即使配置时未设置 strip 选项，也剥离目标文件中的调试信息。

* **加载安装数据:** `load_install_data` 函数负责加载由 Meson 构建系统生成的 `install.dat` 文件，该文件包含了需要安装的文件、目录、权限等信息。

* **创建目录:** `DirMaker` 类用于管理目录的创建，它能记住已创建的目录，避免重复创建，并在 dry-run 模式下模拟目录创建。

* **文件复制:** `Installer` 类中的 `do_copyfile` 和 `do_copydir` 方法负责将文件和目录从构建目录复制到安装目标位置。它会检查目标文件是否存在，并根据 `--only-changed` 选项决定是否覆盖。

* **符号链接处理:** `Installer` 类中的 `do_symlink` 方法用于创建符号链接。

* **权限和所有权设置:**  `set_chown` 和 `set_chmod` 函数用于设置安装文件的所有者、组和权限。`sanitize_permissions` 函数根据 umask 值调整文件权限。

* **SELinux 上下文恢复:** `restore_selinux_contexts` 函数尝试恢复已安装文件的 SELinux 安全上下文。

* **安装不同类型的内容:** `Installer` 类中包含多个 `install_` 开头的方法，分别处理不同类型的安装项：
    * `install_subdirs`: 安装子目录及其内容。
    * `install_data`: 安装普通数据文件。
    * `install_symlinks`: 安装符号链接。
    * `install_man`: 安装 man 手册页。
    * `install_emptydir`: 创建空目录。
    * `install_headers`: 安装头文件。
    * `install_targets`: 安装构建目标（例如：可执行文件、库）。
    * `run_install_script`: 运行自定义的安装脚本。

* **Dry-run 模式支持:** `Installer` 类的大部分方法都有对 `dry_run` 模式的支持，在这种模式下，它们会打印将要执行的操作，但不会实际执行。

* **错误处理:** 包含了一些基本的错误处理机制，例如检查要安装的文件是否存在，以及在权限不足时尝试使用 `sudo` 或 `pkexec` 提权。

* **跳过子项目和标签过滤:**  `should_install` 方法允许根据子项目名称和标签来决定是否安装特定的目标。

**与逆向方法的关联及举例说明：**

* **二进制剥离 (Stripping):**  `--strip` 参数和 `do_strip` 方法直接关联到逆向。剥离二进制文件会移除调试符号和一些元数据，使得逆向分析更加困难。例如，如果 Frida 的某个组件（例如 frida-server）被配置为安装时剥离，那么逆向工程师在分析该组件时会遇到更多挑战，因为他们无法利用调试符号来理解代码的执行流程和数据结构。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **文件权限和所有权:**  `set_chown`, `set_chmod`, `sanitize_permissions` 这些函数涉及到 Linux 文件系统的基本概念，对于理解程序在不同用户和权限下的行为至关重要。例如，Frida 可能需要将其一些组件安装到需要特定权限才能访问的目录，或者设置特定的执行权限。

* **符号链接:** 符号链接是 Linux 系统中重要的文件系统特性。Frida 可能使用符号链接来组织其安装目录结构，或者链接到系统库。理解符号链接对于理解 Frida 的部署方式很有帮助。

* **`DESTDIR` 环境变量:**  `DESTDIR` 是构建系统常用的环境变量，用于将安装目标路径重定向到一个临时目录，常用于打包和创建安装包。理解 `DESTDIR` 对于分析 Frida 的打包过程和如何在 Android 等嵌入式系统上部署 Frida 非常重要。

* **SELinux:** `restore_selinux_contexts` 表明 Frida 的安装过程考虑到了 SELinux 的安全上下文。SELinux 是 Linux 内核的一个安全模块，用于提供强制访问控制。正确设置 SELinux 上下文对于 Frida 的正常运行至关重要，尤其是在安全敏感的环境中。

* **动态链接库（`.so` 或 `.dll`）处理:** `check_for_stampfile` 中对 `.so` 和 `.dll` 文件的处理，以及对 `.a` 和 `.lib` 文件的检查，表明该脚本需要处理动态链接库和静态链接库的安装。这与理解 Frida 如何加载和使用其依赖项有关。

**逻辑推理、假设输入与输出：**

假设用户执行命令：`python minstall.py --destdir=/tmp/frida_install install.dat`

* **假设输入:**
    * `options.destdir` 为 `/tmp/frida_install`
    * `datafilename` 为 `install.dat`
    * `install.dat` 文件中包含需要安装的文件和目录信息，例如一个可执行文件 `frida-server` 需要安装到 `/usr/local/bin` 目录下。

* **逻辑推理:**
    1. `do_install` 函数被调用。
    2. `load_install_data` 加载 `install.dat` 中的安装信息。
    3. `destdir` 被设置为 `/tmp/frida_install`。
    4. `fullprefix` 会根据 `install.dat` 中的 `prefix` 字段和 `destdir` 计算出来，例如如果 `prefix` 是 `/usr/local`，那么 `fullprefix` 就是 `/tmp/frida_install/usr/local`。
    5. 遍历 `install.dat` 中的安装项，例如 `install_targets` 可能会被调用来安装 `frida-server`。
    6. `do_copyfile` 被调用，将构建目录中的 `frida-server` 复制到 `/tmp/frida_install/usr/local/bin/frida-server`。
    7. 根据 `install.dat` 中的权限设置，调用 `set_chmod` 等函数设置 `frida-server` 的权限。

* **预期输出:**  在 `/tmp/frida_install/usr/local/bin/` 目录下会出现 `frida-server` 文件。如果启用了 `--quiet`，则不会有额外的输出。否则，会打印安装过程中的文件复制信息。

**用户或编程常见的使用错误及举例说明：**

* **权限不足:** 如果用户在没有足够权限的情况下运行 `meson install`，可能会遇到 `PermissionError`。例如，尝试将文件安装到 `/usr/bin` 或 `/usr/local/bin` 等系统目录下，但未使用 `sudo`。

* **`DESTDIR` 设置错误:**  如果用户错误地设置了 `DESTDIR`，例如将其设置为一个不存在的路径，安装过程可能会失败或产生意外的结果。

* **依赖文件缺失:**  如果 `install.dat` 中指定要安装的文件在构建目录中不存在，`do_install` 函数会抛出 `MesonException`。这可能是由于构建过程未成功完成。

* **覆盖冲突:**  如果目标安装路径已经存在同名但类型不同的文件（例如，尝试用文件覆盖已存在的目录），安装过程会报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置构建:** 用户首先会使用 `meson` 命令配置 Frida 的构建系统，例如 `meson _build`。这个过程会生成 `build.ninja` 文件以及其他的构建元数据，包括 `install.dat`。

2. **执行构建:** 用户会使用 `ninja` 命令执行构建，例如 `ninja -C _build`。这个过程会编译源代码并生成可执行文件、库等。

3. **执行安装命令:**  用户想要将构建生成的文件安装到系统中，会执行 `meson install -C _build` 命令。

4. **`meson install` 的执行:** `meson install` 命令会读取构建目录下的 `build.ninja` 文件，并根据其中的安装目标调用相应的安装脚本。对于使用 Meson 构建的 Python 项目，通常会调用 `mesonbuild/minstall.py` 脚本。

5. **参数传递:**  `meson install` 命令会将用户指定的命令行参数（例如 `--destdir`）传递给 `minstall.py` 脚本。

6. **`minstall.py` 的执行:**  Python 解释器执行 `minstall.py` 脚本，脚本首先解析命令行参数，然后加载 `install.dat` 文件，并根据其中的指令执行文件复制、目录创建、权限设置等操作。

作为调试线索，了解用户执行的命令和构建配置非常重要。如果安装过程中出现问题，可以检查以下内容：

* **`install.dat` 的内容:** 检查该文件是否包含了正确的安装目标和路径。
* **构建目录的内容:** 确保要安装的文件确实存在于构建目录中。
* **用户权限:** 确认用户是否有足够的权限执行安装操作。
* **`DESTDIR` 的设置:** 检查 `DESTDIR` 环境变量是否被正确设置。
* **Meson 的版本:** 某些功能可能依赖于特定版本的 Meson。

**功能归纳 (第 1 部分):**

`minstall.py` 脚本的第一部分主要负责 Meson 构建系统中软件安装流程的 **初始化和核心文件操作**。它处理命令行参数，加载安装数据，并定义了用于创建目录、复制文件、创建符号链接以及设置文件权限和所有权的基本功能。它还初步涉及了 SELinux 上下文的处理和对不同类型安装项的区分。这部分为后续的安装过程奠定了基础。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/minstall.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```