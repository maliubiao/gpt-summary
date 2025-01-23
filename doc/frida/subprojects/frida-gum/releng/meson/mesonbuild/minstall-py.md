Response:
The user wants a summary of the functionality of the Python script `minstall.py`, which is part of the Frida dynamic instrumentation tool's build system (Meson). I need to identify the key actions this script performs and relate them to reverse engineering, low-level operations, and potential user errors.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `minstall.py` and the context (part of a build system) strongly suggest that the script is responsible for the *installation* phase of the build process. This involves copying files from the build directory to the installation destination.

2. **Analyze Top-Level Functions and Classes:**
    * `add_arguments`:  This indicates the script takes command-line arguments, allowing users to customize the installation process (e.g., `destdir`, `dry-run`).
    * `DirMaker`: This class likely manages the creation of destination directories, ensuring they exist before files are copied.
    * `load_install_data`: This function suggests that the script reads installation instructions from a file (`InstallData`). This file would be generated during the configuration/build phase.
    * `is_executable`, `append_to_log`, `set_chown`, `set_chmod`, `sanitize_permissions`, `set_mode`: These utility functions are for managing file permissions and ownership during installation.
    * `restore_selinux_contexts`: This indicates handling of SELinux security contexts, which is relevant on Linux systems.
    * `get_destdir_path`: This function deals with calculating the final installation path, considering the `DESTDIR` environment variable.
    * `check_for_stampfile`:  This suggests handling cases where filenames might not be known precisely at configuration time, which can occur with certain build tools.
    * `Installer`: This is the main class that orchestrates the installation process. Its methods (e.g., `do_copyfile`, `do_symlink`, `install_targets`, `install_headers`) perform the actual installation tasks.

3. **Group Functionality into Key Areas:** Based on the identified functions and classes, I can group the functionalities:
    * **Configuration and Argument Parsing:** Handling command-line options.
    * **Directory Management:** Creating necessary directories in the installation destination.
    * **File Copying and Installation:**  The core function of copying files.
    * **Permission and Ownership Management:** Setting appropriate permissions and ownership.
    * **Symlink Handling:** Creating symbolic links.
    * **SELinux Context Management:**  Dealing with SELinux contexts.
    * **Custom Install Scripts:** Running user-defined scripts during installation.
    * **Target-Specific Installation:** Installing compiled binaries, libraries, etc.
    * **Handling DESTDIR:**  Supporting installation into an alternative root directory.

4. **Relate to Reverse Engineering:** Consider how these functionalities might be relevant to reverse engineering:
    * Installing Frida itself is a prerequisite for using it for dynamic instrumentation, which is a key reverse engineering technique.
    * The installed files (libraries, executables) are the targets of reverse engineering efforts.
    * Understanding the installation process can reveal the structure of the installed application and the locations of key components.

5. **Relate to Low-Level and Kernel Knowledge:** Identify functionalities that interact with the operating system at a lower level:
    * Setting file permissions and ownership (`set_chown`, `set_chmod`).
    * Creating symbolic links (`os.symlink`).
    * Handling SELinux contexts.
    * The concept of `DESTDIR` is related to packaging and system administration.

6. **Formulate the Summary:** Combine the grouped functionalities into a concise summary, highlighting the key responsibilities of the script. Use clear and understandable language.

7. **Refine and Organize:**  Ensure the summary is logically structured and easy to read. Use bullet points or numbered lists for clarity. Emphasize the overall goal of the script.

By following these steps, I can create a comprehensive and informative summary of the `minstall.py` script's functionality, as demonstrated in the provided good answer.
好的，根据提供的源代码，`minstall.py` 脚本的主要功能是执行软件的安装过程。它是 Meson 构建系统的一部分，用于将构建生成的文件（例如可执行文件、库文件、头文件等）复制到最终的安装目标位置。

以下是对 `minstall.py` 脚本功能的归纳：

**核心功能:**

1. **处理安装指令:**  `minstall.py` 读取由 Meson 构建系统生成的安装数据文件 (`InstallData`，通过 `load_install_data` 函数加载）。这个数据文件包含了需要安装的文件、目录、符号链接以及相关的安装路径、权限等信息。

2. **创建目标目录:**  根据安装数据中的路径信息，创建必要的目录结构 (`DirMaker` 类和 `makedirs` 方法）。

3. **复制文件:** 将构建生成的文件从构建目录复制到安装目标目录 (`do_copyfile` 和相关 `copy` 函数）。 可以选择只复制修改过的文件 (`--only-changed`)。

4. **设置文件权限和所有权:** 根据安装数据中指定的模式 (`FileMode`) 和默认的 `umask`，设置安装后文件的权限 (`set_chmod`) 和所有权 (`set_chown`)。

5. **创建符号链接:**  根据安装数据创建符号链接 (`do_symlink`)。

6. **安装子目录:**  递归地复制整个目录及其内容 (`install_subdirs` 和 `do_copydir`)。

7. **安装数据文件:**  安装普通的数据文件 (`install_data`)。

8. **安装 man 手册页:**  安装 man 手册页 (`install_man`)。

9. **安装空目录:**  创建指定的空目录 (`install_emptydir`)。

10. **安装头文件:**  安装头文件到指定的包含目录 (`install_headers`)。

11. **运行自定义安装脚本:**  执行在构建配置中定义的自定义安装脚本 (`run_install_script`)，允许执行额外的安装后处理。

12. **处理 DESTDIR:** 支持 `DESTDIR` 环境变量，允许将文件安装到一个临时的根目录，这通常用于打包。

13. **剥离调试符号 (Stripping):** 如果启用了剥离选项 (`--strip`)，则可以从可执行文件和库文件中移除调试符号 (`do_strip`)。

14. **处理 SELinux 上下文:** 在支持 SELinux 的系统上，尝试恢复已安装文件的 SELinux 安全上下文 (`restore_selinux_contexts`)。

15. **Dry-run 模式:**  支持 `--dry-run` 选项，允许模拟安装过程而不实际执行任何文件操作。

16. **跳过子项目安装:** 支持 `--skip-subprojects` 选项，允许排除特定子项目的安装。

17. **按标签安装:** 支持 `--tags` 选项，允许只安装带有特定标签的目标。

**与逆向方法的关系:**

* **安装目标是逆向分析的对象:**  `minstall.py` 最终安装的可执行文件、库文件等，正是逆向工程师需要分析的目标程序和组件。了解这些文件如何被安装，以及它们在文件系统中的位置，对于逆向分析至关重要。
    * **举例说明:** 当逆向工程师想要分析 Frida Gum 库的功能时，他们需要知道该库被安装到哪个目录下（例如，`/usr/lib/frida-gum/`）。`minstall.py` 的执行过程就负责将 Gum 库复制到这个位置。

**涉及二进制底层、Linux/Android 内核及框架的知识:**

* **文件权限和所有权:**  `set_chmod` 和 `set_chown` 等函数直接操作底层的文件系统权限，这对于确保安装后的程序能够正确运行至关重要。这涉及到 Linux 文件系统的用户、组和权限模型。
    * **举例说明:**  某些 Frida 组件可能需要以 root 权限运行或访问特定的设备文件。`minstall.py` 可以设置这些组件的权限，例如设置 setuid 位，允许非 root 用户以 root 权限执行。

* **符号链接:**  符号链接是 Linux 和类 Unix 系统中重要的概念，`minstall.py` 可以创建符号链接，将一个文件或目录链接到另一个位置。这在共享库的管理中很常见。
    * **举例说明:**  Frida 可能会安装一些符号链接，例如将特定版本的库链接到通用的库名称，以便应用程序能够找到正确的库版本。

* **SELinux 上下文:**  SELinux 是 Linux 内核中的一个安全模块，`restore_selinux_contexts` 函数处理已安装文件的 SELinux 安全上下文，确保系统安全策略得到执行。
    * **举例说明:**  Frida 的某些组件可能需要特定的 SELinux 策略才能正常工作。`minstall.py` 尝试恢复正确的上下文，以避免权限问题。

* **剥离调试符号 (Stripping):**  `do_strip` 函数调用 `strip` 工具来移除二进制文件中的调试信息，这可以减小文件大小，但也使得逆向分析更加困难。
    * **举例说明:**  Frida 的发布版本通常会剥离调试符号，以减小安装包的大小。逆向工程师如果想进行更深入的调试，可能需要使用未剥离符号的版本。

* **DESTDIR:**  `DESTDIR` 的概念与 Linux 发行版的打包系统密切相关，允许在不修改系统根目录的情况下安装文件，这对于创建软件包非常重要。

**逻辑推理和假设输入/输出:**

假设输入一个 `InstallData` 文件，其中包含以下信息：

* 要安装一个名为 `frida-server` 的可执行文件，位于构建目录的 `src/frida-server`，安装到 `/usr/bin/frida-server`。
* 要安装一个名为 `libfrida-gum.so` 的共享库，位于构建目录的 `gum/libfrida-gum.so`，安装到 `/usr/lib/libfrida-gum.so`。
* 要创建一个符号链接，将 `/usr/lib/libfrida-gum.so` 链接到 `/usr/lib/libfrida-gum.so.18`。
* 设置 `frida-server` 的权限为 `0755`。

**假设输出（在非 `--dry-run` 模式下）：**

1. 创建 `/usr/bin/` 目录（如果不存在）。
2. 复制 `build_dir/src/frida-server` 到 `/usr/bin/frida-server`。
3. 设置 `/usr/bin/frida-server` 的权限为 `0755`。
4. 创建 `/usr/lib/` 目录（如果不存在）。
5. 复制 `build_dir/gum/libfrida-gum.so` 到 `/usr/lib/libfrida-gum.so`。
6. 创建符号链接 `/usr/lib/libfrida-gum.so.18` 指向 `/usr/lib/libfrida-gum.so`。
7. 将上述操作记录到安装日志文件中。

**用户或编程常见的使用错误举例说明:**

* **权限不足:** 用户在没有足够权限的情况下运行安装命令，导致无法创建目录或复制文件。
    * **举例说明:** 如果用户尝试在没有 `sudo` 的情况下运行 `meson install`，并且安装目标路径需要 root 权限才能写入，则会抛出 `PermissionError`。脚本会尝试提示用户使用 `sudo` 或 `pkexec` 等提权工具。

* **目标路径已存在且类型不符:**  尝试安装文件到已经存在的同名目录，或尝试安装目录到已经存在的同名文件。
    * **举例说明:** 如果 `/usr/bin/frida-server` 已经是一个目录，并且用户尝试安装一个名为 `frida-server` 的文件到 `/usr/bin/` 下，则会抛出 `MesonException`，提示目标已存在且不是文件。

* **错误的 `DESTDIR` 使用:**  用户设置了不正确的 `DESTDIR` 路径，导致文件安装到错误的位置。
    * **举例说明:**  用户可能错误地将 `DESTDIR` 设置为一个不存在的路径，导致安装过程失败或文件安装到意想不到的地方。

* **自定义安装脚本错误:**  自定义安装脚本中存在错误（例如，命令不存在，逻辑错误），导致安装失败。
    * **举例说明:**  一个自定义安装脚本尝试复制一个不存在的文件，或者执行了一个带有错误参数的命令，这会导致脚本返回非零退出码，`minstall.py` 会捕获这个错误并终止安装。

**用户操作如何一步步到达这里，作为调试线索:**

1. **开发者配置构建环境:**  开发者使用 Meson 构建系统配置 Frida 的构建环境 (`meson setup builddir`)。
2. **开发者执行构建:**  开发者使用 Meson 执行构建过程 (`meson compile -C builddir`). 这会生成可执行文件、库文件等，并且会生成安装数据文件（`install.json` 或类似的）。
3. **开发者执行安装命令:**  开发者在构建目录中运行安装命令 (`meson install -C builddir`).
4. **Meson 调用 `minstall.py`:**  Meson 构建系统会调用 `minstall.py` 脚本，并将安装数据文件的路径作为参数传递给它。
5. **`minstall.py` 执行安装逻辑:**  `minstall.py` 脚本读取安装数据，并根据其中的指令执行文件复制、权限设置等操作。

**调试线索:**

* **检查安装日志:**  `minstall.py` 会将安装过程中的操作记录到日志文件中。查看这个日志文件可以了解哪些文件被复制，哪些目录被创建，以及是否有任何错误发生。
* **检查 `InstallData` 文件:**  查看 Meson 生成的安装数据文件，可以了解构建系统计划如何安装这些文件。这可以帮助诊断配置阶段的问题。
* **使用 `--dry-run` 模式:**  使用 `--dry-run` 选项运行安装命令，可以模拟安装过程，查看哪些操作会被执行，而不会实际修改文件系统。这有助于在实际安装前发现潜在问题。
* **检查权限:**  如果出现权限错误，需要检查用户运行安装命令的权限，以及目标安装路径的权限。
* **逐步调试 `minstall.py`:**  如果需要深入了解安装过程，可以使用 Python 调试器逐步执行 `minstall.py` 的代码，查看每一步的操作。

总而言之，`minstall.py` 是 Frida 安装过程的关键组件，负责将构建的产物部署到最终的用户系统中。它涉及到文件操作、权限管理、符号链接处理以及与操作系统底层的交互。理解其功能有助于理解 Frida 的安装方式，并在遇到安装问题时进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/minstall.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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