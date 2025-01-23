Response:
The user wants to understand the functionality of the `minstall.py` script in the Frida project. I need to analyze the code and explain what it does, focusing on its relation to reverse engineering, binary manipulation, Linux/Android kernel and framework knowledge, logical reasoning, potential user errors, and debugging steps.

Here's a plan:

1. **Summarize the overall purpose of the script:** It's responsible for installing build artifacts to their destination directories.
2. **Identify key functionalities:** Analyze the code blocks related to file copying, directory creation, permission setting, symlink creation, stripping binaries, and running install scripts.
3. **Relate to reverse engineering:** Explain how the script facilitates the deployment of tools used for dynamic instrumentation, a key reverse engineering technique.
4. **Connect to binary/OS concepts:** Highlight the interactions with the file system, permission model, and binary stripping, mentioning Linux/Android relevance where applicable.
5. **Analyze logical reasoning:** Look for conditional logic and branching in the code, providing examples of input and output.
6. **Identify potential user errors:** Point out common mistakes users might make during installation.
7. **Explain the user path to this script:** Describe the sequence of actions that leads to the execution of `minstall.py`.
8. **Provide a concise summary of its functions.**
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/minstall.py` 文件的功能总结：

**总体功能:**

`minstall.py` 是一个 Python 脚本，负责将使用 Meson 构建系统构建的项目（例如 Frida 工具）的构建产物（例如可执行文件、库、数据文件等）安装到目标系统上的指定位置。它处理文件和目录的复制、权限设置、符号链接的创建、二进制文件的剥离（strip）以及执行自定义的安装脚本。

**具体功能分解和相关知识点：**

1. **处理命令行参数:**
   - 使用 `argparse` 模块解析命令行参数，例如 `-C` (工作目录), `--profile-self` (性能分析), `--no-rebuild` (不重新构建), `--only-changed` (只覆盖已更改的文件), `--quiet` (静默模式), `--destdir` (目标目录前缀), `--dry-run` (模拟运行), `--skip-subprojects` (跳过子项目), `--tags` (只安装指定标签的目标), `--strip` (强制剥离二进制文件)。

2. **加载安装数据:**
   - 使用 `pickle_load` 加载由 Meson 构建系统生成的安装数据文件 (`InstallData`)，该文件包含了需要安装的文件、目录、目标位置、权限等信息。

3. **创建目录:**
   - 使用 `DirMaker` 类管理目录的创建，确保父目录在子目录之前创建，并在 dry-run 模式下跟踪需要创建的目录。
   - **二进制底层/Linux 知识:**  涉及到文件系统的目录结构操作。

4. **文件复制和权限设置:**
   - 提供 `copy`, `copy2`, `copyfile` 等方法用于文件复制。
   - 使用 `shutil.chown` 和 `os.chmod` 设置文件和目录的所有者、用户组和权限。
   - **二进制底层/Linux 知识:** 涉及到文件系统的权限模型 (user, group, other; read, write, execute) 以及 `chown` 和 `chmod` 系统调用。
   - **用户常见错误:**  用户可能在构建配置时设置了错误的安装路径或权限，导致文件安装到错误的位置或没有执行权限。

5. **符号链接处理:**
   - 使用 `os.symlink` 创建符号链接。
   - **二进制底层/Linux 知识:**  理解符号链接的概念，以及相对路径和绝对路径符号链接的区别。

6. **二进制文件剥离 (Stripping):**
   - 使用 `strip` 命令移除二进制文件中的调试符号信息，减小文件大小。
   - **二进制底层知识:**  理解二进制文件的结构，以及调试符号在其中的作用。这与**逆向**相关，因为剥离符号会使静态分析更困难。
   - **举例说明 (逆向):**  如果你想发布一个 Frida Gadget 的 release 版本，通常会使用 `strip` 命令来减小其大小并移除调试信息，使得逆向分析其内部逻辑更加困难。

7. **SELinux 上下文恢复:**
   - 使用 `restorecon` 命令恢复已安装文件的 SELinux 上下文。
   - **Linux 内核/框架知识:** 涉及到 Linux 的安全增强功能 SELinux。

8. **处理 `DESTDIR` 环境变量:**
   - 允许用户通过 `DESTDIR` 环境变量或 `--destdir` 选项指定一个临时的安装根目录，这常用于打包系统。
   - **Linux 知识:**  理解 `DESTDIR` 的作用，以及在构建和安装过程中的应用。

9. **运行自定义安装脚本:**
   - 执行在 Meson 构建配置中定义的自定义安装脚本。
   - **Linux/Android 框架知识:**  自定义安装脚本可能用于执行特定于平台或框架的操作，例如注册服务、配置系统等。
   - **假设输入与输出 (逻辑推理):** 假设一个安装脚本 `install_hook.sh` 需要将一个 Frida hook 配置文件复制到 `/etc/frida/hooks/`:
     - **假设输入:** `InstallData` 中定义了一个 `install_scripts` 条目，指向 `install_hook.sh`，并指定目标路径为 `/etc/frida/hooks/`。
     - **预期输出:** 脚本会被执行，并且配置文件会被复制到 `/etc/frida/hooks/`。

10. **跳过子项目和特定标签的目标:**
    - 可以根据命令行参数 `--skip-subprojects` 和 `--tags` 选择性地跳过某些子项目或带有特定标签的目标的安装。

11. **错误处理:**
    - 捕获各种可能发生的异常，例如权限错误 (`PermissionError`)，并提供相应的提示信息。

**与逆向方法的关系:**

`minstall.py` 直接参与部署用于动态 instrumentation 的 Frida 工具。逆向工程师通常使用 Frida 来运行时修改应用程序的行为、检查内存、跟踪函数调用等。`minstall.py` 确保 Frida 的核心组件和工具能够正确安装到目标系统，为逆向分析提供必要的工具支持。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例说明:**

- **二进制底层:**  `strip` 命令直接操作二进制文件的内容，移除特定的节 (section)。
- **Linux:**  文件权限、用户组、符号链接、SELinux 都是 Linux 操作系统的重要概念。`DESTDIR` 是打包 Linux 软件的常见做法。
- **Android:** 虽然代码没有直接提到 Android，但 Frida 广泛应用于 Android 应用程序的逆向分析。`minstall.py` 安装的 Frida 工具可以被用于 hook Android 应用程序的 Java 或 Native 层，需要对 Android 框架有一定的了解。自定义安装脚本也可能涉及到 Android 特有的操作。

**假设输入与输出 (逻辑推理):**

假设用户执行命令：

```bash
python minstall.py --destdir=/tmp/frida_install --only-changed install.dat
```

- **假设输入:**
    - `install.dat` 文件存在，并且包含了一些需要安装的文件信息，例如一个可执行文件 `frida-server` 和一个库文件 `frida-agent.so`。
    - `/tmp/frida_install` 目录不存在或为空。
    - `--only-changed` 参数被指定。
- **预期输出:**
    - `/tmp/frida_install` 目录会被创建。
    - `frida-server` 和 `frida-agent.so` 会被复制到 `/tmp/frida_install` 下对应的安装目录。
    - 如果目标目录中已经存在同名文件，并且源文件的时间戳不新于目标文件，则该文件会被保留，不会被覆盖。
    - 安装过程的日志信息会输出到控制台（除非使用了 `--quiet` 参数）。

**用户或编程常见的使用错误举例说明:**

1. **权限不足:** 用户在非 root 权限下尝试安装到需要 root 权限的目录（例如 `/usr/bin`），会导致 `PermissionError`。脚本会尝试使用 `sudo` 或 `pkexec` 提升权限（如果可用）。
2. **目标目录已存在且不是目录:**  如果安装目标路径上已经存在一个同名的文件，而不是目录，则脚本会报错。
3. **错误的安装路径配置:** 在 Meson 构建配置中指定了错误的安装路径，导致文件安装到非预期的位置。
4. **`DESTDIR` 使用不当:**  用户可能不理解 `DESTDIR` 的作用，错误地将其设置为最终安装目录，而不是一个临时目录。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发人员使用 Meson 构建系统构建 Frida 工具。**  Meson 会生成一个 `install.dat` 文件，其中包含了安装所需的信息。
2. **开发人员或用户执行 `meson install` 命令。**  Meson 会调用相应的安装脚本，通常是 `mesonbuild/installer.py`。
3. **`mesonbuild/installer.py` 会根据构建配置和目标平台，进一步调用 `minstall.py` 脚本。**  `minstall.py` 会读取 `install.dat` 文件。
4. **用户在命令行传递给 `meson install` 的参数会被传递给 `minstall.py`。** 例如，使用了 `--destdir` 参数。
5. **`minstall.py` 按照 `install.dat` 中的指令和命令行参数，执行文件复制、目录创建、权限设置等操作。**
6. **如果安装过程中出现错误，例如权限问题，`minstall.py` 会抛出异常或打印错误信息。**  调试时，可以查看这些错误信息，并检查 `install.dat` 的内容、目标目录的权限以及用户执行命令时的权限。

**归纳一下它的功能：**

`minstall.py` 的主要功能是 **自动化地将 Meson 构建的项目产物安装到目标系统**。它负责文件和目录的复制、权限管理、符号链接创建、二进制文件优化以及执行自定义安装逻辑，确保软件能够正确部署。它也考虑了打包系统的需求，并提供了一定的错误处理机制。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/minstall.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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