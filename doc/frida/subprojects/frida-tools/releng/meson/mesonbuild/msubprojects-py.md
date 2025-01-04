Response:
My thought process for analyzing the provided Python code and generating the summary goes through these stages:

1. **Understanding the Goal:** The request asks for a functional summary of the provided Python code, specifically focusing on its relation to reverse engineering, low-level details (kernel, etc.), logical reasoning, common user errors, and debugging. It also explicitly asks for a summary of its functionality as the first part of a two-part analysis.

2. **Initial Skim and File Path Context:** I first note the file path: `frida/subprojects/frida-tools/releng/meson/mesonbuild/msubprojects.py`. This immediately tells me it's part of the Frida project, related to its build system (Meson), and specifically deals with managing subprojects. This context is crucial for understanding the code's purpose.

3. **Identifying Key Components:** I start scanning the code for recognizable patterns and structures:
    * **Imports:**  `os`, `subprocess`, `argparse`, `asyncio`, `threading`, `copy`, `shutil`, `pathlib`, `typing`, `tarfile`, `zipfile`. These suggest file system operations, process management, command-line argument parsing, concurrency, and archive handling.
    * **Data Classes:** `@dataclass(eq=False)` for `Runner`. This hints at a central data structure holding information about subproject processing.
    * **Classes:** `Logger` and `Runner`. These are the main actors in the code.
    * **Functions:**  Many functions like `read_archive_files`, `update_wrapdb`, `update_git`, `checkout`, `download`, `purge`, `packagefiles`, `add_arguments`, `run`. These indicate distinct actions the script can perform.
    * **Argument Parsing:**  The use of `argparse` strongly suggests this script is a command-line tool.
    * **Mentions of Git, HG, SVN:**  The presence of `update_git`, `update_hg`, and `update_svn` clearly points to version control system integration.
    * **References to "wrap"**:  Frequent use of "wrap" suggests it's dealing with external dependencies or submodules managed by a "wrap" system (likely Meson's wrap dependency management).

4. **Inferring Core Functionality (The "What"):** Based on the identified components, I start to deduce the core functionality: This script is a tool to manage subprojects within a larger Meson build. It handles tasks like downloading, updating, checking out specific versions, and potentially patching these subprojects. The "wrap" terminology suggests it uses Meson's mechanism for handling external dependencies.

5. **Relating to Reverse Engineering:** Now, I specifically look for connections to reverse engineering:
    * **Frida Context:** Knowing this is part of Frida is the biggest clue. Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. Therefore, this script likely helps manage the dependencies needed to build Frida itself, which includes components used for inspecting and modifying running processes.
    * **Subproject Management:**  Reverse engineering often involves working with complex software that has numerous dependencies. A tool to manage these dependencies is directly relevant. Updating and checking out specific versions of libraries can be critical for replicating specific environments or analyzing particular software versions.
    * **Binary/Low-Level Implications:**  While the script doesn't directly manipulate binaries, the *purpose* of Frida is to interact with binaries at a low level. Managing Frida's build process is a necessary step to *using* Frida for binary analysis.

6. **Identifying Low-Level/Kernel/Framework Aspects:** I look for specific keywords or actions that touch on these areas:
    * **Subproject Dependencies:**  Frida interacts with the target process's memory and execution flow. Its subprojects likely include libraries that interface with the operating system kernel or user-space frameworks. While this script doesn't *implement* those low-level interactions, it manages the build process for those components.
    * **Platform Specificity (Implicit):**  The mention of Linux and Android kernels, though not explicitly in *this code snippet*, is strongly implied by the context of Frida being used for mobile and desktop reverse engineering, which often targets these platforms.

7. **Considering Logical Reasoning (Hypothetical Inputs/Outputs):** I think about how the different commands would behave:
    * **`update`:** If a subproject's `wrap` file specifies a new Git revision, the script would fetch and potentially rebase or reset the local repository.
    * **`checkout`:** If a user specifies a branch name, the script would attempt to switch to that branch in the subproject's Git repository.
    * **`purge`:**  If the `--confirm` flag is used, the script would delete the specified subproject's directory.

8. **Anticipating User Errors:** I consider common mistakes users might make:
    * **Incorrect Command-Line Arguments:**  Typing the wrong subproject name, forgetting flags like `--confirm` for `purge`, or using mutually exclusive options.
    * **Network Issues:**  Problems downloading subproject sources.
    * **Git Conflicts:**  Issues during rebasing or resetting if the user has local changes.
    * **Permissions Problems:**  Difficulties creating or deleting directories.

9. **Tracing User Actions (Debugging Clues):** I imagine the sequence of steps a user might take to end up needing to examine this script:
    * **Building Frida:** The user is trying to build Frida from source and encounters issues with subproject dependencies.
    * **Subproject Problems:**  A specific subproject fails to build or update correctly.
    * **Investigating Build Process:** The user looks into the Frida build system (Meson) and identifies this script as being responsible for managing subprojects.
    * **Debugging Subproject Management:** The user might then try running the script directly with specific commands (like `update` with `--verbose` or by examining the script's logic.

10. **Synthesizing the Summary:** Finally, I combine all of these observations into a concise summary, addressing each point in the request. I focus on the core functionality and then elaborate on the connections to reverse engineering, low-level aspects, logical reasoning, user errors, and debugging. I make sure to explicitly state that this is Part 1 of the analysis, focusing on the functional overview.

This iterative process of scanning, identifying, inferring, relating, and anticipating allows me to develop a comprehensive understanding of the code's purpose and its implications within the larger context of Frida and reverse engineering.
这是文件 `frida/subprojects/frida-tools/releng/meson/mesonbuild/msubprojects.py` 的源代码，它是 Frida 动态 instrumentation 工具的一部分，用于管理构建过程中的子项目。以下是其功能的归纳：

**主要功能概述：**

这个 Python 脚本提供了一组命令，用于管理 Frida 项目构建过程中依赖的外部子项目。它使用 Meson 构建系统的功能来下载、更新、检出、清理和处理这些子项目。该脚本主要围绕 `Runner` 类展开，该类封装了对单个子项目执行各种操作的逻辑。

**详细功能点：**

1. **子项目生命周期管理:**
   - **下载 (`download`):**  确保子项目的源代码被下载到本地。如果已经存在，则不做修改。
   - **更新 (`update`):**  更新子项目的源代码到 `wrap` 文件中指定的版本。支持多种版本控制系统（Git, Mercurial, Subversion）以及直接下载文件的方式。
   - **检出 (`checkout`):**  允许检出子项目中特定的分支或提交 (仅限 Git)。
   - **清理 (`purge`):**  删除与子项目相关的本地文件，包括源代码目录和缓存文件。

2. **与 Meson Wrap 功能集成:**
   - **WrapDB 更新 (`update_wrapdb`):**  从 WrapDB (Meson 的依赖管理数据库) 更新子项目的 `wrap` 文件到最新版本。
   - **解析 `wrap` 文件:**  读取和解析 `wrap` 文件以获取子项目的源地址、版本、补丁等信息。
   - **应用补丁:**  能够应用 `wrap` 文件中指定的补丁到子项目源代码。

3. **版本控制系统支持:**
   - **Git:**  提供详细的 Git 操作支持，包括拉取、检出、创建分支、重置、变基、获取远程仓库信息等。
   - **Mercurial (Hg):** 支持 Mercurial 的拉取和检出操作。
   - **Subversion (Svn):** 支持 Subversion 的更新到指定版本或 HEAD 的操作。

4. **命令行接口:**
   - 使用 `argparse` 模块定义了丰富的命令行参数和子命令，方便用户执行各种子项目管理操作。
   - 支持指定要操作的特定子项目，或操作所有子项目。
   - 提供了诸如 `--num-processes` 来控制并行处理的选项。

5. **日志记录和进度显示:**
   - 使用 `Logger` 类提供带进度的日志输出，清晰地展示当前正在处理的子项目和完成进度。

6. **其他实用功能:**
   - **执行命令 (`foreach`):**  允许在每个子项目的目录下执行任意命令。
   - **管理包文件 (`packagefiles`):**  用于应用或保存子项目的补丁文件。

**与逆向方法的关系及举例说明：**

* **管理逆向工程工具的依赖:** Frida 本身就是一个用于逆向工程的工具，它依赖于许多其他的库和组件。这个脚本可以帮助开发者和用户管理这些依赖项的版本和更新，确保 Frida 能够正确构建和运行。
    * **举例:**  假设 Frida 依赖于某个版本的 GLib 库。逆向工程师可能需要确保他们使用的 Frida 版本依赖的是特定的 GLib 版本，以便复现某个特定的行为或漏洞。这个脚本的 `update` 命令可以用来更新 GLib 子项目到指定的版本。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **子项目可能是底层库:**  Frida 的一些子项目可能是与操作系统底层交互的库，例如用于进程注入、内存操作等的库。
    * **举例:**  Frida 在某些平台上可能依赖于特定的内核模块或者用户态库来实现其功能。这个脚本管理这些子项目，确保这些底层组件能够被正确地构建和集成到 Frida 中。
* **与 Android 框架相关:**  Frida 在 Android 平台上被广泛使用。其子项目可能包含与 Android 系统框架交互的代码。
    * **举例:**  Frida 可能依赖于一个子项目，该子项目提供了与 ART (Android Runtime) 虚拟机交互的功能。这个脚本确保该子项目被正确地获取和构建。

**逻辑推理及假设输入与输出：**

* **假设输入:** 用户执行命令 `python msubprojects.py update --reset my-subproject`
* **逻辑推理:**
    1. 脚本会解析命令行参数，确定要执行的操作是 `update`，并且指定了要重置的子项目是 `my-subproject`。
    2. 脚本会查找名为 `my-subproject` 的子项目的 `wrap` 文件，从中获取其类型（例如 `git`）和版本信息。
    3. 如果子项目类型是 `git`，脚本会执行以下操作：
        - 删除本地 `my-subproject` 目录。
        - 根据 `wrap` 文件中的 URL 克隆该仓库。
        - 检出 `wrap` 文件中指定的 `revision`。
        - 应用 `wrap` 文件中指定的补丁。
* **输出:**  屏幕上会显示更新 `my-subproject` 的日志信息，包括下载、检出、重置等步骤。最终，`my-subproject` 的本地目录会被更新到 `wrap` 文件中指定的状态。

**涉及用户或编程常见的使用错误及举例说明：**

* **未安装版本控制工具:** 如果子项目的类型是 Git，但用户的系统上没有安装 Git，则 `update` 命令会失败。
    * **举例:** 用户尝试更新一个 Git 子项目，但终端提示 "git: command not found"。
* **网络问题:**  下载子项目源代码时，如果网络连接出现问题，会导致下载失败。
    * **举例:** 用户在执行 `download` 或 `update` 命令时，因为网络不稳定，看到下载超时的错误信息。
* **错误的 `wrap` 文件配置:**  如果 `wrap` 文件中的 URL 或 revision 信息不正确，会导致脚本无法找到或检出正确的子项目版本。
    * **举例:** `wrap` 文件中 Git 仓库的 URL 拼写错误，导致脚本在尝试克隆时报错。
* **权限问题:**  用户可能没有足够的权限在指定的目录下创建或删除文件，导致下载或清理操作失败。
    * **举例:** 用户尝试使用 `purge` 命令清理子项目，但因为没有删除目录的权限而失败。
* **忘记 `--confirm` 参数:** 在使用 `purge` 命令时，如果忘记添加 `--confirm` 参数，默认情况下脚本不会执行删除操作，这可能会让用户感到困惑。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **尝试构建 Frida:** 用户首先会尝试按照 Frida 的官方文档或他们自己的构建流程来编译 Frida。这通常涉及到运行类似 `meson build` 和 `ninja` 的命令。
2. **构建失败并提示子项目问题:** 在构建过程中，可能会出现与子项目相关的错误，例如下载失败、版本不匹配、编译错误等。错误信息可能会指向特定的子项目。
3. **意识到需要手动管理子项目:** 用户可能会意识到 Frida 的构建系统使用某种机制来管理子项目，并开始查找相关的信息。他们可能会在 Frida 的源代码中找到 `meson.build` 文件，并了解到 Meson 的子项目功能。
4. **找到 `msubprojects.py` 脚本:**  通过查看 Frida 的构建脚本或文档，用户可能会发现 `frida-tools` 仓库中的 `msubprojects.py` 脚本是用于管理子项目的工具。
5. **尝试使用 `msubprojects.py` 进行调试:**  用户可能会尝试使用这个脚本的各种命令来解决构建问题，例如：
    - 使用 `download` 命令手动下载失败的子项目。
    - 使用 `update` 命令尝试更新子项目到指定的版本。
    - 使用 `purge` 命令清理子项目并重新下载。
    - 阅读脚本的源代码 (`msubprojects.py`) 以了解其工作原理，以便更好地诊断问题。

**归纳一下它的功能 (作为第 1 部分的总结):**

`msubprojects.py` 是 Frida 构建系统中的一个关键脚本，它提供了一套全面的命令行工具，用于自动化管理 Frida 依赖的外部子项目。其核心功能包括下载、更新、检出、清理子项目，并与 Meson 的 Wrap 功能紧密集成。该脚本支持多种版本控制系统，并提供了详细的日志输出和错误处理机制，方便开发者和用户管理 Frida 的依赖关系，确保 Frida 能够被正确地构建。它对于解决构建过程中遇到的子项目相关问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/msubprojects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
from __future__ import annotations

from dataclasses import dataclass, InitVar
import os, subprocess
import argparse
import asyncio
import threading
import copy
import shutil
from concurrent.futures.thread import ThreadPoolExecutor
from pathlib import Path
import typing as T
import tarfile
import zipfile

from . import mlog
from .ast import IntrospectionInterpreter
from .mesonlib import quiet_git, GitException, Popen_safe, MesonException, windows_proof_rmtree
from .wrap.wrap import (Resolver, WrapException, ALL_TYPES,
                        parse_patch_url, update_wrap_file, get_releases)

if T.TYPE_CHECKING:
    from typing_extensions import Protocol

    from .wrap.wrap import PackageDefinition

    SubParsers = argparse._SubParsersAction[argparse.ArgumentParser]

    class Arguments(Protocol):
        sourcedir: str
        num_processes: int
        subprojects: T.List[str]
        types: str
        subprojects_func: T.Callable[[], bool]
        allow_insecure: bool

    class UpdateArguments(Arguments):
        rebase: bool
        reset: bool

    class UpdateWrapDBArguments(Arguments):
        force: bool
        releases: T.Dict[str, T.Any]

    class CheckoutArguments(Arguments):
        b: bool
        branch_name: str

    class ForeachArguments(Arguments):
        command: str
        args: T.List[str]

    class PurgeArguments(Arguments):
        confirm: bool
        include_cache: bool

    class PackagefilesArguments(Arguments):
        apply: bool
        save: bool

ALL_TYPES_STRING = ', '.join(ALL_TYPES)

def read_archive_files(path: Path, base_path: Path) -> T.Set[Path]:
    if path.suffix == '.zip':
        with zipfile.ZipFile(path, 'r') as zip_archive:
            archive_files = {base_path / i.filename for i in zip_archive.infolist()}
    else:
        with tarfile.open(path) as tar_archive: # [ignore encoding]
            archive_files = {base_path / i.name for i in tar_archive}
    return archive_files

class Logger:
    def __init__(self, total_tasks: int) -> None:
        self.lock = threading.Lock()
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.running_tasks: T.Set[str] = set()
        self.should_erase_line = ''

    def flush(self) -> None:
        if self.should_erase_line:
            print(self.should_erase_line, end='\r')
            self.should_erase_line = ''

    def print_progress(self) -> None:
        line = f'Progress: {self.completed_tasks} / {self.total_tasks}'
        max_len = shutil.get_terminal_size().columns - len(line)
        running = ', '.join(self.running_tasks)
        if len(running) + 3 > max_len:
            running = running[:max_len - 6] + '...'
        line = line + f' ({running})'
        print(self.should_erase_line, line, sep='', end='\r')
        self.should_erase_line = '\x1b[K'

    def start(self, wrap_name: str) -> None:
        with self.lock:
            self.running_tasks.add(wrap_name)
            self.print_progress()

    def done(self, wrap_name: str, log_queue: T.List[T.Tuple[mlog.TV_LoggableList, T.Any]]) -> None:
        with self.lock:
            self.flush()
            for args, kwargs in log_queue:
                mlog.log(*args, **kwargs)
            self.running_tasks.remove(wrap_name)
            self.completed_tasks += 1
            self.print_progress()


@dataclass(eq=False)
class Runner:
    logger: Logger
    r: InitVar[Resolver]
    wrap: PackageDefinition
    repo_dir: str
    options: 'Arguments'

    def __post_init__(self, r: Resolver) -> None:
        # FIXME: Do a copy because Resolver.resolve() is stateful method that
        # cannot be called from multiple threads.
        self.wrap_resolver = copy.copy(r)
        self.wrap_resolver.dirname = os.path.join(r.subdir_root, self.wrap.directory)
        self.wrap_resolver.wrap = self.wrap
        self.run_method: T.Callable[[], bool] = self.options.subprojects_func.__get__(self)
        self.log_queue: T.List[T.Tuple[mlog.TV_LoggableList, T.Any]] = []

    def log(self, *args: mlog.TV_Loggable, **kwargs: T.Any) -> None:
        self.log_queue.append((list(args), kwargs))

    def run(self) -> bool:
        self.logger.start(self.wrap.name)
        try:
            result = self.run_method()
        except MesonException as e:
            self.log(mlog.red('Error:'), str(e))
            result = False
        self.logger.done(self.wrap.name, self.log_queue)
        return result

    @staticmethod
    def pre_update_wrapdb(options: 'UpdateWrapDBArguments') -> None:
        options.releases = get_releases(options.allow_insecure)

    def update_wrapdb(self) -> bool:
        self.log(f'Checking latest WrapDB version for {self.wrap.name}...')
        options = T.cast('UpdateWrapDBArguments', self.options)

        # Check if this wrap is in WrapDB
        info = options.releases.get(self.wrap.name)
        if not info:
            self.log('  -> Wrap not found in wrapdb')
            return True

        # Determine current version
        try:
            wrapdb_version = self.wrap.get('wrapdb_version')
            branch, revision = wrapdb_version.split('-', 1)
        except ValueError:
            if not options.force:
                self.log('  ->', mlog.red('Malformed wrapdb_version field, use --force to update anyway'))
                return False
            branch = revision = None
        except WrapException:
            # Fallback to parsing the patch URL to determine current version.
            # This won't work for projects that have upstream Meson support.
            try:
                patch_url = self.wrap.get('patch_url')
                branch, revision = parse_patch_url(patch_url)
            except WrapException:
                if not options.force:
                    self.log('  ->', mlog.red('Could not determine current version, use --force to update anyway'))
                    return False
                branch = revision = None

        # Download latest wrap if version differs
        latest_version = info['versions'][0]
        new_branch, new_revision = latest_version.rsplit('-', 1)
        if new_branch != branch or new_revision != revision:
            filename = self.wrap.filename if self.wrap.has_wrap else f'{self.wrap.filename}.wrap'
            update_wrap_file(filename, self.wrap.name,
                             new_branch, new_revision,
                             options.allow_insecure)
            self.log('  -> New version downloaded:', mlog.blue(latest_version))
        else:
            self.log('  -> Already at latest version:', mlog.blue(latest_version))

        return True

    def update_file(self) -> bool:
        options = T.cast('UpdateArguments', self.options)
        if options.reset:
            # Delete existing directory and redownload. It is possible that nothing
            # changed but we have no way to know. Hopefully tarballs are still
            # cached.
            windows_proof_rmtree(self.repo_dir)
            try:
                self.wrap_resolver.resolve(self.wrap.name)
                self.log('  -> New version extracted')
                return True
            except WrapException as e:
                self.log('  ->', mlog.red(str(e)))
                return False
        else:
            # The subproject has not changed, or the new source and/or patch
            # tarballs should be extracted in the same directory than previous
            # version.
            self.log('  -> Subproject has not changed, or the new source/patch needs to be extracted on the same location.')
            self.log('     Pass --reset option to delete directory and redownload.')
            return False

    def git_output(self, cmd: T.List[str]) -> str:
        return quiet_git(cmd, self.repo_dir, check=True)[1]

    def git_verbose(self, cmd: T.List[str]) -> None:
        self.log(self.git_output(cmd))

    def git_stash(self) -> None:
        # That git command return some output when there is something to stash.
        # We don't want to stash when there is nothing to stash because that would
        # print spurious "No local changes to save".
        if quiet_git(['status', '--porcelain', ':!/.meson-subproject-wrap-hash.txt'], self.repo_dir)[1].strip():
            # Don't pipe stdout here because we want the user to see their changes have
            # been saved.
            # Note: `--all` is used, and not `--include-untracked`, to prevent
            # a potential error if `.meson-subproject-wrap-hash.txt` matches a
            # gitignore pattern.
            # We must add the dot in addition to the negation, because older versions of git have a bug.
            self.git_verbose(['stash', 'push', '--all', ':!/.meson-subproject-wrap-hash.txt', '.'])

    def git_show(self) -> None:
        commit_message = self.git_output(['show', '--quiet', '--pretty=format:%h%n%d%n%s%n[%an]'])
        parts = [s.strip() for s in commit_message.split('\n')]
        self.log('  ->', mlog.yellow(parts[0]), mlog.red(parts[1]), parts[2], mlog.blue(parts[3]))

    def git_rebase(self, revision: str) -> bool:
        try:
            self.git_output(['-c', 'rebase.autoStash=true', 'rebase', 'FETCH_HEAD'])
        except GitException as e:
            self.git_output(['-c', 'rebase.autoStash=true', 'rebase', '--abort'])
            self.log('  -> Could not rebase', mlog.bold(self.repo_dir), 'onto', mlog.bold(revision),
                     '-- aborted')
            self.log(mlog.red(e.output))
            self.log(mlog.red(str(e)))
            return False
        return True

    def git_reset(self, revision: str) -> bool:
        try:
            # Stash local changes, commits can always be found back in reflog, to
            # avoid any data lost by mistake.
            self.git_stash()
            self.git_output(['reset', '--hard', 'FETCH_HEAD'])
            self.wrap_resolver.apply_patch(self.wrap.name)
            self.wrap_resolver.apply_diff_files()
        except GitException as e:
            self.log('  -> Could not reset', mlog.bold(self.repo_dir), 'to', mlog.bold(revision))
            self.log(mlog.red(e.output))
            self.log(mlog.red(str(e)))
            return False
        return True

    def git_checkout(self, revision: str, create: bool = False) -> bool:
        cmd = ['checkout', '--ignore-other-worktrees']
        if create:
            cmd.append('-b')
        cmd += [revision, '--']
        try:
            # Stash local changes, commits can always be found back in reflog, to
            # avoid any data lost by mistake.
            self.git_stash()
            self.git_output(cmd)
        except GitException as e:
            self.log('  -> Could not checkout', mlog.bold(revision), 'in', mlog.bold(self.repo_dir))
            self.log(mlog.red(e.output))
            self.log(mlog.red(str(e)))
            return False
        return True

    def git_checkout_and_reset(self, revision: str) -> bool:
        # revision could be a branch that already exists but is outdated, so we still
        # have to reset after the checkout.
        success = self.git_checkout(revision)
        if success:
            success = self.git_reset(revision)
        return success

    def git_checkout_and_rebase(self, revision: str) -> bool:
        # revision could be a branch that already exists but is outdated, so we still
        # have to rebase after the checkout.
        success = self.git_checkout(revision)
        if success:
            success = self.git_rebase(revision)
        return success

    def git_branch_has_upstream(self, urls: set) -> bool:
        cmd = ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}']
        ret, upstream = quiet_git(cmd, self.repo_dir)
        if not ret:
            return False
        try:
            remote = upstream.split('/', maxsplit=1)[0]
        except IndexError:
            return False
        cmd = ['remote', 'get-url', remote]
        ret, remote_url = quiet_git(cmd, self.repo_dir)
        return remote_url.strip() in urls

    def update_git(self) -> bool:
        options = T.cast('UpdateArguments', self.options)
        if not os.path.exists(os.path.join(self.repo_dir, '.git')):
            if options.reset:
                # Delete existing directory and redownload
                windows_proof_rmtree(self.repo_dir)
                try:
                    self.wrap_resolver.resolve(self.wrap.name)
                    self.update_git_done()
                    return True
                except WrapException as e:
                    self.log('  ->', mlog.red(str(e)))
                    return False
            else:
                self.log('  -> Not a git repository.')
                self.log('Pass --reset option to delete directory and redownload.')
                return False
        revision = self.wrap.values.get('revision')
        url = self.wrap.values.get('url')
        push_url = self.wrap.values.get('push-url')
        if not revision or not url:
            # It could be a detached git submodule for example.
            self.log('  -> No revision or URL specified.')
            return True
        try:
            origin_url = self.git_output(['remote', 'get-url', 'origin']).strip()
        except GitException as e:
            self.log('  -> Failed to determine current origin URL in', mlog.bold(self.repo_dir))
            self.log(mlog.red(e.output))
            self.log(mlog.red(str(e)))
            return False
        if options.reset:
            try:
                self.git_output(['remote', 'set-url', 'origin', url])
                if push_url:
                    self.git_output(['remote', 'set-url', '--push', 'origin', push_url])
            except GitException as e:
                self.log('  -> Failed to reset origin URL in', mlog.bold(self.repo_dir))
                self.log(mlog.red(e.output))
                self.log(mlog.red(str(e)))
                return False
        elif url != origin_url:
            self.log(f'  -> URL changed from {origin_url!r} to {url!r}')
            return False
        try:
            # Same as `git branch --show-current` but compatible with older git version
            branch = self.git_output(['rev-parse', '--abbrev-ref', 'HEAD']).strip()
            branch = branch if branch != 'HEAD' else ''
        except GitException as e:
            self.log('  -> Failed to determine current branch in', mlog.bold(self.repo_dir))
            self.log(mlog.red(e.output))
            self.log(mlog.red(str(e)))
            return False
        if self.wrap_resolver.is_git_full_commit_id(revision) and \
                quiet_git(['rev-parse', '--verify', revision + '^{commit}'], self.repo_dir)[0]:
            # The revision we need is both a commit and available. So we do not
            # need to fetch it because it cannot be updated.  Instead, trick
            # git into setting FETCH_HEAD just in case, from the local commit.
            self.git_output(['fetch', '.', revision])
        else:
            try:
                # Fetch only the revision we need, this avoids fetching useless branches.
                # revision can be either a branch, tag or commit id. In all cases we want
                # FETCH_HEAD to be set to the desired commit and "git checkout <revision>"
                # to to either switch to existing/new branch, or detach to tag/commit.
                # It is more complicated than it first appear, see discussion there:
                # https://github.com/mesonbuild/meson/pull/7723#discussion_r488816189.
                heads_refmap = '+refs/heads/*:refs/remotes/origin/*'
                tags_refmap = '+refs/tags/*:refs/tags/*'
                self.git_output(['fetch', '--refmap', heads_refmap, '--refmap', tags_refmap, 'origin', revision])
            except GitException as e:
                self.log('  -> Could not fetch revision', mlog.bold(revision), 'in', mlog.bold(self.repo_dir))
                self.log(mlog.red(e.output))
                self.log(mlog.red(str(e)))
                return False

        if branch == '':
            # We are currently in detached mode
            if options.reset:
                success = self.git_checkout_and_reset(revision)
            else:
                success = self.git_checkout_and_rebase(revision)
        elif branch == revision:
            # We are in the same branch. A reset could still be needed in the case
            # a force push happened on remote repository.
            if options.reset:
                success = self.git_reset(revision)
            else:
                success = self.git_rebase(revision)
        else:
            # We are in another branch, either the user created their own branch and
            # we should rebase it, or revision changed in the wrap file (we
            # know this when the current branch has an upstream) and we need to
            # checkout the new branch.
            if options.reset:
                success = self.git_checkout_and_reset(revision)
            else:
                if self.git_branch_has_upstream({url, push_url}):
                    success = self.git_checkout_and_rebase(revision)
                else:
                    success = self.git_rebase(revision)
        if success:
            self.update_git_done()
        return success

    def update_git_done(self) -> None:
        self.git_output(['submodule', 'update', '--checkout', '--recursive'])
        self.git_show()

    def update_hg(self) -> bool:
        revno = self.wrap.get('revision')
        if revno.lower() == 'tip':
            # Failure to do pull is not a fatal error,
            # because otherwise you can't develop without
            # a working net connection.
            subprocess.call(['hg', 'pull'], cwd=self.repo_dir)
        else:
            if subprocess.call(['hg', 'checkout', revno], cwd=self.repo_dir) != 0:
                subprocess.check_call(['hg', 'pull'], cwd=self.repo_dir)
                subprocess.check_call(['hg', 'checkout', revno], cwd=self.repo_dir)
        return True

    def update_svn(self) -> bool:
        revno = self.wrap.get('revision')
        _, out, _ = Popen_safe(['svn', 'info', '--show-item', 'revision', self.repo_dir])
        current_revno = out
        if current_revno == revno:
            return True
        if revno.lower() == 'head':
            # Failure to do pull is not a fatal error,
            # because otherwise you can't develop without
            # a working net connection.
            subprocess.call(['svn', 'update'], cwd=self.repo_dir)
        else:
            subprocess.check_call(['svn', 'update', '-r', revno], cwd=self.repo_dir)
        return True

    def update(self) -> bool:
        self.log(f'Updating {self.wrap.name}...')
        success = False
        if not os.path.isdir(self.repo_dir):
            self.log('  -> Not used.')
            # It is not an error if we are updating all subprojects.
            success = not self.options.subprojects
        elif self.wrap.type == 'file':
            success = self.update_file()
        elif self.wrap.type == 'git':
            success = self.update_git()
        elif self.wrap.type == 'hg':
            success = self.update_hg()
        elif self.wrap.type == 'svn':
            success = self.update_svn()
        elif self.wrap.type is None:
            self.log('  -> Cannot update subproject with no wrap file')
            # It is not an error if we are updating all subprojects.
            success = not self.options.subprojects
        else:
            self.log('  -> Cannot update', self.wrap.type, 'subproject')
        if success and os.path.isdir(self.repo_dir):
            self.wrap.update_hash_cache(self.repo_dir)
        return success

    def checkout(self) -> bool:
        options = T.cast('CheckoutArguments', self.options)

        if self.wrap.type != 'git' or not os.path.isdir(self.repo_dir):
            return True
        branch_name = options.branch_name if options.branch_name else self.wrap.get('revision')
        if not branch_name:
            # It could be a detached git submodule for example.
            return True
        self.log(f'Checkout {branch_name} in {self.wrap.name}...')
        if self.git_checkout(branch_name, create=options.b):
            self.git_show()
            return True
        return False

    def download(self) -> bool:
        self.log(f'Download {self.wrap.name}...')
        if os.path.isdir(self.repo_dir):
            self.log('  -> Already downloaded')
            return True
        try:
            self.wrap_resolver.resolve(self.wrap.name)
            self.log('  -> done')
        except WrapException as e:
            self.log('  ->', mlog.red(str(e)))
            return False
        return True

    def foreach(self) -> bool:
        options = T.cast('ForeachArguments', self.options)

        self.log(f'Executing command in {self.repo_dir}')
        if not os.path.isdir(self.repo_dir):
            self.log('  -> Not downloaded yet')
            return True
        cmd = [options.command] + options.args
        p, out, _ = Popen_safe(cmd, stderr=subprocess.STDOUT, cwd=self.repo_dir)
        if p.returncode != 0:
            err_message = "Command '{}' returned non-zero exit status {}.".format(" ".join(cmd), p.returncode)
            self.log('  -> ', mlog.red(err_message))
            self.log(out, end='')
            return False

        self.log(out, end='')
        return True

    def purge(self) -> bool:
        options = T.cast('PurgeArguments', self.options)

        # if subproject is not wrap-based, then don't remove it
        if not self.wrap.type:
            return True

        if self.wrap.redirected:
            redirect_file = Path(self.wrap.original_filename).resolve()
            if options.confirm:
                redirect_file.unlink()
            mlog.log(f'Deleting {redirect_file}')

        if self.wrap.type == 'redirect':
            redirect_file = Path(self.wrap.filename).resolve()
            if options.confirm:
                redirect_file.unlink()
            self.log(f'Deleting {redirect_file}')

        if options.include_cache:
            packagecache = Path(self.wrap_resolver.cachedir).resolve()
            try:
                subproject_cache_file = packagecache / self.wrap.get("source_filename")
                if subproject_cache_file.is_file():
                    if options.confirm:
                        subproject_cache_file.unlink()
                    self.log(f'Deleting {subproject_cache_file}')
            except WrapException:
                pass

            try:
                subproject_patch_file = packagecache / self.wrap.get("patch_filename")
                if subproject_patch_file.is_file():
                    if options.confirm:
                        subproject_patch_file.unlink()
                    self.log(f'Deleting {subproject_patch_file}')
            except WrapException:
                pass

            # Don't log that we will remove an empty directory. Since purge is
            # parallelized, another thread could have deleted it already.
            try:
                if not any(packagecache.iterdir()):
                    windows_proof_rmtree(str(packagecache))
            except FileNotFoundError:
                pass

        # NOTE: Do not use .resolve() here; the subproject directory may be a symlink
        subproject_source_dir = Path(self.repo_dir)
        # Resolve just the parent, just to print out the full path
        subproject_source_dir = subproject_source_dir.parent.resolve() / subproject_source_dir.name

        # Don't follow symlink. This is covered by the next if statement, but why
        # not be doubly sure.
        if subproject_source_dir.is_symlink():
            if options.confirm:
                subproject_source_dir.unlink()
            self.log(f'Deleting {subproject_source_dir}')
            return True
        if not subproject_source_dir.is_dir():
            return True

        try:
            if options.confirm:
                windows_proof_rmtree(str(subproject_source_dir))
            self.log(f'Deleting {subproject_source_dir}')
        except OSError as e:
            mlog.error(f'Unable to remove: {subproject_source_dir}: {e}')
            return False

        return True

    @staticmethod
    def post_purge(options: 'PurgeArguments') -> None:
        if not options.confirm:
            mlog.log('')
            mlog.log('Nothing has been deleted, run again with --confirm to apply.')

    def packagefiles(self) -> bool:
        options = T.cast('PackagefilesArguments', self.options)

        if options.apply and options.save:
            # not quite so nice as argparse failure
            print('error: --apply and --save are mutually exclusive')
            return False
        if options.apply:
            self.log(f'Re-applying patchfiles overlay for {self.wrap.name}...')
            if not os.path.isdir(self.repo_dir):
                self.log('  -> Not downloaded yet')
                return True
            self.wrap_resolver.apply_patch(self.wrap.name)
            return True
        if options.save:
            if 'patch_directory' not in self.wrap.values:
                mlog.error('can only save packagefiles to patch_directory')
                return False
            if 'source_filename' not in self.wrap.values:
                mlog.error('can only save packagefiles from a [wrap-file]')
                return False
            archive_path = Path(self.wrap_resolver.cachedir, self.wrap.values['source_filename'])
            lead_directory_missing = bool(self.wrap.values.get('lead_directory_missing', False))
            directory = Path(self.repo_dir)
            packagefiles = Path(self.wrap.filesdir, self.wrap.values['patch_directory'])

            base_path = directory if lead_directory_missing else directory.parent
            archive_files = read_archive_files(archive_path, base_path)
            directory_files = set(directory.glob('**/*'))

            self.log(f'Saving {self.wrap.name} to {packagefiles}...')
            shutil.rmtree(packagefiles)
            for src_path in directory_files - archive_files:
                if not src_path.is_file():
                    continue
                rel_path = src_path.relative_to(directory)
                dst_path = packagefiles / rel_path
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src_path, dst_path)
        return True


def add_common_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument('--sourcedir', default='.',
                   help='Path to source directory')
    p.add_argument('--types', default='',
                   help=f'Comma-separated list of subproject types. Supported types are: {ALL_TYPES_STRING} (default: all)')
    p.add_argument('-j', '--num-processes', default=None, type=int,
                   help='How many parallel processes to use (Since 0.59.0).')
    p.add_argument('--allow-insecure', default=False, action='store_true',
                   help='Allow insecure server connections.')

def add_subprojects_argument(p: argparse.ArgumentParser) -> None:
    p.add_argument('subprojects', nargs='*',
                   help='List of subprojects (default: all)')

def add_wrap_update_parser(subparsers: 'SubParsers') -> argparse.ArgumentParser:
    p = subparsers.add_parser('update', help='Update wrap files from WrapDB (Since 0.63.0)')
    p.add_argument('--force', default=False, action='store_true',
                   help='Update wraps that does not seems to come from WrapDB')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.set_defaults(subprojects_func=Runner.update_wrapdb)
    p.set_defaults(pre_func=Runner.pre_update_wrapdb)
    return p

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(title='Commands', dest='command')
    subparsers.required = True

    p = subparsers.add_parser('update', help='Update all subprojects from wrap files')
    p.add_argument('--rebase', default=True, action='store_true',
                   help='Rebase your branch on top of wrap\'s revision. ' +
                        'Deprecated, it is now the default behaviour. (git only)')
    p.add_argument('--reset', default=False, action='store_true',
                   help='Checkout wrap\'s revision and hard reset to that commit. (git only)')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.set_defaults(subprojects_func=Runner.update)

    p = subparsers.add_parser('checkout', help='Checkout a branch (git only)')
    p.add_argument('-b', default=False, action='store_true',
                   help='Create a new branch')
    p.add_argument('branch_name', nargs='?',
                   help='Name of the branch to checkout or create (default: revision set in wrap file)')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.set_defaults(subprojects_func=Runner.checkout)

    p = subparsers.add_parser('download', help='Ensure subprojects are fetched, even if not in use. ' +
                                               'Already downloaded subprojects are not modified. ' +
                                               'This can be used to pre-fetch all subprojects and avoid downloads during configure.')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.set_defaults(subprojects_func=Runner.download)

    p = subparsers.add_parser('foreach', help='Execute a command in each subproject directory.')
    p.add_argument('command', metavar='command ...',
                   help='Command to execute in each subproject directory')
    p.add_argument('args', nargs=argparse.REMAINDER,
                   help=argparse.SUPPRESS)
    add_common_arguments(p)
    p.set_defaults(subprojects=[])
    p.set_defaults(subprojects_func=Runner.foreach)

    p = subparsers.add_parser('purge', help='Remove all wrap-based subproject artifacts')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.add_argument('--include-cache', action='store_true', default=False, help='Remove the package cache as well')
    p.add_argument('--confirm', action='store_true', default=False, help='Confirm the removal of subproject artifacts')
    p.set_defaults(subprojects_func=Runner.purge)
    p.set_defaults(post_func=Runner.post_purge)

    p = subparsers.add_parser('packagefiles', help='Manage the packagefiles overlay')
    add_common_arguments(p)
    add_subprojects_argument(p)
    p.add_argument('--apply', action='store_true', default=False, help='Apply packagefiles to the subproject')
    p.add_argument('--save', action='store_true', default=False, help='Save packagefiles from the subproject')
    p.set_defaults(subprojects_func=Runner.packagefiles)

def run(options: 'Arguments') -> int:
    source_dir = os.path.relpath(os.path.realpath(options.sourcedir))
    if not os.path.isfile(os.path.join(source_dir, 'meson.build')):
        mlog.error('Directory', mlog.bold(source_dir), 'does not seem to be a Meson source directory.')
        return 1
    with mlog.no_logging():
        intr = IntrospectionInterpreter(source_dir, '', 'none')
        intr.load_root_meson_file()
        subproject_dir = intr.extract_subproject_dir() or 'subprojects'
    if not os.path.isdir(os.path.join(source_dir, subproject_dir)):
        mlog.log('Directory', mlog.bold(source_dir), 'does not seem to have subprojects.')
        return 0
    r = Resolver(source_dir, subproject_dir, wrap_frontend=True, allow_insecure=options.allow_insecure, silent=True)
    if options.subprojects:
        wraps = [wrap for name, wrap in r.wraps.items() if name in options.subprojects]
    else:
        wraps = list(r.wraps.values())
    types = [t.strip() for t in options.types.split(',')] if options.types else []
    for t in types:
        if t not in ALL_TYPES:
            raise MesonException(f'Unknown subproject type {t!r}, supported types are: {ALL_TYPES_STRING}')
    tasks: T.List[T.Awaitable[bool]] = []
    task_names: T.List[str] = []
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    executor = ThreadPoolExecutor(options.num_processes)
    if types:
        wraps = [wrap for wrap in wraps if wrap.type in types]
    pre_func = getattr(options, 'pre_func', None)
    if pre_func:
        pre_func(options)
    logger = Logger(len(wraps))
    for wrap in wraps:
        dirname = Path(source_dir, subproject_dir, wrap.directory).as_posix()
        runner = Runn
"""


```