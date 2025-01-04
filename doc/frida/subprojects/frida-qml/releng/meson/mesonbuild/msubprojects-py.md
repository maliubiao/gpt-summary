Response:
The user wants a summary of the functionality of the provided Python code. I need to analyze the code and identify the main tasks it performs. The code seems to manage subprojects within a larger project, likely using 'wrap' files to describe them. Keywords like 'update', 'checkout', 'download', 'purge', 'packagefiles', and the presence of git/hg/svn commands suggest this is about managing the source code of these subprojects.

I also need to address specific aspects:
- **Relation to reverse engineering:**  Consider if any actions like 'downloading' or 'updating' subproject code can be related to obtaining targets for reverse engineering.
- **Binary/kernel knowledge:**  Look for interactions with the file system, execution of external commands (especially version control), and any mentions of operating system specifics (Linux, Android).
- **Logical reasoning:**  Identify any conditional logic where inputs lead to specific outputs.
- **Common user errors:**  Think about what mistakes a user might make when using such a tool.
- **User journey:**  Trace how a user might end up executing this specific code.

Let's break down the code's functionality:

1. **Core Structure:** It defines a `Runner` class that encapsulates actions on individual subprojects. It uses an argument parser to handle different commands.
2. **Subproject Management:**  The code manages the lifecycle of subprojects, including:
    - Downloading subproject source code.
    - Updating subproject source code to a specific revision.
    - Checking out different branches or revisions.
    - Removing subproject artifacts.
3. **Wrap File Handling:** It interacts with 'wrap' files, which seem to define the source and version of subprojects. It can update these wrap files from a central database.
4. **Version Control:** It supports Git, Mercurial (hg), and Subversion (svn) for managing subproject repositories.
5. **Patching:** It can apply and save patch files to subprojects.
6. **Command Execution:** It allows executing arbitrary commands within subproject directories.

Now, let's consider the specific points raised in the prompt.
这是 `fridaDynamic instrumentation tool` 中负责管理子项目 (`subprojects`) 的 Python 模块，位于 `frida/subprojects/frida-qml/releng/meson/mesonbuild/msubprojects.py`。其主要功能是提供一系列命令来管理项目中包含的外部依赖或子模块，这些子模块通常通过 "wrap" 文件进行描述。

**主要功能归纳：**

1. **子项目生命周期管理:**  该模块提供了一套完整的工具来管理子项目的生命周期，包括下载、更新、检出特定版本、删除等操作。
2. **Wrap 文件处理:**  核心功能围绕 "wrap" 文件展开，这些文件定义了子项目的来源（如 Git 仓库、HTTP 下载链接等）和版本信息。模块能够读取、更新和操作这些 wrap 文件。
3. **版本控制集成:**  支持多种版本控制系统（Git, Mercurial, Subversion），可以根据 wrap 文件中的信息进行仓库的克隆、更新、检出分支/版本等操作。
4. **补丁管理:**  允许应用和保存针对子项目的补丁文件。
5. **自定义命令执行:**  可以在每个子项目的目录下执行用户指定的任意命令。

**与其他方面的关联：**

**与逆向的方法的关系：**

* **获取目标代码:**  `download` 和 `update` 功能可以被视为获取目标二进制代码的一种方式。在逆向工程中，首先需要获取目标软件或库的二进制文件。通过这个模块，可以方便地下载或更新项目依赖的第三方库的源代码，虽然不是直接获取二进制，但源代码往往是理解二进制行为的基础。
    * **举例说明:**  假设 Frida 依赖于某个开源库 `libuv`，其 wrap 文件指定了 `libuv` 的 Git 仓库地址和特定的 commit 版本。逆向工程师可能需要分析特定版本的 `libuv` 的代码，那么可以使用该模块的 `download` 命令将 `libuv` 的源代码下载到本地。

**涉及二进制底层，Linux, Android 内核及框架的知识：**

* **文件系统操作:**  代码中大量使用了 `os` 和 `shutil` 模块进行文件和目录操作，例如创建目录、删除目录、复制文件等。这些是与底层文件系统交互的基础。
    * **举例说明:**  在 `download` 功能中，代码会根据 wrap 文件指定的 URL 下载压缩包，并解压到指定的目录。这涉及到文件的创建、写入和目录的创建等底层操作。
* **进程管理和外部命令执行:**  代码使用 `subprocess` 模块来执行外部命令，例如 `git`, `hg`, `svn` 命令。这些命令直接与操作系统交互，进行版本控制操作。
    * **举例说明:**  在 `update_git` 功能中，代码会执行 `git fetch`, `git checkout`, `git rebase` 等命令。这些命令直接操作 Git 仓库，涉及到 Git 的底层实现。 虽然代码本身没有直接涉及 Linux 或 Android 内核，但它管理的子项目很可能包含与这些平台相关的代码。
* **压缩包处理:**  代码使用 `tarfile` 和 `zipfile` 模块处理常见的压缩包格式。这在下载和解压子项目源代码时非常关键。
    * **举例说明:**  如果 wrap 文件指定的子项目是以 `.tar.gz` 格式提供的，那么 `read_archive_files` 函数会使用 `tarfile` 模块来读取其中的文件列表。

**逻辑推理：**

* **假设输入:** 用户执行命令 `python msubprojects.py update --sourcedir /path/to/frida -j 4 libuv`
* **输出:**  代码会首先检查 `/path/to/frida` 是否是 Meson 项目，然后查找名为 `libuv` 的子项目的 wrap 文件。如果找到，并且类型是 Git，则会尝试更新 `libuv` 子项目的 Git 仓库，使用 4 个并行进程加速处理。日志会显示更新的进度和结果。

* **假设输入:** 用户执行命令 `python msubprojects.py purge --confirm libssl`
* **输出:** 代码会找到 `libssl` 的 wrap 文件，并尝试删除 `libssl` 子项目相关的源代码目录和缓存文件。由于使用了 `--confirm` 参数，实际会执行删除操作，并在日志中输出删除的文件和目录。

**涉及用户或者编程常见的使用错误：**

* **错误的子项目名称:** 用户在命令行中输入的子项目名称与 wrap 文件中定义的名称不一致。
    * **举例说明:**  用户输入 `python msubprojects.py update OpenSSL`，但 wrap 文件中定义的名称可能是 `openssl` 或 `libopenssl`，导致找不到对应的子项目。
* **网络问题:**  在下载或更新子项目时，如果网络连接不稳定或无法访问 wrap 文件中指定的 URL 或版本控制仓库，会导致操作失败。
    * **举例说明:**  用户尝试更新一个 Git 子项目，但由于网络问题，无法连接到远程 Git 仓库。
* **权限问题:**  在执行某些操作时，例如删除目录或文件，可能由于用户权限不足而失败。
    * **举例说明:**  用户尝试使用 `purge` 命令删除子项目目录，但当前用户没有删除该目录的权限。
* **Git 操作冲突:**  在更新 Git 子项目时，如果本地修改与远程仓库的更新存在冲突，可能会导致 rebase 或 reset 操作失败。
    * **举例说明:**  用户在本地修改了某个 Git 子项目的文件，然后执行 `update` 命令，如果远程仓库的最新版本也修改了相同的文件，就会产生冲突。
* **使用了互斥的参数:** 某些命令的参数是互斥的，例如 `packagefiles` 命令中的 `--apply` 和 `--save`。
    * **举例说明:** 用户同时使用 `--apply` 和 `--save` 参数运行 `packagefiles` 命令，会导致程序报错并提示参数互斥。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 项目的开发或维护者需要管理项目的依赖关系。** Frida 作为一个复杂的动态 instrumentation 工具，通常会依赖于多个外部库或组件。
2. **Frida 使用 Meson 构建系统。** Meson 提供了一套机制来管理子项目，而这个 `msubprojects.py` 脚本就是 Meson 构建系统中用于管理 wrap 文件的工具。
3. **开发人员想要更新某个特定的子项目。** 例如，他们可能发现了某个依赖库的新版本，或者需要修复某个依赖库中的 bug。
4. **开发人员进入 Frida 项目的源代码根目录。**  这是执行 `msubprojects.py` 脚本的上下文。
5. **开发人员使用命令行工具，并执行 `msubprojects.py` 脚本，并带上相应的命令和参数。**  例如，`python subprojects/frida-qml/releng/meson/mesonbuild/msubprojects.py update libuv`。
6. **`msubprojects.py` 脚本被执行，并根据用户提供的命令和参数，调用相应的函数来执行子项目管理操作。**  例如，如果用户执行的是 `update` 命令，并且指定了 `libuv` 子项目，那么会调用 `Runner.update` 方法，并根据 `libuv` 的 wrap 文件信息进行更新操作。

这个脚本的主要目的是为了简化和自动化管理 Meson 项目中的子项目，确保所有开发人员使用相同版本的依赖，并方便地进行依赖更新和维护。它在 Frida 的构建和开发流程中扮演着重要的角色。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/msubprojects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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