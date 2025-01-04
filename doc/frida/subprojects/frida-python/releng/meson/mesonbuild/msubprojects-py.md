Response:
The user wants to understand the functionality of the Python script `msubprojects.py` which is part of the Frida dynamic instrumentation tool. I need to analyze the code and summarize its capabilities, focusing on aspects relevant to reverse engineering, low-level operations, kernel/framework interactions, logical reasoning, common user errors, and debugging.

**Plan:**

1. **High-Level Functionality:** Identify the main purpose of the script based on its imports, class names, and function definitions.
2. **Reverse Engineering Relevance:** Look for actions like patching, updating, downloading, or manipulating code that are commonly used in reverse engineering workflows.
3. **Low-Level/Kernel/Framework Aspects:**  Detect any operations that interact with the operating system, file system, Git, or potentially system-level components (though this script seems more focused on managing subprojects).
4. **Logical Reasoning:**  Analyze functions that involve conditional logic or decision-making based on input or state.
5. **User Errors:** Identify scenarios where incorrect user input or actions could lead to errors.
6. **User Operation Trace:** Deduce how a user might interact with Frida to trigger the execution of this script.
7. **Summarization:**  Provide a concise summary of the script's functions based on the analysis.
这是 `frida/subprojects/frida-python/releng/meson/mesonbuild/msubprojects.py` 文件的源代码，它是一个用于管理 Frida 项目的子项目（subprojects）的工具。 这个脚本使用 Meson 构建系统，并提供了一系列命令来操作和维护项目依赖的外部代码。

**功能归纳:**

这个 Python 脚本的主要功能是自动化管理 Frida 项目依赖的外部子项目，这些子项目通常以 Git 仓库、Mercurial 仓库、Subversion 仓库或压缩包的形式存在。 具体来说，它提供了以下核心功能：

1. **更新 (update):**  用于更新子项目的源代码。可以根据 `.wrap` 文件的配置，从指定的 URL 下载或更新代码仓库。对于 Git 仓库，还可以选择 `rebase` 或 `reset` 本地修改。
2. **更新 WrapDB (update wrap):** 从 WrapDB 仓库更新 `.wrap` 文件本身，以获取最新的子项目信息和版本。
3. **检出 (checkout):**  对于 Git 子项目，允许检出特定的分支或标签。
4. **下载 (download):**  确保子项目已被下载到本地，即使当前没有被使用。这可以用于提前下载所有依赖，避免在配置构建时进行下载。
5. **遍历执行 (foreach):**  在一个或多个子项目的目录下执行指定的命令。
6. **清理 (purge):**  删除子项目的源代码目录以及相关的缓存文件。
7. **管理补丁文件 (packagefiles):**  用于应用或保存子项目中的补丁文件。

接下来，我将针对你提出的具体问题进行更详细的说明：

**与逆向的方法的关系举例:**

*   **更新依赖库:** 在逆向工程中，Frida 经常需要与各种库进行交互。例如，可能需要更新某个用于解析特定文件格式的第三方库。 使用 `python meson/mesonbuild/msubprojects.py update <子项目名称>` 可以确保 Frida 使用的是最新版本的依赖库，这对于分析新版本软件或修复已知问题非常重要。
*   **检出特定版本:** 如果发现某个 Frida 版本在与特定版本的逆向目标交互时存在问题，可能需要回退到旧版本的依赖库。使用 `python meson/mesonbuild/msubprojects.py checkout -- <子项目名称> <版本号/分支名>` 可以检出特定版本的依赖库进行调试或测试。
*   **应用自定义补丁:**  逆向工程师可能需要修改依赖库的源代码来添加调试信息或修复 Bug。  `packagefiles` 命令可以用来保存这些修改，或者在清理后重新应用这些自定义的补丁。

**涉及到二进制底层、Linux、Android 内核及框架的知识的举例:**

虽然这个脚本本身主要是对源代码进行管理，但其操作的对象往往与底层知识紧密相关：

*   **Git 操作 (update, checkout):**  脚本中大量使用了 Git 命令来管理子项目，这涉及到对 Git 版本控制系统的理解，包括分支、标签、提交、远程仓库等概念。  在 Frida 的开发中，子项目可能是某些底层的库，例如用于处理特定架构指令集的库。
*   **文件操作 (purge, download):**  脚本需要创建、删除文件和目录，这涉及到操作系统层面的文件系统操作。 被管理的子项目可能包含与操作系统或内核交互的代码。
*   **`.wrap` 文件配置:**  `.wrap` 文件中会指定子项目的类型 (git, file, hg, svn)，以及下载地址、版本号等信息。  这些信息可能指向包含底层代码的仓库或压缩包。
*   **`foreach` 命令:**  用户可以使用 `foreach` 命令在子项目的目录下执行任意命令，这可以用于编译子项目、运行测试，或者执行与底层相关的操作。 例如，可以在某个包含 Linux 内核模块的子项目目录下使用 `make` 命令进行编译。
*   **`packagefiles` 命令:**  保存或应用补丁文件，可能涉及到对二进制文件的修改或对底层库的调整。

**逻辑推理的假设输入与输出:**

假设当前 Frida 项目的 `subprojects` 目录下有一个名为 `boringssl` 的 Git 子项目，其 `.wrap` 文件中指定的 `revision` 为 `master`。

**场景 1:  执行 `update boringssl`**

*   **假设输入:**
    *   当前 `boringssl` 子项目已存在，并且是一个 Git 仓库。
    *   远程 `boringssl` 仓库的 `master` 分支有新的提交。
*   **逻辑推理:**
    *   脚本会尝试切换到 `boringssl` 目录。
    *   执行 `git fetch origin master` 获取远程更新。
    *   如果配置了 `rebase` (默认情况)，会执行 `git rebase FETCH_HEAD` 将本地修改变基到最新的远程 `master` 分支。
    *   如果配置了 `reset`，会执行 `git reset --hard FETCH_HEAD` 丢弃本地修改，强制同步到远程 `master` 分支。
*   **可能输出:**  显示 Git 操作的输出，例如 "Updating from ...", "Fast-forward", 或 "Successfully rebased..."。

**场景 2: 执行 `checkout -b develop boringssl`**

*   **假设输入:**
    *   当前 `boringssl` 子项目是一个 Git 仓库。
    *   本地不存在名为 `develop` 的分支。
*   **逻辑推理:**
    *   脚本会尝试切换到 `boringssl` 目录。
    *   执行 `git checkout -b develop master` (假设 `.wrap` 文件中 `revision` 为 `master`)，基于 `master` 分支创建一个新的 `develop` 分支并切换过去。
*   **可能输出:** 显示 Git 操作的输出，例如 "Switched to a new branch 'develop'"。

**涉及用户或者编程常见的使用错误举例:**

*   **网络问题:** 如果在执行 `update` 或 `download` 命令时网络连接中断，会导致下载失败。 脚本会打印错误信息，提示连接问题。
*   **错误的子项目名称:** 如果用户输入的子项目名称在 `.wrap` 文件中不存在，脚本会找不到对应的子项目并报错。
*   **Git 冲突:** 在执行 `update` 且使用 `rebase` 时，如果本地修改与远程更新存在冲突，会导致 rebase 失败。脚本会提示用户手动解决冲突。
*   **权限问题:**  如果用户对子项目目录或缓存目录没有写入权限，会导致更新、下载或清理操作失败。
*   **错误的命令参数:**  例如，在 `foreach` 命令中提供了错误的命令或参数，会导致命令执行失败。脚本会显示命令的错误输出。
*   **在非 Frida 项目目录下执行:** 如果在没有 `meson.build` 文件的目录下执行此脚本，会报错，提示不是 Meson 源代码目录。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在开发或调试 Frida 时，需要更新某个依赖的子项目 `capstone`。

1. **用户打开终端或命令提示符。**
2. **用户导航到 Frida 的源代码根目录。**  （该目录下应该包含 `meson.build` 文件）
3. **用户执行命令:** `python meson/mesonbuild/msubprojects.py update capstone`
    *   `python`:  调用 Python 解释器。
    *   `meson/mesonbuild/msubprojects.py`:  指定要执行的脚本路径。
    *   `update`:  指定要执行的子命令，表示更新子项目。
    *   `capstone`:  指定要更新的子项目名称。

如果用户遇到与 `capstone` 子项目相关的问题，例如编译错误或运行时异常，他们可能会使用这个脚本来：

*   **更新到最新版本:** 尝试使用最新版本的 `capstone` 解决问题。
*   **回退到旧版本:** 如果新版本引入了问题，尝试回退到之前工作的版本。
*   **查看当前版本:** 通过查看 `capstone` 目录下的 Git 日志来确认当前使用的版本。
*   **清理并重新下载:**  如果怀疑本地代码损坏，可以先使用 `purge` 清理 `capstone`，然后再使用 `download` 重新下载。

**总结它的功能:**

`frida/subprojects/frida-python/releng/meson/mesonbuild/msubprojects.py` 脚本是 Frida 构建系统的一个重要组成部分，其主要功能是 **自动化管理 Frida 项目的外部依赖子项目**。 它提供了一组命令，允许开发者方便地更新、检出、下载、清理和管理这些子项目的源代码，并支持 Git、Mercurial、Subversion 和本地文件等多种子项目类型。 这个工具简化了 Frida 依赖管理的流程，提高了开发效率，并有助于确保 Frida 项目能够使用正确版本的依赖库。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/msubprojects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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