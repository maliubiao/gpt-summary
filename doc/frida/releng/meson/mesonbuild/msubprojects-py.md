Response:
Let's break down the thought process for analyzing this Python code and generating the requested information.

**1. Initial Understanding & Goal:**

The core task is to analyze a specific Python file (`msubprojects.py`) from the Frida project, focusing on its functionality, relevance to reverse engineering, low-level interactions, logic, potential errors, and user interaction. The prompt also explicitly asks for a summary of its function.

**2. High-Level Overview (Skimming):**

The first step is to quickly skim the code to get a general idea of its purpose. Keywords like `argparse`, `Resolver`, `WrapException`, `git`, `hg`, `svn`, `tarfile`, `zipfile`, and the various command names (`update`, `checkout`, `download`, `purge`) immediately suggest this file is about managing external dependencies or "subprojects" within a larger build system (likely Meson, given the file path). The presence of `frida` in the path confirms this is related to Frida's build process.

**3. Identifying Key Components and Data Structures:**

* **`dataclass Runner`:** This is a central class. It seems to encapsulate the logic for performing operations on individual subprojects. The fields like `logger`, `wrap_resolver`, `wrap`, `repo_dir`, and `options` are important.
* **`dataclass Logger`:**  Manages the display of progress and logging information.
* **`argparse`:** Used for parsing command-line arguments, indicating this script is likely executed as a standalone tool.
* **`Resolver`:**  Likely responsible for finding and downloading/extracting subproject sources.
* **`WrapException`:**  Indicates errors related to the "wrap" system (which seems to be the mechanism for managing subprojects).
* **Version Control Interactions (`git`, `hg`, `svn`):**  The code has specific functions for interacting with these version control systems, suggesting subprojects can be managed via these.
* **Archive Handling (`tarfile`, `zipfile`):**  Indicates subprojects might be distributed as archives.

**4. Analyzing Functionality (Method by Method):**

Now, go through the `Runner` class methods and the main `run` function more carefully:

* **`Logger` methods (`start`, `done`, `print_progress`):**  Focus on the progress tracking and logging aspects.
* **`Runner` methods:** Analyze each method's purpose based on its name and the operations it performs. For example, `update_wrapdb` clearly interacts with a "WrapDB," `update_git` handles Git repositories, `purge` removes subproject files, etc. Pay attention to the arguments and how they influence the behavior.
* **`add_arguments` and related functions:**  These define the command-line interface of the script. List the available commands and their options.
* **`run` function:**  This is the entry point. Understand how it initializes the `Resolver`, determines the list of subprojects to process, and creates `Runner` instances. The use of `asyncio` and `ThreadPoolExecutor` indicates parallel processing.

**5. Connecting to Reverse Engineering:**

At this point, start thinking about how this functionality relates to reverse engineering:

* **Dependency Management:** Reverse engineering often involves dealing with complex software that has dependencies. This script helps manage those dependencies for Frida itself. Think of examples: Frida might depend on a specific version of a library for instrumentation.
* **Source Code Access:** Being able to fetch and update the source code of dependencies is crucial for understanding how Frida works internally and how it interacts with target processes.
* **Patching and Modification:** The `packagefiles` functionality and the Git-related operations suggest the ability to apply and manage patches to subprojects, which is relevant for customizing or debugging Frida.

**6. Identifying Low-Level Interactions:**

Look for code that interacts with the operating system or external tools:

* **`os` module:**  File system operations (creating directories, checking for files, removing files/directories).
* **`subprocess` module:** Executing external commands like `git`, `hg`, `svn`. This directly interacts with the system's command-line tools.
* **File Archive Handling (`tarfile`, `zipfile`):**  Working with compressed files, which are a common way to distribute software.
* **Potential interactions with the kernel/framework:** While the code itself *doesn't directly* manipulate kernel structures, the *purpose* of Frida (dynamic instrumentation) implies that the subprojects managed here might contain code that *does* interact with the kernel or Android framework. This is an indirect connection.

**7. Analyzing Logic and Hypothetical Scenarios:**

For crucial methods like `update_git`, walk through the code with hypothetical inputs:

* **Scenario 1 (Simple Update):** The Git repository exists, the revision is a branch, and there are no local changes. Trace the `fetch` and `checkout`/`rebase` logic.
* **Scenario 2 (Local Changes):** The user has modified files in the subproject. Observe how `git stash` is used.
* **Scenario 3 (Revision is a Commit):**  See how the logic handles fetching and checking out specific commits.

**8. Identifying Potential User Errors:**

Think about common mistakes users might make when using this tool:

* **Incorrect command-line arguments:**  Providing invalid options or subproject names.
* **Network issues:**  Problems downloading dependencies.
* **Version control conflicts:**  Issues when updating Git repositories with local changes.
* **Forgetting `--confirm` for purge:**  Accidentally deleting subproject files without confirmation.
* **Mixing `--apply` and `--save` for packagefiles.**

**9. Tracing User Operations:**

Consider how a user might end up executing this script:

* **During the Frida build process:**  This is the most likely scenario. The Meson build system would call this script to manage subproject dependencies.
* **Manually using the `frida` command-line tool:** Users might invoke this script directly to update or manage specific subprojects.

**10. Summarizing Functionality (Concise Description):**

Finally, synthesize the information gathered into a clear and concise summary of the script's purpose. Focus on the core functions: managing subprojects, handling different types of sources (files, Git, etc.), and providing actions like update, checkout, download, and purge.

**Self-Correction/Refinement:**

* **Initial thought:** This script directly interacts with the Android kernel.
* **Correction:** The script *manages* subprojects, and some of those subprojects *might* interact with the kernel, but this script itself is primarily focused on dependency management.
* **Initial thought:**  Focus only on the `Runner` class.
* **Refinement:** The `argparse` setup and the `run` function are also crucial for understanding how the script is used.

By following these steps, systematically analyzing the code, and thinking about its context within the Frida project, you can effectively answer the prompt and generate a comprehensive explanation.
好的，让我们来分析一下 `frida/releng/meson/mesonbuild/msubprojects.py` 文件的功能。

**文件功能归纳:**

这个 Python 脚本的主要功能是**管理 Meson 构建系统中使用的子项目 (subprojects)**。它提供了一系列命令和操作，允许用户下载、更新、检出、清理和管理这些子项目的源代码。 这些子项目通常以 "wrap" 文件的形式进行描述，包含了子项目的源代码位置、版本信息等。

**功能详细列表:**

1. **子项目管理核心:**  脚本的核心在于 `Runner` 类，它封装了对单个子项目进行操作的逻辑。
2. **命令解析:** 使用 `argparse` 模块解析命令行参数，定义了 `update`, `checkout`, `download`, `foreach`, `purge`, `packagefiles` 等子命令。
3. **Wrap 文件处理:**  与 Meson 的 "wrap" 系统紧密相关。可以读取和解析 `.wrap` 文件，从中获取子项目的元数据（如源代码 URL、版本号、补丁信息等）。
4. **源代码获取:**  支持多种源代码获取方式，包括：
    * **文件:** 直接从本地或远程文件获取。
    * **Git:** 从 Git 仓库克隆或更新代码。
    * **Mercurial (hg):** 从 Mercurial 仓库克隆或更新代码。
    * **Subversion (svn):** 从 Subversion 仓库检出或更新代码。
5. **版本控制集成:** 针对 Git、Mercurial 和 Subversion 提供了特定的更新和检出逻辑，能够根据 `.wrap` 文件中指定的版本号或分支进行操作。
6. **补丁管理:**  支持应用和保存补丁文件，用于对子项目源代码进行修改。
7. **缓存管理:**  可以清除子项目的缓存文件。
8. **并行处理:** 使用 `asyncio` 和 `ThreadPoolExecutor` 实现并行下载和更新子项目，提高效率。
9. **日志记录:**  使用自定义的 `Logger` 类记录操作进度和日志信息。
10. **与 WrapDB 交互 (update_wrapdb):**  可以从 WrapDB（一个在线的 wrap 文件仓库）获取最新的 wrap 文件信息并更新本地的 wrap 文件。
11. **执行自定义命令 (foreach):** 允许在每个子项目的目录下执行任意命令。

**与逆向方法的关系及举例:**

Frida 是一个动态插桩工具，常用于逆向工程、安全研究和软件分析。`msubprojects.py` 脚本虽然不直接进行逆向操作，但它是 Frida 构建过程的一部分，**间接地与逆向方法相关**，因为它负责管理 Frida 依赖的组件。

**举例说明:**

* **获取 Frida 依赖的库的源代码:**  逆向工程师可能需要查看 Frida 依赖的某个库（例如，用于处理特定数据格式的库）的源代码，以理解 Frida 的内部工作原理或分析 Frida 如何与目标程序交互。`msubprojects.py` 的 `download` 或 `update` 命令可以用来获取这些依赖库的源代码。
* **修改 Frida 依赖的库:**  在某些情况下，为了调试 Frida 或扩展其功能，逆向工程师可能需要修改 Frida 依赖的某个库的源代码。`msubprojects.py` 的 `packagefiles` 命令可以帮助保存对子项目源代码的修改。
* **检查特定版本的依赖:**  如果 Frida 在特定版本下工作异常，逆向工程师可能需要回溯到该版本，并检查其依赖库的版本。`msubprojects.py` 的 `checkout` 命令可以用于检出子项目特定版本的代码。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

`msubprojects.py` 脚本本身主要是高级的 Python 代码，用于管理源代码。**它本身不直接涉及二进制底层、Linux/Android 内核及框架的知识**。 然而，它所管理的**子项目**可能包含这些内容。

**举例说明:**

* **子项目可能包含与操作系统交互的代码:**  例如，Frida 的某些组件可能需要调用 Linux 或 Android 的系统调用来实现特定的功能。这些代码会涉及到内核 API 和底层机制。
* **子项目可能包含与 Android 框架交互的代码:**  在 Android 平台上，Frida 需要与 Android 运行时环境 (ART) 或其他系统服务进行交互。这些交互涉及到 Android 框架的知识。
* **子项目可能包含用于处理二进制数据的代码:**  Frida 的核心功能是插桩和分析二进制代码，因此其依赖的库可能包含用于解析 ELF 文件、DEX 文件或其他二进制格式的代码。

**逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，例如在 `update_git` 函数中判断是否需要 `fetch` 远程仓库，以及如何 `checkout` 和 `reset`/`rebase` 分支。

**假设输入与输出示例 (update_git):**

**假设输入:**

* `.wrap` 文件中 `revision` 为 `v1.0` (一个 Git 标签)。
* 本地子项目仓库已经存在，但当前检出的不是 `v1.0`。

**逻辑推理:**

1. 脚本会尝试 `git fetch origin v1.0` 获取远程的 `v1.0` 标签。
2. 如果 `v1.0` 是一个 commit 或 tag，并且可以被 `git rev-parse --verify v1.0^{commit}` 验证，则可能跳过 fetch，直接从本地获取。
3. 然后，根据当前分支状态和 `--reset` 选项的值，决定执行 `git checkout v1.0` 以及可能的 `git reset --hard FETCH_HEAD` 或 `git rebase FETCH_HEAD`。

**预期输出 (部分日志):**

```
Updating <子项目名称>...
  -> Fetching revision v1.0 in <子项目路径>
  -> Checking out v1.0 in <子项目路径>
  -> git show 的输出 (显示 v1.0 对应的 commit 信息)
```

**用户或编程常见的使用错误及举例:**

1. **网络问题:**  如果网络连接不稳定或无法访问子项目的源代码仓库，`download` 或 `update` 命令会失败。
   * **错误示例:**  运行 `python msubprojects.py download <子项目名称>` 时，如果 Git 仓库无法访问，会抛出 `GitException`。
2. **错误的子项目名称:**  如果提供的子项目名称在 `.wrap` 文件中不存在，脚本将无法找到对应的子项目。
   * **错误示例:**  运行 `python msubprojects.py update non_existent_subproject` 会导致脚本找不到该子项目并可能报错。
3. **Git 操作冲突:**  在更新 Git 子项目时，如果本地存在未提交的更改，可能会导致 `git rebase` 或 `git reset` 失败。
   * **错误示例:**  修改了子项目的代码后，直接运行 `python msubprojects.py update <git子项目名称>` 可能会遇到 rebase 冲突。
4. **缺少 `--confirm` 参数:**  在执行 `purge` 命令时，如果忘记添加 `--confirm` 参数，脚本会提示将要删除的内容，但不会实际执行删除操作。
   * **错误示例:**  运行 `python msubprojects.py purge <子项目名称>` 不会删除任何文件，需要运行 `python msubprojects.py purge --confirm <子项目名称>` 才能真正删除。
5. **互斥的参数使用:**  `packagefiles` 命令的 `--apply` 和 `--save` 参数是互斥的，不能同时使用。
   * **错误示例:** 运行 `python msubprojects.py packagefiles --apply --save <子项目名称>` 会报错。

**用户操作如何一步步到达这里作为调试线索:**

通常，用户不会直接运行 `msubprojects.py` 脚本。它更多的是作为 Frida 构建系统的一部分被 Meson 自动调用。

**调试线索示例:**

1. **用户尝试构建 Frida:** 用户执行 `meson build` 或 `ninja` 命令来构建 Frida。
2. **Meson 解析构建配置:** Meson 在解析 `meson.build` 文件时，会发现需要处理子项目。
3. **Meson 调用 `msubprojects.py`:** Meson 会调用 `msubprojects.py` 脚本来下载或更新子项目的源代码。具体的调用方式可能取决于 Meson 的配置和子项目的状态。例如，如果子项目尚未下载，可能会调用 `download` 命令；如果需要更新，则可能调用 `update` 命令。
4. **脚本执行并输出日志:** `msubprojects.py` 脚本会根据 Meson 传递的参数执行相应的操作，并将日志输出到终端。

**作为调试线索:**  如果 Frida 构建过程中出现与子项目相关的问题（例如，下载失败、更新冲突等），开发者可以通过查看 Meson 的构建日志，找到 `msubprojects.py` 脚本的调用信息和输出日志，从而定位问题所在。例如，日志中可能会显示哪个子项目下载失败，或者在执行 Git 操作时出现了错误。

**总结 `msubprojects.py` 的功能 (针对第 1 部分):**

`msubprojects.py` (当前分析的部分) 的主要功能是为 Frida 的构建过程提供**子项目管理能力**。它通过解析命令行参数和 wrap 文件，实现了对子项目源代码的下载、更新、检出等操作，并支持多种版本控制系统。该脚本是 Frida 构建流程中的一个关键组件，确保了 Frida 能够获取和管理其依赖的外部代码。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/msubprojects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```