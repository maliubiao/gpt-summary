Response:
My thinking process to analyze the provided Python code and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the `msubprojects.py` script within the Frida dynamic instrumentation tool. They are particularly interested in its relationship to reverse engineering, low-level aspects (kernel, etc.), logical reasoning, common user errors, and debugging. The request is for the *first part* of the analysis.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code, looking for keywords and patterns that hint at the script's purpose. Key observations:
    * **Imports:**  Libraries like `os`, `subprocess`, `argparse`, `asyncio`, `threading`, `shutil`, `pathlib`, `tarfile`, `zipfile`, and notably, modules within the same directory (`.ast`, `.mesonlib`, `.wrap.wrap`) strongly suggest this script manages external dependencies or subprojects. The `wrap` module specifically points to handling "wrap" files, a common mechanism for managing external libraries in Meson.
    * **Classes:**  The `Logger` and `Runner` classes are central. `Logger` likely handles output and progress reporting. `Runner` seems to encapsulate the logic for operating on individual subprojects.
    * **`argparse` Usage:** The presence of `argparse` clearly indicates that this script is a command-line tool with various subcommands and options.
    * **Subcommands:**  The `add_arguments` function defines subcommands like `update`, `checkout`, `download`, `foreach`, `purge`, and `packagefiles`. This is a strong indicator of the script's core actions.
    * **Git/Mercurial/SVN Keywords:**  Functions like `git_output`, `git_rebase`, `hg_checkout`, `svn_update` indicate support for managing subprojects that are version-controlled using these systems.
    * **File Operations:**  Functions like `read_archive_files`, and actions within the `purge` and `packagefiles` subcommands involve interacting with files and directories.

3. **Deduce High-Level Functionality:** Based on the initial scan, I concluded that the script is primarily concerned with managing subprojects (external dependencies) within a larger Meson build system. This involves downloading, updating, checking out specific versions, and potentially patching these subprojects.

4. **Analyze Key Classes and Methods:** I then focused on the `Runner` class and its methods, as this is where the core logic resides:
    * **`__init__`:**  Sets up the runner, including a copy of the `Resolver` (which is responsible for locating and downloading subprojects based on wrap files).
    * **`run`:**  Executes the appropriate subcommand logic.
    * **`update_wrapdb`:** Interacts with a "WrapDB" to get the latest versions of subprojects. This is important for dependency management.
    * **`update_file`, `update_git`, `update_hg`, `update_svn`:**  Handle updating subprojects based on their type (plain file or version control system).
    * **`checkout`:** Manages checking out specific branches in Git repositories.
    * **`download`:**  Downloads subprojects if they are not already present.
    * **`foreach`:**  Allows executing arbitrary commands within subproject directories.
    * **`purge`:**  Removes subproject artifacts.
    * **`packagefiles`:**  Manages patching and saving changes to subprojects.

5. **Relate to Reverse Engineering:**  I considered how these functionalities connect to reverse engineering. The ability to download and update specific versions of libraries (`update`, `checkout`, `download`) is crucial for setting up a controlled environment for analysis. The `foreach` command allows for running scripts within the context of the subproject, which could be useful for building or testing specific components. The `purge` command helps clean up the environment.

6. **Identify Low-Level Interactions:** I looked for interactions with the operating system and underlying systems:
    * **File and Directory Operations:** The script heavily uses `os`, `shutil`, and `pathlib` for file and directory manipulation, which is fundamental to any build system.
    * **Process Execution:**  The use of `subprocess` to execute Git, Mercurial, and SVN commands indicates interaction with external tools at the operating system level.
    * **Archive Handling:** `tarfile` and `zipfile` are used for extracting downloaded subproject archives.

7. **Consider Logical Reasoning:** The `update_git` function demonstrates logical reasoning by checking the current branch, comparing it to the desired revision, and deciding whether to rebase or reset. The logic around fetching specific revisions and handling detached HEAD states also involves decision-making.

8. **Think About User Errors:** I considered common mistakes users might make:
    * Providing incorrect subcommand arguments.
    * Trying to update a subproject that hasn't been downloaded yet.
    * Conflicts when updating Git subprojects with local changes.
    * Incorrectly using `--reset` and potentially losing work.

9. **Trace User Operations:** I imagined the steps a user would take to reach this script:
    1. Navigate to the root directory of a Frida project.
    2. Run the `meson` command to configure the build system.
    3. Meson, in turn, might invoke this `msubprojects.py` script as part of its dependency management process, or the user might run it directly.
    4. A user might explicitly invoke `msubprojects.py` with subcommands like `update`, `download`, etc., to manage the subprojects.

10. **Structure the Output:** Finally, I organized my findings into the requested categories, providing examples and explanations where necessary. I focused on summarizing the overall functionality in the conclusion for Part 1. I made sure to address each point raised in the user's initial request.

This iterative process of code scanning, deduction, detailed analysis, and connecting the functionality to the user's specific interests allowed me to generate a comprehensive and informative response.
This Python code file, `msubprojects.py`, is a crucial part of Frida's build system, specifically focusing on the management of **subprojects**. Subprojects are external dependencies that Frida relies on. This script provides a command-line interface to interact with and manage these subprojects.

Here's a breakdown of its functionalities:

**Core Functionality: Subproject Management**

The primary goal of this script is to automate the tasks involved in obtaining, updating, and managing the source code of Frida's subprojects. This includes:

* **Downloading Subprojects:**  Fetching the source code of subprojects from various sources (like Git repositories, archives, or local files).
* **Updating Subprojects:** Bringing the subproject source code up to the desired revision or latest version. This can involve fetching changes from remote repositories, applying patches, or re-downloading files.
* **Checking Out Specific Versions/Branches:** Allowing developers to switch to a particular branch or revision of a subproject.
* **Purging Subprojects:** Removing the downloaded source code and potentially cached files of subprojects.
* **Applying/Saving Patches:** Managing local modifications to subprojects through patch files.

**Relationship to Reverse Engineering**

This script indirectly but significantly relates to reverse engineering by ensuring that the necessary tools and libraries (subprojects) are available in the correct versions for Frida to function. Here's how:

* **Dependency Management:** Reverse engineering tools like Frida often depend on specific versions of libraries (e.g., a specific version of V8 JavaScript engine, if Frida targets JavaScript environments). This script ensures these dependencies are correctly managed, providing a consistent and working environment for Frida.
* **Source Code Access:** For advanced reverse engineering or debugging of Frida itself, having the source code of its subprojects available is essential. This script facilitates obtaining that source code.
* **Customization and Modification:** If a reverse engineer wants to modify a subproject used by Frida (e.g., to add logging or instrumentation), this script provides the mechanisms to update the subproject and potentially manage those local changes with the `packagefiles` functionality.

**Example:**

Imagine Frida depends on a specific version of the `capstone` disassembler library. The `msubprojects.py` script could be used to:

1. **Download:** Download the source code of `capstone` from its Git repository (as specified in Frida's configuration).
2. **Update:** Later, if a new version of `capstone` is needed or if Frida's configuration changes, the script can update the `capstone` source code to the required revision.
3. **Checkout:**  A developer might need to investigate a bug related to a specific version of `capstone`. They can use the script to check out that particular version of the `capstone` source code.

**Binary Underlying, Linux, Android Kernel & Framework Knowledge**

While the script itself is Python, its actions directly impact the binary level and interact with operating system features:

* **Git/Mercurial/SVN:** It uses commands like `git fetch`, `git checkout`, `hg pull`, `svn update` which are fundamental to version control systems used extensively in software development, including for projects that interact with the kernel or low-level systems.
* **File System Operations:** The script performs numerous file system operations (creating directories, deleting files, copying files, extracting archives) that are essential for managing source code.
* **Process Execution:** It uses the `subprocess` module to execute external commands like Git, tar, and zip, which are core utilities in Linux and other Unix-like environments (including Android's underlying system).
* **Archive Handling:**  It uses `tarfile` and `zipfile` to extract the source code from downloaded archives. These archives often contain compiled binaries or source code intended to run on specific platforms like Linux or Android.
* **Path Manipulation:** It uses `pathlib` for robust path manipulation, which is crucial when dealing with different operating systems and directory structures, especially when working with kernel headers or Android framework components that might be part of a subproject.

**Example:**

Consider a Frida subproject that wraps a part of the Android NDK (Native Development Kit). This script would:

1. **Download:** Download the necessary source files for that NDK component.
2. **File Operations:** Place those files in the correct directory structure within the Frida build environment.
3. **Potentially Apply Patches:** Apply patches that adapt the NDK component for use within Frida.

**Logical Reasoning**

The script employs logical reasoning in several places:

* **Determining Update Needs:**  The `update_git` function checks if the local repository is a Git repository, compares the current revision with the desired revision, and decides whether to fetch, checkout, rebase, or reset.
* **Handling Different Subproject Types:** It uses conditional logic ( `if self.wrap.type == 'git':`) to handle updates for different types of subprojects (Git, Mercurial, SVN, file archives).
* **Error Handling:** It uses `try...except` blocks to gracefully handle potential errors during Git operations, archive extraction, or file system interactions.
* **Stashing and Rebasing Logic:**  The `update_git` function includes logic to stash local changes before performing Git operations like rebase or reset, attempting to preserve user modifications.

**Hypothetical Input and Output (for `update` command with a Git subproject):**

**Hypothetical Input:**

* **Command:** `python msubprojects.py update --sourcedir /path/to/frida/source some-git-subproject`
* **Subproject Configuration (`wrap` file for `some-git-subproject`):**
  ```ini
  [wrap-git]
  url = https://github.com/example/some-git-repo.git
  revision = some-branch-or-commit
  ```
* **Current state of `some-git-subproject` directory:**  Might be an existing Git repository, might not exist.

**Hypothetical Output (if the subproject needs updating):**

```
Updating some-git-subproject...
  -> Fetching origin some-branch-or-commit
  -> Checking out some-branch-or-commit in /path/to/frida/source/subprojects/some-git-subproject
  -> Submodule update --checkout --recursive
  -> Current commit: <short-commit-hash> (<remote-branch-name>) <commit-message> [<author>]
```

**Hypothetical Output (if the subproject is already up-to-date):**

```
Updating some-git-subproject...
  -> Already up-to-date.
```

**User or Programming Common Usage Errors**

* **Incorrect Subproject Name:** Typing the subproject name wrong in the command line will result in the script not finding the corresponding subproject configuration.
* **Network Issues:** If the script needs to download a subproject from a remote repository and there's no internet connection, it will fail.
* **Conflicting Local Changes (Git):**  If a user has made local changes in a Git-based subproject and tries to update it without committing or stashing those changes, the update might fail or lead to merge conflicts. The script attempts to mitigate this with `git stash`.
* **Missing Dependencies:**  If the script relies on external commands like `git` or `tar` being in the system's PATH, and they are not present, the script will fail.
* **Permissions Issues:**  The script might fail if it doesn't have the necessary permissions to create directories, write files, or execute external commands in the source directory.
* **Incorrectly using `--reset`:** Using the `--reset` flag in the `update` command for Git subprojects will discard any local uncommitted changes, which could lead to data loss if the user is not careful.

**Example of User Operation Leading to This Code:**

1. A developer is working on Frida and wants to update all its subprojects.
2. They navigate to the root directory of the Frida source code in their terminal.
3. They execute the command: `python ./subprojects/frida-gum/releng/meson/mesonbuild/msubprojects.py update`
4. The `msubprojects.py` script is executed.
5. The `run` function is called, which parses the command-line arguments.
6. The `update` subcommand is identified.
7. The script iterates through the configured subprojects.
8. For each subproject, the appropriate update logic (e.g., `Runner.update_git` for a Git subproject) is executed.

**Summary of Functionality (Part 1)**

The `msubprojects.py` script is a command-line tool within Frida's build system responsible for managing external dependencies (subprojects). It provides functionalities to download, update, checkout specific versions, and purge subprojects. It interacts with version control systems (Git, Mercurial, SVN) and file archives to manage subproject source code. This script is crucial for ensuring that Frida has the necessary components to build and function correctly, playing an important role in the overall development and reverse engineering capabilities of Frida. It employs logical reasoning to handle different scenarios and attempts to mitigate common user errors.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/msubprojects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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