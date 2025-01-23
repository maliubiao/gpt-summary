Response:
Let's break down the thought process for analyzing this Python script and answering the prompt's questions.

**1. Initial Skim and Identification of Core Functionality:**

The first step is to quickly read through the code, focusing on function and class names, arguments, and imports. This gives a high-level understanding. Key observations from this initial pass include:

* **Purpose:**  The script's name (`mdist.py`) and the presence of terms like "dist," "archive," "tar," "zip," and "subprojects" strongly suggest it's about creating distribution packages of the project.
* **Version Control Integration:**  References to `git` and `hg` (Mercurial) and checks for "dirty" states indicate integration with version control systems.
* **Meson Integration:** Imports like `mesonbuild.environment`, `mesonbuild.mesonlib`, `mesonbuild.msetup`, and the use of `get_meson_command()` point to its role as part of the Meson build system.
* **Distribution Scripting:** The presence of `dist_scripts` suggests the ability to execute custom scripts during the distribution process.
* **Testing:** The `--no-tests` option and the `check_dist` function highlight a testing component for the generated packages.
* **Configuration:**  The `add_arguments` function indicates it takes command-line arguments.

**2. Deeper Dive into Key Functions and Classes:**

Next, I'd focus on understanding the core logic by examining the most important functions and classes in detail:

* **`Dist` (Abstract Base Class):** This class serves as a blueprint for different distribution methods. The abstract `create_dist` method tells us that concrete implementations will handle the actual archive creation. The `run_dist_scripts` method reveals how custom scripts are executed within the context of the distribution process.
* **`GitDist` and `HgDist`:** These concrete subclasses of `Dist` provide specific implementations for creating distributions from Git and Mercurial repositories, respectively. Their methods like `copy_git`, `process_git_project`, and `have_dirty_index` provide insight into how they interact with these version control systems.
* **`create_dist` (in `GitDist` and `HgDist`):**  These methods contain the core logic for creating the distribution archives (tar.gz, tar.xz, zip). They handle copying files, including submodules/subprojects, and respecting version control states.
* **`check_dist`:** This function describes the process of testing the generated distribution package by unpacking it, running Meson, building, testing, and installing it in a temporary environment.
* **`run`:** This is the main function, orchestrating the entire distribution process. It determines the archive formats, handles subprojects, selects the appropriate `Dist` subclass based on the VCS, creates the distribution, and optionally runs tests.

**3. Answering the Prompt's Questions (Iterative Process):**

Now, I'd go through each part of the prompt, using the understanding gained in the previous steps:

* **功能 (Functionality):** This is a matter of summarizing the high-level purpose and the key actions the script performs. I would list things like creating source archives, supporting different archive formats, handling Git and Mercurial, including subprojects, running custom scripts, and testing the generated packages.

* **与逆向方法的关系 (Relationship with Reverse Engineering):** This requires thinking about how distribution packages are used in a reverse engineering context. The most obvious connection is that a distribution package contains the source code. Reverse engineers often start by examining source code if available. I'd give a concrete example like analyzing the source code of a library to understand its functionality or identify vulnerabilities.

* **二进制底层，linux, android内核及框架的知识 (Binary Lower-Level, Linux, Android Kernel/Framework Knowledge):** This requires identifying code sections that interact with system-level concepts.
    * **Binary/Lower-Level:**  The creation of `.tar.gz`, `.tar.xz`, and `.zip` archives involves manipulating files at a lower level. The `shutil.make_archive` function and the manual compression using `gzip` and `lzma` are relevant here. The execution of external commands using `subprocess` is also a lower-level interaction.
    * **Linux:** The script heavily uses Linux command-line tools like `git`, `hg`, `tar`, `gzip`, and `xz`. The concept of `DESTDIR` for installation is common in Linux.
    * **Android Kernel/Framework:** While the script itself doesn't directly interact with the Android kernel or framework *in its core logic of creating the archive*, the *purpose* of Frida (which this script is a part of) is deeply related to these areas. Frida is used for dynamic instrumentation, which is a technique often used in reverse engineering and analysis of Android apps and the Android system itself. So, even though the *code* doesn't have explicit Android kernel calls, its *context* strongly links it.

* **逻辑推理 (Logical Reasoning):** Here, I'd look for conditional statements and how different inputs lead to different outputs. The selection of `GitDist` or `HgDist` based on the presence of `.git` or `.hg` directories is a good example. The handling of the `--include-subprojects` option and how it affects the contents of the archive is another. I would create a simple scenario with a hypothetical input and expected output to illustrate this.

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  This involves thinking about how a user might misuse the script or how a developer might make mistakes. Examples include specifying invalid archive formats, trying to create a distribution in a non-version-controlled directory, or forgetting to commit changes before creating a release.

* **用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here as a Debugging Clue):**  This requires tracing the execution flow from the user's perspective. The user would typically invoke a Meson command like `meson dist`. I'd describe the steps Meson takes to execute this script, including finding the `mdist.py` file and passing the relevant arguments. This is useful for understanding the context in which the script is executed during debugging.

**4. Refinement and Organization:**

Finally, I'd review and organize my answers to ensure they are clear, concise, and well-structured. I'd use bullet points, code snippets where appropriate, and clear explanations to make the information easy to understand. I'd double-check that I've addressed all parts of the prompt.

This iterative process of skimming, deep diving, and then specifically addressing each point of the prompt, helps to break down a complex script into manageable parts and produce a comprehensive analysis.
这是 frida 动态 Instrumentation 工具中负责创建源代码分发包的 Python 脚本。让我们分解一下它的功能以及与你提到的领域的关系。

**功能列举:**

1. **创建源代码归档文件:**  该脚本的主要功能是根据当前项目的源代码创建一个或多个指定格式（如 `tar.gz`, `tar.xz`, `zip`）的归档文件。这些归档文件通常用于软件发布，允许用户获取项目的完整源代码。
2. **支持多种归档格式:**  它支持 `gztar`, `xztar`, 和 `zip` 这三种常见的归档格式，允许用户根据需求选择合适的格式。
3. **处理 Git 和 Mercurial 版本控制:** 脚本能够识别项目是否使用 Git 或 Mercurial 进行版本控制，并利用相应的工具（`git archive`, `hg archive`）来创建源代码归档。这确保了归档文件中包含的是版本控制系统中的代码快照。
4. **处理未提交的更改:**  脚本会检查版本控制系统中是否存在未提交的更改。默认情况下，如果存在未提交的更改，脚本会报错并退出，除非使用了 `--allow-dirty` 参数，此时会发出警告但继续执行。
5. **包含子项目:** 通过 `--include-subprojects` 参数，脚本可以将构建过程中使用的子项目的源代码也包含到分发包中。这对于需要完整源代码构建环境的项目很有用。
6. **运行自定义分发脚本:**  项目可以定义自定义的脚本，在创建分发包的过程中执行。这些脚本可以用于执行特定的清理、预处理或其他任务。
7. **测试生成的分发包:**  脚本可以选择构建和测试生成的分发包，以确保其可用性和完整性。这通过在临时目录中解压分发包，然后使用 Meson 构建系统进行构建、测试和安装来实现。
8. **生成 SHA256 校验和:**  对于生成的每个归档文件，脚本还会创建一个 `.sha256sum` 文件，其中包含归档文件的 SHA256 哈希值，用于校验文件的完整性。

**与逆向方法的关系 (Reverse Engineering):**

该脚本直接关系到逆向工程，因为它创建了包含程序源代码的分发包。对于逆向工程师来说，源代码是理解程序行为、查找漏洞、分析算法的关键资源。

**举例说明:**

* **情景:** 逆向工程师想要深入了解 Frida 的内部工作原理，特别是 Frida 如何与目标进程进行交互。
* **使用:** 逆向工程师可以下载使用该脚本生成的 Frida 源代码分发包。
* **分析:**  通过阅读 `frida-tools` 和其他相关组件的源代码，逆向工程师可以了解 Frida 的架构、核心算法、使用的 API 以及它如何利用操作系统提供的机制进行动态 instrumentation。例如，他们可以查看 `frida-core` 中的代码来理解 Frida 如何注入代码到目标进程，或者查看 `frida-gum` 中的代码来理解 Frida 的 instrumentation 引擎。

**涉及到二进制底层，Linux, Android 内核及框架的知识:**

虽然此脚本本身主要是 Python 代码，用于组织和打包源代码，但它所处理的对象（Frida 的源代码）以及它执行的操作都与这些底层知识密切相关。

**举例说明:**

* **二进制底层:** Frida 的核心功能是动态 instrumentation，这涉及到对目标进程的二进制代码进行修改和分析。生成的源代码分发包中包含了实现这些功能的 C/C++ 代码，例如 Frida 的 Gum 引擎，它负责在运行时修改目标进程的指令。
* **Linux:** 该脚本在 Linux 环境下运行，并使用了 `git` 和 `tar` 等 Linux 命令行工具。Frida 本身在很大程度上也依赖于 Linux 提供的进程管理、内存管理和安全机制。源代码中会包含与 Linux 系统调用交互的代码。
* **Android 内核及框架:** Frida 主要的应用场景之一是 Android 平台的逆向工程和安全分析。分发包中会包含 Frida 如何与 Android 系统进行交互的代码，例如通过 `ptrace` 系统调用进行进程控制，或者通过 Android 的 Binder 机制与系统服务进行通信。逆向工程师可以研究这些代码来理解 Frida 如何在 Android 环境中实现 instrumentation。

**逻辑推理:**

脚本中包含一些逻辑推理，用于决定如何创建分发包。

**假设输入与输出:**

* **假设输入:**
    * 在一个使用 Git 进行版本控制的 Frida 项目的根目录下运行脚本。
    * 未指定 `--allow-dirty` 参数。
    * 版本控制系统中存在未提交的更改。
* **输出:** 脚本会检测到未提交的更改，并打印错误信息 "Repository has uncommitted changes that will not be included in the dist tarball\nUse --allow-dirty to ignore the warning and proceed anyway"，然后退出。

* **假设输入:**
    * 在一个使用 Git 进行版本控制的 Frida 项目的根目录下运行脚本。
    * 指定了 `--formats gztar,zip` 参数。
    * 版本控制系统中没有未提交的更改。
* **输出:** 脚本会创建两个归档文件：一个名为 `frida-<version>.tar.gz`，另一个名为 `frida-<version>.zip`，其中 `<version>` 是项目的版本号。同时，会为这两个归档文件分别生成 `.sha256sum` 文件。

**涉及用户或者编程常见的使用错误:**

* **错误地指定归档格式:** 用户可能在 `--formats` 参数中指定了不支持的归档格式，例如 `--formats rar`。脚本会检查输入的格式是否在 `archive_choices` 中，如果不在则会报错并退出，例如 "Value "rar" not one of permitted values ['gztar', 'xztar', 'zip']."。
* **在非版本控制目录中运行:** 用户可能在一个没有 `.git` 或 `.hg` 目录的源代码目录中运行该脚本。脚本会尝试检测版本控制系统，如果都找不到，则会输出 "Dist currently only works with Git or Mercurial repos" 并退出。
* **忘记提交更改:**  用户可能在有未提交的更改的情况下运行脚本，且没有使用 `--allow-dirty` 参数。这会导致脚本报错并退出，提醒用户提交更改或使用 `--allow-dirty`。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为调试线索，了解用户如何执行到 `mdist.py` 脚本至关重要。典型的步骤如下：

1. **用户想要创建一个 Frida 的源代码分发包。** 这可能是为了发布新版本、为特定平台构建 Frida，或者仅仅是为了备份源代码。
2. **用户进入 Frida 项目的构建目录（通常是 `build` 目录）。**  或者，用户也可以在源代码根目录使用 `-C` 参数指定构建目录。
3. **用户执行 Meson 的 `dist` 命令。**  这是一个 Meson 提供的子命令，用于创建源代码分发包。命令的形式通常是 `meson dist`。
4. **Meson 构建系统解析 `dist` 命令。**  Meson 会查找负责处理 `dist` 命令的模块。
5. **Meson 找到并执行 `frida/subprojects/frida-tools/releng/meson/mesonbuild/mdist.py` 脚本。**  Meson 框架会将相关的配置信息和用户提供的参数传递给这个脚本。例如，通过 `-C` 参数指定的构建目录会传递给脚本的 `options.wd` 属性。
6. **脚本开始执行，读取构建信息和用户参数。** 脚本会读取 `meson-private/build.dat` 文件来获取项目的名称、版本等信息，并解析用户提供的命令行参数。
7. **脚本根据版本控制系统类型选择相应的处理逻辑。** 如果检测到 `.git` 目录，则使用 `GitDist` 类；如果检测到 `.hg` 目录，则使用 `HgDist` 类。
8. **脚本根据用户参数创建指定格式的归档文件。** 例如，如果用户指定了 `--formats zip`，则会调用 `shutil.make_archive` 创建 ZIP 文件。
9. **脚本可以选择执行测试和生成校验和。** 如果没有指定 `--no-tests`，则会进行测试。最后，会为每个生成的归档文件创建 `.sha256sum` 文件。

**调试线索:**

当遇到与创建分发包相关的问题时，例如分发包内容不正确、创建失败等，了解上述步骤可以帮助定位问题：

* **检查用户执行 `meson dist` 命令时的目录和参数。** 确保用户在正确的构建目录下执行命令，并且传递了正确的参数。
* **检查项目的版本控制状态。**  如果分发包缺少某些更改，可能是因为用户忘记提交。
* **检查自定义分发脚本的执行情况。** 如果分发包有问题，可能是自定义脚本引入了错误。
* **查看 Meson 的构建日志。**  Meson 会记录执行过程中的信息，包括 `mdist.py` 的输出。
* **在开发环境中直接运行 `mdist.py` 脚本进行调试。**  可以模拟用户的操作，并添加调试输出以了解脚本的执行流程和变量值。

总而言之，`mdist.py` 是 Frida 构建系统中一个关键的组件，负责将源代码打包以供发布和分发。理解其功能和工作原理对于 Frida 的开发者和希望深入了解 Frida 内部机制的逆向工程师都非常重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 The Meson development team
# Copyright © 2023 Intel Corporation

from __future__ import annotations


import abc
import argparse
import gzip
import os
import sys
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import hashlib
import typing as T

from dataclasses import dataclass
from glob import glob
from pathlib import Path
from mesonbuild.environment import Environment, detect_ninja
from mesonbuild.mesonlib import (MesonException, RealPathAction, get_meson_command, quiet_git,
                                 windows_proof_rmtree, setup_vsenv, OptionKey)
from mesonbuild.msetup import add_arguments as msetup_argparse
from mesonbuild.wrap import wrap
from mesonbuild import mlog, build, coredata
from .scripts.meson_exe import run_exe

if T.TYPE_CHECKING:
    from ._typing import ImmutableListProtocol
    from .interpreterbase.baseobjects import SubProject
    from .mesonlib import ExecutableSerialisation

archive_choices = ['gztar', 'xztar', 'zip']

archive_extension = {'gztar': '.tar.gz',
                     'xztar': '.tar.xz',
                     'zip': '.zip'}

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('-C', dest='wd', action=RealPathAction,
                        help='directory to cd into before running')
    parser.add_argument('--allow-dirty', action='store_true',
                        help='Allow even when repository contains uncommitted changes.')
    parser.add_argument('--formats', default='xztar',
                        help='Comma separated list of archive types to create. Supports xztar (default), gztar, and zip.')
    parser.add_argument('--include-subprojects', action='store_true',
                        help='Include source code of subprojects that have been used for the build.')
    parser.add_argument('--no-tests', action='store_true',
                        help='Do not build and test generated packages.')


def create_hash(fname: str) -> None:
    hashname = fname + '.sha256sum'
    m = hashlib.sha256()
    m.update(open(fname, 'rb').read())
    with open(hashname, 'w', encoding='utf-8') as f:
        # A space and an asterisk because that is the format defined by GNU coreutils
        # and accepted by busybox and the Perl shasum tool.
        f.write('{} *{}\n'.format(m.hexdigest(), os.path.basename(fname)))


msg_uncommitted_changes = 'Repository has uncommitted changes that will not be included in the dist tarball'

def handle_dirty_opt(msg: str, allow_dirty: bool) -> None:
    if allow_dirty:
        mlog.warning(msg)
    else:
        mlog.error(msg + '\n' + 'Use --allow-dirty to ignore the warning and proceed anyway')
        sys.exit(1)

def is_git(src_root: str) -> bool:
    '''
    Checks if meson.build file at the root source directory is tracked by git.
    It could be a subproject part of the parent project git repository.
    '''
    return quiet_git(['ls-files', '--error-unmatch', 'meson.build'], src_root)[0]

def is_hg(src_root: str) -> bool:
    return os.path.isdir(os.path.join(src_root, '.hg'))


@dataclass
class Dist(metaclass=abc.ABCMeta):
    dist_name: str
    src_root: str
    bld_root: str
    dist_scripts: T.List[ExecutableSerialisation]
    subprojects: T.Dict[SubProject, str]
    options: argparse.Namespace

    def __post_init__(self) -> None:
        self.dist_sub = os.path.join(self.bld_root, 'meson-dist')
        self.distdir = os.path.join(self.dist_sub, self.dist_name)

    @abc.abstractmethod
    def create_dist(self, archives: T.List[str]) -> T.List[str]:
        pass

    def run_dist_scripts(self) -> None:
        assert os.path.isabs(self.distdir)
        mesonrewrite = Environment.get_build_command() + ['rewrite']
        env = {'MESON_DIST_ROOT': self.distdir,
               'MESON_SOURCE_ROOT': self.src_root,
               'MESON_BUILD_ROOT': self.bld_root,
               'MESONREWRITE': ' '.join(shlex.quote(x) for x in mesonrewrite),
               }
        for d in self.dist_scripts:
            if d.subproject and d.subproject not in self.subprojects:
                continue
            subdir = self.subprojects.get(d.subproject, '')
            env['MESON_PROJECT_DIST_ROOT'] = os.path.join(self.distdir, subdir)
            env['MESON_PROJECT_SOURCE_ROOT'] = os.path.join(self.src_root, subdir)
            env['MESON_PROJECT_BUILD_ROOT'] = os.path.join(self.bld_root, subdir)
            name = ' '.join(d.cmd_args)
            print(f'Running custom dist script {name!r}')
            try:
                rc = run_exe(d, env)
                if rc != 0:
                    sys.exit('Dist script errored out')
            except OSError:
                print(f'Failed to run dist script {name!r}')
                sys.exit(1)


class GitDist(Dist):
    def git_root(self, dir_: str) -> Path:
        # Cannot use --show-toplevel here because git in our CI prints cygwin paths
        # that python cannot resolve. Workaround this by taking parent of src_root.
        prefix = quiet_git(['rev-parse', '--show-prefix'], dir_, check=True)[1].strip()
        if not prefix:
            return Path(dir_)
        prefix_level = len(Path(prefix).parents)
        return Path(dir_).parents[prefix_level - 1]

    def have_dirty_index(self) -> bool:
        '''Check whether there are uncommitted changes in git'''
        ret = subprocess.call(['git', '-C', self.src_root, 'diff-index', '--quiet', 'HEAD'])
        return ret == 1

    def copy_git(self, src: T.Union[str, os.PathLike], distdir: str, revision: str = 'HEAD',
                 prefix: T.Optional[str] = None, subdir: T.Optional[str] = None) -> None:
        cmd = ['git', 'archive', '--format', 'tar', revision]
        if prefix is not None:
            cmd.insert(2, f'--prefix={prefix}/')
        if subdir is not None:
            cmd.extend(['--', subdir])
        with tempfile.TemporaryFile() as f:
            subprocess.check_call(cmd, cwd=src, stdout=f)
            f.seek(0)
            t = tarfile.open(fileobj=f) # [ignore encoding]
            t.extractall(path=distdir)

    def process_git_project(self, src_root: str, distdir: str) -> None:
        if self.have_dirty_index():
            handle_dirty_opt(msg_uncommitted_changes, self.options.allow_dirty)
        if os.path.exists(distdir):
            windows_proof_rmtree(distdir)
        repo_root = self.git_root(src_root)
        if repo_root.samefile(src_root):
            os.makedirs(distdir)
            self.copy_git(src_root, distdir)
        else:
            subdir = Path(src_root).relative_to(repo_root)
            tmp_distdir = distdir + '-tmp'
            if os.path.exists(tmp_distdir):
                windows_proof_rmtree(tmp_distdir)
            os.makedirs(tmp_distdir)
            self.copy_git(repo_root, tmp_distdir, subdir=str(subdir))
            Path(tmp_distdir, subdir).rename(distdir)
            windows_proof_rmtree(tmp_distdir)
        self.process_submodules(src_root, distdir)

    def process_submodules(self, src: str, distdir: str) -> None:
        module_file = os.path.join(src, '.gitmodules')
        if not os.path.exists(module_file):
            return
        cmd = ['git', 'submodule', 'status', '--cached', '--recursive']
        modlist = subprocess.check_output(cmd, cwd=src, universal_newlines=True).splitlines()
        for submodule in modlist:
            status = submodule[:1]
            sha1, rest = submodule[1:].split(' ', 1)
            subpath = rest.rsplit(' ', 1)[0]

            if status == '-':
                mlog.warning(f'Submodule {subpath!r} is not checked out and cannot be added to the dist')
                continue
            elif status in {'+', 'U'}:
                handle_dirty_opt(f'Submodule {subpath!r} has uncommitted changes that will not be included in the dist tarball', self.options.allow_dirty)

            self.copy_git(os.path.join(src, subpath), distdir, revision=sha1, prefix=subpath)

    def create_dist(self, archives: T.List[str]) -> T.List[str]:
        self.process_git_project(self.src_root, self.distdir)
        for path in self.subprojects.values():
            sub_src_root = os.path.join(self.src_root, path)
            sub_distdir = os.path.join(self.distdir, path)
            if os.path.exists(sub_distdir):
                continue
            if is_git(sub_src_root):
                self.process_git_project(sub_src_root, sub_distdir)
            else:
                shutil.copytree(sub_src_root, sub_distdir)
        self.run_dist_scripts()
        output_names = []
        for a in archives:
            compressed_name = self.distdir + archive_extension[a]
            shutil.make_archive(self.distdir, a, root_dir=self.dist_sub, base_dir=self.dist_name)
            output_names.append(compressed_name)
        windows_proof_rmtree(self.distdir)
        return output_names


class HgDist(Dist):
    def have_dirty_index(self) -> bool:
        '''Check whether there are uncommitted changes in hg'''
        out = subprocess.check_output(['hg', '-R', self.src_root, 'summary'])
        return b'commit: (clean)' not in out

    def create_dist(self, archives: T.List[str]) -> T.List[str]:
        if self.have_dirty_index():
            handle_dirty_opt(msg_uncommitted_changes, self.options.allow_dirty)
        if self.dist_scripts:
            mlog.warning('dist scripts are not supported in Mercurial projects')

        os.makedirs(self.dist_sub, exist_ok=True)
        tarname = os.path.join(self.dist_sub, self.dist_name + '.tar')
        xzname = tarname + '.xz'
        gzname = tarname + '.gz'
        zipname = os.path.join(self.dist_sub, self.dist_name + '.zip')
        # Note that -X interprets relative paths using the current working
        # directory, not the repository root, so this must be an absolute path:
        # https://bz.mercurial-scm.org/show_bug.cgi?id=6267
        #
        # .hg[a-z]* is used instead of .hg* to keep .hg_archival.txt, which may
        # be useful to link the tarball to the Mercurial revision for either
        # manual inspection or in case any code interprets it for a --version or
        # similar.
        subprocess.check_call(['hg', 'archive', '-R', self.src_root, '-S', '-t', 'tar',
                               '-X', self.src_root + '/.hg[a-z]*', tarname])
        output_names = []
        if 'xztar' in archives:
            import lzma
            with lzma.open(xzname, 'wb') as xf, open(tarname, 'rb') as tf:
                shutil.copyfileobj(tf, xf)
            output_names.append(xzname)
        if 'gztar' in archives:
            with gzip.open(gzname, 'wb') as zf, open(tarname, 'rb') as tf:
                shutil.copyfileobj(tf, zf)
            output_names.append(gzname)
        os.unlink(tarname)
        if 'zip' in archives:
            subprocess.check_call(['hg', 'archive', '-R', self.src_root, '-S', '-t', 'zip', zipname])
            output_names.append(zipname)
        return output_names


def run_dist_steps(meson_command: T.List[str], unpacked_src_dir: str, builddir: str, installdir: str, ninja_args: T.List[str]) -> int:
    if subprocess.call(meson_command + ['--backend=ninja', unpacked_src_dir, builddir]) != 0:
        print('Running Meson on distribution package failed')
        return 1
    if subprocess.call(ninja_args, cwd=builddir) != 0:
        print('Compiling the distribution package failed')
        return 1
    if subprocess.call(ninja_args + ['test'], cwd=builddir) != 0:
        print('Running unit tests on the distribution package failed')
        return 1
    myenv = os.environ.copy()
    myenv['DESTDIR'] = installdir
    if subprocess.call(ninja_args + ['install'], cwd=builddir, env=myenv) != 0:
        print('Installing the distribution package failed')
        return 1
    return 0

def check_dist(packagename: str, meson_command: ImmutableListProtocol[str], extra_meson_args: T.List[str], bld_root: str, privdir: str) -> int:
    print(f'Testing distribution package {packagename}')
    unpackdir = os.path.join(privdir, 'dist-unpack')
    builddir = os.path.join(privdir, 'dist-build')
    installdir = os.path.join(privdir, 'dist-install')
    for p in (unpackdir, builddir, installdir):
        if os.path.exists(p):
            windows_proof_rmtree(p)
        os.mkdir(p)
    ninja_args = detect_ninja()
    shutil.unpack_archive(packagename, unpackdir)
    unpacked_files = glob(os.path.join(unpackdir, '*'))
    assert len(unpacked_files) == 1
    unpacked_src_dir = unpacked_files[0]
    meson_command += ['setup']
    meson_command += create_cmdline_args(bld_root)
    meson_command += extra_meson_args

    ret = run_dist_steps(meson_command, unpacked_src_dir, builddir, installdir, ninja_args)
    if ret > 0:
        print(f'Dist check build directory was {builddir}')
    else:
        windows_proof_rmtree(unpackdir)
        windows_proof_rmtree(builddir)
        windows_proof_rmtree(installdir)
        print(f'Distribution package {packagename} tested')
    return ret

def create_cmdline_args(bld_root: str) -> T.List[str]:
    parser = argparse.ArgumentParser()
    msetup_argparse(parser)
    args = T.cast('coredata.SharedCMDOptions', parser.parse_args([]))
    coredata.parse_cmd_line_options(args)
    coredata.read_cmd_line_file(bld_root, args)
    args.cmd_line_options.pop(OptionKey('backend'), '')
    return shlex.split(coredata.format_cmd_line_options(args))

def determine_archives_to_generate(options: argparse.Namespace) -> T.List[str]:
    result = []
    for i in options.formats.split(','):
        if i not in archive_choices:
            sys.exit(f'Value "{i}" not one of permitted values {archive_choices}.')
        result.append(i)
    if len(i) == 0:
        sys.exit('No archive types specified.')
    return result

def run(options: argparse.Namespace) -> int:
    buildfile = Path(options.wd) / 'meson-private' / 'build.dat'
    if not buildfile.is_file():
        raise MesonException(f'Directory {options.wd!r} does not seem to be a Meson build directory.')
    b = build.load(options.wd)
    need_vsenv = T.cast('bool', b.environment.coredata.get_option(OptionKey('vsenv')))
    setup_vsenv(need_vsenv)
    src_root = b.environment.source_dir
    bld_root = b.environment.build_dir
    priv_dir = os.path.join(bld_root, 'meson-private')

    dist_name = b.project_name + '-' + b.project_version

    archives = determine_archives_to_generate(options)

    subprojects = {}
    extra_meson_args = []
    if options.include_subprojects:
        subproject_dir = os.path.join(src_root, b.subproject_dir)
        for sub in b.subprojects.host:
            directory = wrap.get_directory(subproject_dir, sub)
            subprojects[sub] = os.path.join(b.subproject_dir, directory)
        extra_meson_args.append('-Dwrap_mode=nodownload')

    cls: T.Type[Dist]
    if is_git(src_root):
        cls = GitDist
    elif is_hg(src_root):
        if subprojects:
            print('--include-subprojects option currently not supported with Mercurial')
            return 1
        cls = HgDist
    else:
        print('Dist currently only works with Git or Mercurial repos')
        return 1

    project = cls(dist_name, src_root, bld_root, b.dist_scripts, subprojects, options)
    names = project.create_dist(archives)

    if names is None:
        return 1
    rc = 0
    if not options.no_tests:
        # Check only one.
        rc = check_dist(names[0], get_meson_command(), extra_meson_args, bld_root, priv_dir)
    if rc == 0:
        for name in names:
            create_hash(name)
            print('Created', name)
    return rc
```