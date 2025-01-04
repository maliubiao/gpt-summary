Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to understand the purpose of the script. The filename `mdist.py` within the `mesonbuild` directory of a Frida project strongly suggests it's related to creating distribution packages. The initial comments confirm this. It aims to create source code archives for releasing Frida.

**2. Identifying Core Functionality (High-Level):**

Scanning the script, I look for key function and class definitions. The presence of `add_arguments`, `GitDist`, `HgDist`, `run_dist_steps`, and `check_dist` immediately stand out. These suggest a structure for handling command-line arguments, different version control systems (Git and Mercurial), the core distribution process, and a testing mechanism.

**3. Deeper Dive into Key Components:**

* **`add_arguments`:**  This is standard `argparse` usage. It defines the command-line options users can provide (e.g., `--allow-dirty`, `--formats`).

* **`GitDist` and `HgDist`:** The existence of separate classes for Git and Mercurial strongly indicates the script needs to handle version control to create a source snapshot. I note the methods within each class, like `have_dirty_index` (checking for uncommitted changes) and `create_dist` (the core packaging logic). The `GitDist` class also has methods like `copy_git` and `process_submodules`, hinting at its more complex handling of Git repositories.

* **`create_hash`:** This is a utility function for generating SHA256 checksums, a standard practice for verifying file integrity.

* **`run_dist_steps`:** This function clearly outlines the steps for building and testing the created distribution package: running Meson, compiling with Ninja, running tests, and installing.

* **`check_dist`:** This function orchestrates the testing process by unpacking the archive, setting up build and install directories, and calling `run_dist_steps`.

* **`run`:** This is the main entry point. It loads the Meson build data, determines the archive formats, instantiates the appropriate `Dist` subclass (based on the version control system), creates the distribution, and potentially runs tests.

**4. Connecting to the Prompts:**

Now, I go back to the specific questions in the prompt and map the script's functionalities to them.

* **Functionality:** This is straightforward – list the key functions and what they do (creating archives, handling Git/Hg, testing, etc.).

* **Relationship to Reverse Engineering:** This requires a bit of inference. Frida is a dynamic instrumentation tool used *in* reverse engineering. The script *creates* the distribution package of Frida. Therefore, it's related in that it packages the tools that are used for reverse engineering. The example given about distributing Frida itself for reverse engineering tasks is a direct link.

* **Binary/Low-Level/Kernel/Framework Knowledge:**  The script itself doesn't directly manipulate binaries or interact with the kernel. However, the *purpose* of Frida does. Therefore, the *output* of this script (the Frida distribution) *contains* tools and libraries that operate at those levels. The examples given (instrumentation libraries, interaction with Android framework) are relevant because the distributed package will contain these.

* **Logical Reasoning (Input/Output):** I need to identify scenarios where the script makes decisions based on input. The choice between `GitDist` and `HgDist` based on the presence of `.git` or `.hg` directories is a clear example. The input is the source directory, and the output is the type of `Dist` object created. Another example is the `--formats` option, where the input is the comma-separated list, and the output is the list of archive types to generate.

* **User/Programming Errors:**  I look for places where user input could lead to problems. Providing invalid archive formats to the `--formats` option is an obvious example. Not having Git or Mercurial installed when trying to create a distribution is another. Uncommitted changes without using `--allow-dirty` is explicitly handled in the code.

* **User Steps to Reach the Script:**  This requires understanding the typical Frida development workflow. A developer would make changes, build Frida, and then, to release it, would use a command like `meson dist`. This command would trigger the execution of this `mdist.py` script. Navigating to the build directory is also a crucial step.

**5. Refining and Structuring:**

Finally, I organize my findings into a clear and structured answer, using headings and bullet points for readability. I provide specific examples and explanations for each point. I also review the answer to ensure it's comprehensive and directly addresses all aspects of the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This script just creates archives."  **Correction:** It also handles version control, runs tests, and has a mechanism for custom distribution scripts.

* **Initial thought:** "The script directly manipulates kernel code." **Correction:** The script packages the *tools* that interact with the kernel, but it itself is a higher-level Python script.

* **Ensuring clear examples:** Instead of just saying "it handles errors," I provide a concrete example like providing an invalid archive format.

This systematic approach, moving from a high-level understanding to detailed analysis and then connecting the findings to the specific questions, allows for a comprehensive and accurate analysis of the provided Python script.
这个Python脚本 `mdist.py` 是 `frida-core` 项目中用于创建**源代码分发包 (distribution package)** 的工具。它的主要目标是将项目的源代码打包成不同的压缩格式（如`.tar.gz`, `.tar.xz`, `.zip`），以便于发布和共享。

以下是它的功能列表，以及与你提出的问题相关的说明：

**主要功能:**

1. **处理命令行参数:** 使用 `argparse` 模块定义和解析命令行参数，例如：
   - `-C`: 指定在运行前切换到的目录。
   - `--allow-dirty`: 允许在 Git 或 Mercurial 仓库有未提交更改时仍然创建分发包。
   - `--formats`: 指定要创建的压缩包格式（支持 `xztar`, `gztar`, `zip`）。
   - `--include-subprojects`:  包含构建中使用的子项目的源代码。
   - `--no-tests`: 跳过构建和测试生成的分发包。

2. **检测版本控制系统:** 检查项目根目录下是否存在 `.git` 或 `.hg` 目录，以确定项目是否使用 Git 或 Mercurial 进行版本控制。

3. **创建源代码快照:**
   - **对于 Git 仓库:** 使用 `git archive` 命令创建一个指定提交（默认为 `HEAD`）的源代码快照。它能够处理子模块，并能选择性地包含或排除未跟踪的文件。
   - **对于 Mercurial 仓库:** 使用 `hg archive` 命令创建一个源代码快照。

4. **包含子项目源代码:** 如果指定了 `--include-subprojects`，它会复制构建过程中使用的子项目的源代码到分发包中。对于 Git 子项目，它也会使用 `git archive` 进行处理。

5. **运行自定义分发脚本:** 它允许项目定义一些自定义的脚本在分发包创建过程中运行。这些脚本可以执行额外的清理、修改或生成操作。

6. **创建不同格式的压缩包:** 根据 `--formats` 参数，将源代码快照打包成指定的压缩格式（`.tar.gz`, `.tar.xz`, `.zip`）。

7. **生成校验和:** 为每个创建的压缩包生成 SHA256 校验和文件 (`.sha256sum`)，用于验证文件的完整性。

8. **测试分发包 (可选):** 如果没有指定 `--no-tests`，它会解压生成的分发包，并尝试在新的环境中构建、测试和安装它，以确保分发包是可用的。

**与逆向方法的关系：**

这个脚本本身**不是直接的逆向工具**。然而，它是构建和分发 Frida 这个**动态 instrumentation 工具**的关键部分。Frida 本身被广泛用于逆向工程、安全研究和恶意软件分析等领域。

**举例说明:**

当一个逆向工程师想要使用最新版本的 Frida 时，他们可能会从 Frida 的发布页面下载一个由这个 `mdist.py` 脚本生成的源代码分发包。下载后，他们可以解压这个包，然后按照 Frida 的构建说明进行编译和安装。这个过程的第一步就依赖于 `mdist.py` 生成的压缩包。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

这个脚本本身主要是进行文件操作和调用版本控制工具，**并不直接涉及**二进制底层、内核或框架的具体操作。但是，它打包的 **Frida 的源代码** 却深入地涉及这些领域。

**举例说明:**

- **二进制底层:** Frida 的核心功能是进行代码注入和拦截，这需要深入理解目标进程的内存结构、指令集架构（例如 ARM、x86）以及操作系统加载器的工作原理。
- **Linux 内核:** Frida 可以用来 hook Linux 系统调用，这需要了解 Linux 内核的系统调用接口、内核模块的加载和运行机制等。
- **Android 内核及框架:** Frida 在 Android 平台上被广泛使用，可以 hook Java 层（通过 ART 虚拟机）和 Native 层。这需要了解 Android 的 Binder 机制、Zygote 进程的启动过程、System Server 的工作原理以及 ART 虚拟机的内部结构。`mdist.py` 打包的 Frida 源代码中包含了实现这些功能的代码。

**逻辑推理 (假设输入与输出):**

假设用户运行以下命令：

```bash
python mdist.py -C /path/to/frida/build --formats zip,gztar --include-subprojects
```

**假设输入:**

- `options.wd`: `/path/to/frida/build` (构建目录)
- `options.formats`: `zip,gztar`
- `options.include_subprojects`: `True`
- 项目使用 Git 进行版本控制。

**可能的输出:**

1. **检测 Git 仓库:** 脚本会检测到 `/path/to/frida/` 目录下存在 `.git` 目录。
2. **创建源代码快照:**  会使用 `git archive` 命令在 `/path/to/frida/build/meson-dist/frida-<version>` 目录下创建一个源代码快照。
3. **包含子项目:** 如果在构建过程中使用了子项目，这些子项目的源代码也会被复制到上述目录中。
4. **创建 ZIP 压缩包:** 使用 `shutil.make_archive` 创建 `frida-<version>.zip` 文件。
5. **创建 GZTar 压缩包:** 使用 `shutil.make_archive` 创建 `frida-<version>.tar.gz` 文件。
6. **生成校验和:** 创建 `frida-<version>.zip.sha256sum` 和 `frida-<version>.tar.gz.sha256sum` 文件。
7. **打印消息:** 类似 `Created frida-<version>.zip` 和 `Created frida-<version>.tar.gz` 的消息。

**用户或编程常见的使用错误：**

1. **指定的构建目录不是 Meson 构建目录:** 如果用户使用 `-C` 参数指定了一个不是 Meson 构建输出的目录，脚本会抛出 `MesonException` 并提示该目录不是 Meson 构建目录。

   **错误示例:**

   ```bash
   python mdist.py -C /tmp/some_random_dir
   ```

   **错误信息:** `Directory '/tmp/some_random_dir' does not seem to be a Meson build directory.`

2. **指定了不支持的压缩格式:** 如果用户在 `--formats` 中指定了 `archive_choices` 中不存在的格式，脚本会退出并报错。

   **错误示例:**

   ```bash
   python mdist.py --formats rar
   ```

   **错误信息:** `Value "rar" not one of permitted values ['gztar', 'xztar', 'zip'].`

3. **在有未提交更改的 Git 仓库中创建分发包且未使用 `--allow-dirty`:** 如果 Git 仓库有未提交的更改，脚本会报错并阻止创建分发包，除非使用了 `--allow-dirty` 参数。

   **错误示例:** (假设有未提交的更改)

   ```bash
   python mdist.py
   ```

   **错误信息:** `Repository has uncommitted changes that will not be included in the dist tarball\nUse --allow-dirty to ignore the warning and proceed anyway`

**用户操作是如何一步步的到达这里，作为调试线索：**

一个开发者或打包者通常会按照以下步骤来到这个脚本：

1. **开发和修改 Frida 源代码:**  开发者会对 Frida 的源代码进行修改、添加新功能或修复 bug。
2. **使用 Meson 构建系统配置构建:**  在 Frida 的源代码根目录下创建一个构建目录（例如 `build`），并使用 `meson setup build` 命令配置构建。
3. **使用 Ninja 或其他后端进行编译:** 在构建目录下使用 `ninja` 命令进行编译。
4. **测试构建结果:**  运行 Frida 的测试套件来验证构建的正确性。
5. **准备发布或分发:**  当准备发布 Frida 的新版本时，或者创建一个源代码分发包用于其他目的时，开发者会导航到 Frida 的构建目录。
6. **运行 `mdist.py` 脚本:** 在构建目录下，他们会执行类似以下的命令来生成源代码分发包：

   ```bash
   python path/to/frida/subprojects/frida-core/releng/meson/mesonbuild/mdist.py
   ```

   或者，更常见的是，从构建目录中使用 Meson 的 `dist` 命令，这会内部调用 `mdist.py`:

   ```bash
   meson dist
   ```

**作为调试线索：**

如果 `mdist.py` 脚本执行过程中出现问题，例如创建的压缩包不完整或包含错误的文件，以下是一些调试线索：

- **检查命令行参数:**  确认用户提供的命令行参数是否正确，例如 `--formats` 是否拼写正确，`-C` 指向的目录是否是有效的 Meson 构建目录。
- **检查版本控制状态:**  如果怀疑版本控制方面有问题，可以手动检查 Git 或 Mercurial 的状态，例如 `git status` 或 `hg summary`，确认是否存在未提交的更改或子模块问题。
- **查看 `meson-dist` 目录:**  脚本会将生成的临时文件和最终的压缩包放在构建目录下的 `meson-dist` 目录中，检查这个目录的内容可以帮助理解打包过程中的问题。
- **运行带 `--verbose` 或调试信息的 Meson 命令:**  如果问题涉及到 Meson 的内部行为，可以尝试使用更详细的输出来运行相关的 Meson 命令。
- **检查自定义分发脚本:**  如果项目定义了自定义的分发脚本，需要检查这些脚本是否正确执行，是否有错误发生。
- **查看脚本输出:**  仔细查看脚本的输出信息，是否有任何错误或警告信息。

总而言之，`mdist.py` 是 Frida 项目中一个关键的打包工具，它利用版本控制系统的功能来创建源代码分发包，方便用户获取和构建 Frida。虽然脚本本身不直接涉及逆向的底层技术，但它为 Frida 这一强大的逆向工具的分发提供了基础。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```