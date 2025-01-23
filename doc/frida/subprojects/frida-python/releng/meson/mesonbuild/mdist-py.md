Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:** The first step is to recognize the purpose of the script. The file path `frida/subprojects/frida-python/releng/meson/mesonbuild/mdist.py` and the surrounding directory structure strongly suggest this is related to building and packaging the Python bindings for Frida, likely for distribution. The filename `mdist.py` further hints at "make distribution".

**2. Initial Code Scan (Keywords and Structure):**  A quick scan reveals key elements:
    * Imports: `argparse`, `gzip`, `os`, `shutil`, `subprocess`, `tarfile`, etc. These suggest operations related to command-line arguments, file compression, system interaction, and archive manipulation.
    * Functions: `add_arguments`, `create_hash`, `handle_dirty_opt`, `is_git`, `is_hg`, `run_dist_steps`, `check_dist`, `create_cmdline_args`, `determine_archives_to_generate`, `run`. These are the main functional units.
    * Classes: `Dist`, `GitDist`, `HgDist`. This indicates an object-oriented approach with potential polymorphism based on version control systems.
    * Docstrings and Comments: These provide valuable high-level explanations. The initial docstring clearly states the file's purpose within the Frida project.

**3. Deeper Dive into Functionality (Iterative Analysis):** Now, examine each function and class in more detail, focusing on what they *do* and *how* they do it.

    * **`add_arguments`:**  This is standard `argparse` setup, defining command-line options for the script (working directory, allowing dirty state, archive formats, etc.).
    * **`create_hash`:**  Simple SHA256 checksum creation for a file. This is for verifying the integrity of the distribution packages.
    * **`handle_dirty_opt`:**  Manages warnings/errors when the Git/Hg repository has uncommitted changes. Important for ensuring the distribution is based on a known state.
    * **`is_git` and `is_hg`:**  Checks for the presence of `.git` or `.hg` directories to determine the version control system.
    * **`Dist` (Abstract Base Class):** Defines the common interface for distribution creation. Key methods are `create_dist` and `run_dist_scripts`. The `__post_init__` sets up output directories.
    * **`GitDist`:**  Inherits from `Dist` and implements distribution creation for Git repositories. Key functionalities: checking for dirty state, archiving using `git archive`, handling submodules.
    * **`HgDist`:** Inherits from `Dist` and implements distribution creation for Mercurial repositories using `hg archive`.
    * **`run_dist_scripts`:** Executes custom scripts defined in the build system (`b.dist_scripts`) within the context of the distribution directory.
    * **`run_dist_steps`:** Orchestrates the build and install process of the generated distribution package in a temporary environment (Meson setup, Ninja build, tests, install).
    * **`check_dist`:**  Downloads, unpacks, builds, tests, and installs the generated distribution package to verify its correctness. This is a crucial validation step.
    * **`create_cmdline_args`:** Extracts command-line arguments from the main Meson build configuration, ensuring consistency in the distribution build.
    * **`determine_archives_to_generate`:** Parses the `--formats` option to determine the desired archive types (tar.gz, tar.xz, zip).
    * **`run`:** The main entry point of the script. It loads the Meson build data, determines the version control system, instantiates the appropriate `Dist` subclass, creates the archives, and optionally runs the verification checks.

**4. Identifying Relationships to Reverse Engineering:**  Consider where the script's actions might be relevant to someone performing reverse engineering on Frida or a target using Frida.

    * **Distribution Packages:** The script creates the very packages a reverse engineer might download and install to use Frida. Understanding how these packages are built provides insight into the included files and structure.
    * **Source Code Inclusion:** The `--include-subprojects` option is relevant. If the source code of subprojects is included, it offers more to examine during reverse engineering.
    * **Build Process:** The `check_dist` function mirrors the steps a user would take to build Frida from source. Understanding this process helps in replicating environments and debugging issues.
    * **Custom Dist Scripts:** The ability to run custom scripts (`run_dist_scripts`) means there might be project-specific actions taken during packaging, which could be interesting from a reverse engineering perspective (e.g., obfuscation or specific build steps).

**5. Identifying Low-Level/Kernel/Framework Aspects:** Look for interactions with the operating system and core functionalities.

    * **`subprocess`:**  Extensive use of `subprocess` indicates interaction with external tools like `git`, `hg`, `tar`, `gzip`, `xz`, `zip`, and `ninja`. These are fundamental system utilities.
    * **File System Operations:**  Functions like `os.makedirs`, `shutil.copytree`, `shutil.make_archive`, `os.unlink`, and `windows_proof_rmtree` directly manipulate the file system, which is a low-level concern.
    * **Environment Variables:** The `run_dist_scripts` function sets environment variables (`MESON_DIST_ROOT`, etc.), which can influence the behavior of executed scripts.
    * **Archive Formats:** The script deals with common archive formats (`tar.gz`, `tar.xz`, `zip`), which are low-level ways to package and compress files.

**6. Logic and Assumptions:** Examine conditional statements and assumptions made by the code.

    * **Version Control Detection:**  The script assumes that if either `.git` or `.hg` exists, it's a Git or Mercurial repository, respectively. It doesn't handle other VCS.
    * **Submodule Handling:** `GitDist` specifically handles Git submodules, assuming they need to be included.
    * **Error Handling:**  The script uses `sys.exit()` to terminate on errors, and `handle_dirty_opt` provides a mechanism to warn or error on uncommitted changes.

**7. Common User Errors:** Think about what could go wrong from a user's perspective.

    * **Incorrect `--formats`:** Specifying invalid archive types.
    * **Running outside a build directory:** The script checks for `meson-private/build.dat`.
    * **Dirty repository without `--allow-dirty`:** This is a common scenario when developers haven't committed changes.
    * **Missing dependencies:**  The script relies on `git`, `hg`, `tar`, etc., being installed.

**8. Tracing User Operations:** Consider how a user might end up running this script.

    * **Direct invocation:**  A developer might manually run this script from the Meson build directory.
    * **Part of a larger build/release process:**  More likely, this script is invoked by the main Meson build system when creating distribution packages. The user's interaction would be triggering the overall "dist" or "package" target in Meson.

**Self-Correction/Refinement During Analysis:**

* **Initially, I might just see a bunch of file manipulation.**  But then, focusing on the `GitDist` and `HgDist` classes reveals the importance of version control.
* **I might overlook the significance of `run_dist_scripts`.**  Realizing these allow for custom actions adds another layer of complexity and potential for reverse engineering insights.
* **The connection to `meson.build` and the overall Meson build system needs to be emphasized.** This script isn't a standalone tool; it's part of a larger ecosystem.

By following this structured and iterative analysis, we can gain a comprehensive understanding of the Python script's functionality and its relevance to reverse engineering, low-level systems, and potential user issues.
这个Python源代码文件 `mdist.py` 是 Frida 工具链中负责创建**分发包 (distribution package)** 的一部分。它的主要功能是将项目的源代码和构建产物打包成不同的压缩格式，以便用户下载和安装。

以下是该文件的功能列表，并结合你提出的各个方面进行详细说明：

**1. 创建源代码分发包:**

* **功能:**  `mdist.py` 的核心目标是将项目的源代码打包成常见的压缩格式，如 `.tar.gz`, `.tar.xz`, 和 `.zip`。这使得用户可以下载源码并在自己的系统上构建 Frida。
* **逆向相关性:**  对于逆向工程师来说，拥有 Frida 的源代码非常重要。这允许他们：
    * **深入理解 Frida 的工作原理:**  通过阅读源代码，可以了解 Frida 如何注入进程、hook 函数、进行内存操作等核心机制。
    * **定制 Frida:**  可以修改源代码以添加新的功能、修复 bug 或使其适应特定的逆向场景。
    * **审计安全性:**  可以检查 Frida 的代码是否存在安全漏洞。
* **二进制底层/Linux/Android内核/框架知识:**  虽然 `mdist.py` 本身不直接操作二进制或内核，但它打包的源代码包含了大量与这些领域相关的代码。例如：
    * **`frida-core` (C 代码):**  Frida 的核心功能是用 C 语言实现的，这些代码会涉及到与操作系统底层 API 的交互，包括进程管理、内存管理、线程管理等。在 Linux 和 Android 上，这会涉及到系统调用、内核数据结构等。
    * **`frida-gum` (C 代码):**  一个用于运行时代码操作的库，涉及到指令级别的 hook、代码生成等技术，需要对目标架构（如 ARM, x86）的指令集有深入理解。
    * **Agent (JavaScript/TypeScript):**  虽然 `mdist.py` 不直接处理这些，但分发包中包含的 agent 代码会使用 Frida 提供的 API 来与目标进程交互，这些 API 底层会调用到内核或框架提供的功能。
* **逻辑推理:**
    * **假设输入:** Frida 项目的源代码目录，Meson 构建目录，以及用户指定的打包格式 (`--formats`)。
    * **输出:**  一个或多个压缩包文件（例如 `frida-1.2.3.tar.gz`, `frida-1.2.3.zip`），包含源代码。
* **用户/编程常见错误:**
    * **未提交的代码:**  如果用户在运行 `mdist.py` 时有未提交的 Git 或 Mercurial 更改，默认情况下会报错，除非使用了 `--allow-dirty` 参数。这可以避免打包包含意外修改的代码。
    * **指定的格式错误:**  如果用户使用 `--formats` 参数指定了不支持的压缩格式，程序会报错并提示允许的格式。
* **用户操作到达此处的步骤:**  通常，开发者或发布者会在 Frida 项目的构建目录中，使用 Meson 提供的 `dist` 命令来触发这个脚本。例如：
    1. `cd build_directory`
    2. `meson dist`  (这会调用 `mdist.py` 并传递相应的参数)

**2. 处理版本控制系统:**

* **功能:**  `mdist.py` 可以识别项目是否使用了 Git 或 Mercurial，并利用相应的工具（`git archive` 或 `hg archive`）来创建源代码归档。这确保了打包的源代码是指定版本控制下的快照。
* **逆向相关性:**  对于逆向工程，了解特定 Frida 版本的源代码非常重要，因为不同版本的 API 和行为可能有所不同。通过版本控制信息，可以准确地对应到特定版本的 Frida 实现。
* **二进制底层/Linux/Android内核/框架知识:**  Git 和 Mercurial 是流行的版本控制系统，它们本身不直接操作二进制或内核，但它们管理的代码可能涉及这些领域。
* **逻辑推理:**
    * **假设输入:** Frida 项目的源代码目录，其中包含 `.git` 或 `.hg` 目录。
    * **输出:**  一个包含项目源代码的压缩包，其内容反映了版本控制系统中的特定提交状态。
* **用户/编程常见错误:**
    * **在非版本控制目录下运行:**  如果项目没有使用 Git 或 Mercurial，`mdist.py` 会报错。
* **用户操作到达此处的步骤:**  如上所述，用户通过 `meson dist` 命令触发，Meson 会根据项目根目录是否存在 `.git` 或 `.hg` 目录来判断使用哪个分支进行打包。

**3. 支持包含子项目:**

* **功能:**  通过 `--include-subprojects` 参数，可以将项目依赖的子项目的源代码也包含到分发包中。
* **逆向相关性:**  Frida 可能会依赖一些子项目，例如用于处理 DWARF 调试信息的库。包含子项目的源代码可以让逆向工程师更全面地了解 Frida 的构建和依赖关系。
* **二进制底层/Linux/Android内核/框架知识:**  子项目可能包含与二进制处理、操作系统交互相关的代码。
* **逻辑推理:**
    * **假设输入:** Frida 项目的源代码目录，Meson 构建配置中定义了子项目，并且用户指定了 `--include-subprojects`。
    * **输出:**  一个包含主项目和其子项目源代码的压缩包。
* **用户操作到达此处的步骤:**  用户需要在运行 `meson dist` 命令时加上 `--include-subprojects` 参数。

**4. 运行自定义分发脚本:**

* **功能:**  Frida 的构建系统可以定义一些在创建分发包时需要运行的自定义脚本 (dist scripts)。`mdist.py` 的 `run_dist_scripts` 函数负责执行这些脚本。
* **逆向相关性:**  这些自定义脚本可能执行一些额外的处理，例如修改文件、生成特定的配置文件等。了解这些脚本的操作有助于理解最终分发包的内容。
* **二进制底层/Linux/Android内核/框架知识:**  自定义脚本可以执行任何操作，因此可能涉及到与底层系统交互。
* **逻辑推理:**
    * **假设输入:** Frida 项目的 Meson 构建配置中定义了分发脚本。
    * **输出:**  在创建分发包的过程中，会执行这些脚本，可能会修改输出目录的内容。
* **用户操作到达此处的步骤:**  这些脚本通常由 Frida 的开发者定义，用户在执行 `meson dist` 时会自动触发。

**5. 创建校验和文件:**

* **功能:**  `create_hash` 函数为生成的分发包创建 SHA256 校验和文件 (`.sha256sum`)。
* **逆向相关性:**  校验和文件用于验证下载的分发包是否完整且未被篡改。对于需要确保 Frida 安全性的逆向工程师来说，这是一个重要的步骤。
* **二进制底层/Linux/Android内核/框架知识:**  校验和计算是一种通用的数据完整性验证方法，与特定的操作系统或内核无关。
* **逻辑推理:**
    * **假设输入:** 一个分发包文件。
    * **输出:**  一个包含该文件 SHA256 校验和的 `.sha256sum` 文件。
* **用户操作到达此处的步骤:**  在 `mdist.py` 成功创建分发包后，会自动生成校验和文件。

**6. 执行分发包的构建和测试:**

* **功能:**  通过 `check_dist` 函数，`mdist.py` 可以将生成的分发包解压到一个临时目录，并在该目录下执行构建和测试步骤，以验证分发包是否可以正常构建和工作。
* **逆向相关性:**  这确保了分发包的可用性。如果构建或测试失败，说明分发包存在问题。
* **二进制底层/Linux/Android内核/框架知识:**  构建和测试过程会涉及到编译 C 代码、链接库、运行测试用例，这些都与底层系统密切相关。
* **逻辑推理:**
    * **假设输入:**  一个生成的分发包文件。
    * **输出:**  如果构建和测试成功，则清理临时目录；否则，报告错误。
* **用户操作到达此处的步骤:**  这是 `mdist.py` 的一个可选步骤，可以通过不使用 `--no-tests` 参数来触发。

**7. 处理 "dirty" 仓库状态:**

* **功能:**  `handle_dirty_opt` 函数用于处理当 Git 或 Mercurial 仓库有未提交更改时的情况。默认情况下，会报错并阻止创建分发包，除非使用了 `--allow-dirty` 参数。
* **逆向相关性:**  确保分发包是基于一个已知的、干净的版本库状态，避免包含意外的修改。
* **二进制底层/Linux/Android内核/框架知识:**  与版本控制系统相关。
* **逻辑推理:**
    * **假设输入:**  Git 或 Mercurial 仓库的状态（是否有未提交的更改）。
    * **输出:**  如果仓库是 "dirty" 且未使用 `--allow-dirty`，则程序退出并报错；否则，发出警告（如果使用了 `--allow-dirty`）或继续执行。
* **用户操作到达此处的步骤:**  在运行 `meson dist` 之前，如果本地仓库有未提交的更改，就会触发这个检查。

**用户操作一步步到达 `mdist.py` 的调试线索:**

1. **用户尝试创建 Frida 的分发包。** 这可能是 Frida 的开发者或发布者。
2. **用户进入 Frida 项目的构建目录。**
3. **用户执行 Meson 的 `dist` 命令:**  `meson dist [options]`。
4. **Meson 构建系统解析 `meson.build` 文件，找到与 `dist` 目标相关的定义。**
5. **Meson 调用 `mdist.py` 脚本，并将用户提供的选项作为参数传递给它。**  例如，如果用户使用了 `--formats=zip,gztar`，那么 `options.formats` 的值将会是 `"zip,gztar"`。
6. **`mdist.py` 脚本开始执行，首先解析命令行参数 (使用 `add_arguments`)。**
7. **脚本检查当前目录是否是 Meson 构建目录 (通过查找 `meson-private/build.dat`)。**
8. **脚本检测项目是否使用了 Git 或 Mercurial (`is_git`, `is_hg`)。**
9. **根据检测到的版本控制系统，创建 `GitDist` 或 `HgDist` 对象。**
10. **`GitDist` 或 `HgDist` 对象调用相应的版本控制工具来创建源代码归档。**
11. **如果指定了 `--include-subprojects`，脚本会处理子项目。**
12. **如果定义了分发脚本，`run_dist_scripts` 函数会执行这些脚本。**
13. **脚本根据 `--formats` 参数创建指定格式的压缩包。**
14. **如果未使用 `--no-tests`，脚本会调用 `check_dist` 来验证生成的分发包。**
15. **最后，脚本使用 `create_hash` 为每个生成的分发包创建校验和文件。**

总而言之，`mdist.py` 是 Frida 构建系统中一个关键的自动化工具，负责将源代码打包成可分发的格式，并进行一些基本的验证。它的功能与逆向工程密切相关，因为分发包是逆向工程师获取 Frida 源代码和使用 Frida 的起点。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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