Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to grasp the script's purpose. The filename `mdist.py` and the context of `fridaDynamic instrumentation tool` strongly suggest this script is responsible for creating distribution packages of Frida. The comments at the beginning confirm this, mentioning "dist tarball."

**2. High-Level Overview - Deconstructing the Code:**

Next, I'd skim through the code to get a feel for its structure and key components. I'd look for:

* **Imports:** These give hints about the functionalities being used (e.g., `os`, `shutil` for file manipulation, `subprocess` for external commands, `tarfile`, `gzip`, `lzma`, `zip` for archiving, `hashlib` for checksums, `argparse` for command-line arguments).
* **Function Definitions:**  These are the building blocks of the script. I'd note down the important ones and their apparent roles:
    * `add_arguments`:  Likely handles command-line argument parsing.
    * `create_hash`:  Generates SHA256 checksums.
    * `handle_dirty_opt`: Deals with uncommitted changes in version control.
    * `is_git`, `is_hg`:  Detects the version control system.
    * The `Dist`, `GitDist`, and `HgDist` classes:  These seem to be the core logic for creating the distributions, with specific implementations for Git and Mercurial.
    * `run_dist_scripts`: Executes custom scripts during the distribution process.
    * `run_dist_steps`:  Performs the build, test, and install steps within a distribution check.
    * `check_dist`:  Tests the generated distribution package.
    * `create_cmdline_args`:  Constructs command-line arguments for Meson.
    * `determine_archives_to_generate`:  Parses the desired archive formats.
    * `run`:  The main function that orchestrates the entire process.
* **Class Structure:**  The inheritance relationship between `Dist`, `GitDist`, and `HgDist` is important. It suggests a base class with common functionality and specialized subclasses for different version control systems.
* **Key Variables and Constants:**  Things like `archive_choices`, `archive_extension`, and `msg_uncommitted_changes` are worth noting.

**3. Detailed Analysis - Connecting to the Prompt's Questions:**

Now, I'd go through the code more carefully, addressing each part of the prompt:

* **Functionality:**  Based on the code and the high-level overview, I'd list the core functionalities: creating source archives, handling version control, running custom scripts, and testing the generated packages.

* **Relationship to Reverse Engineering:**  This requires connecting the script's actions to typical reverse engineering workflows. The key here is the *distribution of source code*. Reverse engineers often obtain software through official distributions. This script *creates* those distributions, making it the initial step in the process for someone wanting to analyze Frida's source.

* **Binary/Low-Level, Linux/Android Kernel/Framework:** Look for interactions with the operating system and potential hooks into lower-level systems.
    * `subprocess`:  This is a strong indicator of interaction with external commands, which can involve compiling code (`ninja`), running tests, and potentially interacting with the underlying OS.
    * The mention of "install" and `DESTDIR` hints at file system manipulation common in software deployment.
    * The use of `shutil.make_archive` creates compressed files, which are binary formats.
    * While the script itself doesn't directly interact with the Linux/Android kernel, the *output* it creates (the Frida distribution) contains the code that *does*. It's a preparatory step.

* **Logical Reasoning (Assumptions and Outputs):**  Focus on the decision points and transformations of data.
    * **Input:** Command-line arguments (e.g., `--formats`, `--include-subprojects`), the presence of Git or Mercurial repositories.
    * **Process:**  The script checks for version control, copies files, potentially runs scripts, creates archives.
    * **Output:**  `.tar.xz`, `.tar.gz`, or `.zip` files containing the source code, and `.sha256sum` files.

* **Common User Errors:** Think about how a user might misuse the script or encounter issues.
    * Incorrect `wd` (working directory).
    * Specifying invalid archive formats.
    * Not having Git or Mercurial installed when required.
    * Running the script in a directory that isn't a Meson build directory.
    * Ignoring warnings about uncommitted changes.

* **User Journey and Debugging:** Trace the execution flow from the command line.
    * The user runs `meson dist`.
    * Meson, in turn, executes this `mdist.py` script.
    * The script parses arguments, checks for version control, creates the distribution, and optionally tests it. The provided `print` statements in the code are key debugging indicators.

**4. Refinement and Structuring the Answer:**

Finally, organize the gathered information into a clear and structured response, addressing each point in the prompt. Use headings and bullet points to improve readability. Provide concrete code examples where possible to illustrate your points. Ensure the language is precise and avoids jargon where possible, or explains it clearly.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the details of the Git/Mercurial commands. However, realizing the prompt asks about *reverse engineering* made me shift focus to the *output* of the script – the source code distribution – and how that's the starting point for reverse engineering. Similarly, while the script itself doesn't directly touch the kernel, acknowledging that the *distributed code* does is an important distinction. I also made sure to explicitly connect the `subprocess` calls to the build and test process, which is a common step in software development and related to the content of the distribution.
这个Python源代码文件 `mdist.py` 是 Frida 动态 Instrumentation 工具中负责创建 **源代码分发包 (distribution package)** 的一个模块。它的主要目标是将项目的源代码打包成不同的存档格式，以便用户可以下载、构建和使用 Frida。

下面详细列举它的功能，并根据你的要求进行说明：

**主要功能:**

1. **创建源代码存档:**
   - 支持多种存档格式：`gztar` (gzip 压缩的 tar 包), `xztar` (xz 压缩的 tar 包), `zip`。
   - 默认格式是 `xztar`。
   - 可以通过命令行参数 `--formats` 指定要生成的存档格式。
   - 使用 `shutil.make_archive` 或 `subprocess` 调用 `hg archive` 来创建存档。

2. **处理版本控制系统:**
   - **Git 支持 (GitDist 类):**
     - 检查当前源代码仓库是否是 Git 仓库。
     - 检查是否存在未提交的更改。如果存在，会发出警告或错误，除非使用了 `--allow-dirty` 参数。
     - 使用 `git archive` 命令将源代码打包。
     - 可以处理 Git 子模块，并将子模块的代码包含在分发包中。
   - **Mercurial 支持 (HgDist 类):**
     - 检查当前源代码仓库是否是 Mercurial 仓库。
     - 检查是否存在未提交的更改，行为与 Git 类似。
     - 使用 `hg archive` 命令将源代码打包。
     - **不支持**包含子项目 (`--include-subprojects` 在 Mercurial 中无效)。

3. **包含子项目源代码:**
   - 通过 `--include-subprojects` 命令行参数控制。
   - 如果启用，并且项目使用了 Meson 子项目功能，会将子项目的源代码也包含在分发包中。
   - 对于 Git 子项目，会使用 `git archive` 从子项目的仓库中提取代码。
   - 对于非 Git 子项目，会直接使用 `shutil.copytree` 复制子项目目录。

4. **运行自定义分发脚本:**
   - 支持在分发包创建过程中运行自定义脚本。
   - 这些脚本在 `meson.build` 文件中通过 `dist_scripts` 定义。
   - 脚本运行时会设置一些环境变量，例如：
     - `MESON_DIST_ROOT`: 分发包的根目录。
     - `MESON_SOURCE_ROOT`: 原始源代码根目录。
     - `MESON_BUILD_ROOT`: 构建目录。
     - `MESON_PROJECT_DIST_ROOT`, `MESON_PROJECT_SOURCE_ROOT`, `MESON_PROJECT_BUILD_ROOT`:  如果涉及到子项目，则指向子项目的对应目录。
   - 脚本可以使用 `meson rewrite` 工具来修改分发包中的文件。

5. **测试生成的分发包:**
   - 通过 `--no-tests` 命令行参数控制是否进行测试。
   - 如果不禁用测试，会创建一个临时的构建环境，解压分发包，并尝试构建、测试和安装 Frida。
   - 使用 `meson setup`, `ninja`, `ninja test`, `ninja install` 等命令进行测试。
   - 通过检查构建、测试和安装是否成功来验证分发包的完整性。

6. **生成 SHA256 校验和:**
   - 为每个生成的分发包创建一个 `.sha256sum` 文件，用于验证文件完整性。
   - 使用 `hashlib.sha256` 计算校验和。

**与逆向方法的关系 (举例说明):**

这个脚本本身不是直接进行逆向操作的工具，但它是逆向工程的 **准备阶段** 的关键部分。

* **获取源代码进行分析:** 逆向工程师通常需要获取目标软件的源代码才能进行深入分析。`mdist.py` 的作用正是将 Frida 的源代码打包成可供下载和研究的格式。逆向工程师可以通过下载由 `mdist.py` 生成的分发包，获得 Frida 的完整源代码，然后使用各种静态分析工具（例如代码编辑器、代码搜索工具）来理解 Frida 的内部结构和工作原理。
* **理解构建过程:** 分发包中包含了构建 Frida 所需的 `meson.build` 文件。逆向工程师可以通过分析这些构建文件，了解 Frida 的编译选项、依赖关系等信息，这有助于理解 Frida 的构建过程和潜在的注入点。
* **运行自定义分发脚本进行初步修改:**  虽然主要目的是打包，但自定义分发脚本的概念意味着在打包前可以对源代码进行一些修改。例如，可以添加一些调试符号或日志信息到源代码中，然后再打包，这为后续的逆向调试提供了便利。

**二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

虽然这个 Python 脚本本身是高级语言，但它所处理的对象和执行的操作与底层系统知识紧密相关：

* **二进制文件操作 (创建存档):** 生成 `.tar.gz`, `.tar.xz`, `.zip` 文件涉及对二进制数据的压缩和打包操作。理解这些存档格式的内部结构有助于理解分发包的组织方式。
* **Linux 命令的使用 (subprocess):** 脚本大量使用 `subprocess` 模块来执行 Linux 命令，例如 `git`, `hg`, `tar`, `gzip`, `xz`, `zip`, `ninja` 等。理解这些命令的功能和参数对于理解脚本的行为至关重要。例如，`git archive` 命令涉及到 Git 对象模型和文件存储方式。
* **构建系统 (Meson, Ninja):**  脚本使用 Meson 作为构建系统，并调用 Ninja 进行实际的编译。理解构建系统的原理对于理解 Frida 的编译过程至关重要。Frida 本身会涉及到与操作系统内核的交互，因此构建过程可能包含针对特定内核版本的编译选项。
* **软件分发和安装:** 脚本中的测试步骤包括 `ninja install`，这涉及到将编译后的二进制文件安装到系统中。理解 Linux 下的软件安装路径和文件组织方式（例如 `/usr/bin`, `/usr/lib` 等）是必要的。
* **环境变量:** 脚本中设置和使用了多个环境变量（例如 `DESTDIR`），这些环境变量在 Linux 系统中用于控制程序的行为。理解环境变量的作用有助于理解 Frida 的构建和安装过程。
* **子模块和依赖管理:**  处理 Git 子模块意味着理解 Git 如何管理项目依赖。这与 Frida 可能依赖于其他库或组件有关，而这些依赖可能以子模块的形式存在。

**逻辑推理 (假设输入与输出):**

假设用户在 Frida 源代码根目录下运行以下命令：

```bash
meson dist --formats zip,gztar --include-subprojects
```

**假设输入:**

* `options.wd`: 当前工作目录，指向 Frida 的构建目录。
* `options.formats`: 字符串 "zip,gztar"。
* `options.include_subprojects`: `True`。
* 假设 Frida 的源代码仓库是一个 Git 仓库。
* 假设 Frida 项目使用了 Meson 子项目。

**逻辑推理过程:**

1. `determine_archives_to_generate(options)` 将 `--formats` 解析为 `['zip', 'gztar']`。
2. `run(options)` 函数加载构建信息。
3. 由于是 Git 仓库，将使用 `GitDist` 类。
4. `GitDist.create_dist(['zip', 'gztar'])` 被调用：
   - `process_git_project` 函数使用 `git archive` 将主项目的源代码打包到 `meson-dist/frida-<version>` 目录。
   - 如果 `options.include_subprojects` 为 `True`，则遍历子项目，并使用 `git archive` 或 `shutil.copytree` 将子项目的源代码复制到 `meson-dist/frida-<version>/<子项目路径>`。
   - `run_dist_scripts` 函数执行 `meson.build` 中定义的自定义分发脚本。
   - 使用 `shutil.make_archive` 创建 `frida-<version>.zip` 和 `frida-<version>.tar.gz` 两个存档文件。
5. 如果 `options.no_tests` 为 `False` (默认情况)，则调用 `check_dist` 函数对生成的第一个存档 (`frida-<version>.zip`) 进行测试。
   - 创建临时目录 `dist-unpack`, `dist-build`, `dist-install`。
   - 将 `frida-<version>.zip` 解压到 `dist-unpack` 目录。
   - 在 `dist-build` 目录中使用 `meson setup` 配置构建。
   - 使用 `ninja` 进行编译。
   - 使用 `ninja test` 运行测试。
   - 使用 `ninja install` 将文件安装到 `dist-install` 目录。
   - 如果所有步骤都成功，则删除临时目录。
6. `create_hash` 函数为 `frida-<version>.zip` 和 `frida-<version>.tar.gz` 分别生成 `.sha256sum` 文件。

**预期输出:**

* 在构建目录下生成 `meson-dist` 目录，其中包含 `frida-<version>` 目录，里面是解压后的源代码。
* 在 `meson-dist` 目录下生成 `frida-<version>.zip` 和 `frida-<version>.tar.gz` 两个存档文件。
* 在 `meson-dist` 目录下生成 `frida-<version>.zip.sha256sum` 和 `frida-<version>.tar.gz.sha256sum` 两个校验和文件。
* 如果测试未禁用，并且测试通过，则会打印 "Created frida-<version>.zip" 和 "Created frida-<version>.tar.gz" 等信息。

**用户或编程常见的使用错误 (举例说明):**

1. **在非 Meson 构建目录下运行:**
   - 错误信息: `Directory '<工作目录>' does not seem to be a Meson build directory.`
   - 说明: 用户需要在已经使用 `meson setup` 配置过的构建目录下运行 `meson dist`。

2. **指定的存档格式无效:**
   - 假设用户运行 `meson dist --formats rar`。
   - 错误信息: `Value "rar" not one of permitted values ['gztar', 'xztar', 'zip'].`
   - 说明: 用户只能指定 `gztar`, `xztar` 或 `zip` 作为存档格式。

3. **在存在未提交更改的 Git 仓库中运行且未指定 `--allow-dirty`:**
   - 错误信息: `Repository has uncommitted changes that will not be included in the dist tarball\nUse --allow-dirty to ignore the warning and proceed anyway`
   - 说明:  如果 Git 仓库有未提交的更改，`mdist.py` 默认会阻止创建分发包，除非用户明确使用 `--allow-dirty` 忽略此警告。

4. **Mercurial 项目中使用了 `--include-subprojects`:**
   - 错误信息: `--include-subprojects option currently not supported with Mercurial`
   - 说明:  当前版本 `mdist.py` 不支持在 Mercurial 项目中包含子项目。

5. **缺少必要的工具 (Git 或 Mercurial):**
   - 如果在 Git 或 Mercurial 项目中运行，但系统中没有安装对应的版本控制工具，会因为找不到命令而报错。例如，如果系统中没有安装 Git，则会报类似 `FileNotFoundError: [Errno 2] No such file or directory: 'git'` 的错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要为 Frida 创建一个源代码分发包进行研究或分享。以下是可能的操作步骤：

1. **克隆 Frida 的源代码仓库:** 用户首先需要获取 Frida 的源代码，通常是通过 Git 克隆官方仓库：
   ```bash
   git clone https://github.com/frida/frida.git
   cd frida
   ```

2. **创建构建目录并使用 Meson 配置:** 用户需要在 Frida 源代码目录下创建一个单独的构建目录，并使用 Meson 进行配置：
   ```bash
   mkdir build
   cd build
   meson setup ..
   ```
   或者直接在一个命令中完成：
   ```bash
   meson setup .
   ```

3. **运行 `meson dist` 命令:**  在构建目录中，用户运行 `meson dist` 命令来触发 `mdist.py` 脚本的执行：
   ```bash
   meson dist
   ```
   或者，用户可能想要指定特定的存档格式或包含子项目：
   ```bash
   meson dist --formats zip --include-subprojects
   ```

**调试线索:**

* **检查当前工作目录:** 确认用户是否在正确的 Meson 构建目录下运行 `meson dist` 命令。
* **查看 Meson 的输出:** Meson 在执行 `mdist.py` 之前和之后会有输出信息，可以查看是否有错误或警告。
* **检查 `meson-private/build.dat` 文件:**  `mdist.py` 首先会检查这个文件是否存在，以确认当前目录是否是 Meson 构建目录。
* **查看命令行参数:** 确认用户是否使用了正确的命令行参数，例如 `--formats`, `--include-subprojects`, `--allow-dirty`。
* **检查版本控制系统状态:** 如果涉及到 Git 或 Mercurial，检查仓库的状态，例如是否有未提交的更改。
* **查看生成的存档文件和校验和文件:**  确认是否生成了预期的存档文件和校验和文件，以及它们的内容是否正确。
* **如果测试失败，查看测试日志:**  如果启用了测试，可以查看临时构建目录下的日志文件，以了解测试失败的原因。
* **手动执行 `mdist.py` 脚本并添加调试信息:**  在某些情况下，可以直接运行 `mdist.py` 脚本，并在代码中添加 `print` 语句或其他调试信息，以便更详细地了解脚本的执行过程。例如：
   ```bash
   python path/to/frida/releng/meson/mesonbuild/mdist.py --formats zip
   ```

通过以上分析，可以理解 `frida/releng/meson/mesonbuild/mdist.py` 脚本在 Frida 项目中的作用，以及它与逆向工程、底层系统知识、用户操作和调试过程的联系。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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