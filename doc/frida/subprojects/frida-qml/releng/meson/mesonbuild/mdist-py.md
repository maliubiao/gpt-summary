Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Request:**

The core request is to analyze the provided Python script (`mdist.py`) from the Frida project. The prompt asks for its functions, its relation to reverse engineering, its use of low-level concepts (kernel, etc.), logical inferences, potential user errors, and how a user might reach this code.

**2. Initial Code Scan and Keyword Spotting:**

First, I'd quickly scan the code for keywords and recognizable patterns. This helps to get a high-level overview. Some things that immediately stand out are:

* **`# SPDX-License-Identifier: Apache-2.0` and `Copyright`:**  Indicates open-source licensing and authorship.
* **`fridaDynamic instrumentation tool`:**  Confirms the context.
* **`import` statements:** These are crucial for understanding dependencies and functionalities (e.g., `os`, `sys`, `shutil`, `subprocess`, `tarfile`, `gzip`, `hashlib`, `argparse`, etc.).
* **Function definitions:**  `add_arguments`, `create_hash`, `handle_dirty_opt`, `is_git`, `is_hg`, `create_dist`, `run_dist_scripts`, `process_git_project`, `process_submodules`, `run_dist_steps`, `check_dist`, `create_cmdline_args`, `determine_archives_to_generate`, `run`. These are the main building blocks of the script.
* **Class definitions:** `Dist`, `GitDist`, `HgDist`. This suggests object-oriented design for handling different version control systems.
* **Arguments like `--allow-dirty`, `--formats`, `--include-subprojects`, `--no-tests`:**  These indicate command-line options for controlling the script's behavior.
* **References to `git` and `hg`:**  Clearly points to handling Git and Mercurial repositories.
* **File extensions like `.tar.gz`, `.tar.xz`, `.zip`:**  Indicates archive creation.
* **Environment variables like `MESON_DIST_ROOT`, `MESON_SOURCE_ROOT`, etc.:** Suggests integration with the Meson build system.

**3. Analyzing Key Functions and Classes:**

Now, I'd start diving deeper into the most important parts:

* **`add_arguments`:**  This is standard `argparse` setup, defining the command-line interface.
* **`create_hash`:**  Simple SHA256 checksum generation for created archives.
* **`handle_dirty_opt`:** Deals with uncommitted changes in version control, a common concern in release processes.
* **`is_git` and `is_hg`:**  Basic checks for the presence of Git or Mercurial repositories.
* **`Dist` (Abstract Base Class):**  Defines the interface for distribution creation. The `create_dist` method is abstract, meaning subclasses must implement it. It also handles running distribution scripts.
* **`GitDist`:**  Implements distribution creation for Git repositories. The `copy_git` function is important for extracting specific revisions or subdirectories. `process_submodules` handles Git submodules.
* **`HgDist`:** Implements distribution creation for Mercurial repositories. It uses `hg archive` command.
* **`run_dist_steps`:**  Executes the build, test, and install steps within a temporary distribution environment.
* **`check_dist`:** Sets up a temporary environment, unpacks the created archive, and runs the build/test/install process. This is crucial for validating the created distribution.
* **`run`:** The main entry point. It loads Meson build data, determines the archive formats, instantiates the appropriate `Dist` subclass (based on the version control system), creates the distribution, and optionally runs tests.

**4. Connecting to the Prompt's Questions:**

With a good understanding of the code, I can now address the specific questions:

* **Functionality:** Summarize the main purpose: creating source distribution archives.
* **Reverse Engineering:**  Think about how source code helps in reverse engineering. Highlight the ability to examine algorithms, data structures, and potentially find vulnerabilities. Mention Frida's purpose in dynamic instrumentation, linking the source to deeper analysis.
* **Binary/Kernel/Framework:** Consider where the script interacts with lower-level concepts. The build process itself (invoking compilers, linkers) is a binary-level activity. Frida's nature (dynamic instrumentation) is heavily reliant on OS and potentially kernel interactions. However, *this specific script* is primarily focused on packaging the *source code*. So, the connection to the kernel is more indirect (the *resulting* built artifacts might interact with the kernel).
* **Logical Inference:**  Focus on conditional logic (e.g., choosing between `GitDist` and `HgDist`), argument parsing, and how the script flows based on options. Provide simple input/output examples.
* **User Errors:** Think about common mistakes: specifying invalid archive formats, running the script outside a Meson build directory, having uncommitted changes without using `--allow-dirty`.
* **User Path to Execution:** Trace the steps: configure the project with Meson, build it, and then explicitly run the `mdist.py` script (likely through a Meson command or directly).

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level summary and then delve into specifics. Provide concrete examples wherever possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This script directly interacts with the kernel."  **Correction:** While Frida interacts with the kernel, *this packaging script* primarily deals with source code and build processes. The kernel interaction is more in the context of what Frida *does* rather than what *this script* does directly.
* **Initial thought:** Focus heavily on the archive creation process. **Refinement:**  Also emphasize the testing and validation aspects (`check_dist`). This shows a more complete picture of the distribution workflow.
* **Ensuring examples are clear and relevant:** For instance, in the logical inference section, the example should clearly demonstrate the conditional logic being discussed.

By following these steps, including the iterative refinement, I can construct a comprehensive and accurate answer to the request.
This Python script, `mdist.py`, located within the Frida project's build system, is responsible for creating **source distribution packages**. Think of it as the tool that prepares the Frida source code for release, allowing others to build and install Frida on their systems.

Here's a breakdown of its functionalities:

**Core Functionality: Creating Source Archives**

1. **Determines the Project Details:** It reads information from the Meson build system, such as the project name and version, to name the distribution archive appropriately (e.g., `frida-core-16.x.x.tar.xz`).

2. **Handles Version Control (Git and Mercurial):**
   - **Git:**  It can create a clean snapshot of the Git repository, optionally including submodules at specific revisions. It warns or errors out if there are uncommitted changes unless the `--allow-dirty` flag is used.
   - **Mercurial (Hg):** It also supports creating archives from Mercurial repositories, but currently doesn't support including subprojects when using Hg.

3. **Creates Archives in Different Formats:** It supports creating archives in various formats like `xztar` (default), `gztar`, and `zip`. The user can specify the desired formats using the `--formats` command-line option.

4. **Includes Subprojects (Optional):**  With the `--include-subprojects` flag, it can include the source code of any subprojects used in the build. This is helpful for distributing a self-contained source package.

5. **Runs Distribution Scripts:** It executes custom scripts defined in the `meson.build` file (specified via the `dist_scripts` keyword). These scripts can perform actions like modifying files within the distribution directory before archiving.

6. **Generates Checksums:**  After creating the archives, it generates SHA256 checksum files (`.sha256sum`) for each archive to ensure integrity.

7. **Tests the Distribution (Optional):** If the `--no-tests` flag is not used, it attempts to build, test, and install the generated distribution package in a temporary directory to verify its correctness.

**Relationship to Reverse Engineering:**

This script itself doesn't directly perform reverse engineering. However, it plays a crucial role in making the **source code** of Frida available. Having the source code is extremely valuable for reverse engineers for several reasons:

* **Understanding Frida's Internals:** By examining the source, reverse engineers can gain deep insights into how Frida works, its architecture, and its capabilities. This is essential for effectively using Frida for instrumentation and analysis.
* **Identifying Hooking Mechanisms:** The source code reveals how Frida implements its hooking and instrumentation functionalities, allowing reverse engineers to understand the underlying techniques.
* **Extending Frida:**  Having the source allows developers and reverse engineers to contribute to Frida, add new features, fix bugs, or adapt it to specific needs.
* **Security Auditing:**  Security researchers can analyze the source code to identify potential vulnerabilities or weaknesses in Frida itself.

**Example:** A reverse engineer might download the source distribution created by this script to understand how Frida's JavaScript bridge interacts with the native components. They could trace the code execution within the source to see how JavaScript calls are translated into native function calls for instrumentation.

**Involvement of Binary, Linux, Android Kernel & Framework Knowledge:**

While `mdist.py` primarily deals with packaging source code, its output and the context of Frida deeply involve these areas:

* **Binary Underlying:** The ultimate goal of distributing the source is to enable the creation of binary executables and libraries. The build process that the distribution facilitates involves compiling source code into machine code, linking libraries, and creating executable files.
* **Linux/Android Kernel:** Frida, as a dynamic instrumentation tool, heavily interacts with the operating system kernel. The source code within the distribution will contain code that uses system calls, kernel APIs (on Linux), and potentially interacts with kernel modules or drivers.
* **Android Framework:**  Frida is widely used on Android. The source distribution will contain components specifically designed to interact with the Android runtime (ART), system services, and framework APIs.

**Example:**  The source code within the distribution would contain C/C++ code that uses ptrace (on Linux) or specific Android APIs to inject code into target processes or intercept function calls. A developer examining the source would need knowledge of these low-level concepts to understand how Frida achieves its instrumentation.

**Logical Inference (Hypothetical Input & Output):**

**Assumption:** We are in the root directory of the Frida Git repository.

**Input (Command Line):**

```bash
python3 ./subprojects/frida-qml/releng/meson/mesonbuild/mdist.py --formats=zip,gztar --include-subprojects
```

**Expected Output:**

1. **Archive Creation Messages:**
   ```
   Running custom dist script '...' (if any are defined)
   ```
   followed by messages indicating the creation of the archives:
   ```
   Created frida-core-16.x.x.zip
   Created frida-core-16.x.x.tar.gz
   ```
2. **Checksum Files:** Two new files, `frida-core-16.x.x.zip.sha256sum` and `frida-core-16.x.x.tar.gz.sha256sum`, will be created in the `meson-dist` subdirectory of the build directory. These files will contain the SHA256 hash of the respective archive.
3. **Subproject Inclusion:** The archives will contain the source code of any subprojects defined in the `meson.build` file.
4. **Optional Test Output:** If `--no-tests` is not implied by Meson configuration, there might be output indicating that the generated packages are being tested in a temporary environment.

**User or Programming Common Usage Errors:**

1. **Running Outside a Build Directory:** If the script is run in a directory that is not a Meson build directory (doesn't contain `meson-private/build.dat`), it will raise a `MesonException`:
   ```
   mesonbuild.mesonlib.MesonException: Directory '/path/to/wrong/directory' does not seem to be a Meson build directory.
   ```
   **How to reach here:**  The user might navigate to the `mdist.py` script's directory in their terminal and run it directly without being in the build directory.

2. **Specifying Invalid Archive Format:** If the user provides an unsupported format in the `--formats` option:
   ```bash
   python3 ./subprojects/frida-qml/releng/meson/mesonbuild/mdist.py --formats=rar
   ```
   The script will exit with an error message:
   ```
   Value "rar" not one of permitted values ['gztar', 'xztar', 'zip'].
   ```
   **How to reach here:** The user might mistype the format or try to use a format not supported by the script.

3. **Uncommitted Changes Without `--allow-dirty`:** If the Git repository has uncommitted changes and the user doesn't use `--allow-dirty`, the script will error out:
   ```
   Repository has uncommitted changes that will not be included in the dist tarball
   Use --allow-dirty to ignore the warning and proceed anyway
   ```
   **How to reach here:** The user might run the script after making changes to the code but before committing them to the Git repository.

4. **Typos in Command Line Arguments:** Incorrectly typing argument names will lead to `argparse` errors:
   ```bash
   python3 ./subprojects/frida-qml/releng/meson/mesonbuild/mdist.py --formts=zip
   ```
   This will result in an `argparse` error indicating an unrecognized argument.
   **How to reach here:**  Simple typographical errors in the command line.

**User Operation Steps to Reach `mdist.py` Execution (as a debugging clue):**

1. **Clone the Frida Repository:** A developer or release manager would typically start by cloning the Frida repository from GitHub:
   ```bash
   git clone https://github.com/frida/frida.git
   cd frida
   ```

2. **Configure the Build with Meson:** They would then create a build directory and configure the build using Meson:
   ```bash
   mkdir build
   cd build
   meson ..
   ```

3. **Build Frida (Optional):** While not strictly necessary to run `mdist.py`, typically a build would be performed at some point:
   ```bash
   ninja
   ```

4. **Generate Source Distribution:**  The command to trigger the execution of `mdist.py` (often indirectly) is usually part of the release process. It might be invoked through a Meson target or a custom script. A direct invocation could look like this (from the build directory or after `cd ..` to be in the source root):
   ```bash
   python3 ./subprojects/frida-qml/releng/meson/mesonbuild/mdist.py
   ```
   or, if integrated into a Meson target (defined in `meson.build`), it might be invoked via:
   ```bash
   ninja dist  # If a 'dist' target is defined
   ```
   Meson would then, internally, execute the `mdist.py` script.

5. **Debugging/Manual Invocation:** A developer might manually run `mdist.py` directly for debugging purposes or to test the source distribution creation process in isolation. They would navigate to the script's location and execute it with appropriate arguments.

In summary, `mdist.py` is a vital tool in the Frida project's release pipeline, responsible for packaging the source code for distribution. While not directly involved in reverse engineering, its output provides essential resources for reverse engineers to understand and extend Frida. It interacts with version control systems and supports various archive formats, and its execution is a step in the process of creating official Frida releases.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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