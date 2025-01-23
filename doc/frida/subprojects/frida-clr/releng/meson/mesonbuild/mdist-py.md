Response:
Let's break down the thought process to analyze this Python script for Frida's distribution.

1. **Understand the Goal:** The script's name (`mdist.py`) and location (`frida/subprojects/frida-clr/releng/meson/mesonbuild/`) strongly suggest it's part of the build and release process, specifically for creating distribution packages. The presence of `frida-clr` indicates it's focused on the .NET CLR integration within Frida.

2. **Identify Key Modules and Imports:**  Skimming the imports gives a high-level overview of the script's functionality:
    * `abc`: Abstract Base Classes – hints at a structured, potentially extensible design.
    * `argparse`: Command-line argument parsing – confirms it's a standalone script.
    * `gzip`, `tarfile`, `zip`, `lzma`: Archive handling – central to distribution creation.
    * `os`, `shutil`, `subprocess`, `tempfile`: System-level operations, file manipulation, running external commands.
    * `hashlib`: Generating checksums for integrity.
    * `glob`, `pathlib`: File system path manipulation.
    * `mesonbuild.*`:  Interaction with the Meson build system – crucial for understanding how it integrates into Frida's build.

3. **Analyze the Main Functions and Classes:**

    * **`add_arguments(parser)`:** Defines the command-line options the script accepts (e.g., `--allow-dirty`, `--formats`, `--include-subprojects`). This is the entry point for user interaction.

    * **`create_hash(fname)`:**  A utility function to generate SHA256 checksums for the created archives. Important for verifying the integrity of the downloaded files.

    * **`handle_dirty_opt(msg, allow_dirty)`:**  Manages the behavior when the source repository has uncommitted changes. A common concern in release processes.

    * **`is_git(src_root)`, `is_hg(src_root)`:** Checks the version control system used for the project. This suggests the script adapts its behavior based on the VCS.

    * **`Dist` (Abstract Base Class):**  The core abstraction for creating distributions. It defines common attributes and the abstract `create_dist` method, indicating different strategies for Git and Mercurial.

    * **`GitDist(Dist)`:**  Handles distribution creation for Git repositories. The methods like `copy_git`, `process_git_project`, and `process_submodules` are central to this.

    * **`HgDist(Dist)`:** Handles distribution creation for Mercurial repositories. It has its own `create_dist` implementation.

    * **`run_dist_scripts()`:**  Executes custom scripts defined in the Meson build definition during the distribution process.

    * **`run_dist_steps(...)`:**  A utility function to build and test the distribution package in a temporary environment.

    * **`check_dist(...)`:** Orchestrates the process of unpacking the generated archive, building it, running tests, and installing it in a temporary directory. This verifies the distribution is functional.

    * **`create_cmdline_args(bld_root)`:**  Extracts the Meson command-line arguments used for the original build. This ensures the test build uses the same configuration.

    * **`determine_archives_to_generate(options)`:** Parses the `--formats` command-line option to determine the archive types to create.

    * **`run(options)`:** The main entry point of the script. It loads the Meson build data, determines the VCS, instantiates the appropriate `Dist` subclass, creates the archives, and optionally runs tests.

4. **Connect to Reverse Engineering:**

    * **Distribution for Analysis:** The generated distribution packages are the *output* of the build process. These packages are often the target of reverse engineering efforts. A reverse engineer might download these archives to analyze the compiled binaries, libraries, and supporting files.

    * **Source Code Inclusion:** The `--include-subprojects` option is relevant. If source code is included, it makes reverse engineering easier.

    * **Testing and Validation:** The `check_dist` function highlights the importance of testing the distribution. Ensuring the package builds and runs correctly is a basic quality assurance step, but it also means that reverse engineers are likely dealing with a functional, tested build.

5. **Identify Binary/Kernel/Framework Involvement:**

    * **CLR Focus:** The script is within `frida-clr`, so it inherently deals with the .NET Common Language Runtime. Distribution packages will contain CLR assemblies (DLLs).

    * **Frida's Nature:**  Frida is a dynamic instrumentation toolkit, meaning it interacts deeply with the target process's memory and execution. While this script doesn't *directly* manipulate memory or kernel structures, it's responsible for packaging the tools that *do*.

    * **Platform Specifics (Implicit):**  While not explicitly in the code, the fact that it's creating distribution packages implies there are platform-specific builds of Frida. The archives might contain different binaries for Linux, Android, Windows, etc.

6. **Look for Logical Reasoning and Assumptions:**

    * **VCS Detection:** The script assumes the presence of `.git` or `.hg` directories to determine the VCS. This could fail if the project isn't under version control or uses a different system.

    * **Submodule Handling (Git):** The `GitDist` class has logic to handle Git submodules, assuming they are correctly initialized and checked out.

    * **Distribution Script Execution:** The `run_dist_scripts` function assumes that the custom scripts defined in the Meson build are executable and handle necessary environment variables.

7. **Consider User Errors:**

    * **Incorrect `--formats`:**  Specifying an invalid archive format will cause the script to exit.
    * **Running in the Wrong Directory:** The script checks if it's run within a Meson build directory.
    * **Dirty Repository without `--allow-dirty`:** The script will prevent creating a distribution with uncommitted changes unless the user explicitly allows it.

8. **Trace User Steps (Debugging Clue):**

    A user would typically reach this script by:
    1. Building Frida using Meson (e.g., `meson setup _build`, `ninja -C _build`).
    2. Navigating to the build directory (`_build` in the example).
    3. Running the `meson dist` command (or a similar command that internally calls this script) to create distribution packages. The `-C` option allows running `meson dist` from a different directory. The location of the script relative to the build directory is how Meson finds and executes it.

By following these steps, you can systematically understand the purpose, functionality, and implications of this Python script within the larger Frida project. The iterative process of examining imports, functions, and classes, and then connecting them to broader concepts like reverse engineering and system-level interactions, is key to a comprehensive analysis.
This Python script, `mdist.py`, is a crucial part of the Frida build process, specifically for creating distribution packages of the `frida-clr` component (the .NET CLR integration within Frida). Let's break down its functionalities:

**Core Functionalities:**

1. **Creates Distribution Archives:** The primary function is to package the source code of `frida-clr` into various archive formats (like `.tar.gz`, `.tar.xz`, `.zip`). This allows users to download and build Frida without needing the entire Git repository history.

2. **Handles Git and Mercurial Repositories:** The script intelligently detects whether the source code is managed by Git or Mercurial and uses the appropriate tools (`git archive` or `hg archive`) to create the source archive.

3. **Manages Subprojects:** It can optionally include the source code of subprojects that `frida-clr` depends on, making the distribution self-contained for building.

4. **Executes Distribution Scripts:** It supports running custom scripts defined in the Meson build system during the distribution process. This allows for custom actions like modifying files or generating additional content in the archive.

5. **Verifies Distribution Packages:**  It can optionally build and test the generated distribution package in a temporary environment to ensure it's functional. This involves running the Meson build, compiling, and running the unit tests within the unpacked archive.

6. **Generates Checksums:**  After creating the archives, it generates SHA256 checksum files (`.sha256sum`) for each archive to verify their integrity during download.

7. **Handles Dirty Repositories:** It can warn or prevent the creation of distribution packages if the Git or Mercurial repository has uncommitted changes, ensuring that the released source corresponds to a specific commit.

8. **Parses Command-Line Arguments:** It uses `argparse` to handle command-line options like specifying archive formats, allowing dirty repositories, and including subprojects.

**Relationship with Reverse Engineering:**

This script directly relates to reverse engineering by **creating the artifacts that are often the target of reverse engineering**.

* **Example:** A reverse engineer wanting to understand how Frida interacts with the .NET CLR might download a distribution package created by this script. They would then unpack the archive and analyze the source code (if included), the build scripts, and potentially the compiled binaries within the package. This allows them to study the implementation details and potentially identify vulnerabilities or understand Frida's internal workings.

**Involvement of Binary, Linux, Android Kernel & Framework Knowledge:**

While the Python script itself doesn't directly interact with the binary level or the kernel, it facilitates the distribution of software that heavily relies on these areas.

* **Binary Level:** The distribution packages generated by this script will eventually contain compiled binaries (e.g., shared libraries, executables) that are the core of Frida. Reverse engineers analyze these binaries.
* **Linux:**  The script uses standard Linux tools like `tar`, `gzip`, `xz`, and `shutil`. The created archives are often targeted for Linux systems. The script also uses `subprocess` to execute Git and Mercurial commands, which are common on Linux.
* **Android Kernel & Framework:**  While this specific script is for `frida-clr`, Frida itself is heavily used on Android. The distribution mechanism is similar across Frida's components. A distribution package for Frida on Android would contain binaries and potentially source code that interacts with the Android framework and potentially the kernel (through Frida's instrumentation capabilities).

**Logical Reasoning (Assumption, Input, Output):**

* **Assumption:** The script assumes the presence of a valid Meson build environment in the specified working directory.
* **Input:**
    * **Working Directory (`-C`):** The directory containing the Meson build files.
    * **Allow Dirty Flag (`--allow-dirty`):** A boolean indicating whether to proceed with uncommitted changes.
    * **Formats (`--formats`):** A comma-separated list of desired archive formats (e.g., "gztar,zip").
    * **Include Subprojects Flag (`--include-subprojects`):** A boolean indicating whether to include subproject source code.
    * **No Tests Flag (`--no-tests`):** A boolean indicating whether to skip building and testing the generated package.
* **Output:**
    * A list of created archive filenames (e.g., `frida-clr-X.Y.Z.tar.xz`, `frida-clr-X.Y.Z.tar.gz`).
    * Corresponding checksum files (e.g., `frida-clr-X.Y.Z.tar.xz.sha256sum`).
    * (If tests are run) Output from the build and test processes, indicating success or failure.

**User or Programming Common Usage Errors:**

1. **Specifying Invalid Archive Format:** If a user provides a format in `--formats` that is not in `archive_choices` (e.g., `--formats=rar`), the script will exit with an error message: `ValueError: Value "rar" not one of permitted values ['gztar', 'xztar', 'zip'].`

2. **Running the Script Outside a Build Directory:** If the script is run in a directory that doesn't contain the necessary Meson build files (specifically `meson-private/build.dat`), it will raise a `MesonException`: `mesonbuild.mesonlib.MesonException: Directory '/path/to/wrong/directory' does not seem to be a Meson build directory.`

3. **Forgetting `--allow-dirty` with Uncommitted Changes:** If a user tries to create a distribution when the Git repository has uncommitted changes and doesn't use `--allow-dirty`, the script will print an error message and exit:
   ```
   frida/subprojects/frida-clr/releng/meson/mesonbuild/mdist.py:49: ERROR: Repository has uncommitted changes that will not be included in the dist tarball
   Use --allow-dirty to ignore the warning and proceed anyway
   ```

4. **Misspelling Command-Line Arguments:**  Typos in argument names (e.g., `--includ-subprojects`) will be ignored by `argparse`, potentially leading to unexpected behavior (e.g., subprojects not being included).

**User Operation Steps to Reach Here (Debugging Clue):**

To trigger the execution of `mdist.py`, a user would typically perform the following steps:

1. **Configure the Frida Build with Meson:**
   ```bash
   meson setup _build
   cd _build
   ```

2. **Navigate to the Build Directory:** The `mdist.py` script expects to be run from within or with a reference to a valid Meson build directory.

3. **Execute the Meson Dist Command:** The user would then run the `meson dist` command, often with optional arguments:
   ```bash
   meson dist
   ```
   or with specific options:
   ```bash
   meson dist --formats=zip,gztar --include-subprojects
   ```
   The `meson` command internally calls the `mdist.py` script (or a similar script depending on the specific component being distributed) based on the current build configuration. The `-C` argument can be used to specify the build directory if the user is not currently in it:
   ```bash
   meson dist -C _build
   ```

**In summary, `mdist.py` is a vital part of the Frida release process for the `frida-clr` component. It automates the creation of source distribution packages, handles version control, allows for customization through scripts, and helps ensure the quality of the released artifacts. These packages are the starting point for many users and, importantly, for reverse engineers who wish to understand the inner workings of Frida.**

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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