Response:
Let's break down the thought process to analyze this Python script for Frida's distribution.

**1. Understanding the Goal:**

The first step is to understand the high-level purpose of the script. The filename `mdist.py` and the surrounding directory structure (`frida/subprojects/frida-node/releng/meson/mesonbuild/`) strongly suggest this script is responsible for creating distribution packages for Frida, specifically within a Meson build system context for the Node.js component. The presence of "dist" in names like `Dist`, `GitDist`, and `HgDist` reinforces this idea.

**2. Identifying Key Data Structures and Classes:**

Scanning the code, the `Dist` dataclass immediately stands out. It's an abstract base class, suggesting different implementations for different version control systems. The `GitDist` and `HgDist` classes inheriting from `Dist` confirm this. The `@dataclass` decorator hints at its role in holding distribution-related data.

**3. Analyzing Core Functionality - The `Dist` Class:**

* **Purpose:** This class seems to encapsulate the common logic for creating distribution packages.
* **Key Attributes:** `dist_name`, `src_root`, `bld_root`, `dist_scripts`, `subprojects`, `options`. These clearly represent the package name, source directory, build directory, custom scripts to run during distribution, included subprojects, and command-line options.
* **Key Methods:**
    * `create_dist()`: This is an abstract method, meaning concrete subclasses must implement the actual distribution creation logic.
    * `run_dist_scripts()`: This method is responsible for executing custom scripts defined for the distribution process. It pays attention to subprojects and sets up relevant environment variables.

**4. Analyzing VCS-Specific Logic - `GitDist` and `HgDist`:**

These classes provide concrete implementations of `create_dist()`.

* **`GitDist`:**
    * Focuses on using `git archive` to create a clean snapshot of the repository.
    * Handles submodules.
    * Has logic to check for and warn about uncommitted changes.
* **`HgDist`:**
    * Uses `hg archive` for Mercurial repositories.
    * Has a warning about the lack of support for dist scripts.
    * Creates tar.xz, tar.gz, and zip archives directly.

**5. Identifying Supporting Functions:**

Several standalone functions assist in the distribution process:

* `add_arguments()`:  Sets up the command-line arguments for the script.
* `create_hash()`: Generates SHA256 checksums for the created archives.
* `handle_dirty_opt()`:  Manages the `--allow-dirty` option for uncommitted changes.
* `is_git()` and `is_hg()`: Detect the version control system.
* `run_dist_steps()`:  Orchestrates the steps to build and test the distribution package in a temporary environment.
* `check_dist()`:  The core function for building, testing, and installing the generated package in a clean environment.
* `create_cmdline_args()`:  Extracts relevant command-line arguments from the build configuration.
* `determine_archives_to_generate()`: Parses the `--formats` option.
* `run()`: The main entry point of the script, coordinating the entire distribution process.

**6. Connecting to Reverse Engineering and Low-Level Details:**

Now, specifically looking for connections to the prompt's requirements:

* **Reverse Engineering:** The script's purpose *is* related to the distribution of a dynamic instrumentation tool, Frida. Reverse engineers are the primary users of such tools. The script ensures they receive a clean, reproducible version of Frida. The `--no-tests` option is relevant, as some might skip tests during their initial setup.
* **Binary/Low-Level:** The script interacts with the underlying file system, creates archives (`tar`, `zip`), and executes shell commands (like `git`, `hg`, `ninja`). The creation of checksums (`create_hash`) is a low-level integrity check.
* **Linux/Android Kernel & Framework:** While the script itself doesn't directly touch kernel code, the *result* of this script (the Frida distribution) will be used to interact with these low-level components. The fact that it's part of the Frida Node.js binding suggests it's facilitating interaction with JavaScript, which might eventually control instrumentation of Android apps or Linux processes.
* **Logic and Assumptions:** The script assumes the presence of Git or Mercurial for source control. It makes decisions based on the `--include-subprojects` and `--formats` options. The temporary directories for testing are a key logical step to ensure a clean build.

**7. User Errors and Debugging:**

Consider common mistakes users might make:

* **Running in the wrong directory:**  The `-C` option exists to handle this, but users might forget. The script checks if it's in a Meson build directory.
* **Not having the required tools:** Git, Mercurial, and `ninja` are prerequisites. The script implicitly assumes these are available.
* **Uncommitted changes:** The script warns about this and provides the `--allow-dirty` option.
* **Incorrect format specification:** The script validates the `--formats` argument.

**8. Tracing User Interaction:**

To understand how a user reaches this script:

1. A developer working on Frida Node.js wants to create a release.
2. They navigate to the `frida/subprojects/frida-node/releng/meson/` directory (or use the `-C` option).
3. They run the `meson dist` command (or a similar command that invokes this script indirectly through Meson).
4. Meson, based on its configuration, identifies and executes `mdist.py`.
5. The command-line arguments passed to `meson dist` are parsed by `add_arguments()`.

**Self-Correction/Refinement During the Thought Process:**

Initially, I might have focused too much on the Git/Mercurial parts. It's important to broaden the view to see the overall distribution process and how the different pieces fit together. Recognizing the connection to reverse engineering and the broader context of Frida's usage is crucial. Also, explicitly considering user errors and debugging steps adds practical value to the analysis. The tracing of user interaction clarifies the script's role in the larger development workflow.
This Python script, `mdist.py`, is part of the Meson build system used by Frida to create distribution packages of the Frida Node.js bindings. Here's a breakdown of its functionality:

**Core Functionality:**

1. **Creating Source Distribution Archives:**  The primary goal is to generate archives (like `.tar.gz`, `.tar.xz`, or `.zip`) containing the source code of the Frida Node.js project. This allows users to download and build Frida Node.js from source.

2. **Handling Different Version Control Systems (VCS):**
   - **Git Support (`GitDist` class):** If the source directory is a Git repository, it uses `git archive` to create a clean snapshot of the source code, including handling submodules. It also checks for uncommitted changes and warns the user (unless `--allow-dirty` is used).
   - **Mercurial Support (`HgDist` class):** If the source directory is a Mercurial repository, it uses `hg archive` to create the source archive. It also checks for uncommitted changes. Note that it currently doesn't support including subprojects.

3. **Including Subprojects:** The `--include-subprojects` option allows the script to include the source code of any subprojects that Frida Node.js depends on. This is particularly useful for creating a self-contained source package.

4. **Running Custom Distribution Scripts:** The script supports running custom scripts defined in the `meson.build` file using the `dist_scripts` keyword. This allows for project-specific tasks to be performed during the distribution process, such as modifying files or generating additional assets.

5. **Building and Testing the Distribution Package:**  The `--no-tests` option controls whether the script attempts to build, test, and install the generated source package in a temporary environment. This helps ensure the generated package is usable.

6. **Generating Checksums:** After creating the archive(s), the script generates SHA256 checksum files (`.sha256sum`) for each archive to verify their integrity.

7. **Command-Line Options:** It provides various command-line options to control the distribution process, such as specifying the output directory, the archive formats to create, and whether to allow dirty repositories.

**Relationship to Reverse Engineering:**

This script plays an indirect but important role in the reverse engineering workflow involving Frida:

* **Providing a Reproducible Source:** By creating source distribution archives, this script ensures that reverse engineers can obtain the exact same version of Frida Node.js used by others. This is crucial for collaboration, sharing scripts, and reproducing results.
* **Facilitating Custom Builds:**  Reverse engineers often need to modify or extend Frida's functionality. Having the source code available through these archives allows them to do so. They can then build a custom version of Frida Node.js tailored to their specific needs.
* **Debugging and Understanding Frida Internals:**  Access to the source code, provided by these distribution archives, is essential for understanding how Frida works internally. Reverse engineers might examine the code to understand specific features, identify potential vulnerabilities, or debug issues they encounter.

**Example:** A reverse engineer wants to use a specific feature of Frida Node.js that was introduced in version 16.0.0. They can download the source distribution archive for that version (created by this script), build it, and then use that specific version with confidence that they have the intended functionality.

**Involvement of Binary, Linux, Android Kernel/Framework Knowledge:**

While the script itself is primarily focused on packaging and build system interactions, it touches upon these areas indirectly:

* **Binary:** The resulting distribution archives contain the source code that will eventually be compiled into binary executables and libraries. The script ensures that all necessary source files are included for this compilation process.
* **Linux:**  The script uses standard Linux tools like `tar`, `gzip`, `xz`, and `shutil` for archive creation and manipulation. The build process initiated by the `check_dist` function often involves compiling native code that interacts with the Linux operating system.
* **Android Kernel/Framework:** Frida is heavily used for instrumenting Android applications. While this script doesn't directly interact with the Android kernel or framework, the Frida Node.js bindings it packages are used to control the Frida agent that *does* interact with these low-level components on Android devices. The tests run in `check_dist` might involve basic checks relevant to how Frida interacts with the Android environment.

**Example:** When building Frida Node.js from the source package, the build system will compile native extensions that use system calls and interact with the Linux kernel or Android's Bionic library. This script ensures the necessary source code for these extensions is included.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

```bash
python mdist.py -C /path/to/frida-node/build --formats=zip,gztar --include-subprojects
```

**Assumptions:**

* `/path/to/frida-node/build` is a valid Meson build directory for Frida Node.js.
* The source code is in a Git repository.
* There are subprojects defined in the `meson.build` file.

**Expected Output:**

1. The script will change the current directory to `/path/to/frida-node/build`.
2. It will identify the Git repository and check for uncommitted changes (potentially issuing a warning if there are any).
3. It will create two archive files in the `meson-dist` subdirectory of the build directory:
   - `frida-node-X.Y.Z.zip` (where X.Y.Z is the project version) containing the Frida Node.js source and its subprojects' sources.
   - `frida-node-X.Y.Z.tar.gz` containing the same content.
4. It will generate SHA256 checksum files for both archives:
   - `frida-node-X.Y.Z.zip.sha256sum`
   - `frida-node-X.Y.Z.tar.gz.sha256sum`
5. If tests are not skipped (the default), it will create a temporary build environment, build the package from the generated archive (likely the `.zip` one), run the tests, and install it in the temporary environment.
6. If the tests pass, it will print messages indicating the successful creation of the archives and checksum files.

**User or Programming Common Usage Errors:**

1. **Running the script outside a Meson build directory:** The script checks for the existence of `meson-private/build.dat` and will raise an error if it's not found.
   ```
   Traceback (most recent call last):
     ...
   mesonbuild.mesonlib.MesonException: Directory '/invalid/path' does not seem to be a Meson build directory.
   ```

2. **Specifying invalid archive formats:** If the `--formats` argument contains values other than `gztar`, `xztar`, or `zip`, the script will exit with an error.
   ```
   Value "invalid_format" not one of permitted values ['gztar', 'xztar', 'zip'].
   ```

3. **Trying to include subprojects with Mercurial:** The script currently doesn't support `--include-subprojects` when the source is in a Mercurial repository.
   ```
   --include-subprojects option currently not supported with Mercurial
   ```

4. **Having uncommitted changes without `--allow-dirty`:** If the Git or Mercurial repository has uncommitted changes, the script will issue an error and exit, prompting the user to use `--allow-dirty`.
   ```
   Repository has uncommitted changes that will not be included in the dist tarball
   Use --allow-dirty to ignore the warning and proceed anyway
   ```

**User Operation Steps to Reach Here (Debugging Clues):**

1. **Developer wants to create a release:** A developer working on Frida Node.js decides to create a new release of the bindings.
2. **Navigate to the release engineering directory:** They would typically navigate to the `frida/subprojects/frida-node/releng/meson/` directory in their Frida source tree.
3. **Execute the Meson dist command:** They would run a command like `meson dist` (or potentially a custom script that calls `meson dist`) from the command line within that directory or a build directory associated with it.
4. **Meson invokes `mdist.py`:** The Meson build system, based on its internal logic for handling the `dist` command, identifies and executes the `mdist.py` script.
5. **Command-line arguments are parsed:** The arguments passed to `meson dist` are then parsed by the `add_arguments` function in `mdist.py`.

**As a debugging clue:** If a user reports an issue with the creation of a Frida Node.js source distribution package, understanding that `mdist.py` is the script responsible for this process is the first step. Examining the command-line arguments used, the state of the Git repository (clean or dirty), and the Meson build configuration would be key to diagnosing the problem. Error messages from this script, like those related to invalid formats or missing build files, would directly point to the source of the issue.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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