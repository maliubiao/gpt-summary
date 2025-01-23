Response:
My thinking process to analyze the Python script and answer the prompt involved these steps:

1. **Understand the Goal:** The request is to analyze the `mdist.py` script, focusing on its functionality, relationship to reverse engineering, interaction with low-level systems, logical reasoning, common user errors, and debugging context.

2. **Initial Skim for High-Level Functionality:** I quickly read through the code to get a general idea of what it does. Keywords like "dist", "archive", "git", "hg", "subprojects", and "test" immediately stood out. This told me the script is about creating distribution packages of software projects.

3. **Identify Key Components:** I started breaking down the script into its core parts:
    * **Argument Parsing:** The `add_arguments` function sets up command-line options.
    * **Archive Creation:** The `Dist`, `GitDist`, and `HgDist` classes are responsible for generating the distribution archives (tar.gz, tar.xz, zip).
    * **Version Control Integration:** The `GitDist` and `HgDist` classes handle Git and Mercurial repositories.
    * **Subproject Handling:** The script can include subprojects in the distribution.
    * **Distribution Scripts:** Custom scripts can be run as part of the distribution process.
    * **Distribution Testing:** The script includes functionality to build and test the created packages.
    * **Helper Functions:** Functions like `create_hash`, `handle_dirty_opt`, `is_git`, and `is_hg` perform supporting tasks.

4. **Analyze Functionality in Detail:**  I went back through each component, paying closer attention to the logic and how it interacts with other parts. For example:
    * How are the archive formats specified? (command-line arguments)
    * How are Git and Hg repositories handled differently? (separate classes, different commands)
    * How are subprojects included? (copying or archiving)
    * What environment variables are used for distribution scripts?
    * What are the steps involved in testing a distribution?

5. **Connect to Reverse Engineering (If Applicable):**  I considered how creating a distribution package might be relevant to reverse engineering. The most obvious connection is that a distribution package *is* the target of much reverse engineering work. It contains the binaries, libraries, and other files that are analyzed. While the script *creates* the package, understanding its structure and contents is crucial for reverse engineering. The inclusion of source code (optionally) can also be a factor.

6. **Identify Low-Level/Kernel/Framework Interactions:** I looked for code that interacts directly with the operating system, file system, or external tools. Key indicators were:
    * `subprocess.call` and `subprocess.check_call`: These execute external commands (git, hg, tar, gzip, xz, zip, ninja).
    * File system operations: `os.path`, `shutil`, `tarfile`, `gzip`, `lzma`.
    * Environment variables: Setting and using environment variables (`DESTDIR`, `MESON_DIST_ROOT`, etc.).

7. **Look for Logical Reasoning/Assumptions:** I tried to identify any explicit or implicit assumptions in the code. For instance:
    * Assumption: The project uses either Git or Mercurial for version control.
    * Assumption: The necessary command-line tools (git, hg, tar, etc.) are installed and available in the system's PATH.
    * Implicit logic in handling Git submodules by iterating through their status.

8. **Consider User Errors:** I thought about common mistakes users might make when using this script:
    * Specifying incorrect archive formats.
    * Running the script outside of a Meson build directory.
    * Not having the required version control tools installed.
    * Having uncommitted changes and not using `--allow-dirty`.
    * Issues with submodules not being properly initialized.

9. **Trace User Operations (Debugging Context):** I imagined a user wanting to create a distribution package and walked through the likely steps, leading to the execution of this script:
    1. Develop software using Meson as the build system.
    2. Make changes and commit them (or not, leading to the `--allow-dirty` scenario).
    3. Decide to create a release.
    4. Navigate to the build directory (`cd build`).
    5. Run the Meson command to create a distribution package: `meson dist`.
    6. This command internally calls the `mdist.py` script with appropriate arguments.

10. **Structure the Answer:** Finally, I organized my findings into the categories requested by the prompt, providing clear explanations and examples for each. I aimed for a balance of technical detail and understandable language. I used code snippets where helpful to illustrate specific points. I made sure to clearly label each section according to the prompt's requirements.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the Git/Hg specific parts. I realized I needed to broaden my scope to include the general distribution process and the testing aspects.
* I made sure to explicitly link the "reverse engineering" aspect by mentioning the distributed package as the target.
* I paid attention to the prompt's request for examples, making sure to provide concrete illustrations of user errors and low-level interactions.
* I double-checked my understanding of the script's flow and the purpose of different functions.

By following these steps, I could thoroughly analyze the `mdist.py` script and provide a comprehensive answer to the prompt.
This Python script, `mdist.py`, located within the `frida` project's build system, is responsible for creating distribution archives (like `.tar.gz`, `.tar.xz`, or `.zip`) of the project's source code. It's a crucial part of the release engineering process, allowing developers to package their code for distribution to others.

Here's a breakdown of its functionalities:

**1. Creating Source Distribution Archives:**

* **Packaging Source Code:** The core function is to collect all necessary source files into a compressed archive. This includes the main project's source code and optionally the source code of its subprojects.
* **Supported Archive Formats:** It supports multiple archive formats: `gztar`, `xztar`, and `zip`, allowing flexibility in how the distribution is packaged. The user can specify which formats to create using the `--formats` argument.
* **Version Control Integration (Git and Mercurial):**
    * **Git:**  For projects using Git, it uses `git archive` to create a clean snapshot of the repository at the current `HEAD`. It handles submodules, ensuring their correct versions are included. It also warns or errors out if there are uncommitted changes unless the `--allow-dirty` flag is used.
    * **Mercurial (Hg):** For Mercurial projects, it uses `hg archive` to create the archive. It currently doesn't fully support subprojects when using Mercurial.
* **Excluding Version Control Directories:**  It automatically excludes the `.git` or `.hg` directories from the archive to keep the distribution clean.
* **Generating SHA256 Checksums:** After creating the archives, it generates SHA256 checksum files (`.sha256sum`) for each archive to ensure integrity during download and distribution.

**2. Handling Subprojects:**

* **Optional Inclusion:** The `--include-subprojects` flag allows the inclusion of the source code of subprojects that were used during the build process. This is useful for creating self-contained distributions.
* **Subproject Handling in Git:**  For Git repositories, it recursively handles submodules, ensuring the correct revisions are included.

**3. Running Distribution Scripts:**

* **Custom Actions:**  The script can execute custom scripts defined in the project's Meson build definition (`dist_scripts`). These scripts can perform various tasks specific to the distribution process, such as modifying files, adding extra content, or running custom packaging steps.
* **Environment Variables:** When running these scripts, it sets up environment variables like `MESON_DIST_ROOT`, `MESON_SOURCE_ROOT`, `MESON_BUILD_ROOT`, `MESON_PROJECT_DIST_ROOT`, etc., providing the scripts with context about the distribution being created.

**4. Testing the Distribution Package:**

* **Building and Testing:** If the `--no-tests` flag is not used, the script will build and run the tests within the created distribution package in a temporary environment. This helps ensure that the packaged source code can be built and tested correctly by users.
* **Temporary Build Environment:** It creates temporary directories to unpack the archive, configure the build system, compile the code, and run the tests.
* **Verification:** This step verifies that the generated source distribution is functional and doesn't contain any obvious errors.

**Relation to Reverse Engineering:**

While this script itself isn't a *reverse engineering tool*, it's directly related to the artifacts that are often the target of reverse engineering:

* **Source Code Availability:** By creating a source distribution, the script makes the source code of the `frida` tool available. Reverse engineers can then analyze this source code to understand the tool's functionality, identify vulnerabilities, or learn its internal workings.
* **Understanding Build Processes:**  The structure of the distribution archive and the included files can provide insights into the build process of the `frida` tool. This can be helpful for reverse engineers trying to understand how the final binaries are created.
* **Identifying Customization Points:** The presence of distribution scripts highlights potential customization points or special processing steps involved in packaging the software. Reverse engineers might be interested in understanding what these scripts do.

**Example:**  A reverse engineer might download a `frida` source distribution created by this script to:

* **Understand Frida's Internals:** Analyze the source code to see how Frida's core hooking mechanisms work, how it interacts with target processes, and how its different components are implemented.
* **Look for Security Vulnerabilities:** Examine the code for potential security flaws that could be exploited.
* **Port Frida to a New Platform:** Study the source code to understand the dependencies and platform-specific parts of Frida to facilitate porting efforts.

**Involvement of Binary Underpinnings, Linux, Android Kernel & Framework:**

While the script primarily deals with packaging source code, its actions have implications for binary execution and system-level interactions:

* **Building Binaries:** The testing phase of the script involves building the `frida` tool from the packaged source. This process involves compiling source code into machine code, linking libraries, and creating executable binaries that run on specific operating systems and architectures (including Linux and Android).
* **Frida's Core Functionality:** Frida, as a dynamic instrumentation tool, heavily interacts with the operating system's kernel and process management features. The source code being packaged contains the logic for these interactions, including:
    * **Process Attachment:**  Code to attach to running processes.
    * **Memory Manipulation:**  Code to read and write process memory.
    * **Function Hooking:** Code to intercept and modify function calls.
    * **Inter-Process Communication (IPC):**  Mechanisms for communication between Frida and the target process.
* **Android Specifics:** If the distribution includes Android-specific components, the source code will contain logic for interacting with the Android runtime environment (ART), the Zygote process, system services, and potentially even kernel modules (depending on Frida's capabilities on Android).

**Example:**

* When testing the distribution on Linux, the build process will create ELF binaries. Reverse engineers familiar with ELF structure can analyze these binaries.
* On Android, the build process might produce APK files containing DEX code. Understanding the structure of APKs and DEX is relevant for reverse engineers targeting Android applications.
* The source code will contain system calls and library calls specific to Linux and Android, reflecting the underlying operating system's APIs.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input (Command Line):**

```bash
python mdist.py -C /path/to/frida/build --formats=zip,gztar --include-subprojects
```

**Assumptions:**

* The user is in a terminal.
* `/path/to/frida/build` is a valid Meson build directory for the Frida project.
* The Frida project uses Git for version control.
* The project has subprojects.

**Logical Steps within `mdist.py`:**

1. **Parse Arguments:** The script parses the command-line arguments:
   - `wd`: `/path/to/frida/build`
   - `formats`: `zip,gztar`
   - `include_subprojects`: `True`

2. **Load Build Data:** It loads the Meson build data from `/path/to/frida/build/meson-private/build.dat`.

3. **Determine Archives:** It determines the archive formats to create: `['zip', 'gztar']`.

4. **Handle Git:** It detects that the project uses Git.

5. **Create GitDist Instance:** It creates an instance of the `GitDist` class.

6. **Process Main Project:**
   - Checks for uncommitted changes (may warn or exit if found).
   - Uses `git archive` to create a tar archive of the main project's source code in a temporary directory.

7. **Process Subprojects:**
   - Since `--include-subprojects` is enabled, it iterates through the subprojects defined in the build data.
   - For each subproject, it uses `git archive` (or `shutil.copytree` if it's not a Git repo) to include its source code in the temporary distribution directory.

8. **Run Distribution Scripts:** It executes any custom distribution scripts defined in the project's Meson build definition, passing relevant environment variables.

9. **Create Archives:**
   - It uses `shutil.make_archive` to create `frida-<version>.zip` and `frida-<version>.tar.gz` from the temporary distribution directory.

10. **Generate Checksums:**
    - It creates `frida-<version>.zip.sha256sum` and `frida-<version>.tar.gz.sha256sum`.

11. **Test Distribution (if `--no-tests` is not used):**
    - Creates temporary directories for unpacking, building, and installing.
    - Unpacks `frida-<version>.zip`.
    - Runs `meson setup` and `ninja` inside the unpacked directory to build Frida.
    - Runs `ninja test` to execute the test suite.
    - Installs Frida to a temporary directory.

**Hypothetical Output (Files Created):**

* `frida-<version>.zip`
* `frida-<version>.zip.sha256sum`
* `frida-<version>.tar.gz`
* `frida-<version>.tar.gz.sha256sum`
* (Potentially temporary directories and files created during the testing phase)

**User or Programming Common Usage Errors:**

1. **Running Outside Build Directory:**

   ```bash
   python /path/to/frida/subprojects/frida-swift/releng/meson/mesonbuild/mdist.py
   ```

   **Error:** `MesonException: Directory '.' does not seem to be a Meson build directory.`

   **Explanation:** The script expects to be run from within a Meson build directory (or with the `-C` option pointing to one) because it needs to load the `build.dat` file containing build configuration.

2. **Specifying Invalid Archive Format:**

   ```bash
   python mdist.py --formats=rar
   ```

   **Error:** `Value "rar" not one of permitted values ['gztar', 'xztar', 'zip'].`

   **Explanation:** The `--formats` argument only accepts the predefined archive formats.

3. **Having Uncommitted Changes without `--allow-dirty` (Git):**

   ```bash
   # Make changes to a file but don't commit
   python mdist.py
   ```

   **Error:** `Repository has uncommitted changes that will not be included in the dist tarball\nUse --allow-dirty to ignore the warning and proceed anyway`

   **Explanation:** By default, the script prevents creating a distribution with uncommitted changes to ensure reproducibility.

4. **Forgetting `--include-subprojects`:**

   ```bash
   python mdist.py --formats=zip
   ```

   **Result:** The created zip archive might be missing the source code of necessary subprojects if `--include-subprojects` is not specified, leading to incomplete distributions.

5. **Not having Git or Mercurial installed (depending on the project's VCS):**

   ```bash
   python mdist.py
   ```

   **Error:** (Likely an error from `subprocess.call` or `subprocess.check_call` indicating that `git` or `hg` command was not found).

   **Explanation:** The script relies on the `git` or `hg` command-line tools being available in the system's PATH.

**User Operation Steps to Reach Here (Debugging Clues):**

1. **Developing with Meson:** A developer is working on the Frida project, which uses Meson as its build system.
2. **Making Changes:** The developer makes changes to the Frida source code.
3. **Building Frida:** The developer typically builds Frida using `meson compile` or `ninja` from the build directory.
4. **Preparing a Release:** When preparing a release, the developer needs to create a source distribution package.
5. **Running the `meson dist` Command:** The Meson build system provides a command `meson dist` to create these packages.
6. **Meson Invokes `mdist.py`:** When the user runs `meson dist` from the build directory, Meson internally identifies the relevant `mdist.py` script within the project's source tree and executes it, passing appropriate arguments based on the user's configuration and command-line options.

**Therefore, as a debugger tracing the execution:**

* You would start by observing the user running `meson dist` from the command line within the Frida build directory.
* You would then trace how Meson parses this command and determines the appropriate script to execute for the `dist` action.
* You would see Meson calling the `mdist.py` script with arguments like `-C /path/to/frida/build` (the build directory) and potentially other options like `--formats`.
* You could then step through the `mdist.py` script's execution to understand how it creates the archive, handles version control, and performs any other steps.

Understanding these steps helps in debugging issues related to distribution package creation, such as incorrect file inclusions, problems with version control integration, or failures during the testing phase.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mdist.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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