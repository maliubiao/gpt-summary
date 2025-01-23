Response:
The user wants to understand the functionality of the provided Python code snippet. This file seems to be part of the Meson build system's test suite, specifically focusing on tests that should run on all platforms. I need to analyze the code to identify its key functionalities and relate them to reverse engineering concepts, low-level programming, and common user errors.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file is named `allplatformstests.py` and resides within a `unittests` directory of the Meson build system. This immediately suggests its primary function is to define and execute unit tests applicable across different operating systems.

2. **Analyze Imports:**  The imports provide significant clues about the functionalities being tested:
    * `subprocess`:  Indicates testing of external command execution (crucial for build systems).
    * `re`, `json`: Suggests parsing of output from external processes and configuration files.
    * `tempfile`:  Implies testing scenarios involving temporary files and directories.
    * `os`, `shutil`, `platform`: Points to tests related to file system operations and platform-specific behavior.
    * `pickle`, `zipfile`, `tarfile`: Hints at tests dealing with data serialization and archive handling (potentially related to packaging or dependency management).
    * `unittest`, `mock`: Confirms the use of the Python unittest framework for writing tests.
    * `contextlib`: Shows usage of context managers for resource management within tests.
    * `glob`, `pathlib`: Indicates tests involving file path manipulation.
    * `typing`: Used for type hinting, enhancing code readability and maintainability in tests.
    * `mesonbuild.*`:  A strong indicator that the tests are specifically about Meson's features, including:
        * Logging (`mlog`)
        * Dependency management (`dependencies`, `wrap`)
        * Environment configuration (`envconfig`, `environment`)
        * Core data structures (`coredata`)
        * Modules (e.g., `gnome`, `pkgconfig`)
        * Utility functions (`mesonlib`)
        * Program execution (`programs`)
        * Compiler detection and interaction (`compilers`)
        * Linking (`linkers`)
        * Build target representation (`build`)
        * Testing framework (`mtest`)
        * Script utilities (`scripts`)
    * `run_tests`:  Suggests integration with a larger test running framework.
    * `.baseplatformtests`, `.helpers`: Indicates the use of base test classes and helper functions within the test suite.

3. **Examine Defined Classes and Functions:**
    * `temp_filename()`: A helper function for creating and cleaning up temporary files, common in testing.
    * `git_init()`, `_git_add_all()`:  Functions related to initializing and managing Git repositories, likely used for testing scenarios involving version control.
    * `AllPlatformTests(BasePlatformTests)`: The main test class inheriting from a base class. This structure is typical in `unittest`. The methods within this class will define individual test cases.

4. **Analyze Test Methods (High-Level):**  Scanning the methods of `AllPlatformTests` provides a good overview of the functionalities being tested:
    * Configuration options (`test_default_options_prefix`, `test_absolute_prefix_libdir`, etc.)
    * Configuration file handling (`test_do_conf_file_preserve_newlines`, `test_do_conf_file_by_format`)
    * Library directory handling (`test_clike_get_library_dirs`)
    * Static library behavior (`test_static_library_overwrite`)
    * Compilation order (`test_static_compile_order`)
    * Output encoding (`test_replace_unencodable_xml_chars`)
    * Running targets (`test_run_target_files_path`, `test_run_target_subdir`)
    * Installation introspection (`test_install_introspection`, `test_install_subdir_introspection`, `test_install_introspection_multiple_outputs`)
    * Installation logging (`test_install_log_content`)
    * Uninstallation (`test_uninstall`)
    * Dependency management (Wrap tool) (`test_forcefallback`, `test_implicit_forcefallback`, `test_nopromote`, `test_force_fallback_for`, `test_force_fallback_for_nofallback`)
    * Test execution (`test_testrepeat`, `test_verbose`, `test_long_output`, `test_testsetups`)

5. **Relate to Reverse Engineering, Low-Level, and Common Errors:**  Based on the identified functionalities:
    * **Reverse Engineering:** Testing introspection capabilities (examining build artifacts and configurations) is directly relevant. Understanding how a build system structures its output is key in reverse engineering. The tests around `install_introspection` are particularly relevant here.
    * **Binary/Low-Level:** Tests involving compiler and linker behavior (static libraries, compilation order) touch upon binary-level concerns. The tests involving `ar` (the archiver) directly interact with binary manipulation.
    * **Linux/Android Kernel & Framework:** While not explicitly testing kernel code, the tests for installation paths and standard directories (`/usr`, `/etc`, etc.) are related to Linux system conventions. The absence of explicit Android kernel tests in this snippet suggests this file focuses on cross-platform aspects rather than Android specifics.
    * **Logic and Assumptions:**  Many tests implicitly rely on assumptions about how Meson should behave. For example, the `test_static_library_overwrite` test assumes that static linkers overwrite rather than append.
    * **User Errors:** Tests for configuration options and dependency management often cover scenarios where users might make mistakes in their build setup or dependency specifications.

6. **Illustrative Examples:** Based on the analysis, I can create examples to showcase the connection to the identified areas.

7. **User Journey:**  I need to describe how a user interacting with Frida might indirectly trigger these tests. This would involve actions that lead to Meson being used for building Frida or its components.

8. **Summarize Functionality:**  Finally, I need to condense the findings into a concise summary of the file's purpose.

By following this structured approach, I can thoroughly analyze the code and address all aspects of the user's request.
This Python code file, `allplatformstests.py`, is a crucial part of the **Meson build system's unit test suite**. Its primary function is to define and execute a wide range of tests that are designed to be run and pass on **all platforms** supported by Meson. This ensures the core functionality of Meson remains consistent regardless of the operating system or underlying system architecture.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Testing Meson's Configuration and Setup:**
    *   Verifies how Meson handles default and user-defined options, particularly those related to installation paths (`prefix`, `libdir`, etc.).
    *   Tests the correct parsing and application of configuration data within project files (`meson.build`).
    *   Ensures that Meson correctly determines default paths based on the chosen prefix.

2. **Testing File System Operations and Utilities:**
    *   Checks the correct behavior of file creation, manipulation, and deletion operations within Meson (e.g., using `do_conf_file`).
    *   Tests the handling of temporary files and directories.

3. **Testing Compiler and Linker Interactions:**
    *   Verifies how Meson interacts with C and C++ compilers, including detection of compiler features and library directories.
    *   Tests the behavior of static library creation, ensuring that libraries are overwritten correctly during rebuilds.
    *   Checks the deterministic order of files during static compilation and linking.

4. **Testing Output Handling and Encoding:**
    *   Ensures that Meson can handle and correctly represent non-encodable characters in output, especially in XML formats used for test logs.

5. **Testing Execution of Custom Commands and Targets:**
    *   Verifies that `run_target()` commands are executed from the correct working directory within the build structure.

6. **Testing Installation Procedures:**
    *   Extensively tests Meson's installation capabilities, including the correct placement of files and directories based on specified paths.
    *   Introspects the installed files and directories to verify accuracy.
    *   Tests the generation and content of installation logs.
    *   Verifies the functionality of the `uninstall` command.

7. **Testing Dependency Management (Wrap Tool):**
    *   Tests Meson's ability to handle external dependencies using the "wrap" feature, including force-falling back to subprojects or failing if dependencies are not found.

8. **Testing the Meson Test Suite (`mtest`):**
    *   Tests various features of the built-in test runner, such as repeating tests, verbose output, and the use of test setups.
    *   Verifies the handling of long output from test executions.

**Relationship to Reverse Engineering:**

This file, while not directly performing reverse engineering, tests functionalities that are **crucial for understanding the output of a build process**, which is a common task in reverse engineering.

*   **Introspection of Build Artifacts:** The tests for `test_install_introspection` directly relate to the ability to examine the output of the build process. A reverse engineer often needs to understand *where* files are installed, *what* files are created, and *how* they are named. Meson's introspection API provides this information, and these tests ensure its reliability. For example, a test checks that a static library `libstat.a` is installed in `/usr/lib/`. A reverse engineer could use Meson's introspection to programmatically determine the location of build outputs.

*   **Understanding Build Configuration:**  Reverse engineers sometimes need to reconstruct the build process of a piece of software. Tests related to configuration options (`prefix`, `libdir`) help ensure that Meson behaves predictably based on these configurations. This predictability makes it easier to understand how a particular build was configured.

*   **Analyzing Compiler and Linker Commands:** While not explicitly shown in this snippet, other parts of the test suite likely examine the exact commands passed to the compiler and linker. Understanding these commands is vital for reverse engineering, as they reveal compilation flags, linked libraries, and other build settings.

**Relationship to Binary 底层, Linux, Android 内核及框架知识:**

*   **Binary 底层 (Binary Underpinnings):** Tests related to static libraries and compilation order directly touch upon how binary files are created and linked. The `test_static_library_overwrite` test, for example, deals with the behavior of the `ar` archiver, a fundamental tool for manipulating binary archives.

*   **Linux:** Many of the tested installation paths (`/usr/bin`, `/usr/lib`, `/etc`) are standard Linux directory conventions. The tests implicitly rely on an understanding of the Filesystem Hierarchy Standard (FHS).

*   **Android Kernel & Framework:** While this specific file doesn't have explicit tests for Android kernel or framework components, the underlying principles of build systems and dependency management are relevant to Android development. Meson can be used to build software for Android, and the cross-platform tests ensure its core functionalities work on Android as well. The tests concerning installation paths, though using Linux examples, have analogous concepts in the Android system.

**Logic 推理 (Logical Reasoning) with Hypothesized Input and Output:**

Let's take the `test_do_conf_file_by_format` test as an example of logical reasoning:

*   **Hypothesized Input:** A configuration file template string like `#mesondefine VAR` or `#cmakedefine VAR`, along with a `ConfigurationData` object containing variables and their values (e.g., `{'VAR': (True, 'description')}`). The expected output format is also provided ('meson', 'cmake', 'cmake@').

*   **Logic:** The test verifies that `do_conf_str` correctly substitutes the variable values into the template string based on the specified format. For example, if the format is 'meson' and the template is `#mesondefine VAR` and `VAR` is `True`, the expected output is `#define VAR`. If the format is 'cmake' and the template is `#cmakedefine VAR ${VAR}` and `VAR` is 'value', the output should be `#define VAR value`.

*   **Expected Output:** The test asserts that the generated output string matches the expected output for various combinations of template formats and variable types (boolean, string, integer). It also tests for expected exceptions when the input is invalid (e.g., incorrect format specifiers).

**用户或编程常见的使用错误 (Common User or Programming Errors):**

This test suite implicitly covers many common user errors:

*   **Incorrect Installation Paths:** Tests for `prefix` and other installation directories ensure that Meson prevents users from accidentally installing files in unexpected locations.

*   **Dependency Resolution Issues:** The tests for `--wrap-mode` simulate scenarios where dependencies might be missing or unavailable, helping to catch errors in dependency management logic. A common user error is failing to provide the necessary dependencies for a project.

*   **Incorrect Configuration File Syntax:** The `test_do_conf_file_by_format` test, particularly the exception handling, checks for errors in the syntax of configuration files, a frequent source of user problems.

*   **Platform-Specific Issues:** By running these tests on all platforms, Meson developers can identify and fix platform-specific bugs that users might encounter.

**用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here as Debugging Clues):**

A user interacting with Frida might indirectly trigger these tests through the following steps:

1. **Developing or Modifying Frida:** A developer working on Frida's core components would likely use Meson as the build system.

2. **Running Meson's Test Suite:** During the development process, the developer would execute Meson's test suite (likely using a command like `meson test` or a similar command provided by the build system).

3. **`allplatformstests.py` Execution:** The test runner would discover and execute the tests defined in `allplatformstests.py`.

If a test in this file fails, it provides a **debugging clue** indicating a problem with a core Meson functionality that is expected to work across all platforms. For example, if a test related to installation paths fails on Windows but passes on Linux, it suggests a platform-specific bug in Meson's installation logic. This helps developers pinpoint the source of the issue.

**第1部分功能归纳 (Summary of Functionality - Part 1):**

This first part of the `allplatformstests.py` file focuses on testing the **fundamental configuration, file system interaction, and core utilities** of the Meson build system. It verifies that Meson correctly handles project setup, configuration data, file operations, and basic interactions with compilers and linkers in a platform-independent manner. It also includes tests for handling output encoding and the execution of custom commands. This section lays the groundwork for more complex tests in subsequent parts by ensuring the basic building blocks of Meson are functioning correctly.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2021 The Meson development team

import subprocess
import re
import json
import tempfile
import textwrap
import os
import shutil
import platform
import pickle
import zipfile, tarfile
import sys
from unittest import mock, SkipTest, skipIf, skipUnless
from contextlib import contextmanager
from glob import glob
from pathlib import (PurePath, Path)
import typing as T

import mesonbuild.mlog
import mesonbuild.depfile
import mesonbuild.dependencies.base
import mesonbuild.dependencies.factory
import mesonbuild.envconfig
import mesonbuild.environment
import mesonbuild.coredata
import mesonbuild.modules.gnome
from mesonbuild.mesonlib import (
    BuildDirLock, MachineChoice, is_windows, is_osx, is_cygwin, is_dragonflybsd,
    is_sunos, windows_proof_rmtree, python_command, version_compare, split_args, quote_arg,
    relpath, is_linux, git, search_version, do_conf_file, do_conf_str, default_prefix,
    MesonException, EnvironmentException, OptionKey,
    windows_proof_rm
)
from mesonbuild.programs import ExternalProgram

from mesonbuild.compilers.mixins.clang import ClangCompiler
from mesonbuild.compilers.mixins.gnu import GnuCompiler
from mesonbuild.compilers.mixins.intel import IntelGnuLikeCompiler
from mesonbuild.compilers.c import VisualStudioCCompiler, ClangClCCompiler
from mesonbuild.compilers.cpp import VisualStudioCPPCompiler, ClangClCPPCompiler
from mesonbuild.compilers import (
    detect_static_linker, detect_c_compiler, compiler_from_language,
    detect_compiler_for
)
from mesonbuild.linkers import linkers

from mesonbuild.dependencies.pkgconfig import PkgConfigDependency
from mesonbuild.build import Target, ConfigurationData, Executable, SharedLibrary, StaticLibrary
from mesonbuild import mtest
import mesonbuild.modules.pkgconfig
from mesonbuild.scripts import destdir_join

from mesonbuild.wrap.wrap import PackageDefinition, WrapException

from run_tests import (
    Backend, exe_suffix, get_fake_env, get_convincing_fake_env_and_cc
)

from .baseplatformtests import BasePlatformTests
from .helpers import *

@contextmanager
def temp_filename():
    '''A context manager which provides a filename to an empty temporary file.

    On exit the file will be deleted.
    '''

    fd, filename = tempfile.mkstemp()
    os.close(fd)
    try:
        yield filename
    finally:
        try:
            os.remove(filename)
        except OSError:
            pass

def git_init(project_dir):
    # If a user has git configuration init.defaultBranch set we want to override that
    with tempfile.TemporaryDirectory() as d:
        out = git(['--version'], str(d))[1]
    if version_compare(search_version(out), '>= 2.28'):
        extra_cmd = ['--initial-branch', 'master']
    else:
        extra_cmd = []

    subprocess.check_call(['git', 'init'] + extra_cmd, cwd=project_dir, stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'config',
                           'user.name', 'Author Person'], cwd=project_dir)
    subprocess.check_call(['git', 'config',
                           'user.email', 'teh_coderz@example.com'], cwd=project_dir)
    _git_add_all(project_dir)

def _git_add_all(project_dir):
    subprocess.check_call('git add *', cwd=project_dir, shell=True,
                          stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'commit', '--no-gpg-sign', '-a', '-m', 'I am a project'], cwd=project_dir,
                          stdout=subprocess.DEVNULL)

class AllPlatformTests(BasePlatformTests):
    '''
    Tests that should run on all platforms
    '''

    def test_default_options_prefix(self):
        '''
        Tests that setting a prefix in default_options in project() works.
        Can't be an ordinary test because we pass --prefix to meson there.
        https://github.com/mesonbuild/meson/issues/1349
        '''
        testdir = os.path.join(self.common_test_dir, '87 default options')
        self.init(testdir, default_args=False, inprocess=True)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                prefix = opt['value']
                break
        else:
            raise self.fail('Did not find option "prefix"')
        self.assertEqual(prefix, '/absoluteprefix')

    def test_do_conf_file_preserve_newlines(self):

        def conf_file(in_data, confdata):
            with temp_filename() as fin:
                with open(fin, 'wb') as fobj:
                    fobj.write(in_data.encode('utf-8'))
                with temp_filename() as fout:
                    do_conf_file(fin, fout, confdata, 'meson')
                    with open(fout, 'rb') as fobj:
                        return fobj.read().decode('utf-8')

        confdata = {'VAR': ('foo', 'bar')}
        self.assertEqual(conf_file('@VAR@\n@VAR@\n', confdata), 'foo\nfoo\n')
        self.assertEqual(conf_file('@VAR@\r\n@VAR@\r\n', confdata), 'foo\r\nfoo\r\n')

    def test_do_conf_file_by_format(self):
        def conf_str(in_data, confdata, vformat):
            (result, missing_variables, confdata_useless) = do_conf_str('configuration_file', in_data, confdata, variable_format = vformat)
            return '\n'.join(result)

        def check_meson_format(confdata, result):
            self.assertEqual(conf_str(['#mesondefine VAR'], confdata, 'meson'), result)

        def check_cmake_format_simple(confdata, result):
            self.assertEqual(conf_str(['#cmakedefine VAR'], confdata, 'cmake'), result)

        def check_cmake_formats_full(confdata, result):
            self.assertEqual(conf_str(['#cmakedefine VAR ${VAR}'], confdata, 'cmake'), result)
            self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), result)

        def check_formats(confdata, result):
            check_meson_format(confdata, result)
            check_cmake_formats_full(confdata, result)

        confdata = ConfigurationData()
        # Key error as they do not exists
        check_formats(confdata, '/* #undef VAR */\n')

        # Check boolean
        confdata.values = {'VAR': (False, 'description')}
        check_meson_format(confdata, '#undef VAR\n')
        check_cmake_formats_full(confdata, '/* #undef VAR */\n')

        confdata.values = {'VAR': (True, 'description')}
        check_meson_format(confdata, '#define VAR\n')
        check_cmake_format_simple(confdata, '#define VAR\n')
        check_cmake_formats_full(confdata, '#define VAR 1\n')

        # Check string
        confdata.values = {'VAR': ('value', 'description')}
        check_formats(confdata, '#define VAR value\n')

        # Check integer
        confdata.values = {'VAR': (10, 'description')}
        check_formats(confdata, '#define VAR 10\n')

        # Checking if cmakedefine behaves as it does with cmake
        confdata.values = {'VAR': ("var", 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), '#define VAR var\n')

        confdata.values = {'VAR': (True, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 1\n')

        confdata.values = {'VAR': (0, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')
        confdata.values = {'VAR': (False, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')

        confdata.values = {}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')
        self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), '/* #undef VAR */\n')

        confdata.values = {'VAR': (5, 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR'], confdata, 'cmake'), '#define VAR\n')

        # Check multiple string with cmake formats
        confdata.values = {'VAR': ('value', 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value')
        self.assertEqual(conf_str(['#cmakedefine VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value')

        # Handles meson format exceptions
        #   Unknown format
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'unknown_format')
        #   More than 2 params in mesondefine
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'meson')
        #   Mismatched line with format
        self.assertRaises(MesonException, conf_str, ['#cmakedefine VAR'], confdata, 'meson')
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake')
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake@')
        #   Dict value in confdata
        confdata.values = {'VAR': (['value'], 'description')}
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'meson')

    def test_absolute_prefix_libdir(self):
        '''
        Tests that setting absolute paths for --prefix and --libdir work. Can't
        be an ordinary test because these are set via the command-line.
        https://github.com/mesonbuild/meson/issues/1341
        https://github.com/mesonbuild/meson/issues/1345
        '''
        testdir = os.path.join(self.common_test_dir, '87 default options')
        # on Windows, /someabs is *not* an absolute path
        prefix = 'x:/someabs' if is_windows() else '/someabs'
        libdir = 'libdir'
        extra_args = ['--prefix=' + prefix,
                      # This can just be a relative path, but we want to test
                      # that passing this as an absolute path also works
                      '--libdir=' + prefix + '/' + libdir]
        self.init(testdir, extra_args=extra_args, default_args=False)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                self.assertEqual(prefix, opt['value'])
            elif opt['name'] == 'libdir':
                self.assertEqual(libdir, opt['value'])

    def test_libdir_can_be_outside_prefix(self):
        '''
        Tests that libdir is allowed to be outside prefix.
        Must be a unit test for obvious reasons.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        # libdir being inside prefix is ok
        if is_windows():
            args = ['--prefix', 'x:/opt', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/opt', '--libdir', '/opt/lib32']
        self.init(testdir, extra_args=args)
        self.wipe()
        # libdir not being inside prefix is ok too
        if is_windows():
            args = ['--prefix', 'x:/usr', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/usr', '--libdir', '/opt/lib32']
        self.init(testdir, extra_args=args)
        self.wipe()
        # libdir can be outside prefix even when set via mesonconf
        self.init(testdir)
        if is_windows():
            self.setconf('-Dlibdir=x:/opt', will_build=False)
        else:
            self.setconf('-Dlibdir=/opt', will_build=False)

    def test_prefix_dependent_defaults(self):
        '''
        Tests that configured directory paths are set to prefix dependent
        defaults.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        expected = {
            '/opt': {'prefix': '/opt',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': 'var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': 'com',
                     'sysconfdir': 'etc'},
            '/usr': {'prefix': '/usr',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': '/var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': '/var/lib',
                     'sysconfdir': '/etc'},
            '/usr/local': {'prefix': '/usr/local',
                           'bindir': 'bin', 'datadir': 'share',
                           'includedir': 'include', 'infodir': 'share/info',
                           'libexecdir': 'libexec',
                           'localedir': 'share/locale',
                           'localstatedir': '/var/local', 'mandir': 'share/man',
                           'sbindir': 'sbin', 'sharedstatedir': '/var/local/lib',
                           'sysconfdir': 'etc'},
            # N.B. We don't check 'libdir' as it's platform dependent, see
            # default_libdir():
        }

        if default_prefix() == '/usr/local':
            expected[None] = expected['/usr/local']

        for prefix in expected:
            args = []
            if prefix:
                args += ['--prefix', prefix]
            self.init(testdir, extra_args=args, default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[prefix]:
                    self.assertEqual(value, expected[prefix][name])
            self.wipe()

    def test_default_options_prefix_dependent_defaults(self):
        '''
        Tests that setting a prefix in default_options in project() sets prefix
        dependent defaults for other options, and that those defaults can
        be overridden in default_options or by the command line.
        '''
        testdir = os.path.join(self.common_test_dir, '163 default options prefix dependent defaults')
        expected = {
            '':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--prefix=/usr':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--sharedstatedir=/var/state':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
            '--sharedstatedir=/var/state --prefix=/usr --sysconfdir=sysconf':
            {'prefix':         '/usr',
             'sysconfdir':     'sysconf',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
        }
        for args in expected:
            self.init(testdir, extra_args=args.split(), default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[args]:
                    self.assertEqual(value, expected[args][name])
            self.wipe()

    def test_clike_get_library_dirs(self):
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        for d in cc.get_library_dirs(env):
            self.assertTrue(os.path.exists(d))
            self.assertTrue(os.path.isdir(d))
            self.assertTrue(os.path.isabs(d))

    def test_static_library_overwrite(self):
        '''
        Tests that static libraries are never appended to, always overwritten.
        Has to be a unit test because this involves building a project,
        reconfiguring, and building it again so that `ar` is run twice on the
        same static library.
        https://github.com/mesonbuild/meson/issues/1355
        '''
        testdir = os.path.join(self.common_test_dir, '3 static')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        static_linker = detect_static_linker(env, cc)
        if is_windows():
            raise SkipTest('https://github.com/mesonbuild/meson/issues/1526')
        if not isinstance(static_linker, linkers.ArLinker):
            raise SkipTest('static linker is not `ar`')
        # Configure
        self.init(testdir)
        # Get name of static library
        targets = self.introspect('--targets')
        self.assertGreaterEqual(len(targets), 1)
        libname = targets[0]['filename'][0]
        # Build and get contents of static library
        self.build()
        before = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        before = [f for f in before if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(before), 1, msg=before)
        # Change the source to be built into the static library
        self.setconf('-Dsource=libfile2.c')
        self.build()
        after = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        after = [f for f in after if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(after), 1, msg=after)
        # and the object must have changed
        self.assertNotEqual(before, after)

    def test_static_compile_order(self):
        '''
        Test that the order of files in a compiler command-line while compiling
        and linking statically is deterministic. This can't be an ordinary test
        case because we need to inspect the compiler database.
        https://github.com/mesonbuild/meson/pull/951
        '''
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        compdb = self.get_compdb()
        # Rules will get written out in this order
        self.assertTrue(compdb[0]['file'].endswith("libfile.c"))
        self.assertTrue(compdb[1]['file'].endswith("libfile2.c"))
        self.assertTrue(compdb[2]['file'].endswith("libfile3.c"))
        self.assertTrue(compdb[3]['file'].endswith("libfile4.c"))
        # FIXME: We don't have access to the linker command

    def test_replace_unencodable_xml_chars(self):
        '''
        Test that unencodable xml chars are replaced with their
        printable representation
        https://github.com/mesonbuild/meson/issues/9894
        '''
        # Create base string(\nHello Meson\n) to see valid chars are not replaced
        base_string_invalid = '\n\x48\x65\x6c\x6c\x6f\x20\x4d\x65\x73\x6f\x6e\n'
        base_string_valid = '\nHello Meson\n'
        # Create invalid input from all known unencodable chars
        invalid_string = (
            '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11'
            '\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f'
            '\x80\x81\x82\x83\x84\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
            '\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e'
            '\x9f\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4\ufdd5\ufdd6\ufdd7\ufdd8'
            '\ufdd9\ufdda\ufddb\ufddc\ufddd\ufdde\ufddf\ufde0\ufde1'
            '\ufde2\ufde3\ufde4\ufde5\ufde6\ufde7\ufde8\ufde9\ufdea'
            '\ufdeb\ufdec\ufded\ufdee\ufdef\ufffe\uffff')
        if sys.maxunicode >= 0x10000:
            invalid_string = invalid_string + (
                '\U0001fffe\U0001ffff\U0002fffe\U0002ffff'
                '\U0003fffe\U0003ffff\U0004fffe\U0004ffff'
                '\U0005fffe\U0005ffff\U0006fffe\U0006ffff'
                '\U0007fffe\U0007ffff\U0008fffe\U0008ffff'
                '\U0009fffe\U0009ffff\U000afffe\U000affff'
                '\U000bfffe\U000bffff\U000cfffe\U000cffff'
                '\U000dfffe\U000dffff\U000efffe\U000effff'
                '\U000ffffe\U000fffff\U0010fffe\U0010ffff')

        valid_string = base_string_valid + repr(invalid_string)[1:-1] + base_string_valid
        invalid_string = base_string_invalid + invalid_string + base_string_invalid
        fixed_string = mtest.replace_unencodable_xml_chars(invalid_string)
        self.assertEqual(fixed_string, valid_string)

    def test_replace_unencodable_xml_chars_unit(self):
        '''
        Test that unencodable xml chars are replaced with their
        printable representation
        https://github.com/mesonbuild/meson/issues/9894
        '''
        if not shutil.which('xmllint'):
            raise SkipTest('xmllint not installed')
        testdir = os.path.join(self.unit_test_dir, '111 replace unencodable xml chars')
        self.init(testdir)
        tests_command_output = self.run_tests()
        junit_xml_logs = Path(self.logdir, 'testlog.junit.xml')
        subprocess.run(['xmllint', junit_xml_logs], check=True)
        # Ensure command output and JSON / text logs are not mangled.
        raw_output_sample = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b'
        assert raw_output_sample in tests_command_output
        text_log = Path(self.logdir, 'testlog.txt').read_text(encoding='utf-8')
        assert raw_output_sample in text_log
        json_log = json.loads(Path(self.logdir, 'testlog.json').read_bytes())
        assert raw_output_sample in json_log['stdout']

    def test_run_target_files_path(self):
        '''
        Test that run_targets are run from the correct directory
        https://github.com/mesonbuild/meson/issues/957
        '''
        testdir = os.path.join(self.common_test_dir, '51 run target')
        self.init(testdir)
        self.run_target('check_exists')
        self.run_target('check-env')
        self.run_target('check-env-ct')

    def test_run_target_subdir(self):
        '''
        Test that run_targets are run from the correct directory
        https://github.com/mesonbuild/meson/issues/957
        '''
        testdir = os.path.join(self.common_test_dir, '51 run target')
        self.init(testdir)
        self.run_target('textprinter')

    def test_install_introspection(self):
        '''
        Tests that the Meson introspection API exposes install filenames correctly
        https://github.com/mesonbuild/meson/issues/829
        '''
        if self.backend is not Backend.ninja:
            raise SkipTest(f'{self.backend.name!r} backend can\'t install files')
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/lib/libstat.a'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/usr/bin/prog' + exe_suffix])

    def test_install_subdir_introspection(self):
        '''
        Test that the Meson introspection API also contains subdir install information
        https://github.com/mesonbuild/meson/issues/5556
        '''
        testdir = os.path.join(self.common_test_dir, '59 install subdir')
        self.init(testdir)
        intro = self.introspect('--installed')
        expected = {
            'nested_elided/sub': 'share',
            'new_directory': 'share/new_directory',
            'sub/sub1': 'share/sub1',
            'sub1': 'share/sub1',
            'sub2': 'share/sub2',
            'sub3': '/usr/share/sub3',
            'sub_elided': 'share',
            'subdir/sub1': 'share/sub1',
            'subdir/sub_elided': 'share',
        }

        self.assertEqual(len(intro), len(expected))

        # Convert expected to PurePath
        expected_converted = {PurePath(os.path.join(testdir, key)): PurePath(os.path.join(self.prefix, val)) for key, val in expected.items()}
        intro_converted = {PurePath(key): PurePath(val) for key, val in intro.items()}

        for src, dst in expected_converted.items():
            self.assertIn(src, intro_converted)
            self.assertEqual(dst, intro_converted[src])

    def test_install_introspection_multiple_outputs(self):
        '''
        Tests that the Meson introspection API exposes multiple install filenames correctly without crashing
        https://github.com/mesonbuild/meson/pull/4555

        Reverted to the first file only because of https://github.com/mesonbuild/meson/pull/4547#discussion_r244173438
        TODO Change the format to a list officially in a followup PR
        '''
        if self.backend is not Backend.ninja:
            raise SkipTest(f'{self.backend.name!r} backend can\'t install files')
        testdir = os.path.join(self.common_test_dir, '140 custom target multiple outputs')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/include/diff.h', '/usr/bin/diff.sh'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/opt/same.h', '/opt/same.sh'])
        self.assertPathListEqual(intro[2]['install_filename'], ['/usr/include/first.h', None])
        self.assertPathListEqual(intro[3]['install_filename'], [None, '/usr/bin/second.sh'])

    def read_install_logs(self):
        # Find logged files and directories
        with Path(self.builddir, 'meson-logs', 'install-log.txt').open(encoding='utf-8') as f:
            return list(map(lambda l: Path(l.strip()),
                              filter(lambda l: not l.startswith('#'),
                                     f.readlines())))

    def test_install_log_content(self):
        '''
        Tests that the install-log.txt is consistent with the installed files and directories.
        Specifically checks that the log file only contains one entry per file/directory.
        https://github.com/mesonbuild/meson/issues/4499
        '''
        testdir = os.path.join(self.common_test_dir, '59 install subdir')
        self.init(testdir)
        self.install()
        installpath = Path(self.installdir)
        # Find installed files and directories
        expected = {installpath: 0}
        for name in installpath.rglob('*'):
            expected[name] = 0
        logged = self.read_install_logs()
        for name in logged:
            self.assertTrue(name in expected, f'Log contains extra entry {name}')
            expected[name] += 1

        for name, count in expected.items():
            self.assertGreater(count, 0, f'Log is missing entry for {name}')
            self.assertLess(count, 2, f'Log has multiple entries for {name}')

        # Verify that with --dry-run we obtain the same logs but with nothing
        # actually installed
        windows_proof_rmtree(self.installdir)
        self._run(self.meson_command + ['install', '--dry-run', '--destdir', self.installdir], workdir=self.builddir)
        self.assertEqual(logged, self.read_install_logs())
        self.assertFalse(os.path.exists(self.installdir))

        # If destdir is relative to build directory it should install
        # exactly the same files.
        rel_installpath = os.path.relpath(self.installdir, self.builddir)
        self._run(self.meson_command + ['install', '--dry-run', '--destdir', rel_installpath, '-C', self.builddir])
        self.assertEqual(logged, self.read_install_logs())

    def test_uninstall(self):
        exename = os.path.join(self.installdir, 'usr/bin/prog' + exe_suffix)
        dirname = os.path.join(self.installdir, 'usr/share/dir')
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        self.assertPathDoesNotExist(exename)
        self.install()
        self.assertPathExists(exename)
        self.uninstall()
        self.assertPathDoesNotExist(exename)
        self.assertPathDoesNotExist(dirname)

    def test_forcefallback(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--wrap-mode=forcefallback'])
        self.build()
        self.run_tests()

    def test_implicit_forcefallback(self):
        testdir = os.path.join(self.unit_test_dir, '96 implicit force fallback')
        with self.assertRaises(subprocess.CalledProcessError):
            self.init(testdir)
        self.init(testdir, extra_args=['--wrap-mode=forcefallback'])
        self.new_builddir()
        self.init(testdir, extra_args=['--force-fallback-for=something'])

    def test_nopromote(self):
        testdir = os.path.join(self.common_test_dir, '98 subproject subdir')
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['--wrap-mode=nopromote'])
        self.assertIn('dependency subsub found: NO', cm.exception.stdout)

    def test_force_fallback_for(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--force-fallback-for=zlib,foo'])
        self.build()
        self.run_tests()

    def test_force_fallback_for_nofallback(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--force-fallback-for=zlib,foo', '--wrap-mode=nofallback'])
        self.build()
        self.run_tests()

    def test_testrepeat(self):
        testdir = os.path.join(self.common_test_dir, '206 tap tests')
        self.init(testdir)
        self.build()
        self._run(self.mtest_command + ['--repeat=2'])

    def test_verbose(self):
        testdir = os.path.join(self.common_test_dir, '206 tap tests')
        self.init(testdir)
        self.build()
        out = self._run(self.mtest_command + ['--suite', 'verbose'])
        self.assertIn('1/1 subtest 1', out)

    def test_long_output(self):
        testdir = os.path.join(self.common_test_dir, '254 long output')
        self.init(testdir)
        self.build()
        self.run_tests()

        # Ensure lines are found from testlog.txt when not being verbose.

        i = 1
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            line = f.readline()
            while line and i < 100001:
                if f'# Iteration {i} to stdout' in line:
                    i += 1
                line = f.readline()
            self.assertEqual(i, 100001)

            i = 1
            while line:
                if f'# Iteration {i} to stderr' in line:
                    i += 1
                line = f.readline()
        self.assertEqual(i, 100001)

        # Ensure lines are found from both testlog.txt and console when being verbose.

        out = self._run(self.mtest_command + ['-v'])
        i = 1
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            line = f.readline()
            while line and i < 100001:
                if f'# Iteration {i} to stdout' in line:
                    i += 1
                line = f.readline()
            self.assertEqual(i, 100001)

            i = 1
            while line:
                if f'# Iteration {i} to stderr' in line:
                    i += 1
                line = f.readline()
        self.assertEqual(i, 100001)

        lines = out.split('\n')
        line_number = 0
        i = 1
        while line_number < len(lines) and i < 100001:
            print('---> %s' % lines[line_number])
            if f'# Iteration {i} to stdout' in lines[line_number]:
                i += 1
            line_number += 1
        self.assertEqual(i, 100001)

        line_number = 0
        i = 1
        while line_number < len(lines):
            if f'# Iteration {i} to stderr' in lines[line_number]:
                i += 1
            line_number += 1
        self.assertEqual(i, 100001)


    def test_testsetups(self):
        if not shutil.which('valgrind'):
            raise SkipTest('Valgrind not installed.')
        testdir = os.path.join(self.unit_test_dir, '2 testsetups')
        self.init(testdir)
        self.build()
        # Run tests without setup
        self.run_tests()
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            basic_log = f.read()
        # Run buggy test with setup that has env that will make it fail
        self.assertRaises(subprocess.CalledProcessError,
                          self._run, self.mtest_command + ['--setup=valgrind'])
        with open(os.path.join(self.logdir, 'testlog-valgrind.txt'), encoding='utf-8') as f:
            vg_log = f.read()
```