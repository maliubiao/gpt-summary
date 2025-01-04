Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Context:**

The first and most crucial step is recognizing the context. The prompt clearly states:

* **File path:** `frida/subprojects/frida-swift/releng/meson/unittests/allplatformstests.py`
* **Project:** Frida Dynamic Instrumentation Tool
* **Purpose:** Unit tests
* **Specific focus:** Tests related to Meson (the build system used by Frida-Swift).
* **Sequential part:** "This is part 7 of 7". This tells us we are looking at the *final* piece of a larger set of tests.

Knowing this immediately tells us the code will be about verifying the correct functionality of the Frida-Swift build process, specifically concerning how it interacts with Meson. It won't be core Frida runtime code or Swift code itself, but rather *tests* of the build system.

**2. Initial Code Scan and Pattern Recognition:**

Quickly scanning the code reveals several key patterns:

* **Class Definition:**  `class AllPlatformsTests(BasePlatformTests):`  This confirms it's a test class, inheriting from some base test class.
* **Method Names starting with `test_`:** This is a standard convention for unit tests (likely using the `unittest` module in Python). Each method tests a specific scenario.
* **Path manipulation:**  `os.path.join`, `Path(...)`, indicating interaction with the file system and testing of file/directory operations.
* **`self.init(...)`, `self.build(...)`, `self.setconf(...)`, `self._run(...)`:** These suggest helper methods within the base class for common test setup, build execution, configuration changes, and running commands.
* **Assertions:** `self.assertEqual(...)`, `self.assertTrue(...)`, `self.assertIn(...)`, `self.assertRaises(...)` are standard unit test assertion methods to verify expected outcomes.
* **String literals and file names:**  These give hints about what's being tested (e.g., "multiple envvars", "install skip subprojects", "clang-format-check").
* **Conditional logic (`if` statements):**  Often used to skip tests based on the operating system, compiler, or build backend.
* **Mocking (`mock.patch.dict`, `mock.patch.object`):** Used to isolate tests and control the behavior of external dependencies (like compiler detection).
* **JSON handling (`json.load`):**  Indicates testing of introspection features that output JSON data.

**3. Analyzing Individual Test Methods (Example):**

Let's take the `test_install_skip_subprojects` method as an example of the detailed analysis:

* **Purpose (deduced from name):**  Verify the functionality of skipping the installation of subprojects during the install process.
* **Setup:** It creates a test directory (`testdir`) and initializes the Meson build environment.
* **Build:** It runs the initial build.
* **Expected Files:** It defines lists of expected files for the main project (`main_expected`) and a subproject (`bar_expected`). It considers platform-specific variations (like `.pdb` files on Windows).
* **`check_installed_files` function:** This inner function encapsulates the core test logic:
    * Takes `extra_args` (for the `meson install` command) and `expected` file list.
    * Constructs the `meson install` command.
    * Executes the command.
    * Collects all installed files.
    * **Assertion:** Compares the sorted list of expected files with the sorted list of installed files.
    * Cleans up the installation directory.
* **Test Cases:** It calls `check_installed_files` with different arguments:
    * No extra arguments: Installs everything.
    * `--skip-subprojects`: Skips all subprojects.
    * `--skip-subprojects bar`: Skips the "bar" subproject.
    * `--skip-subprojects another`:  Attempts to skip a non-existent subproject (should install everything).

**4. Connecting to the Prompt's Questions:**

As each test method is analyzed, the connections to the prompt's questions become apparent:

* **Functionality:** Each `test_` method demonstrates a specific feature of the Meson build process.
* **Reverse Engineering:**  While not direct reverse engineering of a target *program*, it tests the reverse engineering *process* in the sense that it validates the tools and steps used to build and package software. For example, testing the `install` command and its options is crucial for the final stages of reverse engineering where you might want to examine the installed files.
* **Binary/Kernel/Framework:** Some tests, especially those involving compiler flags or linker behavior, touch on these lower-level aspects. The `test_env_flags_to_linker` is a prime example.
* **Logic and Assumptions:** Tests often implicitly or explicitly define assumptions. The `test_install_skip_subprojects` assumes that Meson correctly interprets the `--skip-subprojects` flag. Input: the `meson install` command with specific flags. Output: the files present in the installation directory.
* **User Errors:** Tests like those with invalid compiler flags (`test_c_cpp_stds`) directly simulate and verify how the system handles user errors.
* **User Steps/Debugging:**  The structure of the tests mirrors the steps a developer would take when using Meson: configure, build, install. Failed tests provide debugging clues about potential problems in the build process.

**5. Synthesizing the Summary (Final Step 7):**

After analyzing several key test methods, the final summary becomes easier to formulate. It should encapsulate the main purpose and the types of functionalities covered by the tests, focusing on the interaction with the Meson build system. Keywords like "build system," "installation," "configuration," "compiler flags," "subprojects," "introspection," and "error handling" are important.

**Self-Correction/Refinement:**

During the process, if a test method's purpose isn't immediately clear, rereading the code and comments can help. If a test seems unrelated to the core goals, revisiting the initial understanding of the project and the role of these tests might be necessary. For instance, realizing this is about *Frida-Swift's* build process emphasizes the Swift-related aspects, even if the tests themselves are primarily about Meson.
This Python file, `allplatformstests.py`, is part of the unit tests for the Frida dynamic instrumentation tool, specifically focusing on the Meson build system integration for Frida-Swift. It contains a series of test cases designed to verify various aspects of how Frida-Swift is built and packaged across different platforms using Meson.

Here's a breakdown of its functions, categorized according to your requests:

**1. Core Functionalities (as shown in the code snippets):**

* **Testing Environment Variable Handling:**
    * `test_build_dcxxflag`: Checks if environment variables prefixed with `DCXXFLAG` are correctly passed to the build system.
    * `test_build_override_envvars`: Tests overriding environment variables during the build process.
    * `test_multiple_envvars`: Verifies handling of multiple environment variables.
* **Testing Build Options:**
    * `test_build_b_options`:  Checks if specific build options (like `-Dbuild.b_lto=true`) are accepted, even if they don't have a current effect. This is likely for maintaining compatibility or future-proofing.
* **Testing Installation Processes:**
    * `test_install_skip_subprojects`: Tests the functionality to skip installation of specific subprojects during the `meson install` phase.
    * `test_install_tag`: Tests the use of tags to selectively install components based on their defined tags (e.g., 'devel', 'runtime', 'custom').
    * `test_install_script_dry_run`: Verifies the `--dry-run` option for installation scripts, ensuring no actual changes are made.
* **Testing Project Configuration and Management:**
    * `test_adding_subproject_to_configure_project`: Tests adding a new subproject to an already configured project.
    * `test_configure_same_noop`: Checks that running `meson configure` with the same settings doesn't trigger unnecessary rebuilds.
* **Testing Development Environment Setup:**
    * `test_devenv`: Tests the `meson devenv` command, which sets up the development environment by exporting necessary environment variables. It checks different output formats for these variables.
* **Testing Code Formatting:**
    * `test_clang_format_check`: Tests integration with `clang-format` for code formatting, including both formatting and checking modes.
* **Testing Custom Targets:**
    * `test_custom_target_implicit_include`: Verifies that implicit includes work correctly for custom targets.
    * `test_custom_target_name`: Checks if custom target names are handled correctly in the build output.
* **Testing Dependency Handling:**
    * `test_symlinked_subproject`: Tests the handling of symlinked subprojects.
    * `test_rust_rlib_linkage`: (Specific to Rust) Tests how `rlib` (Rust static library) linkage is handled and if changes trigger rebuilds and test reruns.
* **Testing Compiler and Linker Behavior:**
    * `test_env_flags_to_linker`: Tests how environment variables like `CFLAGS` and `LDFLAGS` are passed to the linker based on the compiler's behavior.
    * `test_c_cpp_stds`: Tests setting and validating C and C++ standard versions.
* **Testing Introspection:**
    * `test_introspect_install_plan`: Tests the `meson introspect --install-plan` feature, which provides a JSON representation of the planned installation.
* **Testing Rust Integration:**
    * `test_rust_clippy`: (Specific to Rust) Tests integration with the `clippy` linter, checking for code style issues.
    * `test_bindgen_drops_invalid`: (Specific to Rust and C interop) Tests that `bindgen` (a tool for generating Rust bindings to C code) correctly handles and drops invalid compiler arguments.

**2. Relationship to Reverse Engineering:**

While this file itself doesn't *perform* reverse engineering, it tests the build system, which is a crucial component in the process of understanding and potentially modifying software. Here are some examples:

* **Understanding Build Process:** By examining these tests, a reverse engineer can understand how Frida-Swift is compiled, linked, and packaged. This knowledge is valuable when trying to analyze the final binaries. For instance, the `test_install_skip_subprojects` helps understand how different components are separated during installation.
* **Compiler and Linker Flags:** Tests like `test_env_flags_to_linker` and `test_c_cpp_stds` reveal the compiler and linker flags used during the build. Knowing these flags can be helpful when disassembling or debugging the resulting binaries, as it provides context about optimization levels, debugging information, and language standards.
* **Identifying Dependencies:** The tests implicitly reveal dependencies between different parts of the Frida-Swift project and its subprojects. This can guide a reverse engineer in understanding the software's architecture.
* **Custom Build Steps:** Tests involving custom targets (`test_custom_target_implicit_include`, `test_custom_target_name`) highlight specific build steps that might involve custom logic or code generation, which are important areas for reverse engineering.
* **Introspection for Analysis:** The `test_introspect_install_plan` directly relates to a feature that can be used for analysis. A reverse engineer could use the introspection data to understand the final layout of the installed files.

**Example:** If a reverse engineer is analyzing a compiled Frida-Swift binary and sees unexpected behavior related to inlining or optimization, they might look at tests like those involving compiler flags to see what optimization levels were used during the build process.

**3. Binary Underlying, Linux, Android Kernel & Framework:**

While the tests are mostly focused on the build system, some implicitly touch upon these areas:

* **Binary Underlying:** The entire purpose of the build system is to produce binary executables and libraries. Tests that ensure correct linking, such as `test_rust_rlib_linkage`, are directly related to the structure of these binaries. Tests involving compiler flags also influence the generated machine code.
* **Linux:** Many of these tests likely run on Linux as part of the continuous integration process for Frida. The test setup might involve creating and manipulating files and directories in a Linux-like environment. The use of standard build tools like `clang` or `gcc` also ties into the Linux ecosystem.
* **Android Kernel & Framework:** While not directly testing kernel code, Frida is heavily used on Android. The build system needs to produce binaries compatible with the Android environment. Tests ensuring correct shared library handling and dependency management (`test_install_tag`) are relevant for creating Android packages.
* **Cross-Compilation:**  Frida is a cross-platform tool. The build system must handle cross-compilation for different architectures (e.g., building Android binaries on a Linux host). While not explicitly shown in these snippets, the broader context of Frida's build system would involve testing this.

**Example:** The `test_install_tag` function, when dealing with shared libraries and their installation paths, reflects considerations for different operating systems, including Linux and potentially Android. The naming conventions for shared libraries (`.so`, `.dylib`, `.dll`) are platform-specific.

**4. Logical Inference (Hypothetical Input & Output):**

Let's take the `test_install_skip_subprojects` as an example:

* **Hypothetical Input:**
    * A Meson project with a main project and a subproject named "bar".
    * Running `meson install --destdir /tmp/install --skip-subprojects bar` in the build directory.
* **Expected Output:**
    * Only the files belonging to the main project (defined in `main_expected`) will be present in the `/tmp/install` directory. Files belonging to the "bar" subproject (defined in `bar_expected`) will be absent.

**5. User or Programming Common Mistakes:**

* **Incorrect Environment Variables:**  Tests like `test_build_dcxxflag` and `test_build_override_envvars` highlight the importance of setting environment variables correctly for the build process. A common user mistake is to misspell or not set necessary environment variables, leading to build failures.
* **Incorrect Build Options:**  Tests like `test_build_b_options` and those involving `-D` flags demonstrate how users configure the build. Incorrectly specifying these options can lead to unexpected build configurations or errors. For example, providing an invalid value for a boolean option.
* **Incorrect Installation Commands:** The `test_install_skip_subprojects` highlights a specific installation option. Users might forget or misuse such options, leading to incomplete or incorrect installations.
* **Path Issues:** The extensive use of `os.path.join` and `Path` suggests that dealing with file paths is crucial. Incorrectly specified source or destination paths in Meson build files can lead to errors.
* **Cross-Compilation Misconfiguration:** If a user is cross-compiling, incorrect target architecture or toolchain setup can cause build failures. While not explicitly shown here, the underlying build system tests would cover such scenarios.

**Example:** A user might try to install only the development files but forget to use the `--tags devel` option (as tested in `test_install_tag`), resulting in a full installation.

**6. User Operation Steps Leading Here (Debugging Clue):**

To arrive at this point in the test suite, a developer or tester would typically perform the following steps:

1. **Navigate to the Frida-Swift repository:** `cd frida`
2. **Navigate to the specific test directory:** `cd subprojects/frida-swift/releng/meson/unittests/`
3. **Run the unit tests:** This would typically involve a command like `pytest allplatformstests.py` or a similar command configured in the project's testing setup. The specific test being executed would be one of the `test_*` methods within the `AllPlatformsTests` class.
4. **If a test fails:** The output would indicate which test failed and potentially provide a traceback or error message. The developer would then examine the code of the failing test and the corresponding build logic to understand the cause of the failure. They might also run the failing test individually or with more verbose output for debugging.

**7. Summary of Functionality:**

In summary, the `allplatformstests.py` file provides a comprehensive suite of unit tests for the Frida-Swift project's Meson build system integration. It verifies the correct functioning of various aspects of the build process, including:

* **Configuration:** Handling build options and environment variables.
* **Compilation:** Ensuring correct compiler and linker behavior, including language standard settings.
* **Installation:** Testing different installation scenarios, including selective installation and skipping subprojects.
* **Dependency Management:** Handling subprojects and external dependencies.
* **Code Quality:** Integrating with code formatting tools like `clang-format`.
* **Customization:** Testing custom build targets and scripts.
* **Introspection:** Verifying the ability to inspect the build plan.
* **Rust Integration:**  Testing specific aspects of building Rust components.

These tests are crucial for ensuring the reliability and correctness of the Frida-Swift build process across different platforms and configurations. They help catch regressions and ensure that the build system behaves as expected.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能

"""
DCXXFLAG'}
        srcdir = os.path.join(self.unit_test_dir, '88 multiple envvars')
        self.init(srcdir, override_envvars=envs)
        self.build()

    def test_build_b_options(self) -> None:
        # Currently (0.57) these do nothing, but they've always been allowed
        srcdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(srcdir, extra_args=['-Dbuild.b_lto=true'])

    def test_install_skip_subprojects(self):
        testdir = os.path.join(self.unit_test_dir, '92 install skip subprojects')
        self.init(testdir)
        self.build()

        main_expected = [
            '',
            'share',
            'include',
            'foo',
            'bin',
            'share/foo',
            'share/foo/foo.dat',
            'include/foo.h',
            'foo/foofile',
            'bin/foo' + exe_suffix,
        ]
        bar_expected = [
            'bar',
            'share/bar',
            'share/bar/bar.dat',
            'include/bar.h',
            'bin/bar' + exe_suffix,
            'bar/barfile'
        ]
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_argument_syntax() == 'msvc':
            main_expected.append('bin/foo.pdb')
            bar_expected.append('bin/bar.pdb')
        prefix = destdir_join(self.installdir, self.prefix)
        main_expected = [Path(prefix, p) for p in main_expected]
        bar_expected = [Path(prefix, p) for p in bar_expected]
        all_expected = main_expected + bar_expected

        def check_installed_files(extra_args, expected):
            args = ['install', '--destdir', self.installdir] + extra_args
            self._run(self.meson_command + args, workdir=self.builddir)
            all_files = [p for p in Path(self.installdir).rglob('*')]
            self.assertEqual(sorted(expected), sorted(all_files))
            windows_proof_rmtree(self.installdir)

        check_installed_files([], all_expected)
        check_installed_files(['--skip-subprojects'], main_expected)
        check_installed_files(['--skip-subprojects', 'bar'], main_expected)
        check_installed_files(['--skip-subprojects', 'another'], all_expected)

    def test_adding_subproject_to_configure_project(self) -> None:
        srcdir = os.path.join(self.unit_test_dir, '93 new subproject in configured project')
        self.init(srcdir)
        self.build()
        self.setconf('-Duse-sub=true')
        self.build()

    def test_devenv(self):
        testdir = os.path.join(self.unit_test_dir, '90 devenv')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['devenv', '-C', self.builddir]
        script = os.path.join(testdir, 'test-devenv.py')
        app = os.path.join(self.builddir, 'app')
        self._run(cmd + python_command + [script])
        self.assertEqual('This is text.', self._run(cmd + [app]).strip())

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'sh']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'vscode']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        fname = os.path.join(self.builddir, 'dump.env')
        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', fname]
        o = self._run(cmd)
        self.assertEqual(o, '')
        o = Path(fname).read_text(encoding='utf-8')
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

    def test_clang_format_check(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Skipping clang-format tests with {self.backend.name} backend')
        if not shutil.which('clang-format'):
            raise SkipTest('clang-format not found')

        testdir = os.path.join(self.unit_test_dir, '94 clangformat')
        newdir = os.path.join(self.builddir, 'testdir')
        shutil.copytree(testdir, newdir)
        self.new_builddir()
        self.init(newdir)

        # Should reformat 1 file but not return error
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))

        # Reset source tree then try again with clang-format-check, it should
        # return an error code this time.
        windows_proof_rmtree(newdir)
        shutil.copytree(testdir, newdir)
        with self.assertRaises(subprocess.CalledProcessError):
            output = self.build('clang-format-check')
            self.assertEqual(1, output.count('File reformatted:'))

        # The check format should not touch any files. Thus
        # running format again has some work to do.
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))
        self.build('clang-format-check')

    def test_custom_target_implicit_include(self):
        testdir = os.path.join(self.unit_test_dir, '95 custominc')
        self.init(testdir)
        self.build()
        compdb = self.get_compdb()
        matches = 0
        for c in compdb:
            if 'prog.c' in c['file']:
                self.assertNotIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)
        matches = 0
        for c in compdb:
            if 'prog2.c' in c['file']:
                self.assertIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)

    def test_env_flags_to_linker(self) -> None:
        # Compilers that act as drivers should add their compiler flags to the
        # linker, those that do not shouldn't
        with mock.patch.dict(os.environ, {'CFLAGS': '-DCFLAG', 'LDFLAGS': '-flto'}):
            env = get_fake_env()

            # Get the compiler so we know which compiler class to mock.
            cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
            cc_type = type(cc)

            # Test a compiler that acts as a linker
            with mock.patch.object(cc_type, 'INVOKES_LINKER', True):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-DCFLAG', '-flto']))

            # And one that doesn't
            with mock.patch.object(cc_type, 'INVOKES_LINKER', False):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-flto']))

    def test_install_tag(self) -> None:
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        self.init(testdir)
        self.build()

        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)

        def shared_lib_name(name):
            if cc.get_id() in {'msvc', 'clang-cl'}:
                return f'bin/{name}.dll'
            elif is_windows():
                return f'bin/lib{name}.dll'
            elif is_cygwin():
                return f'bin/cyg{name}.dll'
            elif is_osx():
                return f'lib/lib{name}.dylib'
            return f'lib/lib{name}.so'

        def exe_name(name):
            if is_windows() or is_cygwin():
                return f'{name}.exe'
            return name

        installpath = Path(self.installdir)

        expected_common = {
            installpath,
            Path(installpath, 'usr'),
        }

        expected_devel = expected_common | {
            Path(installpath, 'usr/include'),
            Path(installpath, 'usr/include/bar-devel.h'),
            Path(installpath, 'usr/include/bar2-devel.h'),
            Path(installpath, 'usr/include/foo1-devel.h'),
            Path(installpath, 'usr/include/foo2-devel.h'),
            Path(installpath, 'usr/include/foo3-devel.h'),
            Path(installpath, 'usr/include/out-devel.h'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libstatic.a'),
            Path(installpath, 'usr/lib/libboth.a'),
            Path(installpath, 'usr/lib/libboth2.a'),
            Path(installpath, 'usr/include/ct-header1.h'),
            Path(installpath, 'usr/include/ct-header3.h'),
            Path(installpath, 'usr/include/subdir-devel'),
            Path(installpath, 'usr/include/custom_files'),
            Path(installpath, 'usr/include/custom_files/data.txt'),
        }

        if cc.get_id() in {'msvc', 'clang-cl'}:
            expected_devel |= {
                Path(installpath, 'usr/bin'),
                Path(installpath, 'usr/bin/app.pdb'),
                Path(installpath, 'usr/bin/app2.pdb'),
                Path(installpath, 'usr/bin/both.pdb'),
                Path(installpath, 'usr/bin/both2.pdb'),
                Path(installpath, 'usr/bin/bothcustom.pdb'),
                Path(installpath, 'usr/bin/shared.pdb'),
                Path(installpath, 'usr/bin/versioned_shared-1.pdb'),
                Path(installpath, 'usr/lib/both.lib'),
                Path(installpath, 'usr/lib/both2.lib'),
                Path(installpath, 'usr/lib/bothcustom.lib'),
                Path(installpath, 'usr/lib/shared.lib'),
                Path(installpath, 'usr/lib/versioned_shared.lib'),
                Path(installpath, 'usr/otherbin'),
                Path(installpath, 'usr/otherbin/app-otherdir.pdb'),
            }
        elif is_windows() or is_cygwin():
            expected_devel |= {
                Path(installpath, 'usr/lib/libboth.dll.a'),
                Path(installpath, 'usr/lib/libboth2.dll.a'),
                Path(installpath, 'usr/lib/libshared.dll.a'),
                Path(installpath, 'usr/lib/libbothcustom.dll.a'),
                Path(installpath, 'usr/lib/libversioned_shared.dll.a'),
            }
        else:
            expected_devel |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared')),
            }

        expected_runtime = expected_common | {
            Path(installpath, 'usr/bin'),
            Path(installpath, 'usr/bin/' + exe_name('app')),
            Path(installpath, 'usr/otherbin'),
            Path(installpath, 'usr/otherbin/' + exe_name('app-otherdir')),
            Path(installpath, 'usr/bin/' + exe_name('app2')),
            Path(installpath, 'usr/' + shared_lib_name('shared')),
            Path(installpath, 'usr/' + shared_lib_name('both')),
            Path(installpath, 'usr/' + shared_lib_name('both2')),
        }

        if is_windows() or is_cygwin():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared-1')),
            }
        elif is_osx():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared.1')),
            }
        else:
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1'),
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1.2.3'),
            }

        expected_custom = expected_common | {
            Path(installpath, 'usr/share'),
            Path(installpath, 'usr/share/bar-custom.txt'),
            Path(installpath, 'usr/share/foo-custom.h'),
            Path(installpath, 'usr/share/out1-custom.txt'),
            Path(installpath, 'usr/share/out2-custom.txt'),
            Path(installpath, 'usr/share/out3-custom.txt'),
            Path(installpath, 'usr/share/custom_files'),
            Path(installpath, 'usr/share/custom_files/data.txt'),
            Path(installpath, 'usr/share/excludes'),
            Path(installpath, 'usr/share/excludes/installed.txt'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libbothcustom.a'),
            Path(installpath, 'usr/' + shared_lib_name('bothcustom')),
        }

        if is_windows() or is_cygwin():
            expected_custom |= {Path(installpath, 'usr/bin')}
        else:
            expected_runtime |= {Path(installpath, 'usr/lib')}

        expected_runtime_custom = expected_runtime | expected_custom

        expected_all = expected_devel | expected_runtime | expected_custom | {
            Path(installpath, 'usr/share/foo-notag.h'),
            Path(installpath, 'usr/share/bar-notag.txt'),
            Path(installpath, 'usr/share/out1-notag.txt'),
            Path(installpath, 'usr/share/out2-notag.txt'),
            Path(installpath, 'usr/share/out3-notag.txt'),
            Path(installpath, 'usr/share/foo2.h'),
            Path(installpath, 'usr/share/out1.txt'),
            Path(installpath, 'usr/share/out2.txt'),
            Path(installpath, 'usr/share/subproject'),
            Path(installpath, 'usr/share/subproject/aaa.txt'),
            Path(installpath, 'usr/share/subproject/bbb.txt'),
        }

        def do_install(tags, expected_files, expected_scripts):
            cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
            cmd += ['--tags', tags] if tags else []
            stdout = self._run(cmd, workdir=self.builddir)
            installed = self.read_install_logs()
            self.assertEqual(sorted(expected_files), sorted(installed))
            self.assertEqual(expected_scripts, stdout.count('Running custom install script'))

        do_install('devel', expected_devel, 0)
        do_install('runtime', expected_runtime, 0)
        do_install('custom', expected_custom, 1)
        do_install('runtime,custom', expected_runtime_custom, 1)
        do_install(None, expected_all, 2)


    def test_install_script_dry_run(self):
        testdir = os.path.join(self.common_test_dir, '53 install script')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
        outputs = self._run(cmd, workdir=self.builddir)

        installpath = Path(self.installdir)
        self.assertFalse((installpath / 'usr/diiba/daaba/file.dat').exists())
        self.assertIn("DRYRUN: Writing file file.dat", outputs)


    def test_introspect_install_plan(self):
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-install_plan.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res = json.load(fp)

        env = get_fake_env(testdir, self.builddir, self.prefix)

        def output_name(name, type_):
            target = type_(name=name, subdir=None, subproject=None,
                           for_machine=MachineChoice.HOST, sources=[],
                           structured_sources=None,
                           objects=[], environment=env, compilers=env.coredata.compilers[MachineChoice.HOST],
                           build_only_subproject=False, kwargs={})
            target.process_compilers_late()
            return target.filename

        shared_lib_name = lambda name: output_name(name, SharedLibrary)
        static_lib_name = lambda name: output_name(name, StaticLibrary)
        exe_name = lambda name: output_name(name, Executable)

        expected = {
            'targets': {
                f'{self.builddir}/out1-notag.txt': {
                    'destination': '{datadir}/out1-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out2-notag.txt': {
                    'destination': '{datadir}/out2-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/libstatic.a': {
                    'destination': '{libdir_static}/libstatic.a',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app'): {
                    'destination': '{bindir}/' + exe_name('app'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app-otherdir'): {
                    'destination': '{prefix}/otherbin/' + exe_name('app-otherdir'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + exe_name('app2'): {
                    'destination': '{bindir}/' + exe_name('app2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('shared'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('shared'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('both'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('both'): {
                    'destination': '{libdir_static}/' + static_lib_name('both'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('bothcustom'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('bothcustom'): {
                    'destination': '{libdir_static}/' + static_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + shared_lib_name('both2'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + static_lib_name('both2'): {
                    'destination': '{libdir_static}/' + static_lib_name('both2'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out1-custom.txt': {
                    'destination': '{datadir}/out1-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out2-custom.txt': {
                    'destination': '{datadir}/out2-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out3-custom.txt': {
                    'destination': '{datadir}/out3-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out1.txt': {
                    'destination': '{datadir}/out1.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out2.txt': {
                    'destination': '{datadir}/out2.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out-devel.h': {
                    'destination': '{includedir}/out-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out3-notag.txt': {
                    'destination': '{datadir}/out3-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
            },
            'configure': {
                f'{self.builddir}/foo-notag.h': {
                    'destination': '{datadir}/foo-notag.h',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/foo2-devel.h': {
                    'destination': '{includedir}/foo2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/foo-custom.h': {
                    'destination': '{datadir}/foo-custom.h',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/foo2.h': {
                    'destination': '{datadir}/foo2.h',
                    'tag': None,
                    'subproject': None,
                },
            },
            'data': {
                f'{testdir}/bar-notag.txt': {
                    'destination': '{datadir}/bar-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{testdir}/bar-devel.h': {
                    'destination': '{includedir}/bar-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/bar-custom.txt': {
                    'destination': '{datadir}/bar-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{testdir}/subdir/bar2-devel.h': {
                    'destination': '{includedir}/bar2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subprojects/subproject/aaa.txt': {
                    'destination': '{datadir}/subproject/aaa.txt',
                    'tag': None,
                    'subproject': 'subproject',
                },
                f'{testdir}/subprojects/subproject/bbb.txt': {
                    'destination': '{datadir}/subproject/bbb.txt',
                    'tag': 'data',
                    'subproject': 'subproject',
                },
            },
            'headers': {
                f'{testdir}/foo1-devel.h': {
                    'destination': '{includedir}/foo1-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subdir/foo3-devel.h': {
                    'destination': '{includedir}/foo3-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
            },
            'install_subdirs': {
                f'{testdir}/custom_files': {
                    'destination': '{datadir}/custom_files',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': [],
                    'exclude_files': [],
                },
                f'{testdir}/excludes': {
                    'destination': '{datadir}/excludes',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': ['excluded'],
                    'exclude_files': ['excluded.txt'],
                }
            }
        }

        fix_path = lambda path: os.path.sep.join(path.split('/'))
        expected_fixed = {
            data_type: {
                fix_path(source): {
                    key: fix_path(value) if key == 'destination' else value
                    for key, value in attributes.items()
                }
                for source, attributes in files.items()
            }
            for data_type, files in expected.items()
        }

        for data_type, files in expected_fixed.items():
            for file, details in files.items():
                with self.subTest(key='{}.{}'.format(data_type, file)):
                    self.assertEqual(res[data_type][file], details)

    @skip_if_not_language('rust')
    @unittest.skipIf(not shutil.which('clippy-driver'), 'Test requires clippy-driver')
    def test_rust_clippy(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        # When clippy is used, we should get an exception since a variable named
        # "foo" is used, but is on our denylist
        testdir = os.path.join(self.rust_test_dir, '1 basic')
        self.init(testdir, extra_args=['--werror'], override_envvars={'RUSTC': 'clippy-driver'})
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.build()
        self.assertTrue('error: use of a blacklisted/placeholder name `foo`' in cm.exception.stdout or
                        'error: use of a disallowed/placeholder name `foo`' in cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_rust_rlib_linkage(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        template = textwrap.dedent('''\
                use std::process::exit;

                pub fn fun() {{
                    exit({});
                }}
            ''')

        testdir = os.path.join(self.unit_test_dir, '102 rlib linkage')
        gen_file = os.path.join(testdir, 'lib.rs')
        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(0))
        self.addCleanup(windows_proof_rm, gen_file)

        self.init(testdir)
        self.build()
        self.run_tests()

        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(39))

        self.build()
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.run_tests()
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn('exit status 39', cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_bindgen_drops_invalid(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        testdir = os.path.join(self.rust_test_dir, '12 bindgen')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        # bindgen understands compiler args that clang understands, but not
        # flags by other compilers
        if cc.get_id() == 'gcc':
            bad_arg = '-fdse'
        elif cc.get_id() == 'msvc':
            bad_arg = '/fastfail'
        else:
            raise unittest.SkipTest('Test only supports GCC and MSVC')
        self.init(testdir, extra_args=[f"-Dc_args=['-DCMD_ARG', '{bad_arg}']"])
        intro = self.introspect(['--targets'])
        for i in intro:
            if i['type'] == 'custom' and i['id'].startswith('rustmod-bindgen'):
                args = i['target_sources'][0]['compiler']
                self.assertIn('-DCMD_ARG', args)
                self.assertIn('-DPROJECT_ARG', args)
                self.assertIn('-DGLOBAL_ARG', args)
                self.assertNotIn(bad_arg, args)
                self.assertNotIn('-mtls-dialect=gnu2', args)
                self.assertNotIn('/fp:fast', args)
                return

    def test_custom_target_name(self):
        testdir = os.path.join(self.unit_test_dir, '100 custom target name')
        self.init(testdir)
        out = self.build()
        if self.backend is Backend.ninja:
            self.assertIn('Generating file.txt with a custom command', out)
            self.assertIn('Generating subdir/file.txt with a custom command', out)

    def test_symlinked_subproject(self):
        testdir = os.path.join(self.unit_test_dir, '107 subproject symlink')
        subproject_dir = os.path.join(testdir, 'subprojects')
        subproject = os.path.join(testdir, 'symlinked_subproject')
        symlinked_subproject = os.path.join(testdir, 'subprojects', 'symlinked_subproject')
        if not os.path.exists(subproject_dir):
            os.mkdir(subproject_dir)
        try:
            os.symlink(subproject, symlinked_subproject)
        except OSError:
            raise SkipTest("Symlinks are not available on this machine")
        self.addCleanup(os.remove, symlinked_subproject)

        self.init(testdir)
        self.build()

    def test_configure_same_noop(self):
        testdir = os.path.join(self.unit_test_dir, '109 configure same noop')
        args = [
            '-Dstring=val',
            '-Dboolean=true',
            '-Dcombo=two',
            '-Dinteger=7',
            '-Darray=[\'three\']',
            '-Dfeature=disabled',
            '--buildtype=plain',
            '--prefix=/abc',
        ]
        self.init(testdir, extra_args=args)

        filename = Path(self.privatedir) / 'coredata.dat'

        olddata = filename.read_bytes()
        oldmtime = os.path.getmtime(filename)

        for opt in ('-Dstring=val', '--buildtype=plain', '-Dfeature=disabled', '-Dprefix=/abc'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertEqual(oldmtime, newmtime)
            self.assertEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

        for opt in ('-Dstring=abc', '--buildtype=release', '-Dfeature=enabled', '-Dprefix=/def'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertGreater(newmtime, oldmtime)
            self.assertNotEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

    def test_c_cpp_stds(self):
        testdir = os.path.join(self.unit_test_dir, '115 c cpp stds')
        self.init(testdir)
        # Invalid values should fail whatever compiler we have
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c89,invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c++11')
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'msvc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'c89')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
            # This is deprecated but works for C
            self.setconf('-Dc_std=gnu99')
            self.assertEqual(self.getconf('c_std'), 'c99')
            # C++ however never accepted that fallback
            with self.assertRaises(subprocess.CalledProcessError):
                self.setconf('-Dcpp_std=gnu++11')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=gnu++11,vc++11,c++11')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
        elif cc.get_id() == 'gcc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'gnu89')
            self.assertEqual(self.getconf('cpp_std'), 'gnu++98')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=c++11,gnu++11,vc++11')
            self.assertEqual(self.getconf('cpp_std'), 'c++11')

"""


```