Response:
Let's break down the thought process for analyzing the provided Python code and answering the user's request.

**1. Understanding the Context:**

The user explicitly states the file's location within the Frida project: `frida/subprojects/frida-node/releng/meson/unittests/allplatformstests.py`. This immediately tells us:

* **Frida:** The code is related to Frida, a dynamic instrumentation toolkit.
* **Frida-node:** It's specific to the Node.js bindings for Frida.
* **Releng:**  Likely part of the release engineering or CI/CD process.
* **Meson:** The build system used is Meson.
* **Unittests:** The core purpose of this file is to define and run unit tests.
* **Allplatformstests:** The tests aim to be cross-platform.

**2. Initial Code Scan - Identifying Key Structures:**

A quick scan reveals the following crucial elements:

* **Class `AllPlatformsTests`:** This is the main test class, inheriting from `BasePlatformTests`. This suggests a test framework structure.
* **Test Methods (starting with `test_`):**  Each method prefixed with `test_` is an individual unit test. This is standard Python unittest convention.
* **Assertions (`self.assertEqual`, `self.assertTrue`, `self.assertRaises`):** These are used to verify the expected behavior within each test.
* **Calls to `self.init()`, `self.build()`, `self.setconf()`, `self._run()`:** These are helper methods likely inherited from `BasePlatformTests` to manage test setup, build processes, configuration, and running commands.
* **File Path Manipulations (`os.path.join`, `Path`):**  The code deals heavily with file paths, indicating interactions with the file system.
* **Conditional Logic (`if`, `elif`, `else`):**  There's platform-specific logic based on operating system (`is_windows()`, `is_osx()`, `is_cygwin()`) and compiler ID.
* **External Tool Interactions (`shutil.which`, `subprocess.CalledProcessError`):**  Some tests interact with external tools like `clang-format` and potentially the system shell.
* **JSON Handling (`json.load`):**  The `test_introspect_install_plan` method works with JSON files, implying inspection of build system output.
* **Mocking (`mock.patch.dict`, `mock.patch.object`):**  The `test_env_flags_to_linker` method uses mocking to isolate and test specific compiler behaviors.
* **Language-Specific Tests (`@skip_if_not_language('rust')`):**  Some tests are specific to the Rust language integration.

**3. Detailed Analysis of Test Functionality (Mapping to User Questions):**

Now, let's go through each test method and relate it to the user's specific questions:

* **General Functionality:**  Each `test_` method name usually gives a good hint about its purpose (e.g., `test_build_b_options`, `test_install_skip_subprojects`). Reading the code within each method clarifies the details. The overall function is to test different aspects of the Meson build system within the Frida-node context.

* **Relationship to Reverse Engineering:** Look for tests that involve:
    * Inspecting compiled binaries (though not directly in this snippet).
    * Examining build artifacts and metadata (like the compilation database in `test_custom_target_implicit_include`).
    * Testing the output of build processes, which is crucial for understanding how software is constructed. The installation tests (`test_install_*`) are relevant here.

* **Binary/Kernel/Framework Knowledge:**  Identify tests that touch upon:
    * Executable suffixes (`exe_suffix`).
    * Shared library naming conventions (platform-specific).
    * Linking (`test_env_flags_to_linker`).
    * Installation directories and layouts.
    * Compiler flags and standard library selection (`test_c_cpp_stds`).

* **Logical Reasoning (Assumptions and Outputs):**  For each test, consider:
    * **Input:** The source code in the test directory, the Meson configuration (if any), and environment variables.
    * **Process:** The Meson build process, installation, or other actions.
    * **Output:** The files created, the exit code of commands, the content of files, or the assertions that pass or fail. The `test_install_tag` and `test_introspect_install_plan` methods are good examples of where we can reason about expected file structures.

* **Common Usage Errors:** Look for tests that cover:
    * Incorrect configuration options (`test_c_cpp_stds` with invalid `c_std`).
    * Issues with external tools not being found (`test_clang_format_check`).
    * Problems related to subproject dependencies and installations (`test_install_skip_subprojects`).

* **User Steps to Reach the Code:** Imagine a developer working with Frida-node:
    1. They might be trying to build Frida-node from source.
    2. They encounter build issues and need to run the unit tests.
    3. They navigate to the test directory and execute the test suite.
    4. This specific file (`allplatformstests.py`) would be part of that test suite execution. The specific test methods being run might depend on the flags passed to the test runner.

* **Summarizing Functionality (Final Step):**  After analyzing individual tests, synthesize the overall purpose of the file. It's about ensuring the reliability and correctness of the Frida-node build process across different platforms and with various configurations.

**4. Refining and Structuring the Answer:**

Organize the findings logically, addressing each part of the user's request. Use clear headings and bullet points for better readability. Provide specific code examples where relevant to illustrate the points. Ensure the language is precise and avoids jargon where possible, or explains it when necessary.

By following these steps, one can systematically analyze the provided code snippet and generate a comprehensive and informative answer to the user's questions.
This Python code file, `allplatformstests.py`, is part of the unit tests for the Frida dynamic instrumentation tool, specifically focusing on the Frida-node component and its interaction with the Meson build system across different platforms. Let's break down its functionalities based on your requests:

**Functionalities:**

This file defines a test suite using the Python `unittest` framework to verify various aspects of the Frida-node build process managed by Meson. The tests cover:

1. **Basic Build Functionality:**
   - **`test_build()`:** Checks if a basic build succeeds.
   - **`test_build_with_unicode_source_path()`:** Ensures building works correctly with Unicode characters in the source path.
   - **`test_build_b_options()`:**  Tests if certain `b_` options (related to build) are accepted by Meson (though currently they might not have a functional effect).

2. **Environment Variable Handling:**
   - **`test_build_envvars()`:** Verifies that environment variables are correctly passed to the build process.
   - **`test_build_override_envvars()`:**  Confirms that explicitly provided environment variables override the existing ones.
   - **`test_build_multiple_envvars()`:** Tests the handling of multiple environment variables.
   - **`test_env_flags_to_linker()`:**  Checks how compiler flags set via environment variables (like `CFLAGS`, `LDFLAGS`) are passed to the linker, distinguishing between compilers that act as linkers and those that don't.

3. **Installation Process Testing:**
   - **`test_install_skip_subprojects()`:**  Tests the functionality to selectively skip installation of subprojects.
   - **`test_install_tag()`:** Verifies the tagging system for installation targets, allowing selective installation based on tags like `devel`, `runtime`, `custom`.
   - **`test_install_script_dry_run()`:** Checks the dry-run mode for install scripts.
   - **`test_introspect_install_plan()`:**  Examines the `meson-info/intro-install_plan.json` file generated by Meson to ensure the planned installation steps are correct.

4. **Subproject Handling:**
   - **`test_adding_subproject_to_configure_project()`:** Tests adding a new subproject after the initial configuration.
   - **`test_symlinked_subproject()`:**  Ensures that Meson correctly handles subprojects that are symlinked.

5. **Development Environment Setup:**
   - **`test_devenv()`:** Tests the `meson devenv` command, which sets up an environment with necessary variables for development, including options to dump the environment in different formats.

6. **Code Formatting and Checking:**
   - **`test_clang_format_check()`:**  If the backend is Ninja and `clang-format` is available, this test verifies the `clang-format` and `clang-format-check` targets for code formatting.

7. **Custom Targets and Implicit Includes:**
   - **`test_custom_target_implicit_include()`:**  Checks how implicit include directories are handled for custom targets.
   - **`test_custom_target_name()`:** Tests the ability to define custom names for custom targets.

8. **Configuration and Reconfiguration:**
   - **`test_configure_same_noop()`:**  Verifies that running `meson configure` with the same options doesn't trigger unnecessary rebuilds.
   - **`test_c_cpp_stds()`:** Tests the setting and validation of C and C++ standard versions.

9. **Rust Language Integration Testing (if Rust is enabled):**
   - **`test_rust_clippy()`:** Runs `clippy` (a Rust linter) if enabled and checks for errors.
   - **`test_rust_rlib_linkage()`:** Tests the linking of Rust rlib files.
   - **`test_bindgen_drops_invalid()`:** Checks if `bindgen` (for generating Rust bindings from C/C++ headers) correctly handles and drops invalid compiler arguments.

**Relationship to Reverse Engineering:**

While this file primarily focuses on testing the build process, it has indirect connections to reverse engineering:

* **Understanding Build Artifacts:**  Tests like `test_install_tag` and `test_introspect_install_plan` help understand where different compiled files (executables, libraries, headers) are placed after the build. This knowledge is crucial for reverse engineers who need to locate and analyze specific components of a target application. For instance, knowing that shared libraries are typically installed in `lib/` or `bin/` is essential.
* **Compilation Database Inspection:** The `test_custom_target_implicit_include` method uses `self.get_compdb()`, which retrieves the compilation database (compile_commands.json). This database contains information about how each source file was compiled, including compiler flags and include paths. Reverse engineers can use this information to understand the build process, identify potential vulnerabilities related to compiler flags, and reconstruct the environment in which the target was built.
    * **Example:** If a reverse engineer finds a vulnerability related to a specific compiler optimization, the compilation database can help determine if that optimization was enabled during the build.
* **Environment Variable Influence:** Tests like `test_build_envvars` highlight how environment variables can affect the build process. Reverse engineers sometimes analyze how environment variables influence the behavior of applications, and understanding how they are handled during the build is a related concept.
* **Debugging and Troubleshooting:**  These unit tests themselves serve as a form of automated debugging for the build system. If a build fails, understanding these tests can help pinpoint the root cause. Reverse engineers often face similar debugging challenges when analyzing unfamiliar software.

**Binary Bottom Layer, Linux, Android Kernel & Framework Knowledge:**

Several tests touch upon these areas:

* **Executable Suffixes:** The code uses `exe_suffix` (e.g., `.exe` on Windows) which is a low-level detail of operating systems.
* **Shared Library Naming:** The `test_install_tag` method has platform-specific logic to determine shared library names (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows). This reflects knowledge of binary formats and linking conventions on different operating systems.
* **Installation Directories:** The tests implicitly use standard installation paths like `bin`, `lib`, `include`, `share`. These are fundamental concepts in Linux and other Unix-like systems.
* **Compiler Detection:** The code uses `detect_c_compiler` and `detect_compiler_for`, indicating an awareness of different compilers (GCC, Clang, MSVC) and their characteristics. This is relevant to understanding how code is translated into machine code.
* **Linking:** The `test_env_flags_to_linker` method directly deals with linker flags, which are crucial for combining compiled object files into executables or libraries. Linking is a core part of the binary bottom layer.
* **Platform-Specific Logic:**  The presence of `is_windows()`, `is_osx()`, `is_cygwin()` checks throughout the tests indicates an awareness of operating system differences in build processes and binary formats. While not directly related to the kernel, it acknowledges the system environment.

**Logical Reasoning (Hypothesized Input and Output):**

Let's take the `test_install_skip_subprojects` as an example:

* **Hypothesized Input:**
    * Source code in the `92 install skip subprojects` directory containing a main project and a subproject.
    * A Meson build definition (`meson.build`) that defines install targets in both the main project and the subproject.
    * Different arguments passed to the `meson install` command:
        * No arguments.
        * `--skip-subprojects`.
        * `--skip-subprojects bar` (where 'bar' is the subproject name).
        * `--skip-subprojects another` (an invalid subproject name).

* **Expected Output:**
    * **No arguments:** All install targets from both the main project and the subproject should be installed.
    * **`--skip-subprojects`:** Only the install targets from the main project should be installed.
    * **`--skip-subprojects bar`:** Only the install targets from the main project should be installed.
    * **`--skip-subprojects another`:**  All install targets from both projects should be installed (since 'another' is not a valid subproject to skip).

**Common Usage Errors:**

These tests can help identify common errors users might make:

* **Incorrect Configuration Options:** The `test_c_cpp_stds` tests the validation of C and C++ standard options. A user might accidentally provide an invalid standard, and this test would catch that Meson handles the error correctly.
    * **Example:** A user might try to configure with `-Dc_std=c18` when their compiler doesn't fully support it, or makes a typo like `-Dc_std=c9x`.
* **Missing Dependencies:** While not explicitly shown in this snippet, if a test relies on an external tool (like `clang-format`), and that tool is not installed, the `test_clang_format_check` will skip. This simulates a user trying to use a feature that requires a missing dependency.
* **Incorrect Installation Commands:** The `test_install_skip_subprojects` highlights the correct way to skip subproject installations. A user might try a different syntax that Meson doesn't recognize.
* **Environment Variable Issues:** The environment variable tests show how users need to be aware of how environment variables can influence the build. A user might have unexpected environment variables set that interfere with the build process.

**User Steps to Reach This Code (Debugging Scenario):**

1. **Developer Modifies Frida-node:** A developer working on Frida-node makes changes to the build system (e.g., modifies `meson.build` files, adds new features, or changes how installation works).
2. **Run Unit Tests:** To ensure their changes haven't broken existing functionality, the developer runs the unit tests. This is typically done using a command like `pytest` or a similar test runner from the Frida-node project's root directory.
3. **Test Failure in `allplatformstests.py`:** One of the tests in `allplatformstests.py` fails. The error message will indicate the specific test that failed (e.g., `test_install_skip_subprojects`).
4. **Investigate the Test:** The developer opens `frida/subprojects/frida-node/releng/meson/unittests/allplatformstests.py` and navigates to the failing test method.
5. **Analyze the Test Logic:** The developer examines the code within the test method to understand:
    * What the test is trying to verify.
    * The setup steps (e.g., creating a build directory, running `meson init`).
    * The actions being tested (e.g., running `meson install` with specific arguments).
    * The assertions being made (e.g., checking the existence of specific files in the installation directory).
6. **Reproduce the Failure:** The developer might try to reproduce the failure manually by running the Meson commands used in the test with the same arguments.
7. **Identify the Root Cause:** By analyzing the test logic, the actual output, and the expected output, the developer can pinpoint why the test is failing. This could be due to a bug in their code changes, an issue with the Meson build definition, or a platform-specific problem.
8. **Fix the Issue and Re-run Tests:** After fixing the bug, the developer re-runs the unit tests to confirm that the failure is resolved.

**Summary of Functionalities (as requested in Part 7):**

In essence, `allplatformstests.py` serves as a comprehensive suite of unit tests specifically designed to validate the correctness and robustness of the Frida-node build process when managed by the Meson build system across various operating systems and configurations. It ensures that core functionalities like building, handling environment variables, installing components (with and without subprojects), setting up development environments, and integrating with tools like `clang-format` and Rust's tooling work as expected. These tests act as a safety net during development, preventing regressions and ensuring the reliability of the Frida-node build process.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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