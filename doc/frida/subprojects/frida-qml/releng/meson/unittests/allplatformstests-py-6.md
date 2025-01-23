Response:
The user is asking for a breakdown of the functionalities of a Python file used for testing the Frida dynamic instrumentation tool. I need to identify the core purpose of the file and then delve into specific examples within the code to illustrate its features. The requests about reverse engineering, low-level concepts, and common errors need to be addressed by examining how the tests interact with the build system and potentially simulated environments. Finally, I need to summarize the overall function of the file.

Here's a potential thought process:

1. **Identify the core function:** The filename `allplatformstests.py` within a `unittests` directory strongly suggests this file contains unit tests for Frida. The `releng/meson` path points to the use of the Meson build system. Thus, the tests are likely verifying the correct behavior of Frida's build process across different platforms.

2. **Scan for test function names:**  Keywords like `test_` prefixing function names are a strong indicator of individual test cases. I'll scan for these to get an overview of what's being tested.

3. **Analyze individual test functions and their purpose:**
    * `test_basic`: Seems to check a basic build process.
    * `test_build_default_args`:  Likely tests building with default settings.
    * `test_build_cross_file`: Checks handling of cross-compilation configuration.
    * `test_run_custom_target_command_cwd`: Focuses on custom build steps and working directories.
    * `test_run_depfile_custom_command`: Tests dependency tracking for custom commands.
    * `test_multiple_envvars`: Examines how the build handles multiple environment variables.
    * `test_build_b_options`: Tests build-related options.
    * `test_install_skip_subprojects`: Verifies the ability to skip installing subprojects.
    * `test_adding_subproject_to_configure_project`: Tests dynamically adding subprojects.
    * `test_devenv`: Looks at the developer environment setup.
    * `test_clang_format_check`: Checks code formatting using clang-format.
    * `test_custom_target_implicit_include`: Tests implicit inclusion of headers for custom targets.
    * `test_env_flags_to_linker`:  Focuses on how environment flags affect the linker.
    * `test_install_tag`: Checks the functionality of installing with tags.
    * `test_install_script_dry_run`: Tests a dry run of an installation script.
    * `test_introspect_install_plan`: Verifies the introspection of the installation plan.
    * `test_rust_clippy`: Tests Rust code linting.
    * `test_rust_rlib_linkage`: Tests linking of Rust rlib files.
    * `test_bindgen_drops_invalid`: Tests handling of invalid arguments by bindgen.
    * `test_custom_target_name`: Tests custom target naming.
    * `test_symlinked_subproject`: Tests handling of symlinked subprojects.
    * `test_configure_same_noop`: Checks that re-configuring with the same settings doesn't trigger changes.
    * `test_c_cpp_stds`: Tests setting C and C++ standards.

4. **Identify connections to reverse engineering:** Frida is a dynamic instrumentation tool used for reverse engineering. Tests involving environment variables, linker flags, and build configurations directly relate to how Frida would be configured and used in a reverse engineering context. The `test_env_flags_to_linker` function is a clear example.

5. **Identify connections to low-level concepts:**  Tests involving linker flags, shared libraries, static libraries, and compiler arguments touch upon binary-level details and OS-specific concepts (like `.so` and `.dll` extensions). The `test_install_tag` function demonstrates this by checking the correct installation paths and file types for different platforms.

6. **Identify connections to Linux and Android kernel/framework:** While the provided snippet doesn't explicitly mention Android or kernel code *within the test logic itself*, the fact that this is for Frida, a tool heavily used on Android, suggests the *purpose* of these tests is to ensure Frida's build system works correctly on those platforms. The tests aim for cross-platform compatibility, which implicitly includes Linux and, by extension, Android.

7. **Look for logical reasoning and assumptions:**  Many tests involve setting up a scenario (e.g., with specific environment variables or source files) and then asserting expected outcomes (e.g., specific files being created, specific commands being executed). The assumptions are usually tied to how the Meson build system and Frida's build scripts are *expected* to behave. For instance, `test_install_skip_subprojects` assumes that Meson's `--skip-subprojects` flag will indeed prevent subprojects from being installed.

8. **Identify potential user/programming errors:** Tests that check for exceptions or specific error messages (e.g., `test_rust_clippy` using `assertRaises`) often simulate scenarios where a user might provide invalid input or configuration. The `test_c_cpp_stds` function explicitly checks for errors when invalid C/C++ standard values are provided.

9. **Trace user steps to the code:**  A developer working on Frida or a user trying to build Frida from source would interact with the Meson build system. The steps would involve:
    * Cloning the Frida repository.
    * Navigating to the build directory.
    * Running `meson setup` with various configuration options.
    * Running `meson compile` to build.
    * Potentially running `meson install`.
    The tests in this file automate these steps to verify their correctness. The path `frida/subprojects/frida-qml/releng/meson/unittests/allplatformstests.py` indicates this file is part of the testing for the Frida QML component.

10. **Summarize the overall function:**  The file's primary goal is to rigorously test the build process of the Frida dynamic instrumentation tool across different platforms, ensuring that various configuration options, dependencies, and installation procedures work as expected.

By following these steps, I can generate a comprehensive answer that addresses all aspects of the user's request.
This Python file, `allplatformstests.py`, is part of the unit tests for the Frida dynamic instrumentation tool, specifically for the Frida QML component, within the Meson build system. Its primary function is to **verify the correctness and robustness of the Frida QML build process across various platforms and configurations.**

Here's a breakdown of its functionalities with examples relating to your specific questions:

**1. Functionalities:**

* **Basic Build Verification:** It tests the fundamental ability to configure and build the Frida QML project. For example, `test_basic` likely checks if a simple build succeeds without any special arguments.
* **Testing with Different Build Arguments:**  It verifies the behavior of the build system when provided with different arguments, such as setting specific options (`-D` flags), build types, and prefixes. `test_build_default_args` and `test_build_cross_file` are examples.
* **Custom Target and Command Execution:** It tests the execution of custom build commands and targets defined in the Meson build files. `test_run_custom_target_command_cwd` checks if custom commands are executed correctly in the specified working directory.
* **Dependency Tracking:** It verifies that dependencies for custom commands are correctly tracked, ensuring that rebuilds happen when necessary. `test_run_depfile_custom_command` likely tests this.
* **Environment Variable Handling:** It checks how the build system handles environment variables, including overriding and using them in build processes. `test_multiple_envvars` is a specific test for this.
* **Installation Procedures:** It tests the installation process, including skipping subprojects and using install tags to selectively install components. `test_install_skip_subprojects` and `test_install_tag` are relevant here.
* **Developer Environment Setup:** It verifies the creation and usage of developer environment scripts (`devenv`), which can be used to set up the necessary environment for development and debugging. `test_devenv` is the test for this.
* **Code Formatting Checks:** It integrates with code formatting tools like `clang-format` to ensure code style consistency. `test_clang_format_check` performs these checks.
* **Implicit Include Directories:** It tests how custom targets can implicitly add include directories for compilation. `test_custom_target_implicit_include` verifies this.
* **Linker Flag Propagation:** It checks how environment variables for linker flags are correctly passed to the linker. `test_env_flags_to_linker` specifically targets this.
* **Dry Run Functionality:** It tests the `--dry-run` option for installation scripts, ensuring that no actual changes are made to the system. `test_install_script_dry_run` covers this.
* **Introspection of Install Plan:** It verifies the correctness of the generated installation plan, which describes what will be installed and where. `test_introspect_install_plan` checks this.
* **Rust Language Integration:** It includes tests for building components written in Rust, including integration with linters like `clippy`. `test_rust_clippy` and `test_rust_rlib_linkage` are examples.
* **Handling of Invalid Input:** It tests how the build system handles invalid configuration options and flags, ensuring graceful error handling. `test_c_cpp_stds` tests invalid C/C++ standard values.
* **Subproject Handling:** It verifies the correct handling of subprojects, including symlinked subprojects. `test_symlinked_subproject` tests the symlink case.
* **Configuration No-op:** It checks that re-configuring the build with the same settings doesn't trigger unnecessary rebuilds. `test_configure_same_noop` tests this optimization.
* **C/C++ Standard Setting:** It tests the ability to set specific C and C++ language standards during the build process. `test_c_cpp_stds` covers this.

**2. Relationship with Reverse Engineering:**

Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. While this specific test file primarily focuses on the build process, its success is crucial for anyone wanting to use Frida for reverse engineering.

* **Example:** The `test_env_flags_to_linker` function is relevant. In reverse engineering, you might need to compile Frida with specific linker flags to interact with certain target processes or debug symbols. This test ensures that if you set `LDFLAGS` in your environment, those flags are correctly passed to the linker when building Frida. This is essential for advanced reverse engineering setups.

**3. Relationship with Binary Bottom, Linux, Android Kernel & Framework:**

* **Binary Bottom:**  Tests involving linker flags (`test_env_flags_to_linker`), shared/static libraries (`test_install_tag`), and executable generation directly relate to the binary output of the build process. The tests ensure that the correct binary artifacts are produced and placed in the appropriate locations.
* **Linux & Android:** While not explicitly testing kernel code, the goal of these tests is to ensure Frida (and thus its QML component) can be built correctly on Linux and Android. The `test_install_tag` function, for instance, checks the installation paths for shared libraries (`.so` on Linux) which is a fundamental Linux concept. The cross-compilation tests (`test_build_cross_file`) are crucial for building Frida on a development machine for deployment on a different architecture like an Android device.
* **Framework:** Frida often interacts with application frameworks on various platforms. While these tests don't directly test framework interaction, a successful build process is the prerequisite for Frida to be used for instrumenting applications within those frameworks (including Android's application framework).

**4. Logical Reasoning, Assumptions, Input/Output:**

Many tests follow a pattern:

* **Assumption:** A specific Meson feature or build setting should behave in a certain way.
* **Input:** Setting up a test environment with specific source files, build arguments, or environment variables.
* **Action:** Running Meson commands like `meson setup` and `meson compile`.
* **Output:** Asserting the expected outcome, such as specific files being created, specific commands being executed, or specific errors being raised.

**Example:**

* **Test Function:** `test_install_skip_subprojects`
* **Assumption:** The `--skip-subprojects` flag during installation should prevent the installation of specified subprojects.
* **Input:** A Meson project with a main project and a subproject. Running `meson install --skip-subprojects bar`.
* **Expected Output:**  Files from the main project should be installed, but files belonging to the "bar" subproject should *not* be installed. The test verifies the presence and absence of specific files in the installation directory.

**5. Common User or Programming Errors:**

These tests implicitly check for common errors:

* **Incorrect Build Arguments:**  Tests like `test_build_default_args` and others with specific `-D` flags ensure the build system correctly handles various configuration options. If a user provides an invalid option, Meson should ideally provide a clear error, and these tests help verify that.
* **Missing Dependencies:** While not explicitly shown in this snippet, other parts of the Frida test suite likely verify that missing build dependencies are handled correctly.
* **Incorrectly Defined Custom Targets:** Tests involving custom targets (`test_run_custom_target_command_cwd`) ensure that errors in defining custom commands or their dependencies are caught.
* **Environment Issues:** `test_multiple_envvars` checks for problems when multiple environment variables interact during the build. Users might have conflicting environment settings, and these tests help ensure robustness.
* **Installation Path Issues:** `test_install_tag` verifies that files are installed to the correct locations based on tags. Users might expect files in certain directories, and this ensures those expectations are met.
* **Code Style Violations:** `test_clang_format_check` directly addresses a common programming error – inconsistent code formatting.

**Example:**  The `test_c_cpp_stds` function explicitly tests for errors. If a user tries to set an invalid C or C++ standard using `-Dc_std=invalid`, the test expects a `subprocess.CalledProcessError` to be raised, indicating that Meson correctly rejected the invalid input.

**6. User Operations Leading to This Code (Debugging Clue):**

A developer or a user trying to build Frida QML might encounter issues. To debug, they might:

1. **Clone the Frida repository:** `git clone https://github.com/frida/frida.git`
2. **Navigate to the Frida QML build directory:** `cd frida/subprojects/frida-qml`
3. **Attempt to configure the build:** `meson setup build` (or with specific arguments like `-Dfoo=bar`).
4. **Attempt to compile:** `meson compile -C build`.
5. **Attempt to install:** `meson install -C build`.

If any of these steps fail, a developer working on Frida might add or modify tests in `allplatformstests.py` to reproduce the issue and verify the fix. A user encountering a build error might report it, and developers would use these tests to investigate.

**7. Summary of Functionality:**

In essence, `allplatformstests.py` is a comprehensive suite of unit tests designed to ensure the Frida QML component can be built correctly across various platforms and configurations using the Meson build system. It covers a wide range of build features, from basic compilation to advanced installation procedures and language integrations. Its primary purpose is to guarantee the reliability and correctness of the Frida QML build process, which is a crucial foundation for users and developers of the Frida dynamic instrumentation toolkit.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
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
```