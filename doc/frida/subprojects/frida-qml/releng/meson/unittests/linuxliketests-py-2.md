Response:
My thought process to analyze the Python code and generate the response follows these steps:

1. **Understand the Goal:** The request asks for an explanation of a Python file's functionality, its relevance to reverse engineering, its use of low-level/kernel concepts, its logical reasoning (with examples), common user errors, and how a user reaches this code. Finally, it asks for a summary of its function.

2. **Initial Skim and Keyword Spotting:** I first read through the code quickly, looking for recognizable patterns and keywords related to build systems, testing, and system interaction. Keywords like `testdir`, `builddir`, `install`, `compiler`, `linker`, `environment`, `cross-compilation`, `static linking`, `shared libraries`, `pkgconfig`, `strip`, `rpath`, and assertions (`assertEqual`, `assertRegex`, `assertIn`, etc.) immediately jump out. The presence of `SkipTest` also indicates a testing context.

3. **Identify the Core Purpose:** The file is clearly part of a testing framework for a build system (likely Meson, given the `meson` directory in the path). It focuses on testing various aspects of building software, particularly on Linux-like systems.

4. **Analyze Individual Test Functions:** I then examine each test function (`test_...`) to understand its specific focus.

    * **`test_ldflagdedup`:** Tests that linker flags (specifically `--export-dynamic`) are not duplicated in the generated build files.
    * **`test_compiler_libs_static_dedup`:** Checks for the correct inclusion (and likely de-duplication) of standard C libraries (`-ldl`, `-lm`, `-lc`, `-lrt`) when linking statically.
    * **`test_noncross_options`:** Verifies that compiler options defined in the project (like `-std=c99`) are applied during native compilation.
    * **`test_identity_cross` and `test_identity_cross_env`:**  Deal with cross-compilation scenarios where the "host" and "build" machines are the same, focusing on how compilers are specified.
    * **`test_static_link`:** Tests the process of building and linking against statically linked libraries.
    * **`test_ld_environment_variable_*`:**  Focuses on how the build system handles setting the linker via environment variables. It checks different linkers like `ld.bfd`, `ld.gold`, `ld.lld`.
    * **`test_wrap_with_file_url`:** Tests the functionality of fetching dependencies using local file URLs in wrap files.
    * **`test_no_rpath_for_static`:** Confirms that `rpath` (runtime library path) is not set for statically linked executables.
    * **`test_lookup_system_after_broken_fallback`:** Tests dependency resolution when a fallback dependency fails.
    * **`test_as_link_whole`:**  Checks the `-Wl,--whole-archive` linker flag.
    * **`test_prelinking`:**  Tests the prelinking optimization, where object files are partially linked to speed up final linking.
    * **`do_one_test_with_nativefile` and `test_cmake_multilib`:**  Test integration with CMake, especially for handling multi-architecture builds (using `-m32`).
    * **`test_install_strip`:**  Verifies that the `strip` command can remove debug symbols during installation.
    * **`test_isystem_default_removal_with_symlink`:** Tests the handling of `isystem` include paths, especially when they are symlinks to default system include directories.
    * **`test_freezing`:** Tests a "freezing" feature (likely related to build reproducibility or preventing changes after a certain point).
    * **`test_complex_link_cases`:** Checks the correctness of generated linking commands for various complex scenarios involving static and shared libraries.

5. **Connect to Reverse Engineering:** I consider how these testing scenarios relate to reverse engineering. The key connections are:

    * **Understanding build processes:** Reversing often involves analyzing binaries, and understanding how they were built (compiler flags, linking order, included libraries) provides valuable context. These tests validate the correctness of these aspects of the build system.
    * **Identifying link-time behavior:**  Features like `rpath`, static vs. dynamic linking, and linker flags directly impact how a binary loads and resolves dependencies, which is crucial for reverse engineers.
    * **Debugging information:** The `test_install_strip` function highlights the presence and removal of debugging symbols, which are essential for debugging and reverse engineering.

6. **Identify Low-Level/Kernel Concepts:** I look for tests that touch upon OS-level concepts:

    * **Linking:** The core of many tests involves linking, a fundamental process of combining compiled object files into executables or libraries. This involves understanding loaders, symbol resolution, and library paths.
    * **Shared Libraries (.so, .dylib):** Several tests implicitly or explicitly deal with shared libraries, their loading, and the role of `rpath` and environment variables like `LD_LIBRARY_PATH`.
    * **Static Libraries (.a):**  Tests cover the creation and linking of static libraries.
    * **Kernel Interaction (indirect):** While not directly interacting with the kernel, the build process creates binaries that *will* interact with the kernel. Understanding how libraries are linked and loaded is essential for understanding this interaction.
    * **File System Operations:**  The tests use file system operations (creating files, directories, symlinks) as part of their setup.

7. **Analyze Logical Reasoning (Assumptions and Outputs):** For each test, I consider the assumptions and expected outcomes. For example, in `test_ldflagdedup`, the assumption is that the linker flag `--export-dynamic` should appear only once. The test reads the generated `build.ninja` file and asserts this.

8. **Identify Common User Errors:**  I think about what mistakes a user might make that these tests could catch:

    * **Incorrectly specifying linker flags:**  The `test_ldflagdedup` function directly addresses this.
    * **Problems with library dependencies:** The `test_static_link` and `test_lookup_system_after_broken_fallback` tests relate to this.
    * **Issues with cross-compilation setups:** The `test_identity_cross` tests are relevant here.
    * **Forgetting to set environment variables:** The `test_ld_environment_variable_*` tests highlight the importance of environment variables for controlling the build process.
    * **Expecting debug symbols to be present after stripping:** The `test_install_strip` test clarifies the effect of the `--strip` option.

9. **Trace User Steps:** I consider how a user might end up triggering this code. The most likely scenario is during the development of Frida itself. Developers would:

    * **Modify the Frida build system (Meson files).**
    * **Run the test suite** to ensure their changes haven't introduced regressions or broken existing functionality. This would involve executing a command like `meson test` or a similar command within the Frida development environment.

10. **Summarize Functionality:** Finally, I synthesize the information gathered to provide a concise summary of the file's purpose: verifying the correctness and robustness of the Frida build system on Linux-like platforms.

By following these steps, I can systematically analyze the code, understand its implications, and generate a comprehensive response that addresses all aspects of the request.
This Python file, `linuxliketests.py`, is part of the unit test suite for the Frida dynamic instrumentation tool's QML bindings, specifically focusing on testing build system functionalities on Linux-like operating systems. Here's a breakdown of its functions:

**Core Functionality: Testing the Build System (Meson)**

The primary goal of this file is to verify the correctness and robustness of the Meson build system configuration for Frida's QML bindings on Linux and similar platforms. It achieves this by:

* **Compiling and linking test projects:** It sets up minimal test projects with various configurations (e.g., different linking scenarios, compiler options).
* **Inspecting generated build files (primarily `build.ninja`):** It examines the content of the `build.ninja` file (generated by Meson) to ensure the build system is producing the correct build instructions.
* **Running compiled tests:** It compiles and executes the test projects to confirm they behave as expected.
* **Testing specific build features:**  It targets particular aspects of the build process like:
    * Handling of linker flags (`-Wl,--export-dynamic`).
    * Deduplication of compiler and linker libraries.
    * Applying compiler options defined in the project.
    * Cross-compilation scenarios.
    * Static linking.
    * Using environment variables to specify linkers.
    * Handling wrap files for dependency management.
    * Stripping debug symbols during installation.
    * Prelinking.
    * Integration with CMake.
    * Complex linking scenarios involving static and shared libraries.

**Relationship to Reverse Engineering:**

While this file doesn't directly perform reverse engineering, it's crucial for ensuring the reliability and correctness of Frida, a powerful tool *used* for reverse engineering. Here's how it's related:

* **Ensuring Frida is built correctly:**  If the build system has issues, Frida itself might not be built correctly, potentially leading to unexpected behavior or making it harder to use for reverse engineering tasks. These tests help prevent such problems.
* **Testing features relevant to binary analysis:** Some tests touch upon aspects directly relevant to binary analysis, such as:
    * **Linking behavior (static vs. dynamic):** Understanding how libraries are linked is crucial when analyzing binaries. Tests like `test_static_link` verify that Frida's build system handles these scenarios correctly.
    * **Presence of debug symbols:** The `test_install_strip` function tests the removal of debug symbols. Knowing whether a binary has debug symbols is essential for effective reverse engineering.
    * **Linker flags:** Tests like `test_ldflagdedup` indirectly relate to the flags used during linking, which can influence the final binary structure and behavior.

**Example:** The `test_no_rpath_for_static` function checks that `rpath` is not set for statically linked executables. This is important in reverse engineering because `rpath` dictates where the dynamic linker searches for shared libraries at runtime. If a statically linked binary incorrectly includes an `rpath`, it could indicate a build system error and potentially affect how the binary behaves in different environments.

**Involvement of Binary, Linux, Android Kernel/Framework Knowledge:**

This file implicitly relies on knowledge of these areas:

* **Binary Structure and Linking:** The tests operate on the fundamental concepts of compiling and linking, which produce binary executables and libraries. Understanding how object files are combined, symbol resolution works, and the differences between static and shared linking is essential to interpret the tests.
* **Linux System Calls and Libraries:** While not directly testing system calls, the compiled programs will eventually make system calls. The tests ensuring proper linking of standard libraries (`-ldl`, `-lm`, `-lc`, `-lrt` in `test_compiler_libs_static_dedup`) demonstrate an understanding of the importance of these core libraries.
* **Linux Dynamic Linker:** Tests involving shared libraries and `rpath` touch upon the functionality of the Linux dynamic linker (`ld.so`). The `test_ld_environment_variable_*` tests directly manipulate which linker is used.
* **Packaging and Installation:** The `test_install_strip` function relates to the process of packaging and installing software on Linux, including the concept of stripping debug symbols to reduce binary size.
* **Cross-Compilation:** Tests like `test_identity_cross` and `test_identity_cross_env` deal with the complexities of building software for a different target architecture or operating system, requiring knowledge of toolchain configurations.

**Example:** The `test_ld_environment_variable_bfd` function directly interacts with the concept of linkers. `ld.bfd`, `ld.gold`, and `ld.lld` are different implementations of the linker on Linux. This test ensures the build system can correctly switch between them based on environment variables.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `test_ldflagdedup` function as an example:

* **Hypothetical Input:** A Meson project configuration that might inadvertently include the `-Wl,--export-dynamic` linker flag multiple times, perhaps through dependencies or configuration settings.
* **Logical Reasoning:** The test assumes that the Meson build system should be intelligent enough to deduplicate identical linker flags.
* **Expected Output:** The test reads the generated `build.ninja` file and asserts that the string `'-Wl,--export-dynamic'` appears at most once in any given line related to linking. If it finds the string multiple times, the assertion will fail, indicating a bug in the build system's deduplication logic.

**Common User/Programming Errors:**

These tests can help catch common errors made by developers working on Frida's build system:

* **Incorrectly adding linker flags:**  The `test_ldflagdedup` directly addresses this. A developer might accidentally add the same flag multiple times, leading to unnecessary bloat or potential conflicts.
* **Forgetting to link against necessary libraries:** While not explicitly tested here, the framework of these tests allows for adding tests that would catch such errors.
* **Incorrectly configuring cross-compilation:** The `test_identity_cross` tests help ensure that the build system handles scenarios where the host and target architectures are the same, a common initial step in cross-compilation setup.
* **Issues with wrap file definitions:** The `test_wrap_with_file_url` checks that dependencies defined in wrap files (used for managing external dependencies) are handled correctly, even when using local file URLs.
* **Not understanding the impact of stripping:** The `test_install_strip` highlights the effect of the `--strip` option on removing debug symbols. Developers need to be aware of this when creating release builds.

**User Operation Steps to Reach Here (Debugging Context):**

A developer working on Frida who encounters a build issue related to linking or dependency management on a Linux-like system might end up investigating this file. The steps could be:

1. **Experience a build error:** While trying to compile Frida, they might encounter an error related to linking, missing libraries, or incorrect compiler flags.
2. **Investigate the build process:** They would likely examine the `meson.build` files and the generated `build.ninja` file to understand how the build is being orchestrated.
3. **Suspect a bug in the build system configuration:** If the `build.ninja` file contains unexpected or incorrect commands, they might suspect an issue in the Meson configuration for the QML bindings.
4. **Look at the unit tests:** To confirm their suspicion or to understand how the build system is *supposed* to behave, they would examine the unit tests for the QML bindings, particularly those targeting Linux-like systems.
5. **Find `linuxliketests.py`:** They would locate this file because its name clearly indicates it tests build-related functionalities on Linux.
6. **Analyze the relevant test:** They would then read through the tests in this file to see if there's a test case that covers the specific scenario they are facing or if they need to add a new test case to reproduce and debug the issue.
7. **Run the tests:** They might run individual tests or the entire test suite to verify if the existing tests pass or if their changes to the build system fix the problem without introducing new regressions.

**Summary of Functionality (Part 3):**

This Python file serves as a critical component of Frida's quality assurance process. It comprehensively tests the Meson build system configuration for Frida's QML bindings on Linux-like platforms. By setting up various build scenarios and verifying the generated build instructions and the behavior of the compiled code, it ensures the build system is robust, correct, and handles different linking and dependency management situations appropriately. This ultimately contributes to the stability and reliability of Frida as a reverse engineering tool.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
lf):
        testdir = os.path.join(self.unit_test_dir, '51 ldflagdedup')
        if is_cygwin() or is_osx():
            raise SkipTest('Not applicable on Cygwin or OSX.')
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        linker = cc.linker
        if not linker.export_dynamic_args(env):
            raise SkipTest('Not applicable for linkers without --export-dynamic')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        max_count = 0
        search_term = '-Wl,--export-dynamic'
        with open(build_ninja, encoding='utf-8') as f:
            for line in f:
                max_count = max(max_count, line.count(search_term))
        self.assertEqual(max_count, 1, 'Export dynamic incorrectly deduplicated.')

    def test_compiler_libs_static_dedup(self):
        testdir = os.path.join(self.unit_test_dir, '55 dedup compiler libs')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, encoding='utf-8') as f:
            lines = f.readlines()
        for lib in ('-ldl', '-lm', '-lc', '-lrt'):
            for line in lines:
                if lib not in line:
                    continue
                # Assert that
                self.assertEqual(len(line.split(lib)), 2, msg=(lib, line))

    @skipIfNoPkgconfig
    def test_noncross_options(self):
        # C_std defined in project options must be in effect also when native compiling.
        testdir = os.path.join(self.unit_test_dir, '50 noncross options')
        self.init(testdir, extra_args=['-Dpkg_config_path=' + testdir])
        compdb = self.get_compdb()
        self.assertEqual(len(compdb), 2)
        self.assertRegex(compdb[0]['command'], '-std=c99')
        self.assertRegex(compdb[1]['command'], '-std=c99')
        self.build()

    def test_identity_cross(self):
        testdir = os.path.join(self.unit_test_dir, '60 identity cross')

        constantsfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        constantsfile.write(textwrap.dedent('''\
            [constants]
            py_ext = '.py'
            '''))
        constantsfile.flush()

        nativefile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        nativefile.write(textwrap.dedent('''\
            [binaries]
            c = ['{}' + py_ext]
            '''.format(os.path.join(testdir, 'build_wrapper'))))
        nativefile.flush()
        self.meson_native_files = [constantsfile.name, nativefile.name]

        crossfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        crossfile.write(textwrap.dedent('''\
            [binaries]
            c = ['{}' + py_ext]
            '''.format(os.path.join(testdir, 'host_wrapper'))))
        crossfile.flush()
        self.meson_cross_files = [constantsfile.name, crossfile.name]

        # TODO should someday be explicit about build platform only here
        self.init(testdir)

    def test_identity_cross_env(self):
        testdir = os.path.join(self.unit_test_dir, '60 identity cross')
        env = {
            'CC_FOR_BUILD': '"' + os.path.join(testdir, 'build_wrapper.py') + '"',
            'CC': '"' + os.path.join(testdir, 'host_wrapper.py') + '"',
        }
        crossfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        crossfile.write('')
        crossfile.flush()
        self.meson_cross_files = [crossfile.name]
        # TODO should someday be explicit about build platform only here
        self.init(testdir, override_envvars=env)

    @skipIfNoPkgconfig
    def test_static_link(self):
        if is_cygwin():
            raise SkipTest("Cygwin doesn't support LD_LIBRARY_PATH.")

        # Build some libraries and install them
        testdir = os.path.join(self.unit_test_dir, '66 static link/lib')
        libdir = os.path.join(self.installdir, self.libdir)
        oldprefix = self.prefix
        self.prefix = self.installdir
        self.init(testdir)
        self.install(use_destdir=False)

        # Test that installed libraries works
        self.new_builddir()
        self.prefix = oldprefix
        meson_args = [f'-Dc_link_args=-L{libdir}',
                      '--fatal-meson-warnings']
        testdir = os.path.join(self.unit_test_dir, '66 static link')
        env = {'PKG_CONFIG_LIBDIR': os.path.join(libdir, 'pkgconfig')}
        self.init(testdir, extra_args=meson_args, override_envvars=env)
        self.build()
        self.run_tests()

    def _check_ld(self, check: str, name: str, lang: str, expected: str) -> None:
        if is_sunos():
            raise SkipTest('Solaris currently cannot override the linker.')
        if not shutil.which(check):
            raise SkipTest(f'Could not find {check}.')
        envvars = [mesonbuild.envconfig.ENV_VAR_PROG_MAP[f'{lang}_ld']]

        # Also test a deprecated variable if there is one.
        if f'{lang}_ld' in mesonbuild.envconfig.DEPRECATED_ENV_PROG_MAP:
            envvars.append(
                mesonbuild.envconfig.DEPRECATED_ENV_PROG_MAP[f'{lang}_ld'])

        for envvar in envvars:
            with mock.patch.dict(os.environ, {envvar: name}):
                env = get_fake_env()
                comp = compiler_from_language(env, lang, MachineChoice.HOST)
                if isinstance(comp, (AppleClangCCompiler, AppleClangCPPCompiler,
                                     AppleClangObjCCompiler, AppleClangObjCPPCompiler)):
                    raise SkipTest('AppleClang is currently only supported with ld64')
                if lang != 'rust' and comp.use_linker_args('bfd', '') == []:
                    raise SkipTest(
                        f'Compiler {comp.id} does not support using alternative linkers')
                self.assertEqual(comp.linker.id, expected)

    def test_ld_environment_variable_bfd(self):
        self._check_ld('ld.bfd', 'bfd', 'c', 'ld.bfd')

    def test_ld_environment_variable_gold(self):
        self._check_ld('ld.gold', 'gold', 'c', 'ld.gold')

    def test_ld_environment_variable_lld(self):
        self._check_ld('ld.lld', 'lld', 'c', 'ld.lld')

    @skip_if_not_language('rust')
    @skipIfNoExecutable('ld.gold')  # need an additional check here because _check_ld checks for gcc
    def test_ld_environment_variable_rust(self):
        self._check_ld('gcc', 'gcc -fuse-ld=gold', 'rust', 'ld.gold')

    def test_ld_environment_variable_cpp(self):
        self._check_ld('ld.gold', 'gold', 'cpp', 'ld.gold')

    @skip_if_not_language('objc')
    def test_ld_environment_variable_objc(self):
        self._check_ld('ld.gold', 'gold', 'objc', 'ld.gold')

    @skip_if_not_language('objcpp')
    def test_ld_environment_variable_objcpp(self):
        self._check_ld('ld.gold', 'gold', 'objcpp', 'ld.gold')

    @skip_if_not_language('fortran')
    def test_ld_environment_variable_fortran(self):
        self._check_ld('ld.gold', 'gold', 'fortran', 'ld.gold')

    @skip_if_not_language('d')
    def test_ld_environment_variable_d(self):
        # At least for me, ldc defaults to gold, and gdc defaults to bfd, so
        # let's pick lld, which isn't the default for either (currently)
        if is_osx():
            expected = 'ld64'
        else:
            expected = 'ld.lld'
        self._check_ld('ld.lld', 'lld', 'd', expected)

    def compute_sha256(self, filename):
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def test_wrap_with_file_url(self):
        testdir = os.path.join(self.unit_test_dir, '72 wrap file url')
        source_filename = os.path.join(testdir, 'subprojects', 'foo.tar.xz')
        patch_filename = os.path.join(testdir, 'subprojects', 'foo-patch.tar.xz')
        wrap_filename = os.path.join(testdir, 'subprojects', 'foo.wrap')
        source_hash = self.compute_sha256(source_filename)
        patch_hash = self.compute_sha256(patch_filename)
        wrap = textwrap.dedent("""\
            [wrap-file]
            directory = foo

            source_url = http://server.invalid/foo
            source_fallback_url = file://{}
            source_filename = foo.tar.xz
            source_hash = {}

            patch_url = http://server.invalid/foo
            patch_fallback_url = file://{}
            patch_filename = foo-patch.tar.xz
            patch_hash = {}
            """.format(source_filename, source_hash, patch_filename, patch_hash))
        with open(wrap_filename, 'w', encoding='utf-8') as f:
            f.write(wrap)
        self.init(testdir)
        self.build()
        self.run_tests()

        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'packagecache'))
        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'foo'))
        os.unlink(wrap_filename)

    def test_no_rpath_for_static(self):
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        self.build()
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertIsNone(build_rpath)

    def test_lookup_system_after_broken_fallback(self):
        # Just to generate libfoo.pc so we can test system dependency lookup.
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen')
        self.init(testdir)
        privatedir = self.privatedir

        # Write test project where the first dependency() returns not-found
        # because 'broken' subproject does not exit, but that should not prevent
        # the 2nd dependency() to lookup on system.
        self.new_builddir()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'meson.build'), 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent('''\
                    project('test')
                    dependency('notfound', fallback: 'broken', required: false)
                    dependency('libfoo', fallback: 'broken', required: true)
                    '''))
            self.init(d, override_envvars={'PKG_CONFIG_LIBDIR': privatedir})

    def test_as_link_whole(self):
        testdir = os.path.join(self.unit_test_dir, '76 as link whole')
        self.init(testdir)
        with open(os.path.join(self.privatedir, 'bar1.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertIn('-lfoo', content)
        with open(os.path.join(self.privatedir, 'bar2.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertNotIn('-lfoo', content)

    def test_prelinking(self):
        # Prelinking currently only works on recently new GNU toolchains.
        # Skip everything else. When support for other toolchains is added,
        # remove limitations as necessary.
        if is_osx():
            raise SkipTest('Prelinking not supported on Darwin.')
        if 'clang' in os.environ.get('CC', 'dummy'):
            raise SkipTest('Prelinking not supported with Clang.')
        testdir = os.path.join(self.unit_test_dir, '86 prelinking')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.id == "gcc" and not version_compare(cc.version, '>=9'):
            raise SkipTest('Prelinking not supported with gcc 8 or older.')
        self.init(testdir)
        self.build()
        outlib = os.path.join(self.builddir, 'libprelinked.a')
        ar = shutil.which('ar')
        self.assertPathExists(outlib)
        self.assertIsNotNone(ar)
        p = subprocess.run([ar, 't', outlib],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           text=True, timeout=1)
        obj_files = p.stdout.strip().split('\n')
        self.assertEqual(len(obj_files), 1)
        self.assertTrue(obj_files[0].endswith('-prelink.o'))

    def do_one_test_with_nativefile(self, testdir, args):
        testdir = os.path.join(self.common_test_dir, testdir)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'nativefile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(f'''[binaries]
                    c = {args}
                    ''')
            self.init(testdir, extra_args=['--native-file=' + str(p)])
            self.build()

    def test_cmake_multilib(self):
        '''
        Test that the cmake module handles multilib paths correctly.
        '''
        # Verify that "gcc -m32" works
        try:
            self.do_one_test_with_nativefile('1 trivial', "['gcc', '-m32']")
        except subprocess.CalledProcessError as e:
            raise SkipTest('Not GCC, or GCC does not have the -m32 option')
        self.wipe()

        # Verify that cmake works
        try:
            self.do_one_test_with_nativefile('../cmake/1 basic', "['gcc']")
        except subprocess.CalledProcessError as e:
            raise SkipTest('Could not build basic cmake project')
        self.wipe()

        # If so, we can test that cmake works with "gcc -m32"
        self.do_one_test_with_nativefile('../cmake/1 basic', "['gcc', '-m32']")

    @skipUnless(is_linux() or is_osx(), 'Test only applicable to Linux and macOS')
    def test_install_strip(self):
        testdir = os.path.join(self.unit_test_dir, '104 strip')
        self.init(testdir)
        self.build()

        destdir = self.installdir + self.prefix
        if is_linux():
            lib = os.path.join(destdir, self.libdir, 'liba.so')
        else:
            lib = os.path.join(destdir, self.libdir, 'liba.dylib')
        install_cmd = self.meson_command + ['install', '--destdir', self.installdir]

        # Check we have debug symbols by default
        self._run(install_cmd, workdir=self.builddir)
        if is_linux():
            # file can detect stripped libraries on linux
            stdout = self._run(['file', '-b', lib])
            self.assertIn('not stripped', stdout)
        else:
            # on macOS we need to query dsymutil instead.
            # Alternatively, check if __dyld_private is defined
            # in the output of nm liba.dylib, but that is not
            # 100% reliable, it needs linking to an external library
            stdout = self._run(['dsymutil', '--dump-debug-map', lib])
            self.assertIn('symbols:', stdout)

        # Check debug symbols got removed with --strip
        self._run(install_cmd + ['--strip'], workdir=self.builddir)
        if is_linux():
            stdout = self._run(['file', '-b', lib])
            self.assertNotIn('not stripped', stdout)
        else:
            stdout = self._run(['dsymutil', '--dump-debug-map', lib])
            self.assertNotIn('symbols:', stdout)

    def test_isystem_default_removal_with_symlink(self):
        env = get_fake_env()
        cpp = detect_cpp_compiler(env, MachineChoice.HOST)
        default_dirs = cpp.get_default_include_dirs()
        default_symlinks = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(len(default_dirs)):
                symlink = f'{tmpdir}/default_dir{i}'
                default_symlinks.append(symlink)
                os.symlink(default_dirs[i], symlink)
            self.assertFalse(cpp.compiler_args([f'-isystem{symlink}' for symlink in default_symlinks]).to_native())

    def test_freezing(self):
        testdir = os.path.join(self.unit_test_dir, '110 freeze')
        self.init(testdir)
        self.build()
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.run_tests()
        self.assertNotIn('Traceback', e.exception.output)

    @skipUnless(is_linux(), "Ninja file differs on different platforms")
    def test_complex_link_cases(self):
        testdir = os.path.join(self.unit_test_dir, '114 complex link cases')
        self.init(testdir)
        self.build()
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as f:
            content = f.read()
        # Verify link dependencies, see comments in meson.build.
        self.assertIn('build libt1-s3.a: STATIC_LINKER libt1-s2.a.p/s2.c.o libt1-s3.a.p/s3.c.o\n', content)
        self.assertIn('build t1-e1: c_LINKER t1-e1.p/main.c.o | libt1-s1.a libt1-s3.a\n', content)
        self.assertIn('build libt2-s3.a: STATIC_LINKER libt2-s2.a.p/s2.c.o libt2-s1.a.p/s1.c.o libt2-s3.a.p/s3.c.o\n', content)
        self.assertIn('build t2-e1: c_LINKER t2-e1.p/main.c.o | libt2-s3.a\n', content)
        self.assertIn('build t3-e1: c_LINKER t3-e1.p/main.c.o | libt3-s3.so.p/libt3-s3.so.symbols\n', content)
        self.assertIn('build t4-e1: c_LINKER t4-e1.p/main.c.o | libt4-s2.so.p/libt4-s2.so.symbols libt4-s3.a\n', content)
        self.assertIn('build t5-e1: c_LINKER t5-e1.p/main.c.o | libt5-s1.so.p/libt5-s1.so.symbols libt5-s3.a\n', content)
        self.assertIn('build t6-e1: c_LINKER t6-e1.p/main.c.o | libt6-s2.a libt6-s3.a\n', content)
        self.assertIn('build t7-e1: c_LINKER t7-e1.p/main.c.o | libt7-s3.a\n', content)
        self.assertIn('build t8-e1: c_LINKER t8-e1.p/main.c.o | libt8-s1.a libt8-s2.a libt8-s3.a\n', content)
        self.assertIn('build t9-e1: c_LINKER t9-e1.p/main.c.o | libt9-s1.a libt9-s2.a libt9-s3.a\n', content)
        self.assertIn('build t12-e1: c_LINKER t12-e1.p/main.c.o | libt12-s1.a libt12-s2.a libt12-s3.a\n', content)
        self.assertIn('build t13-e1: c_LINKER t13-e1.p/main.c.o | libt12-s1.a libt13-s3.a\n', content)
```