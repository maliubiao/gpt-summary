Response:
The user wants to understand the functionality of the provided Python code snippet. This code appears to be part of the unit tests for the Frida dynamic instrumentation tool, specifically focusing on aspects related to building software on Linux-like systems.

To answer the user's request, I need to:

1. **Identify the main functionalities** demonstrated by the test methods in the code.
2. **Relate these functionalities to reverse engineering** if applicable, providing examples.
3. **Point out connections to binary, Linux, Android kernel/framework knowledge**, giving illustrative examples.
4. **Analyze tests involving logical reasoning**, providing assumed inputs and expected outputs.
5. **Highlight common user errors** that the tests might be preventing.
6. **Explain how a user might reach this code**, focusing on debugging scenarios.
7. **Summarize the overall functionality** of this code snippet.

Let's break down each test method:

*   `test_ldflagdedup`: Checks if linker flags (specifically `--export-dynamic`) are deduplicated correctly in the generated `build.ninja` file.
*   `test_compiler_libs_static_dedup`: Verifies that common static compiler libraries (`-ldl`, `-lm`, `-lc`, `-lrt`) are not duplicated in the link command.
*   `test_noncross_options`: Ensures that compiler options defined in the project options (like `-std=c99`) are applied during native compilation.
*   `test_identity_cross`: Deals with cross-compilation scenarios where the host and target compilers are the same.
*   `test_identity_cross_env`: Similar to the above but sets compiler paths through environment variables.
*   `test_static_link`: Tests the process of building and linking against static libraries, ensuring correct usage of `-L` flags and `PKG_CONFIG_LIBDIR`.
*   `test_ld_environment_variable_*`: Checks if the Meson build system correctly uses the specified linker (ld.bfd, ld.gold, ld.lld) based on environment variables.
*   `test_wrap_with_file_url`: Tests the functionality of using file URLs as fallback sources for wrap dependencies.
*   `test_no_rpath_for_static`: Verifies that rpath is not added when linking static executables.
*   `test_lookup_system_after_broken_fallback`: Checks if Meson can correctly fall back to system libraries after a subproject dependency fails.
*   `test_as_link_whole`: Tests the `-Wl,--whole-archive` and `-Wl,--no-whole-archive` linker flags.
*   `test_prelinking`: Examines the prelinking process for shared libraries.
*   `do_one_test_with_nativefile`: A helper function to test scenarios with custom native files.
*   `test_cmake_multilib`: Specifically tests CMake integration and handling of multilib paths.
*   `test_install_strip`: Checks the `--strip` option during installation to remove debug symbols.
*   `test_isystem_default_removal_with_symlink`: Verifies the handling of `isystem` include paths with symlinks.
*   `test_freezing`: Tests the freezing of build dependencies.
*   `test_complex_link_cases`:  Verifies complex linking scenarios with dependencies between static and shared libraries.

Now, let's connect these functionalities to the user's prompts.
这是 frida 动态instrumentation 工具源代码文件 `frida/subprojects/frida-gum/releng/meson/unittests/linuxliketests.py` 的第三部分，主要包含了一系列针对 Linux-like 系统的单元测试，用于验证 Frida-gum 构建系统的各种功能和特性。以下是其功能的归纳：

**功能归纳:**

这部分代码主要负责测试 Frida-gum 构建系统在 Linux-like 环境下的以下功能：

1. **链接器行为和标志处理:**
    *   测试链接器标志 (`--export-dynamic`) 的正确去重，避免重复添加导致的问题。
    *   验证常见静态链接库（如 `dl`, `m`, `c`, `rt`）在链接命令中不会重复出现。
    *   测试通过环境变量 (`*_ld`) 显式指定链接器 (bfd, gold, lld) 的功能是否正常工作。
    *   检查静态链接时是否正确地移除了 `rpath`，避免不必要的运行时库搜索路径。
    *   测试 `-Wl,--whole-archive` 和 `-Wl,--no-whole-archive` 链接器标志的使用。
    *   验证复杂的链接场景，包括静态库和共享库之间的依赖关系。
    *   测试预链接 (prelinking) 功能是否按预期工作 (GNU toolchains)。

2. **编译选项处理:**
    *   确保在项目选项中定义的编译器标准（如 `-std=c99`）在本地编译时生效。
    *   测试使用符号链接的默认系统包含路径 (`isystem`) 的处理。

3. **交叉编译:**
    *   测试“身份交叉编译”场景，即构建平台和目标平台相同的情况。

4. **依赖管理:**
    *   测试在子项目依赖查找失败后，系统依赖查找是否能够正常工作。
    *   验证使用 `file://` URL 作为 wrap 文件的备用源的功能。
    *   测试构建依赖的“冻结”机制。

5. **安装和剥离 (Stripping):**
    *   测试安装过程中使用 `--strip` 选项去除调试符号的功能。

6. **CMake 集成:**
    *   测试 CMake 模块是否能正确处理多架构库路径 (multilib)。

7. **自定义构建配置:**
    *   支持通过 `--native-file` 参数指定自定义的构建工具链配置。

**与逆向方法的关系及举例说明:**

Frida 本身就是一个强大的动态 instrumentation 工具，广泛应用于逆向工程。这部分测试虽然主要关注构建系统，但其正确性直接影响到 Frida 工具的构建和使用。

*   **动态库加载和符号解析:**  `test_ldflagdedup` 确保了 `--export-dynamic` 标志的正确使用，这个标志对于导出动态库中的符号至关重要。在逆向分析时，Frida 需要能够 hook 目标进程的函数，而这些函数的符号需要被正确导出。如果该标志没有正确处理，可能导致 Frida 无法找到目标函数。

    *   **举例:**  假设你要使用 Frida hook 一个动态库 `libtarget.so` 中的函数 `target_function`。如果构建 `libtarget.so` 时 `--export-dynamic` 没有被正确添加，那么 Frida 可能无法解析到 `target_function` 的地址，导致 hook 失败。

*   **静态链接和符号剥离:**  `test_no_rpath_for_static` 和 `test_install_strip` 涉及静态链接和符号剥离。静态链接可以将所有依赖库的代码都打包到最终的可执行文件中，避免运行时依赖问题。而符号剥离则可以减小最终文件的大小，但也使得逆向分析更加困难。

    *   **举例:**  如果你逆向分析一个静态链接的可执行文件，并且构建时使用了符号剥离，那么你将无法直接看到函数名等符号信息，需要使用更高级的技术来恢复这些信息。

*   **依赖管理和第三方库:**  `test_wrap_with_file_url` 和 `test_lookup_system_after_broken_fallback` 涉及到依赖管理。在构建 Frida 或依赖 Frida 的工具时，可能需要链接到各种第三方库。这些测试确保了在各种情况下，构建系统都能正确地找到并链接这些依赖库。

    *   **举例:**  Frida 自身可能依赖于一些网络库或加密库。这些测试保证了即使网络源不可用，或者子项目构建失败，也能回退到本地文件或系统库，确保 Frida 能够成功构建。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明:**

*   **链接器 (ld):**  大部分测试都直接或间接地与链接器相关，例如测试链接器标志、环境变量、以及不同链接器 (bfd, gold, lld) 的支持。链接器是将编译后的目标文件组合成最终可执行文件或库的关键工具，理解其工作原理对于理解二进制文件的结构至关重要。

    *   **举例:**  `test_ld_environment_variable_*` 测试了通过环境变量指定不同的链接器。不同的链接器在处理链接过程和生成最终文件的方式上可能存在细微差别，了解这些差异对于解决构建问题或深入理解二进制文件格式很有帮助。

*   **动态链接库 (.so) 和静态链接库 (.a):** 测试中涉及到对动态链接和静态链接的处理，以及它们在构建过程中的不同行为。理解动态链接和静态链接的区别对于理解程序运行时库加载和符号解析至关重要。

    *   **举例:**  `test_static_link` 测试了如何链接静态库。静态库的代码会被直接嵌入到最终的可执行文件中，而动态库则是在运行时加载。这两种链接方式在性能、文件大小和依赖管理方面有不同的特点。

*   **rpath:**  `test_no_rpath_for_static` 关注 `rpath` 的处理。`rpath` 是可执行文件中指定运行时库搜索路径的机制。理解 `rpath` 对于调试动态库加载问题非常重要。

    *   **举例:**  如果一个可执行文件依赖于一个非标准路径下的动态库，那么需要在构建时设置 `rpath`，以便程序运行时能够找到该库。

*   **预链接 (Prelinking):** `test_prelinking` 涉及到预链接技术。预链接是一种优化技术，旨在减少动态链接的开销。理解预链接的工作原理可以帮助分析程序的启动性能。

    *   **举例:**  预链接会将共享库加载到内存中的固定地址，从而减少运行时链接器的工作量。但这也会带来一些潜在的安全风险，例如地址空间布局随机化 (ASLR) 的削弱。

*   **符号剥离 (Stripping):** `test_install_strip` 测试了符号剥离。理解符号剥离对于逆向工程至关重要，因为剥离符号后的二进制文件难以直接分析。

    *   **举例:**  Android 系统中的很多系统库和应用在发布时都会进行符号剥离，这增加了逆向分析的难度。

**逻辑推理，假设输入与输出:**

*   **`test_ldflagdedup`:**
    *   **假设输入:** `meson.build` 文件中多次指定了链接器标志 `-Wl,--export-dynamic`。
    *   **预期输出:** 生成的 `build.ninja` 文件中，`-Wl,--export-dynamic` 只会出现一次。

*   **`test_compiler_libs_static_dedup`:**
    *   **假设输入:** `meson.build` 文件中由于某些依赖关系，可能导致多次请求链接相同的标准库（如 `-ldl`）。
    *   **预期输出:** 生成的链接命令中，每个标准库只会出现一次。

*   **`test_noncross_options`:**
    *   **假设输入:** `meson_options.txt` 中设置了 `c_std = 'c99'`。
    *   **预期输出:** 编译命令中会包含 `-std=c99`。

**用户或编程常见的使用错误及举例说明:**

*   **重复指定链接器标志:** 用户可能在 `meson.build` 文件或命令行中多次指定相同的链接器标志，例如 `-Wl,--export-dynamic`。`test_ldflagdedup` 可以防止这种错误导致的问题。

*   **忘记添加必要的链接库:** 用户可能在构建动态库或可执行文件时忘记链接某些必要的系统库（如 `dl`, `m`, `c`, `rt`）。虽然构建系统通常会自动处理这些库，但在某些特殊情况下可能需要显式指定。`test_compiler_libs_static_dedup` 隐含地确保了这些常见库的正确链接。

*   **交叉编译配置错误:** 在进行交叉编译时，用户可能配置了错误的 host 或 target 编译器。`test_identity_cross` 和 `test_identity_cross_env` 帮助验证交叉编译的基本配置是否正确。

*   **静态链接时错误地添加 rpath:** 用户可能在构建静态链接的可执行文件时错误地添加了 `rpath`。`test_no_rpath_for_static` 可以避免这种错误。

*   **Wrap 文件配置错误:** 在使用 wrap 文件管理子项目依赖时，用户可能配置了错误的源 URL 或哈希值。`test_wrap_with_file_url` 确保了在网络源不可用时，可以正确回退到本地文件。

**用户操作是如何一步步的到达这里，作为调试线索:**

一个开发者在为 Frida-gum 开发或调试新的构建功能时，可能会修改相关的 Meson 构建脚本或源代码。为了确保这些修改没有引入 bug，他们会运行单元测试。

1. **修改 Frida-gum 的构建代码:** 开发者可能修改了 `meson.build` 文件、Python 构建脚本或其他与构建过程相关的代码。

2. **运行单元测试:** 开发者会使用命令（例如 `meson test -C builddir`）来运行 Frida-gum 的单元测试。

3. **执行 `linuxliketests.py`:** Meson 测试框架会加载并执行 `linuxliketests.py` 文件中的各个测试函数。

4. **某个测试失败:** 如果开发者引入了 bug，例如链接器标志处理错误，那么像 `test_ldflagdedup` 这样的测试就会失败。

5. **查看测试输出:** 开发者会查看测试输出，其中包含了失败的测试函数名和断言错误信息。

6. **分析代码:** 开发者会根据失败的测试函数名（例如 `test_ldflagdedup`）定位到 `frida/subprojects/frida-gum/releng/meson/unittests/linuxliketests.py` 文件中的相应代码，并分析其逻辑和断言。

7. **定位 bug:** 通过分析测试代码和相关的 Frida-gum 构建代码，开发者可以找到导致测试失败的 bug。

8. **修复 bug 并重新测试:** 开发者修复 bug 后，会再次运行单元测试，确保所有测试都通过。

因此，开发者查看 `linuxliketests.py` 的目的是为了理解测试用例的逻辑，分析测试失败的原因，并最终定位和修复 Frida-gum 构建系统中的 bug。这个文件是调试 Frida-gum 构建过程的关键线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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