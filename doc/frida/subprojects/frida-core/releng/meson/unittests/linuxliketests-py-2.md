Response:
The user wants a summary of the functionalities present in the provided Python code. I need to go through each test function and extract its purpose. I also need to identify if any of these functionalities are related to reverse engineering, binary manipulation, Linux/Android kernel/framework, logical reasoning, or common user errors. Finally, I need to explain how a user might end up interacting with this code as part of a debugging process.

Here's a breakdown of the functionalities based on the test names and their implementation:

1. **`test_ldflagdedup`**: Checks if linker flags (specifically `--export-dynamic`) are deduplicated correctly.
2. **`test_compiler_libs_static_dedup`**: Verifies that common compiler libraries (like `-ldl`, `-lm`, etc.) are deduplicated when linking statically.
3. **`test_noncross_options`**: Ensures that compiler options (like `-std=c99`) defined in project options are applied during native compilation.
4. **`test_identity_cross`**: Tests a cross-compilation setup where the host and target compilers are the same (identity cross).
5. **`test_identity_cross_env`**: Similar to the previous test, but the compilers are specified through environment variables.
6. **`test_static_link`**: Checks the functionality of static linking and verifies that installed static libraries can be used.
7. **`_check_ld`**: A helper function to test if the correct linker is selected based on environment variables.
8. **`test_ld_environment_variable_*`**: Several tests using `_check_ld` to verify linker selection based on environment variables for different languages (C, C++, Rust, Objective-C, Objective-C++, Fortran, D).
9. **`compute_sha256`**:  A utility function to calculate the SHA256 hash of a file.
10. **`test_wrap_with_file_url`**: Tests the functionality of using local file URLs as fallbacks for wrap dependencies.
11. **`test_no_rpath_for_static`**: Verifies that rpaths are not added when linking statically.
12. **`test_lookup_system_after_broken_fallback`**: Checks that dependency lookup falls back to the system even if a previous fallback failed due to a missing subproject.
13. **`test_as_link_whole`**: Tests the `-Wl,--whole-archive` and `-Wl,--no-whole-archive` linker flags.
14. **`test_prelinking`**: Checks the functionality of prelinking.
15. **`do_one_test_with_nativefile`**: A helper function to run tests with a specified native file defining compiler paths.
16. **`test_cmake_multilib`**: Tests the integration with CMake, specifically handling multilib paths.
17. **`test_install_strip`**: Verifies the `--strip` option during installation to remove debug symbols.
18. **`test_isystem_default_removal_with_symlink`**: Checks the removal of default include directories when using `-isystem` with symlinks.
19. **`test_freezing`**: Tests a scenario related to freezing or a specific build state.
20. **`test_complex_link_cases`**: Tests various complex linking scenarios and verifies the generated Ninja build file.

Now I need to categorize these functionalities based on the prompt's criteria.
这是frida动态instrumentation工具的源代码文件 `frida/subprojects/frida-core/releng/meson/unittests/linuxliketests.py` 的第三部分，主要包含了一系列用于测试在类 Linux 系统上构建和链接 frida-core 的功能的单元测试。以下是根据代码内容归纳的功能点：

**主要功能归纳：**

* **链接器标志 (Linker Flags) 测试:** 验证链接器标志是否被正确处理，例如重复的标志是否会被去除 (`test_ldflagdedup`)。
* **编译器库 (Compiler Libraries) 测试:**  检查在静态链接时，编译器提供的标准库（如 `-ldl`, `-lm`, `-lc`, `-lrt`）是否会被正确地去重 (`test_compiler_libs_static_dedup`)。
* **非交叉编译选项 (Non-Cross Compilation Options) 测试:** 确保在本地编译时，项目选项中定义的编译器标准（如 `-std=c99`）能够生效 (`test_noncross_options`)。
* **交叉编译 (Cross Compilation) 测试:** 测试在宿主机和目标机使用相同编译器的情况下的交叉编译配置 (`test_identity_cross`, `test_identity_cross_env`)。
* **静态链接 (Static Linking) 测试:**  验证静态链接库的构建、安装和使用 (`test_static_link`)。
* **链接器选择 (Linker Selection) 测试:**  测试根据环境变量选择不同的链接器（如 bfd, gold, lld）的功能 (`test_ld_environment_variable_*`)。
* **Wrap 文件处理 (Wrap File Handling) 测试:**  测试使用本地文件 URL 作为 wrap 依赖的 fallback 功能 (`test_wrap_with_file_url`)。
* **静态链接不生成 RPATH (No RPATH for Static Linking) 测试:** 验证在静态链接时不会生成 RPATH (`test_no_rpath_for_static`)。
* **依赖查找 (Dependency Lookup) 测试:** 检查在 fallback 依赖失败后，系统库的查找是否正常工作 (`test_lookup_system_after_broken_fallback`)。
* **链接 Whole Archive (Link Whole Archive) 测试:** 测试使用 `-Wl,--whole-archive` 和 `-Wl,--no-whole-archive` 链接选项 (`test_as_link_whole`)。
* **预链接 (Prelinking) 测试:** 验证预链接功能是否正常工作 (`test_prelinking`)。
* **CMake 集成 (CMake Integration) 测试:** 测试 CMake 模块是否能正确处理多架构库路径 (`test_cmake_multilib`)。
* **安装 Strip (Install Strip) 测试:** 验证安装时 `--strip` 选项是否能正确移除调试符号 (`test_install_strip`)。
* **`isystem` 默认包含目录移除测试:** 检查使用符号链接的默认 include 目录在使用 `-isystem` 时是否被移除 (`test_isystem_default_removal_with_symlink`)。
* **构建冻结状态测试 (Freezing Test):** 测试与构建冻结状态相关的场景 (`test_freezing`)。
* **复杂链接场景测试 (Complex Link Cases):** 测试各种复杂的链接场景，并验证生成的 Ninja 构建文件是否正确 (`test_complex_link_cases`)。

**与逆向方法的关联和举例说明：**

* **二进制底层知识:** 所有的链接器相关的测试都直接涉及到二进制文件的生成和链接过程。逆向工程师需要理解链接过程才能分析最终的可执行文件或库文件。例如，`test_ldflagdedup` 测试的 `--export-dynamic` 标志对于逆向使用 `dlopen` 等动态加载机制加载的库非常重要。
* **Linux 内核及框架知识:** `test_no_rpath_for_static` 涉及到 RPATH，这是 Linux 加载器用于查找动态链接库的机制。理解 RPATH 的工作原理对于逆向分析动态链接的程序至关重要。
* **静态链接和动态链接:** 多个测试（如 `test_static_link`, `test_complex_link_cases`) 涉及静态和动态链接。逆向分析时需要区分这两种链接方式，因为它们会影响程序的结构和依赖关系。静态链接会将所有依赖的代码都包含在最终的可执行文件中，而动态链接则需要在运行时加载依赖的库。

**涉及二进制底层，linux, android内核及框架的知识和举例说明：**

* **链接器 (Linker):** 所有的链接器测试 (`test_ld_environment_variable_*`) 都直接操作底层的链接器。链接器负责将编译后的目标文件组合成可执行文件或库文件。不同的链接器（如 GNU ld, gold, lld）在处理链接过程中的行为可能略有不同。
* **ELF 文件格式:** 链接过程产生的是 ELF (Executable and Linkable Format) 文件，这是 Linux 下可执行文件和库文件的标准格式。逆向工程师需要深入理解 ELF 文件格式的结构，才能进行有效的分析和调试。
* **动态链接库加载:**  `test_static_link` 和 `test_complex_link_cases` 中涉及动态链接库的生成和使用。Linux 系统使用动态链接器（如 `ld-linux.so`）在程序运行时加载所需的动态链接库。
* **Android 平台:** 虽然这些测试主要针对类 Linux 系统，但 frida 也支持 Android 平台。Android 的动态链接机制与 Linux 类似，理解 Linux 的动态链接原理有助于理解 Android 上的动态链接。

**逻辑推理，假设输入与输出：**

* **`test_ldflagdedup`:**
    * **假设输入:** `meson.build` 文件中多次包含了 `-Wl,--export-dynamic` 链接标志。
    * **预期输出:** 生成的 `build.ninja` 文件中，`-Wl,--export-dynamic` 只会出现一次。
* **`test_compiler_libs_static_dedup`:**
    * **假设输入:** `meson.build` 文件中通过不同的方式（例如，直接指定或通过依赖关系）引入了需要链接 `-ldl`, `-lm` 等库的目标文件。
    * **预期输出:** 生成的 `build.ninja` 文件中，每一行链接命令中，`-ldl`, `-lm` 等库只会出现一次。

**涉及用户或者编程常见的使用错误和举例说明：**

* **重复指定链接器标志:**  `test_ldflagdedup` 模拟了用户可能在 `meson.build` 文件中错误地多次添加相同的链接器标志的情况。Meson 应该能够处理这种情况，避免在链接命令中出现重复的标志。
* **静态链接时未包含所有依赖库:** 虽然这个测试没有直接体现，但静态链接的一个常见错误是用户忘记链接某些依赖的静态库，导致链接失败。
* **动态链接库路径配置错误:**  `test_static_link` 间接涉及这个问题。如果用户在运行时没有正确配置 `LD_LIBRARY_PATH`，即使程序链接成功，也可能无法找到所需的动态链接库。
* **交叉编译配置错误:** `test_identity_cross` 和 `test_identity_cross_env`  测试了基本的交叉编译配置，用户在配置交叉编译环境时容易出错，例如指定错误的宿主机或目标机编译器。

**用户操作是如何一步步的到达这里，作为调试线索：**

一个开发者在为 frida-core 贡献代码或者调试构建系统时，可能会遇到构建失败或链接错误。为了定位问题，他们可能会：

1. **修改 `meson.build` 文件:**  例如，尝试添加特定的链接器标志，或者修改依赖关系。
2. **运行 `meson` 命令:**  重新配置构建系统以应用修改。
3. **运行 `ninja` 命令:**  执行实际的构建过程。
4. **观察构建错误:** 如果构建失败，开发者会查看 `ninja` 的输出，找到具体的错误信息。
5. **查看 `build.ninja` 文件:**  为了理解 Meson 如何生成构建规则，开发者可能会查看 `build.ninja` 文件，分析链接命令和依赖关系。
6. **运行单元测试:** 为了验证 Meson 的行为是否符合预期，开发者会运行相关的单元测试，例如 `linuxliketests.py` 中的测试。如果某个测试失败，可以帮助开发者定位 Meson 在处理特定链接场景时的错误。

例如，如果开发者发现链接器标志被重复添加，他们可能会检查 `test_ldflagdedup` 这个测试是否通过，如果测试失败，则说明 Meson 的去重逻辑存在问题。他们可能会进一步分析 `test_ldflagdedup` 的代码，了解测试的场景和断言，从而帮助他们理解错误的根源。

总而言之，`linuxliketests.py` 这个文件是 frida 构建系统的一个重要组成部分，它通过各种单元测试来保证在类 Linux 系统上构建和链接 frida-core 的正确性。 这些测试覆盖了链接器的行为、编译器选项、依赖管理等多个方面，对于确保 frida 的稳定性和可靠性至关重要。 对于逆向工程师来说，理解这些测试所涵盖的构建和链接知识，能够帮助他们更好地分析和理解 frida 的内部工作原理。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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