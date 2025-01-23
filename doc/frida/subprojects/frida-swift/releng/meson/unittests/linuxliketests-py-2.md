Response:
The user wants a summary of the Python code provided. I need to analyze the code and identify its main functionalities. The code seems to be a series of unit tests for the Meson build system, specifically targeting Linux-like environments and aspects related to linking, compiler flags, and dependency management.

Here's a breakdown of the functionalities I can identify:

1. **Deduplication of linker flags:** Testing that the `--export-dynamic` linker flag is not duplicated in the generated build files.
2. **Deduplication of compiler libraries:** Verifying that standard libraries like `-ldl`, `-lm`, `-lc`, and `-lrt` are not duplicated in linker commands.
3. **Handling of project options:** Ensuring that compiler flags defined in project options are correctly applied during native compilation.
4. **Cross-compilation testing:**  Setting up scenarios for identity cross-compilation, where the host and target compilers are the same.
5. **Static linking:** Testing the process of building and linking against static libraries.
6. **Overriding the linker via environment variables:** Checking if the linker can be overridden using environment variables like `LD`, `CXXLD`, etc.
7. **Wrap dependency handling with file URLs:** Testing the functionality of fetching and applying patches to wrap dependencies using local file URLs as fallbacks.
8. **No RPATH for static binaries:** Verifying that RPATH is not added to statically linked executables.
9. **Fallback dependency lookup:** Testing how Meson handles fallback dependencies when the primary dependency is not found.
10. **Link-time whole archive:**  Testing the `-Wl,--whole-archive` and `-Wl,--no-whole-archive` linker flags.
11. **Prelinking:** Testing the prelinking feature, which optimizes library loading.
12. **CMake multilib support:**  Testing the interaction between Meson and CMake, specifically regarding multilib configurations.
13. **Installation stripping:** Testing the removal of debug symbols during the installation process using the `--strip` flag.
14. **Removal of default include directories:**  Testing the removal of default system include directories when using `-isystem` with symbolic links.
15. **Freezing:** Testing the "freezing" functionality, likely related to creating reproducible builds.
16. **Complex linking scenarios:** Testing various complex linking scenarios involving static and shared libraries and their dependencies.

Now, I will address the specific questions raised in the prompt:

*   **Relationship to reverse engineering:**  The tests related to linker flags (`--export-dynamic`), static linking, and the ability to override linkers directly relate to reverse engineering. Understanding how binaries are linked and what symbols are exported is crucial for analyzing and modifying them.
*   **Binary/kernel knowledge:** The tests involving static linking, prelinking, and RPATH directly interact with how the operating system loads and links libraries. The tests related to linker overrides touch upon the underlying system tools used for binary manipulation.
*   **Logical inferences:** The tests often involve setting up specific input scenarios (e.g., creating specific file structures, setting environment variables) and then asserting the expected output or behavior (e.g., the content of generated build files, the presence or absence of certain linker flags).
*   **User errors:**  The tests implicitly cover potential user errors. For instance, incorrect or missing dependencies could lead to fallback scenarios being triggered, or misunderstanding the impact of static linking could lead to unexpected behavior.
*   **User steps to reach the code:** A developer working on the Frida project, specifically the Swift bindings, would be writing these unit tests to ensure the build system behaves correctly in various scenarios on Linux-like systems. They would modify the Meson build files or the underlying C/C++ code and then run these tests to verify their changes.

Finally, I need to summarize the overall functionality of the code.
这是Frida动态Instrumentation工具中，位于`frida/subprojects/frida-swift/releng/meson/unittests/linuxliketests.py`的源代码文件，它是一系列用于测试在Linux类系统上使用Meson构建系统时的特定功能的单元测试。

**功能归纳:**

总的来说，这个文件包含了一系列针对Linux类环境的Meson构建系统行为的自动化测试。这些测试覆盖了编译、链接、依赖管理、安装等多个方面，旨在确保Frida项目在使用Meson构建时能够正确地处理各种Linux特有的场景和配置。

**更详细的功能点:**

1. **测试链接器标志的去重:** 验证链接器标志（例如 `--export-dynamic`）在生成的构建文件中不会被重复添加。
2. **测试编译器库的静态链接去重:** 确保标准C库（例如 `-ldl`, `-lm`, `-lc`, `-lrt`）在链接时不会被重复指定。
3. **测试非交叉编译选项:** 验证在本地编译时，项目选项中定义的C标准（例如 `-std=c99`）能够生效。
4. **测试同一平台的交叉编译:**  测试一种特殊的交叉编译场景，其中构建平台和目标平台相同。这可能用于测试构建系统的某些内部逻辑。
5. **测试通过环境变量定义的同一平台交叉编译:** 类似于上一点，但通过环境变量来指定构建和目标平台的编译器。
6. **测试静态链接:**  构建一些静态库并安装，然后在一个新的构建环境中测试链接这些已安装的静态库。
7. **测试通过环境变量覆盖链接器:**  验证可以通过设置环境变量（例如 `LD`, `CXXLD`等）来覆盖默认的链接器。这包括测试不同的链接器实现，如 `bfd`, `gold`, `lld`。
8. **测试使用本地文件URL的wrap依赖:** 测试当网络URL不可用时，可以使用本地文件URL作为后备来获取wrap依赖的源代码和补丁。
9. **测试静态链接时不添加rpath:** 验证在构建静态链接的可执行文件时，不会添加rpath信息。
10. **测试在回退到系统查找之前的错误回退处理:** 测试当一个依赖项回退到不存在的子项目时，不会阻止后续的依赖项在系统中查找。
11. **测试 `-Wl,--whole-archive` 的使用:**  测试链接器标志 `-Wl,--whole-archive` 和 `-Wl,--no-whole-archive` 的正确应用。
12. **测试预链接 (Prelinking):** 测试预链接功能，这是一种优化共享库加载速度的技术。
13. **使用native file进行测试:**  允许通过外部的 native file 指定编译器等构建工具，用于测试特定的构建场景。
14. **测试CMake multilib支持:**  验证Meson的CMake模块能够正确处理multilib路径。
15. **测试安装时的strip操作:** 测试在安装时使用 `--strip` 参数移除调试符号的功能。
16. **测试使用符号链接的isystem默认移除:** 测试在使用 `-isystem` 包含系统头文件目录的符号链接时，默认行为是移除这些路径。
17. **测试冻结 (Freezing):** 测试“冻结”构建环境的功能，这可能与确保构建的可重复性有关。
18. **测试复杂的链接场景:**  测试各种复杂的链接场景，包括静态库和共享库之间的依赖关系。

**与逆向方法的联系及举例说明:**

*   **链接器标志 (`--export-dynamic`) 测试:**  逆向工程中，了解哪些符号被动态导出是非常重要的。`--export-dynamic` 标志会影响动态链接库中符号的可见性。如果该测试失败，可能意味着Frida在某些情况下无法正确导出符号，从而影响到hook和instrumentation的功能。例如，如果一个关键函数没有被正确导出，Frida就可能无法hook它。
*   **静态链接测试:** 逆向静态链接的二进制文件与动态链接的文件有所不同。静态链接将所有依赖的代码都包含在最终的可执行文件中。这个测试确保Meson能够正确处理静态链接，这对于Frida来说也很重要，因为它可能需要与静态链接的库进行交互。
*   **通过环境变量覆盖链接器:**  在逆向分析时，有时需要使用特定的链接器或链接器版本来重现构建环境或进行特定的二进制修改。这个测试确保Meson允许通过环境变量灵活地指定链接器。

**涉及到二进制底层、Linux、Android内核及框架的知识及举例说明:**

*   **静态链接和共享链接:**  测试中涉及静态库 (`.a`) 和共享库 (`.so`, `.dylib`) 的构建和链接，这直接关系到操作系统加载和链接二进制文件的方式。例如，静态链接会将所有依赖项打包到最终的可执行文件中，而共享链接则依赖于运行时加载的动态库。
*   **RPATH:**  RPATH (Run-Time Search Path) 是一种在可执行文件中指定动态链接库搜索路径的机制。测试确保静态链接的二进制文件不会包含 RPATH，因为它们不需要在运行时查找外部库。
*   **预链接 (Prelinking):**  预链接是一种优化技术，旨在减少动态链接库的加载时间。它涉及到在安装时重新定位共享库的代码和数据。这个测试涉及到对Linux系统库加载机制的理解。
*   **安装时的strip操作:** `strip` 命令用于移除二进制文件中的符号表和调试信息，减小文件大小。这个测试涉及到对二进制文件格式（例如 ELF）的理解。

**逻辑推理的假设输入与输出:**

以 **测试链接器标志的去重** 为例：

*   **假设输入:** 一个简单的Meson项目，其中定义了一个需要动态链接的目标，并且在链接选项中多次（实际上是隐含地）包含了请求动态导出的标志。
*   **预期输出:** 生成的 `build.ninja` 文件中，关于该目标的链接命令中，`--export-dynamic` 标志只出现一次。如果出现多次，则测试失败，因为这意味着链接器标志没有被正确去重。

以 **测试静态链接** 为例：

*   **假设输入:** 两个Meson项目，第一个项目构建并安装一个静态库，第二个项目链接这个已安装的静态库。
*   **预期输出:** 第二个项目能够成功构建并运行，说明静态库被正确链接。如果构建失败或运行时找不到库，则测试失败。

**涉及用户或编程常见的使用错误及举例说明:**

*   **依赖项缺失或配置错误:**  在 **测试静态链接** 或 **测试wrap依赖** 时，如果用户配置了错误的依赖路径或者依赖文件不存在，测试会验证Meson是否能够正确处理这些错误情况，例如给出清晰的错误信息或回退到备用方案。
*   **不理解静态链接和共享链接的区别:** 用户可能错误地将静态链接库用于需要动态链接的场景，或者反之。虽然这个测试本身不是直接测试用户错误，但它的成功运行确保了Meson不会在这种情况下引入额外的错误。
*   **环境变量配置错误:** 在 **测试通过环境变量覆盖链接器** 时，如果用户设置了错误的链接器路径或名称，测试会验证Meson是否按照用户的配置尝试使用指定的链接器，并在失败时给出相应的提示。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发人员修改了 Frida 的 Swift 绑定相关的代码。**
2. **开发人员希望确保其修改没有破坏现有的构建流程，特别是在 Linux 类系统上。**
3. **开发人员运行 Frida 的单元测试套件。**
4. **测试框架执行到 `frida/subprojects/frida-swift/releng/meson/unittests/linuxliketests.py` 文件中的某个测试用例。**
5. **如果某个测试用例失败，开发人员会查看该文件的源代码，理解测试的意图和具体的断言，以便定位问题。**
6. **例如，如果 `test_ldflagdedup` 失败，开发人员会检查生成的 `build.ninja` 文件，查看链接命令中 `--export-dynamic` 是否出现了多次，从而判断是哪个环节引入了重复的标志。**

总而言之，这个文件是 Frida 项目质量保证的关键部分，它通过自动化测试来确保 Meson 构建系统在 Linux 类环境下的行为符合预期，覆盖了编译链接的多个重要方面，并间接地反映了底层二进制、操作系统以及用户可能遇到的问题。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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