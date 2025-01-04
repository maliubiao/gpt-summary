Response:
The user wants a summary of the functionality of the provided Python code. This code is a test suite for the Frida dynamic instrumentation tool, specifically focusing on features related to building and packaging software on Linux-like systems using the Meson build system.

To provide a comprehensive summary, I will go through each test function and identify the core functionality being tested. I will also highlight any connections to reverse engineering, low-level concepts, logic reasoning, common user errors, and how a user might trigger these tests.
这是 `frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py` 文件代码的第二部分，主要功能是测试 Frida 工具在 Linux-like 环境下使用 Meson 构建系统时的一些特定功能和行为。以下是对其功能的归纳总结：

**主要功能归纳:**

这部分代码主要测试了以下与软件构建和安装相关的特性，尤其关注 Linux-like 系统的一些特定概念：

1. **C++ 标准覆盖 (test\_cpp\_std\_override):** 测试 Meson 是否能正确处理针对不同源文件指定的 C++ 标准版本（例如，C++98, C++11）。它验证了编译命令中是否包含了正确的 `-std=c++XX` 标志，并且能够根据配置添加或移除 `-Werror` 标志。

2. **运行已安装的程序 (test\_run\_installed):**  测试已安装的程序能否在没有设置 `LD_LIBRARY_PATH` 的情况下运行失败（因为 RPATH 应该被正确剥离），以及在设置 `LD_LIBRARY_PATH` 后能否正常运行。 这也测试了 `meson introspect --installed` 命令能否正确列出已安装的文件。

3. **`-L` 和 `-l` 参数的顺序 (test\_order\_of\_l\_arguments):** 测试链接器参数 `-L` (库路径) 和 `-l` (库名称) 的顺序是否在生成的 `build.ninja` 文件中保持一致。这对于确保链接的正确性至关重要。

4. **内省依赖 (test\_introspect\_dependencies):** 测试 `meson introspect --dependencies` 命令能否正确返回项目的依赖信息，包括依赖库的名称、编译参数和链接参数。

5. **内省已安装的文件 (test\_introspect\_installed):** 测试 `meson introspect --installed` 命令能否正确列出已安装的文件及其路径，并能根据操作系统 (macOS 或其他 Linux-like 系统) 生成不同的预期结果。

6. **构建 RPATH (test\_build\_rpath):** 测试 Meson 能否正确处理构建时和安装时的 RPATH (Run-Time Path) 设置。RPATH 用于指定程序运行时查找共享库的路径。测试验证了构建目录和安装目录下的可执行文件的 RPATH 是否符合预期。

7. **使用 pkg-config 的构建 RPATH (test\_build\_rpath\_pkgconfig):**  测试在使用 pkg-config 获取依赖库信息时，构建的 RPATH 的优先级顺序：当前构建产物优先，手动指定的 RPATH 次之，pkg-config 文件提供的 RPATH 最后。

8. **全局 RPATH (test\_global\_rpath):** 测试通过 `LDFLAGS` 环境变量设置全局 RPATH 是否能被 Meson 正确处理，并体现在最终安装的程序中。

9. **带 Address Sanitizer 的 PCH (test\_pch\_with\_address\_sanitizer):** 测试在使用 Address Sanitizer 进行代码检测时，预编译头文件 (PCH) 能否正常工作。

10. **交叉编译查找程序 (test\_cross\_find\_program):** 测试在交叉编译环境下，Meson 能否正确查找交叉编译工具链中的程序。

11. **重新配置 (test\_reconfigure):** 测试在已配置的项目上再次运行 Meson 进行重新配置是否能正常工作。

12. **Vala 生成的源文件路径 (test\_vala\_generated\_source\_buildir\_inside\_source\_tree):** 测试当构建目录位于源目录的子目录中时，Vala 编译器生成的 C 代码是否输出到预期位置。

13. **旧版 GNOME 模块代码路径 (test\_old\_gnome\_module\_codepaths):**  模拟旧版本的 GLib 工具链环境，测试 GNOME 模块中的兼容性代码路径是否能正常工作。

14. **pkg-config 的使用 (test\_pkgconfig\_usage):** 测试使用 pkg-config 获取依赖库信息时的各种情况，包括私有库的处理、头文件依赖的泄漏问题，以及构建和运行依赖 pkg-config 的程序。

15. **pkg-config 相对路径 (test\_pkgconfig\_relative\_paths):** 测试 pkg-config 文件中使用相对路径时，Meson 能否正确解析。

16. **pkg-config 重复路径条目 (test\_pkgconfig\_duplicate\_path\_entries):** 测试 Meson 如何处理重复的 pkg-config 路径条目。

17. **pkg-config 内部库 (test\_pkgconfig\_internal\_libraries):** 测试使用 pkg-config 查找内部库的情况。

18. **静态库 strip (test\_static\_archive\_stripping):** 测试在启用 strip 选项后，Meson 生成的静态库是否仍然有效。

19. **pkg-config 格式化 (test\_pkgconfig\_formatting):** 测试 `pkg-config` 命令输出的库链接参数的格式是否正确。

20. **pkg-config C# 库 (test\_pkgconfig\_csharp\_library):** 测试针对 C# 库的 pkg-config 输出是否符合预期。

21. **pkg-config 链接顺序 (test\_pkgconfig\_link\_order):** 测试 pkg-config 返回的库链接顺序是否正确，确保依赖库在被依赖库之后。

22. **确定性的依赖顺序 (test\_deterministic\_dep\_order):** 测试构建规则中依赖项的顺序是否总是确定的。

23. **确定性的 RPATH 顺序 (test\_deterministic\_rpath\_order):** 测试 RPATH 的顺序是否总是确定的。

24. **使用可执行依赖覆盖 (test\_override\_with\_exe\_dep):** 测试当一个程序被另一个可执行文件覆盖时，生成的依赖关系是否正确。

25. **使用外部库 (test\_usage\_external\_library):** 测试如何使用系统或 pkg-config 提供的外部库，并关注 macOS 上 DESTDIR 不会添加到 install\_name 的情况。

26. **链接参数全名 (test\_link\_arg\_fullname):** 测试支持 `-l:libfullname.a` 格式的链接参数。

27. **使用 pkg-config 前缀 (test\_usage\_pkgconfig\_prefixes):** 测试当使用 pkg-config 查找位于不同前缀的多个外部库时，客户端程序能否正确构建和运行。

28. **安装子目录中的无效符号链接 (install\_subdir\_invalid\_symlinks, test\_install\_subdir\_symlinks, test\_install\_subdir\_symlinks\_with\_default\_umask, test\_install\_subdir\_symlinks\_with\_default\_umask\_and\_mode):** 测试安装子目录中的无效符号链接是否能正常处理。

**与逆向方法的关联和举例说明:**

*   **运行已安装的程序 (test\_run\_installed):**  逆向工程师在分析已安装的二进制文件时，需要理解其依赖关系。这个测试模拟了在没有正确设置环境变量的情况下运行程序失败的情况，这与逆向分析时需要找到正确的库路径才能加载程序模块是相关的。例如，如果一个逆向工程师尝试直接运行一个依赖共享库的二进制文件，但没有设置 `LD_LIBRARY_PATH`，就会遇到类似的问题。
*   **构建 RPATH (test\_build\_rpath):**  RPATH 直接影响到程序运行时如何查找依赖的共享库。逆向工程师在分析二进制文件时，可以使用诸如 `readelf -d <binary>` (Linux) 或 `otool -l <binary>` (macOS) 等工具来查看 RPATH，从而了解程序的库依赖关系和加载路径。理解 RPATH 对于绕过某些安全机制或进行动态调试至关重要。

**涉及二进制底层，Linux，Android 内核及框架的知识的举例说明:**

*   **运行已安装的程序 (test\_run\_installed) 和 构建 RPATH (test\_build\_rpath):**  这两个测试都直接涉及到 Linux 系统中动态链接器的工作方式和 RPATH 的概念。RPATH 存储在 ELF 二进制文件的头部，指示动态链接器在运行时优先查找共享库的路径。这属于 Linux 系统加载器和链接器的底层知识。Android 也基于 Linux 内核，虽然其动态链接机制有所不同，但理解 RPATH 的概念对于理解 Android 本地库的加载也是有帮助的。
*   **全局 RPATH (test\_global\_rpath):**  测试通过 `LDFLAGS` 传递链接器选项，这涉及到编译链接过程的底层细节，以及如何通过环境变量影响链接器的行为。
*   **带 Address Sanitizer 的 PCH (test\_pch\_with\_address\_sanitizer):** Address Sanitizer 是一种基于编译器的内存错误检测工具，它需要在编译时进行特定的插桩。这个测试涉及到编译器选项和底层代码检测机制。

**逻辑推理的假设输入与输出:**

*   **C++ 标准覆盖 (test\_cpp\_std\_override):**
    *   **假设输入:**  包含分别需要 C++98 和 C++11 标准编译的源文件，以及一个没有指定标准版本的源文件。
    *   **预期输出:**  编译命令中，C++98 源文件包含 `-std=c++98`，C++11 源文件包含 `-std=c++11`，未指定版本的源文件不包含这两个标志。同时，根据配置，某些编译命令可能包含 `-Werror`。
*   **使用 pkg-config 的构建 RPATH (test\_build\_rpath\_pkgconfig):**
    *   **假设输入:** 一个项目依赖于通过 pkg-config 找到的库，并且 Meson 构建定义了额外的 RPATH。
    *   **预期输出:**  构建生成的可执行文件的 RPATH 按照优先级排序：`$ORIGIN` 相关路径（指向构建目录下的库），手动指定的 RPATH，最后是 pkg-config 提供的 RPATH。

**涉及用户或者编程常见的使用错误的举例说明:**

*   **运行已安装的程序 (test\_run\_installed):**  用户常见的错误是在运行已安装的程序时忘记设置 `LD_LIBRARY_PATH`，导致程序找不到依赖的共享库而无法启动。这个测试模拟了这种情况，并验证了 Meson 生成的构建系统是否正确处理了 RPATH，使得即使没有设置 `LD_LIBRARY_PATH`，程序也能在安装后通过 RPATH 找到库。
*   **使用 pkg-config 的构建 RPATH (test\_build\_rpath\_pkgconfig):**  开发者可能错误地期望 pkg-config 提供的 RPATH 会覆盖手动指定的 RPATH。这个测试验证了 Meson 遵循预期的优先级顺序。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

为了运行这些测试，开发者通常会执行以下步骤：

1. **安装 Frida 和 Meson:**  首先需要在开发环境中安装 Frida 和 Meson 构建系统。
2. **克隆 Frida 仓库:**  获取 Frida 的源代码，其中包含了测试代码。
3. **进入构建目录:**  在 Frida 源代码目录下创建一个构建目录（例如 `build`）。
4. **配置构建:**  在构建目录下运行 `meson` 命令，指向 Frida 源代码的根目录。
5. **编译测试:**  运行 `ninja unittests` 命令来编译单元测试。
6. **运行特定的测试:**  运行 `ninja test -v -C build frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py::TestLinuxLikeTests::<test_function_name>` 来运行 `linuxliketests.py` 文件中的特定测试函数。例如，要运行 `test_cpp_std_override`，命令会是 `ninja test -v -C build frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py::TestLinuxLikeTests::test_cpp_std_override`。

作为调试线索，如果某个构建或安装相关的功能出现问题，开发者可能会逐步检查这些单元测试的执行结果，查看是否有相关的测试失败。例如，如果用户报告已安装的程序无法运行，开发者可能会首先运行 `test_run_installed` 来验证 RPATH 的处理是否正确。如果涉及到与 pkg-config 的集成问题，则会检查 `test_pkgconfig_usage` 等相关测试。这些测试覆盖了构建过程中的关键环节，可以帮助开发者快速定位问题所在。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
    def test_cpp_std_override(self):
        testdir = os.path.join(self.unit_test_dir, '6 std override')
        self.init(testdir)
        compdb = self.get_compdb()
        # Don't try to use -std=c++03 as a check for the
        # presence of a compiler flag, as ICC does not
        # support it.
        for i in compdb:
            if 'prog98' in i['file']:
                c98_comp = i['command']
            if 'prog11' in i['file']:
                c11_comp = i['command']
            if 'progp' in i['file']:
                plain_comp = i['command']
        self.assertNotEqual(len(plain_comp), 0)
        self.assertIn('-std=c++98', c98_comp)
        self.assertNotIn('-std=c++11', c98_comp)
        self.assertIn('-std=c++11', c11_comp)
        self.assertNotIn('-std=c++98', c11_comp)
        self.assertNotIn('-std=c++98', plain_comp)
        self.assertNotIn('-std=c++11', plain_comp)
        # Now werror
        self.assertIn('-Werror', plain_comp)
        self.assertNotIn('-Werror', c98_comp)

    def test_run_installed(self):
        if is_cygwin() or is_osx():
            raise SkipTest('LD_LIBRARY_PATH and RPATH not applicable')

        testdir = os.path.join(self.unit_test_dir, '7 run installed')
        self.init(testdir)
        self.build()
        self.install()
        installed_exe = os.path.join(self.installdir, 'usr/bin/prog')
        installed_libdir = os.path.join(self.installdir, 'usr/foo')
        installed_lib = os.path.join(installed_libdir, 'libfoo.so')
        self.assertTrue(os.path.isfile(installed_exe))
        self.assertTrue(os.path.isdir(installed_libdir))
        self.assertTrue(os.path.isfile(installed_lib))
        # Must fail when run without LD_LIBRARY_PATH to ensure that
        # rpath has been properly stripped rather than pointing to the builddir.
        self.assertNotEqual(subprocess.call(installed_exe, stderr=subprocess.DEVNULL), 0)
        # When LD_LIBRARY_PATH is set it should start working.
        # For some reason setting LD_LIBRARY_PATH in os.environ fails
        # when all tests are run (but works when only this test is run),
        # but doing this explicitly works.
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = ':'.join([installed_libdir, env.get('LD_LIBRARY_PATH', '')])
        self.assertEqual(subprocess.call(installed_exe, env=env), 0)
        # Ensure that introspect --installed works
        installed = self.introspect('--installed')
        for v in installed.values():
            self.assertTrue('prog' in v or 'foo' in v)

    @skipIfNoPkgconfig
    def test_order_of_l_arguments(self):
        testdir = os.path.join(self.unit_test_dir, '8 -L -l order')
        self.init(testdir, override_envvars={'PKG_CONFIG_PATH': testdir})
        # NOTE: .pc file has -Lfoo -lfoo -Lbar -lbar but pkg-config reorders
        # the flags before returning them to -Lfoo -Lbar -lfoo -lbar
        # but pkgconf seems to not do that. Sigh. Support both.
        expected_order = [('-L/me/first', '-lfoo1'),
                          ('-L/me/second', '-lfoo2'),
                          ('-L/me/first', '-L/me/second'),
                          ('-lfoo1', '-lfoo2'),
                          ('-L/me/second', '-L/me/third'),
                          ('-L/me/third', '-L/me/fourth',),
                          ('-L/me/third', '-lfoo3'),
                          ('-L/me/fourth', '-lfoo4'),
                          ('-lfoo3', '-lfoo4'),
                          ]
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as ifile:
            for line in ifile:
                if expected_order[0][0] in line:
                    for first, second in expected_order:
                        self.assertLess(line.index(first), line.index(second))
                    return
        raise RuntimeError('Linker entries not found in the Ninja file.')

    def test_introspect_dependencies(self):
        '''
        Tests that mesonintrospect --dependencies returns expected output.
        '''
        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        self.init(testdir)
        glib_found = False
        gobject_found = False
        deps = self.introspect('--dependencies')
        self.assertIsInstance(deps, list)
        for dep in deps:
            self.assertIsInstance(dep, dict)
            self.assertIn('name', dep)
            self.assertIn('compile_args', dep)
            self.assertIn('link_args', dep)
            if dep['name'] == 'glib-2.0':
                glib_found = True
            elif dep['name'] == 'gobject-2.0':
                gobject_found = True
        self.assertTrue(glib_found)
        self.assertTrue(gobject_found)
        if subprocess.call([PKG_CONFIG, '--exists', 'glib-2.0 >= 2.56.2']) != 0:
            raise SkipTest('glib >= 2.56.2 needed for the rest')
        targets = self.introspect('--targets')
        docbook_target = None
        for t in targets:
            if t['name'] == 'generated-gdbus-docbook':
                docbook_target = t
                break
        self.assertIsInstance(docbook_target, dict)
        self.assertEqual(os.path.basename(t['filename'][0]), 'generated-gdbus-doc-' + os.path.basename(t['target_sources'][0]['sources'][0]))

    def test_introspect_installed(self):
        testdir = os.path.join(self.linuxlike_test_dir, '7 library versions')
        self.init(testdir)

        install = self.introspect('--installed')
        install = {os.path.basename(k): v for k, v in install.items()}
        print(install)
        if is_osx():
            the_truth = {
                'libmodule.dylib': '/usr/lib/libmodule.dylib',
                'libnoversion.dylib': '/usr/lib/libnoversion.dylib',
                'libonlysoversion.5.dylib': '/usr/lib/libonlysoversion.5.dylib',
                'libonlysoversion.dylib': '/usr/lib/libonlysoversion.dylib',
                'libonlyversion.1.dylib': '/usr/lib/libonlyversion.1.dylib',
                'libonlyversion.dylib': '/usr/lib/libonlyversion.dylib',
                'libsome.0.dylib': '/usr/lib/libsome.0.dylib',
                'libsome.dylib': '/usr/lib/libsome.dylib',
            }
            the_truth_2 = {'/usr/lib/libsome.dylib',
                           '/usr/lib/libsome.0.dylib',
            }
        else:
            the_truth = {
                'libmodule.so': '/usr/lib/libmodule.so',
                'libnoversion.so': '/usr/lib/libnoversion.so',
                'libonlysoversion.so': '/usr/lib/libonlysoversion.so',
                'libonlysoversion.so.5': '/usr/lib/libonlysoversion.so.5',
                'libonlyversion.so': '/usr/lib/libonlyversion.so',
                'libonlyversion.so.1': '/usr/lib/libonlyversion.so.1',
                'libonlyversion.so.1.4.5': '/usr/lib/libonlyversion.so.1.4.5',
                'libsome.so': '/usr/lib/libsome.so',
                'libsome.so.0': '/usr/lib/libsome.so.0',
                'libsome.so.1.2.3': '/usr/lib/libsome.so.1.2.3',
            }
            the_truth_2 = {'/usr/lib/libsome.so',
                           '/usr/lib/libsome.so.0',
                           '/usr/lib/libsome.so.1.2.3'}
        self.assertDictEqual(install, the_truth)

        targets = self.introspect('--targets')
        for t in targets:
            if t['name'] != 'some':
                continue
            self.assertSetEqual(the_truth_2, set(t['install_filename']))

    def test_build_rpath(self):
        if is_cygwin():
            raise SkipTest('Windows PE/COFF binaries do not use RPATH')
        testdir = os.path.join(self.unit_test_dir, '10 build_rpath')
        self.init(testdir)
        self.build()
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar')
        build_rpath = get_rpath(os.path.join(self.builddir, 'progcxx'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar')
        self.install()
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/prog'))
        self.assertEqual(install_rpath, '/baz')
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/progcxx'))
        self.assertEqual(install_rpath, 'baz')

    @skipIfNoPkgconfig
    def test_build_rpath_pkgconfig(self):
        '''
        Test that current build artefacts (libs) are found first on the rpath,
        manually specified rpath comes second and additional rpath elements (from
        pkg-config files) come last
        '''
        if is_cygwin():
            raise SkipTest('Windows PE/COFF binaries do not use RPATH')
        testdir = os.path.join(self.unit_test_dir, '89 pkgconfig build rpath order')
        self.init(testdir, override_envvars={'PKG_CONFIG_PATH': testdir})
        self.build()
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar:/foo/dummy')
        build_rpath = get_rpath(os.path.join(self.builddir, 'progcxx'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar:/foo/dummy')
        self.install()
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/prog'))
        self.assertEqual(install_rpath, '/baz:/foo/dummy')
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/progcxx'))
        self.assertEqual(install_rpath, 'baz:/foo/dummy')

    @skipIfNoPkgconfig
    def test_global_rpath(self):
        if is_cygwin():
            raise SkipTest('Windows PE/COFF binaries do not use RPATH')
        if is_osx():
            raise SkipTest('Global RPATHs via LDFLAGS not yet supported on MacOS (does anybody need it?)')

        testdir = os.path.join(self.unit_test_dir, '79 global-rpath')
        oldinstalldir = self.installdir

        # Build and install an external library without DESTDIR.
        # The external library generates a .pc file without an rpath.
        yonder_dir = os.path.join(testdir, 'yonder')
        yonder_prefix = os.path.join(oldinstalldir, 'yonder')
        yonder_libdir = os.path.join(yonder_prefix, self.libdir)
        self.prefix = yonder_prefix
        self.installdir = yonder_prefix
        self.init(yonder_dir)
        self.build()
        self.install(use_destdir=False)

        # Since rpath has multiple valid formats we need to
        # test that they are all properly used.
        rpath_formats = [
            ('-Wl,-rpath=', False),
            ('-Wl,-rpath,', False),
            ('-Wl,--just-symbols=', True),
            ('-Wl,--just-symbols,', True),
            ('-Wl,-R', False),
            ('-Wl,-R,', False)
        ]
        for rpath_format, exception in rpath_formats:
            # Build an app that uses that installed library.
            # Supply the rpath to the installed library via LDFLAGS
            # (as systems like buildroot and guix are wont to do)
            # and verify install preserves that rpath.
            self.new_builddir()
            env = {'LDFLAGS': rpath_format + yonder_libdir,
                   'PKG_CONFIG_PATH': os.path.join(yonder_libdir, 'pkgconfig')}
            if exception:
                with self.assertRaises(subprocess.CalledProcessError):
                    self.init(testdir, override_envvars=env)
                continue
            self.init(testdir, override_envvars=env)
            self.build()
            self.install(use_destdir=False)
            got_rpath = get_rpath(os.path.join(yonder_prefix, 'bin/rpathified'))
            self.assertEqual(got_rpath, yonder_libdir, rpath_format)

    @skip_if_not_base_option('b_sanitize')
    def test_pch_with_address_sanitizer(self):
        if is_cygwin():
            raise SkipTest('asan not available on Cygwin')
        if is_openbsd():
            raise SkipTest('-fsanitize=address is not supported on OpenBSD')

        testdir = os.path.join(self.common_test_dir, '13 pch')
        self.init(testdir, extra_args=['-Db_sanitize=address', '-Db_lundef=false'])
        self.build()
        compdb = self.get_compdb()
        for i in compdb:
            self.assertIn("-fsanitize=address", i["command"])

    def test_cross_find_program(self):
        testdir = os.path.join(self.unit_test_dir, '11 cross prog')
        crossfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        print(os.path.join(testdir, 'some_cross_tool.py'))

        tool_path = os.path.join(testdir, 'some_cross_tool.py')

        crossfile.write(textwrap.dedent(f'''\
            [binaries]
            c = '{shutil.which('gcc' if is_sunos() else 'cc')}'
            ar = '{shutil.which('ar')}'
            strip = '{shutil.which('strip')}'
            sometool.py = ['{tool_path}']
            someothertool.py = '{tool_path}'

            [properties]

            [host_machine]
            system = 'linux'
            cpu_family = 'arm'
            cpu = 'armv7' # Not sure if correct.
            endian = 'little'
            '''))
        crossfile.flush()
        self.meson_cross_files = [crossfile.name]
        self.init(testdir)

    def test_reconfigure(self):
        testdir = os.path.join(self.unit_test_dir, '13 reconfigure')
        self.init(testdir, extra_args=['-Db_coverage=true'], default_args=False)
        self.build('reconfigure')

    def test_vala_generated_source_buildir_inside_source_tree(self):
        '''
        Test that valac outputs generated C files in the expected location when
        the builddir is a subdir of the source tree.
        '''
        if not shutil.which('valac'):
            raise SkipTest('valac not installed.')

        testdir = os.path.join(self.vala_test_dir, '8 generated sources')
        newdir = os.path.join(self.builddir, 'srctree')
        shutil.copytree(testdir, newdir)
        testdir = newdir
        # New builddir
        builddir = os.path.join(testdir, 'subdir/_build')
        os.makedirs(builddir, exist_ok=True)
        self.change_builddir(builddir)
        self.init(testdir)
        self.build()

    def test_old_gnome_module_codepaths(self):
        '''
        A lot of code in the GNOME module is conditional on the version of the
        glib tools that are installed, and breakages in the old code can slip
        by once the CI has a newer glib version. So we force the GNOME module
        to pretend that it's running on an ancient glib so the fallback code is
        also tested.
        '''
        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        with mock.patch('mesonbuild.modules.gnome.GnomeModule._get_native_glib_version', mock.Mock(return_value='2.20')):
            env = {'MESON_UNIT_TEST_PRETEND_GLIB_OLD': "1"}
            self.init(testdir,
                      inprocess=True,
                      override_envvars=env)
            self.build(override_envvars=env)

    @skipIfNoPkgconfig
    def test_pkgconfig_usage(self):
        testdir1 = os.path.join(self.unit_test_dir, '27 pkgconfig usage/dependency')
        testdir2 = os.path.join(self.unit_test_dir, '27 pkgconfig usage/dependee')
        if subprocess.call([PKG_CONFIG, '--cflags', 'glib-2.0'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) != 0:
            raise SkipTest('Glib 2.0 dependency not available.')
        with tempfile.TemporaryDirectory() as tempdirname:
            self.init(testdir1, extra_args=['--prefix=' + tempdirname, '--libdir=lib'], default_args=False)
            self.install(use_destdir=False)
            shutil.rmtree(self.builddir)
            os.mkdir(self.builddir)
            pkg_dir = os.path.join(tempdirname, 'lib/pkgconfig')
            self.assertTrue(os.path.exists(os.path.join(pkg_dir, 'libpkgdep.pc')))
            lib_dir = os.path.join(tempdirname, 'lib')
            myenv = os.environ.copy()
            myenv['PKG_CONFIG_PATH'] = pkg_dir
            # Private internal libraries must not leak out.
            pkg_out = subprocess.check_output([PKG_CONFIG, '--static', '--libs', 'libpkgdep'], env=myenv)
            self.assertNotIn(b'libpkgdep-int', pkg_out, 'Internal library leaked out.')
            # Dependencies must not leak to cflags when building only a shared library.
            pkg_out = subprocess.check_output([PKG_CONFIG, '--cflags', 'libpkgdep'], env=myenv)
            self.assertNotIn(b'glib', pkg_out, 'Internal dependency leaked to headers.')
            # Test that the result is usable.
            self.init(testdir2, override_envvars=myenv)
            self.build(override_envvars=myenv)
            myenv = os.environ.copy()
            myenv['LD_LIBRARY_PATH'] = ':'.join([lib_dir, myenv.get('LD_LIBRARY_PATH', '')])
            if is_cygwin():
                bin_dir = os.path.join(tempdirname, 'bin')
                myenv['PATH'] = bin_dir + os.pathsep + myenv['PATH']
            self.assertTrue(os.path.isdir(lib_dir))
            test_exe = os.path.join(self.builddir, 'pkguser')
            self.assertTrue(os.path.isfile(test_exe))
            subprocess.check_call(test_exe, env=myenv)

    @skipIfNoPkgconfig
    def test_pkgconfig_relative_paths(self):
        testdir = os.path.join(self.unit_test_dir, '61 pkgconfig relative paths')
        pkg_dir = os.path.join(testdir, 'pkgconfig')
        self.assertPathExists(os.path.join(pkg_dir, 'librelativepath.pc'))

        env = get_fake_env(testdir, self.builddir, self.prefix)
        env.coredata.set_options({OptionKey('pkg_config_path'): pkg_dir}, subproject='')
        kwargs = {'required': True, 'silent': True}
        relative_path_dep = PkgConfigDependency('librelativepath', env, kwargs)
        self.assertTrue(relative_path_dep.found())

        # Ensure link_args are properly quoted
        libpath = Path(self.builddir) / '../relativepath/lib'
        link_args = ['-L' + libpath.as_posix(), '-lrelativepath']
        self.assertEqual(relative_path_dep.get_link_args(), link_args)

    @skipIfNoPkgconfig
    def test_pkgconfig_duplicate_path_entries(self):
        testdir = os.path.join(self.unit_test_dir, '111 pkgconfig duplicate path entries')
        pkg_dir = os.path.join(testdir, 'pkgconfig')

        env = get_fake_env(testdir, self.builddir, self.prefix)
        env.coredata.set_options({OptionKey('pkg_config_path'): pkg_dir}, subproject='')

        # Regression test: This used to modify the value of `pkg_config_path`
        # option, adding the meson-uninstalled directory to it.
        PkgConfigInterface.setup_env({}, env, MachineChoice.HOST, uninstalled=True)

        pkg_config_path = env.coredata.options[OptionKey('pkg_config_path')].value
        self.assertEqual(pkg_config_path, [pkg_dir])

    @skipIfNoPkgconfig
    def test_pkgconfig_internal_libraries(self):
        '''
        '''
        with tempfile.TemporaryDirectory() as tempdirname:
            # build library
            testdirbase = os.path.join(self.unit_test_dir, '32 pkgconfig use libraries')
            testdirlib = os.path.join(testdirbase, 'lib')
            self.init(testdirlib, extra_args=['--prefix=' + tempdirname,
                                              '--libdir=lib',
                                              '--default-library=static'], default_args=False)
            self.build()
            self.install(use_destdir=False)

            # build user of library
            pkg_dir = os.path.join(tempdirname, 'lib/pkgconfig')
            self.new_builddir()
            self.init(os.path.join(testdirbase, 'app'),
                      override_envvars={'PKG_CONFIG_PATH': pkg_dir})
            self.build()

    @skipIfNoPkgconfig
    def test_static_archive_stripping(self):
        '''
        Check that Meson produces valid static archives with --strip enabled
        '''
        with tempfile.TemporaryDirectory() as tempdirname:
            testdirbase = os.path.join(self.unit_test_dir, '65 static archive stripping')

            # build lib
            self.new_builddir()
            testdirlib = os.path.join(testdirbase, 'lib')
            testlibprefix = os.path.join(tempdirname, 'libprefix')
            self.init(testdirlib, extra_args=['--prefix=' + testlibprefix,
                                              '--libdir=lib',
                                              '--default-library=static',
                                              '--buildtype=debug',
                                              '--strip'], default_args=False)
            self.build()
            self.install(use_destdir=False)

            # build executable (uses lib, fails if static archive has been stripped incorrectly)
            pkg_dir = os.path.join(testlibprefix, 'lib/pkgconfig')
            self.new_builddir()
            self.init(os.path.join(testdirbase, 'app'),
                      override_envvars={'PKG_CONFIG_PATH': pkg_dir})
            self.build()

    @skipIfNoPkgconfig
    def test_pkgconfig_formatting(self):
        testdir = os.path.join(self.unit_test_dir, '38 pkgconfig format')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = _prepend_pkg_config_path(self.privatedir)
        stdo = subprocess.check_output([PKG_CONFIG, '--libs-only-l', 'libsomething'], env=myenv)
        deps = [b'-lgobject-2.0', b'-lgio-2.0', b'-lglib-2.0', b'-lsomething']
        if is_windows() or is_cygwin() or is_osx() or is_openbsd():
            # On Windows, libintl is a separate library
            deps.append(b'-lintl')
        self.assertEqual(set(deps), set(stdo.split()))

    @skipIfNoPkgconfig
    @skip_if_not_language('cs')
    def test_pkgconfig_csharp_library(self):
        testdir = os.path.join(self.unit_test_dir, '49 pkgconfig csharp library')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = _prepend_pkg_config_path(self.privatedir)
        stdo = subprocess.check_output([PKG_CONFIG, '--libs', 'libsomething'], env=myenv)

        self.assertEqual("-r/usr/lib/libsomething.dll", str(stdo.decode('ascii')).strip())

    @skipIfNoPkgconfig
    def test_pkgconfig_link_order(self):
        '''
        Test that libraries are listed before their dependencies.
        '''
        testdir = os.path.join(self.unit_test_dir, '52 pkgconfig static link order')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = _prepend_pkg_config_path(self.privatedir)
        stdo = subprocess.check_output([PKG_CONFIG, '--libs', 'libsomething'], env=myenv)
        deps = stdo.split()
        self.assertLess(deps.index(b'-lsomething'), deps.index(b'-ldependency'))

    def test_deterministic_dep_order(self):
        '''
        Test that the dependencies are always listed in a deterministic order.
        '''
        testdir = os.path.join(self.unit_test_dir, '42 dep order')
        self.init(testdir)
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as bfile:
            for line in bfile:
                if 'build myexe:' in line or 'build myexe.exe:' in line:
                    self.assertIn('liblib1.a liblib2.a', line)
                    return
        raise RuntimeError('Could not find the build rule')

    def test_deterministic_rpath_order(self):
        '''
        Test that the rpaths are always listed in a deterministic order.
        '''
        if is_cygwin():
            raise SkipTest('rpath are not used on Cygwin')
        testdir = os.path.join(self.unit_test_dir, '41 rpath order')
        self.init(testdir)
        if is_osx():
            rpathre = re.compile(r'-rpath,.*/subprojects/sub1.*-rpath,.*/subprojects/sub2')
        else:
            rpathre = re.compile(r'-rpath,\$\$ORIGIN/subprojects/sub1:\$\$ORIGIN/subprojects/sub2')
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as bfile:
            for line in bfile:
                if '-rpath' in line:
                    self.assertRegex(line, rpathre)
                    return
        raise RuntimeError('Could not find the rpath')

    def test_override_with_exe_dep(self):
        '''
        Test that we produce the correct dependencies when a program is overridden with an executable.
        '''
        testdir = os.path.join(self.src_root, 'test cases', 'native', '9 override with exe')
        self.init(testdir)
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as bfile:
            for line in bfile:
                if 'main1.c:' in line or 'main2.c:' in line:
                    self.assertIn('| subprojects/sub/foobar', line)

    @skipIfNoPkgconfig
    def test_usage_external_library(self):
        '''
        Test that uninstalled usage of an external library (from the system or
        PkgConfigDependency) works. On macOS, this workflow works out of the
        box. On Linux, BSDs, Windows, etc, you need to set extra arguments such
        as LD_LIBRARY_PATH, etc, so this test is skipped.

        The system library is found with cc.find_library() and pkg-config deps.
        '''
        oldprefix = self.prefix
        # Install external library so we can find it
        testdir = os.path.join(self.unit_test_dir, '39 external, internal library rpath', 'external library')
        # install into installdir without using DESTDIR
        installdir = self.installdir
        self.prefix = installdir
        self.init(testdir)
        self.prefix = oldprefix
        self.build()
        self.install(use_destdir=False)
        ## New builddir for the consumer
        self.new_builddir()
        env = {'LIBRARY_PATH': os.path.join(installdir, self.libdir),
               'PKG_CONFIG_PATH': _prepend_pkg_config_path(os.path.join(installdir, self.libdir, 'pkgconfig'))}
        testdir = os.path.join(self.unit_test_dir, '39 external, internal library rpath', 'built library')
        # install into installdir without using DESTDIR
        self.prefix = self.installdir
        self.init(testdir, override_envvars=env)
        self.prefix = oldprefix
        self.build(override_envvars=env)
        # test uninstalled
        self.run_tests(override_envvars=env)
        if not (is_osx() or is_linux()):
            return
        # test running after installation
        self.install(use_destdir=False)
        prog = os.path.join(self.installdir, 'bin', 'prog')
        self._run([prog])
        if not is_osx():
            # Rest of the workflow only works on macOS
            return
        out = self._run(['otool', '-L', prog])
        self.assertNotIn('@rpath', out)
        ## New builddir for testing that DESTDIR is not added to install_name
        self.new_builddir()
        # install into installdir with DESTDIR
        self.init(testdir, override_envvars=env)
        self.build(override_envvars=env)
        # test running after installation
        self.install(override_envvars=env)
        prog = self.installdir + os.path.join(self.prefix, 'bin', 'prog')
        lib = self.installdir + os.path.join(self.prefix, 'lib', 'libbar_built.dylib')
        for f in prog, lib:
            out = self._run(['otool', '-L', f])
            # Ensure that the otool output does not contain self.installdir
            self.assertNotRegex(out, self.installdir + '.*dylib ')

    @skipIfNoPkgconfig
    def test_link_arg_fullname(self):
        '''
        Test for  support of -l:libfullname.a
        see: https://github.com/mesonbuild/meson/issues/9000
             https://stackoverflow.com/questions/48532868/gcc-library-option-with-a-colon-llibevent-a
        '''
        testdir = os.path.join(self.unit_test_dir, '98 link full name','libtestprovider')
        oldprefix = self.prefix
        # install into installdir without using DESTDIR
        installdir = self.installdir
        self.prefix = installdir
        self.init(testdir)
        self.prefix=oldprefix
        self.build()
        self.install(use_destdir=False)

        self.new_builddir()
        env = {'LIBRARY_PATH': os.path.join(installdir, self.libdir),
               'PKG_CONFIG_PATH': _prepend_pkg_config_path(os.path.join(installdir, self.libdir, 'pkgconfig'))}
        testdir = os.path.join(self.unit_test_dir, '98 link full name','proguser')
        self.init(testdir,override_envvars=env)

        # test for link with full path
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as bfile:
            for line in bfile:
                if 'build dprovidertest:' in line:
                    self.assertIn('/libtestprovider.a', line)

        if is_osx():
            # macOS's ld do not supports `--whole-archive`, skip build & run
            return

        self.build(override_envvars=env)

        # skip test if pkg-config is too old.
        #   before v0.28, Libs flags like -Wl will not kept in context order with -l flags.
        #   see https://gitlab.freedesktop.org/pkg-config/pkg-config/-/blob/master/NEWS
        pkgconfigver = subprocess.check_output([PKG_CONFIG, '--version'])
        if b'0.28' > pkgconfigver:
            raise SkipTest('pkg-config is too old to be correctly done this.')
        self.run_tests()

    @skipIfNoPkgconfig
    def test_usage_pkgconfig_prefixes(self):
        '''
        Build and install two external libraries, to different prefixes,
        then build and install a client program that finds them via pkgconfig,
        and verify the installed client program runs.
        '''
        oldinstalldir = self.installdir

        # Build and install both external libraries without DESTDIR
        val1dir = os.path.join(self.unit_test_dir, '74 pkgconfig prefixes', 'val1')
        val1prefix = os.path.join(oldinstalldir, 'val1')
        self.prefix = val1prefix
        self.installdir = val1prefix
        self.init(val1dir)
        self.build()
        self.install(use_destdir=False)
        self.new_builddir()

        env1 = {}
        env1['PKG_CONFIG_PATH'] = os.path.join(val1prefix, self.libdir, 'pkgconfig')
        val2dir = os.path.join(self.unit_test_dir, '74 pkgconfig prefixes', 'val2')
        val2prefix = os.path.join(oldinstalldir, 'val2')
        self.prefix = val2prefix
        self.installdir = val2prefix
        self.init(val2dir, override_envvars=env1)
        self.build()
        self.install(use_destdir=False)
        self.new_builddir()

        # Build, install, and run the client program
        env2 = {}
        env2['PKG_CONFIG_PATH'] = os.path.join(val2prefix, self.libdir, 'pkgconfig')
        testdir = os.path.join(self.unit_test_dir, '74 pkgconfig prefixes', 'client')
        testprefix = os.path.join(oldinstalldir, 'client')
        self.prefix = testprefix
        self.installdir = testprefix
        self.init(testdir, override_envvars=env2)
        self.build()
        self.install(use_destdir=False)
        prog = os.path.join(self.installdir, 'bin', 'client')
        env3 = {}
        if is_cygwin():
            env3['PATH'] = os.path.join(val1prefix, 'bin') + \
                os.pathsep + \
                os.path.join(val2prefix, 'bin') + \
                os.pathsep + os.environ['PATH']
        out = self._run([prog], override_envvars=env3).strip()
        # Expected output is val1 + val2 = 3
        self.assertEqual(out, '3')

    def install_subdir_invalid_symlinks(self, testdir, subdir_path):
        '''
        Test that installation of broken symlinks works fine.
        https://github.com/mesonbuild/meson/issues/3914
        '''
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, testdir))
        subdir = os.path.join(testdir, subdir_path)
        with chdir(subdir):
            # Can't distribute broken symlinks in the source tree because it breaks
            # the creation of zipapps. Create it dynamically and run the test by
            # hand.
            src = '../../nonexistent.txt'
            os.symlink(src, 'invalid-symlink.txt')
            self.init(testdir)
            self.build()
            self.install()
            install_path = subdir_path.split(os.path.sep)[-1]
            link = os.path.join(self.installdir, 'usr', 'share', install_path, 'invalid-symlink.txt')
            self.assertTrue(os.path.islink(link), msg=link)
            self.assertEqual(src, os.readlink(link))
            self.assertFalse(os.path.isfile(link), msg=link)

    def test_install_subdir_symlinks(self):
        self.install_subdir_invalid_symlinks('59 install subdir', os.path.join('sub', 'sub1'))

    def test_install_subdir_symlinks_with_default_umask(self):
        self.install_subdir_invalid_symlinks('190 install_mode', 'sub2')

    def test_install_subdir_symlinks_with_default_umask_and_mode(self):
        self.install_subdir_invalid_symlinks('190 install_mode', 'sub1')

    @skipIfNoPkgconfigDep('gmodule-2.0')
    def test_ldflag_dedup(se
"""


```