Response:
The user wants to understand the functionality of the provided Python code, which is a test file for the Frida dynamic instrumentation tool. I need to analyze each test function, explain its purpose, and relate it to reverse engineering, binary analysis, or common programming errors if applicable.

**Plan:**

1. Iterate through each test function in the code.
2. For each test function, identify its core functionality.
3. Determine if the test relates to:
    *   Reverse engineering techniques (e.g., examining compiled binaries, library loading).
    *   Binary internals, Linux/Android kernel or framework concepts (e.g., RPATH, shared libraries, system calls).
    *   Logical reasoning (identify input and expected output).
    *   Common user/programming errors (e.g., incorrect environment variables, missing dependencies).
4. If a test relates to any of the above, provide illustrative examples.
5. Explain how a user might reach this code as part of a debugging process.
6. Finally, summarize the overall functionality of the code.
这是 `frida/subprojects/frida-gum/releng/meson/unittests/linuxliketests.py` 文件的一部分，主要包含了一系列用于测试在类 Linux 系统上构建和安装软件的 Meson 构建系统特性的单元测试。这些测试覆盖了各种与软件构建、链接、依赖管理和安装相关的场景。

**功能归纳:**

这部分代码主要关注以下方面的功能测试：

*   **C++ 标准覆盖 (test_cpp_std_override):**  验证 Meson 是否能正确处理针对不同源文件指定的 C++ 标准（如 C++98, C++11）。
*   **已安装程序的运行 (test_run_installed):** 测试构建的程序在安装后能否正确运行，特别是验证 RPATH 是否被正确设置，以及依赖的共享库能否被找到。
*   **链接参数顺序 (test_order_of_l_arguments):** 检查 Meson 生成的构建文件中，`-L` (库路径) 和 `-l` (库名称) 链接参数的顺序是否符合预期，这对于某些链接器行为很重要。
*   **依赖内省 (test_introspect_dependencies):** 验证 Meson 的内省功能，即能列出项目依赖的库及其编译和链接参数。
*   **已安装文件内省 (test_introspect_installed):** 测试 Meson 能否准确列出已安装的文件及其路径。
*   **构建 RPATH (test_build_rpath, test_build_rpath_pkgconfig, test_global_rpath):**  验证 Meson 是否能正确处理和设置 RPATH (Run-Time Path)，这是一个指定程序运行时查找共享库路径的机制。测试涵盖了手动指定和通过 pkg-config 获取 RPATH 的情况。
*   **使用地址消毒剂的预编译头文件 (test_pch_with_address_sanitizer):**  测试在使用 AddressSanitizer 进行内存错误检测时，预编译头文件 (PCH) 是否能正常工作。
*   **交叉编译时查找程序 (test_cross_find_program):**  测试在交叉编译环境下，Meson 是否能正确查找到目标平台所需的工具。
*   **重新配置 (test_reconfigure):** 验证 Meson 的重新配置功能，即在配置选项变更后，构建系统能否正确更新。
*   **Vala 生成源代码的构建目录 (test_vala_generated_source_buildir_inside_source_tree):**  测试当构建目录位于源代码树内部时，Vala 编译器生成的 C 代码是否放置在正确的位置。
*   **旧版 GNOME 模块代码路径 (test_old_gnome_module_codepaths):**  测试在模拟旧版本 GLib 工具链环境下，Meson 的 GNOME 模块是否能正常工作，确保对旧版本环境的兼容性。
*   **pkg-config 的使用 (test_pkgconfig_usage, test_pkgconfig_relative_paths, test_pkgconfig_duplicate_path_entries, test_pkgconfig_internal_libraries, test_static_archive_stripping, test_pkgconfig_formatting, test_pkgconfig_csharp_library, test_pkgconfig_link_order, test_usage_external_library, test_link_arg_fullname, test_usage_pkgconfig_prefixes):**  这是一系列关于 Meson 如何与 `pkg-config` 工具交互的测试，`pkg-config` 用于获取库的编译和链接信息。测试覆盖了依赖查找、相对路径处理、重复路径处理、内部库、静态库剥离、格式化输出、C# 库的支持、链接顺序以及使用外部库的情况。
*   **确定性的依赖顺序 (test_deterministic_dep_order):**  验证 Meson 生成的构建文件中，依赖项的顺序是否是确定的，这有助于构建的可重现性。
*   **确定性的 RPATH 顺序 (test_deterministic_rpath_order):**  验证 Meson 生成的构建文件中，RPATH 的顺序是否是确定的。
*   **使用可执行依赖覆盖 (test_override_with_exe_dep):** 测试当一个程序被另一个可执行文件覆盖时，Meson 能否生成正确的依赖关系。
*   **安装子目录 (test_install_subdir_symlinks, test_install_subdir_symlinks_with_default_umask, test_install_subdir_symlinks_with_default_umask_and_mode):** 测试安装过程中处理符号链接的情况。
*   **LD 标志去重 (test_ldflag_dedup):** 验证 Meson 在处理重复的 LD 标志时的行为。

**与逆向方法的关联及举例:**

*   **查看已安装程序的运行 (test_run_installed):** 这直接关系到逆向工程中对目标程序运行时的分析。通过检查程序安装后的行为，逆向工程师可以验证其依赖是否正确加载，以及程序的预期功能是否实现。例如，如果逆向分析发现程序缺少某个库的依赖，可以通过观察此测试的失败来佐证。
    *   **例子:**  逆向工程师可能会使用 `ldd` 命令来查看已安装程序依赖的库，并与此测试中验证的 `LD_LIBRARY_PATH` 和 RPATH 设置进行对比，以理解程序是如何找到其依赖的。
*   **构建 RPATH (test_build_rpath 等):** RPATH 是在二进制文件中嵌入的共享库搜索路径，逆向工程师可以通过工具如 `readelf -d` (Linux) 或 `otool -l` (macOS) 来查看。理解 RPATH 的设置方式对于理解程序如何加载动态链接库至关重要。
    *   **例子:** 逆向工程师可能会分析一个被混淆的二进制文件，该文件使用了非标准的 RPATH 设置来加载特定的恶意库。理解 Meson 如何设置 RPATH 可以帮助逆向工程师识别这种潜在的攻击向量。
*   **依赖内省 (test_introspect_dependencies):**  在逆向分析过程中，了解目标程序依赖的库是第一步。此测试验证了 Meson 能否提供这些信息，类似于逆向工程师使用 `ldd` 或其他工具获取依赖列表。
    *   **例子:** 逆向工程师想要分析一个使用 `glib` 库的程序，可以通过 Meson 的内省功能或类似的工具快速获取 `glib` 的编译和链接参数，以便进一步分析程序对 `glib` 的使用。
*   **pkg-config 的使用 (test_pkgconfig_usage 等):**  `pkg-config` 常用于获取库的编译和链接信息，这对于理解程序如何与外部库交互非常重要。逆向工程师可能会手动使用 `pkg-config` 来获取特定库的信息，与此测试中 Meson 的行为进行对比。
    *   **例子:**  逆向工程师在分析一个使用加密库的程序时，可以使用 `pkg-config` 来查看该库的链接标志，例如是否使用了静态链接，或者链接了哪些其他的依赖库。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

*   **RPATH:**  如前所述，RPATH 是 Linux 和其他类 Unix 系统中动态链接器用于查找共享库的关键机制。测试 `test_build_rpath` 等直接涉及到对 RPATH 的理解和操作。
    *   **例子:** 在 Android 中，虽然不完全使用 RPATH，但其共享库加载机制类似，涉及到 `LD_LIBRARY_PATH` 和系统库的搜索路径。理解 Linux 的 RPATH 可以帮助理解 Android 上类似概念。
*   **共享库加载:**  `test_run_installed` 测试验证了程序能否在安装后找到其依赖的共享库，这涉及到操作系统的动态链接器如何工作，例如查找路径的顺序。
    *   **例子:**  Android 的 linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载共享库。理解 Linux 的共享库加载机制有助于理解 Android 的 linker 如何工作。
*   **编译和链接过程:**  所有测试都隐含了对编译和链接过程的理解，例如 `-std=c++` 标志指定 C++ 标准，`-L` 和 `-l` 指定库路径和库名称。
    *   **例子:**  在 Android 开发中，NDK (Native Development Kit) 使用类似的编译和链接工具链，理解这些基础知识有助于理解 Android 本地代码的构建过程。
*   **`pkg-config`:**  `pkg-config` 是一个用于获取库的编译和链接信息的标准工具，广泛应用于 Linux 开发。测试 `test_pkgconfig_usage` 等验证了 Meson 与 `pkg-config` 的集成。
    *   **例子:**  Android 的 AOSP (Android Open Source Project) 构建系统中也可能使用类似的机制来管理依赖库的信息。

**逻辑推理、假设输入与输出:**

*   **`test_cpp_std_override`:**
    *   **假设输入:**  一个包含三个 C++ 源文件的项目，分别要求使用 C++98, C++11 和默认标准。
    *   **预期输出:**  Meson 生成的编译命令中，`prog98.cc` 的命令包含 `-std=c++98` 但不包含 `-std=c++11`，`prog11.cc` 的命令包含 `-std=c++11` 但不包含 `-std=c++98`，`progp.cc` 的命令不包含这两个标志。
*   **`test_run_installed`:**
    *   **假设输入:**  一个简单的 C++ 项目，包含一个可执行文件和一个共享库，共享库需要通过 RPATH 或 `LD_LIBRARY_PATH` 才能被找到。
    *   **预期输出:**  直接运行安装后的可执行文件会失败（因为 RPATH 被正确剥离，且 `LD_LIBRARY_PATH` 未设置），设置 `LD_LIBRARY_PATH` 后运行成功。
*   **`test_order_of_l_arguments`:**
    *   **假设输入:**  一个项目依赖于通过 `pkg-config` 提供的库，`pkg-config` 文件中 `-L` 和 `-l` 参数的顺序特定。
    *   **预期输出:**  Meson 生成的链接命令中，`-L` 和 `-l` 参数的顺序与 `pkg-config` 提供的一致。

**用户或编程常见的使用错误及举例:**

*   **`test_run_installed`:**  这个测试强调了用户在运行已安装程序时可能犯的错误，即忘记设置 `LD_LIBRARY_PATH` 环境变量。
    *   **例子:** 用户安装了一个程序后，直接在终端运行，但因为程序依赖的共享库不在默认路径下，导致程序报错找不到库。这个测试验证了 Meson 能否确保 RPATH 被正确设置，以减少用户需要手动设置 `LD_LIBRARY_PATH` 的情况。
*   **`test_cpp_std_override`:**  开发者可能会错误地为所有源文件指定相同的 C++ 标准，而忽略了某些代码可能需要特定标准才能编译。此测试确保 Meson 能够根据源文件灵活地应用不同的标准。
    *   **例子:**  一个项目混合了旧的和新的 C++ 代码，部分代码需要 C++11 特性，而另一部分为了兼容性仍使用 C++98。如果构建系统不能正确处理，会导致编译错误。
*   **`test_pkgconfig_usage`:** 用户可能会错误地配置 `PKG_CONFIG_PATH` 环境变量，导致构建系统找不到所需的库。此测试验证了 Meson 在正确配置 `PKG_CONFIG_PATH` 时的行为。
    *   **例子:**  用户安装了一个库，但其 `.pc` 文件所在的目录没有添加到 `PKG_CONFIG_PATH` 中，导致后续依赖该库的项目构建失败。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用 Frida 开发基于 Linux 的工具时遇到了构建或安装问题，例如：

1. **构建失败:** 用户在尝试构建 Frida 或其某个组件时，遇到了与依赖库或编译选项相关的错误。他们可能会查看构建日志，发现 Meson 生成的构建命令有问题。
2. **运行时错误:** 用户成功构建并安装了 Frida 组件，但在运行时遇到找不到共享库的错误。他们可能会怀疑 RPATH 设置或 `LD_LIBRARY_PATH` 配置有问题。
3. **依赖问题:** 用户尝试使用依赖于其他库的 Frida 组件，但 Meson 无法正确找到或链接这些依赖。他们可能会检查 `pkg-config` 的配置或 Meson 的依赖查找机制。

为了调试这些问题，Frida 的开发者可能会编写或运行这些单元测试：

*   如果怀疑是 C++ 标准相关的问题，可能会运行 `test_cpp_std_override`。
*   如果怀疑是共享库加载或 RPATH 的问题，可能会运行 `test_run_installed` 或 `test_build_rpath`。
*   如果怀疑是依赖查找或 `pkg-config` 相关的问题，可能会运行 `test_pkgconfig_usage` 等一系列 `pkg-config` 相关的测试。

这些单元测试可以帮助开发者验证 Meson 的行为是否符合预期，从而缩小问题范围并找到解决方案。例如，如果某个测试失败，表明 Meson 在处理特定场景时存在 bug，需要修复。

总而言之，这段代码是 Frida 项目中用于确保 Meson 构建系统在类 Linux 环境下正确工作的关键组成部分，覆盖了软件构建、链接、依赖管理和安装的多个重要方面，并与逆向工程实践和底层系统知识紧密相关。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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