Response:
The user wants a summary of the functionality of the provided Python code, which is a test suite for the Frida dynamic instrumentation tool, specifically focusing on how it relates to reverse engineering, binary analysis, and potential user errors.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The code is in `frida/subprojects/frida-python/releng/meson/unittests/linuxliketests.py`. The keywords "unittests" and "frida" are key. This is a testing suite for Frida's Python bindings, specifically for Linux-like systems. The tests are likely verifying the correct interaction between Frida and the underlying system.

2. **Analyze Individual Test Functions:** Go through each `test_` function and understand its goal. Look for keywords and patterns that reveal the functionality being tested.

    * `test_cpp_std_override`: Checks how Meson handles different C++ standard versions during compilation. This is about build system correctness.
    * `test_run_installed`: Focuses on whether installed binaries can run correctly, considering library paths (`LD_LIBRARY_PATH`, `RPATH`). This is crucial for deployment and execution.
    * `test_order_of_l_arguments`: Verifies the order of linker arguments (`-L`, `-l`), which can be important for resolving dependencies.
    * `test_introspect_dependencies`:  Tests the introspection feature of Meson to get information about project dependencies.
    * `test_introspect_installed`: Checks if the introspection of installed files (libraries, executables) is correct, especially versioning.
    * `test_build_rpath`, `test_build_rpath_pkgconfig`, `test_global_rpath`: All deal with `RPATH`, a Linux mechanism for specifying library search paths at runtime. This is very relevant to binary analysis and reverse engineering.
    * `test_pch_with_address_sanitizer`: Tests the interaction between precompiled headers (PCH) and AddressSanitizer, a memory error detection tool. This is about build correctness and debugging.
    * `test_cross_find_program`: Checks cross-compilation scenarios, where tools for a different target architecture are used.
    * `test_reconfigure`: Tests the ability to reconfigure the build system with different options.
    * `test_vala_generated_source_buildir_inside_source_tree`: Tests a specific scenario with the Vala language and build directories.
    * `test_old_gnome_module_codepaths`:  Ensures compatibility with older versions of GNOME libraries.
    * `test_pkgconfig_usage`, `test_pkgconfig_relative_paths`, `test_pkgconfig_duplicate_path_entries`, `test_pkgconfig_internal_libraries`, `test_static_archive_stripping`, `test_pkgconfig_formatting`, `test_pkgconfig_csharp_library`, `test_pkgconfig_link_order`, `test_usage_external_library`, `test_link_arg_fullname`, `test_usage_pkgconfig_prefixes`: These tests heavily focus on `pkg-config`, a standard way for libraries to provide compilation and linking flags. This is important for dependency management.
    * `test_deterministic_dep_order`, `test_deterministic_rpath_order`: Check if the order of dependencies and RPATH entries is consistent, crucial for reproducible builds.
    * `test_override_with_exe_dep`: Tests how Meson handles overriding dependencies with executables.
    * `test_install_subdir_symlinks`, `test_install_subdir_symlinks_with_default_umask`, `test_install_subdir_symlinks_with_default_umask_and_mode`: These tests cover the installation of symbolic links in subdirectories.
    * `test_ldflag_dedup`: Checks for the deduplication of linker flags.

3. **Group Functionalities:**  Based on the analysis of individual tests, group them into broader categories of functionality:

    * **Build System Verification:**  Tests related to correct compilation, linking, and installation processes (e.g., C++ standard, RPATH, linker order, PCH, cross-compilation).
    * **Dependency Management:** Tests involving `pkg-config` and how dependencies are resolved and linked.
    * **Installation Verification:** Tests related to the correct installation of files and the behavior of installed binaries.
    * **Introspection Capabilities:** Tests verifying Meson's ability to inspect build information (dependencies, targets, installed files).
    * **Specific Language/Tooling Integration:** Tests for Vala and interactions with GNOME libraries.
    * **Reproducibility:** Tests focusing on deterministic output order (dependencies, RPATH).

4. **Identify Connections to Reverse Engineering/Binary Analysis:** Look for tests that directly relate to binary structure, execution, and analysis techniques. `RPATH` manipulation, checking installed library paths, and ensuring correct linking are all relevant.

5. **Highlight Linux/Android Kernel/Framework Knowledge:** Tests involving `LD_LIBRARY_PATH`, `RPATH`, and how shared libraries are loaded directly relate to Linux system knowledge.

6. **Infer Logic and Assumptions:** In some tests, the expected behavior can be inferred. For example, in `test_cpp_std_override`, the assumption is that specific compiler flags will be present or absent based on the source file names.

7. **Consider User/Programming Errors:** Think about common mistakes developers make related to library paths, dependency management, and build system configuration. The tests implicitly cover these by ensuring correct behavior under various conditions.

8. **Trace User Operations (Debugging Clues):**  The test file itself is a debugging tool. Developers would run these tests to verify the build system's correctness. If a test fails, it points to a problem in the build configuration or Meson's handling of certain scenarios. The file path itself provides context about where these tests are located within the Frida project.

9. **Synthesize the Summary:** Combine the identified functionalities and connections into a concise summary, addressing the user's specific points about reverse engineering, binary analysis, and potential errors.

10. **Address Part 2:**  Specifically answer the request to summarize the functionality of *this specific part* of the code, focusing on the tests within the provided snippet. This will be a subset of the overall functionality.
这是Frida动态Instrumentation工具源代码文件 `frida/subprojects/frida-python/releng/meson/unittests/linuxliketests.py` 的第2部分，该文件包含了一系列针对 Linux-like 系统的单元测试，用于验证 Frida Python 绑定的构建和安装过程中的各种功能。

**第2部分功能归纳:**

这一部分主要测试了以下功能：

1. **C++ 标准覆盖 (test_cpp_std_override):** 验证了 Meson 构建系统能够正确处理和覆盖 C++ 标准标志（例如 `-std=c++98`, `-std=c++11`），并能正确应用警告作为错误 ( `-Werror`) 的设置。

2. **运行已安装的程序 (test_run_installed):** 测试了已安装的可执行文件是否能够正确运行，并验证了 RPATH (运行时库搜索路径) 是否被正确处理，以及 `LD_LIBRARY_PATH` 的影响。还验证了 `meson introspect --installed` 命令能够正确列出已安装的文件。

3. **`-L` 和 `-l` 参数顺序 (test_order_of_l_arguments):** 检查了链接器参数 `-L` (库搜索路径) 和 `-l` (链接库) 的顺序是否符合预期，这对于库的正确链接至关重要。

4. **内省依赖 (test_introspect_dependencies):** 测试了 Meson 的内省功能，验证了 `meson introspect --dependencies` 命令能够正确返回项目的依赖信息，包括编译和链接参数。

5. **内省已安装的文件 (test_introspect_installed):**  验证了 `meson introspect --installed` 命令能够正确列出已安装的文件及其路径，并能处理不同平台的库版本命名约定（例如 `.so`, `.dylib`）。

6. **构建 RPATH (test_build_rpath):**  测试了在构建过程中和安装后，RPATH 是否被正确设置，包括使用 `$ORIGIN` 以及绝对路径。

7. **基于 pkg-config 的构建 RPATH (test_build_rpath_pkgconfig):** 验证了当使用 pkg-config 提供库信息时，构建系统是否能够正确设置 RPATH，并确保构建目录的库优先于其他路径。

8. **全局 RPATH (test_global_rpath):** 测试了通过 `LDFLAGS` 环境变量设置全局 RPATH 的功能，并验证了安装过程能够保留这些 RPATH 设置。

9. **使用 AddressSanitizer 的 PCH (test_pch_with_address_sanitizer):**  验证了当启用 AddressSanitizer (一个内存错误检测工具) 时，预编译头文件 (PCH) 的构建是否能正常工作。

10. **交叉编译时查找程序 (test_cross_find_program):**  测试了在交叉编译场景下，Meson 是否能够根据交叉编译配置文件正确找到所需的工具程序。

11. **重新配置 (test_reconfigure):** 验证了 Meson 的重新配置功能，例如在初始配置后更改构建选项 (例如启用代码覆盖率)。

12. **Vala 生成源码的构建目录 (test_vala_generated_source_buildir_inside_source_tree):**  测试了当构建目录位于源代码树内部时，Vala 编译器生成的 C 代码是否被放置在正确的位置。

13. **旧的 GNOME 模块代码路径 (test_old_gnome_module_codepaths):**  通过模拟旧版本的 GNOME 库，测试了 Meson 的 GNOME 模块在旧版本环境下的兼容性和回退代码路径。

14. **pkg-config 的使用 (test_pkgconfig_usage):**  测试了使用 pkg-config 来查找和链接依赖项的场景，包括私有库的处理和依赖项的可见性控制。

15. **pkg-config 相对路径 (test_pkgconfig_relative_paths):**  验证了 pkg-config 文件中使用相对路径时的处理。

16. **pkg-config 重复路径条目 (test_pkgconfig_duplicate_path_entries):**  测试了处理重复 pkg-config 路径条目的情况。

17. **pkg-config 内部库 (test_pkgconfig_internal_libraries):**  测试了如何使用 pkg-config 链接内部库。

18. **静态库剥离 (test_static_archive_stripping):**  验证了在启用剥离 (strip) 功能时，Meson 是否能够生成有效的静态库。

19. **pkg-config 格式化 (test_pkgconfig_formatting):**  测试了 pkg-config 输出的格式是否符合预期。

20. **pkg-config C# 库 (test_pkgconfig_csharp_library):**  测试了 pkg-config 对 C# 库的支持。

21. **pkg-config 链接顺序 (test_pkgconfig_link_order):**  验证了 pkg-config 输出的链接库顺序，确保依赖项在被依赖的库之后。

22. **确定性的依赖顺序 (test_deterministic_dep_order):**  测试了依赖项的链接顺序是否总是确定的，以保证构建的可重复性。

23. **确定性的 RPATH 顺序 (test_deterministic_rpath_order):**  测试了 RPATH 的添加顺序是否总是确定的。

24. **使用可执行依赖覆盖 (test_override_with_exe_dep):**  测试了当一个程序被另一个可执行文件覆盖时的依赖关系处理。

25. **使用外部库 (test_usage_external_library):**  测试了如何使用系统中的外部库或者通过 PkgConfigDependency 找到的库。

26. **链接参数全名 (test_link_arg_fullname):**  测试了对链接参数全名格式 (例如 `-l:libfullname.a`) 的支持。

27. **使用 pkg-config 前缀 (test_usage_pkgconfig_prefixes):**  测试了当使用不同前缀安装的多个库时，pkg-config 的查找机制。

28. **安装子目录无效符号链接 (install_subdir_invalid_symlinks, test_install_subdir_symlinks, test_install_subdir_symlinks_with_default_umask, test_install_subdir_symlinks_with_default_umask_and_mode):** 测试了安装子目录中的符号链接，包括无效链接的情况。

29. **ldflag 去重 (test_ldflag_dedup):**  （代码片段未完整，推测是测试链接器标志的去重功能）

**与逆向方法的关系：**

* **RPATH 测试 (test_run_installed, test_build_rpath, test_build_rpath_pkgconfig, test_global_rpath, test_deterministic_rpath_order):**  RPATH 是 Linux 系统中指定程序运行时查找共享库路径的一种机制。理解和分析 RPATH 对于逆向工程至关重要，因为它可以揭示程序依赖的库的位置，从而有助于分析程序的行为和依赖关系。例如，逆向工程师可能会使用 `objdump -x` 或 `readelf -d` 等工具来查看二进制文件的 RPATH 信息。这些测试确保了 Frida 构建系统能够正确处理和设置 RPATH，这对于 Frida 注入目标进程并加载自身库至关重要。

* **库依赖测试 (test_order_of_l_arguments, test_introspect_dependencies, test_pkgconfig_usage, test_pkgconfig_link_order, test_usage_external_library, test_link_arg_fullname):**  逆向工程中需要分析目标程序的依赖关系，了解其使用了哪些库。这些测试验证了 Frida 构建系统正确处理库依赖，这关系到 Frida 自身能否正确链接和加载所需的库。`pkg-config` 是一个常用的工具，用于获取库的编译和链接信息，这些测试也覆盖了 Frida 对 `pkg-config` 的使用。

* **已安装文件内省 (test_introspect_installed):**  逆向工程师可能需要知道 Frida 的哪些组件被安装到系统中，以及它们的具体位置。`meson introspect --installed` 提供了这样的信息。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **RPATH 和 LD_LIBRARY_PATH:** 这些是 Linux 系统中用于查找共享库的关键环境变量和机制。测试涉及到它们的正确处理，体现了对 Linux 加载器工作原理的理解。在 Android 中，也有类似的机制，虽然细节有所不同。
* **共享库链接和加载：** 测试中关于 `-L` 和 `-l` 参数的顺序、`pkg-config` 的使用等，都涉及到共享库的链接和加载过程，这是操作系统和编译器底层知识。
* **AddressSanitizer:**  `test_pch_with_address_sanitizer` 涉及到 AddressSanitizer，这是一个基于编译器的工具，用于检测内存错误，这与操作系统的内存管理密切相关。
* **交叉编译：** `test_cross_find_program` 涉及到交叉编译，这需要对不同体系结构的二进制格式和工具链有深入的了解。

**逻辑推理和假设输入输出：**

* **`test_cpp_std_override`:**
    * **假设输入:** 源代码目录下包含名为 `prog98.cc`, `prog11.cc`, `progp.cc` 的 C++ 文件，以及相应的 `meson.build` 文件，其中可能指定了不同的 C++ 标准。
    * **预期输出:**  `compdb` (编译数据库) 中对应源文件的编译命令会包含正确的 `-std=c++XX` 标志，并且 `-Werror` 的应用符合预期。

* **`test_run_installed`:**
    * **假设输入:**  `meson.build` 文件定义了一个可执行文件 `prog` 和一个共享库 `libfoo.so`，库安装到 `usr/foo` 目录下。
    * **预期输出:**
        * 直接运行安装后的 `prog` 会失败（因为 RPATH 被正确剥离，且 `LD_LIBRARY_PATH` 未设置）。
        * 设置 `LD_LIBRARY_PATH` 后，运行 `prog` 会成功。
        * `meson introspect --installed` 会包含 `prog` 和 `libfoo.so` 的安装路径。

* **`test_order_of_l_arguments`:**
    * **假设输入:** `meson.build` 文件以及 `pkg-config` 文件 (`.pc`) 定义了特定的库搜索路径和链接库，且 `.pc` 文件中的顺序与预期不同。
    * **预期输出:** 生成的 `build.ninja` 文件中，链接命令中 `-L` 和 `-l` 参数的顺序符合预期（即使 `pkg-config` 可能会重新排序）。

**用户或编程常见的使用错误：**

* **`test_run_installed`:**  展示了用户在安装后直接运行程序，但由于未设置 `LD_LIBRARY_PATH` 或 RPATH 不正确导致程序无法找到依赖库的常见错误。
* **不正确的依赖顺序：** `test_order_of_l_arguments` 强调了链接器参数顺序的重要性，用户在手动编写链接命令或配置构建系统时可能会犯这个错误。
* **全局 RPATH 的误用：** `test_global_rpath` 演示了通过 `LDFLAGS` 设置全局 RPATH 的方法，用户可能会错误地设置这些环境变量，导致不期望的链接行为。

**用户操作到达此处的调试线索：**

1. **开发者克隆了 Frida 的源代码仓库。**
2. **开发者修改了 Frida Python 绑定的相关代码。**
3. **为了验证修改的正确性，开发者需要运行单元测试。**
4. **开发者进入 `frida/subprojects/frida-python/releng/meson/unittests/` 目录。**
5. **开发者使用 Meson 构建系统配置了构建环境。**
6. **开发者运行了特定的测试命令，例如 `meson test` 或单独运行 `linuxliketests.py` 中的测试函数。**
7. **如果测试失败，开发者可能会查看测试源代码 (`linuxliketests.py`) 以了解测试的预期行为和失败原因，从而进行调试。**
8. **该文件路径 `frida/subprojects/frida-python/releng/meson/unittests/linuxliketests.py` 本身就提供了调试的上下文：这是 Frida 项目中 Python 绑定在 Linux-like 系统上的单元测试。**

总而言之，这部分代码通过各种单元测试，细致地验证了 Frida Python 绑定在 Linux-like 系统上的构建和安装过程，特别关注了与共享库处理、依赖管理、RPATH 设置以及与 `pkg-config` 等工具的集成。这些测试对于确保 Frida 的稳定性和正确性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
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
```