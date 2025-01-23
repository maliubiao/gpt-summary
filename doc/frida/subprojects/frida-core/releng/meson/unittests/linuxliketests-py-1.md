Response:
My thinking process to arrive at the summary of the Python code involved several steps:

1. **Understanding the Context:** The initial prompt states this is a part of the `fridaDynamic` instrumentation tool's source code, specifically a test file within the `meson` build system for Linux-like environments. This immediately tells me the code's primary function is *testing*.

2. **Scanning for Key Words and Patterns:** I looked for recurring keywords, function names, and patterns that indicate the kind of testing being performed. Words like `test_`, `assert`, `SkipTest`, `subprocess`, `os.path`, `introspect`, `install`, `build`, and `pkgconfig` stood out. These suggest testing build processes, installation procedures, interactions with the operating system, and the use of `pkg-config`.

3. **Analyzing Individual Test Functions:** I went through each `test_` function, trying to understand its specific purpose:
    * **`test_cpp_std_override`:**  The presence of `'-std=c++98'`, `'-std=c++11'`, and `'-Werror'` in compiler commands clearly points to testing how C++ standard flags are handled during compilation.
    * **`test_run_installed`:** Checking `LD_LIBRARY_PATH`, `RPATH`, and the execution of an installed program strongly indicates testing the correctness of installation and runtime linking.
    * **`test_order_of_l_arguments`:** The mention of `.pc` files and checking the order of `-L` and `-l` flags suggests testing the ordering of linker arguments when using `pkg-config`.
    * **`test_introspect_dependencies`:** The use of `introspect('--dependencies')` and checking for specific dependency names like `glib-2.0` and `gobject-2.0` reveals testing the introspection of project dependencies.
    * **`test_introspect_installed`:**  The name and the assertions about file paths like `/usr/lib/libmodule.so` clearly indicate testing the introspection of installed files and their locations.
    * **`test_build_rpath` and `test_build_rpath_pkgconfig`:** The presence of `get_rpath` and checks for `$ORIGIN`, `/baz`, and paths involving `pkgconfig` points to testing the generation and correctness of RPATHs (runtime search paths for shared libraries) during the build process.
    * **`test_global_rpath`:**  The focus on `LDFLAGS`, external libraries, and `yonder_libdir` indicates testing how globally defined RPATHs via environment variables are handled.
    * **`test_pch_with_address_sanitizer`:**  The keywords "pch" (precompiled headers) and "address_sanitizer" suggest testing the compatibility of precompiled headers with memory error detection tools.
    * **`test_cross_find_program`:** The creation of a cross-compilation file and mentions of "arm" suggest testing the ability to find programs in cross-compilation scenarios.
    * **`test_reconfigure`:** The call to `build('reconfigure')` suggests testing the reconfiguration functionality of the build system.
    * **`test_vala_generated_source_buildir_inside_source_tree`:**  The mention of "valac" and checking file paths indicates testing how the build system handles generated sources from the Vala language when the build directory is within the source tree.
    * **`test_old_gnome_module_codepaths`:**  The mocking of `_get_native_glib_version` points to testing fallback code paths for older versions of libraries.
    * **Many tests related to `pkgconfig`:**  These tests cover various aspects of `pkg-config` usage, including finding dependencies, handling relative paths, managing duplicate entries, dealing with internal libraries, formatting output, and handling C# libraries.
    * **Tests related to linking order and deterministic builds:** These check that dependencies and RPATHs are listed in a consistent order.
    * **`test_override_with_exe_dep`:** This focuses on testing how dependencies are handled when a program is replaced with an executable.
    * **`test_usage_external_library` and `test_link_arg_fullname`:**  These test the correct usage of external libraries and specific linker argument formats.
    * **`test_usage_pkgconfig_prefixes`:** This tests finding external libraries via `pkg-config` when they are installed in different prefixes.
    * **`test_install_subdir_invalid_symlinks` and related:** These test the installation of symbolic links, even broken ones.

4. **Grouping and Categorization:**  Based on the analysis of individual tests, I grouped them into logical categories to summarize the functionality:
    * **Build System Functionality:** Tests related to compiler flags, RPATHs, build directories, reconfiguration, and cross-compilation.
    * **Installation Procedures:** Tests specifically focusing on the installation process, including checking installed files and RPATHs in installed binaries.
    * **Dependency Management:** Tests involving `pkg-config` and introspection of dependencies.
    * **Specific Language/Tool Integration:** Tests for Vala and C#.
    * **Edge Cases and Error Handling:** Tests for invalid symlinks and simulating older library versions.
    * **Determinism:** Tests ensuring consistent ordering of dependencies and RPATHs.

5. **Synthesizing the Summary:** I combined the grouped categories into concise bullet points, using clear and informative language. I focused on the "what" and "why" of the tests, explaining the purpose of each category of tests in relation to the overall functionality of a build system. I also explicitly noted the file's role in testing the *correctness* of the build system for Linux-like environments within the Frida project.

By following this systematic approach, I was able to dissect the provided code snippet and generate a comprehensive summary of its functionalities. The key was to recognize patterns, understand the purpose of individual tests, and then group them logically to create a high-level overview.
这是提供的 Frida 动态 instrumentation 工具源代码文件 `frida/subprojects/frida-core/releng/meson/unittests/linuxliketests.py` 的第 2 部分。基于这部分代码，我们可以归纳出以下功能：

**主要功能：测试 Frida 在 Linux 类似环境下的构建和安装过程中的各种场景，以及与外部库的交互。**

更具体地说，这部分代码主要测试了以下方面：

* **C++ 标准库版本控制：**
    * 测试了在构建过程中，如何针对不同的源文件覆盖默认的 C++ 标准版本 (例如，使用 `-std=c++98` 或 `-std=c++11`)。
    * 验证了 `-Werror` 编译选项的正确应用。

* **已安装程序的运行：**
    * 测试了已安装的可执行程序是否能正确运行，尤其是在没有设置 `LD_LIBRARY_PATH` 的情况下，验证 RPATH 是否被正确剥离，并且没有指向构建目录。
    * 验证了设置 `LD_LIBRARY_PATH` 后，程序可以正常找到依赖的共享库。
    * 验证了 `meson introspect --installed` 命令可以正确列出已安装的文件。

* **链接参数的顺序：**
    * 测试了使用 `pkg-config` 获取链接参数时，`-L` 和 `-l` 参数的顺序是否符合预期。

* **依赖关系内省：**
    * 测试了 `meson introspect --dependencies` 命令是否能正确返回项目的依赖信息，包括依赖项的名称、编译参数和链接参数。

* **已安装文件内省：**
    * 测试了 `meson introspect --installed` 命令是否能正确列出已安装的文件及其路径，包括不同版本的共享库命名规范。

* **构建时的 RPATH：**
    * 测试了在构建过程中，生成的二进制文件的 RPATH 是否符合预期，包括 `$ORIGIN` 的使用以及自定义路径的设置。

* **构建时 RPATH 与 pkg-config 的结合：**
    * 测试了当同时使用自定义 RPATH 和通过 `pkg-config` 获取的 RPATH 时，最终生成的 RPATH 的顺序是否正确，优先查找构建目录下的库。

* **全局 RPATH：**
    * 测试了通过 `LDFLAGS` 环境变量设置全局 RPATH 的情况，并验证安装后 RPATH 是否被正确保留。

* **Address Sanitizer 与预编译头：**
    * 测试了在使用 Address Sanitizer 进行代码检查时，预编译头是否能正常工作。

* **交叉编译查找程序：**
    * 测试了在交叉编译环境下，能否正确找到指定的工具程序。

* **重新配置：**
    * 测试了构建系统的重新配置功能 (例如，切换编译选项)。

* **Vala 生成源代码的构建目录：**
    * 测试了当构建目录是源代码目录的子目录时，Vala 编译器生成的 C 代码是否位于正确的位置。

* **旧版本 GNOME 模块代码路径：**
    * 通过模拟旧版本的 GLib，测试了 GNOME 模块中的兼容性代码路径。

* **pkg-config 的使用：**
    * 测试了在构建和安装过程中 `pkg-config` 的各种使用场景，包括依赖查找、私有库的隔离、头文件的包含路径等。
    * 测试了使用 `pkg-config` 构建和链接依赖库的应用。

* **pkg-config 相对路径：**
    * 测试了 `pkg-config` 文件中使用相对路径的情况。

* **pkg-config 重复路径条目：**
    * 测试了 `pkg-config` 路径中存在重复条目的处理。

* **pkg-config 内部库：**
    * 测试了使用 `pkg-config` 来链接内部库的情况。

* **静态库剥离：**
    * 测试了在启用剥离选项 (`--strip`) 的情况下，Meson 能否生成有效的静态库。

* **pkg-config 格式化：**
    * 测试了 `pkg-config` 输出的链接库的格式是否正确。

* **pkg-config C# 库：**
    * 测试了 `pkg-config` 如何处理 C# 库。

* **pkg-config 链接顺序：**
    * 测试了 `pkg-config` 输出的链接库的顺序，确保库在其依赖项之前列出。

* **依赖项的确定性顺序：**
    * 测试了构建过程中依赖项的顺序是否是确定的。

* **RPATH 的确定性顺序：**
    * 测试了构建过程中 RPATH 的顺序是否是确定的。

* **使用可执行依赖覆盖：**
    * 测试了当使用可执行文件覆盖某个依赖项时，构建系统是否能正确处理依赖关系。

* **使用外部库：**
    * 测试了如何使用系统库或通过 `PkgConfigDependency` 找到的外部库。

* **链接参数全名：**
    * 测试了支持 `-l:libfullname.a` 这种格式的链接参数。

* **使用 pkg-config 前缀：**
    * 测试了如何使用安装在不同前缀下的多个外部库。

* **安装子目录中的无效符号链接：**
    * 测试了安装包含无效符号链接的子目录是否能正常工作。

**与逆向方法的关联：**

虽然这段代码主要是测试构建和安装过程，但其测试内容与逆向分析息息相关：

* **运行时链接和 RPATH：** 逆向分析时，理解目标程序如何加载共享库至关重要。RPATH 的正确设置直接影响程序的运行，逆向工程师需要了解 RPATH 的工作原理，才能正确分析程序的依赖关系和加载行为。例如，`test_run_installed` 和 `test_build_rpath` 测试确保了 Frida 构建的程序能够正确找到其依赖的库，这对于 Frida 动态注入目标进程至关重要。如果 RPATH 设置不正确，Frida 自身可能无法加载所需的库，或者注入的目标进程可能无法正常运行。
* **依赖关系：** 逆向分析的第一步通常是分析目标程序的依赖关系。`test_introspect_dependencies` 和 `test_pkgconfig_usage` 等测试确保了 Frida 的构建系统能够正确识别和处理依赖，这对于 Frida 自身的功能实现是基础。
* **符号（Symbols）：** 静态库剥离的测试 (`test_static_archive_stripping`) 关系到逆向分析中符号信息的可获得性。虽然剥离符号可以减小库的大小，但会给静态分析带来困难。Frida 的构建系统需要根据配置正确处理符号信息。

**二进制底层、Linux/Android 内核及框架的知识：**

* **RPATH 和 LD_LIBRARY_PATH：** 这些是 Linux 系统中用于指定共享库搜索路径的关键环境变量和机制。理解它们的工作原理对于动态链接和程序加载至关重要。相关测试 (如 `test_run_installed` 和 `test_build_rpath`) 直接涉及到这些概念。
* **共享库命名规范：** 测试中涉及到不同版本的共享库命名 (例如，`libsome.so.1.2.3`)，这反映了 Linux 系统中共享库版本管理的标准。
* **pkg-config：** 这是一个用于获取库的编译和链接参数的标准工具，广泛应用于 Linux 开发。理解 `pkg-config` 的工作方式对于构建依赖外部库的程序至关重要。大量的 `pkgconfig` 相关测试体现了这一点。
* **Address Sanitizer：** 这是一种用于检测内存错误的工具，通常在开发和测试阶段使用。`test_pch_with_address_sanitizer` 测试了其与构建系统的集成。
* **符号链接 (Symlinks)：**  测试安装无效符号链接的功能 (`test_install_subdir_invalid_symlinks`) 涉及到 Linux 文件系统的基本概念。

**逻辑推理、假设输入与输出：**

大多数测试都包含逻辑推理和假设的输入输出：

* **`test_cpp_std_override`：**
    * **假设输入：** 包含 `prog98.c`, `prog11.c`, `prog.c` 的源代码目录，Meson 构建文件配置了不同的 C++ 标准。
    * **预期输出：** 编译命令中 `prog98.c` 包含 `-std=c++98`，`prog11.c` 包含 `-std=c++11`，`prog.c` 不包含 `-std=c++XX`，并且 `prog.c` 包含 `-Werror`。

* **`test_run_installed`：**
    * **假设输入：** 一个依赖于共享库的可执行程序，安装目录。
    * **预期输出：** 直接运行安装后的程序失败，设置 `LD_LIBRARY_PATH` 后运行成功。`meson introspect --installed` 输出包含已安装的文件。

* **`test_order_of_l_arguments`：**
    * **假设输入：**  一个使用 `pkg-config` 获取链接参数的项目，`pkg-config` 文件中定义了特定的 `-L` 和 `-l` 顺序。
    * **预期输出：** `build.ninja` 文件中链接命令的 `-L` 和 `-l` 参数顺序与预期一致。

**用户或编程常见的使用错误：**

* **`test_run_installed`：**  演示了用户在没有正确设置 `LD_LIBRARY_PATH` 的情况下运行依赖共享库的程序时会遇到的错误。
* **`test_global_rpath`：**  暗示了用户可能通过 `LDFLAGS` 错误地设置了全局 RPATH，导致构建失败或运行时错误。
* **`pkgconfig` 相关的测试：**  涵盖了用户在使用 `pkg-config` 时可能遇到的各种问题，例如路径配置错误、依赖项缺失等。

**用户操作如何一步步到达这里，作为调试线索：**

1. **开发者尝试为 Frida Core 添加或修改与 Linux 平台构建相关的特性。**
2. **为了确保新特性或修改不会引入回归，开发者需要编写相应的单元测试。**
3. **开发者查看现有的测试文件 `linuxliketests.py`，并决定添加新的测试用例或修改现有的测试用例。**
4. **开发者可能需要理解 Meson 构建系统的原理，特别是关于 C++ 标准版本控制、RPATH、依赖管理和 `pkg-config` 的使用。**
5. **开发者可能会遇到与链接库、依赖关系或构建选项相关的问题，需要通过调试和分析构建日志来定位问题。**
6. **在调试过程中，开发者可能会运行单独的测试用例，例如 `pytest frida/subprojects/frida-core/releng/meson/unittests/linuxliketests.py::TestLinuxLike::test_run_installed` 来验证特定的功能。**
7. **如果测试失败，开发者会仔细检查测试代码、构建配置和相关的系统环境，例如 `LD_LIBRARY_PATH`、`PKG_CONFIG_PATH` 等环境变量。**
8. **开发者可能会使用 `meson introspect` 命令来检查构建系统的状态，例如已安装的文件、依赖关系等，以便更好地理解问题。**

**归纳功能 (基于第 2 部分)：**

这部分 `linuxliketests.py` 文件主要负责测试 Frida Core 在 Linux 类似环境下使用 Meson 构建系统时的 **编译选项处理、安装过程正确性、依赖管理（特别是与 `pkg-config` 的集成）、运行时链接行为（RPATH）以及与外部库的交互**。它通过各种测试用例覆盖了构建和安装过程中的关键环节，确保 Frida Core 能够在 Linux 平台上正确构建、安装和运行。这些测试对于保证 Frida 功能的稳定性和可靠性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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