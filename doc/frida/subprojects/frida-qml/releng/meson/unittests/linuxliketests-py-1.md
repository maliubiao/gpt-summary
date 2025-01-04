Response:
My thought process for analyzing the Python code and generating the summary went through these steps:

1. **Understanding the Goal:** The request is to analyze a Python file related to the Frida dynamic instrumentation tool. Specifically, I need to understand its functionality, how it relates to reverse engineering, low-level operations, and common user errors, and ultimately summarize its purpose.

2. **Initial Code Scan:** I quickly read through the code, paying attention to function names (like `test_cpp_std_override`, `test_run_installed`, `test_introspect_dependencies`, etc.) and the types of operations performed (e.g., file path manipulation, subprocess calls, assertions). This gives me a high-level understanding that the code is a suite of unit tests.

3. **Identifying Key Themes:** As I scan, recurring themes emerge:
    * **Compiler and Linker Flags:**  Tests like `test_cpp_std_override` and mentions of `-std=c++`, `-Werror`, `-L`, `-l`, and RPATH suggest testing how Meson handles compiler and linker options.
    * **Installation:**  Functions like `test_run_installed` and references to `installdir` indicate tests related to the installation process and verifying installed files.
    * **Introspection:** Tests using `self.introspect` hint at examining the build system's internal representation of targets, dependencies, and installed files.
    * **Dependencies (especially pkg-config):** The frequent use of `@skipIfNoPkgconfig` and tests involving `PKG_CONFIG_PATH` point to a focus on testing how Meson interacts with external libraries through pkg-config.
    * **RPATH:** Several tests explicitly deal with RPATH (`test_build_rpath`, `test_build_rpath_pkgconfig`, `test_global_rpath`), indicating a concern for how shared libraries are located at runtime.
    * **Cross-compilation:**  `test_cross_find_program` suggests testing support for cross-compilation scenarios.
    * **Reconfiguration:** `test_reconfigure` explicitly tests the ability to rebuild with changed settings.
    * **Vala:** `test_vala_generated_source_buildir_inside_source_tree` indicates testing integration with the Vala language.
    * **GNOME Module:** `test_old_gnome_module_codepaths` highlights testing specific integration with the GNOME desktop environment's build system.

4. **Detailed Examination of Individual Tests:**  I go back and analyze individual test functions more closely. For each test, I ask:
    * **What is the test trying to verify?** (e.g., that specific compiler flags are present/absent, that an installed executable runs correctly, that introspection returns expected data).
    * **How does it achieve this?** (e.g., by setting up test directories, running Meson commands, inspecting generated build files, executing compiled programs, using assertions).
    * **Are there any specific conditions or edge cases being tested?** (e.g., different C++ standard versions, running installed binaries without `LD_LIBRARY_PATH`, handling pkg-config output order).

5. **Connecting to Reverse Engineering, Low-Level Concepts, and User Errors:** As I understand the individual tests, I look for connections to the specific areas mentioned in the prompt:
    * **Reverse Engineering:**  The tests related to RPATH and `LD_LIBRARY_PATH` are directly relevant, as understanding library loading is crucial in reverse engineering. The ability to inspect build artifacts (`self.introspect`) can also be useful for understanding how a program is built.
    * **Binary/Low-Level:** Compiler and linker flag tests directly relate to how binaries are generated. RPATH is a binary-level concept.
    * **Linux/Android Kernel/Framework:** The tests targeting RPATH and `LD_LIBRARY_PATH` are heavily tied to Linux dynamic linking. While not explicitly about the *kernel*, they deal with core OS functionalities. The GNOME module tests are relevant to Linux desktop framework development.
    * **Logical Reasoning:** The assertions within the tests represent logical checks based on expected behavior. For example, the `test_order_of_l_arguments` test reasons about the expected order of linker flags.
    * **User Errors:** Tests that check for failures when running installed programs without `LD_LIBRARY_PATH` demonstrate a common user error. Misconfigured `PKG_CONFIG_PATH` is another potential user error that some tests implicitly cover.

6. **Synthesizing the Information (Drafting the Summary):**  Based on the detailed analysis, I start writing the summary. I aim to capture the key functionalities and their relevance to the specified areas. I group related functionalities together for clarity.

7. **Adding Examples and Specifics:**  To make the summary more concrete, I include specific examples from the code. For instance, mentioning the `-std=c++` flag or the purpose of the `test_run_installed` function.

8. **Addressing User Steps and Debugging:** I consider how a user might end up running these tests. This involves typical development workflows using Meson for building software, including potential debugging scenarios.

9. **Review and Refinement:** I review the summary for accuracy, clarity, and completeness. I ensure that I have addressed all the points raised in the original request. I refine the language to be more precise and easy to understand. I also make sure to stick to the "Part 2" request and not introduce information from other potential parts.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and informative summary that addresses all aspects of the request. The key is to break down the code into manageable parts, understand the purpose of each part, and then synthesize that understanding into a coherent overview.
这是名为 `linuxliketests.py` 的 Python 源代码文件，它属于 Frida 项目中 `frida-qml` 子项目的测试套件。这个文件专门用于在类 Unix 系统（如 Linux）上运行单元测试。

**它的主要功能可以归纳为：**

1. **测试 Meson 构建系统的特定功能在类 Unix 环境下的正确性:** 这个文件中的各个 `test_` 开头的函数，每一个都针对 Meson 构建系统的某一个特定方面进行测试，确保 Meson 在 Linux 等系统上的行为符合预期。这些测试覆盖了编译选项、链接、安装、依赖管理、代码生成、introspection 等多个方面。

2. **验证与编译、链接相关的细节:** 很多测试关注编译器和链接器的行为，例如测试 `-std=c++` 标志的处理、`-Werror` 选项、链接库的顺序 (`-L`, `-l`)、RPATH 的设置等。

3. **检查安装过程的正确性:** 一些测试验证了软件的安装过程，包括安装路径、安装文件的内容、以及运行时依赖的正确处理（例如，使用 RPATH 或 `LD_LIBRARY_PATH`）。

4. **测试 Meson 的 introspection 功能:**  `introspect` 是 Meson 提供的一个强大的工具，用于获取构建系统的内部信息。这个文件中有测试用例专门验证 `meson introspect` 命令返回信息的准确性，包括依赖关系、目标文件、安装信息等。

5. **测试与第三方库（通过 pkg-config）的集成:** 很多测试使用了 `@skipIfNoPkgconfig` 装饰器，表明它们测试的是 Meson 如何与使用 `pkg-config` 的外部库进行交互，包括查找依赖、获取编译和链接选项等。

**与逆向方法的关联及举例说明:**

这个文件的很多测试都直接或间接地与逆向方法有关，因为逆向工程经常需要理解目标软件的构建方式、依赖关系以及运行时行为。

* **理解依赖和链接:** 像 `test_order_of_l_arguments`, `test_build_rpath`, `test_run_installed` 这样的测试，帮助理解目标程序依赖了哪些库，以及这些库是如何被链接的。这对于逆向分析时定位关键库和函数非常重要。例如，如果逆向工程师想知道某个程序在运行时加载了哪个版本的 `libfoo.so`，理解 RPATH 的工作原理至关重要，而 `test_build_rpath` 就是在验证 RPATH 的设置是否正确。
* **检查编译选项:** `test_cpp_std_override` 这样的测试关注编译选项，逆向工程师可以通过分析编译选项来推断代码的某些行为或特性。例如，是否使用了特定的 C++ 标准，可能会影响代码的结构和使用的库。
* **Introspection 辅助分析:**  `test_introspect_dependencies` 和 `test_introspect_installed` 测试了 Meson 的 introspection 功能，逆向工程师可以使用 `meson introspect` 来了解目标软件的构建配置，例如依赖了哪些库、编译时定义了哪些宏等，从而辅助理解软件的结构和功能。

**涉及二进制底层，linux, android内核及框架的知识及举例说明:**

* **二进制层面 (RPATH):** `test_build_rpath` 等测试直接涉及到 RPATH (Run-Time Path) 的概念。RPATH 是嵌入到可执行文件或共享库中的路径列表，用于在运行时查找依赖的共享库。理解 RPATH 对于理解动态链接的过程至关重要，这属于二进制层面的知识。在 Linux 和 Android 上，RPATH 的设置和使用方式类似。
* **Linux 系统调用 (`LD_LIBRARY_PATH`):** `test_run_installed` 测试了在没有设置 `LD_LIBRARY_PATH` 的情况下程序是否能正常运行，这涉及到 Linux 动态链接器的行为。`LD_LIBRARY_PATH` 是一个环境变量，用于指定动态链接器搜索共享库的路径。
* **Linux 包管理 (`pkg-config`):**  大量使用了 `@skipIfNoPkgconfig` 的测试表明了与 `pkg-config` 的集成。`pkg-config` 是 Linux 系统上用于获取已安装库的编译和链接信息的工具，理解 `pkg-config` 的工作原理对于理解软件的依赖管理至关重要。
* **Android 框架 (间接关联):** 虽然这个文件没有直接涉及 Android 内核或框架，但 Frida 本身常用于 Android 平台的动态插桩。因此，理解 Frida 的构建过程以及它如何处理依赖关系，对于在 Android 平台上使用 Frida 进行逆向或安全分析是有帮助的。例如，在 Android 上使用 Frida Hook 系统调用或应用层函数，需要理解 Android 的动态链接机制。

**逻辑推理及假设输入与输出:**

以 `test_cpp_std_override` 为例：

* **假设输入:** 一个包含三个源文件的测试目录，分别命名为 `prog98.cc`, `prog11.cc`, `progp.cc`。Meson 构建文件 (`meson.build`) 中会针对这三个文件设置不同的 C++ 标准选项。
* **逻辑推理:** 测试代码首先运行 Meson 生成构建文件，然后通过 `self.get_compdb()` 获取编译数据库 (compile commands database)。接着，它遍历编译数据库，找到对应源文件的编译命令，并断言其中是否包含或不包含特定的 `-std=c++` 标志和 `-Werror` 标志。
* **预期输出:**
    * `prog98.cc` 的编译命令应该包含 `-std=c++98`，不包含 `-std=c++11`，不包含 `-Werror`。
    * `prog11.cc` 的编译命令应该包含 `-std=c++11`，不包含 `-std=c++98`，不包含 `-Werror`。
    * `progp.cc` 的编译命令应该不包含 `-std=c++98`，不包含 `-std=c++11`，包含 `-Werror`。

**用户或编程常见的使用错误及举例说明:**

* **忘记设置 `LD_LIBRARY_PATH`:** `test_run_installed` 测试了在没有设置 `LD_LIBRARY_PATH` 的情况下运行安装后的程序会失败。这是一个常见的用户错误，尤其是在开发和部署需要动态链接库的应用程序时。用户可能直接运行安装后的可执行文件，而没有配置动态链接器去哪里找到依赖的共享库。
* **`PKG_CONFIG_PATH` 配置错误:** 很多测试依赖于 `pkg-config`。如果用户的 `PKG_CONFIG_PATH` 环境变量配置不正确，导致 Meson 找不到所需的库，构建过程就会失败。虽然测试没有直接模拟用户配置错误的场景，但测试的存在本身就是在验证 Meson 在正确配置 `PKG_CONFIG_PATH` 下的行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Frida 的 `frida-qml` 组件时遇到了问题，例如编译错误或运行时错误，并且怀疑是 Meson 构建配置的问题。以下是用户可能到达这个测试代码的步骤：

1. **用户尝试构建 `frida-qml`:** 用户可能会使用 `meson build` 命令在构建目录中配置构建系统，然后使用 `ninja` 命令进行编译。
2. **遇到构建错误或运行时问题:** 如果构建过程中遇到与编译器选项、链接库或 RPATH 相关的错误，或者安装后的程序运行时找不到共享库，用户可能会开始调查。
3. **查看 Frida 的源代码:** 用户可能会下载或克隆 Frida 的源代码，并浏览 `frida-qml` 子项目的相关文件。
4. **定位到测试目录:** 用户可能会发现 `frida/subprojects/frida-qml/releng/meson/unittests/` 目录下包含了一些测试文件。文件名 `linuxliketests.py` 可能会引起用户的注意，因为它看起来是针对 Linux 系统的测试。
5. **阅读测试代码:** 用户会打开 `linuxliketests.py` 文件，阅读其中的测试函数，尝试理解 Meson 是如何处理编译选项、链接、安装和依赖管理的。
6. **根据测试用例进行调试:** 用户可能会尝试修改自己的 `meson.build` 文件或构建环境，以符合测试用例中验证的正确配置。例如，如果用户怀疑 RPATH 设置有问题，他们可能会参考 `test_build_rpath` 测试用例来检查自己的配置。
7. **运行测试 (高级用户):**  更高级的用户甚至可能会尝试运行这些测试用例，以验证 Frida 的构建系统在他们的环境中的行为是否符合预期。

**归纳一下它的功能 (第2部分总结):**

`linuxliketests.py` 文件的主要功能是作为 Frida `frida-qml` 子项目在 Linux 等类 Unix 系统上的单元测试套件。它通过一系列独立的测试用例，验证了 Meson 构建系统在处理 C++ 标准、编译选项、链接库、安装过程、依赖管理（特别是通过 `pkg-config`）、RPATH 设置以及 introspection 功能时的正确性。这些测试对于确保 Frida 在 Linux 系统上的稳定性和可靠性至关重要，同时也为开发者和用户提供了理解 Frida 构建过程和排查相关问题的线索。 很多测试用例直接或间接地与逆向工程的知识和技能相关，例如理解动态链接、库依赖和编译选项。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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