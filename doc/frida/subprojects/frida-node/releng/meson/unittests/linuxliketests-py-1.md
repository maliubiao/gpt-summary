Response:
The user wants to understand the functionality of the provided Python code snippet, which is part of the Frida dynamic instrumentation tool's test suite. Specifically, they are interested in:

1. **General Functionality**: What does this code do?
2. **Relevance to Reverse Engineering**: How is it related to reverse engineering techniques?
3. **Low-Level/Kernel/Framework Knowledge**: Does it touch upon binary internals, Linux/Android kernels or frameworks?
4. **Logical Reasoning**: Can we infer input and output based on the logic?
5. **Common Usage Errors**: Does it highlight potential mistakes users might make?
6. **User Steps to Reach This Code**: How does a user's interaction lead to this code being executed (debugging context)?
7. **Summary of Functionality**: A concise overview of the code's purpose.

Let's break down the code section by section:

- **`test_cpp_std_override(self)`**: This test checks if the Meson build system correctly handles overriding the C++ standard for specific source files. It examines the compiler commands in the compilation database (`compdb`) to verify that different C++ standards (C++98, C++11, and default) are applied based on the file. It also checks for the presence of the `-Werror` flag.
- **`test_run_installed(self)`**: This test verifies that an installed executable can run correctly after installation. It focuses on how shared libraries are found using `LD_LIBRARY_PATH` and RPATH. It checks if the executable fails when run without the correct library path and succeeds when it is set. It also tests the `introspect --installed` command.
- **`test_order_of_l_arguments(self)`**: This test checks the order of `-L` (library path) and `-l` (library name) arguments passed to the linker. It ensures that the order defined in the `.pc` file is maintained in the generated `build.ninja` file.
- **`test_introspect_dependencies(self)`**: This test examines the output of `mesonintrospect --dependencies`. It verifies that the command returns a list of dependencies, each containing compile and link arguments. It specifically checks for the presence of `glib-2.0` and `gobject-2.0` dependencies.
- **`test_introspect_installed(self)`**: This test checks the output of `mesonintrospect --installed`, which lists installed files. It compares the output against expected file paths for different library versions on Linux and macOS.
- **`test_build_rpath(self)`**: This test verifies that the RPATH (runtime library search path) is correctly set for executables during the build and installation processes. It checks the values of RPATH in the built and installed binaries using a helper function `get_rpath`.
- **`test_build_rpath_pkgconfig(self)`**: Similar to `test_build_rpath`, this test checks the RPATH but also considers the influence of `pkg-config` on the order of paths in the RPATH.
- **`test_global_rpath(self)`**: This test focuses on how globally defined RPATHs (e.g., via `LDFLAGS`) are handled during the build and installation. It simulates building and installing an external library and then an application that uses it, ensuring the global RPATH is correctly applied.
- **`test_pch_with_address_sanitizer(self)`**: This test verifies that precompiled headers (PCH) work correctly when the address sanitizer (`-fsanitize=address`) is enabled. It checks if the sanitizer flag is present in the compiler commands.
- **`test_cross_find_program(self)`**: This test checks the functionality of finding programs in a cross-compilation setup. It defines a cross-compilation file and verifies that Meson can locate tools specified in it.
- **`test_reconfigure(self)`**: This test verifies the `reconfigure` functionality of Meson, specifically when toggling a build option (in this case, coverage).
- **`test_vala_generated_source_buildir_inside_source_tree(self)`**: This test ensures that the Vala compiler correctly places generated C source files when the build directory is inside the source tree.
- **`test_old_gnome_module_codepaths(self)`**: This test specifically targets older versions of the GLib library by mocking the detected version. This is important for ensuring backward compatibility and testing fallback code paths.
- **`test_pkgconfig_usage(self)`**: This test covers various aspects of using `pkg-config`. It builds and installs a library and then a program that depends on it via `pkg-config`, checking for correct linking and header inclusion. It also verifies that private internal libraries are not exposed.
- **`test_pkgconfig_relative_paths(self)`**: This test checks if `pkg-config` correctly handles relative paths in `.pc` files.
- **`test_pkgconfig_duplicate_path_entries(self)`**: This test ensures that duplicate entries in the `PKG_CONFIG_PATH` are handled correctly.
- **`test_pkgconfig_internal_libraries(self)`**: This test verifies the handling of internal libraries when using `pkg-config`.
- **`test_static_archive_stripping(self)`**: This test checks that static archives are correctly stripped when the `--strip` option is used, ensuring the resulting archives are valid.
- **`test_pkgconfig_formatting(self)`**: This test verifies the formatting of the output of `pkg-config`, specifically the `-l` flags.
- **`test_pkgconfig_csharp_library(self)`**: This test checks the `pkg-config` output for C# libraries.
- **`test_pkgconfig_link_order(self)`**: This test ensures that libraries are listed before their dependencies in the `pkg-config` output.
- **`test_deterministic_dep_order(self)`**: This test verifies that the order of dependencies in the generated `build.ninja` file is deterministic.
- **`test_deterministic_rpath_order(self)`**: This test ensures that the order of RPATH entries in the `build.ninja` file is deterministic.
- **`test_override_with_exe_dep(self)`**: This test checks the dependency tracking when a program is overridden with an executable.
- **`test_usage_external_library(self)`**: This test verifies the usage of external libraries, both system libraries and those found via `pkg-config`.
- **`test_link_arg_fullname(self)`**: This test checks support for specifying library names with full paths (e.g., `-l:libfullname.a`).
- **`test_usage_pkgconfig_prefixes(self)`**: This test verifies the scenario where multiple external libraries are installed to different prefixes and a client program uses them via `pkg-config`.
- **`install_subdir_invalid_symlinks(self, testdir, subdir_path)`**: This is a helper function to test the installation of broken symbolic links.
- **`test_install_subdir_symlinks(self)`**: Tests the installation of symbolic links in subdirectories.
- **`test_install_subdir_symlinks_with_default_umask(self)`**: Tests the installation of symbolic links with default umask.
- **`test_install_subdir_symlinks_with_default_umask_and_mode(self)`**: Tests the installation of symbolic links with default umask and specified mode.
- **`test_ldflag_dedup(self)`**: This test (truncated) likely checks for the deduplication of linker flags.
This Python code snippet is part of the unit tests for Frida's Node.js bindings, specifically focusing on how the Meson build system handles various scenarios on Linux-like systems. Let's break down its functionalities:

**General Functionality:**

This code defines a series of test methods within a larger test class (`LinuxLikeTests`). Each test method verifies a specific aspect of the Meson build system's behavior when building Node.js addons that might interact with native code and libraries. These tests cover:

* **C++ Standard Overrides:** Ensuring that specific source files can be compiled with different C++ standards (e.g., C++98, C++11).
* **Running Installed Binaries:** Checking if an installed executable can run correctly and find its required shared libraries after installation, paying attention to RPATH and `LD_LIBRARY_PATH`.
* **Linker Argument Order:** Verifying the order of `-L` (library path) and `-l` (library name) arguments passed to the linker, which can be crucial for successful linking.
* **Dependency Introspection:** Testing the `mesonintrospect` command to retrieve information about project dependencies, including compile and link arguments.
* **Installed Files Introspection:** Examining the output of `mesonintrospect --installed` to confirm the correct installation locations and names of libraries, considering versioning schemes.
* **RPATH Handling:** Validating that the RPATH (runtime library search path) is correctly set for executables during build and installation. This ensures that the executable can find its shared libraries at runtime.
* **Global RPATHs:** Testing the application of globally defined RPATHs (via environment variables like `LDFLAGS`).
* **Precompiled Headers with Sanitizers:** Checking the compatibility of precompiled headers with address sanitizers (for memory error detection).
* **Cross-Compilation Tool Finding:** Verifying the ability to find programs defined in a cross-compilation configuration file.
* **Reconfiguration:** Testing the Meson's `reconfigure` functionality, which allows changing build options after the initial configuration.
* **Vala Code Generation:** Ensuring correct placement of generated C source files by the Vala compiler when the build directory is within the source tree.
* **Older GNOME Library Compatibility:** Testing fallback code paths within the build system that are triggered when older versions of GNOME libraries are detected (simulated via mocking).
* **`pkg-config` Usage:** Thoroughly testing integration with `pkg-config`, a standard tool for providing information about installed libraries. This includes testing:
    * Finding dependencies.
    * Handling private internal libraries.
    * Preventing dependency leakage in compile flags.
    * Correctness and usability of generated `pkg-config` files.
    * Handling relative paths in `pkg-config` files.
    * Managing duplicate paths in `PKG_CONFIG_PATH`.
    * Using internal libraries via `pkg-config`.
    * Static archive stripping when using `--strip`.
    * Output formatting of `pkg-config`.
    * Handling C# libraries with `pkg-config`.
    * Link order of libraries and their dependencies in `pkg-config` output.
* **Deterministic Dependency and RPATH Order:** Ensuring that the order of dependencies and RPATH entries in the generated build files is consistent.
* **Overriding Dependencies with Executables:** Testing the dependency tracking when a library dependency is overridden by an executable.
* **Usage of External Libraries:** Verifying that projects can use both system libraries and libraries found via `pkg-config`.
* **Link Argument Full Names:** Testing support for specifying library names with full paths in linker arguments (e.g., `-l:libfullname.a`).
* **`pkg-config` Prefixes:** Testing scenarios where multiple external libraries are installed to different prefixes and a client program correctly finds them via `pkg-config`.
* **Installation of Broken Symlinks:** Ensuring that the installation process correctly handles and preserves broken symbolic links.

**Relationship to Reverse Engineering:**

While these tests primarily focus on the build process, they indirectly relate to reverse engineering in several ways:

* **Understanding Binary Structure and Dependencies:**  Tests involving RPATH, `LD_LIBRARY_PATH`, and dependency introspection are crucial for understanding how compiled binaries find and load their dependencies. This knowledge is fundamental in reverse engineering when analyzing the execution flow and required libraries of a target application. For instance, `test_run_installed` directly simulates a scenario where a dynamically linked executable relies on a shared library. A reverse engineer would need to understand how the operating system searches for this library (using `LD_LIBRARY_PATH` or embedded RPATHs) to properly analyze the application's behavior.
    * **Example:**  If `test_run_installed` failed because the RPATH wasn't correctly set, a reverse engineer might encounter a similar issue when trying to run a stripped binary outside its intended installation directory. Understanding RPATH allows them to either set the `LD_LIBRARY_PATH` manually or potentially patch the binary to modify the RPATH.
* **Analyzing Build Systems:**  Reverse engineers sometimes need to understand the build process of a target application, especially when analyzing closed-source software. These tests provide insights into how Meson, a popular build system, manages dependencies, compiler flags, and linker settings. This knowledge can help in recreating the build environment or understanding the compilation process to identify potential vulnerabilities or hidden functionalities.
    * **Example:** The `test_cpp_std_override` test demonstrates how different parts of a project can be compiled with different language standards. This could be relevant in reverse engineering if you encounter code snippets compiled with older standards that might have known vulnerabilities or different behavior compared to modern C++.
* **Debugging and Instrumentation:** Frida itself is a dynamic instrumentation toolkit. These tests ensure the correct functioning of the build system for Frida's Node.js bindings, which are used to interact with and instrument processes. A correctly built Frida Node.js module is essential for reverse engineers to perform dynamic analysis.
    * **Example:**  If the `test_pkgconfig_usage` test failed, it could indicate a problem with how Frida's Node.js bindings are linked against their dependencies. This would directly impact a reverse engineer's ability to use Frida effectively for tasks like hooking functions or inspecting memory.

**Binary 底层, Linux, Android 内核及框架的知识:**

Several tests directly or indirectly involve concepts related to binary internals, Linux, and potentially Android:

* **RPATH and `LD_LIBRARY_PATH`:** These are core concepts in Linux (and similar Unix-like systems, including Android) for managing shared library loading. The tests (`test_run_installed`, `test_build_rpath`, `test_build_rpath_pkgconfig`, `test_global_rpath`) directly manipulate and verify the correct handling of these mechanisms. Understanding these is crucial for analyzing how applications are loaded and linked on these platforms.
* **Shared Libraries (.so, .dylib):** The tests involving RPATH and `LD_LIBRARY_PATH` deal with the fundamental concept of shared libraries, a cornerstone of modern operating systems like Linux and macOS (and Android uses a similar concept with `.so` files).
* **Linker Flags (-L, -l, -Wl):** The tests examining linker argument order (`test_order_of_l_arguments`) and global RPATHs (`test_global_rpath`) directly interact with linker flags. Understanding these flags is essential for anyone working with compiled code on Linux. `-Wl` is particularly relevant as it passes options directly to the linker.
* **`pkg-config`:**  `pkg-config` is a standard tool on Linux and other Unix-like systems for managing dependencies. Its use in these tests reflects its importance in the Linux development ecosystem.
* **Address Sanitizer (`-fsanitize=address`):** The `test_pch_with_address_sanitizer` test utilizes a compiler flag specific to memory safety analysis, often used in Linux development.
* **Cross-Compilation:** The `test_cross_find_program` test directly deals with the complexities of cross-compiling software for different architectures, a common practice when developing for embedded systems like those running Linux or Android.
* **Symbolic Links:** Tests like `test_install_subdir_symlinks` touch upon the concept of symbolic links, a fundamental file system feature in Linux and other Unix-like systems.
* **Library Versioning (.so.1, .so.1.2.3):** The `test_introspect_installed` test demonstrates how shared libraries are versioned on Linux using the `.so` suffix followed by version numbers.

**逻辑推理 (假设输入与输出):**

Let's take the `test_cpp_std_override` as an example:

* **Assumed Input:** A Meson project with three source files: `prog98.cc` (intended for C++98), `prog11.cc` (intended for C++11), and `progp.cc` (using the default standard). The `meson.build` file would contain logic to set the C++ standard per target/source.
* **Expected Output:** The test will fetch the compilation database. The compiler commands for `prog98.cc` will contain `-std=c++98` but not `-std=c++11`. The commands for `prog11.cc` will contain `-std=c++11` but not `-std=c++98`. The commands for `progp.cc` will contain neither `-std=c++98` nor `-std=c++11`. Additionally, `progp.cc`'s compilation command will include `-Werror`, while `prog98.cc`'s will not.

**用户或编程常见的使用错误 (举例说明):**

* **Incorrect `LD_LIBRARY_PATH`:**  The `test_run_installed` directly highlights a common user error. If a user tries to run an installed executable that depends on shared libraries without setting the `LD_LIBRARY_PATH` environment variable to include the directory of those libraries, the executable will fail to launch. This test verifies that this failure occurs as expected.
* **Incorrect Linker Argument Order:**  The `test_order_of_l_arguments` shows that the order of `-L` and `-l` flags matters. If a user or a build system incorrectly orders these flags, the linker might fail to find the required libraries, leading to build errors. This test ensures that Meson preserves the correct order.
* **Missing Dependencies:** While not explicitly a user *programming* error in this code, the `test_pkgconfig_usage` indirectly touches on a common issue. If a user tries to build a project that depends on external libraries without those libraries (or their `pkg-config` files) being available, the build will fail. This test simulates a successful scenario to ensure the dependency mechanism works.
* **Forgetting to Install Dependencies:**  The setup of some tests, especially those involving `pkg-config`, require pre-installing "external" libraries. A user might forget this step when trying to reproduce a build, leading to errors.

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Developer Modifies Frida's Node.js Bindings:** A developer working on Frida's Node.js integration might make changes to the build system (the `meson.build` files) or the native C/C++ code.
2. **Running Unit Tests:** To ensure their changes haven't broken existing functionality, the developer would run the unit tests. This is typically done through a command-line interface, invoking a testing framework like `pytest`.
3. **Test Execution:** The testing framework discovers and executes the test methods within `linuxliketests.py`.
4. **Individual Test Execution:**  Each test method sets up a specific scenario (e.g., a temporary build directory, source files with particular configurations).
5. **Meson Invocation:**  The test methods then programmatically invoke the Meson build system (`meson setup`, `meson compile`, `meson install`, `meson introspect`) with specific arguments and in specific environments to simulate different build scenarios.
6. **Assertions:** After running Meson commands, the test methods use assertions (e.g., `self.assertEqual`, `self.assertTrue`, `self.assertIn`) to verify that Meson behaved as expected. For example, they might check the content of generated build files (`build.ninja`), the output of Meson commands, or the presence and correctness of installed files.
7. **Debugging:** If a test fails, the developer would use the output of the test framework and potentially add logging or debugging statements within the test code or Meson itself to understand why the expectation wasn't met. The specific test that failed provides a clear indication of the area where the problem lies. For instance, if `test_run_installed` fails, the developer knows to investigate issues related to RPATH or library loading.

**归纳一下它的功能 (第2部分):**

This section of the Frida Node.js bindings unit tests comprehensively examines how the Meson build system functions on Linux-like operating systems. It focuses on core build system functionalities like handling different C++ standards, managing shared library dependencies (through RPATH and `LD_LIBRARY_PATH`), integrating with `pkg-config`, and ensuring the deterministic behavior of the build process. These tests are crucial for guaranteeing the stability and correctness of the Frida Node.js addon build process across various Linux distributions and system configurations. They also highlight potential pitfalls and common errors developers and users might encounter when building or running software with shared library dependencies on these platforms.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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