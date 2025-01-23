Response:
The user wants to understand the functionality of the provided Python code, which is a test suite for the Meson build system, specifically for cross-platform compatibility.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Purpose:** The file name `allplatformstests.py` and the context of `frida/subprojects/frida-python/releng/meson/unittests` strongly suggest this file contains unit tests for the Frida project's Meson integration, focusing on cross-platform build scenarios.

2. **Recognize the Test Structure:** The code uses the `unittest` framework in Python. Each method starting with `test_` is an individual test case.

3. **Analyze Individual Test Cases:**  Go through each `test_` method and infer its purpose by looking at the actions performed:
    * **`test_basic`:**  Simple build and test execution.
    * **`test_basic_options`:** Tests specific build options like `--warnlevel`.
    * **`test_cmd_line_define`:** Checks defining variables on the command line.
    * **`test_override_library_path`:** Tests overriding library paths.
    * **`test_build_install_files`:** Verifies the correct files are installed.
    * **`test_build_install_empty_dir`:** Tests installing an empty directory.
    * **`test_build_install_file_permissions`:** Checks file permissions after installation.
    * **`test_build_include_file_permissions`:** Checks include file permissions.
    * **`test_build_install_symlink_permissions`:** Tests permissions of installed symlinks.
    * **`test_build_install_run_post_install`:** Verifies execution of post-install scripts.
    * **`test_build_install_run_post_install_target`:** Tests post-install scripts for specific targets.
    * **`test_build_install_depfile`:** Checks dependency file generation during install.
    * **`test_build_install_strip`:** Tests stripping binaries during installation.
    * **`test_build_install_absolute_paths`:** Tests installation with absolute paths.
    * **`test_build_install_rename`:** Checks renaming files during installation.
    * **`test_build_install_subproject_rename`:** Tests renaming files in subprojects.
    * **`test_build_install_custom_install_script`:** Tests custom install scripts.
    * **`test_build_install_override_destdir`:** Tests overriding the destination directory.
    * **`test_build_install_destdir_ேயேexisting`:** Tests installing to an existing destination directory.
    * **`test_build_install_no_default_libdir`:** Tests scenarios without a default library directory.
    * **`test_build_install_custom_libexecdir`:** Tests custom libexec directory.
    * **`test_build_install_custom_bindir_and_libdir`:** Tests custom bindir and libdir.
    * **`test_build_install_libexecsubdir`:** Tests libexec subdirectory installation.
    * **`test_build_install_bindir_subdir`:** Tests bindir subdirectory installation.
    * **`test_build_install_shared_lib_subdir`:** Tests shared library subdirectory installation.
    * **`test_install_always_generated`:** Tests always generated files during install.
    * **`test_install_generator`:** Tests installation of generator outputs.
    * **`test_build_install_targets_with_spaces`:** Tests targets with spaces in their names.
    * **`test_build_install_targets_with_non_ascii`:** Tests targets with non-ASCII names.
    * **`test_build_install_targets_with_dots`:** Tests targets with dots in their names.
    * **`test_build_install_module`:** Tests installing Python modules.
    * **`test_build_install_module_package`:** Tests installing Python packages.
    * **`test_build_install_module_package_top_level`:** Tests top-level Python package installation.
    * **`test_build_install_module_package_namespace`:** Tests namespace Python package installation.
    * **`test_build_install_module_package_namespace_flat`:** Tests flat namespace Python package installation.
    * **`test_build_install_module_package_namespace_implicit`:** Tests implicit namespace Python package installation.
    * **`test_build_install_module_package_namespace_reinit`:** Tests re-initializing namespace Python packages.
    * **`test_build_install_subdir_module`:** Tests installing modules to subdirectories.
    * **`test_build_install_skip_pure`:** Tests skipping pure Python modules during install.
    * **`test_build_install_module_symlink`:** Tests installing Python modules as symlinks.
    * **`test_build_install_bytecode`:** Tests installing Python bytecode.
    * **`test_build_install_bytecode_optimization_levels`:** Tests different bytecode optimization levels.
    * **`test_build_install_bytecode_subdir`:** Tests installing bytecode to subdirectories.
    * **`test_build_install_bytecode_symlink`:** Tests installing bytecode as symlinks.
    * **`test_build_install_data`:** Tests installing data files.
    * **`test_build_install_data_subdir`:** Tests installing data files to subdirectories.
    * **`test_build_install_data_symlink`:** Tests installing data files as symlinks.
    * **`test_build_install_include`:** Tests installing include files.
    * **`test_build_install_include_subdir`:** Tests installing include files to subdirectories.
    * **`test_build_install_include_symlink`:** Tests installing include files as symlinks.
    * **`test_build_install_po`:** Tests installing gettext translation files.
    * **`test_build_install_po_subdir`:** Tests installing translation files to subdirectories.
    * **`test_build_install_po_symlink`:** Tests installing translation files as symlinks.
    * **`test_build_install_shared_library`:** Tests installing shared libraries.
    * **`test_build_install_shared_library_subdir`:** Tests installing shared libraries to subdirectories.
    * **`test_build_install_shared_library_symlink`:** Tests installing shared libraries as symlinks.
    * **`test_build_install_static_library`:** Tests installing static libraries.
    * **`test_build_install_static_library_subdir`:** Tests installing static libraries to subdirectories.
    * **`test_build_install_static_library_symlink`:** Tests installing static libraries as symlinks.
    * **`test_build_install_executable`:** Tests installing executables.
    * **`test_build_install_executable_subdir`:** Tests installing executables to subdirectories.
    * **`test_build_install_executable_symlink`:** Tests installing executables as symlinks.
    * **`test_build_install_generated_executable_symlink`:** Tests symlinking generated executables.
    * **`test_build_install_subdir`:** Tests installing entire subdirectories.
    * **`test_build_install_subdir_exclude_files`:** Tests excluding specific files during subdirectory installation.
    * **`test_build_install_subdir_exclude_dirs`:** Tests excluding directories during subdirectory installation.
    * **`test_build_install_subdir_symlink`:** Tests installing subdirectories as symlinks.
    * **`test_build_install_install_scripts`:** Tests installing install scripts.
    * **`test_build_install_install_scripts_subdir`:** Tests installing install scripts to subdirectories.
    * **`test_build_install_install_scripts_symlink`:** Tests installing install scripts as symlinks.
    * **`test_build_install_rename_install_scripts`:** Tests renaming install scripts during installation.
    * **`test_build_install_allow_duplicates`:** Tests allowing duplicate installations.
    * **`test_build_install_allow_duplicates_script`:** Tests allowing duplicate installations with scripts.
    * **`test_build_multiple_envvars`:** Tests using multiple environment variables.
    * **`test_build_b_options`:** Tests build "b_" options (likely related to optimization/debug).
    * **`test_install_skip_subprojects`:** Tests skipping installation of subprojects.
    * **`test_adding_subproject_to_configure_project`:** Tests adding a subproject after initial configuration.
    * **`test_devenv`:** Tests the "devenv" command for setting up development environments.
    * **`test_clang_format_check`:** Tests integration with clang-format for code formatting.
    * **`test_custom_target_implicit_include`:** Tests implicit include directories for custom targets.
    * **`test_env_flags_to_linker`:** Tests how environment flags are passed to the linker.
    * **`test_install_tag`:** Tests installing specific targets based on tags.
    * **`test_install_script_dry_run`:** Tests the dry-run mode for install scripts.
    * **`test_introspect_install_plan`:** Tests the introspection of the install plan.
    * **`test_rust_clippy`:** Tests integration with the Rust linter (clippy).
    * **`test_rust_rlib_linkage`:** Tests linking Rust rlib files.
    * **`test_bindgen_drops_invalid`:** Tests how bindgen handles invalid compiler arguments.
    * **`test_custom_target_name`:** Tests custom names for targets.
    * **`test_symlinked_subproject`:** Tests using symlinked subprojects.
    * **`test_configure_same_noop`:** Tests that re-configuring with the same options doesn't trigger a rebuild.
    * **`test_c_cpp_stds`:** Tests setting C and C++ standard versions.

4. **Identify Relationships to Reverse Engineering:**  Focus on tests that imply interaction with compiled code or the build process itself.
    * **Installation Tests:** Any test starting with `test_build_install_` is relevant as it checks how compiled artifacts are placed. This is key in understanding the final layout of a reverse-engineered target.
    * **Stripping (`test_build_install_strip`):**  Stripping removes debug symbols, a common practice before distributing software and a challenge in reverse engineering.
    * **Shared Libraries (`test_build_install_shared_library`):** Understanding how shared libraries are built and installed is crucial for analyzing dependencies and function calls.
    * **Executables (`test_build_install_executable`):** The installation of executables is the endpoint of the build process.
    * **`test_devenv`:**  While not directly reverse engineering, this test relates to setting up an environment *for* development, which is often a precursor to reverse engineering.
    * **`test_env_flags_to_linker`:** Understanding linker flags is essential for analyzing the final executable structure and potential security mitigations.
    * **`test_rust_clippy`:**  While specific to Rust, the concept of static analysis tools is relevant in identifying potential vulnerabilities before compilation.

5. **Identify Relationships to Binary/Kernel/Framework Concepts:** Look for tests involving lower-level concepts.
    * **Permissions (`test_build_install_*_permissions`):** File permissions are fundamental to operating system security.
    * **Shared/Static Libraries:** These are core concepts in linking and loading binaries.
    * **Executables:** The basic unit of execution in operating systems.
    * **Linker Flags (`test_env_flags_to_linker`):**  Linker behavior directly impacts the final binary structure.
    * **`test_c_cpp_stds`:** C/C++ standards influence the compiled binary's behavior and compatibility.

6. **Identify Logic and Potential Inputs/Outputs:** Look for tests that set up specific conditions and verify the outcome.
    * **`test_cmd_line_define`:** Input: Command-line definitions. Output: The defined values are correctly used in the build.
    * **`test_install_skip_subprojects`:** Input: `--skip-subprojects` flag. Output: Only the main project is installed.
    * **`test_configure_same_noop`:** Input: Re-running configure with the same options. Output: No rebuild is triggered.

7. **Identify Common User/Programming Errors:** Look for tests that prevent or detect incorrect usage.
    * **Invalid options:** Tests like `test_basic_options` with `--warnlevel=NO_SUCH_WARNING` demonstrate handling of invalid input.
    * **Incorrect paths:** Tests involving installation paths could highlight issues if paths are not handled correctly.
    * **Duplicate installations:** `test_build_install_allow_duplicates` touches upon managing potential conflicts.
    * **Incorrect C/C++ standard:** `test_c_cpp_stds` prevents using invalid or unsupported standard versions.

8. **Trace User Actions (Debugging Clues):** Consider how a developer might end up running these tests.
    * A developer working on Frida Python might modify the build system (Meson files) or Python code.
    * To ensure their changes work correctly across platforms, they would run these unit tests.
    * The specific test being executed depends on the area they've modified. For example, changes to installation logic would lead to running `test_build_install_*` tests.
    * If a build fails or behaves unexpectedly on a certain platform, these tests help pinpoint the issue.

9. **Summarize Functionality (as the 7th part):** Combine the observations from the previous steps to create a concise overview of the file's purpose. Emphasize its role in ensuring the reliability and cross-platform compatibility of Frida's Python bindings.

By following this structured approach, you can effectively analyze the code and address all aspects of the user's request.
这是 frida 动态 instrumentation 工具的源代码文件，路径为 `frida/subprojects/frida-python/releng/meson/unittests/allplatformstests.py`。这个文件包含了针对 Meson 构建系统的单元测试，旨在验证 frida-python 项目在各种平台上的构建和安装行为是否正确。

**它的主要功能是：**

1. **测试基本的构建流程:** 验证使用 Meson 构建 frida-python 项目是否成功。
2. **测试构建选项:** 检查各种 Meson 构建选项（例如警告级别、优化级别等）是否按预期工作。
3. **测试命令行定义:** 验证可以通过命令行向构建系统传递定义（例如宏定义、变量定义）并生效。
4. **测试库路径覆盖:** 检查在构建过程中能否正确覆盖默认的库路径。
5. **测试文件安装:**  验证构建产物（例如可执行文件、库文件、数据文件、头文件等）是否被正确安装到指定目录。这包括：
    * 测试安装到不同类型的目录（例如 `bindir`, `libdir`, `datadir`, `includedir` 等）。
    * 测试安装空目录。
    * 测试安装文件的权限是否正确。
    * 测试安装符号链接的权限是否正确。
    * 测试安装后脚本的执行。
    * 测试安装时是否能正确处理依赖文件。
    * 测试安装时是否能去除符号信息 (strip)。
    * 测试使用绝对路径进行安装。
    * 测试安装时重命名文件。
    * 测试安装子项目的文件。
    * 测试自定义安装脚本的执行。
    * 测试覆盖默认安装目录。
    * 测试安装到已存在的目录。
    * 测试在没有默认库目录的情况下的安装。
    * 测试自定义 `libexecdir`, `bindir`, `libdir`。
    * 测试安装到子目录。
    * 测试始终生成的文件在安装时的行为。
    * 测试生成器目标文件的安装。
    * 测试文件名中包含空格、非 ASCII 字符和点号的目标文件的安装。
6. **测试 Python 模块和包的安装:** 验证 Python 模块和包（包括普通包、命名空间包）是否被正确安装，包括：
    * 测试安装到不同的子目录。
    * 测试跳过纯 Python 模块的安装。
    * 测试将 Python 模块安装为符号链接。
    * 测试安装 Python 字节码 (.pyc) 文件，并测试不同的优化级别。
7. **测试数据文件的安装:** 验证数据文件是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将数据文件安装为符号链接。
8. **测试头文件的安装:** 验证头文件是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将头文件安装为符号链接。
9. **测试 gettext 翻译文件的安装:** 验证 `.po` 文件是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将 `.po` 文件安装为符号链接。
10. **测试共享库和静态库的安装:** 验证共享库 (`.so`, `.dll`, `.dylib`) 和静态库 (`.a`, `.lib`) 是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将库文件安装为符号链接。
11. **测试可执行文件的安装:** 验证可执行文件是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将可执行文件安装为符号链接。
    * 测试将生成的可执行文件安装为符号链接。
12. **测试整个子目录的安装:** 验证可以安装整个目录，并能排除特定的文件或子目录。
13. **测试安装脚本的安装:** 验证安装脚本是否被正确安装，包括：
    * 测试安装到子目录。
    * 测试将安装脚本安装为符号链接。
    * 测试重命名安装脚本。
14. **测试允许重复安装:** 验证构建系统是否能处理重复安装的情况。
15. **测试使用多个环境变量:** 验证构建系统是否能正确处理多个环境变量的设置。
16. **测试 `-b_` 开头的构建选项:** 验证以 `-b_` 开头的构建选项是否被允许 (即使在某些版本中可能没有实际作用)。
17. **测试跳过子项目的安装:** 验证在安装时可以选择跳过某些子项目。
18. **测试在已配置的项目中添加新的子项目。**
19. **测试 `devenv` 命令:** 验证 `devenv` 命令能够正确生成用于开发的环境脚本，并支持不同的输出格式（例如 shell 脚本、VSCode 配置）。
20. **测试 `clang-format` 代码格式化检查:** 验证与 `clang-format` 的集成，可以检查和自动格式化代码。
21. **测试自定义目标的隐式包含路径:** 验证自定义目标是否能正确处理隐式的包含路径。
22. **测试环境变量中的标志传递给链接器:** 验证环境变量中的编译器和链接器标志是否正确传递给链接器。
23. **测试安装标签:** 验证可以使用标签来选择性地安装特定的目标。
24. **测试安装脚本的 dry-run 模式:** 验证安装脚本的 `--dry-run` 模式是否能正确模拟安装过程而不实际执行操作。
25. **测试内省安装计划:** 验证可以获取构建系统的安装计划 (哪些文件会被安装到哪里)。
26. **测试 Rust 代码风格检查 (clippy):** (如果启用了 Rust 语言) 验证与 Rust 代码风格检查工具 `clippy` 的集成。
27. **测试 Rust rlib 的链接:** (如果启用了 Rust 语言) 验证 Rust rlib 文件的链接。
28. **测试 bindgen 处理无效参数:** (如果启用了 Rust 语言) 验证 `bindgen` 工具如何处理无效的编译器参数。
29. **测试自定义目标名称。**
30. **测试符号链接的子项目。**
31. **测试重复配置相同选项是否为空操作:** 验证重复执行配置命令且配置没有变化时，是否不会触发重新配置。
32. **测试 C 和 C++ 标准的版本设置:** 验证可以设置 C 和 C++ 的标准版本 (`-Dc_std`, `-Dcpp_std`)。

**与逆向的方法的关系及举例说明：**

* **安装目录结构分析:**  测试文件验证了构建产物最终的安装位置。逆向工程师需要了解目标软件的安装目录结构，才能找到关键的可执行文件、库文件和配置文件。例如，测试 `test_build_install_executable` 验证了可执行文件是否安装到预期的 `bindir`，这对于逆向分析入口点至关重要。
* **库依赖分析:** 测试共享库的安装 (`test_build_install_shared_library`) 揭示了软件的依赖关系。逆向工程师需要知道目标软件依赖哪些库，才能进行更深入的分析，例如查找特定功能的实现或寻找潜在的漏洞。
* **去除符号信息 (Stripping):** `test_build_install_strip` 测试了去除符号信息的功能。逆向工程师经常遇到被 strip 过的二进制文件，这增加了分析难度。了解 strip 的工作原理有助于理解逆向分析中符号信息的重要性。
* **安装脚本:** `test_build_install_install_scripts` 测试了安装脚本的执行。这些脚本可能包含软件的初始化逻辑或配置步骤，逆向工程师可能需要分析这些脚本以了解软件的启动过程。

**涉及到二进制底层，linux, android内核及框架的知识及举例说明：**

* **共享库和静态库:** 测试中涉及到共享库 (`.so` on Linux, `.dll` on Windows, `.dylib` on macOS) 和静态库 (`.a` on Linux, `.lib` on Windows) 的安装，这些都是二进制链接的基本概念，与操作系统加载器的工作方式密切相关。例如，Linux 内核如何加载和链接共享库，以及 Android 系统如何处理 `.so` 文件都是相关的知识点。
* **可执行文件格式:** 测试可执行文件的安装涉及到不同平台的可执行文件格式（例如 ELF on Linux, PE on Windows, Mach-O on macOS）。了解这些格式对于逆向分析二进制文件至关重要。
* **文件权限:** 测试文件权限 (`test_build_install_file_permissions`) 涉及到 Linux 等操作系统中的文件权限管理机制（例如读、写、执行权限）。Android 系统也有类似的权限模型。
* **符号链接:** 测试符号链接的安装 (`test_build_install_*_symlink`) 涉及到文件系统中的符号链接概念，这在 Linux 和 macOS 等系统中很常见。
* **环境变量:** `test_build_multiple_envvars` 测试了环境变量对构建过程的影响。环境变量在 Linux 和 Android 系统中用于配置软件的行为。
* **C 和 C++ 标准:** `test_c_cpp_stds` 测试了 C 和 C++ 标准的选择，不同的标准会影响编译出的二进制代码，可能涉及到不同的 ABI (Application Binary Interface)，这在跨平台开发和逆向分析中需要考虑。

**如果做了逻辑推理，请给出假设输入与输出:**

* **`test_install_skip_subprojects`:**
    * **假设输入:** 执行 `meson install --skip-subprojects` 命令。
    * **预期输出:** 只会安装主项目定义的安装目标，子项目定义的安装目标会被跳过。
* **`test_configure_same_noop`:**
    * **假设输入:**  首次使用特定配置选项（例如 `-Dstring=val`）运行 `meson configure`，然后再次使用相同的配置选项运行 `meson configure`。
    * **预期输出:** 第二次运行 `meson configure` 应该是一个空操作，不会触发重新配置，相关的文件修改时间不会改变。
* **`test_install_tag`:**
    * **假设输入:**  执行 `meson install --tags devel` 命令。
    * **预期输出:** 只会安装带有 `devel` 标签的目标。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的安装路径:** 用户可能错误地配置了安装前缀 (`--prefix`)，导致文件安装到非预期的位置。例如，将 `--prefix` 设置为没有写权限的目录。
* **忘记安装依赖:** 如果构建目标依赖于其他库或组件，用户可能忘记安装这些依赖，导致链接错误或运行时错误。
* **平台特定的问题:**  某些代码或配置可能只在特定平台上有效。用户可能在错误的平台上尝试构建或安装。例如，使用了 Windows 特有的 API 或库，但在 Linux 上构建。
* **环境变量配置错误:** 用户可能错误地设置了环境变量，例如 `LD_LIBRARY_PATH`，导致程序找不到所需的共享库。
* **Meson 选项使用错误:** 用户可能使用了错误的 Meson 选项，例如拼写错误或使用了不兼容的选项。例如，`--warnlevel=NO_SUCH_WARNING` (在 `test_basic_options` 中有体现)。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发人员修改了 frida-python 的构建配置 (meson.build 或相关文件)。**
2. **为了验证修改的正确性，特别是在跨平台场景下，开发人员决定运行单元测试。**
3. **开发人员进入 `frida/subprojects/frida-python/releng/meson/unittests/` 目录。**
4. **他们使用类似 `python3 allplatformstests.py` 或通过集成开发环境 (IDE) 的方式运行 `allplatformstests.py` 文件中的测试。**
5. **如果某个测试失败，例如 `test_build_install_executable` 失败，开发人员会查看测试代码的具体逻辑，了解测试的安装目标和预期行为。**
6. **他们会检查构建日志，查看 Meson 的配置和构建过程，确认可执行文件是否被正确编译和安装。**
7. **他们可能会手动执行构建命令和安装命令，以便更细致地观察中间步骤。**
8. **他们可能会在不同的平台上重复测试，以排除平台特定的问题。**
9. **如果涉及到文件权限问题，他们可能会检查目标目录的权限设置。**
10. **如果涉及到依赖问题，他们会检查依赖库是否已安装，以及链接器是否能找到它们。**

**这是第7部分，共7部分，请归纳一下它的功能:**

总而言之，`allplatformstests.py` 文件是 frida-python 项目的关键测试套件，专注于验证其在各种平台上的构建和安装过程的正确性和一致性。它涵盖了 Meson 构建系统的各种功能，从基本的编译流程到复杂的安装场景，包括对不同类型的文件、目录、Python 包和模块的处理，以及对各种构建选项和用户可能遇到的错误情况的测试。该文件对于确保 frida-python 项目的跨平台兼容性和稳定性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
DCXXFLAG'}
        srcdir = os.path.join(self.unit_test_dir, '88 multiple envvars')
        self.init(srcdir, override_envvars=envs)
        self.build()

    def test_build_b_options(self) -> None:
        # Currently (0.57) these do nothing, but they've always been allowed
        srcdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(srcdir, extra_args=['-Dbuild.b_lto=true'])

    def test_install_skip_subprojects(self):
        testdir = os.path.join(self.unit_test_dir, '92 install skip subprojects')
        self.init(testdir)
        self.build()

        main_expected = [
            '',
            'share',
            'include',
            'foo',
            'bin',
            'share/foo',
            'share/foo/foo.dat',
            'include/foo.h',
            'foo/foofile',
            'bin/foo' + exe_suffix,
        ]
        bar_expected = [
            'bar',
            'share/bar',
            'share/bar/bar.dat',
            'include/bar.h',
            'bin/bar' + exe_suffix,
            'bar/barfile'
        ]
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_argument_syntax() == 'msvc':
            main_expected.append('bin/foo.pdb')
            bar_expected.append('bin/bar.pdb')
        prefix = destdir_join(self.installdir, self.prefix)
        main_expected = [Path(prefix, p) for p in main_expected]
        bar_expected = [Path(prefix, p) for p in bar_expected]
        all_expected = main_expected + bar_expected

        def check_installed_files(extra_args, expected):
            args = ['install', '--destdir', self.installdir] + extra_args
            self._run(self.meson_command + args, workdir=self.builddir)
            all_files = [p for p in Path(self.installdir).rglob('*')]
            self.assertEqual(sorted(expected), sorted(all_files))
            windows_proof_rmtree(self.installdir)

        check_installed_files([], all_expected)
        check_installed_files(['--skip-subprojects'], main_expected)
        check_installed_files(['--skip-subprojects', 'bar'], main_expected)
        check_installed_files(['--skip-subprojects', 'another'], all_expected)

    def test_adding_subproject_to_configure_project(self) -> None:
        srcdir = os.path.join(self.unit_test_dir, '93 new subproject in configured project')
        self.init(srcdir)
        self.build()
        self.setconf('-Duse-sub=true')
        self.build()

    def test_devenv(self):
        testdir = os.path.join(self.unit_test_dir, '90 devenv')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['devenv', '-C', self.builddir]
        script = os.path.join(testdir, 'test-devenv.py')
        app = os.path.join(self.builddir, 'app')
        self._run(cmd + python_command + [script])
        self.assertEqual('This is text.', self._run(cmd + [app]).strip())

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'sh']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'vscode']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        fname = os.path.join(self.builddir, 'dump.env')
        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', fname]
        o = self._run(cmd)
        self.assertEqual(o, '')
        o = Path(fname).read_text(encoding='utf-8')
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

    def test_clang_format_check(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Skipping clang-format tests with {self.backend.name} backend')
        if not shutil.which('clang-format'):
            raise SkipTest('clang-format not found')

        testdir = os.path.join(self.unit_test_dir, '94 clangformat')
        newdir = os.path.join(self.builddir, 'testdir')
        shutil.copytree(testdir, newdir)
        self.new_builddir()
        self.init(newdir)

        # Should reformat 1 file but not return error
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))

        # Reset source tree then try again with clang-format-check, it should
        # return an error code this time.
        windows_proof_rmtree(newdir)
        shutil.copytree(testdir, newdir)
        with self.assertRaises(subprocess.CalledProcessError):
            output = self.build('clang-format-check')
            self.assertEqual(1, output.count('File reformatted:'))

        # The check format should not touch any files. Thus
        # running format again has some work to do.
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))
        self.build('clang-format-check')

    def test_custom_target_implicit_include(self):
        testdir = os.path.join(self.unit_test_dir, '95 custominc')
        self.init(testdir)
        self.build()
        compdb = self.get_compdb()
        matches = 0
        for c in compdb:
            if 'prog.c' in c['file']:
                self.assertNotIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)
        matches = 0
        for c in compdb:
            if 'prog2.c' in c['file']:
                self.assertIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)

    def test_env_flags_to_linker(self) -> None:
        # Compilers that act as drivers should add their compiler flags to the
        # linker, those that do not shouldn't
        with mock.patch.dict(os.environ, {'CFLAGS': '-DCFLAG', 'LDFLAGS': '-flto'}):
            env = get_fake_env()

            # Get the compiler so we know which compiler class to mock.
            cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
            cc_type = type(cc)

            # Test a compiler that acts as a linker
            with mock.patch.object(cc_type, 'INVOKES_LINKER', True):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-DCFLAG', '-flto']))

            # And one that doesn't
            with mock.patch.object(cc_type, 'INVOKES_LINKER', False):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-flto']))

    def test_install_tag(self) -> None:
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        self.init(testdir)
        self.build()

        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)

        def shared_lib_name(name):
            if cc.get_id() in {'msvc', 'clang-cl'}:
                return f'bin/{name}.dll'
            elif is_windows():
                return f'bin/lib{name}.dll'
            elif is_cygwin():
                return f'bin/cyg{name}.dll'
            elif is_osx():
                return f'lib/lib{name}.dylib'
            return f'lib/lib{name}.so'

        def exe_name(name):
            if is_windows() or is_cygwin():
                return f'{name}.exe'
            return name

        installpath = Path(self.installdir)

        expected_common = {
            installpath,
            Path(installpath, 'usr'),
        }

        expected_devel = expected_common | {
            Path(installpath, 'usr/include'),
            Path(installpath, 'usr/include/bar-devel.h'),
            Path(installpath, 'usr/include/bar2-devel.h'),
            Path(installpath, 'usr/include/foo1-devel.h'),
            Path(installpath, 'usr/include/foo2-devel.h'),
            Path(installpath, 'usr/include/foo3-devel.h'),
            Path(installpath, 'usr/include/out-devel.h'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libstatic.a'),
            Path(installpath, 'usr/lib/libboth.a'),
            Path(installpath, 'usr/lib/libboth2.a'),
            Path(installpath, 'usr/include/ct-header1.h'),
            Path(installpath, 'usr/include/ct-header3.h'),
            Path(installpath, 'usr/include/subdir-devel'),
            Path(installpath, 'usr/include/custom_files'),
            Path(installpath, 'usr/include/custom_files/data.txt'),
        }

        if cc.get_id() in {'msvc', 'clang-cl'}:
            expected_devel |= {
                Path(installpath, 'usr/bin'),
                Path(installpath, 'usr/bin/app.pdb'),
                Path(installpath, 'usr/bin/app2.pdb'),
                Path(installpath, 'usr/bin/both.pdb'),
                Path(installpath, 'usr/bin/both2.pdb'),
                Path(installpath, 'usr/bin/bothcustom.pdb'),
                Path(installpath, 'usr/bin/shared.pdb'),
                Path(installpath, 'usr/bin/versioned_shared-1.pdb'),
                Path(installpath, 'usr/lib/both.lib'),
                Path(installpath, 'usr/lib/both2.lib'),
                Path(installpath, 'usr/lib/bothcustom.lib'),
                Path(installpath, 'usr/lib/shared.lib'),
                Path(installpath, 'usr/lib/versioned_shared.lib'),
                Path(installpath, 'usr/otherbin'),
                Path(installpath, 'usr/otherbin/app-otherdir.pdb'),
            }
        elif is_windows() or is_cygwin():
            expected_devel |= {
                Path(installpath, 'usr/lib/libboth.dll.a'),
                Path(installpath, 'usr/lib/libboth2.dll.a'),
                Path(installpath, 'usr/lib/libshared.dll.a'),
                Path(installpath, 'usr/lib/libbothcustom.dll.a'),
                Path(installpath, 'usr/lib/libversioned_shared.dll.a'),
            }
        else:
            expected_devel |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared')),
            }

        expected_runtime = expected_common | {
            Path(installpath, 'usr/bin'),
            Path(installpath, 'usr/bin/' + exe_name('app')),
            Path(installpath, 'usr/otherbin'),
            Path(installpath, 'usr/otherbin/' + exe_name('app-otherdir')),
            Path(installpath, 'usr/bin/' + exe_name('app2')),
            Path(installpath, 'usr/' + shared_lib_name('shared')),
            Path(installpath, 'usr/' + shared_lib_name('both')),
            Path(installpath, 'usr/' + shared_lib_name('both2')),
        }

        if is_windows() or is_cygwin():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared-1')),
            }
        elif is_osx():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared.1')),
            }
        else:
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1'),
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1.2.3'),
            }

        expected_custom = expected_common | {
            Path(installpath, 'usr/share'),
            Path(installpath, 'usr/share/bar-custom.txt'),
            Path(installpath, 'usr/share/foo-custom.h'),
            Path(installpath, 'usr/share/out1-custom.txt'),
            Path(installpath, 'usr/share/out2-custom.txt'),
            Path(installpath, 'usr/share/out3-custom.txt'),
            Path(installpath, 'usr/share/custom_files'),
            Path(installpath, 'usr/share/custom_files/data.txt'),
            Path(installpath, 'usr/share/excludes'),
            Path(installpath, 'usr/share/excludes/installed.txt'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libbothcustom.a'),
            Path(installpath, 'usr/' + shared_lib_name('bothcustom')),
        }

        if is_windows() or is_cygwin():
            expected_custom |= {Path(installpath, 'usr/bin')}
        else:
            expected_runtime |= {Path(installpath, 'usr/lib')}

        expected_runtime_custom = expected_runtime | expected_custom

        expected_all = expected_devel | expected_runtime | expected_custom | {
            Path(installpath, 'usr/share/foo-notag.h'),
            Path(installpath, 'usr/share/bar-notag.txt'),
            Path(installpath, 'usr/share/out1-notag.txt'),
            Path(installpath, 'usr/share/out2-notag.txt'),
            Path(installpath, 'usr/share/out3-notag.txt'),
            Path(installpath, 'usr/share/foo2.h'),
            Path(installpath, 'usr/share/out1.txt'),
            Path(installpath, 'usr/share/out2.txt'),
            Path(installpath, 'usr/share/subproject'),
            Path(installpath, 'usr/share/subproject/aaa.txt'),
            Path(installpath, 'usr/share/subproject/bbb.txt'),
        }

        def do_install(tags, expected_files, expected_scripts):
            cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
            cmd += ['--tags', tags] if tags else []
            stdout = self._run(cmd, workdir=self.builddir)
            installed = self.read_install_logs()
            self.assertEqual(sorted(expected_files), sorted(installed))
            self.assertEqual(expected_scripts, stdout.count('Running custom install script'))

        do_install('devel', expected_devel, 0)
        do_install('runtime', expected_runtime, 0)
        do_install('custom', expected_custom, 1)
        do_install('runtime,custom', expected_runtime_custom, 1)
        do_install(None, expected_all, 2)


    def test_install_script_dry_run(self):
        testdir = os.path.join(self.common_test_dir, '53 install script')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
        outputs = self._run(cmd, workdir=self.builddir)

        installpath = Path(self.installdir)
        self.assertFalse((installpath / 'usr/diiba/daaba/file.dat').exists())
        self.assertIn("DRYRUN: Writing file file.dat", outputs)


    def test_introspect_install_plan(self):
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-install_plan.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res = json.load(fp)

        env = get_fake_env(testdir, self.builddir, self.prefix)

        def output_name(name, type_):
            target = type_(name=name, subdir=None, subproject=None,
                           for_machine=MachineChoice.HOST, sources=[],
                           structured_sources=None,
                           objects=[], environment=env, compilers=env.coredata.compilers[MachineChoice.HOST],
                           build_only_subproject=False, kwargs={})
            target.process_compilers_late()
            return target.filename

        shared_lib_name = lambda name: output_name(name, SharedLibrary)
        static_lib_name = lambda name: output_name(name, StaticLibrary)
        exe_name = lambda name: output_name(name, Executable)

        expected = {
            'targets': {
                f'{self.builddir}/out1-notag.txt': {
                    'destination': '{datadir}/out1-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out2-notag.txt': {
                    'destination': '{datadir}/out2-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/libstatic.a': {
                    'destination': '{libdir_static}/libstatic.a',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app'): {
                    'destination': '{bindir}/' + exe_name('app'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app-otherdir'): {
                    'destination': '{prefix}/otherbin/' + exe_name('app-otherdir'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + exe_name('app2'): {
                    'destination': '{bindir}/' + exe_name('app2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('shared'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('shared'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('both'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('both'): {
                    'destination': '{libdir_static}/' + static_lib_name('both'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('bothcustom'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('bothcustom'): {
                    'destination': '{libdir_static}/' + static_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + shared_lib_name('both2'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + static_lib_name('both2'): {
                    'destination': '{libdir_static}/' + static_lib_name('both2'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out1-custom.txt': {
                    'destination': '{datadir}/out1-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out2-custom.txt': {
                    'destination': '{datadir}/out2-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out3-custom.txt': {
                    'destination': '{datadir}/out3-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out1.txt': {
                    'destination': '{datadir}/out1.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out2.txt': {
                    'destination': '{datadir}/out2.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out-devel.h': {
                    'destination': '{includedir}/out-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out3-notag.txt': {
                    'destination': '{datadir}/out3-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
            },
            'configure': {
                f'{self.builddir}/foo-notag.h': {
                    'destination': '{datadir}/foo-notag.h',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/foo2-devel.h': {
                    'destination': '{includedir}/foo2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/foo-custom.h': {
                    'destination': '{datadir}/foo-custom.h',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/foo2.h': {
                    'destination': '{datadir}/foo2.h',
                    'tag': None,
                    'subproject': None,
                },
            },
            'data': {
                f'{testdir}/bar-notag.txt': {
                    'destination': '{datadir}/bar-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{testdir}/bar-devel.h': {
                    'destination': '{includedir}/bar-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/bar-custom.txt': {
                    'destination': '{datadir}/bar-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{testdir}/subdir/bar2-devel.h': {
                    'destination': '{includedir}/bar2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subprojects/subproject/aaa.txt': {
                    'destination': '{datadir}/subproject/aaa.txt',
                    'tag': None,
                    'subproject': 'subproject',
                },
                f'{testdir}/subprojects/subproject/bbb.txt': {
                    'destination': '{datadir}/subproject/bbb.txt',
                    'tag': 'data',
                    'subproject': 'subproject',
                },
            },
            'headers': {
                f'{testdir}/foo1-devel.h': {
                    'destination': '{includedir}/foo1-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subdir/foo3-devel.h': {
                    'destination': '{includedir}/foo3-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
            },
            'install_subdirs': {
                f'{testdir}/custom_files': {
                    'destination': '{datadir}/custom_files',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': [],
                    'exclude_files': [],
                },
                f'{testdir}/excludes': {
                    'destination': '{datadir}/excludes',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': ['excluded'],
                    'exclude_files': ['excluded.txt'],
                }
            }
        }

        fix_path = lambda path: os.path.sep.join(path.split('/'))
        expected_fixed = {
            data_type: {
                fix_path(source): {
                    key: fix_path(value) if key == 'destination' else value
                    for key, value in attributes.items()
                }
                for source, attributes in files.items()
            }
            for data_type, files in expected.items()
        }

        for data_type, files in expected_fixed.items():
            for file, details in files.items():
                with self.subTest(key='{}.{}'.format(data_type, file)):
                    self.assertEqual(res[data_type][file], details)

    @skip_if_not_language('rust')
    @unittest.skipIf(not shutil.which('clippy-driver'), 'Test requires clippy-driver')
    def test_rust_clippy(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        # When clippy is used, we should get an exception since a variable named
        # "foo" is used, but is on our denylist
        testdir = os.path.join(self.rust_test_dir, '1 basic')
        self.init(testdir, extra_args=['--werror'], override_envvars={'RUSTC': 'clippy-driver'})
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.build()
        self.assertTrue('error: use of a blacklisted/placeholder name `foo`' in cm.exception.stdout or
                        'error: use of a disallowed/placeholder name `foo`' in cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_rust_rlib_linkage(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        template = textwrap.dedent('''\
                use std::process::exit;

                pub fn fun() {{
                    exit({});
                }}
            ''')

        testdir = os.path.join(self.unit_test_dir, '102 rlib linkage')
        gen_file = os.path.join(testdir, 'lib.rs')
        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(0))
        self.addCleanup(windows_proof_rm, gen_file)

        self.init(testdir)
        self.build()
        self.run_tests()

        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(39))

        self.build()
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.run_tests()
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn('exit status 39', cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_bindgen_drops_invalid(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        testdir = os.path.join(self.rust_test_dir, '12 bindgen')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        # bindgen understands compiler args that clang understands, but not
        # flags by other compilers
        if cc.get_id() == 'gcc':
            bad_arg = '-fdse'
        elif cc.get_id() == 'msvc':
            bad_arg = '/fastfail'
        else:
            raise unittest.SkipTest('Test only supports GCC and MSVC')
        self.init(testdir, extra_args=[f"-Dc_args=['-DCMD_ARG', '{bad_arg}']"])
        intro = self.introspect(['--targets'])
        for i in intro:
            if i['type'] == 'custom' and i['id'].startswith('rustmod-bindgen'):
                args = i['target_sources'][0]['compiler']
                self.assertIn('-DCMD_ARG', args)
                self.assertIn('-DPROJECT_ARG', args)
                self.assertIn('-DGLOBAL_ARG', args)
                self.assertNotIn(bad_arg, args)
                self.assertNotIn('-mtls-dialect=gnu2', args)
                self.assertNotIn('/fp:fast', args)
                return

    def test_custom_target_name(self):
        testdir = os.path.join(self.unit_test_dir, '100 custom target name')
        self.init(testdir)
        out = self.build()
        if self.backend is Backend.ninja:
            self.assertIn('Generating file.txt with a custom command', out)
            self.assertIn('Generating subdir/file.txt with a custom command', out)

    def test_symlinked_subproject(self):
        testdir = os.path.join(self.unit_test_dir, '107 subproject symlink')
        subproject_dir = os.path.join(testdir, 'subprojects')
        subproject = os.path.join(testdir, 'symlinked_subproject')
        symlinked_subproject = os.path.join(testdir, 'subprojects', 'symlinked_subproject')
        if not os.path.exists(subproject_dir):
            os.mkdir(subproject_dir)
        try:
            os.symlink(subproject, symlinked_subproject)
        except OSError:
            raise SkipTest("Symlinks are not available on this machine")
        self.addCleanup(os.remove, symlinked_subproject)

        self.init(testdir)
        self.build()

    def test_configure_same_noop(self):
        testdir = os.path.join(self.unit_test_dir, '109 configure same noop')
        args = [
            '-Dstring=val',
            '-Dboolean=true',
            '-Dcombo=two',
            '-Dinteger=7',
            '-Darray=[\'three\']',
            '-Dfeature=disabled',
            '--buildtype=plain',
            '--prefix=/abc',
        ]
        self.init(testdir, extra_args=args)

        filename = Path(self.privatedir) / 'coredata.dat'

        olddata = filename.read_bytes()
        oldmtime = os.path.getmtime(filename)

        for opt in ('-Dstring=val', '--buildtype=plain', '-Dfeature=disabled', '-Dprefix=/abc'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertEqual(oldmtime, newmtime)
            self.assertEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

        for opt in ('-Dstring=abc', '--buildtype=release', '-Dfeature=enabled', '-Dprefix=/def'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertGreater(newmtime, oldmtime)
            self.assertNotEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

    def test_c_cpp_stds(self):
        testdir = os.path.join(self.unit_test_dir, '115 c cpp stds')
        self.init(testdir)
        # Invalid values should fail whatever compiler we have
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c89,invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c++11')
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'msvc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'c89')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
            # This is deprecated but works for C
            self.setconf('-Dc_std=gnu99')
            self.assertEqual(self.getconf('c_std'), 'c99')
            # C++ however never accepted that fallback
            with self.assertRaises(subprocess.CalledProcessError):
                self.setconf('-Dcpp_std=gnu++11')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=gnu++11,vc++11,c++11')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
        elif cc.get_id() == 'gcc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'gnu89')
            self.assertEqual(self.getconf('cpp_std'), 'gnu++98')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=c++11,gnu++11,vc++11')
            self.assertEqual(self.getconf('cpp_std'), 'c++11')
```