Response:
The user wants to understand the functionality of the provided Python code snippet, which is a part of the `ninjabackend.py` file in the Frida dynamic instrumentation tool. I need to go through the code and identify its core functionalities, especially concerning:

1. **Relationship to reverse engineering:**  How does this code contribute to the process of analyzing and understanding compiled programs?
2. **Low-level system knowledge:** Does the code interact with binary formats, Linux/Android kernels, or frameworks?
3. **Logical reasoning:** Are there any conditional statements or algorithms that imply a specific input leading to a predictable output?
4. **Common user errors:**  What mistakes could a user make that might lead them to this part of the code?
5. **User operation flow:** How does a user's action eventually trigger the execution of this code?
6. **Summary of functions:** Provide a concise overview of what the code does.

Let's break down the code section by section:

*   **`generate_link` function:** This function seems responsible for constructing the command-line arguments for the linking stage of the build process. It handles different types of targets (static libraries, shared libraries, modules), linker options, dependencies, and output file names.
*   **`get_dependency_filename` function:** This helper function determines the filename of a dependency based on its type.
*   **`generate_shlib_aliases` function:** This function creates symbolic links (aliases) for shared libraries, often used for versioning.
*   **`generate_custom_target_clean` function:** This function creates a target to clean up the output directories of custom build targets.
*   **`generate_gcov_clean` function:** This function creates targets to remove `.gcno` and `.gcda` files, which are used for code coverage analysis.
*   **`get_user_option_args` function:** This function retrieves user-defined options for the build.
*   **`generate_dist` function:** This function creates a target for generating source distribution packages.
*   **`generate_scanbuild` function:** This function integrates with `scan-build`, a static analysis tool.
*   **`generate_clangtool` function:** This is a helper function to integrate with Clang tools like `clang-format` and `clang-tidy`.
*   **`generate_clangformat` function:** This function creates targets for running `clang-format` for code formatting.
*   **`generate_clangtidy` function:** This function creates targets for running `clang-tidy` for static code analysis.
*   **`generate_tags` function:** This function creates targets for generating code tags using tools like `etags`, `ctags`, and `cscope`.
*   **`generate_utils` function:** This function groups together various utility targets.
*   **`generate_ending` function:** This function creates final targets like `all`, `clean`, `reconfigure`, and handles implicit outputs.
*   **`get_introspection_data` function:** This function retrieves introspection data for a specific target.
*   **`_scan_fortran_file_deps` function:** This function scans Fortran files for dependencies.

Now I can organize these functionalities and address the user's specific questions.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/ninjabackend.py` 文件的最后一部分代码。延续之前的分析，这部分代码主要负责生成 Ninja 构建系统所需的各种构建规则和目标，以完成整个构建过程。

以下是这部分代码的功能及其与逆向、底层知识、逻辑推理和用户错误的关联：

**功能列表：**

1. **`generate_shlib_aliases(self, target, outdir)`:**
    *   为共享库创建别名（符号链接）。这对于共享库的版本控制非常重要，允许在不破坏依赖关系的情况下更新库。

2. **`generate_custom_target_clean(self, trees: T.List[str]) -> str`:**
    *   生成一个用于清理自定义构建目标输出的 Ninja 目标。由于 Ninja 默认不清理非空目录，此功能用于确保自定义目标创建的目录也能被清理。

3. **`generate_gcov_clean(self) -> None`:**
    *   生成用于清理代码覆盖率工具 `gcov` 生成的 `.gcno` 和 `.gcda` 文件的 Ninja 目标。

4. **`get_user_option_args(self)`:**
    *   获取用户通过命令行传递的 Meson 配置选项，并将其格式化为字符串列表。

5. **`generate_dist(self) -> None`:**
    *   生成一个用于创建源代码分发包的 Ninja 目标。

6. **`generate_scanbuild(self) -> None`:**
    *   集成静态代码分析工具 `scan-build`。生成一个 Ninja 目标来运行 `scan-build` 并分析代码。

7. **`generate_clangtool(self, name: str, extra_arg: T.Optional[str] = None) -> None`:**
    *   一个辅助函数，用于生成与 Clang 工具链相关的 Ninja 目标，例如 `clang-format` 和 `clang-tidy`。

8. **`generate_clangformat(self) -> None`:**
    *   生成用于运行 `clang-format` 进行代码格式化的 Ninja 目标。

9. **`generate_clangtidy(self) -> None`:**
    *   生成用于运行 `clang-tidy` 进行静态代码分析的 Ninja 目标。

10. **`generate_tags(self, tool: str, target_name: str) -> None`:**
    *   生成用于创建代码标签（用于代码导航）的 Ninja 目标，支持 `etags`, `ctags`, `cscope` 等工具。

11. **`generate_utils(self) -> None`:**
    *   组合生成各种实用工具相关的 Ninja 目标，例如代码分析、代码格式化和卸载目标。

12. **`generate_ending(self) -> None`:**
    *   生成构建过程的最后阶段所需的 Ninja 目标：
        *   `all`:  默认构建目标，依赖于所有需要构建的目标。
        *   `meson-test-prereq`, `meson-benchmark-prereq`:  测试和基准测试的先决条件目标。
        *   `clean`: 清理构建产物的目标。
        *   `build.ninja`: 重新生成 `build.ninja` 文件的目标。
        *   `meson-implicit-outs`:  处理隐式输出文件的目标。
        *   `reconfigure`: 重新运行 Meson 配置的目标。

13. **`get_introspection_data(self, target_id: str, target: build.Target)`:**
    *   获取特定构建目标的内省数据，用于提供构建过程的详细信息。

14. **`_scan_fortran_file_deps(src: Path, srcdir: Path, dirname: Path, tdeps, compiler) -> T.List[str]`:**
    *   一个用于扫描 Fortran 源代码文件以查找依赖关系的辅助函数，包括 `include` 语句、`use` 模块和 `submodule` 声明。

**与逆向方法的关联：**

*   **符号链接 (`generate_shlib_aliases`)：** 在逆向工程中，理解共享库的版本控制和符号链接对于分析程序如何加载和使用库至关重要。错误的符号链接可能导致程序加载错误的库版本。
*   **静态分析工具集成 (`generate_scanbuild`, `generate_clangtidy`)：** 这些工具可以帮助在编译前发现潜在的安全漏洞和代码缺陷，这对于理解目标程序的行为和识别潜在的攻击面很有帮助。逆向工程师可能会利用这些工具来理解他们正在分析的代码库的质量和潜在问题。
*   **代码标签生成 (`generate_tags`)：**  在大型代码库中进行逆向分析时，代码标签可以极大地提高导航效率，帮助理解函数调用关系和数据结构。

**举例说明：**

*   **`generate_shlib_aliases`:** 当逆向分析一个使用了特定版本共享库的程序时，可以通过查看构建系统中生成的符号链接，了解程序运行时实际链接的是哪个版本的库文件。
*   **`generate_scanbuild`:**  如果逆向分析的目标程序在构建过程中使用了 `scan-build`，那么可以查看 `scan-build` 的输出报告，了解程序可能存在的内存泄漏、空指针解引用等问题，这些问题可能在逆向分析中被利用或需要特别关注。

**涉及二进制底层，Linux, Android 内核及框架的知识：**

*   **链接过程 (`generate_link`)：** 代码中大量涉及链接器的参数和行为，这直接关系到最终生成的可执行文件和库文件的二进制结构。理解这些参数，例如 `-rpath`（运行时库路径）、`-soname`（共享库名称），对于理解程序如何在运行时加载依赖至关重要。
*   **共享库和符号 (`generate_shlib_aliases`)：**  共享库的加载和符号解析是操作系统底层的概念。理解符号链接如何影响库的加载路径和符号查找是分析动态链接程序的基础。
*   **清理操作 (`generate_custom_target_clean`)：** 理解文件系统操作和构建系统如何管理构建产物对于避免构建过程中的冲突和错误非常重要。在嵌入式系统（如 Android）开发中，清理操作尤其重要，因为资源有限。
*   **代码覆盖率 (`generate_gcov_clean`)：** 代码覆盖率分析可以帮助了解程序执行了哪些代码路径，这在测试和逆向分析中都很有用。理解 `.gcno` 和 `.gcda` 文件的作用可以帮助逆向工程师重现程序的执行路径。

**举例说明：**

*   **`generate_link`:** 在分析一个 Linux 可执行文件时，可能会检查其 `.dynamic` section，其中包含了运行时链接器需要的信息，例如 `RPATH` 或 `RUNPATH`。这些信息与 `generate_link` 函数中设置的链接器参数密切相关。
*   **`generate_shlib_aliases`:**  在 Android 系统中，共享库的命名和版本控制遵循一定的规则。理解构建系统如何生成这些别名可以帮助理解 Android 框架中不同组件之间的依赖关系。

**逻辑推理：**

*   **依赖关系 (`generate_ending`)：**  `generate_ending` 函数中，构建目标 `all` 依赖于其他所有需要构建的目标。这是一个逻辑上的依赖关系，确保在构建所有内容之前，其依赖项已经被构建。
*   **条件编译 (`get_user_option_args`)：** 用户通过命令行传递的选项会影响构建过程，例如是否启用调试符号、优化级别等。代码需要根据这些选项来生成不同的构建规则。
*   **工具存在性检查 (`generate_scanbuild`, `generate_clangformat` 等)：** 代码中会检查相关工具是否存在于系统中，只有在工具存在的情况下才会生成相应的构建目标。

**假设输入与输出：**

*   **假设输入：** 用户在运行 Meson 配置时，设置了 `-Db_coverage=true`。
*   **输出：** `generate_ending` 函数会检测到这个选项，并调用 `generate_gcov_clean` 函数生成清理 `.gcno` 和 `.gcda` 文件的 Ninja 目标，并且 `clean` 目标会依赖于 `clean-gcda` 和 `clean-gcno`。

**涉及用户或编程常见的使用错误：**

*   **依赖缺失：** 如果用户修改了构建脚本，导致某些依赖关系没有正确声明，`generate_link` 函数生成的链接命令可能缺少必要的库，导致链接失败。
*   **工具未安装：** 如果用户尝试使用 `scan-build` 或 `clang-format` 等工具，但这些工具没有安装在系统中，相应的构建目标将不会被生成或执行时会报错。
*   **自定义目标清理问题：** 用户自定义的构建目标如果生成了目录，并且在清理时遇到问题（例如目录非空），`generate_custom_target_clean` 函数生成的清理目标可以解决这个问题，但前提是用户正确使用了自定义目标功能。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户执行 `meson setup` 命令：**  用户首先需要运行 `meson setup <build_directory>` 来配置构建系统。Meson 会读取 `meson.build` 文件并生成内部的构建描述。
2. **Meson 解析构建定义：** Meson 在解析 `meson.build` 文件时，会创建各种构建目标（例如可执行文件、库文件、自定义目标）。
3. **Backend 选择：** Meson 根据配置选择一个后端来生成实际的构建文件，例如 Ninja。
4. **调用 `NinjaBackend`：** 对于 Ninja 后端，Meson 会实例化 `ninjabackend.py` 中的 `NinjaBackend` 类。
5. **生成构建规则：** `NinjaBackend` 类会遍历所有定义的构建目标，并调用相应的方法（例如 `generate_link`, `generate_shlib_aliases` 等）来生成 Ninja 的构建规则。
6. **执行到 `generate_ending`：**  `generate_ending` 方法通常在构建过程的最后阶段被调用，用于生成一些收尾的构建目标，例如默认的 `all` 目标和 `clean` 目标。

**作为调试线索：** 如果用户在构建过程中遇到问题，例如链接错误或清理失败，可以检查 `build.ninja` 文件中由这些函数生成的具体命令和依赖关系，从而定位问题所在。例如，如果链接器报错找不到某个库，可以检查 `generate_link` 函数是否正确添加了该库的路径和链接参数。

**归纳一下它的功能：**

这部分 `ninjabackend.py` 代码的主要功能是**生成 Ninja 构建系统的最后阶段所需的构建规则和目标**，包括共享库别名、自定义目标清理、代码覆盖率清理、分发包生成、静态代码分析工具集成、代码标签生成以及最终的 `all` 和 `clean` 目标。它负责将 Meson 的高层构建描述转换为 Ninja 可以理解的底层指令，以完成整个软件的构建过程。它涉及到与操作系统底层、编译链接过程以及各种开发工具的集成。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
[:]
        cmd += prelinker.get_prelink_args(prelink_name, obj_list)

        cmd = self.replace_paths(target, cmd)
        elem.add_item('COMMAND', cmd)
        elem.add_item('description', f'Prelinking {prelink_name}.')
        self.add_build(elem)
        return [prelink_name]

    def generate_link(self, target: build.BuildTarget, outname, obj_list, linker: T.Union['Compiler', 'StaticLinker'], extra_args=None, stdlib_args=None):
        extra_args = extra_args if extra_args is not None else []
        stdlib_args = stdlib_args if stdlib_args is not None else []
        implicit_outs = []
        if isinstance(target, build.StaticLibrary):
            linker_base = 'STATIC'
        else:
            linker_base = linker.get_language() # Fixme.
        if isinstance(target, build.SharedLibrary):
            self.generate_shsym(target)
        crstr = self.get_rule_suffix(target.for_machine)
        linker_rule = linker_base + '_LINKER' + crstr
        # Create an empty commands list, and start adding link arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        #
        # Once all the linker options have been passed, we will start passing
        # libraries and library paths from internal and external sources.
        commands = linker.compiler_args()
        # First, the trivial ones that are impossible to override.
        #
        # Add linker args for linking this target derived from 'base' build
        # options passed on the command-line, in default_options, etc.
        # These have the lowest priority.
        if isinstance(target, build.StaticLibrary):
            commands += linker.get_base_link_args(target.get_options())
        else:
            commands += compilers.get_base_link_args(target.get_options(),
                                                     linker,
                                                     isinstance(target, build.SharedModule),
                                                     self.environment.get_build_dir())
        # Add -nostdlib if needed; can't be overridden
        commands += self.get_no_stdlib_link_args(target, linker)
        # Add things like /NOLOGO; usually can't be overridden
        commands += linker.get_linker_always_args()
        # Add buildtype linker args: optimization level, etc.
        commands += linker.get_optimization_link_args(target.get_option(OptionKey('optimization')))
        # Add /DEBUG and the pdb filename when using MSVC
        if target.get_option(OptionKey('debug')):
            commands += self.get_link_debugfile_args(linker, target)
            debugfile = self.get_link_debugfile_name(linker, target)
            if debugfile is not None:
                implicit_outs += [debugfile]
        # Add link args specific to this BuildTarget type, such as soname args,
        # PIC, import library generation, etc.
        commands += self.get_target_type_link_args(target, linker)
        # Archives that are copied wholesale in the result. Must be before any
        # other link targets so missing symbols from whole archives are found in those.
        if not isinstance(target, build.StaticLibrary):
            commands += self.get_link_whole_args(linker, target)

        if not isinstance(target, build.StaticLibrary):
            # Add link args added using add_project_link_arguments()
            commands += self.build.get_project_link_args(linker, target.subproject, target.for_machine)
            # Add link args added using add_global_link_arguments()
            # These override per-project link arguments
            commands += self.build.get_global_link_args(linker, target.for_machine)
            # Link args added from the env: LDFLAGS. We want these to override
            # all the defaults but not the per-target link args.
            commands += self.environment.coredata.get_external_link_args(target.for_machine, linker.get_language())

        # Now we will add libraries and library paths from various sources

        # Set runtime-paths so we can run executables without needing to set
        # LD_LIBRARY_PATH, etc in the environment. Doesn't work on Windows.
        if has_path_sep(target.name):
            # Target names really should not have slashes in them, but
            # unfortunately we did not check for that and some downstream projects
            # now have them. Once slashes are forbidden, remove this bit.
            target_slashname_workaround_dir = os.path.join(
                os.path.dirname(target.name),
                self.get_target_dir(target))
        else:
            target_slashname_workaround_dir = self.get_target_dir(target)
        (rpath_args, target.rpath_dirs_to_remove) = (
            linker.build_rpath_args(self.environment,
                                    self.environment.get_build_dir(),
                                    target_slashname_workaround_dir,
                                    self.determine_rpath_dirs(target),
                                    target.build_rpath,
                                    target.install_rpath))
        commands += rpath_args

        # Add link args to link to all internal libraries (link_with:) and
        # internal dependencies needed by this target.
        if linker_base == 'STATIC':
            # Link arguments of static libraries are not put in the command
            # line of the library. They are instead appended to the command
            # line where the static library is used.
            dependencies = []
        else:
            dependencies = target.get_dependencies()
        internal = self.build_target_link_arguments(linker, dependencies)
        commands += internal
        # Only non-static built targets need link args and link dependencies
        if not isinstance(target, build.StaticLibrary):
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`

            commands += linker.get_target_link_args(target)
            # External deps must be last because target link libraries may depend on them.
            for dep in target.get_external_deps():
                # Extend without reordering or de-dup to preserve `-L -l` sets
                # https://github.com/mesonbuild/meson/issues/1718
                commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))
            for d in target.get_dependencies():
                if isinstance(d, build.StaticLibrary):
                    for dep in d.get_external_deps():
                        commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))

        # Add link args specific to this BuildTarget type that must not be overridden by dependencies
        commands += self.get_target_type_link_args_post_dependencies(target, linker)

        # Add link args for c_* or cpp_* build options. Currently this only
        # adds c_winlibs and cpp_winlibs when building for Windows. This needs
        # to be after all internal and external libraries so that unresolved
        # symbols from those can be found here. This is needed when the
        # *_winlibs that we want to link to are static mingw64 libraries.
        if isinstance(linker, Compiler):
            # The static linker doesn't know what language it is building, so we
            # don't know what option. Fortunately, it doesn't care to see the
            # language-specific options either.
            #
            # We shouldn't check whether we are making a static library, because
            # in the LTO case we do use a real compiler here.
            commands += linker.get_option_link_args(target.get_options())

        dep_targets = []
        dep_targets.extend(self.guess_external_link_dependencies(linker, target, commands, internal))

        # Add libraries generated by custom targets
        custom_target_libraries = self.get_custom_target_provided_libraries(target)
        commands += extra_args
        commands += custom_target_libraries
        commands += stdlib_args # Standard library arguments go last, because they never depend on anything.
        dep_targets.extend([self.get_dependency_filename(t) for t in dependencies])
        dep_targets.extend([self.get_dependency_filename(t)
                            for t in target.link_depends])
        elem = NinjaBuildElement(self.all_outputs, outname, linker_rule, obj_list, implicit_outs=implicit_outs)
        elem.add_dep(dep_targets + custom_target_libraries)
        elem.add_item('LINK_ARGS', commands)
        self.create_target_linker_introspection(target, linker, commands)
        return elem

    def get_dependency_filename(self, t):
        if isinstance(t, build.SharedLibrary):
            return self.get_target_shsym_filename(t)
        elif isinstance(t, mesonlib.File):
            if t.is_built:
                return t.relative_name()
            else:
                return t.absolute_path(self.environment.get_source_dir(),
                                       self.environment.get_build_dir())
        return self.get_target_filename(t)

    def generate_shlib_aliases(self, target, outdir):
        for alias, to, tag in target.get_aliases():
            aliasfile = os.path.join(outdir, alias)
            abs_aliasfile = os.path.join(self.environment.get_build_dir(), outdir, alias)
            try:
                os.remove(abs_aliasfile)
            except Exception:
                pass
            try:
                os.symlink(to, abs_aliasfile)
            except NotImplementedError:
                mlog.debug("Library versioning disabled because symlinks are not supported.")
            except OSError:
                mlog.debug("Library versioning disabled because we do not have symlink creation privileges.")
            else:
                self.implicit_meson_outs.append(aliasfile)

    def generate_custom_target_clean(self, trees: T.List[str]) -> str:
        e = self.create_phony_target('clean-ctlist', 'CUSTOM_COMMAND', 'PHONY')
        d = CleanTrees(self.environment.get_build_dir(), trees)
        d_file = os.path.join(self.environment.get_scratch_dir(), 'cleantrees.dat')
        e.add_item('COMMAND', self.environment.get_build_command() + ['--internal', 'cleantrees', d_file])
        e.add_item('description', 'Cleaning custom target directories')
        self.add_build(e)
        # Write out the data file passed to the script
        with open(d_file, 'wb') as ofile:
            pickle.dump(d, ofile)
        return 'clean-ctlist'

    def generate_gcov_clean(self) -> None:
        gcno_elem = self.create_phony_target('clean-gcno', 'CUSTOM_COMMAND', 'PHONY')
        gcno_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcno'])
        gcno_elem.add_item('description', 'Deleting gcno files')
        self.add_build(gcno_elem)

        gcda_elem = self.create_phony_target('clean-gcda', 'CUSTOM_COMMAND', 'PHONY')
        gcda_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcda'])
        gcda_elem.add_item('description', 'Deleting gcda files')
        self.add_build(gcda_elem)

    def get_user_option_args(self):
        cmds = []
        for (k, v) in self.environment.coredata.options.items():
            if k.is_project():
                cmds.append('-D' + str(k) + '=' + (v.value if isinstance(v.value, str) else str(v.value).lower()))
        # The order of these arguments must be the same between runs of Meson
        # to ensure reproducible output. The order we pass them shouldn't
        # affect behavior in any other way.
        return sorted(cmds)

    def generate_dist(self) -> None:
        elem = self.create_phony_target('dist', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('DESC', 'Creating source packages')
        elem.add_item('COMMAND', self.environment.get_build_command() + ['dist'])
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_scanbuild(self) -> None:
        if not environment.detect_scanbuild():
            return
        if 'scan-build' in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'scanbuild', self.environment.source_dir, self.environment.build_dir, self.build.get_subproject_dir()] + \
            self.environment.get_build_command() + ['setup'] + self.get_user_option_args()
        elem = self.create_phony_target('scan-build', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangtool(self, name: str, extra_arg: T.Optional[str] = None) -> None:
        target_name = 'clang-' + name
        extra_args = []
        if extra_arg:
            target_name += f'-{extra_arg}'
            extra_args.append(f'--{extra_arg}')
        if not os.path.exists(os.path.join(self.environment.source_dir, '.clang-' + name)) and \
                not os.path.exists(os.path.join(self.environment.source_dir, '_clang-' + name)):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'clang' + name, self.environment.source_dir, self.environment.build_dir] + \
            extra_args
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangformat(self) -> None:
        if not environment.detect_clangformat():
            return
        self.generate_clangtool('format')
        self.generate_clangtool('format', 'check')

    def generate_clangtidy(self) -> None:
        import shutil
        if not shutil.which('clang-tidy'):
            return
        self.generate_clangtool('tidy')
        self.generate_clangtool('tidy', 'fix')

    def generate_tags(self, tool: str, target_name: str) -> None:
        import shutil
        if not shutil.which(tool):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'tags', tool, self.environment.source_dir]
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    # For things like scan-build and other helper tools we might have.
    def generate_utils(self) -> None:
        self.generate_scanbuild()
        self.generate_clangformat()
        self.generate_clangtidy()
        self.generate_tags('etags', 'TAGS')
        self.generate_tags('ctags', 'ctags')
        self.generate_tags('cscope', 'cscope')
        cmd = self.environment.get_build_command() + ['--internal', 'uninstall']
        elem = self.create_phony_target('uninstall', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_ending(self) -> None:
        for targ, deps in [
                ('all', self.get_build_by_default_targets()),
                ('meson-test-prereq', self.get_testlike_targets()),
                ('meson-benchmark-prereq', self.get_testlike_targets(True))]:
            targetlist = []
            # These must also be built by default.
            # XXX: Sometime in the future these should be built only before running tests.
            if targ == 'all':
                targetlist.extend(['meson-test-prereq', 'meson-benchmark-prereq'])
            for t in deps.values():
                # Add the first output of each target to the 'all' target so that
                # they are all built
                #Add archive file if shared library in AIX for build all.
                if isinstance(t, build.SharedLibrary) and t.aix_so_archive:
                    if self.environment.machines[t.for_machine].is_aix():
                        linker, stdlib_args = self.determine_linker_and_stdlib_args(t)
                        t.get_outputs()[0] = linker.get_archive_name(t.get_outputs()[0])
                targetlist.append(os.path.join(self.get_target_dir(t), t.get_outputs()[0]))

            elem = NinjaBuildElement(self.all_outputs, targ, 'phony', targetlist)
            self.add_build(elem)

        elem = self.create_phony_target('clean', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', self.ninja_command + ['-t', 'clean'])
        elem.add_item('description', 'Cleaning')

        # If we have custom targets in this project, add all their outputs to
        # the list that is passed to the `cleantrees.py` script. The script
        # will manually delete all custom_target outputs that are directories
        # instead of files. This is needed because on platforms other than
        # Windows, Ninja only deletes directories while cleaning if they are
        # empty. https://github.com/mesonbuild/meson/issues/1220
        ctlist = []
        for t in self.build.get_targets().values():
            if isinstance(t, build.CustomTarget):
                # Create a list of all custom target outputs
                for o in t.get_outputs():
                    ctlist.append(os.path.join(self.get_target_dir(t), o))
        if ctlist:
            elem.add_dep(self.generate_custom_target_clean(ctlist))

        if OptionKey('b_coverage') in self.environment.coredata.options and \
           self.environment.coredata.options[OptionKey('b_coverage')].value:
            self.generate_gcov_clean()
            elem.add_dep('clean-gcda')
            elem.add_dep('clean-gcno')
        self.add_build(elem)

        deps = self.get_regen_filelist()
        elem = NinjaBuildElement(self.all_outputs, 'build.ninja', 'REGENERATE_BUILD', deps)
        elem.add_item('pool', 'console')
        self.add_build(elem)

        # If these files used to be explicitly created, they need to appear on the build graph somehow,
        # otherwise cleandead deletes them. See https://github.com/ninja-build/ninja/issues/2299
        if self.implicit_meson_outs:
            elem = NinjaBuildElement(self.all_outputs, 'meson-implicit-outs', 'phony', self.implicit_meson_outs)
            self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, 'reconfigure', 'REGENERATE_BUILD', 'PHONY')
        elem.add_item('pool', 'console')
        self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, deps, 'phony', '')
        self.add_build(elem)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List[T.Dict[str, T.Union[bool, str, T.List[T.Union[str, T.Dict[str, T.Union[str, T.List[str], bool]]]]]]]:
        data = self.introspection_data.get(target_id)
        if not data:
            return super().get_introspection_data(target_id, target)

        return list(data.values())


def _scan_fortran_file_deps(src: Path, srcdir: Path, dirname: Path, tdeps, compiler) -> T.List[str]:
    """
    scan a Fortran file for dependencies. Needs to be distinct from target
    to allow for recursion induced by `include` statements.er

    It makes a number of assumptions, including

    * `use`, `module`, `submodule` name is not on a continuation line

    Regex
    -----

    * `incre` works for `#include "foo.f90"` and `include "foo.f90"`
    * `usere` works for legacy and Fortran 2003 `use` statements
    * `submodre` is for Fortran >= 2008 `submodule`
    """

    incre = re.compile(FORTRAN_INCLUDE_PAT, re.IGNORECASE)
    usere = re.compile(FORTRAN_USE_PAT, re.IGNORECASE)
    submodre = re.compile(FORTRAN_SUBMOD_PAT, re.IGNORECASE)

    mod_files = []
    src = Path(src)
    with src.open(encoding='ascii', errors='ignore') as f:
        for line in f:
            # included files
            incmatch = incre.match(line)
            if incmatch is not None:
                incfile = src.parent / incmatch.group(1)
                # NOTE: src.parent is most general, in particular for CMake subproject with Fortran file
                # having an `include 'foo.f'` statement.
                if incfile.suffix.lower()[1:] in compiler.file_suffixes:
                    mod_files.extend(_scan_fortran_file_deps(incfile, srcdir, dirname, tdeps, compiler))
            # modules
            usematch = usere.match(line)
            if usematch is not None:
                usename = usematch.group(1).lower()
                if usename == 'intrinsic':  # this keeps the regex simpler
                    continue
                if usename not in tdeps:
                    # The module is not provided by any source file. This
                    # is due to:
                    #   a) missing file/typo/etc
                    #   b) using a module provided by the compiler, such as
                    #      OpenMP
                    # There's no easy way to tell which is which (that I
                    # know of) so just ignore this and go on. Ideally we
                    # would print a warning message to the user but this is
                    # a common occurrence, which would lead to lots of
                    # distracting noise.
                    continue
                srcfile = srcdir / tdeps[usename].fname
                if not srcfile.is_file():
                    if srcfile.name != src.name:  # generated source file
                        pass
                    else:  # subproject
                        continue
                elif srcfile.samefile(src):  # self-reference
                    continue

                mod_name = compiler.module_name_to_filename(usename)
                mod_files.append(str(dirname / mod_name))
            else:  # submodules
                submodmatch = submodre.match(line)
                if submodmatch is not None:
                    parents = submodmatch.group(1).lower().split(':')
                    assert len(parents) in {1, 2}, (
                        'submodule ancestry must be specified as'
                        f' ancestor:parent but Meson found {parents}')

                    ancestor_child = '_'.join(parents)
                    if ancestor_child not in tdeps:
                        raise MesonException("submodule {} relies on ancestor module {} that was not found.".format(submodmatch.group(2).lower(), ancestor_child.split('_', maxsplit=1)[0]))
                    submodsrcfile = srcdir / tdeps[ancestor_child].fname
                    if not submodsrcfile.is_file():
                        if submodsrcfile.name != src.name:  # generated source file
                            pass
                        else:  # subproject
                            continue
                    elif submodsrcfile.samefile(src):  # self-reference
                        continue
                    mod_name = compiler.module_name_to_filename(ancestor_child)
                    mod_files.append(str(dirname / mod_name))
    return mod_files

"""


```