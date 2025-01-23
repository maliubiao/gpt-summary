Response:
The user wants to understand the functionality of the provided Python code snippet from `ninjabackend.py`. This file seems to be responsible for generating Ninja build files for the Frida dynamic instrumentation tool.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose of the code:** The code is part of a Ninja backend for Meson, a build system generator. Its primary job is to translate Meson's build descriptions into Ninja's build instructions.

2. **Analyze individual functions:** Go through each function in the snippet and describe what it does. Pay attention to the parameters and how they're used.

3. **Relate to reverse engineering:**  Think about how the actions performed by these functions are relevant to the process of reverse engineering, particularly in the context of Frida. This involves understanding how the build process influences the final binary and how Frida interacts with it.

4. **Connect to low-level concepts:** Identify aspects of the code that interact with operating system kernels (Linux, Android), binary formats, and linking processes.

5. **Infer logical reasoning:** Look for conditional logic and how different inputs lead to different outputs. Create hypothetical scenarios to illustrate this.

6. **Spot potential user errors:** Consider common mistakes users might make during the build process that could involve this code.

7. **Trace the user's path:**  Imagine the steps a user would take when building Frida to understand how they would end up interacting with this specific part of the build system.

8. **Summarize the overall functionality:** Provide a concise overview of the code's role within the larger Frida build process.

**Detailed thought process for each point:**

* **Core Purpose:** The file name `ninjabackend.py` strongly suggests it generates Ninja build files. The functions within it confirm this by constructing Ninja build rules and elements.

* **Function Analysis:**
    * `generate_prelink`: Deals with prelinking, an optimization technique.
    * `generate_link`: Handles the linking stage, combining object files into executables or libraries. This is a crucial part.
    * `get_dependency_filename`: Determines the filename of a dependency based on its type.
    * `generate_shlib_aliases`: Creates symbolic links for shared libraries, important for versioning.
    * `generate_custom_target_clean`, `generate_gcov_clean`: Handle cleaning up build artifacts.
    * `get_user_option_args`: Extracts user-defined build options.
    * `generate_dist`, `generate_scanbuild`, `generate_clangtool`, `generate_clangformat`, `generate_clangtidy`, `generate_tags`, `generate_utils`: Manage various build-related utilities.
    * `generate_ending`: Generates the final parts of the Ninja build file, including the "all" target and clean rules.
    * `get_introspection_data`: Provides data for introspection, which is used by IDEs and other tools.
    * `_scan_fortran_file_deps`: Specifically handles dependency scanning for Fortran files.

* **Reverse Engineering Relevance:**
    * Prelinking can affect the layout of the final binary, potentially influencing reverse engineering efforts.
    * Linking is a core concept; understanding how libraries are linked is vital for analyzing dependencies in reverse engineering.
    * Shared library aliases are crucial for understanding versioning and compatibility, which are important when reverse engineering software that relies on specific library versions.

* **Low-Level Concepts:**
    * Binary format: Linking directly deals with the structure of executable and library files.
    * Linux/Android kernel: The code mentions runtime paths (`rpath`), which are used by the dynamic linker in Linux-like systems to find shared libraries. Shared libraries are fundamental to how software is built and executed on these platforms.
    * Android framework: While not explicitly mentioned, the concepts of shared libraries and linking are also relevant to the Android framework.
    * Compiler/Linker flags: The code manipulates various compiler and linker flags (e.g., `-L`, `-l`, `-shared`, `-fPIC`), which are core to understanding the low-level build process.

* **Logical Reasoning:**  Focus on functions like `generate_link`. The conditional logic based on the target type (static library, shared library, etc.) demonstrates how different build targets are handled. Consider scenarios where different build options are set (e.g., debug vs. release) and how this affects the generated Ninja commands.

* **User Errors:** Common errors involve incorrect paths, missing dependencies, or providing incompatible linker flags. The code doesn't directly *prevent* these errors but generates build instructions based on user input, so understanding the process can help diagnose such issues.

* **User Path:**  A user building Frida would typically run the `meson` command followed by `ninja`. `ninjabackend.py` is invoked by `meson` during the configuration phase to generate the `build.ninja` file that `ninja` then uses to perform the actual build.

* **Summary:** The code's primary function is to translate Meson's build instructions into Ninja format. It manages various aspects of the build process, including compilation, linking, dependency management, and cleaning.

**(Self-Correction/Refinement):** Initially, I might have focused too much on the specific details of each function. It's important to step back and understand the *overall* purpose and how each function contributes to that. Also, explicitly connecting the technical details to the domain of reverse engineering is crucial for answering that part of the prompt effectively. Recognizing the limitations – this code generates the build instructions, it doesn't directly execute them or prevent all user errors – is also important.好的，让我们来分析一下 `frida/releng/meson/mesonbuild/backend/ninjabackend.py` 文件的功能。

**文件功能概览**

`ninjabackend.py` 是 Frida 项目中 Meson 构建系统的一个后端实现，专门用于生成 Ninja 构建工具所需要的 `build.ninja` 文件。它的主要职责是将 Meson 的项目描述（例如目标、依赖、编译选项等）转换为 Ninja 可以理解的指令，从而驱动实际的编译、链接等构建过程。

**具体功能列表及说明**

1. **生成预链接 (Prelinking) 指令 (`generate_prelink`)**:
   - 功能：对于某些支持预链接的目标（例如，为了优化启动时间），生成预链接的 Ninja 构建规则。
   - 与逆向的关系：预链接可以改变最终二进制文件的内存布局，逆向工程师可能需要了解是否使用了预链接以及其影响。例如，预链接可能会合并一些小的代码段，使得代码分析时某些函数的起始地址不再是其原始的链接地址。
   - 二进制底层知识：预链接涉及到对目标文件进行初步的链接，处理符号的重定位等底层操作。
   - 逻辑推理：
     - 假设输入：一个需要预链接的共享库目标 `target`，以及其依赖的 object 文件列表 `obj_list`。
     - 输出：生成 Ninja 构建规则，描述如何使用 `prelinker` 工具对 `obj_list` 进行预链接，生成 `prelink_name` 文件。
   - 用户操作如何到达：用户在 `meson.build` 文件中定义了一个共享库目标，并可能通过某些选项启用了预链接。Meson 在配置阶段会解析这些定义，并在生成 Ninja 文件时调用此函数。

2. **生成链接 (Linking) 指令 (`generate_link`)**:
   - 功能：生成将 object 文件链接成最终可执行文件、共享库或静态库的 Ninja 构建规则。这个函数是构建过程中最核心的部分之一。
   - 与逆向的关系：链接过程决定了最终二进制文件的结构、依赖关系和符号信息。逆向工程师需要理解链接过程才能正确分析二进制文件，例如识别导入导出函数、理解库的依赖关系。
   - 二进制底层、Linux/Android 内核及框架知识：
     - **二进制底层：** 链接涉及到符号解析、地址重定位、节（section）合并等二进制层面的操作。
     - **Linux/Android 内核：** 生成运行时路径 (rpath) 是为了让程序在运行时能够找到依赖的共享库，这与 Linux 和 Android 的动态链接器的工作方式相关。
     - **Android 框架：** 构建共享库时可能涉及到 Android 特有的链接选项和依赖关系。
   - 逻辑推理：
     - 假设输入：一个构建目标 `target` (例如，可执行文件或共享库)，输出文件名 `outname`，object 文件列表 `obj_list`，链接器对象 `linker`，以及额外的链接参数 `extra_args` 和标准库参数 `stdlib_args`。
     - 输出：生成 Ninja 构建规则，描述如何使用 `linker` 将 `obj_list` 链接成 `outname`，并包含必要的链接参数、依赖项等。
   - 用户或编程常见的使用错误：
     - 缺少必要的库依赖，导致链接器报错 "undefined reference to..."。
     - 运行时库路径配置不正确，导致程序运行时找不到依赖的共享库。
     - 链接参数冲突或不兼容。
   - 用户操作如何到达：用户在 `meson.build` 文件中定义了一个可执行文件、共享库或静态库目标，并指定了其依赖的源文件和其他库。Meson 在生成 Ninja 文件时会为每个这样的目标调用此函数。

3. **获取依赖文件名 (`get_dependency_filename`)**:
   - 功能：根据依赖项的类型（共享库、已构建的文件、源文件等）返回其在构建系统中的文件名。
   - 用户操作如何到达：在 `generate_link` 等需要处理依赖项的函数中被调用，用于构建 Ninja 依赖关系。

4. **生成共享库别名 (`generate_shlib_aliases`)**:
   - 功能：为共享库生成别名（符号链接），用于支持共享库的版本控制。
   - 与逆向的关系：共享库别名和版本控制是理解软件兼容性的重要方面。逆向工程师需要了解程序依赖的特定共享库版本。
   - Linux 知识：符号链接是 Linux 文件系统的重要特性。
   - 用户操作如何到达：当构建目标是共享库，并且在 `meson.build` 中定义了共享库的别名时，Meson 会调用此函数。

5. **生成自定义目标清理指令 (`generate_custom_target_clean`)**:
   - 功能：为自定义构建目标生成清理其输出的 Ninja 指令。
   - 用户操作如何到达：当项目定义了自定义构建目标时，Meson 会生成相应的清理规则。

6. **生成 Gcov 清理指令 (`generate_gcov_clean`)**:
   - 功能：生成清理 Gcov 代码覆盖率数据的 Ninja 指令。
   - 用户操作如何到达：当启用了代码覆盖率选项 (`b_coverage`) 时，Meson 会生成相应的清理规则。

7. **获取用户选项参数 (`get_user_option_args`)**:
   - 功能：获取用户通过命令行传递的 Meson 构建选项。
   - 用户操作如何到达：在生成其他构建指令时，可能需要包含用户的构建选项。

8. **生成分发包指令 (`generate_dist`)**:
   - 功能：生成创建源代码分发包的 Ninja 指令。
   - 用户操作如何到达：当用户执行 `ninja dist` 命令时，会触发此规则。

9. **生成 Scanbuild 指令 (`generate_scanbuild`)**:
   - 功能：生成运行 `scan-build` 静态代码分析工具的 Ninja 指令。
   - 用户操作如何到达：当环境中检测到 `scan-build` 工具时，Meson 会生成相应的规则。

10. **生成 Clang 工具指令 (`generate_clangtool`)**:
    - 功能：生成运行 Clang 相关工具（如 clang-format, clang-tidy）的 Ninja 指令。
    - 用户操作如何到达：当环境中检测到这些 Clang 工具，并且项目存在相应的配置文件时，Meson 会生成相应的规则。

11. **生成 Tags 指令 (`generate_tags`)**:
    - 功能：生成创建代码标签文件（如 TAGS, ctags, cscope）的 Ninja 指令。
    - 用户操作如何到达：当环境中检测到相应的标签生成工具时，Meson 会生成相应的规则。

12. **生成工具类指令 (`generate_utils`)**:
    - 功能：将一些辅助工具的生成指令集中在一起。
    - 用户操作如何到达：在配置阶段，Meson 会尝试生成这些工具的规则。

13. **生成结尾部分 (`generate_ending`)**:
    - 功能：生成 `build.ninja` 文件的结尾部分，包括 "all" 目标（默认构建所有目标）、"clean" 目标（清理构建产物）、重新配置指令等。
    - 用户操作如何到达：这是生成 Ninja 文件的最后阶段。

14. **获取内省数据 (`get_introspection_data`)**:
    - 功能：提供构建目标的内省数据，用于 IDE 或其他工具进行集成。

15. **扫描 Fortran 文件依赖 (`_scan_fortran_file_deps`)**:
    - 功能：专门用于扫描 Fortran 源文件中的依赖关系，例如 `include` 语句和 `use` 语句引用的模块。
    - 与逆向的关系：如果 Frida 项目中包含 Fortran 代码，理解其依赖关系对于构建和分析至关重要。
    - 编程常见的使用错误：`use` 的模块不存在或路径不正确。
    - 用户操作如何到达：当项目包含 Fortran 源文件时，Meson 在解析依赖关系时会调用此函数。

**功能归纳**

`ninjabackend.py` 的核心功能是将 Meson 的高级构建描述转换为 Ninja 构建工具所需的低级指令。它涵盖了构建过程的各个方面，包括：

- **编译**:  虽然这里没有直接编译的指令，但链接过程依赖于之前的编译步骤，该文件生成的链接指令是构建过程的重要组成部分。
- **链接**:  生成将 object 文件链接成最终二进制文件的指令，这是该文件的核心功能之一。
- **依赖管理**:  跟踪和处理目标之间的依赖关系，确保构建顺序正确。
- **清理**:  生成清理构建产物的指令。
- **辅助工具集成**:  集成静态代码分析、代码格式化、标签生成等工具。
- **配置**:  处理用户提供的构建选项。
- **分发**:  生成创建源代码分发包的指令。

总而言之，`ninjabackend.py` 是 Meson 构建系统与 Ninja 构建工具之间的桥梁，它将开发者友好的 Meson 构建描述转化为高效的 Ninja 构建指令，从而驱动 Frida 项目的实际构建过程。它深入涉及到二进制底层知识、操作系统特性（如动态链接、符号链接），并且需要处理各种构建场景和用户配置。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
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
```