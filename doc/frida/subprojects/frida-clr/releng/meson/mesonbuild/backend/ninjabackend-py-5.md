Response:
The user wants a summary of the functionalities of the provided Python code, which is a part of the Frida dynamic instrumentation tool. The code is specifically the Ninja backend for the Meson build system.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core responsibility:** The filename `ninjabackend.py` and the context of `frida/subprojects/frida-clr/releng/meson/mesonbuild/backend` strongly suggest this code is responsible for generating Ninja build files. Ninja is a fast build system that takes a description of the build process as input.

2. **Analyze key functions and their actions:**  Go through the code and identify the main functions and what they do. Look for keywords like `generate_`, `add_build`, and the manipulation of `NinjaBuildElement`.

    * `generate_phony`: Creates a placeholder target in the Ninja build.
    * `generate_compile`:  Handles compilation of source files. This is a core function.
    * `generate_static_lib`, `generate_dynamic_lib`, `generate_executable`: Functions for creating different types of build outputs.
    * `generate_custom_target`: Deals with user-defined build steps.
    * `generate_run_target`:  For targets that execute commands.
    * `generate_install`:  Handles installation of built artifacts.
    * `generate_prelink`:  An optimization step to pre-link object files.
    * `generate_link`: The crucial step of linking object files into libraries or executables. This function is quite complex and deserves significant attention.
    * `generate_shlib_aliases`:  Creates symbolic links for shared libraries.
    * `generate_custom_target_clean`, `generate_gcov_clean`: Functions for cleaning build outputs.
    * `generate_dist`: Creates source packages.
    * `generate_scanbuild`, `generate_clangtool`, `generate_clangformat`, `generate_clangtidy`, `generate_tags`:  Integrate with various static analysis and code formatting tools.
    * `generate_utils`:  A collection of utility-related build targets.
    * `generate_ending`:  Generates final build targets like 'all', 'clean', 'reconfigure'.
    * `get_introspection_data`:  Provides data for introspection (querying the build system).
    * `_scan_fortran_file_deps`:  A helper function for scanning Fortran files for dependencies.

3. **Relate functionalities to reverse engineering:** Consider how these build steps and generated files are relevant to reverse engineering.

    * **Compilation and Linking:**  The core steps to create the binaries that will be reverse engineered.
    * **Debugging Symbols:** The code explicitly mentions handling debugging symbols (`-g`, `/DEBUG`, `.pdb`). These are vital for debugging and reverse engineering.
    * **Shared Libraries:**  The generation of shared libraries is essential as Frida often works by injecting into processes, which frequently involves shared libraries.
    * **Custom Targets:**  Allow for flexibility in the build process, potentially including steps that aid in reverse engineering (e.g., generating disassembly or intermediate representations).

4. **Connect to low-level concepts:** Think about the underlying technologies and concepts involved in the build process.

    * **Object Files:**  The intermediate output of compilation.
    * **Linking:**  The process of combining object files and libraries.
    * **Executables and Libraries:** The final output of the build.
    * **Linux Kernel and Frameworks:**  While the code itself doesn't directly interact with the kernel, the *output* of the build process (executables and libraries) will run on these systems. The handling of shared library dependencies (`rpath`) is relevant here.
    * **Android:**  The mention of shared library symbols (`generate_shsym`) and the overall build process is similar for Android native libraries.

5. **Identify logical reasoning and potential inputs/outputs:**  Look for conditional logic and try to anticipate how different inputs might affect the output.

    * **Compiler Choice:** The code uses `linker.get_language()`, indicating different handling based on the programming language.
    * **Build Type (Debug/Release):** The code checks `target.get_option(OptionKey('debug'))` and `target.get_option(OptionKey('optimization'))`, which influence compiler/linker flags.
    * **Target Type (Executable/Library):** The `isinstance` checks determine how linking is performed.
    * **Input/Output Example (Prelinking):**  Input: a list of object files. Output: a prelinked object file.

6. **Consider user errors:** Think about common mistakes users might make when using the build system.

    * **Missing Dependencies:** The code handles dependencies, but users might forget to declare them.
    * **Incorrect Compiler/Linker Flags:**  Users might provide invalid or conflicting flags.
    * **Path Issues:** Incorrectly specified paths for source files or libraries.

7. **Trace the user path:** Imagine how a user's actions lead to this code being executed.

    * **`meson setup`:**  The initial configuration step that analyzes the project and generates build files.
    * **`ninja` or `ninja build`:** The command that executes the build process, driven by the generated `build.ninja` file.
    * The `ninjabackend.py` is invoked by Meson *during* the `meson setup` phase to generate the `build.ninja` file.

8. **Synthesize and organize the information:**  Group the identified functionalities and their implications into logical categories (core function, reverse engineering, low-level details, etc.). Provide clear examples and explanations. Since this is the final part of a series, make sure to summarize the overall purpose.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/backend/ninjabackend.py` 文件的最后一部分，它主要负责生成 Ninja 构建系统的最终配置，以及一些清理和工具相关的构建目标。综合之前的部分，我们可以归纳出其功能如下：

**总体功能归纳 (基于所有六部分):**

`ninjabackend.py` 的核心功能是 **将 Meson 构建系统的抽象描述转换为 Ninja 构建系统能够理解和执行的 `build.ninja` 文件**。 它实现了以下关键任务：

1. **目标构建 (Target Generation):**
   - **编译 (Compilation):**  将源代码文件编译成目标文件 (`.o`, `.obj`).
   - **静态链接 (Static Linking):** 将目标文件和静态库链接成静态库 (`.a`, `.lib`).
   - **动态链接 (Dynamic Linking):** 将目标文件和动态库链接成动态库 (`.so`, `.dll`).
   - **可执行文件链接 (Executable Linking):** 将目标文件和库链接成可执行文件。
   - **自定义目标 (Custom Target):** 支持用户自定义的构建步骤，例如代码生成、数据处理等。
   - **运行目标 (Run Target):**  定义需要在构建过程中执行的命令。

2. **依赖管理 (Dependency Management):**
   - 跟踪目标之间的依赖关系，确保构建顺序正确。
   - 处理内部依赖 (同一 Meson 项目内的目标)。
   - 处理外部依赖 (系统库、pkg-config 提供的库)。
   - 处理 Fortran 模块依赖。

3. **安装 (Installation):**
   - 生成安装规则，将构建产物复制到指定目录。
   - 支持不同类型的安装目标 (可执行文件、库、数据文件、头文件、符号链接等)。

4. **清理 (Cleaning):**
   - 生成清理规则，删除构建过程中生成的文件。
   - 支持清理自定义目标生成的文件。
   - 支持清理代码覆盖率数据文件 (`.gcno`, `.gcda`).

5. **工具集成 (Tool Integration):**
   - 集成静态代码分析工具 (如 `scan-build`, `clang-tidy`)。
   - 集成代码格式化工具 (如 `clang-format`).
   - 集成代码标签生成工具 (如 `etags`, `ctags`, `cscope`).

6. **构建系统配置 (Build System Configuration):**
   - 生成 Ninja 的规则 (rule) 和构建目标 (build)。
   - 处理编译器和链接器的参数。
   - 处理构建选项 (如优化级别、调试信息)。
   - 处理平台特定的构建设置。

7. **再生构建文件 (Regenerate Build Files):**
   - 生成规则，当 Meson 的定义文件 (`meson.build`) 或构建选项发生变化时，重新运行 Meson 来生成新的 `build.ninja` 文件。

8. **内部工具 (Internal Tools):**
   - 提供一些内部使用的构建目标，例如 `uninstall`。

**本部分 (第 6 部分) 的具体功能:**

这部分主要负责生成构建过程的最后阶段和一些辅助性的构建目标：

1. **生成最终的构建目标 (Ending Targets):**
   - **`all` 目标:**  依赖于所有需要默认构建的目标，确保执行 `ninja` 命令时构建所有必要产物。
   - **`meson-test-prereq` 和 `meson-benchmark-prereq` 目标:**  依赖于测试和基准测试所需的目标。
   - **`clean` 目标:** 生成清理规则，执行 `ninja clean` 命令时删除构建产物。这部分特别处理了自定义目标产生的目录清理问题。
   - **`build.ninja` 目标:**  生成一个特殊的 Ninja 构建目标，用于重新生成 `build.ninja` 文件本身。这确保了当 Meson 的输入发生变化时，构建配置能够更新。
   - **`meson-implicit-outs` 目标:**  处理隐式生成的输出文件，防止被 Ninja 的 `cleandead` 命令删除。
   - **`reconfigure` 目标:** 生成一个触发重新运行 Meson 配置的快捷方式。
   - **一个依赖所有输入文件的 `phony` 目标:** 这有助于 Ninja 理解何时需要重新生成构建文件。

2. **生成清理相关的构建目标 (Clean Targets):**
   - **`clean-ctlist` 目标:**  用于清理自定义目标生成的目录。
   - **`clean-gcno` 和 `clean-gcda` 目标:** 用于清理代码覆盖率数据文件。

3. **生成工具相关的构建目标 (Utility Targets):**
   - **`dist` 目标:** 用于创建源代码包。
   - **`scan-build` 目标:**  集成 `scan-build` 静态代码分析工具。
   - **`clangtool` (包括 `clang-format`, `clang-tidy`) 目标:** 集成 Clang 的格式化和静态分析工具。
   - **`tags` (包括 `TAGS`, `ctags`, `cscope`) 目标:** 集成代码标签生成工具。
   - **`uninstall` 目标:**  生成卸载规则。

4. **处理构建结束 (Ending Generation):**
   - 将默认构建的目标、测试目标、基准测试目标添加到相应的 Ninja 构建目标中。
   - 处理代码覆盖率的清理依赖。

5. **获取内省数据 (Get Introspection Data):**
   - `get_introspection_data` 函数用于获取构建目标的内省数据，用于 Meson 的内部查询。

**与逆向方法的关系举例:**

- **调试符号:** 在 `generate_link` 函数中，代码会根据 `debug` 选项生成链接调试符号所需的参数 (例如 `-g`，`/DEBUG`)，并将 `.pdb` 文件添加到隐式输出中。这些调试符号对于逆向工程至关重要，因为它们可以帮助逆向工程师理解代码的结构和功能。例如，如果用户启用了调试选项，逆向工程师可以使用调试器加载生成的二进制文件，并通过符号信息设置断点、查看变量值等。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例:**

- **动态链接库的符号 (Shared Library Symbols):**  `generate_shsym` 函数用于生成共享库的符号表文件。这在 Linux 和 Android 等系统中非常重要，因为动态链接器需要这些符号信息来解析库的依赖关系。例如，在 Android 中，当一个应用程序加载一个 native 库时，系统需要找到该库依赖的其他库，而符号表就提供了这些信息。
- **运行时路径 (Run-Paths):** `generate_link` 函数中计算和设置 `rpath` 参数，这是 Linux 系统中用于指定动态链接器搜索共享库的路径。这涉及到对 Linux 动态链接器工作原理的理解。在 Android 中，也有类似的机制，尽管路径的设置方式可能略有不同。
- **AIX 特定的共享库处理:** 代码中针对 AIX 系统，在构建 `all` 目标时，会特别添加共享库的 archive 文件。这体现了对特定操作系统二进制文件格式和链接方式的理解。

**逻辑推理的例子 (假设输入与输出):**

假设用户定义了一个名为 `mylib` 的共享库目标，并且该库依赖于另一个名为 `utils` 的静态库。

**输入:**

- `target`: `mylib` (一个 `build.SharedLibrary` 对象)
- `obj_list`: `['mylib.o', 'some_module.o']` (编译后的目标文件列表)
- `linker`: 当前使用的链接器对象
- `dependencies`: 包含 `utils` 静态库的依赖列表

**输出 (`generate_link` 函数生成的 `NinjaBuildElement`):**

```
NinjaBuildElement(
    outputs=['libmylib.so'],  # 假设输出名为 libmylib.so
    rule='CXX_LINKER',        # 假设是 C++ 动态库
    inputs=['mylib.o', 'some_module.o', 'libutils.a'], # 注意包含了依赖的静态库
    implicit_outs=['libmylib.so.dbg'], # 如果启用了调试符号
    values={
        'LINK_ARGS': [
            # ... 其他链接参数 ...
            '-L/path/to/utils/dir',  # 假设 utils 库的路径
            '-lutils',             # 链接 utils 库
            # ... 其他链接参数 ...
        ],
        'description': 'Linking target mylib'
    },
    deps=[] # 其他依赖，例如 .shsym 文件
)
```

在这个例子中，`generate_link` 函数会根据 `mylib` 的类型和依赖关系，生成相应的 Ninja 构建规则，包括链接器命令、输入的 object 文件以及依赖的 `utils` 静态库。

**用户或编程常见的使用错误举例:**

- **忘记声明依赖:** 用户在 `meson.build` 文件中定义了一个共享库，但忘记使用 `link_with` 或 `dependencies` 声明其依赖的另一个静态库。在这种情况下，`generate_link` 函数生成的 Ninja 构建规则可能缺少链接静态库的参数，导致链接失败。Meson 会尝试推断依赖，但并不总是成功。
- **循环依赖:** 用户在 `meson.build` 文件中创建了循环依赖，例如库 A 依赖库 B，库 B 又依赖库 A。这会导致 `generate_link` 函数在处理依赖时陷入无限循环，或者生成不正确的构建规则，最终导致链接错误。Meson 通常会检测到循环依赖并报错，但这仍然是一个常见的用户错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户编写 `meson.build` 文件:** 定义了 Frida 项目的构建规则，包括编译哪些源文件、链接哪些库、生成哪些目标等。
2. **用户执行 `meson setup builddir`:**  Meson 读取 `meson.build` 文件，分析项目结构和依赖关系。
3. **Meson 调用 `ninjabackend.py`:** 在分析完成后，Meson 会根据选择的 backend (这里是 Ninja) 调用 `ninjabackend.py` 来生成实际的构建文件。
4. **`ninjabackend.py` 的各个 `generate_` 函数被调用:**  根据 `meson.build` 中定义的各种目标 (可执行文件、库、自定义目标等)，`ninjabackend.py` 中的相应 `generate_` 函数会被调用，例如 `generate_executable`、`generate_shared_lib`、`generate_custom_target` 等。
5. **最终调用 `generate_ending`:**  在所有目标都处理完毕后，会调用 `generate_ending` 函数来生成最终的构建目标，例如 `all` 和 `clean`。
6. **生成 `build.ninja` 文件:** `ninjabackend.py` 将生成的所有 Ninja 构建规则写入到 `builddir/build.ninja` 文件中。
7. **用户执行 `ninja` 或 `ninja builddir`:** Ninja 读取 `build.ninja` 文件，并根据其中的规则执行构建操作，包括编译、链接等。

如果用户在构建过程中遇到问题，例如链接错误，可以检查生成的 `build.ninja` 文件中对应目标的构建规则，查看编译器和链接器的参数是否正确，以及依赖关系是否正确处理。这可以帮助定位问题是由 Meson 的配置错误引起的，还是由 `ninjabackend.py` 生成的构建规则错误引起的。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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