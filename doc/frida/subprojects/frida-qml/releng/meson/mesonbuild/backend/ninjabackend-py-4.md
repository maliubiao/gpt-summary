Response:
The user wants a summary of the Python code provided, focusing on its functionality within the Frida dynamic instrumentation tool. I need to identify key actions performed by this code, particularly concerning compilation, linking, debugging information, and interactions with the underlying operating system and hardware. I should also look for examples related to reverse engineering, low-level programming, and potential user errors.

Here's a breakdown of how to approach this:

1. **Identify the main class:** The code is within a class named `NinjaBackend`. This suggests it's responsible for generating Ninja build files.

2. **Analyze key methods:** Focus on methods that perform core build steps like compilation (`generate_single_compile`, `generate_llvm_ir_compile`), linking (`generate_link`, `get_target_type_link_args`), and handling debugging information (`get_compile_debugfile_args`, `get_link_debugfile_args`).

3. **Look for OS/kernel interactions:**  Pay attention to mentions of Linux, Android, and Windows, and how the code handles platform-specific differences (e.g., PDB files on Windows, sonames on Linux).

4. **Find reverse engineering connections:** Look for any mentions of debugging symbols, shared libraries, and how they're processed, as these are relevant to reverse engineering.

5. **Identify logic and assumptions:** Analyze conditional statements and loops to understand the control flow and assumptions made by the code. Look for examples of input and output.

6. **Spot potential user errors:** Check for error handling or comments mentioning common mistakes.

7. **Connect to user actions:**  Infer how a user's actions in configuring the build system (e.g., defining targets, dependencies, compiler flags) would lead to the execution of this code.

8. **Summarize the functionality:**  Synthesize the identified functionalities into a concise overview.
这是 Frida 动态 instrumentation 工具中负责生成 Ninja 构建文件的 Python 代码片段，主要功能是定义了如何将 Frida 项目中的构建目标（例如可执行文件、共享库、静态库）转换为 Ninja 构建系统的规则和命令。以下是它的功能归纳：

**主要功能归纳：**

这段代码是 `NinjaBackend` 类的一部分，它负责将 Meson 构建系统的抽象表示转化为 Ninja 构建工具能够理解的具体构建规则。其核心功能是生成用于编译和链接各种类型目标文件的 Ninja 指令。

**详细功能列表及说明：**

1. **处理编译过程 (Compilation):**
   - `generate_single_compile`:  这是核心的编译函数，负责为单个源文件生成编译命令。它会根据目标和源文件的类型选择合适的编译器，并添加必要的编译参数，例如包含路径、预处理器宏定义、调试信息选项等。
   - `_generate_single_compile_base_args`, `_generate_single_compile_target_args`:  辅助函数，用于构建编译命令的基础参数和目标特定的参数。
   - `generate_llvm_ir_compile`:  为生成 LLVM IR 中间表示的代码生成编译命令。
   - `get_compile_debugfile_args`:  生成与调试信息相关的编译器参数，例如生成 PDB 文件（Program Database）的选项。
   - **与逆向方法的关系：** 生成的调试信息（如 PDB 文件）对于逆向工程至关重要。逆向工程师可以使用这些信息来理解二进制代码的结构、变量和函数名，从而更容易进行分析和调试。例如，在使用调试器（如 gdb 或 lldb）时，调试符号可以帮助将机器码地址映射回源代码行。
   - **涉及到二进制底层：** 编译过程将源代码转换为机器码，这是二进制层面的操作。这段代码需要根据目标架构选择合适的编译器和编译选项。
   - **涉及到 linux, android 内核及框架的知识：**  代码中处理了共享库的符号导出 (`export_dynamic`)，这在 Linux 和 Android 等系统中非常重要。共享库需要在运行时动态链接，`export_dynamic` 确保符号表被导出，以便其他模块可以访问。

2. **处理链接过程 (Linking):**
   - `generate_link`: (尽管此片段中未完整展示，但上下文表明存在此功能) 负责生成将编译后的对象文件链接成最终可执行文件或库文件的命令。
   - `get_link_debugfile_name`, `get_link_debugfile_args`: 生成与链接器相关的调试信息参数。
   - `get_target_type_link_args`:  根据目标类型（可执行文件、共享库、静态库）生成不同的链接参数，例如指定入口点、库依赖、运行时库等。
   - `get_target_type_link_args_post_dependencies`: 在处理依赖之后添加的链接参数，例如 Windows 的子系统参数。
   - `get_link_whole_args`: 处理静态库链接时需要将整个静态库包含进来的情况 (`link_whole`).
   - `guess_external_link_dependencies`:  尝试猜测外部库依赖，这在某些情况下很有用，但通常依赖于更精确的依赖声明。
   - **与逆向方法的关系：** 链接过程将不同的代码模块组合在一起。逆向工程师需要理解链接过程，才能分析各个模块之间的交互关系。共享库的链接尤其重要，因为它是动态分析的常见目标。
   - **涉及到二进制底层：** 链接器将不同的目标文件中的机器码段合并成一个可执行文件或库文件，涉及到内存布局、符号解析等底层操作。
   - **涉及到 linux, android 内核及框架的知识：**  代码中处理了共享库的 soname (Shared Object Name) 和 import library，这些都是 Linux 和 Windows 等操作系统中动态链接的关键概念。

3. **处理预编译头文件 (Precompiled Headers - PCH):**
   - `generate_pch`:  生成预编译头文件的构建命令，可以加速编译过程。
   - `generate_msvc_pch_command`, `generate_gcc_pch_command`, `generate_mwcc_pch_command`:  针对不同编译器生成特定的 PCH 构建命令。
   - **与逆向方法的关系：**  预编译头文件本身对逆向分析没有直接影响，但它可以影响编译速度，间接影响开发效率。

4. **处理符号文件 (Symbol Files):**
   - `generate_shsym`:  生成符号文件的命令，例如用于调试的 `.symbols` 文件。
   - `get_target_shsym_filename`: 获取符号文件的名称。
   - **与逆向方法的关系：**  符号文件包含调试信息，是逆向工程的重要资源。

5. **处理导入库 (Import Libraries):**
   - `get_import_filename`: 获取导入库的名称。
   - **涉及到 linux, android 内核及框架的知识：** 导入库在 Windows 系统中用于动态链接，它包含了共享库导出的符号信息。

6. **处理 Fortran 模块依赖：**
   - `get_fortran_orderdeps`:  处理 Fortran 模块之间的依赖关系，确保模块的编译顺序正确。
   - 代码中提到了 Fortran 的模块依赖问题以及如何通过 Ninja 的 `orderdep` 来解决。

7. **平台特定的处理：**
   - 代码中多次提及 Windows 平台和 Visual Studio 编译器（MSVC），并特别注意了 PDB 文件的生成和命名冲突问题。
   - 也提到了 Linux 系统的共享库命名约定 (soname)。

8. **逻辑推理 (假设输入与输出):**
   - **假设输入:**  一个名为 `foo` 的共享库目标，包含 `foo.c` 和 `bar.c` 两个源文件。
   - **输出:**  `generate_single_compile` 函数会被调用两次，分别处理 `foo.c` 和 `bar.c`，生成类似以下的 Ninja 构建规则：
     ```ninja
     build frida/subprojects/frida-qml/releng/meson/build/foo.c.o: CC frida/subprojects/frida-qml/releng/meson/foo.c
       ARGS = ... (编译 foo.c 的参数)
     build frida/subprojects/frida-qml/releng/meson/build/bar.c.o: CC frida/subprojects/frida-qml/releng/meson/bar.c
       ARGS = ... (编译 bar.c 的参数)
     build frida/subprojects/frida-qml/releng/meson/build/libfoo.so: LINK frida/subprojects/frida-qml/releng/meson/build/foo.c.o frida/subprojects/frida-qml/releng/meson/build/bar.c.o
       ARGS = ... (链接 libfoo.so 的参数，包括 -soname 等)
     ```
   - **假设输入:** 一个使用了预编译头文件 `pch.h` 的 C++ 目标。
   - **输出:** `generate_pch` 函数会生成构建 `pch.h.gch` (GCC) 或 `pch.pch` (MSVC) 的 Ninja 规则，并且后续的编译规则会依赖这个预编译头文件。

9. **用户或编程常见的使用错误：**
   - 代码注释中提到了 Windows 上静态库和动态库重名可能导致 PDB 文件和导出库冲突的问题。这是用户在命名目标时需要注意的。
   - 代码中对预编译头文件的路径有要求，不能和源文件在同一个目录下，这是用户配置预编译头文件时需要注意的。
   - `InvalidArguments` 异常会在遇到无效的源文件类型时抛出，例如尝试编译一个不存在的文件。

10. **用户操作是如何一步步的到达这里，作为调试线索：**
    1. **用户配置 Meson 构建：** 用户运行 `meson setup builddir` 命令来配置构建目录。
    2. **Meson 解析构建定义：** Meson 读取 `meson.build` 文件，其中定义了各种构建目标（例如 `shared_library('foo', 'foo.c', 'bar.c')`）。
    3. **生成 Ninja 文件：** Meson 的后端（这里是 `ninjabackend.py`）将构建目标转换为 Ninja 构建系统的描述。对于每个需要编译的源文件和链接的目标，会调用 `generate_single_compile` 和 `generate_link` 等函数。
    4. **`generate_single_compile` 的触发：**  当 Meson 处理到一个需要编译的源文件时，会调用 `NinjaBackend` 的 `generate_single_compile` 方法。传入的参数包括目标对象、源文件对象以及编译器信息。
    5. **参数构建：** 在 `generate_single_compile` 内部，会调用 `_generate_single_compile_base_args` 和 `_generate_single_compile_target_args` 来构建编译命令的各个部分，包括编译器路径、编译选项、包含路径等。
    6. **Ninja 规则生成：**  最终，`NinjaBuildElement` 对象被创建并添加到构建图中，表示一个 Ninja 构建规则。

总而言之，这段代码是 Frida 构建过程中的关键部分，它负责将高级的构建意图转化为低级的构建指令，以便 Ninja 能够高效地执行编译和链接任务。它需要处理各种编程语言、编译器和操作系统之间的差异，并生成正确的构建参数和依赖关系。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
file called foo.pdb. So will a static library
        # foo.lib, which clobbers both foo.pdb _and_ the dll file's
        # export library called foo.lib (by default, currently we name
        # them libfoo.a to avoid this issue). You can give the files
        # unique names such as foo_exe.pdb but VC also generates a
        # bunch of other files which take their names from the target
        # basename (i.e. "foo") and stomp on each other.
        #
        # CMake solves this problem by doing two things. First of all
        # static libraries do not generate pdb files at
        # all. Presumably you don't need them and VC is smart enough
        # to look up the original data when linking (speculation, not
        # tested). The second solution is that you can only have
        # target named "foo" as an exe, shared lib _or_ static
        # lib. This makes filename collisions not happen. The downside
        # is that you can't have an executable foo that uses a shared
        # library libfoo.so, which is a common idiom on Unix.
        #
        # If you feel that the above is completely wrong and all of
        # this is actually doable, please send patches.

        if target.has_pch():
            tfilename = self.get_target_debug_filename_abs(target)
            if not tfilename:
                tfilename = self.get_target_filename_abs(target)
            return compiler.get_compile_debugfile_args(tfilename, pch=True)
        else:
            return compiler.get_compile_debugfile_args(objfile, pch=False)

    def get_link_debugfile_name(self, linker, target) -> T.Optional[str]:
        return linker.get_link_debugfile_name(self.get_target_debug_filename(target))

    def get_link_debugfile_args(self, linker, target):
        return linker.get_link_debugfile_args(self.get_target_debug_filename(target))

    def generate_llvm_ir_compile(self, target, src):
        base_proxy = target.get_options()
        compiler = get_compiler_for_source(target.compilers.values(), src)
        commands = compiler.compiler_args()
        # Compiler args for compiling this target
        commands += compilers.get_base_compile_args(base_proxy, compiler)
        if isinstance(src, File):
            if src.is_built:
                src_filename = os.path.join(src.subdir, src.fname)
            else:
                src_filename = src.fname
        elif os.path.isabs(src):
            src_filename = os.path.basename(src)
        else:
            src_filename = src
        obj_basename = self.canonicalize_filename(src_filename)
        rel_obj = os.path.join(self.get_target_private_dir(target), obj_basename)
        rel_obj += '.' + self.environment.machines[target.for_machine].get_object_suffix()
        commands += self.get_compile_debugfile_args(compiler, target, rel_obj)
        if isinstance(src, File) and src.is_built:
            rel_src = src.fname
        elif isinstance(src, File):
            rel_src = src.rel_to_builddir(self.build_to_src)
        else:
            raise InvalidArguments(f'Invalid source type: {src!r}')
        # Write the Ninja build command
        compiler_name = self.get_compiler_rule_name('llvm_ir', compiler.for_machine)
        element = NinjaBuildElement(self.all_outputs, rel_obj, compiler_name, rel_src)
        element.add_item('ARGS', commands)
        self.add_build(element)
        return (rel_obj, rel_src)

    def _generate_single_compile(self, target: build.BuildTarget, compiler: Compiler) -> CompilerArgs:
        commands = self._generate_single_compile_base_args(target, compiler)
        commands += self._generate_single_compile_target_args(target, compiler)
        return commands

    def _generate_single_compile_base_args(self, target: build.BuildTarget, compiler: 'Compiler') -> 'CompilerArgs':
        base_proxy = target.get_options()
        # Create an empty commands list, and start adding arguments from
        # various sources in the order in which they must override each other
        commands = compiler.compiler_args()
        # Start with symbol visibility.
        commands += compiler.gnu_symbol_visibility_args(target.gnu_symbol_visibility)
        # Add compiler args for compiling this target derived from 'base' build
        # options passed on the command-line, in default_options, etc.
        # These have the lowest priority.
        commands += compilers.get_base_compile_args(base_proxy,
                                                    compiler)
        return commands

    @lru_cache(maxsize=None)
    def _generate_single_compile_target_args(self, target: build.BuildTarget, compiler: Compiler) -> ImmutableListProtocol[str]:
        # Add compiler args and include paths from several sources; defaults,
        # build options, external dependencies, etc.
        commands = self.generate_basic_compiler_args(target, compiler)
        # Add custom target dirs as includes automatically, but before
        # target-specific include directories.
        if target.implicit_include_directories:
            commands += self.get_custom_target_dir_include_args(target, compiler)
        # Add include dirs from the `include_directories:` kwarg on the target
        # and from `include_directories:` of internal deps of the target.
        #
        # Target include dirs should override internal deps include dirs.
        # This is handled in BuildTarget.process_kwargs()
        #
        # Include dirs from internal deps should override include dirs from
        # external deps and must maintain the order in which they are specified.
        # Hence, we must reverse the list so that the order is preserved.
        for i in reversed(target.get_include_dirs()):
            # We should iterate include dirs in reversed orders because
            # -Ipath will add to begin of array. And without reverse
            # flags will be added in reversed order.
            for d in reversed(i.expand_incdirs(self.environment.get_build_dir())):
                # Add source subdir first so that the build subdir overrides it
                commands += compiler.get_include_args(os.path.normpath(os.path.join(self.build_to_src, d.source)),
                                                      i.is_system)
                if d.build is not None:
                    commands += compiler.get_include_args(d.build, i.is_system)
            for d in i.expand_extra_build_dirs():
                commands += compiler.get_include_args(d, i.is_system)
        # Add per-target compile args, f.ex, `c_args : ['-DFOO']`. We set these
        # near the end since these are supposed to override everything else.
        commands += self.escape_extra_args(target.get_extra_args(compiler.get_language()))

        # D specific additional flags
        if compiler.language == 'd':
            commands += compiler.get_feature_args(target.d_features, self.build_to_src)

        # Add source dir and build dir. Project-specific and target-specific
        # include paths must override per-target compile args, include paths
        # from external dependencies, internal dependencies, and from
        # per-target `include_directories:`
        #
        # We prefer headers in the build dir over the source dir since, for
        # instance, the user might have an srcdir == builddir Autotools build
        # in their source tree. Many projects that are moving to Meson have
        # both Meson and Autotools in parallel as part of the transition.
        if target.implicit_include_directories:
            commands += self.get_source_dir_include_args(target, compiler)
        if target.implicit_include_directories:
            commands += self.get_build_dir_include_args(target, compiler)
        # Finally add the private dir for the target to the include path. This
        # must override everything else and must be the final path added.
        commands += compiler.get_include_args(self.get_target_private_dir(target), False)
        return commands

    # Returns a dictionary, mapping from each compiler src type (e.g. 'c', 'cpp', etc.) to a list of compiler arg strings
    # used for that respective src type.
    # Currently used for the purpose of populating VisualStudio intellisense fields but possibly useful in other scenarios.
    def generate_common_compile_args_per_src_type(self, target: build.BuildTarget) -> dict[str, list[str]]:
        src_type_to_args = {}

        use_pch = self.target_uses_pch(target)

        for src_type_str in target.compilers.keys():
            compiler = target.compilers[src_type_str]
            commands = self._generate_single_compile_base_args(target, compiler)

            # Include PCH header as first thing as it must be the first one or it will be
            # ignored by gcc https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100462
            if use_pch and 'mw' not in compiler.id:
                commands += self.get_pch_include_args(compiler, target)

            commands += self._generate_single_compile_target_args(target, compiler)

            # Metrowerks compilers require PCH include args to come after intraprocedural analysis args
            if use_pch and 'mw' in compiler.id:
                commands += self.get_pch_include_args(compiler, target)

            commands = commands.compiler.compiler_args(commands)

            src_type_to_args[src_type_str] = commands.to_native()
        return src_type_to_args

    def generate_single_compile(self, target: build.BuildTarget, src,
                                is_generated: bool = False, header_deps=None,
                                order_deps: T.Optional[T.List['mesonlib.FileOrString']] = None,
                                extra_args: T.Optional[T.List[str]] = None,
                                unity_sources: T.Optional[T.List[mesonlib.FileOrString]] = None) -> None:
        """
        Compiles C/C++, ObjC/ObjC++, Fortran, and D sources
        """
        header_deps = header_deps if header_deps is not None else []
        order_deps = order_deps if order_deps is not None else []

        if isinstance(src, str) and src.endswith('.h'):
            raise AssertionError(f'BUG: sources should not contain headers {src!r}')

        compiler = get_compiler_for_source(target.compilers.values(), src)
        commands = self._generate_single_compile_base_args(target, compiler)

        # Include PCH header as first thing as it must be the first one or it will be
        # ignored by gcc https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100462
        use_pch = self.target_uses_pch(target)
        if use_pch and 'mw' not in compiler.id:
            commands += self.get_pch_include_args(compiler, target)

        commands += self._generate_single_compile_target_args(target, compiler)

        # Metrowerks compilers require PCH include args to come after intraprocedural analysis args
        if use_pch and 'mw' in compiler.id:
            commands += self.get_pch_include_args(compiler, target)

        commands = commands.compiler.compiler_args(commands)

        # Create introspection information
        if is_generated is False:
            self.create_target_source_introspection(target, compiler, commands, [src], [], unity_sources)
        else:
            self.create_target_source_introspection(target, compiler, commands, [], [src], unity_sources)

        build_dir = self.environment.get_build_dir()
        if isinstance(src, File):
            rel_src = src.rel_to_builddir(self.build_to_src)
            if os.path.isabs(rel_src):
                # Source files may not be from the source directory if they originate in source-only libraries,
                # so we can't assert that the absolute path is anywhere in particular.
                if src.is_built:
                    assert rel_src.startswith(build_dir)
                    rel_src = rel_src[len(build_dir) + 1:]
        elif is_generated:
            raise AssertionError(f'BUG: broken generated source file handling for {src!r}')
        else:
            raise InvalidArguments(f'Invalid source type: {src!r}')
        obj_basename = self.object_filename_from_source(target, src)
        rel_obj = os.path.join(self.get_target_private_dir(target), obj_basename)
        dep_file = compiler.depfile_for_object(rel_obj)

        # Add MSVC debug file generation compile flags: /Fd /FS
        commands += self.get_compile_debugfile_args(compiler, target, rel_obj)

        # PCH handling
        if self.target_uses_pch(target):
            pchlist = target.get_pch(compiler.language)
        else:
            pchlist = []
        if not pchlist:
            pch_dep = []
        elif compiler.id == 'intel':
            pch_dep = []
        else:
            arr = []
            i = os.path.join(self.get_target_private_dir(target), compiler.get_pch_name(pchlist[0]))
            arr.append(i)
            pch_dep = arr

        compiler_name = self.compiler_to_rule_name(compiler)
        extra_deps = []
        if compiler.get_language() == 'fortran':
            # Can't read source file to scan for deps if it's generated later
            # at build-time. Skip scanning for deps, and just set the module
            # outdir argument instead.
            # https://github.com/mesonbuild/meson/issues/1348
            if not is_generated:
                abs_src = Path(build_dir) / rel_src
                extra_deps += self.get_fortran_deps(compiler, abs_src, target)
            if not self.use_dyndeps_for_fortran():
                # Dependency hack. Remove once multiple outputs in Ninja is fixed:
                # https://groups.google.com/forum/#!topic/ninja-build/j-2RfBIOd_8
                for modname, srcfile in self.fortran_deps[target.get_basename()].items():
                    modfile = os.path.join(self.get_target_private_dir(target),
                                           compiler.module_name_to_filename(modname))

                    if srcfile == src:
                        crstr = self.get_rule_suffix(target.for_machine)
                        depelem = NinjaBuildElement(self.all_outputs,
                                                    modfile,
                                                    'FORTRAN_DEP_HACK' + crstr,
                                                    rel_obj)
                        self.add_build(depelem)
            commands += compiler.get_module_outdir_args(self.get_target_private_dir(target))
        if extra_args is not None:
            commands.extend(extra_args)

        element = NinjaBuildElement(self.all_outputs, rel_obj, compiler_name, rel_src)
        self.add_header_deps(target, element, header_deps)
        for d in extra_deps:
            element.add_dep(d)
        for d in order_deps:
            if isinstance(d, File):
                d = d.rel_to_builddir(self.build_to_src)
            elif not self.has_dir_part(d):
                d = os.path.join(self.get_target_private_dir(target), d)
            element.add_orderdep(d)
        element.add_dep(pch_dep)
        for i in self.get_fortran_orderdeps(target, compiler):
            element.add_orderdep(i)
        if dep_file:
            element.add_item('DEPFILE', dep_file)
        if compiler.get_language() == 'cuda':
            # for cuda, we manually escape target name ($out) as $CUDA_ESCAPED_TARGET because nvcc doesn't support `-MQ` flag
            def quote_make_target(targetName: str) -> str:
                # this escape implementation is taken from llvm
                result = ''
                for (i, c) in enumerate(targetName):
                    if c in {' ', '\t'}:
                        # Escape the preceding backslashes
                        for j in range(i - 1, -1, -1):
                            if targetName[j] == '\\':
                                result += '\\'
                            else:
                                break
                        # Escape the space/tab
                        result += '\\'
                    elif c == '$':
                        result += '$'
                    elif c == '#':
                        result += '\\'
                    result += c
                return result
            element.add_item('CUDA_ESCAPED_TARGET', quote_make_target(rel_obj))
        element.add_item('ARGS', commands)

        self.add_dependency_scanner_entries_to_element(target, compiler, element, src)
        self.add_build(element)
        assert isinstance(rel_obj, str)
        assert isinstance(rel_src, str)
        return (rel_obj, rel_src.replace('\\', '/'))

    def add_dependency_scanner_entries_to_element(self, target: build.BuildTarget, compiler, element, src):
        if not self.should_use_dyndeps_for_target(target):
            return
        if isinstance(target, build.CompileTarget):
            return
        extension = os.path.splitext(src.fname)[1][1:]
        if extension != 'C':
            extension = extension.lower()
        if not (extension in compilers.lang_suffixes['fortran'] or extension in compilers.lang_suffixes['cpp']):
            return
        dep_scan_file = self.get_dep_scan_file_for(target)
        element.add_item('dyndep', dep_scan_file)
        element.add_orderdep(dep_scan_file)

    def get_dep_scan_file_for(self, target: build.BuildTarget) -> str:
        return os.path.join(self.get_target_private_dir(target), 'depscan.dd')

    def add_header_deps(self, target, ninja_element, header_deps):
        for d in header_deps:
            if isinstance(d, File):
                d = d.rel_to_builddir(self.build_to_src)
            elif not self.has_dir_part(d):
                d = os.path.join(self.get_target_private_dir(target), d)
            ninja_element.add_dep(d)

    def has_dir_part(self, fname: mesonlib.FileOrString) -> bool:
        # FIXME FIXME: The usage of this is a terrible and unreliable hack
        if isinstance(fname, File):
            return fname.subdir != ''
        return has_path_sep(fname)

    # Fortran is a bit weird (again). When you link against a library, just compiling a source file
    # requires the mod files that are output when single files are built. To do this right we would need to
    # scan all inputs and write out explicit deps for each file. That is stoo slow and too much effort so
    # instead just have an ordered dependency on the library. This ensures all required mod files are created.
    # The real deps are then detected via dep file generation from the compiler. This breaks on compilers that
    # produce incorrect dep files but such is life.
    def get_fortran_orderdeps(self, target, compiler):
        if compiler.language != 'fortran':
            return []
        return [
            os.path.join(self.get_target_dir(lt), lt.get_filename())
            for lt in itertools.chain(target.link_targets, target.link_whole_targets)
        ]

    def generate_msvc_pch_command(self, target, compiler, pch):
        header = pch[0]
        pchname = compiler.get_pch_name(header)
        dst = os.path.join(self.get_target_private_dir(target), pchname)

        commands = []
        commands += self.generate_basic_compiler_args(target, compiler)

        if len(pch) == 1:
            # Auto generate PCH.
            source = self.create_msvc_pch_implementation(target, compiler.get_language(), pch[0])
            pch_header_dir = os.path.dirname(os.path.join(self.build_to_src, target.get_source_subdir(), header))
            commands += compiler.get_include_args(pch_header_dir, False)
        else:
            source = os.path.join(self.build_to_src, target.get_source_subdir(), pch[1])

        just_name = os.path.basename(header)
        (objname, pch_args) = compiler.gen_pch_args(just_name, source, dst)
        commands += pch_args
        commands += self._generate_single_compile(target, compiler)
        commands += self.get_compile_debugfile_args(compiler, target, objname)
        dep = dst + '.' + compiler.get_depfile_suffix()

        link_objects = [objname] if compiler.should_link_pch_object() else []

        return commands, dep, dst, link_objects, source

    def generate_gcc_pch_command(self, target, compiler, pch):
        commands = self._generate_single_compile(target, compiler)
        if pch.split('.')[-1] == 'h' and compiler.language == 'cpp':
            # Explicitly compile pch headers as C++. If Clang is invoked in C++ mode, it actually warns if
            # this option is not set, and for gcc it also makes sense to use it.
            commands += ['-x', 'c++-header']
        dst = os.path.join(self.get_target_private_dir(target),
                           os.path.basename(pch) + '.' + compiler.get_pch_suffix())
        dep = dst + '.' + compiler.get_depfile_suffix()
        return commands, dep, dst, []  # Gcc does not create an object file during pch generation.

    def generate_mwcc_pch_command(self, target, compiler, pch):
        commands = self._generate_single_compile(target, compiler)
        dst = os.path.join(self.get_target_private_dir(target),
                           os.path.basename(pch) + '.' + compiler.get_pch_suffix())
        dep = os.path.splitext(dst)[0] + '.' + compiler.get_depfile_suffix()
        return commands, dep, dst, []  # mwcc compilers do not create an object file during pch generation.

    def generate_pch(self, target, header_deps=None):
        header_deps = header_deps if header_deps is not None else []
        pch_objects = []
        for lang in ['c', 'cpp']:
            pch = target.get_pch(lang)
            if not pch:
                continue
            if not has_path_sep(pch[0]) or not has_path_sep(pch[-1]):
                msg = f'Precompiled header of {target.get_basename()!r} must not be in the same ' \
                      'directory as source, please put it in a subdirectory.'
                raise InvalidArguments(msg)
            compiler: Compiler = target.compilers[lang]
            if compiler.get_argument_syntax() == 'msvc':
                (commands, dep, dst, objs, src) = self.generate_msvc_pch_command(target, compiler, pch)
                extradep = os.path.join(self.build_to_src, target.get_source_subdir(), pch[0])
            elif compiler.id == 'intel':
                # Intel generates on target generation
                continue
            elif 'mwcc' in compiler.id:
                src = os.path.join(self.build_to_src, target.get_source_subdir(), pch[0])
                (commands, dep, dst, objs) = self.generate_mwcc_pch_command(target, compiler, pch[0])
                extradep = None
            else:
                src = os.path.join(self.build_to_src, target.get_source_subdir(), pch[0])
                (commands, dep, dst, objs) = self.generate_gcc_pch_command(target, compiler, pch[0])
                extradep = None
            pch_objects += objs
            rulename = self.compiler_to_pch_rule_name(compiler)
            elem = NinjaBuildElement(self.all_outputs, objs + [dst], rulename, src)
            if extradep is not None:
                elem.add_dep(extradep)
            self.add_header_deps(target, elem, header_deps)
            elem.add_item('ARGS', commands)
            elem.add_item('DEPFILE', dep)
            self.add_build(elem)
        return pch_objects

    def get_target_shsym_filename(self, target):
        # Always name the .symbols file after the primary build output because it always exists
        targetdir = self.get_target_private_dir(target)
        return os.path.join(targetdir, target.get_filename() + '.symbols')

    def generate_shsym(self, target):
        target_file = self.get_target_filename(target)
        symname = self.get_target_shsym_filename(target)
        elem = NinjaBuildElement(self.all_outputs, symname, 'SHSYM', target_file)
        # The library we will actually link to, which is an import library on Windows (not the DLL)
        elem.add_item('IMPLIB', self.get_target_filename_for_linking(target))
        if self.environment.is_cross_build():
            elem.add_item('CROSS', '--cross-host=' + self.environment.machines[target.for_machine].system)
        self.add_build(elem)

    def get_import_filename(self, target):
        return os.path.join(self.get_target_dir(target), target.import_filename)

    def get_target_type_link_args(self, target, linker):
        commands = []
        if isinstance(target, build.Executable):
            # Currently only used with the Swift compiler to add '-emit-executable'
            commands += linker.get_std_exe_link_args()
            # If export_dynamic, add the appropriate linker arguments
            if target.export_dynamic:
                commands += linker.gen_export_dynamic_link_args(self.environment)
            # If implib, and that's significant on this platform (i.e. Windows using either GCC or Visual Studio)
            if target.import_filename:
                commands += linker.gen_import_library_args(self.get_import_filename(target))
            if target.pie:
                commands += linker.get_pie_link_args()
            if target.vs_module_defs and hasattr(linker, 'gen_vs_module_defs_args'):
                commands += linker.gen_vs_module_defs_args(target.vs_module_defs.rel_to_builddir(self.build_to_src))
        elif isinstance(target, build.SharedLibrary):
            if isinstance(target, build.SharedModule):
                commands += linker.get_std_shared_module_link_args(target.get_options())
            else:
                commands += linker.get_std_shared_lib_link_args()
            # All shared libraries are PIC
            commands += linker.get_pic_args()
            if not isinstance(target, build.SharedModule) or target.force_soname:
                # Add -Wl,-soname arguments on Linux, -install_name on OS X
                commands += linker.get_soname_args(
                    self.environment, target.prefix, target.name, target.suffix,
                    target.soversion, target.darwin_versions)
            # This is only visited when building for Windows using either GCC or Visual Studio
            if target.vs_module_defs and hasattr(linker, 'gen_vs_module_defs_args'):
                commands += linker.gen_vs_module_defs_args(target.vs_module_defs.rel_to_builddir(self.build_to_src))
            # This is only visited when building for Windows using either GCC or Visual Studio
            if target.import_filename:
                commands += linker.gen_import_library_args(self.get_import_filename(target))
        elif isinstance(target, build.StaticLibrary):
            commands += linker.get_std_link_args(self.environment, not target.should_install())
        else:
            raise RuntimeError('Unknown build target type.')
        return commands

    def get_target_type_link_args_post_dependencies(self, target, linker):
        commands = []
        if isinstance(target, build.Executable):
            # If win_subsystem is significant on this platform, add the appropriate linker arguments.
            # Unfortunately this can't be done in get_target_type_link_args, because some misguided
            # libraries (such as SDL2) add -mwindows to their link flags.
            m = self.environment.machines[target.for_machine]

            if m.is_windows() or m.is_cygwin():
                commands += linker.get_win_subsystem_args(target.win_subsystem)
        return commands

    def get_link_whole_args(self, linker, target):
        use_custom = False
        if linker.id == 'msvc':
            # Expand our object lists manually if we are on pre-Visual Studio 2015 Update 2
            # (incidentally, the "linker" here actually refers to cl.exe)
            if mesonlib.version_compare(linker.version, '<19.00.23918'):
                use_custom = True

        if use_custom:
            objects_from_static_libs: T.List[ExtractedObjects] = []
            for dep in target.link_whole_targets:
                l = dep.extract_all_objects(False)
                objects_from_static_libs += self.determine_ext_objs(l, '')
                objects_from_static_libs.extend(self.flatten_object_list(dep)[0])

            return objects_from_static_libs
        else:
            target_args = self.build_target_link_arguments(linker, target.link_whole_targets)
            return linker.get_link_whole_for(target_args) if target_args else []

    @lru_cache(maxsize=None)
    def guess_library_absolute_path(self, linker, libname, search_dirs, patterns) -> Path:
        from ..compilers.c import CCompiler
        for d in search_dirs:
            for p in patterns:
                trial = CCompiler._get_trials_from_pattern(p, d, libname)
                if not trial:
                    continue
                trial = CCompiler._get_file_from_list(self.environment, trial)
                if not trial:
                    continue
                # Return the first result
                return trial

    def guess_external_link_dependencies(self, linker, target, commands, internal):
        # Ideally the linker would generate dependency information that could be used.
        # But that has 2 problems:
        # * currently ld cannot create dependency information in a way that ninja can use:
        #   https://sourceware.org/bugzilla/show_bug.cgi?id=22843
        # * Meson optimizes libraries from the same build using the symbol extractor.
        #   Just letting ninja use ld generated dependencies would undo this optimization.
        search_dirs = OrderedSet()
        libs = OrderedSet()
        absolute_libs = []

        build_dir = self.environment.get_build_dir()
        # the following loop sometimes consumes two items from command in one pass
        it = iter(linker.native_args_to_unix(commands))
        for item in it:
            if item in internal and not item.startswith('-'):
                continue

            if item.startswith('-L'):
                if len(item) > 2:
                    path = item[2:]
                else:
                    try:
                        path = next(it)
                    except StopIteration:
                        mlog.warning("Generated linker command has -L argument without following path")
                        break
                if not os.path.isabs(path):
                    path = os.path.join(build_dir, path)
                search_dirs.add(path)
            elif item.startswith('-l'):
                if len(item) > 2:
                    lib = item[2:]
                else:
                    try:
                        lib = next(it)
                    except StopIteration:
                        mlog.warning("Generated linker command has '-l' argument without following library name")
                        break
                libs.add(lib)
            elif os.path.isabs(item) and self.environment.is_library(item) and os.path.isfile(item):
                absolute_libs.append(item)

        guessed_dependencies = []
        # TODO The get_library_naming requirement currently excludes link targets that use d or fortran as their main linker
        try:
            static_patterns = linker.get_library_naming(self.environment, LibType.STATIC, strict=True)
            shared_patterns = linker.get_library_naming(self.environment, LibType.SHARED, strict=True)
            search_dirs = tuple(search_dirs) + tuple(linker.get_library_dirs(self.environment))
            for libname in libs:
                # be conservative and record most likely shared and static resolution, because we don't know exactly
                # which one the linker will prefer
                staticlibs = self.guess_library_absolute_path(linker, libname,
                                                              search_dirs, static_patterns)
                sharedlibs = self.guess_library_absolute_path(linker, libname,
                                                              search_dirs, shared_patterns)
                if staticlibs:
                    guessed_dependencies.append(staticlibs.resolve().as_posix())
                if sharedlibs:
                    guessed_dependencies.append(sharedlibs.resolve().as_posix())
        except (mesonlib.MesonException, AttributeError) as e:
            if 'get_library_naming' not in str(e):
                raise

        return guessed_dependencies + absolute_libs

    def generate_prelink(self, target, obj_list):
        assert isinstance(target, build.StaticLibrary)
        prelink_name = os.path.join(self.get_target_private_dir(target), target.name + '-prelink.o')
        elem = NinjaBuildElement(self.all_outputs, [prelink_name], 'CUSTOM_COMMAND', obj_list)

        prelinker = target.get_prelinker()
        cmd = prelinker.exelist
```