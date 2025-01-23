Response:
The user wants a summary of the functionality of the provided Python code snippet. The code is part of the Ninja backend for the Meson build system, specifically dealing with how to generate build instructions for various types of targets.

Here's a breakdown of how to approach the response:

1. **Identify the Core Function:** The primary function is `Adds the source file introspection information for a language of a target`. However, the surrounding code in `generate_target` provides much more context and functionality.

2. **Analyze `generate_target`:** This function seems to be the central orchestrator for creating build rules for different target types. Identify the major steps involved:
    * Handling different target types (custom, run, jar, rust, cs, swift, compile).
    * Processing dependencies.
    * Handling source files (preexisting, generated, transpiled).
    * Compilation.
    * Linking.
    * Generating dependency scanning information.

3. **Examine Helper Functions:**  Note the roles of functions like `create_target_linker_introspection`, `generate_vala_compile`, `generate_cython_transpile`, `generate_single_compile`, `generate_link`, `generate_dependency_scan_target`, etc.

4. **Look for Interactions with Reverse Engineering:** Consider where the process of building software intersects with reverse engineering. Introspection data itself is valuable for understanding the structure of the built artifacts. Dependency scanning reveals relationships between files, which is crucial in reverse engineering.

5. **Find Interactions with Low-Level Concepts:** Look for keywords and function names that suggest interaction with the operating system, compilers, linkers, and potentially kernel/framework concepts (though this snippet is more focused on the build process than direct kernel interaction).

6. **Identify Logic and Potential Inputs/Outputs:** Focus on conditional statements and how the code reacts to different input parameters (target types, languages, compiler arguments, etc.). Think about what data structures are being manipulated.

7. **Spot Potential User Errors:** Consider scenarios where incorrect configuration or usage of Meson might lead to issues that would involve this code.

8. **Trace User Operations:** Think about the steps a user takes when using Meson that would lead to this code being executed. This involves the Meson configuration process and the actual build command.

9. **Focus on the Specific Snippet:**  While `generate_target` is important context, pay close attention to the `create_target_source_introspection` function itself, its inputs, and the data it stores.

10. **Structure the Response:** Organize the findings into clear categories: core function, relationship to reverse engineering, low-level concepts, logic and I/O, user errors, user operations, and finally, a concise summary of the specific snippet.
这是 `frida/subprojects/frida-node/releng/meson/mesonbuild/backend/ninjabackend.py` 文件的一部分，主要负责向 Ninja 构建系统添加关于目标源文件内省的信息。Ninja 是一个专注于速度的构建系统。

**功能归纳 (基于提供的代码片段):**

这个代码片段的主要功能是 **收集和存储编译目标的源文件信息，以便后续的构建和分析过程使用**。具体来说，它负责维护一个关于每个编译目标的源文件及其编译方式的详细记录。

**详细功能拆解与说明:**

1. **添加源文件内省信息 (create_target_source_introspection):**
   - **目的:** 记录一个编译目标所使用的源文件及其编译器的信息。
   - **存储格式:** 使用 `self.introspection_data` 字典来存储信息，结构如下：
     ```python
     self.introspection_data = {
         '<target ID>': {
             (<语言>, 元组(编译器参数)): {
                 'language': 'lang',
                 'compiler': ['comp', 'exe', 'list'],
                 'parameters': ['UNIQUE', 'parameter', 'list'],
                 'sources': [],
                 'generated_sources': [],
                 'unity_sources': [],
             }
         }
     }
     ```
   - **流程:**
     - 获取目标 ID 和编译器语言。
     - 检查是否已存在具有相同语言和编译器参数的条目。
     - 如果不存在，则创建一个新的条目，包含语言、编译器可执行文件列表、编译器参数以及初始的源文件列表。
     - 将提供的源文件和生成的源文件添加到相应的列表中，并将文件路径转换为绝对路径。
     - 支持 Unity 构建 (一种编译优化技术)。

2. **创建目标链接器内省信息 (create_target_linker_introspection):**
   - **目的:** 记录一个目标的链接器及其参数信息。
   - **存储格式:** 也是存储在 `self.introspection_data` 中，结构如下：
     ```python
     self.introspection_data = {
         '<target ID>': {
             元组(链接器参数): {
                 'linker': ['linker', 'exe', 'list'],
                 'parameters': ['parameter', 'list'],
             }
         }
     }
     ```
   - **流程:**
     - 获取目标 ID。
     - 检查是否已存在具有相同链接器参数的条目。
     - 如果不存在，则创建一个新的条目，包含链接器可执行文件列表和链接器参数。

3. **生成目标 (generate_target):**
   - **目的:** 为给定的构建目标生成 Ninja 构建规则。
   - **核心流程:**
     - 处理不同类型的目标 (`CustomTarget`, `RunTarget`, `Jar`, Rust, C#, Swift 等)。
     - 处理目标依赖项，递归地为依赖目标生成构建规则。
     - 处理各种源文件类型 (预先存在的、生成的、通过 transpiler 生成的)。
     - 调用特定语言的编译处理函数 (例如 `generate_vala_compile`, `generate_cython_transpile`)。
     - 处理 Unity 构建。
     - 调用 `generate_single_compile` 为单个源文件生成编译规则。
     - 确定链接器并调用 `generate_link` 生成链接规则。
     - 调用 `generate_dependency_scan_target` 生成依赖扫描规则 (用于动态依赖发现)。
     - 将生成的构建元素添加到 Ninja 构建描述中。
     - **调用了 `create_target_source_introspection` 来记录源文件信息。**

**与逆向方法的关系 (举例说明):**

- **静态分析支持:**  内省数据记录了每个编译单元的源文件、编译器和编译参数。这些信息对于逆向工程师理解目标二进制文件的构建过程至关重要。例如，通过查看编译器参数，可以推断出是否启用了某些安全特性（如 ASLR、PIE）或者是否使用了特定的优化级别，这些都会影响逆向分析的策略。
    - **例子:**  如果内省数据中显示某个 C++ 目标使用了 `-fno-rtti` 编译选项，逆向工程师可以知道运行时类型信息 (RTTI) 不可用，这会影响他们在调试和分析多态类时的策略。

- **依赖关系分析:** `generate_dependency_scan_target` 生成的依赖扫描信息可以帮助逆向工程师理解模块之间的依赖关系。这对于理解大型程序的架构和控制流非常有帮助。
    - **例子:**  通过分析依赖扫描信息，逆向工程师可以确定哪些库或模块被链接到目标二进制文件中，从而缩小分析范围，专注于关键组件。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

- **编译器和链接器知识:**  代码中涉及到获取编译器和链接器的可执行文件列表 (`comp.get_exelist()`, `linker.get_linker_exelist()`) 以及传递给它们的参数。这需要对不同编译器（如 GCC, Clang, MSVC）和链接器的工作原理有深入的了解，包括它们处理不同语言和平台的方式。
    - **例子:**  对于 Android 平台，可能会涉及到使用 Android NDK 提供的编译器和链接器，以及传递特定的架构 (ARM, ARM64) 和 API 级别的参数。

- **目标文件和库:** 代码中处理了目标文件 (`.o`, `.obj`) 和各种类型的库 (静态库 `.a`, `.lib`，共享库 `.so`, `.dll`) 的生成和链接。这需要了解不同平台下这些二进制文件的格式和链接过程。
    - **例子:**  在 Linux 中，共享库的链接涉及到动态链接器和符号解析，而在 Windows 中则涉及到 DLL 和导入表。

- **Unity 构建:**  代码中对 Unity 构建的处理涉及到将多个源文件合并成一个编译单元来提高编译速度。理解 Unity 构建的原理和潜在的副作用（例如符号冲突）有助于理解某些构建优化的策略。

**逻辑推理 (假设输入与输出):**

假设我们有一个名为 `my_library` 的 C++ 共享库目标，它包含 `source1.cpp` 和 `source2.cpp` 两个源文件，使用 g++ 编译器，并且没有特殊的编译选项。

**假设输入:**

- `target`:  一个代表 `my_library` 共享库的 `build.SharedLibrary` 对象。
- `comp`:  一个代表 g++ 编译器的 `Compiler` 对象。
- `sources`:  包含 `source1.cpp` 和 `source2.cpp` 的 `File` 对象列表。
- `parameters`:  一个空的 `CompilerArgs` 对象（因为没有特殊编译选项）。

**可能的输出 (create_target_source_introspection):**

```python
self.introspection_data['my_library'] = {
    ('cpp', tuple()): {
        'language': 'cpp',
        'compiler': ['g++', '...'],  # g++ 的可执行文件路径
        'parameters': [],
        'sources': ['/path/to/source1.cpp', '/path/to/source2.cpp'],
        'generated_sources': [],
        'unity_sources': [],
    }
}
```

**涉及用户或编程常见的使用错误 (举例说明):**

- **未安装必要的编译器:** 如果用户尝试构建一个 C++ 目标，但系统中没有安装 g++ 或 clang，Meson 会报错，而这个代码片段在执行前会先检查编译器的可用性。但如果用户配置了错误的编译器路径，可能会导致构建失败，而内省数据会记录下这个错误的配置。

- **错误的依赖关系:** 如果用户在 `meson.build` 文件中错误地声明了目标之间的依赖关系，可能导致构建顺序错误。虽然这个代码片段本身不直接处理依赖关系的声明，但 `generate_target` 函数会处理依赖目标的生成，错误的依赖关系可能会导致 `process_target_dependencies` 提前或延迟执行。

- **编译器参数错误:**  用户可能在 `meson.build` 中传递了无效的编译器参数，这会导致编译失败。内省数据会记录下这些错误的参数，有助于调试。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户编写 `meson.build` 文件:** 在该文件中定义了需要构建的目标，包括库、可执行文件等，以及它们的源文件和依赖关系。
2. **用户运行 `meson setup builddir`:** Meson 读取 `meson.build` 文件，解析构建配置，并生成用于特定构建后端（例如 Ninja）的构建文件。
3. **Ninja 后端被调用:**  `ninjabackend.py` 文件中的代码会被执行，负责将 Meson 的构建描述转换为 Ninja 的构建规则。
4. **处理到编译目标:** 当 Meson 处理到一个需要编译的目标时，会调用 `generate_target` 函数。
5. **收集源文件信息:** 在 `generate_target` 函数中，会调用 `create_target_source_introspection` 来收集该目标的源文件、编译器和编译参数等信息。
6. **生成 Ninja 构建规则:**  根据收集到的信息，以及其他相关信息（如依赖关系），生成 Ninja 的构建规则并写入 `build.ninja` 文件。
7. **用户运行 `ninja`:** Ninja 读取 `build.ninja` 文件，并根据其中的规则执行实际的编译和链接操作。

作为调试线索，查看 `self.introspection_data` 的内容可以帮助理解 Meson 是如何理解和处理特定的编译目标的，例如：

- 确认是否识别出了正确的源文件。
- 检查是否使用了预期的编译器和编译参数。
- 了解 Unity 构建是否被启用。

**总结提供的代码片段的功能:**

这个代码片段的核心功能是 **为 Ninja 构建系统记录和管理编译目标的源文件和编译器信息**。它通过 `create_target_source_introspection` 函数将这些信息存储在 `self.introspection_data` 字典中，以便在后续的构建和分析过程中使用。`create_target_linker_introspection` 负责记录链接器信息。 `generate_target` 是一个更高级别的函数，它调用了这些内省函数，并负责生成整个目标的 Ninja 构建规则。这些信息对于理解构建过程、进行静态分析和调试都非常有价值。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
Adds the source file introspection information for a language of a target

        Internal introspection storage format:
        self.introspection_data = {
            '<target ID>': {
                <id tuple>: {
                    'language: 'lang',
                    'compiler': ['comp', 'exe', 'list'],
                    'parameters': ['UNIQUE', 'parameter', 'list'],
                    'sources': [],
                    'generated_sources': [],
                }
            }
        }
        '''
        tid = target.get_id()
        lang = comp.get_language()
        tgt = self.introspection_data[tid]
        # Find an existing entry or create a new one
        id_hash = (lang, tuple(parameters))
        src_block = tgt.get(id_hash, None)
        if src_block is None:
            # Convert parameters
            if isinstance(parameters, CompilerArgs):
                parameters = parameters.to_native(copy=True)
            parameters = comp.compute_parameters_with_absolute_paths(parameters, self.build_dir)
            # The new entry
            src_block = {
                'language': lang,
                'compiler': comp.get_exelist(),
                'parameters': parameters,
                'sources': [],
                'generated_sources': [],
                'unity_sources': [],
            }
            tgt[id_hash] = src_block

        def compute_path(file: mesonlib.FileOrString) -> str:
            """ Make source files absolute """
            if isinstance(file, File):
                return file.absolute_path(self.source_dir, self.build_dir)
            return os.path.normpath(os.path.join(self.build_dir, file))

        src_block['sources'].extend(compute_path(x) for x in sources)
        src_block['generated_sources'].extend(compute_path(x) for x in generated_sources)
        if unity_sources:
            src_block['unity_sources'].extend(compute_path(x) for x in unity_sources)

    def create_target_linker_introspection(self, target: build.Target, linker: T.Union[Compiler, StaticLinker], parameters):
        tid = target.get_id()
        tgt = self.introspection_data[tid]
        lnk_hash = tuple(parameters)
        lnk_block = tgt.get(lnk_hash, None)
        if lnk_block is None:
            if isinstance(parameters, CompilerArgs):
                parameters = parameters.to_native(copy=True)

            if isinstance(linker, Compiler):
                linkers = linker.get_linker_exelist()
            else:
                linkers = linker.get_exelist()

            lnk_block = {
                'linker': linkers,
                'parameters': parameters,
            }
            tgt[lnk_hash] = lnk_block

    def generate_target(self, target):
        try:
            if isinstance(target, build.BuildTarget):
                os.makedirs(self.get_target_private_dir_abs(target))
        except FileExistsError:
            pass
        if isinstance(target, build.CustomTarget):
            self.generate_custom_target(target)
        if isinstance(target, build.RunTarget):
            self.generate_run_target(target)
        compiled_sources = []
        source2object = {}
        name = target.get_id()
        if name in self.processed_targets:
            return
        self.processed_targets.add(name)
        # Initialize an empty introspection source list
        self.introspection_data[name] = {}
        # Generate rules for all dependency targets
        self.process_target_dependencies(target)

        self.generate_shlib_aliases(target, self.get_target_dir(target))

        # If target uses a language that cannot link to C objects,
        # just generate for that language and return.
        if isinstance(target, build.Jar):
            self.generate_jar_target(target)
            return
        if target.uses_rust():
            self.generate_rust_target(target)
            return
        if 'cs' in target.compilers:
            self.generate_cs_target(target)
            return
        if 'swift' in target.compilers:
            self.generate_swift_target(target)
            return

        # CompileTarget compiles all its sources and does not do a final link.
        # This is, for example, a preprocessor.
        is_compile_target = isinstance(target, build.CompileTarget)

        # Preexisting target C/C++ sources to be built; dict of full path to
        # source relative to build root and the original File object.
        target_sources: T.MutableMapping[str, File]

        # GeneratedList and CustomTarget sources to be built; dict of the full
        # path to source relative to build root and the generating target/list
        generated_sources: T.MutableMapping[str, File]

        # List of sources that have been transpiled from a DSL (like Vala) into
        # a language that is handled below, such as C or C++
        transpiled_sources: T.List[str]

        if 'vala' in target.compilers:
            # Sources consumed by valac are filtered out. These only contain
            # C/C++ sources, objects, generated libs, and unknown sources now.
            target_sources, generated_sources, \
                transpiled_sources = self.generate_vala_compile(target)
        elif 'cython' in target.compilers:
            target_sources, generated_sources, \
                transpiled_sources = self.generate_cython_transpile(target)
        else:
            target_sources = self.get_target_sources(target)
            generated_sources = self.get_target_generated_sources(target)
            transpiled_sources = []
        self.scan_fortran_module_outputs(target)
        # Generate rules for GeneratedLists
        self.generate_generator_list_rules(target)

        # Generate rules for building the remaining source files in this target
        outname = self.get_target_filename(target)
        obj_list = []
        is_unity = target.is_unity
        header_deps = []
        unity_src = []
        unity_deps = [] # Generated sources that must be built before compiling a Unity target.
        header_deps += self.get_generated_headers(target)

        if is_unity:
            # Warn about incompatible sources if a unity build is enabled
            langs = set(target.compilers.keys())
            langs_cant = langs.intersection(backends.LANGS_CANT_UNITY)
            if langs_cant:
                langs_are = langs = ', '.join(langs_cant).upper()
                langs_are += ' are' if len(langs_cant) > 1 else ' is'
                msg = f'{langs_are} not supported in Unity builds yet, so {langs} ' \
                      f'sources in the {target.name!r} target will be compiled normally'
                mlog.log(mlog.red('FIXME'), msg)

        # Get a list of all generated headers that will be needed while building
        # this target's sources (generated sources and preexisting sources).
        # This will be set as dependencies of all the target's sources. At the
        # same time, also deal with generated sources that need to be compiled.
        generated_source_files = []
        for rel_src in generated_sources.keys():
            raw_src = File.from_built_relative(rel_src)
            if self.environment.is_source(rel_src):
                if is_unity and self.get_target_source_can_unity(target, rel_src):
                    unity_deps.append(raw_src)
                    abs_src = os.path.join(self.environment.get_build_dir(), rel_src)
                    unity_src.append(abs_src)
                else:
                    generated_source_files.append(raw_src)
            elif self.environment.is_object(rel_src):
                obj_list.append(rel_src)
            elif self.environment.is_library(rel_src) or modules.is_module_library(rel_src):
                pass
            elif is_compile_target:
                generated_source_files.append(raw_src)
            else:
                # Assume anything not specifically a source file is a header. This is because
                # people generate files with weird suffixes (.inc, .fh) that they then include
                # in their source files.
                header_deps.append(raw_src)

        # For D language, the object of generated source files are added
        # as order only deps because other files may depend on them
        d_generated_deps = []

        # These are the generated source files that need to be built for use by
        # this target. We create the Ninja build file elements for this here
        # because we need `header_deps` to be fully generated in the above loop.
        for src in generated_source_files:
            if self.environment.is_llvm_ir(src):
                o, s = self.generate_llvm_ir_compile(target, src)
            else:
                o, s = self.generate_single_compile(target, src, True, order_deps=header_deps)
            compiled_sources.append(s)
            source2object[s] = o
            obj_list.append(o)
            if s.split('.')[-1] in compilers.lang_suffixes['d']:
                d_generated_deps.append(o)

        use_pch = self.target_uses_pch(target)
        if use_pch and target.has_pch():
            pch_objects = self.generate_pch(target, header_deps=header_deps)
        else:
            pch_objects = []

        o, od = self.flatten_object_list(target)
        obj_targets = [t for t in od if t.uses_fortran()]
        obj_list.extend(o)

        fortran_order_deps = [File(True, *os.path.split(self.get_target_filename(t))) for t in obj_targets]
        fortran_inc_args: T.List[str] = []
        if target.uses_fortran():
            fortran_inc_args = mesonlib.listify([target.compilers['fortran'].get_include_args(
                self.get_target_private_dir(t), is_system=False) for t in obj_targets])

        # Generate compilation targets for sources generated by transpilers.
        #
        # Do not try to unity-build the generated source files, as these
        # often contain duplicate symbols and will fail to compile properly.
        #
        # Gather all generated source files and header before generating the
        # compilation rules, to be able to add correct dependencies on the
        # generated headers.
        transpiled_source_files = []
        for src in transpiled_sources:
            raw_src = File.from_built_relative(src)
            # Generated targets are ordered deps because the must exist
            # before the sources compiling them are used. After the first
            # compile we get precise dependency info from dep files.
            # This should work in all cases. If it does not, then just
            # move them from orderdeps to proper deps.
            if self.environment.is_header(src):
                header_deps.append(raw_src)
            else:
                transpiled_source_files.append(raw_src)
        for src in transpiled_source_files:
            o, s = self.generate_single_compile(target, src, True, [], header_deps)
            obj_list.append(o)

        # Generate compile targets for all the preexisting sources for this target
        for src in target_sources.values():
            if not self.environment.is_header(src) or is_compile_target:
                if self.environment.is_llvm_ir(src):
                    o, s = self.generate_llvm_ir_compile(target, src)
                    obj_list.append(o)
                elif is_unity and self.get_target_source_can_unity(target, src):
                    abs_src = os.path.join(self.environment.get_build_dir(),
                                           src.rel_to_builddir(self.build_to_src))
                    unity_src.append(abs_src)
                else:
                    o, s = self.generate_single_compile(target, src, False, [],
                                                        header_deps + d_generated_deps + fortran_order_deps,
                                                        fortran_inc_args)
                    obj_list.append(o)
                    compiled_sources.append(s)
                    source2object[s] = o

        if is_unity:
            for src in self.generate_unity_files(target, unity_src):
                o, s = self.generate_single_compile(target, src, True, unity_deps + header_deps + d_generated_deps,
                                                    fortran_order_deps, fortran_inc_args, unity_src)
                obj_list.append(o)
                compiled_sources.append(s)
                source2object[s] = o
        if is_compile_target:
            # Skip the link stage for this special type of target
            return
        linker, stdlib_args = self.determine_linker_and_stdlib_args(target)
        if isinstance(target, build.StaticLibrary) and target.prelink:
            final_obj_list = self.generate_prelink(target, obj_list)
        else:
            final_obj_list = obj_list
        elem = self.generate_link(target, outname, final_obj_list, linker, pch_objects, stdlib_args=stdlib_args)
        self.generate_dependency_scan_target(target, compiled_sources, source2object, generated_source_files, fortran_order_deps)
        self.add_build(elem)
        #In AIX, we archive shared libraries. If the instance is a shared library, we add a command to archive the shared library
        #object and create the build element.
        if isinstance(target, build.SharedLibrary) and self.environment.machines[target.for_machine].is_aix():
            if target.aix_so_archive:
                elem = NinjaBuildElement(self.all_outputs, linker.get_archive_name(outname), 'AIX_LINKER', [outname])
                self.add_build(elem)

    def should_use_dyndeps_for_target(self, target: 'build.BuildTarget') -> bool:
        if mesonlib.version_compare(self.ninja_version, '<1.10.0'):
            return False
        if 'fortran' in target.compilers:
            return True
        if 'cpp' not in target.compilers:
            return False
        if '-fmodules-ts' in target.extra_args['cpp']:
            return True
        # Currently only the preview version of Visual Studio is supported.
        cpp = target.compilers['cpp']
        if cpp.get_id() != 'msvc':
            return False
        cppversion = target.get_option(OptionKey('std', machine=target.for_machine, lang='cpp'))
        if cppversion not in ('latest', 'c++latest', 'vc++latest'):
            return False
        if not mesonlib.current_vs_supports_modules():
            return False
        if mesonlib.version_compare(cpp.version, '<19.28.28617'):
            return False
        return True

    def generate_dependency_scan_target(self, target: build.BuildTarget, compiled_sources, source2object, generated_source_files: T.List[mesonlib.File],
                                        object_deps: T.List['mesonlib.FileOrString']) -> None:
        if not self.should_use_dyndeps_for_target(target):
            return
        depscan_file = self.get_dep_scan_file_for(target)
        pickle_base = target.name + '.dat'
        pickle_file = os.path.join(self.get_target_private_dir(target), pickle_base).replace('\\', '/')
        pickle_abs = os.path.join(self.get_target_private_dir_abs(target), pickle_base).replace('\\', '/')
        json_abs = os.path.join(self.get_target_private_dir_abs(target), f'{target.name}-deps.json').replace('\\', '/')
        rule_name = 'depscan'
        scan_sources = self.select_sources_to_scan(compiled_sources)

        # Dump the sources as a json list. This avoids potential problems where
        # the number of sources passed to depscan exceeds the limit imposed by
        # the OS.
        with open(json_abs, 'w', encoding='utf-8') as f:
            json.dump(scan_sources, f)
        elem = NinjaBuildElement(self.all_outputs, depscan_file, rule_name, json_abs)
        elem.add_item('picklefile', pickle_file)
        # Add any generated outputs to the order deps of the scan target, so
        # that those sources are present
        for g in generated_source_files:
            elem.orderdeps.add(g.relative_name())
        elem.orderdeps.update(object_deps)
        scaninfo = TargetDependencyScannerInfo(self.get_target_private_dir(target), source2object)
        with open(pickle_abs, 'wb') as p:
            pickle.dump(scaninfo, p)
        self.add_build(elem)

    def select_sources_to_scan(self, compiled_sources):
        # in practice pick up C++ and Fortran files. If some other language
        # requires scanning (possibly Java to deal with inner class files)
        # then add them here.
        all_suffixes = set(compilers.lang_suffixes['cpp']) | set(compilers.lang_suffixes['fortran'])
        selected_sources = []
        for source in compiled_sources:
            ext = os.path.splitext(source)[1][1:]
            if ext != 'C':
                ext = ext.lower()
            if ext in all_suffixes:
                selected_sources.append(source)
        return selected_sources

    def process_target_dependencies(self, target):
        for t in target.get_dependencies():
            if t.get_id() not in self.processed_targets:
                self.generate_target(t)

    def custom_target_generator_inputs(self, target):
        for s in target.sources:
            if isinstance(s, build.GeneratedList):
                self.generate_genlist_for_target(s, target)

    def unwrap_dep_list(self, target):
        deps = []
        for i in target.get_dependencies():
            # FIXME, should not grab element at zero but rather expand all.
            if isinstance(i, list):
                i = i[0]
            # Add a dependency on all the outputs of this target
            for output in i.get_outputs():
                deps.append(os.path.join(self.get_target_dir(i), output))
        return deps

    def generate_custom_target(self, target: build.CustomTarget):
        self.custom_target_generator_inputs(target)
        (srcs, ofilenames, cmd) = self.eval_custom_target_command(target)
        deps = self.unwrap_dep_list(target)
        deps += self.get_target_depend_files(target)
        if target.build_always_stale:
            deps.append('PHONY')
        if target.depfile is None:
            rulename = 'CUSTOM_COMMAND'
        else:
            rulename = 'CUSTOM_COMMAND_DEP'
        elem = NinjaBuildElement(self.all_outputs, ofilenames, rulename, srcs)
        elem.add_dep(deps)
        for d in target.extra_depends:
            # Add a dependency on all the outputs of this target
            for output in d.get_outputs():
                elem.add_dep(os.path.join(self.get_target_dir(d), output))

        cmd, reason = self.as_meson_exe_cmdline(target.command[0], cmd[1:],
                                                extra_bdeps=target.get_transitive_build_target_deps(),
                                                capture=ofilenames[0] if target.capture else None,
                                                feed=srcs[0] if target.feed else None,
                                                env=target.env,
                                                verbose=target.console)
        if reason:
            cmd_type = f' (wrapped by meson {reason})'
        else:
            cmd_type = ''
        if target.depfile is not None:
            depfile = target.get_dep_outname(elem.infilenames)
            rel_dfile = os.path.join(self.get_target_dir(target), depfile)
            abs_pdir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(target))
            os.makedirs(abs_pdir, exist_ok=True)
            elem.add_item('DEPFILE', rel_dfile)
        if target.console:
            elem.add_item('pool', 'console')
        full_name = Path(target.subdir, target.name).as_posix()
        elem.add_item('COMMAND', cmd)
        elem.add_item('description', target.description.format(full_name) + cmd_type)
        self.add_build(elem)
        self.processed_targets.add(target.get_id())

    def build_run_target_name(self, target):
        if target.subproject != '':
            subproject_prefix = f'{target.subproject}@@'
        else:
            subproject_prefix = ''
        return f'{subproject_prefix}{target.name}'

    def generate_run_target(self, target: build.RunTarget):
        target_name = self.build_run_target_name(target)
        if not target.command:
            # This is an alias target, it has no command, it just depends on
            # other targets.
            elem = NinjaBuildElement(self.all_outputs, target_name, 'phony', [])
        else:
            target_env = self.get_run_target_env(target)
            _, _, cmd = self.eval_custom_target_command(target)
            meson_exe_cmd, reason = self.as_meson_exe_cmdline(target.command[0], cmd[1:],
                                                              env=target_env,
                                                              verbose=True)
            cmd_type = f' (wrapped by meson {reason})' if reason else ''
            elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', [])
            elem.add_item('COMMAND', meson_exe_cmd)
            elem.add_item('description', f'Running external command {target.name}{cmd_type}')
            elem.add_item('pool', 'console')
        deps = self.unwrap_dep_list(target)
        deps += self.get_target_depend_files(target)
        elem.add_dep(deps)
        self.add_build(elem)
        self.processed_targets.add(target.get_id())

    def generate_coverage_command(self, elem, outputs: T.List[str], gcovr_exe: T.Optional[str], llvm_cov_exe: T.Optional[str]):
        targets = self.build.get_targets().values()
        use_llvm_cov = False
        exe_args = []
        if gcovr_exe is not None:
            exe_args += ['--gcov', gcovr_exe]
        if llvm_cov_exe is not None:
            exe_args += ['--llvm-cov', llvm_cov_exe]

        for target in targets:
            if not hasattr(target, 'compilers'):
                continue
            for compiler in target.compilers.values():
                if compiler.get_id() == 'clang' and not compiler.info.is_darwin():
                    use_llvm_cov = True
                    break
        elem.add_item('COMMAND', self.environment.get_build_command() +
                      ['--internal', 'coverage'] +
                      outputs +
                      [self.environment.get_source_dir(),
                       os.path.join(self.environment.get_source_dir(),
                                    self.build.get_subproject_dir()),
                       self.environment.get_build_dir(),
                       self.environment.get_log_dir()] +
                      exe_args +
                      (['--use-llvm-cov'] if use_llvm_cov else []))

    def generate_coverage_rules(self, gcovr_exe: T.Optional[str], gcovr_version: T.Optional[str], llvm_cov_exe: T.Optional[str]):
        e = self.create_phony_target('coverage', 'CUSTOM_COMMAND', 'PHONY')
        self.generate_coverage_command(e, [], gcovr_exe, llvm_cov_exe)
        e.add_item('description', 'Generates coverage reports')
        self.add_build(e)
        self.generate_coverage_legacy_rules(gcovr_exe, gcovr_version, llvm_cov_exe)

    def generate_coverage_legacy_rules(self, gcovr_exe: T.Optional[str], gcovr_version: T.Optional[str], llvm_cov_exe: T.Optional[str]):
        e = self.create_phony_target('coverage-html', 'CUSTOM_COMMAND', 'PHONY')
        self.generate_coverage_command(e, ['--html'], gcovr_exe, llvm_cov_exe)
        e.add_item('description', 'Generates HTML coverage report')
        self.add_build(e)

        if gcovr_exe:
            e = self.create_phony_target('coverage-xml', 'CUSTOM_COMMAND', 'PHONY')
            self.generate_coverage_command(e, ['--xml'], gcovr_exe, llvm_cov_exe)
            e.add_item('description', 'Generates XML coverage report')
            self.add_build(e)

            e = self.create_phony_target('coverage-text', 'CUSTOM_COMMAND', 'PHONY')
            self.generate_coverage_command(e, ['--text'], gcovr_exe, llvm_cov_exe)
            e.add_item('description', 'Generates text coverage report')
            self.add_build(e)

            if mesonlib.version_compare(gcovr_version, '>=4.2'):
                e = self.create_phony_target('coverage-sonarqube', 'CUSTOM_COMMAND', 'PHONY')
                self.generate_coverage_command(e, ['--sonarqube'], gcovr_exe, llvm_cov_exe)
                e.add_item('description', 'Generates Sonarqube XML coverage report')
                self.add_build(e)

    def generate_install(self):
        self.create_install_data_files()
        elem = self.create_phony_target('install', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_dep('all')
        elem.add_item('DESC', 'Installing files.')
        elem.add_item('COMMAND', self.environment.get_build_command() + ['install', '--no-rebuild'])
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_tests(self):
        self.serialize_tests()
        cmd = self.environment.get_build_command(True) + ['test', '--no-rebuild']
        if not self.environment.coredata.get_option(OptionKey('stdsplit')):
            cmd += ['--no-stdsplit']
        if self.environment.coredata.get_option(OptionKey('errorlogs')):
            cmd += ['--print-errorlogs']
        elem = self.create_phony_target('test', 'CUSTOM_COMMAND', ['all', 'PHONY'])
        elem.add_item('COMMAND', cmd)
        elem.add_item('DESC', 'Running all tests.')
        elem.add_item('pool', 'console')
        self.add_build(elem)

        # And then benchmarks.
        cmd = self.environment.get_build_command(True) + [
            'test', '--benchmark', '--logbase',
            'benchmarklog', '--num-processes=1', '--no-rebuild']
        elem = self.create_phony_target('benchmark', 'CUSTOM_COMMAND', ['all', 'PHONY'])
        elem.add_item('COMMAND', cmd)
        elem.add_item('DESC', 'Running benchmark suite.')
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_rules(self):
        self.rules = []
        self.ruledict = {}

        self.add_rule_comment(NinjaComment('Rules for module scanning.'))
        self.generate_scanner_rules()
        self.add_rule_comment(NinjaComment('Rules for compiling.'))
        self.generate_compile_rules()
        self.add_rule_comment(NinjaComment('Rules for linking.'))
        self.generate_static_link_rules()
        self.generate_dynamic_link_rules()
        self.add_rule_comment(NinjaComment('Other rules'))
        # Ninja errors out if you have deps = gcc but no depfile, so we must
        # have two rules for custom commands.
        self.add_rule(NinjaRule('CUSTOM_COMMAND', ['$COMMAND'], [], '$DESC',
                                extra='restat = 1'))
        self.add_rule(NinjaRule('CUSTOM_COMMAND_DEP', ['$COMMAND'], [], '$DESC',
                                deps='gcc', depfile='$DEPFILE',
                                extra='restat = 1'))
        self.add_rule(NinjaRule('COPY_FILE', self.environment.get_build_command() + ['--internal', 'copy'],
                                ['$in', '$out'], 'Copying $in to $out'))

        c = self.environment.get_build_command() + \
            ['--internal',
             'regenerate',
             self.environment.get_source_dir(),
             # Ninja always runs from the build_dir. This includes cases where the user moved the
             # build directory and invalidated most references. Make sure it still regenerates.
             '.']
        self.add_rule(NinjaRule('REGENERATE_BUILD',
                                c, [],
                                'Regenerating build files.',
                                extra='generator = 1'))

    def add_rule_comment(self, comment: NinjaComment) -> None:
        self.rules.append(comment)

    def add_build_comment(self, comment: NinjaComment) -> None:
        self.build_elements.append(comment)

    def add_rule(self, rule: NinjaRule) -> None:
        if rule.name in self.ruledict:
            raise MesonException(f'Tried to add rule {rule.name} twice.')
        self.rules.append(rule)
        self.ruledict[rule.name] = rule

    def add_build(self, build: NinjaBuildElement) -> None:
        build.check_outputs()
        self.build_elements.append(build)

        if build.rulename != 'phony':
            # reference rule
            if build.rulename in self.ruledict:
                build.rule = self.ruledict[build.rulename]
            else:
                mlog.warning(f"build statement for {build.outfilenames} references nonexistent rule {build.rulename}")

    def write_rules(self, outfile: T.TextIO) -> None:
        for b in self.build_elements:
            if isinstance(b, NinjaBuildElement):
                b.count_rule_references()

        for r in self.rules:
            r.write(outfile)

    def write_builds(self, outfile: T.TextIO) -> None:
        for b in ProgressBar(self.build_elements, desc='Writing build.ninja'):
            b.write(outfile)
        mlog.log_timestamp("build.ninja generated")

    def generate_phony(self) -> None:
        self.add_build_comment(NinjaComment('Phony build target, always out of date'))
        elem = NinjaBuildElement(self.all_outputs, 'PHONY', 'phony', '')
        self.add_build(elem)

    def generate_jar_target(self, target: build.Jar):
        fname = target.get_filename()
        outname_rel = os.path.join(self.get_target_dir(target), fname)
        src_list = target.get_sources()
        resources = target.get_java_resources()
        class_list = []
        compiler = target.compilers['java']
        c = 'c'
        m = 'm'
        e = ''
        f = 'f'
        main_class = target.get_main_class()
        if main_class != '':
            e = 'e'

        # Add possible java generated files to src list
        generated_sources = self.get_target_generated_sources(target)
        gen_src_list = []
        for rel_src in generated_sources.keys():
            raw_src = File.from_built_relative(rel_src)
            if rel_src.endswith('.java'):
                gen_src_list.append(raw_src)

        compile_args = self.determine_single_java_compile_args(target, compiler)
        for src in src_list + gen_src_list:
            plain_class_path = self.generate_single_java_compile(src, target, compiler, compile_args)
            class_list.append(plain_class_path)
        class_dep_list = [os.path.join(self.get_target_private_dir(target), i) for i in class_list]
        manifest_path = os.path.join(self.get_target_private_dir(target), 'META-INF', 'MANIFEST.MF')
        manifest_fullpath = os.path.join(self.environment.get_build_dir(), manifest_path)
        os.makedirs(os.path.dirname(manifest_fullpath), exist_ok=True)
        with open(manifest_fullpath, 'w', encoding='utf-8') as manifest:
            if any(target.link_targets):
                manifest.write('Class-Path: ')
                cp_paths = [os.path.join(self.get_target_dir(l), l.get_filename()) for l in target.link_targets]
                manifest.write(' '.join(cp_paths))
            manifest.write('\n')
        jar_rule = 'java_LINKER'
        commands = [c + m + e + f]
        commands.append(manifest_path)
        if e != '':
            commands.append(main_class)
        commands.append(self.get_target_filename(target))
        # Java compilation can produce an arbitrary number of output
        # class files for a single source file. Thus tell jar to just
        # grab everything in the final package.
        commands += ['-C', self.get_target_private_dir(target), '.']
        elem = NinjaBuildElement(self.all_outputs, outname_rel, jar_rule, [])
        elem.add_dep(class_dep_list)
        if resources:
            # Copy all resources into the root of the jar.
            elem.add_orderdep(self.__generate_sources_structure(Path(self.get_target_private_dir(target)), resources)[0])
        elem.add_item('ARGS', commands)
        self.add_build(elem)
        # Create introspection information
        self.create_target_source_introspection(target, compiler, compile_args, src_list, gen_src_list)

    def generate_cs_resource_tasks(self, target):
        args = []
        deps = []
        for r in target.resources:
            rel_sourcefile = os.path.join(self.build_to_src, target.subdir, r)
            if r.endswith('.resources'):
                a = '-resource:' + rel_sourcefile
            elif r.endswith('.txt') or r.endswith('.resx'):
                ofilebase = os.path.splitext(os.path.basename(r))[0] + '.resources'
                ofilename = os.path.join(self.get_target_private_dir(target), ofilebase)
                elem = NinjaBuildElement(self.all_outputs, ofilename, "CUSTOM_COMMAND", rel_sourcefile)
                elem.add_item('COMMAND', ['resgen', rel_sourcefile, ofilename])
```