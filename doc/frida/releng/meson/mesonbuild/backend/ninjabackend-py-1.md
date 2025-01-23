Response:
The user wants a functional summary of the provided Python code, which is a part of the Frida dynamic instrumentation tool. Specifically, they are interested in how this code relates to reverse engineering, low-level concepts (like kernel/framework), logical reasoning within the code, potential user errors, and the path that leads to the execution of this code.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code defines a class `NinjaBackend` (implied from the file path and class methods). This class seems responsible for generating `build.ninja` files, which are used by the Ninja build system. The methods within this class handle the generation of build rules and dependencies for various types of targets (e.g., libraries, executables, custom commands, etc.).

2. **Relate to Reverse Engineering:** Frida is a reverse engineering tool. Therefore, this code, which is part of Frida, must contribute to that goal. The connection lies in how Frida instruments target processes. This code likely defines how the Frida agent or injected code is built and packaged. Key methods to focus on here are those that deal with compiling, linking, and handling dependencies.

3. **Pinpoint Low-Level Aspects:**  Look for keywords and concepts related to operating systems, kernels, and binaries. Terms like "linker," "shared library," "static library," "object files," and mentions of specific platforms (Linux, Android, AIX) are strong indicators. The code also interacts with compilers (gcc, clang, msvc), which are essential for generating low-level executables.

4. **Analyze Logical Reasoning:**  Examine the conditional statements (if/elif/else) and loops. Understand how the code decides which build rules to generate based on the target type, language, and dependencies. Look for instances where the code manipulates data structures (dictionaries, lists) based on certain criteria.

5. **Identify Potential User Errors:** Consider common mistakes a developer might make when using a build system. Misconfigured dependencies, incorrect compiler flags, and issues with generated files are common sources of errors. Look for places where the code handles or might expose these errors.

6. **Trace the User Path:**  Think about the steps a user would take when using Frida that would lead to this code being executed. The most likely scenario is that the user is building Frida from source. Meson is the build system used by Frida, so the execution of `meson` would trigger the code generation process, eventually leading to this file.

7. **Address the "Part 2 of 6" Request:** Acknowledge this constraint and focus on summarizing the functionality *within the provided code snippet*. Avoid speculating too much about what might be happening in other parts of the file.

8. **Structure the Answer:** Organize the findings into the requested categories: functions, relationship to reverse engineering, low-level aspects, logical reasoning, user errors, and user path. Use clear and concise language. Provide specific code examples where relevant.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus only on the explicit mentions of Frida in the code.
* **Correction:** Realize that even though "Frida" isn't mentioned directly within *this* snippet, the file path clearly indicates its origin. Therefore, infer the connection to reverse engineering.
* **Initial thought:** Simply list the methods and their names.
* **Correction:** Group similar methods and describe their overarching purpose (e.g., "handles compilation," "manages linking").
* **Initial thought:**  Focus on technical details only.
* **Correction:** Include user-centric aspects like potential errors and the user's interaction with the build system.

By following this process of analysis, categorization, and refinement, we can arrive at a comprehensive and accurate answer to the user's request.
这是 frida 项目中负责使用 Ninja 构建系统生成构建文件的 Python 代码的一部分。具体来说，它处理了为项目中的各种构建目标（targets）添加源代码内省（introspection）信息的功能。

以下是代码段的功能总结：

**主要功能：为构建目标添加源代码内省信息**

这段代码的核心目的是收集和存储关于构建目标的源代码信息，以便后续的构建过程能够了解需要编译哪些文件，使用哪个编译器，以及相关的编译参数。  它将这些信息存储在 `self.introspection_data` 字典中。

**具体功能点：**

1. **`add_target_source_introspection(self, target, comp, sources, generated_sources, parameters, unity_sources=None)`:**
   - 为特定的构建目标添加源代码信息。
   - `target`:  要添加信息的构建目标对象。
   - `comp`:  用于编译的编译器对象。
   - `sources`:  需要编译的源文件列表。
   - `generated_sources`:  由其他构建步骤生成的源文件列表。
   - `parameters`:  传递给编译器的参数列表。
   - `unity_sources`: 用于 Unity 构建的源文件列表（可选）。
   - **内部逻辑：**
     - 获取目标的 ID 和编译器的语言。
     - 使用语言和参数创建一个唯一的键 `id_hash`。
     - 查找是否已存在该组合的内省信息。如果不存在，则创建一个新的条目。
     - 将相对路径的源文件转换为绝对路径。
     - 将源文件和生成的源文件添加到相应的列表中。
     - 处理 Unity 构建的源文件。

2. **`create_target_linker_introspection(self, target: build.Target, linker: T.Union[Compiler, StaticLinker], parameters)`:**
   - 为构建目标添加链接器信息。
   - `target`:  要添加信息的构建目标对象。
   - `linker`:  用于链接的链接器对象（可以是编译器或静态链接器）。
   - `parameters`:  传递给链接器的参数列表。
   - **内部逻辑：**
     - 获取目标的 ID。
     - 使用参数创建一个唯一的键 `lnk_hash`。
     - 查找是否已存在该参数组合的链接器信息。如果不存在，则创建一个新的条目。
     - 获取链接器的可执行文件列表。
     - 存储链接器信息和参数。

**与逆向方法的关系及举例说明：**

* **了解目标编译方式：** 通过内省信息，逆向工程师可以了解目标程序是如何被编译的，例如使用了哪些编译器选项、包含了哪些源文件。这对于理解程序的构建过程和潜在的安全漏洞非常有用。
    * **举例：** 如果内省信息显示使用了 `-fno-stack-protector` 编译选项，逆向工程师会知道该程序可能存在栈溢出的风险。
* **追踪代码来源：** 内省信息中包含了源文件的路径，这有助于逆向工程师定位代码的具体来源，特别是在大型项目中，可以快速找到特定功能的实现代码。
    * **举例：**  如果逆向分析中发现一个可疑的函数，可以通过内省信息找到该函数所在的源文件。
* **理解依赖关系：** 虽然这段代码主要关注单个目标的源代码，但它也为后续处理依赖关系奠定了基础。逆向工程师可以利用这些信息理解模块之间的依赖关系。

**涉及二进制底层，Linux，Android 内核及框架的知识及举例说明：**

* **编译器和链接器：** 代码中直接操作 `Compiler` 和 `StaticLinker` 对象，这些对象代表了底层的编译和链接工具（如 gcc, clang, ld）。了解这些工具的工作原理对于理解代码的含义至关重要。
* **共享库和静态库：** 代码中提到了 `build.SharedLibrary` 和 `build.StaticLibrary`，这涉及到 Linux 和 Android 等操作系统中动态链接和静态链接的概念。
    * **举例：** 在 Android 逆向中，了解一个库是静态链接还是动态链接的，对于分析其依赖关系和查找漏洞至关重要。
* **目标文件 (.o)：** 代码生成的内省信息最终会用于生成编译命令，将源文件编译成目标文件。目标文件是二进制代码的中间产物，是链接过程的输入。
* **Unity 构建：** 代码中处理了 `unity_sources`，Unity 构建是一种编译优化技术，将多个源文件合并成一个进行编译，以减少编译时间。理解 Unity 构建对于逆向分析采用这种方式构建的程序有所帮助。

**逻辑推理及假设输入与输出：**

* **假设输入：**
    * `target`: 一个表示要构建的共享库的 `build.SharedLibrary` 对象。
    * `comp`: 一个 `gcc` 编译器对象。
    * `sources`: 一个包含 `["source1.c", "source2.c"]` 的列表。
    * `generated_sources`: 一个包含 `["generated.c"]` 的列表。
    * `parameters`: 一个包含 `["-O2", "-Wall"]` 的列表。
* **逻辑推理：**
    - 代码会根据 `target.get_id()` 获取目标 ID。
    - 代码会根据 `comp.get_language()` 获取语言（例如 "c"）。
    - 代码会创建一个 `id_hash` 例如 `("c", ("-O2", "-Wall"))`。
    - 代码会将相对路径的源文件转换为绝对路径（例如 `/path/to/build/source1.c`）。
    - 代码会将源文件和生成的源文件添加到 `self.introspection_data` 中对应目标 ID 的条目中。
* **预期输出（添加到 `self.introspection_data`）：**
   ```python
   {
       '<target_id>': {
           ('c', ('-O2', '-Wall')): {
               'language': 'c',
               'compiler': ['gcc', '...'],
               'parameters': ['-O2', '-Wall'],
               'sources': ['/path/to/build/source1.c', '/path/to/build/source2.c'],
               'generated_sources': ['/path/to/build/generated.c'],
               'unity_sources': []  # 如果没有提供 unity_sources
           }
       }
   }
   ```

**涉及用户或者编程常见的使用错误及举例说明：**

* **错误的源文件路径：** 用户可能在 `meson.build` 文件中指定了错误的源文件路径，导致代码无法找到源文件。
    * **举例：**  `meson.build` 中写了 `sources = ['src/myfile.c']`，但实际文件在 `src/impl/myfile.c`。这段代码会尝试将 `src/myfile.c` 转换为绝对路径，如果文件不存在将会导致后续编译错误。
* **不匹配的编译器参数：**  用户可能传递了与当前编译器不兼容的参数。
    * **举例：**  传递了只有 clang 支持的参数给 gcc 编译器。这段代码会记录这些参数，但实际编译时可能会出错。
* **重复添加内省信息：**  虽然代码中检查了 `id_hash` 是否存在，但在更高级的 Meson 使用场景中，用户可能会以某种方式导致同一目标和编译器配置被多次调用 `add_target_source_introspection`，虽然不会直接报错，但可能会导致内省信息冗余。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 `meson.build` 文件：** 用户编写 `meson.build` 文件来描述项目的构建方式，包括定义可执行文件、库以及它们的源文件和依赖项。
2. **运行 `meson` 命令：** 用户在项目根目录下运行 `meson build` 命令（或者其他配置命令），告诉 Meson 配置构建系统。
3. **Meson 解析 `meson.build`：** Meson 解析 `meson.build` 文件，创建内部的项目模型，包括各种构建目标 (`build.Target` 对象)。
4. **Ninja 后端初始化：** Meson 根据配置选择合适的后端，这里是 Ninja 后端 (`ninjabackend.py`)。
5. **生成目标构建规则：**  Ninja 后端遍历项目模型中的每个构建目标，并调用相应的方法来生成构建规则。对于需要编译源代码的目标，会调用 `add_target_source_introspection` 方法。
6. **传递参数：**  在调用 `add_target_source_introspection` 时，会传递目标对象、编译器对象、解析到的源文件列表、生成的源文件列表以及从 `meson.build` 中获取的或默认的编译器参数。

**这段代码是 Frida 构建过程中的一个中间环节，负责收集构建所需的元数据。如果构建过程中出现与源代码或编译器选项相关的问题，可以查看生成的 `build.ninja` 文件中与内省信息相关的部分，或者调试这段 Python 代码来理解 Meson 是如何处理这些信息的。**

**归纳一下它的功能 (作为第2部分)：**

这段代码的主要功能是**收集和存储关于 Frida 项目中各个构建目标的源代码编译信息和链接器信息**。它通过 `add_target_source_introspection` 和 `create_target_linker_introspection` 方法，将目标的语言、编译器、编译参数、源文件以及生成的源文件等信息记录到 `self.introspection_data` 字典中。 这些内省信息将会在后续的构建步骤中被 Ninja 后端使用，以生成实际的编译和链接命令。 简单来说，**它是 Frida 构建系统中负责收集构建元数据的核心部分。**

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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