Response:
The user wants a functional summary of the provided Python code, which is a part of the Ninja backend for the Meson build system, specifically focusing on how it handles source file introspection for the Frida dynamic instrumentation tool.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The initial comment block clearly states the primary function: adding source file introspection for a target's language. This involves storing information about compilers, parameters, and source files.

2. **Analyze the `add_target_source_introspection` method:** This method is central to the core functionality. It takes a target, compiler, parameters, and source files as input. The code checks for existing entries based on language and parameters. If none exists, it creates a new entry, converting `CompilerArgs` to native format and making paths absolute. It then adds the source and generated source files to the appropriate lists. Key aspects to note are the handling of `CompilerArgs`, absolute path conversion, and the different source lists.

3. **Analyze the `create_target_linker_introspection` method:** This method handles introspection for the linking stage. It stores linker information and parameters. It distinguishes between `Compiler` and `StaticLinker`.

4. **Understand the context:** The code is within a `NinjaBackend` class, part of a larger build system. It interacts with `build.Target`, `Compiler`, `StaticLinker`, and other Meson-specific objects. The `self.introspection_data` dictionary is the central storage.

5. **Relate to reverse engineering:** Introspection inherently relates to reverse engineering. By collecting information about compilation, debuggers and reverse engineering tools can understand how the binary was built and what source code corresponds to which parts of the binary. The compiler, parameters, and source file lists are all valuable.

6. **Identify low-level details:** The code interacts with the filesystem to create directories and manage file paths. The mention of "linux, android kernel & framework" is less directly visible in *this specific code snippet*. While Frida interacts with these, this code focuses on the build system aspects.

7. **Look for logic and assumptions:** The code assumes that the input `parameters` can be a `CompilerArgs` object and handles its conversion. It also makes assumptions about file types when determining if something is a source or a header.

8. **Consider user errors:** Incorrectly configuring the build system, providing wrong file paths, or having conflicting build settings could lead to issues. The code tries to handle some of this by ensuring paths are absolute.

9. **Trace user interaction:**  A user would interact with Meson by writing `meson.build` files, configuring the build directory, and then running the `meson compile` command. This triggers the backend code, including this file.

10. **Synthesize the summary:** Combine the findings from the analysis into a concise summary, addressing all the user's points. Focus on the core function of source file introspection, the data structures used, and how it relates to the different aspects requested by the user. Highlight the key methods and their roles.

11. **Review and refine:** Ensure the summary is accurate, clear, and addresses all aspects of the user's prompt. For instance, initially, I might have overemphasized the Linux/Android aspects, but upon closer inspection, the code is more about build system mechanics. Adjust the emphasis accordingly.
这是 `ninjabackend.py` 文件的一部分，负责 Ninja 构建后端的实现，专注于为目标（target）添加源代码的内省（introspection）信息。以下是它的功能归纳：

**主要功能：为构建目标添加源代码内省信息**

该代码段的核心功能是维护和更新一个关于构建目标及其编译方式的详细记录，存储在 `self.introspection_data` 字典中。 这有助于理解构建过程中使用了哪些源代码、编译器及其参数。

**具体功能分解：**

1. **`add_target_source_introspection(self, target, comp, parameters, sources, generated_sources, unity_sources=None)`:**
   - **添加/更新源代码信息：**  为特定的构建目标 `target`，以及使用特定编译器 `comp` 和编译参数 `parameters` 的一组源代码 `sources` 和生成的源代码 `generated_sources` 添加或更新内省信息。
   - **内部存储格式：**  使用一个嵌套的字典结构 `self.introspection_data` 来存储信息。 顶层键是目标 ID，第二层键是语言和编译参数的元组。
   - **查找或创建条目：**  根据目标 ID、语言和编译参数查找是否已存在相应的内省条目。如果不存在，则创建一个新的条目。
   - **处理编译参数：**  如果提供的 `parameters` 是 `CompilerArgs` 对象，则将其转换为原生格式。
   - **计算绝对路径：**  将源代码文件路径转换为绝对路径，方便后续使用。
   - **区分不同类型的源文件：**  区分普通源代码 (`sources`)、生成的源代码 (`generated_sources`) 和 Unity 构建的源代码 (`unity_sources`)。

2. **`create_target_linker_introspection(self, target, linker, parameters)`:**
   - **添加链接器信息：**  为特定的构建目标 `target`，以及使用的链接器 `linker` 和链接参数 `parameters` 添加内省信息。
   - **存储链接器信息：**  在 `self.introspection_data` 中，以链接参数的元组作为键存储链接器的可执行文件列表和链接参数。
   - **区分编译器和静态链接器：**  根据 `linker` 的类型，获取不同的可执行文件列表 (`get_linker_exelist()` 或 `get_exelist()`)。

**与逆向方法的关联及举例说明：**

源代码内省信息对于逆向工程非常有用，因为它提供了关于目标二进制文件是如何构建的线索。

* **了解编译选项：**  内省信息记录了使用的编译器及其参数。例如，如果参数中包含 `-g`，则表示编译时包含了调试信息，逆向工程师可以使用调试器进行更深入的分析。
* **追踪源代码：**  内省信息记录了参与构建的源代码文件列表。这可以帮助逆向工程师找到与二进制代码对应的源代码，理解其功能和逻辑。例如，通过内省信息，逆向工程师可以知道某个特定的库文件是由哪些 `.c` 或 `.cpp` 文件编译而来的。
* **识别生成代码：**  内省信息区分了原始源代码和生成的源代码。这对于分析使用代码生成技术的项目非常有用。例如，逆向工程师可以知道哪些代码是由 IDL 文件生成的。
* **分析链接过程：**  `create_target_linker_introspection` 记录了链接器和链接参数，这有助于理解库的依赖关系和最终二进制文件的组成。例如，逆向工程师可以查看链接参数，了解链接了哪些共享库。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明：**

虽然这段代码本身更多关注构建系统的逻辑，但其产生的结果与底层的知识息息相关：

* **二进制文件结构：** 内省信息最终帮助理解生成的二进制文件的结构，例如代码段、数据段、符号表等。编译器参数会直接影响这些结构。
* **链接过程：**  链接器将编译后的目标文件组合成最终的可执行文件或库文件。 内省信息中的链接器参数揭示了链接过程中使用的库和选项。
* **操作系统 API：**  构建过程涉及到操作系统提供的各种工具，例如编译器、链接器。内省信息间接地反映了这些工具的使用。
* **Android NDK/SDK：**  如果 Frida 构建涉及 Android 平台，那么内省信息可能会记录与 Android NDK 或 SDK 相关的编译器和参数。例如，目标架构 (arm, arm64, x86) 和 Android API 级别。

**逻辑推理及假设输入与输出：**

假设我们有一个名为 `my_target` 的目标，它包含两个 C++ 源文件 `a.cpp` 和 `b.cpp`，并且使用了 g++ 编译器，编译参数为 `-O2 -Wall`。

**假设输入：**

```python
target = build.BuildTarget(...) # 代表 my_target
comp = compilers.Gcc(...)    # 代表 g++ 编译器
parameters = ['-O2', '-Wall']
sources = [mesonlib.File('','a.cpp'), mesonlib.File('','b.cpp')]
generated_sources = []
```

**预期输出（`self.introspection_data['my_target']` 中的一部分）：**

```python
{
    ('cpp', ('-O2', '-Wall')): {
        'language': 'cpp',
        'compiler': ['g++'], # 实际的可执行文件路径
        'parameters': ['-O2', '-Wall'],
        'sources': ['/path/to/source/a.cpp', '/path/to/source/b.cpp'], # 假设的绝对路径
        'generated_sources': [],
        'unity_sources': [],
    }
}
```

**涉及用户或编程常见的使用错误及举例说明：**

* **错误的源文件路径：** 用户可能在 `meson.build` 文件中指定了不存在的源文件路径，导致内省信息不完整或构建失败。例如，拼写错误的源文件名。
* **不一致的编译参数：**  不同的构建目标可能使用了不一致的编译参数，导致内省信息混乱，难以分析。例如，同一个库在不同的子项目中使用了不同的优化级别。
* **未能正确处理生成的源代码：**  如果构建系统未能正确地将生成的源代码添加到内省信息中，逆向工程师可能无法找到对应的源代码。例如，代码生成工具的配置错误。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户在项目中创建 `meson.build` 文件，定义了构建目标（例如可执行文件、库文件），并指定了源代码、编译器选项等。
2. **用户运行 `meson setup builddir`：** 用户运行 Meson 配置构建目录，Meson 会解析 `meson.build` 文件，并根据用户的配置创建构建系统所需的文件。
3. **用户运行 `meson compile -C builddir` 或 `ninja -C builddir`：** 用户运行编译命令，Ninja 构建工具开始执行构建过程。
4. **`ninjabackend.py` 被调用：**  作为 Ninja 构建后端的实现，`ninjabackend.py` 中的代码会被调用，负责生成 `build.ninja` 文件。
5. **构建目标处理：**  当处理到一个需要编译的目标时，`generate_target` 方法会被调用。
6. **添加内省信息：**  在 `generate_target` 方法内部，`add_target_source_introspection` 和 `create_target_linker_introspection` 方法会被调用，根据目标、编译器、参数和源文件等信息，更新 `self.introspection_data`。

**功能归纳:**

这段代码是 Frida 工具的 Ninja 构建后端的一部分，其核心功能是为构建目标创建和维护详细的源代码内省信息。它记录了每个目标的编译语言、使用的编译器及其参数，以及参与构建的源代码文件（包括原始的和生成的）。 这些信息对于理解构建过程、调试和进行逆向工程至关重要。 通过分析这些内省数据，可以追踪源代码、了解编译选项和链接过程，从而更好地理解目标二进制文件的结构和功能。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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