Response:
The user wants to understand the functionality of the `interpreter.py` file in the Frida dynamic instrumentation tool. This file seems to be part of Meson, the build system used by Frida. I need to analyze the provided code snippet and identify its main responsibilities.

Here's a breakdown of the functionalities and how they relate to the user's request:

1. **Target Definition and Management:** The code includes functions for defining and managing build targets like executables, static libraries, shared libraries, and modules. This is directly related to how software is built, which can involve reverse engineering (e.g., analyzing the output binaries).
2. **Source File Handling:** The code handles source files, including checking their existence and converting them into internal representations. This is a fundamental aspect of any build system.
3. **Compiler and Language Settings:** The code interacts with compiler settings and language-specific arguments. Understanding how code is compiled is crucial for reverse engineering.
4. **Dependency Management:** The code manages dependencies between different build targets. This is important for understanding the structure and relationships within a software project.
5. **Variable Management:** The code allows setting and getting variables within the Meson build environment. This is a common feature in build systems for configuration and control.
6. **Error Handling:** The code includes checks for invalid arguments and other errors during the build process. Understanding potential error scenarios can be helpful in debugging.
7. **Subproject Management:** The code seems to handle subprojects, indicating a modular build system.
8. **Feature Flags:** The code uses `@FeatureNew` and `@FeatureDeprecated` decorators, suggesting a system for managing language features and deprecations, which can be relevant when working with different versions of a tool.

Now, let's address the specific questions raised by the user:

*   **Relationship to Reverse Engineering:** Building and understanding the build process is a crucial step in reverse engineering. Knowing how the target software is compiled and linked provides valuable insights into its structure and functionality.
*   **Involvement of Binary Low-Level, Linux, Android Kernel/Framework:** While the code itself is Python, the actions it orchestrates (compiling and linking) directly involve binary manipulation and interaction with the operating system. For Android, this includes the NDK (Native Development Kit) and the specific build processes for Android libraries and executables.
*   **Logical Reasoning (Input/Output):**  The code performs logical checks and transformations based on the input provided in the `meson.build` files. I can create hypothetical scenarios to illustrate this.
*   **Common User Errors:**  The code includes error handling for common mistakes users might make while defining build targets.
*   **User Path to This Code:**  Users interact with this code indirectly by writing `meson.build` files that describe their project. When Meson is run, it interprets these files and uses the logic in `interpreter.py` to generate the actual build commands.
*   **Summary of Functionality:** I need to condense the identified functionalities into a concise summary.
这是 Frida 动态Instrumentation 工具的 Meson 构建系统中负责解释 `meson.build` 文件的核心模块。它主要的功能是**解析和执行 `meson.build` 文件中的指令，从而构建项目的构建图（build graph）和生成构建系统所需的元数据**。

以下是该文件功能的详细列举，并结合逆向方法、二进制底层、Linux/Android 内核及框架知识、逻辑推理、用户错误以及用户操作路径进行说明：

**核心功能：**

1. **目标 (Target) 定义和管理:**
    *   该文件包含了 `build_target` 函数，用于创建各种构建目标，例如可执行文件 (`build.Executable`)、静态库 (`build.StaticLibrary`)、共享库 (`build.SharedLibrary`)、共享模块 (`build.SharedModule`) 和 JAR 包 (`build.Jar`)。
    *   `add_target` 函数将创建的构建目标添加到构建系统的内部数据结构中 (`self.build.targets`)，并处理目标名称的唯一性。
    *   `build_both_libraries` 函数可以同时构建共享库和静态库。
    *   **逆向方法举例:** 在逆向分析一个 Android 应用时，了解其 native 库是如何构建的（例如，是否使用了静态链接、共享链接，以及依赖了哪些库）对于理解其行为和进行 hook 操作至关重要。`interpreter.py` 中定义了如何根据 `meson.build` 文件中的 `shared_library` 或 `static_library` 指令创建这些库的构建规则。
    *   **二进制底层知识举例:**  共享库和静态库的构建过程涉及到二进制文件的链接、符号解析等底层操作。`interpreter.py` 虽然不直接执行这些操作，但它会根据 `meson.build` 的配置（例如 `link_with` 参数）生成相应的链接器命令。
    *   **Linux/Android 内核及框架知识举例:** 构建 Android 平台的 native 库可能需要特定的编译和链接选项，例如针对特定 Android API 级别的 NDK 路径。`interpreter.py` 会处理这些平台相关的配置。

2. **源代码处理:**
    *   `source_strings_to_files` 函数将 `meson.build` 文件中指定的源代码字符串转换为 `mesonlib.File` 对象，方便后续处理。
    *   `check_sources_exist` 函数检查指定的源文件是否存在。
    *   **逆向方法举例:**  在逆向分析时，可能需要查看目标二进制文件的源代码。`interpreter.py` 负责解析 `meson.build` 中指定的源代码路径，这有助于定位源代码位置。

3. **编译器和语言参数处理:**
    *   `__process_language_args` 函数处理不同编程语言的特定编译参数（例如 C++ 的 `-std=c++17`），将 `<lang>_args` 形式的参数转换为统一的 `language_args` 字典。
    *   `kwarg_strings_to_includedirs` 函数处理头文件包含路径。
    *   **逆向方法举例:**  不同的编译选项会影响生成二进制文件的结构和行为。了解编译选项可以帮助逆向工程师理解代码的编译方式和可能的优化。
    *   **二进制底层知识举例:**  编译器参数直接影响生成的机器码，例如优化级别会影响代码执行效率和调试难度。

4. **依赖管理:**
    *   构建目标可以依赖其他目标或外部库。`interpreter.py` 处理 `dependencies` 参数，将依赖关系添加到构建图中。
    *   `add_stdlib_info` 函数处理标准库依赖。
    *   **逆向方法举例:**  理解目标二进制文件依赖的库对于逆向分析至关重要。可以使用工具（如 `ldd` 在 Linux 上）查看动态链接库依赖。`interpreter.py` 负责解析 `meson.build` 中的依赖声明，这反映了最终二进制文件的依赖关系。

5. **变量管理:**
    *   `func_set_variable`、`func_get_variable`、`func_is_variable` 和 `func_unset_variable` 函数提供了在 Meson 构建环境中设置、获取、检查和取消设置变量的功能。
    *   **逻辑推理举例:**
        *   **假设输入 (meson.build):** `my_option = get_variable('my_custom_option', 'default_value')`
        *   **假设输入 (命令行):** 运行 Meson 时未定义 `my_custom_option`。
        *   **输出:** `func_get_variable` 函数将返回 'default_value'。

6. **子项目管理:**
    *   `is_subproject` 函数判断当前是否在子项目中。

7. **功能标志:**
    *   `@FeatureNew` 和 `@FeatureDeprecated` 装饰器用于标记 Meson 的新特性和废弃特性，有助于跟踪 Meson 的发展和兼容性。

8. **路径处理:**
    *   `absolute_builddir_path_for` 和 `relative_builddir_path_for` 函数用于计算构建目录的绝对和相对路径。

9. **错误处理:**
    *   代码中包含多种异常处理，例如 `InvalidArguments` (无效参数) 和 `InvalidCode` (无效代码)，用于捕获 `meson.build` 文件中的错误。
    *   **用户或编程常见的使用错误举例:**
        *   **错误:** 在 `meson.build` 文件中，定义了两个同名的 target：
            ```meson
            executable('my_program', 'main.c')
            executable('my_program', 'another.c')
            ```
        *   **结果:** `add_target` 函数会抛出 `InvalidCode` 异常，提示 "Tried to create target "my\_program", but a target of that name already exists."

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户创建或修改 `meson.build` 文件:** 用户编写 `meson.build` 文件来描述项目的构建方式，例如指定源文件、依赖库、编译选项等。
2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令，指示 Meson 开始构建配置过程。
3. **Meson 解析 `meson.build` 文件:** Meson 读取并解析 `meson.build` 文件。在这个过程中，会调用 `interpreter.py` 中的各种函数来解释 `meson.build` 文件中的指令。
4. **`interpreter.py` 执行指令:** 例如，当遇到 `executable()` 函数时，会调用 `self.build_executable()`，最终会调用 `self.build_target()` 来创建可执行目标的描述。
5. **构建图生成:** `interpreter.py` 的执行过程会逐步构建项目的构建图，描述各个构建目标及其依赖关系。
6. **生成构建系统元数据:**  `interpreter.py` 的输出是构建系统（例如 Ninja 或 Xcode）所需的元数据文件，这些文件包含了构建目标的详细信息和构建规则。
7. **构建系统执行:**  接下来，用户运行 `ninja` (或其他构建系统命令) 来根据生成的元数据实际执行编译和链接等构建步骤。

**归纳一下它的功能 (第 6 部分总结):**

`frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py` 文件是 Frida 构建过程中至关重要的组成部分。它作为 Meson 构建系统的解释器，负责**解析 `meson.build` 文件，定义和管理构建目标，处理源代码和编译参数，管理依赖关系，并生成用于实际构建过程的元数据**。它的核心职责是将用户在 `meson.build` 文件中声明的构建意图转化为构建系统可以理解和执行的指令。这个过程是 Frida 能够成功编译和构建各种组件的基础。

总而言之，`interpreter.py` 是连接 Frida 构建描述 ( `meson.build` ) 和实际构建执行的桥梁，理解其功能对于理解 Frida 的构建过程至关重要，并且可以帮助进行更深入的逆向分析和定制化构建。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
.subdir, os.path.split(name)[0])
            if os.path.exists(os.path.join(self.source_root, pathseg)):
                raise InvalidArguments(textwrap.dedent(f'''\
                    Target "{name}" has a path segment pointing to directory "{pathseg}". This is an error.
                    To define a target that builds in that directory you must define it
                    in the meson.build file in that directory.
            '''))
        self.validate_forbidden_targets(name)
        # To permit an executable and a shared library to have the
        # same name, such as "foo.exe" and "libfoo.a".
        idname = tobj.get_id()
        subdir = tobj.get_output_subdir()
        namedir = (name, subdir)

        if idname in self.build.targets:
            raise InvalidCode(f'Tried to create target "{name}", but a target of that name already exists.')

        if isinstance(tobj, build.Executable) and namedir in self.build.targetnames:
            FeatureNew.single_use(f'multiple executables with the same name, "{tobj.name}", but different suffixes in the same directory',
                                  '1.3.0', self.subproject, location=self.current_node)

        if isinstance(tobj, build.BuildTarget):
            self.add_languages(tobj.missing_languages, True, tobj.for_machine)
            tobj.process_compilers_late()
            self.add_stdlib_info(tobj)

        self.build.targets[idname] = tobj
        # Only need to add executables to this set
        if isinstance(tobj, build.Executable):
            self.build.targetnames.update([namedir])
        if idname not in self.coredata.target_guids:
            self.coredata.target_guids[idname] = str(uuid.uuid4()).upper()

    @FeatureNew('both_libraries', '0.46.0')
    def build_both_libraries(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType], kwargs: kwtypes.Library) -> build.BothLibraries:
        shared_lib = self.build_target(node, args, kwargs, build.SharedLibrary)
        static_lib = self.build_target(node, args, kwargs, build.StaticLibrary)

        if self.backend.name == 'xcode':
            # Xcode is a bit special in that you can't (at least for the moment)
            # form a library only from object file inputs. The simple but inefficient
            # solution is to use the sources directly. This will lead to them being
            # built twice. This is unfortunate and slow, but at least it works.
            # Feel free to submit patches to get this fixed if it is an
            # issue for you.
            reuse_object_files = False
        elif shared_lib.uses_rust():
            # FIXME: rustc supports generating both libraries in a single invocation,
            # but for now compile twice.
            reuse_object_files = False
        elif any(k.endswith(('static_args', 'shared_args')) and v for k, v in kwargs.items()):
            # Ensure not just the keyword arguments exist, but that they are non-empty.
            reuse_object_files = False
        else:
            reuse_object_files = static_lib.pic

        if reuse_object_files:
            # Replace sources with objects from the shared library to avoid
            # building them twice. We post-process the static library instead of
            # removing sources from args because sources could also come from
            # any InternalDependency, see BuildTarget.add_deps().
            static_lib.objects.append(build.ExtractedObjects(shared_lib, shared_lib.sources, shared_lib.generated, []))
            static_lib.sources = []
            static_lib.generated = []
            # Compilers with no corresponding sources confuses the backend.
            # Keep only compilers used for linking
            static_lib.compilers = {k: v for k, v in static_lib.compilers.items() if k in compilers.clink_langs}

        return build.BothLibraries(shared_lib, static_lib)

    def build_library(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType], kwargs: kwtypes.Library):
        default_library = self.coredata.get_option(OptionKey('default_library', subproject=self.subproject))
        assert isinstance(default_library, str), 'for mypy'
        if default_library == 'shared':
            return self.build_target(node, args, T.cast('kwtypes.StaticLibrary', kwargs), build.SharedLibrary)
        elif default_library == 'static':
            return self.build_target(node, args, T.cast('kwtypes.SharedLibrary', kwargs), build.StaticLibrary)
        elif default_library == 'both':
            return self.build_both_libraries(node, args, kwargs)
        else:
            raise InterpreterException(f'Unknown default_library value: {default_library}.')

    def __convert_file_args(self, raw: T.List[mesonlib.FileOrString]) -> T.Tuple[T.List[mesonlib.File], T.List[str]]:
        """Convert raw target arguments from File | str to File.

        This removes files from the command line and replaces them with string
        values, but adds the files to depends list

        :param raw: the raw arguments
        :return: A tuple of file dependencies and raw arguments
        """
        depend_files: T.List[mesonlib.File] = []
        args: T.List[str] = []
        build_to_source = mesonlib.relpath(self.environment.get_source_dir(),
                                           self.environment.get_build_dir())

        for a in raw:
            if isinstance(a, mesonlib.File):
                depend_files.append(a)
                args.append(a.rel_to_builddir(build_to_source))
            else:
                args.append(a)

        return depend_files, args

    def __process_language_args(self, kwargs: T.Dict[str, T.List[mesonlib.FileOrString]]) -> None:
        """Convert split language args into a combined dictionary.

        The Meson DSL takes arguments in the form `<lang>_args : args`, but in the
        build layer we store these in a single dictionary as `{<lang>: args}`.
        This function extracts the arguments from the DSL format and prepares
        them for the IR.
        """
        d = kwargs.setdefault('depend_files', [])
        new_args: T.DefaultDict[str, T.List[str]] = collections.defaultdict(list)

        for l in compilers.all_languages:
            deps, args = self.__convert_file_args(kwargs[f'{l}_args'])
            new_args[l] = args
            d.extend(deps)
        kwargs['language_args'] = new_args

    @T.overload
    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.Executable, targetclass: T.Type[build.Executable]) -> build.Executable: ...

    @T.overload
    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.StaticLibrary, targetclass: T.Type[build.StaticLibrary]) -> build.StaticLibrary: ...

    @T.overload
    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.SharedLibrary, targetclass: T.Type[build.SharedLibrary]) -> build.SharedLibrary: ...

    @T.overload
    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.SharedModule, targetclass: T.Type[build.SharedModule]) -> build.SharedModule: ...

    @T.overload
    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.Jar, targetclass: T.Type[build.Jar]) -> build.Jar: ...

    def build_target(self, node: mparser.BaseNode, args: T.Tuple[str, SourcesVarargsType],
                     kwargs: T.Union[kwtypes.Executable, kwtypes.StaticLibrary, kwtypes.SharedLibrary, kwtypes.SharedModule, kwtypes.Jar],
                     targetclass: T.Type[T.Union[build.Executable, build.StaticLibrary, build.SharedModule, build.SharedLibrary, build.Jar]]
                     ) -> T.Union[build.Executable, build.StaticLibrary, build.SharedModule, build.SharedLibrary, build.Jar]:
        name, sources = args
        for_machine = kwargs['native']
        if kwargs.get('rust_crate_type') == 'proc-macro':
            # Silently force to native because that's the only sensible value
            # and rust_crate_type is deprecated any way.
            for_machine = MachineChoice.BUILD
        # Avoid mutating, since there could be other references to sources
        sources = sources + kwargs['sources']
        if any(isinstance(s, build.BuildTarget) for s in sources):
            FeatureBroken.single_use('passing references to built targets as a source file', '1.1.0', self.subproject,
                                     'Consider using `link_with` or `link_whole` if you meant to link, or dropping them as otherwise they are ignored.',
                                     node)
        if any(isinstance(s, build.ExtractedObjects) for s in sources):
            FeatureBroken.single_use('passing object files as sources', '1.1.0', self.subproject,
                                     'Pass these to the `objects` keyword instead, they are ignored when passed as sources.',
                                     node)
        # Go ahead and drop these here, since they're only allowed through for
        # backwards compatibility anyway
        sources = [s for s in sources
                   if not isinstance(s, (build.BuildTarget, build.ExtractedObjects))]

        # due to lack of type checking, these are "allowed" for legacy reasons
        if not isinstance(kwargs['install'], bool):
            FeatureBroken.single_use('install kwarg with non-boolean value', '1.3.0', self.subproject,
                                     'This was never intended to work, and is essentially the same as using `install: true` regardless of value.',
                                     node)

        sources = self.source_strings_to_files(sources)
        objs = kwargs['objects']
        kwargs['dependencies'] = extract_as_list(kwargs, 'dependencies')
        kwargs['extra_files'] = self.source_strings_to_files(kwargs['extra_files'])
        self.check_sources_exist(os.path.join(self.source_root, self.subdir), sources)
        if targetclass not in {build.Executable, build.SharedLibrary, build.SharedModule, build.StaticLibrary, build.Jar}:
            mlog.debug('Unknown target type:', str(targetclass))
            raise RuntimeError('Unreachable code')
        self.__process_language_args(kwargs)
        if targetclass is build.StaticLibrary:
            for lang in compilers.all_languages - {'java'}:
                deps, args = self.__convert_file_args(kwargs.get(f'{lang}_static_args', []))
                kwargs['language_args'][lang].extend(args)
                kwargs['depend_files'].extend(deps)
        elif targetclass is build.SharedLibrary:
            for lang in compilers.all_languages - {'java'}:
                deps, args = self.__convert_file_args(kwargs.get(f'{lang}_shared_args', []))
                kwargs['language_args'][lang].extend(args)
                kwargs['depend_files'].extend(deps)
        if targetclass is not build.Jar:
            self.kwarg_strings_to_includedirs(kwargs)

        # Filter out kwargs from other target types. For example 'soversion'
        # passed to library() when default_library == 'static'.
        kwargs = {k: v for k, v in kwargs.items() if k in targetclass.known_kwargs | {'language_args'}}

        srcs: T.List['SourceInputs'] = []
        struct: T.Optional[build.StructuredSources] = build.StructuredSources()
        for s in sources:
            if isinstance(s, build.StructuredSources):
                struct = struct + s
            else:
                srcs.append(s)

        if not struct:
            struct = None
        else:
            # Validate that we won't end up with two outputs with the same name.
            # i.e, don't allow:
            # [structured_sources('foo/bar.rs'), structured_sources('bar/bar.rs')]
            for v in struct.sources.values():
                outputs: T.Set[str] = set()
                for f in v:
                    o: T.List[str]
                    if isinstance(f, str):
                        o = [os.path.basename(f)]
                    elif isinstance(f, mesonlib.File):
                        o = [f.fname]
                    else:
                        o = f.get_outputs()
                    conflicts = outputs.intersection(o)
                    if conflicts:
                        raise InvalidArguments.from_node(
                            f"Conflicting sources in structured sources: {', '.join(sorted(conflicts))}",
                            node=node)
                    outputs.update(o)

        kwargs['include_directories'] = self.extract_incdirs(kwargs)

        if targetclass is build.Executable:
            kwargs = T.cast('kwtypes.Executable', kwargs)
            if kwargs['gui_app'] is not None:
                if kwargs['win_subsystem'] is not None:
                    raise InvalidArguments.from_node(
                        'Executable got both "gui_app", and "win_subsystem" arguments, which are mutually exclusive',
                        node=node)
                if kwargs['gui_app']:
                    kwargs['win_subsystem'] = 'windows'
            if kwargs['win_subsystem'] is None:
                kwargs['win_subsystem'] = 'console'

            if kwargs['implib']:
                if kwargs['export_dynamic'] is False:
                    FeatureDeprecated.single_use('implib overrides explict export_dynamic off', '1.3.0', self.subprojct,
                                                 'Do not set ths if want export_dynamic disabled if implib is enabled',
                                                 location=node)
                kwargs['export_dynamic'] = True
            elif kwargs['export_dynamic']:
                if kwargs['implib'] is False:
                    raise InvalidArguments('"implib" keyword" must not be false if "export_dynamic" is set and not false.')
                kwargs['implib'] = True
            if kwargs['export_dynamic'] is None:
                kwargs['export_dynamic'] = False
            if kwargs['implib'] is None:
                kwargs['implib'] = False

        target = targetclass(name, self.subdir, self.subproject, for_machine, srcs, struct, objs,
                             self.environment, self.compilers[for_machine], self.coredata.is_build_only, kwargs)

        self.add_target(name, target)
        self.project_args_frozen = True
        return target

    def kwarg_strings_to_includedirs(self, kwargs: kwtypes._BuildTarget) -> None:
        if kwargs['d_import_dirs']:
            items = kwargs['d_import_dirs']
            cleaned_items: T.List[build.IncludeDirs] = []
            for i in items:
                if isinstance(i, str):
                    # BW compatibility. This was permitted so we must support it
                    # for a few releases so people can transition to "correct"
                    # path declarations.
                    if os.path.normpath(i).startswith(self.environment.get_source_dir()):
                        mlog.warning('''Building a path to the source dir is not supported. Use a relative path instead.
This will become a hard error in the future.''', location=self.current_node)
                        i = os.path.relpath(i, os.path.join(self.environment.get_source_dir(), self.subdir))
                        i = self.build_incdir_object([i])
                cleaned_items.append(i)
            kwargs['d_import_dirs'] = cleaned_items

    def add_stdlib_info(self, target):
        for l in target.compilers.keys():
            dep = self.build.stdlibs[target.for_machine].get(l, None)
            if dep:
                target.add_deps(dep)

    def check_sources_exist(self, subdir, sources):
        for s in sources:
            if not isinstance(s, str):
                continue # This means a generated source and they always exist.
            fname = os.path.join(subdir, s)
            if not os.path.isfile(fname):
                raise InterpreterException(f'Tried to add non-existing source file {s}.')

    def absolute_builddir_path_for(self, subdir: str) -> str:
        return os.path.join(self.environment.build_dir,
                            self.relative_builddir_path_for(subdir))

    def relative_builddir_path_for(self, subdir: str) -> str:
        return build.compute_build_subdir(subdir, self.coredata.is_build_only)

    # Only permit object extraction from the same subproject
    def validate_extraction(self, buildtarget: mesonlib.HoldableObject) -> None:
        if self.subproject != buildtarget.subproject:
            raise InterpreterException('Tried to extract objects from a different subproject.')

    def is_subproject(self) -> bool:
        return self.subproject != ''

    @typed_pos_args('set_variable', str, object)
    @noKwargs
    @noArgsFlattening
    @noSecondLevelHolderResolving
    def func_set_variable(self, node: mparser.BaseNode, args: T.Tuple[str, object], kwargs: 'TYPE_kwargs') -> None:
        varname, value = args
        self.set_variable(varname, value, holderify=True)

    @typed_pos_args('get_variable', (str, Disabler), optargs=[object])
    @noKwargs
    @noArgsFlattening
    @unholder_return
    def func_get_variable(self, node: mparser.BaseNode, args: T.Tuple[T.Union[str, Disabler], T.Optional[object]],
                          kwargs: 'TYPE_kwargs') -> 'TYPE_var':
        varname, fallback = args
        if isinstance(varname, Disabler):
            return varname

        try:
            return self.variables[varname]
        except KeyError:
            if fallback is not None:
                return self._holderify(fallback)
        raise InterpreterException(f'Tried to get unknown variable "{varname}".')

    @typed_pos_args('is_variable', str)
    @noKwargs
    def func_is_variable(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> bool:
        return args[0] in self.variables

    @FeatureNew('unset_variable', '0.60.0')
    @typed_pos_args('unset_variable', str)
    @noKwargs
    def func_unset_variable(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> None:
        varname = args[0]
        try:
            del self.variables[varname]
        except KeyError:
            raise InterpreterException(f'Tried to unset unknown variable "{varname}".')

    @staticmethod
    def machine_from_native_kwarg(kwargs: T.Dict[str, T.Any]) -> MachineChoice:
        native = kwargs.get('native', False)
        if not isinstance(native, bool):
            raise InvalidArguments('Argument to "native" must be a boolean.')
        return MachineChoice.BUILD if native else MachineChoice.HOST

    @FeatureNew('is_disabler', '0.52.0')
    @typed_pos_args('is_disabler', object)
    @noKwargs
    def func_is_disabler(self, node: mparser.BaseNode, args: T.Tuple[object], kwargs: 'TYPE_kwargs') -> bool:
        return isinstance(args[0], Disabler)

    @noKwargs
    @FeatureNew('range', '0.58.0')
    @typed_pos_args('range', int, optargs=[int, int])
    def func_range(self, node, args: T.Tuple[int, T.Optional[int], T.Optional[int]], kwargs: T.Dict[str, T.Any]) -> P_OBJ.RangeHolder:
        start, stop, step = args
        # Just like Python's range, we allow range(stop), range(start, stop), or
        # range(start, stop, step)
        if stop is None:
            stop = start
            start = 0
        if step is None:
            step = 1
        # This is more strict than Python's range()
        if start < 0:
            raise InterpreterException('start cannot be negative')
        if stop < start:
            raise InterpreterException('stop cannot be less than start')
        if step < 1:
            raise InterpreterException('step must be >=1')
        return P_OBJ.RangeHolder(start, stop, step, subproject=self.subproject)
```