Response:
The user wants a summary of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The specific file is `interpreter.py` within the Meson build system's interpreter.

Here's a plan to address the user's request:

1. **Identify the Core Functionality:** Analyze the methods in the `Interpreter` class to determine its main responsibilities. This will likely involve managing build targets (executables, libraries, etc.), handling dependencies, and interacting with the Meson build system.
2. **Connect to Reverse Engineering:** Look for functions or concepts that directly relate to how Frida might be used for reverse engineering. This might involve building shared libraries that can be injected, or creating executables for analysis.
3. **Identify Low-Level Aspects:** Search for interactions with the operating system (Linux, Android), kernel, or binary formats. This could include handling different library types (static, shared), and how they are built.
4. **Analyze Logic and Assumptions:** Examine functions with conditional logic and try to infer the intended behavior based on different inputs. Look for examples where specific inputs lead to predictable outputs.
5. **Find Potential User Errors:** Identify parts of the code where incorrect user input could cause exceptions or unexpected behavior.
6. **Trace User Actions:** Consider how a user would interact with Frida and the Meson build system to reach the code in this file.
7. **Summarize:**  Combine the findings into a concise summary of the file's functionality.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreter.py` 文件（Frida 动态 instrumentation 工具的一部分）的功能总结：

**核心功能：作为 Meson 构建系统的解释器，负责处理项目构建定义，并将其转换为构建系统可以理解的指令。**

这个 Python 文件是 Meson 构建系统解释器的核心部分，它解析 `meson.build` 文件中的声明，并将其转换为内部数据结构，用于生成最终的构建系统文件（例如，Ninja 构建文件）。

以下是更详细的功能列表，并根据要求进行了分类：

**1. 构建目标管理:**

* **创建和管理构建目标 (Targets):**  该文件中的代码负责创建和管理各种构建目标，例如可执行文件 (`executable()`), 静态库 (`static_library()`), 共享库 (`shared_library()`), 以及同时构建静态库和共享库 (`both_libraries()`)。
* **处理源文件和依赖:** 它接收源文件列表、依赖项和其他构建参数，并将它们与相应的构建目标关联起来。
* **处理不同语言的编译参数:**  它支持为不同的编程语言（如 C, C++, Rust 等）指定特定的编译参数 (`<lang>_args`)。
* **管理安装规则:**  虽然代码片段中没有直接展示安装的具体逻辑，但它会处理 `install` 参数，决定构建目标是否需要安装。
* **处理结构化源文件:**  支持将具有特定输出结构的源文件（`structured_sources`）添加到构建目标。

**2. 与逆向方法的关系 (示例说明):**

* **构建 Frida 模块 (Shared Libraries):** Frida 依赖于将代码注入到目标进程中。这些注入的代码通常是以共享库的形式存在的。 `build_library()` 函数，特别是当 `default_library` 设置为 `shared` 或 `both` 时，就直接参与构建这些用于逆向的动态链接库。
    * **示例:** 开发者使用 Frida SDK 创建了一个名为 `my_frida_module.so` 的模块，用于hook 目标应用的特定函数。在 `meson.build` 文件中，他们会使用 `shared_library('my_frida_module', 'src/my_frida_module.c')` 来定义这个构建目标。 `interpreter.py` 中的代码会解析这个声明，并生成构建 `my_frida_module.so` 的指令。
* **构建 Frida 工具 (Executables):**  Frida 包含一些命令行工具，用于与 Frida Agent 交互。 `executable()` 函数用于构建这些工具。
    * **示例:** `frida-ps` 是一个列出正在运行的进程的 Frida 工具。在 Frida 的构建过程中，`interpreter.py` 会处理类似于 `executable('frida-ps', 'src/frida-ps.c')` 的声明，以生成 `frida-ps` 可执行文件。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识 (示例说明):**

* **处理静态库和共享库:** 代码区分了静态库 (`.a` 或 `.lib`) 和共享库 (`.so` 或 `.dll`) 的构建，这直接关系到操作系统底层的链接机制。在 Linux 和 Android 中，动态链接是核心概念，而共享库是其实现方式。
    * **示例:**  当构建 Frida Agent 时，可能需要将一些功能编译成静态库，以便最终的可执行文件不依赖于这些库的运行时存在。`interpreter.py` 会根据 `static_library()` 的声明来处理这些静态库的编译和链接。
* **处理目标平台的架构 (`for_machine`):** 代码中出现了 `for_machine` 参数，用于指定构建目标的体系结构 (host 或 build)。这对于交叉编译（例如，在 x86 机器上构建 Android ARM 平台的 Frida 工具）至关重要。
    * **示例:**  在为 Android 设备构建 Frida 工具时，`for_machine` 会设置为 `MachineChoice.HOST` (如果是在主机上运行构建) 或 `MachineChoice.BUILD` (如果构建过程本身在目标设备上运行，这种情况较少见)。
* **处理 Windows 子系统 (`win_subsystem`):**  对于 Windows 平台，代码会处理 `win_subsystem` 参数，用于指定可执行文件是控制台程序还是 GUI 应用程序。这直接影响到 Windows PE 文件的头部信息。
    * **示例:**  Frida 的一些工具可能需要图形界面，因此在 `executable()` 声明中会设置 `gui_app: true`，这将最终导致 `win_subsystem` 被设置为 `windows`。

**4. 逻辑推理 (假设输入与输出):**

* **假设输入:**  `meson.build` 文件中定义了两个共享库，名称相同但输出目录不同：
  ```meson
  shared_library('mylib', 'a.c', subdir: 'lib_a')
  shared_library('mylib', 'b.c', subdir: 'lib_b')
  ```
* **输出:** `add_target()` 函数会通过 `idname = tobj.get_id()` 生成唯一的内部标识符，避免名称冲突。`self.build.targets` 字典会存储这两个不同的目标，尽管它们的名称相同。`self.build.targetnames` 则会存储 `(name, subdir)` 的元组，用于区分同名但位于不同子目录的目标。

**5. 涉及用户或编程常见的使用错误 (示例说明):**

* **目标名称冲突:**  如果用户在同一个构建目录中定义了两个名称相同的构建目标（例如，两个名为 `mylib` 的共享库，且没有指定不同的 `subdir`），`add_target()` 函数会抛出 `InvalidCode` 异常。
    * **示例:**  用户在 `meson.build` 中写了两次 `shared_library('mylib', 'src.c')`，这将导致构建失败。
* **路径指向目录:** 如果构建目标的路径部分指向一个已存在的目录，代码会抛出 `InvalidArguments` 异常。
    * **示例:** 如果存在一个名为 `foo` 的目录，并且用户尝试定义一个名为 `foo/bar` 的构建目标，Meson 会阻止这种操作，要求在 `foo` 目录下定义构建目标。
* **将已构建的目标作为源文件传递:**  代码会检查并警告用户不要将已经构建的目标（例如，另一个库）直接作为源文件传递给当前的构建目标。这通常是错误的用法，应该使用 `link_with` 或 `link_whole` 来链接库。
    * **示例:**  `executable('mytool', lib_target)`，其中 `lib_target` 是通过 `shared_library()` 定义的库。Meson 会发出警告，提示用户应该使用 `link_with: lib_target`。

**6. 用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户创建或修改 `meson.build` 文件:** 这是 Meson 构建的入口点，用户在其中声明项目的构建目标、依赖项等。
2. **用户在终端中运行 `meson setup builddir`:** 这个命令指示 Meson 读取 `meson.build` 文件并生成构建系统所需的文件。
3. **Meson 解析 `meson.build` 文件:**  Meson 的解析器会读取 `meson.build` 文件的内容，并将其转换为抽象语法树 (AST)。
4. **Meson 解释器执行 AST:**  `interpreter.py` 文件中的 `Interpreter` 类负责解释这个 AST。当遇到诸如 `executable()`, `shared_library()` 等函数调用时，相应的 `func_executable`, `func_shared_library` 等方法会被调用。
5. **构建目标被创建:** 在这些函数内部，会调用 `build_target()` 方法来创建表示构建目标的内部对象（例如，`build.Executable`, `build.SharedLibrary`）。
6. **目标被添加到构建图中:**  `add_target()` 方法将创建的构建目标添加到 Meson 的内部构建图中。

在调试过程中，如果构建过程中出现错误，例如目标名称冲突，错误消息通常会指向相关的 `meson.build` 文件行号，这可以帮助用户追溯到导致错误的 `executable()` 或 `shared_library()` 调用，最终定位到 `interpreter.py` 中处理这些声明的代码。

**总结 `interpreter.py` 的功能:**

`interpreter.py` 是 Frida 构建过程中至关重要的组成部分，它作为 Meson 构建系统的解释器，负责将用户在 `meson.build` 文件中定义的项目构建蓝图转换为构建系统可以理解的指令。它处理各种构建目标、依赖关系、编译选项，并进行必要的验证，以确保构建定义的正确性。对于 Frida 这样的动态 instrumentation 工具来说，它负责构建用于注入目标进程的共享库以及 Frida 的各种命令行工具。  它还涉及处理不同操作系统和架构的特定构建细节。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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