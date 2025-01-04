Response:
The user wants to understand the functionality of the Python code provided, which is part of the Frida dynamic instrumentation tool. Specifically, they are interested in how this code relates to reverse engineering, low-level details (like kernel or OS concepts), logical reasoning, common user errors, and the debugging process. As this is the final part of a multi-part request, I also need to provide a summary of its overall purpose.

Here's a breakdown of my thought process to analyze the code and address each of the user's points:

1. **Overall Functionality (and Summarization):**  The code primarily deals with defining and managing build targets (executables, libraries, etc.) within the Meson build system. It handles processing source files, dependencies, compiler flags, and other build-related configurations. It acts as an *interpreter* for the Meson build definition files (`meson.build`).

2. **Reverse Engineering Relevance:**  Frida is a reverse engineering tool. This code, while part of Frida's *build system*, doesn't directly perform dynamic instrumentation. However, it's crucial for *building* Frida. Reverse engineers need to compile Frida to use it. Therefore, this code indirectly supports reverse engineering by enabling the creation of the Frida tool itself.

3. **Binary/Low-Level, Linux, Android Kernel/Framework Knowledge:** The code interacts with concepts relevant to building software at a lower level.
    * **Executables and Libraries:** These are fundamental binary concepts. The code defines how they are created.
    * **Shared and Static Libraries:**  Understanding the linking process of these library types is important for low-level development and reverse engineering (e.g., how symbols are resolved).
    * **Compiler Flags (indirectly):** While not explicitly visible in this snippet, the functions likely interact with compiler settings, which are essential for controlling how binaries are built and can impact their runtime behavior.
    * **Native Builds:** The `native` keyword and `MachineChoice` enum hint at cross-compilation scenarios, which are common in embedded systems and Android development.

4. **Logical Reasoning (Hypothetical Input/Output):** I need to identify sections where the code makes decisions based on input.
    * **`build_library` Function:**  The input is the `default_library` option. Based on its value ('shared', 'static', 'both'), the code decides which type of library (or both) to build.
        * **Input:** `default_library = 'shared'`, `name = 'mylib'`, `sources = ['a.c']`
        * **Output:**  A `build.SharedLibrary` object representing the shared library.
    * **`build_target` Function (handling `gui_app` and `win_subsystem`):**
        * **Input:** `gui_app = True`, `win_subsystem = None`
        * **Output:** `win_subsystem` is set to `'windows'`.
        * **Input (Error Case):** `gui_app = True`, `win_subsystem = 'console'`
        * **Output:** Raises an `InvalidArguments` exception.

5. **User/Programming Errors:**  I should look for error handling and validation logic.
    * **Target Name Conflicts:** The code checks for duplicate target names.
        * **Error:** Defining two targets with the same name.
    * **Path Segment in Target Name:**  The code prevents target names from having path segments that correspond to existing directories.
        * **Error:** Naming a target "src" when a "src" directory exists.
    * **Non-existent Source Files:** The `check_sources_exist` function validates source file paths.
        * **Error:** Listing a file that doesn't exist in the `sources` list.
    * **Incorrect `native` argument:** The `machine_from_native_kwarg` function checks the type of the `native` argument.
        * **Error:** Providing a string or number as the value for `native`.

6. **User Operation to Reach Here (Debugging Clue):**  Users interact with Meson through `meson.build` files. To reach this specific code, a user would:
    1. Create or modify a `meson.build` file.
    2. Define a build target (e.g., `executable()`, `library()`).
    3. The Meson tool parses this file.
    4. The interpreter (`interpreter.py`) processes these function calls, leading to the execution of the code provided.

7. **Summarization:** To summarize the functionality for part 6, I will reiterate that this section of `interpreter.py` focuses on the core logic of defining and registering build targets within the Meson build system, handling various target types and their specific configurations.
This Python code snippet is a part of the `interpreter.py` file within the Frida project's build system (using Meson). Its primary function revolves around **defining and registering build targets** like executables and libraries.

Here's a breakdown of its functionalities:

**Core Functionalities:**

* **Target Definition and Registration:**  The code contains functions like `build_target`, `build_library`, and `build_both_libraries` which are responsible for creating and registering different types of build targets. These functions take arguments specifying the target name, source files, dependencies, and other build options.
* **Source File Handling:** It manages source files associated with targets, converting string paths to `mesonlib.File` objects and checking for their existence.
* **Dependency Management:** It handles dependencies between targets and external libraries.
* **Compiler Option Processing:** It processes compiler-specific arguments and flags, potentially based on the target language.
* **Installation Handling:** It determines whether a target should be installed after building.
* **Subproject Management:** It tracks which subproject a target belongs to.
* **Variable Management:** It provides functions to set, get, check, and unset variables within the Meson build environment.
* **Feature Flagging:** It uses `FeatureNew` and `FeatureBroken` to manage and track the introduction or breakage of features in different Meson versions.
* **Structured Sources:** It supports structured sources, allowing for more organized source file management.
* **Include Directory Handling:** It processes and manages include directories for compilation.

**Relation to Reverse Engineering:**

While this specific code doesn't perform dynamic instrumentation directly, it's **crucial for building the Frida tool itself**, which is a powerful reverse engineering tool.

* **Example:** When a Frida developer writes the `meson.build` file to define how the Frida core library should be built, this `interpreter.py` code is responsible for interpreting those instructions and creating the necessary build rules. It ensures that the Frida library is compiled with the correct flags and dependencies, making the core instrumentation engine available for reverse engineers.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This code interacts with these concepts in several ways:

* **Binary Bottom:**
    * **Executables and Libraries:** The core purpose is to define how executables (`build.Executable`) and various types of libraries (`build.SharedLibrary`, `build.StaticLibrary`) are built. These are fundamental binary concepts.
    * **Object Files:** The `build_both_libraries` function demonstrates the handling of object files (`reuse_object_files`) to optimize the build process. Object files are the intermediate output of compilation.
    * **Linking:**  The code implicitly deals with linking by managing dependencies between libraries and executables.
    * **Import Libraries (`implib`):** The handling of the `implib` keyword, specifically for executables, is relevant to Windows binary structure and how dynamic linking works on that platform.
* **Linux and Android Kernel/Framework:**
    * **Shared Libraries (`.so` on Linux, `.so` on Android):** The ability to build shared libraries is essential for both Linux and Android development. Frida itself is often used as a shared library.
    * **Native Builds (`native` keyword):** The code handles the `native` keyword, which is used to specify whether a target should be built for the build machine or the host machine. This is crucial for cross-compilation scenarios, common when targeting Android from a Linux development machine.
    * **Platform-Specific Arguments:** While not explicitly shown in this snippet, the broader context of Meson and Frida allows for defining platform-specific compiler flags and linker options, which are essential when dealing with differences between Linux and Android.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `build_library` function:

* **Hypothetical Input:**
    * `node`:  A parsed Meson AST node representing the `library()` function call.
    * `args`: `('mylib', ['a.c', 'b.c'])`  (Target name "mylib" and source files)
    * `kwargs`: `{'default_library': 'shared'}` (Specifying a shared library as the default)
* **Expected Output:**
    * The function would call `self.build_target` with the `build.SharedLibrary` class, resulting in the creation and registration of a shared library target named "mylib" built from "a.c" and "b.c".

Let's consider the `build_target` function with `gui_app`:

* **Hypothetical Input:**
    * `node`: ...
    * `args`: `('mygui', ['main.c'])`
    * `kwargs`: `{'gui_app': True, 'native': False}`
    * `targetclass`: `build.Executable`
* **Expected Output:**
    * The `kwargs` dictionary would be modified to include `'win_subsystem': 'windows'`, as the code detects `gui_app` is true and defaults to the 'windows' subsystem for executables.

* **Hypothetical Input (Error Case):**
    * `node`: ...
    * `args`: `('mygui', ['main.c'])`
    * `kwargs`: `{'gui_app': True, 'win_subsystem': 'console', 'native': False}`
    * `targetclass`: `build.Executable`
* **Expected Output:**
    * The code would raise an `InvalidArguments` exception because both `gui_app` and `win_subsystem` are explicitly set and are mutually exclusive.

**User or Programming Common Usage Errors:**

* **Typos in Target Names:**  Users might mistype the name of a target, leading to errors when trying to refer to it later. The code checks for duplicate target names, which can help catch some of these issues, but not all.
* **Specifying Non-Existent Source Files:** A common error is to list source files that don't exist in the `sources` argument of target definitions. The `check_sources_exist` function is designed to catch this.
    * **Example:** `executable('myprog', sources: ['main.c', 'missing.c'])` would raise an `InterpreterException`.
* **Conflicting Target Names:** Trying to create two targets with the same name in the same directory will raise an `InvalidCode` exception.
* **Incorrect `native` Argument Type:** Passing a non-boolean value to the `native` keyword will raise an `InvalidArguments` exception.
    * **Example:** `executable('myprog', 'main.c', native: 'yes')`
* **Misunderstanding `default_library`:**  If a user expects a static library but `default_library` is set to 'shared', they will get a shared library instead.
* **Mixing `gui_app` and `win_subsystem`:** Explicitly setting both `gui_app` and `win_subsystem` for an executable will lead to an error.

**User Operation to Reach Here (Debugging Clues):**

A user's actions leading to the execution of this code would typically involve:

1. **Writing or Modifying a `meson.build` file:** This file contains the instructions for building the project, including defining targets using functions like `executable()`, `library()`, etc.
2. **Running the `meson` command:** When a user runs `meson setup builddir` (or a similar command), the Meson build system starts parsing and interpreting the `meson.build` files.
3. **The `Interpreter` comes into play:** The `interpreter.py` file (where this code snippet resides) is the core component responsible for interpreting the Meson language in the `meson.build` file.
4. **Target Definition Calls:** When the interpreter encounters functions like `executable()` or `library()`, it calls the corresponding methods within the `Interpreter` class (like `build_target`, `build_library`).
5. **Error or Success:**  Depending on the correctness of the `meson.build` file and the provided arguments, the interpreter will either successfully register the build targets or raise exceptions, providing debugging information to the user.

**Summarization of Functionality (Part 6 of 6):**

This specific section of `frida/releng/meson/mesonbuild/interpreter/interpreter.py` within the Frida project is responsible for the **core logic of defining and registering build targets**. It acts as the engine that translates high-level build instructions from the `meson.build` files into internal representations of executables, libraries, and other build artifacts. It handles source file management, dependency tracking, and processing of build options, ensuring that the build system understands how to construct the final software components of the Frida dynamic instrumentation tool. It also incorporates error checking and feature management to provide a robust and evolving build process.

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
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

"""


```