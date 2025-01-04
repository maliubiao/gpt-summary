Response:
The user is asking for a breakdown of the functionalities of the provided Python code, which is a part of the Frida dynamic instrumentation tool. I need to analyze the code and identify its core functions, explaining their relevance to reverse engineering, binary manipulation, and interaction with low-level system components. I also need to illustrate logical reasoning within the code with example inputs and outputs, highlight potential user errors, and trace the user's path to this code during debugging. Finally, I need to summarize the overall purpose of this code snippet.

Here's a breakdown of the tasks:

1. **Identify Core Functions:**  Analyze the methods in the `Interpreter` class to understand their roles.
2. **Reverse Engineering Relevance:** Determine if any functions directly facilitate or relate to reverse engineering activities.
3. **Binary/Kernel/Framework Interaction:** Identify functions that interact with or have knowledge of binary formats, Linux/Android kernels, or frameworks.
4. **Logical Reasoning:**  Pinpoint areas where the code performs conditional logic and provide examples.
5. **Common User Errors:**  Identify scenarios where users might misuse the provided functions.
6. **User Path to this Code (Debugging):** Explain how a user might end up looking at this specific file during debugging.
7. **Summary:** Provide a concise overview of the code's purpose.
This Python code snippet is part of the `interpreter.py` file within the Meson build system, specifically for the Frida Swift subproject's release engineering. It defines a portion of the `Interpreter` class, which is responsible for executing the Meson build language and translating it into build actions. Here's a breakdown of its functionality:

**1. Core Functionalities:**

* **Target Definition (`build_target`, `build_executable`, `build_library`, `build_both_libraries`):** These functions are the primary way to define build targets (executables, static libraries, shared libraries, modules, JAR files). They take the target's name, source files, and various keyword arguments specifying build options (like dependencies, include directories, compiler flags, etc.).
* **Target Management (`add_target`):**  Registers the created build targets in the internal build representation, ensuring unique naming and generating a unique ID for each.
* **Source Handling:**
    * **`source_strings_to_files`:** Converts string representations of source file paths into `mesonlib.File` objects.
    * **`check_sources_exist`:** Verifies that the specified source files actually exist on the filesystem.
    * **Structured Sources:** Handles grouped source files with potential output name conflicts.
* **Dependency Management:** Handles dependencies between targets and external libraries.
* **Compiler Option Handling:** Processes language-specific arguments (`<lang>_args`, `<lang>_static_args`, `<lang>_shared_args`) and converts them into a unified structure.
* **Include Directory Handling (`kwarg_strings_to_includedirs`, `extract_incdirs`):**  Manages include directories for compilation.
* **Standard Library Linking (`add_stdlib_info`):**  Automatically links against the appropriate standard libraries based on the target's language.
* **Variable Management (`func_set_variable`, `func_get_variable`, `func_is_variable`, `func_unset_variable`):** Provides functions to set, get, check the existence of, and unset variables within the Meson build environment.
* **Subproject Handling (`is_subproject`, `validate_extraction`):**  Manages dependencies and interactions between subprojects.
* **Path Handling (`absolute_builddir_path_for`, `relative_builddir_path_for`):** Calculates absolute and relative paths within the build directory structure.
* **Feature Flagging and Deprecation:** Uses `FeatureNew`, `FeatureBroken`, and `FeatureDeprecated` to manage the introduction and removal of features, providing warnings and errors as needed.

**2. Relationship with Reverse Engineering:**

This code, being part of Frida's build system, indirectly plays a role in enabling reverse engineering. Frida is a dynamic instrumentation toolkit used extensively for reverse engineering, malware analysis, and security research. This `interpreter.py` code is crucial for:

* **Building Frida's Core Components:** It's responsible for compiling and linking the various parts of the Frida framework itself, including the agent that runs inside the target process.
* **Building Frida Gadget:**  Frida's "Gadget" is a library that can be injected into processes. This code would be involved in building that injectable library.
* **Building Frida Bindings:**  Frida has language bindings (like the Swift binding this code resides within). This code manages the compilation of those bindings.

**Example:** When building Frida, this code will be used to define the build targets for the core Frida agent. The `build_executable` function might be used to define the `frida-server` executable, specifying its source files, linking against necessary libraries (like `glib`), and setting compiler flags.

**3. Binary, Linux, Android Kernel & Framework Knowledge:**

* **Binary Formats (Indirect):** While this code doesn't directly manipulate binary code, it understands the concepts of executables, shared libraries, static libraries, and object files, which are fundamental binary formats. The build system orchestrates the compilation and linking processes that produce these binaries.
* **Linux & Android (Indirect):** The build system interacts with compilers and linkers that are specific to the target operating system (Linux, Android, etc.). The `native` keyword and compiler selection logic within this code indicate an awareness of cross-compilation scenarios, which are common when building tools like Frida that need to run on different platforms (including Android).
* **Frameworks (Indirect):** The code handles dependencies on external libraries and frameworks (e.g., `glib` mentioned earlier). When building Frida, it might link against system libraries or other frameworks depending on the target platform.

**Example:**  The code might use conditional logic based on the target operating system to link against different system libraries or set different compiler flags. For instance, when building Frida for Android, it might link against Android-specific libraries.

**4. Logical Reasoning (Assumptions, Inputs & Outputs):**

* **Assumption:** A user defines a build target named "my_tool" with source files `main.c` and `utils.c`.
* **Input:** The `build_executable` function is called with `name="my_tool"` and `sources=["main.c", "utils.c"]`.
* **Logical Reasoning:**
    * The code checks if a target with the same name already exists (`if idname in self.build.targets:`). If so, it raises an error.
    * It validates if any path segments in the target name point to existing directories, which is disallowed.
    * It converts the source file strings into `mesonlib.File` objects.
    * It verifies that `main.c` and `utils.c` exist in the source directory.
* **Output:** A `build.Executable` object representing the "my_tool" target is created and registered in `self.build.targets`.

* **Assumption:** A user attempts to build both a shared and static library with the same name in the same directory.
* **Input:** The `build_both_libraries` function is called for a library named "mylib".
* **Logical Reasoning:**
    * The code checks the backend (e.g., Xcode) and Rust usage. In cases like Xcode or Rust, it might disable the reuse of object files to avoid build issues.
    * It might reuse object files from the shared library build for the static library build if certain conditions are met (performance optimization).
* **Output:** A `build.BothLibraries` object is created containing both the `build.SharedLibrary` and `build.StaticLibrary` objects for "mylib".

**5. Common User/Programming Errors:**

* **Duplicate Target Names:**  Defining two targets with the same name will raise an `InvalidCode` exception.
    * **Example:** Calling `executable('my_tool', 'main.c')` and then later calling `library('my_tool', 'lib.c')`.
* **Source File Not Found:** Specifying a source file that doesn't exist will lead to an `InterpreterException`.
    * **Example:** `executable('my_tool', 'missing.c')` when `missing.c` is not in the source directory.
* **Invalid `native` Argument:** Providing a non-boolean value to the `native` keyword argument will raise an `InvalidArguments` exception.
    * **Example:** `executable('my_tool', 'main.c', native='yes')`.
* **Conflicting Structured Sources:**  Providing structured sources that would result in output files with the same name will raise an `InvalidArguments` exception.
    * **Example:** `structured_sources(['a/file.c', 'b/file.c'])` where both would compile to `file.o`.
* **Mixing `gui_app` and `win_subsystem`:** Specifying both `gui_app` and `win_subsystem` for an executable is an error.
    * **Example:** `executable('my_gui', 'gui.c', gui_app=True, win_subsystem='windows')`.
* **Incorrect `implib`/`export_dynamic` Usage:**  Setting `export_dynamic=True` without `implib=True` for an executable on Windows will raise an `InvalidArguments` exception.

**6. User Operation to Reach This Code (Debugging):**

A user might end up looking at this code during debugging in several scenarios:

1. **Build Failures:** If the Meson build process fails during the target definition stage, error messages might point to issues within this code. For example, if a target name is duplicated or a source file is missing.
2. **Unexpected Build Behavior:** If a target is not being built as expected (e.g., not linking against a required library), a developer might trace the execution of the Meson scripts to understand how the target is being defined. They might step through the `build_executable` or `build_library` functions to see the parameters being passed.
3. **Custom Build Logic:** If a developer is writing custom Meson build logic, they might need to understand how the built-in target definition functions work. Examining this code provides insights into how Meson handles targets internally.
4. **Frida Development:** Developers working on Frida itself might need to debug issues within the build system, particularly related to how Frida's components are compiled and linked. This file is a central part of that process for the Swift bindings.
5. **Investigating Feature Introduction/Deprecation:**  If a build starts failing after upgrading Meson, a developer might examine the `FeatureNew`, `FeatureBroken`, and `FeatureDeprecated` decorators in this code to understand if a previously working pattern is now disallowed.

**Steps to reach this code:**

1. **Run Meson:** The user executes the `meson` command in their build directory.
2. **Meson Parses `meson.build`:** Meson reads and parses the `meson.build` files in the project.
3. **Interpreter Execution:** The `Interpreter` class (and this `interpreter.py` file) is responsible for executing the Meson language constructs.
4. **Target Definition Encountered:** When Meson encounters functions like `executable()`, `library()`, etc., in the `meson.build` files, the corresponding methods in the `Interpreter` class (like `build_target`) are invoked.
5. **Error/Debugging:** If an error occurs during this process, or if the user is manually inspecting the build process, they might trace the execution flow to this specific file and these functions.

**7. Summary of Functionality:**

This code snippet defines a crucial part of Frida's build system, specifically for the Swift bindings. It provides the core mechanisms for defining and managing build targets (executables, libraries), handling source files, managing dependencies and compiler options, and ensuring the integrity of the build process. It acts as the intermediary between the declarative Meson build language and the underlying build system, orchestrating the compilation and linking of Frida's components.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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