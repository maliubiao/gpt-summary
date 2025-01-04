Response:
The user wants a summary of the functionality of the provided Python code snippet, which is part of the Frida dynamic instrumentation tool. I need to analyze the code and identify its key functionalities, especially concerning reverse engineering, low-level binary interactions, Linux/Android kernel/framework knowledge, logical reasoning, user errors, and debugging.

Here's a breakdown of the code's functionalities:

1. **Compiler and Language Handling:** The code manages the detection and configuration of compilers for different programming languages. This is fundamental for building software.
2. **Message and Logging:** Functions like `func_message`, `func_warning`, `func_error`, and `func_debug` are for logging and displaying information to the user during the build process.
3. **Summary Generation:** The `func_summary` and related methods create a summary of the build process, including subprojects and user-defined options.
4. **Subproject Management:** The code handles the inclusion and management of subprojects, which are separate build units.
5. **Program Finding:** The `func_find_program` and related functions are responsible for locating external programs required for the build. This involves searching in system paths and user-specified directories.
6. **Dependency Management:** The `func_dependency` function manages external dependencies, including libraries and other software components.
7. **Target Definition:** Functions like `func_executable`, `func_static_lib`, `func_shared_lib`, `func_shared_module`, `func_library`, `func_both_lib`, and `func_jar` define different types of build targets (executables, libraries, etc.).
8. **Error Handling:** The `func_expect_error` function and the error handling within other functions allow for anticipating and managing errors during the build process.
9. **Option Handling:** The code interacts with Meson's option system, allowing users to customize the build.

Now, I need to consider how these functionalities relate to the specific aspects mentioned by the user.
This section of the `interpreter.py` file in Frida's build system focuses on several key functionalities: **compiler and language management, informational messages, build summaries, external program discovery, and dependency handling.**

Here's a breakdown of its functions:

**1. Compiler and Language Management:**

*   **`func_add_languages`**: This function allows the project to specify which programming languages will be used for the build. It handles both host and target machine languages, considering dependencies between languages (like requiring C for Vala).
    *   **Relationship to Reverse Engineering:** While not directly a reverse engineering *method*, it's crucial for building reverse engineering tools like Frida itself, which often involves multiple languages for different components. For example, the core might be in C/C++, while the scripting interface is in Python or JavaScript.
    *   **Relationship to Binary/OS/Kernel/Framework:** This function interacts with the underlying system by needing to detect and configure compilers that generate machine code for the target architecture (which could be Linux, Android, etc.). It needs to understand the specifics of how compilers are invoked and what libraries are required for different languages on those platforms.
    *   **Logical Reasoning:** The function checks if a language is already added and handles the `native` keyword to determine if the language is for the host or the target machine. It also has logic to automatically add 'C' if 'vala' is specified.
        *   **Hypothetical Input:** `add_languages('vala')`
        *   **Hypothetical Output:**  The function will internally also add 'c' to the list of languages if it's not already present.
*   **`add_languages` and `add_languages_for`**: These are internal helper functions that perform the actual detection and setup of compilers for specified machines (host or build). They interact with the environment to find the compiler executables and handle cross-compilation scenarios.
    *   **Relationship to Binary/OS/Kernel/Framework:** The compiler detection logic within these functions is heavily dependent on understanding the standard locations and naming conventions of compilers on different operating systems. For cross-compilation, it needs to handle toolchains targeting different architectures and OSes.
    *   **Logical Reasoning:** These functions check if a compiler for a language is already configured and attempt to detect it if not. They also handle the `required` flag to decide whether to error out if a compiler is not found.
    *   **User/Programming Errors:** A common user error is specifying a language without the necessary compiler being installed or in the system's PATH. The function will raise an error if `required=True`.

**2. Informational Messages:**

*   **`func_message` and `message_impl`**: These functions display informational messages to the user during the build process.
    *   **Relationship to Reverse Engineering:** These messages can provide feedback during the build of reverse engineering tools, indicating progress or specific configurations.
    *   **Logical Reasoning:** The `func_message` function might perform basic checks on the number of arguments.
*   **`func_warning`**: This function displays warning messages to the user.
    *   **Relationship to Reverse Engineering:** Warnings might indicate potential issues or non-optimal configurations in the reverse engineering tool being built.
*   **`func_error`**: This function displays error messages and halts the build process.
    *   **Relationship to Reverse Engineering:** Errors would prevent the successful building of a reverse engineering tool.
*   **`func_debug`**: This function displays debug messages, usually for development purposes.

**3. Build Summaries:**

*   **`func_summary` and `summary_impl`**: These functions allow the project to add custom information to the build summary that is displayed at the end of the configuration process.
    *   **Relationship to Reverse Engineering:**  The summary could include information about the specific features or components enabled in the built Frida version, which is relevant to its reverse engineering capabilities.
    *   **Logical Reasoning:** The function handles different input formats (string or dictionary) for the summary information.
*   **`_print_subprojects` and `_print_summary`**: These internal functions format and display the build summary, including information about subprojects and user-defined options.

**4. External Program Discovery:**

*   **`func_find_program` and `find_program_impl`**: These functions are crucial for locating external tools required during the build process (e.g., compilers, linkers, other utilities).
    *   **Relationship to Reverse Engineering:** Reverse engineering tools often depend on other external programs (e.g., debuggers, disassemblers). This function is essential for finding those dependencies during the build. For instance, a Frida module might require `lldb` to be present for certain functionalities.
    *   **Relationship to Binary/OS/Kernel/Framework:** This function searches the system's PATH environment variable and potentially other specified directories to find executables. It's OS-dependent as the way programs are located varies across platforms.
    *   **Logical Reasoning:** The function checks for overridden program paths, searches in specified directories, and handles the `required` flag to determine if the build should fail if the program is not found.
        *   **Hypothetical Input:** `find_program('adb')` (on an Android development system)
        *   **Hypothetical Output:** If `adb` is in the system's PATH, the function will return an object representing the `adb` executable.
    *   **User/Programming Errors:** A common user error is not having the required external program installed or not having its directory included in the system's PATH. The `required=True` setting will cause the build to fail.
    *   **User Operation to Reach Here (Debugging Clue):** A user might be running the `meson configure` command in a project that uses `find_program('some_tool')` in its `meson.build` file. If `some_tool` is not found, the execution will trace through these functions.
*   **`program_from_file_for`, `program_from_system`, `program_from_overrides`**: These are helper functions used by `find_program_impl` to locate programs in different ways (from explicitly specified files, from the system's PATH, or from user overrides).
*   **`notfound_program`**: Returns an object representing a program that was not found.
*   **`check_program_version`**:  Verifies the version of a found program against a specified requirement.
    *   **Relationship to Reverse Engineering:** Ensuring the correct version of external tools is crucial for compatibility and proper functioning of the reverse engineering tool being built.

**5. Dependency Handling:**

*   **`func_dependency`**: This function is responsible for finding and configuring external dependencies (libraries, frameworks, etc.) required by the project.
    *   **Relationship to Reverse Engineering:**  Reverse engineering tools heavily rely on various libraries (e.g., for handling different file formats, disassembling code, interacting with the operating system). This function is vital for locating and linking against these dependencies. For example, Frida might depend on `glib` or other system libraries.
    *   **Relationship to Binary/OS/Kernel/Framework:** Finding dependencies often involves interacting with package managers or system-specific mechanisms for locating libraries and headers. The function might need to understand the structure of library installations on different operating systems.
    *   **Logical Reasoning:** The function handles various keyword arguments to specify how to find the dependency (e.g., using `pkg-config`, CMake), handles fallback mechanisms, and checks for specific versions.
        *   **Hypothetical Input:** `dependency('openssl')`
        *   **Hypothetical Output:**  The function will return a dependency object representing the OpenSSL library if found on the system.
    *   **User/Programming Errors:**  Common errors include the dependency not being installed, incorrect dependency names, or missing configuration files (like `.pc` files for `pkg-config`). The `not_found_message` kwarg can help provide more informative error messages.
    *   **User Operation to Reach Here (Debugging Clue):** A user might be running `meson configure` in a project that has `dependency('some_lib')` in its `meson.build` file. If `some_lib` cannot be found, the execution flow will go through this function.
*   **`add_find_program_override`**: Allows overriding the default behavior of `find_program` for specific executables.
*   **`store_name_lookups`**: Keeps track of programs that have been searched for.

**6. Target Definition (Partial):**

*   **`func_executable`, `func_static_lib`, `func_shared_lib`, `func_shared_module`, `func_library`, `func_both_lib`, `func_jar`, `func_build_target`**: These functions define different types of build targets (executables, static libraries, shared libraries, etc.). While their detailed implementation isn't fully shown in this snippet, they represent the core mechanism for defining what the build system should produce.
    *   **Relationship to Reverse Engineering:**  These functions are used to define how the components of the Frida tool itself (e.g., the core library, the command-line interface) are built.

**7. Error Handling:**

*   **`func_expect_error`**: This function is used for testing the build system itself. It allows specifying that a certain code block is expected to raise an error.

**In summary, this section of the code is responsible for the crucial initial steps of a software build process: setting up the build environment, finding necessary tools and libraries, and defining the structure of the software to be built. It's highly relevant to reverse engineering as it lays the foundation for building the very tools used for reverse engineering.**

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
'backend'))
            vsenv = self.coredata.get_option(OptionKey('vsenv'))
            force_vsenv = vsenv or backend.startswith('vs')
            mesonlib.setup_vsenv(force_vsenv)

        self.add_languages(proj_langs, True, MachineChoice.HOST)
        self.add_languages(proj_langs, False, MachineChoice.BUILD)

        self.set_backend()
        if not self.is_subproject():
            self.check_stdlibs()

    @typed_kwargs('add_languages', KwargInfo('native', (bool, NoneType), since='0.54.0'), REQUIRED_KW)
    @typed_pos_args('add_languages', varargs=str)
    def func_add_languages(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddLanguages') -> bool:
        langs = args[0]
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        native = kwargs['native']

        if disabled:
            for lang in sorted(langs, key=compilers.sort_clink):
                mlog.log('Compiler for language', mlog.bold(lang), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        if native is not None:
            return self.add_languages(langs, required, self.machine_from_native_kwarg(kwargs))
        else:
            # absent 'native' means 'both' for backwards compatibility
            tv = FeatureNew.get_target_version(self.subproject)
            if FeatureNew.check_version(tv, '0.54.0'):
                mlog.warning('add_languages is missing native:, assuming languages are wanted for both host and build.',
                             location=node)

            success = self.add_languages(langs, False, MachineChoice.BUILD)
            success &= self.add_languages(langs, required, MachineChoice.HOST)
            return success

    def _stringify_user_arguments(self, args: T.List[TYPE_var], func_name: str) -> T.List[str]:
        try:
            return [stringifyUserArguments(i, self.subproject) for i in args]
        except InvalidArguments as e:
            raise InvalidArguments(f'{func_name}(): {str(e)}')

    @noArgsFlattening
    @noKwargs
    def func_message(self, node: mparser.BaseNode, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('message with more than one argument', '0.54.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'message')
        self.message_impl(args_str)

    def message_impl(self, args):
        mlog.log(mlog.bold('Message:'), *args)

    @noArgsFlattening
    @FeatureNew('summary', '0.53.0')
    @typed_pos_args('summary', (str, dict), optargs=[object])
    @typed_kwargs(
        'summary',
        KwargInfo('section', str, default=''),
        KwargInfo('bool_yn', bool, default=False),
        KwargInfo('list_sep', (str, NoneType), since='0.54.0')
    )
    def func_summary(self, node: mparser.BaseNode, args: T.Tuple[T.Union[str, T.Dict[str, T.Any]], T.Optional[T.Any]],
                     kwargs: 'kwtypes.Summary') -> None:
        if self.coredata.is_build_only:
            return
        if args[1] is None:
            if not isinstance(args[0], dict):
                raise InterpreterException('Summary first argument must be dictionary.')
            values = args[0]
        else:
            if not isinstance(args[0], str):
                raise InterpreterException('Summary first argument must be string.')
            values = {args[0]: args[1]}
        self.summary_impl(kwargs['section'], values, kwargs)

    def summary_impl(self, section: str, values, kwargs: 'kwtypes.Summary') -> None:
        if self.subproject not in self.summary:
            self.summary[self.subproject] = Summary(self.active_projectname, self.project_version)
        self.summary[self.subproject].add_section(
            section, values, kwargs['bool_yn'], kwargs['list_sep'], self.subproject)

    def _print_subprojects(self, for_machine: MachineChoice) -> None:
        # Add automatic 'Subprojects' section in main project.
        all_subprojects = collections.OrderedDict()
        for name, subp in sorted(self.subprojects[for_machine].items()):
            value = [subp.found()]
            if subp.disabled_feature:
                value += [f'Feature {subp.disabled_feature!r} disabled']
            elif subp.exception:
                value += [str(subp.exception)]
            elif subp.warnings > 0:
                value += [f'{subp.warnings} warnings']
            if subp.callstack:
                stack = ' => '.join(subp.callstack)
                value += [f'(from {stack})']
            all_subprojects[name] = value
        if all_subprojects:
            self.summary_impl(f'Subprojects (for {for_machine.get_lower_case_name()} machine)', all_subprojects,
                              {'bool_yn': True,
                               'list_sep': ' ',
                               })

    def _print_summary(self) -> None:
        self._print_subprojects(MachineChoice.HOST)
        if self.environment.is_cross_build():
            self._print_subprojects(MachineChoice.BUILD)
        # Add automatic section with all user defined options
        if self.user_defined_options:
            values = collections.OrderedDict()
            if self.user_defined_options.cross_file:
                values['Cross files'] = self.user_defined_options.cross_file
            if self.user_defined_options.native_file:
                values['Native files'] = self.user_defined_options.native_file
            sorted_options = sorted(self.user_defined_options.cmd_line_options.items())
            values.update({str(k): v for k, v in sorted_options})
            if values:
                self.summary_impl('User defined options', values, {'bool_yn': False, 'list_sep': None})
        # Print all summaries, main project last.
        mlog.log('')  # newline
        main_summary = self.summary.pop('', None)
        for subp_name, summary in sorted(self.summary.items()):
            if self.subprojects.host[subp_name].found():
                summary.dump()
        if main_summary:
            main_summary.dump()

    @noArgsFlattening
    @FeatureNew('warning', '0.44.0')
    @noKwargs
    def func_warning(self, node, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('warning with more than one argument', '0.54.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'warning')
        mlog.warning(*args_str, location=node)

    @noArgsFlattening
    @noKwargs
    def func_error(self, node, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('error with more than one argument', '0.58.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'error')
        raise InterpreterException('Problem encountered: ' + ' '.join(args_str))

    @noArgsFlattening
    @FeatureNew('debug', '0.63.0')
    @noKwargs
    def func_debug(self, node, args, kwargs):
        args_str = self._stringify_user_arguments(args, 'debug')
        mlog.debug('Debug:', *args_str)

    @noKwargs
    @noPosargs
    def func_exception(self, node, args, kwargs):
        raise RuntimeError('unit test traceback :)')

    @typed_pos_args('expect_error', str)
    @typed_kwargs(
        'expect_error',
        KwargInfo('how', str, default='literal', validator=in_set_validator({'literal', 're'})),
    )
    def func_expect_error(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: TYPE_kwargs) -> ContextManagerObject:
        class ExpectErrorObject(ContextManagerObject):
            def __init__(self, msg: str, how: str, subproject: str) -> None:
                super().__init__(subproject)
                self.msg = msg
                self.how = how

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_val is None:
                    raise InterpreterException('Expecting an error but code block succeeded')
                if isinstance(exc_val, mesonlib.MesonException):
                    msg = str(exc_val)
                    if (self.how == 'literal' and self.msg != msg) or \
                       (self.how == 're' and not re.match(self.msg, msg)):
                        raise InterpreterException(f'Expecting error {self.msg!r} but got {msg!r}')
                    return True
        return ExpectErrorObject(args[0], kwargs['how'], self.subproject)

    def add_languages(self, args: T.List[str], required: bool, for_machine: MachineChoice) -> bool:
        success = self.add_languages_for(args, required, for_machine)
        if not self.coredata.is_cross_build():
            self.coredata.copy_build_options_from_regular_ones()
        self._redetect_machines()
        return success

    def should_skip_sanity_check(self, for_machine: MachineChoice) -> bool:
        should = self.environment.properties.host.get('skip_sanity_check', False)
        if not isinstance(should, bool):
            raise InterpreterException('Option skip_sanity_check must be a boolean.')
        if for_machine != MachineChoice.HOST and not should:
            return False
        if not self.environment.is_cross_build() and not should:
            return False
        return should

    def add_languages_for(self, args: T.List[str], required: bool, for_machine: MachineChoice) -> bool:
        args = [a.lower() for a in args]
        langs = set(self.compilers[for_machine].keys())
        langs.update(args)
        # We'd really like to add cython's default language here, but it can't
        # actually be done because the cython compiler hasn't been initialized,
        # so we can't actually get the option yet. Because we can't know what
        # compiler to add by default, and we don't want to add unnecessary
        # compilers we don't add anything for cython here, and instead do it
        # When the first cython target using a particular language is used.
        if 'vala' in langs and 'c' not in langs:
            FeatureNew.single_use('Adding Vala language without C', '0.59.0', self.subproject, location=self.current_node)
            args.append('c')
        if 'nasm' in langs:
            FeatureNew.single_use('Adding NASM language', '0.64.0', self.subproject, location=self.current_node)

        success = True
        for lang in sorted(args, key=compilers.sort_clink):
            if lang in self.compilers[for_machine]:
                continue
            machine_name = 'build' if self.coredata.is_build_only else for_machine.get_lower_case_name()
            comp = self.coredata.compilers[for_machine].get(lang)
            if not comp:
                try:
                    skip_sanity_check = self.should_skip_sanity_check(for_machine)
                    if skip_sanity_check:
                        mlog.log('Cross compiler sanity tests disabled via the cross file.', once=True)
                    comp = compilers.detect_compiler_for(self.environment, lang, for_machine, skip_sanity_check, self.subproject)
                    if comp is None:
                        raise InvalidArguments(f'Tried to use unknown language "{lang}".')
                except mesonlib.MesonException:
                    if not required:
                        mlog.log('Compiler for language',
                                 mlog.bold(lang), 'for the', machine_name,
                                 'machine not found.')
                        success = False
                        continue
                    else:
                        raise
            else:
                # update new values from commandline, if it applies
                self.coredata.process_compiler_options(lang, comp, self.environment, self.subproject)

            # Add per-subproject compiler options. They inherit value from main project.
            if self.subproject:
                options = {}
                for k in comp.get_options():
                    v = copy.copy(self.coredata.options[k])
                    k = k.evolve(subproject=self.subproject)
                    options[k] = v
                self.coredata.add_compiler_options(options, lang, for_machine, self.environment, self.subproject)

            if for_machine == MachineChoice.HOST or self.environment.is_cross_build():
                logger_fun = mlog.log
            else:
                logger_fun = mlog.debug
            logger_fun(comp.get_display_language(), 'compiler for the', machine_name, 'machine:',
                       mlog.bold(' '.join(comp.get_exelist())), comp.get_version_string())
            if comp.linker is not None:
                logger_fun(comp.get_display_language(), 'linker for the', machine_name, 'machine:',
                           mlog.bold(' '.join(comp.linker.get_exelist())), comp.linker.id, comp.linker.version)
            self.build.ensure_static_linker(comp)
            self.compilers[for_machine][lang] = comp

        return success

    def program_from_file_for(self, for_machine: MachineChoice, prognames: T.List[mesonlib.FileOrString]
                              ) -> T.Optional[ExternalProgram]:
        for p in prognames:
            if isinstance(p, mesonlib.File):
                continue # Always points to a local (i.e. self generated) file.
            if not isinstance(p, str):
                raise InterpreterException('Executable name must be a string')
            prog = ExternalProgram.from_bin_list(self.environment, for_machine, p)
            # if the machine file specified something, it may be a regular
            # not-found program but we still want to return that
            if not isinstance(prog, NonExistingExternalProgram):
                return prog
        return None

    def program_from_system(self, args: T.List[mesonlib.FileOrString], search_dirs: T.List[str],
                            extra_info: T.List[mlog.TV_Loggable]) -> T.Optional[ExternalProgram]:
        # Search for scripts relative to current subdir.
        # Do not cache found programs because find_program('foobar')
        # might give different results when run from different source dirs.
        source_dir = os.path.join(self.environment.get_source_dir(), self.subdir)
        for exename in args:
            if isinstance(exename, mesonlib.File):
                if exename.is_built:
                    search_dir = os.path.join(self.environment.get_build_dir(),
                                              exename.subdir)
                else:
                    search_dir = os.path.join(self.environment.get_source_dir(),
                                              exename.subdir)
                exename = exename.fname
                extra_search_dirs = []
            elif isinstance(exename, str):
                search_dir = source_dir
                extra_search_dirs = search_dirs
            else:
                raise InvalidArguments(f'find_program only accepts strings and files, not {exename!r}')
            extprog = ExternalProgram(exename, search_dir=search_dir,
                                      extra_search_dirs=extra_search_dirs,
                                      silent=True)
            if extprog.found():
                extra_info.append(f"({' '.join(extprog.get_command())})")
                return extprog
        return None

    def program_from_overrides(self, command_names: T.List[mesonlib.FileOrString],
                               extra_info: T.List['mlog.TV_Loggable'], for_machine: MachineChoice,
                               ) -> T.Optional[T.Union[ExternalProgram, OverrideProgram, build.Executable]]:
        for name in command_names:
            if not isinstance(name, str):
                continue
            if name in self.build.find_overrides[for_machine]:
                exe = self.build.find_overrides[for_machine][name]
                extra_info.append(mlog.blue('(overridden)'))
                return exe
        return None

    def store_name_lookups(self, command_names: T.List[mesonlib.FileOrString], for_machine: MachineChoice) -> None:
        for name in command_names:
            if isinstance(name, str):
                self.build.searched_programs[for_machine].add(name)

    def add_find_program_override(self, name: str, exe: T.Union[build.Executable, ExternalProgram, 'OverrideProgram'],
                                  for_machine: MachineChoice = MachineChoice.HOST) -> None:
        if name in self.build.searched_programs[for_machine]:
            raise InterpreterException(f'Tried to override finding of executable "{name}" which has already been found.')
        if name in self.build.find_overrides[for_machine]:
            raise InterpreterException(f'Tried to override executable "{name}" which has already been overridden.')
        self.build.find_overrides[for_machine][name] = exe

    def notfound_program(self, args: T.List[mesonlib.FileOrString]) -> ExternalProgram:
        return NonExistingExternalProgram(' '.join(
            [a if isinstance(a, str) else a.absolute_path(self.environment.source_dir, self.environment.build_dir)
             for a in args]))

    # TODO update modules to always pass `for_machine`. It is bad-form to assume
    # the host machine.
    def find_program_impl(self, args: T.List[mesonlib.FileOrString],
                          for_machine: MachineChoice = MachineChoice.HOST,
                          default_options: T.Optional[T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]] = None,
                          required: bool = True, silent: bool = True,
                          wanted: T.Union[str, T.List[str]] = '',
                          search_dirs: T.Optional[T.List[str]] = None,
                          version_func: T.Optional[ProgramVersionFunc] = None
                          ) -> T.Union['ExternalProgram', 'build.Executable', 'OverrideProgram']:
        args = mesonlib.listify(args)

        extra_info: T.List[mlog.TV_Loggable] = []
        progobj = self.program_lookup(args, for_machine, default_options, required, search_dirs, wanted, version_func, extra_info)
        if progobj is None or not self.check_program_version(progobj, wanted, version_func, for_machine, extra_info):
            progobj = self.notfound_program(args)

        if isinstance(progobj, ExternalProgram) and not progobj.found():
            if not silent:
                mlog.log('Program', mlog.bold(progobj.get_name()), 'found:', mlog.red('NO'), *extra_info)
            if required:
                m = 'Program {!r} not found or not executable'
                raise InterpreterException(m.format(progobj.get_name()))
            return progobj

        # Only store successful lookups
        self.store_name_lookups(args, for_machine)
        if not silent:
            mlog.log('Program', mlog.bold(progobj.name), 'found:', mlog.green('YES'), *extra_info)
        if isinstance(progobj, build.Executable):
            progobj.was_returned_by_find_program = True
        return progobj

    def program_lookup(self, args: T.List[mesonlib.FileOrString], for_machine: MachineChoice,
                       default_options: T.Optional[T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]],
                       required: bool,
                       search_dirs: T.List[str],
                       wanted: T.Union[str, T.List[str]],
                       version_func: T.Optional[ProgramVersionFunc],
                       extra_info: T.List[mlog.TV_Loggable]
                       ) -> T.Optional[T.Union[ExternalProgram, build.Executable, OverrideProgram]]:
        progobj = self.program_from_overrides(args, extra_info, for_machine)
        if progobj:
            return progobj

        if args[0] == 'meson':
            # Override find_program('meson') to return what we were invoked with
            return ExternalProgram('meson', self.environment.get_build_command(), silent=True)

        fallback = None
        wrap_mode = self.coredata.get_option(OptionKey('wrap_mode'))
        if wrap_mode != WrapMode.nofallback and self.environment.wrap_resolver:
            fallback = self.environment.wrap_resolver.find_program_provider(args)
        if fallback and wrap_mode == WrapMode.forcefallback:
            return self.find_program_fallback(fallback, args, default_options, required, extra_info, for_machine)

        progobj = self.program_from_file_for(for_machine, args)
        if progobj is None:
            progobj = self.program_from_system(args, search_dirs, extra_info)
        if progobj is None and args[0].endswith('python3'):
            prog = ExternalProgram('python3', mesonlib.python_command, silent=True)
            progobj = prog if prog.found() else None

        if progobj and not self.check_program_version(progobj, wanted, version_func, for_machine, extra_info):
            progobj = None

        if progobj is None and fallback and required:
            progobj = self.notfound_program(args)
            mlog.log('Program', mlog.bold(progobj.get_name()), 'found:', mlog.red('NO'), *extra_info)
            extra_info.clear()
            progobj = self.find_program_fallback(fallback, args, default_options, required, extra_info, for_machine)

        return progobj

    def check_program_version(self, progobj: T.Union[ExternalProgram, build.Executable, OverrideProgram],
                              wanted: T.Union[str, T.List[str]],
                              version_func: T.Optional[ProgramVersionFunc],
                              for_machine: MachineChoice,
                              extra_info: T.List[mlog.TV_Loggable]) -> bool:
        if wanted:
            if version_func:
                version = version_func(progobj)
            elif isinstance(progobj, build.Executable):
                if progobj.subproject:
                    interp = self.subprojects[for_machine][progobj.subproject].held_object
                else:
                    interp = self
                assert isinstance(interp, Interpreter)
                version = interp.project_version
            else:
                version = progobj.get_version(self)
            is_found, not_found, _ = mesonlib.version_compare_many(version, wanted)
            if not is_found:
                extra_info[:0] = ['found', mlog.normal_cyan(version), 'but need:',
                                  mlog.bold(', '.join([f"'{e}'" for e in not_found]))]
                return False
            extra_info.insert(0, mlog.normal_cyan(version))
        return True

    def find_program_fallback(self, fallback: str, args: T.List[mesonlib.FileOrString],
                              default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]],
                              required: bool, extra_info: T.List[mlog.TV_Loggable],
                              for_machine: MachineChoice
                              ) -> T.Optional[T.Union[ExternalProgram, build.Executable, OverrideProgram]]:
        mlog.log('Fallback to subproject', mlog.bold(fallback), 'which provides program',
                 mlog.bold(' '.join(args)))
        sp_kwargs: kwtypes.DoSubproject = {
            'required': required,
            'default_options': default_options or {},
            'version': [],
            'cmake_options': [],
            'options': None,
            'for_machine': for_machine,
        }
        self.do_subproject(fallback, sp_kwargs)
        return self.program_from_overrides(args, extra_info, for_machine)

    @typed_pos_args('find_program', varargs=(str, mesonlib.File), min_varargs=1)
    @typed_kwargs(
        'find_program',
        DISABLER_KW.evolve(since='0.49.0'),
        NATIVE_KW,
        REQUIRED_KW,
        KwargInfo('dirs', ContainerTypeInfo(list, str), default=[], listify=True, since='0.53.0'),
        KwargInfo('version', ContainerTypeInfo(list, str), default=[], listify=True, since='0.52.0'),
        DEFAULT_OPTIONS.evolve(since='1.3.0')
    )
    @disablerIfNotFound
    def func_find_program(self, node: mparser.BaseNode, args: T.Tuple[T.List[mesonlib.FileOrString]],
                          kwargs: 'kwtypes.FindProgram',
                          ) -> T.Union['build.Executable', ExternalProgram, 'OverrideProgram']:
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            mlog.log('Program', mlog.bold(' '.join(args[0])), 'skipped: feature', mlog.bold(feature), 'disabled')
            return self.notfound_program(args[0])

        search_dirs = extract_search_dirs(kwargs)
        default_options = kwargs['default_options']
        return self.find_program_impl(args[0], kwargs['native'], default_options=default_options, required=required,
                                      silent=False, wanted=kwargs['version'],
                                      search_dirs=search_dirs)

    # When adding kwargs, please check if they make sense in dependencies.get_dep_identifier()
    @FeatureNewKwargs('dependency', '0.57.0', ['cmake_package_version'])
    @FeatureNewKwargs('dependency', '0.56.0', ['allow_fallback'])
    @FeatureNewKwargs('dependency', '0.54.0', ['components'])
    @FeatureNewKwargs('dependency', '0.52.0', ['include_type'])
    @FeatureNewKwargs('dependency', '0.50.0', ['not_found_message', 'cmake_module_path', 'cmake_args'])
    @FeatureNewKwargs('dependency', '0.49.0', ['disabler'])
    @FeatureNewKwargs('dependency', '0.40.0', ['method'])
    @disablerIfNotFound
    @permittedKwargs(permitted_dependency_kwargs)
    @typed_pos_args('dependency', varargs=str, min_varargs=1)
    @typed_kwargs('dependency', DEFAULT_OPTIONS.evolve(since='0.38.0'), allow_unknown=True)
    def func_dependency(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]], kwargs) -> Dependency:
        # Replace '' by empty list of names
        names = [n for n in args[0] if n]
        if len(names) > 1:
            FeatureNew('dependency with more than one name', '0.60.0').use(self.subproject)
        allow_fallback = kwargs.get('allow_fallback')
        if allow_fallback is not None and not isinstance(allow_fallback, bool):
            raise InvalidArguments('"allow_fallback" argument must be boolean')
        fallback = kwargs.get('fallback')
        default_options = kwargs.get('default_options')
        for_machine = MachineChoice.BUILD if self.coredata.is_build_only else self.machine_from_native_kwarg(kwargs)
        df = DependencyFallbacksHolder(self, names, for_machine, allow_fallback, default_options)
        df.set_fallback(fallback)
        not_found_message = kwargs.get('not_found_message', '')
        if not isinstance(not_found_message, str):
            raise InvalidArguments('The not_found_message must be a string.')
        try:
            d = df.lookup(kwargs)
        except Exception:
            if not_found_message:
                self.message_impl([not_found_message])
            raise
        assert isinstance(d, Dependency)
        if not d.found() and not_found_message:
            self.message_impl([not_found_message])
        # Ensure the correct include type
        if 'include_type' in kwargs:
            wanted = kwargs['include_type']
            if not isinstance(wanted, str):
                raise InvalidArguments('The `include_type` kwarg must be a string')
            actual = d.get_include_type()
            if wanted != actual:
                mlog.debug(f'Current include type of {args[0]} is {actual}. Converting to requested {wanted}')
                d = d.generate_system_dependency(wanted)
        if d.feature_since is not None:
            version, extra_msg = d.feature_since
            FeatureNew.single_use(f'dep {d.name!r} custom lookup', version, self.subproject, extra_msg, node)
        for f in d.featurechecks:
            f.use(self.subproject, node)
        return d

    @FeatureNew('disabler', '0.44.0')
    @noKwargs
    @noPosargs
    def func_disabler(self, node, args, kwargs):
        return Disabler()

    @permittedKwargs(build.known_exe_kwargs)
    @typed_pos_args('executable', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('executable', *EXECUTABLE_KWS, allow_unknown=True)
    def func_executable(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.Executable) -> build.Executable:
        return self.build_target(node, args, kwargs, build.Executable)

    @permittedKwargs(build.known_stlib_kwargs)
    @typed_pos_args('static_library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('static_library', *STATIC_LIB_KWS, allow_unknown=True)
    def func_static_lib(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.StaticLibrary) -> build.StaticLibrary:
        return self.build_target(node, args, kwargs, build.StaticLibrary)

    @permittedKwargs(build.known_shlib_kwargs)
    @typed_pos_args('shared_library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('shared_library', *SHARED_LIB_KWS, allow_unknown=True)
    def func_shared_lib(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.SharedLibrary) -> build.SharedLibrary:
        holder = self.build_target(node, args, kwargs, build.SharedLibrary)
        holder.shared_library_only = True
        return holder

    @permittedKwargs(known_library_kwargs)
    @typed_pos_args('both_libraries', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('both_libraries', *LIBRARY_KWS, allow_unknown=True)
    def func_both_lib(self, node: mparser.BaseNode,
                      args: T.Tuple[str, SourcesVarargsType],
                      kwargs: kwtypes.Library) -> build.BothLibraries:
        return self.build_both_libraries(node, args, kwargs)

    @FeatureNew('shared_module', '0.37.0')
    @permittedKwargs(build.known_shmod_kwargs)
    @typed_pos_args('shared_module', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('shared_module', *SHARED_MOD_KWS, allow_unknown=True)
    def func_shared_module(self, node: mparser.BaseNode,
                           args: T.Tuple[str, SourcesVarargsType],
                           kwargs: kwtypes.SharedModule) -> build.SharedModule:
        return self.build_target(node, args, kwargs, build.SharedModule)

    @permittedKwargs(known_library_kwargs)
    @typed_pos_args('library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('library', *LIBRARY_KWS, allow_unknown=True)
    def func_library(self, node: mparser.BaseNode,
                     args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.Library) -> build.Executable:
        return self.build_library(node, args, kwargs)

    @permittedKwargs(build.known_jar_kwargs)
    @typed_pos_args('jar', str, varargs=(str, mesonlib.File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList, build.ExtractedObjects, build.BuildTarget))
    @typed_kwargs('jar', *JAR_KWS, allow_unknown=True)
    def func_jar(self, node: mparser.BaseNode,
                 args: T.Tuple[str, T.List[T.Union[str, mesonlib.File, build.GeneratedTypes]]],
                 kwargs: kwtypes.Jar) -> build.Jar:
        return self.build_target(node, args, kwargs, build.Jar)

    @FeatureNewKwargs('build_target', '0.40.0', ['link_whole', 'override_options'])
    @permittedKwargs(known_build_target_kwargs)
    @typed_pos_args('build_target', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('build_target', *BUILD_TARGET_KWS, allow_unknown=True)
    def func_build_target(self, node: mparser.BaseNode,
                          args: T.Tuple[str, SourcesVarargsType],
                          kwargs: kwtypes.BuildTarget
                          ) -> T.Union[build.Executable, build.StaticLibrary, build.SharedLibrary,
                                       build.SharedModule, build.BothLibraries, build.Jar]:
        target_type = kwargs['target_type']
        if target_type == 'executable':
            return self.build_target(node, args, kwargs, build.Executable)
        elif target_type == 'shared_library':
            return self.build_target(node, args, kwargs, build.SharedLibrary)
        elif target_type == 'shared_module':
            return self.build_target(node, args, kwargs, build.SharedModule)
        elif target_type == 'static_library':
            return self.build_target(node, args, kwargs, build.StaticLibrary)
        elif target_type == 'both_libraries':
            return self.build_both_libraries(node, args, kwargs)
        elif target_type == 'library':
            return self.build_library(node, args, kwargs)
        return self.build_target(node, args, kwargs, build.Jar)

    @noPosargs
    @typed_kwargs(
        'vcs_tag',
        CT_INPUT_KW.evolve(required
"""


```