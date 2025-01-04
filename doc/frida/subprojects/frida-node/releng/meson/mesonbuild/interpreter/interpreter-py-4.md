Response:
The user wants to understand the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The code is located in `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py`.

I need to:
1. **List the functions** present in the code.
2. **Explain the purpose** of each function.
3. **Identify connections to reverse engineering**: Look for functions that manipulate or inspect compiled code, handle libraries, or interact with the operating system in ways relevant to dynamic analysis.
4. **Identify connections to low-level details**:  Look for interactions with binary data, Linux/Android kernel or framework components.
5. **Identify logical reasoning**: Analyze functions that involve conditional logic or data manipulation based on input. Provide example inputs and expected outputs.
6. **Identify common user errors**: Point out situations where a user might misuse the provided functions.
7. **Explain how a user might reach this code**:  Describe the user actions in Frida or its build system that would lead to the execution of these functions.
8. **Provide a summary of the functionality**.

Let's break down the provided code snippet function by function:

- `func_configure_file`: Seems to handle the configuration of files based on templates or commands.
- `extract_incdirs`: Extracts include directories from arguments.
- `func_include_directories`: Creates `IncludeDirs` objects.
- `build_incdir_object`:  Helper function to create `IncludeDirs` objects.
- `func_add_test_setup`: Configures test setups.
- `func_add_global_arguments`: Adds arguments that apply globally.
- `func_add_global_link_arguments`: Adds linker arguments that apply globally.
- `func_add_project_arguments`: Adds arguments specific to the project.
- `func_add_project_link_arguments`: Adds linker arguments specific to the project.
- `func_add_project_dependencies`: Adds project-level dependencies.
- `_warn_about_builtin_args`: Checks for the use of built-in arguments.
- `_add_global_arguments`:  Internal helper to add global arguments.
- `_add_project_arguments`: Internal helper to add project arguments.
- `_add_arguments`: Internal helper to manage argument addition.
- `func_environment`:  Manages environment variables.
- `func_join_paths`: Joins path components.
- `run`: Executes the interpreter.
- `print_extra_warnings`: Prints additional warnings.
- `check_clang_asan_lundef`: Checks for potential issues with Clang sanitizer and link undefined behavior.
- `validate_within_subproject`: Enforces sandbox restrictions on file access.
- `source_strings_to_files`: Converts strings representing source files to file objects.
- `validate_forbidden_targets`: Checks for reserved target names.
- `add_target`: Adds a build target.

Now I will go through each point requested by the user for each function where applicable.
This Python code snippet is part of the Meson build system's interpreter, specifically for the `configure_file` function and related utilities. Meson is used by Frida to manage its build process.

Here's a breakdown of its functionality:

**Core Functionality: `func_configure_file`**

This function is the heart of the provided code. Its primary purpose is to generate output files based on input files and configurations. It supports three main modes of operation, selectable via mutually exclusive keyword arguments:

1. **`configuration`**:  Takes an input file (typically a template) and a dictionary of configuration data. It substitutes variables in the input file with values from the configuration data and writes the result to the output file.
2. **`command`**: Executes an external command. It can use input files as context (e.g., their paths). The output of the command can be written to the output file.
3. **`copy`**:  Simply copies an input file to the specified output location.

**Other Supporting Functions and Their Roles:**

*   **`extract_incdirs(self, kwargs, key='include_directories')`**:  This function takes keyword arguments and extracts values associated with include directories. It handles both string-based paths and pre-existing `IncludeDirs` objects.
*   **`func_include_directories(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncIncludeDirectories') -> build.IncludeDirs`**: This function creates an `IncludeDirs` object, representing a set of include directories. It takes a list of directory paths as input and can mark them as system include directories.
*   **`build_incdir_object(self, incdir_strings: T.List[str], is_system: bool = False) -> build.IncludeDirs`**: This is a helper function for `func_include_directories`. It validates the input paths and creates the `IncludeDirs` object. It also enforces sandbox restrictions to prevent accessing files outside the current project.
*   **`func_add_test_setup(...)`**: This function defines test setups for running tests. It allows specifying wrappers for test executables (like `gdb`), timeout multipliers, and excluded test suites.
*   **`func_add_global_arguments(...)`, `func_add_global_link_arguments(...)`, `func_add_project_arguments(...)`, `func_add_project_link_arguments(...)`**: These functions allow adding compiler and linker arguments. "Global" arguments apply to the entire project, while "project" arguments are specific to the current subproject.
*   **`func_add_project_dependencies(...)`**: This function handles adding dependencies at the project level, ensuring necessary compile and link arguments are included.
*   **`_warn_about_builtin_args(...)`**: This internal function checks if the user is using command-line arguments for common build settings (like warning levels or optimization levels) and suggests using Meson's built-in options instead.
*   **`_add_global_arguments(...)`, `_add_project_arguments(...)`, `_add_arguments(...)`**: These are internal helper functions to manage the addition of compiler and linker arguments, enforcing restrictions on when arguments can be added.
*   **`func_environment(...)`**: This function allows defining and manipulating environment variables that will be set during the build process.
*   **`func_join_paths(...)`**: This function joins path components using the operating system's path separator.
*   **`run(self)`**: This method executes the interpreter, processing the `meson.build` files and generating the build system.
*   **`print_extra_warnings(self)`**:  Prints additional warnings, currently focusing on potential issues with Clang's AddressSanitizer and link-time undefined behavior detection.
*   **`check_clang_asan_lundef(self)`**:  Specifically checks for a potentially problematic combination of Clang sanitizer settings and link-time undefined behavior detection.
*   **`validate_within_subproject(self, subdir, fname)`**: This function enforces a sandbox, ensuring that files referenced in the `meson.build` files belong to the current subproject or are explicitly marked as installable. This prevents accidental or malicious access to files outside the project.
*   **`source_strings_to_files(self, sources: T.List['SourceInputs'], strict: bool = True) -> T.List['SourceOutputs']`**: This function takes a list of strings (representing file paths) or file-like objects and converts them into Meson's internal `File` objects. It also performs validation, including the subproject sandbox check.
*   **`validate_forbidden_targets(name: str)`**:  Ensures that target names do not conflict with Meson's internal naming conventions.
*   **`add_target(self, name: str, tobj: build.Target)`**:  Adds a build target (like an executable or a library) to the build graph.

**Relation to Reverse Engineering:**

Several aspects of this code directly or indirectly relate to reverse engineering:

*   **Dynamic Instrumentation (Frida Context):**  Since this code is part of Frida's build system, the entire purpose is to build a tool used for dynamic instrumentation. The functions here are responsible for setting up how Frida itself is built.
*   **Controlling Compiler/Linker Flags:** Functions like `func_add_global_arguments`, `func_add_global_link_arguments`, etc., directly control the flags passed to the compiler and linker. In a reverse engineering context, these flags are crucial for:
    *   **Debugging Symbols (`-g`):**  Including debugging symbols makes the resulting binary easier to analyze in debuggers like GDB or LLDB. While this code warns against directly using `-g` and suggests the built-in `debug` option, the underlying principle is the same.
    *   **Optimization Levels (`-O0`, `-O2`):**  Different optimization levels significantly affect the structure and performance of the compiled code. Reverse engineers often prefer working with unoptimized code (`-O0`) as it more closely resembles the original source.
    *   **Security Hardening Flags:** Flags related to Position Independent Executables (PIE), Stack Smashing Protection (SSP), and Address Space Layout Randomization (ASLR) are important for understanding a binary's security posture. While not explicitly shown in this snippet, these flags could be managed through these argument functions.
    *   **Sanitizers (`-fsanitize`):** Tools like AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) can help detect memory corruption and other errors during runtime. Frida developers might use these during development, and reverse engineers may also compile targets with sanitizers for analysis.
*   **Controlling Build Output:** The `func_configure_file` function, especially in its `command` mode, can be used to perform custom build steps that might involve generating files used in the reverse engineering process (e.g., extracting information from binaries).

**Example of Reverse Engineering Relevance:**

Let's say a Frida developer wants to build Frida with debugging symbols enabled for easier development and testing, which inherently involves reverse engineering concepts of understanding program behavior.

*   **User Action:** The developer would set the `debug` option in Meson (`meson -Ddebug=true build`).
*   **How it reaches this code:**  Meson interprets the `meson.build` files. If the `add_project_arguments` function is used within a `meson.build` file to add compiler flags based on the `debug` option, this code would be executed. For example, the `meson.build` might contain:

    ```python
    if get_option('debug'):
        add_project_arguments('-g', language='c')
    ```

*   **Impact:** The `_add_project_arguments` function would add the `-g` flag to the C compiler commands for the Frida project, resulting in the compiled Frida libraries and executables containing debugging symbols.

**Binary Underlying, Linux, Android Kernel, and Framework Knowledge:**

*   **Compiler and Linker Interaction:** The functions adding arguments directly interact with the underlying compiler (like GCC or Clang) and linker (like `ld`). The specific flags used are often platform-specific (Linux, Android, etc.) and related to the binary format (ELF, Mach-O, etc.).
*   **System Include Directories:**  `func_include_directories` deals with managing include paths. Understanding the standard include directories on Linux and Android is crucial for setting up the build environment correctly.
*   **Executable Wrappers (in `func_add_test_setup`):** The `exe_wrapper` allows specifying commands to run before executing tests. This could involve tools that interact with the operating system at a low level (e.g., setting environment variables specific to the kernel or Android framework).
*   **Environment Variables (in `func_environment`):** Environment variables can influence how programs run at a low level, including how they interact with the operating system kernel or specific frameworks.
*   **Path Manipulation (`func_join_paths`):** Understanding how paths are structured on different operating systems (Linux, Android) is essential for correctly building software.

**Example of Low-Level Relevance:**

Consider the `check_clang_asan_lundef` function.

*   **Underlying Binary Concept:** ASan (AddressSanitizer) is a compiler-based tool that detects memory errors at runtime. Link-time undefined behavior detection (`-Wl,--defsym`) is a linker feature.
*   **Linux/Android Knowledge:** The warning generated by this function highlights a potential incompatibility specific to Clang on Linux-like systems. Combining ASan with certain linker behaviors can lead to unexpected issues. This demonstrates knowledge of the underlying toolchain and operating system behavior.

**Logical Reasoning (with Hypothetical Input/Output):**

Let's focus on `func_configure_file` with the `configuration` action.

**Hypothetical Input:**

*   **Input File (`my_template.c.in`):**
    ```c
    #define VERSION "@VERSION@"
    #define BUILD_DATE "@BUILD_DATE@"
    ```
*   **Configuration Data (`config_data`):**
    ```python
    config_data = {'VERSION': '1.2.3', 'BUILD_DATE': '2023-10-27'}
    ```
*   **Meson Code:**
    ```python
    configure_file(
        input: 'my_template.c.in',
        output: 'my_config.h',
        configuration: config_data
    )
    ```

**Expected Output (`my_config.h`):**

```c
#define VERSION "1.2.3"
#define BUILD_DATE "2023-10-27"
```

**Logic:** The function reads the input file, identifies the variables enclosed in `@` symbols, and substitutes them with the corresponding values from the `configuration` dictionary.

**User Errors:**

*   **Incorrect Keyword Arguments:**  Forgetting to specify `input`, `output`, or the action keyword (`configuration`, `command`, `copy`).
*   **Mutually Exclusive Keywords:** Providing both `configuration` and `command` at the same time.
*   **Missing Configuration Data:**  If the input file has variables that are not present as keys in the `configuration` dictionary, a warning will be issued (as seen in the code).
*   **Incorrect Input File Path:** Providing a path to an input file that does not exist.
*   **Output File Conflicts:**  Accidentally trying to generate the same output file from multiple `configure_file` calls. Meson provides a warning for this.
*   **Type Errors in Configuration Data:**  Providing values in the `configuration` dictionary that are not strings, integers, or booleans.
*   **Incorrect Use of `install_dir`:**  Setting `install: true` without specifying an `install_dir`.

**User Operation to Reach This Code (Debugging Clue):**

1. **User Modifies `meson.build`:** A Frida developer edits a `meson.build` file within the Frida project.
2. **User Runs Meson:** The developer executes the `meson` command (e.g., `meson setup builddir`).
3. **Meson Parses `meson.build`:** Meson reads and interprets the `meson.build` files.
4. **Meson Encounters `configure_file`:** If the `meson.build` file contains a call to the `configure_file` function, the `func_configure_file` method in this Python file will be invoked.
5. **Error or Expected Behavior:** If there's an error in the `configure_file` call (e.g., missing arguments), an `InterpreterException` will be raised from within this code, providing the developer with an error message and line number in the `meson.build` file. If the call is correct, the function will perform the requested file configuration.

**Summary of Functionality:**

This code defines key parts of Meson's file generation and build configuration mechanisms within the Frida project. It handles templating, command execution for build steps, managing include directories, adding compiler/linker flags, defining test setups, and enforcing project structure. It ensures a controlled and reproducible build process for Frida, with attention to potential issues and user errors. The functions related to compiler/linker flags and the checks for specific toolchain configurations have direct relevance to reverse engineering scenarios where controlling the build output is essential for analysis.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
y=True,
            default=[],
        ),
        # Cannot use shared implementation until None backwards compat is dropped
        KwargInfo('install', (bool, NoneType), since='0.50.0'),
        KwargInfo('install_dir', (str, bool), default='',
                  validator=lambda x: 'must be `false` if boolean' if x is True else None),
        OUTPUT_KW,
        KwargInfo('output_format', str, default='c', since='0.47.0', since_values={'json': '1.3.0'},
                  validator=in_set_validator({'c', 'json', 'nasm'})),
        KwargInfo('macro_name', (str, NoneType), default=None, since='1.3.0'),
    )
    def func_configure_file(self, node: mparser.BaseNode, args: T.List[TYPE_var],
                            kwargs: kwtypes.ConfigureFile):
        actions = sorted(x for x in ['configuration', 'command', 'copy']
                         if kwargs[x] not in [None, False])
        num_actions = len(actions)
        if num_actions == 0:
            raise InterpreterException('Must specify an action with one of these '
                                       'keyword arguments: \'configuration\', '
                                       '\'command\', or \'copy\'.')
        elif num_actions == 2:
            raise InterpreterException('Must not specify both {!r} and {!r} '
                                       'keyword arguments since they are '
                                       'mutually exclusive.'.format(*actions))
        elif num_actions == 3:
            raise InterpreterException('Must specify one of {!r}, {!r}, and '
                                       '{!r} keyword arguments since they are '
                                       'mutually exclusive.'.format(*actions))

        if kwargs['capture'] and not kwargs['command']:
            raise InvalidArguments('configure_file: "capture" keyword requires "command" keyword.')

        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        fmt = kwargs['format']
        output_format = kwargs['output_format']
        depfile = kwargs['depfile']

        # Validate input
        inputs = self.source_strings_to_files(kwargs['input'])
        inputs_abs = []
        for f in inputs:
            if isinstance(f, mesonlib.File):
                inputs_abs.append(f.absolute_path(self.environment.source_dir,
                                                  self.environment.build_dir))
                self.add_build_def_file(f)
            else:
                raise InterpreterException('Inputs can only be strings or file objects')

        # Validate output
        output = kwargs['output']
        if inputs_abs:
            values = mesonlib.get_filenames_templates_dict(inputs_abs, None)
            outputs = mesonlib.substitute_values([output], values)
            output = outputs[0]
            if depfile:
                depfile = mesonlib.substitute_values([depfile], values)[0]
        ofile_rpath = self.relative_builddir_path_for(os.path.join(self.subdir, output))
        if ofile_rpath in self.configure_file_outputs:
            mesonbuildfile = os.path.join(self.subdir, 'meson.build')
            current_call = f"{mesonbuildfile}:{self.current_lineno}"
            first_call = "{}:{}".format(mesonbuildfile, self.configure_file_outputs[ofile_rpath])
            mlog.warning('Output file', mlog.bold(ofile_rpath, True), 'for configure_file() at', current_call, 'overwrites configure_file() output at', first_call)
        else:
            self.configure_file_outputs[ofile_rpath] = self.current_lineno
        (ofile_path, ofile_fname) = os.path.split(ofile_rpath)
        ofile_abs = os.path.join(self.environment.build_dir, ofile_path, ofile_fname)

        # Perform the appropriate action
        if kwargs['configuration'] is not None:
            conf = kwargs['configuration']
            if isinstance(conf, dict):
                FeatureNew.single_use('configure_file.configuration dictionary', '0.49.0', self.subproject, location=node)
                for k, v in conf.items():
                    if not isinstance(v, (str, int, bool)):
                        raise InvalidArguments(
                            f'"configuration_data": initial value dictionary key "{k!r}"" must be "str | int | bool", not "{v!r}"')
                conf = build.ConfigurationData(conf)
            mlog.log('Configuring', mlog.bold(output), 'using configuration')
            if len(inputs) > 1:
                raise InterpreterException('At most one input file can given in configuration mode')
            if inputs:
                os.makedirs(self.absolute_builddir_path_for(self.subdir), exist_ok=True)
                file_encoding = kwargs['encoding']
                missing_variables, confdata_useless = \
                    mesonlib.do_conf_file(inputs_abs[0], ofile_abs, conf,
                                          fmt, file_encoding, self.subproject)
                if missing_variables:
                    var_list = ", ".join(repr(m) for m in sorted(missing_variables))
                    mlog.warning(
                        f"The variable(s) {var_list} in the input file '{inputs[0]}' are not "
                        "present in the given configuration data.", location=node)
                if confdata_useless:
                    ifbase = os.path.basename(inputs_abs[0])
                    tv = FeatureNew.get_target_version(self.subproject)
                    if FeatureNew.check_version(tv, '0.47.0'):
                        mlog.warning('Got an empty configuration_data() object and found no '
                                     f'substitutions in the input file {ifbase!r}. If you want to '
                                     'copy a file to the build dir, use the \'copy:\' keyword '
                                     'argument added in 0.47.0', location=node)
            else:
                macro_name = kwargs['macro_name']
                mesonlib.dump_conf_header(ofile_abs, conf, output_format, macro_name)
            conf.used = True
        elif kwargs['command'] is not None:
            if len(inputs) > 1:
                FeatureNew.single_use('multiple inputs in configure_file()', '0.52.0', self.subproject, location=node)
            # We use absolute paths for input and output here because the cwd
            # that the command is run from is 'unspecified', so it could change.
            # Currently it's builddir/subdir for in_builddir else srcdir/subdir.
            values = mesonlib.get_filenames_templates_dict(inputs_abs, [ofile_abs])
            if depfile:
                depfile = os.path.join(self.environment.get_scratch_dir(), depfile)
                values['@DEPFILE@'] = depfile
            # Substitute @INPUT@, @OUTPUT@, etc here.
            _cmd = mesonlib.substitute_values(kwargs['command'], values)
            mlog.log('Configuring', mlog.bold(output), 'with command')
            cmd, *args = _cmd
            res = self.run_command_impl((cmd, args),
                                        {'capture': True, 'check': True, 'env': EnvironmentVariables()},
                                        True)
            if kwargs['capture']:
                dst_tmp = ofile_abs + '~'
                file_encoding = kwargs['encoding']
                with open(dst_tmp, 'w', encoding=file_encoding) as f:
                    f.writelines(res.stdout)
                if inputs_abs:
                    shutil.copymode(inputs_abs[0], dst_tmp)
                mesonlib.replace_if_different(ofile_abs, dst_tmp)
            if depfile:
                mlog.log('Reading depfile:', mlog.bold(depfile))
                with open(depfile, encoding='utf-8') as f:
                    df = DepFile(f.readlines())
                    deps = df.get_all_dependencies(ofile_fname)
                    for dep in deps:
                        self.add_build_def_file(dep)

        elif kwargs['copy']:
            if len(inputs_abs) != 1:
                raise InterpreterException('Exactly one input file must be given in copy mode')
            os.makedirs(self.absolute_builddir_path_for(self.subdir), exist_ok=True)
            shutil.copy2(inputs_abs[0], ofile_abs)

        # Install file if requested, we check for the empty string
        # for backwards compatibility. That was the behaviour before
        # 0.45.0 so preserve it.
        idir = kwargs['install_dir']
        if idir is False:
            idir = ''
            FeatureDeprecated.single_use('configure_file install_dir: false', '0.50.0',
                                         self.subproject, 'Use the `install:` kwarg instead', location=node)
        install = kwargs['install'] if kwargs['install'] is not None else idir != ''
        if install:
            if not idir:
                raise InterpreterException(
                    '"install_dir" must be specified when "install" in a configure_file is true')
            idir_name = idir
            if isinstance(idir_name, P_OBJ.OptionString):
                idir_name = idir_name.optname
            cfile = mesonlib.File.from_built_file(ofile_path, ofile_fname)
            install_tag = kwargs['install_tag']
            self.build.data.append(build.Data([cfile], idir, idir_name, install_mode, self.subproject,
                                              install_tag=install_tag, data_type='configure'))
        return mesonlib.File.from_built_file(self.subdir, output)

    def extract_incdirs(self, kwargs, key: str = 'include_directories') -> T.List[build.IncludeDirs]:
        prospectives = extract_as_list(kwargs, key)
        if key == 'include_directories':
            for i in prospectives:
                if isinstance(i, str):
                    FeatureNew.single_use('include_directories kwarg of type string', '0.50.0', self.subproject,
                                          f'Use include_directories({i!r}) instead', location=self.current_node)
                    break

        result: T.List[build.IncludeDirs] = []
        for p in prospectives:
            if isinstance(p, build.IncludeDirs):
                result.append(p)
            elif isinstance(p, str):
                result.append(self.build_incdir_object([p]))
            else:
                raise InterpreterException('Include directory objects can only be created from strings or include directories.')
        return result

    @typed_pos_args('include_directories', varargs=str)
    @typed_kwargs('include_directories', KwargInfo('is_system', bool, default=False))
    def func_include_directories(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]],
                                 kwargs: 'kwtypes.FuncIncludeDirectories') -> build.IncludeDirs:
        return self.build_incdir_object(args[0], kwargs['is_system'])

    def build_incdir_object(self, incdir_strings: T.List[str], is_system: bool = False) -> build.IncludeDirs:
        if not isinstance(is_system, bool):
            raise InvalidArguments('Is_system must be boolean.')
        src_root = self.environment.get_source_dir()
        absbase_src = os.path.join(src_root, self.subdir)
        absbase_build = self.absolute_builddir_path_for(self.subdir)

        for a in incdir_strings:
            if path_is_in_root(Path(a), Path(src_root)):
                raise InvalidArguments(textwrap.dedent('''\
                    Tried to form an absolute path to a dir in the source tree.
                    You should not do that but use relative paths instead, for
                    directories that are part of your project.

                    To get include path to any directory relative to the current dir do

                    incdir = include_directories(dirname)

                    After this incdir will contain both the current source dir as well as the
                    corresponding build dir. It can then be used in any subdirectory and
                    Meson will take care of all the busywork to make paths work.

                    Dirname can even be '.' to mark the current directory. Though you should
                    remember that the current source and build directories are always
                    put in the include directories by default so you only need to do
                    include_directories('.') if you intend to use the result in a
                    different subdirectory.

                    Note that this error message can also be triggered by
                    external dependencies being installed within your source
                    tree - it's not recommended to do this.
                    '''))
            else:
                try:
                    self.validate_within_subproject(self.subdir, a)
                except InterpreterException:
                    mlog.warning('include_directories sandbox violation!', location=self.current_node)
                    print(textwrap.dedent(f'''\
                        The project is trying to access the directory {a!r} which belongs to a different
                        subproject. This is a problem as it hardcodes the relative paths of these two projects.
                        This makes it impossible to compile the project in any other directory layout and also
                        prevents the subproject from changing its own directory layout.

                        Instead of poking directly at the internals the subproject should be executed and
                        it should set a variable that the caller can then use. Something like:

                        # In subproject
                        some_dep = declare_dependency(include_directories: include_directories('include'))

                        # In subproject wrap file
                        [provide]
                        some = some_dep

                        # In parent project
                        some_dep = dependency('some')
                        executable(..., dependencies: [some_dep])

                        This warning will become a hard error in a future Meson release.
                        '''))
            absdir_src = os.path.join(absbase_src, a)
            absdir_build = os.path.join(absbase_build, a)
            if not os.path.isdir(absdir_src) and not os.path.isdir(absdir_build):
                raise InvalidArguments(f'Include dir {a} does not exist.')
        i = build.IncludeDirs(
            self.subdir, incdir_strings, is_system, is_build_only_subproject=self.coredata.is_build_only)
        return i

    @typed_pos_args('add_test_setup', str)
    @typed_kwargs(
        'add_test_setup',
        KwargInfo('exe_wrapper', ContainerTypeInfo(list, (str, ExternalProgram)), listify=True, default=[]),
        KwargInfo('gdb', bool, default=False),
        KwargInfo('timeout_multiplier', int, default=1),
        KwargInfo('exclude_suites', ContainerTypeInfo(list, str), listify=True, default=[], since='0.57.0'),
        KwargInfo('is_default', bool, default=False, since='0.49.0'),
        ENV_KW,
    )
    def func_add_test_setup(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'kwtypes.AddTestSetup') -> None:
        setup_name = args[0]
        if re.fullmatch('([_a-zA-Z][_0-9a-zA-Z]*:)?[_a-zA-Z][_0-9a-zA-Z]*', setup_name) is None:
            raise InterpreterException('Setup name may only contain alphanumeric characters.')
        if ":" not in setup_name:
            setup_name = f'{(self.subproject if self.subproject else self.build.project_name)}:{setup_name}'

        exe_wrapper: T.List[str] = []
        for i in kwargs['exe_wrapper']:
            if isinstance(i, str):
                exe_wrapper.append(i)
            else:
                if not i.found():
                    raise InterpreterException('Tried to use non-found executable.')
                exe_wrapper += i.get_command()

        timeout_multiplier = kwargs['timeout_multiplier']
        if timeout_multiplier <= 0:
            FeatureNew('add_test_setup() timeout_multiplier <= 0', '0.57.0').use(self.subproject)

        if kwargs['is_default']:
            if self.build.test_setup_default_name is not None:
                raise InterpreterException(f'{self.build.test_setup_default_name!r} is already set as default. '
                                           'is_default can be set to true only once')
            self.build.test_setup_default_name = setup_name
        self.build.test_setups[setup_name] = build.TestSetup(exe_wrapper, kwargs['gdb'], timeout_multiplier, kwargs['env'],
                                                             kwargs['exclude_suites'])

    @typed_pos_args('add_global_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_global_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_global_arguments(node, self.build.global_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_global_link_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_global_link_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_global_arguments(node, self.build.global_link_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_project_arguments', varargs=str)
    @typed_kwargs('add_project_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_project_arguments(node, self.build.projects_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_project_link_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_link_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_project_arguments(node, self.build.projects_link_args[kwargs['native']], args[0], kwargs)

    @FeatureNew('add_project_dependencies', '0.63.0')
    @typed_pos_args('add_project_dependencies', varargs=dependencies.Dependency)
    @typed_kwargs('add_project_dependencies', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_dependencies(self, node: mparser.FunctionNode, args: T.Tuple[T.List[dependencies.Dependency]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        for_machine = kwargs['native']
        for lang in kwargs['language']:
            if lang not in self.compilers[for_machine]:
                raise InvalidCode(f'add_project_dependencies() called before add_language() for language "{lang}"')

        for d in dependencies.get_leaf_external_dependencies(args[0]):
            compile_args = list(d.get_compile_args())
            system_incdir = d.get_include_type() == 'system'
            for i in d.get_include_dirs():
                for lang in kwargs['language']:
                    comp = self.coredata.compilers[for_machine][lang]
                    for idir in i.to_string_list(self.environment.get_source_dir(), self.environment.get_build_dir()):
                        compile_args.extend(comp.get_include_args(idir, system_incdir))

            self._add_project_arguments(node, self.build.projects_args[for_machine], compile_args, kwargs)
            self._add_project_arguments(node, self.build.projects_link_args[for_machine], d.get_link_args(), kwargs)

    def _warn_about_builtin_args(self, args: T.List[str]) -> None:
        # -Wpedantic is deliberately not included, since some people want to use it but not use -Wextra
        # see e.g.
        # https://github.com/mesonbuild/meson/issues/3275#issuecomment-641354956
        # https://github.com/mesonbuild/meson/issues/3742
        warnargs = ('/W1', '/W2', '/W3', '/W4', '/Wall', '-Wall', '-Wextra')
        optargs = ('-O0', '-O2', '-O3', '-Os', '-Oz', '/O1', '/O2', '/Os')
        for arg in args:
            if arg in warnargs:
                mlog.warning(f'Consider using the built-in warning_level option instead of using "{arg}".',
                             location=self.current_node)
            elif arg in optargs:
                mlog.warning(f'Consider using the built-in optimization level instead of using "{arg}".',
                             location=self.current_node)
            elif arg == '-Werror':
                mlog.warning(f'Consider using the built-in werror option instead of using "{arg}".',
                             location=self.current_node)
            elif arg == '-g':
                mlog.warning(f'Consider using the built-in debug option instead of using "{arg}".',
                             location=self.current_node)
            # Don't catch things like `-fsanitize-recover`
            elif arg in {'-fsanitize', '/fsanitize'} or arg.startswith(('-fsanitize=', '/fsanitize=')):
                mlog.warning(f'Consider using the built-in option for sanitizers instead of using "{arg}".',
                             location=self.current_node)
            elif arg.startswith('-std=') or arg.startswith('/std:'):
                mlog.warning(f'Consider using the built-in option for language standard version instead of using "{arg}".',
                             location=self.current_node)

    def _add_global_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.List[str]],
                              args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if self.is_subproject():
            msg = f'Function \'{node.func_name.value}\' cannot be used in subprojects because ' \
                  'there is no way to make that reliable.\nPlease only call ' \
                  'this if is_subproject() returns false. Alternatively, ' \
                  'define a variable that\ncontains your language-specific ' \
                  'arguments and add it to the appropriate *_args kwarg ' \
                  'in each target.'
            raise InvalidCode(msg)
        frozen = self.project_args_frozen or self.global_args_frozen
        self._add_arguments(node, argsdict, frozen, args, kwargs)

    def _add_project_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.Dict[str, T.List[str]]],
                               args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if self.subproject not in argsdict:
            argsdict[self.subproject] = {}
        self._add_arguments(node, argsdict[self.subproject],
                            self.project_args_frozen, args, kwargs)

    def _add_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.List[str]],
                       args_frozen: bool, args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if args_frozen:
            msg = f'Tried to use \'{node.func_name.value}\' after a build target has been declared.\n' \
                  'This is not permitted. Please declare all arguments before your targets.'
            raise InvalidCode(msg)

        self._warn_about_builtin_args(args)

        for lang in kwargs['language']:
            argsdict[lang] = argsdict.get(lang, []) + args

    @noArgsFlattening
    @typed_pos_args('environment', optargs=[(str, list, dict)])
    @typed_kwargs('environment', ENV_METHOD_KW, ENV_SEPARATOR_KW.evolve(since='0.62.0'))
    def func_environment(self, node: mparser.FunctionNode, args: T.Tuple[T.Union[None, str, T.List['TYPE_var'], T.Dict[str, 'TYPE_var']]],
                         kwargs: 'TYPE_kwargs') -> EnvironmentVariables:
        init = args[0]
        if init is not None:
            FeatureNew.single_use('environment positional arguments', '0.52.0', self.subproject, location=node)
            msg = ENV_KW.validator(init)
            if msg:
                raise InvalidArguments(f'"environment": {msg}')
            if isinstance(init, dict) and any(i for i in init.values() if isinstance(i, list)):
                FeatureNew.single_use('List of string in dictionary value', '0.62.0', self.subproject, location=node)
            return env_convertor_with_method(init, kwargs['method'], kwargs['separator'])
        return EnvironmentVariables()

    @typed_pos_args('join_paths', varargs=str, min_varargs=1)
    @noKwargs
    def func_join_paths(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]], kwargs: 'TYPE_kwargs') -> str:
        parts = args[0]
        other = os.path.join('', *parts[1:]).replace('\\', '/')
        ret = os.path.join(*parts).replace('\\', '/')
        if isinstance(parts[0], P_OBJ.DependencyVariableString) and '..' not in other:
            return P_OBJ.DependencyVariableString(ret)
        elif isinstance(parts[0], P_OBJ.OptionString):
            name = os.path.join(parts[0].optname, other)
            return P_OBJ.OptionString(ret, name)
        else:
            return ret

    def run(self) -> None:
        super().run()
        mlog.log('Build targets in project:', mlog.bold(str(len(self.build.targets))))
        FeatureNew.report(self.subproject)
        FeatureDeprecated.report(self.subproject)
        FeatureBroken.report(self.subproject)
        if not self.is_subproject():
            self.print_extra_warnings()
            self._print_summary()

    def print_extra_warnings(self) -> None:
        # TODO cross compilation
        for c in self.coredata.compilers.host.values():
            if c.get_id() == 'clang':
                self.check_clang_asan_lundef()
                break

    def check_clang_asan_lundef(self) -> None:
        if OptionKey('b_lundef') not in self.coredata.options:
            return
        if OptionKey('b_sanitize') not in self.coredata.options:
            return
        if (self.coredata.options[OptionKey('b_lundef')].value and
                self.coredata.options[OptionKey('b_sanitize')].value != 'none'):
            value = self.coredata.options[OptionKey('b_sanitize')].value
            mlog.warning(textwrap.dedent(f'''\
                    Trying to use {value} sanitizer on Clang with b_lundef.
                    This will probably not work.
                    Try setting b_lundef to false instead.'''),
                location=self.current_node)  # noqa: E128

    # Check that the indicated file is within the same subproject
    # as we currently are. This is to stop people doing
    # nasty things like:
    #
    # f = files('../../master_src/file.c')
    #
    # Note that this is validated only when the file
    # object is generated. The result can be used in a different
    # subproject than it is defined in (due to e.g. a
    # declare_dependency).
    def validate_within_subproject(self, subdir, fname):
        srcdir = Path(self.environment.source_dir)
        builddir = Path(self.environment.build_dir)
        if isinstance(fname, P_OBJ.DependencyVariableString):
            def validate_installable_file(fpath: Path) -> bool:
                installablefiles: T.Set[Path] = set()
                for d in self.build.data:
                    for s in d.sources:
                        installablefiles.add(Path(s.absolute_path(srcdir, builddir)))
                installabledirs = [str(Path(srcdir, s.source_subdir)) for s in self.build.install_dirs]
                if fpath in installablefiles:
                    return True
                for d in installabledirs:
                    if str(fpath).startswith(d):
                        return True
                return False

            norm = Path(fname)
            # variables built from a dep.get_variable are allowed to refer to
            # subproject files, as long as they are scheduled to be installed.
            if validate_installable_file(norm):
                return
        norm = Path(os.path.abspath(Path(srcdir, subdir, fname)))
        if os.path.isdir(norm):
            inputtype = 'directory'
        else:
            inputtype = 'file'
        if InterpreterRuleRelaxation.ALLOW_BUILD_DIR_FILE_REFERENCES in self.relaxations and builddir in norm.parents:
            return
        if srcdir not in norm.parents:
            # Grabbing files outside the source tree is ok.
            # This is for vendor stuff like:
            #
            # /opt/vendorsdk/src/file_with_license_restrictions.c
            return
        project_root = Path(srcdir, self.root_subdir)
        subproject_dir = project_root / self.subproject_dir
        if norm == project_root:
            return
        if project_root not in norm.parents:
            raise InterpreterException(f'Sandbox violation: Tried to grab {inputtype} {norm.name} outside current (sub)project.')
        if subproject_dir == norm or subproject_dir in norm.parents:
            raise InterpreterException(f'Sandbox violation: Tried to grab {inputtype} {norm.name} from a nested subproject.')

    @T.overload
    def source_strings_to_files(self, sources: T.List['mesonlib.FileOrString'], strict: bool = True) -> T.List['mesonlib.File']: ...

    @T.overload
    def source_strings_to_files(self, sources: T.List['mesonlib.FileOrString'], strict: bool = False) -> T.List['mesonlib.FileOrString']: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]) -> T.List[T.Union[mesonlib.File, build.GeneratedTypes]]: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List['SourceInputs'], strict: bool = True) -> T.List['SourceOutputs']: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List[SourcesVarargsType], strict: bool = True) -> T.List['SourceOutputs']: ... # noqa: F811

    def source_strings_to_files(self, sources: T.List['SourceInputs'], strict: bool = True) -> T.List['SourceOutputs']: # noqa: F811
        """Lower inputs to a list of Targets and Files, replacing any strings.

        :param sources: A raw (Meson DSL) list of inputs (targets, files, and
            strings)
        :raises InterpreterException: if any of the inputs are of an invalid type
        :return: A list of Targets and Files
        """
        mesonlib.check_direntry_issues(sources)
        if not isinstance(sources, list):
            sources = [sources]
        results: T.List['SourceOutputs'] = []
        for s in sources:
            if isinstance(s, str):
                if not strict and s.startswith(self.environment.get_build_dir()):
                    results.append(s)
                    mlog.warning(f'Source item {s!r} cannot be converted to File object, because it is a generated file. '
                                 'This will become a hard error in the future.', location=self.current_node)
                else:
                    self.validate_within_subproject(self.subdir, s)
                    results.append(mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, s))
            elif isinstance(s, mesonlib.File):
                results.append(s)
            elif isinstance(s, (build.GeneratedList, build.BuildTarget,
                                build.CustomTargetIndex, build.CustomTarget,
                                build.ExtractedObjects, build.StructuredSources)):
                results.append(s)
            else:
                raise InterpreterException(f'Source item is {s!r} instead of '
                                           'string or File-type object')
        return results

    @staticmethod
    def validate_forbidden_targets(name: str) -> None:
        if name.startswith('meson-internal__'):
            raise InvalidArguments("Target names starting with 'meson-internal__' are reserved "
                                   "for Meson's internal use. Please rename.")
        if name.startswith('meson-') and '.' not in name:
            raise InvalidArguments("Target names starting with 'meson-' and without a file extension "
                                   "are reserved for Meson's internal use. Please rename.")
        if name in coredata.FORBIDDEN_TARGET_NAMES:
            raise InvalidArguments(f"Target name '{name}' is reserved for Meson's "
                                   "internal use. Please rename.")

    def add_target(self, name: str, tobj: build.Target) -> None:
        if self.backend.name == 'none':
            raise InterpreterException('Install-only backend cannot generate target rules, try using `--backend=ninja`.')
        if name == '':
            raise InterpreterException('Target name must not be empty.')
        if name.strip() == '':
            raise InterpreterException('Target name must not consist only of whitespace.')
        if has_path_sep(name):
            pathseg = os.path.join(self
"""


```