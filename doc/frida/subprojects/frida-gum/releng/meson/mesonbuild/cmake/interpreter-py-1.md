Response:
The user is asking for a summary of the functionality of the provided Python code. This code is part of the Frida dynamic instrumentation tool and specifically deals with integrating CMake projects into the Meson build system. I need to go through the code and identify its main tasks and how it interacts with the underlying systems.

Here's a breakdown of my thought process:

1. **Identify the core class:** The central class is `CMakeInterpreter`. This suggests that the primary function is to interpret and process CMake project information.

2. **Initialization (`__init__`)**: This method sets up the basic state of the interpreter, including paths, environment information, and data structures to store CMake results and analysis. Key aspects are:
    * Handling different build backends (Visual Studio is specifically mentioned for object library workaround).
    * Setting up the `CMakeFileAPI` to interact with CMake's file API.

3. **Configuration (`configure`)**: This is where the actual interaction with CMake begins. The interpreter executes CMake to configure the subproject. Key steps include:
    * Finding the CMake executable.
    * Setting up a toolchain file to ensure consistent build settings.
    * Passing CMake arguments, including the install prefix.
    * Utilizing `CMakeTraceParser` to capture CMake output for analysis.
    * Handling potential configuration failures.

4. **Initialization (`initialise`)**: This method orchestrates the configuration and then parses the generated CMake file API data. It extracts information about source files and build configurations.

5. **Analysis (`analyse`)**: This is the core of the interpretation process. It parses the captured CMake trace and file API data to understand the project structure, targets, dependencies, and languages used. Key tasks include:
    * Identifying different types of targets (libraries, executables, custom targets).
    * Handling interface targets.
    * Resolving dependencies between targets, including object libraries and custom targets.
    * Cleaning up dependency information to avoid loops.

6. **Meson Integration (`pretend_to_be_meson`)**: This method generates Meson build definitions that mirror the structure and targets of the CMake project. This is the bridge between CMake and Meson. Key actions include:
    * Creating Meson AST nodes (functions, assignments, etc.) representing CMake targets.
    * Handling different target types and their corresponding Meson equivalents.
    * Managing dependencies and include directories.
    * Dealing with custom commands and generated sources.

7. **Target Information (`target_info`) and Target List (`target_list`)**: These methods provide access to information about the processed CMake targets, allowing other parts of the system to query the interpreted data.

8. **Relating to the prompt's questions:**
    * **Reverse engineering:** The code helps understand the structure of a CMake project, which is essential for reverse engineering tools that might need to interact with or analyze software built with CMake.
    * **Binary/low-level, Linux/Android kernel/framework:** The toolchain setup and handling of compiler/linker flags (e.g., PIE) touch upon these areas. The mention of Visual Studio also indicates cross-platform concerns.
    * **Logical reasoning:** The dependency resolution and cycle detection within `analyse` and `pretend_to_be_meson` involve logical reasoning.
    * **User/programming errors:** Incorrect CMake configurations or dependency declarations could lead to errors caught by this code.
    * **User operation to reach here:** A user would typically be using Frida to instrument a process built with CMake. Frida would invoke this code as part of its build process to understand the target application's structure.

9. **Structure the summary:** I'll organize the summary around the main functionalities of the `CMakeInterpreter` class, addressing the specific points raised in the prompt.

By following this process, I can create a comprehensive and accurate summary of the code's functionality.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py` 文件内容的第二部分，主要包含 `CMakeInterpreter` 类的定义及其方法。结合第一部分的内容，我们可以归纳一下它的主要功能：

**总体功能：解析和转换 CMake 项目信息，以便 Meson 构建系统能够理解和集成这些项目。**

**具体功能点：**

1. **CMake 项目的配置和初始化 (`configure`, `initialise`):**
   -  找到并执行 CMake 可执行文件，版本要求 `>=3.14`。
   -  为 CMake 构建配置必要的参数，例如安装前缀 (`CMAKE_INSTALL_PREFIX`)，以及可能的额外 CMake 选项。
   -  使用 `CMakeToolchain` 生成工具链文件，确保构建环境的一致性。
   -  使用 CMake 的 File API (通过 `CMakeFileAPI` 类) 获取 CMake 项目的构建系统信息，例如源文件列表、配置信息等。
   -  加载 CMake 生成的构建系统文件列表 (`bs_files`) 和代码模型配置 (`codemodel_configs`)。
   -  提取项目名称 (`project_name`) 和版本 (`project_version`)。

2. **CMake 项目的分析 (`analyse`):**
   -  解析 CMake 的跟踪信息 (`CMakeTraceParser`) 和 File API 的输出，以理解项目的结构。
   -  识别项目中的目标 (targets)，包括普通目标 (`ConverterTarget`) 和自定义目标 (`ConverterCustomTarget`)。
   -  处理不同类型的目标，例如库、可执行文件等。
   -  解析目标之间的依赖关系。
   -  处理对象库的依赖关系，并针对特定构建系统（例如 Visual Studio）进行特殊处理。
   -  清理和优化目标依赖关系，避免循环依赖。
   -  创建一个输出目标映射 (`output_target_map`)，用于查找目标及其输出。

3. **将 CMake 项目“伪装”成 Meson 项目 (`pretend_to_be_meson`):**
   -  生成一个 Meson 抽象语法树 (AST)，该 AST 描述了与 CMake 项目等效的 Meson 构建定义。
   -  将 CMake 的目标转换为相应的 Meson 函数调用，例如 `executable`, `static_library`, `shared_library`, `custom_target` 等。
   -  处理目标的源文件、头文件、编译选项、链接选项、依赖项等。
   -  处理自定义目标，并使用辅助脚本执行自定义命令。
   -  生成 `declare_dependency` 调用，用于声明其他 Meson 目标可以依赖这些 CMake 目标。
   -  维护一个已处理目标的字典 (`processed`) 和内部名称映射 (`internal_name_map`)。

4. **提供目标信息查询 (`target_info`, `target_list`):**
   -  允许查询特定 CMake 目标的 Meson 信息，例如对应的 Meson 变量名、函数名等。
   -  提供已解析的 CMake 目标列表。

**与逆向方法的关联及举例说明：**

- **理解目标结构:**  在逆向工程中，理解目标程序及其依赖库的结构至关重要。`CMakeInterpreter` 可以帮助理解一个使用 CMake 构建的项目的组件构成，例如哪些是可执行文件，哪些是动态库，它们之间有哪些依赖关系。
    - **举例:** 假设要逆向一个使用 CMake 构建的程序 `my_app`，`CMakeInterpreter` 分析后会告诉你 `my_app` 依赖于哪些静态库或共享库，这些库的源文件在哪里，这对于理解 `my_app` 的功能模块和代码组织很有帮助。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

- **编译和链接选项:** 代码中处理了 CMake 目标的编译选项 (`compile_opts`) 和链接选项 (`link_flags`, `link_libraries`)，这些选项直接影响最终生成的二进制文件的特性，例如是否启用 PIE (Position Independent Executable)，链接哪些库等。
    - **举例:** 如果 CMake 项目中某个目标设置了 `-fPIC` 编译选项，`CMakeInterpreter` 会识别出来，这表明该目标生成的是位置无关代码，常用于构建共享库。在 Android 开发中，理解 NDK 构建系统如何处理这些选项对于逆向分析 Native 代码至关重要。
- **目标类型:** 代码中区分了不同类型的目标，例如 `executable`, `shared_library`, `static_library`, `shared_module` 等，这些类型直接对应着操作系统中不同的二进制文件格式和加载方式。
    - **举例:**  在 Linux 或 Android 中，理解一个目标是 `shared_library` 意味着它是一个动态链接库，在程序运行时会被加载到进程空间。这对于理解程序的运行时依赖和动态加载行为很重要。

**逻辑推理及假设输入与输出：**

- **依赖关系解析:** `CMakeInterpreter` 需要进行逻辑推理来解析 CMake 目标之间的依赖关系。例如，如果目标 A 链接了目标 B，那么 B 必须在 A 之前构建完成。
    - **假设输入:**  一个 CMake 项目定义了两个库 `liba` 和 `libb`，以及一个可执行文件 `app`。 `app` 链接了 `liba`，`liba` 链接了 `libb`。
    - **输出:** `pretend_to_be_meson` 方法会生成相应的 Meson 构建定义，确保 `libb` 在 `liba` 之前构建，`liba` 在 `app` 之前构建。生成的 Meson 代码中，`app` 的 `link_with` 参数会包含对 `liba` 的引用，`liba` 的 `link_with` 参数会包含对 `libb` 的引用。

**涉及用户或者编程常见的使用错误及举例说明：**

- **循环依赖:** 如果 CMake 项目中存在循环依赖（例如，目标 A 依赖于目标 B，目标 B 又依赖于目标 A），`CMakeInterpreter` 的 `detect_cycle` 方法会检测到这种错误并抛出异常。
    - **举例:** 用户在编写 `CMakeLists.txt` 文件时，不小心将两个库相互依赖，运行 Frida 构建时，`CMakeInterpreter` 会报错，提示存在循环依赖，帮助用户定位和修复配置错误。
- **找不到 CMake:** 如果用户的系统环境中没有安装 CMake 或者 CMake 不在 PATH 环境变量中，`CMakeInterpreter` 在 `configure` 方法中会抛出 `CMakeException('Unable to find CMake')`。
    - **举例:** 用户首次使用 Frida 集成 CMake 项目时，忘记安装 CMake，构建过程会因为找不到 CMake 可执行文件而失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试使用 Frida 去 hook 或 instrument 一个使用 CMake 构建的应用程序。**
2. **Frida 的构建系统需要理解目标应用程序的构建方式，才能正确地进行代码注入和拦截。**
3. **Frida 的构建系统会检测到目标应用程序使用了 CMake。**
4. **Frida 会调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py` 中的 `CMakeInterpreter` 类来解析目标应用程序的 `CMakeLists.txt` 文件和其他 CMake 相关的文件。**
5. **`CMakeInterpreter` 会执行 CMake 的配置步骤，并解析 CMake 生成的 File API 信息。**
6. **`pretend_to_be_meson` 方法会将解析到的 CMake 信息转换为 Meson 的构建定义。**
7. **Meson 构建系统使用这些转换后的定义来生成最终的构建脚本，用于构建 Frida agent 或者进行 instrumentation。**

因此，当用户使用 Frida 对基于 CMake 的应用程序进行操作时，例如使用 `frida` 命令或编写 Frida 脚本，Frida 内部的构建流程会自动触发 `CMakeInterpreter` 的运行。如果构建过程中出现与 CMake 相关的错误，查看 `CMakeInterpreter` 的日志输出和源码可以提供调试线索，例如 CMake 配置失败、依赖关系解析错误等。

**总结 `CMakeInterpreter` 的功能：**

`CMakeInterpreter` 的核心功能是作为 Frida 构建系统中连接 CMake 和 Meson 的桥梁。它负责解析 CMake 项目的配置和结构信息，并将其转换为 Meson 构建系统能够理解的形式。这使得 Frida 能够方便地集成和操作使用 CMake 构建的目标应用程序。它涉及到对 CMake 构建流程、目标类型、依赖关系、编译和链接选项的深入理解，以及将这些概念映射到 Meson 构建系统的能力。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
mlog.bold(str(self.conflict_map)))
        mlog.log('  -- working_dir:  ', mlog.bold(str(self.working_dir)))
        mlog.log('  -- depends_raw:  ', mlog.bold(str(self.depends_raw)))
        mlog.log('  -- inputs:       ', mlog.bold(str(self.inputs)))
        mlog.log('  -- depends:      ', mlog.bold(str(self.depends)))

class CMakeInterpreter:
    def __init__(self, subdir: Path, install_prefix: Path, env: 'Environment', backend: 'Backend', for_machine: MachineChoice):
        self.subdir = subdir
        self.src_dir = Path(env.get_source_dir(), subdir)
        self.build_dir_rel = subdir / '__CMake_build'
        self.build_dir = Path(env.get_build_dir()) / self.build_dir_rel
        self.install_prefix = install_prefix
        self.env = env
        self.for_machine = for_machine
        self.backend_name = backend.name
        self.linkers: T.Set[str] = set()
        self.fileapi = CMakeFileAPI(self.build_dir)

        # Raw CMake results
        self.bs_files: T.List[Path] = []
        self.codemodel_configs: T.Optional[T.List[CMakeConfiguration]] = None
        self.cmake_stderr: T.Optional[str] = None

        # Analysed data
        self.project_name = ''
        self.project_version = ''
        self.languages: T.List[str] = []
        self.targets: T.List[ConverterTarget] = []
        self.custom_targets: T.List[ConverterCustomTarget] = []
        self.trace: CMakeTraceParser
        self.output_target_map = OutputTargetMap(self.build_dir)

        # Generated meson data
        self.generated_targets: T.Dict[str, T.Dict[str, T.Optional[str]]] = {}
        self.internal_name_map: T.Dict[str, str] = {}

        # Do some special handling for object libraries for certain configurations
        self._object_lib_workaround = False
        if self.backend_name.startswith('vs'):
            for comp in self.env.coredata.compilers[self.for_machine].values():
                if comp.get_linker_id() == 'link':
                    self._object_lib_workaround = True
                    break

    def configure(self, extra_cmake_options: T.List[str]) -> CMakeExecutor:
        # Find CMake
        cmake_exe = CMakeExecutor(self.env, '>=3.14', self.for_machine)
        if not cmake_exe.found():
            raise CMakeException('Unable to find CMake')
        self.trace = CMakeTraceParser(cmake_exe.version(), self.build_dir, self.env, permissive=True)

        preload_file = DataFile('cmake/data/preload.cmake').write_to_private(self.env)
        toolchain = CMakeToolchain(cmake_exe, self.env, self.for_machine, CMakeExecScope.SUBPROJECT, self.build_dir, preload_file)
        toolchain_file = toolchain.write()

        # TODO: drop this check once the deprecated `cmake_args` kwarg is removed
        extra_cmake_options = check_cmake_args(extra_cmake_options)

        cmake_args = []
        cmake_args += cmake_get_generator_args(self.env)
        cmake_args += [f'-DCMAKE_INSTALL_PREFIX={self.install_prefix}']
        cmake_args += extra_cmake_options
        trace_args = self.trace.trace_args()
        cmcmp_args = [f'-DCMAKE_POLICY_WARNING_{x}=OFF' for x in disable_policy_warnings]

        self.fileapi.setup_request()

        # Run CMake
        mlog.log()
        with mlog.nested():
            mlog.log('Configuring the build directory with', mlog.bold('CMake'), 'version', mlog.cyan(cmake_exe.version()))
            mlog.log(mlog.bold('Running CMake with:'), ' '.join(cmake_args))
            mlog.log(mlog.bold('  - build directory:         '), self.build_dir.as_posix())
            mlog.log(mlog.bold('  - source directory:        '), self.src_dir.as_posix())
            mlog.log(mlog.bold('  - toolchain file:          '), toolchain_file.as_posix())
            mlog.log(mlog.bold('  - preload file:            '), preload_file.as_posix())
            mlog.log(mlog.bold('  - trace args:              '), ' '.join(trace_args))
            mlog.log(mlog.bold('  - disabled policy warnings:'), '[{}]'.format(', '.join(disable_policy_warnings)))
            mlog.log()
            self.build_dir.mkdir(parents=True, exist_ok=True)
            os_env = environ.copy()
            os_env['LC_ALL'] = 'C'
            final_args = cmake_args + trace_args + cmcmp_args + toolchain.get_cmake_args() + [self.src_dir.as_posix()]

            cmake_exe.set_exec_mode(print_cmout=True, always_capture_stderr=self.trace.requires_stderr())
            rc, _, self.cmake_stderr = cmake_exe.call(final_args, self.build_dir, env=os_env, disable_cache=True)

        mlog.log()
        h = mlog.green('SUCCEEDED') if rc == 0 else mlog.red('FAILED')
        mlog.log('CMake configuration:', h)
        if rc != 0:
            # get the last CMake error - We only need the message function for this:
            self.trace.functions = {'message': self.trace.functions['message']}
            self.trace.parse(self.cmake_stderr)
            error = f': {self.trace.errors[-1]}' if self.trace.errors else ''
            raise CMakeException(f'Failed to configure the CMake subproject{error}')

        return cmake_exe

    def initialise(self, extra_cmake_options: T.List[str]) -> None:
        # Configure the CMake project to generate the file API data
        self.configure(extra_cmake_options)

        # Parse the result
        self.fileapi.load_reply()

        # Load the buildsystem file list
        cmake_files = self.fileapi.get_cmake_sources()
        self.bs_files = [x.file for x in cmake_files if not x.is_cmake and not x.is_temp]
        self.bs_files = [relative_to_if_possible(x, Path(self.env.get_source_dir())) for x in self.bs_files]
        self.bs_files = [x for x in self.bs_files if not path_is_in_root(x, Path(self.env.get_build_dir()), resolve=True)]
        self.bs_files = list(OrderedSet(self.bs_files))

        # Load the codemodel configurations
        self.codemodel_configs = self.fileapi.get_cmake_configurations()

        self.project_version = self.fileapi.get_project_version()

    def analyse(self) -> None:
        if self.codemodel_configs is None:
            raise CMakeException('CMakeInterpreter was not initialized')

        # Clear analyser data
        self.project_name = ''
        self.languages = []
        self.targets = []
        self.custom_targets = []

        # Parse the trace
        self.trace.parse(self.cmake_stderr)

        # Find all targets
        added_target_names: T.List[str] = []
        for i_0 in self.codemodel_configs:
            for j_0 in i_0.projects:
                if not self.project_name:
                    self.project_name = j_0.name
                for k_0 in j_0.targets:
                    # Avoid duplicate targets from different configurations and known
                    # dummy CMake internal target types
                    if k_0.type not in skip_targets and k_0.name not in added_target_names:
                        added_target_names += [k_0.name]
                        self.targets += [ConverterTarget(k_0, self.env, self.for_machine)]

        # Add interface targets from trace, if not already present.
        # This step is required because interface targets were removed from
        # the CMake file API output.
        api_target_name_list = [x.name for x in self.targets]
        for i_1 in self.trace.targets.values():
            if i_1.type != 'INTERFACE' or i_1.name in api_target_name_list or i_1.imported:
                continue
            dummy = CMakeTarget({
                'name': i_1.name,
                'type': 'INTERFACE_LIBRARY',
                'sourceDirectory': self.src_dir,
                'buildDirectory': self.build_dir,
            })
            self.targets += [ConverterTarget(dummy, self.env, self.for_machine)]

        for i_2 in self.trace.custom_targets:
            self.custom_targets += [ConverterCustomTarget(i_2, self.env, self.for_machine)]

        # generate the output_target_map
        for i_3 in [*self.targets, *self.custom_targets]:
            assert isinstance(i_3, (ConverterTarget, ConverterCustomTarget))
            self.output_target_map.add(i_3)

        # First pass: Basic target cleanup
        object_libs = []
        custom_target_outputs: T.List[str] = []
        for ctgt in self.custom_targets:
            ctgt.postprocess(self.output_target_map, self.src_dir, custom_target_outputs, self.trace)
        for tgt in self.targets:
            tgt.postprocess(self.output_target_map, self.src_dir, self.subdir, self.install_prefix, self.trace)
            if tgt.type == 'OBJECT_LIBRARY':
                object_libs += [tgt]
            self.languages += [x for x in tgt.languages if x not in self.languages]

        # Second pass: Detect object library dependencies
        for tgt in self.targets:
            tgt.process_object_libs(object_libs, self._object_lib_workaround)

        # Third pass: Reassign dependencies to avoid some loops
        for tgt in self.targets:
            tgt.process_inter_target_dependencies()
        for ctgt in self.custom_targets:
            ctgt.process_inter_target_dependencies()

        # Fourth pass: Remove rassigned dependencies
        for tgt in self.targets:
            tgt.cleanup_dependencies()

        mlog.log('CMake project', mlog.bold(self.project_name), mlog.bold(self.project_version), 'has', mlog.bold(str(len(self.targets) + len(self.custom_targets))), 'build targets.')

    def pretend_to_be_meson(self, options: TargetOptions) -> CodeBlockNode:
        if not self.project_name:
            raise CMakeException('CMakeInterpreter was not analysed')

        def token(tid: str = 'string', val: TYPE_mixed = '') -> Token:
            return Token(tid, self.subdir.as_posix(), 0, 0, 0, None, val)

        def symbol(val: str) -> SymbolNode:
            return SymbolNode(token('', val))

        def string(value: str) -> StringNode:
            return StringNode(token(val=value), escape=False)

        def id_node(value: str) -> IdNode:
            return IdNode(token(val=value))

        def number(value: int) -> NumberNode:
            return NumberNode(token(val=str(value)))

        def nodeify(value: TYPE_mixed_list) -> BaseNode:
            if isinstance(value, str):
                return string(value)
            if isinstance(value, Path):
                return string(value.as_posix())
            elif isinstance(value, bool):
                return BooleanNode(token(val=value))
            elif isinstance(value, int):
                return number(value)
            elif isinstance(value, list):
                return array(value)
            elif isinstance(value, BaseNode):
                return value
            raise RuntimeError('invalid type of value: {} ({})'.format(type(value).__name__, str(value)))

        def indexed(node: BaseNode, index: int) -> IndexNode:
            return IndexNode(node, symbol('['), nodeify(index), symbol(']'))

        def array(elements: TYPE_mixed_list) -> ArrayNode:
            args = ArgumentNode(token())
            if not isinstance(elements, list):
                elements = [args]
            args.arguments += [nodeify(x) for x in elements if x is not None]
            return ArrayNode(symbol('['), args, symbol(']'))

        def function(name: str, args: T.Optional[TYPE_mixed_list] = None, kwargs: T.Optional[TYPE_mixed_kwargs] = None) -> FunctionNode:
            args = [] if args is None else args
            kwargs = {} if kwargs is None else kwargs
            args_n = ArgumentNode(token())
            if not isinstance(args, list):
                assert isinstance(args, (str, int, bool, Path, BaseNode))
                args = [args]
            args_n.arguments = [nodeify(x) for x in args if x is not None]
            args_n.kwargs = {id_node(k): nodeify(v) for k, v in kwargs.items() if v is not None}
            func_n = FunctionNode(id_node(name), symbol('('), args_n, symbol(')'))
            return func_n

        def method(obj: BaseNode, name: str, args: T.Optional[TYPE_mixed_list] = None, kwargs: T.Optional[TYPE_mixed_kwargs] = None) -> MethodNode:
            args = [] if args is None else args
            kwargs = {} if kwargs is None else kwargs
            args_n = ArgumentNode(token())
            if not isinstance(args, list):
                assert isinstance(args, (str, int, bool, Path, BaseNode))
                args = [args]
            args_n.arguments = [nodeify(x) for x in args if x is not None]
            args_n.kwargs = {id_node(k): nodeify(v) for k, v in kwargs.items() if v is not None}
            return MethodNode(obj, symbol('.'), id_node(name), symbol('('), args_n, symbol(')'))

        def assign(var_name: str, value: BaseNode) -> AssignmentNode:
            return AssignmentNode(id_node(var_name), symbol('='), value)

        # Generate the root code block and the project function call
        root_cb = CodeBlockNode(token())
        root_cb.lines += [function('project', [self.project_name] + self.languages, {'version': self.project_version} if self.project_version else None)]

        # Add the run script for custom commands

        # Add the targets
        processing: T.List[str] = []
        processed: T.Dict[str, T.Dict[str, T.Optional[str]]] = {}
        name_map: T.Dict[str, str] = {}

        def extract_tgt(tgt: T.Union[ConverterTarget, ConverterCustomTarget, CustomTargetReference]) -> IdNode:
            tgt_name = None
            if isinstance(tgt, (ConverterTarget, ConverterCustomTarget)):
                tgt_name = tgt.name
            elif isinstance(tgt, CustomTargetReference):
                tgt_name = tgt.ctgt.name
            assert tgt_name is not None and tgt_name in processed
            res_var = processed[tgt_name]['tgt']
            return id_node(res_var) if res_var else None

        def detect_cycle(tgt: T.Union[ConverterTarget, ConverterCustomTarget]) -> None:
            if tgt.name in processing:
                raise CMakeException('Cycle in CMake inputs/dependencies detected')
            processing.append(tgt.name)

        def resolve_ctgt_ref(ref: CustomTargetReference) -> T.Union[IdNode, IndexNode]:
            tgt_var = extract_tgt(ref)
            if len(ref.ctgt.outputs) == 1:
                return tgt_var
            else:
                return indexed(tgt_var, ref.index)

        def process_target(tgt: ConverterTarget) -> None:
            detect_cycle(tgt)

            # First handle inter target dependencies
            link_with: T.List[IdNode] = []
            objec_libs: T.List[IdNode] = []
            sources: T.List[Path] = []
            generated: T.List[T.Union[IdNode, IndexNode]] = []
            generated_filenames: T.List[str] = []
            custom_targets: T.List[ConverterCustomTarget] = []
            dependencies: T.List[IdNode] = []
            for i in tgt.link_with:
                assert isinstance(i, ConverterTarget)
                if i.name not in processed:
                    process_target(i)
                link_with += [extract_tgt(i)]
            for i in tgt.object_libs:
                assert isinstance(i, ConverterTarget)
                if i.name not in processed:
                    process_target(i)
                objec_libs += [extract_tgt(i)]
            for i in tgt.depends:
                if not isinstance(i, ConverterCustomTarget):
                    continue
                if i.name not in processed:
                    process_custom_target(i)
                dependencies += [extract_tgt(i)]

            # Generate the source list and handle generated sources
            sources += tgt.sources
            sources += tgt.generated

            for ctgt_ref in tgt.generated_ctgt:
                ctgt = ctgt_ref.ctgt
                if ctgt.name not in processed:
                    process_custom_target(ctgt)
                generated += [resolve_ctgt_ref(ctgt_ref)]
                generated_filenames += [ctgt_ref.filename()]
                if ctgt not in custom_targets:
                    custom_targets += [ctgt]

            # Add all header files from all used custom targets. This
            # ensures that all custom targets are built before any
            # sources of the current target are compiled and thus all
            # header files are present. This step is necessary because
            # CMake always ensures that a custom target is executed
            # before another target if at least one output is used.
            for ctgt in custom_targets:
                for j in ctgt.outputs:
                    if not is_header(j) or j in generated_filenames:
                        continue

                    generated += [resolve_ctgt_ref(ctgt.get_ref(Path(j)))]
                    generated_filenames += [j]

            # Determine the meson function to use for the build target
            tgt_func = tgt.meson_func()
            if not tgt_func:
                raise CMakeException(f'Unknown target type "{tgt.type}"')

            # Determine the variable names
            inc_var = f'{tgt.name}_inc'
            dir_var = f'{tgt.name}_dir'
            sys_var = f'{tgt.name}_sys'
            src_var = f'{tgt.name}_src'
            dep_var = f'{tgt.name}_dep'
            tgt_var = tgt.name

            install_tgt = options.get_install(tgt.cmake_name, tgt.install)

            # Generate target kwargs
            tgt_kwargs: TYPE_mixed_kwargs = {
                'build_by_default': install_tgt,
                'link_args': options.get_link_args(tgt.cmake_name, tgt.link_flags + tgt.link_libraries),
                'link_with': link_with,
                'include_directories': id_node(inc_var),
                'install': install_tgt,
                'override_options': options.get_override_options(tgt.cmake_name, tgt.override_options),
                'objects': [method(x, 'extract_all_objects') for x in objec_libs],
            }

            # Only set if installed and only override if it is set
            if install_tgt and tgt.install_dir:
                tgt_kwargs['install_dir'] = tgt.install_dir

            # Handle compiler args
            for key, val in tgt.compile_opts.items():
                tgt_kwargs[f'{key}_args'] = options.get_compile_args(tgt.cmake_name, key, val)

            # Handle -fPCI, etc
            if tgt_func == 'executable':
                tgt_kwargs['pie'] = tgt.pie
            elif tgt_func == 'static_library':
                tgt_kwargs['pic'] = tgt.pie

            # declare_dependency kwargs
            dep_kwargs: TYPE_mixed_kwargs = {
                'link_args': tgt.link_flags + tgt.link_libraries,
                'link_with': id_node(tgt_var),
                'compile_args': tgt.public_compile_opts,
                'include_directories': id_node(inc_var),
            }

            if dependencies:
                generated += dependencies

            # Generate the function nodes
            dir_node = assign(dir_var, function('include_directories', tgt.includes))
            sys_node = assign(sys_var, function('include_directories', tgt.sys_includes, {'is_system': True}))
            inc_node = assign(inc_var, array([id_node(dir_var), id_node(sys_var)]))
            node_list = [dir_node, sys_node, inc_node]
            if tgt_func == 'header_only':
                del dep_kwargs['link_with']
                dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                node_list += [dep_node]
                src_var = None
                tgt_var = None
            else:
                src_node = assign(src_var, function('files', sources))
                tgt_node = assign(tgt_var, function(tgt_func, [tgt_var, id_node(src_var), *generated], tgt_kwargs))
                node_list += [src_node, tgt_node]
                if tgt_func in {'static_library', 'shared_library'}:
                    dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                    node_list += [dep_node]
                elif tgt_func == 'shared_module':
                    del dep_kwargs['link_with']
                    dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                    node_list += [dep_node]
                else:
                    dep_var = None

            # Add the nodes to the ast
            root_cb.lines += node_list
            processed[tgt.name] = {'inc': inc_var, 'src': src_var, 'dep': dep_var, 'tgt': tgt_var, 'func': tgt_func}
            name_map[tgt.cmake_name] = tgt.name

        def process_custom_target(tgt: ConverterCustomTarget) -> None:
            # CMake allows to specify multiple commands in a custom target.
            # To map this to meson, a helper script is used to execute all
            # commands in order. This additionally allows setting the working
            # directory.

            detect_cycle(tgt)
            tgt_var = tgt.name

            def resolve_source(x: T.Union[str, ConverterTarget, ConverterCustomTarget, CustomTargetReference]) -> T.Union[str, IdNode, IndexNode]:
                if isinstance(x, ConverterTarget):
                    if x.name not in processed:
                        process_target(x)
                    return extract_tgt(x)
                if isinstance(x, ConverterCustomTarget):
                    if x.name not in processed:
                        process_custom_target(x)
                    return extract_tgt(x)
                elif isinstance(x, CustomTargetReference):
                    if x.ctgt.name not in processed:
                        process_custom_target(x.ctgt)
                    return resolve_ctgt_ref(x)
                else:
                    return x

            # Generate the command list
            command: T.List[T.Union[str, IdNode, IndexNode]] = []
            command += mesonlib.get_meson_command()
            command += ['--internal', 'cmake_run_ctgt']
            command += ['-o', '@OUTPUT@']
            if tgt.original_outputs:
                command += ['-O'] + [x.as_posix() for x in tgt.original_outputs]
            command += ['-d', tgt.working_dir.as_posix()]

            # Generate the commands. Subcommands are separated by ';;;'
            for cmd in tgt.command:
                command += [resolve_source(x) for x in cmd] + [';;;']

            tgt_kwargs: TYPE_mixed_kwargs = {
                'input': [resolve_source(x) for x in tgt.inputs],
                'output': tgt.outputs,
                'command': command,
                'depends': [resolve_source(x) for x in tgt.depends],
            }

            root_cb.lines += [assign(tgt_var, function('custom_target', [tgt.name], tgt_kwargs))]
            processed[tgt.name] = {'inc': None, 'src': None, 'dep': None, 'tgt': tgt_var, 'func': 'custom_target'}
            name_map[tgt.cmake_name] = tgt.name

        # Now generate the target function calls
        for ctgt in self.custom_targets:
            if ctgt.name not in processed:
                process_custom_target(ctgt)
        for tgt in self.targets:
            if tgt.name not in processed:
                process_target(tgt)

        self.generated_targets = processed
        self.internal_name_map = name_map
        return root_cb

    def target_info(self, target: str) -> T.Optional[T.Dict[str, str]]:
        # Try resolving the target name
        # start by checking if there is a 100% match (excluding the name prefix)
        prx_tgt = _sanitize_cmake_name(target)
        if prx_tgt in self.generated_targets:
            return self.generated_targets[prx_tgt]
        # check if there exists a name mapping
        if target in self.internal_name_map:
            target = self.internal_name_map[target]
            assert target in self.generated_targets
            return self.generated_targets[target]
        return None

    def target_list(self) -> T.List[str]:
        return list(self.internal_name_map.keys())

"""


```