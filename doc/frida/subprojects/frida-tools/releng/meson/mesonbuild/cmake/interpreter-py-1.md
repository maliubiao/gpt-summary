Response:
The user wants me to analyze the provided Python code, which is a part of the Frida dynamic instrumentation tool. I need to list its functionalities, explain its relation to reverse engineering, discuss its use of binary, Linux, Android kernel/framework concepts, illustrate logical reasoning with input/output examples, highlight potential user errors, explain how a user might reach this code, and finally, summarize its functions.

**Part 1: Deconstructing the Request**

1. **List Functionalities:**  I need to go through the code and identify what actions it performs.
2. **Reverse Engineering Relevance:**  Connect the code's actions to common reverse engineering tasks or concepts.
3. **Binary/OS/Kernel Knowledge:**  Point out sections where understanding of low-level concepts is necessary.
4. **Logical Reasoning:** Identify any conditional logic or data transformations and provide examples.
5. **User Errors:** Consider common mistakes a user could make that would interact with this code.
6. **User Path:** Explain the steps a user would take in Frida to invoke this specific part of the code.
7. **Summary:** Concisely summarize the code's main purpose.

**Part 2:  Analyzing the Code - Preliminary Scan**

The code seems to be a `CMakeInterpreter` class. It's involved in processing CMake project information to integrate it with the Meson build system. This suggests:

*   **Functionality:** Parsing CMake files, configuring CMake, analyzing CMake targets (libraries, executables, custom targets), and generating Meson build definitions.
*   **Reverse Engineering:** Integrating external libraries or components (often built with CMake) into a Frida project.
*   **Binary/OS/Kernel:**  CMake often deals with compiler flags, linker settings, and platform-specific configurations, which have direct implications for binary creation and execution on different operating systems.
*   **Logical Reasoning:** The code likely uses conditional logic to handle different types of CMake targets and configurations.
*   **User Errors:** Incorrect CMake options, missing dependencies, or conflicts between CMake and Meson settings are possibilities.
*   **User Path:**  A user would likely use a Frida feature that allows incorporating external CMake-based projects or libraries.

**Part 3:  Detailed Code Analysis - Identifying Key Operations**

*   **`__init__`:**  Initializes the interpreter, setting up paths, environment, and data structures to store CMake information.
*   **`configure`:**  Finds and executes CMake, passing necessary arguments like install prefix, toolchain file, and extra options. This is where the actual CMake configuration happens.
*   **`initialise`:**  Runs the CMake configuration and then parses the generated CMake File API data. This populates the interpreter with information about the CMake project.
*   **`analyse`:**  Processes the parsed CMake data to extract project name, languages, targets, and custom targets. It resolves dependencies and performs cleanup.
*   **`pretend_to_be_meson`:** This is the core of the integration. It takes the analyzed CMake information and generates Meson build definitions (represented as an Abstract Syntax Tree - AST). This involves mapping CMake concepts (targets, dependencies, options) to their Meson equivalents.
*   **`target_info`:**  Provides information about a specific CMake target.
*   **`target_list`:** Returns a list of processed CMake target names.

**Part 4: Connecting to the Request - Filling in the Details**

Now I will go through each point of the request and use the information gathered from the code analysis.

**Part 5:  Final Review and Structuring the Output**

I need to ensure the output is clear, well-structured, and directly addresses all parts of the user's request. I should organize the functionalities, examples, and explanations logically. The summary should be concise and highlight the key role of this module.这是Frida动态Instrumentation工具的源代码文件 `frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/interpreter.py` 的第二部分，其主要功能是**将已解析和分析的CMake项目信息转换为Meson构建系统的表示形式**。

这是对第一部分功能的延续，在第一部分中，CMake项目已经被配置和初步分析。第二部分专注于将CMake的项目结构、目标、依赖关系等信息，转换成Meson能够理解和使用的代码结构。

以下是更详细的功能列表，以及与逆向、底层知识、逻辑推理、用户错误和调试线索相关的说明：

**主要功能归纳：**

1. **将CMake项目信息“伪装”成Meson项目定义 (`pretend_to_be_meson` 方法):**
    *   这是核心功能。它接收已分析的CMake项目信息，并生成一个代表该项目的Meson抽象语法树 (AST)。
    *   这个过程涉及到将CMake的目标（库、可执行文件、自定义目标等）、源文件、头文件、编译选项、链接选项、依赖关系等映射到Meson的对应概念和函数。
    *   它通过构建 Meson AST 节点（例如 `FunctionNode`, `AssignmentNode`, `ArrayNode` 等）来模拟 Meson 的项目定义。

2. **处理不同类型的CMake目标:**
    *   代码能够识别和处理不同类型的CMake目标，例如静态库、共享库、可执行文件、头文件库和自定义目标。
    *   对于每种目标类型，它会调用相应的Meson函数（例如 `static_library`, `shared_library`, `executable`, `custom_target`, `declare_dependency`）。

3. **处理目标之间的依赖关系:**
    *   代码会分析CMake目标之间的依赖关系（例如链接库、依赖的自定义目标），并在生成的Meson代码中正确地表示这些关系（例如使用 `link_with` 和 `depends` 参数）。
    *   它还会处理对象库的特殊情况，以及避免循环依赖。

4. **处理编译和链接选项:**
    *   代码会将CMake的编译选项和链接选项转换为Meson的对应参数（例如 `compile_args`, `link_args`）。

5. **处理自定义目标:**
    *   对于CMake的自定义目标，代码会生成一个 `custom_target` 的Meson定义，并使用一个内部脚本 (`cmake_run_ctgt`) 来执行自定义命令。

6. **提供目标信息查询接口 (`target_info` 和 `target_list` 方法):**
    *   `target_info` 方法允许根据目标名称查询已生成的Meson目标信息（例如变量名、类型）。
    *   `target_list` 方法返回所有已处理的CMake目标名称列表。

**与逆向方法的关联举例说明：**

*   **集成第三方库:** 在逆向工程中，经常需要集成使用CMake构建的第三方库。这个 `CMakeInterpreter` 的作用就是将这些库的构建信息转换成Frida (使用Meson) 可以理解的形式，使得Frida可以依赖和链接这些库。例如，某个需要逆向的程序依赖了一个使用 CMake 构建的加密库，Frida 通过这个 `CMakeInterpreter` 可以将该加密库集成到 Frida 的构建过程中。
*   **理解构建过程:** 通过查看 `pretend_to_be_meson` 生成的 Meson 代码，逆向工程师可以更好地理解目标 CMake 项目的构建过程，例如编译选项、链接依赖等。

**涉及到二进制底层、Linux、Android内核及框架的知识举例说明：**

*   **编译和链接选项:** 代码中处理的 `compile_opts` 和 `link_flags` 等直接关系到二进制文件的生成。不同的选项会影响二进制文件的结构、性能和安全性。例如， `-fPIC` 选项用于生成位置无关代码，这对于共享库在 Linux 和 Android 等系统上的加载是必要的。
*   **目标类型:** 理解不同目标类型（静态库、共享库、可执行文件）在操作系统中的加载和链接机制对于逆向分析至关重要。例如，共享库在 Linux 和 Android 中使用 `dlopen` 等机制动态加载。
*   **自定义目标:** 自定义目标可以执行任意命令，这可能涉及到与操作系统底层的交互，例如文件操作、进程管理等。在 Android 逆向中，自定义目标可能用于执行 adb 命令或与 Android 框架进行交互。
*   **工具链:** `CMakeToolchain` 涉及到选择合适的编译器和链接器。在 Android 开发中，通常需要使用 Android NDK 提供的工具链进行交叉编译。

**逻辑推理的假设输入与输出：**

**假设输入:** 一个简单的 CMakeLists.txt 文件定义了一个名为 "mylib" 的静态库，依赖于另一个名为 "utils" 的头文件库。

```cmake
cmake_minimum_required(VERSION 3.14)
project(MyProject)

add_library(utils INTERFACE)
target_include_directories(utils INTERFACE include)

add_library(mylib STATIC
    src/mylib.c
)
target_link_libraries(mylib utils)
target_include_directories(mylib PUBLIC include)
```

**预期输出 (部分生成的 Meson 代码):**

```meson
project('MyProject', 'c')

utils_inc_dir = include_directories('include')
utils_sys_inc = include_directories(include, is_system: true)
utils_inc = [utils_inc_dir, utils_sys_inc]
utils_dep = declare_dependency(include_directories: utils_inc)

mylib_inc_dir = include_directories('include')
mylib_sys_inc = include_directories(include, is_system: true)
mylib_inc = [mylib_inc_dir, mylib_sys_inc]
mylib_src = files('src/mylib.c')
mylib = static_library('mylib', mylib_src, include_directories: mylib_inc, link_with: utils)
mylib_dep = declare_dependency(link_with: mylib, include_directories: mylib_inc)
```

**涉及用户或者编程常见的使用错误举例说明：**

*   **CMake配置错误:** 如果用户提供的 CMakeLists.txt 文件存在语法错误或者逻辑错误，CMake 配置阶段可能会失败，导致 `CMakeInterpreter.configure` 抛出 `CMakeException`。例如，忘记使用 `target_sources` 添加源文件。
*   **依赖项缺失:** 如果 CMake 项目依赖的第三方库或系统库未安装或路径配置不正确，CMake 配置可能会失败。
*   **CMake选项冲突:** 用户通过 `extra_cmake_options` 传递了与 Meson 默认设置冲突的 CMake 选项，可能导致构建错误或意想不到的行为。例如，强制使用与 Meson 默认编译器不同的编译器。
*   **自定义目标命令错误:** 如果自定义目标的 `command` 中引用的文件不存在或命令语法错误，在构建过程中执行该自定义目标时会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要在 Frida 中使用一个基于 CMake 构建的模块或库。**
2. **Frida 的构建系统 (Meson) 遇到需要处理 CMake 项目的情况。** 这通常发生在 Frida 的 `meson.build` 文件中使用了 `cmake.subproject()` 函数来声明一个 CMake 子项目。
3. **Meson 会创建 `CMakeInterpreter` 实例来处理该 CMake 子项目。**
4. **`CMakeInterpreter` 的第一部分（在提供的代码之前）会被执行，负责配置和初步分析 CMake 项目。** 这包括运行 CMake 命令并解析其输出。
5. **`CMakeInterpreter.analyse()` 方法被调用，分析 CMake 项目的结构和目标。**
6. **最终，`CMakeInterpreter.pretend_to_be_meson()` 方法被调用，将分析结果转换为 Meson 代码。**  这是提供的代码片段所在的方法。

**调试线索：**

*   如果用户在集成 CMake 子项目时遇到构建错误，可以检查 `pretend_to_be_meson` 生成的 Meson 代码，看是否正确地反映了 CMake 项目的结构和依赖关系。
*   查看 CMake 配置阶段的输出（通常在 Meson 的构建日志中），可以帮助定位 CMake 配置问题。
*   检查传递给 `cmake.subproject()` 的参数，确保路径和选项正确。

**总结一下它的功能 (第二部分):**

`CMakeInterpreter` 的第二部分主要负责将经过配置和分析的 CMake 项目信息转换成 Meson 构建系统可以理解的表示形式。它通过构建 Meson 的抽象语法树来实现这一点，模拟了 Meson 项目的定义，包括目标、源文件、依赖关系和构建选项。这使得 Frida 可以集成和构建基于 CMake 的外部项目或库。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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