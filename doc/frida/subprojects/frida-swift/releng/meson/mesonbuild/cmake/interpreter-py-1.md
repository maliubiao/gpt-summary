Response:
The user wants me to analyze the provided Python code, which is part of Frida, a dynamic instrumentation toolkit. This code specifically handles the interpretation of CMake projects within Frida's build process. I need to list the functionalities, explain their relation to reverse engineering, low-level aspects (like kernel/framework knowledge), logical reasoning (with examples), common user errors, and how a user might reach this code. Finally, I need to summarize the overall function.

Here's a breakdown of the analysis I need to perform:

1. **Functionality Listing:**  Identify the core actions this code performs. This includes configuring CMake, analyzing the CMake project, and generating Meson build files.

2. **Reverse Engineering Relevance:** Determine how this code aids or relates to reverse engineering workflows. Frida is a reverse engineering tool, so understanding how this piece fits in is crucial. This likely involves preparing targets for instrumentation.

3. **Low-Level Knowledge:** Pinpoint parts of the code that demonstrate knowledge of operating systems (Linux, Android), kernel concepts, or binary formats. This might involve how libraries are linked, how build systems interact with compilers, etc.

4. **Logical Reasoning:** Identify any conditional logic or data transformations. Create hypothetical inputs and the expected outputs to illustrate this reasoning.

5. **User Errors:**  Think about common mistakes users might make when interacting with Frida or setting up build environments that could trigger errors in this code.

6. **User Path to This Code:** Describe the steps a user would take within a Frida workflow that would lead to the execution of this specific Python file. This is essentially tracing the execution flow.

7. **Summary:**  Provide a concise overview of the code's primary purpose.

**Mental Sandbox Simulation:**

* **Functionality:** I see functions like `configure`, `initialise`, `analyse`, and `pretend_to_be_meson`. These clearly map to different stages of processing a CMake project. The logging and error handling are also functional aspects.
* **Reverse Engineering:** The code interacts with CMake, a build system often used for native libraries. Frida instruments these libraries. The generation of Meson files suggests an integration between these two build systems, which is relevant for building Frida itself or its components that interface with target applications.
* **Low-Level:** The code deals with compilers, linkers, and toolchains. It handles platform-specific configurations (`for_machine`). The mention of "object libraries" and linking processes indicates low-level awareness.
* **Logical Reasoning:** The `process_target` and `process_custom_target` functions seem to involve significant conditional logic based on target types and dependencies. I can imagine scenarios where different CMake targets (executables, libraries) are processed differently, leading to different Meson configurations.
* **User Errors:** Incorrect CMake configurations, missing dependencies, or incompatible CMake versions could cause errors.
* **User Path:** A user developing a Frida gadget or module that needs to build against a CMake-based project would likely trigger this code. Frida's build system probably uses this to integrate the CMake project.
* **Summary:** The code bridges the gap between CMake-based projects and Frida's build system (Meson), enabling the building and integration of components that might be necessary for instrumentation.

**Constraint Checklist & Confidence Score:**

1. List functionalities? Yes.
2. Reverse engineering relation with examples? Yes.
3. Binary/low-level/kernel/framework with examples? Yes.
4. Logical reasoning with input/output? Yes.
5. User errors with examples? Yes.
6. User operation path? Yes.
7. Summarize function? Yes.

Confidence Score: 5/5 - I have a good understanding of the code's purpose and can address all the requirements.

Strategizing complete. I will now proceed with generating the response based on these insights.
好的，让我们来分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/interpreter.py` 文件的功能。

**功能列举:**

这个 Python 文件的核心功能是**解析和转换 CMake 构建系统的信息，使其能够被 Meson 构建系统理解和利用**。具体来说，它做了以下几件事情：

1. **配置 CMake 构建环境 (`configure` 方法):**
   - 查找并执行 CMake 工具。
   - 设置 CMake 的构建目录、源目录、安装前缀等。
   - 生成 CMake 工具链文件和预加载脚本。
   - 传递额外的 CMake 选项。
   - 收集 CMake 的标准错误输出。

2. **初始化 CMake 项目信息 (`initialise` 方法):**
   - 运行 CMake 配置过程。
   - 解析 CMake 生成的文件 API 数据，例如构建系统文件列表和代码模型配置。
   - 获取 CMake 项目的名称和版本。

3. **分析 CMake 项目结构 (`analyse` 方法):**
   - 从 CMake 生成的数据中提取目标（targets），包括可执行文件、库、自定义目标等。
   - 解析 CMake 的跟踪（trace）信息，以获取更详细的目标信息，特别是接口目标。
   - 处理目标之间的依赖关系。
   - 清理和优化目标信息。

4. **模拟 Meson 构建定义 (`pretend_to_be_meson` 方法):**
   - 将解析到的 CMake 目标信息转换为 Meson 构建系统可以理解的格式。
   - 生成 Meson 的抽象语法树（AST），描述了如何构建 CMake 项目中的各个目标。
   - 处理各种目标类型，例如可执行文件、静态库、共享库、头文件库、自定义目标等。
   - 处理目标之间的依赖关系、链接库、包含目录、编译选项等。

5. **查询目标信息 (`target_info` 方法):**
   - 根据目标名称查找并返回已解析的 CMake 目标的详细信息。

6. **获取目标列表 (`target_list` 方法):**
   - 返回已解析的 CMake 目标的名称列表。

**与逆向方法的关系及举例说明:**

这个文件与逆向工程密切相关，因为它负责将目标应用程序的构建信息转换为 Frida 可以理解的形式。Frida 是一个动态插桩工具，经常用于逆向分析。

**举例说明:**

假设你要使用 Frida 来 hook 一个使用 CMake 构建的 iOS 应用程序中的某个 Swift 函数。

1. **构建环境准备:** 这个 `interpreter.py` 文件会解析该 iOS 应用程序的 CMake 构建脚本，了解其依赖的库、编译选项等。
2. **目标识别:** 它会识别出包含目标 Swift 函数的动态库。
3. **信息提取:**  它会提取出该动态库的路径、依赖的其他库、以及编译时使用的头文件路径等信息。
4. **Frida Gadget 集成:**  Frida 需要这些信息来将 Frida Gadget（一个小的动态库，用于注入到目标进程）正确地集成到目标应用程序的进程空间中。
5. **符号解析:**  了解了动态库的构建信息后，Frida 才能更好地进行符号解析，找到你需要 hook 的 Swift 函数的地址。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件虽然主要是处理构建系统的逻辑，但也间接涉及到一些底层知识：

**二进制底层:**

* **链接器 (`self.linkers`):**  代码中跟踪了链接器的信息，这对于理解如何将不同的编译单元组合成最终的可执行文件或库至关重要。
* **目标文件类型 (`ConverterTarget` 中对不同库类型的处理):**  代码区分了静态库、共享库、对象库等不同的二进制文件类型，并采取不同的处理方式。
* **编译选项 (`tgt.compile_opts`):**  处理了 CMake 中的编译选项，这些选项直接影响生成的二进制代码。

**Linux/Android 内核及框架:**

* **共享库和动态链接 (`tgt_func == 'shared_library'`):**  代码处理了共享库的构建，这涉及到操作系统加载和链接动态库的机制。在 Android 上，这尤其重要，因为 Android 系统大量使用了共享库。
* **安装路径 (`f'-DCMAKE_INSTALL_PREFIX={self.install_prefix}'`):**  CMake 构建系统需要知道安装路径，这在 Linux 和 Android 系统上有所不同，例如 Android 通常有 `/system`、`/vendor` 等不同的分区。
* **工具链 (`CMakeToolchain`):**  代码中使用了 `CMakeToolchain` 来管理不同平台的编译工具链，这对于交叉编译（例如在 Linux 上编译 Android 应用）至关重要。

**举例说明:**

在 Android 逆向中，你可能需要 hook 系统框架中的某个函数。这个文件会解析 Android 系统库的 CMake 构建脚本（如果可以获取到），从而帮助 Frida 了解这些库是如何构建的，依赖哪些其他库，这对于 Frida 正确地注入和 hook 系统库至关重要。

**逻辑推理及假设输入与输出:**

代码中有很多逻辑判断，例如根据目标类型选择不同的 Meson 函数来生成构建规则。

**假设输入:**

假设 CMake 项目中定义了一个名为 `mylib` 的共享库目标，并且依赖于另一个名为 `utils` 的静态库。

**预期输出 (部分):**

在 `pretend_to_be_meson` 方法生成的 Meson 代码中，你可能会看到类似这样的结构：

```meson
utils_dep = declare_dependency(...)  # `utils` 静态库的依赖声明
mylib_src = files(...)             # `mylib` 的源文件
mylib = shared_library('mylib', mylib_src,
    link_with: utils_dep,
    ...)
mylib_dep = declare_dependency(link_with: mylib) # `mylib` 共享库的依赖声明
```

这里进行了逻辑推理：识别出 `mylib` 是一个共享库，因此使用了 `shared_library` Meson 函数，并将其依赖的 `utils` 静态库通过 `link_with` 参数关联起来。

**用户或编程常见的使用错误及举例说明:**

1. **CMake 配置错误:** 用户提供的 CMake 项目配置不正确，例如缺少必要的依赖项或配置选项，会导致 CMake 配置失败，`configure` 方法会抛出 `CMakeException`。
   ```python
   try:
       self.configure(extra_cmake_options)
   except CMakeException as e:
       mlog.error(f"CMake configuration failed: {e}")
       # 处理错误
   ```

2. **CMake 版本不兼容:** 用户使用的 CMake 版本过低，不满足代码中要求的最低版本 (`>=3.14`)，会导致 `CMakeExecutor` 找不到 CMake 工具。
   ```python
   cmake_exe = CMakeExecutor(self.env, '>=3.14', self.for_machine)
   if not cmake_exe.found():
       raise CMakeException('Unable to find CMake')
   ```

3. **自定义目标输出未声明:**  如果 CMake 的自定义目标生成了一些输出文件，但这些输出文件没有在 CMake 脚本中正确声明，那么 `analyse` 方法在处理依赖关系时可能会出错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建一个 Frida 组件或 Gadget，该组件或 Gadget 依赖于一个使用 CMake 构建的第三方库。**
2. **Frida 的构建系统 (Meson) 需要处理这个 CMake 项目。**
3. **Meson 构建系统会调用 `mesonbuild/cmake/cmake.py` 中的相关逻辑来处理 CMake 子项目。**
4. **`cmake.py` 中的代码会创建 `CMakeInterpreter` 的实例，并将 CMake 项目的路径、构建选项等信息传递给它。**
5. **依次调用 `configure`、`initialise` 和 `analyse` 方法来解析 CMake 项目的信息。**
6. **最后，调用 `pretend_to_be_meson` 方法生成 Meson 构建文件，以便 Meson 可以理解如何构建这个 CMake 子项目。**

作为调试线索，如果用户在构建过程中遇到与 CMake 相关的错误，例如找不到 CMake 工具、CMake 配置失败等，那么就可以从这个 `interpreter.py` 文件入手，查看日志信息，了解 CMake 配置的具体过程和错误信息。

**功能归纳 (第 2 部分):**

作为第 2 部分，我们总结一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/interpreter.py` 的核心功能：

**该文件的主要功能是将 CMake 构建系统的项目信息转换为 Meson 构建系统可以理解和使用的格式。它通过配置 CMake 构建环境、解析 CMake 生成的数据、分析项目结构和依赖关系，最终生成 Meson 构建规则，从而使得 Frida 的构建系统能够无缝集成和构建基于 CMake 的组件或依赖项。** 换句话说，它是 Frida 构建系统中连接 CMake 和 Meson 这两个构建系统的桥梁。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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