Response:
My thinking process to analyze the provided Python code snippet goes through these stages:

1. **Identify the Core Purpose:** I first look for keywords and class names that suggest the overall function of the code. The presence of "Interpreter," "ObjectHolder," "BuildTarget," "CustomTarget," and "Test" strongly indicates that this code is part of a build system or a system that interprets build definitions. The `frida` in the initial prompt confirms it's related to the Frida dynamic instrumentation tool, which needs a build system. The `mesonbuild` path also points to the Meson build system.

2. **Analyze Class by Class:** I then go through each class definition, trying to understand its role and the data it holds.

    * **`Test`:**  The constructor clearly shows it holds information about a test case: `name`, `suite`, `project_name`, `exe` (executable), `depends`, `cmd_args`, etc. The methods `get_exe` and `get_name` are simple accessors.

    * **`NullSubprojectInterpreter`:** This looks like a placeholder or a marker for a disabled or missing subproject.

    * **`SubprojectHolder`:** This class holds a reference to a `subinterpreter`, a `subdir`, and potentially warnings, disabled features, or exceptions. The methods `found_method` and `get_variable_method` suggest it's used to interact with subprojects, checking if they are available and accessing their variables.

    * **`ModuleObjectHolder` and `MutableModuleObjectHolder`:** These classes seem to manage objects that represent modules. The `method_call` function is crucial, indicating how methods of these module objects are invoked. The `MutableModuleObjectHolder` allows for modification of the held module object.

    * **`BuildTargetHolder` and its subclasses (`ExecutableHolder`, `StaticLibraryHolder`, etc.):** This hierarchy is central. `BuildTargetHolder` holds information about a built target (executable, library, etc.). The methods like `extract_objects`, `full_path`, `outdir`, and `name_method` provide access to properties and actions related to build targets. The subclasses specialize the `BuildTargetHolder` for different types of build targets.

    * **`CustomTargetIndexHolder` and `CustomTargetHolder`:**  These handle custom build targets, which are defined by user commands. They allow access to the full path of the output and, in the case of `CustomTargetHolder`, accessing individual output files via indexing.

    * **`RunTargetHolder` and `AliasTargetHolder`:** These represent special types of targets: `RunTarget` likely executes something, and `AliasTarget` is probably a named group of targets.

    * **`GeneratedListHolder`:**  This seems to hold a list of generated files.

    * **`GeneratorHolder`:** This class manages code generators. The `process_method` suggests it takes input files and generates output files based on a defined process.

    * **`StructuredSourcesHolder`:** This likely manages source files organized in a structured manner.

3. **Identify Relationships and Interactions:** I note how these classes might interact. For example, a `SubprojectHolder` might contain an `Interpreter` that defines `BuildTargetHolder` objects. A `GeneratorHolder` might produce outputs that are then used by other build targets.

4. **Connect to the Prompt's Requirements:** Now I explicitly address each point in the prompt:

    * **Functionality:** I summarize the purpose of each class and its methods.

    * **Reverse Engineering:** I think about how these classes are relevant to reverse engineering. The ability to inspect build targets (`BuildTargetHolder`), especially executables and libraries, is key. Custom targets (`CustomTargetHolder`) might be used for reverse engineering tools themselves.

    * **Binary/Kernel/Framework:** I consider how the build system interacts with the underlying OS. Building executables and libraries involves linking, which is a binary-level operation. The mention of Android implies interaction with the Android framework.

    * **Logic and Assumptions:**  I look for conditional statements and try to infer the logic. For instance, the `get_variable_method` in `SubprojectHolder` has error handling based on whether the subproject is enabled. I create examples of inputs and outputs based on this logic.

    * **User Errors:** I think about how a user interacting with the build system might cause errors related to these classes, such as trying to access a variable in a disabled subproject or using an incorrect index for a custom target.

    * **User Operation to Reach Here:** I imagine the steps a user might take that would lead to the execution of this code. This involves running the Meson build system, potentially with subprojects and custom targets.

    * **Part 2 Summary:** I synthesize the information gathered to provide a concise summary of the file's functionality.

5. **Refine and Organize:** Finally, I organize my thoughts into a clear and structured answer, using headings and bullet points to make it easy to read. I also ensure the examples are concrete and illustrate the points I'm making. I double-check that I've addressed all aspects of the prompt.
这是 frida 动态 instrumentation 工具的源代码文件 `interpreterobjects.py` 的第二部分，该文件定义了 Meson 构建系统中用于表示各种构建系统对象的 Python 类。这些类在 Meson 解释构建定义文件（通常是 `meson.build`）时被创建和使用。

**该文件的主要功能是定义用于封装和操作 Meson 构建系统中各种构建目标和结构的 Python 对象。** 这些对象作为 Meson 解释器的一部分，允许用户在构建定义中以面向对象的方式引用和操作构建产物，例如可执行文件、库、自定义目标等。

接下来，我们根据您提出的问题逐一分析：

**1. 功能列举:**

* **`Test` 类:**  表示一个测试用例。它存储了测试的名称、所属的测试套件、项目名称、要执行的可执行文件、依赖项、是否并行执行、命令行参数、环境变量、预期是否失败、超时时间、工作目录、使用的测试协议、优先级和详细程度。

* **`NullSubprojectInterpreter` 类:**  表示一个空的子项目解释器。它可能用于表示一个被禁用或未找到的子项目。

* **`SubprojectHolder` 类:**  持有对子项目解释器的引用。它存储了子解释器对象、子项目目录、警告信息、被禁用的特性以及可能发生的异常。它提供了访问子项目变量的方法 (`get_variable_method`) 和检查子项目是否找到的方法 (`found_method`).

* **`ModuleObjectHolder` 和 `MutableModuleObjectHolder` 类:**  用于持有模块对象。`method_call` 方法允许调用模块对象的方法。`MutableModuleObjectHolder` 允许修改持有的模块对象。

* **`BuildTargetHolder` 类及其子类 (`ExecutableHolder`, `StaticLibraryHolder`, `SharedLibraryHolder`, `BothLibrariesHolder`, `SharedModuleHolder`, `JarHolder`):**  表示各种构建目标（可执行文件、静态库、共享库、同时包含静态和共享库的库、共享模块、JAR 文件）。它们提供了访问构建目标属性的方法，例如提取目标文件 (`extract_objects`, `extract_all_objects`)、获取名称 (`name_method`)、ID (`get_id_method`)、输出目录 (`outdir_method`)、完整路径 (`full_path_method`)、以及检查是否找到 (`found_method`)。

* **`CustomTargetIndexHolder` 类:**  表示自定义目标输出文件列表中的单个文件。它提供了获取文件完整路径的方法 (`full_path_method`)。

* **`_CustomTargetHolder` 类和 `CustomTargetHolder` 类:**  表示用户定义的自定义构建目标。它提供了获取所有输出文件路径 (`full_path_method`)、将输出文件列表转换为列表 (`to_list_method`) 和通过索引访问单个输出文件 (`op_index`) 的方法。

* **`RunTargetHolder` 类:**  表示一个运行目标，它定义了在构建后需要执行的命令或脚本。

* **`AliasTargetHolder` 类:**  表示一个别名目标，它可以将多个其他目标分组在一起。

* **`GeneratedListHolder` 类:**  表示由生成器生成的文件列表。

* **`GeneratorHolder` 类:**  表示一个代码生成器。它提供了 `process_method`，用于执行生成器并生成文件。

* **`StructuredSourcesHolder` 类:**  表示结构化的源文件集合。

**2. 与逆向方法的关系及举例:**

这些类与逆向工程密切相关，尤其是在逆向使用 Frida 进行动态分析时：

* **`ExecutableHolder` 和 库相关的 Holder 类 (`StaticLibraryHolder`, `SharedLibraryHolder`, `BothLibrariesHolder`, `SharedModuleHolder`):**  逆向工程师需要知道目标可执行文件和库的路径才能进行分析。这些 Holder 类提供了 `full_path_method` 来获取这些路径，这对于使用 Frida 加载目标进程或库至关重要。

    * **举例:** 在 Frida 脚本中，你需要指定要附加的进程或加载的库。通过 Meson 构建系统生成的构建信息（虽然 Frida 不直接读取 Meson 的输出，但了解构建结构有助于逆向），你可以知道目标库的路径。例如，如果一个共享库的目标在 Meson 中定义并最终由 `SharedLibraryHolder` 表示，那么其 `full_path_method` 返回的路径就是 Frida `Session.attach()` 或 `Device.inject_library_file()` 需要的参数。

* **`CustomTargetHolder`:**  在某些情况下，逆向工具本身可能作为自定义目标构建。例如，一个用于预处理二进制文件的脚本可能被定义为自定义目标。了解自定义目标的输出路径对于后续分析这些输出至关重要。

    * **举例:** 假设一个 Meson 项目定义了一个自定义目标，该目标使用 `objdump` 反汇编一个可执行文件并将结果保存到文件中。`CustomTargetHolder` 的 `full_path_method` 可以提供反汇编结果文件的路径，逆向工程师可以进一步分析该文件。

* **`Test` 类:**  虽然不是直接用于逆向，但了解测试用例的执行方式和使用的可执行文件可以帮助理解目标软件的功能和行为，从而辅助逆向分析。

    * **举例:** 如果一个测试用例执行了目标程序并传递了特定的命令行参数，那么逆向工程师可以通过查看 `Test` 对象的 `exe` 和 `cmd_args` 属性来了解这些信息，并在 Frida 中使用相同的参数来分析程序的特定行为。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

这些类在构建系统的层面操作，最终影响到二进制文件的生成和部署，因此涉及到这些底层知识：

* **二进制底层:**
    * **链接:**  `StaticLibraryHolder`, `SharedLibraryHolder`, `BothLibrariesHolder` 代表的库是链接过程的产物。Meson 需要知道如何将目标文件链接成这些库，这涉及到对目标文件格式（例如 ELF）的理解。
    * **可执行文件格式:** `ExecutableHolder` 代表的可执行文件也有特定的格式（例如 ELF）。Meson 需要处理如何生成符合操作系统要求的可执行文件。

* **Linux:**
    * **共享库加载:**  `SharedLibraryHolder` 生成的共享库在 Linux 系统中会被动态加载。Meson 需要处理与共享库相关的构建选项，例如 soname。
    * **进程执行:** `ExecutableHolder` 生成的可执行文件在 Linux 系统中通过 `exec` 系统调用执行。

* **Android 内核及框架:**
    * **共享库 (`.so` 文件):**  在 Android 上，共享库是重要的组件。`SharedLibraryHolder` 可以用于构建 Android 应用或 native 库。
    * **可执行文件:**  Android 系统中也有可执行文件，例如系统服务和守护进程。
    * **框架交互:** 虽然 Meson 本身不直接与 Android 框架交互，但它构建的库和可执行文件可能会与 Android 框架进行交互。例如，使用 Frida 分析一个 Android 应用时，你可能会注入一个由 Meson 构建的 native 库。

    * **举例:**  在构建 Android native 库时，`SharedLibraryHolder` 需要处理与 Android NDK 相关的选项，例如目标架构 (arm, arm64, x86 等)。Frida 可以注入这些生成的 `.so` 文件到 Android 进程中进行分析。

**4. 逻辑推理的假设输入与输出:**

* **`SubprojectHolder.get_variable_method`:**
    * **假设输入:**
        * `self.held_object` 是一个有效的子项目解释器，其中 `variables` 字典包含键 `'my_variable'`，值为字符串 `'hello'`.
        * `args` 为 `['my_variable']`.
    * **预期输出:** 字符串 `'hello'`.

    * **假设输入:**
        * `self.held_object` 是一个有效的子项目解释器，但 `variables` 字典不包含键 `'missing_variable'`.
        * `args` 为 `['missing_variable', 'default_value']`.
    * **预期输出:** 字符串 `'default_value'`.

    * **假设输入:**
        * `self.held_object` 是一个 `NullSubprojectInterpreter`.
        * `args` 为 `['any_variable']`.
    * **预期输出:** 抛出 `InterpreterException('Subproject "..." disabled can\'t get_variable on it.')`.

* **`CustomTargetHolder.op_index`:**
    * **假设输入:**
        * `self.held_object` 代表一个自定义目标，该目标生成了 3 个输出文件。
        * `other` 为 `1`.
    * **预期输出:**  表示第二个输出文件的 `build.CustomTargetIndex` 对象。

    * **假设输入:**
        * `self.held_object` 代表一个自定义目标，该目标生成了 3 个输出文件。
        * `other` 为 `5`.
    * **预期输出:** 抛出 `InvalidArguments('Index 5 out of bounds of custom target ... output of size 3.')`.

**5. 涉及用户或编程常见的使用错误及举例:**

* **`SubprojectHolder.get_variable_method`:**
    * **错误:** 尝试获取被禁用子项目的变量。
    * **代码:** 在 `meson.build` 中，如果一个子项目被条件性地禁用，但后续代码尝试使用 `get_variable` 获取其变量，就会导致错误。
    * **举例:**
      ```python
      # meson.build
      if get_option('enable-feature'):
          feature_dep = subproject('feature-subproject')
      else:
          feature_dep = disabler()

      if feature_dep.found():
          # ...
          value = feature_dep.get_variable('some_variable') # 如果 'enable-feature' 为 false，这里会出错
      ```

* **`CustomTargetHolder.op_index`:**
    * **错误:**  使用超出范围的索引访问自定义目标的输出文件。
    * **代码:** 用户在 `meson.build` 中使用自定义目标的结果时，可能会错误地假设输出文件的数量或顺序。
    * **举例:**
      ```python
      # meson.build
      my_target = custom_target('my_custom', ...)
      output_file = my_target[5] # 如果 my_custom 只生成 3 个文件，这里会出错
      ```

* **`GeneratorHolder.process_method`:**
    * **错误:** `preserve_path_from` 参数使用了相对路径（在当前版本中被限制）。
    * **代码:** 用户可能不理解 `preserve_path_from` 的要求，提供了相对路径。
    * **举例:**
      ```python
      # meson.build
      my_generator = generator(...)
      generated_files = my_generator.process(
          'input.txt',
          preserve_path_from='relative/path' # 错误用法
      )
      ```

**6. 用户操作如何一步步的到达这里作为调试线索:**

当用户运行 Meson 构建系统时，`mesonbuild/interpreter/interpreterobjects.py` 中的代码会被执行。以下是一个简化的步骤：

1. **用户执行 `meson setup builddir` 或 `meson compile -C builddir`:**  这将触发 Meson 的解释器来解析 `meson.build` 文件。
2. **Meson 解释器读取 `meson.build` 文件:**  解释器会逐行解析 `meson.build` 中的构建定义。
3. **遇到构建目标定义 (例如 `executable()`, `shared_library()`, `custom_target()`):**  解释器会创建相应的 Holder 对象 (`ExecutableHolder`, `SharedLibraryHolder`, `CustomTargetHolder` 等) 来表示这些目标。这些对象的初始化会调用 `interpreterobjects.py` 中定义的类的 `__init__` 方法。
4. **用户尝试访问构建目标的属性或调用其方法:** 例如，如果 `meson.build` 中有 `my_exe = executable(...)`，然后在后续代码中使用了 `my_exe.full_path()`，那么 `ExecutableHolder` 对象的 `full_path_method` 会被调用。
5. **子项目处理:** 如果 `meson.build` 中使用了 `subproject()` 函数，则会创建 `SubprojectHolder` 对象来管理子项目的信息。
6. **测试处理:** 如果定义了测试用例 (使用 `test()` 函数)，则会创建 `Test` 对象。
7. **生成器处理:** 如果使用了代码生成器 (使用 `generator()` 函数)，则会创建 `GeneratorHolder` 对象。

**作为调试线索:**  如果在 Meson 构建过程中遇到与构建目标属性访问或方法调用相关的错误，例如 "object has no attribute" 或 "invalid arguments"，那么可以查看 `interpreterobjects.py` 文件中对应 Holder 类的定义，了解该对象支持哪些属性和方法，以及参数的类型和要求。例如，如果在使用自定义目标的输出时遇到索引错误，可以查看 `CustomTargetHolder.op_index` 的实现来理解索引的范围。

**总结该部分的功能:**

这部分 `interpreterobjects.py` 文件的主要功能是**定义了 Meson 构建系统中用于表示各种构建构件（如可执行文件、库、自定义目标、测试用例等）的 Python 对象**。这些对象在 Meson 解释 `meson.build` 文件时被实例化，并提供了访问和操作这些构建构件属性和行为的方法。它们是 Meson 构建系统核心的一部分，使得用户可以使用面向对象的方式来描述和管理构建过程。这些对象也为 Meson 的内部逻辑提供了结构化的数据表示，方便后续的构建步骤执行。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
super().__init__()
        self.name = name
        self.suite = listify(suite)
        self.project_name = project
        self.exe = exe
        self.depends = depends
        self.is_parallel = is_parallel
        self.cmd_args = cmd_args
        self.env = env
        self.should_fail = should_fail
        self.timeout = timeout
        self.workdir = workdir
        self.protocol = TestProtocol.from_str(protocol)
        self.priority = priority
        self.verbose = verbose

    def get_exe(self) -> T.Union[ExternalProgram, build.Executable, build.CustomTarget, build.CustomTargetIndex]:
        return self.exe

    def get_name(self) -> str:
        return self.name

class NullSubprojectInterpreter(HoldableObject):
    pass

# TODO: This should really be an `ObjectHolder`, but the additional stuff in this
#       class prevents this. Thus, this class should be split into a pure
#       `ObjectHolder` and a class specifically for storing in `Interpreter`.
class SubprojectHolder(MesonInterpreterObject):

    def __init__(self, subinterpreter: T.Union['Interpreter', NullSubprojectInterpreter],
                 subdir: str,
                 warnings: int = 0,
                 disabled_feature: T.Optional[str] = None,
                 exception: T.Optional[Exception] = None,
                 callstack: T.Optional[mesonlib.PerMachine[T.List[str]]] = None) -> None:
        super().__init__()
        self.held_object = subinterpreter
        self.warnings = warnings
        self.disabled_feature = disabled_feature
        self.exception = exception
        self.subdir = PurePath(subdir).as_posix()
        self.cm_interpreter: T.Optional[CMakeInterpreter] = None
        self.callstack = callstack.host if callstack else None
        self.methods.update({'get_variable': self.get_variable_method,
                             'found': self.found_method,
                             })

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.found()

    def found(self) -> bool:
        return not isinstance(self.held_object, NullSubprojectInterpreter)

    @noKwargs
    @noArgsFlattening
    @unholder_return
    def get_variable_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.Union[TYPE_var, InterpreterObject]:
        if len(args) < 1 or len(args) > 2:
            raise InterpreterException('Get_variable takes one or two arguments.')
        if isinstance(self.held_object, NullSubprojectInterpreter):  # == not self.found()
            raise InterpreterException(f'Subproject "{self.subdir}" disabled can\'t get_variable on it.')
        varname = args[0]
        if not isinstance(varname, str):
            raise InterpreterException('Get_variable first argument must be a string.')
        try:
            return self.held_object.variables[varname]
        except KeyError:
            pass

        if len(args) == 2:
            return self.held_object._holderify(args[1])

        raise InvalidArguments(f'Requested variable "{varname}" not found.')

class ModuleObjectHolder(ObjectHolder[ModuleObject]):
    def method_call(self, method_name: str, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> TYPE_var:
        modobj = self.held_object
        method = modobj.methods.get(method_name)
        if not method:
            raise InvalidCode(f'Unknown method {method_name!r} in object.')
        if not getattr(method, 'no-args-flattening', False):
            args = flatten(args)
        if not getattr(method, 'no-second-level-holder-flattening', False):
            args, kwargs = resolve_second_level_holders(args, kwargs)
        state = ModuleState(self.interpreter)
        # Many modules do for example self.interpreter.find_program_impl(),
        # so we have to ensure they use the current interpreter and not the one
        # that first imported that module, otherwise it will use outdated
        # overrides.
        if isinstance(modobj, ExtensionModule):
            modobj.interpreter = self.interpreter
        ret = method(state, args, kwargs)
        if isinstance(ret, ModuleReturnValue):
            self.interpreter.process_new_values(ret.new_objects)
            ret = ret.return_value
        return ret

class MutableModuleObjectHolder(ModuleObjectHolder, MutableInterpreterObject):
    def __deepcopy__(self, memo: T.Dict[int, T.Any]) -> 'MutableModuleObjectHolder':
        # Deepcopy only held object, not interpreter
        modobj = copy.deepcopy(self.held_object, memo)
        return MutableModuleObjectHolder(modobj, self.interpreter)


_BuildTarget = T.TypeVar('_BuildTarget', bound=T.Union[build.BuildTarget, build.BothLibraries])

class BuildTargetHolder(ObjectHolder[_BuildTarget]):
    def __init__(self, target: _BuildTarget, interp: 'Interpreter'):
        super().__init__(target, interp)
        self.methods.update({'extract_objects': self.extract_objects_method,
                             'extract_all_objects': self.extract_all_objects_method,
                             'name': self.name_method,
                             'get_id': self.get_id_method,
                             'outdir': self.outdir_method,
                             'full_path': self.full_path_method,
                             'path': self.path_method,
                             'found': self.found_method,
                             'private_dir_include': self.private_dir_include_method,
                             })

    def __repr__(self) -> str:
        r = '<{} {}: {}>'
        h = self.held_object
        assert isinstance(h, build.BuildTarget)
        return r.format(self.__class__.__name__, h.get_id(), h.filename)

    @property
    def _target_object(self) -> build.BuildTarget:
        if isinstance(self.held_object, build.BothLibraries):
            return self.held_object.get_default_object()
        assert isinstance(self.held_object, build.BuildTarget)
        return self.held_object

    def is_cross(self) -> bool:
        return not self._target_object.environment.machines.matches_build_machine(self._target_object.for_machine)

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        if not (isinstance(self.held_object, build.Executable) and self.held_object.was_returned_by_find_program):
            FeatureNew.single_use('BuildTarget.found', '0.59.0', subproject=self.held_object.subproject)
        return True

    @noPosargs
    @noKwargs
    def private_dir_include_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> build.IncludeDirs:
        return build.IncludeDirs('', [], False, [self.interpreter.backend.get_target_private_dir(self._target_object)],
                                 self.interpreter.coredata.is_build_only)

    @noPosargs
    @noKwargs
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.interpreter.backend.get_target_filename_abs(self._target_object)

    @noPosargs
    @noKwargs
    @FeatureDeprecated('BuildTarget.path', '0.55.0', 'Use BuildTarget.full_path instead')
    def path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.interpreter.backend.get_target_filename_abs(self._target_object)

    @noPosargs
    @noKwargs
    def outdir_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.interpreter.backend.get_target_dir(self._target_object)

    @noKwargs
    @typed_pos_args('extract_objects', varargs=(mesonlib.File, str, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList))
    def extract_objects_method(self, args: T.Tuple[T.List[T.Union[mesonlib.FileOrString, 'build.GeneratedTypes']]], kwargs: TYPE_nkwargs) -> build.ExtractedObjects:
        return self._target_object.extract_objects(args[0])

    @noPosargs
    @typed_kwargs(
        'extract_all_objects',
        KwargInfo(
            'recursive', bool, default=False, since='0.46.0',
            not_set_warning=textwrap.dedent('''\
                extract_all_objects called without setting recursive
                keyword argument. Meson currently defaults to
                non-recursive to maintain backward compatibility but
                the default will be changed in the future.
            ''')
        )
    )
    def extract_all_objects_method(self, args: T.List[TYPE_nvar], kwargs: 'kwargs.BuildTargeMethodExtractAllObjects') -> build.ExtractedObjects:
        return self._target_object.extract_all_objects(kwargs['recursive'])

    @noPosargs
    @noKwargs
    @FeatureDeprecated('BuildTarget.get_id', '1.2.0',
                       'This was never formally documented and does not seem to have a real world use. ' +
                       'See https://github.com/mesonbuild/meson/pull/6061')
    def get_id_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._target_object.get_id()

    @FeatureNew('name', '0.54.0')
    @noPosargs
    @noKwargs
    def name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._target_object.name

class ExecutableHolder(BuildTargetHolder[build.Executable]):
    pass

class StaticLibraryHolder(BuildTargetHolder[build.StaticLibrary]):
    pass

class SharedLibraryHolder(BuildTargetHolder[build.SharedLibrary]):
    pass

class BothLibrariesHolder(BuildTargetHolder[build.BothLibraries]):
    def __init__(self, libs: build.BothLibraries, interp: 'Interpreter'):
        # FIXME: This build target always represents the shared library, but
        # that should be configurable.
        super().__init__(libs, interp)
        self.methods.update({'get_shared_lib': self.get_shared_lib_method,
                             'get_static_lib': self.get_static_lib_method,
                             })

    def __repr__(self) -> str:
        r = '<{} {}: {}, {}: {}>'
        h1 = self.held_object.shared
        h2 = self.held_object.static
        return r.format(self.__class__.__name__, h1.get_id(), h1.filename, h2.get_id(), h2.filename)

    @noPosargs
    @noKwargs
    def get_shared_lib_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> build.SharedLibrary:
        return self.held_object.shared

    @noPosargs
    @noKwargs
    def get_static_lib_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> build.StaticLibrary:
        return self.held_object.static

class SharedModuleHolder(BuildTargetHolder[build.SharedModule]):
    pass

class JarHolder(BuildTargetHolder[build.Jar]):
    pass

class CustomTargetIndexHolder(ObjectHolder[build.CustomTargetIndex]):
    def __init__(self, target: build.CustomTargetIndex, interp: 'Interpreter'):
        super().__init__(target, interp)
        self.methods.update({'full_path': self.full_path_method,
                             })

    @FeatureNew('custom_target[i].full_path', '0.54.0')
    @noPosargs
    @noKwargs
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        assert self.interpreter.backend is not None
        return self.interpreter.backend.get_target_filename_abs(self.held_object)

_CT = T.TypeVar('_CT', bound=build.CustomTarget)

class _CustomTargetHolder(ObjectHolder[_CT]):
    def __init__(self, target: _CT, interp: 'Interpreter'):
        super().__init__(target, interp)
        self.methods.update({'full_path': self.full_path_method,
                             'to_list': self.to_list_method,
                             })

        self.operators.update({
            MesonOperator.INDEX: self.op_index,
        })

    def __repr__(self) -> str:
        r = '<{} {}: {}>'
        h = self.held_object
        return r.format(self.__class__.__name__, h.get_id(), h.command)

    @noPosargs
    @noKwargs
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.interpreter.backend.get_target_filename_abs(self.held_object)

    @FeatureNew('custom_target.to_list', '0.54.0')
    @noPosargs
    @noKwargs
    def to_list_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.List[build.CustomTargetIndex]:
        result = []
        for i in self.held_object:
            result.append(i)
        return result

    @noKwargs
    @typed_operator(MesonOperator.INDEX, int)
    def op_index(self, other: int) -> build.CustomTargetIndex:
        try:
            return self.held_object[other]
        except IndexError:
            raise InvalidArguments(f'Index {other} out of bounds of custom target {self.held_object.name} output of size {len(self.held_object)}.')

class CustomTargetHolder(_CustomTargetHolder[build.CustomTarget]):
    pass

class RunTargetHolder(ObjectHolder[build.RunTarget]):
    pass

class AliasTargetHolder(ObjectHolder[build.AliasTarget]):
    pass

class GeneratedListHolder(ObjectHolder[build.GeneratedList]):
    pass

class GeneratorHolder(ObjectHolder[build.Generator]):
    def __init__(self, gen: build.Generator, interpreter: 'Interpreter'):
        super().__init__(gen, interpreter)
        self.methods.update({'process': self.process_method})

    @typed_pos_args('generator.process', min_varargs=1, varargs=(str, mesonlib.File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList))
    @typed_kwargs(
        'generator.process',
        KwargInfo('preserve_path_from', (str, NoneType), since='0.45.0'),
        KwargInfo('extra_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        ENV_KW.evolve(since='1.3.0')
    )
    def process_method(self,
                       args: T.Tuple[T.List[T.Union[str, mesonlib.File, 'build.GeneratedTypes']]],
                       kwargs: 'kwargs.GeneratorProcess') -> build.GeneratedList:
        preserve_path_from = kwargs['preserve_path_from']
        if preserve_path_from is not None:
            preserve_path_from = os.path.normpath(preserve_path_from)
            if not os.path.isabs(preserve_path_from):
                # This is a bit of a hack. Fix properly before merging.
                raise InvalidArguments('Preserve_path_from must be an absolute path for now. Sorry.')

        if any(isinstance(a, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for a in args[0]):
            FeatureNew.single_use(
                'Calling generator.process with CustomTarget or Index of CustomTarget.',
                '0.57.0', self.interpreter.subproject)

        gl = self.held_object.process_files(args[0], self.interpreter,
                                            preserve_path_from, extra_args=kwargs['extra_args'], env=kwargs['env'])

        return gl


class StructuredSourcesHolder(ObjectHolder[build.StructuredSources]):

    def __init__(self, sources: build.StructuredSources, interp: 'Interpreter'):
        super().__init__(sources, interp)
```