Response:
The user is asking for an analysis of the provided Python code snippet. This code defines various classes in the context of the Frida dynamic instrumentation tool, specifically within its Meson build system integration.

I need to:
1. **Identify the primary function of each class.**  The class names and their attributes offer strong clues.
2. **Determine the relationship to reverse engineering.** Frida is a reverse engineering tool, so classes managing build targets, executables, and libraries are likely relevant.
3. **Pinpoint interactions with binary, Linux/Android kernel/framework concepts.**  The context of Frida and the presence of terms like "executable," "shared library," and "custom target" suggest these interactions.
4. **Look for logical reasoning and provide examples.** Method calls within these classes often involve decision-making based on input parameters.
5. **Identify potential user errors.** Misusing the methods or providing incorrect arguments are common errors.
6. **Explain how a user might reach this code.**  This involves understanding the typical workflow of using Frida and its build system.
7. **Summarize the overall functionality of the code.**

Here's a breakdown of the classes and their potential functions:

- **`Test`**: Represents a test case. This is directly related to quality assurance and validation within the Frida project.
- **`NullSubprojectInterpreter`**:  A placeholder for a disabled or non-existent subproject.
- **`SubprojectHolder`**:  Manages a subproject within the Meson build system. This is crucial for modularity and dependency management.
- **`ModuleObjectHolder`**: Holds a module object, likely representing a functional unit within the build system.
- **`MutableModuleObjectHolder`**:  Similar to `ModuleObjectHolder` but allows modification of the held object.
- **`BuildTargetHolder`**: A base class for holding various build targets (executables, libraries, etc.). This is central to the build process.
- **`ExecutableHolder`**: Holds information about an executable file.
- **`StaticLibraryHolder`**:  Holds information about a static library.
- **`SharedLibraryHolder`**: Holds information about a shared library (like a DLL or SO file).
- **`BothLibrariesHolder`**: Holds information about a target that can be built as both static and shared.
- **`SharedModuleHolder`**: Holds information about a shared module.
- **`JarHolder`**: Holds information about a Java Archive file.
- **`CustomTargetIndexHolder`**: Holds an index within a custom build target's output.
- **`_CustomTargetHolder` and `CustomTargetHolder`**: Hold information about custom build targets, allowing flexible build steps.
- **`RunTargetHolder`**: Holds information about a target that executes something during the build process.
- **`AliasTargetHolder`**: Holds information about an alias for another build target.
- **`GeneratedListHolder`**: Holds a list of generated files.
- **`GeneratorHolder`**: Manages code generation processes within the build.
- **`StructuredSourcesHolder`**: Holds information about structured source code.
这是 frida-node 项目中 Meson 构建系统解释器处理特定类型对象的代码。它主要定义了各种 "Holder" 类，这些类封装了 Meson 构建系统的内部对象（例如，可执行文件、库、自定义目标等），并为 Meson 构建脚本提供了一种访问和操作这些对象的方式。

以下是它功能的详细列表：

**1. 封装和表示 Meson 构建系统对象:**

   - 代码定义了各种 `Holder` 类，例如 `Test`, `SubprojectHolder`, `BuildTargetHolder`, `ExecutableHolder`, `SharedLibraryHolder`, `CustomTargetHolder`, `GeneratorHolder` 等。
   - 每个 `Holder` 类都持有一个特定的 Meson 构建系统对象实例 (`held_object`)。例如，`ExecutableHolder` 持有一个 `build.Executable` 对象。
   - 这些 Holder 类充当了 Meson 构建脚本和底层构建系统对象之间的桥梁，使得脚本可以使用面向对象的方式来操作构建产物。

**2. 提供访问和操作构建系统对象的方法:**

   - 每个 `Holder` 类都定义了一系列方法，允许在 Meson 构建脚本中访问和操作其封装的构建系统对象的属性和功能。
   - 例如，`ExecutableHolder` 提供了 `full_path_method` 来获取可执行文件的完整路径，`extract_objects_method` 来提取目标文件等。
   - 这些方法通过 `self.methods.update({...})` 注册到 Holder 对象中，使得它们可以在 Meson 构建脚本中作为对象的方法调用。

**3. 处理子项目:**

   - `SubprojectHolder` 用于管理 Meson 构建系统中的子项目。
   - 它提供了 `found_method` 来检查子项目是否启用，以及 `get_variable_method` 来获取子项目中定义的变量。

**4. 处理模块对象:**

   - `ModuleObjectHolder` 用于封装模块对象，允许调用模块中定义的方法。
   - `method_call` 方法负责查找并执行模块对象的方法，并处理参数的扁平化和持有者对象的解析。

**5. 处理构建目标 (Build Targets):**

   - `BuildTargetHolder` 及其子类（如 `ExecutableHolder`, `SharedLibraryHolder`）是核心部分，用于表示和操作构建目标。
   - 提供了获取构建目标名称、ID、输出目录、完整路径、提取目标文件等方法。
   - 特别关注不同类型的构建目标（可执行文件、静态库、共享库等），并提供特定类型的方法。

**6. 处理自定义目标 (Custom Targets):**

   - `CustomTargetHolder` 用于表示用户自定义的构建步骤。
   - 提供了获取完整路径和将自定义目标的输出转换为列表的方法。
   - 支持使用索引操作符 `[]` 访问自定义目标的输出文件。

**7. 处理代码生成器 (Generators):**

   - `GeneratorHolder` 用于管理代码生成过程。
   - `process_method` 允许在构建过程中运行代码生成器，并指定输入文件和额外的参数。

**与逆向方法的关系及举例:**

* **访问构建产物信息:**  在逆向工程中，了解目标程序的构建信息非常重要。例如，确定可执行文件或库文件的路径，可以方便地使用其他逆向工具进行分析。 `ExecutableHolder` 和 `SharedLibraryHolder` 提供的 `full_path_method` 就可以获取这些信息。

   **举例:**  假设 Meson 构建脚本中定义了一个名为 `my_app` 的可执行文件，并将其赋值给变量 `exe_target`。在脚本中可以通过 `exe_target.full_path()` 获取该可执行文件的完整路径，然后可以将这个路径传递给 Frida 脚本进行动态分析。

* **提取目标文件:**  逆向工程师可能需要分析编译生成的中间目标文件（`.o` 或 `.obj`）。 `BuildTargetHolder` 的 `extract_objects_method` 提供了这个功能。

   **举例:**  如果一个库 `mylib` 被编译成目标文件，可以通过 `mylib.extract_objects()` 获取这些目标文件，然后使用 objdump 或类似工具进行静态分析。

* **了解库的依赖关系:** 虽然代码片段本身没有直接展示依赖关系，但 `BuildTargetHolder` 处理的构建目标通常会包含依赖信息。这些信息对于理解程序的架构和组件至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **可执行文件和库:** `ExecutableHolder`，`SharedLibraryHolder`，`StaticLibraryHolder` 等类直接对应于操作系统中的二进制文件类型。理解这些类型的文件格式（如 ELF, PE）对于逆向分析至关重要。
* **共享库 (Shared Libraries):**  在 Linux 和 Android 中，共享库是实现代码重用的重要机制。 Frida 经常需要注入到使用共享库的进程中。`SharedLibraryHolder` 涉及对共享库的构建和管理。
* **自定义目标 (Custom Targets):**  在构建过程中，可能需要执行一些特定的二进制工具或脚本。`CustomTargetHolder` 允许定义这些操作，这可能涉及到与底层系统交互的工具（例如，签名工具，打包工具）。
* **代码生成器 (Generators):**  代码生成器可以用于生成特定平台的代码，例如针对 Android Dalvik 或 ART 虚拟机的代码。`GeneratorHolder` 涉及到这些生成过程。

**逻辑推理及假设输入与输出:**

* **`SubprojectHolder.get_variable_method`:**
    * **假设输入:**  一个 `SubprojectHolder` 对象 `subproj_holder` 代表一个已启用的子项目，该子项目定义了一个名为 `api_key` 的变量，其值为字符串 `"secret123"`.
    * **调用:** `subproj_holder.get_variable('api_key')`
    * **输出:** 字符串 `"secret123"`

    * **假设输入:** 同上，但尝试获取一个不存在的变量。
    * **调用:** `subproj_holder.get_variable('non_existent_key')`
    * **输出:** 抛出 `InvalidArguments` 异常，提示 "Requested variable "non_existent_key" not found."

* **`BuildTargetHolder.extract_objects_method`:**
    * **假设输入:** 一个 `BuildTargetHolder` 对象 `lib_target` 代表一个名为 `mylibrary` 的静态库。
    * **调用:** `lib_target.extract_objects()`
    * **输出:** 一个包含 `mylibrary` 生成的所有目标文件（`.o` 或 `.obj`）的列表。

**涉及用户或编程常见的使用错误及举例:**

* **在禁用的子项目上调用 `get_variable`:**
    * **错误代码:**
      ```python
      if not subproject('my_disabled_sub').found():
          disabled_sub = subproject('my_disabled_sub')
          api_key = disabled_sub.get_variable('api_key') # 错误！
      ```
    * **错误原因:**  尝试从一个被禁用的子项目中获取变量。
    * **后果:** 抛出 `InterpreterException` 异常，提示子项目被禁用。

* **向 `get_variable` 传递错误的参数类型:**
    * **错误代码:**
      ```python
      my_target = executable('my_exe', 'main.c')
      # 假设 my_target 被传递给一个子项目
      sub.get_variable(my_target) # 错误！
      ```
    * **错误原因:** `get_variable` 的第一个参数必须是字符串类型的变量名。
    * **后果:** 抛出 `InterpreterException` 异常，提示第一个参数必须是字符串。

* **`extract_objects_method` 传递错误的参数类型:**
    * **错误代码:**
      ```python
      my_lib = static_library('mylib', 'mylib.c')
      my_lib.extract_objects(123) # 错误！
      ```
    * **错误原因:** `extract_objects_method` 期望的参数是文件对象或字符串，而不是整数。
    * **后果:**  取决于底层的实现，可能会抛出 `TypeError` 或其他异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在项目根目录下创建 `meson.build` 文件，该文件描述了项目的构建过程，包括定义可执行文件、库、测试、子项目等。
2. **用户运行 `meson` 命令配置构建:** 用户在终端中运行 `meson build`（或类似命令）来配置项目的构建。Meson 读取 `meson.build` 文件并创建构建目录。
3. **Meson 解释器解析 `meson.build`:**  Meson 解释器（`interpreterobjects.py` 所在的部分）会解析 `meson.build` 文件中的指令，并创建相应的内部对象，例如 `build.Executable`, `build.SharedLibrary` 等。
4. **创建 Holder 对象:**  在解析过程中，当遇到需要操作这些构建对象时，Meson 解释器会创建相应的 Holder 对象（例如 `ExecutableHolder` 来封装 `build.Executable` 对象）。
5. **用户在 `meson.build` 中调用 Holder 对象的方法:**  用户可以在 `meson.build` 文件中调用 Holder 对象的方法来获取信息或执行操作。例如，`exe_target.full_path()` 会调用 `ExecutableHolder` 的 `full_path_method`。
6. **调试线索:** 当用户在 `meson.build` 文件中遇到与构建对象相关的问题时，例如获取路径错误、提取目标文件失败等，调试过程可能会涉及到查看这些 Holder 类的代码，以了解其行为和可能的错误原因。例如，如果 `get_variable` 抛出异常，开发者可能会查看 `SubprojectHolder` 的 `get_variable_method` 来理解参数校验和错误处理逻辑。

**归纳其功能:**

总而言之，`interpreterobjects.py` 文件定义了 Frida-node 项目中 Meson 构建系统解释器用于封装和操作各种构建系统对象的 "Holder" 类。这些 Holder 类提供了一种结构化的、面向对象的方式来访问和控制构建过程中的各种元素，例如可执行文件、库、自定义构建步骤和代码生成器。这使得 `meson.build` 构建脚本更加清晰和易于维护，并为用户提供了更方便的方式来定义和管理项目的构建过程。这些 Holder 类也直接服务于 Frida 的构建需求，例如获取构建产物的信息以便进行后续的打包和发布。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
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

"""


```