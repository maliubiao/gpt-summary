Response:
My thinking process to analyze the provided Python code snippet and answer the user's request goes through several stages:

1. **Understanding the Context:** The user explicitly states the file path within the Frida project. This immediately tells me the code is related to the build system (Meson) and how Frida interacts with it, specifically concerning the Common Language Runtime (CLR). The "interpreterobjects.py" name suggests this file defines Python objects that represent concepts within the Meson build system.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the code looking for class definitions and their methods. Keywords like `Test`, `Subproject`, `Module`, `BuildTarget`, `Executable`, `Library`, `CustomTarget`, `Generator`, etc., stand out. These hint at the different types of build artifacts and organizational units Meson handles.

3. **Class-by-Class Analysis:**  I go through each class, noting its attributes and methods.

    * **`Test`:**  This seems to represent a test case. The attributes suggest various aspects of a test, like its name, the suite it belongs to, the executable to run, dependencies, command-line arguments, environment variables, expected failure, timeout, working directory, and protocol.

    * **`NullSubprojectInterpreter`:** This looks like a placeholder or a marker indicating that a subproject is not available or loaded.

    * **`SubprojectHolder`:** This class is crucial. It manages a subproject within the larger build. The `get_variable_method` and `found_method` suggest interaction with the subproject's internal state and build status.

    * **`ModuleObjectHolder` and `MutableModuleObjectHolder`:** These likely handle interactions with Meson modules (reusable build logic). The `method_call` function suggests a mechanism for invoking methods within these modules. The "Mutable" version likely allows for modifications to the module's state.

    * **`BuildTargetHolder` and its subclasses (`ExecutableHolder`, `StaticLibraryHolder`, etc.):** This is a core concept. It represents different kinds of build outputs (executables, libraries). The methods like `extract_objects`, `full_path`, `outdir`, and `name` provide access to information about these targets.

    * **`CustomTargetIndexHolder` and `_CustomTargetHolder`:** These deal with custom build steps defined by the user. The `full_path` and `to_list` methods are relevant for accessing the output of these custom steps.

    * **`RunTargetHolder` and `AliasTargetHolder`:** These represent actions to run after the build and named groups of targets, respectively.

    * **`GeneratedListHolder`:** This likely handles lists of generated files.

    * **`GeneratorHolder`:** This is for defining and executing code generators that produce source files or other build artifacts. The `process_method` is the key here.

    * **`StructuredSourcesHolder`:** This probably deals with organizing source files in a structured way.

4. **Identifying Core Functionality:** Based on the class analysis, I can summarize the key functions of the code:
    * Representing and managing different types of build artifacts (executables, libraries, custom targets, etc.).
    * Handling subprojects and their dependencies.
    * Interacting with Meson modules.
    * Defining and running tests.
    * Managing custom build steps and code generators.

5. **Relating to Reverse Engineering:**  I look for connections to reverse engineering concepts.
    * **Dynamic Instrumentation (Frida's core function):** The context makes this the primary link. The code provides the *build-time* representation of things Frida might interact with *at runtime*. For example, a `BuildTargetHolder` for a library could correspond to a library Frida might hook into.
    * **Binary Structure:** While this code doesn't directly parse binaries, it deals with the *outputs* of the build process (executables, libraries), which are binaries. The `extract_objects` methods might be relevant for analyzing the contents of these binaries.
    * **Program Execution:** The `Test` class and `RunTargetHolder` relate to running programs, which is a common aspect of reverse engineering.

6. **Identifying System-Level Interactions:** I look for mentions of operating system concepts.
    * **Linux/Android Kernels/Frameworks:**  While not explicitly in this snippet, the mention of "frida-clr" strongly suggests interaction with the CLR, which runs on various operating systems, including Linux and potentially Android. Frida is often used for reverse engineering on Android. The `Test` class might involve running executables or tests on these platforms.
    * **File Paths and Directories:**  The `full_path`, `outdir`, and `workdir` attributes and methods deal with the file system.

7. **Logical Reasoning and Example Generation:** I consider the methods and their arguments to infer their logic.
    * **`SubprojectHolder.get_variable_method`:** If a subproject is disabled, accessing its variables will raise an exception. This demonstrates a logical check.
    * **`BuildTargetHolder.extract_objects_method`:**  It takes file or string arguments, suggesting it extracts specific object files from a target.

8. **Identifying Potential User Errors:** I think about how a user might misuse these objects in their `meson.build` files.
    * **Incorrect Arguments:**  Calling methods with the wrong number or type of arguments (e.g., `get_variable_method` with no arguments).
    * **Accessing Disabled Subprojects:** Trying to get variables from a disabled subproject.
    * **Invalid Indices:**  Using out-of-bounds indices with `CustomTargetHolder`.
    * **Incorrect Paths:** Providing non-absolute paths to `preserve_path_from` in `GeneratorHolder.process_method`.

9. **Tracing User Actions (Debugging Clues):** I consider how a user's actions in their `meson.build` file might lead to this code being executed. Defining tests, subprojects, libraries, executables, and custom targets would all involve creating instances of these classes. Errors in these definitions would likely surface during the Meson configuration or build process.

10. **Synthesizing the Summary:** Finally, I combine the findings from the previous steps to create a concise summary of the file's functionality. I focus on the key responsibilities of the classes in representing build system concepts and their relationships.

By following these steps, I can systematically analyze the code, understand its purpose within the larger Frida project, and address the specific points raised in the user's request. The iterative process of scanning, analyzing, connecting concepts, and generating examples helps to build a comprehensive understanding of the code's role.
这是Frida动态Instrumentation工具的源代码文件的一部分，专门用于处理Meson构建系统中 Interpreter 的对象。它定义了各种 Python 类，用于表示 Meson 构建系统中的不同实体，例如测试、子项目、模块、构建目标（可执行文件、库等）和自定义目标。

**功能归纳:**

这个文件的主要功能是：

1. **表示 Meson 构建系统的各种对象：** 它定义了 Python 类来封装 Meson 构建系统中的核心概念，使得可以在 Python 代码中操作和管理这些构建元素。这些类包括：
    * `Test`: 代表一个测试用例。
    * `NullSubprojectInterpreter`: 代表一个空的子项目解释器。
    * `SubprojectHolder`: 用于持有和管理一个子项目及其解释器。
    * `ModuleObjectHolder`/`MutableModuleObjectHolder`: 用于持有和管理 Meson 模块对象。
    * `BuildTargetHolder`及其子类 (`ExecutableHolder`, `StaticLibraryHolder`, `SharedLibraryHolder`, `BothLibrariesHolder`, `SharedModuleHolder`, `JarHolder`): 用于持有和管理各种构建目标。
    * `CustomTargetIndexHolder`: 用于持有自定义目标的索引。
    * `_CustomTargetHolder`/`CustomTargetHolder`: 用于持有自定义目标。
    * `RunTargetHolder`: 用于持有运行目标。
    * `AliasTargetHolder`: 用于持有别名目标。
    * `GeneratedListHolder`: 用于持有生成的列表。
    * `GeneratorHolder`: 用于持有生成器对象。
    * `StructuredSourcesHolder`: 用于持有结构化源文件。

2. **提供访问和操作这些对象的方法：**  每个类都定义了方法（以 `_method` 结尾），允许外部代码访问和操作其所代表的 Meson 构建对象的属性和功能。例如，`BuildTargetHolder` 提供了获取构建目标名称、路径、输出目录、提取对象文件等方法。

**与逆向方法的关系及举例:**

由于 Frida 是一个动态 instrumentation 工具，它需要在运行时与目标进程进行交互。而这个文件描述的是构建时 Meson 如何组织和表示构建产物。虽然不直接参与运行时的逆向操作，但它为 Frida 的构建过程提供了基础信息，这些信息可以间接地服务于逆向分析：

* **识别目标二进制文件：** `ExecutableHolder`, `SharedLibraryHolder` 等类代表了最终构建出的可执行文件和共享库。在 Frida 进行 instrumentation 时，需要知道目标二进制文件的路径，而这些信息可以通过解析 Meson 的构建结果（其中可能包含对这些对象的引用）来获取。
    * **举例：**  假设 Frida 需要 hook 一个特定共享库中的函数。Frida 的构建系统可能会使用 `SharedLibraryHolder` 来表示这个库。通过分析 Meson 的构建信息，Frida 可以找到这个共享库的路径，并在运行时加载并 hook 它。

* **理解目标模块结构：**  `SubprojectHolder` 可以帮助理解目标程序由哪些子模块构成。这对于理解大型程序的结构和组织很有帮助，可以指导逆向分析人员从哪里入手。
    * **举例：** 一个复杂的 Android 应用可能由多个 native 库组成。通过 Meson 的构建信息，可以了解这些库的名称和依赖关系，从而在逆向时有更清晰的目标。

* **定位自定义构建步骤：**  `CustomTargetHolder` 代表了用户自定义的构建步骤。这些步骤可能生成一些中间文件或者执行特定的处理，理解这些步骤有助于理解最终构建产物的生成过程，有时这些自定义步骤也会影响到逆向分析的目标。
    * **举例：** 某些加壳或混淆技术可能会在自定义构建步骤中应用。了解这些步骤有助于逆向分析人员识别和绕过这些保护措施。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

这个文件本身更偏向构建系统的抽象层面，直接涉及二进制底层和内核的知识较少。但是，它所表示的构建对象最终会落到这些层面：

* **二进制底层：**  `ExecutableHolder`, `SharedLibraryHolder` 代表的是二进制文件（ELF, PE, Mach-O 等）。Meson 构建系统需要知道如何链接这些二进制文件，而 Frida 在进行 instrumentation 时也需要解析这些二进制文件的结构。
    * **举例：** `extract_objects_method` 涉及到提取目标文件中的对象。这些对象文件是二进制格式的，包含了机器码和数据。理解这些二进制格式对于逆向工程至关重要。

* **Linux/Android 框架：** 在 Frida 用于 Android 逆向时，它经常需要 hook Android 框架层的函数。Meson 构建系统可能会用来构建一些与 Android 框架交互的组件或测试工具。
    * **举例：**  一个 Frida 脚本可能需要 hook `android.app.Activity` 类的方法。Meson 构建系统可能会构建一个用于测试这些 hook 的可执行文件。这个文件中会包含对 Android SDK 的依赖，涉及到 Android 框架的知识。

**逻辑推理及假设输入与输出:**

* **`SubprojectHolder.get_variable_method`:**
    * **假设输入：** 一个 `SubprojectHolder` 对象 `subproject_holder`，以及一个字符串 `var_name` 代表要获取的变量名。
    * **假设 `subproject_holder` 代表的子项目已启用，并且该子项目定义了名为 `my_setting` 的变量，其值为字符串 `"hello"`。**
    * **输出：** 调用 `subproject_holder.get_variable_method(['my_setting'])` 将返回字符串 `"hello"`。
    * **假设 `subproject_holder` 代表的子项目已禁用。**
    * **输出：** 调用 `subproject_holder.get_variable_method(['my_setting'])` 将抛出 `InterpreterException`，提示子项目已禁用。

* **`BuildTargetHolder.full_path_method`:**
    * **假设输入：** 一个 `ExecutableHolder` 对象 `exe_holder`，代表一个名为 `my_program` 的可执行文件。
    * **假设构建输出目录为 `/path/to/build`。**
    * **输出：** 调用 `exe_holder.full_path_method()` 将返回可执行文件的绝对路径，例如 `/path/to/build/my_program` (具体路径取决于操作系统和构建配置)。

**用户或编程常见的使用错误及举例:**

* **在禁用的子项目上调用 `get_variable`：**
    * **错误代码示例：**
      ```python
      if subproject.found():
          value = subproject.get_variable('some_var')
      else:
          # 错误地尝试在禁用的子项目上获取变量
          value = subproject.get_variable('some_var')
      ```
    * **错误说明：**  用户可能会错误地认为即使子项目被禁用，仍然可以访问其变量。正确的做法是在调用 `get_variable` 之前，确保子项目已启用 (`subproject.found()` 返回 `True`)。

* **向需要特定类型参数的方法传递错误的类型：**
    * **错误代码示例：**
      ```python
      # extract_objects_method 期望接收 File, str, CustomTarget 等类型的参数
      executable.extract_objects_method([123])  # 传递了整数，类型错误
      ```
    * **错误说明：**  用户需要仔细阅读 Meson 的文档或 API，了解每个方法期望的参数类型，避免传递不兼容的类型。

* **使用已弃用的方法：**
    * **错误代码示例：**
      ```python
      target.path_method()  # path_method 已被弃用，应该使用 full_path_method
      ```
    * **错误说明：**  Meson 会在控制台输出警告信息，提示用户使用了已弃用的方法。用户应该关注这些警告，并及时更新代码以使用推荐的替代方法。

**用户操作如何一步步到达这里 (作为调试线索):**

当用户编写 `meson.build` 文件时，Meson 会解析这些文件并创建内部的数据结构来表示构建过程。这个 `interpreterobjects.py` 文件中的类就用于在 Meson 的解释器中表示这些构建元素。以下是一些可能导致这个文件中的代码被执行的用户操作：

1. **定义测试用例：** 用户在 `meson.build` 文件中使用 `test()` 函数定义一个测试用例。Meson 会创建一个 `Test` 类的实例来表示这个测试。

2. **声明子项目：** 用户使用 `subproject()` 函数引入一个子项目。Meson 会创建一个 `SubprojectHolder` 类的实例来管理这个子项目。

3. **使用 Meson 模块：** 用户调用 `import` 语句导入一个 Meson 模块。Meson 会创建一个 `ModuleObjectHolder` 的实例来表示这个模块。

4. **构建目标定义：** 用户使用 `executable()`, `library()`, `shared_library()` 等函数定义可执行文件或库。Meson 会创建相应的 `ExecutableHolder`, `LibraryHolder` 等类的实例。

5. **创建自定义目标：** 用户使用 `custom_target()` 函数定义一个自定义的构建步骤。Meson 会创建一个 `CustomTargetHolder` 类的实例。

6. **定义生成器：** 用户使用 `generator()` 函数定义一个代码生成器。Meson 会创建一个 `GeneratorHolder` 类的实例。

在 Meson 的配置阶段（通常通过运行 `meson setup` 命令触发），会解析 `meson.build` 文件并创建这些对象。如果在配置过程中出现错误，例如类型不匹配或调用了不存在的方法，Meson 的解释器会抛出异常，并且堆栈跟踪信息可能会指向 `interpreterobjects.py` 文件中的相关代码，帮助开发者定位错误发生的位置。

**第 2 部分功能归纳:**

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 文件的核心功能是 **定义了 Meson 构建系统中各种构建元素的 Python 表示形式，并提供访问和操作这些元素的方法。** 它在 Frida 的构建过程中扮演着关键的角色，虽然不直接参与运行时的 instrumentation，但为 Frida 的构建和理解目标程序结构提供了必要的基础信息。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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