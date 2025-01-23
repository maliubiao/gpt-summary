Response:
My thinking process to analyze the provided Python code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the Python code, its relationship to reverse engineering, its usage of low-level/kernel concepts, logical inferences it makes, potential user errors, how a user might reach this code, and finally, a concise overall summary.

2. **High-Level Overview:** I first scan the code for class definitions. I see several classes ending in "Holder," suggesting this code is responsible for wrapping or managing different types of objects within the Meson build system. The names of these classes (e.g., `TestDefinition`, `SubprojectHolder`, `BuildTargetHolder`, `ExecutableHolder`) give me a general idea of the types of things being managed.

3. **Focus on Key Classes and Methods:** I then delve into the individual classes, looking at their `__init__` methods to understand their attributes and the methods defined within them. This helps me grasp the specific responsibilities of each class.

4. **Identify Core Functionality:** I notice patterns. Many "Holder" classes have methods like `get_name`, `full_path`, `found`, and methods related to extracting objects (`extract_objects`, `extract_all_objects`). This suggests a common interface or purpose – providing information and manipulating build artifacts.

5. **Connect to Reverse Engineering:** I start thinking about how these functionalities relate to reverse engineering.
    * **`TestDefinition`:**  The ability to define tests with specific executables, arguments, and environment variables is directly relevant to testing reverse-engineered components or tools. The `should_fail` flag hints at testing for expected failure conditions, which is important in security analysis.
    * **`BuildTargetHolder` and its subclasses:** Methods like `full_path` are crucial for locating compiled binaries, libraries, and other artifacts – a fundamental step in reverse engineering. The object extraction methods could be used to get intermediate compilation products for deeper analysis.
    * **`SubprojectHolder`:** Managing subprojects is relevant because reverse engineering often involves analyzing complex systems with dependencies.

6. **Identify Low-Level/Kernel Connections:**  I look for hints of interaction with the operating system or lower levels.
    * **`TestDefinition`:**  Executing external programs (`exe`) and setting environment variables (`env`) directly interacts with the OS. The `workdir` attribute also points to OS-level file system manipulation.
    * **`BuildTargetHolder`:**  The concepts of executables, static/shared libraries, and modules are fundamental to understanding how software is built and how the OS loads and executes it. The paths and output directories are OS-specific.

7. **Look for Logical Inferences/Assumptions:** I examine methods for conditional logic or assumptions.
    * **`SubprojectHolder.get_variable_method`:** It infers the validity of accessing variables based on whether the subproject is enabled. It assumes that if a subproject is disabled, its variables are inaccessible.
    * **`BuildTargetHolder.found_method`:** It makes an assumption about when the `found` method is relevant, specifically for executables returned by `find_program`.

8. **Consider User Errors:**  I think about how a user might misuse the provided functionality.
    * **`SubprojectHolder.get_variable_method`:**  Trying to access a variable in a disabled subproject or requesting a non-existent variable are clear error scenarios.
    * **`CustomTargetHolder.op_index`:** Accessing an out-of-bounds index is a common programming error.
    * **`GeneratorHolder.process_method`:** Providing a non-absolute path for `preserve_path_from` (as the code itself notes as a temporary restriction) is a potential user error.

9. **Trace User Interaction (Debugging):** I imagine a typical Meson build process. A user writes a `meson.build` file, which is then processed by Meson. The code snippet likely comes into play when Meson is interpreting this `meson.build` file, particularly when handling:
    * `test()` calls (leading to `TestDefinition`).
    * `subproject()` calls (leading to `SubprojectHolder`).
    * `executable()`, `shared_library()`, `static_library()`, `custom_target()`, etc. (leading to the various `*TargetHolder` classes).
    * `generator()` calls (leading to `GeneratorHolder`).

10. **Synthesize the Summary:** Finally, I combine my observations into a concise summary, highlighting the key responsibilities of the code, its role in the Meson build system, and its connections to the concepts mentioned in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "These 'Holder' classes just store data."
* **Correction:** "No, they also provide methods to access and manipulate the underlying objects. They are more like wrappers with added functionality."
* **Initial thought:** "The reverse engineering connection is weak."
* **Refinement:** "Actually, locating binaries, understanding build dependencies, and testing are crucial aspects of reverse engineering, so the `BuildTargetHolder` and `TestDefinition` classes are definitely relevant."
* **Initial thought:** "The code doesn't directly interact with the kernel."
* **Refinement:** "While not directly making syscalls, the code manages build artifacts like executables and libraries, which are fundamental OS concepts. The `TestDefinition` class directly interacts with the OS by running executables."

By following these steps and continuously refining my understanding, I can arrive at a comprehensive and accurate analysis of the provided code snippet.这是Frida动态Instrumentation工具源代码文件 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 的第二部分，延续了第一部分的内容，主要定义了用于在Meson构建系统中表示和操作各种构建目标的 Python 对象。这些对象在 Meson 解释器执行 `meson.build` 文件时被创建和使用。

**本部分的功能归纳如下：**

* **构建目标对象的封装 (Wrapping Build Targets):** 这部分代码主要定义了各种 "Holder" 类，用于封装 Meson 构建系统中定义的各种构建目标 (build targets)。这些构建目标包括可执行文件 (Executable)、静态库 (StaticLibrary)、共享库 (SharedLibrary)、同时生成静态库和共享库 (BothLibraries)、共享模块 (SharedModule)、Jar 文件 (Jar)、自定义目标 (CustomTarget)、运行目标 (RunTarget)、别名目标 (AliasTarget)、生成列表 (GeneratedList) 和生成器 (Generator)。

* **提供访问构建目标属性和方法的方式:**  每个 "Holder" 类都提供了一组方法，允许在 Meson 的 Python 解释器环境中访问和操作其封装的构建目标的属性和功能。例如，可以获取构建目标的完整路径、输出目录、名称、ID，以及执行与构建目标相关的操作，例如提取对象文件或处理生成器。

* **支持自定义目标索引:** `CustomTargetIndexHolder` 用于表示自定义目标的单个输出文件，并允许访问其完整路径。

* **实现对构建目标的操作:** 部分 "Holder" 类提供了执行特定于其所代表构建目标的操作的方法。例如，`GeneratorHolder` 提供了 `process_method` 来执行代码生成。

* **提供类型检查和参数验证:**  代码中使用了类型注解 (`T.Union`, `T.List`, etc.) 和装饰器 (`@typed_pos_args`, `@typed_kwargs`) 来进行类型检查和参数验证，有助于提高代码的健壮性和可读性。

**与逆向方法的关系及举例说明：**

* **定位和检查构建产物:**  `BuildTargetHolder` 及其子类提供的 `full_path_method` 可以获取到最终生成的可执行文件、库文件等的完整路径。在逆向工程中，第一步通常是找到目标二进制文件，这个方法可以直接提供帮助。
    * **举例:** 假设逆向工程师想要分析名为 `my_program` 的可执行文件，在 `meson.build` 文件中定义了这个目标，那么在 Meson 解释器执行后，可以通过 `executable_object.full_path()` (其中 `executable_object` 是 `ExecutableHolder` 的实例) 获取到该可执行文件的绝对路径。

* **提取中间编译产物:** `BuildTargetHolder` 提供的 `extract_objects_method` 和 `extract_all_objects_method` 可以提取构建过程中的对象文件 (`.o` 或 `.obj`)。这些对象文件包含了未链接的机器码，可以用于更底层的逆向分析，例如分析单个编译单元的结构和逻辑。
    * **举例:**  如果逆向工程师想分析 `my_library` 的某个特定 `.cpp` 文件编译后的对象代码，可以使用 `library_object.extract_objects()` (其中 `library_object` 是 `StaticLibraryHolder` 或 `SharedLibraryHolder` 的实例) 来获取对应的对象文件。

* **理解构建依赖和结构:**  虽然这部分代码没有直接展示依赖关系，但它封装了各种构建目标，这些目标之间存在依赖关系。通过分析 `meson.build` 文件以及这些 Holder 对象的关系，可以理解目标软件的构建结构，这对于理解逆向目标的功能模块划分非常有帮助。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

* **可执行文件和库的概念:**  代码中涉及的 `ExecutableHolder`，`StaticLibraryHolder`，`SharedLibraryHolder` 等直接对应于操作系统中可执行文件和不同类型的库的概念。这些是操作系统加载和执行程序的基础。
    * **举例:**  在 Linux 和 Android 中，共享库 (`.so` 文件) 是动态链接的关键，理解 `SharedLibraryHolder` 如何表示和操作这些库，有助于理解 Frida 如何注入和 hook 目标进程。

* **对象文件:** `extract_objects_method` 涉及的对象文件是编译器将源代码编译成机器码后的中间产物，是二进制层面的表示。

* **自定义目标执行任意命令:** `CustomTargetHolder` 允许执行任意的 shell 命令，这可以用于执行与构建相关的底层操作，例如签名、打包等。在 Android 逆向中，可能涉及到对 APK 文件进行处理。

* **生成器 (Generator):** `GeneratorHolder` 可以执行代码生成器，这在构建系统中用于生成源代码或其他构建所需的文件。这可能涉及到对特定文件格式的解析和生成，需要对底层文件结构有一定的了解。

**逻辑推理及假设输入与输出：**

* **`SubprojectHolder.get_variable_method`:**
    * **假设输入:**  一个 `SubprojectHolder` 对象 `subproj_holder`，子项目名称为 "my_subproject"，且该子项目已启用。调用 `subproj_holder.get_variable_method(['my_variable'])`，假设子项目的变量字典中存在键为 "my_variable" 的条目，其值为字符串 "hello"。
    * **输出:**  字符串 "hello"。
    * **假设输入 (错误情况):**  一个 `SubprojectHolder` 对象 `subproj_holder`，子项目名称为 "disabled_subproject"，且该子项目被禁用。调用 `subproj_holder.get_variable_method(['my_variable'])`。
    * **输出:**  抛出 `InterpreterException` 异常，提示子项目被禁用，无法获取变量。

* **`BuildTargetHolder.found_method`:**
    * **假设输入:** 一个 `ExecutableHolder` 对象 `exe_holder`，它代表一个通过 `find_program` 找到的可执行文件。调用 `exe_holder.found_method()`。
    * **输出:** `True`。
    * **假设输入:** 一个 `StaticLibraryHolder` 对象 `lib_holder`。调用 `lib_holder.found_method()`。
    * **输出:** `True` (取决于 Meson 版本，旧版本可能会有 FeatureNew 提示)。

**涉及用户或者编程常见的使用错误及举例说明：**

* **`SubprojectHolder.get_variable_method`:**
    * **错误:** 尝试获取禁用子项目的变量。
    * **示例:**  在 `meson.build` 文件中，某个子项目可能通过条件判断被禁用，用户仍然尝试获取该子项目的变量，会导致错误。

    ```python
    # meson.build
    if get_option('enable-feature'):
        my_sub = subproject('my_subproject')
    else:
        my_sub = subproject('my_subproject', default_options={'enable-feature': 'disabled'})

    # 错误用法
    if my_sub.found():
        value = my_sub.get_variable('some_variable')  # 如果子项目被禁用，这里会报错
    ```

* **`CustomTargetHolder.op_index`:**
    * **错误:**  使用超出自定义目标输出文件数量的索引。
    * **示例:**  如果一个自定义目标生成 3 个文件，尝试访问索引为 3 的文件 (索引从 0 开始) 会导致错误。

    ```python
    # meson.build
    my_target = custom_target('my_custom', ...)

    # 错误用法
    invalid_file = my_target[3] # 如果 my_target 只输出 3 个文件，这里会报错
    ```

* **`GeneratorHolder.process_method`:**
    * **错误:**  `preserve_path_from` 参数未使用绝对路径 (根据代码注释，这是一个临时的限制)。
    * **示例:**

    ```python
    # meson.build
    my_generator = generator(...)
    input_files = [...]
    output_list = my_generator.process(input_files, preserve_path_from='relative/path') # 错误，应使用绝对路径
    ```

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件:** 用户首先编写 `meson.build` 文件，定义项目的构建规则，包括可执行文件、库、自定义目标、子项目等。

2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令，指示 Meson 开始解析和配置构建系统。

3. **Meson 解析 `meson.build`:** Meson 的解释器会读取并执行 `meson.build` 文件。

4. **创建 Interpreter 对象:**  Meson 解释器在执行过程中会创建各种内部对象，包括 `Interpreter` 实例。

5. **处理构建目标定义:** 当解释器遇到定义构建目标的函数（如 `executable()`, `shared_library()`, `custom_target()`, `subproject()` 等）时，会创建相应的构建目标对象。

6. **创建 "Holder" 对象:**  为了在解释器环境中操作这些构建目标，Meson 会创建相应的 "Holder" 对象（例如 `ExecutableHolder`, `SharedLibraryHolder`, `SubprojectHolder` 等）来封装这些构建目标。这些 "Holder" 对象的方法会被 Meson 解释器调用。

7. **用户代码调用 "Holder" 对象的方法:**  在 `meson.build` 文件中，用户可以通过访问这些 "Holder" 对象并调用其方法来获取构建目标的属性或执行操作。例如，用户可以通过 `my_executable.full_path()` 获取可执行文件的路径。

**调试线索:**  如果用户在使用 Meson 构建系统时遇到与构建目标相关的错误，例如无法找到构建产物、提取对象文件失败、子项目变量访问错误等，那么调试的线索可能会指向这部分代码。检查用户 `meson.build` 文件中对构建目标的定义和操作，以及相关的 Meson API 调用，可以帮助定位问题。例如，如果 `get_variable` 方法抛出异常，那么问题可能在于子项目的状态或者请求的变量名不存在。

总而言之，这部分代码是 Frida 构建系统中使用 Meson 进行元编程的核心部分，它定义了用于操作各种构建目标的 Python 对象，并提供了访问和控制构建过程的关键接口。理解这部分代码有助于深入了解 Frida 的构建流程，并能更好地调试和扩展 Frida 的构建系统。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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