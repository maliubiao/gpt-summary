Response:
My thinking process to analyze the provided Python code snippet goes like this:

1. **Understand the Context:** The first line of the prompt clearly states the file path: `frida/releng/meson/mesonbuild/interpreter/interpreterobjects.py` within the Frida project. This immediately tells me we're dealing with the internal workings of Meson, a build system, specifically how it represents and interacts with various build artifacts within its interpreter. Frida, being a dynamic instrumentation toolkit, likely uses Meson for its build process.

2. **Identify Core Classes and Their Purpose:** I start by scanning the code for class definitions. The prominent classes and their apparent roles are:

    * `Test`: Represents a test case. Its attributes (name, suite, executable, arguments, environment, etc.) point to its function in defining and running tests.
    * `NullSubprojectInterpreter`:  Seems to be a placeholder or a way to represent a disabled subproject.
    * `SubprojectHolder`: Holds a reference to a subproject's interpreter. This suggests Meson supports nested projects.
    * `ModuleObjectHolder`/`MutableModuleObjectHolder`:  Handle objects originating from Meson modules (likely external functionality). The `method_call` function indicates how method calls on these module objects are dispatched.
    * `BuildTargetHolder` and its subclasses (`ExecutableHolder`, `StaticLibraryHolder`, etc.): These are crucial. They represent the different kinds of build outputs (executables, libraries, etc.) within the Meson build graph. The methods inside these classes expose information about the build targets (path, name, dependencies, etc.) and operations that can be performed on them (e.g., `extract_objects`).
    * `CustomTargetHolder`/`CustomTargetIndexHolder`: Represent custom build steps defined by the user in the `meson.build` file.
    * `RunTargetHolder`/`AliasTargetHolder`/`GeneratedListHolder`:  Other types of build targets with specific purposes (running commands, creating aliases, generating lists of files).
    * `GeneratorHolder`:  Deals with code generators that produce source files during the build.
    * `StructuredSourcesHolder`: Likely manages source files organized in a specific structure.

3. **Analyze Class Members and Methods:** For each class, I examine the `__init__` method to understand the data it holds and the other methods to see what operations it supports. Keywords like `get_`, `extract_`, `full_path`, `process`, etc., provide hints about the functionality. Decorators like `@noPosargs`, `@noKwargs`, `@typed_pos_args`, `@typed_kwargs`, and `@unholder_return` give information about the expected function signature and how arguments are handled.

4. **Look for Connections to Reverse Engineering:**  With the understanding of the classes, I consider how they relate to reverse engineering, given the context of Frida.

    * **`BuildTargetHolder` and its subclasses:**  These are directly relevant. When reverse engineering, you often work with executable files (`ExecutableHolder`), static/shared libraries (`StaticLibraryHolder`, `SharedLibraryHolder`), and potentially custom build outputs (`CustomTargetHolder`). The methods to get the path and extract objects are useful for accessing the compiled artifacts.
    * **`Test`:**  Automated testing is crucial in reverse engineering to verify the correctness of instrumentation or modified code. This class directly supports defining and running such tests.
    * **Subprojects:**  Large reverse engineering projects might involve dependencies built as separate subprojects.

5. **Identify Interactions with Binary, Linux, Android Kernel/Framework:**

    * **`BuildTargetHolder`:**  The concept of executables and libraries is fundamental to all these systems. The methods to get the full path point to binary files.
    * **Custom Targets:**  Could represent steps involving platform-specific tools or operations related to kernel modules or Android framework components.
    * **Environment variables (`Test`, `GeneratorHolder`):** These are essential for controlling the build process and can be used to target specific platforms or architectures.

6. **Infer Logical Reasoning and Hypothetical Inputs/Outputs:**  This requires understanding the *intent* behind the methods.

    * **`SubprojectHolder.get_variable_method`:**  If a subproject named "mylib" defines a variable `version` with the value "1.2.3", calling `subproject_holder.get_variable('version')` would return "1.2.3". If the variable doesn't exist and a default value is provided, that default would be returned.
    * **`BuildTargetHolder.extract_objects_method`:** If an executable target `my_exe` is built, and you call `my_exe.extract_objects(['file1.o', 'file2.o'])`, it would return an object representing the extracted object files.
    * **`GeneratorHolder.process_method`:** If a generator takes a list of input files and produces C code, calling `generator.process(['input1.txt', 'input2.txt'])` would result in a `GeneratedListHolder` containing the generated C files.

7. **Consider User/Programming Errors:**

    * **`SubprojectHolder.get_variable_method`:** Trying to get a variable from a disabled subproject will raise an `InterpreterException`. Providing a non-string variable name will also cause an error.
    * **`GeneratorHolder.process_method`:** Providing an invalid path for `preserve_path_from` before a recent version of Meson would lead to errors.
    * **Incorrect argument types or number of arguments to methods:** The `@typed_pos_args` and `@typed_kwargs` decorators indicate where type mismatches or incorrect argument counts would lead to errors.

8. **Trace User Operations (Debugging Clue):**  How does a user end up interacting with this code?

    * **Defining tests in `meson.build`:** When a user defines a `test()` in their `meson.build` file, Meson will create a `Test` object.
    * **Using `subproject()`:**  The `subproject()` function in `meson.build` leads to the creation of `SubprojectHolder` instances.
    * **Building targets:**  Defining `executable()`, `shared_library()`, `custom_target()`, etc., in `meson.build` results in the creation of the corresponding `BuildTargetHolder` objects.
    * **Calling methods on build targets:** In other parts of the Meson build scripts, users might call methods like `full_path()` or `extract_objects()` on these holder objects, triggering the execution of the methods defined in this file.
    * **Running tests:**  The `meson test` command will use the `Test` objects to execute the defined tests.

9. **Synthesize the Information (Summarize Functionality):** Finally, I group the observations to create a concise summary of the file's purpose. The core function is representing and managing various build-related objects within the Meson interpreter.

By following these steps, I can systematically dissect the code, understand its role within the larger context, and address all the points raised in the prompt. The iterative process of identifying classes, analyzing their members, and then considering the broader implications and potential use cases is key to this kind of code understanding.
好的，让我们继续分析 `frida/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 的剩余部分，并归纳其功能。

**功能归纳（基于提供的第2部分代码）：**

总的来说，这部分代码的主要功能是定义了 Meson 构建系统中各种构建目标（build targets）和相关对象的持有者（Holder）类。这些 Holder 类充当了 Meson 解释器和实际的构建目标之间的桥梁，提供了在 Meson 脚本中操作和访问这些构建目标信息的接口。

具体来说，这些 Holder 类：

1. **封装了不同的构建目标类型:**  例如 `ExecutableHolder` 用于封装可执行文件，`StaticLibraryHolder` 用于静态库，`CustomTargetHolder` 用于自定义构建目标等。这使得 Meson 脚本能够以面向对象的方式处理各种构建产物。

2. **提供了访问构建目标信息的途径:**  每个 Holder 类都提供了一系列方法（通过 `self.methods.update()` 添加）来获取构建目标的属性，例如名称 (`name_method`)、输出路径 (`full_path_method`, `outdir_method`)、是否找到 (`found_method`) 等。

3. **实现了对构建目标的操作:** 部分 Holder 类还定义了操作构建目标的方法，例如 `BuildTargetHolder` 的 `extract_objects_method` 可以提取目标文件中的对象。`GeneratorHolder` 的 `process_method` 可以执行代码生成器。

4. **处理类型转换和参数校验:**  代码中使用了装饰器（如 `@noPosargs`, `@noKwargs`, `@typed_pos_args`, `@typed_kwargs`）来限制方法参数类型和数量，进行参数校验，并提供更友好的错误提示。

5. **支持子项目:**  `SubprojectHolder` 用于管理子项目，允许访问子项目的变量 (`get_variable_method`) 和判断子项目是否被找到 (`found_method`)。

6. **处理模块对象:** `ModuleObjectHolder` 和 `MutableModuleObjectHolder` 用于封装 Meson 模块返回的对象，并提供了 `method_call` 方法来调用模块对象的方法。

7. **支持自定义目标索引:** `CustomTargetIndexHolder` 用于表示自定义目标的单个输出文件，并提供获取完整路径的方法。

**与逆向方法的关联及举例说明：**

* **访问构建产物:** 逆向工程通常需要访问最终生成的可执行文件或库文件。`ExecutableHolder`、`SharedLibraryHolder` 等类提供的 `full_path_method` 可以获取这些文件的绝对路径，这对于逆向工程师找到目标文件至关重要。
    * **举例:** 在 Frida 的构建脚本中，可能会使用 `executable('my_frida_agent', ...)` 定义一个 Frida 代理程序。通过 `my_frida_agent.full_path()` 就可以获取到编译后的代理程序二进制文件的路径，逆向工程师可以使用该路径进行静态分析或动态调试。

* **提取对象文件:**  `BuildTargetHolder` 的 `extract_objects_method` 允许提取构建目标中的对象文件。这些对象文件包含了编译后的机器码，对于理解程序的内部结构和算法非常有用。
    * **举例:**  如果 Frida 的一个核心库 `libfrida-core.so` 被编译为一个 `SharedLibraryHolder` 对象 `frida_core_lib`，那么可以使用 `frida_core_lib.extract_objects()` 来获取编译生成的 `.o` 文件，这些文件可以被反汇编来分析 Frida 的核心功能。

* **了解构建过程:** 虽然 Holder 类本身不直接参与构建过程，但它们提供了构建结果的信息。通过分析 Meson 的构建脚本和这些 Holder 对象，逆向工程师可以了解目标软件的构建方式、依赖关系等，这有助于理解软件的整体架构。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **可执行文件和库文件:** `ExecutableHolder`、`SharedLibraryHolder`、`StaticLibraryHolder` 等类直接对应于操作系统底层的二进制文件格式（如 ELF 文件在 Linux 和 Android 上）。

* **自定义目标 (`CustomTargetHolder`):**  自定义目标可以执行任意 shell 命令，这可以涉及到与操作系统底层的交互，例如编译内核模块、处理 Android 系统服务等。
    * **举例:** 在 Frida 的构建过程中，可能存在自定义目标来处理 Android 特有的资源文件或 AIDL 接口定义，这些操作会涉及到 Android 框架的底层知识。

* **共享库 (`SharedLibraryHolder`):**  共享库是 Linux 和 Android 系统中重要的概念，Frida 自身就是一个动态链接库，需要理解其加载、符号解析等机制。

* **环境变量 (`Test`, `GeneratorHolder`):**  环境变量在构建过程中起到重要作用，可以影响编译器的行为、指定库的搜索路径等。Frida 的构建可能需要设置特定的环境变量来适配不同的目标平台（例如 Android）。

**逻辑推理及假设输入与输出：**

* **`SubprojectHolder.get_variable_method`:**
    * **假设输入:**  一个 `SubprojectHolder` 对象 `subproj_holder`，它持有一个名为 "my_lib" 的子项目的解释器，该子项目定义了一个变量 `version` 的值为 "1.0"。
    * **调用:** `subproj_holder.get_variable_method(['version'], {})`
    * **预期输出:**  字符串 "1.0"。
    * **假设输入:**  同样的 `subproj_holder`，但子项目 "my_lib" 没有定义名为 "version" 的变量。
    * **调用:** `subproj_holder.get_variable_method(['version', 'default_value'], {})`
    * **预期输出:** 字符串 "default_value"。

* **`BuildTargetHolder.full_path_method`:**
    * **假设输入:**  一个 `ExecutableHolder` 对象 `my_app_exe`，它代表一个名为 "my_app" 的可执行文件，编译后位于构建目录的 "bin" 子目录下。
    * **调用:** `my_app_exe.full_path_method([], {})`
    * **预期输出:**  类似于 "/path/to/build/bin/my_app" 的绝对路径字符串。

**用户或编程常见的使用错误及举例说明：**

* **`SubprojectHolder.get_variable_method`:**
    * **错误:** 尝试获取一个禁用的子项目的变量。
    * **代码:**
      ```python
      if not subproject('disabled_lib').found():
          # ...
          disabled_lib_holder = subproject('disabled_lib')
          version = disabled_lib_holder.get_variable('version') # 错误，会抛出异常
      ```
    * **错误信息:** `InterpreterException: Subproject "disabled_lib" disabled can't get_variable on it.`

* **`GeneratorHolder.process_method`:**
    * **错误:**  传递了不符合要求的参数类型。
    * **代码:**
      ```python
      my_generator = generator(...)
      my_generator.process_method([123], {}) # 错误，期望字符串或文件对象
      ```
    * **错误信息:** 可能因参数类型校验失败而抛出异常。

* **`BuildTargetHolder.extract_objects_method`:**
    * **错误:**  尝试提取不存在的文件名。
    * **代码:**
      ```python
      my_lib = shared_library(...)
      my_lib.extract_objects_method(['non_existent.o'], {}) # 错误，可能找不到该文件
      ```
    * **错误信息:**  可能抛出与文件操作相关的异常。

**用户操作如何一步步到达这里，作为调试线索：**

1. **编写 `meson.build` 文件:** 用户首先会编写 `meson.build` 文件来定义项目的构建规则，包括可执行文件、库、测试、自定义目标等。

2. **运行 `meson setup`:** 用户运行 `meson setup builddir` 命令来配置构建环境。Meson 会解析 `meson.build` 文件，并创建相应的内部数据结构，包括这里的 Holder 对象。

3. **运行 `meson compile`:** 用户运行 `meson compile -C builddir` 命令来开始实际的编译过程。在这个过程中，Meson 解释器会与 Holder 对象交互，获取构建目标的信息。

4. **在 `meson.build` 中调用方法:** 用户可以在 `meson.build` 文件中直接调用 Holder 对象的方法。例如：
   ```python
   my_exe = executable('my_app', 'main.c')
   print(my_exe.full_path()) # 这里会调用 ExecutableHolder 的 full_path_method
   ```

5. **运行 `meson test`:** 用户运行 `meson test -C builddir` 命令来执行测试。Meson 会使用 `Test` 对象来运行定义的测试用例。

6. **调试构建脚本:**  如果构建过程中出现问题，开发者可能会检查 Meson 的内部状态，或者在 Meson 的源代码中设置断点，这时就有可能进入到 `interpreterobjects.py` 文件中的代码执行流程。

**总结:**

`interpreterobjects.py` 的这一部分是 Meson 构建系统的核心组成部分，它定义了用于封装和操作各种构建目标的 Holder 类。这些类不仅提供了访问构建目标信息的接口，还支持对构建目标执行特定的操作。理解这些 Holder 类的作用对于深入理解 Meson 的工作原理以及进行 Frida 这样的复杂项目的构建和调试至关重要。这些类与逆向工程、底层系统知识以及常见的编程错误都有着密切的联系。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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