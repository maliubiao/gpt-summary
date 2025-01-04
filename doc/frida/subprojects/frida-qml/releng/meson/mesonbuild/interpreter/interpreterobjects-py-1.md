Response:
Let's break down the thought process for analyzing this Python code snippet from the Frida project.

**1. Initial Understanding - The Context:**

The prompt clearly states this is part of Frida, a dynamic instrumentation tool. The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreterobjects.py` gives crucial context:

* **Frida:** The overarching project. Knowing Frida's purpose (dynamic instrumentation, hooking, introspection of running processes) immediately colors how we interpret the code.
* **`frida-qml`:** This suggests a QML (Qt Meta Language) interface or component within Frida. This hints at user interface elements and potentially interacting with a graphical environment.
* **`releng/meson`:**  "Releng" often stands for Release Engineering. Meson is a build system. This tells us this code is involved in how Frida is built and managed.
* **`mesonbuild/interpreter/interpreterobjects.py`:** This is the most specific part. It strongly suggests this file defines objects used within Meson's interpretation of build files (likely `meson.build`). The "interpreter" aspect is key – these objects represent things defined in the build scripts.

**2. High-Level Analysis - Identifying Key Classes and Their Roles:**

The first pass is to skim the code and identify the major classes. The naming is generally quite descriptive:

* `Test`: Likely represents a test case within the build system.
* `NullSubprojectInterpreter`:  Indicates a disabled or absent subproject.
* `SubprojectHolder`: Represents a subproject being included in the main build.
* `ModuleObjectHolder`, `MutableModuleObjectHolder`: These clearly deal with modules, likely those used within the Meson build system itself (not necessarily Frida's modules). The "Mutable" version suggests some modules can be modified.
* `BuildTargetHolder`, and its subclasses (`ExecutableHolder`, `StaticLibraryHolder`, etc.): These are fundamental. They represent the *things* being built – executables, libraries, etc. This is a direct link to the core of the build process.
* `CustomTargetHolder`, `CustomTargetIndexHolder`: Represent user-defined build steps or outputs.
* `RunTargetHolder`, `AliasTargetHolder`, `GeneratedListHolder`, `GeneratorHolder`, `StructuredSourcesHolder`:  These are more specialized build artifacts or actions.

**3. Deeper Dive - Understanding Class Members and Methods:**

Once the major classes are identified, the next step is to examine their attributes (`self.name`, `self.exe`, etc.) and methods (`get_exe()`, `found_method()`, `full_path_method()`, etc.).

* **`Test`:** Its attributes clearly define the parameters of a test execution: name, executable, arguments, environment, timeout, etc.
* **`SubprojectHolder`:**  The methods `found_method` and `get_variable_method` indicate interaction with subproject definitions.
* **`BuildTargetHolder` family:**  The methods like `extract_objects`, `full_path`, `outdir`, and `name` are crucial for understanding how Meson tracks and manipulates build outputs. The presence of `found_method` is interesting; it might relate to conditional build logic.
* **Methods with decorators like `@noPosargs`, `@noKwargs`, `@typed_pos_args`, `@typed_kwargs`:** These are important for understanding how the methods are called and what types of arguments they expect within the Meson build language. They enforce the build system's syntax.

**4. Connecting to the Prompt's Questions:**

Now, with a solid understanding of the code, we can address the specific points in the prompt:

* **Functionality:** Summarize what each class represents and the actions it facilitates within the build process.
* **Reversing:** This is where the Frida context is key. The `BuildTargetHolder` and its subclasses directly relate to the *output* of the build. Reverse engineers often work with the final executables and libraries. The methods providing paths (`full_path`) are particularly relevant.
* **Binary/Kernel/Framework:** While the code itself doesn't directly manipulate binary code, kernel internals, or Android frameworks, it *manages the building* of components that might interact with these. For instance, Frida itself likely has components that interact with the target process's memory, which could involve kernel interaction. The build system needs to handle compiling and linking these components.
* **Logical Reasoning:**  The `SubprojectHolder`'s `found_method` and `get_variable_method`, especially the checks for `NullSubprojectInterpreter`, illustrate conditional logic within the build process. If a subproject is disabled, you can't access its variables.
* **User Errors:** The decorators enforcing argument types and counts (`@noPosargs`, `@typed_pos_args`) are designed to catch common errors in `meson.build` files. Trying to call a method with the wrong number or type of arguments would lead to an error handled by the Meson interpreter.
* **User Operation and Debugging:**  The path to this file and its role in Meson's interpretation process gives clues. A user interacting with the build process (e.g., running `meson build`, `ninja`) will indirectly cause this code to be executed. If there are errors in the `meson.build` file related to how targets, subprojects, or modules are defined or used, the execution might trace back to these object definitions.

**5. Structuring the Answer:**

Finally, organize the information into a clear and structured answer, addressing each point in the prompt with specific examples from the code. Use clear headings and bullet points to enhance readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this code directly interacts with Frida's instrumentation engine.
* **Correction:**  The file path and Meson context strongly suggest this is about the *build process*, not runtime instrumentation. While the output of the build *will be* Frida, this code manages *how* it's created.
* **Initial thought:**  Focus on the technical details of each method.
* **Refinement:** Emphasize the *purpose* of each class and method within the broader build system and its relationship to Frida. Connect the technical details to the user experience (e.g., how errors manifest).

By following this thought process, we can effectively analyze the code snippet and provide a comprehensive answer that addresses all aspects of the prompt.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 文件中的一部分，它定义了在 Meson 构建系统中用于表示各种构建对象的 Python 类。Meson 是 Frida 使用的构建系统。这些类作为 Meson 解释器在解析 `meson.build` 文件时创建的对象的蓝图。

**功能列举：**

这个文件定义了用于表示以下构建系统概念的 Python 类：

1. **`Test`**:  代表一个测试用例。它包含了运行测试所需的各种属性，例如测试名称、要执行的程序、参数、环境变量、超时设置等。
2. **`NullSubprojectInterpreter`**:  代表一个空的子项目解释器。这通常用于表示一个被禁用或未找到的子项目。
3. **`SubprojectHolder`**:  代表一个子项目。它持有子项目的解释器对象，以及与子项目相关的元数据，例如子目录、警告信息、禁用的特性等。它允许访问子项目定义的变量。
4. **`ModuleObjectHolder` 和 `MutableModuleObjectHolder`**:  用于持有 Meson 模块的对象。`ModuleObjectHolder` 是只读的，而 `MutableModuleObjectHolder` 允许修改其持有的模块对象。模块在 Meson 中提供额外的功能，例如查找程序、处理依赖项等。
5. **`BuildTargetHolder` (及其子类 `ExecutableHolder`, `StaticLibraryHolder`, `SharedLibraryHolder`, `BothLibrariesHolder`, `SharedModuleHolder`, `JarHolder`)**:  这是最重要的类之一，用于表示各种构建目标，例如可执行文件、静态库、共享库、同时构建静态和共享库的目标、共享模块和 Java Archive 文件。它提供了访问构建目标属性和执行与构建目标相关的操作的方法。
6. **`CustomTargetIndexHolder`**:  用于持有自定义目标输出文件列表中特定索引的文件。
7. **`_CustomTargetHolder` 和 `CustomTargetHolder`**:  用于表示用户自定义的构建目标，这些目标允许执行任意命令来生成文件。
8. **`RunTargetHolder`**:  用于表示运行目标，这些目标在构建完成后执行一些操作，例如运行测试或部署文件。
9. **`AliasTargetHolder`**:  用于表示目标别名，它允许用一个名称引用一组目标。
10. **`GeneratedListHolder`**:  用于表示由生成器生成的文件列表。
11. **`GeneratorHolder`**:  用于表示文件生成器，它接收一组输入文件并生成输出文件。
12. **`StructuredSourcesHolder`**:  用于表示结构化源代码，可能用于组织源代码的特定方式。

**与逆向方法的关系及举例说明：**

这些类与逆向工程密切相关，因为它们描述了如何构建最终的可执行文件和库，而这些正是逆向工程师分析的对象。

* **`ExecutableHolder`，`SharedLibraryHolder`，`StaticLibraryHolder`**: 这些类代表了最终被编译和链接的二进制文件。逆向工程师会分析这些文件以理解软件的功能、算法和潜在的安全漏洞。例如，`full_path_method` 可以获取生成的可执行文件的绝对路径，逆向工程师可以使用这个路径来定位和分析目标二进制文件。
* **`CustomTargetHolder`**:  自定义目标可以执行任何命令，这可能包括用于混淆代码、加密或执行其他逆向对抗措施的脚本。理解自定义目标的命令可以帮助逆向工程师了解构建过程中可能引入的特殊处理。
* **`Test`**:  虽然不是直接用于构建最终产品，但测试用例可以揭示软件的预期行为和功能。逆向工程师有时会分析测试用例以获得对代码功能的理解。
* **`GeneratorHolder`**: 代码生成器可以动态生成源代码或其他构建工件。理解生成器的过程对于逆向工程至关重要，因为直接分析生成的代码可能比分析生成器本身更容易。

**二进制底层，Linux, Android 内核及框架知识的说明：**

这些类虽然是构建系统的抽象表示，但它们的操作最终会影响到二进制底层、Linux 和 Android 环境。

* **`ExecutableHolder`, `SharedLibraryHolder`**:  它们代表了编译后的二进制文件，这些文件在 Linux 或 Android 上运行时会直接与操作系统内核交互。理解这些目标的构建方式（例如，链接了哪些库，使用了哪些编译选项）对于理解其运行时行为至关重要。
* **`StaticLibraryHolder`, `SharedLibraryHolder`**: 这些类表示库文件。在 Linux 和 Android 上，动态链接库（共享库）是重要的组成部分。逆向工程可能需要分析这些库以理解程序的功能依赖。
* **`BuildTargetHolder` 的方法 `extract_objects_method` 和 `extract_all_objects_method`**:  这些方法涉及到从库文件中提取目标文件（`.o` 文件）。这些目标文件包含了编译后的机器码，是二进制底层分析的基础。
* **`BuildTargetHolder` 的 `outdir_method` 和 `full_path_method`**:  这些方法返回构建输出的目录和完整路径。在 Android 开发中，这些路径可能指向 APK 文件中的特定位置，例如 `lib/` 目录下的 native 库。
* **构建系统本身 (Meson) 需要理解目标平台的特性**，例如不同的操作系统对共享库的命名约定、系统调用接口等。这些类作为 Meson 解释器的一部分，间接地反映了对底层平台知识的封装。

**逻辑推理及假设输入与输出：**

让我们以 `SubprojectHolder` 的 `get_variable_method` 为例进行逻辑推理：

**假设输入:**

1. 一个 `SubprojectHolder` 对象，代表一个已启用的子项目，其 `held_object` 是一个 `Interpreter` 实例。
2. 调用 `get_variable_method`，`args` 为 `['my_variable']`，其中 `my_variable` 是子项目 `meson.build` 文件中定义的一个变量。

**输出:**

`get_variable_method` 将返回子项目解释器中 `my_variable` 的值。

**假设输入 (错误情况):**

1. 一个 `SubprojectHolder` 对象，代表一个已禁用的子项目，其 `held_object` 是一个 `NullSubprojectInterpreter` 实例。
2. 调用 `get_variable_method`，`args` 为 `['my_variable']`。

**输出:**

`get_variable_method` 将抛出一个 `InterpreterException`，提示 "Subproject "{self.subdir}" disabled can't get_variable on it."。

**用户或编程常见的使用错误及举例说明：**

* **`SubprojectHolder.get_variable_method` 参数错误:** 用户可能在 `meson.build` 文件中尝试使用 `get_variable` 方法时提供了错误的参数数量或类型。例如，`subproject('foo').get_variable()` (缺少变量名) 或 `subproject('foo').get_variable(123)` (变量名应该是字符串)。Meson 解释器在执行到这里时会抛出 `InterpreterException`。
* **访问禁用子项目的变量:**  用户可能尝试访问一个被条件禁用的子项目中的变量。例如，如果子项目仅在特定条件下构建，但在其他条件下尝试访问其变量，就会触发 `SubprojectHolder` 中的检查并抛出异常。
* **`BuildTargetHolder.extract_objects_method` 参数错误:** 用户可能传递了错误类型的文件列表给 `extract_objects` 方法。例如，传递了一个字符串而不是 `mesonlib.File` 对象。Meson 的类型检查机制会捕获这类错误。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户编写 `meson.build` 文件:** 用户定义了项目结构、依赖项、构建目标和测试用例。例如，他们可能会使用 `executable()` 函数定义一个可执行文件，或者使用 `test()` 函数定义一个测试用例。
2. **用户运行 `meson setup builddir`:**  Meson 工具读取 `meson.build` 文件，并创建一个构建目录。在这个过程中，Meson 的解释器会解析 `meson.build` 文件中的各种函数调用和声明。
3. **解释器创建对象:** 当解释器遇到如 `executable()` 或 `test()` 这样的函数调用时，它会创建相应的对象，例如 `ExecutableHolder` 或 `Test` 的实例。这些实例存储了构建目标的元数据。
4. **解释器执行方法:**  在构建过程中，Meson 可能会调用这些对象的方法来执行特定的操作。例如，在构建可执行文件时，可能会调用 `ExecutableHolder` 的方法来获取输出路径。
5. **用户运行 `ninja` 或 `meson compile`:** 构建工具根据 Meson 生成的构建文件执行实际的编译和链接操作。
6. **调试线索:** 如果在构建过程中出现错误，例如找不到依赖项、编译失败或链接失败，开发者可能会检查 Meson 的输出。如果错误信息指向与特定构建目标或测试用例相关的问题，那么调试过程可能会涉及到理解这些 `*Holder` 类中存储的信息以及它们的方法是如何被调用的。例如，如果一个测试失败，开发者可能会查看 `Test` 对象的属性来理解测试是如何配置的。

**归纳一下它的功能 (第 2 部分):**

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 文件定义了 Meson 构建系统在解释 `meson.build` 文件时使用的核心对象类型。这些类充当了构建系统元素的蓝图，例如可执行文件、库、测试用例、子项目和自定义构建步骤。它们封装了与这些元素相关的属性和操作，使得 Meson 能够理解和执行构建过程。这些对象的存在和行为对于 Frida 项目的构建至关重要，并且理解这些类对于进行 Frida 的构建调试、定制和深入分析具有重要意义。它们也间接地反映了构建系统对底层平台（如 Linux 和 Android）的理解和抽象。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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