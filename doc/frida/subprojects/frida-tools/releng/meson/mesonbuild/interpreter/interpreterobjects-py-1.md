Response:
My thinking process to analyze the provided Python code and answer the prompt goes through these stages:

1. **Understand the Goal:** The request asks for a functional breakdown of the Python code, particularly within the context of reverse engineering, low-level interactions, logical reasoning (with examples), common usage errors, and how a user might reach this code during debugging. It emphasizes that this is the *second* part of a larger file and needs a concise summary.

2. **Initial Code Scan and Keyword Identification:** I first quickly read through the code, looking for keywords and class names that hint at the functionality. I noticed terms like `Test`, `Subproject`, `Module`, `BuildTarget`, `Executable`, `Library`, `CustomTarget`, `Generator`, and methods like `get_variable`, `found`, `extract_objects`, `full_path`, `process`. These immediately suggest a build system context.

3. **Class-by-Class Analysis:** I then examine each class definition more closely, focusing on its attributes, methods, and inheritance:

    * **`Test`:**  Clearly related to running tests within the build system. The attributes describe a test case.
    * **`NullSubprojectInterpreter`:**  A placeholder or marker for a disabled subproject.
    * **`SubprojectHolder`:** Represents a subproject within the larger build. It allows access to variables and checks if the subproject is found (enabled).
    * **`ModuleObjectHolder` and `MutableModuleObjectHolder`:** These handle interactions with modules within the build system, including calling their methods and managing their state.
    * **`BuildTargetHolder` and its subclasses (`ExecutableHolder`, `StaticLibraryHolder`, etc.):**  These are central to the build process, representing the various output artifacts (executables, libraries). They provide methods to get information about the target (name, path, output directory) and perform actions like extracting objects.
    * **`CustomTargetIndexHolder` and `CustomTargetHolder`:** Represent custom build steps defined by the user.
    * **`RunTargetHolder` and `AliasTargetHolder`:**  Represent other types of build targets.
    * **`GeneratedListHolder`:** Deals with lists of generated files.
    * **`GeneratorHolder`:**  Represents a tool that generates files during the build process.
    * **`StructuredSourcesHolder`:**  Handles structured source files.

4. **Identify Core Functionality:** From the class analysis, I can deduce the primary functions of this code:

    * **Representing and managing different build artifacts and processes:** This includes executables, libraries, custom targets, generators, and tests.
    * **Providing access to information about these artifacts:**  Methods like `get_name`, `full_path`, `outdir` allow introspection.
    * **Enabling interaction with subprojects and modules:** The `SubprojectHolder` and `ModuleObjectHolder` facilitate this.
    * **Supporting custom build steps:**  The `CustomTargetHolder` allows defining and interacting with user-defined build commands.
    * **Handling file generation:**  The `GeneratorHolder` manages tools that create output files.
    * **Managing test execution:** The `Test` class represents a test case.

5. **Relate to Reverse Engineering, Low-Level, Logic, Errors, and Debugging:** Now I go back through the functionality and think about how it connects to the specific aspects requested in the prompt:

    * **Reverse Engineering:** The ability to access the output paths and extract objects from build targets (`extract_objects`, `full_path`) is directly relevant to reverse engineering. Someone might want to analyze the generated executable or library.
    * **Binary/Low-Level, Linux/Android Kernel/Framework:**  The code doesn't directly manipulate bits or interact with the kernel. However, the *output* of the build process (executables, shared libraries) will run at this level. The build system manages the creation of these low-level artifacts. The `env` argument in `GeneratorHolder.process_method` hints at environment variables which can affect the compilation process, potentially including interactions with system libraries.
    * **Logical Reasoning:** I look for conditional logic and data flow. The `SubprojectHolder.get_variable_method` with its error handling (`try...except KeyError`) and the conditional return based on the number of arguments exemplifies logical reasoning.
    * **User Errors:** I consider how a user might misuse the API. Examples include providing incorrect arguments to methods (wrong types, wrong number), trying to access variables in disabled subprojects, or using deprecated features.
    * **Debugging:** I think about how a developer might end up examining this code. This would likely happen when investigating issues with the build process itself, such as why a particular target isn't being built correctly or why a test is failing. The call stack information in `SubprojectHolder` is a direct debugging aid.

6. **Construct Examples:** Based on the analysis, I create concrete examples for each category (reverse engineering, low-level, logic, errors). These examples should be clear and illustrate the connection.

7. **Address "User Operation as Debugging Clue":**  I consider the steps a user would take that would lead to this code being relevant during debugging. This involves thinking about the Meson build process – configuring the build, running the build, running tests – and where things might go wrong.

8. **Summarize Functionality (Part 2):**  Since this is the second part of the file, I need to provide a concise summary that captures the overall purpose of the code. The key takeaway is that this code defines Python objects that represent various elements of a Meson build, enabling introspection and manipulation of the build process.

9. **Review and Refine:** Finally, I reread my analysis and examples to ensure clarity, accuracy, and completeness. I check that I've addressed all parts of the prompt. I also ensure the tone is appropriate and informative.
这是 frida 动态 instrumentation 工具中 `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 文件的第二部分源代码。这个文件主要定义了 Meson 构建系统中用于表示各种构建目标的 Python 对象，这些对象在 Meson 的解释器中使用，以便在构建配置阶段提供对构建目标的访问和操作。

**归纳一下它的功能:**

总而言之，这部分代码延续了第一部分的功能，定义了更多用于表示 Meson 构建系统中各种构建产物和过程的 Python 对象。这些对象为 Meson 的 DSL 提供了 Python 层的抽象，使得用户可以在 `meson.build` 文件中通过这些对象与构建系统进行交互，例如获取构建目标的路径、提取对象文件、处理生成器等。

接下来，我们详细列举一下这部分代码的功能，并结合逆向、底层、逻辑推理、用户错误和调试线索进行说明。

**功能列举:**

* **表示测试 (`Test` 类):**
    * 封装了测试用例的信息，包括名称、所属套件、项目名称、可执行文件、依赖、是否并行、命令行参数、环境变量、是否应该失败、超时时间、工作目录、协议、优先级和详细程度。
    * **与逆向的关系:** 在逆向工程中，可能需要对目标程序进行测试，以验证逆向分析的正确性或发现漏洞。`Test` 对象定义了如何运行这些测试。例如，可以创建一个 `Test` 对象来运行一个修改后的二进制文件，并检查其行为是否符合预期。
    * **涉及二进制底层:** `exe` 属性指向要执行的二进制文件，测试的最终目的是验证该二进制的行为。
    * **假设输入与输出:** 假设创建一个 `Test` 对象，`exe` 指向一个简单的程序，`cmd_args` 为 `["--version"]`。运行这个测试，预期输出是该程序的版本信息。
* **表示空子项目解释器 (`NullSubprojectInterpreter` 类):**
    *  作为一个标记，表示一个禁用的子项目。
* **表示子项目持有者 (`SubprojectHolder` 类):**
    *  封装了一个子项目解释器，并提供了访问子项目变量的方法。
    * **与逆向的关系:** 在大型项目中，可能会使用子项目来组织代码。逆向工程师可能需要理解不同子项目之间的依赖关系和交互方式。`SubprojectHolder` 允许访问子项目的配置信息。
    * **逻辑推理:** `get_variable_method` 方法首先检查子项目是否被禁用。如果被禁用，则抛出异常。这是一种基于状态的逻辑判断。假设尝试访问一个被禁用的子项目的变量，`get_variable_method` 将抛出一个 `InterpreterException`。
    * **用户错误:** 用户可能会尝试访问一个被禁用的子项目的变量，导致构建失败。
* **表示模块对象持有者 (`ModuleObjectHolder` 和 `MutableModuleObjectHolder` 类):**
    * 封装了 Meson 模块对象，并提供了调用模块方法的能力。
    * **与逆向的关系:** Meson 模块可以提供各种构建辅助功能。逆向工程师可能需要了解项目中使用的自定义 Meson 模块，以理解构建过程。
* **表示构建目标持有者 (`BuildTargetHolder` 及其子类):**
    * 这是核心部分，封装了各种构建目标，如可执行文件、静态库、共享库、模块等。
    * 提供了获取构建目标信息（如名称、ID、输出目录、完整路径）和执行操作（如提取对象文件）的方法。
    * **与逆向的关系:** 这是逆向工程最直接相关的部分。`full_path_method` 可以获取生成的可执行文件或库的绝对路径，这是逆向分析的起点。`extract_objects_method` 可以提取目标文件中的对象代码，方便进行更细粒度的分析。
    * **涉及二进制底层:** 这些类表示最终生成的二进制产物（可执行文件、库），是二进制分析的目标。
    * **涉及 Linux/Android 内核及框架的知识:**  生成的共享库可能与操作系统或 Android 框架进行交互。例如，一个共享库可能使用了 Android NDK 提供的 API。
    * **假设输入与输出:**  假设有一个 `ExecutableHolder` 对象表示一个名为 `my_program` 的可执行文件。调用 `full_path_method` 将返回该可执行文件在构建目录中的完整路径。调用 `extract_objects_method` 并传入一些源文件，将返回这些源文件编译生成的对象文件。
    * **用户错误:** 用户可能尝试在没有生成的情况下调用 `full_path_method`，或者传递错误的文件类型给 `extract_objects_method`。
* **表示自定义目标索引持有者 (`CustomTargetIndexHolder` 类):**
    *  封装了自定义目标输出的单个文件。
    * **与逆向的关系:** 自定义目标可以执行任意命令，可能用于生成逆向分析所需的辅助文件或执行特定的逆向工具。
* **表示自定义目标持有者 (`CustomTargetHolder` 类):**
    * 封装了用户定义的构建步骤，可以执行任意命令并生成输出文件。
    * **与逆向的关系:**  自定义目标可以用于在构建过程中执行逆向工具，例如反汇编器或静态分析工具，并将结果作为构建的一部分。
    * **涉及二进制底层:** 自定义目标执行的命令可能直接操作二进制文件。
    * **逻辑推理:** `op_index` 方法允许通过索引访问自定义目标的输出文件，并进行边界检查，防止索引越界。
    * **用户错误:** 用户可能传递超出范围的索引给 `op_index` 方法。
* **表示运行目标持有者 (`RunTargetHolder` 类):**
    * 封装了在构建完成后执行的任意命令。
    * **与逆向的关系:** 运行目标可以用于在构建后执行测试或部署脚本，也可能包含一些逆向分析相关的后处理步骤。
* **表示别名目标持有者 (`AliasTargetHolder` 类):**
    * 封装了一个指向其他构建目标的别名。
* **表示生成列表持有者 (`GeneratedListHolder` 类):**
    * 封装了由生成器生成的文件列表。
* **表示生成器持有者 (`GeneratorHolder` 类):**
    * 封装了一个代码生成器，可以在构建过程中根据输入生成源代码或其他文件。
    * **与逆向的关系:** 代码生成器可能会生成用于特定架构或平台的代码，理解生成器的逻辑有助于逆向分析最终的二进制文件。
    * **用户错误:**  用户可能在 `generator.process` 中传递不正确的文件类型或缺少必要的参数。
* **表示结构化源文件持有者 (`StructuredSourcesHolder` 类):**
    * 封装了结构化的源文件集合。

**用户操作是如何一步步的到达这里，作为调试线索。**

作为一个开发者或逆向工程师，你通常不会直接与这些 Python 代码交互。你的操作通常是在更高层次，通过 Meson 的 DSL (`meson.build` 文件) 进行。但是，当构建过程出现问题时，你可能会需要查看 Meson 的内部实现来进行调试：

1. **编写 `meson.build` 文件:** 用户首先会编写 `meson.build` 文件来描述项目的构建过程。例如，定义一个可执行目标、一个共享库目标或一个测试。
2. **运行 `meson setup`:**  用户运行 `meson setup <build_directory>` 命令来配置构建。Meson 会读取 `meson.build` 文件，并创建内部的数据结构来表示构建图。在这个过程中，会创建各种 `InterpreterObject` 的实例，包括这里定义的类。
3. **运行 `meson compile` 或 `ninja`:** 用户运行 `meson compile` 或 `ninja` 命令来实际构建项目。在这个阶段，Meson 会根据之前创建的构建图执行相应的构建命令。
4. **构建失败或行为异常:** 如果构建失败，或者生成的二进制文件行为不符合预期，开发者可能需要进行调试。
5. **查看 Meson 的日志和内部状态:**  在调试过程中，开发者可能会查看 Meson 生成的日志文件，或者使用 Meson 提供的调试工具（如果存在）。
6. **查看 Meson 源代码:** 如果日志信息不足以定位问题，开发者可能需要深入 Meson 的源代码进行分析，特别是当问题涉及到 Meson 如何解释 `meson.build` 文件或如何管理构建目标时。此时，就可能需要查看 `interpreterobjects.py` 这样的文件，以理解 Meson 内部是如何表示和操作构建目标的。
7. **设置断点或打印信息:** 开发者可能会在 `interpreterobjects.py` 中设置断点或添加打印语句，以查看在构建过程中创建了哪些对象，这些对象的状态是什么，以及调用了哪些方法。例如，可以查看某个 `BuildTargetHolder` 对象的 `full_path` 属性，以确认生成的可执行文件路径是否正确。
8. **分析调用栈:** 当出现异常时，查看 Python 的调用栈可以帮助理解代码的执行流程，以及如何到达 `interpreterobjects.py` 中的特定代码。例如，如果 `get_variable_method` 抛出了异常，调用栈会显示是从哪个 `meson.build` 的指令触发了这个方法的调用。

**总结:**

这部分 `interpreterobjects.py` 文件定义了 Meson 构建系统中的核心对象，用于表示和操作各种构建目标。理解这些对象的结构和方法对于理解 Meson 的工作原理以及调试构建过程至关重要，尤其是在涉及到逆向工程、底层二进制操作或复杂的构建逻辑时。开发者通过编写 `meson.build` 文件与这些对象间接交互，而在调试构建问题时，则可能需要深入到这些源代码层面进行分析。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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