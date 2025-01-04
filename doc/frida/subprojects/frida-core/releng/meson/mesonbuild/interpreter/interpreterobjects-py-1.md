Response:
The user wants to understand the functionality of the provided Python code snippet, which is part of the Frida dynamic instrumentation tool. This code defines various classes that seem to represent different build artifacts and concepts within the Meson build system. I need to analyze each class and its methods, explaining their purpose and how they relate to reverse engineering, binary internals, Linux/Android specifics, and potential usage errors.

Here's a breakdown of how I'll approach this:

1. **Identify the core classes:**  List the main classes defined in the code.
2. **Analyze each class:** For each class, determine:
    - What build system concept it represents (e.g., test, subproject, executable).
    - Its key attributes (the `__init__` parameters).
    - The purpose of its methods.
3. **Relate to reverse engineering:** Consider how each class and its methods could be used or relevant in a reverse engineering context. Frida being a dynamic instrumentation tool, the connection should exist primarily through manipulating and inspecting running processes.
4. **Connect to binary/kernel/framework concepts:**  Identify any aspects that touch upon low-level binary details, Linux or Android kernel functionalities, or Android framework components.
5. **Look for logical inferences:** If methods perform calculations or decisions based on input, provide example inputs and expected outputs.
6. **Identify potential user errors:** Point out common mistakes a user might make when interacting with these objects or methods.
7. **Explain the user journey:**  Hypothesize how a user might end up interacting with these specific parts of the Frida codebase. This involves understanding the typical Frida workflow.
8. **Summarize the overall functionality:** Provide a concise summary of the purpose of this code section.
这是 Frida 动态 instrumentation 工具中 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 文件的第二部分源代码。这个文件定义了 Meson 构建系统中用于表示各种构建目标和相关概念的 Python 对象。这些对象在 Frida 的构建过程中被创建和操作。

**功能归纳:**

总的来说，这个文件的主要功能是定义了一系列 Python 类，用于封装和操作 Meson 构建系统中的各种构建产物和概念。这些类提供了访问和操作这些构建对象的属性和方法，使得 Frida 的构建脚本能够以面向对象的方式处理构建过程中的各种元素。

**各个类的具体功能：**

* **`TestHolder`**: 表示一个测试用例。它封装了测试的名称、所属的测试套件、项目名称、执行程序、依赖项、是否并行执行、命令行参数、环境变量、是否预期失败、超时时间、工作目录、协议、优先级和详细程度等信息。
* **`NullSubprojectInterpreter`**:  表示一个空的子项目解释器。通常用于表示被禁用或未找到的子项目。
* **`SubprojectHolder`**: 表示一个子项目。它持有子项目的解释器对象（可以是真实的解释器或 `NullSubprojectInterpreter`），子目录路径、警告计数、禁用的特性、异常信息和调用栈信息。它提供了访问子项目变量和检查子项目是否被找到的方法。
* **`ModuleObjectHolder`**:  用于持有模块对象的通用类。它提供了调用模块对象方法的功能，并在调用前后处理参数和返回值。
* **`MutableModuleObjectHolder`**: 继承自 `ModuleObjectHolder`，表示可变的模块对象。它重写了 `__deepcopy__` 方法以支持深拷贝。
* **`BuildTargetHolder`**:  一个抽象基类，用于持有各种构建目标对象（如可执行文件、静态库、共享库）。它提供了获取构建目标信息（如名称、ID、输出目录、完整路径）、提取目标文件中的对象、以及检查目标是否被找到等方法。
* **`ExecutableHolder`**: 继承自 `BuildTargetHolder`，专门用于持有可执行文件构建目标。
* **`StaticLibraryHolder`**: 继承自 `BuildTargetHolder`，专门用于持有静态库构建目标。
* **`SharedLibraryHolder`**: 继承自 `BuildTargetHolder`，专门用于持有共享库构建目标。
* **`BothLibrariesHolder`**: 继承自 `BuildTargetHolder`，用于持有同时生成静态库和共享库的构建目标。它提供了分别获取静态库和共享库对象的方法。
* **`SharedModuleHolder`**: 继承自 `BuildTargetHolder`，专门用于持有共享模块构建目标。
* **`JarHolder`**: 继承自 `BuildTargetHolder`，专门用于持有 Jar 包构建目标。
* **`CustomTargetIndexHolder`**: 用于持有自定义目标输出文件索引的对象。它提供了获取特定输出文件完整路径的方法。
* **`_CustomTargetHolder`**:  一个抽象基类，用于持有自定义目标对象。它提供了获取输出文件完整路径和将所有输出文件转换为列表的方法，并支持通过索引访问特定输出文件。
* **`CustomTargetHolder`**: 继承自 `_CustomTargetHolder`，专门用于持有自定义目标对象。
* **`RunTargetHolder`**: 用于持有运行目标对象，通常用于定义构建后需要执行的命令或脚本。
* **`AliasTargetHolder`**: 用于持有别名目标对象，用于为一个或多个目标定义一个简洁的别名。
* **`GeneratedListHolder`**: 用于持有生成文件列表的对象。
* **`GeneratorHolder`**: 用于持有生成器对象，生成器用于在构建过程中根据输入生成文件。它提供了 `process` 方法来执行生成操作。
* **`StructuredSourcesHolder`**: 用于持有结构化源文件集合的对象。

**与逆向方法的关联 (举例说明):**

* **`ExecutableHolder`**:  在逆向工程中，最终分析的目标往往是可执行文件。通过 `ExecutableHolder` 对象，可以获取到可执行文件的路径 (`full_path_method`)，这对于后续使用 Frida 加载和 hook 该可执行文件至关重要。例如，Frida 脚本可以使用这个路径来启动目标进程并进行动态分析。
* **`SharedLibraryHolder`**: 共享库是逆向分析的常见目标，因为许多功能模块都以共享库的形式存在。`SharedLibraryHolder` 允许获取共享库的路径，这对于使用 Frida hook 共享库中的函数或者替换其实现非常重要。
* **`CustomTargetHolder`**: 如果 Frida 的构建过程涉及到一些自定义的二进制处理工具（例如，将某些数据文件转换为特定格式），那么这些工具的输出可能通过 `CustomTargetHolder` 来表示。逆向工程师可能需要了解这些中间产物的生成过程和内容，以便更好地理解 Frida 的内部工作原理。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

* **`ExecutableHolder` 和 `SharedLibraryHolder` 的 `full_path_method`**:  这些方法返回的是构建产物的绝对路径。在 Linux 和 Android 系统中，可执行文件和共享库以特定的二进制格式（如 ELF）存储在文件系统中。Frida 需要知道这些文件的确切位置才能进行操作。
* **`BuildTargetHolder` 的 `extract_objects_method` 和 `extract_all_objects_method`**: 这些方法涉及到从构建目标（通常是库文件）中提取目标代码对象。这直接关联到二进制文件的结构，例如 ELF 文件中的 `.o` 目标文件。
* **`SharedModuleHolder`**: 在 Android 系统中，共享模块（通常是 `.so` 文件）经常被用作 Native 库。Frida 可以在运行时加载和操作这些共享模块，这涉及到 Android 系统的动态链接机制。

**逻辑推理 (假设输入与输出):**

假设有以下 Meson 构建定义：

```meson
project('my_frida_module', 'cpp')
executable('my_tool', 'my_tool.cpp')
test('my_tool_test', 'my_tool')
```

* **输入 (在 Meson 解释器中处理上述定义)**:
    - 创建一个 `ExecutableHolder` 对象来表示 `my_tool`。
    - 创建一个 `TestHolder` 对象来表示 `my_tool_test`，并将 `my_tool` 的 `ExecutableHolder` 对象作为其 `exe` 属性。
* **输出**:
    - `ExecutableHolder` 对象的 `get_name()` 方法将返回 "my_tool"。
    - `TestHolder` 对象的 `get_exe()` 方法将返回 `my_tool` 的 `ExecutableHolder` 对象。
    - `TestHolder` 对象的 `is_parallel` 属性的默认值可能是 `False` (除非在 `test()` 函数中显式指定)。

**涉及用户或编程常见的使用错误 (举例说明):**

* **`SubprojectHolder` 的 `get_variable_method`**: 如果用户尝试在禁用的子项目上调用 `get_variable`，将会抛出 `InterpreterException`，提示用户无法在禁用的子项目上获取变量。
* **`BuildTargetHolder` 的 `extract_objects_method`**: 如果用户传递了错误类型的文件或者字符串给 `extract_objects_method`，将会导致构建失败或运行时错误。Meson 的类型检查会尽可能提前捕获这些错误。
* **`CustomTargetHolder` 的 `op_index`**: 如果用户尝试使用超出自定义目标输出文件数量的索引访问输出文件（例如，自定义目标只生成 2 个文件，但用户尝试访问索引为 2 的文件），将会抛出 `InvalidArguments` 异常。
* **`GeneratorHolder` 的 `process_method`**: 如果用户在 `preserve_path_from` 参数中传递了相对路径，将会抛出 `InvalidArguments` 异常，因为目前只支持绝对路径。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者编写 `meson.build` 文件:** Frida 的开发者在 `meson.build` 文件中定义了项目的构建规则，包括可执行文件、库文件、测试用例等。这些定义会使用 Meson 提供的函数，例如 `executable()`, `shared_library()`, `test()` 等。
2. **用户运行 `meson` 命令:**  用户在 Frida 的源代码目录下运行 `meson` 命令来配置构建系统。Meson 会读取 `meson.build` 文件并解析其中的指令。
3. **Meson 解释器执行:** Meson 的解释器会执行 `meson.build` 文件中的代码。当遇到诸如 `executable()`, `shared_library()`, `test()` 等函数调用时，解释器会创建相应的 `ExecutableHolder`, `SharedLibraryHolder`, `TestHolder` 等对象，并将这些对象存储在内部的数据结构中。
4. **Meson 后端生成构建系统文件:**  Meson 根据解释器生成的信息，生成特定构建系统（如 Ninja）的构建文件。
5. **用户运行构建命令 (例如 `ninja`):** 用户运行构建命令来实际编译和链接 Frida 的各个组件。
6. **在构建过程中或脚本中使用这些对象:**  在 Meson 的构建脚本中，或者在自定义的构建步骤中，可能会需要访问和操作这些构建对象的信息。例如，一个自定义的脚本可能需要获取某个可执行文件的路径，或者需要列出某个库文件的所有目标文件。这时，就会涉及到访问这些 `Holder` 对象的方法和属性。

当开发者在调试 Frida 的构建过程时，如果遇到了与构建目标或测试相关的错误，他们可能会查看这些 `Holder` 对象的属性和方法，以了解 Meson 是如何表示和处理这些构建元素的。例如，如果一个测试没有按预期运行，开发者可能会检查 `TestHolder` 对象的 `cmd_args` 和 `env` 属性，以确定测试是如何被执行的。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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