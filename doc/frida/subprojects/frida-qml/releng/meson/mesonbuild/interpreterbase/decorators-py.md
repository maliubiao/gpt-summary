Response:
My thinking process to analyze the provided Python code snippet went through these stages:

1. **Initial Skim for Structure and Keywords:** I first scanned the code for familiar Python constructs like `def`, `@`, `class`, `import`, and keywords like `wraps`, `dataclass`, `if`, `for`, `raise`. This gave me a high-level understanding of the code's organization and purpose. I noticed the frequent use of decorators (`@`) which strongly suggests a focus on modifying function behavior.

2. **Identify Core Modules and Concepts:**  I looked at the import statements:
    * `mesonlib`, `mlog`:  These clearly indicate this code is part of the Meson build system.
    * `disabler`:  Suggests a mechanism for conditionally disabling features.
    * `exceptions`:  Indicates custom exception handling.
    * `_unholder`: Likely related to resolving placeholder values.
    * `dataclasses`, `functools`, `abc`, `itertools`, `copy`, `typing`: Standard Python libraries used for data structures, function wrapping, abstract base classes, iteration, copying, and type hinting respectively. The heavy use of `typing` points towards robust type checking.

3. **Focus on Decorators:** The abundance of decorators was the most prominent feature. I started analyzing each decorator individually:
    * `noPosargs`, `noKwargs`, `stringArgs`: These enforce constraints on function arguments (no positional, no keyword, only string arguments).
    * `noArgsFlattening`, `noSecondLevelHolderResolving`:  These seem specific to Meson's internal workings, potentially related to how arguments are processed or resolved.
    * `unholder_return`:  This likely handles the final processing of the return value, potentially resolving placeholders.
    * `disablerIfNotFound`:  This ties into the `Disabler` concept, suggesting conditional disabling based on function results.
    * `permittedKwargs`:  This restricts the allowed keyword arguments.
    * `typed_operator`, `typed_pos_args`, `typed_kwargs`:  These are the most complex and crucial decorators. They are clearly responsible for type checking function arguments (both positional and keyword). The names and the logic within these decorators strongly suggest a focus on enforcing API contracts and preventing common errors.

4. **Analyze Helper Functions and Classes:** I then examined the supporting functions and classes:
    * `get_callee_args`:  This function extracts important context (node, arguments, keyword arguments, subproject) from the arguments passed to the wrapped function. This context is likely used by the decorators for validation and other purposes.
    * `ContainerTypeInfo`: This class defines a way to specify and check the types of container arguments (lists, dictionaries), including constraints like requiring even length or non-emptiness.
    * `KwargInfo`: This class provides a detailed description of a keyword argument, including its type, whether it's required, default value, and deprecation/addition information. This is central to the `typed_kwargs` decorator.
    * `FeatureCheckBase`, `FeatureNew`, `FeatureDeprecated`: These classes implement a system for tracking and reporting the usage of new and deprecated features based on the target Meson version. This is essential for maintaining compatibility and providing user feedback.

5. **Infer Functionality and Purpose:** Based on the analysis of individual components, I synthesized the overall functionality of the module:
    * **Argument Validation:** The core function is to rigorously validate the arguments passed to Meson interpreter functions. This includes type checking, enforcing constraints on positional and keyword arguments, and validating the contents of container arguments.
    * **Feature Management:** The code tracks the usage of new and deprecated features, allowing Meson to warn users when they are using features that might not be supported in older versions or are no longer recommended.
    * **Internal Meson Mechanics:** Some decorators (like `noArgsFlattening`, `noSecondLevelHolderResolving`, and `unholder_return`) suggest involvement in Meson's internal argument processing and value resolution mechanisms.
    * **Error Prevention:** The decorators help prevent common programming errors by enforcing type constraints and argument requirements at runtime.

6. **Connect to Reverse Engineering and Low-Level Concepts:**  I considered how these functionalities relate to reverse engineering and lower-level concepts:
    * **Reverse Engineering:**  The type checking and validation mechanisms act as a form of API documentation and enforcement. A reverse engineer trying to understand or interact with Frida's QML interface would encounter these checks, making it clearer what types of arguments are expected. If the checks are missing, it will be difficult to understand how to call the functions correctly.
    * **Binary/Kernel/Framework:** While the code itself is high-level Python, the underlying purpose of Frida (dynamic instrumentation) directly involves interacting with processes at the binary level. The validation provided by this code helps ensure that the arguments passed from the QML interface to Frida's core engine are valid, preventing crashes or unexpected behavior in the instrumented process. The feature flagging is also relevant when interacting with different versions of Frida or the target environment.

7. **Construct Examples and Scenarios:**  To further solidify my understanding, I mentally constructed examples of how these decorators and classes would be used and what errors they would catch. This helped in formulating the "User Errors" and "Debugging Clues" sections of the summary.

8. **Structure the Summary:** Finally, I organized my findings into a coherent summary, addressing the specific points requested in the prompt: overall functionality, relation to reverse engineering, connection to low-level concepts, logical inference with examples, user errors, and debugging clues. I paid attention to the "Part 1 of 2" instruction, ensuring the summary focused on the core functionalities evident in the provided snippet.
好的，让我们来详细分析一下 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreterbase/decorators.py` 这个文件的功能。

**文件功能归纳：**

该 Python 文件定义了一系列**装饰器 (decorators)**，用于增强和修改 Meson 构建系统中解释器 (Interpreter) 的函数行为。这些装饰器主要用于：

1. **参数校验和类型检查：**  强制函数接收特定类型的参数，包括位置参数和关键字参数，并能处理列表、字典等容器类型。这有助于确保 Meson 脚本的正确性和可靠性。
2. **功能特性管理：**  跟踪和管理 Meson 中新增和废弃的功能特性，并在用户使用时发出警告或通知，以便保持与 Meson 版本的兼容性。
3. **禁用器 (Disabler) 集成：**  允许在特定条件下禁用某些功能或模块，例如当依赖项未找到时。
4. **返回值处理：**  对函数的返回值进行特定的处理，例如“解包” (unhold) 某些类型的返回值。
5. **代码清晰和可维护性：**  通过装饰器，可以将一些通用的逻辑（如参数校验）从函数主体中分离出来，提高代码的可读性和可维护性。

**与逆向方法的关系：**

虽然这个文件本身不直接涉及二进制分析或内存操作等典型的逆向工程技术，但它在理解 Frida 和 Meson 构建过程方面扮演着重要角色。

* **理解 Frida 的构建过程：** 逆向工程师如果想深入了解 Frida 是如何构建的，以及 Frida 的 QML 接口是如何生成的，就需要理解 Meson 构建系统的运作方式。这个文件中的装饰器定义了 Frida QML 相关代码在 Meson 构建过程中所遵循的规则和约束。
* **分析 Frida 的 QML API：**  这些装饰器帮助定义了 Frida QML 模块的 API 接口。通过分析这些装饰器在 Frida QML 模块中的使用方式，逆向工程师可以推断出哪些函数接受哪些类型的参数，哪些功能是新引入的，哪些功能可能已被废弃。
* **调试 Frida QML 模块：** 当 Frida QML 模块出现问题时，了解这些装饰器的作用可以帮助逆向工程师更好地理解错误信息，例如类型错误或参数缺失错误，并定位问题所在。

**举例说明：**

假设 Frida QML 模块中有一个函数 `call_method(object, method_name, args)`，并且使用了 `@stringArgs` 装饰器。这意味着 `args` 参数必须是一个字符串列表。

* **逆向分析：** 逆向工程师在分析 `call_method` 函数时，如果看到使用了 `@stringArgs` 装饰器，就能立即知道 `args` 参数的类型要求。
* **错误推断：** 如果逆向工程师在调用 `call_method` 时传入了其他类型的参数，例如整数列表，Meson 在构建或运行时会抛出带有 "Arguments must be strings." 错误信息的异常，这有助于逆向工程师快速发现问题。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

虽然这个文件本身是 Meson 构建系统的一部分，属于构建层面的抽象，但它所影响的代码最终会运行在目标系统上，可能涉及到以下方面：

* **二进制底层：** Frida 的核心功能是动态插桩，涉及到对目标进程的内存进行读写和代码注入。Meson 构建系统负责将 Frida 的源代码编译成目标平台的二进制文件。这个文件中的装饰器确保了 Frida QML 模块的构建过程符合预期，间接影响了最终生成的二进制文件的行为。
* **Linux/Android 内核：** Frida 通常需要在 Linux 或 Android 系统上运行，并可能与内核进行交互以实现某些高级功能。Meson 构建系统需要根据目标平台的不同来配置编译选项和链接库。这个文件中的装饰器可能用于管理与平台相关的配置，例如选择不同的后端实现。
* **Android 框架：** 当 Frida 用于插桩 Android 应用程序时，它会与 Android 框架进行交互。Meson 构建系统需要处理与 Android SDK 和 NDK 相关的依赖和配置。这个文件中的装饰器可能用于管理与 Android 框架交互相关的代码的构建规则。

**举例说明：**

假设 Frida QML 模块中有一个用于调用 Android 系统服务的函数，并且使用了 `@typed_pos_args('call_service', str, varargs=T.Any)` 装饰器。这表示该函数至少需要一个字符串参数（服务名称），并且可以接受任意类型的后续参数作为服务调用的参数。

* **底层关联：**  在 Linux 或 Android 系统上调用系统服务通常涉及到系统调用或 Binder IPC 机制。Frida 的底层实现需要与这些机制进行交互。
* **构建影响：** Meson 构建系统需要确保 Frida 的代码能够正确地调用这些底层接口，例如链接到正确的库。`@typed_pos_args` 装饰器确保了 QML 层传递给底层调用的参数类型是符合预期的。

**逻辑推理（假设输入与输出）：**

假设有一个使用了 `@noPosargs` 装饰器的函数 `my_function(**kwargs)`。

* **假设输入：**  在 Meson 脚本中调用 `my_function('positional_arg', kwarg1='value1')`。
* **逻辑推理：**  `@noPosargs` 装饰器会检查调用时是否存在位置参数。由于 `'positional_arg'` 是一个位置参数，装饰器会检测到并抛出 `InvalidArguments('Function does not take positional arguments.')` 异常。
* **预期输出：**  Meson 构建过程会因为参数错误而失败，并显示上述错误信息。

**用户或编程常见的使用错误：**

1. **类型错误：**  用户在 Meson 脚本中调用使用了类型检查装饰器的函数时，传递了错误类型的参数。例如，函数要求字符串，但用户传递了整数。
    * **示例：**  如果 `call_method` 使用了 `@stringArgs`，但用户调用 `call_method(obj, 'method', [1, 2, 3])`，将会触发 `InvalidArguments('Arguments must be strings.')`。
2. **缺少必需的关键字参数：**  函数使用了 `@typed_kwargs` 装饰器，并且某些关键字参数被标记为 `required=True`，但用户在调用时没有提供这些参数。
    * **示例：**  如果一个函数定义了 `typed_kwargs('my_func', KwargInfo('name', str, required=True))`，但用户调用 `my_func()`，将会触发 `InvalidArguments('my_func is missing required keyword argument "name"')`。
3. **使用了不允许的关键字参数：**  函数使用了 `@permittedKwargs` 装饰器，限制了允许的关键字参数，但用户在调用时传入了未定义的关键字参数。
    * **示例：**  如果一个函数使用了 `permittedKwargs({'arg1', 'arg2'})`，但用户调用 `my_func(arg1=1, arg3=2)`，将会触发 `InvalidArguments('Got unknown keyword arguments "arg3"')`。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **编写或修改 Meson 构建脚本 `meson.build`：** 用户编写或修改了 `meson.build` 文件，其中包含了对 Frida QML 模块中某些函数的调用。
2. **运行 Meson 配置命令：** 用户在终端中执行 `meson setup build` 或类似的命令来配置构建环境。
3. **Meson 解析构建脚本：** Meson 读取并解析 `meson.build` 文件。当解析到对 Frida QML 模块函数的调用时，解释器会执行相应的函数。
4. **装饰器发挥作用：**  在函数执行之前，定义的装饰器会先被调用，对传入的参数进行校验、进行特性检查等操作。
5. **触发错误（如果存在）：** 如果用户在 `meson.build` 中传递了不符合装饰器要求的参数，例如类型错误或缺少必需的参数，装饰器会抛出异常。
6. **显示错误信息：** Meson 会捕获这些异常，并在终端中显示相应的错误信息，指明哪个函数调用出了问题以及具体的原因（例如参数类型错误）。

**因此，当用户在运行 Meson 构建命令时看到与参数类型、缺失参数或未知参数相关的错误信息，并且涉及到 Frida QML 模块的函数时，就可以怀疑是这个 `decorators.py` 文件中定义的装饰器触发了这些错误。**

**总结该文件的功能（第 1 部分）：**

该文件的主要功能是为 Meson 构建系统中 Frida QML 模块的解释器函数提供**声明式的参数校验、类型检查和功能特性管理机制**。通过定义一系列装饰器，该文件能够确保 Frida QML 模块的函数在构建过程中接收到正确类型的参数，并能够跟踪和报告新功能和废弃功能的使用情况，从而提高代码的健壮性和可维护性，并帮助用户避免常见的编程错误。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2021 The Meson development team

from __future__ import annotations

from .. import mesonlib, mlog
from .disabler import Disabler
from .exceptions import InterpreterException, InvalidArguments
from ._unholder import _unholder

from dataclasses import dataclass
from functools import wraps
import abc
import itertools
import copy
import typing as T

if T.TYPE_CHECKING:
    from typing_extensions import Protocol

    from .. import mparser
    from .baseobjects import InterpreterObject, SubProject, TV_func, TYPE_var, TYPE_kwargs
    from .operator import MesonOperator

    _TV_IntegerObject = T.TypeVar('_TV_IntegerObject', bound=InterpreterObject, contravariant=True)
    _TV_ARG1 = T.TypeVar('_TV_ARG1', bound=TYPE_var, contravariant=True)

    class FN_Operator(Protocol[_TV_IntegerObject, _TV_ARG1]):
        def __call__(s, self: _TV_IntegerObject, other: _TV_ARG1) -> TYPE_var: ...
    _TV_FN_Operator = T.TypeVar('_TV_FN_Operator', bound=FN_Operator)

def get_callee_args(wrapped_args: T.Sequence[T.Any]) -> T.Tuple['mparser.BaseNode', T.List['TYPE_var'], 'TYPE_kwargs', 'SubProject']:
    # First argument could be InterpreterBase, InterpreterObject or ModuleObject.
    # In the case of a ModuleObject it is the 2nd argument (ModuleState) that
    # contains the needed information.
    s = wrapped_args[0]
    if not hasattr(s, 'current_node'):
        s = wrapped_args[1]
    node = s.current_node
    subproject = s.subproject
    args = kwargs = None
    if len(wrapped_args) >= 3:
        args = wrapped_args[-2]
        kwargs = wrapped_args[-1]
    return node, args, kwargs, subproject

def noPosargs(f: TV_func) -> TV_func:
    @wraps(f)
    def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
        args = get_callee_args(wrapped_args)[1]
        if args:
            raise InvalidArguments('Function does not take positional arguments.')
        return f(*wrapped_args, **wrapped_kwargs)
    return T.cast('TV_func', wrapped)

def noKwargs(f: TV_func) -> TV_func:
    @wraps(f)
    def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
        kwargs = get_callee_args(wrapped_args)[2]
        if kwargs:
            raise InvalidArguments('Function does not take keyword arguments.')
        return f(*wrapped_args, **wrapped_kwargs)
    return T.cast('TV_func', wrapped)

def stringArgs(f: TV_func) -> TV_func:
    @wraps(f)
    def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
        args = get_callee_args(wrapped_args)[1]
        if not isinstance(args, list):
            mlog.debug('Not a list:', str(args))
            raise InvalidArguments('Argument not a list.')
        if not all(isinstance(s, str) for s in args):
            mlog.debug('Element not a string:', str(args))
            raise InvalidArguments('Arguments must be strings.')
        return f(*wrapped_args, **wrapped_kwargs)
    return T.cast('TV_func', wrapped)

def noArgsFlattening(f: TV_func) -> TV_func:
    setattr(f, 'no-args-flattening', True)  # noqa: B010
    return f

def noSecondLevelHolderResolving(f: TV_func) -> TV_func:
    setattr(f, 'no-second-level-holder-flattening', True)  # noqa: B010
    return f

def unholder_return(f: TV_func) -> T.Callable[..., TYPE_var]:
    @wraps(f)
    def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
        res = f(*wrapped_args, **wrapped_kwargs)
        return _unholder(res)
    return T.cast('T.Callable[..., TYPE_var]', wrapped)

def disablerIfNotFound(f: TV_func) -> TV_func:
    @wraps(f)
    def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
        kwargs = get_callee_args(wrapped_args)[2]
        disabler = kwargs.pop('disabler', False)
        ret = f(*wrapped_args, **wrapped_kwargs)
        if disabler and not ret.found():
            return Disabler()
        return ret
    return T.cast('TV_func', wrapped)

@dataclass(repr=False, eq=False)
class permittedKwargs:
    permitted: T.Set[str]

    def __call__(self, f: TV_func) -> TV_func:
        @wraps(f)
        def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
            kwargs = get_callee_args(wrapped_args)[2]
            unknowns = set(kwargs).difference(self.permitted)
            if unknowns:
                ustr = ', '.join([f'"{u}"' for u in sorted(unknowns)])
                raise InvalidArguments(f'Got unknown keyword arguments {ustr}')
            return f(*wrapped_args, **wrapped_kwargs)
        return T.cast('TV_func', wrapped)

def typed_operator(operator: MesonOperator,
                   types: T.Union[T.Type, T.Tuple[T.Type, ...]]) -> T.Callable[['_TV_FN_Operator'], '_TV_FN_Operator']:
    """Decorator that does type checking for operator calls.

    The principle here is similar to typed_pos_args, however much simpler
    since only one other object ever is passed
    """
    def inner(f: '_TV_FN_Operator') -> '_TV_FN_Operator':
        @wraps(f)
        def wrapper(self: 'InterpreterObject', other: TYPE_var) -> TYPE_var:
            if not isinstance(other, types):
                raise InvalidArguments(f'The `{operator.value}` of {self.display_name()} does not accept objects of type {type(other).__name__} ({other})')
            return f(self, other)
        return T.cast('_TV_FN_Operator', wrapper)
    return inner


def typed_pos_args(name: str, *types: T.Union[T.Type, T.Tuple[T.Type, ...]],
                   varargs: T.Optional[T.Union[T.Type, T.Tuple[T.Type, ...]]] = None,
                   optargs: T.Optional[T.List[T.Union[T.Type, T.Tuple[T.Type, ...]]]] = None,
                   min_varargs: int = 0, max_varargs: int = 0) -> T.Callable[..., T.Any]:
    """Decorator that types type checking of positional arguments.

    This supports two different models of optional arguments, the first is the
    variadic argument model. Variadic arguments are a possibly bounded,
    possibly unbounded number of arguments of the same type (unions are
    supported). The second is the standard default value model, in this case
    a number of optional arguments may be provided, but they are still
    ordered, and they may have different types.

    This function does not support mixing variadic and default arguments.

    :name: The name of the decorated function (as displayed in error messages)
    :varargs: They type(s) of any variadic arguments the function takes. If
        None the function takes no variadic args
    :min_varargs: the minimum number of variadic arguments taken
    :max_varargs: the maximum number of variadic arguments taken. 0 means unlimited
    :optargs: The types of any optional arguments parameters taken. If None
        then no optional parameters are taken.

    Some examples of usage blow:
    >>> @typed_pos_args('mod.func', str, (str, int))
    ... def func(self, state: ModuleState, args: T.Tuple[str, T.Union[str, int]], kwargs: T.Dict[str, T.Any]) -> T.Any:
    ...     pass

    >>> @typed_pos_args('method', str, varargs=str)
    ... def method(self, node: BaseNode, args: T.Tuple[str, T.List[str]], kwargs: T.Dict[str, T.Any]) -> T.Any:
    ...     pass

    >>> @typed_pos_args('method', varargs=str, min_varargs=1)
    ... def method(self, node: BaseNode, args: T.Tuple[T.List[str]], kwargs: T.Dict[str, T.Any]) -> T.Any:
    ...     pass

    >>> @typed_pos_args('method', str, optargs=[(str, int), str])
    ... def method(self, node: BaseNode, args: T.Tuple[str, T.Optional[T.Union[str, int]], T.Optional[str]], kwargs: T.Dict[str, T.Any]) -> T.Any:
    ...     pass

    When should you chose `typed_pos_args('name', varargs=str,
    min_varargs=1)` vs `typed_pos_args('name', str, varargs=str)`?

    The answer has to do with the semantics of the function, if all of the
    inputs are the same type (such as with `files()`) then the former is
    correct, all of the arguments are string names of files. If the first
    argument is something else the it should be separated.
    """
    def inner(f: TV_func) -> TV_func:

        @wraps(f)
        def wrapper(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
            args = get_callee_args(wrapped_args)[1]

            # These are implementation programming errors, end users should never see them.
            assert isinstance(args, list), args
            assert max_varargs >= 0, 'max_varags cannot be negative'
            assert min_varargs >= 0, 'min_varags cannot be negative'
            assert optargs is None or varargs is None, \
                'varargs and optargs not supported together as this would be ambiguous'

            num_args = len(args)
            num_types = len(types)
            a_types = types

            if varargs:
                min_args = num_types + min_varargs
                max_args = num_types + max_varargs
                if max_varargs == 0 and num_args < min_args:
                    raise InvalidArguments(f'{name} takes at least {min_args} arguments, but got {num_args}.')
                elif max_varargs != 0 and (num_args < min_args or num_args > max_args):
                    raise InvalidArguments(f'{name} takes between {min_args} and {max_args} arguments, but got {num_args}.')
            elif optargs:
                if num_args < num_types:
                    raise InvalidArguments(f'{name} takes at least {num_types} arguments, but got {num_args}.')
                elif num_args > num_types + len(optargs):
                    raise InvalidArguments(f'{name} takes at most {num_types + len(optargs)} arguments, but got {num_args}.')
                # Add the number of positional arguments required
                if num_args > num_types:
                    diff = num_args - num_types
                    a_types = tuple(list(types) + list(optargs[:diff]))
            elif num_args != num_types:
                raise InvalidArguments(f'{name} takes exactly {num_types} arguments, but got {num_args}.')

            for i, (arg, type_) in enumerate(itertools.zip_longest(args, a_types, fillvalue=varargs), start=1):
                if not isinstance(arg, type_):
                    if isinstance(type_, tuple):
                        shouldbe = 'one of: {}'.format(", ".join(f'"{t.__name__}"' for t in type_))
                    else:
                        shouldbe = f'"{type_.__name__}"'
                    raise InvalidArguments(f'{name} argument {i} was of type "{type(arg).__name__}" but should have been {shouldbe}')

            # Ensure that we're actually passing a tuple.
            # Depending on what kind of function we're calling the length of
            # wrapped_args can vary.
            nargs = list(wrapped_args)
            i = nargs.index(args)
            if varargs:
                # if we have varargs we need to split them into a separate
                # tuple, as python's typing doesn't understand tuples with
                # fixed elements and variadic elements, only one or the other.
                # so in that case we need T.Tuple[int, str, float, T.Tuple[str, ...]]
                pos = args[:len(types)]
                var = list(args[len(types):])
                pos.append(var)
                nargs[i] = tuple(pos)
            elif optargs:
                if num_args < num_types + len(optargs):
                    diff = num_types + len(optargs) - num_args
                    nargs[i] = tuple(list(args) + [None] * diff)
                else:
                    nargs[i] = tuple(args)
            else:
                nargs[i] = tuple(args)
            return f(*nargs, **wrapped_kwargs)

        return T.cast('TV_func', wrapper)
    return inner


class ContainerTypeInfo:

    """Container information for keyword arguments.

    For keyword arguments that are containers (list or dict), this class encodes
    that information.

    :param container: the type of container
    :param contains: the types the container holds
    :param pairs: if the container is supposed to be of even length.
        This is mainly used for interfaces that predate the addition of dictionaries, and use
        `[key, value, key2, value2]` format.
    :param allow_empty: Whether this container is allowed to be empty
        There are some cases where containers not only must be passed, but must
        not be empty, and other cases where an empty container is allowed.
    """

    def __init__(self, container: T.Type, contains: T.Union[T.Type, T.Tuple[T.Type, ...]], *,
                 pairs: bool = False, allow_empty: bool = True):
        self.container = container
        self.contains = contains
        self.pairs = pairs
        self.allow_empty = allow_empty

    def check(self, value: T.Any) -> bool:
        """Check that a value is valid.

        :param value: A value to check
        :return: True if it is valid, False otherwise
        """
        if not isinstance(value, self.container):
            return False
        iter_ = iter(value.values()) if isinstance(value, dict) else iter(value)
        if any(not isinstance(i, self.contains) for i in iter_):
            return False
        if self.pairs and len(value) % 2 != 0:
            return False
        if not value and not self.allow_empty:
            return False
        return True

    def check_any(self, value: T.Any) -> bool:
        """Check a value should emit new/deprecated feature.

        :param value: A value to check
        :return: True if any of the items in value matches, False otherwise
        """
        if not isinstance(value, self.container):
            return False
        iter_ = iter(value.values()) if isinstance(value, dict) else iter(value)
        return any(isinstance(i, self.contains) for i in iter_)

    def description(self) -> str:
        """Human readable description of this container type.

        :return: string to be printed
        """
        container = 'dict' if self.container is dict else 'array'
        if isinstance(self.contains, tuple):
            contains = ' | '.join([t.__name__ for t in self.contains])
        else:
            contains = self.contains.__name__
        s = f'{container}[{contains}]'
        if self.pairs:
            s += ' that has even size'
        if not self.allow_empty:
            s += ' that cannot be empty'
        return s

_T = T.TypeVar('_T')

class _NULL_T:
    """Special null type for evolution, this is an implementation detail."""


_NULL = _NULL_T()

class KwargInfo(T.Generic[_T]):

    """A description of a keyword argument to a meson function

    This is used to describe a value to the :func:typed_kwargs function.

    :param name: the name of the parameter
    :param types: A type or tuple of types that are allowed, or a :class:ContainerType
    :param required: Whether this is a required keyword argument. defaults to False
    :param listify: If true, then the argument will be listified before being
        checked. This is useful for cases where the Meson DSL allows a scalar or
        a container, but internally we only want to work with containers
    :param default: A default value to use if this isn't set. defaults to None,
        this may be safely set to a mutable type, as long as that type does not
        itself contain mutable types, typed_kwargs will copy the default
    :param since: Meson version in which this argument has been added. defaults to None
    :param since_message: An extra message to pass to FeatureNew when since is triggered
    :param deprecated: Meson version in which this argument has been deprecated. defaults to None
    :param deprecated_message: An extra message to pass to FeatureDeprecated
        when since is triggered
    :param validator: A callable that does additional validation. This is mainly
        intended for cases where a string is expected, but only a few specific
        values are accepted. Must return None if the input is valid, or a
        message if the input is invalid
    :param convertor: A callable that converts the raw input value into a
        different type. This is intended for cases such as the meson DSL using a
        string, but the implementation using an Enum. This should not do
        validation, just conversion.
    :param deprecated_values: a dictionary mapping a value to the version of
        meson it was deprecated in. The Value may be any valid value for this
        argument.
    :param since_values: a dictionary mapping a value to the version of meson it was
        added in.
    :param not_set_warning: A warning message that is logged if the kwarg is not
        set by the user.
    """
    def __init__(self, name: str,
                 types: T.Union[T.Type[_T], T.Tuple[T.Union[T.Type[_T], ContainerTypeInfo], ...], ContainerTypeInfo],
                 *, required: bool = False, listify: bool = False,
                 default: T.Optional[_T] = None,
                 since: T.Optional[str] = None,
                 since_message: T.Optional[str] = None,
                 since_values: T.Optional[T.Dict[T.Union[_T, ContainerTypeInfo, type], T.Union[str, T.Tuple[str, str]]]] = None,
                 deprecated: T.Optional[str] = None,
                 deprecated_message: T.Optional[str] = None,
                 deprecated_values: T.Optional[T.Dict[T.Union[_T, ContainerTypeInfo, type], T.Union[str, T.Tuple[str, str]]]] = None,
                 validator: T.Optional[T.Callable[[T.Any], T.Optional[str]]] = None,
                 convertor: T.Optional[T.Callable[[_T], object]] = None,
                 not_set_warning: T.Optional[str] = None):
        self.name = name
        self.types = types
        self.required = required
        self.listify = listify
        self.default = default
        self.since = since
        self.since_message = since_message
        self.since_values = since_values
        self.deprecated = deprecated
        self.deprecated_message = deprecated_message
        self.deprecated_values = deprecated_values
        self.validator = validator
        self.convertor = convertor
        self.not_set_warning = not_set_warning

    def evolve(self, *,
               name: T.Union[str, _NULL_T] = _NULL,
               required: T.Union[bool, _NULL_T] = _NULL,
               listify: T.Union[bool, _NULL_T] = _NULL,
               default: T.Union[_T, None, _NULL_T] = _NULL,
               since: T.Union[str, None, _NULL_T] = _NULL,
               since_message: T.Union[str, None, _NULL_T] = _NULL,
               since_values: T.Union[T.Dict[T.Union[_T, ContainerTypeInfo, type], T.Union[str, T.Tuple[str, str]]], None, _NULL_T] = _NULL,
               deprecated: T.Union[str, None, _NULL_T] = _NULL,
               deprecated_message: T.Union[str, None, _NULL_T] = _NULL,
               deprecated_values: T.Union[T.Dict[T.Union[_T, ContainerTypeInfo, type], T.Union[str, T.Tuple[str, str]]], None, _NULL_T] = _NULL,
               validator: T.Union[T.Callable[[_T], T.Optional[str]], None, _NULL_T] = _NULL,
               convertor: T.Union[T.Callable[[_T], TYPE_var], None, _NULL_T] = _NULL) -> 'KwargInfo':
        """Create a shallow copy of this KwargInfo, with modifications.

        This allows us to create a new copy of a KwargInfo with modifications.
        This allows us to use a shared kwarg that implements complex logic, but
        has slight differences in usage, such as being added to different
        functions in different versions of Meson.

        The use the _NULL special value here allows us to pass None, which has
        meaning in many of these cases. _NULL itself is never stored, always
        being replaced by either the copy in self, or the provided new version.
        """
        return type(self)(
            name if not isinstance(name, _NULL_T) else self.name,
            self.types,
            listify=listify if not isinstance(listify, _NULL_T) else self.listify,
            required=required if not isinstance(required, _NULL_T) else self.required,
            default=default if not isinstance(default, _NULL_T) else self.default,
            since=since if not isinstance(since, _NULL_T) else self.since,
            since_message=since_message if not isinstance(since_message, _NULL_T) else self.since_message,
            since_values=since_values if not isinstance(since_values, _NULL_T) else self.since_values,
            deprecated=deprecated if not isinstance(deprecated, _NULL_T) else self.deprecated,
            deprecated_message=deprecated_message if not isinstance(deprecated_message, _NULL_T) else self.deprecated_message,
            deprecated_values=deprecated_values if not isinstance(deprecated_values, _NULL_T) else self.deprecated_values,
            validator=validator if not isinstance(validator, _NULL_T) else self.validator,
            convertor=convertor if not isinstance(convertor, _NULL_T) else self.convertor,
        )


def typed_kwargs(name: str, *types: KwargInfo, allow_unknown: bool = False) -> T.Callable[..., T.Any]:
    """Decorator for type checking keyword arguments.

    Used to wrap a meson DSL implementation function, where it checks various
    things about keyword arguments, including the type, and various other
    information. For non-required values it sets the value to a default, which
    means the value will always be provided.

    If type is a :class:ContainerTypeInfo, then the default value will be
    passed as an argument to the container initializer, making a shallow copy

    :param name: the name of the function, including the object it's attached to
        (if applicable)
    :param *types: KwargInfo entries for each keyword argument.
    """
    def inner(f: TV_func) -> TV_func:

        def types_description(types_tuple: T.Tuple[T.Union[T.Type, ContainerTypeInfo], ...]) -> str:
            candidates = []
            for t in types_tuple:
                if isinstance(t, ContainerTypeInfo):
                    candidates.append(t.description())
                else:
                    candidates.append(t.__name__)
            shouldbe = 'one of: ' if len(candidates) > 1 else ''
            shouldbe += ', '.join(candidates)
            return shouldbe

        def raw_description(t: object) -> str:
            """describe a raw type (ie, one that is not a ContainerTypeInfo)."""
            if isinstance(t, list):
                if t:
                    return f"array[{' | '.join(sorted(mesonlib.OrderedSet(type(v).__name__ for v in t)))}]"
                return 'array[]'
            elif isinstance(t, dict):
                if t:
                    return f"dict[{' | '.join(sorted(mesonlib.OrderedSet(type(v).__name__ for v in t.values())))}]"
                return 'dict[]'
            return type(t).__name__

        def check_value_type(types_tuple: T.Tuple[T.Union[T.Type, ContainerTypeInfo], ...],
                             value: T.Any) -> bool:
            for t in types_tuple:
                if isinstance(t, ContainerTypeInfo):
                    if t.check(value):
                        return True
                elif isinstance(value, t):
                    return True
            return False

        @wraps(f)
        def wrapper(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:

            def emit_feature_change(values: T.Dict[_T, T.Union[str, T.Tuple[str, str]]], feature: T.Union[T.Type['FeatureDeprecated'], T.Type['FeatureNew']]) -> None:
                for n, version in values.items():
                    if isinstance(version, tuple):
                        version, msg = version
                    else:
                        msg = None

                    warning: T.Optional[str] = None
                    if isinstance(n, ContainerTypeInfo):
                        if n.check_any(value):
                            warning = f'of type {n.description()}'
                    elif isinstance(n, type):
                        if isinstance(value, n):
                            warning = f'of type {n.__name__}'
                    elif isinstance(value, list):
                        if n in value:
                            warning = f'value "{n}" in list'
                    elif isinstance(value, dict):
                        if n in value.keys():
                            warning = f'value "{n}" in dict keys'
                    elif n == value:
                        warning = f'value "{n}"'
                    if warning:
                        feature.single_use(f'"{name}" keyword argument "{info.name}" {warning}', version, subproject, msg, location=node)

            node, _, _kwargs, subproject = get_callee_args(wrapped_args)
            # Cast here, as the convertor function may place something other than a TYPE_var in the kwargs
            kwargs = T.cast('T.Dict[str, object]', _kwargs)

            if not allow_unknown:
                all_names = {t.name for t in types}
                unknowns = set(kwargs).difference(all_names)
                if unknowns:
                    ustr = ', '.join([f'"{u}"' for u in sorted(unknowns)])
                    raise InvalidArguments(f'{name} got unknown keyword arguments {ustr}')

            for info in types:
                types_tuple = info.types if isinstance(info.types, tuple) else (info.types,)
                value = kwargs.get(info.name)
                if value is not None:
                    if info.since:
                        feature_name = info.name + ' arg in ' + name
                        FeatureNew.single_use(feature_name, info.since, subproject, info.since_message, location=node)
                    if info.deprecated:
                        feature_name = info.name + ' arg in ' + name
                        FeatureDeprecated.single_use(feature_name, info.deprecated, subproject, info.deprecated_message, location=node)
                    if info.listify:
                        kwargs[info.name] = value = mesonlib.listify(value)
                    if not check_value_type(types_tuple, value):
                        shouldbe = types_description(types_tuple)
                        raise InvalidArguments(f'{name} keyword argument {info.name!r} was of type {raw_description(value)} but should have been {shouldbe}')

                    if info.validator is not None:
                        msg = info.validator(value)
                        if msg is not None:
                            raise InvalidArguments(f'{name} keyword argument "{info.name}" {msg}')

                    if info.deprecated_values is not None:
                        emit_feature_change(info.deprecated_values, FeatureDeprecated)

                    if info.since_values is not None:
                        emit_feature_change(info.since_values, FeatureNew)

                elif info.required:
                    raise InvalidArguments(f'{name} is missing required keyword argument "{info.name}"')
                else:
                    # set the value to the default, this ensuring all kwargs are present
                    # This both simplifies the typing checking and the usage
                    assert check_value_type(types_tuple, info.default), f'In function {name} default value of {info.name} is not a valid type, got {type(info.default)} expected {types_description(types_tuple)}'
                    # Create a shallow copy of the container. This allows mutable
                    # types to be used safely as default values
                    kwargs[info.name] = copy.copy(info.default)
                    if info.not_set_warning:
                        mlog.warning(info.not_set_warning)

                if info.convertor:
                    kwargs[info.name] = info.convertor(kwargs[info.name])

            return f(*wrapped_args, **wrapped_kwargs)
        return T.cast('TV_func', wrapper)
    return inner


# This cannot be a dataclass due to https://github.com/python/mypy/issues/5374
class FeatureCheckBase(metaclass=abc.ABCMeta):
    "Base class for feature version checks"

    feature_registry: T.ClassVar[T.Dict[str, T.Dict[str, T.Set[T.Tuple[str, T.Optional['mparser.BaseNode']]]]]]
    emit_notice = False
    unconditional = False

    def __init__(self, feature_name: str, feature_version: str, extra_message: str = ''):
        self.feature_name = feature_name
        self.feature_version = feature_version
        self.extra_message = extra_message

    @staticmethod
    def get_target_version(subproject: str) -> str:
        # Don't do any checks if project() has not been parsed yet
        if subproject not in mesonlib.project_meson_versions:
            return ''
        return mesonlib.project_meson_versions[subproject]

    @staticmethod
    @abc.abstractmethod
    def check_version(target_version: str, feature_version: str) -> bool:
        pass

    def use(self, subproject: 'SubProject', location: T.Optional['mparser.BaseNode'] = None) -> None:
        tv = self.get_target_version(subproject)
        # No target version
        if tv == '' and not self.unconditional:
            return
        # Target version is new enough, don't warn
        if self.check_version(tv, self.feature_version) and not self.emit_notice:
            return
        # Feature is too new for target version or we want to emit notices, register it
        if subproject not in self.feature_registry:
            self.feature_registry[subproject] = {self.feature_version: set()}
        register = self.feature_registry[subproject]
        if self.feature_version not in register:
            register[self.feature_version] = set()

        feature_key = (self.feature_name, location)
        if feature_key in register[self.feature_version]:
            # Don't warn about the same feature multiple times
            # FIXME: This is needed to prevent duplicate warnings, but also
            # means we won't warn about a feature used in multiple places.
            return
        register[self.feature_version].add(feature_key)
        # Target version is new enough, don't warn even if it is registered for notice
        if self.check_version(tv, self.feature_version):
            return
        self.log_usage_warning(tv, location)

    @classmethod
    def report(cls, subproject: str) -> None:
        if subproject not in cls.feature_registry:
            return
        warning_str = cls.get_warning_str_prefix(cls.get_target_version(subproject))
        notice_str = cls.get_notice_str_prefix(cls.get_target_version(subproject))
        fv = cls.feature_registry[subproject]
        tv = cls.get_target_version(subproject)
        for version in sorted(fv.keys()):
            message = ', '.join(sorted({f"'{i[0]}'" for i in fv[version]}))
            if cls.check_version(tv, version):
                notice_str += '\n * {}: {{{}}}'.format(version, message)
            else:
                warning_str += '\n * {}: {{{}}}'.format(version, message)
        if '\n' in notice_str:
            mlog.notice(notice_str, fatal=False)
        if '\n' in warning_str:
            mlog.warning(warning_str)

    def log_usage_warning(self, tv: str, location: T.Optional['mparser.BaseNode']) -> None:
        raise InterpreterException('log_usage_warning not implemented')

    @staticmethod
    def get_warning_str_prefix(tv: str) -> str:
        raise InterpreterException('get_warning_str_prefix not implemented')

    @staticmethod
    def get_notice_str_prefix(tv: str) -> str:
        raise InterpreterException('get_notice_str_prefix not implemented')

    def __call__(self, f: TV_func) -> TV_func:
        @wraps(f)
        def wrapped(*wrapped_args: T.Any, **wrapped_kwargs: T.Any) -> T.Any:
            node, _, _, subproject = get_callee_args(wrapped_args)
            if subproject is None:
                raise AssertionError(f'{wrapped_args!r}')
            self.use(subproject, node)
            return f(*wrapped_args, **wrapped_kwargs)
        return T.cast('TV_func', wrapped)

    @classmethod
    def single_use(cls, feature_name: str, version: str, subproject: 'SubProject',
                   extra_message: str = '', location: T.Optional['mparser.BaseNode'] = None) -> None:
        """Oneline version that instantiates and calls use()."""
        cls(feature_name, version, extra_message).use(subproject, location)


class FeatureNew(FeatureCheckBase):
    """Checks for new features"""

    # Class variable, shared across all instances
    #
    # Format: {subproject: {feature_version: set(feature_names)}}
    feature_registry = {}

    @staticmethod
    def check_version(target_version: str, feature_version: str) -> bool:
        return mesonlib.version_compare_condition_with_min(target_version, feature_version)

    @staticmethod
    def get_warning_str_prefix(tv: str) -> str:
        retur
```