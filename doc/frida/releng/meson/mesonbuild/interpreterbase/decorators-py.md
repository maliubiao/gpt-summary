Response:
Let's break down the thought process for analyzing this Python code. The request asks for a comprehensive understanding of the file `decorators.py` within the Frida project. Here's a potential step-by-step approach:

1. **Understand the Context:** The prompt explicitly states this is part of the Frida dynamic instrumentation tool and the file path `frida/releng/meson/mesonbuild/interpreterbase/decorators.py`. This tells us the code is likely related to how Frida's internal build system (using Meson) defines and manages function behaviors and argument handling within its Python interpreter.

2. **Initial Code Scan:**  Read through the code, looking for keywords, class names, and function names that give clues about its purpose. Notice terms like `decorators`, `noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, `typed_kwargs`, `FeatureNew`, `FeatureDeprecated`. These immediately suggest the file deals with modifying the behavior of functions, particularly around argument parsing and versioning.

3. **Identify Key Functional Areas:** Group related functions and classes. Based on the initial scan, we can identify these areas:
    * **Argument Validation Decorators:** `noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, `typed_kwargs`, `permittedKwargs`. These seem to enforce constraints on function arguments.
    * **Return Value Modification:** `unholder_return`. This suggests manipulating the return value of a function.
    * **Conditional Disabling:** `disablerIfNotFound`. This indicates a mechanism for conditionally disabling functionality.
    * **Internal Behavior Modifiers:** `noArgsFlattening`, `noSecondLevelHolderResolving`. These likely control internal processing steps.
    * **Operator Type Checking:** `typed_operator`. This is specifically for type checking within operator overloading.
    * **Feature Versioning:** `FeatureNew`, `FeatureDeprecated`, `FeatureCheckBase`. These are clearly designed to manage the introduction and deprecation of features across Frida versions.
    * **Helper Functions:** `get_callee_args`. This assists other decorators.
    * **Data Structures:** `KwargInfo`, `ContainerTypeInfo`. These are used to define the structure and constraints of keyword arguments.

4. **Analyze Each Functional Area in Detail:**

    * **Argument Validation:** For each decorator (`noPosargs`, etc.), figure out *what* it's validating and *how* it's doing it. Notice the use of `get_callee_args` to access the arguments, and the raising of `InvalidArguments`. Pay attention to specific checks like `isinstance(args, list)` and `all(isinstance(s, str) for s in args)`.

    * **Return Value:**  `unholder_return` is straightforward - it uses `_unholder`. Note that this likely interacts with Frida's internal representation of values.

    * **Conditional Disabling:**  `disablerIfNotFound` checks for a `disabler` keyword and returns a `Disabler` object if the wrapped function's result indicates it wasn't "found."

    * **Internal Behavior:**  `noArgsFlattening` and `noSecondLevelHolderResolving` set attributes on the decorated function. Recognize this as a way for other parts of the system to inspect and modify the function's execution. The names hint at internal data structures or processing steps.

    * **Operator Type Checking:**  `typed_operator` is similar to `typed_pos_args` but specialized for operators. Focus on how it checks the type of the `other` operand.

    * **Argument Typing (`typed_pos_args`, `typed_kwargs`):**  These are the most complex. Carefully examine how they use `isinstance`, how they handle `varargs` and `optargs`, and the logic for building error messages. For `typed_kwargs`, understand the role of `KwargInfo` in defining argument properties and the logic for handling defaults, required arguments, and versioning.

    * **Feature Versioning:**  Study the structure of `FeatureCheckBase`, `FeatureNew`, and `FeatureDeprecated`. Understand the `feature_registry`, the `check_version` methods, and the `use` and `report` methods. Recognize the purpose of tracking feature usage and generating warnings or notices.

5. **Connect to Reverse Engineering, Binary, Kernel, etc.:** Now, with a solid understanding of the code's function, consider how it relates to the concepts mentioned in the prompt.

    * **Reverse Engineering:**  Frida is a reverse engineering tool. These decorators help ensure the *internal* consistency and correctness of Frida's scripting interface and core logic. The argument validation, for example, prevents errors in user-provided scripts from crashing Frida.

    * **Binary/Underlying Layers:** While the decorators themselves are Python code, they are used in the *implementation* of Frida's functionality. Functions decorated with these might interact with Frida's core, which *does* interact with binary code, memory, etc. The `_unholder` function is a strong indicator of this abstraction.

    * **Linux/Android Kernel/Framework:**  Frida often operates at the user-space level, but its actions (instrumentation, hooking) directly affect processes and sometimes interact with kernel-level code. The decorators help manage the complexities of this interaction by ensuring functions are called correctly and that feature usage is tracked.

6. **Illustrative Examples:**  For each decorator, think of a simple example of how a user might misuse the decorated function and how the decorator would catch it. For versioning, imagine a scenario where a user tries to use a new feature on an older version.

7. **User Journey and Debugging:**  Imagine a user writing a Frida script and encountering an error. How might that error lead back to this `decorators.py` file? The error messages generated by these decorators are crucial debugging information.

8. **Summarize Functionality:**  Finally, condense your understanding into a concise summary of the file's overall purpose.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  You might initially misunderstand the purpose of a specific decorator. As you delve deeper and see how it's used, you'll refine your understanding. For example, you might initially think `noArgsFlattening` has something to do with argument *validation*, but closer inspection reveals it's about an internal processing step.
* **Looking for Patterns:** Notice the consistent use of `wraps`, the `get_callee_args` helper, and the raising of `InvalidArguments`. This reveals a consistent design pattern.
* **Checking Type Hints:** Pay close attention to the type hints (`T.Sequence`, `T.List`, `TYPE_var`, etc.). These provide valuable information about the expected types of arguments and return values.
* **Considering Edge Cases:** Think about what happens with no arguments, incorrect argument types, missing keyword arguments, etc. The decorators are designed to handle these situations gracefully.

By following these steps, and iteratively refining your understanding, you can arrive at a comprehensive analysis like the example provided in the prompt.
这是 Frida 动态插桩工具中 `frida/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件的源代码。这个文件主要定义了一系列的**装饰器 (decorators)**，用于增强和修改 Frida 中解释器 (interpreter) 中函数的行为。这些装饰器主要关注于**参数验证、返回值处理、功能版本控制**等方面，旨在提高代码的健壮性和可维护性。

以下是该文件的功能归纳和详细说明：

**核心功能归纳：**

该文件定义了一系列 Python 装饰器，用于增强 Frida 的 Meson 构建系统解释器中函数的行为，主要包括：

1. **参数约束和验证：**  强制函数不接受特定类型的参数（位置参数、关键字参数），或者要求参数必须是特定类型（例如字符串）。
2. **返回值处理：**  对函数的返回值进行处理，例如“解包”某些特定的包装对象。
3. **条件禁用：**  根据特定条件（例如找不到某些资源）禁用函数的功能。
4. **关键字参数控制：**  允许指定函数接受的关键字参数，并对类型进行检查。
5. **操作符类型检查：**  对重载的操作符（如加法、减法等）进行参数类型检查。
6. **功能版本控制：**  标记和报告新功能的使用，以及已弃用功能的使用，帮助开发者跟踪 Frida 的版本演变。

**功能详细说明及举例：**

1. **参数约束和验证：**

   * **`noPosargs(f)`:**  装饰器，用于标记函数 `f` 不接受任何位置参数。
     * **举例说明：** 如果 Frida 的一个内部函数，例如用于加载脚本的函数，设计上只接受关键字参数来指定脚本路径和相关配置，就可以使用此装饰器。如果用户尝试使用位置参数传递脚本路径，将会抛出 `InvalidArguments` 异常。
     * **逆向关系：**  在逆向工程中，了解目标函数的参数是至关重要的。此装饰器确保了 Frida 内部函数按照预期的参数方式被调用，防止因参数错误导致的内部错误。
     * **用户错误：** 用户尝试使用 `frida.create_script("my_script.js")` (位置参数) 调用一个被 `noPosargs` 装饰的内部函数，会报错。

   * **`noKwargs(f)`:** 装饰器，用于标记函数 `f` 不接受任何关键字参数。
     * **举例说明：**  Frida 内部可能存在一些非常底层的操作函数，其参数顺序和类型已经严格定义，不需要额外的配置选项，就可以使用此装饰器。
     * **用户错误：** 用户尝试使用 `internal_function(script_path="my_script.js")` (关键字参数) 调用一个被 `noKwargs` 装饰的内部函数，会报错。

   * **`stringArgs(f)`:** 装饰器，用于标记函数 `f` 的所有位置参数必须是字符串类型。
     * **举例说明：**  Frida 中处理文件路径、模块名称等参数的函数可能会使用此装饰器。
     * **逆向关系：**  确保传递给 Frida 内部处理二进制文件的函数的路径是字符串类型，避免因类型错误导致文件操作失败。
     * **用户错误：** 用户尝试使用 `process.inject(123)` (整数参数) 调用一个被 `stringArgs` 装饰的函数，会报错。

2. **返回值处理：**

   * **`unholder_return(f)`:** 装饰器，用于“解包”函数 `f` 的返回值。这可能涉及到 Frida 内部对象表示的转换。
     * **二进制底层/内核/框架知识：**  Frida 内部可能使用某种持有者 (holder) 对象来包装从底层或目标进程获取的数据。`_unholder` 函数可能负责将这些持有者对象转换为更易于 Python 代码使用的标准类型。
     * **逻辑推理 (假设输入与输出)：** 假设 Frida 内部一个函数从目标进程读取了一个字符串，并将其包装在一个 `StringHolder` 对象中。被 `unholder_return` 装饰后，该函数返回的将是 Python 的 `str` 类型，而不是 `StringHolder` 对象。
       * **假设输入 (被装饰函数返回值):**  `StringHolder(value="hello")`
       * **输出 (装饰器处理后的返回值):** `"hello"`

3. **条件禁用：**

   * **`disablerIfNotFound(f)`:** 装饰器，如果调用函数 `f` 后返回的对象 `ret` 的 `found()` 方法返回 `False`，则返回一个 `Disabler` 对象。
     * **举例说明：**  Frida 尝试查找目标进程中的一个特定模块或符号，如果找不到，该函数可能会返回一个表示“未找到”的对象。使用此装饰器，可以将返回值替换为一个 `Disabler` 对象，指示该功能被禁用。
     * **逆向关系：** 在脚本中，可以根据 `Disabler` 对象来判断某个功能是否可用，并采取相应的措施。
     * **逻辑推理 (假设输入与输出)：**
       * **假设输入 (被装饰函数返回值，`found()` 返回 `True`):** `ModuleObject(name="libc.so")`
       * **输出:** `ModuleObject(name="libc.so")`
       * **假设输入 (被装饰函数返回值，`found()` 返回 `False`):** `NotFoundObject()`
       * **输出:** `Disabler()`

4. **关键字参数控制：**

   * **`permittedKwargs(permitted: T.Set[str])`:** 装饰器工厂，用于指定函数允许的关键字参数集合。
     * **举例说明：**  Frida 的一个函数用于附加到进程，可能只接受 `pid` 或 `name` 作为关键字参数。可以使用 `@permittedKwargs({"pid", "name"})` 来装饰该函数。
     * **用户错误：** 用户尝试使用 `frida.attach(target="my_app")` (使用了不允许的关键字 `target`) 调用该函数，会报错。

   * **`typed_kwargs(name: str, *types: KwargInfo, allow_unknown: bool = False)`:**  功能更强大的关键字参数类型检查装饰器。它使用 `KwargInfo` 对象来详细描述每个关键字参数的名称、类型、是否必需、默认值等信息。
     * **举例说明：**  可以定义一个 `KwargInfo` 对象来指定一个名为 `timeout` 的关键字参数，其类型为 `int`，有默认值 `10` 秒。
     * **用户错误：** 用户尝试使用 `frida.rpc.exports.my_function(timeout="not_a_number")` (提供了错误类型的 `timeout`)，会报错。

5. **操作符类型检查：**

   * **`typed_operator(operator: MesonOperator, types: T.Union[T.Type, T.Tuple[T.Type, ...]])`:** 装饰器工厂，用于对重载的操作符进行参数类型检查。
     * **举例说明：**  Frida 的 `MemoryRange` 对象可能重载了加法操作符，用于合并内存区域。可以使用此装饰器来确保加法操作符的另一个操作数也是 `MemoryRange` 类型。
     * **二进制底层知识：** 确保对内存地址和范围进行操作时，操作数的类型是正确的，防止出现意料之外的内存访问错误。
     * **用户错误：**  假设 `range1` 是 `MemoryRange` 对象，用户尝试 `range1 + 10` (将内存范围与整数相加)，如果加法操作符使用了此装饰器，则会报错。

6. **功能版本控制：**

   * **`FeatureNew(feature_name: str, feature_version: str, extra_message: str = '')`:** 装饰器，用于标记一个函数或功能是在指定的 Frida 版本中新增的。当在较旧版本的 Frida 环境中使用该功能时，会发出警告或提示。
     * **举例说明：**  Frida 16.0 引入了一个新的 API 函数 `frida.experimental_api()`. 可以使用 `@FeatureNew("Experimental API", "16.0.0")` 来装饰该函数。
     * **用户错误：**  用户在一个 Frida 15.x 的环境中运行使用了 `frida.experimental_api()` 的脚本，会收到一个关于使用新功能的警告。

   * **`FeatureDeprecated(feature_name: str, feature_version: str, extra_message: str = '')`:** 装饰器，用于标记一个函数或功能在指定的 Frida 版本中被弃用。当在较新版本的 Frida 环境中使用该功能时，会发出警告或提示。
     * **举例说明：**  Frida 某个旧的 API 函数在 15.0 版本被弃用，可以使用 `@FeatureDeprecated("Old API", "15.0.0")` 来装饰它。

**用户操作到达此处的调试线索：**

作为一个普通的 Frida 用户，你通常不会直接与这些装饰器代码交互。但是，当你编写 Frida 脚本并运行时，如果你的脚本尝试调用 Frida 内部的函数，并且这些函数被这些装饰器装饰，那么：

1. **参数错误：** 如果你传递了错误类型或数量的参数，`noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, `typed_kwargs`, `permittedKwargs` 装饰器会捕获这些错误并抛出 `InvalidArguments` 异常。你会在 Frida 的错误输出中看到相关的错误消息，这些消息通常会指示参数错误发生在哪一个函数调用中。

2. **功能版本问题：** 如果你的脚本使用了较新版本的 Frida 才引入的 API，并且你在旧版本的 Frida 上运行，`FeatureNew` 装饰器会记录并报告这个情况。你会看到一个关于使用了新功能的警告消息。类似地，如果使用了已弃用的 API，`FeatureDeprecated` 会发出警告。

**总结：**

`frida/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件是 Frida 构建系统解释器中至关重要的组成部分。它通过定义一系列装饰器，实现了对函数参数、返回值和功能版本的严格控制和管理，提高了 Frida 代码的质量、可维护性和用户体验。虽然用户不会直接与此文件交互，但它在幕后默默地保障了 Frida 内部函数调用的正确性和版本兼容性。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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