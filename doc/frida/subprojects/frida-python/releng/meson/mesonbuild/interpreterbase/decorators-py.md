Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding of the Context:**

The first sentence is crucial: "这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件". This immediately tells us:

* **Frida:** This is about the Frida dynamic instrumentation toolkit.
* **Python:** The code is in Python.
* **Meson:** The code is part of the Meson build system.
* **Decorators:** The filename and the presence of `@` syntax strongly suggest this file defines decorators.
* **`interpreterbase`:** This suggests the decorators are used within the context of interpreting some kind of build definition language or configuration.

**2. Identifying the Core Functionality - Decorators:**

The next step is to recognize the core purpose of decorators in Python. Decorators are a way to modify or enhance the behavior of functions or methods without directly changing their code. They "wrap" the function.

**3. Analyzing Individual Decorators:**

Now, let's go through each decorator definition and understand its specific function:

* **`get_callee_args`:**  This helper function seems to extract arguments related to the build process (node, subproject, args, kwargs) from the arguments passed to the decorated function. The comment about `ModuleObject` is a key detail.

* **`noPosargs`:** This decorator checks if the decorated function is called with positional arguments. If so, it raises an `InvalidArguments` exception.

* **`noKwargs`:**  Similar to `noPosargs`, but checks for keyword arguments.

* **`stringArgs`:** This decorator validates that all positional arguments passed to the decorated function are strings.

* **`noArgsFlattening`:**  This sets an attribute on the decorated function. This likely signals to other parts of the Meson system *not* to perform some kind of argument flattening.

* **`noSecondLevelHolderResolving`:**  Similar to `noArgsFlattening`, this likely prevents another type of argument resolution.

* **`unholder_return`:** This decorator calls the decorated function and then applies a function called `_unholder` to the result. This suggests some form of "holding" or wrapping of values that needs to be unwrapped.

* **`disablerIfNotFound`:** This decorator checks if a `disabler` keyword argument is passed and if the decorated function's return value has a `found()` method that returns `False`. If both are true, it returns a `Disabler` object.

* **`permittedKwargs`:** This decorator enforces that only a specific set of keyword arguments are allowed when calling the decorated function.

* **`typed_operator`:** This decorator performs type checking on the second argument (`other`) of an operator method. It ensures it matches the specified `types`.

* **`typed_pos_args`:** This is a more complex decorator for enforcing type checking on positional arguments. It handles fixed arguments, variadic arguments, and optional arguments. The detailed docstring provides examples and explains the different ways to use it.

* **`typed_kwargs`:** This is the most complex decorator. It's designed for rigorous type checking of keyword arguments based on the `KwargInfo` class. It handles required arguments, default values, type conversions, deprecation warnings, and more.

* **`FeatureCheckBase`, `FeatureNew`, `FeatureDeprecated`:** These classes and decorators are related to tracking and reporting the usage of new and deprecated features based on the target Meson version. They are used to provide warnings to users who are using features that are too new for their specified Meson version.

**4. Connecting to Reverse Engineering, Binaries, Kernels, etc.:**

Now, let's think about how these decorators might relate to the prompt's other points:

* **Reverse Engineering:** Frida is a reverse engineering tool. These decorators are part of the Python bindings for Frida's build system. The decorators enforce structure and type safety in the Python API, making it easier to build and maintain. When *using* Frida, developers interact with the Python API, and these decorators help ensure they're using it correctly.

* **Binary/Low-Level:** While the *decorators themselves* don't directly manipulate binaries, the *functions they decorate* likely do. Meson is used to build Frida, which *does* interact with binaries and low-level system components. The type checking enforced by these decorators helps prevent errors that could lead to problems when building or using Frida's core functionality.

* **Linux/Android Kernels/Frameworks:** Similarly, Frida is used to instrument processes on Linux and Android, often interacting with kernel-level APIs and framework components. The build process needs to be robust, and these decorators contribute to that robustness.

**5. Logical Reasoning and Examples:**

For each decorator, consider:

* **Input:**  What kind of function would this decorator be applied to? What arguments might be passed?
* **Output:** What is the effect of the decorator?  Does it modify the function's behavior, raise an error, or return a different value?

Example for `noPosargs`:

* **Input:** A function decorated with `@noPosargs` called like `my_func(1, "hello")`.
* **Output:** An `InvalidArguments` exception because positional arguments are not allowed.

Example for `stringArgs`:

* **Input:** A function decorated with `@stringArgs` called like `my_func("a", "b")`.
* **Output:** The original function is called.
* **Input:** Same function called like `my_func("a", 1)`.
* **Output:** An `InvalidArguments` exception.

**6. User Errors and Debugging:**

Think about common mistakes developers might make when using the Frida Python API (which is built using Meson). For example:

* Passing a number when a string is expected (`stringArgs`).
* Providing extra keyword arguments (`permittedKwargs`, `typed_kwargs`).
* Not providing required keyword arguments (`typed_kwargs`).
* Using features that are too new for their Meson version (`FeatureNew`, `FeatureDeprecated`).

The traceback would lead them to the Meson code, and understanding these decorators helps them diagnose the issue.

**7. Step-by-Step User Interaction:**

Imagine a developer:

1. Starts writing a Frida script in Python.
2. Uses a function from the Frida Python API.
3. Makes a mistake in how they call the function (e.g., wrong argument type).
4. Runs their script.
5. The Python interpreter encounters an exception raised by one of these decorators within the Frida Python bindings.
6. The traceback points to the line where the incorrect function call occurred and potentially into the Meson/Frida Python binding code.

**8. Summarization:**

Finally, synthesize the individual functionalities into a concise summary, highlighting the main goals: argument validation, type safety, feature tracking, and improving the robustness of the Frida Python bindings built with Meson.
这是Frida动态Instrumentation工具中，`frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件的源代码，它定义了一系列**装饰器 (decorators)**，用于增强和规范 Meson 构建系统中解释器 (interpreter)  中函数的行为。

以下是该文件的功能归纳：

**核心功能：**

1. **参数校验与类型检查：**  大部分装饰器的核心功能是验证被装饰函数的参数，包括：
   - 限制是否允许位置参数或关键字参数 (`noPosargs`, `noKwargs`)。
   - 强制位置参数必须为字符串 (`stringArgs`)。
   - 强制关键字参数必须是预定义的类型 (`typed_kwargs`)，并支持复杂的类型定义，包括容器类型 (列表、字典)。
   - 强制运算符方法的第二个参数为特定类型 (`typed_operator`)。
   - 细致地检查位置参数的类型、数量（固定、可选、可变） (`typed_pos_args`)。
   - 允许的关键字参数列表 (`permittedKwargs`)。

2. **参数处理与转换：**
   - 自动“解包”返回值 (`unholder_return`)，可能用于处理某些包装过的对象。
   - 允许在类型检查后对关键字参数进行转换 (`typed_kwargs` 中的 `convertor`)。
   - 自动将标量值转换为列表 (`typed_kwargs` 中的 `listify`)。

3. **功能特性控制与警告：**
   - 标记函数不进行参数扁平化 (`noArgsFlattening`) 或二级 Holder 解析 (`noSecondLevelHolderResolving`)，这可能与 Meson 内部的参数处理机制有关。
   - 在找不到特定资源时返回 `Disabler` 对象 (`disablerIfNotFound`)，用于构建过程中的条件禁用。
   - 追踪和报告新引入的功能 (`FeatureNew`) 和已弃用的功能 (`FeatureDeprecated`) 的使用，并根据目标 Meson 版本发出警告或通知。

**与逆向方法的关系及举例说明：**

虽然这个文件本身不直接进行逆向操作，但它是 Frida 工具链的一部分，用于构建 Frida 的 Python 绑定。这些装饰器确保了 Frida Python API 的稳定性和易用性，间接支持了逆向工作。

**举例：**

假设 Frida Python API 中有一个函数 `attach(target, **options)`，用于附加到目标进程。  `options` 可能包括 `spawn` (布尔值，是否在附加前启动目标) 和 `realm` (字符串，用于指定附加的命名空间)。

```python
@typed_kwargs('frida.attach',
              KwargInfo('spawn', bool, default=False),
              KwargInfo('realm', str, default='native'))
def attach(target, **options):
    # ... Frida 内部逻辑 ...
    pass
```

- `@typed_kwargs` 装饰器确保了调用 `frida.attach` 时，`options` 中只允许 `spawn` 和 `realm` 这两个关键字参数。
- 它还会检查 `spawn` 是否是布尔类型，`realm` 是否是字符串。
- 如果用户调用 `frida.attach("com.example", spawns=True)`，`typed_kwargs` 会捕获到 `spawns` 是未知的关键字参数，并抛出 `InvalidArguments` 异常，帮助用户尽早发现错误。
- 如果用户调用 `frida.attach("com.example", spawn="yes")`，`typed_kwargs` 会检测到 `spawn` 的类型错误，并抛出异常。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明：**

这些装饰器本身是高层次的 Python 代码，但它们服务于构建一个与底层系统交互的工具。

**举例：**

- Frida 需要与目标进程的内存空间交互，这涉及**二进制底层**的知识，例如内存地址、指令结构等。虽然装饰器不直接处理这些，但它们确保了传递给 Frida 核心功能的参数（例如内存地址、大小）是正确的类型，避免了底层操作中的错误。
- Frida 可以在 **Linux 和 Android** 平台上运行，并与操作系统内核进行交互，例如通过 `ptrace` 或 `/proc` 文件系统进行进程操作。装饰器通过类型检查，可以确保传递给涉及平台特定操作的 API 的参数是符合预期的，例如进程 ID (通常是整数)。
- 在 Android 平台上，Frida 还可以 hook Java 层的函数，这涉及到 **Android 框架**的知识，例如 ART 虚拟机、ClassLoader 等。装饰器可以用于验证传递给 hook 相关 API 的参数，例如类名和方法名（通常是字符串）。

**逻辑推理、假设输入与输出：**

**假设输入：** 一个被 `@noPosargs` 装饰的函数 `my_function`。

```python
@noPosargs
def my_function(*, kwarg1, kwarg2):
    return kwarg1 + kwarg2
```

**假设输入调用 1：** `my_function(10, 20, kwarg1=5, kwarg2=10)`

**逻辑推理：** `@noPosargs` 装饰器会检查 `get_callee_args` 返回的位置参数列表是否为空。在这个例子中，位置参数是 `(10, 20)`，不为空。

**输出：** 抛出 `InvalidArguments('Function does not take positional arguments.')` 异常。

**假设输入调用 2：** `my_function(kwarg1=5, kwarg2=10)`

**逻辑推理：** `@noPosargs` 装饰器会检查位置参数列表是否为空。在这个例子中，没有位置参数。

**输出：** 函数 `my_function` 正常执行，返回 `15`。

**涉及用户或编程常见的使用错误及举例说明：**

1. **传递了错误的参数类型：**

   ```python
   @stringArgs
   def process_strings(*args):
       for s in args:
           print(s.upper())

   process_strings("hello", 123)  # 错误：123 不是字符串
   ```
   `stringArgs` 装饰器会检查到 `123` 不是字符串，抛出 `InvalidArguments('Arguments must be strings.')`。

2. **使用了不允许的关键字参数：**

   ```python
   @permittedKwargs({'name', 'age'})
   def create_user(name, age):
       print(f"User: {name}, Age: {age}")

   create_user(name="Alice", age=30, city="New York") # 错误：city 是不允许的关键字参数
   ```
   `permittedKwargs` 装饰器会检查到 `city` 不在允许的关键字参数集合中，抛出 `InvalidArguments('Got unknown keyword arguments "city"')`。

3. **忘记传递必需的关键字参数：**

   ```python
   @typed_kwargs('my_api_call', KwargInfo('url', str, required=True))
   def my_api_call(url):
       print(f"Calling API at {url}")

   my_api_call() # 错误：缺少必需的关键字参数 url
   ```
   `typed_kwargs` 装饰器会检查到缺少 `url` 这个必需的关键字参数，抛出 `InvalidArguments('my_api_call is missing required keyword argument "url"')`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Meson 构建文件 `meson.build`:**  用户在他们的项目中编写 `meson.build` 文件，定义了如何构建 Frida 的 Python 绑定。
2. **用户运行 `meson` 命令:** 用户执行 `meson` 命令来配置构建过程。Meson 会解析 `meson.build` 文件。
3. **Meson 解析器执行:** Meson 的解释器 (interpreter) 会执行 `meson.build` 文件中的代码。
4. **调用被装饰的函数:** 在执行过程中，可能会调用到一些被这些装饰器装饰的函数，例如处理编译选项、依赖项等。
5. **参数验证失败:** 如果用户在 `meson.build` 文件中传递了不符合要求的参数（例如类型错误、使用了不允许的关键字参数），装饰器会捕获到这些错误。
6. **抛出异常:** 相应的装饰器会抛出 `InterpreterException` 或 `InvalidArguments` 异常。
7. **显示回溯信息:** Meson 会显示包含错误信息和调用堆栈的回溯信息，其中会包含 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件以及发生错误的具体行号，作为调试线索，帮助用户定位 `meson.build` 文件中的错误配置。

**第 1 部分功能归纳：**

这个文件的主要功能是定义了一组 Python 装饰器，用于增强 Meson 构建系统中解释器函数的健壮性和可靠性。这些装饰器专注于**参数校验、类型检查、参数处理和功能特性控制**，旨在防止因参数错误或使用了不兼容的功能而导致的构建失败，并提供清晰的错误信息帮助开发者进行调试。它们是 Frida Python 绑定构建过程中的重要组成部分，虽然不直接参与逆向操作，但确保了构建出的 Frida Python API 的质量。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
"""


```