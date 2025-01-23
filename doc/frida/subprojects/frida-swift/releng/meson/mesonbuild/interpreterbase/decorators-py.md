Response:
My thinking process to answer the request about `decorators.py` goes through these stages:

1. **Understanding the Context:** The request clearly states this is a source code file for Frida, a dynamic instrumentation tool, specifically within its Swift support components and Meson build system. This immediately tells me the file's purpose is likely related to enhancing the functionality and robustness of how Frida's Swift interaction is built. The "decorators" part strongly suggests this file is about using Python decorators to add extra behavior to functions.

2. **Initial Scan and Keyword Spotting:** I quickly scan the code, looking for familiar Python concepts and keywords. I see decorators like `@wraps`, `@dataclass`, and function definitions using the `@` syntax. I also see type hinting (`typing as T`), imports from within the Meson project, and exception handling (`InterpreterException`, `InvalidArguments`). Keywords like "arguments," "kwargs," "type checking," "version," and "feature" stand out as potentially important.

3. **Deconstructing the Functionality (Decorator by Decorator):**  I go through each defined decorator and its associated helper functions, trying to understand its purpose.

    * **`get_callee_args`:**  This looks like a utility to extract standard information (node, args, kwargs, subproject) from the arguments passed to a decorated function. The comment about `ModuleObject` is important – it hints at different call contexts.

    * **`noPosargs`, `noKwargs`, `stringArgs`:** These are straightforward argument validation decorators. They enforce constraints on whether positional or keyword arguments are allowed and whether arguments are strings.

    * **`noArgsFlattening`, `noSecondLevelHolderResolving`:** These seem specific to Meson's internal data structures ("holders"). I'd guess they control how arguments are processed or resolved.

    * **`unholder_return`:** This likely deals with transforming the return value of a function, possibly related to the "holder" concept mentioned before.

    * **`disablerIfNotFound`:** This decorator appears to handle a "disabler" keyword argument, potentially returning a special `Disabler` object if the decorated function doesn't find something and the disabler is active.

    * **`permittedKwargs`:** Another argument validation decorator, ensuring only a specific set of keyword arguments is passed.

    * **`typed_operator`:** This decorator focuses on type checking for overloaded operators, like `+` or `-`, within the Meson interpreter.

    * **`typed_pos_args`:** This is a more complex decorator for type-checking positional arguments, supporting both fixed and variable numbers of arguments, as well as optional arguments. The extensive docstring provides valuable clues.

    * **`ContainerTypeInfo`:** This class defines how to represent and validate container types (lists and dictionaries) used as keyword arguments.

    * **`KwargInfo`:** This dataclass holds metadata about keyword arguments, including type information, whether they are required, default values, versioning information (since/deprecated), and validators/converters. The `evolve` method is interesting, suggesting a way to modify keyword argument definitions.

    * **`typed_kwargs`:**  This is the main decorator for type-checking keyword arguments. It uses `KwargInfo` objects to enforce type constraints, handle default values, and manage versioning (feature flags).

    * **`FeatureCheckBase`, `FeatureNew`, `FeatureDeprecated`:** These classes form a system for managing feature availability based on the Meson version. They allow functions to be marked as requiring a certain Meson version or as being deprecated in a particular version. The registration and reporting mechanism is important.

4. **Connecting to Reverse Engineering, Binary, Kernel, and Framework Concepts:**  With a good understanding of the individual decorators, I now consider how they relate to the broader context of Frida and reverse engineering.

    * **Reverse Engineering:**  The decorators that enforce argument types and constraints are crucial for the stability and predictability of Frida's scripting interface. Incorrect arguments could lead to crashes or unexpected behavior when interacting with target processes. The versioning system helps manage API changes over time.

    * **Binary/Low-Level:** While the Python code itself isn't directly manipulating binary data, it's setting up the *framework* for Frida to do so. The type checking ensures that when a user provides information like memory addresses or function names (often represented as strings), they are in the expected format.

    * **Linux/Android Kernel & Framework:** Frida often interacts with the operating system's kernel and frameworks (like Android's ART). The type checking helps ensure that when Frida's scripting interface exposes functionality related to these components, the user provides valid input. For example, a function to hook a system call might require an integer representing the syscall number.

5. **Logical Reasoning, Assumptions, and Examples:** I start thinking about how these decorators would be used. I imagine scenarios where a Frida script calls a function with incorrect arguments, and how these decorators would catch the error. I consider how the versioning system would prevent a script written for an older Frida version from breaking in a newer version due to API changes.

6. **User Errors and Debugging:** I consider common mistakes a user might make when using Frida's scripting interface and how these decorators would provide helpful error messages. The step-by-step user operation leading to this code would involve writing a Frida script and the Meson build system processing the Frida Swift components.

7. **Structuring the Answer:** Finally, I organize my understanding into a coherent answer, breaking down the functionality, providing specific examples, and addressing each part of the original request. I emphasize the importance of type safety, argument validation, and feature management in the context of a dynamic instrumentation tool.

This iterative process of understanding the code's purpose, dissecting its components, connecting it to the broader context, and generating examples allows me to provide a comprehensive and insightful answer. The key is not just to list the functions but to explain *why* they exist and *how* they contribute to the overall goals of the project.
这是文件 `frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreterbase/decorators.py` 的源代码，它属于 Frida 动态 instrumentation 工具的构建系统 Meson 的一部分。这个文件定义了一系列 Python 装饰器，用于增强 Meson 解释器中函数的行为，主要集中在类型检查、参数验证、特性管理等方面。

**这个文件的主要功能可以归纳为：**

1. **参数类型检查和验证:**  定义了多种装饰器，用于在 Meson 构建脚本执行期间，对传递给函数的参数进行类型检查和验证。这有助于提前发现错误，提高构建脚本的可靠性。
    * 检查是否存在多余的位置参数或关键字参数 (`noPosargs`, `noKwargs`).
    * 检查位置参数是否为字符串类型 (`stringArgs`).
    * 检查关键字参数是否属于允许的集合 (`permittedKwargs`, `typed_kwargs`).
    * 检查操作符的参数类型 (`typed_operator`).
    * 更精细地检查位置参数的类型、数量，支持可变参数和可选参数 (`typed_pos_args`).
    * 支持对容器类型（列表、字典）的元素类型进行检查 (`ContainerTypeInfo`).
    * 允许定义关键字参数的详细信息，包括类型、是否必需、默认值、版本信息（引入和废弃）等 (`KwargInfo`, `typed_kwargs`).

2. **返回值处理:** 提供装饰器用于对函数的返回值进行处理。
    * 取消对 "holder" 对象的封装 (`unholder_return`). 这可能是 Meson 内部用于延迟计算或表示特定类型值的机制。

3. **特性管理:** 提供装饰器用于管理 Meson 的特性版本控制。
    * 标记函数或功能是在哪个 Meson 版本引入的 (`FeatureNew`).
    * 标记函数或功能是在哪个 Meson 版本废弃的 (`FeatureDeprecated`).
    * 这些装饰器会在用户使用的 Meson 版本与特性需要的版本不匹配时发出警告或通知。

4. **控制参数处理方式:**
    * 防止参数列表被展平 (`noArgsFlattening`).
    * 防止二级 "holder" 对象被解析 (`noSecondLevelHolderResolving`).

5. **处理未找到的情况:**
    * 当函数未找到所需资源时，可以返回一个 `Disabler` 对象，并可根据 `disabler` 关键字参数控制是否启用此行为 (`disablerIfNotFound`). `Disabler` 对象可能用于在构建过程中禁用某些功能。

**与逆向的方法的关系及举例说明:**

虽然这个文件本身不直接涉及二进制代码的逆向，但它所支持的 Frida 工具是用于动态 instrumentation 和逆向分析的。这个文件通过确保 Meson 构建系统的稳定性和正确性，间接地支持了 Frida 的开发和使用。

例如，假设 Frida 的 Swift 支持中有一个 Meson 函数用于配置要注入的目标进程。该函数可能使用 `typed_kwargs` 装饰器来确保用户提供的进程名称或进程 ID 是正确的类型：

```python
@typed_kwargs('frida_swift.inject',
              KwargInfo('process_name', str),
              KwargInfo('process_id', int))
def inject(self, state, args, kwargs):
    process_name = kwargs.get('process_name')
    process_id = kwargs.get('process_id')
    # ... 使用 process_name 或 process_id 进行注入操作 ...
```

如果用户在 Meson 构建脚本中调用 `inject` 函数时，`process_name` 传了一个整数，`typed_kwargs` 装饰器会立即抛出 `InvalidArguments` 异常，指出类型错误，避免了在 Frida 运行时才出现难以追踪的错误，从而方便了逆向分析人员。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明:**

这个文件本身是高级的 Python 代码，并不直接操作二进制或内核。但是，它为 Frida 的构建过程提供了类型安全和版本控制，这对于处理底层概念至关重要。

例如，Frida 可能有一个 Meson 函数用于配置注入代码的内存地址。这个地址通常是一个十六进制的整数。`typed_kwargs` 可以用来确保用户提供的地址是整数类型：

```python
@typed_kwargs('frida_swift.set_injection_address',
              KwargInfo('address', int))
def set_injection_address(self, state, args, kwargs):
    address = kwargs['address']
    # ... 使用 address 进行内存操作 ...
```

在 Android 框架层面，Frida 可能需要与 ART (Android Runtime) 交互。Meson 构建脚本中可能有一个函数用于配置 ART 相关的选项。`typed_kwargs` 可以用来验证这些选项的类型和取值范围，例如确保 ART 方法的签名是字符串类型：

```python
@typed_kwargs('frida_swift.hook_art_method',
              KwargInfo('method_signature', str))
def hook_art_method(self, state, args, kwargs):
    signature = kwargs['method_signature']
    # ... 使用 signature 在 ART 中查找并 hook 方法 ...
```

**逻辑推理的假设输入与输出:**

假设有一个使用 `typed_pos_args` 的函数，期望接收一个字符串和一个整数：

```python
@typed_pos_args('my_function', str, int)
def my_function(self, state, args, kwargs):
    arg1, arg2 = args
    return f"String: {arg1}, Integer: {arg2}"
```

**假设输入：** 在 Meson 构建脚本中调用 `my_function`：
```meson
result = my_function('hello', 123)
```

**预期输出：** 函数执行成功，返回字符串 "String: hello, Integer: 123"。

**假设输入错误：**
```meson
result = my_function(123, 'hello')
```

**预期输出：** `typed_pos_args` 装饰器会抛出 `InvalidArguments` 异常，指出参数类型错误，类似：`my_function argument 1 was of type "int" but should have been "str"`。

**涉及用户或编程常见的使用错误及举例说明:**

* **类型错误:** 用户在 Meson 构建脚本中传递了错误类型的参数。例如，一个期望接收字符串的参数，用户传递了一个整数。`typed_kwargs` 或 `typed_pos_args` 可以捕获这类错误并提供清晰的错误信息。

  ```meson
  # 假设 'set_name' 函数使用 @typed_kwargs(KwargInfo('name', str))
  set_name(name: 123)  # 错误：传递了整数而不是字符串
  ```

* **缺少必需的关键字参数:**  如果函数使用了 `typed_kwargs` 并且某个 `KwargInfo` 设置了 `required=True`，用户在调用时忘记提供该参数。

  ```meson
  # 假设 'create_file' 函数使用 @typed_kwargs(KwargInfo('path', str, required=True))
  create_file()  # 错误：缺少必需的 'path' 参数
  ```

* **使用了不允许的关键字参数:** 函数使用 `permittedKwargs` 限制了允许的关键字参数，用户传递了未定义的关键字参数。

  ```python
  @permittedKwargs({'name', 'size'})
  def my_function(self, state, args, kwargs):
      pass

  # Meson 脚本
  my_function(name: 'test', color: 'red') # 错误：'color' 是不允许的关键字参数
  ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 的 Swift 绑定代码:** 开发人员需要定义如何在 Meson 构建系统中构建和集成 Frida 的 Swift 支持。
2. **配置 Meson 构建脚本 (`meson.build`):** 用户在 `meson.build` 文件中调用 Frida Swift 模块提供的函数，并传递参数。
3. **运行 Meson 配置命令:** 用户执行 `meson setup builddir` 或类似的命令来配置构建环境。
4. **Meson 解释器解析构建脚本:** Meson 解释器会读取和解析 `meson.build` 文件。
5. **调用 Frida Swift 模块的函数:** 当解释器执行到用户调用的 Frida Swift 函数时，例如 `inject(process_name: "target_app")`。
6. **装饰器介入:**  定义在 `decorators.py` 中的装饰器 (如 `typed_kwargs`) 会在实际函数执行之前被调用。
7. **参数检查:** 装饰器会检查用户传递的参数类型和是否符合预期。
8. **抛出异常或继续执行:** 如果检查失败，装饰器会抛出 `InvalidArguments` 异常，阻止构建过程继续，并向用户提供错误信息。如果检查成功，则继续执行被装饰的函数。

因此，当用户在配置 Frida 的 Swift 支持时遇到与参数类型相关的错误，调试线索会指向 `decorators.py` 文件，因为那里的装饰器负责进行这些检查。查看错误信息中提到的函数名和参数名，结合 `decorators.py` 中应用的装饰器，可以帮助定位问题所在。

**归纳一下它的功能 (第 1 部分):**

总的来说，`frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件的主要功能是 **为 Meson 构建系统中用于 Frida Swift 支持的函数提供一套强大的装饰器，用于参数类型检查、验证、返回值处理和特性版本管理。**  这些装饰器增强了构建脚本的可靠性和可维护性，并在早期捕获用户在配置 Frida Swift 支持时可能犯的错误，从而间接地支持了 Frida 动态 instrumentation 工具的开发和使用。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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