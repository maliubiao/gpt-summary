Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding - What is the Goal?**

The first step is to read the initial lines and the docstring. We see it's about decorators in the `mesonbuild.interpreterbase` for the Frida dynamic instrumentation tool. Decorators in Python modify the behavior of functions. This suggests the file defines reusable ways to add checks and modifications to functions within the Meson build system's interpreter.

**2. Scanning for Key Concepts and Patterns:**

Next, I'd scan for recurring keywords, class names, and function names. This gives clues about the file's main concerns. I notice:

* `@wraps`: This is a standard Python decorator for preserving function metadata, indicating the decorated functions are still intended to look like the originals.
* `get_callee_args`: This function is used frequently, suggesting it's a core utility for extracting information from the arguments passed to the decorated functions. The comments explain it handles different types of objects.
* `noPosargs`, `noKwargs`, `stringArgs`: These function names clearly indicate checks related to function arguments.
* `unholder_return`, `disablerIfNotFound`: These suggest transformations or conditional behavior based on the function's return value.
* `permittedKwargs`, `typed_operator`, `typed_pos_args`, `typed_kwargs`: These strongly point to argument type checking and validation. The names suggest different strategies for handling keyword and positional arguments.
* `ContainerTypeInfo`, `KwargInfo`: These classes appear to be data structures used to define the expected types and properties of function arguments, especially keyword arguments.
* `FeatureCheckBase`, `FeatureNew`, `FeatureDeprecated`:  These classes are related to managing and reporting on the usage of features based on Meson versions. This is crucial for maintaining backward compatibility and informing users about changes.

**3. Analyzing Individual Decorators and Helper Functions:**

Now, I'd go through each function and decorator in more detail, understanding its specific purpose:

* **`get_callee_args`:**  As noted, it extracts key information (node, args, kwargs, subproject) from function arguments. The comment about `ModuleObject` is important for understanding the context within Meson.
* **`noPosargs`, `noKwargs`, `stringArgs`:** These are straightforward checks for the presence and types of arguments. They raise `InvalidArguments` exceptions.
* **`noArgsFlattening`, `noSecondLevelHolderResolving`:** These set attributes on the decorated function. This suggests these attributes are used elsewhere in the Meson codebase to modify how arguments are processed. Without seeing the code that *uses* these attributes, their exact effect is still somewhat unclear, but we understand they control argument flattening/resolution.
* **`unholder_return`:**  It calls `_unholder` on the return value. We don't know what `_unholder` does without looking at its code, but the name suggests it's related to "unwrapping" or "resolving" some kind of held value.
* **`disablerIfNotFound`:**  It conditionally returns a `Disabler` object if the wrapped function's return value doesn't indicate success and a `disabler` keyword argument is present.
* **`permittedKwargs`:** This restricts the allowed keyword arguments.
* **`typed_operator`:**  Specifically for operator overloading, ensuring the right-hand operand has the correct type.
* **`typed_pos_args`:**  A more complex decorator for type-checking positional arguments, handling both fixed and variadic/optional arguments. The detailed docstring is very helpful here.
* **`ContainerTypeInfo`:** Defines structures for describing container types (lists, dictionaries) with type constraints on their elements.
* **`KwargInfo`:**  A detailed description of a single keyword argument, including its type, whether it's required, default value, deprecation/introduction versions, and validators/converters. The `evolve` method is interesting, as it allows modifying existing `KwargInfo` objects.
* **`typed_kwargs`:** The most complex decorator. It uses `KwargInfo` to perform comprehensive type checking and validation of keyword arguments, handling default values, deprecation, and feature introduction.
* **`FeatureCheckBase`, `FeatureNew`, `FeatureDeprecated`:**  These classes manage the reporting of new and deprecated features based on the target Meson version of the project. They ensure users are aware of potential compatibility issues.

**4. Identifying Connections to Reverse Engineering and Low-Level Concepts:**

As I analyzed, I looked for connections to the prompt's specific requirements:

* **Reverse Engineering:**  Frida is explicitly mentioned, so the decorators that enforce argument types and constraints are relevant to ensuring the correct usage of Frida's API within the Meson build system. Incorrect argument types would likely lead to errors when Frida interacts with the target process.
* **Binary/Low-Level:** While the code itself doesn't directly manipulate bits or interact with the kernel, the *purpose* of Frida does. The decorators in this file help ensure that the Meson build system correctly configures and uses Frida, which *does* operate at a low level.
* **Linux/Android Kernel/Framework:**  Again, the connection is through Frida. Frida is often used to interact with processes running on Linux and Android, potentially including kernel components and framework services. The type checking provided by these decorators helps ensure that the Meson build scripts correctly configure Frida for these tasks.

**5. Constructing Examples and Explanations:**

Once I understood the functionality, I could start generating examples for each aspect of the prompt:

* **Functionality:** Summarize the core purpose of each decorator and helper function.
* **Reverse Engineering Relation:** Explain how type checking and argument validation are important for tools like Frida.
* **Low-Level/Kernel Relation:** Connect the decorators to the high-level goal of using Frida for low-level interaction.
* **Logical Reasoning (Input/Output):**  Create simple scenarios showing how each decorator affects function behavior (e.g., providing the wrong type of argument).
* **User/Programming Errors:** Illustrate common mistakes users might make when using functions decorated with these tools.
* **User Operation to Reach This Code:**  Outline the steps a user would take in the Meson build process that would lead to the execution of code involving these decorators.

**6. Iteration and Refinement:**

After drafting the initial explanation, I would reread the code and my explanation, looking for areas that are unclear or could be explained better. I'd refine the language, add more specific examples, and ensure that I've addressed all parts of the prompt. For instance, initially, I might not have emphasized the connection to Frida as strongly, and I'd go back and strengthen that connection. I also might need to revisit specific decorators if their exact purpose wasn't immediately obvious. For example, I'd need to think more carefully about *where* the attributes set by `noArgsFlattening` and `noSecondLevelHolderResolving` are actually used.

This iterative process of understanding, analyzing, and explaining is key to producing a comprehensive and accurate answer.
好的，让我们来详细分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreterbase/decorators.py` 这个文件的功能。

**文件功能归纳：**

这个 Python 文件定义了一系列的**装饰器 (decorators)**，用于增强和规范 Meson 构建系统中解释器 (Interpreter) 中函数的行为。 这些装饰器主要用于：

1. **参数校验和类型检查：** 确保解释器函数的参数符合预期的类型和格式，防止因错误的参数类型导致程序崩溃或行为异常。
2. **功能特性控制和版本管理：**  用于标记和管理新引入或已弃用的功能特性，根据 Meson 的版本向用户发出警告或通知。
3. **返回值处理：**  对解释器函数的返回值进行特定处理，例如解包 (unholder)。
4. **禁用器 (Disabler) 支持：**  当某些功能或模块未找到时，可以返回一个禁用器对象，优雅地处理缺失的情况。
5. **限制参数类型和数量：** 强制函数只能接收特定类型的参数，或不允许接收位置参数或关键字参数。

**与逆向方法的关联及举例说明：**

虽然这个文件本身并没有直接进行二进制代码的分析或修改，但它在 Frida 这个动态插桩工具的构建过程中扮演着重要角色。Frida 被广泛应用于逆向工程，用于运行时检查、修改目标进程的行为。

* **确保 Frida API 使用的正确性:**  Meson 构建系统可能会生成用于配置 Frida 的脚本或代码。 这些装饰器可以确保在 Meson 构建过程中，与 Frida 相关的函数调用使用了正确的参数类型（例如，目标进程的名称是字符串，内存地址是整数等）。 如果参数类型不正确，可能会导致生成的 Frida 脚本出错，无法成功注入或进行插桩。

   **举例说明：** 假设 Meson 中有一个函数 `frida_attach(process_name: str)` 用于生成附加到指定进程的 Frida 代码。  `typed_pos_args` 装饰器可以用于确保 `process_name` 参数必须是字符串类型。 如果用户错误地传入了一个整数，Meson 将在构建时报错，而不是生成错误的 Frida 脚本，从而避免运行时错误。

* **控制 Frida 功能特性的启用和禁用:** Meson 可以根据不同的 Frida 版本或配置，选择性地启用或禁用某些 Frida 功能。 `FeatureNew` 和 `FeatureDeprecated` 装饰器可以帮助 Meson 在构建时检查当前使用的 Frida 版本是否支持特定的功能，并在不支持的情况下发出警告或错误。

   **举例说明：**  假设某个新的 Frida 版本引入了一个新的 API 函数 `frida_memory_protection_set() `。 Meson 中使用 `FeatureNew` 装饰器标记了使用这个 API 的构建脚本部分，并指定了所需的 Frida 最低版本。 如果用户使用的 Frida 版本过低，Meson 将会发出警告，告知用户需要升级 Frida 版本才能使用该功能。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这些装饰器本身是 Python 代码，并不直接涉及二进制底层操作或内核编程。 然而，它们服务的对象——Frida，却深入到这些领域。

* **通过 Frida 间接关联:**  Meson 构建系统利用这些装饰器来确保与 Frida 相关的配置和脚本生成是正确的。而 Frida 的核心功能就是动态地操作目标进程的内存、调用函数等底层操作。  因此，这些装饰器通过确保 Frida 的正确使用，间接地与二进制底层知识相关联。

* **参数校验反映底层需求:** 某些装饰器强制的参数类型可能反映了底层操作的要求。 例如，如果 Meson 中有一个函数用于配置 Frida 来修改特定内存地址的值，那么 `typed_pos_args` 可能会强制地址参数为整数类型，这与内存地址在底层表示为数字的事实相符。

   **举例说明：**  假设 Meson 有一个函数 `frida_write_memory(address: int, data: bytes)`。 `typed_pos_args` 会确保 `address` 参数是整数，`data` 参数是字节串。 这反映了内存地址通常用整数表示，而要写入内存的数据是二进制数据。

**逻辑推理、假设输入与输出：**

我们来看几个装饰器的逻辑推理：

* **`noPosargs`:**
    * **假设输入：** 一个被 `noPosargs` 装饰的函数 `def my_func(*args, **kwargs): pass`，以及调用 `my_func(1, 2, a=3)`。
    * **逻辑推理：** `get_callee_args` 会提取到位置参数 `(1, 2)`。 `noPosargs` 检查到 `args` 不为空。
    * **输出：** 抛出 `InvalidArguments('Function does not take positional arguments.')` 异常。

* **`stringArgs`:**
    * **假设输入：** 一个被 `stringArgs` 装饰的函数 `def process_strings(*args, **kwargs): pass`，以及调用 `process_strings(["hello", "world"])`。
    * **逻辑推理：** `get_callee_args` 会提取到位置参数 `["hello", "world"]`。 `stringArgs` 检查到 `args` 是一个列表，并且列表中的所有元素都是字符串。
    * **输出：**  函数 `process_strings` 正常执行。

    * **假设输入：** 调用 `process_strings(["hello", 123])`。
    * **逻辑推理：** `stringArgs` 检查到列表中的第二个元素不是字符串。
    * **输出：** 抛出 `InvalidArguments('Arguments must be strings.')` 异常。

* **`typed_kwargs`:**
    * **假设输入：**  一个被 `typed_kwargs` 装饰的函数 `def configure(name: str, options: dict)`，其中 `typed_kwargs` 定义了 `options` 参数的类型为 `KwargInfo('options', dict)`.，以及调用 `configure("my_app", options={"debug": True})`。
    * **逻辑推理：** `typed_kwargs` 检查到 `options` 参数存在，并且类型是字典。
    * **输出：** 函数 `configure` 正常执行。

    * **假设输入：** 调用 `configure("my_app", options=["debug", True])`。
    * **逻辑推理：** `typed_kwargs` 检查到 `options` 参数的类型是列表，而不是字典。
    * **输出：** 抛出 `InvalidArguments('configure keyword argument \'options\' was of type array[bool | str] but should have been dict')` 异常。

**用户或编程常见的使用错误及举例说明：**

* **传递了不允许的位置参数：** 用户在调用被 `noPosargs` 装饰的函数时，错误地传递了位置参数。

   **举例：**  一个 Meson 模块中定义了 `configure_options(name='my_app', debug=True)`，并用 `noPosargs` 装饰。 用户错误地调用 `configure_options('my_app', True)` 将会触发异常。

* **传递了不允许的关键字参数：** 用户在调用被 `permittedKwargs` 装饰的函数时，传递了未定义的关键字参数。

   **举例：**  一个函数 `set_compiler(compiler='gcc')` 被 `permittedKwargs({'compiler'})` 装饰。 用户调用 `set_compiler(toolchain='clang')` 将会触发异常。

* **传递了错误类型的参数：** 用户在调用被 `typed_pos_args` 或 `typed_kwargs` 装饰的函数时，传递了类型不符的参数。

   **举例：**  一个函数 `set_memory_address(address: int)` 被 `typed_pos_args('set_memory_address', int)` 装饰。 用户调用 `set_memory_address("0x1000")` 将会触发异常，因为 "0x1000" 是字符串，而不是整数。

* **忘记传递必需的关键字参数：** 用户在调用被 `typed_kwargs` 装饰的函数时，漏掉了 `required=True` 的关键字参数。

   **举例：**  一个函数 `create_target(name: str, sources: list)`，其中 `sources` 参数在 `typed_kwargs` 中被标记为 `required=True`。 用户调用 `create_target(name='my_lib')` 将会触发异常。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **用户编写 `meson.build` 文件:**  用户在其项目的根目录下创建或编辑 `meson.build` 文件，该文件描述了项目的构建过程。
2. **用户调用 Meson 函数:** 在 `meson.build` 文件中，用户会调用 Meson 提供的各种内置函数或模块提供的函数，例如 `executable()`, `library()`, `configure_file()` 等。
3. **Meson 解析 `meson.build` 文件:** 当用户运行 `meson setup builddir` 命令时，Meson 会解析 `meson.build` 文件，构建一个抽象语法树 (AST)。
4. **解释器执行 AST:** Meson 的解释器会遍历 AST，执行其中定义的函数调用。
5. **执行被装饰的函数:** 当解释器执行到某个函数调用时，如果该函数被这些装饰器装饰，那么装饰器的代码会先于函数本身的逻辑执行。
6. **参数校验和类型检查:** 装饰器会提取函数调用的参数，并根据定义的规则进行校验和类型检查。
7. **抛出异常或继续执行:** 如果参数校验失败，装饰器会抛出 `InvalidArguments` 或其他相关的异常，阻止程序的继续执行，并向用户提供错误信息。 如果校验成功，装饰器可能会对参数或返回值进行一些处理，然后调用被装饰的函数。

**作为调试线索：** 当用户在运行 Meson 构建时遇到与参数类型或数量相关的错误时，错误信息很可能来源于这些装饰器抛出的异常。  查看错误信息中提到的函数名和参数名，可以帮助用户快速定位到 `meson.build` 文件中出错的函数调用，并检查传递的参数是否符合预期。 例如，如果错误信息是 "function 'my_function' got unknown keyword arguments 'extra_option'",  则说明 `my_function` 使用了 `permittedKwargs` 装饰器，并且用户传递了一个不允许的关键字参数 `extra_option`。

**总结其功能 (第 1 部分)：**

总而言之，`frida/subprojects/frida-node/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件定义了一套强大的装饰器，用于在 Meson 构建系统的解释器层面实施严格的参数校验、类型检查、功能特性管理和返回值处理。 这些装饰器提高了 Meson 构建脚本的健壮性和可维护性，减少了因参数错误导致的运行时错误，并帮助用户了解不同 Meson 版本之间的功能差异。 它们在确保 Frida 工具在 Meson 构建环境中正确配置和使用方面发挥着关键作用。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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