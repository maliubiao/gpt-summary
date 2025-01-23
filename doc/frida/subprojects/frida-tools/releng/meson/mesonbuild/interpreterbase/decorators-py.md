Response:
My thought process for analyzing the Python code goes like this:

1. **Understand the Goal:** The request asks for the functionality of the `decorators.py` file in the Frida project, focusing on its relevance to reverse engineering, binary/kernel aspects, logic inference, common user errors, and debugging.

2. **High-Level Overview:**  I first scan the imports and class/function definitions to get a general idea of what the file is about. The name "decorators" immediately suggests that this file defines functions that modify the behavior of other functions. The imports from `mesonbuild` and names like `InterpreterException`, `InvalidArguments`, `Disabler`, and `FeatureNew` point towards a build system or configuration context. The core purpose seems to be adding extra checks and functionality around the invocation of functions within this build system.

3. **Categorize Decorators:** I go through each defined decorator (`noPosargs`, `noKwargs`, `stringArgs`, etc.) and try to understand its specific function:
    * **Argument Validation:**  Several decorators (`noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, `typed_kwargs`, `permittedKwargs`) are clearly about validating the arguments passed to the decorated functions. This is crucial for ensuring the build system functions are used correctly.
    * **Behavior Modification:** Some decorators modify the function's return value or behavior (`unholder_return`, `disablerIfNotFound`).
    * **Metadata/Flags:** Others add metadata or flags to the function (`noArgsFlattening`, `noSecondLevelHolderResolving`).
    * **Feature Management:**  `FeatureNew` and `FeatureDeprecated` are explicitly for managing the introduction and deprecation of features based on Meson versions.

4. **Relate to Reverse Engineering:** Now I start thinking about how these decorators might relate to reverse engineering, even though the file itself isn't directly performing reverse engineering.
    * **Indirectly Related:**  Build systems like Meson are used to build software, including tools used for reverse engineering (like Frida itself). Ensuring the build process is correct and consistent is a prerequisite for having reliable reverse engineering tools. The decorators contribute to this reliability.
    * **Specific Examples:**  I look for specific decorators that have implications. For instance, if a reverse engineering tool uses a build system with these decorators, and a function is decorated with `stringArgs`, a developer trying to call that function with non-string arguments will get an error, preventing incorrect usage. This, while not directly reverse engineering, enforces correct usage of the tool's components.

5. **Relate to Binary/Kernel Aspects:**  This is a slightly more distant connection. The decorators themselves don't directly interact with binaries or the kernel. However:
    * **Build Process Foundation:**  The build system orchestrates the compilation and linking of code that *does* interact with binaries and the kernel. Correct build configuration (helped by these decorators) is essential for these lower-level tools to function.
    * **Indirect Control:** While the decorators don't directly manipulate kernel structures, they control how the build system generates configurations and build instructions, which can influence how kernel modules or Android framework components are built.

6. **Logic Inference (Hypothetical Input/Output):** For decorators that perform validation, I consider what happens with valid and invalid inputs:
    * **`noPosargs`:** Input: `func(1, 2, kw="val")`. Output: `InvalidArguments` exception. Input: `func(kw="val")`. Output: Function execution.
    * **`stringArgs`:** Input: `func(["a", "b"])`. Output: Function execution. Input: `func(["a", 1])`. Output: `InvalidArguments` exception.

7. **Common User Errors:** I think about how developers using the build system might misuse the decorated functions:
    * Passing positional arguments when they aren't allowed.
    * Providing keyword arguments that aren't supported.
    * Using incorrect data types for arguments (e.g., numbers instead of strings).
    * Trying to use features that are too new for the specified Meson version.

8. **Debugging Clues:** I consider how encountering these decorators in a stack trace or error message might help with debugging:
    * **Identifying the problematic function:** The decorator wraps the function, so its name will be in the trace.
    * **Understanding the validation failure:** The exception messages from the decorators often indicate *why* the call failed (e.g., "Function does not take positional arguments.").
    * **Pinpointing argument issues:** `typed_pos_args` and `typed_kwargs` specify the expected argument types.

9. **Functionality Summary (Part 1):** Based on the above analysis, I summarize the core functions of the file, focusing on argument validation, behavior modification, and feature management within the Meson build system context.

10. **Iteration and Refinement:**  I review my analysis and the code again, looking for nuances or details I might have missed. For example, the `ContainerTypeInfo` class provides more sophisticated type checking for lists and dictionaries. The `KwargInfo` class encapsulates information about individual keyword arguments, making the `typed_kwargs` decorator more powerful.

By following this systematic approach, I can break down the complex code into understandable components and analyze its purpose and implications in the broader context of the Frida project and build systems.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreterbase/decorators.py` 文件的第 1 部分。这个文件定义了一系列 Python 装饰器，用于增强 Meson 构建系统中解释器对象的方法的功能。  这些装饰器主要用于进行参数类型检查、限制参数类型、处理返回值以及管理特性版本控制。

**功能归纳 (第 1 部分):**

这个文件主要定义了以下类型的装饰器，用于修饰 Meson 解释器对象的方法：

1. **参数类型和数量限制:**
   - `noPosargs`:  确保被装饰的函数不接受任何位置参数。
   - `noKwargs`: 确保被装饰的函数不接受任何关键字参数。
   - `stringArgs`: 确保被装饰的函数接收的位置参数都是字符串类型。
   - `typed_pos_args`:  对被装饰函数的位置参数进行类型检查，可以指定固定类型的参数、可变参数和可选参数。
   - `typed_kwargs`: 对被装饰函数的关键字参数进行类型检查，可以指定参数名、类型（包括容器类型）、是否必需、默认值、版本信息等。
   - `permittedKwargs`: 允许被装饰的函数接收指定的关键字参数，如果接收到未知的关键字参数则抛出异常。

2. **返回值处理:**
   - `unholder_return`:  对被装饰函数的返回值进行 "unhold" 操作。这可能涉及到解包或提取返回值中实际的值，用于处理 Meson 内部的包装对象。
   - `disablerIfNotFound`:  如果被装饰的函数返回一个表示未找到结果的对象，并且传递了 `disabler=True` 关键字参数，则返回一个 `Disabler` 对象。

3. **参数处理行为控制:**
   - `noArgsFlattening`:  设置一个标志，阻止对被装饰函数的参数进行扁平化处理。
   - `noSecondLevelHolderResolving`: 设置一个标志，阻止对被装饰函数的参数进行第二级 holder 解析。

4. **运算符类型检查:**
   - `typed_operator`:  对被装饰的运算符重载方法（例如 `__add__`）的参数类型进行检查。

5. **特性版本控制:**
   - `FeatureNew`: 用于标记一个功能是在哪个 Meson 版本引入的，并在运行时检查当前项目的 Meson 版本是否支持该功能。
   - `FeatureDeprecated`: 用于标记一个功能是在哪个 Meson 版本被废弃的，并在运行时检查当前项目的 Meson 版本，如果使用了已废弃的功能则发出警告。

**与逆向的方法的关系及举例说明:**

虽然这个文件本身不直接进行二进制逆向，但它作为构建系统的一部分，间接地影响了 Frida 这样的动态插桩工具的构建和使用。

**举例:** 假设 Frida 的某个功能需要在 Meson 构建脚本中调用一个特定的函数，这个函数被装饰了 `@stringArgs`。这意味着用户在 Meson 脚本中调用这个函数时，必须传递字符串类型的参数。

```python
# 假设这是 Frida 构建脚本中的一部分
custom_frida_function(['/path/to/library.so', 'function_name'])  # 正确，参数是字符串

custom_frida_function(['/path/to/library.so', 123])  # 错误，第二个参数是整数，会触发异常
```

如果用户在构建 Frida 时，在 Meson 脚本中错误地传递了非字符串类型的参数，`@stringArgs` 装饰器会捕获到这个错误，并抛出一个 `InvalidArguments` 异常，提示用户参数类型不正确。这有助于确保 Frida 的构建配置是正确的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件本身并不直接操作二进制底层、Linux 或 Android 内核。然而，它所属的 Meson 构建系统和 Frida 工具本身，都与这些底层知识密切相关。

**举例:**

- **二进制底层:**  Frida 的核心功能是动态插桩，涉及到对目标进程的内存进行读写和代码注入等操作。Meson 构建系统负责编译和链接 Frida 的各个组件，包括那些直接与底层二进制交互的代码。`typed_pos_args` 或 `typed_kwargs` 可以确保传递给编译链接相关函数的参数（例如，源文件路径、库文件路径）是正确的类型，这对于生成正确的二进制文件至关重要。
- **Linux/Android 内核:** Frida 可以用于分析 Linux 和 Android 内核。Meson 构建系统可以用于构建 Frida 的内核模块或驱动程序。  `typed_kwargs` 可以用于验证构建内核模块时传递的配置选项是否有效。
- **Android 框架:** Frida 可以用于 hook Android 应用程序和框架。Meson 构建系统可以用于构建 Frida 的 Android 组件。 例如，在构建与 Android 框架交互的 Frida 模块时，可能需要指定特定的 Android SDK 路径或编译选项，`typed_kwargs` 可以用于检查这些路径和选项的有效性。

**逻辑推理及假设输入与输出:**

假设有一个函数 `process_files` 被装饰了 `@typed_pos_args('process_files', str, varargs=str)`：

**假设输入:**

```python
process_files_instance.process_files('input.txt', 'config.ini', 'data.bin')
```

**输出:**  函数 `process_files` 正常执行，因为第一个参数是字符串，后面的参数也是字符串（符合 `varargs=str`）。

**假设输入:**

```python
process_files_instance.process_files('input.txt', 123)
```

**输出:** 抛出 `InvalidArguments` 异常，因为第二个参数是整数，不符合 `varargs=str` 的要求。

**涉及用户或编程常见的使用错误及举例说明:**

1. **传递了不允许的位置参数:** 如果一个函数被装饰了 `@noPosargs`，用户尝试传递位置参数将会导致错误。

   ```python
   @noPosargs
   def my_function(a=1):
       pass

   my_function(10)  # 错误，会抛出 "Function does not take positional arguments."
   ```

2. **传递了不允许的关键字参数:** 如果一个函数被装饰了 `@permittedKwargs({"name", "value"})`，用户传递了其他关键字参数将会导致错误。

   ```python
   @permittedKwargs({"name", "value"})
   def my_function(name="test", value=0):
       pass

   my_function(name="test", setting=True)  # 错误，会抛出 "Got unknown keyword arguments "setting""
   ```

3. **传递了类型错误的参数:** 如果一个函数被装饰了 `@stringArgs` 但传递了非字符串参数。

   ```python
   @stringArgs
   def process_names(names):
       for name in names:
           print(name)

   process_names(["Alice", "Bob"]) # 正确
   process_names(["Alice", 123])   # 错误，会抛出 "Arguments must be strings."
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Meson 构建脚本 (meson.build):** 用户在编写 Frida 的构建脚本时，会调用 Meson 提供的各种内置函数或 Frida 自定义的函数。
2. **Meson 解析构建脚本:** 当用户运行 `meson setup build` 命令时，Meson 会解析 `meson.build` 文件。
3. **调用解释器对象的方法:**  构建脚本中的函数调用会映射到 Meson 解释器对象的方法调用。
4. **装饰器发挥作用:**  在调用这些方法之前，定义的装饰器会先执行，对传入的参数进行检查。
5. **发现错误并抛出异常:** 如果用户在构建脚本中传递了不符合装饰器要求的参数，例如类型错误或参数数量不对，装饰器会抛出相应的异常（如 `InvalidArguments`）。
6. **显示错误信息:** Meson 会将这些异常信息显示给用户，作为调试线索。错误信息中通常会包含函数名、参数名以及类型不匹配等详细信息，帮助用户定位构建脚本中的错误。

例如，如果用户在 `meson.build` 文件中调用了一个被 `@stringArgs` 装饰的函数，并传递了一个整数参数，那么在 `meson setup build` 阶段，Meson 会抛出一个包含 "Arguments must be strings." 的 `InvalidArguments` 异常，并指出是哪个函数调用出了问题，以及哪个参数的类型不正确。 这就为用户提供了明确的调试线索。

总而言之，这个文件的主要作用是为 Meson 构建系统的解释器对象的方法添加静态类型检查和其他约束，以提高构建脚本的健壮性和可维护性，并在早期捕获用户的错误用法。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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