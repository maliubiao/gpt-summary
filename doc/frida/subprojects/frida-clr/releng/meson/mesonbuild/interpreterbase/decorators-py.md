Response:
My thought process to analyze the given Python code and address the user's request goes like this:

1. **Understand the Goal:** The user wants a functional breakdown of a specific Python file from the Frida project, focusing on its relevance to reverse engineering, low-level details, and potential user errors, along with a summary of its purpose. They specifically marked this as "part 1 of 2," implying a broader context will follow.

2. **Identify the Core Functionality:**  The filename `decorators.py` within the `interpreterbase` directory strongly suggests that this file defines decorators. Decorators in Python are used to modify or enhance the behavior of functions. A quick scan confirms this. The decorators listed (e.g., `noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, `typed_kwargs`, `FeatureNew`, `FeatureDeprecated`) provide clues about their specific purposes.

3. **Group Functionality:**  The decorators can be grouped by their primary concern:
    * **Argument Validation:**  Decorators like `noPosargs`, `noKwargs`, `stringArgs`, `typed_pos_args`, and `typed_kwargs` are all about ensuring functions receive the correct types and number of arguments.
    * **Return Value Handling:** `unholder_return` modifies the return value.
    * **Conditional Execution:** `disablerIfNotFound` alters behavior based on a function's result.
    * **Feature Versioning/Compatibility:** `FeatureNew` and `FeatureDeprecated` are clearly related to managing compatibility across different versions of Meson.
    * **Internal Flags:** `noArgsFlattening` and `noSecondLevelHolderResolving` likely control internal Meson behavior.
    * **Keyword Argument Management:** `permittedKwargs` restricts allowed keyword arguments.

4. **Relate to Reverse Engineering (Instruction 2):** This requires connecting the *purpose* of the code with common reverse engineering tasks. Frida is a dynamic instrumentation tool. The decorators in this file are used within Frida's build system (Meson). How does a build system relate to reverse engineering?
    * **Building Frida:**  To use Frida for reverse engineering, you need to build it first. This file is part of that build process.
    * **Targeting Specific Platforms:**  The build system likely handles configuration for different target architectures and operating systems (important in reverse engineering, where you analyze code for specific environments).
    * **Configuration Options:**  Build systems often have configuration options that affect the final binary. These decorators help ensure those options are used correctly.
    * **Example:**  Imagine a build option `--enable-experimental-feature`. The `FeatureNew` decorator could be used to warn the developer if they try to enable this feature with an older version of Meson. This indirectly affects the reverse engineer by ensuring the tool they're using is built correctly and with the intended features.

5. **Connect to Low-Level Concepts (Instruction 3):** This is where things get a bit more abstract. The *decorators themselves* don't directly manipulate binary code or interact with the kernel. However, the *code they decorate* likely does.
    * **Build System Foundation:** Meson, as a build system, needs to understand compiler flags, linker options, and platform-specific details. While this file doesn't *implement* those low-level interactions, it *supports* the framework that does.
    * **Frida's Core:** The decorated functions are part of Frida's build process. Frida *itself* is deeply involved with low-level concepts like process memory, instruction hooks, and system calls. The correctness enforced by these decorators helps ensure Frida is built in a way that allows it to perform these low-level tasks reliably.
    * **Kernel and Framework Awareness (Indirect):** When building Frida for Android, the build system needs to know about the Android NDK, SDK, and specific build flags required for the Android framework. These decorators ensure the build system is configured correctly, which is essential for Frida to function within the Android environment.

6. **Logical Reasoning (Instruction 4):**  For the validation decorators, it's straightforward to create hypothetical input and output scenarios.
    * **`noPosargs`:** Input: `my_func(1, 2)`. Output: `InvalidArguments` exception.
    * **`typed_pos_args`:** Input: `my_func("hello", 123)`. Output:  The function executes successfully if the decorated function expects a string and an integer. Input: `my_func(123, "hello")`. Output: `InvalidArguments` exception.

7. **User/Programming Errors (Instruction 5):** The validation decorators are designed to catch common errors.
    * **Incorrect Argument Types:** Passing a number when a string is expected.
    * **Incorrect Number of Arguments:** Providing too few or too many arguments.
    * **Using Positional Arguments When Only Keyword Arguments are Allowed:** And vice-versa.
    * **Using Unknown Keyword Arguments:**  Typos in keyword argument names.
    * **Using Features Not Supported by the Meson Version:** The `FeatureNew` and `FeatureDeprecated` decorators highlight this.

8. **User Operation Trace (Instruction 6):** How does a user end up "here"?
    * **Developer Writing Build Definitions:**  A developer working on the Frida project would be the primary user of this code when defining how Frida is built using Meson.
    * **Meson Invocation:** The developer runs `meson` to configure the build.
    * **Meson Parsing Build Files:** Meson reads the `meson.build` files.
    * **Decorator Execution:** When Meson processes functions decorated with these decorators, the checks are performed.
    * **Error Reporting:** If a decorator detects an issue (e.g., incorrect argument type), it raises an exception, halting the build configuration process and providing an error message to the developer.

9. **Summarize Functionality (Instruction 7):**  Combine the observations into a concise summary. The file is about defining decorators for validating function arguments, managing feature compatibility, and controlling internal Meson behavior during the Frida build process. It's about enforcing correctness and providing helpful error messages to developers.

10. **Consider "Part 1 of 2":**  This implies that the user might ask about how these decorators are *used* in other parts of the Frida build system in the next part. Keep this in mind when summarizing. The decorators *define* the rules; other parts of the codebase *apply* those rules.

By following these steps, I can systematically analyze the code and provide a comprehensive answer that addresses all aspects of the user's request. The key is to move beyond just describing what the code *does* and explain *why* it does it and how it relates to the broader context of Frida and reverse engineering.
好的，让我们来分析一下 `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreterbase/decorators.py` 这个文件的内容，并根据你的要求进行详细的功能列举和说明。

**文件功能归纳：**

这个 Python 文件定义了一系列装饰器 (decorators)，用于增强和约束 Meson 构建系统中解释器 (interpreter) 中函数的行为。这些装饰器主要用于：

1. **参数校验：** 强制函数接收特定类型和数量的参数（包括位置参数和关键字参数）。
2. **返回值处理：** 对函数的返回值进行特定处理，例如移除 "holder" 对象。
3. **功能开关：**  根据函数执行结果有条件地禁用某些功能。
4. **关键字参数控制：** 允许限制函数可以接收的关键字参数。
5. **类型安全：** 确保操作符 (operator)  作用于兼容的类型。
6. **版本控制与兼容性：**  标记和检查新功能的使用，以及已弃用功能的使用，以便在构建过程中提供警告或错误。

**详细功能列举及说明：**

* **`get_callee_args(wrapped_args)`:**
    * **功能：**  从被装饰的函数的参数中提取关键信息，包括当前节点 (用于定位错误)、位置参数 (`args`)、关键字参数 (`kwargs`) 和子项目信息 (`subproject`)。
    * **逆向关系：**  在逆向工程中，了解代码的执行上下文至关重要。这个函数提取的 `current_node` 可以帮助定位构建脚本中导致错误的代码位置，这对于调试构建过程很有用。
    * **二进制底层/内核/框架：**  虽然这个函数本身不直接涉及底层，但它提取的 `subproject` 信息可能与针对特定平台（如 Android）的构建配置有关，而这些配置会影响最终生成的二进制文件和框架依赖。

* **`noPosargs(f)`:**
    * **功能：**  确保被装饰的函数不能接收任何位置参数。
    * **用户错误：** 用户在调用该函数时传递了位置参数，例如 `function_name(1, 'hello')`。
    * **调试线索：**  用户在调用某个 Meson 内置函数或模块函数时，不小心使用了位置参数，而该函数设计上只接受关键字参数。

* **`noKwargs(f)`:**
    * **功能：**  确保被装饰的函数不能接收任何关键字参数。
    * **用户错误：** 用户在调用该函数时传递了关键字参数，例如 `function_name(name='value')`。
    * **调试线索：** 用户在调用某个 Meson 内置函数或模块函数时，错误地使用了关键字参数，而该函数只接受位置参数。

* **`stringArgs(f)`:**
    * **功能：**  确保被装饰的函数接收的位置参数都是字符串类型。
    * **假设输入与输出：**
        * **输入：**  被装饰的函数接收 `['file1.c', 'file2.cpp']`。**输出：** 函数正常执行。
        * **输入：**  被装饰的函数接收 `['file1.c', 123]`。**输出：** 抛出 `InvalidArguments` 异常。
    * **用户错误：** 用户在应该传递文件名列表的地方，混入了非字符串类型的参数。
    * **调试线索：** 用户在调用需要文件名列表的 Meson 函数（例如 `files()`）时，传递了错误类型的数据。

* **`noArgsFlattening(f)`:**
    * **功能：**  设置一个属性，指示在处理该函数的参数时不要进行扁平化操作。这通常涉及到 Meson 内部对参数的处理方式。
    * **二进制底层/内核/框架：**  扁平化操作可能与 Meson 如何将参数传递给底层的构建工具链有关，例如编译器或链接器。跳过扁平化可能用于处理某些特殊类型的参数或避免潜在的问题。

* **`noSecondLevelHolderResolving(f)`:**
    * **功能：** 设置一个属性，指示在处理该函数的参数时不要进行第二层 "holder" 对象的解析。这涉及到 Meson 内部对变量和引用的处理机制。

* **`unholder_return(f)`:**
    * **功能：**  确保被装饰的函数的返回值中所有 "holder" 对象都被解析成实际的值。 "Holder" 对象是 Meson 内部用于延迟计算或引用的机制。
    * **逆向关系：**  在分析 Meson 构建脚本时，理解 "holder" 对象的概念很重要。这个装饰器确保在某些情况下，返回的是最终的值，方便后续处理。

* **`disablerIfNotFound(f)`:**
    * **功能：**  如果被装饰的函数在执行后返回一个表示 "未找到" 的结果（通过 `found()` 方法判断），则返回一个 `Disabler` 对象。`Disabler` 对象用于禁用构建过程中的某些部分。
    * **逆向关系：**  在分析复杂的构建系统时，理解哪些模块或功能被禁用是很重要的。这个装饰器提供了一种机制来根据条件禁用某些部分。
    * **假设输入与输出：**
        * **假设：** 被装饰的函数尝试查找某个库，但未找到。
        * **输入：**  调用被装饰的函数，并且 `kwargs` 中包含 `disabler=True`。
        * **输出：** 返回 `Disabler()` 对象。
    * **用户错误：** 用户可能依赖于一个未找到的组件，但没有正确处理其缺失的情况。
    * **调试线索：**  构建过程中某些功能意外地被禁用，可以检查相关的函数是否使用了这个装饰器，并查看其查找依赖项的逻辑。

* **`permittedKwargs(permitted)`:**
    * **功能：**  限制被装饰的函数可以接收的关键字参数。只有 `permitted` 集合中定义的关键字参数才会被允许。
    * **用户错误：** 用户传递了未被允许的关键字参数，可能是拼写错误或使用了已移除的参数。
    * **调试线索：** 构建过程中报告了未知的关键字参数错误，可以查看相关函数的装饰器，确认允许的参数列表。

* **`typed_operator(operator, types)`:**
    * **功能：**  为 Meson 中的操作符重载函数提供类型检查。确保操作符的右侧操作数是指定的类型。
    * **逆向关系：**  在分析 Meson 代码时，理解操作符的行为很重要。这个装饰器确保了类型安全，有助于理解操作符的预期输入。
    * **假设输入与输出：**
        * **假设：**  一个自定义的 `InterpreterObject` 定义了加法操作符 `+`，并且使用了 `@typed_operator(MesonOperator.PLUS, (int, float))` 装饰器。
        * **输入：** `object + 10`。**输出：** 正常执行。
        * **输入：** `object + 'hello'`。**输出：** 抛出 `InvalidArguments` 异常。

* **`typed_pos_args(name, *types, varargs=None, optargs=None, min_varargs=0, max_varargs=0)`:**
    * **功能：**  对被装饰函数的位置参数进行类型检查和数量检查。支持固定数量、可变数量以及可选参数。
    * **假设输入与输出（示例）：**
        * **装饰器：** `@typed_pos_args('myfunc', str, int)`
            * **输入：** `myfunc('hello', 123)`。**输出：** 函数正常执行。
            * **输入：** `myfunc(123, 'hello')`。**输出：** 抛出 `InvalidArguments` 异常。
            * **输入：** `myfunc('hello')`。**输出：** 抛出 `InvalidArguments` 异常。
        * **装饰器：** `@typed_pos_args('myfunc', str, varargs=int)`
            * **输入：** `myfunc('hello', 1, 2, 3)`。**输出：** 函数正常执行。
            * **输入：** `myfunc('hello', 1, 'a')`。**输出：** 抛出 `InvalidArguments` 异常。
    * **用户错误：**  用户传递了错误类型或错误数量的位置参数。
    * **调试线索：** 构建过程中报告了位置参数类型或数量不匹配的错误，可以检查相关函数的装饰器定义。

* **`ContainerTypeInfo`:**
    * **功能：**  用于描述容器类型的关键字参数的信息，例如列表或字典，以及容器中元素的类型、是否允许为空等。
    * **应用场景：** 用于 `typed_kwargs` 装饰器中，定义更复杂的关键字参数类型约束。

* **`KwargInfo`:**
    * **功能：**  用于描述单个关键字参数的详细信息，包括名称、类型、是否必需、默认值、版本信息（`since`，`deprecated`）、验证器 (`validator`) 和转换器 (`convertor`) 等。
    * **版本控制与兼容性：** `since` 和 `deprecated` 字段用于标记参数的引入和弃用版本，配合 `FeatureNew` 和 `FeatureDeprecated` 可以提供版本兼容性检查。

* **`typed_kwargs(name, *types, allow_unknown=False)`:**
    * **功能：**  对被装饰函数的关键字参数进行类型检查、是否必需检查、默认值设置、版本检查等。
    * **用户错误：** 用户传递了错误类型的关键字参数、缺少必需的关键字参数、使用了未知的关键字参数或使用了已弃用的关键字参数。
    * **调试线索：** 构建过程中报告了关键字参数相关的错误，可以查看相关函数的装饰器定义，了解参数的预期类型、是否必需以及版本信息。

* **`FeatureCheckBase` (抽象基类), `FeatureNew`, `FeatureDeprecated`:**
    * **功能：**  用于实现版本控制和兼容性检查的机制。
        * **`FeatureNew`:**  标记并检查新引入的功能或参数的使用，如果当前 Meson 版本过低，会发出警告。
        * **`FeatureDeprecated`:** 标记并检查已弃用的功能或参数的使用，会发出警告。
    * **逆向关系：**  在分析不同版本的 Frida 构建过程时，了解哪些功能是新引入的，哪些是被弃用的，有助于理解不同版本之间的差异。
    * **用户错误：** 用户在较低版本的 Meson 环境下使用了较新版本引入的功能。
    * **调试线索：**  构建过程中出现了关于 "feature new" 或 "feature deprecated" 的警告，可以查看警告信息，了解具体的功能和版本信息。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户编写或修改 `meson.build` 文件：** 用户在定义 Frida CLR 模块的构建规则时，可能会调用 Meson 提供的内置函数或自定义的解释器函数。
2. **用户运行 `meson` 命令配置构建：**  Meson 开始解析 `meson.build` 文件，构建抽象语法树 (AST)。
3. **Meson 解释器执行构建脚本：**  在执行过程中，会调用各种函数。如果这些函数使用了上述的装饰器，装饰器会先于函数本体执行，进行参数校验、版本检查等。
4. **触发装饰器的校验逻辑：**  例如，用户传递了错误的参数类型，`typed_pos_args` 或 `typed_kwargs` 会捕获到这个错误。
5. **抛出 `InterpreterException` 或 `InvalidArguments` 异常：** 装饰器会根据校验结果抛出相应的异常，并提供错误信息，包括函数名、参数名、期望的类型等。
6. **用户看到错误信息并根据提示进行调试：** 错误信息通常会指向 `meson.build` 文件中的具体代码行，用户可以根据这些信息修改构建脚本。

**总结 `decorators.py` 的功能：**

总而言之，`decorators.py` 文件在 Frida 的 Meson 构建系统中扮演着**类型安全卫士**和**版本兼容性管理员**的角色。它通过定义一系列装饰器，确保 Meson 解释器中的函数接收到正确类型的参数，并对函数的行为进行规范化处理。同时，它还提供了版本控制机制，帮助开发者了解新功能的使用情况以及已弃用功能的迁移，从而提高构建脚本的健壮性和可维护性。这些装饰器增强了 Meson 构建过程的可靠性，并为开发者提供了清晰的错误提示，帮助他们编写正确的构建脚本。

这是第一部分的分析，希望对你有所帮助。期待你的第二部分问题！

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreterbase/decorators.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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