Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `sourceset.py` file within the Frida project. The request also asks for specific connections to reverse engineering, low-level aspects, logical reasoning, common errors, and how a user might reach this code.

**2. High-Level Overview of the Code:**

The first step is to skim the code to get a general idea of what it's doing. Keywords like `SourceSet`, `add`, `apply`, `dependencies`, and `configuration` stand out. The imports suggest it interacts with Meson's build system (`build`, `dependencies`, `mesonlib`). This immediately tells us it's part of the build process and likely helps manage source files and their dependencies based on certain conditions.

**3. Deeper Dive into Classes and Methods:**

Next, I would analyze the main classes and their methods:

* **`SourceSetRule`:**  This looks like a data structure to store rules for including/excluding source files. The fields `keys`, `deps`, `sources`, `extra_deps`, `sourcesets`, and `if_false` are key to understanding the conditional logic.

* **`SourceFiles`:**  A simple container for sets of sources and dependencies. Using `OrderedSet` is notable, suggesting the order of these items might be important in some contexts.

* **`SourceSet` (Base) and `SourceSetImpl`:** The `Impl` part signifies this is the concrete implementation. The methods within `SourceSetImpl` (`add_method`, `add_all_method`, `all_sources_method`, `all_dependencies_method`, `apply_method`) represent the primary actions you can perform on a source set.

* **`SourceFilesObject`:** This seems to be a wrapper around `SourceFiles`, providing methods to access the sources and dependencies.

* **`SourceSetModule`:**  This is the entry point for this module within the Meson build system. The `source_set` method is how you create a `SourceSetImpl` instance.

**4. Analyzing Functionality - Connecting the Dots:**

Now, the task is to connect the classes and methods to understand the overall functionality:

* **Conditional Source Inclusion:** The `add_method` and `add_all_method`, along with the `when`, `if_true`, and `if_false` keywords, clearly indicate the ability to conditionally include source files or other source sets based on configuration keys or dependency presence.

* **Collecting Sources and Dependencies:** The `collect` method is crucial. It iterates through the rules and determines which sources and dependencies to include based on the provided `enabled_fn` (which checks configuration keys) and the presence of dependencies. The `all_sources` flag allows collecting even the "false" branches.

* **Applying with Configuration:**  The `apply_method` takes configuration data (either a `ConfigurationData` object or a dictionary) and uses it to evaluate the conditions defined in the rules. This is where the conditional logic comes to fruition.

* **Accessing Results:** `all_sources_method` and `all_dependencies_method` provide ways to retrieve all sources and dependencies without applying specific configuration. `SourceFilesObject` also exposes these through its methods.

**5. Addressing Specific Requirements of the Request:**

With a solid understanding of the code's functionality, I would now specifically address each point in the request:

* **Functionality Listing:**  Summarize the key functionalities based on the analysis above (conditional inclusion, dependency management, applying configurations, etc.).

* **Relationship to Reverse Engineering:**  Consider how the ability to selectively include/exclude source code based on conditions might be relevant in a reverse engineering context. Think about scenarios where different build configurations are used for different reverse engineering tasks (e.g., debugging vs. release). The example of disabling anti-tampering features is a good fit.

* **Binary/Low-Level/Kernel/Framework Knowledge:**  Think about where these concepts might intersect. Conditional compilation based on OS (Linux/Android) or architecture is a common use case. The example of architecture-specific code or dealing with kernel headers makes sense.

* **Logical Reasoning (Input/Output):** Choose a simple scenario with a few rules and configuration options to demonstrate how the `apply` method would work. This involves tracing the logic of the `collect` method.

* **Common Usage Errors:**  Focus on potential mistakes developers might make when using this module, such as inconsistent arguments to `add`, using `add` after freezing, or missing keys in strict mode.

* **User Path and Debugging:**  Think about how a user interacting with Frida's build system might end up using this code. The `meson.build` file and the `sourceset` keyword are the entry points. Explain the flow from a user action to this specific Python file.

**6. Refinement and Clarity:**

Finally, review the entire explanation for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. Use clear and concise language. Structure the answer logically, following the points in the request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is just about grouping source files.
* **Correction:**  The conditional logic with `when`, `if_true`, `if_false` makes it more than simple grouping. It's about *conditional* inclusion.

* **Initial thought:** The reverse engineering link is weak.
* **Refinement:**  Consider how conditional compilation is used in practice for debugging, feature flags, or platform-specific code – all relevant to reverse engineering scenarios.

* **Initial thought:** Focus only on the Python code.
* **Refinement:** Remember to connect this to the broader Meson build system and how a user would interact with it (the `meson.build` file).

By following this structured approach, combining code analysis with domain knowledge (reverse engineering, build systems), and systematically addressing the requirements, you can arrive at a comprehensive and accurate explanation of the code's functionality.
这个文件 `sourceset.py` 是 Frida 动态 instrumentation 工具中用于管理和组织源代码集合的 Meson 模块。它允许根据不同的条件（例如，配置选项、依赖项是否存在）来选择性地包含或排除源文件和依赖项。

以下是它的主要功能：

**1. 定义源代码集合 (SourceSet):**

   - 提供了 `source_set()` 函数，用于创建一个 `SourceSetImpl` 对象。这个对象可以被认为是源代码的一个逻辑分组。

**2. 条件化地添加源文件和依赖项:**

   - **`add()` 方法:**  允许向源代码集合中添加源文件和依赖项，并可以指定条件。
     - `when`:  一个包含配置键（字符串）或依赖项的列表。只有当所有配置键为真，并且所有依赖项都存在时，才会应用 `if_true` 中的源文件和依赖项。
     - `if_true`: 当条件为真时，要添加的源文件、生成的类型（如自定义目标）或依赖项的列表。
     - `if_false`: 当条件为假时，要添加的源文件的列表。
   - **`add_all()` 方法:**  允许将另一个 `SourceSetImpl` 对象添加到当前的源代码集合中，同样可以指定条件。
     - `when`:  条件列表，与 `add()` 方法相同。
     - `if_true`: 当条件为真时，要添加的 `SourceSetImpl` 对象列表。

**3. 查询源代码集合的内容:**

   - **`all_sources()` 方法:** 返回源代码集合中包含的所有源文件的列表，忽略条件。
   - **`all_dependencies()` 方法:** 返回源代码集合中包含的所有依赖项的列表，忽略条件。

**4. 应用配置并获取最终的源文件和依赖项:**

   - **`apply()` 方法:**  根据提供的配置数据（`ConfigurationData` 对象或字典）评估定义的条件，并返回一个包含最终选择的源文件和依赖项的 `SourceFilesObject`。
     - `config_data`:  一个 `ConfigurationData` 对象或一个字典，用于评估条件中的配置键。
     - `strict`:  一个布尔值，指示当配置数据中缺少条件中引用的配置键时是否抛出错误（默认为 `True`）。

**5. 获取最终的源文件和依赖项 (SourceFilesObject):**

   - `apply()` 方法返回一个 `SourceFilesObject`，它包含两个方法：
     - **`sources()` 方法:** 返回根据配置条件选择的源文件列表。
     - **`dependencies()` 方法:** 返回根据配置条件选择的依赖项列表。

**与逆向方法的关联及举例:**

`SourceSet` 模块在 Frida 中可以用于根据不同的目标平台、构建类型或启用的功能，选择性地编译不同的代码。这与逆向工程中的一些场景相关：

* **针对特定平台的代码:**  在 Frida 中，可能需要为不同的操作系统（如 Linux、Android、iOS、Windows）或架构（如 x86、ARM）编译不同的代码。`SourceSet` 可以根据目标平台选择包含特定平台的源文件。

   ```python
   # 假设配置中 'target_os' 表示目标操作系统
   sources = sourceset.source_set()
   sources.add(['common.c', 'utils.c'])
   sources.add(['linux_specific.c'], when=['target_os=linux'])
   sources.add(['android_specific.c'], when=['target_os=android'])
   ```

* **包含或排除调试代码/功能:** 在逆向过程中，可能需要构建包含调试符号或额外日志信息的 Frida Agent。`SourceSet` 可以根据构建配置选择性地包含这些代码。

   ```python
   # 假设配置中 'enable_debug_symbols' 表示是否启用调试符号
   sources = sourceset.source_set()
   sources.add(['core.c', 'hook.c'])
   sources.add(['debug_utils.c'], when=['enable_debug_symbols'])
   ```

* **支持不同的 Frida 特性:**  Frida 可能具有不同的功能模块，某些模块可能依赖于特定的库或组件。`SourceSet` 可以根据启用的特性选择性地包含相应的源代码和依赖项。

   ```python
   # 假设配置中 'enable_feature_x' 表示是否启用特性 X
   sources = sourceset.source_set()
   sources.add(['main.c'])
   sources.add(['feature_x.c', dependency('lib_for_x')], when=['enable_feature_x'])
   ```

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

`SourceSet` 本身并不直接涉及二进制操作或内核编程，但它管理的代码最终会被编译成二进制文件，并且可能与底层系统交互。

* **条件编译内核模块:**  如果 Frida 包含一些需要编译为内核模块的部分（虽然 Frida Agent 通常运行在用户空间），`SourceSet` 可以用来管理不同内核版本的兼容性代码。

   ```python
   # 假设配置中 'linux_kernel_version' 表示 Linux 内核版本
   sources = sourceset.source_set()
   sources.add(['common_kernel_code.c'])
   sources.add(['kernel_version_5_plus.c'], when=['linux_kernel_version>=5.0'])
   sources.add(['kernel_version_4_minus.c'], when=['linux_kernel_version<5.0'])
   ```

* **包含 Android Framework 相关的代码:**  在 Frida Android 逆向中，可能需要与 Android Framework 的特定部分交互。`SourceSet` 可以根据目标 Android 版本或设备特性来选择包含相关的 Framework 接口代码。

   ```python
   # 假设配置中 'android_api_level' 表示 Android API 级别
   sources = sourceset.source_set()
   sources.add(['common_android_hooks.c'])
   sources.add(['android_api_level_23_plus.c'], when=['android_api_level>=23'])
   ```

**逻辑推理 (假设输入与输出):**

假设我们有以下 `meson.build` 文件片段：

```python
project('my-frida-agent', 'c')

option('enable_debug', type : 'boolean', value : false)
lib_crypto = dependency('libcrypto', required: false)

sources = sourceset.source_set()
sources.add(['main.c', 'core.c'])
sources.add(['debug.c'], when=['enable_debug'])
sources.add(['crypto_utils.c'], if_true=[lib_crypto])

if get_option('enable_debug')
  message('Debug mode is enabled')
endif

my_lib = library('my-agent', sources.apply(configuration_data()))
```

**假设输入:**

- 用户执行 `meson setup build -Denable_debug=true`
- 系统中安装了 `libcrypto`

**逻辑推理过程:**

1. **`option('enable_debug', ...)`:** Meson 解析配置选项，`enable_debug` 被设置为 `true`。
2. **`dependency('libcrypto', ...)`:** Meson 尝试查找 `libcrypto` 依赖，假设找到。
3. **`sources = sourceset.source_set()`:** 创建一个 `SourceSetImpl` 对象。
4. **`sources.add(['main.c', 'core.c'])`:** 无条件添加 `main.c` 和 `core.c`。
5. **`sources.add(['debug.c'], when=['enable_debug'])`:** 由于 `enable_debug` 为 `true`，添加 `debug.c`。
6. **`sources.add(['crypto_utils.c'], if_true=[lib_crypto])`:** 由于 `libcrypto` 依赖存在，添加 `crypto_utils.c`。
7. **`sources.apply(configuration_data())`:**  `apply` 方法被调用，传入当前的配置数据。
8. **`collect` 方法内部逻辑:**
   - 检查第一个 `add` 规则，条件为空，`main.c` 和 `core.c` 被选中。
   - 检查第二个 `add` 规则，`enable_debug` 为 `true`，`debug.c` 被选中。
   - 检查第三个 `add` 规则，`libcrypto` 存在，`crypto_utils.c` 被选中。

**预期输出 (传递给 `library` 函数的源文件列表):**

`['main.c', 'core.c', 'debug.c', 'crypto_utils.c']`

**涉及用户或者编程常见的使用错误及举例:**

* **条件键入错误:**  在 `when` 中使用了错误的配置键名称，导致条件永远无法满足。

   ```python
   sources.add(['feature_x.c'], when=['enabl_feature_x']) # 拼写错误
   ```

* **`add` 和 `add_all` 的参数混淆:**  错误地将源文件列表作为位置参数传递给 `add_all`。

   ```python
   sources.add_all(['myfile.c']) # 应该传入 SourceSet 对象
   ```

* **在 `apply` 后尝试修改 SourceSet:**  在调用 `apply` 方法后，`SourceSet` 对象会被冻结，尝试再次调用 `add` 或 `add_all` 会抛出异常。

   ```python
   final_sources = sources.apply(configuration_data())
   sources.add(['another.c']) # 错误，SourceSet 已冻结
   ```

* **`apply` 时配置数据缺少必要的键 (strict=True):** 如果 `apply` 方法的 `strict` 参数为 `True`（默认值），而配置数据中缺少 `when` 条件中引用的配置键，则会抛出 `InvalidArguments` 异常。

   ```python
   sources.add(['experimental.c'], when=['enable_experimental'])
   # 如果 configuration_data 中没有 'enable_experimental' 键
   final_sources = sources.apply(configuration_data()) # 会抛出异常
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在 Frida Agent 的源代码目录中创建或修改 `meson.build` 文件，并在其中使用了 `sourceset.source_set()` 创建了一个 `SourceSet` 对象。

2. **用户配置构建选项:** 用户在终端中使用 `meson setup build -D<option>=<value>` 命令配置构建选项，例如 `-Denable_debug=true`。这些选项会被 Meson 解析并存储在配置数据中。

3. **用户执行构建命令:** 用户执行 `ninja -C build` 或类似的命令来触发实际的构建过程。

4. **Meson 解析 `meson.build`:** Meson 读取 `meson.build` 文件，并执行其中的 Python 代码，包括 `sourceset.py` 模块中的函数。

5. **创建 `SourceSet` 对象和添加规则:**  Meson 执行 `sourceset.source_set()` 创建 `SourceSetImpl` 实例，并执行 `add` 和 `add_all` 方法来定义源代码的条件包含规则。

6. **调用 `apply` 方法:**  当需要获取最终的源文件列表时，Meson 会调用 `sources.apply(configuration_data())`，并将当前的配置数据传递给它。

7. **`collect` 方法执行:**  `apply` 方法内部会调用 `collect` 方法，该方法根据配置数据评估之前定义的规则，选择合适的源文件和依赖项。

8. **返回 `SourceFilesObject`:** `apply` 方法返回一个 `SourceFilesObject`，其中包含了最终的源文件和依赖项列表。

9. **传递给构建目标:** 这个 `SourceFilesObject` 的 `sources()` 方法返回的列表会被传递给 `library()`、`executable()` 等构建目标函数，用于指定要编译的源文件。

**调试线索:**

如果用户在构建过程中遇到与源文件包含相关的问题，例如某些代码没有被编译进去，可以按照以下步骤进行调试：

1. **检查 `meson.build` 文件:**  确认 `SourceSet` 的定义和 `add` / `add_all` 方法的调用是否正确，尤其是 `when` 和 `if_true`/`if_false` 条件。

2. **检查构建配置选项:**  确认用户在执行 `meson setup` 时设置的选项是否与 `when` 条件中的配置键匹配。可以使用 `meson configure build` 查看当前的配置。

3. **使用 `message()` 函数进行调试输出:** 在 `meson.build` 文件中添加 `message()` 调用，输出 `SourceSet` 对象的状态或中间结果，例如在调用 `apply` 之前输出 `sources.all_sources()`。

4. **查看 Meson 的日志输出:** Meson 在构建过程中会产生日志，可以从中找到有关依赖项查找和配置评估的信息。

5. **逐步调试 `sourceset.py` (如果需要深入分析):**  虽然通常不需要，但在复杂情况下，可以尝试在 `sourceset.py` 中添加断点或日志输出，来跟踪 `collect` 方法的执行过程，查看哪些规则被匹配，哪些源文件被选择。

总而言之，`sourceset.py` 提供了一种灵活的方式来管理 Frida 项目中的源代码，允许根据不同的构建配置和环境条件动态地调整编译的源文件集合，这对于构建跨平台、具有不同特性的 Frida 工具至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/sourceset.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

from __future__ import annotations
import typing as T

from . import ExtensionModule, ModuleObject, MutableModuleObject, ModuleInfo
from .. import build
from .. import dependencies
from .. import mesonlib
from ..interpreterbase import (
    noPosargs, noKwargs,
    InterpreterException, InvalidArguments, InvalidCode, FeatureNew,
)
from ..interpreterbase.decorators import ContainerTypeInfo, KwargInfo, typed_kwargs, typed_pos_args
from ..mesonlib import OrderedSet

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var, TYPE_kwargs

    class AddKwargs(TypedDict):

        when: T.List[T.Union[str, dependencies.Dependency]]
        if_true: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes, dependencies.Dependency]]
        if_false: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]

    class AddAllKw(TypedDict):

        when: T.List[T.Union[str, dependencies.Dependency]]
        if_true: T.List[SourceSetImpl]

    class ApplyKw(TypedDict):

        strict: bool


_WHEN_KW: KwargInfo[T.List[T.Union[str, dependencies.Dependency]]] = KwargInfo(
    'when',
    ContainerTypeInfo(list, (str, dependencies.Dependency)),
    listify=True,
    default=[],
)


class SourceSetRule(T.NamedTuple):
    keys: T.List[str]
    """Configuration keys that enable this rule if true"""

    deps: T.List[dependencies.Dependency]
    """Dependencies that enable this rule if true"""

    sources: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]
    """Source files added when this rule's conditions are true"""

    extra_deps: T.List[dependencies.Dependency]
    """Dependencies added when this rule's conditions are true, but
       that do not make the condition false if they're absent."""

    sourcesets: T.List[SourceSetImpl]
    """Other sourcesets added when this rule's conditions are true"""

    if_false: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]
    """Source files added when this rule's conditions are false"""


class SourceFiles(T.NamedTuple):
    sources: OrderedSet[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]
    deps: OrderedSet[dependencies.Dependency]


class SourceSet:
    """Base class to avoid circular references.

    Because of error messages, this class is called SourceSet, and the actual
    implementation is an Impl.
    """


class SourceSetImpl(SourceSet, MutableModuleObject):
    def __init__(self, interpreter: Interpreter):
        super().__init__()
        self.rules: T.List[SourceSetRule] = []
        self.frozen = False
        self.methods.update({
            'add': self.add_method,
            'add_all': self.add_all_method,
            'all_sources': self.all_sources_method,
            'all_dependencies': self.all_dependencies_method,
            'apply': self.apply_method,
        })

    def check_source_files(self, args: T.Sequence[T.Union[mesonlib.FileOrString, build.GeneratedTypes, dependencies.Dependency]],
                           ) -> T.Tuple[T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]], T.List[dependencies.Dependency]]:
        sources: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]] = []
        deps: T.List[dependencies.Dependency] = []
        for x in args:
            if isinstance(x, dependencies.Dependency):
                deps.append(x)
            else:
                sources.append(x)
        to_check: T.List[str] = []

        # Get the actual output names to check
        for s in sources:
            if isinstance(s, str):
                to_check.append(s)
            elif isinstance(s, mesonlib.File):
                to_check.append(s.fname)
            else:
                to_check.extend(s.get_outputs())
        mesonlib.check_direntry_issues(to_check)
        return sources, deps

    def check_conditions(self, args: T.Sequence[T.Union[str, dependencies.Dependency]]
                         ) -> T.Tuple[T.List[str], T.List[dependencies.Dependency]]:
        keys: T.List[str] = []
        deps: T.List[dependencies.Dependency] = []
        for x in args:
            if isinstance(x, str):
                keys.append(x)
            else:
                deps.append(x)
        return keys, deps

    @typed_pos_args('sourceset.add', varargs=(str, mesonlib.File, build.GeneratedList, build.CustomTarget, build.CustomTargetIndex, dependencies.Dependency))
    @typed_kwargs(
        'sourceset.add',
        _WHEN_KW,
        KwargInfo(
            'if_true',
            ContainerTypeInfo(list, (str, mesonlib.File, build.GeneratedList, build.CustomTarget, build.CustomTargetIndex, dependencies.Dependency)),
            listify=True,
            default=[],
        ),
        KwargInfo(
            'if_false',
            ContainerTypeInfo(list, (str, mesonlib.File, build.GeneratedList, build.CustomTarget, build.CustomTargetIndex)),
            listify=True,
            default=[],
        ),
    )
    def add_method(self, state: ModuleState,
                   args: T.Tuple[T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes, dependencies.Dependency]]],
                   kwargs: AddKwargs) -> None:
        if self.frozen:
            raise InvalidCode('Tried to use \'add\' after querying the source set')
        when = kwargs['when']
        if_true = kwargs['if_true']
        if_false = kwargs['if_false']
        if not any([when, if_true, if_false]):
            if_true = args[0]
        elif args[0]:
            raise InterpreterException('add called with both positional and keyword arguments')
        keys, dependencies = self.check_conditions(when)
        sources, extra_deps = self.check_source_files(if_true)
        if_false, _ = self.check_source_files(if_false)
        self.rules.append(SourceSetRule(keys, dependencies, sources, extra_deps, [], if_false))

    @typed_pos_args('sourceset.add_all', varargs=SourceSet)
    @typed_kwargs(
        'sourceset.add_all',
        _WHEN_KW,
        KwargInfo(
            'if_true',
            ContainerTypeInfo(list, SourceSet),
            listify=True,
            default=[],
        )
    )
    def add_all_method(self, state: ModuleState, args: T.Tuple[T.List[SourceSetImpl]],
                       kwargs: AddAllKw) -> None:
        if self.frozen:
            raise InvalidCode('Tried to use \'add_all\' after querying the source set')
        when = kwargs['when']
        if_true = kwargs['if_true']
        if not when and not if_true:
            if_true = args[0]
        elif args[0]:
            raise InterpreterException('add_all called with both positional and keyword arguments')
        keys, dependencies = self.check_conditions(when)
        for s in if_true:
            s.frozen = True
        self.rules.append(SourceSetRule(keys, dependencies, [], [], if_true, []))

    def collect(self, enabled_fn: T.Callable[[str], bool],
                all_sources: bool,
                into: T.Optional['SourceFiles'] = None) -> SourceFiles:
        if not into:
            into = SourceFiles(OrderedSet(), OrderedSet())
        for entry in self.rules:
            if all(x.found() for x in entry.deps) and \
               all(enabled_fn(key) for key in entry.keys):
                into.sources.update(entry.sources)
                into.deps.update(entry.deps)
                into.deps.update(entry.extra_deps)
                for ss in entry.sourcesets:
                    ss.collect(enabled_fn, all_sources, into)
                if not all_sources:
                    continue
            into.sources.update(entry.if_false)
        return into

    @noKwargs
    @noPosargs
    def all_sources_method(self, state: ModuleState, args: T.List[TYPE_var], kwargs: TYPE_kwargs
                           ) -> T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]:
        self.frozen = True
        files = self.collect(lambda x: True, True)
        return list(files.sources)

    @noKwargs
    @noPosargs
    @FeatureNew('source_set.all_dependencies() method', '0.52.0')
    def all_dependencies_method(self, state: ModuleState, args: T.List[TYPE_var], kwargs: TYPE_kwargs
                                ) -> T.List[dependencies.Dependency]:
        self.frozen = True
        files = self.collect(lambda x: True, True)
        return list(files.deps)

    @typed_pos_args('sourceset.apply', (build.ConfigurationData, dict))
    @typed_kwargs('sourceset.apply', KwargInfo('strict', bool, default=True))
    def apply_method(self, state: ModuleState, args: T.Tuple[T.Union[build.ConfigurationData, T.Dict[str, TYPE_var]]], kwargs: ApplyKw) -> SourceFilesObject:
        config_data = args[0]
        self.frozen = True
        strict = kwargs['strict']
        if isinstance(config_data, dict):
            def _get_from_config_data(key: str) -> bool:
                assert isinstance(config_data, dict), 'for mypy'
                if strict and key not in config_data:
                    raise InterpreterException(f'Entry {key} not in configuration dictionary.')
                return bool(config_data.get(key, False))
        else:
            config_cache: T.Dict[str, bool] = {}

            def _get_from_config_data(key: str) -> bool:
                assert isinstance(config_data, build.ConfigurationData), 'for mypy'
                if key not in config_cache:
                    if key in config_data:
                        config_cache[key] = bool(config_data.get(key)[0])
                    elif strict:
                        raise InvalidArguments(f'sourceset.apply: key "{key}" not in passed configuration, and strict set.')
                    else:
                        config_cache[key] = False
                return config_cache[key]

        files = self.collect(_get_from_config_data, False)
        res = SourceFilesObject(files)
        return res

class SourceFilesObject(ModuleObject):
    def __init__(self, files: SourceFiles):
        super().__init__()
        self.files = files
        self.methods.update({
            'sources': self.sources_method,
            'dependencies': self.dependencies_method,
        })

    @noPosargs
    @noKwargs
    def sources_method(self, state: ModuleState, args: T.List[TYPE_var], kwargs: TYPE_kwargs
                       ) -> T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]:
        return list(self.files.sources)

    @noPosargs
    @noKwargs
    def dependencies_method(self, state: ModuleState, args: T.List[TYPE_var], kwargs: TYPE_kwargs
                            ) -> T.List[dependencies.Dependency]:
        return list(self.files.deps)

class SourceSetModule(ExtensionModule):

    INFO = ModuleInfo('sourceset', '0.51.0')

    def __init__(self, interpreter: Interpreter):
        super().__init__(interpreter)
        self.methods.update({
            'source_set': self.source_set,
        })

    @noKwargs
    @noPosargs
    def source_set(self, state: ModuleState, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> SourceSetImpl:
        return SourceSetImpl(self.interpreter)

def initialize(interp: Interpreter) -> SourceSetModule:
    return SourceSetModule(interp)

"""

```