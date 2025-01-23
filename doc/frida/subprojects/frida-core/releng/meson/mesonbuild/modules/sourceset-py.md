Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Python file (`sourceset.py`) within the Frida project. The request asks for a functional breakdown, connections to reverse engineering, low-level/kernel aspects, logical reasoning, common user errors, and how a user might end up interacting with this code.

2. **Initial Code Scan (Keywords and Structure):**  Start by quickly scanning the code for key terms and the overall structure. I see:
    * Imports from `mesonbuild`: This immediately tells me it's part of the Meson build system.
    * Class definitions like `SourceSetRule`, `SourceFiles`, `SourceSetImpl`, `SourceFilesObject`, and `SourceSetModule`. This suggests an object-oriented design.
    * Method names like `add`, `add_all`, `all_sources`, `all_dependencies`, `apply`, `sources_method`, `dependencies_method`, `source_set`. These provide clues about the module's operations.
    * Type hints (`typing`, `typing_extensions`):  Indicates a focus on type safety and clarity.
    * Decorators like `@typed_pos_args`, `@typed_kwargs`, `@noPosargs`, `@noKwargs`, `@FeatureNew`:  These are crucial for understanding how the methods are called and what arguments they expect.
    * Docstrings: While not fully analyzed yet, the presence of docstrings is a good sign for understanding the intent.

3. **Focus on Core Functionality (Class `SourceSetImpl`):**  The `SourceSetImpl` class appears to be the central component. It has methods for adding sources and other source sets based on conditions. The `rules` attribute and `SourceSetRule` namedtuple suggest a way to manage conditional inclusion of sources.

4. **Analyze Key Methods:**

    * **`add_method`:** This method takes sources (files, generated files, dependencies) and conditions (`when`, `if_true`, `if_false`). It stores this information as a `SourceSetRule`. This seems fundamental for building up the source set. The error handling for positional and keyword arguments is also important.
    * **`add_all_method`:** This is similar to `add_method` but deals with adding entire other `SourceSetImpl` instances. This allows for hierarchical organization of sources.
    * **`collect`:** This is where the conditional logic comes together. It iterates through the rules and decides which sources and dependencies to include based on the evaluation of the conditions (`enabled_fn`). The `all_sources` flag hints at different levels of collection.
    * **`all_sources_method` and `all_dependencies_method`:** These are straightforward wrappers around `collect` to retrieve all sources and dependencies, respectively. The `frozen` attribute is important here, indicating that the source set can't be modified after these methods are called.
    * **`apply_method`:** This is the method that takes configuration data (either a `ConfigurationData` object or a dictionary) and uses it to evaluate the conditions in the rules. This connects the source set to the build configuration. The `strict` flag controls whether missing configuration keys are errors.

5. **Connect to Reverse Engineering:**  Now, think about how these functionalities relate to reverse engineering. Frida is a dynamic instrumentation tool, often used for reverse engineering. The ability to conditionally include source files based on build configurations or dependencies is useful in Frida's context:

    * **Conditional features:**  Frida might have features that are only included if certain dependencies are met (e.g., specific libraries for certain platforms). The `when` and dependency checks directly support this.
    * **Platform-specific code:** Different operating systems or architectures might require different source files. The conditional logic enables this.
    * **Optional components:** Some parts of Frida might be optional and only built if a specific configuration flag is set.

6. **Connect to Low-Level/Kernel Aspects:**  Consider how this relates to the underlying system:

    * **Dependencies:**  Dependencies often represent external libraries or system components. In Frida's case, these might be libraries for interacting with the target process, the operating system kernel, or specific frameworks like Android's.
    * **Build configuration:**  Build configurations define aspects like the target architecture, operating system, and compiler flags, which directly impact the low-level code that needs to be compiled.
    * **Generated files:** Frida might generate code dynamically based on the target environment or configuration.

7. **Logical Reasoning and Examples:**  Think through scenarios to illustrate the logic:

    * **Simple `add`:** If a configuration flag "enable_feature_x" is true, include `feature_x.c`.
    * **`add_all`:** If building for Android, include the entire "android_specific_sources" source set.
    * **`apply`:**  Demonstrate how passing a configuration dictionary or object influences the output of `apply`.

8. **User Errors:**  Consider common mistakes a developer using this module might make:

    * Confusing positional and keyword arguments.
    * Trying to modify the source set after calling `all_sources` or `apply`.
    * Not understanding the `strict` flag in `apply`.
    * Incorrectly specifying dependencies or configuration keys.

9. **User Journey (Debugging Clue):**  How would a developer even end up looking at this file? They would likely be:

    * Investigating build errors related to missing source files or dependencies.
    * Trying to understand how certain features are included or excluded from the build.
    * Modifying the build system to add new features or support new platforms.
    * Debugging issues with conditional compilation logic.

10. **Structure the Output:** Finally, organize the information into the requested categories (functionality, reverse engineering, low-level, logical reasoning, user errors, user journey) with clear explanations and examples. Use bullet points and code snippets for clarity.

**Self-Correction/Refinement:**

* **Initial thought:**  "This looks like just a way to manage source files."
* **Correction:**  "It's more than just listing files. The conditional logic based on dependencies and configuration is key, especially in a complex project like Frida."
* **Refinement:**  Emphasize the connection between the conditions and Frida's dynamic instrumentation nature (e.g., including agent code only when targeting a specific platform).

By following these steps, moving from a general understanding to specific details and considering the context of Frida and the Meson build system, a comprehensive analysis like the example provided can be constructed.
好的，让我们来详细分析 `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/sourceset.py` 这个文件的功能。

**文件功能概览**

这个 Python 文件定义了一个 Meson 构建系统的模块，名为 `sourceset`。它的主要目的是提供一种结构化的方式来管理和选择构建所需的源文件和依赖项。你可以把它看作是一个智能的源文件集合管理器，它允许你根据各种条件（例如，是否启用了某个配置选项，是否存在某个依赖项）动态地包含或排除特定的源文件或依赖项。

**核心概念和类**

* **`SourceSetRule`:**  表示一条规则，定义了在特定条件下应该包含哪些源文件、依赖项，以及当条件不满足时应该包含哪些源文件。
* **`SourceFiles`:** 一个简单的容器，用于存储最终选定的源文件和依赖项。
* **`SourceSet` (抽象基类) 和 `SourceSetImpl` (实现类):**  `SourceSetImpl` 是 `sourceset` 模块的核心，它维护了一组 `SourceSetRule`，并提供了方法来添加规则、查询所有源文件和依赖项，以及根据配置应用规则来生成最终的源文件和依赖项列表。
* **`SourceFilesObject`:** 一个 Meson 对象，封装了 `SourceFiles` 的结果，并提供可以被 Meson 构建系统使用的 `sources` 和 `dependencies` 方法。
* **`SourceSetModule`:**  Meson 模块的入口点，负责注册 `source_set` 方法，该方法用于创建 `SourceSetImpl` 的实例。

**功能详细列举**

1. **创建源文件集合 (`source_set` 方法):**  允许用户创建一个 `SourceSetImpl` 的实例，作为管理源文件的起点。

2. **添加条件规则 (`add_method`):**  可以向 `SourceSetImpl` 对象添加规则。每条规则可以指定：
   - `when`:  一组条件，可以是字符串（配置项的名称）或依赖项。当所有指定的配置项为真且所有依赖项都找到时，规则生效。
   - `if_true`: 当 `when` 条件为真时要包含的源文件和依赖项。
   - `if_false`: 当 `when` 条件为假时要包含的源文件。

3. **添加其他源文件集合 (`add_all_method`):**  可以将其他 `SourceSetImpl` 对象作为条件规则添加到当前 `SourceSetImpl` 中。

4. **获取所有源文件 (`all_sources_method`):** 返回 `SourceSetImpl` 中定义的所有可能的源文件列表，不考虑任何条件。

5. **获取所有依赖项 (`all_dependencies_method`):** 返回 `SourceSetImpl` 中定义的所有可能的依赖项列表，不考虑任何条件。

6. **应用配置并获取最终源文件和依赖项 (`apply_method`):**  这是核心功能。它接受一个配置数据对象（`build.ConfigurationData`）或一个字典作为输入，根据配置项的值和依赖项的查找结果，评估所有规则，并返回一个 `SourceFilesObject`，其中包含了最终需要构建的源文件和依赖项。

**与逆向方法的关系及举例说明**

Frida 是一个动态插桩工具，常用于逆向工程。`sourceset.py` 模块通过条件化的源文件管理，可以灵活地控制 Frida 构建的不同组件，这与逆向过程中的以下方面有关：

* **目标平台特定代码:**  在逆向不同平台（例如，Android、iOS、Linux、Windows）上的软件时，Frida 需要加载特定于目标平台的代理代码或运行时库。`sourceset` 可以根据目标平台的配置（例如，`target_os`）来包含相应的源文件。

   **举例:**
   假设在 Frida 的 `meson.build` 文件中，使用了 `sourceset` 模块：

   ```python
   core_sources = sourceset.source_set()
   core_sources.add(files('common.c', 'utils.c'))
   core_sources.add(files('platform_linux.c'), when='target_os == "linux"')
   core_sources.add(files('platform_windows.c'), when='target_os == "windows"')
   ```
   当构建目标为 Linux 时，`platform_linux.c` 会被包含；当构建目标为 Windows 时，`platform_windows.c` 会被包含。

* **可选功能模块:** Frida 的某些功能可能是可选的，只有在满足特定条件时才需要构建。`sourceset` 可以根据配置选项来包含这些可选模块的源文件。

   **举例:**
   ```python
   core_sources = sourceset.source_set()
   core_sources.add(files('core.c'))
   core_sources.add(files('debugger_support.c'), when='enable_debugger')
   ```
   只有当 `enable_debugger` 配置项为真时，`debugger_support.c` 才会被加入到构建中。

* **包含或排除特定版本的依赖项:**  某些逆向场景可能需要特定版本的库。`sourceset` 可以根据依赖项的查找结果来决定是否包含某些源文件。

   **举例:**
   ```python
   core_sources = sourceset.source_set()
   glib_dep = dependency('glib-2.0', required=False)
   core_sources.add(files('glib_integration.c'), when=[glib_dep])
   ```
   只有当找到 `glib-2.0` 依赖项时，`glib_integration.c` 才会被包含。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

`sourceset.py` 本身并不直接操作二进制底层或内核，但它管理着构建过程，而构建过程最终会生成与这些方面交互的代码。

* **二进制底层:**  选择不同的源文件可能意味着包含针对特定架构（如 ARM、x86）的代码。`sourceset` 可以根据目标架构来选择相应的底层实现。

   **举例:**
   ```python
   arch_specific_sources = sourceset.source_set()
   arch_specific_sources.add(files('arch_x86.s'), when='target_arch == "x86"')
   arch_specific_sources.add(files('arch_arm.s'), when='target_arch == "arm"')
   core_sources.add_all(arch_specific_sources)
   ```

* **Linux 内核:**  Frida 在 Linux 上运行时，可能需要与特定的内核接口交互。`sourceset` 可以根据是否在 Linux 环境下构建来包含相关的内核交互代码。

   **举例:**
   ```python
   linux_specific_sources = sourceset.source_set()
   linux_specific_sources.add(files('linux_ptrace.c'), when='target_os == "linux"')
   core_sources.add_all(linux_specific_sources)
   ```

* **Android 内核及框架:**  Frida 在 Android 上运行时，需要与 Android 的 Binder 机制、ART 虚拟机等进行交互。`sourceset` 可以根据目标是 Android 来包含这些特定于 Android 的代码。

   **举例:**
   ```python
   android_specific_sources = sourceset.source_set()
   android_specific_sources.add(files('android_binder.c'), when='target_os == "android"')
   android_specific_sources.add(files('android_art.cc'), when='target_os == "android"')
   core_sources.add_all(android_specific_sources)
   ```

**逻辑推理及假设输入与输出**

`sourceset.py` 的核心逻辑在于 `apply_method` 和 `collect` 方法。

**假设输入:**

1. **`SourceSetImpl` 对象 `my_sources` 包含以下规则:**
   - 规则 1: `when='enable_feature_a'`, `if_true=['file_a.c']`, `if_false=['dummy_a.c']`
   - 规则 2: `when='enable_feature_b'`, `if_true=['file_b.c']`
   - 规则 3: 无 `when`, `if_true=['common.c']`
2. **配置数据 `config_data` (字典):**
   - 情况 1: `{'enable_feature_a': True, 'enable_feature_b': False}`
   - 情况 2: `{'enable_feature_a': False, 'enable_feature_b': True}`

**逻辑推理:**

`apply_method` 会调用 `collect` 方法，`collect` 方法会遍历规则并根据配置数据评估 `when` 条件。

**输出:**

* **情况 1 (`{'enable_feature_a': True, 'enable_feature_b': False}`):**
   - 规则 1 的 `when` 为真，包含 `file_a.c`。
   - 规则 2 的 `when` 为假，不包含 `file_b.c`。
   - 规则 3 无条件，包含 `common.c`。
   - 最终 `sources` 为 `['file_a.c', 'common.c']`。

* **情况 2 (`{'enable_feature_a': False, 'enable_feature_b': True}`):**
   - 规则 1 的 `when` 为假，包含 `dummy_a.c`。
   - 规则 2 的 `when` 为真，包含 `file_b.c`。
   - 规则 3 无条件，包含 `common.c`。
   - 最终 `sources` 为 `['dummy_a.c', 'file_b.c', 'common.c']`。

**涉及用户或编程常见的使用错误及举例说明**

1. **混淆位置参数和关键字参数:** `add_method` 和 `add_all_method` 有特定的参数使用方式。

   **错误示例:**
   ```python
   core_sources.add(['my_file.c'], when='some_condition')  # 错误：when 应该作为关键字参数
   ```
   **正确示例:**
   ```python
   core_sources.add(files('my_file.c'), when='some_condition')
   ```

2. **在查询后尝试修改源文件集合:**  一旦调用了 `all_sources_method` 或 `apply_method`，`SourceSetImpl` 对象会被冻结，不能再添加规则。

   **错误示例:**
   ```python
   all_sources = core_sources.all_sources()
   core_sources.add(files('another_file.c'))  # 运行时会抛出 InvalidCode 异常
   ```

3. **`apply_method` 中 `strict=True` 时配置数据缺少必要的键:** 如果 `apply_method` 的 `strict` 参数设置为 `True`，但传递的配置数据中缺少规则中引用的配置项，则会抛出异常。

   **错误示例:**
   ```python
   core_sources.add(files('optional.c'), when='enable_optional')
   config = {}  # 缺少 'enable_optional' 键
   core_sources.apply(config, strict=True)  # 运行时会抛出 InterpreterException 异常
   ```

4. **条件表达式错误:** `when` 参数的值应该是字符串或依赖项列表。

   **错误示例:**
   ```python
   core_sources.add(files('my_file.c'), when=True)  # 错误：when 应该是配置项名称的字符串
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索**

用户通常不会直接编辑或调用 `sourceset.py` 中的代码。这个模块是 Meson 构建系统的一部分，供 Frida 的构建脚本 (`meson.build`) 使用。用户可能通过以下操作间接地触发对这个文件的使用：

1. **配置构建选项:** 用户通过 `meson configure` 命令配置 Frida 的构建选项，例如启用或禁用某些功能（`meson configure -Denable_debugger=true ..`）。这些配置选项的值会被传递到 `sourceset` 模块的 `apply_method` 中，影响最终选择的源文件。

2. **修改构建脚本 (`meson.build`):**  开发者可能会修改 Frida 的 `meson.build` 文件，使用 `sourceset` 模块来添加新的条件规则、源文件或依赖项。如果配置不当，可能会导致构建错误，需要查看 `sourceset.py` 的实现来理解其行为。

3. **查看构建日志:** 当构建过程中出现与源文件或依赖项相关的错误时，查看详细的构建日志可能会显示出 `sourceset` 模块的操作痕迹，例如哪些规则被激活，哪些文件被包含或排除。

4. **调试构建错误:** 如果构建失败，并且错误信息指向缺少某些源文件或依赖项，开发者可能会查看定义这些条件规则的 `meson.build` 文件，并可能需要理解 `sourceset.py` 的逻辑来排查问题。

5. **开发新的 Frida 模块或功能:**  当开发者向 Frida 添加新功能时，他们可能会使用 `sourceset` 模块来管理新功能的源文件，并根据不同的构建配置进行灵活控制。

作为调试线索，当遇到与源文件组织或条件编译相关的问题时，开发者应该关注 Frida 的 `meson.build` 文件中 `sourceset` 模块的使用方式，以及相关的构建配置选项。理解 `sourceset.py` 的代码可以帮助他们理解构建系统是如何根据配置选择源文件的，从而定位问题所在。

总而言之，`frida/subprojects/frida-core/releng/meson/mesonbuild/modules/sourceset.py` 是 Frida 构建系统中一个至关重要的组件，它通过提供灵活的条件化源文件管理，使得 Frida 能够适应不同的目标平台、构建配置和功能需求。理解这个模块的功能有助于理解 Frida 的构建过程，并在遇到构建问题时提供重要的调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/sourceset.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```