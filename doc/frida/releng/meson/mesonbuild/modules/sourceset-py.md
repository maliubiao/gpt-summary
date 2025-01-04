Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The core request is to analyze the `sourceset.py` file from Frida, understand its purpose, and connect it to reverse engineering, low-level details, and potential user errors. The prompt emphasizes providing examples and outlining how a user might reach this code.

**2. Initial Code Scan and High-Level Understanding:**

* **Keywords:** Look for recurring keywords like `SourceSet`, `add`, `apply`, `dependencies`, `sources`, `rules`, `when`, `if_true`, `if_false`. This immediately gives a sense of what the module manages: collections of source files and dependencies, potentially with conditional inclusion.
* **Meson Context:** The `mesonbuild` package namespace is a strong indicator that this code is part of the Meson build system. Knowing this is crucial for understanding the context of its usage. Frida uses Meson for its build system, connecting the dots.
* **Class Structure:**  Note the classes like `SourceSetRule`, `SourceFiles`, `SourceSetImpl`, and `SourceFilesObject`. This helps organize the functionality. The `Impl` suffix often suggests an implementation detail hidden behind an interface (the base `SourceSet`).
* **Method Names:**  The methods like `add_method`, `add_all_method`, `all_sources_method`, `apply_method` clearly indicate the actions one can perform with a `SourceSet`.

**3. Deeper Dive into Functionality:**

* **`SourceSetImpl`:** This appears to be the core class. The `rules` attribute and the `add_method` and `add_all_method` strongly suggest it manages a set of conditional rules for including sources and dependencies.
* **Conditional Logic:** The `when`, `if_true`, and `if_false` keywords in the `add_method` and `add_all_method` signatures are key. This signifies conditional inclusion based on configuration or dependencies.
* **`apply_method`:** This method seems to be where the conditions are evaluated. It takes `ConfigurationData` (from Meson) as input, implying that the rules are applied based on build-time configuration. The `strict` keyword suggests control over whether missing configuration keys are errors.
* **`collect` Method:** This internal method appears to be the engine for actually gathering the sources and dependencies based on the evaluated rules.
* **`SourceFilesObject`:**  This seems to be a simple container for the resulting sources and dependencies after applying the rules.

**4. Connecting to Reverse Engineering (Frida Context):**

This is where the understanding of Frida comes into play.

* **Dynamic Instrumentation:**  Frida's core purpose is dynamic instrumentation. Think about *why* conditional source inclusion would be useful in this context. Different platforms (Android, iOS, Linux, Windows), different architectures (ARM, x86), different build configurations (debug, release) often require different sets of source files or have different dependencies. The `sourceset` module elegantly handles this.
* **Example Scenarios:**  Brainstorm concrete examples. "On Android, include this specific hooking library." "When building for ARM, include these architecture-specific assembly files." This leads to specific examples demonstrating the connection.

**5. Connecting to Low-Level Details:**

* **Operating Systems and Architectures:**  The examples used for reverse engineering naturally lead to discussions about OS and architecture differences. This ties into the "when" conditions potentially checking for target platforms.
* **Kernel and Frameworks (Android):**  Since Frida is heavily used on Android, think about Android-specific components. The example of needing different sources for hooking at the framework level vs. the application level is a good illustration. The NDK is also a relevant low-level detail.
* **Binary Level:** While the code itself doesn't directly manipulate binaries, the *purpose* of Frida does. The source files managed by this module will eventually be compiled into binaries that *do* perform low-level operations.

**6. Logical Reasoning (Input and Output):**

* **Hypothesize a Scenario:**  Create a simplified scenario. "Imagine a build where we have a 'use_feature_x' option."
* **Trace the Logic:** Step through how the `add_method` would be used, how the `apply_method` would evaluate the condition, and what the resulting `SourceFilesObject` would contain. This clarifies the flow and makes the explanation more concrete.

**7. User/Programming Errors:**

* **Read the Error Messages:** The code itself provides clues. `InvalidCode('Tried to use \'add\' after querying the source set')` is a clear indicator of a potential usage error.
* **Think About Common Mistakes:**  Forgetting to pass configuration data, incorrect types, and using `add` after calling `all_sources` are common pitfalls when working with build systems.

**8. Tracing User Operations (Debugging Clue):**

* **Start with the `meson.build` File:** Users interact with Meson primarily through the `meson.build` file. Show how a `sourceset.source_set()` call would initiate the process.
* **Follow the Method Calls:**  Trace the sequence of calls: `add_method`, `apply_method`. Explain how the configuration data is passed in.
* **Explain the Error Scenario:**  Show how the user might have inadvertently called `all_sources_method` before a subsequent `add_method`, leading to the `InvalidCode` error.

**9. Structuring the Explanation:**

* **Start with a Summary:** Provide a concise overview of the module's purpose.
* **Break Down Functionality:** Explain each class and key method in detail.
* **Provide Clear Examples:**  Use concrete examples to illustrate the concepts.
* **Address Each Point from the Prompt:** Ensure all aspects of the request (reverse engineering, low-level details, logic, errors, user operations) are covered.
* **Use Clear and Concise Language:** Avoid overly technical jargon where possible.
* **Use Formatting (Headings, Bullet Points):** Make the explanation easy to read and understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just about managing source files."
* **Correction:** "It's about *conditional* management of source files based on build configuration and dependencies. This is important for cross-platform and feature-based builds."
* **Initial thought:** "The connection to reverse engineering is weak."
* **Correction:** "No, Frida is a reverse engineering tool. This module helps manage the source code *of* Frida, and the conditional logic is crucial for building Frida on different targets."
* **Ensure Examples are Relevant:**  Double-check that the examples directly relate to Frida's use cases and the functionality of the `sourceset` module.

By following these steps, combining code analysis with domain knowledge (Frida, Meson), and focusing on the specific requirements of the prompt, a comprehensive and informative explanation can be generated.
好的，让我们来详细分析一下 `frida/releng/meson/mesonbuild/modules/sourceset.py` 这个文件的功能。

**文件功能概览**

这个 Python 文件定义了一个名为 `sourceset` 的 Meson 构建系统模块。该模块的主要目的是为了 **有条件地管理和组织项目中的源文件和依赖项**。它可以根据特定的条件（例如，编译选项、依赖项是否存在等）来决定是否包含某些源文件或依赖项。这在构建多平台、多架构或具有可选功能的项目时非常有用。

**核心概念和类**

* **`SourceSetRule`**:  表示一条规则，定义了在特定条件下需要包含的源文件、依赖项以及其他源文件集。它包含以下信息：
    * `keys`:  一个字符串列表，表示需要满足的配置键（通常来自 Meson 的 `options`）。
    * `deps`:  一个 `dependencies.Dependency` 对象列表，表示需要满足的依赖项。
    * `sources`: 一个文件或字符串列表，表示当条件为真时要包含的源文件。
    * `extra_deps`: 额外的依赖项，即使这些依赖项不存在，也不会使条件为假。
    * `sourcesets`: 当条件为真时要包含的其他 `SourceSetImpl` 对象。
    * `if_false`: 当条件为假时要包含的源文件。

* **`SourceFiles`**: 一个简单的命名元组，用于存储最终收集到的源文件和依赖项的有序集合。

* **`SourceSet`**:  一个基类，主要用于避免循环引用。实际的实现是 `SourceSetImpl`。

* **`SourceSetImpl`**: 核心实现类，负责管理规则和收集源文件。它包含：
    * `rules`: 一个 `SourceSetRule` 对象列表。
    * `frozen`: 一个布尔值，指示该 `SourceSet` 是否已被冻结（在查询源文件后）。
    * 提供 `add`、`add_all`、`all_sources`、`all_dependencies` 和 `apply` 等方法来操作和查询源文件集。

* **`SourceFilesObject`**: 一个模块对象，用于封装 `SourceFiles` 结果，并提供访问源文件和依赖项的方法。

**功能详解和与逆向方法的关联**

1. **条件化添加源文件和依赖项 (`add_method`, `add_all_method`)**

   * **功能:** 允许开发者根据条件添加源文件、依赖项或其他源文件集。条件可以是配置选项 (`when` 参数中的字符串) 或依赖项的存在与否 (`when` 参数中的 `dependencies.Dependency` 对象)。
   * **逆向方法关联:** 在逆向工程中，目标程序可能在不同的平台、架构或操作系统版本上有不同的实现或依赖项。`sourceset` 可以用来管理这些差异：
      * **举例:**  假设 Frida 需要在 Android 上使用一个特定的 Hook 库 (例如 `libandroid-hook.so`)，而在 Linux 上使用另一个 Hook 库。可以使用 `sourceset` 来根据目标平台选择性地添加对应的源文件或依赖项：
         ```python
         android_hook_sources = files('android_hook.c')
         linux_hook_sources = files('linux_hook.c')
         android_dep = dependency('android-headers')
         linux_dep = dependency('glibc-dev')

         my_sources = sourceset.source_set()
         my_sources.add(android_hook_sources, when=[android_dep])
         my_sources.add(linux_hook_sources, when=['target_os_linux'])
         ```
         这里，`android_hook_sources` 只会在检测到 `android-headers` 依赖项时被添加，`linux_hook_sources` 只会在目标操作系统是 Linux 时被添加。

2. **查询所有源文件和依赖项 (`all_sources_method`, `all_dependencies_method`)**

   * **功能:**  返回当前 `SourceSet` 中所有已包含的源文件和依赖项的列表，忽略条件。
   * **逆向方法关联:**  虽然这个方法本身不直接参与条件判断，但在逆向工具的构建过程中，了解所有可能的源文件和依赖项有助于理解工具的完整功能范围和依赖关系。

3. **应用条件并获取最终的源文件和依赖项 (`apply_method`)**

   * **功能:**  根据提供的配置数据（`build.ConfigurationData` 或字典）来评估规则中的条件，并返回一个包含最终选定的源文件和依赖项的 `SourceFilesObject`。
   * **逆向方法关联:** 这是 `sourceset` 模块的核心功能，它模拟了构建过程中的条件选择。
      * **举例:** 假设有一个配置选项 `enable_feature_x`。`apply_method` 可以根据该选项的值来决定是否包含与该功能相关的源文件：
         ```python
         feature_x_sources = files('feature_x.c')

         my_sources = sourceset.source_set()
         my_sources.add(feature_x_sources, when=['enable_feature_x'])

         config_data = {'enable_feature_x': True} # 模拟配置数据
         selected_files = my_sources.apply(config_data)
         print(selected_files.sources()) # 输出将包含 feature_x.c
         ```
         在 Frida 的构建过程中，可能会有针对不同目标环境或功能的编译选项，`apply_method` 用于根据这些选项确定最终需要编译的源文件。

**与二进制底层，Linux, Android 内核及框架的知识的关联**

`sourceset` 模块本身是用 Python 编写的，并不直接涉及二进制底层操作或内核编程。但是，它所管理的源文件和依赖项最终会被编译成二进制代码，这些代码会与底层系统交互。

* **二进制底层:**  `sourceset` 管理的源文件可能包含汇编代码、C/C++ 代码等，这些代码在编译后会直接操作寄存器、内存地址等底层资源。例如，Frida 的一些核心 hook 功能可能需要直接操作 CPU 指令。
* **Linux 内核:** 当 Frida 在 Linux 上运行时，它可能需要与内核交互，例如通过 `ptrace` 系统调用进行进程注入和内存访问。`sourceset` 可能用于管理与特定内核版本或功能相关的源文件。
* **Android 内核及框架:**  Frida 在 Android 上的功能非常强大，涉及到与 Android 内核和框架的深入交互。
    * **内核:**  Frida 的内核模块（如果有）需要与 Android 内核进行交互，可能涉及到设备驱动、内核 Hook 等。`sourceset` 可以管理这些内核模块的源文件。
    * **框架:** Frida 经常需要在 Android 用户空间框架层进行 Hook，例如 Hook Java 方法或 Native 函数。这可能依赖于 Android 的运行时环境 (ART) 或 Binder 机制。`sourceset` 可以用于管理与特定 Android 版本或设备架构相关的框架层 Hook 代码。
    * **NDK 依赖:** Frida 在 Android 上可能依赖 Android NDK 提供的库。`sourceset` 可以根据目标架构或 Android 版本来管理 NDK 依赖项。

**逻辑推理 (假设输入与输出)**

假设我们有以下 `meson.build` 文件片段：

```python
project('my_frida_module', 'cpp')

option('enable_feature_a', type : 'boolean', value : false)
option('target_arch', type : 'string', choices : ['arm', 'x86'], value : 'arm')

if get_option('target_arch') == 'arm'
  arch_dep = dependency('arm_specific_lib')
else
  arch_dep = dependency('x86_specific_lib')

feature_a_sources = files('feature_a.c')
common_sources = files('common.c')
arm_specific_sources = files('arch_arm.c')
x86_specific_sources = files('arch_x86.c')

my_sources = sourceset.source_set()
my_sources.add(feature_a_sources, when=['enable_feature_a'])
my_sources.add(arm_specific_sources, when=[arch_dep])
my_sources.add(x86_specific_sources, when=['target_arch=x86'])
my_sources.add(common_sources)

config_data = {
    'enable_feature_a': meson.is_option_enabled('enable_feature_a'),
    'target_arch': get_option('target_arch')
}

final_sources = my_sources.apply(config_data)
executable('my_tool', final_sources.sources())
```

**假设输入:**

* `enable_feature_a` 选项设置为 `true`。
* `target_arch` 选项设置为 `x86`。
* 系统上安装了 `x86_specific_lib` 依赖，但没有安装 `arm_specific_lib`。

**逻辑推理和预期输出:**

1. **`my_sources.add(feature_a_sources, when=['enable_feature_a'])`**: 由于 `enable_feature_a` 为 `true`，`feature_a.c` 将会被添加到源文件集中。
2. **`my_sources.add(arm_specific_sources, when=[arch_dep])`**:  由于 `target_arch` 是 `x86`，`arch_dep` 将会是 `x86_specific_lib` 依赖。虽然条件中的 `arch_dep`  在概念上是 `x86_specific_lib`，但规则的触发是基于依赖项是否找到。由于假设系统中安装了 `x86_specific_lib`，即使选项不是 'arm'，这个 `add` 也会因为依赖存在而生效，这可能不是预期的行为，需要注意 `when` 条件的设置。更好的做法是直接使用字符串条件 `'target_arch=arm'`。
3. **`my_sources.add(x86_specific_sources, when=['target_arch=x86'])`**: 由于 `target_arch` 是 `x86`，`arch_x86.c` 将会被添加到源文件集中。
4. **`my_sources.add(common_sources)`**: 没有条件，`common.c` 将始终被添加。

**预期 `final_sources.sources()` 输出 (顺序可能不同):**

```
['feature_a.c', 'arch_x86.c', 'common.c']
```

**注意:** 上述逻辑推理中，关于 `arch_dep` 的处理可能存在歧义，取决于 Meson 如何处理依赖项作为 `when` 条件。更清晰的做法是使用字符串条件来匹配选项值。

**用户或编程常见的使用错误**

1. **在查询源文件后尝试添加 (`add_method`, `add_all_method`)**

   * **错误:** 用户在调用了 `all_sources_method` 或 `apply_method` 冻结了 `SourceSet` 后，尝试调用 `add_method` 或 `add_all_method`。
   * **示例:**
     ```python
     my_sources = sourceset.source_set()
     # ... 添加一些源文件 ...
     all_sources = my_sources.all_sources()  # 冻结了 my_sources
     my_sources.add(files('another.c')) # 抛出 InvalidCode 异常
     ```
   * **原因:**  一旦开始查询源文件，就意味着构建配置已经确定，不应该再修改源文件集。

2. **`add` 方法同时使用位置参数和关键字参数**

   * **错误:**  用户在调用 `add_method` 时，既传递了位置参数（源文件列表），又使用了 `if_true`、`if_false` 或 `when` 等关键字参数来指定源文件。
   * **示例:**
     ```python
     my_sources = sourceset.source_set()
     my_sources.add(files('main.c'), if_true=files('optional.c')) # 抛出 InterpreterException
     ```
   * **原因:**  `add` 方法的设计是，要么使用位置参数提供默认的源文件，要么使用关键字参数来条件化地添加。

3. **在 `apply` 方法中使用了 `strict=True` 但配置数据中缺少某些键**

   * **错误:**  用户在调用 `apply_method` 时设置了 `strict=True`，但传递的配置数据字典或 `ConfigurationData` 对象中缺少了某些在 `when` 条件中使用的键。
   * **示例:**
     ```python
     my_sources = sourceset.source_set()
     my_sources.add(files('special.c'), when=['missing_option'])
     config_data = {}  # 缺少 'missing_option'
     my_sources.apply(config_data, strict=True) # 抛出 InterpreterException 或 InvalidArguments
     ```
   * **原因:** 当 `strict=True` 时，`apply_method` 会检查所有 `when` 条件中用到的配置键是否都存在于提供的配置数据中。

4. **`add_all` 方法同时使用位置参数和关键字参数**

   * **错误:**  类似于 `add` 方法，在调用 `add_all_method` 时，既传递了位置参数（源文件集列表），又使用了 `if_true` 或 `when` 等关键字参数。
   * **示例:**
     ```python
     my_sources = sourceset.source_set()
     another_set = sourceset.source_set()
     my_sources.add_all(another_set, if_true=[sourceset.source_set()]) # 抛出 InterpreterException
     ```

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户编写 `meson.build` 文件:** 用户首先会编写 `meson.build` 文件来定义项目的构建规则。他们可能会使用 `sourceset.source_set()` 创建一个 `SourceSet` 对象。
2. **使用 `add` 或 `add_all` 添加源文件:**  用户根据项目的需求，使用 `add` 或 `add_all` 方法向 `SourceSet` 中添加源文件和依赖项，并可能设置条件。
3. **配置构建选项 (可选):** 用户可能在 `meson_options.txt` 文件中定义了构建选项，或者在命令行中使用 `-D` 参数来配置选项的值。这些选项会影响 `sourceset` 的条件判断。
4. **调用 `apply` 方法:** 在配置好 `SourceSet` 后，用户通常会调用 `apply` 方法，并传入当前的配置数据（通常来自 `meson.get_options()` 或手动构建）。
5. **将 `apply` 的结果用于构建目标:** `apply` 方法返回的 `SourceFilesObject` 中的源文件列表会被用于定义可执行文件、库或其他构建目标。
6. **运行 `meson compile`:** 用户运行 `meson compile` 命令来执行构建过程。Meson 会解析 `meson.build` 文件，执行 `sourceset` 模块的代码，并根据配置选择合适的源文件进行编译。

**作为调试线索:**

* **检查 `meson.build` 文件:**  查看 `sourceset` 的使用方式，特别是 `add` 和 `apply` 方法的调用，以及 `when` 条件的设置。
* **打印配置数据:** 在调用 `apply` 之前，打印出传递给 `apply` 方法的配置数据，确保它包含了预期的键和值。
* **逐步调试:** 如果可能，可以使用 Meson 的调试功能或在 `sourceset.py` 文件中添加打印语句，来跟踪代码的执行流程，查看条件是否按预期评估。
* **查看 Meson 的日志:** Meson 在构建过程中会生成日志，可以从中找到关于依赖项解析和条件评估的信息。
* **确认依赖项状态:** 如果 `when` 条件中使用了依赖项，需要确认这些依赖项是否被正确找到。

总而言之，`frida/releng/meson/mesonbuild/modules/sourceset.py` 提供了一种强大而灵活的方式来管理 Frida 项目的源文件和依赖项，使其能够适应不同的构建配置和目标平台。理解其功能和使用方式对于调试 Frida 的构建过程至关重要。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/sourceset.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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