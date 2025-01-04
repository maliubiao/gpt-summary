Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `dependencyfallbacks.py` file within the Frida project. It specifically asks about:

* **Functionality:** What does this code do?
* **Relevance to Reversing:** How does it relate to reverse engineering?
* **Low-Level Details:** Does it touch on binary, kernel, or framework concepts?
* **Logical Reasoning:** Are there clear input/output scenarios we can analyze?
* **Common User Errors:** What mistakes might a user make while using this?
* **Debugging Context:** How might a user end up at this code during debugging?

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for key terms and structural elements:

* **Class Name:** `DependencyFallbacksHolder` – This immediately suggests the code is about handling situations where a dependency isn't found and alternative approaches (fallbacks) are needed.
* **Imports:** `dependencies`, `build`, `WrapMode`, `mesonlib`, `Dependency`, `NotFoundDependency`, `InterpreterException`, `InvalidArguments`. These imports hint at interactions with Meson's build system, dependency management, and error handling.
* **Methods:** `set_fallback`, `_subproject_impl`, `_do_dependency_cache`, `_do_dependency`, `_do_existing_subproject`, `_do_subproject`, `lookup`, etc. These method names give clues about the steps involved in finding a dependency.
* **Key Variables:** `names`, `subproject_name`, `subproject_varname`, `forcefallback`, `nofallback`, `allow_fallback`. These variables indicate different configuration options and states.
* **Logging:** `mlog.log`, `mlog.warning`. This indicates that the code provides some level of logging and debugging information.
* **Version Handling:**  `version_compare_many`, `get_version`. This suggests the code deals with dependency version requirements.

**3. Deeper Dive into Functionality (Method by Method):**

Now, go through each important method to understand its purpose:

* **`__init__`:** Initializes the `DependencyFallbacksHolder` with dependency names, machine architecture, fallback settings, etc. It also performs basic input validation.
* **`set_fallback`:**  Handles the older `fallback` keyword for specifying a subproject to use as a fallback.
* **`_subproject_impl`:**  Internally sets the subproject name and variable name for the fallback.
* **`_do_dependency_cache`:** Checks if the dependency has already been found and cached.
* **`_do_dependency`:** Attempts to find the dependency as an external system dependency.
* **`_do_existing_subproject`:** If a subproject is already configured, tries to get the dependency from it.
* **`_do_subproject`:** Configures and builds the fallback subproject to obtain the dependency. This is a crucial part.
* **`_get_subproject`:**  Retrieves a configured subproject.
* **`_get_subproject_dep`:** Gets the dependency from a configured subproject, handling version checks and logging.
* **`lookup`:** The main entry point for looking up a dependency. It orchestrates the different lookup strategies (cache, external, subproject).

**4. Connecting to Reverse Engineering:**

At this point, consider how the functionality relates to reverse engineering:

* **Frida's Context:** Frida is a dynamic instrumentation toolkit. Reverse engineers use it to inspect and modify running processes. Dependencies are *essential* for building Frida itself.
* **Handling Missing Libraries:**  When building Frida (or projects that use Frida components), the build system needs to find necessary libraries. `dependencyfallbacks.py` helps handle situations where these libraries aren't readily available on the target system. The fallback mechanism allows building against a known, potentially bundled version of the library.
* **Subproject Fallbacks:** The ability to build a subproject as a fallback is directly relevant. This allows including a specific version of a library known to work with Frida, avoiding potential compatibility issues with system-installed versions.

**5. Identifying Low-Level and System Concepts:**

Think about what kind of dependencies might be involved and where they come from:

* **External Dependencies:** These are libraries installed on the system (Linux, Android, etc.). This connects to OS package management, library linking, and the underlying operating system.
* **Subproject Dependencies:** These are often bundled or built as part of the Frida build process. This relates to how software projects are organized and built.
* **Static vs. Shared Libraries:** The code mentions `default_library`. This is a core concept in how software is linked and loaded, crucial for understanding binary structure and execution.
* **Target Machines:** The `for_machine` parameter highlights the need to build for different architectures (x86, ARM, etc.), a fundamental consideration in cross-platform development and reverse engineering on various devices.

**6. Crafting Logical Reasoning Examples:**

Come up with simple scenarios to illustrate the flow:

* **Scenario 1 (Cache Hit):** A common dependency is already cached. The code should retrieve it quickly.
* **Scenario 2 (External Found):** A standard dependency is present on the system. The code should find it.
* **Scenario 3 (Subproject Fallback):** An external dependency is missing, so the code builds a subproject to provide it.
* **Scenario 4 (Fallback Forced):** The user explicitly forces the use of the subproject fallback.

For each scenario, define the *input* (dependency name, existing libraries, force_fallback setting) and the expected *output* (the found dependency object).

**7. Spotting Potential User Errors:**

Consider how a user might misconfigure things:

* **Incorrect Fallback Names:** Specifying the wrong subproject or variable name.
* **Version Mismatches:** Requesting a specific version that the fallback subproject doesn't provide.
* **Conflicting Options:** Using mutually exclusive options like `fallback` and `allow_fallback`.
* **Missing Required Dependencies:**  Not having the necessary build tools or dependencies to build the fallback subproject.

**8. Tracing User Operations (Debugging Context):**

Imagine a user encountering an issue during the build process. How might they end up looking at this file?

* **Build Errors:** The build system might complain about a missing dependency.
* **Configuration Issues:**  Problems with finding a specific library.
* **Debugging Build Scripts:** Developers might be examining the Meson build files (`meson.build`) and tracing the execution flow to understand how dependencies are resolved. `dependencyfallbacks.py` is a key part of this resolution process.
* **Wrap Files:** Users might be investigating wrap files (`.wrap`) which define how to obtain dependencies.

**9. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original prompt with specific examples and explanations. Use headings and bullet points to improve readability. Ensure the language is precise and avoids overly technical jargon where possible, while still conveying the necessary information. Review and refine the answer for clarity and accuracy.
这个 `dependencyfallbacks.py` 文件是 Frida 构建系统中 Meson 构建脚本的一部分，它的主要功能是**管理依赖项的查找和处理，特别是当首选的外部依赖项找不到时，它会尝试使用子项目作为回退方案。**

让我们详细列举一下它的功能，并结合你提出的几个方面进行说明：

**1. 功能列举:**

* **定义依赖回退策略:**  `DependencyFallbacksHolder` 类封装了查找依赖项的逻辑。它允许指定一个或多个依赖项的名称，并定义在找不到这些外部依赖项时应该如何回退到构建一个子项目来提供该依赖。
* **查找外部依赖项:**  它首先尝试使用 `dependencies.find_external_dependency` 函数在系统上查找指定的外部依赖项。
* **使用子项目作为回退:** 如果外部依赖项找不到，并且配置了回退子项目，它会尝试配置和构建该子项目，并从该子项目中获取所需的依赖。
* **缓存依赖项信息:** 它利用 Meson 的依赖项缓存机制 (`self.coredata.deps`) 来存储和检索已找到的依赖项信息，避免重复查找。
* **处理依赖项版本要求:**  它可以处理依赖项的版本要求 (通过 `version` 关键字参数)，并检查找到的依赖项版本是否满足要求。
* **处理不同构建机器的需求:** 它区分了宿主机 (host machine) 和目标机 (target machine) 的依赖项需求 (`self.for_machine`)，这对于交叉编译非常重要。
* **支持依赖项的模块化:** 可以指定依赖项的模块 (通过 `modules` 关键字参数)。
* **处理依赖项的覆盖:**  它考虑了用户通过 `meson.override_dependency()` 手动覆盖依赖项的情况。
* **处理 `wrap_mode` 和 `force_fallback_for` 选项:**  可以根据 Meson 的 `wrap_mode` 设置（如强制回退或禁用回退）和 `force_fallback_for` 选项来决定是否应该强制使用子项目回退。
* **提供详细的日志信息:** 使用 `mlog` 模块记录依赖项查找的过程，包括是否找到、从哪里找到以及版本信息。
* **处理 `static` 关键字:**  如果指定了 `static: true`，则在构建回退子项目时可能会自动添加 `default_options: ['default_library=static']`。

**2. 与逆向方法的关系及举例:**

Frida 本身就是一个动态插桩工具，广泛应用于逆向工程。 `dependencyfallbacks.py` 文件确保了 Frida 能够成功构建，而构建成功是使用 Frida 进行逆向的前提。

**举例说明:**

假设 Frida 依赖于 `glib-2.0` 库，但在某些嵌入式 Linux 系统上可能没有预装这个库。Frida 的构建脚本可能会这样定义依赖回退：

```python
dependency_fallbacks('glib-2.0', fallback='glib')
```

这里，`'glib-2.0'` 是外部依赖项的名称，`'glib'` 是一个子项目的名称。

* **逆向工程师在目标设备上使用 Frida 时:**  Frida 需要 `glib-2.0` 的某些功能。如果构建 Frida 时使用了上述回退策略，并且目标系统上没有 `glib-2.0`，那么 Frida 将会链接到构建时编译的 `glib` 子项目提供的库。这保证了 Frida 即使在缺少某些标准库的环境下也能运行。
* **构建 Frida 用于 Android 环境:** Android 系统可能没有标准的 Linux 发行版提供的 `glib-2.0`。通过使用子项目回退，Frida 可以在构建过程中包含一个针对 Android 平台编译的 `glib` 库，从而能在 Android 设备上运行。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制底层:**
    * **链接 (Linking):**  依赖项管理的核心是链接过程。无论是找到的外部库还是子项目构建的库，最终都需要链接到 Frida 的二进制文件中。`dependencyfallbacks.py` 影响着链接器最终选择哪个库。
    * **静态库 vs. 共享库:** 文件中处理 `static` 关键字表明了对静态库和共享库的考虑。这直接关系到最终生成的可执行文件或库的结构和加载方式。
* **Linux:**
    * **动态链接器 (Dynamic Linker):**  当 Frida 运行时，Linux 的动态链接器负责加载 Frida 依赖的共享库。如果 Frida 使用了回退的子项目库，那么动态链接器会加载子项目构建的共享库。
    * **标准库:**  `glib-2.0` 这样的库是许多 Linux 应用程序的基础。处理这些标准库的依赖是构建系统的常见任务。
* **Android 内核及框架:**
    * **Bionic Libc:** Android 使用 Bionic Libc 而不是标准的 glibc。回退机制允许 Frida 在 Android 上构建时使用兼容 Bionic 的库。
    * **Android NDK:**  当为 Android 构建 Frida 时，可能需要使用 Android NDK 提供的工具链和库。子项目回退可以集成 NDK 构建的库。
    * **Framework 依赖:**  Frida Agent 可能会依赖 Android framework 的某些组件。构建系统需要能够找到或提供这些依赖。

**举例说明:**

* **外部依赖查找失败:**  在为嵌入式 Linux 构建 Frida 时，如果系统上没有安装 `libusb` 开发包，`dependencyfallbacks.py` 将会指示 Meson 构建 `libusb` 子项目，并将编译好的 `libusb` 库链接到 Frida。这涉及到底层的库编译和链接过程。
* **处理 Android 特有依赖:**  构建 Frida Android Agent 时，可能需要依赖 Android 的 `libcutils` 或其他 framework 库。如果这些库在标准路径下找不到，回退机制可能会尝试使用 NDK 中提供的版本。

**4. 逻辑推理、假设输入与输出:**

**假设输入:**

* `names`: `['openssl']` (需要查找 OpenSSL 依赖)
* `for_machine`:  表示目标机器是 Linux x86_64
* `allow_fallback`: `True` (允许回退)
* `subproject_name`: `'openssl-cmake'` (回退子项目的名称)
* 系统上没有安装 `openssl` 开发包。

**逻辑推理过程:**

1. `lookup` 方法被调用。
2. 首先尝试使用 `_do_dependency_cache` 查找缓存，假设没有找到。
3. 接着尝试使用 `_do_dependency` 在系统上查找 `openssl`。
4. 由于系统上没有安装 `openssl` 开发包，`_do_dependency` 返回 `None` 或一个表示未找到的依赖对象。
5. 因为配置了回退子项目 `'openssl-cmake'`，并且 `allow_fallback` 为 `True`，所以会调用 `_do_subproject`。
6. `_do_subproject` 会配置并构建 `openssl-cmake` 子项目。
7. 构建成功后，`_get_subproject_dep` 会尝试从子项目中获取 OpenSSL 依赖。
8. 假设子项目成功构建并导出了 OpenSSL 依赖，`_get_subproject_dep` 将返回一个表示 OpenSSL 依赖的对象，该对象指向子项目构建的库。

**假设输出:**

一个 `Dependency` 对象，其属性指示：

* 依赖项名称: `openssl`
* 依赖项来源: 子项目 `'openssl-cmake'`
* 包含子项目构建的 OpenSSL 库的路径和链接信息。

**5. 涉及用户或编程常见的使用错误及举例:**

* **错误的子项目名称:** 用户在 `meson.build` 文件中指定了一个不存在的子项目作为回退：
    ```python
    dependency_fallbacks('libfoo', fallback='nonexistent_subproject')
    ```
    这会导致构建失败，并可能抛出 `InterpreterException`。
* **回退子项目构建失败:**  回退的子项目本身可能由于配置错误、缺少依赖等原因构建失败。这将导致依赖项查找失败。
* **循环依赖:**  如果回退子项目依赖于正在尝试查找的依赖项，则可能导致循环依赖，最终导致构建失败。
* **版本冲突:**  外部依赖项的版本和回退子项目提供的版本不兼容，可能导致运行时错误。虽然 `dependencyfallbacks.py` 会进行版本检查，但用户可能没有正确指定版本要求。
* **不正确的 `fallback` 语法:**  早期版本的 Meson 使用 `fallback` 关键字，如果用户使用了不正确的语法，例如提供了错误数量的参数，会导致 `InterpreterException`。
* **混淆 `fallback` 和 `allow_fallback`:** 用户可能不理解 `fallback` 和 `allow_fallback` 的区别，导致配置错误。例如，同时设置了 `fallback` 和 `allow_fallback=False`。

**举例说明:**

用户在 `meson.build` 中写了：

```python
foo_dep = dependency('libfoo', fallback : ['libfoo-provided', 'my_libfoo'])
```

但是，在 `subprojects` 目录下并没有名为 `libfoo-provided` 的子项目，或者子项目导出的变量名不是 `my_libfoo`。  这将导致构建过程在查找 `libfoo` 时，尝试访问一个不存在的子项目或变量，最终报错。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置 `meson.build`:** 用户编写 `meson.build` 文件，其中使用了 `dependency()` 或 `dependency_fallbacks()` 函数来声明项目依赖。 例如：
   ```python
   my_lib = dependency_fallbacks('mylibrary', fallback : ['mylibrary-fallback', 'mylib'])
   ```
2. **用户运行 `meson setup builddir`:**  用户执行 Meson 的配置命令，Meson 开始解析 `meson.build` 文件。
3. **Meson 执行到 `dependency_fallbacks()`:** 当 Meson 的解释器执行到 `dependency_fallbacks()` 函数时，会创建 `DependencyFallbacksHolder` 对象。
4. **查找外部依赖项:**  `DependencyFallbacksHolder` 对象会尝试查找名为 `mylibrary` 的外部依赖项。
5. **外部依赖项未找到:** 如果系统上没有安装 `mylibrary` 的开发包，查找会失败。
6. **尝试回退:**  由于配置了 `fallback`，`DependencyFallbacksHolder` 会尝试查找名为 `mylibrary-fallback` 的子项目，并期望该子项目导出一个名为 `mylib` 的依赖项对象。
7. **子项目配置或构建:** Meson 会尝试配置和构建 `mylibrary-fallback` 子项目。
8. **调试线索:** 如果在上述任何步骤中出现问题，用户可能会查看 `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py` 文件作为调试线索：
   * **构建错误提示:** 如果构建过程中出现关于找不到依赖项或子项目构建失败的错误，用户可能会查看这个文件来理解 Meson 是如何处理依赖回退的。
   * **查看日志:** Meson 的日志输出可能会指示问题出在依赖项查找或子项目构建阶段。用户查看 `dependencyfallbacks.py` 的代码可以了解日志信息的来源和含义。
   * **理解回退逻辑:** 用户可能想深入了解 Meson 是如何实现依赖回退的，以及各个参数的作用，从而打开这个文件查看源代码。
   * **检查变量值:**  在某些 IDE 或调试器中，用户可能会设置断点或打印 `DependencyFallbacksHolder` 对象的属性值，以了解当前的依赖项查找状态。

总而言之，`dependencyfallbacks.py` 是 Frida 构建系统中至关重要的一个环节，它负责处理依赖项的查找和回退，确保 Frida 能够在不同的环境下成功构建。理解它的功能有助于理解 Frida 的构建过程，并在遇到依赖问题时提供调试线索。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from __future__ import annotations

from .interpreterobjects import extract_required_kwarg
from .. import mlog
from .. import dependencies
from .. import build
from ..wrap import WrapMode
from ..mesonlib import OptionKey, extract_as_list, stringlistify, version_compare_many, listify
from ..dependencies import Dependency, DependencyException, NotFoundDependency
from ..interpreterbase import (MesonInterpreterObject, FeatureNew,
                               InterpreterException, InvalidArguments)

import typing as T
if T.TYPE_CHECKING:
    from .interpreter import Interpreter
    from ..interpreterbase import TYPE_nkwargs, TYPE_nvar
    from .interpreterobjects import SubprojectHolder
    from ..utils.universal import MachineChoice


class DependencyFallbacksHolder(MesonInterpreterObject):
    def __init__(self, interpreter: 'Interpreter', names: T.List[str], for_machine: MachineChoice,
                 allow_fallback: T.Optional[bool] = None,
                 default_options: T.Optional[T.Dict[OptionKey, str]] = None) -> None:
        super().__init__(subproject=interpreter.subproject)
        self.interpreter = interpreter
        self.subproject = interpreter.subproject
        self.for_machine = for_machine
        self.coredata = interpreter.coredata
        self.build = interpreter.build
        self.environment = interpreter.environment
        self.wrap_resolver = interpreter.environment.wrap_resolver
        self.allow_fallback = allow_fallback
        self.subproject_name: T.Optional[str] = None
        self.subproject_varname: T.Optional[str] = None
        self.subproject_kwargs = {'default_options': default_options or {}}
        self.names: T.List[str] = []
        self.forcefallback: bool = False
        self.nofallback: bool = False
        for name in names:
            if not name:
                raise InterpreterException('dependency_fallbacks empty name \'\' is not allowed')
            if '<' in name or '>' in name or '=' in name:
                raise InvalidArguments('Characters <, > and = are forbidden in dependency names. To specify'
                                       'version\n requirements use the \'version\' keyword argument instead.')
            if name in self.names:
                raise InterpreterException(f'dependency_fallbacks name {name!r} is duplicated')
            self.names.append(name)
        self._display_name = self.names[0] if self.names else '(anonymous)'

    def set_fallback(self, fbinfo: T.Optional[T.Union[T.List[str], str]]) -> None:
        # Legacy: This converts dependency()'s fallback kwargs.
        if fbinfo is None:
            return
        if self.allow_fallback is not None:
            raise InvalidArguments('"fallback" and "allow_fallback" arguments are mutually exclusive')
        fbinfo = stringlistify(fbinfo)
        if len(fbinfo) == 0:
            # dependency('foo', fallback: []) is the same as dependency('foo', allow_fallback: false)
            self.allow_fallback = False
            return
        if len(fbinfo) == 1:
            FeatureNew.single_use('Fallback without variable name', '0.53.0', self.subproject)
            subp_name, varname = fbinfo[0], None
        elif len(fbinfo) == 2:
            subp_name, varname = fbinfo
        else:
            raise InterpreterException('Fallback info must have one or two items.')
        self._subproject_impl(subp_name, varname)

    def _subproject_impl(self, subp_name: str, varname: str) -> None:
        assert self.subproject_name is None
        self.subproject_name = subp_name
        self.subproject_varname = varname

    def _do_dependency_cache(self, kwargs: TYPE_nkwargs, func_args: TYPE_nvar, func_kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        name = func_args[0]
        cached_dep = self._get_cached_dep(name, kwargs)
        if cached_dep:
            self._verify_fallback_consistency(cached_dep)
        return cached_dep

    def _do_dependency(self, kwargs: TYPE_nkwargs, func_args: TYPE_nvar, func_kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        # Note that there is no df.dependency() method, this is called for names
        # given as positional arguments to dependency_fallbacks(name1, ...).
        # We use kwargs from the dependency() function, for things like version,
        # module, etc.
        name = func_args[0]
        self._handle_featurenew_dependencies(name)
        dep = dependencies.find_external_dependency(name, self.environment, kwargs)
        if dep.found():
            identifier = dependencies.get_dep_identifier(name, kwargs)
            self.coredata.deps[self.for_machine].put(identifier, dep)
            return dep
        return None

    def _do_existing_subproject(self, kwargs: TYPE_nkwargs, func_args: TYPE_nvar, func_kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        subp_name = func_args[0]
        varname = self.subproject_varname
        if subp_name and self._get_subproject(subp_name):
            return self._get_subproject_dep(subp_name, varname, kwargs)
        return None

    def _do_subproject(self, kwargs: TYPE_nkwargs, func_args: TYPE_nvar, func_kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        if self.forcefallback:
            mlog.log('Looking for a fallback subproject for the dependency',
                     mlog.bold(self._display_name), 'because:\nUse of fallback dependencies is forced.')
        elif self.nofallback:
            mlog.log('Not looking for a fallback subproject for the dependency',
                     mlog.bold(self._display_name), 'because:\nUse of fallback dependencies is disabled.')
            return None
        else:
            mlog.log('Looking for a fallback subproject for the dependency',
                     mlog.bold(self._display_name))

        # dependency('foo', static: true) should implicitly add
        # default_options: ['default_library=static']
        static = kwargs.get('static')
        default_options = func_kwargs.get('default_options', {})
        if static is not None and 'default_library' not in default_options:
            default_library = 'static' if static else 'shared'
            mlog.log(f'Building fallback subproject with default_library={default_library}')
            default_options[OptionKey('default_library')] = default_library
            func_kwargs['default_options'] = default_options

        # Configure the subproject
        subp_name = self.subproject_name
        varname = self.subproject_varname
        func_kwargs.setdefault('version', [])
        if 'default_options' in kwargs and isinstance(kwargs['default_options'], str):
            func_kwargs['default_options'] = listify(kwargs['default_options'])
        self.interpreter.do_subproject(subp_name, func_kwargs)
        return self._get_subproject_dep(subp_name, varname, kwargs)

    def _get_subproject(self, subp_name: str) -> T.Optional[SubprojectHolder]:
        sub = self.interpreter.subprojects[self.for_machine].get(subp_name)
        if sub and sub.found():
            return sub
        return None

    def _get_subproject_dep(self, subp_name: str, varname: str, kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        # Verify the subproject is found
        subproject = self._get_subproject(subp_name)
        if not subproject:
            self._log_found(False, subproject=subp_name, extra_args=[mlog.blue('(subproject failed to configure)')])
            return None

        # The subproject has been configured. If for any reason the dependency
        # cannot be found in this subproject we have to return not-found object
        # instead of None, because we don't want to continue the lookup on the
        # system.

        # Check if the subproject overridden at least one of the names we got.
        cached_dep = None
        for name in self.names:
            cached_dep = self._get_cached_dep(name, kwargs)
            if cached_dep:
                break

        # If we have cached_dep we did all the checks and logging already in
        # self._get_cached_dep().
        if cached_dep:
            self._verify_fallback_consistency(cached_dep)
            return cached_dep

        # Legacy: Use the variable name if provided instead of relying on the
        # subproject to override one of our dependency names
        if not varname:
            # If no variable name is specified, check if the wrap file has one.
            # If the wrap file has a variable name, better use it because the
            # subproject most probably is not using meson.override_dependency().
            for name in self.names:
                varname = self.wrap_resolver.get_varname(subp_name, name)
                if varname:
                    break
        if not varname:
            mlog.warning(f'Subproject {subp_name!r} did not override {self._display_name!r} dependency and no variable name specified')
            self._log_found(False, subproject=subproject.subdir)
            return self._notfound_dependency()

        var_dep = self._get_subproject_variable(subproject, varname) or self._notfound_dependency()
        if not var_dep.found():
            self._log_found(False, subproject=subproject.subdir)
            return var_dep

        wanted = stringlistify(kwargs.get('version', []))
        found = var_dep.get_version()
        if not self._check_version(wanted, found):
            self._log_found(False, subproject=subproject.subdir,
                            extra_args=['found', mlog.normal_cyan(found), 'but need:',
                                        mlog.bold(', '.join([f"'{e}'" for e in wanted]))])
            return self._notfound_dependency()

        self._log_found(True, subproject=subproject.subdir,
                        extra_args=[mlog.normal_cyan(found) if found else None])
        return var_dep

    def _log_found(self, found: bool, extra_args: T.Optional[mlog.TV_LoggableList] = None,
                   subproject: T.Optional[str] = None) -> None:
        msg: mlog.TV_LoggableList = [
            'Dependency', mlog.bold(self._display_name),
            'for', mlog.bold(self.for_machine.get_lower_case_name()), 'machine']
        if subproject:
            msg.extend(['from subproject', subproject])
        msg.extend(['found:', mlog.red('NO') if not found else mlog.green('YES')])
        if extra_args:
            msg.extend(extra_args)

        mlog.log(*msg)

    def _get_cached_dep(self, name: str, kwargs: TYPE_nkwargs) -> T.Optional[Dependency]:
        # Unlike other methods, this one returns not-found dependency instead
        # of None in the case the dependency is cached as not-found, or if cached
        # version does not match. In that case we don't want to continue with
        # other candidates.
        identifier = dependencies.get_dep_identifier(name, kwargs)
        wanted_vers = stringlistify(kwargs.get('version', []))

        override = self.build.dependency_overrides[self.for_machine].get(identifier)
        if not override and self.subproject_name:
            identifier_without_modules = tuple((k, v) for k, v in identifier if k not in {'modules', 'optional_modules'})
            if identifier_without_modules != identifier:
                override = self.build.dependency_overrides[self.for_machine].get(identifier_without_modules)
        if override:
            info = [mlog.blue('(overridden)' if override.explicit else '(cached)')]
            cached_dep = override.dep
            # We don't implicitly override not-found dependencies, but user could
            # have explicitly called meson.override_dependency() with a not-found
            # dep.
            if not cached_dep.found():
                self._log_found(False, extra_args=info)
                return cached_dep
        elif self.forcefallback and self.subproject_name:
            cached_dep = None
        else:
            info = [mlog.blue('(cached)')]
            cached_dep = self.coredata.deps[self.for_machine].get(identifier)

        if cached_dep:
            found_vers = cached_dep.get_version()
            if not self._check_version(wanted_vers, found_vers):
                if not override:
                    # We cached this dependency on disk from a previous run,
                    # but it could got updated on the system in the meantime.
                    return None
                self._log_found(
                    False, extra_args=[
                        'found', mlog.normal_cyan(found_vers), 'but need:',
                        mlog.bold(', '.join([f"'{e}'" for e in wanted_vers])),
                        *info])
                return self._notfound_dependency()
            if found_vers:
                info = [mlog.normal_cyan(found_vers), *info]
            self._log_found(True, extra_args=info)
            return cached_dep
        return None

    def _get_subproject_variable(self, subproject: SubprojectHolder, varname: str) -> T.Optional[Dependency]:
        try:
            var_dep = subproject.get_variable_method([varname], {})
        except InvalidArguments:
            var_dep = None
        if not isinstance(var_dep, Dependency):
            mlog.warning(f'Variable {varname!r} in the subproject {subproject.subdir!r} is',
                         'not found' if var_dep is None else 'not a dependency object')
            return None
        return var_dep

    def _verify_fallback_consistency(self, cached_dep: Dependency) -> None:
        subp_name = self.subproject_name
        varname = self.subproject_varname
        subproject = self._get_subproject(subp_name)
        if subproject and varname:
            var_dep = self._get_subproject_variable(subproject, varname)
            if var_dep and cached_dep.found() and var_dep != cached_dep:
                mlog.warning(f'Inconsistency: Subproject has overridden the dependency with another variable than {varname!r}')

    def _handle_featurenew_dependencies(self, name: str) -> None:
        'Do a feature check on dependencies used by this subproject'
        if name == 'mpi':
            FeatureNew.single_use('MPI Dependency', '0.42.0', self.subproject)
        elif name == 'pcap':
            FeatureNew.single_use('Pcap Dependency', '0.42.0', self.subproject)
        elif name == 'vulkan':
            FeatureNew.single_use('Vulkan Dependency', '0.42.0', self.subproject)
        elif name == 'libwmf':
            FeatureNew.single_use('LibWMF Dependency', '0.44.0', self.subproject)
        elif name == 'openmp':
            FeatureNew.single_use('OpenMP Dependency', '0.46.0', self.subproject)

    def _notfound_dependency(self) -> NotFoundDependency:
        return NotFoundDependency(self.names[0] if self.names else '', self.environment)

    @staticmethod
    def _check_version(wanted: T.List[str], found: str) -> bool:
        if not wanted:
            return True
        return not (found == 'undefined' or not version_compare_many(found, wanted)[0])

    def _get_candidates(self) -> T.List[T.Tuple[T.Callable[[TYPE_nkwargs, TYPE_nvar, TYPE_nkwargs], T.Optional[Dependency]], TYPE_nvar, TYPE_nkwargs]]:
        candidates = []
        # 1. check if any of the names is cached already.
        for name in self.names:
            candidates.append((self._do_dependency_cache, [name], {}))
        # 2. check if the subproject fallback has already been configured.
        if self.subproject_name:
            candidates.append((self._do_existing_subproject, [self.subproject_name], self.subproject_kwargs))
        # 3. check external dependency if we are not forced to use subproject
        if not self.forcefallback or not self.subproject_name:
            for name in self.names:
                candidates.append((self._do_dependency, [name], {}))
        # 4. configure the subproject
        if self.subproject_name:
            candidates.append((self._do_subproject, [self.subproject_name], self.subproject_kwargs))
        return candidates

    def lookup(self, kwargs: TYPE_nkwargs, force_fallback: bool = False) -> Dependency:
        mods = extract_as_list(kwargs, 'modules')
        if mods:
            self._display_name += ' (modules: {})'.format(', '.join(str(i) for i in mods))

        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            mlog.log('Dependency', mlog.bold(self._display_name),
                     'for', mlog.bold(self.for_machine.get_lower_case_name()), 'machine',
                     'skipped: feature', mlog.bold(feature), 'disabled')
            return self._notfound_dependency()

        # Check if usage of the subproject fallback is forced
        wrap_mode = self.coredata.get_option(OptionKey('wrap_mode'))
        assert isinstance(wrap_mode, WrapMode), 'for mypy'
        force_fallback_for = self.coredata.get_option(OptionKey('force_fallback_for'))
        assert isinstance(force_fallback_for, list), 'for mypy'
        self.nofallback = wrap_mode == WrapMode.nofallback
        self.forcefallback = (force_fallback or
                              wrap_mode == WrapMode.forcefallback or
                              any(name in force_fallback_for for name in self.names) or
                              self.subproject_name in force_fallback_for)

        # Add an implicit subproject fallback if none has been set explicitly,
        # unless implicit fallback is not allowed.
        # Legacy: self.allow_fallback can be None when that kwarg is not defined
        # in dependency('name'). In that case we don't want to use implicit
        # fallback when required is false because user will typically fallback
        # manually using cc.find_library() for example.
        if not self.subproject_name and self.allow_fallback is not False:
            for name in self.names:
                subp_name, varname = self.wrap_resolver.find_dep_provider(name)
                if subp_name:
                    self.forcefallback |= subp_name in force_fallback_for
                    if self.forcefallback or self.allow_fallback is True or required or self._get_subproject(subp_name):
                        self._subproject_impl(subp_name, varname)
                    break

        candidates = self._get_candidates()

        # writing just "dependency('')" is an error, because it can only fail
        if not candidates and required:
            raise InvalidArguments('Dependency is required but has no candidates.')

        # Try all candidates, only the last one is really required.
        last = len(candidates) - 1
        for i, item in enumerate(candidates):
            func, func_args, func_kwargs = item
            func_kwargs['required'] = required and (i == last)
            func_kwargs['for_machine'] = self.for_machine
            kwargs['required'] = required and (i == last)
            dep = func(kwargs, func_args, func_kwargs)
            if dep and dep.found():
                # Override this dependency to have consistent results in subsequent
                # dependency lookups.
                for name in self.names:
                    identifier = dependencies.get_dep_identifier(name, kwargs)
                    if identifier not in self.build.dependency_overrides[self.for_machine]:
                        self.build.dependency_overrides[self.for_machine][identifier] = \
                            build.DependencyOverride(dep, self.interpreter.current_node, explicit=False)
                return dep
            elif required and (dep or i == last):
                # This was the last candidate or the dependency has been cached
                # as not-found, or cached dependency version does not match,
                # otherwise func() would have returned None instead.
                raise DependencyException(f'Dependency {self._display_name!r} is required but not found.')
            elif dep:
                # Same as above, but the dependency is not required.
                return dep
        return self._notfound_dependency()

"""

```