Response:
Let's break down the thought process to analyze this Python code.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `dependencyfallbacks.py` file within the Frida project. Specifically, it wants to know:

* **Functionality:** What does this code do?
* **Relevance to Reverse Engineering:** How does it relate to the core purpose of Frida?
* **Underlying System Knowledge:** What low-level concepts are involved (binary, kernel, etc.)?
* **Logical Reasoning:**  Can we infer input/output behavior?
* **Common Usage Errors:**  What mistakes might developers make when using this?
* **Debugging Context:** How does a user reach this part of the code?

**2. Initial Code Scan and Keyword Recognition:**

I started by scanning the code for keywords and patterns that suggest its purpose. Here are some initial observations:

* **`dependencyfallbacks`:**  This immediately suggests a mechanism for trying different ways to find a dependency. If one method fails, it "falls back" to another.
* **`Dependency`, `NotFoundDependency`, `DependencyException`:**  These classes strongly indicate a system for managing external libraries or components required by the Frida build process.
* **`subproject`:** The frequent use of "subproject" implies that Frida's build system can incorporate other projects as dependencies.
* **`wrap_mode`, `force_fallback_for`:** These options hint at control over how dependency resolution is handled, potentially related to pre-built binaries or specific build configurations.
* **`find_external_dependency`:**  This function likely handles the standard way of locating dependencies on the system.
* **`meson`:** The presence of `mesonbuild` in the path and imports from `mesonlib` clearly points to the Meson build system being used.
* **`interpreter`:** The code is part of the Meson interpreter, suggesting it's involved in processing the `meson.build` files.
* **`for_machine`:** This indicates the code handles cross-compilation scenarios where dependencies might be different for the host and target architectures.
* **`mlog.log`:** This suggests logging, important for debugging and understanding the build process.

**3. Deconstructing the `DependencyFallbacksHolder` Class:**

The core of the file is the `DependencyFallbacksHolder` class. I analyzed its methods to understand their roles:

* **`__init__`:** Initializes the object, storing dependency names, machine architecture, and configuration options.
* **`set_fallback`:**  Handles the legacy syntax for specifying a fallback subproject.
* **`_subproject_impl`:**  Internally sets the subproject name and variable name for the fallback.
* **`_do_dependency_cache`:** Checks if the dependency is already known (cached) from previous builds. This is an optimization.
* **`_do_dependency`:**  Attempts to find the dependency using standard system mechanisms.
* **`_do_existing_subproject`:**  Checks if a previously configured subproject can provide the dependency.
* **`_do_subproject`:** Configures and builds the fallback subproject if necessary.
* **`_get_subproject`:**  Retrieves a configured subproject.
* **`_get_subproject_dep`:**  Retrieves the dependency from a configured subproject.
* **`_log_found`:**  Logs whether a dependency was found and where.
* **`_get_cached_dep`:** A helper for checking the dependency cache.
* **`_get_subproject_variable`:** Retrieves a specific variable (expected to be a dependency) from a subproject.
* **`_verify_fallback_consistency`:** Checks for inconsistencies between cached dependencies and subproject-provided dependencies.
* **`_handle_featurenew_dependencies`:**  Raises warnings for using certain dependencies with older Meson versions.
* **`_notfound_dependency`:** Returns a special object indicating the dependency wasn't found.
* **`_check_version`:**  Compares dependency versions.
* **`_get_candidates`:**  Determines the order in which different dependency lookup methods should be tried. This is the core logic of the fallback mechanism.
* **`lookup`:** The main entry point. It orchestrates the dependency lookup process, trying the candidates in order.

**4. Connecting to Reverse Engineering and Frida:**

At this point, I considered how these functionalities relate to Frida. Frida is about dynamic instrumentation, often involving interacting with the internals of processes. This means it relies on various libraries and components. The dependency fallback mechanism ensures that Frida's build process can locate these necessary components, even if they aren't in the standard system locations. Subprojects are a natural fit for bundling or building specific versions of libraries Frida needs.

**5. Identifying Low-Level Concepts:**

The concepts of "binary," "Linux kernel," and "Android framework" came into play when considering *what* kind of dependencies Frida might need. For example, Frida might require libraries for interacting with the operating system's API, which could involve kernel-level interfaces or framework-specific components on Android. Cross-compilation (`for_machine`) is crucial when building Frida for different target architectures (like ARM for Android).

**6. Inferring Logic and Examples:**

Based on the code structure, I started to create hypothetical scenarios and examples. The `lookup` function's flow, the order of candidates in `_get_candidates`, and the various conditions (like `forcefallback`, `nofallback`, `required`) provided clues for how the system behaves. For instance, the order of checking the cache, then existing subprojects, then external dependencies, then configuring a new subproject made logical sense.

**7. Considering User Errors:**

Thinking about common mistakes led to examples like:

* Incorrect dependency names.
* Conflicting fallback specifications.
* Version mismatches.
* Forgetting to define necessary variables in subprojects.

**8. Tracing the User Journey:**

To understand how a user reaches this code, I considered the typical Frida development workflow:

1. Modifying or extending Frida's functionality.
2. Running the build system (likely Meson).
3. Meson processing `meson.build` files.
4. The `dependency()` function being called in `meson.build`.
5. The `DependencyFallbacksHolder` being used to resolve that dependency.

**9. Refining and Structuring the Answer:**

Finally, I organized my findings into the requested categories, providing clear explanations and concrete examples. I aimed to be as specific as possible, referencing code snippets where relevant. I also made sure to highlight the connections to reverse engineering, low-level concepts, and the practical aspects of using Frida's build system.

This iterative process of code scanning, deconstruction, connection to the project's purpose, and example generation allowed me to arrive at a comprehensive understanding of the `dependencyfallbacks.py` file.
这个 `dependencyfallbacks.py` 文件是 Frida 动态Instrumentation 工具构建系统中 Meson 构建工具的一部分，负责处理依赖查找和回退机制。它的主要功能是为 Frida 的构建过程提供一种灵活的方式来查找所需的外部依赖库，并在找不到首选依赖项时尝试使用预定义的后备方案，通常是一个子项目。

以下是它的功能列表，并根据你的要求进行了详细说明：

**功能列表:**

1. **定义依赖查找的优先级和回退策略:**  该文件定义了查找依赖项的顺序。它会先尝试查找系统上的外部依赖，如果找不到，则会尝试使用指定的子项目作为后备。
2. **处理多种依赖查找方式:** 它支持直接查找系统依赖、查找已配置的子项目提供的依赖，以及配置并构建一个子项目作为依赖回退。
3. **管理依赖项的版本需求:** 可以指定依赖项的版本要求，并在查找时进行版本匹配。
4. **处理依赖项的模块需求:**  允许指定依赖项所需的特定模块。
5. **支持强制或禁用回退:**  提供了选项来强制使用子项目回退，或者完全禁用回退机制。
6. **处理 wrap 文件提供的隐式回退:**  如果存在 wrap 文件指定了某个依赖项的提供者，它可以自动使用该子项目作为回退。
7. **缓存依赖查找结果:**  它会缓存已找到的依赖项信息，以提高后续构建速度。
8. **处理依赖项的 overrides:**  允许用户通过 `meson.override_dependency()` 显式地覆盖依赖项的查找结果。
9. **记录依赖查找过程:**  使用 `mlog` 模块记录依赖查找的详细过程，方便调试。
10. **处理 `required` 关键字:**  如果依赖项被标记为 `required` 且所有查找方法都失败，则会抛出异常。
11. **处理 `allow_fallback` 关键字 (已废弃的 `fallback` 关键字):**  允许显式控制是否允许回退到子项目。
12. **Feature New 检查:**  针对一些特定的依赖项（如 `mpi`, `pcap`, `vulkan` 等），会进行 Meson 版本特性检查，如果使用的 Meson 版本过低会发出警告。

**与逆向方法的关系及举例:**

Frida 本身是一个强大的逆向工程工具，而这个文件是 Frida 构建系统的一部分，其功能直接关系到 Frida 能否成功构建。  逆向工程师在构建 Frida 时，可能需要它依赖的一些库（例如用于处理网络、加密、或者特定平台 API 的库）。

* **例子 1：构建针对 Android 的 Frida Server，需要 `libusb`：**
    * Frida 的构建脚本可能会声明依赖于 `libusb`。
    * 如果目标机器上没有安装 `libusb`，并且配置了相应的子项目（例如，预编译的 `libusb` 库），则 `dependencyfallbacks.py` 会尝试构建或使用该子项目提供的 `libusb`。
    * 这使得逆向工程师可以在没有预装 `libusb` 的环境下为 Android 设备构建 Frida Server。

* **例子 2：构建包含特定扩展的 Frida，依赖于特定的加密库：**
    * 假设 Frida 的一个扩展需要 `openssl`。
    * 如果构建时找不到系统 `openssl`，而构建配置中指定了一个包含 `openssl` 的子项目，`dependencyfallbacks.py` 会负责找到并使用该子项目的 `openssl`。
    * 这允许逆向工程师构建定制化的 Frida 版本，即使目标环境的依赖配置不同。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例:**

这个文件本身的代码主要是 Meson 构建系统的逻辑，但它所处理的依赖项查找过程会涉及到这些底层知识：

* **二进制底层:**
    * **查找共享库:**  在查找系统依赖时，它会涉及到操作系统查找共享库的机制（例如 Linux 的 `ld.so`）。
    * **链接器标志:**  构建子项目时，可能需要设置特定的链接器标志来确保依赖项的正确链接。
    * **静态库与共享库:**  `static` 关键字的处理涉及到选择静态链接或动态链接依赖项。

* **Linux:**
    * **系统库路径:**  在 Linux 上查找依赖项时，会搜索标准的系统库路径（如 `/usr/lib`, `/usr/local/lib` 等）。
    * **pkg-config:**  Frida 的构建过程通常会使用 `pkg-config` 工具来获取依赖项的编译和链接信息。`dependencyfallbacks.py` 会间接利用 `pkg-config` 提供的信息。

* **Android 内核及框架:**
    * **Android NDK:**  当为 Android 构建 Frida 时，可能会依赖 Android NDK 提供的库。`dependencyfallbacks.py` 需要能够找到这些库。
    * **特定于 Android 的依赖:**  某些 Frida 组件可能依赖于 Android 特有的库或框架，例如与 Binder IPC 机制相关的库。
    * **交叉编译:**  为 Android 构建 Frida 通常是交叉编译，`for_machine` 参数就体现了对目标机器架构的考虑。

**逻辑推理的假设输入与输出:**

假设我们正在构建 Frida，并且 `meson.build` 文件中声明了对名为 `my_custom_lib` 的依赖，并且定义了一个名为 `my_custom_lib_subproject` 的子项目作为回退。

**假设输入:**

* **`names`:** `['my_custom_lib']`  (要查找的依赖项名称)
* **`for_machine`:**  `MachineChoice.HOST` 或 `MachineChoice.BUILD` 或 `MachineChoice.TARGET` (目标机器类型)
* **系统上不存在 `my_custom_lib`。**
* **存在一个名为 `my_custom_lib_subproject` 的子项目，并且该子项目的 `meson.build` 文件中定义了如何构建 `my_custom_lib`。**
* **`allow_fallback`:** 默认为 `None` 或 `True`。

**预期输出:**

1. `_do_dependency_cache` 会检查缓存，如果之前没有构建过，则返回 `None`。
2. `_do_dependency` 会尝试在系统上查找 `my_custom_lib`，因为找不到，返回 `None`。
3. `_do_existing_subproject` 会检查是否已经配置过 `my_custom_lib_subproject`，如果还没配置，则返回 `None`。
4. `_do_subproject` 会被调用，配置并构建 `my_custom_lib_subproject`。
5. `_get_subproject_dep` 会尝试从构建好的 `my_custom_lib_subproject` 中获取 `my_custom_lib` 依赖项。
6. `lookup` 函数最终会返回从子项目中获取的 `my_custom_lib` 的 `Dependency` 对象。

**涉及用户或者编程常见的使用错误及举例:**

1. **依赖项名称拼写错误:**
   ```python
   # 错误，依赖项名称拼写错误
   dependency('mycustm_lib', fallback : 'my_custom_lib_subproject')
   ```
   这会导致系统找不到对应的依赖，并且回退到错误的子项目（如果存在）。

2. **回退子项目名称错误或不存在:**
   ```python
   dependency('my_custom_lib', fallback : 'non_existent_subproject')
   ```
   这将导致构建失败，因为无法找到指定的回退子项目。

3. **循环依赖:**
   如果子项目本身依赖于需要回退的依赖项，则可能导致无限循环。

4. **子项目构建失败:**
   如果回退的子项目构建失败，则依赖查找也会失败。这可能是由于子项目配置错误、缺少子项目的依赖等原因。

5. **版本冲突:**
   如果系统上的依赖项版本与要求的版本不匹配，并且回退的子项目提供的版本也不正确，则可能导致构建失败或运行时错误。

6. **`allow_fallback` 和 `fallback` 的混用或误用:**
   虽然 `fallback` 已经过时，但仍然可能在旧代码中看到。混用或误用这两个关键字会导致不可预测的行为。

7. **在子项目中没有正确导出依赖项:**
   即使子项目成功构建，如果子项目的 `meson.build` 文件没有使用 `meson.override_dependency()` 或其他方式将构建产物（例如库）导出为可被主项目使用的依赖项，那么 `_get_subproject_dep` 将无法找到依赖项。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida 或其组件:**  用户通常会执行类似 `meson build` 或 `ninja` 命令来启动构建过程。
2. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录和子目录下的 `meson.build` 文件。
3. **遇到 `dependency()` 函数调用:**  在 `meson.build` 文件中，会使用 `dependency()` 函数来声明项目所需的外部依赖项。
4. **`DependencyFallbacksHolder` 被创建:**  当 Meson 遇到 `dependency()` 函数调用时，如果指定了回退或者 Meson 需要处理依赖查找，就会创建 `DependencyFallbacksHolder` 的实例。
5. **调用 `lookup()` 方法:**  `DependencyFallbacksHolder` 实例的 `lookup()` 方法会被调用，开始执行依赖查找流程。
6. **依次尝试 `_get_candidates()` 返回的方法:**  `lookup()` 方法会根据配置和当前状态，依次调用 `_do_dependency_cache`, `_do_existing_subproject`, `_do_dependency`, `_do_subproject` 等方法来查找依赖项。
7. **记录日志:**  在查找过程中，`mlog.log()` 会记录详细的查找信息，包括尝试的方法、是否找到、使用的版本等等。

**作为调试线索:**

* **查看构建日志:**  当构建失败时，首先应该查看详细的构建日志。`mlog.log` 记录的信息会显示 `dependencyfallbacks.py` 尝试了哪些查找方法，以及为什么失败。例如，可以查看是否成功找到了系统依赖，是否尝试了子项目回退，以及子项目构建是否成功。
* **检查 `meson.build` 文件:**  确认 `dependency()` 函数的参数是否正确，包括依赖项名称、回退子项目名称等。
* **检查子项目的 `meson.build` 文件:**  如果使用了子项目回退，需要检查子项目的构建配置是否正确，并且是否正确导出了所需的依赖项。
* **使用 Meson 的调试选项:**  Meson 提供了一些调试选项，可以更详细地了解构建过程，例如查看变量的值，跟踪函数调用等。
* **检查 `wrap` 文件:**  如果存在 `wrap` 文件，需要确认其中定义的依赖项提供者是否正确。

总而言之，`dependencyfallbacks.py` 是 Frida 构建系统中一个至关重要的组件，它通过灵活的依赖查找和回退机制，确保了 Frida 可以在不同的环境中成功构建，这对于逆向工程师来说非常重要，因为他们可能需要在各种目标系统上部署和使用 Frida。 理解这个文件的功能有助于诊断构建问题，并更好地理解 Frida 的构建过程。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```