Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Understanding the Goal:**

The first step is to recognize that the core purpose of this code is to manage the process of finding and using dependencies in a build system. Specifically, it focuses on handling fallbacks, where if a dependency isn't found directly, it tries to build it as a subproject.

**2. High-Level Reading and Identifying Key Classes/Functions:**

Quickly scanning the code reveals the main class, `DependencyFallbacksHolder`. This immediately suggests it's responsible for holding and managing fallback logic for dependencies. Other important elements that jump out include:

* **`dependency_fallbacks`**:  The name of the module itself strongly suggests its function.
* **`dependency()`**: Mentions of `dependency()` point to interaction with the core dependency finding mechanism of the build system.
* **`subproject`**:  Frequent references to subprojects indicate this is a key aspect of the fallback strategy.
* **`wrap_mode` and `force_fallback_for`**:  These option keys hint at configuration related to dependency handling.
* **`lookup()`**: This function likely orchestrates the entire dependency finding process, including fallbacks.
* **`_do_dependency_cache`, `_do_dependency`, `_do_existing_subproject`, `_do_subproject`**: These private methods seem to represent different stages or strategies in the dependency lookup process.

**3. Deconstructing Functionality - Asking "What does this do?" for each part:**

Now, dive deeper into the code, method by method. For each method, ask:

* **What are the inputs?** (Arguments, class attributes)
* **What is the core logic?** (Step-by-step actions)
* **What are the outputs or side effects?** (Return value, changes to internal state, logging)

For example, for `__init__`:

* **Inputs:** `interpreter`, `names`, `for_machine`, `allow_fallback`, `default_options`.
* **Logic:** Initializes the object, stores inputs, validates dependency names, sets up for subproject fallbacks.
* **Outputs:** Creates a `DependencyFallbacksHolder` object.

For `set_fallback`:

* **Inputs:** `fbinfo`.
* **Logic:** Processes the fallback information, setting `allow_fallback` or configuring the subproject fallback.
* **Outputs:** Modifies the object's state (`allow_fallback`, `subproject_name`, `subproject_varname`).

For `lookup`:

* **Inputs:** `kwargs`, `force_fallback`.
* **Logic:**  The central control flow. Checks for disabled dependencies, determines fallback behavior, iterates through candidate lookup methods, and returns a `Dependency` object.
* **Outputs:** Returns a `Dependency` object (either found or not found).

**4. Connecting to Reverse Engineering, Binary/Kernel, and User Errors:**

* **Reverse Engineering:** Think about *why* someone would need fallbacks in a reverse engineering context. Often, specific libraries or components required for analysis or instrumentation might not be standardly installed on the target system. The fallback mechanism allows building these dependencies from source. The example of instrumenting a Swift application with Frida is a perfect fit.

* **Binary/Kernel/Framework:** Consider what kinds of dependencies are common in such low-level work. Libraries for interacting with the operating system, handling low-level data structures, or specific frameworks (like Android's) come to mind. The code mentions `mpi`, `pcap`, `vulkan`, which are often used in system-level or performance-critical applications. The concept of "machine" and handling different architectures is also relevant to binary compatibility.

* **User/Programming Errors:**  Look for validation checks and potential failure points. The code explicitly checks for empty dependency names, invalid characters in names, and inconsistencies in fallback configurations. The "required" flag and the error when no candidates are found for a required dependency are also sources of user errors.

**5. Constructing Examples and Scenarios:**

Based on the understanding of the code's logic and its relation to the target domains, create concrete examples.

* **Input/Output:**  Imagine calling `lookup` with different configurations (e.g., `force_fallback=True`, a specific version requirement) and trace the execution path to predict the output.
* **User Error:** Think about common mistakes a developer might make, like misspelling a dependency name or providing incorrect fallback information.
* **Debugging:** Consider how a developer would use the logging messages to understand why a dependency lookup failed.

**6. Addressing the "How did the user get here?" Question:**

This requires understanding the broader context of a build system. The user would typically start by defining dependencies in their build configuration files (e.g., `meson.build`). The `dependency()` function would be called, potentially triggering the `dependency_fallbacks` mechanism if a fallback is defined or implied. Tracing the call stack from the user's initial configuration down to this specific file is the key.

**7. Iteration and Refinement:**

Review the generated answers. Are they clear, concise, and accurate?  Are the examples relevant and easy to understand?  Refine the explanations and examples as needed to ensure clarity and completeness. For example, initially, I might have just said "it handles fallbacks," but then I'd refine that to explain *how* it handles them (subprojects, wrap files).

By following these steps, you can systematically analyze the code and generate comprehensive answers to the prompt's questions. The key is to break down the problem into smaller, manageable parts and then connect those parts to the broader context.
这个 Python 源代码文件 `dependencyfallbacks.py` 是 Frida 动态插桩工具中 Meson 构建系统的一部分，专门用于处理 **依赖查找的备用方案 (fallback)**。当 Meson 尝试找到一个外部依赖项时，如果找不到，这个文件中的逻辑会尝试使用预定义的备用方法来提供该依赖项，通常是通过构建一个子项目来实现。

以下是它的功能列表，并根据你的要求进行了详细说明：

**主要功能：处理依赖查找的备用方案**

1. **定义和管理依赖回退规则：**  `DependencyFallbacksHolder` 类负责存储和管理针对特定依赖项的备用构建方案。它可以处理多种情况，例如：
   - 当找不到外部依赖项时，构建一个子项目来提供该依赖项。
   - 强制使用子项目来构建依赖项，即使系统上可能存在该依赖项。
   - 禁用依赖回退，直接报告依赖项找不到。

2. **查找依赖项的多种策略：** `lookup` 方法是核心，它会尝试多种策略来查找依赖项：
   - **检查缓存：** 首先检查之前是否已经找到并缓存了该依赖项。
   - **检查已配置的子项目：** 如果已定义了回退子项目，检查该子项目是否已经配置成功并提供了该依赖项。
   - **查找外部依赖项：** 尝试在系统上查找外部依赖项。
   - **配置子项目回退：** 如果定义了回退子项目，并且之前的查找都失败了，则会触发子项目的配置和构建。

3. **处理依赖项的版本要求：** 代码可以处理依赖项的版本要求。它会比较找到的依赖项版本和要求的版本，以确保兼容性。

4. **处理依赖项的模块 (modules)：** 允许指定依赖项的特定模块，并将其纳入查找过程。

5. **与 Wrap 文件集成：**  可以与 Meson 的 Wrap 文件机制集成，Wrap 文件可以指定如何获取依赖项的源代码，通常用于构建子项目。

6. **记录详细的查找过程：**  使用 `mlog` 模块记录依赖查找的详细过程，包括是否找到、来自哪里（外部或子项目）以及版本信息，有助于调试。

**与逆向方法的关系举例说明：**

在逆向工程中，你可能需要依赖一些特定的库来进行代码分析、hook 或内存操作。这些库可能不是目标系统上默认安装的。`dependencyfallbacks.py` 允许 Frida 的构建系统在找不到这些库时，自动从源代码构建它们。

**举例：**

假设 Frida 需要 `libcapstone` 库来进行反汇编。目标系统上没有安装 `libcapstone`。Frida 的 `meson.build` 文件中可能会定义一个针对 `capstone` 依赖的 fallback：

```meson
capstone_dep = dependency('capstone', fallback: 'capstone')
```

当 Meson 构建 Frida 时，会调用 `dependency('capstone')`。如果找不到系统级的 `capstone`，`dependencyfallbacks.py` 中的逻辑会检测到 `fallback: 'capstone'`，然后触发构建名为 `capstone` 的子项目（通常在 `subprojects/capstone` 目录下）。这个子项目会编译 `libcapstone`，然后 Frida 的构建会链接到这个新构建的库。

**涉及到二进制底层、Linux、Android 内核及框架的知识的举例说明：**

1. **二进制底层：**
   - 代码中涉及到 "machine" 的概念 (`for_machine`)，这与目标架构（如 x86、ARM）有关。不同的架构可能需要不同的依赖项或不同的构建方式。
   - 子项目构建通常涉及编译 C/C++ 代码，这直接操作二进制层面。
   - 依赖项可能是一些底层的库，如处理进程内存、系统调用等的库。

2. **Linux 内核：**
   - 一些依赖项可能与 Linux 内核的特定功能相关，例如，用于网络抓包的 `pcap` 库。如果系统上找不到 `pcap`，fallback 机制可能会构建它，这涉及到理解 Linux 内核的网络接口和数据包捕获机制。

3. **Android 内核及框架：**
   - 在为 Android 构建 Frida 组件时，可能需要依赖 Android 的特定库或框架，例如用于与 ART 虚拟机交互的库。这些库通常不会在标准的 Linux 系统上找到。
   - `dependencyfallbacks.py` 允许 Frida 构建系统在找不到这些 Android 特有的依赖项时，通过子项目的方式来提供它们。这可能涉及到从 Android SDK 或 NDK 中获取源代码并进行交叉编译。

**逻辑推理的假设输入与输出：**

**假设输入：**

- `names`: `['glib-2.0']` (要查找的依赖项名称)
- `kwargs`: `{'required': True}` (该依赖项是必需的)
- 系统上没有安装 `glib-2.0`。
- `meson.build` 中定义了 `glib` 的 fallback 子项目。

**输出：**

1. **日志输出：**  `mlog` 会记录尝试查找 `glib-2.0` 的过程，包括找不到外部依赖项的信息。
2. **子项目构建：**  `dependencyfallbacks.py` 会触发 `glib` 子项目的构建过程。
3. **返回 Dependency 对象：** 如果子项目构建成功，`lookup` 方法会返回一个表示成功找到 `glib-2.0` 的 `Dependency` 对象，该对象指向构建的子项目中的库。如果子项目构建失败，且 `required` 为 `True`，则会抛出 `DependencyException`。

**涉及用户或编程常见的使用错误举例说明：**

1. **拼写错误或错误的依赖项名称：**  如果在 `meson.build` 中将依赖项名称写错，例如 `dependency('gllib-2.0', fallback: 'glib')`，那么系统可能会找不到该依赖项，即使 `glib` 子项目存在。
2. **循环依赖：**  如果子项目 `A` 依赖于子项目 `B`，而子项目 `B` 又依赖于子项目 `A`，并且都使用了 fallback 机制，可能会导致无限递归的构建过程。Meson 会尝试检测并阻止这种情况。
3. **错误的 fallback 配置：**  如果 `fallback` 指定的子项目名称不存在，或者子项目配置失败，会导致依赖查找失败。
4. **版本冲突：**  如果外部依赖项的版本与子项目提供的版本不兼容，可能会导致运行时错误。`dependencyfallbacks.py` 尝试通过版本比较来缓解这种情况，但用户仍然需要注意版本兼容性。
5. **缺少子项目依赖：**  构建 fallback 子项目可能需要额外的依赖项。如果这些依赖项在构建环境中缺失，会导致子项目构建失败，进而导致依赖查找失败。

**说明用户操作是如何一步步到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户在 `meson.build` 文件中声明了一个依赖项，并可能指定了 fallback 子项目：
   ```meson
   my_dep = dependency('my-library', fallback: 'my-library-fallback')
   ```
2. **用户运行 Meson 配置：** 用户在命令行执行 `meson setup builddir` 来配置构建。
3. **Meson 解析 `meson.build`：** Meson 解析 `meson.build` 文件，遇到 `dependency('my-library', ...)` 函数调用。
4. **调用 `dependency()` 函数：** Meson 的解释器会执行 `dependency()` 函数。
5. **进入 `dependencyfallbacks.py` 的逻辑：**  `dependency()` 函数内部会创建 `DependencyFallbacksHolder` 对象来处理依赖查找。
6. **`lookup()` 方法被调用：**  `DependencyFallbacksHolder` 对象的 `lookup()` 方法被调用，开始尝试查找 `my-library`。
7. **查找失败，尝试 fallback：** 如果系统上找不到 `my-library`，`lookup()` 方法会根据 `fallback: 'my-library-fallback'` 的配置，尝试构建 `my-library-fallback` 子项目。
8. **子项目构建过程：**  Meson 会查找 `subprojects/my-library-fallback` 目录下的 `meson.build` 文件，并执行该子项目的构建过程。
9. **返回 Dependency 对象或抛出异常：**  根据子项目构建的结果，`lookup()` 方法会返回一个表示找到依赖项的 `Dependency` 对象，或者抛出一个异常（如果子项目构建失败且依赖项是必需的）。

**调试线索：**

- **查看 Meson 的输出：**  Meson 的配置和构建输出会包含有关依赖查找过程的详细信息，包括是否尝试了 fallback，子项目构建是否成功，以及任何错误消息。
- **检查 `meson-log.txt`：** Meson 会生成一个详细的日志文件 `meson-log.txt`，其中包含了更底层的调试信息，可以查看 `dependencyfallbacks.py` 中的 `mlog` 输出。
- **检查子项目的构建日志：** 如果使用了 fallback 子项目，可以查看该子项目的构建日志，以了解子项目构建过程中是否发生了错误。
- **使用 `--wrap-mode=nofallback`：** 可以使用 `--wrap-mode=nofallback` 选项来禁用 fallback 机制，以便直接查看在没有 fallback 的情况下是否能找到依赖项，从而判断问题是否出在 fallback 逻辑上。
- **逐步调试 Meson 解释器：**  对于更复杂的问题，可以使用 Python 调试器逐步执行 Meson 的解释器代码，包括 `dependencyfallbacks.py` 中的逻辑，以更深入地了解依赖查找的过程。

总而言之，`dependencyfallbacks.py` 是 Frida 构建系统中一个关键的组件，它通过定义和管理依赖查找的备用方案，提高了构建的灵活性和可移植性，尤其在需要依赖一些非标准库或特定版本库的场景下非常有用。它与逆向工程、底层系统编程以及构建系统的细节紧密相关。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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