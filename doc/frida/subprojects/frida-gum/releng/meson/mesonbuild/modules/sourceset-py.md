Response:
Let's break down the thought process for analyzing this Python code for Frida.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided `sourceset.py` file within the context of the Frida dynamic instrumentation tool. The request also asks for specific connections to reverse engineering, low-level concepts, logical reasoning, potential user errors, and debugging.

**2. Initial Code Scan and Keyword Spotting:**

My first step is a quick scan of the code, looking for keywords and patterns that hint at its purpose. I see:

* **`SourceSet` and `SourceSetImpl`:**  These immediately suggest this code is about managing sets of source files.
* **`add_method`, `add_all_method`, `all_sources_method`, `all_dependencies_method`, `apply_method`:** These are the methods exposed by the `SourceSetImpl` class, indicating its main actions.
* **`when`, `if_true`, `if_false`:** These keywords in the `add_method` and `add_all_method` suggest conditional inclusion of source files.
* **`dependencies.Dependency`:**  This confirms the code deals with managing dependencies.
* **`build.GeneratedTypes`, `mesonlib.FileOrString`:**  These indicate the types of source files being managed.
* **`ConfigurationData`:** This hints at integration with a build system's configuration.
* **`frozen`:** This flag suggests a state change after certain operations.
* **`meson` in the file path and comments:** This strongly indicates the code is part of the Meson build system integration.

**3. Deciphering the Core Functionality: Conditional Source Inclusion**

The `add_method` and `add_all_method` with their `when`, `if_true`, and `if_false` arguments are central. I deduce that this code allows defining rules for including or excluding source files based on conditions. These conditions can be:

* **Configuration keys (`when` with strings):**  Based on the value of certain configuration options.
* **Dependencies (`when` with `dependencies.Dependency`):** Based on whether certain libraries or components are available.

**4. Tracing the Data Flow:**

I follow the data flow through the key methods:

* **`add_method`:** Takes source files and conditions, creates a `SourceSetRule`, and appends it to the `rules` list.
* **`add_all_method`:**  Similar to `add_method`, but deals with adding entire other `SourceSetImpl` instances.
* **`collect`:** This is the core logic for evaluating the rules. It iterates through the `rules`, checks the conditions (`enabled_fn`), and adds the corresponding source files and dependencies to the `into` set. The `all_sources` flag controls whether to include the `if_false` sources.
* **`all_sources_method` and `all_dependencies_method`:** These are simple wrappers around `collect` to retrieve all sources and dependencies unconditionally.
* **`apply_method`:** This is where the conditions are actually evaluated against configuration data. It uses a function (`_get_from_config_data`) to check the values of configuration keys. It calls `collect` with the appropriate `enabled_fn`.

**5. Connecting to Reverse Engineering:**

Now I consider how this relates to reverse engineering, keeping Frida's purpose in mind:

* **Conditional Instrumentation:** The ability to conditionally include source code directly aligns with Frida's need to inject code dynamically. Different reverse engineering tasks might require different sets of instrumentation. The `when` conditions could represent different target platforms, operating system versions, or specific application features being analyzed.

**6. Connecting to Low-Level Concepts:**

Next, I think about low-level, kernel, and framework aspects:

* **Platform-Specific Code:** The `when` conditions could easily be used to select source code specific to Linux, Android, or particular kernel versions.
* **Framework Integration:** For Android, dependencies could represent specific Android framework components.
* **Binary Manipulation:** While this code itself doesn't *perform* binary manipulation, it *manages the source code* that might perform such manipulations within Frida.

**7. Logical Reasoning (Hypothetical Input/Output):**

I create a simple scenario to illustrate the logic:

* **Input:** A `SourceSet`, adding two rules. One includes `file1.c` if a config option "FEATURE_A" is true, another includes `file2.c` if dependency "libssl" is found.
* **Output:** When `apply_method` is called with config data where "FEATURE_A" is true and "libssl" is installed, both files will be in the resulting `SourceFilesObject`.

**8. Identifying Potential User Errors:**

I consider common mistakes developers might make:

* **Incorrect File Paths:** Typos or incorrect relative paths in the `add_method`.
* **Mixing Positional and Keyword Args:** The code explicitly checks for this.
* **Using `add` After Querying:** The `frozen` flag prevents modification after `all_sources` or `apply` is called.
* **Missing Configuration Keys in Strict Mode:** The `strict` flag in `apply_method` can cause errors if expected keys are missing.

**9. Debugging Scenario:**

I construct a plausible debugging scenario:

* **User Action:** A Frida developer is trying to build Frida with a specific feature enabled.
* **Reaching the Code:** The Meson build system processes the `meson.build` file, which uses the `sourceset` module to manage conditional source inclusion for that feature.
* **Debugging:** If the feature's source files aren't being included, the developer might examine the `meson.log` to see how the `sourceset` rules are being evaluated or step through the Meson build process.

**10. Structuring the Explanation:**

Finally, I organize my findings into a clear and structured explanation, using headings and bullet points to address each aspect of the request. I use concrete examples to illustrate the abstract concepts. I make sure to highlight the connections to Frida's core purpose of dynamic instrumentation.
This Python code defines a Meson module named `sourceset`. Meson is a build system, and this module provides a way to manage sets of source files and their dependencies conditionally within the build process. Since Frida uses Meson for its build system, this module is part of how Frida organizes and compiles its code.

Let's break down its functionality:

**Core Functionality: Conditional Inclusion of Source Files and Dependencies**

The primary purpose of this `sourceset` module is to allow developers to define sets of source files and dependencies that should be included in the build based on certain conditions. This is achieved through the `SourceSetImpl` class and its methods.

**Key Components and Methods:**

* **`SourceSetImpl` Class:** This is the main class that represents a collection of source files and their conditional inclusion rules.
    * **`add_method`:**  Adds a rule to the source set. This rule specifies a set of source files (and optional extra dependencies) to include if a certain condition (`when`) is true, and optionally a different set of source files to include if the condition is false (`if_false`). The condition can be based on the presence of configuration options or dependencies.
    * **`add_all_method`:** Adds all the sources from another `SourceSetImpl` based on a condition.
    * **`all_sources_method`:** Returns a list of all source files that would be included if all conditions were considered true.
    * **`all_dependencies_method`:** Returns a list of all dependencies that would be included if all conditions were considered true.
    * **`apply_method`:** Evaluates the conditions against provided configuration data and returns a `SourceFilesObject` containing the final set of source files and dependencies that should be included in the build.
* **`SourceSetRule` Class:** A simple data structure to hold the details of a single conditional inclusion rule: the conditions (`keys`, `deps`), the source files to include if true (`sources`, `sourcesets`), extra dependencies if true (`extra_deps`), and the source files to include if false (`if_false`).
* **`SourceFilesObject` Class:** A simple object that holds the final lists of source files and dependencies after applying the conditions.

**Relation to Reverse Engineering (with examples):**

Yes, this module is highly relevant to reverse engineering, particularly within the context of Frida. Here's how:

* **Conditional Instrumentation:** Frida's core purpose is dynamic instrumentation. Different reverse engineering tasks might require different sets of instrumentation code. The `sourceset` module allows Frida's developers to include specific instrumentation modules or functionalities based on the target environment or the specific analysis being performed.

    * **Example:** Imagine Frida has instrumentation code for Android and iOS. Using `sourceset`, they could define a rule like this (in the `meson.build` file that uses this module):
        ```python
        if host_machine.system() == 'android':
            android_sources = source_set()
            android_sources.add('android_instrumentation.c', 'android_hooks.c')
            frida_sources.add_all(android_sources)
        elif host_machine.system() == 'ios':
            ios_sources = source_set()
            ios_sources.add('ios_instrumentation.m', 'ios_syscalls.c')
            frida_sources.add_all(ios_sources)
        ```
        Here, `frida_sources` is a `SourceSetImpl`. The `add_all` method conditionally includes Android or iOS specific instrumentation code based on the host operating system.

* **Target-Specific Modules:** Frida might have modules that target specific applications or frameworks. `sourceset` can be used to include these modules only when the corresponding target is being built or a specific build option is enabled.

    * **Example:** If Frida has a module for analyzing Chrome browser internals, they might have a build option `enable_chrome_module`. The `meson.build` could then use:
        ```python
        chrome_module_sources = source_set()
        chrome_module_sources.add('chrome_analyzer.c', when: 'enable_chrome_module')
        frida_core_sources.add_all(chrome_module_sources)
        ```
        The `chrome_analyzer.c` file will only be included if the `enable_chrome_module` option is true.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge (with examples):**

This module itself doesn't directly interact with the binary bottom or the kernel. However, it *manages the source code* that will eventually be compiled into binaries that *do* interact with these low-level components.

* **Platform-Specific System Calls and APIs:** When including source files conditionally based on the operating system (Linux, Android, etc.), the included code will inherently use OS-specific system calls and APIs.
    * **Example:**  As seen in the Android/iOS example above, the `android_instrumentation.c` and `ios_instrumentation.m` files would contain code that interacts with the respective operating system's APIs for process manipulation, memory access, etc.
* **Kernel Modules/Drivers:** While not directly shown in this code, if Frida had optional kernel modules or drivers, `sourceset` could be used to conditionally include their source files during the build process, based on whether kernel module support is enabled.
* **Android Framework Interaction:**  For Android, the conditional inclusion of source files might involve code that interacts with the Android Runtime (ART), Binder IPC, or other framework components.
    * **Example:** Frida might have specific hooks or instrumentation points within the Android framework. The `sourceset` module could be used to include the source code for these hooks only when building Frida for Android.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider a scenario:

**Hypothetical Input:**

1. A `SourceSetImpl` object named `my_sources`.
2. Adding a rule:
    *   `when`: `['FEATURE_A']` (a configuration option)
    *   `if_true`: `['src/feature_a.c']`
    *   `if_false`: `['src/feature_a_stub.c']`
3. Adding another rule:
    *   `when`: `[dependency('zlib')]` (checks for the zlib library)
    *   `if_true`: `['src/compression.c']`
4. Calling `apply_method` with `ConfigurationData` where `'FEATURE_A'` is `True`.

**Hypothetical Output:**

The `apply_method` would return a `SourceFilesObject` containing:

*   **Sources:** `['src/feature_a.c', 'src/compression.c']` (assuming zlib is found on the system). If zlib was not found, the sources would be `['src/feature_a.c']`.
*   **Dependencies:**  The dependency object for `zlib` (if found).

**Explanation of Logic:**

*   The first rule's condition (`'FEATURE_A'`) is true based on the provided `ConfigurationData`, so `src/feature_a.c` is included. `src/feature_a_stub.c` is skipped.
*   The second rule's condition depends on the `dependency('zlib')`. Meson will check if the zlib library is available on the system. If it is, `src/compression.c` will be included.

**User or Programming Common Usage Errors (with examples):**

* **Incorrect File Paths:**  Providing an incorrect path to a source file in `add_method`.
    *   **Example:** `my_sources.add('srs/feature.c')` (typo in `src`). This would likely cause a build error later when Meson tries to find the file.
* **Mixing Positional and Keyword Arguments Incorrectly:** The code explicitly checks for this in `add_method` and `add_all_method`.
    *   **Example:** `my_sources.add('file1.c', when=['SOME_FEATURE'], if_true=['file2.c'])` - This is ambiguous and the code will raise an `InterpreterException`.
* **Using `add` or `add_all` After Calling a Querying Method:** Once methods like `all_sources_method` or `apply_method` are called, the `frozen` flag is set to `True`. Trying to add more rules after this will raise an `InvalidCode` exception.
    *   **Example:**
        ```python
        sources = my_sources.all_sources()
        my_sources.add('another_file.c') # This will raise an error.
        ```
* **Missing Configuration Keys in Strict Mode:** When using `apply_method` with `strict=True`, if a condition key specified in a `when` clause is not present in the provided configuration data, an `InvalidArguments` exception will be raised.
    *   **Example:** If a rule has `when=['MY_OPTION']` and `apply_method` is called with configuration data that doesn't contain `'MY_OPTION'`, and `strict=True`, it will fail.

**User Operation to Reach This Code (Debugging Clues):**

A user (likely a Frida developer) would interact with this code indirectly through the Meson build system. Here's a potential sequence of steps and how it might lead to this code being involved in debugging:

1. **Modify `meson.build`:** The developer might modify Frida's `meson.build` file to add a new feature, conditionally include a new module, or change the conditions for including existing code. This would involve using the `sourceset` module's functions.
2. **Run Meson Configuration:** The developer runs the Meson configuration command (e.g., `meson setup build`). This is where Meson parses the `meson.build` files and executes the Python code, including the `sourceset` module.
3. **Run Meson Compilation:** The developer runs the Meson compilation command (e.g., `meson compile -C build`). Meson uses the information gathered during the configuration stage, including the lists of source files determined by the `sourceset` module, to compile the project.
4. **Encounter Build Errors or Unexpected Behavior:** If there are issues with which source files are being included, the developer might need to investigate.
5. **Debugging:**
    *   **Examine `meson.log`:** Meson often logs information about its operations, including the evaluation of conditional logic. The developer might look in `meson.log` to see which `sourceset` rules were matched and which source files were included.
    *   **Print Statements:** The developer might temporarily add `print()` statements within the `sourceset.py` code or in their `meson.build` file (around the `sourceset` calls) to inspect the state of the `SourceSetImpl` objects and the values of the configuration options.
    *   **Meson's Introspection Tools:** Meson has introspection capabilities that allow developers to query the build setup. This could be used to inspect the final list of source files generated by the `sourceset` module.
    *   **Stepping Through the Code:** In more complex scenarios, a developer might use a Python debugger to step through the execution of the `sourceset.py` code to understand exactly how the conditions are being evaluated and why certain files are being included or excluded.

In essence, this `sourceset.py` file is a fundamental part of Frida's build system, enabling a flexible and configurable way to manage the inclusion of source code based on various factors. Understanding its functionality is crucial for developers working on or extending Frida.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/sourceset.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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