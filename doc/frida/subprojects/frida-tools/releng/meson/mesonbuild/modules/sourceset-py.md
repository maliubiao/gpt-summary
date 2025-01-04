Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `sourceset.py` file within the Frida project. They're particularly interested in connections to reverse engineering, low-level concepts, and potential usage errors. They also want to understand how a user's actions might lead to this code being executed.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to get a general idea of what it does. Keywords like `SourceSet`, `add`, `apply`, `dependencies`, `ConfigurationData`, and `meson` stand out. This suggests the code is about managing sets of source files and their dependencies based on certain conditions, likely within the context of the Meson build system.

**3. Deeper Dive into Key Classes and Methods:**

Next, focus on the main classes and their methods:

* **`SourceSetRule`:** This seems to represent a conditional rule for including sources and dependencies. The `keys` and `deps` attributes likely control when the rule is active.
* **`SourceSetImpl`:** This appears to be the core class for managing a collection of `SourceSetRule` objects. The methods like `add`, `add_all`, `all_sources`, `all_dependencies`, and `apply` suggest ways to manipulate and query the source set.
* **`SourceFilesObject`:** This seems to be a container for the final resolved set of sources and dependencies.
* **`SourceSetModule`:** This is the Meson module that makes the `source_set` function available to Meson build scripts.

**4. Analyzing Functionality and Relating to Reverse Engineering:**

Now, consider how these functionalities could relate to reverse engineering:

* **Conditional Inclusion of Tools/Scripts:** The `when` keyword in `add` and `add_all` could be used to include specific reverse engineering tools or scripts based on build configuration flags (e.g., whether a debug build is being created or a specific architecture is targeted). *Self-correction:* Initially, I might just think about source files, but the inclusion of dependencies suggests this could extend to executables or libraries used by those tools.
* **Dynamic Analysis Setup:**  Frida is a dynamic instrumentation tool. This module could be used to conditionally include scripts or libraries needed for specific dynamic analysis scenarios. For example, different hooking scripts might be needed for different target applications.
* **Integration with Build System:**  This code is part of the build system. It helps automate the process of including the correct components for Frida's functionality, potentially including components used for reverse engineering tasks.

**5. Connecting to Low-Level Concepts:**

Think about how the code interacts with lower levels:

* **Binary Files:** The `mesonlib.File` and build targets clearly point to managing binary files that will be part of the Frida installation.
* **Linux/Android Kernel/Framework:** Frida interacts deeply with these. While this code doesn't directly manipulate kernel code, it *manages* the inclusion of files that *will* interact with the kernel or Android framework. Dependencies might include libraries that perform low-level operations.
* **Dependencies:**  Dependencies in a build system often represent libraries or other components needed at runtime, which could include libraries for interacting with the operating system or performing low-level operations.

**6. Identifying Logic and Providing Examples:**

Focus on the `collect` and `apply_method`. These perform logical operations based on the conditions defined in the `SourceSetRule` objects.

* **Hypothetical Input/Output:** Create simple scenarios to illustrate how the conditional logic works. For instance, a rule that includes a specific source file only if a "enable_feature_x" option is true.

**7. Spotting Potential Usage Errors:**

Consider how a user might misuse the API:

* **Using `add` after `apply`:** The code explicitly checks for `self.frozen`. This is a classic example of incorrect usage after a state change.
* **Mixing positional and keyword arguments:** The code has checks for this. It's a common source of confusion for users.
* **Missing configuration keys in strict mode:** The `apply_method` with `strict=True` will raise an error if a required key isn't present.

**8. Tracing User Actions to Code Execution (Debugging Clues):**

Think about the steps a user takes to build Frida:

1. **Configuration:** The user runs `meson` to configure the build, potentially setting options that influence the conditions in the `SourceSetRule` objects.
2. **Build Script Execution:** Meson executes the build scripts, including those that use the `sourceset` module.
3. **`source_set()` call:**  A Meson script would call the `source_set()` function to create a `SourceSetImpl` object.
4. **`add()` and `add_all()` calls:** The script would then use these methods to populate the source set with rules.
5. **`apply()` call:** Finally, the script would likely call `apply()` to resolve the source set based on the configuration.

**9. Structuring the Answer:**

Organize the information clearly, addressing each part of the user's request. Use headings and bullet points for readability. Provide code snippets where relevant.

**Self-Correction and Refinement During the Process:**

* **Initial thought:**  Maybe this is just about organizing source code.
* **Correction:** The inclusion of dependencies and the connection to the Meson build system suggest it's about managing build artifacts and their relationships.
* **Initial thought:** The reverse engineering connection is weak.
* **Correction:** Frida *is* a reverse engineering tool, and this module helps manage the components needed for its functionality, including those used for analysis.

By following these steps, we can systematically analyze the code and provide a comprehensive and informative answer to the user's question.
This Python code defines a Meson module named `sourceset` for the Frida dynamic instrumentation tool. Its primary function is to manage collections of source files and dependencies based on conditional rules. This is a crucial part of Frida's build system, allowing for flexible and configurable compilation.

Let's break down its functionalities with examples relating to reverse engineering, low-level concepts, logic, user errors, and debugging:

**Functionalities:**

1. **Defining Conditional Source Sets:**
   - The core concept is the `SourceSetImpl` class, which holds a list of `SourceSetRule` objects.
   - Each `SourceSetRule` defines conditions (based on configuration keys or dependencies) under which certain source files, other source sets, and dependencies should be included in the final build.
   - This allows Frida to include or exclude specific components based on the build configuration.

2. **Adding Sources and Dependencies Conditionally:**
   - The `add_method` allows adding individual source files and dependencies with conditions.
   - The `add_all_method` allows adding entire other `SourceSetImpl` instances conditionally.
   - Conditions are specified using the `when` keyword argument, which takes a list of configuration keys (strings) or dependencies. The rule is active if all the keys evaluate to true in the build configuration and all the dependencies are found.
   - `if_true` specifies what to add if the condition is true, and `if_false` specifies what to add if the condition is false.

3. **Resolving the Source Set:**
   - The `apply_method` takes a `ConfigurationData` object (from Meson) or a dictionary representing the build configuration.
   - It iterates through the rules and evaluates the conditions based on the provided configuration.
   - It collects the relevant source files and dependencies into a `SourceFilesObject`.
   - The `strict` keyword argument controls whether an error is raised if a configuration key referenced in a condition is not found in the provided configuration data.

4. **Retrieving Sources and Dependencies:**
   - The `all_sources_method` returns all source files in the source set, regardless of the configuration.
   - The `all_dependencies_method` returns all dependencies in the source set, regardless of the configuration.
   - The `SourceFilesObject` returned by `apply_method` also has `sources_method` and `dependencies_method` to retrieve the resolved sources and dependencies based on the applied configuration.

**Relationship to Reverse Engineering:**

- **Conditional Inclusion of Analysis Tools/Scripts:** Frida often incorporates helper scripts or tools for specific reverse engineering tasks. This `sourceset` module can be used to include these tools conditionally.
    - **Example:** Imagine Frida has a script to analyze Mach-O binaries (common on macOS). A `SourceSetRule` could be defined to include this script only when the target platform is macOS.
    ```python
    # In a Meson build definition file
    frida_tools = import('sourceset')
    my_sources = frida_tools.source_set()

    # ... other source additions ...

    if host_machine.system() == 'darwin':
        my_sources.add(files('mach_o_analyzer.py'), when: 'enable_macho_analysis')
    ```
    This means `mach_o_analyzer.py` will only be included in the build if the build is happening on macOS and a Meson option `enable_macho_analysis` is set to `true`.

- **Platform-Specific Instrumentation Modules:** Frida supports various platforms (Android, iOS, Linux, Windows). Certain instrumentation modules might be specific to a platform. `sourceset` helps manage the inclusion of these platform-specific modules.
    - **Example:** An Android-specific module for hooking system calls could be included conditionally.
    ```python
    # In a Meson build definition file
    frida_core = import('sourceset')
    core_sources = frida_core.source_set()

    # ... other core sources ...

    if target_machine.system() == 'android':
        core_sources.add(files('android_syscall_hook.c'))
    ```

**Relationship to Binary Bottom, Linux, Android Kernel & Framework:**

- **Managing Native Code and Libraries:** Frida heavily relies on native code (C/C++) that interacts directly with the operating system kernel and frameworks. `sourceset` is crucial for managing the compilation and linking of these native components.
    - **Example:** On Linux, Frida needs to interact with the `ptrace` system call for debugging. Source files related to this interaction would be managed by `sourceset`.
    - **Example:** On Android, Frida interacts with the Android Runtime (ART) and system services. The source code for Frida's agent running within the target Android process would be managed here.

- **Conditional Inclusion of Kernel Modules/Components (Less Direct):** While this specific Python code doesn't directly interact with kernel code, it manages the build process for components that *do*. For instance, if Frida had optional kernel-level instrumentation capabilities, `sourceset` would manage the source files for those components.

**Logical Reasoning with Hypothetical Input/Output:**

**Hypothetical Input (Meson Configuration):**
```
configuration_data = {
    'enable_feature_x': True,
    'target_arch': 'x86_64',
}
```

**Hypothetical Source Set Rules:**
```python
# Inside a Meson build definition
my_sources = sourceset_module.source_set(interpreter)
my_sources.add(files('common.c'))
my_sources.add(files('feature_x.c'), when: 'enable_feature_x')
my_sources.add(files('arch_specific.c'), when: 'target_arch == "x86_64"')
my_sources.add(files('fallback.c'), if_false: 'enable_feature_x')
```

**Hypothetical Output (from `apply_method`):**

The `apply_method` called with `configuration_data` would return a `SourceFilesObject` containing:

- **Sources:** `['common.c', 'feature_x.c', 'arch_specific.c']`
- **Dependencies:** (Assuming no dependencies were added in this example, but could contain library objects, etc.)

**Explanation:**

- `common.c` is always included.
- `feature_x.c` is included because `enable_feature_x` is `True`.
- `arch_specific.c` is included because `target_arch` is `x86_64`.
- `fallback.c` is *not* included because the `if_false` condition (`enable_feature_x`) is `True`.

**User or Programming Common Usage Errors:**

1. **Calling `add` after `apply`:** Once `apply` is called, the source set is considered "frozen."  Trying to add more sources afterward will raise an `InvalidCode` exception. This prevents accidental modifications after the resolution process.
   ```python
   my_sources = sourceset_module.source_set(interpreter)
   my_sources.add(files('initial.c'))
   resolved_sources = my_sources.apply(config_data)
   my_sources.add(files('oops.c')) # Raises InvalidCode
   ```

2. **Incorrect `when` condition:**  If the string in the `when` argument doesn't correspond to a valid configuration key, and `strict=True` is used in `apply`, an `InterpreterException` will be raised. If `strict=False`, the condition will simply evaluate to `False`.
   ```python
   my_sources = sourceset_module.source_set(interpreter)
   my_sources.add(files('conditional.c'), when: 'non_existent_option')
   resolved_sources = my_sources.apply(config_data, strict=True) # Raises InterpreterException if 'non_existent_option' not in config_data
   ```

3. **Mixing positional and keyword arguments in `add` or `add_all`:** The code enforces using either positional arguments (the source files directly) or the keyword arguments (`if_true`, `if_false`). Mixing them leads to an `InterpreterException`.
   ```python
   my_sources = sourceset_module.source_set(interpreter)
   my_sources.add(files('file1.c'), files('file2.c'), when: 'some_option') # Raises InterpreterException
   ```

**User Operations Leading to This Code:**

The execution of this code is part of the Frida build process using the Meson build system. Here's how a user's actions lead here:

1. **User Modifies Build Configuration (Optional):** The user might modify `meson_options.txt` or pass command-line arguments to `meson` (e.g., `-Denable_feature_x=true`). These actions set the values in the `ConfigurationData` object.

2. **User Runs `meson`:** The user executes the `meson` command to configure the build. Meson reads the `meson.build` files.

3. **Meson Executes Build Scripts:** Within the `meson.build` files (or other files included by them), the `sourceset` module is imported:
   ```python
   frida_sourceset = import('sourceset')
   ```

4. **`source_set()` is Called:** An instance of `SourceSetImpl` is created:
   ```python
   core_sources = frida_sourceset.source_set()
   ```

5. **`add()` and `add_all()` are Called:** The build scripts then use `add` and `add_all` to populate the `core_sources` object with conditional rules, specifying source files, dependencies, and conditions based on the build configuration and target platform.

6. **`apply()` is Called:**  Finally, to resolve the source set based on the current configuration, the `apply` method is called:
   ```python
   resolved_core_sources = core_sources.apply(meson.configuration_data())
   ```
   The `meson.configuration_data()` function provides the current build configuration to the `apply` method.

7. **Meson Uses the Resolved Sources:** Meson then uses the list of source files and dependencies returned by `apply` to generate the build system instructions for compiling and linking the Frida components.

**Debugging Clues:**

- **Tracebacks:** If there are errors in the Meson build scripts related to the `sourceset` module (e.g., incorrect method calls, type errors), Meson will provide tracebacks pointing to the line of code in the `sourceset.py` file where the error occurred.
- **Meson Log:** The Meson log (`meson-log.txt`) will contain information about the execution of the build scripts, including the calls to the `sourceset` module and the evaluation of the conditions. This can help understand why certain sources were included or excluded.
- **Print Statements (for Developers):** Developers working on the Frida build system might temporarily add `print()` statements within the `sourceset.py` code to inspect the state of the `SourceSetImpl` object, the rules, and the configuration data during the build process.

In summary, the `sourceset.py` file is a fundamental part of Frida's build system, enabling a flexible and configurable compilation process based on various build options and target platforms. It plays a crucial role in managing the inclusion of different components, including those related to reverse engineering and low-level system interactions.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/sourceset.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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