Response:
Let's break down the thought process for analyzing this Python code snippet from the Frida project.

1. **Understand the Goal:** The request asks for an explanation of the code's functionality, its relation to reverse engineering, low-level concepts, logical reasoning, common user errors, and how a user's actions might lead to this code being executed.

2. **High-Level Overview:**  The filename `dependencyfallbacks.py` and the class name `DependencyFallbacksHolder` strongly suggest this code is responsible for handling scenarios where a dependency needed by the build system (Meson) is not found. It seems to manage alternative ways to satisfy the dependency, potentially by building it from source (a subproject).

3. **Core Functionality - Dissecting the Code:**

   * **Initialization (`__init__`)**:  It takes a list of dependency names, the target machine architecture, and options related to fallbacks. It initializes various Meson-related objects like the interpreter, build information, and environment.
   * **Fallback Mechanisms:**  The presence of methods like `set_fallback`, `_subproject_impl`, `_do_subproject`, and `_get_subproject_dep` clearly points to the core function: trying different methods to find a dependency.
   * **Caching (`_do_dependency_cache`, `_get_cached_dep`):**  This indicates optimization. Meson tries to avoid repeatedly searching for the same dependency.
   * **External Dependency Search (`_do_dependency`):**  This suggests the code interacts with the system's package manager or standard search paths.
   * **Subproject Handling:** The code explicitly deals with subprojects, implying that if a dependency isn't found externally, it might try to build it as part of the current build process.
   * **Version Checking (`_check_version`):**  Dependencies often have version requirements. This method verifies if a found dependency meets those requirements.
   * **Override Mechanism:**  The code mentions `dependency_overrides`, suggesting a way to force the use of a specific dependency.
   * **Error Handling:**  `InterpreterException`, `InvalidArguments`, and `DependencyException` are used for signaling errors.
   * **Logging (`mlog`):**  The code uses a logging module to provide information about the dependency resolution process.

4. **Connecting to Reverse Engineering:**  Frida is a dynamic instrumentation toolkit used extensively in reverse engineering. The dependencies this code manages are likely libraries and tools necessary to build Frida itself. These dependencies could be:
    * **Core Libraries:**  glib, libxml2, etc., which Frida might rely on.
    * **Platform-Specific Libraries:** Libraries needed for specific operating systems or architectures Frida targets.
    * **Build Tools:**  While not strictly dependencies of the *built* Frida, the build process itself depends on tools like compilers and linkers (though this specific code doesn't directly manage those).

5. **Relating to Low-Level Concepts:**

   * **Binary/Native Code:** Frida interacts directly with running processes at a binary level. The dependencies being managed are often compiled native libraries.
   * **Linux/Android Kernel/Framework:** Frida can target these environments. The dependencies might include kernel headers or Android framework libraries required for building the parts of Frida that interact with these systems.
   * **Shared Libraries/Static Libraries:** The `static` keyword in the code indicates awareness of different linking methods.
   * **Machine Architecture:** The `for_machine` parameter highlights that dependencies can be architecture-specific.

6. **Logical Reasoning (Hypothetical Inputs and Outputs):**

   * **Input:** `dependency_fallbacks(['glib-2.0'], for_machine='host', allow_fallback=True)` followed by a `dependency('glib-2.0', version='>=2.60')`.
   * **Scenario 1 (glib found):** If glib >= 2.60 is found on the system, the output is a `Dependency` object representing the system's glib.
   * **Scenario 2 (glib not found, fallback available):** If glib is not found, and a subproject providing glib is defined, the output is a `Dependency` object representing the built glib from the subproject.
   * **Scenario 3 (glib not found, no fallback, required):** If glib is not found and no fallback is defined, and the dependency is `required`, a `DependencyException` is raised.

7. **Common User Errors:**

   * **Incorrect Dependency Name:** Misspelling the dependency name.
   * **Missing Subproject:** Specifying a fallback subproject that doesn't exist or isn't correctly configured.
   * **Version Mismatch:** Requiring a version of a dependency that's not available on the system or provided by the fallback.
   * **Conflicting Fallback Settings:**  Using both `fallback` and `allow_fallback` which are mutually exclusive.
   * **Incorrect `default_options`:** Providing invalid or unsupported options for the fallback subproject.

8. **User Steps Leading to This Code:**

   * **Initial Setup:** The user wants to build Frida. This usually involves running a build system like Meson.
   * **Meson Configuration:** Meson reads the `meson.build` file, which likely contains `dependency()` calls to find required libraries.
   * **Dependency Not Found:** Meson encounters a `dependency()` call for a library that isn't found on the system.
   * **Fallback Mechanism Triggered:** If the `dependency()` call was within a `dependency_fallbacks()` block (as is the case in this code), this `dependencyfallbacks.py` code is invoked to attempt alternative ways of satisfying the dependency. The user doesn't directly interact with this file, it's part of Meson's internal dependency resolution process.

9. **Refinement and Structure:**  Organize the findings into logical sections with clear headings and bullet points for readability. Use examples where appropriate. Emphasize the key concepts and their relevance to Frida and reverse engineering.

By following these steps, we can systematically analyze the code and generate a comprehensive explanation covering all aspects of the prompt. The key is to combine understanding the Python code itself with knowledge of the broader context of Frida and build systems.
This Python code file, `dependencyfallbacks.py`, is part of the Meson build system's interpreter, specifically within the Frida project's build setup for the `frida-qml` subproject. Its primary function is to manage the process of finding and handling dependencies required to build `frida-qml`. It introduces a mechanism for defining fallback strategies when a direct dependency lookup fails.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Dependency Grouping and Fallback Definition:**
   - The `DependencyFallbacksHolder` class allows defining a group of dependency names (e.g., `['Qt5Core', 'QtCore']`).
   - It provides a way to specify a fallback mechanism, typically involving building the dependency as a subproject if the system-wide dependency is not found or doesn't meet the requirements.
   - The `set_fallback` method (legacy) and the constructor's parameters handle the specification of the fallback subproject and its variable name.

2. **Dependency Lookup with Fallback Logic:**
   - The `lookup` method is the main entry point for finding a dependency. It orchestrates the following steps:
     - **Cache Check:** It first checks if the dependency has been previously found and cached.
     - **Existing Subproject Check:** If a fallback subproject is defined and already configured, it checks for the dependency within that subproject.
     - **External Dependency Search:** It attempts to find the dependency using standard system mechanisms (pkg-config, find_library, etc.).
     - **Subproject Build (Fallback):** If the external search fails and a fallback subproject is specified, it configures and builds the subproject to obtain the dependency.

3. **Version Management:**
   - The code handles dependency version requirements using the `version` keyword argument in the `dependency()` function.
   - The `_check_version` method compares the found dependency's version against the required versions.

4. **Handling `wrap_mode` and `force_fallback_for`:**
   - It respects Meson's `wrap_mode` option, which controls how wrap dependencies (pre-built binaries or source packages) are handled.
   - It considers the `force_fallback_for` option, which allows forcing the use of subproject fallbacks for specific dependencies.

5. **Logging and Debugging:**
   - The code uses Meson's logging (`mlog`) to provide information about the dependency lookup process, indicating whether dependencies were found, where they were found (system or subproject), and any version mismatches.

**Relationship to Reverse Engineering:**

This code is directly related to the reverse engineering process because Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. The dependencies managed by this code are essential for building Frida itself. These dependencies might include:

* **Core Libraries:** Libraries like glib, libxml2, etc., which Frida uses internally.
* **Platform-Specific Dependencies:** Libraries needed for specific operating systems (Linux, Android, Windows, macOS) that Frida targets. For example, on Android, it might need access to certain Android framework libraries.
* **Build Tools:** While not directly dependencies of the built Frida, the build process relies on tools (handled elsewhere in Meson), and sometimes, specific versions of libraries are required to interact with these tools correctly.

**Examples related to Reverse Engineering:**

* **Scenario:** Frida requires a specific version of `glib` to function correctly on Linux. If the system's `glib` version is too old, this code would detect that and potentially trigger the building of a newer `glib` version as a subproject (if configured) to satisfy Frida's requirements. This ensures Frida can be built and used even on systems with older base libraries.
* **Scenario:** When building Frida for Android, it might depend on certain Android NDK (Native Development Kit) libraries. If these libraries are not found in the standard locations, a fallback might involve pointing to a specific NDK installation or building a compatibility layer.

**Binary底层, Linux, Android内核及框架的知识:**

This code interacts with these concepts in several ways:

* **Binary 底层:** The dependencies being managed are often compiled binary libraries. The `static` keyword in the code hints at linking methods (static vs. shared libraries). The success of finding and linking these binaries is crucial for creating a functional Frida executable.
* **Linux:**  On Linux, the code might interact with `pkg-config` to find dependencies. It also needs to understand library search paths and linking conventions on Linux. The fallback mechanism might involve building libraries using standard Linux build tools (like `make`).
* **Android内核及框架:** When building Frida for Android, this code needs to handle dependencies on Android-specific libraries and frameworks. This could involve:
    * **NDK Libraries:**  Locating libraries provided by the Android NDK.
    * **System Libraries:**  Knowing how to link against system libraries present on Android devices (which may vary across versions).
    * **Framework Interaction:**  Understanding dependencies related to interacting with the Android runtime environment (e.g., libraries for hooking or instrumentation). The fallback mechanism might involve building custom libraries or shims to interact with the Android framework.

**逻辑推理 (Hypothetical Input and Output):**

**Hypothetical Input:**

```python
df_holder = DependencyFallbacksHolder(
    interpreter=some_interpreter_instance,
    names=['libxml2'],
    for_machine='host',
    allow_fallback=True
)
df_holder.set_fallback(['libxml2_fallback', 'libxml2_dep'])

# Later, during dependency lookup:
result = df_holder.lookup({'version': '>=2.9.0'}, force_fallback=False)
```

**Scenario 1: `libxml2` >= 2.9.0 is found on the system.**

* **Output:** `result` will be a `Dependency` object representing the system's `libxml2` library. The logs will indicate that `libxml2` was found on the system with a version meeting the requirement.

**Scenario 2: `libxml2` is found on the system, but the version is older than 2.9.0.**

* **Output:** The code will proceed to check the fallback. If the subproject `libxml2_fallback` builds successfully and provides a `Dependency` object named `libxml2_dep` with a version >= 2.9.0, `result` will be that `Dependency` object. The logs will show the system `libxml2` was found but did not meet the version requirement, and then the fallback subproject was used.

**Scenario 3: `libxml2` is not found on the system, and the `libxml2_fallback` subproject fails to build or doesn't provide the dependency correctly.**

* **Output:** A `DependencyException` will be raised because the required dependency could not be satisfied. The logs will indicate that the system `libxml2` was not found and the fallback subproject failed.

**用户或编程常见的使用错误:**

1. **Incorrect Fallback Subproject Name or Variable Name:**
   ```python
   df_holder.set_fallback(['wrong_subproject_name', 'incorrect_var_name'])
   ```
   If `wrong_subproject_name` doesn't exist or `incorrect_var_name` is not a valid dependency variable within the subproject, the lookup will fail during the fallback stage. The error message might indicate that the subproject couldn't be found or the variable was not a dependency object.

2. **Version Mismatch in Fallback:**
   If the fallback subproject builds successfully but provides a version of the dependency that still doesn't meet the requirements:
   ```python
   result = df_holder.lookup({'version': '>=3.0'}, force_fallback=True)
   # If the fallback subproject only provides libxml2 version 2.9
   ```
   The lookup will fail, and the logs will indicate that the fallback subproject provided a version that didn't match the requirement.

3. **Circular Dependencies in Fallbacks:**  While less directly caused by this code, if a fallback subproject itself depends on something that triggers another fallback leading back to the original dependency, it can create a circular dependency problem, potentially causing infinite loops or errors during the build process.

4. **Misunderstanding `allow_fallback` and `fallback`:** Using both or misunderstanding their behavior. `allow_fallback=False` prevents implicit fallback, while `fallback` explicitly defines a subproject.

**用户操作如何一步步的到达这里 (调试线索):**

1. **User initiates the Frida build process:** The user typically runs a command like `meson build` followed by `ninja -C build`.

2. **Meson parses the `meson.build` files:** Meson reads the `meson.build` file in the root directory and any subdirectories, including `frida/subprojects/frida-qml/meson.build`.

3. **`dependency()` function is encountered:** Within the `frida-qml/meson.build` file (or potentially included files), a call to the `dependency()` function might be used to require a dependency.

4. **Dependency lookup fails:** If the required dependency is not found on the system or doesn't meet the version requirements specified in the `dependency()` call, Meson's dependency resolution mechanism is triggered.

5. **`dependency_fallbacks()` is used:** If the original `dependency()` call was actually wrapped within a `dependency_fallbacks()` call (or if `allow_fallback` is True and an implicit fallback is available via wrap files), the `DependencyFallbacksHolder` class in this `dependencyfallbacks.py` file is instantiated and its `lookup()` method is called.

6. **Code execution within `lookup()`:** The code within the `lookup()` method proceeds through the steps described above: checking the cache, looking for existing subprojects, attempting external dependency search, and finally, potentially configuring and building the fallback subproject.

7. **Debugging Tip:** To debug issues related to dependency fallbacks, users can:
   - **Examine the Meson logs:** Meson provides detailed logs about the dependency resolution process, indicating which dependencies were found, where they were found, and if fallbacks were attempted.
   - **Inspect the `meson.build` files:** Verify the correct dependency names, version requirements, and fallback subproject configurations are specified.
   - **Run Meson interactively:** Meson offers interactive modes or options to get more detailed output during the configuration phase.
   - **Check the fallback subproject's build process:** If a fallback subproject is failing, investigating its own build logs and configuration is crucial.

In essence, this `dependencyfallbacks.py` file is a crucial part of Frida's build system, ensuring that all necessary components can be found or built, enabling the creation of the final Frida toolkit. It provides flexibility and robustness in handling varying system configurations and dependency availability.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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