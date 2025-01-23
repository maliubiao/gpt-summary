Response:
Let's break down the thought process for analyzing this Python code snippet. The goal is to understand its functionality within the Frida ecosystem, particularly concerning dependency management.

**1. Initial Reading and High-Level Understanding:**

* **Keywords:**  The filename `dependencyfallbacks.py` immediately suggests this code deals with handling situations where a dependency isn't found and needs a fallback mechanism. The presence of `frida`, `subprojects`, `meson`, and `interpreter` strongly implies this is part of Frida's build system, which likely uses Meson.
* **Imports:**  Looking at the imports confirms this. `mesonbuild.interpreterobjects`, `mesonbuild.mlog`, `mesonbuild.dependencies`, etc., all point to Meson's internal modules. The import of `frida.tools` from the directory path reinforces its belonging to the Frida project.
* **Class Definition:** The core of the file is the `DependencyFallbacksHolder` class. This is the central actor managing the fallback logic.

**2. Deeper Dive into the `DependencyFallbacksHolder` Class:**

* **`__init__`:**  This method initializes the object. Key parameters include `interpreter`, `names` (the dependencies being looked for), `for_machine` (target architecture), and `allow_fallback`. The initialization of various attributes like `coredata`, `build`, `environment`, and `wrap_resolver` hints at interaction with Meson's core functionalities. The handling of `names` with checks for empty names, forbidden characters, and duplicates shows input validation.
* **`set_fallback` and `_subproject_impl`:** These methods seem to handle specifying a subproject as a fallback for the dependencies. The separation suggests `set_fallback` might be a higher-level interface (potentially for legacy reasons as the comment suggests), while `_subproject_impl` does the actual assignment.
* **`_do_dependency_cache`:** This is likely the first step in the dependency lookup process. It checks if a dependency is already cached, which is common in build systems to avoid redundant searches.
* **`_do_dependency`:**  This method appears to be responsible for finding external dependencies using Meson's `dependencies.find_external_dependency`. The logic for caching found dependencies is present.
* **`_do_existing_subproject` and `_do_subproject`:** These methods handle the fallback mechanism. `_do_existing_subproject` checks if the fallback subproject is already configured, while `_do_subproject` seems to initiate the configuration of the fallback subproject if needed. The logging statements within these methods ("Looking for a fallback subproject...") are crucial for understanding the flow.
* **`_get_subproject` and `_get_subproject_dep`:** These helper methods are for retrieving and handling dependencies within a subproject. The version checking logic (`_check_version`) and the warning about inconsistent overrides are important details.
* **Logging (`_log_found`):** This method provides visibility into the dependency resolution process, indicating whether a dependency was found and from where.
* **Caching (`_get_cached_dep`):** This method details how dependencies are retrieved from the cache and how version requirements are handled against cached versions. The interaction with `dependency_overrides` is worth noting.
* **Subproject Variable Access (`_get_subproject_variable`):** This method explains how to retrieve a dependency object exposed as a variable within a subproject.
* **Feature Checks (`_handle_featurenew_dependencies`):** This highlights the use of Meson's `FeatureNew` mechanism to track when specific dependency types were introduced.
* **Not Found (`_notfound_dependency`):** This is a utility to create a "not found" dependency object.
* **Version Checking (`_check_version`):** This static method implements the logic for comparing found dependency versions with required versions.
* **`_get_candidates`:** This crucial method defines the *order* in which different dependency lookup strategies are attempted. This order is critical to the fallback logic.
* **`lookup`:** This is the main entry point for the dependency lookup. It orchestrates the entire process, including handling disabled dependencies, forced fallbacks, implicit fallbacks based on wrap files, and iterating through the candidates defined in `_get_candidates`. The error handling for required dependencies is also here.

**3. Connecting to Reverse Engineering and Frida:**

* **Frida's Dynamic Instrumentation:**  Knowing that Frida is a dynamic instrumentation toolkit, dependencies are essential. Frida might depend on libraries for code injection, memory manipulation, or inter-process communication.
* **Subprojects and Fallbacks:**  If a user is building Frida on a system where a specific dependency (like `glib` or `openssl`) isn't available in the standard system paths, Frida's build system needs a way to handle this. The `dependencyfallbacks.py` provides this by trying to use a pre-packaged version of the dependency (the "subproject").

**4. Identifying Low-Level, Kernel, and Framework Connections:**

* **External Dependencies:**  The code directly uses `dependencies.find_external_dependency`, indicating it interacts with the operating system's package management or standard library locations to find libraries. This ties into the underlying OS.
* **Subprojects (Potentially):**  The subprojects themselves might involve building libraries that interact with the kernel (e.g., if Frida needs a specific low-level driver or library).
* **Android (Potentially):** While not explicitly mentioned in the code, Frida is heavily used on Android. The dependency management could handle dependencies specific to the Android framework or NDK.

**5. Logical Reasoning, Assumptions, and Examples:**

* **Order of Operations:**  The `_get_candidates` method makes assumptions about the best order to find dependencies (cache first, then existing subproject, then external, then building a subproject).
* **Input/Output Examples:** Imagining a call to `dependency_fallbacks(['glib'], for_machine='host')`. The code would first check the cache, then look for a `glib` subproject, then search system-wide for `glib`, and finally try to build the `glib` subproject if available.

**6. Common User Errors:**

* **Missing Dependencies:** A common error is when a required dependency isn't found, and no fallback is provided or the fallback fails to build.
* **Incorrect Configuration:** Users might misconfigure the build environment, leading to the dependency lookup failing.

**7. Tracing User Operations:**

* **Meson Invocation:**  The user starts the process by running `meson setup build`.
* **`meson.build`:**  The `meson.build` file will contain calls to `dependency()` or a similar function that eventually leads to the `DependencyFallbacksHolder`.
* **Dependency Lookup:**  Meson will then use the logic in this file to try and find the required dependencies.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  "This is just about finding dependencies."
* **Correction:** "It's specifically about handling *fallback* scenarios when dependencies aren't found directly."
* **Initial thought:** "The subprojects are just pre-built binaries."
* **Refinement:** "The subprojects might need to be *built* if they aren't already configured, which involves running their own build scripts."
* **Initial thought:**  "The code directly calls OS APIs for finding libraries."
* **Refinement:** "It uses Meson's dependency finding mechanisms, which abstract away the direct OS calls, but the underlying principle is still about finding system libraries."

By following this detailed thought process, breaking down the code into smaller parts, understanding the context (Frida and Meson), and making connections to related concepts, we can arrive at a comprehensive understanding of the `dependencyfallbacks.py` file's functionality.
This Python code file, `dependencyfallbacks.py`, is a crucial part of Frida's build system, specifically within the Meson build environment. Its primary function is to manage the process of finding and handling dependencies required to build Frida and its associated tools. It implements a fallback mechanism, attempting various strategies to locate a dependency before giving up.

Here's a breakdown of its functions and how they relate to reverse engineering, low-level aspects, logic, and potential user errors:

**Core Functionality:**

1. **Dependency Lookup with Fallbacks:** The central purpose of this code is to locate dependencies needed for building Frida components. It doesn't just look in standard system paths; it defines a sequence of "fallbacks" to try if the initial attempt fails. These fallbacks can include:
    * **Checking a cache:** See if the dependency was found in a previous build.
    * **Using an existing subproject:** If the dependency is provided as a separate sub-project within the Frida source tree, use that.
    * **Searching for the external dependency:** Look in standard system locations and using system package managers.
    * **Configuring and building a subproject:** If a fallback subproject exists for the dependency, configure and build it.

2. **Managing Subproject Dependencies:**  Frida's build might involve incorporating code from other smaller projects (subprojects). This file helps manage dependencies that might be fulfilled by these subprojects.

3. **Handling Dependency Overrides:**  Meson allows overriding dependencies. This code interacts with Meson's override mechanism to ensure consistent dependency resolution.

4. **Version Checking:** It checks if the found dependency meets the required version constraints.

5. **Logging and Diagnostics:**  The code includes logging statements to provide information about the dependency lookup process, indicating which strategies are being tried and whether they succeed or fail.

**Relationship to Reverse Engineering:**

* **Dependency on Libraries for Instrumentation:** Frida, as a dynamic instrumentation tool, heavily relies on various libraries. These libraries might include:
    * **Low-level system libraries:** Libraries for memory management, threading, inter-process communication, etc. (e.g., `libc`, `pthread`).
    * **Platform-specific libraries:** Libraries relevant to the target operating system (e.g., on Linux, libraries related to process management, ptrace; on Android, libraries from the Android framework).
    * **Communication libraries:** Libraries for communicating between the Frida client and the target process.
* **Building Blocks for Reverse Engineering Tools:**  The successful building of Frida, which this code contributes to, is a prerequisite for using Frida for reverse engineering tasks. Without the necessary dependencies, Frida cannot be built and therefore cannot be used for dynamic analysis, hooking, and other reverse engineering techniques.
* **Example:**  Frida might depend on `glib` for its core functionalities. If the system doesn't have `glib` installed or the correct version, this code would try to use a provided `glib` subproject as a fallback, ensuring Frida can still be built.

**Binary底层, Linux, Android Kernel & Framework Knowledge:**

* **Binary 底层:** The concept of dependencies itself is fundamental at the binary level. Executables rely on shared libraries at runtime. This code ensures that the necessary binary libraries are available during the build process.
* **Linux Kernel:** Frida on Linux often interacts directly with the kernel through system calls like `ptrace`. Dependencies related to debugging and system interaction might be involved. For instance, if Frida uses a library that wraps `ptrace` functionality in a more convenient way, this code would manage that dependency.
* **Android Kernel & Framework:** Frida is heavily used on Android. Dependencies here could include:
    * **NDK Libraries:** Libraries provided by the Android Native Development Kit (NDK), which offer low-level access to system functionalities.
    * **Android Framework Libraries:**  While Frida often bypasses the framework for direct instrumentation, some build components might depend on framework libraries for utility functions or build tooling.
* **Example:**  If Frida uses a specific library for interacting with Android's ART runtime (the runtime environment for Android apps), this code would manage that library as a dependency.

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario:** Building Frida on a Linux system where the `libssl-dev` package (containing header files for OpenSSL development) is missing.

**Input:**

* **`names` in `DependencyFallbacksHolder`:** `['openssl']` (Frida needs the OpenSSL library)
* **Meson configuration:** Does not specify a custom path for OpenSSL.
* **`allow_fallback`:**  Likely `True` or left as default.
* **Frida source tree:** Contains a subproject for OpenSSL (e.g., a pre-packaged version or build script).

**Process:**

1. **`_do_dependency_cache`:** Checks the cache; likely misses.
2. **`_do_existing_subproject`:** Checks if an OpenSSL subproject is already configured; might miss initially.
3. **`_do_dependency`:** Attempts to find the external `openssl` dependency using system mechanisms. This would likely fail because `libssl-dev` is missing.
4. **`_do_subproject`:** Detects the OpenSSL subproject.
5. **Subproject Configuration:** The code triggers the configuration and build process for the OpenSSL subproject.
6. **`_get_subproject_dep`:** Retrieves the OpenSSL dependency information from the now built subproject.

**Output:**

* **Logging output:**  Will show attempts to find the external dependency failing, followed by the successful configuration and use of the OpenSSL subproject.
* **Return value of `lookup()`:** A `Dependency` object representing the OpenSSL library, sourced from the subproject.

**User or Programming Common Usage Errors:**

1. **Missing or Incorrectly Configured Fallback Subproject:**
   * **Error:** If the Frida source tree is incomplete or the OpenSSL subproject is corrupted, the fallback mechanism will fail.
   * **Example:**  A user might accidentally delete or modify files within the OpenSSL subproject directory.
   * **Debugging:** The logging output from `dependencyfallbacks.py` would indicate that the external dependency wasn't found, and the attempt to configure the subproject failed.

2. **Conflicting Dependencies:**
   * **Error:** The system might have an older version of a dependency that conflicts with the version required by Frida's subproject.
   * **Example:** The system has OpenSSL 1.0, but the Frida subproject requires OpenSSL 1.1.
   * **Debugging:**  The version checking logic (`_check_version`) would detect the mismatch, and logging might indicate the found version and the required version.

3. **Incorrect Meson Options:**
   * **Error:**  Users might provide Meson options that unintentionally disable fallback mechanisms or force the use of system dependencies when they are not available.
   * **Example:** Using a Meson option like `--wrap-mode=nofallback`.
   * **Debugging:** Understanding Meson's options and how they influence dependency resolution is crucial.

4. **Permissions Issues:**
   * **Error:** The user running the build might not have the necessary permissions to configure or build the fallback subproject.
   * **Example:**  The subproject's build process requires writing to a directory where the user lacks permissions.
   * **Debugging:** System error messages during the subproject configuration or build would provide clues.

**How User Operations Reach This Code (Debugging Clues):**

1. **User runs `meson setup build` or `ninja`:** This initiates the Frida build process.
2. **Meson parses the `meson.build` files:** Frida's `meson.build` files contain calls to the `dependency()` function (or similar), specifying the required dependencies.
3. **Meson's interpreter executes the `dependency()` calls:** When a `dependency()` call is encountered, and if fallbacks are involved, the Meson interpreter will create a `DependencyFallbacksHolder` object.
4. **The `lookup()` method is called:** The interpreter calls the `lookup()` method of the `DependencyFallbacksHolder` to find the dependency.
5. **The methods within `dependencyfallbacks.py` are executed:**  The `_do_dependency_cache`, `_do_existing_subproject`, `_do_dependency`, and `_do_subproject` methods are called in sequence to try different ways of finding the dependency.
6. **Logging output is generated:** The `mlog.log()` calls within this file will produce output on the console, providing insights into the dependency resolution process.

**To debug issues related to dependency resolution, a user can:**

* **Examine the Meson output:** Look for messages related to dependency checks, fallback attempts, and any errors encountered.
* **Increase Meson's verbosity:** Use options like `-v` or `-vv` with Meson to get more detailed output.
* **Inspect the `meson.build` files:** Understand which dependencies are being requested and if any specific fallback mechanisms are configured.
* **Check the Frida source tree:** Verify the presence and integrity of any expected fallback subprojects.
* **Ensure necessary development packages are installed:**  Before building, make sure that the system has the required development packages (e.g., `-dev` packages on Debian/Ubuntu) for common dependencies.

In summary, `dependencyfallbacks.py` is a critical component for ensuring a robust and user-friendly build process for Frida by intelligently handling missing dependencies through a well-defined fallback mechanism. Its functionality directly relates to the low-level aspects of building software and is essential for reverse engineering efforts using Frida.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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