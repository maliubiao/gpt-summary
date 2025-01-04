Response:
Let's break down the thought process to analyze the Python code for `dependencyfallbacks.py`.

1. **Understand the Core Purpose:** The filename and the initial comments clearly point to dependency handling within the Frida build system. Specifically, it seems to manage fallback strategies when a direct dependency isn't found.

2. **Identify Key Classes and Functions:** Start by listing the primary structures:
    * `DependencyFallbacksHolder`: This is the central class. Its name strongly suggests it holds information and manages the logic for dependency fallbacks.
    * `__init__`:  The constructor is always a good place to start to understand the initial state and required inputs. Here, it takes `interpreter`, `names`, `for_machine`, etc. These inputs hint at the broader build context.
    * Methods starting with `_do_`: These likely represent different stages or strategies in the dependency lookup process. `_do_dependency_cache`, `_do_dependency`, `_do_existing_subproject`, `_do_subproject`.
    * `lookup`: This seems like the main entry point for finding a dependency, considering fallbacks.
    * `set_fallback`:  Likely a way to configure the fallback mechanism.

3. **Analyze Function Signatures and Docstrings (even if brief):** Look at the arguments and return types of the key functions. This gives clues about what data they process and produce. For instance, `lookup` returns a `Dependency` object.

4. **Trace the `lookup` Function (the main flow):** This is often the most crucial part. Follow the steps within `lookup`:
    * It checks for `modules`.
    * It checks if the dependency is disabled or required.
    * It handles `wrap_mode` and `force_fallback_for` options, indicating interaction with build configuration.
    * It potentially adds implicit subproject fallbacks using `wrap_resolver`.
    * It calls `_get_candidates` to generate a list of lookup strategies.
    * It iterates through these candidates, trying each one.
    * It handles the cases where a dependency is found, not found but required, or not found but optional.

5. **Examine Individual `_do_` Methods:**  Understand what each strategy does:
    * `_do_dependency_cache`: Checks for previously cached dependency information.
    * `_do_dependency`:  Attempts to find the dependency using standard system mechanisms. This strongly relates to linking and finding libraries on the system.
    * `_do_existing_subproject`:  Looks for the dependency within a previously configured subproject.
    * `_do_subproject`: Configures and builds the fallback subproject if necessary. This implies building from source.

6. **Identify Key Concepts and Data Structures:**
    * `Dependency`:  A class representing a software dependency.
    * `SubprojectHolder`: Represents a subproject within the build.
    * `WrapMode`:  An enum or similar structure controlling dependency wrapping/fallback behavior.
    * `OptionKey`:  Keys for accessing build options.
    * `self.coredata`, `self.build`, `self.environment`, `self.wrap_resolver`: These are attributes likely representing core components of the Meson build system. Understanding what these generally do is helpful.

7. **Connect to Reverse Engineering Concepts:** Think about how dependency management relates to reverse engineering:
    * **Dynamic Instrumentation (Frida's purpose):**  Frida needs to inject code, which often requires resolving dependencies on libraries at runtime. This file helps ensure those libraries can be found, potentially by building them from source if they're missing on the target system.
    * **Library Resolution:**  The code explicitly deals with finding external dependencies (`dependencies.find_external_dependency`). This mirrors the challenges in reverse engineering where you often need to identify which libraries a binary uses.
    * **Building from Source:** The fallback mechanism involving subprojects directly relates to building dependencies from source, which can be necessary in reverse engineering environments where pre-built binaries aren't available or match the target.

8. **Connect to System-Level Concepts:**
    * **Linux/Android:** The concepts of shared libraries, static libraries, and the linking process are fundamental to understanding how this code works. The `default_library` option, for example, is a direct Linux/Android concept.
    * **Kernel/Framework:**  While this specific file doesn't directly interact with the *running* kernel, the dependencies it manages *might* be kernel modules or framework components. Frida itself interacts deeply with the target process, which may involve framework APIs.

9. **Look for Logic and Decision Points:**  Identify the `if` conditions and how they control the flow. For example, the checks for `forcefallback`, `nofallback`, and the order of the candidates in `_get_candidates`.

10. **Consider User Errors:**  Think about how a user might misuse the dependency system:
    * Incorrectly specifying fallback options.
    * Forcing or disabling fallbacks in ways that break the build.
    * Providing incorrect version requirements.

11. **Trace User Actions:** Imagine the steps a developer takes that lead to this code being executed:
    * Editing the `meson.build` file.
    * Declaring a dependency using `dependency()`.
    * Potentially using the `fallback` or `allow_fallback` keywords.
    * Running the `meson` command to configure the build.

12. **Review for Specific Details:**  Notice things like the version checking (`_check_version`, `version_compare_many`), the handling of "modules," and the logging statements. These provide finer-grained understanding.

By following these steps, you can systematically analyze the code and understand its functionality, its relationship to reverse engineering, its reliance on system-level concepts, and potential areas for user error. The key is to start with the high-level purpose and gradually drill down into the details, always relating the code back to the broader context of the Frida build system and its goals.
This Python code file, `dependencyfallbacks.py`, is a crucial part of the Frida build system, specifically within the Meson build environment. Its primary function is to manage the process of finding and resolving external dependencies required to build Frida. It implements a fallback mechanism, meaning if a dependency isn't found in the standard system locations, it can try alternative methods like building it from a subproject.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Dependency Lookup with Fallbacks:** The central goal is to locate dependencies needed for building Frida. It employs a prioritized approach, trying different methods in sequence until a suitable dependency is found. This includes:
    * **Checking the dependency cache:**  See if the dependency has been found and cached in a previous build.
    * **Searching for external dependencies:** Looking for the dependency in standard system locations using tools provided by the underlying operating system (e.g., `pkg-config` on Linux).
    * **Checking for existing subprojects:**  If a subproject providing the dependency has already been configured, use the dependency provided by that subproject.
    * **Configuring and building a fallback subproject:** If all other methods fail, it can configure and build the dependency from source as a subproject.

2. **Managing Fallback Subprojects:**  It handles the logic for using subprojects as fallbacks. This involves:
    * **Specifying the subproject:**  The `fallback` keyword in the `dependency()` function in `meson.build` files (the build definition files for Meson) is used to point to a subproject that provides the dependency.
    * **Configuring the subproject:** It triggers the configuration of the fallback subproject.
    * **Retrieving the dependency from the subproject:** Once the subproject is configured, it retrieves the dependency object from the subproject's variables.

3. **Handling Dependency Overrides:** It interacts with the dependency override mechanism in Meson. This allows developers to explicitly specify which dependency to use, bypassing the standard lookup.

4. **Version Checking:** It supports specifying version requirements for dependencies and verifies if the found dependency meets those requirements.

5. **Logging and Debugging:** It includes logging statements to provide information about the dependency lookup process, including whether a dependency was found, where it was found, and any version mismatches.

**Relationship to Reverse Engineering:**

This file is directly related to reverse engineering because Frida is a dynamic instrumentation toolkit heavily used in reverse engineering.

* **Dependency on Target Environment:** When Frida is used to instrument a process on a target system (e.g., Android, iOS, Linux), it often needs to interact with libraries and frameworks present on that target. This file ensures that the *build* process of Frida itself can locate the necessary build-time dependencies, which might be related to the target environments Frida will be used on. For example, building Frida for Android might require dependencies related to the Android NDK.

* **Building from Source for Specific Targets:** The fallback subproject mechanism is crucial when building Frida for platforms where pre-built dependencies are not readily available or are outdated. This is very common in embedded systems and specialized target environments often encountered in reverse engineering. Imagine you're reverse-engineering a specific embedded Linux device. You might need to build Frida with dependencies specifically compiled for that device's architecture and libraries, and this file facilitates that.

**Example:**

Let's say Frida needs the `glib-2.0` library. The `meson.build` file might contain a line like this:

```python
glib_dep = dependency('glib-2.0', fallback: 'glib')
```

If the system doesn't have `glib-2.0` installed or if the installed version doesn't meet the requirements, `dependencyfallbacks.py` will:

1. **Attempt to find `glib-2.0` using standard system methods (e.g., `pkg-config`).**
2. **If that fails, it will look for a subproject named `glib`.**  This subproject would contain the source code and build instructions for `glib-2.0`.
3. **It will configure and build the `glib` subproject.**
4. **Finally, it will retrieve the `glib-2.0` dependency object from the built `glib` subproject.**

**Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

This code implicitly touches upon these areas:

* **Binary Underlying:**  The entire process of finding and linking dependencies is fundamental to how binary executables are built. The code deals with the abstract concept of a "dependency," but ultimately, these dependencies manifest as shared libraries (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows) or static libraries (`.a` on Linux).

* **Linux:** The use of `pkg-config` (though not explicitly in this snippet, it's part of the `dependencies.find_external_dependency` function) is a common Linux practice for finding library information. The concepts of shared libraries and how the linker finds them are relevant.

* **Android Kernel & Framework:** While this specific file doesn't directly interact with the Android kernel code, the dependencies Frida needs to function on Android often relate to the Android framework. For instance, building Frida for Android might require dependencies from the Android NDK (Native Development Kit), which provides access to lower-level framework components. The fallback mechanism might be used to build specific versions of libraries required by the Android framework Frida aims to interact with.

**Example:** When building Frida for Android, a dependency on `libusb` might be required to communicate with the Android device. If `libusb` isn't found on the build machine, a fallback subproject could build it specifically for the target Android architecture.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

* `names`: `['openssl']` (The dependency we are looking for is OpenSSL)
* `for_machine`: `MachineChoice.HOST` (We are building for the host machine)
* `allow_fallback`: `True`
* A subproject named `openssl-source` exists, containing the OpenSSL source code and a `meson.build` file to build it.

**Hypothetical Output:**

* The function `lookup` would return a `Dependency` object representing OpenSSL. This object would contain information about the location of the OpenSSL library, include files, etc.
* The logging would show:
    * "Looking for dependency openssl for host machine"
    * "Dependency openssl for host machine found: NO" (initially, if not found via system methods)
    * "Looking for a fallback subproject for the dependency openssl"
    * (Logs related to configuring and building the `openssl-source` subproject)
    * "Dependency openssl for host machine from subproject openssl-source found: YES" (or similar)

**User/Programming Common Usage Errors:**

1. **Incorrect Fallback Subproject Name:**  If the `fallback` keyword in `dependency()` points to a subproject that doesn't exist or has a typo in its name, the build will fail.

   ```python
   # Error: "openssls" is misspelled
   openssl_dep = dependency('openssl', fallback: 'openssls')
   ```
   **Error message:**  Likely an error during the subproject lookup or configuration phase.

2. **Missing `meson.build` in Fallback Subproject:** If the specified fallback subproject directory doesn't contain a `meson.build` file, Meson won't know how to build it.

   **Error message:** Meson will complain that it cannot find a `meson.build` file in the specified subproject directory.

3. **Circular Dependencies in Fallback Subprojects:** If a fallback subproject depends on another dependency that also has a fallback pointing back to the first subproject (or a chain leading back), this will create a circular dependency and the build will likely fail.

   **Error message:**  Meson might detect the circular dependency and report an error, or the build process might hang indefinitely.

4. **Version Mismatches in Fallback:**  The fallback subproject might build a version of the dependency that doesn't satisfy the version requirements specified in the main project's `dependency()` call.

   ```python
   # Requires OpenSSL >= 1.1
   openssl_dep = dependency('openssl', version: '>=1.1', fallback: 'openssl-legacy')
   # If openssl-legacy builds OpenSSL 1.0, this will fail
   ```
   **Error message:**  The logging will indicate that the found version from the subproject doesn't meet the requirements.

**User Operations Leading to This Code:**

1. **Developer Edits `meson.build`:** A developer defines a dependency using the `dependency()` function in a `meson.build` file. This might include the `fallback` keyword.

   ```python
   # In frida/meson.build or a subproject's meson.build
   pcre_dep = dependency('libpcre2-8', fallback: 'pcre2')
   ```

2. **Developer Runs `meson`:** The developer executes the `meson` command to configure the build:

   ```bash
   meson setup builddir
   ```

3. **Meson Interprets `meson.build`:**  Meson reads and interprets the `meson.build` files. When it encounters the `dependency()` call, it creates a `DependencyFallbacksHolder` object.

4. **`lookup` Method is Called:** The `lookup` method of the `DependencyFallbacksHolder` is called to find the dependency.

5. **Dependency Lookup Process:** The `lookup` method within `dependencyfallbacks.py` orchestrates the various attempts to find the dependency (cache, system, existing subproject, fallback subproject).

6. **If Fallback is Needed:** If the dependency isn't found through standard methods, the code in `dependencyfallbacks.py` will initiate the configuration and building of the specified fallback subproject. This involves interacting with the Meson subproject functionality.

7. **Dependency Object is Returned:**  Finally, the `lookup` method returns a `Dependency` object, which Meson uses to provide information about the dependency to other parts of the build system (e.g., for linking executables).

In essence, this file is a core part of the dependency resolution mechanism within the Frida build process, triggered by the developer's declaration of dependencies in the `meson.build` files and the subsequent execution of the `meson` configuration command. It acts as a central point for managing fallback strategies when dependencies are not readily available.

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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