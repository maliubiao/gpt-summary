Response:
Let's break down the thought process for analyzing this Python code and fulfilling the request.

**1. Understanding the Core Request:**

The request asks for an explanation of a specific Python file (`dependencyfallbacks.py`) within the Frida project. Key aspects to address are: functionality, relevance to reverse engineering, low-level details (kernel, etc.), logical reasoning (inputs/outputs), common user errors, and how a user reaches this code (debugging context).

**2. Initial Code Scan and Keyword Recognition:**

My first step was to quickly scan the code for recognizable keywords and patterns:

* **Class `DependencyFallbacksHolder`:** This is the central element, suggesting it manages fallback mechanisms for dependencies.
* **`dependency_fallbacks`:**  The file name and class name strongly suggest this is about handling scenarios where a dependency isn't directly found and alternative methods (fallbacks) are used.
* **`dependency()`:**  This function is likely the primary way dependencies are declared in the build system. The code mentions it and its interaction with the fallback mechanism.
* **`subproject`:**  The code frequently refers to subprojects, indicating that using another project as a source for a dependency is a key fallback strategy.
* **`wrap_mode`, `force_fallback_for`:** These option names point to build system settings influencing dependency resolution.
* **`find_external_dependency`, `get_dep_identifier`:**  Functions related to finding dependencies outside of subprojects.
* **`NotFoundDependency`:**  A clear indicator of what happens when a dependency isn't found.
* **`version_compare_many`:** Implies version checking is part of the dependency management.
* **`_get_cached_dep`:**  Suggests caching of dependency information for efficiency.
* **`Interpreter`, `coredata`, `build`, `environment`:** These are likely components of the larger Meson build system.

**3. Deconstructing Functionality - Top-Down Approach:**

With the initial keywords in mind, I began to analyze the methods within `DependencyFallbacksHolder` to understand their individual roles and how they fit together:

* **`__init__`:**  Initializes the object, taking dependency names and configuration options. The checks for invalid characters and duplicate names highlight input validation.
* **`set_fallback` and `_subproject_impl`:**  Clearly handle the specification of a subproject as a fallback.
* **`_do_dependency_cache`, `_do_dependency`, `_do_existing_subproject`, `_do_subproject`:** These methods represent the different strategies for finding a dependency. The order suggests a priority: cache, existing subproject, external search, then building the subproject.
* **`_get_subproject`, `_get_subproject_dep`, `_get_subproject_variable`:** Focus on retrieving dependencies from subprojects.
* **`_log_found`:**  Handles logging of dependency resolution outcomes.
* **`_get_cached_dep`:**  Details how dependency caching works, including handling version mismatches and overrides.
* **`_verify_fallback_consistency`:**  Ensures consistency between cached dependencies and those provided by subprojects.
* **`_handle_featurenew_dependencies`:** Tracks when new dependency types are introduced, likely for deprecation warnings or feature management.
* **`_notfound_dependency`:** Creates an object representing a missing dependency.
* **`_check_version`:**  Performs version comparison.
* **`_get_candidates`:**  Assembles the list of possible dependency resolution strategies.
* **`lookup`:** The main entry point for finding a dependency, orchestrating the execution of the different candidate strategies. It also handles "required" dependencies and interactions with `wrap_mode`.

**4. Connecting to Reverse Engineering:**

My understanding of Frida as a dynamic instrumentation tool immediately suggested the relevance to reverse engineering. The need for specific libraries (dependencies) in Frida's core development directly links to the reverse engineering context:

* **Example:** Frida might depend on a library for interacting with process memory or handling debugging symbols. If that library isn't on the system, the fallback mechanism would kick in, potentially using a bundled version.

**5. Identifying Low-Level Aspects:**

The keywords and concepts hinted at low-level details:

* **Linux/Android Kernel/Framework:** The mention of "pcap" (packet capture) directly relates to network interaction, a common aspect of system-level tools and potentially relevant to Frida's instrumentation capabilities. The concept of "dependencies" itself is fundamental in compiled software on these platforms.
* **Binary Underlying:** The entire process of finding and linking libraries is inherently about working with binary code. The `dependency()` function eventually leads to linking against compiled libraries.

**6. Logical Reasoning (Inputs and Outputs):**

For logical reasoning, I focused on the `lookup` method as the entry point:

* **Input:**  A list of dependency names, keywords like `version`, `required`, and build system options like `wrap_mode`.
* **Process:** The `lookup` method iterates through the candidate strategies, attempting to find a suitable dependency.
* **Output:** Either a `Dependency` object (if found) or a `NotFoundDependency` object.

I then constructed specific examples to illustrate different paths within `lookup`, such as a successful external dependency lookup and a fallback to a subproject.

**7. Common User Errors:**

I considered common mistakes developers make when working with build systems and dependencies:

* **Incorrect Dependency Names:** Typographical errors.
* **Missing Dependencies:** Forgetting to install required libraries.
* **Version Mismatches:** Specifying incompatible versions.
* **Incorrect `wrap_mode`:**  Misconfiguring the build system's fallback behavior.

**8. Debugging Context (How to Reach the Code):**

To explain how a user ends up in this code, I outlined the typical development workflow with Frida:

1. **Frida Core Development:**  Developers working on Frida itself would directly encounter this code.
2. **Building Frida:**  The Meson build system uses this code during the dependency resolution phase.
3. **Debugging Build Issues:** If the build fails due to missing dependencies, developers would likely trace the error back to this file.

**9. Iterative Refinement and Organization:**

Throughout this process, I iteratively refined my understanding and organized the information into logical sections based on the prompt's requirements. I used headings and bullet points to structure the explanation clearly.

**Self-Correction/Refinement Example:**

Initially, I might have focused too much on the individual methods without clearly explaining the overarching purpose of the `DependencyFallbacksHolder`. I realized that starting with a high-level summary of its role in dependency resolution would provide better context before diving into the details of each method. Similarly, I ensured I explicitly linked the functionality to the specific context of Frida and reverse engineering.
This Python code snippet is from `dependencyfallbacks.py`, a file within the Frida project's build system (using Meson). Its primary function is to manage the process of finding and resolving dependencies required to build Frida's core components. It implements a fallback mechanism, meaning it tries different strategies to locate a dependency if the initial attempt fails.

Here's a breakdown of its functionalities:

**1. Managing Dependency Fallback Strategies:**

* **Central Logic for Finding Dependencies:** The `DependencyFallbacksHolder` class acts as a central orchestrator for finding dependencies. It encapsulates the logic for trying different sources and methods.
* **Prioritized Search Order:** It defines a prioritized order for searching for dependencies:
    * **Cache:** Checks if the dependency has been found and cached in a previous build.
    * **Existing Subproject:** If a fallback subproject is defined, it checks if that subproject provides the dependency.
    * **External System:** Searches for the dependency in the system's standard locations (e.g., using `pkg-config`).
    * **Building Subproject:** If a fallback subproject is defined, it configures and builds that subproject to obtain the dependency.
* **Handling Multiple Dependency Names:** It can handle scenarios where a dependency might have different names across platforms or build systems.
* **Version Requirements:** It supports specifying version requirements for dependencies and checks if found dependencies meet those requirements.
* **Module Dependencies:** It can handle dependencies that are provided as modules (e.g., Python modules).

**2. Interaction with the Meson Build System:**

* **Integration with Subprojects:** It deeply integrates with Meson's subproject feature, allowing the build to fall back to building a dependency from source if it's not found on the system.
* **Utilizing Meson's Dependency Handling:** It uses Meson's built-in functions for finding external dependencies and managing dependency overrides.
* **Configuration Options:** It respects Meson's configuration options like `wrap_mode` and `force_fallback_for`, which control the fallback behavior.

**3. Logging and Debugging:**

* **Detailed Logging:** It provides detailed logging of the dependency resolution process, indicating which strategies are being tried and whether they succeed or fail. This is crucial for debugging build issues related to dependencies.

**Relationship to Reverse Engineering:**

This code directly relates to reverse engineering because Frida is a dynamic instrumentation toolkit heavily used for reverse engineering. Frida itself depends on various libraries and components to function, and this code ensures that those dependencies are found and correctly linked during the build process.

**Example:**

Let's say Frida depends on the `glib-2.0` library. The `dependency_fallbacks.py` logic might work like this:

1. **Initial Attempt:** It first tries to find `glib-2.0` on the system using `pkg-config`.
2. **Fallback to Subproject:** If `glib-2.0` isn't found, and a fallback subproject (e.g., building `glib` from source) is configured, the code will then initiate the building of that `glib` subproject.
3. **Using the Subproject's Dependency:** Once the `glib` subproject is built, the code retrieves the necessary information (e.g., include directories, library paths) to link against the newly built `glib-2.0`.

**In the context of reverse engineering Frida:** If a reverse engineer is building Frida from source on a system where `glib-2.0` isn't installed, this fallback mechanism allows the build to proceed by compiling `glib` itself as part of the Frida build process.

**Involvement of Binary Underlying, Linux, Android Kernel & Framework:**

* **Binary Underlying:** The entire process of resolving dependencies is about finding and linking against binary libraries (`.so` on Linux, `.dylib` on macOS, etc.). The code interacts with the build system to ensure the correct linker flags are used to link against these binary libraries.
* **Linux and Android:** Frida runs on Linux and Android, and many of its dependencies are system libraries common on these platforms (e.g., `glib`, `pcap`). The code uses standard tools like `pkg-config` which are prevalent in Linux environments to locate these libraries. The concept of shared libraries and dynamic linking, fundamental to these operating systems, is at play here.
* **Kernel and Framework:** While this specific file doesn't directly interact with the kernel, the *dependencies* it's resolving might. For example, if Frida needs to interact with network interfaces at a low level, it might depend on libraries that ultimately make system calls to the kernel. On Android, dependencies might involve framework libraries. The `pcap` dependency mentioned in the code is a good example of a library that interacts closely with the operating system's networking stack.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario:** Building Frida on a Linux system where `libusb-1.0` is not installed. A fallback subproject named `libusb` is defined.

**Hypothetical Input (to the `lookup` function):**

* `names`: `['libusb-1.0']`
* `kwargs`: `{'required': True}`
* `force_fallback`: `False` (initially)

**Logical Reasoning within the code:**

1. **`_get_candidates` is called:** This creates a list of strategies to try.
2. **`_do_dependency_cache`:** Checks the cache - likely `libusb-1.0` is not cached as found.
3. **`_do_existing_subproject`:** Checks if the `libusb` subproject has already been configured. Assuming it hasn't.
4. **`_do_dependency`:** Attempts to find `libusb-1.0` using `pkg-config`. This will likely fail.
5. **`_do_subproject`:** Since a fallback subproject `libusb` is defined, this method is called.
6. **Subproject Configuration:** The `interpreter.do_subproject('libusb', ...)` call initiates the configuration and building of the `libusb` subproject.
7. **`_get_subproject_dep`:** After the subproject is built, this attempts to retrieve the dependency information (include paths, library paths) for `libusb-1.0` from the built subproject.

**Hypothetical Output (from the `lookup` function):**

A `Dependency` object representing the `libusb-1.0` library, with its paths pointing to the location where it was built within the `libusb` subproject.

**User or Programming Common Usage Errors:**

1. **Incorrect Dependency Names:**  Typos in dependency names (e.g., `libusbx-1.0` instead of `libusb-1.0`) will lead to the code not finding the dependency.
    * **Example:** In the `meson.build` file, if a dependency is declared as `dependency('libusbx-1.0')` while the actual library name is `libusb-1.0`, the initial search will fail. The fallback mechanism might or might not succeed depending on if a subproject is configured to provide something matching that incorrect name.

2. **Missing Fallback Subproject Definition:** If a dependency isn't found on the system and no fallback subproject is defined, the build will fail.
    * **Example:** If `dependency('some-rare-library')` is used, and `some-rare-library` is not installed and no `some-rare-library` subproject is configured in the `meson.build` file or `wrap` files, the `lookup` function will eventually throw a `DependencyException`.

3. **Incorrect Fallback Subproject Configuration:**  The fallback subproject might fail to build due to its own dependency issues or configuration errors.
    * **Example:** The `libusb` subproject might require CMake to build, and if CMake is not installed, the `interpreter.do_subproject('libusb', ...)` call will fail, and the dependency will not be resolved.

4. **Version Mismatches:**  Specifying a version constraint that the fallback subproject doesn't satisfy.
    * **Example:** `dependency('zlib', version: '>1.2.11')`. If the fallback `zlib` subproject builds an older version, the `_check_version` method will return `False`, and the dependency will be considered not found.

**How User Operation Reaches Here (Debugging Clues):**

1. **User Starts a Build:** A developer initiates the build process for Frida, typically by running `meson build` followed by `ninja -C build`.
2. **Meson Parses Build Files:** Meson reads the `meson.build` files, where dependencies are declared using the `dependency()` function.
3. **Dependency Resolution:** When Meson encounters a `dependency()` call, it internally uses the logic in `dependencyfallbacks.py` to find the dependency.
4. **Dependency Not Found:** If a dependency is not found on the system using the initial search methods, the code in `dependencyfallbacks.py` starts exploring fallback options.
5. **Logging Output:** Meson will output log messages indicating the attempts to find the dependency and whether fallbacks are being used. Messages like "Looking for a fallback subproject for the dependency..." are generated from this file.
6. **Subproject Invocation:** If a fallback subproject is used, Meson will invoke the build system of that subproject (e.g., CMake, Meson for the subproject itself).
7. **Build Failure:** If all attempts to find or build the dependency fail, Meson will throw an error message, often indicating which dependency was not found.

**Debugging Steps:**

* **Examine Meson's Output:** The first step is to carefully read the error messages and logging output from Meson. This will often point to the specific dependency that's causing the problem.
* **Check `meson.build`:** Verify that the dependency name in the `meson.build` file is correct.
* **Check for Fallback Subprojects:** Look for definitions of fallback subprojects in the `meson.build` or related files.
* **Verify Subproject Build Requirements:** If a fallback subproject is being used, ensure that the necessary build tools (e.g., CMake, compilers) are installed for that subproject.
* **Inspect `wrap` Files:** Frida uses `wrap` files to provide instructions on how to obtain certain dependencies, often by pointing to subprojects. Inspect these files if fallbacks are involved.
* **Run Meson with Increased Verbosity:** Using options like `-v` or `-vv` when running Meson can provide more detailed logging output, potentially revealing more information about the dependency resolution process.

By understanding the logic within `dependencyfallbacks.py` and the steps involved in the build process, developers can effectively diagnose and resolve dependency-related build issues in Frida.

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/dependencyfallbacks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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