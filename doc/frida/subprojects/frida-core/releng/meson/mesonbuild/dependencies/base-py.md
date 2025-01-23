Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Initial Understanding of the Request:**

The request asks for a functional analysis of a specific Python file within the Frida project, focusing on its relevance to reverse engineering, binary/kernel/framework aspects, logical reasoning, potential errors, and user interaction tracing.

**2. High-Level Overview of the File:**

The file `base.py` within the `frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/` directory strongly suggests it's part of the Meson build system's dependency management for the Frida core. The imports confirm this, including modules like `mesonlib`, `compilers`, and `environment`. The presence of classes like `Dependency`, `ExternalDependency`, `InternalDependency` reinforces this.

**3. Core Functionality - Dependency Management:**

The primary function is clearly managing external and internal dependencies for building Frida. This involves:

* **Detection:**  Finding required libraries, headers, and other components. The `DependencyMethods` enum outlines the various mechanisms (pkg-config, CMake, system paths, etc.).
* **Representation:**  The `Dependency` class acts as a container for information about a dependency (name, version, compile flags, link flags, sources).
* **Abstraction:**  It provides a unified interface for accessing dependency information, regardless of the underlying detection method.
* **Conditional Inclusion:** Mechanisms like `include_type` control how include paths are passed to the compiler.
* **Version Handling:**  The code includes logic for checking dependency versions against requirements.

**4. Relationship to Reverse Engineering (Instruction #2):**

This is where we need to connect the dots to Frida's purpose. Frida is a dynamic instrumentation tool used extensively in reverse engineering. Therefore, the dependencies this file manages are likely crucial for Frida's functionality.

* **Examples:**  Think about what Frida needs:  Native libraries for interacting with the operating system, potentially libraries for code injection, and perhaps libraries for handling different architectures or debugging protocols. Even though the *code* here doesn't *perform* reverse engineering, it's *essential* for *building* the tool that does. We can hypothesize about potential dependencies like `glib` (common in Linux), platform-specific libraries, and potentially even custom libraries within the Frida ecosystem.

**5. Binary/Kernel/Framework Knowledge (Instruction #3):**

Building software like Frida that interacts deeply with systems requires knowledge of low-level details.

* **Examples:**
    * **Binary Level:** Compile and link flags (`-I`, `-L`, `-l`) directly manipulate the binary creation process. The distinction between static and shared libraries is fundamental.
    * **Linux/Android Kernel:**  Dependencies might involve kernel headers or libraries that interface with kernel features. Frida itself interacts with the kernel for instrumentation.
    * **Android Framework:**  On Android, Frida needs to interact with the Android Runtime (ART) and potentially framework services. Dependencies could relate to this interaction.

**6. Logical Reasoning (Instruction #4):**

Look for conditional logic and how data flows.

* **Example: `get_compile_args()`:**  The logic around `include_type` (preserve, system, non-system) demonstrates conditional modification of compile arguments. If the input is `include_type='system'`, the output will use `-isystem`. We can create hypothetical input and output to illustrate this.
* **Example: `_check_version()`:** This function takes a dependency and its version requirements as input. The output is whether the dependency is considered found or not, potentially raising an exception if required and not found. Again, we can construct test cases.

**7. User/Programming Errors (Instruction #5):**

Consider how a user building Frida might misuse the dependency system or make common mistakes.

* **Examples:**
    * Providing an invalid `method` for dependency detection.
    * Incorrectly specifying version requirements.
    * Assuming a dependency is available when it's not installed on their system.
    * Misunderstanding the `static` keyword.

**8. User Interaction and Debugging (Instruction #6):**

Think about how a developer would end up looking at this file.

* **Scenario:**  A build failure related to a missing dependency would likely lead a developer to investigate the Meson build files, potentially tracing down to this `base.py` file to understand how dependencies are being handled. Debugging messages from Meson or error messages related to finding packages would be clues.

**9. Structuring the Explanation:**

Organize the findings into logical sections as requested by the prompt. Use clear headings and bullet points. Provide concrete code examples where applicable.

**10. Iterative Refinement:**

After the initial draft, review and refine the explanation. Ensure clarity, accuracy, and completeness. Double-check the examples and ensure they accurately reflect the code's behavior. For instance, I initially focused heavily on *Frida's* direct dependencies. While relevant, the core focus should be on what this *file* does. It *manages* dependencies, it doesn't *define* Frida's exact dependency list. This requires a subtle shift in emphasis. Also, ensuring the examples directly link to the provided code snippets is crucial.

By following these steps, we can systematically analyze the code and generate a comprehensive and informative explanation that addresses all aspects of the request. The key is to understand the code's purpose within the larger project, connect it to the specific domain (reverse engineering), and illustrate its functionality with concrete examples.
This Python code file, `base.py`, is a core component of Meson's dependency management system, specifically for handling external dependencies within the Frida project's build process. Here's a breakdown of its functionality:

**Core Functionality:**

1. **Defines Base Classes for Dependencies:**
   - It introduces the fundamental `Dependency` class, which serves as a blueprint for representing any kind of dependency (internal or external). This class holds common attributes like name, version, compile arguments, link arguments, and whether the dependency was found.
   - It defines `ExternalDependency` as a subclass of `Dependency`, specifically designed for external libraries and packages. This class includes attributes related to the build environment and methods for checking versions.
   - `InternalDependency` represents dependencies within the same project or build system.
   - `NotFoundDependency` is a specific type of dependency indicating that a required dependency could not be located.

2. **Specifies Dependency Detection Methods:**
   - The `DependencyMethods` Enum lists various strategies Meson can use to find external dependencies. These include `pkg-config`, `cmake`, system libraries, framework searches (macOS), and configuration tools like `*-config`. The `AUTO` option allows Meson to choose the most appropriate method.

3. **Manages Compile and Link Arguments:**
   - The `Dependency` class stores and provides methods (`get_compile_args`, `get_link_args`, `get_all_compile_args`, `get_all_link_args`) to retrieve the compiler and linker flags necessary for using the dependency. It also handles different `include_type` settings ('preserve', 'system', 'non-system') to adjust include paths.

4. **Handles Dependency Versions:**
   - The `ExternalDependency` class includes logic for checking if the found version of an external dependency meets the specified requirements using the `version_compare_many` function.

5. **Supports Partial Dependencies:**
   - The `get_partial_dependency` method allows creating a new dependency object containing only a subset of the original dependency's information (e.g., only link arguments, only include directories). This is useful for fine-grained control over how dependencies are used in different parts of the build.

6. **Provides Abstraction for Dependency Information:**
   - Regardless of how a dependency is found (pkg-config, CMake, etc.), the `Dependency` class offers a consistent interface to access its properties.

7. **Handles Internal Dependencies:**
   - The `InternalDependency` class stores information about dependencies managed within the project itself, such as include directories, libraries built within the project, and custom variables.

8. **Manages "Native" Dependencies:**
   - The `HasNativeKwarg` mixin and the `native` keyword argument allow specifying whether a dependency is for the build machine or the host machine (where the built software will run).

9. **Utilities for Dependency Lists:**
   - Functions like `get_leaf_external_dependencies` help process lists of dependencies.
   - `sort_libpaths` and `strip_system_libdirs/strip_system_includedirs` provide utilities for manipulating link and include paths.

10. **Error Handling:**
    - The `DependencyException` is raised for errors related to finding or using dependencies.
    - The `MissingCompiler` class represents a scenario where no suitable compiler could be found.

**Relationship to Reverse Engineering:**

This file is indirectly related to reverse engineering as it's part of the build system for Frida, a powerful tool used extensively for dynamic analysis and reverse engineering.

* **Example:** Imagine Frida needs to link against a specific library for interacting with processes on Linux (e.g., `libcap` for capabilities). When building Frida, Meson, guided by this `base.py` and other related files, would use methods like `pkg-config` to find `libcap` on the system. The `Dependency` object for `libcap` would then store the necessary compile flags (like `-I/usr/include/libcap`) and link flags (like `-lcap`), which are crucial for the linker to successfully incorporate `libcap` into the Frida executable. Without this dependency management, the Frida build would fail, and the reverse engineering tool wouldn't be available.

**Involvement of Binary 底层, Linux, Android Kernel & Framework Knowledge:**

This file touches upon these areas because the dependencies it manages often directly interact with low-level system components:

* **Binary 底层 (Binary Low-Level):**
    - **Compile and Link Arguments:** The core purpose of this file is to manage compiler and linker flags. These flags directly dictate how the final binary is constructed, including linking against specific libraries and specifying include paths for headers necessary to interact with the underlying system.
    - **Static vs. Shared Libraries:** The code handles the preference for static or shared libraries, a fundamental concept in binary linking.

* **Linux:**
    - **System Libraries:** The `SYSTEM` dependency method directly refers to libraries provided by the Linux operating system.
    - **`pkg-config`:** This is a standard tool on Linux for retrieving information about installed libraries, and `base.py` integrates with it.
    - **Kernel Interaction (Indirect):** While this file doesn't directly interact with the kernel, the libraries Frida depends on likely do. For example, libraries for process injection or memory manipulation.

* **Android Kernel & Framework:**
    - **System Libraries (Android):** Similar to Linux, Android provides system libraries that Frida might depend on.
    - **Framework Interaction (Indirect):** If Frida interacts with specific Android framework components (like the Android Runtime - ART), it might depend on libraries or headers related to those components. The dependency management in this file would be responsible for finding them.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider a hypothetical scenario where the build system needs to find the `zlib` library using `pkg-config`.

**Hypothetical Input:**

- The `meson.build` file contains a dependency declaration: `dependency('zlib')`.
- Meson, through its dependency resolution process, decides to use the `PKGCONFIG` method.
- `pkg-config zlib --cflags` returns `-I/usr/include`
- `pkg-config zlib --libs` returns `-lz`

**Hypothetical Output:**

- A `Dependency` object for `zlib` would be created.
- `dependency_object.is_found` would be `True`.
- `dependency_object.compile_args` would be `['-I/usr/include']`.
- `dependency_object.link_args` would be `['-lz']`.
- `dependency_object.version` would be the version reported by `pkg-config zlib --modversion` (if successful).

**User or Programming Common Usage Errors:**

1. **Incorrect `method` specification:**
   ```python
   # Error: 'my-own-method' is not a valid DependencyMethods value
   dependency('mylib', method='my-own-method')
   ```
   This would raise a `DependencyException` because `'my-own-method'` is not a recognized dependency detection method.

2. **Missing dependency:**
   If a required dependency is not installed on the system:
   ```python
   # If the 'foobar' library is not installed and pkg-config cannot find it
   dependency('foobar')
   ```
   This would likely result in a `NotFoundDependency` object, and the build would fail later during the linking stage, with error messages indicating that the `foobar` library could not be found.

3. **Incorrect version requirements:**
   ```python
   # If the installed zlib version is older than 1.3
   dependency('zlib', version='>=1.3')
   ```
   The `_check_version` method in `ExternalDependency` would detect this mismatch, set `is_found` to `False`, and potentially raise a `DependencyException` if the dependency is marked as `required=True`.

**User Operation Steps to Reach This File (Debugging Clue):**

1. **User initiates a Frida build:** The user would typically run a command like `meson setup build` or `ninja` in the Frida project directory.
2. **Meson processes `meson.build` files:** Meson reads the `meson.build` files to understand the project's structure, dependencies, and build rules.
3. **Dependency resolution:** When Meson encounters a `dependency()` call (e.g., `dependency('glib-2.0')`), it starts the process of finding that dependency.
4. **`base.py` comes into play:** The logic within `base.py` (and other files in the same directory) is used to implement the different dependency detection methods (pkg-config, CMake, etc.).
5. **Debugging scenario:** If the build fails due to a missing dependency, a developer might:
   - **Examine the Meson log:** The log would likely indicate which dependency failed to be found and which methods were tried.
   - **Trace the dependency resolution:** A developer familiar with Meson's internals might look at the Meson source code, including `base.py`, to understand how the dependency search is being performed. They might set breakpoints or add print statements within this file to see which detection methods are being attempted and why they are failing.
   - **Verify system setup:** The developer might check if the necessary development packages (e.g., `libglib2.0-dev` on Debian/Ubuntu) are installed on their system.
   - **Investigate `pkg-config` or CMake:** If the dependency uses these methods, the developer might run the `pkg-config` or CMake commands manually to diagnose the issue.

In essence, `base.py` is a foundational file in Frida's build system, responsible for the crucial task of locating and configuring the necessary external components that enable Frida's functionality. Understanding this file is key to troubleshooting dependency-related build issues.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/base.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2018 The Meson development team
# Copyright © 2024 Intel Corporation

# This file contains the detection logic for external dependencies.
# Custom logic for several other packages are in separate files.

from __future__ import annotations
import copy
import os
import collections
import itertools
import typing as T
from enum import Enum

from .. import mlog, mesonlib
from ..compilers import clib_langs
from ..mesonlib import LibType, MachineChoice, MesonException, HoldableObject, OptionKey
from ..mesonlib import version_compare_many
#from ..interpreterbase import FeatureDeprecated, FeatureNew

if T.TYPE_CHECKING:
    from ..compilers.compilers import Compiler
    from ..environment import Environment
    from ..interpreterbase import FeatureCheckBase
    from ..build import (
        CustomTarget, IncludeDirs, CustomTargetIndex, LibTypes,
        StaticLibrary, StructuredSources, ExtractedObjects, GeneratedTypes
    )
    from ..interpreter.type_checking import PkgConfigDefineType

    _MissingCompilerBase = Compiler
else:
    _MissingCompilerBase = object


class DependencyException(MesonException):
    '''Exceptions raised while trying to find dependencies'''


class MissingCompiler(_MissingCompilerBase):
    """Represent a None Compiler - when no tool chain is found.
    replacing AttributeError with DependencyException"""

    # These are needed in type checking mode to avoid errors, but we don't want
    # the extra overhead at runtime
    if T.TYPE_CHECKING:
        def __init__(self) -> None:
            pass

        def get_optimization_args(self, optimization_level: str) -> T.List[str]:
            return []

        def get_output_args(self, outputname: str) -> T.List[str]:
            return []

        def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
            return None

    def __getattr__(self, item: str) -> T.Any:
        if item.startswith('__'):
            raise AttributeError()
        raise DependencyException('no toolchain found')

    def __bool__(self) -> bool:
        return False


class DependencyMethods(Enum):
    # Auto means to use whatever dependency checking mechanisms in whatever order meson thinks is best.
    AUTO = 'auto'
    PKGCONFIG = 'pkg-config'
    CMAKE = 'cmake'
    # The dependency is provided by the standard library and does not need to be linked
    BUILTIN = 'builtin'
    # Just specify the standard link arguments, assuming the operating system provides the library.
    SYSTEM = 'system'
    # This is only supported on OSX - search the frameworks directory by name.
    EXTRAFRAMEWORK = 'extraframework'
    # Detect using the sysconfig module.
    SYSCONFIG = 'sysconfig'
    # Specify using a "program"-config style tool
    CONFIG_TOOL = 'config-tool'
    # For backwards compatibility
    SDLCONFIG = 'sdlconfig'
    CUPSCONFIG = 'cups-config'
    PCAPCONFIG = 'pcap-config'
    LIBWMFCONFIG = 'libwmf-config'
    QMAKE = 'qmake'
    # Misc
    DUB = 'dub'


DependencyTypeName = T.NewType('DependencyTypeName', str)


class Dependency(HoldableObject):

    @classmethod
    def _process_include_type_kw(cls, kwargs: T.Dict[str, T.Any]) -> str:
        if 'include_type' not in kwargs:
            return 'preserve'
        if not isinstance(kwargs['include_type'], str):
            raise DependencyException('The include_type kwarg must be a string type')
        if kwargs['include_type'] not in ['preserve', 'system', 'non-system']:
            raise DependencyException("include_type may only be one of ['preserve', 'system', 'non-system']")
        return kwargs['include_type']

    def __init__(self, type_name: DependencyTypeName, kwargs: T.Dict[str, T.Any]) -> None:
        # This allows two Dependencies to be compared even after being copied.
        # The purpose is to allow the name to be changed, but still have a proper comparison
        self.__id = id(self)
        self.name = f'dep{id(self)}'
        self.version:  T.Optional[str] = None
        self.language: T.Optional[str] = None # None means C-like
        self.is_found = False
        self.type_name = type_name
        self.compile_args: T.List[str] = []
        self.link_args:    T.List[str] = []
        # Raw -L and -l arguments without manual library searching
        # If None, self.link_args will be used
        self.raw_link_args: T.Optional[T.List[str]] = None
        self.sources: T.List[T.Union[mesonlib.File, GeneratedTypes, 'StructuredSources']] = []
        self.extra_files: T.List[mesonlib.File] = []
        self.include_type = self._process_include_type_kw(kwargs)
        self.ext_deps: T.List[Dependency] = []
        self.d_features: T.DefaultDict[str, T.List[T.Any]] = collections.defaultdict(list)
        self.featurechecks: T.List['FeatureCheckBase'] = []
        self.feature_since: T.Optional[T.Tuple[str, str]] = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return self.__id == other.__id

    def __hash__(self) -> int:
        return self.__id

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.name}: {self.is_found}>'

    def is_built(self) -> bool:
        return False

    def summary_value(self) -> T.Union[str, mlog.AnsiDecorator, mlog.AnsiText]:
        if not self.found():
            return mlog.red('NO')
        if not self.version:
            return mlog.green('YES')
        return mlog.AnsiText(mlog.green('YES'), ' ', mlog.cyan(self.version))

    def get_compile_args(self) -> T.List[str]:
        if self.include_type == 'system':
            converted = []
            for i in self.compile_args:
                if i.startswith('-I') or i.startswith('/I'):
                    converted += ['-isystem' + i[2:]]
                else:
                    converted += [i]
            return converted
        if self.include_type == 'non-system':
            converted = []
            for i in self.compile_args:
                if i.startswith('-isystem'):
                    converted += ['-I' + i[8:]]
                else:
                    converted += [i]
            return converted
        return self.compile_args

    def get_all_compile_args(self) -> T.List[str]:
        """Get the compile arguments from this dependency and it's sub dependencies."""
        return list(itertools.chain(self.get_compile_args(),
                                    *(d.get_all_compile_args() for d in self.ext_deps)))

    def get_link_args(self, language: T.Optional[str] = None, raw: bool = False) -> T.List[str]:
        if raw and self.raw_link_args is not None:
            return self.raw_link_args
        return self.link_args

    def get_all_link_args(self) -> T.List[str]:
        """Get the link arguments from this dependency and it's sub dependencies."""
        return list(itertools.chain(self.get_link_args(),
                                    *(d.get_all_link_args() for d in self.ext_deps)))

    def found(self) -> bool:
        return self.is_found

    def get_sources(self) -> T.List[T.Union[mesonlib.File, GeneratedTypes, 'StructuredSources']]:
        """Source files that need to be added to the target.
        As an example, gtest-all.cc when using GTest."""
        return self.sources

    def get_extra_files(self) -> T.List[mesonlib.File]:
        """Mostly for introspection and IDEs"""
        return self.extra_files

    def get_name(self) -> str:
        return self.name

    def get_version(self) -> str:
        if self.version:
            return self.version
        else:
            return 'unknown'

    def get_include_dirs(self) -> T.List['IncludeDirs']:
        return []

    def get_include_type(self) -> str:
        return self.include_type

    def get_exe_args(self, compiler: 'Compiler') -> T.List[str]:
        return []

    def get_partial_dependency(self, *, compile_args: bool = False,
                               link_args: bool = False, links: bool = False,
                               includes: bool = False, sources: bool = False) -> 'Dependency':
        """Create a new dependency that contains part of the parent dependency.

        The following options can be inherited:
            links -- all link_with arguments
            includes -- all include_directory and -I/-isystem calls
            sources -- any source, header, or generated sources
            compile_args -- any compile args
            link_args -- any link args

        Additionally the new dependency will have the version parameter of it's
        parent (if any) and the requested values of any dependencies will be
        added as well.
        """
        raise RuntimeError('Unreachable code in partial_dependency called')

    def _add_sub_dependency(self, deplist: T.Iterable[T.Callable[[], 'Dependency']]) -> bool:
        """Add an internal dependency from a list of possible dependencies.

        This method is intended to make it easier to add additional
        dependencies to another dependency internally.

        Returns true if the dependency was successfully added, false
        otherwise.
        """
        for d in deplist:
            dep = d()
            if dep.is_found:
                self.ext_deps.append(dep)
                return True
        return False

    def get_variable(self, *, cmake: T.Optional[str] = None, pkgconfig: T.Optional[str] = None,
                     configtool: T.Optional[str] = None, internal: T.Optional[str] = None,
                     default_value: T.Optional[str] = None,
                     pkgconfig_define: PkgConfigDefineType = None) -> str:
        if default_value is not None:
            return default_value
        raise DependencyException(f'No default provided for dependency {self!r}, which is not pkg-config, cmake, or config-tool based.')

    def generate_system_dependency(self, include_type: str) -> 'Dependency':
        new_dep = copy.deepcopy(self)
        new_dep.include_type = self._process_include_type_kw({'include_type': include_type})
        return new_dep

class InternalDependency(Dependency):
    def __init__(self, version: str, incdirs: T.List['IncludeDirs'], compile_args: T.List[str],
                 link_args: T.List[str],
                 libraries: T.List[LibTypes],
                 whole_libraries: T.List[T.Union[StaticLibrary, CustomTarget, CustomTargetIndex]],
                 sources: T.Sequence[T.Union[mesonlib.File, GeneratedTypes, StructuredSources]],
                 extra_files: T.Sequence[mesonlib.File],
                 ext_deps: T.List[Dependency], variables: T.Dict[str, str],
                 d_module_versions: T.List[T.Union[str, int]], d_import_dirs: T.List['IncludeDirs'],
                 objects: T.List['ExtractedObjects']):
        super().__init__(DependencyTypeName('internal'), {})
        self.version = version
        self.is_found = True
        self.include_directories = incdirs
        self.compile_args = compile_args
        self.link_args = link_args
        self.libraries = libraries
        self.whole_libraries = whole_libraries
        self.sources = list(sources)
        self.extra_files = list(extra_files)
        self.ext_deps = ext_deps
        self.variables = variables
        self.objects = objects
        if d_module_versions:
            self.d_features['versions'] = d_module_versions
        if d_import_dirs:
            self.d_features['import_dirs'] = d_import_dirs

    def __deepcopy__(self, memo: T.Dict[int, 'InternalDependency']) -> 'InternalDependency':
        result = self.__class__.__new__(self.__class__)
        assert isinstance(result, InternalDependency)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            if k in {'libraries', 'whole_libraries'}:
                setattr(result, k, copy.copy(v))
            else:
                setattr(result, k, copy.deepcopy(v, memo))
        return result

    def summary_value(self) -> mlog.AnsiDecorator:
        # Omit the version.  Most of the time it will be just the project
        # version, which is uninteresting in the summary.
        return mlog.green('YES')

    def is_built(self) -> bool:
        if self.sources or self.libraries or self.whole_libraries:
            return True
        return any(d.is_built() for d in self.ext_deps)

    def get_partial_dependency(self, *, compile_args: bool = False,
                               link_args: bool = False, links: bool = False,
                               includes: bool = False, sources: bool = False,
                               extra_files: bool = False) -> InternalDependency:
        final_compile_args = self.compile_args.copy() if compile_args else []
        final_link_args = self.link_args.copy() if link_args else []
        final_libraries = self.libraries.copy() if links else []
        final_whole_libraries = self.whole_libraries.copy() if links else []
        final_sources = self.sources.copy() if sources else []
        final_extra_files = self.extra_files.copy() if extra_files else []
        final_includes = self.include_directories.copy() if includes else []
        final_deps = [d.get_partial_dependency(
            compile_args=compile_args, link_args=link_args, links=links,
            includes=includes, sources=sources) for d in self.ext_deps]
        return InternalDependency(
            self.version, final_includes, final_compile_args,
            final_link_args, final_libraries, final_whole_libraries,
            final_sources, final_extra_files, final_deps, self.variables, [], [], [])

    def get_include_dirs(self) -> T.List['IncludeDirs']:
        return self.include_directories

    def get_variable(self, *, cmake: T.Optional[str] = None, pkgconfig: T.Optional[str] = None,
                     configtool: T.Optional[str] = None, internal: T.Optional[str] = None,
                     default_value: T.Optional[str] = None,
                     pkgconfig_define: PkgConfigDefineType = None) -> str:
        val = self.variables.get(internal, default_value)
        if val is not None:
            return val
        raise DependencyException(f'Could not get an internal variable and no default provided for {self!r}')

    def generate_link_whole_dependency(self) -> Dependency:
        from ..build import SharedLibrary, CustomTarget, CustomTargetIndex
        new_dep = copy.deepcopy(self)
        for x in new_dep.libraries:
            if isinstance(x, SharedLibrary):
                raise MesonException('Cannot convert a dependency to link_whole when it contains a '
                                     'SharedLibrary')
            elif isinstance(x, (CustomTarget, CustomTargetIndex)) and x.links_dynamically():
                raise MesonException('Cannot convert a dependency to link_whole when it contains a '
                                     'CustomTarget or CustomTargetIndex which is a shared library')

        # Mypy doesn't understand that the above is a TypeGuard
        new_dep.whole_libraries += T.cast('T.List[T.Union[StaticLibrary, CustomTarget, CustomTargetIndex]]',
                                          new_dep.libraries)
        new_dep.libraries = []
        return new_dep

class HasNativeKwarg:
    def __init__(self, kwargs: T.Dict[str, T.Any]):
        self.for_machine = self.get_for_machine_from_kwargs(kwargs)

    def get_for_machine_from_kwargs(self, kwargs: T.Dict[str, T.Any]) -> MachineChoice:
        return MachineChoice.BUILD if kwargs.get('native', False) else MachineChoice.HOST

class ExternalDependency(Dependency, HasNativeKwarg):
    def __init__(self, type_name: DependencyTypeName, environment: 'Environment', kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None):
        Dependency.__init__(self, type_name, kwargs)
        self.env = environment
        self.name = type_name # default
        self.is_found = False
        self.language = language
        version_reqs = kwargs.get('version', None)
        if isinstance(version_reqs, str):
            version_reqs = [version_reqs]
        self.version_reqs: T.Optional[T.List[str]] = version_reqs
        self.required = kwargs.get('required', True)
        self.silent = kwargs.get('silent', False)
        self.static = kwargs.get('static', self.env.coredata.get_option(OptionKey('prefer_static')))
        self.libtype = LibType.STATIC if self.static else LibType.PREFER_SHARED
        if not isinstance(self.static, bool):
            raise DependencyException('Static keyword must be boolean')
        # Is this dependency to be run on the build platform?
        HasNativeKwarg.__init__(self, kwargs)
        self.clib_compiler = detect_compiler(self.name, environment, self.for_machine, self.language)

    def get_compiler(self) -> T.Union['MissingCompiler', 'Compiler']:
        return self.clib_compiler

    def get_partial_dependency(self, *, compile_args: bool = False,
                               link_args: bool = False, links: bool = False,
                               includes: bool = False, sources: bool = False) -> Dependency:
        new = copy.copy(self)
        if not compile_args:
            new.compile_args = []
        if not link_args:
            new.link_args = []
        if not sources:
            new.sources = []
        if not includes:
            pass # TODO maybe filter compile_args?
        if not sources:
            new.sources = []

        return new

    def log_details(self) -> str:
        return ''

    def log_info(self) -> str:
        return ''

    @staticmethod
    def log_tried() -> str:
        return ''

    # Check if dependency version meets the requirements
    def _check_version(self) -> None:
        if not self.is_found:
            return

        if self.version_reqs:
            for_msg = ['for', mlog.bold(self.for_machine.get_lower_case_name()), 'machine']

            # an unknown version can never satisfy any requirement
            if not self.version:
                self.is_found = False
                found_msg: mlog.TV_LoggableList = []
                found_msg.extend(['Dependency', mlog.bold(self.name)])
                found_msg.extend(for_msg)
                found_msg.append('found:')
                found_msg.extend([mlog.red('NO'), 'unknown version, but need:', self.version_reqs])
                mlog.log(*found_msg)

                if self.required:
                    m = f'Unknown version, but need {self.version_reqs!r}.'
                    raise DependencyException(m)

            else:
                (self.is_found, not_found, found) = \
                    version_compare_many(self.version, self.version_reqs)
                if not self.is_found:
                    found_msg = ['Dependency', mlog.bold(self.name)]
                    found_msg.extend(for_msg)
                    found_msg.append('found:')
                    found_msg += [mlog.red('NO'),
                                  'found', mlog.normal_cyan(self.version), 'but need:',
                                  mlog.bold(', '.join([f"'{e}'" for e in not_found]))]
                    if found:
                        found_msg += ['; matched:',
                                      ', '.join([f"'{e}'" for e in found])]
                    mlog.log(*found_msg)

                    if self.required:
                        m = 'Invalid version, need {!r} {!r} found {!r}.'
                        raise DependencyException(m.format(self.name, not_found, self.version))
                    return


class NotFoundDependency(Dependency):
    def __init__(self, name: str, environment: 'Environment') -> None:
        super().__init__(DependencyTypeName('not-found'), {})
        self.env = environment
        self.name = name
        self.is_found = False

    def get_partial_dependency(self, *, compile_args: bool = False,
                               link_args: bool = False, links: bool = False,
                               includes: bool = False, sources: bool = False) -> 'NotFoundDependency':
        return copy.copy(self)


class ExternalLibrary(ExternalDependency):
    def __init__(self, name: str, link_args: T.List[str], environment: 'Environment',
                 language: str, silent: bool = False) -> None:
        super().__init__(DependencyTypeName('library'), environment, {}, language=language)
        self.name = name
        self.language = language
        self.is_found = False
        if link_args:
            self.is_found = True
            self.link_args = link_args
        if not silent:
            if self.is_found:
                mlog.log('Library', mlog.bold(name), 'found:', mlog.green('YES'))
            else:
                mlog.log('Library', mlog.bold(name), 'found:', mlog.red('NO'))

    def get_link_args(self, language: T.Optional[str] = None, raw: bool = False) -> T.List[str]:
        '''
        External libraries detected using a compiler must only be used with
        compatible code. For instance, Vala libraries (.vapi files) cannot be
        used with C code, and not all Rust library types can be linked with
        C-like code. Note that C++ libraries *can* be linked with C code with
        a C++ linker (and vice-versa).
        '''
        # Using a vala library in a non-vala target, or a non-vala library in a vala target
        # XXX: This should be extended to other non-C linkers such as Rust
        if (self.language == 'vala' and language != 'vala') or \
           (language == 'vala' and self.language != 'vala'):
            return []
        return super().get_link_args(language=language, raw=raw)

    def get_partial_dependency(self, *, compile_args: bool = False,
                               link_args: bool = False, links: bool = False,
                               includes: bool = False, sources: bool = False) -> 'ExternalLibrary':
        # External library only has link_args, so ignore the rest of the
        # interface.
        new = copy.copy(self)
        if not link_args:
            new.link_args = []
        return new


def get_leaf_external_dependencies(deps: T.List[Dependency]) -> T.List[Dependency]:
    if not deps:
        # Ensure that we always return a new instance
        return deps.copy()
    final_deps = []
    while deps:
        next_deps = []
        for d in mesonlib.listify(deps):
            if not isinstance(d, Dependency) or d.is_built():
                raise DependencyException('Dependencies must be external dependencies')
            final_deps.append(d)
            next_deps.extend(d.ext_deps)
        deps = next_deps
    return final_deps


def sort_libpaths(libpaths: T.List[str], refpaths: T.List[str]) -> T.List[str]:
    """Sort <libpaths> according to <refpaths>

    It is intended to be used to sort -L flags returned by pkg-config.
    Pkg-config returns flags in random order which cannot be relied on.
    """
    if len(refpaths) == 0:
        return list(libpaths)

    def key_func(libpath: str) -> T.Tuple[int, int]:
        common_lengths: T.List[int] = []
        for refpath in refpaths:
            try:
                common_path: str = os.path.commonpath([libpath, refpath])
            except ValueError:
                common_path = ''
            common_lengths.append(len(common_path))
        max_length = max(common_lengths)
        max_index = common_lengths.index(max_length)
        reversed_max_length = len(refpaths[max_index]) - max_length
        return (max_index, reversed_max_length)
    return sorted(libpaths, key=key_func)

def strip_system_libdirs(environment: 'Environment', for_machine: MachineChoice, link_args: T.List[str]) -> T.List[str]:
    """Remove -L<system path> arguments.

    leaving these in will break builds where a user has a version of a library
    in the system path, and a different version not in the system path if they
    want to link against the non-system path version.
    """
    exclude = {f'-L{p}' for p in environment.get_compiler_system_lib_dirs(for_machine)}
    return [l for l in link_args if l not in exclude]

def strip_system_includedirs(environment: 'Environment', for_machine: MachineChoice, include_args: T.List[str]) -> T.List[str]:
    """Remove -I<system path> arguments.

    leaving these in will break builds where user want dependencies with system
    include-type used in rust.bindgen targets as if will cause system headers
    to not be found.
    """

    exclude = {f'-I{p}' for p in environment.get_compiler_system_include_dirs(for_machine)}
    return [i for i in include_args if i not in exclude]

def process_method_kw(possible: T.Iterable[DependencyMethods], kwargs: T.Dict[str, T.Any]) -> T.List[DependencyMethods]:
    method: T.Union[DependencyMethods, str] = kwargs.get('method', 'auto')
    if isinstance(method, DependencyMethods):
        return [method]
    # TODO: try/except?
    if method not in [e.value for e in DependencyMethods]:
        raise DependencyException(f'method {method!r} is invalid')
    method = DependencyMethods(method)

    # Raise FeatureNew where appropriate
    if method is DependencyMethods.CONFIG_TOOL:
        # FIXME: needs to get a handle on the subproject
        # FeatureNew.single_use('Configuration method "config-tool"', '0.44.0')
        pass
    # This sets per-tool config methods which are deprecated to to the new
    # generic CONFIG_TOOL value.
    if method in [DependencyMethods.SDLCONFIG, DependencyMethods.CUPSCONFIG,
                  DependencyMethods.PCAPCONFIG, DependencyMethods.LIBWMFCONFIG]:
        # FIXME: needs to get a handle on the subproject
        #FeatureDeprecated.single_use(f'Configuration method {method.value}', '0.44', 'Use "config-tool" instead.')
        method = DependencyMethods.CONFIG_TOOL
    if method is DependencyMethods.QMAKE:
        # FIXME: needs to get a handle on the subproject
        # FeatureDeprecated.single_use('Configuration method "qmake"', '0.58', 'Use "config-tool" instead.')
        method = DependencyMethods.CONFIG_TOOL

    # Set the detection method. If the method is set to auto, use any available method.
    # If method is set to a specific string, allow only that detection method.
    if method == DependencyMethods.AUTO:
        methods = list(possible)
    elif method in possible:
        methods = [method]
    else:
        raise DependencyException(
            'Unsupported detection method: {}, allowed methods are {}'.format(
                method.value,
                mlog.format_list([x.value for x in [DependencyMethods.AUTO] + list(possible)])))

    return methods

def detect_compiler(name: str, env: 'Environment', for_machine: MachineChoice,
                    language: T.Optional[str]) -> T.Union['MissingCompiler', 'Compiler']:
    """Given a language and environment find the compiler used."""
    compilers = env.coredata.compilers[for_machine]

    # Set the compiler for this dependency if a language is specified,
    # else try to pick something that looks usable.
    if language:
        if language not in compilers:
            m = name.capitalize() + ' requires a {0} compiler, but ' \
                '{0} is not in the list of project languages'
            raise DependencyException(m.format(language.capitalize()))
        return compilers[language]
    else:
        for lang in clib_langs:
            try:
                return compilers[lang]
            except KeyError:
                continue
    return MissingCompiler()


class SystemDependency(ExternalDependency):

    """Dependency base for System type dependencies."""

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any],
                 language: T.Optional[str] = None) -> None:
        super().__init__(DependencyTypeName('system'), env, kwargs, language=language)
        self.name = name

    @staticmethod
    def log_tried() -> str:
        return 'system'


class BuiltinDependency(ExternalDependency):

    """Dependency base for Builtin type dependencies."""

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any],
                 language: T.Optional[str] = None) -> None:
        super().__init__(DependencyTypeName('builtin'), env, kwargs, language=language)
        self.name = name

    @staticmethod
    def log_tried() -> str:
        return 'builtin'
```