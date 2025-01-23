Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding: The Purpose of the File**

The header comments immediately tell us this is about detecting external dependencies within the Meson build system, specifically for the Frida project's CLR (Common Language Runtime) subproject. The file name `base.py` suggests foundational logic. The copyright mentions both the Meson team and Intel, indicating collaboration or Intel's adoption of Meson for this project.

**2. Core Concepts - Dependencies in Build Systems**

Before diving deep, it's helpful to recall what "dependencies" mean in a build system context. Think of it like this: to build software (A), you might need other software (B) already built or available. These "other software" are dependencies. The build system needs a way to:

* **Find** these dependencies (e.g., libraries, headers).
* **Get information** about them (e.g., include paths, library names, versions).
* **Tell the compiler and linker** how to use them.

**3. Skimming for Key Structures and Concepts**

A quick scan reveals important elements:

* **Classes:** `Dependency`, `ExternalDependency`, `InternalDependency`, `NotFoundDependency`, etc. These represent different types of dependencies.
* **Enums:** `DependencyMethods` - lists the various ways Meson can try to find dependencies (pkg-config, CMake, etc.). This is a crucial point.
* **Exceptions:** `DependencyException` - how errors related to dependency handling are reported.
* **Methods:**  Lots of methods related to getting compile args, link args, versions, sources, etc. These are the building blocks for interacting with dependencies.
* **`kwargs`:**  The use of `kwargs` in constructors suggests a flexible way to pass configuration options.
* **Logging:** Mentions of `mlog` indicate logging within Meson.
* **MachineChoice:**  Indicates support for cross-compilation (building for different architectures).

**4. Analyzing Key Classes in Detail**

* **`Dependency`:**  This is the base class. It defines the core attributes and methods common to all dependencies. The methods like `get_compile_args`, `get_link_args`, `found()` are fundamental to how Meson uses dependency information. The `partial_dependency` method hints at optimizing build processes by taking only necessary parts of a dependency.

* **`ExternalDependency`:** Represents dependencies found outside the current project (e.g., system libraries, third-party libraries). The `DependencyMethods` enum comes into play here, as this class deals with finding these external resources. The version checking (`_check_version`) is important for ensuring compatibility.

* **`InternalDependency`:** Represents dependencies within the current Meson project or build. It holds information about include directories, libraries built within the project, etc.

* **`NotFoundDependency`:**  A placeholder when a dependency cannot be located.

**5. Connecting to Reverse Engineering Concepts**

Now, let's link this to reverse engineering:

* **Dynamic Instrumentation (Frida):** The file's location within the Frida project is the biggest clue. Frida works by injecting into running processes. To do this effectively, it needs to interact with the target process's environment, which often involves understanding its dependencies (e.g., which libraries are loaded, where their headers are).

* **Finding Library Dependencies:** Tools like `ldd` (on Linux) or Dependency Walker (on Windows) are used in reverse engineering to discover a program's dependencies. This code mirrors that at a build-system level. Meson needs to figure out these dependencies *before* the program is even built.

* **Symbol Resolution:**  When reverse engineering, you often need to understand how symbols (functions, variables) are resolved between different modules (libraries). The `link_args` and `get_link_args` methods are directly related to this, as link arguments tell the linker how to connect different parts of the program.

* **Header Files:** Include paths are essential for compilation. Reverse engineers also use header files (or reconstructed headers) to understand the interfaces of libraries they're analyzing. The `get_include_dirs` method reflects this.

**6. Considering Low-Level Details**

* **Binary Level:** The code deals with concepts like linkers and compiler flags (`-L`, `-I`, `-l`). These directly manipulate the binary creation process.
* **Linux/Android Kernel/Framework:** While this specific file doesn't directly interact with the kernel, the *purpose* of Frida often involves interacting with the lower layers of the operating system. The dependency management here ensures that Frida's components can be built correctly to facilitate that interaction.

**7. Logical Reasoning and Examples**

* **Assumption:** If a dependency is found (`is_found` is True), then methods like `get_compile_args` and `get_link_args` will return relevant information. If not found, they might return empty lists or raise exceptions.
* **Example:** If `DependencyMethods.PKGCONFIG` is used, the code will likely execute external commands (like `pkg-config --cflags <dependency>`) to retrieve compile arguments.

**8. Common User/Programming Errors**

* **Incorrect Dependency Names:**  Typos or using the wrong names for dependencies.
* **Missing Dependencies:** The required libraries or headers aren't installed on the system.
* **Version Mismatches:** Trying to use a version of a dependency that's incompatible with the project's requirements. This is handled by the `_check_version` method.
* **Conflicting Methods:** Specifying a dependency method that's not appropriate for the dependency (e.g., trying to use `pkg-config` for a dependency that doesn't have a `.pc` file).

**9. Tracing User Actions (Debugging)**

* **`meson.build` file:** The user will typically declare dependencies in the `meson.build` file using functions like `dependency()`.
* **Meson Execution:** When the user runs `meson setup` or `meson compile`, Meson will parse the `meson.build` file and execute the dependency resolution logic in files like `base.py`.
* **Debugging Steps:** If a dependency isn't found, a developer might:
    * Check the dependency name in `meson.build`.
    * Verify that the dependency is installed.
    * Examine the Meson log output for clues about why the dependency lookup failed.
    * Experiment with different `method` options in the `dependency()` call.

**10. Iteration and Refinement**

This kind of analysis often involves some iteration. You might skim, then focus on key parts, then go back and fill in details. Understanding the surrounding context (Frida and Meson) is crucial. If you weren't familiar with these tools, you'd need to do some research on them to fully grasp the purpose of this code.
This Python code file, `base.py`, is a core component of Meson's dependency handling system, specifically within the context of the Frida dynamic instrumentation tool's CLR subproject. Its primary function is to **define the fundamental structures and logic for detecting and representing external dependencies** required to build the Frida CLR components.

Let's break down its functionalities, relating them to reverse engineering, low-level details, logic, potential errors, and debugging.

**1. Core Functionalities:**

* **Defining Dependency Classes:**
    * **`Dependency`:** This is the base class for all dependency types. It defines common attributes like name, version, whether it's found, compile arguments, link arguments, and source files. It provides fundamental methods to access and manipulate this information (e.g., `get_compile_args`, `get_link_args`, `found`).
    * **`ExternalDependency`:**  Represents dependencies that are external to the current build project (e.g., system libraries, third-party libraries). It includes logic for checking versions and handling "native" dependencies (dependencies needed for the build machine vs. the target machine).
    * **`InternalDependency`:** Represents dependencies that are built within the same Meson project. It holds information about include directories, internal libraries, and compile/link arguments.
    * **`NotFoundDependency`:** A placeholder dependency used when a required dependency cannot be found.
* **Defining Dependency Methods (`DependencyMethods` Enum):** This enumeration lists the different mechanisms Meson can use to locate external dependencies (e.g., `pkg-config`, `cmake`, system search, etc.). This allows for flexibility in how dependencies are discovered.
* **Handling Compile and Link Arguments:**  The code manages lists of compiler flags (`compile_args`) and linker flags (`link_args`) associated with each dependency. These flags are crucial for telling the compiler and linker where to find header files and libraries.
* **Version Checking:** The `ExternalDependency` class includes logic (`_check_version`) to verify if the found dependency meets the version requirements specified in the build definition.
* **"Native" Dependency Handling:** The `HasNativeKwarg` mixin and `ExternalDependency` class handle cases where a dependency is needed for the build process itself (e.g., code generators) rather than the target being built.
* **Partial Dependency Creation:** The `get_partial_dependency` method allows creating a new dependency object containing only specific parts of the original dependency (e.g., only compile args or only link args). This can be useful for optimizing build processes.
* **Logging and Error Handling:** The code uses `mlog` for logging information about dependency detection. It also defines `DependencyException` for raising errors when dependency issues occur.

**2. Relationship to Reverse Engineering:**

This file is deeply intertwined with reverse engineering principles, especially in the context of Frida:

* **Dynamic Instrumentation:** Frida's core purpose is to inject into running processes and manipulate their behavior. To do this effectively, Frida needs to interact with the target process's environment, which includes its dependencies (libraries). Understanding and managing these dependencies is crucial for Frida's functionality.
* **Library Dependencies:** When reverse engineering, understanding which libraries a program depends on is a fundamental step. This code handles the build-time equivalent of that – ensuring the necessary libraries are available and linked correctly when building Frida components.
* **Symbol Resolution:**  The `link_args` directly relate to how symbols (functions, variables) are resolved between different modules (libraries). Properly managing link dependencies is essential for the final Frida binaries to function correctly.
* **Header Files:** The `compile_args` and the handling of include directories (`-I` flags) are vital for finding the header files that define the interfaces of the libraries Frida depends on. Reverse engineers often rely on header files to understand library interfaces.

**Example:**

Imagine Frida needs to interact with the system's C standard library (`libc`). This file would be responsible for:

* **Identifying `libc` as a dependency.**
* **Finding the location of `libc`'s header files (e.g., `/usr/include`).** This would translate to adding `-I/usr/include` to the `compile_args`.
* **Finding the `libc` library itself (e.g., `libc.so` on Linux).** This would translate to adding `-lc` to the `link_args`.

**3. Relationship to Binary底层, Linux, Android Kernel & Framework:**

* **Binary Level:** The code directly manipulates compiler and linker flags, which are instructions for the tools that generate the final binary executables and libraries. Understanding these flags is essential for low-level development.
* **Linux/Android:**  The dependency detection mechanisms (like `pkg-config`) are common on Linux and often used in Android development. The search paths for libraries and headers are also OS-specific, and this code would interact with Meson's OS awareness to handle those differences.
* **Kernel/Framework:** While this specific file might not directly interact with kernel code, the dependencies it manages often *do*. For example, Frida might depend on libraries that interact with the Linux kernel (e.g., `libcap` for capabilities). On Android, Frida would certainly interact with the Android framework, and this file would handle dependencies on framework libraries.

**Example:**

If Frida on Android needs to use a specific system library like `libbinder` for inter-process communication, this code would be responsible for:

* **Detecting the presence of `libbinder`.**
* **Adding the appropriate linker flag (e.g., `-lbinder`) to `link_args`.**
* **Potentially adding include paths for `libbinder` headers to `compile_args`.**

**4. Logical Reasoning and Assumptions:**

* **Assumption:** If a dependency method like `PKGCONFIG` is specified, the system has the `pkg-config` tool installed and the dependency provides a `.pc` file.
* **Assumption:** The information retrieved from dependency detection tools (like `pkg-config`) is accurate and provides the necessary compile and link flags.
* **Logic:** The `_check_version` method uses string comparison logic to determine if the found dependency version satisfies the required version constraints. It assumes a certain format for version strings.
* **Logic:** The `get_all_compile_args` and `get_all_link_args` methods recursively collect arguments from the current dependency and its sub-dependencies, assuming that all these arguments are needed for building.

**Example (Hypothetical Input & Output):**

Let's say the `meson.build` file specifies a dependency on `glib-2.0` with a minimum version of `2.50`.

* **Input:** Meson processes the `dependency('glib-2.0', version: '>=2.50')` call.
* **Process:** The code might use the `PKGCONFIG` method. It would execute `pkg-config --cflags glib-2.0` and `pkg-config --libs glib-2.0`. It would also get the version using `pkg-config --modversion glib-2.0`.
* **Assumption:** `pkg-config` returns:
    * `compile_args`: `-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include`
    * `link_args`: `-lglib-2.0`
    * `version`: `2.70.1`
* **Output:**
    * `dependency.is_found` would be `True`.
    * `dependency.compile_args` would be `['-I/usr/include/glib-2.0', '-I/usr/lib/glib-2.0/include']`.
    * `dependency.link_args` would be `['-lglib-2.0']`.
    * `dependency.version` would be `'2.70.1'`.
    * The `_check_version` method would confirm that `2.70.1` is `>=2.50`.

**5. User or Programming Common Usage Errors:**

* **Incorrect Dependency Names:**  Typos or using the wrong name for a dependency in the `meson.build` file (e.g., `dependecy('libusb-1.0')` instead of `dependency('libusb-1.0')`).
* **Missing Dependencies:** The required library or its development headers are not installed on the system. Meson will report that the dependency was not found.
* **Version Mismatches:** Specifying a version requirement that cannot be satisfied by the installed version of the dependency. The `_check_version` method will detect this and raise an error.
* **Incorrect `method` Specification:**  Forcefully specifying a dependency method that is not appropriate for the dependency (e.g., using `method: 'cmake'` for a library that doesn't provide CMake config files).
* **Permissions Issues:**  The user running Meson might not have the necessary permissions to execute dependency detection tools like `pkg-config`.

**Example (User Error):**

A user might have a typo in their `meson.build`:

```python
project('myproject', 'c')
dep = dependency('gib-2.0') # Typo: 'gib' instead of 'glib'
```

This would lead to Meson reporting that the dependency `gib-2.0` was not found.

**6. User Operation Steps to Reach This Code (Debugging Context):**

1. **User Creates or Modifies `meson.build`:** The user defines the project's dependencies using the `dependency()` function in the `meson.build` file.
2. **User Runs `meson setup`:** This command initiates the Meson configuration process.
3. **Meson Parses `meson.build`:** Meson reads the `meson.build` file and identifies the declared dependencies.
4. **Dependency Resolution:** For each dependency, Meson calls the relevant dependency detection logic, which often involves code within `base.py`.
5. **`ExternalDependency.__init__` (or a subclass):** When an external dependency is encountered, an instance of `ExternalDependency` (or a more specific subclass like `PkgConfigDependency` which might import from `base.py`) is created.
6. **Dependency Detection Methods:**  Based on the specified `method` (or the default `auto`), Meson will execute the corresponding detection logic (e.g., using `pkg-config`, searching for CMake files, etc.). This logic often resides in other files but relies on the classes and structures defined in `base.py`.
7. **Information Gathering:** The detection logic populates the attributes of the `Dependency` object (name, version, compile args, link args).
8. **Error Reporting:** If a dependency is not found or if version requirements are not met, exceptions defined in `base.py` (like `DependencyException`) are raised, and Meson reports the error to the user.

**Debugging Scenario:**

If a user encounters an error like "Dependency glib-2.0 not found," a developer investigating this would:

* **Check the `meson.build` file:** Ensure the dependency name is correct.
* **Examine the Meson log output:** Look for messages related to dependency detection attempts. The log might indicate which methods were tried and why they failed.
* **Verify the dependency is installed:** Check if the `glib-2.0` development packages are installed on the system.
* **Potentially step through the Meson code:** A developer might use a debugger to trace the execution flow within `base.py` and related files to understand exactly how Meson is trying to find the dependency and why it's failing. They might examine the values of variables like `self.compile_args`, `self.link_args`, and `self.is_found` during the debugging process.

In summary, `base.py` is a foundational file in Meson's dependency management system, providing the core data structures and logic for representing and handling dependencies. Its functionality is crucial for building software projects, especially complex ones like Frida, and it has significant connections to reverse engineering concepts and low-level system details. Understanding this file is essential for anyone developing with Meson or debugging dependency-related issues.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/dependencies/base.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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