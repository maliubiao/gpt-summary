Response:
The user wants to understand the functionality of the Python code provided, which is part of the Frida dynamic instrumentation tool. Specifically, the file `base.py` seems to handle the detection and representation of external dependencies within the Meson build system.

Here's a breakdown of the thinking process to address each of the user's requests:

1. **List the functionalities:**
    -  Read through the code and identify the main classes and their purposes.
    -  Focus on what each class is responsible for, its methods, and the data it holds.
    -  Keywords like "detection logic," "external dependencies," "compile args," "link args," "version," etc., are good indicators of functionality.
    -  List the identified functionalities concisely.

2. **Relationship to reverse engineering:**
    - Consider how managing dependencies relates to the process of reverse engineering tools like Frida.
    - Frida interacts with target processes and their libraries. Knowing how Frida's build system handles these dependencies is relevant.
    - Think about scenarios where understanding dependencies is crucial for reverse engineering Frida itself or targets it interacts with.

3. **Binary, Linux, Android kernel/framework knowledge:**
    - Look for code elements that hint at low-level concepts or platform-specific details.
    - The terms "compile_args," "link_args," and handling of static/shared libraries are relevant to binary interaction.
    - The code interacts with the operating system's library search paths, which is a Linux concept.
    - While this specific file doesn't directly mention Android kernel or framework, the broader context of Frida (dynamic instrumentation, often used on Android) makes it relevant to consider. The dependency management in this file is a foundational step for building tools that interact with such systems.

4. **Logical reasoning (input/output):**
    - Identify functions or methods where a clear input leads to a predictable output based on defined logic.
    - The `_check_version` method is a good example. It takes the found version and required versions as input and outputs a boolean indicating if the requirements are met.
    - Create a simple scenario with example versions to illustrate the input and output.

5. **User/programming errors:**
    - Look for error handling, type checking, or places where incorrect usage could lead to problems.
    - The `include_type` parameter and its validation are a good example of preventing user errors.
    - The `static` keyword and its type check also highlight a potential area for user error.
    - Provide concrete examples of incorrect usage and the resulting error message.

6. **User operation to reach this code (debugging):**
    -  Think about the steps a developer would take when working with Frida that would involve the build system and dependency management.
    - Starting with the desire to build Frida, the Meson build system is invoked, and the dependency resolution process begins.
    -  Highlight key steps like configuring the build, specifying dependencies, and the role of Meson in finding these dependencies. This leads to the execution of the code in `base.py`.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on the specific syntax of the code. It's important to step back and think about the *purpose* and *function* of each part.
- When considering the reverse engineering aspect, it's easy to get lost in the details of specific Frida features. The key is to connect the *dependency management* aspect to the broader task of understanding and manipulating software.
- For the binary/kernel knowledge, avoid making assumptions if the code doesn't explicitly show it. Stick to what the code *does* reveal about low-level interactions.
-  The input/output examples should be simple and illustrative, not overly complex.
-  For user errors, focus on common mistakes related to the parameters and options handled by this code.
-  The debugging scenario should be a logical sequence of actions a developer would take, connecting the user's intent to the execution of this specific file.
This Python file, `base.py`, within the Frida project's Meson build system, is primarily responsible for defining the foundational classes and logic for handling **external dependencies**. Meson is a build system, and dependencies are external libraries or software components that a project needs to compile and link against.

Here's a breakdown of its functionalities:

**1. Defining Core Dependency Classes:**

*   **`Dependency`:** This is the base class for all dependencies. It provides a common interface and attributes for representing a dependency, regardless of its origin or how it's found. Key attributes include:
    *   `name`: The name of the dependency.
    *   `version`: The version of the dependency (if known).
    *   `is_found`: A boolean indicating whether the dependency was successfully located.
    *   `compile_args`: A list of compiler flags required to use the dependency (e.g., `-I/path/to/headers`).
    *   `link_args`: A list of linker flags required to link against the dependency (e.g., `-L/path/to/libs`, `-llibname`).
    *   `sources`: Source files provided by the dependency (e.g., for static linking or when the dependency provides source).
    *   `include_type`: Specifies how include directories should be treated ('preserve', 'system', 'non-system').
    *   `ext_deps`: A list of other `Dependency` objects that this dependency relies on.

*   **`InternalDependency`:** Represents dependencies that are built within the current project (not external).

*   **`ExternalDependency`:**  A base class for dependencies that are external to the current project. It adds attributes related to finding the dependency:
    *   `version_reqs`: A list of version requirements for the dependency.
    *   `required`: A boolean indicating if the dependency is mandatory.
    *   `static`: A boolean indicating if the static version of the library should be preferred.
    *   `for_machine`:  Specifies whether the dependency is for the build machine or the host machine.

*   **`NotFoundDependency`:** Represents a dependency that could not be found.

*   **`ExternalLibrary`:** A specific type of `ExternalDependency` that represents a pre-built library found on the system.

**2. Defining Dependency Finding Methods:**

*   **`DependencyMethods` (Enum):** Defines the different methods Meson can use to locate dependencies. This includes:
    *   `AUTO`: Let Meson decide the best method.
    *   `PKGCONFIG`: Use the `pkg-config` utility.
    *   `CMAKE`: Use CMake's find mechanism.
    *   `BUILTIN`: The dependency is part of the standard library.
    *   `SYSTEM`: The dependency is assumed to be present on the operating system.
    *   Other methods like `EXTRAFRAMEWORK`, `SYSCONFIG`, `CONFIG_TOOL`, `QMAKE`, etc., for specific dependency types.

**3. Utility Functions for Dependency Handling:**

*   **`process_include_type_kw`:**  Validates and processes the `include_type` keyword argument.
*   **`get_compile_args` and `get_all_compile_args`:** Methods to retrieve compile flags, handling the `include_type`.
*   **`get_link_args` and `get_all_link_args`:** Methods to retrieve linker flags.
*   **`found`:** Returns whether the dependency was found.
*   **`get_sources` and `get_extra_files`:**  Retrieve source and extra files associated with the dependency.
*   **`get_version`:** Retrieves the dependency's version.
*   **`get_partial_dependency`:** Creates a new dependency object containing only a subset of the original dependency's information.
*   **`_add_sub_dependency`:**  Adds internal dependencies to a dependency object.
*   **`get_variable`:**  Retrieves variables associated with the dependency (e.g., from pkg-config or CMake).
*   **`generate_system_dependency` and `generate_link_whole_dependency`:**  Create modified dependency objects for specific purposes.
*   **`get_leaf_external_dependencies`:**  Extracts the "leaf" dependencies (those without further external dependencies).
*   **`sort_libpaths`:** Sorts library paths based on reference paths (useful for consistent linking).
*   **`strip_system_libdirs` and `strip_system_includedirs`:**  Remove system library and include directories from link and compile arguments.
*   **`process_method_kw`:** Processes the `method` keyword argument to select dependency detection methods.
*   **`detect_compiler`:** Determines the appropriate compiler for a given language and machine.

**Relationship to Reverse Engineering:**

This file is directly related to reverse engineering because Frida is a dynamic instrumentation toolkit used extensively for reverse engineering. Understanding how Frida's build system manages dependencies is important for:

*   **Building Frida from Source:**  When a user wants to build Frida, Meson uses the logic in `base.py` to find Frida's dependencies (e.g., GLib, libuv, etc.). Without these dependencies, Frida cannot be compiled and linked.
*   **Extending Frida:**  If a developer wants to extend Frida's functionality by adding new features or integrating with other libraries, they need to understand how to declare and manage these new dependencies within the build system. `base.py` provides the framework for this.
*   **Debugging Frida Build Issues:**  If the Frida build fails due to missing dependencies or version conflicts, understanding the classes and methods in `base.py` helps diagnose the problem. For example, if `pkg-config` fails to find a library, the code related to `DependencyMethods.PKGCONFIG` would be relevant.
*   **Understanding Frida's Architecture:** Knowing how Frida depends on other libraries provides insight into its internal workings and how different components interact.

**Example:**  Let's say Frida needs the GLib library. When Meson is run, it might try to find GLib using `pkg-config`. The `ExternalDependency` class would be instantiated to represent GLib. If `pkg-config` succeeds, `glib_dep.is_found` would be `True`, and `glib_dep.compile_args` would contain the include paths from GLib's `.pc` file (e.g., `-I/usr/include/glib-2.0`, `-I/usr/lib/glib-2.0/include`), and `glib_dep.link_args` would contain the library linking flags (e.g., `-lglib-2.0`). These flags are then used by the compiler and linker during the Frida build process.

**In terms of specific reverse engineering tasks related to this file:**

*   **Analyzing Frida's Dependencies:** A reverse engineer could examine the Meson build files (e.g., `meson.build`) to see what dependencies Frida uses and how they are specified. Understanding the logic in `base.py` helps interpret how Meson handles these specifications.
*   **Modifying Frida's Build:**  A reverse engineer might want to build a modified version of Frida, perhaps with different dependencies or versions. Knowing the dependency management mechanisms in `base.py` is crucial for making these changes correctly.

**Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

This file touches upon these areas indirectly:

*   **Binary Underlying:** The core purpose of managing dependencies is to facilitate the creation of executable binaries. The `compile_args` and `link_args` directly manipulate how the compiler and linker process binary files. The concepts of static vs. shared libraries (`self.static`, `LibType`) are fundamental to binary linking.
*   **Linux:**  Many of the dependency finding methods (like `pkg-config`) are standard on Linux systems. The handling of library paths (e.g., using `-L`) and include paths (e.g., using `-I`) are standard Linux conventions for compiling and linking. The functions `strip_system_libdirs` and `strip_system_includedirs` are specifically designed to handle the complexities of system-provided libraries on Linux and other Unix-like systems.
*   **Android Kernel & Framework:** While not explicitly mentioning Android in this specific file, Frida is heavily used on Android. The dependency management here is the foundation for building Frida for Android. When building Frida for Android, Meson will use the logic in `base.py` to find dependencies required on the Android platform, potentially using different methods or configuration. The distinction between "host" and "build" machines (`for_machine`) is crucial in cross-compilation scenarios like building for Android from a Linux desktop. Frida often interacts with Android framework components, so ensuring the correct dependencies for those components are found is essential.

**Example:** When building Frida for an Android target, Meson needs to find the Android NDK (Native Development Kit). The `base.py` logic will be involved in locating the NDK's toolchain and libraries, setting up the correct compiler and linker flags (`compile_args`, `link_args`) for the Android architecture (e.g., ARM, ARM64).

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario:** Meson is trying to find the `zlib` library using the `PKGCONFIG` method.

**Hypothetical Input:**

*   `name` (in `ExternalDependency`): "zlib"
*   `method` (in `kwargs` passed to a dependency finding function): `DependencyMethods.PKGCONFIG`
*   System has `pkg-config` installed, and a `zlib.pc` file is present in a standard location (e.g., `/usr/lib/pkgconfig`).

**Logical Reasoning within `base.py`:**

1. The `process_method_kw` function would validate that `PKGCONFIG` is a valid method.
2. A function (not in this specific file but utilizing these classes) would execute `pkg-config --cflags zlib` and `pkg-config --libs zlib`.
3. The output of these commands (e.g., `-I/usr/include`, `-lz`) would be stored in the `compile_args` and `link_args` attributes of an `ExternalDependency` object representing `zlib`.
4. The `_check_version` method would compare the found version of `zlib` (obtained via `pkg-config --modversion zlib`) with any specified version requirements (`version_reqs`).

**Hypothetical Output (if zlib is found and version requirements are met):**

*   `zlib_dep.is_found`: `True`
*   `zlib_dep.version`: The version string obtained from `pkg-config --modversion zlib` (e.g., "1.2.11")
*   `zlib_dep.compile_args`:  A list containing the output of `pkg-config --cflags zlib` (e.g., `['-I/usr/include']`)
*   `zlib_dep.link_args`: A list containing the output of `pkg-config --libs zlib` (e.g., `['-lz']`)

**User or Programming Common Usage Errors:**

*   **Incorrect `include_type`:** A user might accidentally provide an invalid value for `include_type` (e.g., `"global"`). The `_process_include_type_kw` function will raise a `DependencyException` with a clear error message: `"include_type may only be one of ['preserve', 'system', 'non-system']"`.
*   **Incorrect `static` type:**  A user might provide a non-boolean value for the `static` keyword (e.g., `static="maybe"`). The `ExternalDependency.__init__` method checks the type and raises a `DependencyException`: `"Static keyword must be boolean"`.
*   **Specifying an invalid `method`:**  If a user tries to use a dependency detection method that doesn't exist or isn't supported for a particular dependency, the `process_method_kw` function will raise a `DependencyException`. For example, if they specify `method="foobar"`, the error would be: `"method 'foobar' is invalid"`.
*   **Forgetting to install dependency development packages:** A common user error is trying to build Frida without having the necessary development headers and libraries for its dependencies installed on their system. In this case, Meson might try to find a dependency (e.g., using `pkg-config`), but `pkg-config` won't find the `.pc` file, or the headers/libraries themselves might be missing. This would lead to `dependency.is_found` being `False`, and the build would likely fail with an error message indicating the missing dependency.

**User Operation to Reach This Code (Debugging Scenario):**

1. **User wants to build Frida from source:**  They download the Frida source code.
2. **User navigates to the Frida build directory:** They open a terminal and go to the directory where the `meson.build` file is located.
3. **User runs the Meson configuration command:** They execute a command like `meson setup build`.
4. **Meson starts processing the `meson.build` file:** Meson reads the build instructions, which include declarations of dependencies (e.g., `dependency('glib-2.0')`).
5. **Meson calls dependency finding functions:** For each dependency, Meson's internal logic (which utilizes the classes and functions in `base.py`) starts the process of locating the dependency.
6. **Instantiation of `ExternalDependency` (or a subclass):** For a dependency like GLib, an `ExternalDependency` object would be created.
7. **Processing `method` and attempting dependency detection:** Meson would determine the appropriate method (e.g., `PKGCONFIG`) and execute the relevant commands (e.g., `pkg-config --cflags glib-2.0`).
8. **Code in `base.py` is executed:** The methods in `base.py`, such as `process_method_kw`, `_check_version`, and the getters for compile and link arguments, are called to manage the dependency information.
9. **Debugging Scenario:** If the build fails with an error related to a missing dependency, the user might:
    *   **Examine the Meson log output:** The log might indicate which dependency was not found and what methods were tried.
    *   **Check if the dependency's development packages are installed:**  They might realize they are missing `libglib2.0-dev` (on Debian/Ubuntu) and install it.
    *   **Inspect the `meson.build` file:** They might check if the dependency name is spelled correctly or if any specific options are being used.
    *   **Manually run `pkg-config` commands:**  To verify if `pkg-config` is finding the dependency correctly.

By understanding the code in `base.py`, developers and users can better understand how Meson handles dependencies, troubleshoot build issues, and potentially extend Frida's build system.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/base.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```