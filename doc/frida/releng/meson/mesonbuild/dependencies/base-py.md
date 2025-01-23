Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Understanding the Request:**

The core request is to analyze the provided Python code (`frida/releng/meson/mesonbuild/dependencies/base.py`) and explain its functionality, especially in the context of Frida, reverse engineering, low-level concepts, and potential user errors. The request also emphasizes tracing how a user might end up interacting with this code.

**2. Initial Code Scan - High-Level Purpose:**

My first step is a quick skim of the code to understand its general purpose. I see imports related to Meson (a build system), type hinting (`typing`), enums, and logging. The presence of classes like `Dependency`, `ExternalDependency`, `InternalDependency`, and specific dependency types (like `SystemDependency`, `BuiltinDependency`) strongly suggests this file is about managing external dependencies within the Meson build process. The copyright notices also confirm its origin within the Meson project.

**3. Deeper Dive - Key Classes and Concepts:**

Now, I'll go through the code more carefully, focusing on the key classes and their attributes and methods.

* **`Dependency`:**  This is clearly the base class for all dependencies. I note attributes like `name`, `version`, `compile_args`, `link_args`, `is_found`, and methods like `get_compile_args`, `get_link_args`, `found()`. This class represents a generic dependency and provides the fundamental interface for interacting with it. The `partial_dependency` method hints at the ability to extract specific parts of a dependency.

* **`ExternalDependency`:** This inherits from `Dependency` and adds attributes like `env` (environment), `version_reqs` (version requirements), `required`, `static`, and `for_machine`. The `_check_version` method is important for verifying dependency versions. The connection to `detect_compiler` is also crucial. This class represents dependencies that are external to the current project.

* **`InternalDependency`:**  Another subclass of `Dependency`, but with a different set of attributes like `include_directories`, `libraries`, `whole_libraries`, and `objects`. This likely represents dependencies that are built as part of the current project or are tightly coupled with it.

* **`DependencyMethods` Enum:**  This enum lists various ways Meson can find dependencies (e.g., `pkg-config`, `cmake`, `system`). This is key to understanding how Meson resolves dependencies.

* **Helper Functions:** Functions like `get_leaf_external_dependencies`, `sort_libpaths`, `strip_system_libdirs`, `strip_system_includedirs`, `process_method_kw`, and `detect_compiler` perform utility tasks related to dependency management.

**4. Connecting to the Request's Specific Points:**

Now, I'll systematically address each point in the request:

* **Functionality:** I need to summarize what this file does. The core function is managing external dependencies in a Meson build. This involves finding dependencies, checking their versions, and providing information (compile flags, link flags) needed to build software that depends on them.

* **Relationship to Reverse Engineering:** This requires thinking about how Frida and reverse engineering interact with build systems. Frida *uses* build systems like Meson to compile its components. The dependency system ensures that Frida's build process can find and link against the necessary libraries (e.g., V8, Capstone). I can provide examples of Frida depending on libraries that are relevant to reverse engineering.

* **Binary/Low-Level, Linux/Android Kernel/Framework:** This requires thinking about the *types* of dependencies Frida might have. Frida interacts with operating systems and potentially low-level components. Examples include:
    * **glibc (Linux):** A fundamental system library.
    * **Android NDK libraries:**  For building Frida components on Android.
    * **Kernel headers (indirectly):** While this file doesn't directly handle kernel headers, the dependencies it manages might require them.
    * **Frameworks (Android):**  Frida often interacts with Android frameworks.

* **Logical Reasoning (Hypothetical Input/Output):** I can create a scenario where Meson tries to find a dependency (e.g., OpenSSL). The input would be the dependency name and version requirements. The output would be a `Dependency` object (if found) or an indication that it was not found.

* **User/Programming Errors:** I can consider common mistakes developers make when dealing with dependencies:
    * Incorrect dependency names.
    * Incorrect version requirements.
    * Missing development packages.
    * Conflicting dependencies.
    * Issues with static vs. shared linking.

* **User Path to This Code (Debugging Clues):** This requires thinking about the typical Frida development workflow:
    1. Modifying Frida's source code.
    2. Running Meson to configure the build.
    3. Meson encounters a dependency declaration.
    4. Meson uses the logic in this file to find the dependency.
    5. If there's a problem (e.g., dependency not found), the error message might trace back to this code.

**5. Structuring the Explanation:**

Finally, I need to organize the information logically and clearly, using headings and bullet points for better readability. I'll start with the overall functionality and then delve into the specific aspects requested. I'll provide code examples and hypothetical scenarios where appropriate. I'll also make sure to use terminology relevant to build systems and software development.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the Meson-specific aspects. I need to constantly bring it back to the context of Frida and reverse engineering.
* I might overlook some of the subtle functionalities, like the `include_type` parameter in the `Dependency` class. A closer reading reveals its purpose.
* I need to ensure the examples I provide are relevant and understandable to someone familiar with Frida and reverse engineering concepts.
*  I need to remember that the request asks about *how* a user might end up here as a *debugging clue*, so focusing on error scenarios and the Meson build process is important.

By following this structured approach, I can analyze the code effectively and generate a comprehensive and insightful explanation that addresses all aspects of the request.
This Python file, `base.py`, located within the Meson build system's dependency handling logic (specifically for Frida), is the foundational piece for detecting and managing external dependencies required to build software. Here's a breakdown of its functionality:

**Core Functionality:**

1. **Dependency Abstraction:** It defines the base `Dependency` class, which acts as a blueprint for representing any external library or software component that the project being built relies upon. This class provides common attributes and methods for describing a dependency (name, version, include paths, libraries to link against, etc.).

2. **Dependency Types:** It introduces various subclasses of `Dependency` to categorize different ways dependencies are found and handled:
    * **`ExternalDependency`:** Represents a generic external dependency that needs to be located.
    * **`InternalDependency`:** Represents dependencies that are part of the current project's build process or are provided internally.
    * **`SystemDependency`:** Represents dependencies expected to be available on the target system (e.g., standard libraries).
    * **`BuiltinDependency`:** Represents dependencies that are considered built-in or part of the core toolchain.
    * **`NotFoundDependency`:**  Represents a dependency that could not be found.

3. **Dependency Finding Methods:** It defines an enumeration `DependencyMethods` that lists the different strategies Meson can use to locate external dependencies. These methods include:
    * `PKGCONFIG`: Using `pkg-config` to get dependency information.
    * `CMAKE`: Using CMake's find_package mechanism.
    * `SYSTEM`: Assuming the dependency is a standard system library.
    * `BUILTIN`: The dependency is considered built-in.
    * `EXTRAFRAMEWORK` (macOS): Searching for frameworks.
    * `SYSCONFIG`: Using Python's `sysconfig` module.
    * `CONFIG_TOOL`: Using a `<package>-config` style tool.
    * `QMAKE`: Using `qmake` (deprecated, now maps to `CONFIG_TOOL`).
    * `DUB`: Using the D programming language's package manager.

4. **Handling Dependency Information:** The `Dependency` class and its subclasses store crucial information about a detected dependency, such as:
    * **Compile arguments (`compile_args`):** Flags needed to compile code that uses the dependency (e.g., include paths `-I`).
    * **Link arguments (`link_args`):** Flags needed to link the final executable or library against the dependency (e.g., library names `-l`, library paths `-L`).
    * **Sources (`sources`):** Source files that might be provided by the dependency (e.g., for static linking).
    * **Version (`version`):** The version of the detected dependency.
    * **"Found" status (`is_found`):** Whether the dependency was successfully located.

5. **Version Checking:** The `ExternalDependency` class includes logic (`_check_version`) to verify if the found dependency's version meets the requirements specified by the build definition.

6. **Partial Dependencies:** The `get_partial_dependency` method allows creating a new dependency object containing only a subset of the original dependency's information (e.g., only compile arguments or only link arguments).

7. **Internal Dependency Management:** The `InternalDependency` class specifically handles dependencies that are built within the same Meson project or are tightly integrated.

8. **Compiler Detection:** The `detect_compiler` function helps determine the appropriate compiler to use for a given dependency based on the target language.

**Relationship to Reverse Engineering (and Frida):**

This file is directly relevant to reverse engineering through its role in building tools like Frida. Here's how:

* **Frida's Dependencies:** Frida relies on various external libraries (e.g., V8 for JavaScript engine, Capstone for disassembly, GLib, potentially custom C/C++ libraries). This `base.py` file is part of the mechanism that Meson uses to find these libraries when building Frida.
* **Linking with Target Processes:** When Frida injects into a target process, it needs to load its agent code (often written in JavaScript, executed by V8). The build process, guided by Meson and this file, ensures that the necessary components (like the V8 library) are correctly linked into Frida.
* **Cross-Compilation for Different Architectures:** Frida is often used for reverse engineering on different architectures (e.g., ARM on Android, x86 on desktop). Meson, along with this dependency logic, helps manage the correct dependencies for the target architecture.
* **Dealing with Platform-Specific Libraries:** Different operating systems and architectures have different ways of providing libraries. This file's logic, especially the different `DependencyMethods`, helps Meson adapt to these platform-specific mechanisms.

**Example of Reverse Engineering Relevance:**

Imagine Frida needs to link against the `Capstone` disassembly library.

1. **Meson Configuration:** Frida's `meson.build` file would declare a dependency on `capstone`.
2. **Dependency Resolution:** Meson, utilizing the logic in `base.py`, would try different methods (defined in `DependencyMethods`) to find Capstone:
    * It might check if `pkg-config --libs capstone` returns valid link flags.
    * If not found via `pkg-config`, it might try other methods.
3. **`Dependency` Object Creation:** If found, a `Dependency` object (likely an `ExternalDependency`) for Capstone would be created, storing its link flags (e.g., `-lcapstone`).
4. **Linking:**  During the linking stage of the Frida build, Meson would use the stored link flags from the Capstone `Dependency` object to tell the linker to include the Capstone library in the final Frida executable or shared library.

**Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

* **Binary Underlying:** The file deals with the fundamental steps of linking binary code. The `link_args` directly translate to command-line arguments passed to the linker, instructing it how to combine compiled object files and libraries into an executable.
* **Linux:** Methods like `PKGCONFIG` are heavily used on Linux systems for managing library dependencies. The logic to handle `-L` (library path) and `-l` (library name) arguments is crucial for Linux development.
* **Android Kernel & Framework:**
    * **Android NDK:** When building Frida for Android, Meson (guided by this file) needs to find libraries provided by the Android NDK (Native Development Kit). This might involve using specific toolchains and linker flags relevant to Android.
    * **System Libraries:**  Frida might depend on standard Android system libraries. The `SYSTEM` dependency method would be used to indicate these.
    * **Framework Interaction (Indirect):** While this file doesn't directly interact with Android framework code, it ensures that Frida can be built with the necessary native components that *will* interact with the framework at runtime. For example, if Frida uses a library that interfaces with Android's Binder mechanism, this file helps find that library.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

```python
from mesonbuild.dependencies.base import DependencyMethods, ExternalDependency
from mesonbuild.environment import Environment  # Assume this is properly initialized

# Assume an Environment object 'env' exists

# Attempt to find the 'openssl' library using pkg-config
kwargs = {'method': DependencyMethods.PKGCONFIG}
dep = ExternalDependency('openssl', env, kwargs)
dep._check_version() # Check version requirements (if any were set)

print(f"Openssl found: {dep.found()}")
if dep.found():
    print(f"Openssl version: {dep.get_version()}")
    print(f"Openssl compile args: {dep.get_compile_args()}")
    print(f"Openssl link args: {dep.get_link_args()}")
```

**Hypothetical Output (assuming OpenSSL is installed and pkg-config is working):**

```
Openssl found: True
Openssl version: 1.1.1w  # Example version
Openssl compile args: ['-I/usr/include/openssl'] # Example include path
Openssl link args: ['-lssl', '-lcrypto'] # Example link flags
```

**Hypothetical Output (assuming OpenSSL is NOT found via pkg-config):**

```
Openssl found: False
```

**User or Programming Common Usage Errors:**

1. **Incorrect Dependency Name:**  If a user misspells the dependency name in the `meson.build` file (e.g., `dependecy('opnssl')`), Meson will try to find a dependency with that incorrect name, leading to a "not found" error.

   ```python
   # Incorrect spelling in meson.build
   project('myproject', 'cpp', dependencies : ['opnssl'])
   ```

   **Error:** Meson will likely report that it couldn't find a dependency named "opnssl".

2. **Missing Development Packages:** If a dependency is installed on the system but the development headers and static/shared library files are missing (e.g., only the runtime library is installed), Meson might find the library but not the necessary include files, leading to compilation errors.

   **Scenario:** User has `libssl` installed for running applications but not `libssl-dev` (or equivalent).
   **Error:** Meson might find the `libssl` shared object, but compilation will fail because the OpenSSL header files are not in the include paths.

3. **Incorrect Version Requirements:**  Specifying version requirements that don't match the installed version will cause the version check to fail.

   ```python
   # In meson.build
   project('myproject', 'cpp', dependencies : [dependency('openssl', version : '>=2.0')])
   ```

   **Error:** If the installed OpenSSL version is 1.1.1w, Meson will report that the version requirement is not met.

4. **Conflicting Dependencies or Link Order Issues:** While this file helps *find* dependencies, issues can still arise during linking if there are conflicts between different libraries or if the order in which libraries are linked is incorrect. This might manifest as linker errors.

5. **Forgetting to Install Dependencies:** The most common error is simply not having the required dependencies installed on the system.

   **Error:** Meson will report that it cannot find the specified dependency.

**User Operations to Reach This Code (Debugging Clues):**

1. **Modifying `meson.build`:** A user editing the `meson.build` file to add or modify a dependency declaration is the most direct way to trigger the logic in this file.

   ```meson
   # In meson.build
   project('my_frida_module', 'cpp',
           dependencies : [
               dependency('glib-2.0'),  # This will trigger dependency lookup
               dependency('v8', method : 'pkgconfig'), # Specific method
           ])
   ```

2. **Running `meson` Command:** When the user runs the `meson` command to configure the build (e.g., `meson setup build`), Meson parses the `meson.build` file and starts resolving dependencies. This involves executing the code in `base.py` to find each declared dependency.

3. **Dependency Lookup Failure:** If Meson cannot find a dependency, the error message often points to the dependency name. Looking at the Meson debug log (often enabled with `-Ddebug=true`) would show the steps Meson took to find the dependency, potentially leading back to the logic in `base.py`.

4. **Investigating Build Errors:** If the build fails during the compilation or linking stage due to missing headers or libraries, the user might investigate the Meson configuration and dependency resolution process. Examining the `meson-info` directory and the `meson-log.txt` file can provide insights into how dependencies were handled.

5. **Developing Custom Find Modules:** For more complex dependencies, developers might need to write custom "find modules" (e.g., for CMake or custom config tools). Understanding the basic `Dependency` class and the different `DependencyMethods` in `base.py` is crucial for writing these custom modules.

In summary, `frida/releng/meson/mesonbuild/dependencies/base.py` is a fundamental component of Frida's build system, responsible for abstracting, locating, and managing the external libraries and software components that Frida depends on. It plays a critical role in ensuring that Frida can be built correctly across different platforms and architectures, making it a key piece in the reverse engineering workflow.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/dependencies/base.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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