Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:** The core request is to understand the *functionality* of this specific Python file within the Frida project. This means identifying what the code *does*. The prompt also specifically asks about its relation to reverse engineering, low-level systems, logical reasoning, common user errors, and debugging.

**2. Initial Scan and Identification of Key Components:**

* **File Path:**  `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/mesonmain.py`  This immediately tells us it's part of the Frida project, specifically within the QML (Qt Meta Language) related components, and further within the Meson build system integration. The `interpreter` directory suggests it plays a role in interpreting Meson build files.
* **Imports:** The imports provide clues about the modules and functionalities used:
    * `mesonlib`:  Likely utility functions and data structures specific to Meson.
    * `dependencies`:  Deals with managing external dependencies.
    * `build`: Represents the build system's internal state and objects (targets, executables, etc.).
    * `mlog`: Meson's logging system.
    * `coredata`: Core Meson configuration data.
    * `MachineChoice`, `OptionKey`:  Concepts related to cross-compilation and build options.
    * `OverrideProgram`, `ExternalProgram`: Representing external programs used in the build.
    * `interpreter.type_checking`: Hints at type checking within the Meson interpreter.
    * `interpreterbase`: Base classes and utilities for the Meson interpreter.
    * `primitives`: Basic data types used in Meson.
    * `typing`, `typing_extensions`: For static type hinting.
* **Class `MesonMain`:** This is the central focus. The name strongly suggests it's the main entry point or a core component for handling Meson-specific logic.
* **`__init__` method:** This initializes the `MesonMain` object, linking it to a `build.Build` and an `Interpreter` instance. This reinforces the idea that `MesonMain` acts as an intermediary between the build state and the interpretation process.
* **`self.methods` dictionary:**  This is crucial. It maps string names (like `'add_install_script'`) to methods of the `MesonMain` class. This is a clear indicator of the *actions* this class can perform.

**3. Deeper Dive into Key Methods (and Relating to the Prompts):**

* **Methods related to scripts (`add_install_script`, `add_postconf_script`, `add_dist_script`):** These methods deal with running external scripts during different phases of the build process. This immediately connects to **reverse engineering** (you might run scripts to manipulate binaries or extract information) and potentially **low-level systems** (if the scripts interact directly with the operating system or target environment). The method logic shows it handles different types of arguments (strings, files, build targets, executables) and prepares them for execution.
* **Methods for getting build information (`current_source_dir`, `current_build_dir`, `project_version`, etc.):** These provide access to the build environment's state. While not directly reverse engineering, this information is vital for build processes that might *involve* reverse engineering tools or steps.
* **Methods for compiler and dependency management (`get_compiler`, `override_dependency`, `override_find_program`):**  These relate to how the build system finds and uses compilers and libraries. `override_dependency` is particularly interesting as it allows forcing the use of specific dependency versions, which could be relevant in a reverse engineering context if you need to link against specific library versions for compatibility.
* **`can_run_host_binaries`:** This is directly related to **cross-compilation**. Frida often targets different architectures, making cross-compilation a key concept. This method determines if the build system can execute programs built for the host machine (where the build is happening) on the target machine. This is important for running build-time tools.
* **`add_devenv`:** This allows manipulating environment variables during the build. This can be crucial for setting up the correct environment for cross-compilation or for tools used in reverse engineering.

**4. Connecting to Specific Prompt Points:**

* **Reverse Engineering:**  The script-related methods are the most direct link. Imagine a post-processing step that uses a script to disassemble a binary or extract symbols. The `add_install_script` or `add_postconf_script` could be used to integrate this into the build process.
* **Binary/Low-Level, Linux/Android Kernel/Framework:**
    * **Binary:**  Scripts executed by these methods could certainly interact with binaries (e.g., patching, analyzing).
    * **Linux/Android Kernel/Framework:** While this file itself doesn't directly touch the kernel, Frida *does*. The build system managed by this code is used to build Frida components that *will* interact with these systems. Cross-compilation aspects are relevant here.
* **Logical Reasoning (Hypothetical Input/Output):**  Consider `override_dependency('mylib', my_custom_lib)`. The *input* is the name "mylib" and a `dependencies.Dependency` object `my_custom_lib`. The *output* is the build system now using `my_custom_lib` whenever a dependency on "mylib" is encountered.
* **User/Programming Errors:**
    * Trying to override a dependency or program with a non-existent file (handled by checks in `override_find_program_method`).
    * Providing incorrect arguments to methods (the type hinting and argument parsing help prevent this, but users can still make mistakes).
    * Incorrectly specifying native/host machine for cross-compilation.
* **Debugging:** The file itself is part of the Meson build system. If a build using Frida fails, and the error points to issues with how dependencies or scripts are handled, then understanding this file becomes a crucial part of the debugging process. You might trace the execution of these methods to understand why a particular dependency isn't being found or why a script isn't running correctly.

**5. Structuring the Answer:**

Start with a high-level summary of the file's purpose. Then, systematically go through the key functionalities, explaining what each method does and how it relates to the prompt's specific points (reverse engineering, low-level, etc.). Use concrete examples where possible to illustrate the concepts. Finally, discuss potential user errors and how one might arrive at this file during debugging.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  This file just manages scripts. **Correction:**  While scripts are a significant part, it also handles dependencies, compiler selection, and provides access to build environment information.
* **Initial thought:**  The low-level connection is weak. **Refinement:** Realize that while *this specific file* doesn't manipulate bits, it's part of the *build process* for Frida, which *does* deal with low-level system interaction. The cross-compilation aspect also strengthens this link.
* **Over-reliance on code details:**  Avoid simply reciting code. Focus on explaining the *purpose* and *implications* of the code.
This Python code file, `mesonmain.py`, is a core component of the Meson build system, specifically within the context of a Frida project. It defines the `MesonMain` class, which acts as a bridge between the Meson build system's internal representation and the build logic defined in `meson.build` files. Think of it as providing a set of built-in functions and methods that `meson.build` files can call to interact with the build environment.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Providing Built-in Methods for `meson.build`:** The `MesonMain` class exposes various methods (listed in the `self.methods` dictionary) that can be called from `meson.build` files using the `meson` namespace (e.g., `meson.add_install_script()`, `meson.project_version()`).

2. **Managing Build Scripts:**
   - `add_install_script()`: Registers scripts to be executed during the installation phase of the build.
   - `add_postconf_script()`: Registers scripts to be executed after the configuration phase.
   - `add_dist_script()`: Registers scripts to be executed when creating distribution packages.

3. **Providing Information about the Build Environment:**
   - `current_source_dir()`, `current_build_dir()`:  Return the paths to the current source and build directories.
   - `project_source_root()`, `project_build_root()`, `global_source_root()`, `global_build_root()`: Return the root directories for the project and the overall build.
   - `backend()`: Returns the name of the backend being used (e.g., ninja).
   - `is_cross_build()`: Indicates if a cross-compilation build is being performed.
   - `is_subproject()`: Indicates if the current build is part of a subproject.
   - `project_name()`, `project_version()`, `project_license()`, `project_license_files()`:  Provide access to project metadata defined in the `project()` call in `meson.build`.
   - `version()`: Returns the version of Meson being used.
   - `build_options()`: Returns the command-line options used for the build.

4. **Compiler and Dependency Management:**
   - `get_compiler()`: Retrieves a compiler object for a specific language.
   - `override_dependency()`: Allows overriding the default behavior of finding a dependency with a specific dependency object.
   - `override_find_program()`: Allows overriding the default behavior of finding a program with a specific executable.
   - `install_dependency_manifest()`:  Specifies the name of the dependency manifest file.

5. **Cross-Compilation Support:**
   - `can_run_host_binaries()`: Checks if the host machine can execute binaries built for the target machine in a cross-compilation scenario.
   - `get_cross_property()` (deprecated), `get_external_property()`:  Retrieve properties defined in the cross-compilation configuration file.
   - `has_external_property()`: Checks if a specific property exists in the cross-compilation configuration.

6. **Environment Variable Management:**
   - `add_devenv()`: Allows adding or modifying environment variables that will be set when executing build commands.

7. **Unity Builds:**
   - `is_unity()`:  Indicates if unity builds are enabled.

**Relationship to Reverse Engineering:**

This file, as part of the build system, indirectly relates to reverse engineering in several ways when building tools like Frida:

* **Building Frida Itself:**  Frida is a dynamic instrumentation toolkit often used for reverse engineering. This `mesonmain.py` file is essential for building Frida from its source code. The build process might involve compiling native code, linking libraries, and potentially running scripts that perform pre-processing or code generation steps relevant to instrumentation.
* **Custom Build Steps for Frida Modules:** Developers building custom modules or extensions for Frida might use the scripting capabilities exposed by `mesonmain.py` (like `add_install_script`) to automate tasks related to packaging, deployment, or even basic analysis of target binaries during the build process. For example, a script could be used to extract symbols from a library or perform basic checks on the target application.
* **Cross-Compilation for Target Devices:** Frida often targets mobile platforms like Android and iOS. The cross-compilation features exposed by `mesonmain.py` (like `is_cross_build()`, `get_external_property()`) are crucial for building Frida components that run on these different architectures. Reverse engineering often involves analyzing software on different target platforms, making robust cross-compilation support essential.
* **Dependency Management for Frida:**  Frida relies on various libraries and dependencies. `mesonmain.py`'s functions for managing dependencies (`override_dependency()`) ensure that the correct versions of libraries are used during the build process. In a reverse engineering context, controlling library versions can be important for reproducing specific behaviors or analyzing vulnerabilities.

**Example of Reverse Engineering Relation:**

Let's imagine a scenario where a Frida module needs to be built that interacts with a specific version of the `libc` library on an Android device. The `meson.build` file for this module might use `meson.add_install_script()` to copy the necessary `libc.so` to a staging directory during the build. This script, registered via `mesonmain.py`, becomes a part of the build process that facilitates the reverse engineering task by ensuring the correct library is available.

**Binary Underpinnings, Linux, Android Kernel & Framework:**

* **Binary Underpinnings:**  While `mesonmain.py` is a Python script, it orchestrates the compilation and linking of binary code. Methods like `get_compiler()` retrieve compiler objects that are responsible for translating source code into machine code. The output of the build process managed by this file is ultimately binary executables and libraries.
* **Linux:** Meson is a popular build system on Linux. Many of the functionalities assume a Linux-like environment for executing commands and managing files.
* **Android Kernel & Framework:**  Building Frida for Android inherently involves knowledge of the Android kernel and framework. The cross-compilation settings managed through `get_external_property()` and related methods will define how the build system interacts with the Android NDK (Native Development Kit), which provides headers and libraries for interacting with the Android system at a lower level. For example, the cross-compilation configuration would specify the target architecture (ARM, ARM64), the sysroot (location of the Android system libraries), and the compiler toolchain.

**Example of Linux/Android Kernel & Framework Relation:**

The `get_compiler()` method, when used in a Frida Android build, will retrieve a compiler (likely from the Android NDK) configured to target the specific Android architecture. This compiler will then be used to compile the C/C++ code of Frida or its modules, which will eventually interact with the Android kernel and framework APIs. The `get_external_property()` method might be used to retrieve the path to the Android SDK or NDK, which are essential for building Android applications and libraries.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `override_dependency()` method:

* **Hypothetical Input:**
    * In a `meson.build` file: `meson.override_dependency('glib-2.0', my_custom_glib)`
    * Where `my_custom_glib` is a `dependencies.Dependency` object representing a specific version or build of the `glib-2.0` library.
* **Logical Process:**  When the Meson interpreter processes this line, the `override_dependency_method` in `mesonmain.py` is called. It stores this override information in the build state.
* **Hypothetical Output:**  Subsequent calls to `dependency('glib-2.0')` within the same `meson.build` file (or other files within the same Meson project) will now return the `my_custom_glib` dependency object instead of the default one found by Meson's dependency resolution mechanisms.

**User or Programming Common Usage Errors:**

* **Incorrect Argument Types:** Calling a method with the wrong type of argument. For example, passing an integer to `add_install_script()` where a string (path to the script) is expected. Meson's type checking (evident from the `@typed_pos_args` and `@typed_kwargs` decorators) helps to catch these errors during the configuration phase.
* **Typos in Method Names:**  Calling a non-existent method of the `meson` object. This will result in an error during the Meson configuration.
* **Incorrect File Paths:** Providing an invalid or non-existent path to a script in methods like `add_install_script()`. Meson might not immediately catch this, but the script execution will fail during the build or install phase.
* **Overriding Dependencies Incorrectly:**  Using `override_dependency()` without understanding the implications. For instance, overriding a critical system library with an incompatible version can lead to build failures or runtime issues.
* **Cross-Compilation Misconfiguration:**  Providing incorrect or incomplete information in the cross-compilation configuration file, leading to the `get_external_property()` method returning incorrect values or causing build errors.

**Example of a User Error:**

A user might try to add an install script but provide the script name without the full path:

```python
# In meson.build
meson.add_install_script('my_install_script.sh')
```

If `my_install_script.sh` is not in the current source directory or any of the default search paths, Meson will likely fail to find the script during the install phase, leading to an error.

**User Operations Leading to This File (Debugging Scenario):**

1. **A Frida developer modifies the `meson.build` file in a Frida subproject (like `frida-qml`).** This modification might involve adding a new install script, overriding a dependency, or changing build options.
2. **The developer runs the Meson configuration command:** `meson setup builddir`.
3. **Meson parses the `meson.build` file.** When it encounters calls to functions like `meson.add_install_script()`, `meson.override_dependency()`, etc., the corresponding methods in the `MesonMain` class within `mesonmain.py` are executed.
4. **If an error occurs during the configuration phase**, such as a typo in a method name or an incorrect argument type, the Meson error message might point to the line in the `meson.build` file where the error occurred.
5. **To debug this**, the developer might need to understand how Meson interprets these calls. This leads them to examine the source code of `mesonmain.py` to see the implementation of the methods being called. They might set breakpoints in this file (if debugging the Meson setup process itself) or simply read the code to understand the logic and identify potential issues in their `meson.build` file.

In essence, `mesonmain.py` is a fundamental part of the Meson build system's internal workings, especially for projects like Frida that leverage Meson's features for complex build processes, cross-compilation, and custom scripting. Understanding its functions is crucial for anyone developing or debugging the build system of such projects.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2021 The Meson development team
# Copyright © 2021-2024 Intel Corporation
from __future__ import annotations

import copy
import os
import typing as T

from .. import mesonlib
from .. import dependencies
from .. import build
from .. import mlog, coredata

from ..mesonlib import MachineChoice, OptionKey
from ..programs import OverrideProgram, ExternalProgram
from ..interpreter.type_checking import ENV_KW, ENV_METHOD_KW, ENV_SEPARATOR_KW, env_convertor_with_method
from ..interpreterbase import (MesonInterpreterObject, FeatureNew, FeatureDeprecated,
                               typed_pos_args,  noArgsFlattening, noPosargs, noKwargs,
                               typed_kwargs, KwargInfo, InterpreterException)
from .primitives import MesonVersionString
from .type_checking import NATIVE_KW, NoneType

if T.TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    from ..compilers import Compiler
    from ..interpreterbase import TYPE_kwargs, TYPE_var
    from ..mesonlib import ExecutableSerialisation
    from .interpreter import Interpreter

    class FuncOverrideDependency(TypedDict):

        native: mesonlib.MachineChoice
        static: T.Optional[bool]

    class AddInstallScriptKW(TypedDict):

        skip_if_destdir: bool
        install_tag: str
        dry_run: bool

    class NativeKW(TypedDict):

        native: mesonlib.MachineChoice

    class AddDevenvKW(TypedDict):
        method: Literal['set', 'prepend', 'append']
        separator: str


class MesonMain(MesonInterpreterObject):
    def __init__(self, build: 'build.Build', interpreter: 'Interpreter'):
        super().__init__(subproject=interpreter.subproject)
        self.build = build
        self.interpreter = interpreter
        self.methods.update({'add_devenv': self.add_devenv_method,
                             'add_dist_script': self.add_dist_script_method,
                             'add_install_script': self.add_install_script_method,
                             'add_postconf_script': self.add_postconf_script_method,
                             'backend': self.backend_method,
                             'build_options': self.build_options_method,
                             'build_root': self.build_root_method,
                             'can_run_host_binaries': self.can_run_host_binaries_method,
                             'current_source_dir': self.current_source_dir_method,
                             'current_build_dir': self.current_build_dir_method,
                             'get_compiler': self.get_compiler_method,
                             'get_cross_property': self.get_cross_property_method,
                             'get_external_property': self.get_external_property_method,
                             'global_build_root': self.global_build_root_method,
                             'global_source_root': self.global_source_root_method,
                             'has_exe_wrapper': self.has_exe_wrapper_method,
                             'has_external_property': self.has_external_property_method,
                             'install_dependency_manifest': self.install_dependency_manifest_method,
                             'is_cross_build': self.is_cross_build_method,
                             'is_subproject': self.is_subproject_method,
                             'is_unity': self.is_unity_method,
                             'override_dependency': self.override_dependency_method,
                             'override_find_program': self.override_find_program_method,
                             'project_build_root': self.project_build_root_method,
                             'project_license': self.project_license_method,
                             'project_license_files': self.project_license_files_method,
                             'project_name': self.project_name_method,
                             'project_source_root': self.project_source_root_method,
                             'project_version': self.project_version_method,
                             'source_root': self.source_root_method,
                             'version': self.version_method,
                             })

    def _find_source_script(
            self, name: str, prog: T.Union[str, mesonlib.File, build.Executable, ExternalProgram],
            args: T.List[str]) -> 'ExecutableSerialisation':
        largs: T.List[T.Union[str, build.Executable, ExternalProgram]] = []

        if isinstance(prog, (build.Executable, ExternalProgram)):
            FeatureNew.single_use(f'Passing executable/found program object to script parameter of {name}',
                                  '0.55.0', self.subproject, location=self.current_node)
            largs.append(prog)
        else:
            if isinstance(prog, mesonlib.File):
                FeatureNew.single_use(f'Passing file object to script parameter of {name}',
                                      '0.57.0', self.subproject, location=self.current_node)
            found = self.interpreter.find_program_impl([prog])
            largs.append(found)

        largs.extend(args)
        es = self.interpreter.backend.get_executable_serialisation(largs, verbose=True)
        es.subproject = self.interpreter.subproject
        return es

    def _process_script_args(
            self, name: str, args: T.Sequence[T.Union[
                str, mesonlib.File, build.BuildTarget, build.CustomTarget,
                build.CustomTargetIndex,
                ExternalProgram,
            ]]) -> T.List[str]:
        script_args = []  # T.List[str]
        new = False
        for a in args:
            if isinstance(a, str):
                script_args.append(a)
            elif isinstance(a, mesonlib.File):
                new = True
                script_args.append(a.rel_to_builddir(self.interpreter.environment.source_dir))
            elif isinstance(a, (build.BuildTarget, build.CustomTarget, build.CustomTargetIndex)):
                new = True
                script_args.extend([os.path.join(a.get_source_subdir(), o) for o in a.get_outputs()])

                # This feels really hacky, but I'm not sure how else to fix
                # this without completely rewriting install script handling.
                # This is complicated by the fact that the install target
                # depends on all.
                if isinstance(a, build.CustomTargetIndex):
                    a.target.build_by_default = True
                else:
                    a.build_by_default = True
            else:
                script_args.extend(a.command)
                new = True

        if new:
            FeatureNew.single_use(
                f'Calling "{name}" with File, CustomTarget, Index of CustomTarget, '
                'Executable, or ExternalProgram',
                '0.55.0', self.interpreter.subproject, location=self.current_node)
        return script_args

    @typed_pos_args(
        'meson.add_install_script',
        (str, mesonlib.File, build.Executable, ExternalProgram),
        varargs=(str, mesonlib.File, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram)
    )
    @typed_kwargs(
        'meson.add_install_script',
        KwargInfo('skip_if_destdir', bool, default=False, since='0.57.0'),
        KwargInfo('install_tag', (str, NoneType), since='0.60.0'),
        KwargInfo('dry_run', bool, default=False, since='1.1.0'),
    )
    def add_install_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, build.Executable, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram]]],
            kwargs: 'AddInstallScriptKW') -> None:
        script_args = self._process_script_args('add_install_script', args[1])
        script = self._find_source_script('add_install_script', args[0], script_args)
        script.skip_if_destdir = kwargs['skip_if_destdir']
        script.tag = kwargs['install_tag']
        script.dry_run = kwargs['dry_run']
        self.build.install_scripts.append(script)

    @typed_pos_args(
        'meson.add_postconf_script',
        (str, mesonlib.File, ExternalProgram),
        varargs=(str, mesonlib.File, ExternalProgram)
    )
    @noKwargs
    def add_postconf_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, ExternalProgram]]],
            kwargs: 'TYPE_kwargs') -> None:
        script_args = self._process_script_args('add_postconf_script', args[1])
        script = self._find_source_script('add_postconf_script', args[0], script_args)
        self.build.postconf_scripts.append(script)

    @typed_pos_args(
        'meson.add_dist_script',
        (str, mesonlib.File, ExternalProgram),
        varargs=(str, mesonlib.File, ExternalProgram)
    )
    @noKwargs
    @FeatureNew('meson.add_dist_script', '0.48.0')
    def add_dist_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, ExternalProgram]]],
            kwargs: 'TYPE_kwargs') -> None:
        if args[1]:
            FeatureNew.single_use('Calling "add_dist_script" with multiple arguments',
                                  '0.49.0', self.interpreter.subproject, location=self.current_node)
        if self.interpreter.subproject != '':
            FeatureNew.single_use('Calling "add_dist_script" in a subproject',
                                  '0.58.0', self.interpreter.subproject, location=self.current_node)
        script_args = self._process_script_args('add_dist_script', args[1])
        script = self._find_source_script('add_dist_script', args[0], script_args)
        self.build.dist_scripts.append(script)

    @noPosargs
    @noKwargs
    def current_source_dir_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.source_dir
        sub = self.interpreter.subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    def current_build_dir_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        sub = self.interpreter.subdir
        if sub == '':
            return self.interpreter.environment.build_dir
        return self.interpreter.absolute_builddir_path_for(sub)

    @noPosargs
    @noKwargs
    def backend_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.backend.name

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.source_root', '0.56.0', 'use meson.project_source_root() or meson.global_source_root() instead.')
    def source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.source_dir

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.build_root', '0.56.0', 'use meson.project_build_root() or meson.global_build_root() instead.')
    def build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.build_dir

    @noPosargs
    @noKwargs
    @FeatureNew('meson.project_source_root', '0.56.0')
    def project_source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.source_dir
        sub = self.interpreter.root_subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.project_build_root', '0.56.0')
    def project_build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.build_dir
        sub = self.interpreter.root_subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.global_source_root', '0.58.0')
    def global_source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.source_dir

    @noPosargs
    @noKwargs
    @FeatureNew('meson.global_build_root', '0.58.0')
    def global_build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.build_dir

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.has_exe_wrapper', '0.55.0', 'use meson.can_run_host_binaries instead.')
    def has_exe_wrapper_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self._can_run_host_binaries_impl()

    @noPosargs
    @noKwargs
    @FeatureNew('meson.can_run_host_binaries', '0.55.0')
    def can_run_host_binaries_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self._can_run_host_binaries_impl()

    def _can_run_host_binaries_impl(self) -> bool:
        return not (
            self.build.environment.is_cross_build() and
            self.build.environment.need_exe_wrapper() and
            self.build.environment.exe_wrapper is None
        )

    @noPosargs
    @noKwargs
    def is_cross_build_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.build.environment.is_cross_build()

    @typed_pos_args('meson.get_compiler', str)
    @typed_kwargs('meson.get_compiler', NATIVE_KW)
    def get_compiler_method(self, args: T.Tuple[str], kwargs: 'NativeKW') -> 'Compiler':
        cname = args[0]
        for_machine = kwargs['native']
        clist = self.interpreter.coredata.compilers[for_machine]
        try:
            return clist[cname]
        except KeyError:
            raise InterpreterException(f'Tried to access compiler for language "{cname}", not specified for {for_machine.get_lower_case_name()} machine.')

    @noPosargs
    @noKwargs
    def is_unity_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        optval = self.interpreter.environment.coredata.get_option(OptionKey('unity'))
        return optval == 'on' or (optval == 'subprojects' and self.interpreter.is_subproject())

    @noPosargs
    @noKwargs
    def is_subproject_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.interpreter.is_subproject()

    @typed_pos_args('meson.install_dependency_manifest', str)
    @noKwargs
    def install_dependency_manifest_method(self, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> None:
        self.build.dep_manifest_name = args[0]

    @FeatureNew('meson.override_find_program', '0.46.0')
    @typed_pos_args('meson.override_find_program', str, (mesonlib.File, ExternalProgram, build.Executable))
    @typed_kwargs('meson.override_find_program', NATIVE_KW.evolve(since='1.3.0'))
    def override_find_program_method(self, args: T.Tuple[str, T.Union[mesonlib.File, ExternalProgram, build.Executable]], kwargs: NativeKW) -> None:
        name, exe = args
        if isinstance(exe, mesonlib.File):
            abspath = exe.absolute_path(self.interpreter.environment.source_dir,
                                        self.interpreter.environment.build_dir)
            if not os.path.exists(abspath):
                raise InterpreterException(f'Tried to override {name} with a file that does not exist.')
            exe = OverrideProgram(name, [abspath])
        self.interpreter.add_find_program_override(name, exe, kwargs['native'])

    @typed_kwargs(
        'meson.override_dependency',
        NATIVE_KW,
        KwargInfo('static', (bool, NoneType), since='0.60.0'),
    )
    @typed_pos_args('meson.override_dependency', str, dependencies.Dependency)
    @FeatureNew('meson.override_dependency', '0.54.0')
    def override_dependency_method(self, args: T.Tuple[str, dependencies.Dependency], kwargs: 'FuncOverrideDependency') -> None:
        name, dep = args
        if not name:
            raise InterpreterException('First argument must be a string and cannot be empty')

        # Make a copy since we're going to mutate.
        #
        #   dep = declare_dependency()
        #   meson.override_dependency('foo', dep)
        #   meson.override_dependency('foo-1.0', dep)
        #   dep = dependency('foo')
        #   dep.name() # == 'foo-1.0'
        dep = copy.copy(dep)
        dep.name = name

        optkey = OptionKey('default_library', subproject=self.interpreter.subproject)
        default_library = self.interpreter.coredata.get_option(optkey)
        assert isinstance(default_library, str), 'for mypy'
        static = kwargs['static']
        if static is None:
            # We don't know if dep represents a static or shared library, could
            # be a mix of both. We assume it is following default_library
            # value.
            self._override_dependency_impl(name, dep, kwargs, static=None)
            if default_library == 'static':
                self._override_dependency_impl(name, dep, kwargs, static=True)
            elif default_library == 'shared':
                self._override_dependency_impl(name, dep, kwargs, static=False)
            else:
                self._override_dependency_impl(name, dep, kwargs, static=True)
                self._override_dependency_impl(name, dep, kwargs, static=False)
        else:
            # dependency('foo') without specifying static kwarg should find this
            # override regardless of the static value here. But do not raise error
            # if it has already been overridden, which would happen when overriding
            # static and shared separately:
            # meson.override_dependency('foo', shared_dep, static: false)
            # meson.override_dependency('foo', static_dep, static: true)
            # In that case dependency('foo') would return the first override.
            self._override_dependency_impl(name, dep, kwargs, static=None, permissive=True)
            self._override_dependency_impl(name, dep, kwargs, static=static)

    def _override_dependency_impl(self, name: str, dep: dependencies.Dependency, kwargs: 'FuncOverrideDependency',
                                  static: T.Optional[bool], permissive: bool = False) -> None:
        # We need the cast here as get_dep_identifier works on such a dict,
        # which FuncOverrideDependency is, but mypy can't figure that out
        nkwargs = T.cast('T.Dict[str, T.Any]', kwargs.copy())
        if static is None:
            del nkwargs['static']
        else:
            nkwargs['static'] = static
        identifier = dependencies.get_dep_identifier(name, nkwargs)
        for_machine = kwargs['native']
        override = self.build.dependency_overrides[for_machine].get(identifier)
        if override:
            if permissive:
                return
            m = 'Tried to override dependency {!r} which has already been resolved or overridden at {}'
            location = mlog.get_error_location_string(override.node.filename, override.node.lineno)
            raise InterpreterException(m.format(name, location))
        self.build.dependency_overrides[for_machine][identifier] = \
            build.DependencyOverride(dep, self.interpreter.current_node)

    @noPosargs
    @noKwargs
    def project_version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.build.dep_manifest[self.interpreter.active_projectname].version

    @FeatureNew('meson.project_license()', '0.45.0')
    @noPosargs
    @noKwargs
    def project_license_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> T.List[str]:
        return self.build.dep_manifest[self.interpreter.active_projectname].license

    @FeatureNew('meson.project_license_files()', '1.1.0')
    @noPosargs
    @noKwargs
    def project_license_files_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.List[mesonlib.File]:
        return [l[1] for l in self.build.dep_manifest[self.interpreter.active_projectname].license_files]

    @noPosargs
    @noKwargs
    def version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> MesonVersionString:
        return MesonVersionString(self.interpreter.coredata.version)

    @noPosargs
    @noKwargs
    def project_name_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.active_projectname

    def __get_external_property_impl(self, propname: str, fallback: T.Optional[object], machine: MachineChoice) -> object:
        """Shared implementation for get_cross_property and get_external_property."""
        try:
            return self.interpreter.environment.properties[machine][propname]
        except KeyError:
            if fallback is not None:
                return fallback
            raise InterpreterException(f'Unknown property for {machine.get_lower_case_name()} machine: {propname}')

    @noArgsFlattening
    @FeatureDeprecated('meson.get_cross_property', '0.58.0', 'Use meson.get_external_property() instead')
    @typed_pos_args('meson.get_cross_property', str, optargs=[object])
    @noKwargs
    def get_cross_property_method(self, args: T.Tuple[str, T.Optional[object]], kwargs: 'TYPE_kwargs') -> object:
        propname, fallback = args
        return self.__get_external_property_impl(propname, fallback, MachineChoice.HOST)

    @noArgsFlattening
    @FeatureNew('meson.get_external_property', '0.54.0')
    @typed_pos_args('meson.get_external_property', str, optargs=[object])
    @typed_kwargs('meson.get_external_property', NATIVE_KW)
    def get_external_property_method(self, args: T.Tuple[str, T.Optional[object]], kwargs: 'NativeKW') -> object:
        propname, fallback = args
        return self.__get_external_property_impl(propname, fallback, kwargs['native'])

    @FeatureNew('meson.has_external_property', '0.58.0')
    @typed_pos_args('meson.has_external_property', str)
    @typed_kwargs('meson.has_external_property', NATIVE_KW)
    def has_external_property_method(self, args: T.Tuple[str], kwargs: 'NativeKW') -> bool:
        prop_name = args[0]
        return prop_name in self.interpreter.environment.properties[kwargs['native']]

    @FeatureNew('add_devenv', '0.58.0')
    @typed_kwargs('environment', ENV_METHOD_KW, ENV_SEPARATOR_KW.evolve(since='0.62.0'))
    @typed_pos_args('add_devenv', (str, list, dict, mesonlib.EnvironmentVariables))
    def add_devenv_method(self, args: T.Tuple[T.Union[str, list, dict, mesonlib.EnvironmentVariables]],
                          kwargs: 'AddDevenvKW') -> None:
        env = args[0]
        msg = ENV_KW.validator(env)
        if msg:
            raise build.InvalidArguments(f'"add_devenv": {msg}')
        converted = env_convertor_with_method(env, kwargs['method'], kwargs['separator'])
        assert isinstance(converted, mesonlib.EnvironmentVariables)
        self.build.devenv.append(converted)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.build_options', '1.1.0')
    def build_options_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        options = self.interpreter.user_defined_options
        if options is None:
            return ''
        return coredata.format_cmd_line_options(options)
```