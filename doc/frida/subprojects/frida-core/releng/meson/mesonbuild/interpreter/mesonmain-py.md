Response:
My thinking process for analyzing the provided Python code and generating the explanation involved these steps:

1. **Understand the Context:** The first thing I did was note the file path: `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/mesonmain.py`. This immediately tells me it's part of the Frida project and specifically relates to the Meson build system's interpreter. The `mesonmain.py` suggests it's a core component within the Meson interpreter.

2. **Identify the Core Class:** I saw the `class MesonMain(MesonInterpreterObject)` declaration. This is the central entity, and its methods are the primary focus of the code. The inheritance from `MesonInterpreterObject` indicates it's deeply integrated with Meson's internal workings.

3. **Scan for Method Definitions:** I then scanned through the `methods.update({...})` call in the `__init__` method. This provided a high-level overview of the functionalities provided by the `MesonMain` class. These method names are descriptive and hint at their purpose (e.g., `add_install_script`, `get_compiler`, `override_dependency`).

4. **Analyze Individual Methods:** For each method identified, I looked at:
    * **Docstrings/Comments:**  While this code doesn't have extensive docstrings, the method names themselves are informative. The SPDX license and copyright information at the top are also noted, though not directly related to functionality.
    * **Arguments and Return Types:** I paid attention to the arguments each method accepts (positional and keyword) and the data types involved. The use of type hints (`T.List`, `str`, `bool`, custom `TypedDict`s like `AddInstallScriptKW`) was very helpful in understanding the expected inputs and outputs.
    * **Logic Within the Method:** I tried to understand the core operation of each method. For instance, `add_install_script_method` clearly deals with adding scripts to the installation process. Methods like `get_compiler_method` retrieve compiler information. Methods starting with `override_` modify build system behavior.
    * **Use of Internal Meson Objects:** I noticed the frequent interaction with `self.build` (an instance of `build.Build`) and `self.interpreter` (an instance of `Interpreter`). This indicates the class's role in manipulating the build definition and accessing interpreter state.
    * **Feature Flags (`@FeatureNew`, `@FeatureDeprecated`):** These decorators are crucial for understanding when features were introduced or deprecated. This is useful for knowing the code's evolution and compatibility.

5. **Relate to Reverse Engineering:**  Based on the identified functionalities, I started thinking about how they could be relevant to reverse engineering, specifically in the context of Frida. The key connections I identified were:
    * **Execution Hooks (via scripts):** The `add_install_script`, `add_postconf_script`, and `add_dist_script` methods allow the execution of custom scripts during various build phases. These scripts could be used for instrumenting or analyzing the target software.
    * **Dependency Overrides:**  `override_dependency_method` and `override_find_program_method` are very relevant. In reverse engineering, you might want to substitute a library or program with a modified version for analysis. Frida uses Meson to build its components, and these overrides could be used to inject custom Frida modules or intercept calls.
    * **Compiler Information:**  `get_compiler_method` provides access to compiler details, which can be useful for understanding how the target software was built and potentially for identifying vulnerabilities or specific compilation flags.
    * **Build Options:** `build_options_method` reveals the build configuration, which can provide insights into the software's intended behavior and security features.
    * **Cross-Compilation (`is_cross_build_method`, property access):**  Frida often targets different architectures. The methods related to cross-compilation and accessing target-specific properties are relevant for building Frida components that run on the target device.

6. **Connect to Binary Underpinnings and System Knowledge:** I considered how the methods relate to lower-level concepts:
    * **Binary Manipulation:**  While this Python code doesn't directly manipulate binaries, the scripts executed by `add_install_script`, etc., *can* be used for binary patching, code injection, or other reverse engineering tasks.
    * **Operating System Interaction:** The methods dealing with environment variables (`add_devenv_method`) and finding programs implicitly interact with the underlying operating system. For Frida, this is crucial for interacting with the target process.
    * **Kernel/Framework Awareness:** When Frida targets Android, the ability to influence the build process (e.g., through dependency overrides) could be used to inject code or modify framework behavior for analysis.

7. **Develop Examples and Scenarios:** To illustrate the concepts, I created concrete examples for each relevant area, such as:
    * Injecting a Frida gadget library using `override_dependency`.
    * Modifying a program path using `override_find_program`.
    * Using install scripts to perform post-build actions relevant to Frida.
    * How build options might affect Frida's functionality.

8. **Identify Potential User Errors:**  I thought about common mistakes developers might make when using these Meson features:
    * Incorrect paths in script arguments.
    * Overriding dependencies or programs with non-existent files.
    * Type mismatches in method arguments.
    * Misunderstanding the scope of overrides.

9. **Trace User Actions:** Finally, I considered how a user's actions could lead to the execution of this specific code. The most direct path is running the `meson` command to configure a build, where Meson parses the `meson.build` files and executes the Python interpreter, which in turn uses `mesonmain.py` to handle the `meson.*` function calls.

10. **Structure and Refine the Explanation:** I organized my findings into logical sections (Functionality, Relationship to Reverse Engineering, Binary/System Aspects, etc.) and used clear language to explain the concepts. I aimed to provide specific examples and connect the code functionality to the broader context of Frida and reverse engineering.

This iterative process of understanding the code's purpose, analyzing its components, connecting it to relevant concepts, and creating illustrative examples allowed me to generate a comprehensive explanation of the `mesonmain.py` file within the Frida project.

This Python code defines the `MesonMain` class, a crucial component within the Meson build system's interpreter, specifically for the Frida dynamic instrumentation tool. It acts as a central point for exposing various build-related functionalities to the Meson build definition files (`meson.build`).

Let's break down its functionalities, connections to reverse engineering, low-level details, logic, potential errors, and user interaction:

**Functionalities of `MesonMain`:**

The `MesonMain` class provides methods (accessible in `meson.build` files as `meson.<method_name>`) to:

* **Manage Scripts:**
    * `add_install_script`: Adds scripts to be executed during the installation phase.
    * `add_postconf_script`: Adds scripts to be executed after the configuration phase.
    * `add_dist_script`: Adds scripts to be executed when creating distribution packages.
* **Access Build Directories:**
    * `current_source_dir`: Gets the source directory of the current `meson.build` file.
    * `current_build_dir`: Gets the build directory of the current `meson.build` file.
    * `project_source_root`: Gets the root source directory of the current project.
    * `project_build_root`: Gets the root build directory of the current project.
    * `global_source_root`: Gets the overall source root directory.
    * `global_build_root`: Gets the overall build root directory.
    * `source_root` (deprecated): Older way to get the source root.
    * `build_root` (deprecated): Older way to get the build root.
* **Get Build Information:**
    * `backend`: Gets the name of the build backend being used (e.g., ninja).
    * `is_cross_build`: Checks if it's a cross-compilation build.
    * `is_unity`: Checks if unity builds are enabled.
    * `is_subproject`: Checks if the current context is within a subproject.
    * `project_version`: Gets the project's version.
    * `project_name`: Gets the project's name.
    * `project_license`: Gets the project's license(s).
    * `project_license_files`: Gets the project's license files.
    * `version`: Gets the Meson version.
    * `build_options`: Gets the build options used for configuration.
* **Manage Dependencies and Programs:**
    * `get_compiler`: Gets a compiler object for a specific language.
    * `override_dependency`: Overrides how a dependency is found.
    * `override_find_program`: Overrides how a program is found.
    * `install_dependency_manifest`: Specifies the name of the dependency manifest file.
* **Handle Execution:**
    * `has_exe_wrapper` (deprecated): Checks if an executable wrapper is needed for cross-compilation.
    * `can_run_host_binaries`: Checks if host binaries can be executed directly (relevant for cross-compilation).
* **Access Cross-Compilation Properties:**
    * `get_cross_property` (deprecated): Gets a property from the cross-compilation file.
    * `get_external_property`: Gets a property for a specific machine (host or build).
    * `has_external_property`: Checks if a specific property exists for a machine.
* **Manage Development Environment:**
    * `add_devenv`: Adds environment variables to the development environment.

**Relationship with Reverse Engineering (Frida Context):**

This file is highly relevant to reverse engineering, especially within the context of Frida:

* **Custom Build Steps and Instrumentation:** The `add_install_script`, `add_postconf_script`, and `add_dist_script` functions are crucial for integrating custom build steps. In Frida's development, these scripts could be used for:
    * **Packaging Frida gadgets:** Scripts can be used to copy or process Frida gadget libraries (`.so` files on Android, `.dylib` on macOS, etc.) into the final package.
    * **Code signing and notarization:** Scripts are often needed to sign binaries for distribution and to notarize them on macOS.
    * **Generating metadata:** Scripts could create files containing information about the build, versions, or included components.
    * **Performing post-build analysis or checks:**  Scripts might be used to run basic tests or checks on the built Frida components.

    **Example:** Imagine a script added using `meson.add_install_script()` that copies the Frida gadget library (`frida-agent.so`) to the correct location within an Android application's APK during the installation process.

* **Dependency Overriding for Injection:** The `override_dependency` and `override_find_program` functions are powerful for controlling how Frida and its components are built:
    * **Injecting custom libraries:** During the build of a target application (or a Frida component that targets a specific application), `override_dependency` could be used to replace a standard library with a modified version that includes Frida's instrumentation hooks.
    * **Substituting tools:** `override_find_program` could be used to replace standard build tools (like `gcc` or `ld`) with custom wrappers that inject Frida-specific compilation flags or link against Frida libraries.

    **Example:** If Frida needs to intercept calls to a specific system library on Android (e.g., `libc.so`), `override_dependency` could be used to replace the standard `libc.so` with a modified version containing Frida's interception logic.

* **Cross-Compilation Setup:** Frida is often used to target different architectures (e.g., building Frida tools on a desktop to instrument an Android application on an ARM device). The functions related to cross-compilation (`is_cross_build`, `get_external_property`) are essential for managing the build process in these scenarios, ensuring that the correct compilers and libraries for the target architecture are used.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This code interacts indirectly with these low-level aspects:

* **Binary Bottom:** The scripts executed by `add_install_script`, etc., can directly manipulate binary files (executables, libraries). They might be used for patching, code injection, or modifying binary headers.
* **Linux and Android Kernel:** When building Frida for Linux or Android, the `get_compiler` function will retrieve the appropriate compiler (e.g., `gcc`, `clang`) that targets the Linux kernel or Android's Bionic libc. Cross-compilation settings managed by functions like `get_external_property` are crucial for targeting these specific environments.
* **Android Framework:**  Building Frida gadgets or components that interact with the Android framework often involves linking against framework libraries. `override_dependency` can be used to control how these framework libraries are linked or to substitute them with instrumented versions. Understanding the Android framework's structure and dependencies is essential for effective Frida development.
* **Executable Wrappers (for Cross-Compilation):** The deprecated `has_exe_wrapper` and the newer `can_run_host_binaries` relate to the need for a wrapper when cross-compiling. If the build machine cannot directly execute binaries for the target architecture, a wrapper (like `qemu`) is needed to run host tools during the build process.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `get_compiler_method`:

* **Hypothetical Input:** In a `meson.build` file, you might have:
  ```python
  cpp_compiler = meson.get_compiler('cpp')
  ```
* **Assumptions:**
    * The project is being configured for a native build (not cross-compiling).
    * A C++ compiler (`cpp`) is configured in Meson's project settings.
* **Logical Reasoning:** The `get_compiler_method` will look up the configured C++ compiler for the native architecture within Meson's internal data structures.
* **Hypothetical Output:** `cpp_compiler` will be an object representing the C++ compiler (e.g., a `GccCompiler` or `ClangCompiler` instance), allowing you to access its properties (like the compiler executable path) and use it in other Meson functions.

**User or Programming Common Usage Errors:**

* **Incorrect Script Paths:**  In `add_install_script`, if the path to the script provided as the first argument is incorrect, the build will fail during the install phase.
  ```python
  # Error: Path is wrong
  meson.add_install_script('scripts/my_install_script.sh', 'some', 'args')
  ```
* **Type Mismatches:** Providing arguments of the wrong type to the methods will lead to errors. For example, expecting a string but providing a number.
  ```python
  # Error: Second argument to get_compiler should be a string
  compiler = meson.get_compiler('cpp', 123)
  ```
* **Overriding Non-Existent Dependencies/Programs:** Using `override_dependency` or `override_find_program` with names that don't correspond to actual dependencies or programs will result in build failures or unexpected behavior.
  ```python
  # Error: 'non_existent_lib' is not a known dependency
  meson.override_dependency('non_existent_lib', my_custom_lib)
  ```
* **Incorrect `native:` Keyword Argument:** When using functions like `get_compiler` or `get_external_property` in a cross-compilation scenario, failing to specify the correct `native:` keyword argument (e.g., `native: 'host'` or `native: 'build'`) can lead to accessing properties or compilers for the wrong architecture.

**User Operation Flow to Reach This Code (Debugging Clue):**

1. **User writes `meson.build` files:** Developers create `meson.build` files that define the project's structure, dependencies, build targets, and custom build steps. These files contain calls to `meson.*` methods.
2. **User runs `meson setup <build_directory>`:** This command initiates the Meson configuration process.
3. **Meson parses `meson.build`:** Meson reads and parses the `meson.build` files.
4. **Meson's interpreter is invoked:** The Meson interpreter (which includes `mesonmain.py`) is used to execute the Python code in the `meson.build` files.
5. **`MesonMain` is instantiated:** An instance of the `MesonMain` class is created within the interpreter.
6. **`meson.*` method calls are resolved:** When the interpreter encounters a call like `meson.add_install_script(...)`, it looks up the corresponding method in the `MesonMain` instance.
7. **The corresponding method in `mesonmain.py` is executed:** The Python code within the relevant method (e.g., `add_install_script_method`) is executed, interacting with Meson's internal data structures and build definitions.

**As a debugging clue:** If a user reports an issue related to a `meson.*` function, tracing the execution flow will likely lead to the corresponding method within `mesonmain.py`. Examining the arguments passed to the method and the internal state of the `MesonMain` object can help pinpoint the source of the problem. For example, if an install script isn't being executed, debugging might involve inspecting the `self.build.install_scripts` list in the `add_install_script_method` to ensure the script was added correctly.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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