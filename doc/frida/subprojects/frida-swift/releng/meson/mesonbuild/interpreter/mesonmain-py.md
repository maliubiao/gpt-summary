Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Core Request:**

The user wants a functional breakdown of the provided Python code (`mesonmain.py`) within the context of the Frida dynamic instrumentation tool. Key aspects to cover include its relationship to reverse engineering, low-level details (OS, kernel, frameworks), logical reasoning, common user errors, and the path leading to this code.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to get a general idea of its purpose. Keywords like "meson," "build," "interpreter," "script," "dependency," "compiler," "environment," and function names like `add_install_script`, `get_compiler`, `override_dependency` stand out. This immediately suggests the code is part of a build system (Meson) and handles various aspects of project configuration, dependency management, and execution of scripts.

**3. Identifying Key Classes and Their Roles:**

The class `MesonMain` is central. Its `__init__` method and the `self.methods.update(...)` dictionary reveal the core functionality it exposes. The code interacts with `build.Build` and `interpreter.Interpreter` objects, suggesting this class acts as an interface between the build system's internal state and the Meson language interpreter.

**4. Analyzing Individual Methods and Their Functionality:**

Now, we need to go through each method within `MesonMain` and understand what it does. For each method, consider:

* **Purpose:** What problem does this method solve?
* **Inputs:** What arguments does it take?  Pay attention to type hints.
* **Outputs:** What does it return or what side effects does it have?
* **Relevance to the Overall System:** How does this method contribute to the larger build process?
* **Keywords/Concepts:** Are there any specific terms or concepts associated with this method (e.g., "dependency," "compiler," "install script")?

**5. Connecting to Reverse Engineering (Instruction #2):**

This requires bridging the gap between the generic build system and the specific context of Frida. Frida is about dynamic instrumentation, which often involves manipulating running processes. Look for methods that might be relevant to preparing or executing code that interacts with a target process:

* `add_install_script`, `add_postconf_script`, `add_dist_script`: These methods execute scripts. These scripts *could* be used for post-processing, packaging, or even preparing Frida gadgets or agents.
* `override_dependency`, `override_find_program`: These allow replacing default dependencies or programs, which could be useful for injecting custom libraries or tools into the Frida build process.
* `get_compiler`: Knowing the compiler is essential for building Frida components.

**6. Identifying Low-Level and System-Related Aspects (Instruction #3):**

Focus on methods that interact with the underlying operating system, build environment, or concepts related to compilation and linking:

* `get_compiler`: Compilers are very low-level.
* `is_cross_build`: Cross-compilation is a key concept in embedded systems and mobile development (like Android, a target for Frida).
* `add_devenv`: Setting environment variables is fundamental to process execution and can influence how Frida behaves.
* `can_run_host_binaries`: This is relevant for cross-compilation scenarios where build tools might need to be executed on the host machine.

**7. Deriving Logical Reasoning and Examples (Instruction #4):**

For methods that involve decision-making or processing data, construct hypothetical input and output scenarios:

* `current_source_dir`, `current_build_dir`: Given a `subdir`, what are the expected paths?
* `is_unity`: Based on the `unity` option, what's the boolean output?
* `override_dependency`:  If a dependency is overridden, what happens when a later attempt to use that dependency occurs?

**8. Identifying Common User Errors (Instruction #5):**

Think about the types of mistakes a user might make when using these methods in a Meson build file:

* Incorrect argument types to functions.
* Providing non-existent file paths for scripts.
* Overriding dependencies incorrectly (e.g., trying to override a dependency that has already been resolved).
* Using deprecated functions.

**9. Tracing User Operations (Instruction #6):**

Imagine a developer using Frida and wanting to leverage this `mesonmain.py` code. How would they end up triggering the execution of these methods?

* They would be writing a `meson.build` file.
* Within that file, they would call functions exposed by `MesonMain`, like `meson.add_install_script()`, `meson.override_dependency()`, etc.
* The Meson build system would parse this `meson.build` file and invoke the corresponding Python methods in `mesonmain.py`.
* Debugging might involve examining the Meson log output or using a debugger to step through the Meson build process.

**10. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request. Use clear headings, bullet points, and code examples where appropriate. Start with a general overview and then delve into specifics for each method.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the Frida aspect.
* **Correction:** Remember this code is part of Meson, a general build system. Explain the Meson context first, then connect it to Frida.
* **Initial thought:**  Just list the function names.
* **Correction:**  Provide a brief explanation of what each function *does*.
* **Initial thought:** Assume the user is an expert.
* **Correction:** Explain concepts clearly, even if they seem basic (like source/build directories).
* **Initial thought:**  Only focus on direct connections to reverse engineering.
* **Correction:** Consider indirect connections too, like how build scripts can facilitate reverse engineering workflows.

By following this structured approach and iterating on the analysis, you can arrive at a comprehensive and informative answer like the example provided.
This Python code file, `mesonmain.py`, is a core part of the Meson build system's interpreter. Meson is the build system used by Frida. This file defines the `MesonMain` class, which acts as a bridge, exposing various functionalities of the Meson build system to the project's `meson.build` files. Think of it as a set of built-in functions and methods that can be called from your Meson build definition.

Let's break down its functionalities based on your request:

**1. Functionalities of `mesonmain.py`:**

* **Managing Build Scripts:**
    * `add_install_script`: Registers a script to be executed during the installation phase of the build. This script can perform tasks like copying files, setting permissions, etc.
    * `add_postconf_script`: Registers a script to be executed after the configuration phase but before the actual build. This is often used for tasks that depend on the generated build environment.
    * `add_dist_script`: Registers a script to be executed when creating distribution archives (like tarballs).
* **Providing Information about the Build Environment:**
    * `backend`: Returns the name of the backend being used by Meson (e.g., ninja, vs).
    * `build_options`: Returns the command-line options used to configure the build.
    * `build_root`: Returns the main build directory. (Deprecated in favor of more specific methods).
    * `can_run_host_binaries`: Checks if the host machine can execute binaries built for the host architecture (relevant for cross-compilation).
    * `current_source_dir`: Returns the source directory of the current `meson.build` file.
    * `current_build_dir`: Returns the build directory corresponding to the current `meson.build` file.
    * `global_build_root`, `global_source_root`: Return the top-level build and source directories, respectively.
    * `project_build_root`, `project_source_root`: Return the build and source directories for the current project.
    * `source_root`: Returns the main source directory. (Deprecated).
    * `version`: Returns the version of Meson being used.
* **Accessing Project Information:**
    * `project_license`, `project_license_files`:  Retrieve the project's license information as defined in the `project()` declaration.
    * `project_name`: Returns the name of the project.
    * `project_version`: Returns the version of the project.
* **Managing Dependencies and Programs:**
    * `get_compiler`: Retrieves a compiler object for a specific language (e.g., 'c', 'cpp').
    * `get_cross_property`, `get_external_property`: Retrieve properties defined in the cross-compilation or native files.
    * `has_exe_wrapper`: Checks if an executable wrapper is needed for cross-compilation. (Deprecated).
    * `has_external_property`: Checks if a specific property exists in the cross or native file.
    * `install_dependency_manifest`: Specifies the name of the dependency manifest file.
    * `is_cross_build`: Checks if it's a cross-compilation build.
    * `override_dependency`:  Allows you to force the build system to use a specific dependency object instead of automatically finding one.
    * `override_find_program`: Allows you to force the build system to use a specific program (executable) when searching for it.
* **Subproject and Unity Builds:**
    * `is_subproject`: Checks if the current context is within a subproject.
    * `is_unity`: Checks if unity builds are enabled.
* **Environment Variables:**
    * `add_devenv`:  Adds or modifies environment variables that will be set when running tests or custom commands defined in the Meson build.
* **Build Options:**
    * `build_options`:  Returns the formatted command-line options used for configuration.

**2. Relationship with Reverse Engineering (with examples):**

Yes, this file and the functionalities it exposes are directly relevant to the reverse engineering process, especially when dealing with projects that use Frida:

* **Controlling the Build Process:** Reverse engineers often need to modify and rebuild parts of a target application or library. Meson, through this file, provides fine-grained control over the build process.
    * **Example:** A reverse engineer might want to compile a custom Frida gadget (a shared library injected into a process). They would use Meson to define how this gadget is built, including source files, dependencies, and compiler flags.
* **Dependency Management:** Frida itself and the target applications it interacts with have dependencies. `override_dependency` is crucial here.
    * **Example:** If a reverse engineer is working with an older version of a library that Frida depends on, they might use `override_dependency` to force Meson to link against that specific older version during the Frida build. This can be important for compatibility or for analyzing how Frida interacts with different library versions.
* **Custom Build Steps:**  `add_install_script`, `add_postconf_script`, and `add_dist_script` allow for the execution of arbitrary scripts.
    * **Example:** A reverse engineer could use `add_install_script` to copy Frida binaries or scripts to a specific location on an Android device after building.
    * **Example:**  They might use `add_postconf_script` to automatically patch a built binary with specific instrumentation points before packaging it.
* **Cross-Compilation:** Frida is often used to target mobile platforms like Android and iOS. `is_cross_build`, `get_compiler`, `get_cross_property` are essential for configuring cross-compilation builds.
    * **Example:** When building Frida for an Android device, Meson will use the information provided through these methods (and configuration files) to select the correct Android NDK compiler and linker.
* **Finding Programs:** `override_find_program` can be used to point Meson to specific versions or patched versions of build tools.
    * **Example:** A reverse engineer might want to use a specific version of `llvm` tools for building Frida and can ensure Meson uses that version using `override_find_program`.

**3. Involvement of Binary Bottom, Linux, Android Kernel & Frameworks:**

This file indirectly interacts with these low-level aspects:

* **Binary Bottom:** The primary goal of a build system is to produce binary executables and libraries. The compiler objects obtained through `get_compiler` are the tools that directly interact with assembly code and generate the final binary output. The build process managed by Meson orchestrates the compilation and linking steps necessary to create these binaries.
* **Linux:** When building Frida on a Linux host or for a Linux target, the compiler will be a Linux-specific compiler (like GCC or Clang). The scripts executed by `add_install_script`, etc., can perform Linux-specific operations (e.g., setting file permissions using `chmod`).
* **Android Kernel & Frameworks:** When cross-compiling Frida for Android, Meson uses the Android NDK (Native Development Kit). The `get_compiler` method will return the appropriate Android NDK compiler (targeting ARM or other Android architectures). The `get_cross_property` method is used to access settings specific to the Android target (e.g., sysroot, architecture). The scripts might interact with the Android Debug Bridge (adb) or other Android-specific tools. The built Frida libraries will eventually interact with the Android runtime environment and potentially the kernel (if using kernel-level instrumentation).

**4. Logical Reasoning (Hypothetical Input & Output):**

Let's take the `is_unity_method` as an example:

* **Hypothetical Input:**
    * The user has configured the Meson project with the option `-Dunity=on`.
* **Logical Reasoning:**
    1. The `is_unity_method` is called.
    2. It accesses the `coredata` (build configuration data).
    3. It retrieves the value of the `unity` option.
    4. It checks if the value is equal to `'on'` or if it's `'subprojects'` and the current context is a subproject.
* **Hypothetical Output:** `True` (because `-Dunity=on`)

Another example with `override_dependency_method`:

* **Hypothetical Input:**
    * `meson.override_dependency('glib-2.0', glib_dep)` is called in `meson.build`, where `glib_dep` is a dependency object representing a specific version of GLib.
* **Logical Reasoning:**
    1. The `override_dependency_method` is called with the dependency name 'glib-2.0' and the dependency object `glib_dep`.
    2. It stores this override information in the `build.dependency_overrides` dictionary, associated with the target architecture.
    3. Subsequent calls to `dependency('glib-2.0')` will now return the `glib_dep` object that was provided, instead of letting Meson automatically find GLib.
* **Hypothetical Output:**  The override is registered, and future dependency lookups for 'glib-2.0' will use the provided dependency.

**5. Common User or Programming Errors:**

* **Incorrect Argument Types:**  Passing a string when a file object is expected, or vice versa, in methods like `add_install_script`.
    * **Example:** `meson.add_install_script('/path/to/script.sh', ['arg1', 123])` - If `123` is meant to be a string argument, this would be an error.
* **File Not Found:**  Providing a path to a script or file that doesn't exist.
    * **Example:** `meson.add_install_script('non_existent_script.sh')` - If `non_existent_script.sh` is not in the project's source directory.
* **Overriding Dependencies Incorrectly:** Trying to override a dependency with an object that doesn't provide the necessary information (e.g., missing include directories or library paths).
    * **Example:** `meson.override_dependency('openssl', my_incomplete_openssl_dep)` - If `my_incomplete_openssl_dep` is missing crucial information, the build might fail later during linking.
* **Using Deprecated Methods:**  Using methods like `source_root` or `build_root` which are deprecated and might be removed in future Meson versions.
* **Incorrect Keyword Arguments:**  Using an incorrect keyword argument name or providing a value of the wrong type for a keyword argument.
    * **Example:** `meson.add_install_script('my_script.sh', skip_dest_dir=True)` - The correct keyword argument is `skip_if_destdir`.

**6. User Operation Leading to This Code (Debugging Clue):**

A user would interact with this code by writing a `meson.build` file in their project. Here's a step-by-step example:

1. **User creates a `meson.build` file:** This file defines the build process for their Frida-related project.
2. **User calls a Meson function:**  Inside the `meson.build` file, the user might call functions provided by `MesonMain`, such as:
   ```meson
   project('my_frida_gadget', 'cpp')
   executable('mygadget.so', 'mygadget.cpp')
   meson.add_install_script('install_gadget.sh', join_paths(meson.build_root(), 'mygadget.so'))
   ```
3. **Meson parses the `meson.build` file:** When the user runs the `meson` command to configure the build (e.g., `meson setup builddir`), the Meson interpreter starts parsing the `meson.build` file.
4. **Interpreter encounters `meson.add_install_script`:** The interpreter recognizes the `meson.add_install_script` call.
5. **Mapping to Python method:** The interpreter maps this function call to the `add_install_script_method` within the `MesonMain` class in `mesonbuild/interpreter/mesonmain.py`.
6. **Python method execution:** The `add_install_script_method` is executed with the provided arguments ('install_gadget.sh' and the path to the built gadget). This method then registers the install script with the build system.

**As a debugging clue:** If a user is experiencing issues with their Meson build, understanding this flow helps them pinpoint where the problem might be:

* **Error in the `meson.build` file:**  A typo in the function name or incorrect arguments.
* **Problem within the Python code of `mesonmain.py`:** (Less likely for standard functionality, but possible if a bug exists or if a custom Meson module is involved).
* **Issue with the underlying build system or tools:**  Problems with the compiler, linker, or other build tools being used by Meson.

By examining the `meson.build` file and the arguments passed to the Meson functions, and by understanding how these functions are implemented in `mesonmain.py`, developers can effectively debug their Frida and other Meson-based projects.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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