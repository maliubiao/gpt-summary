Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Initial Understanding & Context**

The first step is to recognize the file's location and its name: `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/mesonmain.py`. This immediately tells us:

* **Frida:** It's part of the Frida dynamic instrumentation toolkit. This is a crucial piece of context.
* **Meson:** It's related to the Meson build system. This implies the code is involved in the build process of Frida.
* **Interpreter:** The `interpreter` directory suggests this code is part of how Meson interprets build definitions (usually `meson.build` files).
* **`mesonmain.py`:**  The name strongly suggests this is a core component, potentially handling main Meson-related functionalities.

**2. High-Level Code Inspection**

Quickly scanning the code reveals key elements:

* **Imports:**  Standard Python imports, plus imports from other `mesonbuild` modules. This indicates the file relies on other parts of the Meson system. Pay attention to imports like `dependencies`, `build`, `mlog`, `coredata`, and modules related to the interpreter (`interpreterbase`, `.primitives`).
* **Class `MesonMain`:** This is the central focus. It inherits from `MesonInterpreterObject`, further confirming its role in interpreting build files.
* **`__init__` method:** Initializes the object, storing references to `build` and `interpreter` objects. This suggests the class interacts with the overall build state and the interpreter.
* **`methods` dictionary:** A crucial dictionary mapping strings to methods. These strings are likely keywords used within `meson.build` files. This is the primary way users interact with this code.
* **Methods:** A large number of methods with descriptive names (e.g., `add_install_script_method`, `get_compiler_method`, `override_dependency_method`). These names provide strong clues about their functionality.
* **Decorators:**  Decorators like `@typed_pos_args`, `@typed_kwargs`, `@noPosargs`, `@noKwargs`, and `@FeatureNew`/`@FeatureDeprecated` provide information about the expected arguments, keyword arguments, and versioning of these methods. This is important for understanding how these methods are *intended* to be used.

**3. Functionality Deduction (Iterating Through Methods)**

Now, the core of the analysis involves going through each method in the `methods` dictionary and understanding what it does. Here's a possible thought process for a few key methods:

* **`add_install_script_method`:** The name suggests adding a script to be run during the installation phase. The arguments (`prog`, `args`) and keyword arguments (`skip_if_destdir`, `install_tag`, `dry_run`) further detail its purpose. The internal call to `_find_source_script` and `_process_script_args` indicates how the script and its arguments are handled. *Connection to reverse engineering:* Install scripts can be used to perform post-installation steps, potentially including actions relevant to reverse engineering tools.
* **`get_compiler_method`:**  Clearly retrieves information about a compiler. The `native` keyword argument indicates it can specify the target architecture. *Connection to binary/low-level:* Compilers are fundamental to generating machine code.
* **`override_dependency_method`:** This strongly hints at the ability to replace a default dependency with a custom one. The `static` keyword argument is relevant to library linking. *Connection to reverse engineering:* Overriding dependencies can be useful in controlled environments for analyzing how software behaves with specific library versions or modified libraries.
* **`current_source_dir_method`, `current_build_dir_method`, etc.:** These provide access to directory paths within the build process. This is crucial for knowing where source code and build outputs are located.
* **`is_cross_build_method`:**  Indicates whether a cross-compilation is taking place. This is important for understanding the target architecture.
* **`add_devenv_method`:**  Modifies environment variables. This can impact the execution environment of build tools and the final application.

**4. Connecting to Reverse Engineering, Binary/Low-Level, and Kernels/Frameworks**

As you understand the functionality of the methods, actively think about how they relate to the specific points in the prompt:

* **Reverse Engineering:** Look for methods that allow control over the build process, dependency resolution, or the inclusion of custom scripts. Consider how these could be leveraged for analysis or modification.
* **Binary/Low-Level:** Focus on methods related to compilers, linking (static/shared), target architectures (cross-compilation), and potentially the execution of external programs.
* **Linux/Android Kernel & Frameworks:** This requires more specialized knowledge, but think about how build systems might interact with system libraries, kernel headers, or Android-specific components. The `get_cross_property` and `get_external_property` methods could potentially access information about the target system.

**5. Logic and Examples (Hypothetical Inputs/Outputs)**

For methods that involve some processing or decision-making, think about simple examples:

* **`current_source_dir_method`:**  If the project is in `/home/user/myproject` and the current `meson.build` is in the root, the output would be `/home/user/myproject`. If the `meson.build` is in a subdirectory `src`, the output would be `/home/user/myproject/src`.
* **`is_cross_build_method`:** The output would be `True` if a cross-compilation configuration is active, and `False` otherwise.
* **`get_compiler_method`:**  Input: `meson.get_compiler('c')`. Output: An object representing the C compiler configured for the current build.

**6. User Errors and Debugging**

Consider common mistakes users might make when interacting with these methods in `meson.build` files:

* **Incorrect arguments:**  Passing the wrong number or type of arguments (e.g., calling `get_compiler` without specifying the language).
* **Using deprecated features:** Trying to use methods marked with `@FeatureDeprecated`.
* **Trying to override non-existent dependencies:**  Calling `override_dependency` with an incorrect dependency name.
* **File path issues:** Providing incorrect file paths to scripts in `add_install_script`.

To explain how a user reaches this code (debugging perspective):

1. A user runs the `meson` command to configure their build.
2. Meson parses the `meson.build` files in the project.
3. During parsing, when Meson encounters a function call like `meson.add_install_script(...)`, it needs to execute that function.
4. The interpreter within Meson looks up the corresponding method in the `MesonMain` class's `methods` dictionary.
5. The appropriate method in `mesonmain.py` is then executed.
6. If there's an error in the `meson.build` file (e.g., incorrect arguments), the execution will halt, and the error message might point to the line in `meson.build` where the error occurred. Examining the Meson source code, like this file, can help understand the *underlying cause* of the error.

**7. Structuring the Answer**

Finally, organize the information clearly, addressing each part of the prompt systematically. Use headings and bullet points to make the answer easy to read and understand. Provide concrete examples to illustrate the concepts.
This Python code defines the `MesonMain` class, which is a crucial part of the Meson build system's interpreter. It exposes a set of functions that can be called within `meson.build` files to configure and control the build process. Since Frida uses Meson for its build system, this file plays a significant role in how Frida is built.

Here's a breakdown of its functionalities, with connections to reverse engineering, binary/low-level concepts, kernel/framework knowledge, logic, user errors, and debugging:

**Core Functionalities of `MesonMain`:**

1. **Managing Build Scripts:**
   - `add_install_script`: Registers a script to be executed during the installation phase of the build. This script can perform actions like copying files, setting permissions, or running post-installation tasks.
   - `add_postconf_script`: Registers a script to be run after the configuration phase.
   - `add_dist_script`: Registers a script to be executed when creating distribution packages.

2. **Providing Build Information:**
   - `current_source_dir`: Returns the path to the current source directory where the `meson.build` file is located.
   - `current_build_dir`: Returns the path to the current build directory corresponding to the source directory.
   - `backend`: Returns the name of the backend being used (e.g., ninja, vs2017).
   - `source_root` (deprecated), `build_root` (deprecated), `project_source_root`, `project_build_root`, `global_source_root`, `global_build_root`: Provide various root directory paths for the source and build trees.
   - `project_name`: Returns the name of the current project.
   - `project_version`: Returns the version of the current project.
   - `project_license`, `project_license_files`: Return the project's license information.
   - `version`: Returns the version of Meson itself.

3. **Compiler and Target Information:**
   - `get_compiler`: Retrieves information about a specific compiler (e.g., 'c', 'cpp').
   - `is_cross_build`: Indicates whether the build is a cross-compilation.
   - `can_run_host_binaries` (replaces `has_exe_wrapper`): Checks if the host system can execute binaries built for the host architecture during a cross-compilation.

4. **Dependency Management:**
   - `override_dependency`: Allows overriding the default dependency resolution for a given dependency name, providing a specific dependency object instead.
   - `override_find_program`: Allows overriding the default program search for a given program name, providing a specific executable.
   - `install_dependency_manifest`: Specifies the name of the dependency manifest file.

5. **Build Options:**
   - `build_options`: Returns the command-line options used for the current build.

6. **Environment Variables:**
   - `add_devenv`: Allows adding or modifying environment variables that will be set during the build process.

7. **Subproject Handling:**
   - `is_subproject`: Indicates whether the current build is part of a subproject.
   - `is_unity`: Checks if unity builds are enabled.

8. **External Properties:**
   - `get_cross_property` (deprecated), `get_external_property`: Retrieves properties defined for different machine types (host, build, target).
   - `has_external_property`: Checks if a specific external property exists.

**Relationship with Reverse Engineering:**

* **Controlling Build Artifacts:** The ability to add install scripts (`add_install_script`) is directly relevant. A reverse engineer could use this to ensure specific debugging symbols, disassembled code, or analysis tools are included in the final build or easily accessible. For example, an install script could copy a disassembled version of a library to the installation directory.
* **Dependency Substitution:** `override_dependency` is a powerful tool. A reverse engineer could use this to substitute a standard library with a modified version that logs function calls, inspects arguments, or injects custom behavior. This allows for controlled experimentation and observation of how a program interacts with its dependencies.
    * **Example:**  Assume a target application depends on `libcrypto`. A reverse engineer could create a modified `libcrypto` that logs all calls to cryptographic functions and then use `override_dependency('crypto', my_modified_libcrypto)` in the `meson.build` to force the application to use their instrumented version.
* **Program Overriding:** `override_find_program` can be used to replace standard build tools with custom ones. For instance, a reverse engineer might replace the standard linker with a wrapper that logs all linking commands and the libraries being linked.
    * **Example:**  `override_find_program('ld', my_logging_linker)` would ensure the custom linker is used during the build process.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **Compiler Interaction:** Methods like `get_compiler` directly interact with the compilers used to generate machine code. This is fundamental to understanding the binary output. The ability to specify the compiler and its settings influences the generated binary's architecture, instruction set, and optimizations.
* **Cross-Compilation:** `is_cross_build` and related functionalities are essential when targeting different architectures (e.g., building an Android application on a Linux desktop). Understanding cross-compilation is crucial for reverse engineering targets that don't run on the analysis machine.
* **Library Linking (Static/Shared):** The `override_dependency` method with its `static` keyword indirectly relates to how libraries are linked. Understanding the difference between static and shared linking is important for analyzing binary dependencies and potential attack surfaces.
* **Install Scripts and System Interaction:** Install scripts often interact directly with the underlying operating system (Linux or Android). They might involve setting file permissions (`chmod`), copying files to specific locations, or running system commands. Reverse engineers need to understand these actions to fully grasp the installation process and the final state of the installed software.
* **Android Framework (Indirect):** While this file doesn't directly touch Android kernel code, it's part of the build process for Frida, which is heavily used for dynamic instrumentation on Android. The build configuration and scripts managed here determine how Frida itself is built and packaged for Android. Understanding the build process is a prerequisite for understanding how Frida interacts with the Android framework and kernel.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `current_source_dir_method` as an example:

* **Hypothetical Input:** Assume the `meson.build` file is located at `/home/user/frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/`.
* **Logical Reasoning:** The method simply returns the directory where the current `meson.build` file resides.
* **Hypothetical Output:** `/home/user/frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/`

Another example, `is_cross_build_method`:

* **Hypothetical Input:** The build is configured with a cross-compilation target (e.g., targeting ARM architecture from an x86 host).
* **Logical Reasoning:** The method checks the build environment's configuration. If a cross-compilation setup is detected, it returns `True`.
* **Hypothetical Output:** `True`

**User or Programming Common Usage Errors:**

* **Incorrect Argument Types:** Calling a method with arguments of the wrong type. For example, passing an integer to `add_install_script` where a string (path to the script) is expected. Meson's type checking (using `@typed_pos_args` and `@typed_kwargs`) aims to catch these errors early.
* **Using Deprecated Features:**  Using methods marked with `@FeatureDeprecated`. Meson will usually issue warnings about this, and the behavior might change or be removed in future versions.
* **Incorrect File Paths:** Providing wrong paths to scripts in `add_install_script` or to files in other methods. This will lead to errors during the build or installation process.
* **Overriding Non-Existent Dependencies:** Trying to `override_dependency` with a name that doesn't correspond to a known dependency.
* **Misunderstanding `native` Keyword:**  Incorrectly using the `native` keyword in methods like `get_compiler` or `override_dependency`, leading to attempts to access compilers or dependencies for the wrong machine type (host vs. target).
* **Incorrectly Using `add_devenv`:** Providing invalid input types or structures for environment variables.

**User Operation Steps to Reach This Code (Debugging Context):**

1. **User Modifies `meson.build`:** A developer working on Frida or a related project modifies a `meson.build` file. This file contains calls to functions defined in `MesonMain` (e.g., `meson.add_install_script(...)`).
2. **User Runs `meson` Command:** The user executes the `meson` command in their terminal, pointing it to the source directory containing the `meson.build` file. For example: `meson builddir`.
3. **Meson Configuration Phase:** Meson starts its configuration phase.
4. **Parsing `meson.build`:** The Meson interpreter reads and parses the `meson.build` files.
5. **Encountering `meson.` Calls:** When the interpreter encounters a function call starting with `meson.`, it needs to resolve and execute that function.
6. **Looking up in `MesonMain`:** The interpreter looks up the called function name (e.g., `add_install_script`) in the `self.methods` dictionary of the `MesonMain` class.
7. **Executing the Method:** The corresponding method in `mesonmain.py` is executed. The arguments provided in the `meson.build` file are passed to this method.
8. **Error Occurs (Hypothetical):** If there's an error during the execution of the method in `mesonmain.py` (e.g., a file not found in `add_install_script`), Meson will raise an exception and report it to the user. The traceback might point to the line in `mesonmain.py` where the error occurred, helping developers understand the root cause.
9. **Debugging:** A developer investigating the build error might then examine the `mesonmain.py` file to understand how the specific `meson.` function they used is implemented and identify potential issues in their `meson.build` file or the Meson internals.

In summary, `mesonmain.py` is a core file in Meson that provides the building blocks for defining and controlling the build process of software like Frida. Its functionalities have direct relevance to reverse engineering through dependency manipulation, build artifact control, and interaction with low-level aspects of the build system. Understanding this file is crucial for anyone deeply involved in building, customizing, or analyzing software built with Meson.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```