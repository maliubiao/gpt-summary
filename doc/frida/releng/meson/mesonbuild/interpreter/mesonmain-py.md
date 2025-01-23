Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Context:** The initial prompt tells us this is a source file (`mesonmain.py`) within the Frida project, specifically related to Meson (a build system). This immediately gives us important keywords to focus on: "build system," "Meson," and "Frida."  The path also hints at the file's role: `frida/releng/meson/mesonbuild/interpreter/`. This suggests it's part of Meson's interpreter, likely dealing with the execution of Meson build files (`meson.build`).

2. **High-Level Overview:**  The code defines a class `MesonMain`. This class likely contains methods that are exposed as built-in functions within the Meson build language. The `__init__` method confirms this, as it takes a `build` and `interpreter` object, linking it to the ongoing build process. The `self.methods.update(...)` line is crucial: it maps strings (method names in the Meson language) to the Python methods within the `MesonMain` class.

3. **Categorizing Functionality:**  The next step is to go through the `self.methods` dictionary and the defined methods to understand what functionalities are provided. As we read through the method names, natural categories emerge:

    * **Paths:** `build_root`, `current_source_dir`, `global_source_root`, etc. These seem to deal with getting directory paths.
    * **Project Information:** `project_name`, `project_version`, `project_license`. These provide metadata about the project being built.
    * **Build System Interaction:** `backend`, `is_cross_build`, `is_unity`. These relate to the configuration and state of the Meson build itself.
    * **Dependency Management:** `override_dependency`, `override_find_program`, `install_dependency_manifest`. These deal with how Meson handles external libraries and programs.
    * **Script Execution:** `add_install_script`, `add_postconf_script`, `add_dist_script`. These allow running custom scripts during various stages of the build process.
    * **Environment Variables:** `add_devenv`. This deals with manipulating environment variables.
    * **Compiler Information:** `get_compiler`. This retrieves information about the compilers being used.
    * **Features and Capabilities:** `can_run_host_binaries`. This checks for certain build environment capabilities.
    * **Options:** `build_options`. This retrieves build-time options.
    * **External Properties:** `get_external_property`, `has_external_property`. This is for accessing properties defined outside the main build file (like in cross-compilation files).

4. **Connecting to Reverse Engineering:**  Now we start thinking about how these functionalities relate to reverse engineering, specifically in the context of Frida. Frida is a *dynamic* instrumentation tool. This means it modifies the behavior of a running program. How does Meson fit in?  Meson builds Frida itself. Therefore, features that control *how* Frida is built can indirectly impact reverse engineering workflows.

    * **Script Execution (`add_install_script`, etc.):** This is a direct link. Reverse engineers might use custom scripts during Frida's build process to embed specific configurations, add custom tools, or perform pre/post-processing steps relevant to their reverse engineering tasks. *Example:* A script could download pre-trained models for some analysis feature.
    * **Dependency Management (`override_dependency`, `override_find_program`):** Frida relies on various libraries. Reverse engineers might need to use specific versions or patched versions of these dependencies. `override_dependency` allows forcing the build to use a particular version. *Example:*  Using a debug build of a dependency to facilitate debugging Frida itself. `override_find_program` could point to custom build tools.
    * **Cross-Compilation (`is_cross_build`, `get_compiler`, `get_external_property`):** Frida is often used to instrument processes on different architectures (e.g., instrumenting an Android app from a Linux machine). Meson's cross-compilation features, exposed through these methods, are vital for building Frida for target platforms. *Example:*  Getting the path to the Android NDK's compiler.
    * **Environment Variables (`add_devenv`):** Setting environment variables can influence the build process, such as pointing to specific SDK locations or setting up build environments for cross-compilation.

5. **Connecting to Binary/Kernel/Framework Knowledge:**  Think about the underlying systems Frida interacts with.

    * **Cross-Compilation (again):** Building for Android inherently involves knowledge of the Android NDK, its toolchain, and the differences between Linux and Android systems.
    * **Script Execution:** Scripts executed during the build process might interact with the underlying operating system, file system, or even perform actions requiring root privileges.
    * **Dependency Management:** Understanding the ABI (Application Binary Interface) and linking requirements is crucial when dealing with native libraries, especially when cross-compiling.
    * **Compiler Information:** Knowledge of compiler flags and how they impact the generated binary is important, especially for performance and debugging.

6. **Logical Reasoning (Input/Output):**  For methods that perform actions or return specific values, consider what the inputs are and what the expected output would be.

    * `current_source_dir()`: Input: None. Output: The path to the current source directory within the project.
    * `get_compiler('c')`: Input: "c". Output: A `Compiler` object representing the C compiler configured for the current build. *Assumption:* A C compiler is configured.
    * `is_cross_build()`: Input: None. Output: `True` if it's a cross-compilation build, `False` otherwise.

7. **User Errors:**  Consider common mistakes developers might make when using these Meson functions.

    * **Incorrect Path in Scripts:** Providing a wrong path to a script in `add_install_script`.
    * **Overriding Non-Existent Dependencies:**  Trying to override a dependency with `override_dependency` that doesn't exist or isn't used by the project.
    * **Incorrect Compiler Name:**  Providing an invalid language name to `get_compiler`.
    * **Type Mismatches:** Providing arguments of the wrong type to the methods (although Meson has type checking, mistakes can still happen).

8. **Debugging and User Journey:**  Imagine a developer is troubleshooting a problem during Frida's build. How might they end up looking at this code?

    * **Build Script Failure:** If a custom script added with `add_install_script` fails, the developer might trace the execution back to this method.
    * **Dependency Resolution Issues:** If Frida fails to link against a specific library, the developer might investigate how `override_dependency` is being used.
    * **Cross-Compilation Problems:**  If the build fails when targeting a different architecture, the developer might examine the `get_compiler` and `get_external_property` calls.
    * **Understanding Meson Internals:** A developer might simply be exploring the Meson codebase to understand how it works, leading them to core files like this.

9. **Refinement and Organization:** Finally, organize the findings into the requested categories, providing clear explanations and examples. Ensure the language is precise and avoids jargon where possible, while still being technically accurate. Review for clarity and completeness. For example, initially, I might have just said "deals with dependencies," but refining it to "dependency management" and providing examples like "using a debug build" adds much more value.
This Python code defines the `MesonMain` class, which is a crucial part of the Meson build system's interpreter. It exposes a set of built-in functions (methods of this class) that can be called from `meson.build` files, the configuration files used by Meson. Think of `MesonMain` as providing the core functionalities and information about the current build process to the Meson build scripts.

Here's a breakdown of its functionalities, relating them to reverse engineering, binary/kernel knowledge, logical reasoning, user errors, and debugging:

**Functionalities of `MesonMain`:**

* **Managing Build Directories and Paths:**
    * `current_source_dir()`, `current_build_dir()`, `global_source_root()`, `global_build_root()`, `project_source_root()`, `project_build_root()`, `source_root()`, `build_root()`: These methods provide access to various directory paths relevant to the build.
* **Accessing Build System Information:**
    * `backend()`: Returns the name of the backend being used (e.g., ninja, vs2017).
    * `is_cross_build()`:  Indicates whether a cross-compilation build is being performed.
    * `is_unity()`: Checks if the unity build option is enabled.
    * `is_subproject()`:  Indicates if the current `meson.build` file belongs to a subproject.
    * `version()`: Returns the version of Meson being used.
    * `build_options()`: Returns the build options used for the current configuration.
* **Managing Dependencies:**
    * `override_dependency()`: Allows overriding the found dependency for a given name with a specific dependency object.
    * `override_find_program()`: Enables overriding the result of a `find_program()` call with a specified program.
    * `install_dependency_manifest()`: Specifies the name of the dependency manifest file.
* **Managing Programs and Compilers:**
    * `get_compiler()`: Retrieves a compiler object for a given language and target machine.
    * `can_run_host_binaries()`: Checks if the host machine can execute binaries built for it (important for cross-compilation).
    * `has_exe_wrapper()`: (Deprecated)  Similar to `can_run_host_binaries()`.
* **Executing Scripts:**
    * `add_install_script()`:  Registers a script to be executed during the installation phase.
    * `add_postconf_script()`: Registers a script to be executed after the configuration phase.
    * `add_dist_script()`: Registers a script to be executed during the distribution packaging phase.
* **Managing Environment Variables:**
    * `add_devenv()`:  Allows adding or modifying environment variables that will be set when build targets are executed.
* **Accessing Project Information:**
    * `project_name()`: Returns the name of the project.
    * `project_version()`: Returns the version of the project.
    * `project_license()`: Returns the project's license(s).
    * `project_license_files()`: Returns the project's license file(s).
* **Accessing Cross-Compilation Properties:**
    * `get_cross_property()`: (Deprecated) Retrieves a property defined in the cross-compilation file.
    * `get_external_property()`: Retrieves a property for a specific machine (host or build).
    * `has_external_property()`: Checks if a specific property exists for a machine.

**Relationship to Reverse Engineering:**

The functionalities in `MesonMain` are indirectly related to reverse engineering in the context of building tools *for* reverse engineering, such as Frida itself.

* **Building Frida for Different Architectures (`is_cross_build()`, `get_compiler()`, `get_cross_property()`, `get_external_property()`):** Frida is a cross-platform tool and needs to be built for various target architectures (e.g., ARM for Android, x86 for desktop). These methods are crucial for configuring the build process when targeting a different architecture than the host machine. For example, when building Frida for an Android device, `is_cross_build()` would be true, and `get_compiler('c', native='target')` would fetch the ARM compiler from the Android NDK. `get_external_property()` could be used to retrieve specific paths or settings from the Android cross-compilation setup.

* **Customizing the Build Process with Scripts (`add_install_script()`, `add_postconf_script()`, `add_dist_script()`):**  Reverse engineers contributing to Frida or building custom Frida variants might use these scripts to automate tasks during the build.
    * **Example:** An `add_install_script()` could be used to copy pre-compiled native libraries or tools into the Frida installation directory. A `postconf_script()` might generate configuration files based on the build environment.

* **Overriding Dependencies (`override_dependency()`, `override_find_program()`):**  Sometimes, specific versions or patched versions of libraries are needed. These methods allow forcing the build system to use a particular dependency.
    * **Example:**  If a bug is found in a specific version of a dependency used by Frida, a developer might use `override_dependency()` to point to a patched version during development. `override_find_program()` could be used to specify a custom build of a tool like `protoc` (for Protocol Buffers) if needed.

**Relationship to Binary Underlying, Linux, Android Kernel, and Framework Knowledge:**

* **Cross-Compilation Details:** When `is_cross_build()` is true, methods like `get_compiler()` and `get_external_property()` directly interact with the toolchain for the target architecture. Building for Android requires understanding the Android NDK (Native Development Kit), which provides compilers, linkers, and headers for building native code.
    * **Example:**  Getting the path to the `aarch64-linux-android-gcc` compiler using `get_compiler('c', native='target')` involves knowledge of the naming conventions and structure of the Android NDK.

* **Installation Scripts and System Interaction (`add_install_script()`):**  Installation scripts often involve interacting with the underlying operating system, such as copying files to specific system directories. On Linux and Android, this might involve understanding file system permissions, standard installation paths (`/usr/local`, `/system`), and potentially using commands like `install` or `cp`.

* **Environment Variables and Process Execution (`add_devenv()`):**  Setting environment variables can influence how compiled binaries behave at runtime. This is particularly relevant in the context of libraries and shared objects, where `LD_LIBRARY_PATH` is used on Linux (and similar mechanisms on Android) to locate shared libraries.

**Logical Reasoning (Hypothetical Input and Output):**

* **`current_source_dir()`:**
    * **Input:** None
    * **Output:**  The absolute path to the directory containing the `meson.build` file currently being processed. For example, if processing `frida/releng/meson/mesonbuild/interpreter/mesonmain.py`, the output would be the absolute path to `frida/releng/meson/mesonbuild/interpreter`.

* **`is_cross_build()`:**
    * **Input:** None
    * **Output:** `True` if the user ran the Meson configuration command with a `--cross-file` argument (indicating cross-compilation), `False` otherwise.

* **`get_compiler('c')`:**
    * **Input:** `'c'` (string representing the C language)
    * **Output:** An object representing the C compiler configured for the *host* machine (by default). This object would have attributes like the compiler's path, version, and supported flags.

* **`get_compiler('c', native='target')`:**
    * **Input:** `'c'` and `native='target'` (indicating the target machine for cross-compilation)
    * **Output:** An object representing the C compiler configured for the *target* architecture (e.g., the ARM compiler from the Android NDK).

* **`add_install_script('my_script.sh', 'arg1', 'arg2')`:**
    * **Input:** `'my_script.sh'` (path to the script), `'arg1'`, `'arg2'` (arguments to the script)
    * **Output:** This method doesn't return a value. It registers `my_script.sh` to be executed during the install phase with the arguments `arg1` and `arg2`. The actual execution happens later when the user runs the `meson install` command.

**User or Programming Common Usage Errors:**

* **Incorrect Path in `add_install_script()`:** Providing a relative path to the script that doesn't exist or isn't relative to the source or build directory. Meson might throw an error during the install phase when it tries to execute the non-existent script.

* **Typos in Dependency Names in `override_dependency()`:**  If the user misspells the name of the dependency they are trying to override, Meson will not find a matching dependency and the override will not be applied. This could lead to linking errors or the use of the default dependency.

* **Providing Incorrect Compiler Language to `get_compiler()`:**  If the user tries to get a compiler for a language that isn't configured for the project (e.g., `get_compiler('go')` when no Go compiler is set up), Meson will raise an `InterpreterException`.

* **Using Deprecated Methods:**  Using `source_root()` or `build_root()` instead of the newer `project_source_root()`/`global_source_root()` and `project_build_root()`/`global_build_root()`. While these might still work for a while, the deprecation warning indicates potential future removal, leading to code breakage.

* **Incorrectly Specifying `native` Keyword:** When using methods like `get_compiler()` or `get_external_property()`, misunderstanding the `native` keyword (which can be 'host', 'build', or 'target' in cross-compilation scenarios) can lead to accessing properties or compilers for the wrong machine.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Writing a `meson.build` File:** A developer starts by creating or modifying a `meson.build` file in their project. This file uses the built-in functions provided by `MesonMain`.

2. **Running the Meson Configuration Command:** The developer executes a command like `meson setup builddir` (or `meson --prefix /usr`). This initiates the Meson configuration process.

3. **Meson Interpreter Execution:**  During the configuration, Meson parses the `meson.build` file. When it encounters calls to functions like `meson.add_install_script()`, `meson.get_compiler()`, or `meson.override_dependency()`, the Meson interpreter looks up the corresponding methods in the `MesonMain` class within this `mesonmain.py` file.

4. **Potential Errors or Debugging:**
    * **Configuration Errors:** If there's an error in the `meson.build` file (e.g., a typo in a function name or incorrect arguments), the Meson interpreter will raise an exception. The traceback might point to the line in `meson.build` where the error occurred, and understanding how the interpreter maps these calls to `MesonMain` is crucial for debugging.
    * **Build Failures:** If a script added with `add_install_script()` fails during the installation phase (`meson install`), the developer might need to examine the script and how it was registered in `MesonMain`.
    * **Dependency Resolution Issues:** If Meson fails to find a dependency or uses the wrong version, a developer might investigate how `override_dependency()` is being used and whether it's correctly overriding the dependency.
    * **Cross-Compilation Problems:** If the build fails when cross-compiling, the developer might need to check the values returned by `is_cross_build()`, `get_compiler()`, and `get_external_property()` to ensure the correct toolchain and settings are being used. They might set breakpoints or add print statements within the `MesonMain` methods to inspect the state during the configuration.

In summary, `mesonmain.py` and the `MesonMain` class are at the heart of how Meson interprets and executes build configurations. Understanding its functionalities is essential for anyone working with Meson, especially when customizing the build process or debugging build-related issues, which can be relevant in the context of building complex tools like Frida.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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