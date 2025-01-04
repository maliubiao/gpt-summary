Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Core Purpose:** The first thing to recognize is the file path: `frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/mesonmain.py`. Keywords like "frida," "meson," and "interpreter" are crucial. Frida is the dynamic instrumentation tool, Meson is a build system, and "interpreter" suggests this file is part of how Meson processes build instructions. The `MesonMain` class name reinforces this. Therefore, this code is likely part of Frida's build process, defining some build-related functions within the Meson environment.

2. **Identify Key Classes and Objects:**  The code defines the `MesonMain` class. Its `__init__` method is important. It shows that a `MesonMain` object holds references to `build.Build` and `Interpreter` objects. This hints at its role: providing build-related functionality within the Meson interpreter.

3. **Analyze the `methods` Dictionary:** The `self.methods.update({...})` line is a treasure trove. It lists the functions that `MesonMain` makes available within the Meson build scripts. Each key in this dictionary is a Meson function name (e.g., `add_install_script`, `get_compiler`), and the value is the corresponding Python method within the `MesonMain` class. This is the primary interface this file provides.

4. **Categorize Functionality:**  As you go through the `methods` dictionary, start grouping the functions by their apparent purpose. Some initial categories might be:
    * **Script Execution:** `add_install_script`, `add_postconf_script`, `add_dist_script` (These deal with executing scripts during different stages of the build).
    * **Path Information:** `current_source_dir`, `current_build_dir`, `project_source_root`, etc. (These provide access to directory paths).
    * **Compiler Information:** `get_compiler` (Provides access to compiler information).
    * **Build Configuration:** `is_cross_build`, `is_unity` (Indicates aspects of the build setup).
    * **Dependency Management:** `override_dependency`, `override_find_program`, `install_dependency_manifest` (Functions for handling dependencies).
    * **Project Information:** `project_name`, `project_version`, `project_license` (Accessing project metadata).
    * **Environment Variables:** `add_devenv` (Modifying environment variables during the build).
    * **General Meson Info:** `backend`, `version`, `build_options`, `can_run_host_binaries`.

5. **Look for Reverse Engineering Connections:**  Think about how each category relates to reverse engineering.
    * **Script Execution:**  Installation scripts, post-configuration scripts, and distribution scripts are prime targets for reverse engineers to understand how software is deployed and configured.
    * **Path Information:** Knowing where source and build files are located is essential for analyzing the build process.
    * **Compiler Information:**  Understanding the compiler and its settings is crucial for analyzing compiled binaries.
    * **Build Configuration:** Whether it's a cross-build or uses unity builds affects the final binary structure and how it's built.
    * **Dependency Management:** Knowing the dependencies and how they are handled is vital for understanding the software's architecture and potential vulnerabilities. Overriding dependencies is a powerful technique in dynamic instrumentation.
    * **Project Information:**  Metadata can provide clues about the software's origins and intended use.

6. **Identify Low-Level/Kernel Connections:** Scan the function names and docstrings for keywords related to low-level concepts. "Cross-build," "host binaries," and mentions of Android (even indirectly through Frida's purpose) are indicators. The `get_cross_property` and `get_external_property` functions suggest access to platform-specific information.

7. **Analyze Logic and Potential Inputs/Outputs:** For each function, consider:
    * **What inputs does it take?** (Positional and keyword arguments)
    * **What does it do with those inputs?** (Internal logic, calls to other objects)
    * **What does it output?** (Return value)
    * **What assumptions does it make?**
    * **What could go wrong?** (Potential errors, user mistakes)

    For example, `add_install_script` takes a script path and arguments. It then serializes this information for later execution during the installation phase. A user error might be providing a non-existent script path.

8. **Trace User Operations:** Think about how a developer using Meson to build Frida would interact with these functions. They'd write `meson.build` files that call these functions to configure the build. Debugging might involve looking at Meson's output or even stepping into the Meson interpreter's code. The file path itself provides a clue about the location of this code within the Frida project.

9. **Pay Attention to Decorators and Type Hints:**  Decorators like `@typed_pos_args`, `@typed_kwargs`, `@FeatureNew`, and `@FeatureDeprecated` provide valuable information about the function's arguments, keyword arguments, and when features were introduced or deprecated. Type hints (like `T.List[str]`) help understand the expected data types.

10. **Iterate and Refine:** After the initial pass, review your findings. Are there any connections you missed? Can you provide more specific examples?  Is your explanation clear and well-organized?

**Self-Correction Example During Analysis:**

Initially, I might have overlooked the significance of the `_find_source_script` and `_process_script_args` helper methods. However, noticing their use by multiple script-related functions (like `add_install_script`) would prompt me to examine them more closely. I'd realize they handle the details of preparing script arguments and finding the executable, which is a crucial part of the script execution functionality. This would lead to a more comprehensive understanding. Similarly, seeing the `FeatureNew` and `FeatureDeprecated` decorators highlights the evolution of the Meson API and suggests that some functions are newer or older than others, which can be relevant for understanding different versions of Frida's build process.
This Python code file, `mesonmain.py`, is part of the Meson build system, specifically within the Frida project. It defines the `MesonMain` class, which acts as a bridge, providing a set of functions accessible from the Meson build definition files (`meson.build`). These functions allow the build system to interact with and configure various aspects of the Frida build process.

Here's a breakdown of its functionalities:

**Core Functionalities:**

* **Script Execution Management:**
    * **`add_install_script`:**  Registers a script to be executed during the installation phase of the build. This is crucial for tasks like copying additional files, setting up configurations post-compilation, or performing other installation-related actions.
    * **`add_postconf_script`:** Registers a script to be executed after the configuration phase but before the actual build. This is useful for tasks that need to run after Meson has generated the initial build system but before compilation starts.
    * **`add_dist_script`:** Registers a script to be executed when creating distribution packages (e.g., tarballs, zip files). This is used for tasks like bundling extra resources or generating distribution-specific files.

* **Path and Directory Information:**
    * **`current_source_dir`:** Returns the path to the current source directory where the `meson.build` file is located.
    * **`current_build_dir`:** Returns the path to the current build directory corresponding to the source directory.
    * **`project_source_root`:** Returns the root directory of the current project's source code.
    * **`project_build_root`:** Returns the root directory of the current project's build output.
    * **`global_source_root`:** Returns the top-level source directory.
    * **`global_build_root`:** Returns the top-level build directory.
    * **`source_root` (Deprecated):**  An older version of `global_source_root`.
    * **`build_root` (Deprecated):** An older version of `global_build_root`.

* **Build System Information:**
    * **`backend`:** Returns the name of the backend being used by Meson (e.g., ninja, vs2019).
    * **`is_cross_build`:** Returns `True` if it's a cross-compilation build, `False` otherwise.
    * **`is_unity`:** Returns `True` if unity builds are enabled, `False` otherwise.
    * **`is_subproject`:** Returns `True` if the current `meson.build` file belongs to a subproject, `False` otherwise.
    * **`can_run_host_binaries`:** Checks if the build system can execute binaries built for the host machine during the build process.
    * **`has_exe_wrapper` (Deprecated):** Older version of `can_run_host_binaries`.
    * **`build_options`:** Returns a string representing the command-line options used for the build.
    * **`version`:** Returns the version of Meson being used.

* **Compiler and Target Information:**
    * **`get_compiler`:** Retrieves the compiler object for a specific language (e.g., 'c', 'cpp').
    * **`get_cross_property` (Deprecated):** Retrieves a property defined in the cross-compilation file for the host machine.
    * **`get_external_property`:** Retrieves a property defined in the cross-compilation file or environment for a specified machine (host or build).
    * **`has_external_property`:** Checks if a specific property exists for a given machine.

* **Dependency Management:**
    * **`override_dependency`:** Allows overriding how a dependency is found. This is essential for providing custom dependency implementations or for scenarios where the automatic dependency detection fails.
    * **`override_find_program`:** Allows overriding the program found by the `find_program` function. This is useful for specifying a specific path to a tool or executable.
    * **`install_dependency_manifest`:** Sets the name of the dependency manifest file.

* **Project Information:**
    * **`project_name`:** Returns the name of the current project.
    * **`project_version`:** Returns the version of the current project.
    * **`project_license`:** Returns a list of license names for the project.
    * **`project_license_files`:** Returns a list of `mesonlib.File` objects representing the license files.

* **Environment Variable Management:**
    * **`add_devenv`:** Allows adding or modifying environment variables that will be set when executing certain build steps or running the built application.

**Relationship with Reverse Engineering:**

This file has a significant relationship with reverse engineering, especially in the context of a tool like Frida:

* **Understanding the Build Process:** Reverse engineers often need to understand how a target application is built to gain insights into its structure, dependencies, and potential vulnerabilities. `mesonmain.py` defines the fundamental building blocks of Frida's build system. By analyzing the calls to these functions in Frida's `meson.build` files, a reverse engineer can reconstruct the build steps, identify dependencies, and understand how different components are integrated.
* **Identifying Dependencies and Linking:** Functions like `override_dependency` are crucial for understanding how Frida links against its dependencies (e.g., V8, Capstone). Overriding dependencies can also be a technique used during dynamic analysis or instrumentation. A reverse engineer might want to know which specific version of a library Frida is using or if a custom build of a dependency is being employed.
* **Analyzing Installation and Configuration:** The `add_install_script` and `add_postconf_script` functions point to scripts that perform post-build actions. These scripts might contain valuable information about how Frida is deployed, configured, and what runtime dependencies it relies on. Reverse engineers can analyze these scripts to understand the final state of the installed Frida tool.
* **Cross-Compilation Analysis:** The `is_cross_build`, `get_cross_property`, and `get_external_property` functions are relevant when Frida is built for different target architectures (e.g., Android, iOS). Understanding the cross-compilation setup can reveal target-specific configurations and adaptations within the Frida codebase.
* **Locating Key Files and Directories:** The path-related functions help in locating source files, build outputs, and intermediate files. This is essential for navigating the Frida project structure and finding specific components for analysis.

**Examples Relating to Reverse Engineering:**

* **Dependency Override Example:**  A reverse engineer might observe a call to `meson.override_dependency('v8', custom_v8_dep)` in a `meson.build` file. This immediately tells them that Frida is using a custom or specific version of the V8 JavaScript engine, which could be significant for analyzing Frida's JavaScript bridge.
* **Installation Script Analysis:** Examining the script registered with `meson.add_install_script('install_frida.sh', ...)` could reveal how Frida's core components are copied to their final installation locations, what environment variables are set, and if any specific permissions are configured.
* **Cross-Compilation Property:**  If `meson.get_external_property('android_ndk_path', native='android')` is used, a reverse engineer knows that the build process relies on the Android NDK and can investigate how this path influences the build for Android targets.

**Relationship with Binary Underpinnings, Linux, Android Kernel/Framework:**

While `mesonmain.py` itself is a high-level build system component, it indirectly touches upon these lower levels:

* **Binary Underpinnings:** The build process orchestrated by Meson and this file ultimately produces binary executables and libraries. The choice of compiler (obtained via `get_compiler`), compiler flags (often configured elsewhere in the build system), and linker settings all influence the final binary structure and how it interacts with the underlying operating system.
* **Linux:** Frida heavily relies on Linux system calls and kernel features. The build system needs to configure the compilation and linking process to correctly target Linux. Installation scripts might involve setting up shared library paths or other Linux-specific configurations.
* **Android Kernel and Framework:** When building Frida for Android, the cross-compilation settings and the use of the Android NDK are directly related to the Android kernel and framework. The build system needs to ensure that the generated binaries are compatible with the Android runtime environment (e.g., using the correct ABI). Installation scripts for Android might involve pushing files to specific locations within the Android file system.

**Examples:**

* **Compiler Selection:** If `meson.get_compiler('c')` is used, the specific C compiler (like GCC or Clang) chosen for the build will have a direct impact on the generated machine code.
* **Cross-Compilation for Android:** When cross-compiling for Android, the `get_external_property` function might retrieve the target architecture (e.g., ARM, ARM64), which dictates the instruction set the compiler will generate.
* **Installation on Android:** An installation script might use `adb push` to copy Frida's agent library (`frida-agent.so`) to a specific location on an Android device, demonstrating interaction with the Android framework.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input (in a `meson.build` file):**

```meson
project('my-frida-module', 'cpp')

frida_core = shared_library('frida-core', 'core.cpp')

# ... other build definitions ...

install_subdir(frida_core, install_dir: get_option('libdir'))

run_target('post-install-setup',
  command: find_program('setup.sh'),
  args: ['--install-path', get_option('prefix') + '/lib']
)

meson.add_install_script('my_install_script.py', '--prefix', get_option('prefix'))
```

**Logical Reasoning and Potential Outputs:**

1. **`get_option('libdir')`:**  Meson will look up the value of the `libdir` option (likely set by the user during configuration). Let's assume the user configured `--libdir=/usr/local/lib`. The output of this function call would be `/usr/local/lib`.
2. **`get_option('prefix')`:** Similarly, let's assume the user configured `--prefix=/usr/local`. The output would be `/usr/local`.
3. **`find_program('setup.sh')`:** Meson will search for an executable named `setup.sh` in the project's source directories or in the system's PATH. The output would be the full path to the `setup.sh` script (e.g., `/path/to/project/setup.sh`).
4. **`meson.add_install_script('my_install_script.py', '--prefix', '/usr/local')`:** Meson will register `my_install_script.py` to be executed during the install phase, with the arguments `--prefix` and `/usr/local`.

**User/Programming Errors:**

* **Incorrect Path in `add_install_script`:**
    * **Error:** `meson.add_install_script('non_existent_script.sh')`
    * **Explanation:** If `non_existent_script.sh` does not exist in the source tree or is not an executable found in the PATH, Meson will likely raise an error during the configuration phase or when trying to execute the script during installation.
* **Incorrect Argument Types:**
    * **Error:** `meson.add_install_script(123)`  (Passing an integer instead of a string for the script path)
    * **Explanation:** Meson's type checking (using decorators like `@typed_pos_args`) will catch this error during the configuration phase and report a type mismatch.
* **Using Deprecated Functions:**
    * **Warning:** Using `meson.source_root()` will likely produce a warning during the Meson configuration, advising the user to switch to `meson.project_source_root()` or `meson.global_source_root()`.
* **Overriding a Dependency Incorrectly:**
    * **Error:** `meson.override_dependency(123, some_dependency)` (Providing a non-string for the dependency name)
    * **Explanation:**  Similar to incorrect argument types, type checking will catch this. Also, trying to override a dependency with an incompatible object type will lead to errors.

**User Operation Flow to Reach This Code (as a Debugging Clue):**

1. **Developer Modifies `meson.build`:** A Frida developer needs to add or modify some aspect of the build process, such as adding a new installation step or overriding a dependency. They edit the relevant `meson.build` file within the Frida source tree.
2. **Developer Runs Meson:** The developer executes the Meson command-line tool to configure the build: `meson setup builddir`.
3. **Meson Parses `meson.build`:** Meson reads and parses the `meson.build` files. When it encounters functions like `meson.add_install_script` or `meson.get_compiler`, it needs to execute the corresponding Python methods.
4. **`MesonMain` is Instantiated:** The Meson interpreter instantiates the `MesonMain` class, making its methods available.
5. **Method Invocation:** When a function like `meson.add_install_script` is encountered in the `meson.build` file, the Meson interpreter looks up the corresponding method in the `MesonMain.methods` dictionary and calls that Python method (`self.add_install_script_method`).
6. **Execution within `mesonmain.py`:** The code within `add_install_script_method` (or other methods in `mesonmain.py`) is executed. This involves manipulating the internal Meson build state, such as adding scripts to the list of install scripts or storing dependency overrides.
7. **Potential Errors and Debugging:** If there are errors in the `meson.build` file (like incorrect function arguments or non-existent files), the exceptions might be raised from within the methods of `MesonMain`. A developer debugging the build process might step into this `mesonmain.py` file to understand how the build system is interpreting their `meson.build` instructions and to diagnose the cause of errors. They might set breakpoints in functions like `add_install_script_method` or `override_dependency_method` to inspect the arguments being passed and the internal state of the Meson build system.

In summary, `mesonmain.py` is a crucial component of Frida's build system, providing a high-level interface for configuring and managing the build process. Understanding its functionalities is valuable for reverse engineers seeking to analyze Frida's architecture and dependencies, and it highlights the interplay between the build system and lower-level aspects of the target platform.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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