Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding - What is Hotdoc?**

The first lines tell us this file is related to "hotdoc."  A quick search for "hotdoc" reveals it's a documentation generator, similar to Sphinx or Doxygen. Knowing this provides context for the code. The module's name, `hotdoc.py`, reinforces this.

**2. Core Functionality - `generate_doc`**

The function `generate_doc` stands out as the primary entry point for users. It takes arguments related to documentation generation: `sitemap`, `index`, `project_version`, etc. This suggests the module's main job is to orchestrate the generation of documentation using hotdoc.

**3. Key Classes - `HotdocExternalProgram`, `HotdocTargetBuilder`, `HotdocTarget`, `HotDocModule`**

*   **`HotdocExternalProgram`**: This clearly handles interactions with the external `hotdoc` command-line tool. The `run_hotdoc` method confirms this. It encapsulates the execution of the hotdoc binary.

*   **`HotdocTargetBuilder`**: This class is responsible for setting up the hotdoc configuration. The `process_known_arg`, `set_arg_value`, `process_dependencies`, `generate_hotdoc_config` methods point to this. It translates Meson's input into hotdoc's configuration format.

*   **`HotdocTarget`**:  This represents the build target for generating the documentation within the Meson build system. It inherits from `CustomTarget`, indicating it's a user-defined build step.

*   **`HotDocModule`**: This is the main Meson module that exposes the functionality to the Meson build system. It initializes the `HotdocExternalProgram` and registers the `generate_doc` method.

**4. Workflow Analysis -  How does it work?**

Following the execution flow, especially within `generate_doc` and `HotdocTargetBuilder`, is crucial:

*   `generate_doc` receives user-defined parameters.
*   It creates a `HotdocTargetBuilder` to manage the configuration.
*   The `HotdocTargetBuilder` processes the input arguments, converting them into hotdoc command-line options.
*   `generate_hotdoc_config` is called to generate a hotdoc configuration file (JSON).
*   A `HotdocTarget` is created, representing the documentation build process. This target will execute the `hotdoc run` command.
*   If `install` is true, an installation script is generated.

**5. Connecting to Reverse Engineering, Low-Level, etc.**

Now, we need to link the code to the specific topics mentioned in the prompt:

*   **Reverse Engineering**:  Documentation is essential for understanding software, including for reverse engineering. This module *facilitates* the creation of that documentation. The `extra_extension_paths` argument is a strong indicator, as extensions can provide custom documentation for specific aspects of a project, which might be relevant during reverse engineering.

*   **Binary/Low-Level**: The code interacts with an external program (`hotdoc`), which operates on files and potentially processes low-level data to generate documentation. The `--c-include-directories` option hints at the documentation of C/C++ code, which often involves low-level concepts.

*   **Linux/Android Kernel/Framework**:  While the module itself doesn't directly interact with the kernel, the *documentation it generates* could be for projects that do. For example, if Frida is used to instrument Android, this module might document aspects of the Android framework or even kernel modules. The mention of `gi_c_source_roots` is also relevant, as GObject Introspection is used in various system-level components.

*   **Logic and Assumptions**:  The code makes assumptions about the input (e.g., file paths are valid). The processing of lists and different argument types involves logical checks and transformations. Consider the `ensure_list` function.

*   **User Errors**:  The code includes error handling (e.g., `InvalidArguments`, `MesonException`). Looking at the argument parsing (`typed_kwargs`) helps identify potential user errors (incorrect types, missing required arguments). The deprecation warning is another example.

*   **User Journey**: To understand how a user reaches this code, think about the steps involved in using Meson to build a project that uses hotdoc for documentation. The user would:
    1. Have a project with documentation that hotdoc can process.
    2. Use the `hotdoc.generate_doc()` Meson function in their `meson.build` file.
    3. Pass arguments to this function, which are then handled by this Python code.
    4. Run the Meson configuration step, which executes this Python code.

**6. Example Construction**

For each point, construct concrete examples based on the code's functionality. For instance, for reverse engineering, imagine a Frida extension being documented. For user errors, think about what happens if the `sitemap` is not provided.

**7. Refinement and Organization**

Finally, organize the findings logically, grouping related points together and ensuring clear explanations for each connection. Use code snippets and terminology from the source to illustrate the points. Review for clarity and accuracy. The initial "dump all thoughts" approach followed by structuring them is a useful technique.
This Python code file, `hotdoc.py`, is a module for the Meson build system that provides integration with the Hotdoc documentation generator. Essentially, it allows projects built with Meson to easily generate documentation using Hotdoc.

Here's a breakdown of its functionalities:

**Core Functionality: Generating Documentation with Hotdoc**

1. **`HotDocModule` Class:** This is the main entry point of the module, registered with Meson. It initializes the connection to the Hotdoc executable.
    *   It checks if the `hotdoc` executable is installed and if its version meets the minimum requirement (`MIN_HOTDOC_VERSION`).
    *   It provides two main methods:
        *   `has_extensions()`: Checks if Hotdoc has specific extensions enabled.
        *   `generate_doc()`: The core function that orchestrates the documentation generation process.

2. **`generate_doc()` Method:** This method takes various arguments specifying how the documentation should be generated.
    *   **Required Arguments:**
        *   `project_name`: The name of the project being documented.
        *   `sitemap`: The main sitemap file for the documentation.
        *   `index`: The main index file for the documentation.
        *   `project_version`: The version of the project.
    *   **Optional Arguments:**
        *   `html_extra_theme`:  An extra HTML theme to use for the documentation.
        *   `include_paths`:  Directories containing files to be included in the documentation.
        *   `dependencies`: Libraries, other build targets, or dependencies whose include directories should be considered during documentation generation (for things like API references).
        *   `depends`: Other custom build targets that must be built before the documentation can be generated.
        *   `gi_c_source_roots`:  Source roots for projects using GObject Introspection (for generating API documentation from C code).
        *   `extra_assets`: Additional files or directories to be copied to the documentation output.
        *   `extra_extension_paths`: Paths to additional Hotdoc extensions.
        *   `subprojects`: Other Hotdoc documentation targets that this target depends on.
        *   `install`: A boolean indicating whether to install the generated documentation.

3. **`HotdocTargetBuilder` Class:** This helper class manages the process of configuring and building the Hotdoc documentation target.
    *   It takes the arguments passed to `generate_doc()` and transforms them into command-line arguments for the `hotdoc` tool.
    *   It handles dependencies, include paths, and other configuration options.
    *   It generates a Hotdoc configuration file (`.json`).
    *   It creates a `CustomTarget` in Meson representing the documentation build process.

4. **`HotdocTarget` Class:** This class represents the actual documentation build target within Meson. It's a subclass of `CustomTarget`.
    *   It stores information about the Hotdoc configuration, extra assets, and subprojects.
    *   When built, it executes the `hotdoc run` command.

5. **`HotdocExternalProgram` Class:** A simple wrapper around `ExternalProgram` for executing the `hotdoc` command.

**Relationship to Reverse Engineering:**

This module's connection to reverse engineering is indirect but important:

*   **Documentation is Key:**  Good documentation is invaluable for reverse engineering. It helps understand the purpose, structure, and functionality of software. This module facilitates the creation of such documentation.
*   **API Documentation:**  The `dependencies` and `gi_c_source_roots` options are particularly relevant. They allow documenting the APIs of libraries and C code. Reverse engineers often need to understand the APIs a program uses to analyze its behavior. For example, if Frida's core components have their APIs documented using this module, a reverse engineer studying Frida would find this documentation very helpful.
*   **Extension Documentation:** The `extra_extension_paths` option suggests that Hotdoc can be extended. These extensions might document specific aspects of a system or framework, which can be crucial for reverse engineering specific targets.

**Example:**  Imagine a Frida extension that provides new functionalities for interacting with Android processes. The developers of this extension could use this `hotdoc.py` module to generate documentation explaining how to use these new features, the underlying APIs, and perhaps even internal implementation details relevant for advanced users or those wanting to understand the extension's mechanics. A reverse engineer looking into this extension would directly benefit from this documentation.

**Involvement of Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

*   **Binary Underlying:** While the Python code itself doesn't directly manipulate binaries, Hotdoc, the tool it interacts with, *processes* source code and can generate documentation about the structure and APIs of software, including software written in languages like C/C++ that compile to binary. The documentation generated might describe data structures, function signatures, and other low-level details that are crucial for understanding the underlying binary.
*   **Linux:**  Frida itself is heavily used on Linux. This module, being part of Frida's build process, is used in a Linux environment. The paths and commands used within the module are generally Linux-style.
*   **Android Kernel & Framework:** Frida is widely used for dynamic instrumentation on Android. Therefore, documentation generated using this module could very well be about:
    *   **Frida's own API:** Which allows interaction with Android processes.
    *   **Internal details of Frida's Android agent:** How it injects and executes code.
    *   **Aspects of the Android Framework:**  If Frida is used to document certain framework components or APIs.
    *   **Potentially even parts of the Android Kernel:** If extensions are developed to interact with kernel-level components and are documented using Hotdoc.
    *   The `gi_c_source_roots` option is particularly relevant here, as much of the Android framework and kernel is written in C/C++.

**Example:** If Frida developers use this module to document the JavaScript API that Frida provides for interacting with Android processes, that documentation will describe how to call Android framework functions, access memory, and perform other actions that directly relate to the Android framework's architecture.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input (in a `meson.build` file):**

```python
hotdoc = import('hotdoc')

hotdoc.generate_doc(
  'MyFridaExtension',
  sitemap: files('sitemap.xml'),
  index: files('index.md'),
  project_version: '1.0',
  dependencies: [
    dependency('glib-2.0'),
    mylibrary,  # A custom library target
  ],
  include_paths: ['include'],
  extra_assets: ['images'],
  install: true,
)
```

**Logical Reasoning within `hotdoc.py`:**

1. The `generate_doc` function receives these arguments.
2. A `HotdocTargetBuilder` is created.
3. `process_known_arg` would handle `sitemap`, `index`, and `project_version`, setting the corresponding Hotdoc command-line arguments.
4. `process_dependencies` would analyze the `dependencies`:
    *   For `dependency('glib-2.0')`, it would fetch the include directories provided by the `glib-2.0` dependency and add them to the Hotdoc configuration (using `--c-include-directories`).
    *   For `mylibrary`, if it's a build target with include directories, those would also be added.
5. `include_paths` would be processed, adding `include` as an additional include path for Hotdoc.
6. `extra_assets` would add the `images` directory to the list of extra assets for Hotdoc.
7. A `HotdocTarget` would be created with the appropriate command to run Hotdoc, including the configured arguments.
8. If `install` is `true`, an installation script would be generated to copy the generated documentation to the installation directory.

**Hypothetical Output (after building):**

*   A directory named `MyFridaExtension-doc` (or similar) would be created in the build directory, containing the generated HTML documentation.
*   This documentation would likely include:
    *   Content from `sitemap.xml` and `index.md`.
    *   API documentation for `glib-2.0` (if Hotdoc is configured to generate it).
    *   API documentation for `mylibrary` (if it's a C/C++ library and Hotdoc is configured correctly).
    *   Images from the `images` directory.
*   If `install: true` was set, the documentation would be copied to the appropriate installation directory (e.g., `/usr/share/doc/MyFridaExtension`).

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:** Providing an incorrect path to the `sitemap` or `index` file.
    *   **Error:** Hotdoc will likely fail to run or produce an incomplete documentation set.
    *   **Debugging:** Meson might show an error during configuration if the files don't exist, or Hotdoc's error messages during the build process will indicate issues with the input files.

2. **Missing Dependencies:** Not specifying all necessary dependencies in the `dependencies` argument.
    *   **Error:** Hotdoc might not be able to find header files or generate complete API documentation.
    *   **Debugging:** Hotdoc's warnings or errors during the build process will point to missing headers or unresolved symbols.

3. **Incorrect `project_version` Type:** Providing a non-string value for `project_version`.
    *   **Error:** Meson's type checking in `typed_kwargs` would likely raise an `InvalidArguments` exception during the configuration phase.

4. **Using Forbidden Arguments:**  The code explicitly checks for forbidden arguments like `conf_file`. If a user tries to pass this directly, it will raise an `InvalidArguments` error.

5. **Incorrectly Specifying Include Paths:** Providing paths that don't actually contain the necessary header files.
    *   **Error:** Similar to missing dependencies, Hotdoc will fail to find headers.

6. **Forgetting to Install Hotdoc:** If the `hotdoc` executable is not in the system's PATH, the `HotDocModule` initialization will fail with a `MesonException`.

**User Operations to Reach This Code (Debugging Clues):**

1. **Writing a `meson.build` file:** A user is creating or modifying a `meson.build` file for their project.
2. **Using the `hotdoc.generate_doc()` function:** The user explicitly calls this function within their `meson.build` file to integrate Hotdoc documentation generation.
3. **Passing arguments to `generate_doc()`:** The user provides values for arguments like `sitemap`, `index`, `dependencies`, etc. Incorrect values here can lead to errors within this Python code.
4. **Running `meson setup`:** The user executes the `meson setup` command to configure the build. This is when Meson parses the `meson.build` file and executes the Python code in `hotdoc.py`.
5. **Running `meson compile` (or `ninja` etc.):** The user builds the project. This triggers the `CustomTarget` defined in `HotdocTarget`, which executes the `hotdoc` command.
6. **Encountering an error:** If something goes wrong during setup or build related to documentation generation, the traceback or error message will likely point back to this `hotdoc.py` file or the underlying Hotdoc execution.

**Debugging Scenario:**  Imagine a user gets an error message during `meson compile` saying "hotdoc failed to configure". To debug, they might:

1. **Examine their `meson.build` file:** Check the arguments passed to `hotdoc.generate_doc()`.
2. **Verify file paths:** Ensure the `sitemap` and `index` files exist at the specified locations.
3. **Check dependencies:** Confirm that the declared dependencies are correct and provide the necessary header files.
4. **Look at Hotdoc's output:**  Meson usually captures and displays the output of the `hotdoc` command, which might contain specific error messages from Hotdoc itself.
5. **Potentially step through the `hotdoc.py` code:** For more complex issues, a developer might need to examine the logic within `HotdocTargetBuilder` to understand how the arguments are being processed and how the `hotdoc` command is being constructed. This would involve looking at this specific source code.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2018 The Meson development team

from __future__ import annotations

'''This module provides helper functions for generating documentation using hotdoc'''

import os, subprocess
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleInfo
from .. import build, mesonlib, mlog
from ..build import CustomTarget, CustomTargetIndex
from ..dependencies import Dependency, InternalDependency
from ..interpreterbase import (
    InvalidArguments, noPosargs, noKwargs, typed_kwargs, FeatureDeprecated,
    ContainerTypeInfo, KwargInfo, typed_pos_args
)
from ..interpreter.interpreterobjects import _CustomTargetHolder
from ..interpreter.type_checking import NoneType
from ..mesonlib import File, MesonException
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..environment import Environment
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_kwargs, TYPE_var

    _T = T.TypeVar('_T')

    class GenerateDocKwargs(TypedDict):
        sitemap: T.Union[str, File, CustomTarget, CustomTargetIndex]
        index: T.Union[str, File, CustomTarget, CustomTargetIndex]
        project_version: str
        html_extra_theme: T.Optional[str]
        include_paths: T.List[str]
        dependencies: T.List[T.Union[Dependency, build.StaticLibrary, build.SharedLibrary, CustomTarget, CustomTargetIndex]]
        depends: T.List[T.Union[CustomTarget, CustomTargetIndex]]
        gi_c_source_roots: T.List[str]
        extra_assets: T.List[str]
        extra_extension_paths: T.List[str]
        subprojects: T.List['HotdocTarget']
        install: bool

def ensure_list(value: T.Union[_T, T.List[_T]]) -> T.List[_T]:
    if not isinstance(value, list):
        return [value]
    return value


MIN_HOTDOC_VERSION = '0.8.100'

file_types = (str, File, CustomTarget, CustomTargetIndex)


class HotdocExternalProgram(ExternalProgram):
    def run_hotdoc(self, cmd: T.List[str]) -> int:
        return subprocess.run(self.get_command() + cmd, stdout=subprocess.DEVNULL).returncode


class HotdocTargetBuilder:

    def __init__(self, name: str, state: ModuleState, hotdoc: HotdocExternalProgram, interpreter: Interpreter, kwargs):
        self.hotdoc = hotdoc
        self.build_by_default = kwargs.pop('build_by_default', False)
        self.kwargs = kwargs
        self.name = name
        self.state = state
        self.interpreter = interpreter
        self.include_paths: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()

        self.builddir = state.environment.get_build_dir()
        self.sourcedir = state.environment.get_source_dir()
        self.subdir = state.subdir
        self.build_command = state.environment.get_build_command()

        self.cmd: T.List[TYPE_var] = ['conf', '--project-name', name, "--disable-incremental-build",
                                      '--output', os.path.join(self.builddir, self.subdir, self.name + '-doc')]

        self._extra_extension_paths = set()
        self.extra_assets = set()
        self.extra_depends = []
        self._subprojects = []

    def process_known_arg(self, option: str, argname: T.Optional[str] = None, value_processor: T.Optional[T.Callable] = None) -> None:
        if not argname:
            argname = option.strip("-").replace("-", "_")

        value = self.kwargs.pop(argname)
        if value is not None and value_processor:
            value = value_processor(value)

        self.set_arg_value(option, value)

    def set_arg_value(self, option: str, value: TYPE_var) -> None:
        if value is None:
            return

        if isinstance(value, bool):
            if value:
                self.cmd.append(option)
        elif isinstance(value, list):
            # Do not do anything on empty lists
            if value:
                # https://bugs.python.org/issue9334 (from 2010 :( )
                # The syntax with nargs=+ is inherently ambiguous
                # A workaround for this case is to simply prefix with a space
                # every value starting with a dash
                escaped_value = []
                for e in value:
                    if isinstance(e, str) and e.startswith('-'):
                        escaped_value += [' %s' % e]
                    else:
                        escaped_value += [e]
                if option:
                    self.cmd.extend([option] + escaped_value)
                else:
                    self.cmd.extend(escaped_value)
        else:
            # argparse gets confused if value(s) start with a dash.
            # When an option expects a single value, the unambiguous way
            # to specify it is with =
            if isinstance(value, str):
                self.cmd.extend([f'{option}={value}'])
            else:
                self.cmd.extend([option, value])

    def check_extra_arg_type(self, arg: str, value: TYPE_var) -> None:
        if isinstance(value, list):
            for v in value:
                self.check_extra_arg_type(arg, v)
            return

        valid_types = (str, bool, File, build.IncludeDirs, CustomTarget, CustomTargetIndex, build.BuildTarget)
        if not isinstance(value, valid_types):
            raise InvalidArguments('Argument "{}={}" should be of type: {}.'.format(
                arg, value, [t.__name__ for t in valid_types]))

    def process_extra_args(self) -> None:
        for arg, value in self.kwargs.items():
            option = "--" + arg.replace("_", "-")
            self.check_extra_arg_type(arg, value)
            self.set_arg_value(option, value)

    def get_value(self, types, argname, default=None, value_processor=None,
                  mandatory=False, force_list=False):
        if not isinstance(types, list):
            types = [types]
        try:
            uvalue = value = self.kwargs.pop(argname)
            if value_processor:
                value = value_processor(value)

            for t in types:
                if isinstance(value, t):
                    if force_list and not isinstance(value, list):
                        return [value], uvalue
                    return value, uvalue
            raise MesonException(f"{argname} field value {value} is not valid,"
                                 f" valid types are {types}")
        except KeyError:
            if mandatory:
                raise MesonException(f"{argname} mandatory field not found")

            if default is not None:
                return default, default

        return None, None

    def add_extension_paths(self, paths: T.Union[T.List[str], T.Set[str]]) -> None:
        for path in paths:
            if path in self._extra_extension_paths:
                continue

            self._extra_extension_paths.add(path)
            self.cmd.extend(["--extra-extension-path", path])

    def replace_dirs_in_string(self, string: str) -> str:
        return string.replace("@SOURCE_ROOT@", self.sourcedir).replace("@BUILD_ROOT@", self.builddir)

    def process_gi_c_source_roots(self) -> None:
        if self.hotdoc.run_hotdoc(['--has-extension=gi-extension']) != 0:
            return

        value = self.kwargs.pop('gi_c_source_roots')
        value.extend([
            os.path.join(self.sourcedir, self.state.root_subdir),
            os.path.join(self.builddir, self.state.root_subdir)
        ])

        self.cmd += ['--gi-c-source-roots'] + value

    def process_dependencies(self, deps: T.List[T.Union[Dependency, build.StaticLibrary, build.SharedLibrary, CustomTarget, CustomTargetIndex]]) -> T.List[str]:
        cflags = set()
        for dep in mesonlib.listify(ensure_list(deps)):
            if isinstance(dep, InternalDependency):
                inc_args = self.state.get_include_args(dep.include_directories)
                cflags.update([self.replace_dirs_in_string(x)
                               for x in inc_args])
                cflags.update(self.process_dependencies(dep.libraries))
                cflags.update(self.process_dependencies(dep.sources))
                cflags.update(self.process_dependencies(dep.ext_deps))
            elif isinstance(dep, Dependency):
                cflags.update(dep.get_compile_args())
            elif isinstance(dep, (build.StaticLibrary, build.SharedLibrary)):
                self.extra_depends.append(dep)
                for incd in dep.get_include_dirs():
                    cflags.update(incd.get_incdirs())
            elif isinstance(dep, HotdocTarget):
                # Recurse in hotdoc target dependencies
                self.process_dependencies(dep.get_target_dependencies())
                self._subprojects.extend(dep.subprojects)
                self.process_dependencies(dep.subprojects)
                self.include_paths.add(os.path.join(self.builddir, dep.hotdoc_conf.subdir))
                self.cmd += ['--extra-assets=' + p for p in dep.extra_assets]
                self.add_extension_paths(dep.extra_extension_paths)
            elif isinstance(dep, (CustomTarget, build.BuildTarget)):
                self.extra_depends.append(dep)
            elif isinstance(dep, CustomTargetIndex):
                self.extra_depends.append(dep.target)

        return [f.strip('-I') for f in cflags]

    def process_extra_assets(self) -> None:
        self._extra_assets = self.kwargs.pop('extra_assets')

        for assets_path in self._extra_assets:
            self.cmd.extend(["--extra-assets", assets_path])

    def process_subprojects(self) -> None:
        value = self.kwargs.pop('subprojects')

        self.process_dependencies(value)
        self._subprojects.extend(value)

    def flatten_config_command(self) -> T.List[str]:
        cmd = []
        for arg in mesonlib.listify(self.cmd, flatten=True):
            if isinstance(arg, File):
                arg = arg.absolute_path(self.state.environment.get_source_dir(),
                                        self.state.environment.get_build_dir())
            elif isinstance(arg, build.IncludeDirs):
                for inc_dir in arg.get_incdirs():
                    cmd.append(os.path.join(self.sourcedir, arg.get_curdir(), inc_dir))
                    cmd.append(os.path.join(self.builddir, arg.get_curdir(), inc_dir))

                continue
            elif isinstance(arg, (build.BuildTarget, CustomTarget)):
                self.extra_depends.append(arg)
                arg = self.interpreter.backend.get_target_filename_abs(arg)
            elif isinstance(arg, CustomTargetIndex):
                self.extra_depends.append(arg.target)
                arg = self.interpreter.backend.get_target_filename_abs(arg)

            cmd.append(arg)

        return cmd

    def generate_hotdoc_config(self) -> None:
        cwd = os.path.abspath(os.curdir)
        ncwd = os.path.join(self.sourcedir, self.subdir)
        mlog.log('Generating Hotdoc configuration for: ', mlog.bold(self.name))
        os.chdir(ncwd)
        if self.hotdoc.run_hotdoc(self.flatten_config_command()) != 0:
            raise MesonException('hotdoc failed to configure')
        os.chdir(cwd)

    def ensure_file(self, value: T.Union[str, File, CustomTarget, CustomTargetIndex]) -> T.Union[File, CustomTarget, CustomTargetIndex]:
        if isinstance(value, list):
            res = []
            for val in value:
                res.append(self.ensure_file(val))
            return res

        if isinstance(value, str):
            return File.from_source_file(self.sourcedir, self.subdir, value)

        return value

    def ensure_dir(self, value: str) -> str:
        if os.path.isabs(value):
            _dir = value
        else:
            _dir = os.path.join(self.sourcedir, self.subdir, value)

        if not os.path.isdir(_dir):
            raise InvalidArguments(f'"{_dir}" is not a directory.')

        return os.path.relpath(_dir, os.path.join(self.builddir, self.subdir))

    def check_forbidden_args(self) -> None:
        for arg in ['conf_file']:
            if arg in self.kwargs:
                raise InvalidArguments(f'Argument "{arg}" is forbidden.')

    def make_targets(self) -> T.Tuple[HotdocTarget, mesonlib.ExecutableSerialisation]:
        self.check_forbidden_args()
        self.process_known_arg("--index", value_processor=self.ensure_file)
        self.process_known_arg("--project-version")
        self.process_known_arg("--sitemap", value_processor=self.ensure_file)
        self.process_known_arg("--html-extra-theme", value_processor=self.ensure_dir)
        self.include_paths.update(self.ensure_dir(v) for v in self.kwargs.pop('include_paths'))
        self.process_known_arg('--c-include-directories', argname="dependencies", value_processor=self.process_dependencies)
        self.process_gi_c_source_roots()
        self.process_extra_assets()
        self.add_extension_paths(self.kwargs.pop('extra_extension_paths'))
        self.process_subprojects()
        self.extra_depends.extend(self.kwargs.pop('depends'))

        install = self.kwargs.pop('install')
        self.process_extra_args()

        fullname = self.name + '-doc'
        hotdoc_config_name = fullname + '.json'
        hotdoc_config_path = os.path.join(
            self.builddir, self.subdir, hotdoc_config_name)
        with open(hotdoc_config_path, 'w', encoding='utf-8') as f:
            f.write('{}')

        self.cmd += ['--conf-file', hotdoc_config_path]
        self.include_paths.add(os.path.join(self.builddir, self.subdir))
        self.include_paths.add(os.path.join(self.sourcedir, self.subdir))

        depfile = os.path.join(self.builddir, self.subdir, self.name + '.deps')
        self.cmd += ['--deps-file-dest', depfile]

        for path in self.include_paths:
            self.cmd.extend(['--include-path', path])

        if self.state.environment.coredata.get_option(mesonlib.OptionKey('werror', subproject=self.state.subproject)):
            self.cmd.append('--fatal-warnings')
        self.generate_hotdoc_config()

        target_cmd = self.build_command + ["--internal", "hotdoc"] + \
            self.hotdoc.get_command() + ['run', '--conf-file', hotdoc_config_name] + \
            ['--builddir', os.path.join(self.builddir, self.subdir)]

        target = HotdocTarget(fullname,
                              subdir=self.subdir,
                              subproject=self.state.subproject,
                              environment=self.state.environment,
                              hotdoc_conf=File.from_built_file(
                                  self.subdir, hotdoc_config_name),
                              extra_extension_paths=self._extra_extension_paths,
                              extra_assets=self._extra_assets,
                              subprojects=self._subprojects,
                              is_build_only_subproject=self.interpreter.coredata.is_build_only,
                              command=target_cmd,
                              extra_depends=self.extra_depends,
                              outputs=[fullname],
                              sources=[],
                              depfile=os.path.basename(depfile),
                              build_by_default=self.build_by_default)

        install_script = None
        if install:
            datadir = os.path.join(self.state.get_option('prefix'), self.state.get_option('datadir'))
            devhelp = self.kwargs.get('devhelp_activate', False)
            if not isinstance(devhelp, bool):
                FeatureDeprecated.single_use('hotdoc.generate_doc() devhelp_activate must be boolean', '1.1.0', self.state.subproject)
                devhelp = False
            if devhelp:
                install_from = os.path.join(fullname, 'devhelp')
                install_to = os.path.join(datadir, 'devhelp')
            else:
                install_from = os.path.join(fullname, 'html')
                install_to = os.path.join(datadir, 'doc', self.name, 'html')

            install_script = self.state.backend.get_executable_serialisation(self.build_command + [
                "--internal", "hotdoc",
                "--install", install_from,
                "--docdir", install_to,
                '--name', self.name,
                '--builddir', os.path.join(self.builddir, self.subdir)] +
                self.hotdoc.get_command() +
                ['run', '--conf-file', hotdoc_config_name])
            install_script.tag = 'doc'

        return (target, install_script)


class HotdocTargetHolder(_CustomTargetHolder['HotdocTarget']):
    def __init__(self, target: HotdocTarget, interp: Interpreter):
        super().__init__(target, interp)
        self.methods.update({'config_path': self.config_path_method})

    @noPosargs
    @noKwargs
    def config_path_method(self, *args: T.Any, **kwargs: T.Any) -> str:
        conf = self.held_object.hotdoc_conf.absolute_path(self.interpreter.environment.source_dir,
                                                          self.interpreter.environment.build_dir)
        return conf


class HotdocTarget(CustomTarget):
    def __init__(self, name: str, subdir: str, subproject: str, hotdoc_conf: File,
                 extra_extension_paths: T.Set[str], extra_assets: T.List[str],
                 subprojects: T.List['HotdocTarget'], environment: Environment,
                 is_build_only_subproject: bool, **kwargs: T.Any):
        super().__init__(name, subdir, subproject, environment, **kwargs, build_only_subproject=is_build_only_subproject, absolute_paths=True)
        self.hotdoc_conf = hotdoc_conf
        self.extra_extension_paths = extra_extension_paths
        self.extra_assets = extra_assets
        self.subprojects = subprojects

    def __getstate__(self) -> dict:
        # Make sure we do not try to pickle subprojects
        res = self.__dict__.copy()
        res['subprojects'] = []

        return res


class HotDocModule(ExtensionModule):

    INFO = ModuleInfo('hotdoc', '0.48.0')

    def __init__(self, interpreter: Interpreter):
        super().__init__(interpreter)
        self.hotdoc = HotdocExternalProgram('hotdoc')
        if not self.hotdoc.found():
            raise MesonException('hotdoc executable not found')
        version = self.hotdoc.get_version(interpreter)
        if not mesonlib.version_compare(version, f'>={MIN_HOTDOC_VERSION}'):
            raise MesonException(f'hotdoc {MIN_HOTDOC_VERSION} required but not found.)')

        self.methods.update({
            'has_extensions': self.has_extensions,
            'generate_doc': self.generate_doc,
        })

    @noKwargs
    @typed_pos_args('hotdoc.has_extensions', varargs=str, min_varargs=1)
    def has_extensions(self, state: ModuleState, args: T.Tuple[T.List[str]], kwargs: TYPE_kwargs) -> bool:
        return self.hotdoc.run_hotdoc([f'--has-extension={extension}' for extension in args[0]]) == 0

    @typed_pos_args('hotdoc.generate_doc', str)
    @typed_kwargs(
        'hotdoc.generate_doc',
        KwargInfo('sitemap', file_types, required=True),
        KwargInfo('index', file_types, required=True),
        KwargInfo('project_version', str, required=True),
        KwargInfo('html_extra_theme', (str, NoneType)),
        KwargInfo('include_paths', ContainerTypeInfo(list, str), listify=True, default=[]),
        # --c-include-directories
        KwargInfo(
            'dependencies',
            ContainerTypeInfo(list, (Dependency, build.StaticLibrary, build.SharedLibrary,
                                     CustomTarget, CustomTargetIndex)),
            listify=True,
            default=[],
        ),
        KwargInfo(
            'depends',
            ContainerTypeInfo(list, (CustomTarget, CustomTargetIndex)),
            listify=True,
            default=[],
            since='0.64.1',
        ),
        KwargInfo('gi_c_source_roots', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('extra_assets', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('extra_extension_paths', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('subprojects', ContainerTypeInfo(list, HotdocTarget), listify=True, default=[]),
        KwargInfo('install', bool, default=False),
        allow_unknown=True
    )
    def generate_doc(self, state: ModuleState, args: T.Tuple[str], kwargs: GenerateDocKwargs) -> ModuleReturnValue:
        project_name = args[0]
        if any(isinstance(x, (CustomTarget, CustomTargetIndex)) for x in kwargs['dependencies']):
            FeatureDeprecated.single_use('hotdoc.generate_doc dependencies argument with custom_target',
                                         '0.64.1', state.subproject, 'use `depends`', state.current_node)
        builder = HotdocTargetBuilder(project_name, state, self.hotdoc, self.interpreter, kwargs)
        target, install_script = builder.make_targets()
        targets: T.List[T.Union[HotdocTarget, mesonlib.ExecutableSerialisation]] = [target]
        if install_script:
            targets.append(install_script)

        return ModuleReturnValue(target, targets)


def initialize(interpreter: Interpreter) -> HotDocModule:
    mod = HotDocModule(interpreter)
    mod.interpreter.append_holder_map(HotdocTarget, HotdocTargetHolder)
    return mod
```