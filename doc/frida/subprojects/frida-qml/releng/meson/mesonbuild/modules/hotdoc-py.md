Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for the functionality of this `hotdoc.py` file within the context of the Frida dynamic instrumentation tool. It also specifically asks about its relationship to reverse engineering, low-level details, logic, user errors, and debugging.

2. **Identify the Core Purpose:**  The module's name (`hotdoc`) and the import statement `# Copyright 2018 The Meson development team` immediately suggest this is related to documentation generation, specifically using a tool called "hotdoc". The code itself confirms this with functions like `generate_doc` and the interaction with the `hotdoc` external program.

3. **Deconstruct the Code by Sections:**  I'll mentally (or physically) divide the code into logical blocks:

    * **Imports:**  These indicate the module's dependencies. I see standard Python libraries (`os`, `subprocess`, `typing`) and Meson-specific ones (`.`, `..`, `build`, `mesonlib`, `mlog`, `dependencies`, `interpreterbase`, `interpreter`, `programs`). This tells me it's a Meson module for documentation.

    * **Constants:** `MIN_HOTDOC_VERSION` is important – it defines the minimum required version of the external `hotdoc` tool.

    * **Helper Functions:** `ensure_list` is a simple utility for handling single values vs. lists.

    * **`HotdocExternalProgram` Class:** This encapsulates the interaction with the external `hotdoc` command-line tool. The `run_hotdoc` method is the key here.

    * **`HotdocTargetBuilder` Class:** This is the most complex part. It handles the configuration and setup of the hotdoc documentation generation process. I'll need to pay close attention to its methods.

    * **`HotdocTargetHolder` Class:** This seems to be a Meson-specific class for managing `HotdocTarget` instances within the Meson build system. The `config_path_method` provides a specific functionality.

    * **`HotdocTarget` Class:** This likely represents the actual documentation target within the Meson build. It inherits from `CustomTarget`.

    * **`HotDocModule` Class:** This is the main entry point for the Meson module. It initializes the `hotdoc` external program and defines the module's exposed methods (`has_extensions`, `generate_doc`).

    * **`initialize` Function:**  This is the standard Meson module initialization function.

4. **Analyze Key Functionality (Focus on `HotdocTargetBuilder` and `HotDocModule.generate_doc`):**

    * **`HotdocTargetBuilder`:**  I'll go through the methods:
        * `__init__`:  Sets up the basic configuration. The `cmd` list is where the hotdoc configuration commands are built.
        * `process_known_arg`, `set_arg_value`: Handle specific hotdoc options.
        * `process_extra_args`:  Handles arbitrary hotdoc options passed by the user.
        * `get_value`:  Retrieves values from the `kwargs`.
        * `add_extension_paths`, `replace_dirs_in_string`, `process_gi_c_source_roots`, `process_dependencies`, `process_extra_assets`, `process_subprojects`: These methods are crucial for understanding how dependencies, include paths, and other resources are handled for the documentation. The `process_dependencies` method is particularly interesting as it recursively handles dependencies.
        * `flatten_config_command`: Converts the command arguments into a flat list suitable for execution.
        * `generate_hotdoc_config`:  Executes the `hotdoc conf` command.
        * `ensure_file`, `ensure_dir`:  Utility functions for validating file and directory arguments.
        * `check_forbidden_args`: Prevents users from using specific arguments.
        * `make_targets`: Orchestrates the entire process, creating the `HotdocTarget` and potentially an installation script.

    * **`HotDocModule.generate_doc`:**  This is the main entry point for users. It takes arguments related to documentation and uses the `HotdocTargetBuilder` to create the documentation target. The `@typed_kwargs` decorator tells me the expected arguments and their types.

5. **Connect to the Request's Specific Points:**

    * **Functionality:**  Based on the analysis above, I can summarize the main functions: configure hotdoc, run hotdoc, handle dependencies, install documentation.

    * **Reverse Engineering:** This is where the connection isn't *direct* but lies in the *purpose* of Frida. Frida helps in understanding software behavior. Good documentation is crucial for that. So, while this module *generates* documentation, its output helps in reverse engineering efforts. I need to think of concrete examples (API docs, architecture overviews).

    * **Binary/Low-Level:**  Again, not a direct interaction, but the *subject* of the documentation likely includes low-level APIs, data structures, etc., relevant to Frida's internals or the systems it instruments. `gi_c_source_roots` hints at documenting C code, which often has low-level aspects.

    * **Linux/Android Kernel/Framework:** Similar to the binary point, if Frida's documentation covers interactions with the Linux or Android kernel, then this module indirectly relates. The mention of `gi-extension` suggests potential documentation of GObject Introspection, which is common in Linux/GNOME development.

    * **Logic/Assumptions:**  I need to think about what inputs the `generate_doc` function expects and what the outputs would be. The `HotdocTargetBuilder` performs logical steps to build the hotdoc configuration. I can create hypothetical input and output scenarios.

    * **User Errors:**  The `check_forbidden_args`, type checking in `process_known_arg`, and the validation in `ensure_file` and `ensure_dir` point to potential user errors. I can think of examples like providing an incorrect file path or using a forbidden argument.

    * **User Journey/Debugging:** I need to explain how a user might end up interacting with this code. This involves the Meson build system and the steps a developer would take to generate documentation for their Frida-related project. The debugging aspect involves understanding how Meson invokes this module and how errors might surface.

6. **Structure the Output:** I'll organize the information according to the request's categories, providing clear explanations and examples for each. I need to ensure I address all the points raised in the initial request. Using bullet points and clear headings will make the explanation easier to read.

7. **Review and Refine:**  After drafting the initial response, I'll reread it to ensure accuracy, clarity, and completeness. I'll double-check the code snippets and examples to make sure they are relevant. I'll also make sure I haven't made any incorrect assumptions about the code's functionality. For example, initially, I might overemphasize the direct interaction with the kernel, but upon closer inspection, the module's focus is on *generating documentation about* such interactions, not performing them directly.
This Python code defines a Meson module named `hotdoc` which integrates the `hotdoc` documentation generator into the Meson build system. Let's break down its functionalities and connections to the requested topics.

**Core Functionality:**

The primary function of this module is to allow projects built with Meson to easily generate documentation using the `hotdoc` tool. It provides a `generate_doc` method that takes various parameters specifying the documentation to be built and configures `hotdoc` accordingly.

Here's a breakdown of the key functionalities:

1. **Integration with `hotdoc`:** It wraps the execution of the external `hotdoc` command-line tool (`hotdoc conf` for configuration and `hotdoc run` for building). It checks for the presence and minimum required version of `hotdoc`.
2. **Configuration Generation:** It takes various arguments (like sitemap, index page, project version, theme, include paths, dependencies) and translates them into command-line arguments for the `hotdoc conf` command.
3. **Dependency Management:** It handles dependencies specified as other Meson targets (libraries, custom targets) or external dependencies. It extracts include directories and potentially other relevant information from these dependencies to inform `hotdoc`.
4. **Customization:** It allows for various customizations like specifying extra assets, extra extension paths for `hotdoc`, and handling subprojects that also generate documentation with `hotdoc`.
5. **Installation:** It provides an option to install the generated documentation to the system's data directory.
6. **Build System Integration:** It creates a custom target within the Meson build system that represents the documentation generation process. This ensures that the documentation is built when the project is built.
7. **Subproject Support:** It allows including documentation from subprojects into the main project's documentation.

**Relationship to Reverse Engineering:**

While this module doesn't directly perform reverse engineering, it's **crucially important for the results of reverse engineering efforts**. Good documentation, often generated using tools like `hotdoc`, is essential for understanding the structure, APIs, and functionality of software that has been reverse-engineered.

**Example:**

Imagine someone is reverse-engineering a closed-source library used by Frida. If the developers of that library had used `hotdoc` to generate API documentation, a reverse engineer could potentially:

* **Analyze the generated HTML files:**  Explore the documented functions, classes, and data structures to get a high-level understanding of the library's purpose and how its components interact.
* **Examine the sitemap and index:** Quickly navigate through the documentation to find specific information.
* **Look for documented data types and structures:** Gain insights into the library's internal workings, which can be valuable for tasks like crafting custom Frida scripts to interact with it.

In the context of Frida itself, this `hotdoc.py` module is likely used to generate the official Frida documentation, which is an invaluable resource for users trying to understand Frida's APIs and how to use it for dynamic instrumentation and, consequently, reverse engineering.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This module interacts with these areas indirectly through the documentation it helps generate.

* **Binary Bottom:** The documentation generated might describe the binary interface of libraries, data structures in memory, or low-level interactions. The `gi_c_source_roots` option suggests it can generate documentation from C source code, which often deals with low-level concepts.
* **Linux/Android Kernel & Framework:** If Frida's documentation covers how to instrument code running within the Linux kernel or Android framework, then this module is involved in generating that documentation. The documentation could describe kernel APIs, system calls, or framework components that Frida can interact with.
* **Dependencies:** The module handles dependencies, and these dependencies might be libraries that directly interact with the kernel or low-level system components. The documentation for those libraries would then be included.

**Example:**

The Frida documentation might explain how to use Frida to intercept system calls on Linux. This documentation, potentially generated by `hotdoc.py`, would inherently involve knowledge of the Linux kernel and its system call interface.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input (arguments to `generate_doc`):**

```python
meson.get_compiler('c').create_library('mylib', 'mylib.c', install : true)

hotdoc = import('hotdoc')
hotdoc.generate_doc(
  'My Project',
  sitemap: files('sitemap.xml'),
  index: files('index.md'),
  project_version: meson.project_version(),
  dependencies: [meson.get_建成目标('mylib')],
  include_paths: ['include'],
  install: true
)
```

**Assumptions:**

* `sitemap.xml` and `index.md` exist in the source directory.
* `mylib` is a C library being built by Meson.
* The `include` directory in the source root contains header files for `mylib`.

**Likely Output (actions performed by the module):**

1. **`hotdoc conf` execution:** The module would execute `hotdoc conf` with arguments derived from the input. This would likely include:
   - `--project-name=My Project`
   - `--project-version=<project version from meson>`
   - `--sitemap=<path to sitemap.xml>`
   - `--index=<path to index.md>`
   - `--include-path=<path to the 'include' directory>`
   - `--c-include-directories=<path to the include directory of mylib>` (This is inferred from the `dependencies` argument).
   - `--output=<path to the documentation output directory>`
2. **`hotdoc run` execution:** After successful configuration, the module would execute `hotdoc run` to build the documentation.
3. **Meson Custom Target:** A Meson custom target named something like `my-project-doc` would be created, depending on the build of `mylib`. This ensures the documentation is built after the library.
4. **Installation (if `install: true`):** The generated HTML documentation would be copied to the appropriate installation directory (e.g., `/usr/share/doc/my-project/html`).

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:** Providing incorrect paths to the sitemap, index, or extra assets.
   ```python
   hotdoc.generate_doc('My Project', sitemap: 'wrong_sitemap.xml', ...) # File doesn't exist
   ```
   **Error:** `InvalidArguments: "wrong_sitemap.xml" does not exist.` (or a similar error from `hotdoc`).

2. **Missing Dependencies:** Not specifying all necessary dependencies for the documented code.
   ```python
   # mylib_doc.c uses functions from another_lib, but it's not listed as a dependency
   hotdoc.generate_doc('My Project', ..., gi_c_source_roots: ['.'])
   ```
   **Error:** The generated documentation might have unresolved references or warnings from `hotdoc` about missing symbols.

3. **Incorrect `hotdoc` Version:** Running Meson with an older version of `hotdoc` than the minimum required.
   **Error:** `MesonException: hotdoc 0.8.100 required but not found.)`

4. **Type Mismatches in Arguments:** Providing arguments of the wrong type (e.g., passing an integer where a string is expected).
   ```python
   hotdoc.generate_doc('My Project', project_version: 123, ...) # project_version should be a string
   ```
   **Error:** `mesonlib.MesonException: project_version field value 123 is not valid, valid types are [<class 'str'>]`

5. **Forbidden Arguments:** Trying to use arguments that are explicitly disallowed by the module.
   ```python
   hotdoc.generate_doc('My Project', conf_file: 'my_hotdoc.ini', ...) # conf_file is forbidden
   ```
   **Error:** `InvalidArguments: Argument "conf_file" is forbidden.`

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Project Configuration:** A developer working on Frida or a Frida-related project includes the `hotdoc` Meson module in their `meson.build` file.
   ```python
   hotdoc = import('hotdoc')
   ```
2. **Documentation Generation Definition:** The developer calls the `hotdoc.generate_doc()` function in their `meson.build` to define how the documentation should be generated.
3. **Meson Execution:** The developer runs Meson to configure the build system (e.g., `meson setup build`).
4. **Meson Processing:** When Meson processes the `meson.build` file, it encounters the `import('hotdoc')` statement and loads the `hotdoc.py` module.
5. **`generate_doc` Call:** Meson executes the `hotdoc.generate_doc()` call, passing the provided arguments. This is where the logic in `hotdoc.py` comes into play.
6. **Configuration and Target Creation:** The `HotdocTargetBuilder` class within `hotdoc.py` is used to process the arguments, generate the `hotdoc` configuration command, and create a Meson custom target for the documentation build.
7. **Build Execution:** When the developer builds the project (e.g., `ninja -C build`), Ninja will execute the custom target created by the `hotdoc` module, which in turn runs the `hotdoc` commands.

**Debugging Scenarios:**

* **Documentation Not Building:** If the documentation isn't being generated, the developer might:
    * **Check Meson Output:** Look for errors or warnings related to the `hotdoc` module during the Meson configuration or build process.
    * **Examine the `meson.build`:** Verify the correctness of the arguments passed to `hotdoc.generate_doc()`.
    * **Run `hotdoc` Manually:** Try running the `hotdoc conf` and `hotdoc run` commands manually with similar arguments to isolate issues with the `hotdoc` tool itself.
    * **Inspect the Generated Configuration:** Look at the `hotdoc config` file generated by the module (e.g., `*-doc.json`) to see if the configuration is as expected.
* **Incorrect Documentation:** If the documentation is generated but has errors or is missing content, the developer might:
    * **Check `hotdoc` Warnings:** Look for warnings generated by `hotdoc` during the build process.
    * **Verify Dependencies:** Ensure all necessary dependencies are correctly specified.
    * **Examine Source Files:** Check the source files being documented for any issues that might cause `hotdoc` to fail or produce incorrect output.

This detailed breakdown illustrates the functionalities of the `hotdoc.py` module within the Frida project's build system and its connections to reverse engineering, low-level concepts, and potential user errors.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```