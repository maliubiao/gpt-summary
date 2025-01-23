Response:
Let's break down the thought process for analyzing this Python code and extracting the requested information.

1. **Understanding the Goal:** The core request is to understand the functionality of the `hotdoc.py` file within the Frida project. The request specifically asks about its relation to reverse engineering, low-level details, logic, potential errors, and how a user might reach this code.

2. **Initial Skim for High-Level Overview:**  The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "hotdoc," "documentation," "generate," "sitemap," "index," and "project_version" immediately suggest that this file is responsible for generating documentation using the Hotdoc tool. The presence of `subprocess` hints at interaction with external commands.

3. **Identifying Key Classes and Functions:** Next, I'd identify the major structural components:
    * **`HotdocExternalProgram`:**  Clearly a wrapper around the external `hotdoc` command.
    * **`HotdocTargetBuilder`:** This class seems to be the core logic for configuring and setting up the Hotdoc documentation generation process. It handles arguments, dependencies, and command construction.
    * **`HotdocTargetHolder` and `HotdocTarget`:** These likely represent the internal representation of the documentation build target within the Meson build system. `HotdocTargetHolder` suggests a way to interact with `HotdocTarget` objects from the Meson interpreter.
    * **`HotDocModule`:** This appears to be the main entry point for this module, registering the functionality with the Meson build system. The `generate_doc` method within this class is the primary function exposed to users.

4. **Analyzing Functionality (Focus on `HotdocTargetBuilder` and `HotDocModule.generate_doc`):**  The `HotdocTargetBuilder` class warrants deeper inspection because it contains the core logic. I'd examine its methods:
    * **`__init__`:**  Initialization, storing state, and setting up the basic `hotdoc conf` command.
    * **`process_known_arg`, `set_arg_value`:** Handling known arguments for the `hotdoc conf` command.
    * **`process_extra_args`:** Handling any additional, user-defined arguments.
    * **`process_dependencies`:**  Crucial for understanding how the documentation build incorporates information from other parts of the project. The handling of `InternalDependency`, `Dependency`, `StaticLibrary`, `SharedLibrary`, `CustomTarget`, and even other `HotdocTarget` instances is important.
    * **`generate_hotdoc_config`:**  Executing the `hotdoc conf` command.
    * **`make_targets`:**  The final stage where the `HotdocTarget` object is created, and the actual build command is constructed.

   Similarly, analyzing `HotDocModule.generate_doc` reveals how users interact with this module. It shows the expected arguments and how they are passed to the `HotdocTargetBuilder`.

5. **Connecting to the Requested Information:** Now, I'd systematically go through each part of the request:

    * **Functionality:** This is largely covered by the analysis of the key classes and methods. I'd summarize the main tasks performed by the module.

    * **Relation to Reverse Engineering:** This requires thinking about how documentation is relevant in reverse engineering. Specifically, API documentation is key. Frida is a dynamic instrumentation tool, so documenting its own APIs or the APIs of target applications is highly relevant for reverse engineers using Frida.

    * **Binary/Low-Level, Linux/Android Kernel/Framework:** The code itself doesn't directly manipulate binaries or kernel internals. However, the *purpose* of the documentation is often to describe such low-level aspects. The `gi_c_source_roots` argument suggests that this module might be used to generate documentation for GObject-based libraries, which are common in Linux and Android frameworks. The dependency handling can also pull in information about libraries used in the target system.

    * **Logic/Inference:** Look for conditional statements and how inputs are transformed into outputs. The `process_dependencies` method, which recursively handles dependencies, involves logical steps. The handling of different argument types and the construction of the command-line arguments involve conditional logic. I'd create a simple hypothetical example of input arguments and the resulting `hotdoc conf` command.

    * **User/Programming Errors:** Consider what could go wrong from a user's perspective. Incorrect file paths, missing dependencies, wrong argument types, and incompatible Hotdoc versions are likely candidates.

    * **User Path to the Code (Debugging Clues):** This requires understanding how Meson works. A user would typically call a Meson function (in this case, `hotdoc.generate_doc`) in their `meson.build` file. When Meson processes this file, it will load and execute this Python module. I'd outline the steps involved in the build process that lead to this code being executed.

6. **Structuring the Answer:** Finally, organize the extracted information into a clear and well-structured answer, using headings and bullet points for readability. Provide specific examples where requested. Ensure the language is clear and concise. Use code snippets where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Perhaps the module directly interacts with binaries.
* **Correction:**  Upon closer inspection, it's clear the module *generates documentation about* binaries and low-level concepts, but doesn't manipulate them directly. The interaction is via the `hotdoc` tool and the information provided in the build configuration.

* **Initial Thought:** Focus only on the Python code itself.
* **Correction:**  The request asks about the *purpose* and *context* of the code within the Frida project. Therefore, understanding Frida's role and how documentation fits into that is crucial.

By following these steps, iteratively refining understanding, and focusing on the specific questions asked, a comprehensive and accurate answer can be constructed.
This Python code file, `hotdoc.py`, is a module for the Meson build system that provides functionality to generate documentation using the Hotdoc documentation generator. Let's break down its functions and how they relate to your questions:

**Functionality of `hotdoc.py`:**

1. **Provides a Meson interface for Hotdoc:**  It acts as a bridge between the Meson build system and the Hotdoc tool. This allows developers using Meson to easily integrate Hotdoc into their build process for generating documentation.

2. **Configures Hotdoc:** It takes various parameters as input from the Meson build definition (e.g., project name, version, input files, dependencies) and uses them to generate a Hotdoc configuration file. This configuration tells Hotdoc how to build the documentation.

3. **Runs Hotdoc:** It executes the Hotdoc command-line tool with the generated configuration to build the actual documentation (typically HTML).

4. **Handles Dependencies:** It can manage dependencies of the documentation, including other libraries, source code, and even other Hotdoc documentation projects. This ensures that Hotdoc has all the necessary information to build the documentation correctly.

5. **Supports Installation:**  It can define installation rules to copy the generated documentation to the appropriate location during the installation process.

6. **Supports Extensions:** It has functionality to check for and use Hotdoc extensions, like the `gi-extension` for generating documentation from GObject introspection data.

**Relation to Reverse Engineering:**

* **Documenting APIs for Frida:** This module is part of Frida itself. Frida is a powerful dynamic instrumentation toolkit heavily used in reverse engineering. This `hotdoc.py` file is very likely used to generate the official Frida documentation, which is crucial for reverse engineers learning how to use Frida's APIs to hook functions, inspect memory, and analyze running processes. Good API documentation is essential for effectively using a tool like Frida in a reverse engineering context.

    **Example:** A reverse engineer might want to find out how to use Frida's `Interceptor.attach()` function to intercept a specific function call in an Android application. They would consult the Frida documentation generated using tools like Hotdoc (and potentially this very `hotdoc.py` module).

* **Documenting Instrumented Code:** While this specific module doesn't directly *perform* reverse engineering, the documentation it generates can be about code that is often the target of reverse engineering. For instance, Frida might document its own internal APIs or provide examples of instrumenting specific libraries or frameworks.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **`gi_c_source_roots`:** This argument specifically points to C source code directories used by the GObject introspection system. GObject is a fundamental part of the GNOME desktop environment and is also heavily used in the Android framework (especially for system services and hardware abstraction layers via Binder). This suggests that Frida's documentation might cover aspects of interacting with or instrumenting code that uses GObject, which often involves low-level concepts and knowledge of Linux/Android system architecture.

    **Example:** Documenting how to use Frida to hook a method in an Android system service implemented using GObject would require understanding the structure of GObject objects and how method calls are dispatched.

* **Dependencies on Libraries:** The module can handle dependencies on shared and static libraries. In the context of Frida, this could involve documenting how Frida interacts with or instruments low-level libraries on Linux or Android.

    **Example:**  Documenting how Frida can be used to inspect the internal state of a native library used in an Android application would require understanding the binary layout of shared libraries (`.so` files) and potentially the calling conventions used.

* **Building for Different Platforms:** While not directly in this code, the fact that Frida targets multiple platforms (including Linux and Android) means the documentation generated might need to cover platform-specific details relevant to reverse engineering on those systems.

**Logic and Inference (Hypothetical Input and Output):**

Let's assume the following simplified input in a `meson.build` file:

```meson
hotdoc = import('hotdoc')

hotdoc.generate_doc(
  'MyProject',
  sitemap: 'sitemap.xml',
  index: 'index.md',
  project_version: '1.0',
  include_paths: ['include'],
  dependencies: libfoo, # Assuming libfoo is a declared library
)
```

**Assumed Input:**

* `project_name`: "MyProject"
* `sitemap`:  A file named "sitemap.xml" in the source directory.
* `index`: A file named "index.md" in the source directory.
* `project_version`: "1.0"
* `include_paths`: A list containing the string "include".
* `dependencies`: A Meson dependency object representing a library named `libfoo`.

**Logical Steps within `hotdoc.py`:**

1. **Initialization:** The `HotdocTargetBuilder` is created with the provided arguments.
2. **Processing Known Arguments:**  The `sitemap`, `index`, and `project_version` are processed, and corresponding command-line arguments are added to the `self.cmd` list (e.g., `--sitemap=...`, `--index=...`).
3. **Processing Include Paths:** The `include_paths` are processed, and `--include-path` arguments are added to `self.cmd`.
4. **Processing Dependencies:**
   - If `libfoo` is an `InternalDependency`, the module might extract include directories and compile flags from it and add them to the Hotdoc configuration.
   - If `libfoo` is a `StaticLibrary` or `SharedLibrary`, the module might add its include directories to the include paths for Hotdoc.
5. **Generating Hotdoc Configuration:** The `generate_hotdoc_config()` method is called. This will execute `hotdoc conf` with the constructed `self.cmd` list, creating a `MyProject-doc.json` file in the build directory. This JSON file contains the configuration for the actual documentation build.
6. **Creating the Build Target:** The `make_targets()` method creates a `HotdocTarget` which represents the documentation build process. This target will have a command that executes `hotdoc run` using the generated configuration file.

**Hypothetical Output (Key elements of the `self.cmd` list before `generate_hotdoc_config`):**

```
['conf',
 '--project-name', 'MyProject',
 '--disable-incremental-build',
 '--output', '.../builddir/frida/subprojects/frida-gum/releng/meson/MyProject-doc',  // Output directory
 '--sitemap=.../sourcedir/frida/subprojects/frida-gum/releng/meson/sitemap.xml',
 '--index=.../sourcedir/frida/subprojects/frida-gum/releng/meson/index.md',
 '--project-version=1.0',
 '--include-path', '.../sourcedir/frida/subprojects/frida-gum/releng/meson/include',
 # ... potentially more include paths from libfoo ...
 '--conf-file', '.../builddir/frida/subprojects/frida-gum/releng/meson/MyProject-doc.json',
 '--deps-file-dest', '.../builddir/frida/subprojects/frida-gum/releng/meson/MyProject.deps',
 # ... potentially more include paths from dependencies ...
]
```

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:** Providing an incorrect path to the sitemap or index file.

   **Example:**  `sitemap: 'wrong_path/sitemap.xml'` when `sitemap.xml` is in the current directory. This would likely lead to Hotdoc failing to find the input files.

2. **Missing Dependencies:** Not declaring all necessary dependencies in the `dependencies` argument.

   **Example:** If the documentation needs information from headers in `libbar`, but `libbar` is not included in the `dependencies` list, Hotdoc might not be able to find those headers, leading to build errors or incomplete documentation.

3. **Incorrect Argument Types:** Providing an argument of the wrong type.

   **Example:** `project_version: 1.0` (a float instead of a string). Meson's type checking should catch this, but if not, it could cause issues in the Hotdoc configuration.

4. **Incompatible Hotdoc Version:** Using a version of Hotdoc that is too old. The code explicitly checks for a minimum Hotdoc version (`MIN_HOTDOC_VERSION`). If the installed Hotdoc version is older, Meson will throw an error.

5. **Typos in Argument Names:**  Misspelling keyword arguments like `include_paths` as `inclue_paths`. Meson would likely report an error about an unexpected keyword argument.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Developer Adds Documentation Logic:** A developer working on the Frida project decides to add or update the documentation for a specific part of the Frida Gum library.
2. **Editing `meson.build`:** They would modify the `meson.build` file within the `frida/subprojects/frida-gum/releng/meson/` directory (or a subdirectory).
3. **Using the `hotdoc.generate_doc()` function:** They would call the `hotdoc.generate_doc()` function from this module, providing the necessary arguments like sitemap, index, project version, and dependencies.
4. **Running Meson:** The developer then runs the Meson command to configure the build: `meson setup build`.
5. **Meson Executes `hotdoc.py`:** During the configuration phase, Meson encounters the `import('hotdoc')` statement and the `hotdoc.generate_doc()` call in the `meson.build` file. This causes Meson to load and execute the `hotdoc.py` module.
6. **`generate_doc()` is Called:** The `generate_doc()` function within the `HotDocModule` class is executed with the arguments provided in the `meson.build` file.
7. **`HotdocTargetBuilder` is Used:**  The `generate_doc()` function creates an instance of `HotdocTargetBuilder` to handle the configuration and execution of Hotdoc.
8. **Hotdoc Configuration and Execution:** The `HotdocTargetBuilder` methods are called to generate the Hotdoc configuration and define the build target that will run the Hotdoc command.
9. **Building the Documentation:**  When the developer runs the build command (e.g., `ninja`), Ninja will execute the custom target defined by `HotdocTarget`, which in turn runs the Hotdoc command-line tool to generate the documentation.

If there's an issue with the documentation build, a developer debugging the process might:

* **Examine the `meson.build` file:** To check the arguments passed to `hotdoc.generate_doc()`.
* **Inspect the generated `MyProject-doc.json` file:** To see the actual Hotdoc configuration that was created.
* **Run the Hotdoc command manually:** To isolate if the issue is with Meson or Hotdoc itself.
* **Set breakpoints or add print statements in `hotdoc.py`:** To trace the execution flow and inspect the values of variables during the Meson configuration phase.

Therefore, the path to this code starts with the developer's intention to generate documentation within the Meson build system and involves the execution of Meson parsing the `meson.build` file and invoking the functionality provided by this `hotdoc.py` module.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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