Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Understanding the Goal:**

The core goal is to understand the functionality of the `hotdoc.py` module within the Frida project. The prompt specifically asks about its relation to reverse engineering, low-level aspects, logical reasoning, common user errors, and how users reach this code.

**2. Initial Code Scan and High-Level Understanding:**

* **Module Name:** `hotdoc.py` strongly suggests it's related to generating documentation using a tool named "hotdoc".
* **Imports:**  The imports provide crucial clues:
    * `subprocess`:  Indicates external program execution (likely hotdoc itself).
    * `os`: File system operations.
    * `typing`: Type hinting for better code readability and maintainability.
    * `mesonbuild.*`:  This immediately tells us this module is part of the Meson build system. This is key context.
    * `build`, `mesonlib`, `mlog`, `dependencies`, `interpreterbase`, `interpreter`, `programs`: These imports point to core Meson concepts and objects.
* **Class `HotdocExternalProgram`:**  This class seems to be a wrapper around the `hotdoc` executable. It simplifies running hotdoc commands.
* **Class `HotdocTargetBuilder`:** This is the heart of the module. It's responsible for configuring and setting up the hotdoc documentation generation process. Keywords like `conf`, `output`, `include_paths`, `dependencies`, `extra_assets`, `install` jump out.
* **Class `HotdocTarget`:** Represents the output of the hotdoc process – the generated documentation itself, treated as a custom target within Meson.
* **Class `HotDocModule`:** This is the Meson module that exposes the functionality to the `meson.build` files. The `generate_doc` method is the primary entry point.

**3. Deconstructing Key Functionality (Mental Walkthrough of `HotdocTargetBuilder`):**

I mentally stepped through the `HotdocTargetBuilder` class, focusing on the key methods:

* **`__init__`:** Sets up the basic configuration, taking in arguments and initializing lists/sets.
* **`process_known_arg` and `set_arg_value`:** These handle the standard hotdoc options (like sitemap, index, version).
* **`process_extra_args`:**  Allows passing arbitrary hotdoc options.
* **`process_gi_c_source_roots`:**  Specifically handles options related to generating documentation from C source code with GObject introspection.
* **`process_dependencies`:** This is *very* important. It iterates through dependencies (libraries, other targets, etc.) and extracts information (include paths, compile flags) to pass to hotdoc. This is where reverse engineering relevance might lie.
* **`process_extra_assets` and `process_subprojects`:** Handle additional files and documentation from other hotdoc projects.
* **`flatten_config_command`:**  Prepares the command-line arguments for the hotdoc `conf` command. It handles different types of arguments (files, include directories, build targets).
* **`generate_hotdoc_config`:** Executes the `hotdoc conf` command.
* **`make_targets`:** Orchestrates the entire process: processing arguments, generating the hotdoc configuration, and creating the Meson `CustomTarget` to build the documentation.

**4. Connecting to the Prompt's Questions:**

Now, I explicitly address each part of the prompt:

* **Functionality:**  Summarize the core purpose: generating documentation using hotdoc, driven by Meson. List the key options it handles.
* **Reverse Engineering:** Look for clues related to analyzing existing software. The `process_dependencies` method is the key. If the documentation includes information about internal APIs or data structures of libraries Frida might interact with (especially through its Swift bridge), then generating this documentation *could* indirectly aid reverse engineering efforts. However, *this module itself doesn't perform reverse engineering*. It documents. The example of documenting Frida's internal Swift API is relevant.
* **Binary/Low-Level/Kernel/Framework:**  Look for interactions with compiled code or system-level components. Again, `process_dependencies` is important. If the documented libraries interact with the kernel or Android framework, that connection exists. The GObject introspection feature (`process_gi_c_source_roots`) is relevant here, as it's often used for documenting system libraries. The example of documenting Swift code that interacts with the Android framework illustrates this.
* **Logical Reasoning (Hypothetical Input/Output):** Choose a simple scenario. Providing a sitemap and index file should result in hotdoc being configured with those options. The output is the command executed by Meson.
* **User/Programming Errors:** Think about common mistakes when using a documentation generator. Incorrect file paths, missing dependencies, and typos are likely.
* **User Path to this Code (Debugging Clue):** Start from the user interacting with Meson. They'd use the `hotdoc.generate_doc()` function in their `meson.build` file. Meson would then execute this Python code.

**5. Structuring the Answer:**

Organize the findings logically, mirroring the prompt's structure. Use clear headings and bullet points for readability. Provide specific code snippets where relevant. Use examples to illustrate the connections to reverse engineering and low-level aspects.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this module *directly* interfaces with binaries.
* **Correction:**  It's more accurate to say it gathers information *about* dependencies, which *could* be binaries or libraries interacting with low-level systems. The documentation itself is the output.
* **Refinement:**  Emphasize the *indirect* link to reverse engineering. It doesn't reverse engineer; it documents things that might be targets of reverse engineering.

By following this structured approach, combining code analysis with an understanding of the broader context (Meson, Frida's purpose), and explicitly addressing each part of the prompt, I can generate a comprehensive and accurate answer.
This Python code defines a Meson module for generating documentation using the `hotdoc` tool. Let's break down its functionality and connections to the concepts you mentioned.

**Functionality of `hotdoc.py`:**

The primary function of this module is to integrate the `hotdoc` documentation generator into the Meson build system. It allows developers to easily generate documentation for their projects as part of the build process. Here's a breakdown of its key capabilities:

1. **Finds and Validates Hotdoc:** It checks if the `hotdoc` executable is available and meets the minimum required version (`MIN_HOTDOC_VERSION`).
2. **Configures Hotdoc:** It provides a `generate_doc` function that takes various parameters to configure how `hotdoc` should generate the documentation. This includes:
    * **Basic Project Information:** Project name, version.
    * **Input Files:** Sitemap and index files (likely Markdown or other supported formats).
    * **Themes:** Applying custom HTML themes.
    * **Include Paths:** Specifying directories containing files to be included in the documentation.
    * **Dependencies:**  Handling dependencies on other libraries, static libraries, shared libraries, and even other `hotdoc` targets. This is crucial for linking documentation across projects.
    * **Extra Assets:** Including additional files (like CSS, images) in the generated documentation.
    * **Extensions:**  Loading `hotdoc` extensions to add specific features.
    * **Subprojects:** Integrating documentation from other Meson subprojects.
    * **Installation:**  Optionally installing the generated documentation.
3. **Generates Hotdoc Configuration:** It creates a `hotdoc.json` configuration file based on the provided parameters.
4. **Executes Hotdoc:** It uses the `subprocess` module to execute the `hotdoc` command-line tool with the generated configuration.
5. **Creates a Meson Target:** It defines a `HotdocTarget` as a custom target in Meson. This means the documentation generation is treated as a build step, ensuring it's built whenever necessary.
6. **Handles Dependencies:** The module meticulously handles dependencies. It extracts include directories and compile arguments from dependencies and passes them to `hotdoc` so it can properly link and reference code elements in the documentation.
7. **Installation Support:** It can generate installation scripts to place the generated documentation in the appropriate directories (e.g., under `/usr/share/doc`).

**Relation to Reverse Engineering (Indirect):**

While this module itself doesn't *perform* reverse engineering, it can be *useful* in the context of reverse engineering tools like Frida in the following ways:

* **Documenting Internal APIs:** Frida is a complex tool with internal APIs used for instrumentation and manipulation. Generating documentation for these internal APIs (perhaps written in Swift, as indicated by the file path) makes it easier for developers (including those reverse engineering or extending Frida) to understand how Frida works internally and how to interact with its components.
* **Documenting Frida's Swift Bridge:** The file path suggests this module is involved in documenting the Swift components of Frida. This is crucial for anyone wanting to use Frida's Swift API or understand how Swift code interacts with Frida's core. Reverse engineers often need to understand these language bindings.
* **Understanding Data Structures:** If the documentation includes details about internal data structures used by Frida, it can aid reverse engineers in understanding how Frida represents information and how to manipulate it.

**Example:**

Imagine a reverse engineer wants to understand how Frida intercepts function calls on iOS. If the Frida Swift API related to interception is well-documented using this `hotdoc` module, the reverse engineer can:

1. Consult the generated documentation to understand the available Swift classes and methods for setting up function hooks.
2. Learn about the parameters and return types of these methods.
3. Understand the data structures involved in representing function hooks.

This documentation significantly simplifies the process of understanding and using Frida's features for reverse engineering.

**Involvement of Binary底层, Linux, Android内核及框架 Knowledge:**

This module interacts with these concepts indirectly by documenting software that *does* interact with them:

* **Binary 底层 (Binary Low-Level):** Frida itself operates at a low level, injecting code into processes and manipulating memory. The documentation generated by this module for Frida's internal APIs or Swift bindings would describe how to interact with these low-level mechanisms. For example, documentation might explain how to read and write process memory using Frida's APIs.
* **Linux and Android Kernel:** Frida can be used to instrument applications and libraries running on Linux and Android. The documentation might detail Frida's features for interacting with kernel structures or system calls. For instance, it might document how to trace system calls made by an application.
* **Android Framework:** Frida is often used for reverse engineering and dynamic analysis of Android applications. The documentation generated by this module for Frida's Swift components could describe how to use Frida to interact with the Android framework APIs, hook framework methods, or analyze framework behavior.

**Example:**

If Frida has a Swift API to intercept calls to specific Android framework APIs (e.g., `android.app.Activity.onCreate`), the documentation generated by this module would explain how to use this API. This directly involves knowledge of the Android framework.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input (Arguments to `generate_doc`):**

```python
hotdoc.generate_doc(
    'MyFridaSwiftDocs',
    sitemap='sitemap.md',
    index='index.md',
    project_version='1.0',
    include_paths=['src/swift_api'],
    dependencies=[
        frida_core_lib,  # A Frida core library target
        my_swift_module, # Another Meson target for a Swift module
    ],
    install=True
)
```

**Assumed Output (Simplified):**

1. **Configuration File (`MyFridaSwiftDocs-doc.json`):** This file would contain configuration details for `hotdoc`, such as:
   ```json
   {
       "project-name": "MyFridaSwiftDocs",
       "project-version": "1.0",
       "index": "index.md",
       "sitemap": "sitemap.md",
       "include-paths": ["/path/to/builddir/src/swift_api", "/path/to/sourcedir/src/swift_api"],
       // ... other configuration based on dependencies
   }
   ```
2. **Hotdoc Execution:** Meson would execute a command similar to:
   ```bash
   hotdoc conf --project-name=MyFridaSwiftDocs --project-version=1.0 --index=index.md --sitemap=sitemap.md --include-path=/path/to/builddir/src/swift_api --include-path=/path/to/sourcedir/src/swift_api --conf-file=MyFridaSwiftDocs-doc.json
   hotdoc run --conf-file=MyFridaSwiftDocs-doc.json --builddir=/path/to/builddir/frida/subprojects/frida-swift/releng/meson
   ```
3. **Meson Target:** A custom target named `MyFridaSwiftDocs-doc` would be created.
4. **Installation (if `install=True`):**  An installation script would be generated to copy the generated HTML documentation to the appropriate installation directory (e.g., `/usr/share/doc/MyFridaSwiftDocs`).

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:** Providing wrong paths for `sitemap` or `index` files.
   ```python
   hotdoc.generate_doc('MyDocs', sitemap='typo_sitemap.md', index='index.md', ...) # If typo_sitemap.md doesn't exist
   ```
   **Error:** `hotdoc` will likely fail with an error indicating it cannot find the sitemap file.

2. **Missing Dependencies:** Not listing all necessary dependencies.
   ```python
   hotdoc.generate_doc('MyDocs', ..., dependencies=[only_some_libs], ...) # If documentation needs info from other libraries
   ```
   **Error:** The generated documentation might have broken links or missing information if symbols or types from the missing dependencies are referenced.

3. **Incorrect `include_paths`:** Not specifying the correct directories where source code or other documentation files reside.
   ```python
   hotdoc.generate_doc('MyDocs', ..., include_paths=['wrong/path'], ...)
   ```
   **Error:** `hotdoc` won't be able to find the files it needs to generate the documentation.

4. **Forgetting to Install Hotdoc:** If `hotdoc` is not installed on the system, Meson will fail with an error when trying to execute the `hotdoc` command.

5. **Version Mismatch:** Using a `hotdoc` version older than the required `MIN_HOTDOC_VERSION`.
   **Error:** Meson will raise an exception indicating the version requirement is not met.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **User edits `meson.build`:** A developer working on Frida's Swift components wants to generate documentation. They will add a `hotdoc.generate_doc()` call within their `meson.build` file (likely within the `frida/subprojects/frida-swift/releng/meson/meson.build` file or a similar location).

   ```python
   # In frida/subprojects/frida-swift/releng/meson/meson.build
   hotdoc_mod = import('hotdoc')
   swift_api_doc = hotdoc_mod.generate_doc(
       'FridaSwiftAPI',
       sitemap='api_sitemap.md',
       index='api_index.md',
       project_version=frida_version,
       include_paths=['../../../../src/swift'], # Path to Swift source code
       dependencies=[frida_swift_library],
       install=True
   )
   ```

2. **User runs Meson:** The developer then runs the Meson configuration command from the top-level Frida directory:
   ```bash
   meson setup builddir
   ```

3. **Meson interprets `meson.build`:** Meson reads and interprets the `meson.build` file. When it encounters the `import('hotdoc')`, it loads the `hotdoc.py` module.

4. **`generate_doc` is called:** Meson executes the `hotdoc_mod.generate_doc()` function call, passing the provided arguments. This is where the code in `hotdoc.py` starts executing.

5. **Meson generates build files:** Based on the `generate_doc` call, Meson creates the necessary build rules and scripts to execute the `hotdoc` command during the build process.

6. **User runs the build:** The developer then runs the build command:
   ```bash
   ninja -C builddir
   ```

7. **Hotdoc is executed:** During the build process, Ninja (or another backend) executes the commands generated by Meson, which includes running the `hotdoc` command with the configured parameters.

If there's an issue with the documentation generation, a developer might need to debug this process. They would likely:

* **Check the Meson output:** Look for error messages from Meson or `hotdoc`.
* **Examine the generated `hotdoc.json` file:** See if the configuration is as expected.
* **Step through the `hotdoc.py` code:** Use a debugger (if necessary) to understand how the arguments are being processed and how the `hotdoc` command is being constructed.

Therefore, the `hotdoc.py` file is a crucial part of Frida's build system, enabling the generation of documentation for its Swift components and potentially other parts of the project. It bridges the gap between the Meson build system and the `hotdoc` documentation generator.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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