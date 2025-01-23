Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Initial Understanding and Goal:**

The first step is to recognize the core purpose of the code: it's a Meson module for integrating the `hotdoc` documentation generator into the build process. Meson is a build system, and modules extend its functionality. `hotdoc` is a tool for creating API documentation, particularly for projects using GTK technologies.

The request asks for several things: functionality, relation to reverse engineering, low-level details, logical reasoning, user errors, and debugging. This provides a clear structure for the analysis.

**2. Dissecting the Code - Functionality Identification (Top-Down and Bottom-Up):**

* **Module Definition:** The presence of `class HotDocModule(ExtensionModule):` immediately tells us this is a Meson module. The `initialize` function registers the module.
* **External Program Interaction:** The `HotdocExternalProgram` class signifies interaction with an external command-line tool (`hotdoc`). Methods like `run_hotdoc` confirm this.
* **Configuration Generation:** The `HotdocTargetBuilder` class is central. It handles the configuration of `hotdoc` using the `hotdoc conf` command. Key methods like `process_known_arg`, `set_arg_value`, and `flatten_config_command` are involved in building the command-line arguments for `hotdoc`.
* **Target Creation:** The `HotdocTarget` class represents the documentation build target within Meson. It's a subclass of `CustomTarget`, meaning Meson will execute a custom command to build it.
* **Installation:** The code handles the installation of the generated documentation.
* **Input Processing:**  The `generate_doc` method parses arguments provided by the user in the `meson.build` file. Type checking and validation are present.
* **Dependency Handling:** The code processes dependencies (`dependencies` and `depends` keywords) to inform `hotdoc` about include paths and other relevant information.

**3. Identifying Connections to Reverse Engineering:**

This requires thinking about how documentation relates to understanding existing software.

* **API Documentation:** The primary output of `hotdoc` is API documentation. This is crucial for reverse engineers trying to understand the interface of a library or framework.
* **C/C++ Focus:** The mention of `gi_c_source_roots` and the handling of include directories suggest a strong focus on documenting C/C++ code, which are common languages in reverse engineering targets.
* **Understanding Internal Structure:** While not directly a reverse engineering *tool*, good documentation significantly aids the process of understanding the internal workings of a system.

**4. Identifying Low-Level/Kernel/Framework Connections:**

* **C/C++ Libraries:**  The focus on C/C++ documentation and the processing of include paths directly link to native libraries often found in operating systems and frameworks.
* **GTK:** The mention of GTK in the initial comment is a strong indicator. GTK is a fundamental UI toolkit used in Linux desktop environments.
* **System Calls/ABIs:** While not explicitly coded here, the *purpose* of documenting C/C++ libraries is often to understand the interface they provide to the operating system kernel or other low-level components. Reverse engineers often work with these interfaces.
* **Android (Implicit):** Frida, the context of the code, is heavily used for dynamic instrumentation on Android. Therefore, while the code itself might not directly interact with the Android kernel, the *documented* code very likely does.

**5. Logical Reasoning (Hypothetical Inputs and Outputs):**

This involves imagining how a user would use this module and what the expected outcome would be.

* **Simple Case:** A minimal `meson.build` snippet using `hotdoc.generate_doc` would trigger the creation of a `hotdoc` configuration file and a custom target to build the documentation.
* **Dependencies:**  If the documented project depends on other libraries, the include paths of those libraries would be added to the `hotdoc` configuration.
* **Customization:** The various keyword arguments to `generate_doc` (like `html_extra_theme`, `extra_assets`) allow for customization of the documentation output.

**6. Identifying Potential User Errors:**

This requires thinking about common mistakes when using build systems and documentation generators.

* **Incorrect File Paths:** Providing wrong paths for the sitemap or index file is a common error.
* **Missing Dependencies:** If the `dependencies` are not correctly specified, `hotdoc` might not find the necessary headers.
* **Incorrect Types:**  Providing arguments of the wrong type will be caught by Meson's type checking.
* **Forgetting Installation:** Users might forget to set `install: true` if they want the documentation to be installed.
* **Hotdoc Configuration Errors (Implicit):** While not directly the fault of the module, users might make mistakes in files referenced by `hotdoc` (e.g., the sitemap).

**7. Tracing User Actions to the Code (Debugging Clues):**

This is about understanding how a developer would end up looking at this specific file.

* **Encountering Errors:** If the documentation build fails, developers might trace the error back to this module.
* **Understanding Build Process:** Developers might examine this code to understand how `hotdoc` is integrated into the Meson build.
* **Customization:** If developers need to customize the `hotdoc` integration, they might need to modify or understand this module.

**8. Structuring the Explanation:**

Finally, the information gathered needs to be organized logically. The structure provided in the original request (functionality, reverse engineering, low-level, reasoning, errors, debugging) is a good starting point. Within each section, specific examples and code references make the explanation more concrete and easier to understand. Using bullet points and clear headings improves readability.

**Self-Correction/Refinement during the Process:**

* **Initial Focus might be too narrow:**  At first, I might focus too much on the technical details of the Python code. I need to broaden the scope to include the *purpose* of the code and its context within Frida and documentation generation.
* **Connecting the Dots:**  It's important to explicitly connect the code elements to the concepts mentioned in the request (reverse engineering, low-level, etc.). Don't just list features; explain *why* they are relevant.
* **Providing Concrete Examples:**  Abstract explanations are less helpful than concrete examples of user errors, input/output scenarios, etc.
* **Ensuring Clarity:**  Use clear and concise language. Avoid jargon where possible, or explain technical terms.

By following these steps and continually refining the analysis, a comprehensive and informative explanation can be generated.
This Python code file, `hotdoc.py`, is a Meson module designed to integrate the `hotdoc` documentation generator into the build process of projects managed by Meson. Let's break down its functionalities:

**Core Functionalities:**

1. **Provides a `hotdoc` Meson module:** This module allows Meson build files (`meson.build`) to interact with the `hotdoc` documentation generator. It essentially adds a new set of functions (`hotdoc.generate_doc`, `hotdoc.has_extensions`) that can be called within Meson build definitions.

2. **`hotdoc.generate_doc()` function:** This is the primary function for generating documentation using `hotdoc`. It takes various arguments to configure the `hotdoc` run, such as:
    * **`sitemap` and `index`:** Paths to the sitemap and index files for the documentation.
    * **`project_version`:** The version of the project being documented.
    * **`html_extra_theme`:**  Allows specifying an extra HTML theme for the documentation.
    * **`include_paths`:**  Directories containing files that `hotdoc` should consider when generating documentation.
    * **`dependencies`:**  A list of dependencies (libraries, other build targets) whose include paths might be needed for documentation.
    * **`depends`:**  A list of custom build targets that must be built before the documentation can be generated.
    * **`gi_c_source_roots`:**  Specifies directories containing C source code for use with the `gi-extension` of `hotdoc` (likely for generating documentation from GObject introspection data).
    * **`extra_assets`:**  Additional files or directories to include in the generated documentation output.
    * **`extra_extension_paths`:**  Paths to extra `hotdoc` extensions.
    * **`subprojects`:**  Allows incorporating documentation from other Meson subprojects that also use `hotdoc`.
    * **`install`:** A boolean indicating whether to install the generated documentation.

3. **`hotdoc.has_extensions()` function:** Checks if the `hotdoc` installation has specific extensions enabled.

4. **Handles `hotdoc` configuration:** The module generates a `hotdoc` configuration file (`<project_name>-doc.json`) with the provided settings.

5. **Creates a custom Meson build target:**  When `hotdoc.generate_doc()` is called, it creates a `CustomTarget` in Meson. This target represents the process of building the documentation. Meson will execute the necessary `hotdoc` commands when this target is built.

6. **Manages dependencies:** The module understands how to extract include directories from Meson dependencies (libraries, internal dependencies, etc.) and pass them to `hotdoc`.

7. **Supports installation:** If `install=True` is passed to `generate_doc()`, the module creates an installation step to copy the generated documentation to the appropriate location.

**Relationship to Reverse Engineering:**

This module is indirectly related to reverse engineering. Good API documentation is crucial for understanding the functionality and interfaces of software, which is a key aspect of reverse engineering.

* **Understanding Library Interfaces:**  If you are reverse engineering a library that uses `hotdoc` to generate its documentation, this module is what makes that documentation generation happen during the build process. The generated documentation provides valuable insights into the library's functions, structures, and how to interact with it. This can significantly speed up the reverse engineering process by providing a starting point for understanding the code.

* **Example:** Imagine you are reverse engineering a closed-source library that happens to include (though you wouldn't initially know it's from the official source) a developer package with documentation generated by `hotdoc`. Understanding how `hotdoc` works and the structure of its output can help you navigate and interpret that documentation more effectively.

**Involvement of Binary Underpinnings, Linux, Android Kernel/Framework:**

The connection here is also indirect but relevant in the context of Frida:

* **Frida's Target Platforms:** Frida is a dynamic instrumentation toolkit primarily used for reverse engineering on platforms like Linux, Android, macOS, and Windows. It often interacts with the underlying operating system kernel and frameworks.
* **Documenting Native Code:**  `hotdoc` is often used to document C and C++ code, which are the languages in which operating system kernels and many system frameworks are written. The `gi_c_source_roots` option specifically suggests the documentation might involve GObject Introspection, a technology heavily used in the Linux/GNOME ecosystem for providing runtime type information for C libraries.
* **Android Context (Frida):** Given that this file is part of the Frida project, the documentation being generated likely pertains to Frida's own APIs or the APIs of software that Frida is designed to instrument. This software very often interacts with the Android kernel or framework (e.g., system services, native libraries).
* **Include Paths and Dependencies:**  The module's ability to handle dependencies and include paths is essential for documenting code that interacts with platform-specific headers (e.g., Linux kernel headers, Android NDK headers).

**Example:** If Frida is documenting its C API for interacting with an Android process, this `hotdoc` module would be used to generate that documentation. The `dependencies` argument might include paths to Android NDK headers, allowing `hotdoc` to correctly resolve types and function signatures used in the Frida API.

**Logical Reasoning (Hypothetical Input and Output):**

Let's assume a simplified `meson.build` file:

```meson
project('my_project', 'c')

hotdoc_dep = dependency('hotdoc')

hotdoc_module = import('hotdoc')

hotdoc_module.generate_doc(
  'MyProject',
  sitemap: 'sitemap.xml',
  index: 'index.md',
  project_version: '1.0',
  include_paths: 'src',
  dependencies: [],
  install: true
)
```

**Hypothetical Input:**

* **Meson Build System:**  Running the `meson` command to configure the build.
* **`hotdoc` installed and available in the system's PATH.**
* **`sitemap.xml` and `index.md` files present in the source directory.**
* **A `src` directory containing header files for the project.**

**Hypothetical Output:**

1. **A `MyProject-doc.json` file generated in the build directory:** This file will contain the configuration for `hotdoc`, including the project name, version, and include paths.
2. **A Meson custom target named `MyProject-doc` is created:** This target, when built, will execute the `hotdoc` command using the generated configuration file.
3. **Documentation output is generated in the build directory under `MyProject-doc/html`:** This will contain the HTML documentation generated by `hotdoc`.
4. **If `ninja` is used to build, running `ninja MyProject-doc` will trigger the documentation generation.**
5. **If `install: true` is set, running `ninja install` will copy the generated documentation (typically the `html` directory) to the installation prefix (e.g., `/usr/local/share/doc/my_project/html`).**

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:**  Specifying wrong paths for `sitemap` or `index`.
   * **Example:** `sitemap: 'wrong_path/sitemap.xml'` when `sitemap.xml` is in the root of the source directory. This will likely cause `hotdoc` to fail.

2. **Missing Dependencies:** Forgetting to include necessary dependencies in the `dependencies` list.
   * **Example:** If the project being documented uses a library with headers in `/usr/include/mylib`, and this isn't added as a dependency, `hotdoc` might fail to resolve types or functions from that library.

3. **Incorrect `project_version` format:** While less critical, providing a version string that doesn't adhere to expected conventions might cause issues with documentation indexing or display.

4. **Type Mismatches in Arguments:**  Providing arguments of the wrong type to `generate_doc`. Meson's type checking should catch most of these.
   * **Example:**  Passing a string instead of a list for `include_paths`.

5. **Forgetting to Install `hotdoc`:** If the `hotdoc` executable is not found in the system's PATH, the Meson configuration will fail with an error message indicating that.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user might end up looking at this code for several reasons during debugging:

1. **Encountering `hotdoc` build errors:** If the documentation build fails during the Meson build process, the user might examine the Meson log or the output of the `ninja` command. The log will likely point to the execution of the `hotdoc` command. To understand how that command is being constructed and configured, the user might trace back to this `hotdoc.py` module.

2. **Wanting to customize `hotdoc` integration:**  A developer might want to add specific `hotdoc` extensions or configure options not directly exposed by the `generate_doc` function. They would then need to understand how this module interacts with `hotdoc` to see if modifications are necessary or if there are alternative approaches.

3. **Investigating dependency issues:** If the documentation build fails due to missing header files, the user might inspect this code to understand how include paths are being extracted from dependencies and passed to `hotdoc`.

4. **Understanding the installation process:** If there are issues with the installation of the documentation, the user might look at the `install: true` logic within this module to see how the installation is being handled.

**Example Debugging Scenario:**

A user runs `ninja` and gets an error like:

```
[1/1] Generating MyProject documentation
FAILED: subprojects/my_project/MyProject-doc
/usr/bin/python3 /path/to/meson-internal hotdoc /usr/bin/hotdoc run --conf-file MyProject-doc.json --builddir subprojects/my_project
... hotdoc error output about missing input file ...
```

To debug this, the user might:

1. **Examine `MyProject-doc.json`:**  See the configuration being passed to `hotdoc`.
2. **Realize the `sitemap.xml` path is incorrect in `meson.build`.**
3. **Open `frida/subprojects/frida-python/releng/meson/mesonbuild/modules/hotdoc.py` to understand how the `generate_doc` function processes the `sitemap` argument and constructs the `hotdoc` command.** This allows them to confirm their suspicion about the incorrect path and understand how to fix it in their `meson.build` file.

In summary, this `hotdoc.py` module acts as a bridge between the Meson build system and the `hotdoc` documentation generator, providing a convenient and structured way to generate documentation for projects, particularly those written in C/C++ and potentially targeting platforms like Linux and Android, as is relevant in the context of Frida. Understanding its functionality is crucial for developers who use `hotdoc` within Meson-based projects and for debugging issues related to documentation generation.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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