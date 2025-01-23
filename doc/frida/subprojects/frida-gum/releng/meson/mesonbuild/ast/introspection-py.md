Response:
Let's break down the thought process for analyzing this Python code.

1. **Understanding the Goal:** The request asks for the functionality of `introspection.py`, its relevance to reverse engineering, its use of low-level concepts, any logical inferences, potential user errors, and how a user might trigger its execution. The core idea is "introspection," meaning looking inward at the build process itself.

2. **Initial Skim and Keyword Spotting:**  A quick read-through highlights terms like "interpreter," "AST," "options," "project," "executable," "library," "dependency," "compiler," "source root," "subdir," and "subproject."  This immediately suggests the code is about analyzing build definitions (likely Meson's). The "introspection" part suggests it's doing this *without* actually building anything.

3. **Identifying Key Classes:** The presence of `IntrospectionHelper` and `IntrospectionInterpreter` is crucial. The naming is highly suggestive. `IntrospectionInterpreter` likely does the main work of interpreting the Meson build files. `IntrospectionHelper` seems to manage configuration related to the introspection process.

4. **Dissecting `IntrospectionInterpreter`'s `__init__`:** This method sets up the interpreter. Key observations:
    * It takes `source_root`, `subdir`, `backend`, etc. – these are standard build system concepts.
    * It initializes `self.funcs` with functions like `executable`, `library`, `project`, `dependency`. This strongly implies it's parsing and understanding the commands used in a `meson.build` file.
    * It initializes `self.targets` and `self.dependencies` as empty lists, suggesting these will be populated during the analysis.

5. **Analyzing Core Functions:**  The request asks about functionality, so let's examine some of the key methods:
    * `func_project`: This function is clearly responsible for processing the `project()` command in `meson.build`. It extracts project name, version, languages, and handles `meson_options.txt`. The logic for handling subprojects is also here.
    * `func_add_languages`: This method deals with the `add_languages()` command, crucial for knowing which languages the project uses. It interacts with compiler detection.
    * `func_dependency`: This handles the `dependency()` command, extracting information about external libraries.
    * `build_target`: This is a central function for processing targets (executables, libraries, etc.). It takes care of parsing source files and other target properties. Notice the logic to avoid crashes by providing a reduced set of keyword arguments when creating the `BuildTarget` object.
    * `func_executable`, `func_library`, etc.: These are wrappers around `build_target` for specific target types.

6. **Connecting to Reverse Engineering:**  Now, think about how this *relates* to reverse engineering:
    * **Understanding Build Structure:**  Reverse engineers often need to understand how a target was built to analyze its components and dependencies. This script provides that insight. It can reveal the source files, linked libraries, and compilation settings *without* needing to compile.
    * **Identifying Dependencies:** Knowing which external libraries are used is essential for reverse engineering. This script extracts dependency information.
    * **Target Types:**  Knowing whether a component is an executable, shared library, etc., is critical for analysis. This script identifies target types.

7. **Identifying Low-Level/Kernel Concepts:**
    * **Compilers:** The code directly interacts with compiler detection (`detect_compiler_for`). Compilers are fundamental to how software interacts with the underlying operating system.
    * **Executables, Libraries (Shared/Static):** These are core concepts in operating systems and how software is structured and linked.
    * **Linux/Android Kernel & Framework (Implied):** While not directly manipulating kernel code *here*, the purpose of Frida is dynamic instrumentation, heavily used in reverse engineering Android and Linux systems. The *output* of this introspection would be vital for setting up Frida to instrument these systems. The mention of `SPDX-License-Identifier: Apache-2.0` and `Copyright © 2024 Intel Corporation` suggests this is real-world, potentially system-level code.

8. **Logical Inferences and Assumptions:**
    * **Input:**  The primary input is the `meson.build` file and potentially `meson_options.txt`. The interpreter traverses the AST of these files.
    * **Output:**  The output is stored in `self.project_data`, `self.targets`, and `self.dependencies`. These data structures contain information about the project's structure, targets, and dependencies. Think about what these structures would look like given a simple `meson.build`.

9. **User Errors:**  Consider common mistakes:
    * **Incorrect `meson.build` Syntax:** The interpreter is parsing the AST, so syntax errors in `meson.build` would likely cause parsing failures.
    * **Missing Dependencies:** While this script introspects, a real build would fail if dependencies aren't met. This script identifies *declared* dependencies.
    * **Incorrect Option Names:** If a user provides an incorrect option name in `meson_options.txt` or on the command line, the introspection might not capture the intended configuration.

10. **Tracing User Interaction:**  How does a user get here?
    * **Frida's Internal Processes:** Frida likely uses this script internally when it needs to understand the build structure of a target application or library it's about to instrument.
    * **Command-Line Tools:** There might be Frida command-line tools that trigger this introspection as part of their operation. For example, before attaching to a process, Frida might need to analyze its build to understand its components.
    * **Developer/Build System Integration:** Developers integrating Frida into their build process might indirectly trigger this code.

11. **Structure and Refine:**  Finally, organize the findings into the requested categories. Provide concrete examples where possible. Ensure the explanations are clear and connect the code's functionality to the broader context of reverse engineering and system-level programming. The initial thought process might be more scattered, but the final output should be well-structured.
This Python code file, `introspection.py`, part of the Frida dynamic instrumentation tool, is responsible for **analyzing Meson build files without actually performing a full build**. Its primary goal is to **extract information about the project's structure, targets, dependencies, and options** by interpreting the Abstract Syntax Tree (AST) of the `meson.build` and `meson_options.txt` files. This is crucial for Frida to understand the target application or library it will be instrumenting.

Here's a breakdown of its functionalities:

**1. Project Metadata Extraction:**

*   **Parsing `project()` calls:** It identifies and parses the `project()` function calls in `meson.build` to extract the project's name, version, and supported programming languages.
*   **Handling `meson_options.txt`:** It reads and interprets `meson_options.txt` (or `meson.options`) to understand the project's configurable options and their default values.
*   **Subproject Discovery:** It detects and analyzes subprojects defined within the main project, recursively processing their `meson.build` files.

**2. Target Discovery and Analysis:**

*   **Identifying Build Targets:** It recognizes function calls that define build targets such as `executable()`, `library()`, `shared_library()`, `static_library()`, `shared_module()`, and `jar()`.
*   **Extracting Target Properties:** For each target, it extracts information like:
    *   Target name and ID
    *   Target type (executable, library, etc.)
    *   Location of the defining `meson.build` file
    *   Subdirectory of the target
    *   Whether the target is built by default
    *   Whether the target is installed
    *   Output file names
    *   Source files (crucially, it attempts to resolve variable assignments and function calls within the source lists to get a comprehensive list of source files)
    *   Extra files
    *   Keyword arguments passed to the target definition

**3. Dependency Analysis:**

*   **Processing `dependency()` calls:** It identifies and parses `dependency()` function calls to extract information about external libraries or dependencies required by the project.
*   **Dependency Properties:** For each dependency, it extracts:
    *   Dependency name
    *   Whether the dependency is required
    *   Expected version(s) of the dependency
    *   Whether a fallback mechanism is defined
    *   Whether the dependency is conditional (defined within an `if` statement)

**4. Language Support Detection:**

*   **Analyzing `add_languages()` calls:** It parses `add_languages()` calls to determine the programming languages used in the project.
*   **Compiler Detection (Simulated):** While it doesn't perform a full compiler detection like a regular Meson build, it simulates the process to understand which compilers would be used for the project's languages.

**Relation to Reverse Engineering and Examples:**

This script is **directly relevant to reverse engineering**, especially when using tools like Frida. Here's how:

*   **Understanding the Target's Build Structure:** Before instrumenting an application, a reverse engineer needs to understand how it's built. This script provides a way to do that programmatically. For instance, it can identify all the shared libraries that make up an application.

    *   **Example:**  Imagine you want to hook a function within a specific shared library of an Android application. This script can be used to find the names and file paths of all shared libraries belonging to that application's build.

*   **Identifying Key Components:** Knowing the executables and libraries involved helps focus the reverse engineering effort.

    *   **Example:** When analyzing a game, you might want to focus on the main executable or a specific game logic library. This script can tell you the names of these components.

*   **Discovering Dependencies:** Understanding the dependencies can reveal the use of specific third-party libraries, which might have known vulnerabilities or interesting functionalities to explore.

    *   **Example:** An Android app might depend on a specific version of `libssl`. This script would reveal that dependency, allowing a reverse engineer to check for known vulnerabilities in that version of OpenSSL.

*   **Analyzing Build Options:** Sometimes, specific build options can affect the behavior of the application. This script can extract these options.

    *   **Example:** A build option might enable debugging symbols. Knowing this can help in setting up debugging environments for reverse engineering.

**Binary, Linux, Android Kernel & Framework Knowledge:**

This script touches upon these areas indirectly:

*   **Binary Structure (Indirect):** While it doesn't directly analyze binary files, the information it extracts (like target types and output names) is crucial for understanding the resulting binary structure (executables, shared libraries, etc.).
*   **Linux/Android Libraries (Dependencies):**  The `dependency()` function calls often refer to standard Linux or Android libraries (e.g., `pthread`, `cutils`). Understanding these dependencies is essential for reverse engineering on these platforms.
*   **Android Framework (Indirect):**  When analyzing Android applications, the build process often involves Android-specific libraries and components. This script can help identify these components.
*   **Compilers:** The script interacts with compiler detection logic, which inherently understands the tools used to generate machine code for specific platforms (including Linux and Android).

**Logical Reasoning and Examples:**

The script performs logical reasoning based on the structure of the Meson build files:

*   **Assumption:** The code assumes that the `meson.build` file follows Meson's syntax and semantics.
*   **Input:** A `meson.build` file containing the following:

    ```meson
    project('my_app', 'c')
    executable('my_executable', 'main.c', sources: ['a.c', 'b.c'])
    shared_library('my_library', 'lib.c')
    dependency('zlib')
    ```

*   **Output (Hypothetical):**

    ```python
    project_data = {'descriptive_name': 'my_app', 'version': 'undefined'}
    targets = [
        {
            'name': 'my_executable',
            'type': 'executable',
            'sources': [ /* AST nodes for 'main.c', 'a.c', 'b.c' */ ],
            # ... other properties
        },
        {
            'name': 'my_library',
            'type': 'shared_library',
            'sources': [ /* AST node for 'lib.c' */ ],
            # ... other properties
        }
    ]
    dependencies = [
        {
            'name': 'zlib',
            'required': True,
            'version': [],
            'has_fallback': False,
            'conditional': False,
            # ... other properties
        }
    ]
    ```

**User Errors and Examples:**

Common user or programming errors that could lead to issues here:

*   **Invalid `meson.build` Syntax:** If the `meson.build` file has syntax errors, the AST parsing will fail, and the introspection will not work correctly.

    *   **Example:**  Misspelling a function name like `executible()` instead of `executable()`.

*   **Incorrect File Paths:** If the `meson.build` file refers to source files or other resources with incorrect paths, the script might not be able to resolve them correctly.

    *   **Example:**  `executable('my_app', 'main.c')` where `main.c` doesn't exist in the specified directory.

*   **Complex or Dynamic Source Lists:** If the `meson.build` file uses very complex logic to generate source lists at build time, this static introspection might not be able to fully resolve them.

    *   **Example:** A source list generated by a custom script that's executed during the build.

*   **Typos in Dependency Names:** If there are typos in the names of dependencies, the introspection will record the incorrect dependency name.

    *   **Example:** `dependency('zlibb')` instead of `dependency('zlib')`.

**User Operation and Debugging Clues:**

A user (likely a Frida developer or someone using Frida's internal APIs) would not directly interact with this file in a typical workflow. Instead, Frida itself would use this code internally when it needs to analyze the build structure of a target application.

Here's how a user operation might indirectly lead to this code being executed, serving as a debugging clue:

1. **User wants to attach Frida to a process or instrument a library.**
2. **Frida needs to understand the structure of the target (the process or library).**
3. **Frida determines the source code location (where the `meson.build` file is likely located) of the target.**  This might involve looking at build artifacts or configuration files.
4. **Frida instantiates `IntrospectionInterpreter` with the source root and other relevant paths.**
5. **Frida calls the `analyze()` method of the `IntrospectionInterpreter`.**
6. **The `analyze()` method loads the `meson.build` file, parses its AST, and then traverses the AST, calling functions like `func_project`, `func_executable`, `func_dependency`, etc., defined in this `introspection.py` file.**
7. **The information extracted is stored in the interpreter's internal data structures (like `self.targets` and `self.dependencies`).**
8. **Frida uses this extracted information to perform the requested instrumentation or analysis.**

**Debugging Clue:** If Frida fails to attach to a process or instrument it correctly, and the error messages point to issues with understanding the target's structure, examining the execution flow within `introspection.py` could be a crucial debugging step. You might look at:

*   Whether the `meson.build` file is being parsed correctly.
*   Whether the expected targets and dependencies are being identified.
*   Whether there are errors in resolving source file paths or other properties.

In summary, `introspection.py` is a vital component of Frida's ability to understand the build process of target applications, enabling dynamic instrumentation by providing a programmatic way to analyze Meson build files without performing a full build.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/ast/introspection.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright © 2024 Intel Corporation

# This class contains the basic functionality needed to run any interpreter
# or an interpreter-based tool

from __future__ import annotations
import copy
import os
import typing as T

from .. import compilers, environment, mesonlib, optinterpreter
from .. import coredata as cdata
from ..build import Executable, Jar, SharedLibrary, SharedModule, StaticLibrary
from ..compilers import detect_compiler_for
from ..interpreterbase import InvalidArguments, SubProject
from ..mesonlib import MachineChoice, OptionKey
from ..mparser import BaseNode, ArithmeticNode, ArrayNode, ElementaryNode, IdNode, FunctionNode, BaseStringNode
from .interpreter import AstInterpreter

if T.TYPE_CHECKING:
    from ..build import BuildTarget
    from ..interpreterbase import TYPE_var
    from .visitor import AstVisitor


# TODO: it would be nice to not have to duplicate this
BUILD_TARGET_FUNCTIONS = [
    'executable', 'jar', 'library', 'shared_library', 'shared_module',
    'static_library', 'both_libraries'
]

class IntrospectionHelper:
    # mimic an argparse namespace
    def __init__(self, cross_file: T.Optional[str]):
        self.cross_file = [cross_file] if cross_file is not None else []
        self.native_file: T.List[str] = []
        self.cmd_line_options: T.Dict[OptionKey, str] = {}
        self.projectoptions: T.List[str] = []

    def __eq__(self, other: object) -> bool:
        return NotImplemented

class IntrospectionInterpreter(AstInterpreter):
    # Interpreter to detect the options without a build directory
    # Most of the code is stolen from interpreter.Interpreter
    def __init__(self,
                 source_root: str,
                 subdir: str,
                 backend: str,
                 visitors: T.Optional[T.List[AstVisitor]] = None,
                 cross_file: T.Optional[str] = None,
                 subproject: SubProject = SubProject(''),
                 subproject_dir: str = 'subprojects',
                 env: T.Optional[environment.Environment] = None):
        visitors = visitors if visitors is not None else []
        super().__init__(source_root, subdir, subproject, visitors=visitors)

        options = IntrospectionHelper(cross_file)
        self.cross_file = cross_file
        if env is None:
            self.environment = environment.Environment(source_root, None, options)
        else:
            self.environment = env
        self.subproject_dir = subproject_dir
        self.coredata = self.environment.get_coredata()
        self.backend = backend
        self.default_options = {OptionKey('backend'): self.backend}
        self.project_data: T.Dict[str, T.Any] = {}
        self.targets: T.List[T.Dict[str, T.Any]] = []
        self.dependencies: T.List[T.Dict[str, T.Any]] = []
        self.project_node: BaseNode = None

        self.funcs.update({
            'add_languages': self.func_add_languages,
            'dependency': self.func_dependency,
            'executable': self.func_executable,
            'jar': self.func_jar,
            'library': self.func_library,
            'project': self.func_project,
            'shared_library': self.func_shared_lib,
            'shared_module': self.func_shared_module,
            'static_library': self.func_static_lib,
            'both_libraries': self.func_both_lib,
        })

    def func_project(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        if self.project_node:
            raise InvalidArguments('Second call to project()')
        self.project_node = node
        if len(args) < 1:
            raise InvalidArguments('Not enough arguments to project(). Needs at least the project name.')

        proj_name = args[0]
        proj_vers = kwargs.get('version', 'undefined')
        proj_langs = self.flatten_args(args[1:])
        if isinstance(proj_vers, ElementaryNode):
            proj_vers = proj_vers.value
        if not isinstance(proj_vers, str):
            proj_vers = 'undefined'
        self.project_data = {'descriptive_name': proj_name, 'version': proj_vers}

        optfile = os.path.join(self.source_root, self.subdir, 'meson.options')
        if not os.path.exists(optfile):
            optfile = os.path.join(self.source_root, self.subdir, 'meson_options.txt')
        if os.path.exists(optfile):
            oi = optinterpreter.OptionInterpreter(self.subproject)
            oi.process(optfile)
            assert isinstance(proj_name, str), 'for mypy'
            self.coredata.update_project_options(oi.options, T.cast('SubProject', proj_name))

        def_opts = self.flatten_args(kwargs.get('default_options', []))
        _project_default_options = mesonlib.stringlistify(def_opts)
        self.project_default_options = cdata.create_options_dict(_project_default_options, self.subproject)
        self.default_options.update(self.project_default_options)
        self.coredata.set_default_options(self.default_options, self.subproject, self.environment)

        if not self.is_subproject() and 'subproject_dir' in kwargs:
            spdirname = kwargs['subproject_dir']
            if isinstance(spdirname, BaseStringNode):
                assert isinstance(spdirname.value, str)
                self.subproject_dir = spdirname.value
        if not self.is_subproject():
            self.project_data['subprojects'] = []
            subprojects_dir = os.path.join(self.source_root, self.subproject_dir)
            if os.path.isdir(subprojects_dir):
                for i in os.listdir(subprojects_dir):
                    if os.path.isdir(os.path.join(subprojects_dir, i)):
                        self.do_subproject(SubProject(i))

        self.coredata.init_backend_options(self.backend)
        options = {k: v for k, v in self.environment.options.items() if k.is_backend()}

        self.coredata.set_options(options)
        self._add_languages(proj_langs, True, MachineChoice.HOST)
        self._add_languages(proj_langs, True, MachineChoice.BUILD)

    def do_subproject(self, dirname: SubProject) -> None:
        subproject_dir_abs = os.path.join(self.environment.get_source_dir(), self.subproject_dir)
        subpr = os.path.join(subproject_dir_abs, dirname)
        try:
            subi = IntrospectionInterpreter(subpr, '', self.backend, cross_file=self.cross_file, subproject=dirname, subproject_dir=self.subproject_dir, env=self.environment, visitors=self.visitors)
            subi.analyze()
            subi.project_data['name'] = dirname
            self.project_data['subprojects'] += [subi.project_data]
        except (mesonlib.MesonException, RuntimeError):
            return

    def func_add_languages(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        kwargs = self.flatten_kwargs(kwargs)
        required = kwargs.get('required', True)
        assert isinstance(required, (bool, cdata.UserFeatureOption)), 'for mypy'
        if isinstance(required, cdata.UserFeatureOption):
            required = required.is_enabled()
        if 'native' in kwargs:
            native = kwargs.get('native', False)
            self._add_languages(args, required, MachineChoice.BUILD if native else MachineChoice.HOST)
        else:
            for for_machine in [MachineChoice.BUILD, MachineChoice.HOST]:
                self._add_languages(args, required, for_machine)

    def _add_languages(self, raw_langs: T.List[TYPE_var], required: bool, for_machine: MachineChoice) -> None:
        langs: T.List[str] = []
        for l in self.flatten_args(raw_langs):
            if isinstance(l, str):
                langs.append(l)
            elif isinstance(l, BaseStringNode):
                langs.append(l.value)

        for lang in sorted(langs, key=compilers.sort_clink):
            lang = lang.lower()
            if lang not in self.coredata.compilers[for_machine]:
                try:
                    comp = detect_compiler_for(self.environment, lang, for_machine, True, self.subproject)
                except mesonlib.MesonException:
                    # do we even care about introspecting this language?
                    if required:
                        raise
                    else:
                        continue
                if self.subproject:
                    options = {}
                    for k in comp.get_options():
                        v = copy.copy(self.coredata.options[k])
                        k = k.evolve(subproject=self.subproject)
                        options[k] = v
                    self.coredata.add_compiler_options(options, lang, for_machine, self.environment, self.subproject)

    def func_dependency(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        args = self.flatten_args(args)
        kwargs = self.flatten_kwargs(kwargs)
        if not args:
            return
        name = args[0]
        has_fallback = 'fallback' in kwargs
        required = kwargs.get('required', True)
        version = kwargs.get('version', [])
        if not isinstance(version, list):
            version = [version]
        if isinstance(required, ElementaryNode):
            required = required.value
        if not isinstance(required, bool):
            required = False
        self.dependencies += [{
            'name': name,
            'required': required,
            'version': version,
            'has_fallback': has_fallback,
            'conditional': node.condition_level > 0,
            'node': node
        }]

    def build_target(self, node: BaseNode, args: T.List[TYPE_var], kwargs_raw: T.Dict[str, TYPE_var], targetclass: T.Type[BuildTarget]) -> T.Optional[T.Dict[str, T.Any]]:
        args = self.flatten_args(args)
        if not args or not isinstance(args[0], str):
            return None
        name = args[0]
        srcqueue = [node]
        extra_queue = []

        # Process the sources BEFORE flattening the kwargs, to preserve the original nodes
        if 'sources' in kwargs_raw:
            srcqueue += mesonlib.listify(kwargs_raw['sources'])

        if 'extra_files' in kwargs_raw:
            extra_queue += mesonlib.listify(kwargs_raw['extra_files'])

        kwargs = self.flatten_kwargs(kwargs_raw, True)

        def traverse_nodes(inqueue: T.List[BaseNode]) -> T.List[BaseNode]:
            res: T.List[BaseNode] = []
            while inqueue:
                curr = inqueue.pop(0)
                arg_node = None
                assert isinstance(curr, BaseNode)
                if isinstance(curr, FunctionNode):
                    arg_node = curr.args
                elif isinstance(curr, ArrayNode):
                    arg_node = curr.args
                elif isinstance(curr, IdNode):
                    # Try to resolve the ID and append the node to the queue
                    assert isinstance(curr.value, str)
                    var_name = curr.value
                    if var_name in self.assignments:
                        tmp_node = self.assignments[var_name]
                        if isinstance(tmp_node, (ArrayNode, IdNode, FunctionNode)):
                            inqueue += [tmp_node]
                elif isinstance(curr, ArithmeticNode):
                    inqueue += [curr.left, curr.right]
                if arg_node is None:
                    continue
                arg_nodes = arg_node.arguments.copy()
                # Pop the first element if the function is a build target function
                if isinstance(curr, FunctionNode) and curr.func_name.value in BUILD_TARGET_FUNCTIONS:
                    arg_nodes.pop(0)
                elementary_nodes = [x for x in arg_nodes if isinstance(x, (str, BaseStringNode))]
                inqueue += [x for x in arg_nodes if isinstance(x, (FunctionNode, ArrayNode, IdNode, ArithmeticNode))]
                if elementary_nodes:
                    res += [curr]
            return res

        source_nodes = traverse_nodes(srcqueue)
        extraf_nodes = traverse_nodes(extra_queue)

        # Make sure nothing can crash when creating the build class
        kwargs_reduced = {k: v for k, v in kwargs.items() if k in targetclass.known_kwargs and k in {'install', 'build_by_default', 'build_always'}}
        kwargs_reduced = {k: v.value if isinstance(v, ElementaryNode) else v for k, v in kwargs_reduced.items()}
        kwargs_reduced = {k: v for k, v in kwargs_reduced.items() if not isinstance(v, BaseNode)}
        for_machine = MachineChoice.HOST
        objects: T.List[T.Any] = []
        empty_sources: T.List[T.Any] = []
        # Passing the unresolved sources list causes errors
        kwargs_reduced['_allow_no_sources'] = True
        target = targetclass(name, self.subdir, self.subproject, for_machine, empty_sources, None, objects,
                             self.environment, self.coredata.compilers[for_machine], self.coredata.is_build_only, kwargs_reduced)
        target.process_compilers_late()

        new_target = {
            'name': target.get_basename(),
            'id': target.get_id(),
            'type': target.get_typename(),
            'defined_in': os.path.normpath(os.path.join(self.source_root, self.subdir, environment.build_filename)),
            'subdir': self.subdir,
            'build_by_default': target.build_by_default,
            'installed': target.should_install(),
            'outputs': target.get_outputs(),
            'sources': source_nodes,
            'extra_files': extraf_nodes,
            'kwargs': kwargs,
            'node': node,
        }

        self.targets += [new_target]
        return new_target

    def build_library(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        default_library = self.coredata.get_option(OptionKey('default_library'))
        if default_library == 'shared':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif default_library == 'static':
            return self.build_target(node, args, kwargs, StaticLibrary)
        elif default_library == 'both':
            return self.build_target(node, args, kwargs, SharedLibrary)
        return None

    def func_executable(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, Executable)

    def func_static_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, StaticLibrary)

    def func_shared_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedLibrary)

    def func_both_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedLibrary)

    def func_shared_module(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedModule)

    def func_library(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_library(node, args, kwargs)

    def func_jar(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, Jar)

    def func_build_target(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        if 'target_type' not in kwargs:
            return None
        target_type = kwargs.pop('target_type')
        if isinstance(target_type, ElementaryNode):
            target_type = target_type.value
        if target_type == 'executable':
            return self.build_target(node, args, kwargs, Executable)
        elif target_type == 'shared_library':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif target_type == 'static_library':
            return self.build_target(node, args, kwargs, StaticLibrary)
        elif target_type == 'both_libraries':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif target_type == 'library':
            return self.build_library(node, args, kwargs)
        elif target_type == 'jar':
            return self.build_target(node, args, kwargs, Jar)
        return None

    def is_subproject(self) -> bool:
        return self.subproject != ''

    def analyze(self) -> None:
        self.load_root_meson_file()
        self.sanity_check_ast()
        self.parse_project()
        self.run()

    def extract_subproject_dir(self) -> T.Optional[str]:
        '''Fast path to extract subproject_dir kwarg.
           This is faster than self.parse_project() which also initialize options
           and also calls parse_project() on every subproject.
        '''
        if not self.ast.lines:
            return None
        project = self.ast.lines[0]
        # first line is always project()
        if not isinstance(project, FunctionNode):
            return None
        for kw, val in project.args.kwargs.items():
            assert isinstance(kw, IdNode), 'for mypy'
            if kw.value == 'subproject_dir':
                # mypy does not understand "and isinstance"
                if isinstance(val, BaseStringNode):
                    return val.value
        return None
```