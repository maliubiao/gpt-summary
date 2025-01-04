Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its functionality, its relation to reverse engineering, its use of low-level concepts, logical reasoning, potential user errors, and how a user might reach this code during debugging.

**1. Initial Read and Understanding the Core Purpose:**

* The first few lines clearly indicate this is part of the `mesonbuild` project, specifically dealing with Abstract Syntax Tree (AST) introspection.
* The class names `IntrospectionHelper` and `IntrospectionInterpreter` strongly suggest the code's primary function is to analyze Meson build files (`meson.build`) without actually performing a full build. This "introspection" likely aims to extract information about the project's structure, dependencies, and build targets.

**2. Identifying Key Functionality - Looking for Keywords and Function Names:**

*  Functions like `func_project`, `func_executable`, `func_library`, `func_dependency`, `func_add_languages` immediately stand out as central to the build definition process in Meson. These functions are likely parsing and storing information about the project's components.
*  The presence of `BUILD_TARGET_FUNCTIONS` confirms the code is aware of the different types of build targets.
*  The `analyze()` method suggests the main entry point for the introspection process.
*  The `extract_subproject_dir()` method points to a specific, optimized task within the broader introspection.

**3. Connecting to Reverse Engineering (Instruction #2):**

*  Think about what information is valuable in reverse engineering a compiled application. Dependencies, build targets, and compilation flags are key.
*  Consider how this introspection code could provide those insights *before* a build even happens. It's reading the build instructions (the `meson.build` file) and extracting relevant data.
*  Formulate an example:  Imagine a dynamically linked executable. Knowing its dependencies is crucial for reverse engineering. This code can extract those declared dependencies.

**4. Identifying Low-Level Concepts (Instruction #3):**

*  Look for keywords or concepts associated with operating systems, compilers, and binary formats.
*  `Executable`, `SharedLibrary`, `StaticLibrary`, `SharedModule`, and `Jar` directly relate to common binary output formats.
*  `add_languages` and the interaction with `detect_compiler_for` indicate involvement with compilers and language-specific build processes.
*  The mention of "host" and "build" machines (`MachineChoice`) hints at cross-compilation scenarios, which are relevant in embedded systems and Android development.
*  Consider how these concepts relate to Linux and Android. Shared libraries (`.so`) are fundamental in Linux. Android, being based on Linux, also utilizes shared libraries and has its own specific packaging format (`.apk`, which can contain `.dex` files, but this code doesn't go that deep).
*  Kernel interaction is less direct here, but knowing the build process can reveal information about how the software interacts with the kernel (e.g., through specific libraries or system calls).

**5. Analyzing Logical Reasoning and Assumptions (Instruction #4):**

*  Focus on functions that manipulate data or make decisions.
*  `func_project` handles project-level settings and reads `meson.options`. The assumption is that these files follow the Meson syntax. A possible input is a `meson.build` file with a `project()` call and a `meson.options` file. The output would be the extracted project name, version, and default options.
*  `func_dependency` extracts dependency information. The assumption is that dependencies are declared using the `dependency()` function.
*  `build_target` is complex but handles different target types. The logic branches based on the `targetclass` parameter. An example input is a call to `executable()` with source files. The output would be a dictionary containing information about the executable target.

**6. Spotting Potential User Errors (Instruction #5):**

*  Think about common mistakes when writing build files.
*  Calling `project()` multiple times is explicitly checked for and raises an `InvalidArguments` exception.
*  Not providing enough arguments to `project()` is another checked error.
*  Incorrect types for arguments (e.g., a non-string project name) could also lead to errors, although the code does some type checking and defaulting (like the version).
*  Misspelling target names or providing incorrect file paths in source lists are common issues that could surface later in the build process but might be caught during introspection if the source files are checked.

**7. Tracing User Operations and Debugging (Instruction #6):**

*  Consider the typical Meson workflow.
*  A user starts by writing a `meson.build` file.
*  Then, they typically run `meson setup builddir` to configure the build.
*  This introspection code is used *internally* by Meson. A user wouldn't directly call these Python classes.
*  However, during debugging of Meson itself or a Meson-based project, developers might need to understand how Meson parses and interprets the build files.
*  Setting breakpoints within these classes, examining the AST, and tracing the execution flow would be ways to debug the introspection process. Understanding how Meson discovers build targets and dependencies is crucial for diagnosing build issues.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** This code directly interacts with the kernel or hardware. **Correction:** While it deals with build targets that *become* executables interacting with the OS, the introspection itself is at a higher level, parsing the build instructions.
* **Initial thought:**  All user errors are caught by this code. **Correction:**  This code primarily focuses on parsing the `meson.build` structure. Errors like incorrect compiler flags or missing source files are likely caught later in the actual build process.
* **Focus on the "introspection" aspect:**  Continuously remind yourself that the core function is to *understand* the build file's intent, not to perform the build itself. This helps clarify the code's purpose and its relation to reverse engineering (understanding the project's structure).

By following this structured thought process, combining code reading with knowledge of build systems and reverse engineering principles, and iteratively refining understanding, we can arrive at a comprehensive analysis of the given Python code.
This Python code snippet belongs to the Frida dynamic instrumentation tool and is specifically part of Meson's build system for the Python bindings of Frida. It defines an `IntrospectionInterpreter` class designed to analyze Meson build files (`meson.build`) and extract information *without* actually performing a full build. This is crucial for tools that need to understand the project structure, dependencies, and build targets.

Let's break down its functionalities and their relevance:

**Functionalities of `introspection.py`:**

1. **Parsing `meson.build` files:** The core function is to interpret the `meson.build` file, which describes how the Frida Python bindings are built. This involves understanding the syntax and semantics of the Meson language.

2. **Extracting Project Information:** It extracts key project details like the project name, version, and supported programming languages using the `project()` function call in `meson.build`.

3. **Discovering Build Targets:** It identifies different build targets declared in `meson.build`, such as:
    * `executable()`: Defines an executable program.
    * `library()`, `shared_library()`, `static_library()`, `shared_module()`, `both_libraries()`: Define different types of libraries (shared, static, modules).
    * `jar()`: Defines a Java Archive (likely for some related tooling or dependencies).

4. **Identifying Dependencies:** It parses the `dependency()` function calls to identify external libraries or other Meson projects that the Frida Python bindings rely on.

5. **Handling Subprojects:** It supports the concept of subprojects, allowing for modular build structures where dependencies are built separately. It identifies and analyzes these subprojects.

6. **Detecting Compiler Options:** It infers compiler options and settings defined in `meson.options` files, which customize the build process.

7. **Storing Extracted Information:**  The `IntrospectionInterpreter` stores the extracted information in its internal attributes like `project_data`, `targets`, and `dependencies`. This data can then be used by other parts of Frida's build system or related tools.

**Relation to Reverse Engineering:**

This code is indirectly related to reverse engineering. Here's how:

* **Understanding Target Binaries:**  By extracting information about build targets (executables, shared libraries), this code reveals the structure and components of the final Frida Python bindings. This knowledge can be valuable for someone trying to understand how Frida works internally or how the Python bindings interact with the core Frida library. For example, knowing the names and types of shared libraries built can be a starting point for investigating Frida's internal APIs.

* **Dependency Analysis:** Identifying dependencies is crucial in reverse engineering. Knowing which external libraries the Frida Python bindings depend on can provide insights into its functionality and potential areas of interest for analysis. For instance, if it depends on a specific cryptography library, that might be a point of focus.

**Example:**

Let's say the `meson.build` file contains the following lines:

```meson
project('frida-python', '>=16.0.0', 'python')

executable('frida-cli', 'frida_cli.py')

shared_library('frida_module',
  'src/frida_module.c',
  dependencies: [dependency('glib-2.0')]
)
```

The `IntrospectionInterpreter` would extract the following information:

* **Project:** `descriptive_name`: 'frida-python', `version`: '16.0.0'
* **Targets:**
    * `frida-cli` (type: 'executable', sources: [`IdNode('frida_cli.py')`])
    * `frida_module` (type: 'shared_library', sources: [`IdNode('src/frida_module.c')`], dependencies: [{'name': 'glib-2.0', ...}])
* **Dependencies:** [{'name': 'glib-2.0', ...}]

**Binary Underpinnings, Linux, Android Kernel/Framework:**

This code touches on these concepts in the following ways:

* **Binary Output Formats:** The code is aware of different binary output formats like executables (`executable`), shared libraries (`shared_library`), static libraries (`static_library`), and shared modules (`shared_module`). These are fundamental concepts in compiled languages and operating systems like Linux and Android.

* **Shared Libraries (.so on Linux, .so on Android):** The `shared_library` target directly corresponds to the creation of dynamic libraries, which are essential for code sharing and modularity in Linux and Android. Frida itself heavily relies on shared libraries.

* **Android Framework (Indirect):** While this code doesn't directly interact with the Android kernel or framework code, the fact that Frida supports Android means that the build system needs to be able to produce artifacts that can run on Android. The `shared_module` target might be relevant for creating modules that can be loaded within the Android runtime environment.

* **Compiler Detection (`detect_compiler_for`):** The code uses `detect_compiler_for` to identify the appropriate compiler for the specified languages. This is a low-level detail that involves understanding how to find and invoke compilers like GCC or Clang on different platforms (including Linux and potentially Android).

**Example:**

If the project specifies 'c' as a language, the `detect_compiler_for` function will likely try to find a C compiler (like GCC or Clang) available in the environment. On Android, this might involve locating the NDK (Native Development Kit) compilers.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input (`meson.build`):**

```meson
project('my-frida-plugin', '0.1.0', 'c')

static_library('my_plugin_core', 'core.c')

executable('plugin-tester', 'tester.c',
  link_with: my_plugin_core
)

dependency('libssl', required: false)
```

**Hypothetical Output (from `IntrospectionInterpreter`):**

```python
{
    'project_data': {'descriptive_name': 'my-frida-plugin', 'version': '0.1.0'},
    'targets': [
        {
            'name': 'my_plugin_core',
            'id': '...',
            'type': 'static_library',
            'defined_in': '...',
            'subdir': '.',
            'build_by_default': True,
            'installed': True,
            'outputs': ['libmy_plugin_core.a'],
            'sources': [<ast.mparser.IdNode object at ...>],
            'extra_files': [],
            'kwargs': {},
            'node': <ast.mparser.FunctionNode object at ...>
        },
        {
            'name': 'plugin-tester',
            'id': '...',
            'type': 'executable',
            'defined_in': '...',
            'subdir': '.',
            'build_by_default': True,
            'installed': True,
            'outputs': ['plugin-tester'],
            'sources': [<ast.mparser.IdNode object at ...>],
            'extra_files': [],
            'kwargs': {'link_with': [<ast.mparser.IdNode object at ...>]},
            'node': <ast.mparser.FunctionNode object at ...>
        }
    ],
    'dependencies': [
        {'name': 'libssl', 'required': False, 'version': [], 'has_fallback': False, 'conditional': False, 'node': <ast.mparser.FunctionNode object at ...>}
    ]
}
```

**User/Programming Common Usage Errors:**

1. **Incorrect `meson.build` Syntax:** If the user writes an invalid `meson.build` file (e.g., typos in function names, incorrect argument types), the `IntrospectionInterpreter` will likely raise exceptions (like `InvalidArguments`).

   **Example:**  `executible('myprog', 'main.c')` (misspelled `executable`).

2. **Calling `project()` Multiple Times:** The code explicitly checks for this and raises an `InvalidArguments` error. A `meson.build` file should only have one `project()` declaration.

3. **Providing Incorrect Argument Types:** If a function expects a string but receives a number, or vice-versa, the interpreter might fail.

   **Example:** `executable(123, 'main.c')` (project name should be a string).

4. **Referring to Non-Existent Source Files:** While the introspection doesn't necessarily validate the existence of source files, it does record the names. If the user later tries to build with incorrect source file names, the build process will fail.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **Developing Frida or its Python Bindings:** A developer working on Frida or its Python bindings might modify the `meson.build` file to add new features, dependencies, or change build configurations.

2. **Running `meson setup builddir`:**  The user will execute the `meson setup builddir` command to configure the build in the specified `builddir`.

3. **Meson Internally Uses `IntrospectionInterpreter`:** During the `meson setup` phase, Meson needs to understand the structure of the project defined in `meson.build`. It internally uses the `IntrospectionInterpreter` (this code) to parse the `meson.build` file *before* actually generating build files for a specific backend (like Ninja).

4. **Debugging Meson Itself:** If there's an issue with how Meson is interpreting the `meson.build` file (e.g., it's not recognizing a new build target or dependency correctly), a developer debugging Meson itself might step into the code of `IntrospectionInterpreter` to see how it's processing the AST of the `meson.build` file. They might set breakpoints within the `func_project`, `func_executable`, `func_dependency`, or other relevant functions to inspect the parsed data and identify the source of the error.

In summary, this `introspection.py` file plays a crucial role in Frida's build system by providing a mechanism to analyze the project's build definition without performing a full compilation. This information is essential for the build system itself and can also be valuable for understanding the structure and dependencies of the Frida Python bindings, which has indirect relevance to reverse engineering efforts.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/ast/introspection.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```