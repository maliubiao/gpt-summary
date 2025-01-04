Response:
Let's break down the thought process for analyzing the Python code.

**1. Understanding the Goal:**

The core request is to understand what the provided Python code does, specifically within the context of Frida (a dynamic instrumentation tool). The prompt also asks for connections to reverse engineering, low-level concepts, logical reasoning, potential errors, and how a user might reach this code.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. This helps establish the overall purpose and identify key areas for deeper investigation.

* **Imports:**  `frida`, `meson`, `compilers`, `environment`, `optinterpreter`, `coredata`, `build`, `interpreterbase`, `mesonlib`, `mparser`. These imports strongly suggest a connection to the Meson build system and a custom interpreter. The `build` imports (Executable, Library, etc.) hint at build process definitions.
* **Class Names:** `IntrospectionHelper`, `IntrospectionInterpreter`. The name "Introspection" is highly suggestive. It implies examining or inspecting something. "Interpreter" indicates code execution or parsing.
* **Function Names:** `func_project`, `func_add_languages`, `func_dependency`, `func_executable`, `func_library`, etc. These function names look like implementations of functions that might appear in a build configuration file (like Meson's `meson.build`).
* **Variables:** `project_data`, `targets`, `dependencies`. These variable names suggest the code is extracting information about a project's structure and build components.
* **Comments:**  The initial comment block is helpful, identifying the file's location within the Frida project and mentioning Meson. The `TODO` comment is also a minor point of interest.

**3. Formulating a High-Level Hypothesis:**

Based on the initial scan, a hypothesis emerges: This code is part of Frida's build process, likely using Meson. It seems to be designed to *introspect* or analyze the `meson.build` files *without actually performing a full build*. It's extracting information about the project's structure, dependencies, and targets.

**4. Deeper Dive into Key Components:**

Now, let's examine specific parts of the code more closely, connecting them to the initial hypothesis.

* **`IntrospectionHelper`:**  This class seems to hold configuration related to cross-compilation and command-line options. It's used to mimic the structure expected by the Meson environment.
* **`IntrospectionInterpreter`:**  This is the core of the code.
    * **Inheritance:** It inherits from `AstInterpreter`, reinforcing the idea of parsing and interpreting code.
    * **`__init__`:** Sets up the environment, coredata, and initializes dictionaries to store project data, targets, and dependencies. The `cross_file` parameter is a clear indicator of handling cross-compilation.
    * **`func_project`:** This function is crucial. It's called when the `project()` function is encountered in `meson.build`. It extracts project name, version, and handles `meson_options.txt`. It also recursively processes subprojects. This solidifies the idea of analyzing the project structure.
    * **`func_add_languages`:**  This handles the `add_languages()` function in `meson.build`, detecting and potentially configuring compilers.
    * **`func_dependency`:**  Extracts information about project dependencies.
    * **`build_target` and related `func_executable`, `func_library`, etc.:** These functions are responsible for processing build target definitions (executables, libraries). They extract key information like name, sources, outputs, and dependencies. The code specifically handles source node traversal to understand complex source definitions.
    * **`analyze`:**  This function orchestrates the introspection process: loading the `meson.build` file, performing sanity checks on the abstract syntax tree (AST), parsing the project, and then running the interpreter.
    * **`extract_subproject_dir`:** A more direct way to get the subproject directory.

**5. Connecting to the Prompt's Requirements:**

Now, let's address the specific points raised in the prompt:

* **Functionality:**  Summarize the purpose of the code based on the deeper dive. Focus on introspection, extracting build information, and processing `meson.build` files.
* **Reverse Engineering:**  Think about how this information would be useful in reverse engineering. Knowing targets, dependencies, and build settings provides valuable context for understanding the structure and components of the Frida framework or any software built with it. Give concrete examples like identifying libraries to hook.
* **Binary/Low-Level, Linux/Android Kernel/Framework:** Consider how the extracted information relates to lower levels. For example, library dependencies directly relate to shared objects loaded at runtime. The target type (executable, library) is fundamental. If Frida targets Android, the introspection could reveal libraries or executables that interact with the Android framework.
* **Logical Reasoning:** Identify any conditional logic or processing steps that involve making decisions based on input. The handling of `required` dependencies and different library types (`shared`, `static`) are good examples. Create simple hypothetical input and output scenarios.
* **User/Programming Errors:**  Think about common mistakes a developer might make in a `meson.build` file that this introspection code would encounter (e.g., incorrect function calls, missing arguments).
* **User Operation and Debugging:**  Consider the steps a user takes that lead to this code being executed. It's likely part of the Frida build process itself. How might a developer or user encounter this code in a debugging context? Perhaps while working on the build system or investigating build failures.

**6. Structuring the Answer:**

Organize the findings logically, addressing each point of the prompt clearly and concisely. Use bullet points, headings, and examples to make the information easy to understand.

**7. Refinement and Review:**

Finally, review the answer for clarity, accuracy, and completeness. Ensure that the connections between the code and the prompt's requirements are well-explained. Check for any technical inaccuracies or areas where more detail might be needed. For instance, initially, I might have overlooked the importance of the AST and needed to go back and emphasize that `IntrospectionInterpreter` works on the *abstract syntax tree* rather than directly executing build commands.

This iterative process of scanning, hypothesizing, deep-diving, connecting, and refining is key to effectively analyzing and understanding complex code.
This Python code, located in `frida/subprojects/frida-core/releng/meson/mesonbuild/ast/introspection.py`, is part of Frida's build system, specifically focusing on **introspecting** Meson build files (`meson.build`) to gather information about the project's structure and build targets **without actually performing a full build**.

Here's a breakdown of its functionality:

**Core Functionality: Introspection of Meson Build Files**

The primary goal of this code is to parse and analyze `meson.build` files to extract metadata about the project. This includes:

* **Project Information:**  Name, version, and supported languages (using the `project()` function in `meson.build`).
* **Dependencies:** Declared dependencies, whether they are required, and potential fallback mechanisms (using the `dependency()` function).
* **Build Targets:**  Executables, static libraries, shared libraries, shared modules, and JAR files defined in the `meson.build` file (using functions like `executable()`, `library()`, `shared_library()`, etc.). It extracts information about their names, types, source files, extra files, build options, whether they are installed, and their output file names.
* **Subprojects:** Information about subprojects included in the main project.
* **Compiler Options:**  Default compiler options and options specific to the project.

**Relationship to Reverse Engineering:**

This code plays an indirect but important role in the reverse engineering context of Frida:

* **Understanding Frida's Structure:**  For someone wanting to understand how Frida itself is built, this code provides insights into the different components (libraries, executables) that make up Frida core. A reverse engineer could use the information gathered by this script to understand the relationships between different parts of Frida, identify potential entry points, and understand the build process.
    * **Example:**  If a reverse engineer wants to understand how Frida's core library (`frida-core.so` or `frida-core.dylib`) is built, this script can reveal its source files, dependencies (like `glib`, `v8`), and build flags. This helps in navigating the codebase and understanding its dependencies.
* **Identifying Target Libraries for Instrumentation:** While this code introspects Frida's *own* build files, the concept of introspecting build files is also applicable to understanding how *other* software is built. Knowing the libraries and executables a target application uses (obtained through similar introspection techniques or build system analysis) is crucial for deciding *where* to inject Frida's instrumentation.
    * **Example:** If a reverse engineer wants to hook functions in a specific library used by an Android app, understanding the app's build structure (if available) can reveal the exact name and location of that library.

**Involvement of Binary/Low-Level, Linux, Android Kernel & Framework Knowledge:**

The code touches upon these areas implicitly:

* **Binary Output:** The functions processing build targets (like `func_executable`, `func_shared_lib`) ultimately lead to the creation of binary files (executables, shared libraries). The `outputs` field extracted for each target reflects the names of these binary artifacts.
* **Shared Libraries and Modules:** The distinction between `shared_library` and `shared_module` is relevant in dynamic linking scenarios, particularly common on Linux and Android. Understanding these differences is crucial for reverse engineering dynamically loaded code.
* **Linux and Android Framework:** While the code itself doesn't directly interact with the kernel or framework, the *information* it extracts is vital for building software that interacts with these systems. Frida, as a dynamic instrumentation tool, heavily relies on understanding the underlying operating system and its frameworks (especially on Android).
    * **Example:** On Android, knowing the names and locations of system libraries (like `libc.so`, `libbinder.so`) is essential for Frida to hook into system calls or framework components. This introspection code helps build Frida, which then facilitates interaction with these low-level components.

**Logical Reasoning (Hypothetical Input & Output):**

Let's assume a simple `meson.build` file:

```meson
project('my_app', 'c', version: '1.0')

executable('my_program', 'main.c', dependencies: ['mylib'])

static_library('mylib', 'mylib.c')

dependency('glib-2.0')
```

**Hypothetical Input (Parsing the above `meson.build`):**

* The `IntrospectionInterpreter` would parse this file.

**Hypothetical Output (from the introspection process):**

* **`project_data`:** `{'descriptive_name': 'my_app', 'version': '1.0'}`
* **`targets`:**
    * `{'name': 'my_program', 'id': 'my_program', 'type': 'executable', ..., 'sources': [/* nodes representing 'main.c' */], 'kwargs': {'dependencies': ['mylib']}, ...}`
    * `{'name': 'mylib', 'id': 'mylib', 'type': 'static_library', ..., 'sources': [/* nodes representing 'mylib.c' */], 'kwargs': {}, ...}`
* **`dependencies`:**
    * `{'name': 'glib-2.0', 'required': True, 'version': [], 'has_fallback': False, 'conditional': False, ...}`

**User/Programming Common Usage Errors:**

This code primarily *reads* the `meson.build` file. Errors are more likely to occur in the `meson.build` file itself, which this code would then detect. Examples include:

* **Incorrect Function Names:**  Using a non-existent Meson function (e.g., `excutable(...)` instead of `executable(...)`). The `AstInterpreter` would likely raise an error when encountering this unknown function.
* **Missing Required Arguments:** Forgetting a mandatory argument for a Meson function (e.g., `executable('my_program')` without specifying source files). The `func_executable` method might detect this and raise an `InvalidArguments` exception.
* **Type Mismatches in Arguments:** Providing an argument of the wrong type (e.g., passing an integer where a string is expected for a library name). The type checking within the interpreter or the underlying Meson library would catch this.
* **Circular Dependencies:** While this specific code might not directly detect circular dependencies, the overall Meson build system, which uses the information gathered here, would likely flag such issues during the dependency resolution phase.

**User Operation Leading to This Code (Debugging Clues):**

A user (likely a Frida developer or someone building Frida from source) would reach this code implicitly as part of the Frida build process:

1. **Checkout Frida Source Code:** The user clones the Frida repository.
2. **Run Meson Setup:** The user executes a command like `meson setup build`. This command invokes the Meson build system.
3. **Meson Parses `meson.build`:** Meson starts by parsing the top-level `meson.build` file and any subproject `meson.build` files.
4. **`IntrospectionInterpreter` is Used:**  During the parsing phase, Meson uses the `IntrospectionInterpreter` class (from this file) to analyze the `meson.build` files. This happens *before* the actual compilation and linking.
5. **Information Gathering:** The `IntrospectionInterpreter` walks through the Abstract Syntax Tree (AST) of the `meson.build` files and calls the various `func_*` methods to extract information about the project, targets, and dependencies.
6. **Meson Uses the Introspected Data:** Meson uses the collected information to generate build system files (like Makefiles or Ninja files) that will be used for the actual compilation and linking.

**Debugging Scenario:**

If there's an error in a `meson.build` file within Frida's source code (e.g., a typo in a function name), the Meson setup process will likely fail, and the error message might point to the specific line in the `meson.build` file where the error occurred. While the user might not directly interact with the Python code in `introspection.py`, the error message generated by Meson is a consequence of this code's analysis of the `meson.build` file. A Frida developer might then need to examine this file to understand how the introspection process works and why it's failing.

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/ast/introspection.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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