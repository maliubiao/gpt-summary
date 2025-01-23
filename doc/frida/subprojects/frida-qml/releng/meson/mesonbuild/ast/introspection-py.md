Response:
Let's break down the thought process for analyzing this Python code snippet. The goal is to understand its functionality and relate it to reverse engineering concepts.

**1. Initial Understanding and Context:**

* **File Path:**  The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/ast/introspection.py` immediately tells us a few things:
    * It's part of the Frida project, a dynamic instrumentation toolkit (already stated in the prompt, but good to confirm).
    * It's within a `mesonbuild` directory, suggesting it's related to the Meson build system.
    * It resides in an `ast` (Abstract Syntax Tree) directory, indicating it operates on the parsed structure of some language (likely Meson's build definition language).
    * The filename `introspection.py` is a strong hint about its purpose – examining and understanding the structure of something else.

* **License and Copyright:** The header indicates it's Apache 2.0 licensed and has copyright from Meson developers and Intel. This is generally less relevant to the core functionality analysis but good to note for context.

* **Imports:**  The imports provide crucial information:
    * `compilers`, `environment`, `mesonlib`, `optinterpreter`: These are clearly parts of the Meson build system.
    * `coredata`:  Likely holds core configuration data for the build.
    * `build`: Contains classes like `Executable`, `Jar`, `SharedLibrary`, etc., representing build targets.
    * `interpreterbase`:  Provides base classes for interpreters within Meson.
    * `mparser`:  Deals with parsing, evident from `BaseNode`, `ArithmeticNode`, etc.
    * `ast.interpreter`:  Indicates this code builds upon a more general AST interpreter.
    * `ast.visitor`: Suggests a visitor pattern is used for traversing the AST.

* **Class `IntrospectionHelper`:** This looks like a simple data container to hold command-line options, suggesting this introspection process might be configurable.

* **Class `IntrospectionInterpreter`:**  This is the core of the code. The docstring "Interpreter to detect the options without a build directory" is a key piece of information. It means this code can analyze a Meson build file *without* actually running the build.

**2. Deeper Dive into `IntrospectionInterpreter`:**

* **Inheritance:** It inherits from `AstInterpreter`, confirming it's a specialized interpreter for ASTs.
* **Initialization (`__init__`)**:  It initializes with source root, subdirectory, backend, etc., mirroring the setup of a regular Meson build. Crucially, it initializes an `IntrospectionHelper` for options.
* **Function Overrides and Additions:** The `funcs` dictionary maps function names in the Meson build file (like `project`, `executable`, `library`) to Python methods within the interpreter. This is a standard interpreter pattern.
* **Key Methods and Their Actions:**  Go through each significant method and understand its purpose:
    * `func_project`:  Handles the `project()` call in the Meson file, extracting project name, version, and processing options. It also looks for subprojects.
    * `do_subproject`: Recursively analyzes subprojects.
    * `func_add_languages`: Processes the `add_languages()` call, detecting and configuring compilers.
    * `func_dependency`: Handles `dependency()`, recording dependency information.
    * `build_target`:  A central function for processing various build targets (`executable`, `library`, etc.). It extracts source files and other target properties. The complex logic within `traverse_nodes` is important – it resolves variables and function calls within the source lists.
    * `func_executable`, `func_library`, etc.:  Specific handlers for different build target types, usually calling `build_target`.
    * `analyze`:  The main entry point for the analysis, loading the `meson.build` file, performing sanity checks, parsing the project, and running the interpreter.
    * `extract_subproject_dir`: A fast-path method to extract the subproject directory.

**3. Connecting to Reverse Engineering:**

* **Understanding the Goal:**  The core idea is that this code *inspects* a build definition without executing the build. This is highly relevant to reverse engineering because you often want to understand how software is built *without* having to compile it yourself.

* **Identifying Key Information:** The introspection process extracts crucial build information:
    * Project name and version
    * Supported languages
    * Dependencies (internal and external)
    * Executables, libraries, and other build targets
    * Source files for each target
    * Build options and their defaults

* **Relating to Frida:** Since this is part of Frida, the information gathered by this introspection tool could be used to:
    * Understand the structure of the application Frida is targeting.
    * Identify key components (executables, libraries) that might be of interest for instrumentation.
    * Determine dependencies that need to be present for the target application to run.

**4. Considering Binary/Kernel/Framework Aspects:**

* **Compiler Detection:** The `detect_compiler_for` function directly interacts with the system to find available compilers. This is a low-level interaction, as it involves searching paths and potentially running compiler executables.
* **Build Targets:** The classes like `Executable`, `SharedLibrary`, etc., represent fundamental binary components. Understanding how these are defined in the Meson file provides insight into the final binary structure.
* **Dependencies:**  Dependencies often link to system libraries or other low-level components. Introspection reveals these linkages.
* **Cross-Compilation:** The `cross_file` parameter indicates support for cross-compilation, a common concept in embedded systems and Android development.

**5. Logic and Assumptions:**

* **Assumptions about Input:** The code assumes the input is a valid Meson `meson.build` file.
* **Output:** The code populates data structures (`project_data`, `targets`, `dependencies`) representing the extracted information.

**6. User Errors and Debugging:**

* **Invalid `meson.build`:**  Common user errors involve syntax errors in the `meson.build` file. The interpreter will likely raise exceptions in these cases.
* **Incorrect Dependencies:**  Specifying incorrect or missing dependencies is another common error. The introspection tool can help identify these.

**7. Tracing User Actions:**

Think about how a user would end up using this code. It's likely an internal part of the Frida build process or a related tool. A developer might run a command that internally invokes this introspection to analyze the build setup.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this is just about listing files. **Correction:** The presence of AST parsing and the handling of build targets indicates a deeper analysis of the build structure, not just file listing.
* **Initial thought:** This is purely a Meson tool. **Correction:** While it's part of Meson, its inclusion in Frida suggests a specific use case within the Frida ecosystem, likely related to understanding target application builds.
* **Focus on the "how":**  Instead of just saying "it extracts dependencies," consider *how* it does it – by parsing the `dependency()` function call in the Meson file.

By following these steps, breaking down the code into smaller parts, understanding the context, and making connections to reverse engineering principles, we can arrive at a comprehensive explanation of the code's functionality.
This Python code file, `introspection.py`, is a part of the Meson build system used within the Frida dynamic instrumentation toolkit. Its primary function is to **analyze `meson.build` files and extract information about the project's structure and build configuration without actually performing a full build.**  This process is called "introspection."

Here's a breakdown of its functionalities:

**Core Functionality: Introspecting Meson Build Files**

1. **Parsing `meson.build`:** It uses an AST (Abstract Syntax Tree) interpreter (`IntrospectionInterpreter`) to parse the `meson.build` file. This involves converting the text-based build definition into a structured representation that the code can understand.

2. **Extracting Project Information:**
   - It identifies and extracts the project's name, version, and supported languages from the `project()` function call in `meson.build`.
   - It reads and processes `meson_options.txt` (or `meson.options`) to understand project-specific build options.
   - It detects and processes subprojects, recursively analyzing their `meson.build` files.

3. **Discovering Dependencies:**
   - It identifies and records dependencies declared using the `dependency()` function, including their names, whether they are required, expected versions, and whether a fallback mechanism is defined.

4. **Identifying Build Targets:**
   - It recognizes and extracts information about various build targets defined in `meson.build`, such as:
     - `executable()`: Executable programs.
     - `library()`, `shared_library()`: Shared libraries (DLLs, SOs).
     - `static_library()`: Static libraries (LIBs, As).
     - `shared_module()`: Dynamically loadable modules.
     - `jar()`: Java Archive files.
   - For each target, it gathers details like:
     - Name and ID.
     - Type (executable, library, etc.).
     - Location of the defining `meson.build` file.
     - Subdirectory.
     - Whether it's built by default.
     - Whether it's installed.
     - Output file names.
     - Source files.
     - Extra files.
     - Keyword arguments passed to the target function.

5. **Handling Languages:**
   - It processes the `add_languages()` function to determine the programming languages used in the project and attempts to detect the corresponding compilers.

**Relationship to Reverse Engineering:**

This introspection capability is directly relevant to reverse engineering in several ways:

* **Understanding the Target's Build Structure:** Before diving into the binaries, understanding how the target application or library is built provides valuable context. Introspection reveals:
    - **Key Components:** Identifying the main executables and libraries helps pinpoint the core functionalities.
    - **Dependencies:** Knowing the dependencies (both internal and external) is crucial for setting up a reverse engineering environment and understanding how different parts of the target interact. For example, if a specific cryptographic library is a dependency, that might be an area of focus.
    - **Build Options:** Understanding build options can reveal how the software was configured (e.g., debug symbols enabled, specific features toggled), which can influence the reverse engineering approach.
    - **Source Organization:**  While it doesn't provide the actual source code, knowing the source file structure can give hints about the modularity and organization of the project.

**Example:**

Let's say a `meson.build` file contains the following:

```meson
project('MyTargetApp', 'cpp', version: '1.0')

executable('mytarget', 'src/main.cpp', 'src/utils.cpp', dependencies: [
  dependency('zlib'),
  dependency('mylib', fallback: 'internal_mylib')
])

shared_library('corelib', 'src/core.cpp', install: true)
```

The `IntrospectionInterpreter` would extract information like:

- **Project:** Name: "MyTargetApp", Version: "1.0", Languages: ["cpp"]
- **Dependencies:**
    - `zlib`: Required, no specific version.
    - `mylib`: Required, with a fallback to an internal project named "internal_mylib".
- **Executable Target:**
    - Name: "mytarget"
    - Sources: `src/main.cpp`, `src/utils.cpp`
    - Dependencies: References to the `zlib` and `mylib` dependency objects.
- **Shared Library Target:**
    - Name: "corelib"
    - Sources: `src/core.cpp`
    - Install: True

This information tells a reverse engineer that `mytarget` is the main executable, it uses `zlib` and `mylib`, and there's a shared library named `corelib` that's likely a core component and will be installed.

**Relationship to Binary Bottom, Linux, Android Kernel/Framework Knowledge:**

While this code operates at the build system level, it has indirect connections to lower-level concepts:

* **Binary Types:** The code understands the different types of binaries being built (executables, shared libraries, static libraries). A reverse engineer needs to understand the characteristics and linking mechanisms of these binary formats (e.g., ELF on Linux, Mach-O on macOS, PE on Windows).
* **Linux and Android Context:**  Frida is heavily used on Linux and Android. The build system needs to be aware of the specific tools and conventions of these platforms (e.g., compilers like GCC/Clang, dynamic linking mechanisms).
* **Kernel and Framework Awareness (Indirect):** While this code doesn't directly interact with the kernel or Android framework, the build targets it identifies might be libraries or executables that *do* interact with these lower layers. For example, on Android, it might identify build targets that use the Android NDK or interact with system services.
* **Cross-Compilation:** The code handles `cross_file` options, which are relevant when building software for different architectures or operating systems (common in embedded Linux and Android development). Reverse engineers often encounter binaries built for specific architectures.

**Example (Android):**

If the introspection is run on an Android project's `meson.build`, it might identify:

- Shared libraries built using the Android NDK.
- Dependencies on Android system libraries.
- Specific build flags used for the Android platform.

**Logical Reasoning and Assumptions:**

* **Assumption:** The code assumes the `meson.build` files are syntactically correct according to Meson's language.
* **Assumption:**  It assumes the presence of necessary build tools (compilers, linkers) on the system to attempt compiler detection.
* **Logic:** The code uses pattern matching (identifying function calls like `project()`, `executable()`) to extract information.
* **Logic:** It follows the structure of the Meson AST to traverse and analyze the build definition.

**Hypothetical Input and Output:**

**Input (Snippet of `meson.build`):**

```meson
project('MyLib', 'c')

static_library('mylib_static', 'src/a.c', 'src/b.c')

declare_dependency(
  link_with: mylib_static
)
```

**Output (Simplified representation of extracted data):**

```
{
  "project_data": {
    "descriptive_name": "MyLib",
    "version": "undefined"
  },
  "targets": [
    {
      "name": "mylib_static",
      "type": "static_library",
      "sources": ["src/a.c", "src/b.c"],
      // ... other details
    }
  ],
  "dependencies": []
}
```

**Common User/Programming Errors and Examples:**

1. **Incorrect `meson.build` Syntax:**
   - **Error:** Misspelling function names (e.g., `excutable` instead of `executable`).
   - **Consequence:** The parser will fail, and the introspection will likely throw an error.

2. **Missing Required Arguments:**
   - **Error:** Not providing a name for an executable: `executable('src/main.cpp')`.
   - **Consequence:** The interpreter will raise an `InvalidArguments` exception.

3. **Incorrect Data Types in Arguments:**
   - **Error:** Providing a number instead of a string for the project name: `project(123, 'cpp')`.
   - **Consequence:** The interpreter will likely raise a type error or `InvalidArguments`.

4. **Circular Dependencies:** While this introspection tool might not directly catch circular dependencies during analysis, a full Meson build would fail. The extracted dependency information could help identify potential circularity if manually reviewed.

**User Operations Leading to This Code:**

This code is typically executed as part of Frida's internal processes or by tools that leverage Frida's capabilities. Here's a possible sequence:

1. **User wants to instrument a target application built with Meson.**
2. **Frida (or a Frida-related tool) needs to understand the target's structure.**
3. **The Frida tooling might invoke Meson's introspection functionality.**
4. **Internally, the `IntrospectionInterpreter` in `introspection.py` is used to parse the target application's `meson.build` file.**
5. **The `analyze()` method of `IntrospectionInterpreter` is called, which then:**
   - Loads the `meson.build` file.
   - Performs sanity checks on the AST.
   - Parses the project definition.
   - Runs the interpreter, which executes the code that extracts information about dependencies and build targets.

**Debugging Clues:**

If the introspection fails, common debugging steps would involve:

1. **Examining the `meson.build` file for syntax errors or semantic issues.**
2. **Checking the Meson version being used.**
3. **Looking for error messages or stack traces generated by the Python interpreter.**
4. **Verifying the existence and accessibility of dependencies.**
5. **Manually stepping through the `introspection.py` code with a debugger to understand where the process fails.**

In summary, `introspection.py` is a crucial component for understanding the structure of Meson-built projects, providing valuable information for reverse engineering efforts, especially within the context of the Frida dynamic instrumentation toolkit. It bridges the gap between the high-level build definition and the lower-level details of binaries and dependencies.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/ast/introspection.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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