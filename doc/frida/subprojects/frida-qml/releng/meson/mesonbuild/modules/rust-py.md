Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for a functional analysis of a specific Python file within the Frida project, focusing on its relationship to reverse engineering, low-level concepts, and potential user errors. It also asks about the user journey to this code.

2. **Initial Skim and Identification of Key Areas:**  A quick scan reveals that the file is a Meson module named `rust.py`. It seems to provide functions for interacting with Rust code within a Meson build system. Keywords like `test`, `bindgen`, and `proc_macro` suggest the functionalities offered. The imports hint at Meson's internal structures (`BuildTarget`, `Executable`, `CustomTarget`, etc.).

3. **Function-by-Function Analysis:**  The most logical approach is to analyze each defined function (`test`, `bindgen`, `proc_macro`) separately.

    * **`test` Function:**
        * **Purpose:** The docstring clearly explains it's for creating Rust test executables. It aims to simplify the common pattern of having separate test targets for Rust libraries.
        * **Reverse Engineering Relevance:** While not directly a reverse engineering *tool*, it facilitates testing the output of reverse engineering efforts (e.g., libraries that interact with analyzed binaries). The example of testing `rust_lib` is crucial.
        * **Low-Level Relevance:**  Potentially through the `link_with` argument, which can involve linking to native libraries (although a specific example isn't immediately evident in this code snippet).
        * **Logic and Assumptions:** The function assumes the input is a Rust-based target. It modifies arguments (like adding `--test`) and creates a new `Executable` target. A good assumption to test would be providing a non-Rust target as input.
        * **User Errors:**  Trying to add `--test` manually is explicitly warned against. Linking with JAR files is disallowed.
        * **User Journey:**  A user would define a Rust library and then want to create a test for it. They would use the `rust.test` function, providing the test name and the library target.

    * **`bindgen` Function:**
        * **Purpose:**  The docstring states it's a wrapper around the `bindgen` tool, used for generating Rust bindings from C/C++ headers.
        * **Reverse Engineering Relevance:** This is *directly* related to reverse engineering. Often, when interacting with native libraries (the target of reverse engineering), you need language bindings. `bindgen` is a key tool for this. The example of generating Rust bindings for `mylib.h` is essential.
        * **Low-Level Relevance:**  Deals with C/C++ headers, which are foundational to low-level programming. Handles include directories and compiler arguments (`c_args`).
        * **Logic and Assumptions:**  Assumes the input is a C/C++ header file. It intelligently determines the language (C or C++) based on the extension. Testing with different header types and language settings would be beneficial.
        * **User Errors:** Providing a non-header file, not specifying the language when ambiguous, or using an older version of `bindgen` without inline wrapper support are all potential issues.
        * **User Journey:**  A user working with a C/C++ library would want to use it from Rust. They would use `rust.bindgen`, providing the header file and output path.

    * **`proc_macro` Function:**
        * **Purpose:**  For creating Rust procedural macros (compile-time code generation).
        * **Reverse Engineering Relevance:**  While less direct, procedural macros can be used in reverse engineering contexts. For example, to generate boilerplate code for interacting with specific data structures or APIs found during analysis.
        * **Low-Level Relevance:**  Procedural macros often deal with manipulating code at a lower level, and can interact with platform-specific APIs.
        * **Logic and Assumptions:** It essentially creates a `SharedLibrary` with specific settings for procedural macros.
        * **User Errors:**  The code snippet doesn't provide specific error examples beyond general `SharedLibrary` misconfigurations.
        * **User Journey:**  A Rust developer wanting to create a procedural macro would use this function, providing the macro's name and source files.

4. **General Module Functionality:**  The `RustModule` class itself acts as a container for these functions. It initializes with an `Interpreter` object, indicating it's part of the Meson build system's logic.

5. **Connections to Low-Level Concepts:** Explicitly look for mentions of operating systems (Linux, Android), kernel, and frameworks. While the code doesn't directly manipulate these, `bindgen`'s interaction with C/C++ headers that *might* interface with the kernel or Android frameworks is a crucial connection.

6. **Reverse Engineering Relationship:**  Consolidate the identified connections. `bindgen` is a primary tool. `test` facilitates verifying reverse-engineered components. `proc_macro` has potential but is less direct.

7. **User Journey - Stepping Back:** Consider how a user arrives at this code. They are using the Meson build system and have imported the `unstable-rust` module. This likely means they are working on a project involving Rust and potentially interacting with C/C++ code. The path `frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/rust.py` suggests this module is part of the Frida project, specifically within the QML (Qt Modeling Language) related components and release engineering parts. A developer working on Frida's QML interface and needing to integrate with Rust would likely encounter this code indirectly through Meson.

8. **Refinement and Structuring:** Organize the findings logically, using headings and bullet points for clarity. Provide concrete examples for each function's usage and potential errors.

9. **Self-Correction/Review:**  Read through the analysis, ensuring the connections are clear and the examples are relevant. Are there any assumptions made that should be explicitly stated?  Is the language clear and concise?  For instance, initially, I might have overlooked the significance of the `frida/` path, but realizing it's part of Frida strengthens the connection to dynamic instrumentation and reverse engineering. Also, ensure the explanation of user journey is coherent.

This iterative process of examining the code, understanding its context, and relating it to the specific requirements of the prompt allows for a comprehensive and accurate analysis.
This Python code defines a Meson module named `rust` that provides helper functions for working with Rust code within the Meson build system. Let's break down its functionalities and connections to reverse engineering and low-level concepts.

**Core Functionalities:**

1. **`test(self, state: ModuleState, args: T.Tuple[str, BuildTarget], kwargs: FuncTest) -> ModuleReturnValue`:**
   - **Purpose:** Generates a Rust test executable from an existing Rust library or executable target.
   - **Mechanism:** It creates a new executable target by copying the settings of the base target and adding the `--test` flag to the Rust arguments. It then defines a Meson test that runs this executable with the `rust` protocol.
   - **Benefit:** Simplifies the process of defining Rust tests, avoiding redundancy in specifying sources and dependencies.

2. **`bindgen(self, state: ModuleState, args: T.List, kwargs: FuncBindgen) -> ModuleReturnValue`:**
   - **Purpose:**  Wraps the `bindgen` tool, which generates Rust FFI (Foreign Function Interface) bindings from C/C++ header files.
   - **Mechanism:** It constructs a custom build target that executes the `bindgen` command with appropriate arguments, including include directories, compiler flags, input header file, and output file.
   - **Benefit:**  Simplifies the use of `bindgen` within Meson, especially handling include directories and dependencies.

3. **`proc_macro(self, state: ModuleState, args: T.Tuple[str, SourcesVarargsType], kwargs: _kwargs.SharedLibrary) -> SharedLibrary`:**
   - **Purpose:** Creates a Rust procedural macro target.
   - **Mechanism:** It essentially defines a `SharedLibrary` target with the `rust_crate_type` set to `proc-macro` and includes the `proc_macro` extern.
   - **Benefit:** Provides a convenient way to define Rust procedural macros within the Meson build system.

**Relationship to Reverse Engineering:**

This module has a strong connection to reverse engineering, primarily through the `bindgen` function.

* **Example:** Imagine you are reverse engineering a closed-source library written in C and want to interact with it from your Frida script (which can be written in JavaScript or Python). You would need to generate Rust bindings for the C library's headers. The `rust.bindgen` function facilitates this:

   ```meson
   rust_mod = import('unstable-rust')

   # Assuming you have the header file 'mylib.h'
   mylib_bindings = rust_mod.bindgen(
       input: files('mylib.h'),
       output: 'src/mylib_bindings.rs',
   )

   # Then, in your Rust code, you can use the generated bindings.
   ```
   This allows you to call functions and access data structures defined in the C library from your Rust code, which can then be integrated with Frida.

**Involvement of Binary 底层, Linux, Android Kernel & Framework Knowledge:**

* **`bindgen` and Low-Level Binaries:** The `bindgen` function directly interacts with C/C++ header files. These headers often define interfaces to low-level system components, libraries, and even kernel APIs (though direct kernel interaction from userspace is usually limited). When reverse engineering, you often encounter libraries that interact directly with the operating system or hardware. `bindgen` helps create a bridge to interact with these binary components from Rust.
* **Linux/Android Kernel and Framework Interaction (via C/C++):**  While this Meson module doesn't directly interact with the kernel, the C/C++ libraries whose bindings are generated *do*. For example, on Android, you might use `bindgen` to create bindings for system libraries like `libbinder` or framework components. These libraries provide the interface to the Android framework, which in turn interacts with the kernel.
* **Compiler Flags and Arguments:** The `bindgen` function allows passing `c_args` and uses logic to extract relevant compiler flags (like include paths and defines) from the Meson environment. These flags are crucial for correctly interpreting the C/C++ headers, especially when dealing with platform-specific code (like that found in Linux or Android system libraries).

**Logical Reasoning (Assumptions and Outputs):**

* **`test` function:**
    * **Assumption Input:** A valid Rust library or executable target (`base_target`).
    * **Assumption Input:** A test name (`name`).
    * **Possible Output:** A new `Executable` target configured for testing and a Meson `test` definition.
    * **Example:**
        * **Input:** `rust.test('my_lib_test', my_lib)` where `my_lib` is a `static_library` target.
        * **Output:**  A new executable target named `my_lib_test` will be created, built using the same sources as `my_lib`, but with the `--test` flag. A Meson test named `my_lib_test` will be registered to run this executable.

* **`bindgen` function:**
    * **Assumption Input:**  A path to a valid C or C++ header file (`input`).
    * **Assumption Input:** A desired output path for the Rust bindings (`output`).
    * **Possible Output:** A custom build target that, when executed, generates a Rust file containing the FFI bindings.
    * **Example:**
        * **Input:** `rust.bindgen(input: 'include/my_c_lib.h', output: 'src/bindings.rs')`
        * **Output:** A custom target will be created. When built, it will run the `bindgen` command on `include/my_c_lib.h` and generate the Rust bindings in `src/bindings.rs`.

* **`proc_macro` function:**
    * **Assumption Input:** A name for the procedural macro.
    * **Assumption Input:** Source files for the procedural macro.
    * **Possible Output:** A `SharedLibrary` target configured as a Rust procedural macro.

**User or Programming Common Usage Errors:**

* **`test` function:**
    * **Providing a non-Rust target:**  The code explicitly checks for `base_target.uses_rust()` and raises an `InterpreterException` if it's not a Rust target.
    * **Manually adding `--test`:** The code warns against this, as it's automatically added.
    * **Linking with Jar targets:** Rust tests cannot directly link with Java Archive files, and the code throws an `InvalidArguments` error.
* **`bindgen` function:**
    * **Providing a non-header file as input:** The code expects a C/C++ header. Providing a source file or object file will raise an `InterpreterException`.
    * **Not specifying the language for ambiguous headers:** If the header file extension doesn't clearly indicate C or C++, the user might need to explicitly set the `language` argument.
    * **Incorrect include directories:** If `bindgen` cannot find the included headers, the build will fail. Users need to ensure the `include_directories` argument is correctly set.
    * **Using `output_inline_wrapper` with an older `bindgen` version:** This feature requires `bindgen` 0.65 or newer.
* **`proc_macro` function:**
    * Common errors related to defining shared libraries, such as missing sources or incorrect linking arguments.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **Project Setup:** A user is working on a Frida project (indicated by the file path `frida/`). Specifically, they are within the `frida-qml` subproject, which likely deals with the QML interface of Frida.
2. **Meson Build System:** The user is utilizing the Meson build system, as evident by the `meson.build` files and the structure of the code.
3. **Rust Integration:** The user wants to integrate Rust code into their Frida QML project. This involves importing the `unstable-rust` Meson module (or potentially a stable version if available later).
4. **Specific Task:**
   - **Testing:** If the user wants to write tests for their Rust code, they would use the `rust.test()` function.
   - **FFI Bindings:** If they need to interact with C/C++ code from Rust (common in reverse engineering scenarios), they would use `rust.bindgen()`. This might involve inspecting header files of the target they are reverse engineering.
   - **Procedural Macros:** If they are developing custom compile-time code generation for their Rust code within Frida, they would use `rust.proc_macro()`.
5. **Meson Execution:** When the user runs the Meson configuration and build commands (e.g., `meson setup build`, `ninja -C build`), Meson will parse the `meson.build` files, identify the usage of the `rust` module, and execute the corresponding Python code in `rust.py`.
6. **Debugging Scenario:** If there is an error in how the user has called one of the functions in `rust.py` (e.g., incorrect arguments to `bindgen`), the Python interpreter will execute this code, and the error might originate from within this file. The stack trace would lead back to this specific module.

In summary, this `rust.py` module is a crucial component for integrating Rust code into the Frida build process, especially for tasks related to interacting with native code through FFI using `bindgen` and for simplifying the creation of Rust tests. Its location within the Frida QML project suggests its importance for extending Frida's capabilities using Rust and potentially interacting with Qt and other C/C++ libraries.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2020-2024 Intel Corporation

from __future__ import annotations
import itertools
import os
import typing as T

from mesonbuild.interpreterbase.decorators import FeatureNew

from . import ExtensionModule, ModuleReturnValue, ModuleInfo
from .. import mesonlib, mlog
from ..build import (BothLibraries, BuildTarget, CustomTargetIndex, Executable, ExtractedObjects, GeneratedList,
                     CustomTarget, InvalidArguments, Jar, StructuredSources, SharedLibrary)
from ..compilers.compilers import are_asserts_disabled, lang_suffixes
from ..interpreter.type_checking import (
    DEPENDENCIES_KW, LINK_WITH_KW, SHARED_LIB_KWS, TEST_KWS, OUTPUT_KW,
    INCLUDE_DIRECTORIES, SOURCES_VARARGS, NoneType, in_set_validator
)
from ..interpreterbase import ContainerTypeInfo, InterpreterException, KwargInfo, typed_kwargs, typed_pos_args, noPosargs, permittedKwargs
from ..mesonlib import File
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from . import ModuleState
    from ..build import IncludeDirs, LibTypes
    from ..dependencies import Dependency, ExternalLibrary
    from ..interpreter import Interpreter
    from ..interpreter import kwargs as _kwargs
    from ..interpreter.interpreter import SourceInputs, SourceOutputs
    from ..programs import OverrideProgram
    from ..interpreter.type_checking import SourcesVarargsType

    from typing_extensions import TypedDict, Literal

    class FuncTest(_kwargs.BaseTest):

        dependencies: T.List[T.Union[Dependency, ExternalLibrary]]
        is_parallel: bool
        link_with: T.List[LibTypes]
        rust_args: T.List[str]

    class FuncBindgen(TypedDict):

        args: T.List[str]
        c_args: T.List[str]
        include_directories: T.List[IncludeDirs]
        input: T.List[SourceInputs]
        output: str
        output_inline_wrapper: str
        dependencies: T.List[T.Union[Dependency, ExternalLibrary]]
        language: T.Optional[Literal['c', 'cpp']]
        bindgen_version: T.List[str]


class RustModule(ExtensionModule):

    """A module that holds helper functions for rust."""

    INFO = ModuleInfo('rust', '0.57.0', stabilized='1.0.0')

    def __init__(self, interpreter: Interpreter) -> None:
        super().__init__(interpreter)
        self._bindgen_bin: T.Optional[T.Union[ExternalProgram, Executable, OverrideProgram]] = None
        self.methods.update({
            'test': self.test,
            'bindgen': self.bindgen,
            'proc_macro': self.proc_macro,
        })

    @typed_pos_args('rust.test', str, BuildTarget)
    @typed_kwargs(
        'rust.test',
        *TEST_KWS,
        DEPENDENCIES_KW,
        LINK_WITH_KW.evolve(since='1.2.0'),
        KwargInfo(
            'rust_args',
            ContainerTypeInfo(list, str),
            listify=True,
            default=[],
            since='1.2.0',
        ),
        KwargInfo('is_parallel', bool, default=False),
    )
    def test(self, state: ModuleState, args: T.Tuple[str, BuildTarget], kwargs: FuncTest) -> ModuleReturnValue:
        """Generate a rust test target from a given rust target.

        Rust puts it's unitests inside it's main source files, unlike most
        languages that put them in external files. This means that normally
        you have to define two separate targets with basically the same
        arguments to get tests:

        ```meson
        rust_lib_sources = [...]
        rust_lib = static_library(
            'rust_lib',
            rust_lib_sources,
        )

        rust_lib_test = executable(
            'rust_lib_test',
            rust_lib_sources,
            rust_args : ['--test'],
        )

        test(
            'rust_lib_test',
            rust_lib_test,
            protocol : 'rust',
        )
        ```

        This is all fine, but not very DRY. This method makes it much easier
        to define rust tests:

        ```meson
        rust = import('unstable-rust')

        rust_lib = static_library(
            'rust_lib',
            [sources],
        )

        rust.test('rust_lib_test', rust_lib)
        ```
        """
        if any(isinstance(t, Jar) for t in kwargs.get('link_with', [])):
            raise InvalidArguments('Rust tests cannot link with Jar targets')

        name = args[0]
        base_target: BuildTarget = args[1]
        if not base_target.uses_rust():
            raise InterpreterException('Second positional argument to rustmod.test() must be a rust based target')
        extra_args = kwargs['args']

        # Delete any arguments we don't want passed
        if '--test' in extra_args:
            mlog.warning('Do not add --test to rustmod.test arguments')
            extra_args.remove('--test')
        if '--format' in extra_args:
            mlog.warning('Do not add --format to rustmod.test arguments')
            i = extra_args.index('--format')
            # Also delete the argument to --format
            del extra_args[i + 1]
            del extra_args[i]
        for i, a in enumerate(extra_args):
            if isinstance(a, str) and a.startswith('--format='):
                del extra_args[i]
                break

        # We need to cast here, as currently these don't have protocol in them, but test itself does.
        tkwargs = T.cast('_kwargs.FuncTest', kwargs.copy())

        tkwargs['args'] = extra_args + ['--test', '--format', 'pretty']
        tkwargs['protocol'] = 'rust'

        new_target_kwargs = base_target.original_kwargs.copy()
        # Don't mutate the shallow copied list, instead replace it with a new
        # one
        new_target_kwargs['install'] = False
        new_target_kwargs['dependencies'] = new_target_kwargs.get('dependencies', []) + kwargs['dependencies']
        new_target_kwargs['link_with'] = new_target_kwargs.get('link_with', []) + kwargs['link_with']
        del new_target_kwargs['rust_crate_type']

        lang_args = base_target.extra_args.copy()
        lang_args['rust'] = base_target.extra_args['rust'] + kwargs['rust_args'] + ['--test']
        new_target_kwargs['language_args'] = lang_args

        sources = T.cast('T.List[SourceOutputs]', base_target.sources.copy())
        sources.extend(base_target.generated)

        new_target = Executable(
            name, base_target.subdir, state.subproject, base_target.for_machine,
            sources, base_target.structured_sources,
            base_target.objects, base_target.environment, base_target.compilers,
            state.is_build_only_subproject, new_target_kwargs
        )

        test = self.interpreter.make_test(
            self.interpreter.current_node, (name, new_target), tkwargs)

        return ModuleReturnValue(None, [new_target, test])

    @noPosargs
    @typed_kwargs(
        'rust.bindgen',
        KwargInfo('c_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo(
            'input',
            ContainerTypeInfo(list, (File, GeneratedList, BuildTarget, BothLibraries, ExtractedObjects, CustomTargetIndex, CustomTarget, str), allow_empty=False),
            default=[],
            listify=True,
            required=True,
        ),
        KwargInfo('language', (str, NoneType), since='1.4.0', validator=in_set_validator({'c', 'cpp'})),
        KwargInfo('bindgen_version', ContainerTypeInfo(list, str), default=[], listify=True, since='1.4.0'),
        INCLUDE_DIRECTORIES.evolve(since_values={ContainerTypeInfo(list, str): '1.0.0'}),
        OUTPUT_KW,
        KwargInfo(
            'output_inline_wrapper',
            str,
            default='',
            since='1.4.0',
        ),
        DEPENDENCIES_KW.evolve(since='1.0.0'),
    )
    def bindgen(self, state: ModuleState, args: T.List, kwargs: FuncBindgen) -> ModuleReturnValue:
        """Wrapper around bindgen to simplify it's use.

        The main thing this simplifies is the use of `include_directory`
        objects, instead of having to pass a plethora of `-I` arguments.
        """
        header, *_deps = self.interpreter.source_strings_to_files(kwargs['input'])

        # Split File and Target dependencies to add pass to CustomTarget
        depends: T.List[SourceOutputs] = []
        depend_files: T.List[File] = []
        for d in _deps:
            if isinstance(d, File):
                depend_files.append(d)
            else:
                depends.append(d)

        # Copy to avoid subsequent calls mutating the original
        # TODO: if we want this to be per-machine we'll need a native kwarg
        clang_args = state.environment.properties.host.get_bindgen_clang_args().copy()

        for i in state.process_include_dirs(kwargs['include_directories']):
            # bindgen always uses clang, so it's safe to hardcode -I here
            clang_args.extend([f'-I{x}' for x in i.to_string_list(
                state.environment.get_source_dir(), state.environment.get_build_dir())])
        if are_asserts_disabled(state.environment.coredata.options):
            clang_args.append('-DNDEBUG')

        for de in kwargs['dependencies']:
            for i in de.get_include_dirs():
                clang_args.extend([f'-I{x}' for x in i.to_string_list(
                    state.environment.get_source_dir(), state.environment.get_build_dir())])
            clang_args.extend(de.get_all_compile_args())
            for s in de.get_sources():
                if isinstance(s, File):
                    depend_files.append(s)
                elif isinstance(s, CustomTarget):
                    depends.append(s)

        if self._bindgen_bin is None:
            self._bindgen_bin = state.find_program('bindgen', wanted=kwargs['bindgen_version'])

        name: str
        if isinstance(header, File):
            name = header.fname
        elif isinstance(header, (BuildTarget, BothLibraries, ExtractedObjects, StructuredSources)):
            raise InterpreterException('bindgen source file must be a C header, not an object or build target')
        else:
            name = header.get_outputs()[0]

        # bindgen assumes that C++ headers will be called .hpp. We want to
        # ensure that anything Meson considers a C++ header is treated as one.
        language = kwargs['language']
        if language is None:
            ext = os.path.splitext(name)[1][1:]
            if ext in lang_suffixes['cpp']:
                language = 'cpp'
            elif ext == 'h':
                language = 'c'
            else:
                raise InterpreterException(f'Unknown file type extension for: {name}')

        # We only want include directories and defines, other things may not be valid
        cargs = state.get_option('args', state.subproject, lang=language)
        assert isinstance(cargs, list), 'for mypy'
        for a in itertools.chain(state.global_args.get(language, []), state.project_args.get(language, []), cargs):
            if a.startswith(('-I', '/I', '-D', '/D', '-U', '/U')):
                clang_args.append(a)

        if language == 'cpp':
            clang_args.extend(['-x', 'c++'])

        # Add the C++ standard to the clang arguments. Attempt to translate VS
        # extension versions into the nearest standard version
        std = state.get_option('std', lang=language)
        assert isinstance(std, str), 'for mypy'
        if std.startswith('vc++'):
            if std.endswith('latest'):
                mlog.warning('Attempting to translate vc++latest into a clang compatible version.',
                             'Currently this is hardcoded for c++20', once=True, fatal=False)
                std = 'c++20'
            else:
                mlog.debug('The current C++ standard is a Visual Studio extension version.',
                           'bindgen will use a the nearest C++ standard instead')
                std = std[1:]

        if std != 'none':
            clang_args.append(f'-std={std}')

        inline_wrapper_args: T.List[str] = []
        outputs = [kwargs['output']]
        if kwargs['output_inline_wrapper']:
            # Todo drop this isinstance once Executable supports version_compare
            if isinstance(self._bindgen_bin, ExternalProgram):
                if mesonlib.version_compare(self._bindgen_bin.get_version(), '< 0.65'):
                    raise InterpreterException('\'output_inline_wrapper\' parameter of rust.bindgen requires bindgen-0.65 or newer')

            outputs.append(kwargs['output_inline_wrapper'])
            inline_wrapper_args = [
                '--experimental', '--wrap-static-fns',
                '--wrap-static-fns-path', os.path.join(state.environment.build_dir, '@OUTPUT1@')
            ]

        cmd = self._bindgen_bin.get_command() + \
            [
                '@INPUT@', '--output',
                os.path.join(state.environment.build_dir, '@OUTPUT0@')
            ] + \
            kwargs['args'] + inline_wrapper_args + ['--'] + \
            kwargs['c_args'] + clang_args + \
            ['-MD', '-MQ', '@INPUT@', '-MF', '@DEPFILE@']

        target = CustomTarget(
            f'rustmod-bindgen-{name}'.replace('/', '_'),
            state.subdir,
            state.subproject,
            state.environment,
            cmd,
            [header],
            outputs,
            state.is_build_only_subproject,
            depfile='@PLAINNAME@.d',
            extra_depends=depends,
            depend_files=depend_files,
            backend=state.backend,
            description='Generating bindings for Rust {}',
        )

        return ModuleReturnValue(target, [target])

    # Allow a limited set of kwargs, but still use the full set of typed_kwargs()
    # because it could be setting required default values.
    @FeatureNew('rust.proc_macro', '1.3.0')
    @permittedKwargs({'rust_args', 'rust_dependency_map', 'sources', 'dependencies', 'extra_files',
                      'link_args', 'link_depends', 'link_with', 'override_options'})
    @typed_pos_args('rust.proc_macro', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('rust.proc_macro', *SHARED_LIB_KWS, allow_unknown=True)
    def proc_macro(self, state: ModuleState, args: T.Tuple[str, SourcesVarargsType], kwargs: _kwargs.SharedLibrary) -> SharedLibrary:
        kwargs['native'] = True  # type: ignore
        kwargs['rust_crate_type'] = 'proc-macro'  # type: ignore
        kwargs['rust_args'] = kwargs['rust_args'] + ['--extern', 'proc_macro']
        target = state._interpreter.build_target(state.current_node, args, kwargs, SharedLibrary)
        return target


def initialize(interp: Interpreter) -> RustModule:
    return RustModule(interp)
```