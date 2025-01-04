Response:
Let's break down the thought process to analyze the Python code and address the prompt's requirements.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `rust.py` file within the Frida project and relate it to concepts like reverse engineering, low-level details, and potential user errors. The prompt explicitly asks for examples in each of these categories.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd scan the code to get a general idea of its purpose. Keywords like `rust`, `bindgen`, `test`, `proc_macro`, `static_library`, `executable`, `include_directories`, and `dependencies` jump out. The imports also hint at the Meson build system. This suggests the file is about integrating Rust code into a larger project using Meson.

**3. Analyzing Each Function:**

I'd then analyze each function (`test`, `bindgen`, `proc_macro`) individually:

* **`test`:**  The docstring is very helpful here. It explains how this function simplifies creating Rust test executables. The key idea is avoiding redundancy by defining the test based on an existing library target. This leads to the "DRY" principle. I would also note the handling of `--test` and `--format` arguments, which points to how Rust tests are executed. The function creates a new `Executable` target with specific `rust_args`.

* **`bindgen`:**  The docstring again provides valuable information. It's a wrapper around `bindgen`, a tool for generating Rust FFI (Foreign Function Interface) bindings from C/C++ headers. Key aspects here are handling include directories, dependencies, language detection (C/C++), and generating a `CustomTarget`. The handling of clang arguments and C++ standard is also important.

* **`proc_macro`:** The name suggests this handles Rust procedural macros. The code is concise, setting specific flags (`native=True`, `rust_crate_type='proc-macro'`) for creating a `SharedLibrary`.

**4. Connecting to Reverse Engineering:**

Now, I'd explicitly consider the "reverse engineering" aspect. `bindgen` is the most obvious connection. Reverse engineering often involves interacting with existing (sometimes closed-source) libraries. `bindgen` allows Rust code to interface with C/C++ libraries, which are common in reverse engineering scenarios. I'd think of a concrete example: using Frida to hook into a native Android library written in C++. `bindgen` would be crucial for generating the Rust bindings to interact with that library's functions and data structures.

**5. Identifying Low-Level Details and System Knowledge:**

Next, I'd focus on the low-level aspects:

* **`bindgen` and FFI:** The very nature of `bindgen` and creating FFI bindings implies working at a lower level, bridging the gap between Rust's memory management and the potentially manual memory management of C/C++.
* **Include Directories:** The handling of `include_directories` directly relates to how compilers find header files, a fundamental concept in compilation and linking.
* **Clang Arguments:** The code directly manipulates clang arguments, indicating an understanding of how the C/C++ compilation process works. Mentioning `-I`, `-D`, `-std`, `-x c++` shows specific compiler flags.
* **`proc_macro` and Shared Libraries:** Procedural macros are a more advanced Rust feature that often involves manipulating the Rust compiler's abstract syntax tree (AST). Building them as shared libraries is relevant to how they are loaded and used by the compiler.
* **`rust_crate_type`:** The `proc_macro` function sets `rust_crate_type`, demonstrating knowledge of Rust's crate types and how they affect the build process.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

For logical reasoning, I'd pick a function and create a simple scenario:

* **`bindgen` Example:** Imagine a C header file `mylib.h` with a function `int add(int a, int b);`. I would trace the execution of `bindgen` with this as input and predict the generated Rust code, focusing on the function signature translation.

**7. Identifying User Errors:**

I'd consider common mistakes a user might make when using these functions:

* **`test`:** Incorrect target type, forgetting dependencies, misunderstanding how `rust_args` work.
* **`bindgen`:** Incorrect input file type, missing include directories, version mismatch with `bindgen`, problems with clang arguments, forgetting dependencies.
* **`proc_macro`:** Issues with dependencies, incorrect crate type (though this is handled internally here), errors in the macro logic itself (though this file doesn't directly control that).

**8. Tracing User Operations:**

Finally, I'd imagine the steps a user would take to reach this code:

1. **Project Setup:**  Creating a Meson project that includes Rust code.
2. **Importing the Module:** Using `rust = import('unstable-rust')` in their `meson.build` file.
3. **Using the Functions:** Calling `rust.test()`, `rust.bindgen()`, or `rust.proc_macro()` with appropriate arguments.
4. **Meson Processing:** Meson interprets the `meson.build` file and executes the Python code, including this `rust.py` module.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the Rust side.** I'd need to remember this is about the *Meson* integration of Rust.
* **I would double-check the parameter types and keyword arguments** of each function to ensure my examples are accurate.
* **For user errors, I'd try to think from a beginner's perspective.** What are the most common pitfalls?
* **I'd ensure the examples for reverse engineering, low-level, and logical reasoning are distinct and relevant.**

By following these steps, combining code analysis with an understanding of the underlying concepts, and specifically addressing each part of the prompt, I can generate a comprehensive and informative answer.This Python code file, `rust.py`, is a module within the Meson build system specifically designed to facilitate the integration of Rust code into projects. Meson is a build system like CMake or Make, used to automate the compilation process. This module provides custom functionality for handling Rust-specific tasks.

Here's a breakdown of its functionalities:

**1. Rust Test Integration (`test` function):**

   * **Functionality:** This function simplifies the creation of Rust test executables. Rust's unit tests are typically embedded within the source files. Without this function, you'd need to create a separate executable target with the `--test` flag. This function streamlines this process by taking an existing Rust library or executable target and creating a test runner from it.
   * **Relationship to Reverse Engineering:** While not directly a reverse engineering *tool*, writing tests for existing Rust code can be a crucial part of understanding its behavior, which is often a step in reverse engineering. By running these tests, you can observe the inputs and outputs of functions, helping to deduce their purpose and logic.
   * **Binary/Low-Level/Kernel/Framework Relevance:**
      *  Rust tests often interact with the compiled binary of the Rust code. The `--test` flag instructs the Rust compiler (`rustc`) to build an executable that runs these tests.
      *  If the Rust code being tested interacts with the operating system (e.g., file system, networking), the tests will indirectly involve those OS functionalities.
   * **Logical Reasoning (Hypothetical Input/Output):**
      * **Input:**  Let's say you have a Rust static library target named `my_rust_lib`. You call `rust.test('my_rust_lib_test', my_rust_lib)`.
      * **Output:** Meson will generate a new executable target (likely named `my_rust_lib_test`) that, when built and run, will execute the unit tests found within the source files of `my_rust_lib`. The output will be the results of these tests (pass/fail).
   * **Common User Errors:**
      * **Incorrect Target Type:**  Providing a non-Rust target as the second argument will raise an `InterpreterException`. For example, `rust.test('my_c_test', my_c_library)` where `my_c_library` is a C library.
      * **Adding Redundant Arguments:** Users might mistakenly add `--test` to the `rust_args` kwarg, which the function explicitly warns against.
   * **User Operation to Reach Here:**
      1. The user has a Meson project that includes Rust code.
      2. In their `meson.build` file, they've imported the `unstable-rust` module: `rust = import('unstable-rust')`.
      3. They've defined a Rust library or executable target.
      4. They call the `rust.test()` function, passing the desired test name and the Rust target as arguments.
      5. When Meson processes the `meson.build` file, it executes this `test` function in `rust.py`.

**2. `bindgen` Integration (`bindgen` function):**

   * **Functionality:** This function provides a wrapper around the `bindgen` tool. `bindgen` is a crucial tool in Rust development for generating Rust Foreign Function Interface (FFI) bindings from C or C++ header files. This allows Rust code to interact with libraries written in C or C++.
   * **Relationship to Reverse Engineering:** This is directly relevant to reverse engineering. When analyzing closed-source or pre-existing native libraries (often written in C/C++), `bindgen` is essential to create Rust bindings that allow inspection and interaction with the library's functions and data structures from within a Frida script or other Rust-based tooling.
      * **Example:** Imagine you're reverse engineering an Android app with a native library (`.so` file). You would first obtain the header files for that library. Then, you'd use this `rust.bindgen` function within your Meson build setup to generate Rust code that defines the structures, functions, and constants declared in those headers, making it possible to call those native functions from Rust.
   * **Binary/Low-Level/Kernel/Framework Relevance:**
      * **Binary/Low-Level:** `bindgen` directly deals with the binary layout and calling conventions of C/C++ code. The generated Rust code allows interaction at the memory level with data structures defined in C/C++.
      * **Linux/Android Kernel/Framework:** If the C/C++ headers describe interfaces to the Linux kernel or Android framework (e.g., system calls, framework APIs), `bindgen` bridges the gap, enabling Rust code to interact with these lower-level components.
   * **Logical Reasoning (Hypothetical Input/Output):**
      * **Input:** You have a C header file `mylib.h` with a function declaration `int add(int a, int b);`. You call `rust.bindgen(input: 'mylib.h', output: 'bindings.rs')`.
      * **Output:** Meson will execute the `bindgen` tool, which will parse `mylib.h` and generate a Rust source file named `bindings.rs`. This file will contain Rust code declaring a function like `pub fn add(a: ::std::os::raw::c_int, b: ::std::os::raw::c_int) -> ::std::os::raw::c_int;`, allowing you to call the C `add` function from your Rust code.
   * **Common User Errors:**
      * **Incorrect Input:** Providing a non-header file or a build target as input will cause an error. The input should be the C/C++ header file.
      * **Missing Include Directories:** If the header file includes other headers, you need to specify the paths to those directories using the `include_directories` kwarg.
      * **`bindgen` Version Issues:**  Using features of `bindgen` that are not available in the installed version (specified by `bindgen_version`) will lead to errors.
   * **User Operation to Reach Here:**
      1. The user wants to use a C/C++ library from their Rust code.
      2. They have the header file(s) for that library.
      3. In their `meson.build`, they call `rust.bindgen()`, providing the path to the header file (`input`) and the desired output path for the generated Rust bindings (`output`).
      4. Meson will invoke this `bindgen` function.

**3. Procedural Macro Integration (`proc_macro` function):**

   * **Functionality:** This function assists in building Rust procedural macros. Procedural macros are a powerful feature in Rust that allows you to write code that generates other Rust code at compile time. They are essentially compiler plugins.
   * **Relationship to Reverse Engineering:** While not a direct reverse engineering technique, procedural macros can be used to automate tasks related to reverse engineering, such as generating boilerplate code for interacting with specific data formats or automatically deriving traits for interacting with certain types.
   * **Binary/Low-Level/Kernel/Framework Relevance:**
      * Procedural macros are compiled into dynamic libraries (shared libraries) that are loaded by the Rust compiler. This involves low-level details of dynamic linking.
   * **Logical Reasoning (Hypothetical Input/Output):**
      * **Input:** You have Rust source files that define a procedural macro. You call `rust.proc_macro('my_macro', sources: 'src/lib.rs')`.
      * **Output:** Meson will compile the Rust code in `src/lib.rs` as a procedural macro (a dynamic library). This macro can then be used in other parts of your Rust project by annotating code with `#[my_macro]`.
   * **Common User Errors:**
      * **Incorrect `rust_crate_type`:** While this function sets the `rust_crate_type` internally to `proc-macro`, if a user tries to override it incorrectly, it will lead to build errors.
      * **Dependency Issues:** Procedural macros often depend on other crates. Incorrectly specifying or missing dependencies in the `dependencies` kwarg will cause compilation failures.
   * **User Operation to Reach Here:**
      1. The user is developing a Rust procedural macro.
      2. In their `meson.build`, they use `rust.proc_macro()` to define the build target for their macro, specifying the macro's name and source files.
      3. Meson executes this function to configure the build process for the procedural macro.

**In Summary:**

This `rust.py` module in Frida's build system provides essential tools for integrating Rust code into the larger project. It simplifies common Rust development tasks like testing, generating FFI bindings, and building procedural macros. Its `bindgen` functionality is particularly relevant to reverse engineering efforts, enabling interaction with native libraries from Rust code. The module touches upon binary-level concepts, interaction with the operating system, and the intricacies of the Rust compiler and its ecosystem.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```