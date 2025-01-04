Response:
Let's break down the thought process for analyzing this Python code and fulfilling the user's request.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `rust.py` file within the Frida project, particularly in relation to reverse engineering, low-level details, and potential user errors. The request also asks how a user might end up interacting with this code.

**2. High-Level Overview of the Code:**

First, I skimmed the code to identify the main components. I saw:

* **Imports:** Standard Python imports, plus specific imports from the Meson build system (`mesonbuild`). This immediately signals that this code is part of Meson's functionality for building Rust projects.
* **`RustModule` Class:** This is the central class, indicating this file defines a Meson module named "rust".
* **Methods (`test`, `bindgen`, `proc_macro`):**  These are the key functions that the "rust" module provides. The names suggest their purpose.
* **Type Hints:** Extensive use of type hints (`T.List`, `TypedDict`, etc.) helps in understanding the expected data types.
* **Docstrings:**  Each method has a docstring explaining its purpose and providing usage examples. This is a goldmine of information.

**3. Deconstructing Each Method:**

I then examined each method individually:

* **`test`:**
    * **Purpose (from docstring):**  Simplifies creating Rust test executables. It avoids redundant configuration compared to manually creating test targets.
    * **Reverse Engineering Relevance:** While not directly performing reverse engineering, it's essential for *testing* the results of reverse engineering efforts on Rust binaries. If you've modified a Rust binary, you'd use tests to verify your changes didn't break things or introduced new behavior.
    * **Low-Level Relevance:** It interacts with the build process, which ultimately compiles to machine code. It understands the structure of Rust projects (unit tests within source files).
    * **Logic/Assumptions:** Assumes the input is a Rust-based build target. It adds the `--test` flag to the compiler arguments.
    * **User Errors:**  Adding `--test` manually is discouraged, as the function handles it. Linking with `Jar` targets is not allowed.
    * **How to Reach:** By using `rust.test()` in a `meson.build` file.

* **`bindgen`:**
    * **Purpose (from docstring):** Wraps the `bindgen` tool, which generates Rust FFI (Foreign Function Interface) bindings to C/C++ code.
    * **Reverse Engineering Relevance:**  Crucial!  When reverse engineering native code (e.g., a shared library), you often want to interact with it from Rust. `bindgen` automates the creation of Rust code that can call C/C++ functions, access structs, etc. This is a fundamental step in many reverse engineering workflows involving Rust.
    * **Low-Level Relevance:** Directly deals with the low-level ABI (Application Binary Interface) between Rust and C/C++. Handles include paths, compiler arguments, and generates code that interacts with raw memory.
    * **Logic/Assumptions:**  Assumes the input is a C/C++ header file. It intelligently handles include directories and compiler flags.
    * **User Errors:**  Providing a non-header file as input. Incorrectly specifying language. Using an older version of `bindgen` if `output_inline_wrapper` is used.
    * **How to Reach:** By using `rust.bindgen()` in a `meson.build` file.

* **`proc_macro`:**
    * **Purpose (from docstring):**  Builds Rust procedural macros.
    * **Reverse Engineering Relevance:**  Indirectly related. Procedural macros are compile-time code generators in Rust. They can be used to create DSLs (Domain Specific Languages) or perform code transformations that might be helpful in reverse engineering tasks (e.g., generating boilerplate code for interacting with specific binary formats).
    * **Low-Level Relevance:**  Deals with the Rust compiler's internals and the process of creating compiler plugins.
    * **Logic/Assumptions:** Assumes the input sources define a Rust procedural macro.
    * **User Errors:** Likely related to misconfiguring dependencies or compiler arguments for procedural macros, which are a more advanced Rust feature.
    * **How to Reach:** By using `rust.proc_macro()` in a `meson.build` file.

**4. Identifying Connections to Reverse Engineering and Low-Level Concepts:**

As I analyzed each method, I explicitly looked for keywords and concepts related to reverse engineering, binary formats, operating systems, and low-level programming. "FFI", "C/C++", "header files", "ABI", "compiler arguments", "procedural macros" all pointed to these areas.

**5. Constructing Examples:**

For each method, I devised simple, concrete examples to illustrate its functionality and its relevance to the specific areas mentioned in the request. These examples aimed to be understandable and highlight the key aspects.

**6. Tracing User Interaction (Debugging Clues):**

To address how a user might reach this code, I considered the standard Meson workflow:

1. **`meson.build`:** The user writes a `meson.build` file to describe their project.
2. **Importing the Module:** The user imports the `rust` module using `rust = import('unstable-rust')`.
3. **Calling Module Functions:** The user then calls the functions provided by the module (e.g., `rust.test()`, `rust.bindgen()`).
4. **Meson Execution:**  When Meson is run, it parses the `meson.build` file and executes the Python code, including the `rust.py` module.

This step-by-step process provides the "debugging clues" for how user actions lead to the execution of this code.

**7. Review and Refinement:**

Finally, I reviewed my analysis to ensure it was clear, accurate, and addressed all parts of the user's request. I checked for any ambiguities or missing information. I aimed for a structured presentation, separating the analysis by method and then summarizing the overall connections.

This methodical approach, combining code reading with an understanding of the underlying concepts and the Meson build system, allowed me to generate a comprehensive and informative response.
This Python code defines a Meson build system module named `rust` for managing Rust-related build tasks within the Frida dynamic instrumentation tool. Let's break down its functionalities, connections to reverse engineering, low-level concepts, logic, potential errors, and how a user might interact with it.

**Functionalities:**

1. **`test(state, args, kwargs)`:**
   - **Purpose:** Generates a Rust test target from an existing Rust library or executable target.
   - **Simplification:**  Avoids the need to redundantly define almost identical targets for library and its tests. It automatically adds the necessary `--test` flag to the Rust compiler.
   - **Features:** Supports linking with dependencies, setting Rust-specific arguments (`rust_args`), and controlling parallel execution.

2. **`bindgen(state, args, kwargs)`:**
   - **Purpose:**  Provides a wrapper around the `bindgen` tool, which generates Rust Foreign Function Interface (FFI) bindings to C/C++ code.
   - **Simplification:**  Handles the complexities of passing include directories and compiler arguments to `bindgen`.
   - **Features:** Supports specifying input header files, output file names, C/C++ compiler arguments (`c_args`), custom `bindgen` arguments, language (C or C++), and dependencies. It also supports generating an inline wrapper for static functions (since bindgen 0.65).

3. **`proc_macro(state, args, kwargs)`:**
   - **Purpose:**  Builds Rust procedural macro libraries.
   - **Features:**  Treats the target as a native shared library with the `proc-macro` crate type and automatically includes `proc_macro` as an external dependency.

**Relationship to Reverse Engineering:**

* **`bindgen` is directly related to reverse engineering.** When reverse engineering native libraries (written in C/C++) and you want to interact with them from Rust, `bindgen` is a crucial tool. It automatically generates the necessary Rust code to call functions, access structs, and interact with data structures defined in the C/C++ headers.

   **Example:** Imagine you are reverse engineering a closed-source shared library (`libtarget.so`) with a C API. You have the header file (`target.h`) describing its functions. You would use `rust.bindgen` to generate Rust bindings:

   ```meson
   rust = import('unstable-rust')

   # Assuming target.h is in the same directory
   bindings = rust.bindgen(
       input: 'target.h',
       output: 'src/bindings.rs',
   )

   my_rust_lib = library(
       'my_rust_lib',
       sources: 'src/lib.rs',
       dependencies: bindings, # Use the generated bindings
   )
   ```

   Now, your Rust code in `src/lib.rs` can import the generated `bindings.rs` module and call functions from `libtarget.so`.

* **`test` is indirectly related.**  After reverse engineering and potentially modifying a Rust binary or library, you would use tests to ensure your changes haven't broken existing functionality or introduced new bugs. The `rust.test` function simplifies creating these tests.

* **`proc_macro` is less directly related but can be useful.** Procedural macros in Rust allow you to write code that generates other code at compile time. This could be used for tasks related to reverse engineering, such as automatically generating code to parse specific binary formats or create wrappers around complex data structures.

**Involvement of Binary Underpinnings, Linux, Android Kernel/Framework:**

* **Binary Underpinnings:** All these functions ultimately deal with the compilation and linking of code into binary executables or libraries. `bindgen` specifically generates code that interacts with the binary ABI (Application Binary Interface) of C/C++ libraries.
* **Linux/Android Kernel/Framework (Indirect):**  While this specific Python code doesn't directly interact with the kernel, the tools it manages (the Rust compiler, `bindgen`) are used to build software that runs on these platforms. For example, Frida itself is often used for reverse engineering and instrumentation on Android. The generated Rust bindings (via `bindgen`) could be used to interact with Android framework components or even potentially kernel interfaces (though this is more complex).

**Logic and Assumptions (Hypothetical Input/Output):**

**`test`:**

* **Hypothetical Input:**
   - `base_target`: A Rust `static_library` named 'mylib' with source files `src/lib.rs`.
   - `name`: 'mylib_test'.
* **Assumption:** The `mylib` target contains unit tests within its source code (common in Rust).
* **Output:** A new `executable` target named 'mylib_test' that compiles the same source files as 'mylib' but with the `--test` flag. This executable, when run, will execute the unit tests. A Meson `test` definition will also be created to run this executable.

**`bindgen`:**

* **Hypothetical Input:**
   - `input`: A C header file named `mylib.h` defining functions and structs.
   - `output`: `src/bindings.rs`.
* **Assumption:** The `bindgen` tool is installed and accessible in the system's PATH.
* **Output:** A Rust source file named `src/bindings.rs` containing Rust code that defines equivalent structs, functions (with `extern "C"` linkage), and other items from `mylib.h`, allowing Rust code to interact with a C library.

**`proc_macro`:**

* **Hypothetical Input:**
   - `name`: 'my_macro'
   - `sources`: `src/lib.rs` (containing the procedural macro definition).
* **Assumption:** The `src/lib.rs` file is structured correctly to define a Rust procedural macro.
* **Output:** A Rust shared library (with the `.so` or `.dylib` extension) that can be used as a procedural macro by other Rust crates.

**User or Programming Common Usage Errors:**

* **`test`:**
    * **Error:** Manually adding `--test` to the `rust_args`. The function already adds it.
    * **Example:** `rust.test('mylib_test', mylib, rust_args: ['--test'])` will likely result in a warning and the redundant flag being removed.
    * **Error:** Trying to link a Rust test with a `Jar` target (common in Java). Rust tests execute natively and cannot directly link with Java archives.
    * **Example:** `rust.test('mylib_test', mylib, link_with: my_java_jar)` will raise an `InvalidArguments` exception.

* **`bindgen`:**
    * **Error:** Providing a non-header file as input. `bindgen` expects C or C++ header files.
    * **Example:** `rust.bindgen(input: 'src/main.rs', output: 'bindings.rs')` will likely result in an error from `bindgen`.
    * **Error:** Incorrectly specifying the `language`. If you provide a `.h` file but set `language: 'cpp'`, `bindgen` might misinterpret the file.
    * **Error:** Using the `output_inline_wrapper` option with an older version of `bindgen` that doesn't support it. This will raise an `InterpreterException`.

* **`proc_macro`:**
    * **Error:** Not understanding the specific structure and requirements of Rust procedural macros. This is a more advanced Rust feature, and incorrect source code structure will lead to compilation errors.
    * **Error:**  Incorrectly managing dependencies for the procedural macro.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Writing a `meson.build` file:** A user starts by creating or modifying a `meson.build` file in their project.
2. **Importing the `rust` module:**  Within the `meson.build` file, the user imports the `rust` module using the line:
   ```meson
   rust = import('unstable-rust')
   ```
3. **Calling the `rust` module functions:** The user then calls the functions provided by the `rust` module to define Rust-related build targets:
   - To create a test target:
     ```meson
     my_rust_lib = static_library('mylib', 'src/lib.rs')
     rust.test('mylib_test', my_rust_lib)
     ```
   - To generate FFI bindings:
     ```meson
     bindings = rust.bindgen(input: 'mylib.h', output: 'src/bindings.rs')
     ```
   - To build a procedural macro:
     ```meson
     my_macro = rust.proc_macro('my_macro', 'src/lib.rs')
     ```
4. **Running Meson:** The user then executes the Meson command in their terminal (e.g., `meson setup builddir`). This command reads and interprets the `meson.build` file.
5. **Meson invokes the `rust.py` module:** During the interpretation of `meson.build`, when Meson encounters calls to functions within the imported `rust` module, it executes the corresponding Python code in `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/rust.py`.
6. **Error or Success:** Depending on the arguments provided to the `rust` module functions and the state of the project, the Python code will either successfully create the desired build targets or raise exceptions due to errors in the `meson.build` file or the project structure. These exceptions or warnings will often be reported to the user by Meson, providing debugging clues.

In essence, a user indirectly interacts with this Python code by using the high-level Meson API provided by the `rust` module in their `meson.build` file. Meson then acts as an intermediary, executing this Python code to perform the underlying build system operations.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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