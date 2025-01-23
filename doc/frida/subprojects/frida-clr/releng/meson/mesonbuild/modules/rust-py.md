Response:
Let's break down the thought process for analyzing this Python code and generating the detailed response.

**1. Understanding the Goal:**

The primary goal is to analyze the provided Python code (`rust.py`) which is part of the Frida dynamic instrumentation tool. The analysis needs to cover its functionality, its relation to reverse engineering, its use of low-level/kernel concepts, any logical inferences it makes, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and Identification of Key Areas:**

First, a quick scan of the code reveals keywords and patterns that hint at the functionality:

* **`class RustModule(ExtensionModule)`:** This tells us it's a Meson module extending Meson's build system capabilities for Rust projects.
* **`self.methods.update(...)`:** This shows the main functions exposed by the module: `test`, `bindgen`, and `proc_macro`.
* **Decorators like `@typed_pos_args`, `@typed_kwargs`, `@FeatureNew`:** These indicate how the functions are used and provide metadata.
* **Imports like `mesonbuild`, `mlog`, `build`, `compilers`, `interpreter`, `mesonlib`, `programs`:** These reveal the code interacts with Meson's core components.
* **Type hints (`T.List`, `T.Optional`, `typing`):**  These improve code readability and help understand the expected types of variables and function arguments.
* **Function docstrings:**  These provide a high-level overview of each function's purpose.

**3. Detailed Analysis of Each Function:**

* **`test(self, state, args, kwargs)`:**
    * **Purpose:**  Creates a test executable for a Rust library. It avoids redundant definitions by reusing the source files of the library.
    * **Reverse Engineering Relevance:**  While it doesn't directly perform reverse engineering, testing is crucial in understanding and validating the behavior of software, which is often a part of reverse engineering workflows.
    * **Low-Level/Kernel:**  Not directly involved.
    * **Logic:** It infers the test target's sources from the base library and adds test-specific arguments (`--test`, `--format pretty`).
    * **User Errors:**  Trying to link with Jar files is caught. Adding redundant `--test` or `--format` arguments triggers a warning.
    * **User Journey:** A user defines a Rust library and then wants to add a test for it using `rust.test`.

* **`bindgen(self, state, args, kwargs)`:**
    * **Purpose:**  Wraps the `bindgen` tool to generate Rust FFI (Foreign Function Interface) bindings for C/C++ headers.
    * **Reverse Engineering Relevance:**  Generating FFI bindings is essential for interacting with native libraries from Rust, a common task in reverse engineering scenarios where you need to interface with existing C/C++ code.
    * **Low-Level/Kernel:** Deals with include directories and compiler arguments, which can be relevant when dealing with system libraries or kernel headers.
    * **Logic:** It determines the language (C or C++) of the header file, handles include directories, and constructs the `bindgen` command.
    * **User Errors:**  Providing a non-header file as input, using an older version of `bindgen` with `output_inline_wrapper`.
    * **User Journey:** A user has a C/C++ header file and wants to generate Rust bindings for it using `rust.bindgen`.

* **`proc_macro(self, state, args, kwargs)`:**
    * **Purpose:**  Creates a Rust procedural macro library.
    * **Reverse Engineering Relevance:** Procedural macros in Rust can be used to analyze and manipulate code at compile time. While not direct reverse engineering, they can be powerful tools in code analysis and transformation.
    * **Low-Level/Kernel:** Not directly involved.
    * **Logic:**  It sets specific crate types and arguments for procedural macros.
    * **User Errors:**  The code doesn't explicitly show error handling beyond Meson's built-in checks.
    * **User Journey:** A user wants to create a Rust procedural macro library using `rust.proc_macro`.

**4. Identifying Connections to Reverse Engineering, Low-Level Concepts, and User Errors:**

As the function analysis progresses, note down the connections to the specific areas mentioned in the prompt. This involves recognizing:

* **Reverse Engineering:**  FFI bindings (via `bindgen`), testing for understanding behavior, potential for code analysis with procedural macros.
* **Low-Level:** Interaction with compiler arguments, include directories (important for system headers), handling of C/C++ language differences.
* **User Errors:**  Incorrect input types, missing dependencies, using features with incompatible versions, redundant arguments.

**5. Logical Inferences and Hypothetical Scenarios:**

Think about what the code *implicitly* does. For example, `rust.test` infers that you want a test executable based on an existing library. Construct hypothetical input/output examples to illustrate the function's behavior.

**6. User Journey for Debugging:**

Consider how a developer might arrive at this specific file. They are likely working on a Rust project that uses Meson as a build system and are encountering issues related to:

* Building Rust tests.
* Generating FFI bindings using `bindgen`.
* Creating Rust procedural macros.

They might be inspecting the Meson build files or encountering errors during the build process, leading them to investigate the `rust.py` module.

**7. Structuring the Response:**

Organize the information clearly, addressing each point in the prompt. Use headings and bullet points for readability. Provide concrete examples to illustrate the concepts. Start with a general overview and then delve into the specifics of each function.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have focused too much on the direct reverse engineering actions.**  It's important to also consider how the tools facilitate the *process* of reverse engineering (like testing and interacting with native code).
* **I could have initially missed the significance of `proc_macro`.**  Realizing its potential in code analysis strengthens the reverse engineering connection.
* **The "User Journey" requires stepping back and thinking about the typical development workflow.**  It's not just about what the code *does*, but *why* and *how* someone would interact with it.

By following this structured thought process, combining code analysis with an understanding of the broader context of Frida and Meson, it's possible to generate a comprehensive and accurate response like the example provided.
This Python file, `rust.py`, is a module within the Meson build system that provides functionality specifically for building and integrating Rust code into larger projects. Frida, being a dynamic instrumentation toolkit, often needs to interact with code written in various languages, and Rust is becoming increasingly common for performance-critical components.

Here's a breakdown of its functionalities, connecting them to reverse engineering, low-level concepts, logical inferences, potential user errors, and debugging:

**Core Functionalities:**

1. **`test(self, state, args, kwargs)`:**  This function simplifies the creation of Rust test executables.
   - **Functionality:** It takes an existing Rust library or executable target as input and creates a new executable that runs the Rust unit tests embedded within the source code. It automatically adds the necessary `--test` flag to the Rust compiler.
   - **Reverse Engineering Relevance:** Testing is a fundamental aspect of reverse engineering. By running the unit tests of a Rust component, a reverse engineer can gain insights into its intended behavior, data structures, and internal logic without necessarily having the source code's full context. You can observe the test cases and infer how different inputs are expected to be handled.
   - **Low-Level/Kernel:** Not directly involved at this level, but the tests themselves might interact with lower-level APIs or system calls.
   - **Logical Inference:** The function infers that if you have a Rust target, you might want to easily create a corresponding test runner. It avoids redundant definitions of source files.
   - **User Errors:**
     - **Example:** A user might try to link a Rust test with a Java `Jar` target, which is not supported. The function explicitly checks for this and raises an `InvalidArguments` exception.
     - **Example:** A user might manually add `--test` to the `rust_args`. The function detects this and issues a warning, as it adds this argument automatically.
   - **User Journey (Debugging):** A developer working on a Frida component written in Rust defines a library (`static_library`). They then want to create a test. They use the `rust.test` function, providing the test name and the library target. If the test fails to link or run, they might inspect the arguments passed to the Rust compiler by Meson, potentially tracing back to this `test` function to see how the test target was constructed.

2. **`bindgen(self, state, args, kwargs)`:** This function acts as a wrapper around the `bindgen` tool, which generates Rust FFI (Foreign Function Interface) bindings for C/C++ headers.
   - **Functionality:** It simplifies the process of calling the `bindgen` command by handling include directories, dependencies, and output paths.
   - **Reverse Engineering Relevance:** `bindgen` is crucial for reverse engineering scenarios where you need to interact with native libraries (often written in C/C++) from Rust. Frida itself extensively uses this to interact with system APIs and target processes. By generating Rust bindings, you can call functions, access data structures, and interact with the native code in a type-safe manner from your Rust code.
     - **Example:** If Frida needs to interact with a specific function in the Android NDK (written in C), `bindgen` would be used to create Rust bindings for the relevant header files, allowing Rust code within Frida to call that NDK function.
   - **Low-Level/Kernel:** This function directly deals with aspects of compiling C/C++ code, such as include directories (`-I`), preprocessor definitions (`-D`), and language standards (`-std`). These are fundamental concepts when working with native code and interacting with operating system APIs or kernel headers.
   - **Logical Inference:** The function infers the language (C or C++) of the input header file based on its extension.
   - **User Errors:**
     - **Example:** A user might provide a non-header file as input to `bindgen`. The function checks the input type and raises an `InterpreterException`.
     - **Example:** If the user forgets to specify necessary include directories for the C/C++ headers, `bindgen` will fail. This function helps by allowing the user to specify `include_directories` in a Meson-friendly way, which are then translated to `-I` flags for `bindgen`.
     - **Example:**  Using a feature like `output_inline_wrapper` with an older version of `bindgen` will result in an error caught by this function.
   - **User Journey (Debugging):** A Frida developer wants to call a function from a C library. They use `rust.bindgen` to generate the Rust bindings. If the generated bindings are incorrect or the `bindgen` command fails, they might inspect the arguments passed to `bindgen` by Meson, the include directories being used, and the version of `bindgen` being called. This leads them back to the `bindgen` function in `rust.py`.

3. **`proc_macro(self, state, args, kwargs)`:** This function creates a Rust procedural macro library.
   - **Functionality:** It simplifies the creation of Rust procedural macros by setting the correct `rust_crate_type` and ensuring the `proc_macro` extern is included.
   - **Reverse Engineering Relevance:** While not directly involved in analyzing existing binaries, procedural macros are powerful tools for code generation and manipulation at compile time. In the context of Frida, one could potentially use them to create custom code transformations or analysis tools that operate on the Rust code being instrumented.
   - **Low-Level/Kernel:** Not directly involved.
   - **Logical Inference:** The function infers that if you're calling `proc_macro`, you intend to create a library with the `proc-macro` crate type.
   - **User Errors:**  Users might incorrectly configure dependencies or arguments for the procedural macro. While this function simplifies the initial setup, more complex errors might arise within the macro's implementation.
   - **User Journey (Debugging):** A Frida developer wants to create a compile-time code transformation using a Rust procedural macro. They use `rust.proc_macro`. If the macro fails to compile or doesn't function as expected, they might inspect the arguments passed to the Rust compiler and the overall build process, potentially tracing back to how the `proc_macro` target was defined.

**General Connections:**

* **Binary Underlying:** While not directly manipulating raw binary code, this module deals with compiling Rust code, which ultimately produces binary executables or libraries. The `bindgen` functionality bridges the gap between Rust and native C/C++ binaries.
* **Linux/Android Kernel & Framework:** Frida often operates by injecting into processes running on Linux and Android. The `bindgen` functionality is crucial for interacting with system libraries and framework components on these platforms. For example, on Android, Frida might use `bindgen` to interact with the Android Runtime (ART) or system services.
* **User Operations Reaching This Code (Debugging Scenario):**
    1. **Project Setup:** A developer is setting up a Frida project that includes Rust components. They use the Meson build system.
    2. **Defining a Rust Target:** They define a `static_library` or `executable` using the `rust` language.
    3. **Adding Tests (for `test`):** They decide to add unit tests for their Rust code and use the `rust.test` function in their `meson.build` file.
    4. **Interfacing with Native Code (for `bindgen`):** They need to interact with a C library (e.g., from the Android NDK) and use `rust.bindgen` to generate the necessary FFI bindings.
    5. **Creating a Procedural Macro (for `proc_macro`):** They want to create a compile-time code transformation and use `rust.proc_macro` to define the macro library.
    6. **Build Execution:** They run the `meson compile` command.
    7. **Build Errors:** If any errors occur during the Rust compilation or `bindgen` execution, Meson will provide error messages that might point back to issues in the `meson.build` file related to how these functions were used.
    8. **Inspecting Build Files:** The developer might then inspect the generated Ninja build files (used by Meson) to see the exact commands being executed for Rust compilation and `bindgen`.
    9. **Tracing Back to `rust.py`:** If the issue seems related to how Meson is handling the Rust-specific aspects, the developer might look into the `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/rust.py` file to understand the implementation of the `test`, `bindgen`, and `proc_macro` functions and how they translate the Meson definitions into actual build commands.

**In summary, `rust.py` is a crucial component for integrating Rust code into Frida projects. It simplifies common tasks like creating tests, generating FFI bindings, and defining procedural macros, making it easier for developers to leverage Rust's performance and safety within the Frida ecosystem. Its functionalities are directly relevant to reverse engineering when interacting with native code or analyzing program behavior through testing.**

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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