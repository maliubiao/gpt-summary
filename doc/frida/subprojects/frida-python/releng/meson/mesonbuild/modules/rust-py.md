Response:
Let's break down the request and the provided Python code to address all the points systematically.

**1. Understanding the Goal:**

The core goal is to analyze a specific Python file (`rust.py`) within the Frida project and explain its functionality, relating it to reverse engineering, low-level concepts, and common usage scenarios. The emphasis is on explaining *how* this code fits into the broader Frida ecosystem.

**2. Initial Code Scan and High-Level Understanding:**

First, I skim the code to get a general idea of what it does. I see:

* **Module for Rust integration:** The name `RustModule` and the imported modules like `bindgen` suggest this is about integrating Rust code into a larger build system (likely Meson, given the file path).
* **Key functions:** `test`, `bindgen`, and `proc_macro` stand out. These are likely the primary functionalities offered by this module.
* **Interaction with build system concepts:**  It uses Meson concepts like `BuildTarget`, `Executable`, `SharedLibrary`, `CustomTarget`, `IncludeDirs`, `Dependency`, etc. This means it's extending Meson's capabilities for Rust.

**3. Function-Specific Analysis (Mental Walkthrough):**

* **`test` function:**  This seems to simplify creating Rust test executables. It takes an existing Rust target and wraps it to run tests. The code manipulates arguments (`--test`, `--format`) which is typical in testing frameworks.

* **`bindgen` function:** This clearly deals with `bindgen`, a tool for generating FFI (Foreign Function Interface) bindings between Rust and C/C++. It handles include directories, compiler arguments, and output file generation. The logic to determine the language (`c` or `cpp`) based on file extension is present.

* **`proc_macro` function:** This is about building Rust procedural macros. It sets specific crate types and includes `proc_macro` as an external dependency, which aligns with how procedural macros work in Rust.

**4. Connecting to Reverse Engineering (Instruction 2):**

Now, the crucial part is connecting these functionalities to reverse engineering. I think about *why* someone using Frida might want to use Rust and these specific features:

* **`bindgen` for interacting with native code:**  Frida often interacts with the target process's native code (C/C++). `bindgen` is the bridge that allows Rust code within Frida to call into these native libraries or frameworks. This is a direct link to reverse engineering as it facilitates inspecting and manipulating the target's internals.

* **`test` function for validating hooks and instrumentation:** After implementing hooks or instrumentation logic in Rust, developers need to test them. The `test` function helps create test executables within the build process to verify that the instrumentation behaves as expected.

* **`proc_macro` for metaprogramming and code generation:** Procedural macros can be used to generate code at compile time. In a reverse engineering context, this could be used for tasks like automatically generating wrappers for specific APIs or creating specialized instrumentation logic based on the target's structure.

**5. Connecting to Low-Level Concepts (Instruction 3):**

This requires knowledge of how Rust interacts with the underlying system:

* **FFI and `bindgen`:**  The entire `bindgen` functionality revolves around FFI, which is the mechanism for Rust to interact with code compiled in other languages at the binary level. This touches upon concepts like calling conventions, data layout, and memory management across language boundaries.

* **Rust's interaction with the OS (Linux/Android):** When Frida runs on Linux or Android, the Rust code will interact with the kernel and framework APIs. This might involve system calls, interacting with shared libraries, or using platform-specific features. While this code doesn't directly *implement* those interactions, it provides the *building blocks* for doing so.

* **Memory safety and control:** Rust is known for its memory safety features. Using Rust within Frida can offer a safer way to interact with potentially unsafe target processes.

**6. Logical Reasoning and Examples (Instruction 4):**

Here, I need to create hypothetical scenarios to illustrate how the functions work. This involves imagining input to these functions and predicting the output (in terms of Meson build targets).

* **`test` example:**  Imagine a Rust library target is passed to `rust.test`. The output will be a new executable target configured to run tests against that library.

* **`bindgen` example:**  Providing a C header file to `rust.bindgen` will result in a custom target that executes `bindgen` to generate Rust bindings.

**7. Common Usage Errors (Instruction 5):**

This requires thinking about mistakes a user might make when using these functions based on their parameters and expected behavior.

* **`test` errors:**  Trying to test a non-Rust target, forgetting the `protocol: 'rust'` in the `test()` call.
* **`bindgen` errors:**  Providing incorrect include directories, missing required input files, misunderstanding the `output` and `output_inline_wrapper` parameters.
* **`proc_macro` errors:**  Incorrectly specifying dependencies or crate types.

**8. User Journey and Debugging (Instruction 6):**

This is about tracing how a user's actions in the Meson build system would lead to the execution of this code.

* **Meson project setup:** The user would have a `meson.build` file.
* **Importing the Rust module:** They would use `rust = import('unstable-rust')`.
* **Calling the module's functions:** They would call `rust.test()`, `rust.bindgen()`, or `rust.proc_macro()` with specific arguments.
* **Meson processing:** Meson would parse the `meson.build` file and execute the Python code in `rust.py` to create the necessary build targets.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** I might initially focus too much on the internal implementation details of `bindgen`. However, the request asks for the *functionality* from the perspective of the Meson module. So, the focus should be on how this module *uses* `bindgen`.
* **Connecting to Frida:** It's crucial to explicitly tie the functionalities back to the use cases within Frida. Simply explaining what `bindgen` does isn't enough; I need to explain *why* Frida would use it.
* **Clarity of examples:** The input/output examples need to be concrete enough to be understandable but not overly complex.

By following these steps, I can systematically analyze the code and address all aspects of the request, resulting in a comprehensive and informative explanation.
Let's break down the functionality of the `rust.py` file within the Frida project and address your specific questions.

**Core Functionality: Extending Meson for Rust Projects**

This Python file is a **Meson module** designed to simplify the integration of Rust code into projects built with the Meson build system. Meson is a meta-build system, meaning it generates native build files (like Makefiles or Ninja build files) from a higher-level description of the project. This `rust.py` module adds Rust-specific capabilities to Meson.

Here's a breakdown of its main functions:

* **`test(self, state, args, kwargs)`:**  Simplifies the creation of Rust test executables. It takes an existing Rust library or executable target and automatically creates a new executable configured to run the Rust unit tests embedded within the source code.
* **`bindgen(self, state, args, kwargs)`:**  Provides a wrapper around the `bindgen` tool, which generates Rust Foreign Function Interface (FFI) bindings to C and C++ code. This allows Rust code to interact with existing native libraries.
* **`proc_macro(self, state, args, kwargs)`:**  Facilitates the creation of Rust procedural macros (compile-time code generators). It essentially defines a special kind of shared library for proc macros.

**Relationship to Reverse Engineering:**

This module is **highly relevant** to reverse engineering using Frida. Here's how:

* **Interoperability with Native Code:** Reverse engineering often involves interacting with the target application's native code (written in C, C++, etc.). The `bindgen` function is crucial for this. It allows Frida's Rust components to seamlessly call functions, access data structures, and interact with the target process's internals written in native languages.

    **Example:** Imagine a target application has a core C++ library. With `rust.bindgen`, you can generate Rust bindings for the headers of this library. Then, your Frida scripts (partially written in Rust) can directly call functions within that C++ library, inspect its data, and even modify its behavior.

* **Testing Instrumentation Logic:** When developing Frida scripts to hook functions or modify behavior, testing is essential. The `test` function helps create isolated test environments for your Rust-based instrumentation logic. You can write unit tests in Rust that verify your hooks are working as expected before deploying them to a live target.

    **Example:** You write a Frida script in Rust to intercept a specific function in the target application. Using `rust.test`, you can create a small Rust test that loads your instrumentation library and calls a dummy function. This test can assert that your hook was indeed called and that the arguments were as expected.

* **Building Custom Tools:** Frida allows you to build custom tools and extensions. The `proc_macro` function enables you to create sophisticated compile-time code generation logic in Rust. This can be useful for generating boilerplate code for interacting with specific APIs or data structures discovered during reverse engineering.

    **Example:**  You might discover a complex data structure in the target application. You could write a procedural macro that, based on a description of this structure, automatically generates Rust code to parse and interact with it, making your Frida scripts more concise and less error-prone.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework:**

While this Python code itself doesn't directly manipulate bits or interact with the kernel, it's a crucial part of the infrastructure that *enables* those interactions in Frida:

* **`bindgen` and FFI:** The `bindgen` tool generates code that deals directly with the binary layout of data structures and function calling conventions at the ABI (Application Binary Interface) level. This is the fundamental interface between compiled code.
* **Linux/Android Context:** Frida often operates on Linux and Android. The generated Rust code (using `bindgen`) will interact with shared libraries, system calls, and potentially Android framework APIs. The `rust.py` module ensures that the build process correctly links against these native components.
* **Kernel Interactions (Indirect):** While not directly in this file, Frida's core functionality (enabled partly by this module) involves injecting code into running processes and intercepting function calls. This inevitably interacts with the operating system's kernel for process management, memory management, and system call interception.

**Logical Reasoning and Examples (Hypothetical):**

Let's consider the `bindgen` function:

**Hypothetical Input:**

* `input`: A C header file named `target_api.h` containing function declarations and struct definitions.
* `output`: The desired name for the generated Rust bindings file, e.g., `bindings.rs`.
* `include_directories`: A list of directories where the compiler can find included headers.

**Hypothetical Processing:**

The `bindgen` function will:

1. Locate the `bindgen` executable.
2. Construct a command-line invocation of `bindgen` that includes:
    * The path to `target_api.h`.
    * The output file path (`bindings.rs`).
    * `-I` flags for the provided `include_directories`.
    * Potentially other arguments for customizing the binding generation (like language: 'cpp').
3. Execute the `bindgen` command.
4. Meson will track the generated `bindings.rs` file as a build artifact.

**Hypothetical Output:**

A Rust source file named `bindings.rs` will be created in the build directory. This file will contain Rust structs and function declarations that mirror the contents of `target_api.h`, allowing Rust code to interact with the C/C++ API defined in that header.

**User or Programming Common Usage Errors:**

* **Incorrect `bindgen` Input Path:**  If the `input` path provided to `rust.bindgen` is incorrect or the header file doesn't exist, the `bindgen` command will fail, and the Meson build will also fail. This would manifest as an error during the build process.

    **Example:** The user provides `input: 'missing_header.h'` when the file doesn't exist. Meson will report an error that the file cannot be found when trying to run `bindgen`.

* **Missing Include Directories:** If the C/C++ header files have dependencies on other headers located in non-standard directories, and those directories are not specified in `include_directories`, `bindgen` will fail to find those dependent headers.

    **Example:** `target_api.h` includes `<some_lib/some_other_header.h>`, but the path to `some_lib` is not included in the `include_directories` argument. `bindgen` will report an error about not finding `some_lib/some_other_header.h`.

* **Forgetting `protocol: 'rust'` in `test`:** If you manually create a test executable that uses Rust and forget to specify `protocol: 'rust'` in the `test()` call in your `meson.build` file, Meson might not correctly interpret the test results.

    **Example:**

    ```meson
    rust_lib = static_library('my_rust_lib', 'src/lib.rs')
    test_exe = executable('my_rust_test', 'src/tests.rs', link_with: rust_lib)
    test('my_rust_test', test_exe) # Missing protocol: 'rust'
    ```

    While the test might run, Meson might not parse its output correctly to determine if it passed or failed.

**User Operation to Reach This Code (Debugging Clues):**

A user would interact with this code indirectly through their `meson.build` file. Here's a typical flow:

1. **Project Setup:** The user creates a new Frida project or is working on an existing one.
2. **Rust Integration:** The user decides to incorporate Rust code into their Frida components (e.g., for better performance or memory safety).
3. **`meson.build` Modification:** The user edits the `meson.build` file to:
    * **Import the Rust module:** `rust = import('unstable-rust')`
    * **Define Rust targets:** Use Meson's `static_library` or `executable` functions with the `language: 'rust'` option.
    * **Create Rust tests:** Call `rust.test('my_test', my_rust_target)` to create test targets.
    * **Generate FFI bindings:** Call `rust.bindgen(...)` to generate Rust bindings for C/C++ headers.
    * **Create procedural macros:** Call `rust.proc_macro(...)` to define a procedural macro target.
4. **Meson Configuration:** The user runs `meson setup builddir` to configure the build. During this phase, Meson parses the `meson.build` file. When it encounters calls to the `rust` module's functions (like `rust.test`, `rust.bindgen`), the corresponding Python code in `frida/subprojects/frida-python/releng/meson/mesonbuild/modules/rust.py` is executed.
5. **Build Process:** The user runs `meson compile -C builddir` (or `ninja -C builddir`). Meson then uses the generated build files to invoke the Rust compiler (`rustc`), the `bindgen` tool, and other necessary build tools. If there are errors in the `meson.build` file or during the build process, Meson will often report the location of the error within the `meson.build` file.

**Debugging Clues:**

* **Error Messages:** If the user encounters errors during `meson setup` or `meson compile`, the error messages will often point to the line in the `meson.build` file where the problematic `rust.*` function call is made, or to issues within the Rust code itself.
* **Meson Log Output:** Meson provides verbose output that can show the commands it's executing. Examining this output can reveal if `bindgen` is being called with the correct arguments, for example.
* **`build.ninja` or Makefiles:** Inspecting the generated native build files (like `build.ninja`) can show the exact commands that Meson has constructed based on the `rust.py` module's logic. This can be helpful for understanding how the Rust targets and `bindgen` invocations are being handled.

In essence, this `rust.py` file acts as a bridge, allowing users to leverage the power of Rust within the Frida ecosystem through the familiar interface of the Meson build system. It automates common tasks like setting up tests and generating FFI bindings, making it easier to build robust and performant Frida components using Rust.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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