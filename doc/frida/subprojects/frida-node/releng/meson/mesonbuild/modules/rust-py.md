Response:
My thought process to analyze the `rust.py` file went something like this:

1. **Understand the Purpose:** The initial lines and the class name "RustModule" immediately suggest this code is related to integrating Rust projects within the Meson build system. The path `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/rust.py` reinforces this – it's a Meson module specifically for Rust within the Frida project.

2. **Identify Core Functionalities (Methods):** I scanned the class definition and looked for methods. The key methods are `test`, `bindgen`, and `proc_macro`. These likely represent the main features this module provides.

3. **Analyze Each Method:**

   * **`test`:** The docstring clearly explains its purpose: simplifying the creation of Rust test executables. It addresses the "DRY" (Don't Repeat Yourself) principle by avoiding redundant target definitions. I noted the keywords it accepts and the error handling for linking with JARs (which makes sense as Rust tests are native executables).

   * **`bindgen`:** The docstring states it's a "wrapper around bindgen."  Bindgen is a common tool for generating FFI (Foreign Function Interface) bindings between Rust and C/C++. The keywords point to common `bindgen` configurations like include directories, input/output files, and language.

   * **`proc_macro`:** The name suggests it's for building Rust procedural macros. The limited allowed keyword arguments are characteristic of how proc macros are built within the Rust ecosystem.

4. **Look for Interactions with the Build System:** I paid attention to how these methods interact with Meson's build system. Key indicators were:
   * `BuildTarget`, `Executable`, `CustomTarget`, `SharedLibrary`: These are all Meson's representation of build artifacts.
   * `state: ModuleState`: This object provides access to the current build state, including environment information, options, and the ability to find programs.
   * `self.interpreter.make_test()`: This clearly indicates the `test` method is creating a Meson test object.
   * `CustomTarget`: The `bindgen` method creates a `CustomTarget`, which is a way to execute arbitrary commands within the build process.

5. **Consider the Context of Frida:**  Knowing that this is part of Frida, a dynamic instrumentation toolkit, I started to think about how these Rust features fit into Frida's overall architecture. Frida often needs to interact with native code (hence the `bindgen` functionality). The `proc_macro` functionality might be used for extending Frida's functionality or for code generation related to instrumentation.

6. **Address the Specific Questions:**  With a good understanding of the code, I addressed each of the user's questions:

   * **Functionality:**  I summarized the core functionalities of each method based on my analysis.

   * **Relationship to Reversing:**  I connected `bindgen` to reverse engineering scenarios where one needs to interact with C/C++ libraries from Rust, which is a common task in dynamic analysis and instrumentation.

   * **Binary, Linux, Android:** I linked `bindgen` to the need for FFI when interacting with OS-level APIs and Android's native layer. I also connected the `proc_macro` to potential low-level code generation or manipulation.

   * **Logical Reasoning (Hypothetical Input/Output):** I created simple examples for each method to illustrate the input parameters and the type of output (Meson build targets).

   * **Common Usage Errors:**  I highlighted potential errors based on the code's constraints, like incorrect argument types, missing required arguments, or using inappropriate keywords.

   * **User Journey (Debugging Clue):** I outlined a likely path a user would take to end up modifying this file, emphasizing the iterative process of developing and debugging Rust integration within Frida using Meson.

7. **Refine and Organize:** I organized my findings logically, using headings and bullet points to make the information clear and easy to understand. I made sure to use precise language and connect the code functionalities to the user's questions.

Essentially, I employed a combination of code reading, understanding the domain (build systems, FFI, dynamic instrumentation), and reasoning about the intended use of the module within the larger Frida project. I also paid close attention to the specific details requested in the prompt.
This Python code defines a Meson module named `rust` that provides helper functions for integrating Rust code into a Meson build system. Specifically, it's designed to work with the Frida dynamic instrumentation toolkit. Let's break down its functionality, connections to reverse engineering, low-level details, logic, potential errors, and debugging clues.

**Functionalities:**

1. **`test(self, state: ModuleState, args: T.Tuple[str, BuildTarget], kwargs: FuncTest) -> ModuleReturnValue`:**
   - **Purpose:** Simplifies the creation of Rust test executables. Rust typically includes unit tests within the source files. This function takes an existing Rust library or executable target and creates a new executable specifically for running tests.
   - **Functionality:** It avoids redundant definitions by reusing the source files of the base target. It adds the `--test` flag to the Rust compiler arguments and configures the test runner protocol as `rust`. It also handles dependencies and linking requirements.

2. **`bindgen(self, state: ModuleState, args: T.List, kwargs: FuncBindgen) -> ModuleReturnValue`:**
   - **Purpose:** Wraps the `bindgen` tool, which generates Rust FFI (Foreign Function Interface) bindings to C/C++ code. This allows Rust code to interact with existing C/C++ libraries.
   - **Functionality:** It takes C/C++ header files as input and outputs Rust code that defines the necessary structs, functions, and constants to interact with the C/C++ code. It handles include directories, compiler arguments, and dependencies. It also supports generating inline wrappers for static functions (with certain `bindgen` versions).

3. **`proc_macro(self, state: ModuleState, args: T.Tuple[str, SourcesVarargsType], kwargs: _kwargs.SharedLibrary) -> SharedLibrary`:**
   - **Purpose:** Facilitates the creation of Rust procedural macros. Procedural macros are functions that operate on the Rust syntax tree at compile time, allowing for code generation and manipulation.
   - **Functionality:** It builds a shared library with the `proc-macro` crate type and adds the necessary `--extern proc_macro` argument.

**Relationship to Reverse Engineering:**

This module is highly relevant to reverse engineering, particularly within the context of Frida:

* **`bindgen`:**  A cornerstone of interacting with native code. In reverse engineering, you often need to interface with:
    * **Operating System APIs (Linux, Android):** Frida needs to call system functions to perform instrumentation. `bindgen` can generate Rust bindings for these APIs.
    * **Libraries within the target process:** When instrumenting an application, you might need to interact with its internal libraries. `bindgen` allows you to create Rust interfaces to these libraries' headers.
    * **Kernel interfaces:**  For lower-level instrumentation, Frida might need to interact with kernel structures and functions. `bindgen` can generate the necessary bindings.
    * **Example:** Imagine you want to hook a function called `my_native_function` in a target Android app's native library (`libtarget.so`). You would:
        1. Find the header file declaring `my_native_function`.
        2. Use the `rust.bindgen` function in your Meson build script, providing the header file as input.
        3. This generates Rust code that you can then use in your Frida gadget or agent to call and intercept `my_native_function`.

* **`test`:**  Writing tests for your Frida gadgets or agents is crucial for ensuring they work correctly. The `rust.test` function simplifies this process. You can write unit tests that exercise the Rust code responsible for instrumentation logic.

* **`proc_macro`:** While potentially less directly used in basic hooking scenarios, procedural macros can be powerful for:
    * **Generating boilerplate code:** For instance, automatically generating the necessary FFI wrappers or struct definitions based on some metadata.
    * **Creating domain-specific languages (DSLs):**  You could potentially create a DSL for defining instrumentation rules.

**Binary/Low-Level, Linux, Android Kernel/Framework Knowledge:**

* **`bindgen` inherently deals with binary layouts:** It parses C/C++ headers, which define the structure and memory layout of data and functions in compiled code. This is fundamental to interacting with binaries.
* **Linux/Android Kernel/Framework:**
    * **System Calls:** Frida often needs to intercept or make system calls on Linux and Android. `bindgen` is used to create Rust interfaces to the kernel's system call interface (via header files).
    * **Android Framework:**  When instrumenting Android applications, you might need to interact with the Android runtime environment (ART) or other framework components. `bindgen` would be used to create bindings to the relevant C/C++ headers of these components.
    * **Driver Interaction:** In some cases, Frida might interact with kernel drivers. `bindgen` would be essential for creating Rust interfaces to driver APIs.

**Logical Reasoning (Hypothetical Input/Output):**

**`test` example:**

* **Input (in `meson.build`):**
  ```meson
  rust_lib = static_library('mylib', 'src/lib.rs')
  rust = import('unstable-rust')
  rust.test('mylib_test', rust_lib)
  ```
* **Assumed:** `src/lib.rs` contains Rust code with unit tests marked with `#[cfg(test)]` and `#[test]`.
* **Output (Meson will generate):** A new executable target named `mylib_test` that, when built and run, will execute the unit tests within `src/lib.rs`.

**`bindgen` example:**

* **Input (in `meson.build`):**
  ```meson
  rust = import('unstable-rust')
  native_header = files('native.h')
  bindings = rust.bindgen(
      input: native_header,
      output: 'src/native_bindings.rs'
  )
  ```
* **Assumed:** `native.h` contains C function declarations and struct definitions.
* **Output (will generate a file):** A Rust file named `src/native_bindings.rs` containing Rust code (structs, `extern "C"` function declarations, etc.) that mirrors the definitions in `native.h`.

**`proc_macro` example:**

* **Input (in `meson.build`):**
  ```meson
  rust = import('unstable-rust')
  my_macro = rust.proc_macro('my_macro', 'src/lib.rs')
  ```
* **Assumed:** `src/lib.rs` is a Rust crate defining a procedural macro.
* **Output (Meson will generate):** A shared library (`libmy_macro.so` or similar) that can be used as a procedural macro in other Rust crates within the project.

**Common Usage Errors:**

* **`rust.test`:**
    * Providing a non-Rust target as the second argument.
    * Trying to link a Rust test with a JAR file (Rust tests are native executables).
    * Manually adding `--test` or `--format` to `rust_args` (the function adds these automatically).
* **`bindgen`:**
    * Providing a build target or object file as input instead of a C/C++ header file.
    * Forgetting to specify the `output` file.
    * Incorrectly configuring include directories.
    * Version mismatch with `bindgen` when using features like `output_inline_wrapper`.
* **`proc_macro`:**
    * Providing incorrect source files for the procedural macro.
    * Not specifying the `rust_crate_type` (although this module sets it).

**User Operation Leading to This File (Debugging Clue):**

A developer working on Frida's Rust components might need to modify this file in the following scenarios:

1. **Adding new features to the Rust module:** If they want to provide more helper functions for Rust integration (e.g., a function to simplify building Rust FFI libraries).
2. **Fixing bugs or improving existing functionality:**  If there are issues with how `rust.test`, `rust.bindgen`, or `rust.proc_macro` work, they would need to debug and modify this code.
3. **Adapting to changes in Meson or Rust:**  As Meson or the Rust toolchain evolves, this module might need updates to maintain compatibility.
4. **Implementing specific requirements for Frida's build process:** Frida might have unique needs for building its Rust components that necessitate changes in this module.

**Steps a developer might take (leading to examining `rust.py`):**

1. **Encountering a build error related to Rust:**  For example, a `bindgen` command failing or a Rust test not being created correctly.
2. **Tracing the error back to the Meson build system:** Realizing that the `rust` module is responsible for the problematic functionality.
3. **Locating the source code of the `rust` module:** Finding `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/rust.py`.
4. **Examining the code:** Reading the function definitions, understanding how they interact with Meson's APIs and external tools like `bindgen`.
5. **Potentially modifying the code:**  Making changes to fix the bug, add a feature, or adapt to new requirements.
6. **Testing the changes:** Running the Meson build to verify the modifications.

In essence, this `rust.py` file acts as a bridge between the Meson build system and the Rust toolchain, providing convenient abstractions for building and testing Rust code within the larger Frida project. Its functionalities are deeply intertwined with the needs of dynamic instrumentation and reverse engineering, particularly the ability to interact with native code.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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