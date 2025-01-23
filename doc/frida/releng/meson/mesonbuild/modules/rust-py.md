Response:
Let's break down the thought process for analyzing this Python code for the Frida dynamic instrumentation tool.

**1. Understanding the Goal:**

The core request is to analyze the `rust.py` file within the Frida project. The analysis should cover its functionality, relationship to reverse engineering, interaction with low-level concepts, logical reasoning, potential user errors, and how a user reaches this code.

**2. Initial Code Scan and High-Level Understanding:**

* **Imports:** The imports provide initial clues. `mesonbuild` strongly suggests this is part of the Meson build system integration for Rust. Keywords like `ExtensionModule`, `BuildTarget`, `Executable`, `SharedLibrary`, `CustomTarget`, `Dependency`, and `ExternalProgram` are key Meson concepts. The `rust` namespace hints at Rust-specific build functionalities.
* **Class Definition:** The `RustModule` class is the central element. It inherits from `ExtensionModule`, confirming its role as a Meson module.
* **Methods:** The `__init__`, `test`, `bindgen`, and `proc_macro` methods define the module's core functionalities.

**3. Detailed Analysis of Each Method:**

* **`test` Method:**
    * **Purpose:**  The docstring clearly explains this: simplifying the creation of Rust test executables. It addresses the DRY (Don't Repeat Yourself) principle in defining Rust tests.
    * **Reverse Engineering Relevance:** While not directly *performing* reverse engineering, it facilitates testing the *results* of reverse engineering efforts (e.g., testing bindings generated from reverse-engineered libraries).
    * **Low-Level Concepts:**  It deals with `BuildTarget`, `Executable`, linking (`link_with`, `dependencies`), which are fundamental to how software is built and how different parts interact at a lower level.
    * **Logic:**  It takes an existing Rust target, modifies its arguments (`--test`), and creates a new executable. The logic around handling existing `rust_args` and the `--test` flag is important.
    * **User Errors:** The warning about adding `--test` directly is a prime example of anticipating user mistakes. Linking with JAR files is also explicitly disallowed.
    * **How to Reach:** A user would call `rust.test()` in their `meson.build` file after importing the `unstable-rust` module and defining a Rust library target.

* **`bindgen` Method:**
    * **Purpose:**  The docstring indicates it's a wrapper around the `bindgen` tool, simplifying its use within Meson, especially with include directories.
    * **Reverse Engineering Relevance:** `bindgen` is a crucial tool for reverse engineering. It automatically generates Rust FFI (Foreign Function Interface) bindings from C/C++ headers. This is essential for interacting with native libraries.
    * **Low-Level Concepts:** This method heavily involves interaction with C/C++ headers, compiler arguments (`-I`, `-D`), and understanding the relationship between C/C++ and Rust at the ABI level. It uses `ExternalProgram` to execute `bindgen`.
    * **Logic:** It processes include directories, handles dependencies, determines the language (C or C++), constructs the command-line arguments for `bindgen`, and creates a `CustomTarget` to execute the command.
    * **User Errors:** Providing a non-header file as input, incorrect `bindgen` versions for certain features, and issues with C++ standard settings are potential errors.
    * **How to Reach:** A user would call `rust.bindgen()` in their `meson.build` to generate Rust bindings from a C/C++ header file.

* **`proc_macro` Method:**
    * **Purpose:** This method defines how to build Rust procedural macros within the Meson build system.
    * **Reverse Engineering Relevance:** Procedural macros, while more of a meta-programming feature of Rust, can be used in reverse engineering contexts. For instance, one might create a proc macro to automatically generate code based on binary structures or function signatures.
    * **Low-Level Concepts:** It deals with creating shared libraries (`SharedLibrary`) and specifies the `proc-macro` crate type, which is a specific Rust concept.
    * **Logic:** It sets specific flags and options to tell the Rust compiler to build a procedural macro.
    * **User Errors:** While the code itself doesn't show specific error handling here beyond Meson's general checks, incorrect dependencies or `rust_args` could cause issues.
    * **How to Reach:** A user would call `rust.proc_macro()` in their `meson.build` to define and build a Rust procedural macro library.

**4. Identifying Connections to Core Concepts:**

* **Reverse Engineering:** `bindgen` is the most direct link, enabling interaction with native code. The `test` method helps verify the correctness of such interactions.
* **Binary/Low Level:**  The module interacts with compilers, linkers, and build processes, all of which operate at a lower level. `bindgen` specifically deals with the binary interface between Rust and C/C++.
* **Linux/Android Kernel/Framework:** While the code itself doesn't directly interact with kernel specifics, the *output* of `bindgen` could be used to interact with Linux or Android kernel interfaces if the headers for those systems are used as input. Frida itself heavily interacts with these systems, so this module is a part of that ecosystem.
* **Logic and Assumptions:**  The `test` method assumes the input is a Rust target. The `bindgen` method makes assumptions about header file extensions.

**5. Simulating User Interaction (Debugging Clues):**

To understand how a user reaches this code, think about the steps involved in building a Frida project that uses Rust components:

1. **User Writes `meson.build`:** The user creates a `meson.build` file to define their build process.
2. **Importing the Module:** The user includes a line like `rust = import('unstable-rust')` (or a similar import statement) to access the functionalities of this module.
3. **Calling Module Functions:** The user calls methods like `rust.test()`, `rust.bindgen()`, or `rust.proc_macro()` within their `meson.build` file.
4. **Meson Processing:** When Meson processes the `meson.build` file, it encounters these calls and executes the corresponding Python code in `rust.py`.
5. **Error Scenarios:** If the user makes a mistake (as highlighted in the user error examples), the exceptions or warnings are generated from this Python code during the Meson configuration or build phase.

**6. Structuring the Output:**

Finally, organize the analysis into clear sections, providing explanations, examples, and connections to the initial request points. Use formatting (like bullet points and code blocks) to improve readability. Ensure the examples are concrete and illustrate the points being made. Pay attention to explicitly addressing each part of the prompt (functionality, reverse engineering, low-level concepts, logic, user errors, debugging).
This Python code defines a Meson module named `rust` for the Frida dynamic instrumentation tool. Its purpose is to provide helper functions for building and testing Rust code within the Frida project's build system. Let's break down its functionalities and connections to your specified areas.

**Functionalities:**

1. **`test(self, state: ModuleState, args: T.Tuple[str, BuildTarget], kwargs: FuncTest) -> ModuleReturnValue`**:
   - **Purpose:**  Simplifies the creation of Rust test executables. Rust unit tests are typically embedded within the source code. This function takes an existing Rust library or executable target and generates a new executable target specifically for running tests.
   - **Key Actions:**
     - Takes the name for the test and the existing Rust build target as input.
     - Verifies that the base target is indeed a Rust target.
     - Appends the necessary `--test` and formatting arguments to the Rust compiler/linker invocation.
     - Creates a new executable target with the same source files as the base target.
     - Registers this new executable as a test within the Meson test suite.

2. **`bindgen(self, state: ModuleState, args: T.List, kwargs: FuncBindgen) -> ModuleReturnValue`**:
   - **Purpose:**  Acts as a wrapper around the `bindgen` tool. `bindgen` is a popular tool in the Rust ecosystem for automatically generating Rust Foreign Function Interface (FFI) bindings from C and C++ header files.
   - **Key Actions:**
     - Takes C/C++ header files as input.
     - Configures `bindgen` with include directories, compiler arguments, and other settings.
     - Executes the `bindgen` command as a custom build step.
     - Generates Rust source code containing the FFI bindings.

3. **`proc_macro(self, state: ModuleState, args: T.Tuple[str, SourcesVarargsType], kwargs: _kwargs.SharedLibrary) -> SharedLibrary`**:
   - **Purpose:**  Facilitates the building of Rust procedural macros. Procedural macros are a powerful feature in Rust that allows you to write code that generates other code at compile time.
   - **Key Actions:**
     - Creates a shared library target specifically configured as a Rust procedural macro (`rust_crate_type = 'proc-macro'`).
     - Adds the necessary `--extern proc_macro` argument for linking.

**Relationship with Reverse Engineering:**

The `bindgen` functionality is directly related to reverse engineering.

* **Example:** Imagine you are reverse engineering a closed-source library written in C or C++. To interact with this library from Rust code (which is often desired in dynamic instrumentation scenarios like Frida), you need to create Rust bindings that define the functions, structures, and constants of the C/C++ library in a way that Rust understands. The `rust.bindgen` function automates this process.

   **Steps in a reverse engineering scenario using `rust.bindgen`:**
   1. **Obtain Header Files:** You would first need to obtain the header files (`.h` or `.hpp`) for the target C/C++ library. This might involve extracting them from the library itself, finding public SDKs, or even reconstructing them based on your analysis.
   2. **Create `meson.build` Entry:** In your Frida module's `meson.build` file, you would use `rust.bindgen` like this:
      ```meson
      rust = import('unstable-rust')

      ffi_bindings = rust.bindgen(
          input: 'path/to/target_library.h',
          output: 'src/ffi.rs',
          c_args: ['-I/path/to/include/dir'], # Include directories for the C headers
      )

      frida_module = shared_library(
          'my_frida_module',
          sources: ['src/lib.rs', ffi_bindings],
          # ... other settings
      )
      ```
   3. **`rust.bindgen` Generation:** Meson will execute the `bindgen` tool, using the provided header file as input and generating Rust code in `src/ffi.rs`. This generated code will contain Rust definitions that mirror the C/C++ structures and function signatures.
   4. **Using the Bindings in Rust:** Your Rust code (`src/lib.rs`) can now import and use the generated bindings to call functions and interact with the reverse-engineered C/C++ library.

**Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge:**

* **Binary 底层 (Binary Underpinnings):**
    * **`bindgen` interaction:** `bindgen` works at the level of parsing C/C++ header files, which describe the binary layout of data structures and function calling conventions. This directly relates to understanding how data is represented in memory and how functions are called at the binary level.
    * **FFI (Foreign Function Interface):** The entire concept of `bindgen` and its output relies on the FFI mechanism, which is the bridge between different programming languages at the binary level. It deals with issues like data type mapping, calling conventions (how arguments are passed and results are returned), and memory management across language boundaries.

* **Linux/Android Kernel & Framework:**
    * **Frida's Target:** Frida, by its nature, often targets processes running on Linux and Android, including system libraries, frameworks, and even the kernel itself.
    * **`bindgen` for System Libraries:** If you were reverse engineering or interacting with Linux or Android system libraries (e.g., `libc`, `libbinder` on Android), you might use `rust.bindgen` to generate bindings from their header files. This would allow your Frida module (written in Rust) to directly call functions within these system components.
    * **Kernel Interaction (Indirect):** While this specific Python code doesn't directly manipulate kernel structures, the Rust code generated by `bindgen` *could* be used to interact with the kernel if you are working with kernel headers. Frida itself has components that interact with the kernel for tracing and other instrumentation tasks.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `bindgen` function:

* **Hypothetical Input:**
   ```python
   rust.bindgen(
       input: 'path/to/my_structs.h',
       output: 'src/generated_bindings.rs',
       c_args: ['-I/opt/mylib/include'],
       dependencies: some_c_library_target  # Assuming you have a Meson target for a C library
   )
   ```
   Where `path/to/my_structs.h` contains:
   ```c
   typedef struct {
       int id;
       char name[32];
   } MyData;

   int process_data(MyData *data);
   ```
   And `some_c_library_target` represents a Meson target that compiles a C library whose headers are needed.

* **Likely Output (Conceptual - the actual output is Rust code):**
   The `bindgen` call would trigger the `bindgen` tool to parse `my_structs.h`. The `generated_bindings.rs` file would be created (or overwritten) and would contain Rust code defining:
   ```rust
   #[repr(C)]
   #[derive(Debug, Copy, Clone)]
   pub struct MyData {
       pub id: ::std::os::raw::c_int,
       pub name: [::std::os::raw::c_char; 32usize],
   }

   extern "C" {
       pub fn process_data(data: *mut MyData) -> ::std::os::raw::c_int;
   }
   ```
   This generated Rust code mirrors the C structure and function signature, allowing safe interaction from Rust.

**User or Programming Common Usage Errors:**

1. **Incorrect Path to Header File (`bindgen`):**
   ```meson
   rust.bindgen(input: 'wrong_path/missing.h', output: 'src/bindings.rs')
   ```
   **Error:** `bindgen` will likely fail with an error message indicating that the input file cannot be found. Meson's configuration step might also fail if it can't resolve the input file.

2. **Missing or Incorrect Include Directories (`bindgen`):**
   If the header file includes other headers that are not in the standard include paths, and the user doesn't provide the correct `c_args` with `-I` flags, `bindgen` will fail to parse the header file.
   ```meson
   rust.bindgen(input: 'needs_other_headers.h', output: 'src/bindings.rs') # Missing -I flags
   ```
   **Error:** `bindgen` will report errors about missing header files.

3. **Providing a Non-Rust Target to `rust.test`:**
   ```meson
   my_c_lib = static_library('my_c_lib', 'my_c_source.c')
   rust.test('test_my_c_lib', my_c_lib)
   ```
   **Error:** The `test` function explicitly checks if the second argument is a Rust-based target and will raise an `InterpreterException` if it's not.

4. **Trying to Link a Rust Test with a JAR File:**
   The `test` function explicitly forbids linking Rust tests with JAR targets.
   ```meson
   my_jar = jar('my_jar.jar')
   my_rust_lib = static_library('my_rust_lib', 'src/lib.rs')
   rust.test('test_rust_lib', my_rust_lib, link_with: my_jar)
   ```
   **Error:** The `test` function will raise an `InvalidArguments` exception.

5. **Adding `--test` or Formatting Arguments Manually to `rust.test`:**
   The `test` function explicitly warns against this, as it adds these arguments automatically.
   ```meson
   rust.test('my_test', my_rust_lib, rust_args: ['--test', '--format', 'compact'])
   ```
   **Warning:** Meson will issue warnings to the console.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user interacts with this code indirectly through their `meson.build` file. Here's how the execution flow leads to this module:

1. **User Writes `meson.build`:** The user creates or modifies a `meson.build` file within their Frida module project.
2. **Importing the Rust Module:** The `meson.build` file will contain a line like `rust = import('unstable-rust')`. When Meson parses this, it locates and loads the `rust.py` module.
3. **Calling `rust.test`, `rust.bindgen`, or `rust.proc_macro`:** The user then uses the imported `rust` object to call the functions defined in this module, for example:
   ```meson
   rust_lib = static_library('my_rust_lib', 'src/lib.rs')
   rust.test('test_my_rust_lib', rust_lib)
   ```
4. **Meson Configuration:** When the user runs `meson setup build`, Meson interprets the `meson.build` file. When it encounters the calls to `rust.test`, `rust.bindgen`, or `rust.proc_macro`, it executes the corresponding Python methods within `rust.py`.
5. **Function Execution:** The Python code in `rust.py` then performs its logic, interacting with the Meson build system to create new build targets, configure compiler arguments, and schedule the execution of external tools like `bindgen`.
6. **Error Reporting (if any):** If the user has made a mistake in their `meson.build` file (as described in the "User Errors" section), the Python code in this module will likely raise exceptions (like `InterpreterException`, `InvalidArguments`) or issue warnings, which Meson will then display to the user.

Therefore, when debugging issues related to building Rust code within a Frida module, looking at the error messages generated during the `meson setup` or `meson compile` steps and tracing back to how the `rust.test`, `rust.bindgen`, or `rust.proc_macro` functions were used in the `meson.build` file is crucial for understanding how the execution reached this specific Python code.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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