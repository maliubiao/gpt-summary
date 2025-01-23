Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding - What is this?**

The first line, `# SPDX-License-Identifier: Apache-2.0`, immediately tells us this is open-source software under the Apache 2.0 license. The `Copyright` line confirms this. The comment indicating the file path `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/rust.py` and mentioning "frida Dynamic instrumentation tool" gives context: this code is part of the Frida project, specifically related to building Rust components within the Meson build system.

**2. Core Functionality Identification - What does it *do*?**

Scanning through the code, especially the class `RustModule` and its methods (`test`, `bindgen`, `proc_macro`), reveals the core functionalities:

*   **`test`**:  This method is clearly about creating Rust test executables. The comments and code explain it simplifies defining tests by reusing the source of the library being tested.
*   **`bindgen`**:  This method wraps the `bindgen` tool, which is used to generate Rust FFI (Foreign Function Interface) bindings from C/C++ headers.
*   **`proc_macro`**: This method is about building Rust procedural macros.

**3. Relationship to Reverse Engineering - How does this relate to my domain?**

Frida is a dynamic instrumentation toolkit, heavily used in reverse engineering. Knowing this context makes the connections clearer:

*   **`test`**: While general, ensuring the correctness of Frida's Rust components is crucial for its reliability in reverse engineering tasks.
*   **`bindgen`**:  Reverse engineering often involves interacting with native libraries (written in C/C++). `bindgen` is a key tool for enabling Rust code to interface with these libraries within Frida. This is a *direct* link to reverse engineering workflows.
*   **`proc_macro`**:  Procedural macros in Rust can be used to automate code generation and manipulation, which can be helpful in creating custom Frida gadgets or extensions. This is a more *indirect* but still relevant connection.

**4. Low-Level Aspects - Where does it touch the system?**

Look for keywords and concepts related to the underlying system:

*   **Kernel/Framework (Android):**  The mention of "frida Dynamic instrumentation tool" itself strongly implies interaction with the target system's internals. While this specific Python file doesn't directly manipulate kernel code, it's part of the *build process* for components that *will* interact with the kernel or framework (especially on Android where Frida is heavily used).
*   **Binary Level:** `bindgen` deals with generating bindings to C/C++ code, which is often compiled to native machine code. The concept of FFI inherently involves understanding the binary interface between languages. `proc_macro` manipulates Rust code at a relatively low level before compilation.
*   **Linux:** While not explicitly Linux-specific in *this* file, Frida's roots are strongly tied to Linux. The build system (Meson) is cross-platform, but the underlying technologies often have Linux dependencies. The use of command-line tools like `bindgen` is common in Linux development.

**5. Logical Reasoning - What are the inputs and outputs?**

Analyze the function signatures and the operations performed:

*   **`test`**:
    *   *Input (Hypothetical):* A Rust static library target defined in a `meson.build` file.
    *   *Output:* A new executable target configured as a test runner for the library.
*   **`bindgen`**:
    *   *Input (Hypothetical):* A C header file path, include directories, and desired output file name.
    *   *Output:* A Rust source file containing FFI bindings.
*   **`proc_macro`**:
    *   *Input (Hypothetical):* The name of the procedural macro and its source files.
    *   *Output:* A shared library containing the procedural macro.

**6. Common Usage Errors - What mistakes can developers make?**

Consider the constraints and error handling within the code:

*   **`test`**:  Trying to link a Rust test with a Java `Jar` file. Forgetting to add the `--test` flag manually (the code handles this).
*   **`bindgen`**: Providing a non-header file as input, forgetting necessary include directories, incorrect `bindgen` version requirements, providing incorrect language hints.
*   **`proc_macro`**:  Likely errors related to Rust's macro system itself (incorrect macro syntax, dependency issues), though this Python code focuses on the build integration.

**7. User Journey - How does a user reach this code?**

Think about the typical Frida development workflow:

1. A developer wants to add a new feature to Frida or extend its functionality.
2. They decide to implement this feature in Rust for performance or safety reasons.
3. The Frida project uses Meson as its build system.
4. To integrate their Rust code, they'll use the `rust` module provided by Meson (this file).
5. They'll use functions like `rust.test`, `rust.bindgen`, or `rust.proc_macro` in their `meson.build` files.
6. When Meson processes the `meson.build` file, it will execute the corresponding Python code in `rust.py`.

**8. Iteration and Refinement:**

After the initial pass, review the code and your analysis. Are there any details missed? Are the explanations clear and concise? For example, the initial thought might be "this just builds Rust code," but realizing the specific purpose of `bindgen` and `proc_macro` within the *Frida context* adds significant depth to the analysis. Similarly, explicitly mentioning the role of Meson in the user journey is important.

This systematic approach, combining code analysis with domain knowledge, allows for a comprehensive understanding of the given code snippet.
这个Python源代码文件 `rust.py` 是 Frida 动态Instrumentation 工具的 Meson 构建系统中用于处理 Rust 代码的模块。它提供了一些辅助函数，用于简化在 Frida 项目中构建和测试 Rust 组件的过程。

以下是它的功能列表，并结合您提出的几个方面进行说明：

**功能列表：**

1. **`test(state, args, kwargs)`：创建 Rust 测试目标**
    *   **功能描述:**  这个函数用于从现有的 Rust 构建目标（如静态库或动态库）中生成一个 Rust 测试目标。它简化了 Rust 测试的定义，因为 Rust 的单元测试通常放在源代码文件中，不像其他语言那样放在单独的文件中。
    *   **与逆向方法的关联:**  在 Frida 这样的逆向工程工具中，测试至关重要。确保 Frida 的 Rust 组件（例如，用于与目标进程交互的模块）按预期工作，对于工具的可靠性至关重要。这个函数帮助开发者轻松地为这些 Rust 组件创建和管理测试。
    *   **二进制底层/Linux/Android 内核及框架知识:**  虽然这个函数本身不直接涉及这些底层知识，但它构建的测试目标 *会* 间接地涉及到。例如，如果被测试的 Rust 代码与 Android 框架进行交互（通过 Frida 提供的 API），那么这些测试就会涉及到与 Binder 通信、系统调用等底层操作相关的逻辑。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个名为 `my_rust_lib` 的静态库目标，已在 `meson.build` 文件中定义。
        *   **调用方式:** `rust.test('my_rust_lib_test', my_rust_lib)`
        *   **输出:**  一个新的可执行文件目标 `my_rust_lib_test`，它会编译 `my_rust_lib` 的源代码并运行其中的测试函数。
    *   **用户或编程常见的使用错误:**
        *   尝试将 Rust 测试目标与 Java 的 `Jar` 文件链接（会抛出 `InvalidArguments` 异常）。
        *   在 `rust_args` 中手动添加 `--test` 参数（会有警告提示）。

2. **`bindgen(state, args, kwargs)`：封装 bindgen 工具**
    *   **功能描述:**  这个函数是对 `bindgen` 工具的封装。`bindgen` 是一个用于从 C/C++ 头文件生成 Rust FFI (Foreign Function Interface) 绑定的工具。这个函数简化了 `bindgen` 的使用，特别是处理 `include_directories` 对象。
    *   **与逆向方法的关联:**  在逆向工程中，经常需要与 C/C++ 编写的本地库进行交互。Frida 本身也大量使用了 C/C++。`bindgen` 是一个关键工具，使得 Frida 的 Rust 组件能够安全有效地调用这些本地库的函数。例如，Frida 的某些 hook 功能可能需要与目标进程的 C/C++ 代码进行交互，`bindgen` 生成的绑定就允许 Rust 代码做到这一点。
    *   **二进制底层/Linux/Android 内核及框架知识:**  `bindgen` 的工作原理是解析 C/C++ 头文件，这涉及到对 C/C++ 语言规范以及 ABI (Application Binary Interface) 的理解。生成的 Rust 代码会直接与底层的二进制代码进行交互。当为 Android 框架的头文件生成绑定时，就会涉及到 Android 系统调用的结构、JNI (Java Native Interface) 的使用等知识。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个名为 `my_header.h` 的 C 头文件，位于 `include/` 目录下。
        *   **调用方式:**
            ```python
            my_bindings = rust.bindgen(
                input: 'include/my_header.h',
                output: 'src/bindings.rs',
                include_directories: include_directories('include')
            )
            ```
        *   **输出:**  一个名为 `bindings.rs` 的 Rust 源文件，其中包含了 `my_header.h` 中定义的结构体、函数等的 Rust FFI 绑定。
    *   **用户或编程常见的使用错误:**
        *   将非 C 头文件的文件作为 `input` 传递给 `bindgen`。
        *   忘记指定必要的 `include_directories`，导致 `bindgen` 无法找到头文件中引用的其他头文件。
        *   `bindgen_version` 参数指定的版本与实际安装的 `bindgen` 版本不兼容。

3. **`proc_macro(state, args, kwargs)`：创建 Rust 过程宏目标**
    *   **功能描述:**  这个函数用于构建 Rust 的过程宏 (procedural macro)。过程宏是一种在编译时执行代码以生成或修改其他 Rust 代码的特性。
    *   **与逆向方法的关联:**  过程宏可以用于简化与 Frida 交互的 Rust 代码的编写。例如，可以创建一个过程宏来自动生成与 Frida 的 C API 交互所需的样板代码，或者用于定义更高级别的、类型安全的 Frida hook 接口。
    *   **二进制底层/Linux/Android 内核及框架知识:**  过程宏虽然在编译时运行，但它们可以生成与底层系统交互的代码。如果过程宏生成的代码涉及到系统调用、内存操作等，那么就需要了解相关的底层知识。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个名为 `my_macro` 的过程宏，其源代码位于 `src/lib.rs`。
        *   **调用方式:** `my_proc_macro = rust.proc_macro('my_macro', 'src/lib.rs')`
        *   **输出:**  一个动态链接库 (`.so` 或 `.dylib`，取决于操作系统)，其中包含了编译后的 `my_macro` 过程宏。
    *   **用户或编程常见的使用错误:**
        *   在过程宏的实现中使用了不兼容的 Rust 特性或依赖项。
        *   过程宏的输出代码中存在语法错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者正在为 Frida 添加一个使用 Rust 编写的新功能：

1. **编写 Rust 代码:** 开发者编写了实现新功能的 Rust 代码，可能包含需要与 C/C++ 代码交互的部分，也可能包含需要进行单元测试的逻辑。
2. **编辑 `meson.build` 文件:** 为了将 Rust 代码集成到 Frida 的构建系统中，开发者需要编辑 Frida 项目的 `meson.build` 文件。
3. **使用 `rust.test` 定义测试:** 如果 Rust 代码包含单元测试，开发者会在 `meson.build` 中使用 `rust.test` 函数来定义测试目标，例如：
    ```python
    my_rust_lib = static_library('my_rust_lib', sources: 'src/lib.rs')
    rust.test('my_rust_lib_test', my_rust_lib)
    ```
    当 Meson 解析到这行代码时，就会调用 `rust.py` 文件中的 `test` 函数。
4. **使用 `rust.bindgen` 生成 FFI 绑定:** 如果 Rust 代码需要调用 C/C++ 代码，开发者会使用 `rust.bindgen` 函数来生成 FFI 绑定，例如：
    ```python
    my_bindings = rust.bindgen(
        input: 'include/my_native_lib.h',
        output: 'src/bindings.rs',
        include_directories: include_directories('include')
    )
    ```
    Meson 解析到这行代码时，会调用 `rust.py` 中的 `bindgen` 函数。
5. **使用 `rust.proc_macro` 构建过程宏:** 如果开发者编写了过程宏，他们会使用 `rust.proc_macro` 函数来构建它，例如：
    ```python
    my_proc_macro = rust.proc_macro('my_macro', 'src/lib.rs')
    ```
    Meson 解析到这行代码时，会调用 `rust.py` 中的 `proc_macro` 函数.
6. **运行 Meson:** 开发者在 Frida 项目的根目录下运行 `meson setup build` (如果尚未配置) 或 `ninja -C build` 来启动构建过程。
7. **Meson 执行 `rust.py` 中的代码:** 在构建过程中，当 Meson 遇到 `meson.build` 文件中对 `rust.test`, `rust.bindgen`, 或 `rust.proc_macro` 的调用时，它会加载并执行 `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/rust.py` 文件，并调用相应的函数。

**作为调试线索:**

*   如果构建过程中出现与 Rust 测试相关的错误，开发者可以检查 `meson.build` 文件中 `rust.test` 的参数是否正确，例如目标名称、依赖项等。
*   如果 `bindgen` 生成的绑定不正确，开发者可以检查 `rust.bindgen` 的 `input`、`output`、`include_directories` 等参数是否正确，以及 `bindgen` 工具本身是否安装正确。
*   如果构建过程无法找到 Rust 编译器或 `bindgen` 工具，可能是因为环境变量配置不正确，或者这些工具没有安装。Meson 的日志通常会提供有关这些错误的线索。
*   如果涉及到过程宏的构建问题，开发者需要检查过程宏的源代码是否存在编译错误，以及 `rust.proc_macro` 的参数是否正确。

总而言之，`rust.py` 文件是 Frida 构建系统中处理 Rust 代码的关键部分，它通过封装常用的 Rust 构建工具，简化了 Frida 中 Rust 组件的开发和集成过程。它与逆向工程紧密相关，因为 Frida 经常使用 Rust 来实现高性能和安全的组件，并且需要与 C/C++ 编写的目标进程进行交互。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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