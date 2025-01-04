Response:
The user wants to understand the functionality of the provided Python code, which is part of the Frida dynamic instrumentation tool and specifically relates to the Rust compiler integration within the Meson build system. I need to break down the code's features, focusing on aspects relevant to reverse engineering, binary analysis, and low-level system interactions.

Here's a plan:

1. **Identify Core Functionality:**  Analyze the class `RustCompiler` and its methods to determine its primary purpose. It seems to be about configuring and invoking the Rust compiler (`rustc`) within the Meson build process.
2. **Reverse Engineering Relevance:** Look for features that aid in or are used during reverse engineering. This might involve compilation flags for debugging, controlling output, or linking specific libraries.
3. **Binary and System Interaction:**  Pinpoint parts of the code that deal with binary output, linking, and system-level concerns (Linux, Android, kernel, frameworks).
4. **Logical Reasoning:** Examine methods where input leads to predictable output, such as argument generation based on optimization levels.
5. **User Errors:** Identify common mistakes a user might make when using these functionalities.
6. **User Path:** Trace how a user's actions in a build system configuration could lead to this code being executed.
好的，让我们来分析一下 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/rust.py` 这个文件。这是一个 Frida 项目中，用于集成 Rust 编译器的 Meson 构建系统的代码。

**功能列举：**

1. **定义 Rust 编译器类 (`RustCompiler`)**: 这个类继承自 Meson 的 `Compiler` 基类，专门用于处理 Rust 代码的编译。
2. **编译器识别信息**:  定义了 Rust 编译器的语言 (`rust`) 和 ID (`rustc`)。
3. **默认编译/链接参数**:  设置了不同优化级别 (`rust_optimization_args`) 和警告级别 (`_WARNING_LEVELS`) 对应的 `rustc` 命令行参数。
4. **MSVCRT 支持**:  针对 Windows 平台，处理不同版本的 MSVCRT 运行时库的链接参数 (`MSVCRT_ARGS`)。
5. **初始化**:  在 `__init__` 方法中，初始化了编译器实例，包括可执行文件路径、版本信息、目标机器类型等。它还处理了与链接器相关的选项 (`b_vscrt`)。
6. **静态链接器需求**:  `needs_static_linker` 方法返回 `False`，表明 Rust 编译器自身不需要静态链接器（因为它会调用底层的 C 链接器）。
7. **健全性检查 (`sanity_check`)**:  用于验证 Rust 编译器是否可以正常工作，通过编译一个简单的 Rust 程序并运行来确认。
8. **获取原生静态库 (`_native_static_libs`)**:  用于获取链接 Rust 静态库所需的原生库。它执行 `rustc` 命令并解析输出，排除一些常见的 C/C++ 库。
9. **依赖关系生成参数 (`get_dependency_gen_args`)**:  返回生成依赖关系信息的 `rustc` 参数 (`--dep-info`)。
10. **获取 sysroot (`get_sysroot`)**:  调用 `rustc` 获取系统根目录。
11. **获取 CRT 静态链接状态 (`get_crt_static`)**:  调用 `rustc` 并解析输出来判断是否使用了静态链接的 C 运行时库。
12. **获取调试参数 (`get_debug_args`)**:  根据是否开启调试模式返回 `['-C', 'debug=1']` 或 `['-C', 'debug=0']`。
13. **获取优化参数 (`get_optimization_args`)**:  根据优化级别返回预定义的 `rustc` 优化参数。
14. **处理绝对路径 (`compute_parameters_with_absolute_paths`)**:  将 `-L` 开头的库路径参数转换为绝对路径。
15. **获取输出参数 (`get_output_args`)**:  返回指定输出文件名的 `rustc` 参数 (`-o`)。
16. **指定链接器 (`use_linker_args`)**:  返回指定链接器的 `rustc` 参数 (`-C linker=`)。
17. **获取编译器选项 (`get_options`)**:  定义了 Rust 特有的编译选项，如 Rust edition (`std`)。
18. **获取依赖项编译参数 (`get_dependency_compile_args`)**:  Rust 没有特定的依赖项编译参数，因此返回空列表。
19. **获取选项编译参数 (`get_option_compile_args`)**:  根据用户设置的选项生成 `rustc` 的编译参数，例如指定 Rust edition。
20. **获取 CRT 编译参数 (`get_crt_compile_args`)**:  Rust 编译器自身处理 CRT，所以返回空列表。
21. **获取 CRT 链接参数 (`get_crt_link_args`)**:  针对 MSVC 链接器 (`link`, `lld-link`)，根据 CRT 的设置返回相应的链接参数。
22. **获取颜色输出参数 (`get_colorout_args`)**:  返回控制颜色输出的 `rustc` 参数 (`--color=`)。
23. **获取始终传递的链接器参数 (`get_linker_always_args`)**:  将父类的链接器参数转换为 `rustc` 的 `-C link-arg=` 格式。
24. **获取将警告视为错误的参数 (`get_werror_args`)**:  返回 `-D warnings`，将所有未显式允许的警告视为错误。
25. **获取警告级别参数 (`get_warn_args`)**:  根据警告级别返回相应的 `rustc` 参数。
26. **获取 PIC 参数 (`get_pic_args`)**:  Rust 默认启用 PIC，所以返回空列表。
27. **获取 PIE 参数 (`get_pie_args`)**:  PIE 的启用与 PIC 相关，Rust 编译器目前没有直接控制 PIE 的选项，所以返回空列表。
28. **获取断言参数 (`get_assert_args`)**:  控制是否启用 debug 断言和溢出检查。
29. **定义 Clippy Rust 编译器类 (`ClippyRustCompiler`)**:  继承自 `RustCompiler`，用于支持使用 Clippy 代码检查工具，只是 ID 不同。

**与逆向方法的联系及举例说明：**

*   **调试信息**: `get_debug_args` 方法生成了 `['-C', 'debug=1']` 参数，这会在编译出的二进制文件中包含调试符号信息。逆向工程师可以使用这些符号信息来更容易地理解代码的结构和执行流程，例如在 GDB 或 LLDB 中设置断点、查看变量值等。
    *   **举例**:  如果逆向工程师想分析某个 Rust 函数的具体实现，但该函数没有符号信息，那么他们需要进行更多的静态分析和反汇编。但如果编译时使用了调试信息，逆向工程师可以直接在调试器中查看源代码，单步执行，极大地提高分析效率。
*   **优化级别**: `get_optimization_args` 方法允许设置不同的优化级别，例如 `-C opt-level=0` (无优化) 或 `-C opt-level=3` (最高优化)。低优化级别的代码更接近源代码，更容易阅读和理解，适合逆向分析。高优化级别的代码可能经过了指令重排、内联等优化，使得逆向分析更加困难。
    *   **举例**:  逆向一个被高度优化的二进制文件时，可能会发现代码执行流程被打乱，一些简单的操作被合并成复杂的指令，变量被优化掉等等，这会增加理解代码逻辑的难度。相比之下，未优化的代码会保留更多的原始结构。
*   **链接参数**: `get_linker_always_args` 和 `get_crt_link_args` 允许指定链接器参数和 C 运行时库。逆向工程师可能需要关注链接了哪些库，特别是当分析涉及到与外部库的交互时。例如，如果程序链接了某个加密库，逆向工程师可能需要进一步分析该库的实现。
    *   **举例**:  通过分析链接参数，逆向工程师可以确定目标程序是否使用了动态链接。如果是，他们可能需要加载相关的动态链接库，并分析程序与这些库之间的接口和调用关系。
*   **静态链接与动态链接**:  `get_crt_static` 方法可以判断 CRT 是否是静态链接的。这对于逆向分析程序如何处理运行时环境非常重要。静态链接会将所有依赖库的代码都包含在最终的可执行文件中，而动态链接则依赖于系统中已安装的库。
    *   **举例**:  如果一个程序静态链接了 CRT，那么逆向工程师只需要分析一个单独的可执行文件。如果使用了动态链接，则还需要关注目标系统上是否存在所需的动态链接库，以及程序如何加载和使用这些库。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

*   **二进制输出**: `get_output_args` 指定了编译输出的二进制文件名。逆向的最终目标就是分析这些二进制文件。
*   **系统调用 (隐含)**: 尽管代码本身没有直接涉及系统调用，但 Rust 编译器生成的代码最终会进行系统调用来执行各种操作。Frida 的动态插桩技术正是通过拦截和修改系统调用来实现其功能的。
*   **链接器**: 代码中多次提到了链接器，包括 `use_linker_args` 和 `get_linker_always_args`。链接器负责将编译后的目标文件和库文件组合成最终的可执行文件或库文件。链接过程涉及到符号解析、地址重定位等底层操作。
    *   **举例 (Linux)**:  在 Linux 上，默认的链接器通常是 `ld`。`use_linker_args` 方法可以用来指定其他的链接器，例如 `lld`。
    *   **举例 (Windows)**: 在 Windows 上，常见的链接器是 `link.exe` 或 `lld-link.exe`。`get_crt_link_args` 方法会根据不同的 CRT 版本选择合适的库进行链接。
*   **PIC/PIE**: `get_pic_args` 和 `get_pie_args` 涉及到位置无关代码 (PIC) 和位置无关可执行文件 (PIE)。这在现代操作系统中是重要的安全特性，可以防止某些类型的攻击，例如地址空间布局随机化 (ASLR) 的绕过。
    *   **举例 (Linux/Android)**:  在 Linux 和 Android 系统中，为了提高安全性，通常会要求生成 PIC 和 PIE 的代码。Frida 自身也需要处理这些安全特性，以便在目标进程中注入和执行代码。
*   **CRT (C 运行时库)**: `get_crt_link_args` 涉及到 C 运行时库的链接。Rust 编译出的代码通常会依赖底层的 C 运行时库，例如 `glibc` (Linux) 或 MSVCRT (Windows)。
    *   **举例 (Android)**:  在 Android 系统中，不同的 Android 版本可能使用不同的 Bionic C 库版本。Frida 需要考虑这些差异，以确保其在不同 Android 版本上的兼容性。

**逻辑推理及假设输入与输出：**

*   **假设输入 (优化级别)**: 用户在 Meson 构建配置中设置了优化级别为 `'2'`。
*   **输出 (`get_optimization_args`)**: `get_optimization_args('2')` 方法会返回 `[' -C', 'opt-level=2']`。
*   **假设输入 (调试模式)**: 用户启用了调试模式。
*   **输出 (`get_debug_args`)**: `get_debug_args(True)` 方法会返回 `['-C', 'debug=1']`。
*   **假设输入 (Windows, CRT 为 MDd)**: 目标平台是 Windows，用户选择了动态链接调试版本的 MSVCRT。
*   **输出 (`get_crt_link_args`)**: `get_crt_link_args('md', 'debug')` 方法会返回 `['-l', 'dylib=msvcrtd']`。
*   **假设输入 (指定链接器)**: 用户希望使用 `lld` 作为链接器。
*   **输出 (`use_linker_args`)**: `RustCompiler.use_linker_args('lld', 'some_version')` 会返回 `['-C', 'linker=lld']`。

**用户或编程常见的使用错误及举例说明：**

*   **错误的优化级别**: 用户可能会输入一个无效的优化级别，例如 `'4'`。由于 `rust_optimization_args` 中没有 `'4'` 这个键，这会导致 `get_optimization_args` 方法抛出 `KeyError`。
*   **错误的颜色类型**: 用户可能会在配置中输入一个不支持的颜色类型，例如 `'purple'`。这会导致 `get_colorout_args` 方法抛出 `MesonException`。
    *   **举例**:  用户在 `meson_options.txt` 中设置了 `rust_colorout = 'purple'`，Meson 在处理这个选项时会调用 `get_colorout_args('purple')`，从而报错。
*   **Rust edition 不存在**: 用户可能会指定一个不存在的 Rust edition。虽然 `get_options` 中列出了一些常见的 edition，但如果用户尝试使用一个更新但 Meson 不知道的 edition，可能会导致编译错误。
    *   **举例**:  如果 Rust 发布了新的 edition，例如 `'2024'`，但 `get_options` 中没有更新，用户设置 `std = '2024'` 可能会导致 `rustc` 报错。
*   **依赖项问题**:  如果 Rust 代码依赖了外部的 C 库，但没有正确配置链接参数，会导致链接失败。虽然这个文件本身不直接处理依赖项链接，但理解其如何生成链接参数对于解决此类问题很重要。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置 Meson 构建**: 用户在一个 Frida 的子项目 (例如 `frida-gum`) 的根目录下执行 `meson setup build` 命令来配置构建。
2. **Meson 解析构建定义**: Meson 会读取 `meson.build` 文件，该文件定义了如何构建项目，包括哪些源代码需要编译，使用的编译器等。
3. **识别 Rust 代码**: Meson 在 `meson.build` 文件中遇到需要编译的 Rust 代码时，会根据语言类型选择相应的编译器处理类，即 `RustCompiler`。
4. **创建 RustCompiler 实例**: Meson 会实例化 `RustCompiler` 类，这会调用 `__init__` 方法，需要找到 Rust 编译器的可执行文件路径。
5. **获取编译/链接参数**:  当 Meson 需要编译 Rust 代码时，会调用 `RustCompiler` 类的方法来获取相应的编译和链接参数，例如 `get_optimization_args`、`get_debug_args`、`get_output_args` 等。这些参数会根据用户的构建配置和 Meson 的内部逻辑生成。
6. **执行 Rust 编译器**: Meson 使用生成的参数调用 `rustc` 命令来编译 Rust 源代码。
7. **处理链接**: 当需要链接生成最终的可执行文件或库时，Meson 会调用与链接相关的 `RustCompiler` 方法，例如 `get_linker_always_args` 和 `get_crt_link_args`，以获取链接所需的参数。

**调试线索**: 如果在构建过程中遇到与 Rust 编译相关的问题，例如编译错误或链接错误，开发者可以：

*   **检查 Meson 的配置**: 查看 `meson_options.txt` 或 `meson setup` 命令的输出，确认编译选项（如优化级别、调试模式、Rust edition）是否正确设置。
*   **查看 Meson 的日志**: Meson 会生成详细的构建日志，其中包含了执行的 `rustc` 命令及其参数。通过分析这些命令，可以了解 Meson 是如何调用 Rust 编译器的，以及传递了哪些参数。
*   **断点调试 Meson 代码**:  如果需要深入了解 Meson 的行为，可以使用 Python 调试器（如 `pdb`）在 `rust.py` 文件中设置断点，逐步执行代码，查看变量的值，理解参数是如何生成的。例如，可以在 `get_optimization_args` 方法中设置断点，查看当用户设置了某个优化级别时，该方法返回了哪些参数。
*   **对比不同版本的 Meson 或 Rust**: 如果在升级 Meson 或 Rust 版本后出现问题，可以尝试回滚到之前的版本，以确定问题是否与版本更新有关。

总而言之，`rust.py` 文件是 Frida 项目中 Meson 构建系统与 Rust 编译器交互的核心桥梁，它封装了调用 `rustc` 的细节，并根据用户的配置和目标平台生成合适的编译和链接参数。理解这个文件的功能对于调试 Frida 的构建过程以及进行与 Rust 代码相关的逆向工程都非常有帮助。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2022 The Meson development team

from __future__ import annotations

import functools
import subprocess, os.path
import textwrap
import re
import typing as T

from .. import coredata
from ..mesonlib import EnvironmentException, MesonException, Popen_safe_logged, OptionKey
from .compilers import Compiler, clike_debug_args

if T.TYPE_CHECKING:
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..envconfig import MachineInfo
    from ..environment import Environment  # noqa: F401
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    from ..dependencies import Dependency


rust_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': [],
    'g': ['-C', 'opt-level=0'],
    '1': ['-C', 'opt-level=1'],
    '2': ['-C', 'opt-level=2'],
    '3': ['-C', 'opt-level=3'],
    's': ['-C', 'opt-level=s'],
}

class RustCompiler(Compiler):

    # rustc doesn't invoke the compiler itself, it doesn't need a LINKER_PREFIX
    language = 'rust'
    id = 'rustc'

    _WARNING_LEVELS: T.Dict[str, T.List[str]] = {
        '0': ['-A', 'warnings'],
        '1': [],
        '2': [],
        '3': ['-W', 'warnings'],
    }

    # Those are static libraries, but we use dylib= here as workaround to avoid
    # rust --tests to use /WHOLEARCHIVE.
    # https://github.com/rust-lang/rust/issues/116910
    MSVCRT_ARGS: T.Mapping[str, T.List[str]] = {
        'none': [],
        'md': [], # this is the default, no need to inject anything
        'mdd': ['-l', 'dylib=msvcrtd'],
        'mt': ['-l', 'dylib=libcmt'],
        'mtd': ['-l', 'dylib=libcmtd'],
    }

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 full_version: T.Optional[str] = None,
                 linker: T.Optional['DynamicLinker'] = None):
        super().__init__([], exelist, version, for_machine, info,
                         is_cross=is_cross, full_version=full_version,
                         linker=linker)
        self.base_options.update({OptionKey(o) for o in ['b_colorout', 'b_ndebug']})
        if 'link' in self.linker.id:
            self.base_options.add(OptionKey('b_vscrt'))
        self.native_static_libs: T.List[str] = []

    def needs_static_linker(self) -> bool:
        return False

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        source_name = os.path.join(work_dir, 'sanity.rs')
        output_name = os.path.join(work_dir, 'rusttest')
        with open(source_name, 'w', encoding='utf-8') as ofile:
            ofile.write(textwrap.dedent(
                '''fn main() {
                }
                '''))

        cmdlist = self.exelist + ['-o', output_name, source_name]
        pc, stdo, stde = Popen_safe_logged(cmdlist, cwd=work_dir)
        if pc.returncode != 0:
            raise EnvironmentException(f'Rust compiler {self.name_string()} cannot compile programs.')
        self._native_static_libs(work_dir, source_name)
        if environment.need_exe_wrapper(self.for_machine):
            if not environment.has_exe_wrapper():
                # Can't check if the binaries run so we have to assume they do
                return
            cmdlist = environment.exe_wrapper.get_command() + [output_name]
        else:
            cmdlist = [output_name]
        pe = subprocess.Popen(cmdlist, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pe.wait()
        if pe.returncode != 0:
            raise EnvironmentException(f'Executables created by Rust compiler {self.name_string()} are not runnable.')

    def _native_static_libs(self, work_dir: str, source_name: str) -> None:
        # Get libraries needed to link with a Rust staticlib
        cmdlist = self.exelist + ['--crate-type', 'staticlib', '--print', 'native-static-libs', source_name]
        p, stdo, stde = Popen_safe_logged(cmdlist, cwd=work_dir)
        if p.returncode != 0:
            raise EnvironmentException('Rust compiler cannot compile staticlib.')
        match = re.search('native-static-libs: (.*)$', stde, re.MULTILINE)
        if not match:
            raise EnvironmentException('Failed to find native-static-libs in Rust compiler output.')
        # Exclude some well known libraries that we don't need because they
        # are always part of C/C++ linkers. Rustc probably should not print
        # them, pkg-config for example never specify them.
        # FIXME: https://github.com/rust-lang/rust/issues/55120
        exclude = {'-lc', '-lgcc_s', '-lkernel32', '-ladvapi32'}
        self.native_static_libs = [i for i in match.group(1).split() if i not in exclude]

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['--dep-info', outfile]

    def get_sysroot(self) -> str:
        cmd = self.get_exelist(ccache=False) + ['--print', 'sysroot']
        p, stdo, stde = Popen_safe_logged(cmd)
        return stdo.split('\n', maxsplit=1)[0]

    @functools.lru_cache(maxsize=None)
    def get_crt_static(self) -> bool:
        cmd = self.get_exelist(ccache=False) + ['--print', 'cfg']
        p, stdo, stde = Popen_safe_logged(cmd)
        return bool(re.search('^target_feature="crt-static"$', stdo, re.MULTILINE))

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        return clike_debug_args[is_debug]

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return rust_optimization_args[optimization_level]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-L':
                for j in ['dependency', 'crate', 'native', 'framework', 'all']:
                    combined_len = len(j) + 3
                    if i[:combined_len] == f'-L{j}=':
                        parameter_list[idx] = i[:combined_len] + os.path.normpath(os.path.join(build_dir, i[combined_len:]))
                        break

        return parameter_list

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    @classmethod
    def use_linker_args(cls, linker: str, version: str) -> T.List[str]:
        return ['-C', f'linker={linker}']

    # Rust does not have a use_linker_args because it dispatches to a gcc-like
    # C compiler for dynamic linking, as such we invoke the C compiler's
    # use_linker_args method instead.

    def get_options(self) -> MutableKeyedOptionDictType:
        return dict((self.create_option(coredata.UserComboOption,
                                        OptionKey('std', machine=self.for_machine, lang=self.language),
                                        'Rust edition to use',
                                        ['none', '2015', '2018', '2021'],
                                        'none'),))

    def get_dependency_compile_args(self, dep: 'Dependency') -> T.List[str]:
        # Rust doesn't have dependency compile arguments so simply return
        # nothing here. Dependencies are linked and all required metadata is
        # provided by the linker flags.
        return []

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('--edition=' + std.value)
        return args

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        # Rust handles this for us, we don't need to do anything
        return []

    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        if self.linker.id not in {'link', 'lld-link'}:
            return []
        return self.MSVCRT_ARGS[self.get_crt_val(crt_val, buildtype)]

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        if colortype in {'always', 'never', 'auto'}:
            return [f'--color={colortype}']
        raise MesonException(f'Invalid color type for rust {colortype}')

    def get_linker_always_args(self) -> T.List[str]:
        args: T.List[str] = []
        for a in super().get_linker_always_args():
            args.extend(['-C', f'link-arg={a}'])
        return args

    def get_werror_args(self) -> T.List[str]:
        # Use -D warnings, which makes every warning not explicitly allowed an
        # error
        return ['-D', 'warnings']

    def get_warn_args(self, level: str) -> T.List[str]:
        # TODO: I'm not really sure what to put here, Rustc doesn't have warning
        return self._WARNING_LEVELS[level]

    def get_pic_args(self) -> T.List[str]:
        # relocation-model=pic is rustc's default already.
        return []

    def get_pie_args(self) -> T.List[str]:
        # Rustc currently has no way to toggle this, it's controlled by whether
        # pic is on by rustc
        return []

    def get_assert_args(self, disable: bool) -> T.List[str]:
        action = "no" if disable else "yes"
        return ['-C', f'debug-assertions={action}', '-C', 'overflow-checks=no']


class ClippyRustCompiler(RustCompiler):

    """Clippy is a linter that wraps Rustc.

    This just provides us a different id
    """

    id = 'clippy-driver rustc'

"""

```