Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding - What is this?**

The first line gives us a huge clue: "frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/rust.py". This tells us:

* **Frida:** The tool this code belongs to. Knowing Frida's purpose (dynamic instrumentation) is key.
* **Subprojects/frida-node:**  Indicates this is part of Frida's Node.js integration.
* **releng/meson:**  Points to release engineering and the Meson build system.
* **mesonbuild/compilers:** This confirms this file defines how the Rust compiler is handled within the Meson build process.
* **rust.py:**  The specific programming language being dealt with is Rust.

Therefore, this code is part of Frida's build system, specifically dealing with how to compile Rust code when building the Frida Node.js bindings.

**2. Core Functionality - What does it do?**

The code defines two classes: `RustCompiler` and `ClippyRustCompiler`. This suggests it's about managing the Rust compilation process. Let's examine the methods within `RustCompiler`:

* **`__init__`:**  Initialization – takes compiler executable path, version, target machine, etc. This is standard setup.
* **`sanity_check`:**  Compiles a simple Rust program and runs it. This verifies the Rust compiler is working correctly.
* **`_native_static_libs`:**  Determines the native static libraries required for linking Rust static libraries. This is important for cross-language linking.
* **`get_dependency_gen_args`:**  Gets arguments for generating dependency information (like Makefiles).
* **`get_sysroot`:**  Gets the Rust system root directory.
* **`get_crt_static`:**  Checks if the C runtime is linked statically.
* **`get_debug_args`:**  Gets compiler arguments for debug builds.
* **`get_optimization_args`:**  Gets compiler arguments for different optimization levels.
* **`compute_parameters_with_absolute_paths`:**  Makes library paths absolute.
* **`get_output_args`:**  Gets arguments for specifying the output file name.
* **`use_linker_args`:**  Specifies the linker to use.
* **`get_options`:**  Gets user-configurable options (like the Rust edition).
* **`get_dependency_compile_args`:**  Gets arguments needed when compiling dependencies.
* **`get_option_compile_args`:** Gets arguments based on user-defined options.
* **`get_crt_compile_args`:** Gets arguments related to the C runtime (for compilation).
* **`get_crt_link_args`:** Gets arguments related to the C runtime (for linking).
* **`get_colorout_args`:** Gets arguments for controlling color output.
* **`get_linker_always_args`:** Gets arguments that should always be passed to the linker.
* **`get_werror_args`:** Gets arguments to treat warnings as errors.
* **`get_warn_args`:** Gets arguments to control warning levels.
* **`get_pic_args`:** Gets arguments for Position Independent Code.
* **`get_pie_args`:** Gets arguments for Position Independent Executables.
* **`get_assert_args`:** Gets arguments to control assertions.

`ClippyRustCompiler` seems to be a specialized version for using the Clippy linter.

**3. Relation to Reverse Engineering:**

This is where the Frida context becomes crucial. Frida is a reverse engineering tool. How does compiling Rust code relate?

* **Frida Gadget:** Frida often injects a "gadget" into the target process. This gadget might be written in Rust for performance or safety reasons. This code manages the compilation of that gadget.
* **Custom Instrumentation:**  Users might write their own Frida scripts or extensions in Rust. This code is part of how those could be built.

**4. Binary/Low-Level, Linux/Android Kernel/Framework:**

* **Native Static Libraries (`_native_static_libs`):**  When you link Rust code into a shared library (like Frida's gadget), it needs to link against system libraries. This code identifies those libraries. This is definitely low-level.
* **`get_sysroot`:**  Knowing the system root is essential for finding headers and libraries – a low-level concern.
* **`-L` flags in `compute_parameters_with_absolute_paths`:** These flags tell the linker where to find libraries. This is part of the binary linking process.
* **PIC/PIE (`get_pic_args`, `get_pie_args`):**  These are crucial for security and how shared libraries are loaded in memory, especially on Linux and Android.
* **C Runtime (`get_crt_static`, `get_crt_link_args`):**  Rust often interoperates with C code, requiring careful management of the C runtime library. This is especially relevant on platforms like Android.

**5. Logic and Assumptions:**

* **Optimization Levels:**  The `rust_optimization_args` dictionary maps human-readable optimization levels ('0', '1', '2', '3', 's') to Rust compiler flags. The assumption is that these flags are the standard way to control optimization in `rustc`.
* **Warning Levels:** The `_WARNING_LEVELS` dictionary does the same for warning levels.
* **MSVCRT Arguments:** The `MSVCRT_ARGS` dictionary handles different versions of the Microsoft Visual C Runtime, a Windows-specific concern. The assumption is that the linker being used is `link` or `lld-link` on Windows.

**6. User/Programming Errors:**

* **Incorrect Optimization Level:** If a user specifies an invalid optimization level (not in the `rust_optimization_args` keys), the `get_optimization_args` function would raise a KeyError (though the current implementation doesn't explicitly handle this).
* **Invalid Color Type:** The `get_colorout_args` function explicitly checks for valid color types and raises a `MesonException` for invalid input.
* **Missing Dependencies:** If the Rust code being compiled depends on external libraries that aren't properly specified, the linking stage will fail. While this code doesn't directly *cause* this, it's part of the system that needs those dependencies configured correctly.
* **Incorrect Rust Edition:** Specifying an incorrect or unsupported Rust edition via the `std` option would likely lead to compilation errors.

**7. User Operation - Debugging Clues:**

Imagine a user is trying to build Frida with Node.js support, and the Rust compilation is failing. How do they reach this code?

1. **Configuration:** The user runs Meson to configure the build (e.g., `meson setup build`). Meson reads the build configuration, including instructions to build the Frida Node.js bindings, which likely involves compiling Rust code.
2. **Compiler Selection:** Meson needs to know how to compile Rust code. It will look for a `rustc` compiler.
3. **Compiler Class Instantiation:** Meson will instantiate the `RustCompiler` class in this `rust.py` file, passing in information about the detected Rust compiler.
4. **Sanity Check:** Meson will likely call `sanity_check` to ensure the Rust compiler works. If this fails, it indicates a problem with the Rust installation.
5. **Compilation:**  When building actual targets, Meson will use the methods in this class (like `get_output_args`, `get_optimization_args`, etc.) to construct the command-line arguments for the Rust compiler.
6. **Error:** If the Rust compilation fails during this stage, the error message might provide clues related to the arguments generated by this code. For example, if a library isn't found, the `-L` flags might be incorrect (and `compute_parameters_with_absolute_paths` might be involved).

By following this thought process, we can systematically dissect the code and understand its purpose, its connection to reverse engineering, its low-level aspects, and how it fits into the broader Frida build process.
This Python code defines a `RustCompiler` class (and a subclass `ClippyRustCompiler`) within the Meson build system. Meson is used by the Frida project to manage its build process. This specific file handles the specifics of compiling Rust code as part of the Frida build.

Here's a breakdown of its functions and their relevance:

**Core Functionality of `RustCompiler`:**

1. **Compiler Definition:**  It identifies `rustc` as the Rust compiler and sets the programming language to 'rust'.

2. **Sanity Check (`sanity_check`):**
   - Compiles a minimal Rust program to ensure the compiler is functional.
   - Executes the compiled program to verify it runs correctly.
   - This is a basic but crucial step to confirm the build environment is set up correctly.

3. **Native Static Libraries (`_native_static_libs`):**
   - Determines the native (system-level) static libraries required when linking Rust static libraries.
   - It uses `rustc` with specific flags (`--crate-type staticlib`, `--print native-static-libs`) to get this information.
   - It filters out common libraries that are usually handled by C/C++ linkers.

4. **Dependency Generation (`get_dependency_gen_args`):**
   - Provides the command-line arguments (`--dep-info`) to instruct the Rust compiler to generate dependency information (used for incremental builds).

5. **System Root (`get_sysroot`):**
   - Retrieves the Rust system root directory using `rustc --print sysroot`. This is important for finding standard library files and other compiler-related resources.

6. **C Runtime Linking (`get_crt_static`, `get_crt_link_args`):**
   - `get_crt_static`: Checks if the C runtime library is linked statically by querying `rustc`'s configuration.
   - `get_crt_link_args`:  Provides linker arguments related to the Microsoft Visual C Runtime (MSVCRT) on Windows, based on the user's `b_vscrt` option. This is necessary for interoperability with C/C++ code.

7. **Debug and Optimization Arguments (`get_debug_args`, `get_optimization_args`):**
   - `get_debug_args`: Returns the appropriate compiler flags for debug builds (typically `-C debuginfo=2`).
   - `get_optimization_args`:  Maps optimization levels ('0', '1', '2', '3', 's') to corresponding `rustc` flags (`-C opt-level=...`).

8. **Path Handling (`compute_parameters_with_absolute_paths`):**
   - Converts relative library paths (specified with `-L`) to absolute paths. This ensures that the linker can find the libraries regardless of the current working directory during the build.

9. **Output Arguments (`get_output_args`):**
   - Provides the argument (`-o`) to specify the output file name for the compiled binary.

10. **Linker Selection (`use_linker_args`):**
    - Specifies the linker to use (e.g., `-C linker=lld`).

11. **Compiler Options (`get_options`, `get_option_compile_args`):**
   - `get_options`: Defines user-configurable options specific to the Rust compiler, such as the Rust edition (`std`).
   - `get_option_compile_args`: Translates these user options into `rustc` command-line arguments (e.g., `--edition=2021`).

12. **Dependency Handling (`get_dependency_compile_args`):**
   - Currently returns an empty list. Rust's dependency management is primarily handled through its build system (Cargo) and linker flags, not specific compiler flags during compilation of dependent crates.

13. **C Runtime Compilation Arguments (`get_crt_compile_args`):**
   - Returns an empty list. Rust generally handles C runtime linking automatically, and doesn't require specific compiler flags for this.

14. **Color Output (`get_colorout_args`):**
   - Provides the `--color` argument to control whether `rustc` should use colored output.

15. **Linker Always Arguments (`get_linker_always_args`):**
   - Wraps arguments meant for the linker (via the parent class) with `-C link-arg=`.

16. **Warnings as Errors (`get_werror_args`):**
   - Provides the `-D warnings` argument to treat all warnings as errors.

17. **Warning Levels (`get_warn_args`):**
   - Maps warning levels ('0', '1', '2', '3') to `rustc` flags to control the verbosity of warnings.

18. **Position Independent Code/Executable (`get_pic_args`, `get_pie_args`):**
   - `get_pic_args`: Returns an empty list as `rustc` defaults to generating Position Independent Code (PIC).
   - `get_pie_args`: Returns an empty list. PIE is often controlled by whether PIC is enabled in Rust.

19. **Assertions (`get_assert_args`):**
   - Provides arguments (`-C debug-assertions=...`, `-C overflow-checks=no`) to control whether debug assertions and overflow checks are enabled.

**How it Relates to Reverse Engineering (Frida Context):**

This code is crucial for building Frida because Frida often uses Rust for performance-sensitive or lower-level components. Here's how it connects to reverse engineering techniques:

* **Frida Gadget:** Frida injects a "gadget" into the target process. This gadget, which contains the core instrumentation logic, might be written in Rust for safety and performance reasons. This `RustCompiler` class is responsible for compiling that Rust code.
* **Custom Frida Modules/Extensions:** Users can write their own Frida modules or extensions in Rust to perform specific instrumentation tasks. This code ensures that these Rust components can be built as part of the overall Frida build process.
* **Interfacing with Native Code:**  When Frida interacts with the target process's memory and functions, it often needs to call into native code. Rust's ability to interface with C/C++ makes it a suitable choice, and this compiler configuration ensures correct linking and interoperability.

**Examples Relating to Binary, Linux, Android Kernel/Framework:**

* **Binary/Low-Level:**
    * **Native Static Libraries (`_native_static_libs`):** Identifying system libraries like `libc` is fundamental to binary linking. When Frida's Rust code needs to interact with OS functionalities, it needs to link against these libraries.
    * **C Runtime Linking (`get_crt_link_args`):** On Windows, the choice of MSVCRT (e.g., `md`, `mt`) affects how the binary interacts with the operating system at a low level.
    * **Position Independent Code (PIC/PIE):** These are critical for shared libraries and executables on Linux and Android. PIC allows code to be loaded at any address in memory, which is essential for shared libraries. PIE enhances security by randomizing the base address of executables.

* **Linux/Android Kernel/Framework:**
    * **`get_sysroot`:** Knowing the system root is necessary to find the correct standard library implementations for the target platform (e.g., the specific Linux distribution or Android version).
    * **PIC/PIE:**  These are core security features in modern Linux and Android systems. Ensuring Rust code is compiled with PIC/PIE is essential for Frida to function correctly and securely on these platforms.
    * **Interfacing with Android Framework:**  If Frida's Rust components need to interact with Android system services or framework components, they might need to link against specific Android libraries. This compiler configuration would be involved in setting up the correct linking environment.

**Logical Reasoning (Hypothetical Input/Output):**

Let's say a user wants to build Frida with an optimized release build for a Linux target.

* **Hypothetical Input:**
    * Meson configuration specifies a release build (`buildtype=release`).
    * The target machine is Linux.
    * The user hasn't explicitly set the Rust edition.
* **Logical Processing within `RustCompiler`:**
    * `get_optimization_args('3')` would be called (assuming '3' is the default for release builds), returning `['-C', 'opt-level=3']`.
    * `get_debug_args(False)` would be called, returning an empty list (no debug info in release).
    * `get_option_compile_args({})` would be called (no specific Rust edition set), returning an empty list.
* **Hypothetical Output:**
    * The `rustc` command-line arguments generated by Meson (using this class) would include `-C opt-level=3`.

**User/Programming Common Usage Errors:**

1. **Incorrect Optimization Level:**
   - **Example:** The user might try to pass an invalid optimization level like `'fastest'` to a Meson option that maps to Rust optimization.
   - **Error:** The `get_optimization_args` function would likely not have a mapping for `'fastest'` and might raise a `KeyError` or result in unexpected compiler behavior. Meson would ideally validate these options.

2. **Conflicting C Runtime Options:**
   - **Example:** On Windows, a user might incorrectly configure options related to static/dynamic linking of the C runtime (`b_vscrt`), leading to conflicts during linking.
   - **Error:** The linker might fail with errors related to duplicate symbols or missing dependencies if the `get_crt_link_args` are not set up correctly based on the user's choices.

3. **Missing Dependencies:**
   - **Example:** If a custom Frida module written in Rust depends on an external Rust crate (library), and this dependency isn't properly specified in the module's `Cargo.toml` file or the overall build system, the compilation will fail.
   - **Error:** The `rustc` compiler will report errors about missing crates.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Configuration:** The user runs the Meson configuration command (e.g., `meson setup builddir`). Meson reads the build definition files, including those for Frida, and identifies that Rust compilation is required.

2. **Compiler Detection:** Meson attempts to find a suitable Rust compiler (`rustc`) on the system.

3. **`RustCompiler` Instantiation:** If a Rust compiler is found, Meson instantiates the `RustCompiler` class from this `rust.py` file.

4. **Sanity Check:** Meson calls the `sanity_check` method to verify that the detected Rust compiler is working correctly. If this fails, it indicates a problem with the Rust installation.

5. **Compilation of Rust Targets:** When building specific Frida components or user-provided Rust modules, Meson uses the methods in the `RustCompiler` class to generate the necessary command-line arguments for `rustc`.

6. **Debugging Scenario:** If the Rust compilation step fails during the build process, the error messages from `rustc` might contain clues related to the arguments generated by this `RustCompiler` class. For instance, if there are linking errors, the `-L` flags (handled by `compute_parameters_with_absolute_paths`) or the C runtime arguments (`get_crt_link_args`) might be involved. Examining the verbose build output (often enabled with `-v` or `--verbose` flags in Meson) can reveal the exact `rustc` commands being executed.

In summary, this `rust.py` file is a crucial part of Frida's build system, responsible for encapsulating the logic and configuration needed to compile Rust code within the broader Frida project. It bridges the gap between the generic Meson build system and the specifics of the Rust compiler.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/rust.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```