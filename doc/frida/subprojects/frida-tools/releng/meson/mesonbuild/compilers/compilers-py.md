Response:
The user is asking for a summary of the functionality of the Python code provided. I need to go through the code and identify the key actions and data structures defined.

Here's a breakdown of the code's purpose and features:

1. **Data Structures for Compiler Information:** The code defines various data structures to hold information about different compilers. This includes:
    * `header_suffixes`, `obj_suffixes`, `lib_suffixes`: Sets of file suffixes for headers, objects, and libraries.
    * `lang_suffixes`: A dictionary mapping programming languages to their common file suffixes.
    * `all_languages`, `c_cpp_suffixes`, `cpp_suffixes`, `c_suffixes`, `assembler_suffixes`, `llvm_ir_suffixes`, `all_suffixes`, `source_suffixes`: Sets representing different groups of file suffixes.
    * `SUFFIX_TO_LANG`:  A dictionary mapping file suffixes back to their programming languages.
    * `clib_langs`, `clink_langs`: Tuples defining which languages can be linked together following the C ABI or directly.
    * `CFLAGS_MAPPING`: A dictionary mapping languages to the environment variables used for compiler flags.

2. **Utility Functions for File Type Identification:** Several functions are defined to determine the type of a file based on its suffix:
    * `is_header()`
    * `is_source_suffix()`
    * `is_source()`
    * `is_assembly()`
    * `is_llvm_ir()`
    * `is_object()`
    * `is_library()`
    * `is_known_suffix()`

3. **Enumeration for Compile Check Mode:**  The `CompileCheckMode` enum defines the different stages of compilation that can be checked (preprocess, compile, link).

4. **Data for Windows Libraries:** Lists of libraries commonly used on Windows with GNU (`gnu_winlibs`) and MSVC (`msvc_winlibs`) compilers.

5. **Optimization and Debug Arguments:** Dictionaries (`clike_optimization_args`, `clike_debug_args`) store command-line arguments for optimization and debugging levels common to C-like compilers.

6. **Data for MSVC Runtime Library Options:** `MSCRT_VALS` lists the possible values for the MSVC runtime library setting.

7. **Base Options for Compilation:** The `BaseOption` dataclass and `BASE_OPTIONS` dictionary define common build options (like LTO, sanitizers, PGO, coverage) and their types, descriptions, defaults, and allowed choices.

8. **Functions for Managing Build Options:**
    * `option_enabled()`: Checks if a specific build option is enabled.
    * `get_option_value()`: Retrieves the value of a build option, providing a fallback if not found.
    * `are_asserts_disabled()`: Determines if assertions should be disabled based on the build options.
    * `get_base_compile_args()`: Generates a list of base compiler arguments based on the enabled build options.
    * `get_base_link_args()`: Generates a list of base linker arguments based on the enabled build options.

9. **Exception for Cross-Compilation:** `CrossNoRunException` is defined for situations where running executables is not possible in a cross-compilation environment.

10. **Data Classes for Compilation Results:**
    * `RunResult`: Stores the outcome of running a compiled program (success, return code, output).
    * `CompileResult`: Stores the result of a compilation attempt (output, return code, commands used).

11. **Abstract Base Class for Compilers:** The `Compiler` class serves as an abstract base class for representing different compilers. It defines common attributes and methods that all compilers should have. Key methods include:
    * Initialization with compiler executable paths, version, and target machine.
    * Checking if a source file can be compiled.
    * Getting the compiler's ID, language, and default file suffix.
    * Methods for performing compile-time checks (e.g., `get_define`, `has_header`, `sizeof`).
    * Methods for running compiled code (`run`, `cached_run`).
    * Methods for getting compiler and linker arguments (e.g., output arguments, search paths, always arguments).
    * Methods for managing compiler options (`create_option`, `update_options`, `get_options`, `get_option_compile_args`, `get_option_link_args`).
    * Methods for finding libraries.

12. **Helper Functions within the Compiler Class:**  The `Compiler` class also includes helper functions:
    * `_unix_args_to_native()` and `unix_args_to_native()`: For converting Unix-style arguments to the native format.
    * `native_args_to_unix()`: For converting native arguments back to Unix-style.
    * `_get_compile_output()`:  For getting the output filename for compilation.

**Relation to Reverse Engineering:**

This code is related to reverse engineering in the following ways:

* **Understanding Binary Structure:** The code deals with different types of binary files (.o, .so, .dll, .a), which are the output of compilation and linking. Reverse engineers often work with these file formats.
* **Compiler Flags and Options:** The code manages compiler flags (optimization levels, debugging symbols, etc.). These flags directly influence the generated binary code, which is crucial for reverse engineers to understand. For example, knowing if LTO is enabled or what sanitizers were used can provide insights into the binary's characteristics.
* **Linker Behavior:** The code interacts with linkers, which combine compiled object files into executables or libraries. Understanding linker behavior (e.g., library search paths, handling of undefined symbols) is essential in reverse engineering to analyze dependencies and the overall structure of a program.
* **Cross-Compilation:**  The code considers cross-compilation scenarios. Reverse engineers might encounter binaries compiled for different architectures, and this code provides the infrastructure for handling such cases.
* **Testing Compilation and Execution:** The `run` and `cached_run` methods demonstrate the ability to compile and execute code snippets, which can be used in reverse engineering to test hypotheses about how certain code sections behave.

**Examples Relating to Reverse Engineering:**

* **Compiler Flags and Optimization:** A reverse engineer might notice that a binary is heavily optimized. By looking at the build system (which might use code like this), they could identify the optimization flags used (e.g., `-O3`), helping them understand why the code is difficult to follow.
* **Library Dependencies:**  If a reverse engineer is analyzing a binary and encounters a call to a function in a shared library, they can use the concepts of library search paths (handled in methods like `find_library` and `get_linker_search_args`) to understand where that library might have been located during the build process.
* **Sanitizers:** If the build system enabled address or memory sanitizers, this might leave traces or specific runtime checks in the binary, which a reverse engineer could identify and use to understand potential vulnerabilities.
* **Position Independent Executables (PIE):** The `b_pie` option relates to generating position-independent executables. A reverse engineer analyzing a binary on a modern Linux system will likely encounter PIE, and understanding how it's enabled during the build process is helpful.

**Binary Underpinnings, Linux/Android Kernel, and Frameworks:**

* **Binary File Formats:** The code inherently deals with binary file formats like ELF (on Linux) or Mach-O (on macOS). The suffixes `.o`, `.so`, `.a`, `.dll` directly represent these binary formats.
* **Linking:** The process of linking involves resolving symbols and creating the final executable or library. This is a fundamental operation at the binary level.
* **Shared Libraries (.so, .dll):** The code manages the creation and linking of shared libraries, which are a core concept in both Linux and Android systems for code reuse and modularity.
* **Linux Kernel (Indirectly):** While this code doesn't directly interact with the Linux kernel, the compiler and linker tools it manages are responsible for generating code that runs on the kernel. The flags and options used can affect how the generated code interacts with system calls and kernel features.
* **Android Framework (Indirectly):** Similarly, for Android development, the compilers and linkers managed by this code are used to build applications and libraries that run within the Android runtime environment (ART) and interact with the Android framework.
* **System Calls:** The compiled code ultimately makes system calls to interact with the operating system kernel. The compiler flags and linking process influence how these system calls are generated.

**Examples Relating to Binary/Kernel/Framework Concepts:**

* **Shared Library Versioning:** The regular expression `soregex` is designed to match shared library names with versioning information (e.g., `libfoo.so.1.2.3`), a common practice in Linux systems.
* **Position Independent Code (PIC):** The `b_staticpic` and `b_pie` options relate to generating position-independent code, which is crucial for shared libraries and modern security practices in Linux and Android.
* **Linker Flags:** Options like `-Wl,--as-needed` directly translate to linker flags that control how dependencies are handled, impacting the final binary structure and potentially its interaction with the operating system's dynamic linker.

**Logical Reasoning and Assumptions:**

* **Assumption:** The code assumes that the provided lists of file suffixes are generally accurate for the respective languages.
* **Assumption:** The logic for enabling/disabling features based on build options (like LTO, sanitizers) is based on the standard command-line flags for common compilers.
* **Input/Output Examples:**
    * **Input:**  A source file named `my_code.cpp`.
    * **Reasoning:** The `is_source()` function would split the filename, extract the suffix `.cpp`, convert it to lowercase, and check if it exists in the `source_suffixes` set.
    * **Output:** `True` (because `.cpp` is a source file suffix).
    * **Input:** Build options with `b_lto` set to `True`.
    * **Reasoning:** The `get_base_compile_args()` function would check the value of the `b_lto` option and, if true, call the compiler's `get_lto_compile_args()` method to get the necessary compiler flags for link-time optimization.
    * **Output:** A list of compiler flags specific to LTO for the given compiler (e.g., `['-flto']` for GCC/Clang).

**Common User/Programming Errors:**

* **Incorrect File Suffixes:**  A user might try to compile a file with an unrecognized suffix. The `can_compile()` method would return `False`, leading to a build error.
* **Misconfigured Build Options:** Users might enable incompatible build options (e.g., certain sanitizers with LTO) that can cause compilation or linking failures. The build system using this code would need to handle such conflicts or provide informative error messages.
* **Missing Dependencies:** If the code being compiled relies on external libraries, and the linker search paths are not correctly configured, the linking stage will fail.
* **Cross-Compilation Issues:**  Users might encounter `CrossNoRunException` if they are cross-compiling and try to run tests without a suitable execution environment.
* **Forgetting to install compiler or linker:** If the compiler or linker specified in the environment is not installed or not in the system's PATH, the `exelist` will be incorrect, leading to errors when trying to invoke the compiler.

**User Operations Leading to This Code:**

This code is part of the internal workings of the Meson build system. A user's actions that would indirectly lead to this code being executed include:

1. **Creating a Meson Project:** The user creates a `meson.build` file that defines the project's build logic, including source files, dependencies, and build options.
2. **Running `meson setup`:** This command configures the build environment. Meson will analyze the `meson.build` file and detect the compilers available on the system. The code in `compilers.py` is crucial for representing and interacting with these compilers.
3. **Specifying Build Options:** The user might use the `-D` option with `meson setup` to set specific build options (e.g., `-Db_lto=true`, `-Db_sanitize=address`). These options are then used by the functions in `compilers.py` to generate the correct compiler and linker arguments.
4. **Running `meson compile`:** This command starts the actual compilation process. Meson will use the compiler information and flags generated by this code to compile the source files.
5. **Building Targets with Dependencies:** When building targets (executables or libraries) with dependencies, Meson will use the library finding mechanisms (like `find_library`) in this code to locate and link against the required libraries.
6. **Running Tests:** If the `meson.build` file defines tests, Meson might use the `run` or `cached_run` methods to compile and execute test programs.

**Summary of Functionality (Part 1):**

The primary function of this code (up to the provided point) is to **define and manage information about different compilers and their associated tools within the Meson build system.** This includes:

* **Defining data structures to represent compiler capabilities, supported file types, and command-line arguments.**
* **Providing utility functions for identifying file types and managing build options.**
* **Defining an abstract `Compiler` class that serves as a blueprint for concrete compiler implementations.**
* **Implementing logic for generating compiler and linker arguments based on selected build options.**
* **Providing mechanisms for performing compile-time checks and running compiled code snippets.**

In essence, this code acts as the **foundation for Meson's compiler abstraction layer**, allowing it to work with a variety of compilers in a consistent manner.

这是 frida 动态 instrumentation 工具的一部分，位于 Meson 构建系统的编译器处理模块中。其主要功能是 **定义和管理 Meson 已知的各种编译器的信息和行为方式。**  具体来说，它提供了用于描述和操作不同编程语言编译器及其相关工具（如链接器）的抽象和数据结构。

以下是该代码的功能归纳：

**1. 定义了各种编程语言的文件后缀名：**

*   **`header_suffixes`**:  定义了头文件的常见后缀名（.h, .hpp 等）。
*   **`obj_suffixes`**: 定义了目标文件的常见后缀名（.o, .obj 等）。
*   **`lib_suffixes`**: 定义了库文件的常见后缀名（.a, .so, .dll 等）。
*   **`lang_suffixes`**:  一个字典，将编程语言映射到该语言的常见源文件后缀名。
*   **`all_languages`**:  包含所有已知编程语言的键。
*   **`c_cpp_suffixes`, `cpp_suffixes`, `c_suffixes`, `assembler_suffixes`, `llvm_ir_suffixes`, `all_suffixes`, `source_suffixes`**: 定义了不同类型文件的后缀名集合。
*   **`SUFFIX_TO_LANG`**: 一个反向映射，将文件后缀名映射回编程语言。

**2. 定义了与链接相关的语言分类：**

*   **`clib_langs`**:  可以生成遵循 C ABI 库的语言列表（排序）。
*   **`clink_langs`**:  可以直接与 C 代码链接的语言列表（排序）。

**3. 定义了文件类型判断函数：**

*   **`is_header(fname)`**: 判断文件是否是头文件。
*   **`is_source_suffix(suffix)`**: 判断后缀名是否是源文件后缀。
*   **`is_source(fname)`**: 判断文件是否是源文件。
*   **`is_assembly(fname)`**: 判断文件是否是汇编文件。
*   **`is_llvm_ir(fname)`**: 判断文件是否是 LLVM IR 文件。
*   **`is_object(fname)`**: 判断文件是否是目标文件。
*   **`is_library(fname)`**: 判断文件是否是库文件。
*   **`is_known_suffix(fname)`**: 判断文件后缀名是否是已知的。

**4. 定义了编译检查模式枚举 `CompileCheckMode`：**

*   **`PREPROCESS`**: 预处理阶段。
*   **`COMPILE`**: 编译阶段。
*   **`LINK`**: 链接阶段。

**5. 定义了 Windows 平台常用的库列表：**

*   **`gnu_winlibs`**:  GNU 工具链在 Windows 上常用的库。
*   **`msvc_winlibs`**:  MSVC 工具链常用的库。

**6. 定义了类 C 语言的优化和调试参数：**

*   **`clike_optimization_args`**:  定义了不同优化级别的命令行参数（-O0, -O1, -O2, -O3, -Os）。
*   **`clike_debug_args`**:  定义了是否开启调试信息的命令行参数（-g）。

**7. 定义了 MSVC 运行库类型选项 `MSCRT_VALS`。**

**8. 定义了构建选项的基类 `BaseOption` 和默认选项 `BASE_OPTIONS`：**

*   **`BaseOption`**:  一个数据类，用于描述构建选项的类型、描述、默认值和可选值。
*   **`BASE_OPTIONS`**:  一个字典，包含了 Meson 提供的基础构建选项（例如，是否使用预编译头、LTO、代码清理器、PGO 等）。

**9. 定义了操作构建选项的函数：**

*   **`option_enabled(boptions, options, option)`**: 检查特定构建选项是否启用。
*   **`get_option_value(options, opt, fallback)`**: 获取构建选项的值，如果不存在则返回默认值。
*   **`are_asserts_disabled(options)`**:  判断是否禁用了断言。
*   **`get_base_compile_args(options, compiler)`**:  根据构建选项生成通用的编译参数。
*   **`get_base_link_args(options, linker, is_shared_module, build_dir)`**:  根据构建选项生成通用的链接参数。

**10. 定义了 `CrossNoRunException` 异常类，用于表示跨平台编译时无法运行可执行文件的情况。**

**11. 定义了 `RunResult` 和 `CompileResult` 数据类，用于存储程序运行和编译的结果。**

**12. 定义了抽象基类 `Compiler`：**

*   这是一个抽象基类，用于表示各种编译器。它定义了所有编译器都应该具有的通用属性和方法，例如：
    *   编译器的可执行文件列表 (`exelist`)
    *   编译器版本 (`version`)
    *   目标机器 (`for_machine`)
    *   支持的语言 (`language`)
    *   警告参数 (`warn_args`)
    *   用于获取编译器输出参数、链接器输出参数、搜索路径参数等的方法。
    *   用于检查头文件、宏定义、类型大小等的方法。
    *   用于编译和运行代码的方法。
    *   用于管理编译器选项的方法。

**与逆向方法的关系：**

该代码与逆向工程存在间接但重要的联系。

*   **理解构建过程：** 逆向工程通常需要理解目标程序的构建过程。该代码揭示了构建过程中涉及的编译器、链接器以及各种编译选项。了解这些信息可以帮助逆向工程师推断代码的编译方式，例如是否开启了优化、是否使用了特定的安全特性等，从而更好地理解程序的行为。
*   **识别编译器和链接器特性：**  通过分析构建脚本和构建系统的行为，逆向工程师可以识别出目标程序使用的编译器和链接器。该代码提供了各种编译器的元数据，可以帮助逆向工程师理解特定编译器或链接器的行为和特性，例如默认的链接库、代码生成方式等。
*   **分析二进制文件结构：** 编译器和链接器的参数会影响最终生成的可执行文件或库文件的结构。例如，是否使用 PIC/PIE（位置无关代码/可执行文件）会影响内存布局。了解这些构建选项可以帮助逆向工程师更好地分析二进制文件的结构和加载方式。

**举例说明：**

*   **假设逆向工程师发现一个二进制文件使用了 `-fPIC` 编译选项。**  查看该代码可以发现 `b_staticpic` 选项与此相关，逆向工程师可以了解到这个二进制文件很可能是一个共享库，需要在内存中的任意位置加载。
*   **假设逆向工程师想要了解某个二进制文件是否使用了链接时优化 (LTO)。**  他们可以查看构建日志或尝试分析构建脚本，如果发现 `b_lto` 选项被设置为 `True`，结合该代码中 `get_base_link_args` 方法对 LTO 参数的处理，可以推断出该二进制文件可能经过了更深层次的优化，增加了逆向分析的难度。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层：**  该代码处理编译和链接过程，最终生成的是二进制文件（目标文件、库文件、可执行文件）。定义的各种文件后缀名（.o, .so, .dll）代表了不同的二进制文件格式。链接过程是将多个目标文件和库文件组合成一个可执行的二进制文件的过程，涉及符号解析、地址重定位等底层操作。
*   **Linux 内核：**  生成的二进制文件最终运行在操作系统内核之上。编译器选项，例如是否生成位置无关代码 (PIC)，会影响程序在内存中的加载和运行方式，这直接与 Linux 内核的内存管理机制相关。共享库的加载和链接也是 Linux 内核的一部分。
*   **Android 内核及框架：**  虽然代码本身不直接操作 Android 内核，但 Frida 工具常用于 Android 平台的动态 instrumentation。该代码定义的编译器和链接器设置会影响生成的 Android 应用或 Native 库的结构和行为。例如，Android 上的共享库也使用 `.so` 后缀，其加载方式与 Linux 类似。

**举例说明：**

*   **共享库后缀 `.so`：**  该代码中 `lib_suffixes` 包含 `.so`，这代表了 Linux 和 Android 系统中常用的共享库文件。
*   **位置无关代码 `b_staticpic`：**  在 Linux 和 Android 上构建共享库时，通常需要使用位置无关代码，该选项的设置会影响编译器生成机器码的方式，使其可以在内存中的任意地址加载。

**逻辑推理：**

*   **假设输入：**  构建选项 `options` 中 `b_lto` 的值为 `True`。
*   **推理：**  `get_base_compile_args(options, compiler)` 函数会检查 `options[OptionKey('b_lto')].value`，如果为 `True`，则会调用 `compiler.get_lto_compile_args()` 方法获取链接时优化的编译参数。
*   **输出：**  `get_base_compile_args` 函数会返回一个包含链接时优化编译参数的列表，具体的参数取决于所使用的编译器。

**用户或编程常见的使用错误：**

*   **文件后缀名错误：** 用户可能将一个 C++ 源文件命名为 `.c` 后缀，导致编译器按照 C 语言的方式处理，可能会产生编译错误。`is_source` 等函数可以帮助 Meson 识别这类错误。
*   **构建选项冲突：** 用户可能同时启用了不兼容的构建选项，例如同时开启了某些代码清理器和链接时优化，这可能会导致编译或链接失败。Meson 需要根据这些选项的定义来避免或报告这类冲突。
*   **依赖库未找到：**  用户在 `meson.build` 文件中声明了依赖库，但系统上没有安装或 Meson 无法找到该库，会导致链接错误。`find_library` 方法就是用于查找库文件的。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户创建或修改 `meson.build` 文件：**  用户在 `meson.build` 文件中定义项目结构、源文件、依赖项和构建选项。
2. **用户运行 `meson setup builddir`：**  Meson 会读取 `meson.build` 文件，并开始配置构建环境。在这个过程中，Meson 需要检测系统中可用的编译器。
3. **Meson 调用 `detect.py` (假设) 中的代码来检测编译器：**  `detect.py` 可能会调用系统命令来查找各种编译器（如 `gcc`, `clang`, `cl.exe`）。
4. **Meson 根据检测到的编译器类型创建相应的 `Compiler` 对象：**  例如，如果检测到 `gcc`，则会创建一个 `GnuCCompiler` 对象（具体的类名可能不同）。
5. **在创建 `Compiler` 对象时，会读取 `compilers.py` 中的信息：**  Meson 会使用 `compilers.py` 中定义的语言后缀、默认编译选项、以及 `Compiler` 抽象基类的实现来初始化编译器对象。
6. **用户运行 `meson compile -C builddir`：**  Meson 开始执行编译操作。
7. **Meson 调用 `compilers.py` 中的函数来生成编译和链接命令：**  例如，根据 `meson.build` 中定义的构建选项和目标文件，调用 `get_base_compile_args` 和 `get_base_link_args` 来生成传递给编译器的命令行参数。

**作为调试线索，如果用户遇到编译错误，可以查看以下信息：**

*   **Meson 的配置输出：**  查看 `meson setup` 的输出，可以了解 Meson 检测到的编译器版本和配置。
*   **编译命令的详细输出：**  Meson 通常会显示实际执行的编译和链接命令，可以查看这些命令是否包含了预期的编译选项（这些选项的生成逻辑在 `compilers.py` 中定义）。
*   **`meson.build` 文件中的构建选项：**  检查 `meson.build` 文件中是否设置了影响编译器行为的选项。

总而言之，`compilers.py` 文件在 Frida 项目的构建过程中扮演着核心角色，它为 Meson 提供了关于各种编译器的必要信息和操作接口，使得 Meson 能够跨平台地管理和执行编译过程。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2022 The Meson development team
# Copyright © 2023 Intel Corporation

from __future__ import annotations

import abc
import contextlib, os.path, re
import enum
import itertools
import typing as T
from dataclasses import dataclass
from functools import lru_cache

from .. import coredata
from .. import mlog
from .. import mesonlib
from ..mesonlib import (
    HoldableObject,
    EnvironmentException, MesonException,
    Popen_safe_logged, LibType, TemporaryDirectoryWinProof, OptionKey,
)

from ..arglist import CompilerArgs

if T.TYPE_CHECKING:
    from ..build import BuildTarget, DFeatures
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers import RSPFileSyntax
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    from ..dependencies import Dependency

    CompilerType = T.TypeVar('CompilerType', bound='Compiler')
    _T = T.TypeVar('_T')
    UserOptionType = T.TypeVar('UserOptionType', bound=coredata.UserOption)

"""This file contains the data files of all compilers Meson knows
about. To support a new compiler, add its information below.
Also add corresponding autodetection code in detect.py."""

header_suffixes = {'h', 'hh', 'hpp', 'hxx', 'H', 'ipp', 'moc', 'vapi', 'di'}
obj_suffixes = {'o', 'obj', 'res'}
# To the emscripten compiler, .js files are libraries
lib_suffixes = {'a', 'lib', 'dll', 'dll.a', 'dylib', 'so', 'js'}
# Mapping of language to suffixes of files that should always be in that language
# This means we can't include .h headers here since they could be C, C++, ObjC, etc.
# First suffix is the language's default.
lang_suffixes = {
    'c': ('c',),
    'cpp': ('cpp', 'cc', 'cxx', 'c++', 'hh', 'hpp', 'ipp', 'hxx', 'ino', 'ixx', 'C', 'H'),
    'cuda': ('cu',),
    # f90, f95, f03, f08 are for free-form fortran ('f90' recommended)
    # f, for, ftn, fpp are for fixed-form fortran ('f' or 'for' recommended)
    'fortran': ('f90', 'f95', 'f03', 'f08', 'f', 'for', 'ftn', 'fpp'),
    'd': ('d', 'di'),
    'objc': ('m',),
    'objcpp': ('mm',),
    'rust': ('rs',),
    'vala': ('vala', 'vapi', 'gs'),
    'cs': ('cs',),
    'swift': ('swift',),
    'java': ('java',),
    'cython': ('pyx', ),
    'nasm': ('asm',),
    'masm': ('masm',),
}
all_languages = lang_suffixes.keys()
c_cpp_suffixes = {'h'}
cpp_suffixes = set(lang_suffixes['cpp']) | c_cpp_suffixes
c_suffixes = set(lang_suffixes['c']) | c_cpp_suffixes
assembler_suffixes = {'s', 'S', 'sx', 'asm', 'masm'}
llvm_ir_suffixes = {'ll'}
all_suffixes = set(itertools.chain(*lang_suffixes.values(), assembler_suffixes, llvm_ir_suffixes, c_cpp_suffixes))
source_suffixes = all_suffixes - header_suffixes
# List of languages that by default consume and output libraries following the
# C ABI; these can generally be used interchangeably
# This must be sorted, see sort_clink().
clib_langs = ('objcpp', 'cpp', 'objc', 'c', 'nasm', 'fortran')
# List of languages that can be linked with C code directly by the linker
# used in build.py:process_compilers() and build.py:get_dynamic_linker()
# This must be sorted, see sort_clink().
clink_langs = ('d', 'cuda') + clib_langs

SUFFIX_TO_LANG = dict(itertools.chain(*(
    [(suffix, lang) for suffix in v] for lang, v in lang_suffixes.items())))

# Languages that should use LDFLAGS arguments when linking.
LANGUAGES_USING_LDFLAGS = {'objcpp', 'cpp', 'objc', 'c', 'fortran', 'd', 'cuda'}
# Languages that should use CPPFLAGS arguments when linking.
LANGUAGES_USING_CPPFLAGS = {'c', 'cpp', 'objc', 'objcpp'}
soregex = re.compile(r'.*\.so(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?$')

# Environment variables that each lang uses.
CFLAGS_MAPPING: T.Mapping[str, str] = {
    'c': 'CFLAGS',
    'cpp': 'CXXFLAGS',
    'cuda': 'CUFLAGS',
    'objc': 'OBJCFLAGS',
    'objcpp': 'OBJCXXFLAGS',
    'fortran': 'FFLAGS',
    'd': 'DFLAGS',
    'vala': 'VALAFLAGS',
    'rust': 'RUSTFLAGS',
    'cython': 'CYTHONFLAGS',
    'cs': 'CSFLAGS', # This one might not be standard.
}

# All these are only for C-linkable languages; see `clink_langs` above.

def sort_clink(lang: str) -> int:
    '''
    Sorting function to sort the list of languages according to
    reversed(compilers.clink_langs) and append the unknown langs in the end.
    The purpose is to prefer C over C++ for files that can be compiled by
    both such as assembly, C, etc. Also applies to ObjC, ObjC++, etc.
    '''
    if lang not in clink_langs:
        return 1
    return -clink_langs.index(lang)

def is_header(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in header_suffixes

def is_source_suffix(suffix: str) -> bool:
    return suffix in source_suffixes

def is_source(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1].lower()
    return is_source_suffix(suffix)

def is_assembly(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in assembler_suffixes

def is_llvm_ir(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in llvm_ir_suffixes

@lru_cache(maxsize=None)
def cached_by_name(fname: 'mesonlib.FileOrString') -> bool:
    suffix = fname.split('.')[-1]
    return suffix in obj_suffixes

def is_object(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    return cached_by_name(fname)

def is_library(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname

    if soregex.match(fname):
        return True

    suffix = fname.split('.')[-1]
    return suffix in lib_suffixes

def is_known_suffix(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]

    return suffix in all_suffixes


class CompileCheckMode(enum.Enum):

    PREPROCESS = 'preprocess'
    COMPILE = 'compile'
    LINK = 'link'


gnu_winlibs = ['-lkernel32', '-luser32', '-lgdi32', '-lwinspool', '-lshell32',
               '-lole32', '-loleaut32', '-luuid', '-lcomdlg32', '-ladvapi32']

msvc_winlibs = ['kernel32.lib', 'user32.lib', 'gdi32.lib',
                'winspool.lib', 'shell32.lib', 'ole32.lib', 'oleaut32.lib',
                'uuid.lib', 'comdlg32.lib', 'advapi32.lib']

clike_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': [],
    'g': [],
    '1': ['-O1'],
    '2': ['-O2'],
    '3': ['-O3'],
    's': ['-Os'],
}

clike_debug_args: T.Dict[bool, T.List[str]] = {
    False: [],
    True: ['-g']
}


MSCRT_VALS = ['none', 'md', 'mdd', 'mt', 'mtd']

@dataclass
class BaseOption(T.Generic[coredata._T, coredata._U]):
    opt_type: T.Type[coredata._U]
    description: str
    default: T.Any = None
    choices: T.Any = None

    def init_option(self, name: OptionKey) -> coredata._U:
        keywords = {'value': self.default}
        if self.choices:
            keywords['choices'] = self.choices
        return self.opt_type(name.name, self.description, **keywords)

BASE_OPTIONS: T.Mapping[OptionKey, BaseOption] = {
    OptionKey('b_pch'): BaseOption(coredata.UserBooleanOption, 'Use precompiled headers', True),
    OptionKey('b_lto'): BaseOption(coredata.UserBooleanOption, 'Use link time optimization', False),
    OptionKey('b_lto_threads'): BaseOption(coredata.UserIntegerOption, 'Use multiple threads for Link Time Optimization', (None, None, 0)),
    OptionKey('b_lto_mode'): BaseOption(coredata.UserComboOption, 'Select between different LTO modes.', 'default',
                                        choices=['default', 'thin']),
    OptionKey('b_thinlto_cache'): BaseOption(coredata.UserBooleanOption, 'Use LLVM ThinLTO caching for faster incremental builds', False),
    OptionKey('b_thinlto_cache_dir'): BaseOption(coredata.UserStringOption, 'Directory to store ThinLTO cache objects', ''),
    OptionKey('b_sanitize'): BaseOption(coredata.UserComboOption, 'Code sanitizer to use', 'none',
                                        choices=['none', 'address', 'thread', 'undefined', 'memory', 'leak', 'address,undefined']),
    OptionKey('b_lundef'): BaseOption(coredata.UserBooleanOption, 'Use -Wl,--no-undefined when linking', True),
    OptionKey('b_asneeded'): BaseOption(coredata.UserBooleanOption, 'Use -Wl,--as-needed when linking', True),
    OptionKey('b_pgo'): BaseOption(coredata.UserComboOption, 'Use profile guided optimization', 'off',
                                   choices=['off', 'generate', 'use']),
    OptionKey('b_coverage'): BaseOption(coredata.UserBooleanOption, 'Enable coverage tracking.', False),
    OptionKey('b_colorout'): BaseOption(coredata.UserComboOption, 'Use colored output', 'always',
                                        choices=['auto', 'always', 'never']),
    OptionKey('b_ndebug'): BaseOption(coredata.UserComboOption, 'Disable asserts', 'false', choices=['true', 'false', 'if-release']),
    OptionKey('b_staticpic'): BaseOption(coredata.UserBooleanOption, 'Build static libraries as position independent', True),
    OptionKey('b_pie'): BaseOption(coredata.UserBooleanOption, 'Build executables as position independent', False),
    OptionKey('b_bitcode'): BaseOption(coredata.UserBooleanOption, 'Generate and embed bitcode (only macOS/iOS/tvOS)', False),
    OptionKey('b_vscrt'): BaseOption(coredata.UserComboOption, 'VS run-time library type to use.', 'from_buildtype',
                                     choices=MSCRT_VALS + ['from_buildtype', 'static_from_buildtype']),
}

base_options: KeyedOptionDictType = {key: base_opt.init_option(key) for key, base_opt in BASE_OPTIONS.items()}

def option_enabled(boptions: T.Set[OptionKey], options: 'KeyedOptionDictType',
                   option: OptionKey) -> bool:
    try:
        if option not in boptions:
            return False
        ret = options[option].value
        assert isinstance(ret, bool), 'must return bool'  # could also be str
        return ret
    except KeyError:
        return False


def get_option_value(options: 'KeyedOptionDictType', opt: OptionKey, fallback: '_T') -> '_T':
    """Get the value of an option, or the fallback value."""
    try:
        v: '_T' = options[opt].value
    except KeyError:
        return fallback

    assert isinstance(v, type(fallback)), f'Should have {type(fallback)!r} but was {type(v)!r}'
    # Mypy doesn't understand that the above assert ensures that v is type _T
    return v


def are_asserts_disabled(options: KeyedOptionDictType) -> bool:
    """Should debug assertions be disabled

    :param options: OptionDictionary
    :return: whether to disable assertions or not
    """
    return (options[OptionKey('b_ndebug')].value == 'true' or
            (options[OptionKey('b_ndebug')].value == 'if-release' and
             options[OptionKey('buildtype')].value in {'release', 'plain'}))


def get_base_compile_args(options: 'KeyedOptionDictType', compiler: 'Compiler') -> T.List[str]:
    args: T.List[str] = []
    try:
        if options[OptionKey('b_lto')].value:
            args.extend(compiler.get_lto_compile_args(
                threads=get_option_value(options, OptionKey('b_lto_threads'), 0),
                mode=get_option_value(options, OptionKey('b_lto_mode'), 'default')))
    except KeyError:
        pass
    try:
        args += compiler.get_colorout_args(options[OptionKey('b_colorout')].value)
    except KeyError:
        pass
    try:
        args += compiler.sanitizer_compile_args(options[OptionKey('b_sanitize')].value)
    except KeyError:
        pass
    try:
        pgo_val = options[OptionKey('b_pgo')].value
        if pgo_val == 'generate':
            args.extend(compiler.get_profile_generate_args())
        elif pgo_val == 'use':
            args.extend(compiler.get_profile_use_args())
    except KeyError:
        pass
    try:
        if options[OptionKey('b_coverage')].value:
            args += compiler.get_coverage_args()
    except KeyError:
        pass
    try:
        args += compiler.get_assert_args(are_asserts_disabled(options))
    except KeyError:
        pass
    # This does not need a try...except
    if option_enabled(compiler.base_options, options, OptionKey('b_bitcode')):
        args.append('-fembed-bitcode')
    try:
        crt_val = options[OptionKey('b_vscrt')].value
        buildtype = options[OptionKey('buildtype')].value
        try:
            args += compiler.get_crt_compile_args(crt_val, buildtype)
        except AttributeError:
            pass
    except KeyError:
        pass
    return args

def get_base_link_args(options: 'KeyedOptionDictType', linker: 'Compiler',
                       is_shared_module: bool, build_dir: str) -> T.List[str]:
    args: T.List[str] = []
    try:
        if options[OptionKey('b_lto')].value:
            if options[OptionKey('werror')].value:
                args.extend(linker.get_werror_args())

            thinlto_cache_dir = None
            if get_option_value(options, OptionKey('b_thinlto_cache'), False):
                thinlto_cache_dir = get_option_value(options, OptionKey('b_thinlto_cache_dir'), '')
                if thinlto_cache_dir == '':
                    thinlto_cache_dir = os.path.join(build_dir, 'meson-private', 'thinlto-cache')
            args.extend(linker.get_lto_link_args(
                threads=get_option_value(options, OptionKey('b_lto_threads'), 0),
                mode=get_option_value(options, OptionKey('b_lto_mode'), 'default'),
                thinlto_cache_dir=thinlto_cache_dir))
    except KeyError:
        pass
    try:
        args += linker.sanitizer_link_args(options[OptionKey('b_sanitize')].value)
    except KeyError:
        pass
    try:
        pgo_val = options[OptionKey('b_pgo')].value
        if pgo_val == 'generate':
            args.extend(linker.get_profile_generate_args())
        elif pgo_val == 'use':
            args.extend(linker.get_profile_use_args())
    except KeyError:
        pass
    try:
        if options[OptionKey('b_coverage')].value:
            args += linker.get_coverage_link_args()
    except KeyError:
        pass

    as_needed = option_enabled(linker.base_options, options, OptionKey('b_asneeded'))
    bitcode = option_enabled(linker.base_options, options, OptionKey('b_bitcode'))
    # Shared modules cannot be built with bitcode_bundle because
    # -bitcode_bundle is incompatible with -undefined and -bundle
    if bitcode and not is_shared_module:
        args.extend(linker.bitcode_args())
    elif as_needed:
        # -Wl,-dead_strip_dylibs is incompatible with bitcode
        args.extend(linker.get_asneeded_args())

    # Apple's ld (the only one that supports bitcode) does not like -undefined
    # arguments or -headerpad_max_install_names when bitcode is enabled
    if not bitcode:
        args.extend(linker.headerpad_args())
        if (not is_shared_module and
                option_enabled(linker.base_options, options, OptionKey('b_lundef'))):
            args.extend(linker.no_undefined_link_args())
        else:
            args.extend(linker.get_allow_undefined_link_args())

    try:
        crt_val = options[OptionKey('b_vscrt')].value
        buildtype = options[OptionKey('buildtype')].value
        try:
            args += linker.get_crt_link_args(crt_val, buildtype)
        except AttributeError:
            pass
    except KeyError:
        pass
    return args


class CrossNoRunException(MesonException):
    pass

class RunResult(HoldableObject):
    def __init__(self, compiled: bool, returncode: int = 999,
                 stdout: str = 'UNDEFINED', stderr: str = 'UNDEFINED',
                 cached: bool = False):
        self.compiled = compiled
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.cached = cached


class CompileResult(HoldableObject):

    """The result of Compiler.compiles (and friends)."""

    def __init__(self, stdo: T.Optional[str] = None, stde: T.Optional[str] = None,
                 command: T.Optional[T.List[str]] = None,
                 returncode: int = 999,
                 input_name: T.Optional[str] = None,
                 output_name: T.Optional[str] = None,
                 cached: bool = False):
        self.stdout = stdo
        self.stderr = stde
        self.input_name = input_name
        self.output_name = output_name
        self.command = command or []
        self.cached = cached
        self.returncode = returncode


class Compiler(HoldableObject, metaclass=abc.ABCMeta):
    # Libraries to ignore in find_library() since they are provided by the
    # compiler or the C library. Currently only used for MSVC.
    ignore_libs: T.List[str] = []
    # Libraries that are internal compiler implementations, and must not be
    # manually searched.
    internal_libs: T.List[str] = []

    LINKER_PREFIX: T.Union[None, str, T.List[str]] = None
    INVOKES_LINKER = True

    language: str
    id: str
    warn_args: T.Dict[str, T.List[str]]
    mode = 'COMPILER'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str,
                 for_machine: MachineChoice, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None, is_cross: bool = False):
        self.exelist = ccache + exelist
        self.exelist_no_ccache = exelist
        # In case it's been overridden by a child class already
        if not hasattr(self, 'file_suffixes'):
            self.file_suffixes = lang_suffixes[self.language]
        if not hasattr(self, 'can_compile_suffixes'):
            self.can_compile_suffixes: T.Set[str] = set(self.file_suffixes)
        self.default_suffix = self.file_suffixes[0]
        self.version = version
        self.full_version = full_version
        self.for_machine = for_machine
        self.base_options: T.Set[OptionKey] = set()
        self.linker = linker
        self.info = info
        self.is_cross = is_cross
        self.modes: T.List[Compiler] = []

    def __repr__(self) -> str:
        repr_str = "<{0}: v{1} `{2}`>"
        return repr_str.format(self.__class__.__name__, self.version,
                               ' '.join(self.exelist))

    @lru_cache(maxsize=None)
    def can_compile(self, src: 'mesonlib.FileOrString') -> bool:
        if isinstance(src, mesonlib.File):
            src = src.fname
        suffix = os.path.splitext(src)[1]
        if suffix != '.C':
            suffix = suffix.lower()
        return bool(suffix) and suffix[1:] in self.can_compile_suffixes

    def get_id(self) -> str:
        return self.id

    def get_modes(self) -> T.List[Compiler]:
        return self.modes

    def get_linker_id(self) -> str:
        # There is not guarantee that we have a dynamic linker instance, as
        # some languages don't have separate linkers and compilers. In those
        # cases return the compiler id
        try:
            return self.linker.id
        except AttributeError:
            return self.id

    def get_version_string(self) -> str:
        details = [self.id, self.version]
        if self.full_version:
            details += ['"%s"' % (self.full_version)]
        return '(%s)' % (' '.join(details))

    def get_language(self) -> str:
        return self.language

    @classmethod
    def get_display_language(cls) -> str:
        return cls.language.capitalize()

    def get_default_suffix(self) -> str:
        return self.default_suffix

    def get_define(self, dname: str, prefix: str, env: 'Environment',
                   extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                   dependencies: T.List['Dependency'],
                   disable_cache: bool = False) -> T.Tuple[str, bool]:
        raise EnvironmentException('%s does not support get_define ' % self.get_id())

    def compute_int(self, expression: str, low: T.Optional[int], high: T.Optional[int],
                    guess: T.Optional[int], prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                    dependencies: T.Optional[T.List['Dependency']]) -> int:
        raise EnvironmentException('%s does not support compute_int ' % self.get_id())

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        raise EnvironmentException('%s does not support compute_parameters_with_absolute_paths ' % self.get_id())

    def has_members(self, typename: str, membernames: T.List[str],
                    prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                    dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('%s does not support has_member(s) ' % self.get_id())

    def has_type(self, typename: str, prefix: str, env: 'Environment',
                 extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]], *,
                 dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('%s does not support has_type ' % self.get_id())

    def symbols_have_underscore_prefix(self, env: 'Environment') -> bool:
        raise EnvironmentException('%s does not support symbols_have_underscore_prefix ' % self.get_id())

    def get_exelist(self, ccache: bool = True) -> T.List[str]:
        return self.exelist.copy() if ccache else self.exelist_no_ccache.copy()

    def get_linker_exelist(self) -> T.List[str]:
        return self.linker.get_exelist() if self.linker else self.get_exelist()

    @abc.abstractmethod
    def get_output_args(self, outputname: str) -> T.List[str]:
        pass

    def get_linker_output_args(self, outputname: str) -> T.List[str]:
        return self.linker.get_output_args(outputname)

    def get_linker_search_args(self, dirname: str) -> T.List[str]:
        return self.linker.get_search_args(dirname)

    def get_builtin_define(self, define: str) -> T.Optional[str]:
        raise EnvironmentException('%s does not support get_builtin_define.' % self.id)

    def has_builtin_define(self, define: str) -> bool:
        raise EnvironmentException('%s does not support has_builtin_define.' % self.id)

    def get_always_args(self) -> T.List[str]:
        return []

    def can_linker_accept_rsp(self) -> bool:
        """
        Determines whether the linker can accept arguments using the @rsp syntax.
        """
        return self.linker.get_accepts_rsp()

    def get_linker_always_args(self) -> T.List[str]:
        return self.linker.get_always_args()

    def get_linker_lib_prefix(self) -> str:
        return self.linker.get_lib_prefix()

    def gen_import_library_args(self, implibname: str) -> T.List[str]:
        """
        Used only on Windows for libraries that need an import library.
        This currently means C, C++, Fortran.
        """
        return []

    def create_option(self, option_type: T.Type[UserOptionType], option_key: OptionKey, *args: T.Any, **kwargs: T.Any) -> T.Tuple[OptionKey, UserOptionType]:
        return option_key, option_type(f'{self.language}_{option_key.name}', *args, **kwargs)

    @staticmethod
    def update_options(options: MutableKeyedOptionDictType, *args: T.Tuple[OptionKey, UserOptionType]) -> MutableKeyedOptionDictType:
        options.update(args)
        return options

    def get_options(self) -> 'MutableKeyedOptionDictType':
        return {}

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return self.linker.get_option_args(options)

    def check_header(self, hname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        """Check that header is usable.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support header checks.' % self.get_display_language())

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:
        """Check that header is exists.

        This check will return true if the file exists, even if it contains:

        ```c
        # error "You thought you could use this, LOLZ!"
        ```

        Use check_header if your header only works in some cases.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support header checks.' % self.get_display_language())

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('Language %s does not support header symbol checks.' % self.get_display_language())

    def run(self, code: 'mesonlib.FileOrString', env: 'Environment',
            extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None,
            dependencies: T.Optional[T.List['Dependency']] = None,
            run_env: T.Optional[T.Dict[str, str]] = None,
            run_cwd: T.Optional[str] = None) -> RunResult:
        need_exe_wrapper = env.need_exe_wrapper(self.for_machine)
        if need_exe_wrapper and not env.has_exe_wrapper():
            raise CrossNoRunException('Can not run test applications in this cross environment.')
        with self._build_wrapper(code, env, extra_args, dependencies, mode=CompileCheckMode.LINK, want_output=True) as p:
            if p.returncode != 0:
                mlog.debug(f'Could not compile test file {p.input_name}: {p.returncode}\n')
                return RunResult(False)
            if need_exe_wrapper:
                cmdlist = env.exe_wrapper.get_command() + [p.output_name]
            else:
                cmdlist = [p.output_name]
            try:
                pe, so, se = mesonlib.Popen_safe(cmdlist, env=run_env, cwd=run_cwd)
            except Exception as e:
                mlog.debug(f'Could not run: {cmdlist} (error: {e})\n')
                return RunResult(False)

        mlog.debug('Program stdout:\n')
        mlog.debug(so)
        mlog.debug('Program stderr:\n')
        mlog.debug(se)
        return RunResult(True, pe.returncode, so, se)

    # Caching run() in general seems too risky (no way to know what the program
    # depends on), but some callers know more about the programs they intend to
    # run.
    # For now we just accept code as a string, as that's what internal callers
    # need anyway. If we wanted to accept files, the cache key would need to
    # include mtime.
    def cached_run(self, code: str, env: 'Environment', *,
                   extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None) -> RunResult:
        run_check_cache = env.coredata.run_check_cache
        args = self.build_wrapper_args(env, extra_args, dependencies, CompileCheckMode('link'))
        key = (code, tuple(args))
        if key in run_check_cache:
            p = run_check_cache[key]
            p.cached = True
            mlog.debug('Using cached run result:')
            mlog.debug('Code:\n', code)
            mlog.debug('Args:\n', extra_args)
            mlog.debug('Cached run returncode:\n', p.returncode)
            mlog.debug('Cached run stdout:\n', p.stdout)
            mlog.debug('Cached run stderr:\n', p.stderr)
        else:
            p = self.run(code, env, extra_args=extra_args, dependencies=dependencies)
            run_check_cache[key] = p
        return p

    def sizeof(self, typename: str, prefix: str, env: 'Environment', *,
               extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
               dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        raise EnvironmentException('Language %s does not support sizeof checks.' % self.get_display_language())

    def alignment(self, typename: str, prefix: str, env: 'Environment', *,
                  extra_args: T.Optional[T.List[str]] = None,
                  dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        raise EnvironmentException('Language %s does not support alignment checks.' % self.get_display_language())

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        """See if a function exists.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support function checks.' % self.get_display_language())

    @classmethod
    def _unix_args_to_native(cls, args: T.List[str], info: MachineInfo) -> T.List[str]:
        "Always returns a copy that can be independently mutated"
        return args.copy()

    def unix_args_to_native(self, args: T.List[str]) -> T.List[str]:
        return self._unix_args_to_native(args, self.info)

    @classmethod
    def native_args_to_unix(cls, args: T.List[str]) -> T.List[str]:
        "Always returns a copy that can be independently mutated"
        return args.copy()

    def find_library(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                     libtype: LibType = LibType.PREFER_SHARED, lib_prefix_warning: bool = True) -> T.Optional[T.List[str]]:
        raise EnvironmentException(f'Language {self.get_display_language()} does not support library finding.')

    def get_library_naming(self, env: 'Environment', libtype: LibType,
                           strict: bool = False) -> T.Optional[T.Tuple[str, ...]]:
        raise EnvironmentException(
            'Language {} does not support get_library_naming.'.format(
                self.get_display_language()))

    def get_program_dirs(self, env: 'Environment') -> T.List[str]:
        return []

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        """Checks if the compiler has all of the arguments.

        :returns:
            A tuple of (bool, bool). The first value is whether the check
            succeeded, and the second is whether it was retrieved from a cache
        """
        raise EnvironmentException(
            'Language {} does not support has_multi_arguments.'.format(
                self.get_display_language()))

    def has_multi_link_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        """Checks if the linker has all of the arguments.

        :returns:
            A tuple of (bool, bool). The first value is whether the check
            succeeded, and the second is whether it was retrieved from a cache
        """
        return self.linker.has_multi_arguments(args, env)

    def _get_compile_output(self, dirname: str, mode: CompileCheckMode) -> str:
        assert mode != CompileCheckMode.PREPROCESS, 'In pre-processor mode, the output is sent to stdout and discarded'
        # Exten
```