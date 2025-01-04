Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Understanding the Goal:**

The core request is to analyze the `env_generic.py` file from the Frida project and explain its functionalities, connections to reverse engineering, low-level concepts, logical reasoning, potential user errors, and how a user might reach this code.

**2. Initial Code Scan and High-Level Purpose:**

First, I quickly scanned the imports and function definitions. Keywords like `ConfigParser`, `subprocess`, `shutil`, and mentions of compilers (`gcc`, `cl.exe`) and linkers immediately suggested that this code deals with configuring build environments, especially cross-compilation. The function name `init_machine_config` reinforces this idea.

**3. Deeper Dive into `init_machine_config`:**

This is the central function, so I focused on its parameters and the actions within it.

* **Parameters:**  The parameters clearly indicate it's about configuring for a specific `machine` (target) and `build_machine` (host), considering cross-compilation, environment variables, toolchain locations, and using `meson` for the build system.
* **Key Actions:**
    * **Handling Undefined Symbols:** The `allow_undefined_symbols` logic shows OS-specific behavior (FreeBSD).
    * **Meson Configuration:** It initializes a `ConfigParser` and maps some internal concepts to Meson options (like `c_args`, `cpp_args`).
    * **Compiler Detection:**  The code tries to find C/C++ compilers (`gcc` or MSVC). It prioritizes `gcc` if a triplet is provided (common in cross-compilation).
    * **`env2mfile` and Machine Files:** The use of `env2mfile` to generate a machine configuration file for Meson is a crucial step for cross-compilation. It highlights the need to describe the target architecture to the build system.
    * **MSVC Specifics:**  There's explicit handling for Windows using MSVC, including detecting tools like `cl.exe`, `link.exe`, and setting environment variables like `VSINSTALLDIR`, `INCLUDE`, `LIB`.
    * **GCC Detection:** The `resolve_gcc_binaries` function is specifically for locating GCC toolchain binaries.
    * **Linker Flavor Detection:** `detect_linker_flavor` analyzes linker output to determine if it's MSVC, GNU ld, Gold, LLD, or Apple's linker. This is important for setting platform-specific linker flags.
    * **Setting Flags:** The code sets compiler and linker flags based on the detected compiler and target architecture.
    * **Constants:** It populates a "constants" section in the configuration with the generated flags.

**4. Analyzing Helper Functions:**

* **`resolve_gcc_binaries`:**  This clearly focuses on finding GCC-related binaries, handling potential prefixing.
* **`detect_linker_flavor`:** This function uses `subprocess` to run the linker and parse its output, a common technique for identifying tools.

**5. Connecting to the Prompt's Questions:**

Now, systematically address each part of the prompt:

* **Functionality:** Summarize the main actions observed in the code, focusing on environment setup, compiler detection, and flag generation for Meson.
* **Reverse Engineering:** Think about how the actions relate to reverse engineering. The need for specific compiler flags, understanding target architectures, and dealing with different operating systems are all relevant. Examples like analyzing binaries compiled with specific flags or setting up an environment to rebuild parts of a system come to mind.
* **Low-Level Concepts:** Identify areas where the code touches on low-level details:
    * **Binary formats:** Implicit in the compiler and linker choices.
    * **Operating systems:** The code explicitly handles Windows, Linux, macOS, FreeBSD, and QNX.
    * **Kernel:** The `machine.kernel` parameter.
    * **CPU architecture:**  The code uses `machine.arch` and sets architecture-specific flags.
    * **Linking:**  The detection of linker flavor and setting linker flags.
    * **Assembly:** The handling of assemblers (`ml.exe`, `ml64.exe`, `armasm64.exe`).
* **Logical Reasoning:** Look for conditional logic and its implications:
    * The fallback to `env2mfile` if a specific compiler isn't found. Consider the input and output in such a scenario.
    * The MSVC-specific handling based on `machine.os == "windows"` and `machine.toolchain_is_msvc`.
    * The architecture-specific flag settings.
* **User Errors:** Consider common mistakes users might make:
    * Incorrect or missing environment variables.
    * Not having the required toolchains installed.
    * Issues with cross-compilation setup (wrong target architecture).
* **User Path to the Code:** Imagine a developer using Frida and encountering a build issue. They might be debugging their build setup, looking at the build system's configuration, and potentially tracing back to this environment setup code.

**6. Structuring the Answer:**

Organize the findings logically, using clear headings and bullet points for readability. Provide specific code examples where relevant. Explain *why* certain actions are important in the context of reverse engineering or low-level concepts.

**7. Review and Refine:**

Read through the answer to ensure accuracy, clarity, and completeness. Check for any jargon that might need further explanation. Ensure the examples are relevant and illustrate the points effectively. For instance, for logical reasoning, explicitly state the *if* condition and the corresponding *then* action.

This systematic approach, moving from a high-level understanding to detailed analysis and then connecting the findings back to the prompt's questions, helps in generating a comprehensive and accurate answer. The key is to not just describe *what* the code does, but also *why* it does it and how it relates to the broader context of Frida and reverse engineering.
`frida/releng/env_generic.py` 是 Frida 动态 instrumentation 工具中负责生成和管理构建环境配置的模块。它主要为 Frida 的构建系统（通常是 Meson）提供必要的编译器、链接器和其他工具链的信息，并设置相应的编译和链接标志。其目标是支持在各种不同的操作系统和架构上构建 Frida。

下面详细列举了 `env_generic.py` 的功能，并根据你的要求进行了说明：

**功能列表：**

1. **初始化机器配置 ( `init_machine_config` 函数):** 这是该文件的核心功能。它根据目标机器（`machine`）和构建机器（`build_machine`）的规格，以及提供的环境变量、工具链路径等信息，生成 Meson 构建系统所需的配置。
2. **编译器和工具链查找:** 尝试自动检测系统中可用的 C 和 C++ 编译器（通常是 GCC 或 MSVC）。可以根据目标架构的前缀（`triplet`）查找特定架构的编译器。
3. **跨平台编译支持:**  通过区分 `machine` 和 `build_machine`，支持交叉编译。
4. **生成 Meson 机器文件:** 如果无法直接找到编译器，它会调用 `env2mfile` 工具生成一个描述目标机器环境的 Meson 机器文件。
5. **MSVC 工具链支持:** 特别处理 Windows 平台，使用 `winenv` 模块来检测和配置 Microsoft Visual Studio (MSVC) 工具链。
6. **设置编译和链接标志:**  根据目标操作系统、架构和编译器类型，设置合适的 C 和 C++ 编译参数 (`c_args`, `cpp_args`) 和链接参数 (`c_link_args`, `cpp_link_args`)。
7. **处理链接器特性:**  检测链接器的类型 (`detect_linker_flavor`)，并根据不同的链接器（GNU ld, GNU gold, LLD, Apple ld, MSVC link）设置特定的链接选项。
8. **处理静态链接:**  为 GNU 链接器设置静态链接选项 (`-static-libgcc`, `-static-libstdc++`)。
9. **处理符号剥离:**  为 `strip` 工具设置平台相关的参数。
10. **定义常量:**  将生成的编译和链接标志存储在配置的 `constants` 部分，供 Meson 构建系统使用。
11. **查找 GCC 二进制文件 (`resolve_gcc_binaries` 函数):**  用于查找 GCC 工具链中的各种二进制文件（如 `gcc`, `g++`, `ar`, `nm` 等）。
12. **检测链接器类型 (`detect_linker_flavor` 函数):**  通过运行链接器并分析其输出，判断链接器的类型。
13. **异常处理:**  定义了 `CompilerNotFoundError`, `BinaryNotFoundError`, `LinkerDetectionError` 等异常类，用于处理在查找编译器或工具链时可能发生的错误。

**与逆向方法的关系及举例说明：**

* **编译目标二进制代码:**  逆向工程通常涉及分析目标二进制代码。`env_generic.py` 确保 Frida 能够被编译到目标平台，这对于在目标设备上运行 Frida Agent 和 Hook 目标进程至关重要。
    * **举例:** 如果你想在 Android 设备上使用 Frida，`env_generic.py` 需要能够找到 Android NDK 中的编译器，并设置正确的编译标志来生成可以在 Android 上运行的 Frida Agent。
* **理解编译选项的影响:**  了解目标二进制代码是如何编译的对于逆向分析很重要。`env_generic.py` 中设置的编译和链接标志会直接影响生成的可执行文件的特性。
    * **举例:**  `-ffunction-sections` 和 `-fdata-sections` 允许链接器进行更细粒度的代码和数据去重，这在逆向分析时可能会看到不同的内存布局。`-Wl,--gc-sections` 可以移除未使用的代码段，这可能会使逆向工程师分析的代码更精简。
* **交叉编译环境的搭建:**  在很多情况下，逆向工程师需要在与目标平台不同的主机上编译代码。`env_generic.py` 提供的交叉编译支持是完成此类任务的基础。
    * **举例:**  在 Linux 主机上为运行 iOS 的 iPhone 编译 Frida Gadget 需要配置正确的 iOS SDK 和交叉编译工具链。`env_generic.py` 的逻辑会尝试找到这些工具并生成相应的 Meson 配置。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    * **编译器和链接器:**  `env_generic.py` 直接操作编译器（如 GCC, clang, MSVC）和链接器。这些工具负责将源代码转换为机器码和最终的可执行文件，涉及到二进制文件的结构、指令集、符号表等底层概念。
        * **举例:**  代码中通过 `binaries["c"]` 和 `binaries["cpp"]` 配置 C 和 C++ 编译器，这些编译器会将 C/C++ 代码编译成目标架构的机器码。链接器则将编译后的目标文件和库文件链接成最终的可执行文件或动态链接库。
    * **架构特定标志:**  代码中根据不同的 CPU 架构（如 x86, ARM, ARM64 等）设置特定的编译标志 (`-march`, `-mabi` 等)。这些标志直接影响生成的机器码指令。
        * **举例:**  在 ARM 架构上，`-march=armv7-a` 指示编译器生成兼容 ARMv7-A 指令集的代码。
    * **链接器标志:**  代码中设置了与链接过程相关的标志，如 `-Wl,-z,relro` (启用 RELRO 安全机制), `-Wl,-z,noexecstack` (禁用堆栈执行), `-Wl,--gc-sections` (回收未使用的代码段)。这些都涉及到二进制文件的加载和执行安全。
        * **举例:**  `-Wl,-dead_strip` 在 Apple 平台上用于移除未使用的代码，这影响最终二进制文件的大小和内容。

* **Linux:**
    * **GCC 工具链:**  在 Linux 环境下，通常使用 GCC 作为编译器。`resolve_gcc_binaries` 函数专门用于查找 GCC 工具链中的各种工具。
    * **环境变量:**  代码中会读取和设置环境变量（如 `CC`, `CFLAGS`, `LDFLAGS`, `PATH`），这些环境变量在 Linux 构建系统中至关重要。
    * **进程执行:**  代码中使用了 `subprocess` 模块来执行外部命令，例如 `env2mfile` 和编译器、链接器等。这涉及到 Linux 进程的创建和管理。
    * **文件系统操作:**  代码中使用了 `pathlib` 和 `shutil` 模块来进行文件和目录操作，例如查找可执行文件 (`shutil.which`) 和创建临时目录 (`tempfile.TemporaryDirectory`).

* **Android 内核及框架:**
    * **交叉编译到 Android:** 当 `machine.os == "linux"` 且目标架构是 Android 时，此代码会尝试找到 Android NDK 中的交叉编译工具链。
    * **NDK 工具链前缀:** `triplet` 变量通常会包含 Android 架构的前缀（例如 `arm-linux-androideabi-` 或 `aarch64-linux-android-`），用于定位 NDK 中的工具。
    * **链接器行为:**  Android 使用基于 BFD 或 LLD 的链接器，此代码会根据检测到的链接器类型设置相应的链接标志。
    * **系统调用和 ABI:**  虽然此代码本身不直接操作 Android 内核，但它生成的构建环境配置最终会影响到 Frida Agent 的编译，而 Frida Agent 需要与 Android 系统进行交互，涉及到系统调用和应用程序二进制接口 (ABI)。

**逻辑推理及假设输入与输出：**

* **假设输入:**
    * `machine`: `MachineSpec(os='linux', system='linux', subsystem='gnu', kernel='linux', cpu_family='arm', cpu='armv7l', endian='little', pointer_size=4, msvc_platform=None, toolchain_is_msvc=False, triplet='arm-linux-gnueabihf-')` (代表一个 32 位 ARM Linux 系统)
    * `build_machine`: `MachineSpec(os='linux', system='linux', subsystem='gnu', kernel='linux', cpu_family='x86_64', cpu='x86_64', endian='little', pointer_size=8, msvc_platform=None, toolchain_is_msvc=False, triplet=None)` (代表一个 64 位 x86 Linux 构建系统)
    * 假设环境变量中没有设置 `CC` 和 `CFLAGS`。
    * 假设系统中安装了 `arm-linux-gnueabihf-gcc` 等交叉编译工具链。

* **逻辑推理:**
    1. `is_cross_build` 为 True，因为 `machine != build_machine`。
    2. 代码会尝试根据 `machine.triplet` (`arm-linux-gnueabihf-`) 使用 `resolve_gcc_binaries` 函数查找带有 `arm-linux-gnueabihf-` 前缀的 GCC 工具链。
    3. 如果找到了交叉编译工具链，`binaries` 配置项会被更新，包含 `arm-linux-gnueabihf-gcc`, `arm-linux-gnueabihf-g++` 等。
    4. 会设置特定于 ARM 架构的编译标志，例如 `-march=armv7-a`。
    5. 输出的 Meson 配置文件将包含这些交叉编译器的路径和相应的编译/链接标志。

* **假设输出 (Meson 配置文件片段):**
    ```meson
    [binaries]
    c = ['/usr/bin/arm-linux-gnueabihf-gcc', 'c_like_flags']
    cpp = ['/usr/bin/arm-linux-gnueabihf-g++', 'c_like_flags', 'cxx_like_flags']
    ar = ['/usr/bin/arm-linux-gnueabihf-ar']
    # ... 其他工具

    [built-in options]
    c_args = 'c_like_flags'
    cpp_args = 'c_like_flags + cxx_like_flags'
    c_link_args = 'linker_flags'
    cpp_link_args = 'linker_flags + cxx_link_flags'
    b_lundef = 'true'

    [constants]
    common_flags = []
    c_like_flags = ['-march=armv7-a', '-mfpu=vfpv3', '-mfloat-abi=hard', '-ffunction-sections', '-fdata-sections']
    linker_flags = ['-static-libgcc', '-Wl,-z,relro', '-Wl,-z,noexecstack', '-Wl,--gc-sections']
    cxx_like_flags = []
    cxx_link_flags = ['-static-libstdc++']
    ```

**用户或编程常见的使用错误及举例说明：**

1. **缺少必要的工具链:** 用户可能没有安装目标平台的编译器或相关的开发工具包。
    * **举例:** 在尝试为 Android 编译 Frida 时，如果用户没有安装 Android NDK 并正确配置环境变量，`resolve_gcc_binaries` 或 `env2mfile` 可能会失败，抛出 `CompilerNotFoundError` 或 `BinaryNotFoundError` 异常。
2. **环境变量配置错误:** 环境变量（如 `PATH`, `CC`, `CFLAGS`）配置不正确可能导致工具链查找失败或使用错误的编译器。
    * **举例:** 用户可能错误地设置了 `CC` 环境变量指向了一个不兼容目标平台的编译器，导致编译过程出错。
3. **交叉编译配置不当:**  在进行交叉编译时，用户可能没有指定正确的目标架构或工具链前缀。
    * **举例:** 用户可能忘记设置或设置了错误的 `machine.triplet`，导致代码无法找到正确的交叉编译工具。
4. **依赖项缺失:**  构建过程可能依赖于某些库或工具，如果这些依赖项缺失，`env_generic.py` 生成的配置可能不完整或导致后续构建步骤失败。
    * **举例:**  在 Windows 上编译时，如果没有安装 Visual Studio 或相应的构建组件，`winenv` 模块可能无法找到必要的 MSVC 工具。
5. **权限问题:**  在某些情况下，执行编译器或链接器可能需要特定的权限。
    * **举例:** 如果编译器或链接器位于受限目录下，用户可能因为权限不足而无法执行它们。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida:**  用户通常会执行 Frida 项目的构建命令，例如 `python ./meson.py build --prefix=/opt/frida -Dtarget=android_arm64` (或其他类似的 Meson 命令)。
2. **Meson 开始配置构建环境:** Meson 构建系统会读取 `meson.build` 文件，并根据指定的配置（如 `--target`）开始配置构建环境。
3. **调用 Frida 的构建脚本:** Frida 的 `meson.build` 文件会调用 Frida 仓库中的相关脚本来处理特定平台的配置。
4. **执行 `frida/releng/env_generic.py`:** 在配置过程中，为了获取特定目标平台的编译器和构建选项，Frida 的构建脚本会调用 `frida/releng/env_generic.py` 中的 `init_machine_config` 函数。
5. **传递机器规格和环境变量:**  调用 `init_machine_config` 时，会传递 `MachineSpec` 对象（描述目标机器和构建机器的属性）以及当前的环境变量。
6. **`env_generic.py` 执行工具链查找和配置:**  `init_machine_config` 函数会根据传入的参数和系统环境，执行前面描述的各种功能，如查找编译器、检测链接器类型、设置编译和链接标志等。
7. **生成 Meson 机器文件或更新配置:**  `env_generic.py` 的输出会影响 Meson 构建系统的配置，可能生成一个描述目标机器的 `.ini` 文件，或者直接更新 Meson 的内部配置。
8. **后续的编译和链接步骤:**  Meson 构建系统会根据 `env_generic.py` 生成的配置，调用相应的编译器和链接器来编译 Frida 的各个组件。

**作为调试线索:**

如果用户在 Frida 的构建过程中遇到错误，并且怀疑是编译器或链接器配置问题，那么 `frida/releng/env_generic.py` 就是一个重要的调试入口。

* **检查传递给 `init_machine_config` 的参数:**  查看 `MachineSpec` 对象的内容和环境变量，确认目标平台和构建平台的设置是否正确。
* **查看 `env_generic.py` 的输出:**  如果构建过程有详细的日志输出，可以查看 `env_generic.py` 是否成功找到了编译器和链接器，以及设置了哪些编译和链接标志。
* **手动运行 `env2mfile`:**  如果怀疑 `env2mfile` 的行为，可以尝试手动运行它，观察其输出，以确定是否能正确识别目标环境。
* **检查 `resolve_gcc_binaries` 的执行情况:**  如果使用的是 GCC 工具链，可以查看该函数是否成功找到了所需的二进制文件，以及是否有 `CompilerNotFoundError` 异常抛出。
* **分析 `detect_linker_flavor` 的输出:**  如果怀疑链接器类型检测有问题，可以尝试手动运行链接器并分析其输出，与 `detect_linker_flavor` 的逻辑进行对比。

总而言之，`frida/releng/env_generic.py` 是 Frida 构建系统的基础，它负责为不同平台生成正确的构建环境配置。理解其功能和逻辑对于调试 Frida 的构建问题至关重要，尤其是在涉及交叉编译或使用特定工具链的情况下。

Prompt: 
```
这是目录为frida/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from collections import OrderedDict
from configparser import ConfigParser
import locale
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Callable, Optional, Mapping, Sequence

from . import winenv
from .machine_file import strv_to_meson
from .machine_spec import MachineSpec


def init_machine_config(machine: MachineSpec,
                        build_machine: MachineSpec,
                        is_cross_build: bool,
                        environ: dict[str, str],
                        toolchain_prefix: Optional[Path],
                        sdk_prefix: Optional[Path],
                        call_selected_meson: Callable,
                        config: ConfigParser,
                        outpath: list[str],
                        outenv: dict[str, str],
                        outdir: Path):
    allow_undefined_symbols = machine.os == "freebsd"

    options = config["built-in options"]
    options["c_args"] = "c_like_flags"
    options["cpp_args"] = "c_like_flags + cxx_like_flags"
    options["c_link_args"] = "linker_flags"
    options["cpp_link_args"] = "linker_flags + cxx_link_flags"
    options["b_lundef"] = str(not allow_undefined_symbols).lower()

    binaries = config["binaries"]
    cc = None
    common_flags = []
    c_like_flags = []
    linker_flags = []
    cxx_like_flags = []
    cxx_link_flags = []

    triplet = machine.triplet
    if triplet is not None:
        try:
            cc, gcc_binaries = resolve_gcc_binaries(toolprefix=triplet + "-")
            binaries.update(gcc_binaries)
        except CompilerNotFoundError:
            pass

    diagnostics = None
    if cc is None:
        with tempfile.TemporaryDirectory() as raw_prober_dir:
            prober_dir = Path(raw_prober_dir)
            machine_file = prober_dir / "machine.txt"

            argv = [
                "env2mfile",
                "-o", machine_file,
                "--native" if machine == build_machine else "--cross",
            ]

            if machine != build_machine:
                argv += [
                    "--system", machine.system,
                    "--subsystem", machine.subsystem,
                    "--kernel", machine.kernel,
                    "--cpu-family", machine.cpu_family,
                    "--cpu", machine.cpu,
                    "--endian", machine.endian,
                ]

            process = call_selected_meson(argv,
                                          cwd=raw_prober_dir,
                                          env=environ,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT,
                                          encoding=locale.getpreferredencoding())
            if process.returncode == 0:
                mcfg = ConfigParser()
                mcfg.read(machine_file)

                for section in mcfg.sections():
                    copy = config[section] if section in config else OrderedDict()
                    for key, val in mcfg.items(section):
                        if section == "binaries":
                            argv = eval(val.replace("\\", "\\\\"))
                            if not Path(argv[0]).is_absolute():
                                path = shutil.which(argv[0])
                                if path is None:
                                    raise BinaryNotFoundError(f"unable to locate {argv[0]}")
                                argv[0] = path
                            val = strv_to_meson(argv)
                            if key in {"c", "cpp"}:
                                val += " + common_flags"
                        if key in copy and section == "built-in options" and key.endswith("_args"):
                            val = val + " + " + copy[key]
                        copy[key] = val
                    config[section] = copy

                raw_cc = binaries.get("c", None)
                if raw_cc is not None:
                    cc = eval(raw_cc.replace("\\", "\\\\"), None, {"common_flags": []})
            else:
                diagnostics = process.stdout

    linker_flavor = None

    if cc is not None \
            and machine.os == "windows" \
            and machine.toolchain_is_msvc:
        linker_flavor = detect_linker_flavor(cc)
        detected_wrong_toolchain = linker_flavor != "msvc"
        if detected_wrong_toolchain:
            cc = None
            linker_flavor = None

    if cc is None:
        if machine.os == "windows":
            detect_tool_path = lambda name: winenv.detect_msvs_tool_path(machine, build_machine, name, toolchain_prefix)

            cc = [str(detect_tool_path("cl.exe"))]
            lib = [str(detect_tool_path("lib.exe"))]
            link = [str(detect_tool_path("link.exe"))]
            assembler_name = MSVC_ASSEMBLER_NAMES[machine.arch]
            assembler_tool = [str(detect_tool_path(assembler_name + ".exe"))]

            raw_cc = strv_to_meson(cc) + " + common_flags"
            binaries["c"] = raw_cc
            binaries["cpp"] = raw_cc
            binaries["lib"] = strv_to_meson(lib) + " + common_flags"
            binaries["link"] = strv_to_meson(link) + " + common_flags"
            binaries[assembler_name] = strv_to_meson(assembler_tool) + " + common_flags"

            runtime_dirs = winenv.detect_msvs_runtime_path(machine, build_machine, toolchain_prefix)
            outpath.extend(runtime_dirs)

            vs_dir = winenv.detect_msvs_installation_dir(toolchain_prefix)
            outenv["VSINSTALLDIR"] = str(vs_dir) + "\\"
            outenv["VCINSTALLDIR"] = str(vs_dir / "VC") + "\\"
            outenv["Platform"] = machine.msvc_platform
            outenv["INCLUDE"] = ";".join([str(path) for path in winenv.detect_msvs_include_path(toolchain_prefix)])
            outenv["LIB"] = ";".join([str(path) for path in winenv.detect_msvs_library_path(machine, toolchain_prefix)])
        elif machine != build_machine \
                and "CC" not in environ \
                and "CFLAGS" not in environ \
                and machine.os == build_machine.os \
                and machine.os == "linux" \
                and machine.pointer_size == 4 \
                and build_machine.pointer_size == 8:
            try:
                cc, gcc_binaries = resolve_gcc_binaries()
                binaries.update(gcc_binaries)
                common_flags += ["-m32"]
            except CompilerNotFoundError:
                pass

    if cc is None:
        suffix = ":\n" + diagnostics if diagnostics is not None else ""
        raise CompilerNotFoundError("no C compiler found" + suffix)

    if "cpp" not in binaries:
        raise CompilerNotFoundError("no C++ compiler found")

    if linker_flavor is None:
        linker_flavor = detect_linker_flavor(cc)

    strip_binary = binaries.get("strip", None)
    if strip_binary is not None:
        strip_arg = "-Sx" if linker_flavor == "apple" else "--strip-all"
        binaries["strip"] = strip_binary[:-1] + f", '{strip_arg}']"

    if linker_flavor == "msvc":
        for gnu_tool in ["ar", "as", "ld", "nm", "objcopy", "objdump",
                         "ranlib", "readelf", "size", "strip", "windres"]:
            binaries.pop(gnu_tool, None)

        c_like_flags += [
            "/GS-",
            "/Gy",
            "/Zc:inline",
            "/fp:fast",
        ]
        if machine.arch == "x86":
            c_like_flags += ["/arch:SSE2"]

        # Relax C++11 compliance for XP compatibility.
        cxx_like_flags += ["/Zc:threadSafeInit-"]
    else:
        if machine.os == "qnx":
            common_flags += ARCH_COMMON_FLAGS_QNX.get(machine.arch, [])
        else:
            common_flags += ARCH_COMMON_FLAGS_UNIX.get(machine.arch, [])
        c_like_flags += ARCH_C_LIKE_FLAGS_UNIX.get(machine.arch, [])

        c_like_flags += [
            "-ffunction-sections",
            "-fdata-sections",
        ]

        if linker_flavor.startswith("gnu-"):
            linker_flags += ["-static-libgcc"]
            if machine.os != "windows":
                linker_flags += [
                    "-Wl,-z,relro",
                    "-Wl,-z,noexecstack",
                ]
            cxx_link_flags += ["-static-libstdc++"]

        if linker_flavor == "apple":
            linker_flags += ["-Wl,-dead_strip"]
        else:
            linker_flags += ["-Wl,--gc-sections"]
        if linker_flavor == "gnu-gold":
            linker_flags += ["-Wl,--icf=all"]

    constants = config["constants"]
    constants["common_flags"] = strv_to_meson(common_flags)
    constants["c_like_flags"] = strv_to_meson(c_like_flags)
    constants["linker_flags"] = strv_to_meson(linker_flags)
    constants["cxx_like_flags"] = strv_to_meson(cxx_like_flags)
    constants["cxx_link_flags"] = strv_to_meson(cxx_link_flags)


def resolve_gcc_binaries(toolprefix: str = "") -> tuple[list[str], dict[str, str]]:
    cc = None
    binaries = OrderedDict()

    for identifier in GCC_TOOL_IDS:
        name = GCC_TOOL_NAMES.get(identifier, identifier)
        full_name = toolprefix + name

        val = shutil.which(full_name)
        if val is None:
            raise CompilerNotFoundError(f"missing {full_name}")

        # QNX SDP 6.5 gcc-* tools are broken, erroring out with:
        # > sorry - this program has been built without plugin support
        # We detect this and use the tool without the gcc-* prefix.
        if name.startswith("gcc-"):
            p = subprocess.run([val, "--version"], capture_output=True)
            if p.returncode != 0:
                full_name = toolprefix + name[4:]
                val = shutil.which(full_name)
                if val is None:
                    raise CompilerNotFoundError(f"missing {full_name}")

        if identifier == "c":
            cc = [val]

        extra = " + common_flags" if identifier in {"c", "cpp"} else ""

        binaries[identifier] = strv_to_meson([val]) + extra

    return (cc, binaries)


def detect_linker_flavor(cc: list[str]) -> str:
    linker_version = subprocess.run(cc + ["-Wl,--version"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    encoding=locale.getpreferredencoding()).stdout
    if "Microsoft " in linker_version:
        return "msvc"
    if "GNU ld " in linker_version:
        return "gnu-ld"
    if "GNU gold " in linker_version:
        return "gnu-gold"
    if linker_version.startswith("LLD "):
        return "lld"
    if linker_version.startswith("ld: "):
        return "apple"

    excerpt = linker_version.split("\n")[0].rstrip()
    raise LinkerDetectionError(f"unknown linker: '{excerpt}'")


class CompilerNotFoundError(Exception):
    pass


class BinaryNotFoundError(Exception):
    pass


class LinkerDetectionError(Exception):
    pass


ARCH_COMMON_FLAGS_UNIX = {
    "x86": [
        "-march=pentium4",
    ],
    "arm": [
        "-march=armv5t",
    ],
    "armbe8": [
        "-march=armv6",
        "-mbe8",
    ],
    "armhf": [
        "-march=armv7-a",
    ],
    "arm64": [
        "-march=armv8-a",
    ],
    "mips": [
        "-march=mips1",
        "-mfp32",
    ],
    "mipsel": [
        "-march=mips1",
        "-mfp32",
    ],
    "mips64": [
        "-march=mips64r2",
        "-mabi=64",
    ],
    "mips64el": [
        "-march=mips64r2",
        "-mabi=64",
    ],
    "s390x": [
        "-march=z10",
        "-m64",
    ],
}

ARCH_COMMON_FLAGS_QNX = {
    "x86": [
        "-march=i686",
    ],
    "arm": [
        "-march=armv6",
        "-mno-unaligned-access",
    ],
    "armeabi": [
        "-march=armv7-a",
        "-mno-unaligned-access",
    ],
}

ARCH_C_LIKE_FLAGS_UNIX = {
    "x86": [
        "-mfpmath=sse",
        "-mstackrealign",
    ],
}

GCC_TOOL_IDS = [
    "c",
    "cpp",
    "ar",
    "nm",
    "ranlib",
    "strip",
    "readelf",
    "objcopy",
    "objdump",
]

GCC_TOOL_NAMES = {
    "c": "gcc",
    "cpp": "g++",
    "ar": "gcc-ar",
    "nm": "gcc-nm",
    "ranlib": "gcc-ranlib",
}

MSVC_ASSEMBLER_NAMES = {
    "x86": "ml",
    "x86_64": "ml64",
    "arm64": "armasm64",
}

"""

```