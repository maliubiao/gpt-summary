Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The request asks for a functional breakdown of a Frida build script (`env_generic.py`), focusing on its relationship to reverse engineering, low-level details, logical reasoning, potential errors, and how a user might end up invoking it.

**2. Initial Scan and Keyword Spotting:**

I'd first quickly scan the code, looking for familiar keywords and patterns:

* **Imports:** `collections`, `configparser`, `locale`, `pathlib`, `shutil`, `subprocess`, `tempfile`, `typing`. These suggest file system operations, configuration handling, external process execution, and type hinting.
* **Function Definition:** `init_machine_config`. This is likely the core function and the starting point for detailed analysis.
* **Class Definitions:** `CompilerNotFoundError`, `BinaryNotFoundError`, `LinkerDetectionError`. These indicate error handling related to build tools.
* **Constants:**  `ARCH_COMMON_FLAGS_UNIX`, `ARCH_COMMON_FLAGS_QNX`, `ARCH_C_LIKE_FLAGS_UNIX`, `GCC_TOOL_IDS`, `GCC_TOOL_NAMES`, `MSVC_ASSEMBLER_NAMES`. These hint at platform-specific configurations and toolchain details.
* **Function Calls:**  `resolve_gcc_binaries`, `detect_linker_flavor`, `winenv.*`, `call_selected_meson`. These indicate dependencies on other functions and potentially external modules.

**3. Deeper Dive into `init_machine_config`:**

This function appears to be the heart of the script. I'd analyze its parameters and logic step by step:

* **Parameters:**  `machine`, `build_machine`, `is_cross_build`, `environ`, `toolchain_prefix`, `sdk_prefix`, `call_selected_meson`, `config`, `outpath`, `outenv`, `outdir`. These suggest it configures the build environment based on target and host machine information. The presence of `call_selected_meson` is a strong indicator this script is part of a larger Meson build system.
* **Initial Setup:**  Setting `allow_undefined_symbols`, initializing `options`, `binaries`, and flag lists.
* **Toolchain Detection (GCC):** The code tries to resolve GCC binaries based on the target triplet. This is clearly related to cross-compilation.
* **Fallback Mechanism (env2mfile):** If GCC isn't found directly, it uses a `env2mfile` tool (presumably part of Meson) to generate a machine configuration file. This involves executing an external process.
* **Toolchain Detection (MSVC):**  Specific handling for Windows and MSVC, using functions from the `winenv` module. This involves detecting the locations of MSVC tools.
* **Compiler Selection Logic:**  There's a clear preference for GCC, but it falls back to MSVC on Windows or tries to find a 32-bit GCC on a 64-bit Linux host for cross-compilation.
* **Flag and Option Setting:** The code sets various compiler and linker flags based on the target OS, architecture, and detected linker flavor.
* **Constants Update:** Finally, it updates the `constants` section of the configuration with the collected flags.

**4. Connecting to the Request's Points:**

* **Functionality:** Summarize the purpose of `init_machine_config` and the overall script.
* **Reverse Engineering:**  Think about *how* this script aids reverse engineering. The ability to build tools that *do* reverse engineering is the key. Frida itself is a dynamic instrumentation tool used for reverse engineering. This script configures the build for different targets, allowing Frida to be deployed on various platforms.
* **Binary/Low-Level:**  Identify the concepts directly related to the lower levels of computing: compiler flags (architecture, ABI, linking), assembler selection, detection of linker flavor, handling of different operating systems (Windows, Linux, Android, QNX, FreeBSD).
* **Logical Reasoning:** Look for conditional logic (e.g., `if machine.os == "windows"`, `if cc is None`). Consider the *inputs* to these conditions and the *outputs* (different configurations). The fallback mechanisms also represent logical reasoning.
* **User Errors:**  Imagine common mistakes a developer might make when trying to build Frida (e.g., missing compilers, incorrect environment variables).
* **User Path:** Trace back how a user's actions might lead to this script being executed (e.g., running a build script that uses Meson).

**5. Structuring the Answer:**

Organize the findings according to the request's categories. Use clear headings and bullet points for readability. Provide specific code examples where relevant.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focus too much on the individual lines of code.
* **Correction:** Step back and focus on the *purpose* of each section of the code. What problem is it trying to solve?
* **Initial thought:**  Overlook the connection to Frida.
* **Correction:** Realize that this script is part of Frida's build process and directly contributes to its functionality as a reverse engineering tool.
* **Initial thought:** Not explicitly linking the code to specific OS/kernel concepts.
* **Correction:**  Highlight the sections dealing with Windows (MSVC), Linux (GCC, linker flags), and even mentions of Android and QNX, explaining how these relate to their respective kernels and frameworks.
* **Initial thought:**  Not giving concrete examples for user errors.
* **Correction:** Brainstorm common build-related issues developers face (missing compilers, wrong environment).

By following these steps, including initial scanning, detailed analysis of the core function, connecting the code to the prompt's requirements, and structuring the answer effectively, a comprehensive and accurate response can be generated.
这是一个Frida动态 instrumentation工具的构建系统中负责生成特定构建环境配置文件的Python脚本。它主要用于为不同目标平台（操作系统、架构）配置编译环境，以便Frida的核心组件 `frida-core` 能够在这些平台上被正确编译和链接。

以下是该脚本的功能列表，并结合你提出的几个方面进行说明：

**主要功能:**

1. **初始化构建环境配置 (Core Function):** `init_machine_config` 函数是脚本的核心。它接收目标机器和构建机器的规范 (MachineSpec)、交叉编译状态、环境变量、工具链/SDK路径等信息，并生成用于 Meson 构建系统的配置文件。

2. **自动检测编译器:** 脚本尝试自动检测目标平台上可用的 C 和 C++ 编译器。
    * **GCC 检测:**  优先尝试通过 `resolve_gcc_binaries` 函数，根据目标平台的 triplet 前缀 (例如 `arm-linux-gnueabi-`) 查找 GCC 工具链 (如 `gcc`, `g++`, `ar` 等)。
    * **MSVC 检测:** 如果目标平台是 Windows，则使用 `winenv` 模块中的函数来定位 MSVC 的编译器 (`cl.exe`)、链接器 (`link.exe`)、库管理器 (`lib.exe`) 和汇编器 (`ml.exe` 或 `ml64.exe`)。

3. **生成 Meson 配置文件:**  脚本修改并填充 `ConfigParser` 对象 `config`，该对象最终会被写入 Meson 可以理解的配置文件。它设置了以下关键信息：
    * **编译器路径:**  `binaries` 部分存储了检测到的 C 和 C++ 编译器的路径。
    * **编译/链接参数:**  `built-in options` 部分定义了 `c_args`, `cpp_args`, `c_link_args`, `cpp_link_args` 等选项，用于传递编译和链接标志。
    * **链接器行为:**  `b_lundef` 选项控制是否允许未定义的符号链接，这在不同的操作系统上可能有所不同。
    * **通用常量:** `constants` 部分存储了一些通用的编译标志。

4. **处理交叉编译:** 脚本能够处理交叉编译的情况，即在一种平台上构建运行在另一种平台上的代码。它通过比较 `machine` 和 `build_machine` 来判断是否是交叉编译，并采取相应的措施，例如使用带 triplet 前缀的工具链。

5. **处理不同操作系统和架构的差异:**  脚本针对不同的操作系统（如 Linux, Windows, FreeBSD, QNX）和 CPU 架构（如 x86, ARM, ARM64, MIPS）设置不同的编译和链接标志。

6. **检测链接器类型:** `detect_linker_flavor` 函数尝试通过运行链接器并分析其输出，来判断链接器的类型 (如 MSVC, GNU ld, GNU gold, LLVM LLD, Apple ld)。这有助于选择合适的链接器标志。

**与逆向方法的关系及举例说明:**

该脚本本身不直接执行逆向操作，但它是构建 Frida 工具链的关键部分。Frida 作为一个动态 instrumentation 工具，被广泛用于逆向工程。该脚本确保 Frida 能够在目标平台上正确编译，从而让逆向工程师能够使用 Frida 的功能，例如：

* **代码注入:** Frida 允许将 JavaScript 代码注入到目标进程中，从而修改其行为。该脚本保证了 Frida 核心组件能够被编译到目标平台，是代码注入的基础。
* **函数 Hooking:** Frida 可以拦截和修改目标进程中函数的调用。正确的编译环境是实现 hooking 功能的前提。
* **内存分析:** Frida 可以读取和修改目标进程的内存。该脚本确保了 Frida 核心能够访问和操作目标平台的内存。

**举例:**

假设逆向工程师需要在 Android 设备上使用 Frida。这个脚本就需要正确配置 Android 平台的编译环境，包括：

* 检测 Android NDK 中的编译器（例如 `arm-linux-androideabi-gcc` 或 `aarch64-linux-android-gcc`）。
* 设置针对 ARM 或 ARM64 架构的编译标志。
* 链接 Android 系统的库。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

1. **二进制底层:**
    * **编译器标志:** 脚本中设置的 `-march`, `-mabi`, `-mfpmath` 等编译器标志直接影响生成的二进制代码的架构、ABI (Application Binary Interface) 和浮点运算方式。例如，`-march=armv7-a` 指定了 ARMv7-A 架构的指令集。
    * **链接器标志:**  `-Wl,-z,relro`, `-Wl,-z,noexecstack` 等链接器标志涉及到二进制文件的安全特性，例如地址空间布局随机化 (ASLR) 和防止执行栈代码。
    * **汇编器:**  在 Windows 上使用 MSVC 时，会根据架构选择不同的汇编器 (`ml.exe` 或 `ml64.exe`)，这些汇编器将汇编代码转换为机器码。

2. **Linux 内核:**
    * **系统调用约定:**  不同的 Linux 架构有不同的系统调用约定，编译器需要生成符合这些约定的代码。脚本中设置的架构相关的标志会影响这部分。
    * **动态链接:** Frida 经常需要与目标进程的库进行动态链接。脚本生成的配置需要确保链接器能够找到并正确链接这些库。

3. **Android 内核及框架:**
    * **NDK (Native Development Kit):**  在 Android 平台上构建 Frida 需要使用 NDK 提供的工具链。脚本会尝试检测 NDK 中的编译器。
    * **Android ABI:**  Android 支持多种 CPU 架构，每种架构有其对应的 ABI。脚本需要根据目标 Android 设备的架构选择正确的编译器和编译标志。例如，构建用于 ARM 设备的 Frida 需要使用 `arm-linux-androideabi-` 前缀的工具链。
    * **Android 系统库:** Frida 需要与 Android 系统的一些库进行交互，例如 `libc.so`, `libdl.so` 等。构建配置需要确保链接器能够找到这些库。

**涉及逻辑推理及假设输入与输出:**

脚本中包含一些逻辑推理，例如：

* **假设输入:** `machine.os` 为 "windows" 且 `machine.toolchain_is_msvc` 为 True。
* **逻辑推理:** 则认为目标平台是使用 MSVC 工具链的 Windows，并执行相应的 MSVC 工具链检测和配置逻辑。
* **输出:**  `binaries["c"]` 将被设置为 `cl.exe` 的路径，并且会设置相应的 MSVC 编译选项，如 `/GS-`, `/Gy` 等。

* **假设输入:** 脚本在尝试检测 GCC 工具链时，`shutil.which(toolprefix + name)` 返回 None。
* **逻辑推理:** 则认为当前环境下没有找到带特定前缀的 GCC 工具，可能会尝试其他方式或抛出 `CompilerNotFoundError` 异常。
* **输出:** 如果最终没有找到编译器，则会抛出异常，导致构建失败。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **缺少必要的构建工具:**
    * **错误:** 用户在没有安装 GCC 或 MSVC 构建工具链的环境中尝试构建 Frida。
    * **后果:** 脚本无法找到编译器，抛出 `CompilerNotFoundError` 异常，导致构建失败。
    * **用户操作:** 用户可能直接运行了构建脚本，但没有事先安装必要的依赖。

2. **环境变量配置错误:**
    * **错误:**  在交叉编译时，用户没有正确设置环境变量，例如 `PATH` 中没有包含目标平台的工具链路径，或者 `ANDROID_NDK_HOME` 没有指向正确的 NDK 目录。
    * **后果:** 脚本可能无法找到正确的编译器，或者找到错误的编译器，导致构建出的 Frida 版本无法在目标平台上运行。
    * **用户操作:** 用户可能手动设置了环境变量，但设置了错误的路径。

3. **目标平台信息不正确:**
    * **错误:**  用户提供的目标平台 `MachineSpec` 信息不准确，例如指定了错误的操作系统或架构。
    * **后果:** 脚本可能会选择错误的编译器或编译标志，导致构建出的 Frida 版本与目标平台不兼容。
    * **用户操作:**  在调用构建脚本时，用户传递了错误的参数或配置文件。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:** 用户通常会从 Frida 的源代码仓库开始，并按照官方文档或 README 中的说明进行构建。这通常涉及到运行一个顶层的构建脚本（例如 `meson.py` 或 `build.sh`）。

2. **构建系统调用 Meson:** Frida 的构建系统通常使用 Meson。顶层的构建脚本会调用 Meson 来配置和执行构建。

3. **Meson 读取构建定义:** Meson 会读取 `meson.build` 文件，该文件定义了构建过程、依赖项和配置选项。

4. **Meson 调用 `env_generic.py`:**  在配置阶段，Meson 需要为不同的目标平台生成构建环境配置文件。当需要构建 `frida-core` 时，Meson 会调用 `frida/subprojects/frida-core/releng/env_generic.py` 脚本，并将目标平台和构建平台的信息作为参数传递给 `init_machine_config` 函数。

5. **`init_machine_config` 执行:**  `env_generic.py` 脚本根据传入的参数，执行编译器检测、标志设置等操作，并将结果写入 Meson 可以理解的配置文件。

**调试线索:**

当构建过程中出现问题时，可以按照以下线索进行调试：

* **检查 Meson 的输出:** Meson 的输出通常会显示配置过程中的详细信息，包括调用的脚本和执行的命令。可以查看 Meson 的输出，确认 `env_generic.py` 是否被调用，以及传递给它的参数是否正确。
* **查看 `env_generic.py` 的日志或输出:**  可以在 `env_generic.py` 中添加 `print` 语句来输出中间变量的值，例如检测到的编译器路径、设置的编译标志等，以便了解脚本的执行过程。
* **检查环境变量:** 确认构建环境中相关的环境变量是否正确设置，例如 `PATH`, `ANDROID_NDK_HOME` 等。
* **手动执行编译器检测命令:** 可以尝试手动执行脚本中用于检测编译器的命令（例如 `gcc --version` 或 `cl.exe`），以确认编译器是否存在并且可以正常运行。
* **查看 Meson 生成的配置文件:**  Meson 通常会将生成的配置文件保存在构建目录中，可以查看这些文件，确认 `env_generic.py` 生成的配置是否符合预期。

总而言之，`frida/subprojects/frida-core/releng/env_generic.py` 是 Frida 构建系统中一个至关重要的组件，它负责根据目标平台的特性配置编译环境，确保 Frida 能够成功构建并在目标平台上运行，从而为逆向工程师提供强大的动态 instrumentation 能力。 理解其工作原理有助于诊断构建问题，并深入了解 Frida 的构建过程。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```