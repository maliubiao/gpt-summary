Response:
Let's break down the thought process for analyzing the provided Python code.

**1. Initial Understanding of the File's Purpose:**

The filename `env_generic.py` and the surrounding directory structure `frida/subprojects/frida-clr/releng/` strongly suggest this file is responsible for setting up the build environment for Frida's CLR bridge (likely for .NET integration). The `generic` part hints at platform-agnostic setup, with specifics possibly handled elsewhere or within conditional logic.

**2. Core Function Identification: `init_machine_config`:**

The most prominent function is `init_machine_config`. Its parameters (`machine`, `build_machine`, `is_cross_build`, `environ`, etc.) and the operations within it clearly indicate its role: configuring the build system based on the target and build machines. This becomes the central point of analysis.

**3. Deconstructing `init_machine_config` - Step by Step:**

* **Initial Setup:**  The function starts with basic initializations: `allow_undefined_symbols`, accessing `config` (likely a Meson configuration object), and setting up dictionaries for compiler flags.

* **Triplet Handling:** The code checks for a `triplet` (a standard way to represent architecture/OS). If present, it tries to resolve GCC binaries. This suggests the file supports GCC-based builds.

* **Probing for Compiler (Crucial Logic):** The code then enters a crucial section:  if `cc` (C compiler) is still `None`, it attempts to find one. This involves:
    * Using `meson env2mfile`: This is a key detail. It uses Meson itself to probe the target environment. This is a common technique for cross-compilation scenarios.
    * Handling output: It reads the output of `env2mfile` and updates the configuration.
    * Handling errors:  It captures diagnostics if the probing fails.

* **MSVC Specific Handling:** The code explicitly checks for Windows and MSVC. If the initially detected compiler isn't MSVC on Windows, it resets `cc`. If no compiler is found yet, it attempts to detect MSVC tools (`cl.exe`, `lib.exe`, `link.exe`, etc.). This signifies strong Windows/MSVC support. Environment variables like `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, and `LIB` are set, which are essential for MSVC builds.

* **Cross-Compilation with GCC (Linux/x86):** There's a specific case for cross-compiling from a 64-bit Linux host to a 32-bit Linux target using GCC. This demonstrates awareness of common cross-compilation scenarios.

* **Error Handling:** If no compiler is found after all attempts, it raises `CompilerNotFoundError`.

* **Linker Flavor Detection:** The code attempts to detect the linker flavor (MSVC, GNU ld, Gold, LLD, Apple). This is important for adjusting linker flags.

* **Setting Strip Command:** It configures the `strip` command based on the linker flavor.

* **Applying Compiler/Linker Flags:**  Based on the linker flavor and target OS/architecture, it sets specific compiler and linker flags. This is where platform-specific knowledge is applied. For instance, `/GS-`, `/Gy`, `/Zc:inline`, etc. for MSVC, and `-ffunction-sections`, `-fdata-sections`, `-Wl,-z,relro`, etc. for GCC/GNU ld.

* **Populating Configuration:** Finally, it populates the `config` object with the detected binaries, compiler flags, and linker flags.

* **Helper Functions:**  The functions `resolve_gcc_binaries` and `detect_linker_flavor` are crucial helpers that encapsulate specific tasks.

**4. Identifying Key Concepts and Connections:**

* **Cross-Compilation:** The code heavily deals with cross-compilation, evidenced by the `machine` and `build_machine` parameters, the use of `env2mfile`, and the handling of different toolchains.
* **Build Systems (Meson):**  The interaction with `ConfigParser` and the use of `call_selected_meson` point to the use of the Meson build system.
* **Compiler and Linker Basics:**  The code manipulates compiler flags (C/C++ args) and linker flags, demonstrating a fundamental understanding of the compilation process.
* **Platform-Specific Knowledge:**  The conditional logic for Windows/MSVC and different Linux architectures shows an awareness of platform-specific tools and conventions.
* **Environment Variables:** The manipulation of `environ`, `outpath`, and `outenv` is critical for setting up the build environment correctly.

**5. Answering the Specific Questions:**

With the above understanding, I can now systematically address the prompts:

* **Functionality:**  List the tasks the code performs.
* **Reverse Engineering:**  Think about how Frida interacts with target processes and how this code facilitates building those components.
* **Binary/Kernel/Framework Knowledge:** Identify specific lines of code or logic that relate to these concepts (e.g., linker flags for security, handling of MSVC internals).
* **Logical Reasoning:**  Devise simple input scenarios and trace the expected execution flow and output.
* **User Errors:** Consider what mistakes a user might make that would lead to this code being executed or failing.
* **User Journey:**  Outline the steps a user would take to trigger the execution of this code as part of a Frida build process.

**6. Iteration and Refinement:**

During the analysis, I might go back and forth between different parts of the code. For example, when looking at the MSVC section, I might realize the importance of the `winenv` module and its role in detecting MSVC toolpaths. This iterative process helps to build a more complete and accurate understanding.

By following these steps, I can analyze the code effectively and generate a comprehensive response that addresses all the prompts. The key is to break down the code into smaller, manageable parts, understand the purpose of each part, and then connect those parts to the broader context of the Frida project and software development in general.
好的，让我们详细分析一下 `env_generic.py` 文件的功能和它与逆向工程、底层知识、以及用户操作的关系。

**文件功能概览:**

`env_generic.py` 文件的主要目的是为 Frida 的 CLR (Common Language Runtime，通常指 .NET) 组件构建过程初始化特定机器的构建环境。它负责检测和配置编译器、链接器以及相关的构建工具链，并根据目标平台的特性设置相应的编译和链接选项。

具体来说，该文件执行以下操作：

1. **初始化配置:** 读取构建配置（`config`），并根据目标机器（`machine`）和构建机器（`build_machine`）的属性设置一些基础选项，例如是否允许未定义的符号 (`b_lundef`)。
2. **查找编译器:**  尝试自动查找 C 和 C++ 编译器。它会优先尝试使用目标平台的三元组 (triplet) 前缀来查找 GCC 工具链。
3. **使用 Meson 探测环境:** 如果找不到合适的编译器，它会使用 Meson 构建系统自带的 `env2mfile` 工具来探测目标环境的配置，并将结果写入一个临时文件。然后读取这个文件来获取编译器和其他工具的信息。这个过程可以处理交叉编译的情况。
4. **处理 MSVC (Microsoft Visual C++) 环境:** 如果目标平台是 Windows，并且检测到需要使用 MSVC 工具链，则会调用 `winenv` 模块中的函数来查找 MSVC 的编译器、链接器、库文件路径等。它还会设置必要的环境变量，如 `VSINSTALLDIR` 和 `VCINSTALLDIR`。
5. **处理交叉编译 (Linux x86 -> x86_64):**  对于从 64 位 Linux 构建 32 位 Linux 目标的情况，它会尝试查找并使用 GCC 并添加 `-m32` 编译选项。
6. **检测链接器类型:**  尝试通过运行链接器并分析其版本输出来检测链接器的类型 (如 MSVC, GNU ld, GNU gold, LLD, Apple)。这对于后续设置正确的链接选项非常重要。
7. **设置剥离 (strip) 工具:**  如果找到 `strip` 工具，则根据链接器类型设置剥离选项。
8. **设置编译和链接选项:** 根据目标平台和链接器类型，设置 C 和 C++ 的编译选项 (`c_args`, `cpp_args`) 和链接选项 (`c_link_args`, `cpp_link_args`)。例如，对于 MSVC，它会添加 `/GS-`, `/Gy`, `/Zc:inline` 等选项；对于 GNU 链接器，会添加 `-ffunction-sections`, `-fdata-sections`, `-Wl,-z,relro` 等选项。
9. **定义常量:**  将常用的编译和链接选项组合定义为常量，方便在其他地方引用。
10. **辅助函数:** 包含一些辅助函数，如 `resolve_gcc_binaries` 用于查找 GCC 工具链，`detect_linker_flavor` 用于检测链接器类型。

**与逆向方法的关系及举例:**

`env_generic.py` 文件虽然不直接参与逆向分析的过程，但它为 Frida 的构建提供了必要的环境，而 Frida 本身就是一个强大的动态插桩工具，广泛用于逆向工程。

* **动态插桩依赖编译工具:** Frida 的核心功能需要将 JavaScript 代码注入到目标进程中，这通常涉及到编译一些本地代码 (agent) 或 hook 函数。`env_generic.py` 的功能是确保构建这些组件时能够找到合适的编译器和链接器。
* **平台特定的注入机制:** 不同的操作系统和架构有不同的进程注入机制。该文件根据目标平台配置编译选项和链接选项，确保生成的 Frida 组件与目标平台的运行环境兼容。例如，在 Windows 上需要使用 MSVC 编译器和链接器，并链接相应的 Windows 库。
* **示例:**  假设你想使用 Frida 去 hook 一个运行在 ARM Android 设备上的 .NET 应用程序。Frida 需要在你的开发机器上编译一个 agent，这个 agent 将被注入到目标 Android 设备的进程中。`env_generic.py` 会根据你指定的 Android ARM 目标平台，配置使用合适的 ARM 交叉编译工具链，并设置正确的编译选项，例如指定 ARM 架构 (`-march=armv7-a`)。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制文件处理:** 文件中涉及到 `strip` 工具的使用，这是用于移除二进制文件中的符号信息和调试信息的工具，减小文件大小。不同的链接器有不同的 strip 选项 (`-Sx` for Apple, `--strip-all` for others)。
* **链接器选项:**  代码中设置了各种链接器选项，例如 `-Wl,-z,relro` (启用 RELRO 安全机制，防止 GOT 表覆盖), `-Wl,-z,noexecstack` (禁用堆栈执行，防止栈溢出攻击)。这些选项直接影响生成二进制文件的安全性和运行特性。
* **MSVC 运行时库:** 在处理 Windows 环境时，代码涉及到查找 MSVC 运行时库路径 (`winenv.detect_msvs_runtime_path`)，这些运行时库是 C/C++ 程序在 Windows 上运行所必需的。
* **交叉编译:**  整个文件的逻辑很大程度上围绕着交叉编译展开，即在一个平台上构建在另一个平台上运行的代码。这需要对目标平台的架构、ABI (Application Binary Interface) 有深入的理解。
* **Android 平台:**  虽然代码没有显式地针对 Android 内核进行操作，但它为构建运行在 Android 上的 Frida 组件提供了环境。Android 基于 Linux 内核，但其用户空间框架 (如 ART 虚拟机) 与标准的 Linux 发行版有所不同。Frida 需要能够与这些框架进行交互。

**逻辑推理及假设输入与输出:**

假设我们正在为一个 ARM Linux 目标平台构建 Frida 的 CLR 组件。

**假设输入:**

* `machine`: 一个 `MachineSpec` 对象，描述目标平台为 ARM Linux (例如，`os="linux"`, `arch="arm"`)。
* `build_machine`: 一个 `MachineSpec` 对象，描述构建平台 (例如，x86_64 Linux)。
* `is_cross_build`: `True`，因为目标平台和构建平台不同。
* `environ`: 当前的环境变量。
* `toolchain_prefix`: 可能指向 ARM 交叉编译工具链的路径前缀 (例如，`arm-linux-gnueabihf-`)。
* `config`:  一个 `ConfigParser` 对象，包含初始的构建配置。

**可能的输出 (部分):**

* `binaries["c"]`:  可能被设置为 `['arm-linux-gnueabihf-gcc'] + common_flags`。
* `binaries["cpp"]`: 可能被设置为 `['arm-linux-gnueabihf-g++'] + common_flags + cxx_like_flags`。
* `options["c_args"]`:  包含针对 ARM 架构的编译选项，例如 `-march=armv5t`。
* `options["cpp_args"]`: 包含针对 ARM 架构的 C++ 编译选项。
* `options["c_link_args"]`:  包含针对 ARM 架构的链接选项。
* `options["cpp_link_args"]`: 包含针对 ARM 架构的 C++ 链接选项。

**用户或编程常见的使用错误及举例:**

* **未安装必要的构建工具:** 用户可能没有安装目标平台所需的编译器和链接器。例如，在为 ARM Android 构建时，没有安装 Android NDK 或相应的交叉编译工具链。这会导致 `resolve_gcc_binaries` 抛出 `CompilerNotFoundError`。
* **环境变量配置错误:** 用户可能没有正确设置与构建工具链相关的环境变量，例如 `PATH` 环境变量没有包含编译器所在的目录。这也会导致找不到编译器。
* **交叉编译工具链路径错误:**  如果手动指定了 `toolchain_prefix`，但路径不正确，会导致找不到工具链中的工具。
* **目标平台配置错误:** 在调用构建脚本时，用户可能错误地指定了目标平台的架构或操作系统，导致 `env_generic.py` 尝试查找错误的工具链或设置错误的编译选项。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户尝试构建 Frida 的 CLR 组件:**  用户可能在 Frida 的源代码目录下执行了构建脚本，例如 `meson build --backend=ninja`，并指定了目标平台，例如 `meson configure build -Dtarget=android_arm`。
2. **Meson 构建系统开始配置:** Meson 读取构建配置文件 (通常是 `meson.build`)，并开始配置构建过程。
3. **调用 `env_generic.py`:**  Meson 会根据目标平台的配置，调用 `frida/subprojects/frida-clr/releng/env_generic.py` 脚本来初始化特定于该平台的构建环境。
4. **脚本执行并尝试查找编译器:**  `env_generic.py` 脚本会按照其逻辑，尝试查找目标平台的编译器。如果设置了 `toolchain_prefix`，它会首先尝试使用该前缀查找。
5. **可能的错误点:**
    * **找不到编译器:** 如果没有安装交叉编译工具链或者 `toolchain_prefix` 配置错误，`resolve_gcc_binaries` 或 Meson 的 `env2mfile` 可能会失败，抛出 `CompilerNotFoundError` 或 `BinaryNotFoundError`。
    * **链接器检测失败:**  如果链接器的输出格式不被脚本识别，`detect_linker_flavor` 可能会抛出 `LinkerDetectionError`。
    * **环境变量问题:** 如果相关的环境变量没有正确设置，可能会导致找不到构建工具。

**作为调试线索:**

当构建过程出错时，可以按照以下步骤进行调试：

1. **查看构建日志:**  Meson 会输出详细的构建日志，其中包含了执行的命令和输出信息。查找与 `env_generic.py` 相关的日志，看是否有关于查找编译器、链接器或设置编译选项的错误信息。
2. **检查环境变量:** 确认构建过程中使用的环境变量是否正确设置，特别是与工具链相关的 `PATH` 变量。
3. **检查目标平台配置:** 确认在执行构建命令时指定的目标平台是否正确。
4. **检查交叉编译工具链:** 如果是交叉编译，确认交叉编译工具链已正确安装，并且 `toolchain_prefix` 指向正确的路径。
5. **手动执行相关命令:** 可以尝试手动执行 `env_generic.py` 中涉及的命令，例如 `arm-linux-gnueabihf-gcc --version` 或 `ld.bfd --version`，来检查工具链是否可用。
6. **阅读错误信息:**  仔细阅读 Python 抛出的异常信息，例如 `CompilerNotFoundError` 或 `LinkerDetectionError`，这些信息通常会提供关于错误原因的线索。

总而言之，`env_generic.py` 是 Frida 构建系统中的一个关键组件，它负责根据目标平台的特性配置构建环境，确保 Frida 的 CLR 组件能够正确编译和链接。理解其功能和涉及的底层知识对于解决 Frida 构建过程中可能出现的问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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