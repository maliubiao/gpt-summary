Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality, relate it to reverse engineering, identify low-level and kernel aspects, explore logical reasoning, point out potential user errors, and trace how a user might reach this code.

**1. Initial Skim and Keyword Spotting:**

First, I'd quickly read through the code, looking for familiar terms and patterns. Keywords like "compiler," "linker," "machine," "OS," "architecture," "flags," "environment," "subprocess," "path," "binary," and "toolchain" immediately jump out. This suggests the script is heavily involved in setting up a build environment, especially concerning cross-compilation.

**2. Deeper Dive into Function `init_machine_config`:**

This function is the core of the script. I'd analyze it section by section:

* **Initial Setup:** It takes various `MachineSpec` objects (likely describing target and build architectures), environment variables, toolchain/SDK paths, and a Meson configuration object. The `allow_undefined_symbols` line hints at platform-specific behavior (FreeBSD).
* **Options:**  It manipulates Meson options related to compiler arguments and linker behavior (`b_lundef`). This directly relates to how code is compiled and linked, crucial for reverse engineers who often need to understand these processes.
* **Binaries:** This section is key. It tries to find C/C++ compilers and other essential build tools. The logic handles cases where a specific toolchain prefix is provided. The fallback mechanism using `env2mfile` to probe the environment is interesting and suggests a way to automatically detect system configurations.
* **Windows Specific Logic:** The code has distinct handling for Windows, particularly with MSVC. It uses `winenv` module functions to locate compiler, linker, assembler, and necessary environment variables. This highlights the platform-specific nature of build systems.
* **GCC/Other Toolchain Handling:**  If a specific compiler isn't found (especially on non-Windows), it attempts to resolve GCC binaries based on a provided prefix or by searching the system path. There's a workaround for a QNX-specific GCC issue.
* **Linker Flavor Detection:**  The script attempts to identify the linker being used (MSVC, GNU ld, Gold, LLD, Apple's ld). This is important because linker flags and behavior differ significantly.
* **Setting Compiler/Linker Flags:** Based on the detected linker flavor and target architecture, the script sets various compiler and linker flags (e.g., `-static-libgcc`, `-Wl,-z,relro`, `/GS-`). These flags have a direct impact on the security and behavior of the compiled binary, which is relevant for reverse engineering.
* **Constants:**  Finally, it stores the collected compiler and linker flags into the Meson configuration.

**3. Analyzing Helper Functions:**

* **`resolve_gcc_binaries`:** This function specifically locates GCC toolchain binaries, optionally with a prefix. The QNX workaround is a notable detail.
* **`detect_linker_flavor`:** This function executes the linker with `--version` to identify its type. This is a common technique to introspect tools.

**4. Identifying Connections to Reverse Engineering:**

At this stage, the relationship to reverse engineering becomes clearer. The script configures the build process, directly influencing the characteristics of the resulting binary. Understanding compiler flags, linker options, and the overall toolchain is vital for reverse engineers.

**5. Identifying Low-Level/Kernel Aspects:**

The script deals with:

* **Target Architectures:** It handles various CPU architectures (x86, ARM, MIPS, etc.) and sets architecture-specific flags.
* **Operating Systems:** It has specific logic for Windows, Linux, FreeBSD, and QNX.
* **System Calls (Indirectly):** While not directly making syscalls, the choice of compiler flags (like position-independent code) influences how the compiled code interacts with the operating system and kernel.
* **Binary Structure (Indirectly):** Linker flags like `-z,relro` and `--gc-sections` directly affect the layout and security features of the generated executable.

**6. Exploring Logical Reasoning:**

The script uses conditional logic to handle different scenarios: OS, architecture, presence of specific tools, and linker flavors. The `if cc is None:` blocks demonstrate fallback mechanisms. The QNX GCC workaround is a specific example of addressing a known issue.

**7. Considering User Errors:**

The exceptions (`CompilerNotFoundError`, `BinaryNotFoundError`, `LinkerDetectionError`) indicate potential user errors, such as not having the required build tools installed or configured correctly.

**8. Tracing User Actions:**

To understand how a user gets here, I considered the broader context of the Frida build process. The script is part of the build system, so the user is likely trying to build Frida (or a component of it, like the Python bindings). The steps would involve:

* Cloning the Frida repository.
* Installing build dependencies (including Meson and likely a C/C++ compiler).
* Running the Meson configuration step, which would invoke this Python script to set up the build environment based on the detected or specified target platform.

**Self-Correction/Refinement During the Process:**

Initially, I might have focused too much on the individual lines of code. However, recognizing the overall purpose – setting up a build environment – helped to contextualize the individual parts. Also, I initially might have missed some of the more subtle connections to reverse engineering. Thinking about *why* certain compiler flags are used and their impact on the final binary helped to make these connections more explicit. The QNX workaround was a detail that required careful attention to understand its significance.
This Python script, `env_generic.py`, is a crucial part of Frida's build system, specifically for setting up the build environment when targeting a generic platform (i.e., not specifically Android or iOS). It focuses on detecting and configuring the necessary tools and flags for cross-compilation. Here's a breakdown of its functionalities:

**Functionalities:**

1. **Machine Configuration Initialization:** The primary function `init_machine_config` takes information about the target machine (`machine`), the build machine (`build_machine`), and other build-related settings to configure the build environment.

2. **Compiler Detection:** It attempts to automatically detect the C and C++ compilers available for the target platform.
   - It first tries to use a compiler prefixed with the target triplet (e.g., `arm-linux-gnueabi-gcc`).
   - If that fails, it uses Meson's `env2mfile` tool to probe the environment and extract compiler information.
   - As a last resort (especially for Windows), it attempts to locate MSVC tools.

3. **Linker Detection:** After finding a compiler, it attempts to determine the "flavor" of the linker being used (GNU ld, GNU Gold, LLD, Apple's ld, or MSVC). This is crucial for setting appropriate linker flags.

4. **Setting Compiler and Linker Flags:** Based on the target operating system, architecture, and linker flavor, it sets essential compiler and linker flags.
   - This includes architecture-specific flags (e.g., `-march`, `-mabi`).
   - Flags for function and data section separation (`-ffunction-sections`, `-fdata-sections`).
   - Flags related to security (e.g., `-Wl,-z,relro`, `-Wl,-z,noexecstack`).
   - Flags specific to the linker (e.g., `-Wl,--gc-sections`).
   - Flags for MSVC compatibility.

5. **Handling Cross-Compilation:** The script explicitly handles cross-compilation scenarios where the target machine is different from the build machine. It uses Meson's cross-compilation features and sets up the necessary environment.

6. **Windows Specific Configuration:** It includes specific logic for configuring the build environment on Windows, including detecting and setting up MSVC toolchain paths and environment variables.

7. **Tool Path Resolution:** It uses `shutil.which` to locate executable tools and `winenv` (another module likely within the Frida project) to detect MSVC tool paths.

8. **Error Handling:** It defines custom exception classes (`CompilerNotFoundError`, `BinaryNotFoundError`, `LinkerDetectionError`) to handle cases where essential build tools cannot be found.

9. **Meson Integration:** The script interacts heavily with Meson, a build system. It updates the `config` (which is a `ConfigParser` object likely representing a Meson machine file) with the detected compiler, linker, and flags.

**Relationship to Reverse Engineering:**

This script is deeply intertwined with reverse engineering because the choices made here directly influence the characteristics of the compiled binaries that a reverse engineer might analyze.

* **Compiler and Linker Flags:** The flags set by this script determine how the code is compiled and linked. For example:
    * `-ffunction-sections` and `-fdata-sections`: These flags can help in identifying individual functions and data sections in the compiled binary, which is useful for code analysis.
    * `-Wl,-z,relro` and `-Wl,-z,noexecstack`: These security flags, when enabled, make it harder for exploits to succeed. A reverse engineer needs to know if these are active to understand the security posture of the target.
    * Architecture-specific flags (`-march`): These determine the instruction set used, which is fundamental for understanding the binary's execution flow.
    * MSVC flags (`/GS-`, `/Gy`, `/Zc:inline`): These influence compiler optimizations and security features specific to the MSVC toolchain.
* **Static vs. Dynamic Linking:** The script sets flags like `-static-libgcc` and `-static-libstdc++`, which influence whether the resulting binary statically or dynamically links against standard libraries. This affects the dependencies a reverse engineer needs to consider.
* **Stripping Symbols:** The script uses the `strip` tool to remove debugging symbols from the final binary. Reverse engineers often deal with stripped binaries, and knowing how this process is configured can be relevant.

**Example:** If the script detects a GNU linker and sets the `-Wl,--gc-sections` flag, it means the linker will remove unused code and data sections. A reverse engineer analyzing such a binary might encounter a smaller, more optimized binary, making static analysis slightly more challenging as some code might be absent.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

The script touches upon these areas:

* **Binary Bottom:** The entire purpose of this script is to prepare for the compilation and linking process, which ultimately produces the binary code that runs on the processor. It deals with the fundamental tools needed to translate source code into executable form.
* **Linux:** The script includes specific logic for Linux, particularly in the GCC detection and the setting of linker flags common on Linux systems (e.g., `-Wl,-z,relro`).
* **Android Kernel & Framework (Indirectly):** While this specific file is for the "generic" environment, Frida is heavily used for reverse engineering on Android. The concepts of cross-compilation and setting up toolchains are directly applicable to building Frida components that run on Android. The flags and tools used here might have parallels in the Android NDK (Native Development Kit). The script's ability to handle different architectures (like ARM) is relevant for Android development.
* **Windows:** The extensive handling of MSVC toolchains demonstrates knowledge of the Windows binary format and the specific compilers and linkers used on that platform.

**Logical Reasoning (Hypothetical Input & Output):**

**Assumption:**  The target machine is an ARM Linux system, and the build machine is an x86_64 Linux system. The necessary ARM cross-compilation toolchain (e.g., `arm-linux-gnueabi-gcc`) is installed and in the system's PATH.

**Hypothetical Input (relevant parts):**

* `machine.triplet`: "arm-linux-gnueabi"
* `machine.os`: "linux"
* `machine.arch`: "arm"
* `build_machine.os`: "linux"
* `build_machine.arch`: "x86_64"

**Hypothetical Output (relevant parts of the `config` object):**

* `binaries["c"]`: `['arm-linux-gnueabi-gcc', '+', 'common_flags']`
* `binaries["cpp"]`: `['arm-linux-gnueabi-g++', '+', 'common_flags']`
* `binaries["ar"]`: `['arm-linux-gnueabi-ar']`
* `options["c_args"]`: "c_like_flags"
* `options["cpp_args"]`: "c_like_flags + cxx_like_flags"
* `constants["common_flags"]`: `['-march=armv5t']`  (This is based on `ARCH_COMMON_FLAGS_UNIX["arm"]`)
* `constants["c_like_flags"]`: `['-ffunction-sections', '-fdata-sections']` (and potentially architecture-specific flags from `ARCH_C_LIKE_FLAGS_UNIX`)
* `constants["linker_flags"]`: `['-static-libgcc', '-Wl,-z,relro', '-Wl,-z,noexecstack', '-Wl,--gc-sections']` (assuming a GNU-like linker is detected)

**User/Programming Common Usage Errors:**

1. **Missing Toolchain:** The most common error is not having the correct cross-compilation toolchain installed for the target platform. For example, trying to build for ARM without `arm-linux-gnueabi-gcc` being in the PATH. This would likely result in a `CompilerNotFoundError`.
2. **Incorrect Environment Variables:** If environment variables like `CC` or `CXX` are set incorrectly and point to the wrong compilers, this script might pick up the wrong tools, leading to build failures or binaries that don't work as expected.
3. **Conflicting Configurations:**  Manually trying to override compiler or linker flags in a way that conflicts with the logic in this script can lead to unpredictable build behavior.
4. **Windows Specific Issues:** On Windows, not having the Visual Studio build tools installed or the environment variables (like `VSINSTALLDIR`) not being set correctly will cause the MSVC detection logic to fail.
5. **Incorrect Meson Setup:**  If Meson itself is not configured correctly or if the machine file provided to Meson is wrong, this script will operate on incorrect input, leading to misconfiguration.

**User Operation Steps to Reach This Point (Debugging Clue):**

1. **User Clones Frida Repository:** A developer or reverse engineer downloads the Frida source code.
2. **User Navigates to Frida Directory:** They open a terminal and go to the root directory of the Frida project.
3. **User Initiates the Build Process:** Typically, this involves running a command to configure the build using Meson. A common command is:
   ```bash
   python3 meson.py <build_directory>
   ```
   or if cross-compiling:
   ```bash
   python3 meson.py --cross-file <path_to_cross_file> <build_directory>
   ```
4. **Meson Invokes `env_generic.py`:**  During the configuration phase, Meson needs to determine the build environment for the target platform. If a "generic" target is being used (or if the specific OS/platform isn't handled by more specialized environment setup scripts), Meson will execute `frida/subprojects/frida-python/releng/env_generic.py`.
5. **Script Executes and Modifies Meson Configuration:** The `init_machine_config` function in this script is called with information about the target and build machines. It then proceeds with the compiler and linker detection and flag setting logic, modifying the Meson configuration files in the `<build_directory>`.
6. **Debugging Scenario:** If the build fails, a developer might investigate the Meson configuration files or the output from the Meson configuration step. Errors related to compiler or linker detection could lead them to examine the logic within `env_generic.py` to understand why the tools were not found or why specific flags were set. They might add print statements within this script or use a debugger to trace its execution.

In essence, `env_generic.py` is a foundational piece of Frida's build system, ensuring that the necessary tools and settings are correctly configured for compiling Frida components across various platforms. Its logic directly impacts the characteristics of the resulting binaries, making it a relevant area for reverse engineers to understand.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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