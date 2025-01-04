Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to understand the overall purpose of the script. The filename `env_generic.py` and the surrounding directory structure (`frida/subprojects/frida-qml/releng/`) strongly suggest it's part of the Frida build system, specifically for setting up the build environment for different target platforms. The `releng` part likely means "release engineering," indicating it's about managing the build and release process. The `env_generic` suggests it's a general, platform-agnostic part of environment setup.

**2. High-Level Structure and Key Functions:**

Next, I'd scan the script for its main components:

* **Imports:** These give clues about what the script interacts with (file system, subprocesses, configuration files, etc.).
* **Function Definitions:**  The presence of `init_machine_config`, `resolve_gcc_binaries`, and `detect_linker_flavor` immediately points to the core functionalities.
* **Constants/Data Structures:**  Things like `ARCH_COMMON_FLAGS_UNIX`, `GCC_TOOL_IDS`, and `MSVC_ASSEMBLER_NAMES` provide specific configuration data.
* **Exception Classes:** Custom exceptions like `CompilerNotFoundError` indicate error handling strategies.

**3. Deep Dive into Key Functions:**

Now, focus on the key functions, particularly `init_machine_config`:

* **Parameters:** Understand what inputs this function takes (`MachineSpec`, `build_machine`, `environ`, etc.). This reveals what information is needed to configure the environment.
* **Core Logic:**  Trace the steps within the function:
    * **Initial Setup:** Setting `allow_undefined_symbols` based on the OS.
    * **Options Configuration:**  Mapping generic options like `c_args` to specific flags.
    * **Compiler Detection (Crucial):** The logic for finding the C/C++ compiler is central. Notice the attempts to find GCC based on a triplet, and the fallback to using `env2mfile` and then potentially MSVC detection on Windows.
    * **Linker Flavor Detection:**  The script needs to know which linker is being used (GNU ld, Gold, LLD, Apple's ld, or MSVC).
    * **Flag Setting:**  Different sets of compiler and linker flags are applied based on the target architecture, OS, and linker flavor.
    * **Binary Tool Configuration:** The `binaries` dictionary is populated with paths to essential tools (compiler, linker, assembler, etc.).
    * **Environment Variable Setup (Windows):**  Specific environment variables are set for MSVC builds.
    * **Error Handling:** The `CompilerNotFoundError` is raised if no suitable compiler is found.

* **Supporting Functions:** Analyze `resolve_gcc_binaries` (finding GCC tools) and `detect_linker_flavor` (determining the linker).

**4. Connecting to Reverse Engineering:**

Now, think about how this relates to reverse engineering:

* **Target Environment Setup:** Frida is used to instrument processes. This script is about preparing the *build environment* for Frida itself to run on various target platforms (Linux, Android, Windows, etc.). Reverse engineers use Frida *on* these targets.
* **Compiler and Linker Flags:** The flags used during compilation and linking (like `-ffunction-sections`, `-fdata-sections`, `-Wl,--gc-sections`) directly affect the structure and behavior of the compiled Frida agent that will be injected into target processes. Understanding these flags can be helpful when analyzing Frida's behavior or potential limitations on different platforms.
* **Binary Tools:** The script configures paths to tools like `strip`, `objdump`, etc. Reverse engineers use these same tools to analyze the binaries that Frida interacts with.

**5. Relating to Binary, Kernel, and Framework Concepts:**

* **Binary:** The entire process revolves around building binaries (Frida agent, tools). The script manipulates compiler and linker settings to produce these binaries for different architectures.
* **Linux/Android Kernel/Framework:**  The script explicitly handles Linux and Android (through the `machine.os` checks and the `ARCH_COMMON_FLAGS` for different architectures common in these systems). The concept of cross-compilation (building on one system for another) is evident, which is crucial for targeting embedded systems like Android.
* **System Calls/Low-Level Operations:**  While the script doesn't directly interact with system calls, the *output* of the build process (the Frida agent) will heavily use them. The choice of compiler flags can influence how system calls are made.

**6. Logic and Assumptions:**

* **Input:**  The `MachineSpec` object is a key input. Imagine it contains information like `os="linux"`, `arch="arm64"`, `endian="little"`.
* **Process Flow:** If the target is Linux ARM64, the script would likely:
    1. Check `machine.triplet` for a pre-configured GCC.
    2. If not found, potentially use `env2mfile` to probe the environment.
    3. Set compiler flags from `ARCH_COMMON_FLAGS_UNIX["arm64"]`.
    4. Configure linker flags for a GNU-like system.
* **Output:** The `config` object is modified, containing the paths to tools, compiler flags, and linker flags suitable for building on the specified target.

**7. User/Programming Errors:**

* **Missing Compiler:** If GCC or MSVC isn't installed or in the PATH, the `CompilerNotFoundError` will be raised. The traceback will point to the `init_machine_config` function.
* **Incorrect Environment:** If environment variables like `CC` or `CFLAGS` are set incorrectly, they might interfere with the script's detection logic, leading to unexpected compiler choices or build failures.
* **Cross-Compilation Setup Issues:** Incorrectly configured toolchain prefixes or SDK paths will cause the script to fail to find the necessary tools.

**8. Debugging Scenario:**

Imagine a user is trying to build Frida for an Android device but gets a "Compiler not found" error.

1. **User Action:** They run the Frida build command (likely involving Meson).
2. **Meson invokes the `env_generic.py` script.**
3. **`init_machine_config` is called with `machine` representing the Android target.**
4. **The script tries to find a suitable compiler.**
5. **If no compiler is found (e.g., no Android NDK configured correctly), `CompilerNotFoundError` is raised.**
6. **The Meson build process stops, showing the error message and traceback, potentially including the relevant lines from `env_generic.py`.**

This detailed analysis covers the key aspects requested, moving from a high-level understanding to specific examples and considerations.
This Python script, `env_generic.py`, is a crucial part of Frida's build system. Its primary function is to **initialize and configure the build environment** for a specific target machine during the Frida compilation process. It determines which compilers, linkers, and other build tools to use, along with appropriate flags, based on the target operating system, architecture, and other characteristics.

Here's a breakdown of its functionalities with examples related to reverse engineering, binary internals, and potential errors:

**1. Core Functionality: Configuring the Build Environment**

* **Detecting the Target Machine:** The script takes a `MachineSpec` object as input, which describes the target architecture (e.g., x86, ARM, ARM64), operating system (e.g., Linux, Windows, Android, FreeBSD), and other relevant details.
* **Finding Compilers and Linkers:** It attempts to locate suitable C and C++ compilers (like GCC or MSVC) and their associated tools (linker, assembler, etc.). It prioritizes using compilers specified by a "triplet" (a naming convention for cross-compilation toolchains) if provided.
* **Setting Compiler and Linker Flags:**  Based on the target machine, it sets appropriate compiler flags (e.g., `-march`, `-m32`, `/arch`, optimization flags) and linker flags (e.g., `-static-libgcc`, `-Wl,--gc-sections`, library paths).
* **Handling Cross-Compilation:**  It explicitly supports cross-compilation scenarios where the build machine (where the compilation happens) is different from the target machine.
* **Generating Machine Files:** It can generate a "machine file" (using `env2mfile`) which is a configuration file Meson (the build system used by Frida) uses to understand the target environment.
* **Setting Environment Variables:** For Windows builds, it sets environment variables like `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, and `LIB` to point to the Visual Studio installation and its libraries.

**2. Relationship to Reverse Engineering**

* **Building Frida for Specific Targets:** Reverse engineers often need to use Frida on various target devices (Android phones, embedded Linux systems, Windows machines). This script ensures that Frida can be compiled correctly for those specific environments. Without this, Frida might not function as expected or might not even build on the target platform.
    * **Example:** If a reverse engineer wants to use Frida on an Android ARM64 device, this script will detect the ARM64 architecture, locate the appropriate Android NDK toolchain (if configured), and set the correct compiler flags for ARM64.
* **Understanding Compiler/Linker Options:** The script reveals the compiler and linker flags used to build Frida. This knowledge can be valuable for reverse engineers analyzing Frida's behavior. They can understand how the code was optimized, what security features were enabled (like `-Wl,-z,relro`), and potentially identify vulnerabilities based on the compilation flags.
    * **Example:** Seeing flags like `-ffunction-sections` and `-fdata-sections` suggests that the resulting binary might be more amenable to techniques like dead code elimination and function-level linking, which can affect reverse engineering efforts.

**3. Relationship to Binary Bottom, Linux, Android Kernel & Framework**

* **Binary Level:** The script directly deals with the creation of binary executables and libraries. It determines how the code is compiled and linked, influencing the final binary structure.
    * **Example:** The use of `strip` to remove debugging symbols is a binary-level operation that reduces the size of the final Frida agent. The choice between static and dynamic linking (influenced by flags like `-static-libgcc`) directly impacts the binary's dependencies.
* **Linux Kernel:** The script handles different Linux architectures and sets flags relevant to the Linux environment.
    * **Example:** For Linux, it sets linker flags like `-Wl,-z,relro` and `-Wl,-z,noexecstack`, which are security features implemented at the kernel level to protect against certain types of attacks.
* **Android Kernel and Framework:** When targeting Android, the script needs to find the Android NDK (Native Development Kit), which contains the compilers and libraries necessary for building native code for Android.
    * **Example:** The script might need to locate the `aarch64-linux-android-gcc` compiler from the NDK when building for a 64-bit Android device. It doesn't directly interact with the Android framework in this stage, but ensures that the Frida agent built is compatible with it.

**4. Logical Reasoning and Assumptions**

* **Assumption:** The script assumes that either a suitable compiler is already present in the system's PATH or that a toolchain prefix (for cross-compilation) is provided.
* **Input:** `machine` (a `MachineSpec` object describing the target), `build_machine` (the machine where the build is happening), `environ` (environment variables), `toolchain_prefix`, `sdk_prefix`.
* **Conditional Logic:** The script uses conditional statements (if/elif/else) to determine the appropriate actions based on the target OS, architecture, and the availability of tools.
* **Output:** The script modifies the `config` object (a `ConfigParser` instance) by adding sections for "binaries" (paths to tools), "built-in options" (compiler and linker flags), and "constants". It also modifies `outpath` (additional paths to search for libraries) and `outenv` (environment variables to set).

**Example of Logical Reasoning:**

If `machine.os == "windows"` and `machine.toolchain_is_msvc` is True:
1. The script assumes the target is Windows and using the Microsoft Visual C++ compiler.
2. It attempts to detect the paths to `cl.exe` (the C compiler), `link.exe` (the linker), and other MSVC tools.
3. It sets specific compiler flags like `/GS-`, `/Gy`, and linker flags relevant to MSVC.

**5. User or Programming Common Usage Errors**

* **Missing Compiler:** If the required compiler (e.g., GCC, Clang, MSVC) is not installed or not in the system's PATH, the script will raise a `CompilerNotFoundError`.
    * **Example:** A user trying to build Frida without having GCC installed would encounter this error.
* **Incorrect Toolchain Prefix:** When cross-compiling, if the `toolchain_prefix` is incorrect or doesn't point to a valid toolchain, the script might fail to find the compilers.
    * **Example:**  If a user provides a prefix like `arm-linux-gnueabi-` but the actual toolchain uses a different prefix, the `resolve_gcc_binaries` function will likely fail.
* **Environment Variable Conflicts:**  Manually setting environment variables like `CC`, `CFLAGS`, `LDFLAGS` might interfere with the script's logic and lead to unexpected behavior or build failures.
    * **Example:** If a user has `CC` set to a different compiler than intended for the target architecture, the script might incorrectly use that compiler.
* **Permissions Issues:** The script might need permissions to execute the detected compiler and linker binaries.

**6. User Operations Leading to This Script (Debugging Clues)**

This script is typically executed as part of the Frida build process, which is usually initiated by a user running a command like:

1. **Cloning the Frida repository:** `git clone https://github.com/frida/frida.git`
2. **Navigating to the build directory:** `cd frida`
3. **Using the Meson build system:**
   * Creating a build directory: `mkdir build`
   * Navigating into it: `cd build`
   * Configuring the build: `meson ..` (for a native build) or `meson --cross-file <path_to_cross_file.txt> ..` (for a cross-compilation build).

When Meson configures the build, it needs to understand the target environment. It uses "machine files" to describe the target. This `env_generic.py` script (or similar platform-specific scripts) is called by Meson (or a related helper script) to generate or contribute to these machine files.

**Debugging Scenario:**

Imagine a user is trying to build Frida for an embedded Linux device using cross-compilation.

1. **User action:** The user runs `meson --cross-file my_embedded_linux.txt ..`.
2. **Meson reads the `my_embedded_linux.txt` cross-file.** This file contains information about the target architecture, OS, and potentially the toolchain prefix.
3. **Meson calls into Frida's build system.**
4. **Frida's build system identifies that it needs to configure the build environment for the target described in the cross-file.**
5. **The `env_generic.py` script is executed.**  The `MachineSpec` object passed to `init_machine_config` is derived from the information in the cross-file.
6. **The script attempts to find the compilers and set the flags based on the target's characteristics.**
7. **If the toolchain prefix in `my_embedded_linux.txt` is incorrect, the `resolve_gcc_binaries` function might raise a `CompilerNotFoundError`.**
8. **Meson will report the error, potentially including a traceback that points to the `env_generic.py` script and the line where the exception occurred.**

By understanding the purpose and functionality of `env_generic.py`, developers and reverse engineers can better diagnose build issues and understand the underlying configuration of their Frida builds for different target platforms.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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