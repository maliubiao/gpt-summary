Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to understand the overall purpose of the script. The file path `frida/subprojects/frida-tools/releng/env_generic.py` provides crucial context. "frida" suggests dynamic instrumentation. "releng" likely refers to release engineering or build infrastructure. "env_generic.py" strongly hints at environment setup, likely for cross-compilation.

**2. High-Level Functionality Scan:**

Read through the code, paying attention to function names, imports, and key data structures. Notice functions like `init_machine_config`, `resolve_gcc_binaries`, and `detect_linker_flavor`. Imports like `subprocess`, `shutil`, `tempfile`, and `configparser` suggest interaction with the system, file manipulation, temporary file usage, and configuration file parsing.

**3. Deeper Dive into `init_machine_config`:**

This appears to be the core function. Analyze its parameters: `MachineSpec`, `build_machine`, `is_cross_build`, `environ`, `toolchain_prefix`, `sdk_prefix`, `call_selected_meson`, `config`, `outpath`, `outenv`, `outdir`. These names strongly suggest it's about configuring the build environment for a specific target machine, potentially different from the build machine.

* **Machine Specification (`MachineSpec`):**  This is a key concept. It likely holds information about the target architecture, OS, etc. This immediately connects to cross-compilation.
* **Compiler Detection:** The code tries to find a C compiler (`cc`). It first attempts to use GCC based on a triplet (like `arm-linux-gnueabi-`). If that fails, it uses `env2mfile` (likely a Meson utility) to probe the environment. For Windows, it specifically looks for MSVC tools.
* **Linker Flavor:** The code attempts to detect the linker (GNU ld, Gold, LLD, Apple ld, or MSVC). This is important because linker flags and behavior vary.
* **Flags and Options:** The code sets various compiler and linker flags based on the target architecture, OS, and linker flavor. This directly relates to compiling and linking binaries.
* **Environment Variables:** The code manipulates environment variables (`outenv`), particularly for Windows (e.g., `VSINSTALLDIR`, `INCLUDE`, `LIB`). This is essential for the build process to find the necessary tools and libraries.
* **Meson Integration:** The presence of `call_selected_meson` and the manipulation of `config` (a `ConfigParser` object) strongly indicate integration with the Meson build system. Meson uses configuration files to manage build settings.

**4. Analyzing Helper Functions:**

* **`resolve_gcc_binaries`:** Clearly finds GCC-related tools (compiler, archiver, linker, etc.) based on a prefix. Handles potential issues with QNX's GCC wrappers.
* **`detect_linker_flavor`:**  Executes the linker with `--version` to identify its type. This is a common technique for program introspection.

**5. Connecting to Key Concepts:**

* **Reverse Engineering:** The script prepares the build environment for creating tools like Frida, which *are* used for dynamic instrumentation and reverse engineering. The script itself isn't directly involved in analyzing binaries, but it's a prerequisite for building the tools that do.
* **Binary Underpinnings:** The script directly deals with compilers, linkers, assemblers, and their flags. It differentiates between architectures (x86, ARM, etc.) and operating systems (Linux, Windows, macOS, QNX). This is all fundamental to how software is built at a low level.
* **Operating Systems (Linux, Android, Windows):** The script has specific logic for different operating systems, especially Windows (MSVC) and Linux (GCC). It handles OS-specific compiler flags, linker behavior, and environment variables. While Android isn't explicitly handled with unique logic *in this specific file*, the general concepts of cross-compilation and targeting different architectures apply to Android development.
* **Kernel/Framework:**  While not directly manipulating the kernel, the tools built using this environment *will* interact with the kernel (e.g., Frida hooking into process memory). The script sets up the *ability* to build such tools.

**6. Logical Reasoning and Examples:**

Think about the flow of execution and the conditions that trigger different code paths.

* **Cross-compilation:** If `is_cross_build` is true, the script will likely use the triplet to find the correct compiler and adjust flags accordingly.
* **Compiler Not Found:** If the script cannot find a C compiler, it will raise a `CompilerNotFoundError`. Consider scenarios where the necessary toolchains are not installed or are not in the system's PATH.
* **Linker Detection Failure:** If the linker's output doesn't match any known patterns, a `LinkerDetectionError` will be raised. This could happen with custom or obscure linkers.

**7. User Errors and Debugging:**

Consider how a user might end up in a situation where this code is executed and what could go wrong.

* **Incorrect Configuration:**  Users might provide incorrect `MachineSpec` details or have a misconfigured build environment.
* **Missing Dependencies:** The required compilers and build tools might not be installed.
* **Environment Issues:** Incorrect environment variables can lead to the script not finding the necessary tools.

**8. Tracing User Operations:**

Think about the steps a user would take to initiate the build process. This often involves running a build system like Meson, which would then call this Python script to configure the environment.

**Self-Correction/Refinement During Analysis:**

Initially, I might focus too much on the specific flags. However, realizing the overarching goal is *environment setup for cross-compilation* helps to prioritize the information and connect the pieces. For example, the handling of Windows environment variables becomes more significant in that context. Also, distinguishing between what the script *does* and what the *resulting tools* do is crucial for answering the "reverse engineering" aspect. The script facilitates building those tools, it doesn't perform reverse engineering itself.
This Python script, `env_generic.py`, is a crucial part of the Frida build system. Its primary function is to **initialize and configure the build environment** for a specific target machine. It sets up the necessary compilers, linkers, and flags required to cross-compile Frida components for various operating systems and architectures.

Here's a breakdown of its functionalities:

**1. Machine Configuration:**

* **`init_machine_config(machine, build_machine, is_cross_build, environ, toolchain_prefix, sdk_prefix, call_selected_meson, config, outpath, outenv, outdir)`:** This is the core function. It takes information about the target `machine` (OS, architecture, etc.) and the `build_machine`, whether it's a cross-build, environment variables, toolchain paths, and a Meson configuration object.
* **Determines Build Settings:** Based on the `machine` specification, it sets up compiler and linker flags, binary paths, and other environment settings. This includes things like:
    *  C and C++ compiler paths (`cc`, `cpp`).
    *  Linker path (`ld`, `link`).
    *  Archiver path (`ar`).
    *  Assembler path (`as`, `ml`, `ml64`, `armasm64`).
    *  Stripping tool path (`strip`).
    *  Various compiler and linker flags based on the target architecture and OS (e.g., `-march`, `-m32`, `/arch`, `/GS-`).
* **Handles Cross-Compilation:** The `is_cross_build` flag guides the configuration process, ensuring the correct toolchain and settings are used when compiling for a different architecture than the build machine.
* **Integrates with Meson:** It interacts with the Meson build system by using `call_selected_meson` to execute Meson commands and by manipulating the `config` object, which holds Meson configuration data.

**2. Compiler and Linker Detection:**

* **`resolve_gcc_binaries(toolprefix="")`:** Attempts to locate GCC-based toolchain binaries (like `gcc`, `g++`, `ar`, `nm`, etc.) by searching for executables with a given `toolprefix` (e.g., `arm-linux-gnueabi-`). This is vital for cross-compilation where you need a toolchain targeting the specific architecture.
* **`detect_linker_flavor(cc)`:** Analyzes the output of the linker when called with `--version` to determine its type (e.g., "msvc", "gnu-ld", "gnu-gold", "lld", "apple"). The linker flavor influences the necessary linker flags.

**3. Platform-Specific Configuration:**

* **Windows (MSVC):**  Includes logic to detect and use the Microsoft Visual Studio compiler (`cl.exe`), linker (`link.exe`), librarian (`lib.exe`), and assembler (`ml.exe` or `ml64.exe`). It sets up necessary environment variables like `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, and `LIB`.
* **Linux and other Unix-like systems (GCC/Clang):** Configures the build environment for GCC or Clang, setting appropriate compiler and linker flags.
* **QNX:** Has specific handling for the QNX operating system, including architecture-specific flags.
* **macOS (Apple Clang):** Detects the Apple linker and applies relevant flags.

**4. Handling Compiler and Binary Availability:**

* **`CompilerNotFoundError` and `BinaryNotFoundError`:** These custom exceptions are raised when the script cannot find the required compiler or other binary tools.

**Relationship to Reverse Engineering:**

This script indirectly relates to reverse engineering because it's responsible for building **Frida itself**, which is a powerful dynamic instrumentation toolkit used extensively in reverse engineering.

* **Building the Tools:**  Without this script correctly setting up the build environment, Frida wouldn't be able to be compiled for various target platforms (like Android, iOS, Linux, Windows). Reverse engineers rely on having Frida available on the target system they are analyzing.
* **Cross-Platform Reverse Engineering:** The ability of this script to handle cross-compilation is crucial for reverse engineering scenarios where the target device has a different architecture or operating system than the researcher's machine. For instance, analyzing an Android application from a Linux or macOS workstation requires cross-compiling Frida for the Android target.

**Example:**

Let's say a reverse engineer wants to analyze an Android application running on an ARM64 device from their x86_64 Linux machine.

* **Input (Hypothetical):**
    * `machine`: `MachineSpec(os='android', arch='arm64', ...)`
    * `build_machine`: `MachineSpec(os='linux', arch='x86_64', ...)`
    * `is_cross_build`: `True`
    * `toolchain_prefix`: Path to an Android NDK toolchain for ARM64.
* **Logic:**
    * `init_machine_config` would be called.
    * Because `is_cross_build` is `True` and the target is Android/ARM64, the script would likely use the provided `toolchain_prefix` to locate the ARM64 GCC/Clang toolchain.
    * `resolve_gcc_binaries` would be used with the toolchain prefix to find the `arm64-linux-android-gcc`, `arm64-linux-android-g++`, etc.
    * Compiler flags like `-march=armv8-a` would be set.
    * The output `config` would be updated with the correct paths and flags for building Frida components targeting ARM64 Android.
* **Output:** The `config` object and `outenv` would be modified to contain the necessary settings for a successful cross-compilation.

**Relationship to Binary Underpinnings, Linux, Android Kernel/Framework:**

This script heavily relies on knowledge of binary formats, operating system specifics, and build toolchains.

* **Binary Underpinnings:**
    * **Compiler and Linker Flags:** The script directly manipulates compiler and linker flags that control how code is compiled and linked into executable binaries. Flags like `-ffunction-sections`, `-fdata-sections`, `-Wl,--gc-sections` are used for optimizing binary size and security.
    * **Architecture-Specific Instructions:**  Flags like `-march=armv7-a` or `-march=pentium4` tell the compiler which instruction set to target, impacting the generated machine code.
    * **Linker Behavior:** Understanding how linkers work is crucial for setting flags like `-Wl,-z,relro` and `-Wl,-z,noexecstack` (for security hardening).
* **Linux:**
    * **GCC Toolchain:** On Linux, the script primarily deals with the GNU Compiler Collection (GCC) and its associated tools.
    * **Environment Variables:** It uses and modifies environment variables like `PATH` to locate binaries.
* **Android Kernel and Framework:**
    * **Android NDK:** When cross-compiling for Android, the script often interacts with the Android NDK (Native Development Kit), which provides the necessary toolchains and libraries for building native code. The `toolchain_prefix` parameter often points to the NDK toolchain directory.
    * **Target Architecture:** The script needs to know the target Android device's architecture (ARM, ARM64, x86, x86_64) to select the correct compiler and flags.
    * **System Libraries:** While this script doesn't directly interact with the Android framework at runtime, it sets up the build environment so that Frida can be built to interact with Android's native libraries and services.

**Example (Binary Underpinnings):**

The lines:

```python
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
```

demonstrate knowledge of:

* **`-ffunction-sections` and `-fdata-sections`:**  These GCC/Clang flags instruct the compiler to place each function and data item in its own section in the object file. This allows the linker to perform more aggressive dead code elimination (`-Wl,--gc-sections`) and potentially improve security (e.g., by making it easier to apply position-independent code).
* **`-static-libgcc` and `-static-libstdc++`:** These flags tell the linker to statically link the libgcc and libstdc++ runtime libraries into the executable.
* **`-Wl,-z,relro` and `-Wl,-z,noexecstack`:** These are linker flags (passed via `-Wl,`) that enable security features:
    * `relro` (Relocation Read-Only): Makes certain data sections read-only after relocation, preventing some types of memory corruption vulnerabilities.
    * `noexecstack`: Marks the stack as non-executable, preventing shellcode injection attacks that rely on executing code on the stack.
* **`-Wl,-dead_strip` (macOS) and `-Wl,--gc-sections` (other Unix-like):** These are linker flags for removing unused code and data sections from the final executable, reducing its size.

**Logical Reasoning with Assumptions:**

Let's consider the section dealing with 32-bit cross-compilation on a 64-bit Linux host:

```python
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
```

* **Assumption:** If the target machine is 32-bit Linux and the build machine is 64-bit Linux, and the user hasn't explicitly set `CC` or `CFLAGS`, the script assumes the user wants to cross-compile using the default GCC on the build machine.
* **Input:**
    * `machine.pointer_size == 4` (32-bit target)
    * `build_machine.pointer_size == 8` (64-bit build)
    * `machine.os == "linux"`
    * `build_machine.os == "linux"`
    * `"CC"` and `"CFLAGS"` are not in `environ`.
* **Logic:** The `if` condition evaluates to `True`. The script attempts to find the default GCC binaries and then adds the `-m32` flag to the `common_flags`.
* **Output:** If GCC is found, the `common_flags` will include `-m32`, instructing the compiler to generate 32-bit code. If GCC is not found, the `CompilerNotFoundError` is caught, and the script proceeds without adding the `-m32` flag (potentially leading to a build failure later).

**User or Programming Common Usage Errors:**

* **Missing Toolchain:**  A common error is not having the necessary cross-compilation toolchain installed. For example, if trying to cross-compile for Android, the user needs to have the Android NDK installed and its toolchain directory accessible.
    * **How to reach this point:** A user attempts to build Frida for Android without installing the NDK or without configuring the build system to find it. When Meson calls `env_generic.py`, `resolve_gcc_binaries` might fail, raising a `CompilerNotFoundError`.
* **Incorrect Environment Variables:** If environment variables like `CC` or `CFLAGS` are set incorrectly, they might interfere with the script's logic.
    * **How to reach this point:** A user might have experimented with different compilers or build configurations and left environment variables set that conflict with the current build target.
* **Permissions Issues:** The script might fail if the user running the build process doesn't have the necessary permissions to execute the compiler or linker binaries.
    * **How to reach this point:** A user attempts to build Frida without the appropriate permissions to execute the tools in the toolchain.
* **Incorrect `MachineSpec`:** Providing an incorrect `MachineSpec` (e.g., wrong architecture or OS) will lead to the script configuring the build environment incorrectly.
    * **How to reach this point:** The user might have misconfigured the Meson options or provided incorrect command-line arguments that get translated into the `MachineSpec`.

**User Operation Steps to Reach This Code (as a Debugging Clue):**

1. **User wants to build Frida for a specific target (e.g., Android, iOS).**
2. **User clones the Frida repository.**
3. **User navigates to the Frida build directory.**
4. **User runs a build command using Meson, specifying the target architecture and OS.**  For example:
   ```bash
   meson setup _build --buildtype=release -Dtarget=android -Darch=arm64
   ```
5. **Meson parses the build configuration and determines the target environment.**
6. **Meson executes build scripts and finds `frida/subprojects/frida-tools/releng/env_generic.py`.**
7. **Meson calls the `init_machine_config` function in `env_generic.py`, passing the determined `MachineSpec` and other relevant parameters.**
8. **The Python script executes, attempting to configure the build environment.**
9. **If errors occur (e.g., `CompilerNotFoundError`), the script raises an exception, and Meson will likely report a build failure.**  The traceback will point to this script, providing a debugging starting point.

By understanding the functionalities of `env_generic.py`, developers and advanced users can diagnose and resolve issues related to Frida's build process, especially when cross-compiling for different platforms.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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