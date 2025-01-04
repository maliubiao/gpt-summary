Response:
Let's break down the thought process to analyze the provided Python script `env_generic.py`.

**1. Understanding the Goal:**

The core purpose of this script is to generate a Meson machine file configuration. Meson is a build system, and machine files describe the target architecture, compiler, and linker settings for a build. The filename `env_generic.py` suggests it handles generic cases, likely falling back to standard tools when more specific information isn't available. The directory `frida/subprojects/frida-node/releng/` indicates it's part of the Frida project, specifically for building the Node.js bindings and related release engineering tasks.

**2. Deconstructing the Code - Initial Pass & Keyword Identification:**

I'd start by skimming the code, identifying key elements:

* **Imports:** `collections.OrderedDict`, `configparser.ConfigParser`, `locale`, `pathlib.Path`, `shutil`, `subprocess`, `tempfile`, `typing.*`. These indicate configuration parsing, file system operations, process execution, and type hinting.
* **Function `init_machine_config`:** This is the main entry point. Its arguments provide context: `machine`, `build_machine`, `is_cross_build`, `environ`, `toolchain_prefix`, `sdk_prefix`, `call_selected_meson`, `config`, `outpath`, `outenv`, `outdir`. These relate to target architecture, build architecture, environment variables, toolchain paths, Meson interaction, existing configuration, and output paths.
* **ConfigParser usage:**  The script heavily uses `ConfigParser` to manage configuration data.
* **`subprocess` calls:** The script runs external commands like `env2mfile` and compiler/linker commands.
* **Platform-specific logic:**  There are checks for `machine.os == "windows"` and handling for MSVC toolchains. There's also logic for Linux and QNX.
* **Architecture-specific flags:** Dictionaries like `ARCH_COMMON_FLAGS_UNIX` store compiler flags for different architectures.
* **Error handling:**  Custom exceptions like `CompilerNotFoundError`, `BinaryNotFoundError`, and `LinkerDetectionError` are defined and raised.
* **Helper functions:** `resolve_gcc_binaries` and `detect_linker_flavor` are used to find compiler binaries and determine the linker type.

**3. Analyzing Functionality (Iterative Process):**

Now, I'd go through the `init_machine_config` function step-by-step:

* **Initial Setup:**  It sets `allow_undefined_symbols` based on the OS. It initializes `options` within the `config`.
* **Toolchain Discovery (GCC Attempt):** It tries to find GCC binaries based on the `machine.triplet`. If successful, it updates the `binaries` section of the configuration.
* **Fallback Toolchain Discovery (env2mfile):** If GCC isn't found, it uses `env2mfile` to generate a basic machine file. This involves running a Meson command in a temporary directory. This is a crucial fallback for cross-compilation or when the environment isn't standard.
* **MSVC Handling:**  If the target is Windows, it attempts to detect MSVC tools using `winenv` (assuming there's a separate `winenv.py` module). It sets environment variables specific to MSVC.
* **Fallback GCC on Linux (32-bit on 64-bit host):**  There's a specific fallback for building 32-bit Frida on a 64-bit Linux host.
* **Error if no Compiler:** If no C compiler is found, it raises `CompilerNotFoundError`.
* **Linker Flavor Detection:** It tries to detect the linker flavor (MSVC, GNU ld, GNU gold, LLD, Apple) by running the linker with `--version`.
* **Stripping Binaries:** If a `strip` tool is found, it adds the appropriate arguments based on the linker flavor.
* **Compiler Flag Adjustments:** It sets compiler and linker flags based on the linker flavor and target OS/architecture. This includes disabling certain features for MSVC, adding position-independent code flags for Unix-like systems, and handling static linking.
* **Constants:** Finally, it populates the `constants` section of the configuration with the collected flags.

**4. Connecting to Reverse Engineering and Low-Level Concepts:**

At this point, I'd start drawing connections to the prompt's specific points:

* **Reverse Engineering:** Frida is a dynamic instrumentation toolkit, directly used for reverse engineering. This script *configures the build environment* for Frida's Node.js bindings. Therefore, the ability to build Frida is a prerequisite for using it in reverse engineering.
* **Binary/Low-Level:** The script interacts directly with compilers, linkers, and assemblers – tools that operate on binary code. The compiler flags (e.g., `-march`, `-m32`, `/arch`) directly control how the binary code is generated for specific architectures. Linker flags control how object files are combined into executables or libraries.
* **Linux/Android Kernel/Framework:**  While this specific script doesn't directly interact with the *running* kernel, the generated build configuration is used to create Frida components that *will* interact with the kernel and Android framework at runtime. The architecture-specific flags are crucial for targeting these environments.
* **Logic and Assumptions:**  The script makes assumptions about the presence of tools in the system's PATH or uses specific detection methods. For instance, it assumes that if `machine.triplet` is set, it likely points to a GCC cross-compiler. The `env2mfile` fallback assumes that Meson and `env2mfile` are available.

**5. Generating Examples (Hypothetical Inputs/Outputs, User Errors):**

Based on the understanding of the code, I'd create illustrative examples:

* **Hypothetical Input/Output:**  Imagine building for ARM Linux. The `machine` object would specify `os="linux"`, `arch="armhf"`. The output `config` would have compiler flags like `-march=armv7-a`.
* **User Errors:**  A common error would be not having the necessary build tools installed (e.g., GCC, make, ninja). Another could be an incorrectly configured `toolchain_prefix`.

**6. Tracing User Operations (Debugging Clues):**

Finally, I'd consider how a user might end up in this code:

* A developer wants to build Frida's Node.js bindings.
* They run a build command that triggers Meson.
* Meson needs to configure the build environment for the target platform.
* Meson calls this `env_generic.py` script to generate the machine file.

**Self-Correction/Refinement:**

During this process, I'd continually refine my understanding. For instance, initially, I might not fully grasp the purpose of `env2mfile`. By examining the `subprocess` call and its arguments, I'd realize its role as a fallback for generating machine file information. Similarly, researching the specific compiler and linker flags used would deepen my understanding of their implications. I would also double-check my assumptions about the surrounding Frida codebase (like the existence and purpose of `winenv.py`).
This Python code file, `env_generic.py`, is a crucial part of the Frida dynamic instrumentation tool's build system, specifically for the Node.js bindings. Its primary function is to **initialize the machine configuration** for building Frida's native components. This configuration tells the build system (Meson in this case) how to compile and link code for a specific target architecture and operating system.

Here's a breakdown of its functionalities:

**1. Target Environment Detection and Configuration:**

* **Determines the Target Machine:** It takes a `MachineSpec` object as input, which describes the target architecture (e.g., x86, ARM), operating system (e.g., Linux, Windows, Android), and other related details.
* **Handles Cross-Compilation:** It differentiates between building for the same machine it's running on (native build) and building for a different machine (cross-build).
* **Toolchain and SDK Discovery:** It attempts to locate the necessary compiler toolchain (like GCC or MSVC) and SDK prefixes, either provided explicitly or by searching the environment.
* **Generates Meson Machine File Configuration:** It populates a `ConfigParser` object with settings that are then used by Meson to drive the build process. This includes:
    * **Compiler and Linker Paths:**  Specifying the paths to the C and C++ compilers, linker, archiver, and other build tools.
    * **Compiler and Linker Flags:** Setting architecture-specific and platform-specific flags for the compiler and linker (e.g., optimization levels, architecture targeting, linking behavior).
    * **Defining Constants:**  Setting up preprocessor definitions that might be needed during compilation.

**2. Compiler and Linker Flavor Detection:**

* **Attempts to Detect GCC Binaries:** If a target triplet (e.g., `arm-linux-gnueabihf-`) is provided, it tries to find GCC binaries prefixed with that triplet.
* **Falls Back to `env2mfile`:** If specific toolchains aren't readily available, it uses a utility called `env2mfile` (likely part of Meson) to probe the environment and generate a basic machine file configuration. This is especially important for cross-compilation.
* **Detects MSVC on Windows:**  For Windows targets, it uses a separate `winenv` module (not shown in the provided code) to locate the Microsoft Visual Studio compiler and linker tools.
* **Detects Linker Flavor:** It runs the linker with a `--version` flag to determine the linker's type (e.g., MSVC, GNU ld, GNU gold, Apple's ld). This is crucial for applying the correct linker flags.

**3. Architecture-Specific Settings:**

* **Applies Architecture-Specific Flags:** It uses dictionaries (`ARCH_COMMON_FLAGS_UNIX`, `ARCH_COMMON_FLAGS_QNX`, `ARCH_C_LIKE_FLAGS_UNIX`) to apply compiler flags tailored to specific architectures (e.g., enabling SSE2 on x86, setting the target ARM architecture).

**4. Error Handling:**

* **Raises Exceptions for Missing Tools:** It raises `CompilerNotFoundError` if it can't find a C compiler and `BinaryNotFoundError` if other required binaries are missing. It also raises `LinkerDetectionError` if it can't determine the linker's flavor.

**Relationship to Reverse Engineering:**

This script is indirectly but fundamentally related to reverse engineering through Frida:

* **Building the Foundation:** Frida is a dynamic instrumentation toolkit used extensively in reverse engineering. This script is responsible for building the *native component* of Frida's Node.js bindings. Without a properly built native component, Frida wouldn't function.
* **Targeting Specific Architectures:** Reverse engineers often need to analyze software on various architectures (e.g., ARM for mobile devices, x86/x64 for desktops). This script ensures that Frida can be built for those specific target architectures.
* **Cross-Compilation for Emulation/Analysis:**  Reverse engineers might want to analyze firmware or software for embedded devices on their development machines. This often involves cross-compilation, which this script handles. By configuring the correct toolchain and architecture, it enables building Frida for the target device's architecture, even if the development machine has a different architecture.

**Examples Relating to Binary底层, Linux, Android Kernel, and Framework:**

* **Binary 底层 (Binary Low-Level):**
    * **Compiler Flags:** The script sets flags like `-march=armv7-a` or `-march=pentium4`. These flags directly instruct the compiler how to generate machine code for specific CPU architectures and instruction sets. This is the core of interacting with the binary level.
    * **Linker Flags:** Flags like `-Wl,-z,relro` and `-Wl,-z,noexecstack` are linker flags that control memory layout and security features at the binary level. They are crucial for hardening the built Frida library.
    * **Stripping Binaries:** The script uses the `strip` tool to remove debugging symbols from the final binary. This reduces the size of the binary and is often done for release builds.

* **Linux:**
    * **`allow_undefined_symbols` for FreeBSD:**  The specific handling of `allow_undefined_symbols` based on the OS highlights OS-specific differences in how linking works on Linux-like systems versus FreeBSD.
    * **GNU Toolchain Detection:** The script prioritizes detecting GCC and related GNU tools, which are the standard toolchain on Linux.
    * **Linker Flags:** Flags like `-Wl,--gc-sections` (garbage collection of unused code sections) are common on Linux and other Unix-like systems.

* **Android Kernel and Framework (Implicit):**
    * **ARM Architecture Support:** The presence of ARM-specific flags (`-march=armv7-a`, `-march=arm64`) is essential for building Frida to run on Android devices, which are predominantly ARM-based.
    * **Cross-Compilation Scenarios:** When building Frida for an Android device from a desktop Linux machine, this script will configure the cross-compilation environment, ensuring the compiled Frida library is compatible with the Android kernel and its ARM architecture.

**Logical Reasoning with Assumptions:**

* **Assumption:** If `machine.triplet` is provided (e.g., `arm-linux-gnueabihf-`), it's highly likely that a GCC-based cross-compilation toolchain is available with binaries prefixed with that triplet.
* **Input:** `machine.triplet` is set to `arm-linux-gnueabihf-`.
* **Output:** The `binaries` section of the configuration will be populated with the paths to `arm-linux-gnueabihf-gcc`, `arm-linux-gnueabihf-g++`, `arm-linux-gnueabihf-ar`, etc.

* **Assumption:** If the target OS is Windows, and no specific toolchain prefix is given, the script assumes the presence of a standard Visual Studio installation.
* **Input:** `machine.os` is "windows", `toolchain_prefix` is `None`.
* **Output:** The `binaries` section will contain paths to `cl.exe`, `link.exe`, `lib.exe`, etc., located using the `winenv` module's detection logic. Environment variables like `VSINSTALLDIR` and `VCINSTALLDIR` will be set in `outenv`.

**User or Programming Common Usage Errors:**

* **Missing Build Tools:** A common user error is not having the necessary build tools installed (e.g., GCC, make, ninja for Linux; Visual Studio Build Tools for Windows). If the script can't find the compiler, it will raise a `CompilerNotFoundError`.
    * **Example:** On a Linux system, if GCC is not installed, and the user attempts to build Frida, this script will fail when `resolve_gcc_binaries` or the `env2mfile` fallback doesn't find a compiler.

* **Incorrectly Configured Environment:**  If environment variables like `PATH` are not set up correctly to point to the build tools, the script might fail to locate them.
    * **Example:**  If the user has installed a cross-compilation toolchain but hasn't added its bin directory to their `PATH`, the script might not find the prefixed GCC binaries.

* **Incorrect `toolchain_prefix`:** If the user provides an incorrect `toolchain_prefix`, the script will fail to find the compiler binaries with that prefix.
    * **Example:**  The user might provide a prefix like `arm-linux-` when the actual prefix is `arm-linux-gnueabihf-`.

**User Operations to Reach This Code (Debugging Clues):**

1. **User Initiates a Frida Build:** The user typically starts by cloning the Frida repository and navigating to the `frida-node` subdirectory.
2. **Running the Build Command:** They then execute a build command, which usually involves Meson. This could be something like:
   ```bash
   python3 ../meson.py <build_directory>
   ninja -C <build_directory>
   ```
3. **Meson Invokes the Configuration:**  Meson, as part of its configuration phase, needs to determine the build settings for the target machine.
4. **`init_machine_config` is Called:** Meson will call the `init_machine_config` function in `env_generic.py` (or a similar platform-specific file) to generate the machine configuration.
   * **Parameters Passed:** Meson will provide the necessary `MachineSpec`, environment variables, and other parameters to this function.
5. **Script Execution:** The `env_generic.py` script executes, attempting to locate the compiler, linker, and set up the build environment as described above.
6. **Configuration Output:** The script modifies the `config` object, which Meson then uses to generate the final build system files (like Ninja build files).

**Debugging Clues:**

* **Error Messages:** If the build fails, the error messages often indicate issues in this script, such as "Compiler not found" or "Unable to locate linker."
* **Meson Log Output:** Meson usually provides detailed logs during the configuration phase. These logs can show the output of commands executed by this script (like the `env2mfile` call or linker version checks) and any errors encountered.
* **Environment Variables:** Checking the environment variables set before running the build command can help diagnose issues related to toolchain paths.
* **Inspecting the Generated Machine File:** After Meson configuration, you can inspect the generated machine file (usually in the build directory) to see the compiler and linker paths, flags, and other settings that were determined by this script. This can help identify if the script configured something incorrectly.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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