Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality, its relevance to reverse engineering, low-level details, logical reasoning, potential errors, and how a user might end up interacting with it.

**1. Initial Scan and Overall Purpose:**

First, I'd quickly scan the imports and function definitions to get a high-level overview. Keywords like `configparser`, `subprocess`, `Path`, and the function names like `init_machine_config`, `resolve_gcc_binaries`, `detect_linker_flavor` suggest the script is involved in configuring build environments. The file path `frida/subprojects/frida-swift/releng/env_generic.py` strongly implies it's part of Frida's build process, specifically for Swift and likely handles generic environment setup. The `releng` directory suggests release engineering tasks.

**2. Core Function: `init_machine_config`:**

This function looks like the heart of the script. I'd focus on its parameters and the steps it performs:

* **Input Parameters:** `machine`, `build_machine`, `is_cross_build`, `environ`, `toolchain_prefix`, `sdk_prefix`, `call_selected_meson`, `config`, `outpath`, `outenv`, `outdir`. These parameters hint at configuring for different target architectures, handling cross-compilation, using Meson as a build system, and manipulating environment variables.
* **Key Actions:**
    * **Setting basic options:**  It manipulates `config` (likely a Meson configuration object) to set compiler flags and linker settings. The `b_lundef` option being set based on the OS (FreeBSD) suggests it deals with symbol visibility.
    * **Resolving GCC binaries:**  It attempts to find GCC toolchain binaries based on the target triplet.
    * **Probing with `env2mfile`:** If GCC is not found, it uses a tool named `env2mfile` (likely another Frida utility) to generate a machine file. This file seems to describe the target environment. This is a key part of the cross-compilation setup.
    * **Handling MSVC on Windows:**  It has specific logic for Windows, attempting to detect and use MSVC tools. It sets up environment variables like `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, and `LIB`, which are crucial for MSVC builds.
    * **Handling cross-compilation for Linux (x86 on x86_64):** It has a specific case for 32-bit Linux builds on 64-bit hosts, trying to find the necessary GCC.
    * **Detecting linker flavor:** It uses `detect_linker_flavor` to determine whether the linker is MSVC, GNU ld, Gold, LLD, or Apple's linker. This influences how linker flags are set.
    * **Setting architecture-specific flags:** It applies compiler and linker flags based on the target architecture (e.g., `-march`, `-mabi`, `/arch`).
    * **Populating `config`:**  It ultimately updates the `config` object with the determined compiler, linker, and flag settings.
    * **Populating `outpath` and `outenv`:** It updates these dictionaries with environment variables and paths needed for the build.

**3. Secondary Functions:**

* **`resolve_gcc_binaries`:**  This is about locating GCC toolchain executables based on a given prefix. It handles a specific case for broken QNX GCC tools.
* **`detect_linker_flavor`:**  This uses the linker's `--version` output to identify the linker. This involves parsing text output, a common task in build systems.

**4. Exceptions:**

The script defines custom exceptions: `CompilerNotFoundError`, `BinaryNotFoundError`, and `LinkerDetectionError`. These are used for error handling during the configuration process.

**5. Relationship to Reverse Engineering:**

At this point, I'd start connecting the dots to reverse engineering:

* **Dynamic Instrumentation (Frida's Purpose):** The script is part of Frida, a dynamic instrumentation toolkit. This means it's involved in setting up the environment to *build* Frida, which will then be used for reverse engineering. The connection isn't direct code execution within the target process, but rather preparing the *tools* for that.
* **Cross-Compilation:**  The heavy focus on cross-compilation is directly relevant. Reverse engineers often analyze software on different architectures than their development machine. Frida needs to be built for those target architectures.
* **Compiler and Linker Flags:**  The script manipulates compiler and linker flags. These flags directly impact the generated binary, including security features (like RELRO and noexecstack), debugging information, and optimization levels. Understanding these flags is crucial for reverse engineers analyzing compiled code.
* **Binary Tools:** The script deals with locating tools like assemblers (`ml`, `ml64`, `armasm64`), linkers (`link.exe`, `ld`), and other binary utilities (`strip`, `objcopy`, etc.). These tools are fundamental to the reverse engineering process.

**6. Low-Level Details:**

* **Target Triplets:** The use of `machine.triplet` highlights the concept of target triplets (architecture-vendor-os).
* **Machine Files:** The generation of `machine.txt` demonstrates how build systems abstract away platform-specific details.
* **MSVC Environment Variables:** The handling of MSVC environment variables directly relates to the internal workings of the MSVC toolchain.
* **Architecture-Specific Flags:**  The `ARCH_COMMON_FLAGS_*` dictionaries show how compilation needs to be tailored to different CPU architectures.

**7. Logical Reasoning and Assumptions:**

* **Input to `init_machine_config`:**  To illustrate logical reasoning, I'd create hypothetical inputs for `machine` and `build_machine` (e.g., targeting Android ARM64 from a Linux x86_64 host) and trace how the script would behave. This helps understand the cross-compilation logic.
* **`detect_linker_flavor` Assumptions:** The `detect_linker_flavor` function assumes that the linker's version output will contain specific strings. If a new linker emerges with a different output format, this function could fail.

**8. User/Programming Errors:**

* **Incorrect Toolchain:** A common error is having the wrong toolchain installed or not having it in the system's PATH. The script's attempts to locate compilers and the `CompilerNotFoundError` exception are related to this.
* **Missing Dependencies:**  The `BinaryNotFoundError` exception handles cases where necessary build tools are missing.
* **Incorrect Environment Variables:**  For MSVC, incorrect or missing environment variables like `VSINSTALLDIR` can cause build failures.
* **Cross-Compilation Misconfiguration:**  If the `machine` and `build_machine` parameters are not set correctly for a cross-compilation scenario, the script might pick the wrong tools or flags.

**9. Debugging and User Steps:**

To understand how a user might reach this code during debugging:

* **Frida Build Process:** The user is trying to build Frida, likely for a specific target platform. They might be using a command like `meson build --cross-file my_cross_file.txt`.
* **Cross-Compilation File:** The `my_cross_file.txt` would define the target architecture and potentially specify toolchain paths.
* **Meson Invocation:**  Meson, the build system, would parse the cross-compilation file and call Frida's build scripts.
* **`init_machine_config` Execution:**  This Python script (`env_generic.py`) would be invoked by the Frida build scripts (likely through the `call_selected_meson` function) to configure the build environment based on the target specified in the cross-compilation file.
* **Error Encounter:** If there's a problem (e.g., missing compiler), the script would raise an exception, and the user would see an error message indicating a missing tool or configuration issue. This would lead them to investigate their toolchain setup or cross-compilation file.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on the specific code details. I'd then step back and consider the broader context of Frida and its purpose in dynamic instrumentation.
* I'd re-read the prompt to ensure I'm addressing all aspects: functionality, reverse engineering, low-level details, logical reasoning, errors, and debugging context.
* If a section is unclear, I'd look for related code (e.g., the `env2mfile` tool, the `MachineSpec` class) to gain more understanding. Although I don't have that code here, the function calls provide clues.

By following these steps, I can systematically analyze the code, understand its role within Frida, and connect it to the concepts of reverse engineering and low-level system details.
This Python script, `env_generic.py`, is a crucial part of Frida's build system, specifically designed to initialize the build environment for various target platforms. It's responsible for detecting and configuring the necessary tools (like compilers and linkers) and flags required to compile Frida for a given target architecture and operating system.

Here's a breakdown of its functionality:

**1. Detecting and Configuring Build Tools:**

* **Compiler Detection:** The script attempts to locate a C compiler (and optionally a C++ compiler) for the target platform. It prioritizes using GCC if available (by trying prefixed versions based on the target triplet) but also handles MSVC on Windows.
* **Linker Detection:** It identifies the type of linker being used (MSVC, GNU ld, GNU gold, LLD, or Apple's linker) by inspecting its version output. This is important because different linkers have different syntax for their flags.
* **Assembler Detection:** For Windows builds using MSVC, it identifies the correct assembler (`ml.exe`, `ml64.exe`, `armasm64.exe`) based on the target architecture.
* **Toolchain Prefix Handling:** It uses the `toolchain_prefix` to look for cross-compilation toolchains.
* **SDK Prefix Handling:**  Although present as a parameter, its usage isn't immediately apparent in the provided code snippet. It might be used in other parts of the Frida build system.

**2. Setting Compiler and Linker Flags:**

* **Architecture-Specific Flags:**  It sets compiler flags (like `-march`, `-mabi`, `/arch`) and linker flags based on the target architecture (x86, ARM, ARM64, MIPS, etc.) and operating system (Unix-like, QNX, Windows).
* **Common Flags:**  It defines and applies common compiler flags (`-ffunction-sections`, `-fdata-sections`, `/GS-`, etc.) and linker flags (`-static-libgcc`, `-Wl,-z,relro`, `/dead_strip`, etc.) depending on the linker flavor.
* **Handling Undefined Symbols:** It adjusts the `-Wl,--no-undefined` (or equivalent) linker flag based on whether the target OS allows undefined symbols (FreeBSD being an exception).
* **MSVC Specific Flags:** It adds flags specific to the MSVC compiler, such as disabling certain security features (`/GS-`) and enabling specific instruction sets (`/arch:SSE2`).

**3. Generating Meson Configuration:**

* **Populating `config`:** The script populates a `ConfigParser` object (likely representing a Meson configuration dictionary) with the detected compiler paths, linker paths, and the determined compiler and linker flags. This configuration is then used by Meson to drive the actual compilation process.
* **Setting Binary Paths:** It sets the paths to essential build tools (compiler, linker, assembler, archiver, etc.) within the Meson configuration.
* **Defining Constants:** It defines Meson constants to hold the lists of compiler and linker flags.

**4. Handling Cross-Compilation:**

* **`is_cross_build` Flag:** The script takes an `is_cross_build` flag as input, indicating whether it's building for a different target architecture than the host.
* **`env2mfile` Tool:**  If a suitable compiler is not directly found, it uses an external tool called `env2mfile` to probe the target environment and generate a "machine file" (`machine.txt`). This file contains information about the target system's architecture, OS, and available tools, which are then parsed to configure the build.
* **Windows Cross-Compilation:** It has specific logic for setting up the MSVC environment for cross-compilation on Windows, including detecting the necessary MSVC tools and setting environment variables like `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, and `LIB`.
* **Linux Cross-Compilation (32-bit on 64-bit):**  It includes a specific case for building 32-bit Frida on a 64-bit Linux host by trying to find a 32-bit GCC.

**5. Error Handling:**

* **`CompilerNotFoundError`:** Raised when no suitable C compiler is found.
* **`BinaryNotFoundError`:** Raised when a required binary (like an assembler) cannot be located.
* **`LinkerDetectionError`:** Raised when the linker's version output cannot be parsed to determine its type.

**Relationship to Reverse Engineering:**

This script is directly related to reverse engineering because it's responsible for building **Frida itself**, a dynamic instrumentation tool heavily used in reverse engineering. By correctly configuring the build environment, this script ensures that Frida is compiled properly for the target system that a reverse engineer wants to analyze.

**Example:** Imagine a reverse engineer wants to analyze an iOS application running on an ARM64 device. They would need to build Frida for iOS/ARM64. This script would be invoked during that build process. It would:

1. **Detect the iOS/ARM64 toolchain:**  It might rely on environment variables or paths specified by the user or the build system to locate the necessary Apple developer tools (including `clang` and `ld`).
2. **Set ARM64 specific flags:** It would apply compiler flags like `-arch arm64` and linker flags specific to the Apple linker.
3. **Configure Meson:** It would update the Meson configuration with the paths to the iOS toolchain and the appropriate flags, allowing Meson to build the Frida Gadget or Frida server for iOS/ARM64.

**In essence, this script lays the groundwork for the reverse engineering process by ensuring the creation of the necessary tools.**

**Involvement of Binary Underlying Knowledge:**

This script heavily relies on binary underlying knowledge in several ways:

* **Understanding Compiler and Linker Flags:** The script manipulates numerous compiler and linker flags that directly affect the generated binary code. For example:
    * `-march`: Specifies the target CPU architecture and instruction set.
    * `-mabi`: Specifies the Application Binary Interface (ABI), which defines how data is laid out in memory and how functions are called.
    * `-static-libgcc` and `-static-libstdc++`: Control whether the GNU C and C++ standard libraries are statically linked into the binary.
    * `-Wl,-z,relro` and `-Wl,-z,noexecstack`: Security-related linker flags that harden the binary against certain types of attacks.
    * `/arch`: (MSVC) Specifies the target processor architecture.
* **Knowledge of Toolchain Structure:** The script understands the typical structure of toolchains, including the names of common binaries like `gcc`, `g++`, `clang`, `ld`, `ar`, and their prefixed versions for cross-compilation.
* **Operating System Differences:**  It differentiates between operating systems (Windows, Linux, macOS, FreeBSD, QNX) and applies different logic and flags accordingly. For example, the way MSVC tools are located and configured is very different from how GCC is handled on Linux.
* **Architecture-Specific Conventions:**  The script uses target "triplets" (e.g., `arm-linux-gnueabihf`) to identify the target architecture, vendor, and operating system, which is a common convention in cross-compilation.
* **Understanding Linker Behavior:**  The `detect_linker_flavor` function relies on understanding the output format of different linkers' `--version` commands.

**Example:** The section handling MSVC on Windows demonstrates binary underlying knowledge. It knows that the compiler is `cl.exe`, the linker is `link.exe`, the archiver is `lib.exe`, and it uses specific assemblers (`ml.exe`, `ml64.exe`, `armasm64.exe`) based on the architecture. It also understands the need to set specific environment variables like `INCLUDE` and `LIB` to point to the correct SDK directories for MSVC to find necessary headers and libraries.

**Logical Reasoning with Assumptions:**

Let's consider the logic in the `detect_linker_flavor` function:

* **Assumption:** The output of the linker's `--version` command will contain a specific string identifying the linker.
* **Input:** A list of strings representing the command to execute the C compiler with the linker version flag (e.g., `['/usr/bin/gcc', '-Wl,--version']`).
* **Output:** A string representing the linker flavor (e.g., "gnu-ld", "msvc", "apple").

**Reasoning:** The function executes the compiler with the linker version flag and captures the output. It then checks for specific substrings within the output to identify the linker.

**Example:** If the `linker_version` string contains "Microsoft ", the function assumes it's the MSVC linker and returns "msvc". This is a reasonable assumption based on the typical output of the MSVC linker.

**Potential User/Programming Errors:**

* **Incorrect or Missing Toolchain:** A common user error is not having the correct cross-compilation toolchain installed or not having it in the system's PATH. The script's attempts to find compilers and the `CompilerNotFoundError` exception handle this scenario.
    * **Example:** A user tries to build Frida for Android without installing the Android NDK or setting the necessary environment variables. The script would fail to find the Android GCC or Clang.
* **Misconfigured Environment Variables:** For Windows builds, incorrect or missing environment variables like `VSINSTALLDIR` can prevent the script from finding the MSVC tools.
    * **Example:** A user has Visual Studio installed, but the `VSINSTALLDIR` environment variable is not set correctly. The script will be unable to locate `cl.exe` or `link.exe`.
* **Incorrect Target Specification:** If the user provides an invalid or unsupported target architecture, the script might not have specific flags defined, or it might fail to find a suitable toolchain.
    * **Example:** The user tries to build for an architecture that Frida doesn't officially support.
* **Interference from Existing Environment:** Existing environment variables (like `CC`, `CFLAGS`, `CXX`, `CXXFLAGS`) might interfere with the script's toolchain detection logic if the user intends to use a specific compiler that the script is not prioritizing.
    * **Example:** A user has explicitly set `CC=/usr/bin/clang` in their environment, but the script is designed to primarily look for GCC-prefixed binaries for a specific target.

**User Operation Leading to This Code (Debugging Scenario):**

1. **User wants to build Frida for a specific target:**  For example, they want to build Frida for an embedded Linux device with an ARM architecture.
2. **User navigates to the Frida source directory:** They clone the Frida repository and go to the root directory.
3. **User initiates the build process using Meson:** They typically create a build directory (e.g., `build`) and run `meson setup build --cross-file my_cross_config.txt`. The `--cross-file` option is crucial for cross-compilation.
4. **Meson reads the cross-compilation file:** `my_cross_config.txt` contains information about the target architecture, operating system, and potentially paths to the cross-compilation toolchain.
5. **Meson executes Frida's build scripts:** These scripts will eventually call the `init_machine_config` function in `env_generic.py`.
6. **`init_machine_config` is called:**  It receives the target machine specification (`machine`), the host machine specification (`build_machine`), and other relevant information as arguments.
7. **The script attempts to detect the toolchain:**  It will try to find GCC binaries prefixed with the target triplet or, if on Windows, attempt to locate MSVC tools.
8. **If there's an issue (e.g., missing compiler), an exception is raised:**  For instance, if the user hasn't installed the ARM cross-compilation toolchain, a `CompilerNotFoundError` will be raised.
9. **Meson reports the error to the user:** The user will see an error message indicating that a compiler could not be found, along with potential debugging information (like the output of failed commands).

This debugging scenario highlights how a user's attempt to build Frida for a specific target can lead to the execution of this script and potentially reveal issues with their build environment configuration. The error messages generated by this script (like `CompilerNotFoundError`) serve as crucial debugging clues for the user.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层的知识，请做出对应的举例说明，
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