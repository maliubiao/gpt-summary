Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality and its relevance to reverse engineering, low-level concepts, and potential user errors.

**1. Initial Skim and High-Level Understanding:**

* **Filename:** `env_generic.py` suggests it's about setting up an environment, likely for building software. The `generic` part hints it's not specific to one OS or architecture.
* **Imports:**  Standard Python libraries for collections, config parsing, locales, paths, subprocesses, temporary files, and typing. This indicates configuration management, external command execution, and type hinting for clarity.
* **Function `init_machine_config`:** This is the core function. The name and parameters (`machine`, `build_machine`, `is_cross_build`, `environ`, etc.) strongly suggest it's about configuring the build environment for a target machine. The presence of `config: ConfigParser` points to reading configuration from a file. `outpath`, `outenv`, `outdir` suggest setting up output paths and environment variables.

**2. Deeper Dive into `init_machine_config`:**

* **Machine Specification (`MachineSpec`):**  The function takes `machine` and `build_machine` of type `MachineSpec`. This is a key concept. It implies there's a separate definition (likely in `machine_spec.py`) for describing the target and build architectures, OS, etc. This is crucial for cross-compilation.
* **Cross-Compilation:** The `is_cross_build` flag is explicit. This immediately signals relevance to reverse engineering scenarios where you might be building tools for a different architecture (e.g., analyzing an Android app on your x86 laptop).
* **Toolchain and SDK Prefixes:** `toolchain_prefix` and `sdk_prefix` indicate support for specifying custom toolchains and SDKs, common in embedded development and potentially reverse engineering when dealing with specific targets.
* **Meson:** The `call_selected_meson` function parameter means this script interacts with the Meson build system. Understanding Meson's role is important. Meson is a meta-build system that generates native build files (like Makefiles or Ninja files) based on a higher-level description.
* **Compiler Detection:** The code attempts to detect the C and C++ compilers. It first tries using a triplet (e.g., `arm-linux-gnueabi-`) to find GCC. If that fails, it uses Meson's `env2mfile` tool to probe the environment. For Windows, it specifically looks for MSVC tools. This compiler detection is vital for building native code.
* **Linker Flavor Detection:**  The `detect_linker_flavor` function uses command-line output to determine the type of linker (MSVC, GNU ld, Gold, LLD, Apple). This affects the linker flags used.
* **Flags and Options:** The code manipulates compiler and linker flags (`c_args`, `cpp_args`, `c_link_args`, `cpp_link_args`). This is where architecture-specific and OS-specific settings are applied.
* **Binary Paths:** The script finds paths to essential build tools (compiler, linker, assembler, etc.). For Windows, it uses `winenv` module to locate MSVC tools.
* **Output Configuration:** `outpath` (PATH environment variable), `outenv` (other environment variables), and `outdir` (output directory) are being configured.

**3. Analyzing Helper Functions:**

* **`resolve_gcc_binaries`:**  This function specifically looks for GCC toolchain binaries based on a prefix. It handles a QNX-specific issue where prefixed tools might fail.
* **`detect_linker_flavor`:**  As noted before, it parses the output of the linker's `--version` command.

**4. Connecting to Reverse Engineering and Low-Level Concepts:**

* **Cross-Compilation:**  A fundamental aspect of reverse engineering embedded systems or mobile applications. You need to build tools that run on your development machine but target the architecture of the device you're analyzing.
* **Binary Format Knowledge:**  Linker flags (`-Wl,--gc-sections`, `-Wl,-dead_strip`) directly influence the structure of the generated executable. Understanding these flags is crucial for analyzing binaries.
* **Operating System Differences:** The code handles Windows, Linux, FreeBSD, and QNX specifically. Reverse engineers often deal with platform-specific behaviors.
* **Architecture-Specific Settings:**  Flags like `-march`, `-mabi`, and assembler names (`ml`, `ml64`, `armasm64`) are architecture-dependent. Reverse engineers need to be aware of instruction set architectures (ISAs).
* **Toolchains:** The concept of a toolchain (compiler, linker, assembler, libraries) is central to both building software and understanding how existing software was built.

**5. Considering User Errors and Debugging:**

* **Missing Compilers:** The `CompilerNotFoundError` is a common issue. Users might not have the necessary development tools installed.
* **Incorrectly Configured Environment:**  Environment variables like `CC`, `CFLAGS`, `PATH` can interfere with the script's ability to find tools.
* **Cross-Compilation Setup:**  Setting up a cross-compilation environment can be complex. Users might provide incorrect target specifications.

**6. Tracing User Operations:**

* The script is part of the Frida build process. Users likely interact with it indirectly by running Frida's build commands (e.g., using Meson).
* The `init_machine_config` function is called with specific machine configurations derived from the user's build setup and target specification.

**7. Formulating Examples and Explanations:**

Based on the above analysis, I started constructing the detailed explanation, focusing on:

* **Functionality:** Summarizing the purpose of the script.
* **Reverse Engineering Relevance:** Providing concrete examples like analyzing Android apps.
* **Low-Level Concepts:**  Explaining the significance of compiler flags, linker behavior, and OS/architecture differences.
* **Logic and Assumptions:**  Creating scenarios with example inputs and outputs to illustrate how the script behaves.
* **User Errors:**  Listing common pitfalls like missing compilers or incorrect environment settings.
* **User Journey:**  Describing how a user's actions lead to this code being executed.

This step-by-step approach, from high-level understanding to detailed analysis and example creation, allows for a comprehensive explanation of the script's functionality and its relevance to various technical domains.
This Python script, `env_generic.py`, is a crucial part of the Frida dynamic instrumentation tool's build system. Its primary function is to **initialize and configure the build environment** for a specific target machine architecture. It does this by determining the necessary compilers, linkers, and flags based on the target and build machine specifications.

Here's a breakdown of its functionalities and connections to various concepts:

**1. Core Functionality: Setting up the Build Environment**

* **Detecting Compilers and Linkers:** The script attempts to find suitable C and C++ compilers (like GCC or MSVC) and their associated linkers for the target machine. It prioritizes using a toolchain prefix (e.g., `arm-linux-gnueabi-gcc`) if provided. If no prefix is given or the prefixed tools are not found, it tries to locate them in the system's PATH.
* **Handling Cross-Compilation:** It explicitly handles cross-compilation scenarios where the target machine is different from the build machine. It takes `machine` (target) and `build_machine` as arguments to configure the environment accordingly.
* **Generating Machine Configuration Files:**  It utilizes Meson's `env2mfile` tool to generate a basic machine configuration file based on the target machine's properties (OS, architecture, endianness, etc.). This file is then parsed to gather information about available tools.
* **Configuring Compiler and Linker Flags:** Based on the detected compiler (GCC or MSVC) and the target architecture/OS, it sets appropriate compiler and linker flags. This includes flags for architecture-specific optimizations, stack protection, and linking behavior.
* **Setting Environment Variables:** It sets up necessary environment variables (e.g., `VSINSTALLDIR`, `VCINSTALLDIR`, `INCLUDE`, `LIB` on Windows) required by the build tools.
* **Defining Build Constants:** It defines constants that will be used by the Meson build system, such as the lists of compiler flags (`common_flags`, `c_like_flags`, `linker_flags`, etc.).

**2. Relationship to Reverse Engineering**

This script is indirectly related to reverse engineering, but it's a fundamental part of building the tools that *enable* reverse engineering.

* **Building Frida for Different Architectures:**  When a reverse engineer wants to use Frida to instrument an application on a specific architecture (e.g., ARM Android device), this script is involved in configuring the build environment to compile Frida's components for that target architecture.
* **Example:** Let's say a reverse engineer wants to analyze an Android application running on an ARM64 device. To use Frida, they would typically install the Frida server component on the Android device. The build process for this server involves cross-compiling for the ARM64 architecture. `env_generic.py` would be executed during this build to detect the ARM64 compiler and set the correct flags for that architecture.

**3. Relationship to Binary底, Linux, Android Kernel & Framework Knowledge**

This script deeply interacts with low-level concepts and operating system specifics:

* **Binary 底层 (Binary Underpinnings):**
    * **Compiler and Linker Flags:**  The script directly manipulates compiler and linker flags that directly affect the generated binary code. For example, `-ffunction-sections` and `-fdata-sections` can help with optimizing binary size and enabling more granular garbage collection by the linker. Linker flags like `-Wl,-z,relro` and `-Wl,-z,noexecstack` are security features applied at the binary level.
    * **Architecture-Specific Flags:** It uses dictionaries like `ARCH_COMMON_FLAGS_UNIX` and `ARCH_C_LIKE_FLAGS_UNIX` to apply architecture-specific flags (e.g., `-march=pentium4` for x86, `-march=armv7-a` for ARM). This demonstrates an understanding of different instruction set architectures and their compiler requirements.
    * **Linker Flavor:** The script detects the "flavor" of the linker (GNU ld, Gold, LLD, Apple's ld, MSVC's link.exe). Different linkers have different syntax and features, requiring specific handling of flags.

* **Linux:**
    * **GCC Toolchain:**  The script heavily relies on the GCC toolchain (gcc, g++, ar, ld, etc.) which is the standard compiler suite on Linux.
    * **Environment Variables:** It understands and manipulates environment variables commonly used in Linux development environments.
    * **File System Paths:** It uses `pathlib` to work with file system paths, a standard practice in modern Python development, especially on Linux.

* **Android Kernel & Framework:**
    * **Cross-Compilation for ARM:** When building Frida for Android (which uses a Linux-based kernel), the script will be configured to use an ARM cross-compiler (like `arm-linux-gnueabi-gcc` or `aarch64-linux-gnu-gcc`).
    * **Understanding Android's Architecture:** The `MachineSpec` object (though not fully defined in this snippet) likely contains information about the target Android architecture (e.g., `arm`, `arm64`) which drives the selection of compiler flags.

* **Windows:**
    * **MSVC Toolchain:** The script has specific logic to detect and use the Microsoft Visual C++ (MSVC) toolchain (`cl.exe`, `link.exe`, `lib.exe`) on Windows.
    * **Windows Environment Variables:** It sets Windows-specific environment variables related to MSVC.
    * **MSVC Linker Flavors:** It correctly identifies the MSVC linker.

**4. Logical Reasoning, Assumptions, Input & Output**

Let's consider a simplified scenario:

**Hypothetical Input:**

* `machine`: A `MachineSpec` object representing an ARM Linux target.
    * `machine.os = "linux"`
    * `machine.arch = "arm"`
    * `machine.triplet = "arm-linux-gnueabi-"`
* `build_machine`:  A `MachineSpec` object representing an x86 Linux build machine.
* `is_cross_build = True`
* `environ`: The current environment variables (including PATH).
* `toolchain_prefix`:  `Path("/opt/arm-toolchain/")` (assuming the ARM cross-compiler is installed there).

**Logical Reasoning within the Script:**

1. The script checks `machine.triplet`. It's not `None`, so it tries to `resolve_gcc_binaries` with the prefix `"arm-linux-gnueabi-"`.
2. `resolve_gcc_binaries` will attempt to find executables like `arm-linux-gnueabi-gcc`, `arm-linux-gnueabi-g++`, etc., within the directories in the PATH.
3. If the tools are found (assuming the toolchain is correctly installed), the `binaries` dictionary in the `config` object will be updated with the paths to these tools.
4. The script then applies architecture-specific common flags for ARM from `ARCH_COMMON_FLAGS_UNIX`, such as `-march=armv5t`.
5. It also adds generic Unix-like C flags.
6. Since the linker flavor will likely be detected as `gnu-ld`, it will add linker flags like `-static-libgcc`, `-Wl,-z,relro`, and `-Wl,-z,noexecstack`.

**Hypothetical Output (changes to the `config` object):**

* `config["binaries"]["c"]` might be set to `['/opt/arm-toolchain/arm-linux-gnueabi-gcc'] + common_flags`
* `config["binaries"]["cpp"]` might be set to `['/opt/arm-toolchain/arm-linux-gnueabi-g++'] + common_flags`
* `config["constants"]["common_flags"]` would contain `['-march=armv5t']`
* `config["constants"]["c_like_flags"]` would contain generic C flags plus ARM-specific ones if any in `ARCH_C_LIKE_FLAGS_UNIX`.
* `config["constants"]["linker_flags"]` would contain `['-static-libgcc', '-Wl,-z,relro', '-Wl,-z,noexecstack']`

**5. Common User or Programming Errors**

* **Missing Compiler:** If the user doesn't have the necessary compiler installed for the target architecture (especially in cross-compilation scenarios), the `resolve_gcc_binaries` function will raise a `CompilerNotFoundError`.
    * **Example:** Trying to build Frida for Android without installing the Android NDK or a standalone ARM cross-compiler.
* **Incorrect Toolchain Prefix:** Providing an incorrect `toolchain_prefix` will lead to the script not finding the compilers.
    * **Example:**  Specifying `/opt/my-wrong-toolchain/` when the actual toolchain is in `/opt/arm-toolchain/`.
* **PATH Issues:** If the required compilers are installed but not in the system's PATH, the script won't be able to find them.
    * **Example:** Installing the Android NDK but not adding its toolchain directory to the PATH environment variable.
* **Conflicting Environment Variables:**  Manually setting environment variables like `CC` or `CFLAGS` might interfere with the script's automatic detection and configuration. The script does check for these, but unexpected values could cause issues.
* **Permissions Issues:** Lack of execute permissions on the compiler binaries can also lead to failures.

**6. User Operations Leading to This Script**

A user typically doesn't interact with `env_generic.py` directly. It's part of the Frida build process, which is usually initiated through commands like:

1. **Cloning the Frida repository:** The user first clones the Frida source code.
2. **Using the Meson build system:** Frida uses Meson as its build system. The user would typically run commands like:
   * `meson setup <build_directory>` (to configure the build)
   * `ninja` (to compile the project)

During the `meson setup` phase, Meson will analyze the `meson.build` files in the Frida project. These files will invoke custom Python scripts like `env_generic.py` to configure the build environment based on the specified target platform.

**As a debugging clue:**

If a user is encountering build errors related to compilers or linkers not being found, or incorrect flags being used, investigating the execution of `env_generic.py` can be crucial. This might involve:

* **Examining the Meson log output:** Meson usually provides detailed logs of its configuration and build steps, including the execution of scripts like this one.
* **Temporarily modifying the script for debugging:**  A developer might add print statements to `env_generic.py` to see which compilers are being detected, which flags are being set, and what environment variables are being configured.
* **Manually running parts of the script:** In some cases, it might be helpful to run parts of `env_generic.py` in isolation with specific `MachineSpec` objects to understand how it behaves under different conditions.

In summary, `env_generic.py` is a foundational script in Frida's build system responsible for setting up the necessary environment to compile Frida's components for various target platforms. It interacts with low-level concepts, operating system specifics, and plays a critical role in enabling cross-compilation, which is essential for a dynamic instrumentation tool like Frida that needs to run on diverse architectures. Understanding its functionality is key to troubleshooting build issues and appreciating the complexities involved in creating cross-platform development tools.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/env_generic.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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