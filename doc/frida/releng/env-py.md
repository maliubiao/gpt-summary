Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Understanding the Goal:**

The core goal is to understand the functionality of `frida/releng/env.py`, particularly in the context of reverse engineering, low-level details (binary, OS, kernel), logical reasoning, potential user errors, and debugging.

**2. Initial Code Scan and High-Level Purpose:**

The first step is a quick skim of the code to get a general idea. Keywords like `configparser`, `subprocess`, `platform`, `dataclass`, `Path`, `environ`, `meson` immediately suggest this code is involved in:

* **Configuration:** Reading and managing configuration settings.
* **External Processes:** Interacting with other programs (like `meson`, compilers, etc.).
* **Platform Awareness:** Handling differences between operating systems.
* **Data Structures:**  Organizing data using classes and dictionaries.
* **File System Operations:**  Working with files and directories.
* **Build System Integration:** Specifically mentions `meson`, a build system.

The filename `env.py` reinforces the idea that this file deals with setting up the build environment.

**3. Deeper Dive and Functional Breakdown:**

Now, read through the code more carefully, focusing on the functions and their roles:

* **`MachineConfig`:** A data class to hold configuration information for a specific machine (target or host). Key attributes: `machine_file`, `binpath`, `environ`.
* **`make_merged_environment`:** Merges environment variables, prioritizing the machine's specific settings and prepending to the `PATH`.
* **`call_meson`, `query_meson_entrypoint`:**  Functions to interact with the Meson build system. This is a *major* clue about the file's purpose.
* **`load_meson_config`, `query_machine_file_path`:**  Deal with loading and locating Meson configuration files for different machine types.
* **`detect_default_prefix`:**  Determines the default installation directory based on the OS.
* **`generate_machine_configs`, `generate_machine_config`:** The core logic for creating the machine-specific configuration. This involves:
    * Identifying the target and host machines.
    * Handling cross-compilation scenarios.
    * Using platform-specific logic (`env_apple`, `env_android`, `env_generic`).
    * Setting up compiler and linker paths.
    * Handling `pkg-config`.
    * Potentially using an emulator (`qemu`).
    * Writing the configuration to a file.
* **`needs_exe_wrapper`, `can_run_host_binaries`, `find_exe_wrapper`:** Logic related to running executables built for a different architecture (cross-compilation). This is crucial for reverse engineering scenarios where you might analyze code on a different platform than your development machine.
* **`make_pkg_config_wrapper`:** Creates a wrapper script to customize `pkg-config` behavior.
* **`detect_toolchain_vala_compiler`:**  Specific logic for finding the Vala compiler within a toolchain.
* **`build_envvar_to_host`:**  A utility for renaming environment variables in cross-compilation.
* **`quote`:**  A utility for properly quoting strings in shell commands.
* **`QEMUNotFoundError`:** A custom exception.

**4. Connecting to the Prompt's Requirements:**

Now, systematically go through each point in the prompt:

* **Functionality:**  List the key responsibilities identified in step 3. Use clear and concise language.
* **Relationship to Reverse Engineering:** Focus on aspects directly relevant to reverse engineering, like cross-compilation (analyzing Android binaries on a Linux host), interacting with debuggers (`gdbus-codegen`), and understanding the build process of tools used for dynamic instrumentation (like Frida itself).
* **Binary/Low-Level/Kernel/Framework Knowledge:** Identify code sections that demonstrate this knowledge. Examples:
    * Handling executable suffixes (`.exe`).
    * Setting up toolchains and compilers (GCC, Clang, MSVC).
    * Dealing with architecture-specific settings (ARM, x86).
    * Understanding the role of `pkg-config` for finding libraries.
    * Using `qemu` for emulation.
* **Logical Reasoning (Hypothetical Inputs/Outputs):**  Think about specific scenarios and trace the code's execution. Example: What happens when cross-compiling for Android? How does the code determine if an emulator is needed?
* **User/Programming Errors:** Consider common mistakes users might make when setting up the build environment. Examples: Incorrect `PATH`, missing dependencies, wrong environment variables.
* **User Operation to Reach This Code (Debugging Clues):**  Imagine a developer building Frida from source. What steps would lead to this code being executed?  Consider the initial configuration, the build system (`meson`), and any environment setup steps.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Provide concrete examples to illustrate each point.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This just seems like build system stuff."  **Correction:**  While build systems are central, recognize the specific relevance to *Frida*, a dynamic instrumentation tool used for reverse engineering.
* **Overly technical jargon:**  Simplify explanations where possible to be understandable to a broader audience.
* **Missing key connections:**  Ensure the link between the code's functionality and the prompt's specific requirements (reverse engineering, low-level details, etc.) is explicit. For instance, don't just say "it handles cross-compilation"; explain *why* cross-compilation is important for reverse engineering mobile apps on a desktop.
* **Lack of concrete examples:**  Instead of just saying "it handles different platforms," give examples of how it handles Windows vs. Linux.

By following these steps, iteratively refining the analysis, and focusing on the prompt's specific requirements, you can produce a comprehensive and informative answer like the example provided.
This Python code file, `frida/releng/env.py`, plays a crucial role in setting up the build environment for Frida, a dynamic instrumentation toolkit. It generates configuration files tailored to the specific target and host machines involved in the build process. Let's break down its functionalities with examples related to your points.

**Core Functionalities:**

1. **Machine Configuration Generation:** The primary function is to generate "machine files" that describe the build and host environments. These files are used by the Meson build system to configure the compilation process correctly. It gathers information about the operating system, architecture, compiler toolchain, and other relevant settings.

2. **Cross-Compilation Support:** It handles scenarios where the machine building Frida is different from the target machine where Frida will run (cross-compilation). This is essential for developing Frida on a desktop (e.g., Linux x86_64) to target Android or iOS devices.

3. **Toolchain Management:** It detects and configures the necessary toolchains (compilers, linkers, and other utilities) required for building Frida. This includes handling custom toolchain prefixes.

4. **SDK Integration:**  It integrates with Software Development Kits (SDKs) by setting up paths to headers, libraries, and other necessary components.

5. **Environment Variable Management:** It manipulates environment variables to ensure the build process has the correct settings.

6. **Meson Integration:** It provides functions to interact with the Meson build system, such as running Meson commands and querying the Meson entry point.

7. **Platform-Specific Handling:** It includes logic to handle platform-specific differences for Apple (macOS, iOS), Android, and generic Linux-like systems.

8. **Executable Wrapper Logic:**  For cross-compilation scenarios where the build machine cannot directly execute binaries built for the target machine, it sets up mechanisms to use an emulator (like QEMU) as an executable wrapper.

**Relationship to Reverse Engineering (with Examples):**

* **Targeting Different Architectures:**  Reverse engineering often involves analyzing software running on different architectures than the developer's machine. This script directly addresses this by facilitating cross-compilation. For example, a reverse engineer might be running a Linux x86_64 machine but needs to build Frida to inject into an Android application running on an ARM64 device. This script helps configure the build process to use the appropriate ARM64 toolchain.

* **Dynamic Instrumentation Setup:** Frida is a dynamic instrumentation tool. This script is a foundational part of building Frida itself. Without correctly generated machine configurations, Frida wouldn't be built for the target architecture, rendering it useless for reverse engineering tasks on that target.

* **Example:**  Imagine a reverse engineer wants to use Frida to inspect the runtime behavior of an iOS application. They would need to build Frida for iOS (arm64 or armv7). This script would be involved in:
    * Detecting that the target machine is `iOS`.
    * Finding the appropriate iOS SDK.
    * Setting up the environment variables to use the Apple's `clang` compiler for ARM64.
    * Potentially configuring code signing settings.
    * Generating a machine file that Meson uses to build the iOS version of Frida.

**Binary底层, Linux, Android内核及框架知识 (with Examples):**

* **Executable Suffixes:** The code uses `build_machine.executable_suffix` to determine the correct file extension for executables on the target platform (e.g., `.exe` on Windows, empty string on Linux). This is a low-level detail about how operating systems recognize executable files.

* **Library Paths (`libdatadir`):**  The script interacts with paths like `sdk_prefix / machine.libdatadir / "pkgconfig"`. `libdatadir` is a convention on Linux and other Unix-like systems to store library-related data. Understanding these standard directory structures is crucial for building software that works correctly across different Linux distributions and Android.

* **Toolchain Components (GCC, Clang, MSVC):** The script implicitly deals with different compiler toolchains. For example, on Android, it would likely configure the build to use the Android NDK's toolchain (based on Clang). On Windows, it might use MSVC. This requires knowledge of how these different toolchains are structured and how to invoke their components (compiler, linker, etc.).

* **`pkg-config`:** The script uses `pkg-config` to find information about installed libraries. This is a common mechanism in the Linux ecosystem. Understanding how `pkg-config` works and how it uses `.pc` files is important for linking against system libraries or libraries provided by an SDK.

* **QEMU for Emulation:**  The use of QEMU as an executable wrapper directly relates to the concept of system emulation. When cross-compiling for an architecture that the build machine cannot execute directly, QEMU simulates that architecture, allowing build tools to run target binaries as part of the build process. This touches upon kernel-level concepts of process execution and system calls.

* **Android Specifics (`env_android.py`):** Although not directly in this file, the reference to `env_android` indicates that there's separate logic to handle Android-specific build configurations. This would involve knowledge of the Android NDK, its directory structure, and specific build requirements for Android libraries and executables (like shared library extensions `.so`).

**Logical Reasoning (Hypothetical Inputs & Outputs):**

* **Assumption:** The build machine is Linux x86_64, and the target machine is Android ARM64.
* **Input (relevant parts inferred):**
    * `build_machine.identifier` would be something like `linux-x86_64`.
    * `host_machine.identifier` would be something like `android-arm64`.
    * `environ` might contain paths to the Android NDK.
* **Output (relevant parts of `MachineConfig`):**
    * `machine_file`:  A file named something like `frida-android-arm64.txt` in the `outdir`.
    * `binpath`:  Might include the `bin` directory of the Android NDK toolchain.
    * `environ`: Would contain environment variables like `CC`, `CXX` pointing to the ARM64 Clang compiler and C++ compiler from the NDK. It might also contain `PATH` adjusted to include the NDK's bin directory.
    * The generated machine file would contain sections like `[binaries]` with entries for the Android NDK's compiler and linker. If `FRIDA_QEMU_SYSROOT` is set, it might include an `exe_wrapper` using QEMU.

**User or Programming Common Usage Errors (with Examples):**

* **Incorrect Toolchain Paths:**  If the user doesn't provide the correct `toolchain_prefix` or if the necessary tools are not in the system's `PATH`, the script might fail to find the compilers and other build utilities.
    * **Example:** The user forgets to set the `ANDROID_NDK_HOME` environment variable, and the script cannot locate the Android NDK's compiler. This would lead to errors when Meson tries to configure the build.

* **Missing Dependencies:** The build process relies on external tools like `ninja`, `pkg-config`, `vala`, etc. If these are not installed or not in the `PATH`, the script might not find them, leading to build failures.
    * **Example:** The user tries to build Frida without having `ninja` installed. The script won't be able to set the `NINJA` environment variable in the machine config, and Meson will fail.

* **Incorrect Environment Variables for Cross-Compilation:** When cross-compiling, setting the correct environment variables is crucial. Mistakes in variables like `FRIDA_QEMU_SYSROOT` (if needed) or platform-specific variables can lead to incorrect build configurations.
    * **Example:** The user sets `FRIDA_QEMU_SYSROOT` to an invalid path. The script will find the `qemu` binary but won't be able to use the specified sysroot, leading to errors during the build or when running tests.

* **Permissions Issues:** If the script doesn't have write permissions to the `outdir`, it won't be able to create the machine configuration files.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Cloning the Frida Repository:** A developer starts by cloning the Frida source code from a Git repository.
2. **Setting Up the Build Environment:** The developer would typically follow the Frida build instructions, which involve installing dependencies and potentially setting environment variables for toolchains or SDKs.
3. **Running the Meson Configuration Command:** The core step that triggers this script is running a Meson command to configure the build. This usually looks something like:
   ```bash
   python3 -m mesonbuild setup _build
   ```
   or, for cross-compilation:
   ```bash
   python3 -m mesonbuild setup _build --cross-file <path_to_cross_config>
   ```
4. **Meson Invokes `env.py`:**  During the Meson configuration process, Meson needs to understand the target and host environments. It will execute Python scripts within the Frida build system to gather this information. `frida/releng/env.py` is one of these scripts. Meson will call functions within this script (likely `generate_machine_configs`) to create the machine-specific configuration files.
5. **Machine Files are Generated:** The script will then create files like `frida-linux-x86_64.txt` (for the build machine) and `frida-android-arm64.txt` (for the target machine if cross-compiling) in the `_build` directory (or whatever the build directory is named).
6. **Meson Uses the Machine Files:** Meson reads these generated machine files to understand the available tools, compiler flags, and other settings needed to proceed with the actual compilation.

**As a debugging clue:** If a Frida build fails during the configuration step, examining the contents of the generated machine files can provide valuable insights into how the `env.py` script detected the environment and what settings it configured. Errors in these files can point to issues with toolchain setup, missing dependencies, or incorrect environment variables. You might also inspect the output of the Meson configuration command for errors or warnings related to environment detection.

Prompt: 
```
这是目录为frida/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from collections import OrderedDict
from configparser import ConfigParser
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import pprint
import shlex
import shutil
import subprocess
import sys
from typing import Callable, Literal, Optional

from . import env_android, env_apple, env_generic, machine_file
from .machine_file import bool_to_meson, str_to_meson, strv_to_meson
from .machine_spec import MachineSpec


@dataclass
class MachineConfig:
    machine_file: Path
    binpath: list[Path]
    environ: dict[str, str]

    def make_merged_environment(self, source_environ: dict[str, str]) -> dict[str, str]:
        menv = {**source_environ}
        menv.update(self.environ)

        if self.binpath:
            old_path = menv.get("PATH", "")
            old_dirs = old_path.split(os.pathsep) if old_path else []
            menv["PATH"] = os.pathsep.join([str(p) for p in self.binpath] + old_dirs)

        return menv


DefaultLibrary = Literal["shared", "static"]


def call_meson(argv, use_submodule, *args, **kwargs):
    return subprocess.run(query_meson_entrypoint(use_submodule) + argv, *args, **kwargs)


def query_meson_entrypoint(use_submodule):
    if use_submodule:
        return [sys.executable, str(INTERNAL_MESON_ENTRYPOINT)]
    return ["meson"]


def load_meson_config(machine: MachineSpec, flavor: str, build_dir: Path):
    return machine_file.load(query_machine_file_path(machine, flavor, build_dir))


def query_machine_file_path(machine: MachineSpec, flavor: str, build_dir: Path) -> Path:
    return build_dir / f"frida{flavor}-{machine.identifier}.txt"


def detect_default_prefix() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ["ProgramFiles"]) / "Frida"
    return Path("/usr/local")


def generate_machine_configs(build_machine: MachineSpec,
                             host_machine: MachineSpec,
                             environ: dict[str, str],
                             toolchain_prefix: Optional[Path],
                             build_sdk_prefix: Optional[Path],
                             host_sdk_prefix: Optional[Path],
                             call_selected_meson: Callable,
                             default_library: DefaultLibrary,
                             outdir: Path) -> tuple[MachineConfig, MachineConfig]:
    is_cross_build = host_machine != build_machine

    if is_cross_build:
        build_environ = {build_envvar_to_host(k): v for k, v in environ.items() if k not in TOOLCHAIN_ENVVARS}
    else:
        build_environ = environ

    build_config = \
            generate_machine_config(build_machine,
                                    build_machine,
                                    is_cross_build,
                                    build_environ,
                                    toolchain_prefix,
                                    build_sdk_prefix,
                                    call_selected_meson,
                                    default_library,
                                    outdir)

    if is_cross_build:
        host_config = generate_machine_config(host_machine,
                                              build_machine,
                                              is_cross_build,
                                              environ,
                                              toolchain_prefix,
                                              host_sdk_prefix,
                                              call_selected_meson,
                                              default_library,
                                              outdir)
    else:
        host_config = build_config

    return (build_config, host_config)


def generate_machine_config(machine: MachineSpec,
                            build_machine: MachineSpec,
                            is_cross_build: bool,
                            environ: dict[str, str],
                            toolchain_prefix: Optional[Path],
                            sdk_prefix: Optional[Path],
                            call_selected_meson: Callable,
                            default_library: DefaultLibrary,
                            outdir: Path) -> MachineConfig:
    config = ConfigParser(dict_type=OrderedDict)
    config["constants"] = OrderedDict()
    config["binaries"] = OrderedDict()
    config["built-in options"] = OrderedDict()
    config["properties"] = OrderedDict()
    config["host_machine"] = OrderedDict([
        ("system", str_to_meson(machine.system)),
        ("subsystem", str_to_meson(machine.subsystem)),
        ("kernel", str_to_meson(machine.kernel)),
        ("cpu_family", str_to_meson(machine.cpu_family)),
        ("cpu", str_to_meson(machine.cpu)),
        ("endian", str_to_meson(machine.endian)),
    ])

    binaries = config["binaries"]
    builtin_options = config["built-in options"]
    properties = config["properties"]

    outpath = []
    outenv = OrderedDict()
    outdir.mkdir(parents=True, exist_ok=True)

    if machine.is_apple:
        impl = env_apple
    elif machine.os == "android":
        impl = env_android
    else:
        impl = env_generic

    impl.init_machine_config(machine,
                             build_machine,
                             is_cross_build,
                             environ,
                             toolchain_prefix,
                             sdk_prefix,
                             call_selected_meson,
                             config,
                             outpath,
                             outenv,
                             outdir)

    if machine.toolchain_is_msvc:
        builtin_options["b_vscrt"] = str_to_meson(machine.config)

    pkg_config = None
    vala_compiler = None
    if toolchain_prefix is not None:
        toolchain_bindir = toolchain_prefix / "bin"
        exe_suffix = build_machine.executable_suffix

        ninja_binary = toolchain_bindir / f"ninja{exe_suffix}"
        if ninja_binary.exists():
            outenv["NINJA"] = str(ninja_binary)

        for (tool_name, filename_suffix) in {("gdbus-codegen", ""),
                                             ("gio-querymodules", exe_suffix),
                                             ("glib-compile-resources", exe_suffix),
                                             ("glib-compile-schemas", exe_suffix),
                                             ("glib-genmarshal", ""),
                                             ("glib-mkenums", ""),
                                             ("flex", exe_suffix),
                                             ("bison", exe_suffix),
                                             ("nasm", exe_suffix)}:
            tool_path = toolchain_bindir / (tool_name + filename_suffix)
            if tool_path.exists():
                if tool_name == "bison":
                    outenv["BISON_PKGDATADIR"] = str(toolchain_prefix / "share" / "bison")
                    outenv["M4"] = str(toolchain_bindir / f"m4{exe_suffix}")
            else:
                tool_path = shutil.which(tool_name)
            if tool_path is not None:
                binaries[tool_name] = strv_to_meson([str(tool_path)])

        pkg_config_binary = toolchain_bindir / f"pkg-config{exe_suffix}"
        if not pkg_config_binary.exists():
            pkg_config_binary = shutil.which("pkg-config")
        if pkg_config_binary is not None:
            pkg_config = [
                str(pkg_config_binary),
            ]
            if default_library == "static":
                pkg_config += ["--static"]
            if sdk_prefix is not None:
                pkg_config += [f"--define-variable=frida_sdk_prefix={sdk_prefix}"]
            binaries["pkg-config"] = strv_to_meson(pkg_config)

        vala_compiler = detect_toolchain_vala_compiler(toolchain_prefix, build_machine)

    pkg_config_path = shlex.split(environ.get("PKG_CONFIG_PATH", "").replace("\\", "\\\\"))

    if sdk_prefix is not None:
        builtin_options["vala_args"] = strv_to_meson([
            "--vapidir=" + str(sdk_prefix / "share" / "vala" / "vapi")
        ])

        pkg_config_path += [str(sdk_prefix / machine.libdatadir / "pkgconfig")]

        sdk_bindir = sdk_prefix / "bin" / build_machine.os_dash_arch
        if sdk_bindir.exists():
            for f in sdk_bindir.iterdir():
                binaries[f.stem] = strv_to_meson([str(f)])

    if vala_compiler is not None:
        valac, vapidir = vala_compiler
        vala = [
            str(valac),
            f"--vapidir={vapidir}",
        ]
        if pkg_config is not None:
            wrapper = outdir / "frida-pkg-config.py"
            wrapper.write_text(make_pkg_config_wrapper(pkg_config, pkg_config_path), encoding="utf-8")
            vala += [f"--pkg-config={quote(sys.executable)} {quote(str(wrapper))}"]
        binaries["vala"] = strv_to_meson(vala)

    qmake6 = shutil.which("qmake6")
    if qmake6 is not None:
        binaries["qmake6"] = strv_to_meson([qmake6])

    builtin_options["pkg_config_path"] = strv_to_meson(pkg_config_path)

    needs_wrapper = needs_exe_wrapper(build_machine, machine, environ)
    properties["needs_exe_wrapper"] = bool_to_meson(needs_wrapper)
    if needs_wrapper:
        wrapper = find_exe_wrapper(machine, environ)
        if wrapper is not None:
            binaries["exe_wrapper"] = strv_to_meson(wrapper)

    machine_file = outdir / f"frida-{machine.identifier}.txt"
    with machine_file.open("w", encoding="utf-8") as f:
        config.write(f)

    return MachineConfig(machine_file, outpath, outenv)


def needs_exe_wrapper(build_machine: MachineSpec,
                      host_machine: MachineSpec,
                      environ: dict[str, str]) -> bool:
    return not can_run_host_binaries(build_machine, host_machine, environ)


def can_run_host_binaries(build_machine: MachineSpec,
                          host_machine: MachineSpec,
                          environ: dict[str, str]) -> bool:
    if host_machine == build_machine:
        return True

    build_os = build_machine.os
    build_arch = build_machine.arch

    host_os = host_machine.os
    host_arch = host_machine.arch

    if host_os == build_os:
        if build_os == "windows":
            return build_arch == "arm64" or host_arch != "arm64"

        if build_os == "macos":
            if build_arch == "arm64" and host_arch == "x86_64":
                return True

        if build_os == "linux" and host_machine.config == build_machine.config:
            if build_arch == "x86_64" and host_arch == "x86":
                return True

    return environ.get("FRIDA_CAN_RUN_HOST_BINARIES", "no") == "yes"


def find_exe_wrapper(machine: MachineSpec,
                     environ: dict[str, str]) -> Optional[list[str]]:
    qemu_sysroot = environ.get("FRIDA_QEMU_SYSROOT")
    if qemu_sysroot is None:
        return None

    qemu_flavor = "qemu-" + QEMU_ARCHS.get(machine.arch, machine.arch)
    qemu_binary = shutil.which(qemu_flavor)
    if qemu_binary is None:
        raise QEMUNotFoundError(f"unable to find {qemu_flavor}, needed due to FRIDA_QEMU_SYSROOT being set")

    return [qemu_binary, "-L", qemu_sysroot]


def make_pkg_config_wrapper(pkg_config: list[str], pkg_config_path: list[str]) -> str:
    return "\n".join([
        "import os",
        "import subprocess",
        "import sys",
        "",
        "args = [",
        f" {pprint.pformat(pkg_config, indent=4)[1:-1]},",
        "    *sys.argv[1:],",
        "]",
        "env = {",
        "    **os.environ,",
        f"    'PKG_CONFIG_PATH': {repr(os.pathsep.join(pkg_config_path))},",
        "}",
        f"p = subprocess.run(args, env=env)",
        "sys.exit(p.returncode)"
    ])


def detect_toolchain_vala_compiler(toolchain_prefix: Path,
                                   build_machine: MachineSpec) -> Optional[tuple[Path, Path]]:
    datadir = next((toolchain_prefix / "share").glob("vala-*"), None)
    if datadir is None:
        return None

    api_version = datadir.name.split("-", maxsplit=1)[1]

    valac = toolchain_prefix / "bin" / f"valac-{api_version}{build_machine.executable_suffix}"
    vapidir = datadir / "vapi"
    return (valac, vapidir)


def build_envvar_to_host(name: str) -> str:
    if name.endswith("_FOR_BUILD"):
        return name[:-10]
    return name


def quote(s: str) -> str:
    if " " not in s:
        return s
    return "\"" + s.replace("\"", "\\\"") + "\""


class QEMUNotFoundError(Exception):
    pass


INTERNAL_MESON_ENTRYPOINT = Path(__file__).resolve().parent / "meson" / "meson.py"

# Based on mesonbuild/envconfig.py and mesonbuild/compilers/compilers.py
TOOLCHAIN_ENVVARS = {
    # Compilers
    "CC",
    "CXX",
    "CSC",
    "CYTHON",
    "DC",
    "FC",
    "OBJC",
    "OBJCXX",
    "RUSTC",
    "VALAC",
    "NASM",

    # Linkers
    "CC_LD",
    "CXX_LD",
    "DC_LD",
    "FC_LD",
    "OBJC_LD",
    "OBJCXX_LD",
    "RUSTC_LD",

    # Binutils
    "AR",
    "AS",
    "LD",
    "NM",
    "OBJCOPY",
    "OBJDUMP",
    "RANLIB",
    "READELF",
    "SIZE",
    "STRINGS",
    "STRIP",
    "WINDRES",

    # Other tools
    "CMAKE",
    "QMAKE",
    "PKG_CONFIG",
    "PKG_CONFIG_PATH",
    "MAKE",
    "VAPIGEN",
    "LLVM_CONFIG",

    # Deprecated
    "D_LD",
    "F_LD",
    "RUST_LD",
    "OBJCPP_LD",

    # Flags
    "CFLAGS",
    "CXXFLAGS",
    "CUFLAGS",
    "OBJCFLAGS",
    "OBJCXXFLAGS",
    "FFLAGS",
    "DFLAGS",
    "VALAFLAGS",
    "RUSTFLAGS",
    "CYTHONFLAGS",
    "CSFLAGS",
    "LDFLAGS",
}

QEMU_ARCHS = {
    "armeabi": "arm",
    "armhf": "arm",
    "armbe8": "armeb",
    "arm64": "aarch64",
}

"""

```