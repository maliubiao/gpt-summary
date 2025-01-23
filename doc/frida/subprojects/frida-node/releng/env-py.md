Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Skim and High-Level Understanding:**

First, I read through the code quickly to get a general idea of its purpose. Keywords like "meson," "machine config," "toolchain," "SDK," "cross-build," and the file path `frida/subprojects/frida-node/releng/env.py` suggest it's related to the build environment setup for Frida, particularly for Node.js bindings. The "releng" directory often implies release engineering or related build processes.

**2. Identifying Core Functionality - The "What":**

I started looking for functions that seemed to perform the main actions. `generate_machine_configs` and `generate_machine_config` stood out. The names clearly indicate they are creating configuration files related to the build machine. The presence of `MachineSpec` and `MachineConfig` dataclasses reinforces this. I also noticed functions related to Meson (`call_meson`, `query_meson_entrypoint`, `load_meson_config`).

**3. Deeper Dive into Key Functions - The "How":**

I then examined the key functions more closely:

*   **`generate_machine_configs`:**  This function handles the logic for both build and host machines, distinguishing between cross-compilation and native builds. It calls `generate_machine_config` to do the actual configuration generation.
*   **`generate_machine_config`:** This is where the core configuration logic resides. It initializes a `ConfigParser` to create INI-like configuration files. It gathers information about the target machine (OS, architecture, etc.) and populates the configuration. It also handles toolchain detection, SDK paths, and sets up environment variables.
*   **`detect_default_prefix`:**  Simple but important - determines the default installation directory.
*   **Functions interacting with external tools:**  Functions like `call_meson`, and the logic for finding tools like `ninja`, `pkg-config`, `vala`, `qmake` are important for understanding how the build system integrates with external dependencies.
*   **Cross-compilation logic:** The `is_cross_build` checks and the `needs_exe_wrapper` and `find_exe_wrapper` functions are critical for understanding how the script handles building for different architectures.

**4. Identifying Relationships to Reverse Engineering:**

Knowing Frida's purpose, I started connecting the dots:

*   **Dynamic Instrumentation:** Frida's core functionality is directly related to this. The script sets up the environment needed to *build* Frida, which is used for dynamic instrumentation.
*   **Target Architectures and OSes:** The script explicitly handles different operating systems (Windows, macOS, Linux, Android) and architectures (x86, x64, ARM, ARM64). This is fundamental to reverse engineering, as you often target specific platforms.
*   **Toolchain and SDK:**  The script's focus on toolchains and SDKs is essential for cross-compilation, a common task in reverse engineering when analyzing embedded systems or mobile apps.
*   **`pkg-config`:**  This tool is used to find libraries, which is crucial for understanding dependencies in reverse-engineered software.
*   **QEMU wrapper:** The logic for using QEMU to execute binaries for different architectures is a direct link to emulation, which is frequently used in reverse engineering.

**5. Identifying Low-Level and Kernel/Framework Aspects:**

*   **Operating Systems:** The script has conditional logic based on `platform.system()` and checks for Android, indicating an understanding of OS-specific details.
*   **File Paths and Environment Variables:** The manipulation of `PATH`, `PKG_CONFIG_PATH`, and other environment variables demonstrates interaction with the underlying operating system.
*   **Executable Suffixes:**  The use of `build_machine.executable_suffix` indicates awareness of platform-specific executable formats.
*   **Android Specifics:** The import of `env_android` and the handling of SDK prefixes point to knowledge of the Android framework.

**6. Looking for Logic and Assumptions:**

*   **Cross-compilation detection:**  The script assumes that if the build and host machines are different, it's a cross-compile.
*   **Tool location:**  It assumes certain tools (like `ninja`, `pkg-config`) are either in the toolchain prefix or in the system's PATH.
*   **QEMU usage:**  It assumes that if `FRIDA_QEMU_SYSROOT` is set, the user intends to use QEMU for execution.

**7. Identifying Potential User Errors:**

I thought about common mistakes users might make when setting up a build environment:

*   **Incorrect or Missing Toolchain:** If the toolchain prefix is wrong or tools are missing, the script might fail to find necessary binaries.
*   **Incorrect SDK Paths:**  Similar to the toolchain, incorrect SDK paths can lead to errors.
*   **Misconfigured Environment Variables:** Incorrectly setting `PKG_CONFIG_PATH` or `FRIDA_QEMU_SYSROOT` could cause issues.
*   **Cross-compilation Misunderstandings:** Users might not understand the need for QEMU or the implications of cross-compiling.

**8. Tracing User Actions to Reach the Code:**

I considered how a developer would typically interact with this script:

*   **Building Frida:** The most likely scenario is that a user is trying to build Frida, specifically the Node.js bindings.
*   **Using a Build System:** They would likely be using a build system like Meson, which this script integrates with.
*   **Configuration:** They might be providing configuration options through Meson or environment variables.
*   **Troubleshooting:** If the build fails, they might be examining the generated machine configuration files or looking at the script's output.

**9. Structuring the Answer:**

Finally, I organized the information into the requested categories (functionality, reverse engineering, low-level/kernel, logic/assumptions, user errors, and user journey), providing specific examples from the code for each point. I aimed for clarity and conciseness, explaining *why* each aspect was relevant.
This Python script, `env.py`, is a crucial part of the Frida build system, specifically for the Node.js bindings. Its primary function is to **generate machine-specific configuration files** that are used by the Meson build system to compile Frida for different target platforms.

Here's a breakdown of its functionalities:

**1. Generating Machine Configuration Files:**

*   The core purpose is to create text files (named like `frida-linux-x86_64.txt`) containing build settings tailored to a specific target machine (defined by its OS, architecture, etc.).
*   These configuration files are in a format that Meson can understand, defining things like compiler paths, linker flags, and other build options.
*   The script distinguishes between the **build machine** (where the compilation happens) and the **host machine** (the target where Frida will run), especially important for cross-compilation scenarios.

**2. Detecting and Configuring Toolchains and SDKs:**

*   It attempts to locate necessary build tools (compilers, linkers, binutils, etc.) based on the specified toolchain prefix and standard system paths.
*   It handles different compiler suites like GCC and MSVC, adapting the configuration accordingly.
*   It integrates with `pkg-config` to find libraries and their dependencies.
*   It can detect and utilize Vala compilers and related tools.
*   It allows specifying SDK prefixes, which are particularly important for cross-compiling for platforms like Android.

**3. Handling Cross-Compilation:**

*   The script explicitly supports cross-compilation, where the build machine and the target host machine have different architectures or operating systems.
*   It manages environment variables differently for the build and host environments in cross-compilation scenarios.
*   It includes logic to determine if an **executable wrapper** (like QEMU) is needed to run host binaries on the build machine during the build process.

**4. Abstracting Platform-Specific Logic:**

*   It uses separate modules (`env_android.py`, `env_apple.py`, `env_generic.py`) to handle platform-specific configurations, keeping the main logic cleaner.

**5. Integrating with Meson:**

*   It provides functions (`call_meson`, `query_meson_entrypoint`) to interact with the Meson build system.
*   It generates machine files in the format expected by Meson.

**Relationship to Reverse Engineering (with examples):**

This script is **fundamentally related to reverse engineering** because Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. This script sets up the build environment necessary to create Frida itself.

*   **Targeting Specific Architectures/OSes:** When reverse engineers want to analyze software on a specific platform (e.g., an ARM-based Android device), they need a version of Frida compiled for that target. This script is directly involved in configuring the build process for such targets. For example, if you're targeting an `arm64` Android device, this script, when invoked with the correct parameters, will generate a configuration file that tells Meson to use the appropriate Android NDK toolchain for that architecture.
*   **Cross-Compilation for Embedded Devices:** Reverse engineering often involves analyzing embedded systems with different architectures than the developer's machine. This script's cross-compilation capabilities are essential for building Frida that can run on these target devices. For instance, you might be developing on an x86-64 Linux machine but need to build Frida for an ARM-based IoT device. This script handles the complexities of using a cross-compiler.
*   **Interacting with System Libraries:** Frida often needs to interact with low-level system libraries on the target. The script's handling of `pkg-config` ensures that the build system can find these libraries and link against them correctly. This is critical for Frida's ability to hook into system calls and access internal data structures.
*   **Using Emulators (QEMU):** The script's `find_exe_wrapper` function, which can configure QEMU, is directly relevant to reverse engineering workflows that involve emulating target devices. For example, if you are building Frida for an architecture you don't have a physical machine for, you might set the `FRIDA_QEMU_SYSROOT` environment variable. This script will then configure Meson to use QEMU to run host tools during the build process, allowing for cross-compilation even without a native build environment.

**Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge (with examples):**

*   **Binary 底层 (Binary Low-Level):**
    *   The script deals with compiler and linker settings, which directly affect the generated binary code. It needs to understand the implications of different compiler flags and linker options for the target architecture's ABI (Application Binary Interface).
    *   The distinction between shared and static libraries (`DefaultLibrary` type hint) is a fundamental binary-level concept.
*   **Linux:**
    *   The script uses standard Linux conventions for file paths (e.g., `/usr/local`) and environment variables (e.g., `PATH`, `PKG_CONFIG_PATH`).
    *   It utilizes tools common on Linux systems like `pkg-config`, `flex`, `bison`, and potentially others in the toolchain.
    *   The detection of executable suffixes (`build_machine.executable_suffix`) acknowledges the lack of extensions for executables on Linux.
*   **Android Kernel & Framework:**
    *   The presence of `env_android.py` indicates specific handling for Android builds. This module would likely contain logic for locating the Android NDK, setting up the correct compiler flags for the Android ABI, and potentially handling framework-specific build requirements.
    *   The use of SDK prefixes (`build_sdk_prefix`, `host_sdk_prefix`) is crucial for Android development, where the SDK provides necessary libraries and tools.
    *   The script might need to handle variations in Android versions and their corresponding NDK revisions.

**Logic and Assumptions (with hypothetical input/output):**

*   **Assumption:** If `host_machine` is different from `build_machine`, it's a cross-compilation scenario.
    *   **Input:** `build_machine` is `linux-x86_64`, `host_machine` is `android-arm64`.
    *   **Output:** The `is_cross_build` variable will be `True`, and the script will generate separate configuration files for the build and host machines, potentially setting up QEMU for running host tools.
*   **Assumption:** Tools like `ninja` or `pkg-config` are either in the specified `toolchain_prefix` or in the system's `PATH`.
    *   **Input:** `toolchain_prefix` is `/opt/my-toolchain`, and it contains `ninja` and `pkg-config` executables.
    *   **Output:** The generated machine configuration file will likely contain entries like `binaries.ninja = ['/opt/my-toolchain/bin/ninja']` and `binaries.pkg-config = [...]`.
*   **Logic:** If `FRIDA_QEMU_SYSROOT` environment variable is set, attempt to find and use QEMU as an executable wrapper.
    *   **Input:** `environ["FRIDA_QEMU_SYSROOT"] = "/path/to/my/qemu-sysroot"`.
    *   **Output:** The `needs_exe_wrapper` will likely be `True`, and the `find_exe_wrapper` function will attempt to locate the appropriate `qemu-` binary for the target architecture and return the command to execute it.

**User or Programming Common Usage Errors (with examples):**

*   **Incorrect Toolchain Prefix:**
    *   **Error:** User provides a `toolchain_prefix` that doesn't contain the necessary compilers or build tools.
    *   **Consequence:** The script will fail to find the required binaries (like `gcc`, `g++`, `ninja`), leading to errors during the Meson configuration step.
*   **Missing or Incorrect SDK Paths (for cross-compilation):**
    *   **Error:** When cross-compiling for Android, the user doesn't provide the correct path to the Android NDK.
    *   **Consequence:** The `env_android` module will be unable to locate the Android-specific compilers and libraries, resulting in build failures.
*   **Misconfigured Environment Variables:**
    *   **Error:** User sets `PKG_CONFIG_PATH` incorrectly, pointing to directories that don't contain the required `.pc` files.
    *   **Consequence:** The script might not find necessary libraries, leading to linking errors during the build process.
*   **Forgetting to Install Dependencies:**
    *   **Error:** User tries to build Frida without having necessary system dependencies (like `glib`, `vala`, etc.) installed on the build machine.
    *   **Consequence:**  While this script itself might not directly detect missing *system* dependencies, the subsequent Meson configuration step will likely fail when it tries to find these dependencies using `pkg-config`.
*   **Cross-compilation without QEMU setup (when needed):**
    *   **Error:** User attempts to cross-compile for an architecture where host binaries cannot be run directly on the build machine, without setting `FRIDA_QEMU_SYSROOT`.
    *   **Consequence:** The build process will fail when trying to execute host tools (like code generators or preprocessors) that are built for the target architecture but cannot run on the build machine's architecture.

**User Operation Steps to Reach Here (as a debugging clue):**

1. **Developer wants to build Frida:** A developer wants to either build Frida from source or build the Node.js bindings for Frida.
2. **Navigates to the Frida repository:** The developer clones or navigates to the root directory of the `frida` project.
3. **Enters the Node.js bindings directory:** They navigate to `frida/frida-node`.
4. **Initiates the build process:** They typically use a command like `npm install` (if building the Node.js bindings) or a direct Meson command from the root Frida directory.
5. **Meson is invoked:** The `npm install` command (or direct Meson invocation) will trigger the Meson build system.
6. **Meson needs machine configuration:** Meson will need to determine the configuration for the build and host machines.
7. **`env.py` is executed:** Meson, as part of its configuration phase, will execute this `env.py` script. It will likely call functions within this script (like `generate_machine_configs`) with information about the target machine and specified build options.
8. **Machine configuration files are generated:**  `env.py` will create the `frida-<flavor>-<machine identifier>.txt` files in the specified build directory (`frida/subprojects/frida-node/build` or a similar location).
9. **Meson proceeds with the build:** Meson then reads these generated machine configuration files to understand how to compile Frida for the target platform.

**Therefore, if a developer is encountering issues related to the build process, especially during the configuration phase, looking at the generated machine configuration files and the logic within `env.py` can provide valuable debugging clues.** For instance, if the wrong compiler is being selected or if library paths are incorrect, the generated machine file will reflect these errors, and the logic in `env.py` is the place to investigate how those settings were determined.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
```