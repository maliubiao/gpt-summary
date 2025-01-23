Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its function and relevance to reverse engineering, low-level details, and potential user errors.

**1. Initial Skim and High-Level Understanding:**

* **Keywords and Imports:**  The presence of `frida`, `meson`, `subprocess`, `os`, `platform`, `configparser` immediately suggests this code is involved in the build process of the Frida dynamic instrumentation tool. `meson` strongly indicates a build system. `subprocess` hints at interacting with external tools.
* **Class `MachineConfig`:** This likely holds configuration information specific to a target machine (architecture, OS, etc.).
* **Functions with `meson`:** Functions like `call_meson`, `query_meson_entrypoint`, `load_meson_config`, and `query_machine_file_path` clearly point to interaction with the Meson build system.
* **Platform-Specific Logic:** The `if machine.is_apple` and `elif machine.os == "android"` blocks indicate handling different operating systems.
* **Toolchain and SDK:**  Variables like `toolchain_prefix` and `sdk_prefix` suggest the code manages dependencies on compilers and libraries.
* **Execution Wrapper:**  The functions `needs_exe_wrapper`, `can_run_host_binaries`, and `find_exe_wrapper` suggest handling cross-compilation scenarios where directly running binaries on the build machine isn't possible.

**2. Decomposition by Function and Purpose:**

* **`MachineConfig`:**  Understood as a data container for machine-specific build settings.
* **`call_meson`, `query_meson_entrypoint`:**  Helper functions to execute Meson commands. The `use_submodule` parameter is interesting – it suggests Frida might bundle its own Meson version.
* **`load_meson_config`, `query_machine_file_path`:**  Functions to manage Meson configuration files per target machine and "flavor" (likely debug/release).
* **`detect_default_prefix`:** Determines the default installation directory based on the host OS.
* **`generate_machine_configs`, `generate_machine_config`:**  The core logic for creating the machine-specific configuration. This involves:
    * Determining if it's a cross-build.
    * Creating `build_config` and potentially `host_config`.
    * Calling platform-specific initialization (`env_apple.init_machine_config`, etc.).
    * Handling toolchain and SDK paths.
    * Detecting and configuring tools like `pkg-config`, `vala`, `qmake`.
    * Managing execution wrappers for cross-compilation.
* **`needs_exe_wrapper`, `can_run_host_binaries`, `find_exe_wrapper`:**  Crucial for cross-compilation. The logic in `can_run_host_binaries` is particularly important for understanding when a wrapper is needed (different OS, architecture incompatibilities).
* **`make_pkg_config_wrapper`:** Generates a Python script to wrap `pkg-config`, potentially to customize its behavior (like setting `PKG_CONFIG_PATH`).
* **`detect_toolchain_vala_compiler`:**  Looks for a Vala compiler within the provided toolchain.
* **`build_envvar_to_host`:** A utility to adjust environment variable names during cross-compilation.
* **`quote`:**  A simple helper for quoting strings for command-line use.
* **`QEMUNotFoundError`:** A custom exception.
* **`INTERNAL_MESON_ENTRYPOINT`:**  The path to the bundled Meson.
* **`TOOLCHAIN_ENVVARS`:** A list of environment variables related to build tools.
* **`QEMU_ARCHS`:**  A mapping of Frida architecture names to QEMU architecture names.

**3. Identifying Connections to Reverse Engineering, Low-Level Details, etc.:**

* **Reverse Engineering:** Frida itself is a reverse engineering tool. This script sets up the *build environment* for Frida, which is essential for creating the tools used for reverse engineering. The cross-compilation aspects are important because you often target devices with different architectures (e.g., ARM Android devices from an x86 development machine).
* **Binary/Low-Level:** The script deals with compilers, linkers, and other binary tools. It manipulates paths to executables and sets environment variables that affect the compilation and linking process. The handling of architecture (`machine.arch`) and operating system (`machine.os`) is fundamental to low-level concerns.
* **Linux/Android Kernel/Framework:** The `env_android.py` module (imported but not shown) would contain logic specific to building Frida for Android, potentially interacting with the Android NDK and understanding Android's runtime environment. The mention of `qemu` and `FRIDA_QEMU_SYSROOT` strongly suggests support for emulating Android or other targets.
* **Logic and Assumptions:** The logic in `can_run_host_binaries` makes assumptions about when direct execution is possible based on the build and host architectures and operating systems. The `FRIDA_CAN_RUN_HOST_BINARIES` environment variable provides a way to override these assumptions.
* **User Errors:** Misconfigured toolchain paths, missing dependencies (like QEMU), or incorrect environment variables are common pitfalls.

**4. Generating Examples and Explanations:**

Based on the decomposed understanding, it's now possible to generate specific examples for each aspect:

* **Reverse Engineering:**  Focus on cross-compilation and how this script enables building Frida for different architectures.
* **Binary/Low-Level:**  Highlight the management of compiler paths, linker flags, and environment variables like `PATH`.
* **Linux/Android:** Explain the use of `qemu` and how the script might interact with Android-specific build tools.
* **Logic:** Demonstrate the `can_run_host_binaries` logic with different build/host machine combinations.
* **User Errors:** Provide concrete examples of incorrect paths or missing tools and how they would manifest.
* **User Steps:** Trace the user's actions from initiating a build to where this script plays a role.

**5. Iteration and Refinement:**

After the initial pass, review the code and explanations for clarity, accuracy, and completeness. Are there any edge cases missed? Are the examples clear and illustrative?  For instance, the `pkg-config` wrapper is a detail that deserves explanation in the context of potentially needing to customize `pkg-config` behavior for cross-compilation.

This systematic approach of skimming, decomposing, connecting to the requirements, generating examples, and refining allows for a thorough understanding of the code's functionality and its relevance to the given context.
This Python code, located in `frida/subprojects/frida-swift/releng/env.py`, is a crucial part of Frida's build system, specifically responsible for **generating configuration files for the Meson build system**. These configuration files define the build environment for different target machines (architectures, operating systems, etc.) where Frida will be used.

Here's a breakdown of its functionalities:

**1. Machine Configuration Generation:**

* **Purpose:** The core function is to create "machine files" (e.g., `frida-linux-x86_64.txt`) that Meson uses to understand the target platform's characteristics and how to build software for it.
* **Input:** It takes information about the build machine (where the compilation happens) and the host machine (where the built Frida will run). This includes the operating system, architecture, CPU family, endianness, and potentially information about toolchains and SDKs.
* **Output:**  It generates a text file in a specific format that Meson can parse. This file contains definitions for:
    * **Constants:**  Potentially fixed values related to the target.
    * **Binaries:** Paths to essential build tools like compilers (gcc, clang, msvc), linkers, and other utilities (like `pkg-config`, `vala`, `qmake`, `ninja`).
    * **Built-in Options:** Meson-specific options that control the build process (e.g., the C runtime library to use on Windows).
    * **Properties:**  Flags or settings related to the target environment (e.g., whether an execution wrapper is needed).
    * **Host Machine Information:** Details about the target machine itself.
* **Cross-Compilation Handling:** It intelligently handles cross-compilation scenarios where the build machine and the host machine are different.

**2. Toolchain and SDK Management:**

* **Toolchain Detection:**  It attempts to locate common build tools, potentially within a specified toolchain prefix. This is important for cross-compilation where standard system tools might not be for the target architecture.
* **SDK Integration:** It allows specifying paths to Software Development Kits (SDKs) for the target platform. This ensures that the build process can find necessary libraries and headers.
* **`pkg-config` Integration:** It configures `pkg-config`, a utility used to retrieve information about installed libraries, ensuring it searches in the correct locations (especially if an SDK prefix is provided). It can even create a wrapper script for `pkg-config` to customize its behavior.
* **Vala Support:** It detects and configures the Vala compiler if available in the toolchain.

**3. Execution Wrapper for Cross-Compilation:**

* **Problem:** When cross-compiling, you can't directly run binaries built for the target architecture on the build machine.
* **Solution:**  It detects if an "execution wrapper" (like `qemu`) is needed and configures Meson to use it when running target executables during the build process (e.g., for generating code or running tests).
* **`can_run_host_binaries` Logic:**  It implements logic to determine if the build machine can directly execute binaries for the host machine based on the OS and architecture. This avoids unnecessary wrapper usage when possible.

**4. Platform-Specific Logic:**

* **Apple and Android:**  The code imports modules `env_apple` and `env_android` to handle platform-specific configurations for macOS/iOS and Android respectively. This allows for tailoring the build process to the specific requirements of these platforms.
* **Generic Handling:**  `env_generic` handles configurations for other platforms.

**5. User Environment Consideration:**

* **Environment Variables:** It reads environment variables (like `PKG_CONFIG_PATH`, `FRIDA_QEMU_SYSROOT`) to customize the build process.
* **Tool Detection:** It uses `shutil.which` to find tools in the system's PATH if they aren't explicitly provided in a toolchain prefix.

**Relation to Reverse Engineering:**

This script is directly related to reverse engineering because **Frida itself is a dynamic instrumentation toolkit used for reverse engineering**. This script is responsible for setting up the build environment to *build* Frida for various target platforms that reverse engineers might want to analyze (Android apps, iOS apps, embedded devices, etc.).

* **Cross-Compilation for Target Devices:**  A common scenario in reverse engineering is analyzing software on a different architecture than the development machine. This script enables building Frida for those target architectures (e.g., building Frida for an ARM Android device on an x86 Linux machine).
* **Building Frida for Specific Environments:** Reverse engineers might need to build Frida with specific dependencies or configurations to work correctly in a particular target environment. This script provides the flexibility to manage those dependencies and settings.

**Examples Linking to Binary, Linux, Android Kernel/Framework:**

* **Binary Bottom Layer:**
    * **Compiler and Linker Paths:** The script explicitly deals with finding and setting paths to compilers (like `gcc`, `clang`, MSVC) and linkers. This is fundamental to the binary compilation process.
    * **`objcopy`, `objdump`, `strip`:** The `TOOLCHAIN_ENVVARS` list includes these binary utilities, which are used for manipulating object files and executables at a low level.
    * **Execution Wrappers (`qemu`):**  Using `qemu` to run target binaries during the build process directly interacts with binary execution and emulation.
* **Linux:**
    * **`pkg-config`:** This is a standard utility on Linux (and other Unix-like systems) for managing library dependencies. The script's interaction with `pkg-config` is Linux-specific.
    * **Environment Variables:**  Linux environments heavily rely on environment variables like `PATH` and `PKG_CONFIG_PATH`, which the script manipulates.
* **Android Kernel and Framework:**
    * **`env_android.py`:** This separate module would contain logic specific to the Android build process, potentially interacting with the Android NDK (Native Development Kit) and understanding the structure of Android system libraries.
    * **Cross-Compilation to ARM:** Building Frida for Android involves cross-compiling to ARM architectures, which is a key focus of this script.
    * **SDK Prefix for Android:** Specifying an Android SDK prefix allows the build system to find Android-specific libraries and headers.

**Logical Reasoning with Assumptions:**

* **Assumption:** If a `toolchain_prefix` is provided, the script assumes that the essential build tools are located within the `bin` subdirectory of that prefix.
* **Input:** `toolchain_prefix = Path("/opt/my-android-toolchain")`
* **Output:** The script will attempt to locate binaries like `gcc`, `g++`, `ld`, etc., in `/opt/my-android-toolchain/bin/`.
* **Assumption:** The presence of the environment variable `FRIDA_QEMU_SYSROOT` indicates that cross-compilation requiring an execution wrapper is intended.
* **Input:** `environ = {"FRIDA_QEMU_SYSROOT": "/path/to/my/qemu/sysroot"}`
* **Output:** The script will search for a `qemu-<target_arch>` binary in the system's PATH and configure Meson to use it with the specified sysroot.

**User and Programming Errors:**

* **Incorrect Toolchain Path:**
    * **User Action:**  Providing an incorrect path to the toolchain prefix (e.g., through a command-line argument or environment variable).
    * **How it reaches here:** The `generate_machine_configs` or `generate_machine_config` functions receive this path.
    * **Error:** Meson configuration will fail because the script won't be able to find the necessary compilers and linkers. Meson will report errors about missing executables.
* **Missing Dependencies (e.g., QEMU):**
    * **User Action:** Attempting a cross-compilation that requires QEMU without having QEMU installed or in the system's PATH.
    * **How it reaches here:** If `FRIDA_QEMU_SYSROOT` is set, the `find_exe_wrapper` function will be called.
    * **Error:** A `QEMUNotFoundError` will be raised, indicating that the required QEMU binary couldn't be found.
* **Incorrect SDK Path:**
    * **User Action:** Providing an incorrect path to the SDK prefix.
    * **How it reaches here:** The `generate_machine_configs` or `generate_machine_config` functions receive this path.
    * **Error:**  The build process might fail later when linking, as the linker won't be able to find the necessary libraries in the specified SDK path. `pkg-config` might also fail to find package information.
* **Conflicting Environment Variables:**
    * **User Action:** Setting environment variables that conflict with the intended build setup (e.g., an incorrect `PKG_CONFIG_PATH` that hides the correct library information).
    * **How it reaches here:** The script reads environment variables directly using `os.environ`.
    * **Error:** The build might link against the wrong versions of libraries or fail to find required packages.

**User Operation to Reach Here (Debugging Clues):**

1. **User Initiates a Frida Build:** The user would typically run a command to build Frida, often involving Meson directly (e.g., `meson setup build`).
2. **Meson Invokes Configuration Generation:** During the `meson setup` phase, Meson needs to understand the build environment for the target platform. It will call into Frida's build scripts to generate the necessary machine files.
3. **`generate_machine_configs` is Called:**  A part of Frida's build system will call the `generate_machine_configs` function in `env.py`. This function is responsible for orchestrating the creation of the build and host machine configurations.
4. **`generate_machine_config` is Called (Multiple Times):**  `generate_machine_configs` will call `generate_machine_config` for both the build machine and the host machine (if cross-compiling).
5. **Machine-Specific Logic Executes:** Inside `generate_machine_config`, the code will determine the target OS and call the appropriate platform-specific initialization function (e.g., `env_apple.init_machine_config` or `env_android.init_machine_config`).
6. **Machine File is Created:** Finally, the generated configuration is written to a file (e.g., `frida-linux-x86_64.txt`) in the build directory.

By examining the arguments passed to `generate_machine_configs` and `generate_machine_config`, the contents of the generated machine files, and the environment variables active during the build process, a developer or troubleshooter can understand how the build environment is being configured and diagnose potential issues.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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