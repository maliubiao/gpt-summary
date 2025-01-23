Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `env.py` file within the Frida project. Specifically, the prompt asks for:

* **Functionality:** What does this code *do*?
* **Relevance to Reversing:** How does this relate to the field of reverse engineering?
* **Low-Level Aspects:** Connections to binary formats, Linux/Android kernels, and frameworks.
* **Logic and Inference:**  Examples of how inputs lead to specific outputs.
* **Common Usage Errors:**  Mistakes a user or programmer might make.
* **Debugging Context:** How a user might end up at this code during debugging.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords and structures that stand out include:

* **Imports:**  `configparser`, `dataclasses`, `os`, `pathlib`, `platform`, `subprocess`, `typing`. This suggests the code is involved in configuration, file system operations, running external commands, and dealing with different operating systems.
* **Class `MachineConfig`:** This likely represents the configuration for a specific target machine (where Frida will run).
* **Functions like `call_meson`, `load_meson_config`, `generate_machine_configs`, `generate_machine_config`:** These suggest a process of generating configuration files for the Meson build system.
* **Platform-specific logic:** `if machine.is_apple:`, `elif machine.os == "android":`, `else:`. This indicates the code adapts to different operating systems.
* **Environment variables:** References to `environ` and the `TOOLCHAIN_ENVVARS` set suggest handling build environments.
* **Execution wrappers (`needs_exe_wrapper`, `find_exe_wrapper`):**  Points to the possibility of needing to run executables in emulated environments (like using QEMU).

**3. Deeper Dive into Key Functions and Concepts:**

Once a high-level understanding is established, the next step is to examine the core functions more closely.

* **`generate_machine_configs` and `generate_machine_config`:** These are the central functions. They take information about the build and host machines and produce `MachineConfig` objects. The code within `generate_machine_config` populates a `ConfigParser` object with settings related to compilers, linkers, and other tools.
* **Meson Integration:**  The functions `call_meson`, `query_meson_entrypoint`, `load_meson_config`, and `query_machine_file_path` clearly indicate that this code is deeply integrated with the Meson build system. The generated configuration files are meant for Meson.
* **Toolchain Handling:** The code explicitly deals with `toolchain_prefix`, `sdk_prefix`, and environment variables related to compilers and build tools. This is crucial for cross-compilation.
* **Platform-Specific Implementations:** The calls to `env_apple.init_machine_config`, `env_android.init_machine_config`, and `env_generic.init_machine_config` show that the configuration process is customized for different operating systems. This is a key area to investigate for platform-specific behaviors relevant to reverse engineering.
* **Execution Wrappers (QEMU):**  The logic around `needs_exe_wrapper`, `can_run_host_binaries`, and `find_exe_wrapper` highlights the importance of being able to execute binaries built for the target architecture on the host machine. QEMU is a primary tool for this.

**4. Connecting to the Prompt's Specific Questions:**

With a solid understanding of the code's functionality, I can now address the specific points raised in the prompt:

* **Functionality:** Summarize the purpose of the code in clear terms (generating Meson configuration files).
* **Reversing:** Think about *why* Frida needs this. Frida instruments processes, which often involves dealing with compiled code. Cross-compilation and setting up the correct build environment are essential for targeting different architectures and operating systems. The ability to run target binaries on the host (using QEMU) is directly related to testing and analysis.
* **Low-Level:** Identify the parts of the code that directly interact with low-level concepts:  handling executable suffixes, setting up paths to compilers and linkers, using QEMU for emulation, and the general need to compile code for specific architectures.
* **Logic and Inference:**  Create concrete examples of how the code makes decisions. The cross-compilation logic and the QEMU wrapper selection are good examples. Choose specific inputs (e.g., `host_machine != build_machine`, `FRIDA_QEMU_SYSROOT` being set) and explain the resulting output.
* **Common Errors:** Consider what could go wrong. Incorrectly set environment variables, missing toolchains, and issues with QEMU are common pitfalls. Provide specific examples.
* **Debugging:**  Imagine a scenario where a user is encountering a build error or Frida isn't working correctly on a target device. Explain how they might trace the issue back to the configuration files generated by this code.

**5. Structuring the Explanation:**

Finally, organize the information logically and clearly, using the headings provided in the prompt as a guide. Use clear and concise language, and provide specific code snippets where appropriate to illustrate the points being made. Use bolding and formatting to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the code directly *compiles* Frida. **Correction:**  The code *configures the build environment* for Meson, which then handles the compilation.
* **Vague understanding of QEMU:** Initially, I might just say "it uses an emulator." **Refinement:**  Specifically mention QEMU and explain *why* it's needed (running host binaries).
* **Missing concrete examples:**  Initially, the explanations might be too abstract. **Refinement:** Add specific examples of environment variables, function calls, and conditional logic.

By following this structured approach, focusing on understanding the code's purpose and then addressing each aspect of the prompt systematically, a comprehensive and accurate explanation can be generated.
This Python file, `env.py`, plays a crucial role in the Frida build process by generating machine-specific configuration files that are used by the Meson build system. Essentially, it sets up the environment needed to compile Frida for various target platforms (like different operating systems and architectures).

Here's a breakdown of its functionalities:

**1. Generating Meson Configuration Files:**

* **Core Function:** The primary purpose of this file is to generate `.txt` files containing configuration settings for Meson. These files describe the target machine's architecture, operating system, available tools (like compilers, linkers), and other environment details.
* **`generate_machine_configs` and `generate_machine_config`:** These are the main functions responsible for this. They take information about the build machine (where the compilation is happening) and the host machine (the target where Frida will run) and create configuration files for each.
* **`MachineConfig` Class:** This dataclass holds the path to the generated machine file (`machine_file`), a list of directories to add to the `PATH` environment variable (`binpath`), and a dictionary of environment variables (`environ`).
* **ConfigParser:** The `ConfigParser` from the `configparser` module is used to structure the configuration data into sections like `constants`, `binaries`, `built-in options`, `properties`, and `host_machine`.

**2. Handling Cross-Compilation:**

* **`is_cross_build`:** The code detects if a cross-compilation is happening (i.e., the build machine and host machine are different).
* **Separate Configurations:**  It generates separate configuration files for the build machine and the host machine when cross-compiling.
* **Environment Variable Handling:** It intelligently filters and modifies environment variables based on whether it's for the build or host environment (e.g., using `build_envvar_to_host`).

**3. Detecting and Configuring Toolchains:**

* **`toolchain_prefix`:**  The code can take an optional `toolchain_prefix` argument, which points to a directory containing a custom toolchain (compilers, linkers, etc.).
* **Binary Detection:** It searches for common build tools like `ninja`, `gdbus-codegen`, `glib-compile-resources`, `flex`, `bison`, `nasm`, `pkg-config`, and `vala` within the toolchain prefix and system paths.
* **`binaries` Section:**  The paths to these detected tools are added to the `binaries` section of the Meson configuration.
* **`pkg-config` Integration:** It handles `pkg-config`, a utility to retrieve information about installed libraries. It can add flags to `pkg-config` calls depending on whether static or shared libraries are being built and if an SDK prefix is provided.
* **Vala Compiler Detection:** It specifically tries to detect the Vala compiler (`valac`) within the toolchain.

**4. Handling SDK Prefixes:**

* **`build_sdk_prefix` and `host_sdk_prefix`:**  The code can take optional arguments pointing to SDK (Software Development Kit) directories for the build and host machines.
* **`vala_args`:** If an SDK prefix is provided, it adds Vala API directory paths to the `vala_args` in the Meson configuration.
* **`pkg_config_path`:** It includes the `pkgconfig` directory from the SDK prefix in the `PKG_CONFIG_PATH`.
* **Adding Binaries from SDK:**  It can add specific binaries found within the SDK's `bin` directory to the Meson configuration.

**5. Handling Execution Wrappers (for Cross-Compilation):**

* **`needs_exe_wrapper` and `can_run_host_binaries`:**  These functions determine if an execution wrapper is needed to run binaries built for the host architecture on the build machine (common in cross-compilation scenarios).
* **QEMU Support:** If the environment variable `FRIDA_QEMU_SYSROOT` is set, the code assumes QEMU will be used as the execution wrapper and tries to locate the appropriate `qemu-*` binary.
* **`find_exe_wrapper`:** This function constructs the command to execute the host binary using QEMU.
* **`properties["needs_exe_wrapper"]`:** This setting in the Meson configuration indicates whether a wrapper is necessary.

**6. Platform-Specific Configurations:**

* **Conditional Logic:** The code uses `if machine.is_apple:`, `elif machine.os == "android":`, and `else:` to handle platform-specific configurations.
* **External Modules:** It imports and calls functions from `env_android.py`, `env_apple.py`, and `env_generic.py` to handle OS-specific setup details.

**7. Default Prefix Detection:**

* **`detect_default_prefix`:** This function determines the default installation directory for Frida based on the operating system (e.g., `Program Files\Frida` on Windows, `/usr/local` on Linux/macOS).

**Relationship to Reversing:**

This file is deeply intertwined with the process of reverse engineering, especially when using dynamic instrumentation tools like Frida:

* **Targeting Different Architectures:**  Reverse engineers often need to analyze software running on various architectures (ARM, x86, etc.) and operating systems (Android, iOS, Linux, Windows). This file ensures that Frida can be built correctly for these diverse targets. For example, when analyzing an Android application, this file will help configure the build to target the specific Android architecture (e.g., arm64-v8a).
* **Cross-Compilation for Mobile Devices:**  Building Frida for mobile platforms like Android and iOS typically involves cross-compilation from a desktop machine. This file manages the complexities of setting up the correct toolchains and SDKs for these cross-compilation scenarios.
* **Emulation and Execution:** When cross-compiling, you might need to run tools or libraries built for the target architecture on your development machine. The QEMU integration is directly related to this. For instance, if you're building Frida for an ARM device on an x86 machine, this file will help configure the use of QEMU to execute ARM binaries during the build process.
* **Setting up the Environment:**  Reverse engineering often requires setting up specific environments with particular libraries and dependencies. This file helps automate the configuration of these environments for building Frida. For example, if a target system relies on specific versions of GLib, the toolchain configuration here ensures the correct GLib tools are used during the Frida build.

**Examples Illustrating Relationship to Reversing:**

* **Scenario:** A reverse engineer wants to use Frida on an Android phone with an ARM64 processor.
    * **How `env.py` is involved:** This file will be executed during the Frida build process. Based on the target architecture (`arm64`) and operating system (`android`), it will:
        *  Invoke functions from `env_android.py` to handle Android-specific configurations (like finding the Android NDK).
        *  Configure the Meson build to use the appropriate ARM64 cross-compiler from the Android NDK.
        *  Potentially set up QEMU if needed for running host binaries during the build.
* **Scenario:** A reverse engineer is analyzing an iOS application and needs to build Frida for an iPhone.
    * **How `env.py` is involved:** Similar to the Android case, but it will invoke functions from `env_apple.py` to handle macOS/iOS-specific configurations, including code signing requirements and SDK paths.

**Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge:**

This file touches upon these areas in several ways:

* **Binary底层 (Binary Underpinnings):**
    * **Executable Suffixes:** The code deals with platform-specific executable suffixes (e.g., `.exe` on Windows). This is a fundamental concept in binary formats.
    * **Architecture Detection:** It relies on identifying the target machine's architecture (`machine.arch`), which is crucial for selecting the correct compiler and linker for binary code generation.
    * **Toolchain Binaries:** It directly interacts with binary tools like compilers (`gcc`, `clang`), linkers (`ld`), and archivers (`ar`).
* **Linux:**
    * **Path Separators:** It uses `os.pathsep` which is typically `:` on Linux, when constructing the `PATH` environment variable.
    * **Standard Directories:** It uses `/usr/local` as a default prefix, a common convention on Linux.
    * **`pkg-config`:**  `pkg-config` is heavily used on Linux systems to manage library dependencies.
* **Android Kernel & Framework:**
    * **Android NDK:**  The `env_android.py` module (not shown here but imported) will interact with the Android NDK (Native Development Kit), which provides tools and headers for building native code on Android. This involves understanding the structure and components of the Android system.
    * **OS and Architecture Identification:** The code needs to accurately identify that the target is Android and its specific architecture to configure the build process correctly.

**Logical Inference (Hypothesized Input and Output):**

Let's consider a simplified example:

**Hypothesized Input:**

* `build_machine`: A `MachineSpec` object representing a Linux x86_64 machine.
* `host_machine`: A `MachineSpec` object representing an Android ARM64 device.
* `environ`: A dictionary of environment variables, without `FRIDA_QEMU_SYSROOT` set.
* `toolchain_prefix`:  Path to an Android NDK toolchain for ARM64.
* `outdir`: A path to a temporary output directory.

**Expected Output (Simplified):**

* **`build_config`:** A `MachineConfig` object with a `machine_file` (e.g., `frida-linux-x86_64.txt`) containing Meson configuration for the build machine. This would likely include paths to standard Linux development tools.
* **`host_config`:** A `MachineConfig` object with a `machine_file` (e.g., `fridaandroid-arm64.txt`) containing Meson configuration for the Android ARM64 device. This would include:
    * Paths to the ARM64 compilers and linkers from the provided `toolchain_prefix`.
    * Potentially settings for `pkg-config` pointing to libraries in the Android NDK.
    * `properties["needs_exe_wrapper"]` set to `true`, as you can't directly run Android ARM64 binaries on a Linux x86_64 machine. The `binaries` section would *not* have an `exe_wrapper` defined in this scenario since `FRIDA_QEMU_SYSROOT` is not set.

**User/Programming Common Usage Errors:**

* **Incorrect Toolchain Path:** Providing an incorrect or incomplete path to the `toolchain_prefix`. This will lead to Meson not being able to find the necessary compilers and linkers, resulting in build errors.
    * **Example:**  `generate_machine_configs(..., toolchain_prefix="/path/to/incomplete/ndk", ...)`
* **Missing Environment Variables:** Failing to set necessary environment variables required by the build process or specific toolchains (though this file tries to be somewhat self-sufficient).
* **Mismatched Build and Host Architectures without QEMU:** Attempting to build for a different architecture without setting up QEMU (by setting `FRIDA_QEMU_SYSROOT`). This will cause issues when the build process tries to execute host binaries.
    * **Example:** Building for Android ARM64 on a Linux x86_64 machine without setting `FRIDA_QEMU_SYSROOT`.
* **Permissions Issues:** Having incorrect permissions on the toolchain or SDK directories, preventing the script from accessing the necessary files.

**How User Operations Reach This Point (Debugging Clues):**

A user might end up debugging this file in several scenarios:

1. **Build Failures:** If the Frida build process fails, especially during the configuration phase, the error messages from Meson might point to issues in the generated machine configuration files. A developer might then examine `env.py` to understand how these files are created.
2. **Cross-Compilation Problems:** When cross-compiling for a different architecture, errors related to finding the correct compilers, linkers, or execution wrappers could lead to investigating this file.
3. **Issues with Frida on a Specific Target:** If Frida behaves unexpectedly on a particular target device (e.g., crashes, fails to inject), developers might suspect issues with the build configuration for that target and examine how `env.py` configured the build.
4. **Toolchain Integration Problems:** If using a custom toolchain, and the build fails to pick up the correct tools, the logic in `env.py` for detecting and configuring toolchains would be a prime suspect.
5. **Examining Build System Internals:** Developers contributing to Frida or trying to understand its build system might explore this file to grasp how machine-specific configurations are handled.

**Debugging Steps that Might Lead Here:**

1. A user runs the Frida build command (e.g., `meson setup build --prefix=/opt/frida`).
2. Meson executes and calls scripts within the Frida build system, including `env.py`.
3. If Meson reports an error like "Unable to find compiler" or "Invalid machine specification," a developer might:
    * Examine the generated machine files in the `build` directory to see their contents.
    * Set breakpoints or add print statements in `env.py` to trace how the configuration is being generated.
    * Inspect the values of variables like `toolchain_prefix`, `environ`, `build_machine`, and `host_machine` to understand the input to the configuration process.
    * Investigate the platform-specific modules (`env_android.py`, `env_apple.py`) to see how they contribute to the configuration.

In essence, `env.py` is a foundational piece of the Frida build system, responsible for adapting the build process to the specifics of the target platform. Understanding its functionality is crucial for anyone involved in building, troubleshooting, or extending Frida, especially when dealing with cross-compilation or targeting diverse environments.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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