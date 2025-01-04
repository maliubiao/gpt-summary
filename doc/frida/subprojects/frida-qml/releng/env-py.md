Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the `env.py` file within the Frida project. The user also wants to know about its relevance to reverse engineering, its use of low-level/kernel concepts, any logical reasoning within the code, common user errors, and how a user might reach this code.

**2. Initial Code Scan and High-Level Interpretation:**

My first pass through the code focuses on identifying key components and their purpose. I see:

* **Imports:** `collections`, `configparser`, `dataclasses`, `os`, `pathlib`, `platform`, `pprint`, `shlex`, `shutil`, `subprocess`, `sys`, `typing`. These suggest interaction with the file system, environment variables, external processes, configuration files, and type hinting.
* **`@dataclass`:** The `MachineConfig` class uses this decorator, indicating it's a simple data holder.
* **Function Names:**  Names like `call_meson`, `query_meson_entrypoint`, `load_meson_config`, `generate_machine_configs`, `generate_machine_config`, `needs_exe_wrapper`, `find_exe_wrapper`, `make_pkg_config_wrapper`. These are very descriptive and hint at the core logic: managing configurations for different machines and environments, especially related to the Meson build system.
* **MachineSpec:**  The frequent use of `MachineSpec` suggests this is a crucial data structure representing a target machine's architecture, OS, etc.
* **Conditional Logic:**  `if machine.is_apple`, `elif machine.os == "android"`, `else`. This clearly indicates handling platform-specific configurations.
* **Environment Variables:**  The code interacts with environment variables (e.g., `environ`, `PATH`, `PKG_CONFIG_PATH`, `FRIDA_QEMU_SYSROOT`).
* **External Processes:** The use of `subprocess.run` and calls to tools like `meson`, `ninja`, `pkg-config`, `qemu` are apparent.
* **File I/O:**  Creating and writing to files (machine configuration files).

**3. Connecting to Frida's Purpose:**

Knowing Frida is a dynamic instrumentation toolkit, I start linking the code elements to that goal:

* **Dynamic Instrumentation Implies Execution:**  The need for setting up proper execution environments (PATH, libraries) becomes clear. The cross-compilation logic (`is_cross_build`) is relevant because Frida is often used to target devices with different architectures than the development machine.
* **Target Environments:** The platform-specific logic (`env_apple`, `env_android`, `env_generic`) directly relates to instrumenting different operating systems.
* **Build System Integration:**  The heavy reliance on Meson suggests this file is part of the build process for Frida, responsible for configuring the build for various target platforms.

**4. Addressing Specific Questions:**

Now I tackle each part of the user's request systematically:

* **Functionality:**  Summarize the core responsibilities identified in step 2, focusing on configuration generation for different machines, managing build tools, and handling cross-compilation.
* **Reverse Engineering:**  This is where I connect the dots. Frida is a reverse engineering tool. This code *supports* the creation of Frida for different targets. The ability to target different architectures and OSes is fundamental to reverse engineering. Examples include instrumenting Android or iOS apps from a Linux/macOS development machine. The `exe_wrapper` logic using QEMU is a direct link to emulating architectures for analysis.
* **Binary/Low-Level/Kernel/Framework Knowledge:**  Identify code elements that touch on these areas:
    * **Binary:**  Setting up paths for executables, handling executable suffixes, and the existence of tools like `objdump`, `readelf`.
    * **Linux/Android Kernel/Framework:** The explicit handling of Android, the use of `pkg-config` (common in Linux environments), and the concept of SDKs relate to these.
    * **Cross-compilation:**  This inherently involves understanding different architectures and their binary formats.
* **Logical Reasoning:** Look for conditional statements and their outcomes. The `needs_exe_wrapper` and `can_run_host_binaries` functions involve decision-making based on architecture and environment variables. Hypothesize different machine configurations and trace the code's logic.
* **User/Programming Errors:** Think about common mistakes when setting up build environments: incorrect paths, missing dependencies (like QEMU), conflicting environment variables.
* **User Steps to Reach Here:**  Trace back from the code's purpose. It's part of the build process. A user would likely be involved in setting up a development environment to build Frida for a specific target device. This might involve commands like `meson setup`, which would trigger the execution of this code.

**5. Structuring the Answer:**

Organize the findings clearly, using headings and bullet points to address each part of the user's question. Provide concrete examples to illustrate the points. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus too much on individual functions. **Correction:**  Shift to a higher-level view of the overall purpose and how the functions contribute to it.
* **Overlooking connections:**  Initially might miss the strong connection between the `exe_wrapper` and reverse engineering for different architectures. **Correction:** Emphasize this link with the QEMU example.
* **Too technical:**  Could use jargon that the user might not understand. **Correction:** Explain concepts clearly, especially when discussing kernel/framework specifics.

By following this thought process, I can systematically analyze the code and provide a comprehensive and informative answer to the user's request. The key is to understand the code's context within the larger Frida project and to connect its technical details to the user's specific questions about reverse engineering, low-level concepts, and potential errors.

这个Python文件 `env.py` 是 Frida 动态 instrumentation 工具构建系统的一部分，其主要功能是 **为不同的目标平台生成构建环境配置文件**。 这些配置文件会被 Meson 构建系统使用，以确保 Frida 能够正确地编译和链接到目标设备上。

下面是它各个功能的详细解释以及与您提出的问题的关联：

**1. 功能概述:**

* **定义数据结构 `MachineConfig`:**  这是一个简单的数据类，用于存储特定目标机器的配置信息，包括：
    * `machine_file`:  指向生成的 Meson 机器配置文件的路径。
    * `binpath`:  一个包含可执行文件路径的列表，用于添加到构建环境的 `PATH` 环境变量中。
    * `environ`:  一个包含需要设置的环境变量的字典。

* **调用 Meson 构建系统:**  `call_meson` 和 `query_meson_entrypoint` 函数用于执行 Meson 命令。它们可以根据是否使用子模块来确定 Meson 的入口点。

* **加载和查询机器配置文件:** `load_meson_config` 和 `query_machine_file_path` 函数用于加载或构建 Meson 的机器配置文件的路径。这些文件描述了目标机器的架构、操作系统等信息。

* **检测默认安装前缀:** `detect_default_prefix` 函数根据操作系统返回 Frida 的默认安装路径（例如 Windows 上的 `Program Files\Frida` 或 Linux/macOS 上的 `/usr/local`）。

* **生成机器配置 (`generate_machine_configs`, `generate_machine_config`):**  这是文件的核心功能。它负责为构建主机（执行构建的机器）和目标主机（Frida 将运行的机器）生成 `MachineConfig` 对象。
    * **处理交叉编译:**  如果构建主机和目标主机不同（交叉编译），它会采取不同的环境变量设置策略。
    * **平台特定配置:**  根据目标机器的操作系统（Apple, Android 或其他）调用相应的模块 (`env_apple`, `env_android`, `env_generic`) 来进行平台特定的配置。
    * **工具链配置:**  如果提供了工具链前缀，它会查找并配置各种构建工具（如 `ninja`, `gdbus-codegen`, `pkg-config`, `vala` 等）。
    * **SDK 配置:**  如果提供了 SDK 前缀，它会配置 Vala 的 VAPI 路径和 `pkg-config` 的搜索路径。
    * **生成 Meson 机器文件:**  最终，它将所有配置信息写入一个 `.txt` 文件，供 Meson 使用。

* **判断是否需要执行包装器 (`needs_exe_wrapper`, `can_run_host_binaries`):**  在交叉编译场景下，构建主机可能无法直接运行目标主机的可执行文件。这些函数判断是否需要使用类似 QEMU 的模拟器来运行这些程序。

* **查找执行包装器 (`find_exe_wrapper`):** 如果需要执行包装器，此函数会查找并配置 QEMU，前提是设置了 `FRIDA_QEMU_SYSROOT` 环境变量。

* **创建 `pkg-config` 包装器 (`make_pkg_config_wrapper`):**  为了在交叉编译环境下正确使用 `pkg-config`，此函数生成一个 Python 脚本作为包装器，确保 `pkg-config` 能找到目标平台的库。

* **检测工具链中的 Vala 编译器 (`detect_toolchain_vala_compiler`):**  如果提供了工具链前缀，此函数会尝试查找工具链中特定版本的 Vala 编译器。

* **转换环境变量名称 (`build_envvar_to_host`):**  用于在交叉编译时将构建主机的环境变量名称转换为目标主机的名称。

* **引用字符串 (`quote`):**  用于在命令行中正确引用包含空格的字符串。

**2. 与逆向方法的关系 (举例说明):**

该文件与逆向工程方法紧密相关，因为它 **负责构建用于逆向的 Frida 工具本身**。

* **交叉编译以分析目标设备:**  逆向工程师通常需要在自己的开发机上构建 Frida Agent，然后在目标设备（例如 Android 手机、iOS 设备）上运行。`env.py` 负责处理交叉编译的配置，确保生成的 Frida Agent 可以在目标设备的架构上运行。例如，你可能在 x86_64 的 Linux 机器上构建用于 ARM64 Android 设备的 Frida Agent。

* **模拟器支持:**  在某些情况下，目标设备可能不容易直接访问。`find_exe_wrapper` 函数通过配置 QEMU 这样的模拟器，允许在构建过程中执行目标平台的工具，这对于逆向分析至关重要。 例如，在为 ARM 架构的嵌入式设备构建 Frida 时，可以使用 QEMU 来模拟执行一些构建工具。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **二进制底层:**
    * **架构差异处理:** 文件中大量涉及 `MachineSpec`，包括 `cpu_family`, `cpu`, `endian` 等属性，这直接关系到不同 CPU 架构的二进制格式差异。例如，ARM 和 x86 架构的指令集和内存模型不同，构建 Frida 时需要针对这些差异进行配置。
    * **可执行文件后缀 (`executable_suffix`):**  不同操作系统有不同的可执行文件后缀（如 Windows 的 `.exe`，Linux/macOS 通常没有后缀），这个文件需要处理这些差异。

* **Linux:**
    * **`pkg-config`:**  该文件大量使用 `pkg-config` 来查找依赖库的信息。`pkg-config` 是 Linux 系统上常用的工具，用于管理库的编译和链接选项。
    * **环境变量 (`PATH`, `PKG_CONFIG_PATH`):**  构建过程依赖于正确的环境变量设置，例如 `PATH` 用于查找可执行文件，`PKG_CONFIG_PATH` 用于查找 `.pc` 文件。

* **Android 内核及框架:**
    * **`env_android` 模块:**  专门的 `env_android` 模块处理 Android 平台的特殊配置，例如 NDK 的使用、系统库的链接等。
    * **SDK 前缀 (`sdk_prefix`):**  Android 开发需要使用 Android SDK，该文件可以配置 SDK 的路径，以便找到必要的头文件和库。

**4. 逻辑推理 (假设输入与输出):**

假设输入：

* `build_machine`:  一个 `MachineSpec` 对象，描述构建主机的架构，例如 `MachineSpec(system='Linux', subsystem='...', kernel='Linux', cpu_family='x86_64', cpu='x86_64', endian='little')`.
* `host_machine`:  一个 `MachineSpec` 对象，描述目标主机的架构，例如 `MachineSpec(system='Android', subsystem='...', kernel='Linux', cpu_family='arm64', cpu='arm64', endian='little')`.
* `environ`:  一个包含当前环境变量的字典。
* `toolchain_prefix`:  指向交叉编译工具链的路径，例如 `/opt/android-toolchain`.
* `default_library`:  字符串 "shared" 或 "static"，指定默认构建共享库还是静态库。
* `outdir`:  输出目录的路径，例如 `/path/to/frida/build/`.

逻辑推理与输出：

* **`is_cross_build`:**  由于 `build_machine` 和 `host_machine` 不同，`is_cross_build` 将为 `True`。
* **`generate_machine_config` 调用:**  会分别调用 `generate_machine_config` 为构建主机和目标主机生成配置。目标主机的调用会进入 `elif machine.os == "android":` 分支，调用 `env_android.init_machine_config`。
* **工具链配置:**  由于提供了 `toolchain_prefix`，代码会尝试在工具链的 `bin` 目录下查找 `ninja`, `pkg-config` 等工具，并将它们的路径添加到 `binaries` 配置中。
* **`pkg-config` 配置:** 如果 `default_library` 是 "static"，生成的 `pkg-config` 命令将包含 `--static` 参数。
* **生成机器文件:**  最终会在 `outdir` 中生成两个文件，例如 `frida-linux-x86_64.txt` (构建主机配置) 和 `frida-android-arm64.txt` (目标主机配置)。这些文件包含了 Meson 构建系统所需的配置信息。

**5. 用户或编程常见的使用错误 (举例说明):**

* **错误的工具链路径:** 用户可能提供了错误的 `toolchain_prefix`，导致构建系统找不到必要的交叉编译工具，从而在配置阶段失败。例如，如果用户将 `toolchain_prefix` 设置为 `/opt/wrong-toolchain`，而该目录下没有 `bin/gcc` 或 `bin/ld` 等工具，构建将会出错。

* **缺少 QEMU 或未设置 `FRIDA_QEMU_SYSROOT`:**  如果用户尝试为无法直接运行可执行文件的目标平台构建，并且没有安装 QEMU 或没有设置 `FRIDA_QEMU_SYSROOT` 环境变量，`find_exe_wrapper` 函数会抛出 `QEMUNotFoundError` 异常。 这通常发生在交叉编译到不同架构的嵌入式设备时。

* **`PKG_CONFIG_PATH` 设置不正确:**  如果目标平台依赖的库的 `.pc` 文件不在默认的 `PKG_CONFIG_PATH` 中，用户可能需要手动设置该环境变量，否则构建系统可能找不到这些库。例如，在为某个特定的 Linux 发行版构建 Frida 时，可能需要设置 `PKG_CONFIG_PATH` 指向该发行版特定的库路径。

**6. 用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户尝试构建 Frida:** 用户通常会从 Frida 的源代码仓库开始，并按照官方文档的指示进行构建。这通常涉及到使用 `git clone` 克隆仓库。
2. **运行 Meson 配置命令:**  用户会执行类似 `meson setup build --prefix=/opt/frida --default-library=shared -Dfrida_ Host=android,arm64` 这样的命令。
3. **Meson 执行 `env.py`:**  当 Meson 处理配置命令时，它会执行 `frida/subprojects/frida-qml/releng/env.py` 文件，因为这个文件定义了如何为不同的目标平台生成构建环境。
4. **`generate_machine_configs` 被调用:**  Meson 会根据用户提供的目标平台信息（`Host=android,arm64`）以及构建主机的环境信息，调用 `generate_machine_configs` 函数。
5. **平台特定配置执行:**  在 `generate_machine_configs` 内部，会根据目标平台调用相应的平台特定配置函数（例如 `env_android.init_machine_config`）。
6. **生成机器配置文件:**  `generate_machine_config` 函数会将配置信息写入到类似 `build/frida-android-arm64.txt` 的文件中。
7. **Meson 使用配置文件:**  后续的 Meson 构建步骤会读取这些生成的机器配置文件，以便正确地编译和链接 Frida。

**调试线索:** 如果用户在构建 Frida 时遇到问题，可以检查以下内容：

* **Meson 的输出:**  Meson 的输出通常会显示执行 `env.py` 时的信息，包括使用的参数和生成的配置文件路径。
* **生成的机器配置文件内容:**  检查 `build/frida-*.txt` 文件的内容，确认配置是否正确，例如工具链路径、SDK 路径、环境变量等。
* **环境变量:**  确认构建环境中相关的环境变量（如 `PATH`, `PKG_CONFIG_PATH`, `FRIDA_QEMU_SYSROOT`) 是否设置正确。
* **工具链和 SDK:**  确认交叉编译工具链和目标平台的 SDK 是否已正确安装并可访问。

总而言之，`frida/subprojects/frida-qml/releng/env.py` 是 Frida 构建流程中至关重要的一环，它负责根据目标平台的需求生成构建环境配置，使得 Frida 能够跨平台编译和运行，这对于其作为动态 instrumentation 工具的功能至关重要，也与逆向工程实践息息相关。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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