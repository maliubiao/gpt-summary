Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `env.py` within the Frida project, specifically focusing on its role in setting up the build environment. The prompt also emphasizes connections to reverse engineering, low-level concepts, logical reasoning, common errors, and debugging context.

**2. Initial Code Scan and High-Level Understanding:**

* **Imports:** Recognize standard libraries (collections, configparser, dataclasses, os, pathlib, platform, subprocess, sys, typing) and internal Frida modules (`env_android`, `env_apple`, `env_generic`, `machine_file`, `machine_spec`). This suggests the script is involved in configuration and potentially platform-specific logic.
* **`MachineConfig` Dataclass:** This likely represents the final configuration for a specific machine (build or host). Key attributes are `machine_file`, `binpath`, and `environ`.
* **`generate_machine_configs` and `generate_machine_config`:** These are the core functions for creating `MachineConfig` instances. The presence of both suggests a distinction between build and host machines in cross-compilation scenarios.
* **`call_meson` and related functions:**  Indicates interaction with the Meson build system, a central part of Frida's build process.
* **Platform-specific logic:** The `if machine.is_apple:`, `elif machine.os == "android":`, and `else:` block clearly points to handling different operating systems.
* **Toolchain Handling:**  Keywords like `toolchain_prefix`, `sdk_prefix`, and the section on finding tools (`ninja`, `gdbus-codegen`, etc.) highlight the management of compiler and utility paths.
* **Environment Variables:**  The code manipulates environment variables extensively, indicating their crucial role in the build process.

**3. Deeper Dive into Key Functions and Concepts:**

* **`generate_machine_config` (Central Logic):**
    * **Purpose:** Creates the configuration file (`frida-{identifier}.txt`) that Meson uses.
    * **Steps:**
        * Initializes a `ConfigParser` to structure the configuration.
        * Populates sections like `constants`, `binaries`, `built-in options`, `properties`, and `host_machine`.
        * Delegates platform-specific initialization to `env_apple`, `env_android`, or `env_generic`.
        * Handles toolchain discovery (compilers, linkers, utilities).
        * Manages `pkg-config` and Vala compiler settings.
        * Determines the need for an "exe_wrapper" for cross-compilation.
    * **Key Observation:** This function is the orchestrator of environment setup.

* **Cross-Compilation (`is_cross_build`):**
    * **Importance:**  Recognize the distinction between `build_machine` and `host_machine`. This is fundamental for understanding why certain steps are necessary (like `exe_wrapper`).
    * **Environment Variable Handling:** Note how environment variables are filtered and potentially renamed (`build_envvar_to_host`).

* **Toolchain Discovery:**
    * **Methods:**  Looks for tools in `toolchain_prefix/bin` and uses `shutil.which` to find them in the system's PATH.
    * **Relevance to Reverse Engineering:** Understanding where these tools are located is crucial for using them in reverse engineering workflows.

* **`pkg-config` and Vala:**
    * **Purpose:**  `pkg-config` helps find library dependencies. Vala is a programming language used in some parts of Frida.
    * **`make_pkg_config_wrapper`:** Understands the need for a wrapper script to adjust `PKG_CONFIG_PATH` in cross-compilation scenarios.

* **`needs_exe_wrapper` and `find_exe_wrapper`:**
    * **Reasoning:**  When the build machine can't directly run binaries for the host architecture (cross-compilation), a tool like `qemu` is needed as an intermediary.

* **Meson Integration:**
    * **`call_meson` and `query_meson_entrypoint`:** Shows how this script interacts with the Meson build system. The machine configuration files generated are fed into Meson.

**4. Connecting to Prompt Requirements:**

* **Reverse Engineering:**  Consider how Frida is used in reverse engineering. The tools configured by this script (debuggers, disassemblers, etc.) are directly relevant.
* **Binary/Kernel/Framework:**  Think about the different levels of the system that Frida interacts with. The toolchain is essential for compiling code that runs at the binary level. Android framework knowledge is relevant for targeting Android.
* **Logical Reasoning:** Analyze the conditional logic (e.g., `if is_cross_build:`, platform checks). Trace the flow of data and decisions. Consider "what if" scenarios.
* **User Errors:** Think about common mistakes users might make when setting up their environment or using Frida.
* **Debugging:**  Imagine how a developer would use this script and what kind of issues they might encounter. The `print` statements in the initial exploration are a good starting point.

**5. Structuring the Explanation:**

Organize the findings into logical sections, as requested by the prompt:

* **Functionality:** Provide a concise overview of the script's purpose.
* **Reverse Engineering Relevance:**  Connect the script's actions to common reverse engineering tasks.
* **Low-Level Concepts:** Explain how the script interacts with the binary level, kernel, and frameworks.
* **Logical Reasoning:**  Illustrate the decision-making process within the code with concrete examples.
* **User Errors:**  Provide practical examples of common mistakes.
* **User Journey (Debugging):** Describe the steps a user might take that lead to this script being executed.

**6. Refining and Adding Detail:**

* **Code Examples:**  Where appropriate, include snippets of code to illustrate points.
* **Terminology:**  Use accurate technical terms related to building software and reverse engineering.
* **Clarity:**  Ensure the explanation is easy to understand, even for someone who might not be deeply familiar with Frida's internals.
* **Completeness:** Cover all the significant aspects of the script's functionality.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This script just generates some environment variables."  **Correction:**  Realize it's more sophisticated, generating full Meson machine configuration files.
* **Focus on individual functions:**  Initially might analyze each function in isolation. **Correction:** Understand the relationships between functions and how they contribute to the overall goal.
* **Overlook subtle details:** Miss nuances like the `pkg-config` wrapper. **Correction:**  Pay closer attention to the details of each code block.
* **Assume too much prior knowledge:**  Write explanations that are too technical. **Correction:**  Explain concepts in a way that is accessible to a broader audience.

By following this iterative process of exploration, analysis, and refinement, we arrive at a comprehensive and accurate explanation of the `env.py` script.
好的，让我们详细分析一下 `frida/subprojects/frida-clr/releng/env.py` 这个文件。

**文件功能概览**

`env.py` 文件的主要功能是为 Frida 的 CLR (Common Language Runtime) 组件构建过程生成和管理构建环境配置文件。它负责：

1. **定义构建和主机机器的配置 (Machine Configuration):**  它会根据目标平台（例如，Android、iOS、Linux、Windows）和架构，收集必要的信息，例如操作系统类型、CPU 架构、字节序等。
2. **生成 Meson 构建系统的机器文件:** Meson 是 Frida 使用的构建系统。`env.py` 生成的机器文件（通常命名为 `frida-<flavor>-<identifier>.txt`）包含了特定构建环境所需的编译器、链接器、工具链路径以及其他构建选项。
3. **管理工具链和 SDK 路径:**  它会查找并配置构建所需的工具链（例如 GCC、Clang、MSVC）和 SDK 的路径。这包括编译器、链接器、构建工具（如 `ninja`）、以及平台特定的工具。
4. **处理交叉编译场景:** 当构建机器（执行构建的机器）和主机机器（目标运行环境）不同时，它会进行相应的配置，例如设置 QEMU 作为执行包装器 (executor wrapper)。
5. **设置环境变量:** 它会设置构建过程中需要的环境变量，例如 `PATH`、`PKG_CONFIG_PATH` 等。
6. **为不同平台提供定制化配置:**  它会根据目标平台调用相应的模块 (`env_android.py`, `env_apple.py`, `env_generic.py`) 来进行平台特定的配置。

**与逆向方法的关系及举例说明**

`env.py` 虽然本身不是一个直接进行逆向操作的工具，但它为 Frida 的构建过程奠定了基础，而 Frida 本身是强大的动态 instrumentation 工具，广泛应用于逆向工程。

* **配置用于构建 Frida 的环境:**  逆向工程师如果需要修改 Frida 的源代码或者为特定的目标平台构建 Frida，就需要依赖 `env.py` 来正确配置构建环境。例如，如果要在 Android 设备上使用自定义的 Frida 版本，就需要配置 Android NDK 的路径，`env.py` 会负责处理。
* **间接影响 Frida 的功能:**  `env.py` 生成的配置直接影响 Frida 最终构建出的库和工具的功能。例如，如果配置中缺少了某些依赖库的路径，可能会导致 Frida 的某些功能无法正常使用，而这些功能可能正是逆向工程师需要的（如与特定 API 的交互）。
* **调试 Frida 自身:** 当 Frida 本身出现问题时，理解其构建过程和环境配置对于调试非常有帮助。逆向工程师可能需要查看 `env.py` 生成的机器文件，了解 Frida 在特定平台上的编译选项和依赖关系。

**举例说明:**

假设一个逆向工程师想要在 Android 上使用 Frida 来 hook 一个使用了特定加密算法的 native 函数。如果该加密算法的库不在 Frida 默认的依赖中，工程师可能需要：

1. **修改 Frida 的构建配置:** 这可能涉及到修改 Frida 的 `meson.build` 文件，或者通过环境变量传递额外的编译选项。
2. **重新构建 Frida:** 这时 `env.py` 就会发挥作用，它会根据 Android NDK 的配置，以及可能修改过的环境变量，生成新的机器文件，指导 Meson 正确编译包含新依赖的 Frida 版本。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

`env.py` 在配置构建环境时，需要了解一些底层的知识：

* **二进制底层知识:**
    * **目标架构 (Architecture):**  它需要知道目标设备的 CPU 架构（例如 ARM, ARM64, x86, x86_64），以便选择正确的编译器和链接器。例如，在 `generate_machine_config` 函数中，会根据 `machine.arch` 来设置 QEMU 的 flavor。
    * **字节序 (Endianness):**  某些平台使用大端字节序，而另一些使用小端字节序。构建过程可能需要根据目标平台的字节序进行调整。`env.py` 中的 `machine.endian` 属性就反映了这一点。
    * **可执行文件后缀 (Executable Suffix):**  不同的操作系统有不同的可执行文件后缀（例如，Windows 是 `.exe`，Linux 和 macOS 通常没有后缀）。`env.py` 会根据目标平台设置正确的后缀，例如在查找 `ninja` 时会尝试 `ninja.exe` 或 `ninja`。

* **Linux 知识:**
    * **环境变量:**  Linux 系统广泛使用环境变量来配置软件的行为。`env.py` 会读取和设置各种环境变量，例如 `PATH`（用于查找可执行文件）、`PKG_CONFIG_PATH`（用于查找库的 `.pc` 文件）。
    * **工具链路径:**  在 Linux 上构建软件通常需要指定编译器（如 GCC 或 Clang）的路径。`env.py` 会尝试在 `toolchain_prefix` 中查找这些工具。
    * **`pkg-config` 工具:**  `env.py` 会检测和配置 `pkg-config` 工具，这是一个用于获取库的编译和链接选项的实用程序，在 Linux 开发中非常常见。

* **Android 内核及框架知识:**
    * **Android NDK (Native Development Kit):**  构建 Android native 代码需要使用 NDK。`env_android.py` 模块会处理与 NDK 相关的配置，例如查找 NDK 中的编译器、链接器和头文件。
    * **Android SDK:**  虽然 `env.py` 主要是关于 native 代码的构建，但在某些情况下，可能需要访问 Android SDK 中的工具或库。
    * **ABI (Application Binary Interface):**  Android 支持多种 ABI (如 `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`)。构建过程需要指定目标 ABI，`env.py` 会根据目标平台进行配置。

**举例说明:**

在 `generate_machine_config` 函数中，如果 `machine.os == "android"`，则会调用 `env_android.init_machine_config`。`env_android.py` 可能会执行以下操作：

1. **查找 NDK 路径:**  它会检查环境变量（如 `ANDROID_NDK_HOME`）或预定义的路径来定位 Android NDK。
2. **设置交叉编译工具链:**  它会根据目标 Android 架构选择 NDK 中对应的编译器和链接器（例如 `aarch64-linux-android-clang`, `arm-linux-androideabi-ld`）。
3. **配置 sysroot:**  为了进行交叉编译，需要指定目标系统的 sysroot，其中包含目标系统的库和头文件。`env_android.py` 会配置 NDK 中的 sysroot 路径。

**逻辑推理及假设输入与输出**

`env.py` 中包含一些逻辑推理，用于确定构建环境的配置。

**例子 1：确定是否需要执行包装器 (exe_wrapper)**

* **假设输入:**
    * `build_machine`:  一个 `MachineSpec` 对象，描述构建机器的架构，例如 `system='Linux', machine='x86_64'`.
    * `host_machine`: 一个 `MachineSpec` 对象，描述目标主机机器的架构，例如 `system='Android', machine='arm64'`.
    * `environ`: 一个包含环境变量的字典。

* **逻辑推理:** `needs_exe_wrapper` 函数会比较 `build_machine` 和 `host_machine` 的架构。如果构建机器不能直接运行目标主机机器的二进制文件（例如，在 x86_64 Linux 上构建 ARM64 Android 的程序），则需要一个执行包装器（如 QEMU）。

* **假设输出:** 如果 `build_machine` 和 `host_machine` 的操作系统或架构不同且无法直接运行，`needs_exe_wrapper` 函数将返回 `True`。

**例子 2：查找合适的 Vala 编译器**

* **假设输入:**
    * `toolchain_prefix`: 一个 `Path` 对象，指向工具链的安装目录。
    * `build_machine`: 一个 `MachineSpec` 对象，描述构建机器的架构。

* **逻辑推理:** `detect_toolchain_vala_compiler` 函数会在 `toolchain_prefix/bin` 目录下查找与 Vala 版本匹配的编译器（例如 `valac-0.56`）。它还会查找对应的 VAPI 文件。

* **假设输出:** 如果找到匹配的 Vala 编译器和 VAPI 目录，该函数将返回一个包含编译器路径和 VAPI 目录路径的元组。否则，返回 `None`。

**涉及用户或者编程常见的使用错误及举例说明**

* **未设置必要的环境变量:**  如果用户没有设置构建所需的某些环境变量（例如 `ANDROID_NDK_HOME`），`env.py` 可能无法找到必要的工具链或 SDK，导致构建失败。例如，如果构建 Android 版本但未设置 `ANDROID_NDK_HOME`，则 `env_android.py` 可能会抛出异常或使用默认的错误路径。
* **工具链或 SDK 路径错误:**  用户可能错误地设置了工具链或 SDK 的路径。例如，`toolchain_prefix` 指向了一个不包含有效工具链的目录。这会导致 `env.py` 找不到编译器、链接器等工具。
* **交叉编译环境配置不当:**  在交叉编译场景下，用户可能没有安装 QEMU 或没有正确设置 `FRIDA_QEMU_SYSROOT` 环境变量，导致 `find_exe_wrapper` 函数无法找到合适的执行包装器。
* **依赖项缺失:**  构建过程可能依赖于某些系统库或工具。如果这些依赖项未安装，`env.py` 可能会生成不完整的配置，导致后续的构建步骤失败。例如，如果构建依赖于 `pkg-config`，但系统上未安装该工具，则与 `pkg-config` 相关的配置可能会出错。

**用户操作是如何一步步的到达这里，作为调试线索**

当用户尝试构建 Frida 的 CLR 组件时，`env.py` 会被 Meson 构建系统自动调用。以下是用户操作可能导致执行到 `env.py` 的步骤：

1. **获取 Frida 源代码:** 用户首先需要从 GitHub 或其他来源获取 Frida 的源代码。
2. **进入 Frida 的构建目录:** 通常是 `frida/build` 或者用户自己创建的构建目录。
3. **执行 Meson 配置命令:** 用户会执行类似 `meson setup <构建目录> frida` 的命令来配置构建系统。
4. **Meson 执行构建配置:** Meson 在执行 `setup` 命令时，会读取 `frida/meson.build` 文件，并根据其中的配置执行相应的操作。
5. **调用 `env.py`:** `frida/meson.build` 文件中会定义如何生成机器文件。通常，会调用一个 Python 脚本（即 `env.py`）来生成特定于目标平台的机器配置文件。
6. **`env.py` 执行:**  `env.py` 接收构建和主机机器的规范信息，以及环境变量等参数，然后按照其逻辑生成机器配置文件。

**作为调试线索:**

* **查看 Meson 的输出:** Meson 在配置构建环境时会输出详细的日志。查看这些日志可以了解 `env.py` 是如何被调用的，以及传递给它的参数。
* **检查生成的机器文件:**  `env.py` 生成的机器文件（例如 `frida-linux-x86_64.txt`）包含了关键的构建配置信息。检查这些文件的内容可以帮助理解构建环境是如何设置的，以及是否存在错误的路径或选项。
* **设置环境变量进行调试:**  可以临时设置一些环境变量来影响 `env.py` 的行为，例如 `FRIDA_QEMU_SYSROOT` 或 `PKG_CONFIG_PATH`，以便测试不同的配置或排查问题。
* **在 `env.py` 中添加调试输出:**  可以在 `env.py` 中添加 `print()` 语句来输出关键变量的值，以便更深入地了解其执行过程和逻辑。例如，可以打印 `machine` 对象的内容、找到的工具链路径等。

总而言之，`frida/subprojects/frida-clr/releng/env.py` 是 Frida 构建过程中的一个关键组件，负责生成和管理构建环境配置文件，它与逆向工程、底层知识以及用户操作都密切相关。理解其功能和工作原理对于构建、定制和调试 Frida 至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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