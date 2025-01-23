Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The core request is to understand the functionality of `env.py` within the context of Frida. Specifically, we need to identify its role in the build process and how it relates to reverse engineering, low-level details, and potential user errors.

**2. Initial Skim and Keyword Spotting:**

A quick read reveals several key concepts and keywords:

* **`meson`:**  This appears frequently, indicating interaction with the Meson build system.
* **`MachineSpec`, `MachineConfig`:**  These suggest the script deals with different target platforms and their configurations.
* **`toolchain`, `sdk`:** These point to cross-compilation and the management of development tools.
* **`build_machine`, `host_machine`:**  Further confirmation of cross-compilation.
* **`environ`:**  The script clearly manipulates environment variables.
* **Platform-specific logic (`env_android`, `env_apple`, `env_generic`):**  Indicates platform-dependent configuration.
* **`pkg-config`:** A standard tool for finding library dependencies.
* **`qemu`:**  Suggests emulation support for cross-compilation.

**3. Deeper Dive into Key Functions:**

Now, let's examine the purpose of the main functions:

* **`generate_machine_configs` and `generate_machine_config`:**  These are the heart of the script. They seem responsible for creating configuration files (`frida...txt`) based on target machine specifications. The `MachineConfig` dataclass encapsulates this configuration.
* **`load_meson_config` and `query_machine_file_path`:**  These are helper functions for locating and loading the generated configuration files.
* **`call_meson` and `query_meson_entrypoint`:**  Functions to invoke the Meson build system.
* **`detect_default_prefix`:** Determines the default installation directory.
* **`needs_exe_wrapper`, `can_run_host_binaries`, `find_exe_wrapper`:** Logic related to executing binaries built for a different architecture (cross-compilation with emulation).
* **`make_pkg_config_wrapper`:** Creates a wrapper script for `pkg-config`, likely to adjust the search path during cross-compilation.
* **`detect_toolchain_vala_compiler`:**  Detects the Vala compiler within the toolchain.

**4. Connecting to Frida's Purpose (Reverse Engineering):**

Frida is a dynamic instrumentation toolkit. How does this script relate?

* **Cross-Compilation:** Frida needs to run on various targets (Android, iOS, Linux, Windows, etc.). This script's emphasis on cross-compilation is crucial for building Frida components for these diverse platforms.
* **Target Configuration:**  To instrument a target, Frida needs to be built with the correct settings for that target's architecture, operating system, and dependencies. This script is responsible for generating these configuration files.
* **Toolchain Management:**  Reverse engineers often work with specific toolchains (e.g., Android NDK). This script handles the integration of these toolchains into the build process.
* **Emulation:** When cross-compiling, the build process might need to execute binaries built for the target architecture. The QEMU integration facilitates this.

**5. Identifying Low-Level and Kernel/Framework Aspects:**

* **Binary Tooling:** The script mentions tools like `objcopy`, `strip`, `nasm`, which are standard binary manipulation utilities.
* **System Calls (Implicit):** While not directly coded here, the *purpose* of Frida relies heavily on interacting with the target system's kernel (system calls for process injection, memory access, etc.). The *build process* configured by this script ensures Frida can perform these operations on the target.
* **Android Framework (Implicit):** The presence of `env_android` and the mention of SDK prefixes directly relate to building Frida components that interact with the Android framework (e.g., hooking Java methods).

**6. Logical Reasoning and Hypothetical Inputs/Outputs:**

Let's consider `generate_machine_config`:

* **Input (Hypothetical):**
    * `machine`: `MachineSpec(system='Linux', subsystem=None, kernel='Linux', cpu_family='x86_64', cpu='x86_64', endian='little', os='linux', arch='x86_64', config=None, executable_suffix='')`
    * `build_machine`: Same as `machine` (native build)
    * `is_cross_build`: `False`
    * `environ`: `{'PATH': '/usr/bin:/bin', 'CC': 'gcc'}`
    * `toolchain_prefix`: `None`
    * `sdk_prefix`: `None`
    * `default_library`: `'shared'`
    * `outdir`: `Path('./build')`
* **Output (Expected):**
    * A `MachineConfig` object.
    * A file `build/frida-linux-x86_64.txt` containing Meson configuration settings. This file would include details about the host machine and might point to system binaries like `gcc`. The `binpath` in the `MachineConfig` would likely be empty or contain standard system paths.

**7. Identifying Potential User Errors:**

* **Missing Dependencies:** If a tool like `ninja`, `pkg-config`, or `qemu` is not in the system's `PATH`, the build might fail. The script checks for some of these, but incorrect setup is a common problem.
* **Incorrect Environment Variables:** Setting `FRIDA_QEMU_SYSROOT` without having QEMU installed is an example. Typos in environment variable names would also cause issues.
* **Conflicting Toolchains:** If multiple toolchains are present and the wrong one is picked up, build errors can occur.
* **Incorrect SDK Paths:** Providing incorrect paths for the Android SDK or other SDKs will lead to build failures.

**8. Tracing User Actions to the Script:**

* **User runs a build command:**  Typically, a user interacts with the build system by running a command like `meson setup build` or `ninja`.
* **Meson needs configuration:** Meson, the build system, will need to determine how to build for the target platform.
* **Frida's build system invokes `env.py`:** Frida's Meson build files will call this script to generate the machine-specific configuration files.
* **Parameters passed based on user choices:**  The user might specify a target architecture or provide paths to SDKs via command-line arguments or environment variables, which are then passed to the functions in `env.py`.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Perhaps the script directly interacts with the kernel.
* **Correction:**  The script primarily *configures* the build process. The *resulting Frida binaries* will interact with the kernel. The script itself is more about build system integration.
* **Initial thought:** Focus solely on individual function details.
* **Refinement:** Emphasize the overall workflow and the relationships between the functions to understand the bigger picture of configuration generation.

By following these steps, systematically examining the code, connecting it to Frida's purpose, and considering potential issues, we can arrive at a comprehensive understanding of the `env.py` script's functionality.
`frida/subprojects/frida-python/releng/env.py` 是 Frida 动态 instrumentation 工具中负责生成特定于目标机器的构建环境配置文件的 Python 脚本。它为 Frida 的构建过程准备必要的工具链、SDK 和环境变量，以便能够成功地交叉编译或本地编译 Frida 的 Python 绑定。

以下是该脚本的功能及其与逆向方法、底层知识、逻辑推理和常见用户错误的关系：

**功能列举:**

1. **机器配置抽象:**  定义了 `MachineSpec` (机器规格) 和 `MachineConfig` (机器配置) 数据结构，用于抽象描述构建机器和目标机器的属性（如操作系统、架构、CPU 系列等）以及构建所需的工具和环境变量。
2. **加载和查询机器配置文件:** 提供函数 `load_meson_config` 和 `query_machine_file_path`，用于加载和定位已经生成的机器配置文件。
3. **检测默认安装前缀:** 函数 `detect_default_prefix` 根据操作系统返回默认的 Frida 安装路径。
4. **生成机器配置:** 核心功能由 `generate_machine_configs` 和 `generate_machine_config` 函数实现。这些函数根据构建机器和目标机器的规格、环境变量、工具链和 SDK 路径等信息，生成 Meson 构建系统所需的机器配置文件。
5. **平台特定处理:**  通过引入 `env_android.py`、`env_apple.py` 和 `env_generic.py` 等模块，实现了对不同平台（Android、Apple 和通用平台）特定的配置处理。
6. **工具链集成:**  脚本能够检测并配置工具链中的各种二进制工具，例如编译器 (gcc, clang, msvc)、链接器、汇编器 (nasm)、以及其他构建工具 (ninja, pkg-config, glib 工具等)。
7. **SDK 集成:**  能够处理 SDK 路径，并设置相应的环境变量和构建选项，例如 Vala 的 vapi 路径和 pkg-config 的搜索路径。
8. **交叉编译支持:**  通过区分构建机器和目标机器，并处理 `FRIDA_QEMU_SYSROOT` 环境变量，支持使用 QEMU 进行交叉编译。
9. **生成 pkg-config 包装器:**  在交叉编译场景下，如果需要调整 `pkg-config` 的行为，脚本会生成一个 Python 包装器脚本。
10. **处理可执行文件包装器:**  在无法直接运行目标平台二进制文件的情况下（例如交叉编译），脚本会查找或配置可执行文件包装器（如 QEMU）。
11. **Meson 集成:**  脚本与 Meson 构建系统紧密集成，生成符合 Meson 语法要求的机器配置文件。
12. **环境变量管理:**  负责管理构建过程中需要的环境变量，例如 `PATH`、`PKG_CONFIG_PATH` 等。

**与逆向方法的关系及举例说明:**

该脚本直接支持 Frida 的构建，而 Frida 本身是一个强大的逆向工程工具。脚本的功能体现在以下方面：

* **目标平台适配:**  为了让 Frida 能够在不同的目标平台上运行，`env.py` 确保 Frida 的 Python 绑定能够针对这些平台正确编译。例如，在逆向 Android 应用时，需要构建针对 Android 架构的 Frida Agent，`env.py` 中的 Android 相关逻辑 (`env_android.py`) 负责处理 Android NDK 的配置，确保能够使用正确的编译器和链接器。
* **工具链准备:**  逆向工程常常需要在目标环境执行代码或进行调试。`env.py` 确保构建过程中使用了正确的工具链，例如交叉编译到 ARM 架构的 Android 设备时，需要使用 ARM 交叉编译工具链。
* **依赖管理:**  Frida 的 Python 绑定依赖于一些底层的库。`env.py` 通过 `pkg-config` 等工具来管理这些依赖，确保在目标平台上能够找到所需的库。这对于逆向分析依赖特定库的程序至关重要。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **架构差异 (ARM, x86, x64):** 脚本中多次出现对不同架构的判断和处理 (`machine.arch`)，这直接关系到二进制代码的指令集和内存布局。例如，在交叉编译时，需要根据目标架构选择正确的编译器和链接器。
    * **字节序 (endian):**  `machine.endian` 属性用于处理不同架构的字节序问题，这在解析二进制数据结构时非常重要。
    * **可执行文件后缀:** 脚本会根据目标操作系统设置可执行文件的后缀 (`build_machine.executable_suffix`)，例如 Windows 上是 `.exe`，Linux 上通常为空。
* **Linux:**
    * **路径分隔符 (`os.pathsep`):**  用于拼接环境变量 `PATH`。
    * **标准库路径 (`/usr/local`):** 作为默认安装前缀。
    * **`pkg-config`:**  一个标准的 Linux 工具，用于查找库的编译和链接参数。
* **Android 内核及框架:**
    * **Android NDK:** `env_android.py` 模块负责处理 Android NDK 的路径和配置，NDK 提供了编译 Android Native 代码所需的工具链和库。
    * **SDK 路径:** 脚本中涉及到 `sdk_prefix`，这通常指向 Android SDK 或其他平台的 SDK，用于提供编译时需要的头文件和库。
    * **Android 架构 (`armeabi`, `arm64` 等):**  `QEMU_ARCHS` 字典中定义了 Android 架构到 QEMU 架构的映射，用于在交叉编译时选择正确的 QEMU 模拟器。
    * **`libdatadir`:** 用于定位特定于架构的库数据目录。

**逻辑推理及假设输入与输出:**

假设有以下输入：

* `build_machine`:  `MachineSpec(system='Linux', subsystem=None, kernel='Linux', cpu_family='x86_64', cpu='x86_64', endian='little', os='linux', arch='x86_64', config=None, executable_suffix='')` (构建机器为 x64 Linux)
* `host_machine`: `MachineSpec(system='Linux', subsystem=None, kernel='Linux', cpu_family='arm64', cpu='arm64', endian='little', os='android', arch='arm64', config=None, executable_suffix='')` (目标机器为 ARM64 Android)
* `environ`: 包含指向 Android NDK 的环境变量，例如 `ANDROID_NDK_ROOT`.
* `toolchain_prefix`:  指向自定义的工具链路径（可选）。
* `build_sdk_prefix`: 指向构建机器 SDK 的路径（可选）。
* `host_sdk_prefix`: 指向目标机器 Android SDK 的路径。
* `default_library`: `"shared"`
* `outdir`:  `Path('./build')`

**逻辑推理:**

1. `is_cross_build` 将为 `True`，因为构建机器和目标机器不同。
2. 会调用 `generate_machine_config` 两次，一次为构建机器，一次为目标机器。
3. 在生成目标机器配置时，会进入 `env_android.py` 的逻辑。
4. `env_android.py` 会根据 `host_sdk_prefix` 和 NDK 路径，设置 Android 相关的环境变量和构建选项。
5. 如果设置了 `FRIDA_QEMU_SYSROOT` 环境变量，并且没有找到对应的 QEMU 二进制文件，则会抛出 `QEMUNotFoundError`。

**假设输出:**

* 在 `outdir` 目录下会生成两个机器配置文件：
    * `frida-linux-x86_64.txt` (构建机器的配置)
    * `fridaandroid-arm64.txt` (目标机器的配置)
* `fridaandroid-arm64.txt` 文件中会包含针对 ARM64 Android 的 Meson 配置，例如：
    * `[host_machine]` 部分会包含 `system = 'android'`, `cpu_family = 'arm64'`, 等信息。
    * `[binaries]` 部分可能会包含 Android NDK 中的编译器和链接器路径。
    * `[built-in options]` 部分可能会包含与 Android 构建相关的选项。
* `MachineConfig` 对象会包含目标机器所需的二进制工具路径和环境变量。

**涉及用户或编程常见的使用错误及举例说明:**

1. **未安装必要的依赖工具:**  如果系统上没有安装 `meson`、`ninja` 或所需的工具链，脚本执行会失败。例如，如果用户尝试构建 Frida 但没有安装 Meson，运行构建脚本会报错，提示找不到 `meson` 命令。
2. **环境变量配置错误:**
    * **`ANDROID_NDK_ROOT` 未设置或设置错误:** 如果用户尝试构建 Android 版本的 Frida 但没有正确设置 `ANDROID_NDK_ROOT` 环境变量，`env_android.py` 将无法找到 Android NDK，导致构建失败。
    * **`FRIDA_QEMU_SYSROOT` 设置但未安装 QEMU:** 如果用户设置了 `FRIDA_QEMU_SYSROOT` 环境变量，但没有安装对应的 QEMU 模拟器，脚本会抛出 `QEMUNotFoundError`。
    * **`PKG_CONFIG_PATH` 配置错误:**  如果 `PKG_CONFIG_PATH` 没有包含必要的 `.pc` 文件路径，构建过程可能无法找到所需的库。
3. **工具链或 SDK 路径错误:**  如果用户提供的 `toolchain_prefix`、`build_sdk_prefix` 或 `host_sdk_prefix` 路径不正确，脚本将无法找到相应的工具或库，导致构建失败。
4. **交叉编译环境未配置正确:**  进行交叉编译时，需要确保目标平台的 SDK 和工具链已正确安装并配置，否则 `env.py` 无法生成正确的配置。
5. **权限问题:**  在某些情况下，脚本可能需要访问特定的目录或执行某些命令，如果没有足够的权限，可能会导致错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida 的 Python 绑定:** 用户通常会克隆 Frida 的代码仓库，并尝试构建 Python 绑定。这通常涉及到运行类似 `python setup.py install` 或使用 `meson` 进行构建。
2. **构建系统 (例如 Meson) 被调用:** 当用户运行构建命令时，构建系统（例如 `meson`) 会被调用来配置和执行构建过程。
3. **Meson 执行配置步骤:** Meson 会读取 `meson.build` 文件，并执行其中的配置步骤。
4. **调用 `env.py` 生成机器配置文件:** 在 Frida 的构建过程中，`meson.build` 文件会调用 `frida/subprojects/frida-python/releng/env.py` 脚本，传递构建机器和目标机器的相关信息以及环境变量。
5. **`env.py` 根据参数生成配置文件:** `env.py` 脚本会根据接收到的参数，执行上述的各种功能，生成特定于目标机器的 Meson 配置文件（例如 `frida-linux-x86_64.txt`）。
6. **Meson 使用生成的配置文件进行构建:** Meson 读取生成的机器配置文件，从中获取编译器、链接器、库路径等信息，然后使用这些信息来编译 Frida 的 Python 绑定。

**作为调试线索:**

如果用户在构建 Frida 的 Python 绑定时遇到问题，可以按照以下步骤进行调试，并可能涉及到 `env.py`：

1. **检查 Meson 的输出:**  查看 Meson 的配置输出，确认是否正确检测到了编译器、工具链和 SDK。
2. **检查生成的机器配置文件:** 查看 `frida/subprojects/frida-python/build` 目录下生成的机器配置文件，例如 `frida-linux-x86_64.txt` 或 `fridaandroid-arm64.txt`，检查其中的配置是否正确，例如编译器路径、SDK 路径等。
3. **检查环境变量:**  确认相关的环境变量（例如 `ANDROID_NDK_ROOT`, `PKG_CONFIG_PATH`) 是否已正确设置。
4. **手动运行 `env.py` (谨慎):**  在某些情况下，可以尝试手动运行 `env.py` 脚本，并传递不同的参数，以观察其行为和输出，但这需要对脚本的输入参数有深入的理解。
5. **查看 `env.py` 的日志或添加调试信息:**  如果需要更深入地了解 `env.py` 的执行过程，可以在脚本中添加 `print` 语句或其他日志记录方式，以便在构建过程中输出关键信息。

总而言之，`frida/subprojects/frida-python/releng/env.py` 是 Frida 构建过程中至关重要的一部分，它负责根据目标平台配置构建环境，确保 Frida 的 Python 绑定能够正确编译和运行，这直接关系到 Frida 作为动态 instrumentation 工具的可用性。理解该脚本的功能有助于解决 Frida 构建过程中可能遇到的问题。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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