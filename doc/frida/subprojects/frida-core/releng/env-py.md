Response:
Let's break down the thought process for analyzing this Python script and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `env.py` script within the Frida project and relate it to reverse engineering, low-level concepts, potential errors, and user interaction. The request is quite comprehensive, demanding connections across several domains.

**2. Initial Code Scan and High-Level Understanding:**

* **Imports:**  Immediately, the imports suggest configuration parsing (`configparser`), data structures (`collections`, `dataclasses`), file system operations (`os`, `pathlib`, `shutil`), process execution (`subprocess`), platform information (`platform`), type hinting (`typing`), and inter-process communication related elements (through `meson`).
* **Key Classes:** The `MachineConfig` dataclass stands out. It likely holds environment-specific information.
* **Core Functions:** Functions like `generate_machine_configs`, `generate_machine_config`, `load_meson_config`, and `call_meson` seem central to the script's purpose. The presence of "meson" strongly indicates a build system integration.
* **Conditional Logic:**  The script uses `if machine.is_apple`, `elif machine.os == "android"`, and `else` to handle platform-specific logic. This is a common pattern for cross-platform build systems.

**3. Deciphering the Functionality (Iterative Process):**

* **`MachineConfig`:** This class stores the paths to machine-specific configuration files, binary directories, and environment variables. The `make_merged_environment` method clearly shows how the script combines environment variables.
* **Meson Integration:**  The functions `call_meson`, `query_meson_entrypoint`, and `load_meson_config` confirm that this script is a helper for the Meson build system. It generates machine-specific configuration files that Meson uses.
* **Machine Specification (`MachineSpec`):** The code interacts with a `MachineSpec` object (imported from `machine_spec.py`). This likely encapsulates information about the target platform (OS, architecture, etc.). The generation of filenames like `frida<flavor>-<machine.identifier>.txt` reinforces this.
* **Cross-Compilation:** The `is_cross_build` variable and the handling of `build_environ` and `host_config` point towards the script's ability to generate configurations for cross-compilation scenarios.
* **Toolchain Handling:** The code deals with `toolchain_prefix`, `sdk_prefix`, and searches for tools like `ninja`, `gdbus-codegen`, `pkg-config`, and `vala`. This is typical for build systems that need to locate and configure compilers and related tools.
* **`pkg-config` Wrapper:** The `make_pkg_config_wrapper` function is interesting. It suggests the script might need to manipulate how `pkg-config` searches for libraries, especially during cross-compilation or when using a specific SDK.
* **Execution Wrapper:** The `needs_exe_wrapper` and `find_exe_wrapper` functions and the mention of `QEMU` indicate support for running host binaries on the build machine, likely using an emulator like QEMU.
* **Platform-Specific Logic:** The `env_apple`, `env_android`, and `env_generic` imports, along with the conditional `impl = ...`, clearly separate platform-specific configuration logic.

**4. Connecting to Reverse Engineering and Low-Level Concepts:**

* **Reverse Engineering:** The script's focus on setting up build environments for different architectures and operating systems is directly relevant to reverse engineering. Reverse engineers often need to build tools and libraries for the target platform they are analyzing. Frida itself is a dynamic instrumentation tool used for reverse engineering.
* **Binary Underpinnings:** The script deals with finding and configuring compilers, linkers, and other binary tools. It also touches on executable suffixes (`.exe`), shared and static libraries, and the concept of a `PATH` environment variable.
* **OS/Kernel/Framework:** The platform-specific logic (`env_apple`, `env_android`) directly relates to the nuances of building on those systems. The Android section implicitly involves knowledge of the Android SDK and NDK. The detection of `ProgramFiles` on Windows and `/usr/local` on Linux shows OS-level awareness.

**5. Identifying Potential Issues and User Errors:**

* **Missing Dependencies:** The `QEMUNotFoundError` is a clear example of a missing dependency. The script also checks for the existence of various tools.
* **Incorrect Environment Variables:**  The script relies on environment variables like `FRIDA_QEMU_SYSROOT`. Incorrectly setting these could lead to build failures.
* **Toolchain Configuration:**  Pointing to the wrong toolchain prefix or SDK prefix would cause problems.

**6. Tracing User Interaction:**

The thought process here is to imagine how someone would use Frida and how that would lead to the execution of this script. The steps involve:

* **Setting up the Build Environment:** Users will need to install dependencies like Python and Meson.
* **Configuring for a Target:** Users might specify the target architecture or device type, triggering the logic within this script to generate the correct configuration.
* **Running the Build:**  Executing the Meson build command would ultimately call into this script to prepare the build environment.

**7. Structuring the Explanation:**

Finally, the generated explanation is organized logically to cover each aspect of the request: functionality, relation to reverse engineering, low-level concepts, logical reasoning, potential errors, and user interaction. Code snippets and concrete examples are used to illustrate the points. The language is kept clear and accessible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this script *is* the core of the build system.
* **Correction:**  No, it *supports* the Meson build system by generating configuration files.
* **Initial thought:** Focus only on the Python code.
* **Correction:** Need to consider the broader context of Frida and its build process.
* **Initial thought:**  Just list the functions.
* **Correction:**  Explain *what* the functions do and *why* they are important.

This iterative process of exploring the code, connecting it to the broader context, and refining the understanding leads to a comprehensive and accurate explanation.
`frida/subprojects/frida-core/releng/env.py` 是 Frida 动态 instrumentation 工具的一个源代码文件，其主要功能是为不同目标平台生成构建环境配置文件，特别是为了与 Meson 构建系统配合使用。 它定义了如何配置编译器、链接器以及其他构建工具，以便 Frida 能够成功地编译和构建在各种操作系统和架构上。

下面列举其功能，并根据要求进行说明：

**1. 生成机器配置文件 (Machine Configuration):**

* **功能:** 脚本的核心功能是根据目标机器的规格（操作系统、架构等）生成 Meson 构建系统所需的机器配置文件。这些文件包含了构建过程中需要用到的编译器、链接器、工具链路径以及其他特定于目标平台的配置信息。
* **逆向关系:** 在逆向工程中，经常需要在目标平台上构建和运行工具。`env.py` 确保了 Frida 能够为目标环境正确配置构建环境，使得逆向工程师可以在目标设备上构建 Frida 服务端或相关的工具。例如，如果需要在 Android 设备上运行 Frida Server，就需要为其生成相应的机器配置文件。
* **二进制底层/Linux/Android 内核及框架知识:**
    * **二进制底层:** 脚本需要识别目标架构（例如 arm64, x86_64）以选择合适的编译器和链接器。它还处理不同平台的二进制文件后缀（例如 Windows 的 `.exe`）。
    * **Linux:**  对于 Linux 平台，脚本会查找常见的构建工具，如 `gcc`, `g++`, `pkg-config` 等，并配置相应的环境变量。它还处理共享库和静态库的构建选项。
    * **Android 内核及框架:** 脚本包含针对 Android 平台的特殊处理 (`env_android.py`)，例如处理 Android SDK 和 NDK 的路径，以及可能的交叉编译需求。它可能需要配置 Android 特有的工具链，如 `aarch64-linux-android-gcc`。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `machine` (包含目标操作系统和架构信息的 `MachineSpec` 对象), `flavor` (构建类型，如 "Release" 或 "Debug"), `build_dir` (构建目录的路径)。
    * **输出:** 一个包含目标平台构建配置的文本文件，例如 `fridaRelease-android_arm64.txt`。该文件包含了 Meson 理解的格式，定义了编译器、链接器、库路径等信息。
* **用户使用错误:**
    * **错误示例:** 用户在构建 Frida 时，可能没有正确设置 Android SDK 或 NDK 的环境变量，导致脚本无法找到必要的编译工具。
    * **用户操作到达此处的步骤:** 用户尝试使用 Meson 构建 Frida，例如执行 `meson setup build --backend=ninja`，Meson 会调用相关的脚本来生成初始的构建配置，其中就包括执行 `env.py` 来生成机器配置文件。如果环境变量缺失，`env.py` 可能会抛出错误或生成不完整的配置文件，导致后续构建失败。

**2. 合并和管理环境变量:**

* **功能:** `MachineConfig` 类及其 `make_merged_environment` 方法负责合并来自不同来源的环境变量，包括系统环境变量和特定于机器配置的环境变量。这确保了构建过程能够访问到所有必要的环境变量。
* **逆向关系:**  在逆向工程中，某些工具可能依赖特定的环境变量。`env.py` 确保在构建过程中正确设置这些变量，以便构建出的 Frida 可以与这些工具正常交互。
* **二进制底层/Linux/Android 内核及框架知识:** 脚本使用了 `os.pathsep` 来处理不同操作系统上的路径分隔符，并理解 `PATH` 环境变量的重要性，以便找到可执行文件。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 一个 `MachineConfig` 对象和一个包含当前环境变量的字典 `source_environ`。
    * **输出:** 一个新的字典，包含了合并后的环境变量，其中 `MachineConfig` 中定义的 `binpath` 会被添加到 `PATH` 环境变量中。
* **用户使用错误:**
    * **错误示例:** 用户可能错误地修改了系统环境变量，导致 `env.py` 继承了错误的配置，最终影响 Frida 的构建。
    * **用户操作到达此处的步骤:** 当 Meson 执行构建命令时，它会读取当前的环境变量，并将其传递给 `env.py`。 `env.py` 会使用这些环境变量来生成构建配置。

**3. 查找和配置构建工具:**

* **功能:** 脚本会尝试查找各种构建工具，例如 `ninja`, `gdbus-codegen`, `pkg-config`, `vala` 编译器等，并将其路径添加到配置文件中。它还会根据目标平台和工具链的前缀来定位这些工具。
* **逆向关系:**  逆向工程工具的构建可能依赖于特定的库和工具。`env.py` 确保了构建系统能够找到这些依赖，例如通过 `pkg-config` 来查找库的路径和编译选项。
* **二进制底层/Linux/Android 内核及框架知识:** 脚本需要了解不同构建工具的常见名称和位置。例如，在 Linux 上通常通过 `shutil.which` 来查找可执行文件。对于交叉编译，它可能需要处理带有目标架构前缀的工具名称。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `toolchain_prefix` (工具链的安装路径，可选)。
    * **输出:**  配置文件的 `[binaries]` 部分会包含找到的工具的路径，例如 `ninja = ['/path/to/ninja']`。
* **用户使用错误:**
    * **错误示例:** 用户可能没有安装某些必要的构建工具，导致脚本无法找到它们，从而导致构建失败。
    * **用户操作到达此处的步骤:**  在 Frida 的构建过程中，`env.py` 会被调用来探测可用的构建工具。如果用户缺少某些依赖，脚本会在日志中报告找不到这些工具。

**4. 处理交叉编译:**

* **功能:** 脚本能够处理交叉编译的场景，即在一种平台上构建用于另一种平台的软件。它会区分构建机器 (build machine) 和宿主机 (host machine)，并为两者生成不同的配置文件。
* **逆向关系:**  在逆向嵌入式设备或移动设备时，通常需要在桌面电脑上进行交叉编译。`env.py` 确保了 Frida 能够为目标设备（例如 Android 或 iOS 设备）正确配置构建环境。
* **二进制底层/Linux/Android 内核及框架知识:** 交叉编译需要使用目标平台的工具链。脚本会根据 `host_machine` 和 `build_machine` 的信息来选择正确的编译器和链接器，并设置相应的环境变量。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  不同的 `build_machine` 和 `host_machine` 对象，表示构建主机和目标主机的规格。
    * **输出:**  生成两个不同的机器配置文件，一个用于构建主机，一个用于目标主机。目标主机的配置文件会指向交叉编译工具链。
* **用户使用错误:**
    * **错误示例:** 用户在进行交叉编译时，可能没有正确配置交叉编译工具链的路径，导致脚本使用了错误的编译器。
    * **用户操作到达此处的步骤:** 用户在配置 Meson 构建时，会指定目标平台。Meson 会将这些信息传递给 `env.py`，使其能够判断是否需要进行交叉编译，并据此生成相应的配置文件。

**5. 生成 `pkg-config` 包装器 (wrapper):**

* **功能:**  `make_pkg_config_wrapper` 函数生成一个 Python 脚本，作为 `pkg-config` 的包装器。这在某些情况下很有用，例如在交叉编译时，需要确保 `pkg-config` 查询的是目标平台的库。
* **逆向关系:**  在逆向工程中，可能需要链接到目标平台的特定库。这个包装器确保了在构建过程中能够正确找到这些库。
* **Linux/Android 内核及框架知识:**  `pkg-config` 是一个用于获取库的编译和链接选项的工具，常用于 Linux 和类 Unix 系统。该包装器通过设置 `PKG_CONFIG_PATH` 环境变量来控制 `pkg-config` 的行为。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  `pkg_config` (原始 `pkg-config` 命令的参数列表), `pkg_config_path` (需要添加到 `PKG_CONFIG_PATH` 的路径列表)。
    * **输出:** 一个 Python 脚本，当执行时，会设置 `PKG_CONFIG_PATH` 环境变量，然后调用原始的 `pkg-config` 命令。
* **用户使用错误:**
    * **错误示例:**  用户可能没有正确设置目标平台的 `PKG_CONFIG_PATH`，导致构建系统找不到目标平台的库。
    * **用户操作到达此处的步骤:** 当 Frida 的构建需要链接到外部库时，Meson 会调用 `pkg-config` 来获取库的信息。在交叉编译场景下，可能会使用这个包装器来确保 `pkg-config` 查询的是目标平台的库信息。

**6. 检测 Valac 编译器:**

* **功能:** `detect_toolchain_vala_compiler` 函数用于检测指定工具链中的 Vala 编译器及其 VAPI 目录。
* **逆向关系:** Frida 的某些组件可能使用 Vala 语言编写。正确配置 Vala 编译器是构建这些组件的必要条件。
* **Linux 知识:** 该函数需要在工具链的特定目录下查找 Vala 编译器和相关的 VAPI 文件。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `toolchain_prefix` (工具链的安装路径), `build_machine` (构建主机的规格)。
    * **输出:** 如果找到 Vala 编译器，则返回一个包含编译器路径和 VAPI 目录路径的元组；否则返回 `None`。
* **用户使用错误:**
    * **错误示例:** 用户可能安装了不兼容的 Vala 编译器版本，或者 Vala 编译器的路径没有正确配置在工具链中。
    * **用户操作到达此处的步骤:**  如果 Frida 的构建配置中启用了 Vala 组件的构建，`env.py` 会尝试检测 Vala 编译器。如果检测失败，构建过程可能会出错。

**7. 处理可执行文件包装器 (execution wrapper):**

* **功能:** `needs_exe_wrapper` 和 `find_exe_wrapper` 函数用于确定是否需要以及如何使用可执行文件包装器，例如 `qemu`，以便在构建主机上运行目标平台的二进制文件。
* **逆向关系:**  在交叉编译或模拟目标环境时，可能需要在构建主机上运行为目标平台构建的工具。`qemu` 等模拟器可以实现这一点。
* **二进制底层知识:**  涉及到不同架构的二进制文件的执行，以及模拟器的工作原理。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `build_machine`, `host_machine`, `environ` (环境变量)。
    * **输出:** `needs_exe_wrapper` 返回一个布尔值，指示是否需要包装器。`find_exe_wrapper` 返回包装器的命令行参数列表（例如 `['qemu-arm64', '-L', '/path/to/sysroot']`）或 `None`。
* **用户使用错误:**
    * **错误示例:**  用户可能设置了 `FRIDA_QEMU_SYSROOT` 环境变量，但没有安装对应的 `qemu` 版本，导致脚本无法找到模拟器。
    * **用户操作到达此处的步骤:** 当 Frida 的构建过程需要在构建主机上运行为目标平台构建的程序时，`env.py` 会检查是否需要以及如何使用可执行文件包装器。

总而言之，`frida/subprojects/frida-core/releng/env.py` 扮演着 Frida 构建过程中的关键角色，负责根据目标平台配置构建环境，确保 Frida 能够成功地在各种操作系统和架构上编译和运行。它深入涉及到操作系统、架构、编译工具链以及构建系统的细节，是 Frida 实现跨平台支持的重要组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/env.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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