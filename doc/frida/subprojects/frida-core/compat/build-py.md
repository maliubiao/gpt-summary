Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality and relate it to reverse engineering concepts, low-level details, and potential user errors.

**1. Initial Skim and High-Level Understanding:**

* **File Name:** `build.py` in a `compat` directory within Frida. This strongly suggests it's involved in building compatibility components.
* **Imports:** Standard Python libraries (argparse, os, pathlib, subprocess, etc.) and some typing hints. This tells us it's a script likely executed from the command line.
* **`main` function:** This is the entry point. It uses `argparse` to define command-line arguments and subcommands (`setup`, `compile`). This is a common pattern for build scripts.
* **`setup` and `compile` functions:**  These are the core actions. `setup` seems to prepare the build environment, while `compile` actually builds things.
* **Constants:**  Variables like `HELPER_TARGET`, `AGENT_FILE_WINDOWS`, `DEPFILE_FILENAME` point to specific output files and targets. This indicates the script manages the generation of these files.

**2. Deeper Dive into `setup`:**

* **Purpose:** The docstring says "setup everything needed to compile". Looking at the arguments, it takes information about the build environment (OS, architecture, version, etc.).
* **Key Logic:**
    * **Compatibility (`compat` argument):** This is a central theme. The script handles building for the *host* architecture and potentially *other* architectures (native and emulated).
    * **Toolchain Detection:** The script tries to detect if the necessary compilers (like a 32-bit GCC on a 64-bit Linux system) are available. This is crucial for cross-compilation.
    * **Output Generation:** It creates a dictionary `outputs` where keys represent build configurations (architecture, triplet) and values are lists of `Output` objects (filenames, targets). This suggests it's defining what needs to be built for different scenarios.
    * **State Serialization:** It serializes the build state into a base64-encoded string and prints it. This likely passes information to the `compile` step.
* **Connections to Reverse Engineering:** Building for different architectures is a core concern in reverse engineering when you're analyzing software on various platforms. Frida itself is used for dynamic analysis, often involving different target architectures than the host.
* **Low-Level/Kernel/Framework:** The need for different toolchains (like MinGW for Windows or cross-compilers for Linux) directly relates to low-level compilation. Building for Android involves understanding the Android NDK and its toolchains.

**3. Deeper Dive into `compile`:**

* **Purpose:** The docstring says "compile compatibility assets". It receives the serialized state from `setup`.
* **Key Logic:**
    * **Deserialization:** It loads the build state.
    * **Meson Integration:** It uses the Meson build system (`releng.meson_configure`, `releng.meson_make`). Meson is a meta-build system that generates native build files (like Ninja files) based on a higher-level description.
    * **Iterating through Output Groups:** It loops through the `outputs` defined in the `setup` step, building each group separately.
    * **Dependency Tracking:** It uses Ninja to track dependencies and writes them to a `.deps` file. This is vital for incremental builds.
* **Connections to Reverse Engineering:**  The output files (like `frida-agent.so`, `frida-helper.exe`) are the core components used in Frida's dynamic instrumentation. Building these correctly for different target platforms is essential.
* **Low-Level/Kernel/Framework:** The use of Meson and the need to handle different target architectures (e.g., building a `.so` for Android) directly touches upon low-level build processes and platform-specific details.

**4. Identifying Assumptions, Inputs, Outputs, and Errors:**

* **Assumptions:** The script assumes certain tools are available (like `ninja`, `git`). It also assumes a specific directory structure for the Frida project.
* **Inputs:** Command-line arguments for `setup` (role, build directories, versions, host info, compatibility options, compilers). The serialized state passed to `compile`.
* **Outputs:** The script prints "ok" or "error" along with messages. It generates the compatibility assets in the build directory and a dependency file (`compat.deps`).
* **User Errors:**
    * **Incorrect Command-Line Arguments:**  Providing invalid values for arguments like `role` or `compat`.
    * **Missing Toolchains:** The script explicitly checks for toolchains and raises `ToolchainNotFoundError`.
    * **Environment Issues:** Incorrect environment variables might lead to build failures.
    * **Submodule Issues:**  Problems with Git submodules could prevent the `releng` directory from being set up correctly.

**5. Tracing User Actions:**

* A developer working on Frida would typically invoke this script as part of the build process. This is usually done through a higher-level build system (like Meson itself).
* The command would look something like:
    ```bash
    python frida/subprojects/frida-core/compat/build.py setup ... [arguments]
    python frida/subprojects/frida-core/compat/build.py compile ... [arguments]
    ```
* The `setup` command would be run first to configure the build, and then the `compile` command would use the output of `setup` to actually build the compatibility components.

**Self-Correction/Refinement during Analysis:**

* Initially, I might have focused too much on individual lines of code. It's important to step back and understand the overall flow and purpose of the `setup` and `compile` functions.
* Recognizing the role of Meson is crucial. It simplifies the analysis by understanding that this script interacts with Meson rather than implementing the entire build process itself.
* The `compat` option is a key driver of the script's logic. Understanding how it influences the `outputs` dictionary and the subsequent build process is essential.

By following these steps, combining high-level understanding with detailed analysis of key sections, and connecting the script's actions to relevant concepts, we can arrive at a comprehensive explanation of its functionality.
好的，让我们来详细分析一下 `frida/subprojects/frida-core/compat/build.py` 这个 Python 脚本的功能。

**功能概述**

这个脚本的主要目的是为了构建 Frida 核心库（frida-core）的兼容性组件。这意味着它负责生成一些额外的二进制文件，使得 Frida 能够在不同的操作系统、架构和配置下运行，特别是当目标环境与构建环境不同时。

**功能分解与举例说明**

1. **`setup` 命令：设置编译环境**

   - **功能:** `setup` 命令负责准备编译兼容性组件所需的一切环境信息。它接收大量的命令行参数，描述了构建环境和目标环境的各种属性。
   - **与逆向的关系:**  逆向工程师经常需要在不同的目标平台上运行 Frida，例如在 x64 的主机上分析运行在 ARM 架构的 Android 设备上的程序。`setup` 命令就为这种跨平台分析场景做了准备。
   - **二进制底层/Linux/Android 内核及框架:**
     - **二进制底层:**  `setup` 需要知道目标架构 (`host_arch`)，这直接关系到生成的二进制文件的指令集。
     - **Linux/Android:**  脚本会根据 `host_os` 来判断是否需要特定的工具链或构建步骤，例如针对 Linux 可能需要检测是否存在 32 位的 GCC 编译器。对于 Android，虽然这里没有直接体现内核或框架的交互，但其目的是为了生成能在 Android 上运行的 Frida 组件。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**
       ```
       python build.py setup project build-x86_64 build-x86_64 16.1.9 linux x86_64 none auto installed agent,gadget >>>gcc<<< >>>g++<<<
       ```
     - **输出:** （部分输出）
       ```
       ok
       enabled by default for linux-x86_64
       arch_support_bundle
       arch-support.bundle
       compat.deps
       ... (base64 encoded state)
       ```
       这个例子中，假设我们在 x86_64 Linux 系统上构建 Frida，`compat` 设置为 `auto`，表示自动检测需要构建的兼容性组件。输出会指示兼容性功能已启用，并列出要生成的输出文件。
   - **用户或编程常见的使用错误:**
     - **错误举例:** 用户可能在 `compat` 参数中同时指定了 `"auto"` 和其他特定的架构，这会导致 `argparse.ArgumentTypeError` 异常，因为 `"auto"` 意味着自动处理，不应与其他选项混用。

2. **`compile` 命令：编译兼容性资产**

   - **功能:** `compile` 命令接收 `setup` 命令生成的 `state` 信息，并根据这些信息实际执行编译过程，生成兼容性所需的二进制文件。
   - **与逆向的关系:** `compile` 命令生成的 `frida-agent.so` (Linux/Android) 或 `frida-agent.dll` (Windows) 是 Frida 注入到目标进程的关键组件，逆向工程师会直接与这些文件打交道。
   - **二进制底层/Linux/Android 内核及框架:**
     - **二进制底层:**  编译过程会调用编译器 (通过 `compilers` 参数传递)，生成特定架构的机器码。
     - **Linux/Android:** 在 Linux 和 Android 上，可能会生成 ELF 格式的共享库 (`.so`)，这涉及到 ELF 文件格式的知识。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `compile` 命令接收 `setup` 命令输出的 base64 编码的 `state`。
     - **输出:** 在 `builddir` 目录下生成 `frida-helper`、`frida-agent.so` 等兼容性二进制文件，以及 `compat.deps` 依赖文件。
   - **用户或编程常见的使用错误:**
     - **错误举例:** 如果 `setup` 步骤中没有正确检测到所需的交叉编译工具链，`compile` 步骤可能会因为找不到编译器而失败，抛出 `subprocess.CalledProcessError` 异常。

3. **兼容性处理 (`compat` 参数)**

   - **功能:** `compat` 参数允许用户指定需要支持的目标架构。它可以是 `"auto"` (自动检测)， `"disabled"` (禁用兼容性)，或者一个或多个具体的架构名称 (例如 `"x86"`, `"arm"`)。
   - **与逆向的关系:**  这直接关系到 Frida 能否在特定的目标架构上工作。如果逆向目标是一个运行在 ARM 架构上的嵌入式设备，那么就需要确保 Frida 编译时包含了对 ARM 的兼容性支持。
   - **二进制底层:**  指定不同的架构会触发不同的编译流程，使用不同的编译器选项，生成不同指令集的二进制文件。
   - **逻辑推理:**
     - **假设输入:** `compat` 设置为 `"x86"`，构建主机是 x86_64。
     - **输出:**  `setup` 阶段会检测是否存在 32 位的交叉编译工具链，`compile` 阶段会使用该工具链编译出 32 位的 `frida-agent` 等文件。

4. **工具链检测**

   - **功能:** 脚本会尝试检测构建环境中是否存在用于交叉编译的工具链，例如在 x86_64 Linux 上检测 `i686-linux-gnu-gcc`。
   - **与逆向的关系:**  交叉编译是逆向工程中常见的需求，用于在与目标架构不同的主机上构建分析工具。
   - **Linux:**  脚本中检测 Linux 下 32 位 GCC 的逻辑 (`shutil.which(other_triplet + "-gcc")`) 以及尝试使用 `-m32` 选项编译测试代码，都直接涉及到 Linux 编译工具链的使用。

5. **Meson 构建系统集成**

   - **功能:** 脚本集成了 Meson 构建系统，用于生成实际的构建文件 (如 Ninja 文件) 并执行编译。
   - **与逆向的关系:**  理解 Meson 的工作方式有助于理解 Frida 的构建流程。
   - **逻辑推理:** `compile` 函数中调用 `releng.meson_configure` 和 `releng.meson_make`，表明实际的编译工作是由 Meson 驱动的。脚本本身负责配置 Meson 所需的参数。

**用户操作步骤 (调试线索)**

假设用户在使用 Frida 时遇到兼容性问题，例如无法在某个特定的目标架构上注入 Frida。作为调试线索，可以追溯到构建过程：

1. **用户执行 Frida 的构建命令。** 这通常涉及到调用 Meson。
2. **Meson 会调用 `frida/subprojects/frida-core/compat/build.py` 脚本的 `setup` 命令。**  Meson 会传递各种参数，包括目标操作系统、架构等。
3. **`setup` 命令根据参数判断需要构建哪些兼容性组件。**  例如，如果目标是 32 位 Windows，但构建主机是 64 位 Windows，`setup` 可能会配置构建 32 位的 `frida-agent.dll`。
4. **`setup` 命令将构建状态信息序列化并输出。**
5. **Meson 随后调用 `frida/subprojects/frida-core/compat/build.py` 脚本的 `compile` 命令。** 并将 `setup` 命令输出的状态信息作为参数传递。
6. **`compile` 命令根据状态信息，调用相应的编译器，生成兼容性二进制文件。**
7. **如果构建过程中出现错误 (例如找不到交叉编译工具链)，用户可能会看到错误信息。**  这些错误信息可以帮助定位问题，例如缺少必要的软件包。

**涉及到的二进制底层、Linux、Android 内核及框架知识的举例说明**

- **二进制文件格式:** 脚本生成的文件如 `.dll`、`.so`、可执行文件等，都需要理解这些二进制文件的结构 (例如 PE 格式、ELF 格式)。
- **指令集架构:**  `host_arch` 参数直接关系到生成的二进制文件的指令集 (例如 x86, ARM, ARM64)。交叉编译需要针对目标架构生成正确的指令。
- **链接器:**  编译过程涉及到链接器，用于将编译后的目标文件组合成最终的可执行文件或共享库。
- **操作系统 API:** 生成的 Frida 组件会调用目标操作系统的 API，因此需要了解目标系统的 API 接口。
- **Android NDK:**  如果要构建 Android 平台的 Frida 组件，需要使用 Android NDK (Native Development Kit) 提供的工具链。

**用户或编程常见的使用错误举例说明**

- **`compat` 参数配置错误:**  用户可能错误地禁用了需要的兼容性支持，导致 Frida 无法在目标平台上运行。
- **缺少必要的交叉编译工具链:**  例如，在 x64 Linux 上构建 32 位 Windows 的 Frida 组件，需要安装 MinGW-w64 的 32 位版本。
- **环境变量配置错误:**  某些编译工具依赖特定的环境变量，如果配置不正确可能导致编译失败。
- **依赖项问题:**  Frida 的构建依赖于其他库，如果这些依赖项没有正确安装或配置，构建可能会失败。

总而言之，`frida/subprojects/frida-core/compat/build.py` 是 Frida 构建过程中一个关键的脚本，它负责处理跨平台兼容性的构建需求。它涉及到编译原理、操作系统特性、目标平台架构等多种知识，是理解 Frida 如何在不同环境下运行的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-core/compat/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from __future__ import annotations
import argparse
import base64
from collections import OrderedDict
from dataclasses import dataclass, field
import itertools
import locale
import os
from pathlib import Path
import pickle
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback
from typing import Any, Literal, Mapping, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
NINJA = os.environ.get("NINJA", "ninja")


Role = Literal["project", "subproject"]


def main(argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    command = subparsers.add_parser("setup", help="setup everything needed to compile")
    command.add_argument("role", help="project vs subproject", choices=["project", "subproject"])
    command.add_argument("builddir", help="build directory", type=Path)
    command.add_argument("top_builddir", help="top build directory", type=Path)
    command.add_argument("frida_version", help="the Frida version")
    command.add_argument("host_os", help="operating system binaries are being built for")
    command.add_argument("host_arch", help="architecture binaries are being built for")
    command.add_argument("host_config", help="configuration binaries are being built for")
    command.add_argument("compat", help="support for targets with a different architecture",
                         type=parse_compat_option_value)
    command.add_argument("assets", help="whether assets are embedded vs installed and loaded at runtime")
    command.add_argument("components", help="which components will be built",
                         type=parse_array_option_value)
    command.add_argument("compilers", help="compiler command arrays", nargs="+")
    command.set_defaults(func=lambda args: setup(args.role,
                                                 args.builddir,
                                                 args.top_builddir,
                                                 args.frida_version,
                                                 args.host_os,
                                                 args.host_arch,
                                                 args.host_config if args.host_config else None,
                                                 args.compat,
                                                 args.assets,
                                                 args.components,
                                                 parse_compilers(args.compilers)))

    command = subparsers.add_parser("compile", help="compile compatibility assets")
    command.add_argument("privdir", help="directory to store intermediate files", type=Path)
    command.add_argument("state", help="opaque state from the setup step")
    command.set_defaults(func=lambda args: compile(args.privdir, pickle.loads(base64.b64decode(args.state))))

    args = parser.parse_args()
    if "func" in args:
        try:
            args.func(args)
        except subprocess.CalledProcessError as e:
            print(e, file=sys.stderr)
            print("Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")), file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_usage(file=sys.stderr)
        sys.exit(1)


def parse_compat_option_value(v: str) -> set[str]:
    vals = parse_array_option_value(v)

    if len(vals) > 1:
        for choice in {"auto", "disabled"}:
            if choice in vals:
                raise argparse.ArgumentTypeError(f"the compat '{choice}' choice cannot be combined with other choices")

    return vals


def parse_array_option_value(v: str) -> set[str]:
    return {v.strip() for v in v.split(",")}


def parse_compilers(compilers: list[str]) -> Compilers:
    cc = pop_cmd_array_arg(compilers)
    cpp = pop_cmd_array_arg(compilers)
    return Compilers(cc, cpp)


def pop_cmd_array_arg(args: list[str]) -> list[str]:
    result: list[str] = []
    first = args.pop(0)
    assert first == ">>>"
    while True:
        cur = args.pop(0)
        if cur == "<<<":
            break
        result.append(cur)
    if len(result) == 1 and not result[0]:
        return None
    return result


def setup(role: Role,
          builddir: Path,
          top_builddir: Path,
          frida_version: str,
          host_os: str,
          host_arch: str,
          host_config: Optional[str],
          compat: set[str],
          assets: str,
          components: set[str],
          compilers: Compilers):
    try:
        outputs: Mapping[str, Sequence[Output]] = OrderedDict()

        outputs[OutputGroup(arch=None)] = [Output("arch_support_bundle", "arch-support.bundle", Path("compat"), "")]

        releng_location = query_releng_location(role)
        ensure_submodules_checked_out(releng_location)
        configure_import_path(releng_location)

        auto_detect = "auto" in compat
        if auto_detect:
            if host_os in {"windows", "macos", "linux", "ios", "tvos", "android"}:
                summary = f"enabled by default for {host_os}-{host_arch}"
                compat = {"native", "emulated"}
            else:
                summary = f"disabled by default for {host_os}-{host_arch}"
                compat = set()
        elif "disabled" in compat:
            summary = "disabled by user"
            compat = set()
        else:
            summary = "enabled by user"
        missing: list[MissingFeature] = []

        if "native" in compat:
            have_toolchain = True
            other_label: Optional[str] = None
            other_triplet: Optional[str] = None
            extra_environ: dict[str, str] = {}

            if host_os == "windows" and host_arch == "x86_64" and host_config == "mingw":
                other_label = "x86"
                have_toolchain, other_triplet = detect_mingw_toolchain_for("x86")
            elif host_os == "linux" and host_arch == "x86_64" and host_config is None:
                other_label = "x86"
                other_triplet = "i686-linux-gnu"
                have_toolchain = shutil.which(other_triplet + "-gcc") is not None
                if not have_toolchain:
                    with (tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".c") as probe_c,
                          tempfile.NamedTemporaryFile(delete=False) as probe_executable):
                        try:
                            probe_c.write("int main (void) { return 0; }")
                            probe_c.flush()
                            p = subprocess.run(compilers.cc + ["-m32", probe_c.name, "-o", probe_executable.name],
                                               capture_output=True)
                            if p.returncode == 0:
                                extra_environ["CC"] = shlex.join(compilers.cc + ["-m32"])
                                extra_environ["CXX"] = shlex.join(compilers.cpp + ["-m32"])
                                have_toolchain = True
                        finally:
                            try:
                                os.unlink(probe_executable.name)
                            except:
                                pass

            if not have_toolchain:
                if not auto_detect:
                    raise ToolchainNotFoundError(f"unable to locate toolchain for {other_triplet}")
                missing.append(MissingFeature(other_label, other_triplet))

            if host_os == "windows" and host_arch == "x86_64" and have_toolchain:
                group = OutputGroup("x86", other_triplet, extra_environ)
                outputs[group] = [
                    Output(identifier="helper_legacy",
                           name=HELPER_FILE_WINDOWS.name,
                           file=HELPER_FILE_WINDOWS,
                           target=HELPER_TARGET),
                    Output(identifier="agent_legacy",
                           name=AGENT_FILE_WINDOWS.name,
                           file=AGENT_FILE_WINDOWS,
                           target=AGENT_TARGET),
                ]
                if "gadget" in components:
                    outputs[group] += [
                        Output(identifier="gadget_legacy",
                               name=GADGET_FILE_WINDOWS.name,
                               file=GADGET_FILE_WINDOWS,
                               target=GADGET_TARGET),
                    ]

            if host_os in {"macos", "ios"} and host_arch in {"arm64e", "arm64"} and host_config != "simulator":
                if host_arch == "arm64e":
                    other_arch = "arm64"
                    kind = "legacy"
                else:
                    other_arch = "arm64e"
                    kind = "modern"
                group = OutputGroup(other_arch)
                outputs[group] = [
                    Output(identifier=f"helper_{kind}",
                           name=f"frida-helper-{other_arch}",
                           file=HELPER_FILE_UNIX,
                           target=HELPER_TARGET),
                    Output(identifier=f"agent_{kind}",
                           name=f"frida-agent-{other_arch}.dylib",
                           file=AGENT_FILE_DARWIN,
                           target=AGENT_TARGET),
                ]
                if "gadget" in components:
                    outputs[group] += [
                        Output(identifier=f"gadget_{kind}",
                               name=f"frida-gadget-{other_arch}.dylib",
                               file=GADGET_FILE_DARWIN,
                               target=GADGET_TARGET),
                    ]
                if "server" in components and assets == "installed":
                    outputs[group] += [
                        Output(identifier=f"server_{kind}",
                               name=f"frida-server-{other_arch}",
                               file=SERVER_FILE_UNIX,
                               target=SERVER_TARGET),
                    ]

            if host_os == "linux" and host_arch == "x86_64" and have_toolchain:
                group = OutputGroup("x86", other_triplet, extra_environ)
                outputs[group] = [
                    Output(identifier="helper_legacy",
                           name=HELPER_FILE_UNIX.name,
                           file=HELPER_FILE_UNIX,
                           target=HELPER_TARGET),
                    Output(identifier="agent_legacy",
                           name=AGENT_FILE_ELF.name,
                           file=AGENT_FILE_ELF,
                           target=AGENT_TARGET),
                ]
                if "gadget" in components:
                    outputs[group] += [
                        Output(identifier="gadget_legacy",
                               name=GADGET_FILE_ELF.name,
                               file=GADGET_FILE_ELF,
                               target=GADGET_TARGET),
                    ]

            if host_os == "android" and host_arch in {"arm64", "x86_64"}:
                group = OutputGroup("arm" if host_arch == "arm64" else "x86")
                outputs[group] = [
                    Output(identifier="helper_legacy",
                           name=HELPER_FILE_UNIX.name,
                           file=HELPER_FILE_UNIX,
                           target=HELPER_TARGET),
                    Output(identifier="agent_legacy",
                           name=AGENT_FILE_ELF.name,
                           file=AGENT_FILE_ELF,
                           target=AGENT_TARGET),
                ]
                if "gadget" in components:
                    outputs[group] += [
                        Output(identifier="gadget_legacy",
                               name=GADGET_FILE_ELF.name,
                               file=GADGET_FILE_ELF,
                               target=GADGET_TARGET),
                    ]

        if "emulated" in compat:
            if host_os == "windows" and host_arch == "arm64":
                for kind, emulated_arch in [("modern", "x86_64"), ("legacy", "x86")]:
                    if host_config == "mingw":
                        found, emulated_triplet = detect_mingw_toolchain_for(emulated_arch)
                        if not found:
                            if not auto_detect:
                                raise ToolchainNotFoundError(f"unable to locate toolchain for {emulated_triplet}")
                            missing.append(MissingFeature(emulated_arch, emulated_triplet))
                            continue
                    else:
                        emulated_triplet = None
                    outputs[OutputGroup(emulated_arch, emulated_triplet, extra_environ)] = [
                        Output(identifier=f"helper_emulated_{kind}",
                               name=HELPER_FILE_WINDOWS.name.replace(".exe", f"-{emulated_arch}.exe"),
                               file=HELPER_FILE_WINDOWS,
                               target=HELPER_TARGET),
                        Output(identifier=f"agent_emulated_{kind}",
                               name=AGENT_FILE_WINDOWS.name.replace(".dll", f"-{emulated_arch}.dll"),
                               file=AGENT_FILE_WINDOWS,
                               target=AGENT_TARGET),
                    ]

            if host_os == "android" and host_arch in {"x86_64", "x86"}:
                outputs[OutputGroup("arm")] = [
                    Output(identifier="agent_emulated_legacy",
                           name="frida-agent-arm.so",
                           file=AGENT_FILE_ELF,
                           target=AGENT_TARGET),
                ]
                if host_arch == "x86_64":
                    outputs[OutputGroup("arm64")] = [
                        Output(identifier="agent_emulated_modern",
                               name="frida-agent-arm64.so",
                               file=AGENT_FILE_ELF,
                               target=AGENT_TARGET),
                    ]

        raw_allowed_prebuilds = os.environ.get("FRIDA_ALLOWED_PREBUILDS")
        allowed_prebuilds = set(raw_allowed_prebuilds.split(",")) if raw_allowed_prebuilds is not None else None

        state = State(role, builddir, top_builddir, frida_version, host_os, host_config, allowed_prebuilds, outputs)
        serialized_state = base64.b64encode(pickle.dumps(state)).decode('ascii')

        if missing:
            summary = ", ".join([f"{m.label} disabled due to missing toolchain for {m.triplet}" for m in missing])
        variable_names, output_names = zip(*[(output.identifier, output.name) \
                for output in itertools.chain.from_iterable(outputs.values())])
        print("ok")
        print(summary)
        print(f"{','.join(variable_names)}")
        print(f"{','.join(output_names)}")
        print(DEPFILE_FILENAME)
        print(serialized_state)
    except Exception as e:
        print(f"error {e}")
        print("")
        print(traceback.format_exception(e))


class ToolchainNotFoundError(Exception):
    pass


@dataclass
class Compilers:
    cc: list[str]
    cpp: list[str]


@dataclass
class State:
    role: Role
    builddir: Path
    top_builddir: Path
    frida_version: str
    host_os: str
    host_config: Optional[str]
    allowed_prebuilds: Optional[set[str]]
    outputs: Mapping[OutputGroup, Sequence[Output]]


@dataclass
class OutputGroup:
    arch: Optional[str]
    triplet: Optional[str] = None
    extra_environ: dict[str, str] = field(default_factory=dict)

    def __eq__(self, other):
        if isinstance(other, OutputGroup):
            return other.arch == self.arch
        return False

    def __hash__(self):
        return hash(self.arch)


@dataclass
class Output:
    identifier: str
    name: str
    file: Path
    target: str


@dataclass
class MissingFeature:
    label: str
    triplet: str


def compile(privdir: Path, state: State):
    releng_location = query_releng_location(state.role)
    subprojects = detect_relevant_subprojects(releng_location)
    if state.role == "subproject":
        grab_subprojects_from_parent(subprojects, releng_location)
    configure_import_path(releng_location)

    from releng.env import call_meson
    from releng.machine_spec import MachineSpec
    from releng.meson_configure import configure
    from releng.meson_make import make

    def call_internal_meson(argv, *args, **kwargs):
        if "stdout" not in kwargs and "stderr" not in kwargs:
            silenced_kwargs = {
                **kwargs,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "encoding": locale.getpreferredencoding(),
            }
        else:
            silenced_kwargs = kwargs
        return call_meson(argv, *args, **silenced_kwargs)

    options: Optional[Sequence[str]] = None
    build_env = scrub_environment(os.environ)
    build_env["FRIDA_RELENG"] = str(releng_location)
    top_builddir = state.top_builddir
    depfile_lines = []
    for group, outputs in state.outputs.items():
        if group.arch is None:
            for o in outputs:
                (state.builddir / o.name).write_bytes(b"")
            continue

        workdir = (privdir / group.arch).resolve()

        if not (workdir / "build.ninja").exists():
            if options is None:
                options = load_meson_options(top_builddir, state.role, set(subprojects.keys()))
                version_opt = next((opt for opt in options if opt.startswith("-Dfrida_version=")), None)
                if version_opt is None:
                    options += [f"-Dfrida_version={state.frida_version}"]

            host_machine = MachineSpec(state.host_os, group.arch, state.host_config, group.triplet)

            configure(sourcedir=REPO_ROOT,
                      builddir=workdir,
                      host_machine=host_machine,
                      environ={**build_env, **group.extra_environ},
                      allowed_prebuilds=state.allowed_prebuilds,
                      extra_meson_options=[
                          "-Dhelper_modern=",
                          "-Dhelper_legacy=",
                          "-Dagent_modern=",
                          "-Dagent_legacy=",
                          "-Dagent_emulated_modern=",
                          "-Dagent_emulated_legacy=",
                          *options,
                      ],
                      call_meson=call_internal_meson,
                      on_progress=lambda progress: None)

        make(sourcedir=REPO_ROOT,
             builddir=workdir,
             targets=[o.target for o in outputs],
             environ=build_env,
             call_meson=call_internal_meson)

        for o in outputs:
            shutil.copy(workdir / o.file, state.builddir / o.name)

            output_relpath = (workdir / o.name).relative_to(top_builddir).as_posix()
            input_paths = shlex.split(subprocess.run([NINJA, "-t", "inputs", o.file],
                                                     cwd=workdir,
                                                     capture_output=True,
                                                     encoding="utf-8",
                                                     check=True).stdout)
            input_entries = []
            for raw_path in input_paths:
                path = Path(raw_path)
                if not path.is_absolute():
                    path = Path(os.path.relpath(workdir / path, top_builddir))
                input_entries.append(escape_depfile_path(path.as_posix()))
            depfile_lines.append(f"{output_relpath}: {' '.join(input_entries)}")

    (state.builddir / DEPFILE_FILENAME).write_text("\n".join(depfile_lines), encoding="utf-8")


def load_meson_options(top_builddir: Path,
                       role: Role,
                       subprojects: set[str]) -> Sequence[str]:
    from mesonbuild import coredata

    return [f"-D{adapt_key(k, role)}={v.value}" for k, v in coredata.load(top_builddir).options.items()
            if option_should_be_forwarded(k, v, role, subprojects)]


def adapt_key(k: "OptionKey", role: Role) -> "OptionKey":
    if role == "subproject" and k.subproject == "frida-core":
        return k.as_root()
    return k


def option_should_be_forwarded(k: "OptionKey",
                               v: "coredata.UserOption[Any]",
                               role: Role,
                               subprojects: set[str]) -> bool:
    from mesonbuild import coredata

    our_project_id = "frida-core" if role == "subproject" else ""
    is_for_us = k.subproject == our_project_id
    is_for_child = k.subproject in subprojects

    if k.is_project():
        if is_for_us:
            tokens = k.name.split("_")
            if tokens[0] in {"helper", "agent"} and tokens[-1] in {"modern", "legacy"}:
                return False
        if k.subproject and k.machine is not coredata.MachineChoice.HOST:
            return False
        return is_for_us or is_for_child

    if coredata.CoreData.is_per_machine_option(k):
        return k.machine is coredata.MachineChoice.BUILD

    if k.is_builtin():
        if k.name in {"buildtype", "genvslite"}:
            return False
        if not str(v.value):
            return False
        if not is_for_child and role == "subproject" and k.subproject in {"", our_project_id}:
            if not coredata.BUILTIN_OPTIONS[k.as_root()].yielding:
                return k.subproject == our_project_id
            return True

    if k.module == "python":
        if k.name == "install_env" and v.value == "prefix":
            return False
        if not str(v.value):
            return False

    return is_for_us or is_for_child


def scrub_environment(env: Mapping[str, str]) -> Mapping[str, str]:
    from releng.env import TOOLCHAIN_ENVVARS
    clean_env = OrderedDict()
    envvars_to_avoid = {*TOOLCHAIN_ENVVARS, *MSVS_ENVVARS}
    for k, v in env.items():
        if k in envvars_to_avoid:
            continue
        if k.upper() == "PATH" and platform.system() == "Windows":
            v = scrub_windows_devenv_dirs_from_path(v, env)
        clean_env[k] = v
    return clean_env


def scrub_windows_devenv_dirs_from_path(raw_path: str, env: Mapping[str, str]) -> str:
    raw_vcinstalldir = env.get("VCINSTALLDIR")
    if raw_vcinstalldir is None:
        return raw_path
    vcinstalldir = Path(raw_vcinstalldir)
    clean_entries = []
    for raw_entry in raw_path.split(";"):
        entry = Path(raw_entry)
        if entry.is_relative_to(vcinstalldir):
            continue
        if "WINDOWS KITS" in [p.upper() for p in entry.parts]:
            continue
        clean_entries.append(raw_entry)
    return ";".join(clean_entries)


def escape_depfile_path(path: str) -> str:
    return path.replace(" ", "\\ ")


def query_releng_location(role: Role) -> Path:
    if role == "subproject":
        candidate = REPO_ROOT.parent.parent / "releng"
        if candidate.exists():
            return candidate
    return REPO_ROOT / "releng"


def ensure_submodules_checked_out(releng_location: Path):
    if not (releng_location / "meson" / "meson.py").exists():
        subprocess.run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1", "releng"],
                       cwd=releng_location.parent,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT,
                       encoding="utf-8",
                       check=True)


def detect_relevant_subprojects(releng_location: Path) -> dict[str, Path]:
    subprojects = detect_relevant_subprojects_in(REPO_ROOT, releng_location)
    gum_location = subprojects.get("frida-gum")
    if gum_location is not None:
        subprojects.update(detect_relevant_subprojects_in(gum_location, releng_location))
    return subprojects


def detect_relevant_subprojects_in(repo_root: Path, releng_location: Path) -> dict[str, Path]:
    result = {}
    for f in (repo_root / "subprojects").glob("*.wrap"):
        name = f.stem
        location = releng_location.parent / "subprojects" / name
        if location.exists():
            result[name] = location
    return result


def grab_subprojects_from_parent(subprojects: dict[str, Path], releng_location: Path):
    for name, location in subprojects.items():
        subp_here = REPO_ROOT / "subprojects" / name
        if subp_here.exists():
            continue

        try:
            subp_here.symlink_to(Path("..") / ".." / name, target_is_directory=True)
            continue
        except OSError as e:
            if not getattr(e, "winerror", None) == 1314:
                raise e

        subprocess.run(["git", "worktree", "add", subp_here],
                       cwd=location,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT,
                       encoding="utf-8",
                       check=True)


def configure_import_path(releng_location: Path):
    sys.path.insert(0, str(releng_location / "meson"))
    sys.path.insert(0, str(releng_location.parent))


def detect_mingw_toolchain_for(arch: str) -> Tuple[bool, Optional[str]]:
    triplet = MINGW_ARCHS.get(arch, arch) + "-w64-mingw32"
    found = shutil.which(triplet + "-gcc") is not None
    return (found, triplet)


STATE_FILENAME = "state.dat"
DEPFILE_FILENAME = "compat.deps"

HELPER_TARGET = "frida-helper"
HELPER_FILE_WINDOWS = Path("src") / "frida-helper.exe"
HELPER_FILE_UNIX = Path("src") / "frida-helper"

AGENT_TARGET = "frida-agent"
AGENT_FILE_WINDOWS = Path("lib") / "agent" / "frida-agent.dll"
AGENT_FILE_DARWIN = Path("lib") / "agent" / "frida-agent.dylib"
AGENT_FILE_ELF = Path("lib") / "agent" / "frida-agent.so"

GADGET_TARGET = "frida-gadget"
GADGET_FILE_WINDOWS = Path("lib") / "gadget" / "frida-gadget.dll"
GADGET_FILE_DARWIN = Path("lib") / "gadget" / "frida-gadget.dylib"
GADGET_FILE_ELF = Path("lib") / "gadget" / "frida-gadget.so"

SERVER_TARGET = "frida-server"
SERVER_FILE_UNIX = Path("server") / "frida-server"

MSVS_ENVVARS = {
    "PLATFORM",
    "VCINSTALLDIR",
    "INCLUDE",
    "LIB",
}

MINGW_ARCHS = {
    "x86": "i686",
    "arm64": "aarch64",
}


if __name__ == "__main__":
    main(sys.argv)

"""

```