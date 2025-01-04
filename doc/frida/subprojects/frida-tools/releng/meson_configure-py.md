Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to recognize the overarching purpose of the script. The filename `meson_configure.py` within the `releng` directory strongly suggests it's involved in the configuration process of a software project that uses the Meson build system. The "frida-tools" part of the path indicates it's specific to the Frida project.

**2. Initial Code Scan - Identifying Key Components:**

A quick skim of the code reveals several important elements:

* **Imports:**  Libraries like `argparse`, `os`, `pathlib`, `subprocess`, etc., hint at command-line argument parsing, file system operations, and running external commands. The import of `mesonbuild` clearly confirms the Meson connection.
* **`main()` function:** This is the entry point of the script and where execution begins. It handles command-line arguments and orchestrates the configuration process.
* **`configure()` function:** This is the core logic of the configuration. It takes various parameters and sets up the build environment.
* **Argument Parsing (`argparse`):**  The `argparse` setup defines the command-line options users can provide (e.g., `--prefix`, `--build`, `--host`, `--enable-symbols`).
* **Dependency Handling (`deps`):** Imports from a local `deps` module indicate the script manages external dependencies (toolchains, SDKs).
* **Machine Specifications (`MachineSpec`):** The `MachineSpec` class suggests the script deals with different target architectures and operating systems.
* **Meson Interaction:**  The script calls Meson with specific options.
* **Prebuilt Bundles:**  The `--without-prebuilds` option and related logic point to the use of pre-compiled components for faster setup.

**3. Functional Decomposition (Thinking in terms of "What does it do?"):**

Now, let's analyze the functionality by considering what the script *does*:

* **Receives User Input:**  It takes command-line arguments.
* **Determines Build and Host Environments:** It figures out the target architecture and OS.
* **Manages Dependencies:** It downloads or uses existing toolchains and SDKs.
* **Generates Meson Configuration:** It creates Meson setup files (`build.ninja`).
* **Handles Cross-Compilation:** It supports building for different architectures.
* **Creates Build Scripts:** It generates `Makefile` and `make.bat`.
* **Stores Configuration Data:** It saves the configuration in `frida-env.dat`.

**4. Connecting to Reverse Engineering Concepts:**

With the functional understanding, we can now connect it to reverse engineering:

* **Target Environment Setup:** Reverse engineers often need to set up a specific environment to analyze a target (e.g., an Android app). This script automates that for Frida.
* **Cross-Compilation:**  Analyzing binaries for different architectures is common in RE. The script's cross-compilation support is directly relevant.
* **Debugging Symbols:**  The `--enable-symbols` option is crucial for debugging and reverse engineering.
* **Toolchain Management:** RE often involves using specific toolchains (compilers, linkers). This script manages those.
* **Understanding Build Processes:** Knowing how Frida is built (which this script helps define) can aid in understanding its internals.

**5. Identifying Binary/Low-Level/Kernel/Framework Connections:**

* **Toolchains (Binary):** Compilers and linkers operate on binaries.
* **Target Architectures (Low-Level):**  Options like `--build` and `--host` directly relate to CPU architectures.
* **Operating Systems (Kernel/Framework):** The script handles Windows, Linux, and Android. SDKs contain components of the operating system framework.
* **Shared Libraries (`--enable-shared`):** Understanding shared libraries is fundamental to reverse engineering as many programs use them.

**6. Logical Reasoning - Input/Output Examples:**

Think about different user inputs and the expected outcomes:

* **Basic Configuration:**  `python meson_configure.py .`  (Assumes building for the current system). Output: A `build` directory is created with Meson configuration files.
* **Cross-Compilation (Hypothetical):** `python meson_configure.py . --host=android-arm64`  Output: Configuration files for building Frida for Android on an ARM64 architecture.
* **Disabling Prebuilds:** `python meson_configure.py . --without-prebuilds=toolchain` Output: Configuration that relies on the system's toolchain.

**7. Common User Errors:**

Consider what could go wrong:

* **Incorrect Arguments:** Typos in option names or invalid values.
* **Missing Dependencies:** If prebuilds are disabled and required tools aren't present.
* **Existing Configuration:** Running the script again without cleaning the build directory.

**8. Tracing User Actions (Debugging Clues):**

How does a user end up running this script?

* **Initial Setup:**  The user wants to build Frida from source.
* **Following Documentation:**  The Frida documentation likely instructs users to run this script.
* **Build System Integration:**  This script is part of Frida's build process.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on individual lines of code.** The key is to step back and understand the *purpose* of different sections and functions.
* **Recognizing the importance of the `deps` module:**  This highlights the dependency management aspect, which is crucial for building complex software.
* **Connecting the prebuilt bundle concept to efficiency:**  Realizing that this is a way to speed up the build process.
* **Explicitly linking the options to RE concepts:**  For example, stating that `--enable-symbols` is vital for debugging.

By following these steps, we can systematically analyze the script and address all the requirements of the prompt, providing a comprehensive explanation of its functionality and its relevance to reverse engineering.
好的，让我们详细分析一下 `frida/subprojects/frida-tools/releng/meson_configure.py` 这个文件的功能。

**文件功能概述：**

这个 Python 脚本的主要功能是作为 Frida 工具链的一部分，用于配置使用 Meson 构建系统的 Frida 项目的构建环境。 它的作用类似于传统的 `configure` 脚本，但它是基于 Meson 构建系统的。  具体来说，它做了以下几件事情：

1. **解析命令行参数:**  接收用户提供的各种配置选项，例如安装路径、目标平台、是否启用调试符号、是否构建共享库等。
2. **检测构建环境和宿主环境:**  确定进行编译的机器（build）和编译出的二进制文件运行的机器（host）。这对于交叉编译非常重要。
3. **管理依赖:**  负责处理 Frida 构建所需的各种依赖，包括工具链（compiler, linker 等）和 SDK。它可以选择使用预编译的 bundle 来加速构建过程，或者在没有预编译 bundle 的情况下，可能需要从源代码构建一些依赖项（例如 Vala 编译器）。
4. **生成 Meson 构建文件:**  根据用户提供的选项和检测到的环境信息，生成 Meson 所需的 native 文件和 cross 文件（用于交叉编译）。这些文件包含了特定于构建和宿主机器的配置信息。
5. **调用 Meson 初始化构建目录:**  实际调用 Meson 的 `setup` 命令，使用前面生成的配置文件来初始化构建目录，并生成 `build.ninja` 文件，该文件包含了构建的规则。
6. **生成额外的构建脚本:**  生成 `BSDmakefile`、`Makefile` 和 `make.bat` 文件，方便在不直接使用 Meson 的情况下进行构建。
7. **保存构建环境信息:**  将构建过程中的重要信息（例如 Meson 版本、构建和宿主配置、允许的预编译 bundle 类型、依赖目录等）保存到 `frida-env.dat` 文件中，供后续构建步骤使用。

**与逆向方法的关系及举例说明：**

这个脚本与逆向工程密切相关，因为它负责配置 Frida 这个动态插桩工具的构建。Frida 本身就是逆向工程师常用的工具，用于运行时分析、修改和监控目标进程的行为。

* **配置目标平台：**  逆向工程师可能需要在不同的平台上使用 Frida，例如 Android、iOS、Linux、Windows 等。这个脚本允许通过 `--host` 参数指定目标平台，从而构建出适用于特定平台的 Frida 版本。
    * **举例：**  逆向工程师想要分析一个运行在 Android 设备上的应用程序，他们会使用 `--host=android-arm64` 或类似的选项来配置 Frida 的构建，以便在 Android 设备上运行 Frida 服务端。
* **启用调试符号：**  调试符号包含了源代码到二进制代码的映射信息，对于理解程序的执行流程和进行调试至关重要。通过 `--enable-symbols` 选项，可以在构建 Frida 时包含调试符号。
    * **举例：**  逆向工程师想要深入了解 Frida 内部的工作原理，或者在开发 Frida 脚本时进行调试，他们会启用调试符号，这样就可以在调试器中查看 Frida 的源代码。
* **构建共享库：**  Frida 的核心功能通常以共享库的形式提供。通过 `--enable-shared` 选项，可以构建出共享库版本的 Frida。
    * **举例：**  逆向工程师通常会将 Frida 的共享库注入到目标进程中。构建共享库是 Frida 正常工作的前提。
* **依赖管理和工具链：**  逆向工程工具的构建往往依赖于特定的工具链。这个脚本负责管理 Frida 的构建依赖，确保使用了正确的编译器、链接器等。
    * **举例：**  构建针对 Android 的 Frida 需要使用 Android NDK 提供的交叉编译工具链。这个脚本会根据 `--host` 参数选择合适的工具链。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这个脚本的很多功能都涉及到二进制底层、Linux、Android 内核及框架的知识：

* **目标架构 (`--build`, `--host`)：**  脚本需要理解不同的 CPU 架构，例如 x86, x86_64, ARM, ARM64 等。这些架构决定了指令集和二进制文件的格式。
    * **举例：**  指定 `--host=android-arm64` 表明目标平台是 Android，并且 CPU 架构是 ARM64。脚本需要知道如何为 ARM64 架构构建二进制文件。
* **操作系统 (`MachineSpec`)：**  脚本需要区分不同的操作系统，例如 Linux、Windows、Android。不同的操作系统有不同的 ABI（应用程序二进制接口）、系统调用约定、文件系统结构等。
    * **举例：**  针对 Android 构建时，脚本需要考虑 Android 特有的动态链接器、权限模型等。
* **工具链 (Toolchain)：**  构建过程需要使用编译器（例如 GCC, Clang）、链接器、汇编器等工具。这些工具直接操作二进制文件，将源代码转换为机器码。
    * **举例：**  在交叉编译到 Android 时，会使用 Android NDK 提供的 `aarch64-linux-android-gcc` 等工具。
* **共享库 (`--enable-shared`)：**  共享库是操作系统的重要组成部分，允许多个进程共享同一份代码和数据，节省内存。理解共享库的加载、链接过程对于逆向工程至关重要。
    * **举例：**  Frida 的核心功能以共享库（例如 `frida-agent.so` 在 Android 上）的形式存在，需要被注入到目标进程中。
* **SDK (Software Development Kit)：**  SDK 包含了特定平台开发的库、头文件和工具。构建 Frida 时可能需要依赖目标平台的 SDK。
    * **举例：**  构建 Android 版本的 Frida 需要 Android SDK 和 NDK。
* **预编译 Bundle：**  为了加速构建，Frida 使用了预编译的工具链和 SDK。这涉及到对不同平台构建过程的理解，并能将构建产物打包成可分发的 bundle。
    * **举例：**  脚本会尝试下载针对特定平台和架构的预编译 toolchain 或 sdk bundle。

**逻辑推理、假设输入与输出：**

脚本中存在一些逻辑推理，例如根据用户提供的参数和环境变量来推断构建和宿主环境，以及选择合适的依赖。

* **假设输入：** 用户在 Linux x86_64 系统上执行命令 `python meson_configure.py . --prefix=/opt/frida --enable-shared`。
* **输出：**
    * 脚本会检测到构建机器（build）是 Linux x86_64。
    * 宿主机器（host）也会被默认为 Linux x86_64（因为没有指定 `--host`）。
    * 安装路径（prefix）被设置为 `/opt/frida`。
    * 启用了共享库构建。
    * 脚本会尝试找到或下载适用于 Linux x86_64 的依赖，并生成相应的 Meson 配置文件。
    * Meson 会在当前目录下的 `build` 目录中初始化构建环境，生成 `build.ninja` 文件，并且配置会包含构建共享库的选项。
    * `frida-env.dat` 文件会记录这些配置信息。

* **假设输入：** 用户在 macOS 上执行命令 `python meson_configure.py . --host=android-arm64`。
* **输出：**
    * 脚本会检测到构建机器是 macOS x86_64 或 arm64。
    * 宿主机器被设置为 Android ARM64。
    * 脚本会进行交叉编译配置。
    * 它会尝试找到或下载适用于 Android ARM64 的工具链和 SDK bundle。
    * 生成的 Meson 配置文件会指示 Meson 使用交叉编译工具链，并链接 Android 相关的库。
    * `frida-env.dat` 文件会记录构建机器和宿主机器的信息，以及交叉编译相关的配置。

**用户或编程常见的使用错误及举例说明：**

* **未安装必要的依赖：** 如果用户禁用了预编译 bundle (`--without-prebuilds`)，但系统上又没有安装构建所需的工具（例如编译器、Vala），脚本会报错。
    * **举例：**  用户执行 `python meson_configure.py . --without-prebuilds=toolchain`，但系统上没有安装 GCC 或 Clang，Meson 的配置过程会失败。
* **指定了无效的选项：** 用户可能会输入错误的选项名称或值。
    * **举例：**  用户输入了 `--enables-symbols` (拼写错误) 而不是 `--enable-symbols`，`argparse` 会报错提示未知选项。
* **在已配置的目录中重新运行：** 如果用户在已经配置过的构建目录中重新运行脚本，并且没有清理之前的构建文件，脚本会提示已经配置过，并建议清理目录。
    * **举例：**  用户第一次运行 `python meson_configure.py .` 后，又再次运行，脚本会打印 "Already configured. Wipe ./build to reconfigure."
* **交叉编译环境未配置好：** 进行交叉编译时，如果用户的环境变量没有正确设置（例如缺少 Android NDK 的路径），或者预编译的 bundle 不存在，脚本可能会报错。
    * **举例：**  用户执行 `python meson_configure.py . --host=android-arm64`，但没有设置 `ANDROID_NDK_HOME` 环境变量，脚本在尝试使用 NDK 工具时会失败。

**用户操作是如何一步步到达这里的，作为调试线索：**

通常，用户需要构建 Frida 时，会按照以下步骤操作，最终会执行到这个脚本：

1. **下载 Frida 源代码：** 用户从 Frida 的 GitHub 仓库或其他渠道获取源代码。
2. **进入 Frida Tools 目录：**  用户会进入 `frida/subprojects/frida-tools` 目录，因为 `meson_configure.py` 是这个子项目的一部分。
3. **阅读构建文档：**  Frida 的文档会指导用户如何进行构建，通常会提到运行 `meson_configure.py` 脚本。
4. **执行配置脚本：**  用户会在命令行中执行 `python releng/meson_configure.py <源代码根目录>`，其中 `<源代码根目录>` 通常是 `frida` 目录的父目录，或者当前目录 `.`。
5. **根据需要添加选项：**  用户可能会根据自己的需求添加额外的选项，例如 `--prefix` 指定安装路径，`--host` 指定目标平台，`--enable-symbols` 启用调试符号等。
6. **查看输出和错误信息：**  用户会查看脚本的输出信息，了解配置过程是否成功，或者根据错误信息排查问题。

**作为调试线索：**

* **检查命令行参数：**  首先检查用户执行命令时提供的参数是否正确，例如选项名称、值是否合法。
* **查看环境变量：**  特别是进行交叉编译时，需要检查相关的环境变量是否设置正确，例如 `ANDROID_NDK_HOME` 等。
* **检查预编译 bundle 的存在：**  如果启用了预编译 bundle，需要确认相关的 bundle 文件是否存在于默认的下载目录或用户指定的目录。
* **查看 `meson_options.txt`：**  这个文件定义了项目特定的 Meson 选项，可以帮助理解有哪些可配置的选项。
* **分析脚本的逻辑：**  如果配置过程中出现错误，可以逐步分析脚本的代码，了解它是如何检测环境、处理依赖和生成配置文件的。
* **查看 Meson 的输出：**  脚本最终会调用 Meson，可以查看 Meson 的输出信息，了解更底层的配置过程和错误信息。
* **检查 `frida-env.dat`：**  这个文件记录了配置过程中的重要信息，可以用来诊断配置是否符合预期。

希望以上分析能够帮助你理解 `frida/subprojects/frida-tools/releng/meson_configure.py` 文件的功能和它在 Frida 构建过程中的作用。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
import argparse
import os
from pathlib import Path
import pickle
import platform
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any, Callable, Optional

RELENG_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = RELENG_DIR / "meson-scripts"

sys.path.insert(0, str(RELENG_DIR / "meson"))
import mesonbuild.interpreter
from mesonbuild.coredata import UserArrayOption, UserBooleanOption, \
        UserComboOption, UserFeatureOption, UserOption, UserStringOption

from . import deps, env
from .machine_spec import MachineSpec
from .progress import ProgressCallback, print_progress


def main():
    default_sourcedir = Path(sys.argv.pop(1))
    sourcedir = Path(os.environ.get("MESON_SOURCE_ROOT", default_sourcedir)).resolve()

    workdir = Path(os.getcwd())
    if workdir == sourcedir:
        default_builddir = sourcedir / "build"
    else:
        default_builddir = workdir
    builddir = Path(os.environ.get("MESON_BUILD_ROOT", default_builddir)).resolve()

    parser = argparse.ArgumentParser(prog="configure",
                                     add_help=False)
    opts = parser.add_argument_group(title="generic options")
    opts.add_argument("-h", "--help",
                      help="show this help message and exit",
                      action="help")
    opts.add_argument("--prefix",
                      help="install files in PREFIX",
                      metavar="PREFIX",
                      type=parse_prefix)
    opts.add_argument("--build",
                      help="configure for building on BUILD",
                      metavar="BUILD",
                      type=MachineSpec.parse)
    opts.add_argument("--host",
                      help="cross-compile to build binaries to run on HOST",
                      metavar="HOST",
                      type=MachineSpec.parse)
    opts.add_argument("--enable-symbols",
                      help="build binaries with debug symbols included (default: disabled)",
                      action="store_true")
    opts.add_argument("--enable-shared",
                      help="enable building shared libraries (default: disabled)",
                      action="store_true")
    opts.add_argument("--with-meson",
                      help="which Meson implementation to use (default: internal)",
                      choices=["internal", "system"],
                      dest="meson",
                      default="internal")
    opts.add_argument(f"--without-prebuilds",
                      help="do not make use of prebuilt bundles",
                      metavar="{" + ",".join(query_supported_bundle_types(include_wildcards=True)) + "}",
                      type=parse_bundle_type_set,
                      default=set())
    opts.add_argument("extra_meson_options",
                      nargs="*",
                      help=argparse.SUPPRESS)

    meson_options_file = sourcedir / "meson.options"
    if not meson_options_file.exists():
        meson_options_file = sourcedir / "meson_options.txt"
    if meson_options_file.exists():
        meson_group = parser.add_argument_group(title="project-specific options")
        meson_opts = register_meson_options(meson_options_file, meson_group)

    options = parser.parse_args()

    if builddir.exists():
        if (builddir / "build.ninja").exists():
            print(f"Already configured. Wipe .{os.sep}{builddir.relative_to(workdir)} to reconfigure.",
                  file=sys.stderr)
            sys.exit(1)

    default_library = "shared" if options.enable_shared else "static"

    allowed_prebuilds = set(query_supported_bundle_types(include_wildcards=False)) - options.without_prebuilds

    try:
        configure(sourcedir,
                  builddir,
                  options.prefix,
                  options.build,
                  options.host,
                  os.environ,
                  "included" if options.enable_symbols else "stripped",
                  default_library,
                  allowed_prebuilds,
                  options.meson,
                  collect_meson_options(options))
    except Exception as e:
        print(e, file=sys.stderr)
        if isinstance(e, subprocess.CalledProcessError):
            for label, data in [("Output", e.output),
                                ("Stderr", e.stderr)]:
                if data:
                    print(f"{label}:\n\t| " + "\n\t| ".join(data.strip().split("\n")), file=sys.stderr)
        sys.exit(1)


def configure(sourcedir: Path,
              builddir: Path,
              prefix: Optional[str] = None,
              build_machine: Optional[MachineSpec] = None,
              host_machine: Optional[MachineSpec] = None,
              environ: dict[str, str] = os.environ,
              debug_symbols: str = "stripped",
              default_library: str = "static",
              allowed_prebuilds: set[str] = None,
              meson: str = "internal",
              extra_meson_options: list[str] = [],
              call_meson: Callable = env.call_meson,
              on_progress: ProgressCallback = print_progress):
    if prefix is None:
        prefix = env.detect_default_prefix()

    project_vscrt = detect_project_vscrt(sourcedir)

    if build_machine is None:
        build_machine = MachineSpec.make_from_local_system()
    build_machine = build_machine.default_missing(recommended_vscrt=project_vscrt)

    if host_machine is None:
        host_machine = build_machine
    else:
        host_machine = host_machine.default_missing(recommended_vscrt=project_vscrt)

    if host_machine.os == "windows":
        vs_arch = environ.get("VSCMD_ARG_TGT_ARCH")
        if vs_arch == "x86":
            host_machine = host_machine.evolve(arch=vs_arch)

    build_machine = build_machine.maybe_adapt_to_host(host_machine)

    if allowed_prebuilds is None:
        allowed_prebuilds = set(query_supported_bundle_types(include_wildcards=False))

    call_selected_meson = lambda argv, *args, **kwargs: call_meson(argv,
                                                                   use_submodule=meson == "internal",
                                                                   *args,
                                                                   **kwargs)

    meson_options = [
        f"-Dprefix={prefix}",
        f"-Ddefault_library={default_library}",
        *host_machine.meson_optimization_options,
    ]
    if debug_symbols == "stripped" and host_machine.toolchain_can_strip:
        meson_options += ["-Dstrip=true"]

    deps_dir = deps.detect_cache_dir(sourcedir)

    allow_prebuilt_toolchain = "toolchain" in allowed_prebuilds
    if allow_prebuilt_toolchain:
        try:
            toolchain_prefix, _ = deps.ensure_toolchain(build_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_toolchain_not_found(e)
    else:
        if project_depends_on_vala_compiler(sourcedir):
            toolchain_prefix = deps.query_toolchain_prefix(build_machine, deps_dir)
            vala_compiler = env.detect_toolchain_vala_compiler(toolchain_prefix, build_machine)
            if vala_compiler is None:
                build_vala_compiler(toolchain_prefix, deps_dir, call_selected_meson)
        else:
            toolchain_prefix = None

    is_cross_build = host_machine != build_machine

    build_sdk_prefix = None
    required = {"sdk:build"}
    if not is_cross_build:
        required.add("sdk:host")
    if allowed_prebuilds.issuperset(required):
        try:
            build_sdk_prefix, _ = deps.ensure_sdk(build_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_sdk_not_found(e, "build", build_machine)

    host_sdk_prefix = None
    if is_cross_build and "sdk:host" in allowed_prebuilds:
        try:
            host_sdk_prefix, _ = deps.ensure_sdk(host_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_sdk_not_found(e, "host", host_machine)

    build_config, host_config = \
            env.generate_machine_configs(build_machine,
                                         host_machine,
                                         environ,
                                         toolchain_prefix,
                                         build_sdk_prefix,
                                         host_sdk_prefix,
                                         call_selected_meson,
                                         default_library,
                                         builddir)

    meson_options += [f"--native-file={build_config.machine_file}"]
    if host_config is not build_config:
        meson_options += [f"--cross-file={host_config.machine_file}"]

    setup_env = host_config.make_merged_environment(environ)
    setup_env["FRIDA_ALLOWED_PREBUILDS"] = ",".join(allowed_prebuilds)

    call_selected_meson(["setup"] + meson_options + extra_meson_options + [builddir],
                        cwd=sourcedir,
                        env=setup_env,
                        check=True)

    shutil.copy(SCRIPTS_DIR / "BSDmakefile", builddir)
    (builddir / "Makefile").write_text(generate_out_of_tree_makefile(sourcedir), encoding="utf-8")
    if platform.system() == "Windows":
        (builddir / "make.bat").write_text(generate_out_of_tree_make_bat(sourcedir), encoding="utf-8")

    (builddir / "frida-env.dat").write_bytes(pickle.dumps({
        "meson": meson,
        "build": build_config,
        "host": host_config if host_config is not build_config else None,
        "allowed_prebuilds": allowed_prebuilds,
        "deps": deps_dir,
    }))


def parse_prefix(raw_prefix: str) -> Path:
    prefix = Path(raw_prefix)
    if not prefix.is_absolute():
        prefix = Path(os.getcwd()) / prefix
    return prefix


def query_supported_bundle_types(include_wildcards: bool) -> list[str]:
    for e in deps.Bundle:
        identifier = e.name.lower()
        if e == deps.Bundle.SDK:
            if include_wildcards:
                yield identifier
            yield identifier + ":build"
            yield identifier + ":host"
        else:
            yield identifier


def query_supported_bundle_type_values() -> list[deps.Bundle]:
    return [e for e in deps.Bundle]


def parse_bundle_type_set(raw_array: str) -> list[str]:
    supported_types = list(query_supported_bundle_types(include_wildcards=True))
    result = set()
    for element in raw_array.split(","):
        bundle_type = element.strip()
        if bundle_type not in supported_types:
            pretty_choices = "', '".join(supported_types)
            raise argparse.ArgumentTypeError(f"invalid bundle type: '{bundle_type}' (choose from '{pretty_choices}')")
        if bundle_type == "sdk":
            result.add("sdk:build")
            result.add("sdk:host")
        else:
            result.add(bundle_type)
    return result


def raise_toolchain_not_found(e: Exception):
    raise ToolchainNotFoundError("\n".join([
        f"Unable to download toolchain: {e}",
        "",
        "Specify --without-prebuilds=toolchain to only use tools on your PATH.",
        "",
        "Another option is to do what Frida's CI does:",
        "",
        "    ./releng/deps.py build --bundle=toolchain",
        "",
        "This produces a tarball in ./deps which gets picked up if you retry `./configure`.",
        "You may also want to make a backup of it for future reuse.",
    ]))


def raise_sdk_not_found(e: Exception, kind: str, machine: MachineSpec):
    raise SDKNotFoundError("\n".join([
        f"Unable to download SDK: {e}",
        "",
        f"Specify --without-prebuilds=sdk:{kind} to build dependencies from source code.",
        "",
        "Another option is to do what Frida's CI does:",
        "",
        f"    ./releng/deps.py build --bundle=sdk --host={machine.identifier}",
        "",
        "This produces a tarball in ./deps which gets picked up if you retry `./configure`.",
        "You may also want to make a backup of it for future reuse.",
    ]))


def generate_out_of_tree_makefile(sourcedir: Path) -> str:
    m = ((SCRIPTS_DIR / "Makefile").read_text(encoding="utf-8")
            .replace("sys.argv[1]", "r'" + str(RELENG_DIR.parent) + "'")
            .replace('"$(shell pwd)"', shlex.quote(str(sourcedir)))
            .replace("./build", "."))
    return re.sub(r"git-submodules:.+?(?=\.PHONY:)", "", m, flags=re.MULTILINE | re.DOTALL)


def generate_out_of_tree_make_bat(sourcedir: Path) -> str:
    m = ((SCRIPTS_DIR / "make.bat").read_text(encoding="utf-8")
            .replace("sys.argv[1]", "r'" + str(RELENG_DIR.parent) + "'")
            .replace('"%dp0%"', '"' + str(sourcedir) + '"')
            .replace('.\\build', "\"%dp0%\""))
    return re.sub(r"if not exist .+?(?=endlocal)", "", m, flags=re.MULTILINE | re.DOTALL)


def register_meson_options(meson_option_file: Path, group: argparse._ArgumentGroup):
    interpreter = mesonbuild.optinterpreter.OptionInterpreter(subproject="")
    interpreter.process(meson_option_file)

    for key, opt in interpreter.options.items():
        name = key.name
        pretty_name = name.replace("_", "-")

        if isinstance(opt, UserFeatureOption):
            if opt.value != "enabled":
                action = "enable"
                value_to_set = "enabled"
            else:
                action = "disable"
                value_to_set = "disabled"
            group.add_argument(f"--{action}-{pretty_name}",
                               action="append_const",
                               const=f"-D{name}={value_to_set}",
                               dest="main_meson_options",
                               **parse_option_meta(name, action, opt))
            if opt.value == "auto":
                group.add_argument(f"--disable-{pretty_name}",
                                   action="append_const",
                                   const=f"-D{name}=disabled",
                                   dest="main_meson_options",
                                   **parse_option_meta(name, "disable", opt))
        elif isinstance(opt, UserBooleanOption):
            if not opt.value:
                action = "enable"
                value_to_set = "true"
            else:
                action = "disable"
                value_to_set = "false"
            group.add_argument(f"--{action}-{pretty_name}",
                               action="append_const",
                               const=f"-D{name}={value_to_set}",
                               dest="main_meson_options",
                               **parse_option_meta(name, action, opt))
        elif isinstance(opt, UserComboOption):
            group.add_argument(f"--with-{pretty_name}",
                               choices=opt.choices,
                               dest="meson_option:" + name,
                               **parse_option_meta(name, "with", opt))
        elif isinstance(opt, UserArrayOption):
            group.add_argument(f"--with-{pretty_name}",
                               dest="meson_option:" + name,
                               type=make_array_option_value_parser(opt),
                               **parse_option_meta(name, "with", opt))
        else:
            group.add_argument(f"--with-{pretty_name}",
                               dest="meson_option:" + name,
                               **parse_option_meta(name, "with", opt))


def parse_option_meta(name: str,
                      action: str,
                      opt: UserOption[Any]):
    params = {}

    if isinstance(opt, UserStringOption):
        default_value = repr(opt.value)
        metavar = name.upper()
    elif isinstance(opt, UserArrayOption):
        default_value = ",".join(opt.value)
        metavar = "{" + ",".join(opt.choices) + "}"
    elif isinstance(opt, UserComboOption):
        default_value = opt.value
        metavar = "{" + "|".join(opt.choices) + "}"
    else:
        default_value = str(opt.value).lower()
        metavar = name.upper()

    if not (isinstance(opt, UserFeatureOption) \
            and opt.value == "auto" \
            and action == "disable"):
        text = f"{help_text_from_meson(opt.description)} (default: {default_value})"
        if action == "disable":
            text = "do not " + text
        params["help"] = text
    params["metavar"] = metavar

    return params


def help_text_from_meson(description: str) -> str:
    if description:
        return description[0].lower() + description[1:]
    return description


def collect_meson_options(options: argparse.Namespace) -> list[str]:
    result = []

    for raw_name, raw_val in vars(options).items():
        if raw_val is None:
            continue
        if raw_name == "main_meson_options":
            result += raw_val
        if raw_name.startswith("meson_option:"):
            name = raw_name[13:]
            val = raw_val if isinstance(raw_val, str) else ",".join(raw_val)
            result += [f"-D{name}={val}"]

    result += options.extra_meson_options

    return result


def make_array_option_value_parser(opt: UserOption[Any]) -> Callable[[str], list[str]]:
    return lambda v: parse_array_option_value(v, opt)


def parse_array_option_value(v: str, opt: UserArrayOption) -> list[str]:
    vals = [v.strip() for v in v.split(",")]

    choices = opt.choices
    for v in vals:
        if v not in choices:
            pretty_choices = "', '".join(choices)
            raise argparse.ArgumentTypeError(f"invalid array value: '{v}' (choose from '{pretty_choices}')")

    return vals


def detect_project_vscrt(sourcedir: Path) -> Optional[str]:
    m = next(re.finditer(r"project\(([^)]+\))", read_meson_build(sourcedir)), None)
    if m is not None:
        project_args = m.group(1)
        m = next(re.finditer("'b_vscrt=([^']+)'", project_args), None)
        if m is not None:
            return m.group(1)
    return None


def project_depends_on_vala_compiler(sourcedir: Path) -> bool:
    return "'vala'" in read_meson_build(sourcedir)


def read_meson_build(sourcedir: Path) -> str:
    return (sourcedir / "meson.build").read_text(encoding="utf-8")


def build_vala_compiler(toolchain_prefix: Path, deps_dir: Path, call_selected_meson: Callable):
    print("Building Vala compiler...", flush=True)

    workdir = deps_dir / "src"
    workdir.mkdir(parents=True, exist_ok=True)

    git = lambda *args, **kwargs: subprocess.run(["git", *args],
                                                 **kwargs,
                                                 capture_output=True,
                                                 encoding="utf-8")
    vala_checkout = workdir / "vala"
    if vala_checkout.exists():
        shutil.rmtree(vala_checkout)
    vala_pkg = deps.load_dependency_parameters().packages["vala"]
    deps.clone_shallow(vala_pkg, vala_checkout, git)

    run_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "encoding": "utf-8",
        "check": True,
    }
    call_selected_meson([
                            "setup",
                            f"--prefix={toolchain_prefix}",
                            "-Doptimization=2",
                            "build",
                        ],
                        cwd=vala_checkout,
                        **run_kwargs)
    call_selected_meson(["install"],
                        cwd=vala_checkout / "build",
                        **run_kwargs)


class ToolchainNotFoundError(Exception):
    pass


class SDKNotFoundError(Exception):
    pass

"""

```