Response:
Let's break down the thought process for analyzing the `meson_configure.py` script.

1. **Understand the Purpose:** The filename `meson_configure.py` and the import of `mesonbuild` strongly suggest this script is a configuration tool for a project using the Meson build system. The `frida` directory in the path indicates this is specific to the Frida project.

2. **Identify Key Actions:**  Scan the `main()` function for top-level actions. The presence of `argparse` tells us it handles command-line arguments. The calls to `configure()` and the handling of `builddir` existence are crucial configuration steps.

3. **Deconstruct `configure()`:** This is the core logic. Go through it step by step, noting the key variables and function calls:
    * **Paths:** `sourcedir`, `builddir`, `prefix`. These are standard for build systems.
    * **Machine Specs:** `build_machine`, `host_machine`. This hints at cross-compilation support.
    * **Environment:** Interaction with `os.environ`.
    * **Debug Symbols & Shared Libraries:**  Options related to build artifacts.
    * **Meson Execution:**  `call_selected_meson`. This confirms the script orchestrates Meson.
    * **Prebuilt Dependencies:**  The `allowed_prebuilds` and `deps` module suggest managing pre-compiled libraries.
    * **Toolchain and SDK:**  The calls to `deps.ensure_toolchain` and `deps.ensure_sdk` are significant for cross-compilation or providing a consistent build environment.
    * **Configuration Files:** Generation of `build_config` and `host_config` using `env.generate_machine_configs`. These are likely Meson cross/native files.
    * **Makefile Generation:** Creating `BSDmakefile`, `Makefile`, and `make.bat`. This indicates support for traditional `make` workflows in addition to Meson/Ninja.
    * **Environment Data:** Saving configuration in `frida-env.dat`. This is useful for subsequent build steps.

4. **Connect to Reverse Engineering:** Look for elements that are directly relevant to reverse engineering workflows:
    * **Dynamic Instrumentation:** The Frida project itself is about dynamic instrumentation. Configuration is a prerequisite.
    * **Debug Symbols:** The `--enable-symbols` option is a direct tie-in to debugging and reverse engineering.
    * **Cross-Compilation:**  Targeting different architectures (Android, etc.) is essential for reverse engineering on those platforms.
    * **Prebuilt Dependencies:**  Having prebuilt libraries can speed up the configuration process and ensure consistency, which is important when replicating reverse engineering environments.

5. **Identify Binary/Kernel/Framework Aspects:** Focus on the parts dealing with low-level details:
    * **Toolchain:** Compilers, linkers – fundamental for binary creation.
    * **SDK:** Libraries and headers needed to interact with specific operating systems (Linux, Android).
    * **Machine Specs:** Architecture (x86, ARM), OS (Linux, Windows, Android), and potentially ABI details.
    * **Cross-Compilation:**  By definition, involves targeting a different OS or architecture.
    * **`detect_project_vscrt`:**  Specifically for Windows, indicating interaction with the Visual Studio runtime.

6. **Look for Logic and Assumptions:**
    * **Default Paths:**  How `builddir` is determined.
    * **Precedence of Environment Variables:** `MESON_SOURCE_ROOT`, `MESON_BUILD_ROOT`.
    * **Prebuilt Logic:**  The `--without-prebuilds` option and how it affects dependency handling.
    * **Toolchain Selection:**  The internal vs. system Meson choice.

7. **Consider User Errors:** Think about common mistakes users might make:
    * **Running `configure` in the source directory:** The script detects this.
    * **Not having necessary dependencies:** The error messages for missing toolchains and SDKs.
    * **Incorrectly specifying prebuilt options.**
    * **Issues with environment variables (especially on Windows with Visual Studio).**

8. **Trace User Actions:**  Imagine the steps a user takes to reach this script:
    1. Clone the Frida repository.
    2. Navigate to the root directory.
    3. Run `./releng/meson_configure.py <source_directory> [options]`.

9. **Structure the Answer:** Organize the findings into logical sections (functionality, reverse engineering, low-level details, logic, errors, user actions). Use examples to illustrate points. Be clear and concise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just configures Meson."  **Correction:** It does more than that. It manages dependencies, handles toolchains/SDKs, and generates additional Makefiles.
* **Focusing too much on specific code lines:** **Correction:**  Step back and understand the higher-level purpose of blocks of code.
* **Overlooking the error handling:** **Correction:** The `try...except` blocks and the custom exception classes (`ToolchainNotFoundError`, `SDKNotFoundError`) are important for user feedback.
* **Not explicitly connecting to reverse engineering:** **Correction:**  Make the links clearer and provide concrete examples.

By following these steps and iteratively refining the analysis, you can create a comprehensive and accurate explanation of the script's functionality.
这是一个Frida动态 instrumentation工具的构建配置文件，用于配置使用Meson构建系统的Frida CLR（Common Language Runtime）部分。

以下是它的功能列表，并结合逆向、底层、内核、框架知识以及逻辑推理和用户错误进行说明：

**主要功能：**

1. **配置构建环境 (Core Function):**  这是脚本的主要目的。它根据用户提供的选项和系统环境，生成用于Meson构建系统的配置文件，以便后续的编译过程能够正确地执行。

2. **处理命令行参数:**
   - 使用 `argparse` 模块解析用户通过命令行传递的各种选项，例如安装路径 (`--prefix`)、目标构建平台 (`--build`)、宿主平台 (`--host`)、是否启用符号 (`--enable-symbols`)、是否构建共享库 (`--enable-shared`)、使用的Meson实现 (`--with-meson`) 以及额外的Meson选项。

3. **检测和管理构建目录:**
   - 确定源代码目录 (`sourcedir`) 和构建目录 (`builddir`)。
   - 如果构建目录已存在且已配置过，会提示用户并退出，避免重复配置。

4. **处理通用构建选项:**
   -  `--prefix`:  指定Frida安装的目标路径。这在逆向分析中很重要，因为你需要知道Frida的工具和库将被安装在哪里，以便在目标环境中使用。
   -  `--build` 和 `--host`: 支持交叉编译。在逆向Android或嵌入式系统时，你通常需要在桌面系统上交叉编译Frida agent。`--build` 指定运行构建的主机，`--host` 指定目标设备。
   -  `--enable-symbols`:  启用调试符号。这对于逆向工程至关重要，因为调试符号能让你在调试器中看到函数名、变量名等信息，极大地简化分析过程。
   -  `--enable-shared`:  构建共享库。这决定了Frida核心库是以静态链接还是动态链接的方式构建。动态链接通常更灵活，但也可能引入依赖问题。
   -  `--with-meson`:  选择使用的Meson实现。Frida可能自带了一个Meson的子模块，或者使用系统安装的Meson。

5. **处理项目特定的构建选项:**
   - 读取 `meson.options` 或 `meson_options.txt` 文件，解析并注册项目自定义的构建选项。这些选项允许用户更精细地控制Frida CLR的构建过程。

6. **处理预构建依赖 (Prebuilds):**
   - 允许用户通过 `--without-prebuilds` 选项排除某些类型的预构建包，例如工具链或SDK。
   - **与逆向的关系:** 使用预构建包可以加速构建过程，特别是对于交叉编译环境。例如，预构建的Android SDK可以省去从源代码编译的时间。排除预构建包可能用于调试构建问题或使用自定义的工具链/SDK。

7. **下载和管理依赖 (Toolchain & SDK):**
   - 使用 `deps` 模块检测和下载所需的工具链 (编译器、链接器等) 和 SDK (Software Development Kit)。
   - **与二进制底层，linux, android内核及框架的知识的关系:**
     - **工具链:**  编译生成的二进制文件直接依赖于工具链。选择正确的工具链对于生成目标平台可执行的二进制至关重要。例如，交叉编译Android agent需要使用Android NDK提供的工具链。
     - **SDK:** SDK提供了目标平台的库和头文件，用于编译Frida agent并使其能够与目标平台的API进行交互。例如，构建用于Android的Frida CLR需要Android SDK中关于ART虚拟机的头文件。
     - **Linux/Android内核及框架:**  Frida CLR需要与目标平台的运行时环境（例如，.NET Core在Linux上的实现或Android上的ART虚拟机）进行交互。SDK中包含了这些框架的接口定义。
   - **逻辑推理:** 脚本会根据目标平台 (`--host`) 推断需要下载的工具链和SDK。例如，如果 `--host` 指定为 `android-arm64`，它会尝试下载适用于Android ARM64架构的工具链和SDK。
   - **假设输入与输出:**
     - **输入:** `--host android-arm64`, 并且本地没有预构建的Android工具链和SDK。
     - **输出:** 脚本会尝试从预定义的源下载Android ARM64的工具链和SDK，并将它们放置在 `deps` 目录中。

8. **生成 Meson 的 native 和 cross 文件:**
   - 使用 `env.generate_machine_configs` 函数生成 Meson 构建系统所需的 native 文件（描述构建主机的环境）和 cross 文件（描述目标主机的环境）。
   - **与二进制底层，linux, android内核及框架的知识的关系:** 这些文件包含了关于目标平台架构、操作系统、编译器、链接器等关键信息，Meson 使用这些信息来配置构建过程，确保生成的二进制文件与目标平台兼容。

9. **调用 Meson 进行配置:**
   - 使用收集到的选项和生成的配置文件，调用 Meson 的 `setup` 命令来生成构建系统所需的构建文件 (通常是 Ninja 文件)。

10. **生成额外的 Makefile 和 Batch 文件:**
    - 为了方便用户，脚本还会生成传统的 `Makefile` (在类 Unix 系统上) 和 `make.bat` (在 Windows 上)，允许用户使用 `make` 命令进行构建。

11. **保存构建环境信息:**
    - 将重要的构建环境信息 (例如 Meson 配置、目标平台信息、允许的预构建类型) 序列化到 `frida-env.dat` 文件中，供后续的构建步骤使用。

**与逆向的方法的关系及举例说明:**

- **准备调试环境:**  通过 `--enable-symbols` 选项，可以构建包含调试符号的Frida agent，这对于在gdb或lldb等调试器中分析Frida的内部行为至关重要。例如，逆向Frida自身的功能或排查Frida agent在目标设备上的问题。
- **交叉编译 Frida Agent:**  使用 `--host` 选项可以配置为针对特定平台（如Android）构建Frida agent。这是在移动安全逆向中常见的步骤，需要在PC上编译出能在Android设备上运行的Frida agent。
- **定制构建选项:**  项目特定的构建选项可能允许用户启用或禁用某些Frida的功能，或者选择不同的底层实现，这在针对特定目标进行逆向分析时可能需要。例如，可能需要禁用某些安全特性以便进行更深入的分析。

**涉及二进制底层，linux, android内核及框架的知识及举例说明:**

- **目标架构 (`--host`):**  指定目标设备的CPU架构（例如，arm, arm64, x86, x86_64）。这直接影响编译器如何生成机器码。例如，为Android ARM64编译需要使用支持AArch64指令集的编译器。
- **操作系统 (`--host`):** 指定目标设备的操作系统（例如，linux, windows, android）。这影响链接器如何处理系统调用和库的链接。例如，在Android上，需要链接到Android的libc和linker。
- **工具链 (通过 `deps` 模块管理):**  脚本会根据目标平台选择合适的编译器、链接器、汇编器等。例如，交叉编译Android需要使用Android NDK提供的clang和lld。
- **SDK (通过 `deps` 模块管理):**  对于Android，SDK包含了Android系统的头文件和库，例如ART虚拟机的API，Frida CLR需要使用这些API来注入和hook .NET 代码。

**逻辑推理及假设输入与输出:**

- **假设输入:** 用户运行 `./releng/meson_configure.py . --host android-arm64 --enable-shared`
- **逻辑推理:**
    - 脚本会识别目标平台为 `android-arm64`。
    - 它会检查本地是否已经有适用于 `android-arm64` 的预构建工具链和SDK。
    - 如果没有，它会尝试下载。
    - 它会配置 Meson 以进行交叉编译，并启用共享库的构建。
- **输出:**
    - 生成适用于 Android ARM64 的 Meson 配置文件。
    - 如果成功，会在构建目录中生成 `build.ninja` 文件，以及可能的 `Makefile` 和 `make.bat` 文件。
    - 可能会下载 Android ARM64 的工具链和SDK 到 `deps` 目录。

**涉及用户或者编程常见的使用错误及举例说明:**

- **在错误的目录下运行脚本:** 用户可能在不是 Frida 源代码根目录的父目录运行脚本，导致找不到 `meson.options` 等文件。脚本会尝试根据环境变量 `MESON_SOURCE_ROOT` 来修正。
- **指定的 `--host` 不存在或拼写错误:**  如果用户指定的 `--host`  Meson 无法识别，配置过程会出错。脚本内部会使用 `MachineSpec.parse` 进行校验。
- **缺少必要的依赖:**  如果用户没有安装 Meson 或其他构建依赖，脚本在调用 Meson 时会失败。脚本依赖系统上安装的Python和一些基本的shell工具。
- **预构建依赖下载失败:**  网络问题可能导致预构建的工具链或SDK下载失败。脚本会抛出 `ToolchainNotFoundError` 或 `SDKNotFoundError` 异常。
- **权限问题:**  在某些系统上，用户可能没有写入构建目录或安装目录的权限。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **下载 Frida 源代码:** 用户通常会通过 Git 克隆 Frida 的源代码仓库。
2. **阅读构建文档或尝试构建:**  用户会查看 Frida 的构建文档或者尝试执行构建命令，这通常会引导他们运行配置脚本。
3. **执行配置脚本:**  用户在 Frida 源代码根目录下，或者在 `frida/subprojects/frida-clr/releng/` 目录下执行 `./meson_configure.py <源代码目录> [选项]`。
4. **遇到配置错误:**  如果配置过程中出现错误，用户可能会检查脚本的输出，查看错误信息，并根据错误信息调整命令行选项或环境。
5. **查看 `meson_configure.py` 源代码:**  为了理解配置过程的细节或排查问题，用户可能会查看 `meson_configure.py` 的源代码，以了解脚本是如何处理选项、下载依赖以及配置 Meson 的。

总而言之，`meson_configure.py` 是 Frida CLR 构建过程的关键入口点，它负责根据用户的需求和系统环境准备构建环境，并协调 Meson 构建系统的执行。理解这个脚本的功能对于成功构建 Frida CLR，以及在逆向工程中定制 Frida 的行为至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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