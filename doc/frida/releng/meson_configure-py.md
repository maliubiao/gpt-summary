Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code to grasp its primary purpose. Keywords like `configure`, `meson`, `build`, `host`, `prefix`, and the file path `frida/releng/meson_configure.py` strongly suggest that this script is responsible for configuring the build process of the Frida dynamic instrumentation tool using the Meson build system. The `releng` directory often indicates release engineering or build-related tasks.

**2. Identifying Core Functionality - The `configure` Function:**

The `configure` function stands out as it orchestrates the configuration process. I'd focus on its parameters and what it does with them:

* `sourcedir`, `builddir`, `prefix`: Standard build system concepts.
* `build_machine`, `host_machine`:  Indicates support for cross-compilation.
* `environ`:  Interaction with the environment.
* `debug_symbols`, `default_library`:  Build options.
* `allowed_prebuilds`:  A key feature, suggesting the use of precompiled binaries.
* `meson`:  Choice of Meson implementation.
* `extra_meson_options`:  Passing through additional Meson flags.
* `call_meson`:  Abstraction for invoking Meson.

**3. Tracing the Execution Flow - The `main` Function:**

The `main` function is the entry point. It handles:

* Argument parsing using `argparse`. This is a critical area for understanding user input.
* Determining source and build directories.
* Checking for existing configurations.
* Calling the `configure` function with parsed arguments.

**4. Identifying Key Components and Their Roles:**

* **`MachineSpec`:**  Represents build and host machines, crucial for cross-compilation. Look for how it's parsed and used.
* **`deps` module:**  Deals with dependencies, including prebuilt ones. Pay attention to functions like `ensure_toolchain`, `ensure_sdk`, and the concept of "bundles."
* **Meson:**  The underlying build system. The script wraps and interacts with it.
* **Prebuilt Bundles:**  A significant optimization. Understand how the script manages and selects them.

**5. Analyzing Function-Specific Logic:**

Go through each function and understand its purpose:

* **Argument Parsing (`argparse`):**  What options are available to the user? How do they map to configuration settings?
* **Path Handling (`pathlib`):**  How are directories and files managed?
* **Meson Interaction (`call_meson`):**  How is Meson invoked? What arguments are passed?
* **Dependency Management (`deps` module):** How are toolchains and SDKs handled?  What are the different bundle types?
* **Environment Variables:** How are they used and modified?
* **Makefile Generation:** Why are `BSDmakefile`, `Makefile`, and `make.bat` generated?

**6. Connecting to Reverse Engineering Concepts:**

Think about how the script's functionality relates to reverse engineering:

* **Dynamic Instrumentation:** The script configures the build for Frida, a dynamic instrumentation tool *itself used for reverse engineering*.
* **Debug Symbols:** The `--enable-symbols` option is directly related to making reverse engineering easier.
* **Cross-Compilation:** Building Frida for different architectures (like Android) is essential for reverse engineering on those platforms.
* **Binary Stripping:** The script handles stripping debug symbols, which is a technique used to make reverse engineering harder.

**7. Identifying Low-Level and Kernel Aspects:**

Look for elements related to operating systems and architectures:

* **`MachineSpec`:**  OS, architecture are key attributes.
* **Toolchains:**  Compiler and linker specifics for target platforms.
* **SDKs:**  Libraries and headers needed for building on specific platforms.
* **Cross-Compilation:**  Involves understanding different ABIs and system calls.
* **Windows-Specific Handling:** The script has logic for Windows, indicating platform-specific considerations.

**8. Inferring Logical Reasoning and Assumptions:**

Consider the conditions and choices made in the code:

* **Default Settings:** What happens if the user doesn't provide specific options?
* **Prebuilt Selection:** How does the script decide whether to use a prebuilt bundle?
* **Cross-Compilation Logic:** How are build and host machines handled differently?
* **Error Handling:** What happens when dependencies are not found?

**9. Identifying Potential User Errors:**

Think about how a user might misuse the script:

* **Incorrect Arguments:**  Typos, invalid options.
* **Missing Dependencies:** Not having necessary tools or libraries.
* **Conflicting Options:**  Providing mutually exclusive settings.
* **Trying to Reconfigure:**  Not wiping the build directory.

**10. Tracing User Actions to the Script:**

Consider the typical workflow for building Frida:

1. Cloning the Frida repository.
2. Navigating to the repository directory.
3. Running a configuration script (this script).

The command-line arguments passed to this script are the direct result of user actions.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretations:**  I might initially misunderstand the purpose of a specific function. Rereading the code and looking at its interactions with other parts can clarify this.
* **Overlooking Details:**  It's easy to miss subtle aspects. Going back and carefully reviewing sections, especially around conditional logic, is important.
* **Clarifying Terminology:**  Making sure I understand terms like "toolchain," "SDK," and "prebuilt bundle" is crucial for an accurate analysis.

By following this structured approach, I can systematically analyze the code, understand its functionality, and relate it to the specific questions asked. The iterative process of skimming, focusing on key components, analyzing details, and then connecting it to broader concepts is key to effective code comprehension.
这个Python脚本 `meson_configure.py` 的主要功能是 **配置 Frida 的构建环境**，它是一个使用 Meson 构建系统的辅助脚本。它允许用户自定义构建选项，处理依赖关系，并生成必要的构建文件。

以下是其功能的详细列表，并结合你提出的几个方面进行解释：

**1. 功能列表:**

* **解析命令行参数:** 使用 `argparse` 模块解析用户提供的命令行选项，例如 `--prefix` (安装路径), `--build` (构建机器规范), `--host` (目标机器规范), `--enable-symbols` (启用调试符号) 等。
* **确定构建和源目录:** 自动或根据环境变量 (`MESON_SOURCE_ROOT`, `MESON_BUILD_ROOT`) 确定源代码目录和构建目录。
* **处理预构建包 (Prebuilds):** 允许用户指定是否使用预构建的工具链和 SDK，以加速构建过程。
* **下载和管理依赖:** 使用 `frida.releng.deps` 模块来下载和管理构建所需的依赖项，例如工具链和 SDK。
* **生成 Meson 配置文件:** 根据用户选项和系统环境生成 Meson 构建系统所需的 native 和 cross-compilation 文件。
* **调用 Meson 构建系统:** 使用内部或系统的 Meson 实现 (`--with-meson` 选项) 来执行 Meson 的 `setup` 命令，初始化构建环境。
* **生成 Makefile:**  生成一个顶层的 `Makefile` (以及 Windows 上的 `make.bat`)，方便用户使用 `make` 命令进行构建。
* **保存构建环境信息:** 将构建配置信息保存到 `frida-env.dat` 文件中，供后续构建步骤使用。
* **处理项目特定的 Meson 选项:**  读取 `meson.options` 或 `meson_options.txt` 文件，解析项目自定义的构建选项，并将它们添加到 Meson 的配置中。
* **检测项目依赖:**  检查 `meson.build` 文件，以确定项目是否依赖特定的工具，例如 Vala 编译器。

**2. 与逆向方法的关系:**

这个脚本直接关系到 Frida 逆向工具的构建过程。

* **示例:** 用户想要构建一个带有调试符号的 Frida 版本，以便在逆向分析目标程序时能够更方便地进行调试。用户可以使用 `--enable-symbols` 选项来配置构建，生成的 Frida 库和可执行文件将包含调试信息。
* **解释:**  Frida 是一个动态插桩工具，广泛应用于软件逆向工程。这个脚本确保 Frida 能够被正确构建，使其能够执行代码注入、hook 函数、跟踪执行等逆向分析的核心功能。通过配置选项，开发者可以控制最终构建出的 Frida 版本的特性，例如是否包含调试符号，这直接影响到逆向分析的便捷程度。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识:**

这个脚本在配置构建过程中涉及到这些底层的概念。

* **二进制底层:**
    * **工具链选择:** 脚本需要根据目标平台（通过 `--build` 和 `--host` 选项指定）选择合适的编译器、链接器等工具链。不同的架构（如 x86, ARM, ARM64）需要不同的工具链来生成相应的二进制代码。
    * **调试符号:** `--enable-symbols` 选项控制是否在生成的二进制文件中包含调试信息，这些信息在底层包含了符号表、行号等，用于调试器将二进制地址映射回源代码。
    * **共享库/静态库:** `--enable-shared` 选项决定 Frida 的核心组件是以共享库 (`.so` 或 `.dylib` 或 `.dll`) 还是静态库 (`.a` 或 `.lib`) 的形式构建。这影响到最终程序如何加载和链接 Frida 的代码。
    * **剥离符号 (Stripping):** 脚本可以根据目标平台的能力选择是否剥离最终二进制文件中的符号信息，减小文件大小，但也增加了逆向分析的难度。
* **Linux 和 Android 内核及框架:**
    * **交叉编译:**  如果要构建用于 Android 平台的 Frida，需要进行交叉编译。脚本中的 `--host` 选项用于指定目标 Android 平台的架构，脚本会配置 Meson 使用相应的 Android NDK 工具链。
    * **SDK (Software Development Kit):**  构建 Frida 可能需要特定平台的 SDK，例如 Android SDK。脚本会下载和使用这些 SDK 中的头文件和库文件。
    * **目标平台适配:**  脚本需要处理不同操作系统的差异，例如 Windows 和 Linux 在库文件命名、路径约定等方面有所不同。
    * **VSCrt (Visual C Runtime):** 在 Windows 平台上，脚本会检测并考虑项目所需的 Visual C++ 运行时库。

* **示例:**
    * **交叉编译到 Android:** 用户使用 `--host android,arm64` 配置构建，脚本会下载 Android NDK 并配置 Meson 使用 `aarch64-linux-android-clang` 等编译器。
    * **构建带符号的 Frida Server for Android:** 用户使用 `--host android,arm64 --enable-symbols`，生成的 `frida-server` 可执行文件将包含调试信息，方便在 Android 设备上进行调试。

**4. 逻辑推理 (假设输入与输出):**

假设用户执行以下命令:

```bash
python3 releng/meson_configure.py . --prefix=/opt/frida --host=linux,x64 --enable-shared
```

* **假设输入:**
    * `sourcedir`: 当前目录 (".")
    * `--prefix`: `/opt/frida`
    * `--host`: `linux,x64`
    * `--enable-shared`: 存在
* **逻辑推理:**
    1. 脚本解析命令行参数，提取出 `--prefix`, `--host`, `--enable-shared` 的值。
    2. 根据 `--host=linux,x64`，脚本会尝试找到适用于 Linux x64 的工具链和 SDK (如果需要)。
    3. 由于 `--enable-shared` 被指定，脚本会配置 Meson 构建共享库。
    4. 脚本会生成 Meson 的配置文件，指定安装路径为 `/opt/frida`，目标平台为 Linux x64，并启用共享库构建。
    5. 脚本调用 Meson 的 `setup` 命令，使用生成的配置文件初始化构建环境。
* **预期输出:**
    * 在当前目录下创建一个 `build` 目录 (如果不存在)。
    * 在 `build` 目录中生成 Meson 构建文件 (例如 `build.ninja`)。
    * 在 `build` 目录中生成 `Makefile` 和 `frida-env.dat` 文件。
    * 如果一切顺利，Meson 的配置过程会成功完成，不会有报错信息。

**5. 用户或编程常见的使用错误:**

* **错误的参数拼写或值:** 例如，输入 `--enables-symbols` (拼写错误) 或 `--host=androix,arm64` (平台名称错误)。这会导致 `argparse` 抛出错误并提示用户。
* **缺少必要的依赖:** 如果用户没有安装构建所需的工具（例如 Git, Python, Meson）或依赖项（例如 Android NDK），脚本在下载或配置过程中可能会失败，并提示缺少相关工具。
* **在已配置的目录中重新配置:** 如果用户在已经配置过的构建目录中再次运行 `meson_configure.py`，脚本会检测到已存在的 `build.ninja` 文件，并提示用户先清理构建目录。
* **权限问题:** 如果用户尝试将 Frida 安装到需要管理员权限的目录 (例如 `/opt`)，但没有使用 `sudo`，安装步骤可能会失败。
* **网络问题:** 下载预构建包或依赖项时，如果网络连接不稳定或无法访问相关资源，会导致下载失败。
* **Meson 版本不兼容:** 如果系统安装的 Meson 版本与 Frida 所需的版本不兼容，可能会导致配置或构建错误。

* **示例:** 用户在已经配置过的 `build` 目录下再次执行配置命令，会看到类似以下的错误信息：

```
Already configured. Wipe ./build to reconfigure.
```

**6. 用户操作如何一步步到达这里 (作为调试线索):**

1. **下载 Frida 源代码:** 用户首先需要从 GitHub 或其他来源下载 Frida 的源代码。
2. **进入 Frida 源代码目录:** 使用终端或命令提示符导航到 Frida 的根目录。
3. **运行配置脚本:** 用户执行 `python3 releng/meson_configure.py <options>` 命令，其中 `<options>` 是用户希望自定义的构建选项。
4. **脚本执行:** `meson_configure.py` 脚本被 Python 解释器执行，开始解析参数、下载依赖、生成构建文件等操作。
5. **可能的错误点:**
    * **步骤 3 命令输入错误:**  这是最常见的用户错误，例如拼写错误的选项、不支持的平台名称等。
    * **步骤 4 依赖下载失败:** 如果脚本需要下载工具链或 SDK，网络问题或仓库不可用可能导致下载失败。
    * **步骤 4 Meson 执行失败:**  如果 Meson 本身存在问题或配置错误，`meson setup` 命令可能会失败。

**作为调试线索:**

当构建 Frida 遇到问题时，可以按照以下步骤进行调试：

1. **检查 `meson_configure.py` 的输出:**  仔细查看脚本执行过程中的输出信息，特别是错误或警告信息。这些信息通常会提示问题的根源，例如缺少依赖、参数错误等。
2. **检查 `frida-env.dat` 文件:**  这个文件包含了配置信息，可以查看是否与预期一致。
3. **查看 Meson 的日志:** Meson 通常会生成详细的日志文件，可以帮助定位配置或构建过程中的问题。
4. **逐步执行 `meson_configure.py` (使用 `pdb` 等调试器):**  如果问题比较复杂，可以使用 Python 调试器逐步执行脚本，查看变量的值和执行流程，帮助理解脚本的行为。
5. **查阅 Frida 的文档和社区:**  Frida 的官方文档和社区论坛可能包含解决类似问题的方案或建议。

总而言之，`meson_configure.py` 是 Frida 构建过程中的一个核心组件，它负责收集用户配置、处理依赖关系，并为后续的构建步骤准备环境。理解其功能和工作原理对于成功构建 Frida 以及排查构建问题至关重要。

Prompt: 
```
这是目录为frida/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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