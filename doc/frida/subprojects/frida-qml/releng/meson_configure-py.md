Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `meson_configure.py` within the Frida project. This means figuring out what it does, how it does it, and its relevance to reverse engineering and low-level aspects.

**2. Initial Scan and Keywords:**

A quick skim reveals keywords like "configure", "meson", "build", "host", "prefix", "toolchain", "sdk", "symbols", "shared", "static", "cross-compile", "prebuilds". These immediately suggest the script is involved in the build process of Frida, likely using the Meson build system. The presence of "toolchain" and "sdk" hints at managing dependencies and build environments.

**3. Core Functionality - The `configure` Function:**

The `configure` function is the heart of the script. It takes several parameters, hinting at its responsibilities:

* `sourcedir`, `builddir`:  Standard build system inputs.
* `prefix`: Installation location.
* `build_machine`, `host_machine`:  Indicates cross-compilation support.
* `debug_symbols`, `default_library`: Build options.
* `allowed_prebuilds`:  A key optimization/dependency management mechanism.
* `meson`:  Choice of Meson implementation.
* `extra_meson_options`:  Flexibility for advanced users.

**4. Deeper Dive into Key Areas:**

* **Meson Integration:** The script extensively interacts with Meson. It calls `meson setup`, passes options, and parses `meson.options`. Understanding Meson's role as a meta-build system is crucial.

* **Cross-Compilation:** The `--build` and `--host` arguments, along with the `build_machine` and `host_machine` parameters, clearly indicate support for building Frida for different target architectures.

* **Prebuilt Dependencies:** The `--without-prebuilds` option and the logic around "toolchain" and "sdk" bundles point to a system for using pre-compiled dependencies to speed up the build process. This is a common practice in large projects.

* **Toolchain and SDK Management:** The `deps` module (imported as `from . import deps`) is central to this. The script attempts to download or locate prebuilt toolchains and SDKs based on the target architecture. If not found, it provides guidance on building them.

* **Machine Configuration:** The `MachineSpec` class and the generation of `build_config` and `host_config` suggest creating Meson "native files" and "cross files" to configure the build for the target platforms.

* **Error Handling:**  The `try...except` block in `main` and the custom exceptions `ToolchainNotFoundError` and `SDKNotFoundError` show attention to handling dependency-related issues.

**5. Connecting to Reverse Engineering:**

This is where the "why does this matter for reverse engineering?" question comes in.

* **Building Frida:**  To *use* Frida for reverse engineering, you need to *build* it. This script is a fundamental part of that process. Understanding its options allows you to tailor the build for your target environment (e.g., building for Android, a specific architecture).
* **Debugging Symbols:** The `--enable-symbols` option is directly relevant. Debug symbols are crucial for effective debugging and reverse engineering.
* **Shared vs. Static Libraries:** The `--enable-shared` option controls how Frida's components are linked. This can impact how you interact with Frida from your own tools or scripts.
* **Cross-Compilation for Targets:**  If you're reverse engineering on an Android device, you need to build Frida for Android. This script handles that.

**6. Connecting to Low-Level Aspects:**

* **Operating System and Architecture:** The script deals directly with OS and architecture detection (`platform.system()`, `MachineSpec`).
* **Toolchains and Compilers:** The concept of toolchains (compilers, linkers, etc.) is central to building software for different platforms.
* **SDKs:** SDKs provide necessary libraries and headers for targeting specific operating systems and platforms (like the Android SDK).
* **Environment Variables:** The script uses environment variables (like `VSCMD_ARG_TGT_ARCH`) to adapt to different build environments.

**7. Logical Reasoning and Examples:**

* **Assumptions:**  The script assumes a working Python environment, access to the internet (for downloading prebuilds), and a basic understanding of build systems by the user.
* **Input/Output:**  The input is command-line arguments and the state of the source directory. The output is a configured build directory ready for compilation.
* **User Errors:**  Common errors include incorrect paths, missing dependencies (if not using prebuilds), and incorrect cross-compilation settings.

**8. Tracing User Actions (Debugging Clues):**

To reach this script, a user would typically:

1. **Download the Frida source code.**
2. **Navigate to the Frida source directory.**
3. **Execute a command to configure the build, likely something like `./re.frida-qml/releng/meson_configure.py . build`**. The `.` represents the source directory, and `build` is the desired build directory. The exact command might vary depending on the user's specific needs and environment. The script is designed to be run directly, hence `sys.argv.pop(1)` to get the source directory.

**9. Iterative Refinement:**

After the initial analysis, I'd go back and reread the code more carefully, paying attention to details like the `parse_*` functions, the generation of Makefile-like files, and the specific Meson options being set. This helps fill in any gaps and confirm the initial understanding.

By following this structured approach, combining keyword scanning, function analysis, and connecting the code to broader concepts like reverse engineering and low-level system aspects, it becomes possible to generate a comprehensive and accurate explanation of the script's functionality.
这个Python脚本 `meson_configure.py` 的主要功能是**为 Frida 动态插桩工具配置构建环境**，它使用了 Meson 构建系统。

以下是它的详细功能列表，以及与逆向、二进制底层、Linux/Android 内核及框架的关联，并包含逻辑推理、用户错误和调试线索的说明：

**主要功能：**

1. **解析命令行参数：**  脚本使用 `argparse` 模块来处理用户在命令行中提供的各种选项，例如：
   - `--prefix`:  指定 Frida 的安装路径。
   - `--build`:  指定构建机器的架构和操作系统。
   - `--host`:  指定目标运行机器的架构和操作系统（用于交叉编译）。
   - `--enable-symbols`:  启用构建包含调试符号的二进制文件。
   - `--enable-shared`:  启用构建共享库。
   - `--with-meson`:  选择使用的 Meson 实现（内部或系统）。
   - `--without-prebuilds`:  禁用使用预构建的依赖包。
   - 以及项目特定的选项（从 `meson.options` 文件中读取）。

2. **检测构建环境：**
   - 确定源代码目录 (`sourcedir`) 和构建目录 (`builddir`)。
   - 检测默认的安装前缀 (`prefix`)。
   - 检测项目是否依赖 Vala 编译器。

3. **处理交叉编译：**
   - 根据 `--build` 和 `--host` 参数，解析构建机器和目标机器的规范 (`MachineSpec`)。
   - 自动补全缺失的机器规范信息。
   - 根据目标平台调整构建机器规范。

4. **管理依赖项：**
   - 使用 `deps` 模块 (从 `./deps.py` 导入) 来管理 Frida 的依赖项。
   - 支持使用预构建的依赖包（例如，toolchain 和 SDK）以加速构建过程。
   - 可以禁用特定类型的预构建包。
   - 如果没有预构建的 toolchain，并且项目依赖 Vala，则会尝试构建 Vala 编译器。

5. **生成 Meson 配置文件：**
   - 创建 Meson 的 native 文件和 cross 文件，用于配置构建过程。这些文件包含了目标平台的信息，例如编译器路径、链接器选项等。
   - 设置 Meson 的构建选项，例如安装前缀、默认库类型（共享或静态）、是否包含调试符号、是否剥离符号等。

6. **调用 Meson 进行配置：**
   - 使用 `meson setup` 命令来执行实际的配置过程，将之前收集的选项传递给 Meson。

7. **生成 Makefile：**
   - 创建一个顶层的 `Makefile` (或者在 Windows 上是 `make.bat`)，方便用户使用 `make` 命令进行构建。这个 Makefile 实际上是调用 Meson 进行构建。

8. **保存构建环境信息：**
   - 将构建过程中的重要信息（例如 Meson 的设置、构建和目标机器的配置、允许的预构建类型、依赖项目录等）序列化到 `frida-env.dat` 文件中，以便后续的构建步骤使用。

**与逆向方法的关系：**

- **构建 Frida Server:** 这个脚本的最终目标是构建 Frida Server，这是 Frida 框架的核心组件，运行在目标设备上（例如 Android 设备），用于接收和执行来自主机的指令，实现动态插桩。逆向工程师需要 Frida Server 才能在目标设备上进行代码分析、hook 函数、查看内存等操作。
- **调试符号 ( `--enable-symbols` )：**  启用调试符号对于逆向工程至关重要。有了调试符号，逆向工程师可以使用调试器 (例如 GDB) 更容易地理解代码的执行流程、变量的值等。这个脚本允许用户选择是否包含调试符号。
- **交叉编译：** 逆向工程师经常需要在主机上构建 Frida Server 以部署到目标设备上，而目标设备的架构可能与主机不同。例如，在 x86-64 的 Linux 主机上构建 Frida Server 以运行在 ARM64 的 Android 设备上。`--build` 和 `--host` 参数以及相关的逻辑就是为了支持这种交叉编译场景。

**举例说明：**

假设逆向工程师需要在自己的 Linux x86-64 机器上构建 Frida Server 以运行在 Android ARM64 设备上。他们可能会执行如下命令：

```bash
python3 releng/meson_configure.py . build --host=aarch64-linux-android --enable-symbols
```

这个命令会告诉 `meson_configure.py`：
- 源代码在当前目录 (`.`)。
- 目标运行平台是 `aarch64-linux-android`。
- 构建包含调试符号。

`meson_configure.py` 会解析这些参数，下载或使用合适的 Android ARM64 toolchain 和 SDK，生成 Meson 的交叉编译配置文件，并调用 Meson 进行配置。最终，用户可以使用生成的 `Makefile` 来构建 Frida Server。

**涉及到二进制底层，Linux, Android 内核及框架的知识：**

- **Toolchain (工具链)：**  脚本需要知道如何找到或构建用于目标平台的编译器、链接器等工具。例如，当目标是 Android ARM64 时，需要使用 Android NDK 中的 Clang 编译器和相关工具。
- **SDK (软件开发工具包)：**  为了编译针对特定平台的代码，需要目标平台的 SDK，例如 Android SDK。SDK 包含了必要的头文件和库文件。
- **交叉编译原理：**  理解交叉编译的概念至关重要。脚本需要处理不同架构的指令集、ABI (应用程序二进制接口) 等差异。
- **Linux 系统编程：**  生成的 Frida Server 最终会在 Linux 或 Android (基于 Linux 内核) 系统上运行，因此构建过程需要考虑 Linux 的一些特性，例如共享库的加载、进程管理等。
- **Android 系统框架：**  当构建 Frida 用于 Android 时，可能需要与 Android 的运行时环境 (例如 ART) 和系统服务进行交互。脚本需要配置构建环境以支持这些交互。

**举例说明：**

- 当指定 `--host=aarch64-linux-android` 时，脚本会尝试找到一个适用于 Android ARM64 的 toolchain。这涉及到查找包含 `aarch64-linux-android-gcc` 或 `clang` 等编译器的目录。
- 如果启用了共享库 (`--enable-shared`)，Meson 会配置链接器生成动态链接的库文件 (`.so` 文件在 Linux/Android 上)。

**逻辑推理和假设输入与输出：**

**假设输入：**

```bash
python3 releng/meson_configure.py . build --prefix=/opt/frida --enable-shared
```

**逻辑推理：**

1. 用户指定了安装前缀为 `/opt/frida`。
2. 用户启用了共享库构建。
3. 脚本会检测本地的构建环境 (操作系统、架构)。
4. 脚本会查找或下载必要的依赖项。
5. 脚本会生成 Meson 的配置文件，其中会包含：
   - `prefix = '/opt/frida'`
   - `default_library = 'shared'`
   - 以及根据本地构建环境确定的其他选项。

**预期输出：**

- 在当前目录下创建一个 `build` 目录（如果不存在）。
- 在 `build` 目录中生成 Meson 的构建文件 (例如 `build.ninja`) 和配置文件。
- 在 `build` 目录中生成一个 `Makefile`。
- 在 `build` 目录中创建一个 `frida-env.dat` 文件，包含构建环境信息。

**假设输入 (交叉编译)：**

```bash
python3 releng/meson_configure.py . build --host=arm-linux-gnueabihf --without-prebuilds=toolchain
```

**逻辑推理：**

1. 用户指定了目标平台为 `arm-linux-gnueabihf`。
2. 用户禁用了预构建的 toolchain，意味着需要使用系统提供的 toolchain。
3. 脚本会尝试找到系统上可用的适用于 `arm-linux-gnueabihf` 的编译器。
4. 脚本会生成 Meson 的交叉编译配置文件，其中会包含指定目标平台的编译器和链接器信息。

**预期输出：**

- 类似于上面的输出，但生成的 Meson 配置文件会针对 `arm-linux-gnueabihf` 平台。
- 如果系统上找不到合适的 toolchain，Meson 配置可能会失败并报错。

**用户或编程常见的使用错误：**

1. **错误的路径：**  如果用户提供的 `--prefix` 路径不存在或没有写入权限，后续的构建或安装过程可能会失败。
2. **缺少依赖项：**  如果用户禁用了预构建 (`--without-prebuilds`)，但系统上缺少必要的编译工具或库，Meson 配置可能会失败。例如，缺少 `pkg-config` 或特定的开发库。
3. **不兼容的构建和目标平台：**  如果用户指定的 `--build` 和 `--host` 参数不兼容（例如，在 32 位主机上构建 64 位目标），可能会导致配置或编译错误。
4. **错误的预构建类型：**  `--without-prebuilds` 参数的值必须是支持的预构建类型，否则 `parse_bundle_type_set` 函数会抛出 `argparse.ArgumentTypeError`。
5. **重复配置：**  如果构建目录已经配置过，脚本会提示用户清理构建目录以重新配置。

**举例说明：**

- 用户执行 `python3 releng/meson_configure.py . build --prefix=/readonly`，如果 `/readonly` 目录是只读的，脚本本身可能能成功执行，但后续的 `meson install` 步骤会失败。
- 用户执行 `python3 releng/meson_configure.py . build --without-prebuilds=invalid_type`，会因为 `invalid_type` 不是有效的预构建类型而报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户会按照以下步骤操作来调用 `meson_configure.py`：

1. **下载 Frida 的源代码：**  用户从 GitHub 或其他源下载 Frida 的源代码仓库。
2. **进入 Frida 源代码目录：**  使用 `cd` 命令进入下载的 Frida 源代码根目录。
3. **执行配置脚本：**  用户会在终端中输入类似以下的命令来启动配置过程：

   ```bash
   python3 frida/subprojects/frida-qml/releng/meson_configure.py <sourcedir> <builddir> [options]
   ```

   - `<sourcedir>` 通常是 `.` (表示当前目录，即 Frida 源代码根目录)。
   - `<builddir>` 是用户希望创建的构建目录的名称，例如 `build`。
   - `[options]` 是用户根据需要提供的各种命令行选项，如 `--prefix`, `--host`, `--enable-symbols` 等。

**作为调试线索：**

- **检查命令行参数：**  如果配置过程中出现问题，首先要检查用户提供的命令行参数是否正确。例如，目标平台是否拼写错误，预构建类型是否有效。
- **查看构建目录：**  检查生成的 `build` 目录中的文件，例如 `meson-logs/meson-log.txt` 可以提供 Meson 配置的详细日志信息。`frida-env.dat` 文件包含了配置过程中的重要参数。
- **检查依赖项：**  如果启用了预构建，可以检查 `deps` 目录中是否下载了所需的依赖包。如果没有启用预构建，需要确认系统上是否安装了必要的编译工具和库。
- **查看错误信息：**  脚本在出错时会打印错误信息到终端，这些信息通常能提供问题的线索。例如，如果找不到 toolchain 或 SDK，会抛出 `ToolchainNotFoundError` 或 `SDKNotFoundError` 异常，并给出相应的提示。
- **回溯用户操作：**  了解用户执行的具体命令和操作步骤，可以帮助定位问题是出在配置阶段还是后续的构建阶段。

总而言之，`meson_configure.py` 是 Frida 构建过程的关键入口点，它负责解析用户意图，管理依赖项，并生成 Meson 构建系统所需的配置文件，最终为 Frida 的编译和安装奠定基础。理解它的功能对于需要构建或定制 Frida 的用户和开发者至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```