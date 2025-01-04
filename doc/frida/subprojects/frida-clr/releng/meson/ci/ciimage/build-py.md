Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Skim and Identify Purpose:**

The filename `build.py` and the overall structure immediately suggest this script is for building something. Keywords like `docker`, `image`, `Dockerfile`, `build`, and `test` solidify this. The path `frida/subprojects/frida-clr/releng/meson/ci/ciimage/build.py` tells us this is part of the Frida project, specifically related to its Common Language Runtime (CLR) support, and used within a Continuous Integration (CI) environment managed by Meson. The `ciimage` directory further hints at building container images for CI purposes.

**2. Core Functionality - The "What":**

The script uses the `argparse` module, so the first step is to look at the command-line arguments. We see `what` (the image name) and `type` (build, test, testTTY, TTY). This immediately tells us the script can perform different actions on different images.

**3. Deconstructing the Classes - The "How":**

Now, examine the classes:

*   **`ImageDef`:** This class clearly reads and parses the `image.json` file. It extracts the base image and environment variables. This configuration is fundamental to the image building process.

*   **`BuilderBase`:** This acts as a parent class, setting up common resources like temporary directories, checking for Docker and Git, and validating the input data directory. It's responsible for initial setup and dependency checks.

*   **`Builder`:** This class *builds* the Docker image. Key methods are:
    *   `gen_bashrc`: Creates a shell script to set environment variables *inside* the Docker image.
    *   `gen_dockerfile`: Creates the `Dockerfile` which defines the steps to build the image.
    *   `do_build`: Orchestrates the build process: copying files, generating scripts, and running the `docker build` command.

*   **`ImageTester`:** This class *tests* the built Docker image. Key methods are:
    *   `gen_dockerfile`: Creates a `Dockerfile` for the *testing* image, adding the Meson source code.
    *   `copy_meson`: Copies the Meson source tree into the temporary directory.
    *   `do_test`: Builds a temporary test image and then runs tests within it. It has a `tty` option for interactive debugging.

*   **`ImageTTY`:** This class provides an *interactive shell* within the built Docker image, allowing direct inspection and debugging.

**4. Connecting to Reverse Engineering:**

With the understanding of what the script does, now think about how it relates to reverse engineering:

*   **Frida's Nature:** Frida is a dynamic instrumentation toolkit. This script builds the environment where Frida will *run*. This is the crucial link. The built images are likely used to test Frida's capabilities on different platforms or with different configurations.

*   **Targeted Environment:** The script builds specific environments (likely Linux-based, given the shell commands and paths like `/etc/profile`). Reverse engineers often need to set up specific target environments to analyze software. This script automates that process for Frida's testing.

*   **Example:** If a reverse engineer wants to test Frida's CLR support on a specific version of .NET within a controlled environment, this script can create that environment.

**5. Identifying Binary/Kernel/Framework Elements:**

Look for actions that interact with low-level system components:

*   **Docker:** Containerization relies heavily on kernel features (namespaces, cgroups).
*   **`source /etc/profile` (in `gen_bashrc`):**  This directly interacts with the Linux system's initialization process.
*   **Environment Variables:** These influence the behavior of binaries and libraries at runtime.
*   **File Permissions (`chmod`):** A fundamental OS-level concept.

**6. Logical Inference and Assumptions:**

*   **Input/Output:**  The input is the image name (`what`) and the action (`type`). The output is either a built Docker image or the result of running tests/interactive shell within an image.

*   **Assumptions:** The script assumes Docker and Git are installed. It also assumes the existence of `image.json` and `install.sh` in the data directory.

**7. Common User Errors:**

Consider things that could go wrong from a user's perspective:

*   **Missing Dependencies:** Not having Docker or Git installed.
*   **Incorrect Arguments:**  Providing an invalid image name or action.
*   **Permissions Issues:**  Not having the necessary permissions to run Docker.
*   **Network Issues:** Docker might need to pull base images.
*   **Configuration Errors:**  Mistakes in `image.json` or `install.sh`.

**8. Tracing User Operations (Debugging Clues):**

Imagine a developer using Frida's CI:

1. They make changes to the Frida codebase.
2. The CI system (likely triggered by a Git commit) runs scripts like this one.
3. The script is invoked with specific arguments (e.g., `build.py ubuntu-20.04 -t build`).
4. The script creates temporary directories and Dockerfiles.
5. Docker builds the image based on these instructions.
6. If it's a test run, another Docker image is created, copying the updated Frida code, and the tests are executed.
7. Errors during this process would point to specific parts of the script or the Docker configuration.

**Self-Correction/Refinement during the process:**

*   Initially, I might have focused too much on the specific Frida CLR aspect. While important context, the script's core function is generic Docker image management for CI.
*   I double-checked the `textwrap.dedent` usage to understand how it formats the Dockerfile content.
*   I paid attention to the error handling (`raise RuntimeError`) to understand potential failure points.
*   I considered the flow of execution based on the command-line arguments to understand how different parts of the script are triggered.

By following this structured approach, breaking down the code into manageable parts, and connecting it to the broader context of Frida and reverse engineering, we can comprehensively analyze the script's functionality and its implications.
这个Python脚本 `build.py` 是 Frida 动态Instrumentation 工具项目的一部分，它用于构建和测试持续集成 (CI) 环境中使用的 Docker 镜像。这些镜像预装了运行 Frida 测试所需的各种依赖和配置。

**功能列举：**

1. **定义镜像配置 (`ImageDef` 类):**
    *   读取 `image.json` 文件，该文件定义了构建 Docker 镜像的基础镜像 (`base_image`) 和环境变量 (`env`)。
    *   可以包含额外的参数 (`args`)，这些参数会在测试时传递给 `run_tests.py` 脚本。

2. **构建 Docker 镜像 (`Builder` 类):**
    *   创建一个临时目录作为构建环境。
    *   将必要的脚本 (`install.sh`, `common.sh`) 和配置文件 (`image.json`) 复制到临时目录。
    *   生成 `env_vars.sh` 脚本，该脚本设置了镜像内的环境变量，包括从 `image.json` 中读取的变量，以及 `CI_ARGS` (从 `image.json` 的 `args` 字段生成)。它还会将 `/ci` 添加到 `PATH` 环境变量中。
    *   生成 `Dockerfile`，其中定义了构建 Docker 镜像的步骤：
        *   基于 `image.json` 中指定的 `base_image`。
        *   将 `install.sh`, `common.sh`, 和 `env_vars.sh` 添加到镜像的 `/ci` 目录。
        *   执行 `/ci/install.sh` 脚本来安装所需的软件包和进行配置。
    *   使用 `docker build` 命令构建 Docker 镜像，并打上 `latest` 和包含 Git commit 哈希的标签。

3. **测试 Docker 镜像 (`ImageTester` 类):**
    *   创建一个用于测试的临时目录。
    *   将 Meson 源代码复制到临时目录中，排除一些不必要的文件和目录（如 `.git`, `*_cache`, `__pycache__` 等）。
    *   生成用于测试的 `Dockerfile`，它基于已经构建好的镜像 (`image_namespace/{self.data_dir.name}`)，并将复制的 Meson 源代码添加到镜像的 `/meson` 目录。
    *   构建一个临时的测试 Docker 镜像 (`meson_test_image`)。
    *   运行测试：
        *   可以以交互式 TTY 模式运行，允许用户进入容器并手动执行命令进行调试。在这种模式下，会加载 `/ci/env_vars.sh` 设置环境变量，并执行 `ci/ciimage/user.sh` (如果存在) 进行用户自定义配置。
        *   也可以以非交互式模式运行，直接执行 `source /ci/env_vars.sh; cd meson; ./run_tests.py $CI_ARGS` 命令来运行测试。
    *   清理临时测试 Docker 镜像。

4. **运行交互式 Docker 容器 (`ImageTTY` 类):**
    *   基于已构建的镜像创建一个名为 `meson_test_container` 的交互式 Docker 容器。
    *   将 Meson 源代码目录挂载到容器的 `/meson` 目录。
    *   启动一个 bash shell，并加载环境变量和用户自定义配置，类似于 `ImageTester` 的 TTY 模式。

5. **主程序入口 (`main` 函数):**
    *   使用 `argparse` 处理命令行参数，包括要构建/测试的镜像名称 (`what`) 和执行的操作类型 (`type`: build, test, testTTY, TTY)。
    *   根据指定的镜像名称和操作类型，创建相应的 `Builder`, `ImageTester`, 或 `ImageTTY` 对象。
    *   调用相应对象的方法来执行构建或测试操作。

**与逆向方法的关系：**

这个脚本本身并不是直接进行逆向操作的工具，但它创建了用于测试 Frida 的环境。Frida 是一个动态 Instrumentation 工具，广泛应用于逆向工程中，用于：

*   **运行时分析：** 在目标程序运行时注入代码，监控其行为，例如函数调用、内存访问、参数返回值等。
*   **动态修改：**  在运行时修改程序的行为，例如 hook 函数、修改变量值、绕过安全检查等。
*   **漏洞挖掘：** 通过动态分析发现程序中的潜在漏洞。

**举例说明：**

假设要测试 Frida 在特定 Linux 发行版上的 CLR 支持。`build.py` 可能会构建一个包含该发行版、预装了 .NET Core 或 Mono 环境的 Docker 镜像。逆向工程师可以使用这个镜像运行 Frida 脚本来：

*   **Hook .NET 函数：**  拦截并分析 .NET 程序中特定函数的调用，查看其参数和返回值。
*   **跟踪内存操作：** 监控 .NET 程序的内存分配和释放，查找潜在的内存泄漏或缓冲区溢出。
*   **动态修改 .NET 代码：** 在运行时修改 .NET 程序的方法实现，用于调试或绕过限制。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层：**  Frida 本身就涉及到二进制层面的操作，例如注入代码到目标进程、修改内存等。这个脚本构建的环境是 Frida 运行的基础。例如，构建镜像时需要安装必要的库和工具，这些库和工具最终会操作二进制代码。
*   **Linux：**
    *   **Docker：**  脚本的核心是使用 Docker 构建和管理容器，这依赖于 Linux 内核的容器化特性（如 namespaces, cgroups）。
    *   **环境变量：**  脚本大量使用和设置环境变量，这是 Linux 系统中影响程序行为的重要机制。
    *   **Shell 脚本：**  `install.sh` 和 `common.sh` 是 Shell 脚本，用于在 Linux 环境中执行各种安装和配置操作。例如，使用 `apt-get` 或 `yum` 安装软件包。
    *   **文件权限 (`chmod`):**  脚本中使用了 `chmod` 来修改 `env_vars.sh` 的执行权限，这是 Linux 文件系统权限管理的一部分。
    *   **进程管理：**  Docker 的运行涉及到 Linux 的进程管理。
*   **Android 内核及框架：** 虽然脚本本身没有直接操作 Android 内核，但 Frida 可以用于 Android 平台的逆向工程。这个脚本构建的镜像可能被用来测试 Frida 在 Android 环境下的功能，例如连接到 Android 设备或模拟器，hook Android 系统服务或应用。这会涉及到对 Android 的 Binder 机制、ART 虚拟机等知识的理解。

**逻辑推理和假设输入与输出：**

**假设输入：**

*   `args.what` = `ubuntu-20.04` (表示要构建/测试 Ubuntu 20.04 的镜像)
*   `args.type` = `build`

**逻辑推理：**

1. `main` 函数会创建一个 `Builder` 对象，并传入 `ci_data` (指向 `frida/subprojects/frida-clr/releng/meson/ci/ciimage/ubuntu-20.04` 目录) 和一个临时目录。
2. `Builder` 类的 `__init__` 方法会读取 `ubuntu-20.04/image.json` 文件，获取基础镜像和环境变量。
3. `Builder.do_build()` 方法会被调用。
4. `do_build` 方法会将 `ubuntu-20.04` 目录下的 `install.sh` 等文件复制到临时目录。
5. `gen_bashrc()` 方法会根据 `image.json` 中的 `env` 生成 `env_vars.sh` 文件。
6. `gen_dockerfile()` 方法会根据 `image.json` 中的 `base_image` 生成 `Dockerfile`，其中会添加复制脚本和执行 `install.sh` 的指令。
7. `do_build` 方法会执行 `docker build` 命令，使用生成的 `Dockerfile` 构建一个名为 `mesonbuild/ubuntu-20.04:latest` 和 `mesonbuild/ubuntu-20.04:<git-commit-hash>` 的 Docker 镜像。

**预期输出：**

*   成功构建两个 Docker 镜像，可以通过 `docker images` 命令查看到。
*   如果在构建过程中出现错误（例如，`install.sh` 执行失败，基础镜像不存在等），会抛出 `RuntimeError`。

**涉及用户或编程常见的使用错误：**

1. **缺少依赖：** 用户在运行脚本前没有安装 Docker 或 Git，会导致脚本抛出 `RuntimeError`。
2. **配置错误：** `image.json` 文件格式错误（例如，缺少必要的字段，类型不匹配）会导致 `ImageDef` 类在初始化时抛出 `AssertionError`。
3. **文件缺失：** 如果 `image.json` 或 `install.sh` 文件不存在于指定的镜像目录下，`BuilderBase.validate_data_dir()` 方法会抛出 `RuntimeError`。
4. **权限问题：** 用户没有执行 Docker 命令的权限，会导致 `subprocess.run(cmd)` 调用失败，并抛出 `RuntimeError`。
5. **网络问题：** Docker 在拉取基础镜像或执行 `install.sh` 中的网络操作时可能遇到网络问题，导致构建失败。
6. **错误的镜像名称或类型：** 在命令行中提供了不存在的镜像名称或错误的操作类型，会导致 `main` 函数中无法找到对应的目录或执行相应的逻辑。

**用户操作是如何一步步的到达这里，作为调试线索：**

通常，开发者或 CI 系统会执行这个脚本来构建和测试 Frida。以下是可能的操作步骤：

1. **修改代码：**  Frida 的开发者修改了 Frida CLR 相关的代码。
2. **触发 CI：**  将代码推送到 Git 仓库，触发了预先配置的 CI 流水线。
3. **执行构建脚本：** CI 系统在某个构建步骤中执行了 `build.py` 脚本。
4. **指定镜像和类型：** CI 系统会根据需要构建或测试的镜像类型传递相应的参数，例如：
    *   构建 Ubuntu 20.04 镜像：`./build.py ubuntu-20.04 -t build`
    *   测试 Ubuntu 20.04 镜像：`./build.py ubuntu-20.04 -t test`
    *   以交互式 TTY 模式测试：`./build.py ubuntu-20.04 -t testTTY`
    *   运行交互式容器：`./build.py ubuntu-20.04 -t TTY`

**作为调试线索：**

*   **查看日志：**  CI 系统的日志会记录 `build.py` 的执行过程，包括打印的临时目录路径、执行的 Docker 命令及其输出。
*   **检查临时目录：**  可以查看脚本创建的临时目录的内容，例如生成的 `Dockerfile`、`env_vars.sh` 以及复制的文件，以了解构建过程的中间状态。
*   **手动执行 Docker 命令：**  可以将脚本中生成的 Docker 命令复制出来，在本地手动执行，以便更细致地观察构建过程中的错误。
*   **检查 `image.json` 和 `install.sh`：**  确认这些配置文件的内容是否正确，是否存在语法错误或逻辑错误。
*   **查看 Docker 镜像：**  使用 `docker images` 命令查看是否成功构建了镜像，以及镜像的大小和创建时间。
*   **进入 Docker 容器调试：**  对于测试失败的情况，可以使用 `docker run` 命令手动启动构建出的镜像，进入容器内部进行调试，例如查看日志文件、执行测试命令等。

总而言之，这个 `build.py` 脚本是 Frida 项目 CI 流程的关键部分，它自动化了构建和测试 Frida 运行环境的过程，为保证 Frida 的质量和兼容性提供了基础。理解其功能有助于理解 Frida 的构建流程，并在出现问题时进行调试。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/ci/ciimage/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#!/usr/bin/env python3

import json
import argparse
import stat
import textwrap
import shutil
import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path
import typing as T

image_namespace = 'mesonbuild'

image_def_file = 'image.json'
install_script = 'install.sh'

class ImageDef:
    def __init__(self, image_dir: Path) -> None:
        path = image_dir / image_def_file
        data = json.loads(path.read_text(encoding='utf-8'))

        assert isinstance(data, dict)
        assert all([x in data for x in ['base_image', 'env']])
        assert isinstance(data['base_image'], str)
        assert isinstance(data['env'],  dict)

        self.base_image: str = data['base_image']
        self.args: T.List[str] = data.get('args', [])
        self.env: T.Dict[str, str] = data['env']

class BuilderBase():
    def __init__(self, data_dir: Path, temp_dir: Path) -> None:
        self.data_dir = data_dir
        self.temp_dir = temp_dir

        self.common_sh = self.data_dir.parent / 'common.sh'
        self.common_sh = self.common_sh.resolve(strict=True)
        self.validate_data_dir()

        self.image_def = ImageDef(self.data_dir)

        self.docker = shutil.which('docker')
        self.git = shutil.which('git')
        if self.docker is None:
            raise RuntimeError('Unable to find docker')
        if self.git is None:
            raise RuntimeError('Unable to find git')

    def validate_data_dir(self) -> None:
        files = [
            self.data_dir / image_def_file,
            self.data_dir / install_script,
        ]
        if not self.data_dir.exists():
            raise RuntimeError(f'{self.data_dir.as_posix()} does not exist')
        for i in files:
            if not i.exists():
                raise RuntimeError(f'{i.as_posix()} does not exist')
            if not i.is_file():
                raise RuntimeError(f'{i.as_posix()} is not a regular file')

class Builder(BuilderBase):
    def gen_bashrc(self) -> None:
        out_file = self.temp_dir / 'env_vars.sh'
        out_data = ''

        # run_tests.py parameters
        self.image_def.env['CI_ARGS'] = ' '.join(self.image_def.args)

        for key, val in self.image_def.env.items():
            out_data += f'export {key}="{val}"\n'

        # Also add /ci to PATH
        out_data += 'export PATH="/ci:$PATH"\n'

        out_data += '''
            if [ -f "$HOME/.cargo/env" ]; then
                source "$HOME/.cargo/env"
            fi
        '''

        if self.data_dir.name == 'gentoo':
            out_data += '''
                source /etc/profile
            '''

        out_file.write_text(out_data, encoding='utf-8')

        # make it executable
        mode = out_file.stat().st_mode
        out_file.chmod(mode | stat.S_IEXEC)

    def gen_dockerfile(self) -> None:
        out_file = self.temp_dir / 'Dockerfile'
        out_data = textwrap.dedent(f'''\
            FROM {self.image_def.base_image}

            ADD install.sh  /ci/install.sh
            ADD common.sh   /ci/common.sh
            ADD env_vars.sh /ci/env_vars.sh
            RUN /ci/install.sh
        ''')

        out_file.write_text(out_data, encoding='utf-8')

    def do_build(self) -> None:
        # copy files
        for i in self.data_dir.iterdir():
            shutil.copy(str(i), str(self.temp_dir))
        shutil.copy(str(self.common_sh), str(self.temp_dir))

        self.gen_bashrc()
        self.gen_dockerfile()

        cmd_git = [self.git, 'rev-parse', '--short', 'HEAD']
        res = subprocess.run(cmd_git, cwd=self.data_dir, stdout=subprocess.PIPE)
        if res.returncode != 0:
            raise RuntimeError('Failed to get the current commit hash')
        commit_hash = res.stdout.decode().strip()

        cmd = [
            self.docker, 'build',
            '-t', f'{image_namespace}/{self.data_dir.name}:latest',
            '-t', f'{image_namespace}/{self.data_dir.name}:{commit_hash}',
            '--pull',
            self.temp_dir.as_posix(),
        ]
        if subprocess.run(cmd).returncode != 0:
            raise RuntimeError('Failed to build the docker image')

class ImageTester(BuilderBase):
    def __init__(self, data_dir: Path, temp_dir: Path, ci_root: Path) -> None:
        super().__init__(data_dir, temp_dir)
        self.meson_root = ci_root.parent.parent.resolve()

    def gen_dockerfile(self) -> None:
        out_file = self.temp_dir / 'Dockerfile'
        out_data = textwrap.dedent(f'''\
            FROM {image_namespace}/{self.data_dir.name}

            ADD meson /meson
        ''')

        out_file.write_text(out_data, encoding='utf-8')

    def copy_meson(self) -> None:
        shutil.copytree(
            self.meson_root,
            self.temp_dir / 'meson',
            symlinks=True,
            ignore=shutil.ignore_patterns(
                '.git',
                '*_cache',
                '__pycache__',
                # 'work area',
                self.temp_dir.name,
            ),
        )

    def do_test(self, tty: bool = False) -> None:
        self.copy_meson()
        self.gen_dockerfile()

        try:
            build_cmd = [
                self.docker, 'build',
                '-t', 'meson_test_image',
                self.temp_dir.as_posix(),
            ]
            if subprocess.run(build_cmd).returncode != 0:
                raise RuntimeError('Failed to build the test docker image')

            test_cmd = []
            if tty:
                test_cmd = [
                    self.docker, 'run', '--rm', '-t', '-i', 'meson_test_image',
                    '/bin/bash', '-c', ''
                    + 'cd meson;'
                    + 'source /ci/env_vars.sh;'
                    + f'echo -e "\\n\\nInteractive test shell in the {image_namespace}/{self.data_dir.name} container with the current meson tree";'
                    + 'echo -e "The file ci/ciimage/user.sh will be sourced if it exists to enable user specific configurations";'
                    + 'echo -e "Run the following command to run all CI tests: ./run_tests.py $CI_ARGS\\n\\n";'
                    + '[ -f ci/ciimage/user.sh ] && exec /bin/bash --init-file ci/ciimage/user.sh;'
                    + 'exec /bin/bash;'
                ]
            else:
                test_cmd = [
                    self.docker, 'run', '--rm', '-t', 'meson_test_image',
                    '/bin/bash', '-xc', 'source /ci/env_vars.sh; cd meson; ./run_tests.py $CI_ARGS'
                ]

            if subprocess.run(test_cmd).returncode != 0 and not tty:
                raise RuntimeError('Running tests failed')
        finally:
            cleanup_cmd = [self.docker, 'rmi', '-f', 'meson_test_image']
            subprocess.run(cleanup_cmd).returncode

class ImageTTY(BuilderBase):
    def __init__(self, data_dir: Path, temp_dir: Path, ci_root: Path) -> None:
        super().__init__(data_dir, temp_dir)
        self.meson_root = ci_root.parent.parent.resolve()

    def do_run(self) -> None:
        try:
            tty_cmd = [
                self.docker, 'run',
                '--name', 'meson_test_container', '-t', '-i', '-v', f'{self.meson_root.as_posix()}:/meson',
                f'{image_namespace}/{self.data_dir.name}',
                '/bin/bash', '-c', ''
                    + 'cd meson;'
                    + 'source /ci/env_vars.sh;'
                    + f'echo -e "\\n\\nInteractive test shell in the {image_namespace}/{self.data_dir.name} container with the current meson tree";'
                    + 'echo -e "The file ci/ciimage/user.sh will be sourced if it exists to enable user specific configurations";'
                    + 'echo -e "Run the following command to run all CI tests: ./run_tests.py $CI_ARGS\\n\\n";'
                    + '[ -f ci/ciimage/user.sh ] && exec /bin/bash --init-file ci/ciimage/user.sh;'
                    + 'exec /bin/bash;'
            ]
            subprocess.run(tty_cmd).returncode != 0
        finally:
            cleanup_cmd = [self.docker, 'rm', '-f', 'meson_test_container']
            subprocess.run(cleanup_cmd).returncode


def main() -> None:
    parser = argparse.ArgumentParser(description='Meson CI image builder')
    parser.add_argument('what', type=str, help='Which image to build / test')
    parser.add_argument('-t', '--type', choices=['build', 'test', 'testTTY', 'TTY'], help='What to do', required=True)

    args = parser.parse_args()

    ci_root = Path(__file__).parent
    ci_data = ci_root / args.what

    with TemporaryDirectory(prefix=f'{args.type}_{args.what}_', dir=ci_root) as td:
        ci_build = Path(td)
        print(f'Build dir: {ci_build}')

        if args.type == 'build':
            builder = Builder(ci_data, ci_build)
            builder.do_build()
        elif args.type == 'test':
            tester = ImageTester(ci_data, ci_build, ci_root)
            tester.do_test()
        elif args.type == 'testTTY':
            tester = ImageTester(ci_data, ci_build, ci_root)
            tester.do_test(tty=True)
        elif args.type == 'TTY':
            tester = ImageTTY(ci_data, ci_build, ci_root)
            tester.do_run()

if __name__ == '__main__':
    main()

"""

```