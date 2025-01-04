Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Core Purpose:**

The first step is to read the docstring and the initial imports and class definitions to get a high-level understanding. The script's name, `build.py` within a `ciimage` directory, strongly suggests it's involved in building and testing container images for Continuous Integration (CI). The presence of `docker` and `TemporaryDirectory` reinforces this idea.

**2. Deconstructing the Classes:**

Next, I'd examine each class individually:

* **`ImageDef`:**  This class clearly handles the *definition* of an image. It reads a `image.json` file and extracts information like the base image, environment variables, and arguments. This tells me the script is *configurable* via these JSON files.

* **`BuilderBase`:** This appears to be an abstract base class or a class providing common functionality for builders and testers. It initializes paths, validates the input directory structure, and checks for the presence of `docker` and `git`. This emphasizes that the script interacts with the system environment.

* **`Builder`:** This class is responsible for the *building* process. Key methods are `gen_bashrc` (generating environment setup scripts), `gen_dockerfile` (creating the Dockerfile), and `do_build` (orchestrating the build process using `docker build`). The connection to Docker is clear here.

* **`ImageTester`:** This class is for *testing* the built images. It has methods to copy the `meson` source code into the image, generate a Dockerfile for testing, and run tests using `docker run`. The presence of `meson_root` suggests this CI is specifically for testing the Meson build system. The interactive `testTTY` option is interesting for debugging.

* **`ImageTTY`:** This class provides a way to run the built image interactively. It uses `docker run` to start a container and mount the `meson` source. This is another important debugging and development feature.

**3. Identifying Key Functionalities:**

Based on the class analysis, I can list the core functionalities:

* Reading image definitions from JSON.
* Generating environment setup scripts.
* Creating Dockerfiles.
* Building Docker images.
* Running tests within Docker containers.
* Providing interactive access to Docker containers.

**4. Connecting to Reverse Engineering:**

Now, the prompt asks about relevance to reverse engineering. The key connection is the use of Docker containers as controlled environments. Reverse engineering often involves analyzing software in isolated environments to prevent harm to the host system and to have predictable conditions. The script's ability to create and run these environments is directly relevant.

* **Example:** A reverse engineer could use this script to create a consistent environment with specific dependencies to analyze a Swift binary compiled within that environment.

**5. Identifying Binary/Kernel/Framework Connections:**

The script interacts with low-level aspects:

* **Docker:**  Docker itself relies on Linux kernel features like namespaces and cgroups for containerization. The script implicitly uses these features by interacting with the Docker command-line tool.
* **Shell Scripts:** The `install.sh` and the generated `env_vars.sh` are shell scripts that execute commands directly on the underlying operating system. These can perform low-level operations.
* **Environment Variables:**  Setting environment variables is a fundamental way to influence the behavior of programs at the binary level.
* **Path Manipulation:** Modifying the `PATH` variable affects how the operating system finds executable files.

**6. Analyzing Logic and Assumptions:**

* **Input:** The script takes the name of an image directory as input (`args.what`) and the desired action (`args.type`).
* **Assumptions:**
    * The existence of `image.json` and `install.sh` in the image directory.
    * The availability of `docker` and `git` on the system.
    * The `image.json` file having the correct structure.
* **Output:** The primary output is a Docker image. For testing, it also produces the output of the test commands. For `TTY`, it starts an interactive shell.

**7. Considering User Errors:**

Common errors include:

* **Incorrect `image.json`:**  Missing or malformed fields.
* **Missing `install.sh`:**  The installation script is crucial.
* **Docker/Git not installed:** The script explicitly checks for these.
* **Incorrect image name:**  The `what` argument must correspond to an existing directory.
* **Permissions issues:** Problems with file permissions within the container.

**8. Tracing User Operations (Debugging):**

To reach this script, a user would likely:

1. Navigate to the `frida/subprojects/frida-swift/releng/meson/ci/ciimage/` directory.
2. Run the `build.py` script from the command line, providing arguments for `what` (the image name) and `type` (build, test, etc.). For example: `python build.py ubuntu -t build`.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific commands within the shell scripts. It's more important to understand *why* those scripts are there – to set up the environment and install dependencies.
* I also needed to ensure I addressed *all* parts of the prompt, including reverse engineering, low-level details, logic, user errors, and debugging steps.
*  Recognizing the significance of environment variables in controlling program behavior, especially in the context of debugging and CI, was a key refinement.

By following these steps, focusing on the purpose, dissecting the code, and connecting it to the broader context of reverse engineering, containerization, and CI, I could arrive at a comprehensive understanding of the script's functionality and its relevance to the given topics.
这个Python脚本 `build.py` 的主要功能是**构建和测试用于 Frida Swift 项目的持续集成 (CI) Docker 镜像**。它允许创建包含必要依赖和环境配置的 Docker 镜像，以便在这些隔离的环境中运行自动化测试。

以下是它的详细功能分解：

**核心功能：构建和测试 Docker 镜像**

1. **定义镜像 (`ImageDef` 类):**
   - 读取名为 `image.json` 的配置文件，该文件定义了镜像的基础镜像 (base image)、环境变量 (env) 和可选的构建参数 (args)。
   - 验证 `image.json` 文件中的必要字段。

2. **构建镜像 (`Builder` 类):**
   - **准备构建环境:** 创建一个临时目录，用于存放构建所需的文件。
   - **复制必要文件:** 将 `image.json`、`install.sh` 和 `common.sh` 复制到临时目录。
   - **生成 `env_vars.sh`:**  创建一个 shell 脚本，用于设置镜像内的环境变量，包括从 `image.json` 读取的变量以及一些默认的路径设置（例如，将 `/ci` 添加到 `PATH`）。
   - **生成 `Dockerfile`:**  创建一个 Dockerfile，定义了镜像的构建步骤。它基于 `image.json` 中指定的 `base_image`，并将 `install.sh`、`common.sh` 和 `env_vars.sh` 添加到镜像中，并运行 `install.sh` 来安装必要的软件和配置。
   - **执行 Docker 构建:** 使用 `docker build` 命令构建镜像，并打上两个标签：`mesonbuild/<镜像目录名>:latest` 和 `mesonbuild/<镜像目录名>:<当前 Git commit 的短哈希值>`。

3. **测试镜像 (`ImageTester` 类):**
   - **准备测试环境:** 创建一个临时目录。
   - **复制 Meson 源代码:** 将 Meson 项目的源代码复制到临时目录中，以便在镜像中进行测试。
   - **生成测试 `Dockerfile`:** 创建一个 Dockerfile，基于已构建的镜像 (`mesonbuild/<镜像目录名>`)，并将复制的 Meson 源代码添加到镜像的 `/meson` 目录。
   - **执行 Docker 测试构建:** 使用 `docker build` 构建一个临时的测试镜像。
   - **运行测试:** 使用 `docker run` 命令运行测试镜像，并在容器内执行测试脚本 `./run_tests.py $CI_ARGS`。可以选择以交互式终端 (TTY) 模式运行，方便调试。
   - **清理:**  移除临时的测试镜像。

4. **交互式运行镜像 (`ImageTTY` 类):**
   - 允许用户以交互方式运行已构建的镜像。
   - 使用 `docker run` 命令启动一个容器，并将 Meson 源代码目录挂载到容器中。
   - 提供一个交互式的 shell 供用户在容器内进行操作和调试。

5. **主程序 (`main` 函数):**
   - 使用 `argparse` 处理命令行参数，允许用户指定要构建或测试的镜像以及执行的操作类型 (`build`, `test`, `testTTY`, `TTY`)。
   - 根据用户选择的操作类型，创建相应的 `Builder`、`ImageTester` 或 `ImageTTY` 对象，并执行相应的构建或测试方法。

**与逆向方法的关系：**

该脚本与逆向方法有密切关系，因为它构建的环境是为了**测试 Frida**，而 Frida 本身就是一个强大的**动态插桩工具**，常用于逆向工程。

**举例说明：**

假设你需要逆向分析一个在 Android 系统上运行的 Swift 应用程序。你可以使用这个脚本构建一个包含特定 Android SDK 版本、Swift 工具链和 Frida 环境的 Docker 镜像。然后在该镜像中运行 Frida，连接到目标应用程序进程，并进行动态分析，例如：

- **Hook 函数:**  使用 Frida 脚本拦截并修改应用程序的 Swift 函数调用，观察其行为。
- **查看内存:**  使用 Frida 读取和修改应用程序的内存，了解其数据结构和状态。
- **跟踪系统调用:**  使用 Frida 跟踪应用程序的系统调用，了解其与操作系统的交互。

这个脚本确保了 Frida 运行在一个可控且一致的环境中，避免了宿主机环境的干扰，这对于可靠的逆向分析至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

- **二进制底层:**
    - **Docker 镜像构建:**  理解 Dockerfile 的指令，例如 `FROM`、`ADD`、`RUN`，涉及到如何将二进制文件和依赖项打包到镜像中。
    - **Shell 脚本 (`install.sh`, `env_vars.sh`):** 这些脚本会执行底层的命令，例如安装软件包 (`apt-get install`)，设置环境变量，这些都会影响到程序运行时如何加载和执行二进制代码。
- **Linux:**
    - **Docker 的基础:** Docker 基于 Linux 内核的特性，如命名空间和 cgroups。这个脚本通过 `docker` 命令与这些底层机制交互。
    - **环境变量 (`env_vars.sh`):**  环境变量是 Linux 系统中重要的配置方式，会影响到进程的执行。
    - **文件系统操作:**  脚本中使用了 `shutil` 和 `pathlib` 模块进行文件和目录的复制、创建等操作，这些都是 Linux 文件系统的基础操作。
- **Android 内核及框架:**
    - **构建 Android 环境:** 如果基础镜像 (`base_image`) 是一个 Android 环境的镜像，那么这个脚本构建的镜像就包含了 Android 内核和框架的一部分，例如 Android SDK。
    - **Frida 与 Android:** Frida 可以运行在 Android 系统上，需要与 Android 的 Dalvik/ART 虚拟机和底层库进行交互。这个脚本构建的镜像可能包含预装的 Frida 服务端，或者包含安装 Frida 的步骤。

**举例说明：**

- **二进制底层:**  `install.sh` 可能会包含安装特定版本的 LLVM 或 Swift 工具链的命令，这直接涉及到编译和运行 Swift 代码的底层二进制工具。
- **Linux:**  设置 `PATH` 环境变量确保了 Frida 和其他工具的可执行文件可以在容器内被找到并执行。
- **Android 内核及框架:**  如果构建的是 Android 测试镜像，`install.sh` 可能会安装 Android SDK 的特定组件，例如 `platform-tools` 和 `build-tools`，这些是与 Android 系统底层交互的工具。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- `args.what = 'ubuntu'` (假设存在一个名为 `ubuntu` 的子目录，其中包含 `image.json` 和 `install.sh`)
- `args.type = 'build'`
- `frida/subprojects/frida-swift/releng/meson/ci/ciimage/ubuntu/image.json` 内容如下:
  ```json
  {
    "base_image": "ubuntu:latest",
    "env": {
      "DEBIAN_FRONTEND": "noninteractive"
    }
  }
  ```
- `frida/subprojects/frida-swift/releng/meson/ci/ciimage/ubuntu/install.sh` 内容如下:
  ```bash
  #!/bin/bash
  apt-get update
  apt-get install -y some-package
  ```

**输出:**

1. **创建一个临时目录:** 例如 `/tmp/build_ubuntu_xxxx`。
2. **复制文件:** `image.json`, `install.sh`, `common.sh` 被复制到临时目录。
3. **生成 `env_vars.sh`:**  临时目录中生成一个 `env_vars.sh` 文件，内容可能如下：
   ```bash
   export DEBIAN_FRONTEND="noninteractive"
   export CI_ARGS=""
   export PATH="/ci:$PATH"

   if [ -f "$HOME/.cargo/env" ]; then
       source "$HOME/.cargo/env"
   fi
   ```
4. **生成 `Dockerfile`:** 临时目录中生成一个 `Dockerfile` 文件，内容可能如下：
   ```dockerfile
   FROM ubuntu:latest

   ADD install.sh  /ci/install.sh
   ADD common.sh   /ci/common.sh
   ADD env_vars.sh /ci/env_vars.sh
   RUN /ci/install.sh
   ```
5. **执行 `docker build`:**  执行类似于 `docker build -t mesonbuild/ubuntu:latest -t mesonbuild/ubuntu:<git_commit_hash> --pull /tmp/build_ubuntu_xxxx` 的命令。
6. **构建成功:**  成功构建出名为 `mesonbuild/ubuntu:latest` 和 `mesonbuild/ubuntu:<git_commit_hash>` 的 Docker 镜像。

**涉及用户或编程常见的使用错误：**

1. **`image.json` 格式错误:**  如果 `image.json` 文件不是有效的 JSON，或者缺少必要的字段 (如 `base_image` 或 `env`)，脚本会抛出断言错误或 JSON 解析错误。
   ```
   # 错误示例 image.json
   {
     "base_image": "ubuntu:latest"
     # 缺少 "env" 字段
   }
   ```
   **用户操作步骤到达这里:** 用户创建或修改 `image.json` 文件，并运行 `python build.py ubuntu -t build`。

2. **缺少 `install.sh` 文件:** 如果指定的镜像目录下缺少 `install.sh` 文件，脚本会抛出 `RuntimeError`。
   ```
   RuntimeError: /path/to/frida/subprojects/frida-swift/releng/meson/ci/ciimage/some_image/install.sh does not exist
   ```
   **用户操作步骤到达这里:** 用户运行 `python build.py some_image -t build`，但 `some_image` 目录下没有 `install.sh` 文件。

3. **`install.sh` 执行失败:**  如果 `install.sh` 脚本中的命令执行失败 (例如，网络问题导致软件包下载失败)，Docker 构建过程会失败。
   ```
   # 错误示例 install.sh
   #!/bin/bash
   apt-get update  # 可能因为网络问题失败
   apt-get install -y non_existent_package
   ```
   **用户操作步骤到达这里:** 用户创建了一个包含错误的 `install.sh` 文件，并运行 `python build.py some_image -t build`。

4. **Docker 或 Git 未安装:** 如果系统上没有安装 Docker 或 Git，脚本在初始化时会抛出 `RuntimeError`。
   ```
   RuntimeError: Unable to find docker
   ```
   **用户操作步骤到达这里:** 用户在一个没有安装 Docker 的系统上运行脚本。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户遇到了一个构建失败的问题。以下是可能的步骤和调试线索：

1. **用户尝试构建镜像:** 用户在终端中执行命令 `python build.py my_swift_image -t build`。
2. **脚本开始执行:** `main()` 函数解析参数，确定要构建的镜像为 `my_swift_image`。
3. **创建构建器对象:**  根据参数创建 `Builder` 类的实例，传入 `ci_data` (指向 `my_swift_image` 目录) 和临时目录。
4. **验证数据目录:** `BuilderBase` 的 `validate_data_dir()` 方法检查 `my_swift_image` 目录下是否存在 `image.json` 和 `install.sh`。如果缺少，会抛出 `RuntimeError`，提示用户检查文件是否存在。
5. **读取 `image.json`:** `ImageDef` 类读取并解析 `image.json` 文件。如果文件格式错误，会抛出 JSON 解析错误或断言错误。
6. **生成构建文件:** `Builder` 类生成 `env_vars.sh` 和 `Dockerfile`。用户可以检查这些生成的文件，查看环境变量设置和 Docker 构建步骤是否正确。
7. **执行 Docker 构建:** `Builder` 类执行 `docker build` 命令。如果构建失败，Docker 会输出详细的错误信息，例如 `install.sh` 中的某个命令执行失败。用户需要查看 Docker 的构建日志，定位错误发生的步骤和原因。
8. **检查 Git 提交哈希:**  脚本会尝试获取当前 Git 仓库的提交哈希。如果不在 Git 仓库中运行，或者 Git 命令失败，会抛出 `RuntimeError`。

**调试线索:**

- **检查脚本输出:** 查看脚本在执行过程中打印的信息，例如临时目录的路径。
- **查看 Docker 构建日志:**  如果构建失败，Docker 的输出是关键的调试信息。
- **检查生成的文件:** 查看临时目录中生成的 `env_vars.sh` 和 `Dockerfile`，确认其内容是否符合预期。
- **手动执行 `install.sh`:**  可以在容器内部或者在本地环境中手动执行 `install.sh` 脚本，以便更方便地调试其中的错误。
- **使用 `-t testTTY` 运行测试:**  如果构建成功但测试失败，可以使用 `-t testTTY` 参数进入测试容器的交互式终端，手动运行测试命令并进行调试。

总而言之，这个脚本是 Frida Swift 项目 CI 流程的关键组成部分，它利用 Docker 实现了环境隔离和自动化构建测试，这对于保证软件质量和可重复性至关重要，并且与逆向工程领域有密切联系。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/ci/ciimage/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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