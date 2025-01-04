Response:
Let's break down the thought process for analyzing the provided Python script.

**1. Initial Understanding - The Big Picture:**

The first step is to understand the overall purpose of the script. The name "build.py" and the directory "ciimage" strongly suggest that this script is involved in building or managing container images for Continuous Integration (CI). The import of libraries like `docker`, `shutil`, `subprocess`, and `TemporaryDirectory` reinforces this idea.

**2. Dissecting the Classes:**

Next, I'd analyze the classes present in the script: `ImageDef`, `BuilderBase`, `Builder`, `ImageTester`, and `ImageTTY`. For each class, I'd focus on:

* **Purpose:** What is the core responsibility of this class?  `ImageDef` seems to handle the configuration of the image, `BuilderBase` sets up common functionalities, `Builder` actually builds the image, `ImageTester` runs tests within the image, and `ImageTTY` provides an interactive shell.
* **Key Attributes:** What data does the class hold?  For example, `ImageDef` stores `base_image`, `args`, and `env`. `BuilderBase` holds paths and checks for the existence of `docker` and `git`.
* **Key Methods:** What actions can the class perform? `Builder` has methods like `gen_bashrc`, `gen_dockerfile`, and `do_build`. `ImageTester` has `do_test`.

**3. Tracing the Workflow:**

Now, I'd try to piece together how these classes interact. The `main` function is the entry point, so I'd start there. It parses command-line arguments (`what` and `type`). Based on the `type` argument, it instantiates different classes (`Builder`, `ImageTester`, `ImageTTY`). This indicates different modes of operation.

* **'build' mode:** Creates a `Builder` instance and calls `do_build`. This likely involves creating a Dockerfile and running the `docker build` command.
* **'test' and 'testTTY' modes:** Create an `ImageTester` and call `do_test`. This involves building a *test* Docker image based on the previously built image and running tests inside it. The `testTTY` variant provides an interactive shell.
* **'TTY' mode:** Creates an `ImageTTY` and calls `do_run`. This launches an interactive shell directly into the built image.

**4. Identifying Key Operations:**

As I trace the workflow, I'd note the important actions being performed:

* **Reading Configuration:** `ImageDef` reads `image.json`.
* **Generating Files:** `Builder` generates `env_vars.sh` and `Dockerfile`.
* **Docker Interaction:**  The script heavily relies on `docker build`, `docker run`, and `docker rmi`.
* **File System Operations:** Copying files and directories using `shutil`.
* **Process Execution:** Running commands using `subprocess`.
* **Environment Setup:** Setting environment variables in `env_vars.sh`.

**5. Connecting to the Request's Specific Points:**

Now, I'd go back to the user's request and specifically address each point:

* **Functionality:**  List the identified key operations as the script's functions.
* **Reversing Relevance:**  Consider how building and testing these images might be used in reverse engineering. The environment setup, the execution of test scripts, and the ability to run interactive shells are all relevant. Specifically, these images likely contain the necessary dependencies and tools to *run* Frida itself or tools built with Frida. Reverse engineers might use this to test their Frida scripts or analyze how Frida interacts with target applications in a controlled environment.
* **Binary/Kernel/Framework:** Look for direct interactions with low-level components. The `base_image` in `image.json` will likely be a Linux distribution. The `install.sh` script (not shown in the provided snippet but referenced) would likely install system-level dependencies. The environment variables set up could affect how binaries run. The mention of Gentoo in `gen_bashrc` and the potential use of `source /etc/profile` indicates awareness of Linux system initialization.
* **Logical Inference:** Examine the conditional logic. The script checks for the existence of files and directories. It uses the `type` argument to determine the execution path. The `gen_bashrc` function adds different configurations based on the `data_dir.name`. Think about the inputs and outputs of these conditional blocks.
* **User Errors:**  Consider common mistakes users might make. Forgetting to install Docker or Git is handled with error messages. Providing an invalid `what` argument would lead to a file not found error. Trying to run tests without building first would also fail.
* **User Path to Execution:**  Imagine a developer working on Frida. They might want to build a new CI image or test changes to the existing image configurations. This leads to the steps of navigating to the directory and running the script with appropriate arguments.

**6. Structuring the Response:**

Finally, I'd organize the findings into a clear and structured response, addressing each point of the user's request with examples and explanations. Using headings and bullet points improves readability. I'd emphasize the connections to reverse engineering and the underlying technical details.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the Docker commands.**  I'd then realize that understanding the *purpose* of these commands within the larger CI context is more important.
* **I might overlook the `ImageDef` class initially.** Recognizing its role in centralizing image configuration is key.
* **The absence of `install.sh` content is a limitation.** I'd acknowledge this and make educated guesses about its content based on its name and context.
* **Connecting to reverse engineering requires more thought.**  It's not immediately obvious. I'd need to think about how CI images would be used by Frida developers and how that relates to reverse engineering workflows (e.g., testing Frida scripts).

By following this detailed thought process, I can thoroughly analyze the script and provide a comprehensive answer that addresses all aspects of the user's request.
这个Python脚本 `build.py` 的主要功能是**构建和测试用于 Frida CI (Continuous Integration) 的 Docker 镜像**。它定义了不同的类和方法来自动化 Docker 镜像的创建和测试过程，确保 Frida 在各种预定义的 CI 环境中能够正常工作。

以下是更详细的功能分解：

**主要功能:**

1. **定义镜像配置 (`ImageDef` 类):**
   - 从 `image.json` 文件中读取镜像的配置信息，例如基础镜像 (`base_image`)、环境变量 (`env`) 和构建参数 (`args`)。
   - 提供了一种结构化的方式来定义不同 CI 环境的特性。

2. **构建 Docker 镜像 (`Builder` 类):**
   - 基于 `ImageDef` 中定义的配置，生成 Dockerfile。
   - 将必要的脚本 (`install.sh`, `common.sh`, `env_vars.sh`) 添加到镜像中。
   - 执行 Docker 构建命令，创建带有 `latest` 和基于 Git commit hash 标签的镜像。

3. **测试 Docker 镜像 (`ImageTester` 类):**
   - 基于已构建的镜像创建一个新的 Dockerfile，用于测试。
   - 将 Meson 源代码复制到测试镜像中。
   - 在 Docker 容器中运行测试命令 (`./run_tests.py $CI_ARGS`)。
   - 可以选择以交互式 TTY 模式运行测试，方便调试。

4. **以交互模式运行 Docker 镜像 (`ImageTTY` 类):**
   - 允许用户以交互式终端 (TTY) 的方式运行已构建的 Docker 镜像。
   - 将 Meson 源代码挂载到容器中，方便开发和调试。

5. **命令行接口 (`main` 函数):**
   - 提供了一个命令行界面，允许用户指定要构建或测试的镜像 (`what`) 和操作类型 (`type`)。
   - 使用 `argparse` 处理命令行参数。

**与逆向方法的关系及举例:**

该脚本与逆向方法有密切关系，因为它为 Frida 提供了持续集成环境，确保 Frida 的功能在各种平台上（例如不同的 Linux 发行版、Android 版本等）都能正常运行。

**举例说明:**

* **环境一致性:**  逆向工程师经常需要在与目标设备相似的环境中测试 Frida 脚本。该脚本可以构建包含特定 Android 或 Linux 版本的镜像，确保测试环境与目标环境一致。例如，一个逆向工程师可能需要分析运行在 Android 7.0 上的应用，该脚本可以构建一个基于 Android 7.0 的 CI 镜像，用于测试 Frida 脚本的兼容性。
* **自动化测试:**  逆向工程师开发 Frida 脚本后，可以使用该脚本构建的 CI 环境来自动化测试脚本的功能。例如，他们可以编写一个测试脚本，验证 Frida 是否能够成功 hook 某个函数并修改其行为，然后在 CI 环境中自动运行这些测试。
* **问题复现:** 如果在特定的环境下 Frida 出现问题，逆向工程师可以利用该脚本构建一个相同的环境，以便更容易地复现和调试问题。

**涉及二进制底层、Linux、Android内核及框架的知识及举例:**

该脚本在构建 CI 镜像的过程中，会涉及到以下方面的知识：

* **二进制底层:**
    * **编译工具链:** `install.sh` 脚本可能会安装编译 Frida 所需的工具链，例如 GCC、LLVM 等。这些工具链负责将源代码编译成二进制代码。
    * **动态链接库:** Frida 依赖于一些动态链接库。`install.sh` 可能会安装这些库，并且 CI 镜像会模拟 Frida 运行时所需的动态链接环境。
* **Linux:**
    * **Docker:**  脚本的核心是使用 Docker 来构建和管理容器。理解 Docker 的概念，例如镜像、容器、Dockerfile 等是必要的。
    * **Linux 命令:** 脚本中使用了大量的 Linux 命令，例如 `shutil.copy`, `subprocess.run`, `chmod`, `export` 等。
    * **Shell 脚本:** `install.sh` 和 `common.sh` 是 Shell 脚本，需要了解 Shell 脚本的语法和常用命令。
    * **文件系统:** 脚本涉及到文件和目录的操作，例如创建临时目录、复制文件等。
    * **环境变量:**  脚本设置和使用了环境变量，例如 `CI_ARGS` 和 `PATH`。
* **Android内核及框架:**
    * **Android SDK/NDK:** 如果构建 Android 相关的 CI 镜像，`install.sh` 可能会安装 Android SDK 或 NDK，这些是开发 Android 应用和 Frida Android 桥梁所必需的。
    * **Android 系统库:** Frida 在 Android 上运行时会与 Android 系统库进行交互。CI 镜像需要包含或模拟这些库。
    * **init 系统和启动脚本:**  `gen_bashrc` 中提到的 `source /etc/profile`  涉及到 Linux 的启动过程，对于理解 Frida 在 Linux 系统中的初始化很有帮助。

**举例说明:**

* **`install.sh` 可能安装 LLVM:**  Frida 的 Code Writer 功能依赖于 LLVM，`install.sh` 中可能包含安装 LLVM 库和工具的命令。
* **设置 `PATH` 环境变量:**  脚本将 `/ci` 添加到 `PATH` 环境变量中，这意味着在容器中可以直接执行放在 `/ci` 目录下的脚本，而无需指定完整路径。
* **Gentoo 特殊处理:**  针对 Gentoo 镜像，脚本会额外 `source /etc/profile`，这表明 Gentoo 的环境配置方式与其他 Linux 发行版可能有所不同。

**逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，例如根据命令行参数决定执行哪个类和方法。

**假设输入:**

```bash
./build.py ubuntu -t build
```

**输出:**

1. 创建一个临时目录，例如 `build_ubuntu_...`。
2. `Builder` 类被实例化，`data_dir` 指向 `frida/subprojects/frida-tools/releng/meson/ci/ciimage/ubuntu` 目录。
3. `gen_bashrc` 方法生成 `env_vars.sh` 文件，其中包含从 `ubuntu/image.json` 读取的环境变量和 `CI_ARGS`。
4. `gen_dockerfile` 方法生成 `Dockerfile`，其中指定了基础镜像和要添加的脚本。
5. `do_build` 方法将 `ubuntu` 目录下的文件和 `common.sh` 复制到临时目录。
6. 执行 `docker build` 命令，基于临时目录下的 Dockerfile 构建镜像，并打上 `mesonbuild/ubuntu:latest` 和 `mesonbuild/ubuntu:<git_commit_hash>` 标签。

**假设输入:**

```bash
./build.py android -t test
```

**输出:**

1. 创建一个临时目录，例如 `test_android_...`。
2. `ImageTester` 类被实例化，`data_dir` 指向 `frida/subprojects/frida-tools/releng/meson/ci/ciimage/android` 目录。
3. Meson 源代码被复制到临时目录下的 `meson` 目录。
4. `gen_dockerfile` 方法生成一个测试用的 `Dockerfile`，基于 `mesonbuild/android` 镜像，并添加了 Meson 源代码。
5. 执行 `docker build` 命令构建一个名为 `meson_test_image` 的测试镜像。
6. 执行 `docker run` 命令，在 `meson_test_image` 容器中运行 `source /ci/env_vars.sh; cd meson; ./run_tests.py $CI_ARGS` 命令。
7. 运行测试完成后，清理 `meson_test_image` 镜像。

**涉及用户或编程常见的使用错误及举例:**

* **未安装 Docker 或 Git:** 脚本开头会检查是否安装了 `docker` 和 `git`，如果未找到则会抛出 `RuntimeError`。
    ```
    # 错误示例：未安装 Docker
    Traceback (most recent call last):
      File "./build.py", line ..., in <module>
        main()
      File "./build.py", line ..., in main
        builder = Builder(ci_data, ci_build)
      File "./build.py", line ..., in __init__
        raise RuntimeError('Unable to find docker')
    RuntimeError: Unable to find docker
    ```
* **指定的镜像名称不存在:** 如果用户在命令行中指定的 `what` 参数对应的目录不存在，脚本会抛出 `RuntimeError`。
    ```
    # 错误示例：指定了不存在的镜像名称 "nonexistent_image"
    Traceback (most recent call last):
      File "./build.py", line ..., in <module>
        main()
      File "./build.py", line ..., in main
        ci_data = ci_root / args.what
      File "/usr/lib/python3.x/pathlib.py", line ..., in __rtruediv__
        return self._make_child_relpath(other)
      File "/usr/lib/python3.x/pathlib.py", line ..., in _make_child_relpath
        self._raise_not_found(self)
      File "/usr/lib/python3.x/pathlib.py", line ..., in _raise_not_found
        raise FileNotFoundError(errno.ENOENT, "%s" % self)
    FileNotFoundError: [Errno 2] frida/subprojects/frida-tools/releng/meson/ci/ciimage/nonexistent_image
    ```
* **`image.json` 或 `install.sh` 文件缺失:**  如果指定镜像的目录下缺少 `image.json` 或 `install.sh` 文件，`BuilderBase` 类的 `validate_data_dir` 方法会抛出 `RuntimeError`。
    ```
    # 错误示例：缺少 install.sh 文件
    Traceback (most recent call last):
      File "./build.py", line ..., in <module>
        main()
      File "./build.py", line ..., in main
        builder = Builder(ci_data, ci_build)
      File "./build.py", line ..., in __init__
        self.validate_data_dir()
      File "./build.py", line ..., in validate_data_dir
        raise RuntimeError(f'{i.as_posix()} does not exist')
    RuntimeError: frida/subprojects/frida-tools/releng/meson/ci/ciimage/ubuntu/install.sh does not exist
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发人员修改了 Frida 的代码或 CI 相关的配置文件。**
2. **开发人员希望创建一个新的 CI 镜像，或者测试现有的 CI 镜像配置。**
3. **开发人员导航到 `frida/subprojects/frida-tools/releng/meson/ci/ciimage/` 目录。**
4. **开发人员查阅文档或代码，了解如何构建和测试 CI 镜像。**
5. **开发人员执行 `build.py` 脚本，并提供相应的命令行参数。** 例如：
   - `python3 build.py ubuntu -t build`  (构建 Ubuntu 镜像)
   - `python3 build.py android -t test` (测试 Android 镜像)
   - `python3 build.py ubuntu -t testTTY` (以交互模式测试 Ubuntu 镜像)
   - `python3 build.py ubuntu -t TTY` (以交互模式运行 Ubuntu 镜像)

如果脚本执行过程中出现错误，例如上述的几种常见错误，开发人员可以根据错误信息和堆栈跟踪来定位问题：

* **`RuntimeError: Unable to find docker` 或 `RuntimeError: Unable to find git`:** 提示用户需要安装 Docker 或 Git。
* **`FileNotFoundError`:** 提示用户指定的镜像名称不存在，需要检查 `what` 参数是否正确。
* **`RuntimeError: ... does not exist`:** 提示用户指定的镜像目录下缺少必要的文件，需要检查文件是否存在。
* **`RuntimeError: Failed to build the docker image` 或 `RuntimeError: Running tests failed`:**  表明 Docker 构建或测试过程中出现了错误，需要查看 Docker 的构建日志或测试脚本的输出，进一步排查问题。

通过理解脚本的功能和可能的错误情况，开发人员可以更有效地使用和调试 Frida 的 CI 环境。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/ci/ciimage/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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