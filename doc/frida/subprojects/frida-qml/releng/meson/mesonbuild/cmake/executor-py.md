Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Understanding the Request:**

The core request is to analyze the provided Python code (`executor.py`) which is part of Frida, a dynamic instrumentation tool. The request asks for a breakdown of its functionality, connection to reverse engineering, relevance to low-level systems, logical inferences, potential user errors, and how a user might end up interacting with this specific file.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to get a general idea of its purpose. Keywords like `CMakeExecutor`, `subprocess`, `Popen`, `find_external_program`, `version_compare`, and arguments like `-DCMAKE_PREFIX_PATH` immediately suggest that this code is responsible for executing CMake. The presence of `PerMachine` hints at handling cross-compilation scenarios (different architectures).

**3. Deeper Dive into Key Components:**

Now, focus on the important classes and methods:

* **`CMakeExecutor` Class:** This is the central entity. It manages the execution of CMake. Note the class variables like `class_cmakebin` and `class_cmakevers`, which are used for caching the CMake executable path and version.
* **`__init__`:**  Initialization sets up the environment, finds the CMake binary, checks the version, and sets up CMake arguments based on Meson configuration.
* **`find_cmake_binary`:** This method is crucial. It searches for the CMake executable using Meson's mechanisms. The caching logic using `class_cmakebin` is important.
* **`check_cmake`:** Verifies if a found executable is actually CMake and extracts its version.
* **`call` and the `_call_*` methods:** These methods handle the actual execution of CMake using `subprocess`. Notice the different `_call_*` variants (`_call_cmout_stderr`, `_call_cmout`, `_call_quiet`) which control output handling. The caching mechanism in `call` is also key.
* **`_cache_key`:**  Determines the unique identifier for a CMake call to facilitate caching.

**4. Connecting to the Request's Specific Points:**

Now, systematically address each point in the request:

* **Functionality:**  Summarize the overall purpose. Focus on finding, verifying, and executing CMake. Mention the output handling and caching.
* **Reverse Engineering Relationship:**  Think about *why* Frida would need to execute CMake. It's likely for building native components or libraries that Frida interacts with during dynamic instrumentation. Provide concrete examples like recompiling a library with debugging symbols or building a custom agent.
* **Binary/Low-Level, Linux/Android Kernel/Framework:** Consider the context of CMake. It's used to build native code, which is inherently binary and low-level. Think about how Frida targets processes running on operating systems, including Android (which is based on Linux). CMake builds libraries that interact directly with the kernel and frameworks. Provide examples like building native hooks or Frida gadgets.
* **Logical Inferences (Input/Output):** Choose a simple, representative scenario. Invoking CMake with a specific `CMakeLists.txt` in a build directory and providing an environment variable is a good choice. Describe the expected outcome (success or failure) and what would be printed to stdout/stderr. Emphasize the caching.
* **User/Programming Errors:**  Consider common mistakes users make when working with build systems and external tools like CMake. Incorrect CMakeLists.txt, missing dependencies, and wrong paths are good examples. Explain how Meson and this code would react to these errors.
* **User Operation to Reach Here (Debugging):** Think about the typical Frida development workflow. A user would be writing a Frida script that interacts with a target application. If that application has native components built with CMake, Meson would be used to build those components, and this `executor.py` file would be involved. Describe the steps leading to this point, including configuration and the potential need for debugging CMake execution.

**5. Structuring the Explanation:**

Organize the findings into logical sections that directly correspond to the request's points. Use clear headings and bullet points for readability. Provide concrete examples whenever possible to illustrate abstract concepts.

**6. Refining and Adding Detail:**

Review the explanation. Are there any ambiguities? Can any points be expanded with more technical detail?  For example, explicitly mention the role of Meson in the build process. Ensure the examples are relevant and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Maybe this is just about finding CMake.
* **Correction:** Realized it's about *executing* CMake and managing its output and caching.
* **Initial Thought:** The connection to reverse engineering is weak.
* **Correction:**  Focus on the scenario of building native components for Frida's usage, providing more specific examples like building custom agents.
* **Initial Thought:**  Just list potential errors.
* **Correction:**  Explain how Meson might report these errors and how the user could diagnose them.

By following these steps, systematically analyzing the code and addressing each part of the request, we can generate a comprehensive and informative explanation like the example provided previously.
这个Python文件 `executor.py` 是 Frida 工具链中负责执行 CMake 的模块。它的主要功能是管理和执行 CMake 命令，并处理其输出。由于 Frida 经常需要构建一些与目标进程交互的本地代码，CMake 作为流行的跨平台构建工具，被 Frida 的构建系统 Meson 集成也就理所当然了。

下面详细列举其功能，并根据要求进行说明：

**功能:**

1. **查找 CMake 可执行文件:**
   - `find_cmake_binary` 方法负责在系统中查找 CMake 的可执行文件。它会利用 Meson 的配置信息和默认路径进行搜索。
   - 为了避免重复搜索，它使用了类变量 `class_cmakebin` 和 `class_cmakevers` 来缓存找到的 CMake 路径和版本信息，并针对不同的机器架构（target/host）进行区分。
   - 它会调用 `check_cmake` 方法来验证找到的程序是否真的是 CMake，并提取其版本号。

2. **检查 CMake 版本:**
   - `check_cmake` 方法接收一个潜在的 CMake 可执行文件路径，并尝试运行 `cmake --version` 命令。
   - 它会解析输出，提取 CMake 的版本号，并将其与要求的最低版本进行比较。如果版本不符合要求，则会发出警告。

3. **设置 CMake 执行模式:**
   - `set_exec_mode` 方法允许配置 CMake 执行时的输出处理方式。
   - `print_cmout`: 控制是否将 CMake 的标准输出打印到 Meson 的日志中。
   - `always_capture_stderr`: 控制是否始终捕获 CMake 的标准错误输出。

4. **执行 CMake 命令:**
   - `call` 方法是执行 CMake 命令的核心方法。它接收要传递给 CMake 的参数列表、构建目录和环境变量。
   - **缓存机制:** 为了提高构建效率，它实现了缓存机制。它使用 `_cache_key` 方法生成一个基于 CMake 路径、参数、构建目录和环境变量的唯一键。如果相同的 CMake 调用之前执行过，则直接返回缓存的结果，避免重复执行。
   - **不同的执行方式:**  `_call_impl` 方法根据 `print_cmout` 和 `always_capture_stderr` 的设置，选择不同的方式执行 CMake 命令：
     - `_call_quiet`: 静默执行，捕获标准输出和标准错误。
     - `_call_cmout`: 将标准输出打印到 Meson 日志，标准错误和标准输出合并。
     - `_call_cmout_stderr`: 将标准输出打印到 Meson 日志，标准错误单独处理，并尝试解析 CMake 的跟踪信息。
   - 它使用 `subprocess` 模块来执行 CMake 命令。为了避免管道阻塞，对于需要打印标准输出的情况，它使用了线程来异步读取标准输出。

5. **获取 CMake 相关信息:**
   - `found`: 返回是否找到了可用的 CMake。
   - `version`: 返回找到的 CMake 的版本号。
   - `executable_path`: 返回找到的 CMake 的可执行文件路径。
   - `get_command`: 返回 CMake 的命令列表（通常只是可执行文件路径）。
   - `get_cmake_prefix_paths`: 返回通过 Meson 配置的 `cmake_prefix_path`。
   - `machine_choice`: 返回当前操作针对的目标机器架构。

**与逆向方法的关系及举例说明:**

Frida 作为一个动态 instrumentation 工具，经常需要在运行时与目标进程进行交互。为了实现某些功能，Frida 可能需要编译一些本地代码 (例如，C/C++ 编写的 Agent 或 Gadget) 并注入到目标进程中。CMake 就是用来构建这些本地代码的工具。

**举例说明:**

假设你正在使用 Frida 逆向一个 Android 应用，并且你需要编写一个 Frida 脚本来 hook (拦截)  应用 Native 层 (使用 C/C++ 编写) 的某个函数。

1. **编写 Native 代码:** 你可能需要编写一个 C/C++ 的共享库 (例如 `my_agent.so`)，其中包含了 Frida Agent 的代码，包括 hook 函数的逻辑。
2. **使用 CMake 构建:** 你会创建一个 `CMakeLists.txt` 文件来描述如何构建这个共享库，包括源文件、头文件路径、链接库等信息。
3. **Frida 构建系统:** 当 Frida 的构建系统 (Meson) 检测到需要构建 Native 组件时，它会调用 `executor.py` 中的 `CMakeExecutor` 来执行 CMake。
4. **执行 CMake:** `executor.py` 会找到 CMake 可执行文件，并根据 `CMakeLists.txt` 的描述，在指定的构建目录下执行 CMake 命令来生成构建文件 (例如 Makefile 或 Ninja 文件)。
5. **编译 Native 代码:** 接下来，Meson 会使用构建工具 (如 `make` 或 `ninja`) 来编译 `my_agent.so`。
6. **注入到目标进程:** 最终，你的 Frida 脚本会将编译好的 `my_agent.so` 注入到目标 Android 应用的进程中。

在这个过程中，`executor.py` 扮演了关键角色，负责驱动 CMake 完成 Native 代码的构建准备工作。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

- **二进制底层:** CMake 的目标是构建可执行的二进制文件 (如共享库 `.so`，可执行文件) 或静态库 `.a`。`executor.py` 通过调用 CMake，间接地参与了二进制代码的构建过程。
- **Linux:** Frida 本身以及其构建系统 Meson 通常在 Linux 环境下开发。`executor.py` 中使用 `subprocess` 执行 CMake 命令是标准的 Linux 进程管理方式。
- **Android:** Frida 可以用来分析 Android 应用。CMake 经常用于构建 Android 应用的 Native 组件 (通过 NDK)。`executor.py` 会被用于构建这些 Native 组件。
- **内核及框架:** 虽然 `executor.py` 本身不直接操作内核或框架，但它构建出的 Native 代码可能会与内核或 Android 框架进行交互。例如，Frida Agent 可以 hook Android 系统框架中的函数。

**举例说明:**

假设你正在开发一个 Frida Gadget (Frida 的一个组件，可以嵌入到目标进程中)。这个 Gadget 需要在 Android 系统启动时就运行，并 hook 一些底层的系统调用 (属于 Linux 内核的范畴)。

1. **编写 Gadget 代码:** 你会编写 C/C++ 代码，使用 Frida 的 API 来实现 hook 系统调用的逻辑。
2. **CMake 构建:** 使用 CMake 来配置 Gadget 的构建，指定目标平台为 Android，并链接必要的库。
3. **`executor.py` 的作用:** Meson 会调用 `executor.py` 来执行 CMake，生成 Android 平台所需的构建文件。CMake 需要理解 Android NDK 的工具链和构建流程，而 `executor.py` 只是负责执行 CMake 命令。
4. **编译 Gadget:** 构建系统会使用 Android NDK 的编译器来编译 Gadget 代码，生成能在 Android 上运行的二进制文件。
5. **部署和运行:**  这个 Gadget 会被打包并部署到 Android 系统中，并在系统启动时加载运行，从而 hook 目标系统调用。

**逻辑推理及假设输入与输出:**

假设有以下输入：

- `args`: `['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Debug', '../../my_project']`  (CMake 参数，指定使用 Ninja 构建系统，构建类型为 Debug，以及源代码路径)
- `build_dir`: `/path/to/build` (构建目录)
- `env`: `{'PATH': '/usr/bin:/bin', 'MY_CUSTOM_VAR': 'value'}` (环境变量)
- `CMakeExecutor` 实例已成功找到 CMake 可执行文件 `/usr/bin/cmake`，版本为 `3.18.0`。

**逻辑推理:**

1. `call` 方法被调用，传递了以上参数。
2. `_cache_key` 方法会生成一个缓存键，基于 CMake 路径、参数、构建目录和环境变量。
3. 检查缓存中是否已存在该键的结果。
4. 如果缓存未命中，则调用 `_call_impl` 方法。
5. `_call_impl` 方法会根据 `self.print_cmout` 和 `self.always_capture_stderr` 的设置，选择合适的执行方式。假设 `self.print_cmout` 为 `False`，则会调用 `_call_quiet`。
6. `_call_quiet` 方法会使用 `subprocess.run` 执行命令：`['/usr/bin/cmake', '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Debug', '../../my_project']`，工作目录为 `/path/to/build`，并使用提供的环境变量。

**可能的输出:**

- **成功:** 如果 CMake 执行成功，`_call_quiet` 会返回 `(0, stdout_content, stderr_content)`，其中 `stdout_content` 和 `stderr_content` 分别是 CMake 标准输出和标准错误的字符串。这些内容不会打印到 Meson 日志中 (因为 `self.print_cmout` 为 `False`)。
- **失败:** 如果 CMake 执行失败 (例如 `CMakeLists.txt` 存在错误)，`_call_quiet` 会返回非零的返回码，以及相应的标准输出和标准错误信息。

**缓存的影响:** 如果之后使用相同的输入再次调用 `call` 方法，由于缓存命中，`_call_impl` 将不会被执行，而是直接返回之前缓存的结果。

**用户或编程常见的使用错误及举例说明:**

1. **CMake 未安装或不在 PATH 中:** 如果系统上没有安装 CMake，或者 CMake 的可执行文件路径没有添加到系统的 PATH 环境变量中，`find_cmake_binary` 方法将无法找到 CMake，导致后续调用 CMake 的操作失败。
   - **错误示例:** 用户在没有安装 CMake 的环境下运行 Frida 的构建命令。
   - **Meson 的提示:** Meson 会提示找不到 CMake 可执行文件。

2. **CMake 版本过低:** Frida 可能依赖特定版本的 CMake 功能。如果系统上的 CMake 版本低于 `min_version` 中指定的要求，`CMakeExecutor` 会发出警告，并且不会使用该版本的 CMake。
   - **错误示例:** 用户使用的 CMake 版本太旧，不支持某些 CMake 命令或特性。
   - **Meson 的提示:** Meson 会发出版本不兼容的警告。

3. **`CMakeLists.txt` 配置错误:** 如果用户提供的 `CMakeLists.txt` 文件中存在语法错误、逻辑错误或缺失必要的配置，CMake 执行时会报错。
   - **错误示例:**  `CMakeLists.txt` 中使用了未定义的变量，或者尝试链接不存在的库。
   - **`executor.py` 的处理:** `executor.py` 会捕获 CMake 的标准错误输出，并将其记录到 Meson 的日志中，帮助用户定位错误。

4. **构建目录权限问题:** 如果用户对指定的构建目录没有读写权限，CMake 将无法在该目录下生成构建文件。
   - **错误示例:** 构建目录被设置为只读权限。
   - **`executor.py` 的处理:**  `executor.py` 会尝试创建构建目录 (如果不存在)，但如果权限不足，`subprocess.run` 会抛出异常。

5. **环境变量配置错误:** 某些 CMake 项目可能依赖特定的环境变量。如果用户没有正确设置这些环境变量，CMake 构建可能会失败。
   - **错误示例:**  构建 Android Native 代码时，没有正确设置 `ANDROID_NDK_ROOT` 环境变量。
   - **`executor.py` 的处理:**  用户需要确保传递给 `call` 方法的 `env` 参数包含了正确的环境变量。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 项目的构建:** 用户通常会从一个包含 `meson.build` 文件的 Frida 项目根目录开始。
2. **配置构建:** 用户运行 `meson setup build` 命令来配置构建环境。Meson 会读取 `meson.build` 文件，解析构建需求。
3. **检测 CMake 依赖:** 如果 `meson.build` 文件中声明了需要使用 CMake 构建的子项目或依赖项，Meson 会调用 `executor.py` 中的 `CMakeExecutor` 来处理这些 CMake 项目。
4. **查找 CMake:** `CMakeExecutor` 初始化时会尝试查找 CMake 可执行文件 (`find_cmake_binary`)。
5. **执行 CMake 命令:**  当 Meson 需要生成 CMake 项目的构建文件时，会调用 `CMakeExecutor` 的 `call` 方法，并传递相应的 CMake 参数、构建目录和环境变量。这些参数通常由 Meson 根据 `meson.build` 文件中的配置生成。
6. **处理 CMake 输出:** `executor.py` 会执行 CMake 命令，并根据配置处理其标准输出和标准错误。
7. **缓存:** 如果启用了缓存，后续相同的 CMake 调用会直接从缓存中获取结果。

**作为调试线索:**

- **查看 Meson 日志:** 当构建过程中出现与 CMake 相关的错误时，用户应该首先查看 Meson 的日志文件 (通常位于 `build/meson-log.txt`)。日志中会包含 `executor.py` 执行 CMake 命令的详细信息，包括使用的 CMake 命令、参数、构建目录、输出和错误信息。
- **检查 CMake 版本:** 如果怀疑是 CMake 版本问题，可以查看 Meson 日志中关于 CMake 版本检测的信息。
- **调试 `CMakeLists.txt`:** 如果 CMake 执行失败，错误信息通常会指向 `CMakeLists.txt` 文件中的具体问题。
- **检查环境变量:**  确认构建过程中使用的环境变量是否正确设置。
- **手动执行 CMake 命令:**  为了进一步调试，用户可以从 Meson 日志中复制 `executor.py` 执行的 CMake 命令，然后在命令行中手动执行，以便更直接地观察 CMake 的行为和输出。

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/cmake/executor.py` 文件是 Frida 构建系统中用于集成和执行 CMake 的关键组件，它负责查找、验证和运行 CMake，并管理其输出，为 Frida 的 Native 组件构建提供了基础。理解其功能有助于理解 Frida 的构建流程以及排查与 CMake 相关的构建问题。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/cmake/executor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

from __future__ import annotations

import subprocess as S
from threading import Thread
import typing as T
import re
import os

from .. import mlog
from ..mesonlib import PerMachine, Popen_safe, version_compare, is_windows, OptionKey
from ..programs import find_external_program, NonExistingExternalProgram

if T.TYPE_CHECKING:
    from pathlib import Path

    from ..environment import Environment
    from ..mesonlib import MachineChoice
    from ..programs import ExternalProgram

    TYPE_result = T.Tuple[int, T.Optional[str], T.Optional[str]]
    TYPE_cache_key = T.Tuple[str, T.Tuple[str, ...], str, T.FrozenSet[T.Tuple[str, str]]]

class CMakeExecutor:
    # The class's copy of the CMake path. Avoids having to search for it
    # multiple times in the same Meson invocation.
    class_cmakebin: PerMachine[T.Optional[ExternalProgram]] = PerMachine(None, None)
    class_cmakevers: PerMachine[T.Optional[str]] = PerMachine(None, None)
    class_cmake_cache: T.Dict[T.Any, TYPE_result] = {}

    def __init__(self, environment: 'Environment', version: str, for_machine: MachineChoice, silent: bool = False):
        self.min_version = version
        self.environment = environment
        self.for_machine = for_machine
        self.cmakebin, self.cmakevers = self.find_cmake_binary(self.environment, silent=silent)
        self.always_capture_stderr = True
        self.print_cmout = False
        self.prefix_paths: T.List[str] = []
        self.extra_cmake_args: T.List[str] = []

        if self.cmakebin is None:
            return

        if not version_compare(self.cmakevers, self.min_version):
            mlog.warning(
                'The version of CMake', mlog.bold(self.cmakebin.get_path()),
                'is', mlog.bold(self.cmakevers), 'but version', mlog.bold(self.min_version),
                'is required')
            self.cmakebin = None
            return

        self.prefix_paths = self.environment.coredata.options[OptionKey('cmake_prefix_path', machine=self.for_machine)].value
        if self.prefix_paths:
            self.extra_cmake_args += ['-DCMAKE_PREFIX_PATH={}'.format(';'.join(self.prefix_paths))]

    def find_cmake_binary(self, environment: 'Environment', silent: bool = False) -> T.Tuple[T.Optional['ExternalProgram'], T.Optional[str]]:
        # Only search for CMake the first time and store the result in the class
        # definition
        if isinstance(CMakeExecutor.class_cmakebin[self.for_machine], NonExistingExternalProgram):
            mlog.debug(f'CMake binary for {self.for_machine} is cached as not found')
            return None, None
        elif CMakeExecutor.class_cmakebin[self.for_machine] is not None:
            mlog.debug(f'CMake binary for {self.for_machine} is cached.')
        else:
            assert CMakeExecutor.class_cmakebin[self.for_machine] is None

            mlog.debug(f'CMake binary for {self.for_machine} is not cached')
            for potential_cmakebin in find_external_program(
                    environment, self.for_machine, 'cmake', 'CMake',
                    environment.default_cmake, allow_default_for_cross=False):
                version_if_ok = self.check_cmake(potential_cmakebin)
                if not version_if_ok:
                    continue
                if not silent:
                    mlog.log('Found CMake:', mlog.bold(potential_cmakebin.get_path()),
                             f'({version_if_ok})')
                CMakeExecutor.class_cmakebin[self.for_machine] = potential_cmakebin
                CMakeExecutor.class_cmakevers[self.for_machine] = version_if_ok
                break
            else:
                if not silent:
                    mlog.log('Found CMake:', mlog.red('NO'))
                # Set to False instead of None to signify that we've already
                # searched for it and not found it
                CMakeExecutor.class_cmakebin[self.for_machine] = NonExistingExternalProgram()
                CMakeExecutor.class_cmakevers[self.for_machine] = None
                return None, None

        return CMakeExecutor.class_cmakebin[self.for_machine], CMakeExecutor.class_cmakevers[self.for_machine]

    def check_cmake(self, cmakebin: 'ExternalProgram') -> T.Optional[str]:
        if not cmakebin.found():
            mlog.log(f'Did not find CMake {cmakebin.name!r}')
            return None
        try:
            cmd = cmakebin.get_command()
            p, out = Popen_safe(cmd + ['--version'])[0:2]
            if p.returncode != 0:
                mlog.warning('Found CMake {!r} but couldn\'t run it'
                             ''.format(' '.join(cmd)))
                return None
        except FileNotFoundError:
            mlog.warning('We thought we found CMake {!r} but now it\'s not there. How odd!'
                         ''.format(' '.join(cmd)))
            return None
        except PermissionError:
            msg = 'Found CMake {!r} but didn\'t have permissions to run it.'.format(' '.join(cmd))
            if not is_windows():
                msg += '\n\nOn Unix-like systems this is often caused by scripts that are not executable.'
            mlog.warning(msg)
            return None

        cmvers = re.search(r'(cmake|cmake3)\s*version\s*([\d.]+)', out)
        if cmvers is not None:
            return cmvers.group(2)
        mlog.warning(f'We thought we found CMake {cmd!r}, but it was missing the expected '
                     'version string in its output.')
        return None

    def set_exec_mode(self, print_cmout: T.Optional[bool] = None, always_capture_stderr: T.Optional[bool] = None) -> None:
        if print_cmout is not None:
            self.print_cmout = print_cmout
        if always_capture_stderr is not None:
            self.always_capture_stderr = always_capture_stderr

    def _cache_key(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]]) -> TYPE_cache_key:
        fenv = frozenset(env.items()) if env is not None else frozenset()
        targs = tuple(args)
        return (self.cmakebin.get_path(), targs, build_dir.as_posix(), fenv)

    def _call_cmout_stderr(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]]) -> TYPE_result:
        cmd = self.cmakebin.get_command() + args
        proc = S.Popen(cmd, stdout=S.PIPE, stderr=S.PIPE, cwd=str(build_dir), env=env)  # TODO [PYTHON_37]: drop Path conversion

        # stdout and stderr MUST be read at the same time to avoid pipe
        # blocking issues. The easiest way to do this is with a separate
        # thread for one of the pipes.
        def print_stdout() -> None:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                mlog.log(line.decode(errors='ignore').strip('\n'))
            proc.stdout.close()

        t = Thread(target=print_stdout)
        t.start()

        try:
            # Read stderr line by line and log non trace lines
            raw_trace = ''
            tline_start_reg = re.compile(r'^\s*(.*\.(cmake|txt))\(([0-9]+)\):\s*(\w+)\(.*$')
            inside_multiline_trace = False
            while True:
                line_raw = proc.stderr.readline()
                if not line_raw:
                    break
                line = line_raw.decode(errors='ignore')
                if tline_start_reg.match(line):
                    raw_trace += line
                    inside_multiline_trace = not line.endswith(' )\n')
                elif inside_multiline_trace:
                    raw_trace += line
                else:
                    mlog.warning(line.strip('\n'))

        finally:
            proc.stderr.close()
            t.join()
            proc.wait()

        return proc.returncode, None, raw_trace

    def _call_cmout(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]]) -> TYPE_result:
        cmd = self.cmakebin.get_command() + args
        proc = S.Popen(cmd, stdout=S.PIPE, stderr=S.STDOUT, cwd=str(build_dir), env=env)  # TODO [PYTHON_37]: drop Path conversion
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            mlog.log(line.decode(errors='ignore').strip('\n'))
        proc.stdout.close()
        proc.wait()
        return proc.returncode, None, None

    def _call_quiet(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]]) -> TYPE_result:
        build_dir.mkdir(parents=True, exist_ok=True)
        cmd = self.cmakebin.get_command() + args
        ret = S.run(cmd, env=env, cwd=str(build_dir), close_fds=False,
                    stdout=S.PIPE, stderr=S.PIPE, universal_newlines=False)   # TODO [PYTHON_37]: drop Path conversion
        rc = ret.returncode
        out = ret.stdout.decode(errors='ignore')
        err = ret.stderr.decode(errors='ignore')
        return rc, out, err

    def _call_impl(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]]) -> TYPE_result:
        mlog.debug(f'Calling CMake ({self.cmakebin.get_command()}) in {build_dir} with:')
        for i in args:
            mlog.debug(f'  - "{i}"')
        if not self.print_cmout:
            return self._call_quiet(args, build_dir, env)
        else:
            if self.always_capture_stderr:
                return self._call_cmout_stderr(args, build_dir, env)
            else:
                return self._call_cmout(args, build_dir, env)

    def call(self, args: T.List[str], build_dir: Path, env: T.Optional[T.Dict[str, str]] = None, disable_cache: bool = False) -> TYPE_result:
        if env is None:
            env = os.environ.copy()

        args = args + self.extra_cmake_args
        if disable_cache:
            return self._call_impl(args, build_dir, env)

        # First check if cached, if not call the real cmake function
        cache = CMakeExecutor.class_cmake_cache
        key = self._cache_key(args, build_dir, env)
        if key not in cache:
            cache[key] = self._call_impl(args, build_dir, env)
        return cache[key]

    def found(self) -> bool:
        return self.cmakebin is not None

    def version(self) -> str:
        return self.cmakevers

    def executable_path(self) -> str:
        return self.cmakebin.get_path()

    def get_command(self) -> T.List[str]:
        return self.cmakebin.get_command()

    def get_cmake_prefix_paths(self) -> T.List[str]:
        return self.prefix_paths

    def machine_choice(self) -> MachineChoice:
        return self.for_machine
```