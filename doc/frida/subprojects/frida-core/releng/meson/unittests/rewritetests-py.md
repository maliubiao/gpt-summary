Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The first step is to understand the purpose of the script. The filename `rewritetests.py` and the class name `RewriterTests` strongly suggest this is a test suite. The `frida` directory context confirms it's part of the Frida project, a dynamic instrumentation toolkit. Therefore, the code likely tests the ability to modify or "rewrite" build configurations.

**2. High-Level Overview of the Code:**

Skimming through the code, I see:

* **Imports:** Standard Python libraries like `subprocess`, `os`, `shutil`, `unittest`, and `json`, along with specific Meson libraries (`mesonbuild.ast`). This indicates interaction with the file system, running external commands, and manipulating build system definitions (likely Meson's `meson.build` files).
* **`RewriterTests` Class:** This class inherits from `BasePlatformTests`, suggesting a framework for running tests in different environments.
* **Setup (`setUp`) and Teardown (implicit in `prime`):**  The `setUp` method initializes the test environment. The `prime` method prepares the test case by copying a test project into a build directory.
* **`rewrite_raw` and `rewrite` Methods:** These are the core functions that execute the "rewriting" process. They run an external command (`self.rewrite_command`).
* **Test Methods (starting with `test_`):**  Each test method focuses on a specific rewriting scenario (e.g., adding sources, removing targets, modifying project options). They use `self.rewrite` to perform the action and then assert the expected outcome.

**3. Deeper Dive into Key Functions:**

* **`prime(self, dirname)`:** This function is crucial for setting up each test. It copies a pre-defined test project (`dirname`) into the `builddir`. This isolation prevents tests from interfering with each other.
* **`rewrite_raw(self, directory, args)`:** This is the workhorse. It executes an external command. The command includes `--verbose`, `--skip`, `--sourcedir`, and potentially `command`. The output (both stdout and stderr) is captured. The key observation here is the parsing of stderr as JSON. This suggests the rewriting tool likely outputs its results or status in JSON format.
* **`rewrite(self, directory, args)`:** This is a helper function that simplifies calling `rewrite_raw` by automatically prepending "command" to the arguments. This implies the rewriting tool has a "command" mode or subcommand.

**4. Connecting to Reverse Engineering Concepts:**

Now, the crucial step is to link the code's functionality to reverse engineering.

* **Dynamic Instrumentation (Frida Context):**  The fact that this code is part of Frida is the biggest clue. Frida is used for *dynamically* analyzing and modifying running processes. While this particular *test* script doesn't directly inject into a process, it tests the *underlying mechanisms* that would enable such actions. The rewriting likely involves modifying build configurations so that when the target application is *built*, it includes hooks or modifications necessary for dynamic instrumentation.
* **Modifying Target Binaries (Indirectly):**  The tests manipulate source files and build configurations. This indirectly leads to changes in the final compiled binary. In reverse engineering, you often want to modify a binary's behavior, and changing the build process is one way to achieve this (e.g., adding logging, instrumentation points).
* **Understanding Build Systems (Meson):** The script heavily relies on Meson concepts (targets, sources, dependencies, project options). Reverse engineers often need to understand how target applications are built to effectively analyze or modify them.
* **Analyzing Build Artifacts (Implicit):** While not explicitly shown, the fact that the tests check the "info.json" file suggests the rewriting process produces or modifies build metadata that can be inspected. This metadata could be useful for reverse engineers to understand the structure and dependencies of the target application.

**5. Identifying Binary/Kernel/Framework Connections:**

* **Build Process (General):** The entire script deals with the build process, which is fundamental to creating binaries that run on specific operating systems (Linux, Android, Windows).
* **Linux/Android Kernel (Indirect):** While the script itself doesn't directly interact with the kernel, the *purpose* of Frida often involves interacting with the kernel to perform instrumentation. The rewriting tested here likely prepares the groundwork for such kernel-level interactions. For example, it might configure build flags that enable specific kernel features or link against libraries that facilitate kernel communication.
* **Android Framework (Indirect):** Similarly, Frida is heavily used on Android. The rewriting might configure the build to interact with Android-specific frameworks or services, though this isn't directly visible in the test code itself.

**6. Logical Reasoning and Examples:**

* **Assumptions:**  The tests assume the existence of a `rewrite_command` and that it takes specific arguments and outputs JSON on stderr.
* **Input/Output Examples:** The tests themselves provide examples of input (JSON files like `addSrc.json`) and expected output (dictionaries representing the modified build configuration). For example, `test_target_add_sources` takes an `addSrc.json` file and expects the `sources` list of specific targets to be updated.

**7. Common User Errors:**

* **Incorrect JSON Format:**  The script relies on JSON for input. Users could make errors in the JSON syntax, leading to parsing failures.
* **Incorrect Target Names:**  Operations like `src_add` and `target_remove` require specifying target names. Typographical errors would cause the operations to fail.
* **Specifying Non-Existent Files:** Adding sources or extra files that don't exist would likely lead to build errors later on.
* **Conflicting Modifications:** Users might try to add and remove the same source file simultaneously, leading to unpredictable results.

**8. Tracing User Actions:**

To get to this point, a user would typically:

1. **Install Frida:**  Download and install the Frida toolkit.
2. **Set up a Development Environment:**  Install necessary build tools (like Meson) and dependencies.
3. **Configure a Frida Project:** Create a project that uses Frida for dynamic instrumentation. This project would likely have a `meson.build` file.
4. **Attempt to Modify the Build Configuration:**  The user might want to add new source files, change compiler options, or include specific libraries for instrumentation.
5. **Use a Tool that Internally Calls the Rewriting Logic:**  Frida likely provides higher-level tools or APIs that, under the hood, invoke the logic being tested in this script to modify the `meson.build` file. The user wouldn't directly call this Python script, but their actions in a Frida tool would trigger it.
6. **Encounter a Need for Debugging:** If the build configuration is not being modified as expected, developers might need to examine the Frida internals, potentially leading them to this `rewritetests.py` file to understand how the rewriting mechanism works and to debug issues.

By following this structured approach, we can systematically analyze the code and connect it to the broader context of Frida, reverse engineering, and software development.
这个Python源代码文件 `rewritetests.py` 是 Frida 动态 instrumentation 工具的测试套件的一部分，专门用于测试 Frida 中用于重写 (rewriting) Meson 构建系统项目配置的功能。Meson 是一个用于构建软件的构建系统，类似于 CMake 和 Make。

以下是该文件的主要功能及其与逆向、底层知识、逻辑推理和常见错误的关系：

**功能列表:**

1. **测试目标源文件列表获取 (`test_target_source_list`)**:
   - 验证 Frida 能否正确读取 Meson 项目中定义的各个构建目标 (target) 的源文件列表。
   - 它读取一个 `info.json` 文件，该文件包含了期望的目标及其源文件信息，并与实际从 Meson 构建系统中获取的信息进行比较。

2. **测试向目标添加源文件 (`test_target_add_sources`, `test_target_add_sources_abs`)**:
   - 验证 Frida 能否向现有的构建目标动态添加新的源文件。
   - 它读取一个 `addSrc.json` 文件，该文件指示 Frida 向特定目标添加哪些源文件，然后检查修改后的源文件列表是否符合预期。
   - `test_target_add_sources_abs` 特别测试了添加绝对路径的源文件的情况。

3. **测试从目标移除源文件 (`test_target_remove_sources`)**:
   - 验证 Frida 能否从现有的构建目标动态移除指定的源文件。
   - 它读取一个 `rmSrc.json` 文件，指示 Frida 从特定目标移除哪些源文件，并验证修改后的源文件列表。

4. **测试子目录中的目标操作 (`test_target_subdir`, `test_target_remove_subdir`, `test_target_add_subdir`)**:
   - 验证 Frida 在处理包含子目录的 Meson 项目时，添加和移除目标的功能是否正常工作。

5. **测试目标移除 (`test_target_remove`)**:
   - 验证 Frida 能否从 Meson 构建系统中移除整个构建目标。
   - 它读取一个 `rmTgt.json` 文件，指定要移除的目标，然后检查该目标是否不再存在。

6. **测试目标添加 (`test_target_add`)**:
   - 验证 Frida 能否向 Meson 构建系统添加新的构建目标。
   - 它读取一个 `addTgt.json` 文件，包含新目标的定义，然后验证该目标是否已成功添加。

7. **测试目标源文件排序 (`test_target_source_sorting`)**:
   - 验证 Frida 在获取或修改目标源文件列表时，是否能正确处理源文件的排序。

8. **测试同名目标的处理 (`test_target_same_name_skip`)**:
   - 验证 Frida 如何处理具有相同名称的多个目标。

9. **测试关键字参数信息获取和修改 (`test_kwargs_info`, `test_kwargs_set`, `test_kwargs_add`, `test_kwargs_remove`, `test_kwargs_remove_regex`, `test_kwargs_delete`, `test_default_options_set`, `test_default_options_delete`)**:
   - 验证 Frida 能否读取和修改 Meson 项目中各种构建元素的关键字参数 (kwargs)，例如项目本身的参数、目标的参数和依赖项的参数。
   - 这些测试覆盖了设置、添加、删除特定键值对以及使用正则表达式删除键值对的情况。
   - `test_default_options_set` 和 `test_default_options_delete` 特别关注了修改项目默认选项的功能。

10. **测试向目标添加额外的文件 (`test_target_add_extra_files`)**:
    - 验证 Frida 能否向构建目标添加除了源文件之外的额外文件。

11. **测试从目标移除额外的文件 (`test_target_remove_extra_files`)**:
    - 验证 Frida 能否从构建目标移除指定的额外文件。

12. **测试 RawPrinter 的幂等性 (`test_raw_printer_is_idempotent`)**:
    - 验证 `RawPrinter` 类（用于将 Meson AST 转换为文本表示）是否是幂等的，即对相同的 AST 多次调用 `RawPrinter` 应该产生相同的结果。这对于确保重写操作的稳定性和可预测性很重要。

**与逆向方法的关系及举例说明:**

- **动态修改构建配置以插入 hook 或修改代码:** 在逆向工程中，我们可能需要在目标程序运行时插入自定义的代码来监控其行为或修改其逻辑。Frida 提供了这样的能力。此测试文件中的功能可以用来修改目标程序的构建配置，例如添加包含 hook 代码的源文件，或者修改编译选项以方便 hook 的插入和调试。
    - **举例:** 假设我们要逆向一个 Android 应用，需要在其 native 代码中插入一个 hook 来记录某个函数的调用参数。我们可以使用 Frida 的重写功能，向该应用的 native library 的构建目标添加一个新的源文件，该源文件包含 Frida 的 hook 代码，并在构建后使用 Frida 加载并执行。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

- **二进制文件的生成过程:** 理解构建系统的运作方式是理解最终生成的二进制文件的基础。此测试文件直接操作构建系统的配置，涉及到编译器如何将源文件编译链接成可执行文件或库的知识。
- **Linux 动态链接库 (.so) 和可执行文件:**  Frida 经常用于分析和修改 Linux 平台上的动态链接库和可执行文件。测试中操作的目标类型 (例如 `@exe`, `@sha`) 暗示了生成不同类型的二进制文件。
- **Android APK 构建:** 虽然测试本身没有直接涉及 Android 特定的代码，但 Frida 在 Android 逆向中扮演着重要角色。理解 Android APK 的构建过程，包括如何编译 native library (通常是 `.so` 文件) 并将其打包到 APK 中，有助于理解 Frida 如何在 Android 环境下工作。
- **代码注入:**  Frida 的核心功能之一是将代码注入到目标进程中。此测试文件中的重写功能可以为代码注入做准备，例如通过修改构建配置来包含必要的 Frida runtime 或 hook 库。

**逻辑推理及假设输入与输出:**

大多数测试都遵循以下逻辑推理：

1. **假设输入:** 一个初始的 Meson 项目配置（通过复制一个测试目录来模拟）和一个描述修改操作的 JSON 文件（例如 `addSrc.json`）。
2. **操作:** 运行 Frida 的重写工具，并传入 JSON 文件作为指令。
3. **预期输出:** 修改后的 Meson 项目配置，例如目标源文件列表的更新，或者新的目标被添加。

**举例:**

- **假设输入 (`addSrc.json`):**
  ```json
  [
    {
      "type": "target",
      "target": "trivialprog0",
      "operation": "src_add",
      "sources": ["a1.cpp", "a2.cpp"]
    }
  ]
  ```
- **初始状态 (`meson.build` 中 `trivialprog0` 的源文件列表):** `['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp']`
- **预期输出 (运行重写工具后 `trivialprog0` 的源文件列表):** `['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp', 'a1.cpp', 'a2.cpp']`

**涉及用户或编程常见的使用错误及举例说明:**

- **JSON 格式错误:**  如果用户提供的 JSON 文件格式不正确（例如，缺少逗号、引号不匹配），Frida 的重写工具将无法解析，导致操作失败。
    - **举例:**  在 `addSrc.json` 中，如果写成 `{"type": "target" "target": ...}` (缺少逗号)，会导致 JSON 解析错误。
- **目标名称错误:**  如果在 JSON 文件中指定了不存在的目标名称，Frida 将无法找到该目标并执行操作。
    - **举例:**  如果 `meson.build` 中没有名为 `nonexistent_target` 的目标，但在 `addSrc.json` 中指定 `"target": "nonexistent_target"`，操作将失败。
- **文件路径错误:**  在添加源文件时，如果提供的文件路径不存在或不正确，构建过程将会失败。
    - **举例:**  在 `addSrc.json` 中指定了一个不存在的源文件路径 `"sources": ["missing_file.cpp"]`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试使用 Frida 修改项目的构建配置:** 用户可能希望通过 Frida 的 API 或命令行工具来自动化修改一个 Meson 项目的 `meson.build` 文件，例如添加一些用于代码注入或监控的源文件。
2. **Frida 内部调用重写逻辑:** Frida 的高级接口会解析用户的请求，并将其转化为对底层重写功能的调用。这可能涉及到解析 JSON 格式的指令，然后调用相应的 Meson API 来修改构建配置。
3. **遇到问题，需要调试:** 如果用户的修改操作没有按预期生效，或者构建过程因为修改而失败，用户或 Frida 的开发者可能需要深入研究 Frida 的源代码来查找问题。
4. **定位到 `rewritetests.py`:**  作为调试过程的一部分，开发者可能会查看 Frida 的测试套件，特别是 `rewritetests.py`，来理解 Frida 的重写功能是如何实现的，以及如何编写正确的指令。测试用例通常会覆盖各种场景，可以帮助理解可能出错的地方。
5. **分析测试用例:** 开发者可以通过阅读 `rewritetests.py` 中的测试用例，了解 Frida 期望的输入格式（JSON 文件），以及在不同操作下应该产生的预期结果。这有助于他们诊断自己的使用方法是否正确，或者 Frida 的重写功能是否存在 bug。
6. **使用 verbose 输出进行调试:**  测试代码中使用了 `--verbose` 标志，表明 Frida 的重写工具可能提供详细的输出。用户在实际使用中也可以启用 verbose 输出，以获取更多的调试信息，例如查看 Frida 是如何解析 JSON 指令，以及如何与 Meson 构建系统交互的。

总而言之，`rewritetests.py` 是 Frida 动态 instrumentation 工具中用于验证 Meson 构建系统配置重写功能的关键测试文件。它测试了添加、删除和修改构建目标、源文件以及其他构建参数的各种场景，对于理解 Frida 如何与构建系统交互以及如何进行调试至关重要。其功能与逆向工程密切相关，因为它允许在构建阶段为动态分析和修改做准备。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/unittests/rewritetests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2021 The Meson development team

import subprocess
from itertools import zip_longest
import json
import os
from pathlib import Path
import shutil
import unittest

from mesonbuild.ast import IntrospectionInterpreter, AstIDGenerator
from mesonbuild.ast.printer import RawPrinter
from mesonbuild.mesonlib import windows_proof_rmtree
from .baseplatformtests import BasePlatformTests

class RewriterTests(BasePlatformTests):
    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def prime(self, dirname):
        if os.path.exists(self.builddir):
            windows_proof_rmtree(self.builddir)
        shutil.copytree(os.path.join(self.rewrite_test_dir, dirname), self.builddir)

    def rewrite_raw(self, directory, args):
        if isinstance(args, str):
            args = [args]
        command = self.rewrite_command + ['--verbose', '--skip', '--sourcedir', directory] + args
        p = subprocess.run(command, capture_output=True, text=True, timeout=60)
        print('STDOUT:')
        print(p.stdout)
        print('STDERR:')
        print(p.stderr)
        if p.returncode != 0:
            if 'MESON_SKIP_TEST' in p.stdout:
                raise unittest.SkipTest('Project requested skipping.')
            raise subprocess.CalledProcessError(p.returncode, command, output=p.stdout)
        if not p.stderr:
            return {}
        return json.loads(p.stderr)

    def rewrite(self, directory, args):
        if isinstance(args, str):
            args = [args]
        return self.rewrite_raw(directory, ['command'] + args)

    def test_target_source_list(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_add_sources(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp', 'a7.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['a7.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['a5.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['a5.cpp', 'main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['a3.cpp', 'main.cpp', 'a7.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp', 'a4.cpp'], 'extra_files': []},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_target_add_sources_abs(self):
        self.prime('1 basic')
        abs_src = [os.path.join(self.builddir, x) for x in ['a1.cpp', 'a2.cpp', 'a6.cpp']]
        add = json.dumps([{"type": "target", "target": "trivialprog1", "operation": "src_add", "sources": abs_src}])
        inf = json.dumps([{"type": "target", "target": "trivialprog1", "operation": "info"}])
        self.rewrite(self.builddir, add)
        out = self.rewrite(self.builddir, inf)
        expected = {'target': {'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp'], 'extra_files': []}}}
        self.assertDictEqual(out, expected)

    def test_target_remove_sources(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'rmSrc.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileC.cpp'], 'extra_files': []},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileC.cpp', 'main.cpp'], 'extra_files': []},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_target_subdir(self):
        self.prime('2 subdirs')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        expected = {'name': 'something', 'sources': ['first.c', 'second.c', 'third.c'], 'extra_files': []}
        self.assertDictEqual(list(out['target'].values())[0], expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(list(out['target'].values())[0], expected)

    def test_target_remove(self):
        self.prime('1 basic')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'rmTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))

        expected = {
            'target': {
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_add(self):
        self.prime('1 basic')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'addTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))

        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp'], 'extra_files': []},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp', 'fileA.cpp'], 'extra_files': []},
                'trivialprog10@sha': {'name': 'trivialprog10', 'sources': ['new1.cpp', 'new2.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_remove_subdir(self):
        self.prime('2 subdirs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'rmTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, {})

    def test_target_add_subdir(self):
        self.prime('2 subdirs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'addTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {'name': 'something', 'sources': ['first.c', 'second.c'], 'extra_files': []}
        self.assertDictEqual(out['target']['94b671c@@something@exe'], expected)

    def test_target_source_sorting(self):
        self.prime('5 sorting')
        add_json = json.dumps([{'type': 'target', 'target': 'exe1', 'operation': 'src_add', 'sources': ['a666.c']}])
        inf_json = json.dumps([{'type': 'target', 'target': 'exe1', 'operation': 'info'}])
        out = self.rewrite(self.builddir, add_json)
        out = self.rewrite(self.builddir, inf_json)
        expected = {
            'target': {
                'exe1@exe': {
                    'name': 'exe1',
                    'sources': [
                        'aaa/a/a1.c',
                        'aaa/b/b1.c',
                        'aaa/b/b2.c',
                        'aaa/f1.c',
                        'aaa/f2.c',
                        'aaa/f3.c',
                        'bbb/a/b1.c',
                        'bbb/b/b2.c',
                        'bbb/c1/b5.c',
                        'bbb/c2/b7.c',
                        'bbb/c10/b6.c',
                        'bbb/a4.c',
                        'bbb/b3.c',
                        'bbb/b4.c',
                        'bbb/b5.c',
                        'a1.c',
                        'a2.c',
                        'a3.c',
                        'a10.c',
                        'a20.c',
                        'a30.c',
                        'a100.c',
                        'a101.c',
                        'a110.c',
                        'a210.c',
                        'a666.c',
                        'b1.c',
                        'c2.c'
                    ],
                    'extra_files': []
                }
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_same_name_skip(self):
        self.prime('4 same name targets')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {'name': 'myExe', 'sources': ['main.cpp'], 'extra_files': []}
        self.assertEqual(len(out['target']), 2)
        for val in out['target'].values():
            self.assertDictEqual(expected, val)

    def test_kwargs_info(self):
        self.prime('3 kwargs')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1'},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_set(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'set.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.2', 'meson_version': '0.50.0', 'license': ['GPL', 'MIT']},
                'target#tgt1': {'build_by_default': False, 'build_rpath': '/usr/local', 'dependencies': 'dep1'},
                'dependency#dep1': {'required': True, 'method': 'cmake'}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_add(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'add.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'license': ['GPL', 'MIT', 'BSD', 'Boost']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_remove(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'remove.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'license': 'GPL'},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_remove_regex(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'remove_regex.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': 'debug=true'},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_delete(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'delete.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {},
                'target#tgt1': {},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_default_options_set(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'defopts_set.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': ['buildtype=release', 'debug=True', 'cpp_std=c++11']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_default_options_delete(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'defopts_delete.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': ['cpp_std=c++14', 'debug=true']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_add_extra_files(self):
        self.prime('6 extra_files')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addExtraFiles.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp'], 'extra_files': ['a1.hpp', 'a2.hpp', 'a6.hpp', 'fileA.hpp', 'main.hpp', 'a7.hpp', 'fileB.hpp', 'fileC.hpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp'], 'extra_files': ['a1.hpp', 'a2.hpp', 'a6.hpp', 'fileA.hpp', 'main.hpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['main.cpp'], 'extra_files': ['a7.hpp', 'fileB.hpp', 'fileC.hpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp'], 'extra_files': ['a5.hpp', 'fileA.hpp', 'main.hpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp'], 'extra_files': ['a5.hpp', 'main.hpp', 'fileA.hpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp'], 'extra_files': ['a3.hpp', 'main.hpp', 'a7.hpp', 'fileB.hpp', 'fileC.hpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp'], 'extra_files': ['a1.hpp', 'a2.hpp', 'a6.hpp', 'fileA.hpp', 'main.hpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['main.cpp'], 'extra_files': ['a1.hpp', 'a2.hpp', 'a6.hpp', 'fileA.hpp', 'main.hpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp'], 'extra_files': ['a2.hpp', 'a7.hpp']},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp'], 'extra_files': ['a8.hpp', 'a9.hpp']},
                'trivialprog10@exe': {'name': 'trivialprog10', 'sources': ['main.cpp'], 'extra_files': ['a1.hpp', 'a4.hpp']},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_target_remove_extra_files(self):
        self.prime('6 extra_files')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'rmExtraFiles.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp'], 'extra_files': ['main.hpp', 'fileC.hpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp'], 'extra_files': ['main.hpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['main.cpp'], 'extra_files': ['fileC.hpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp'], 'extra_files': ['main.hpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp'], 'extra_files': ['main.hpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp'], 'extra_files': ['main.hpp', 'fileC.hpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp'], 'extra_files': ['main.hpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['main.cpp'], 'extra_files': ['main.hpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp'], 'extra_files': []},
                'trivialprog10@exe': {'name': 'trivialprog10', 'sources': ['main.cpp'], 'extra_files': []},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_raw_printer_is_idempotent(self):
        test_path = Path(self.unit_test_dir, '120 rewrite')
        meson_build_file = test_path / 'meson.build'
        # original_contents = meson_build_file.read_bytes()
        original_contents = meson_build_file.read_text(encoding='utf-8')

        interpreter = IntrospectionInterpreter(test_path, '', 'ninja', visitors = [AstIDGenerator()])
        interpreter.analyze()

        printer = RawPrinter()
        interpreter.ast.accept(printer)
        # new_contents = printer.result.encode('utf-8')
        new_contents = printer.result

        # Do it line per line because it is easier to debug like that
        for orig_line, new_line in zip_longest(original_contents.splitlines(), new_contents.splitlines()):
            self.assertEqual(orig_line, new_line)
```