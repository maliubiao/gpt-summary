Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The first step is to understand the overall purpose of the script. The file path `frida/subprojects/frida-swift/releng/meson/unittests/rewritetests.py` gives strong clues. "frida" suggests it's related to the Frida dynamic instrumentation tool. "unittests" indicates this is a test suite. "rewritetests" suggests it tests code rewriting functionality. The presence of "meson" further clarifies that it's testing Meson's code rewriting capabilities.

2. **Identify Key Classes and Functions:**  Scan the code for class definitions and important functions. The main class is `RewriterTests`, inheriting from `BasePlatformTests`. Key methods within `RewriterTests` include `setUp`, `prime`, `rewrite_raw`, `rewrite`, and various `test_*` methods.

3. **Analyze `setUp`:**  This method initializes the test environment. `super().setUp()` likely calls the parent class's setup. `self.maxDiff = None` is common in unit tests to show full diffs.

4. **Analyze `prime`:** This function copies test project directories. It clears the build directory if it exists and then copies the specified directory to the build directory. This suggests a testing pattern where different scenarios are set up by copying pre-defined project structures.

5. **Analyze `rewrite_raw`:** This is a core function. It executes an external command (`self.rewrite_command`) with various arguments. It captures stdout and stderr, checks the return code, and parses the stderr as JSON if successful. The `--skip` argument is interesting and suggests the command can selectively skip tests.

6. **Analyze `rewrite`:** This is a helper function that calls `rewrite_raw` with the `"command"` argument. It simplifies calling the core rewriting functionality for specific commands.

7. **Analyze `test_*` Methods:** These methods perform specific tests. Look for patterns:
    * **`self.prime(...)`:** Sets up a test scenario.
    * **`self.rewrite(...)`:** Executes the rewriting command.
    * **`self.assertDictEqual(...)` or `self.assertEqual(...)`:**  Asserts the expected outcome.
    * The names of the test methods (e.g., `test_target_source_list`, `test_target_add_sources`) provide clear indications of what each test verifies.

8. **Infer Functionality from Test Names and Assertions:**  The test names and the assertions give strong hints about the script's capabilities:
    * `test_target_source_list`: Verifies the script can retrieve a list of source files for targets.
    * `test_target_add_sources`: Checks if the script can add source files to a target.
    * `test_target_remove_sources`: Checks if the script can remove source files from a target.
    * `test_target_add`, `test_target_remove`: Test adding and removing entire targets.
    * `test_kwargs_*`: Tests the manipulation of keyword arguments for Meson functions (like `project()`, `executable()`, `dependency()`).
    * `test_target_add_extra_files`, `test_target_remove_extra_files`: Tests managing extra files associated with targets.
    * `test_raw_printer_is_idempotent`: Tests a specific part of Meson's internal AST handling.

9. **Connect to Reverse Engineering:** Consider how the functionality relates to reverse engineering. The ability to modify target sources and keyword arguments directly impacts how a program is built. This is relevant for tasks like:
    * **Adding instrumentation code:** Inserting code for tracing or hooking into existing binaries.
    * **Changing build flags:** Modifying compiler or linker options to influence the generated binary.
    * **Substituting libraries:** Replacing original dependencies with custom ones.

10. **Consider Binary/Kernel/Framework Aspects:** The script interacts with the build system (Meson). While it doesn't directly manipulate binary code or kernel structures, the actions it performs (adding/removing sources, changing build flags) directly affect the *resulting* binary. The tests use `.cpp` and `.c` files, indicating compilation is involved. The mention of targets and dependencies are build system concepts.

11. **Logical Reasoning (Hypothetical Input/Output):**  For the `test_target_add_sources` example:
    * **Input (Implicit):** The initial state of the "1 basic" project as defined in its `meson.build` file.
    * **Input (Explicit):** The `addSrc.json` file containing instructions to add specific source files to particular targets.
    * **Output:** The modified `info.json` file reflecting the added source files in the target definitions.

12. **User Errors:** The most likely user error is providing incorrect or malformed JSON files for the rewrite operations. For instance:
    * Incorrect target names.
    * Specifying non-existent source files.
    * Invalid JSON syntax in the input files.

13. **Debugging Path:**  The script itself is a test suite, so the "user" in this context is likely a developer working on Frida or Meson. To reach this code, a developer would:
    * Be working on the Frida project.
    * Be focusing on the Swift bridge or related components.
    * Be interested in testing the code rewriting capabilities within the build system.
    * Run the Meson test suite, specifically targeting this `rewritetests.py` file or a broader set of tests that includes it.

14. **Refine and Organize:** Finally, organize the observations into a coherent explanation, grouping related points and providing clear examples. Use the information gleaned from the code structure, test names, and assertions to infer the script's purpose and capabilities.
这个Python源代码文件 `rewritetests.py` 是 Frida 动态 Instrumentation 工具项目的一部分，位于 `frida/subprojects/frida-swift/releng/meson/unittests/` 目录下。它的主要功能是**测试 Frida 的代码重写 (rewriting) 功能**，更具体地说，是测试 Frida 如何通过修改 Meson 构建系统生成的元数据来动态地添加、删除目标文件的源代码、以及修改构建参数等。

**功能列举:**

1. **模拟 Meson 构建环境:**  它通过 `prime` 方法复制预定义的测试项目目录结构到构建目录，模拟不同的 Meson 项目状态。
2. **执行代码重写命令:**  `rewrite_raw` 和 `rewrite` 方法执行一个外部命令 (`self.rewrite_command`)，该命令是 Frida 提供的代码重写工具，用于修改 Meson 构建系统的输出。
3. **测试添加和删除源文件:**  通过不同的测试用例（如 `test_target_add_sources`, `test_target_remove_sources`），验证 Frida 能否根据指令向指定的目标 (target) 添加或删除源文件。
4. **测试添加和删除构建目标:**  `test_target_add` 和 `test_target_remove` 测试了添加和删除整个构建目标的能力。
5. **测试修改构建参数 (kwargs):**  `test_kwargs_*` 系列的测试用例验证了 Frida 如何修改 Meson 构建系统中定义的关键字参数 (kwargs)，例如项目的版本、目标的构建选项、依赖项的要求等。
6. **测试添加和删除额外的文件:** `test_target_add_extra_files` 和 `test_target_remove_extra_files` 测试了向构建目标添加或删除额外文件的功能，这些文件可能不是源代码，但需要在构建过程中处理。
7. **验证重写操作的幂等性:** `test_raw_printer_is_idempotent` 测试了 Meson 内部的抽象语法树 (AST) 打印器的幂等性，虽然不是直接的代码重写测试，但也与构建系统的稳定性相关。
8. **读取和验证构建信息:**  测试用例通过执行重写命令后，再次请求构建信息 (`info.json`)，并与期望的结果进行比较 (`assertDictEqual`)，以验证重写操作是否成功。

**与逆向方法的关系及举例说明:**

这个测试文件直接关联到逆向工程中动态 Instrumentation 的方法。Frida 作为一个动态 Instrumentation 工具，允许在运行时修改程序的行为。这个测试文件验证了 Frida 如何通过修改构建系统的元数据，来为后续的 Instrumentation 过程做准备。

**举例说明:**

假设我们想为一个名为 `trivialprog0` 的可执行文件添加一段额外的代码，用于在程序启动时打印一些调试信息。通常，我们需要修改源代码并重新编译。但使用 Frida，我们可以通过以下步骤实现：

1. **分析构建信息:** 运行 Frida 的重写工具，获取 `trivialprog0` 的当前源文件列表。
2. **生成重写指令:** 创建一个 JSON 文件，指示 Frida 向 `trivialprog0` 添加一个新的源文件 `debug_hook.cpp`。
   ```json
   [
     {
       "type": "target",
       "target": "trivialprog0",
       "operation": "src_add",
       "sources": ["debug_hook.cpp"]
     }
   ]
   ```
3. **应用重写指令:**  使用 `rewritetests.py` 中测试的类似方法，Frida 的重写工具会读取这个 JSON 文件，并修改 Meson 生成的构建信息，将 `debug_hook.cpp` 添加到 `trivialprog0` 的源文件列表中。
4. **后续构建和 Instrumentation:**  当重新构建项目时，Meson 会编译 `debug_hook.cpp` 并链接到 `trivialprog0` 中。`debug_hook.cpp` 中可以包含 Frida 的 Gadget 或其他用于 Instrumentation 的代码，在程序运行时被 Frida 注入和执行。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个测试文件本身是用 Python 编写的，并且主要关注 Meson 构建系统的元数据，但它背后的逻辑和测试的功能直接关系到二进制底层和操作系统框架的知识：

1. **二进制链接:**  添加或删除源文件会影响最终二进制文件的链接过程。测试用例隐含地验证了 Frida 修改构建信息后，构建系统能够正确地链接生成新的二进制文件。这涉及到对目标文件格式（如 ELF）、链接器的工作原理的理解。
2. **动态链接库 (Shared Libraries):**  修改构建参数，例如添加依赖项 (`dependencies`)，会影响动态链接库的加载。测试 `test_kwargs_set` 中设置 `dependencies` 字段就体现了这一点。这涉及到对操作系统加载器如何解析和加载共享库的理解。
3. **操作系统调用:**  最终被 Instrumentation 的代码可能需要与操作系统内核进行交互，例如进行系统调用。Frida 的工作原理也涉及到对操作系统进程管理、内存管理等底层机制的理解。
4. **Android Framework:**  在 Android 平台上使用 Frida 进行逆向时，通常需要与 Android Framework 进行交互。修改构建参数可能涉及到添加或修改与 Android 平台相关的库或编译选项。虽然这个测试文件没有直接涉及 Android 特有的代码，但它测试的修改构建参数的能力是进行 Android 逆向的基础。

**逻辑推理、假设输入与输出:**

以 `test_target_source_list` 为例：

* **假设输入:**
    * 一个名为 "1 basic" 的 Meson 项目，其中定义了多个可执行目标 (`trivialprog0` 到 `trivialprog9`)，每个目标有不同的源文件列表。
    * 执行重写命令，请求获取构建目录 (`self.builddir`) 中 `info.json` 文件的信息。
* **逻辑推理:** 重写工具会读取 Meson 生成的 `info.json` 文件，解析其中关于构建目标及其源文件的信息，并以 JSON 格式输出。
* **预期输出:** 一个包含 `target` 键的 JSON 字典，其中每个键是目标的名称（例如 `trivialprog0@exe`），值是包含 `name` 和 `sources` 键的字典，`sources` 键的值是该目标的源文件列表。

**涉及用户或编程常见的使用错误及举例说明:**

1. **JSON 格式错误:**  用户在编写用于指导 Frida 重写操作的 JSON 文件时，可能会犯语法错误，例如缺少逗号、引号不匹配等。这将导致 Frida 的重写工具无法正确解析指令。
   ```json
   # 错误示例：缺少逗号
   [
     {
       "type": "target"
       "target": "my_target"
       "operation": "src_add",
       "sources": ["new_source.cpp"]
     }
   ]
   ```
2. **目标名称错误:** 用户在 JSON 指令中指定的目标名称与 Meson 构建系统中实际的目标名称不符。
   ```json
   # 错误示例：目标名称拼写错误
   [
     {
       "type": "target",
       "target": "trivalprog0",  # 正确的是 trivialprog0
       "operation": "src_add",
       "sources": ["new_source.cpp"]
     }
   ]
   ```
3. **源文件路径错误:** 用户指定的源文件路径不正确，可能文件不存在或路径不相对于项目根目录。
   ```json
   # 错误示例：源文件路径错误
   [
     {
       "type": "target",
       "target": "trivialprog0",
       "operation": "src_add",
       "sources": ["/tmp/nonexistent.cpp"]
     }
   ]
   ```
4. **操作类型错误:**  在 JSON 指令中使用了不支持的操作类型，或者操作类型与目标类型不匹配。
   ```json
   # 错误示例：对目标使用了错误的 operation
   [
     {
       "type": "kwargs", # 应该为 "target"
       "target": "trivialprog0",
       "operation": "src_add",
       "sources": ["new_source.cpp"]
     }
   ]
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户希望使用 Frida 对一个使用 Meson 构建的 Swift 项目进行动态 Instrumentation。**
2. **用户需要修改目标文件的源代码，或者调整构建参数，以便插入 Instrumentation 代码。** 例如，用户可能想添加一个包含 Frida Gadget 的源文件到特定的可执行文件中。
3. **用户了解到 Frida 提供了代码重写功能，可以通过修改 Meson 构建系统的输出来实现上述目的。**
4. **用户可能会查看 Frida 的文档或者示例，了解如何使用 Frida 的重写工具。** 这可能涉及到编写 JSON 格式的指令文件。
5. **在开发和测试 Frida 的重写功能时，开发者会编写单元测试，例如 `rewritetests.py`，来验证重写功能的正确性。**
6. **当 Frida 的重写功能出现问题时，开发者可能会运行这些单元测试来定位 bug。**  例如，如果添加源文件功能不起作用，开发者会运行 `test_target_add_sources` 这个测试用例，查看测试的输入（测试项目和 JSON 指令）和期望的输出，并将实际输出与期望输出进行比较，从而找到问题的根源。
7. **调试过程可能包括:**
    * **查看 `prime` 方法加载的测试项目结构，确认初始状态是否正确。**
    * **检查 `rewrite_raw` 方法执行的命令和参数，确保 Frida 的重写工具被正确调用。**
    * **打印 `rewrite_raw` 方法的 `stdout` 和 `stderr`，查看 Frida 重写工具的输出信息，是否有错误或警告。**
    * **比较实际生成的 `info.json` 文件与期望的 `info.json` 文件，找出差异。**
    * **逐步修改测试用例或 Frida 的重写工具代码，以修复 bug。**

总而言之，`rewritetests.py` 是 Frida 项目中用于确保其代码重写功能正确性的关键测试文件，它模拟了用户通过 Frida 修改 Meson 构建信息的场景，并验证了各种重写操作的有效性。这对于 Frida 作为一个动态 Instrumentation 工具的可靠性至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/unittests/rewritetests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```