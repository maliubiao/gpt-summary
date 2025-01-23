Response:
Let's break down the thought process for analyzing the Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The core request is to analyze a Python script (`rewritetests.py`) related to the Frida dynamic instrumentation tool. The analysis needs to cover its functionality, connections to reverse engineering, low-level aspects, logical reasoning, potential user errors, and debugging hints.

**2. Initial Code Scan & High-Level Understanding:**

I started by quickly scanning the code to get a general idea of its purpose. Keywords like `unittest`, `subprocess`, `json`, `os`, `shutil`, and file paths (`frida/subprojects/frida-qml/releng/meson/unittests/rewritetests.py`) suggested that this is a set of unit tests for a tool that manipulates build files (likely Meson build files). The presence of "rewrite" in the filename and function names (`rewrite_raw`, `rewrite`) strongly indicates that the tests verify a functionality to modify these build files.

**3. Identifying Key Components and Functionality:**

I then focused on the `RewriterTests` class, which inherits from `BasePlatformTests`. The `setUp` method and the `prime` method pointed to setting up test environments by copying and cleaning directories. The core logic seemed to reside in the `rewrite_raw` and `rewrite` methods, which use `subprocess.run` to execute some external command. The interaction with JSON further hinted at the exchange of structured data.

**4. Analyzing Individual Test Methods:**

Next, I went through each `test_...` method. These methods provide concrete examples of how the "rewrite" functionality is being tested. I paid attention to:

* **The `prime` method call:** What test directory is being used?
* **The `rewrite` method call:** What arguments are being passed (often JSON files)?
* **The `expected` dictionary:** What is the anticipated output after the rewrite operation?
* **The `assertDictEqual` calls:** What aspects of the output are being verified?

By examining the test names (e.g., `test_target_source_list`, `test_target_add_sources`, `test_kwargs_set`), I could infer the specific functionality being tested in each case. For instance, `test_target_source_list` clearly checks the ability to retrieve the source files of targets.

**5. Connecting to Reverse Engineering:**

With an understanding of the code's functionality (manipulating build files), I started to think about its relevance to reverse engineering. Frida is a dynamic instrumentation tool, and the ability to modify build configurations could be useful in preparing targets for instrumentation. For example, adding debug symbols or specific compiler flags. This led to the example of injecting custom compiler flags for easier debugging in a reverse engineering context.

**6. Identifying Low-Level Aspects:**

The use of `subprocess.run` to execute an external command immediately suggested interaction with the underlying operating system. The manipulation of file paths and directories using `os` and `shutil` further reinforced this. I considered how build systems like Meson interact with compilers and linkers, which are inherently low-level processes. This prompted the examples related to compiler flags and linking libraries. While the *Python code itself* isn't directly manipulating kernel code, the *tool it's testing* likely does during the build process.

**7. Spotting Logical Reasoning:**

The tests demonstrate logical reasoning in the form of input (the initial build files and the JSON instructions) and expected output (the modified build information). I looked for patterns in how the JSON instructions drive the changes. For instance, the `addSrc.json` files contain instructions to add source files to specific targets, and the tests verify that these additions are correctly reflected in the output. I formulated the example of adding a source file to a target and checking the updated source list.

**8. Considering User Errors:**

Based on the code and its purpose, I considered common errors a user might make. Providing incorrect file paths in the JSON instructions seemed like a likely mistake. Also, misunderstandings about the structure of the JSON and the expected keys could lead to errors. The example of providing a wrong target name in `addSrc.json` illustrates this.

**9. Tracing User Operations (Debugging Hints):**

To understand how a user might reach this test code, I considered the broader context of Frida development. A developer working on the "rewrite" feature of the Frida build system would likely run these tests to ensure their changes are correct. The steps involved would include modifying the relevant code, then executing the unit tests (likely using a command-line tool like `pytest`).

**10. Refining and Structuring the Explanation:**

Finally, I organized my observations and examples into a structured explanation, addressing each point in the original request. I used clear headings and bullet points to improve readability and ensure all aspects were covered. I also tried to use precise language and avoid jargon where possible, while still being technically accurate. I paid attention to the phrasing "if it relates to..." and provided examples specifically where those connections existed.

Essentially, the process involved:  understanding the code's purpose, dissecting its components, inferring functionality from the tests, connecting the functionality to the broader context of Frida and reverse engineering, considering potential errors and debugging scenarios, and finally, structuring the findings clearly and comprehensively.
这个Python源代码文件 `rewritetests.py` 是 Frida 动态 instrumentation 工具中 `frida-qml` 子项目的一部分，专门用于测试 Meson 构建系统中“重写” (rewrite) 功能的单元测试。更具体地说，它测试了修改已构建项目的元数据信息的能力。

以下是它的主要功能：

1. **测试 Meson 构建信息的获取:** 它能够加载已构建的 Meson 项目的构建信息 (通常存储在 `meson-info` 目录下的 JSON 文件中)，并验证这些信息是否可以被正确解析和访问。
2. **测试 Meson 构建信息的修改:**  该文件中的测试用例模拟了对已构建项目的各种元数据进行修改的操作，例如：
    * **添加、删除和列出目标 (targets) 的源文件 (source files)。**
    * **添加、删除目标。**
    * **修改目标的额外文件 (extra files)。**
    * **修改项目、目标和依赖项的关键字参数 (kwargs)。** 这包括设置、添加、删除和删除特定属性，例如版本号、编译选项、依赖项等。
    * **修改项目的默认选项 (default options)。**
3. **验证修改操作的正确性:**  每个测试用例在执行修改操作后，会重新读取构建信息，并将实际结果与预期结果进行比较，以确保修改操作按预期工作。
4. **提供详细的测试输出:** 如果测试失败，它会打印标准输出和标准错误，帮助开发人员诊断问题。
5. **支持跳过测试:** 允许项目请求跳过某些测试用例。
6. **测试 RawPrinter 的幂等性:**  `test_raw_printer_is_idempotent`  测试确保 `RawPrinter` 类（用于将 AST 转换为文本）多次运行的结果相同，这对于确保代码生成的稳定性很重要。

**与逆向方法的关系及举例说明:**

虽然这个测试文件本身不是直接的逆向工具，但它测试的功能与逆向过程中的一些场景相关：

* **修改构建配置以插入代码或 hook 点:** 在逆向工程中，有时需要在目标程序中插入自定义代码或 hook 点来监控其行为。为了实现这一点，可能需要在构建过程中添加额外的源文件或修改编译选项。这个测试文件验证了修改构建信息以实现类似目的的能力。
    * **举例:** 假设你正在逆向一个 Android 应用，并想在特定的 Java 方法被调用时执行一些 Frida 脚本。你可以修改应用的构建脚本，添加一个包含 Frida Native 桥接代码的源文件，或者修改编译选项以包含必要的链接库。这个测试文件中的 `test_target_add_sources` 就模拟了向目标添加源文件的过程。
* **检查目标文件的编译方式:** 逆向工程师可能需要了解目标程序是如何编译的，例如使用了哪些源文件、链接了哪些库、设置了哪些编译选项。这个测试文件中的 `test_target_source_list` 和 `test_kwargs_info` 模拟了获取这些构建信息的过程。
    * **举例:** 通过查看构建信息，逆向工程师可以确定某个动态链接库是否被包含在最终的可执行文件中，或者某个特定的编译宏是否被定义。这有助于理解程序的行为和依赖关系。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个测试文件是用 Python 编写的，并且操作的是 Meson 构建信息，但它所测试的功能最终会影响到二进制文件的生成和运行，因此间接地涉及到一些底层知识：

* **二进制文件的结构和链接:** 修改源文件和链接库会直接影响生成的可执行文件或库的二进制结构。例如，添加源文件会导致更多的代码被编译和链接到最终的二进制文件中。
    * **举例:** `test_target_add_sources` 测试向目标添加源文件，这最终会反映在生成的可执行文件中，例如代码段 (text section) 的大小会增加，并且新增代码的符号会被添加到符号表中。
* **编译选项和 ABI (Application Binary Interface):** 修改编译选项，例如优化级别或目标架构，会影响生成的二进制代码的性能和兼容性。
    * **举例:**  `test_kwargs_set` 中修改 `build_rpath` 可能会影响程序运行时如何查找动态链接库，这与 Linux 的动态链接器的工作方式有关。
* **Android 框架和构建系统:** 在 Android 开发中，修改构建信息可以影响 APK 文件的生成，例如添加 Native 代码、修改 Manifest 文件中的属性等。
    * **举例:** 虽然这个测试是通用的 Meson 测试，但 `frida-qml` 可以用于构建与 Android 相关的工具。因此，理解如何修改构建信息对于在 Android 环境中使用 Frida 是有帮助的。例如，在逆向 Android 应用时，可能需要修改应用的构建信息来包含 Frida Agent。
* **Linux 进程和库加载:**  `build_rpath` 等编译选项直接影响 Linux 系统如何加载和管理动态链接库。

**逻辑推理及假设输入与输出:**

测试用例通过预定义的 JSON 文件 (例如 `addSrc.json`, `rmTgt.json`) 来指定修改操作。这些 JSON 文件可以被视为假设的输入，而测试用例会验证执行这些操作后构建信息的输出是否符合预期。

* **假设输入 (addSrc.json):**
  ```json
  [
    {"type": "target", "target": "trivialprog0", "operation": "src_add", "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]},
    {"type": "target", "target": "trivialprog0", "operation": "src_add", "sources": ["a7.cpp"]},
    {"type": "target", "target": "trivialprog1", "operation": "src_add", "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]},
    {"type": "target", "target": "trivialprog3", "operation": "src_add", "sources": ["a5.cpp"]},
    {"type": "target", "target": "trivialprog4", "operation": "src_add", "sources": ["a5.cpp"]},
    {"type": "target", "target": "trivialprog5", "operation": "src_add", "sources": ["a3.cpp", "a7.cpp"]},
    {"type": "target", "target": "trivialprog6", "operation": "src_add", "sources": ["a4.cpp"]},
    {"type": "target", "target": "trivialprog7", "operation": "src_add", "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]},
    {"type": "target", "target": "trivialprog8", "operation": "src_add", "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]},
    {"type": "target", "target": "trivialprog9", "operation": "src_add", "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]}
  ]
  ```
* **假设输出 (部分 `test_target_add_sources` 的预期结果):**  在 `trivialprog0` 目标的 `sources` 列表中会添加 `a1.cpp`, `a2.cpp`, `a6.cpp`, `a7.cpp` 等文件。

**涉及用户或编程常见的使用错误及举例说明:**

测试用例也间接地反映了用户在操作构建系统时可能犯的错误：

* **指定不存在的目标名称:** 如果在 JSON 文件中指定了一个不存在的目标名称，重写操作可能会失败或产生意想不到的结果。
    * **举例:**  如果在 `addSrc.json` 中将 `target` 设置为 "nonexistent_program"，则 `rewrite` 函数可能会报错，或者修改操作不会生效。
* **提供错误的文件路径:**  如果提供的源文件路径不存在，重写操作可能会失败。
    * **举例:** 如果在 `addSrc.json` 中提供的 `sources` 列表中包含一个不存在的文件 "missing_file.cpp"，则 `rewrite` 函数可能会报错。
* **JSON 格式错误:** 如果提供的 JSON 文件格式不正确，例如缺少逗号或引号，`json.loads` 函数会抛出异常。
* **对关键字参数的错误操作:** 尝试设置一个不存在的关键字参数或使用错误的数据类型可能会导致错误。
    * **举例:**  如果在 `set.json` 中尝试将一个需要布尔值的关键字参数设置为字符串，则重写操作可能会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

这个测试文件是在 Frida 开发过程中被使用的，用户（通常是 Frida 的开发人员或贡献者）在修改 Frida 的构建系统相关代码时，会运行这些单元测试来验证他们的修改是否正确，并没有引入错误。以下是可能的步骤：

1. **修改 Frida 构建系统的代码:** 开发人员可能正在修改 `frida-qml` 中与构建信息重写功能相关的代码。
2. **运行单元测试:** 为了确保修改的正确性，开发人员会运行 `rewritetests.py` 这个单元测试文件。这通常通过一个测试运行器来完成，例如 `pytest`。
   ```bash
   pytest frida/subprojects/frida-qml/releng/meson/unittests/rewritetests.py
   ```
3. **测试框架执行测试用例:**  `pytest` 会自动发现并执行 `RewriterTests` 类中以 `test_` 开头的方法。
4. **`setUp` 方法执行:** 在每个测试用例运行之前，`setUp` 方法会被调用，用于初始化测试环境，例如创建临时构建目录和复制测试文件。
5. **`prime` 方法执行:**  `prime` 方法用于准备特定的测试场景，例如复制特定的测试项目到构建目录。
6. **`rewrite` 或 `rewrite_raw` 方法执行:**  测试用例会调用 `rewrite` 或 `rewrite_raw` 方法，模拟执行构建信息重写操作。这会调用底层的 Frida 工具或脚本来完成实际的修改。
7. **断言 (assert) 检查:**  测试用例会使用 `assertDictEqual` 等断言方法来比较实际的构建信息与预期结果。如果断言失败，则表明重写功能存在问题。
8. **查看输出 (STDOUT/STDERR):** 如果测试失败，开发人员会查看 `rewrite_raw` 方法打印的 `STDOUT` 和 `STDERR`，以获取更详细的错误信息，例如底层命令的输出或错误消息。

作为调试线索，如果测试失败，开发人员可以：

* **检查测试用例的 JSON 输入文件:** 确认 JSON 文件的内容是否符合预期，例如目标名称、文件路径是否正确。
* **查看 `rewrite_raw` 的输出:** 分析底层命令的输出，了解是否是底层工具执行失败。
* **使用 `print` 语句进行调试:** 在测试代码中添加 `print` 语句，输出中间变量的值，帮助理解代码的执行流程。
* **逐步调试代码:** 使用 Python 调试器 (例如 `pdb`) 逐步执行测试代码，查看变量的值和程序的状态。

总而言之，`rewritetests.py` 是 Frida 项目中一个关键的单元测试文件，它确保了修改 Meson 构建信息的功能能够正常工作，这对于 Frida 的一些高级特性和用户自定义构建流程至关重要，并且与逆向工程中的一些场景存在间接的联系。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/rewritetests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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