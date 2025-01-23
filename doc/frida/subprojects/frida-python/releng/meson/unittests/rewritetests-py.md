Response:
My thought process for analyzing the Python code and fulfilling the request goes like this:

1. **Understand the Core Purpose:** The filename `rewritetests.py` within the `frida-python` project's `releng/meson/unittests` directory immediately suggests this is a test suite for a code rewriting or modification tool. The presence of "meson" further points to a build system context.

2. **Identify Key Components:** I scan the imports and class definition (`RewriterTests` inheriting from `BasePlatformTests`). The imports reveal dependencies on standard Python libraries (`subprocess`, `itertools`, `json`, `os`, `pathlib`, `shutil`, `unittest`) and Meson-specific modules (`mesonbuild.ast`). The `BasePlatformTests` inheritance implies setup and teardown routines for test environments.

3. **Analyze Key Methods:** I focus on the methods within `RewriterTests`:
    * `setUp`: Standard test setup, likely initializing the build directory.
    * `prime`:  Sets up a test case by copying a specific directory to the build directory. This is crucial for creating isolated test environments.
    * `rewrite_raw`: The core function. It executes a command-line tool (`self.rewrite_command`) with various arguments, captures its output (stdout and stderr), and handles potential errors (like skipping tests). The parsing of stderr as JSON is a strong indicator of how the rewriting tool communicates results.
    * `rewrite`: A simplified wrapper around `rewrite_raw`, prepending "command" to the arguments. This suggests the rewriting tool likely has different subcommands.
    * `test_*`:  These are the individual test methods. Each one focuses on testing a specific rewriting operation or scenario. I pay close attention to the `prime()` calls to see which test directories are being used.

4. **Infer Functionality from Test Cases:**  The names of the test methods and the assertions within them are very informative:
    * `test_target_source_list`: Checks if the tool can extract the source files of build targets.
    * `test_target_add_sources`, `test_target_remove_sources`: Tests adding and removing source files from targets.
    * `test_target_add_sources_abs`: Similar to `test_target_add_sources` but with absolute paths, indicating path handling is tested.
    * `test_target_subdir`, `test_target_remove`, `test_target_add`, `test_target_remove_subdir`, `test_target_add_subdir`: These test scenarios involving subdirectories, indicating the rewriter can operate in more complex project structures.
    * `test_target_source_sorting`: Checks if the rewriter maintains a specific order of source files.
    * `test_target_same_name_skip`: Tests how the rewriter handles targets with the same name.
    * `test_kwargs_*`:  These tests manipulate keyword arguments (kwargs) within the Meson build definition, suggesting the rewriter can modify project-level settings or target/dependency properties.
    * `test_target_add_extra_files`, `test_target_remove_extra_files`: Tests adding and removing "extra files" associated with targets.
    * `test_raw_printer_is_idempotent`: This test is about the `RawPrinter` in Meson, ensuring that printing the AST and then re-parsing it results in the same structure (idempotency). This is related to the integrity of AST manipulation.

5. **Connect to Reverse Engineering:**  Based on the functionality, I consider how this tool could be used in reverse engineering:
    * **Source Code Analysis:** The ability to list target sources is fundamental for understanding the components of a compiled program.
    * **Modification for Instrumentation:** Adding or removing source files allows injecting instrumentation code (like Frida's own agents) or excluding parts of the original code.
    * **Build System Manipulation:** Modifying keywords can change build configurations, potentially enabling debug symbols, disabling optimizations, or linking against specific libraries—all useful for reverse engineering.

6. **Identify Low-Level/Kernel Aspects:** The filename includes "frida," which is a dynamic instrumentation toolkit often used to interact with running processes at a low level. The mentions of "linux" and "android" in the prompt reinforce this connection. While the *test code itself* doesn't directly interact with the kernel, the *tool being tested* likely does. The test suite ensures that the *manipulation of the build system* required for integrating Frida (or similar tools) works correctly.

7. **Look for Logic and Assumptions:** The tests make assumptions about the input JSON files (e.g., `addSrc.json`, `rmTgt.json`). The expected outputs are based on the actions defined in these JSON files. I try to infer the structure of these JSON files from the test cases (though the code doesn't explicitly show their contents).

8. **Consider User Errors:** I think about common mistakes a user might make when using such a tool:
    * Incorrect target names.
    * Specifying non-existent source files.
    * Providing invalid JSON input.
    * Conflicting modifications.

9. **Trace User Steps (Debugging):** I consider how a user might end up needing to examine this test code:
    * **Debugging Frida Integration:** If Frida integration fails, developers might look at the underlying Meson build system and how it's being modified.
    * **Understanding Meson:** Developers new to Meson might explore test cases to understand its features.
    * **Contributing to Frida:** Developers contributing to Frida might need to modify or add new tests.

10. **Structure the Response:** I organize my findings into the requested categories: functionality, relationship to reverse engineering, low-level aspects, logical inference, user errors, and debugging context. I provide concrete examples wherever possible.

By following these steps, I can systematically analyze the provided code and generate a comprehensive response that addresses all aspects of the prompt.
这个Python源代码文件 `rewritetests.py` 是 `frida` 动态 instrumentation 工具中用于测试 Meson 构建系统相关代码重写功能的单元测试文件。它的主要功能是：

**1. 测试 Meson 构建文件的修改能力:**

   - **目标（Target）操作:** 测试添加、删除和修改构建目标（例如可执行文件、库）。
     - 添加新的源文件到目标。
     - 移除目标中的源文件。
     - 添加新的构建目标。
     - 移除已有的构建目标。
     - 添加与目标关联的额外文件（例如头文件）。
     - 移除与目标关联的额外文件。
   - **关键字参数（Keyword Arguments）操作:** 测试修改 Meson 构建函数（例如 `project()`, `executable()`, `dependency()`）的关键字参数。
     - 获取关键字参数信息。
     - 设置关键字参数的值。
     - 添加关键字参数的值（例如列表类型的参数）。
     - 移除关键字参数的值。
     - 使用正则表达式移除关键字参数的值。
     - 删除整个关键字参数。
   - **默认选项（Default Options）操作:** 测试修改 `project()` 函数中的 `default_options`。
     - 设置默认选项。
     - 删除默认选项。

**与逆向方法的关系及举例说明:**

这个测试文件虽然本身不是逆向工具，但它测试的功能是 `frida` 为了实现其动态 instrumentation 能力所必需的。逆向工程师在使用 `frida` 时，可能需要修改目标应用的构建方式或依赖项，以便将 `frida` 的 agent 代码注入到目标进程中。

**举例说明:**

1. **注入 Frida Agent:** 逆向工程师可能需要向目标应用的构建配置中添加 Frida agent 的源文件，以便将其编译到应用中。 `test_target_add_sources` 测试了向目标添加源文件的功能，这可以模拟将 Frida agent 代码添加到目标应用构建的过程。例如，`addSrc.json` 文件可能包含指示向特定目标添加 `frida_agent.cpp` 的指令。

2. **修改依赖关系:** 为了让 Frida agent 能够正常工作，可能需要确保目标应用链接了 Frida 相关的库。 `test_kwargs_set` 测试了修改构建目标关键字参数的功能，可以模拟修改目标依赖项，例如添加 Frida 的库作为依赖。

3. **控制编译选项:**  逆向分析时，可能希望以调试模式编译目标应用，以便更容易进行调试。 `test_default_options_set` 测试了修改默认编译选项的功能，可以模拟设置 `debug=true` 这样的选项。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明:**

虽然这个测试文件本身是用 Python 编写的，没有直接操作二进制或内核，但它测试的 `frida` 代码重写功能是为了服务于动态 instrumentation，这与以下底层知识密切相关：

1. **二进制结构:**  修改构建系统最终会影响生成的可执行文件或库的二进制结构。例如，添加源文件会增加二进制文件的大小，修改链接选项会改变二进制文件的符号表和依赖关系。

2. **Linux/Android 进程模型:** Frida 的动态 instrumentation 依赖于对目标进程内存空间和执行流程的理解。修改构建系统可以帮助在目标进程启动时或运行时注入代码，这需要理解 Linux/Android 的进程加载和执行机制。

3. **Android Framework:** 在 Android 平台上，Frida 可以 hook Java 层和 Native 层的函数。修改 Android 应用的构建配置，例如添加 Native 代码或修改 Manifest 文件，可能会影响 Frida 与 Android Framework 的交互。

**举例说明:**

- **Android Native Hook:**  为了 hook Android 应用的 Native 函数，可能需要修改应用的 `CMakeLists.txt` 或 `build.gradle` 文件，添加 Frida 的 Native 桥接代码。这个测试文件测试的修改目标源文件的功能，可以验证这种修改是否能正确反映到构建系统中。

- **Linux 系统调用 Hook:** Frida 也可以 hook Linux 系统调用。修改构建配置可能会涉及到链接 `libdl` 或其他用于动态链接的库，以便 Frida 能够加载和执行 hook 代码。这个测试文件测试的修改目标依赖的功能，可以验证相关修改的有效性。

**逻辑推理及假设输入与输出:**

大部分测试用例都是基于预定义的 JSON 输入文件，指示要执行的重写操作。测试框架会根据这些输入，调用相应的重写功能，并断言输出结果是否符合预期。

**假设输入与输出 (以 `test_target_add_sources` 为例):**

**假设输入 (`addSrc.json` 的内容，这部分代码没有直接展示，但可以推断):**

```json
[
  {
    "type": "target",
    "target": "trivialprog0",
    "operation": "src_add",
    "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]
  },
  {
    "type": "target",
    "target": "trivialprog0",
    "operation": "src_add",
    "sources": ["a7.cpp"]
  },
  {
    "type": "target",
    "target": "trivialprog1",
    "operation": "src_add",
    "sources": ["a1.cpp", "a2.cpp", "a6.cpp"]
  },
  // ... 其他目标的添加源文件操作
]
```

**预期输出 (从 `test_target_add_sources` 的断言中得出):**

```json
{
    "target": {
        "trivialprog0@exe": {"name": "trivialprog0", "sources": ["a1.cpp", "a2.cpp", "a6.cpp", "fileA.cpp", "main.cpp", "a7.cpp", "fileB.cpp", "fileC.cpp"], "extra_files": []},
        "trivialprog1@exe": {"name": "trivialprog1", "sources": ["a1.cpp", "a2.cpp", "a6.cpp", "fileA.cpp", "main.cpp"], "extra_files": []},
        // ... 其他目标的预期输出
    }
}
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **拼写错误的目标名称:** 用户在 JSON 文件中指定要修改的目标名称时，可能会拼写错误，导致重写操作无法应用到预期的目标上。测试框架可能会抛出异常或返回错误信息。

2. **指定不存在的源文件:**  用户尝试添加一个不存在的源文件到目标时，构建系统可能会报错。测试框架可以验证这种情况下的行为。

3. **JSON 格式错误:**  如果用户提供的 JSON 文件格式不正确（例如缺少逗号、引号不匹配），解析 JSON 时会出错，导致重写操作失败。

4. **尝试删除必要的源文件:** 用户可能不小心删除了构建目标正常工作所必需的源文件，导致编译失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 `frida` 时，发现某个特定的代码重写操作没有按预期工作。为了调试这个问题，用户可能会：

1. **查看 Frida 的文档和示例:** 了解 Frida 提供的代码重写 API 和工具的使用方法。

2. **检查 Frida 的日志输出:** Frida 在执行重写操作时通常会输出日志，用户可以查看日志以获取错误信息。

3. **查看 Meson 的构建日志:**  了解 Meson 是如何处理构建配置的，以及重写操作是否被正确地应用。

4. **阅读 `frida-python` 的源代码:** 为了更深入地理解 Frida 的工作原理，用户可能会查看 `frida-python` 的源代码，特别是与 Meson 构建相关的部分。

5. **定位到 `rewritetests.py`:** 如果怀疑是 Frida 的代码重写功能本身存在问题，或者需要了解 Frida 是如何测试这些功能的，用户可能会找到这个单元测试文件。

6. **分析具体的测试用例:**  用户可以查看与自己遇到的问题相关的测试用例，例如，如果添加源文件失败，可能会查看 `test_target_add_sources`。通过分析测试用例的输入（JSON 文件）和预期输出，用户可以更好地理解 Frida 的重写机制，并找到问题所在。

总而言之，`rewritetests.py` 是 `frida` 项目中一个关键的测试文件，它确保了 Frida 能够可靠地修改 Meson 构建系统的配置，这对于实现其动态 instrumentation 功能至关重要。理解这个文件的功能，可以帮助逆向工程师更好地利用 Frida，并在遇到问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/rewritetests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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