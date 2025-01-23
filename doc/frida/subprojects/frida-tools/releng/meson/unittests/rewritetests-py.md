Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

1. **Understand the Core Purpose:** The file is located within `frida/subprojects/frida-tools/releng/meson/unittests/`. The name `rewritetests.py` strongly suggests it's a test suite for a code rewriting tool, likely within the Frida ecosystem. The `meson` part indicates the tool probably interacts with Meson build files.

2. **Identify Key Classes and Methods:**  The code defines a single test class, `RewriterTests`, inheriting from `BasePlatformTests`. This immediately tells us it's a unit test setup. Within the class, several methods stand out: `setUp`, `prime`, `rewrite_raw`, `rewrite`, and numerous methods starting with `test_`. The `test_` prefixed methods are clearly individual test cases.

3. **Analyze `setUp` and `prime`:**
    * `setUp`:  Standard unittest setup, likely initializes some common resources. The `self.maxDiff = None` is a hint that tests might compare large text outputs.
    * `prime`: This method takes a directory name, and seems to copy the contents of a test case directory into the build directory (`self.builddir`). This suggests that each test case operates on a fresh, isolated project.

4. **Deconstruct `rewrite_raw` and `rewrite`:** These are the core functions being tested.
    * `rewrite_raw`:
        * It takes a `directory` and `args`.
        * It constructs a command using `self.rewrite_command` (not defined in this snippet but assumed to be the actual rewriting tool executable).
        * It executes the command using `subprocess.run`, capturing output (stdout and stderr).
        * It handles potential `unittest.SkipTest` exceptions.
        * It raises an error if the command fails (non-zero return code).
        * Crucially, it parses the stderr as JSON if it's not empty. This is a significant clue: the rewriting tool likely outputs its results or information via stderr in JSON format.
    * `rewrite`: This is a helper that calls `rewrite_raw` with a fixed initial argument "command". This suggests the rewriting tool has a "command" subcommand or mode.

5. **Examine the `test_` methods:** These are the individual test cases, and their names give clues about what aspects of the rewriting tool they are testing:
    * `test_target_source_list`:  Getting the list of source files for targets.
    * `test_target_add_sources`: Adding source files to targets.
    * `test_target_remove_sources`: Removing source files from targets.
    * `test_target_subdir`: Handling targets in subdirectories.
    * `test_target_remove`, `test_target_add`:  Removing and adding entire targets.
    * `test_kwargs_info`, `test_kwargs_set`, `test_kwargs_add`, `test_kwargs_remove`, `test_kwargs_delete`: Interacting with keyword arguments (likely in the Meson build file).
    * `test_default_options_*`:  Modifying default project options.
    * `test_target_add_extra_files`, `test_target_remove_extra_files`: Handling extra files associated with targets.
    * `test_raw_printer_is_idempotent`:  Testing a `RawPrinter` which is related to the Abstract Syntax Tree (AST) of Meson files. "Idempotent" means applying it multiple times has the same effect as applying it once.

6. **Infer the Rewriting Tool's Functionality:** Based on the test cases, we can deduce the rewriting tool can:
    * Inspect and modify target properties (sources, names, extra files).
    * Add and remove entire targets.
    * Inspect and modify keyword arguments in Meson project definitions, targets, and dependencies.
    * Modify default project options.

7. **Connect to Reverse Engineering:** The ability to modify target source lists, add/remove targets, and manipulate build options directly relates to reverse engineering. By changing the build process, you can inject code, disable features, or alter the final binary to facilitate analysis or modification.

8. **Identify Low-Level Connections:** The interaction with Meson build files directly relates to the build process, which eventually produces binary executables. Understanding how targets are linked, what source files are included, and the impact of build options requires knowledge of compilation, linking, and binary formats. The mentioning of Linux and Android kernels/frameworks in the desired explanation prompts looking for any clues, though this specific code snippet doesn't directly manipulate kernel code. However, the *purpose* of Frida, the broader project, *is* deeply involved in dynamic instrumentation and interacting with running processes, which definitely ties into those low-level areas.

9. **Consider User Errors and Debugging:**  The test setup itself provides debugging hints (isolated test cases, captured output). User errors might involve incorrect JSON input, specifying non-existent targets, or providing invalid file paths.

10. **Address Logical Reasoning (Hypothetical Inputs/Outputs):** For each test case, we can infer the input (the JSON file being processed by `rewrite`) and the expected output (the JSON returned by `rewrite`, which is then asserted against an expected dictionary). The examples in the explanation are derived from these test cases.

11. **Structure the Explanation:**  Organize the findings into logical sections (functionality, reverse engineering, low-level aspects, logical reasoning, user errors, debugging). Provide concrete examples from the code to illustrate each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this just about modifying text files?  **Correction:** The JSON parsing of stderr indicates it's more structured than simple text manipulation. It's interacting with the underlying Meson build system's data model.
* **Focus too narrowly on the code:**  **Correction:** Remember the context – Frida. Even if this specific file doesn't show kernel interaction, the tool it's testing likely does.
* **Missing the user flow:** **Correction:**  Consider how a user would actually trigger this – they wouldn't directly run this test file. They would use the Frida tools, which internally might use the functionality being tested here. The debugging section addresses this.

By following these steps, combining code analysis with understanding the project's broader goals, a comprehensive explanation can be constructed.
这个Python源代码文件 `rewritetests.py` 是 Frida 动态 instrumentation 工具的一个单元测试文件。它的主要功能是测试 Frida 工具集中的一个代码重写工具（`rewrite_command`）。这个重写工具能够读取并修改使用 Meson 构建系统构建的项目信息，特别是关于目标（targets）的源代码列表、依赖关系和构建选项等。

以下是它的功能列表，并根据你的要求进行了详细的解释和举例：

**1. 核心功能：测试 Meson 构建信息的修改能力**

   - **读取目标源代码列表 (`test_target_source_list`)**:  测试重写工具能否正确读取 Meson 构建文件中定义的各个目标（例如可执行文件、库文件）的源代码文件列表。
      - **逆向关系**: 在逆向工程中，了解目标由哪些源代码文件组成是理解程序结构和功能的第一步。这个测试确保 Frida 工具能够准确获取这些信息，为后续的动态修改和分析提供基础。
      - **假设输入与输出**: 假设 `self.builddir` 下的 `info.json` 文件包含了从 Meson 构建系统中导出的目标信息，其中定义了 `trivialprog0@exe` 目标及其源代码列表 `['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp']`。`test_target_source_list` 会调用重写工具，预期输出的 JSON 数据中 `trivialprog0@exe` 的 `sources` 字段与上述列表一致。

   - **添加目标源代码 (`test_target_add_sources`, `test_target_add_sources_abs`)**: 测试重写工具能否向现有目标的源代码列表中添加新的源代码文件。
      - **逆向关系**: 在逆向过程中，有时需要在目标程序中注入自定义代码。通过修改目标的源代码列表，可以将恶意代码或 hook 代码添加到编译过程中。
      - **二进制底层**:  添加源代码最终会影响到链接过程，产生包含新代码的二进制文件。
      - **假设输入与输出**:  假设 `addSrc.json` 指示向 `trivialprog0@exe` 添加 `a1.cpp`, `a2.cpp` 等文件。测试会调用重写工具，然后再次读取目标信息，预期 `trivialprog0@exe` 的 `sources` 字段会包含新增的文件。

   - **移除目标源代码 (`test_target_remove_sources`)**: 测试重写工具能否从目标的源代码列表中移除已有的源代码文件。
      - **逆向关系**:  在分析特定功能时，可能需要排除某些源代码文件的影响。通过移除源代码，可以简化编译过程，专注于分析特定模块。
      - **假设输入与输出**:  假设 `rmSrc.json` 指示从 `trivialprog0@exe` 移除 `fileA.cpp` 和 `fileB.cpp`。测试会调用重写工具，然后读取目标信息，预期 `trivialprog0@exe` 的 `sources` 字段不再包含被移除的文件。

   - **添加和移除整个目标 (`test_target_add`, `test_target_remove`)**: 测试重写工具能否在 Meson 构建信息中添加或删除整个目标定义。
      - **逆向关系**: 在某些场景下，可能需要禁用或替换整个目标模块。例如，禁用某个安全检查模块或者替换掉原有的功能实现。
      - **假设输入与输出**:
         - `test_target_add`:  `addTgt.json` 定义了一个新的目标 `trivialprog10@sha`。测试预期在执行重写后，读取到的目标信息中会包含这个新的目标。
         - `test_target_remove`: `rmTgt.json` 指示移除 `trivialprog0@exe` 和 `trivialprog1@exe`。测试预期在执行重写后，读取到的目标信息中不再包含这两个目标。

   - **处理子目录中的目标 (`test_target_subdir`, `test_target_remove_subdir`, `test_target_add_subdir`)**:  测试重写工具是否能正确处理位于子目录中的目标。
      - **Linux**: 在 Linux 环境下，项目通常使用目录结构来组织源代码。理解如何处理子目录中的目标对于 Frida 在实际项目中的应用至关重要。

   - **处理同名目标 (`test_target_same_name_skip`)**:  测试当存在多个同名目标时，重写工具的行为（通常会跳过或以某种方式区分）。

   - **修改目标的额外文件 (`test_target_add_extra_files`, `test_target_remove_extra_files`)**: 测试重写工具能否添加或移除与目标关联的额外文件（例如头文件、资源文件）。
      - **逆向关系**:  有时需要在目标编译时包含或排除特定的头文件或资源文件。
      - **假设输入与输出**: 类似于添加/移除源代码，只是操作的是 `extra_files` 字段。

**2. 修改 Meson 构建选项 (Keywords Arguments - `kwargs`)**

   - **读取构建选项 (`test_kwargs_info`)**: 测试重写工具能否读取 Meson 构建文件中定义的关键字参数，例如项目版本、目标构建选项、依赖项的配置等。
   - **设置、添加、移除和删除构建选项 (`test_kwargs_set`, `test_kwargs_add`, `test_kwargs_remove`, `test_kwargs_delete`, `test_kwargs_remove_regex`)**: 测试重写工具能否修改、添加、删除 Meson 构建文件中的关键字参数。
      - **逆向关系**:  修改构建选项可以影响最终二进制文件的编译方式和功能。例如，可以禁用优化、启用调试信息、修改库的链接方式等。
      - **假设输入与输出**:
         - `test_kwargs_set`: `set.json` 指示修改项目版本、目标构建选项和依赖项的 `required` 属性。测试预期在执行重写后，读取到的 `kwargs` 信息会反映这些修改。
         - `test_kwargs_add`: `add.json` 指示向项目许可证列表中添加新的许可证。
         - `test_kwargs_remove`: `remove.json` 指示从项目许可证列表中移除特定的许可证。
         - `test_kwargs_delete`: `delete.json` 指示删除特定模块的所有关键字参数。
         - `test_kwargs_remove_regex`: `remove_regex.json` 指示使用正则表达式移除匹配的关键字参数。

   - **修改默认选项 (`test_default_options_set`, `test_default_options_delete`)**: 测试重写工具能否修改 Meson 项目的默认选项。
      - **逆向关系**:  修改默认选项会影响所有目标的构建方式，可以批量修改编译配置。
      - **假设输入与输出**: `defopts_set.json` 和 `defopts_delete.json` 分别指示设置和删除默认选项。

**3. 其他功能**

   - **源代码排序测试 (`test_target_source_sorting`)**: 测试重写工具在添加源代码时是否会进行排序，以及排序的逻辑是否正确。这通常是为了保持构建文件的一致性。
   - **测试 `RawPrinter` 的幂等性 (`test_raw_printer_is_idempotent`)**:  测试 Meson AST (抽象语法树) 的打印功能是否是幂等的，即多次打印结果相同。这与重写工具内部如何处理和表示 Meson 构建文件有关。

**与逆向方法的关联举例说明:**

1. **动态注入代码**: 通过 `test_target_add_sources` 测试的功能，逆向工程师可以修改 Meson 构建文件，将包含 hook 代码的源文件添加到目标程序的编译列表中。当重新编译后，目标程序在运行时就会加载并执行这些 hook 代码，从而实现动态分析和修改。

2. **禁用安全特性**: 某些程序会使用编译选项来启用安全特性（例如地址空间布局随机化 ASLR、栈保护 Canary 等）。通过 `test_kwargs_set` 或 `test_default_options_set` 测试的功能，可以修改 Meson 构建文件，禁用这些安全选项，使得逆向分析更加容易。

3. **修改库的链接方式**:  通过修改 Meson 构建文件中关于依赖项的配置，可以改变目标程序链接的库。例如，可以将动态链接改为静态链接，或者替换成自定义的库版本，用于分析程序对特定库的依赖和调用行为。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

1. **二进制文件结构**: 修改源代码列表和构建选项最终会影响到生成的二进制文件的结构，例如代码段、数据段的布局，以及符号表的生成。理解这些底层知识有助于逆向工程师分析修改后的二进制文件。

2. **链接器行为**:  添加或移除源代码会直接影响链接器的行为。理解链接过程，例如符号解析、重定位等，有助于理解修改构建信息对最终可执行文件的影响。

3. **Linux 共享库 (`.so`)**: 在 Linux 环境下，很多程序依赖共享库。通过修改 Meson 构建文件，可以控制目标程序依赖哪些共享库以及如何加载这些库，这涉及到对 Linux 动态链接机制的理解。

4. **Android Framework**: 虽然这个测试文件本身不直接操作 Android 内核或框架，但 Frida 的主要应用场景之一就是 Android 平台的动态 instrumentation。理解 Android Framework 的构建过程 (通常也使用类似的构建系统) 以及系统服务的加载方式，可以帮助逆向工程师利用 Frida 修改系统服务的构建配置，例如添加额外的权限或修改启动参数。

**逻辑推理的假设输入与输出举例:**

以 `test_target_add_sources` 为例：

- **假设输入**:
    - 当前 `self.builddir` 下的 `meson.build` 文件定义了 `trivialprog0` 目标，其源代码为 `['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp']`。
    - `addSrc.json` 文件的内容为：
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
- **预期输出**:  在执行 `self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))` 后，再次读取 `trivialprog0` 的源代码列表时，应该变为 `['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp', 'a1.cpp', 'a2.cpp']` (顺序可能不同，但包含所有文件)。

**用户或编程常见的使用错误举例说明:**

1. **JSON 格式错误**: 用户提供的 `addSrc.json` 等控制文件如果包含语法错误（例如缺少逗号、引号不匹配），重写工具可能无法解析，导致操作失败。

2. **目标名称错误**:  在 JSON 文件中指定了不存在的目标名称（例如拼写错误），重写工具将无法找到对应的目标进行修改。

3. **文件路径错误**:  在添加源代码时，如果提供的文件路径不存在或不正确，重写工具可能无法添加成功。

4. **操作类型错误**:  在 JSON 文件中指定了不支持的操作类型（例如 "src_removee" 而不是 "src_remove"），重写工具会报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要修改 Frida 工具的行为或添加新的测试用例。**
2. **用户克隆了 Frida 的源代码仓库。**
3. **用户导航到 `frida/subprojects/frida-tools/releng/meson/unittests/` 目录。**
4. **用户查看或修改 `rewritetests.py` 文件。**
5. **用户可能需要运行这些测试用例来验证其修改是否正确。** 这通常涉及到在 Frida 的构建环境中执行特定的命令，例如 `meson test -C builddir` 或者运行特定的测试套件。
6. **如果测试失败，用户会查看测试输出（包括 `STDOUT` 和 `STDERR`）来定位问题。** `rewritetests.py` 中的 `print(p.stdout)` 和 `print(p.stderr)` 就是为了方便用户调试而输出重写工具的执行结果。
7. **用户可能会修改测试用例的输入 JSON 文件 (`addSrc.json`, `rmSrc.json` 等) 或者修改 `rewritetests.py` 中的断言来适应其测试需求。**
8. **用户也可能需要修改被测试的 Meson 项目 (`self.prime` 方法加载的项目) 来创建不同的测试场景。**

总而言之，`rewritetests.py` 是 Frida 工具链中用于测试 Meson 构建信息修改功能的关键组件。它通过模拟各种修改操作，确保 Frida 能够可靠地与使用 Meson 构建的项目进行交互，这对于 Frida 的动态 instrumentation 功能至关重要，尤其在逆向工程和安全分析领域。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/rewritetests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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