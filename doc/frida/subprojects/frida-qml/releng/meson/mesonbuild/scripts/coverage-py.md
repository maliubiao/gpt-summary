Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Core Purpose:** The file name `coverage.py` and the presence of tools like `gcovr` and `lcov` immediately suggest this script is about generating code coverage reports. The comment at the top reinforces this.

2. **Identify Key Inputs:**  The `coverage` function signature is the first place to look for inputs: `outputs`, `source_root`, `subproject_root`, `build_root`, `log_dir`, `use_llvm_cov`, `gcovr_exe`, `llvm_cov_exe`. The `run` function and `argparse` further define how these inputs are provided (command-line arguments).

3. **Trace the Execution Flow:** Start from the `run` function (the entry point). It parses command-line arguments and calls the `coverage` function. The `coverage` function then has several conditional blocks based on the desired output format (`xml`, `sonarqube`, `text`, `html`).

4. **Identify External Tools:** The script heavily relies on external tools: `gcovr`, `lcov`, `genhtml`, and optionally `llvm-cov`. Understanding the purpose of these tools is crucial:
    * `gcovr`:  Generates code coverage reports in various formats (XML, text, HTML) from `gcov` data.
    * `lcov`: Captures and manipulates `gcov` coverage data.
    * `genhtml`: Generates HTML reports from `lcov` data.
    * `llvm-cov`:  A coverage tool in the LLVM project, potentially used as an alternative to `gcov`.

5. **Analyze Conditional Logic:** The `if` statements throughout the `coverage` function are important. They determine which tools are used and how they are invoked, based on:
    * Requested output formats (`outputs`).
    * Availability of tools (`gcovr_exe`, `lcov_exe`, `genhtml_exe`).
    * Versions of the tools.
    * The `--use-llvm-cov` flag.

6. **Focus on Key Actions:** Within each conditional block, identify the core actions:
    * **Detection:**  Using `environment.detect_gcovr`, `environment.detect_lcov_genhtml`, and `mesonlib.exe_exists` to find the tools.
    * **Configuration:** Handling configuration files (`.lcovrc`, `gcovr.cfg`).
    * **Execution:** Using `subprocess.check_call` to run the external tools with appropriate arguments.
    * **Output File Handling:** Creating and naming output files in the `log_dir`.

7. **Connect to Reverse Engineering (if applicable):**  Think about how code coverage is relevant to reverse engineering. Coverage reports can show which parts of the code were executed during testing. This information is invaluable for understanding the functionality of a binary without having the source code. Areas with low coverage might indicate less frequently used or less understood parts of the code.

8. **Consider Binary/Kernel/Framework Aspects:** If `llvm-cov` is used, it interacts directly with compiled binaries. `gcov` (and thus `gcovr` and `lcov`) also work at the binary level, instrumenting code to track execution. While the script itself doesn't directly interact with the *kernel*, the code being analyzed *might*. On Android, this could involve framework components.

9. **Reason About Inputs and Outputs:** For the logical reasoning part, consider the different scenarios based on command-line arguments. What happens if the user requests XML output? What if they specify a custom `gcovr` path? What if they forget to provide a necessary argument?

10. **Identify Potential User Errors:** Look for situations where the script might fail or produce unexpected results due to incorrect usage. Missing dependencies, incorrect paths, or requesting unsupported output formats are good examples.

11. **Trace User Actions (Debugging):**  Imagine a developer is trying to generate coverage reports. How do they end up running this script? They would likely be using a build system (like Meson) that invokes this script as part of a coverage generation target. Understanding this context is important for debugging.

12. **Structure the Analysis:** Organize the findings into logical sections (functionality, relation to reverse engineering, binary/kernel aspects, logical reasoning, user errors, debugging). Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This script just runs `gcovr`."  **Correction:** Realized it also supports `lcov/genhtml` and `llvm-cov`, making it more flexible.
* **Initial thought:** "The subproject root is always excluded." **Correction:** Saw the logic related to `gcovr.cfg` which allows the project to control filtering, so direct exclusion is conditional.
* **Initial thought:** "The script directly instruments binaries." **Correction:**  It *invokes tools* that do the instrumentation (or rely on already instrumented binaries). The script itself is a build system utility.

By following these steps, including the crucial aspect of critically evaluating initial assumptions and refining understanding, we can arrive at a comprehensive analysis of the provided Python script.
好的，让我们来分析一下 `frida/subprojects/frida-qml/releng/meson/mesonbuild/scripts/coverage.py` 这个 Python 脚本的功能和相关知识点。

**功能概览**

这个脚本的主要功能是生成代码覆盖率报告。它通过调用不同的代码覆盖率工具（`gcovr` 和 `lcov/genhtml`，可选 `llvm-cov`）来收集覆盖率数据并生成不同格式的报告，例如 XML、Sonarqube XML、文本和 HTML。  它被设计为 Meson 构建系统的一部分，用于在构建和测试 Frida 的过程中生成覆盖率信息。

**功能详细分解**

1. **参数解析:** 脚本首先使用 `argparse` 模块解析命令行参数，允许用户指定要生成的报告类型 (`--text`, `--xml`, `--sonarqube`, `--html`)，是否使用 `llvm-cov` (`--use-llvm-cov`)，以及 `gcovr` 和 `llvm-cov` 的可执行文件路径。

2. **工具检测:** 脚本会尝试检测系统上是否安装了所需的覆盖率工具 `gcovr` 和 `lcov/genhtml`。如果指定了 `--use-llvm-cov`，还会检测 `llvm-cov`。

3. **配置加载:** 脚本会检查源代码根目录下是否存在 `.lcovrc` 和 `gcovr.cfg` 配置文件，并加载这些配置来影响覆盖率工具的行为。

4. **覆盖率数据收集和报告生成:**
   - **使用 `gcovr`:** 如果安装了 `gcovr` 并且版本符合要求，脚本会调用 `gcovr` 来生成 XML、Sonarqube XML 和文本格式的覆盖率报告。`gcovr` 能够读取 `gcov` 生成的覆盖率数据。
   - **使用 `lcov/genhtml`:** 如果安装了 `lcov` 和 `genhtml`，脚本会执行以下步骤来生成 HTML 格式的覆盖率报告：
     - 使用 `lcov` 命令初始化和捕获覆盖率数据。
     - 如果使用了 `--use-llvm-cov`，会创建一个小的 shell 脚本或批处理文件作为 `gcov` 的代理，以便 `lcov` 可以调用 `llvm-cov gcov`。
     - 合并初始覆盖率数据和运行时的覆盖率数据。
     - 过滤掉不属于项目源代码的覆盖率数据。
     - 使用 `genhtml` 命令将覆盖率数据转换为 HTML 报告。
   - **使用 `llvm-cov`:** 可以通过 `--use-llvm-cov` 标志来指示使用 `llvm-cov` 代替标准的 `gcov`。 这会影响 `gcovr` 和 `lcov` 的调用方式。

5. **输出文件:** 生成的覆盖率报告会保存在指定的 `log_dir` 目录下，文件名根据报告类型命名（例如 `coverage.xml`, `coverage.txt`, `index.html`）。

6. **错误处理:** 脚本会检查所需的工具是否安装以及版本是否满足要求，并根据情况输出警告信息或退出。

**与逆向方法的关系及举例说明**

代码覆盖率分析是逆向工程中一种非常有用的技术。通过运行目标程序并观察哪些代码被执行，逆向工程师可以更好地理解程序的控制流、功能和内部逻辑。

**举例说明：**

假设你想逆向一个加密算法的实现。你可以通过以下步骤使用覆盖率分析：

1. **准备测试用例：**  构造不同的输入数据，包括正常输入、边界情况输入和恶意输入。
2. **运行程序并收集覆盖率数据：** 使用 Frida 或其他动态分析工具运行目标程序，并在运行过程中使用该脚本生成覆盖率报告。你需要配置 Frida 来执行目标程序并生成 `gcov` 或 LLVM coverage 数据。
3. **分析覆盖率报告：** 查看生成的报告，特别是 HTML 报告。
   - **高覆盖率区域：**  被频繁执行的代码区域很可能包含了加密算法的核心逻辑，例如加密循环、密钥处理等。
   - **低覆盖率区域：**  可能是一些错误处理分支、不常用的功能或者未被你的测试用例覆盖到的代码。这些区域可能包含漏洞或者一些特殊的处理逻辑。
4. **结合反汇编分析：**  将覆盖率信息与反汇编代码结合起来分析。例如，你可以查看高覆盖率区域对应的汇编指令，理解算法的具体实现细节。低覆盖率区域可能需要更仔细地检查，以发现潜在的问题。

**二进制底层、Linux、Android 内核及框架的知识及举例说明**

这个脚本本身是一个高层次的 Python 脚本，主要负责调用底层的覆盖率工具。但是，它所依赖的覆盖率工具以及 Frida 本身都涉及到二进制底层、Linux/Android 内核及框架的知识。

**举例说明：**

* **二进制底层:**
    - `gcov` 和 `llvm-cov` 需要在编译时对二进制代码进行插桩（instrumentation），插入额外的代码来记录代码的执行情况。
    - Frida 作为动态插桩工具，可以直接在运行时修改进程的内存，插入代码来收集覆盖率信息，或者控制程序的执行流程以覆盖更多的代码路径。
* **Linux 内核:**
    - 在 Linux 环境下，`gcov` 通常与 GCC 编译器一起使用，它会生成 `.gcno` 和 `.gcda` 文件，这些文件包含了覆盖率信息。
    - Frida 可以与 Linux 的 `ptrace` 系统调用或其他调试接口交互，来监控和控制目标进程。
* **Android 内核及框架:**
    - 在 Android 上，Frida 可以附加到应用程序进程或系统服务进程，包括使用 Java 或 Native 代码编写的组件。
    - 逆向 Android 应用或框架时，可以使用 Frida 动态地注入代码，调用特定的函数，并使用覆盖率分析来理解代码的执行路径，例如了解一个特定的 API 调用会触发哪些底层的系统调用或框架操作。

**逻辑推理、假设输入与输出**

假设我们有以下输入：

```bash
python coverage.py --html --use-llvm-cov source_root subproject_root build_root log_dir --llvm-cov /usr/bin/llvm-cov
```

**假设输入：**

* `outputs`: `['html']` (用户指定生成 HTML 报告)
* `source_root`:  `/path/to/frida/`
* `subproject_root`: `/path/to/frida/subprojects/frida-qml/`
* `build_root`: `/path/to/frida/build/`
* `log_dir`: `/path/to/frida/build/meson-logs/coverage/`
* `use_llvm_cov`: `True` (用户指定使用 llvm-cov)
* `gcovr_exe`: `None` (如果没有指定，或者系统上没有)
* `llvm_cov_exe`: `/usr/bin/llvm-cov` (用户指定了 llvm-cov 的路径)

**逻辑推理：**

1. 脚本会检测到用户指定了 `--html`，因此会尝试生成 HTML 报告。
2. 脚本检测到 `--use-llvm-cov` 为 True，因此会尝试使用 `llvm-cov`。
3. 脚本会检测 `lcov` 和 `genhtml` 是否可用。假设它们可用。
4. 由于使用了 `llvm-cov`，脚本会创建一个 shim 脚本（例如 `llvm-cov.sh`）来模拟 `gcov` 的接口。
5. 脚本会调用 `lcov` 命令，并使用创建的 shim 脚本作为 `--gcov-tool` 的参数。
6. 脚本会执行一系列 `lcov` 命令来初始化、捕获、合并和过滤覆盖率数据。
7. 脚本会调用 `genhtml` 命令，将处理后的覆盖率数据转换为 HTML 报告。

**预期输出：**

1. 在 `/path/to/frida/build/meson-logs/coverage/coveragereport/` 目录下生成 HTML 格式的覆盖率报告（例如 `index.html`）。
2. 终端输出类似以下信息：
   ```
   Html coverage report can be found at file:///path/to/frida/build/meson-logs/coverage/coveragereport/index.html
   ```

**用户或编程常见的使用错误及举例说明**

1. **缺少依赖工具:** 用户在运行脚本之前没有安装 `gcovr` 或 `lcov/genhtml`，或者没有安装指定版本的工具。
   ```bash
   python coverage.py --html source_root subproject_root build_root log_dir
   ```
   **错误信息:** `Need gcovr or lcov/genhtml to generate any coverage reports`

2. **错误的工具路径:**  用户通过 `--gcovr` 或 `--llvm-cov` 指定了错误的工具路径。
   ```bash
   python coverage.py --html --gcovr /invalid/path/to/gcovr source_root subproject_root build_root log_dir
   ```
   **错误信息:** 可能导致 `subprocess.check_call` 抛出 `FileNotFoundError` 或类似的异常。

3. **未进行代码插桩的构建:**  用户在运行覆盖率脚本之前，没有使用支持覆盖率收集的编译选项（例如 GCC 的 `-coverage` 选项或 LLVM 的 `-fprofile-instr-generate -fcoverage-mapping` 选项）构建 Frida。
   ```bash
   python coverage.py --html source_root subproject_root build_root log_dir
   ```
   **结果：** 即使脚本成功运行，生成的覆盖率报告也会显示非常低的覆盖率，因为没有覆盖率数据可以收集。

4. **权限问题:**  脚本在执行过程中可能没有足够的权限访问构建目录、日志目录或执行覆盖率工具。
   ```bash
   python coverage.py --html source_root subproject_root build_root /protected/log/dir
   ```
   **错误信息:** 可能导致 `OSError: [Errno 13] Permission denied` 等异常。

**用户操作是如何一步步到达这里的，作为调试线索**

通常，用户不会直接调用 `coverage.py` 脚本。这个脚本是 Frida 项目构建系统的一部分，通常通过 Meson 构建系统间接调用。以下是用户操作到达这里的典型步骤：

1. **修改 Frida 代码或配置:** 开发者修改了 Frida 的源代码或构建配置。
2. **执行构建命令:** 开发者在 Frida 的源代码根目录下执行 Meson 构建命令，例如：
   ```bash
   meson setup builddir
   cd builddir
   ninja
   ```
3. **执行测试命令 (包含覆盖率生成):**  开发者可能会执行一个特定的 Ninja 目标来生成覆盖率报告，这通常是在测试运行之后：
   ```bash
   ninja coverage
   ```
   或者，在某些 CI/CD 环境中，覆盖率生成可能会自动作为构建过程的一部分执行。
4. **Meson 构建系统调用 `coverage.py`:** 当执行 `ninja coverage` 时，Meson 会根据 `meson.build` 文件中的定义，调用 `coverage.py` 脚本，并将相关的参数传递给它。这些参数包括源代码根目录、构建目录、日志目录等。

**作为调试线索:**

* 如果覆盖率报告生成失败，开发者应该首先检查执行 `ninja coverage` 命令时是否有错误信息输出。
* 检查 `meson.build` 文件中关于覆盖率目标的定义，确认传递给 `coverage.py` 的参数是否正确。
* 检查日志目录（`log_dir`）下是否有相关的错误日志或中间文件。
* 确认所需的覆盖率工具（`gcovr`, `lcov`, `genhtml`, `llvm-cov`）已正确安装并且在系统的 PATH 环境变量中，或者通过命令行参数指定了正确的路径。
* 确认在构建 Frida 时使用了正确的编译选项来生成覆盖率数据。

总而言之，`coverage.py` 是 Frida 构建系统中一个重要的工具，它利用成熟的覆盖率分析工具链，为开发者提供代码覆盖率信息，这对于代码质量保证、测试和逆向分析都非常有价值。 了解其功能和背后的原理，有助于理解 Frida 的构建过程，并在遇到问题时进行调试。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/scripts/coverage.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 The Meson development team

from __future__ import annotations

from mesonbuild import environment, mesonlib

import argparse, re, sys, os, subprocess, pathlib, stat
import typing as T

def coverage(outputs: T.List[str], source_root: str, subproject_root: str, build_root: str, log_dir: str, use_llvm_cov: bool,
             gcovr_exe: str, llvm_cov_exe: str) -> int:
    outfiles = []
    exitcode = 0

    if gcovr_exe == '':
        gcovr_exe = None
    else:
        gcovr_exe, gcovr_version = environment.detect_gcovr(gcovr_exe)
    if llvm_cov_exe == '' or not mesonlib.exe_exists([llvm_cov_exe, '--version']):
        llvm_cov_exe = None

    lcov_exe, lcov_version, genhtml_exe = environment.detect_lcov_genhtml()

    # load config files for tools if available in the source tree
    # - lcov requires manually specifying a per-project config
    # - gcovr picks up the per-project config, and also supports filtering files
    #   so don't exclude subprojects ourselves, if the project has a config,
    #   because they either don't want that, or should set it themselves
    lcovrc = os.path.join(source_root, '.lcovrc')
    if os.path.exists(lcovrc):
        lcov_config = ['--config-file', lcovrc]
    else:
        lcov_config = []

    if lcov_exe and mesonlib.version_compare(lcov_version, '>=2.0'):
        lcov_exe_rc_branch_coverage = ['--rc', 'branch_coverage=1']
    else:
        lcov_exe_rc_branch_coverage = ['--rc', 'lcov_branch_coverage=1']

    gcovr_config = ['-e', re.escape(subproject_root)]

    # gcovr >= 4.2 requires a different syntax for out of source builds
    if gcovr_exe and mesonlib.version_compare(gcovr_version, '>=4.2'):
        gcovr_base_cmd = [gcovr_exe, '-r', source_root, build_root]
        # it also started supporting the config file
        if os.path.exists(os.path.join(source_root, 'gcovr.cfg')):
            gcovr_config = []
    else:
        gcovr_base_cmd = [gcovr_exe, '-r', build_root]

    if use_llvm_cov:
        gcov_exe_args = ['--gcov-executable', llvm_cov_exe + ' gcov']
    else:
        gcov_exe_args = []

    if not outputs or 'xml' in outputs:
        if gcovr_exe and mesonlib.version_compare(gcovr_version, '>=3.3'):
            subprocess.check_call(gcovr_base_cmd + gcovr_config +
                                  ['-x',
                                   '-o', os.path.join(log_dir, 'coverage.xml')
                                   ] + gcov_exe_args)
            outfiles.append(('Xml', pathlib.Path(log_dir, 'coverage.xml')))
        elif outputs:
            print('gcovr >= 3.3 needed to generate Xml coverage report')
            exitcode = 1

    if not outputs or 'sonarqube' in outputs:
        if gcovr_exe and mesonlib.version_compare(gcovr_version, '>=4.2'):
            subprocess.check_call(gcovr_base_cmd + gcovr_config +
                                  ['--sonarqube',
                                   '-o', os.path.join(log_dir, 'sonarqube.xml'),
                                   ] + gcov_exe_args)
            outfiles.append(('Sonarqube', pathlib.Path(log_dir, 'sonarqube.xml')))
        elif outputs:
            print('gcovr >= 4.2 needed to generate Xml coverage report')
            exitcode = 1

    if not outputs or 'text' in outputs:
        if gcovr_exe and mesonlib.version_compare(gcovr_version, '>=3.3'):
            subprocess.check_call(gcovr_base_cmd + gcovr_config +
                                  ['-o', os.path.join(log_dir, 'coverage.txt')] +
                                  gcov_exe_args)
            outfiles.append(('Text', pathlib.Path(log_dir, 'coverage.txt')))
        elif outputs:
            print('gcovr >= 3.3 needed to generate text coverage report')
            exitcode = 1

    if not outputs or 'html' in outputs:
        if lcov_exe and genhtml_exe:
            htmloutdir = os.path.join(log_dir, 'coveragereport')
            covinfo = os.path.join(log_dir, 'coverage.info')
            initial_tracefile = covinfo + '.initial'
            run_tracefile = covinfo + '.run'
            raw_tracefile = covinfo + '.raw'
            lcov_subpoject_exclude = []
            if os.path.exists(subproject_root):
                lcov_subpoject_exclude.append(os.path.join(subproject_root, '*'))
            if use_llvm_cov:
                # Create a shim to allow using llvm-cov as a gcov tool.
                if mesonlib.is_windows():
                    llvm_cov_shim_path = os.path.join(log_dir, 'llvm-cov.bat')
                    with open(llvm_cov_shim_path, 'w', encoding='utf-8') as llvm_cov_bat:
                        llvm_cov_bat.write(f'@"{llvm_cov_exe}" gcov %*')
                else:
                    llvm_cov_shim_path = os.path.join(log_dir, 'llvm-cov.sh')
                    with open(llvm_cov_shim_path, 'w', encoding='utf-8') as llvm_cov_sh:
                        llvm_cov_sh.write(f'#!/usr/bin/env sh\nexec "{llvm_cov_exe}" gcov $@')
                    os.chmod(llvm_cov_shim_path, os.stat(llvm_cov_shim_path).st_mode | stat.S_IEXEC)
                gcov_tool_args = ['--gcov-tool', llvm_cov_shim_path]
            else:
                gcov_tool_args = []
            subprocess.check_call([lcov_exe,
                                   '--directory', build_root,
                                   '--capture',
                                   '--initial',
                                   '--output-file',
                                   initial_tracefile] +
                                  lcov_config +
                                  gcov_tool_args)
            subprocess.check_call([lcov_exe,
                                   '--directory', build_root,
                                   '--capture',
                                   '--output-file', run_tracefile,
                                   '--no-checksum',
                                   *lcov_exe_rc_branch_coverage] +
                                  lcov_config +
                                  gcov_tool_args)
            # Join initial and test results.
            subprocess.check_call([lcov_exe,
                                   '-a', initial_tracefile,
                                   '-a', run_tracefile,
                                   *lcov_exe_rc_branch_coverage,
                                   '-o', raw_tracefile] + lcov_config)
            # Remove all directories outside the source_root from the covinfo
            subprocess.check_call([lcov_exe,
                                   '--extract', raw_tracefile,
                                   os.path.join(source_root, '*'),
                                   *lcov_exe_rc_branch_coverage,
                                   '--output-file', covinfo] + lcov_config)
            # Remove all directories inside subproject dir
            subprocess.check_call([lcov_exe,
                                   '--remove', covinfo,
                                   *lcov_subpoject_exclude,
                                   *lcov_exe_rc_branch_coverage,
                                   '--ignore-errors', 'unused',
                                   '--output-file', covinfo] + lcov_config)
            subprocess.check_call([genhtml_exe,
                                   '--prefix', build_root,
                                   '--prefix', source_root,
                                   '--output-directory', htmloutdir,
                                   '--title', 'Code coverage',
                                   '--legend',
                                   '--show-details',
                                   '--branch-coverage',
                                   covinfo] + lcov_config)
            outfiles.append(('Html', pathlib.Path(htmloutdir, 'index.html')))
        elif gcovr_exe and mesonlib.version_compare(gcovr_version, '>=3.3'):
            htmloutdir = os.path.join(log_dir, 'coveragereport')
            if not os.path.isdir(htmloutdir):
                os.mkdir(htmloutdir)
            subprocess.check_call(gcovr_base_cmd + gcovr_config +
                                  ['--html',
                                   '--html-details',
                                   '--print-summary',
                                   '-o', os.path.join(htmloutdir, 'index.html'),
                                   ] + gcov_exe_args)
            outfiles.append(('Html', pathlib.Path(htmloutdir, 'index.html')))
        elif outputs:
            print('lcov/genhtml or gcovr >= 3.3 needed to generate Html coverage report')
            exitcode = 1

    if not outputs and not outfiles:
        print('Need gcovr or lcov/genhtml to generate any coverage reports')
        exitcode = 1

    if outfiles:
        print('')
        for (filetype, path) in outfiles:
            print(filetype + ' coverage report can be found at', path.as_uri())

    return exitcode

def run(args: T.List[str]) -> int:
    if not os.path.isfile('build.ninja'):
        print('Coverage currently only works with the Ninja backend.')
        return 1
    parser = argparse.ArgumentParser(description='Generate coverage reports')
    parser.add_argument('--text', dest='outputs', action='append_const',
                        const='text', help='generate Text report')
    parser.add_argument('--xml', dest='outputs', action='append_const',
                        const='xml', help='generate Xml report')
    parser.add_argument('--sonarqube', dest='outputs', action='append_const',
                        const='sonarqube', help='generate Sonarqube Xml report')
    parser.add_argument('--html', dest='outputs', action='append_const',
                        const='html', help='generate Html report')
    parser.add_argument('--use-llvm-cov', action='store_true',
                        help='use llvm-cov')
    parser.add_argument('--gcovr', action='store', default='',
                        help='The gcovr executable to use if specified')
    parser.add_argument('--llvm-cov', action='store', default='',
                        help='The llvm-cov executable to use if specified')
    parser.add_argument('source_root')
    parser.add_argument('subproject_root')
    parser.add_argument('build_root')
    parser.add_argument('log_dir')
    options = parser.parse_args(args)
    return coverage(options.outputs, options.source_root,
                    options.subproject_root, options.build_root,
                    options.log_dir, options.use_llvm_cov,
                    options.gcovr, options.llvm_cov)

if __name__ == '__main__':
    sys.exit(run(sys.argv[1:]))

"""

```