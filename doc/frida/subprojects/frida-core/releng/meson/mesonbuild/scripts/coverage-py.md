Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Skim and Understanding the Purpose:**

The first step is to read the script quickly to get a general idea of its functionality. Keywords like "coverage," "gcovr," "lcov," "llvm-cov," "XML," "HTML," and the function `coverage()` itself strongly suggest that this script is about generating code coverage reports. The path `frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/coverage.py` further reinforces this, placing it within the Frida project's build system setup.

**2. Identifying Key Tools and Libraries:**

The script imports modules like `argparse`, `re`, `sys`, `os`, `subprocess`, `pathlib`, and `stat`. These are standard Python libraries used for argument parsing, regular expressions, system interactions, process execution, and file system operations. More importantly, it mentions external tools: `gcovr`, `lcov`, and `llvm-cov`. Recognizing these tools is crucial. A quick mental note or search confirms they are common code coverage analysis tools.

**3. Deconstructing the `coverage()` Function:**

This is the core of the script. I'd go through it section by section:

* **Initialization:**  Variables are initialized, including checking for the existence of `gcovr` and `llvm-cov`. The detection of `lcov` and `genhtml` is also noted. The script attempts to locate configuration files (`.lcovrc`, `gcovr.cfg`).
* **Output Format Logic (if/elif/else blocks):**  The core logic revolves around generating different coverage report formats (XML, Sonarqube XML, Text, HTML). Each format has associated tool dependencies and conditional execution based on tool versions. This tells me the script is flexible and supports different reporting needs.
* **`gcovr` Integration:**  The script uses `subprocess.check_call()` to execute `gcovr` with various arguments to generate XML, Sonarqube, and text reports. The arguments passed to `gcovr` reveal how it's being used (specifying source and build directories, output files, and excluding subprojects). The version checks are important to note.
* **`lcov` and `genhtml` Integration:** This part handles HTML report generation. It involves a multi-step process: capturing initial data, running tests and capturing more data, merging the data, filtering out irrelevant paths, and finally using `genhtml` to create the HTML report. The creation of a "shim" for `llvm-cov` is a detail worth highlighting.
* **Error Handling and Output:** The script checks if any reports were generated and prints informative messages. It also handles cases where necessary tools are missing or the wrong versions are present.

**4. Analyzing the `run()` Function:**

This function is responsible for parsing command-line arguments using `argparse`. It defines the supported output formats (`--text`, `--xml`, `--sonarqube`, `--html`) and options for specifying the coverage tools (`--use-llvm-cov`, `--gcovr`, `--llvm-cov`). It then calls the `coverage()` function with the parsed arguments.

**5. Connecting to Reverse Engineering and Underlying Technologies:**

Now, the core task is to link the script's functionality to reverse engineering and the underlying technologies.

* **Reverse Engineering Connection:**  The key insight here is that code coverage is invaluable in reverse engineering. When analyzing an unknown binary, running it with coverage enabled reveals which parts of the code are executed under specific conditions. This helps understand the program's behavior and identify key code paths.
* **Binary/Low-Level:**  Coverage tools like `gcov` and `llvm-cov` work at a low level, instrumenting the compiled binary to track which code blocks are executed. This instrumentation adds extra instructions to the binary. The resulting data reflects the execution flow at a very granular level.
* **Linux/Android Kernel/Framework:**  Frida is often used for dynamic analysis on Linux and Android systems. Therefore, the targets for this coverage script are likely binaries running on these platforms. The concepts of code coverage apply equally to user-space applications and kernel modules. Frameworks built on top of these kernels can also be analyzed using this approach.

**6. Constructing Examples and Scenarios:**

To illustrate the script's functionality, I would create scenarios:

* **Basic Usage:**  Show the command to generate a basic HTML report.
* **Tool Selection:** Demonstrate how to specify `llvm-cov` instead of the default `gcov`.
* **Error Scenarios:**  Illustrate what happens if `gcovr` is missing or too old.
* **Debugging Scenario:**  Explain how a reverse engineer might use this script to understand the execution flow of a specific function in a target process.

**7. Detailing User Steps and Debugging:**

To explain how a user might reach this script during debugging, I'd outline the typical Frida development workflow:

* **Project Setup:** Creating a Frida project.
* **Building with Coverage:**  Configuring the build system (likely Meson in this case) to enable coverage.
* **Running Tests:** Executing the test suite.
* **Generating Reports:** Manually invoking this `coverage.py` script to analyze the coverage data.

**8. Refining and Structuring the Output:**

Finally, I'd organize the information logically, using clear headings and bullet points. I'd ensure that the explanations are concise and easy to understand, highlighting the key aspects of the script's functionality and its relevance to reverse engineering and underlying technologies. I would also pay attention to the specific requests in the prompt (listing functions, reverse engineering relevance with examples, low-level details, logic inference, common errors, and debugging).
好的，让我们来分析一下 `frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/coverage.py` 文件的功能。

**功能列表:**

这个 Python 脚本的主要功能是**生成代码覆盖率报告**。它支持多种报告格式，并集成了多个代码覆盖率分析工具，例如 `gcovr` 和 `lcov/genhtml`，还可选地支持 `llvm-cov`。

具体来说，脚本可以：

1. **检测必要的代码覆盖率工具:** 脚本会尝试检测系统上是否安装了 `gcovr`、`lcov` 和 `genhtml`，并可选地检测 `llvm-cov`。
2. **生成不同格式的覆盖率报告:**
   - **XML 报告:** 使用 `gcovr` 生成，用于与其他工具（如 CI 系统）集成。
   - **Sonarqube XML 报告:** 使用 `gcovr` 生成，用于 Sonarqube 代码质量平台。
   - **文本报告:** 使用 `gcovr` 生成，提供控制台输出的覆盖率摘要。
   - **HTML 报告:** 可以使用 `lcov/genhtml` 或 `gcovr` 生成，提供更详细的交互式覆盖率报告，包括源代码行的覆盖信息。
3. **处理源代码和构建目录:** 脚本需要知道源代码根目录、子项目根目录和构建目录，以便找到编译产生的覆盖率数据文件。
4. **使用不同的覆盖率后端:** 脚本允许用户选择使用 `llvm-cov` 作为 `gcov` 的替代品，这在某些情况下可能更准确或提供更好的性能。
5. **过滤子项目:**  脚本会排除子项目目录的覆盖率数据，避免重复计算或干扰主项目的覆盖率分析。
6. **处理配置文件:** 脚本会尝试加载项目根目录下的 `.lcovrc` 和 `gcovr.cfg` 配置文件，以便使用项目特定的覆盖率设置。
7. **为 `llvm-cov` 创建 shim:**  如果使用 `llvm-cov`，脚本会在临时目录创建一个小的 shell 脚本或批处理文件作为 `gcov` 的替代品，因为 `lcov` 期望调用 `gcov`。
8. **合并和清理覆盖率数据:**  在使用 `lcov` 生成 HTML 报告时，脚本会执行多个步骤，包括捕获初始数据、运行测试并捕获数据、合并数据、提取相关数据、移除不需要的数据，最后生成报告。

**与逆向方法的关系及举例说明:**

代码覆盖率在逆向工程中是一个非常有用的工具，可以帮助逆向工程师理解程序的执行路径和代码结构。 `coverage.py` 脚本生成的报告可以为逆向分析提供关键信息。

**举例说明:**

假设你正在逆向一个闭源的 Frida 模块，你想了解当调用某个特定函数时，模块内部哪些代码被执行了。你可以按照以下步骤操作：

1. **编译 Frida 模块并启用代码覆盖率:** 在构建 Frida 时，需要配置编译选项以生成覆盖率数据。这通常需要在 Meson 构建文件中进行配置，启用 `-coverage` 编译标志。
2. **运行 Frida 并调用目标函数:** 使用 Frida 连接到目标进程，并执行会触发你感兴趣的模块函数的代码。
3. **生成覆盖率报告:** 运行 `coverage.py` 脚本，指定正确的源代码根目录、构建目录和日志目录。例如：
   ```bash
   python coverage.py /path/to/frida /path/to/frida/subprojects/frida-core /path/to/frida/build /path/to/frida/build/meson-logs --html
   ```
4. **分析覆盖率报告:** 打开生成的 HTML 报告（在 `coveragereport/index.html`），你可以看到哪些源代码行被执行了，哪些没有。这可以帮助你：
   - **理解函数的功能:** 被覆盖的代码行很可能与该函数的主要逻辑相关。
   - **发现代码分支:** 你可以看到哪些条件分支被执行了，哪些没有，这有助于理解函数的控制流。
   - **识别未执行的代码:** 未覆盖的代码可能包含错误处理逻辑、不常用的功能或死代码。
   - **辅助动态调试:** 覆盖率报告可以指导你设置断点，以便更有效地进行动态调试。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

代码覆盖率工具（如 `gcov` 和 `llvm-cov`）的工作原理是**在编译时对二进制代码进行插桩 (instrumentation)**。这些插桩代码会在程序运行时记录哪些代码块被执行了。

**举例说明:**

1. **二进制底层:**
   - 当使用 GCC 或 Clang 编译并启用覆盖率时，编译器会在每个基本块（一段没有跳转指令的代码）的开始处插入额外的指令。这些指令通常会增加一个计数器，记录该基本块被执行的次数。
   - `gcov` 和 `llvm-cov` 工具会分析这些插桩的二进制文件以及在程序运行期间生成的 `.gcda` (gcov data file) 或 `.profdata` (llvm profile data) 文件，从而生成覆盖率报告。

2. **Linux 内核:**
   - 尽管此脚本主要针对用户空间代码，但代码覆盖率的概念也适用于 Linux 内核模块。可以使用类似的方法对内核模块进行插桩和覆盖率分析，例如使用 `kcov` 工具。
   - 理解内核的执行路径对于逆向分析内核漏洞或理解内核行为至关重要。

3. **Android 框架:**
   - Frida 常用于 Android 平台的动态分析。此脚本生成的覆盖率报告可以帮助理解 Android 框架层代码的执行情况。
   - 例如，你可以分析当调用某个 Android API 时，系统框架内部哪些代码被执行，这有助于理解 API 的实现细节。

**逻辑推理及假设输入与输出:**

脚本中包含一些逻辑推理，主要是基于已安装的工具和其版本来决定生成哪种格式的报告以及如何调用相应的工具。

**假设输入与输出示例:**

**假设输入:**

```python
outputs=['html'],  # 只生成 HTML 报告
source_root='/path/to/frida',
subproject_root='/path/to/frida/subprojects/frida-core',
build_root='/path/to/frida/build',
log_dir='/path/to/frida/build/meson-logs',
use_llvm_cov=False,
gcovr_exe='/usr/bin/gcovr',  # 假设 gcovr 已安装
llvm_cov_exe=''
```

**可能的输出:**

如果系统中安装了 `lcov` 和 `genhtml`，脚本可能会执行类似以下的命令：

```bash
lcov --directory /path/to/frida/build --capture --initial --output-file /path/to/frida/build/meson-logs/coverage.info.initial
lcov --directory /path/to/frida/build --capture --output-file /path/to/frida/build/meson-logs/coverage.info.run --no-checksum --rc branch_coverage=1
lcov -a /path/to/frida/build/meson-logs/coverage.info.initial -a /path/to/frida/build/meson-logs/coverage.info.run --rc branch_coverage=1 -o /path/to/frida/build/meson-logs/coverage.info.raw
lcov --extract /path/to/frida/build/meson-logs/coverage.info.raw /path/to/frida/* --rc branch_coverage=1 --output-file /path/to/frida/build/meson-logs/coverage.info
lcov --remove /path/to/frida/build/meson-logs/coverage.info /path/to/frida/subprojects/frida-core/* --rc branch_coverage=1 --ignore-errors unused --output-file /path/to/frida/build/meson-logs/coverage.info
genhtml --prefix /path/to/frida/build --prefix /path/to/frida --output-directory /path/to/frida/build/meson-logs/coveragereport --title 'Code coverage' --legend --show-details --branch-coverage /path/to/frida/build/meson-logs/coverage.info
```

最终会在 `/path/to/frida/build/meson-logs/coveragereport/index.html` 生成 HTML 覆盖率报告。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **未安装必要的工具:** 如果用户尝试生成特定格式的报告，但系统中没有安装对应的工具（例如，尝试生成 HTML 报告但未安装 `lcov` 和 `genhtml`），脚本会提示错误或跳过该报告的生成。
   ```
   print('lcov/genhtml or gcovr >= 3.3 needed to generate Html coverage report')
   ```
2. **错误的路径配置:** 用户可能提供了错误的源代码根目录、构建目录或日志目录，导致脚本无法找到覆盖率数据文件或生成报告到期望的位置。
   ```
   # 如果 build_root 路径错误，lcov 将无法找到 .gcda 文件
   subprocess.check_call([lcov_exe, '--directory', build_root, ...])
   ```
3. **工具版本不兼容:** 脚本针对特定版本的工具进行了适配。如果用户使用的工具版本过低，某些功能可能无法使用或产生错误。
   ```
   if gcovr_exe and mesonlib.version_compare(gcovr_version, '>=3.3'):
       # ... 执行 gcovr 命令
   else:
       print('gcovr >= 3.3 needed to generate Xml coverage report')
   ```
4. **忘记启用覆盖率编译选项:** 如果在构建 Frida 时没有启用代码覆盖率相关的编译选项（例如，Meson 中的 `-Dcoverage=true`），则不会生成覆盖率数据，脚本运行时将无法生成有意义的报告。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **配置 Frida 的构建系统 (Meson):** 用户在构建 Frida 时，会在 `meson_options.txt` 或通过命令行选项启用代码覆盖率。例如，设置 `coverage` 选项为 `true`。
2. **执行构建:** 用户运行 `meson build` 命令配置构建目录，然后运行 `ninja` 或 `ninja -C build` 进行编译。
3. **运行测试或目标程序:** 为了生成覆盖率数据，用户需要运行 Frida 的测试套件或者运行使用 Frida 进行插桩的目标程序。在程序运行过程中，编译器插入的代码会生成 `.gcda` 或其他格式的覆盖率数据文件。
4. **生成覆盖率报告:** 用户进入 Frida 的构建目录，通常是 `build`，然后执行 `meson test --coverage` 命令。Meson 会检测到需要生成覆盖率报告，并调用 `frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/coverage.py` 脚本。
5. **手动调用 (可选):** 在某些情况下，用户可能不通过 `meson test --coverage`，而是直接执行 `coverage.py` 脚本，例如，在调试覆盖率生成过程或需要自定义报告选项时。他们需要手动提供脚本所需的参数，例如源代码根目录、构建目录等。

当调试覆盖率生成问题时，理解这些步骤可以帮助定位问题所在：

- **检查构建配置:** 确保覆盖率编译选项已正确启用。
- **检查覆盖率数据文件:** 确认在构建目录中生成了 `.gcda` 或其他覆盖率数据文件。
- **检查脚本参数:** 确保传递给 `coverage.py` 脚本的参数是正确的，特别是源代码和构建目录。
- **检查工具版本:** 确认系统中安装的 `gcovr`、`lcov`、`genhtml` 等工具的版本符合脚本的要求。
- **查看脚本输出:** 分析脚本的输出信息，了解是否有错误提示或警告信息。

希望以上分析能够帮助你理解 `coverage.py` 脚本的功能和其在 Frida 项目中的作用。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/coverage.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```