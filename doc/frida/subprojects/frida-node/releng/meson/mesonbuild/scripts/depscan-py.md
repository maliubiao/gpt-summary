Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The immediate goal is to analyze the provided Python script, `depscan.py`, and explain its functionality, relating it to reverse engineering concepts where applicable, and highlighting any interaction with low-level details, kernel/framework knowledge, logical reasoning, potential user errors, and how a user might arrive at this script's execution.

**2. Initial Code Scan (Superficial):**

A quick glance reveals:

* **Imports:** Standard Python libraries (`json`, `os`, `pathlib`, `re`, `sys`, `typing`, `pickle`). Specific imports like `ninja_quote` and `TargetDependencyScannerInfo` suggest interaction with the Ninja build system and some form of dependency tracking.
* **Regular Expressions:**  The presence of `CPP_IMPORT_RE`, `CPP_EXPORT_RE`, `FORTRAN_INCLUDE_PAT`, etc., strongly indicates the script parses source code files.
* **Classes:**  The `DependencyScanner` class is the central component, suggesting an object-oriented approach to the dependency scanning task.
* **Functions:** `scan_file`, `scan_fortran_file`, `scan_cpp_file`, `objname_for`, `module_name_for`, `scan`, and `run` are the main actions the script performs.
* **File I/O:** The script reads a pickle file, potentially writes to an output file, and reads source code files.

**3. Deep Dive into Functionality (Logical Deduction):**

Now, let's go function by function and piece together the script's purpose:

* **`DependencyScanner.__init__`:** Loads data from a pickle file (`pickle_file`) which contains information about the target being built (likely build artifacts and dependencies). Initializes data structures to store discovered dependencies (`provided_by`, `exports`, `needs`).
* **`scan_file`:**  Dispatches to language-specific scanning functions based on file extension. This hints at supporting multiple languages.
* **`scan_fortran_file`:**  Uses regular expressions to find `include`, `module`, `submodule`, and `use` statements in Fortran code. It populates `provided_by` (what module a file exports) and `needs` (what modules a file imports). The logic around submodules is more complex, handling parent-child dependencies.
* **`scan_cpp_file`:** Similar to `scan_fortran_file`, but uses different regexes for C++ `import` and `export module`.
* **`objname_for`:**  Retrieves the object file name corresponding to a source file from the `target_data`. This ties back to the Ninja build system and its tracking of build outputs.
* **`module_name_for`:** Determines the name of the module file produced by a source file. The naming convention differs for Fortran (with `.mod` and `.smod` extensions) and C++ (`.ifc`). This indicates knowledge of how different compilers generate module files.
* **`scan`:** The core logic. It iterates through the input source files, calls `scan_file` to analyze each, and then generates Ninja build rules based on the discovered dependencies. It constructs `dyndep` (dynamic dependency) rules, which allow Ninja to discover dependencies during the build process itself. The logic specifically handles cases where a needed module is not provided by any of the scanned sources (assuming it's a library dependency).
* **`run`:** The entry point. It receives command-line arguments (pickle file, output file, JSON file containing the list of source files), loads the source list, creates a `DependencyScanner` instance, and calls its `scan` method.

**4. Connecting to Reverse Engineering:**

While this script *isn't* directly involved in disassembling or analyzing compiled binaries, the concept of dependency analysis is crucial in reverse engineering:

* **Understanding Code Structure:**  Just like this script maps module imports/exports, a reverse engineer tries to understand how different parts of a program interact.
* **Identifying Key Components:**  Dependencies can highlight critical modules or functions within a target.
* **Tracing Execution Flow:**  Understanding dependencies helps in tracing how different parts of the program call each other.

**5. Identifying Low-Level/Kernel/Framework Connections:**

* **Binary Bottom Layer:**  The script deals with compiler artifacts like `.mod`, `.smod`, and `.ifc` files, which are intermediate binary representations created during compilation.
* **Linux:**  The script is likely run on a Linux-based system, as indicated by the file paths and the integration with Ninja, a common build system on Linux. The script itself is platform-agnostic Python, but its *purpose* is tied to building software typically done on such systems.
* **Android (Potentially):** Frida, the tool this script belongs to, is often used for dynamic instrumentation on Android. While the script itself doesn't directly interact with the Android kernel, the build process it supports likely produces components that *do* interact with the Android framework or even the kernel (e.g., native libraries).

**6. Logical Reasoning and Hypothetical Inputs/Outputs:**

Consider a simple Fortran example:

* **`module_a.f90`:**
  ```fortran
  module module_a
    implicit none
    integer :: value_a
  end module module_a
  ```
* **`program_b.f90`:**
  ```fortran
  program program_b
    use module_a
    implicit none
    value_a = 10
    print *, value_a
  end program program_b
  ```

**Input:**  `pickle_file` containing build info, `outfile` (e.g., `deps.ninja`), `jsonfile` listing `module_a.f90` and `program_b.f90`.

**Processing:**

* `depscan.py` would parse `module_a.f90` and identify the `module module_a` export.
* It would parse `program_b.f90` and identify the `use module_a` import.
* It would store that `program_b.f90` *needs* `module_a`.
* `module_a.f90` *provides* `module_a`.

**Output (`deps.ninja`):**

The `deps.ninja` file would contain rules indicating that the object file for `program_b.f90` depends on the module file generated by `module_a.f90` (e.g., `frida/subprojects/frida-node/releng/meson/build/module_a.mod`).

**7. Common User Errors:**

* **Incorrect File Paths:**  Providing the wrong paths to the pickle file, output file, or source files in the JSON file would cause the script to fail.
* **Missing Build System Integration:** Running this script outside of the intended Meson/Ninja build process wouldn't make sense, as it relies on the data generated by Meson.
* **Syntax Errors in Source Files:**  While the script ignores encoding errors, severe syntax errors that prevent the regular expressions from matching might lead to incomplete dependency information.

**8. Tracing User Actions:**

1. **Developer modifies source code:** A developer changes a Fortran or C++ file, adding or removing module imports or exports.
2. **Build system is invoked:** The developer runs a build command (e.g., `ninja` or a higher-level build tool that uses Ninja, like one configured by Meson).
3. **Meson generates build files:** Meson, the build system generator, analyzes the project's `meson.build` files and generates `build.ninja` and other necessary files, including the pickle file (`pickle_file` argument to `depscan.py`).
4. **Ninja executes build steps:** Ninja reads `build.ninja` and executes the build steps in parallel.
5. **`depscan.py` is invoked:** As part of the build process, Ninja encounters a rule that calls `depscan.py`. The arguments passed to `depscan.py` are determined by Meson based on the project configuration. These arguments point to the pickle file containing target information, the output file where the dynamic dependencies should be written, and a JSON file listing the source files for the current target.
6. **`depscan.py` analyzes dependencies:** The script performs its analysis and writes the dynamic dependency information to the output file.
7. **Ninja uses dynamic dependency information:** Ninja reads the output file generated by `depscan.py` to discover additional dependencies that weren't known at the start of the build. This allows for more accurate and efficient rebuilding when module dependencies change.

By following these steps, we can arrive at a comprehensive understanding of the script's function, its connections to other areas, and potential issues.
好的，让我们来详细分析一下 `depscan.py` 这个 Python 脚本的功能和它在 Frida 中的作用。

**功能概述**

`depscan.py` 是 Frida 构建系统中的一个脚本，其主要功能是**扫描源代码文件，提取模块依赖关系，并生成 Ninja 构建系统所需的动态依赖信息 (dyndep)。**  简单来说，它用来告诉 Ninja，在编译某些源文件之前，需要先编译哪些模块。这对于支持模块化编程语言（如 Fortran 和 C++ Modules）的项目来说至关重要，因为这些语言的编译过程涉及到模块接口文件的生成和依赖。

**具体功能点:**

1. **解析构建元数据:**  脚本首先读取一个 pickle 文件 (`pickle_file`)，这个文件包含了 Meson 构建系统生成的关于当前构建目标的信息，例如源文件到目标文件的映射 (`target_data.source2object`) 和私有目录 (`target_data.private_dir`)。

2. **扫描源代码文件:**
   - 根据文件后缀判断编程语言（目前支持 Fortran 和 C++）。
   - **Fortran 文件扫描:** 使用正则表达式 (`FORTRAN_USE_RE`, `FORTRAN_MODULE_RE`, `FORTRAN_SUBMOD_RE`) 提取 `use` (引入模块), `module` (定义模块), 和 `submodule` (定义子模块) 语句，从而识别模块的导入和导出关系。
   - **C++ 文件扫描:** 使用正则表达式 (`CPP_IMPORT_RE`, `CPP_EXPORT_RE`) 提取 `import` (引入模块) 和 `export module` (导出模块) 语句，识别 C++ Modules 的依赖关系。

3. **记录模块依赖关系:**
   - `provided_by`:  记录哪个源文件提供了哪个模块。
   - `exports`: 记录哪个源文件导出了哪个模块。
   - `needs`: 记录哪个源文件需要哪些模块。

4. **生成 Ninja 动态依赖信息:**
   - 遍历所有源文件。
   - 对于每个源文件，确定它依赖的模块以及它生成的模块文件。
   - 使用 Ninja 的 `dyndep` 语法生成构建规则，指示 Ninja 在编译当前源文件之前，需要先编译其依赖的模块。

**与逆向方法的关系**

`depscan.py` 本身并不直接进行逆向操作，但它所做的工作为构建出的 Frida 提供了基础，而 Frida 是一个强大的动态 instrumentation 工具，被广泛用于逆向工程。

**举例说明:**

假设你正在逆向一个使用了 C++ Modules 的 Android 应用，并且你想要 hook 其中一个模块中的函数。

1. **Frida 的构建过程:**  `depscan.py` 会在 Frida 的构建过程中运行，分析 Frida 自身的 C++ 源代码，确定模块间的依赖关系。例如，如果 `frida-core/libglue.cc` 导入了 `frida/core/runtime.h` 定义的模块，`depscan.py` 会生成相应的 Ninja 规则，确保 `frida-core/libglue.o` 的编译依赖于 `frida/core/runtime.ifc` (C++ Module 的接口文件) 的生成。

2. **逆向分析:**  当你使用 Frida attach 到目标应用后，Frida 的核心组件（其构建过程受到 `depscan.py` 的影响）会被加载到目标进程中。你可以利用 Frida 提供的 API，基于模块化的结构来定位和 hook 目标函数，因为 Frida 内部的模块依赖关系已经明确。

**涉及二进制底层，Linux, Android 内核及框架的知识**

1. **二进制底层:**
   - **目标文件 (.o):** `depscan.py` 关联源文件和最终生成的目标文件，这是二进制编译的中间产物。
   - **模块接口文件 (.ifc, .mod, .smod):**  对于支持模块化的语言，`depscan.py` 识别和处理模块的接口文件，这些文件是编译器生成的二进制表示，包含了模块的导出信息。
   - **动态链接:**  虽然 `depscan.py` 不直接处理链接，但它确保了模块按照正确的依赖顺序编译，这对于后续的动态链接过程至关重要。

2. **Linux:**
   - **Ninja 构建系统:**  `depscan.py` 是为 Ninja 构建系统服务的，Ninja 是一个快速的小型构建系统，常用于 Linux 环境下的项目构建。
   - **文件路径和操作:**  脚本使用 `os` 和 `pathlib` 模块处理文件路径，这是在 Linux 环境下进行文件操作的基础。

3. **Android 内核及框架 (间接关联):**
   - **Frida 的目标平台:**  Frida 经常被用于 Android 平台的动态 instrumentation。虽然 `depscan.py` 自身不直接与 Android 内核或框架交互，但它确保了 Frida 能够正确构建，从而为在 Android 上进行逆向分析提供了工具。
   - **动态库 (.so):**  Frida 的核心组件通常以动态库的形式存在于 Android 系统中。`depscan.py` 确保了 Frida 的 C++ 模块能够正确编译，最终链接成动态库。

**逻辑推理**

`depscan.py` 做了以下逻辑推理：

**假设输入:**
- `pickle_file`: 包含构建目标的元数据。
- `outfile`:  指定输出的 Ninja 动态依赖信息文件的路径。
- `sources`:  一个 JSON 列表，包含了需要扫描依赖的源文件路径。

**逻辑推理过程:**

1. **读取构建元数据:** 从 `pickle_file` 中加载 `TargetDependencyScannerInfo`，获取源文件到目标文件的映射等信息。
2. **遍历源文件:** 逐个处理 `sources` 列表中的源文件。
3. **识别语言:**  根据文件后缀判断是 Fortran 还是 C++ 文件。
4. **提取依赖:** 使用相应的正则表达式解析源代码，识别 `import`/`use` 和 `export module`/`module` 等语句。
5. **记录依赖关系:**  将提取到的模块提供者和需求者信息分别存储在 `provided_by` 和 `needs` 字典中。
6. **生成 Ninja 规则:** 对于每个源文件，根据其导出的模块和依赖的模块，生成 `build ... : dyndep ...` 格式的 Ninja 构建规则。

**假设输出 (outfile 中的内容片段):**

```ninja
ninja_dyndep_version = 1
build obj/frida-core/libglue.o : dyndep | frida/core/runtime.ifc
```

这个输出表示，在构建 `obj/frida-core/libglue.o` 这个目标文件之前，Ninja 需要先确保 `frida/core/runtime.ifc` 文件已经生成。

**用户或编程常见的使用错误**

1. **修改或删除 `pickle_file`:**  这个文件是由 Meson 生成的，用户不应该手动修改或删除它。如果文件丢失或损坏，`depscan.py` 将无法读取构建元数据，导致程序崩溃或生成错误的依赖信息。

   **用户操作到达这里的路径:** 用户可能在清理构建目录时，错误地删除了 `meson-info` 或 `build` 目录下的相关文件。

2. **提供的源文件列表不完整或错误:**  如果 `jsonfile` 中列出的源文件与实际需要编译的源文件不符，`depscan.py` 可能无法正确识别所有依赖关系。

   **用户操作到达这里的路径:**  这可能是 Meson 配置错误，导致传递给 `depscan.py` 的源文件列表不正确。

3. **源代码中存在语法错误，导致正则表达式匹配失败:**  虽然脚本会忽略一些编码错误，但如果源代码中存在严重的语法错误，导致正则表达式无法正确匹配 `import`/`use` 或 `export module`/`module` 语句，可能会导致依赖关系遗漏。

   **用户操作到达这里的路径:**  开发者在编写代码时引入了语法错误，并且在构建过程中触发了 `depscan.py` 的执行。

4. **运行 `depscan.py` 时没有提供正确的参数:**  `depscan.py` 需要三个参数：pickle 文件路径，输出文件路径和 JSON 文件路径。如果参数缺失或错误，脚本会抛出断言错误。

   **用户操作到达这里的路径:**  用户可能尝试手动运行 `depscan.py` 进行调试，但没有提供或提供了错误的命令行参数。

**说明用户操作是如何一步步的到达这里，作为调试线索**

假设开发者在构建 Frida 的过程中遇到了与模块依赖相关的编译错误。为了调试，他可能会尝试了解 `depscan.py` 的工作原理，以确定是否是依赖关系计算错误导致了问题。

1. **编译错误发生:**  开发者运行 `ninja` 命令构建 Frida，但编译过程因为找不到某个模块接口文件而失败。
2. **查看构建日志:** 开发者查看 Ninja 的构建日志，发现与模块编译相关的错误信息。
3. **定位 `depscan.py`:**  在构建日志中，开发者可能会看到 `depscan.py` 的执行命令，因为它参与了生成动态依赖信息。
4. **分析 `depscan.py` 的输入:** 开发者可能会检查传递给 `depscan.py` 的参数：
   - `pickle_file`: 检查这个文件是否存在，是否完整。
   - `outfile`:  查看生成的动态依赖信息文件，看是否包含了期望的依赖关系。
   - `jsonfile`:  查看源文件列表是否正确，是否包含了导致编译错误的源文件及其依赖。
5. **阅读 `depscan.py` 源代码:** 为了更深入地理解，开发者会阅读 `depscan.py` 的源代码，了解它是如何解析源文件和生成依赖信息的。
6. **模拟执行或添加调试信息:** 开发者可能会尝试使用相同的参数手动运行 `depscan.py`，或者在脚本中添加 `print` 语句来输出中间结果，例如提取到的依赖关系，以排查问题。

通过以上步骤，开发者可以利用 `depscan.py` 作为调试线索，理解 Frida 的模块依赖是如何被处理的，并找出导致编译错误的根本原因。

总而言之，`depscan.py` 是 Frida 构建流程中一个关键的辅助脚本，它负责处理模块化语言的依赖关系，确保构建过程的正确性和效率。虽然它不直接进行逆向操作，但它为 Frida 这样的逆向工具的构建奠定了基础。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/depscan.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

import json
import os
import pathlib
import pickle
import re
import sys
import typing as T

from ..backend.ninjabackend import ninja_quote
from ..compilers.compilers import lang_suffixes

if T.TYPE_CHECKING:
    from ..backend.ninjabackend import TargetDependencyScannerInfo

CPP_IMPORT_RE = re.compile(r'\w*import ([a-zA-Z0-9]+);')
CPP_EXPORT_RE = re.compile(r'\w*export module ([a-zA-Z0-9]+);')

FORTRAN_INCLUDE_PAT = r"^\s*include\s*['\"](\w+\.\w+)['\"]"
FORTRAN_MODULE_PAT = r"^\s*\bmodule\b\s+(\w+)\s*(?:!+.*)*$"
FORTRAN_SUBMOD_PAT = r"^\s*\bsubmodule\b\s*\((\w+:?\w+)\)\s*(\w+)"
FORTRAN_USE_PAT = r"^\s*use,?\s*(?:non_intrinsic)?\s*(?:::)?\s*(\w+)"

FORTRAN_MODULE_RE = re.compile(FORTRAN_MODULE_PAT, re.IGNORECASE)
FORTRAN_SUBMOD_RE = re.compile(FORTRAN_SUBMOD_PAT, re.IGNORECASE)
FORTRAN_USE_RE = re.compile(FORTRAN_USE_PAT, re.IGNORECASE)

class DependencyScanner:
    def __init__(self, pickle_file: str, outfile: str, sources: T.List[str]):
        with open(pickle_file, 'rb') as pf:
            self.target_data: TargetDependencyScannerInfo = pickle.load(pf)
        self.outfile = outfile
        self.sources = sources
        self.provided_by: T.Dict[str, str] = {}
        self.exports: T.Dict[str, str] = {}
        self.needs: T.Dict[str, T.List[str]] = {}
        self.sources_with_exports: T.List[str] = []

    def scan_file(self, fname: str) -> None:
        suffix = os.path.splitext(fname)[1][1:]
        if suffix != 'C':
            suffix = suffix.lower()
        if suffix in lang_suffixes['fortran']:
            self.scan_fortran_file(fname)
        elif suffix in lang_suffixes['cpp']:
            self.scan_cpp_file(fname)
        else:
            sys.exit(f'Can not scan files with suffix .{suffix}.')

    def scan_fortran_file(self, fname: str) -> None:
        fpath = pathlib.Path(fname)
        modules_in_this_file = set()
        for line in fpath.read_text(encoding='utf-8', errors='ignore').split('\n'):
            import_match = FORTRAN_USE_RE.match(line)
            export_match = FORTRAN_MODULE_RE.match(line)
            submodule_export_match = FORTRAN_SUBMOD_RE.match(line)
            if import_match:
                needed = import_match.group(1).lower()
                # In Fortran you have an using declaration also for the module
                # you define in the same file. Prevent circular dependencies.
                if needed not in modules_in_this_file:
                    if fname in self.needs:
                        self.needs[fname].append(needed)
                    else:
                        self.needs[fname] = [needed]
            if export_match:
                exported_module = export_match.group(1).lower()
                assert exported_module not in modules_in_this_file
                modules_in_this_file.add(exported_module)
                if exported_module in self.provided_by:
                    raise RuntimeError(f'Multiple files provide module {exported_module}.')
                self.sources_with_exports.append(fname)
                self.provided_by[exported_module] = fname
                self.exports[fname] = exported_module
            if submodule_export_match:
                # Store submodule "Foo" "Bar" as "foo:bar".
                # A submodule declaration can be both an import and an export declaration:
                #
                # submodule (a1:a2) a3
                #  - requires a1@a2.smod
                #  - produces a1@a3.smod
                parent_module_name_full = submodule_export_match.group(1).lower()
                parent_module_name = parent_module_name_full.split(':')[0]
                submodule_name = submodule_export_match.group(2).lower()
                concat_name = f'{parent_module_name}:{submodule_name}'
                self.sources_with_exports.append(fname)
                self.provided_by[concat_name] = fname
                self.exports[fname] = concat_name
                # Fortran requires that the immediate parent module must be built
                # before the current one. Thus:
                #
                # submodule (parent) parent   <- requires parent.mod (really parent.smod, but they are created at the same time)
                # submodule (a1:a2) a3        <- requires a1@a2.smod
                #
                # a3 does not depend on the a1 parent module directly, only transitively.
                if fname in self.needs:
                    self.needs[fname].append(parent_module_name_full)
                else:
                    self.needs[fname] = [parent_module_name_full]

    def scan_cpp_file(self, fname: str) -> None:
        fpath = pathlib.Path(fname)
        for line in fpath.read_text(encoding='utf-8', errors='ignore').split('\n'):
            import_match = CPP_IMPORT_RE.match(line)
            export_match = CPP_EXPORT_RE.match(line)
            if import_match:
                needed = import_match.group(1)
                if fname in self.needs:
                    self.needs[fname].append(needed)
                else:
                    self.needs[fname] = [needed]
            if export_match:
                exported_module = export_match.group(1)
                if exported_module in self.provided_by:
                    raise RuntimeError(f'Multiple files provide module {exported_module}.')
                self.sources_with_exports.append(fname)
                self.provided_by[exported_module] = fname
                self.exports[fname] = exported_module

    def objname_for(self, src: str) -> str:
        objname = self.target_data.source2object[src]
        assert isinstance(objname, str)
        return objname

    def module_name_for(self, src: str) -> str:
        suffix = os.path.splitext(src)[1][1:].lower()
        if suffix in lang_suffixes['fortran']:
            exported = self.exports[src]
            # Module foo:bar goes to a file name foo@bar.smod
            # Module Foo goes to a file name foo.mod
            namebase = exported.replace(':', '@')
            if ':' in exported:
                extension = 'smod'
            else:
                extension = 'mod'
            return os.path.join(self.target_data.private_dir, f'{namebase}.{extension}')
        elif suffix in lang_suffixes['cpp']:
            return '{}.ifc'.format(self.exports[src])
        else:
            raise RuntimeError('Unreachable code.')

    def scan(self) -> int:
        for s in self.sources:
            self.scan_file(s)
        with open(self.outfile, 'w', encoding='utf-8') as ofile:
            ofile.write('ninja_dyndep_version = 1\n')
            for src in self.sources:
                objfilename = self.objname_for(src)
                mods_and_submods_needed = []
                module_files_generated = []
                module_files_needed = []
                if src in self.sources_with_exports:
                    module_files_generated.append(self.module_name_for(src))
                if src in self.needs:
                    for modname in self.needs[src]:
                        if modname not in self.provided_by:
                            # Nothing provides this module, we assume that it
                            # comes from a dependency library somewhere and is
                            # already built by the time this compilation starts.
                            pass
                        else:
                            mods_and_submods_needed.append(modname)

                for modname in mods_and_submods_needed:
                    provider_src = self.provided_by[modname]
                    provider_modfile = self.module_name_for(provider_src)
                    # Prune self-dependencies
                    if provider_src != src:
                        module_files_needed.append(provider_modfile)

                quoted_objfilename = ninja_quote(objfilename, True)
                quoted_module_files_generated = [ninja_quote(x, True) for x in module_files_generated]
                quoted_module_files_needed = [ninja_quote(x, True) for x in module_files_needed]
                if quoted_module_files_generated:
                    mod_gen = '| ' + ' '.join(quoted_module_files_generated)
                else:
                    mod_gen = ''
                if quoted_module_files_needed:
                    mod_dep = '| ' + ' '.join(quoted_module_files_needed)
                else:
                    mod_dep = ''
                build_line = 'build {} {}: dyndep {}'.format(quoted_objfilename,
                                                             mod_gen,
                                                             mod_dep)
                ofile.write(build_line + '\n')
        return 0

def run(args: T.List[str]) -> int:
    assert len(args) == 3, 'got wrong number of arguments!'
    pickle_file, outfile, jsonfile = args
    with open(jsonfile, encoding='utf-8') as f:
        sources = json.load(f)
    scanner = DependencyScanner(pickle_file, outfile, sources)
    return scanner.scan()
```