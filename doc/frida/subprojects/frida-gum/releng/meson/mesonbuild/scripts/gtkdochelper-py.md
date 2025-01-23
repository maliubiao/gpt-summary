Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Context:** The prompt clearly states this is `gtkdochelper.py` within the `frida` project. This immediately suggests it's related to generating documentation for Frida, specifically using `gtk-doc`. The file path gives further clues about its location within the build system (`meson`).

2. **High-Level Overview:**  The script starts with standard Python boilerplate (license, imports). The presence of `argparse` strongly indicates it's a command-line tool. The core of the script seems to be the `build_gtkdoc` function, which likely orchestrates the documentation generation process. There's also an `install_gtkdoc` function for the installation phase.

3. **Dissecting the `argparse` Setup:**  The `argparse` section is crucial for understanding the script's inputs. Each `add_argument` defines a command-line option. I'd list these out mentally or physically:

    * `--sourcedir`, `--builddir`, `--subdir`:  Path information.
    * `--headerdirs`:  Where to find header files.
    * `--mainfile`: The main documentation file.
    * `--modulename`, `--moduleversion`: Identifiers for the documentation.
    * `--htmlargs`, `--scanargs`, etc.: Arguments passed to `gtk-doc` tools.
    * `--ld`, `--cc`, `--ldflags`, `--cflags`:  Compiler and linker settings – important for processing code.
    * `--content-files`, `--expand-content-files`, `--html-assets`, `--ignore-headers`: Input files and filtering options.
    * `--namespace`: A documentation namespace.
    * `--mode`:  Documentation output mode (XML or SGML).
    * `--installdir`: Installation directory.
    * `--run`:  Likely a command to execute for introspection.
    * `--gtkdoc-scan`, `--gtkdoc-scangobj`, etc.: Paths to the `gtk-doc` tools themselves.

4. **Analyzing Key Functions:**

    * **`gtkdoc_run_check`:** This is a helper function for executing external commands (`gtk-doc` tools). It handles environment setup (especially `LD_LIBRARY_PATH` and `PATH`), error checking, and output printing. The Windows/Cygwin specific handling is notable.

    * **`build_gtkdoc`:**  This is the core logic. I'd break it down step-by-step:
        * **Path Handling:**  It constructs paths, copies files, and creates output directories.
        * **`gtkdoc-scan` Execution:**  This step extracts API information from the source code. The `--ignore-headers` option is relevant.
        * **`gtkdoc-scangobj` Execution:** This step deals with GObject type information. The script passes compiler/linker flags, indicating it's introspecting compiled objects. The `library_paths` extraction is interesting.
        * **`gtkdoc-mkdb` Execution:** This generates the DocBook XML (or SGML) files.
        * **`gtkdoc-mkhtml` Execution:**  This converts the DocBook files to HTML.
        * **`gtkdoc-fixxref` Execution:**  This fixes cross-references in the generated HTML.
        * **Version Handling:**  Renaming the Devhelp file.

    * **`install_gtkdoc`:**  This simply copies the generated HTML documentation to the installation directory.

    * **`run`:**  This function parses the command-line arguments, calls `build_gtkdoc`, and then `install_gtkdoc` if the environment indicates an installation.

5. **Connecting to the Prompt's Questions:**  Now, armed with an understanding of the script's functionality, I can address the specific questions:

    * **Functionality:**  Summarize the main steps of documentation generation.
    * **Relationship to Reverse Engineering:** Think about how documentation aids in RE. Having clear API references is crucial. The script itself doesn't *perform* reverse engineering, but it supports the process by providing information about the target. The introspection aspect (`gtkdoc-scangobj`, compiler flags) hints at looking *inside* the compiled code.
    * **Binary/Kernel/Framework Knowledge:** The use of compiler flags (`-I`, `-L`, etc.), linker flags, and the handling of `LD_LIBRARY_PATH` are direct connections to binary and system-level knowledge. The reference to GObject is specific to the Linux/GNOME framework.
    * **Logical Reasoning (Input/Output):** Choose a simplified scenario with minimal options to illustrate the input/output flow. Focus on the core `build_gtkdoc` function.
    * **User Errors:** Think about common mistakes when using such a tool – incorrect paths, missing dependencies, wrong arguments, etc. Relate these back to the script's input parameters.
    * **User Steps (Debugging):**  How would a developer end up needing to look at this script?  The most likely scenario is a documentation build failure. Trace the steps from initiating the build to encountering an error that might lead to inspecting the helper script.

6. **Structuring the Answer:** Organize the information logically, using headings and bullet points to make it easier to read. Start with a high-level summary and then delve into the specifics. Provide concrete examples for the reverse engineering, binary knowledge, and user error sections.

7. **Refinement:** Review the answer for clarity, accuracy, and completeness. Ensure all aspects of the prompt are addressed. For example, double-check the explanations for the `gtk-doc` tools and their roles.

By following these steps, you can systematically analyze a complex script and generate a comprehensive and informative answer like the example provided in the prompt. The key is to understand the context, break down the code into manageable parts, and then connect the functionality to the specific questions asked.
这个Python脚本 `gtkdochelper.py` 是 Frida 项目中用于生成文档的辅助工具，它基于 `gtk-doc` 工具集来为 Frida 的 C/C++ 代码生成 API 文档。

**以下是它的功能列表：**

1. **配置文档生成过程:**  该脚本接收一系列命令行参数，这些参数定义了文档生成的各种配置，例如源代码目录、构建目录、头文件目录、主文档文件、模块名称和版本等。

2. **调用 `gtk-doc` 工具:**  脚本的核心功能是封装了对 `gtk-doc` 工具集（如 `gtkdoc-scan`, `gtkdoc-scangobj`, `gtkdoc-mkdb`, `gtkdoc-mkhtml`, `gtkdoc-fixxref`）的调用。它根据传入的参数构建合适的命令行，并执行这些工具。

3. **提取 API 信息 (`gtkdoc-scan`):**  通过 `gtkdoc-scan` 工具扫描指定的头文件，提取 C/C++ API 的信息，例如函数、结构体、宏定义等。

4. **处理 GObject 类型信息 (`gtkdoc-scangobj`):** 如果涉及到 GObject（GNOME 的对象系统），则使用 `gtkdoc-scangobj` 工具处理 GObject 的类型信息。这需要提供编译和链接相关的参数，以便正确地加载和解析动态库。

5. **生成 DocBook 文件 (`gtkdoc-mkdb`):**  使用 `gtkdoc-mkdb` 工具将提取到的 API 信息和手动编写的文档内容（例如 `*-sections.txt`, `*-overrides.txt`）合并，生成 DocBook XML 或 SGML 格式的文档源文件。

6. **生成 HTML 文档 (`gtkdoc-mkhtml`):**  使用 `gtkdoc-mkhtml` 工具将 DocBook 格式的文档源文件转换为 HTML 格式，以便于浏览器查看。

7. **修复交叉引用 (`gtkdoc-fixxref`):**  使用 `gtkdoc-fixxref` 工具修复生成的 HTML 文档中的交叉引用，确保链接的正确性。

8. **安装文档 (`install_gtkdoc`):**  将生成的 HTML 文档复制到指定的安装目录下。

9. **处理环境变量:**  脚本会根据操作系统类型（Windows/Cygwin 或其他）设置 `PATH` 或 `LD_LIBRARY_PATH` 环境变量，以便能够找到依赖的动态库。

**与逆向方法的关系及举例说明:**

虽然这个脚本本身不执行逆向工程，但它生成的文档对于 Frida 的使用者进行逆向分析至关重要。

* **理解 API 接口:** 逆向工程师可以使用生成的 API 文档来了解 Frida Gum 库提供的各种函数和接口的作用、参数和返回值。这有助于他们理解如何使用 Frida 来 hook、跟踪和修改目标进程的行为。

* **查找隐藏功能:** 通过阅读文档，逆向工程师可能会发现一些在代码中不容易直接看到的 API 或功能点，从而拓展他们的逆向分析思路。

* **快速定位目标:**  当逆向分析遇到特定的行为或功能时，可以查阅文档，快速定位到可能相关的 Frida API，例如：

    * 如果要 hook 某个函数，可以查看 `frida-gum` 提供的 `Interceptor` 类和相关的 API。
    * 如果要访问内存，可以查找 `Memory` 相关的 API。
    * 如果要操作线程，可以查找 `Thread` 相关的 API。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个脚本在处理 GObject 类型信息时，需要提供编译和链接参数，这直接涉及到二进制底层和操作系统相关的知识。

* **编译和链接参数 (`--cc`, `--ld`, `--cflags`, `--ldflags`):** 这些参数告诉 `gtkdoc-scangobj` 如何编译和链接目标代码，以便加载和解析其中的类型信息。这需要了解编译器和链接器的工作原理，例如头文件搜索路径、库文件搜索路径、链接库等。

* **动态库加载 (`LD_LIBRARY_PATH` / `PATH`):**  脚本需要设置 `LD_LIBRARY_PATH` (Linux) 或 `PATH` (Windows) 环境变量，以便 `gtkdoc-scangobj` 能够找到 Frida Gum 库和其他依赖的动态库。这涉及到操作系统如何加载和管理动态链接库的知识。

* **GObject 类型系统:**  如果 Frida Gum 使用了 GObject，那么 `gtkdoc-scangobj` 需要理解 GObject 的类型系统，例如对象的继承、信号机制等。GObject 是 GNOME 桌面环境的核心框架，常用于 Linux 平台上的 C 语言开发。

* **Frida Gum 的底层实现:**  虽然脚本本身不涉及 Frida Gum 的具体实现，但其生成的文档是基于 Frida Gum 的源代码和构建过程的，因此隐含了对 Frida Gum 底层实现的理解，例如其内存管理、代码注入机制等。

**逻辑推理及假设输入与输出:**

假设我们有以下简化输入参数：

* `--sourcedir`: `/path/to/frida/frida-gum/`
* `--builddir`: `/path/to/frida/build/frida-gum/`
* `--subdir`: `docs/gum`
* `--headerdirs`: `gum/@@gum/backend-posix/@@gum/backend-asan/`
* `--mainfile`: `gum-docs.xml`
* `--modulename`: `Gum`
* `--moduleversion`: `16.0`
* `--cc`: `gcc`
* `--ld`: `ld`

**逻辑推理过程:**

1. 脚本会首先解析这些命令行参数，并将它们存储在 `options` 对象中。
2. `build_gtkdoc` 函数会被调用，传入这些参数。
3. 脚本会根据 `headerdirs` 创建源文件目录参数 `--source-dir`，例如：`--source-dir=/path/to/frida/frida-gum/gum/`，`--source-dir=/path/to/frida/build/frida-gum/gum/backend-posix/` 等。
4. 脚本会构建 `gtkdoc-scan` 命令，包含模块名、源文件目录和忽略的头文件（如果有）。
5. 脚本会执行 `gtkdoc-scan`，假设成功执行，会在构建目录下生成一些中间文件，例如 `.xml` 或 `.sgml` 文件，包含提取到的 API 信息。
6. 如果提供了 `--gobjects-types-file`，则会构建并执行 `gtkdoc-scangobj` 命令，包含类型文件、模块名、运行命令（如果有）、编译和链接参数等。
7. 脚本会构建 `gtkdoc-mkdb` 命令，包含模块名、输出格式、扩展内容文件、命名空间（如果有）、主文档文件等。
8. 脚本会执行 `gtkdoc-mkdb`，将 API 信息和手动编写的文档合并，生成 `Gum-docs.xml` (取决于 `--mainfile`) 在构建目录下。
9. 脚本会构建 `gtkdoc-mkhtml` 命令，包含文档路径、模块名和主文档文件。
10. 脚本会执行 `gtkdoc-mkhtml`，将 `Gum-docs.xml` 转换为 HTML 文件，输出到 `builddir/subdir/html` 目录下。
11. 脚本会构建 `gtkdoc-fixxref` 命令，修复 HTML 文件中的交叉引用。
12. 如果提供了 `--moduleversion`，则会将生成的 Devhelp 文件重命名为 `Gum-16.0.devhelp2`。
13. 如果设置了 `MESON_INSTALL_PREFIX` 环境变量，则会将生成的 HTML 文档复制到安装目录下。

**假设输出:**

在 `/path/to/frida/build/frida-gum/docs/gum/html/` 目录下会生成一系列 HTML 文件，包含 Frida Gum 的 API 文档，例如 `index.html`, `Gum-types.html`, `Gum-functions.html` 等。 如果提供了版本号，还会在该目录下生成 `Gum-16.0.devhelp2` 文件。

**涉及用户或编程常见的使用错误及举例说明:**

1. **路径错误:** 用户可能提供了错误的源代码目录、构建目录或头文件目录，导致 `gtkdoc-scan` 无法找到源文件或头文件。

   ```bash
   # 错误示例：错误的源代码目录
   python gtkdochelper.py --sourcedir /incorrect/path/to/frida ...
   ```

   这会导致 `gtkdoc-scan` 报错，提示找不到指定的源文件或头文件。

2. **缺少依赖工具:** 如果系统中没有安装 `gtk-doc` 工具集，脚本在尝试执行 `gtkdoc-scan` 等命令时会失败。

   ```bash
   # 错误示例：缺少 gtk-doc
   python gtkdochelper.py ...
   ```

   这会导致类似 "找不到命令" 的错误。

3. **编译/链接参数错误:** 在处理 GObject 类型信息时，如果提供的编译或链接参数不正确，`gtkdoc-scangobj` 可能会加载失败或解析错误。

   ```bash
   # 错误示例：错误的头文件搜索路径
   python gtkdochelper.py --cflags "-I/wrong/path" ...
   ```

   这可能导致 `gtkdoc-scangobj` 报错，提示找不到相关的头文件或符号。

4. **文档结构错误:** 手动编写的文档文件（如 `*-sections.txt`, `*-overrides.txt`）可能存在语法错误，导致 `gtkdoc-mkdb` 解析失败。

5. **权限问题:**  脚本在创建目录或复制文件时可能遇到权限问题。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常情况下，用户不会直接运行 `gtkdochelper.py`。这个脚本是由 Frida 的构建系统 Meson 自动调用的。用户操作到达这里的步骤如下：

1. **配置 Frida 构建:** 用户会执行 Meson 的配置命令，例如 `meson setup builddir`，Meson 会读取 `meson.build` 文件。

2. **触发文档构建:** `meson.build` 文件中会包含定义如何生成文档的规则，通常会使用 `gtkdoc` Meson 模块。当用户执行 `meson compile -C builddir` 或 `ninja -C builddir` 来编译 Frida 时，Meson 会根据这些规则生成构建任务。

3. **Meson 调用 `gtkdochelper.py`:**  当执行到文档构建任务时，Meson 会调用 `gtkdochelper.py` 脚本，并将相关的参数传递给它。这些参数是从 `meson.build` 文件中的配置信息和构建环境推导出来的。

4. **文档生成失败:** 如果文档生成过程中出现错误，例如上述的使用错误，用户会在构建输出中看到相关的错误信息，例如 `gtkdoc-scan failed with status ...`。

5. **调试线索:**  当用户遇到文档构建失败时，他们可能会：
    * **查看构建日志:**  仔细阅读构建输出，查找具体的错误信息。
    * **检查 `meson.build` 文件:**  查看文档相关的配置，确认路径、参数等是否正确。
    * **手动执行 `gtkdoc` 命令 (用于排查):**  有时，为了更精确地定位问题，开发者可能会尝试手动构造并执行 `gtkdoc-scan` 或其他 `gtkdoc` 工具的命令，模拟 `gtkdochelper.py` 的行为。
    * **查看 `gtkdochelper.py` 源代码:**  如果错误信息不够明确，或者怀疑是脚本本身的问题，开发者可能会查看 `gtkdochelper.py` 的源代码，了解其具体的工作流程和参数处理方式，以便更好地理解错误原因。

因此，查看 `gtkdochelper.py` 的源代码通常是开发者在遇到 Frida 文档构建问题时进行深入调试的一个步骤。他们会分析脚本如何调用 `gtk-doc` 工具，以及如何处理各种参数和环境变量，从而找到问题的根源。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/gtkdochelper.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015-2016 The Meson development team

from __future__ import annotations

import sys, os
import subprocess
import shutil
import argparse
from ..mesonlib import MesonException, Popen_safe, is_windows, is_cygwin, split_args
from . import destdir_join
import typing as T

parser = argparse.ArgumentParser()

parser.add_argument('--sourcedir', dest='sourcedir')
parser.add_argument('--builddir', dest='builddir')
parser.add_argument('--subdir', dest='subdir')
parser.add_argument('--headerdirs', dest='headerdirs')
parser.add_argument('--mainfile', dest='mainfile')
parser.add_argument('--modulename', dest='modulename')
parser.add_argument('--moduleversion', dest='moduleversion')
parser.add_argument('--htmlargs', dest='htmlargs', default='')
parser.add_argument('--scanargs', dest='scanargs', default='')
parser.add_argument('--scanobjsargs', dest='scanobjsargs', default='')
parser.add_argument('--gobjects-types-file', dest='gobject_typesfile', default='')
parser.add_argument('--fixxrefargs', dest='fixxrefargs', default='')
parser.add_argument('--mkdbargs', dest='mkdbargs', default='')
parser.add_argument('--ld', dest='ld', default='')
parser.add_argument('--cc', dest='cc', default='')
parser.add_argument('--ldflags', dest='ldflags', default='')
parser.add_argument('--cflags', dest='cflags', default='')
parser.add_argument('--content-files', dest='content_files', default='')
parser.add_argument('--expand-content-files', dest='expand_content_files', default='')
parser.add_argument('--html-assets', dest='html_assets', default='')
parser.add_argument('--ignore-headers', dest='ignore_headers', default='')
parser.add_argument('--namespace', dest='namespace', default='')
parser.add_argument('--mode', dest='mode', default='')
parser.add_argument('--installdir', dest='install_dir')
parser.add_argument('--run', dest='run', default='')
for tool in ['scan', 'scangobj', 'mkdb', 'mkhtml', 'fixxref']:
    program_name = 'gtkdoc-' + tool
    parser.add_argument('--' + program_name, dest=program_name.replace('-', '_'))

def gtkdoc_run_check(cmd: T.List[str], cwd: str, library_paths: T.Optional[T.List[str]] = None) -> None:
    if library_paths is None:
        library_paths = []

    env = dict(os.environ)
    if is_windows() or is_cygwin():
        if 'PATH' in env:
            library_paths.extend(env['PATH'].split(os.pathsep))
        env['PATH'] = os.pathsep.join(library_paths)
    else:
        if 'LD_LIBRARY_PATH' in env:
            library_paths.extend(env['LD_LIBRARY_PATH'].split(os.pathsep))
        env['LD_LIBRARY_PATH'] = os.pathsep.join(library_paths)

    if is_windows():
        cmd.insert(0, sys.executable)

    # Put stderr into stdout since we want to print it out anyway.
    # This preserves the order of messages.
    p, out = Popen_safe(cmd, cwd=cwd, env=env, stderr=subprocess.STDOUT)[0:2]
    if p.returncode != 0:
        err_msg = [f"{cmd!r} failed with status {p.returncode:d}"]
        if out:
            err_msg.append(out)
        raise MesonException('\n'.join(err_msg))
    elif out:
        # Unfortunately Windows cmd.exe consoles may be using a codepage
        # that might choke print() with a UnicodeEncodeError, so let's
        # ignore such errors for now, as a compromise as we are outputting
        # console output here...
        try:
            print(out)
        except UnicodeEncodeError:
            pass

def build_gtkdoc(source_root: str, build_root: str, doc_subdir: str, src_subdirs: T.List[str],
                 main_file: str, module: str, module_version: str,
                 html_args: T.List[str], scan_args: T.List[str], fixxref_args: T.List[str], mkdb_args: T.List[str],
                 gobject_typesfile: str, scanobjs_args: T.List[str], run: str, ld: str, cc: str, ldflags: str, cflags: str,
                 html_assets: T.List[str], content_files: T.List[str], ignore_headers: T.List[str], namespace: str,
                 expand_content_files: T.List[str], mode: str, options: argparse.Namespace) -> None:
    print("Building documentation for %s" % module)

    src_dir_args = []
    for src_dir in src_subdirs:
        if not os.path.isabs(src_dir):
            dirs = [os.path.join(source_root, src_dir),
                    os.path.join(build_root, src_dir)]
        else:
            dirs = [src_dir]
        src_dir_args += ['--source-dir=' + d for d in dirs]

    doc_src = os.path.join(source_root, doc_subdir)
    abs_out = os.path.join(build_root, doc_subdir)
    htmldir = os.path.join(abs_out, 'html')

    content_files += [main_file]
    sections = os.path.join(doc_src, module + "-sections.txt")
    if os.path.exists(sections):
        content_files.append(sections)

    overrides = os.path.join(doc_src, module + "-overrides.txt")
    if os.path.exists(overrides):
        content_files.append(overrides)

    # Copy files to build directory
    for f in content_files:
        # FIXME: Use mesonlib.File objects so we don't need to do this
        if not os.path.isabs(f):
            f = os.path.join(doc_src, f)
        elif os.path.commonpath([f, build_root]) == build_root:
            continue
        shutil.copyfile(f, os.path.join(abs_out, os.path.basename(f)))

    shutil.rmtree(htmldir, ignore_errors=True)
    try:
        os.mkdir(htmldir)
    except Exception:
        pass

    for f in html_assets:
        f_abs = os.path.join(doc_src, f)
        shutil.copyfile(f_abs, os.path.join(htmldir, os.path.basename(f_abs)))

    scan_cmd = [options.gtkdoc_scan, '--module=' + module] + src_dir_args
    if ignore_headers:
        scan_cmd.append('--ignore-headers=' + ' '.join(ignore_headers))
    # Add user-specified arguments
    scan_cmd += scan_args
    gtkdoc_run_check(scan_cmd, abs_out)

    # Use the generated types file when available, otherwise gobject_typesfile
    # would often be a path to source dir instead of build dir.
    if '--rebuild-types' in scan_args:
        gobject_typesfile = os.path.join(abs_out, module + '.types')

    if gobject_typesfile:
        scanobjs_cmd = [options.gtkdoc_scangobj] + scanobjs_args
        scanobjs_cmd += ['--types=' + gobject_typesfile,
                         '--module=' + module,
                         '--run=' + run,
                         '--cflags=' + cflags,
                         '--ldflags=' + ldflags,
                         '--cc=' + cc,
                         '--ld=' + ld,
                         '--output-dir=' + abs_out]

        library_paths = []
        for ldflag in split_args(ldflags):
            if ldflag.startswith('-Wl,-rpath,'):
                library_paths.append(ldflag[11:])

        gtkdoc_run_check(scanobjs_cmd, build_root, library_paths)

    # Make docbook files
    if mode == 'auto':
        # Guessing is probably a poor idea but these keeps compat
        # with previous behavior
        if main_file.endswith('sgml'):
            modeflag = '--sgml-mode'
        else:
            modeflag = '--xml-mode'
    elif mode == 'xml':
        modeflag = '--xml-mode'
    elif mode == 'sgml':
        modeflag = '--sgml-mode'
    else: # none
        modeflag = None

    mkdb_cmd = [options.gtkdoc_mkdb,
                '--module=' + module,
                '--output-format=xml',
                '--expand-content-files=' + ' '.join(expand_content_files),
                ] + src_dir_args
    if namespace:
        mkdb_cmd.append('--name-space=' + namespace)
    if modeflag:
        mkdb_cmd.append(modeflag)
    if main_file:
        # Yes, this is the flag even if the file is in xml.
        mkdb_cmd.append('--main-sgml-file=' + main_file)
    # Add user-specified arguments
    mkdb_cmd += mkdb_args
    gtkdoc_run_check(mkdb_cmd, abs_out)

    # Make HTML documentation
    mkhtml_cmd = [options.gtkdoc_mkhtml,
                  '--path=' + os.pathsep.join((doc_src, abs_out)),
                  module,
                  ] + html_args
    if main_file:
        mkhtml_cmd.append('../' + main_file)
    else:
        mkhtml_cmd.append('%s-docs.xml' % module)
    # html gen must be run in the HTML dir
    gtkdoc_run_check(mkhtml_cmd, htmldir)

    # Fix cross-references in HTML files
    fixref_cmd = [options.gtkdoc_fixxref,
                  '--module=' + module,
                  '--module-dir=html'] + fixxref_args
    gtkdoc_run_check(fixref_cmd, abs_out)

    if module_version:
        shutil.move(os.path.join(htmldir, f'{module}.devhelp2'),
                    os.path.join(htmldir, f'{module}-{module_version}.devhelp2'))

def install_gtkdoc(build_root: str, doc_subdir: str, install_prefix: str, datadir: str, module: str) -> None:
    source = os.path.join(build_root, doc_subdir, 'html')
    final_destination = os.path.join(install_prefix, datadir, module)
    shutil.rmtree(final_destination, ignore_errors=True)
    shutil.copytree(source, final_destination)

def run(args: T.List[str]) -> int:
    options = parser.parse_args(args)
    if options.htmlargs:
        htmlargs = options.htmlargs.split('@@')
    else:
        htmlargs = []
    if options.scanargs:
        scanargs = options.scanargs.split('@@')
    else:
        scanargs = []
    if options.scanobjsargs:
        scanobjsargs = options.scanobjsargs.split('@@')
    else:
        scanobjsargs = []
    if options.fixxrefargs:
        fixxrefargs = options.fixxrefargs.split('@@')
    else:
        fixxrefargs = []
    if options.mkdbargs:
        mkdbargs = options.mkdbargs.split('@@')
    else:
        mkdbargs = []
    build_gtkdoc(
        options.sourcedir,
        options.builddir,
        options.subdir,
        options.headerdirs.split('@@'),
        options.mainfile,
        options.modulename,
        options.moduleversion,
        htmlargs,
        scanargs,
        fixxrefargs,
        mkdbargs,
        options.gobject_typesfile,
        scanobjsargs,
        options.run,
        options.ld,
        options.cc,
        options.ldflags,
        options.cflags,
        options.html_assets.split('@@') if options.html_assets else [],
        options.content_files.split('@@') if options.content_files else [],
        options.ignore_headers.split('@@') if options.ignore_headers else [],
        options.namespace,
        options.expand_content_files.split('@@') if options.expand_content_files else [],
        options.mode,
        options)

    if 'MESON_INSTALL_PREFIX' in os.environ:
        destdir = os.environ.get('DESTDIR', '')
        install_prefix = destdir_join(destdir, os.environ['MESON_INSTALL_PREFIX'])
        if options.install_dir:
            install_dir = options.install_dir
        else:
            install_dir = options.modulename
            if options.moduleversion:
                install_dir += '-' + options.moduleversion
        if os.path.isabs(install_dir):
            install_dir = destdir_join(destdir, install_dir)
        install_gtkdoc(options.builddir,
                       options.subdir,
                       install_prefix,
                       'share/gtk-doc/html',
                       install_dir)
    return 0

if __name__ == '__main__':
    sys.exit(run(sys.argv[1:]))
```