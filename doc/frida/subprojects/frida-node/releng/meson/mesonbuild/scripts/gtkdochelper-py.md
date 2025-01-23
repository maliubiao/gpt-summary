Response:
Let's break down the thought process for analyzing the `gtkdochelper.py` script. The request asks for a multi-faceted analysis, touching upon functionality, relevance to reverse engineering, low-level details, logic, user errors, and debugging.

**1. Understanding the Core Purpose:**

The file name `gtkdochelper.py` and the presence of arguments like `--modulename`, `--moduleversion`, `--headerdirs`, and mentions of `gtkdoc-scan`, `gtkdoc-mkhtml`, etc., strongly suggest this script is a helper for generating documentation using the `gtk-doc` tool. The initial comments confirm this.

**2. Deconstructing the Functionality:**

The script uses `argparse` to handle command-line arguments. This is the first thing to analyze. Listing the arguments and their descriptions will reveal the script's inputs. I would go through the `parser.add_argument` calls and summarize each argument's purpose.

Next, I'd look for the main functions. `build_gtkdoc` and `install_gtkdoc` stand out. `build_gtkdoc` seems responsible for the core documentation generation process, calling various `gtkdoc` utilities. `install_gtkdoc` handles the installation of the generated documentation. The `run` function appears to be the entry point, parsing arguments and calling the build and potentially install functions.

Within `build_gtkdoc`, I'd identify the sequence of operations:

* **Setup:** Creating directories, copying content files.
* **Scanning:** Using `gtkdoc-scan` to process source code.
* **Object Scanning (Optional):**  Using `gtkdoc-scangobj` for GObject introspection.
* **Database Generation:** Using `gtkdoc-mkdb` to create DocBook XML.
* **HTML Generation:** Using `gtkdoc-mkhtml` to convert DocBook to HTML.
* **Fixing Cross-References:** Using `gtkdoc-fixxref`.
* **Versioning:** Renaming the Devhelp file.

The `gtkdoc_run_check` function is crucial. It handles the execution of external commands and checks for errors. Understanding how it sets up the environment (especially `PATH` and `LD_LIBRARY_PATH`) is important.

**3. Identifying Reverse Engineering Relevance:**

The key connection to reverse engineering lies in the documentation itself. Generated documentation helps understand the structure, APIs, and behavior of a software library or framework. This is valuable in reverse engineering to:

* **Understand APIs:** Discover available functions, their parameters, and return values.
* **Identify Data Structures:**  Learn about the organization of data used by the target.
* **Trace Execution Flow:**  Infer how different components interact based on documented relationships.

The example of using documentation to understand function signatures and data structures in a closed-source library is a direct application in reverse engineering.

**4. Spotting Low-Level/Kernel/Framework Aspects:**

* **Binary Execution:** The script executes external binaries (`gtkdoc-*`). This is a fundamental interaction with the operating system.
* **Shared Libraries (`LD_LIBRARY_PATH`):** The `gtkdoc_run_check` function manipulates `LD_LIBRARY_PATH` (or `PATH` on Windows). This directly relates to how the system finds and loads shared libraries, crucial in understanding program dependencies and runtime behavior.
* **GObject Introspection:** The `--gobjects-types-file` and `gtkdoc-scangobj` relate to the GObject introspection system, commonly used in GTK+ and related libraries. This is a framework-specific detail.
* **Installation Paths:** The `install_gtkdoc` function and the use of `MESON_INSTALL_PREFIX` and `DESTDIR` touch on standard Linux installation conventions.

**5. Logical Inference (Assumptions and Outputs):**

Here, I'd consider specific scenarios and trace the script's execution:

* **Scenario 1 (Basic HTML generation):**  Assume minimal input, focusing on generating basic HTML documentation. I'd then walk through the `build_gtkdoc` function and identify which `gtkdoc-*` tools are called and with what arguments.
* **Scenario 2 (GObject introspection):** If `--gobjects-types-file` is provided, the `gtkdoc-scangobj` part of the code will execute. The output would be the generated introspection data.

The input/output examples should clearly demonstrate the transformation performed by the script.

**6. Anticipating User Errors:**

Think about common mistakes users might make when configuring or running the build system:

* **Incorrect Paths:**  Providing wrong paths for source directories, build directories, or the main documentation file.
* **Missing Dependencies:** Not having the `gtk-doc` tools installed.
* **Incorrect Arguments:**  Misspelling or providing invalid arguments to the script or the underlying `gtkdoc` tools.
* **Environment Issues:** Problems with `PATH` or `LD_LIBRARY_PATH` preventing the execution of the `gtkdoc` tools.

**7. Debugging Steps (How to Reach the Script):**

This requires understanding the context in which the script is used. Since it's part of a Meson build system for Frida, the steps would involve:

* **Configuring the Build:** Running `meson` to set up the build environment.
* **Initiating the Build:** Running `ninja` or a similar build tool.
* **Identifying the Documentation Target:**  There would likely be a specific target in the `meson.build` file that triggers the execution of `gtkdochelper.py`. Looking for `custom_target` or similar constructs related to documentation would be key.
* **Following the Execution:**  Using build system logs or debugging tools to trace the execution flow and see how `gtkdochelper.py` is invoked with specific arguments.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the Python code itself. **Correction:**  Shift focus to the *purpose* of the script within the larger build process and the `gtk-doc` ecosystem.
* **Overlooking external commands:**  Not paying enough attention to the `gtkdoc_*` commands being executed. **Correction:** Research the function of each `gtkdoc` tool and how the script orchestrates them.
* **Not connecting to reverse engineering deeply enough:**  Simply stating "documentation is useful." **Correction:** Provide concrete examples of how documentation aids in understanding and reversing software.
* **Too generic on user errors:** Listing general programming errors. **Correction:** Focus on errors specific to using `gtk-doc` and the build system.

By following these steps and continually refining the analysis, a comprehensive and accurate understanding of the `gtkdochelper.py` script can be achieved.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/gtkdochelper.py` 这个 Python 脚本的功能，并根据你的要求进行详细说明。

**功能概述**

这个脚本的主要功能是作为 Frida 项目中用于生成 GTK-Doc 格式文档的辅助工具。它被 Meson 构建系统调用，用于自动化文档的生成过程。具体来说，它执行以下操作：

1. **解析命令行参数:**  脚本使用 `argparse` 模块解析 Meson 传递的各种参数，这些参数包含了源代码目录、构建目录、头文件目录、主文档文件、模块名称、版本号、各种 `gtkdoc` 工具的参数等等。
2. **配置文档构建环境:**  根据解析到的参数，脚本会设置文档构建所需的环境，例如源文件路径、输出路径等。
3. **调用 GTK-Doc 工具链:**  脚本的核心功能是调用 GTK-Doc 工具链中的多个工具，包括：
    * `gtkdoc-scan`: 扫描源代码中的注释，提取文档信息。
    * `gtkdoc-scangobj`: (可选) 如果涉及到 GObject，则扫描 GObject 的类型信息。
    * `gtkdoc-mkdb`: 将扫描到的信息生成 DocBook XML 格式的文档。
    * `gtkdoc-mkhtml`: 将 DocBook XML 转换为 HTML 格式的文档。
    * `gtkdoc-fixxref`: 修复 HTML 文档中的交叉引用。
4. **处理文件和目录:**  脚本会创建必要的输出目录，复制内容文件（如主文档文件、章节文件、覆盖文件），以及 HTML 资源文件。
5. **处理环境变量:**  脚本会设置 `PATH` 或 `LD_LIBRARY_PATH` 环境变量，以便正确找到和执行 GTK-Doc 工具。
6. **安装文档:**  如果指定了安装前缀，脚本会将生成的 HTML 文档安装到指定的位置。

**与逆向方法的关系及举例说明**

GTK-Doc 生成的文档对于逆向工程来说是非常有价值的资源。它可以提供关于目标软件库或框架的结构、API 和使用方式的详细信息。

**举例说明:**

假设我们要逆向一个使用了 GLib 库的二进制文件。GLib 使用 GTK-Doc 生成了完善的文档。通过查看 GLib 的文档，我们可以：

* **了解数据结构:**  例如，我们可以查阅 `GList` 的文档，了解链表的结构，这有助于我们分析程序中使用的链表操作。
* **理解函数签名和功能:**  我们可以查看 `g_strdup()` 函数的文档，了解它的作用是复制字符串，参数和返回值是什么，这有助于我们理解程序中字符串处理的逻辑。
* **发现关键 API:**  通过浏览文档，我们可能会发现一些与安全相关的 API，例如加密、解密、权限控制等，这为我们寻找潜在的安全漏洞提供了线索。

虽然 `gtkdochelper.py` 本身不直接参与逆向分析，但它生成的文档是逆向工程师的重要参考资料。在逆向过程中，我们经常需要查阅文档来理解代码的功能和行为。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明**

这个脚本在执行过程中涉及到一些底层和框架的知识：

1. **二进制执行:** 脚本会调用外部的二进制程序 (`gtkdoc-*`)，这涉及到操作系统如何加载和执行二进制文件。
2. **共享库加载 (`LD_LIBRARY_PATH`):** `gtkdoc_run_check` 函数会根据操作系统设置 `LD_LIBRARY_PATH` (Linux) 或 `PATH` (Windows)，这涉及到动态链接器如何查找和加载共享库。在逆向分析中，理解共享库的加载机制对于理解程序依赖和运行时行为至关重要。例如，如果一个 Frida 模块依赖于特定的库，而该库不在默认的搜索路径中，那么就需要正确设置 `LD_LIBRARY_PATH`。
3. **GObject 类型系统:**  如果使用了 `--gobjects-types-file` 参数，脚本会调用 `gtkdoc-scangobj`，这涉及到 GObject 的类型内省 (introspection) 机制。GObject 是 GTK+ 和许多其他 Linux 桌面环境库的基础，理解 GObject 的类型系统对于逆向基于这些库的程序非常重要。例如，通过 GObject 的类型信息，我们可以了解对象的属性、信号和方法。
4. **安装路径:**  脚本中的 `install_gtkdoc` 函数涉及到将文档安装到标准 Linux 系统目录，例如 `/usr/share/gtk-doc/html`。理解文件系统的组织结构对于逆向工程中的文件操作分析很有帮助。

**逻辑推理及假设输入与输出**

脚本的主要逻辑是 orchestrating GTK-Doc 工具链的执行。

**假设输入:**

```
--sourcedir=/path/to/frida/frida-node
--builddir=/path/to/frida/frida-node/build
--subdir=docs/api
--headerdirs=src/lib@@src/script
--mainfile=index.sgml
--modulename=Frida
--moduleversion=16.0.0
--scanargs=--deprecated-since=1.0
--mkdbargs=--title='Frida API Reference'
--gtkdoc-scan=/usr/bin/gtkdoc-scan
--gtkdoc-mkdb=/usr/bin/gtkdoc-mkdb
--gtkdoc-mkhtml=/usr/bin/gtkdoc-mkhtml
--gtkdoc-fixxref=/usr/bin/gtkdoc-fixxref
```

**逻辑推理:**

1. 脚本会解析这些参数。
2. `build_gtkdoc` 函数会被调用。
3. `gtkdoc-scan` 会被执行，扫描 `/path/to/frida/frida-node/src/lib` 和 `/path/to/frida/frida-node/src/script` 目录下的源代码，提取文档注释，并标记 `deprecated since 1.0` 的内容。
4. `gtkdoc-mkdb` 会被执行，使用扫描结果生成 DocBook XML 文件，并设置文档标题为 "Frida API Reference"。
5. `gtkdoc-mkhtml` 会被执行，将 DocBook XML 转换为 HTML 文件，输出到 `/path/to/frida/frida-node/build/docs/api/html` 目录。
6. `gtkdoc-fixxref` 会被执行，修复 HTML 文件中的交叉引用。

**假设输出:**

在 `/path/to/frida/frida-node/build/docs/api/html` 目录下会生成一系列 HTML 文件，包含了 Frida 的 API 参考文档。这些文档将包含从源代码注释中提取的信息，并按照 DocBook 格式组织。

**用户或编程常见的使用错误及举例说明**

1. **路径错误:** 用户可能提供了错误的源文件目录、构建目录或 GTK-Doc 工具的路径。
   * **示例:** 如果 `--gtkdoc-scan=/usr/bin/nonexistent-gtkdoc-scan`，脚本在调用 `gtkdoc_run_check` 时会抛出 `MesonException`，因为找不到该命令。

2. **缺少依赖:** 用户可能没有安装 GTK-Doc 工具链。
   * **示例:** 如果系统中没有安装 `gtkdoc-scan`，当脚本尝试执行它时，会因为找不到命令而失败。

3. **参数错误:** 用户可能提供了错误的 GTK-Doc 工具的参数。
   * **示例:** 如果 `--scanargs=--invalid-argument`，`gtkdoc-scan` 可能会因为无法识别该参数而报错，导致 `gtkdoc_run_check` 抛出异常。

4. **权限问题:**  用户可能没有执行 GTK-Doc 工具的权限。
   * **示例:** 如果 GTK-Doc 工具的执行权限被移除，`gtkdoc_run_check` 会因为无法执行命令而失败。

5. **环境变量配置错误:**  在某些情况下，GTK-Doc 工具可能依赖于特定的环境变量。如果这些环境变量没有正确设置，可能会导致文档生成失败。
   * **示例:** 尽管脚本尝试设置 `LD_LIBRARY_PATH`，但在复杂环境下，可能仍然存在库加载问题。

**用户操作是如何一步步的到达这里，作为调试线索**

这个脚本通常不会被用户直接调用，而是作为 Frida 的构建过程的一部分被 Meson 构建系统自动调用。以下是用户操作到达这里的步骤：

1. **配置构建环境:** 用户首先需要配置 Frida 的构建环境，这通常涉及到运行 `meson` 命令。例如：
   ```bash
   meson setup builddir
   ```
   Meson 会读取项目中的 `meson.build` 文件，根据配置生成构建文件。

2. **执行构建:** 用户然后会执行构建命令，通常是 `ninja`。例如：
   ```bash
   ninja -C builddir
   ```
   Ninja 会读取 Meson 生成的构建文件，并按照依赖关系执行构建任务。

3. **触发文档生成目标:** 在 Frida 的 `meson.build` 文件中，可能定义了一个或多个用于生成文档的自定义目标 (`custom_target`)。当 Ninja 执行到这些目标时，就会调用 `gtkdochelper.py` 脚本。`meson.build` 文件中可能类似如下定义：

   ```python
   gtkdoc_helper = find_program('gtkdochelper.py')
   gtkdoc_scan = find_program('gtkdoc-scan')
   gtkdoc_mkdb = find_program('gtkdoc-mkdb')
   gtkdoc_mkhtml = find_program('gtkdoc-mkhtml')
   gtkdoc_fixxref = find_program('gtkdoc-fixxref')

   gtkdoc_target = custom_target(
       'api-doc',
       command: [
           gtkdoc_helper,
           '--sourcedir', meson.source_root(),
           '--builddir', meson.build_root(),
           '--subdir', 'docs/api',
           # ... 其他参数
       ],
       # ... 其他属性
   )
   ```

4. **Meson 传递参数:** 当 Ninja 执行 `gtkdoc_target` 时，Meson 会构造包含所有必要参数的命令行，并将这些参数传递给 `gtkdochelper.py` 脚本。这些参数就包括了我们在前面分析中看到的那些 `--sourcedir`, `--builddir` 等。

**作为调试线索:**

当文档生成出现问题时，理解上述步骤可以帮助我们进行调试：

1. **检查 `meson.build`:** 查看 Frida 的 `meson.build` 文件，确认文档生成的目标是如何定义的，以及传递了哪些参数给 `gtkdochelper.py`。
2. **查看构建日志:**  查看 Ninja 的构建日志，可以找到 `gtkdochelper.py` 的具体调用命令，包括传递的参数。这可以帮助我们确认 Meson 是否正确地传递了参数。
3. **手动执行脚本:**  可以尝试从构建目录中手动执行 `gtkdochelper.py` 脚本，并使用相同的参数，以便更直接地观察脚本的运行情况和错误信息。
4. **检查 GTK-Doc 工具:**  确认 GTK-Doc 工具链是否已正确安装并且在系统的 PATH 环境变量中。
5. **分析错误信息:**  仔细分析脚本输出的错误信息，这通常会提供关于问题所在的线索。

总而言之，`gtkdochelper.py` 是 Frida 构建系统中一个关键的辅助脚本，它通过调用 GTK-Doc 工具链来自动化生成 API 文档。理解其功能和工作原理，对于理解 Frida 的构建过程以及在遇到文档生成问题时进行调试至关重要。同时，它生成的文档对于 Frida 的使用者，包括逆向工程师，都是非常有价值的参考资料。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/gtkdochelper.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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