Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Context:** The prompt clearly states this is part of `frida`, a dynamic instrumentation tool. The file path `frida/subprojects/frida-swift/releng/meson/mesonbuild/scripts/gtkdochelper.py` gives a strong hint: this script is likely involved in generating documentation, specifically using `gtk-doc`, for the Swift bindings of Frida. The `meson` part further suggests this is integrated with the Meson build system.

2. **Identify the Core Functionality:** The script's name, `gtkdochelper.py`, and the presence of arguments like `--sourcedir`, `--builddir`, `--modulename`, `--moduleversion`, and tools like `gtkdoc-scan`, `gtkdoc-mkhtml`, etc., immediately point to documentation generation using the `gtk-doc` toolchain.

3. **Analyze the `argparse` Setup:**  The initial section using `argparse.ArgumentParser()` defines all the command-line arguments the script accepts. This is crucial for understanding *how* the script is used and what information it needs. Notice the arguments correspond to directories, file names, module information, and crucially, arguments passed down to the `gtk-doc` tools.

4. **Examine Key Functions:**

   * **`gtkdoc_run_check(cmd, cwd, library_paths=None)`:**  This function is a utility for running external commands (`gtk-doc` tools in this case). It handles environment setup (especially `PATH` and `LD_LIBRARY_PATH`), platform differences (Windows/Cygwin), and error checking. The `Popen_safe` call is significant – it indicates the script interacts with the underlying operating system.

   * **`build_gtkdoc(...)`:** This is the heart of the script. It orchestrates the entire documentation build process. It performs the following steps:
      * Sets up directories and file paths.
      * Copies relevant documentation files.
      * Cleans the output directory.
      * Executes `gtkdoc-scan` to extract documentation comments from the source code.
      * Executes `gtkdoc-scangobj` (if applicable) to extract information about GObject types.
      * Executes `gtkdoc-mkdb` to generate DocBook XML files.
      * Executes `gtkdoc-mkhtml` to generate HTML documentation from the DocBook files.
      * Executes `gtkdoc-fixxref` to fix cross-references in the generated HTML.
      * Potentially renames the Devhelp index file with the version.

   * **`install_gtkdoc(...)`:** This function handles the installation of the generated documentation to the specified installation prefix.

   * **`run(args)`:** This is the main entry point of the script. It parses the command-line arguments and calls `build_gtkdoc` and `install_gtkdoc`.

5. **Connect to Reverse Engineering:**  Think about how documentation is used in reverse engineering:

   * **Understanding APIs:**  Documentation reveals the intended usage of functions, classes, and data structures. This is vital for understanding how a program works internally. `gtk-doc` focuses on C-based APIs, often used in lower-level libraries. Frida interacts with the target process at a low level, so understanding the APIs of the target (e.g., system libraries, frameworks) is crucial.
   * **Identifying Functionality:**  Good documentation describes the purpose and behavior of different components. This helps reverse engineers quickly grasp the overall structure and functionality of the target.
   * **Finding Vulnerabilities:** While not the primary purpose, understanding the intended behavior can sometimes reveal discrepancies or edge cases that could be potential vulnerabilities.

6. **Identify Low-Level and System Aspects:**

   * **`LD_LIBRARY_PATH` and `PATH`:** These environment variables are crucial for finding shared libraries and executables. Manipulating them is a common technique in reverse engineering and debugging, especially when dealing with dynamically linked libraries.
   * **External Processes:** The script heavily relies on executing external `gtk-doc` tools using `subprocess`. This interaction with the operating system's process management is a fundamental low-level concept.
   * **File System Operations:**  The script performs many file system operations (copying, creating directories, deleting). Understanding file system structures and permissions is essential for reverse engineering.
   * **C Flags and Linker Flags (`cflags`, `ldflags`):** These flags are directly related to the compilation and linking process of native code. Reverse engineers often need to understand how code was compiled to analyze it effectively.

7. **Logical Reasoning and Assumptions:**

   * **Input:** Assume the script is called with appropriate arguments, including source and build directories, the module name, and paths to `gtk-doc` tools.
   * **Output:** The primary output is a set of HTML documentation files in the specified build directory. The script might also produce intermediate files like DocBook XML.
   * **Workflow:** The script follows a specific sequence of steps: scanning source code, generating DocBook, generating HTML, and then potentially installing the documentation.

8. **User Errors:**  Consider common mistakes a user (likely a developer in this context) might make:

   * **Incorrect Paths:** Providing wrong paths for source directories, build directories, or `gtk-doc` tools.
   * **Missing Dependencies:** Not having the `gtk-doc` tools installed or available in the `PATH`.
   * **Incorrect Arguments:** Passing incorrect or malformed arguments to the script or the underlying `gtk-doc` tools.
   * **Permissions Issues:**  Lack of write permissions in the build or installation directories.

9. **Debugging Clues (How the User Gets Here):** The script is likely called as part of the Frida-Swift build process, managed by Meson. A developer working on Frida-Swift would trigger the build, and Meson would execute this script at the appropriate stage to generate the documentation. If documentation generation fails, error messages from this script (especially those raised by `gtkdoc_run_check`) would be the initial clues for debugging. The command-line arguments passed to the script would be defined in the Meson build files.

10. **Refine and Organize:** Finally, organize the observations and insights into the requested categories (functionality, reverse engineering relevance, low-level aspects, logic, user errors, debugging). Use clear examples and concise explanations. Pay attention to the specific wording of the prompt to ensure all aspects are addressed.这是一个用于生成和安装GTK-Doc格式文档的Python脚本，它是Frida项目构建过程的一部分，特别是针对Frida的Swift绑定部分。

**功能列举:**

1. **解析命令行参数:** 脚本使用 `argparse` 模块来解析构建系统（Meson）传递的各种参数，例如源目录、构建目录、头文件目录、主文档文件、模块名称、版本等。这些参数用于配置文档生成过程。
2. **配置 GTK-Doc 工具:**  脚本接收 GTK-Doc 工具的路径作为参数 (例如 `gtkdoc-scan`, `gtkdoc-mkhtml` 等)，并使用它们来执行文档生成的各个阶段。
3. **扫描源代码 (gtkdoc-scan):**  脚本调用 `gtkdoc-scan` 工具来扫描指定的源文件和头文件，提取文档注释。
4. **扫描目标文件 (gtkdoc-scangobj):** 如果提供了 GObject 类型文件，脚本会调用 `gtkdoc-scangobj` 工具，结合编译和链接信息（cc, ld, cflags, ldflags），来生成关于 GObject 类型的文档。
5. **生成 DocBook 文件 (gtkdoc-mkdb):** 脚本使用 `gtkdoc-mkdb` 工具将扫描结果转换为 DocBook XML 格式的文件，这是生成最终 HTML 文档的中间步骤。
6. **生成 HTML 文档 (gtkdoc-mkhtml):** 脚本使用 `gtkdoc-mkhtml` 工具将 DocBook XML 文件转换为用户可浏览的 HTML 格式文档。
7. **修复交叉引用 (gtkdoc-fixxref):** 脚本调用 `gtkdoc-fixxref` 工具来修复生成的 HTML 文档中的交叉引用，确保链接的正确性。
8. **安装文档:**  如果设置了 `MESON_INSTALL_PREFIX` 环境变量，脚本会将生成的 HTML 文档复制到安装目录下的指定位置。
9. **处理平台差异:** 脚本考虑了 Windows 和 Cygwin 平台，在执行外部命令时会做相应的调整，例如在 Windows 上使用 `sys.executable` 来执行命令，并正确设置 `PATH` 和 `LD_LIBRARY_PATH` 环境变量。
10. **错误处理:**  脚本使用 `Popen_safe` 函数来安全地执行外部命令，并检查其返回码，如果命令执行失败会抛出 `MesonException` 异常。

**与逆向方法的关联及举例:**

此脚本本身不是直接用于逆向的工具，但它生成的文档对于逆向工程师理解目标软件的API和内部结构非常有帮助。

**举例:**

* **API 理解:** 假设逆向工程师想要理解 Frida Swift 绑定的某个特定功能，例如如何拦截 Swift 函数。通过查看此脚本生成的 Frida Swift API 文档，他们可以找到相关的类、方法和参数的描述，例如 `Frida.Interceptor` 类的 `attach` 方法，以及如何使用 `NativeCallback` 来定义拦截后的行为。
* **内部结构探索:**  文档可能会揭示 Frida Swift 绑定内部的一些设计和实现细节，例如某些类的继承关系、方法的调用顺序等，这有助于逆向工程师更深入地理解其工作原理。

**涉及二进制底层，Linux, Android内核及框架的知识及举例:**

虽然脚本本身是用 Python 编写的，但它所操作的对象（需要生成文档的代码）以及它所使用的工具（GTK-Doc）都与底层的概念密切相关。

* **二进制底层:**
    * **链接器标志 (`ldflags`):** 脚本接收链接器标志作为参数，这些标志会影响最终生成的可执行文件或库的链接方式。逆向工程师需要理解链接器的工作原理以及各种链接器标志的含义，才能分析目标程序的依赖关系和内存布局。
    * **C 编译器标志 (`cflags`):** 脚本接收 C 编译器标志作为参数，这些标志会影响代码的编译方式，例如优化级别、宏定义等。逆向工程师理解这些标志有助于推断代码的编译过程和潜在的编译器优化。
* **Linux:**
    * **`LD_LIBRARY_PATH` 环境变量:** 脚本在执行外部命令时会设置或使用 `LD_LIBRARY_PATH` 环境变量，这是 Linux 系统中指定动态链接库搜索路径的重要环境变量。逆向工程师经常需要处理动态链接库的问题。
    * **外部命令执行 (`subprocess`):** 脚本使用 `subprocess` 模块来调用外部的 GTK-Doc 工具，这是 Linux 环境下常见的程序交互方式。
* **Android内核及框架:**
    * 尽管此脚本主要关注 Frida Swift 绑定，而 Swift 通常不直接与 Android 内核交互，但 Frida 本身在 Android 平台上被广泛用于动态分析和逆向。此脚本生成的文档可能间接涉及到与 Android 框架交互的 Swift 代码部分。例如，Frida 可能需要调用 Android 的 ART (Android Runtime) 虚拟机提供的 API，而这些 API 的使用方式可能会在生成的文档中体现。

**逻辑推理及假设输入与输出:**

**假设输入:**

```
--sourcedir /path/to/frida-swift/src
--builddir /path/to/frida-swift/build
--subdir doc
--headerdirs include@@src/some_header_dir
--mainfile frida-swift-docs.xml
--modulename FridaSwift
--moduleversion 1.0.0
--htmlargs --css=style.css@@--index-mode
--scanargs --deprecated-gtk=no
--scanobjsargs
--gobjects-types-file
--fixxrefargs
--mkdbargs
--ld /usr/bin/ld
--cc /usr/bin/gcc
--ldflags -L/opt/lib
--cflags -I/opt/include
--content-files overview.md@@tutorial.md
--expand-content-files
--html-assets logo.png
--ignore-headers internal.h
--namespace FridaSwift
--mode auto
--installdir /usr/local/share/doc/FridaSwift-1.0.0
--run /path/to/some/executable
--gtkdoc-scan /usr/bin/gtkdoc-scan
--gtkdoc-scangobj /usr/bin/gtkdoc-scangobj
--gtkdoc-mkdb /usr/bin/gtkdoc-mkdb
--gtkdoc-mkhtml /usr/bin/gtkdoc-mkhtml
--gtkdoc-fixxref /usr/bin/gtkdoc-fixxref
```

**预期输出:**

1. 在 `/path/to/frida-swift/build/doc/html/` 目录下生成包含 FridaSwift API 文档的 HTML 文件，例如 `index.html`, `FridaSwift.html` 等。
2. 生成的 HTML 文档会使用 `style.css` 作为样式表，并可能包含一个索引页面 (`--index-mode`)。
3. 文档生成过程中会忽略 `internal.h` 头文件中的内容。
4. 文档中会包含 `overview.md` 和 `tutorial.md` 的内容。
5. 如果设置了 `MESON_INSTALL_PREFIX` 环境变量，生成的 HTML 文档会被复制到 `/usr/local/share/doc/FridaSwift-1.0.0` 目录下。
6. 控制台输出会显示文档生成的进度信息，以及 GTK-Doc 工具的输出信息。

**涉及用户或编程常见的使用错误及举例:**

1. **路径错误:** 用户在配置构建系统时，可能会提供错误的源目录、构建目录或 GTK-Doc 工具的路径。这会导致脚本无法找到必要的文件或工具，从而报错。
   * **例子:**  如果 `--gtkdoc-scan` 参数指向一个不存在的文件，脚本在执行 `gtkdoc_run_check` 时会因为 `Popen_safe` 调用失败而抛出 `MesonException`。
2. **缺失依赖:** 用户的系统中可能没有安装 GTK-Doc 工具，或者相关工具不在系统的 PATH 环境变量中。这会导致脚本无法找到这些工具。
   * **例子:** 如果系统中没有安装 `gtkdoc-scan`，执行脚本时会报告找不到该命令。
3. **参数错误:** 用户提供的其他参数可能不符合 GTK-Doc 工具的要求，例如使用了不存在的选项或提供了错误的参数值。
   * **例子:** 如果 `--htmlargs` 中包含一个 `gtkdoc-mkhtml` 不支持的选项，`gtkdoc-mkhtml` 可能会报错，导致 `gtkdoc_run_check` 抛出异常。
4. **权限问题:** 用户可能没有在构建目录或安装目录写入文件的权限。
   * **例子:** 如果用户对 `/path/to/frida-swift/build/doc/html/` 目录没有写权限，脚本在尝试创建或复制文件时会失败。
5. **文档注释格式错误:** 如果源代码中的文档注释格式不符合 GTK-Doc 的规范，`gtkdoc-scan` 可能无法正确提取文档信息，导致生成的文档不完整或不正确。

**用户操作如何一步步到达这里，作为调试线索:**

1. **开发者修改了 Frida Swift 的源代码:**  开发者在 `frida/subprojects/frida-swift/` 目录下修改了 Swift 代码，并添加或修改了相关的文档注释。
2. **开发者触发了 Frida 的构建过程:**  开发者使用 Meson 构建系统来编译和构建 Frida，通常会执行类似 `meson build` 和 `ninja -C build` 的命令。
3. **Meson 构建系统执行到文档生成阶段:**  Meson 的构建配置 (通常是 `meson.build` 文件) 中会定义生成 Frida Swift 文档的步骤，其中会调用此 `gtkdochelper.py` 脚本。
4. **Meson 将参数传递给 `gtkdochelper.py`:**  Meson 会根据其配置和当前构建环境，生成相应的命令行参数，并将这些参数传递给 `gtkdochelper.py` 脚本。这些参数包括源代码路径、构建路径、要使用的 GTK-Doc 工具路径等。
5. **`gtkdochelper.py` 执行文档生成:**  脚本根据接收到的参数，依次调用 GTK-Doc 的各个工具来完成文档的生成过程。
6. **如果文档生成失败，开发者会查看错误信息:**  如果 `gtkdochelper.py` 在执行过程中遇到错误（例如 GTK-Doc 工具返回非零状态码），脚本会抛出 `MesonException` 并打印相关的错误信息。
7. **开发者分析错误信息并进行调试:**  开发者会查看错误信息，例如失败的命令、返回码、以及 GTK-Doc 工具的输出，来判断问题的原因。可能的调试步骤包括：
    * **检查传递给 `gtkdochelper.py` 的参数是否正确。**
    * **确认 GTK-Doc 工具是否已正确安装并可在 PATH 中找到。**
    * **检查源代码中的文档注释格式是否符合 GTK-Doc 的要求。**
    * **手动执行失败的 GTK-Doc 命令，以便更详细地了解错误信息。**
    * **检查文件权限和磁盘空间。**

因此，当开发者遇到 Frida Swift 文档生成的问题时，这个脚本的源代码以及它接收到的参数和执行过程中的输出，都是重要的调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/scripts/gtkdochelper.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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