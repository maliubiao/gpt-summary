Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Purpose from Context:**

The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/scripts/gtkdochelper.py` provides significant clues.

* **frida:**  Indicates the tool is part of the Frida project, a dynamic instrumentation toolkit. This immediately suggests a connection to reverse engineering and low-level system interaction.
* **subprojects/frida-qml:** Suggests this part relates to Frida's integration with Qt/QML, implying it's documenting APIs related to this.
* **releng/meson:**  Points to release engineering and the use of Meson, a build system. This means the script is involved in the build process, likely generating documentation.
* **mesonbuild/scripts:** Further confirms its role in the Meson build process.
* **gtkdochelper.py:**  Clearly states its purpose: it's a helper script for `gtk-doc`, a tool for generating API documentation, especially for C-based libraries (although it can be used more broadly).

**Initial Hypothesis:** This script is used during the Frida build process to generate API documentation for the Frida QML bindings using `gtk-doc`.

**2. Deconstructing the Code - Function by Function:**

* **`gtkdoc_run_check(cmd, cwd, library_paths)`:**
    * **Purpose:** Executes a command (`cmd`) in a specified directory (`cwd`). It handles environment setup, especially for library paths (`LD_LIBRARY_PATH` or `PATH`). Crucially, it checks the return code and raises an error if the command fails.
    * **Relevance to Reverse Engineering:**  While not directly a reverse engineering *tool*, it's used in the build process of a reverse engineering tool. The handling of library paths is relevant because Frida interacts with loaded processes and libraries. Incorrect library paths could prevent `gtk-doc`'s sub-tools from finding necessary components.
    * **Low-Level/Kernel/Framework:** The `LD_LIBRARY_PATH` manipulation is directly related to how Linux (and other Unix-like systems) find shared libraries. This is a core operating system concept.
    * **Error Handling:**  Demonstrates good practice by checking return codes.

* **`build_gtkdoc(...)`:**
    * **Purpose:** The core logic for generating the documentation. It orchestrates various `gtk-doc` tools.
    * **Key `gtk-doc` tools used:** `gtkdoc-scan`, `gtkdoc-scangobj`, `gtkdoc-mkdb`, `gtkdoc-mkhtml`, `gtkdoc-fixxref`. Understanding these tools is key to understanding the script's functionality.
    * **Workflow:**
        1. Sets up directories.
        2. Copies necessary files.
        3. Runs `gtkdoc-scan` to extract API information from source code.
        4. Runs `gtkdoc-scangobj` (optionally) to extract information from compiled object files (useful for GObject introspection).
        5. Runs `gtkdoc-mkdb` to generate DocBook XML files.
        6. Runs `gtkdoc-mkhtml` to generate HTML documentation from the DocBook files.
        7. Runs `gtkdoc-fixxref` to fix cross-references in the HTML.
    * **Relevance to Reverse Engineering:**  Documents the APIs that Frida exposes, which are used for instrumentation and hooking. Understanding these APIs is crucial for using Frida effectively in reverse engineering. The GObject introspection part is relevant to how Frida might interact with GObject-based applications.
    * **Low-Level/Kernel/Framework:** The inclusion of compiler (`cc`) and linker (`ld`) flags suggests that the documentation might include information about low-level interfaces. The handling of object files (`.o` files) in `gtkdoc-scangobj` relates to the compilation process.
    * **Logic/Assumptions:** The `mode` parameter and the handling of `.sgml` vs. `.xml` files show conditional logic based on file extensions.

* **`install_gtkdoc(...)`:**
    * **Purpose:** Installs the generated HTML documentation to a specified location.
    * **Relevance to Reverse Engineering:** Makes the documentation readily available for users of Frida.
    * **User Errors:** Incorrect `install_prefix` or `datadir` could lead to documentation being installed in the wrong location.

* **`run(args)`:**
    * **Purpose:**  Parses command-line arguments using `argparse` and calls `build_gtkdoc` and `install_gtkdoc`.
    * **User Interaction:** This is the entry point for the script, processing arguments provided by the user (or the build system).
    * **User Errors:** Providing incorrect arguments would lead to errors.

**3. Connecting to Reverse Engineering:**

The generated documentation directly benefits reverse engineers using Frida. It provides information on:

* **Frida's QML API:** How to interact with Frida from QML, which is useful for creating user interfaces for instrumentation tasks.
* **Underlying C/C++ APIs:** While not explicitly shown in *this* script, the use of `gtk-doc` suggests that the documented API likely has a C/C++ foundation, which is relevant for understanding Frida's core functionality.

**4. Identifying Low-Level/Kernel/Framework Aspects:**

* **Library Paths (`LD_LIBRARY_PATH`, `PATH`):**  Crucial for dynamic linking and loading of shared libraries, a fundamental OS concept.
* **Compiler and Linker Flags (`cflags`, `ldflags`):** Directly related to the compilation and linking process, which is essential for creating executable code and libraries.
* **Object Files (`.o`):** Intermediate files produced during compilation. Understanding object files is key to understanding the compilation process.
* **GObject Introspection:** A mechanism in the GLib ecosystem that allows runtime inspection of object types, often used in frameworks like GTK.

**5. Logical Reasoning and Assumptions:**

* **File Extensions:** The script makes assumptions based on file extensions (e.g., `.sgml`, `.xml`).
* **Presence of Files:** It checks for the existence of certain files (e.g., `-sections.txt`, `-overrides.txt`).
* **Build System Integration:** The script relies on the Meson build system to provide necessary parameters (source directory, build directory, etc.).

**6. User Errors and Debugging:**

* **Incorrect Arguments:** Users might provide wrong paths or options to the script.
* **Missing Dependencies:** `gtk-doc` or its related tools might not be installed.
* **Environment Issues:** Incorrectly set environment variables could cause problems.

**7. Tracing User Operations:**

The most common way to reach this script is through the Meson build system. A developer building Frida would typically:

1. **Clone the Frida repository.**
2. **Navigate to the Frida QML subdirectory.**
3. **Run Meson to configure the build (e.g., `meson setup build`).**
4. **Run Meson to compile (e.g., `meson compile -C build`).**

During the `meson compile` step, Meson will identify that documentation needs to be generated and will execute this `gtkdochelper.py` script with the appropriate arguments. The arguments would be derived from the `meson.build` files within the Frida QML project.

This systematic approach allows for a comprehensive understanding of the script's purpose, its relationship to reverse engineering, its interaction with low-level systems, and potential issues users might encounter.
This Python script, `gtkdochelper.py`, is a helper script used by the Meson build system to generate API documentation using `gtk-doc`. `gtk-doc` is a tool, commonly used in the GNOME ecosystem, to extract documentation from source code comments and generate various output formats like HTML.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Configuration Parsing:** It uses `argparse` to parse command-line arguments provided by the Meson build system. These arguments specify crucial information for the documentation generation process. Examples include:
    * Source and build directories
    * Subdirectory for documentation files
    * Header file directories
    * Main documentation file
    * Module name and version
    * Arguments for various `gtk-doc` tools
    * Compiler and linker information
    * Files to include in the documentation

2. **Execution of `gtk-doc` Tools:** The script orchestrates the execution of several `gtk-doc` utilities:
    * **`gtkdoc-scan`:** Scans source code for documentation comments and generates intermediate files.
    * **`gtkdoc-scangobj`:**  Scans compiled object files (especially for GObject-based libraries) to extract type information.
    * **`gtkdoc-mkdb`:**  Generates DocBook XML files from the scanned data. DocBook is a standard XML format for technical documentation.
    * **`gtkdoc-mkhtml`:** Converts the DocBook XML files into HTML documentation.
    * **`gtkdoc-fixxref`:** Fixes cross-references (links between different parts of the documentation) in the generated HTML.

3. **Environment Setup:** The `gtkdoc_run_check` function sets up the environment before executing `gtk-doc` commands, specifically handling library paths (`LD_LIBRARY_PATH` on Linux/macOS, `PATH` on Windows) to ensure that any dynamically linked libraries required by `gtk-doc` tools are found.

4. **File Management:** It copies necessary documentation source files (like `-sections.txt`, `-overrides.txt`) and HTML assets to the build directory.

5. **Installation:** The `install_gtkdoc` function handles the installation of the generated HTML documentation to the specified installation directory.

**Relationship to Reverse Engineering:**

While this script itself isn't a direct reverse engineering tool, it plays a crucial role in **documenting the API of Frida**. Good documentation is invaluable for reverse engineers who want to understand how Frida works and how to use its features effectively.

**Example:**

Imagine a reverse engineer wants to write a Frida script to hook a specific function in an Android application. To do this, they need to know the available Frida APIs for hooking, such as `Interceptor.attach()`. The documentation generated by this script would provide details on this function, its parameters, return values, and usage examples. Without such documentation, the reverse engineer would have to resort to more difficult methods like:

* **Reading Frida's source code directly:** Time-consuming and requires deep knowledge of the codebase.
* **Experimenting through trial and error:**  Inefficient and potentially error-prone.
* **Relying on community knowledge (if available):** Might not be complete or accurate.

**Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

* **Binary Underlying:**  The `gtkdoc-scangobj` tool operates on compiled object files. Object files are binary representations of compiled source code. Understanding the structure of object files (e.g., ELF on Linux, Mach-O on macOS) is a lower-level concept. The script uses compiler (`cc`) and linker (`ld`) flags, which are fundamental to the binary compilation process.
* **Linux:** The script explicitly handles the `LD_LIBRARY_PATH` environment variable, which is a standard mechanism on Linux and other Unix-like systems for specifying where to find shared libraries at runtime. This is crucial for executing dynamically linked binaries like the `gtk-doc` tools.
* **Android Kernel & Framework:** While the script itself doesn't directly interact with the Android kernel or framework, the *documentation it generates* likely covers Frida's APIs for interacting with Android processes. Frida, being a dynamic instrumentation tool, heavily relies on kernel-level features (like `ptrace` on Linux/Android) to intercept function calls and modify program behavior. The documentation might explain how to use Frida to hook into Android framework services or native libraries.

**Example:**

The `--ldflags` and `--cflags` arguments passed to the script can include flags specific to the target platform (e.g., Android). For instance, `--ldflags=-L/path/to/android/ndk/sysroot/usr/lib` would instruct the linker to look for libraries in the Android NDK's system root.

**Logical Reasoning (with Assumptions):**

**Assumption:** The input `mainfile` argument points to a file that contains the main structure of the documentation (e.g., an XML or SGML file).

**Input:**
```
--sourcedir=/path/to/frida/
--builddir=/path/to/frida/build/
--subdir=subprojects/frida-qml/docs
--headerdirs=src@@include
--mainfile=index.xml
--modulename=FridaQML
--moduleversion=1.0
--htmlargs=
--scanargs=
--scanobjsargs=
--gobjects-types-file=
--fixxrefargs=
--mkdbargs=
--ld=/usr/bin/ld
--cc=/usr/bin/gcc
--ldflags=-L/some/lib
--cflags=-I/some/include
--content-files=
--expand-content-files=
--html-assets=style.css
--ignore-headers=
--namespace=FridaQML
--mode=xml
--installdir=
--run=
--gtkdoc_scan=/usr/bin/gtkdoc-scan
--gtkdoc_scangobj=/usr/bin/gtkdoc-scangobj
--gtkdoc_mkdb=/usr/bin/gtkdoc-mkdb
--gtkdoc_mkhtml=/usr/bin/gtkdoc-mkhtml
--gtkdoc_fixxref=/usr/bin/gtkdoc-fixxref
```

**Output (likely actions):**

1. **`gtkdoc-scan` execution:**  `gtkdoc-scan --module=FridaQML --source-dir=/path/to/frida/src --source-dir=/path/to/frida/build/src --source-dir=/path/to/frida/include` would be executed in the `/path/to/frida/build/subprojects/frida-qml/docs` directory. This scans the source and include directories for documentation.
2. **`gtkdoc-mkdb` execution:** `gtkdoc-mkdb --module=FridaQML --output-format=xml --expand-content-files= --source-dir=/path/to/frida/src --source-dir=/path/to/frida/build/src --source-dir=/path/to/frida/include --name-space=FridaQML --xml-mode --main-sgml-file=index.xml` would be executed in the same directory. This generates DocBook XML.
3. **`gtkdoc-mkhtml` execution:** `gtkdoc-mkhtml --path=/path/to/frida/subprojects/frida-qml/docs:/path/to/frida/build/subprojects/frida-qml/docs FridaQML ../index.xml` would be executed in the `/path/to/frida/build/subprojects/frida-qml/docs/html` directory. This generates HTML from the DocBook XML.
4. **`gtkdoc-fixxref` execution:** `gtkdoc-fixxref --module=FridaQML --module-dir=html` would be executed in the `/path/to/frida/build/subprojects/frida-qml/docs` directory to fix cross-references in the generated HTML.
5. HTML files would be created in `/path/to/frida/build/subprojects/frida-qml/docs/html/`.

**User or Programming Common Usage Errors:**

1. **Incorrect Paths:** Providing incorrect paths for `--sourcedir`, `--builddir`, or `--headerdirs` will cause `gtk-doc` tools to fail to find the necessary files.
   * **Example:**  If `--headerdirs` is missing a directory where Frida's header files are located, `gtkdoc-scan` won't be able to extract documentation from those headers.

2. **Missing Dependencies:** If the `gtk-doc` toolchain (`gtkdoc-scan`, `gtkdoc-mkdb`, etc.) is not installed on the system, the script will fail with an error when trying to execute these commands.
   * **Error Message:**  `FileNotFoundError: [Errno 2] No such file or directory: 'gtkdoc-scan'`

3. **Incorrect `gtk-doc` Arguments:** Providing wrong arguments in `--scanargs`, `--htmlargs`, etc., can lead to unexpected output or errors from the `gtk-doc` tools.
   * **Example:**  A typo in a `--ignore-headers` argument might cause unintended headers to be processed.

4. **Malformed Documentation Comments:** If the comments in the source code are not in the format expected by `gtk-doc`, the documentation will be incomplete or incorrect.

5. **Permission Issues:**  The script might fail if it doesn't have the necessary permissions to create directories or write files in the build directory.

**User Operation Steps to Reach This Script (Debugging Clue):**

This script is typically executed as part of the **build process** of Frida when using the Meson build system. Here's a likely sequence of steps a user would take:

1. **Clone the Frida repository:** `git clone https://github.com/frida/frida`
2. **Navigate to the Frida directory:** `cd frida`
3. **Create a build directory:** `mkdir build`
4. **Navigate to the build directory:** `cd build`
5. **Configure the build using Meson:** `meson ..` (or `meson setup ..`)  This step reads the `meson.build` files in the Frida project.
6. **Compile the project using Meson:** `ninja` (or `meson compile`) This is the step where Meson will determine that documentation needs to be generated for the `frida-qml` subproject.
7. **Meson executes this `gtkdochelper.py` script.**  Meson reads the `meson.build` file in the `frida/subprojects/frida-qml` directory. This `meson.build` file will contain instructions on how to generate the documentation, including calling this `gtkdochelper.py` script with specific arguments.

**As a debugging clue:** If a user reports an issue with the generated Frida QML documentation, a developer would:

1. **Examine the Meson build logs:** Look for the specific command line used to execute `gtkdochelper.py` and any error messages from the `gtk-doc` tools.
2. **Check the `meson.build` file for the `frida-qml` subproject:** Verify the arguments passed to `gtkdochelper.py`.
3. **Reproduce the build process:** Try building Frida locally to see if the issue can be replicated.
4. **Inspect the intermediate files:** Examine the output of `gtkdoc-scan` and the generated DocBook XML to pinpoint where the documentation generation is going wrong.
5. **Verify the `gtk-doc` installation:** Ensure that the `gtk-doc` toolchain is correctly installed and accessible in the system's PATH.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/scripts/gtkdochelper.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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