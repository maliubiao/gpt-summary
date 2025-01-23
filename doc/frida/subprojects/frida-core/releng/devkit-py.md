Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality and relate it to reverse engineering, low-level details, and common user errors.

**1. Initial Skim and High-Level Understanding:**

The first step is a quick read-through to get a general idea. Keywords like `CompilerApplication`, `devkit`, `header`, `library`, `meson`, `pkgconfig` immediately suggest this script is involved in building or packaging software development kits (devkits), likely for use with the Frida dynamic instrumentation framework. The presence of platform-specific logic (MSVC vs. Unix) also stands out.

**2. Identifying Core Functionality - The `CompilerApplication` Class:**

The `CompilerApplication` class seems central. It takes a `kit` (like "frida-gum"), a `MachineSpec`, and `meson_config` as input. This points to the script being a step in a larger build process managed by Meson. The `run()` method is the main entry point.

**3. Analyzing the `run()` Method Step-by-Step:**

This is where the details emerge. I'd go through the `run()` method line by line, noting the key actions:

* **Initialization:** Setting up output directories, detecting compiler syntax.
* **Library Generation:** Calling `_generate_library()`. This is important as libraries are core to software.
* **Header Generation:** Creating a consolidated header file (`_generate_header()`). This header is crucial for using the devkit.
* **Example Generation:**  Creating a simple example (`_generate_example()`). This helps users get started.
* **Generating GIR (for `frida-core`):** Handling introspection data.
* **MSVC Assets:**  Copying Visual Studio project files.

**4. Delving into Helper Methods:**

The methods called by `run()` are where the more specific functionality resides.

* **`_generate_library()`:**  Uses `pkg-config` to get library information, resolves library paths, and then calls platform-specific library generation (`_do_generate_library_msvc` or `_do_generate_library_unix`). This clearly involves interaction with the system's build environment.
* **`_generate_header()`:** This method is more complex. It preprocesses the umbrella header, extracts included files, and then stitches them together. The conditional logic for different kits and operating systems is important. The handling of symbol mapping (`thirdparty_symbol_mappings`) is also a key aspect.
* **`_generate_example()`:**  Generates a basic C example, including compilation instructions.

**5. Identifying Connections to Reverse Engineering:**

Now, I'd specifically look for aspects relevant to reverse engineering:

* **Dynamic Instrumentation (Frida's Core Purpose):** The entire script is about building devkits *for* Frida. This is the most direct link. The devkit enables *using* Frida.
* **Headers and Libraries:**  Understanding the structure and content of the generated headers and libraries is fundamental to writing Frida scripts or extensions. Knowing what functions and data structures are available is crucial.
* **Symbol Mapping:** The renaming of third-party symbols is a common technique in reverse engineering to avoid conflicts and make things clearer.
* **Example Code:** The generated examples demonstrate basic usage, which is often the starting point for reverse engineering tasks with Frida.

**6. Identifying Low-Level and OS Concepts:**

* **Binary Libraries (`.a`, `.lib`):** The script manipulates these directly.
* **Linkers and Linker Flags:** The `-l`, `-L`, `-Wl` flags are direct interactions with the linker.
* **Operating System Differences:** The distinct handling for Windows (MSVC) and Unix-like systems is evident.
* **Android Kernel/Framework (in `_generate_header`):**  The inclusion of `frida-selinux.h` specifically for Android points to interaction with the Android security framework.
* **`pkg-config`:**  A standard tool for finding library information on Unix-like systems.
* **System Calls (Implicit):** While not directly in the code, Frida ultimately interacts with the OS kernel through system calls, and this devkit enables that interaction.

**7. Looking for Logical Reasoning and Assumptions:**

* **Assumptions about Build Environment:** The script assumes `meson`, `pkg-config`, and a C/C++ compiler are available.
* **Conditional Logic:**  The `if` statements based on `machine.os` and `kit` represent logical decisions based on input.
* **Deduplication:** The `deduplicate` function is a clear piece of logical processing.

**8. Considering User Errors:**

* **Missing Dependencies (`pkg-config` errors):**  If `pkg-config` can't find the required packages, the script will fail.
* **Incorrect Meson Configuration:** If the `meson_config` is wrong, the compiler or linker commands might fail.
* **Trying to Use the Devkit Incorrectly:**  The example code helps prevent basic usage errors, but more complex errors are possible.

**9. Tracing User Operations (Debugging Clues):**

To understand how a user might end up here, think about the typical Frida development workflow:

1. **Setting up a build environment:** This often involves using Meson.
2. **Configuring the build:** This might involve specifying target platforms and dependencies.
3. **Building Frida:** The Meson build system would invoke this `devkit.py` script as part of the process.
4. **Encountering a build error:** If something goes wrong during devkit generation, the traceback might lead to this script.

**Self-Correction/Refinement During the Process:**

* **Initial Overgeneralization:**  I might initially think the script *only* builds headers, but realizing the library generation is a major part would be a correction.
* **Understanding the "Umbrella Header":** I'd need to research what this term means in the context of C/C++ development (a single header that includes many others).
* **Connecting the Dots:** Explicitly linking the script's actions to concrete reverse engineering scenarios (like writing a Frida hook) is important.

By following this systematic approach, combining a broad overview with detailed analysis, and specifically looking for the aspects requested in the prompt, you can generate a comprehensive explanation of the script's functionality.
好的，让我们详细分析一下 `frida/subprojects/frida-core/releng/devkit.py` 这个文件。

**文件功能概述:**

这个 Python 脚本的主要功能是为 Frida 的不同组件（如 `frida-gum`, `frida-gumjs`, `frida-core`）生成软件开发工具包 (Devkit)。这个 Devkit 包含了编译和链接使用这些 Frida 组件所需的头文件、静态库以及示例代码。 简单来说，它是一个自动化工具，用于打包和提供 Frida 核心库的开发接口。

**与逆向方法的关系及举例说明:**

这个脚本本身不是一个直接的逆向工具，而是为逆向分析师**提供必要的开发环境**来使用 Frida。Frida 是一个动态插桩工具，广泛应用于逆向工程、安全研究和漏洞分析。

* **提供头文件:**  脚本生成的 `.h` 头文件定义了 Frida 库的 API，包括函数、数据结构和常量。逆向工程师在编写 Frida 脚本或扩展时，需要这些头文件来了解如何与 Frida 库进行交互。例如，如果逆向工程师想使用 Frida 的内存操作功能，他们需要查看 `frida-core.h` 中定义的 `Memory` 相关的函数，如 `Memory::read_ptr()`, `Memory::write_bytes()` 等。
* **生成静态库:** 脚本生成的 `.a` (Unix) 或 `.lib` (Windows) 静态库包含了 Frida 库的编译后代码。逆向工程师如果想将 Frida 的功能嵌入到自己的工具中，就需要链接这些静态库。例如，他们可能会编写一个 C++ 程序，使用 Frida 的 API 来自动化某些逆向任务，这时就需要这个静态库。
* **提供示例代码:**  脚本生成的 `-example.c` 文件提供了如何使用生成 Devkit 的基本示例。这可以帮助逆向工程师快速上手，了解如何编译和链接他们的 Frida 代码。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个脚本的实现过程和最终产物都涉及到许多底层的概念：

* **二进制底层:**
    * **静态库的生成和链接:** 脚本使用 `ar`, `libtool` (Unix) 或 `lib.exe` (Windows) 等工具来创建静态库，这些工具直接操作二进制文件格式。链接器（ld）将这些静态库与用户的代码组合成最终的可执行文件。
    * **符号映射 (Symbol Mapping):**  脚本中涉及重命名第三方库的符号（例如使用 `objcopy --redefine-syms`）。这通常是为了避免符号冲突，属于链接过程中的底层操作。
    * **目标文件 (.o):** 在 Unix 系统的静态库生成过程中，脚本会先提取 `.a` 文件中的 `.o` 目标文件，然后再重新打包。

* **Linux:**
    * **`pkg-config`:**  脚本大量使用 `pkg-config` 工具来查询 Frida 依赖库的编译和链接选项（Cflags 和 LDFLAGS）。`pkg-config` 是 Linux 系统中用于管理库依赖的标准工具。
    * **头文件搜索路径 (-I):** 脚本会解析 `pkg-config` 返回的 `-I` 参数，这些参数指定了编译器搜索头文件的路径。
    * **库文件搜索路径 (-L):** 脚本会解析 `pkg-config` 返回的 `-L` 参数，这些参数指定了链接器搜索库文件的路径。
    * **库文件命名约定 (lib*.a):** Linux 系统中静态库的命名通常以 `lib` 开头，以 `.a` 结尾。脚本会根据这个约定查找库文件。
    * **链接器标志 (-Wl):** 脚本处理了 `-Wl` 标志，这些标志直接传递给链接器，用于进行更细粒度的链接控制。

* **Android 内核及框架:**
    * **`frida-selinux.h`:** 脚本中特别提到了在生成 `frida-core` 的 Devkit 且目标平台为 Android 时，会包含 `frida-selinux.h` 头文件。这表明 Frida 在 Android 平台上会涉及到 SELinux 的相关操作。SELinux 是 Android 内核中的一个安全模块，用于强制访问控制。
    * **`clang` / `clang++`:**  在 Android 平台上，脚本倾向于使用 `clang` 或 `clang++` 作为编译器，这是 Android NDK 推荐的编译器。

**逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，例如：

* **判断编译器类型:**  `detect_compiler_argument_syntax` 函数会检查 C 编译器的输出来判断是 MSVC (Windows) 还是 Unix 风格的编译器，这会影响后续的库文件名和编译参数的处理。
    * **假设输入:** `meson_config["c"]` 指向的 C 编译器可执行文件路径。
    * **假设输出:** `"msvc"` 或 `"unix"` 字符串。
* **计算库文件名:** `compute_library_filename` 函数根据编译器类型来确定生成的静态库文件名。
    * **假设输入:** `kit` (例如 `"frida-gum"`) 和编译器参数语法 (例如 `"msvc"` 或 `"unix"`）。
    * **假设输出:**  `"frida-gum.lib"` (对于 MSVC) 或 `"libfrida-gum.a"` (对于 Unix)。
* **解析头文件依赖:** `ingest_header` 函数递归地解析 `#include` 指令，并将包含的头文件内容添加到最终的 Devkit 头文件中。
    * **假设输入:** 一个头文件的路径，所有头文件列表，已处理的头文件集合，以及用于存储结果的列表。
    * **假设输出:**  `result` 列表会追加当前头文件及其包含的头文件的内容。

**用户或编程常见的使用错误及举例说明:**

* **缺少依赖:** 如果系统缺少 Frida 依赖的库，`pkg-config` 命令可能会失败，导致脚本运行出错。
    * **错误示例:** 如果缺少 `glib` 库，`call_pkgconfig(["--cflags", "frida-core"], meson_config)` 可能会返回错误，提示找不到 `glib.pc` 文件。
* **Meson 配置错误:**  如果 `meson_config` 中的编译器路径、`pkg-config` 路径等配置不正确，脚本将无法正常工作。
    * **错误示例:** 如果 `meson_config["c"]` 指向了一个不存在的编译器，执行预处理命令时会报错。
* **环境配置问题:** `PKG_CONFIG_PATH` 环境变量设置不正确，可能导致 `pkg-config` 找不到所需的 `.pc` 文件。
    * **用户操作:** 用户在构建 Frida 时，可能没有正确设置 `PKG_CONFIG_PATH`，导致脚本运行时无法找到 Frida 依赖的库的信息。
* **编译器或链接器参数不兼容:** 手动修改或添加不兼容的编译或链接器参数可能会导致生成的 Devkit 无法正常使用。
    * **用户操作:** 用户可能尝试修改 `meson.build` 文件，添加一些不正确的编译器或链接器标志，导致生成的示例代码编译失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要基于 Frida 开发工具或扩展:** 这可能是为了自动化逆向分析任务，编写自定义的 Frida Gadget，或者将 Frida 集成到自己的安全工具中。
2. **用户尝试构建 Frida 项目或使用 Frida 的开发接口:** 这通常涉及到使用构建系统，如 Meson。用户会执行类似 `meson build` 和 `ninja` 的命令。
3. **Meson 构建系统执行构建脚本，包括 `devkit.py`:** 在构建 `frida-core` 或其子项目时，Meson 会调用 `devkit.py` 脚本来生成相应的 Devkit。
4. **脚本执行过程中发生错误:**  如果在 Devkit 生成过程中出现问题（例如找不到头文件、链接库失败等），Python 解释器会抛出异常。
5. **用户查看错误信息和调用堆栈:**  错误信息可能会指向 `devkit.py` 文件的某一行，调用堆栈会显示脚本的执行路径。
6. **用户打开 `devkit.py` 文件进行调试:** 为了理解错误原因，用户可能会查看 `devkit.py` 的源代码，分析脚本的逻辑，检查相关的环境变量和配置，例如 `meson_config` 的内容。

**总结:**

`devkit.py` 是 Frida 构建过程中的一个重要组成部分，它自动化了生成 Frida 开发工具包的过程。这个过程涉及到与操作系统底层功能（如库的链接和加载）、编译器和链接器工具链的交互，以及对 Linux 和 Android 等特定平台的适配。理解这个脚本的功能有助于深入了解 Frida 的构建过程和开发接口，并能帮助开发者排查构建过程中可能出现的问题。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/devkit.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
from collections import OrderedDict
import itertools
import locale
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Mapping, Sequence, Union

from . import env
from .machine_spec import MachineSpec


REPO_ROOT = Path(__file__).resolve().parent.parent

DEVKITS = {
    "frida-gum": ("frida-gum-1.0", Path("gum") / "gum.h"),
    "frida-gumjs": ("frida-gumjs-1.0", Path("gumjs") / "gumscriptbackend.h"),
    "frida-core": ("frida-core-1.0", Path("frida-core.h")),
}

ASSETS_PATH = Path(__file__).parent / "devkit-assets"

INCLUDE_PATTERN = re.compile(r"#include\s+[<\"](.*?)[>\"]")


class CompilerApplication:
    def __init__(self,
                 kit: str,
                 machine: MachineSpec,
                 meson_config: Mapping[str, Union[str, Sequence[str]]],
                 output_dir: Path):
        self.kit = kit
        package, umbrella_header = DEVKITS[kit]
        self.package = package
        self.umbrella_header = umbrella_header

        self.machine = machine
        self.meson_config = meson_config
        self.compiler_argument_syntax = None
        self.output_dir = output_dir
        self.library_filename = None

    def run(self):
        output_dir = self.output_dir
        kit = self.kit

        self.compiler_argument_syntax = detect_compiler_argument_syntax(self.meson_config)
        self.library_filename = compute_library_filename(self.kit, self.compiler_argument_syntax)

        output_dir.mkdir(parents=True, exist_ok=True)

        (extra_ldflags, thirdparty_symbol_mappings) = self._generate_library()

        umbrella_header_path = compute_umbrella_header_path(self.machine,
                                                            self.package,
                                                            self.umbrella_header,
                                                            self.meson_config)

        header_file = output_dir / f"{kit}.h"
        if not umbrella_header_path.exists():
            raise Exception(f"Header not found: {umbrella_header_path}")
        header_source = self._generate_header(umbrella_header_path, thirdparty_symbol_mappings)
        header_file.write_text(header_source, encoding="utf-8")

        example_file = output_dir / f"{kit}-example.c"
        example_source = self._generate_example(example_file, extra_ldflags)
        example_file.write_text(example_source, encoding="utf-8")

        extra_files = []

        extra_files += self._generate_gir()

        if self.compiler_argument_syntax == "msvc":
            for msvs_asset in itertools.chain(ASSETS_PATH.glob(f"{kit}-*.sln"), ASSETS_PATH.glob(f"{kit}-*.vcxproj*")):
                shutil.copy(msvs_asset, output_dir)
                extra_files.append(msvs_asset.name)

        return [header_file.name, self.library_filename, example_file.name] + extra_files

    def _generate_gir(self):
        if self.kit != "frida-core":
            return []

        gir_path = Path(query_pkgconfig_variable("frida_girdir", self.package, self.meson_config)) / "Frida-1.0.gir"
        gir_name = "frida-core.gir"

        shutil.copy(gir_path, self.output_dir / gir_name)

        return [gir_name]

    def _generate_header(self, umbrella_header_path, thirdparty_symbol_mappings):
        kit = self.kit
        package = self.package
        machine = self.machine
        meson_config = self.meson_config

        c_args = meson_config.get("c_args", [])

        include_cflags = query_pkgconfig_cflags(package, meson_config)

        if self.compiler_argument_syntax == "msvc":
            preprocessor = subprocess.run(meson_config["c"] + c_args + ["/nologo", "/E", umbrella_header_path] + include_cflags,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          encoding="utf-8")
            if preprocessor.returncode != 0:
                raise Exception(f"Failed to spawn preprocessor: {preprocessor.stderr}")
            lines = preprocessor.stdout.split("\n")

            mapping_prefix = "#line "
            header_refs = [line[line.index("\"") + 1:line.rindex("\"")].replace("\\\\", "/") for line in lines if line.startswith(mapping_prefix)]

            header_files = deduplicate(header_refs)
            frida_root_slashed = REPO_ROOT.as_posix()
            header_files = [Path(h) for h in header_files if bool(re.match("^" + frida_root_slashed, h, re.I))]
        else:
            header_dependencies = subprocess.run(
                meson_config["c"] + c_args + include_cflags + ["-E", "-M", umbrella_header_path],
                capture_output=True,
                encoding="utf-8",
                check=True).stdout
            _, raw_header_files = header_dependencies.split(": ", maxsplit=1)
            header_files = [Path(item) for item in shlex.split(raw_header_files) if item != "\n"]
            header_files = [h for h in header_files if h.is_relative_to(REPO_ROOT)]

        devkit_header_lines = []
        umbrella_header = header_files[0]
        processed_header_files = {umbrella_header}
        ingest_header(umbrella_header, header_files, processed_header_files, devkit_header_lines)
        if kit == "frida-gumjs":
            inspector_server_header = umbrella_header_path.parent / "guminspectorserver.h"
            ingest_header(inspector_server_header, header_files, processed_header_files, devkit_header_lines)
        if kit == "frida-core" and machine.os == "android":
            selinux_header = umbrella_header_path.parent / "frida-selinux.h"
            ingest_header(selinux_header, header_files, processed_header_files, devkit_header_lines)
        devkit_header = u"".join(devkit_header_lines)

        if package.startswith("frida-gumjs"):
            config = """#ifndef GUM_STATIC
# define GUM_STATIC
#endif

"""
        else:
            config = ""

        if machine.os == "windows":
            deps = ["dnsapi", "iphlpapi", "psapi", "shlwapi", "winmm", "ws2_32"]
            if package == "frida-core-1.0":
                deps.extend(["advapi32", "crypt32", "gdi32", "kernel32", "ole32", "secur32", "shell32", "user32"])
            deps.sort()

            frida_pragmas = f"#pragma comment(lib, \"{compute_library_filename(kit, self.compiler_argument_syntax)}\")"
            dep_pragmas = "\n".join([f"#pragma comment(lib, \"{dep}.lib\")" for dep in deps])

            config += f"#ifdef _MSC_VER\n\n{frida_pragmas}\n\n{dep_pragmas}\n\n#endif\n\n"

        if len(thirdparty_symbol_mappings) > 0:
            public_mappings = []
            for original, renamed in extract_public_thirdparty_symbol_mappings(thirdparty_symbol_mappings):
                public_mappings.append((original, renamed))
                if f"define {original}" not in devkit_header and f"define  {original}" not in devkit_header:
                    continue
                def fixup_macro(match):
                    prefix = match.group(1)
                    suffix = re.sub(f"\\b{original}\\b", renamed, match.group(2))
                    return f"#undef {original}\n{prefix}{original}{suffix}"
                devkit_header = re.sub(r"^([ \t]*#[ \t]*define[ \t]*){0}\b((.*\\\n)*.*)$".format(original), fixup_macro, devkit_header, flags=re.MULTILINE)

            config += "#ifndef __FRIDA_SYMBOL_MAPPINGS__\n"
            config += "#define __FRIDA_SYMBOL_MAPPINGS__\n\n"
            config += "\n".join([f"#define {original} {renamed}" for original, renamed in public_mappings]) + "\n\n"
            config += "#endif\n\n"

        return (config + devkit_header).replace("\r\n", "\n")

    def _generate_library(self):
        library_flags = call_pkgconfig(["--static", "--libs", self.package], self.meson_config).split(" ")

        library_dirs = infer_library_dirs(library_flags)
        library_names = infer_library_names(library_flags)
        library_paths, extra_flags = resolve_library_paths(library_names, library_dirs, self.machine)
        extra_flags += infer_linker_flags(library_flags)

        if self.compiler_argument_syntax == "msvc":
            thirdparty_symbol_mappings = self._do_generate_library_msvc(library_paths)
        else:
            thirdparty_symbol_mappings = self._do_generate_library_unix(library_paths)

        return (extra_flags, thirdparty_symbol_mappings)

    def _do_generate_library_msvc(self, library_paths):
        subprocess.run(self.meson_config["lib"] + ["/nologo", "/out:" + str(self.output_dir / self.library_filename)] + library_paths,
                       capture_output=True,
                       encoding="utf-8",
                       check=True)

        thirdparty_symbol_mappings = []

        return thirdparty_symbol_mappings

    def _do_generate_library_unix(self, library_paths):
        output_path = self.output_dir / self.library_filename
        output_path.unlink(missing_ok=True)

        v8_libs = [path for path in library_paths if path.name.startswith("libv8")]
        if len(v8_libs) > 0:
            v8_libdir = v8_libs[0].parent
            libcxx_libs = list((v8_libdir / "c++").glob("*.a"))
            library_paths.extend(libcxx_libs)

        meson_config = self.meson_config

        ar = meson_config.get("ar", ["ar"])
        ar_help = subprocess.run(ar + ["--help"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 encoding="utf-8").stdout
        mri_supported = "-M [<mri-script]" in ar_help

        if mri_supported:
            mri = ["create " + str(output_path)]
            mri += [f"addlib {path}" for path in library_paths]
            mri += ["save", "end"]
            subprocess.run(ar + ["-M"],
                           input="\n".join(mri),
                           encoding="utf-8",
                           check=True)
        elif self.machine.is_apple:
            subprocess.run(meson_config.get("libtool", ["xcrun", "libtool"]) +
                                ["-static", "-o", output_path] + library_paths,
                           capture_output=True,
                           check=True)
        else:
            combined_dir = Path(tempfile.mkdtemp(prefix="devkit"))
            object_names = set()

            for library_path in library_paths:
                scratch_dir = Path(tempfile.mkdtemp(prefix="devkit"))

                subprocess.run(ar + ["x", library_path],
                               cwd=scratch_dir,
                               capture_output=True,
                               check=True)
                for object_name in [entry.name for entry in scratch_dir.iterdir() if entry.name.endswith(".o")]:
                    object_path = scratch_dir / object_name
                    while object_name in object_names:
                        object_name = "_" + object_name
                    object_names.add(object_name)
                    shutil.move(object_path, combined_dir / object_name)

                shutil.rmtree(scratch_dir)

            subprocess.run(ar + ["rcs", output_path] + list(object_names),
                           cwd=combined_dir,
                           capture_output=True,
                           check=True)

            shutil.rmtree(combined_dir)

        objcopy = meson_config.get("objcopy", None)
        if objcopy is not None:
            thirdparty_symbol_mappings = get_thirdparty_symbol_mappings(output_path, meson_config)

            renames = "\n".join([f"{original} {renamed}" for original, renamed in thirdparty_symbol_mappings]) + "\n"
            with tempfile.NamedTemporaryFile() as renames_file:
                renames_file.write(renames.encode("utf-8"))
                renames_file.flush()
                subprocess.run(objcopy + ["--redefine-syms=" + renames_file.name, output_path],
                               check=True)
        else:
            thirdparty_symbol_mappings = []

        return thirdparty_symbol_mappings

    def _generate_example(self, source_file, extra_ldflags):
        kit = self.kit
        machine = self.machine

        os_flavor = "windows" if machine.os == "windows" else "unix"

        example_code = (ASSETS_PATH / f"{kit}-example-{os_flavor}.c").read_text(encoding="utf-8")

        if machine.os == "windows":
            return example_code
        else:
            if machine.is_apple or machine.os == "android":
                cc = "clang++" if kit == "frida-gumjs" else "clang"
            else:
                cc = "g++" if kit == "frida-gumjs" else "gcc"
            meson_config = self.meson_config
            cflags = meson_config.get("common_flags", []) + meson_config.get("c_args", [])
            ldflags = meson_config.get("c_link_args", [])

            (cflags, ldflags) = tweak_flags(cflags, extra_ldflags + ldflags)

            if cc == "g++":
                ldflags.append("-static-libstdc++")

            params = {
                "cc": cc,
                "cflags": shlex.join(cflags),
                "ldflags": shlex.join(ldflags),
                "source_filename": source_file.name,
                "program_filename": source_file.stem,
                "library_name": kit
            }

            preamble = """\
/*
 * Compile with:
 *
 * %(cc)s %(cflags)s %(source_filename)s -o %(program_filename)s -L. -l%(library_name)s %(ldflags)s
 *
 * Visit https://frida.re to learn more about Frida.
 */""" % params

            return preamble + "\n\n" + example_code


def ingest_header(header, all_header_files, processed_header_files, result):
    with header.open(encoding="utf-8") as f:
        for line in f:
            match = INCLUDE_PATTERN.match(line.strip())
            if match is not None:
                name_parts = tuple(match.group(1).split("/"))
                num_parts = len(name_parts)
                inline = False
                for other_header in all_header_files:
                    if other_header.parts[-num_parts:] == name_parts:
                        inline = True
                        if other_header not in processed_header_files:
                            processed_header_files.add(other_header)
                            ingest_header(other_header, all_header_files, processed_header_files, result)
                        break
                if not inline:
                    result.append(line)
            else:
                result.append(line)


def extract_public_thirdparty_symbol_mappings(mappings):
    public_prefixes = ["g_", "glib_", "gobject_", "gio_", "gee_", "json_", "cs_"]
    return [(original, renamed) for original, renamed in mappings if any([original.startswith(prefix) for prefix in public_prefixes])]


def get_thirdparty_symbol_mappings(library, meson_config):
    return [(name, "_frida_" + name) for name in get_thirdparty_symbol_names(library, meson_config)]


def get_thirdparty_symbol_names(library, meson_config):
    visible_names = list(set([name for kind, name in get_symbols(library, meson_config) if kind in ("T", "D", "B", "R", "C")]))
    visible_names.sort()

    frida_prefixes = ["frida", "_frida", "gum", "_gum"]
    thirdparty_names = [name for name in visible_names if not any([name.startswith(prefix) for prefix in frida_prefixes])]

    return thirdparty_names


def get_symbols(library, meson_config):
    result = []

    for line in subprocess.run(meson_config.get("nm", "nm") + [library],
                               capture_output=True,
                               encoding="utf-8",
                               check=True).stdout.split("\n"):
        tokens = line.split(" ")
        if len(tokens) < 3:
            continue
        (kind, name) = tokens[-2:]
        result.append((kind, name))

    return result


def infer_include_dirs(flags):
    return [Path(flag[2:]) for flag in flags if flag.startswith("-I")]


def infer_library_dirs(flags):
    return [Path(flag[2:]) for flag in flags if flag.startswith("-L")]


def infer_library_names(flags):
    return [flag[2:] for flag in flags if flag.startswith("-l")]


def infer_linker_flags(flags):
    return [flag for flag in flags if flag.startswith("-Wl") or flag == "-pthread"]


def resolve_library_paths(names, dirs, machine):
    paths = []
    flags = []
    for name in names:
        library_path = None
        for d in dirs:
            candidate = d / f"lib{name}.a"
            if candidate.exists():
                library_path = candidate
                break
        if library_path is not None and not is_os_library(library_path, machine):
            paths.append(library_path)
        else:
            flags.append(f"-l{name}")
    return (deduplicate(paths), flags)


def is_os_library(path, machine):
    if machine.os == "linux":
        return path.name in {"libdl.a", "libm.a", "libpthread.a"}
    return False


def query_pkgconfig_cflags(package, meson_config):
    raw_flags = call_pkgconfig(["--cflags", package], meson_config)
    return shlex.split(raw_flags)


def query_pkgconfig_variable(name, package, meson_config):
    return call_pkgconfig([f"--variable={name}", package], meson_config)


def call_pkgconfig(argv, meson_config):
    pc_env = {
        **os.environ,
        "PKG_CONFIG_PATH": os.pathsep.join(meson_config.get("pkg_config_path", [])),
    }
    return subprocess.run(meson_config.get("pkg-config", ["pkg-config"]) + argv,
                          capture_output=True,
                          encoding="utf-8",
                          check=True,
                          env=pc_env).stdout.strip()


def detect_compiler_argument_syntax(meson_config):
    if "Microsoft " in subprocess.run(meson_config["c"],
                      capture_output=True,
                      encoding=locale.getpreferredencoding()).stderr:
        return "msvc"

    return "unix"


def compute_library_filename(kit, compiler_argument_syntax):
    if compiler_argument_syntax == "msvc":
        return f"{kit}.lib"
    else:
        return f"lib{kit}.a"


def compute_umbrella_header_path(machine, package, umbrella_header, meson_config):
    for incdir in infer_include_dirs(query_pkgconfig_cflags(package, meson_config)):
        candidate = (incdir / umbrella_header)
        if candidate.exists():
            return candidate
    raise Exception(f"Unable to resolve umbrella header path for {umbrella_header}")


def tweak_flags(cflags, ldflags):
    tweaked_cflags = []
    tweaked_ldflags = []

    pending_cflags = cflags[:]
    while len(pending_cflags) > 0:
        flag = pending_cflags.pop(0)
        if flag == "-include":
            pending_cflags.pop(0)
        else:
            tweaked_cflags.append(flag)

    tweaked_cflags = deduplicate(tweaked_cflags)
    existing_cflags = set(tweaked_cflags)

    pending_ldflags = ldflags[:]
    seen_libs = set()
    seen_flags = set()
    while len(pending_ldflags) > 0:
        flag = pending_ldflags.pop(0)
        if flag in ("-arch", "-isysroot") and flag in existing_cflags:
            pending_ldflags.pop(0)
        else:
            if flag == "-isysroot":
                sysroot = pending_ldflags.pop(0)
                if "MacOSX" in sysroot:
                    tweaked_ldflags.append("-isysroot \"$(xcrun --sdk macosx --show-sdk-path)\"")
                elif "iPhoneOS" in sysroot:
                    tweaked_ldflags.append("-isysroot \"$(xcrun --sdk iphoneos --show-sdk-path)\"")
                continue
            elif flag == "-L":
                pending_ldflags.pop(0)
                continue
            elif flag.startswith("-L"):
                continue
            elif flag.startswith("-l"):
                if flag in seen_libs:
                    continue
                seen_libs.add(flag)
            elif flag == "-pthread":
                if flag in seen_flags:
                    continue
                seen_flags.add(flag)
            tweaked_ldflags.append(flag)

    pending_ldflags = tweaked_ldflags
    tweaked_ldflags = []
    while len(pending_ldflags) > 0:
        flag = pending_ldflags.pop(0)

        raw_flags = []
        while flag.startswith("-Wl,"):
            raw_flags.append(flag[4:])
            if len(pending_ldflags) > 0:
                flag = pending_ldflags.pop(0)
            else:
                flag = None
                break
        if len(raw_flags) > 0:
            merged_flags = "-Wl," + ",".join(raw_flags)
            if "--icf=" in merged_flags:
                tweaked_ldflags.append("-fuse-ld=gold")
            tweaked_ldflags.append(merged_flags)

        if flag is not None and flag not in existing_cflags:
            tweaked_ldflags.append(flag)

    return (tweaked_cflags, tweaked_ldflags)


def deduplicate(items):
    return list(OrderedDict.fromkeys(items))
```