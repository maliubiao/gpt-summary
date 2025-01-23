Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding of the Goal:**

The filename `devkit.py` and the comment at the top clearly indicate this script is involved in generating development kits for Frida. A "devkit" usually contains header files, libraries, and examples needed to build applications that interact with a specific library or framework. The `frida` prefix and the subdirectories suggest this devkit is for the Frida dynamic instrumentation tool.

**2. Identifying Key Components and Their Roles:**

I'll start by scanning the top-level definitions and classes to get a high-level view:

* **`DEVKITS` dictionary:** This maps logical kit names (e.g., "frida-gum") to package names ("frida-gum-1.0") and the path to an "umbrella header."  This immediately suggests the script handles different Frida components. The umbrella header is likely the main header file that includes other related headers.
* **`ASSETS_PATH`:** Points to a directory containing "devkit-assets."  This suggests pre-existing files (likely examples, project files) are used.
* **`INCLUDE_PATTERN`:** A regular expression for identifying `#include` directives. This reinforces the idea that the script manipulates header files.
* **`CompilerApplication` class:** This is the core of the script. It takes a kit name, machine specification, Meson configuration, and output directory as input. The `run()` method is the main entry point.

**3. Deeper Dive into `CompilerApplication.run()`:**

This method orchestrates the devkit generation. I'll analyze its steps:

* **Initialization:** Sets up internal variables based on the input.
* **Compiler Detection:** `detect_compiler_argument_syntax()` suggests handling differences between compilers (like MSVC vs. GCC/Clang).
* **Library Filename Computation:** `compute_library_filename()` likely creates a platform-specific library filename (e.g., `.lib` on Windows, `.a` on Linux).
* **Directory Creation:** Ensures the output directory exists.
* **Library Generation:** `_generate_library()` is crucial. It likely compiles or packages the necessary libraries. The return value of `extra_ldflags` and `thirdparty_symbol_mappings` hints at handling linking and symbol visibility.
* **Umbrella Header Path Computation:** `compute_umbrella_header_path()` finds the main header file.
* **Header File Generation:** `_generate_header()` seems responsible for creating the consolidated header file for the devkit. This involves parsing existing headers and potentially adding configuration.
* **Example File Generation:** `_generate_example()` creates a sample C program demonstrating how to use the generated devkit.
* **Extra File Generation:** `_generate_gir()` and handling MSVC assets suggest copying additional files.

**4. Examining Key Helper Methods:**

Now I'll look at the functions called by `CompilerApplication` to understand their specifics:

* **Header Processing (`_generate_header`, `ingest_header`):**  These functions parse header files, recursively include nested headers (following `#include` directives), and potentially add preprocessor definitions and linker pragmas. The handling of `thirdparty_symbol_mappings` in `_generate_header` is interesting and likely relates to managing symbol conflicts or providing access to specific symbols.
* **Library Generation (`_generate_library`, `_do_generate_library_msvc`, `_do_generate_library_unix`):**  These handle platform-specific library creation (static libraries). The Unix version shows logic for extracting object files from archives and recombining them, which is a common technique. The handling of `objcopy` and symbol renaming is relevant to controlling symbol visibility and potentially resolving conflicts.
* **Example Generation (`_generate_example`):** This generates platform-specific compile instructions.
* **Pkg-config Interaction (`query_pkgconfig_cflags`, `query_pkgconfig_variable`, `call_pkgconfig`):** Frida relies on `pkg-config` to find dependencies and their compilation flags.
* **Symbol Extraction (`get_thirdparty_symbol_mappings`, `get_thirdparty_symbol_names`, `get_symbols`):** These functions extract symbols from library files (using `nm`) and filter them to identify third-party symbols that need special handling.
* **Flag Manipulation (`infer_include_dirs`, `infer_library_dirs`, `infer_library_names`, `infer_linker_flags`, `resolve_library_paths`, `tweak_flags`):** These functions parse compiler and linker flags to extract relevant information and modify them as needed.
* **Platform/Compiler Detection (`detect_compiler_argument_syntax`):**  Distinguishes between MSVC and Unix-like compilers.

**5. Connecting to the Questions:**

Now I can address the specific questions:

* **Functionality:** Summarize the purpose of each major component and the overall goal of generating development kits.
* **Relationship to Reverse Engineering:**  Focus on how the generated devkit facilitates interaction with processes, memory, and functions, which are core aspects of dynamic instrumentation and reverse engineering.
* **Binary/Kernel/Framework Knowledge:** Highlight the aspects dealing with libraries (`.a`, `.lib`), linking, symbol management, and platform-specific concepts (like Android SELinux).
* **Logic and Assumptions:** Identify areas where the script makes decisions based on input (e.g., compiler type, OS) and describe the expected input and output.
* **User Errors:** Think about common mistakes users might make when using the generated devkit or the Frida tools that lead to this script being executed.
* **User Steps:**  Trace back the typical user actions that would trigger the execution of this script as part of generating a custom Frida environment.

**6. Refinement and Organization:**

Finally, I would organize the information logically, using clear headings and examples, to create the comprehensive explanation provided in the initial prompt's example answer. This involves synthesizing the information gathered in the previous steps and structuring it in a way that is easy to understand.

This detailed walkthrough allows for a systematic understanding of the script's purpose and its relation to the broader context of Frida and dynamic instrumentation.This Python script, `devkit.py`, part of the Frida dynamic instrumentation tool, is responsible for **generating development kits (devkits)** for different components of Frida. These devkits contain header files, static libraries, and example code that allow developers to write native extensions or interact with Frida's internals programmatically.

Here's a breakdown of its functionalities:

**1. Generates Header Files:**

* **Consolidates Headers:** It takes an "umbrella header" (a main header file that includes other related headers) and recursively includes all necessary headers into a single output header file (`frida-gum.h`, `frida-gumjs.h`, or `frida-core.h`).
* **Handles Inclusions:** It parses `#include` directives in the umbrella header and recursively includes the content of the referenced header files.
* **Platform-Specific Adjustments:** It might include platform-specific headers (e.g., `frida-selinux.h` on Android for `frida-core`).
* **Adds Compiler Pragmas (Windows):** For Windows, it adds `#pragma comment(lib, ...)` directives to automatically link against the generated static library and necessary system libraries (like `ws2_32.lib`).
* **Manages Symbol Mappings:** It handles renaming of third-party library symbols to avoid conflicts with Frida's own symbols.

**2. Generates Static Libraries:**

* **Packages Libraries:** It takes a list of static libraries (identified through `pkg-config`) and combines them into a single static library (`libfrida-gum.a`, `libfrida-gumjs.a`, or `libfrida-core.a`).
* **Platform-Specific Library Creation:** It uses different commands and approaches for creating static libraries on different platforms (e.g., `libtool` on macOS, `ar` on Linux, `lib.exe` on Windows).
* **Symbol Renaming (Optional):** On Unix-like systems, it can use `objcopy` to rename symbols from third-party libraries to avoid potential naming conflicts.

**3. Generates Example Code:**

* **Provides Basic Usage:** It creates a simple C example (`frida-gum-example.c`, etc.) demonstrating how to include the generated header file and link against the generated static library.
* **Platform-Specific Examples:** It might provide slightly different examples for Windows and Unix-like systems, particularly in the compilation instructions.

**4. Handles Different Frida Components (Kits):**

* **`DEVKITS` Dictionary:**  This dictionary defines the different Frida components (like `frida-gum`, `frida-gumjs`, `frida-core`) and their corresponding package names and umbrella header paths. This allows the script to generate devkits for specific parts of Frida.

**5. Integrates with Meson Build System:**

* **`meson_config`:** The script receives configuration information from the Meson build system, including paths to compilers, linkers, and flags.
* **`pkg-config` Usage:** It uses `pkg-config` to query information about Frida's dependencies (C flags, library paths, etc.).

**6. Platform Awareness:**

* **`MachineSpec`:** The script takes a `MachineSpec` object as input, which contains information about the target platform (OS, architecture). This allows it to generate devkits tailored to specific platforms.
* **Compiler Detection:** It detects the compiler type (MSVC or Unix-like) to adjust commands and flags accordingly.

**Relationship to Reverse Engineering:**

This script is directly related to reverse engineering because it enables developers to build tools that *perform* reverse engineering.

* **Example:** A reverse engineer might want to write a custom Frida gadget (a shared library injected into a process) to hook specific functions or modify program behavior. This script provides the necessary header files (`frida-gum.h`) and libraries (`libfrida-gum.a`) to interact with Frida's Gum engine, which is responsible for code instrumentation and manipulation. They would use the generated `frida-gum-example.c` as a starting point.

**Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge:**

* **Binary 底层:**
    * **Static Libraries (.a, .lib):** The script generates static libraries, which are archives of compiled object code. Understanding how static linking works is crucial here.
    * **Symbol Management:**  The script deals with symbol visibility and potential conflicts when combining multiple libraries. This touches upon concepts like symbol tables and linking.
    * **Object File Manipulation:**  On Unix, it extracts and recombines object files from existing libraries, requiring knowledge of the structure of these files.
* **Linux:**
    * **`ar` command:** Used for creating and manipulating archive files (static libraries).
    * **`pkg-config`:** A standard tool on Linux (and other Unix-like systems) for managing library dependencies.
    * **Shared Libraries and Linking:** While generating static libraries, the process inherently involves understanding how linking works in general on Linux.
* **Android Kernel & Framework:**
    * **SELinux:** The inclusion of `frida-selinux.h` for Android indicates the devkit exposes interfaces related to Security-Enhanced Linux, a security module in the Android kernel. This is important for Frida's ability to operate within the constraints of Android's security model.
    * **Frida Gadget Development:** The generated devkit is used to build Frida gadgets, which are often injected into Android processes. This requires understanding the Android application framework and how native code interacts with it.

**Logic and Assumptions (Hypothetical Example):**

**Assumption:** The user wants to generate a devkit for `frida-gum` on a Linux x86_64 system, using GCC.

**Input:**

* `kit`: "frida-gum"
* `machine`: A `MachineSpec` object indicating Linux OS and x86_64 architecture.
* `meson_config`: A dictionary containing paths to GCC, `ar`, `pkg-config`, and relevant flags obtained from the Meson build system. This would include paths where Frida's Gum library dependencies are located.
* `output_dir`: A specified directory where the devkit files will be generated.

**Output:**

* **`output_dir/frida-gum.h`:** A consolidated header file containing the content of `gum/gum.h` and all its recursively included headers.
* **`output_dir/libfrida-gum.a`:** A static library containing the compiled code of Frida's Gum engine and its dependencies.
* **`output_dir/frida-gum-example.c`:** A simple C file demonstrating how to include `frida-gum.h` and use some basic Gum functions. The compilation instructions would likely involve `gcc`, `-L.` (to include the current directory for libraries), and `-lfrida-gum`.

**User or Programming Common Usage Errors:**

* **Incorrect `meson_config`:** If the `meson_config` is not correctly set up (e.g., incorrect paths to compilers or dependencies), the script will fail to find the necessary tools or libraries.
    * **Example:** If the path to `pkg-config` is wrong, the script won't be able to query the C flags and library paths for Frida's dependencies, leading to errors in library generation.
* **Missing Dependencies:** If the required dependencies for Frida's components are not installed or their paths are not correctly configured in the build system, the script will fail to generate the static library.
    * **Example:** If the development packages for GLib (a dependency of Frida Gum) are not installed, `pkg-config` will not find them, and the linking stage of library generation will fail.
* **Incorrect Output Directory:** If the user doesn't have write permissions to the `output_dir`, the script will fail to create the files.

**User Operation Steps Leading to This Script:**

This script is typically executed as part of Frida's build process or when a developer explicitly requests to generate a devkit. Here's a possible sequence of steps:

1. **Developer Clones Frida Repository:** A developer downloads the Frida source code from GitHub or another source.
2. **Configures Build using Meson:** The developer uses the Meson build system to configure the build, specifying the desired build options and target platform. This involves running commands like `meson setup build`.
3. **Builds Frida:** The developer initiates the build process using a Meson command like `ninja -C build`.
4. **`devkit.py` is Invoked:** During the build process, Meson will identify the need to generate devkits for certain Frida components. Meson will then execute `devkit.py` with the appropriate arguments:
    * **How Meson Finds It:** The `meson.build` files within the Frida repository will contain instructions to run this script as a custom build step.
    * **Arguments Passed:** Meson will pass the necessary information to `devkit.py`, such as the target `kit` (e.g., "frida-gum"), the `MachineSpec` for the target platform, the `meson_config` dictionary containing build settings, and the desired `output_dir`.

**Debugging Clue:**

If the devkit generation fails, a developer would look at the output of the Meson build process. Error messages from `devkit.py` would indicate issues such as:

* **"Header not found"**:  Suggests a problem resolving the path to the umbrella header or its included files.
* **"Failed to spawn preprocessor"**:  Indicates issues with the C preprocessor configuration or finding the C compiler.
* **Errors during library creation (e.g., `ar`, `libtool` failing):** Points to problems with the linker, missing libraries, or incorrect linker flags.
* **`pkg-config` errors:** Suggests issues with the `pkg-config` setup or missing dependency information.

By examining these error messages and the arguments passed to `devkit.py`, developers can pinpoint the source of the problem and take corrective actions, such as installing missing dependencies or adjusting the build configuration.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/devkit.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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