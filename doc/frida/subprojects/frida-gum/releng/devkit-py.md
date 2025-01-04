Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The core purpose of this script is to generate development kits (devkits) for different parts of Frida (gum, gumjs, core). These devkits contain header files, pre-built static libraries, and example code to help developers interact with Frida's internals.

2. **Identify Key Classes and Functions:**  Scan the code for major building blocks:
    * `CompilerApplication`:  This class seems to be the central orchestrator for generating a devkit. It handles the different stages.
    * `DEVKITS`:  A dictionary defining the different Frida components for which devkits can be generated.
    * Helper functions like `ingest_header`, `get_thirdparty_symbol_mappings`, `resolve_library_paths`, etc. These likely perform specific, smaller tasks within the devkit generation process.

3. **Trace the Execution Flow (Conceptual):**  Imagine how the `CompilerApplication`'s `run` method would execute.
    * Initialization:  It takes the target kit, machine information, Meson configuration, and output directory as input.
    * Detect compiler syntax (MSVC vs. Unix).
    * Compute library filename.
    * Create the output directory.
    * Generate the static library (`_generate_library`).
    * Generate the main header file (`_generate_header`).
    * Generate an example C file (`_generate_example`).
    * Potentially generate extra files like GObject introspection data (`_generate_gir`).
    * Copy platform-specific assets (e.g., Visual Studio project files).

4. **Analyze Individual Components:**  Dive deeper into the key functions and methods:

    * **`CompilerApplication.__init__`:** Stores input parameters, sets up basic information about the target kit.
    * **`CompilerApplication.run`:** The main driver, orchestrating the devkit generation.
    * **`_generate_library`:** This is crucial for understanding the binary aspect. It uses `pkg-config` to find necessary libraries, resolves their paths, and then uses the archiver (`ar` or `libtool` on Unix, `lib` on Windows) to create a static library. The handling of third-party symbols is also important.
    * **`_generate_header`:** Focuses on creating the consolidated header file. It preprocesses the main umbrella header, resolves `#include` dependencies, and filters the relevant headers. The logic for handling different compilers (MSVC vs. Unix) is noteworthy.
    * **`_generate_example`:** Creates a simple C program demonstrating how to use the generated devkit. It takes into account platform differences for compilation commands.
    * **Helper functions:** Understand their roles (e.g., `ingest_header` recursively includes headers, `resolve_library_paths` finds the actual library files on disk, `get_thirdparty_symbol_mappings` deals with symbol renaming).

5. **Relate to Reverse Engineering:** Connect the script's functionalities to reverse engineering concepts.
    * **Header Generation:** Essential for understanding data structures, function signatures, and constants in the target Frida component.
    * **Static Library:** Provides pre-compiled code, allowing reverse engineers to link against Frida's internals in their tools or experiments. Understanding symbol mappings is crucial when interacting with this library.
    * **Example Code:** Offers a starting point for experimenting and understanding how to use the Frida API at a lower level.

6. **Identify System/Kernel Dependencies:** Look for interactions with the underlying operating system and potential kernel involvement.
    * **`pkg-config`:** A standard Unix tool for retrieving compiler and linker flags, essential for finding library dependencies.
    * **Archivers (`ar`, `libtool`, `lib`):** Operating system utilities for creating static libraries.
    * **File system operations:** Creating directories, copying files, reading/writing files.
    * **Process execution (`subprocess`):** Running external commands like the C preprocessor, compiler, archiver, and `nm`.
    * **Conditional logic based on `machine.os`:** Handling platform-specific differences (Windows vs. Unix). The Android case within `_generate_header` is a specific kernel-related point.

7. **Look for Logic and Assumptions:**  Identify any logical steps or assumptions made by the script.
    * **Assumption:**  `pkg-config` is available and correctly configured.
    * **Assumption:**  The necessary compilers and tools (like `ar`, `libtool`, `nm`, `objcopy`) are in the system's PATH.
    * **Logic:**  The header ingestion process prioritizes local headers within the Frida repository.
    * **Logic:**  Third-party symbols are renamed to avoid conflicts.

8. **Consider User Errors:** Think about common mistakes a user might make.
    * **Incorrect Meson Configuration:**  If the `meson_config` doesn't accurately reflect the build environment, the script might fail to find dependencies or use the wrong compiler flags.
    * **Missing Dependencies:** If `pkg-config` reports missing packages, the script won't be able to generate a complete devkit.
    * **Incorrect Output Directory:** Specifying a non-existent or write-protected output directory will cause errors.

9. **Trace User Interaction (Debugging Clues):**  Imagine the steps a developer would take to reach this code.
    * They are likely building Frida from source.
    * The Meson build system would call this Python script as part of the build process, specifically when generating the devkits.
    * Developers might encounter this code if they are investigating build issues or trying to understand how the Frida devkits are created.

10. **Structure the Explanation:** Organize the findings into logical sections covering the requested aspects (functionality, reverse engineering, OS/kernel, logic, errors, debugging). Use examples where appropriate to illustrate the concepts. Maintain clarity and conciseness.
This Python script, `devkit.py`, part of the Frida dynamic instrumentation toolkit, is responsible for **generating development kits (devkits)** for different components of Frida. These devkits contain header files and pre-built static libraries, making it easier for developers to integrate and interact with Frida's internal APIs.

Here's a breakdown of its functionalities and connections to the topics you mentioned:

**1. Core Functionality: Generating Development Kits**

* **Targeted Components:** The script generates devkits for `frida-gum`, `frida-gumjs`, and `frida-core`, as defined in the `DEVKITS` dictionary. Each devkit focuses on a specific part of Frida's architecture.
* **Output Contents:**  For each target component, the script creates:
    * A consolidated header file (e.g., `frida-gum.h`) containing declarations of relevant functions, structures, and constants.
    * A static library (e.g., `libfrida-gum.a` on Unix, `frida-gum.lib` on Windows) containing pre-compiled code.
    * An example C source file (e.g., `frida-gum-example.c`) demonstrating basic usage.
    * Potentially other files like GObject introspection data (`.gir` files).
* **Platform Awareness:** The script adapts to the target platform (Windows, Linux, macOS, Android) by adjusting compiler flags, library names, and build commands.

**2. Relationship with Reverse Engineering**

* **Providing Interface Definitions:** The generated header files are invaluable for reverse engineers. They provide:
    * **Function Signatures:**  Understanding the arguments and return types of Frida's internal functions is crucial for calling them programmatically.
    * **Data Structures:**  Header files define the layout of structures used within Frida, allowing reverse engineers to inspect and manipulate data.
    * **Constants and Macros:**  These provide symbolic names for important values and help understand the logic of Frida's internals.

    **Example:**  If a reverse engineer wants to understand how Frida's `Interceptor` class works (part of `frida-gum`), they can examine `frida-gum.h` to see the function signatures for creating interceptors, attaching to functions, and modifying their behavior. This is much easier than reverse engineering the raw binary.

* **Enabling Custom Tools and Extensions:** The static library allows developers (including reverse engineers) to link against Frida's core functionalities in their own tools or plugins. This enables building custom instrumentation agents or analysis tools that leverage Frida's capabilities.

    **Example:** A reverse engineer might write a custom tool that uses the `frida-gum` library to hook specific functions in a target process and log their arguments or modify their return values, going beyond the capabilities of Frida's standard command-line tools.

**3. Binary 底层, Linux, Android Kernel and Framework Knowledge**

* **Binary 底层 (Binary Low-Level):**
    * **Static Library Creation:** The script uses tools like `ar` (on Unix-like systems) and `lib.exe` (on Windows) to create static libraries from object files. This process involves understanding object file formats and linking.
    * **Symbol Management:** The script deals with symbol visibility and potential naming conflicts, especially with third-party libraries. It includes logic to rename symbols (`get_thirdparty_symbol_mappings`) to avoid collisions. This touches on concepts like symbol tables and linking.
    * **Object File Extraction:** On Unix systems, to handle static libraries containing multiple object files, the script extracts individual `.o` files, potentially renames them, and then re-archives them. This shows awareness of the structure of static libraries.

* **Linux:**
    * **`pkg-config` Usage:** The script heavily relies on `pkg-config` to retrieve compiler and linker flags for Frida's dependencies. This is a standard tool in the Linux ecosystem for managing library dependencies.
    * **Shared Library Conventions:** The script generates static libraries (`.a`), but it interacts with information about shared libraries through `pkg-config`.
    * **Process Execution:**  The `subprocess` module is used extensively to execute shell commands like `gcc`, `clang`, `ar`, `nm`, and `pkg-config`, which are fundamental to the Linux development environment.

* **Android Kernel and Framework:**
    * **Conditional Header Inclusion:** The script has specific logic to include `frida-selinux.h` when building the `frida-core` devkit for Android. This header likely deals with Security-Enhanced Linux (SELinux) policies, which are crucial for understanding security restrictions on Android.
    * **Cross-Compilation Considerations:** While not explicitly shown in this snippet, the broader Frida build process (which this script is a part of) needs to handle cross-compilation for Android's architecture (typically ARM or ARM64). The `MachineSpec` class likely plays a role in this.

**4. Logical Reasoning (Assumptions and Outputs)**

* **Assumption:** The script assumes that the necessary build tools (compilers, linkers, archivers, `pkg-config`) are installed and accessible in the system's PATH.
* **Assumption:** The `meson_config` dictionary contains correct information about the build environment, including the paths to compilers and flags.
* **Input (Hypothetical):** Let's assume the script is run to generate the devkit for `frida-gum` on a Linux system.
    * `kit` = "frida-gum"
    * `machine.os` = "linux"
    * `meson_config` contains paths to `gcc`, `ar`, `pkg-config`, and necessary compiler/linker flags obtained from the Meson build system.
* **Output (Expected):**
    * A directory (defined by `output_dir`) will be created.
    * Inside that directory:
        * `frida-gum.h`: A header file containing declarations from `gum/gum.h` and its dependencies.
        * `libfrida-gum.a`: A static library containing the compiled code for `frida-gum`.
        * `frida-gum-example.c`: A simple C program demonstrating how to use the `frida-gum` library.

**5. Common User or Programming Errors**

* **Missing Dependencies:** If the required libraries for `frida-gum` (as specified in its `pkg-config` file) are not installed, the `call_pkgconfig` function will likely fail, halting the devkit generation.

    **Example:** If the development files for GLib (a dependency of Frida) are not installed, `pkg-config --cflags frida-gum-1.0` might return an error.

* **Incorrect Meson Configuration:** If the `meson_config` is not set up correctly (e.g., wrong compiler paths), the `subprocess.run` calls to the compiler or linker will fail.

    **Example:** If the path to the C compiler in `meson_config["c"]` is incorrect, the attempt to preprocess the umbrella header will fail.

* **Conflicting Library Names:** If there are other libraries with the same name as Frida's internal libraries on the system, linking errors might occur when trying to compile the example code. The symbol renaming logic helps mitigate this but isn't foolproof.

* **Permissions Issues:** If the script doesn't have write permissions to the `output_dir`, it will fail to create the files.

**6. User Operation and Debugging Clues**

* **User Operation:** A developer typically doesn't interact with this script directly. It's part of Frida's build process, orchestrated by the Meson build system.
    1. The user would clone the Frida repository.
    2. They would use the `meson` command to configure the build, specifying build options and the output directory.
    3. They would then use the `ninja` command (or another backend configured with Meson) to compile and link Frida.
    4. During the build process, Meson will invoke this `devkit.py` script with the appropriate parameters to generate the devkits.

* **Debugging Clues:** If a developer encounters issues related to the devkit generation, they might:
    * **Examine the Meson build log:** This log will show the exact commands executed, including the calls to `devkit.py` and any errors encountered.
    * **Check the `meson_config`:** Inspect the `meson-info/intro-buildsystem_files.json` file in the build directory to see the configuration passed to the script.
    * **Run the script manually (with caution):** A developer could try running `devkit.py` directly, providing the necessary arguments (though this requires understanding the expected inputs). This can help isolate problems within the script itself.
    * **Verify dependencies:** Ensure that `pkg-config` is working correctly and that all the necessary development packages for Frida's dependencies are installed.
    * **Check file permissions:** Ensure the build process has write access to the output directory.

In summary, `devkit.py` is a crucial part of Frida's build system, responsible for creating developer-friendly packages that expose Frida's internal APIs. It demonstrates knowledge of system-level programming, build processes, and platform-specific conventions, and its output is essential for extending and understanding Frida's capabilities.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/devkit.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```