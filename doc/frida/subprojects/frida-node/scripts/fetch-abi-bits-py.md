Response:
Let's break down the thought process for analyzing the Python script.

**1. Understanding the Goal:**

The first step is to understand the script's primary purpose. The filename `fetch-abi-bits.py` and the context of `frida-node` suggest it's related to retrieving information about Application Binary Interfaces (ABIs). The script takes runtime, target, OS, and architecture as input, further reinforcing this idea.

**2. Identifying Key Operations:**

Next, I'd scan the code for the main actions it performs. Keywords like `subprocess.run`, `urllib.request.urlopen`, `tarfile.open`, `json.loads`, `json.dumps`, and file operations (`exists`, `read_text`, `write_text`, `mkdir`, `rename`, `shutil.rmtree`) are good indicators.

* **Downloading:**  The script fetches files from URLs, likely Node.js or Electron headers and libraries.
* **Extracting:** It unpacks downloaded tar archives.
* **Running Commands:** It executes `npm` and `node` commands.
* **Parsing/Generating Data:** It reads and writes JSON, and seems to parse output from `node` and `node-gyp`.
* **File System Manipulation:** It creates directories, deletes them, and moves files.
* **Binary Manipulation (Crucially):**  The `redact_node_lib_symbols` function stands out, indicating low-level binary processing.

**3. Analyzing Function by Function (Top-Down):**

* **`main`:** This is the entry point. It parses arguments, checks for existing metadata, downloads assets if needed, runs npm commands, gets the ABI, loads node defines, saves metadata, and prints it. The conditional logic based on `metadata` existing suggests a caching mechanism.
* **`print_metadata`:**  Simple function to display the gathered information.
* **`load_dev_assets`:**  This is where the downloading and extraction happen. It handles different runtimes (node, electron, node-webkit) and operating systems. The logic for Windows library handling (redaction) is significant.
* **`load_node_defines`:** This part interacts with `node-gyp` to retrieve compiler definitions. The creation of a temporary `binding.gyp` file is a key detail.
* **`want_node_define`, `adapt_node_define`:** These functions filter and modify the compiler definitions.
* **`redact_node_lib_symbols`:** This is the most complex function. It reads the structure of a Windows `.lib` file, identifies symbols, and potentially renames certain Node.js-related symbols. The binary format parsing (using `struct.unpack`) is a strong indicator of low-level work.
* **Helper Functions:** The remaining functions (`function_name_to_cdecl_symbol`, `read_image_archive_member_header`, `read_import_object_header`, `update_string_pool`) are utilities for the binary manipulation.

**4. Connecting to Concepts:**

As I analyze each function, I relate it to the concepts mentioned in the prompt:

* **Reverse Engineering:** The script aims to understand the ABI, which is essential for interacting with Node.js native modules. The symbol redaction hints at obscuring or modifying aspects of the library, which could be related to security or compatibility considerations in a reverse engineering context.
* **Binary 底层 (Binary Low-Level):**  The `redact_node_lib_symbols` function directly manipulates the bytes of a `.lib` file, parsing headers and modifying symbol names. This is clearly a low-level binary operation.
* **Linux/Android Kernel & Framework:** While the script itself might run on these platforms, the downloaded assets and the focus on `.lib` files (Windows) suggest its primary target for binary manipulation is Windows. However, the script handles downloading different header formats, implying awareness of cross-platform needs. The use of `node-gyp` and the concept of ABIs are fundamental to building native modules on any platform.
* **Logical Inference:** The script makes decisions based on the input arguments (runtime, target, OS, arch) to determine which files to download and how to process them. The caching mechanism using the `metadata.json` file is another example of logical flow.

**5. Constructing Examples:**

Once I understand the functionality, I can create illustrative examples:

* **Reverse Engineering:**  Hypothesize a scenario where you're trying to understand how a native module interacts with Node.js. This script provides insights into the expected symbols and function signatures.
* **Binary 底层:**  Demonstrate the structure of a `.lib` file and how the redaction modifies it.
* **User Errors:** Think about common mistakes users might make when providing arguments or setting up their environment.

**6. Tracing User Actions (Debugging Clues):**

To understand how a user might reach this script, I consider the context of Frida and native module development:

* A developer wants to use Frida to instrument a Node.js application that uses native addons.
* Frida needs to interact with the native code.
* To do this, Frida needs to understand the ABI of the Node.js runtime the application is using.
* This script is part of the Frida tooling to automatically fetch and prepare this ABI information.

Therefore, a likely user path involves running a Frida script that targets a Node.js process. Frida, in turn, might execute this `fetch-abi-bits.py` script as part of its initialization process.

**Self-Correction/Refinement:**

During the analysis, I might encounter parts I don't fully understand. For instance, the exact purpose of redacting symbols might not be immediately obvious. In such cases, I would:

* **Consult Documentation:** Look for Frida or Node.js documentation related to ABIs, native modules, and symbol visibility.
* **Experiment (If Possible):**  Run the script with different inputs and observe the output.
* **Make Educated Guesses:** Based on the surrounding code, try to infer the purpose. For example, the "redact" term suggests hiding or modifying something, possibly for compatibility or internal reasons.

By following this structured approach, combining code analysis with conceptual understanding and example generation, I can effectively dissect and explain the functionality of the Python script.
This Python script, `fetch-abi-bits.py`, is a utility within the Frida framework specifically designed to gather essential information about the Application Binary Interface (ABI) of different JavaScript runtimes like Node.js, Electron, and Node-WebKit. This information is crucial for Frida to correctly interact with and instrument native addons used by these runtimes.

Let's break down its functionalities and connections to the areas you mentioned:

**Core Functionalities:**

1. **Determines the Target ABI:**  The script takes command-line arguments specifying the runtime (`node`, `electron`, `node-webkit`), target version, operating system (`gyp_os`), and architecture (`gyp_arch`). Based on these inputs, it figures out the specific ABI string (e.g., `nodeXX-abiYY`) required by native modules for that runtime. It leverages the `node-abi` npm package for this.

2. **Downloads Development Assets:**  It downloads the necessary header files and potentially library files for the specified runtime and target version.
    * For Node.js and Electron, it fetches the "headers" package from official distribution sites.
    * For Node-WebKit, it downloads the appropriate headers.
    * On Windows, it specifically downloads the `node.lib` file (and `nw.lib` for Node-WebKit) containing symbols necessary for linking native addons.

3. **Extracts and Organizes Files:**  The downloaded archives (typically `.tar.gz` or `.tar.xz`) are extracted into a temporary directory, and the relevant files are moved to an `abi-bits` subdirectory within the output directory.

4. **Gathers Compiler Defines:** It uses `node-gyp` (Node.js's native addon build tool) to determine the compiler definitions used when building native modules for the target runtime. This involves creating a temporary `binding.gyp` file (a `node-gyp` project file) and running `gyp.Load` to parse it and extract the compiler flags.

5. **Redacts Node.js Library Symbols (Windows Specific):** A crucial step, especially on Windows, is the `redact_node_lib_symbols` function. This function modifies the downloaded `node.lib` file. It iterates through the symbols within the library and renames symbols related to Node.js itself (starting with `napi_`, `node`, `uv_`) to prevent potential symbol conflicts when instrumenting the target application. This is a direct interaction with the binary structure of the library file.

6. **Stores and Prints Metadata:** All the gathered information (ABI string, compiler definitions, include directories, library files) is stored in a `abi-bits.json` file for caching and later use. The script also prints this metadata to the console.

**Relationship to Reverse Engineering:**

* **Understanding Native Addon Structure:**  By fetching the header files and understanding the ABI, this script provides essential building blocks for reverse engineers who want to analyze or modify native addons used by Node.js applications. The header files reveal the data structures and function signatures used in the native code.
* **Symbol Information:** The `redact_node_lib_symbols` function, despite its purpose of avoiding conflicts, indirectly provides insight into the symbols present in the Node.js library. A reverse engineer might be interested in these symbols to understand the internal workings of Node.js or to hook specific functions.
* **Example:** Imagine you are reverse engineering a Node.js application that uses a native addon for cryptographic operations. By knowing the ABI and having access to the Node.js headers (obtained through this script), you can understand the interfaces the native addon uses to interact with Node.js's crypto APIs (like `napi_create_object`, `napi_get_cb_info`, etc.). You can then use Frida to hook these interactions and observe the data being passed.

**Relationship to Binary 底层, Linux, Android Kernel & Framework:**

* **Binary 底层 (Binary Low-Level):** The `redact_node_lib_symbols` function directly operates on the binary structure of the Windows `.lib` file. It parses the archive format (`!<arch>\n`), reads member headers, and analyzes the import object headers within the library. It uses `struct.unpack` to interpret the binary data and modifies bytes in the file to rename symbols. This is a clear example of low-level binary manipulation.
* **Linux:** While the core binary manipulation of `.lib` files is Windows-specific, the script's ability to download headers and determine ABIs for Node.js on Linux demonstrates awareness of Linux environments. The `node-gyp` tool itself is cross-platform and used for building native modules on Linux as well.
* **Android Kernel & Framework:**  Although not explicitly targeting Android kernel development, the concepts of ABIs and native libraries are fundamental to Android. Node.js can be run on Android, and native modules can be built for Android's architecture. This script's logic for determining ABIs and fetching development assets is conceptually similar to what would be needed in an Android context, although the specific tools and file formats might differ. Frida is also a powerful tool for reverse engineering and dynamic analysis on Android.

**Logical Inference (Hypothetical Input & Output):**

**Hypothetical Input (Command-line arguments):**

```
python fetch-abi-bits.py node 16.0.0 linux x64 /path/to/node /output/dir /output/dir
```

**Logical Inferences and Potential Output Snippets:**

* **Runtime:** `node`
* **Target Version:** `16.0.0`
* **OS:** `linux`
* **Architecture:** `x64`
* **Script will download:** Node.js v16.0.0 headers for Linux x64 from `https://nodejs.org/dist/v16.0.0/node-v16.0.0-headers.tar.gz` (or similar).
* **ABI:** The script will likely determine the ABI string to be something like `node88` (the exact ABI number depends on the Node.js version).
* **`abi-bits.json` content (snippet):**
  ```json
  {
    "flavor": "node|16.0.0|linux|x64",
    "abi": "node88",
    "node_defines": [
      "NODE_WANT_INTERNALS=1",
      "V8_DEPRECATION_WARNINGS=1",
      // ... other compiler defines ...
    ],
    "node_incdirs": [
      "abi-bits/include/node"
      // ... other include directories ...
    ],
    "node_libs": [] // Likely empty on Linux as .lib redaction is Windows-specific
  }
  ```
* **Console Output (snippet):**
  ```
  abi: node88
  node_defines: NODE_WANT_INTERNALS=1 V8_DEPRECATION_WARNINGS=1 ...
  node_incdir: abi-bits/include/node
  ...
  ```

**User or Programming Common Usage Errors:**

1. **Incorrect Command-Line Arguments:**
   * **Example:**  Running the script without enough arguments or with incorrect values for runtime, target, OS, or architecture. This will likely lead to an `IndexError` or incorrect behavior.
   * **Error Message/Behavior:** The script might crash or download the wrong set of assets, leading to issues when Frida tries to interact with the target application.

2. **Network Issues:**
   * **Example:**  If the user's machine has no internet connection or cannot reach the Node.js or Electron download servers.
   * **Error Message/Behavior:** The script will raise `urllib.error.HTTPError` (likely a 404 if the version is not found or other network errors). The script attempts to handle 404 gracefully by trying different compression formats but other network errors will cause it to exit.

3. **Missing Dependencies (npm):**
   * **Example:** If `npm` is not installed or not in the system's PATH.
   * **Error Message/Behavior:** The `subprocess.run` calls involving `npm` will fail with a `FileNotFoundError`.

4. **Incorrect Output Directory Permissions:**
   * **Example:** If the user does not have write permissions to the specified output directory.
   * **Error Message/Behavior:** The script will encounter `PermissionError` when trying to create the `abi-bits` directory or write files to it.

**User Operation Steps to Reach This Script (as a debugging clue):**

The user likely doesn't directly execute this script in most common Frida usage scenarios. It's typically invoked internally by Frida itself. Here's a likely sequence:

1. **User Installs Frida:** The user installs the Frida Python package (`pip install frida-tools`).
2. **User Wants to Instrument a Node.js Application:** The user aims to use Frida to inspect or modify the behavior of a running Node.js, Electron, or Node-WebKit application that uses native addons.
3. **User Runs a Frida Script:** The user executes a Frida script using the `frida` command-line tool, targeting the specific process ID or name of the Node.js application.
4. **Frida Needs ABI Information:** When Frida starts instrumenting the target process, it needs to understand the ABI of the Node.js runtime to correctly interact with the native addons.
5. **Frida Invokes `fetch-abi-bits.py` (Internally):**  Behind the scenes, Frida (or a component within Frida like `frida-node`) determines that it needs the ABI information for the specific runtime and version being used by the target application. It then executes `fetch-abi-bits.py` with the appropriate arguments to gather this information. The arguments are derived from inspecting the target process or potentially from configuration settings.
6. **`fetch-abi-bits.py` Performs its Tasks:** The script downloads headers, extracts files, gathers compiler definitions, and potentially modifies the `node.lib` file.
7. **Frida Uses the Gathered Information:** Frida reads the `abi-bits.json` file created by the script to understand the ABI, include paths, and compiler definitions. This allows Frida to correctly load symbols from the native addons and inject JavaScript code that can interact with the native code.

Therefore, as a debugging clue, if a user encounters issues related to Frida not being able to instrument native addons or seeing errors related to missing headers or incorrect ABIs, investigating the output of `fetch-abi-bits.py` (or understanding if it was executed correctly) can be a valuable step.

### 提示词
```
这是目录为frida/subprojects/frida-node/scripts/fetch-abi-bits.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
from __future__ import annotations
from dataclasses import dataclass
from io import BytesIO, IOBase
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Union
import urllib.request


IMAGE_ARCHIVE_START = b"!<arch>\n"
IMAGE_FILE_MACHINE_UNKNOWN = 0
IMPORT_OBJECT_HDR_SIG2 = 0xffff


def main(argv: list[str]):
    runtime, target, gyp_os, gyp_arch = argv[1:5]
    flavor = "|".join(argv[1:5])
    node, npm, outdir = [Path(p) for p in argv[5:8]]

    abidir = outdir / "abi-bits"
    metadata_file = abidir / "abi-bits.json"

    metadata = None
    if metadata_file.exists():
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
        if metadata["flavor"] != flavor:
            metadata = None

    if metadata is None:
        if abidir.exists():
            shutil.rmtree(abidir)

        (node_incdirs, node_gypdir, node_libs) = load_dev_assets(runtime, target, gyp_os, gyp_arch,
                                                                 node, outdir, abidir)

        subprocess.run([npm, "init", "-y"],
                       capture_output=True,
                       cwd=abidir,
                       check=True)
        subprocess.run([npm, "install", "node-abi", "node-gyp"],
                       capture_output=True,
                       cwd=abidir,
                       check=True)

        abi = subprocess.run([node, "-e", f"console.log(require('node-abi').getAbi('{target}', '{runtime}'))"],
                             capture_output=True,
                             encoding="utf-8",
                             cwd=abidir,
                             check=True).stdout.strip()

        node_defines = load_node_defines(gyp_os, gyp_arch, node_gypdir,
                                         abidir / "node_modules" / "node-gyp" / "gyp" / "pylib")

        node_incdirs_rel = [d.relative_to(outdir) if d.is_relative_to(outdir) else d for d in node_incdirs]
        node_libs_rel    = [l.relative_to(outdir) if l.is_relative_to(outdir) else l for l in node_libs]

        metadata = {
            "flavor": flavor,
            "abi": abi,
            "node_defines": node_defines,
            "node_incdirs": [str(d) for d in node_incdirs_rel],
            "node_libs": [str(l) for l in node_libs_rel],
        }
        metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print_metadata(metadata)


def print_metadata(metadata: dict[str, Union[str, list[str]]]):
    print("abi:", metadata["abi"])
    print("node_defines:", " ".join(metadata["node_defines"]))
    for d in metadata["node_incdirs"]:
        print("node_incdir:", d)
    for l in metadata["node_libs"]:
        print("node_lib:", l)


def load_dev_assets(runtime: str,
                    target: str,
                    gyp_os: str,
                    gyp_arch: str,
                    node: Path,
                    outdir: Path,
                    abidir: Path) -> tuple[list[Path], Path, list[Path]]:
    if runtime == "node" and target == "" and gyp_os != "win":
        node_incroot = node.parent.parent / "include"
        node_incdir = node_incroot / "node"
        if node_incdir.exists():
            abidir.mkdir()
            node_gypdir = node_incdir
            node_libs = []
            return ([node_incdir, node_incroot], node_gypdir, node_libs)

    if target == "":
        version = subprocess.run([node, "--version"], capture_output=True, encoding="utf-8").stdout.strip()
    else:
        version = f"v{target}"

    node_arch = "x86" if gyp_arch == "ia32" else gyp_arch

    if runtime == "node":
        base_url = f"https://nodejs.org/dist/{version}"
        headers_stem = f"node-{version}-headers"
        libs_subpath = f"/win-{node_arch}"
        compression_formats = ["xz", "gz"]
    elif runtime == "electron":
        base_url = f"https://electronjs.org/headers/{version}"
        headers_stem = f"node-{version}-headers"
        libs_subpath = f"/win-{node_arch}"
        compression_formats = ["gz"]
    else:
        assert runtime == "node-webkit"
        base_url = f"https://node-webkit.s3.amazonaws.com/{version}"
        headers_stem = f"nw-headers-{version}"
        libs_subpath = "" if node_arch == "x86" else f"/{node_arch}"
        compression_formats = ["gz"]

    download_error = None
    for compression in compression_formats:
        try:
            with urllib.request.urlopen(f"{base_url}/{headers_stem}.tar.{compression}") as response:
                tar_blob = response.read()
        except urllib.error.HTTPError as e:
            download_error = e
            if e.code == 404:
                continue
            raise e

        with tarfile.open(fileobj=BytesIO(tar_blob), mode=f"r:{compression}") as tar:
            extracted_rootdir_name = tar.getnames()[0].split("/", maxsplit=1)[0]
            tar.extractall(outdir)

        download_error = None
        break
    if download_error is not None:
        print(download_error, file=sys.stderr)
        sys.exit(1)

    extracted_rootdir = outdir / extracted_rootdir_name

    node_libnames = []
    if gyp_os == "win":
        libdir = extracted_rootdir / "lib"
        libdir.mkdir()

        node_lib = libdir / "node.lib"
        with urllib.request.urlopen(f"{base_url}{libs_subpath}/node.lib") as response:
            vanilla_lib = response.read()
            redacted_lib = BytesIO(vanilla_lib)
            redact_node_lib_symbols(redacted_lib, gyp_arch)
            node_lib.write_bytes(redacted_lib.getvalue())
        node_libnames.append(node_lib.name)

        if runtime == "node-webkit":
            nw_lib = libdir / "nw.lib"
            with urllib.request.urlopen(f"{base_url}{libs_subpath}/nw.lib") as response:
                nw_lib.write_bytes(response.read())
            node_libnames.append(nw_lib.name)

    os.rename(extracted_rootdir, abidir)

    if runtime == "node-webkit":
        node_incdirs = [
            abidir / "src",
            abidir / "deps" / "uv" / "include",
            abidir / "deps" / "v8" / "include",
        ]
        node_gypdir = abidir
    else:
        incdir = abidir / "include" / "node"
        node_incdirs = [incdir]
        node_gypdir = incdir

    node_libs = [abidir / "lib" / name for name in node_libnames]

    return (node_incdirs, node_gypdir, node_libs)


def load_node_defines(gyp_os: str, gyp_arch: str, node_gypdir: Path, gyp_pylib: Path) -> list[str]:
    sys.path.insert(0, str(gyp_pylib))
    import gyp

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as binding_gyp:
        binding_gyp.write("""{
  "targets": [
    {
      "target_name": "frida_binding",
      "type": "loadable_module",
      "sources": [
        "src/addon.cc",
      ],
    },
  ],
}
""")
        binding_gyp.close()
        try:
            [generator, flat_list, targets, data] = \
                    gyp.Load([binding_gyp.name],
                             "compile_commands_json",
                             default_variables={
                                 "OS": gyp_os,
                                 "target_arch": gyp_arch,
                                 "MSVS_VERSION": "auto",
                                 "node_engine": "v8",
                             },
                             includes=[
                                 node_gypdir / "common.gypi",
                                 node_gypdir / "config.gypi",
                             ],
                             params={
                                 "options": GypOptions(),
                                 "parallel": False,
                                 "root_targets": None,
                             })
        finally:
            os.unlink(binding_gyp.name)

    target = targets[flat_list[0]]
    config = target["configurations"][target["default_configuration"]]
    return [adapt_node_define(d) for d in config["defines"] if want_node_define(d)]


def want_node_define(d: str) -> bool:
    if d.startswith("V8_") and "DEPRECATION_WARNINGS" in d:
        return False
    return True


def adapt_node_define(d: str) -> str:
    if d.startswith("BUILDING_"):
        return "USING_" + d[9:]
    if d == "_HAS_EXCEPTIONS=1":
        return "_HAS_EXCEPTIONS=0"
    return d


class GypOptions:
    generator_output = os.getcwd()


def redact_node_lib_symbols(lib: Path, gyp_arch: str):
    magic = lib.read(8)
    assert magic == IMAGE_ARCHIVE_START

    file_header = read_image_archive_member_header(lib)

    num_symbols, = struct.unpack(">I", lib.read(4))

    symbol_offsets = []
    for i in range(num_symbols):
        sym_offset, = struct.unpack(">I", lib.read(4))
        symbol_offsets.append(sym_offset)
    symbol_offsets = list(sorted(set(symbol_offsets)))

    string_pool_start = lib.tell()
    string_pool_end = symbol_offsets[0]

    renamed_symbols = {}
    node_prefixes = [function_name_to_cdecl_symbol(p, gyp_arch).encode("ascii") for p in {"napi_", "node", "uv_"}]
    for offset in symbol_offsets:
        lib.seek(offset)

        member_header = read_image_archive_member_header(lib)
        object_header = read_import_object_header(lib)

        if object_header.sig1 == IMAGE_FILE_MACHINE_UNKNOWN and \
                object_header.sig2 == IMPORT_OBJECT_HDR_SIG2:
            import_name_offset = lib.tell()
            strings = lib.read(object_header.size_of_data).split(b"\x00")
            import_name = strings[0]
            dll_name = strings[1]
            is_node_symbol = import_name.startswith(b"?") or (
                    next((p for p in node_prefixes if import_name.startswith(p)), None) is not None)
            if not is_node_symbol:
                new_prefix = b"X" if not import_name.startswith(B"X") else b"Y"
                redacted_name = new_prefix + import_name[1:]
                lib.seek(import_name_offset)
                lib.write(redacted_name)
                renamed_symbols[import_name] = redacted_name

    lib.seek(string_pool_start)
    string_pool = lib.read(string_pool_end - string_pool_start)
    lib.seek(string_pool_start)
    lib.write(update_string_pool(string_pool, renamed_symbols))


def function_name_to_cdecl_symbol(name: str, gyp_arch: str) -> str:
    if gyp_arch == "ia32":
        return "_" + name
    return name


def read_image_archive_member_header(f: IOBase) -> ImageArchiveMemberHeader:
    data = f.read(60)

    raw_name = data[:16].decode("utf-8")
    name = raw_name[:raw_name.index("/")]

    size = int(data[48:58].decode("utf-8"))

    return ImageArchiveMemberHeader(name, size, data)


def read_import_object_header(f: IOBase) -> ImportObjectHeader:
    data = f.read(20)

    (sig1, sig2, version, machine, time_date_stamp, size_of_data) \
            = struct.unpack("<HHHHII", data[:16])

    return ImportObjectHeader(sig1, sig2, version, machine, size_of_data, data)


def update_string_pool(pool: bytes, renames: dict[str, str]) -> bytes:
    return b"\x00".join(map(lambda s: renames.get(s, s), pool.split(b"\x00")))


@dataclass
class ImageArchiveMemberHeader:
    name: str
    size: int
    raw_header: bytes


@dataclass
class ImportObjectHeader:
    sig1: int
    sig2: int
    version: int
    machine: int
    size_of_data: int
    raw_header: bytes


if __name__ == "__main__":
    main(sys.argv)
```