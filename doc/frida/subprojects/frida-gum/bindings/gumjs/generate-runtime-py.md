Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The immediate goal is to figure out what this script *does*. The filename and the import statements (`base64`, `json`, `os`, `pathlib`, `subprocess`, etc.) give strong hints. It's clearly involved in generating some kind of runtime environment. The "frida" and "gumjs" in the path suggest this is related to Frida's JavaScript bridge.

2. **Identify Key Functions:**  The `main` function is the entry point. It parses command-line arguments and calls `generate_runtime`. `generate_runtime` is the core function, and within it, we see calls to other `generate_runtime_*` functions (`generate_runtime_quick`, `generate_runtime_v8`, `generate_runtime_cmodule`). This suggests a modular approach, handling different runtime environments.

3. **Trace Data Flow in `generate_runtime`:**
    * It sets up a private directory (`priv_dir`) and installs necessary npm packages (`frida-compile`, `frida-java-bridge`, etc.). This immediately flags it as a build-time script.
    * It copies source files from `input_dir` to `runtime_intdir`.
    * It then conditionally calls different compilation functions based on the `backends` argument ("qjs" for QuickJS, "v8" for V8).
    * Finally, it calls `generate_runtime_cmodule` and creates an empty `runtime.bundle` file.

4. **Analyze Individual `generate_runtime_*` Functions:**
    * **`generate_runtime_quick` and `generate_runtime_v8`:**  These functions are very similar. They iterate through input JavaScript files, compile them using `frida-compile`, and then generate C header files (`gumquickscript-*.h`, `gumv8script-*.h`). These header files contain the compiled bytecode or source code as C arrays. They also handle source maps.
    * **`generate_runtime_cmodule`:** This one is different. It focuses on C headers. It searches for header files in specified directories, extracts function and variable declarations, and writes them into a C header (`gumcmodule-runtime.h`). It also creates a symbol table for these C functions and variables.

5. **Connect to Frida Concepts:**  The names of the generated header files (`gumquickscript-*`, `gumv8script-*`, `gumcmodule-*`) strongly indicate these are components of Frida's Gum runtime. Frida needs to execute JavaScript within a target process. It uses different JavaScript engines (QuickJS and V8). It also needs to interact with the target process's C/C++ code.

6. **Relate to Reverse Engineering:**
    * **Hooking:** The generated code likely enables Frida to inject and execute JavaScript code into a target process. This JavaScript can then be used to hook functions, inspect memory, and modify program behavior – core reverse engineering techniques.
    * **Bypassing Protections:** Frida is often used to bypass anti-debugging or anti-tampering mechanisms. This script's role in creating the runtime environment is foundational to these capabilities.
    * **Dynamic Analysis:** Frida is a dynamic analysis tool. This script is responsible for setting up the environment where dynamic analysis can occur.

7. **Identify Binary/Kernel/Framework Connections:**
    * **Binary Level:** The script compiles JavaScript into bytecode (QuickJS) or directly uses source code (V8), which is then embedded into C headers as byte arrays. This is a direct interaction with binary representations.
    * **Linux/Android:**  Frida is heavily used on Linux and Android. The script doesn't directly interact with the kernel, but the *purpose* of the generated runtime is to interact with processes running on these operating systems. The mentions of architecture (`arch`, `endian`) are relevant to these platforms.
    * **Frameworks (Java/Objective-C/Swift):** The script explicitly includes dependencies for `frida-java-bridge`, `frida-objc-bridge`, and `frida-swift-bridge`. This signifies that the generated runtime supports interaction with these language runtimes.

8. **Look for Logic and Assumptions:**
    * **Assumptions about Input:** The script assumes the presence of specific files in the input directories. It relies on the `frida-compile` tool being available.
    * **Conditional Logic:** The `if "qjs" in backends:` and `if "v8" in backends:` blocks show conditional compilation based on the desired JavaScript engine.
    * **String Manipulation:**  Functions like `identifier` show logic for transforming filenames into valid C identifiers.

9. **Consider User Errors:**
    * **Missing Dependencies:** If npm or `frida-compile` are not installed, the script will fail.
    * **Incorrect Paths:**  Providing wrong paths for input or output directories will cause errors.
    * **Invalid `backends`:** Specifying an invalid backend will lead to parts of the runtime not being generated.

10. **Trace User Actions (Debugging Perspective):**
    * A developer working on Frida's internals might modify the JavaScript or C code in the input directories.
    * They would then run a build process that includes executing this `generate-runtime.py` script.
    * If something goes wrong, they would examine the command-line arguments passed to the script, check the output of the `subprocess.run` calls for errors, and potentially step through the Python code using a debugger. The print statement in the `try...except` block is a basic error reporting mechanism.

11. **Refine and Organize:** Finally, organize the observations into clear categories (functionality, reverse engineering relevance, binary/kernel/framework details, logic, user errors, debugging). Use examples where possible to illustrate the points. This step involves structuring the information logically and using precise language.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/generate-runtime.py` 这个 Python 脚本的功能。

**脚本的主要功能：**

这个脚本的主要功能是为 Frida 的 Gum 模块生成 JavaScript 运行时的 C 语言头文件。这些头文件包含了编译后的 JavaScript 代码（用于 QuickJS）或 JavaScript 源代码（用于 V8），以及相关的元数据，这些数据会被编译到 Frida 的 Gum 库中。这样做的好处是可以将 JavaScript 运行时环境嵌入到 Gum 库中，避免在运行时动态加载，提高效率和安全性。

具体来说，脚本执行以下任务：

1. **设置编译环境:**
   - 创建一个临时的私有目录 (`priv_dir`)。
   - 如果 `frida-compile` 工具不存在，则使用 `npm` 初始化一个 Node.js 项目，并安装必要的依赖包，包括 `frida-compile`（用于编译 JavaScript 代码）、`frida-java-bridge`、`frida-objc-bridge` 和 `frida-swift-bridge`（这些桥接库的 JavaScript 代码也会被包含进来）。

2. **复制运行时源代码:**
   - 将 `input_dir/runtime` 目录下的 JavaScript 运行时源代码复制到临时目录中。

3. **编译 JavaScript 代码 (针对 QuickJS):**
   - 如果指定的后端包含 `qjs` (QuickJS)，则使用 `frida-compile` 将 `runtime/entrypoint-quickjs.js`、`runtime/objc.js`、`runtime/swift.js` 和 `runtime/java.js` 编译成 QuickJS 字节码。
   - 然后，调用 `generate_runtime_quick` 函数，将这些字节码和相关的 Source Map 数据嵌入到 C 头文件 (`gumquickscript-runtime.h` 等) 中。

4. **处理 JavaScript 源代码 (针对 V8):**
   - 如果指定的后端包含 `v8`，则使用 `frida-compile` 将 `runtime/entrypoint-v8.js`、`runtime/objc.js`、`runtime/swift.js` 和 `runtime/java.js` 进行处理（通常是压缩）。
   - 然后，调用 `generate_runtime_v8` 函数，将这些 JavaScript 源代码和相关的 Source Map 数据嵌入到 C 头文件 (`gumv8script-runtime.h` 等) 中。

5. **生成 C 模块头文件:**
   - 调用 `generate_runtime_cmodule` 函数，扫描指定的 C 头文件目录（包括 Gum 模块自身的头文件、Capstone 反汇编库的头文件、以及可选的 TinyCC 库的头文件）。
   - 将这些头文件的内容嵌入到 `gumcmodule-runtime.h` 文件中，并提取其中的函数和变量声明，创建一个符号表。

6. **创建运行时捆绑文件:**
   - 创建一个空的 `runtime.bundle` 文件，目前看来这个文件在这个脚本中没有实际用途，可能在 Frida 的其他部分被使用。

**与逆向方法的关联及举例说明：**

这个脚本是 Frida 动态 Instrumentation 工具链中的一个关键构建步骤，它直接支持了 Frida 的核心逆向能力：

- **代码注入和执行:** 通过将 JavaScript 运行时嵌入到 Gum 库中，Frida 可以在目标进程中注入和执行 JavaScript 代码。逆向工程师可以编写 JavaScript 脚本来 hook 函数、修改内存、跟踪程序执行流程等。例如，一个逆向工程师可能想要 hook `malloc` 函数来跟踪内存分配：
  ```javascript
  // Frida JavaScript 脚本
  Interceptor.attach(Module.findExportByName(null, 'malloc'), {
    onEnter: function (args) {
      console.log('malloc called with size: ' + args[0]);
    },
    onLeave: function (retval) {
      console.log('malloc returned address: ' + retval);
    }
  });
  ```
  这个脚本能够运行的前提就是 Frida 能够在一个目标进程中拥有一个 JavaScript 运行时环境，而这个脚本正是负责构建这个环境的一部分。

- **动态分析:** Frida 允许逆向工程师在程序运行时动态地检查和修改其行为。生成的运行时环境是 Frida 实现动态分析功能的基础。例如，逆向工程师可以使用 Frida 脚本来修改函数的返回值，从而绕过某些安全检查或改变程序的行为进行测试。

- **跨平台逆向:** Frida 支持多种操作系统和架构。这个脚本通过参数 `backends`、`arch` 和 `endian` 来生成不同后端和架构的运行时环境，使得 Frida 能够跨平台运行和进行逆向分析。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

这个脚本虽然是 Python 代码，但它生成的 C 头文件和最终构建的 Gum 库与二进制底层和操作系统内核及框架密切相关：

- **二进制底层:**
  - **字节码:** 对于 QuickJS 后端，脚本将 JavaScript 代码编译成字节码，这些字节码是 JavaScript 代码的一种更底层的二进制表示形式，可以直接被 QuickJS 虚拟机执行。`generate_runtime_quick` 函数将这些字节码嵌入到 C 数组中。
  - **架构 (arch) 和字节序 (endian):** 脚本接收 `arch` 和 `endian` 参数，用于指定目标架构和字节序。例如，如果 `arch` 是 `arm` 且 `endian` 是 `little`，则生成的运行时环境将针对小端序的 ARM 架构。`generate_runtime_quick` 函数中会根据字节序设置 QuickJS 的编译选项 (`--bswap`)。
  - **C 头文件:**  脚本最终生成的是 C 头文件，这些头文件会被 C/C++ 编译器编译成二进制代码，成为 Gum 库的一部分。

- **Linux/Android 内核及框架:**
  - **系统调用:** Frida 的 Gum 模块最终会通过系统调用与操作系统内核进行交互，例如内存分配、进程控制等。虽然这个脚本本身不直接操作系统调用，但它生成的运行时环境是 Frida 进行这些操作的基础。
  - **动态链接:** Frida 通常以动态库的形式注入到目标进程中。生成的运行时环境需要能够与目标进程的内存空间和动态链接器协同工作。
  - **Android 框架:** 脚本中包含了 `frida-java-bridge`，这表明生成的运行时环境支持与 Android 的 Java 框架进行交互。逆向工程师可以使用 Frida 脚本来 hook Android 框架中的 Java 方法。
  - **Objective-C/Swift 运行时:** 同样，`frida-objc-bridge` 和 `frida-swift-bridge` 表明 Frida 能够与 iOS 和 macOS 上的 Objective-C 和 Swift 运行时进行交互。

- **Capstone 反汇编库:** 脚本中包含了对 Capstone 头文件的处理。Capstone 是一个多架构的反汇编库，Frida 使用它来分析目标进程的机器码。`generate_runtime_cmodule` 函数负责将 Capstone 的头文件嵌入到 Gum 库中，使得 Gum 库可以使用 Capstone 的功能。

**逻辑推理、假设输入与输出：**

假设我们调用这个脚本时传入以下参数：

```
argv = [
    "generate-runtime.py",
    "/path/to/output",           # output_dir
    "/path/to/priv",             # priv_dir
    "/path/to/input",            # input_dir
    "/path/to/gum",              # gum_dir
    "/path/to/capstone/include", # capstone_incdir
    "/path/to/libtcc/include",   # libtcc_incdir
    "/usr/bin/npm",              # npm
    "/path/to/quickjs/qjsc",     # quickcompile
    "qjs,v8",                     # backends
    "arm64",                     # arch
    "little"                     # endian
]
```

**逻辑推理：**

1. **依赖安装:** 脚本会检查 `/path/to/priv/node_modules/.bin/frida-compile` 是否存在。如果不存在，则会在 `/path/to/priv` 目录下初始化一个 Node.js 项目，并安装 `frida-compile`、`frida-java-bridge`、`frida-objc-bridge` 和 `frida-swift-bridge`。
2. **QuickJS 编译:** 由于 `backends` 包含 `qjs`，脚本会使用 `/path/to/quickjs/qjsc` 编译 `input_dir/runtime` 目录下的 JavaScript 文件，并将生成的字节码嵌入到 `/path/to/output/gumquickscript-runtime.h` 等文件中。由于 `endian` 是 `little`，`qcflags` 会包含 `--bswap`。
3. **V8 处理:** 由于 `backends` 包含 `v8`，脚本会使用 `frida-compile` 处理 `input_dir/runtime` 目录下的 JavaScript 文件，并将处理后的源代码嵌入到 `/path/to/output/gumv8script-runtime.h` 等文件中。
4. **C 模块处理:** 脚本会扫描 `/path/to/input/runtime/cmodule`、`/path/to/gum/arch-arm64` 和 `/path/to/capstone/include` 目录下的头文件，并将它们的内容嵌入到 `/path/to/output/gumcmodule-runtime.h` 文件中。还会提取这些头文件中的函数和变量声明，生成符号表。
5. **输出文件:** 最终会在 `/path/to/output` 目录下生成以下文件：
   - `gumquickscript-runtime.h`
   - `gumquickscript-objc.h`
   - `gumquickscript-swift.h`
   - `gumquickscript-java.h`
   - `gumv8script-runtime.h`
   - `gumv8script-objc.h`
   - `gumv8script-swift.h`
   - `gumv8script-java.h`
   - `gumcmodule-runtime.h`
   - `runtime.bundle` (内容为空)

**用户或编程常见的使用错误及举例说明：**

1. **缺少依赖:** 如果用户环境中没有安装 `npm` 或 `frida-compile`，脚本在尝试安装依赖时会失败。例如，如果 `npm` 不在系统的 PATH 环境变量中，会抛出 `FileNotFoundError: [Errno 2] No such file or directory: 'npm'`.
2. **路径错误:** 如果用户提供的输入目录或输出目录路径不正确，脚本在尝试访问这些目录或文件时会出错。例如，如果 `/path/to/input` 目录不存在，`shutil.copytree(runtime_srcdir, runtime_intdir)` 会抛出 `FileNotFoundError: [Errno 2] No such file or directory: '/path/to/input/runtime'`.
3. **QuickJS 编译器路径错误:** 如果用户提供的 QuickJS 编译器路径 (`quickcompile`) 不正确，脚本在尝试编译 QuickJS 代码时会失败。例如，如果 `/path/to/quickjs/qjsc` 不存在或不可执行，`subprocess.run([quickcompile] ...)` 会抛出 `FileNotFoundError: [Errno 2] No such file or directory: '/path/to/quickjs/qjsc'`.
4. **权限问题:** 如果脚本没有在输出目录创建文件的权限，或者没有读取输入目录文件的权限，会导致相应的操作失败。
5. **Node.js 环境问题:**  `npm install` 可能会因为网络问题或 Node.js 版本兼容性问题而失败。

**用户操作是如何一步步到达这里，作为调试线索：**

通常，用户不会直接运行这个 `generate-runtime.py` 脚本。这个脚本是 Frida 构建过程的一部分。以下是用户操作如何间接导致这个脚本被执行的典型场景：

1. **开发者修改 Frida 源代码:** Frida 的开发者可能会修改 `frida-gum` 模块中的 JavaScript 运行时代码（在 `input_dir/runtime` 目录下）或者相关的 C 头文件。
2. **执行 Frida 的构建脚本:** 开发者会执行 Frida 的构建脚本（例如，使用 Meson 构建系统），这个构建脚本会分析项目的依赖关系和构建步骤。
3. **触发 `generate-runtime.py` 脚本:** Meson 构建系统会检测到需要生成 JavaScript 运行时环境，并调用 `generate-runtime.py` 脚本。它会根据构建配置（例如，目标架构、后端）传递相应的参数给这个脚本。
4. **脚本执行并生成文件:** `generate-runtime.py` 脚本按照前面描述的步骤执行，生成必要的 C 头文件。
5. **C/C++ 编译:**  构建系统会继续编译 Frida 的 C/C++ 源代码，包括 `gumjs` 模块，这些生成的 C 头文件会被包含到编译过程中。
6. **链接生成最终库:**  最终，所有的编译产物会被链接在一起，生成 Frida 的 Gum 库。

**调试线索：**

当 Frida 的功能出现问题，例如 JavaScript hook 不生效，或者在特定架构上运行异常时，开发者可能会查看这个脚本的执行情况作为调试线索：

- **检查脚本的输出:** 查看脚本的输出日志，确认依赖是否安装成功，JavaScript 代码是否编译成功，以及 C 头文件是否正确生成。
- **检查生成的头文件内容:** 检查生成的 `gumquickscript-*.h` 和 `gumv8script-*.h` 文件，确认 JavaScript 代码是否被正确嵌入。检查 `gumcmodule-runtime.h` 文件，确认相关的 C 头文件内容和符号表是否正确。
- **检查传递给脚本的参数:** 确认构建系统传递给脚本的参数（例如，`backends`、`arch`、`endian`、各种路径）是否符合预期。如果参数不正确，可能会导致生成错误的运行时环境。
- **手动运行脚本进行测试:** 在某些情况下，开发者可能会尝试手动运行这个脚本，并修改参数来测试不同的配置，以隔离问题。

总而言之，`generate-runtime.py` 脚本是 Frida 构建流程中至关重要的一环，它负责将 JavaScript 运行时环境和相关的 C 代码集成到 Frida 的核心库中，为 Frida 的动态 Instrumentation 功能提供了基础支持。理解这个脚本的功能有助于深入理解 Frida 的内部工作原理，并为调试 Frida 相关问题提供有价值的线索。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/generate-runtime.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from base64 import b64decode
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


RELAXED_DEPS = {
    "frida-compile": "^10.2.5",
}

EXACT_DEPS = {
    "frida-java-bridge": "6.3.6",
    "frida-objc-bridge": "7.0.6",
    "frida-swift-bridge": "2.0.8"
}


def main(argv):
    output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir, npm, quickcompile = \
            [Path(d).resolve() if d else None for d in argv[1:9]]
    backends = set(argv[9].split(","))
    arch, endian = argv[10:]

    try:
        generate_runtime(output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir,
                         npm, quickcompile,
                         backends, arch, endian)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def generate_runtime(output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir, npm, quickcompile, backends, arch, endian):
    frida_compile = priv_dir / "node_modules" / ".bin" / make_script_filename("frida-compile")
    if not frida_compile.exists():
        if priv_dir.exists():
            shutil.rmtree(priv_dir)
        priv_dir.mkdir()

        (priv_dir / "tsconfig.json").write_text("{ \"files\": [], \"compilerOptions\": { \"typeRoots\": [] } }", encoding="utf-8")

        subprocess.run([npm, "init", "-y"],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)
        subprocess.run([npm, "install"] + [f"{name}@{version_spec}" for name, version_spec in RELAXED_DEPS.items()],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)
        subprocess.run([npm, "install", "-E"] + [f"{name}@{version_spec}" for name, version_spec in EXACT_DEPS.items()],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)

    runtime_reldir = Path("runtime")
    runtime_srcdir = input_dir / runtime_reldir
    runtime_intdir = priv_dir / runtime_reldir
    if runtime_intdir.exists():
        shutil.rmtree(runtime_intdir)
    shutil.copytree(runtime_srcdir, runtime_intdir)

    call_compiler = lambda *args: subprocess.run([frida_compile, *args], cwd=priv_dir, check=True)

    if "qjs" in backends:
        quick_tmp_dir = Path("out-qjs")
        runtime = quick_tmp_dir / "frida.js"
        objc = quick_tmp_dir / "objc.js"
        swift = quick_tmp_dir / "swift.js"
        java = quick_tmp_dir / "java.js"

        quick_options = [
            "-c", # Compress for smaller code and better performance.
        ]
        call_compiler(runtime_reldir / "entrypoint-quickjs.js", "-o", runtime, *quick_options)
        call_compiler(runtime_reldir / "objc.js", "-o", objc, *quick_options)
        call_compiler(runtime_reldir / "swift.js", "-o", swift, *quick_options)
        call_compiler(runtime_reldir / "java.js", "-o", java, *quick_options)

        qcflags = []
        if endian != sys.byteorder:
            qcflags.append("--bswap")

        generate_runtime_quick("runtime", output_dir, priv_dir, "gumquickscript-runtime.h", [runtime], quickcompile, qcflags)
        generate_runtime_quick("objc", output_dir, priv_dir, "gumquickscript-objc.h", [objc], quickcompile, qcflags)
        generate_runtime_quick("swift", output_dir, priv_dir, "gumquickscript-swift.h", [swift], quickcompile, qcflags)
        generate_runtime_quick("java", output_dir, priv_dir, "gumquickscript-java.h", [java], quickcompile, qcflags)

    if "v8" in backends:
        v8_tmp_dir = Path("out-v8")
        runtime = v8_tmp_dir / "frida.js"
        objc = v8_tmp_dir / "objc.js"
        swift = v8_tmp_dir / "swift.js"
        java = v8_tmp_dir / "java.js"

        v8_options = [
            "-c", # Compress for smaller code and better performance.
        ]
        call_compiler(runtime_reldir / "entrypoint-v8.js", "-o", runtime, *v8_options)
        call_compiler(runtime_reldir / "objc.js", "-o", objc, *v8_options)
        call_compiler(runtime_reldir / "swift.js", "-o", swift, *v8_options)
        call_compiler(runtime_reldir / "java.js", "-o", java, *v8_options)

        generate_runtime_v8("runtime", output_dir, priv_dir, "gumv8script-runtime.h", [runtime])
        generate_runtime_v8("objc", output_dir, priv_dir, "gumv8script-objc.h", [objc])
        generate_runtime_v8("swift", output_dir, priv_dir, "gumv8script-swift.h", [swift])
        generate_runtime_v8("java", output_dir, priv_dir, "gumv8script-java.h", [java])

    generate_runtime_cmodule(output_dir, "gumcmodule-runtime.h", input_dir, gum_dir, capstone_incdir, libtcc_incdir, arch)

    (output_dir / "runtime.bundle").write_bytes(b"")


def generate_runtime_quick(runtime_name, output_dir, priv_dir, output, inputs, quickcompile, flags):
    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        output_file.write("#include \"gumquickbundle.h\"\n")

        modules = []
        for input_relpath in inputs:
            input_path = priv_dir / input_relpath
            stem = input_relpath.stem

            input_quick_relpath = input_relpath.parent / (stem + ".qjs")
            input_quick_path = priv_dir / input_quick_relpath
            subprocess.run([quickcompile] + flags + [input_relpath, input_quick_relpath], cwd=priv_dir, check=True)
            bytecode = input_quick_path.read_bytes()
            bytecode_size = len(bytecode)

            stem_cname = identifier(stem)
            input_bytecode_identifier = "gumjs_{0}_bytecode".format(stem_cname)
            input_source_map_identifier = "gumjs_{0}_source_map".format(stem_cname)

            output_file.write("\nstatic const guint8 {0}[{1}] =\n{{".format(input_bytecode_identifier, bytecode_size))
            write_bytes(bytecode, output_file, 'unsigned')
            output_file.write("\n};\n")

            source_code = input_path.read_text(encoding='utf-8')
            (stripped_source_code, source_map) = extract_source_map(input_relpath.name, source_code)

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file, 'signed')
                output_file.write("\n};\n")

                modules.append((input_bytecode_identifier, bytecode_size, input_source_map_identifier))
            else:
                output_file.write("\nstatic const gchar {0}[1] = {{ 0 }};\n".format(input_source_map_identifier))
                modules.append((input_bytecode_identifier, bytecode_size, "NULL"))

        output_file.write("\nstatic const GumQuickRuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for bytecode_identifier, bytecode_size, source_map_identifier in modules:
            output_file.write("\n  {{ {0}, {1}, {2} }},".format(bytecode_identifier, bytecode_size, source_map_identifier))
        output_file.write("\n  { NULL, 0, NULL }\n};")


def generate_runtime_v8(runtime_name, output_dir, priv_dir, output, inputs):
    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        output_file.write("#include \"gumv8bundle.h\"\n")

        modules = []
        for input_relpath in inputs:
            input_path = priv_dir / input_relpath
            input_name = input_relpath.name

            stem_cname = identifier(input_relpath.stem)
            input_source_code_identifier = "gumjs_{0}_source_code".format(stem_cname)
            input_source_map_identifier = "gumjs_{0}_source_map".format(stem_cname)

            source_code = input_path.read_text(encoding='utf-8')
            (stripped_source_code, source_map) = extract_source_map(input_name, source_code)
            source_code_bytes = bytearray(stripped_source_code.encode('utf-8'))
            source_code_bytes.append(0)
            source_code_size = len(source_code_bytes)

            output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_code_identifier, source_code_size))
            write_bytes(source_code_bytes, output_file, 'signed')
            output_file.write("\n};\n")

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file, 'signed')
                output_file.write("\n};\n")

                modules.append((input_name, input_source_code_identifier, input_source_map_identifier))
            else:
                output_file.write("\nstatic const gchar {0}[1] = {{ 0 }};\n".format(input_source_map_identifier))
                modules.append((input_name, input_source_code_identifier, "NULL"))

        output_file.write("\nstatic const GumV8RuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for filename, source_code_identifier, source_map_identifier in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2} }},".format(filename, source_code_identifier, source_map_identifier))
        output_file.write("\n  { NULL, NULL, NULL }\n};")


cmodule_function_pattern = re.compile(
        r"^(void|size_t|int|unsigned int|bool|const char \*|gpointer|gsize|gssize|gint[0-9]*|guint[0-9]*|gfloat|gdouble|gboolean||(?:const )?\w+ \*|Gum\w+|csh|cs_err) ([a-z][a-z0-9_]+)\s?\(",
    re.MULTILINE)
cmodule_variable_pattern = re.compile(r"^(extern .+? )(\w+);", re.MULTILINE)
capstone_include_pattern = re.compile(r'^#include "(\w+)\.h"$', re.MULTILINE)
capstone_export_pattern = re.compile(r"^CAPSTONE_EXPORT$", re.MULTILINE)

c_comment_pattern = re.compile(r"\/\*(\*(?!\/)|[^*])*\*\/")
cpp_comment_pattern = re.compile(r"\s+?\/\/.+")


def generate_runtime_cmodule(output_dir, output, input_dir, gum_dir, capstone_incdir, libtcc_incdir, arch):
    if arch.startswith("x86") or arch == "x64":
        writer_arch = "x86"
    elif arch.startswith("mips"):
        writer_arch = "mips"
    else:
        writer_arch = arch
    capstone_arch = writer_arch

    def gum_header_matches_writer(name):
        if writer_arch == "arm":
            return name in ("gumarmwriter.h", "gumthumbwriter.h")
        else:
            return name == "gum" + writer_arch + "writer.h"

    def optimize_gum_header(source):
        return source.replace("GUM_API ", "")

    def capstone_header_matches_arch(name):
        if name in ("capstone.h", "platform.h"):
            return True
        return name == capstone_arch + ".h"

    def optimize_capstone_header(source):
        result = capstone_include_pattern.sub(transform_capstone_include, source)
        result = capstone_export_pattern.sub("", result)
        result = result.replace("CAPSTONE_API ", "")
        return result

    def transform_capstone_include(m):
        name = m.group(1)

        if name in ("platform", capstone_arch):
            return m.group(0)

        if name == "systemz":
            name = "sysz"

        return "typedef int cs_{0};".format(name)

    def libtcc_is_header(name):
        """Ignore symbols from the TinyCC standard library: dlclose() etc."""
        return is_header(name) and name != "tcclib.h"

    inputs = [
        (input_dir / "runtime" / "cmodule", None, is_header, identity_transform, 'GUM_CHEADER_FRIDA'),
        (gum_dir / ("arch-" + writer_arch), gum_dir.parent, gum_header_matches_writer, optimize_gum_header, 'GUM_CHEADER_FRIDA'),
        (capstone_incdir, None, capstone_header_matches_arch, optimize_capstone_header, 'GUM_CHEADER_FRIDA'),
    ]
    if libtcc_incdir is not None:
        inputs += [
            (input_dir / "runtime" / "cmodule-tcc", None, is_header, identity_transform, 'GUM_CHEADER_TCC'),
            (libtcc_incdir, None, libtcc_is_header, identity_transform, 'GUM_CHEADER_TCC'),
        ]

    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        modules = []
        symbols = []

        for header_dir, header_reldir, header_filter, header_transform, header_kind in inputs:
            for header_name, header_source in find_headers(header_dir, header_reldir, header_filter, header_transform):
                input_identifier = "gum_cmodule_{0}".format(identifier(header_name))

                for pattern in (cmodule_function_pattern, cmodule_variable_pattern):
                    for m in pattern.finditer(header_source):
                        name = m.group(2)
                        if name.startswith("cs_arch_register_"):
                            continue
                        symbols.append(name)

                source_bytes = bytearray(header_source.encode('utf-8'))
                source_bytes.append(0)
                source_size = len(source_bytes)

                output_file.write("static const gchar {0}[{1}] =\n{{".format(input_identifier, source_size))
                write_bytes(source_bytes, output_file, 'signed')
                output_file.write("\n};\n\n")

                modules.append((header_name, input_identifier, source_size - 1, header_kind))

        output_file.write("static const GumCHeaderDetails gum_cmodule_headers[] =\n{")
        for input_name, input_identifier, input_size, header_kind in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2}, {3} }},".format(input_name, input_identifier, input_size, header_kind))
        output_file.write("\n};\n")

        symbol_insertions = ["    g_hash_table_insert (symbols, \"{0}\", GUM_FUNCPTR_TO_POINTER ({0}));".format(name) for name in symbols]
        output_file.write("""
static void gum_cmodule_deinit_symbols (void);

static GHashTable *
gum_cmodule_get_symbols (void)
{{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {{
    GHashTable * symbols;

    symbols = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4996)
#endif

{insertions}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

    _gum_register_destructor (gum_cmodule_deinit_symbols);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (symbols) + 1);
  }}

  return GSIZE_TO_POINTER (gonce_value - 1);
}}

static void
gum_cmodule_deinit_symbols (void)
{{
  g_hash_table_unref (gum_cmodule_get_symbols ());
}}
""".format(insertions="\n".join(symbol_insertions)))


def find_headers(include_dir, relative_to_dir, is_header, transform):
    if relative_to_dir is None:
        relative_to_dir = include_dir

    for root, dirs, files in os.walk(include_dir):
        for name in files:
            if is_header(name):
                path = Path(root) /  name
                name = os.path.relpath(path, relative_to_dir).replace("\\", "/")
                source = strip_header(transform(strip_header(path.read_text(encoding='utf-8'))))
                yield (name, source)


def is_header(name):
    return name.endswith(".h")


def identity_transform(v):
    return v


def strip_header(source):
    result = c_comment_pattern.sub("", source)
    result = cpp_comment_pattern.sub("", result)
    while True:
        if "\n\n" not in result:
            break
        result = result.replace("\n\n", "\n")
    return result


source_map_pattern = re.compile("//[#@][ \t]sourceMappingURL=[ \t]*data:application/json;.*?base64,([^\\s'\"]*)[ \t]*\n")


def extract_source_map(filename, source_code):
    m = source_map_pattern.search(source_code)
    if m is None:
        return (source_code, None)
    raw_source_map = m.group(1)

    source_map = json.loads(b64decode(raw_source_map).decode('utf-8'))
    source_map['file'] = filename
    source_map['sources'] = list(map(to_canonical_source_path, source_map['sources']))

    raw_source_map = json.dumps(source_map)

    stripped_source_code = source_map_pattern.sub("", source_code)

    return (stripped_source_code, raw_source_map)


def to_canonical_source_path(path):
    return "frida/" + path


def write_bytes(data, sink, encoding):
    sink.write("\n  ")
    line_length = 0
    offset = 0
    for b in bytearray(data):
        if offset > 0:
            sink.write(",")
            line_length += 1
        if line_length >= 70:
            sink.write("\n  ")
            line_length = 0
        if encoding == 'signed' and b >= 128:
            b -= 256
        token = str(b)
        sink.write(token)

        line_length += len(token)
        offset += 1


def identifier(filename):
    result = ""
    if filename.startswith("frida-"):
        filename = filename[6:]
    for c in filename:
        if c.isalnum():
            result += c.lower()
        else:
            result += "_"
    return result


def make_script_filename(name):
    build_os = platform.system().lower()
    extension = ".cmd" if build_os == 'windows' else ""
    return name + extension


if __name__ == '__main__':
    main(sys.argv)

"""

```