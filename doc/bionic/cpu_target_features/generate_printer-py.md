Response:
Let's break down the thought process for answering the user's request about the `generate_printer.py` script.

**1. Understanding the Core Request:**

The user wants to understand what the Python script does within the context of Android's Bionic library. The core of the script is "generating source code," so that should be a central theme.

**2. Initial Analysis of the Script:**

* **Shebang:** `#!/usr/bin/env python3` - It's a Python 3 script.
* **Docstring:**  "Generate the compilation target feature printing source code." This confirms the primary purpose.
* **Imports:** `argparse`, `pathlib`, `typing`. `argparse` indicates command-line argument parsing. `pathlib` is for file system operations. `typing` adds type hints for better readability and static analysis.
* **`_CPP_BOILERPLATE`:** This string looks like the beginning of a C++ file, including standard headers and macros. This hints at the *type* of code being generated.
* **`_FEATURES`:** A dictionary mapping architecture names (Aarch64, Arm32, X86, Riscv) to lists of preprocessor definitions (like `__ARM_FEATURE_AES__`). This is the *data* driving the code generation. These definitions represent CPU features.
* **`_make_function_sig`:** Creates a function signature like `void printAarch64TargetFeatures()`.
* **`check_template`:** Generates C preprocessor directives and `printf` statements to check if a macro is defined and print its value.
* **`generate_cpp_file`:** Iterates through the `_FEATURES` dictionary and calls `generate_print_function` for each architecture.
* **`generate_print_function`:** Creates a C++ function that checks and prints the status of the CPU features for a given architecture.
* **`parse_args` and `main`:**  Standard `argparse` setup for taking the output file path as a command-line argument.

**3. Connecting to Bionic and Android:**

* **Bionic Context:** The script resides in `bionic/cpu_target_features`. This immediately tells us it's related to how Bionic handles CPU-specific optimizations. Bionic needs to know what CPU features are available at runtime to potentially choose optimized code paths.
* **Android Context:** Android devices have diverse CPUs. Bionic, as the foundational C library, needs a way to abstract away these differences and provide the best performance on each device. This script helps in *detecting* those differences.

**4. Answering the User's Specific Questions (Iterative Process):**

* **功能 (Functionality):** The core function is generating C++ code to print the status of CPU target features. This code will be compiled into Bionic.
* **与 Android 的关系 (Relationship with Android):**  Crucial for Bionic's adaptive behavior. Examples include:
    * Optimizing math functions based on SIMD support (like NEON on ARM, SSE/AVX on x86).
    * Utilizing cryptographic instructions for faster security operations.
* **libc 函数实现 (libc function implementation):**  The script *doesn't* implement libc functions. It *helps detect* CPU features that *libc functions might use for optimization*. This is a crucial distinction. Explain that the *generated code* will be part of Bionic, and *other* parts of Bionic (not this script) will contain the actual libc implementations.
* **dynamic linker 功能 (dynamic linker functionality):**  The script itself doesn't directly interact with the dynamic linker. However, the *output* of this script helps *inform* decisions made by the dynamic linker. When an app loads a shared library, the dynamic linker *could* potentially use information about CPU features to load optimized versions of the library (though this specific script's output is more about runtime detection within a process). Provide a simplified SO layout example and the basic linking process. Emphasize that this script's role is more about *reporting* CPU features, not directly *controlling* linking.
* **逻辑推理 (Logical Reasoning):** Focus on the conditional nature of the generated C++ code. If a macro is defined, it prints one thing; otherwise, it prints another. Provide a simple example with a likely input (e.g., compiling on an ARMv8-A device) and the expected output.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Highlight that users don't directly interact with this script. The errors would be more on the Bionic development side (incorrectly defining `_FEATURES`, typos, etc.).
* **Android Framework/NDK 到达这里 (Android Framework/NDK reaching here):**  This requires tracing the path from app execution to Bionic's code. Start with an NDK app, explain how it links to libc.so (part of Bionic), and how Bionic initializes and might use this generated code to detect CPU features. Provide a Frida hook example targeting the generated `print...TargetFeatures` functions. This demonstrates how to observe the execution of the generated code.

**5. Structuring the Answer:**

Organize the information logically, following the user's questions as a guide. Use clear headings and bullet points for readability. Provide code examples where appropriate (SO layout, Frida hook).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This script implements CPU feature detection."  **Correction:** The script *generates the code* that does the detection. It's a code generator, not the detector itself.
* **Initial thought (dynamic linker):** "The script tells the dynamic linker what features are available." **Correction:** The script generates code that *reports* features *at runtime within a process*. The dynamic linker might use *other* information (like the `android_cpuabi` in the manifest) for initial library selection. The information from this script might be used later within the process.
* **Emphasis:**  Constantly reinforce the idea that this is a *code generation* script and the generated code is what performs the actual feature detection.

By following this thought process, breaking down the script, connecting it to the broader Android ecosystem, and addressing each of the user's specific questions, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `bionic/cpu_target_features/generate_printer.py` 这个 Python 脚本的功能以及它在 Android Bionic 中的作用。

**脚本功能概览**

`generate_printer.py` 的主要功能是**生成 C++ 源代码**，这些源代码用于在运行时检测目标 CPU 的特性（features）。由于手动维护这些检测代码非常冗余且容易出错，因此使用代码生成脚本能够更高效且易于维护。

**详细功能分解**

1. **定义 CPU 特性列表 (`_FEATURES` 字典):**
   -  脚本的核心是 `_FEATURES` 字典，它为不同的 CPU 架构（例如 "Aarch64", "Arm32", "X86", "Riscv"）定义了需要检测的 CPU 特性宏。
   - 例如，对于 "Aarch64"，它列出了像 `__ARM_FEATURE_AES`（ARM AES 加密扩展）、`__ARM_FEATURE_CRC32`（ARM CRC32 指令）等宏。
   - 这些宏通常由编译器在编译时定义，以指示目标 CPU 支持哪些特性。

2. **生成 C++ 样板代码 (`_CPP_BOILERPLATE`):**
   -  `_CPP_BOILERPLATE` 字符串包含了生成的 C++ 文件的头部信息，包括 `<stdio.h>` 头文件和两个宏定义 `TO_STRING_EXP` 和 `TO_STRING`。
   - 这两个宏用于将宏定义的名称转换为字符串，方便后续打印输出。

3. **生成函数签名 (`_make_function_sig`):**
   -  `_make_function_sig` 函数接收一个架构名称作为输入，并生成一个用于打印该架构特性的 C++ 函数签名。
   - 例如，对于 "Aarch64"，它会生成 `void printAarch64TargetFeatures()`。

4. **生成特性检查代码 (`check_template`):**
   -  `check_template` 函数接收一个 CPU 特性宏的名称作为输入，并生成一段 C++ 代码，用于检查该宏是否被定义，并打印相应的消息。
   - 例如，对于宏 `__ARM_FEATURE_AES`，它会生成：
     ```cpp
     #if defined(__ARM_FEATURE_AES)
       printf("%s=%s\n", TO_STRING_EXP(__ARM_FEATURE_AES), TO_STRING(__ARM_FEATURE_AES));
     #else
       printf("%s not defined\n", TO_STRING_EXP(__ARM_FEATURE_AES));
     #endif
     ```
   - 这段代码使用预处理器指令 `#if defined` 来判断宏是否被定义，如果定义了，则打印宏的名称和值（通常为 1），否则打印 "not defined"。

5. **生成打印函数 (`generate_print_function`):**
   -  `generate_print_function` 函数接收一个架构名称和该架构的特性宏列表作为输入，并生成一个完整的 C++ 函数，用于打印该架构的所有目标特性。
   - 它首先生成函数签名，然后遍历特性宏列表，为每个宏调用 `check_template` 生成检查代码，最后添加函数结束的大括号。

6. **生成完整的 C++ 文件 (`generate_cpp_file`):**
   -  `generate_cpp_file` 函数接收包含架构和特性宏列表的字典作为输入，并生成一个完整的 C++ 文件内容。
   - 它首先添加样板代码，然后遍历字典，为每个架构调用 `generate_print_function` 生成对应的打印函数。

7. **命令行参数解析 (`parse_args`):**
   -  `parse_args` 函数使用 `argparse` 模块来处理命令行参数，允许用户指定生成的 C++ 文件的输出路径。

8. **主函数 (`main`):**
   -  `main` 函数是脚本的入口点。它调用 `parse_args` 解析命令行参数，然后调用 `generate_cpp_file` 生成 C++ 代码，并将代码写入指定的输出文件。

**与 Android 功能的关系及举例说明**

这个脚本生成的 C++ 代码是 Android Bionic 的一部分，Bionic 是 Android 的 C 库、数学库和动态链接器。CPU 特性检测对于 Bionic 来说至关重要，原因如下：

* **运行时优化:** Bionic 可以在运行时检测目标 CPU 支持哪些特性，并根据这些特性选择最优的代码路径。例如：
    * **SIMD 指令 (NEON, SSE, AVX):** 如果 CPU 支持 SIMD 指令，Bionic 的数学库（`libm`）可以使用这些指令来加速向量运算，例如浮点数加法、乘法等。生成的代码会检测 `__ARM_FEATURE_NEON` (对于 ARM) 或 `__AVX__` (对于 x86)。
    * **加密指令 (AES, SHA):** 如果 CPU 支持硬件加速的加密指令，Bionic 的加密相关功能（例如 OpenSSL 的部分实现）可以使用这些指令来提高加密和解密的速度。生成的代码会检测 `__ARM_FEATURE_AES` 或 `__AES__`，以及 `__ARM_FEATURE_SHA2` 或 `__SHA__` 等。
    * **原子操作:** 某些 CPU 架构提供更高效的原子操作指令，Bionic 可以利用这些指令来实现更高效的线程同步。
* **ABI 兼容性:**  了解目标 CPU 的特性有助于确保应用程序的二进制接口（ABI）兼容性。例如，某些指令集扩展可能需要在特定的 CPU 上才能运行。
* **错误报告和调试:**  在某些情况下，如果应用程序尝试使用 CPU 不支持的特性，Bionic 可以检测到这种情况并提供有用的错误信息。

**举例说明:**

假设在搭载 ARMv8-A CPU 的 Android 设备上运行该脚本生成的代码。生成的 `printAarch64TargetFeatures` 函数可能会输出类似以下的内容：

```
__ARM_FEATURE_AES=1
__ARM_FEATURE_BTI=1
__ARM_FEATURE_CRC32=1
__ARM_FEATURE_CRYPTO=1
__ARM_FEATURE_PAC_DEFAULT=1
__ARM_FEATURE_SHA2=1
__ARM_FEATURE_SHA3 not defined
__ARM_FEATURE_SHA512 not defined
```

这表示该 CPU 支持 AES 加密、分支目标识别（BTI）、CRC32 计算、通用加密扩展、指针身份验证（PAC）以及 SHA-2 算法的硬件加速，但不支持 SHA-3 和 SHA-512 的硬件加速。

Bionic 的其他部分（例如 `libc.so` 或 `libm.so`）会在运行时调用这些生成的函数，获取 CPU 特性信息，然后根据这些信息选择不同的代码路径。

**详细解释每一个 libc 函数的功能是如何实现的**

这个脚本本身**并不实现**任何 libc 函数。它的作用是生成 C++ 代码，用于**检测** CPU 特性。这些被检测到的 CPU 特性信息，可以被 Bionic 中的其他组件（包括 libc 函数的实现）使用来优化其行为。

例如，`memcpy` 函数的实现可能会在运行时检测 CPU 是否支持特定的 SIMD 指令（如 NEON），如果支持，则使用 SIMD 指令进行更快速的内存复制；如果不支持，则使用更通用的实现。`generate_printer.py` 生成的代码负责告诉 `memcpy` 的实现 "这个 CPU 支持 NEON"。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

`generate_printer.py` 生成的代码主要是在**运行时**获取当前进程运行的 CPU 的特性。它与 dynamic linker 的关系相对间接，主要体现在以下方面：

* **库的加载和选择:** Dynamic linker (如 `linker64` 或 `linker`) 在加载共享库 (`.so` 文件) 时，会考虑目标设备的 CPU 架构。Android 系统通常会为不同的 CPU 架构提供不同版本的共享库 (例如 `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`)。Dynamic linker 会根据设备的 CPU 架构选择合适的库进行加载。
* **运行时优化 (间接影响):**  虽然 `generate_printer.py` 生成的代码不是 dynamic linker 的核心功能，但它生成的 CPU 特性信息可以被链接到应用程序的共享库使用。这些共享库可以根据检测到的 CPU 特性进行运行时优化。

**SO 布局样本:**

一个典型的 Android 共享库 (`.so`) 文件结构可能如下：

```
my_library.so:
  .init       # 初始化代码段
  .plt        # 程序链接表
  .text       # 代码段
  .rodata     # 只读数据段
  .data       # 可读写数据段
  .bss        # 未初始化数据段
  .fini       # 终止代码段
  ...         # 其他段，如调试信息等
```

**链接的处理过程 (简化描述):**

1. **应用程序启动:** 当 Android 启动一个应用程序时，操作系统会加载应用程序的主执行文件。
2. **依赖项解析:** 操作系统会解析应用程序依赖的共享库列表。
3. **库查找:** Dynamic linker 根据预定义的路径 (如 `/system/lib64`, `/vendor/lib64` 等) 查找所需的共享库。它会根据设备的 ABI 选择合适的版本。
4. **加载和映射:** Dynamic linker 将找到的共享库加载到内存中，并将其各个段 (如 `.text`, `.data`) 映射到进程的地址空间。
5. **符号解析:** Dynamic linker 解析共享库中的符号 (函数和全局变量)，并将应用程序中对这些符号的引用绑定到共享库中的实际地址。这包括解析 PLT (Procedure Linkage Table) 中的条目。
6. **重定位:** Dynamic linker 对共享库中的某些地址进行重定位，因为库被加载到内存的哪个位置在编译时是未知的。
7. **初始化:** Dynamic linker 执行共享库的初始化代码 (`.init` 段中的代码)。这可能包括调用构造函数、初始化全局变量等。**Bionic 中生成的用于检测 CPU 特性的代码可能会在这个阶段被调用。**

**`generate_printer.py` 在链接过程中的作用:**

`generate_printer.py` 生成的 C++ 代码会被编译到 Bionic 的某个共享库中 (例如 `libc.so`)。当应用程序链接到 `libc.so` 时，其中包含的 CPU 特性检测代码也会被链接进来。在运行时，`libc.so` 中的代码会调用这些检测函数来获取 CPU 特性信息。

**如果做了逻辑推理，请给出假设输入与输出**

`generate_printer.py` 的主要逻辑是根据 `_FEATURES` 字典生成代码。

**假设输入:**  修改 `_FEATURES` 字典，例如添加一个新的 CPU 架构 "MyNewArch" 和一些特性宏：

```python
_FEATURES = {
    "Aarch64": [
        "__ARM_FEATURE_AES",
        # ... 其他特性
    ],
    "Arm32": [
        # ... 其他特性
    ],
    "MyNewArch": [
        "__MY_NEW_FEATURE_ABC",
        "__MY_NEW_FEATURE_XYZ",
    ],
}
```

**假设输出 (生成的 C++ 文件部分):**

除了原有的 `printAarch64TargetFeatures`, `printArm32TargetFeatures` 等函数外，还会生成一个新的函数：

```cpp
void printMyNewArchTargetFeatures() {
#if defined(__MY_NEW_FEATURE_ABC)
  printf("%s=%s\n", TO_STRING_EXP(__MY_NEW_FEATURE_ABC), TO_STRING(__MY_NEW_FEATURE_ABC));
#else
  printf("%s not defined\n", TO_STRING_EXP(__MY_NEW_FEATURE_ABC));
#endif
#if defined(__MY_NEW_FEATURE_XYZ)
  printf("%s=%s\n", TO_STRING_EXP(__MY_NEW_FEATURE_XYZ), TO_STRING(__MY_NEW_FEATURE_XYZ));
#else
  printf("%s not defined\n", TO_STRING_EXP(__MY_NEW_FEATURE_XYZ));
#endif
}
```

**如果涉及用户或者编程常见的使用错误，请举例说明**

对于 `generate_printer.py` 脚本本身，常见的错误主要发生在 Bionic 的开发过程中：

1. **`_FEATURES` 字典中的拼写错误:** 如果在 `_FEATURES` 字典中错误地拼写了 CPU 架构名称或特性宏的名称，那么生成的 C++ 代码将无法正确检测这些特性。例如，将 `__ARM_FEATURE_AES` 拼写成 `__ARM_FEATURE_ASS`。
2. **忘记添加新的 CPU 特性:** 当新的 CPU 架构或特性被引入时，如果忘记更新 `_FEATURES` 字典，那么生成的代码将无法检测这些新的特性。
3. **生成的 C++ 文件路径错误:** 在运行脚本时，如果提供的输出文件路径不正确，可能导致生成的文件被放置在错误的位置，或者无法生成文件。

**对于使用生成的 C++ 代码的用户（通常是 Bionic 的开发者）：**

1. **假设 CPU 支持错误的特性:**  如果在 Bionic 的代码中，开发者错误地假设某个 CPU 一定支持某个特性，而实际上某些设备上可能不支持，可能会导致运行时错误或性能问题。正确的做法是通过生成的检测函数来动态判断。
2. **忘记调用特性检测函数:** 如果开发者忘记在需要的地方调用生成的 `print...TargetFeatures` 函数，就无法获取到 CPU 特性信息，从而无法进行针对性的优化。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 应用调用 libc 函数:**
   - 一个使用 NDK 开发的 Android 应用，通常会链接到 Bionic 提供的 C 库 (`libc.so`)。
   - 当应用调用 `libc.so` 中的某个函数时（例如 `memcpy`, `memset`, `pthread_create` 等），实际上会执行 `libc.so` 中实现的代码。

2. **libc 函数内部的 CPU 特性检测:**
   - 许多 Bionic 中的 libc 函数的实现会利用 CPU 特性来优化性能。
   - 例如，`memcpy` 的实现可能会首先调用由 `generate_printer.py` 生成的 `print...TargetFeatures` 函数或者相关的辅助函数，来检查 CPU 是否支持 NEON 等 SIMD 指令。

3. **`print...TargetFeatures` 函数的执行:**
   - 这些函数内部会使用预处理器宏来判断 CPU 特性是否被定义，并通过 `printf` 打印出来。在实际的 Bionic 代码中，通常不会直接 `printf`，而是使用更底层的机制来获取这些信息。

**Frida Hook 示例:**

我们可以使用 Frida hook 由 `generate_printer.py` 生成的 `print...TargetFeatures` 函数，来观察它们何时被调用以及输出了什么。

假设我们想 hook `libc.so` 中的 `printAarch64TargetFeatures` 函数：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "printAarch64TargetFeatures"), {
  onEnter: function (args) {
    console.log("[*] printAarch64TargetFeatures called");
  },
  onLeave: function (retval) {
    console.log("[*] printAarch64TargetFeatures returned");
  }
});

// Hook printf 来查看输出的特性信息
Interceptor.attach(Module.findExportByName("libc.so", "printf"), {
  onEnter: function (args) {
    var fmt = Memory.readUtf8String(args[0]);
    var arg1 = ptr(args[1]);
    var arg2 = ptr(args[2]);

    if (fmt.includes("%s=%s")) {
        var key = Memory.readUtf8String(arg1);
        var value = Memory.readUtf8String(arg2);
        send(`CPU Feature: ${key}=${value}`);
    } else if (fmt.includes("%s not defined")) {
        var key = Memory.readUtf8String(arg1);
        send(`CPU Feature: ${key} not defined`);
    }
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定应用包名:** 将 `your.app.package.name` 替换为你要调试的应用的包名。
3. **连接到设备和应用:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标应用进程。
4. **编写 Frida 脚本:**
   - 使用 `Interceptor.attach` hook `libc.so` 中的 `printAarch64TargetFeatures` 函数，在函数进入和退出时打印日志。
   - 使用 `Interceptor.attach` hook `libc.so` 中的 `printf` 函数，拦截格式化字符串，并提取 CPU 特性信息并发送到 Frida 客户端。
5. **创建和加载脚本:** 使用 `session.create_script(script_code)` 创建 Frida 脚本，并使用 `script.load()` 加载脚本。
6. **监听消息:** 使用 `script.on('message', on_message)` 监听来自脚本的消息，并将 CPU 特性信息打印出来.
7. **保持脚本运行:** `sys.stdin.read()` 阻止脚本退出，以便持续监听。

**运行此 Frida 脚本后，当你运行目标应用时，如果 `libc.so` 中的代码调用了 `printAarch64TargetFeatures` 函数，你将会在 Frida 的输出中看到相关的日志和 CPU 特性信息。** 这可以帮助你理解 Bionic 如何在运行时检测 CPU 特性。

总结来说，`generate_printer.py` 是一个 Bionic 构建过程中的重要工具，它自动化生成了用于运行时检测 CPU 特性的 C++ 代码，这些代码被 Bionic 的其他组件（包括 libc 函数）使用，以实现运行时优化和兼容性。 理解这个脚本的功能有助于理解 Android 系统如何根据不同的硬件平台进行自适应调整。

### 提示词
```
这是目录为bionic/cpu_target_features/generate_printer.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```python
#!/usr/bin/env python3

"""Generate the compilation target feature printing source code.

The source code for detecting target features is heavily redundant and
copy-pasted, and is easier to maintain using a generative script.

This script creates the source and the include files in its current
directory.
"""

import argparse
from pathlib import Path
from typing import Dict, List, Iterable

_CPP_BOILERPLATE: str = """\
#include <stdio.h>

#define TO_STRING_EXP(DEF) #DEF
#define TO_STRING(DEF) TO_STRING_EXP(DEF)
"""

_FEATURES = {
    "Aarch64": [
        "__ARM_FEATURE_AES",
        "__ARM_FEATURE_BTI",
        "__ARM_FEATURE_CRC32",
        "__ARM_FEATURE_CRYPTO",
        "__ARM_FEATURE_PAC_DEFAULT",
        "__ARM_FEATURE_SHA2",
        "__ARM_FEATURE_SHA3",
        "__ARM_FEATURE_SHA512",
    ],
    "Arm32": [
        "__ARM_ARCH_ISA_THUMB",
        "__ARM_FEATURE_AES",
        "__ARM_FEATURE_BTI",
        "__ARM_FEATURE_CRC32",
        "__ARM_FEATURE_CRYPTO",
        "__ARM_FEATURE_PAC_DEFAULT",
        "__ARM_FEATURE_SHA2",
    ],
    "X86": [
        "__AES__",
        "__AVX__",
        "__CRC32__",
        "__POPCNT__",
        "__SHA512__",
        "__SHA__",
    ],
    "Riscv": [
        "__riscv_vector",
    ],
}


def _make_function_sig(name: str) -> str:
    return f"void print{name}TargetFeatures()"


def check_template(define: str) -> List[str]:
    return [
        f"#if defined({define})",
        f'  printf("%s=%s\\n", TO_STRING_EXP({define}), TO_STRING({define}));',
        "#else",
        f'  printf("%s not defined\\n", TO_STRING_EXP({define}));',
        "#endif",
    ]


def generate_cpp_file(define_mapping: Dict[str, List[str]]) -> List[str]:
    out: List[str] = _CPP_BOILERPLATE.split("\n")
    for target, defines in define_mapping.items():
        out.append("")
        out.extend(generate_print_function(target, defines))
    return out


def generate_print_function(name: str, defines: List[str]) -> List[str]:
    """Generate a print<DEFINE>TargetFeatures function."""
    function_body = [_make_function_sig(name) + " {"]
    for d in defines:
        function_body.extend(check_template(d))
    function_body.append("}")
    return function_body


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "cpp_in",
        type=Path,
        help="Output path to generate the cpp file.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    printer_cpp_filepath = args.cpp_in
    printer_cpp_filepath.write_text(
        "\n".join(generate_cpp_file(_FEATURES)), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
```