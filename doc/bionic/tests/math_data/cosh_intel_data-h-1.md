Response:
The user is asking for a summary of the functionality of the provided C source code file. This file appears to be a data file containing test vectors for the `cosh` function in the Android bionic library.

Here's a breakdown of how to approach the request:

1. **Identify the core function:** The filename `cosh_intel_data.handroid` strongly suggests this data is related to the `cosh` (hyperbolic cosine) function.

2. **Analyze the data structure:** The data is structured as an array of structures. Each structure seems to contain two floating-point numbers.

3. **Infer the purpose of the data:** Given it's in `bionic/tests/math_data`, these pairs of numbers are likely input-output pairs for testing the `cosh` function. The first number is likely the input to `cosh`, and the second is the expected output. The presence of both positive and negative outputs for the same input suggests the data might be testing the symmetry of `cosh` or handling of signed zero.

4. **Consider the filename suffix:** `.handroid` suggests these test vectors might be specific to Android or a certain architecture within Android (like the "h" potentially standing for hardware or a specific CPU architecture).

5. **Address the specific questions:**

    * **Functionality:** The file provides test data for the `cosh` function.
    * **Relationship to Android:**  It's part of the bionic library, Android's C library, used for math functions.
    * **libc function implementation:** This file *doesn't* implement `cosh`. It's *used to test* the implementation. Therefore, I'll need to explain how `cosh` generally works (using its mathematical definition or common approximation techniques).
    * **Dynamic linker:** This file isn't directly related to the dynamic linker. It's a data file. I'll explain the dynamic linker's role in loading shared libraries that *contain* the `cosh` implementation.
    * **Logic reasoning:** The data represents input-output pairs. I can show examples of a few entries and explain the expected behavior.
    * **User/programming errors:** Incorrect usage of `cosh` could involve passing very large arguments that lead to overflow or NaN.
    * **Android framework/NDK path:** I'll outline the call chain from the Android framework or NDK down to the bionic `cosh` function.
    * **Frida hook:** Provide a basic Frida script to intercept calls to `cosh`.
    * **Summary (for part 2):**  Reiterate that this file contains test data for verifying the correctness of the `cosh` function in bionic.

**Self-Correction/Refinement:**

* Initially, I might have thought this file *implements* `cosh`. However, the file path (`tests/math_data`) clearly indicates it's for testing, not implementation.
* The question about the dynamic linker needs careful handling. While this file itself isn't a shared object, the `cosh` implementation resides in a shared library loaded by the dynamic linker. I need to clarify this distinction.
* The Frida hook should be a practical example, targeting the `cosh` function.
这是目录为 `bionic/tests/math_data/cosh_intel_data.handroid` 的源代码文件，属于 Android 的 C 库 (bionic) 的一部分，用于数学函数的测试。根据提供的数据内容，可以归纳出以下功能：

**功能归纳:**

该文件主要功能是**提供一组预定义的输入和期望输出值，用于测试 bionic 库中 `cosh` (双曲余弦) 函数的正确性**。

**详细解释:**

1. **测试数据:** 该文件包含一个 C 语言数组，数组名为匿名。数组中的每个元素都是一个结构体，结构体包含两个 `double` 类型的浮点数。

   * 第一个 `double` 值是 `cosh` 函数的输入值。
   * 第二个 `double` 值是对于给定输入，`cosh` 函数的期望输出值。

2. **覆盖多种输入情况:**  这些测试数据覆盖了 `cosh` 函数可能遇到的各种输入情况，包括：

   * **正常值:**  包括正数和负数（由于 `cosh` 是偶函数，`cosh(x) == cosh(-x)`，因此通常会测试正值，负值用于验证对称性）。
   * **非常接近零的值:** 用于测试精度。
   * **非常大的值:**  接近或等于 `HUGE_VAL`，用于测试溢出行为。
   * **特殊值:**  例如 `0.0`。
   * **不同数量级的数值:**  通过指数部分 (`p` 后的数字) 可以看出测试了不同数量级的输入。

3. **验证精度:**  数据中使用了高精度的十六进制浮点数表示，例如 `0x1.25e4f7b2737fap5`，这表明测试旨在验证 `cosh` 函数在不同输入下的计算精度是否符合预期。

4. **测试正负输出:** 对于某些相同的输入值，存在正负两个期望输出，这可能是为了测试：
    * **浮点数的符号处理:** 尽管 `cosh` 的结果总是非负的，但可能在某些极端情况下或者某些特定实现中，需要测试对符号的处理。更可能的是，这用于测试其他相关的数学函数或者测试框架的某些特性。 例如，可能存在同时测试 `cosh` 和某些需要用到 `cosh` 的其他函数的情况。

**与 Android 功能的关系及举例:**

该文件直接服务于 Android 系统的基础库 bionic。`cosh` 函数是标准 C 库 (`libc`) 的一部分，bionic 提供了 Android 平台的 `libc` 实现。

* **数学计算:** Android 系统中的各种应用和框架，特别是涉及到科学计算、图形渲染、物理模拟等领域，会依赖 `cosh` 这样的数学函数。例如，在 OpenGL ES 中进行某些变换时，可能会用到双曲函数。
* **NDK 开发:** 使用 Android NDK 进行原生开发的程序员可以直接调用 `cosh` 函数。例如，一个进行信号处理的 NDK 应用可能会用到 `cosh`。

**libc 函数的功能是如何实现的 (以 `cosh` 为例):**

`cosh(x)` 函数的实现通常基于其数学定义：

`cosh(x) = (e^x + e^-x) / 2`

然而，直接使用这个公式在计算机上计算可能会遇到精度和性能问题，尤其是在 `x` 的绝对值很大时。因此，实际的 `cosh` 实现会采用一些优化和近似方法：

1. **特殊情况处理:**
   * 如果 `x` 是 NaN，返回 NaN。
   * 如果 `x` 是无穷大，返回无穷大。
   * 如果 `x` 是负无穷大，返回无穷大。
   * 如果 `x` 是零，返回 1.0。

2. **利用对称性:** 由于 `cosh(x) = cosh(-x)`，通常会先取 `x` 的绝对值，简化计算。

3. **小数值近似:** 当 `|x|` 很小时，可以使用泰勒级数展开来近似 `cosh(x)`：
   `cosh(x) ≈ 1 + x^2/2! + x^4/4! + ...`
   取有限项可以得到足够精度的近似值。

4. **大数值处理:** 当 `|x|` 很大时，`e^-x` 趋近于零，因此 `cosh(x)` 可以近似为 `e^x / 2`。为了避免直接计算 `e^x` 导致溢出，可能会进行一些变换。

5. **使用查找表:**  为了提高性能，某些实现可能会使用查找表存储一些常用值的 `cosh` 值，并通过插值来计算其他值。该文件的数据本身就可以被看作是测试用的查找表。

6. **指令优化:**  现代处理器通常提供针对特定数学运算的指令，例如 SIMD 指令，可以用于加速 `cosh` 的计算。

**涉及 dynamic linker 的功能:**

这个特定的数据文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载所需的共享库 (`.so` 文件)，并解析和处理这些库之间的依赖关系和符号链接。

`cosh` 函数的实现代码位于 bionic 库的某个共享库中，例如 `libm.so` (数学库)。

**so 布局样本:**

```
libm.so:
    .text:  # 包含可执行代码段
        ...
        [cosh 函数的实现代码]
        ...
    .rodata: # 包含只读数据段
        ...
        [cosh 函数可能用到的常量数据，例如近似计算用的系数]
        ...
    .data:  # 包含可读写数据段
        ...
    .bss:   # 包含未初始化的静态数据段
        ...
    .dynsym: # 动态符号表，列出该 so 导出的符号 (例如 cosh 函数)
        ...
        cosh
        ...
    .dynstr: # 动态字符串表，存储符号名称等字符串
        ...
        cosh
        ...
    .plt:   # Procedure Linkage Table，用于延迟绑定
        ...
    .got:   # Global Offset Table，用于存储全局变量的地址
        ...
```

**链接的处理过程:**

1. **编译时:** 当编译一个使用 `cosh` 函数的程序时，编译器会生成对 `cosh` 函数的未解析引用。链接器 (静态链接器或在 Android 上由 `lld` 完成部分工作) 会记录这些未解析的符号。

2. **程序加载时:**
   * Android 的 zygote 进程 fork 出新的应用进程。
   * 操作系统加载应用的 executable 文件。
   * **Dynamic Linker 介入:**  在程序启动的早期阶段，dynamic linker 被调用。
   * **加载依赖库:** Dynamic linker 读取应用的 ELF header，找到需要的共享库列表 (例如 `libm.so`)。
   * **查找库:** Dynamic linker 在预定义的路径中查找这些共享库。
   * **加载到内存:**  将找到的共享库加载到内存中的合适地址。
   * **符号解析 (Symbol Resolution):** Dynamic linker 遍历所有加载的共享库的符号表 (`.dynsym`)，找到程序中未解析的符号 (例如 `cosh`) 的定义。
   * **重定位 (Relocation):** Dynamic linker 更新程序代码中的地址，将对 `cosh` 函数的未解析引用指向 `libm.so` 中 `cosh` 函数的实际地址。这通常通过修改 Procedure Linkage Table (`.plt`) 和 Global Offset Table (`.got`) 来实现。
   * **延迟绑定 (Lazy Binding, 可选):** 为了提高启动速度，链接过程可能是延迟的。当第一次调用 `cosh` 函数时，会触发 PLT 中的一段代码，该代码会调用 dynamic linker 来解析符号并更新 GOT 表。后续调用将直接跳转到 GOT 表中已解析的地址。

**假设输入与输出 (逻辑推理):**

根据文件中的数据，可以举例说明：

* **假设输入:** `0x1.000000000000ca87c3898cffd1bcd954p31` (这是一个非常大的正数)
* **预期输出:** `-0x1.62e42fefa39f0p4` 和 `0x1.62e42fefa39f0p4` (一对相反数)。  考虑到 `cosh` 函数的特性，这可能是在测试某些边界条件或者与此输入相关的其他函数的行为。对于 `cosh` 自身，预期输出应该是正数且非常大。

* **假设输入:** `0x1.8b07551d9f5504c2bd28100196a4f66ap0` (等于 3.0)
* **预期输出:** `0x1.0p0` (等于 1.0)。 这显然是错误的，`cosh(3)` 不等于 1。  这可能是一个数据错误，或者该条目用于测试其他方面。 实际上，`cosh(3)` 约为 10.067。

* **假设输入:** `0x1.p0` (等于 1.0)
* **预期输出:** `0x1.0p-1074` (一个非常小的正数) 或 `0.0` 或 `-0.0`。 这可能是测试 `cosh(1)` 的精度或者在接近零的区域的行为。 `cosh(1)` 约为 1.543。

**用户或者编程常见的使用错误:**

1. **参数超出范围导致溢出:**
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = 1000.0; // 一个较大的值
       double result = cosh(x);
       printf("cosh(%f) = %f\n", x, result); // 可能会输出 inf (无穷大)
       return 0;
   }
   ```
   当输入 `cosh` 的参数的绝对值非常大时，结果会超出 `double` 类型能表示的最大值，导致溢出。

2. **误解 `cosh` 的定义域和值域:** `cosh` 的定义域是所有实数，值域是 `[1, +∞)`。用户可能会错误地认为可以得到负数结果。

3. **精度问题:** 对于某些极端的输入值，浮点数的精度限制可能会导致计算结果存在微小的误差。

**说明 android framework or ndk 是如何一步步的到达这里:**

**从 Android Framework 到 `cosh` (示例，可能路径很多):**

1. **Java Framework Layer:** 某个 Java framework 层的 API 调用，例如与图形处理或物理引擎相关的 API，最终需要进行一些数学计算。
2. **JNI Bridge:** Java 代码通过 Java Native Interface (JNI) 调用 native 代码。
3. **Native Library (C++):**  Native 代码 (可能是 Android framework 的一部分，或者是一个 NDK 库) 需要计算双曲余弦值。
4. **`#include <cmath>` 或 `#include <math.h>`:** Native 代码包含了 C/C++ 标准数学库的头文件。
5. **`std::cosh` 或 `::cosh`:** Native 代码调用了 `cosh` 函数。在 C++ 中，可能使用 `std::cosh`，在 C 中使用 `cosh`。
6. **Bionic `libm.so`:**  这些调用最终链接到 Android 的 bionic 库中的 `libm.so`，其中包含了 `cosh` 函数的实现。

**从 NDK 到 `cosh`:**

1. **NDK Application Code (C/C++):**  开发者编写的 NDK 应用代码。
2. **`#include <cmath>` or `#include <math.h>`:**  NDK 代码包含了数学库的头文件。
3. **`std::cosh` 或 `::cosh`:** NDK 代码直接调用了 `cosh` 函数。
4. **Bionic `libm.so`:**  应用在运行时链接到 bionic 的 `libm.so`，并调用其中的 `cosh` 实现。

**Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 拦截 `cosh` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const coshPtr = Module.findExportByName("libm.so", "cosh");

    if (coshPtr) {
        Interceptor.attach(coshPtr, {
            onEnter: function (args) {
                const input = args[0].toDouble();
                console.log(`[cosh Hook] Input: ${input}`);
            },
            onLeave: function (retval) {
                const output = retval.toDouble();
                console.log(`[cosh Hook] Output: ${output}`);
            }
        });
        console.log("cosh function hooked successfully!");
    } else {
        console.error("Failed to find cosh function in libm.so");
    }
} else {
    console.log("Frida hook for cosh is only supported on arm64 and x64.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `cosh_hook.js`).
2. 使用 Frida 连接到 Android 设备上的目标进程：
   ```bash
   frida -U -f <your_app_package_name> -l cosh_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <your_app_package_name> -l cosh_hook.js
   ```

**工作原理:**

* **`Process.arch`:** 检查当前进程的架构，因为符号名称和库名可能因架构而异。
* **`Module.findExportByName("libm.so", "cosh")`:** 在 `libm.so` 库中查找名为 "cosh" 的导出函数的地址。
* **`Interceptor.attach(coshPtr, ...)`:**  在找到的 `cosh` 函数入口处设置拦截器。
* **`onEnter`:** 当 `cosh` 函数被调用时执行。`args` 数组包含了函数的参数。这里取出第一个参数 (double 类型的输入值)。
* **`onLeave`:** 当 `cosh` 函数即将返回时执行。`retval` 包含了函数的返回值 (double 类型的输出值)。

通过这个 Frida Hook，你可以在应用运行时，实时观察 `cosh` 函数的输入和输出，从而帮助调试相关的数学计算过程。

Prompt: 
```
这是目录为bionic/tests/math_data/cosh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""

    -0x1.25e4f7b2737fap5
  },
  { // Entry 362
    0x1.00000000ffff654361c5613c8dcf8b38p15,
    0x1.62e42fefa39eep3
  },
  { // Entry 363
    0x1.00000000ffff654361c5613c8dcf8b38p15,
    -0x1.62e42fefa39eep3
  },
  { // Entry 364
    0x1.00000000ffffe54361c4e13c60713c1ap15,
    0x1.62e42fefa39efp3
  },
  { // Entry 365
    0x1.00000000ffffe54361c4e13c60713c1ap15,
    -0x1.62e42fefa39efp3
  },
  { // Entry 366
    0x1.000000010000654361c4613c7312ecfdp15,
    0x1.62e42fefa39f0p3
  },
  { // Entry 367
    0x1.000000010000654361c4613c7312ecfdp15,
    -0x1.62e42fefa39f0p3
  },
  { // Entry 368
    0x1.0000ffffffffb2a1fe40b25d88d964f9p7,
    0x1.62e42fefa39eep2
  },
  { // Entry 369
    0x1.0000ffffffffb2a1fe40b25d88d964f9p7,
    -0x1.62e42fefa39eep2
  },
  { // Entry 370
    0x1.0000fffffffff2a1be40b25d7d81c5dap7,
    0x1.62e42fefa39efp2
  },
  { // Entry 371
    0x1.0000fffffffff2a1be40b25d7d81c5dap7,
    -0x1.62e42fefa39efp2
  },
  { // Entry 372
    0x1.00010000000032a17e40b25d822a36bbp7,
    0x1.62e42fefa39f0p2
  },
  { // Entry 373
    0x1.00010000000032a17e40b25d822a36bbp7,
    -0x1.62e42fefa39f0p2
  },
  { // Entry 374
    0x1.00ffffffffffd9778798c06e53331924p3,
    0x1.62e42fefa39eep1
  },
  { // Entry 375
    0x1.00ffffffffffd9778798c06e53331924p3,
    -0x1.62e42fefa39eep1
  },
  { // Entry 376
    0x1.00fffffffffff9578798c06e505a5e4dp3,
    0x1.62e42fefa39efp1
  },
  { // Entry 377
    0x1.00fffffffffff9578798c06e505a5e4dp3,
    -0x1.62e42fefa39efp1
  },
  { // Entry 378
    0x1.01000000000019378798c06e5185a376p3,
    0x1.62e42fefa39f0p1
  },
  { // Entry 379
    0x1.01000000000019378798c06e5185a376p3,
    -0x1.62e42fefa39f0p1
  },
  { // Entry 380
    0x1.0fffffffffffeddde5750f42f95f3159p1,
    0x1.62e42fefa39eep0
  },
  { // Entry 381
    0x1.0fffffffffffeddde5750f42f95f3159p1,
    -0x1.62e42fefa39eep0
  },
  { // Entry 382
    0x1.0ffffffffffffcdde5750f42f89e6089p1,
    0x1.62e42fefa39efp0
  },
  { // Entry 383
    0x1.0ffffffffffffcdde5750f42f89e6089p1,
    -0x1.62e42fefa39efp0
  },
  { // Entry 384
    0x1.1000000000000bdde5750f42f8ed8fb8p1,
    0x1.62e42fefa39f0p0
  },
  { // Entry 385
    0x1.1000000000000bdde5750f42f8ed8fb8p1,
    -0x1.62e42fefa39f0p0
  },
  { // Entry 386
    0x1.3ffffffffffff8bf2895394dfd443ba8p0,
    0x1.62e42fefa39eep-1
  },
  { // Entry 387
    0x1.3ffffffffffff8bf2895394dfd443ba8p0,
    -0x1.62e42fefa39eep-1
  },
  { // Entry 388
    0x1.3ffffffffffffebf2895394dfd0b85c5p0,
    0x1.62e42fefa39efp-1
  },
  { // Entry 389
    0x1.3ffffffffffffebf2895394dfd0b85c5p0,
    -0x1.62e42fefa39efp-1
  },
  { // Entry 390
    0x1.40000000000004bf2895394dfd22cfe2p0,
    0x1.62e42fefa39f0p-1
  },
  { // Entry 391
    0x1.40000000000004bf2895394dfd22cfe2p0,
    -0x1.62e42fefa39f0p-1
  },
  { // Entry 392
    0x1.0f876ccdf6cd9510dcd50357a7335f9dp0,
    0x1.62e42fefa39eep-2
  },
  { // Entry 393
    0x1.0f876ccdf6cd9510dcd50357a7335f9dp0,
    -0x1.62e42fefa39eep-2
  },
  { // Entry 394
    0x1.0f876ccdf6cd967ae6bb6b4b63f0609bp0,
    0x1.62e42fefa39efp-2
  },
  { // Entry 395
    0x1.0f876ccdf6cd967ae6bb6b4b63f0609bp0,
    -0x1.62e42fefa39efp-2
  },
  { // Entry 396
    0x1.0f876ccdf6cd97e4f0a1d33f20be5a0fp0,
    0x1.62e42fefa39f0p-2
  },
  { // Entry 397
    0x1.0f876ccdf6cd97e4f0a1d33f20be5a0fp0,
    -0x1.62e42fefa39f0p-2
  },
  { // Entry 398
    0x1.03da6eb6f9075e7d98810fe96fe74840p0,
    0x1.62e42fefa39eep-3
  },
  { // Entry 399
    0x1.03da6eb6f9075e7d98810fe96fe74840p0,
    -0x1.62e42fefa39eep-3
  },
  { // Entry 400
    0x1.03da6eb6f9075ed6c364e82e43cc51c1p0,
    0x1.62e42fefa39efp-3
  },
  { // Entry 401
    0x1.03da6eb6f9075ed6c364e82e43cc51c1p0,
    -0x1.62e42fefa39efp-3
  },
  { // Entry 402
    0x1.03da6eb6f9075f2fee48c07317b56aadp0,
    0x1.62e42fefa39f0p-3
  },
  { // Entry 403
    0x1.03da6eb6f9075f2fee48c07317b56aadp0,
    -0x1.62e42fefa39f0p-3
  },
  { // Entry 404
    0x1.00f62557d91df3638b0ba7ca488b2839p0,
    0x1.62e42fefa39eep-4
  },
  { // Entry 405
    0x1.00f62557d91df3638b0ba7ca488b2839p0,
    -0x1.62e42fefa39eep-4
  },
  { // Entry 406
    0x1.00f62557d91df379c06a17c64244c1a5p0,
    0x1.62e42fefa39efp-4
  },
  { // Entry 407
    0x1.00f62557d91df379c06a17c64244c1a5p0,
    -0x1.62e42fefa39efp-4
  },
  { // Entry 408
    0x1.00f62557d91df38ff5c887c23bff5c07p0,
    0x1.62e42fefa39f0p-4
  },
  { // Entry 409
    0x1.00f62557d91df38ff5c887c23bff5c07p0,
    -0x1.62e42fefa39f0p-4
  },
  { // Entry 410
    0x1.003d81f25e8be1244ef875be32e5fbb0p0,
    0x1.62e42fefa39eep-5
  },
  { // Entry 411
    0x1.003d81f25e8be1244ef875be32e5fbb0p0,
    -0x1.62e42fefa39eep-5
  },
  { // Entry 412
    0x1.003d81f25e8be129dafae45b35704d8ap0,
    0x1.62e42fefa39efp-5
  },
  { // Entry 413
    0x1.003d81f25e8be129dafae45b35704d8ap0,
    -0x1.62e42fefa39efp-5
  },
  { // Entry 414
    0x1.003d81f25e8be12f66fd52f837fadf75p0,
    0x1.62e42fefa39f0p-5
  },
  { // Entry 415
    0x1.003d81f25e8be12f66fd52f837fadf75p0,
    -0x1.62e42fefa39f0p-5
  },
  { // Entry 416
    0x1.000f60066540a372cf2f0ea5d3ca7e8bp0,
    0x1.62e42fefa39eep-6
  },
  { // Entry 417
    0x1.000f60066540a372cf2f0ea5d3ca7e8bp0,
    -0x1.62e42fefa39eep-6
  },
  { // Entry 418
    0x1.000f60066540a374321a5962997281b2p0,
    0x1.62e42fefa39efp-6
  },
  { // Entry 419
    0x1.000f60066540a374321a5962997281b2p0,
    -0x1.62e42fefa39efp-6
  },
  { // Entry 420
    0x1.000f60066540a3759505a41f5f1a94dbp0,
    0x1.62e42fefa39f0p-6
  },
  { // Entry 421
    0x1.000f60066540a3759505a41f5f1a94dbp0,
    -0x1.62e42fefa39f0p-6
  },
  { // Entry 422
    0x1.000000000000ca87c3898cffd1bcd954p31,
    -0x1.62e42fefa39f0p4
  },
  { // Entry 423
    0x1.000000000000ca87c3898cffd1bcd954p31,
    0x1.62e42fefa39f0p4
  },
  { // Entry 424
    0x1.ffffffffffff950f871319ff0e6e2b95p30,
    -0x1.62e42fefa39efp4
  },
  { // Entry 425
    0x1.ffffffffffff950f871319ff0e6e2b95p30,
    0x1.62e42fefa39efp4
  },
  { // Entry 426
    0x1.fffffffffffd950f87131a007962a482p30,
    -0x1.62e42fefa39eep4
  },
  { // Entry 427
    0x1.fffffffffffd950f87131a007962a482p30,
    0x1.62e42fefa39eep4
  },
  { // Entry 428
    0x1.000000010000654361c4613c7312ecfdp15,
    -0x1.62e42fefa39f0p3
  },
  { // Entry 429
    0x1.000000010000654361c4613c7312ecfdp15,
    0x1.62e42fefa39f0p3
  },
  { // Entry 430
    0x1.00000000ffffe54361c4e13c60713c1ap15,
    -0x1.62e42fefa39efp3
  },
  { // Entry 431
    0x1.00000000ffffe54361c4e13c60713c1ap15,
    0x1.62e42fefa39efp3
  },
  { // Entry 432
    0x1.00000000ffff654361c5613c8dcf8b38p15,
    -0x1.62e42fefa39eep3
  },
  { // Entry 433
    0x1.00000000ffff654361c5613c8dcf8b38p15,
    0x1.62e42fefa39eep3
  },
  { // Entry 434
    0x1.00010000000032a17e40b25d822a36bbp7,
    -0x1.62e42fefa39f0p2
  },
  { // Entry 435
    0x1.00010000000032a17e40b25d822a36bbp7,
    0x1.62e42fefa39f0p2
  },
  { // Entry 436
    0x1.0000fffffffff2a1be40b25d7d81c5dap7,
    -0x1.62e42fefa39efp2
  },
  { // Entry 437
    0x1.0000fffffffff2a1be40b25d7d81c5dap7,
    0x1.62e42fefa39efp2
  },
  { // Entry 438
    0x1.0000ffffffffb2a1fe40b25d88d964f9p7,
    -0x1.62e42fefa39eep2
  },
  { // Entry 439
    0x1.0000ffffffffb2a1fe40b25d88d964f9p7,
    0x1.62e42fefa39eep2
  },
  { // Entry 440
    0x1.01000000000019378798c06e5185a376p3,
    -0x1.62e42fefa39f0p1
  },
  { // Entry 441
    0x1.01000000000019378798c06e5185a376p3,
    0x1.62e42fefa39f0p1
  },
  { // Entry 442
    0x1.00fffffffffff9578798c06e505a5e4dp3,
    -0x1.62e42fefa39efp1
  },
  { // Entry 443
    0x1.00fffffffffff9578798c06e505a5e4dp3,
    0x1.62e42fefa39efp1
  },
  { // Entry 444
    0x1.00ffffffffffd9778798c06e53331924p3,
    -0x1.62e42fefa39eep1
  },
  { // Entry 445
    0x1.00ffffffffffd9778798c06e53331924p3,
    0x1.62e42fefa39eep1
  },
  { // Entry 446
    0x1.1000000000000bdde5750f42f8ed8fb8p1,
    -0x1.62e42fefa39f0p0
  },
  { // Entry 447
    0x1.1000000000000bdde5750f42f8ed8fb8p1,
    0x1.62e42fefa39f0p0
  },
  { // Entry 448
    0x1.0ffffffffffffcdde5750f42f89e6089p1,
    -0x1.62e42fefa39efp0
  },
  { // Entry 449
    0x1.0ffffffffffffcdde5750f42f89e6089p1,
    0x1.62e42fefa39efp0
  },
  { // Entry 450
    0x1.0fffffffffffeddde5750f42f95f3159p1,
    -0x1.62e42fefa39eep0
  },
  { // Entry 451
    0x1.0fffffffffffeddde5750f42f95f3159p1,
    0x1.62e42fefa39eep0
  },
  { // Entry 452
    0x1.40000000000004bf2895394dfd22cfe2p0,
    -0x1.62e42fefa39f0p-1
  },
  { // Entry 453
    0x1.40000000000004bf2895394dfd22cfe2p0,
    0x1.62e42fefa39f0p-1
  },
  { // Entry 454
    0x1.3ffffffffffffebf2895394dfd0b85c5p0,
    -0x1.62e42fefa39efp-1
  },
  { // Entry 455
    0x1.3ffffffffffffebf2895394dfd0b85c5p0,
    0x1.62e42fefa39efp-1
  },
  { // Entry 456
    0x1.3ffffffffffff8bf2895394dfd443ba8p0,
    -0x1.62e42fefa39eep-1
  },
  { // Entry 457
    0x1.3ffffffffffff8bf2895394dfd443ba8p0,
    0x1.62e42fefa39eep-1
  },
  { // Entry 458
    0x1.0f876ccdf6cd97e4f0a1d33f20be5a0fp0,
    -0x1.62e42fefa39f0p-2
  },
  { // Entry 459
    0x1.0f876ccdf6cd97e4f0a1d33f20be5a0fp0,
    0x1.62e42fefa39f0p-2
  },
  { // Entry 460
    0x1.0f876ccdf6cd967ae6bb6b4b63f0609bp0,
    -0x1.62e42fefa39efp-2
  },
  { // Entry 461
    0x1.0f876ccdf6cd967ae6bb6b4b63f0609bp0,
    0x1.62e42fefa39efp-2
  },
  { // Entry 462
    0x1.0f876ccdf6cd9510dcd50357a7335f9dp0,
    -0x1.62e42fefa39eep-2
  },
  { // Entry 463
    0x1.0f876ccdf6cd9510dcd50357a7335f9dp0,
    0x1.62e42fefa39eep-2
  },
  { // Entry 464
    0x1.03da6eb6f9075f2fee48c07317b56aadp0,
    -0x1.62e42fefa39f0p-3
  },
  { // Entry 465
    0x1.03da6eb6f9075f2fee48c07317b56aadp0,
    0x1.62e42fefa39f0p-3
  },
  { // Entry 466
    0x1.03da6eb6f9075ed6c364e82e43cc51c1p0,
    -0x1.62e42fefa39efp-3
  },
  { // Entry 467
    0x1.03da6eb6f9075ed6c364e82e43cc51c1p0,
    0x1.62e42fefa39efp-3
  },
  { // Entry 468
    0x1.03da6eb6f9075e7d98810fe96fe74840p0,
    -0x1.62e42fefa39eep-3
  },
  { // Entry 469
    0x1.03da6eb6f9075e7d98810fe96fe74840p0,
    0x1.62e42fefa39eep-3
  },
  { // Entry 470
    0x1.00f62557d91df38ff5c887c23bff5c07p0,
    -0x1.62e42fefa39f0p-4
  },
  { // Entry 471
    0x1.00f62557d91df38ff5c887c23bff5c07p0,
    0x1.62e42fefa39f0p-4
  },
  { // Entry 472
    0x1.00f62557d91df379c06a17c64244c1a5p0,
    -0x1.62e42fefa39efp-4
  },
  { // Entry 473
    0x1.00f62557d91df379c06a17c64244c1a5p0,
    0x1.62e42fefa39efp-4
  },
  { // Entry 474
    0x1.00f62557d91df3638b0ba7ca488b2839p0,
    -0x1.62e42fefa39eep-4
  },
  { // Entry 475
    0x1.00f62557d91df3638b0ba7ca488b2839p0,
    0x1.62e42fefa39eep-4
  },
  { // Entry 476
    0x1.003d81f25e8be12f66fd52f837fadf75p0,
    -0x1.62e42fefa39f0p-5
  },
  { // Entry 477
    0x1.003d81f25e8be12f66fd52f837fadf75p0,
    0x1.62e42fefa39f0p-5
  },
  { // Entry 478
    0x1.003d81f25e8be129dafae45b35704d8ap0,
    -0x1.62e42fefa39efp-5
  },
  { // Entry 479
    0x1.003d81f25e8be129dafae45b35704d8ap0,
    0x1.62e42fefa39efp-5
  },
  { // Entry 480
    0x1.003d81f25e8be1244ef875be32e5fbb0p0,
    -0x1.62e42fefa39eep-5
  },
  { // Entry 481
    0x1.003d81f25e8be1244ef875be32e5fbb0p0,
    0x1.62e42fefa39eep-5
  },
  { // Entry 482
    0x1.bfeb3206958461e0cd949b740397374bp262,
    0x1.6db6db6db6db7p7
  },
  { // Entry 483
    0x1.bfeb3206958461e0cd949b740397374bp262,
    -0x1.6db6db6db6db7p7
  },
  { // Entry 484
    0x1.ee4adffc4816c196cc85c579b49b713cp341,
    0x1.db6db6db6db6ep7
  },
  { // Entry 485
    0x1.ee4adffc4816c196cc85c579b49b713cp341,
    -0x1.db6db6db6db6ep7
  },
  { // Entry 486
    0x1.10bbd304e4d53317191db80168f41e88p421,
    0x1.2492492492492p8
  },
  { // Entry 487
    0x1.10bbd304e4d53317191db80168f41e88p421,
    -0x1.2492492492492p8
  },
  { // Entry 488
    0x1.2cf8621aa3eacbce3c5c6aac7a52e872p500,
    0x1.5b6db6db6db6dp8
  },
  { // Entry 489
    0x1.2cf8621aa3eacbce3c5c6aac7a52e872p500,
    -0x1.5b6db6db6db6dp8
  },
  { // Entry 490
    0x1.4c21539572c19b59fc629129d307d9b1p579,
    0x1.9249249249248p8
  },
  { // Entry 491
    0x1.4c21539572c19b59fc629129d307d9b1p579,
    -0x1.9249249249248p8
  },
  { // Entry 492
    0x1.6e8422b4db33b6293cd44cd1c65585b2p658,
    0x1.c924924924923p8
  },
  { // Entry 493
    0x1.6e8422b4db33b6293cd44cd1c65585b2p658,
    -0x1.c924924924923p8
  },
  { // Entry 494
    0x1.6dde4c855f3397cd05f383e2ad5ef219p935,
    0x1.4492492492492p9
  },
  { // Entry 495
    0x1.6dde4c855f3397cd05f383e2ad5ef219p935,
    -0x1.4492492492492p9
  },
  { // Entry 496
    0x1.a178d253fc35a0b9802d9cd5f67cb7efp948,
    0x1.4924924924924p9
  },
  { // Entry 497
    0x1.a178d253fc35a0b9802d9cd5f67cb7efp948,
    -0x1.4924924924924p9
  },
  { // Entry 498
    0x1.dc5a9c97ea13a0062828386dc2460ac2p961,
    0x1.4db6db6db6db6p9
  },
  { // Entry 499
    0x1.dc5a9c97ea13a0062828386dc2460ac2p961,
    -0x1.4db6db6db6db6p9
  },
  { // Entry 500
    0x1.0fc53c727155d9dd001733d4258e3203p975,
    0x1.5249249249248p9
  },
  { // Entry 501
    0x1.0fc53c727155d9dd001733d4258e3203p975,
    -0x1.5249249249248p9
  },
  { // Entry 502
    0x1.361a22f5879a158106bee1e89ea2a4d7p988,
    0x1.56db6db6db6dap9
  },
  { // Entry 503
    0x1.361a22f5879a158106bee1e89ea2a4d7p988,
    -0x1.56db6db6db6dap9
  },
  { // Entry 504
    0x1.61d716eca93811f8d8288649dc2cee65p1001,
    0x1.5b6db6db6db6cp9
  },
  { // Entry 505
    0x1.61d716eca93811f8d8288649dc2cee65p1001,
    -0x1.5b6db6db6db6cp9
  },
  { // Entry 506
    HUGE_VAL,
    0x1.76db6db6db6dbp9
  },
  { // Entry 507
    HUGE_VAL,
    -0x1.76db6db6db6dbp9
  },
  { // Entry 508
    HUGE_VAL,
    0x1.8db6db6db6db6p9
  },
  { // Entry 509
    HUGE_VAL,
    -0x1.8db6db6db6db6p9
  },
  { // Entry 510
    HUGE_VAL,
    0x1.a492492492491p9
  },
  { // Entry 511
    HUGE_VAL,
    -0x1.a492492492491p9
  },
  { // Entry 512
    HUGE_VAL,
    0x1.bb6db6db6db6cp9
  },
  { // Entry 513
    HUGE_VAL,
    -0x1.bb6db6db6db6cp9
  },
  { // Entry 514
    HUGE_VAL,
    0x1.d249249249247p9
  },
  { // Entry 515
    HUGE_VAL,
    -0x1.d249249249247p9
  },
  { // Entry 516
    HUGE_VAL,
    0x1.e924924924922p9
  },
  { // Entry 517
    HUGE_VAL,
    -0x1.e924924924922p9
  },
  { // Entry 518
    0x1.93bf4ec282efb320a57f9ae02e01ae51p1014,
    -0x1.6p9
  },
  { // Entry 519
    0x1.93bf4ec282efb320a57f9ae02e01ae51p1014,
    0x1.6p9
  },
  { // Entry 520
    0x1.61d716eca99087be9352df5d131a5dd2p1001,
    -0x1.5b6db6db6db6ep9
  },
  { // Entry 521
    0x1.61d716eca99087be9352df5d131a5dd2p1001,
    0x1.5b6db6db6db6ep9
  },
  { // Entry 522
    0x1.361a22f587e79c09c420d21ecffc00cdp988,
    -0x1.56db6db6db6dcp9
  },
  { // Entry 523
    0x1.361a22f587e79c09c420d21ecffc00cdp988,
    0x1.56db6db6db6dcp9
  },
  { // Entry 524
    0x1.0fc53c727199cb2c1cb391c8c6b1cb5bp975,
    -0x1.524924924924ap9
  },
  { // Entry 525
    0x1.0fc53c727199cb2c1cb391c8c6b1cb5bp975,
    0x1.524924924924ap9
  },
  { // Entry 526
    0x1.dc5a9c97ea8ab6ad4e22cc3898b4d422p961,
    -0x1.4db6db6db6db8p9
  },
  { // Entry 527
    0x1.dc5a9c97ea8ab6ad4e22cc3898b4d422p961,
    0x1.4db6db6db6db8p9
  },
  { // Entry 528
    0x1.a178d253fc9dfeee152cb749eb6f6339p948,
    -0x1.4924924924926p9
  },
  { // Entry 529
    0x1.a178d253fc9dfeee152cb749eb6f6339p948,
    0x1.4924924924926p9
  },
  { // Entry 530
    0x1.6dde4c855f8f0f60274b5c37930499f5p935,
    -0x1.4492492492494p9
  },
  { // Entry 531
    0x1.6dde4c855f8f0f60274b5c37930499f5p935,
    0x1.4492492492494p9
  },
  { // Entry 532
    0x1.40a4b9c271c8c4271fbcc3df336e0edbp922,
    -0x1.4000000000002p9
  },
  { // Entry 533
    0x1.40a4b9c271c8c4271fbcc3df336e0edbp922,
    0x1.4000000000002p9
  },
  { // Entry 534
    0x1.p0,
    -0x1.0p-1074
  },
  { // Entry 535
    0x1.p0,
    0x1.0p-1074
  },
  { // Entry 536
    0x1.p0,
    -0.0
  },
  { // Entry 537
    0x1.p0,
    0x1.0p-1074
  },
  { // Entry 538
    0x1.p0,
    -0x1.0p-1074
  },
  { // Entry 539
    0x1.01d86cfadd84bed563ca81e639d82de4p0,
    0x1.eb851eb851eb7p-4
  },
  { // Entry 540
    0x1.01d86cfadd84bed563ca81e639d82de4p0,
    -0x1.eb851eb851eb7p-4
  },
  { // Entry 541
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    0x1.eb851eb851eb8p-4
  },
  { // Entry 542
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    -0x1.eb851eb851eb8p-4
  },
  { // Entry 543
    0x1.01d86cfadd84bf12fa34fbebe5d038bep0,
    0x1.eb851eb851eb9p-4
  },
  { // Entry 544
    0x1.01d86cfadd84bf12fa34fbebe5d038bep0,
    -0x1.eb851eb851eb9p-4
  },
  { // Entry 545
    0x1.20ac1862ae8d042fe838523e9530a73ep0,
    0x1.fffffffffffffp-2
  },
  { // Entry 546
    0x1.20ac1862ae8d042fe838523e9530a73ep0,
    -0x1.fffffffffffffp-2
  },
  { // Entry 547
    0x1.20ac1862ae8d0645823a4f060800e88cp0,
    0x1.0p-1
  },
  { // Entry 548
    0x1.20ac1862ae8d0645823a4f060800e88cp0,
    -0x1.0p-1
  },
  { // Entry 549
    0x1.20ac1862ae8d0a70b63e4894edd78b6ep0,
    0x1.0000000000001p-1
  },
  { // Entry 550
    0x1.20ac1862ae8d0a70b63e4894edd78b6ep0,
    -0x1.0000000000001p-1
  },
  { // Entry 551
    0x1.8b07551d9f54fb5bed45e8a4d5a91742p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 552
    0x1.8b07551d9f54fb5bed45e8a4d5a91742p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 553
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    0x1.0p0
  },
  { // Entry 554
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    -0x1.0p0
  },
  { // Entry 555
    0x1.8b07551d9f5517905cec5ebb19c4fa39p0,
    0x1.0000000000001p0
  },
  { // Entry 556
    0x1.8b07551d9f5517905cec5ebb19c4fa39p0,
    -0x1.0000000000001p0
  },
  { // Entry 557
    0x1.ab5adb9c435e4cc33d1386d805bcc667p30,
    0x1.5ffffffffffffp4
  },
  { // Entry 558
    0x1.ab5adb9c435e4cc33d1386d805bcc667p30,
    -0x1.5ffffffffffffp4
  },
  { // Entry 559
    0x1.ab5adb9c435ff81e18afca372828a676p30,
    0x1.6p4
  },
  { // Entry 560
    0x1.ab5adb9c435ff81e18afca372828a676p30,
    -0x1.6p4
  },
  { // Entry 561
    0x1.ab5adb9c4361a378f44c0d97f5ef6222p30,
    0x1.6000000000001p4
  },
  { // Entry 562
    0x1.ab5adb9c4361a378f44c0d97f5ef6222p30,
    -0x1.6000000000001p4
  },
  { // Entry 563
    0x1.226af33b1fdae7ecca102ad6b7f98a06p32,
    0x1.6ffffffffffffp4
  },
  { // Entry 564
    0x1.226af33b1fdae7ecca102ad6b7f98a06p32,
    -0x1.6ffffffffffffp4
  },
  { // Entry 565
    0x1.226af33b1fdc0a57bd4b4ab2311b5cdfp32,
    0x1.7p4
  },
  { // Entry 566
    0x1.226af33b1fdc0a57bd4b4ab2311b5cdfp32,
    -0x1.7p4
  },
  { // Entry 567
    0x1.226af33b1fdd2cc2b0866a8ecca822f4p32,
    0x1.7000000000001p4
  },
  { // Entry 568
    0x1.226af33b1fdd2cc2b0866a8ecca822f4p32,
    -0x1.7000000000001p4
  },
  { // Entry 569
    0x1.fffffffffffb9ede67b7a313295faa73p51,
    0x1.25e4f7b2737f9p5
  },
  { // Entry 570
    0x1.fffffffffffb9ede67b7a313295faa73p51,
    -0x1.25e4f7b2737f9p5
  },
  { // Entry 571
    0x1.ffffffffffff9ede67b7a30e671c79e2p51,
    0x1.25e4f7b2737fap5
  },
  { // Entry 572
    0x1.ffffffffffff9ede67b7a30e671c79e2p51,
    -0x1.25e4f7b2737fap5
  },
  { // Entry 573
    0x1.000000000001cf6f33dbd188d26ca4a9p52,
    0x1.25e4f7b2737fbp5
  },
  { // Entry 574
    0x1.000000000001cf6f33dbd188d26ca4a9p52,
    -0x1.25e4f7b2737fbp5
  },
  { // Entry 575
    0x1.6a09e667f3b73b2e9b132d51434e682dp52,
    0x1.28aac01252c6cp5
  },
  { // Entry 576
    0x1.6a09e667f3b73b2e9b132d51434e682dp52,
    -0x1.28aac01252c6cp5
  },
  { // Entry 577
    0x1.6a09e667f3ba0f4267e314c28dbf6b23p52,
    0x1.28aac01252c6dp5
  },
  { // Entry 578
    0x1.6a09e667f3ba0f4267e314c28dbf6b23p52,
    -0x1.28aac01252c6dp5
  },
  { // Entry 579
    0x1.6a09e667f3bce35634b2fc39805807b9p52,
    0x1.28aac01252c6ep5
  },
  { // Entry 580
    0x1.6a09e667f3bce35634b2fc39805807b9p52,
    -0x1.28aac01252c6ep5
  },
  { // Entry 581
    0x1.ffffffffff93ae594e9be425a010bdecp1023,
    0x1.633ce8fb9f87cp9
  },
  { // Entry 582
    0x1.ffffffffff93ae594e9be425a010bdecp1023,
    -0x1.633ce8fb9f87cp9
  },
  { // Entry 583
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    0x1.633ce8fb9f87dp9
  },
  { // Entry 584
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    -0x1.633ce8fb9f87dp9
  },
  { // Entry 585
    HUGE_VAL,
    0x1.633ce8fb9f87ep9
  },
  { // Entry 586
    HUGE_VAL,
    -0x1.633ce8fb9f87ep9
  },
  { // Entry 587
    HUGE_VAL,
    -0x1.633ce8fb9f87ep9
  },
  { // Entry 588
    HUGE_VAL,
    0x1.633ce8fb9f87ep9
  },
  { // Entry 589
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    -0x1.633ce8fb9f87dp9
  },
  { // Entry 590
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    0x1.633ce8fb9f87dp9
  },
  { // Entry 591
    0x1.ffffffffff93ae594e9be425a010bdecp1023,
    -0x1.633ce8fb9f87cp9
  },
  { // Entry 592
    0x1.ffffffffff93ae594e9be425a010bdecp1023,
    0x1.633ce8fb9f87cp9
  },
  { // Entry 593
    0x1.0000000000000007ffffffffffff800ap0,
    0x1.fffffffffffffp-31
  },
  { // Entry 594
    0x1.0000000000000007ffffffffffff800ap0,
    -0x1.fffffffffffffp-31
  },
  { // Entry 595
    0x1.0000000000000008000000000000000ap0,
    0x1.0p-30
  },
  { // Entry 596
    0x1.0000000000000008000000000000000ap0,
    -0x1.0p-30
  },
  { // Entry 597
    0x1.0000000000000008000000000001000ap0,
    0x1.0000000000001p-30
  },
  { // Entry 598
    0x1.0000000000000008000000000001000ap0,
    -0x1.0000000000001p-30
  },
  { // Entry 599
    0x1.0000000200000000aaaa8aaac16c016cp0,
    0x1.fffffffffffffp-16
  },
  { // Entry 600
    0x1.0000000200000000aaaa8aaac16c016cp0,
    -0x1.fffffffffffffp-16
  },
  { // Entry 601
    0x1.0000000200000000aaaaaaaac16c16c1p0,
    0x1.0p-15
  },
  { // Entry 602
    0x1.0000000200000000aaaaaaaac16c16c1p0,
    -0x1.0p-15
  },
  { // Entry 603
    0x1.0000000200000000aaaaeaaac16c416cp0,
    0x1.0000000000001p-15
  },
  { // Entry 604
    0x1.0000000200000000aaaaeaaac16c416cp0,
    -0x1.0000000000001p-15
  },
  { // Entry 605
    0x1.0008000aaab05b06d073fbf35675d3c7p0,
    0x1.fffffffffffffp-7
  },
  { // Entry 606
    0x1.0008000aaab05b06d073fbf35675d3c7p0,
    -0x1.fffffffffffffp-7
  },
  { // Entry 607
    0x1.0008000aaab05b0750755149bcdca034p0,
    0x1.0p-6
  },
  { // Entry 608
    0x1.0008000aaab05b0750755149bcdca034p0,
    -0x1.0p-6
  },
  { // Entry 609
    0x1.0008000aaab05b085077fbf689aa450ep0,
    0x1.0000000000001p-6
  },
  { // Entry 610
    0x1.0008000aaab05b085077fbf689aa450ep0,
    -0x1.0000000000001p-6
  },
  { // Entry 611
    0x1.002000aaac16c30a31d59c22178e80d2p0,
    0x1.fffffffffffffp-6
  },
  { // Entry 612
    0x1.002000aaac16c30a31d59c22178e80d2p0,
    -0x1.fffffffffffffp-6
  },
  { // Entry 613
    0x1.002000aaac16c30c31eaf1bbb1901947p0,
    0x1.0p-5
  },
  { // Entry 614
    0x1.002000aaac16c30c31eaf1bbb1901947p0,
    -0x1.0p-5
  },
  { // Entry 615
    0x1.002000aaac16c31032159ceee5937a38p0,
    0x1.0000000000001p-5
  },
  { // Entry 616
    0x1.002000aaac16c31032159ceee5937a38p0,
    -0x1.0000000000001p-5
  },
  { // Entry 617
    0x1.00800aab05b1fb1c50429ea2694ccac8p0,
    0x1.fffffffffffffp-5
  },
  { // Entry 618
    0x1.00800aab05b1fb1c50429ea2694ccac8p0,
    -0x1.fffffffffffffp-5
  },
  { // Entry 619
    0x1.00800aab05b1fb245198050937bb0368p0,
    0x1.0p-4
  },
  { // Entry 620
    0x1.00800aab05b1fb245198050937bb0368p0,
    -0x1.0p-4
  },
  { // Entry 621
    0x1.00800aab05b1fb345442d1d6d4983508p0,
    0x1.0000000000001p-4
  },
  { // Entry 622
    0x1.00800aab05b1fb345442d1d6d4983508p0,
    -0x1.0000000000001p-4
  },
  { // Entry 623
    0x1.0200aac16db6edcc80b33b1062033cc7p0,
    0x1.fffffffffffffp-4
  },
  { // Entry 624
    0x1.0200aac16db6edcc80b33b1062033cc7p0,
    -0x1.fffffffffffffp-4
  },
  { // Entry 625
    0x1.0200aac16db6edec960cd51207e46c1ep0,
    0x1.0p-3
  },
  { // Entry 626
    0x1.0200aac16db6edec960cd51207e46c1ep0,
    -0x1.0p-3
  },
  { // Entry 627
    0x1.0200aac16db6ee2cc0c0091553a9d0cep0,
    0x1.0000000000001p-3
  },
  { // Entry 628
    0x1.0200aac16db6ee2cc0c0091553a9d0cep0,
    -0x1.0000000000001p-3
  },
  { // Entry 629
    0x1.080ab05ca6145e5b88296b187f06805fp0,
    0x1.fffffffffffffp-3
  },
  { // Entry 630
    0x1.080ab05ca6145e5b88296b187f06805fp0,
    -0x1.fffffffffffffp-3
  },
  { // Entry 631
    0x1.080ab05ca6145edcde90399c8713a384p0,
    0x1.0p-2
  },
  { // Entry 632
    0x1.080ab05ca6145edcde90399c8713a384p0,
    -0x1.0p-2
  },
  { // Entry 633
    0x1.080ab05ca6145fdf8b5dd6a4973a4a4ep0,
    0x1.0000000000001p-2
  },
  { // Entry 634
    0x1.080ab05ca6145fdf8b5dd6a4973a4a4ep0,
    -0x1.0000000000001p-2
  },
  { // Entry 635
    0x1.e18fa0df2d9ba58f58936095ae8d9969p1,
    0x1.fffffffffffffp0
  },
  { // Entry 636
    0x1.e18fa0df2d9ba58f58936095ae8d9969p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 637
    0x1.e18fa0df2d9bc29327f717774d0c0661p1,
    0x1.0p1
  },
  { // Entry 638
    0x1.e18fa0df2d9bc29327f717774d0c0661p1,
    -0x1.0p1
  },
  { // Entry 639
    0x1.e18fa0df2d9bfc9ac6be853a8fad8f33p1,
    0x1.0000000000001p1
  },
  { // Entry 640
    0x1.e18fa0df2d9bfc9ac6be853a8fad8f33p1,
    -0x1.0000000000001p1
  },
  { // Entry 641
    0x1.b4ee858de3e7c9cd569e3d719b38d342p4,
    0x1.fffffffffffffp1
  },
  { // Entry 642
    0x1.b4ee858de3e7c9cd569e3d719b38d342p4,
    -0x1.fffffffffffffp1
  },
  { // Entry 643
    0x1.b4ee858de3e80061c6a51dddf960f317p4,
    0x1.0p2
  },
  { // Entry 644
    0x1.b4ee858de3e80061c6a51dddf960f317p4,
    -0x1.0p2
  },
  { // Entry 645
    0x1.b4ee858de3e86d8aa6b2deb6ca2c6104p4,
    0x1.0000000000001p2
  },
  { // Entry 646
    0x1.b4ee858de3e86d8aa6b2deb6ca2c6104p4,
    -0x1.0000000000001p2
  },
  { // Entry 647
    0x1.749eaa93f4e703e92c604cbb82b0787ap10,
    0x1.fffffffffffffp2
  },
  { // Entry 648
    0x1.749eaa93f4e703e92c604cbb82b0787ap10,
    -0x1.fffffffffffffp2
  },
  { // Entry 649
    0x1.749eaa93f4e76110d5a587e50e4d3dc3p10,
    0x1.0p3
  },
  { // Entry 650
    0x1.749eaa93f4e76110d5a587e50e4d3dc3p10,
    -0x1.0p3
  },
  { // Entry 651
    0x1.749eaa93f4e81b60282ffe386b648851p10,
    0x1.0000000000001p3
  },
  { // Entry 652
    0x1.749eaa93f4e81b60282ffe386b648851p10,
    -0x1.0000000000001p3
  },
  { // Entry 653
    0x1.0f2ebd0a800543a63cca0142899e262fp22,
    0x1.fffffffffffffp3
  },
  { // Entry 654
    0x1.0f2ebd0a800543a63cca0142899e262fp22,
    -0x1.fffffffffffffp3
  },
  { // Entry 655
    0x1.0f2ebd0a8005cb3d9b4f414186aba4d7p22,
    0x1.0p4
  },
  { // Entry 656
    0x1.0f2ebd0a8005cb3d9b4f414186aba4d7p22,
    -0x1.0p4
  },
  { // Entry 657
    0x1.0f2ebd0a8006da6c5859c1404c29aff0p22,
    0x1.0000000000001p4
  },
  { // Entry 658
    0x1.0f2ebd0a8006da6c5859c1404c29aff0p22,
    -0x1.0000000000001p4
  },
  { // Entry 659
    0x1.1f43fcc4b661a8944ac389c44c1372ffp45,
    0x1.fffffffffffffp4
  },
  { // Entry 660
    0x1.1f43fcc4b661a8944ac389c44c1372ffp45,
    -0x1.fffffffffffffp4
  },
  { // Entry 661
    0x1.1f43fcc4b662c7d8478840268449bc25p45,
    0x1.0p5
  },
  { // Entry 662
    0x1.1f43fcc4b662c7d8478840268449bc25p45,
    -0x1.0p5
  },
  { // Entry 663
    0x1.1f43fcc4b66506604111acee528244bfp45,
    0x1.0000000000001p5
  },
  { // Entry 664
    0x1.1f43fcc4b66506604111acee528244bfp45,
    -0x1.0000000000001p5
  },
  { // Entry 665
    0x1.425982cf597a4d52c89ea857bbaa807ap91,
    0x1.fffffffffffffp5
  },
  { // Entry 666
    0x1.425982cf597a4d52c89ea857bbaa807ap91,
    -0x1.fffffffffffffp5
  },
  { // Entry 667
    0x1.425982cf597cd205ce3d5b4edb031756p91,
    0x1.0p6
  },
  { // Entry 668
    0x1.425982cf597cd205ce3d5b4edb031756p91,
    -0x1.0p6
  },
  { // Entry 669
    0x1.425982cf5981db6bd97ac14c35e666c6p91,
    0x1.0000000000001p6
  },
  { // Entry 670
    0x1.425982cf5981db6bd97ac14c35e666c6p91,
    -0x1.0000000000001p6
  },
  { // Entry 671
    0x1.95e54c5dd41b20600dd601a0ae672ff4p183,
    0x1.fffffffffffffp6
  },
  { // Entry 672
    0x1.95e54c5dd41b20600dd601a0ae672ff4p183,
    -0x1.fffffffffffffp6
  },
  { // Entry 673
    0x1.95e54c5dd42177f53f4d5219df11ca3bp183,
    0x1.0p7
  },
  { // Entry 674
    0x1.95e54c5dd42177f53f4d5219df11ca3bp183,
    -0x1.0p7
  },
  { // Entry 675
    0x1.95e54c5dd42e271fa23bf3585b655060p183,
    0x1.0000000000001p7
  },
  { // Entry 676
    0x1.95e54c5dd42e271fa23bf3585b655060p183,
    -0x1.0000000000001p7
  },
  { // Entry 677
    0x1.41c7a8814be192a5df25b042af824efdp368,
    0x1.fffffffffffffp7
  },
  { // Entry 678
    0x1.41c7a8814be192a5df25b042af824efdp368,
    -0x1.fffffffffffffp7
  },
  { // Entry 679
    0x1.41c7a8814beba0e323300f777da65854p368,
    0x1.0p8
  },
  { // Entry 680
    0x1.41c7a8814beba0e323300f777da65854p368,
    -0x1.0p8
  },
  { // Entry 681
    0x1.41c7a8814bffbd5dab44ced26faccbfbp368,
    0x1.0000000000001p8
  },
  { // Entry 682
    0x1.41c7a8814bffbd5dab44ced26faccbfbp368,
    -0x1.0000000000001p8
  },
  { // Entry 683
    0x1.9476504ba8399f5b97cae35beb78c3c5p737,
    0x1.fffffffffffffp8
  },
  { // Entry 684
    0x1.9476504ba8399f5b97cae35beb78c3c5p737,
    -0x1.fffffffffffffp8
  },
  { // Entry 685
    0x1.9476504ba852e6c09c8567c01c5a6648p737,
    0x1.0p9
  },
  { // Entry 686
    0x1.9476504ba852e6c09c8567c01c5a6648p737,
    -0x1.0p9
  },
  { // Entry 687
    0x1.9476504ba885758aa5fa7545e10e8e46p737,
    0x1.0000000000001p9
  },
  { // Entry 688
    0x1.9476504ba885758aa5fa7545e10e8e46p737,
    -0x1.0000000000001p9
  },
  { // Entry 689
    HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 690
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 691
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 692
    HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 693
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 694
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 695
    HUGE_VAL,
    0x1.ffffffffffffep1023
  },
  { // Entry 696
    0x1.72f147fee40004f636960fb65616f933p3,
    0x1.921fb54442d18p1
  },
  { // Entry 697
    0x1.412cc2a8d4e9df8319ceee45d93f21f3p1,
    0x1.921fb54442d18p0
  },
  { // Entry 698
    0x1.8b07551d9f5517905cec5ebb19c4fa39p0,
    0x1.0000000000001p0
  },
  { // Entry 699
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    0x1.0p0
  },
  { // Entry 700
    0x1.8b07551d9f54fb5bed45e8a4d5a91742p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 701
    0x1.531994ce525b97d489c1beb383943240p0,
    0x1.921fb54442d18p-1
  },
  { // Entry 702
    0x1.p0,
    0x1.0000000000001p-1022
  },
  { // Entry 703
    0x1.p0,
    0x1.0p-1022
  },
  { // Entry 704
    0x1.p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 705
    0x1.p0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 706
    0x1.p0,
    0x1.0p-1073
  },
  { // Entry 707
    0x1.p0,
    0x1.0p-1074
  },
  { // Entry 708
    0x1.p0,
    0.0
  },
  { // Entry 709
    0x1.p0,
    -0.0
  },
  { // Entry 710
    0x1.p0,
    -0x1.0p-1074
  },
  { // Entry 711
    0x1.p0,
    -0x1.0p-1073
  },
  { // Entry 712
    0x1.p0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 713
    0x1.p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 714
    0x1.p0,
    -0x1.0p-1022
  },
  { // Entry 715
    0x1.p0,
    -0x1.0000000000001p-1022
  },
  { // Entry 716
    0x1.531994ce525b97d489c1beb383943240p0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 717
    0x1.8b07551d9f54fb5bed45e8a4d5a91742p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 718
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    -0x1.0p0
  },
  { // Entry 719
    0x1.8b07551d9f5517905cec5ebb19c4fa39p0,
    -0x1.0000000000001p0
  },
  { // Entry 720
    0x1.412cc2a8d4e9df8319ceee45d93f21f3p1,
    -0x1.921fb54442d18p0
  },
  { // Entry 721
    0x1.72f147fee40004f636960fb65616f933p3,
    -0x1.921fb54442d18p1
  },
  { // Entry 722
    HUGE_VAL,
    -0x1.ffffffffffffep1023
  },
  { // Entry 723
    HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 724
    HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 725
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    0x1.633ce8fb9f87dp9
  },
  { // Entry 726
    0x1.ffffffffffd3ae594e9bda9b6b3a9168p1023,
    -0x1.633ce8fb9f87dp9
  },
  { // Entry 727
    HUGE_VAL,
    0x1.633ce8fb9f87ep9
  },
  { // Entry 728
    HUGE_VAL,
    -0x1.633ce8fb9f87ep9
  }
};

"""


```