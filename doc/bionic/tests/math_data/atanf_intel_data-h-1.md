Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The user has provided a data file (`atanf_intel_data.handroid`) used for testing the `atanf` function in Android's Bionic library. The goal is to understand the function of this *data file*, not the `atanf` function itself. The request asks for the file's purpose, its relation to Android, and details about related functions (specifically libc and dynamic linker).

2. **Initial Assessment of the Data:** I quickly scanned the provided data. I see a large array of C-style structures. Each structure contains two floating-point numbers. The format `0x1.abcdefp-n` strongly suggests hexadecimal representation of floating-point values. The consistent pairing of negative and positive values is also noticeable.

3. **Formulate the Primary Function:** The most obvious conclusion is that this file contains test data. Specifically, it looks like input/output pairs for the `atanf` function. The first number in each pair is likely an input to `atanf`, and the second is the expected output. The presence of both positive and negative inputs suggests testing the function's behavior across the number line and handling of sign.

4. **Connect to Android's Purpose:** Since the file is in `bionic/tests/math_data/`, it's clearly part of Android's testing infrastructure for its math library. This library is crucial for any application that performs floating-point calculations. Testing ensures accuracy and robustness.

5. **Address the libc Function Question:** The relevant libc function is `atanf`. The prompt asks how it's implemented. This is a complex topic, but the core idea is using mathematical approximations (like Taylor series or Chebyshev polynomials) and range reduction techniques to calculate the arctangent. It's important to emphasize that this *data file* doesn't *implement* `atanf`; it validates its implementation.

6. **Address the Dynamic Linker Question:**  The dynamic linker's role is to load and link shared libraries. While this *data file* itself isn't directly involved in dynamic linking, the `atanf` function it tests resides in a shared library (likely `libm.so`). I need to explain how the linker would handle this. This involves describing the structure of a `.so` file, the process of symbol resolution, and relocation. A simple example of an `.so` layout is helpful.

7. **Logical Reasoning and Examples:** I need to illustrate how the test data works. A simple example of an input/output pair and its relation to the `atanf` function is essential. The positive/negative pairing should be explained as testing symmetry.

8. **Common Usage Errors:** While the data file itself isn't directly "used" by programmers, misunderstanding the limitations of floating-point arithmetic and relying on exact equality are common errors when working with math functions. An example demonstrating this is important.

9. **Android Framework/NDK Connection:**  I need to trace how a call to `atanf` from an Android application (either through the framework or NDK) reaches the Bionic library. This involves steps like the app calling a method, the framework delegating to native code (for framework calls), the NDK providing C APIs, and ultimately the dynamic linker loading `libm.so`.

10. **Frida Hook Example:** A practical demonstration of how to intercept a call to `atanf` using Frida is very valuable. This should show how to hook the function, log input and output, and potentially modify the behavior.

11. **Summarize the Function (Part 2 of 3):**  Finally, I need to concisely summarize the function of this specific data file, based on the analysis above. The key points are: test data for `atanf`, input/output pairs, validation of the Bionic implementation.

12. **Structure and Language:** I need to organize the answer logically, using clear and concise language. Chinese is required. Breaking down the answer into sections corresponding to the user's questions makes it easier to read. Using code formatting for the data snippets and Frida example improves readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file contains coefficients for some approximation algorithm.
* **Correction:** The structure of input/output pairs is much more evident upon closer inspection. This is more likely test data.
* **Initial thought:** Focus heavily on the mathematical implementation of `atanf`.
* **Correction:** The request is about the *data file*. While explaining `atanf`'s purpose is necessary, the focus should be on how the data file helps test it.
* **Initial thought:** Provide a very detailed explanation of the dynamic linker.
* **Correction:** Keep the dynamic linker explanation concise and focused on the relevant aspects (loading and linking `libm.so`). The user didn't ask for a deep dive into linker internals.
* **Initial thought:** Just list potential errors in using `atanf`.
* **Correction:** Focus on errors *related to the testing* or the *nature of floating-point numbers*, as that’s more relevant to the data file's purpose.

By following these steps and refining my understanding along the way, I can construct a comprehensive and accurate answer to the user's request.
好的，我们来归纳一下 `bionic/tests/math_data/atanf_intel_data.handroid` 这个文件的功能，这是第 2 部分的总结。

**文件功能归纳（第 2 部分）:**

这份代码片段展示了 `atanf_intel_data.handroid` 文件中 **Entry 380 到 Entry 770** 的内容。

从数据结构来看，每一项 `Entry` 包含两个 `float` 类型的数值。  结合文件路径和文件名 (`atanf_intel_data`)，以及第一部分的分析，我们可以推断出：

* **这是一个用于测试 `atanf` 函数的数据文件。**  `atanf` 是 C 标准库 `<math.h>` 中反正切函数的单精度浮点数版本。
* **每条 `Entry` 包含一对输入和期望输出值。** 第一个 `float` 值很可能是 `atanf` 函数的输入参数，第二个 `float` 值是对于该输入的期望返回值。
* **该文件针对 Intel 架构进行了优化或特定的测试。** 文件名中的 "intel" 暗示了这一点。
* **该文件可能用于回归测试。** 通过存储大量的输入输出对，可以确保 `atanf` 函数在修改后仍然能够产生正确的结果。
* **数据覆盖了不同的输入范围和特殊情况。**  可以看到输入值有正有负，有接近于零的小数，也有较大数值，甚至包括 0.0 和 -0.0。 这有助于全面测试 `atanf` 函数的各种边界情况和精度。
* **正负成对出现，用于测试函数的奇偶性。**  观察到很多 Entry 中，输入值是一对相反数，相应的输出值也是一对相反数，这符合反正切函数是奇函数的性质 (atan(-x) = -atan(x))。

**与 Android 功能的关系举例说明：**

这个数据文件是 Android Bionic 库的一部分，Bionic 是 Android 系统的 C 库。  `atanf` 函数是 Bionic 库提供的数学函数之一。

举例来说，Android 系统中的图形渲染、物理模拟、传感器数据处理等很多底层功能都可能涉及到浮点数的运算，包括反正切计算。 假设一个 Android 应用需要计算一个触摸事件的角度，可能会使用到 `atanf` 函数。  Bionic 提供的 `atanf` 函数的正确性直接影响到这些功能的准确性。

**详细解释每一个 libc 函数的功能是如何实现的：**

这里涉及的 libc 函数主要是 `atanf`。 `atanf` 的实现通常不会直接存储在像这样的数据文件中，而是实现在 `libm.so` (math library) 中。

`atanf` 函数的实现是一个复杂的数学过程，通常会采用以下几种技术：

1. **范围归约 (Range Reduction):**  由于反正切函数的定义域是实数域，直接计算所有可能的输入值效率不高。 范围归约将输入值 `x` 转换到一个较小的、易于计算的区间（例如 `[-1, 1]`），然后在该区间内进行近似计算。 这通常使用三角恒等式，例如：
   * 如果 `|x| > 1`，可以使用 `atan(x) = π/2 - atan(1/x)` 或 `atan(x) = -π/2 - atan(1/x)`。

2. **多项式或有理逼近:** 在归约后的区间内，使用多项式或有理函数来近似反正切函数。  常用的逼近方法包括：
   * **泰勒级数展开:**  `atan(x) = x - x^3/3 + x^5/5 - x^7/7 + ...` (收敛域为 `|x| <= 1`)。 但泰勒级数在接近边界时收敛速度较慢。
   * **切比雪夫多项式逼近:** 可以更有效地在给定区间内逼近函数，减少所需的项数以达到一定的精度。
   * **Padé 逼近:** 使用有理函数（两个多项式的比值）进行逼近，通常比多项式逼近更精确。

3. **特殊情况处理:**  对于一些特殊输入值，例如 0, ±1, ±∞, NaN，需要进行特殊处理以返回正确的结果。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`atanf` 函数位于 `libm.so` 共享库中。 当一个 Android 应用（或其他动态链接的程序）调用 `atanf` 时，动态链接器负责在运行时加载 `libm.so` 并解析对 `atanf` 函数的引用。

**`libm.so` 的简单布局样本：**

```
libm.so:
  .text          # 包含可执行代码，包括 atanf 的实现
  .rodata        # 包含只读数据，例如数学常数
  .data          # 包含已初始化的全局变量
  .bss           # 包含未初始化的全局变量
  .dynsym        # 动态符号表，列出导出的符号 (例如 atanf)
  .dynstr        # 动态字符串表，存储符号名称
  .plt           # 程序链接表，用于延迟绑定
  .got           # 全局偏移表，存储全局符号的地址
  ... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接 (Static Linking)：** 当应用程序被编译时，编译器会记录下对外部符号（例如 `atanf`）的引用，但不会解析其具体地址。

2. **加载时链接 (Load Time Linking)：** 当 Android 系统启动应用程序时，动态链接器 (如 `linker64` 或 `linker`) 会被调用。

3. **加载共享库：** 动态链接器会找到应用程序依赖的共享库 (`libm.so`) 并将其加载到内存中。

4. **符号解析 (Symbol Resolution)：** 动态链接器会遍历应用程序和其依赖的共享库的动态符号表 (`.dynsym`)，找到 `atanf` 符号在 `libm.so` 中的地址。

5. **重定位 (Relocation)：**  由于共享库被加载到内存的哪个地址是运行时决定的，链接器需要更新应用程序中对 `atanf` 的引用，将其指向 `libm.so` 中 `atanf` 函数的实际内存地址。 这通常通过全局偏移表 (`.got`) 和程序链接表 (`.plt`) 实现。  第一次调用 `atanf` 时，会通过 `.plt` 跳转到链接器，链接器解析地址并更新 `.got` 表项，后续调用将直接通过 `.plt` 跳转到 `atanf` 的实际地址（延迟绑定）。

**假设输入与输出（逻辑推理）：**

查看数据文件中的一些条目，我们可以进行逻辑推理：

* **假设输入:**  `0x1.0c1521c014d01f8a9ddecc36f1430940p-1` (十六进制浮点数，大约为 0.539)
* **期望输出:** `0x1.279a72p-1` (十六进制浮点数，大约为 0.463)

根据反正切函数的定义，`atan(0.539)` 应该接近 `0.494` 弧度。  需要注意的是，这里的数据是单精度浮点数，精度有限。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **精度问题：**  浮点数运算存在精度限制。 直接比较两个浮点数是否相等是很危险的。 应该使用一个小的容差值 (epsilon) 来判断它们是否足够接近。
   ```c++
   float result = atanf(x);
   if (result == expected_value) { // 错误的做法
       // ...
   }
   if (fabs(result - expected_value) < 1e-6f) { // 推荐的做法
       // ...
   }
   ```

2. **输入超出定义域：** 虽然 `atanf` 的定义域是整个实数域，但在某些上下文中，输入值可能超出预期范围，导致不期望的结果。

3. **未包含头文件：** 使用 `atanf` 函数需要包含 `<math.h>` 头文件。  如果忘记包含，可能会导致编译错误或链接错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `atanf` 的路径示例：**

1. **Java 代码调用 Framework API:**  例如，一个图形相关的操作，可能在 `android.graphics` 包下的某个类中调用了需要角度计算的方法。

2. **Framework 调用 Native 代码:**  Android Framework 的很多底层实现是使用 C/C++ 编写的。  Java 代码会通过 JNI (Java Native Interface) 调用相应的 Native 方法。

3. **Native 代码调用 Bionic 库函数:**  Framework 的 Native 代码可能会直接或间接地调用 Bionic 库提供的数学函数，例如 `atanf`。

**NDK 到 `atanf` 的路径示例：**

1. **NDK 应用调用 C/C++ 函数:**  使用 NDK 开发的应用可以直接编写 C/C++ 代码。

2. **C/C++ 代码调用 `atanf`:**  NDK 应用的 C/C++ 代码可以直接包含 `<math.h>` 并调用 `atanf` 函数。

**Frida Hook 示例：**

以下是一个使用 Frida hook `atanf` 函数的示例，用于监控其输入和输出：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "atanf"), {
    onEnter: function(args) {
        this.input = args[0];
        console.log("atanf called with input: " + this.input);
    },
    onLeave: function(retval) {
        console.log("atanf returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. **安装 Frida 和 Python 绑定。**
2. **将 `你的应用包名` 替换为要调试的 Android 应用的包名。**
3. **运行该 Python 脚本。**
4. **在 Android 设备上运行目标应用，并执行会调用 `atanf` 的操作。**

**预期输出：**

当目标应用调用 `atanf` 函数时，Frida 会拦截该调用并打印输入参数和返回值到控制台。

**总结:**

`atanf_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `atanf` 函数正确性的数据文件。 它包含大量的输入输出对，用于回归测试和验证 `atanf` 在不同输入范围下的行为。  理解这个文件的作用有助于理解 Android 底层数学库的测试机制和确保系统功能的稳定性和准确性。

### 提示词
```
这是目录为bionic/tests/math_data/atanf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
},
  { // Entry 380
    -0x1.d6e1429159f6f0290cf9f2fb24bc26bdp-4,
    -0x1.d8f720p-4
  },
  { // Entry 381
    0x1.5f3d40f500501f80bba7a781b1619b85p-3,
    0x1.62b958p-3
  },
  { // Entry 382
    -0x1.5f3d40f500501f80bba7a781b1619b85p-3,
    -0x1.62b958p-3
  },
  { // Entry 383
    0x1.d0d0f7d861c753c31fa29e74145dc127p-3,
    0x1.d8f720p-3
  },
  { // Entry 384
    -0x1.d0d0f7d861c753c31fa29e74145dc127p-3,
    -0x1.d8f720p-3
  },
  { // Entry 385
    0x1.1fc79ca9ca92823d01375328ac472eedp-2,
    0x1.279a74p-2
  },
  { // Entry 386
    -0x1.1fc79ca9ca92823d01375328ac472eedp-2,
    -0x1.279a74p-2
  },
  { // Entry 387
    0x1.5579fd644a1a2d96faf5bb8844656d0cp-2,
    0x1.62b958p-2
  },
  { // Entry 388
    -0x1.5579fd644a1a2d96faf5bb8844656d0cp-2,
    -0x1.62b958p-2
  },
  { // Entry 389
    0x1.894ae05fefe6ee1164c3e769b2b1a84ep-2,
    0x1.9dd83cp-2
  },
  { // Entry 390
    -0x1.894ae05fefe6ee1164c3e769b2b1a84ep-2,
    -0x1.9dd83cp-2
  },
  { // Entry 391
    0x1.bb12f2d65df13ff36b74e12066022236p-2,
    0x1.d8f720p-2
  },
  { // Entry 392
    -0x1.bb12f2d65df13ff36b74e12066022236p-2,
    -0x1.d8f720p-2
  },
  { // Entry 393
    0x1.eab7b26f955752e78c062cb6087064d9p-2,
    0x1.0a0b02p-1
  },
  { // Entry 394
    -0x1.eab7b26f955752e78c062cb6087064d9p-2,
    -0x1.0a0b02p-1
  },
  { // Entry 395
    0x1.1c03f7900131c7cb3fbfbb5e6c5115eap-1,
    0x1.3d3e36p-1
  },
  { // Entry 396
    -0x1.1c03f7900131c7cb3fbfbb5e6c5115eap-1,
    -0x1.3d3e36p-1
  },
  { // Entry 397
    0x1.2b5b634ea20bdc86ee2a005916e6440ap-1,
    0x1.52e1f8p-1
  },
  { // Entry 398
    -0x1.2b5b634ea20bdc86ee2a005916e6440ap-1,
    -0x1.52e1f8p-1
  },
  { // Entry 399
    0x1.3a1d033b0b8af99ba311a5b2b61923fdp-1,
    0x1.6885bap-1
  },
  { // Entry 400
    -0x1.3a1d033b0b8af99ba311a5b2b61923fdp-1,
    -0x1.6885bap-1
  },
  { // Entry 401
    0x1.484b53fe3670095a8de580bd37b09834p-1,
    0x1.7e297cp-1
  },
  { // Entry 402
    -0x1.484b53fe3670095a8de580bd37b09834p-1,
    -0x1.7e297cp-1
  },
  { // Entry 403
    0x1.55e989109067d04fb47f38831112284ep-1,
    0x1.93cd3ep-1
  },
  { // Entry 404
    -0x1.55e989109067d04fb47f38831112284ep-1,
    -0x1.93cd3ep-1
  },
  { // Entry 405
    0x1.62fb670fb893cf191d38ab2f1067b2dep-1,
    0x1.a971p-1
  },
  { // Entry 406
    -0x1.62fb670fb893cf191d38ab2f1067b2dep-1,
    -0x1.a971p-1
  },
  { // Entry 407
    0x1.6f8521f44dc815420fa612edb64cbde6p-1,
    0x1.bf14c2p-1
  },
  { // Entry 408
    -0x1.6f8521f44dc815420fa612edb64cbde6p-1,
    -0x1.bf14c2p-1
  },
  { // Entry 409
    0x1.7b8b3f52ed1004e7b2fde26964f1ce72p-1,
    0x1.d4b884p-1
  },
  { // Entry 410
    -0x1.7b8b3f52ed1004e7b2fde26964f1ce72p-1,
    -0x1.d4b884p-1
  },
  { // Entry 411
    0x1.8712787339dc1bb28aacdbb75d0eda49p-1,
    0x1.ea5c3ep-1
  },
  { // Entry 412
    -0x1.8712787339dc1bb28aacdbb75d0eda49p-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 413
    0x1.a431f41e221ee2993e28481f34f7c822p-1,
    0x1.12bd92p0
  },
  { // Entry 414
    -0x1.a431f41e221ee2993e28481f34f7c822p-1,
    -0x1.12bd92p0
  },
  { // Entry 415
    0x1.b4fe853106c1ee9ed92061a86abea8fbp-1,
    0x1.257b24p0
  },
  { // Entry 416
    -0x1.b4fe853106c1ee9ed92061a86abea8fbp-1,
    -0x1.257b24p0
  },
  { // Entry 417
    0x1.c49e49d8ce799df605c0c3754f12c804p-1,
    0x1.3838b6p0
  },
  { // Entry 418
    -0x1.c49e49d8ce799df605c0c3754f12c804p-1,
    -0x1.3838b6p0
  },
  { // Entry 419
    0x1.d32908a5e902e2f9d1bdd644edec4fecp-1,
    0x1.4af648p0
  },
  { // Entry 420
    -0x1.d32908a5e902e2f9d1bdd644edec4fecp-1,
    -0x1.4af648p0
  },
  { // Entry 421
    0x1.e0b5269ed18eb6e8f1b485483f950e69p-1,
    0x1.5db3dap0
  },
  { // Entry 422
    -0x1.e0b5269ed18eb6e8f1b485483f950e69p-1,
    -0x1.5db3dap0
  },
  { // Entry 423
    0x1.ed57828f84cacdec44b29eaeb9138ae7p-1,
    0x1.70716cp0
  },
  { // Entry 424
    -0x1.ed57828f84cacdec44b29eaeb9138ae7p-1,
    -0x1.70716cp0
  },
  { // Entry 425
    0x1.f9236870954c3910ae46db78e8dab4a1p-1,
    0x1.832efep0
  },
  { // Entry 426
    -0x1.f9236870954c3910ae46db78e8dab4a1p-1,
    -0x1.832efep0
  },
  { // Entry 427
    0x1.02154a9c2f5c8c14720789b394a8d71ep0,
    0x1.95ec90p0
  },
  { // Entry 428
    -0x1.02154a9c2f5c8c14720789b394a8d71ep0,
    -0x1.95ec90p0
  },
  { // Entry 429
    0x1.073ea11368f7a47972c7a90fc77e3c33p0,
    0x1.a8aa1cp0
  },
  { // Entry 430
    -0x1.073ea11368f7a47972c7a90fc77e3c33p0,
    -0x1.a8aa1cp0
  },
  { // Entry 431
    0x1.96c4c21383607ec90510b32aa175fe13p-1,
    0x1.04aff8p0
  },
  { // Entry 432
    -0x1.96c4c21383607ec90510b32aa175fe13p-1,
    -0x1.04aff8p0
  },
  { // Entry 433
    0x1.96c5670707d079f967bde56724a1508cp-1,
    0x1.04b0a0p0
  },
  { // Entry 434
    -0x1.96c5670707d079f967bde56724a1508cp-1,
    -0x1.04b0a0p0
  },
  { // Entry 435
    0x1.96c60bfa20055aa638999dba9d5b9ba4p-1,
    0x1.04b148p0
  },
  { // Entry 436
    -0x1.96c60bfa20055aa638999dba9d5b9ba4p-1,
    -0x1.04b148p0
  },
  { // Entry 437
    0x1.96c6b0eccbff69175eae7d730f2d63c8p-1,
    0x1.04b1f0p0
  },
  { // Entry 438
    -0x1.96c6b0eccbff69175eae7d730f2d63c8p-1,
    -0x1.04b1f0p0
  },
  { // Entry 439
    0x1.96c755df0bbeed94bc0a76fe6f6efe03p-1,
    0x1.04b298p0
  },
  { // Entry 440
    -0x1.96c755df0bbeed94bc0a76fe6f6efe03p-1,
    -0x1.04b298p0
  },
  { // Entry 441
    0x1.96c7fad0df4430662dbe23a125fdf4dcp-1,
    0x1.04b340p0
  },
  { // Entry 442
    -0x1.96c7fad0df4430662dbe23a125fdf4dcp-1,
    -0x1.04b340p0
  },
  { // Entry 443
    0x1.96c89fc2468f79d38bdc192ed1b15eadp-1,
    0x1.04b3e8p0
  },
  { // Entry 444
    -0x1.96c89fc2468f79d38bdc192ed1b15eadp-1,
    -0x1.04b3e8p0
  },
  { // Entry 445
    0x1.96c944b341a11224a9783fc55088730ap-1,
    0x1.04b490p0
  },
  { // Entry 446
    -0x1.96c944b341a11224a9783fc55088730ap-1,
    -0x1.04b490p0
  },
  { // Entry 447
    0x1.96c9e5b678ff391c2d3fa2849c0a25d4p-1,
    0x1.04b534p0
  },
  { // Entry 448
    -0x1.96c9e5b678ff391c2d3fa2849c0a25d4p-1,
    -0x1.04b534p0
  },
  { // Entry 449
    -0.0f,
    -0x1.p-149
  },
  { // Entry 450
    0.0f,
    0x1.p-149
  },
  { // Entry 451
    0.0,
    0.0
  },
  { // Entry 452
    0.0f,
    0x1.p-149
  },
  { // Entry 453
    -0.0f,
    -0x1.p-149
  },
  { // Entry 454
    0x1.0c1521c014d01f8a9ddecc36f1430940p-1,
    0x1.279a72p-1
  },
  { // Entry 455
    -0x1.0c1521c014d01f8a9ddecc36f1430940p-1,
    -0x1.279a72p-1
  },
  { // Entry 456
    0x1.0c15234014d0ffa236d9926a680fd817p-1,
    0x1.279a74p-1
  },
  { // Entry 457
    -0x1.0c15234014d0ffa236d9926a680fd817p-1,
    -0x1.279a74p-1
  },
  { // Entry 458
    0x1.0c1524c014d0932c0cf0350674c305cap-1,
    0x1.279a76p-1
  },
  { // Entry 459
    -0x1.0c1524c014d0932c0cf0350674c305cap-1,
    -0x1.279a76p-1
  },
  { // Entry 460
    0x1.0c1522e17602fe431351c1c08ae51ff7p0,
    0x1.bb67acp0
  },
  { // Entry 461
    -0x1.0c1522e17602fe431351c1c08ae51ff7p0,
    -0x1.bb67acp0
  },
  { // Entry 462
    0x1.0c1523617603a6edb72557e634b4b8e0p0,
    0x1.bb67aep0
  },
  { // Entry 463
    -0x1.0c1523617603a6edb72557e634b4b8e0p0,
    -0x1.bb67aep0
  },
  { // Entry 464
    0x1.0c1523e1760371e48330a6db47968a93p0,
    0x1.bb67b0p0
  },
  { // Entry 465
    -0x1.0c1523e1760371e48330a6db47968a93p0,
    -0x1.bb67b0p0
  },
  { // Entry 466
    0x1.a64eea8f03b7833c1b78f9cef282cf0fp-2,
    0x1.bffffep-2
  },
  { // Entry 467
    -0x1.a64eea8f03b7833c1b78f9cef282cf0fp-2,
    -0x1.bffffep-2
  },
  { // Entry 468
    0x1.a64eec3cc23fcb6c84f92bd2003ce26cp-2,
    0x1.c0p-2
  },
  { // Entry 469
    -0x1.a64eec3cc23fcb6c84f92bd2003ce26cp-2,
    -0x1.c0p-2
  },
  { // Entry 470
    0x1.a64eedea80c775ce2723b37d5f27788dp-2,
    0x1.c00002p-2
  },
  { // Entry 471
    -0x1.a64eedea80c775ce2723b37d5f27788dp-2,
    -0x1.c00002p-2
  },
  { // Entry 472
    0x1.345f007137aead7202d87adc5e70e53ep-1,
    0x1.5ffffep-1
  },
  { // Entry 473
    -0x1.345f007137aead7202d87adc5e70e53ep-1,
    -0x1.5ffffep-1
  },
  { // Entry 474
    0x1.345f01cce37bb440844df1c4409fe779p-1,
    0x1.60p-1
  },
  { // Entry 475
    -0x1.345f01cce37bb440844df1c4409fe779p-1,
    -0x1.60p-1
  },
  { // Entry 476
    0x1.345f03288f477671552f403f77363c6ep-1,
    0x1.600002p-1
  },
  { // Entry 477
    -0x1.345f03288f477671552f403f77363c6ep-1,
    -0x1.600002p-1
  },
  { // Entry 478
    0x1.bde70d2b5b9861800016d24f37e1f182p-1,
    0x1.2ffffep0
  },
  { // Entry 479
    -0x1.bde70d2b5b9861800016d24f37e1f182p-1,
    -0x1.2ffffep0
  },
  { // Entry 480
    0x1.bde70ed439fe6cba95391a7f421b3821p-1,
    0x1.30p0
  },
  { // Entry 481
    -0x1.bde70ed439fe6cba95391a7f421b3821p-1,
    -0x1.30p0
  },
  { // Entry 482
    0x1.bde7107d1861329d77f85e21c5cf991dp-1,
    0x1.300002p0
  },
  { // Entry 483
    -0x1.bde7107d1861329d77f85e21c5cf991dp-1,
    -0x1.300002p0
  },
  { // Entry 484
    0x1.2e7571f4ae6251e5ddb771325105495ep0,
    0x1.37fffep1
  },
  { // Entry 485
    -0x1.2e7571f4ae6251e5ddb771325105495ep0,
    -0x1.37fffep1
  },
  { // Entry 486
    0x1.2e75728833a54116e3ef7326bd9839p0,
    0x1.38p1
  },
  { // Entry 487
    -0x1.2e75728833a54116e3ef7326bd9839p0,
    -0x1.38p1
  },
  { // Entry 488
    0x1.2e75731bb8e691dca788c02332d288f0p0,
    0x1.380002p1
  },
  { // Entry 489
    -0x1.2e75731bb8e691dca788c02332d288f0p0,
    -0x1.380002p1
  },
  { // Entry 490
    0x1.0640a805eb5ac8d45f6e626469cfd37cp-4,
    0x1.069c8cp-4
  },
  { // Entry 491
    -0x1.0640a805eb5ac8d45f6e626469cfd37cp-4,
    -0x1.069c8cp-4
  },
  { // Entry 492
    0x1.052fabecdb3192006601da57b9f185bbp-3,
    0x1.069c8cp-3
  },
  { // Entry 493
    -0x1.052fabecdb3192006601da57b9f185bbp-3,
    -0x1.069c8cp-3
  },
  { // Entry 494
    0x1.852a2293776e3c2cf4b7a237dfbcac9cp-3,
    0x1.89ead2p-3
  },
  { // Entry 495
    -0x1.852a2293776e3c2cf4b7a237dfbcac9cp-3,
    -0x1.89ead2p-3
  },
  { // Entry 496
    0x1.01123c6ee78df9fddeaeaac0f651fffdp-2,
    0x1.069c8cp-2
  },
  { // Entry 497
    -0x1.01123c6ee78df9fddeaeaac0f651fffdp-2,
    -0x1.069c8cp-2
  },
  { // Entry 498
    0x1.3daa74f913ef98bebdaf6ff5fe9ed93ep-2,
    0x1.4843b0p-2
  },
  { // Entry 499
    -0x1.3daa74f913ef98bebdaf6ff5fe9ed93ep-2,
    -0x1.4843b0p-2
  },
  { // Entry 500
    0x1.780c486991daa5d72fdda5ce57d44289p-2,
    0x1.89ead4p-2
  },
  { // Entry 501
    -0x1.780c486991daa5d72fdda5ce57d44289p-2,
    -0x1.89ead4p-2
  },
  { // Entry 502
    0x1.affab023fe5819ab1f4cad60051a8345p-2,
    0x1.cb91f8p-2
  },
  { // Entry 503
    -0x1.affab023fe5819ab1f4cad60051a8345p-2,
    -0x1.cb91f8p-2
  },
  { // Entry 504
    0x1.e54c83edcc5caaa7a074644b3d2183a2p-2,
    0x1.069c8ep-1
  },
  { // Entry 505
    -0x1.e54c83edcc5caaa7a074644b3d2183a2p-2,
    -0x1.069c8ep-1
  },
  { // Entry 506
    0x1.0bf5631d21b59bea6037065bd184c7fdp-1,
    0x1.277020p-1
  },
  { // Entry 507
    -0x1.0bf5631d21b59bea6037065bd184c7fdp-1,
    -0x1.277020p-1
  },
  { // Entry 508
    0x1.23e71a9565cd2e40ee391514bdb4e6d5p-1,
    0x1.4843b2p-1
  },
  { // Entry 509
    -0x1.23e71a9565cd2e40ee391514bdb4e6d5p-1,
    -0x1.4843b2p-1
  },
  { // Entry 510
    0x1.3a7e42481b7080ceeca06ac375e2af5bp-1,
    0x1.691744p-1
  },
  { // Entry 511
    -0x1.3a7e42481b7080ceeca06ac375e2af5bp-1,
    -0x1.691744p-1
  },
  { // Entry 512
    0x1.4fc2c891491b52874ce2931f24e4b619p-1,
    0x1.89ead6p-1
  },
  { // Entry 513
    -0x1.4fc2c891491b52874ce2931f24e4b619p-1,
    -0x1.89ead6p-1
  },
  { // Entry 514
    0x1.63c0625215a8fafdacb65eebcc76d090p-1,
    0x1.aabe68p-1
  },
  { // Entry 515
    -0x1.63c0625215a8fafdacb65eebcc76d090p-1,
    -0x1.aabe68p-1
  },
  { // Entry 516
    0x1.768565c528c1c7512181ef021a9befe5p-1,
    0x1.cb91fap-1
  },
  { // Entry 517
    -0x1.768565c528c1c7512181ef021a9befe5p-1,
    -0x1.cb91fap-1
  },
  { // Entry 518
    0x1.8821d517853a9293101e345ad74f6492p-1,
    0x1.ec658cp-1
  },
  { // Entry 519
    -0x1.8821d517853a9293101e345ad74f6492p-1,
    -0x1.ec658cp-1
  },
  { // Entry 520
    0x1.98a6983a1f69e2ba7830d45b9caa2847p-1,
    0x1.069c8ep0
  },
  { // Entry 521
    -0x1.98a6983a1f69e2ba7830d45b9caa2847p-1,
    -0x1.069c8ep0
  },
  { // Entry 522
    0x1.a824e7446479e89c28c3c93afc5c60a3p-1,
    0x1.170656p0
  },
  { // Entry 523
    -0x1.a824e7446479e89c28c3c93afc5c60a3p-1,
    -0x1.170656p0
  },
  { // Entry 524
    0x1.b6add56905c11877985184b1ee5d353ap-1,
    0x1.27701ep0
  },
  { // Entry 525
    -0x1.b6add56905c11877985184b1ee5d353ap-1,
    -0x1.27701ep0
  },
  { // Entry 526
    0x1.c4520084d880847dda367ba8b7a8b21dp-1,
    0x1.37d9e6p0
  },
  { // Entry 527
    -0x1.c4520084d880847dda367ba8b7a8b21dp-1,
    -0x1.37d9e6p0
  },
  { // Entry 528
    0x1.d121598ed50fface6324aa1c21a74d23p-1,
    0x1.4843aep0
  },
  { // Entry 529
    -0x1.d121598ed50fface6324aa1c21a74d23p-1,
    -0x1.4843aep0
  },
  { // Entry 530
    0x1.dd2b014fde35d165c474a1122825802dp-1,
    0x1.58ad76p0
  },
  { // Entry 531
    -0x1.dd2b014fde35d165c474a1122825802dp-1,
    -0x1.58ad76p0
  },
  { // Entry 532
    0x1.e87d3481ac8dd5621a3b3c4f921c44fap-1,
    0x1.69173ep0
  },
  { // Entry 533
    -0x1.e87d3481ac8dd5621a3b3c4f921c44fap-1,
    -0x1.69173ep0
  },
  { // Entry 534
    0x1.f32543520ef9c5f5810f6db85d7aaf28p-1,
    0x1.798106p0
  },
  { // Entry 535
    -0x1.f32543520ef9c5f5810f6db85d7aaf28p-1,
    -0x1.798106p0
  },
  { // Entry 536
    0x1.fd2f9116e59cee8a040e62d4b5243e1ap-1,
    0x1.89eacep0
  },
  { // Entry 537
    -0x1.fd2f9116e59cee8a040e62d4b5243e1ap-1,
    -0x1.89eacep0
  },
  { // Entry 538
    0x1.0353ccda2d644d7938c482410bb91bb1p0,
    0x1.9a5496p0
  },
  { // Entry 539
    -0x1.0353ccda2d644d7938c482410bb91bb1p0,
    -0x1.9a5496p0
  },
  { // Entry 540
    0x1.07cbfd6728be1d728e6efaa566962a31p0,
    0x1.aabe5ep0
  },
  { // Entry 541
    -0x1.07cbfd6728be1d728e6efaa566962a31p0,
    -0x1.aabe5ep0
  },
  { // Entry 542
    0x1.0c053fac5615bd33ea669091fc7a90bcp0,
    0x1.bb2826p0
  },
  { // Entry 543
    -0x1.0c053fac5615bd33ea669091fc7a90bcp0,
    -0x1.bb2826p0
  },
  { // Entry 544
    0x1.1004163d82000593e7df6bce3d8cab10p0,
    0x1.cb91eep0
  },
  { // Entry 545
    -0x1.1004163d82000593e7df6bce3d8cab10p0,
    -0x1.cb91eep0
  },
  { // Entry 546
    0x1.13cca783c7bd2088b900b4113ba87852p0,
    0x1.dbfbb6p0
  },
  { // Entry 547
    -0x1.13cca783c7bd2088b900b4113ba87852p0,
    -0x1.dbfbb6p0
  },
  { // Entry 548
    0x1.1762c47f210f545ac9a8a7e0241e7259p0,
    0x1.ec657ep0
  },
  { // Entry 549
    -0x1.1762c47f210f545ac9a8a7e0241e7259p0,
    -0x1.ec657ep0
  },
  { // Entry 550
    0x1.1ac9ef601c2f97f7b0f0a6d93dd834eep0,
    0x1.fccf46p0
  },
  { // Entry 551
    -0x1.1ac9ef601c2f97f7b0f0a6d93dd834eep0,
    -0x1.fccf46p0
  },
  { // Entry 552
    0x1.1e05623dfb4cc3c6baa62e4bc279a9a4p0,
    0x1.069c88p1
  },
  { // Entry 553
    -0x1.1e05623dfb4cc3c6baa62e4bc279a9a4p0,
    -0x1.069c88p1
  },
  { // Entry 554
    0x1.21181384588be60732d01848bc71700bp0,
    0x1.0ed16cp1
  },
  { // Entry 555
    -0x1.21181384588be60732d01848bc71700bp0,
    -0x1.0ed16cp1
  },
  { // Entry 556
    0x1.2404bde8e2552de3cc50334d78b5dc4ap0,
    0x1.170650p1
  },
  { // Entry 557
    -0x1.2404bde8e2552de3cc50334d78b5dc4ap0,
    -0x1.170650p1
  },
  { // Entry 558
    0x1.26cde4061c757738e2ce7f21522b89dap0,
    0x1.1f3b34p1
  },
  { // Entry 559
    -0x1.26cde4061c757738e2ce7f21522b89dap0,
    -0x1.1f3b34p1
  },
  { // Entry 560
    0x1.2975d58f5e9bdfe1899ef21d99c49b2bp0,
    0x1.277018p1
  },
  { // Entry 561
    -0x1.2975d58f5e9bdfe1899ef21d99c49b2bp0,
    -0x1.277018p1
  },
  { // Entry 562
    0x1.2bfeb3b9bbea83cde56fbf951e871487p0,
    0x1.2fa4fcp1
  },
  { // Entry 563
    -0x1.2bfeb3b9bbea83cde56fbf951e871487p0,
    -0x1.2fa4fcp1
  },
  { // Entry 564
    0x1.2e6a7545ba88692a48d56e5581873211p0,
    0x1.37d9e0p1
  },
  { // Entry 565
    -0x1.2e6a7545ba88692a48d56e5581873211p0,
    -0x1.37d9e0p1
  },
  { // Entry 566
    0x1.30baea2f60c5a59cc6d2e94130f95768p0,
    0x1.400ec4p1
  },
  { // Entry 567
    -0x1.30baea2f60c5a59cc6d2e94130f95768p0,
    -0x1.400ec4p1
  },
  { // Entry 568
    0x1.32f1bf0aa92c8a65a6948643fdcfd255p0,
    0x1.4843a8p1
  },
  { // Entry 569
    -0x1.32f1bf0aa92c8a65a6948643fdcfd255p0,
    -0x1.4843a8p1
  },
  { // Entry 570
    0x1.35108012a113c05aaab2d146f1393f5cp0,
    0x1.50788cp1
  },
  { // Entry 571
    -0x1.35108012a113c05aaab2d146f1393f5cp0,
    -0x1.50788cp1
  },
  { // Entry 572
    0x1.37189bf16a71201adaf5b8708459828ep0,
    0x1.58ad70p1
  },
  { // Entry 573
    -0x1.37189bf16a71201adaf5b8708459828ep0,
    -0x1.58ad70p1
  },
  { // Entry 574
    0x1.390b6647268e4ff7a7fc9ad3d315ca68p0,
    0x1.60e254p1
  },
  { // Entry 575
    -0x1.390b6647268e4ff7a7fc9ad3d315ca68p0,
    -0x1.60e254p1
  },
  { // Entry 576
    0x1.3aea19f582cfb2fc7f01e690b9e61c32p0,
    0x1.691738p1
  },
  { // Entry 577
    -0x1.3aea19f582cfb2fc7f01e690b9e61c32p0,
    -0x1.691738p1
  },
  { // Entry 578
    0x1.3cb5db3545a9577b9d057ce82dc608c6p0,
    0x1.714c1cp1
  },
  { // Entry 579
    -0x1.3cb5db3545a9577b9d057ce82dc608c6p0,
    -0x1.714c1cp1
  },
  { // Entry 580
    0x1.3e6fb97ad7a66ba04c7b01d1646602e1p0,
    0x1.7981p1
  },
  { // Entry 581
    -0x1.3e6fb97ad7a66ba04c7b01d1646602e1p0,
    -0x1.7981p1
  },
  { // Entry 582
    0x1.4018b12e603d690dfd89144ca355ad7cp0,
    0x1.81b5e4p1
  },
  { // Entry 583
    -0x1.4018b12e603d690dfd89144ca355ad7cp0,
    -0x1.81b5e4p1
  },
  { // Entry 584
    0x1.41b1ad3bab8b579c71ceb89cb23a4191p0,
    0x1.89eac8p1
  },
  { // Entry 585
    -0x1.41b1ad3bab8b579c71ceb89cb23a4191p0,
    -0x1.89eac8p1
  },
  { // Entry 586
    -0x1.6807a9ecb61e7179d47b86a3d7d89614p0,
    -0x1.81b5eep2
  },
  { // Entry 587
    0x1.6807a9ecb61e7179d47b86a3d7d89614p0,
    0x1.81b5eep2
  },
  { // Entry 588
    -0x1.6631e1e590c8943bb980827585841401p0,
    -0x1.714c26p2
  },
  { // Entry 589
    0x1.6631e1e590c8943bb980827585841401p0,
    0x1.714c26p2
  },
  { // Entry 590
    -0x1.6431bbdbbb23b05a6294690cc8fe4afbp0,
    -0x1.60e25ep2
  },
  { // Entry 591
    0x1.6431bbdbbb23b05a6294690cc8fe4afbp0,
    0x1.60e25ep2
  },
  { // Entry 592
    -0x1.620149ba05b3abd7c744898b395ff078p0,
    -0x1.507896p2
  },
  { // Entry 593
    0x1.620149ba05b3abd7c744898b395ff078p0,
    0x1.507896p2
  },
  { // Entry 594
    -0x1.5f99784c16ae6ade09784989de90f9cep0,
    -0x1.400ecep2
  },
  { // Entry 595
    0x1.5f99784c16ae6ade09784989de90f9cep0,
    0x1.400ecep2
  },
  { // Entry 596
    -0x1.5cf1c615f954a1c183fa9df874538ee9p0,
    -0x1.2fa506p2
  },
  { // Entry 597
    0x1.5cf1c615f954a1c183fa9df874538ee9p0,
    0x1.2fa506p2
  },
  { // Entry 598
    -0x1.59ffe38b71898ed7998b335085e65964p0,
    -0x1.1f3b3ep2
  },
  { // Entry 599
    0x1.59ffe38b71898ed7998b335085e65964p0,
    0x1.1f3b3ep2
  },
  { // Entry 600
    -0x1.56b7343ee6671bf137c3060d6bbac90bp0,
    -0x1.0ed176p2
  },
  { // Entry 601
    0x1.56b7343ee6671bf137c3060d6bbac90bp0,
    0x1.0ed176p2
  },
  { // Entry 602
    -0x1.530824ba9228f906cf6fbbb114073212p0,
    -0x1.fccf5ap1
  },
  { // Entry 603
    0x1.530824ba9228f906cf6fbbb114073212p0,
    0x1.fccf5ap1
  },
  { // Entry 604
    -0x1.4edf449b38ca3a22476f62c7349bb773p0,
    -0x1.dbfbc8p1
  },
  { // Entry 605
    0x1.4edf449b38ca3a22476f62c7349bb773p0,
    0x1.dbfbc8p1
  },
  { // Entry 606
    -0x1.4a2408f508131a351e75bd65a563180ap0,
    -0x1.bb2836p1
  },
  { // Entry 607
    0x1.4a2408f508131a351e75bd65a563180ap0,
    0x1.bb2836p1
  },
  { // Entry 608
    -0x1.44b712953f85f723e8b9348c9f600a8cp0,
    -0x1.9a54a4p1
  },
  { // Entry 609
    0x1.44b712953f85f723e8b9348c9f600a8cp0,
    0x1.9a54a4p1
  },
  { // Entry 610
    -0x1.3e6fbd3122418ea0ac307a2ed17c0d28p0,
    -0x1.798112p1
  },
  { // Entry 611
    0x1.3e6fbd3122418ea0ac307a2ed17c0d28p0,
    0x1.798112p1
  },
  { // Entry 612
    -0x1.37189fd23f9a7ac18ff4e4c5821e80bfp0,
    -0x1.58ad80p1
  },
  { // Entry 613
    0x1.37189fd23f9a7ac18ff4e4c5821e80bfp0,
    0x1.58ad80p1
  },
  { // Entry 614
    -0x1.2e6a794f37529d7b8c78438094df8560p0,
    -0x1.37d9eep1
  },
  { // Entry 615
    0x1.2e6a794f37529d7b8c78438094df8560p0,
    0x1.37d9eep1
  },
  { // Entry 616
    -0x1.2404c2150e76f6d23e4a514c77839926p0,
    -0x1.17065cp1
  },
  { // Entry 617
    0x1.2404c2150e76f6d23e4a514c77839926p0,
    0x1.17065cp1
  },
  { // Entry 618
    -0x1.1762c92d89f7b516e38b1fadbc7c1725p0,
    -0x1.ec6594p0
  },
  { // Entry 619
    0x1.1762c92d89f7b516e38b1fadbc7c1725p0,
    0x1.ec6594p0
  },
  { // Entry 620
    -0x1.07cc022a998cd36350736775629f7411p0,
    -0x1.aabe70p0
  },
  { // Entry 621
    0x1.07cc022a998cd36350736775629f7411p0,
    0x1.aabe70p0
  },
  { // Entry 622
    -0x1.e87d3ddf5d974d08f4dd58fe2cb62a75p-1,
    -0x1.69174cp0
  },
  { // Entry 623
    0x1.e87d3ddf5d974d08f4dd58fe2cb62a75p-1,
    0x1.69174cp0
  },
  { // Entry 624
    -0x1.b6adddfcb60791bdfa29e43ae237526cp-1,
    -0x1.277028p0
  },
  { // Entry 625
    0x1.b6adddfcb60791bdfa29e43ae237526cp-1,
    0x1.277028p0
  },
  { // Entry 626
    -0x1.76856ea18da195176e0ece2cba9470a9p-1,
    -0x1.cb920ap-1
  },
  { // Entry 627
    0x1.76856ea18da195176e0ece2cba9470a9p-1,
    0x1.cb920ap-1
  },
  { // Entry 628
    -0x1.23e72757057c5809379a3139ba87791dp-1,
    -0x1.4843c4p-1
  },
  { // Entry 629
    0x1.23e72757057c5809379a3139ba87791dp-1,
    0x1.4843c4p-1
  },
  { // Entry 630
    -0x1.780c6b4190a4c02ec686d865d59869c8p-2,
    -0x1.89eafcp-2
  },
  { // Entry 631
    0x1.780c6b4190a4c02ec686d865d59869c8p-2,
    0x1.89eafcp-2
  },
  { // Entry 632
    -0x1.052ffe90feb23c1016d89c3f01bc9e1fp-3,
    -0x1.069ce0p-3
  },
  { // Entry 633
    0x1.052ffe90feb23c1016d89c3f01bc9e1fp-3,
    0x1.069ce0p-3
  },
  { // Entry 634
    0x1.052f5948b6d5f860bd33815fb4292679p-3,
    0x1.069c38p-3
  },
  { // Entry 635
    -0x1.052f5948b6d5f860bd33815fb4292679p-3,
    -0x1.069c38p-3
  },
  { // Entry 636
    0x1.780c22159221d1976cc58c067c712c12p-2,
    0x1.89eaa8p-2
  },
  { // Entry 637
    -0x1.780c22159221d1976cc58c067c712c12p-2,
    -0x1.89eaa8p-2
  },
  { // Entry 638
    0x1.23e709933aec019daf9a653afa37bd56p-1,
    0x1.48439ap-1
  },
  { // Entry 639
    -0x1.23e709933aec019daf9a653afa37bd56p-1,
    -0x1.48439ap-1
  },
  { // Entry 640
    0x1.7685575f043fc937570fbcd679218a9ep-1,
    0x1.cb91e0p-1
  },
  { // Entry 641
    -0x1.7685575f043fc937570fbcd679218a9ep-1,
    -0x1.cb91e0p-1
  },
  { // Entry 642
    0x1.b6adccd55525b9c5503e0cdc8d37e90ep-1,
    0x1.277014p0
  },
  { // Entry 643
    -0x1.b6adccd55525b9c5503e0cdc8d37e90ep-1,
    -0x1.277014p0
  },
  { // Entry 644
    0x1.e87d307e1763e6189f33adfb0e8068c9p-1,
    0x1.691738p0
  },
  { // Entry 645
    -0x1.e87d307e1763e6189f33adfb0e8068c9p-1,
    -0x1.691738p0
  },
  { // Entry 646
    0x1.07cbfcdfaa6996b12b44434dca3635e9p0,
    0x1.aabe5cp0
  },
  { // Entry 647
    -0x1.07cbfcdfaa6996b12b44434dca3635e9p0,
    -0x1.aabe5cp0
  },
  { // Entry 648
    0x1.1762c4ec13567bd7f5f799b650139ef2p0,
    0x1.ec6580p0
  },
  { // Entry 649
    -0x1.1762c4ec13567bd7f5f799b650139ef2p0,
    -0x1.ec6580p0
  },
  { // Entry 650
    0x1.2404be9ae9b56a1e7b93aab429a437dcp0,
    0x1.170652p1
  },
  { // Entry 651
    -0x1.2404be9ae9b56a1e7b93aab429a437dcp0,
    -0x1.170652p1
  },
  { // Entry 652
    0x1.2e6a766d02ca49766b8c5e064edd330ap0,
    0x1.37d9e4p1
  },
  { // Entry 653
    -0x1.2e6a766d02ca49766b8c5e064edd330ap0,
    -0x1.37d9e4p1
  },
  { // Entry 654
    0x1.37189d65ba6a203671b78263ea59150ep0,
    0x1.58ad76p1
  },
  { // Entry 655
    -0x1.37189d65ba6a203671b78263ea59150ep0,
    -0x1.58ad76p1
  },
  { // Entry 656
    0x1.3e6fbb2131bc83fb7bb1680528d88125p0,
    0x1.798108p1
  },
  { // Entry 657
    -0x1.3e6fbb2131bc83fb7bb1680528d88125p0,
    -0x1.798108p1
  },
  { // Entry 658
    0x1.44b710cf357eefd513350249454692fep0,
    0x1.9a549ap1
  },
  { // Entry 659
    -0x1.44b710cf357eefd513350249454692fep0,
    -0x1.9a549ap1
  },
  { // Entry 660
    0x1.4a24076ac744c5d206c4362f0a81c539p0,
    0x1.bb282cp1
  },
  { // Entry 661
    -0x1.4a24076ac744c5d206c4362f0a81c539p0,
    -0x1.bb282cp1
  },
  { // Entry 662
    0x1.4edf4341eeb190f38d0f628df7c0f39cp0,
    0x1.dbfbbep1
  },
  { // Entry 663
    -0x1.4edf4341eeb190f38d0f628df7c0f39cp0,
    -0x1.dbfbbep1
  },
  { // Entry 664
    0x1.53082389d4de0bf0033c96e02e4ce915p0,
    0x1.fccf50p1
  },
  { // Entry 665
    -0x1.53082389d4de0bf0033c96e02e4ce915p0,
    -0x1.fccf50p1
  },
  { // Entry 666
    0x1.56b732f9ebf592c0c94096bc1ed28a6bp0,
    0x1.0ed170p2
  },
  { // Entry 667
    -0x1.56b732f9ebf592c0c94096bc1ed28a6bp0,
    -0x1.0ed170p2
  },
  { // Entry 668
    0x1.59ffe268d6801ace03f3d195dcfe7b03p0,
    0x1.1f3b38p2
  },
  { // Entry 669
    -0x1.59ffe268d6801ace03f3d195dcfe7b03p0,
    -0x1.1f3b38p2
  },
  { // Entry 670
    0x1.5cf1c510a2c51231c77aeb5bcfdb18f6p0,
    0x1.2fa5p2
  },
  { // Entry 671
    -0x1.5cf1c510a2c51231c77aeb5bcfdb18f6p0,
    -0x1.2fa5p2
  },
  { // Entry 672
    0x1.5f99775fdcea19d02889374d890664b5p0,
    0x1.400ec8p2
  },
  { // Entry 673
    -0x1.5f99775fdcea19d02889374d890664b5p0,
    -0x1.400ec8p2
  },
  { // Entry 674
    0x1.620148e37eeeed056aad41e79a62c2c1p0,
    0x1.507890p2
  },
  { // Entry 675
    -0x1.620148e37eeeed056aad41e79a62c2c1p0,
    -0x1.507890p2
  },
  { // Entry 676
    0x1.6431bb181361216275b0d203a9331c13p0,
    0x1.60e258p2
  },
  { // Entry 677
    -0x1.6431bb181361216275b0d203a9331c13p0,
    -0x1.60e258p2
  },
  { // Entry 678
    0x1.6631e1326b64f0282c465af90d9d3bd9p0,
    0x1.714c20p2
  },
  { // Entry 679
    -0x1.6631e1326b64f0282c465af90d9d3bd9p0,
    -0x1.714c20p2
  },
  { // Entry 680
    0x1.6807a948166caac881ad676127631903p0,
    0x1.81b5e8p2
  },
  { // Entry 681
    -0x1.6807a948166caac881ad676127631903p0,
    -0x1.81b5e8p2
  },
  { // Entry 682
    0x1.ef652bd0a90c724b11a56d2fd671af31p-5,
    0x1.effffep-5
  },
  { // Entry 683
    -0x1.ef652bd0a90c724b11a56d2fd671af31p-5,
    -0x1.effffep-5
  },
  { // Entry 684
    0x1.ef652dceca4dbeb14ee907159dd1c369p-5,
    0x1.f0p-5
  },
  { // Entry 685
    -0x1.ef652dceca4dbeb14ee907159dd1c369p-5,
    -0x1.f0p-5
  },
  { // Entry 686
    0x1.ef652fcceb8f073ec7ec4e0d20bb7bfbp-5,
    0x1.f00002p-5
  },
  { // Entry 687
    -0x1.ef652fcceb8f073ec7ec4e0d20bb7bfbp-5,
    -0x1.f00002p-5
  },
  { // Entry 688
    0x1.f57aae2e668fcd953f95c1400b66f69ap-4,
    0x1.f7fffep-4
  },
  { // Entry 689
    -0x1.f57aae2e668fcd953f95c1400b66f69ap-4,
    -0x1.f7fffep-4
  },
  { // Entry 690
    0x1.f57ab026c3a8fc7b278a06e9d0c43e3ap-4,
    0x1.f8p-4
  },
  { // Entry 691
    -0x1.f57ab026c3a8fc7b278a06e9d0c43e3ap-4,
    -0x1.f8p-4
  },
  { // Entry 692
    0x1.f57ab21f20c21c186f960384371cb174p-4,
    0x1.f80002p-4
  },
  { // Entry 693
    -0x1.f57ab21f20c21c186f960384371cb174p-4,
    -0x1.f80002p-4
  },
  { // Entry 694
    0x1.49230059e7c45adb8ec67bfb8e8a656bp-3,
    0x1.4bfffep-3
  },
  { // Entry 695
    -0x1.49230059e7c45adb8ec67bfb8e8a656bp-3,
    -0x1.4bfffep-3
  },
  { // Entry 696
    0x1.4923024ccb780f5a7e2ead4e2bd24d33p-3,
    0x1.4cp-3
  },
  { // Entry 697
    -0x1.4923024ccb780f5a7e2ead4e2bd24d33p-3,
    -0x1.4cp-3
  },
  { // Entry 698
    0x1.4923043faf2b9c728ca66011aefa5d95p-3,
    0x1.4c0002p-3
  },
  { // Entry 699
    -0x1.4923043faf2b9c728ca66011aefa5d95p-3,
    -0x1.4c0002p-3
  },
  { // Entry 700
    0x1.2a73a5481536bc5af06b6df4531f2c45p-2,
    0x1.333332p-2
  },
  { // Entry 701
    -0x1.2a73a5481536bc5af06b6df4531f2c45p-2,
    -0x1.333332p-2
  },
  { // Entry 702
    0x1.2a73a71dcec15ae5ead00add4294e754p-2,
    0x1.333334p-2
  },
  { // Entry 703
    -0x1.2a73a71dcec15ae5ead00add4294e754p-2,
    -0x1.333334p-2
  },
  { // Entry 704
    0x1.2a73a8f3884b7828b0c0111255103dc3p-2,
    0x1.333336p-2
  },
  { // Entry 705
    -0x1.2a73a8f3884b7828b0c0111255103dc3p-2,
    -0x1.333336p-2
  },
  { // Entry 706
    0x1.2fc480fa0e88570eda20090113e29e36p-1,
    0x1.594316p-1
  },
  { // Entry 707
    -0x1.2fc480fa0e88570eda20090113e29e36p-1,
    -0x1.594316p-1
  },
  { // Entry 708
    0x1.2fc4825a02d3f974157fe3c500a7defbp-1,
    0x1.594318p-1
  },
  { // Entry 709
    -0x1.2fc4825a02d3f974157fe3c500a7defbp-1,
    -0x1.594318p-1
  },
  { // Entry 710
    0x1.2fc483b9f71e558d99929cc8e5da29dfp-1,
    0x1.59431ap-1
  },
  { // Entry 711
    -0x1.2fc483b9f71e558d99929cc8e5da29dfp-1,
    -0x1.59431ap-1
  },
  { // Entry 712
    0x1.538f567a9ef925d9ba9a4231046e7f2cp-1,
    0x1.8ffffep-1
  },
  { // Entry 713
    -0x1.538f567a9ef925d9ba9a4231046e7f2cp-1,
    -0x1.8ffffep-1
  },
  { // Entry 714
    0x1.538f57b89061eb9122d5096b7cf267ebp-1,
    0x1.90p-1
  },
  { // Entry 715
    -0x1.538f57b89061eb9122d5096b7cf267ebp-1,
    -0x1.90p-1
  },
  { // Entry 716
    0x1.538f58f681c97cc9bd5a1277e9e2f0fbp-1,
    0x1.900002p-1
  },
  { // Entry 717
    -0x1.538f58f681c97cc9bd5a1277e9e2f0fbp-1,
    -0x1.900002p-1
  },
  { // Entry 718
    -0.0f,
    -0x1.p-149
  },
  { // Entry 719
    0.0f,
    0x1.p-149
  },
  { // Entry 720
    0.0,
    0.0
  },
  { // Entry 721
    0.0f,
    0x1.p-149
  },
  { // Entry 722
    -0.0f,
    -0x1.p-149
  },
  { // Entry 723
    0x1.91cd2399d43fabf90187544276a9fdd6p-5,
    0x1.921fb4p-5
  },
  { // Entry 724
    -0x1.91cd2399d43fabf90187544276a9fdd6p-5,
    -0x1.921fb4p-5
  },
  { // Entry 725
    0x1.91cd2598992e3959b33089adc931af1bp-5,
    0x1.921fb6p-5
  },
  { // Entry 726
    -0x1.91cd2598992e3959b33089adc931af1bp-5,
    -0x1.921fb6p-5
  },
  { // Entry 727
    0x1.91cd27975e1cc39a020e1155956c974ep-5,
    0x1.921fb8p-5
  },
  { // Entry 728
    -0x1.91cd27975e1cc39a020e1155956c974ep-5,
    -0x1.921fb8p-5
  },
  { // Entry 729
    0x1.90d6de7dda04008932bb9dc6d6663dffp-4,
    0x1.921fb4p-4
  },
  { // Entry 730
    -0x1.90d6de7dda04008932bb9dc6d6663dffp-4,
    -0x1.921fb4p-4
  },
  { // Entry 731
    0x1.90d6e078f6c425534a52900d55c07c08p-4,
    0x1.921fb6p-4
  },
  { // Entry 732
    -0x1.90d6e078f6c425534a52900d55c07c08p-4,
    -0x1.921fb6p-4
  },
  { // Entry 733
    0x1.90d6e27413843dc984d6d696c18f157ap-4,
    0x1.921fb8p-4
  },
  { // Entry 734
    -0x1.90d6e27413843dc984d6d696c18f157ap-4,
    -0x1.921fb8p-4
  },
  { // Entry 735
    0x1.8d128d765c163bb2a4684b359bc37b4ap-3,
    0x1.921fb4p-3
  },
  { // Entry 736
    -0x1.8d128d765c163bb2a4684b359bc37b4ap-3,
    -0x1.921fb4p-3
  },
  { // Entry 737
    0x1.8d128f635a6f85e06f888e0887f9908fp-3,
    0x1.921fb6p-3
  },
  { // Entry 738
    -0x1.8d128f635a6f85e06f888e0887f9908fp-3,
    -0x1.921fb6p-3
  },
  { // Entry 739
    0x1.8d12915058c8a173e6b2d7c8cf5f012ap-3,
    0x1.921fb8p-3
  },
  { // Entry 740
    -0x1.8d12915058c8a173e6b2d7c8cf5f012ap-3,
    -0x1.921fb8p-3
  },
  { // Entry 741
    0x1.7f2d690b879f26b1634350104478a209p-2,
    0x1.921fb4p-2
  },
  { // Entry 742
    -0x1.7f2d690b879f26b1634350104478a209p-2,
    -0x1.921fb4p-2
  },
  { // Entry 743
    0x1.7f2d6ac71f4b19b38cf78bbadec1435ap-2,
    0x1.921fb6p-2
  },
  { // Entry 744
    -0x1.7f2d6ac71f4b19b38cf78bbadec1435ap-2,
    -0x1.921fb6p-2
  },
  { // Entry 745
    0x1.7f2d6c82b6f675c92c9dfa635f318ed7p-2,
    0x1.921fb8p-2
  },
  { // Entry 746
    -0x1.7f2d6c82b6f675c92c9dfa635f318ed7p-2,
    -0x1.921fb8p-2
  },
  { // Entry 747
    0x1.54e04b3d43589d0cc0bd332c6a822ecfp-1,
    0x1.921fb4p-1
  },
  { // Entry 748
    -0x1.54e04b3d43589d0cc0bd332c6a822ecfp-1,
    -0x1.921fb4p-1
  },
  { // Entry 749
    0x1.54e04c79ed9a93b01c6a9062dbd8e0ffp-1,
    0x1.921fb6p-1
  },
  { // Entry 750
    -0x1.54e04c79ed9a93b01c6a9062dbd8e0ffp-1,
    -0x1.921fb6p-1
  },
  { // Entry 751
    0x1.54e04db697db56ae489f89986a14a1b7p-1,
    0x1.921fb8p-1
  },
  { // Entry 752
    -0x1.54e04db697db56ae489f89986a14a1b7p-1,
    -0x1.921fb8p-1
  },
  { // Entry 753
    0x1.00fe98214bd47b0727cef70af68aceeep0,
    0x1.921fb4p0
  },
  { // Entry 754
    -0x1.00fe98214bd47b0727cef70af68aceeep0,
    -0x1.921fb4p0
  },
  { // Entry 755
    0x1.00fe98b4f50d8b3c36b9e2a180d97eeap0,
    0x1.921fb6p0
  },
  { // Entry 756
    -0x1.00fe98b4f50d8b3c36b9e2a180d97eeap0,
    -0x1.921fb6p0
  },
  { // Entry 757
    0x1.00fe99489e458fdeaf9be968cab6da63p0,
    0x1.921fb8p0
  },
  { // Entry 758
    -0x1.00fe99489e458fdeaf9be968cab6da63p0,
    -0x1.921fb8p0
  },
  { // Entry 759
    0x1.433b89f683ed7fa5817d865f4f40b772p0,
    0x1.921fb4p1
  },
  { // Entry 760
    -0x1.433b89f683ed7fa5817d865f4f40b772p0,
    -0x1.921fb4p1
  },
  { // Entry 761
    0x1.433b8a54b916d7eb27cee6293066e9f6p0,
    0x1.921fb6p1
  },
  { // Entry 762
    -0x1.433b8a54b916d7eb27cee6293066e9f6p0,
    -0x1.921fb6p1
  },
  { // Entry 763
    0x1.433b8ab2ee3f565d04344459852fbcf4p0,
    0x1.921fb8p1
  },
  { // Entry 764
    -0x1.433b8ab2ee3f565d04344459852fbcf4p0,
    -0x1.921fb8p1
  },
  { // Entry 765
    0x1.69b8152ba44a49cab381a82d3efbf702p0,
    0x1.921fb4p2
  },
  { // Entry 766
    -0x1.69b8152ba44a49cab381a82d3efbf702p0,
    -0x1.921fb4p2
  },
  { // Entry 767
    0x1.69b8155e3c934e6ce63a344b2956ab50p0,
    0x1.921fb6p2
  },
  { // Entry 768
    -0x1.69b8155e3c934e6ce63a344b2956ab50p0,
    -0x1.921fb6p2
  },
  { // Entry 769
    0x1.69b81590d4dbd567331c0dc4b7fd047bp0,
    0x1.921fb8p2
  },
  { // Entry 770
    -0x1.69b81590d4dbd567331c0dc4b7fd047bp0,
    -0x1.921fb8p2
```