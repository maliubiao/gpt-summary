Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of Android's Bionic library. This file seems to contain test data for the `sincos` function, specifically for Intel architectures.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose of the file:** The filename `sincos_intel_data.handroid` and the directory `bionic/tests/math_data` strongly suggest that this file holds test data related to the `sincos` math function within Android's Bionic library. The "intel" part indicates it's likely specific to Intel architectures. The `.handroid` extension might be related to a specific testing or data generation process within Android.

2. **Analyze the data structure:** The code consists of a C array named (based on the previous parts of the conversation) `kSinCosIntelData`. Each element in the array is a struct (or anonymous struct) containing three `double` values. The comments like `// Entry 713` suggest these are individual test cases, numbered sequentially.

3. **Infer the meaning of the data:**  Given it's for `sincos`, the three `double` values likely represent:
    * **Input angle:** The first value.
    * **Expected sine:** The second value.
    * **Expected cosine:** The third value.

4. **Connect to Android's functionality:** The `sincos` function is a standard mathematical function, and Android uses it for various purposes, including graphics rendering, game development, sensor data processing, and any application requiring trigonometric calculations.

5. **Explain the libc function (`sincos`):** Describe what the `sincos` function does – it calculates both the sine and cosine of an angle efficiently.

6. **Address dynamic linker aspects (though not directly present in *this* file):** While this specific file doesn't directly involve the dynamic linker, acknowledge its role in loading and linking the math library. Provide a general example of an SO layout and how linking occurs (symbol resolution, relocation).

7. **Consider logical reasoning (already done implicitly by the data generation):** The data itself represents logical reasoning – given an input angle, the expected sine and cosine are pre-calculated. No further logical inference is needed for *this* file's summary.

8. **Think about common user errors:**  When using `sincos` or related functions, common mistakes include providing angles in degrees instead of radians, precision errors, and ignoring potential edge cases (like very large or very small numbers).

9. **Describe the path from Android Framework/NDK:** Outline how a call to a math function in an Android app (either through the Framework or NDK) eventually leads to the Bionic library and potentially uses this test data during development or testing.

10. **Provide a Frida hook example:** Show how to intercept calls to `sincos` using Frida to observe the input and output values. This helps in debugging and understanding the function's behavior.

11. **Summarize the functionality:** Condense the above points into a concise summary of the file's purpose.

12. **Structure the answer:** Organize the information into logical sections based on the user's request. Use clear headings and formatting for readability.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe the data represents different implementations or optimization levels of `sincos`.
* **Correction:**  The "intel" suffix suggests it's more likely test data specific to that architecture's implementation to ensure correctness.
* **Initial thought:**  Focus heavily on the mathematical implementation of `sincos`.
* **Correction:** The request asks about the *data* file, so focus on its purpose within the testing framework rather than the detailed algorithm of `sincos` itself. The other parts of the request about `libc` functions and dynamic linking should be addressed in a more general sense, as this specific file doesn't demonstrate those functionalities directly. The context of "part 4 of 4" suggests building upon previous information, which likely covered more detail about the underlying implementation.

By following this thought process, the provided comprehensive answer can be generated, addressing all aspects of the user's request.
好的，这是第 4 部分，我们来归纳一下这个代码文件的功能。

**功能归纳:**

这个 `sincos_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `sincos` 函数在 Intel 架构上的实现是否正确的测试数据文件。

**具体来说，它的功能是：**

1. **存储测试用例：**  它以 C 数组 `kSinCosIntelData` 的形式存储了大量的测试用例。每个测试用例都是一个包含三个 `double` 类型数值的结构体（或匿名结构体）。
2. **定义输入和预期输出：**  每个结构体中的三个 `double` 值分别代表：
    * **输入角度 (弧度)：** 用于传递给 `sincos` 函数的输入值。
    * **预期正弦值：**  当输入上述角度时，`sincos` 函数应该返回的预期正弦值。
    * **预期余弦值：** 当输入上述角度时，`sincos` 函数应该返回的预期余弦值。
3. **覆盖不同的输入范围和精度：**  这些测试用例覆盖了 `sincos` 函数可能接收的各种输入值，包括正数、负数、非常小和非常大的数，以及不同的精度要求。文件名中的 `intel` 表明这些数据是针对 Intel 架构的特点生成的。
4. **用于自动化测试：**  这些数据被 Bionic 的测试框架使用，用于自动化地验证 `sincos` 函数在 Intel 架构上的实现是否符合预期，是否存在精度问题或其他错误。

**与 Android 功能的关系举例说明：**

在 Android 系统中，`sincos` 函数被广泛应用于各种需要进行三角函数计算的场景，例如：

* **图形渲染 (Framework)：**  Android Framework 中的图形渲染引擎 (例如 Skia) 在进行 2D 和 3D 图形变换、动画效果计算时会使用 `sincos` 函数。例如，旋转一个 View 或者计算一个动画帧中元素的位置。
* **传感器数据处理 (Framework/NDK)：**  Android 系统中的传感器 (例如陀螺仪、加速度计) 会产生需要进行坐标转换和姿态解算的原始数据，这些处理过程会用到 `sincos` 函数。
* **游戏开发 (NDK)：**  使用 NDK 开发的 Android 游戏在进行物理模拟、角色动画、相机控制等操作时，经常需要进行复杂的三角函数计算。
* **科学计算类应用 (NDK)：**  一些科学计算或者工程类应用如果使用 NDK 进行高性能计算，也会直接调用 `sincos` 函数。

**详细解释 libc 函数 (`sincos`) 的功能是如何实现的:**

`sincos` 函数是 C 标准库 `<math.h>` 中的一个函数，它用于同时计算给定角度的正弦值和余弦值。其实现通常会利用以下技术来提高效率和精度：

1. **区间规约：**  由于正弦和余弦函数是周期函数，`sincos` 函数首先会将输入的任意角度规约到一个较小的标准区间 (例如 [-π/4, π/4])。这可以通过减去或加上 2π 的整数倍来实现。
2. **查表法和多项式逼近：**  对于规约后的角度，`sincos` 函数通常会结合查表法和多项式逼近 (例如泰勒级数或切比雪夫多项式) 来计算正弦和余弦值。
    * **查表法：**  预先计算一些关键角度的正弦和余弦值并存储在一个查找表中。对于接近这些关键角度的输入，可以直接或通过插值查找表得到结果。
    * **多项式逼近：**  使用多项式来近似表示正弦和余弦函数在小区间内的值。选择合适的多项式和项数可以在精度和计算效率之间取得平衡。
3. **利用三角恒等式：**  在区间规约和多项式逼近的过程中，可能会利用三角恒等式 (例如 sin(x+y) = sin(x)cos(y) + cos(x)sin(y)) 来简化计算。
4. **硬件加速：**  现代处理器通常提供专门的指令集 (例如 SSE、AVX) 来加速浮点运算，包括三角函数计算。Bionic 的 `sincos` 实现会尽可能利用这些硬件加速特性。
5. **针对不同架构的优化：**  `sincos_intel_data.handroid` 文件本身就暗示了 Bionic 对不同 CPU 架构进行了专门的优化。针对 Intel 架构，`sincos` 的实现可能会利用 Intel 特有的指令或算法。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

虽然这个数据文件本身不直接涉及 dynamic linker，但 `sincos` 函数的实现位于 `libm.so` (数学库) 中，而 dynamic linker (在 Android 中是 `linker` 或 `linker64`) 负责在程序运行时加载和链接这个共享库。

**so 布局样本 (`libm.so`):**

```
libm.so:
    .text          # 包含 sincos 等函数的机器码
    .rodata        # 包含只读数据，例如 sincos 使用的查找表和常数
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .dynsym        # 动态符号表，列出导出的符号 (例如 sincos)
    .dynstr        # 动态字符串表，存储符号名称
    .plt           # 程序链接表，用于延迟绑定
    .got           # 全局偏移表，存储外部符号的地址
    ... 其他段 ...
```

**链接的处理过程：**

1. **加载共享库：** 当应用程序启动或者在运行时需要使用 `libm.so` 中的函数时，dynamic linker 会负责加载 `libm.so` 到内存中。
2. **符号查找：** 当程序调用 `sincos` 函数时，如果该函数是第一次被调用，dynamic linker 需要找到 `sincos` 函数在 `libm.so` 中的实际地址。它会查找 `libm.so` 的 `.dynsym` 段中的符号表，匹配符号名称 "sincos"。
3. **重定位：**  由于共享库被加载到内存中的地址可能每次都不同，dynamic linker 需要修改程序代码中的一些地址引用，使其指向 `libm.so` 中正确的地址。这包括更新 `.got` (全局偏移表) 中的条目，使其指向 `sincos` 函数的实际地址。这个过程称为重定位。
4. **延迟绑定 (Lazy Binding)：**  为了提高启动速度，Android 的 dynamic linker 默认使用延迟绑定。这意味着只有在函数第一次被调用时才进行符号查找和重定位。`.plt` (程序链接表) 中的代码会负责在第一次调用时跳转到 dynamic linker 进行解析，后续调用会直接跳转到已解析的地址。

**假设输入与输出 (针对代码中的数据):**

代码中给出的数据条目展示了假设的输入和输出。例如：

```c
  { // Entry 713
    0xb39bd8373e0d6b94p-49,        // 假设输入角度
    -0x1.ffffffffffffffffffffffffa2c9eda8p-1, // 假设预期正弦值
    -0x1.2d97c7f3321d1p3,          // 假设预期余弦值
  },
```

这意味着，如果将十六进制浮点数 `0xb39bd8373e0d6b94p-49` 作为输入传递给 `sincos` 函数，那么预期返回的正弦值应该是 `-0x1.ffffffffffffffffffffffffa2c9eda8p-1`，余弦值应该是 `-0x1.2d97c7f3321d1p3`。这里的 `p-xx` 表示乘以 2 的负 xx 次方。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **角度单位错误：** `sincos` 函数期望输入的是弧度值，但用户可能错误地提供了角度值。

   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
     double angle_degrees = 90.0;
     // 错误用法：直接将角度值传给 sincos
     double sin_val, cos_val;
     sincos(angle_degrees, &sin_val, &cos_val);
     printf("sin(%f) = %f, cos(%f) = %f\n", angle_degrees, sin_val, angle_degrees, cos_val);

     // 正确用法：将角度转换为弧度
     double angle_radians = angle_degrees * M_PI / 180.0;
     sincos(angle_radians, &sin_val, &cos_val);
     printf("sin(%f radians) = %f, cos(%f radians) = %f\n", angle_radians, sin_val, angle_radians, cos_val);
     return 0;
   }
   ```

2. **精度问题：** 浮点数运算存在精度限制。对于某些特殊的输入值，计算结果可能存在微小的误差。用户在进行精确比较时需要注意这一点。

   ```c
   #include <math.h>
   #include <stdio.h>
   #include <float.h> // 包含 DBL_EPSILON

   int main() {
     double angle = M_PI / 2.0;
     double sin_val, cos_val;
     sincos(angle, &sin_val, &cos_val);

     // 直接比较浮点数是否相等可能出错
     if (sin_val == 1.0) { // 可能不成立
       printf("sin(pi/2) is exactly 1.0\n");
     }

     // 应该使用一个小的误差范围进行比较
     if (fabs(sin_val - 1.0) < DBL_EPSILON) {
       printf("sin(pi/2) is very close to 1.0\n");
     }
     return 0;
   }
   ```

3. **忽略返回值和错误处理：** 某些数学函数可能会返回错误代码或特殊值 (例如 NaN)。用户应该检查返回值并进行适当的错误处理，尽管 `sincos` 函数本身通常不会返回错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Framework 或 NDK 调用：**
   * **Framework:** Android Framework 中的某个组件 (例如 View 的动画、Canvas 绘图) 调用了 Java 层的 Math 类中的 `sin()` 或 `cos()` 方法。
   * **NDK:**  Native 代码直接调用了 `<math.h>` 中的 `sincos()` 函数。

2. **JNI 调用 (Framework -> Native)：** 如果是 Framework 调用，Java 层的 `Math.sin()` 或 `Math.cos()` 方法会通过 JNI (Java Native Interface) 调用到 Bionic 库中对应的 native 函数。

3. **Bionic 库 (`libm.so`)：**  无论是 Framework 还是 NDK 调用，最终都会执行到 Bionic 库 (`libm.so`) 中 `sincos` 函数的实现。

4. **测试数据使用 (开发/测试阶段)：**  在 Bionic 库的开发和测试阶段，测试框架会读取 `bionic/tests/math_data/sincos_intel_data.handroid` 文件中的数据，并将输入角度传递给 `sincos` 函数，然后将函数的返回值与文件中存储的预期值进行比较，以验证函数的正确性。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `sincos` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const libc = Module.findExportByName(null, 'libc.so'); // 或 'libc.so.6'
  if (libc) {
    const sincosPtr = Module.findExportByName(libc.name, 'sincos');
    if (sincosPtr) {
      Interceptor.attach(sincosPtr, {
        onEnter: function (args) {
          const angle = args[0].readDouble();
          console.log(`[sincos Hook] Calling sincos with angle: ${angle}`);
        },
        onLeave: function (retval) {
          const sinVal = this.context.xmm0 ? this.context.xmm0.readDouble() : ptr(this.context.r0).readDouble();
          const cosVal = this.context.xmm1 ? this.context.xmm1.readDouble() : ptr(this.context.r1).readDouble();
          console.log(`[sincos Hook] sincos returned: sin = ${sinVal}, cos = ${cosVal}`);
        }
      });
    } else {
      console.log('[Frida] sincos function not found in libc.');
    }
  } else {
    console.log('[Frida] libc.so not found.');
  }
} else {
  console.log('[Frida] This script is for ARM64 or X64 architectures.');
}
```

**Frida Hook 代码解释：**

1. **检查架构：**  代码首先检查进程架构是否为 ARM64 或 X64，因为寄存器约定可能不同。
2. **查找 `libc.so` 和 `sincos`：**  使用 `Module.findExportByName` 查找 `libc.so` 库以及其中的 `sincos` 函数的地址。
3. **附加 Interceptor：** 使用 `Interceptor.attach` 拦截 `sincos` 函数的调用。
4. **`onEnter`：**  在 `sincos` 函数被调用之前执行。
   * `args[0]` 包含了传递给 `sincos` 的第一个参数，即角度。
   * `readDouble()` 读取该地址中的 `double` 值。
   * 打印调用 `sincos` 时的角度。
5. **`onLeave`：** 在 `sincos` 函数执行完毕后执行。
   *  获取返回值：`sincos` 通常通过寄存器 (例如 xmm0 和 xmm1 在 x64 上，r0 和 r1 在 ARM 上) 返回正弦和余弦值。代码根据架构选择正确的寄存器读取返回值。
   *  打印 `sincos` 函数返回的正弦和余弦值。

**使用 Frida Hook 调试步骤：**

1. **准备环境：**  确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. **编写 Frida 脚本：** 将上面的 JavaScript 代码保存到一个文件中 (例如 `sincos_hook.js`).
3. **运行 Frida：**  使用 Frida 命令行工具将脚本注入到目标 Android 进程中。例如，如果你的目标应用的进程名为 `com.example.myapp`，则可以运行：
   ```bash
   frida -U -f com.example.myapp -l sincos_hook.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U com.example.myapp -l sincos_hook.js
   ```
4. **触发 `sincos` 调用：**  在你的 Android 应用中执行某些操作，这些操作会间接地调用到 `sincos` 函数 (例如，执行一个动画或进行一些图形渲染)。
5. **查看 Frida 输出：**  Frida 会在终端中打印出 `sincos` 函数被调用时的输入角度以及返回的正弦和余弦值。

通过 Frida Hook，你可以动态地观察 `sincos` 函数的调用情况，验证输入输出，以及在开发或调试过程中排查问题。

总而言之，`sincos_intel_data.handroid` 是 Bionic 库中一个关键的测试数据文件，它保证了 Android 系统中 `sincos` 函数在 Intel 架构上的正确性和精度，这对于依赖三角函数计算的各种 Android 功能至关重要。

### 提示词
```
这是目录为bionic/tests/math_data/sincos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
b39bd8373e0d6b94p-49,
    -0x1.ffffffffffffffffffffffffa2c9eda8p-1,
    -0x1.2d97c7f3321d1p3,
  },
  { // Entry 713
    0x1.a79394c9e8a0a5159cdec1ba85a688bdp-52,
    -0x1.fffffffffffffffffffffffffd4326f5p-1,
    0x1.2d97c7f3321d2p3,
  },
  { // Entry 714
    -0x1.a79394c9e8a0a5159cdec1ba85a688bdp-52,
    -0x1.fffffffffffffffffffffffffd4326f5p-1,
    -0x1.2d97c7f3321d2p3,
  },
  { // Entry 715
    -0x1.961b1acd85d7d6ba98c84f9153c0cc16p-50,
    -0x1.ffffffffffffffffffffffffd7bc6041p-1,
    0x1.2d97c7f3321d3p3,
  },
  { // Entry 716
    0x1.961b1acd85d7d6ba98c84f9153c0cc16p-50,
    -0x1.ffffffffffffffffffffffffd7bc6041p-1,
    -0x1.2d97c7f3321d3p3,
  },
  { // Entry 717
    -0x1.6a09e667f3bb90f220f856d0b1a406c3p-1,
    -0x1.6a09e667f3be011f44fdcffc167f7140p-1,
    0x1.46b9c347764a2p3,
  },
  { // Entry 718
    0x1.6a09e667f3bb90f220f856d0b1a406c3p-1,
    -0x1.6a09e667f3be011f44fdcffc167f7140p-1,
    -0x1.46b9c347764a2p3,
  },
  { // Entry 719
    -0x1.6a09e667f3bc45f7142c50af84f26c75p-1,
    -0x1.6a09e667f3bd4c1a51c9d61e20c523f7p-1,
    0x1.46b9c347764a3p3,
  },
  { // Entry 720
    0x1.6a09e667f3bc45f7142c50af84f26c75p-1,
    -0x1.6a09e667f3bd4c1a51c9d61e20c523f7p-1,
    -0x1.46b9c347764a3p3,
  },
  { // Entry 721
    -0x1.6a09e667f3bcfafc07604a8dfdbe588dp-1,
    -0x1.6a09e667f3bc97155e95dc3fd0885d14p-1,
    0x1.46b9c347764a4p3,
  },
  { // Entry 722
    0x1.6a09e667f3bcfafc07604a8dfdbe588dp-1,
    -0x1.6a09e667f3bc97155e95dc3fd0885d14p-1,
    -0x1.46b9c347764a4p3,
  },
  { // Entry 723
    -0x1.ffffffffffffffffffffffff9d634e9fp-1,
    -0x1.3dc585b2c742181326e07c40748873bbp-49,
    0x1.5fdbbe9bba774p3,
  },
  { // Entry 724
    0x1.ffffffffffffffffffffffff9d634e9fp-1,
    -0x1.3dc585b2c742181326e07c40748873bbp-49,
    -0x1.5fdbbe9bba774p3,
  },
  { // Entry 725
    -0x1.fffffffffffffffffffffffffc461178p-1,
    -0x1.ee2c2d963a10c0993703e20446463301p-52,
    0x1.5fdbbe9bba775p3,
  },
  { // Entry 726
    0x1.fffffffffffffffffffffffffc461178p-1,
    -0x1.ee2c2d963a10c0993703e20446463301p-52,
    -0x1.5fdbbe9bba775p3,
  },
  { // Entry 727
    -0x1.ffffffffffffffffffffffffdb28d451p-1,
    0x1.8474f49a717bcfd9b23f077ee4d090cfp-50,
    0x1.5fdbbe9bba776p3,
  },
  { // Entry 728
    0x1.ffffffffffffffffffffffffdb28d451p-1,
    0x1.8474f49a717bcfd9b23f077ee4d090cfp-50,
    -0x1.5fdbbe9bba776p3,
  },
  { // Entry 729
    -0x1.6a09e667f3be075cad2d50dfc68cd88fp-1,
    0x1.6a09e667f3bb8ab4b8c8d5ecf6b910d6p-1,
    0x1.78fdb9effea45p3,
  },
  { // Entry 730
    0x1.6a09e667f3be075cad2d50dfc68cd88fp-1,
    0x1.6a09e667f3bb8ab4b8c8d5ecf6b910d6p-1,
    -0x1.78fdb9effea45p3,
  },
  { // Entry 731
    -0x1.6a09e667f3bd5257b9f95701d3f13f5dp-1,
    0x1.6a09e667f3bc3fb9abfccfcbcd262aa0p-1,
    0x1.78fdb9effea46p3,
  },
  { // Entry 732
    0x1.6a09e667f3bd5257b9f95701d3f13f5dp-1,
    0x1.6a09e667f3bc3fb9abfccfcbcd262aa0p-1,
    -0x1.78fdb9effea46p3,
  },
  { // Entry 733
    -0x1.6a09e667f3bc9d52c6c55d2386d32c92p-1,
    0x1.6a09e667f3bcf4be9f30c9aa4910cacfp-1,
    0x1.78fdb9effea47p3,
  },
  { // Entry 734
    0x1.6a09e667f3bc9d52c6c55d2386d32c92p-1,
    0x1.6a09e667f3bcf4be9f30c9aa4910cacfp-1,
    -0x1.78fdb9effea47p3,
  },
  { // Entry 735
    0x1.6a09e667f3bb8477509955093bb292bep-1,
    0x1.6a09e667f3be0d9a155cd1c3767eb7b3p-1,
    0x1.ab41b09886fe8p3,
  },
  { // Entry 736
    -0x1.6a09e667f3bb8477509955093bb292bep-1,
    0x1.6a09e667f3be0d9a155cd1c3767eb7b3p-1,
    -0x1.ab41b09886fe8p3,
  },
  { // Entry 737
    0x1.6a09e667f3bc397c43cd4ee8153e60a0p-1,
    0x1.6a09e667f3bd58952228d7e58701d299p-1,
    0x1.ab41b09886fe9p3,
  },
  { // Entry 738
    -0x1.6a09e667f3bc397c43cd4ee8153e60a0p-1,
    0x1.6a09e667f3bd58952228d7e58701d299p-1,
    -0x1.ab41b09886fe9p3,
  },
  { // Entry 739
    0x1.6a09e667f3bcee81370148c69447b4e7p-1,
    0x1.6a09e667f3bca3902ef4de073d0273e6p-1,
    0x1.ab41b09886feap3,
  },
  { // Entry 740
    -0x1.6a09e667f3bcee81370148c69447b4e7p-1,
    0x1.6a09e667f3bca3902ef4de073d0273e6p-1,
    -0x1.ab41b09886feap3,
  },
  { // Entry 741
    0x1.ffffffffffffffffffffffff922141b4p-1,
    0x1.4f6babe5db9e1ef40d69c452e135591dp-49,
    0x1.c463abeccb2bap3,
  },
  { // Entry 742
    -0x1.ffffffffffffffffffffffff922141b4p-1,
    0x1.4f6babe5db9e1ef40d69c452e135591dp-49,
    -0x1.c463abeccb2bap3,
  },
  { // Entry 743
    0x1.fffffffffffffffffffffffff9d717a7p-1,
    0x1.3daeaf976e787bd035a7114be387b5c3p-51,
    0x1.c463abeccb2bbp3,
  },
  { // Entry 744
    -0x1.fffffffffffffffffffffffff9d717a7p-1,
    0x1.3daeaf976e787bd035a7114be387b5c3p-51,
    -0x1.c463abeccb2bbp3,
  },
  { // Entry 745
    0x1.ffffffffffffffffffffffffe18ced9ap-1,
    -0x1.6128a83448c3c217e52c775a0698d26ap-50,
    0x1.c463abeccb2bcp3,
  },
  { // Entry 746
    -0x1.ffffffffffffffffffffffffe18ced9ap-1,
    -0x1.6128a83448c3c217e52c775a0698d26ap-50,
    -0x1.c463abeccb2bcp3,
  },
  { // Entry 747
    0x1.6a09e667f3be13d77d8c52a726550eacp-1,
    -0x1.6a09e667f3bb7e39e869d42580908c7cp-1,
    0x1.dd85a7410f58bp3,
  },
  { // Entry 748
    -0x1.6a09e667f3be13d77d8c52a726550eacp-1,
    -0x1.6a09e667f3bb7e39e869d42580908c7cp-1,
    -0x1.dd85a7410f58bp3,
  },
  { // Entry 749
    0x1.6a09e667f3bd5ed28a5858c939f6ddaap-1,
    -0x1.6a09e667f3bc333edb9dce045d3b0e75p-1,
    0x1.dd85a7410f58cp3,
  },
  { // Entry 750
    -0x1.6a09e667f3bd5ed28a5858c939f6ddaap-1,
    -0x1.6a09e667f3bc333edb9dce045d3b0e75p-1,
    -0x1.dd85a7410f58cp3,
  },
  { // Entry 751
    0x1.6a09e667f3bca9cd97245eeaf316330ep-1,
    -0x1.6a09e667f3bce843ced1c7e2df6316d4p-1,
    0x1.dd85a7410f58dp3,
  },
  { // Entry 752
    -0x1.6a09e667f3bca9cd97245eeaf316330ep-1,
    -0x1.6a09e667f3bce843ced1c7e2df6316d4p-1,
    -0x1.dd85a7410f58dp3,
  },
  { // Entry 753
    0x1.583ebeff65cc226480ae685c1765dec1p-49,
    -0x1.ffffffffffffffffffffffff8c45d3d4p-1,
    0x1.f6a7a2955385dp3,
  },
  { // Entry 754
    -0x1.583ebeff65cc226480ae685c1765dec1p-49,
    -0x1.ffffffffffffffffffffffff8c45d3d4p-1,
    -0x1.f6a7a2955385dp3,
  },
  { // Entry 755
    0x1.60fafbfd9730899202b9a170c3971e86p-51,
    -0x1.fffffffffffffffffffffffff8653353p-1,
    0x1.f6a7a2955385ep3,
  },
  { // Entry 756
    -0x1.60fafbfd9730899202b9a170c3971e86p-51,
    -0x1.fffffffffffffffffffffffff8653353p-1,
    -0x1.f6a7a2955385ep3,
  },
  { // Entry 757
    -0x1.4f8282013467bb36fea32f479753fe7ap-50,
    -0x1.ffffffffffffffffffffffffe48492d3p-1,
    0x1.f6a7a2955385fp3,
  },
  { // Entry 758
    0x1.4f8282013467bb36fea32f479753fe7ap-50,
    -0x1.ffffffffffffffffffffffffe48492d3p-1,
    -0x1.f6a7a2955385fp3,
  },
  { // Entry 759
    -0x1.6a09e667f3ba0df299d25f82f639251fp-1,
    -0x1.6a09e667f3bf841ecc23c74599076a81p-1,
    0x1.07e4cef4cbd96p4,
  },
  { // Entry 760
    0x1.6a09e667f3ba0df299d25f82f639251fp-1,
    -0x1.6a09e667f3bf841ecc23c74599076a81p-1,
    -0x1.07e4cef4cbd96p4,
  },
  { // Entry 761
    -0x1.6a09e667f3bb77fc803a5341c552fe0fp-1,
    -0x1.6a09e667f3be1a14e5bbd38ad60fdd7bp-1,
    0x1.07e4cef4cbd97p4,
  },
  { // Entry 762
    0x1.6a09e667f3bb77fc803a5341c552fe0fp-1,
    -0x1.6a09e667f3be1a14e5bbd38ad60fdd7bp-1,
    -0x1.07e4cef4cbd97p4,
  },
  { // Entry 763
    -0x1.6a09e667f3bce20666a246ff2a62f097p-1,
    -0x1.6a09e667f3bcb00aff53dfcea90e6a0cp-1,
    0x1.07e4cef4cbd98p4,
  },
  { // Entry 764
    0x1.6a09e667f3bce20666a246ff2a62f097p-1,
    -0x1.6a09e667f3bcb00aff53dfcea90e6a0cp-1,
    -0x1.07e4cef4cbd98p4,
  },
  { // Entry 765
    -0x1.fffffffffffffffffffffffd2531a43dp-1,
    -0x1.b088e90c77fd12ea79f98631e6f0b74bp-48,
    0x1.1475cc9eedeffp4,
  },
  { // Entry 766
    0x1.fffffffffffffffffffffffd2531a43dp-1,
    -0x1.b088e90c77fd12ea79f98631e6f0b74bp-48,
    -0x1.1475cc9eedeffp4,
  },
  { // Entry 767
    -0x1.ffffffffffffffffffffffff86437656p-1,
    -0x1.6111d218effa25d4f3f30c654d7c36a1p-49,
    0x1.1475cc9eedfp4,
  },
  { // Entry 768
    0x1.ffffffffffffffffffffffff86437656p-1,
    -0x1.6111d218effa25d4f3f30c654d7c36a1p-49,
    -0x1.1475cc9eedfp4,
  },
  { // Entry 769
    -0x1.ffffffffffffffffffffffffe755486fp-1,
    0x1.3ddc5bce200bb4561819e73527f5a6d7p-50,
    0x1.1475cc9eedf01p4,
  },
  { // Entry 770
    0x1.ffffffffffffffffffffffffe755486fp-1,
    0x1.3ddc5bce200bb4561819e73527f5a6d7p-50,
    -0x1.1475cc9eedf01p4,
  },
  { // Entry 771
    -0x1.6a09e667f3bed557411f4e4c114d7357p-1,
    0x1.6a09e667f3babcba24d6d87ecc8f83b4p-1,
    0x1.2106ca4910068p4,
  },
  { // Entry 772
    0x1.6a09e667f3bed557411f4e4c114d7357p-1,
    0x1.6a09e667f3babcba24d6d87ecc8f83b4p-1,
    -0x1.2106ca4910068p4,
  },
  { // Entry 773
    -0x1.6a09e667f3bd6b4d5ab75a909f8e5b4cp-1,
    0x1.6a09e667f3bc26c40b3ecc3cece1d1a0p-1,
    0x1.2106ca4910069p4,
  },
  { // Entry 774
    0x1.6a09e667f3bd6b4d5ab75a909f8e5b4cp-1,
    0x1.6a09e667f3bc26c40b3ecc3cece1d1a0p-1,
    -0x1.2106ca4910069p4,
  },
  { // Entry 775
    -0x1.6a09e667f3bc0143744f66d3c3c55cd9p-1,
    0x1.6a09e667f3bd90cdf1a6bff9a32a3923p-1,
    0x1.2106ca491006ap4,
  },
  { // Entry 776
    0x1.6a09e667f3bc0143744f66d3c3c55cd9p-1,
    0x1.6a09e667f3bd90cdf1a6bff9a32a3923p-1,
    -0x1.2106ca491006ap4,
  },
  { // Entry 777
    -0x1.34f272993d1414a2b39bd83705cec120p-48,
    0x1.fffffffffffffffffffffffe8b27b6a2p-1,
    0x1.2d97c7f3321d1p4,
  },
  { // Entry 778
    0x1.34f272993d1414a2b39bd83705cec120p-48,
    0x1.fffffffffffffffffffffffe8b27b6a2p-1,
    -0x1.2d97c7f3321d1p4,
  },
  { // Entry 779
    -0x1.a79394c9e8a0a5159cdec1ba8362b968p-51,
    0x1.fffffffffffffffffffffffff50c9bd4p-1,
    0x1.2d97c7f3321d2p4,
  },
  { // Entry 780
    0x1.a79394c9e8a0a5159cdec1ba8362b968p-51,
    0x1.fffffffffffffffffffffffff50c9bd4p-1,
    -0x1.2d97c7f3321d2p4,
  },
  { // Entry 781
    0x1.961b1acd85d7d6ba98c84f9133d10abep-49,
    0x1.ffffffffffffffffffffffff5ef18107p-1,
    0x1.2d97c7f3321d3p4,
  },
  { // Entry 782
    -0x1.961b1acd85d7d6ba98c84f9133d10abep-49,
    0x1.ffffffffffffffffffffffff5ef18107p-1,
    -0x1.2d97c7f3321d3p4,
  },
  { // Entry 783
    0x1.6a09e667f3ba0177c9735dbb72f09f65p-1,
    0x1.6a09e667f3bf90999c82c90cebaf9f3fp-1,
    0x1.3a28c59d54339p4,
  },
  { // Entry 784
    -0x1.6a09e667f3ba0177c9735dbb72f09f65p-1,
    0x1.6a09e667f3bf90999c82c90cebaf9f3fp-1,
    -0x1.3a28c59d54339p4,
  },
  { // Entry 785
    0x1.6a09e667f3bb6b81afdb517a4e8548b4p-1,
    0x1.6a09e667f3be268fb61ad5523532e298p-1,
    0x1.3a28c59d5433ap4,
  },
  { // Entry 786
    -0x1.6a09e667f3bb6b81afdb517a4e8548b4p-1,
    0x1.6a09e667f3be268fb61ad5523532e298p-1,
    -0x1.3a28c59d5433ap4,
  },
  { // Entry 787
    0x1.6a09e667f3bcd58b96434537c0100b9bp-1,
    0x1.6a09e667f3bcbc85cfb2e19614ac3f88p-1,
    0x1.3a28c59d5433bp4,
  },
  { // Entry 788
    -0x1.6a09e667f3bcd58b96434537c0100b9bp-1,
    0x1.6a09e667f3bcbc85cfb2e19614ac3f88p-1,
    -0x1.3a28c59d5433bp4,
  },
  { // Entry 789
    0x1.fffffffffffffffffffffffd0711f437p-1,
    0x1.b95bfc26022b165aed3e2a3b12382479p-48,
    0x1.46b9c347764a2p4,
  },
  { // Entry 790
    -0x1.fffffffffffffffffffffffd0711f437p-1,
    0x1.b95bfc26022b165aed3e2a3b12382479p-48,
    -0x1.46b9c347764a2p4,
  },
  { // Entry 791
    0x1.ffffffffffffffffffffffff79c9ec83p-1,
    0x1.72b7f84c04562cb5da7c5477b957adebp-49,
    0x1.46b9c347764a3p4,
  },
  { // Entry 792
    -0x1.ffffffffffffffffffffffff79c9ec83p-1,
    0x1.72b7f84c04562cb5da7c5477b957adebp-49,
    -0x1.46b9c347764a3p4,
  },
  { // Entry 793
    0x1.ffffffffffffffffffffffffec81e4cfp-1,
    -0x1.1a900f67f753a6944b07571048f1cad2p-50,
    0x1.46b9c347764a4p4,
  },
  { // Entry 794
    -0x1.ffffffffffffffffffffffffec81e4cfp-1,
    -0x1.1a900f67f753a6944b07571048f1cad2p-50,
    -0x1.46b9c347764a4p4,
  },
  { // Entry 795
    0x1.6a09e667f3bee1d2117e501369fbffefp-1,
    -0x1.6a09e667f3bab03f5477d6b74f4d55d5p-1,
    0x1.534ac0f19860bp4,
  },
  { // Entry 796
    -0x1.6a09e667f3bee1d2117e501369fbffefp-1,
    -0x1.6a09e667f3bab03f5477d6b74f4d55d5p-1,
    -0x1.534ac0f19860bp4,
  },
  { // Entry 797
    0x1.6a09e667f3bd77c82b165c5804b7b843p-1,
    -0x1.6a09e667f3bc1a493adfca757c1a741fp-1,
    0x1.534ac0f19860cp4,
  },
  { // Entry 798
    -0x1.6a09e667f3bd77c82b165c5804b7b843p-1,
    -0x1.6a09e667f3bc1a493adfca757c1a741fp-1,
    -0x1.534ac0f19860cp4,
  },
  { // Entry 799
    0x1.6a09e667f3bc0dbe44ae689b35698a2fp-1,
    -0x1.6a09e667f3bd84532147be323eddac01p-1,
    0x1.534ac0f19860dp4,
  },
  { // Entry 800
    -0x1.6a09e667f3bc0dbe44ae689b35698a2fp-1,
    -0x1.6a09e667f3bd84532147be323eddac01p-1,
    -0x1.534ac0f19860dp4,
  },
  { // Entry 801
    0x1.3dc585b2c742181326e07c40375464dep-48,
    -0x1.fffffffffffffffffffffffe758d3a7cp-1,
    0x1.5fdbbe9bba774p4,
  },
  { // Entry 802
    -0x1.3dc585b2c742181326e07c40375464dep-48,
    -0x1.fffffffffffffffffffffffe758d3a7cp-1,
    -0x1.5fdbbe9bba774p4,
  },
  { // Entry 803
    0x1.ee2c2d963a10c0993703e20442ad7b8dp-51,
    -0x1.fffffffffffffffffffffffff11845e1p-1,
    0x1.5fdbbe9bba775p4,
  },
  { // Entry 804
    -0x1.ee2c2d963a10c0993703e20442ad7b8dp-51,
    -0x1.fffffffffffffffffffffffff11845e1p-1,
    -0x1.5fdbbe9bba775p4,
  },
  { // Entry 805
    -0x1.8474f49a717bcfd9b23f077ec8dd175bp-49,
    -0x1.ffffffffffffffffffffffff6ca35147p-1,
    0x1.5fdbbe9bba776p4,
  },
  { // Entry 806
    0x1.8474f49a717bcfd9b23f077ec8dd175bp-49,
    -0x1.ffffffffffffffffffffffff6ca35147p-1,
    -0x1.5fdbbe9bba776p4,
  },
  { // Entry 807
    -0x1.6a09e667f3b9f4fcf9145bf3ef39f901p-1,
    -0x1.6a09e667f3bf9d146ce1cad43de9b352p-1,
    0x1.6c6cbc45dc8dcp4,
  },
  { // Entry 808
    0x1.6a09e667f3b9f4fcf9145bf3ef39f901p-1,
    -0x1.6a09e667f3bf9d146ce1cad43de9b352p-1,
    -0x1.6c6cbc45dc8dcp4,
  },
  { // Entry 809
    -0x1.6a09e667f3bb5f06df7c4fb2d74972aep-1,
    -0x1.6a09e667f3be330a8679d71993e7c709p-1,
    0x1.6c6cbc45dc8ddp4,
  },
  { // Entry 810
    0x1.6a09e667f3bb5f06df7c4fb2d74972aep-1,
    -0x1.6a09e667f3be330a8679d71993e7c709p-1,
    -0x1.6c6cbc45dc8ddp4,
  },
  { // Entry 811
    -0x1.6a09e667f3bcc910c5e44370554f05f4p-1,
    -0x1.6a09e667f3bcc900a011e35d7fdbf459p-1,
    0x1.6c6cbc45dc8dep4,
  },
  { // Entry 812
    0x1.6a09e667f3bcc910c5e44370554f05f4p-1,
    -0x1.6a09e667f3bcc900a011e35d7fdbf459p-1,
    -0x1.6c6cbc45dc8dep4,
  },
  { // Entry 813
    -0x1.fffffffffffffffffffffffce85685bdp-1,
    -0x1.c22f0f3f8c5919cb6082ce443cf95022p-48,
    0x1.78fdb9effea45p4,
  },
  { // Entry 814
    0x1.fffffffffffffffffffffffce85685bdp-1,
    -0x1.c22f0f3f8c5919cb6082ce443cf95022p-48,
    -0x1.78fdb9effea45p4,
  },
  { // Entry 815
    -0x1.ffffffffffffffffffffffff6cb4a43dp-1,
    -0x1.845e1e7f18b23396c1059c8a24c2609cp-49,
    0x1.78fdb9effea46p4,
  },
  { // Entry 816
    0x1.ffffffffffffffffffffffff6cb4a43dp-1,
    -0x1.845e1e7f18b23396c1059c8a24c2609cp-49,
    -0x1.78fdb9effea46p4,
  },
  { // Entry 817
    -0x1.fffffffffffffffffffffffff112c2bcp-1,
    0x1.ee8786039d3731a4fbe98dd6d32ff62ap-51,
    0x1.78fdb9effea47p4,
  },
  { // Entry 818
    0x1.fffffffffffffffffffffffff112c2bcp-1,
    0x1.ee8786039d3731a4fbe98dd6d32ff62ap-51,
    -0x1.78fdb9effea47p4,
  },
  { // Entry 819
    -0x1.6a09e667f3beee4ce1dd51dac23c6bdcp-1,
    0x1.6a09e667f3baa3c48418d4efd19d074ap-1,
    0x1.858eb79a20baep4,
  },
  { // Entry 820
    0x1.6a09e667f3beee4ce1dd51dac23c6bdcp-1,
    0x1.6a09e667f3baa3c48418d4efd19d074ap-1,
    -0x1.858eb79a20baep4,
  },
  { // Entry 821
    -0x1.6a09e667f3bd8442fb755e1f6972f48fp-1,
    0x1.6a09e667f3bc0dce6a80c8ae0ae4f5f3p-1,
    0x1.858eb79a20bafp4,
  },
  { // Entry 822
    0x1.6a09e667f3bd8442fb755e1f6972f48fp-1,
    0x1.6a09e667f3bc0dce6a80c8ae0ae4f5f3p-1,
    -0x1.858eb79a20bafp4,
  },
  { // Entry 823
    -0x1.6a09e667f3bc1a39150d6a62a69f96dap-1,
    0x1.6a09e667f3bd77d850e8bc6ada22fe34p-1,
    0x1.858eb79a20bb0p4,
  },
  { // Entry 824
    0x1.6a09e667f3bc1a39150d6a62a69f96dap-1,
    0x1.6a09e667f3bd77d850e8bc6ada22fe34p-1,
    -0x1.858eb79a20bb0p4,
  },
  { // Entry 825
    0x1.fa7299b17573d373c615096572a0de04p-1,
    -0x1.2ccaf641d4261ea3ccd8d2a102dc3066p-3,
    0x1.fffffffffffffp62,
  },
  { // Entry 826
    -0x1.fa7299b17573d373c615096572a0de04p-1,
    -0x1.2ccaf641d4261ea3ccd8d2a102dc3066p-3,
    -0x1.fffffffffffffp62,
  },
  { // Entry 827
    0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    0x1.0p63,
  },
  { // Entry 828
    -0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    -0x1.0p63,
  },
  { // Entry 829
    0x1.e456b818e7396b45989978d4b7ebf7b3p-1,
    0x1.4c0622a6e35ddefd5f2b7700716a581fp-2,
    0x1.0000000000001p63,
  },
  { // Entry 830
    -0x1.e456b818e7396b45989978d4b7ebf7b3p-1,
    0x1.4c0622a6e35ddefd5f2b7700716a581fp-2,
    -0x1.0000000000001p63,
  },
  { // Entry 831
    -0x1.86dcca0d689e7b56ef79481be4a645c6p-1,
    0x1.4ab650b8c60734385375e22603fcdb10p-1,
    0x1.fffffffffffffp26,
  },
  { // Entry 832
    0x1.86dcca0d689e7b56ef79481be4a645c6p-1,
    0x1.4ab650b8c60734385375e22603fcdb10p-1,
    -0x1.fffffffffffffp26,
  },
  { // Entry 833
    -0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    0x1.0p27,
  },
  { // Entry 834
    0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    -0x1.0p27,
  },
  { // Entry 835
    -0x1.86dcc9155fe182d4515599426bb14b94p-1,
    0x1.4ab651ddeb9e61438382f02167ade4afp-1,
    0x1.0000000000001p27,
  },
  { // Entry 836
    0x1.86dcc9155fe182d4515599426bb14b94p-1,
    0x1.4ab651ddeb9e61438382f02167ade4afp-1,
    -0x1.0000000000001p27,
  },
  { // Entry 837
    -0x1.8f22f84d42da1f57469dfaac44a8b73ap-1,
    0x1.40ad67e777b1df0195189f50a8c26345p-1,
    0x1.fffffffffffffp23,
  },
  { // Entry 838
    0x1.8f22f84d42da1f57469dfaac44a8b73ap-1,
    0x1.40ad67e777b1df0195189f50a8c26345p-1,
    -0x1.fffffffffffffp23,
  },
  { // Entry 839
    -0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    0x1.0p24,
  },
  { // Entry 840
    0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    -0x1.0p24,
  },
  { // Entry 841
    -0x1.8f22f82f32985fe30699c6e12d9dfce2p-1,
    0x1.40ad680ce2f924d716769d1064bc8defp-1,
    0x1.0000000000001p24,
  },
  { // Entry 842
    0x1.8f22f82f32985fe30699c6e12d9dfce2p-1,
    0x1.40ad680ce2f924d716769d1064bc8defp-1,
    -0x1.0000000000001p24,
  },
  { // Entry 843
    -0x1.837b9dddc1eabd379d729f575fc1144cp-1,
    -0x1.4eaa606db24c3cb5e15d7b19d5ee73a1p-1,
    0x1.fffffffffffffp1,
  },
  { // Entry 844
    0x1.837b9dddc1eabd379d729f575fc1144cp-1,
    -0x1.4eaa606db24c3cb5e15d7b19d5ee73a1p-1,
    -0x1.fffffffffffffp1,
  },
  { // Entry 845
    -0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    0x1.0p2,
  },
  { // Entry 846
    0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    -0x1.0p2,
  },
  { // Entry 847
    -0x1.837b9dddc1eb3ab7819bc233db4697b5p-1,
    -0x1.4eaa606db24bab67862a5261b7719dcfp-1,
    0x1.0000000000001p2,
  },
  { // Entry 848
    0x1.837b9dddc1eb3ab7819bc233db4697b5p-1,
    -0x1.4eaa606db24bab67862a5261b7719dcfp-1,
    -0x1.0000000000001p2,
  },
  { // Entry 849
    0x1.d18f6ead1b446b4bcb73c2390b330d75p-1,
    -0x1.aa2265753720101145230952e61c6f2cp-2,
    0x1.fffffffffffffp0,
  },
  { // Entry 850
    -0x1.d18f6ead1b446b4bcb73c2390b330d75p-1,
    -0x1.aa2265753720101145230952e61c6f2cp-2,
    -0x1.fffffffffffffp0,
  },
  { // Entry 851
    0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    0x1.0p1,
  },
  { // Entry 852
    -0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    -0x1.0p1,
  },
  { // Entry 853
    0x1.d18f6ead1b44435891f0c50e01826988p-1,
    -0x1.aa2265753720bea70ea3f38c86db40afp-2,
    0x1.0000000000001p1,
  },
  { // Entry 854
    -0x1.d18f6ead1b44435891f0c50e01826988p-1,
    -0x1.aa2265753720bea70ea3f38c86db40afp-2,
    -0x1.0000000000001p1,
  },
  { // Entry 855
    0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    0x1.fffffffffffffp-1,
  },
  { // Entry 856
    -0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    -0x1.fffffffffffffp-1,
  },
  { // Entry 857
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.0p0,
  },
  { // Entry 858
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.0p0,
  },
  { // Entry 859
    0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    0x1.0000000000001p0,
  },
  { // Entry 860
    -0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    -0x1.0000000000001p0,
  },
  { // Entry 861
    0x1.eaee8744b05ef07cd0b9089130598314p-2,
    0x1.c1528065b7d4fdb158c9c4a6b3e4b740p-1,
    0x1.fffffffffffffp-2,
  },
  { // Entry 862
    -0x1.eaee8744b05ef07cd0b9089130598314p-2,
    0x1.c1528065b7d4fdb158c9c4a6b3e4b740p-1,
    -0x1.fffffffffffffp-2,
  },
  { // Entry 863
    0x1.eaee8744b05efe8764bc364fd837b666p-2,
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    0x1.0p-1,
  },
  { // Entry 864
    -0x1.eaee8744b05efe8764bc364fd837b666p-2,
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    -0x1.0p-1,
  },
  { // Entry 865
    0x1.eaee8744b05f1a9c8cc291cd27981051p-2,
    0x1.c1528065b7d4f22fc19e288479c36b27p-1,
    0x1.0000000000001p-1,
  },
  { // Entry 866
    -0x1.eaee8744b05f1a9c8cc291cd27981051p-2,
    0x1.c1528065b7d4f22fc19e288479c36b27p-1,
    -0x1.0000000000001p-1,
  },
  { // Entry 867
    0x1.faaeed4f31575c27f39c1d7c012a4413p-3,
    0x1.f01549f7deea184c5f1d210b6adbe56cp-1,
    0x1.fffffffffffffp-3,
  },
  { // Entry 868
    -0x1.faaeed4f31575c27f39c1d7c012a4413p-3,
    0x1.f01549f7deea184c5f1d210b6adbe56cp-1,
    -0x1.fffffffffffffp-3,
  },
  { // Entry 869
    0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    0x1.0p-2,
  },
  { // Entry 870
    -0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    -0x1.0p-2,
  },
  { // Entry 871
    0x1.faaeed4f31578aa9f28b5a61f34dccb1p-3,
    0x1.f01549f7deea155458b92a4167aec7ffp-1,
    0x1.0000000000001p-2,
  },
  { // Entry 872
    -0x1.faaeed4f31578aa9f28b5a61f34dccb1p-3,
    0x1.f01549f7deea155458b92a4167aec7ffp-1,
    -0x1.0000000000001p-2,
  },
  { // Entry 873
    0x1.feaaeee86ee34cc05eff28740ee7b469p-4,
    0x1.fc015527d5bd371a12320249ca4dafd7p-1,
    0x1.fffffffffffffp-4,
  },
  { // Entry 874
    -0x1.feaaeee86ee34cc05eff28740ee7b469p-4,
    0x1.fc015527d5bd371a12320249ca4dafd7p-1,
    -0x1.fffffffffffffp-4,
  },
  { // Entry 875
    0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    0x1.0p-3,
  },
  { // Entry 876
    -0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    -0x1.0p-3,
  },
  { // Entry 877
    0x1.feaaeee86ee37c607efae47dcc092c1cp-4,
    0x1.fc015527d5bd365a92186b203507f9adp-1,
    0x1.0000000000001p-3,
  },
  { // Entry 878
    -0x1.feaaeee86ee37c607efae47dcc092c1cp-4,
    0x1.fc015527d5bd365a92186b203507f9adp-1,
    -0x1.0000000000001p-3,
  },
  { // Entry 879
    0x1.ffaaaeeed4ed9b53a408c0f2bc02c8f9p-5,
    0x1.ff0015549f4d34da0b745dc7433145efp-1,
    0x1.fffffffffffffp-5,
  },
  { // Entry 880
    -0x1.ffaaaeeed4ed9b53a408c0f2bc02c8f9p-5,
    0x1.ff0015549f4d34da0b745dc7433145efp-1,
    -0x1.fffffffffffffp-5,
  },
  { // Entry 881
    0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    0x1.0p-4,
  },
  { // Entry 882
    -0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    -0x1.0p-4,
  },
  { // Entry 883
    0x1.ffaaaeeed4edcb3ba608afe1f8f4fa6bp-5,
    0x1.ff0015549f4d34aa1373f7634ce87737p-1,
    0x1.0000000000001p-4,
  },
  { // Entry 884
    -0x1.ffaaaeeed4edcb3ba608afe1f8f4fa6bp-5,
    0x1.ff0015549f4d34aa1373f7634ce87737p-1,
    -0x1.0000000000001p-4,
  },
  { // Entry 885
    0x1.ffeaaaeeee86d8ccfe368cd95e38f003p-6,
    0x1.ffc00155527d2b16aeb09fb70636a10ap-1,
    0x1.fffffffffffffp-6,
  },
  { // Entry 886
    -0x1.ffeaaaeeee86d8ccfe368cd95e38f003p-6,
    0x1.ffc00155527d2b16aeb09fb70636a10ap-1,
    -0x1.fffffffffffffp-6,
  },
  { // Entry 887
    0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    0x1.0p-5,
  },
  { // Entry 888
    -0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    -0x1.0p-5,
  },
  { // Entry 889
    0x1.ffeaaaeeee8708c6fe568c951a428069p-6,
    0x1.ffc00155527d2b0aaf309e1d6f0cfc4ep-1,
    0x1.0000000000001p-5,
  },
  { // Entry 890
    -0x1.ffeaaaeeee8708c6fe568c951a428069p-6,
    0x1.ffc00155527d2b0aaf309e1d6f0cfc4ep-1,
    -0x1.0000000000001p-5,
  },
  { // Entry 891
    0x1.fffaaaaeeeed3ed5c9c5ab6538f9cce0p-7,
    0x1.fff000155549f4a38a2563ef344c3ff4p-1,
    0x1.fffffffffffffp-7,
  },
  { // Entry 892
    -0x1.fffaaaaeeeed3ed5c9c5ab6538f9cce0p-7,
    0x1.fff000155549f4a38a2563ef344c3ff4p-1,
    -0x1.fffffffffffffp-7,
  },
  { // Entry 893
    0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    0x1.0p-6,
  },
  { // Entry 894
    -0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    -0x1.0p-6,
  },
  { // Entry 895
    0x1.fffaaaaeeeed6ed449c7ab6427e8fdd4p-7,
    0x1.fff000155549f4a08a2d63e8cde83db5p-1,
    0x1.0000000000001p-6,
  },
  { // Entry 896
    -0x1.fffaaaaeeeed6ed449c7ab6427e8fdd4p-7,
    0x1.fff000155549f4a08a2d63e8cde83db5p-1,
    -0x1.0000000000001p-6,
  },
  { // Entry 897
    0x1.fffffffaaaaa9aaeeeef6eed4ed442a4p-15,
    0x1.fffffff00000001555565549f49c9f4dp-1,
    0x1.fffffffffffffp-15,
  },
  { // Entry 898
    -0x1.fffffffaaaaa9aaeeeef6eed4ed442a4p-15,
    0x1.fffffff00000001555565549f49c9f4dp-1,
    -0x1.fffffffffffffp-15,
  },
  { // Entry 899
    0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    0x1.fffffff00000001555555549f49f49f7p-1,
    0x1.0p-14,
  },
  { // Entry 900
    -0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    0x1.fffffff00000001555555549f49f49f7p-1,
    -0x1.0p-14,
  },
  { // Entry 901
    0x1.fffffffaaaaacaaeeeedeeed4ed642a4p-15,
    0x1.fffffff00000001555535549f4a49f4dp-1,
    0x1.0000000000001p-14,
  },
  { // Entry 902
    -0x1.fffffffaaaaacaaeeeedeeed4ed642a4p-15,
    0x1.fffffff00000001555535549f4a49f4dp-1,
    -0x1.0000000000001p-14,
  },
  { // Entry 903
    0x1.ffffffffffffeeaaaaaaaaaaaacaeeeep-28,
    0x1.fffffffffffffc000000000000415555p-1,
    0x1.fffffffffffffp-28,
  },
  { // Entry 904
    -0x1.ffffffffffffeeaaaaaaaaaaaacaeeeep-28,
    0x1.fffffffffffffc000000000000415555p-1,
    -0x1.fffffffffffffp-28,
  },
  { // Entry 905
    0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    0x1.fffffffffffffc000000000000015555p-1,
    0x1.0p-27,
  },
  { // Entry 906
    -0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    0x1.fffffffffffffc000000000000015555p-1,
    -0x1.0p-27,
  },
  { // Entry 907
    0x1.0000000000000f555555555555357777p-27,
    0x1.fffffffffffffbffffffffffff815555p-1,
    0x1.0000000000001p-27,
  },
  { // Entry 908
    -0x1.0000000000000f555555555555357777p-27,
    0x1.fffffffffffffbffffffffffff815555p-1,
    -0x1.0000000000001p-27,
  },
  { // Entry 909
    0x1.ffffffffffffeffaaaaaaaaaaaab2aaep-31,
    0x1.fffffffffffffff00000000000010015p-1,
    0x1.fffffffffffffp-31,
  },
  { // Entry 910
    -0x1.ffffffffffffeffaaaaaaaaaaaab2aaep-31,
    0x1.fffffffffffffff00000000000010015p-1,
    -0x1.fffffffffffffp-31,
  },
  { // Entry 911
    0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    0x1.fffffffffffffff00000000000000015p-1,
    0x1.0p-30,
  },
  { // Entry 912
    -0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    0x1.fffffffffffffff00000000000000015p-1,
    -0x1.0p-30,
  },
  { // Entry 913
    0x1.0000000000000ffd555555555554d557p-30,
    0x1.ffffffffffffffeffffffffffffe0015p-1,
    0x1.0000000000001p-30,
  },
  { // Entry 914
    -0x1.0000000000000ffd555555555554d557p-30,
    0x1.ffffffffffffffeffffffffffffe0015p-1,
    -0x1.0000000000001p-30,
  },
  { // Entry 915
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023,
  },
  { // Entry 916
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023,
  },
  { // Entry 917
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023,
  },
  { // Entry 918
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023,
  },
  { // Entry 919
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023,
  },
  { // Entry 920
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023,
  },
  { // Entry 921
    0x1.daa3677c6ee8a22eb6c4b12ca10ce021p-1,
    0x1.7ffdfb4c5308f777cf774c733b256695p-2,
    0x1.ffffffffffffep1023,
  },
  { // Entry 922
    -0x1.daa3677c6ee8a22eb6c4b12ca10ce021p-1,
    0x1.7ffdfb4c5308f777cf774c733b256695p-2,
    -0x1.ffffffffffffep1023,
  },
  { // Entry 923
    0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    0x1.921fb54442d18p1,
  },
  { // Entry 924
    -0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    -0x1.921fb54442d18p1,
  },
  { // Entry 925
    0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    0x1.921fb54442d18p0,
  },
  { // Entry 926
    -0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    -0x1.921fb54442d18p0,
  },
  { // Entry 927
    0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    0x1.0000000000001p0,
  },
  { // Entry 928
    -0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    -0x1.0000000000001p0,
  },
  { // Entry 929
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.0p0,
  },
  { // Entry 930
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.0p0,
  },
  { // Entry 931
    0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    0x1.fffffffffffffp-1,
  },
  { // Entry 932
    -0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    -0x1.fffffffffffffp-1,
  },
  { // Entry 933
    0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    0x1.921fb54442d18p-1,
  },
  { // Entry 934
    -0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    -0x1.921fb54442d18p-1,
  },
  { // Entry 935
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022,
  },
  { // Entry 936
    -0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022,
  },
  { // Entry 937
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022,
  },
  { // Entry 938
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022,
  },
  { // Entry 939
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023,
  },
  { // Entry 940
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023,
  },
  { // Entry 941
    0x1.ffffffffffffbfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffcp-1023,
  },
  { // Entry 942
    -0x1.ffffffffffffbfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffcp-1023,
  },
  { // Entry 943
    0x1.ffffffffffffffffffffffffffffffffp-1074,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1073,
  },
  { // Entry 944
    -0x1.ffffffffffffffffffffffffffffffffp-1074,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1073,
  },
  { // Entry 945
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 946
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 947
    0.0,
    0x1.p0,
    0.0,
  },
  { // Entry 948
    -0.0,
    0x1.p0,
    -0.0,
  },
};
```