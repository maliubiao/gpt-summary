Response:
Here's a breakdown of the thinking process to generate the comprehensive response:

1. **Understand the Core Request:** The user wants to understand the purpose and functionality of the provided C source code snippet, specifically in the context of Android's bionic library. They also want to know how it relates to Android functionality, libc functions, the dynamic linker, common errors, and how to debug it.

2. **Initial Code Analysis:**  The code is a C array of structures. Each structure contains two `double` values represented in hexadecimal floating-point format. The naming convention `sinf_intel_data.handroid` strongly suggests this data is related to the `sinf` function (single-precision sine) and is likely used for testing or lookup tables, potentially optimized for Intel architectures. The ".handroid" part might indicate it's specifically for Android.

3. **Identify Key Areas to Address:** Based on the user's requests, the response needs to cover:
    * **Functionality:** What does this data *do*?
    * **Android Relevance:** How does it fit into the Android ecosystem?
    * **libc Functions:**  Specifically `sinf`.
    * **Dynamic Linker:** How is this data used in the linking process?
    * **Common Errors:** What mistakes might developers make when using related functions?
    * **Android Framework/NDK Integration:** How does data flow from the application to this point?
    * **Frida Hooking:** How can this be debugged dynamically?
    * **Summarization:**  A concise overview of the data's purpose.

4. **Flesh out each area:**

    * **Functionality:**  The data is clearly a table of input-output pairs for the `sinf` function. The first value in each pair is an input angle, and the second is the corresponding sine value. The large number of entries suggests this is for accuracy across a wide range of inputs. The hexadecimal format is for precise representation. *Self-correction:* Initially, I thought it might be *only* for testing. While testing is a primary use, it could also be part of a lookup table optimization within the actual `sinf` implementation.

    * **Android Relevance:**  The `sinf` function is part of the standard C math library (`libm`), which is crucial for many Android apps, especially those dealing with graphics, games, and scientific computations. Provide concrete examples like game physics, signal processing, and UI animations.

    * **libc `sinf` Implementation:** This requires some background knowledge of how `sinf` is typically implemented. Common approaches include:
        * **Range Reduction:** Bringing the input angle to a smaller range (e.g., 0 to pi/2).
        * **Taylor Series:** Approximating the sine function using a polynomial.
        * **Lookup Tables:** Storing pre-computed values for certain angles and interpolating for others. *Crucially, this data file hints at the lookup table approach.*
        * **Combination of Methods:**  Often, implementations combine these techniques for accuracy and performance.

    * **Dynamic Linker:** This is where things get more nuanced. While the *data itself* isn't directly involved in linking, the `sinf` function *is* part of `libm.so`, which *is* linked dynamically. Explain the basic dynamic linking process: library loading, symbol resolution. Provide a simplified `libm.so` layout example showing the `.data` section where this table would likely reside. Explain how the linker resolves calls to `sinf` to the actual implementation in `libm.so`.

    * **Common Errors:** Think about common mistakes developers make when using math functions like `sinf`:
        * **Units of Angles:** Radians vs. Degrees.
        * **Precision Issues:**  Understanding the limitations of floating-point numbers.
        * **Input Range:** Handling edge cases and very large/small numbers.

    * **Android Framework/NDK Integration:**  Trace the path from a high-level Android API call down to this data. Start with an example like `Canvas.drawArc()`, which eventually relies on math functions. Show how the NDK allows direct C/C++ calls to `sinf`. Emphasize the layers involved: Framework -> NDK -> `libm.so` -> Data.

    * **Frida Hooking:**  Provide a practical Frida example. Demonstrate how to hook `sinf`, inspect its arguments, and potentially modify the return value. This directly shows how to interact with the function at runtime.

    * **Summarization:**  Condense the key takeaway: this data is a pre-computed table used to optimize the `sinf` function's performance and accuracy within Android's math library.

5. **Refine and Organize:**  Structure the answer logically using headings and bullet points. Use clear and concise language, explaining technical terms where necessary. Ensure the examples are relevant and easy to understand. Pay attention to the "Chinese reply" requirement.

6. **Review and Self-Critique:** Read through the entire response. Does it address all parts of the user's request? Is the explanation clear and accurate? Are there any areas where more detail or clarification is needed?  For example, initially, I didn't explicitly connect the hexadecimal representation in the data to the need for precision in math functions. I added that during the review. Also, ensuring the dynamic linker explanation was clear and focused on the *relevance* to the data (even if not a direct interaction) was important.
好的，这是对您提供的 `bionic/tests/math_data/sinf_intel_data.handroid` 文件的第三部分归纳总结：

**文件功能归纳：**

这个 C 源代码文件定义了一个名为 `kSinFIntelData` 的常量数组。这个数组存储了一系列预先计算好的单精度浮点数（`float`）的输入值以及对应的正弦函数 (`sinf`) 的返回值。

**具体来说，每一项数据都是一个包含两个 `double` 类型数值的结构体：**

* **第一个 `double` 值：** 代表 `sinf` 函数的输入角度，以十六进制浮点数格式表示。
* **第二个 `double` 值：** 代表使用 Intel 架构优化的 `sinf` 函数计算出的，对应输入角度的正弦值，也以十六进制浮点数格式表示。

**总而言之，这个文件作为一个查找表或者测试数据集合存在，其核心功能是为 `sinf` 函数在 Intel 架构的 Android 设备上提供精确的测试用例或作为优化的依据。**

---

**以下是针对您先前问题的详细解答，也适用于理解这部分数据：**

**1. 功能列举：**

* **存储 `sinf` 函数的测试数据：** 该文件存储了大量的输入值和预期输出值，用于验证 `bionic` 库中 `sinf` 函数的正确性和精度，特别是在 Intel 架构上的实现。
* **可能作为 `sinf` 函数优化的参考：** 这些数据可能被用于对比不同算法或实现方式的 `sinf` 函数的计算结果，以进行性能或精度的优化。
* **提供特定架构（Intel）的基准数据：** 文件名中的 "intel" 表明这些数据可能是针对 Intel 处理器的特性进行过特殊处理或选择的。

**2. 与 Android 功能的关系举例：**

`sinf` 函数是标准 C 库 `<math.h>` 中的一部分，在 Android 系统中被广泛使用。以下是一些例子：

* **图形渲染 (Graphics Rendering)：**  在 Android 图形系统（例如 SurfaceFlinger、Skia 图形库）中，计算旋转、动画、路径等操作时，经常需要使用 `sinf` 来计算角度对应的坐标变化。例如，在绘制一个弧形或者进行 2D 旋转变换时。
* **游戏开发 (Game Development)：** 游戏中的物理引擎、角色动画、视角控制等都离不开三角函数。例如，计算子弹的飞行轨迹、角色的跳跃曲线等。
* **信号处理 (Signal Processing)：**  在音频或视频处理中，`sinf` 可以用于生成正弦波、进行傅里叶变换等。Android 的多媒体框架会使用这些函数。
* **传感器数据处理 (Sensor Data Processing)：** 处理加速度计、陀螺仪等传感器数据时，可能需要使用三角函数进行坐标转换或姿态估计。

**3. `libc` 函数 (`sinf`) 的功能实现：**

`sinf` 函数用于计算给定角度（以弧度为单位）的正弦值。其具体实现通常会采用以下方法的组合：

* **范围规约 (Range Reduction)：**  由于正弦函数是周期性的，首先将输入角度规约到 `[-π/2, π/2]` 或 `[0, 2π]` 这样的较小区间，简化计算。常用的方法包括模运算和利用三角函数的周期性。
* **泰勒级数展开 (Taylor Series Expansion)：** 在规约后的范围内，使用泰勒级数来逼近正弦函数。`sin(x) = x - x^3/3! + x^5/5! - x^7/7! + ...`。为了提高精度和效率，通常会使用优化后的泰勒级数或 Chebyshev 多项式等。
* **查找表 (Lookup Table)：** 对于某些特定的输入值，可以预先计算好结果并存储在查找表中。当输入接近这些值时，可以直接查表或进行插值计算。您提供的这个数据文件很可能就是用于构建或测试这样的查找表。
* **硬件指令优化 (Hardware Instruction Optimization)：** 现代处理器通常提供专门的浮点运算指令，`libc` 的实现会尽可能利用这些指令来提高性能。

**4. 动态链接器功能及 `so` 布局样本和链接处理过程：**

`sinf` 函数通常位于 `libm.so`（数学库）中。当一个 Android 应用或者系统服务需要使用 `sinf` 时，动态链接器会负责将 `libm.so` 加载到进程的内存空间，并将对 `sinf` 函数的调用链接到 `libm.so` 中实际的函数地址。

**`libm.so` 布局样本 (简化)：**

```
ELF Header
...
Program Headers:
  LOAD           offset=0x000000, vaddr=0xb7000000, paddr=0xb7000000, filesz=0x10000, memsz=0x12000, flags=R E
  LOAD           offset=0x010000, vaddr=0xb7010000, paddr=0xb7010000, filesz=0x2000, memsz=0x3000, flags=RW-
Dynamic Section:
  NEEDED         Shared library: [libc.so]
  SONAME         libm.so
  SYMTAB         0x... (符号表)
  STRTAB         0x... (字符串表)
  ...
Symbol Table (.symtab):
  ...
  00012345 g    F .text    sinf  (sinf 函数的地址)
  ...
.text section (代码段):
  ...
  <sinf 函数的机器码>
  ...
.data section (数据段):
  ...
  <kSinFIntelData 数组可能存储在这里>
  ...
.bss section (未初始化数据段):
  ...
```

**链接处理过程：**

1. **编译时：** 当编译器遇到 `sinf` 函数调用时，会在目标文件（`.o`）中生成一个对 `sinf` 的未定义引用。
2. **链接时：** 链接器（在 Android 上通常是 `lld`）会扫描所有的库文件，寻找与未定义引用匹配的符号。
3. **动态链接时（运行时）：**
   * 当应用启动或首次调用 `sinf` 时，Android 的动态链接器 (`linker` 或 `linker64`) 会检查 `libm.so` 是否已经被加载。
   * 如果没有加载，链接器会根据应用的依赖关系加载 `libm.so` 到进程的内存空间。
   * 链接器会解析符号表，找到 `sinf` 函数在 `libm.so` 中的实际地址（例如上面的 `00012345`）。
   * 链接器会修改调用 `sinf` 的指令，将其跳转目标指向 `libm.so` 中 `sinf` 的实际地址。这个过程被称为**重定位 (Relocation)**。
   * 之后，对 `sinf` 的调用就会直接跳转到 `libm.so` 中的代码执行。

**5. 逻辑推理、假设输入与输出：**

该文件本身是数据，不涉及复杂的逻辑推理。但是，我们可以假设一些输入并根据数据推断预期的输出。

**假设输入：**  `-0x1.777a5cf72cec5fd61896cb4f40d1de79p-24` (来自 Entry 769 的第一个值)

**预期输出：** `0x1.921fb6p1` (来自 Entry 769 的第二个值)

这表示，如果将角度 `-0x1.777a5cf72cec5fd61896cb4f40d1de79p-24` 弧度作为 `sinf` 的输入，那么在 Intel 架构的 Android 设备上，`bionic` 库的 `sinf` 函数应该返回 `0x1.921fb6p1`。

**6. 用户或编程常见的使用错误：**

* **角度单位错误：** `sinf` 接受弧度作为输入，但开发者可能会错误地使用角度。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       float angle_degrees = 90.0f;
       // 错误：直接将角度传入 sinf
       float result_wrong = sinf(angle_degrees);
       printf("错误结果: %f\n", result_wrong);

       // 正确：将角度转换为弧度
       float angle_radians = angle_degrees * M_PI / 180.0f;
       float result_correct = sinf(angle_radians);
       printf("正确结果: %f\n", result_correct);
       return 0;
   }
   ```
* **精度问题：** `sinf` 返回单精度浮点数，可能存在精度损失。在需要更高精度的情况下，应该使用 `sin` (double 类型)。
* **输入范围过大：** 虽然 `sinf` 可以处理各种输入，但对于非常大或非常小的输入，可能会遇到数值计算上的问题。
* **忽略返回值检查：** 某些数学函数可能返回特殊值（例如 `NaN`）来表示错误或未定义的结果。开发者应该检查返回值。

**7. Android Framework/NDK 到达这里的步骤及 Frida Hook 示例：**

**步骤：**

1. **Android Framework 调用：**  例如，一个自定义 View 的 `onDraw()` 方法中使用 `Canvas.rotate()` 进行旋转。
2. **Framework 层调用 NDK：** `Canvas.rotate()` 的实现最终会调用 Skia 图形库的 C/C++ 代码。
3. **Skia 调用 `libm.so` 中的 `sinf`：** Skia 内部在计算旋转矩阵时会调用 `sinf` 或相关的数学函数。
4. **动态链接器加载 `libm.so` 并链接 `sinf`：** 当 Skia 首次调用 `sinf` 时，动态链接器会完成链接过程。
5. **`sinf` 函数执行，可能参考 `kSinFIntelData`：** `libm.so` 中 `sinf` 的实现可能会使用预先计算好的数据（如 `kSinFIntelData`）进行优化或作为基准测试。

**Frida Hook 示例：**

```javascript
if (Process.arch === 'arm64') {
  const sinf_ptr = Module.findExportByName("libm.so", "sinf");
  if (sinf_ptr) {
    Interceptor.attach(sinf_ptr, {
      onEnter: function (args) {
        const input = parseFloat(args[0]);
        console.log("[+] 调用 sinf, 输入:", input);
      },
      onLeave: function (retval) {
        const output = parseFloat(retval);
        console.log("[+] sinf 返回:", output);
      }
    });
    console.log("[+] 已 Hook sinf");
  } else {
    console.log("[-] 未找到 sinf");
  }
} else {
  console.log("[-] 此脚本仅适用于 arm64 架构");
}
```

**解释：**

* 此 Frida 脚本仅在 `arm64` 架构上运行（需要根据实际设备架构调整）。
* `Module.findExportByName("libm.so", "sinf")` 尝试在 `libm.so` 中找到 `sinf` 函数的地址。
* `Interceptor.attach()` 用于拦截对 `sinf` 函数的调用。
* `onEnter` 函数在 `sinf` 函数被调用时执行，可以访问其参数 (`args[0]` 是第一个参数，即输入的浮点数)。
* `onLeave` 函数在 `sinf` 函数返回后执行，可以访问其返回值 (`retval`)。

通过运行这个 Frida 脚本，您可以观察到哪些模块调用了 `sinf` 函数，以及每次调用的输入和输出值，从而帮助调试与数学运算相关的问题。

希望以上解释能够帮助您理解这个数据文件的功能和它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/math_data/sinf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共3部分，请归纳一下它的功能

"""
2d184698831f15b6315bfa6b5ae75p-23,
    -0x1.921fb4p1
  },
  { // Entry 769
    -0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    0x1.921fb6p1
  },
  { // Entry 770
    0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    -0x1.921fb6p1
  },
  { // Entry 771
    -0x1.5dde973dcb346afa46203cddc6f7fe97p-22,
    0x1.921fb8p1
  },
  { // Entry 772
    0x1.5dde973dcb346afa46203cddc6f7fe97p-22,
    -0x1.921fb8p1
  },
  { // Entry 773
    -0x1.4442d1846984217628872e56eb58b4c1p-22,
    0x1.921fb4p2
  },
  { // Entry 774
    0x1.4442d1846984217628872e56eb58b4c1p-22,
    -0x1.921fb4p2
  },
  { // Entry 775
    0x1.777a5cf72ceacbf6ec657e977ef771f1p-23,
    0x1.921fb6p2
  },
  { // Entry 776
    -0x1.777a5cf72ceacbf6ec657e977ef771f1p-23,
    -0x1.921fb6p2
  },
  { // Entry 777
    0x1.5dde973dcb1fff10bb0388479e82f4bbp-21,
    0x1.921fb8p2
  },
  { // Entry 778
    -0x1.5dde973dcb1fff10bb0388479e82f4bbp-21,
    -0x1.921fb8p2
  },
  { // Entry 779
    -0x1.4442d1846973df895d1791023ded513cp-21,
    0x1.921fb4p3
  },
  { // Entry 780
    0x1.4442d1846973df895d1791023ded513cp-21,
    -0x1.921fb4p3
  },
  { // Entry 781
    0x1.777a5cf72ce47c7a3ba04bc2a607a9a7p-22,
    0x1.921fb6p3
  },
  { // Entry 782
    -0x1.777a5cf72ce47c7a3ba04bc2a607a9a7p-22,
    -0x1.921fb6p3
  },
  { // Entry 783
    0x1.5dde973dcace4f6a8e90bd15e00610f8p-20,
    0x1.921fb8p3
  },
  { // Entry 784
    -0x1.5dde973dcace4f6a8e90bd15e00610f8p-20,
    -0x1.921fb8p3
  },
  { // Entry 785
    -0x1.4442d1846932d7d62f59209388c7f7cap-20,
    0x1.921fb4p4
  },
  { // Entry 786
    0x1.4442d1846932d7d62f59209388c7f7cap-20,
    -0x1.921fb4p4
  },
  { // Entry 787
    0x1.777a5cf72ccb3e87788b811229e725bcp-21,
    0x1.921fb6p4
  },
  { // Entry 788
    -0x1.777a5cf72ccb3e87788b811229e725bcp-21,
    -0x1.921fb6p4
  },
  { // Entry 789
    0x1.5dde973dc98790d1dcc602bd1b86bccap-19,
    0x1.921fb8p4
  },
  { // Entry 790
    -0x1.5dde973dc98790d1dcc602bd1b86bccap-19,
    -0x1.921fb8p4
  },
  { // Entry 791
    -0x1.4442d184682eb909785fad18bcb5dbfcp-19,
    0x1.921fb4p5
  },
  { // Entry 792
    0x1.4442d184682eb909785fad18bcb5dbfcp-19,
    -0x1.921fb4p5
  },
  { // Entry 793
    0x1.777a5cf72c6646bc6c38607eb34eea13p-20,
    0x1.921fb6p5
  },
  { // Entry 794
    -0x1.777a5cf72c6646bc6c38607eb34eea13p-20,
    -0x1.921fb6p5
  },
  { // Entry 795
    0x1.5dde973dc46c966f15a2403d60cd14d0p-18,
    0x1.921fb8p5
  },
  { // Entry 796
    -0x1.5dde973dc46c966f15a2403d60cd14d0p-18,
    -0x1.921fb8p5
  },
  { // Entry 797
    -0x1.4442d184641e3dd69c7ec32e14a209a5p-18,
    0x1.921fb4p6
  },
  { // Entry 798
    0x1.4442d184641e3dd69c7ec32e14a209a5p-18,
    -0x1.921fb4p6
  },
  { // Entry 799
    0x1.777a5cf72ad267903aec8118778b3b5ap-19,
    0x1.921fb6p6
  },
  { // Entry 800
    -0x1.777a5cf72ad267903aec8118778b3b5ap-19,
    -0x1.921fb6p6
  },
  { // Entry 801
    0x1.5dde973db000ace3f985a473ea1fc039p-17,
    0x1.921fb8p6
  },
  { // Entry 802
    -0x1.5dde973db000ace3f985a473ea1fc039p-17,
    -0x1.921fb8p6
  },
  { // Entry 803
    -0x1.4442d18453dc510b2d495b8bf79bd1cep-17,
    0x1.921fb4p7
  },
  { // Entry 804
    0x1.4442d18453dc510b2d495b8bf79bd1cep-17,
    -0x1.921fb4p7
  },
  { // Entry 805
    0x1.777a5cf72482eadf75c731f972507718p-18,
    0x1.921fb6p7
  },
  { // Entry 806
    -0x1.777a5cf72482eadf75c731f972507718p-18,
    -0x1.921fb6p7
  },
  { // Entry 807
    0x1.5dde973d5e5106b7903a18a552aefc6ep-16,
    0x1.921fb8p7
  },
  { // Entry 808
    -0x1.5dde973d5e5106b7903a18a552aefc6ep-16,
    -0x1.921fb8p7
  },
  { // Entry 809
    0x1.6a09f1940b80c8e25cfc8c10d42576c6p-1,
    0x1.2d97c4p1
  },
  { // Entry 810
    -0x1.6a09f1940b80c8e25cfc8c10d42576c6p-1,
    -0x1.2d97c4p1
  },
  { // Entry 811
    0x1.6a09ebebe40889245d57c5c9d90a6d82p-1,
    0x1.2d97c6p1
  },
  { // Entry 812
    -0x1.6a09ebebe40889245d57c5c9d90a6d82p-1,
    -0x1.2d97c6p1
  },
  { // Entry 813
    0x1.6a09e643bc79a8c79ef4bf187727e269p-1,
    0x1.2d97c8p1
  },
  { // Entry 814
    -0x1.6a09e643bc79a8c79ef4bf187727e269p-1,
    -0x1.2d97c8p1
  },
  { // Entry 815
    -0x1.6a09df19704cf14108e09000ff6374bfp-1,
    0x1.f6a7a0p1
  },
  { // Entry 816
    0x1.6a09df19704cf14108e09000ff6374bfp-1,
    -0x1.f6a7a0p1
  },
  { // Entry 817
    -0x1.6a09e4c197f87ace1c81b43022be39b1p-1,
    0x1.f6a7a2p1
  },
  { // Entry 818
    0x1.6a09e4c197f87ace1c81b43022be39b1p-1,
    -0x1.f6a7a2p1
  },
  { // Entry 819
    -0x1.6a09ea69bf8d63bce40958f5c4b4f155p-1,
    0x1.f6a7a4p1
  },
  { // Entry 820
    0x1.6a09ea69bf8d63bce40958f5c4b4f155p-1,
    -0x1.f6a7a4p1
  },
  { // Entry 821
    -0x1.ffffffffff065cb240bb8f9519d2c6f1p-1,
    0x1.2d97c4p2
  },
  { // Entry 822
    0x1.ffffffffff065cb240bb8f9519d2c6f1p-1,
    -0x1.2d97c4p2
  },
  { // Entry 823
    -0x1.ffffffffffc32939898f464aafc2e74ap-1,
    0x1.2d97c6p2
  },
  { // Entry 824
    0x1.ffffffffffc32939898f464aafc2e74ap-1,
    -0x1.2d97c6p2
  },
  { // Entry 825
    -0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    0x1.2d97c8p2
  },
  { // Entry 826
    0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    -0x1.2d97c8p2
  },
  { // Entry 827
    -0x1.6a09f529316cde5a190d235cc4ccb825p-1,
    0x1.5fdbbcp2
  },
  { // Entry 828
    0x1.6a09f529316cde5a190d235cc4ccb825p-1,
    -0x1.5fdbbcp2
  },
  { // Entry 829
    -0x1.6a09e9d8e2826770567ea818b2e89960p-1,
    0x1.5fdbbep2
  },
  { // Entry 830
    0x1.6a09e9d8e2826770567ea818b2e89960p-1,
    -0x1.5fdbbep2
  },
  { // Entry 831
    -0x1.6a09de88933d6e0c1db78e1d7cd15173p-1,
    0x1.5fdbc0p2
  },
  { // Entry 832
    0x1.6a09de88933d6e0c1db78e1d7cd15173p-1,
    -0x1.5fdbc0p2
  },
  { // Entry 833
    0x1.6a09d033fa715a407a6f03d01b91113fp-1,
    0x1.c463a8p2
  },
  { // Entry 834
    -0x1.6a09d033fa715a407a6f03d01b91113fp-1,
    -0x1.c463a8p2
  },
  { // Entry 835
    0x1.6a09db844a28f8635851fdf8818515efp-1,
    0x1.c463aap2
  },
  { // Entry 836
    -0x1.6a09db844a28f8635851fdf8818515efp-1,
    -0x1.c463aap2
  },
  { // Entry 837
    0x1.6a09e6d49986140f55226fc58672612cp-1,
    0x1.c463acp2
  },
  { // Entry 838
    -0x1.6a09e6d49986140f55226fc58672612cp-1,
    -0x1.c463acp2
  },
  { // Entry 839
    0x1.ffffffffff95397934cac1f28532d3d3p-1,
    0x1.f6a7a0p2
  },
  { // Entry 840
    -0x1.ffffffffff95397934cac1f28532d3d3p-1,
    -0x1.f6a7a0p2
  },
  { // Entry 841
    0x1.fffffffffffa8e5aae2bb93ae590f984p-1,
    0x1.f6a7a2p2
  },
  { // Entry 842
    -0x1.fffffffffffa8e5aae2bb93ae590f984p-1,
    -0x1.f6a7a2p2
  },
  { // Entry 843
    0x1.ffffffffffdfe33c278cb48a59ee3ef2p-1,
    0x1.f6a7a4p2
  },
  { // Entry 844
    -0x1.ffffffffffdfe33c278cb48a59ee3ef2p-1,
    -0x1.f6a7a4p2
  },
  { // Entry 845
    0x1.6a0a040ea5c32ba4afbeb86a614c5d16p-1,
    0x1.1475cap3
  },
  { // Entry 846
    -0x1.6a0a040ea5c32ba4afbeb86a614c5d16p-1,
    -0x1.1475cap3
  },
  { // Entry 847
    0x1.6a09ed6e088212b1e260a5132d6959b7p-1,
    0x1.1475ccp3
  },
  { // Entry 848
    -0x1.6a09ed6e088212b1e260a5132d6959b7p-1,
    -0x1.1475ccp3
  },
  { // Entry 849
    0x1.6a09d6cd69d6efd1a6fa2dd4c617cbbep-1,
    0x1.1475cep3
  },
  { // Entry 850
    -0x1.6a09d6cd69d6efd1a6fa2dd4c617cbbep-1,
    -0x1.1475cep3
  },
  { // Entry 851
    0x1.f9990e91a64ae486757878bdfee0f703p-20,
    0x1.2d97c4p3
  },
  { // Entry 852
    -0x1.f9990e91a64ae486757878bdfee0f703p-20,
    -0x1.2d97c4p3
  },
  { // Entry 853
    0x1.f3321d234ed8128aabb0499a43b4def2p-21,
    0x1.2d97c6p3
  },
  { // Entry 854
    -0x1.f3321d234ed8128aabb0499a43b4def2p-21,
    -0x1.2d97c6p3
  },
  { // Entry 855
    -0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    0x1.2d97c8p3
  },
  { // Entry 856
    0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    -0x1.2d97c8p3
  },
  { // Entry 857
    -0x1.6a09c14e83f8db080d1223f887cc12ecp-1,
    0x1.46b9c0p3
  },
  { // Entry 858
    0x1.6a09c14e83f8db080d1223f887cc12ecp-1,
    -0x1.46b9c0p3
  },
  { // Entry 859
    -0x1.6a09d7ef23fbec1ed812e807beb0492fp-1,
    0x1.46b9c2p3
  },
  { // Entry 860
    0x1.6a09d7ef23fbec1ed812e807beb0492fp-1,
    -0x1.46b9c2p3
  },
  { // Entry 861
    -0x1.6a09ee8fc294f35db3efce565365af89p-1,
    0x1.46b9c4p3
  },
  { // Entry 862
    0x1.6a09ee8fc294f35db3efce565365af89p-1,
    -0x1.46b9c4p3
  },
  { // Entry 863
    -0x1.fffffffffe4c96b397d951cb21861c95p-1,
    0x1.5fdbbcp3
  },
  { // Entry 864
    0x1.fffffffffe4c96b397d951cb21861c95p-1,
    -0x1.5fdbbcp3
  },
  { // Entry 865
    -0x1.ffffffffffe8512aebb56c9e75b41941p-1,
    0x1.5fdbbep3
  },
  { // Entry 866
    0x1.ffffffffffe8512aebb56c9e75b41941p-1,
    -0x1.5fdbbep3
  },
  { // Entry 867
    -0x1.ffffffffff840ba23f91c9cb49a10b27p-1,
    0x1.5fdbc0p3
  },
  { // Entry 868
    0x1.ffffffffff840ba23f91c9cb49a10b27p-1,
    -0x1.5fdbc0p3
  },
  { // Entry 869
    -0x1.6a0a12f4197c90a0ee4a094b6377aa23p-1,
    0x1.78fdb6p3
  },
  { // Entry 870
    0x1.6a0a12f4197c90a0ee4a094b6377aa23p-1,
    -0x1.78fdb6p3
  },
  { // Entry 871
    -0x1.6a09fc537d29cf131d6710991bebabedp-1,
    0x1.78fdb8p3
  },
  { // Entry 872
    0x1.6a09fc537d29cf131d6710991bebabedp-1,
    -0x1.78fdb8p3
  },
  { // Entry 873
    -0x1.6a09e5b2df6d0388f9070c4340f3e669p-1,
    0x1.78fdbap3
  },
  { // Entry 874
    0x1.6a09e5b2df6d0388f9070c4340f3e669p-1,
    -0x1.78fdbap3
  },
  { // Entry 875
    0x1.6a09c909add4dbf32253a39d5c306308p-1,
    0x1.ab41aep3
  },
  { // Entry 876
    -0x1.6a09c909add4dbf32253a39d5c306308p-1,
    -0x1.ab41aep3
  },
  { // Entry 877
    0x1.6a09dfaa4d5c3a7f056f3e61a365b29ep-1,
    0x1.ab41b0p3
  },
  { // Entry 878
    -0x1.6a09dfaa4d5c3a7f056f3e61a365b29ep-1,
    -0x1.ab41b0p3
  },
  { // Entry 879
    0x1.6a09f64aeb798f2b3e3d9b16e8e3c412p-1,
    0x1.ab41b2p3
  },
  { // Entry 880
    -0x1.6a09f64aeb798f2b3e3d9b16e8e3c412p-1,
    -0x1.ab41b2p3
  },
  { // Entry 881
    0x1.fffffffffc260d6ffb8f4cd8ab3fd020p-1,
    0x1.c463a8p3
  },
  { // Entry 882
    -0x1.fffffffffc260d6ffb8f4cd8ab3fd020p-1,
    -0x1.c463a8p3
  },
  { // Entry 883
    0x1.ffffffffff12d89bb084dd762848b3d6p-1,
    0x1.c463aap3
  },
  { // Entry 884
    -0x1.ffffffffff12d89bb084dd762848b3d6p-1,
    -0x1.c463aap3
  },
  { // Entry 885
    0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    0x1.c463acp3
  },
  { // Entry 886
    -0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    -0x1.c463acp3
  },
  { // Entry 887
    0x1.6a0a0b38f134a3295a0b386e42f1ca7ap-1,
    0x1.dd85a4p3
  },
  { // Entry 888
    -0x1.6a0a0b38f134a3295a0b386e42f1ca7ap-1,
    -0x1.dd85a4p3
  },
  { // Entry 889
    0x1.6a09f49854662eff1b35755a129044a7p-1,
    0x1.dd85a6p3
  },
  { // Entry 890
    -0x1.6a09f49854662eff1b35755a129044a7p-1,
    -0x1.dd85a6p3
  },
  { // Entry 891
    0x1.6a09ddf7b62db0e0440b6a4262203b11p-1,
    0x1.dd85a8p3
  },
  { // Entry 892
    -0x1.6a09ddf7b62db0e0440b6a4262203b11p-1,
    -0x1.dd85a8p3
  },
  { // Entry 893
    0x1.4aa9c2f2c19a062b18a017bcd5424feap-20,
    0x1.f6a7a0p3
  },
  { // Entry 894
    -0x1.4aa9c2f2c19a062b18a017bcd5424feap-20,
    -0x1.f6a7a0p3
  },
  { // Entry 895
    0x1.2aa70bcb07d3a40781510d213652e43ap-22,
    0x1.f6a7a2p3
  },
  { // Entry 896
    -0x1.2aa70bcb07d3a40781510d213652e43ap-22,
    -0x1.f6a7a2p3
  },
  { // Entry 897
    -0x1.6aac7a1a7bf5bbd49572ffb8d7749922p-21,
    0x1.f6a7a4p3
  },
  { // Entry 898
    0x1.6aac7a1a7bf5bbd49572ffb8d7749922p-21,
    -0x1.f6a7a4p3
  },
  { // Entry 899
    -0x1.6a09a383953124096898340f9168b9d5p-1,
    0x1.07e4ccp4
  },
  { // Entry 900
    0x1.6a09a383953124096898340f9168b9d5p-1,
    -0x1.07e4ccp4
  },
  { // Entry 901
    -0x1.6a09d0c4d7869961c47a9b0b968cc910p-1,
    0x1.07e4cep4
  },
  { // Entry 902
    0x1.6a09d0c4d7869961c47a9b0b968cc910p-1,
    -0x1.07e4cep4
  },
  { // Entry 903
    -0x1.6a09fe061433e7770d00ca59d5a56251p-1,
    0x1.07e4d0p4
  },
  { // Entry 904
    0x1.6a09fe061433e7770d00ca59d5a56251p-1,
    -0x1.07e4d0p4
  },
  { // Entry 905
    -0x1.fffffffff9219dae5feda1b539335803p-1,
    0x1.1475cap4
  },
  { // Entry 906
    0x1.fffffffff9219dae5feda1b539335803p-1,
    -0x1.1475cap4
  },
  { // Entry 907
    -0x1.ffffffffff9d556e8c0bf0a80d610808p-1,
    0x1.1475ccp4
  },
  { // Entry 908
    0x1.ffffffffff9d556e8c0bf0a80d610808p-1,
    -0x1.1475ccp4
  },
  { // Entry 909
    -0x1.fffffffffe190d2eb82e74efd2093215p-1,
    0x1.1475cep4
  },
  { // Entry 910
    0x1.fffffffffe190d2eb82e74efd2093215p-1,
    -0x1.1475cep4
  },
  { // Entry 911
    -0x1.6a0a1a1e64a28eee238dc852846aacd5p-1,
    0x1.2106c8p4
  },
  { // Entry 912
    0x1.6a0a1a1e64a28eee238dc852846aacd5p-1,
    -0x1.2106c8p4
  },
  { // Entry 913
    -0x1.6a09ecdd2b784b699034ee8102670e27p-1,
    0x1.2106cap4
  },
  { // Entry 914
    0x1.6a09ecdd2b784b699034ee8102670e27p-1,
    -0x1.2106cap4
  },
  { // Entry 915
    -0x1.6a09bf9beca5e03188301639c09ed574p-1,
    0x1.2106ccp4
  },
  { // Entry 916
    0x1.6a09bf9beca5e03188301639c09ed574p-1,
    -0x1.2106ccp4
  },
  { // Entry 917
    -0x1.f9990e91a270d3bc1c02f4f69f48e675p-19,
    0x1.2d97c4p4
  },
  { // Entry 918
    0x1.f9990e91a270d3bc1c02f4f69f48e675p-19,
    -0x1.2d97c4p4
  },
  { // Entry 919
    -0x1.f3321d234deacd6f3afd75039685012fp-20,
    0x1.2d97c6p4
  },
  { // Entry 920
    0x1.f3321d234deacd6f3afd75039685012fp-20,
    -0x1.2d97c6p4
  },
  { // Entry 921
    0x1.99bc5b961b1aa1c9e8023074f3406fd9p-25,
    0x1.2d97c8p4
  },
  { // Entry 922
    -0x1.99bc5b961b1aa1c9e8023074f3406fd9p-25,
    -0x1.2d97c8p4
  },
  { // Entry 923
    0x1.6a09949e1ce1ec501afcb35d731bf62cp-1,
    0x1.3a28c2p4
  },
  { // Entry 924
    -0x1.6a09949e1ce1ec501afcb35d731bf62cp-1,
    -0x1.3a28c2p4
  },
  { // Entry 925
    0x1.6a09c1df6114100c65d1ff6c55755e72p-1,
    0x1.3a28c4p4
  },
  { // Entry 926
    -0x1.6a09c1df6114100c65d1ff6c55755e72p-1,
    -0x1.3a28c4p4
  },
  { // Entry 927
    0x1.6a09ef209f9e0cc13324ddf2b361553fp-1,
    0x1.3a28c6p4
  },
  { // Entry 928
    -0x1.6a09ef209f9e0cc13324ddf2b361553fp-1,
    -0x1.3a28c6p4
  },
  { // Entry 929
    0x1.fffffffff53f476ec4f59f26c4bcdfa0p-1,
    0x1.46b9c0p4
  },
  { // Entry 930
    -0x1.fffffffff53f476ec4f59f26c4bcdfa0p-1,
    -0x1.46b9c0p4
  },
  { // Entry 931
    0x1.fffffffffe5d2097b34334ad679dd7a4p-1,
    0x1.46b9c2p4
  },
  { // Entry 932
    -0x1.fffffffffe5d2097b34334ad679dd7a4p-1,
    -0x1.46b9c2p4
  },
  { // Entry 933
    0x1.ffffffffff7af9c0a19a005c565c6af7p-1,
    0x1.46b9c4p4
  },
  { // Entry 934
    -0x1.ffffffffff7af9c0a19a005c565c6af7p-1,
    -0x1.46b9c4p4
  },
  { // Entry 935
    0x1.6a0a2903d773925b052fb006ac670c23p-1,
    0x1.534abep4
  },
  { // Entry 936
    -0x1.6a0a2903d773925b052fb006ac670c23p-1,
    -0x1.534abep4
  },
  { // Entry 937
    0x1.6a09fbc2a025fdae918466fa00142143p-1,
    0x1.534ac0p4
  },
  { // Entry 938
    -0x1.6a09fbc2a025fdae918466fa00142143p-1,
    -0x1.534ac0p4
  },
  { // Entry 939
    0x1.6a09ce8163304113135a68ae93d3fa0ep-1,
    0x1.534ac2p4
  },
  { // Entry 940
    -0x1.6a09ce8163304113135a68ae93d3fa0ep-1,
    -0x1.534ac2p4
  },
  { // Entry 941
    0x1.4ddd3ba9ecb19d6bb6ea161120e447b9p-19,
    0x1.5fdbbcp4
  },
  { // Entry 942
    -0x1.4ddd3ba9ecb19d6bb6ea161120e447b9p-19,
    -0x1.5fdbbcp4
  },
  { // Entry 943
    0x1.3774eea7b89d80df7816fe208ec69fc0p-21,
    0x1.5fdbbep4
  },
  { // Entry 944
    -0x1.3774eea7b89d80df7816fe208ec69fc0p-21,
    -0x1.5fdbbep4
  },
  { // Entry 945
    -0x1.644588ac2334a3d5452d9960282cf80dp-20,
    0x1.5fdbc0p4
  },
  { // Entry 946
    0x1.644588ac2334a3d5452d9960282cf80dp-20,
    -0x1.5fdbc0p4
  },
  { // Entry 947
    -0x1.6a09b2f9ea049e855e35ca9ce7e0d89ap-1,
    0x1.6c6cbap4
  },
  { // Entry 948
    0x1.6a09b2f9ea049e855e35ca9ce7e0d89ap-1,
    -0x1.6c6cbap4
  },
  { // Entry 949
    -0x1.6a09e03b2a6b49c6134c67b42baee668p-1,
    0x1.6c6cbcp4
  },
  { // Entry 950
    0x1.6a09e03b2a6b49c6134c67b42baee668p-1,
    -0x1.6c6cbcp4
  },
  { // Entry 951
    -0x1.6a0a0d7c6529cd85dbbb3a5c2cd3fae5p-1,
    0x1.6c6cbep4
  },
  { // Entry 952
    0x1.6a0a0d7c6529cd85dbbb3a5c2cd3fae5p-1,
    -0x1.6c6cbep4
  },
  { // Entry 953
    -0x1.fffffffff07f0ab12aa8f41f29c15392p-1,
    0x1.78fdb6p4
  },
  { // Entry 954
    0x1.fffffffff07f0ab12aa8f41f29c15392p-1,
    -0x1.78fdb6p4
  },
  { // Entry 955
    -0x1.fffffffffc3f0542db21dcbcb847dac3p-1,
    0x1.78fdb8p4
  },
  { // Entry 956
    0x1.fffffffffc3f0542db21dcbcb847dac3p-1,
    -0x1.78fdb8p4
  },
  { // Entry 957
    -0x1.fffffffffffeffd48bac73efe60c7fcfp-1,
    0x1.78fdbap4
  },
  { // Entry 958
    0x1.fffffffffffeffd48bac73efe60c7fcfp-1,
    -0x1.78fdbap4
  },
  { // Entry 959
    -0x1.6a0a37e949a7ad698a32234c73e5afbap-1,
    0x1.858eb4p4
  },
  { // Entry 960
    0x1.6a0a37e949a7ad698a32234c73e5afbap-1,
    -0x1.858eb4p4
  },
  { // Entry 961
    -0x1.6a0a0aa81436c7a8d33a38d704030d14p-1,
    0x1.858eb6p4
  },
  { // Entry 962
    0x1.6a0a0aa81436c7a8d33a38d704030d14p-1,
    -0x1.858eb6p4
  },
  { // Entry 963
    -0x1.6a09dd66d91db9bd7bf355faff08f194p-1,
    0x1.858eb8p4
  },
  { // Entry 964
    0x1.6a09dd66d91db9bd7bf355faff08f194p-1,
    -0x1.858eb8p4
  },
  { // Entry 965
    0x1.c048b38a8bbf59f414fec7079209926ep-3,
    0x1.fffffep62
  },
  { // Entry 966
    -0x1.c048b38a8bbf59f414fec7079209926ep-3,
    -0x1.fffffep62
  },
  { // Entry 967
    0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    0x1.p63
  },
  { // Entry 968
    -0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    -0x1.p63
  },
  { // Entry 969
    -0x1.d6637d070347ee94e830445e76486727p-1,
    0x1.000002p63
  },
  { // Entry 970
    0x1.d6637d070347ee94e830445e76486727p-1,
    -0x1.000002p63
  },
  { // Entry 971
    -0x1.0e5283661df0ca0f55ab6167e14514a1p-1,
    0x1.fffffep26
  },
  { // Entry 972
    0x1.0e5283661df0ca0f55ab6167e14514a1p-1,
    -0x1.fffffep26
  },
  { // Entry 973
    -0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    0x1.p27
  },
  { // Entry 974
    0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    -0x1.p27
  },
  { // Entry 975
    0x1.171999b629fd5b6357c6dff4d7827d95p-1,
    0x1.000002p27
  },
  { // Entry 976
    -0x1.171999b629fd5b6357c6dff4d7827d95p-1,
    -0x1.000002p27
  },
  { // Entry 977
    -0x1.e57ec09221973550d1e5798dcf0cd25dp-1,
    0x1.fffffep23
  },
  { // Entry 978
    0x1.e57ec09221973550d1e5798dcf0cd25dp-1,
    -0x1.fffffep23
  },
  { // Entry 979
    -0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    0x1.p24
  },
  { // Entry 980
    0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    -0x1.p24
  },
  { // Entry 981
    0x1.c9b0c7265c543f80faf01741c6458560p-1,
    0x1.000002p24
  },
  { // Entry 982
    -0x1.c9b0c7265c543f80faf01741c6458560p-1,
    -0x1.000002p24
  },
  { // Entry 983
    -0x1.837b98a3185d1466d852f0a7dc1d248ep-1,
    0x1.fffffep1
  },
  { // Entry 984
    0x1.837b98a3185d1466d852f0a7dc1d248ep-1,
    -0x1.fffffep1
  },
  { // Entry 985
    -0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    0x1.p2
  },
  { // Entry 986
    0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    -0x1.p2
  },
  { // Entry 987
    -0x1.837ba85314bde52b1e9c2c8ed2712c72p-1,
    0x1.000002p2
  },
  { // Entry 988
    0x1.837ba85314bde52b1e9c2c8ed2712c72p-1,
    -0x1.000002p2
  },
  { // Entry 989
    0x1.d18f70573da63012fa1c0e3d2ebbe59cp-1,
    0x1.fffffep0
  },
  { // Entry 990
    -0x1.d18f70573da63012fa1c0e3d2ebbe59cp-1,
    -0x1.fffffep0
  },
  { // Entry 991
    0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    0x1.p1
  },
  { // Entry 992
    -0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    -0x1.p1
  },
  { // Entry 993
    0x1.d18f6b58d66ae7110b2b6f7cffba6ec1p-1,
    0x1.000002p1
  },
  { // Entry 994
    -0x1.d18f6b58d66ae7110b2b6f7cffba6ec1p-1,
    -0x1.000002p1
  },
  { // Entry 995
    0x1.aed547dbee4d0d8680d0813d1e4e21d0p-1,
    0x1.fffffep-1
  },
  { // Entry 996
    -0x1.aed547dbee4d0d8680d0813d1e4e21d0p-1,
    -0x1.fffffep-1
  },
  { // Entry 997
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.p0
  },
  { // Entry 998
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    -0x1.p0
  },
  { // Entry 999
    0x1.aed54b19d5cd7937cbf41ed408ca0a52p-1,
    0x1.000002p0
  },
  { // Entry 1000
    -0x1.aed54b19d5cd7937cbf41ed408ca0a52p-1,
    -0x1.000002p0
  },
  { // Entry 1001
    0x1.eaee85835dde5b71beec7d8d98052112p-2,
    0x1.fffffep-2
  },
  { // Entry 1002
    -0x1.eaee85835dde5b71beec7d8d98052112p-2,
    -0x1.fffffep-2
  },
  { // Entry 1003
    0x1.eaee8744b05efe8764bc364fd837b666p-2,
    0x1.p-1
  },
  { // Entry 1004
    -0x1.eaee8744b05efe8764bc364fd837b666p-2,
    -0x1.p-1
  },
  { // Entry 1005
    0x1.eaee8ac7555ed47fca77ceed174c8ea0p-2,
    0x1.000002p-1
  },
  { // Entry 1006
    -0x1.eaee8ac7555ed47fca77ceed174c8ea0p-2,
    -0x1.000002p-1
  },
  { // Entry 1007
    0x1.faaeeb5f1c0d63f43c6f3ec46011690fp-3,
    0x1.fffffep-3
  },
  { // Entry 1008
    -0x1.faaeeb5f1c0d63f43c6f3ec46011690fp-3,
    -0x1.fffffep-3
  },
  { // Entry 1009
    0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    0x1.p-2
  },
  { // Entry 1010
    -0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    -0x1.p-2
  },
  { // Entry 1011
    0x1.faaef12f5beb1c1094473d3c3365b9e1p-3,
    0x1.000002p-2
  },
  { // Entry 1012
    -0x1.faaef12f5beb1c1094473d3c3365b9e1p-3,
    -0x1.000002p-2
  },
  { // Entry 1013
    0x1.feaaecec6d8e30cd56950eb2ebdcebd4p-4,
    0x1.fffffep-4
  },
  { // Entry 1014
    -0x1.feaaecec6d8e30cd56950eb2ebdcebd4p-4,
    -0x1.fffffep-4
  },
  { // Entry 1015
    0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    0x1.p-3
  },
  { // Entry 1016
    -0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    -0x1.p-3
  },
  { // Entry 1017
    0x1.feaaf2e0718d9c568c9442c81545cd62p-4,
    0x1.000002p-3
  },
  { // Entry 1018
    -0x1.feaaf2e0718d9c568c9442c81545cd62p-4,
    -0x1.000002p-3
  },
  { // Entry 1019
    0x1.ffaaacefd4d855ac8227799f3e263d7ap-5,
    0x1.fffffep-5
  },
  { // Entry 1020
    -0x1.ffaaacefd4d855ac8227799f3e263d7ap-5,
    -0x1.fffffep-5
  },
  { // Entry 1021
    0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    0x1.p-4
  },
  { // Entry 1022
    -0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    -0x1.p-4
  },
  { // Entry 1023
    0x1.ffaab2ecd518508ae9bc730a165a8eadp-5,
    0x1.000002p-4
  },
  { // Entry 1024
    -0x1.ffaab2ecd518508ae9bc730a165a8eadp-5,
    -0x1.000002p-4
  },
  { // Entry 1025
    0x1.ffeaa8ef2e85933883c0dc33462387b5p-6,
    0x1.fffffep-6
  },
  { // Entry 1026
    -0x1.ffeaa8ef2e85933883c0dc33462387b5p-6,
    -0x1.fffffep-6
  },
  { // Entry 1027
    0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    0x1.p-5
  },
  { // Entry 1028
    -0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    -0x1.p-5
  },
  { // Entry 1029
    0x1.ffeaaeee6e89927003413abe64e9dc21p-6,
    0x1.000002p-5
  },
  { // Entry 1030
    -0x1.ffeaaeee6e89927003413abe64e9dc21p-6,
    -0x1.000002p-5
  },
  { // Entry 1031
    0x1.fffaa8aefeed396ffffc636313d0ba6dp-7,
    0x1.fffffep-7
  },
  { // Entry 1032
    -0x1.fffaa8aefeed396ffffc636313d0ba6dp-7,
    -0x1.fffffep-7
  },
  { // Entry 1033
    0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    0x1.p-6
  },
  { // Entry 1034
    -0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    -0x1.p-6
  },
  { // Entry 1035
    0x1.fffaaeaeceed793fde5a1a9ca5bb1ee6p-7,
    0x1.000002p-6
  },
  { // Entry 1036
    -0x1.fffaaeaeceed793fde5a1a9ca5bb1ee6p-7,
    -0x1.000002p-6
  },
  { // Entry 1037
    0x1.fffffdfaaaaabaaeeeded997feffa35ap-15,
    0x1.fffffep-15
  },
  { // Entry 1038
    -0x1.fffffdfaaaaabaaeeeded997feffa35ap-15,
    -0x1.fffffep-15
  },
  { // Entry 1039
    0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    0x1.p-14
  },
  { // Entry 1040
    -0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    -0x1.p-14
  },
  { // Entry 1041
    0x1.000001fd5555455777578ccbe7bfc09cp-14,
    0x1.000002p-14
  },
  { // Entry 1042
    -0x1.000001fd5555455777578ccbe7bfc09cp-14,
    -0x1.000002p-14
  },
  { // Entry 1043
    0x1.fffffdfffffffeaaaaaeaaaaa6aaeef0p-28,
    0x1.fffffep-28
  },
  { // Entry 1044
    -0x1.fffffdfffffffeaaaaaeaaaaa6aaeef0p-28,
    -0x1.fffffep-28
  },
  { // Entry 1045
    0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    0x1.p-27
  },
  { // Entry 1046
    -0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    -0x1.p-27
  },
  { // Entry 1047
    0x1.000001ffffffff55555155554d557772p-27,
    0x1.000002p-27
  },
  { // Entry 1048
    -0x1.000001ffffffff55555155554d557772p-27,
    -0x1.000002p-27
  },
  { // Entry 1049
    0x1.fffffdfffffffffaaaaabaaaaa9aaaaep-31,
    0x1.fffffep-31
  },
  { // Entry 1050
    -0x1.fffffdfffffffffaaaaabaaaaa9aaaaep-31,
    -0x1.fffffep-31
  },
  { // Entry 1051
    0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    0x1.p-30
  },
  { // Entry 1052
    -0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    -0x1.p-30
  },
  { // Entry 1053
    0x1.000001fffffffffd5555455555355557p-30,
    0x1.000002p-30
  },
  { // Entry 1054
    -0x1.000001fffffffffd5555455555355557p-30,
    -0x1.000002p-30
  },
  { // Entry 1055
    0x1.0b3366508957520d9dc88d7c09337e24p-1,
    -0x1.fffffep127
  },
  { // Entry 1056
    -0x1.0b3366508957520d9dc88d7c09337e24p-1,
    0x1.fffffep127
  },
  { // Entry 1057
    -0x1.0b3366508957520d9dc88d7c09337e24p-1,
    0x1.fffffep127
  },
  { // Entry 1058
    0x1.0b3366508957520d9dc88d7c09337e24p-1,
    -0x1.fffffep127
  },
  { // Entry 1059
    -0x1.0b3366508957520d9dc88d7c09337e24p-1,
    0x1.fffffep127
  },
  { // Entry 1060
    0x1.0b3366508957520d9dc88d7c09337e24p-1,
    -0x1.fffffep127
  },
  { // Entry 1061
    -0x1.48ce575202efd93c62f7b88106ea1d4dp-1,
    0x1.fffffcp127
  },
  { // Entry 1062
    0x1.48ce575202efd93c62f7b88106ea1d4dp-1,
    -0x1.fffffcp127
  },
  { // Entry 1063
    -0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    0x1.921fb6p1
  },
  { // Entry 1064
    0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    -0x1.921fb6p1
  },
  { // Entry 1065
    0x1.ffffffffffff76521249c7422930ed82p-1,
    0x1.921fb6p0
  },
  { // Entry 1066
    -0x1.ffffffffffff76521249c7422930ed82p-1,
    -0x1.921fb6p0
  },
  { // Entry 1067
    0x1.aed54b19d5cd7937cbf41ed408ca0a52p-1,
    0x1.000002p0
  },
  { // Entry 1068
    -0x1.aed54b19d5cd7937cbf41ed408ca0a52p-1,
    -0x1.000002p0
  },
  { // Entry 1069
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.p0
  },
  { // Entry 1070
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    -0x1.p0
  },
  { // Entry 1071
    0x1.aed547dbee4d0d8680d0813d1e4e21d0p-1,
    0x1.fffffep-1
  },
  { // Entry 1072
    -0x1.aed547dbee4d0d8680d0813d1e4e21d0p-1,
    -0x1.fffffep-1
  },
  { // Entry 1073
    0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    0x1.921fb6p-1
  },
  { // Entry 1074
    -0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    -0x1.921fb6p-1
  },
  { // Entry 1075
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 1076
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 1077
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 1078
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 1079
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 1080
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1081
    0x1.fffff7ffffffffffffffffffffffffffp-127,
    0x1.fffff8p-127
  },
  { // Entry 1082
    -0x1.fffff7ffffffffffffffffffffffffffp-127,
    -0x1.fffff8p-127
  },
  { // Entry 1083
    0x1.ffffffffffffffffffffffffffffffffp-149,
    0x1.p-148
  },
  { // Entry 1084
    -0x1.ffffffffffffffffffffffffffffffffp-149,
    -0x1.p-148
  },
  { // Entry 1085
    0.0f,
    0x1.p-149
  },
  { // Entry 1086
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1087
    0.0,
    0.0f
  },
  { // Entry 1088
    -0.0,
    -0.0f
  },
};

"""


```