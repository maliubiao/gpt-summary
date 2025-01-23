Response:
The user wants a summary of the functionality of the provided C code. This is the third part of a three-part request. I need to look at the structure of the data to infer its purpose.

The data is a C array of structures. Each structure contains two floating-point numbers. The file name suggests it's related to the `cosf` function and likely contains test data for Intel architecture.

Therefore, the functionality is to provide test input and expected output values for the `cosf` function.
这是一个C语言源代码文件，它定义了一个名为 `kCosfIntelData` 的常量数组。这个数组的元素是结构体，每个结构体包含两个 `double` 类型的浮点数。根据文件名 `cosf_intel_data.handroid` 以及之前的上下文（第 3 部分），可以推断出这个文件是为 `cosf` 函数提供测试数据，特别是针对 Intel 架构的 Android 平台。

**功能归纳:**

该文件的主要功能是提供了一系列预定义的输入和期望输出值，用于测试 `cosf` 函数在特定平台（Intel 架构的 Android）上的正确性。

**与 Android 功能的关系：**

* **测试框架:**  这个文件是 Android Bionic 库的测试套件的一部分。Android 系统需要确保其 C 库（Bionic）中的数学函数（如 `cosf`）在不同的硬件架构上都能正确运行。因此，会针对不同的架构（例如 Intel）提供特定的测试数据。
* **兼容性:** 通过使用这些测试数据，Android 开发者可以验证 Bionic 库在 Intel 设备上的 `cosf` 实现是否符合预期，确保应用程序在这些设备上的数学计算结果的准确性。

**libc 函数的功能实现：**

虽然这个文件本身不包含任何 libc 函数的实现代码，但它与 `cosf` 函数的功能测试直接相关。`cosf(float x)` 是一个标准 C 库函数，用于计算弧度值 `x` 的余弦值。

`cosf` 函数的实现通常基于以下方法：

1. **参数约减 (Argument Reduction):**  由于余弦函数是周期性的，可以使用三角恒等式将输入值 `x` 约减到一个较小的范围，通常是 `[0, π/2]`。这样可以减少后续计算的复杂性，并提高精度。例如，可以使用以下恒等式：
   * `cos(x + 2πn) = cos(x)`
   * `cos(-x) = cos(x)`
   * `cos(π - x) = -cos(x)`
   * `cos(π/2 - x) = sin(x)`

2. **泰勒级数展开 (Taylor Series Expansion):** 在约减后的范围内，可以使用泰勒级数来逼近余弦函数的值：
   ```
   cos(x) ≈ 1 - x^2/2! + x^4/4! - x^6/6! + ...
   ```
   为了保证精度，通常会计算足够多的项。

3. **查表法 (Look-up Table):** 对于一些实现，可能会使用一个预先计算好的余弦值表，然后通过插值来计算所需的精度。这通常用于一些嵌入式系统或者需要快速计算的场景。

4. **CORDIC 算法 (Coordinate Rotation Digital Computer):**  CORDIC 是一种迭代算法，可以通过一系列简单的移位和加减操作来计算三角函数。这种方法在硬件实现中很常见。

**dynamic linker 的功能和处理过程：**

这个代码文件与 dynamic linker 的功能没有直接关系。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载和链接共享库（.so 文件）。

**so 布局样本和链接处理过程：**

假设有一个使用了 `cosf` 函数的共享库 `libMyMath.so`。它的布局可能如下：

```
libMyMath.so:
  .text         # 包含函数代码，包括可能调用 cosf 的代码
  .rodata       # 包含只读数据，例如字符串常量
  .data         # 包含已初始化的全局变量
  .bss          # 包含未初始化的全局变量
  .dynsym       # 动态符号表，包含导出的和导入的符号
  .dynstr       # 动态字符串表，存储符号名称
  .plt          # 程序链接表，用于延迟绑定
  .got.plt      # 全局偏移表，存储外部符号的地址
```

**链接处理过程：**

1. **加载共享库：** 当应用程序启动并加载 `libMyMath.so` 时，dynamic linker 会将其加载到内存中的某个地址空间。
2. **解析依赖关系：** Dynamic linker 会检查 `libMyMath.so` 的依赖关系，找到它所依赖的其他共享库（例如 `libm.so`，其中包含 `cosf` 函数）。
3. **加载依赖库：** Dynamic linker 会加载 `libm.so` 到内存中。
4. **符号解析（重定位）：**
   * 当 `libMyMath.so` 中有代码调用 `cosf` 时，编译器会生成一个对外部符号 `cosf` 的引用。
   * Dynamic linker 会在 `libm.so` 的动态符号表 (`.dynsym`) 中查找 `cosf` 的定义。
   * 找到 `cosf` 的定义后，dynamic linker 会更新 `libMyMath.so` 的全局偏移表 (`.got.plt`) 中的相应条目，使其指向 `cosf` 函数在 `libm.so` 中的实际地址。这个过程称为重定位。
5. **延迟绑定（可选）：** 为了提高启动速度，Android 默认使用延迟绑定。这意味着只有在第一次调用 `cosf` 时，dynamic linker 才会解析其地址并更新 GOT 表。在首次调用前，PLT 表中的指令会将控制权转移给 dynamic linker 进行解析。

**逻辑推理、假设输入与输出：**

这个文件主要包含测试数据，其逻辑是针对特定的输入值，验证 `cosf` 函数的输出是否与预期的值相符。

**假设输入与输出示例 (从文件中选取):**

* **假设输入:** `0x1.fffffffffff76521249c74285bf73c07p-1` (这是一个十六进制浮点数表示法，大约等于 0.9999999999999998)
* **期望输出:** `0x1.921fb6p2` (大约等于 6.531854)  或者 `-0x1.921fb6p2` (大约等于 -6.531854)

这些数据点代表了 `cosf` 函数在特定输入下的预期行为。测试框架会用左边的值作为 `cosf` 的输入，然后比较其计算结果是否与右边的值（或其负值）在误差范围内一致。

**用户或编程常见的使用错误：**

* **输入角度单位错误：** `cosf` 函数接受的参数是弧度值，而不是角度值。如果用户传入的是角度值，会导致计算结果错误。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       float angle_degrees = 90.0f;
       // 错误的使用方式：直接将角度值传递给 cosf
       float result_wrong = cosf(angle_degrees);
       printf("cos(%f degrees) (wrong): %f\n", angle_degrees, result_wrong);

       // 正确的使用方式：将角度转换为弧度
       float angle_radians = angle_degrees * M_PI / 180.0f;
       float result_correct = cosf(angle_radians);
       printf("cos(%f degrees) (correct): %f\n", angle_degrees, result_correct);
       return 0;
   }
   ```
* **精度问题：**  `cosf` 返回的是单精度浮点数，在某些需要高精度的场景下可能会有误差。应该考虑使用 `cos` (double) 或其他高精度计算方法。
* **边界条件处理不当：**  对于一些特殊的输入值，例如非常大或非常小的数，可能会导致精度损失或溢出。开发者需要了解 `cosf` 的行为并进行适当的边界处理。

**Android framework or ndk 如何到达这里：**

1. **NDK 开发:** 开发者使用 Android NDK 编写 C/C++ 代码，其中可能调用了 `cosf` 函数。
   ```c++
   #include <cmath>

   float calculate_cosine(float angle) {
       return std::cosf(angle);
   }
   ```
2. **编译：** NDK 的编译器（例如 clang）会将 C/C++ 代码编译成目标平台的机器码，包括对 `cosf` 的调用。由于 `cosf` 是 libc 的一部分，编译器会生成对动态链接库 `libm.so` 中 `cosf` 符号的引用。
3. **打包成 APK/AAB：** 编译后的共享库会被打包到 APK 或 AAB 文件中。
4. **安装和加载：** 当应用安装到 Android 设备上后，操作系统会在应用启动时加载必要的共享库。
5. **Dynamic Linker 介入：** Android 的 dynamic linker (linker64 或 linker) 会负责加载 `libm.so` 和应用自身的共享库，并解析 `cosf` 等符号的地址。
6. **执行 `cosf`:** 当应用程序执行到调用 `cosf` 的代码时，实际上会跳转到 `libm.so` 中 `cosf` 函数的实现。
7. **测试（可选但重要）：** 在 Android 系统开发或 Bionic 库的开发过程中，会使用类似 `cosf_intel_data.handroid` 这样的测试数据来验证 `cosf` 函数在不同平台上的正确性。这些测试通常在 Android 的编译和测试流程中运行。

**Frida Hook 示例调试：**

可以使用 Frida hook `cosf` 函数来观察其输入输出，验证测试数据的有效性或排查问题。

```python
import frida
import sys

package_name = "your.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please ensure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "cosf"), {
    onEnter: function(args) {
        var input = args[0];
        console.log("[*] cosf called with input: " + input);
        this.input = input;
    },
    onLeave: function(retval) {
        console.log("[*] cosf returned: " + retval);
        send({"input": this.input.toString(), "output": retval.toString()});
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用包名。**
3. **定义消息处理函数 `on_message`，用于打印 hook 的信息。**
4. **连接到 USB 设备并附加到目标进程。**
5. **编写 Frida script:**
   * 使用 `Interceptor.attach` hook `libm.so` 中的 `cosf` 函数。
   * `onEnter` 函数在 `cosf` 函数被调用时执行，记录输入参数。
   * `onLeave` 函数在 `cosf` 函数返回时执行，记录返回值，并使用 `send` 函数将输入和输出发送到 Python 脚本。
6. **创建并加载 Frida script。**
7. **保持脚本运行，直到手动停止。**

运行此脚本后，当目标应用调用 `cosf` 函数时，Frida 会拦截调用并打印输入和输出值，可以用来验证 `cosf_intel_data.handroid` 中的数据是否与实际运行时的行为一致。

**总结:**

总而言之， `bionic/tests/math_data/cosf_intel_data.handroid` 这个源代码文件是 Android Bionic 库中用于测试 `cosf` 函数在 Intel 架构上正确性的测试数据集合。它包含了预定义的输入和期望输出值，用于确保 Android 系统在 Intel 设备上进行余弦计算的准确性。虽然它本身不涉及 libc 函数的实现或 dynamic linker 的操作，但它是 Bionic 数学库测试的重要组成部分，对于保证 Android 平台的兼容性和稳定性至关重要。

### 提示词
```
这是目录为bionic/tests/math_data/cosf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
e8deeb97p-1,
    -0x1.921fb4p2
  },
  { // Entry 765
    0x1.fffffffffff76521249c74285bf73c07p-1,
    0x1.921fb6p2
  },
  { // Entry 766
    0x1.fffffffffff76521249c74285bf73c07p-1,
    -0x1.921fb6p2
  },
  { // Entry 767
    0x1.ffffffffff8875d585b6db2c31711004p-1,
    0x1.921fb8p2
  },
  { // Entry 768
    0x1.ffffffffff8875d585b6db2c31711004p-1,
    -0x1.921fb8p2
  },
  { // Entry 769
    0x1.ffffffffff9951b30e084a6a993b8675p-1,
    0x1.921fb4p3
  },
  { // Entry 770
    0x1.ffffffffff9951b30e084a6a993b8675p-1,
    -0x1.921fb4p3
  },
  { // Entry 771
    0x1.ffffffffffdd94849271d0eb7b7b884bp-1,
    0x1.921fb6p3
  },
  { // Entry 772
    0x1.ffffffffffdd94849271d0eb7b7b884bp-1,
    -0x1.921fb6p3
  },
  { // Entry 773
    0x1.fffffffffe21d75616dba48283d3c2f7p-1,
    0x1.921fb8p3
  },
  { // Entry 774
    0x1.fffffffffe21d75616dba48283d3c2f7p-1,
    -0x1.921fb8p3
  },
  { // Entry 775
    0x1.fffffffffe6546cc382152d9c0eb9b47p-1,
    0x1.921fb4p4
  },
  { // Entry 776
    0x1.fffffffffe6546cc382152d9c0eb9b47p-1,
    -0x1.921fb4p4
  },
  { // Entry 777
    0x1.ffffffffff76521249c7484ea7d7a409p-1,
    0x1.921fb6p4
  },
  { // Entry 778
    0x1.ffffffffff76521249c7484ea7d7a409p-1,
    -0x1.921fb6p4
  },
  { // Entry 779
    0x1.fffffffff8875d585b720f25f0473943p-1,
    0x1.921fb8p4
  },
  { // Entry 780
    0x1.fffffffff8875d585b720f25f0473943p-1,
    -0x1.921fb8p4
  },
  { // Entry 781
    0x1.fffffffff9951b30e087de5cc38683b8p-1,
    0x1.921fb4p5
  },
  { // Entry 782
    0x1.fffffffff9951b30e087de5cc38683b8p-1,
    -0x1.921fb4p5
  },
  { // Entry 783
    0x1.fffffffffdd94849271d6b463df6bddfp-1,
    0x1.921fb6p5
  },
  { // Entry 784
    0x1.fffffffffdd94849271d6b463df6bddfp-1,
    -0x1.921fb6p5
  },
  { // Entry 785
    0x1.ffffffffe21d75616e000e55d09f8757p-1,
    0x1.921fb8p5
  },
  { // Entry 786
    0x1.ffffffffe21d75616e000e55d09f8757p-1,
    -0x1.921fb8p5
  },
  { // Entry 787
    0x1.ffffffffe6546cc38248a8cf0b9b5795p-1,
    0x1.921fb4p6
  },
  { // Entry 788
    0x1.ffffffffe6546cc38248a8cf0b9b5795p-1,
    -0x1.921fb4p6
  },
  { // Entry 789
    0x1.fffffffff76521249c7a4dd2e15dd1c4p-1,
    0x1.921fb6p6
  },
  { // Entry 790
    0x1.fffffffff76521249c7a4dd2e15dd1c4p-1,
    -0x1.921fb6p6
  },
  { // Entry 791
    0x1.ffffffff8875d585bb7d55383a9b39a4p-1,
    0x1.921fb8p6
  },
  { // Entry 792
    0x1.ffffffff8875d585bb7d55383a9b39a4p-1,
    -0x1.921fb8p6
  },
  { // Entry 793
    0x1.ffffffff9951b30e0bb598fc0679a6f7p-1,
    0x1.921fb4p7
  },
  { // Entry 794
    0x1.ffffffff9951b30e0bb598fc0679a6f7p-1,
    -0x1.921fb4p7
  },
  { // Entry 795
    0x1.ffffffffdd948492723342ea1da49bacp-1,
    0x1.921fb6p7
  },
  { // Entry 796
    0x1.ffffffffdd948492723342ea1da49bacp-1,
    -0x1.921fb6p7
  },
  { // Entry 797
    0x1.fffffffe21d7561725c712f068fc9718p-1,
    0x1.921fb8p7
  },
  { // Entry 798
    0x1.fffffffe21d7561725c712f068fc9718p-1,
    -0x1.921fb8p7
  },
  { // Entry 799
    -0x1.6a09db3bdba0868a31e766359a8406cap-1,
    0x1.2d97c4p1
  },
  { // Entry 800
    -0x1.6a09db3bdba0868a31e766359a8406cap-1,
    -0x1.2d97c4p1
  },
  { // Entry 801
    -0x1.6a09e0e4035b86694c16534e42fbe111p-1,
    0x1.2d97c6p1
  },
  { // Entry 802
    -0x1.6a09e0e4035b86694c16534e42fbe111p-1,
    -0x1.2d97c6p1
  },
  { // Entry 803
    -0x1.6a09e68c2affe5aa58050accb05c6248p-1,
    0x1.2d97c8p1
  },
  { // Entry 804
    -0x1.6a09e68c2affe5aa58050accb05c6248p-1,
    -0x1.2d97c8p1
  },
  { // Entry 805
    -0x1.6a09edb67706e0997121d12a0c87bae8p-1,
    0x1.f6a7a0p1
  },
  { // Entry 806
    -0x1.6a09edb67706e0997121d12a0c87bae8p-1,
    -0x1.f6a7a0p1
  },
  { // Entry 807
    -0x1.6a09e80e4f7f2a88debed37faa93e8c8p-1,
    0x1.f6a7a2p1
  },
  { // Entry 808
    -0x1.6a09e80e4f7f2a88debed37faa93e8c8p-1,
    -0x1.f6a7a2p1
  },
  { // Entry 809
    -0x1.6a09e26627e0d3d9cb76de00cb902becp-1,
    0x1.f6a7a4p1
  },
  { // Entry 810
    -0x1.6a09e26627e0d3d9cb76de00cb902becp-1,
    -0x1.f6a7a4p1
  },
  { // Entry 811
    -0x1.f9990e91a74168b90bd68dfab775c9cap-21,
    0x1.2d97c4p2
  },
  { // Entry 812
    -0x1.f9990e91a74168b90bd68dfab775c9cap-21,
    -0x1.2d97c4p2
  },
  { // Entry 813
    -0x1.f3321d234f1363d187dd09528b67b215p-22,
    0x1.2d97c6p2
  },
  { // Entry 814
    -0x1.f3321d234f1363d187dd09528b67b215p-22,
    -0x1.2d97c6p2
  },
  { // Entry 815
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    0x1.2d97c8p2
  },
  { // Entry 816
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    -0x1.2d97c8p2
  },
  { // Entry 817
    0x1.6a09d7a6b572c2c824d137d0405d8188p-1,
    0x1.5fdbbcp2
  },
  { // Entry 818
    0x1.6a09d7a6b572c2c824d137d0405d8188p-1,
    -0x1.5fdbbcp2
  },
  { // Entry 819
    0x1.6a09e2f704eecb181e3f5ece9be0ca0fp-1,
    0x1.5fdbbep2
  },
  { // Entry 820
    0x1.6a09e2f704eecb181e3f5ece9be0ca0fp-1,
    -0x1.5fdbbep2
  },
  { // Entry 821
    0x1.6a09ee47541050ef59ec4bfce935cc1ap-1,
    0x1.5fdbc0p2
  },
  { // Entry 822
    0x1.6a09ee47541050ef59ec4bfce935cc1ap-1,
    -0x1.5fdbc0p2
  },
  { // Entry 823
    0x1.6a09fc9bebaba208c81ec0b1cd307589p-1,
    0x1.c463a8p2
  },
  { // Entry 824
    0x1.6a09fc9bebaba208c81ec0b1cd307589p-1,
    -0x1.c463a8p2
  },
  { // Entry 825
    0x1.6a09f14b9cfcc0f6227d386cc3704a05p-1,
    0x1.c463aap2
  },
  { // Entry 826
    0x1.6a09f14b9cfcc0f6227d386cc3704a05p-1,
    -0x1.c463aap2
  },
  { // Entry 827
    0x1.6a09e5fb4df35d6729f472da3413e404p-1,
    0x1.c463acp2
  },
  { // Entry 828
    0x1.6a09e5fb4df35d6729f472da3413e404p-1,
    -0x1.c463acp2
  },
  { // Entry 829
    0x1.4aa9c2f2c1defb8728f0d2da1217aae1p-21,
    0x1.f6a7a0p2
  },
  { // Entry 830
    0x1.4aa9c2f2c1defb8728f0d2da1217aae1p-21,
    -0x1.f6a7a0p2
  },
  { // Entry 831
    0x1.2aa70bcb07d6d0f36b777cb380a845d9p-23,
    0x1.f6a7a2p2
  },
  { // Entry 832
    0x1.2aa70bcb07d6d0f36b777cb380a845d9p-23,
    -0x1.f6a7a2p2
  },
  { // Entry 833
    -0x1.6aac7a1a7c0c7afc5fcb2313a7eca229p-22,
    0x1.f6a7a4p2
  },
  { // Entry 834
    -0x1.6aac7a1a7c0c7afc5fcb2313a7eca229p-22,
    -0x1.f6a7a4p2
  },
  { // Entry 835
    -0x1.6a09c8c13f48b7aad851f9d6474bcb31p-1,
    0x1.1475cap3
  },
  { // Entry 836
    -0x1.6a09c8c13f48b7aad851f9d6474bcb31p-1,
    -0x1.1475cap3
  },
  { // Entry 837
    -0x1.6a09df61ded49d1ee4fca4ba6140d179p-1,
    0x1.1475ccp3
  },
  { // Entry 838
    -0x1.6a09df61ded49d1ee4fca4ba6140d179p-1,
    -0x1.1475ccp3
  },
  { // Entry 839
    -0x1.6a09f6027cf678b38fc8992cd9990302p-1,
    0x1.1475cep3
  },
  { // Entry 840
    -0x1.6a09f6027cf678b38fc8992cd9990302p-1,
    -0x1.1475cep3
  },
  { // Entry 841
    -0x1.fffffffffc1972c902ef31c37cb54817p-1,
    0x1.2d97c4p3
  },
  { // Entry 842
    -0x1.fffffffffc1972c902ef31c37cb54817p-1,
    -0x1.2d97c4p3
  },
  { // Entry 843
    -0x1.ffffffffff0ca4e6263d27a0204389dfp-1,
    0x1.2d97c6p3
  },
  { // Entry 844
    -0x1.ffffffffff0ca4e6263d27a0204389dfp-1,
    -0x1.2d97c6p3
  },
  { // Entry 845
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    0x1.2d97c8p3
  },
  { // Entry 846
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    -0x1.2d97c8p3
  },
  { // Entry 847
    -0x1.6a0a0b815fb37b2d01551e07cb3009d1p-1,
    0x1.46b9c0p3
  },
  { // Entry 848
    -0x1.6a0a0b815fb37b2d01551e07cb3009d1p-1,
    -0x1.46b9c0p3
  },
  { // Entry 849
    -0x1.6a09f4e0c2e98deb78642b6032a73d46p-1,
    0x1.46b9c2p3
  },
  { // Entry 850
    -0x1.6a09f4e0c2e98deb78642b6032a73d46p-1,
    -0x1.46b9c2p3
  },
  { // Entry 851
    -0x1.6a09de4024b596b50eb06d562db8c777p-1,
    0x1.46b9c4p3
  },
  { // Entry 852
    -0x1.6a09de4024b596b50eb06d562db8c777p-1,
    -0x1.46b9c4p3
  },
  { // Entry 853
    -0x1.4ddd3ba9edcd898b9946fdd20af22a68p-20,
    0x1.5fdbbcp3
  },
  { // Entry 854
    -0x1.4ddd3ba9edcd898b9946fdd20af22a68p-20,
    -0x1.5fdbbcp3
  },
  { // Entry 855
    -0x1.3774eea7b8abe8fa8c380142b97af4b6p-22,
    0x1.5fdbbep3
  },
  { // Entry 856
    -0x1.3774eea7b8abe8fa8c380142b97af4b6p-22,
    -0x1.5fdbbep3
  },
  { // Entry 857
    0x1.644588ac238ae493fa32435ba51329bfp-21,
    0x1.5fdbc0p3
  },
  { // Entry 858
    0x1.644588ac238ae493fa32435ba51329bfp-21,
    -0x1.5fdbc0p3
  },
  { // Entry 859
    0x1.6a09b9dbc881c458e747908caf2aa5e1p-1,
    0x1.78fdb6p3
  },
  { // Entry 860
    0x1.6a09b9dbc881c458e747908caf2aa5e1p-1,
    -0x1.78fdb6p3
  },
  { // Entry 861
    0x1.6a09d07c68fc010ffcfd3b19f1ee4f44p-1,
    0x1.78fdb8p3
  },
  { // Entry 862
    0x1.6a09d07c68fc010ffcfd3b19f1ee4f44p-1,
    -0x1.78fdb8p3
  },
  { // Entry 863
    0x1.6a09e71d080c33f6964a07d1a0bf5980p-1,
    0x1.78fdbap3
  },
  { // Entry 864
    0x1.6a09e71d080c33f6964a07d1a0bf5980p-1,
    -0x1.78fdbap3
  },
  { // Entry 865
    0x1.6a0a03c63742d62802d163d5cfb3b7d5p-1,
    0x1.ab41aep3
  },
  { // Entry 866
    0x1.6a0a03c63742d62802d163d5cfb3b7d5p-1,
    -0x1.ab41aep3
  },
  { // Entry 867
    0x1.6a09ed2599fd364c97660cca6652c0a3p-1,
    0x1.ab41b0p3
  },
  { // Entry 868
    0x1.6a09ed2599fd364c97660cca6652c0a3p-1,
    -0x1.ab41b0p3
  },
  { // Entry 869
    0x1.6a09d684fb4d8c840660d6b42ec83039p-1,
    0x1.ab41b2p3
  },
  { // Entry 870
    0x1.6a09d684fb4d8c840660d6b42ec83039p-1,
    -0x1.ab41b2p3
  },
  { // Entry 871
    0x1.f66595da7a1ae308d26a18de4c2ed3a3p-20,
    0x1.c463a8p3
  },
  { // Entry 872
    0x1.f66595da7a1ae308d26a18de4c2ed3a3p-20,
    -0x1.c463a8p3
  },
  { // Entry 873
    0x1.eccb2bb4f66ea861241fa09ca9d8a034p-21,
    0x1.c463aap3
  },
  { // Entry 874
    0x1.eccb2bb4f66ea861241fa09ca9d8a034p-21,
    -0x1.c463aap3
  },
  { // Entry 875
    -0x1.334d44b0945407b118b361ab78171f67p-25,
    0x1.c463acp3
  },
  { // Entry 876
    -0x1.334d44b0945407b118b361ab78171f67p-25,
    -0x1.c463acp3
  },
  { // Entry 877
    -0x1.6a09c196f2867cc916ae2b7e6c9d99c1p-1,
    0x1.dd85a4p3
  },
  { // Entry 878
    -0x1.6a09c196f2867cc916ae2b7e6c9d99c1p-1,
    -0x1.dd85a4p3
  },
  { // Entry 879
    -0x1.6a09d837928506f7cff76f094b4e0377p-1,
    0x1.dd85a6p3
  },
  { // Entry 880
    -0x1.6a09d837928506f7cff76f094b4e0377p-1,
    -0x1.dd85a6p3
  },
  { // Entry 881
    -0x1.6a09eed83119874e51ae4bb8aeddc1f2p-1,
    0x1.dd85a8p3
  },
  { // Entry 882
    -0x1.6a09eed83119874e51ae4bb8aeddc1f2p-1,
    -0x1.dd85a8p3
  },
  { // Entry 883
    -0x1.fffffffffe54e5e4d32b3453166060b3p-1,
    0x1.f6a7a0p3
  },
  { // Entry 884
    -0x1.fffffffffe54e5e4d32b3453166060b3p-1,
    -0x1.f6a7a0p3
  },
  { // Entry 885
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    0x1.f6a7a2p3
  },
  { // Entry 886
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    -0x1.f6a7a2p3
  },
  { // Entry 887
    -0x1.ffffffffff7f8cf09e32d6309bea85cap-1,
    0x1.f6a7a4p3
  },
  { // Entry 888
    -0x1.ffffffffff7f8cf09e32d6309bea85cap-1,
    -0x1.f6a7a4p3
  },
  { // Entry 889
    -0x1.6a0a294c45ec747a47711a4994d2c5e4p-1,
    0x1.07e4ccp4
  },
  { // Entry 890
    -0x1.6a0a294c45ec747a47711a4994d2c5e4p-1,
    -0x1.07e4ccp4
  },
  { // Entry 891
    -0x1.6a09fc0b0ea7ed9fb5dd50a0c8af19cbp-1,
    0x1.07e4cep4
  },
  { // Entry 892
    -0x1.6a09fc0b0ea7ed9fb5dd50a0c8af19cbp-1,
    -0x1.07e4cep4
  },
  { // Entry 893
    -0x1.6a09cec9d1bb3ed4f810c9f9786d610ep-1,
    0x1.07e4d0p4
  },
  { // Entry 894
    -0x1.6a09cec9d1bb3ed4f810c9f9786d610ep-1,
    -0x1.07e4d0p4
  },
  { // Entry 895
    -0x1.4f76f80582c73fc0cc0903ed8ca7d6b3p-19,
    0x1.1475cap4
  },
  { // Entry 896
    -0x1.4f76f80582c73fc0cc0903ed8ca7d6b3p-19,
    -0x1.1475cap4
  },
  { // Entry 897
    -0x1.3ddbe0161108b690eed70a7f59de751cp-21,
    0x1.1475ccp4
  },
  { // Entry 898
    -0x1.3ddbe0161108b690eed70a7f59de751cp-21,
    -0x1.1475ccp4
  },
  { // Entry 899
    0x1.61120ff4f70180b0d55c3ae0f69585cap-20,
    0x1.1475cep4
  },
  { // Entry 900
    0x1.61120ff4f70180b0d55c3ae0f69585cap-20,
    -0x1.1475cep4
  },
  { // Entry 901
    0x1.6a09b2b17b741050a6cfd64b81c76485p-1,
    0x1.2106c8p4
  },
  { // Entry 902
    0x1.6a09b2b17b741050a6cfd64b81c76485p-1,
    -0x1.2106c8p4
  },
  { // Entry 903
    0x1.6a09dff2bbe3c9616a3576c55e773207p-1,
    0x1.2106cap4
  },
  { // Entry 904
    0x1.6a09dff2bbe3c9616a3576c55e773207p-1,
    -0x1.2106cap4
  },
  { // Entry 905
    0x1.6a0a0d33f6ab5af262ad6ad18ac1ce9fp-1,
    0x1.2106ccp4
  },
  { // Entry 906
    0x1.6a0a0d33f6ab5af262ad6ad18ac1ce9fp-1,
    -0x1.2106ccp4
  },
  { // Entry 907
    0x1.fffffffff065cb240bcbfdff4977ddf8p-1,
    0x1.2d97c4p4
  },
  { // Entry 908
    0x1.fffffffff065cb240bcbfdff4977ddf8p-1,
    -0x1.2d97c4p4
  },
  { // Entry 909
    0x1.fffffffffc32939898f585d6948cf2d1p-1,
    0x1.2d97c6p4
  },
  { // Entry 910
    0x1.fffffffffc32939898f585d6948cf2d1p-1,
    -0x1.2d97c6p4
  },
  { // Entry 911
    0x1.ffffffffffff5c0d2630ee0a27e8d6d1p-1,
    0x1.2d97c8p4
  },
  { // Entry 912
    0x1.ffffffffffff5c0d2630ee0a27e8d6d1p-1,
    -0x1.2d97c8p4
  },
  { // Entry 913
    0x1.6a0a3831b81d94966ad8df4d378824f9p-1,
    0x1.3a28c2p4
  },
  { // Entry 914
    0x1.6a0a3831b81d94966ad8df4d378824f9p-1,
    -0x1.3a28c2p4
  },
  { // Entry 915
    0x1.6a0a0af082b5bca7f5569f4da6883f64p-1,
    0x1.3a28c4p4
  },
  { // Entry 916
    0x1.6a0a0af082b5bca7f5569f4da6883f64p-1,
    -0x1.3a28c4p4
  },
  { // Entry 917
    0x1.6a09ddaf47a5bc8dbdcb6b13844902aep-1,
    0x1.3a28c6p4
  },
  { // Entry 918
    0x1.6a09ddaf47a5bc8dbdcb6b13844902aep-1,
    -0x1.3a28c6p4
  },
  { // Entry 919
    0x1.a3bb251dc7efaa1e2137bb37ed6654dbp-19,
    0x1.46b9c0p4
  },
  { // Entry 920
    0x1.a3bb251dc7efaa1e2137bb37ed6654dbp-19,
    -0x1.46b9c0p4
  },
  { // Entry 921
    0x1.47764a3b9566758e5baa2e3029f1abbap-20,
    0x1.46b9c2p4
  },
  { // Entry 922
    0x1.47764a3b9566758e5baa2e3029f1abbap-20,
    -0x1.46b9c2p4
  },
  { // Entry 923
    -0x1.71136b88d4608490f2ddfe90101112aep-21,
    0x1.46b9c4p4
  },
  { // Entry 924
    -0x1.71136b88d4608490f2ddfe90101112aep-21,
    -0x1.46b9c4p4
  },
  { // Entry 925
    -0x1.6a09a3cc03c4bbad2222dfe5be317565p-1,
    0x1.534abep4
  },
  { // Entry 926
    -0x1.6a09a3cc03c4bbad2222dfe5be317565p-1,
    -0x1.534abep4
  },
  { // Entry 927
    -0x1.6a09d10d46112335d0e43d738387de8cp-1,
    0x1.534ac0p4
  },
  { // Entry 928
    -0x1.6a09d10d46112335d0e43d738387de8cp-1,
    -0x1.534ac0p4
  },
  { // Entry 929
    -0x1.6a09fe4e82b5637a4a8f392c3301be94p-1,
    0x1.534ac2p4
  },
  { // Entry 930
    -0x1.6a09fe4e82b5637a4a8f392c3301be94p-1,
    -0x1.534ac2p4
  },
  { // Entry 931
    -0x1.fffffffff9325ace5f682bbb8b122a09p-1,
    0x1.5fdbbcp4
  },
  { // Entry 932
    -0x1.fffffffff9325ace5f682bbb8b122a09p-1,
    -0x1.5fdbbcp4
  },
  { // Entry 933
    -0x1.ffffffffffa144abaed5b4aab880635dp-1,
    0x1.5fdbbep4
  },
  { // Entry 934
    -0x1.ffffffffffa144abaed5b4aab880635dp-1,
    -0x1.5fdbbep4
  },
  { // Entry 935
    -0x1.fffffffffe102e88fe476331e1ddefafp-1,
    0x1.5fdbc0p4
  },
  { // Entry 936
    -0x1.fffffffffe102e88fe476331e1ddefafp-1,
    -0x1.5fdbc0p4
  },
  { // Entry 937
    -0x1.6a0a19d5f626a35ee112a34638e07808p-1,
    0x1.6c6cbap4
  },
  { // Entry 938
    -0x1.6a0a19d5f626a35ee112a34638e07808p-1,
    -0x1.6c6cbap4
  },
  { // Entry 939
    -0x1.6a09ec94bcf35208ccd030684d5ddd9cp-1,
    0x1.6c6cbcp4
  },
  { // Entry 940
    -0x1.6a09ec94bcf35208ccd030684d5ddd9cp-1,
    -0x1.6c6cbcp4
  },
  { // Entry 941
    -0x1.6a09bf537e17d900659bd2fa24c3a8c8p-1,
    0x1.6c6cbep4
  },
  { // Entry 942
    -0x1.6a09bf537e17d900659bd2fa24c3a8c8p-1,
    -0x1.6c6cbep4
  },
  { // Entry 943
    -0x1.f7ff52360c622b3f94d9c7250bfad8d4p-19,
    0x1.78fdb6p4
  },
  { // Entry 944
    -0x1.f7ff52360c622b3f94d9c7250bfad8d4p-19,
    -0x1.78fdb6p4
  },
  { // Entry 945
    -0x1.effea46c21baa3da7c266c953a013598p-20,
    0x1.78fdb8p4
  },
  { // Entry 946
    -0x1.effea46c21baa3da7c266c953a013598p-20,
    -0x1.78fdb8p4
  },
  { // Entry 947
    0x1.0015b93dd0f095be1eb0a5b87fe5e33ep-24,
    0x1.78fdbap4
  },
  { // Entry 948
    0x1.0015b93dd0f095be1eb0a5b87fe5e33ep-24,
    -0x1.78fdbap4
  },
  { // Entry 949
    0x1.6a0994e68b787ee4fd6830b288225745p-1,
    0x1.858eb4p4
  },
  { // Entry 950
    0x1.6a0994e68b787ee4fd6830b288225745p-1,
    -0x1.858eb4p4
  },
  { // Entry 951
    0x1.6a09c227cfa194d1fa7ab9909de5083cp-1,
    0x1.858eb6p4
  },
  { // Entry 952
    0x1.6a09c227cfa194d1fa7ab9909de5083cp-1,
    -0x1.858eb6p4
  },
  { // Entry 953
    0x1.6a09ef690e2283b658509ed319483839p-1,
    0x1.858eb8p4
  },
  { // Entry 954
    0x1.6a09ef690e2283b658509ed319483839p-1,
    -0x1.858eb8p4
  },
  { // Entry 955
    -0x1.f3957bad70e0741f1d3d6751246ce21ap-1,
    0x1.fffffep62
  },
  { // Entry 956
    -0x1.f3957bad70e0741f1d3d6751246ce21ap-1,
    -0x1.fffffep62
  },
  { // Entry 957
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    0x1.p63
  },
  { // Entry 958
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    -0x1.p63
  },
  { // Entry 959
    0x1.945e6c69a580fb7bb27d02c0fe0f8a71p-2,
    0x1.000002p63
  },
  { // Entry 960
    0x1.945e6c69a580fb7bb27d02c0fe0f8a71p-2,
    -0x1.000002p63
  },
  { // Entry 961
    -0x1.b2d255f2bd0423e29e2a548728f034abp-1,
    0x1.fffffep26
  },
  { // Entry 962
    -0x1.b2d255f2bd0423e29e2a548728f034abp-1,
    -0x1.fffffep26
  },
  { // Entry 963
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    0x1.p27
  },
  { // Entry 964
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    -0x1.p27
  },
  { // Entry 965
    -0x1.ad3d80c82f4452b076581de24648435bp-1,
    0x1.000002p27
  },
  { // Entry 966
    -0x1.ad3d80c82f4452b076581de24648435bp-1,
    -0x1.000002p27
  },
  { // Entry 967
    -0x1.4532c3721ed4343ad88eea8908a988cbp-2,
    0x1.fffffep23
  },
  { // Entry 968
    -0x1.4532c3721ed4343ad88eea8908a988cbp-2,
    -0x1.fffffep23
  },
  { // Entry 969
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    0x1.p24
  },
  { // Entry 970
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    -0x1.p24
  },
  { // Entry 971
    0x1.caf8537c3e442ca8aca86c156773853ap-2,
    0x1.000002p24
  },
  { // Entry 972
    0x1.caf8537c3e442ca8aca86c156773853ap-2,
    -0x1.000002p24
  },
  { // Entry 973
    -0x1.4eaa667ba0b90dfb05ab3d9c247cdee7p-1,
    0x1.fffffep1
  },
  { // Entry 974
    -0x1.4eaa667ba0b90dfb05ab3d9c247cdee7p-1,
    -0x1.fffffep1
  },
  { // Entry 975
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    0x1.p2
  },
  { // Entry 976
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    -0x1.p2
  },
  { // Entry 977
    -0x1.4eaa5451d53348eb89dc478d4d11be02p-1,
    0x1.000002p2
  },
  { // Entry 978
    -0x1.4eaa5451d53348eb89dc478d4d11be02p-1,
    -0x1.000002p2
  },
  { // Entry 979
    -0x1.aa225e2ef96241915b6fd217522814f5p-2,
    0x1.fffffep0
  },
  { // Entry 980
    -0x1.aa225e2ef96241915b6fd217522814f5p-2,
    -0x1.fffffep0
  },
  { // Entry 981
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    0x1.p1
  },
  { // Entry 982
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    -0x1.p1
  },
  { // Entry 983
    -0x1.aa227401b288620a0372d5a96084915dp-2,
    0x1.000002p1
  },
  { // Entry 984
    -0x1.aa227401b288620a0372d5a96084915dp-2,
    -0x1.000002p1
  },
  { // Entry 985
    0x1.14a282aa25b11f6312a7a65180e7c3d4p-1,
    0x1.fffffep-1
  },
  { // Entry 986
    0x1.14a282aa25b11f6312a7a65180e7c3d4p-1,
    -0x1.fffffep-1
  },
  { // Entry 987
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.p0
  },
  { // Entry 988
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.p0
  },
  { // Entry 989
    0x1.14a27d9da5d4aebce71428f9057b08dap-1,
    0x1.000002p0
  },
  { // Entry 990
    0x1.14a27d9da5d4aebce71428f9057b08dap-1,
    -0x1.000002p0
  },
  { // Entry 991
    0x1.c15280e0737692dd436908fdc8e6e2e1p-1,
    0x1.fffffep-2
  },
  { // Entry 992
    0x1.c15280e0737692dd436908fdc8e6e2e1p-1,
    -0x1.fffffep-2
  },
  { // Entry 993
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    0x1.p-1
  },
  { // Entry 994
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    -0x1.p-1
  },
  { // Entry 995
    0x1.c1527f70409076da0c3204df1e099a83p-1,
    0x1.000002p-1
  },
  { // Entry 996
    0x1.c1527f70409076da0c3204df1e099a83p-1,
    -0x1.000002p-1
  },
  { // Entry 997
    0x1.f0154a1789d8dcc172cd2092d05f6394p-1,
    0x1.fffffep-3
  },
  { // Entry 998
    0x1.f0154a1789d8dcc172cd2092d05f6394p-1,
    -0x1.fffffep-3
  },
  { // Entry 999
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    0x1.p-2
  },
  { // Entry 1000
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    -0x1.p-2
  },
  { // Entry 1001
    0x1.f01549b8890c2f66337cac15a7237c8ep-1,
    0x1.000002p-2
  },
  { // Entry 1002
    0x1.f01549b8890c2f66337cac15a7237c8ep-1,
    -0x1.000002p-2
  },
  { // Entry 1003
    0x1.fc01552fd068ee83f5b742c05245e8b2p-1,
    0x1.fffffep-4
  },
  { // Entry 1004
    0x1.fc01552fd068ee83f5b742c05245e8b2p-1,
    -0x1.fffffep-4
  },
  { // Entry 1005
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    0x1.p-3
  },
  { // Entry 1006
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    -0x1.p-3
  },
  { // Entry 1007
    0x1.fc015517e065afb6bb102c18f5919820p-1,
    0x1.000002p-3
  },
  { // Entry 1008
    0x1.fc015517e065afb6bb102c18f5919820p-1,
    -0x1.000002p-3
  },
  { // Entry 1009
    0x1.ff0015569ef7e2b96301e6f752c019d4p-1,
    0x1.fffffep-5
  },
  { // Entry 1010
    0x1.ff0015569ef7e2b96301e6f752c019d4p-1,
    -0x1.fffffep-5
  },
  { // Entry 1011
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    0x1.p-4
  },
  { // Entry 1012
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    -0x1.p-4
  },
  { // Entry 1013
    0x1.ff0015509ff7d2ee6418e924f0de5e97p-1,
    0x1.000002p-4
  },
  { // Entry 1014
    0x1.ff0015509ff7d2ee6418e924f0de5e97p-1,
    -0x1.000002p-4
  },
  { // Entry 1015
    0x1.ffc00155d277d58e727cd95c43f759cfp-1,
    0x1.fffffep-6
  },
  { // Entry 1016
    0x1.ffc00155d277d58e727cd95c43f759cfp-1,
    -0x1.fffffep-6
  },
  { // Entry 1017
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    0x1.p-5
  },
  { // Entry 1018
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    -0x1.p-5
  },
  { // Entry 1019
    0x1.ffc001545287d49b57972af5145663a0p-1,
    0x1.000002p-5
  },
  { // Entry 1020
    0x1.ffc001545287d49b57972af5145663a0p-1,
    -0x1.000002p-5
  },
  { // Entry 1021
    0x1.fff0001575499f3d7996e2da11cdeb24p-1,
    0x1.fffffep-7
  },
  { // Entry 1022
    0x1.fff0001575499f3d7996e2da11cdeb24p-1,
    -0x1.fffffep-7
  },
  { // Entry 1023
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    0x1.p-6
  },
  { // Entry 1024
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    -0x1.p-6
  },
  { // Entry 1025
    0x1.fff00015154a9f0cae4a62151501cd0ap-1,
    0x1.000002p-6
  },
  { // Entry 1026
    0x1.fff00015154a9f0cae4a62151501cd0ap-1,
    -0x1.000002p-6
  },
  { // Entry 1027
    0x1.fffffff0000020155544fff49fca38e6p-1,
    0x1.fffffep-15
  },
  { // Entry 1028
    0x1.fffffff0000020155544fff49fca38e6p-1,
    -0x1.fffffep-15
  },
  { // Entry 1029
    0x1.fffffff00000001555555549f49f49f7p-1,
    0x1.p-14
  },
  { // Entry 1030
    0x1.fffffff00000001555555549f49f49f7p-1,
    -0x1.p-14
  },
  { // Entry 1031
    0x1.ffffffefffffc0155515fff4a1496c1cp-1,
    0x1.000002p-14
  },
  { // Entry 1032
    0x1.ffffffefffffc0155515fff4a1496c1cp-1,
    -0x1.000002p-14
  },
  { // Entry 1033
    0x1.fffffffffffffc000007fffffc015555p-1,
    0x1.fffffep-28
  },
  { // Entry 1034
    0x1.fffffffffffffc000007fffffc015555p-1,
    -0x1.fffffep-28
  },
  { // Entry 1035
    0x1.fffffffffffffc000000000000015555p-1,
    0x1.p-27
  },
  { // Entry 1036
    0x1.fffffffffffffc000000000000015555p-1,
    -0x1.p-27
  },
  { // Entry 1037
    0x1.fffffffffffffbffffeffffff0015555p-1,
    0x1.000002p-27
  },
  { // Entry 1038
    0x1.fffffffffffffbffffeffffff0015555p-1,
    -0x1.000002p-27
  },
  { // Entry 1039
    0x1.fffffffffffffff000001ffffff00015p-1,
    0x1.fffffep-31
  },
  { // Entry 1040
    0x1.fffffffffffffff000001ffffff00015p-1,
    -0x1.fffffep-31
  },
  { // Entry 1041
    0x1.fffffffffffffff00000000000000015p-1,
    0x1.p-30
  },
  { // Entry 1042
    0x1.fffffffffffffff00000000000000015p-1,
    -0x1.p-30
  },
  { // Entry 1043
    0x1.ffffffffffffffefffffbfffffc00015p-1,
    0x1.000002p-30
  },
  { // Entry 1044
    0x1.ffffffffffffffefffffbfffffc00015p-1,
    -0x1.000002p-30
  },
  { // Entry 1045
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    -0x1.fffffep127
  },
  { // Entry 1046
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    0x1.fffffep127
  },
  { // Entry 1047
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    0x1.fffffep127
  },
  { // Entry 1048
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    -0x1.fffffep127
  },
  { // Entry 1049
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    0x1.fffffep127
  },
  { // Entry 1050
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    -0x1.fffffep127
  },
  { // Entry 1051
    -0x1.8877a29e3d7b6defcb528e86f4c3e09ap-1,
    0x1.fffffcp127
  },
  { // Entry 1052
    -0x1.8877a29e3d7b6defcb528e86f4c3e09ap-1,
    -0x1.fffffcp127
  },
  { // Entry 1053
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    0x1.921fb6p1
  },
  { // Entry 1054
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    -0x1.921fb6p1
  },
  { // Entry 1055
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    0x1.921fb6p0
  },
  { // Entry 1056
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    -0x1.921fb6p0
  },
  { // Entry 1057
    0x1.14a27d9da5d4aebce71428f9057b08dap-1,
    0x1.000002p0
  },
  { // Entry 1058
    0x1.14a27d9da5d4aebce71428f9057b08dap-1,
    -0x1.000002p0
  },
  { // Entry 1059
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.p0
  },
  { // Entry 1060
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.p0
  },
  { // Entry 1061
    0x1.14a282aa25b11f6312a7a65180e7c3d4p-1,
    0x1.fffffep-1
  },
  { // Entry 1062
    0x1.14a282aa25b11f6312a7a65180e7c3d4p-1,
    -0x1.fffffep-1
  },
  { // Entry 1063
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    0x1.921fb6p-1
  },
  { // Entry 1064
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    -0x1.921fb6p-1
  },
  { // Entry 1065
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.000002p-126
  },
  { // Entry 1066
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.000002p-126
  },
  { // Entry 1067
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-126
  },
  { // Entry 1068
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-126
  },
  { // Entry 1069
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffcp-127
  },
  { // Entry 1070
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp-127
  },
  { // Entry 1071
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffff8p-127
  },
  { // Entry 1072
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffff8p-127
  },
  { // Entry 1073
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-148
  },
  { // Entry 1074
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-148
  },
  { // Entry 1075
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 1076
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 1077
    0x1.p0,
    0.0f
  },
  { // Entry 1078
    0x1.p0,
    -0.0f
  },
};
```