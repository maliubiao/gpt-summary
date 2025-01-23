Response:
Here's a breakdown of the thinking process to answer the prompt effectively:

1. **Understand the Core Request:** The prompt asks for an analysis of a code snippet from `cos_intel_data.handroid`, part of Android's math library. The focus is on its function, relationship to Android, implementation details (especially libc and dynamic linker), usage errors, and how Android reaches this code. It's also explicitly labeled as part 3 of 4 and needs a summary of its function.

2. **Initial Assessment of the Code:** The code is a large array of structures. Each structure contains two floating-point numbers. The numbers are in hexadecimal floating-point representation. The comments like "// Entry NNN" suggest this is a lookup table. The file name `cos_intel_data` strongly hints at data used for cosine calculations, potentially optimized for Intel architectures.

3. **Deduce Functionality:** Based on the structure and filename, the primary function is highly likely to be a lookup table for cosine (or a related trigonometric function) calculations. The two values in each entry probably represent an input value (an angle or a value related to an angle) and its corresponding cosine value. The presence of both positive and negative second values for the same first value suggests symmetry, which is a property of the cosine function (cos(x) = cos(-x)).

4. **Relate to Android Functionality:**  Since it's part of Android's math library (`bionic`), this data is crucial for any Android functionality that requires cosine calculations. Examples include:
    * **Graphics:** Rendering, animations, physics simulations.
    * **Sensors:** Processing data from accelerometers, gyroscopes, which often involves trigonometric calculations for orientation and motion.
    * **Audio/Video:** Signal processing.
    * **Location:**  Some calculations might involve angles.

5. **Address libc Function Implementation:** This specific file *doesn't* contain libc function implementations. It's *data*. Therefore, the answer should clarify this and point out that the *use* of this data would be within the implementation of functions like `cos()`. Briefly explain that `cos()` often uses Taylor series approximations, CORDIC algorithms, or lookup tables (like this one) for efficiency.

6. **Address Dynamic Linker Functionality:** This file is a static data file and doesn't directly involve the dynamic linker. However, *the library that uses this data* (`libm.so`) *does*. Therefore, explain the role of the dynamic linker in loading `libm.so` and resolving symbols. Provide a simplified `libm.so` layout example. Describe the linking process: locating dependencies, resolving symbols, and memory mapping.

7. **Logical Reasoning (Hypothetical Input/Output):**  Choose a few example entries from the data. Explain that the first number is the input and the second is the pre-calculated cosine. Convert the hexadecimal floating-point numbers to decimal (or explain how they *could* be converted) to make the relationship clearer. Emphasize this is an approximation due to the nature of floating-point and the lookup table approach.

8. **Common Usage Errors:**  Since this is a data file, direct user errors are unlikely. The errors would occur in the *code* that *uses* this data. Examples:
    * Passing an angle outside the valid range (if the table has limits).
    * Incorrectly interpreting the data (though the format seems clear).
    * Issues with floating-point precision in code using the `cos()` function.

9. **Android Framework/NDK Path:** Describe how a call to `cos()` from an Android app (Java/Kotlin) using the framework or from native code (NDK) eventually leads to the `cos()` implementation in `libm.so`, which *might* use this data. Illustrate the chain of calls: App -> Framework (Math class or similar) -> JNI -> `libm.so` -> data lookup.

10. **Frida Hook Example:** Provide a practical Frida script to intercept calls to `cos()` and potentially examine the input and output, showing how to verify that `libm.so` (and thus potentially this data) is being used.

11. **Part 3 Summary:**  Focus on the core purpose: this data file is a lookup table for optimizing cosine calculations within Android's math library. Highlight its role in improving performance.

12. **Review and Refine:** Read through the entire answer, ensuring clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. Ensure the language is clear and avoids overly technical jargon where possible. Double-check the hexadecimal floating-point conversions (or the explanation of them). Make sure the connection to Android functionality is concrete with examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file contains the *implementation* of `cos()`. **Correction:**  The file extension and the data format strongly suggest it's *data*, not code.
* **Uncertainty:** How is this data used by `cos()`? **Resolution:**  Likely a lookup table for faster calculations, potentially combined with interpolation for values not directly in the table.
* **Missing Link:**  Need to explicitly connect the data file to the `libm.so` library and the `cos()` function.
* **Frida Focus:**  Make the Frida example directly relevant to hooking the `cos()` function, not just any random function in `libm.so`.

By following this thought process, the aim is to provide a comprehensive and accurate answer that addresses all aspects of the prompt, even when the provided code snippet itself is not executable code but rather data.
好的，我们来归纳一下这个代码文件的功能。

**功能归纳**

这个代码文件 `cos_intel_data.handroid` 的主要功能是：

* **存储预计算的余弦函数（cosine）的查找表数据。**  它包含了一系列的条目（Entry），每个条目存储了一对十六进制浮点数。
* **用于优化 `cos()` 函数的性能。**  通过预先计算一部分余弦值并存储起来，可以在实际计算时直接查找，避免重复计算，提高效率。这在资源受限的移动设备上尤其重要。
* **特定于 Intel 架构（暗示）。** 文件名中的 "intel" 暗示这些数据可能针对 Intel 的处理器架构进行了优化或测试。
* **作为 Android 系统 `bionic` 库的一部分。**  `bionic` 是 Android 的 C 库，包含了数学库。这个文件是 `bionic` 数学库中用于计算余弦函数的一部分数据。

**与 Android 功能的关系举例**

Android 系统中许多功能都依赖于数学计算，包括余弦函数。以下是一些例子：

* **图形渲染 (Graphics Rendering):** 在 2D 和 3D 图形渲染中，经常需要计算角度和三角函数来进行旋转、缩放、投影等操作。例如，在绘制一个旋转的物体时，会用到 `cos()` 函数来计算顶点的坐标。Android Framework 中的 `android.graphics` 包下的类，以及更底层的 Skia 图形库，都会用到这些数学函数。
* **动画 (Animations):**  动画效果的实现通常涉及到随时间变化的属性。例如，一个淡入淡出的动画，其透明度变化可能基于一个正弦或余弦函数。Android 动画框架中的 `android.animation` 包会使用数学函数来实现各种动画效果。
* **传感器数据处理 (Sensor Data Processing):**  Android 设备上的各种传感器，如加速度计、陀螺仪、磁力计等，产生的数据需要经过复杂的数学运算才能得到有意义的结果，例如设备的姿态、方向等。余弦函数在旋转矩阵、四元数等表示方向的计算中非常常见。Android Framework 提供了 `android.hardware` 包来访问和处理传感器数据。
* **物理引擎 (Physics Engines):**  如果 Android 应用使用了物理引擎（例如游戏开发），那么碰撞检测、运动模拟等都需要大量的数学计算，包括三角函数。
* **音频/视频处理 (Audio/Video Processing):**  在音频和视频信号处理中，例如傅里叶变换、滤波器设计等，也会用到余弦函数。

**详细解释 libc 函数的功能是如何实现的**

这个代码文件本身 **不是** libc 函数的实现，而是一个 **数据文件**。它存储的是用于实现 `cos()` 函数的预计算数据。

`cos()` 函数在 libc 中的实现通常会采用以下一种或多种方法：

1. **泰勒级数展开 (Taylor Series Expansion):**  这是计算三角函数的一种基本方法。将 `cos(x)` 展开为无穷级数：`cos(x) = 1 - x^2/2! + x^4/4! - x^6/6! + ...`。通过计算有限项的级数和来逼近真实值。这种方法的缺点是计算量较大，尤其当 `x` 的绝对值较大时，收敛速度慢。

2. **切比雪夫逼近 (Chebyshev Approximation):**  使用切比雪夫多项式来逼近 `cos(x)`。这种方法比泰勒级数展开收敛更快，可以用更少的项获得更高的精度。

3. **CORDIC 算法 (Coordinate Rotation Digital Computer):**  一种迭代算法，通过一系列简单的加减和位移操作来计算三角函数和其他复杂函数。CORDIC 算法在硬件实现中很常见，因为它不需要乘法器。

4. **查找表 (Lookup Table) 和插值 (Interpolation):**  预先计算一些关键角度的余弦值，并将它们存储在查找表中。当需要计算某个角度的余弦值时，首先在查找表中找到最接近的两个值，然后通过线性插值或其他插值方法来估算结果。这个代码文件 `cos_intel_data.handroid` 正是这种方法的体现。

   * **实现细节：**  `cos()` 函数的实现可能会先将输入角度 `x` 归约到一个较小的区间（例如 `[0, pi/2]`），利用余弦函数的对称性和周期性。然后，根据归约后的角度，在查找表中找到对应的条目，并可能进行插值以提高精度。例如，如果需要计算的输入值恰好是查找表中的某个第一列的值，那么可以直接取出对应的第二列的值作为结果。如果不在表中，则可能需要找到相邻的两个条目，根据输入值与这两个条目的第一列值的关系，对它们的第二列值进行线性插值。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

这个数据文件本身不涉及 dynamic linker 的功能。Dynamic linker 主要负责加载共享库 (`.so` 文件) 并在运行时解析符号引用。

**假设 `libm.so` 中使用了这个数据文件：**

**`libm.so` 布局样本：**

```
libm.so:
    .text          # 包含 cos() 等函数的代码段
        cos:       # cos() 函数的实现
            ...     # 代码，可能包含查表和插值逻辑
    .rodata        # 只读数据段
        cos_table: # 存储 cos_intel_data.handroid 的数据
            entry_0:
                input_0:  0x1.9dd83c7c9e128p-1
                output_0: -0x1.9dd83c7c9e128p-2
            entry_1:
                input_1:  ...
                output_1: ...
            ...
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    ...
```

**链接的处理过程：**

1. **编译和链接时：** 当编译链接一个使用了 `cos()` 函数的程序时，链接器会将程序代码中对 `cos()` 的调用解析为对 `libm.so` 中 `cos` 符号的引用。但是，在静态链接阶段，并不会将 `libm.so` 的代码直接嵌入到程序中。

2. **程序加载时：** 当 Android 系统加载包含 `cos()` 函数调用的可执行文件时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被启动。

3. **加载依赖库：** Dynamic linker 会检查可执行文件依赖的共享库列表，其中包括 `libm.so`。然后，它会在系统路径下查找 `libm.so` 文件，并将其加载到内存中。

4. **符号解析 (Symbol Resolution):** Dynamic linker 会遍历可执行文件和已加载的共享库的符号表。当遇到未解析的符号引用（例如对 `cos` 的调用）时，它会在 `libm.so` 的符号表中查找匹配的符号定义。

5. **重定位 (Relocation):** 一旦找到符号定义，dynamic linker 会修改可执行文件中的指令，将对 `cos` 符号的引用指向 `libm.so` 中 `cos()` 函数的实际内存地址。这个过程称为重定位。

6. **`cos()` 函数执行：** 当程序执行到调用 `cos()` 函数的指令时，程序会跳转到 `libm.so` 中 `cos()` 函数的内存地址执行。`cos()` 函数的实现可能会读取 `.rodata` 段中的 `cos_table` 数据来进行查找或插值计算。

**逻辑推理，给出假设输入与输出**

假设我们使用查找表中的一个条目：

* **假设输入 (角度或相关值):** `0x1.ca59c6fa3d9cdb17530927aff1b33abbp-1` (这是 Entry 711 的第一个值)
* **预期输出 (cos 值):** `0x1.d8f7208e6b82ep-2` (这是 Entry 711 的第二个值)

**解释：**  如果 `cos()` 函数的实现逻辑是直接查找这个表，并且输入值与表中的某个第一列的值完全匹配，那么函数会直接返回该条目对应的第二列的值作为结果。

**用户或编程常见的使用错误**

虽然用户不会直接操作这个数据文件，但在使用 `cos()` 函数时可能遇到以下错误：

1. **参数超出定义域:**  `cos()` 函数的参数是角度（通常以弧度表示）。虽然数学上 `cos()` 的定义域是所有实数，但在实际实现中，为了精度和性能考虑，可能会对输入参数进行范围限制或归约。如果传入的参数非常大或非常小，可能会导致计算结果不准确或出现 NaN (Not a Number)。

   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double angle = 1e10; // 一个非常大的角度
       double result = cos(angle);
       printf("cos(%f) = %f\n", angle, result); // 输出可能为 NaN
       return 0;
   }
   ```

2. **精度问题:**  浮点数的表示存在精度限制。当进行大量的数学运算时，可能会累积误差，导致最终结果与理论值存在微小偏差。

   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double pi = 3.14159265358979323846;
       double result1 = cos(pi / 2.0);
       double result2 = cos(asin(1.0)); // 理论上也是 cos(pi/2)
       printf("cos(pi/2) = %f\n", result1);       // 输出接近 0，但不完全是 0
       printf("cos(asin(1)) = %f\n", result2);   // 输出接近 0，但不完全是 0
       return 0;
   }
   ```

3. **误解角度单位:**  `cos()` 函数通常期望输入角度以弧度为单位。如果将角度误用角度制传入，会导致计算结果错误。

   ```c
   #include <math.h>
   #include <stdio.h>

   #define PI 3.14159265358979323846

   double degreesToRadians(double degrees) {
       return degrees * PI / 180.0;
   }

   int main() {
       double angle_degrees = 90.0;
       double angle_radians = degreesToRadians(angle_degrees);
       double result1 = cos(angle_radians); // 正确，计算 cos(pi/2)
       double result2 = cos(angle_degrees); // 错误，计算 cos(90) 弧度
       printf("cos(90 degrees) radians = %f\n", result1);
       printf("cos(90 degrees) directly = %f\n", result2);
       return 0;
   }
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

以下是从 Android 应用调用 `cos()` 函数到最终可能使用到 `cos_intel_data.handroid` 的大致步骤：

1. **Java/Kotlin 代码调用:**  在 Android 应用的 Java 或 Kotlin 代码中，可能会调用 `java.lang.Math.cos()` 方法。

   ```java
   double angle = Math.PI / 4.0;
   double cosValue = Math.cos(angle);
   ```

2. **Framework 层调用:** `java.lang.Math.cos()` 是一个 native 方法，它的实现位于 Android Framework 的 native 代码中（通常在 `libjavacrypto.so` 或其他相关库中）。

3. **JNI 调用:** Framework 层的 native 代码会通过 JNI (Java Native Interface) 调用到 Android 系统库 `libm.so` 中的 `cos()` 函数。`libm.so` 是 `bionic` 库的一部分，包含了标准的 C 数学函数。

4. **`libm.so` 中的 `cos()` 实现:** `libm.so` 中的 `cos()` 函数实现会执行实际的余弦计算。正如前面所述，它可能会使用泰勒级数、切比雪夫逼近、CORDIC 算法，或者查找表（如 `cos_intel_data.handroid`）和插值的组合。

5. **访问数据文件:** 如果 `cos()` 的实现采用了查找表方法，它会读取 `libm.so` 的 `.rodata` 段中存储的 `cos_intel_data.handroid` 数据。

**Frida Hook 示例：**

可以使用 Frida hook `libm.so` 中的 `cos()` 函数，查看其输入和输出，以验证是否被调用。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "cos"), {
    onEnter: function(args) {
        var angle = args[0];
        console.log("[Cos] Input angle: " + angle);
        this.angle = angle;
    },
    onLeave: function(retval) {
        console.log("[Cos] Output cos(" + this.angle + "): " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 frida-tools。
2. **找到目标应用包名:**  替换 `package_name` 为你要调试的 Android 应用的包名。
3. **运行 Frida 脚本:**  将代码保存为 Python 文件（例如 `hook_cos.py`），然后在你的电脑上运行 `python hook_cos.py`。
4. **在 Android 设备上操作应用:**  运行你的 Android 应用，并触发会调用 `Math.cos()` 的功能。
5. **查看 Frida 输出:**  Frida 会拦截对 `libm.so` 中 `cos()` 函数的调用，并打印出输入角度和计算结果。

**更深入的 Hook (如果需要查看是否使用了查找表数据):**

要更深入地了解是否使用了 `cos_intel_data.handroid`，你可能需要 hook `libm.so` 中 `cos()` 函数的 **内部实现**，这通常需要反汇编 `libm.so` 并找到访问查找表的代码位置。这需要更高级的 Frida 技术和对汇编代码的理解。例如，你可以尝试 hook 访问 `.rodata` 段内存的操作，并检查访问的地址是否在 `cos_table` 的范围内。

总结来说，`cos_intel_data.handroid` 是 Android 系统 `bionic` 库中用于优化余弦函数计算的预计算数据查找表。它通过存储一系列输入值及其对应的余弦值，使得 `cos()` 函数在运行时可以快速查找结果，提高性能。这在各种需要三角函数计算的 Android 功能中都有应用。

### 提示词
```
这是目录为bionic/tests/math_data/cos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
791cf983d53efaa7d45e291ep-1,
    -0x1.9dd83c7c9e128p-2
  },
  { // Entry 711
    0x1.ca59c6fa3d9cdb17530927aff1b33abbp-1,
    0x1.d8f7208e6b82ep-2
  },
  { // Entry 712
    0x1.ca59c6fa3d9cdb17530927aff1b33abbp-1,
    -0x1.d8f7208e6b82ep-2
  },
  { // Entry 713
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    0x1.0a0b02501c799p-1
  },
  { // Entry 714
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 715
    0x1.a0d1f8a9a791f9dff5c993af4908264dp-1,
    0x1.3d3e35834faccp-1
  },
  { // Entry 716
    0x1.a0d1f8a9a791f9dff5c993af4908264dp-1,
    -0x1.3d3e35834faccp-1
  },
  { // Entry 717
    0x1.93e2948233fd0f69e3918982148f8265p-1,
    0x1.52e1f6ad9c27cp-1
  },
  { // Entry 718
    0x1.93e2948233fd0f69e3918982148f8265p-1,
    -0x1.52e1f6ad9c27cp-1
  },
  { // Entry 719
    0x1.863a850e43900997e76be80405437377p-1,
    0x1.6885b7d7e8a2cp-1
  },
  { // Entry 720
    0x1.863a850e43900997e76be80405437377p-1,
    -0x1.6885b7d7e8a2cp-1
  },
  { // Entry 721
    0x1.77e008d0775e9fc38e3f492f8e93ff51p-1,
    0x1.7e297902351dcp-1
  },
  { // Entry 722
    0x1.77e008d0775e9fc38e3f492f8e93ff51p-1,
    -0x1.7e297902351dcp-1
  },
  { // Entry 723
    0x1.68d9afe052d21e50560f9ffb6cc1b945p-1,
    0x1.93cd3a2c8198cp-1
  },
  { // Entry 724
    0x1.68d9afe052d21e50560f9ffb6cc1b945p-1,
    -0x1.93cd3a2c8198cp-1
  },
  { // Entry 725
    0x1.592e58ea0a9f1b4fddbaaf868fe47911p-1,
    0x1.a970fb56ce13cp-1
  },
  { // Entry 726
    0x1.592e58ea0a9f1b4fddbaaf868fe47911p-1,
    -0x1.a970fb56ce13cp-1
  },
  { // Entry 727
    0x1.48e52e0a65bce4d9d62a31293f7d41c1p-1,
    0x1.bf14bc811a8ecp-1
  },
  { // Entry 728
    0x1.48e52e0a65bce4d9d62a31293f7d41c1p-1,
    -0x1.bf14bc811a8ecp-1
  },
  { // Entry 729
    0x1.3805a188200a254247f30462c36acf6ap-1,
    0x1.d4b87dab6709cp-1
  },
  { // Entry 730
    0x1.3805a188200a254247f30462c36acf6ap-1,
    -0x1.d4b87dab6709cp-1
  },
  { // Entry 731
    0x1.26976a6c4e0fbabb84632bd99feec9c6p-1,
    0x1.ea5c3ed5b384cp-1
  },
  { // Entry 732
    0x1.26976a6c4e0fbabb84632bd99feec9c6p-1,
    -0x1.ea5c3ed5b384cp-1
  },
  { // Entry 733
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    0x1.12bd9173c07abp0
  },
  { // Entry 734
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    -0x1.12bd9173c07abp0
  },
  { // Entry 735
    0x1.a5a4ccf40d9cb25f16ad97e480c4b483p-2,
    0x1.257b22e780f56p0
  },
  { // Entry 736
    0x1.a5a4ccf40d9cb25f16ad97e480c4b483p-2,
    -0x1.257b22e780f56p0
  },
  { // Entry 737
    0x1.6043621b13bd3f904b3b876df5b2c6f4p-2,
    0x1.3838b45b41701p0
  },
  { // Entry 738
    0x1.6043621b13bd3f904b3b876df5b2c6f4p-2,
    -0x1.3838b45b41701p0
  },
  { // Entry 739
    0x1.18fee96a1a5762fc6770ff168e06ab3ep-2,
    0x1.4af645cf01eacp0
  },
  { // Entry 740
    0x1.18fee96a1a5762fc6770ff168e06ab3ep-2,
    -0x1.4af645cf01eacp0
  },
  { // Entry 741
    0x1.a0723a95492ce998457fb7a0d09a6385p-3,
    0x1.5db3d742c2657p0
  },
  { // Entry 742
    0x1.a0723a95492ce998457fb7a0d09a6385p-3,
    -0x1.5db3d742c2657p0
  },
  { // Entry 743
    0x1.0cab9115640b9d9d466723bbd5d589bep-3,
    0x1.707168b682e02p0
  },
  { // Entry 744
    0x1.0cab9115640b9d9d466723bbd5d589bep-3,
    -0x1.707168b682e02p0
  },
  { // Entry 745
    0x1.ddd1ec25e201f538925bf5bcf7c7df6ep-5,
    0x1.832efa2a435adp0
  },
  { // Entry 746
    0x1.ddd1ec25e201f538925bf5bcf7c7df6ep-5,
    -0x1.832efa2a435adp0
  },
  { // Entry 747
    -0x1.e6669a270c56d3a08d91cc2721f92fe1p-7,
    0x1.95ec8b9e03d58p0
  },
  { // Entry 748
    -0x1.e6669a270c56d3a08d91cc2721f92fe1p-7,
    -0x1.95ec8b9e03d58p0
  },
  { // Entry 749
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 750
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 751
    0x1.0cb3469a29ea66d4031be769702aad5cp-1,
    0x1.04aff6d330942p0
  },
  { // Entry 752
    0x1.0cb3469a29ea66d4031be769702aad5cp-1,
    -0x1.04aff6d330942p0
  },
  { // Entry 753
    0x1.0cb228fa7f8117c82e61cf5393341c64p-1,
    0x1.04b09e98dcdb4p0
  },
  { // Entry 754
    0x1.0cb228fa7f8117c82e61cf5393341c64p-1,
    -0x1.04b09e98dcdb4p0
  },
  { // Entry 755
    0x1.0cb10b5a61b05a73e78a3e4447baf514p-1,
    0x1.04b1465e89226p0
  },
  { // Entry 756
    0x1.0cb10b5a61b05a73e78a3e4447baf514p-1,
    -0x1.04b1465e89226p0
  },
  { // Entry 757
    0x1.0cafedb9d078a984086928aa40d2e4a5p-1,
    0x1.04b1ee2435698p0
  },
  { // Entry 758
    0x1.0cafedb9d078a984086928aa40d2e4a5p-1,
    -0x1.04b1ee2435698p0
  },
  { // Entry 759
    0x1.0caed018cbda7fa59c631cd55b31aa8dp-1,
    0x1.04b295e9e1b0ap0
  },
  { // Entry 760
    0x1.0caed018cbda7fa59c631cd55b31aa8dp-1,
    -0x1.04b295e9e1b0ap0
  },
  { // Entry 761
    0x1.0cadb27753d65785e06d0e464006149ep-1,
    0x1.04b33daf8df7cp0
  },
  { // Entry 762
    0x1.0cadb27753d65785e06d0e464006149ep-1,
    -0x1.04b33daf8df7cp0
  },
  { // Entry 763
    0x1.0cac94d5686cabd2430c20fdf2855b47p-1,
    0x1.04b3e5753a3eep0
  },
  { // Entry 764
    0x1.0cac94d5686cabd2430c20fdf2855b47p-1,
    -0x1.04b3e5753a3eep0
  },
  { // Entry 765
    0x1.0cab7733099df738645574cd482ef4b2p-1,
    0x1.04b48d3ae6860p0
  },
  { // Entry 766
    0x1.0cab7733099df738645574cd482ef4b2p-1,
    -0x1.04b48d3ae6860p0
  },
  { // Entry 767
    0x1.0caa5990376b061ec1cf3890f1b8e1e3p-1,
    0x1.04b5350092ccfp0
  },
  { // Entry 768
    0x1.0caa5990376b061ec1cf3890f1b8e1e3p-1,
    -0x1.04b5350092ccfp0
  },
  { // Entry 769
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 770
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 771
    0x1.p0,
    -0.0
  },
  { // Entry 772
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 773
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 774
    0x1.ad02c771c35ed5f01089a00c6a27e0cfp-1,
    0x1.279a74590331bp-1
  },
  { // Entry 775
    0x1.ad02c771c35ed5f01089a00c6a27e0cfp-1,
    -0x1.279a74590331bp-1
  },
  { // Entry 776
    0x1.ad02c771c35ecd3471de9021e6c3b92bp-1,
    0x1.279a74590331cp-1
  },
  { // Entry 777
    0x1.ad02c771c35ecd3471de9021e6c3b92bp-1,
    -0x1.279a74590331cp-1
  },
  { // Entry 778
    0x1.ad02c771c35ec478d333803762f450d5p-1,
    0x1.279a74590331dp-1
  },
  { // Entry 779
    0x1.ad02c771c35ec478d333803762f450d5p-1,
    -0x1.279a74590331dp-1
  },
  { // Entry 780
    -0x1.48d1ddd2b2b3f8c21b9421e65b380735p-3,
    0x1.bb67ae8584ca9p0
  },
  { // Entry 781
    -0x1.48d1ddd2b2b3f8c21b9421e65b380735p-3,
    -0x1.bb67ae8584ca9p0
  },
  { // Entry 782
    -0x1.48d1ddd2b2b47718ff3063b6bd981099p-3,
    0x1.bb67ae8584caap0
  },
  { // Entry 783
    -0x1.48d1ddd2b2b47718ff3063b6bd981099p-3,
    -0x1.bb67ae8584caap0
  },
  { // Entry 784
    -0x1.48d1ddd2b2b4f56fe2cca5871eaf4820p-3,
    0x1.bb67ae8584cabp0
  },
  { // Entry 785
    -0x1.48d1ddd2b2b4f56fe2cca5871eaf4820p-3,
    -0x1.bb67ae8584cabp0
  },
  { // Entry 786
    0x1.cfc6cfa52ad9f9911db4ca0d45fdb0b3p-1,
    0x1.bffffffffffffp-2
  },
  { // Entry 787
    0x1.cfc6cfa52ad9f9911db4ca0d45fdb0b3p-1,
    -0x1.bffffffffffffp-2
  },
  { // Entry 788
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    0x1.cp-2
  },
  { // Entry 789
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    -0x1.cp-2
  },
  { // Entry 790
    0x1.cfc6cfa52ad9f2c9bcf37d87c05892f5p-1,
    0x1.c000000000001p-2
  },
  { // Entry 791
    0x1.cfc6cfa52ad9f2c9bcf37d87c05892f5p-1,
    -0x1.c000000000001p-2
  },
  { // Entry 792
    0x1.8bb105a5dc90104051d08cb965631807p-1,
    0x1.5ffffffffffffp-1
  },
  { // Entry 793
    0x1.8bb105a5dc90104051d08cb965631807p-1,
    -0x1.5ffffffffffffp-1
  },
  { // Entry 794
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    0x1.6p-1
  },
  { // Entry 795
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    -0x1.6p-1
  },
  { // Entry 796
    0x1.8bb105a5dc8ffbf19e4ebd80fab2cdb8p-1,
    0x1.6000000000001p-1
  },
  { // Entry 797
    0x1.8bb105a5dc8ffbf19e4ebd80fab2cdb8p-1,
    -0x1.6000000000001p-1
  },
  { // Entry 798
    0x1.7ef4842f0bcd11686aaf6f21c9aa8354p-2,
    0x1.2ffffffffffffp0
  },
  { // Entry 799
    0x1.7ef4842f0bcd11686aaf6f21c9aa8354p-2,
    -0x1.2ffffffffffffp0
  },
  { // Entry 800
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    0x1.3p0
  },
  { // Entry 801
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    -0x1.3p0
  },
  { // Entry 802
    0x1.7ef4842f0bcc9ab229f0cc6fad6d378dp-2,
    0x1.3000000000001p0
  },
  { // Entry 803
    0x1.7ef4842f0bcc9ab229f0cc6fad6d378dp-2,
    -0x1.3000000000001p0
  },
  { // Entry 804
    -0x1.863efa361dc2294e929b9515fb34f9bap-1,
    0x1.37fffffffffffp1
  },
  { // Entry 805
    -0x1.863efa361dc2294e929b9515fb34f9bap-1,
    -0x1.37fffffffffffp1
  },
  { // Entry 806
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    0x1.380p1
  },
  { // Entry 807
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    -0x1.380p1
  },
  { // Entry 808
    -0x1.863efa361dc27c2ab13a48912d45880bp-1,
    0x1.3800000000001p1
  },
  { // Entry 809
    -0x1.863efa361dc27c2ab13a48912d45880bp-1,
    -0x1.3800000000001p1
  },
  { // Entry 810
    0x1.fef2b2d21cf6c106e86ff9395f8204a0p-1,
    0x1.069c8b46b3792p-4
  },
  { // Entry 811
    0x1.fef2b2d21cf6c106e86ff9395f8204a0p-1,
    -0x1.069c8b46b3792p-4
  },
  { // Entry 812
    0x1.fbcbe693bd8ec85723b6cb55e4f5e78fp-1,
    0x1.069c8b46b3792p-3
  },
  { // Entry 813
    0x1.fbcbe693bd8ec85723b6cb55e4f5e78fp-1,
    -0x1.069c8b46b3792p-3
  },
  { // Entry 814
    0x1.f68eebfcbb5e841900e2542f7c24bab0p-1,
    0x1.89ead0ea0d35bp-3
  },
  { // Entry 815
    0x1.f68eebfcbb5e841900e2542f7c24bab0p-1,
    -0x1.89ead0ea0d35bp-3
  },
  { // Entry 816
    0x1.ef4145b4aecffbdaaffb78ffb49ac9bdp-1,
    0x1.069c8b46b3792p-2
  },
  { // Entry 817
    0x1.ef4145b4aecffbdaaffb78ffb49ac9bdp-1,
    -0x1.069c8b46b3792p-2
  },
  { // Entry 818
    0x1.e5eaa286fbbc670dbf6392d7c98ab0a0p-1,
    0x1.4843ae1860576p-2
  },
  { // Entry 819
    0x1.e5eaa286fbbc670dbf6392d7c98ab0a0p-1,
    -0x1.4843ae1860576p-2
  },
  { // Entry 820
    0x1.da94d54dd4c0876e18ee97c70d1a4a94p-1,
    0x1.89ead0ea0d35ap-2
  },
  { // Entry 821
    0x1.da94d54dd4c0876e18ee97c70d1a4a94p-1,
    -0x1.89ead0ea0d35ap-2
  },
  { // Entry 822
    0x1.cd4bca9cb5c715302001e446cc93a7bcp-1,
    0x1.cb91f3bbba13ep-2
  },
  { // Entry 823
    0x1.cd4bca9cb5c715302001e446cc93a7bcp-1,
    -0x1.cb91f3bbba13ep-2
  },
  { // Entry 824
    0x1.be1d7c3534c40331fddf243d8a0a56b0p-1,
    0x1.069c8b46b3791p-1
  },
  { // Entry 825
    0x1.be1d7c3534c40331fddf243d8a0a56b0p-1,
    -0x1.069c8b46b3791p-1
  },
  { // Entry 826
    0x1.ad19e2535aa9678bd5fdafc68817700bp-1,
    0x1.27701caf89e83p-1
  },
  { // Entry 827
    0x1.ad19e2535aa9678bd5fdafc68817700bp-1,
    -0x1.27701caf89e83p-1
  },
  { // Entry 828
    0x1.9a52e2e0fbcb3a3f4bde6f6ec27767a9p-1,
    0x1.4843ae1860575p-1
  },
  { // Entry 829
    0x1.9a52e2e0fbcb3a3f4bde6f6ec27767a9p-1,
    -0x1.4843ae1860575p-1
  },
  { // Entry 830
    0x1.85dc3ea1bbce9a8085f66593a87b7e2ep-1,
    0x1.69173f8136c67p-1
  },
  { // Entry 831
    0x1.85dc3ea1bbce9a8085f66593a87b7e2ep-1,
    -0x1.69173f8136c67p-1
  },
  { // Entry 832
    0x1.6fcb7c6b8b919af3dda53094c9a27aabp-1,
    0x1.89ead0ea0d359p-1
  },
  { // Entry 833
    0x1.6fcb7c6b8b919af3dda53094c9a27aabp-1,
    -0x1.89ead0ea0d359p-1
  },
  { // Entry 834
    0x1.5837d2817cf303ef6dae69faeb0f015ep-1,
    0x1.aabe6252e3a4bp-1
  },
  { // Entry 835
    0x1.5837d2817cf303ef6dae69faeb0f015ep-1,
    -0x1.aabe6252e3a4bp-1
  },
  { // Entry 836
    0x1.3f3a0e28bedd40445858f823e150264bp-1,
    0x1.cb91f3bbba13dp-1
  },
  { // Entry 837
    0x1.3f3a0e28bedd40445858f823e150264bp-1,
    -0x1.cb91f3bbba13dp-1
  },
  { // Entry 838
    0x1.24ec799171642dbd24d259005822bd25p-1,
    0x1.ec6585249082fp-1
  },
  { // Entry 839
    0x1.24ec799171642dbd24d259005822bd25p-1,
    -0x1.ec6585249082fp-1
  },
  { // Entry 840
    0x1.096ac02ec42c85b7b10afed9202785b9p-1,
    0x1.069c8b46b3791p0
  },
  { // Entry 841
    0x1.096ac02ec42c85b7b10afed9202785b9p-1,
    -0x1.069c8b46b3791p0
  },
  { // Entry 842
    0x1.d9a3a336edb7613df062e86a32d09fe1p-2,
    0x1.170653fb1eb0ap0
  },
  { // Entry 843
    0x1.d9a3a336edb7613df062e86a32d09fe1p-2,
    -0x1.170653fb1eb0ap0
  },
  { // Entry 844
    0x1.9e7f8652b47582afd29744293170c07cp-2,
    0x1.27701caf89e83p0
  },
  { // Entry 845
    0x1.9e7f8652b47582afd29744293170c07cp-2,
    -0x1.27701caf89e83p0
  },
  { // Entry 846
    0x1.61a76077aee07bb349ca76cf700913d1p-2,
    0x1.37d9e563f51fcp0
  },
  { // Entry 847
    0x1.61a76077aee07bb349ca76cf700913d1p-2,
    -0x1.37d9e563f51fcp0
  },
  { // Entry 848
    0x1.235b331d8f748e20fb6ddb6a708dba10p-2,
    0x1.4843ae1860575p0
  },
  { // Entry 849
    0x1.235b331d8f748e20fb6ddb6a708dba10p-2,
    -0x1.4843ae1860575p0
  },
  { // Entry 850
    0x1.c7b90e3024593da8449963cfe08dde85p-3,
    0x1.58ad76cccb8eep0
  },
  { // Entry 851
    0x1.c7b90e3024593da8449963cfe08dde85p-3,
    -0x1.58ad76cccb8eep0
  },
  { // Entry 852
    0x1.46dc4f4ce83da727ea048cc7d2f276d1p-3,
    0x1.69173f8136c67p0
  },
  { // Entry 853
    0x1.46dc4f4ce83da727ea048cc7d2f276d1p-3,
    -0x1.69173f8136c67p0
  },
  { // Entry 854
    0x1.894f70befbb99ab7df9d1790a28f48adp-4,
    0x1.79810835a1fe0p0
  },
  { // Entry 855
    0x1.894f70befbb99ab7df9d1790a28f48adp-4,
    -0x1.79810835a1fe0p0
  },
  { // Entry 856
    0x1.069107ae9332f95fa2c5ceeadfb29f77p-5,
    0x1.89ead0ea0d359p0
  },
  { // Entry 857
    0x1.069107ae9332f95fa2c5ceeadfb29f77p-5,
    -0x1.89ead0ea0d359p0
  },
  { // Entry 858
    -0x1.069107ae9327e0731a748c21f03b5efcp-5,
    0x1.9a54999e786d2p0
  },
  { // Entry 859
    -0x1.069107ae9327e0731a748c21f03b5efcp-5,
    -0x1.9a54999e786d2p0
  },
  { // Entry 860
    -0x1.894f70befbb41417dff843e81fac388bp-4,
    0x1.aabe6252e3a4bp0
  },
  { // Entry 861
    -0x1.894f70befbb41417dff843e81fac388bp-4,
    -0x1.aabe6252e3a4bp0
  },
  { // Entry 862
    -0x1.46dc4f4ce83ae9ab1cc1b2367cb753ebp-3,
    0x1.bb282b074edc4p0
  },
  { // Entry 863
    -0x1.46dc4f4ce83ae9ab1cc1b2367cb753ebp-3,
    -0x1.bb282b074edc4p0
  },
  { // Entry 864
    -0x1.c7b90e30245688e099860e8d4fff601cp-3,
    0x1.cb91f3bbba13dp0
  },
  { // Entry 865
    -0x1.c7b90e30245688e099860e8d4fff601cp-3,
    -0x1.cb91f3bbba13dp0
  },
  { // Entry 866
    -0x1.235b331d8f7339841a517312d0d347fbp-2,
    0x1.dbfbbc70254b6p0
  },
  { // Entry 867
    -0x1.235b331d8f7339841a517312d0d347fbp-2,
    -0x1.dbfbbc70254b6p0
  },
  { // Entry 868
    -0x1.61a76077aedf2e43aca418f7a2e1324dp-2,
    0x1.ec6585249082fp0
  },
  { // Entry 869
    -0x1.61a76077aedf2e43aca418f7a2e1324dp-2,
    -0x1.ec6585249082fp0
  },
  { // Entry 870
    -0x1.9e7f8652b4743dcc3c3568baff8bf9ebp-2,
    0x1.fccf4dd8fbba8p0
  },
  { // Entry 871
    -0x1.9e7f8652b4743dcc3c3568baff8bf9ebp-2,
    -0x1.fccf4dd8fbba8p0
  },
  { // Entry 872
    -0x1.d9a3a336edb65efa30e1a6679aa064c2p-2,
    0x1.069c8b46b3791p1
  },
  { // Entry 873
    -0x1.d9a3a336edb65efa30e1a6679aa064c2p-2,
    -0x1.069c8b46b3791p1
  },
  { // Entry 874
    -0x1.096ac02ec42c24880a5951788cb383c8p-1,
    0x1.0ed16fa0e914ep1
  },
  { // Entry 875
    -0x1.096ac02ec42c24880a5951788cb383c8p-1,
    -0x1.0ed16fa0e914ep1
  },
  { // Entry 876
    -0x1.24ec79917163dda65afd8109f59cb465p-1,
    0x1.170653fb1eb0bp1
  },
  { // Entry 877
    -0x1.24ec79917163dda65afd8109f59cb465p-1,
    -0x1.170653fb1eb0bp1
  },
  { // Entry 878
    -0x1.3f3a0e28bedd0cf0c4bfbd8c82a3baafp-1,
    0x1.1f3b3855544c8p1
  },
  { // Entry 879
    -0x1.3f3a0e28bedd0cf0c4bfbd8c82a3baafp-1,
    -0x1.1f3b3855544c8p1
  },
  { // Entry 880
    -0x1.5837d2817cf2eb069035552dc3ae834cp-1,
    0x1.27701caf89e85p1
  },
  { // Entry 881
    -0x1.5837d2817cf2eb069035552dc3ae834cp-1,
    -0x1.27701caf89e85p1
  },
  { // Entry 882
    -0x1.6fcb7c6b8b9199ce2f17dd3ee86b3b9ap-1,
    0x1.2fa50109bf842p1
  },
  { // Entry 883
    -0x1.6fcb7c6b8b9199ce2f17dd3ee86b3b9ap-1,
    -0x1.2fa50109bf842p1
  },
  { // Entry 884
    -0x1.85dc3ea1bbceae2d294421e8c7350f8cp-1,
    0x1.37d9e563f51ffp1
  },
  { // Entry 885
    -0x1.85dc3ea1bbceae2d294421e8c7350f8cp-1,
    -0x1.37d9e563f51ffp1
  },
  { // Entry 886
    -0x1.9a52e2e0fbcb5f8a3f55c274f9ec754bp-1,
    0x1.400ec9be2abbcp1
  },
  { // Entry 887
    -0x1.9a52e2e0fbcb5f8a3f55c274f9ec754bp-1,
    -0x1.400ec9be2abbcp1
  },
  { // Entry 888
    -0x1.ad19e2535aa99b049ac0b5858c5d381fp-1,
    0x1.4843ae1860579p1
  },
  { // Entry 889
    -0x1.ad19e2535aa99b049ac0b5858c5d381fp-1,
    -0x1.4843ae1860579p1
  },
  { // Entry 890
    -0x1.be1d7c3534c44132ab1c4130cbe9dfa0p-1,
    0x1.5078927295f36p1
  },
  { // Entry 891
    -0x1.be1d7c3534c44132ab1c4130cbe9dfa0p-1,
    -0x1.5078927295f36p1
  },
  { // Entry 892
    -0x1.cd4bca9cb5c759e4d6dc8601ec3d84b6p-1,
    0x1.58ad76cccb8f3p1
  },
  { // Entry 893
    -0x1.cd4bca9cb5c759e4d6dc8601ec3d84b6p-1,
    -0x1.58ad76cccb8f3p1
  },
  { // Entry 894
    -0x1.da94d54dd4c0cedccd73684994422740p-1,
    0x1.60e25b27012b0p1
  },
  { // Entry 895
    -0x1.da94d54dd4c0cedccd73684994422740p-1,
    -0x1.60e25b27012b0p1
  },
  { // Entry 896
    -0x1.e5eaa286fbbcad1e4a6373392e679669p-1,
    0x1.69173f8136c6dp1
  },
  { // Entry 897
    -0x1.e5eaa286fbbcad1e4a6373392e679669p-1,
    -0x1.69173f8136c6dp1
  },
  { // Entry 898
    -0x1.ef4145b4aed03c5f1d39763b1eee6ed8p-1,
    0x1.714c23db6c62ap1
  },
  { // Entry 899
    -0x1.ef4145b4aed03c5f1d39763b1eee6ed8p-1,
    -0x1.714c23db6c62ap1
  },
  { // Entry 900
    -0x1.f68eebfcbb5eba124d8cc48fd1beb04dp-1,
    0x1.79810835a1fe7p1
  },
  { // Entry 901
    -0x1.f68eebfcbb5eba124d8cc48fd1beb04dp-1,
    -0x1.79810835a1fe7p1
  },
  { // Entry 902
    -0x1.fbcbe693bd8ef006f5ff02210dfe0619p-1,
    0x1.81b5ec8fd79a4p1
  },
  { // Entry 903
    -0x1.fbcbe693bd8ef006f5ff02210dfe0619p-1,
    -0x1.81b5ec8fd79a4p1
  },
  { // Entry 904
    -0x1.fef2b2d21cf6be1a2c7ea665ef1f874ep-1,
    0x1.89ead0ea0d35bp1
  },
  { // Entry 905
    -0x1.fef2b2d21cf6be1a2c7ea665ef1f874ep-1,
    -0x1.89ead0ea0d35bp1
  },
  { // Entry 906
    0x1.ef4145b4aecff6f58edecf24955428c1p-1,
    -0x1.81b5ec8fd799fp2
  },
  { // Entry 907
    0x1.ef4145b4aecff6f58edecf24955428c1p-1,
    0x1.81b5ec8fd799fp2
  },
  { // Entry 908
    0x1.be1d7c3534c3f9b9b35619280049de85p-1,
    -0x1.714c23db6c626p2
  },
  { // Entry 909
    0x1.be1d7c3534c3f9b9b35619280049de85p-1,
    0x1.714c23db6c626p2
  },
  { // Entry 910
    0x1.6fcb7c6b8b918d86fc83d612a6587eddp-1,
    -0x1.60e25b27012adp2
  },
  { // Entry 911
    0x1.6fcb7c6b8b918d86fc83d612a6587eddp-1,
    0x1.60e25b27012adp2
  },
  { // Entry 912
    0x1.096ac02ec42c82e5b225185bd6c757d5p-1,
    -0x1.5078927295f34p2
  },
  { // Entry 913
    0x1.096ac02ec42c82e5b225185bd6c757d5p-1,
    0x1.5078927295f34p2
  },
  { // Entry 914
    0x1.235b331d8f7487ce2db97819fae7777cp-2,
    -0x1.400ec9be2abbbp2
  },
  { // Entry 915
    0x1.235b331d8f7487ce2db97819fae7777cp-2,
    0x1.400ec9be2abbbp2
  },
  { // Entry 916
    0x1.069107ae9332c4a1cd2dc033b8d50598p-5,
    -0x1.2fa50109bf842p2
  },
  { // Entry 917
    0x1.069107ae9332c4a1cd2dc033b8d50598p-5,
    0x1.2fa50109bf842p2
  },
  { // Entry 918
    -0x1.c7b90e30245695bd1ec170f45feeb1ffp-3,
    -0x1.1f3b3855544c9p2
  },
  { // Entry 919
    -0x1.c7b90e30245695bd1ec170f45feeb1ffp-3,
    0x1.1f3b3855544c9p2
  },
  { // Entry 920
    -0x1.d9a3a336edb62c1541b8584cd6c00f87p-2,
    -0x1.0ed16fa0e9150p2
  },
  { // Entry 921
    -0x1.d9a3a336edb62c1541b8584cd6c00f87p-2,
    0x1.0ed16fa0e9150p2
  },
  { // Entry 922
    -0x1.5837d2817cf27705cac7881fb569ffc7p-1,
    -0x1.fccf4dd8fbbaep1
  },
  { // Entry 923
    -0x1.5837d2817cf27705cac7881fb569ffc7p-1,
    0x1.fccf4dd8fbbaep1
  },
  { // Entry 924
    -0x1.ad19e2535aa8ffb40066d78aef71fabdp-1,
    -0x1.dbfbbc70254bcp1
  },
  { // Entry 925
    -0x1.ad19e2535aa8ffb40066d78aef71fabdp-1,
    0x1.dbfbbc70254bcp1
  },
  { // Entry 926
    -0x1.e5eaa286fbbc2b129238160df30ce704p-1,
    -0x1.bb282b074edcap1
  },
  { // Entry 927
    -0x1.e5eaa286fbbc2b129238160df30ce704p-1,
    0x1.bb282b074edcap1
  },
  { // Entry 928
    -0x1.fef2b2d21cf6b40ff3b530ce8dc0d8a7p-1,
    -0x1.9a54999e786d8p1
  },
  { // Entry 929
    -0x1.fef2b2d21cf6b40ff3b530ce8dc0d8a7p-1,
    0x1.9a54999e786d8p1
  },
  { // Entry 930
    -0x1.f68eebfcbb5eadd65c261cd803990ae1p-1,
    -0x1.79810835a1fe6p1
  },
  { // Entry 931
    -0x1.f68eebfcbb5eadd65c261cd803990ae1p-1,
    0x1.79810835a1fe6p1
  },
  { // Entry 932
    -0x1.cd4bca9cb5c775a99729f7ad95b7dce3p-1,
    -0x1.58ad76cccb8f4p1
  },
  { // Entry 933
    -0x1.cd4bca9cb5c775a99729f7ad95b7dce3p-1,
    0x1.58ad76cccb8f4p1
  },
  { // Entry 934
    -0x1.85dc3ea1bbcf2aa2e21ec586d5497e35p-1,
    -0x1.37d9e563f5202p1
  },
  { // Entry 935
    -0x1.85dc3ea1bbcf2aa2e21ec586d5497e35p-1,
    0x1.37d9e563f5202p1
  },
  { // Entry 936
    -0x1.24ec79917164e41addd4bacd4420f9fbp-1,
    -0x1.170653fb1eb10p1
  },
  { // Entry 937
    -0x1.24ec79917164e41addd4bacd4420f9fbp-1,
    0x1.170653fb1eb10p1
  },
  { // Entry 938
    -0x1.61a76077aee23b11f0c673f638003b0ap-2,
    -0x1.ec6585249083cp0
  },
  { // Entry 939
    -0x1.61a76077aee23b11f0c673f638003b0ap-2,
    0x1.ec6585249083cp0
  },
  { // Entry 940
    -0x1.894f70befbc104b706e85cf4c1c96a52p-4,
    -0x1.aabe6252e3a58p0
  },
  { // Entry 941
    -0x1.894f70befbc104b706e85cf4c1c96a52p-4,
    0x1.aabe6252e3a58p0
  },
  { // Entry 942
    0x1.46dc4f4ce8373c7c44f13b57363edd3bp-3,
    -0x1.69173f8136c74p0
  },
  { // Entry 943
    0x1.46dc4f4ce8373c7c44f13b57363edd3bp-3,
    0x1.69173f8136c74p0
  },
  { // Entry 944
    0x1.9e7f8652b47289e53fccd54955db4552p-2,
    -0x1.27701caf89e90p0
  },
  { // Entry 945
    0x1.9e7f8652b47289e53fccd54955db4552p-2,
    0x1.27701caf89e90p0
  },
  { // Entry 946
    0x1.3f3a0e28bedbfb066b67abd9c338409ep-1,
    -0x1.cb91f3bbba157p-1
  },
  { // Entry 947
    0x1.3f3a0e28bedbfb066b67abd9c338409ep-1,
    0x1.cb91f3bbba157p-1
  },
  { // Entry 948
    0x1.9a52e2e0fbca4b00c72daa3cdaca257cp-1,
    -0x1.4843ae186058ep-1
  },
  { // Entry 949
    0x1.9a52e2e0fbca4b00c72daa3cdaca257cp-1,
    0x1.4843ae186058ep-1
  },
  { // Entry 950
    0x1.da94d54dd4bff753d988c1755e2ffc04p-1,
    -0x1.89ead0ea0d38ap-2
  },
  { // Entry 951
    0x1.da94d54dd4bff753d988c1755e2ffc04p-1,
    0x1.89ead0ea0d38ap-2
  },
  { // Entry 952
    0x1.fbcbe693bd8e98423207e36587d942b7p-1,
    -0x1.069c8b46b37f0p-3
  },
  { // Entry 953
    0x1.fbcbe693bd8e98423207e36587d942b7p-1,
    0x1.069c8b46b37f0p-3
  },
  { // Entry 954
    0x1.fbcbe693bd8ef86c1565b3453036e55ep-1,
    0x1.069c8b46b3734p-3
  },
  { // Entry 955
    0x1.fbcbe693bd8ef86c1565b3453036e55ep-1,
    -0x1.069c8b46b3734p-3
  },
  { // Entry 956
    0x1.da94d54dd4c11187405ada7f04e5b171p-1,
    0x1.89ead0ea0d32cp-2
  },
  { // Entry 957
    0x1.da94d54dd4c11187405ada7f04e5b171p-1,
    -0x1.89ead0ea0d32cp-2
  },
  { // Entry 958
    0x1.9a52e2e0fbcc0cc83b843bae58c6cdf8p-1,
    0x1.4843ae186055fp-1
  },
  { // Entry 959
    0x1.9a52e2e0fbcc0cc83b843bae58c6cdf8p-1,
    -0x1.4843ae186055fp-1
  },
  { // Entry 960
    0x1.3f3a0e28bede46f65ca5b5c19ad99dd7p-1,
    0x1.cb91f3bbba128p-1
  },
  { // Entry 961
    0x1.3f3a0e28bede46f65ca5b5c19ad99dd7p-1,
    -0x1.cb91f3bbba128p-1
  },
  { // Entry 962
    0x1.9e7f8652b478066eec563f835097f148p-2,
    0x1.27701caf89e78p0
  },
  { // Entry 963
    0x1.9e7f8652b478066eec563f835097f148p-2,
    -0x1.27701caf89e78p0
  },
  { // Entry 964
    0x1.46dc4f4ce843151b9d14e561879e5fe3p-3,
    0x1.69173f8136c5cp0
  },
  { // Entry 965
    0x1.46dc4f4ce843151b9d14e561879e5fe3p-3,
    -0x1.69173f8136c5cp0
  },
  { // Entry 966
    -0x1.894f70befba9211b0dcaa4dca450670fp-4,
    0x1.aabe6252e3a40p0
  },
  { // Entry 967
    -0x1.894f70befba9211b0dcaa4dca450670fp-4,
    -0x1.aabe6252e3a40p0
  },
  { // Entry 968
    -0x1.61a76077aedc99952438421f820a2befp-2,
    0x1.ec65852490824p0
  },
  { // Entry 969
    -0x1.61a76077aedc99952438421f820a2befp-2,
    -0x1.ec65852490824p0
  },
  { // Entry 970
    -0x1.24ec799171626e36709cfcf7c7752332p-1,
    0x1.170653fb1eb04p1
  },
  { // Entry 971
    -0x1.24ec799171626e36709cfcf7c7752332p-1,
    -0x1.170653fb1eb04p1
  },
  { // Entry 972
    -0x1.85dc3ea1bbcd38cbfeb4370d5405eebap-1,
    0x1.37d9e563f51f6p1
  },
  { // Entry 973
    -0x1.85dc3ea1bbcd38cbfeb4370d5405eebap-1,
    -0x1.37d9e563f51f6p1
  },
  { // Entry 974
    -0x1.cd4bca9cb5c628709388a39fc84591d1p-1,
    0x1.58ad76cccb8e8p1
  },
  { // Entry 975
    -0x1.cd4bca9cb5c628709388a39fc84591d1p-1,
    -0x1.58ad76cccb8e8p1
  },
  { // Entry 976
    -0x1.f68eebfcbb5e1b070b564037f5571a39p-1,
    0x1.79810835a1fdap1
  },
  { // Entry 977
    -0x1.f68eebfcbb5e1b070b564037f5571a39p-1,
    -0x1.79810835a1fdap1
  },
  { // Entry 978
    -0x1.fef2b2d21cf6e544ab7795aed10d9fa7p-1,
    0x1.9a54999e786ccp1
  },
  { // Entry 979
    -0x1.fef2b2d21cf6e544ab7795aed10d9fa7p-1,
    -0x1.9a54999e786ccp1
  },
  { // Entry 980
    -0x1.e5eaa286fbbd1d135e216c49a9f7e5dap-1,
    0x1.bb282b074edbep1
  },
  { // Entry 981
    -0x1.e5eaa286fbbd1d135e216c49a9f7e5dap-1,
    -0x1.bb282b074edbep1
  },
  { // Entry 982
    -0x1.ad19e2535aaaa2ac87056b6d7776e97ap-1,
    0x1.dbfbbc70254b0p1
  },
  { // Entry 983
    -0x1.ad19e2535aaaa2ac87056b6d7776e97ap-1,
    -0x1.dbfbbc70254b0p1
  },
  { // Entry 984
    -0x1.5837d2817cf4af8e5e59b13b4aa9b5e3p-1,
    0x1.fccf4dd8fbba2p1
  },
  { // Entry 985
    -0x1.5837d2817cf4af8e5e59b13b4aa9b5e3p-1,
    -0x1.fccf4dd8fbba2p1
  },
  { // Entry 986
    -0x1.d9a3a336edbb7de64a2183cb27be4b5bp-2,
    0x1.0ed16fa0e914ap2
  },
  { // Entry 987
    -0x1.d9a3a336edbb7de64a2183cb27be4b5bp-2,
    -0x1.0ed16fa0e914ap2
  },
  { // Entry 988
    -0x1.c7b90e30246248b7a0c2c87a3dd25224p-3,
    0x1.1f3b3855544c3p2
  },
  { // Entry 989
    -0x1.c7b90e30246248b7a0c2c87a3dd25224p-3,
    -0x1.1f3b3855544c3p2
  },
  { // Entry 990
    0x1.069107ae9302caf2068b48842afdf051p-5,
    0x1.2fa50109bf83cp2
  },
  { // Entry 991
    0x1.069107ae9302caf2068b48842afdf051p-5,
    -0x1.2fa50109bf83cp2
  },
  { // Entry 992
    0x1.235b331d8f6ec74aa3de5aed15fa3f68p-2,
    0x1.400ec9be2abb5p2
  },
  { // Entry 993
    0x1.235b331d8f6ec74aa3de5aed15fa3f68p-2,
    -0x1.400ec9be2abb5p2
  },
  { // Entry 994
    0x1.096ac02ec429f225c99b89bb4c9e5d3ep-1,
    0x1.5078927295f2ep2
  },
  { // Entry 995
    0x1.096ac02ec429f225c99b89bb4c9e5d3ep-1,
    -0x1.5078927295f2ep2
  },
  { // Entry 996
    0x1.6fcb7c6b8b8f773e3b421dded6fc1f26p-1,
    0x1.60e25b27012a7p2
  },
  { // Entry 997
    0x1.6fcb7c6b8b8f773e3b421dded6fc1f26p-1,
    -0x1.60e25b27012a7p2
  },
  { // Entry 998
    0x1.be1d7c3534c280dab43dced670330b63p-1,
    0x1.714c23db6c620p2
  },
  { // Entry 999
    0x1.be1d7c3534c280dab43dced670330b63p-1,
    -0x1.714c23db6c620p2
  },
  { // Entry 1000
    0x1.ef4145b4aecf342709a3b19320d1b194p-1,
    0x1.81b5ec8fd7999p2
  },
  { // Entry 1001
    0x1.ef4145b4aecf342709a3b19320d1b194p-1,
    -0x1.81b5ec8fd7999p2
  },
  { // Entry 1002
    0x1.ff0fd2c96adfbae576981ee4b34769dep-1,
    0x1.effffffffffffp-5
  },
  { // Entry 1003
    0x1.ff0fd2c96adfbae576981ee4b34769dep-1,
    -0x1.effffffffffffp-5
  },
  { // Entry 1004
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    0x1.fp-5
  },
  { // Entry 1005
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    -0x1.fp-5
  },
  { // Entry 1006
    0x1.ff0fd2c96adfbac67b712f51a6fa2ab3p-1,
    0x1.f000000000001p-5
  },
  { // Entry 1007
    0x1.ff0fd2c96adfbac67b712f51a6fa2ab3p-1,
    -0x1.f000000000001p-5
  },
  { // Entry 1008
    0x1.fc210055467fe5c8f76e75fd7083818cp-1,
    0x1.f7fffffffffffp-4
  },
  { // Entry 1009
    0x1.fc210055467fe5c8f76e75fd7083818cp-1,
    -0x1.f7fffffffffffp-4
  },
  { // Entry 1010
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    0x1.f80p-4
  },
  { // Entry 1011
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    -0x1.f80p-4
  },
  { // Entry 1012
    0x1.fc210055467fe54b48c3f135f6f29df7p-1,
    0x1.f800000000001p-4
  },
  { // Entry 1013
    0x1.fc210055467fe54b48c3f135f6f29df7p-1,
    -0x1.f800000000001p-4
  },
  { // Entry 1014
    0x1.f94984b2552e19e7329413b8c2e8dc51p-1,
    0x1.4bfffffffffffp-3
  },
  { // Entry 1015
    0x1.f94984b2552e19e7329413b8c2e8dc51p-1,
    -0x1.4bfffffffffffp-3
  },
  { // Entry 1016
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    0x1.4c0p-3
  },
  { // Entry 1017
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    -0x1.4c0p-3
  },
  { // Entry 1018
    0x1.f94984b2552e189ca658c51c42e907cep-1,
    0x1.4c00000000001p-3
  },
  { // Entry 1019
    0x1.f94984b2552e189ca658c51c42e907cep-1,
    -0x1.4c00000000001p-3
  },
  { // Entry 1020
    0x1.e921dd42f09ba868603ea376f6e2d012p-1,
    0x1.3333333333332p-2
  },
  { // Entry 1021
    0x1.e921dd42f09ba868603ea376f6e2d012p-1,
    -0x1.3333333333332p-2
  },
  { // Entry 1022
    0x1.e921dd42f09ba60b268bec1fb0878a42p-1,
    0x1.3333333333333p-2
  },
  { // Entry 1023
    0x1.e921dd42f09ba60b268bec1fb0878a42p-1,
    -0x1.3333333333333p-2
  },
  { // Entry 1024
    0x1.e921dd42f09ba3adecd934c86a0db254p-1,
    0x1.3333333333334p-2
  },
  { // Entry 1025
    0x1.e921dd42f09ba3adecd934c86a0db254p-1,
    -0x1.3333333333334p-2
  },
  { // Entry 1026
    0x1.8feedb86bf0ef3158f8a1dcbef49d123p-1,
    0x1.594317acc4ef8p-1
  },
  { // Entry 1027
    0x1.8feedb86bf0ef3158f8a1dcbef49d123p-1,
    -0x1.594317acc4ef8p-1
  },
  { // Entry 1028
    0x1.8feedb86bf0ee91817a64b28b79e5119p-1,
    0x1.594317acc4ef9p-1
  },
  { // Entry 1029
    0x1.8feedb86bf0ee91817a64b28b79e5119p-1,
    -0x1.594317acc4ef9p-1
  },
  { // Entry 1030
    0x1.8feedb86bf0edf1a9fc278857f8ed559p-1,
    0x1.594317acc4efap-1
  },
  { // Entry 1031
    0x1.8feedb86bf0edf1a9fc278857f8ed559p-1,
    -0x1.594317acc4efap-1
  },
  { // Entry 1032
    0x1.6b898fa9efb5dd6f9e17e3442d59b241p-1,
    0x1.8ffffffffffffp-1
  },
  { // Entry 1033
    0x1.6b898fa9efb5dd6f9e17e3442d59b241p-1,
    -0x1.8ffffffffffffp-1
  },
  { // Entry 1034
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    0x1.9p-1
  },
  { // Entry 1035
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    -0x1.9p-1
  },
  { // Entry 1036
    0x1.6b898fa9efb5c6e713c9cff8feb4918fp-1,
    0x1.9000000000001p-1
  },
  { // Entry 1037
    0x1.6b898fa9efb5c6e713c9cff8feb4918fp-1,
    -0x1.9000000000001p-1
  },
  { // Entry 1038
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 1039
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 1040
    0x1.p0,
    -0.0
  },
  { // Entry 1041
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 1042
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 1043
    0x1.ff621e3796d7de4a8ab7d7cd8488f499p-1,
    0x1.921fb54442d17p-5
  },
  { // Entry 1044
    0x1.ff621e3796d7de4a8ab7d7cd8488f499p-1,
    -0x1.921fb54442d17p-5
  },
  { // Entry 1045
    0x1.ff621e3796d7de3dfb04df46987f6450p-1,
    0x1.921fb54442d18p-5
  },
  { // Entry 1046
    0x1.ff621e3796d7de3dfb04df46987f6450p-1,
    -0x1.921fb54442d18p-5
  },
  { // Entry 1047
    0x1.ff621e3796d7de316b51e6bfac75542fp-1,
    0x1.921fb54442d19p-5
  },
  { // Entry 1048
    0x1.ff621e3796d7de316b51e6bfac75542fp-1,
    -0x1.921fb54442d19p-5
  },
  { // Entry 1049
    0x1.fd88da3d12525a208898cf58ded0eeb3p-1,
    0x1.921fb54442d17p-4
  },
  { // Entry 1050
    0x1.fd88da3d12525a208898cf58ded0eeb3p-1,
    -0x1.921fb54442d17p-4
  },
  { // Entry 1051
    0x1.fd88da3d125259ee594b5705767ab649p-1,
    0x1.921fb54442d18p-4
  },
  { // Entry 1052
    0x1.fd88da3d125259ee594b5705767ab649p-1,
    -0x1.921fb54442d18p-4
  },
  { // Entry 1053
    0x1.fd88da3d125259bc29fddeb20e228056p-1,
    0x1.921fb54442d19p-4
  },
  { // Entry 1054
    0x1.fd88da3d125259bc29fddeb20e228056p-1,
    -0x1.921fb54442d19p-4
  },
  { // Entry 1055
    0x1.f6297cff75cb03ab1fced6337e35a245p-1,
    0x1.921fb54442d17p-3
  },
  { // Entry 1056
    0x1.f6297cff75cb03ab1fced6337e35a245p-1,
    -0x1.921fb54442d17p-3
  },
  { // Entry 1057
    0x1.f6297cff75cb02e35a0cf2e64de60626p-1,
    0x1.921fb54442d18p-3
  },
  { // Entry 1058
    0x1.f6297cff75cb02e35a0cf2e64de60626p-1,
    -0x1.921fb54442d18p-3
  },
  { // Entry 1059
    0x1.f6297cff75cb021b944b0f991d8e9161p-1,
    0x1.921fb54442d19p-3
  },
  { // Entry 1060
    0x1.f6297cff75cb021b944b0f991d8e9161p-1,
    -0x1.921fb54442d19p-3
  },
  { // Entry 1061
    0x1.d906bcf328d46672d9c1a865898e5966p-1,
    0x1.921fb54442d17p-2
  },
  { // Entry 1062
    0x1.d906bcf328d46672d9c1a865898e5966p-1,
    -0x1.921fb54442d17p-2
  },
  { // Entry 1063
    0x1.d906bcf328d463631d6cd2905d4b13f5p-1,
    0x1.921fb54442d18p-2
  },
  { // Entry 1064
    0x1.d906bcf328d463631d6cd2905d4b13f5p-1,
    -0x1.921fb54442d18p-2
  },
  { // Entry 1065
    0x1.d906bcf328d460536117fcbb30ea3e17p-1,
    0x1.921fb54442d19p-2
  },
  { // Entry 1066
    0x1.d906bcf328d460536117fcbb30ea3e17p-1,
    -0x1.921fb54442d19p-2
  },
  { // Entry 1067
    0x1.6a09e667f3bcd777b6461376ab523242p-1,
    0x1.921fb54442d17p-1
  },
  { // Entry 1068
    0x1.6a09e667f3bcd777b6461376ab523242p-1
```