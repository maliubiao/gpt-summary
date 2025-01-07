Response:
The user wants to understand the purpose of the provided C code snippet, which is a part of Android's bionic library and located in a directory related to tangent function test data.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core function:** The code snippet is an array of structures. Each structure contains two floating-point numbers. The directory name `tan_intel_data.handroid` strongly suggests these are input/output pairs for testing the tangent function. The "intel" part might hint at specific optimizations or test cases relevant to Intel architectures. "handroid" likely indicates it's specifically for the Android environment.

2. **Infer the functionality:** Based on the above, the primary function of this data file is to provide test cases for the `tan()` function in Android's math library (`libm`). Each pair likely represents an input angle and its expected tangent value.

3. **Connect to Android functionality:** The `tan()` function is a standard mathematical function used in various parts of Android. Examples include:
    * **Graphics:** Calculating angles and transformations in 2D/3D rendering (e.g., `Canvas`, `OpenGL`).
    * **Sensors:**  Processing data from orientation sensors or accelerometers.
    * **Location:**  Calculations involving angles and distances.
    * **Animations:**  Defining motion paths and effects.

4. **Explain libc function implementation (tan()):** The `tan()` function in `libm` typically relies on:
    * **Argument reduction:** Reducing the input angle to a smaller range (usually within -pi/4 to pi/4) using trigonometric identities and the periodicity of the tangent function.
    * **Polynomial or rational approximation:** Approximating the tangent function within the reduced range using Taylor series or other polynomial/rational functions. Lookup tables might be used for initial approximations or to handle special cases.

5. **Address dynamic linker aspects (if applicable):**  In this *specific* code snippet (just data), the dynamic linker is not directly involved. The linker's role comes into play when the `libm.so` library containing the `tan()` implementation is loaded and its symbols are resolved by applications. A sample SO layout would involve the `libm.so` file containing the compiled `tan()` function and the necessary metadata for linking. The linking process would involve the dynamic linker (`linker` or `linker64`) mapping `libm.so` into memory and resolving the `tan` symbol when an application calls it.

6. **Consider logical reasoning and input/output:**  The data itself *is* the input and expected output for testing. For instance, if the input is `0x1.efdad938b4b0e834014bf56a7084675dp-4`, the expected output of the `tan()` function should be `-0x1.ed7424ba2aa4ep-4`.

7. **Identify common user/programming errors:**  Common errors when using `tan()` include:
    * **Input in degrees instead of radians:** The `tan()` function expects angles in radians.
    * **Input near pi/2 or its multiples:**  Tangent approaches infinity at these points, potentially leading to overflow or very large numbers.
    * **Incorrect data types:**  Passing integers instead of floating-point numbers.

8. **Explain how Android reaches this data:**
    * **Android Framework/NDK Call:**  An application using the NDK might call a function that internally uses `tan()`. For example, a graphics library or a physics engine.
    * **`libm` Call:** The application's compiled code will call the `tan()` function, which is part of `libm.so`.
    * **Test Execution:** During Android system testing or when developers run unit tests for `libm`, this data file is loaded. The test framework iterates through the entries, calls `tan()` with the input value, and compares the result with the expected output.

9. **Provide a Frida hook example:** A Frida hook can intercept calls to the `tan()` function and inspect the input and output values.

10. **Address the "归纳一下它的功能" (summarize its function) part:**  The primary function is to provide test data for the `tan()` function in `libm`.

11. **Structure the response:** Organize the information logically with clear headings and explanations for each point. Use code blocks for examples and formatting for clarity. Ensure the language is Chinese as requested.

**(Self-correction during the process):** Initially, I might have focused too much on the `tan()` function's implementation details. However, the question is primarily about the *data file's* purpose. Therefore, shifting the focus to its role in testing is crucial. Also, explicitly stating that the dynamic linker is not *directly* involved in this data file, but plays a role in the library loading, is important for clarity. Making sure to address all parts of the decomposed prompt is essential.
好的，让我们来归纳一下 `bionic/tests/math_data/tan_intel_data.handroid` 这个源代码文件的功能。

**功能归纳：**

这个 C 源代码文件定义了一个常量数组，该数组用于存储一系列预定义的**双精度浮点数**的输入值和对应的**正切函数**的预期输出值。  更具体地说，它为 `tan()` 函数提供了一组测试用例。

**详细解释：**

1. **测试数据：**  该文件本质上是一个测试数据集。数组中的每个元素都是一个结构体，包含两个 `double` 类型的成员。
   - 第一个 `double` 值是 `tan()` 函数的输入角度（以弧度表示）。
   - 第二个 `double` 值是对于给定输入角度，`tan()` 函数的**预期**返回值。

2. **用于测试 `tan()` 函数：**  该文件存在于 `bionic/tests` 目录下，这表明它的主要目的是用于测试 Android Bionic 库中的 `tan()` 函数的正确性和精度。

3. **`intel_data` 的含义：** 文件名中的 `intel_data` 可能暗示这个数据集是基于 Intel 处理器的特性或者是在 Intel 架构上生成的。这可能是因为浮点数运算在不同架构上可能会有细微的差异，因此需要针对特定架构进行测试。

4. **`.handroid` 的含义：** `.handroid` 后缀很可能表示这些测试数据是专门为 Android 平台准备的。

**与 Android 功能的关系举例：**

`tan()` 函数是 C 标准库 `<math.h>` 中的一部分，在 Android 系统中被广泛使用。以下是一些例子：

* **图形渲染 (Graphics Rendering)：** 在 Android 的图形框架中，例如使用 `Canvas` 或 `OpenGL ES` 进行 2D 或 3D 渲染时，`tan()` 函数可能用于计算角度、投影变换、旋转等。例如，计算视角矩阵时可能需要用到正切值。

* **传感器 (Sensors)：**  Android 设备中的传感器（如陀螺仪、加速度计）会产生角度或方向信息。在处理这些传感器数据时，可能需要使用 `tan()` 函数进行坐标转换或角度计算。

* **定位服务 (Location Services)：** 在地理定位相关的计算中，例如计算方位角或距离时，可能会用到三角函数，包括 `tan()`。

* **动画效果 (Animations)：** 在实现各种动画效果时，可能需要根据时间或其他参数计算角度，从而使用 `tan()` 函数。

**libc 函数 `tan()` 的功能是如何实现的：**

`tan()` 函数的实现通常涉及以下步骤：

1. **参数约减 (Argument Reduction)：**  由于 `tan()` 函数是周期函数（周期为 π），因此首先会将输入的角度约减到一个较小的区间，通常是 `[-π/4, π/4]`。这可以通过减去 π 的整数倍来实现。

2. **奇偶性处理 (Parity and Sign Handling)：**  利用 `tan(-x) = -tan(x)` 的性质处理负角度。

3. **特殊值处理 (Special Value Handling)：**
   - 如果输入接近 `π/2` 的奇数倍，`tan()` 的值会趋于无穷大，需要返回 `HUGE_VAL` 或类似的值，并设置 `errno`。
   - 如果输入为 0，则返回 0。

4. **多项式或有理逼近 (Polynomial or Rational Approximation)：** 在约减后的区间内，使用多项式或有理函数来逼近 `tan(x)` 的值。常用的方法包括：
   - **泰勒级数 (Taylor Series)：** 将 `tan(x)` 展开为泰勒级数的前几项进行逼近。
   - **切比雪夫逼近 (Chebyshev Approximation)：** 使用切比雪夫多项式进行更精确的逼近。
   - **有理逼近 (Rational Approximation)：** 使用两个多项式的比值来逼近 `tan(x)`。

5. **精度处理 (Precision Handling)：**  根据需要返回单精度 (`float`) 或双精度 (`double`) 的结果。

**涉及 dynamic linker 的功能：**

这个数据文件本身并不直接涉及 dynamic linker 的功能。Dynamic linker 的作用在于加载共享库，并解析和链接库中的符号。

**SO 布局样本 (针对 `libm.so`)：**

```
libm.so:
  .dynsym:  # 动态符号表
    ...
    符号: tan
    类型: 函数
    地址: 0x... # tan 函数的入口地址
    ...
  .text:    # 代码段
    0x...:  # tan 函数的机器码指令
      ...
  .rodata:  # 只读数据段
    ...     # 可能包含 tan 函数使用的常量
```

**链接的处理过程：**

1. **编译时：** 当应用程序的代码调用 `tan()` 函数时，编译器会生成一个对外部符号 `tan` 的引用。

2. **链接时：**
   - **静态链接（不常见于 Android 的 `libm`）：**  如果静态链接，链接器会将 `libm.a` 中 `tan()` 函数的目标代码直接复制到应用程序的可执行文件中。
   - **动态链接（Android 的情况）：**  链接器会在应用程序的可执行文件中记录对 `libm.so` 中 `tan` 符号的依赖。

3. **运行时：**
   - 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载所有需要的共享库，包括 `libm.so`。
   - Dynamic linker 会解析应用程序中对 `tan` 符号的引用，并在 `libm.so` 的动态符号表 `.dynsym` 中查找 `tan` 符号的地址。
   - Dynamic linker 会将应用程序中对 `tan` 的调用重定向到 `libm.so` 中 `tan()` 函数的实际地址。这个过程被称为**符号解析 (Symbol Resolution)** 或**重定位 (Relocation)**。

**假设输入与输出：**

文件中的每一行 ` { 输入值, 输出值 }, `  就是一个假设的输入和输出。例如：

* **假设输入：** `0x1.efdad938b4b0e834014bf56a7084675dp-4`  (这是一个十六进制浮点数表示，相当于十进制的某个小数)
* **预期输出：** `-0x1.ed7424ba2aa4ep-4`

**用户或编程常见的使用错误：**

1. **输入角度单位错误：**  `tan()` 函数期望输入的是弧度值，但用户可能误输入了角度值。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double angle_degrees = 45.0;
       // 错误：直接将角度值传递给 tan()
       double result_wrong = tan(angle_degrees);
       printf("Wrong result: tan(45 degrees) = %f\n", result_wrong);

       // 正确：将角度转换为弧度
       double angle_radians = angle_degrees * M_PI / 180.0;
       double result_correct = tan(angle_radians);
       printf("Correct result: tan(45 degrees) = %f\n", result_correct);
       return 0;
   }
   ```

2. **输入值接近 π/2 的奇数倍：** 当输入值接近 `π/2`, `3π/2`, `5π/2` 等时，`tan()` 函数的值会趋于无穷大，可能导致溢出或得到非常大的结果。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double angle_near_pi_over_2 = M_PI / 2.0 - 0.00001;
       double result = tan(angle_near_pi_over_2);
       printf("tan(angle near pi/2) = %f\n", result); // 结果会非常大
       return 0;
   }
   ```

3. **未包含头文件：**  使用 `tan()` 函数需要包含 `<math.h>` 头文件。
   ```c
   // 错误：缺少 math.h
   #include <stdio.h>

   int main() {
       double x = 1.0;
       // 编译错误：tan 未声明
       double result = tan(x);
       printf("%f\n", result);
       return 0;
   }
   ```

**Android framework or ndk 是如何一步步的到达这里：**

1. **Android Framework 或 NDK 调用：**  应用程序（Java 或 Native 代码）可能需要进行三角函数计算。
   - **Java 代码：**  可能会调用 `java.lang.Math.tan()` 方法。`java.lang.Math` 中的许多方法最终会委托给 Native 代码实现。
   - **NDK 代码 (C/C++)：** 会直接调用 `<math.h>` 中声明的 `tan()` 函数。

2. **调用 `libm.so` 中的 `tan()`：**  当 Native 代码调用 `tan()` 时，实际上调用的是 Android Bionic 库 (`libc.so` 或其链接的库，如 `libm.so`) 中提供的 `tan()` 实现。

3. **`tan()` 函数的执行：**  `libm.so` 中的 `tan()` 函数会根据其内部实现（参数约减、多项式逼近等）计算结果。

4. **测试数据的加载和使用：**
   - 在 Android 系统的编译和测试阶段，为了确保 `libm.so` 中 `tan()` 函数的正确性，会运行相关的测试程序。
   - 这些测试程序会加载 `bionic/tests/math_data/tan_intel_data.handroid` 文件中定义的测试数据。
   - 测试程序会遍历数组中的每一项，将输入值传递给 `tan()` 函数，并将 `tan()` 函数的实际返回值与数组中存储的预期输出值进行比较，以验证 `tan()` 函数的实现是否正确。

**Frida hook 示例调试步骤：**

可以使用 Frida hook 来拦截对 `tan()` 函数的调用，查看输入参数和返回值。

**Frida Hook 脚本 (Python)：**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python frida_tan_hook.py <process_name_or_pid>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libm.so", "tan"), {
        onEnter: function(args) {
            this.input = args[0];
            console.log("[+] Calling tan with input: " + this.input);
        },
        onLeave: function(retval) {
            console.log("[+] tan returned: " + retval + " for input: " + this.input);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Hooking tan function. Press Ctrl+C to stop.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤：**

1. **保存脚本：** 将上面的 Python 代码保存为 `frida_tan_hook.py`。
2. **运行 Android 应用：** 运行你想要监控的，可能会调用 `tan()` 函数的 Android 应用。
3. **查找进程名或 PID：** 使用 `adb shell ps | grep <your_app_package_name>` 找到目标应用的进程名或 PID。
4. **运行 Frida 脚本：** 在你的电脑上运行 Frida hook 脚本：
   ```bash
   python frida_tan_hook.py <process_name_or_pid>
   ```
   将 `<process_name_or_pid>` 替换为实际的进程名或 PID。
5. **查看输出：** 当目标应用调用 `tan()` 函数时，Frida 脚本会在终端输出输入参数和返回值。

这个 Frida 示例会拦截对 `libm.so` 中 `tan` 函数的调用，并在函数进入和退出时打印相关信息，帮助你调试 `tan()` 函数的使用情况。

总而言之，`bionic/tests/math_data/tan_intel_data.handroid` 是 Android Bionic 库中用于测试 `tan()` 函数正确性的一个数据文件，包含了预定义的输入输出对。它在 Android 系统的开发和测试中扮演着重要的角色，确保了数学库的可靠性。

Prompt: 
```
这是目录为bionic/tests/math_data/tan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共4部分，请归纳一下它的功能

"""
0x1.efdad938b4b0e834014bf56a7084675dp-4,
    -0x1.ed7424ba2aa4ep-4
  },
  { // Entry 358
    0x1.da347607948f47ffef21697161fd3cddp-1,
    0x1.ee9eda5890390p499
  },
  { // Entry 359
    -0x1.da347607948f47ffef21697161fd3cddp-1,
    -0x1.ee9eda5890390p499
  },
  { // Entry 360
    0x1.f682d27a8be87f783d494857b6f30e05p0,
    0x1.f4ff0d7b3ac10p100
  },
  { // Entry 361
    -0x1.f682d27a8be87f783d494857b6f30e05p0,
    -0x1.f4ff0d7b3ac10p100
  },
  { // Entry 362
    -0x1.ffd36a753ced9027c93845adde046246p-1,
    0x1.f5a814afd69f5p119
  },
  { // Entry 363
    0x1.ffd36a753ced9027c93845adde046246p-1,
    -0x1.f5a814afd69f5p119
  },
  { // Entry 364
    -0x1.0fa7701d059b51de05df58ade26bec5cp-9,
    0x1.f8fc824d2693bp61
  },
  { // Entry 365
    0x1.0fa7701d059b51de05df58ade26bec5cp-9,
    -0x1.f8fc824d2693bp61
  },
  { // Entry 366
    -0x1.afe3875bd3afe801f149d0a9ad36f453p-4,
    0x1.f9be6f9be6f98p9
  },
  { // Entry 367
    0x1.afe3875bd3afe801f149d0a9ad36f453p-4,
    -0x1.f9be6f9be6f98p9
  },
  { // Entry 368
    0x1.fd1032e82deab7baba99c913dee10b9ap-4,
    0x1.fa775cd264f43p-4
  },
  { // Entry 369
    -0x1.fd1032e82deab7baba99c913dee10b9ap-4,
    -0x1.fa775cd264f43p-4
  },
  { // Entry 370
    0x1.fea8c67dd46ca83ca49ab9ecd0360739p-4,
    0x1.fc09b47402d82p-4
  },
  { // Entry 371
    -0x1.fea8c67dd46ca83ca49ab9ecd0360739p-4,
    -0x1.fc09b47402d82p-4
  },
  { // Entry 372
    -0x1.9020caf18a87438127a85d1f0a3d4205p-1,
    0x1.feeffffffffc6p995
  },
  { // Entry 373
    0x1.9020caf18a87438127a85d1f0a3d4205p-1,
    -0x1.feeffffffffc6p995
  },
  { // Entry 374
    0x1.af135beb0f2817fba77204a5b1b6766bp0,
    0x1.ff01fffffffffp7
  },
  { // Entry 375
    -0x1.af135beb0f2817fba77204a5b1b6766bp0,
    -0x1.ff01fffffffffp7
  },
  { // Entry 376
    -0x1.fd97532efd89b26bc294b27e0a1956b9p3,
    0x1.ff8ffffffffffp540
  },
  { // Entry 377
    0x1.fd97532efd89b26bc294b27e0a1956b9p3,
    -0x1.ff8ffffffffffp540
  },
  { // Entry 378
    -0x1.cc32cb933818111e6ddf00c5c79cbc88p-1,
    0x1.ff8ffffffffffp870
  },
  { // Entry 379
    0x1.cc32cb933818111e6ddf00c5c79cbc88p-1,
    -0x1.ff8ffffffffffp870
  },
  { // Entry 380
    -0x1.8659d3e2b52b880668ac8b4b9fae9538p-1,
    0x1.ffc10p9
  },
  { // Entry 381
    0x1.8659d3e2b52b880668ac8b4b9fae9538p-1,
    -0x1.ffc10p9
  },
  { // Entry 382
    -0x1.b66066fb812ee27dbb623a1a1353e062p-2,
    0x1.ffcfff8p19
  },
  { // Entry 383
    0x1.b66066fb812ee27dbb623a1a1353e062p-2,
    -0x1.ffcfff8p19
  },
  { // Entry 384
    -0x1.520ebd32e1d8ecd38bfcd6a57e1a377fp1,
    0x1.ffcfff8p365
  },
  { // Entry 385
    0x1.520ebd32e1d8ecd38bfcd6a57e1a377fp1,
    -0x1.ffcfff8p365
  },
  { // Entry 386
    0x1.489813c24d13b00ab69627d858bb63b5p0,
    0x1.ffcffffffff6cp720
  },
  { // Entry 387
    -0x1.489813c24d13b00ab69627d858bb63b5p0,
    -0x1.ffcffffffff6cp720
  },
  { // Entry 388
    0x1.413e63f7dd607ef3c8422a490af2dc30p0,
    0x1.ffcfffffffff9p320
  },
  { // Entry 389
    -0x1.413e63f7dd607ef3c8422a490af2dc30p0,
    -0x1.ffcfffffffff9p320
  },
  { // Entry 390
    -0x1.fc3928a39b65284d4c7ef3b6a2edc8f1p-2,
    0x1.ffcffffffffffp990
  },
  { // Entry 391
    0x1.fc3928a39b65284d4c7ef3b6a2edc8f1p-2,
    -0x1.ffcffffffffffp990
  },
  { // Entry 392
    -0x1.9ad70d284f16d59dcaa0ab9fb77d7490p-1,
    0x1.ffeffffffffccp995
  },
  { // Entry 393
    0x1.9ad70d284f16d59dcaa0ab9fb77d7490p-1,
    -0x1.ffeffffffffccp995
  },
  { // Entry 394
    0x1.aad6effcb6783826de7b24dba501c11cp-3,
    0x1.ffefffffffffdp366
  },
  { // Entry 395
    -0x1.aad6effcb6783826de7b24dba501c11cp-3,
    -0x1.ffefffffffffdp366
  },
  { // Entry 396
    0x1.c88645f9d119ec2030724a4ce4e6ebbap2,
    0x1.ffeffffffffffp180
  },
  { // Entry 397
    -0x1.c88645f9d119ec2030724a4ce4e6ebbap2,
    -0x1.ffeffffffffffp180
  },
  { // Entry 398
    0x1.131aa7b9d4aa07ff5840ac1e8fb42360p2,
    0x1.ffeffffffffffp231
  },
  { // Entry 399
    -0x1.131aa7b9d4aa07ff5840ac1e8fb42360p2,
    -0x1.ffeffffffffffp231
  },
  { // Entry 400
    0x1.f671719be50d1d4debe85c922e1e2913p-3,
    0x1.ffeffffffffffp1019
  },
  { // Entry 401
    -0x1.f671719be50d1d4debe85c922e1e2913p-3,
    -0x1.ffeffffffffffp1019
  },
  { // Entry 402
    0x1.ff078a2d2d871ac1f32765e9db644eb1p-1,
    0x1.fff1fffffffffp40
  },
  { // Entry 403
    -0x1.ff078a2d2d871ac1f32765e9db644eb1p-1,
    -0x1.fff1fffffffffp40
  },
  { // Entry 404
    0x1.0784b04fc42a59e77f85d9967da6775dp9,
    0x1.fff1fffffffffp41
  },
  { // Entry 405
    -0x1.0784b04fc42a59e77f85d9967da6775dp9,
    -0x1.fff1fffffffffp41
  },
  { // Entry 406
    0x1.8eb22dd167a37ad21ddf1e69734e9ce2p0,
    0x1.fffff1fffffffp-1
  },
  { // Entry 407
    -0x1.8eb22dd167a37ad21ddf1e69734e9ce2p0,
    -0x1.fffff1fffffffp-1
  },
  { // Entry 408
    -0x1.22e7346fd3dda553b146c37f61127a4cp1,
    0x1.ffffff8p119
  },
  { // Entry 409
    0x1.22e7346fd3dda553b146c37f61127a4cp1,
    -0x1.ffffff8p119
  },
  { // Entry 410
    -0x1.db0b3b019f175bed5bcf1a5602db00afp-3,
    0x1.ffffff8p192
  },
  { // Entry 411
    0x1.db0b3b019f175bed5bcf1a5602db00afp-3,
    -0x1.ffffff8p192
  },
  { // Entry 412
    0x1.06b6bede910257f315a5083a9ab2b650p-1,
    0x1.ffffff8p543
  },
  { // Entry 413
    -0x1.06b6bede910257f315a5083a9ab2b650p-1,
    -0x1.ffffff8p543
  },
  { // Entry 414
    -0x1.40f02a15dfa3d7ff3e2a4553f19cb2d0p1,
    0x1.ffffffffbbfffp40
  },
  { // Entry 415
    0x1.40f02a15dfa3d7ff3e2a4553f19cb2d0p1,
    -0x1.ffffffffbbfffp40
  },
  { // Entry 416
    0x1.ab60112ef4fddff3f5a2690c7d3ea6efp-2,
    0x1.fffffffff7fffp231
  },
  { // Entry 417
    -0x1.ab60112ef4fddff3f5a2690c7d3ea6efp-2,
    -0x1.fffffffff7fffp231
  },
  { // Entry 418
    0x1.35a9929eeafd70f0712abe2a511854a1p0,
    0x1.fffffffffff78p920
  },
  { // Entry 419
    -0x1.35a9929eeafd70f0712abe2a511854a1p0,
    -0x1.fffffffffff78p920
  },
  { // Entry 420
    0x1.4630298f3b993287205dc0b89b0601e0p0,
    0x1.fffffffffffd5p995
  },
  { // Entry 421
    -0x1.4630298f3b993287205dc0b89b0601e0p0,
    -0x1.fffffffffffd5p995
  },
  { // Entry 422
    -0x1.9472e045129fdba63791712416ec9613p-1,
    0x1.fffffffffffe8p720
  },
  { // Entry 423
    0x1.9472e045129fdba63791712416ec9613p-1,
    -0x1.fffffffffffe8p720
  },
  { // Entry 424
    0x1.42e586daa1b428fc0580888f2fc46893p0,
    0x1.fffffffffffebp920
  },
  { // Entry 425
    -0x1.42e586daa1b428fc0580888f2fc46893p0,
    -0x1.fffffffffffebp920
  },
  { // Entry 426
    -0x1.bfc436b94374b5f16b60ea69cd883992p-1,
    0x1.ffffffffffff1p245
  },
  { // Entry 427
    0x1.bfc436b94374b5f16b60ea69cd883992p-1,
    -0x1.ffffffffffff1p245
  },
  { // Entry 428
    0x1.35117d4a4f1e4bb22fdd03164a364ccfp0,
    0x1.ffffffffffff4p845
  },
  { // Entry 429
    -0x1.35117d4a4f1e4bb22fdd03164a364ccfp0,
    -0x1.ffffffffffff4p845
  },
  { // Entry 430
    -0x1.bfdd9292798aaa789c3df0df7729835ap-1,
    0x1.ffffffffffff4p1020
  },
  { // Entry 431
    0x1.bfdd9292798aaa789c3df0df7729835ap-1,
    -0x1.ffffffffffff4p1020
  },
  { // Entry 432
    -0x1.9b768ccdae6ebb70b45ac14e92b3d5c8p9,
    0x1.ffffffffffffcp45
  },
  { // Entry 433
    0x1.9b768ccdae6ebb70b45ac14e92b3d5c8p9,
    -0x1.ffffffffffffcp45
  },
  { // Entry 434
    0x1.feca047f2730f7395d95f469ccb5a5d3p-1,
    0x1.ffffffffffffcp474
  },
  { // Entry 435
    -0x1.feca047f2730f7395d95f469ccb5a5d3p-1,
    -0x1.ffffffffffffcp474
  },
  { // Entry 436
    -0x1.449f15cc945597ff58f2426acbff9c62p-2,
    0x1.ffffffffffffcp976
  },
  { // Entry 437
    0x1.449f15cc945597ff58f2426acbff9c62p-2,
    -0x1.ffffffffffffcp976
  },
  { // Entry 438
    0x1.fffc58da07951cbe22c96d73b1289e1ep-2,
    0x1.ffffffffffffep881
  },
  { // Entry 439
    -0x1.fffc58da07951cbe22c96d73b1289e1ep-2,
    -0x1.ffffffffffffep881
  },
  { // Entry 440
    -0x1.c1c9195ec23aa64df145dd269cd895e8p-1,
    0x1.ffffffffffffep970
  },
  { // Entry 441
    0x1.c1c9195ec23aa64df145dd269cd895e8p-1,
    -0x1.ffffffffffffep970
  },
  { // Entry 442
    0x1.3cc1ed3906d2f7fdd633cf4eb06f3f19p-2,
    0x1.33328c1b37321p-2
  },
  { // Entry 443
    -0x1.3cc1ed3906d2f7fdd633cf4eb06f3f19p-2,
    -0x1.33328c1b37321p-2
  },
  { // Entry 444
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 445
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 446
    -0.0,
    -0.0
  },
  { // Entry 447
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 448
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 449
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 450
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 451
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 452
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 453
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 454
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 455
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 456
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 457
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 458
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 459
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 460
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 461
    0x1.999999f0fb38c6122a1fa8e043bb07c2p-13,
    0x1.999999999999ap-13
  },
  { // Entry 462
    -0x1.999999f0fb38c6122a1fa8e043bb07c2p-13,
    -0x1.999999999999ap-13
  },
  { // Entry 463
    0x1.99999af7201744b823e5b270fd1aa39dp-12,
    0x1.999999999999ap-12
  },
  { // Entry 464
    -0x1.99999af7201744b823e5b270fd1aa39dp-12,
    -0x1.999999999999ap-12
  },
  { // Entry 465
    0x1.33333581062a38f04df024142ddaa05dp-11,
    0x1.3333333333334p-11
  },
  { // Entry 466
    -0x1.33333581062a38f04df024142ddaa05dp-11,
    -0x1.3333333333334p-11
  },
  { // Entry 467
    0x1.99999f0fb3a0f9d88738be2ff7af9aaap-11,
    0x1.999999999999ap-11
  },
  { // Entry 468
    -0x1.99999f0fb3a0f9d88738be2ff7af9aaap-11,
    -0x1.999999999999ap-11
  },
  { // Entry 469
    0x1.000005555577777854854dedc28ead51p-10,
    0x1.0p-10
  },
  { // Entry 470
    -0x1.000005555577777854854dedc28ead51p-10,
    -0x1.0p-10
  },
  { // Entry 471
    0x1.33333c6a7f4ec73853151cd76b79e135p-10,
    0x1.3333333333333p-10
  },
  { // Entry 472
    -0x1.33333c6a7f4ec73853151cd76b79e135p-10,
    -0x1.3333333333333p-10
  },
  { // Entry 473
    0x1.66667508e0a1b502287034d36bf4e3d5p-10,
    0x1.6666666666666p-10
  },
  { // Entry 474
    -0x1.66667508e0a1b502287034d36bf4e3d5p-10,
    -0x1.6666666666666p-10
  },
  { // Entry 475
    0x1.9999af7202c366f1e0b548a31c41d210p-10,
    0x1.9999999999999p-10
  },
  { // Entry 476
    -0x1.9999af7202c366f1e0b548a31c41d210p-10,
    -0x1.9999999999999p-10
  },
  { // Entry 477
    0x1.ccccebe76f102ff633c5f02a34076687p-10,
    0x1.cccccccccccccp-10
  },
  { // Entry 478
    -0x1.ccccebe76f102ff633c5f02a34076687p-10,
    -0x1.cccccccccccccp-10
  },
  { // Entry 479
    0x1.0667d5fcf3d078f940687eb974310fb9p-7,
    0x1.0666666666666p-7
  },
  { // Entry 480
    -0x1.0667d5fcf3d078f940687eb974310fb9p-7,
    -0x1.0666666666666p-7
  },
  { // Entry 481
    0x1.ccd4939d0ccd7646b3f81b7553675c23p-7,
    0x1.cccccccccccccp-7
  },
  { // Entry 482
    -0x1.ccd4939d0ccd7646b3f81b7553675c23p-7,
    -0x1.cccccccccccccp-7
  },
  { // Entry 483
    0x1.49a4fc02ad193e8e94c4b2429190b5b2p-6,
    0x1.4999999999999p-6
  },
  { // Entry 484
    -0x1.49a4fc02ad193e8e94c4b2429190b5b2p-6,
    -0x1.4999999999999p-6
  },
  { // Entry 485
    0x1.ace5ded5f6be698f56697ac761f3dc69p-6,
    0x1.accccccccccccp-6
  },
  { // Entry 486
    -0x1.ace5ded5f6be698f56697ac761f3dc69p-6,
    -0x1.accccccccccccp-6
  },
  { // Entry 487
    0x1.081767fd3cb685f7b069146ce3333851p-5,
    0x1.080p-5
  },
  { // Entry 488
    -0x1.081767fd3cb685f7b069146ce3333851p-5,
    -0x1.080p-5
  },
  { // Entry 489
    0x1.39c0d6dea66fb6d286d403c292527356p-5,
    0x1.399999999999ap-5
  },
  { // Entry 490
    -0x1.39c0d6dea66fb6d286d403c292527356p-5,
    -0x1.399999999999ap-5
  },
  { // Entry 491
    0x1.6b702b954bc1d583c4a46773c2c2a15dp-5,
    0x1.6b33333333334p-5
  },
  { // Entry 492
    -0x1.6b702b954bc1d583c4a46773c2c2a15dp-5,
    -0x1.6b33333333334p-5
  },
  { // Entry 493
    0x1.9d265618dd0c688e049c61090d3e3fe2p-5,
    0x1.9cccccccccccep-5
  },
  { // Entry 494
    -0x1.9d265618dd0c688e049c61090d3e3fe2p-5,
    -0x1.9cccccccccccep-5
  },
  { // Entry 495
    0x1.cee446e4cfd4be6900f4b906ca9725b1p-5,
    0x1.ce66666666666p-5
  },
  { // Entry 496
    -0x1.cee446e4cfd4be6900f4b906ca9725b1p-5,
    -0x1.ce66666666666p-5
  },
  { // Entry 497
    0x1.a1eaedd5a4313e9d08bc7bb17a22531fp-1,
    0x1.5e7fc4369bdadp-1
  },
  { // Entry 498
    -0x1.a1eaedd5a4313e9d08bc7bb17a22531fp-1,
    -0x1.5e7fc4369bdadp-1
  },
  { // Entry 499
    0x1.d93b8aad424de0e43fb04d6781be81a3p1,
    0x1.4e7fc4369bdadp0
  },
  { // Entry 500
    -0x1.d93b8aad424de0e43fb04d6781be81a3p1,
    -0x1.4e7fc4369bdadp0
  },
  { // Entry 501
    -0x1.563acf158c2eb678d71be31e0f34754dp1,
    0x1.edbfa651e9c84p0
  },
  { // Entry 502
    0x1.563acf158c2eb678d71be31e0f34754dp1,
    -0x1.edbfa651e9c84p0
  },
  { // Entry 503
    -0x1.576b77609f0890313c371a0a2c582145p-1,
    0x1.467fc4369bdadp1
  },
  { // Entry 504
    0x1.576b77609f0890313c371a0a2c582145p-1,
    -0x1.467fc4369bdadp1
  },
  { // Entry 505
    0x1.00155777aebf6ad41b39a808ed5c3384p-5,
    0x1.961fb54442d18p1
  },
  { // Entry 506
    -0x1.00155777aebf6ad41b39a808ed5c3384p-5,
    -0x1.961fb54442d18p1
  },
  { // Entry 507
    0x1.87e9966e7d22d348fec6c95f851775f4p-1,
    0x1.e5bfa651e9c83p1
  },
  { // Entry 508
    -0x1.87e9966e7d22d348fec6c95f851775f4p-1,
    -0x1.e5bfa651e9c83p1
  },
  { // Entry 509
    0x1.a49e7d8987850f9ca5b9332e39dcd88fp1,
    0x1.1aafcbafc85f7p2
  },
  { // Entry 510
    -0x1.a49e7d8987850f9ca5b9332e39dcd88fp1,
    -0x1.1aafcbafc85f7p2
  },
  { // Entry 511
    -0x1.79ced8156d040edde5a6ab62255e2261p1,
    0x1.427fc4369bdadp2
  },
  { // Entry 512
    0x1.79ced8156d040edde5a6ab62255e2261p1,
    -0x1.427fc4369bdadp2
  },
  { // Entry 513
    -0x1.6f1f65cd1e91b5e5ec1e120e9e0ddc0ap-1,
    0x1.6a4fbcbd6f562p2
  },
  { // Entry 514
    0x1.6f1f65cd1e91b5e5ec1e120e9e0ddc0ap-1,
    -0x1.6a4fbcbd6f562p2
  },
  { // Entry 515
    -0x1.67747d5f844e1b0c503d51e7ba032ffcp-1,
    0x1.6af2eff0a2896p2
  },
  { // Entry 516
    0x1.67747d5f844e1b0c503d51e7ba032ffcp-1,
    -0x1.6af2eff0a2896p2
  },
  { // Entry 517
    -0x1.626a258815d1823506d17069130eb9fbp1,
    0x1.43c62a9d02414p2
  },
  { // Entry 518
    0x1.626a258815d1823506d17069130eb9fbp1,
    -0x1.43c62a9d02414p2
  },
  { // Entry 519
    0x1.d6adaf80f8b051fbc7ab9f2e09e8e608p1,
    0x1.1c99654961f92p2
  },
  { // Entry 520
    -0x1.d6adaf80f8b051fbc7ab9f2e09e8e608p1,
    -0x1.1c99654961f92p2
  },
  { // Entry 521
    0x1.a94d1b21370d52bfcd9ec417e41d6e5bp-1,
    0x1.ead93feb8361fp1
  },
  { // Entry 522
    -0x1.a94d1b21370d52bfcd9ec417e41d6e5bp-1,
    -0x1.ead93feb8361fp1
  },
  { // Entry 523
    0x1.4cba9e78222340ca493f803bbc947659p-4,
    0x1.9c7fb54442d1ap1
  },
  { // Entry 524
    -0x1.4cba9e78222340ca493f803bbc947659p-4,
    -0x1.9c7fb54442d1ap1
  },
  { // Entry 525
    -0x1.2cb6d02634531a6839bf898cc1f918dep-1,
    0x1.4e262a9d02415p1
  },
  { // Entry 526
    0x1.2cb6d02634531a6839bf898cc1f918dep-1,
    -0x1.4e262a9d02415p1
  },
  { // Entry 527
    -0x1.18d9112308d5b897ba44cfc5c4437317p1,
    0x1.ff993feb83620p0
  },
  { // Entry 528
    0x1.18d9112308d5b897ba44cfc5c4437317p1,
    -0x1.ff993feb83620p0
  },
  { // Entry 529
    0x1.56fe0145cf2901975829ddc3fc786df0p2,
    0x1.62e62a9d02416p0
  },
  { // Entry 530
    -0x1.56fe0145cf2901975829ddc3fc786df0p2,
    -0x1.62e62a9d02416p0
  },
  { // Entry 531
    0x1.f4ad353aca453f62beae01cd5b13d50dp-1,
    0x1.8c662a9d02419p-1
  },
  { // Entry 532
    -0x1.f4ad353aca453f62beae01cd5b13d50dp-1,
    -0x1.8c662a9d02419p-1
  },
  { // Entry 533
    0x1.6a7e1f6407ee61397d016d691bb61d17p3,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 534
    -0x1.6a7e1f6407ee61397d016d691bb61d17p3,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 535
    0x1.0d718cfc82464536bfd621be419f007cp6,
    -0x1.95ec8b9e03d54p0
  },
  { // Entry 536
    -0x1.0d718cfc82464536bfd621be419f007cp6,
    0x1.95ec8b9e03d54p0
  },
  { // Entry 537
    -0x1.11d87146c2d5a1832c24f3d87052d7ebp4,
    -0x1.832efa2a435a9p0
  },
  { // Entry 538
    0x1.11d87146c2d5a1832c24f3d87052d7ebp4,
    0x1.832efa2a435a9p0
  },
  { // Entry 539
    -0x1.e3a3729b3e86e2221fa5f04abf699e6ep2,
    -0x1.707168b682dfep0
  },
  { // Entry 540
    0x1.e3a3729b3e86e2221fa5f04abf699e6ep2,
    0x1.707168b682dfep0
  },
  { // Entry 541
    -0x1.3429e61a5d1f2e80fbd1370d4a7c2b10p2,
    -0x1.5db3d742c2653p0
  },
  { // Entry 542
    0x1.3429e61a5d1f2e80fbd1370d4a7c2b10p2,
    0x1.5db3d742c2653p0
  },
  { // Entry 543
    -0x1.c08caec5cf99725e57c32766fb084c5fp1,
    -0x1.4af645cf01ea8p0
  },
  { // Entry 544
    0x1.c08caec5cf99725e57c32766fb084c5fp1,
    0x1.4af645cf01ea8p0
  },
  { // Entry 545
    -0x1.5d603d751767ee70e9a2ff54959fa4a7p1,
    -0x1.3838b45b416fdp0
  },
  { // Entry 546
    0x1.5d603d751767ee70e9a2ff54959fa4a7p1,
    0x1.3838b45b416fdp0
  },
  { // Entry 547
    -0x1.1b48a35b1b277effabd7278b525708edp1,
    -0x1.257b22e780f52p0
  },
  { // Entry 548
    0x1.1b48a35b1b277effabd7278b525708edp1,
    0x1.257b22e780f52p0
  },
  { // Entry 549
    -0x1.d74caf9912dc7d9669b00926aa1ade11p0,
    -0x1.12bd9173c07abp0
  },
  { // Entry 550
    0x1.d74caf9912dc7d9669b00926aa1ade11p0,
    0x1.12bd9173c07abp0
  },
  { // Entry 551
    -0x1.6be702e1f6cd60bfd86ad86180d18490p0,
    -0x1.ea5c3ed5b3850p-1
  },
  { // Entry 552
    0x1.6be702e1f6cd60bfd86ad86180d18490p0,
    0x1.ea5c3ed5b3850p-1
  },
  { // Entry 553
    -0x1.4d0df1fc1d3484b027537d8117a395f4p0,
    -0x1.d4b87dab670a0p-1
  },
  { // Entry 554
    0x1.4d0df1fc1d3484b027537d8117a395f4p0,
    0x1.d4b87dab670a0p-1
  },
  { // Entry 555
    -0x1.316c8b068a7af257f1e5a51943834f3ep0,
    -0x1.bf14bc811a8f0p-1
  },
  { // Entry 556
    0x1.316c8b068a7af257f1e5a51943834f3ep0,
    0x1.bf14bc811a8f0p-1
  },
  { // Entry 557
    -0x1.1872a1aaa7e26cf417e6331617ea7dd0p0,
    -0x1.a970fb56ce140p-1
  },
  { // Entry 558
    0x1.1872a1aaa7e26cf417e6331617ea7dd0p0,
    0x1.a970fb56ce140p-1
  },
  { // Entry 559
    -0x1.01aeeed04cbb0dfacd1d00c657d08b19p0,
    -0x1.93cd3a2c81990p-1
  },
  { // Entry 560
    0x1.01aeeed04cbb0dfacd1d00c657d08b19p0,
    0x1.93cd3a2c81990p-1
  },
  { // Entry 561
    -0x1.d98e408ac2085c4e0588df10ba7fb023p-1,
    -0x1.7e297902351e0p-1
  },
  { // Entry 562
    0x1.d98e408ac2085c4e0588df10ba7fb023p-1,
    0x1.7e297902351e0p-1
  },
  { // Entry 563
    -0x1.b2e4750631c53c54f5830fd41753d427p-1,
    -0x1.6885b7d7e8a30p-1
  },
  { // Entry 564
    0x1.b2e4750631c53c54f5830fd41753d427p-1,
    0x1.6885b7d7e8a30p-1
  },
  { // Entry 565
    -0x1.8ee916392e04590ce988d82cc3959021p-1,
    -0x1.52e1f6ad9c280p-1
  },
  { // Entry 566
    0x1.8ee916392e04590ce988d82cc3959021p-1,
    0x1.52e1f6ad9c280p-1
  },
  { // Entry 567
    -0x1.6d395e495f77e709842592e226607b53p-1,
    -0x1.3d3e35834fad0p-1
  },
  { // Entry 568
    0x1.6d395e495f77e709842592e226607b53p-1,
    0x1.3d3e35834fad0p-1
  },
  { // Entry 569
    -0x1.24e3e017a098ecf4de48bceeb026743ap-1,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 570
    0x1.24e3e017a098ecf4de48bceeb026743ap-1,
    0x1.0a0b02501c799p-1
  },
  { // Entry 571
    -0x1.fdbd5f0596bdc6ef8da53ee652b57cf7p-2,
    -0x1.d8f7208e6b82cp-2
  },
  { // Entry 572
    0x1.fdbd5f0596bdc6ef8da53ee652b57cf7p-2,
    0x1.d8f7208e6b82cp-2
  },
  { // Entry 573
    -0x1.b5f3d6afbe6f259af37c4e633ab5fdfap-2,
    -0x1.9dd83c7c9e126p-2
  },
  { // Entry 574
    0x1.b5f3d6afbe6f259af37c4e633ab5fdfap-2,
    0x1.9dd83c7c9e126p-2
  },
  { // Entry 575
    -0x1.71a0f98081ea98b5f30a1593e3fc6373p-2,
    -0x1.62b9586ad0a20p-2
  },
  { // Entry 576
    0x1.71a0f98081ea98b5f30a1593e3fc6373p-2,
    0x1.62b9586ad0a20p-2
  },
  { // Entry 577
    -0x1.301909a2c36e89a67528a38c77ac9e43p-2,
    -0x1.279a74590331ap-2
  },
  { // Entry 578
    0x1.301909a2c36e89a67528a38c77ac9e43p-2,
    0x1.279a74590331ap-2
  },
  { // Entry 579
    -0x1.e18e941cc7fd519ecc40548a86d2a3edp-3,
    -0x1.d8f7208e6b829p-3
  },
  { // Entry 580
    0x1.e18e941cc7fd519ecc40548a86d2a3edp-3,
    0x1.d8f7208e6b829p-3
  },
  { // Entry 581
    -0x1.6650784bbdcc02f3390262cf68bad3c6p-3,
    -0x1.62b9586ad0a1ep-3
  },
  { // Entry 582
    0x1.6650784bbdcc02f3390262cf68bad3c6p-3,
    0x1.62b9586ad0a1ep-3
  },
  { // Entry 583
    -0x1.db142468cdafc56ecfdf8b1052b09e63p-4,
    -0x1.d8f7208e6b826p-4
  },
  { // Entry 584
    0x1.db142468cdafc56ecfdf8b1052b09e63p-4,
    0x1.d8f7208e6b826p-4
  },
  { // Entry 585
    -0x1.d97dd6d2e53f27e0fe1f3bd2b035662ap-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 586
    0x1.d97dd6d2e53f27e0fe1f3bd2b035662ap-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 587
    0x1.d97dd6d2e53f27e0fe1f3bd2b035662ap-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 588
    -0x1.d97dd6d2e53f27e0fe1f3bd2b035662ap-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 589
    0x1.db142468cdb036f08783d936b19348f6p-4,
    0x1.d8f7208e6b82dp-4
  },
  { // Entry 590
    -0x1.db142468cdb036f08783d936b19348f6p-4,
    -0x1.d8f7208e6b82dp-4
  },
  { // Entry 591
    0x1.6650784bbdcc44e8be2c220e1d673ffbp-3,
    0x1.62b9586ad0a22p-3
  },
  { // Entry 592
    -0x1.6650784bbdcc44e8be2c220e1d673ffbp-3,
    -0x1.62b9586ad0a22p-3
  },
  { // Entry 593
    0x1.e18e941cc7fd9528a5585157ac65e615p-3,
    0x1.d8f7208e6b82dp-3
  },
  { // Entry 594
    -0x1.e18e941cc7fd9528a5585157ac65e615p-3,
    -0x1.d8f7208e6b82dp-3
  },
  { // Entry 595
    0x1.301909a2c36eac78ec1b4e711316d0c4p-2,
    0x1.279a74590331cp-2
  },
  { // Entry 596
    -0x1.301909a2c36eac78ec1b4e711316d0c4p-2,
    -0x1.279a74590331cp-2
  },
  { // Entry 597
    0x1.71a0f98081eabce155f310288c4245eap-2,
    0x1.62b9586ad0a22p-2
  },
  { // Entry 598
    -0x1.71a0f98081eabce155f310288c4245eap-2,
    -0x1.62b9586ad0a22p-2
  },
  { // Entry 599
    0x1.b5f3d6afbe6f4b756842b8eee5c85a31p-2,
    0x1.9dd83c7c9e128p-2
  },
  { // Entry 600
    -0x1.b5f3d6afbe6f4b756842b8eee5c85a31p-2,
    -0x1.9dd83c7c9e128p-2
  },
  { // Entry 601
    0x1.fdbd5f0596bdeedd82d5223c3c1b1925p-2,
    0x1.d8f7208e6b82ep-2
  },
  { // Entry 602
    -0x1.fdbd5f0596bdeedd82d5223c3c1b1925p-2,
    -0x1.d8f7208e6b82ep-2
  },
  { // Entry 603
    0x1.24e3e017a098ecf4de48bceeb026743ap-1,
    0x1.0a0b02501c799p-1
  },
  { // Entry 604
    -0x1.24e3e017a098ecf4de48bceeb026743ap-1,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 605
    0x1.6d395e495f778678b9ea0d4808c7220ap-1,
    0x1.3d3e35834faccp-1
  },
  { // Entry 606
    -0x1.6d395e495f778678b9ea0d4808c7220ap-1,
    -0x1.3d3e35834faccp-1
  },
  { // Entry 607
    0x1.8ee916392e03f2335033a41b3b0206e4p-1,
    0x1.52e1f6ad9c27cp-1
  },
  { // Entry 608
    -0x1.8ee916392e03f2335033a41b3b0206e4p-1,
    -0x1.52e1f6ad9c27cp-1
  },
  { // Entry 609
    0x1.b2e4750631c4ce283ef8753fa1edf324p-1,
    0x1.6885b7d7e8a2cp-1
  },
  { // Entry 610
    -0x1.b2e4750631c4ce283ef8753fa1edf324p-1,
    -0x1.6885b7d7e8a2cp-1
  },
  { // Entry 611
    0x1.d98e408ac207e58e15f0185d4b10cf71p-1,
    0x1.7e297902351dcp-1
  },
  { // Entry 612
    -0x1.d98e408ac207e58e15f0185d4b10cf71p-1,
    -0x1.7e297902351dcp-1
  },
  { // Entry 613
    0x1.01aeeed04cbacd8eb6bc094664db7763p0,
    0x1.93cd3a2c8198cp-1
  },
  { // Entry 614
    -0x1.01aeeed04cbacd8eb6bc094664db7763p0,
    -0x1.93cd3a2c8198cp-1
  },
  { // Entry 615
    0x1.1872a1aaa7e2268cb946fceb83f0ea5ep0,
    0x1.a970fb56ce13cp-1
  },
  { // Entry 616
    -0x1.1872a1aaa7e2268cb946fceb83f0ea5ep0,
    -0x1.a970fb56ce13cp-1
  },
  { // Entry 617
    0x1.316c8b068a7aa4cb77bc3f39921c2c8dp0,
    0x1.bf14bc811a8ecp-1
  },
  { // Entry 618
    -0x1.316c8b068a7aa4cb77bc3f39921c2c8dp0,
    -0x1.bf14bc811a8ecp-1
  },
  { // Entry 619
    0x1.4d0df1fc1d342e867e49f1f6ddacedaap0,
    0x1.d4b87dab6709cp-1
  },
  { // Entry 620
    -0x1.4d0df1fc1d342e867e49f1f6ddacedaap0,
    -0x1.d4b87dab6709cp-1
  },
  { // Entry 621
    0x1.6be702e1f6cd0016ba1677a9cd33f139p0,
    0x1.ea5c3ed5b384cp-1
  },
  { // Entry 622
    -0x1.6be702e1f6cd0016ba1677a9cd33f139p0,
    -0x1.ea5c3ed5b384cp-1
  },
  { // Entry 623
    0x1.d74caf9912dc7d9669b00926aa1ade11p0,
    0x1.12bd9173c07abp0
  },
  { // Entry 624
    -0x1.d74caf9912dc7d9669b00926aa1ade11p0,
    -0x1.12bd9173c07abp0
  },
  { // Entry 625
    0x1.1b48a35b1b283bbc82bb044e99c4d9b1p1,
    0x1.257b22e780f56p0
  },
  { // Entry 626
    -0x1.1b48a35b1b283bbc82bb044e99c4d9b1p1,
    -0x1.257b22e780f56p0
  },
  { // Entry 627
    0x1.5d603d751768fcd8af82b38746888530p1,
    0x1.3838b45b41701p0
  },
  { // Entry 628
    -0x1.5d603d751768fcd8af82b38746888530p1,
    -0x1.3838b45b41701p0
  },
  { // Entry 629
    0x1.c08caec5cf9b1b54b045228b3eeb2469p1,
    0x1.4af645cf01eacp0
  },
  { // Entry 630
    -0x1.c08caec5cf9b1b54b045228b3eeb2469p1,
    -0x1.4af645cf01eacp0
  },
  { // Entry 631
    0x1.3429e61a5d20b175d45c2a675a386ba3p2,
    0x1.5db3d742c2657p0
  },
  { // Entry 632
    -0x1.3429e61a5d20b175d45c2a675a386ba3p2,
    -0x1.5db3d742c2657p0
  },
  { // Entry 633
    0x1.e3a3729b3e8a83d44a76e342d6b3fcbfp2,
    0x1.707168b682e02p0
  },
  { // Entry 634
    -0x1.e3a3729b3e8a83d44a76e342d6b3fcbfp2,
    -0x1.707168b682e02p0
  },
  { // Entry 635
    0x1.11d87146c2da39408e86083bf1471c8bp4,
    0x1.832efa2a435adp0
  },
  { // Entry 636
    -0x1.11d87146c2da39408e86083bf1471c8bp4,
    -0x1.832efa2a435adp0
  },
  { // Entry 637
    -0x1.0d718cfc82348ab9754f3d6b5e0ea499p6,
    0x1.95ec8b9e03d58p0
  },
  { // Entry 638
    0x1.0d718cfc82348ab9754f3d6b5e0ea499p6,
    -0x1.95ec8b9e03d58p0
  },
  { // Entry 639
    -0x1.6a7e1f6407ee61397d016d691bb61d17p3,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 640
    0x1.6a7e1f6407ee61397d016d691bb61d17p3,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 641
    0x1.9f39ea5bbe4749e962a807c2dc11c825p0,
    0x1.04aff6d330942p0
  },
  { // Entry 642
    -0x1.9f39ea5bbe4749e962a807c2dc11c825p0,
    -0x1.04aff6d330942p0
  },
  { // Entry 643
    0x1.9f3c4b8469f853b8507455717327c311p0,
    0x1.04b09e98dcdb4p0
  },
  { // Entry 644
    -0x1.9f3c4b8469f853b8507455717327c311p0,
    -0x1.04b09e98dcdb4p0
  },
  { // Entry 645
    0x1.9f3eacb224c2086ef391b0dfad2f1010p0,
    0x1.04b1465e89226p0
  },
  { // Entry 646
    -0x1.9f3eacb224c2086ef391b0dfad2f1010p0,
    -0x1.04b1465e89226p0
  },
  { // Entry 647
    0x1.9f410de4eeb69590caee85e886f478a8p0,
    0x1.04b1ee2435698p0
  },
  { // Entry 648
    -0x1.9f410de4eeb69590caee85e886f478a8p0,
    -0x1.04b1ee2435698p0
  },
  { // Entry 649
    0x1.9f436f1cc7e828f752819af1e2f4b6a2p0,
    0x1.04b295e9e1b0ap0
  },
  { // Entry 650
    -0x1.9f436f1cc7e828f752819af1e2f4b6a2p0,
    -0x1.04b295e9e1b0ap0
  },
  { // Entry 651
    0x1.9f45d059b068f0d205485ad648223e6dp0,
    0x1.04b33daf8df7cp0
  },
  { // Entry 652
    -0x1.9f45d059b068f0d205485ad648223e6dp0,
    -0x1.04b33daf8df7cp0
  },
  { // Entry 653
    0x1.9f48319ba84b1ba65f452cfe65e02d0ep0,
    0x1.04b3e5753a3eep0
  },
  { // Entry 654
    -0x1.9f48319ba84b1ba65f452cfe65e02d0ep0,
    -0x1.04b3e5753a3eep0
  },
  { // Entry 655
    0x1.9f4a92e2afa0d84fdf7ddbaad302f150p0,
    0x1.04b48d3ae6860p0
  },
  { // Entry 656
    -0x1.9f4a92e2afa0d84fdf7ddbaad302f150p0,
    -0x1.04b48d3ae6860p0
  },
  { // Entry 657
    0x1.9f4cf42ec67ba7ad0db2be248a870bfep0,
    0x1.04b5350092ccfp0
  },
  { // Entry 658
    -0x1.9f4cf42ec67ba7ad0db2be248a870bfep0,
    -0x1.04b5350092ccfp0
  },
  { // Entry 659
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 660
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 661
    -0.0,
    -0.0
  },
  { // Entry 662
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 663
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 664
    0x1.4d82b68cac19e6d065c5f1aa7621c08cp-1,
    0x1.279a74590331bp-1
  },
  { // Entry 665
    -0x1.4d82b68cac19e6d065c5f1aa7621c08cp-1,
    -0x1.279a74590331bp-1
  },
  { // Entry 666
    0x1.4d82b68cac19fd9a5b0c912d9093aa4ap-1,
    0x1.279a74590331cp-1
  },
  { // Entry 667
    -0x1.4d82b68cac19fd9a5b0c912d9093aa4ap-1,
    -0x1.279a74590331cp-1
  },
  { // Entry 668
    0x1.4d82b68cac1a1464505330b0abf316bfp-1,
    0x1.279a74590331dp-1
  },
  { // Entry 669
    -0x1.4d82b68cac1a1464505330b0abf316bfp-1,
    -0x1.279a74590331dp-1
  },
  { // Entry 670
    -0x1.89712eeca32be97dba2ca3f9b8379154p2,
    0x1.bb67ae8584ca9p0
  },
  { // Entry 671
    0x1.89712eeca32be97dba2ca3f9b8379154p2,
    -0x1.bb67ae8584ca9p0
  },
  { // Entry 672
    -0x1.89712eeca32b4e528d25635a4293be1dp2,
    0x1.bb67ae8584caap0
  },
  { // Entry 673
    0x1.89712eeca32b4e528d25635a4293be1dp2,
    -0x1.bb67ae8584caap0
  },
  { // Entry 674
    -0x1.89712eeca32ab327601e22bb442cdc37p2,
    0x1.bb67ae8584cabp0
  },
  { // Entry 675
    0x1.89712eeca32ab327601e22bb442cdc37p2,
    -0x1.bb67ae8584cabp0
  },
  { // Entry 676
    0x1.def49eaab37a00f90cb4454710e4e545p-2,
    0x1.bffffffffffffp-2
  },
  { // Entry 677
    -0x1.def49eaab37a00f90cb4454710e4e545p-2,
    -0x1.bffffffffffffp-2
  },
  { // Entry 678
    0x1.def49eaab37a1479231e899509ecf26cp-2,
    0x1.cp-2
  },
  { // Entry 679
    -0x1.def49eaab37a1479231e899509ecf26cp-2,
    -0x1.cp-2
  },
  { // Entry 680
    0x1.def49eaab37a27f93988cde3033df72cp-2,
    0x1.c000000000001p-2
  },
  { // Entry 681
    -0x1.def49eaab37a27f93988cde3033df72cp-2,
    -0x1.c000000000001p-2
  },
  { // Entry 682
    0x1.a46cb2be6a0b02e2dfffc95e6dcb2842p-1,
    0x1.5ffffffffffffp-1
  },
  { // Entry 683
    -0x1.a46cb2be6a0b02e2dfffc95e6dcb2842p-1,
    -0x1.5ffffffffffffp-1
  },
  { // Entry 684
    0x1.a46cb2be6a0b1dacb36269c41a4a9147p-1,
    0x1.6p-1
  },
  { // Entry 685
    -0x1.a46cb2be6a0b1dacb36269c41a4a9147p-1,
    -0x1.6p-1
  },
  { // Entry 686
    0x1.a46cb2be6a0b387686c50a29c829ee42p-1,
    0x1.6000000000001p-1
  },
  { // Entry 687
    -0x1.a46cb2be6a0b387686c50a29c829ee42p-1,
    -0x1.6000000000001p-1
  },
  { // Entry 688
    0x1.3d6dc956eac79a85b47456fa0c946b13p1,
    0x1.2ffffffffffffp0
  },
  { // Entry 689
    -0x1.3d6dc956eac79a85b47456fa0c946b13p1,
    -0x1.2ffffffffffffp0
  },
  { // Entry 690
    0x1.3d6dc956eac7d3b8d6eb2174110d1ddcp1,
    0x1.3p0
  },
  { // Entry 691
    -0x1.3d6dc956eac7d3b8d6eb2174110d1ddcp1,
    -0x1.3p0
  },
  { // Entry 692
    0x1.3d6dc956eac80cebf961ebee274107p1,
    0x1.3000000000001p0
  },
  { // Entry 693
    -0x1.3d6dc956eac80cebf961ebee274107p1,
    -0x1.3000000000001p0
  },
  { // Entry 694
    -0x1.b2d89a93829536cc9283cfc7e01fe2a3p-1,
    0x1.37fffffffffffp1
  },
  { // Entry 695
    0x1.b2d89a93829536cc9283cfc7e01fe2a3p-1,
    -0x1.37fffffffffffp1
  },
  { // Entry 696
    -0x1.b2d89a938294c8a2604db9f7aa56a0f8p-1,
    0x1.380p1
  },
  { // Entry 697
    0x1.b2d89a938294c8a2604db9f7aa56a0f8p-1,
    -0x1.380p1
  },
  { // Entry 698
    -0x1.b2d89a9382945a782e17a4278bf17736p-1,
    0x1.3800000000001p1
  },
  { // Entry 699
    0x1.b2d89a9382945a782e17a4278bf17736p-1,
    -0x1.3800000000001p1
  },
  { // Entry 700
    0x1.06f8d014bf083cd36650e9466dc086dcp-4,
    0x1.069c8b46b3792p-4
  },
  { // Entry 701
    -0x1.06f8d014bf083cd36650e9466dc086dcp-4,
    -0x1.069c8b46b3792p-4
  },
  { // Entry 702
    0x1.080f73b07051e37b23da3337c0aed353p-3,
    0x1.069c8b46b3792p-3
  },
  { // Entry 703
    -0x1.080f73b07051e37b23da3337c0aed353p-3,
    -0x1.069c8b46b3792p-3
  },
  { // Entry 704
    0x1.8ed9142fc918888e294d3ff5d0149415p-3,
    0x1.89ead0ea0d35bp-3
  },
  { // Entry 705
    -0x1.8ed9142fc918888e294d3ff5d0149415p-3,
    -0x1.89ead0ea0d35bp-3
  },
  { // Entry 706
    0x1.0c864083d1e7ca5551bce24972878127p-2,
    0x1.069c8b46b3792p-2
  },
  { // Entry 707
    -0x1.0c864083d1e7ca5551bce24972878127p-2,
    -0x1.069c8b46b3792p-2
  },
  { // Entry 708
    0x1.53fdcdfd37f04375d9ffb6aebafe7df8p-2,
    0x1.4843ae1860576p-2
  },
  { // Entry 709
    -0x1.53fdcdfd37f04375d9ffb6aebafe7df8p-2,
    -0x1.4843ae1860576p-2
  },
  { // Entry 710
    0x1.9e9257e6b62a0a8de5650c837f7f6227p-2,
    0x1.89ead0ea0d35ap-2
  },
  { // Entry 711
    -0x1.9e9257e6b62a0a8de5650c837f7f6227p-2,
    -0x1.89ead0ea0d35ap-2
  },
  { // Entry 712
    0x1.ed21e59972b07c7053f4f35dd5502493p-2,
    0x1.cb91f3bbba13ep-2
  },
  { // Entry 713
    -0x1.ed21e59972b07c7053f4f35dd5502493p-2,
    -0x1.cb91f3bbba13ep-2
  },
  { // Entry 714
    0x1.205a6009d5e3dde25d6deb7d521ff140p-1,
    0x1.069c8b46b3791p-1
  },
  { // Entry 715
    -0x1.205a6009d5e3dde25d6deb7d521ff140p-1,
    -0x1.069c8b46b3791p-1
  },
  { // Entry 716
    0x1.4d466accad48dd958ab168f5cfc6c99cp-1,
    0x1.27701caf89e83p-1
  },
  { // Entry 717
    -0x1.4d466accad48dd958ab168f5cfc6c99cp-1,
    -0x1.27701caf89e83p-1
  },
  { // Entry 718
    0x1.7e1d936f4d6152fb74809595717fa06dp-1,
    0x1.4843ae1860575p-1
  },
  { // Entry 719
    -0x1.7e1d936f4d6152fb74809595717fa06dp-1,
    -0x1.4843ae1860575p-1
  },
  { // Entry 720
    0x1.b3df386f18227ebcee905fd
"""


```