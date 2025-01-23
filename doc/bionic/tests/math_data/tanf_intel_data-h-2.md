Response:
The user wants a summary of the functionality of the provided C source code file. This is the third part of a series. Since the content is a large array of floating-point pairs, the likely function is to provide test data for the `tanf` function in the Android bionic library.

Here's a plan:
1. **Identify the core purpose:** The data is clearly structured as input/output pairs for a trigonometric function.
2. **Connect to `tanf`:** The filename `tanf_intel_data.handroid` strongly suggests it's test data for the `tanf` function (tangent for floats).
3. **Explain the structure:**  Describe the array and the meaning of each pair (input, expected output).
4. **Relate to bionic and Android:** Explain that bionic is Android's C library and how this data is used for testing the correctness of the `tanf` implementation.
这是目录为 `bionic/tests/math_data/tanf_intel_data.handroid` 的源代码文件的第 3 部分，它主要的功能是**为 `tanf` 函数提供测试数据**。

**归纳其功能:**

这个代码片段定义了一个名为 `data` 的常量数组，该数组包含了大量的 `Entry` 结构体。每个 `Entry` 结构体包含两个 `double` 类型的浮点数。根据文件名和上下文（前面两部分应该也包含类似的数据），这些数据很可能是用于测试 `tanf` 函数在各种输入情况下的精度和正确性。

具体来说：

* **测试 `tanf` 函数的精度:**  数组中的每一个 `{输入值, 期望的 tanf(输入值)}` 对，都被用来验证 `tanf` 函数的计算结果是否与期望值足够接近。
* **覆盖不同的输入范围:**  数组中包含了各种不同数量级和正负的输入值，以及特殊值（如 0 和非常接近 0 的值），旨在全面测试 `tanf` 函数在不同输入场景下的表现。

**与 Android 功能的关系举例：**

在 Android 系统中，当一个应用程序或系统组件调用 `tanf` 函数时，最终会执行 bionic 库中 `libm.so` 提供的 `tanf` 实现。为了确保这个实现的正确性，开发者会使用像 `tanf_intel_data.handroid` 这样的测试数据进行单元测试。

例如，当 bionic 的开发者修改或优化了 `tanf` 的实现后，他们会运行包含这些测试数据的测试程序。测试程序会遍历 `data` 数组，对每个输入值调用 `tanf` 函数，并将计算结果与数组中提供的期望值进行比较。如果所有或大部分测试用例都通过，则可以认为 `tanf` 的实现是正确的。

**关于 libc 函数 `tanf` 的实现：**

`tanf(float x)` 函数用于计算给定弧度制角 `x` 的正切值。其实现通常会涉及以下步骤：

1. **处理特殊情况:**
   * 如果 `x` 是 NaN (Not a Number)，则返回 NaN。
   * 如果 `x` 是无穷大，则返回 NaN。
   * 如果 `x` 是 0，则返回 0。
   * 如果 `x` 非常接近 0，可以直接返回 `x` (利用小角度近似)。

2. **范围缩减:** 由于正切函数是周期函数，周期为 π，为了提高计算效率和精度，通常会将输入值 `x` 缩减到一个较小的区间，例如 [-π/4, π/4]。这可以通过以下公式实现：
   ```
   y = remainder(x, π)  // 将 x 折叠到 [-π/2, π/2] 区间
   if (y > π/4) y -= π/2;
   else if (y < -π/4) y += π/2;
   ```
   同时需要记录下缩减过程中使用的 π 的倍数，以便后续调整符号。

3. **多项式逼近或查表法:** 在缩减后的较小区间内，可以使用多项式逼近（如泰勒级数展开）或查表法来计算正切值。
   * **多项式逼近:**  使用一个多项式来近似 `tan(y)` 的值。例如，可以使用泰勒展开式的前几项：
     ```
     tan(y) ≈ y + y^3/3 + 2y^5/15 + ...
     ```
     为了提高精度，通常会使用更复杂的有理逼近或 minimax 多项式。
   * **查表法:**  将缩减后的区间划分为更小的子区间，并预先计算好每个子区间中某些点的正切值，存储在一个表中。计算时，根据输入值所在的子区间，查找表中的值并进行插值计算。

4. **符号调整:** 根据输入值 `x` 的象限和范围缩减过程中使用的 π 的倍数，调整计算结果的符号。

**对于涉及 dynamic linker 的功能:**

这个代码文件本身不直接涉及 dynamic linker 的功能。它只是一个包含静态数据的 C 源文件。dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是在程序启动时加载共享库 (`.so` 文件) 并解析库之间的依赖关系。

**so 布局样本:**

假设 `libm.so` 是包含 `tanf` 函数实现的共享库。其布局可能如下：

```
LOAD 0x... // 代码段
    ... // 其他代码
    .text:0000... tanf:         // tanf 函数的入口地址
        ... // tanf 函数的指令
LOAD 0x... // 数据段
    ... // 其他数据
    .rodata:0000... data:         // 这个 tanf_intel_data.handroid 生成的 data 数组可能会被编译到这里 (如果是内联测试)
```

**链接的处理过程:**

1. **编译时:** 编译器会将对 `tanf` 函数的调用生成一个 PLT (Procedure Linkage Table) 条目。
2. **加载时:** 当程序加载时，dynamic linker 会解析程序的依赖关系，找到 `libm.so`。
3. **符号解析:**  当第一次调用 `tanf` 时，PLT 条目会跳转到 GOT (Global Offset Table) 中对应的条目。初始时，GOT 条目包含的是一个跳转回 dynamic linker 的地址。
4. **动态链接:** dynamic linker 会找到 `libm.so` 中 `tanf` 函数的地址，并将其写入 GOT 条目。
5. **后续调用:**  后续对 `tanf` 的调用会直接通过 GOT 跳转到 `libm.so` 中 `tanf` 的实现。

**假设输入与输出:**

由于这个文件是测试数据，我们可以直接从文件中找到一些例子：

* **假设输入:** `0x1.921fb4p0` (十进制约等于 1.57079632679)，
  **期望输出:** `0x1.2d97c2p51` (十进制约等于 1.633123935327279e+15)。
  这表示 `tanf(1.57079632679)` 应该非常接近无穷大。

* **假设输入:** `-0x1.9437b336b6b0c479b2280999b19575c7p23` (一个很大的负数)，
  **期望输出:** `-0x1.921fb4p0` (十进制约等于 -1.57079632679)。
  由于正切函数的周期性，对于很大的输入值，其正切值会重复出现。

**用户或编程常见的使用错误:**

* **输入角度单位错误:** `tanf` 函数期望输入的是弧度值，如果传入的是角度值，会导致计算结果错误。
  ```c
  #include <math.h>
  #include <stdio.h>

  int main() {
    float angle_degrees = 45.0f;
    // 错误：直接将角度值传给 tanf
    float result_wrong = tanf(angle_degrees);
    printf("tan(%f degrees) (wrong): %f\n", angle_degrees, result_wrong);

    // 正确：将角度转换为弧度
    float angle_radians = angle_degrees * M_PI / 180.0f;
    float result_correct = tanf(angle_radians);
    printf("tan(%f degrees) (correct): %f\n", angle_degrees, result_correct);
    return 0;
  }
  ```
* **输入值接近 π/2 的奇数倍:** 在这些点附近，正切函数的值会趋于无穷大，可能导致数值溢出或精度问题。用户需要注意处理这些情况。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**  开发者使用 NDK 编写 C/C++ 代码，其中可能调用了 `tanf` 函数。
   ```c++
   #include <cmath>

   float calculate_tan(float x) {
     return std::tanf(x);
   }
   ```
2. **编译 NDK 代码:** NDK 工具链会将 C/C++ 代码编译成包含对 `tanf` 函数调用的机器码。
3. **应用程序运行:** 当 Android 应用程序运行时，需要加载包含 `calculate_tan` 函数的 native 库。
4. **调用 `tanf`:** 当应用程序调用 `calculate_tan` 函数时，会执行到 `std::tanf(x)` 的调用。
5. **libc 函数调用:** `std::tanf` 通常会调用 bionic 库中的 `tanf` 函数。
6. **`libm.so` 加载和符号解析:**  Android 的 dynamic linker 会确保 `libm.so` 被加载，并且 `tanf` 函数的符号被正确解析。
7. **执行 `tanf` 实现:**  最终会执行 `libm.so` 中 `tanf` 函数的实现。为了验证这个实现的正确性，开发者使用了类似 `tanf_intel_data.handroid` 中的测试数据。

**Frida Hook 示例调试步骤:**

```python
import frida
import sys

package_name = "your.package.name" # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
    Interceptor.attach(Module.findExportByName("libm.so", "tanf"), {
        onEnter: function(args) {
            this.x = args[0];
            send({ tag: "tanf", data: "Entering tanf with argument: " + this.x });
        },
        onLeave: function(retval) {
            send({ tag: "tanf", data: "Leaving tanf with return value: " + retval + ", for input: " + this.x });
        }
    });
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.input()
```

**Frida Hook 示例解释:**

1. **导入 Frida 库:** 导入必要的 Frida 库。
2. **指定包名:**  设置要 hook 的应用程序的包名。
3. **连接到设备和进程:** 使用 Frida 连接到 USB 设备，并附加到目标应用程序的进程。
4. **Frida Script:**
   * `Interceptor.attach`:  拦截对 `libm.so` 中 `tanf` 函数的调用。
   * `Module.findExportByName`: 查找 `libm.so` 中名为 `tanf` 的导出函数。
   * `onEnter`: 在 `tanf` 函数被调用前执行。
     * `args[0]`: 获取 `tanf` 函数的第一个参数（浮点数输入值）。
     * `send`:  通过 Frida 发送消息，包含标签 "tanf" 和输入值。
   * `onLeave`: 在 `tanf` 函数执行完毕后执行。
     * `retval`: 获取 `tanf` 函数的返回值。
     * `send`: 通过 Frida 发送消息，包含标签 "tanf"、返回值和输入值。
5. **加载 Script:** 将 Frida script 加载到目标进程中。
6. **监听消息:** 设置消息处理函数 `on_message` 来打印 Frida 发送的消息。
7. **保持运行:** 使用 `sys.input()` 使脚本保持运行状态，以便持续监听 `tanf` 函数的调用。

运行此 Frida 脚本后，当目标应用程序调用 `tanf` 函数时，你将在终端看到类似以下的输出，显示了 `tanf` 函数的输入和输出值：

```
[*] tanf: Entering tanf with argument: 1.0471975803375244
[*] tanf: Leaving tanf with return value: 1.7320508075688767, for input: 1.0471975803375244
```

这个 Frida 示例可以帮助你动态地观察 `tanf` 函数的调用情况，验证输入输出，辅助理解其行为。

### 提示词
```
这是目录为bionic/tests/math_data/tanf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
0x1.921fb4p0
  },
  { // Entry 778
    -0x1.9437b336b6b0c479b2280999b19575c7p23,
    -0x1.921fb4p0
  },
  { // Entry 779
    -0x1.5d14946dc98975d6421a55284fe020a1p24,
    0x1.921fb6p0
  },
  { // Entry 780
    0x1.5d14946dc98975d6421a55284fe020a1p24,
    -0x1.921fb6p0
  },
  { // Entry 781
    -0x1.76a190eb2b0718d8db55f7d2abeb07d2p22,
    0x1.921fb8p0
  },
  { // Entry 782
    0x1.76a190eb2b0718d8db55f7d2abeb07d2p22,
    -0x1.921fb8p0
  },
  { // Entry 783
    -0x1.4442d184698c426c8e3efd356cbebe0ap-23,
    0x1.921fb4p1
  },
  { // Entry 784
    0x1.4442d184698c426c8e3efd356cbebe0ap-23,
    -0x1.921fb4p1
  },
  { // Entry 785
    0x1.777a5cf72cedf3b544c81808b515f1f9p-24,
    0x1.921fb6p1
  },
  { // Entry 786
    -0x1.777a5cf72cedf3b544c81808b515f1f9p-24,
    -0x1.921fb6p1
  },
  { // Entry 787
    0x1.5dde973dcb48d6e3d13cf2a51550e911p-22,
    0x1.921fb8p1
  },
  { // Entry 788
    -0x1.5dde973dcb48d6e3d13cf2a51550e911p-22,
    -0x1.921fb8p1
  },
  { // Entry 789
    -0x1.4442d18469946362f3f6cc7c43857661p-22,
    0x1.921fb4p2
  },
  { // Entry 790
    0x1.4442d18469946362f3f6cc7c43857661p-22,
    -0x1.921fb4p2
  },
  { // Entry 791
    0x1.777a5cf72cf11b739d2ab1877e81a9c7p-23,
    0x1.921fb6p2
  },
  { // Entry 792
    -0x1.777a5cf72cf11b739d2ab1877e81a9c7p-23,
    -0x1.921fb6p2
  },
  { // Entry 793
    0x1.5dde973dcb71aeb6e776668bbb3de253p-21,
    0x1.921fb8p2
  },
  { // Entry 794
    -0x1.5dde973dcb71aeb6e776668bbb3de253p-21,
    -0x1.921fb8p2
  },
  { // Entry 795
    -0x1.4442d18469b4e73c8ad60e7b9f288c5cp-21,
    0x1.921fb4p3
  },
  { // Entry 796
    0x1.4442d18469b4e73c8ad60e7b9f288c5cp-21,
    -0x1.921fb4p3
  },
  { // Entry 797
    0x1.777a5cf72cfdba6cfeb518258bcf263cp-22,
    0x1.921fb6p3
  },
  { // Entry 798
    -0x1.777a5cf72cfdba6cfeb518258bcf263cp-22,
    -0x1.921fb6p3
  },
  { // Entry 799
    0x1.5dde973dcc150e03405ca894886602c2p-20,
    0x1.921fb8p3
  },
  { // Entry 800
    -0x1.5dde973dcc150e03405ca894886602c2p-20,
    -0x1.921fb8p3
  },
  { // Entry 801
    -0x1.4442d1846a36f6a2e65364b916382e9bp-20,
    0x1.921fb4p4
  },
  { // Entry 802
    0x1.4442d1846a36f6a2e65364b916382e9bp-20,
    -0x1.921fb4p4
  },
  { // Entry 803
    0x1.777a5cf72d30365284debccc3aeeec17p-21,
    0x1.921fb6p4
  },
  { // Entry 804
    -0x1.777a5cf72d30365284debccc3aeeec17p-21,
    -0x1.921fb6p4
  },
  { // Entry 805
    0x1.5dde973dcea28b34a3fcd79b144a5050p-19,
    0x1.921fb8p4
  },
  { // Entry 806
    -0x1.5dde973dcea28b34a3fcd79b144a5050p-19,
    -0x1.921fb8p4
  },
  { // Entry 807
    -0x1.4442d1846c3f343c544da1af7aab690cp-19,
    0x1.921fb4p5
  },
  { // Entry 808
    0x1.4442d1846c3f343c544da1af7aab690cp-19,
    -0x1.921fb4p5
  },
  { // Entry 809
    0x1.777a5cf72dfa25e89d85f24e960b4455p-20,
    0x1.921fb6p5
  },
  { // Entry 810
    -0x1.777a5cf72dfa25e89d85f24e960b4455p-20,
    -0x1.921fb6p5
  },
  { // Entry 811
    0x1.5dde973dd8d87ffa32f001eab81d960cp-18,
    0x1.921fb8p5
  },
  { // Entry 812
    -0x1.5dde973dd8d87ffa32f001eab81d960cp-18,
    -0x1.921fb8p5
  },
  { // Entry 813
    -0x1.4442d18474602aa20c84d5918fc68a8ep-18,
    0x1.921fb4p6
  },
  { // Entry 814
    0x1.4442d18474602aa20c84d5918fc68a8ep-18,
    -0x1.921fb4p6
  },
  { // Entry 815
    0x1.777a5cf73121e441002cf6d1ec50d56dp-19,
    0x1.921fb6p6
  },
  { // Entry 816
    -0x1.777a5cf73121e441002cf6d1ec50d56dp-19,
    -0x1.921fb6p6
  },
  { // Entry 817
    0x1.5dde973e01b0531075e38e808ce048f2p-17,
    0x1.921fb8p6
  },
  { // Entry 818
    -0x1.5dde973e01b0531075e38e808ce048f2p-17,
    -0x1.921fb8p6
  },
  { // Entry 819
    -0x1.4442d18494e40438f245a5a219dea235p-17,
    0x1.921fb4p7
  },
  { // Entry 820
    0x1.4442d18494e40438f245a5a219dea235p-17,
    -0x1.921fb4p7
  },
  { // Entry 821
    0x1.777a5cf73dc0dda28b6bf07de2b2d5e6p-18,
    0x1.921fb6p7
  },
  { // Entry 822
    -0x1.777a5cf73dc0dda28b6bf07de2b2d5e6p-18,
    -0x1.921fb6p7
  },
  { // Entry 823
    0x1.5dde973ea50f9f69f41ff64c8c6db761p-16,
    0x1.921fb8p7
  },
  { // Entry 824
    -0x1.5dde973ea50f9f69f41ff64c8c6db761p-16,
    -0x1.921fb8p7
  },
  { // Entry 825
    -0x1.00000fccc8f15ee89f09d222e14c7292p0,
    0x1.2d97c4p1
  },
  { // Entry 826
    0x1.00000fccc8f15ee89f09d222e14c7292p0,
    -0x1.2d97c4p1
  },
  { // Entry 827
    -0x1.000007ccc892f8a0760cc20827ace476p0,
    0x1.2d97c6p1
  },
  { // Entry 828
    0x1.000007ccc892f8a0760cc20827ace476p0,
    -0x1.2d97c6p1
  },
  { // Entry 829
    -0x1.ffffff9990e924b866e831c9e9e639c7p-1,
    0x1.2d97c8p1
  },
  { // Entry 830
    0x1.ffffff9990e924b866e831c9e9e639c7p-1,
    -0x1.2d97c8p1
  },
  { // Entry 831
    0x1.ffffeb55643b9a648c2720bde1d22764p-1,
    0x1.f6a7a0p1
  },
  { // Entry 832
    -0x1.ffffeb55643b9a648c2720bde1d22764p-1,
    -0x1.f6a7a0p1
  },
  { // Entry 833
    0x1.fffffb5563d64585e9dcc97d74321461p-1,
    0x1.f6a7a2p1
  },
  { // Entry 834
    -0x1.fffffb5563d64585e9dcc97d74321461p-1,
    -0x1.f6a7a2p1
  },
  { // Entry 835
    0x1.000005aab1f87852792237652d34b1cep0,
    0x1.f6a7a4p1
  },
  { // Entry 836
    -0x1.000005aab1f87852792237652d34b1cep0,
    -0x1.f6a7a4p1
  },
  { // Entry 837
    0x1.033dd91c1035861ae455e0f8dc274b0dp20,
    0x1.2d97c4p2
  },
  { // Entry 838
    -0x1.033dd91c1035861ae455e0f8dc274b0dp20,
    -0x1.2d97c4p2
  },
  { // Entry 839
    0x1.0690fb4774ab80ccddc9ef5ad0fcc237p21,
    0x1.2d97c6p2
  },
  { // Entry 840
    -0x1.0690fb4774ab80ccddc9ef5ad0fcc237p21,
    -0x1.2d97c6p2
  },
  { // Entry 841
    -0x1.3fe4dac06d830837f6c584af6f8d9399p26,
    0x1.2d97c8p2
  },
  { // Entry 842
    0x1.3fe4dac06d830837f6c584af6f8d9399p26,
    -0x1.2d97c8p2
  },
  { // Entry 843
    -0x1.000014ddd4945394cb6ec7f87debc7a5p0,
    0x1.5fdbbcp2
  },
  { // Entry 844
    0x1.000014ddd4945394cb6ec7f87debc7a5p0,
    -0x1.5fdbbcp2
  },
  { // Entry 845
    -0x1.000004ddd3c6764d7369a0be61a630e7p0,
    0x1.5fdbbep2
  },
  { // Entry 846
    0x1.000004ddd3c6764d7369a0be61a630e7p0,
    -0x1.5fdbbep2
  },
  { // Entry 847
    -0x1.ffffe9bba7f1321fae192943a3e848c0p-1,
    0x1.5fdbc0p2
  },
  { // Entry 848
    0x1.ffffe9bba7f1321fae192943a3e848c0p-1,
    -0x1.5fdbc0p2
  },
  { // Entry 849
    0x1.ffffc133511ea2d3b988bf85316d4e05p-1,
    0x1.c463a8p2
  },
  { // Entry 850
    -0x1.ffffc133511ea2d3b988bf85316d4e05p-1,
    -0x1.c463a8p2
  },
  { // Entry 851
    0x1.ffffe1334e31d7ef20d6220c65dd2f9bp-1,
    0x1.c463aap2
  },
  { // Entry 852
    -0x1.ffffe1334e31d7ef20d6220c65dd2f9bp-1,
    -0x1.c463aap2
  },
  { // Entry 853
    0x1.00000099a6a286667761c2874c5890aep0,
    0x1.c463acp2
  },
  { // Entry 854
    -0x1.00000099a6a286667761c2874c5890aep0,
    -0x1.c463acp2
  },
  { // Entry 855
    0x1.8c642e8cc56a9b233450d6b635a6266dp20,
    0x1.f6a7a0p2
  },
  { // Entry 856
    -0x1.8c642e8cc56a9b233450d6b635a6266dp20,
    -0x1.f6a7a0p2
  },
  { // Entry 857
    0x1.b6e0bfb728e42363cd5fb26b31c366c2p22,
    0x1.f6a7a2p2
  },
  { // Entry 858
    -0x1.b6e0bfb728e42363cd5fb26b31c366c2p22,
    -0x1.f6a7a2p2
  },
  { // Entry 859
    -0x1.69679b966acc43dfdb28383aa976f5c1p21,
    0x1.f6a7a4p2
  },
  { // Entry 860
    0x1.69679b966acc43dfdb28383aa976f5c1p21,
    -0x1.f6a7a4p2
  },
  { // Entry 861
    -0x1.000029eee26fe211bb4a2f8e23a0a9e9p0,
    0x1.1475cap3
  },
  { // Entry 862
    0x1.000029eee26fe211bb4a2f8e23a0a9e9p0,
    -0x1.1475cap3
  },
  { // Entry 863
    -0x1.000009eedf3205d2e9b66a3783e02f05p0,
    0x1.1475ccp3
  },
  { // Entry 864
    0x1.000009eedf3205d2e9b66a3783e02f05p0,
    -0x1.1475ccp3
  },
  { // Entry 865
    -0x1.ffffd3ddbfe853c71e4a5f7502b09c4ep-1,
    0x1.1475cep3
  },
  { // Entry 866
    0x1.ffffd3ddbfe853c71e4a5f7502b09c4ep-1,
    -0x1.1475cep3
  },
  { // Entry 867
    -0x1.f9990e91aa24f550cef57fa4106c56ebp-20,
    0x1.2d97c4p3
  },
  { // Entry 868
    0x1.f9990e91aa24f550cef57fa4106c56ebp-20,
    -0x1.2d97c4p3
  },
  { // Entry 869
    -0x1.f3321d234fc557a61c638ef7752de43fp-21,
    0x1.2d97c6p3
  },
  { // Entry 870
    0x1.f3321d234fc557a61c638ef7752de43fp-21,
    -0x1.2d97c6p3
  },
  { // Entry 871
    0x1.99bc5b961b1ae363cfc0ffaab4f0e505p-26,
    0x1.2d97c8p3
  },
  { // Entry 872
    -0x1.99bc5b961b1ae363cfc0ffaab4f0e505p-26,
    -0x1.2d97c8p3
  },
  { // Entry 873
    0x1.ffff971141794461276f342bd29c5a1fp-1,
    0x1.46b9c0p3
  },
  { // Entry 874
    -0x1.ffff971141794461276f342bd29c5a1fp-1,
    -0x1.46b9c0p3
  },
  { // Entry 875
    0x1.ffffd711385b6c9a013dabe9b7254665p-1,
    0x1.46b9c2p3
  },
  { // Entry 876
    -0x1.ffffd711385b6c9a013dabe9b7254665p-1,
    -0x1.46b9c2p3
  },
  { // Entry 877
    0x1.00000b889b9ec9c5b277fb6a91cf5f49p0,
    0x1.46b9c4p3
  },
  { // Entry 878
    -0x1.00000b889b9ec9c5b277fb6a91cf5f49p0,
    -0x1.46b9c4p3
  },
  { // Entry 879
    0x1.88973cb02a0eea2cfe1a281ca7f04663p19,
    0x1.5fdbbcp3
  },
  { // Entry 880
    -0x1.88973cb02a0eea2cfe1a281ca7f04663p19,
    -0x1.5fdbbcp3
  },
  { // Entry 881
    0x1.a4d5d5d753841c89cfe71c25abc8d645p21,
    0x1.5fdbbep3
  },
  { // Entry 882
    -0x1.a4d5d5d753841c89cfe71c25abc8d645p21,
    -0x1.5fdbbep3
  },
  { // Entry 883
    -0x1.6fe62a1a9a12b70b1fbb952801f99801p20,
    0x1.5fdbc0p3
  },
  { // Entry 884
    0x1.6fe62a1a9a12b70b1fbb952801f99801p20,
    -0x1.5fdbc0p3
  },
  { // Entry 885
    -0x1.00003efff2073e1c0dd65d3b83e5e589p0,
    0x1.78fdb6p3
  },
  { // Entry 886
    0x1.00003efff2073e1c0dd65d3b83e5e589p0,
    -0x1.78fdb6p3
  },
  { // Entry 887
    -0x1.00001effec273fb46bb5ecfec53c3105p0,
    0x1.78fdb8p3
  },
  { // Entry 888
    0x1.00001effec273fb46bb5ecfec53c3105p0,
    -0x1.78fdb8p3
  },
  { // Entry 889
    -0x1.fffffdffd48e84899227cea1f77a1cf7p-1,
    0x1.78fdbap3
  },
  { // Entry 890
    0x1.fffffdffd48e84899227cea1f77a1cf7p-1,
    -0x1.78fdbap3
  },
  { // Entry 891
    0x1.ffffacef26e965d1253424fbbc9ff354p-1,
    0x1.ab41aep3
  },
  { // Entry 892
    -0x1.ffffacef26e965d1253424fbbc9ff354p-1,
    -0x1.ab41aep3
  },
  { // Entry 893
    0x1.ffffecef20874a8f035ac4dc1a6029f8p-1,
    0x1.ab41b0p3
  },
  { // Entry 894
    -0x1.ffffecef20874a8f035ac4dc1a6029f8p-1,
    -0x1.ab41b0p3
  },
  { // Entry 895
    0x1.000016779112975a2d4b9b75bd90b3c1p0,
    0x1.ab41b2p3
  },
  { // Entry 896
    -0x1.000016779112975a2d4b9b75bd90b3c1p0,
    -0x1.ab41b2p3
  },
  { // Entry 897
    0x1.04e4b40acdf9439feccd49bbeb37da0fp19,
    0x1.c463a8p3
  },
  { // Entry 898
    -0x1.04e4b40acdf9439feccd49bbeb37da0fp19,
    -0x1.c463a8p3
  },
  { // Entry 899
    0x1.09fa3ae1f4913d1b3764ff9a9678ef68p20,
    0x1.c463aap3
  },
  { // Entry 900
    -0x1.09fa3ae1f4913d1b3764ff9a9678ef68p20,
    -0x1.c463aap3
  },
  { // Entry 901
    -0x1.aa8679009203dd6e942f9175275a7461p24,
    0x1.c463acp3
  },
  { // Entry 902
    0x1.aa8679009203dd6e942f9175275a7461p24,
    -0x1.c463acp3
  },
  { // Entry 903
    -0x1.00003410fad846fd67d35e0c0d983628p0,
    0x1.dd85a4p3
  },
  { // Entry 904
    0x1.00003410fad846fd67d35e0c0d983628p0,
    -0x1.dd85a4p3
  },
  { // Entry 905
    -0x1.00001410f656279e89d14cf4054f6c56p0,
    0x1.dd85a6p3
  },
  { // Entry 906
    0x1.00001410f656279e89d14cf4054f6c56p0,
    -0x1.dd85a6p3
  },
  { // Entry 907
    -0x1.ffffe821eba811c067240f666c904371p-1,
    0x1.dd85a8p3
  },
  { // Entry 908
    0x1.ffffe821eba811c067240f666c904371p-1,
    -0x1.dd85a8p3
  },
  { // Entry 909
    -0x1.4aa9c2f2c2addb9b59e39401239761e2p-20,
    0x1.f6a7a0p3
  },
  { // Entry 910
    0x1.4aa9c2f2c2addb9b59e39401239761e2p-20,
    -0x1.f6a7a0p3
  },
  { // Entry 911
    -0x1.2aa70bcb07e057b729eacbc0cf17cbbfp-22,
    0x1.f6a7a2p3
  },
  { // Entry 912
    0x1.2aa70bcb07e057b729eacbc0cf17cbbfp-22,
    -0x1.f6a7a2p3
  },
  { // Entry 913
    0x1.6aac7a1a7c50b873bed39b6859bf2934p-21,
    0x1.f6a7a4p3
  },
  { // Entry 914
    -0x1.6aac7a1a7c50b873bed39b6859bf2934p-21,
    -0x1.f6a7a4p3
  },
  { // Entry 915
    0x1.ffff42cd2c95508e700ab76956dd04cfp-1,
    0x1.07e4ccp4
  },
  { // Entry 916
    -0x1.ffff42cd2c95508e700ab76956dd04cfp-1,
    -0x1.07e4ccp4
  },
  { // Entry 917
    0x1.ffffc2cd0d489b48844179c594356e0dp-1,
    0x1.07e4cep4
  },
  { // Entry 918
    -0x1.ffffc2cd0d489b48844179c594356e0dp-1,
    -0x1.07e4cep4
  },
  { // Entry 919
    0x1.0000216686fdef2e1dd31a2eaa6a1cd4p0,
    0x1.07e4d0p4
  },
  { // Entry 920
    -0x1.0000216686fdef2e1dd31a2eaa6a1cd4p0,
    -0x1.07e4d0p4
  },
  { // Entry 921
    0x1.86b7ba4923bcf157dcc33291871e88d4p18,
    0x1.1475cap4
  },
  { // Entry 922
    -0x1.86b7ba4923bcf157dcc33291871e88d4p18,
    -0x1.1475cap4
  },
  { // Entry 923
    0x1.9c5becf2873eed369afdc3159a7f797cp20,
    0x1.1475ccp4
  },
  { // Entry 924
    -0x1.9c5becf2873eed369afdc3159a7f797cp20,
    -0x1.1475ccp4
  },
  { // Entry 925
    -0x1.733c0d84332fa606d1bd207a491e4371p19,
    0x1.1475cep4
  },
  { // Entry 926
    0x1.733c0d84332fa606d1bd207a491e4371p19,
    -0x1.1475cep4
  },
  { // Entry 927
    -0x1.000049220b451bf6e8e605550c88602fp0,
    0x1.2106c8p4
  },
  { // Entry 928
    0x1.000049220b451bf6e8e605550c88602fp0,
    -0x1.2106c8p4
  },
  { // Entry 929
    -0x1.0000092200fc99c5dfa4fe18085cf7cdp0,
    0x1.2106cap4
  },
  { // Entry 930
    0x1.0000092200fc99c5dfa4fe18085cf7cdp0,
    -0x1.2106cap4
  },
  { // Entry 931
    -0x1.ffff92440d6831722dec0d31810d8fc7p-1,
    0x1.2106ccp4
  },
  { // Entry 932
    0x1.ffff92440d6831722dec0d31810d8fc7p-1,
    -0x1.2106ccp4
  },
  { // Entry 933
    -0x1.f9990e91b1d916e582242347112ba1d6p-19,
    0x1.2d97c4p4
  },
  { // Entry 934
    0x1.f9990e91b1d916e582242347112ba1d6p-19,
    -0x1.2d97c4p4
  },
  { // Entry 935
    -0x1.f3321d23519fe1dcfdcd2f1f762008a4p-20,
    0x1.2d97c6p4
  },
  { // Entry 936
    0x1.f3321d23519fe1dcfdcd2f1f762008a4p-20,
    -0x1.2d97c6p4
  },
  { // Entry 937
    0x1.99bc5b961b1b24fdb77fcee08ba2f720p-25,
    0x1.2d97c8p4
  },
  { // Entry 938
    -0x1.99bc5b961b1b24fdb77fcee08ba2f720p-25,
    -0x1.2d97c8p4
  },
  { // Entry 939
    0x1.ffff18ab2756ba0a20aaf4392b0a8019p-1,
    0x1.3a28c2p4
  },
  { // Entry 940
    -0x1.ffff18ab2756ba0a20aaf4392b0a8019p-1,
    -0x1.3a28c2p4
  },
  { // Entry 941
    0x1.ffff98aafd818525d24d664ef962ef14p-1,
    0x1.3a28c4p4
  },
  { // Entry 942
    -0x1.ffff98aafd818525d24d664ef962ef14p-1,
    -0x1.3a28c4p4
  },
  { // Entry 943
    0x1.00000c5579d621ab7334eff31d23cf2cp0,
    0x1.3a28c6p4
  },
  { // Entry 944
    -0x1.00000c5579d621ab7334eff31d23cf2cp0,
    -0x1.3a28c6p4
  },
  { // Entry 945
    0x1.3846b310de7c796adb3ea2ea22b108e2p18,
    0x1.46b9c0p4
  },
  { // Entry 946
    -0x1.3846b310de7c796adb3ea2ea22b108e2p18,
    -0x1.46b9c0p4
  },
  { // Entry 947
    0x1.904425fc92eab0abfe96aeeb6ffb2dc8p19,
    0x1.46b9c2p4
  },
  { // Entry 948
    -0x1.904425fc92eab0abfe96aeeb6ffb2dc8p19,
    -0x1.46b9c2p4
  },
  { // Entry 949
    -0x1.6322bacb22de6af00228d2ea4d6d2799p20,
    0x1.46b9c4p4
  },
  { // Entry 950
    0x1.6322bacb22de6af00228d2ea4d6d2799p20,
    -0x1.46b9c4p4
  },
  { // Entry 951
    -0x1.00005e331d6dbee9f9d431b49ea7b723p0,
    0x1.534abep4
  },
  { // Entry 952
    0x1.00005e331d6dbee9f9d431b49ea7b723p0,
    -0x1.534abep4
  },
  { // Entry 953
    -0x1.00001e330de0f7c734bc57a4c6650327p0,
    0x1.534ac0p4
  },
  { // Entry 954
    0x1.00001e330de0f7c734bc57a4c6650327p0,
    -0x1.534ac0p4
  },
  { // Entry 955
    -0x1.ffffbc661ca868d5a4418f0d1cd7c22fp-1,
    0x1.534ac2p4
  },
  { // Entry 956
    0x1.ffffbc661ca868d5a4418f0d1cd7c22fp-1,
    -0x1.534ac2p4
  },
  { // Entry 957
    -0x1.4ddd3ba9f1214deb40672397d6f191bcp-19,
    0x1.5fdbbcp4
  },
  { // Entry 958
    0x1.4ddd3ba9f1214deb40672397d6f191bcp-19,
    -0x1.5fdbbcp4
  },
  { // Entry 959
    -0x1.3774eea7b8d7214bc89b11532f82d323p-21,
    0x1.5fdbbep4
  },
  { // Entry 960
    0x1.3774eea7b8d7214bc89b11532f82d323p-21,
    -0x1.5fdbbep4
  },
  { // Entry 961
    0x1.644588ac248da6d01941121f50673b3fp-20,
    0x1.5fdbc0p4
  },
  { // Entry 962
    -0x1.644588ac248da6d01941121f50673b3fp-20,
    -0x1.5fdbc0p4
  },
  { // Entry 963
    0x1.ffff6e88f1320794d845e8e0fe1fd8bdp-1,
    0x1.6c6cbap4
  },
  { // Entry 964
    -0x1.ffff6e88f1320794d845e8e0fe1fd8bdp-1,
    -0x1.6c6cbap4
  },
  { // Entry 965
    0x1.ffffee88dcd4429f15c0e4a95b9ba0e6p-1,
    0x1.6c6cbcp4
  },
  { // Entry 966
    -0x1.ffffee88dcd4429f15c0e4a95b9ba0e6p-1,
    -0x1.6c6cbcp4
  },
  { // Entry 967
    0x1.00003744743b3dbd37dd053e702bd754p0,
    0x1.6c6cbep4
  },
  { // Entry 968
    -0x1.00003744743b3dbd37dd053e702bd754p0,
    -0x1.6c6cbep4
  },
  { // Entry 969
    0x1.04109ab0ec78f827ee95cea746b38c20p18,
    0x1.78fdb6p4
  },
  { // Entry 970
    -0x1.04109ab0ec78f827ee95cea746b38c20p18,
    -0x1.78fdb6p4
  },
  { // Entry 971
    0x1.0842c9b32d2125dbf5c20d70c46b17a5p19,
    0x1.78fdb8p4
  },
  { // Entry 972
    -0x1.0842c9b32d2125dbf5c20d70c46b17a5p19,
    -0x1.78fdb8p4
  },
  { // Entry 973
    -0x1.ffd49133e26a9c749966630dee813ddep23,
    0x1.78fdbap4
  },
  { // Entry 974
    0x1.ffd49133e26a9c749966630dee813ddep23,
    -0x1.78fdbap4
  },
  { // Entry 975
    -0x1.000073443152301fa59338eec29c3778p0,
    0x1.858eb4p4
  },
  { // Entry 976
    0x1.000073443152301fa59338eec29c3778p0,
    -0x1.858eb4p4
  },
  { // Entry 977
    -0x1.000033441c81232d3d9fc34bea81fb7cp0,
    0x1.858eb6p4
  },
  { // Entry 978
    0x1.000033441c81232d3d9fc34bea81fb7cp0,
    -0x1.858eb6p4
  },
  { // Entry 979
    -0x1.ffffe6882f603946b53b042361aec82cp-1,
    0x1.858eb8p4
  },
  { // Entry 980
    0x1.ffffe6882f603946b53b042361aec82cp-1,
    -0x1.858eb8p4
  },
  { // Entry 981
    -0x1.cb6cd4cb82a91dfc4af9a499a575e4a4p-3,
    0x1.fffffep62
  },
  { // Entry 982
    0x1.cb6cd4cb82a91dfc4af9a499a575e4a4p-3,
    -0x1.fffffep62
  },
  { // Entry 983
    0x1.52f50e757941cbff5b7c2e06a1ab7e9dp6,
    0x1.p63
  },
  { // Entry 984
    -0x1.52f50e757941cbff5b7c2e06a1ab7e9dp6,
    -0x1.p63
  },
  { // Entry 985
    -0x1.29cbd12821b399c9ee4f265da51881a8p1,
    0x1.000002p63
  },
  { // Entry 986
    0x1.29cbd12821b399c9ee4f265da51881a8p1,
    -0x1.000002p63
  },
  { // Entry 987
    0x1.3e4d9148d7086727da944e1c052b68afp-1,
    0x1.fffffep26
  },
  { // Entry 988
    -0x1.3e4d9148d7086727da944e1c052b68afp-1,
    -0x1.fffffep26
  },
  { // Entry 989
    -0x1.2e8fc1af81d8baa8899a3325200c0dcbp0,
    0x1.p27
  },
  { // Entry 990
    0x1.2e8fc1af81d8baa8899a3325200c0dcbp0,
    -0x1.p27
  },
  { // Entry 991
    -0x1.4ce9748e524f77ad85735c7f7d668cf1p-1,
    0x1.000002p27
  },
  { // Entry 992
    0x1.4ce9748e524f77ad85735c7f7d668cf1p-1,
    -0x1.000002p27
  },
  { // Entry 993
    0x1.7e3005d57ed93ae45b1bea3e3615bb67p1,
    0x1.fffffep23
  },
  { // Entry 994
    -0x1.7e3005d57ed93ae45b1bea3e3615bb67p1,
    -0x1.fffffep23
  },
  { // Entry 995
    -0x1.3ea28271a9bea36e744f9ce537ba4b59p0,
    0x1.p24
  },
  { // Entry 996
    0x1.3ea28271a9bea36e744f9ce537ba4b59p0,
    -0x1.p24
  },
  { // Entry 997
    0x1.fe929b4282105a160a9be2731df20a6cp0,
    0x1.000002p24
  },
  { // Entry 998
    -0x1.fe929b4282105a160a9be2731df20a6cp0,
    -0x1.000002p24
  },
  { // Entry 999
    0x1.2866f06194e0c2c7ee22ee9f8f9dcaeep0,
    0x1.fffffep1
  },
  { // Entry 1000
    -0x1.2866f06194e0c2c7ee22ee9f8f9dcaeep0,
    -0x1.fffffep1
  },
  { // Entry 1001
    0x1.2866f9be4de1370db9078607012cb07bp0,
    0x1.p2
  },
  { // Entry 1002
    -0x1.2866f9be4de1370db9078607012cb07bp0,
    -0x1.p2
  },
  { // Entry 1003
    0x1.28670c77c0e647138d4fc7181ef9b61fp0,
    0x1.000002p2
  },
  { // Entry 1004
    -0x1.28670c77c0e647138d4fc7181ef9b61fp0,
    -0x1.000002p2
  },
  { // Entry 1005
    -0x1.17af68a6d42f772bd249f5d692afa4e7p1,
    0x1.fffffep0
  },
  { // Entry 1006
    0x1.17af68a6d42f772bd249f5d692afa4e7p1,
    -0x1.fffffep0
  },
  { // Entry 1007
    -0x1.17af62e0950f83b5099087aaf67af9c1p1,
    0x1.p1
  },
  { // Entry 1008
    0x1.17af62e0950f83b5099087aaf67af9c1p1,
    -0x1.p1
  },
  { // Entry 1009
    -0x1.17af5754176705173cec89d01381f553p1,
    0x1.000002p1
  },
  { // Entry 1010
    0x1.17af5754176705173cec89d01381f553p1,
    -0x1.000002p1
  },
  { // Entry 1011
    0x1.8eb2425eff72860d56d61056db54ef67p0,
    0x1.fffffep-1
  },
  { // Entry 1012
    -0x1.8eb2425eff72860d56d61056db54ef67p0,
    -0x1.fffffep-1
  },
  { // Entry 1013
    0x1.8eb245cbee3a5b8acc7d41323140b3b5p0,
    0x1.p0
  },
  { // Entry 1014
    -0x1.8eb245cbee3a5b8acc7d41323140b3b5p0,
    -0x1.p0
  },
  { // Entry 1015
    0x1.8eb24ca5cbea08f991206a3eaf93ab98p0,
    0x1.000002p0
  },
  { // Entry 1016
    -0x1.8eb24ca5cbea08f991206a3eaf93ab98p0,
    -0x1.000002p0
  },
  { // Entry 1017
    0x1.17b4f472cd791aabfe4ea91afb5e79e7p-1,
    0x1.fffffep-2
  },
  { // Entry 1018
    -0x1.17b4f472cd791aabfe4ea91afb5e79e7p-1,
    -0x1.fffffep-2
  },
  { // Entry 1019
    0x1.17b4f5bf3474a4317964807882444cc8p-1,
    0x1.p-1
  },
  { // Entry 1020
    -0x1.17b4f5bf3474a4317964807882444cc8p-1,
    -0x1.p-1
  },
  { // Entry 1021
    0x1.17b4f858026dd8033ed3d8d6d5350ca9p-1,
    0x1.000002p-1
  },
  { // Entry 1022
    -0x1.17b4f858026dd8033ed3d8d6d5350ca9p-1,
    -0x1.000002p-1
  },
  { // Entry 1023
    0x1.0578593313db659cf3ab88a235218456p-2,
    0x1.fffffep-3
  },
  { // Entry 1024
    -0x1.0578593313db659cf3ab88a235218456p-2,
    -0x1.fffffep-3
  },
  { // Entry 1025
    0x1.05785a43c4c55e63940188965c28bd0fp-2,
    0x1.p-2
  },
  { // Entry 1026
    -0x1.05785a43c4c55e63940188965c28bd0fp-2,
    -0x1.p-2
  },
  { // Entry 1027
    0x1.05785c652699b8628b7876b7bd83c0ccp-2,
    0x1.000002p-2
  },
  { // Entry 1028
    -0x1.05785c652699b8628b7876b7bd83c0ccp-2,
    -0x1.000002p-2
  },
  { // Entry 1029
    0x1.015779ed46574724b9025a4472a1ae0ap-3,
    0x1.fffffep-4
  },
  { // Entry 1030
    -0x1.015779ed46574724b9025a4472a1ae0ap-3,
    -0x1.fffffep-4
  },
  { // Entry 1031
    0x1.01577af1511a4e0459f5b872d4ff34fdp-3,
    0x1.p-3
  },
  { // Entry 1032
    -0x1.01577af1511a4e0459f5b872d4ff34fdp-3,
    -0x1.p-3
  },
  { // Entry 1033
    0x1.01577cf966a0744553dd44a994f0bbd1p-3,
    0x1.000002p-3
  },
  { // Entry 1034
    -0x1.01577cf966a0744553dd44a994f0bbd1p-3,
    -0x1.000002p-3
  },
  { // Entry 1035
    0x1.005576844d44fda0b80348bb17498aa1p-4,
    0x1.fffffep-5
  },
  { // Entry 1036
    -0x1.005576844d44fda0b80348bb17498aa1p-4,
    -0x1.fffffep-5
  },
  { // Entry 1037
    0x1.005577854df0083293be639057b0c681p-4,
    0x1.p-4
  },
  { // Entry 1038
    -0x1.005577854df0083293be639057b0c681p-4,
    -0x1.p-4
  },
  { // Entry 1039
    0x1.005579874f46235e52082a4d0ddfc6e1p-4,
    0x1.000002p-4
  },
  { // Entry 1040
    -0x1.005579874f46235e52082a4d0ddfc6e1p-4,
    -0x1.000002p-4
  },
  { // Entry 1041
    0x1.001556776eb5d98f82e1b5eab28c6b5fp-5,
    0x1.fffffep-6
  },
  { // Entry 1042
    -0x1.001556776eb5d98f82e1b5eab28c6b5fp-5,
    -0x1.fffffep-6
  },
  { // Entry 1043
    0x1.00155777aec0857d22c97e809860288dp-5,
    0x1.p-5
  },
  { // Entry 1044
    -0x1.00155777aec0857d22c97e809860288dp-5,
    -0x1.p-5
  },
  { // Entry 1045
    0x1.001559782ed5ded8e2b4c819cb7c9f11p-5,
    0x1.000002p-5
  },
  { // Entry 1046
    -0x1.001559782ed5ded8e2b4c819cb7c9f11p-5,
    -0x1.000002p-5
  },
  { // Entry 1047
    0x1.000554776853e041010da22a656f8267p-6,
    0x1.fffffep-7
  },
  { // Entry 1048
    -0x1.000554776853e041010da22a656f8267p-6,
    -0x1.fffffep-7
  },
  { // Entry 1049
    0x1.0005557778548ae1b5f60574706e8238p-6,
    0x1.p-6
  },
  { // Entry 1050
    -0x1.0005557778548ae1b5f60574706e8238p-6,
    -0x1.p-6
  },
  { // Entry 1051
    0x1.000557779855e08327c758e20d691dadp-6,
    0x1.000002p-6
  },
  { // Entry 1052
    -0x1.000557779855e08327c758e20d691dadp-6,
    -0x1.000002p-6
  },
  { // Entry 1053
    0x1.fffffe0aaaaa8aeeef0d9b53ad2f4823p-15,
    0x1.fffffep-15
  },
  { // Entry 1054
    -0x1.fffffe0aaaaa8aeeef0d9b53ad2f4823p-15,
    -0x1.fffffep-15
  },
  { // Entry 1055
    0x1.00000005555555777777785485485a1ep-14,
    0x1.p-14
  },
  { // Entry 1056
    -0x1.00000005555555777777785485485a1ep-14,
    -0x1.p-14
  },
  { // Entry 1057
    0x1.000002055555757777b8cdaa0aa9c640p-14,
    0x1.000002p-14
  },
  { // Entry 1058
    -0x1.000002055555757777b8cdaa0aa9c640p-14,
    -0x1.000002p-14
  },
  { // Entry 1059
    0x1.fffffe00000002aaaaa2aaaab2aeeeecp-28,
    0x1.fffffep-28
  },
  { // Entry 1060
    -0x1.fffffe00000002aaaaa2aaaab2aeeeecp-28,
    -0x1.fffffep-28
  },
  { // Entry 1061
    0x1.00000000000001555555555555577777p-27,
    0x1.p-27
  },
  { // Entry 1062
    -0x1.00000000000001555555555555577777p-27,
    -0x1.p-27
  },
  { // Entry 1063
    0x1.0000020000000155555d555565577782p-27,
    0x1.000002p-27
  },
  { // Entry 1064
    -0x1.0000020000000155555d555565577782p-27,
    -0x1.000002p-27
  },
  { // Entry 1065
    0x1.fffffe000000000aaaaa8aaaaacaaaeep-31,
    0x1.fffffep-31
  },
  { // Entry 1066
    -0x1.fffffe000000000aaaaa8aaaaacaaaeep-31,
    -0x1.fffffep-31
  },
  { // Entry 1067
    0x1.00000000000000055555555555555577p-30,
    0x1.p-30
  },
  { // Entry 1068
    -0x1.00000000000000055555555555555577p-30,
    -0x1.p-30
  },
  { // Entry 1069
    0x1.00000200000000055555755555955577p-30,
    0x1.000002p-30
  },
  { // Entry 1070
    -0x1.00000200000000055555755555955577p-30,
    -0x1.000002p-30
  },
  { // Entry 1071
    0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    -0x1.fffffep127
  },
  { // Entry 1072
    -0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    0x1.fffffep127
  },
  { // Entry 1073
    -0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    0x1.fffffep127
  },
  { // Entry 1074
    0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    -0x1.fffffep127
  },
  { // Entry 1075
    -0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    0x1.fffffep127
  },
  { // Entry 1076
    0x1.393d94b4988c1f254345c9f7d9ea0c03p-1,
    -0x1.fffffep127
  },
  { // Entry 1077
    0x1.acf315a87aa5da8654c844b917d14745p-1,
    0x1.fffffcp127
  },
  { // Entry 1078
    -0x1.acf315a87aa5da8654c844b917d14745p-1,
    -0x1.fffffcp127
  },
  { // Entry 1079
    0x1.777a5cf72cedf3b544c81808b515f1f9p-24,
    0x1.921fb6p1
  },
  { // Entry 1080
    -0x1.777a5cf72cedf3b544c81808b515f1f9p-24,
    -0x1.921fb6p1
  },
  { // Entry 1081
    -0x1.5d14946dc98975d6421a55284fe020a1p24,
    0x1.921fb6p0
  },
  { // Entry 1082
    0x1.5d14946dc98975d6421a55284fe020a1p24,
    -0x1.921fb6p0
  },
  { // Entry 1083
    0x1.8eb24ca5cbea08f991206a3eaf93ab98p0,
    0x1.000002p0
  },
  { // Entry 1084
    -0x1.8eb24ca5cbea08f991206a3eaf93ab98p0,
    -0x1.000002p0
  },
  { // Entry 1085
    0x1.8eb245cbee3a5b8acc7d41323140b3b5p0,
    0x1.p0
  },
  { // Entry 1086
    -0x1.8eb245cbee3a5b8acc7d41323140b3b5p0,
    -0x1.p0
  },
  { // Entry 1087
    0x1.8eb2425eff72860d56d61056db54ef67p0,
    0x1.fffffep-1
  },
  { // Entry 1088
    -0x1.8eb2425eff72860d56d61056db54ef67p0,
    -0x1.fffffep-1
  },
  { // Entry 1089
    0x1.000000bbbd2ec06d6d6fff3655a346acp0,
    0x1.921fb6p-1
  },
  { // Entry 1090
    -0x1.000000bbbd2ec06d6d6fff3655a346acp0,
    -0x1.921fb6p-1
  },
  { // Entry 1091
    0x1.000002p-126,
    0x1.000002p-126
  },
  { // Entry 1092
    -0x1.000002p-126,
    -0x1.000002p-126
  },
  { // Entry 1093
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1094
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1095
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1096
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1097
    0x1.fffff8p-127,
    0x1.fffff8p-127
  },
  { // Entry 1098
    -0x1.fffff8p-127,
    -0x1.fffff8p-127
  },
  { // Entry 1099
    0x1.p-148,
    0x1.p-148
  },
  { // Entry 1100
    -0x1.p-148,
    -0x1.p-148
  },
  { // Entry 1101
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1102
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1103
    0.0,
    0.0f
  },
  { // Entry 1104
    -0.0,
    -0.0f
  },
};
```