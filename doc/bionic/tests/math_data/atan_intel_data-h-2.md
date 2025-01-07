Response:
The user wants to understand the purpose of the provided C code snippet. This file seems to contain test data for the `atan` function in Android's bionic library.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Function:** The filename `atan_intel_data.handroid` strongly suggests this file holds data related to the `atan` (arctangent) function. The "intel" part might hint at architecture-specific data or the origin of the data. The ".handroid" suffix is less clear but likely signifies a specific data format or origin within the Android project.

2. **Analyze the Data Structure:** The data is presented as a series of `{ value1, value2 }` pairs. Given it's for `atan`, `value1` likely represents the input to the `atan` function, and `value2` represents the expected output (the arctangent).

3. **Infer Functionality:** The primary function of this file is to provide test cases for the `atan` implementation. These test cases probably cover a range of input values, including positive and negative numbers, zero, and potentially edge cases.

4. **Connect to Android:**  This file is part of the bionic library, which is fundamental to Android. The `atan` function is a standard math function used across various Android components and applications. Examples of its use include:
    * **Graphics:** Calculating angles for animations or transformations.
    * **Sensors:** Processing sensor data that involves angular measurements.
    * **Location:**  Calculations related to bearing or direction.

5. **Explain Libc Function Implementation (General):**  It's important to explain that the *exact* implementation of `atan` within `libc` isn't directly visible in this data file. The data *tests* the implementation. A general explanation of how `atan` is typically implemented involves Taylor series expansions, CORDIC algorithms, or lookup tables with interpolation.

6. **Address Dynamic Linker (Not Applicable):** This data file doesn't directly involve the dynamic linker. It's static data. Therefore, it's crucial to state this explicitly and explain why the concepts of SO layout and linking process aren't relevant here.

7. **Provide Logical Reasoning (Based on Data):**
    * **Assumption:** The data pairs represent (input, expected_output) for `atan`.
    * **Example:**  If an entry is `{0.0, 0.0}`, it tests that `atan(0.0)` should return `0.0`. If there are entries with negative inputs, it tests the function's behavior for negative angles. The hexadecimal floating-point format provides precision.

8. **Illustrate Common Usage Errors (General):**  While the file itself doesn't cause errors, it's useful to discuss common mistakes when *using* `atan` in code:
    * **Incorrect Units:**  Forgetting that the output is typically in radians.
    * **Domain Errors (for related functions like `asin`, `acos`):**  Though not directly `atan`, it's a helpful point of context for new programmers.
    * **Precision Issues:** Understanding the limitations of floating-point arithmetic.

9. **Explain How Android Framework/NDK Reaches Here (Conceptual):**
    * **Framework:** When an Android framework component (e.g., a graphics library) needs to calculate an arctangent, it will ultimately call the `atan` function provided by the C library (`libc`).
    * **NDK:**  NDK developers can directly use `atan` from the standard C library in their native code. The NDK provides headers and libraries that link to bionic.

10. **Frida Hook Example (Conceptual):** Since we don't have the C code for `atan`, a direct hook of the *implementation* isn't possible with just this data file. However, we can demonstrate hooking the *usage* of `atan` in an application using Frida. This requires identifying where `atan` might be called within the app's code.

11. **Summarize Functionality (Specifically for Part 3):** Given this is part 3 of a 4-part discussion, focus the summary on the data itself within this specific part of the file (entries 716 to the end). The function remains the same (testing `atan`), but the specific range of test values is what defines this part.

12. **Structure and Language:**  Use clear and concise Chinese. Organize the information logically with headings and bullet points for better readability. Explain technical terms where necessary.

**Self-Correction/Refinement:**

* Initially, I might have been tempted to speculate on the "intel" part of the filename. However, without further context, it's best to stick to verifiable observations.
* I considered providing a detailed explanation of floating-point representation, but for this request, it might be too much detail and could distract from the core purpose. A brief mention of precision is sufficient.
* I also thought about including more complex mathematical concepts related to `atan`, but decided to keep the explanation focused on the practical aspects of testing.
* The Frida example needs to be general because we don't have a specific Android app in mind. The key is to illustrate the *process* of hooking.

By following this structured thought process, the answer addresses all aspects of the user's request in a comprehensive and understandable way.
好的，我们来归纳一下提供的代码片段（第 3 部分，从 Entry 716 到文件末尾）的功能。

**这个代码片段的功能是：为 `atan` 函数提供测试数据。**

更具体地说，这部分数据包含了大量的浮点数对，每一对都用于测试 `atan` 函数在不同输入值下的输出结果是否正确。

* **输入 (第一个值):**  代表 `atan` 函数的输入参数。
* **预期输出 (第二个值):** 代表对于给定的输入，`atan` 函数应该返回的正确结果。

**与 Android 功能的关系举例：**

`atan` 函数是 C 标准库 `<math.h>` 中的一部分，在 Android 的 C 库 bionic 中实现。它用于计算反正切值，即已知一个角的正切值，求该角的弧度。

在 Android 系统中，`atan` 函数会被各种组件和应用使用，例如：

* **图形处理:** 在 2D 或 3D 图形渲染中，计算角度进行旋转、变换等操作。例如，一个自定义 View 可能需要根据触摸事件计算旋转角度，这时就可能用到 `atan` 或 `atan2`。
* **传感器数据处理:**  在处理来自加速度计、陀螺仪等传感器的数据时，可能需要计算角度。例如，计算设备倾斜的角度。
* **地理位置计算:**  在地图应用或定位服务中，计算两个坐标点之间的方位角（bearing）。

**libc 函数 `atan` 的功能实现 (概要)：**

`atan(double x)` 函数计算的是参数 `x` 的反正切值，返回值的范围是 (-π/2, π/2) 弧度。

通常 `atan` 函数的实现会使用以下一种或多种技术：

* **泰勒级数展开:** 对于较小的 `x` 值，可以使用泰勒级数展开来逼近结果。
* **切比雪夫逼近:** 使用切比雪夫多项式来更有效地逼近函数值。
* **查找表与插值:**  预先计算一些关键点的 `atan` 值，存储在查找表中。对于其他输入，通过在查找表中查找相邻的点并进行插值来估算结果。
* **CORDIC 算法:**  一种迭代算法，通过一系列简单的移位和加减运算来逼近三角函数的值。

**这个数据文件本身并不涉及 `atan` 的具体实现，而是用于验证 `atan` 实现的正确性。**

**涉及 dynamic linker 的功能：**

这个数据文件是一个静态数据文件，它不涉及动态链接器的功能。动态链接器负责在程序运行时加载和链接共享库 (`.so` 文件)。

**so 布局样本和链接的处理过程 (不适用此文件):**

由于这个文件不涉及动态链接，所以关于 `.so` 布局和链接过程的讨论不适用于这里。通常，一个 `.so` 文件的布局会包含代码段、数据段、符号表等，链接过程涉及符号解析、重定位等步骤。

**逻辑推理 (基于数据内容):**

* **假设输入:** 代码中的每一行 `{input, expected_output}`。
* **输出:**  假设我们有一个 `atan` 函数的实现，将 `input` 值传递给它，我们期望得到 `expected_output` 值。

例如，对于 Entry 716:

* **假设输入:** `0x1.b6add448714dcb8a52cd35a987330f71p-1` (这是一个十六进制浮点数)
* **预期输出:** `0x1.27701caf89e78p0`

这个测试用例检查了当 `atan` 的输入为 `0x1.b6add448714dcb8a52cd35a987330f71p-1` 时，其返回值是否精确等于 `0x1.27701caf89e78p0`。

**用户或编程常见的使用错误 (与 `atan` 函数本身相关):**

虽然这个数据文件本身不会导致使用错误，但使用 `atan` 函数时常见的错误包括：

1. **单位错误:**  `atan` 返回的是弧度值，如果期望得到角度值，需要进行转换 (乘以 `180/PI`)。
2. **参数范围理解错误:** `atan` 的输入可以是任意实数，但其返回值范围是 (-π/2, π/2)。如果需要得到完整的角度范围 (0 到 2π 或 -π 到 π)，通常应该使用 `atan2(y, x)` 函数。
3. **精度问题:** 浮点数运算存在精度限制，不应期望得到绝对精确的结果。

**Android framework 或 NDK 如何一步步到达这里：**

这个数据文件是 bionic 库的内部测试数据，通常不会被 Android framework 或 NDK 直接访问。它的作用是在 bionic 库的开发和测试过程中，确保 `atan` 函数的实现符合预期。

一个简化的流程可能是：

1. **bionic 开发者编写 `atan` 函数的实现代码。**
2. **bionic 开发者创建或更新 `atan_intel_data.handroid` 文件，**  添加各种测试用例，覆盖不同的输入范围和边界条件。
3. **bionic 构建系统会使用这些测试数据来运行测试。**  这通常涉及到编译一个测试程序，该程序会读取数据文件中的输入，调用 `atan` 函数，并将结果与预期输出进行比较。
4. **如果测试失败，开发者会检查 `atan` 的实现并修复 bug。**

**Frida hook 示例调试这些步骤 (更准确地说，是调试 `atan` 函数的使用):**

由于我们无法直接 hook 到这个数据文件本身，我们可以演示如何 hook `atan` 函数在 Android 应用中的使用。

假设我们有一个 Android 应用，它在 native 代码中调用了 `atan` 函数。我们可以使用 Frida hook 这个调用：

```javascript
Java.perform(function() {
    var libc = Process.getModuleByName("libc.so");
    var atanPtr = libc.getExportByName("atan");

    if (atanPtr) {
        Interceptor.attach(atanPtr, {
            onEnter: function(args) {
                console.log("[+] atan called with argument: " + args[0]);
            },
            onLeave: function(retval) {
                console.log("[+] atan returned: " + retval);
            }
        });
        console.log("[+] Hooked atan function");
    } else {
        console.log("[-] atan function not found");
    }
});
```

**代码解释：**

1. `Java.perform(function() { ... });`:  确保 Frida 代码在 Dalvik/ART 虚拟机上下文中执行。
2. `Process.getModuleByName("libc.so");`:  获取 `libc.so` 模块的句柄。
3. `libc.getExportByName("atan");`:  获取 `atan` 函数的地址。
4. `Interceptor.attach(atanPtr, { ... });`:  在 `atan` 函数的入口和出口处设置 hook。
5. `onEnter: function(args)`:  在 `atan` 函数被调用时执行，`args[0]` 是第一个参数 (double)。
6. `onLeave: function(retval)`: 在 `atan` 函数返回时执行，`retval` 是返回值。

运行这个 Frida 脚本，当目标应用调用 `atan` 函数时，Frida 会打印出调用的参数和返回值。

**总结 (针对第 3 部分):**

这个代码片段（Entry 716 到文件末尾）的功能是 **为 Android bionic 库中的 `atan` 函数提供大量的测试数据**。这些数据以浮点数对的形式存在，用于验证 `atan` 函数在各种输入情况下的计算结果是否正确。  这部分数据延续了之前部分的功能，只是涵盖了不同的输入值范围。它并不涉及动态链接器的功能，而是 bionic 库内部测试的一部分，旨在保证数学函数的准确性。

Prompt: 
```
这是目录为bionic/tests/math_data/atan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共4部分，请归纳一下它的功能

"""
},
  { // Entry 716
    0x1.b6add448714dcb8a52cd35a987330f71p-1,
    0x1.27701caf89e78p0
  },
  { // Entry 717
    -0x1.b6add448714dcb8a52cd35a987330f71p-1,
    -0x1.27701caf89e78p0
  },
  { // Entry 718
    0x1.e87d358361bcd19359996a7779c977a2p-1,
    0x1.69173f8136c5cp0
  },
  { // Entry 719
    -0x1.e87d358361bcd19359996a7779c977a2p-1,
    -0x1.69173f8136c5cp0
  },
  { // Entry 720
    0x1.07cbfe8c14dd6c531603e943f23b5395p0,
    0x1.aabe6252e3a40p0
  },
  { // Entry 721
    -0x1.07cbfe8c14dd6c531603e943f23b5395p0,
    -0x1.aabe6252e3a40p0
  },
  { // Entry 722
    0x1.1762c60438ce078252d85e42621311efp0,
    0x1.ec65852490824p0
  },
  { // Entry 723
    -0x1.1762c60438ce078252d85e42621311efp0,
    -0x1.ec65852490824p0
  },
  { // Entry 724
    0x1.2404bf4b3eacd91e132bfb674e2913adp0,
    0x1.170653fb1eb04p1
  },
  { // Entry 725
    -0x1.2404bf4b3eacd91e132bfb674e2913adp0,
    -0x1.170653fb1eb04p1
  },
  { // Entry 726
    0x1.2e6a76d3a7c4b1226452cbee254cb00ep0,
    0x1.37d9e563f51f6p1
  },
  { // Entry 727
    -0x1.2e6a76d3a7c4b1226452cbee254cb00ep0,
    -0x1.37d9e563f51f6p1
  },
  { // Entry 728
    0x1.37189d975e5f721039ee06227b2cc34ep0,
    0x1.58ad76cccb8e8p1
  },
  { // Entry 729
    -0x1.37189d975e5f721039ee06227b2cc34ep0,
    -0x1.58ad76cccb8e8p1
  },
  { // Entry 730
    0x1.3e6fbb2c413941ff899c462376afaff3p0,
    0x1.79810835a1fdap1
  },
  { // Entry 731
    -0x1.3e6fbb2c413941ff899c462376afaff3p0,
    -0x1.79810835a1fdap1
  },
  { // Entry 732
    0x1.44b710bde944d3a9aeff63d91fa1f037p0,
    0x1.9a54999e786ccp1
  },
  { // Entry 733
    -0x1.44b710bde944d3a9aeff63d91fa1f037p0,
    -0x1.9a54999e786ccp1
  },
  { // Entry 734
    0x1.4a2407447a81aa4a6751ba1c00ad16b4p0,
    0x1.bb282b074edbep1
  },
  { // Entry 735
    -0x1.4a2407447a81aa4a6751ba1c00ad16b4p0,
    -0x1.bb282b074edbep1
  },
  { // Entry 736
    0x1.4edf430c00242d9760af2ba3d134ee30p0,
    0x1.dbfbbc70254b0p1
  },
  { // Entry 737
    -0x1.4edf430c00242d9760af2ba3d134ee30p0,
    -0x1.dbfbbc70254b0p1
  },
  { // Entry 738
    0x1.530823483d35eed7bdc41c7d43d4d1bep0,
    0x1.fccf4dd8fbba2p1
  },
  { // Entry 739
    -0x1.530823483d35eed7bdc41c7d43d4d1bep0,
    -0x1.fccf4dd8fbba2p1
  },
  { // Entry 740
    0x1.56b732e5cd9e621620c292f21c370a65p0,
    0x1.0ed16fa0e914ap2
  },
  { // Entry 741
    -0x1.56b732e5cd9e621620c292f21c370a65p0,
    -0x1.0ed16fa0e914ap2
  },
  { // Entry 742
    0x1.59ffe278fb5cfdacbc51061667641320p0,
    0x1.1f3b3855544c3p2
  },
  { // Entry 743
    -0x1.59ffe278fb5cfdacbc51061667641320p0,
    -0x1.1f3b3855544c3p2
  },
  { // Entry 744
    0x1.5cf1c53dd9ca8f4d320efaf2bed238dep0,
    0x1.2fa50109bf83cp2
  },
  { // Entry 745
    -0x1.5cf1c53dd9ca8f4d320efaf2bed238dep0,
    -0x1.2fa50109bf83cp2
  },
  { // Entry 746
    0x1.5f9977a47aee090d54ca7b763af2b8f6p0,
    0x1.400ec9be2abb5p2
  },
  { // Entry 747
    -0x1.5f9977a47aee090d54ca7b763af2b8f6p0,
    -0x1.400ec9be2abb5p2
  },
  { // Entry 748
    0x1.6201493b02235454cfe997849b56e6a4p0,
    0x1.5078927295f2ep2
  },
  { // Entry 749
    -0x1.6201493b02235454cfe997849b56e6a4p0,
    -0x1.5078927295f2ep2
  },
  { // Entry 750
    0x1.6431bb7edf2baae88464ead12ab4619ep0,
    0x1.60e25b27012a7p2
  },
  { // Entry 751
    -0x1.6431bb7edf2baae88464ead12ab4619ep0,
    -0x1.60e25b27012a7p2
  },
  { // Entry 752
    0x1.6631e1a595902c3b42171a76898ec8fbp0,
    0x1.714c23db6c620p2
  },
  { // Entry 753
    -0x1.6631e1a595902c3b42171a76898ec8fbp0,
    -0x1.714c23db6c620p2
  },
  { // Entry 754
    0x1.6807a9c540dd2ae72a3e8ad8c9147867p0,
    0x1.81b5ec8fd7999p2
  },
  { // Entry 755
    -0x1.6807a9c540dd2ae72a3e8ad8c9147867p0,
    -0x1.81b5ec8fd7999p2
  },
  { // Entry 756
    0x1.ef652dceca4daec044deb346c4b08d48p-5,
    0x1.effffffffffffp-5
  },
  { // Entry 757
    -0x1.ef652dceca4daec044deb346c4b08d48p-5,
    -0x1.effffffffffffp-5
  },
  { // Entry 758
    0x1.ef652dceca4dbeb14ee907159dd1c369p-5,
    0x1.fp-5
  },
  { // Entry 759
    -0x1.ef652dceca4dbeb14ee907159dd1c369p-5,
    -0x1.fp-5
  },
  { // Entry 760
    0x1.ef652dceca4dcea258f35ae476f20359p-5,
    0x1.f000000000001p-5
  },
  { // Entry 761
    -0x1.ef652dceca4dcea258f35ae476f20359p-5,
    -0x1.f000000000001p-5
  },
  { // Entry 762
    0x1.f57ab026c3a8ecb83ec0ccdd10add49ep-4,
    0x1.f7fffffffffffp-4
  },
  { // Entry 763
    -0x1.f57ab026c3a8ecb83ec0ccdd10add49ep-4,
    -0x1.f7fffffffffffp-4
  },
  { // Entry 764
    0x1.f57ab026c3a8fc7b278a06e9d0c43e3ap-4,
    0x1.f80p-4
  },
  { // Entry 765
    -0x1.f57ab026c3a8fc7b278a06e9d0c43e3ap-4,
    -0x1.f80p-4
  },
  { // Entry 766
    0x1.f57ab026c3a90c3e105340f690d6d5afp-4,
    0x1.f800000000001p-4
  },
  { // Entry 767
    -0x1.f57ab026c3a90c3e105340f690d6d5afp-4,
    -0x1.f800000000001p-4
  },
  { // Entry 768
    0x1.4923024ccb77ffc36091a6f234051783p-3,
    0x1.4bfffffffffffp-3
  },
  { // Entry 769
    -0x1.4923024ccb77ffc36091a6f234051783p-3,
    -0x1.4bfffffffffffp-3
  },
  { // Entry 770
    0x1.4923024ccb780f5a7e2ead4e2bd24d33p-3,
    0x1.4c0p-3
  },
  { // Entry 771
    -0x1.4923024ccb780f5a7e2ead4e2bd24d33p-3,
    -0x1.4c0p-3
  },
  { // Entry 772
    0x1.4923024ccb781ef19bcbb3aa2395a92bp-3,
    0x1.4c00000000001p-3
  },
  { // Entry 773
    -0x1.4923024ccb781ef19bcbb3aa2395a92bp-3,
    -0x1.4c00000000001p-3
  },
  { // Entry 774
    0x1.2a73a661eaf04c94833e0199180e931dp-2,
    0x1.3333333333332p-2
  },
  { // Entry 775
    -0x1.2a73a661eaf04c94833e0199180e931dp-2,
    -0x1.3333333333332p-2
  },
  { // Entry 776
    0x1.2a73a661eaf05b424f928e83f4ea7bc2p-2,
    0x1.3333333333333p-2
  },
  { // Entry 777
    -0x1.2a73a661eaf05b424f928e83f4ea7bc2p-2,
    -0x1.3333333333333p-2
  },
  { // Entry 778
    0x1.2a73a661eaf069f01be71b6ed1a61259p-2,
    0x1.3333333333334p-2
  },
  { // Entry 779
    -0x1.2a73a661eaf069f01be71b6ed1a61259p-2,
    -0x1.3333333333334p-2
  },
  { // Entry 780
    0x1.2fc48220cc1fce7fc93a77a07e48b002p-1,
    0x1.594317acc4ef8p-1
  },
  { // Entry 781
    -0x1.2fc48220cc1fce7fc93a77a07e48b002p-1,
    -0x1.594317acc4ef8p-1
  },
  { // Entry 782
    0x1.2fc48220cc1fd97f6b9419f2cefa0646p-1,
    0x1.594317acc4ef9p-1
  },
  { // Entry 783
    -0x1.2fc48220cc1fd97f6b9419f2cefa0646p-1,
    -0x1.594317acc4ef9p-1
  },
  { // Entry 784
    0x1.2fc48220cc1fe47f0dedbc451f59c99cp-1,
    0x1.594317acc4efap-1
  },
  { // Entry 785
    -0x1.2fc48220cc1fe47f0dedbc451f59c99cp-1,
    -0x1.594317acc4efap-1
  },
  { // Entry 786
    0x1.538f57b89061e1a19793adab72dc4cd0p-1,
    0x1.8ffffffffffffp-1
  },
  { // Entry 787
    -0x1.538f57b89061e1a19793adab72dc4cd0p-1,
    -0x1.8ffffffffffffp-1
  },
  { // Entry 788
    0x1.538f57b89061eb9122d5096b7cf267ebp-1,
    0x1.9p-1
  },
  { // Entry 789
    -0x1.538f57b89061eb9122d5096b7cf267ebp-1,
    -0x1.9p-1
  },
  { // Entry 790
    0x1.538f57b89061f580ae16652b86bb6353p-1,
    0x1.9000000000001p-1
  },
  { // Entry 791
    -0x1.538f57b89061f580ae16652b86bb6353p-1,
    -0x1.9000000000001p-1
  },
  { // Entry 792
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 793
    0.0,
    0x1.0p-1074
  },
  { // Entry 794
    -0.0,
    -0.0
  },
  { // Entry 795
    0.0,
    0x1.0p-1074
  },
  { // Entry 796
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 797
    0x1.91cd24dd4f86f3abcfa4276d83a13d73p-5,
    0x1.921fb54442d17p-5
  },
  { // Entry 798
    -0x1.91cd24dd4f86f3abcfa4276d83a13d73p-5,
    -0x1.921fb54442d17p-5
  },
  { // Entry 799
    0x1.91cd24dd4f8703a1f7188f1d645421b1p-5,
    0x1.921fb54442d18p-5
  },
  { // Entry 800
    -0x1.91cd24dd4f8703a1f7188f1d645421b1p-5,
    -0x1.921fb54442d18p-5
  },
  { // Entry 801
    0x1.91cd24dd4f8713981e8cf6cd45063dd6p-5,
    0x1.921fb54442d19p-5
  },
  { // Entry 802
    -0x1.91cd24dd4f8713981e8cf6cd45063dd6p-5,
    -0x1.921fb54442d19p-5
  },
  { // Entry 803
    0x1.90d6dfbf0463be2efc3d3ae995b9e240p-4,
    0x1.921fb54442d17p-4
  },
  { // Entry 804
    -0x1.90d6dfbf0463be2efc3d3ae995b9e240p-4,
    -0x1.921fb54442d17p-4
  },
  { // Entry 805
    0x1.90d6dfbf0463ce07e23e541458c4aa07p-4,
    0x1.921fb54442d18p-4
  },
  { // Entry 806
    -0x1.90d6dfbf0463ce07e23e541458c4aa07p-4,
    -0x1.921fb54442d18p-4
  },
  { // Entry 807
    0x1.90d6dfbf0463dde0c83f6d3f1bcc5cd7p-4,
    0x1.921fb54442d19p-4
  },
  { // Entry 808
    -0x1.90d6dfbf0463dde0c83f6d3f1bcc5cd7p-4,
    -0x1.921fb54442d19p-4
  },
  { // Entry 809
    0x1.8d128eae9561353a88062ef0a34b4e80p-3,
    0x1.921fb54442d17p-3
  },
  { // Entry 810
    -0x1.8d128eae9561353a88062ef0a34b4e80p-3,
    -0x1.921fb54442d17p-3
  },
  { // Entry 811
    0x1.8d128eae956144a27ad04eaa5b924d06p-3,
    0x1.921fb54442d18p-3
  },
  { // Entry 812
    -0x1.8d128eae956144a27ad04eaa5b924d06p-3,
    -0x1.921fb54442d18p-3
  },
  { // Entry 813
    0x1.8d128eae9561540a6d9a6e6413cda4f7p-3,
    0x1.921fb54442d19p-3
  },
  { // Entry 814
    -0x1.8d128eae9561540a6d9a6e6413cda4f7p-3,
    -0x1.921fb54442d19p-3
  },
  { // Entry 815
    0x1.7f2d6a24777e099c2376cf0898b3c360p-2,
    0x1.921fb54442d17p-2
  },
  { // Entry 816
    -0x1.7f2d6a24777e099c2376cf0898b3c360p-2,
    -0x1.921fb54442d17p-2
  },
  { // Entry 817
    0x1.7f2d6a24777e1778e0d5c62102085610p-2,
    0x1.921fb54442d18p-2
  },
  { // Entry 818
    -0x1.7f2d6a24777e1778e0d5c62102085610p-2,
    -0x1.921fb54442d18p-2
  },
  { // Entry 819
    0x1.7f2d6a24777e25559e34bd396b372d9ep-2,
    0x1.921fb54442d19p-2
  },
  { // Entry 820
    -0x1.7f2d6a24777e25559e34bd396b372d9ep-2,
    -0x1.921fb54442d19p-2
  },
  { // Entry 821
    0x1.54e04c05d069fa1ecac0c3f5d7fae70fp-1,
    0x1.921fb54442d17p-1
  },
  { // Entry 822
    -0x1.54e04c05d069fa1ecac0c3f5d7fae70fp-1,
    -0x1.921fb54442d17p-1
  },
  { // Entry 823
    0x1.54e04c05d06a04041ccf30f00110c0f6p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 824
    -0x1.54e04c05d06a04041ccf30f00110c0f6p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 825
    0x1.54e04c05d06a0de96edd9dea29d9b191p-1,
    0x1.921fb54442d19p-1
  },
  { // Entry 826
    -0x1.54e04c05d06a0de96edd9dea29d9b191p-1,
    -0x1.921fb54442d19p-1
  },
  { // Entry 827
    0x1.00fe987ed02fed962e123a7e12a6d283p0,
    0x1.921fb54442d17p0
  },
  { // Entry 828
    -0x1.00fe987ed02fed962e123a7e12a6d283p0,
    -0x1.921fb54442d17p0
  },
  { // Entry 829
    0x1.00fe987ed02ff23377d99ec36db533fep0,
    0x1.921fb54442d18p0
  },
  { // Entry 830
    -0x1.00fe987ed02ff23377d99ec36db533fep0,
    -0x1.921fb54442d18p0
  },
  { // Entry 831
    0x1.00fe987ed02ff6d0c1a10308c880b0d3p0,
    0x1.921fb54442d19p0
  },
  { // Entry 832
    -0x1.00fe987ed02ff6d0c1a10308c880b0d3p0,
    -0x1.921fb54442d19p0
  },
  { // Entry 833
    0x1.433b8a322ddd266fd81ec843d7c92a7ap0,
    0x1.921fb54442d17p1
  },
  { // Entry 834
    -0x1.433b8a322ddd266fd81ec843d7c92a7ap0,
    -0x1.921fb54442d17p1
  },
  { // Entry 835
    0x1.433b8a322ddd29618168a21c962c68bcp0,
    0x1.921fb54442d18p1
  },
  { // Entry 836
    -0x1.433b8a322ddd29618168a21c962c68bcp0,
    -0x1.921fb54442d18p1
  },
  { // Entry 837
    0x1.433b8a322ddd2c532ab27bf55459320bp0,
    0x1.921fb54442d19p1
  },
  { // Entry 838
    -0x1.433b8a322ddd2c532ab27bf55459320bp0,
    -0x1.921fb54442d19p1
  },
  { // Entry 839
    0x1.69b8154baf42e0f527ff3f4df7a4633ep0,
    0x1.921fb54442d17p2
  },
  { // Entry 840
    -0x1.69b8154baf42e0f527ff3f4df7a4633ep0,
    -0x1.921fb54442d17p2
  },
  { // Entry 841
    0x1.69b8154baf42e289ea46de59f75a7b90p0,
    0x1.921fb54442d18p2
  },
  { // Entry 842
    -0x1.69b8154baf42e289ea46de59f75a7b90p0,
    -0x1.921fb54442d18p2
  },
  { // Entry 843
    0x1.69b8154baf42e41eac8e7d65f6f129e7p0,
    0x1.921fb54442d19p2
  },
  { // Entry 844
    -0x1.69b8154baf42e41eac8e7d65f6f129e7p0,
    -0x1.921fb54442d19p2
  },
  { // Entry 845
    0x1.7dcb7c5c399ec04ad5c1eabbb0cccf9fp0,
    0x1.921fb54442d17p3
  },
  { // Entry 846
    -0x1.7dcb7c5c399ec04ad5c1eabbb0cccf9fp0,
    -0x1.921fb54442d17p3
  },
  { // Entry 847
    0x1.7dcb7c5c399ec11908f5986443f30bdap0,
    0x1.921fb54442d18p3
  },
  { // Entry 848
    -0x1.7dcb7c5c399ec11908f5986443f30bdap0,
    -0x1.921fb54442d18p3
  },
  { // Entry 849
    0x1.7dcb7c5c399ec1e73c29460cd708f9d8p0,
    0x1.921fb54442d19p3
  },
  { // Entry 850
    -0x1.7dcb7c5c399ec1e73c29460cd708f9d8p0,
    -0x1.921fb54442d19p3
  },
  { // Entry 851
    0x1.87f17cfda0b5caf7b170dd86f8287b63p0,
    0x1.921fb54442d17p4
  },
  { // Entry 852
    -0x1.87f17cfda0b5caf7b170dd86f8287b63p0,
    -0x1.921fb54442d17p4
  },
  { // Entry 853
    0x1.87f17cfda0b5cb5f4832c04cdf736f84p0,
    0x1.921fb54442d18p4
  },
  { // Entry 854
    -0x1.87f17cfda0b5cb5f4832c04cdf736f84p0,
    -0x1.921fb54442d18p4
  },
  { // Entry 855
    0x1.87f17cfda0b5cbc6def4a312c6b628b0p0,
    0x1.921fb54442d19p4
  },
  { // Entry 856
    -0x1.87f17cfda0b5cbc6def4a312c6b628b0p0,
    -0x1.921fb54442d19p4
  },
  { // Entry 857
    0x1.8d08152eddb7a3b8c976d7e120ba1197p0,
    0x1.921fb54442d17p5
  },
  { // Entry 858
    -0x1.8d08152eddb7a3b8c976d7e120ba1197p0,
    -0x1.921fb54442d17p5
  },
  { // Entry 859
    0x1.8d08152eddb7a3eca4948f3acff50864p0,
    0x1.921fb54442d18p5
  },
  { // Entry 860
    -0x1.8d08152eddb7a3eca4948f3acff50864p0,
    -0x1.921fb54442d18p5
  },
  { // Entry 861
    0x1.8d08152eddb7a4207fb246947f2bdf35p0,
    0x1.921fb54442d19p5
  },
  { // Entry 862
    -0x1.8d08152eddb7a4207fb246947f2bdf35p0,
    -0x1.921fb54442d19p5
  },
  { // Entry 863
    0x1.8f93d4b78b7cddf446e36e538b980193p0,
    0x1.921fb54442d17p6
  },
  { // Entry 864
    -0x1.8f93d4b78b7cddf446e36e538b980193p0,
    -0x1.921fb54442d17p6
  },
  { // Entry 865
    0x1.8f93d4b78b7cde0e366aa212646d3cb6p0,
    0x1.921fb54442d18p6
  },
  { // Entry 866
    -0x1.8f93d4b78b7cde0e366aa212646d3cb6p0,
    -0x1.921fb54442d18p6
  },
  { // Entry 867
    0x1.8f93d4b78b7cde2825f1d5d13d40678bp0,
    0x1.921fb54442d19p6
  },
  { // Entry 868
    -0x1.8f93d4b78b7cde2825f1d5d13d40678bp0,
    -0x1.921fb54442d19p6
  },
  { // Entry 869
    0x1.90d9c2ed8873775a4f6e3fe4c3a5982bp0,
    0x1.921fb54442d17p7
  },
  { // Entry 870
    -0x1.90d9c2ed8873775a4f6e3fe4c3a5982bp0,
    -0x1.921fb54442d17p7
  },
  { // Entry 871
    0x1.90d9c2ed887377674770eac36c2436b5p0,
    0x1.921fb54442d18p7
  },
  { // Entry 872
    -0x1.90d9c2ed887377674770eac36c2436b5p0,
    -0x1.921fb54442d18p7
  },
  { // Entry 873
    0x1.90d9c2ed887377743f7395a214a1cd0ep0,
    0x1.921fb54442d19p7
  },
  { // Entry 874
    -0x1.90d9c2ed887377743f7395a214a1cd0ep0,
    -0x1.921fb54442d19p7
  },
  { // Entry 875
    0x1.2b5f4b53c7948df5568782d0a75b8459p0,
    0x1.2d97c7f3321d1p1
  },
  { // Entry 876
    -0x1.2b5f4b53c7948df5568782d0a75b8459p0,
    -0x1.2d97c7f3321d1p1
  },
  { // Entry 877
    0x1.2b5f4b53c79492d7b5a6cd6203c9aae2p0,
    0x1.2d97c7f3321d2p1
  },
  { // Entry 878
    -0x1.2b5f4b53c79492d7b5a6cd6203c9aae2p0,
    -0x1.2d97c7f3321d2p1
  },
  { // Entry 879
    0x1.2b5f4b53c79497ba14c617f35fc7662ep0,
    0x1.2d97c7f3321d3p1
  },
  { // Entry 880
    -0x1.2b5f4b53c79497ba14c617f35fc7662ep0,
    -0x1.2d97c7f3321d3p1
  },
  { // Entry 881
    0x1.524a69fcff2af09f5f140df341a455ddp0,
    0x1.f6a7a2955385dp1
  },
  { // Entry 882
    -0x1.524a69fcff2af09f5f140df341a455ddp0,
    -0x1.f6a7a2955385dp1
  },
  { // Entry 883
    0x1.524a69fcff2af2923cab5c00b660c55fp0,
    0x1.f6a7a2955385ep1
  },
  { // Entry 884
    -0x1.524a69fcff2af2923cab5c00b660c55fp0,
    -0x1.f6a7a2955385ep1
  },
  { // Entry 885
    0x1.524a69fcff2af4851a42aa0e2aff61bcp0,
    0x1.f6a7a2955385fp1
  },
  { // Entry 886
    -0x1.524a69fcff2af4851a42aa0e2aff61bcp0,
    -0x1.f6a7a2955385fp1
  },
  { // Entry 887
    0x1.5c97d37d98aa37af1a1b75a619098288p0,
    0x1.2d97c7f3321d1p2
  },
  { // Entry 888
    -0x1.5c97d37d98aa37af1a1b75a619098288p0,
    -0x1.2d97c7f3321d1p2
  },
  { // Entry 889
    0x1.5c97d37d98aa3a711b94359371aaf903p0,
    0x1.2d97c7f3321d2p2
  },
  { // Entry 890
    -0x1.5c97d37d98aa3a711b94359371aaf903p0,
    -0x1.2d97c7f3321d2p2
  },
  { // Entry 891
    0x1.5c97d37d98aa3d331d0cf580ca04c102p0,
    0x1.2d97c7f3321d3p2
  },
  { // Entry 892
    -0x1.5c97d37d98aa3d331d0cf580ca04c102p0,
    -0x1.2d97c7f3321d3p2
  },
  { // Entry 893
    0x1.64102fc571c7422b6ad0ed05fd24e652p0,
    0x1.5fdbbe9bba774p2
  },
  { // Entry 894
    -0x1.64102fc571c7422b6ad0ed05fd24e652p0,
    -0x1.5fdbbe9bba774p2
  },
  { // Entry 895
    0x1.64102fc571c744381d266feb08ddfcc4p0,
    0x1.5fdbbe9bba775p2
  },
  { // Entry 896
    -0x1.64102fc571c744381d266feb08ddfcc4p0,
    -0x1.5fdbbe9bba775p2
  },
  { // Entry 897
    0x1.64102fc571c74644cf7bf2d01468e265p0,
    0x1.5fdbbe9bba776p2
  },
  { // Entry 898
    -0x1.64102fc571c74644cf7bf2d01468e265p0,
    -0x1.5fdbbe9bba776p2
  },
  { // Entry 899
    0x1.6e2561a6cd2181c009d7d863e666c437p0,
    0x1.c463abeccb2bap2
  },
  { // Entry 900
    -0x1.6e2561a6cd2181c009d7d863e666c437p0,
    -0x1.c463abeccb2bap2
  },
  { // Entry 901
    0x1.6e2561a6cd21830183c87ae1761354b0p0,
    0x1.c463abeccb2bbp2
  },
  { // Entry 902
    -0x1.6e2561a6cd21830183c87ae1761354b0p0,
    -0x1.c463abeccb2bbp2
  },
  { // Entry 903
    0x1.6e2561a6cd218442fdb91d5f05a99ap0,
    0x1.c463abeccb2bcp2
  },
  { // Entry 904
    -0x1.6e2561a6cd218442fdb91d5f05a99ap0,
    -0x1.c463abeccb2bcp2
  },
  { // Entry 905
    0x1.71b4100f0956769d1c64ae4d729107a5p0,
    0x1.f6a7a2955385dp2
  },
  { // Entry 906
    -0x1.71b4100f0956769d1c64ae4d729107a5p0,
    -0x1.f6a7a2955385dp2
  },
  { // Entry 907
    0x1.71b4100f095677a27b2c03b940d5e613p0,
    0x1.f6a7a2955385ep2
  },
  { // Entry 908
    -0x1.71b4100f095677a27b2c03b940d5e613p0,
    -0x1.f6a7a2955385ep2
  },
  { // Entry 909
    0x1.71b4100f095678a7d9f359250f0a64c8p0,
    0x1.f6a7a2955385fp2
  },
  { // Entry 910
    -0x1.71b4100f095678a7d9f359250f0a64c8p0,
    -0x1.f6a7a2955385fp2
  },
  { // Entry 911
    0x1.749f96097c7015073733e2e3659a844bp0,
    0x1.1475cc9eedeffp3
  },
  { // Entry 912
    -0x1.749f96097c7015073733e2e3659a844bp0,
    -0x1.1475cc9eedeffp3
  },
  { // Entry 913
    0x1.749f96097c7016b86e95ca64b3f1546fp0,
    0x1.1475cc9eedfp3
  },
  { // Entry 914
    -0x1.749f96097c7016b86e95ca64b3f1546fp0,
    -0x1.1475cc9eedfp3
  },
  { // Entry 915
    0x1.749f96097c701869a5f7b1e60216a952p0,
    0x1.1475cc9eedf01p3
  },
  { // Entry 916
    -0x1.749f96097c701869a5f7b1e60216a952p0,
    -0x1.1475cc9eedf01p3
  },
  { // Entry 917
    0x1.77100abbdfe4f88c42b76a1a44ccb487p0,
    0x1.2d97c7f3321d1p3
  },
  { // Entry 918
    -0x1.77100abbdfe4f88c42b76a1a44ccb487p0,
    -0x1.2d97c7f3321d1p3
  },
  { // Entry 919
    0x1.77100abbdfe4f9f90d90533c02b3964ep0,
    0x1.2d97c7f3321d2p3
  },
  { // Entry 920
    -0x1.77100abbdfe4f9f90d90533c02b3964ep0,
    -0x1.2d97c7f3321d2p3
  },
  { // Entry 921
    0x1.77100abbdfe4fb65d8693c5dc07431bdp0,
    0x1.2d97c7f3321d3p3
  },
  { // Entry 922
    -0x1.77100abbdfe4fb65d8693c5dc07431bdp0,
    -0x1.2d97c7f3321d3p3
  },
  { // Entry 923
    0x1.79216b94b662deb07e2d6de7f1804507p0,
    0x1.46b9c347764a2p3
  },
  { // Entry 924
    -0x1.79216b94b662deb07e2d6de7f1804507p0,
    -0x1.46b9c347764a2p3
  },
  { // Entry 925
    0x1.79216b94b662dfe7d5a91b73c06086ebp0,
    0x1.46b9c347764a3p3
  },
  { // Entry 926
    -0x1.79216b94b662dfe7d5a91b73c06086ebp0,
    -0x1.46b9c347764a3p3
  },
  { // Entry 927
    0x1.79216b94b662e11f2d24c8ff8f2294b3p0,
    0x1.46b9c347764a4p3
  },
  { // Entry 928
    -0x1.79216b94b662e11f2d24c8ff8f2294b3p0,
    -0x1.46b9c347764a4p3
  },
  { // Entry 929
    0x1.7ae7d7e5d1f9ee2a0e89a2289062ad74p0,
    0x1.5fdbbe9bba774p3
  },
  { // Entry 930
    -0x1.7ae7d7e5d1f9ee2a0e89a2289062ad74p0,
    -0x1.5fdbbe9bba774p3
  },
  { // Entry 931
    0x1.7ae7d7e5d1f9ef36dc870ed6964fa9dfp0,
    0x1.5fdbbe9bba775p3
  },
  { // Entry 932
    -0x1.7ae7d7e5d1f9ef36dc870ed6964fa9dfp0,
    -0x1.5fdbbe9bba775p3
  },
  { // Entry 933
    0x1.7ae7d7e5d1f9f043aa847b849c24674ap0,
    0x1.5fdbbe9bba776p3
  },
  { // Entry 934
    -0x1.7ae7d7e5d1f9f043aa847b849c24674ap0,
    -0x1.5fdbbe9bba776p3
  },
  { // Entry 935
    0x1.7c722476319a280dab0b4cf4c187f8abp0,
    0x1.78fdb9effea45p3
  },
  { // Entry 936
    -0x1.7c722476319a280dab0b4cf4c187f8abp0,
    -0x1.78fdb9effea45p3
  },
  { // Entry 937
    0x1.7c722476319a28f8131f5d500f0f03e6p0,
    0x1.78fdb9effea46p3
  },
  { // Entry 938
    -0x1.7c722476319a28f8131f5d500f0f03e6p0,
    -0x1.78fdb9effea46p3
  },
  { // Entry 939
    0x1.7c722476319a29e27b336dab5c824dedp0,
    0x1.78fdb9effea47p3
  },
  { // Entry 940
    -0x1.7c722476319a29e27b336dab5c824dedp0,
    -0x1.78fdb9effea47p3
  },
  { // Entry 941
    0x1.7efc711c97aca34b1628231d4f4fabe2p0,
    0x1.ab41b09886fe8p3
  },
  { // Entry 942
    -0x1.7efc711c97aca34b1628231d4f4fabe2p0,
    -0x1.ab41b09886fe8p3
  },
  { // Entry 943
    0x1.7efc711c97aca401df609cab03bab68cp0,
    0x1.ab41b09886fe9p3
  },
  { // Entry 944
    -0x1.7efc711c97aca401df609cab03bab68cp0,
    -0x1.ab41b09886fe9p3
  },
  { // Entry 945
    0x1.7efc711c97aca4b8a8991638b818241cp0,
    0x1.ab41b09886feap3
  },
  { // Entry 946
    -0x1.7efc711c97aca4b8a8991638b818241cp0,
    -0x1.ab41b09886feap3
  },
  { // Entry 947
    0x1.800bb15ffe80dd150b83506ecafcd897p0,
    0x1.c463abeccb2bap3
  },
  { // Entry 948
    -0x1.800bb15ffe80dd150b83506ecafcd897p0,
    -0x1.c463abeccb2bap3
  },
  { // Entry 949
    0x1.800bb15ffe80ddb82f1388a941a8215cp0,
    0x1.c463abeccb2bbp3
  },
  { // Entry 950
    -0x1.800bb15ffe80ddb82f1388a941a8215cp0,
    -0x1.c463abeccb2bbp3
  },
  { // Entry 951
    0x1.800bb15ffe80de5b52a3c0e3b847eeaap0,
    0x1.c463abeccb2bcp3
  },
  { // Entry 952
    -0x1.800bb15ffe80de5b52a3c0e3b847eeaap0,
    -0x1.c463abeccb2bcp3
  },
  { // Entry 953
    0x1.80fe86b132e8f8618de08cf337993ca3p0,
    0x1.dd85a7410f58bp3
  },
  { // Entry 954
    -0x1.80fe86b132e8f8618de08cf337993ca3p0,
    -0x1.dd85a7410f58bp3
  },
  { // Entry 955
    0x1.80fe86b132e8f8f40c19d09e489d38e1p0,
    0x1.dd85a7410f58cp3
  },
  { // Entry 956
    -0x1.80fe86b132e8f8f40c19d09e489d38e1p0,
    -0x1.dd85a7410f58cp3
  },
  { // Entry 957
    0x1.80fe86b132e8f9868a53144959976f3cp0,
    0x1.dd85a7410f58dp3
  },
  { // Entry 958
    -0x1.80fe86b132e8f9868a53144959976f3cp0,
    -0x1.dd85a7410f58dp3
  },
  { // Entry 959
    0x1.81d92def25f25718c6829a063fb81fd7p0,
    0x1.f6a7a2955385dp3
  },
  { // Entry 960
    -0x1.81d92def25f25718c6829a063fb81fd7p0,
    -0x1.f6a7a2955385dp3
  },
  { // Entry 961
    0x1.81d92def25f2579d0b06bd55e5dd10d1p0,
    0x1.f6a7a2955385ep3
  },
  { // Entry 962
    -0x1.81d92def25f2579d0b06bd55e5dd10d1p0,
    -0x1.f6a7a2955385ep3
  },
  { // Entry 963
    0x1.81d92def25f258214f8ae0a58bf99edep0,
    0x1.f6a7a2955385fp3
  },
  { // Entry 964
    -0x1.81d92def25f258214f8ae0a58bf99edep0,
    -0x1.f6a7a2955385fp3
  },
  { // Entry 965
    0x1.829f16bb7d95108c0eb21238a0c53f5ep0,
    0x1.07e4cef4cbd96p4
  },
  { // Entry 966
    -0x1.829f16bb7d95108c0eb21238a0c53f5ep0,
    -0x1.07e4cef4cbd96p4
  },
  { // Entry 967
    0x1.829f16bb7d95117c16ba648f3486d718p0,
    0x1.07e4cef4cbd97p4
  },
  { // Entry 968
    -0x1.829f16bb7d95117c16ba648f3486d718p0,
    -0x1.07e4cef4cbd97p4
  },
  { // Entry 969
    0x1.829f16bb7d95126c1ec2b6e5c82b6edep0,
    0x1.07e4cef4cbd98p4
  },
  { // Entry 970
    -0x1.829f16bb7d95126c1ec2b6e5c82b6edep0,
    -0x1.07e4cef4cbd98p4
  },
  { // Entry 971
    0x1.835311c4fa5d7c37c557b7a5a3338324p0,
    0x1.1475cc9eedeffp4
  },
  { // Entry 972
    -0x1.835311c4fa5d7c37c557b7a5a3338324p0,
    -0x1.1475cc9eedeffp4
  },
  { // Entry 973
    0x1.835311c4fa5d7d128c5fa09cc922483dp0,
    0x1.1475cc9eedfp4
  },
  { // Entry 974
    -0x1.835311c4fa5d7d128c5fa09cc922483dp0,
    -0x1.1475cc9eedfp4
  },
  { // Entry 975
    0x1.835311c4fa5d7ded53678993eef7d037p0,
    0x1.1475cc9eedf01p4
  },
  { // Entry 976
    -0x1.835311c4fa5d7ded53678993eef7d037p0,
    -0x1.1475cc9eedf01p4
  },
  { // Entry 977
    0x1.83f7731825dc9d8ff5737093bb3540dep0,
    0x1.2106ca4910068p4
  },
  { // Entry 978
    -0x1.83f7731825dc9d8ff5737093bb3540dep0,
    -0x1.2106ca4910068p4
  },
  { // Entry 979
    0x1.83f7731825dc9e582ebc020978ee1a95p0,
    0x1.2106ca4910069p4
  },
  { // Entry 980
    -0x1.83f7731825dc9e582ebc020978ee1a95p0,
    -0x1.2106ca4910069p4
  },
  { // Entry 981
    0x1.83f7731825dc9f206804937f3690da9bp0,
    0x1.2106ca491006ap4
  },
  { // Entry 982
    -0x1.83f7731825dc9f206804937f3690da9bp0,
    -0x1.2106ca491006ap4
  },
  { // Entry 983
    0x1.848e2bec799ece48230ea9b4de60cfb7p0,
    0x1.2d97c7f3321d1p4
  },
  { // Entry 984
    -0x1.848e2bec799ece48230ea9b4de60cfb7p0,
    -0x1.2d97c7f3321d1p4
  },
  { // Entry 985
    0x1.848e2bec799ecf0011a08e93bfcbf6bap0,
    0x1.2d97c7f3321d2p4
  },
  { // Entry 986
    -0x1.848e2bec799ecf0011a08e93bfcbf6bap0,
    -0x1.2d97c7f3321d2p4
  },
  { // Entry 987
    0x1.848e2bec799ecfb800327372a123a7b7p0,
    0x1.2d97c7f3321d3p4
  },
  { // Entry 988
    -0x1.848e2bec799ecfb800327372a123a7b7p0,
    -0x1.2d97c7f3321d3p4
  },
  { // Entry 989
    0x1.8518de4b48e76e411ea1cdeeb59cbf77p0,
    0x1.3a28c59d54339p4
  },
  { // Entry 990
    -0x1.8518de4b48e76e411ea1cdeeb59cbf77p0,
    -0x1.3a28c59d54339p4
  },
  { // Entry 991
    0x1.8518de4b48e76eeaab2a58ab739c30cbp0,
    0x1.3a28c59d5433ap4
  },
  { // Entry 992
    -0x1.8518de4b48e76eeaab2a58ab739c30cbp0,
    -0x1.3a28c59d5433ap4
  },
  { // Entry 993
    0x1.8518de4b48e76f9437b2e368318a6869p0,
    0x1.3a28c59d5433bp4
  },
  { // Entry 994
    -0x1.8518de4b48e76f9437b2e368318a6869p0,
    -0x1.3a28c59d5433bp4
  },
  { // Entry 995
    0x1.8598ec35167127ce203d29cce66b685bp0,
    0x1.46b9c347764a2p4
  },
  { // Entry 996
    -0x1.8598ec35167127ce203d29cce66b685bp0,
    -0x1.46b9c347764a2p4
  },
  { // Entry 997
    0x1.8598ec351671286aea010a7cf15304a4p0,
    0x1.46b9c347764a3p4
  },
  { // Entry 998
    -0x1.8598ec351671286aea010a7cf15304a4p0,
    -0x1.46b9c347764a3p4
  },
  { // Entry 999
    0x1.8598ec3516712907b3c4eb2cfc2b4f2dp0,
    0x1.46b9c347764a4p4
  },
  { // Entry 1000
    -0x1.8598ec3516712907b3c4eb2cfc2b4f2dp0,
    -0x1.46b9c347764a4p4
  },
  { // Entry 1001
    0x1.860f836e59cf533a5f5acd977fb3bd1bp0,
    0x1.534ac0f19860bp4
  },
  { // Entry 1002
    -0x1.860f836e59cf533a5f5acd977fb3bd1bp0,
    -0x1.534ac0f19860bp4
  },
  { // Entry 1003
    0x1.860f836e59cf53cbc97c4e327874fe3fp0,
    0x1.534ac0f19860cp4
  },
  { // Entry 1004
    -0x1.860f836e59cf53cbc97c4e327874fe3fp0,
    -0x1.534ac0f19860cp4
  },
  { // Entry 1005
    0x1.860f836e59cf545d339dcecd7128903ap0,
    0x1.534ac0f19860dp4
  },
  { // Entry 1006
    -0x1.860f836e59cf545d339dcecd7128903ap0,
    -0x1.534ac0f19860dp4
  },
  { // Entry 1007
    0x1.867da6c87b57e8adf8990014ae6c012fp0,
    0x1.5fdbbe9bba774p4
  },
  { // Entry 1008
    -0x1.867da6c87b57e8adf8990014ae6c012fp0,
    -0x1.5fdbbe9bba774p4
  },
  { // Entry 1009
    0x1.867da6c87b57e935349724e0cc37b311p0,
    0x1.5fdbbe9bba775p4
  },
  { // Entry 1010
    -0x1.867da6c87b57e935349724e0cc37b311p0,
    -0x1.5fdbbe9bba775p4
  },
  { // Entry 1011
    0x1.867da6c87b57e9bc709549ace9f71ee9p0,
    0x1.5fdbbe9bba776p4
  },
  { // Entry 1012
    -0x1.867da6c87b57e9bc709549ace9f71ee9p0,
    -0x1.5fdbbe9bba776p4
  },
  { // Entry 1013
    0x1.86e435818151b84fe25834c19a7e2e5fp0,
    0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1014
    -0x1.86e435818151b84fe25834c19a7e2e5fp0,
    -0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1015
    0x1.86e435818151b8cdf86e6345f58c69fap0,
    0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1016
    -0x1.86e435818151b8cdf86e6345f58c69fap0,
    -0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1017
    0x1.86e435818151b94c0e8491ca508f98b5p0,
    0x1.6c6cbc45dc8dep4
  },
  { // Entry 1018
    -0x1.86e435818151b94c0e8491ca508f98b5p0,
    -0x1.6c6cbc45dc8dep4
  },
  { // Entry 1019
    0x1.8743f12bf9fc92a7f65de8d6cd3df59dp0,
    0x1.78fdb9effea45p4
  },
  { // Entry 1020
    -0x1.8743f12bf9fc92a7f65de8d6cd3df59dp0,
    -0x1.78fdb9effea45p4
  },
  { // Entry 1021
    0x1.8743f12bf9fc931dcc400e45f1cbfd18p0,
    0x1.78fdb9effea46p4
  },
  { // Entry 1022
    -0x1.8743f12bf9fc931dcc400e45f1cbfd18p0,
    -0x1.78fdb9effea46p4
  },
  { // Entry 1023
    0x1.8743f12bf9fc9393a22233b51650089fp0,
    0x1.78fdb9effea47p4
  },
  { // Entry 1024
    -0x1.8743f12bf9fc9393a22233b51650089fp0,
    -0x1.78fdb9effea47p4
  },
  { // Entry 1025
    0x1.879d82738cdb0715c7e50907e7a87c80p0,
    0x1.858eb79a20baep4
  },
  { // Entry 1026
    -0x1.879d82738cdb0715c7e50907e7a87c80p0,
    -0x1.858eb79a20baep4
  },
  { // Entry 1027
    0x1.879d82738cdb07842634f187eb77dddcp0,
    0x1.858eb79a20bafp4
  },
  { // Entry 1028
    -0x1.879d82738cdb07842634f187eb77dddcp0,
    -0x1.858eb79a20bafp4
  },
  { // Entry 1029
    0x1.879d82738cdb07f28484da07ef3e3230p0,
    0x1.858eb79a20bb0p4
  },
  { // Entry 1030
    -0x1.879d82738cdb07f28484da07ef3e3230p0,
    -0x1.858eb79a20bb0p4
  },
  { // Entry 1031
    0x1.921fb54442d18467898cc51701b829a2p0,
    0x1.fffffffffffffp62
  },
  { // Entry 1032
    -0x1.921fb54442d18467898cc51701b829a2p0,
    -0x1.fffffffffffffp62
  },
  { // Entry 1033
    0x1.921fb54442d18467898cc51701b839a2p0,
    0x1.0p63
  },
  { // Entry 1034
    -0x1.921fb54442d18467898cc51701b839a2p0,
    -0x1.0p63
  },
  { // Entry 1035
    0x1.921fb54442d18467898cc51701b859a2p0,
    0x1.0000000000001p63
  },
  { // Entry 1036
    -0x1.921fb54442d18467898cc51701b859a2p0,
    -0x1.0000000000001p63
  },
  { // Entry 1037
    0x1.921fb52442d18469898befc1ac62e44cp0,
    0x1.fffffffffffffp26
  },
  { // Entry 1038
    -0x1.921fb52442d18469898befc1ac62e44cp0,
    -0x1.fffffffffffffp26
  },
  { // Entry 1039
    0x1.921fb52442d18469898cefc1ac62e44cp0,
    0x1.0p27
  },
  { // Entry 1040
    -0x1.921fb52442d18469898cefc1ac62e44cp0,
    -0x1.0p27
  },
  { // Entry 1041
    0x1.921fb52442d18469898eefc1ac62e44cp0,
    0x1.0000000000001p27
  },
  { // Entry 1042
    -0x1.921fb52442d18469898eefc1ac62e44cp0,
    -0x1.0000000000001p27
  },
  { // Entry 1043
    0x1.921fb44442d1846989da1a6c570d8eccp0,
    0x1.fffffffffffffp23
  },
  { // Entry 1044
    -0x1.921fb44442d1846989da1a6c570d8eccp0,
    -0x1.fffffffffffffp23
  },
  { // Entry 1045
    0x1.921fb44442d1846989e21a6c570d8ec4p0,
    0x1.0p24
  },
  { // Entry 1046
    -0x1.921fb44442d1846989e21a6c570d8ec4p0,
    -0x1.0p24
  },
  { // Entry 1047
    0x1.921fb44442d1846989f21a6c570d8eb3p0,
    0x1.0000000000001p24
  },
  { // Entry 1048
    -0x1.921fb44442d1846989f21a6c570d8eb3p0,
    -0x1.0000000000001p24
  },
  { // Entry 1049
    0x1.5368c951e9cfc7c24c38fb77a1dfa57cp0,
    0x1.fffffffffffffp1
  },
  { // Entry 1050
    -0x1.5368c951e9cfc7c24c38fb77a1dfa57cp0,
    -0x1.fffffffffffffp1
  },
  { // Entry 1051
    0x1.5368c951e9cfc9a42e1add5983cfb3a8p0,
    0x1.0p2
  },
  { // Entry 1052
    -0x1.5368c951e9cfc9a42e1add5983cfb3a8p0,
    -0x1.0p2
  },
  { // Entry 1053
    0x1.5368c951e9cfcd67f1dea11d475ac643p0,
    0x1.0000000000001p2
  },
  { // Entry 1054
    -0x1.5368c951e9cfcd67f1dea11d475ac643p0,
    -0x1.0000000000001p2
  },
  { // Entry 1055
    0x1.1b6e192ebbe443939e676eed7053450cp0,
    0x1.fffffffffffffp0
  },
  { // Entry 1056
    -0x1.1b6e192ebbe443939e676eed7053450cp0,
    -0x1.fffffffffffffp0
  },
  { // Entry 1057
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.0p1
  },
  { // Entry 1058
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.0p1
  },
  { // Entry 1059
    0x1.1b6e192ebbe44d2d3801088709af6e01p0,
    0x1.0000000000001p1
  },
  { // Entry 1060
    -0x1.1b6e192ebbe44d2d3801088709af6e01p0,
    -0x1.0000000000001p1
  },
  { // Entry 1061
    0x1.921fb54442d17c69898cc517019839a2p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 1062
    -0x1.921fb54442d17c69898cc517019839a2p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 1063
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p0
  },
  { // Entry 1064
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p0
  },
  { // Entry 1065
    0x1.921fb54442d19469898cc517013839a2p-1,
    0x1.0000000000001p0
  },
  { // Entry 1066
    -0x1.921fb54442d19469898cc517013839a2p-1,
    -0x1.0000000000001p0
  },
  { // Entry 1067
    0x1.dac670561bb4e9be12fbbf0cab93d258p-2,
    0x1.fffffffffffffp-2
  },
  { // Entry 1068
    -0x1.dac670561bb4e9be12fbbf0cab93d258p-2,
    -0x1.fffffffffffffp-2
  },
  { // Entry 1069
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.0p-1
  },
  { // Entry 1070
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.0p-1
  },
  { // Entry 1071
    0x1.dac670561bb510247962257311bcc81bp-2,
    0x1.0000000000001p-1
  },
  { // Entry 1072
    -0x1.dac670561bb510247962257311bcc81bp-2,
    -0x1.0000000000001p-1
  },
  { // Entry 1073
    0x1.f5b75f92c80dc71bcc802edce02e0a97p-3,
    0x1.fffffffffffffp-3
  },
  { // Entry 1074
    -0x1.f5b75f92c80dc71bcc802edce02e0a97p-3,
    -0x1.fffffffffffffp-3
  },
  { // Entry 1075
    0x1.f5b75f92c80dd62adb8f3debef442fcbp-3,
    0x1.0p-2
  },
  { // Entry 1076
    -0x1.f5b75f92c80dd62adb8f3debef442fcbp-3,
    -0x1.0p-2
  },
  { // Entry 1077
    0x1.f5b75f92c80df448f9ad5c0a0d45f554p-3,
    0x1.0000000000001p-2
  },
  { // Entry 1078
    -0x1.f5b75f92c80df448f9ad5c0a0d45f554p-3,
    -0x1.000
"""


```