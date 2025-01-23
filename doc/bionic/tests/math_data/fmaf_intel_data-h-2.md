Response:
The user wants a summary of the functionality of the provided C code snippet. This code snippet appears to be a part of a larger dataset used for testing the `fmaf` (fused multiply-add, single-precision float) function in Android's Bionic library.

Here's a breakdown of the thought process:

1. **Identify the Core Function:** The filename `fmaf_intel_data.handroid` and the context of `bionic/tests/math_data` strongly suggest this data is for testing the `fmaf` function. The data entries themselves, consisting of four floating-point numbers, reinforce this idea (typically `fmaf(a, b, c)` computes `a * b + c`).

2. **Understand the Data Structure:** The code presents a series of C struct literals. Each struct likely represents a test case for the `fmaf` function. The four float values within each struct probably correspond to the inputs (`a`, `b`, `c`) and the expected output of the `fmaf` function.

3. **Infer the Testing Purpose:**  The presence of special values like `HUGE_VALF`, `-HUGE_VALF`, and various representations of small numbers (e.g., `0x1.p-126`) indicates that these tests are designed to cover edge cases and boundary conditions for the `fmaf` function. This is crucial for robust software development. The different powers of 2 in the small number representations also suggest testing the function's precision across a range of exponents.

4. **Relate to Android's Functionality:**  Since this is part of Bionic, the data directly contributes to the reliability and correctness of floating-point math operations on Android devices. Applications using floating-point numbers will rely on the `fmaf` implementation being accurate.

5. **Address Specific Instructions (even if information is limited in the current snippet):**

    * **List Functionality:**  The primary function is providing test data for `fmaf`.
    * **Relationship to Android:**  Ensuring accurate floating-point calculations in Android.
    * **libc Function Implementation:**  The snippet *is* data, not the implementation. Therefore, a detailed explanation of `fmaf`'s implementation isn't directly present. However, I can briefly explain what `fmaf` does conceptually.
    * **Dynamic Linker:**  The snippet doesn't directly involve the dynamic linker. It's data used *by* the math library, which is linked. I need to acknowledge this lack of direct involvement while keeping the broader context of Bionic in mind.
    * **Logical Reasoning (Input/Output):** The provided data *are* the assumed inputs and expected outputs for the `fmaf` function. I can give an example of how one of these entries would be used.
    * **Common Usage Errors:**  Because this is test data, common *user* errors are less relevant here. However, *implementation* errors in `fmaf` would be revealed by this data. I can rephrase this slightly to fit the context.
    * **Android Framework/NDK Path:**  I need to explain the chain of events from an Android app using math functions down to this data being used in testing.
    * **Frida Hook:** I can provide a basic example of how Frida could be used to hook the `fmaf` function and observe its behavior.
    * **Part 3 Summary:**  Focus on the role of this data in validating the `fmaf` function's correctness within the broader Bionic library context.

6. **Structure the Response:** Organize the information clearly using headings and bullet points to address each part of the user's request.

7. **Refine Language:** Use clear and concise Chinese to explain the concepts. Pay attention to technical terms and ensure they are accurately translated and understood.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's request, even with the limited scope of the provided code snippet.
好的，根据您提供的代码片段，这是 `bionic/tests/math_data/fmaf_intel_data.handroid` 文件的一部分内容，主要包含了一系列用于测试 `fmaf` (floating-point multiply-add) 函数的测试数据。

**功能归纳（第3部分）：**

这部分代码的主要功能是提供了一批用于测试 `fmaf` 函数在特定输入下的行为是否正确的测试用例。  这些测试用例覆盖了 `fmaf` 函数可能遇到的一些边界条件和特殊值，例如：

* **极大值 (HUGE_VALF, -HUGE_VALF):**  测试处理无穷大值的能力。
* **接近零的值 (例如 0x1.p-126, 0x1.fffffcp-127, 0x1.p-149):** 测试处理极小值和精度问题的能力。
* **正零和负零 (0.0f, -0.0f):** 测试对零的正确处理。
* **正常范围内的浮点数:**  验证基本计算的正确性。
* **不同的符号组合:**  覆盖各种输入符号的情况。

**更详细的分析：**

* **功能:**
    * **提供 `fmaf` 函数的测试数据:**  这是此文件的核心功能。它包含了一系列预定义的输入值（三个浮点数）以及期望的输出值（一个浮点数）。
    * **覆盖不同的输入场景:**  测试数据精心设计，旨在覆盖 `fmaf` 函数可能遇到的各种输入组合，包括特殊值和边界情况。

* **与 Android 功能的关系及举例说明:**
    * **`fmaf` 是一个标准的 C 数学库函数:** 它执行融合乘加运算，即计算 `a * b + c`，但中间乘积不进行舍入，从而提高精度和性能。
    * **Android 的 libc (Bionic) 实现了 `fmaf`:**  这个文件中的数据用于验证 Bionic 提供的 `fmaf` 实现是否符合预期。
    * **应用场景:**  任何在 Android 上进行浮点数密集型计算的应用都会间接使用到 `fmaf` (如果编译器或库使用了它)。例如：
        * **图形渲染:** 计算顶点变换、光照等。
        * **物理引擎:** 计算物体运动、碰撞检测等。
        * **机器学习:**  矩阵运算、模型推理等。
    * **举例:** 如果一个 Android 游戏使用 `fmaf` 来加速其物理引擎的计算，那么这个文件中的测试数据可以帮助确保游戏在各种情况下物理计算的正确性。如果 `fmaf` 的实现有错误，可能会导致游戏中物体运动异常。

* **libc 函数的功能实现 (以 `fmaf` 为例):**
    `fmaf` 函数的实现通常依赖于硬件支持。如果 CPU 提供了 FMA 指令，那么 `fmaf` 会直接映射到该硬件指令，实现非常高效。如果硬件不支持，则需要在软件层面模拟 FMA 的行为，这通常涉及到一些底层的浮点数操作，以确保中间乘积不被舍入。软件模拟会比硬件实现慢一些。

* **Dynamic Linker 功能 (本代码片段不直接涉及):**
    这个代码片段是静态数据，不涉及动态链接。动态链接器负责在程序运行时加载和链接共享库 (`.so` 文件)。
    * **so 布局样本:**  例如，一个简单的 native library (`libexample.so`) 的布局可能如下：
        ```
        libexample.so:
            .text   # 代码段
            .data   # 初始化数据段
            .bss    # 未初始化数据段
            .rodata # 只读数据段
            .dynsym # 动态符号表
            .dynstr # 动态字符串表
            .rel.dyn # 动态重定位表
            .plt    # 过程链接表
            .got    # 全局偏移表
        ```
    * **链接的处理过程:**
        1. **加载:** 动态链接器将 `.so` 文件加载到内存中的特定地址。
        2. **符号解析:** 链接器根据 `.dynsym` 和 `.dynstr` 解析需要的符号 (函数、变量)。
        3. **重定位:**  链接器根据 `.rel.dyn` 中的信息，修改代码和数据段中的地址，使其指向正确的内存位置。例如，如果 `libexample.so` 中调用了 `libc.so` 中的 `fmaf`，链接器会修改 `libexample.so` 中对 `fmaf` 的调用地址。
        4. **GOT/PLT:**  过程链接表 (`.plt`) 和全局偏移表 (`.got`) 用于实现延迟绑定，即在函数第一次被调用时才解析其地址。

* **逻辑推理 (假设输入与输出):**
    取一个 Entry 作为例子：
    ```c
    { // Entry 722
      -HUGE_VALF,
      0x1.fffffep127,
      -HUGE_VALF,
      -0x1.p-126
    },
    ```
    * **假设输入:**  `a = -HUGE_VALF`, `b = 0x1.fffffep127` (接近 float 的最大正数), `c = -HUGE_VALF`
    * **预期输出:** `-0x1.p-126` (一个很小的负数)
    * **逻辑推理:**  由于 `a` 和 `c` 都是 `-HUGE_VALF`，而 `b` 是一个很大的正数，`a * b` 的结果会是负无穷。然后加上 `c` (也是负无穷)，结果仍然是负无穷。  但是，这里预期输出是一个很小的负数，这可能是在测试 `fmaf` 如何处理某些特殊情况，例如，某些优化或特定硬件行为可能导致结果不是严格的负无穷。  这表明测试用例的设计考虑了各种可能的实现细节和边缘情况。

* **用户或编程常见的使用错误:**
    * **精度问题:**  浮点数运算本身存在精度问题，直接比较两个浮点数是否相等可能会出错。应该使用一个小的 epsilon 值进行比较。
    * **溢出/下溢:**  进行乘法运算时，可能导致结果超出浮点数的表示范围（溢出）或过于接近零（下溢）。`fmaf` 可以通过不进行中间舍入来缓解某些溢出/下溢问题。
    * **未初始化变量:**  将未初始化的浮点数传递给 `fmaf` 会导致不可预测的结果。
    * **误用 `fmaf`:**  在不需要高精度或特定优化的情况下，过度使用 `fmaf` 可能不会带来明显的性能提升，反而可能使代码更复杂。

* **Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例调试这些步骤:**
    1. **Android Framework/NDK:**
        * **Java 代码 (Framework):** Android Framework 中的某些组件（例如，涉及图形或高性能计算的部分）可能会调用 Native 代码。
        * **NDK (C/C++):**  开发者使用 NDK 编写的 Native 代码可以直接调用 Bionic 提供的 `fmaf` 函数。
        * **编译:**  Native 代码通过 NDK 的工具链编译成 `.so` 文件。
        * **链接:**  在程序加载时，动态链接器会将应用程序的 `.so` 文件与 Bionic 提供的 `libc.so` 链接起来，使得 Native 代码可以调用 `fmaf`。
        * **执行:**  当 Native 代码执行到调用 `fmaf` 的地方时，就会执行 Bionic 中 `fmaf` 的实现。  在 Bionic 的开发和测试过程中，就会使用到 `fmaf_intel_data.handroid` 中的测试数据来验证 `fmaf` 的正确性。

    2. **Frida Hook 示例:**
        假设你想 hook 应用程序中调用的 `fmaf` 函数，观察其输入和输出。

        ```python
        import frida, sys

        package_name = "your.application.package"  # 替换为你的应用包名

        def on_message(message, data):
            if message['type'] == 'send':
                print("[*] {0}".format(message['payload']))
            else:
                print(message)

        try:
            session = frida.get_usb_device().attach(package_name)
        except Exception as e:
            print(f"Error attaching to process: {e}")
            sys.exit(1)

        script_code = """
        Interceptor.attach(Module.findExportByName("libc.so", "fmaf"), {
            onEnter: function(args) {
                console.log("[+] fmaf called");
                console.log("    Arg 0 (a): " + args[0]);
                console.log("    Arg 1 (b): " + args[1]);
                console.log("    Arg 2 (c): " + args[2]);
            },
            onLeave: function(retval) {
                console.log("    Return Value: " + retval);
            }
        });
        """

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        sys.stdin.read()
        ```

        **解释:**
        * **`frida.get_usb_device().attach(package_name)`:** 连接到正在运行的目标 Android 应用程序。
        * **`Module.findExportByName("libc.so", "fmaf")`:** 找到 `libc.so` 中导出的 `fmaf` 函数的地址。
        * **`Interceptor.attach(...)`:**  拦截对 `fmaf` 函数的调用。
        * **`onEnter`:** 在 `fmaf` 函数被调用之前执行，打印输入参数。
        * **`onLeave`:** 在 `fmaf` 函数执行完毕之后执行，打印返回值。

总而言之，这个代码片段是 Android Bionic 数学库测试套件的一部分，专门用于验证 `fmaf` 函数的正确性，确保 Android 设备上的浮点数计算的准确性和可靠性。

### 提示词
```
这是目录为bionic/tests/math_data/fmaf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
},
  { // Entry 722
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 723
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 724
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 725
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 726
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 727
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 728
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 729
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 730
    -HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 731
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 732
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 733
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 734
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 735
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 736
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 737
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 738
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 739
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 740
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 741
    HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 742
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 743
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 744
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 745
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 746
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 747
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 748
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 749
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 750
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 751
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 752
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 753
    HUGE_VALF,
    0x1.fffffep127,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 754
    -HUGE_VALF,
    0x1.fffffep127,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 755
    0x1.fffffe00000000000000000000000007p127,
    0x1.fffffep127,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 756
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 757
    0x1.fffffe00000000000000000000000002p1,
    0x1.fffffep127,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 758
    0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.fffffep127,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 759
    0x1.fffffe00000000000000000000000001p1,
    0x1.fffffep127,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 760
    0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 761
    0x1.fffffep1,
    0x1.fffffep127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 762
    0x1.fffffdffffffffffffffffffffffffffp1,
    0x1.fffffep127,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 763
    0x1.fffffep1,
    0x1.fffffep127,
    0x1.p-126,
    0.0f
  },
  { // Entry 764
    0x1.fffffep1,
    0x1.fffffep127,
    0x1.p-126,
    -0.0f
  },
  { // Entry 765
    HUGE_VALF,
    0x1.fffffep127,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 766
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 767
    0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffep127,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 768
    -0x1.fffffe00000000000000000000000007p127,
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 769
    -0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.fffffep127,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 770
    -0x1.fffffe00000000000000000000000002p1,
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 771
    -0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.fffffep127,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 772
    -0x1.fffffe00000000000000000000000001p1,
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 773
    -0x1.fffffdffffffffffffffffffffffffffp1,
    0x1.fffffep127,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 774
    -0x1.fffffep1,
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 775
    -0x1.fffffep1,
    0x1.fffffep127,
    -0x1.p-126,
    0.0f
  },
  { // Entry 776
    -0x1.fffffep1,
    0x1.fffffep127,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 777
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 778
    -HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 779
    0x1.fffffe00000000000000000000000007p127,
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 780
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 781
    0x1.fffffa00000400000000000000000002p1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 782
    0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 783
    0x1.fffffa00000400000000000000000001p1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 784
    0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 785
    0x1.fffffa000004p1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 786
    0x1.fffffa000003ffffffffffffffffffffp1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 787
    0x1.fffffa000004p1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 788
    0x1.fffffa000004p1,
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 789
    HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 790
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 791
    0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 792
    -0x1.fffffe00000000000000000000000007p127,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 793
    -0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 794
    -0x1.fffffa00000400000000000000000002p1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 795
    -0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 796
    -0x1.fffffa00000400000000000000000001p1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 797
    -0x1.fffffa000003ffffffffffffffffffffp1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 798
    -0x1.fffffa000004p1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 799
    -0x1.fffffa000004p1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 800
    -0x1.fffffa000004p1,
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 801
    HUGE_VALF,
    0x1.fffffep127,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 802
    -HUGE_VALF,
    0x1.fffffep127,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 803
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 804
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 805
    0x1.fffffe00000000000000000001p-22,
    0x1.fffffep127,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 806
    0x1.fffffdffffffffffffffffffffp-22,
    0x1.fffffep127,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 807
    0x1.fffffe00000000000000000000fffffep-22,
    0x1.fffffep127,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 808
    0x1.fffffdffffffffffffffffffff000002p-22,
    0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 809
    0x1.fffffe00000000000000000000000002p-22,
    0x1.fffffep127,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 810
    0x1.fffffdfffffffffffffffffffffffffep-22,
    0x1.fffffep127,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 811
    0x1.fffffep-22,
    0x1.fffffep127,
    0x1.p-149,
    0.0f
  },
  { // Entry 812
    0x1.fffffep-22,
    0x1.fffffep127,
    0x1.p-149,
    -0.0f
  },
  { // Entry 813
    HUGE_VALF,
    0x1.fffffep127,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 814
    -HUGE_VALF,
    0x1.fffffep127,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 815
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 816
    -0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 817
    -0x1.fffffdffffffffffffffffffffp-22,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 818
    -0x1.fffffe00000000000000000001p-22,
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 819
    -0x1.fffffdffffffffffffffffffff000002p-22,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 820
    -0x1.fffffe00000000000000000000fffffep-22,
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 821
    -0x1.fffffdfffffffffffffffffffffffffep-22,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 822
    -0x1.fffffe00000000000000000000000002p-22,
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 823
    -0x1.fffffep-22,
    0x1.fffffep127,
    -0x1.p-149,
    0.0f
  },
  { // Entry 824
    -0x1.fffffep-22,
    0x1.fffffep127,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 825
    HUGE_VALF,
    0x1.fffffep127,
    0.0f,
    HUGE_VALF
  },
  { // Entry 826
    -HUGE_VALF,
    0x1.fffffep127,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 827
    0x1.fffffep127,
    0x1.fffffep127,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 828
    -0x1.fffffep127,
    0x1.fffffep127,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 829
    0x1.p-126,
    0x1.fffffep127,
    0.0f,
    0x1.p-126
  },
  { // Entry 830
    -0x1.p-126,
    0x1.fffffep127,
    0.0f,
    -0x1.p-126
  },
  { // Entry 831
    0x1.fffffcp-127,
    0x1.fffffep127,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 832
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 833
    0x1.p-149,
    0x1.fffffep127,
    0.0f,
    0x1.p-149
  },
  { // Entry 834
    -0x1.p-149,
    0x1.fffffep127,
    0.0f,
    -0x1.p-149
  },
  { // Entry 835
    0.0,
    0x1.fffffep127,
    0.0f,
    0.0f
  },
  { // Entry 836
    0.0,
    0x1.fffffep127,
    0.0f,
    -0.0f
  },
  { // Entry 837
    HUGE_VALF,
    0x1.fffffep127,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 838
    -HUGE_VALF,
    0x1.fffffep127,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 839
    0x1.fffffep127,
    0x1.fffffep127,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 840
    -0x1.fffffep127,
    0x1.fffffep127,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 841
    0x1.p-126,
    0x1.fffffep127,
    -0.0f,
    0x1.p-126
  },
  { // Entry 842
    -0x1.p-126,
    0x1.fffffep127,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 843
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 844
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 845
    0x1.p-149,
    0x1.fffffep127,
    -0.0f,
    0x1.p-149
  },
  { // Entry 846
    -0x1.p-149,
    0x1.fffffep127,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 847
    0.0,
    0x1.fffffep127,
    -0.0f,
    0.0f
  },
  { // Entry 848
    -0.0,
    0x1.fffffep127,
    -0.0f,
    -0.0f
  },
  { // Entry 849
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 850
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 851
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 852
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 853
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 854
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 855
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 856
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 857
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 858
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    0.0f
  },
  { // Entry 859
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 860
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 861
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 862
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 863
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 864
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 865
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 866
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 867
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 868
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 869
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 870
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 871
    HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 872
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 873
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 874
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 875
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 876
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 877
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 878
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 879
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 880
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 881
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 882
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 883
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 884
    -HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 885
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 886
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 887
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 888
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 889
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 890
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 891
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 892
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 893
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 894
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 895
    HUGE_VALF,
    -0x1.fffffep127,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 896
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 897
    0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffep127,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 898
    -0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 899
    -0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.fffffep127,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 900
    -0x1.fffffe00000000000000000000000002p1,
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 901
    -0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.fffffep127,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 902
    -0x1.fffffe00000000000000000000000001p1,
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 903
    -0x1.fffffdffffffffffffffffffffffffffp1,
    -0x1.fffffep127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 904
    -0x1.fffffep1,
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 905
    -0x1.fffffep1,
    -0x1.fffffep127,
    0x1.p-126,
    0.0f
  },
  { // Entry 906
    -0x1.fffffep1,
    -0x1.fffffep127,
    0x1.p-126,
    -0.0f
  },
  { // Entry 907
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 908
    -HUGE_VALF,
    -0x1.fffffep127,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 909
    0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 910
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffep127,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 911
    0x1.fffffe00000000000000000000000002p1,
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 912
    0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 913
    0x1.fffffe00000000000000000000000001p1,
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 914
    0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.fffffep127,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 915
    0x1.fffffep1,
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 916
    0x1.fffffdffffffffffffffffffffffffffp1,
    -0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 917
    0x1.fffffep1,
    -0x1.fffffep127,
    -0x1.p-126,
    0.0f
  },
  { // Entry 918
    0x1.fffffep1,
    -0x1.fffffep127,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 919
    HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 920
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 921
    0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 922
    -0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 923
    -0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 924
    -0x1.fffffa00000400000000000000000002p1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 925
    -0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 926
    -0x1.fffffa00000400000000000000000001p1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 927
    -0x1.fffffa000003ffffffffffffffffffffp1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 928
    -0x1.fffffa000004p1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 929
    -0x1.fffffa000004p1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 930
    -0x1.fffffa000004p1,
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 931
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 932
    -HUGE_VALF,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 933
    0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 934
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 935
    0x1.fffffa00000400000000000000000002p1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 936
    0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 937
    0x1.fffffa00000400000000000000000001p1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 938
    0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 939
    0x1.fffffa000004p1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 940
    0x1.fffffa000003ffffffffffffffffffffp1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 941
    0x1.fffffa000004p1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 942
    0x1.fffffa000004p1,
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 943
    HUGE_VALF,
    -0x1.fffffep127,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 944
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 945
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffep127,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 946
    -0x1.fffffep127,
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 947
    -0x1.fffffdffffffffffffffffffffp-22,
    -0x1.fffffep127,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 948
    -0x1.fffffe00000000000000000001p-22,
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 949
    -0x1.fffffdffffffffffffffffffff000002p-22,
    -0x1.fffffep127,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 950
    -0x1.fffffe00000000000000000000fffffep-22,
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 951
    -0x1.fffffdfffffffffffffffffffffffffep-22,
    -0x1.fffffep127,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 952
    -0x1.fffffe00000000000000000000000002p-22,
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 953
    -0x1.fffffep-22,
    -0x1.fffffep127,
    0x1.p-149,
    0.0f
  },
  { // Entry 954
    -0x1.fffffep-22,
    -0x1.fffffep127,
    0x1.p-149,
    -0.0f
  },
  { // Entry 955
    HUGE_VALF,
    -0x1.fffffep127,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 956
    -HUGE_VALF,
    -0x1.fffffep127,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 957
    0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 958
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 959
    0x1.fffffe00000000000000000001p-22,
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 960
    0x1.fffffdffffffffffffffffffffp-22,
    -0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 961
    0x1.fffffe00000000000000000000fffffep-22,
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 962
    0x1.fffffdffffffffffffffffffff000002p-22,
    -0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 963
    0x1.fffffe00000000000000000000000002p-22,
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 964
    0x1.fffffdfffffffffffffffffffffffffep-22,
    -0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 965
    0x1.fffffep-22,
    -0x1.fffffep127,
    -0x1.p-149,
    0.0f
  },
  { // Entry 966
    0x1.fffffep-22,
    -0x1.fffffep127,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 967
    HUGE_VALF,
    -0x1.fffffep127,
    0.0f,
    HUGE_VALF
  },
  { // Entry 968
    -HUGE_VALF,
    -0x1.fffffep127,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 969
    0x1.fffffep127,
    -0x1.fffffep127,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 970
    -0x1.fffffep127,
    -0x1.fffffep127,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 971
    0x1.p-126,
    -0x1.fffffep127,
    0.0f,
    0x1.p-126
  },
  { // Entry 972
    -0x1.p-126,
    -0x1.fffffep127,
    0.0f,
    -0x1.p-126
  },
  { // Entry 973
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 974
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 975
    0x1.p-149,
    -0x1.fffffep127,
    0.0f,
    0x1.p-149
  },
  { // Entry 976
    -0x1.p-149,
    -0x1.fffffep127,
    0.0f,
    -0x1.p-149
  },
  { // Entry 977
    0.0,
    -0x1.fffffep127,
    0.0f,
    0.0f
  },
  { // Entry 978
    -0.0,
    -0x1.fffffep127,
    0.0f,
    -0.0f
  },
  { // Entry 979
    HUGE_VALF,
    -0x1.fffffep127,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 980
    -HUGE_VALF,
    -0x1.fffffep127,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 981
    0x1.fffffep127,
    -0x1.fffffep127,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 982
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 983
    0x1.p-126,
    -0x1.fffffep127,
    -0.0f,
    0x1.p-126
  },
  { // Entry 984
    -0x1.p-126,
    -0x1.fffffep127,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 985
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 986
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 987
    0x1.p-149,
    -0x1.fffffep127,
    -0.0f,
    0x1.p-149
  },
  { // Entry 988
    -0x1.p-149,
    -0x1.fffffep127,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 989
    0.0,
    -0x1.fffffep127,
    -0.0f,
    0.0f
  },
  { // Entry 990
    0.0,
    -0x1.fffffep127,
    -0.0f,
    -0.0f
  },
  { // Entry 991
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 992
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 993
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 994
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 995
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 996
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 997
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 998
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 999
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1000
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1001
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1002
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1003
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1004
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1005
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1006
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1007
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1008
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1009
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1010
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1011
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1012
    -HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1013
    HUGE_VALF,
    0x1.p-126,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1014
    -HUGE_VALF,
    0x1.p-126,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1015
    0x1.fffffe00000000000000000000000007p127,
    0x1.p-126,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1016
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.p-126,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1017
    0x1.fffffe00000000000000000000000002p1,
    0x1.p-126,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1018
    0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.p-126,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1019
    0x1.fffffe00000000000000000000000001p1,
    0x1.p-126,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1020
    0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.p-126,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1021
    0x1.fffffep1,
    0x1.p-126,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1022
    0x1.fffffdffffffffffffffffffffffffffp1,
    0x1.p-126,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1023
    0x1.fffffep1,
    0x1.p-126,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1024
    0x1.fffffep1,
    0x1.p-126,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1025
    HUGE_VALF,
    0x1.p-126,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1026
    -HUGE_VALF,
    0x1.p-126,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1027
    0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.p-126,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1028
    -0x1.fffffe00000000000000000000000007p127,
    0x1.p-126,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1029
    -0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.p-126,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1030
    -0x1.fffffe00000000000000000000000002p1,
    0x1.p-126,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1031
    -0x1.fffffdfffffffffffffffffffffffffep1,
    0x1.p-126,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1032
    -0x1.fffffe00000000000000000000000001p1,
    0x1.p-126,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1033
    -0x1.fffffdffffffffffffffffffffffffffp1,
    0x1.p-126,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1034
    -0x1.fffffep1,
    0x1.p-126,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1035
    -0x1.fffffep1,
    0x1.p-126,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1036
    -0x1.fffffep1,
    0x1.p-126,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1037
    HUGE_VALF,
    0x1.p-126,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1038
    -HUGE_VALF,
    0x1.p-126,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1039
    0x1.fffffep127,
    0x1.p-126,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1040
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1041
    0x1.00000000000000000000000000000004p-126,
    0x1.p-126,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1042
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.p-126,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1043
    0x1.fffffc00000000000000000000000008p-127,
    0x1.p-126,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1044
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.p-126,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1045
    0x1.00000000000000000000000002p-149,
    0x1.p-126,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1046
    -0.0f,
    0x1.p-126,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1047
    0.0f,
    0x1.p-126,
    0x1.p-126,
    0.0f
  },
  { // Entry 1048
    0.0f,
    0x1.p-126,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1049
    HUGE_VALF,
    0x1.p-126,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1050
    -HUGE_VALF,
    0x1.p-126,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1051
```