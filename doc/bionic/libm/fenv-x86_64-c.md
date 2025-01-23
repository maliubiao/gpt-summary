Response:
Let's break down the thought process for answering this complex question about `fenv-x86_64.c`.

**1. Understanding the Core Task:**

The request asks for a comprehensive analysis of the `fenv-x86_64.c` file, covering its functionality, relationship to Android, implementation details, dynamic linking aspects (though the file itself isn't a linker), common errors, and debugging hints.

**2. Initial File Analysis and Functionality Listing:**

* **Identify the purpose:** The file name and header comments clearly indicate it deals with floating-point environment control. This immediately points to the `<fenv.h>` standard library.
* **List the functions:**  Go through the code and list all the defined functions: `feclearexcept`, `fegetexceptflag`, `feraiseexcept`, `fesetexceptflag`, `fetestexcept`, `fegetround`, `fesetround`, `fegetenv`, `feholdexcept`, `fesetenv`, `feupdateenv`, `feenableexcept`, `fedisableexcept`, `fegetexcept`.
* **Summarize each function's purpose:** Based on the function names and standard `<fenv.h>` documentation (if familiar) or by reading the comments and code snippets, briefly describe what each function does. Focus on manipulating floating-point exceptions, rounding modes, and the floating-point environment itself.

**3. Connecting to Android and Providing Examples:**

* **Android's Reliance on Standard Libraries:**  Recognize that Android's Bionic libc is based on standard C libraries. The floating-point behavior is crucial for many applications.
* **Identify Key Android Use Cases:** Think about where floating-point calculations are important in Android:
    * **Graphics (OpenGL, Vulkan):** Transformations, rendering.
    * **Audio/Video Processing:** Signal processing, codecs.
    * **Scientific/Mathematical Apps (NDK):** Complex calculations.
    * **General Computation:** Even basic arithmetic can be affected by the rounding mode.
* **Create Specific Examples:**  For each function, try to invent a simple, illustrative scenario where it might be used in an Android context. For instance, demonstrate how `fesetround` could be used to control rounding in a financial calculation app. Emphasize the impact of these functions on the accuracy and behavior of applications.

**4. Deep Dive into Libc Function Implementation:**

* **Focus on the Core Logic:**  For each function, explain the steps involved in its implementation. This involves analyzing the inline assembly (`__asm__ __volatile__`).
* **Explain Assembly Instructions:**  Describe the purpose of instructions like `fnstenv`, `fldenv`, `fnstsw`, `fldcw`, `stmxcsr`, `ldmxcsr`, `fnclex`, and `fwait`. Relate them to reading and writing the x87 FPU control word, status word, environment, and the SSE MXCSR register.
* **Highlight Key Operations:** Explain how each function modifies the relevant registers to achieve its intended purpose (e.g., clearing/setting exception flags, changing rounding modes).
* **Structure the Explanation:**  Use a consistent format for each function, outlining the steps involved.

**5. Addressing Dynamic Linker Aspects (Despite File Content):**

* **Acknowledge the Misdirection:**  Recognize that this specific *source* file doesn't contain dynamic linker logic.
* **Explain the Relevant Concepts:**  Since the request asks about it, provide a general overview of how dynamic linking works in Android.
* **SO Layout Sample:** Create a simplified example of an SO file structure, including sections like `.text`, `.data`, `.bss`, `.dynsym`, `.plt`, and `.got`.
* **Symbol Resolution Process:** Describe the steps involved in resolving different types of symbols (global, local, undefined, PLT/GOT). Explain lazy binding.

**6. Logical Reasoning, Assumptions, Inputs, and Outputs:**

* **Choose a Function:** Select a relatively simple function (like `feclearexcept`) for demonstrating logical reasoning.
* **Define Input:** Specify the input to the function (e.g., `FE_DIVBYZERO`).
* **State Assumptions:** Clearly list any assumptions made about the initial state of the system (e.g., certain exceptions might be set initially).
* **Trace the Code:**  Step through the code logically, explaining how the input will affect the internal state.
* **Predict Output:**  Determine the return value and the changes to the floating-point environment.

**7. Common Usage Errors:**

* **Identify Potential Pitfalls:** Think about common mistakes developers might make when using the `<fenv.h>` functions.
* **Provide Concrete Examples:**  Illustrate these errors with short code snippets showing incorrect usage or misunderstandings of how the functions work. For example, not saving and restoring the environment properly or incorrectly masking exceptions.

**8. Tracing Backwards from Android Framework/NDK:**

* **Start from the Top:** Begin with high-level Android components and gradually move down.
* **Identify Key Entry Points:** Think about where floating-point operations are likely to occur in the Android Framework or NDK (e.g., graphics APIs, math libraries).
* **Illustrate the Call Stack:**  Create a simplified example of a call stack demonstrating how a framework API call might eventually lead to the execution of a function in `libm` and specifically within `fenv-x86_64.c`.
* **Emphasize Debugging Tools:** Mention tools like debuggers (GDB, LLDB) and logging that can be used to trace the execution flow.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on the Specific File:**  Realize that while the request focuses on `fenv-x86_64.c`, broader context about floating-point operations and dynamic linking in Android is needed.
* **Balancing Detail and Clarity:** Decide how much low-level detail about assembly instructions to include. Aim for a level that is informative but not overwhelming.
* **Ensuring Correctness:** Double-check the explanations of the assembly instructions and the function logic. Refer to x86 architecture documentation if necessary.
* **Addressing All Parts of the Prompt:** Review the original request to make sure all aspects have been addressed. Don't miss points like the dynamic linker section, even if the file itself isn't a linker.

By following this structured thought process, we can systematically analyze the provided C code and generate a comprehensive and informative answer that addresses all the aspects of the complex request.
好的，让我们来详细分析一下 `bionic/libm/fenv-x86_64.c` 这个文件。

**文件功能概览**

这个文件实现了 `<fenv.h>` 头文件中定义的用于控制浮点环境的函数。浮点环境包括控制字（Control Word），状态字（Status Word），以及异常掩码和舍入模式等。这些函数允许程序查询和修改浮点单元（FPU）的行为，例如：

* **异常处理:**  清除、设置、测试和引发浮点异常（如除零、溢出等）。
* **舍入模式:** 获取和设置浮点运算的舍入方式（如舍入到最近、向上舍入、向下舍入等）。
* **环境管理:** 保存和恢复整个浮点环境。

**与 Android 功能的关系及举例**

Android 系统中的应用程序，特别是那些进行数值计算、图形处理、音视频编解码等操作的程序，都可能涉及到浮点运算。`fenv-x86_64.c` 提供的功能使得开发者可以更精细地控制这些浮点运算的行为，以满足特定的需求或处理特定的边缘情况。

**举例说明:**

1. **图形渲染 (OpenGL/Vulkan):** 在进行 3D 图形变换时，涉及到大量的浮点数运算。开发者可能需要使用 `fesetround()` 设置特定的舍入模式，以确保渲染结果的精度和一致性。例如，在进行裁剪操作时，可能需要使用 `FE_TOWARDZERO` 舍入模式。

2. **音频/视频处理:** 音频和视频编解码过程中，涉及到大量的信号处理算法，这些算法通常需要进行精确的浮点运算。开发者可以使用 `feenableexcept()` 或 `fedisableexcept()` 来控制对某些浮点异常的响应，例如，在已知可能出现除零错误的情况下，可以禁用该异常的抛出，并提供自定义的处理逻辑。

3. **科学计算应用 (NDK):** 通过 Android NDK 开发的科学计算应用，可能会遇到需要精确控制浮点行为的场景。例如，在求解微分方程或进行统计分析时，选择合适的舍入模式和异常处理方式至关重要。

**libc 函数的实现细节**

这个文件中的每个函数都直接操作 x87 FPU 和 SSE 单元的寄存器，以实现对浮点环境的控制。以下逐个解释：

* **`feclearexcept(int excepts)`:**
    * **功能:** 清除指定的浮点异常标志位。
    * **实现:**
        1. 获取当前的 x87 FPU 环境 (`fnstenv %0`).
        2. 清除状态字寄存器中与 `excepts` 对应的位 (`fenv.__x87.__status &= ~excepts`).
        3. 加载修改后的 x87 FPU 环境 (`fldenv %0`).
        4. 对 SSE 单元的 MXCSR 寄存器执行类似操作 (`stmxcsr %0`, `mxcsr &= ~excepts`, `ldmxcsr %0`).
    * **操作的寄存器:** x87 FPU 的控制字、状态字，SSE 单元的 MXCSR 寄存器。

* **`fegetexceptflag(fexcept_t *flagp, int excepts)`:**
    * **功能:** 将指定的浮点异常标志位的状态存储到 `flagp` 指向的内存中。
    * **实现:**
        1. 获取当前的 x87 FPU 状态字 (`fnstsw %0`).
        2. 获取 SSE 单元的 MXCSR 寄存器 (`stmxcsr %0`).
        3. 将状态字和 MXCSR 中与 `excepts` 对应的位进行或运算，存储到 `*flagp` 中。
    * **操作的寄存器:** x87 FPU 的状态字，SSE 单元的 MXCSR 寄存器。

* **`feraiseexcept(int excepts)`:**
    * **功能:** 触发指定的浮点异常。
    * **实现:**
        1. 调用 `fesetexceptflag()` 设置指定的异常标志位。
        2. 执行 `fwait` 指令，等待浮点操作完成，从而触发异常（如果未被屏蔽）。
    * **操作的寄存器:**  间接通过 `fesetexceptflag` 操作 x87 和 SSE 的状态寄存器。

* **`fesetexceptflag(const fexcept_t *flagp, int excepts)`:**
    * **功能:** 将指定的浮点异常标志位设置为 `flagp` 指向的值。
    * **实现:**
        1. 获取当前的 x87 FPU 环境 (`fnstenv %0`).
        2. 根据 `*flagp` 设置状态字寄存器中与 `excepts` 对应的位 (`fenv.__x87.__status &= ~excepts`, `fenv.__x87.__status |= *flagp & excepts`).
        3. 加载修改后的 x87 FPU 环境 (`fldenv %0`).
        4. 对 SSE 单元的 MXCSR 寄存器执行类似操作。
    * **操作的寄存器:** x87 FPU 的控制字、状态字，SSE 单元的 MXCSR 寄存器。

* **`fetestexcept(int excepts)`:**
    * **功能:** 测试指定的浮点异常标志位是否被设置。
    * **实现:**
        1. 获取当前的 x87 FPU 状态字 (`fnstsw %0`).
        2. 获取 SSE 单元的 MXCSR 寄存器 (`stmxcsr %0`).
        3. 返回状态字和 MXCSR 中与 `excepts` 对应的位的或运算结果。
    * **操作的寄存器:** x87 FPU 的状态字，SSE 单元的MXCSR 寄存器。

* **`fegetround(void)`:**
    * **功能:** 获取当前的浮点舍入模式。
    * **实现:**
        1. 获取 x87 FPU 的控制字 (`fnstcw %0`).
        2. 提取控制字中与舍入模式相关的位 (`control & X87_ROUND_MASK`).
    * **操作的寄存器:** x87 FPU 的控制字。

* **`fesetround(int round)`:**
    * **功能:** 设置浮点舍入模式。
    * **实现:**
        1. 检查 `round` 是否为有效的舍入模式。
        2. 获取当前的 x87 FPU 控制字 (`fnstcw %0`).
        3. 修改控制字中与舍入模式相关的位 (`control &= ~X87_ROUND_MASK`, `control |= round`).
        4. 加载修改后的 x87 FPU 控制字 (`fldcw %0`).
        5. 对 SSE 单元的 MXCSR 寄存器执行类似操作。
    * **操作的寄存器:** x87 FPU 的控制字，SSE 单元的 MXCSR 寄存器。

* **`fegetenv(fenv_t *envp)`:**
    * **功能:** 将当前的浮点环境保存到 `envp` 指向的内存中。
    * **实现:**
        1. 保存当前的 x87 FPU 环境 (`fnstenv %0`).
        2. 保存 SSE 单元的 MXCSR 寄存器 (`stmxcsr %0`).
        3. 重新加载 x87 控制字，因为 `fnstenv` 可能会清除挂起的异常。
    * **操作的寄存器:** x87 FPU 的控制字、状态字、标签字，SSE 单元的 MXCSR 寄存器。

* **`feholdexcept(fenv_t *envp)`:**
    * **功能:** 保存当前的浮点环境，清除异常标志，并进入非停止模式（屏蔽所有异常）。
    * **实现:**
        1. 保存当前的 x87 FPU 环境 (`fnstenv %0`).
        2. 清除 x87 FPU 的异常标志 (`fnclex`).
        3. 保存 SSE 单元的 MXCSR 寄存器 (`stmxcsr %0`).
        4. 清除并屏蔽 MXCSR 寄存器中的异常标志。
        5. 加载修改后的 MXCSR 寄存器 (`ldmxcsr %0`).
    * **操作的寄存器:** x87 FPU 的控制字、状态字、标签字，SSE 单元的 MXCSR 寄存器。

* **`fesetenv(const fenv_t *envp)`:**
    * **功能:** 将浮点环境设置为 `envp` 指向的值。
    * **实现:**
        1. 加载 `envp` 中的 x87 FPU 环境 (`fldenv %0`).
        2. 加载 `envp` 中的 MXCSR 寄存器 (`ldmxcsr %0`).
    * **操作的寄存器:** x87 FPU 的控制字、状态字、标签字，SSE 单元的 MXCSR 寄存器。

* **`feupdateenv(const fenv_t *envp)`:**
    * **功能:** 保存当前的浮点异常，设置新的浮点环境，然后重新引发保存的异常。
    * **实现:**
        1. 保存当前的 x87 FPU 状态字 (`fnstsw %0`).
        2. 保存 SSE 单元的 MXCSR 寄存器 (`stmxcsr %0`).
        3. 调用 `fesetenv()` 设置新的浮点环境。
        4. 调用 `feraiseexcept()` 重新引发之前保存的异常。
    * **操作的寄存器:** x87 FPU 的控制字、状态字、标签字，SSE 单元的 MXCSR 寄存器。

* **`feenableexcept(int mask)`:**
    * **功能:** 启用指定的浮点异常。
    * **实现:**
        1. 获取当前的 x87 FPU 控制字和 SSE 单元的 MXCSR 寄存器。
        2. 清除控制字和 MXCSR 寄存器中与 `mask` 对应的异常屏蔽位。
        3. 加载修改后的控制字和 MXCSR 寄存器。
    * **操作的寄存器:** x87 FPU 的控制字，SSE 单元的 MXCSR 寄存器。

* **`fedisableexcept(int mask)`:**
    * **功能:** 禁用指定的浮点异常。
    * **实现:**
        1. 获取当前的 x87 FPU 控制字和 SSE 单元的 MXCSR 寄存器。
        2. 设置控制字和 MXCSR 寄存器中与 `mask` 对应的异常屏蔽位。
        3. 加载修改后的控制字和 MXCSR 寄存器。
    * **操作的寄存器:** x87 FPU 的控制字，SSE 单元的 MXCSR 寄存器。

* **`fegetexcept(void)`:**
    * **功能:** 获取当前已启用的浮点异常。
    * **实现:**
        1. 获取当前的 x87 FPU 控制字。
        2. 返回控制字中未被屏蔽的异常位。
    * **操作的寄存器:** x87 FPU 的控制字。

**Dynamic Linker 的功能**

虽然 `fenv-x86_64.c` 本身不是动态链接器的代码，但它所处的 `libm.so` 库是由动态链接器加载和管理的。

**SO 布局样本:**

一个典型的 Android SO (Shared Object) 文件布局如下：

```
ELF Header
Program Headers (描述内存段，如 .text, .data)
Section Headers (描述各个 section 的信息)

.text         可执行代码段
.rodata       只读数据段 (例如，字符串常量)
.data         已初始化的可读写数据段
.bss          未初始化的可读写数据段
.dynsym       动态符号表 (包含导出的和导入的符号)
.dynstr       动态字符串表 (存储符号名称)
.rel.plt      PLT 重定位表
.rel.dyn      其他段的重定位表
.plt          Procedure Linkage Table (过程链接表，用于延迟绑定)
.got.plt      Global Offset Table (全局偏移表，用于存储符号地址)
... 其他 section ...
```

**每种符号的处理过程:**

1. **全局符号 (Global Symbols):** 在 `.dynsym` 中声明，可以被其他 SO 文件引用。
   * **导出符号 (Exported Symbols):** `libm.so` 中的函数（如 `sin`, `cos`, `fesetround` 等）是导出的全局符号。动态链接器会将这些符号添加到全局符号表中，使得其他 SO 可以找到并使用它们。
   * **导入符号 (Imported Symbols):**  `libm.so` 可能依赖于其他 SO 的函数（例如，libc 的函数）。这些依赖的符号会在 `libm.so` 的 `.dynsym` 中标记为需要导入。

2. **本地符号 (Local Symbols):**  通常用于 SO 内部，不会被其他 SO 直接引用。这些符号在 `.symtab` 中，但动态链接过程中主要关注 `.dynsym`。

3. **未定义符号 (Undefined Symbols):**  在链接时，如果一个 SO 引用了一个没有在自身或其他已加载 SO 中定义的符号，则该符号为未定义。动态链接器需要在加载时找到这些符号的定义，否则会报错。

**符号解析过程:**

* **加载时:** 当动态链接器加载一个 SO 文件时，它会解析该 SO 的 `.dynsym` 表。
* **符号查找:** 当一个 SO 需要调用另一个 SO 的函数时，动态链接器会在全局符号表中查找该函数的地址。
* **重定位:**  由于共享库的加载地址可能在每次运行时都不同，动态链接器需要修改代码和数据段中引用的全局符号的地址，这个过程称为重定位。
* **延迟绑定 (Lazy Binding):**  为了提高启动速度，动态链接器通常采用延迟绑定策略。对于通过 PLT 调用的外部函数，最初 `GOT.plt` 表项指向 PLT 中的一段代码。第一次调用该函数时，PLT 代码会调用动态链接器来解析符号并更新 `GOT.plt` 表项，使其直接指向目标函数。后续调用将直接通过 `GOT.plt` 跳转到目标函数。

**处理过程示例 (以 `fesetround` 为例):**

1. **`libm.so` 的 `.dynsym`:**  `fesetround` 在 `libm.so` 的 `.dynsym` 表中被声明为一个导出的全局符号。
2. **应用程序调用:** 当应用程序调用 `fesetround` 时，编译器会生成一个通过 PLT 的调用指令。
3. **PLT 入口:**  第一次调用 `fesetround` 时，会跳转到 `libm.so` 的 `.plt` 段中 `fesetround` 对应的入口。
4. **动态链接器介入:**  PLT 入口的代码会调用动态链接器。
5. **符号解析:** 动态链接器查找全局符号表，找到 `fesetround` 在 `libm.so` 中的实际地址。
6. **GOT 更新:** 动态链接器将 `fesetround` 的实际地址写入 `libm.so` 的 `.got.plt` 段中对应的表项。
7. **函数调用:** 后续对 `fesetround` 的调用将直接通过 `GOT.plt` 跳转到其在 `libm.so` 中的实现。

**逻辑推理、假设输入与输出**

假设我们调用 `fesetround(FE_DOWNWARD)`，并且当前的舍入模式是 `FE_TONEAREST`。

* **假设输入:** `round = FE_DOWNWARD`
* **当前状态:** x87 控制字的舍入模式位为 `FE_TONEAREST` 的值，MXCSR 寄存器的舍入控制位也为 `FE_TONEAREST` 的值。
* **函数执行逻辑:**
    1. `fesetround` 检查 `FE_DOWNWARD` 是否有效（是）。
    2. 读取当前的 x87 控制字。
    3. 将控制字的舍入模式位清零，然后设置为 `FE_DOWNWARD` 对应的值。
    4. 加载修改后的控制字。
    5. 读取当前的 MXCSR 寄存器。
    6. 将 MXCSR 的舍入控制位清零，然后设置为 `FE_DOWNWARD` 对应的值。
    7. 加载修改后的 MXCSR 寄存器。
* **预期输出:** 函数返回 0 (表示成功)，x87 FPU 和 SSE 单元的舍入模式都被设置为向下舍入 (`FE_DOWNWARD`)。

**用户或编程常见的使用错误**

1. **不理解浮点环境的影响:**  开发者可能不清楚修改浮点环境（如舍入模式或异常掩码）可能对数值计算结果产生的微妙影响，导致程序出现非预期的行为。

2. **错误地设置异常掩码:**  禁用某些浮点异常可能导致程序在遇到这些异常时继续运行，但结果可能是不正确的，且没有明显的错误提示。例如，禁用除零异常可能导致程序得到 `NaN` 或无穷大的结果，而开发者没有意识到。

3. **未正确保存和恢复浮点环境:**  在修改浮点环境后，如果没有使用 `fegetenv()` 和 `fesetenv()` 或 `feholdexcept()` 和 `feupdateenv()` 来保存和恢复环境，可能会影响其他依赖默认浮点环境的代码。

4. **多线程环境下的竞争条件:**  浮点环境是线程本地的，但在某些情况下（例如，通过全局变量传递浮点结果），不正确的环境设置可能会在多线程环境中导致竞争条件和难以调试的问题。

**Android Framework 或 NDK 如何到达这里（调试线索）**

1. **Framework API 调用:**  Android Framework 提供了许多与图形、媒体、传感器等相关的 API。这些 API 的实现可能最终依赖于底层的 C/C++ 代码进行数值计算。例如，`android.graphics.Canvas` 的绘制操作、`android.media.MediaCodec` 的编解码操作等。

2. **NDK 调用:**  开发者通过 NDK 使用 C/C++ 开发应用程序。如果 NDK 代码中使用了 `<fenv.h>` 中的函数，或者调用了依赖于浮点运算的 `libm` 中的数学函数（如 `sin()`, `cos()`, `sqrt()` 等），那么最终会调用到 `bionic/libm/fenv-x86_64.c` 中的函数。

3. **`libm` 数学函数:**  许多 `libm` 中的数学函数在内部可能会依赖于当前的浮点环境设置。例如，`round()` 函数的实现会受到当前舍入模式的影响。

**调试线索:**

* **断点调试:**  在 Android Studio 中，可以设置断点在 `bionic/libm/fenv-x86_64.c` 的函数入口，观察何时以及如何调用这些函数。
* **日志记录:**  在 NDK 代码中，可以使用 `__android_log_print` 记录浮点环境的相关信息（例如，通过读取控制字和 MXCSR 寄存器）。
* **系统调用追踪:**  使用 `strace` 或 `systrace` 等工具可以追踪应用程序的系统调用，观察与浮点环境相关的操作。
* **反汇编分析:**  对于更底层的调试，可以使用反汇编工具查看相关代码的汇编指令，理解浮点环境的修改过程。

**示例：Android Framework 如何间接调用 `fesetround`**

1. 应用程序调用 Android Framework 的图形 API，例如 `Canvas.drawCircle()`.
2. `Canvas.drawCircle()` 的实现会调用 Skia 图形库。
3. Skia 库在进行图形渲染时，可能需要进行浮点数计算，例如计算圆的边界。
4. 在某些特定的图形操作或算法中，Skia 可能会为了精度或性能的考虑，临时修改浮点舍入模式。这可能通过调用 `fesetround()` 来实现。
5. 最终，对 `fesetround()` 的调用会落到 `bionic/libm/fenv-x86_64.c` 中的实现。

总而言之，`bionic/libm/fenv-x86_64.c` 是 Android 系统中控制底层浮点运算行为的关键组件。理解其功能和实现对于开发高性能、高精度的 Android 应用程序至关重要。

### 提示词
```
这是目录为bionic/libm/fenv-x86_64.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*  $OpenBSD: fenv.c,v 1.3 2012/12/05 23:20:02 deraadt Exp $  */
/*  $NetBSD: fenv.c,v 1.1 2010/07/31 21:47:53 joerg Exp $ */

/*-
 * Copyright (c) 2004-2005 David Schultz <das (at) FreeBSD.ORG>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <fenv.h>

/*
 * The i387 defaults to Intel extended precision mode and round to nearest,
 * with all exceptions masked.
 */
#define	__INITIAL_NPXCW__	0x037f
#define __INITIAL_MXCSR__ 	0x1f80
#define __INITIAL_MXCSR_MASK__	0xffbf

#define SSE_MASK_SHIFT 7

/*
 * The following symbol is simply the bitwise-inclusive OR of all floating-point
 * rounding direction constants defined above.
 */
#define X87_ROUND_MASK  (FE_TONEAREST | FE_DOWNWARD | FE_UPWARD | FE_TOWARDZERO)
#define SSE_ROUND_SHIFT 3

/*
 * The following constant represents the default floating-point environment
 * (that is, the one installed at program startup) and has type pointer to
 * const-qualified fenv_t.
 *
 * It can be used as an argument to the functions within the <fenv.h> header
 * that manage the floating-point environment, namely fesetenv() and
 * feupdateenv().
 *
 * x87 fpu registers are 16bit wide. The upper bits, 31-16, are marked as
 * RESERVED.
 */
const fenv_t __fe_dfl_env = {
  {
    0xffff0000 | __INITIAL_NPXCW__, /* Control word register */
    0xffff0000,                     /* Status word register */
    0xffffffff,                     /* Tag word register */
    {
      0x00000000,
      0x00000000,
      0x00000000,
      0xffff0000
    }
  },
  __INITIAL_MXCSR__                 /* MXCSR register */
};


/*
 * The feclearexcept() function clears the supported floating-point exceptions
 * represented by `excepts'.
 */
int
feclearexcept(int excepts)
{
  fenv_t fenv;
  unsigned int mxcsr;

  excepts &= FE_ALL_EXCEPT;

  /* Store the current x87 floating-point environment */
  __asm__ __volatile__ ("fnstenv %0" : "=m" (fenv));

  /* Clear the requested floating-point exceptions */
  fenv.__x87.__status &= ~excepts;

  /* Load the x87 floating-point environent */
  __asm__ __volatile__ ("fldenv %0" : : "m" (fenv));

  /* Same for SSE environment */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));
  mxcsr &= ~excepts;
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (0);
}

/*
 * The fegetexceptflag() function stores an implementation-defined
 * representation of the states of the floating-point status flags indicated by
 * the argument excepts in the object pointed to by the argument flagp.
 */
int
fegetexceptflag(fexcept_t *flagp, int excepts)
{
  unsigned short status;
  unsigned int mxcsr;

  excepts &= FE_ALL_EXCEPT;

  /* Store the current x87 status register */
  __asm__ __volatile__ ("fnstsw %0" : "=am" (status));

  /* Store the MXCSR register */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));

  /* Store the results in flagp */
  *flagp = (status | mxcsr) & excepts;

  return (0);
}

/*
 * The feraiseexcept() function raises the supported floating-point exceptions
 * represented by the argument `excepts'.
 *
 * The standard explicitly allows us to execute an instruction that has the
 * exception as a side effect, but we choose to manipulate the status register
 * directly.
 *
 * The validation of input is being deferred to fesetexceptflag().
 */
int
feraiseexcept(int excepts)
{
  excepts &= FE_ALL_EXCEPT;

  fesetexceptflag((fexcept_t *)&excepts, excepts);
  __asm__ __volatile__ ("fwait");

  return (0);
}

/*
 * This function sets the floating-point status flags indicated by the argument
 * `excepts' to the states stored in the object pointed to by `flagp'. It does
 * NOT raise any floating-point exceptions, but only sets the state of the flags.
 */
int
fesetexceptflag(const fexcept_t *flagp, int excepts)
{
  fenv_t fenv;
  unsigned int mxcsr;

  excepts &= FE_ALL_EXCEPT;

  /* Store the current x87 floating-point environment */
  __asm__ __volatile__ ("fnstenv %0" : "=m" (fenv));

  /* Set the requested status flags */
  fenv.__x87.__status &= ~excepts;
  fenv.__x87.__status |= *flagp & excepts;

  /* Load the x87 floating-point environent */
  __asm__ __volatile__ ("fldenv %0" : : "m" (fenv));

  /* Same for SSE environment */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));
  mxcsr &= ~excepts;
  mxcsr |= *flagp & excepts;
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (0);
}

/*
 * The fetestexcept() function determines which of a specified subset of the
 * floating-point exception flags are currently set. The `excepts' argument
 * specifies the floating-point status flags to be queried.
 */
int
fetestexcept(int excepts)
{
  unsigned short status;
  unsigned int mxcsr;

  excepts &= FE_ALL_EXCEPT;

  /* Store the current x87 status register */
  __asm__ __volatile__ ("fnstsw %0" : "=am" (status));

  /* Store the MXCSR register state */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));

  return ((status | mxcsr) & excepts);
}

/*
 * The fegetround() function gets the current rounding direction.
 */
int
fegetround(void)
{
  unsigned short control;

  /*
   * We assume that the x87 and the SSE unit agree on the
   * rounding mode.  Reading the control word on the x87 turns
   * out to be about 5 times faster than reading it on the SSE
   * unit on an Opteron 244.
   */
  __asm__ __volatile__ ("fnstcw %0" : "=m" (control));

  return (control & X87_ROUND_MASK);
}

/*
 * The fesetround() function establishes the rounding direction represented by
 * its argument `round'. If the argument is not equal to the value of a rounding
 * direction macro, the rounding direction is not changed.
 */
int
fesetround(int round)
{
  unsigned short control;
  unsigned int mxcsr;

  /* Check whether requested rounding direction is supported */
  if (round & ~X87_ROUND_MASK)
    return (-1);

  /* Store the current x87 control word register */
  __asm__ __volatile__ ("fnstcw %0" : "=m" (control));

  /* Set the rounding direction */
  control &= ~X87_ROUND_MASK;
  control |= round;

  /* Load the x87 control word register */
  __asm__ __volatile__ ("fldcw %0" : : "m" (control));

  /* Same for the SSE environment */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));
  mxcsr &= ~(X87_ROUND_MASK << SSE_ROUND_SHIFT);
  mxcsr |= round << SSE_ROUND_SHIFT;
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (0);
}

/*
 * The fegetenv() function attempts to store the current floating-point
 * environment in the object pointed to by envp.
 */
int
fegetenv(fenv_t *envp)
{
  /* Store the current x87 floating-point environment */
  __asm__ __volatile__ ("fnstenv %0" : "=m" (*envp));

  /* Store the MXCSR register state */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (envp->__mxcsr));

  /*
   * When an FNSTENV instruction is executed, all pending exceptions are
   * essentially lost (either the x87 FPU status register is cleared or
   * all exceptions are masked).
   *
   * 8.6 X87 FPU EXCEPTION SYNCHRONIZATION -
   * Intel(R) 64 and IA-32 Architectures Softare Developer's Manual - Vol1
   */
  __asm__ __volatile__ ("fldcw %0" : : "m" (envp->__x87.__control));

  return (0);
}

/*
 * The feholdexcept() function saves the current floating-point environment
 * in the object pointed to by envp, clears the floating-point status flags, and
 * then installs a non-stop (continue on floating-point exceptions) mode, if
 * available, for all floating-point exceptions.
 */
int
feholdexcept(fenv_t *envp)
{
  unsigned int mxcsr;

  /* Store the current x87 floating-point environment */
  __asm__ __volatile__ ("fnstenv %0" : "=m" (*envp));

  /* Clear all exception flags in FPU */
  __asm__ __volatile__ ("fnclex");

  /* Store the MXCSR register state */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (envp->__mxcsr));

  /* Clear exception flags in MXCSR */
  mxcsr = envp->__mxcsr;
  mxcsr &= ~FE_ALL_EXCEPT;

  /* Mask all exceptions */
  mxcsr |= FE_ALL_EXCEPT << SSE_MASK_SHIFT;

  /* Store the MXCSR register */
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (0);
}

/*
 * The fesetenv() function attempts to establish the floating-point environment
 * represented by the object pointed to by envp. The argument `envp' points
 * to an object set by a call to fegetenv() or feholdexcept(), or equal a
 * floating-point environment macro. The fesetenv() function does not raise
 * floating-point exceptions, but only installs the state of the floating-point
 * status flags represented through its argument.
 */
int
fesetenv(const fenv_t *envp)
{
  /* Load the x87 floating-point environent */
  __asm__ __volatile__ ("fldenv %0" : : "m" (*envp));

  /* Store the MXCSR register */
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (envp->__mxcsr));

  return (0);
}

/*
 * The feupdateenv() function saves the currently raised floating-point
 * exceptions in its automatic storage, installs the floating-point environment
 * represented by the object pointed to by `envp', and then raises the saved
 * floating-point exceptions. The argument `envp' shall point to an object set
 * by a call to feholdexcept() or fegetenv(), or equal a floating-point
 * environment macro.
 */
int
feupdateenv(const fenv_t *envp)
{
  unsigned short status;
  unsigned int mxcsr;

  /* Store the x87 status register */
  __asm__ __volatile__ ("fnstsw %0" : "=am" (status));

  /* Store the MXCSR register */
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));

  /* Install new floating-point environment */
  fesetenv(envp);

  /* Raise any previously accumulated exceptions */
  feraiseexcept(status | mxcsr);

  return (0);
}

/*
 * The following functions are extentions to the standard
 */
int
feenableexcept(int mask)
{
  unsigned int mxcsr, omask;
  unsigned short control;

  mask &= FE_ALL_EXCEPT;

  __asm__ __volatile__ ("fnstcw %0" : "=m" (control));
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));

  omask = ~(control | (mxcsr >> SSE_MASK_SHIFT)) & FE_ALL_EXCEPT;
  control &= ~mask;
  __asm__ __volatile__ ("fldcw %0" : : "m" (control));

  mxcsr &= ~(mask << SSE_MASK_SHIFT);
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (omask);
}

int
fedisableexcept(int mask)
{
  unsigned int mxcsr, omask;
  unsigned short control;

  mask &= FE_ALL_EXCEPT;

  __asm__ __volatile__ ("fnstcw %0" : "=m" (control));
  __asm__ __volatile__ ("stmxcsr %0" : "=m" (mxcsr));

  omask = ~(control | (mxcsr >> SSE_MASK_SHIFT)) & FE_ALL_EXCEPT;
  control |= mask;
  __asm__ __volatile__ ("fldcw %0" : : "m" (control));

  mxcsr |= mask << SSE_MASK_SHIFT;
  __asm__ __volatile__ ("ldmxcsr %0" : : "m" (mxcsr));

  return (omask);
}

int
fegetexcept(void)
{
  unsigned short control;

  /*
   * We assume that the masks for the x87 and the SSE unit are
   * the same.
   */
  __asm__ __volatile__ ("fnstcw %0" : "=m" (control));

  return (~control & FE_ALL_EXCEPT);
}
```