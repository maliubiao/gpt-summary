Response:
Let's break down the thought process to generate the comprehensive analysis of `fenv-arm.c`.

**1. Understanding the Request:**

The initial request asks for a detailed analysis of the `fenv-arm.c` file within the Android bionic library. Key aspects to cover include:

* **Functionality:** What does the code do?
* **Android Relevance:** How does it relate to the broader Android system?
* **Libc Function Implementation:**  A deep dive into each function's implementation.
* **Dynamic Linker (SO) Aspects:**  Structure of shared objects and symbol resolution (even though this file isn't directly involved in dynamic linking, the request specifically asks, so we need to address it).
* **Logical Reasoning:**  Hypothetical inputs and outputs.
* **Common Errors:**  Pitfalls for users.
* **Debugging:** How does one reach this code during debugging?

**2. Initial Code Scan and Core Function Identification:**

The first step is to quickly read through the code. I immediately notice the `#include <fenv.h>` and the function names like `fegetenv`, `fesetenv`, `feclearexcept`, etc. This strongly suggests the file deals with **floating-point environment control**, as per the `<fenv.h>` standard. The `FPSCR_RMODE_SHIFT` constant further confirms this, hinting at manipulation of the Floating-Point Status and Control Register (FPSCR) on ARM.

**3. Deconstructing Each Function:**

Now, I go through each function individually:

* **`fegetenv`:**  The `vmrs` assembly instruction clearly indicates reading the FPSCR. The function stores this value in the provided `fenv_t` pointer. The return value of 0 suggests success.
* **`fesetenv`:** The `vmsr` assembly instruction indicates writing to the FPSCR. The function takes an `fenv_t` pointer as input.
* **`feclearexcept`:**  This involves reading the FPSCR, performing a bitwise AND NOT to clear specific exception flags, and then writing back the modified FPSCR.
* **`fegetexceptflag`:** Reads the FPSCR and performs a bitwise AND to extract specific exception flags.
* **`fesetexceptflag`:** Reads the FPSCR, clears the target exception flags, then sets them based on the input `__flagp`.
* **`feraiseexcept`:**  This is interesting. It *sets* the exception flags, but doesn't immediately trigger a signal or trap. This suggests it prepares the FPSCR for a future floating-point operation that might then raise the exception.
* **`fetestexcept`:** Reads the FPSCR and performs a bitwise AND to check if specific exception flags are set.
* **`fegetround`:** Reads the FPSCR and extracts the rounding mode bits using bit shifting and masking.
* **`fesetround`:** Reads the FPSCR, clears the existing rounding mode bits, and then sets the new rounding mode bits.
* **`feholdexcept`:** Reads the current FPSCR, stores it, and then clears *all* exception flags. This is for temporarily preventing exceptions.
* **`feupdateenv`:**  Sets the floating-point environment based on the input, and *then* raises any exceptions that were pending *before* the environment change.
* **`feenableexcept` & `fedisableexcept` & `fegetexcept`:** These functions return fixed values (-1, 0, 0 respectively) and have the `__unused` attribute. This strongly suggests they are **placeholders** or **not implemented** for this specific ARM architecture in bionic. This is a crucial observation.

**4. Connecting to Android:**

* **System-Level Functionality:**  Floating-point exception handling is a fundamental aspect of numerical computation, affecting various parts of Android.
* **NDK:**  Native code using floating-point operations will directly interact with these functions.
* **Framework:** While the framework might not directly call these functions, they are essential for the underlying C library that the framework depends on. For example, Java's `Math` class operations are often implemented using native code that relies on these functions.

**5. Dynamic Linker Considerations (Even if the File Isn't Directly Involved):**

The request specifically asked about the dynamic linker. Even though `fenv-arm.c` is a source file within `libm.so`, it's important to address this. I would describe:

* **SO Layout:** Sections like `.text`, `.data`, `.bss`, `.rodata`, `.dynsym`, `.dynstr`, `.plt`, `.got`.
* **Symbol Resolution:** Explanation of how the dynamic linker resolves symbols (global, local, undefined, etc.) using the symbol tables and relocation entries. A simple example demonstrating this would be beneficial.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

For each function, consider a simple input and the expected outcome. For example:

* `fegetenv`:  Input: pointer to an `fenv_t`. Output: The `fenv_t` pointed to will contain the current FPSCR value.
* `fesetround`: Input: `FE_TONEAREST`. Output: The rounding mode in the FPSCR will be set to round to the nearest.

**7. Common Errors:**

Think about how a programmer might misuse these functions:

* Incorrect bitwise operations when manipulating exception flags.
* Forgetting to restore the floating-point environment after using `feholdexcept`.
* Assuming `feenableexcept` and `fedisableexcept` work as expected, when they don't in this implementation.

**8. Debugging Path:**

Trace how execution reaches `fenv-arm.c`:

1. **Java Code:** `Math.sqrt()`, `StrictMath.sin()`, etc.
2. **Framework Native Code:**  JNI calls to native methods in the framework.
3. **NDK:** Direct usage of math functions from the NDK.
4. **`libm.so`:** The math library where `fenv-arm.c` resides.
5. **Specific `fenv-*` functions:** Called within other `libm` functions or directly by user code.

**9. Refinement and Structuring:**

Finally, organize the information logically with clear headings and examples. Ensure that the language is precise and easy to understand. Use code snippets to illustrate the implementation details. Highlight the important limitations and architecture-specific behavior (like the unimplemented exception enabling/disabling).

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to systematically analyze the code, understand its purpose within the broader Android ecosystem, and anticipate potential user questions and debugging scenarios.
好的，让我们来详细分析一下 `bionic/libm/fenv-arm.c` 这个文件。

**功能概述**

`fenv-arm.c` 文件实现了 ISO C 标准中定义的浮点环境控制相关的函数，这些函数允许程序查询和修改浮点运算的状态，例如舍入模式和异常处理。由于该文件位于 `bionic/libm` 目录下，并且文件名中包含 "arm"，可以推断出它是 Android Bionic C 库中针对 ARM 架构的浮点环境控制实现。

**与 Android 功能的关系和举例说明**

浮点环境控制对于依赖浮点运算的应用程序至关重要，而 Android 系统上的应用，尤其是那些进行科学计算、图形渲染、音频处理等任务的应用，会大量使用浮点运算。

* **保证数值计算的一致性:** 通过设置相同的舍入模式，可以确保在不同的设备上或者在同一设备的不同运行阶段，相同的浮点计算会得到相同的结果。这对于需要精确数值结果的应用非常重要。
* **处理浮点异常:**  浮点运算可能会产生各种异常，例如除零错误、溢出、无效操作等。通过 `fenv` 相关的函数，程序可以查询这些异常的状态，并在必要时采取相应的处理措施，例如记录日志、抛出异常或者采取替代计算方案。
* **性能优化（间接影响）:** 虽然 `fenv` 函数本身可能不是性能关键路径，但正确地管理浮点环境可以避免一些潜在的性能问题，例如某些异常可能会导致处理器陷入慢速处理路径。

**举例说明:**

假设一个 Android 应用使用 OpenGL ES 进行 3D 渲染。在渲染过程中，需要进行大量的矩阵运算和向量运算，这些运算都涉及到浮点数。

* **舍入模式:**  开发者可能需要设置特定的舍入模式，例如 `FE_TOWARDZERO` (向零舍入)，以确保在裁剪坐标时，超出屏幕范围的顶点被正确地丢弃。
* **浮点异常:** 如果在计算过程中发生了除零错误（例如，法向量长度为零），`feraiseexcept(FE_DIVBYZERO)` 可以被用来模拟产生这个异常，方便测试和调试错误处理逻辑。或者，`fetestexcept(FE_DIVBYZERO)` 可以用来检查是否发生了除零错误。

**libc 函数的实现细节**

让我们逐个分析 `fenv-arm.c` 中实现的 libc 函数：

1. **`const fenv_t __fe_dfl_env = 0;`**
   - **功能:** 定义了默认的浮点环境。在 ARM 架构上，浮点环境主要由 FPSCR (Floating-Point Status and Control Register) 寄存器的值决定。这里将默认环境设置为 0，意味着使用默认的 FPSCR 设置。
   - **实现:** 这是一个全局常量，直接初始化为 0。

2. **`int fegetenv(fenv_t* __envp)`**
   - **功能:** 获取当前的浮点环境并将结果存储在 `__envp` 指向的 `fenv_t` 结构中。
   - **实现:**
     ```assembly
     __asm__ __volatile__("vmrs %0,fpscr" : "=r"(_fpscr));
     ```
     这段内联汇编使用 `vmrs` 指令将 FPSCR 寄存器的值读取到 C 变量 `_fpscr` 中。
     - `%0`: 表示第一个输出操作数，对应 `_fpscr`。
     - `=r`: 表示 `_fpscr` 是一个通用寄存器类型的输出操作数，并且值会被修改。
     - `fpscr`:  ARM 处理器的浮点状态和控制寄存器。
     然后，将 `_fpscr` 的值赋值给 `*__envp`。

3. **`int fesetenv(const fenv_t* __envp)`**
   - **功能:** 设置当前的浮点环境为 `__envp` 指向的值。
   - **实现:**
     ```assembly
     __asm__ __volatile__("vmsr fpscr,%0" : : "ri"(_fpscr));
     ```
     这段内联汇编使用 `vmsr` 指令将 C 变量 `_fpscr` 的值写入到 FPSCR 寄存器中。
     - `%0`: 表示第一个输入操作数，对应 `_fpscr`。
     - `ri`: 表示 `_fpscr` 是一个立即数或寄存器类型的输入操作数。

4. **`int feclearexcept(int __excepts)`**
   - **功能:** 清除由 `__excepts` 指定的浮点异常标志。
   - **实现:**
     - 首先，调用 `fegetenv` 获取当前的 FPSCR 值。
     - 然后，使用按位与非 (`&= ~`) 操作清除 FPSCR 中与 `__excepts` 对应的位。
     - 最后，调用 `fesetenv` 将修改后的 FPSCR 值写回。

5. **`int fegetexceptflag(fexcept_t* __flagp, int __excepts)`**
   - **功能:** 获取由 `__excepts` 指定的浮点异常标志的当前状态。
   - **实现:**
     - 调用 `fegetenv` 获取当前的 FPSCR 值。
     - 使用按位与 (`&`) 操作提取 FPSCR 中与 `__excepts` 对应的位，并将结果存储在 `*__flagp` 中。

6. **`int fesetexceptflag(const fexcept_t* __flagp, int __excepts)`**
   - **功能:** 设置由 `__excepts` 指定的浮点异常标志为 `__flagp` 中对应的值。
   - **实现:**
     - 调用 `fegetenv` 获取当前的 FPSCR 值。
     - 使用按位与非 (`&= ~`) 操作清除 FPSCR 中与 `__excepts` 对应的位。
     - 使用按位与 (`&`) 操作提取 `__flagp` 中与 `__excepts` 对应的位。
     - 使用按位或 (`|=`) 操作将提取的位设置到 FPSCR 中。
     - 最后，调用 `fesetenv` 将修改后的 FPSCR 值写回。

7. **`int feraiseexcept(int __excepts)`**
   - **功能:** 触发由 `__excepts` 指定的浮点异常。
   - **实现:**
     - 创建一个 `fexcept_t` 类型的变量 `__ex` 并赋值为 `__excepts`。
     - 调用 `fesetexceptflag` 来设置 FPSCR 中与 `__excepts` 对应的异常标志。注意，这里仅仅是设置了标志位，是否会真正产生硬件异常取决于系统的配置和具体的浮点操作。

8. **`int fetestexcept(int __excepts)`**
   - **功能:** 测试由 `__excepts` 指定的浮点异常标志是否被设置。
   - **实现:**
     - 调用 `fegetenv` 获取当前的 FPSCR 值。
     - 使用按位与 (`&`) 操作检查 FPSCR 中与 `__excepts` 对应的位是否非零。

9. **`int fegetround(void)`**
   - **功能:** 获取当前的浮点舍入模式。
   - **实现:**
     - 调用 `fegetenv` 获取当前的 FPSCR 值。
     - 使用位移 (`>> FPSCR_RMODE_SHIFT`) 和掩码 (`& 0x3`) 操作提取 FPSCR 中表示舍入模式的位。`FPSCR_RMODE_SHIFT` 常量定义了舍入模式位在 FPSCR 中的偏移量。

10. **`int fesetround(int __round)`**
    - **功能:** 设置当前的浮点舍入模式为 `__round` 指定的值。
    - **实现:**
      - 调用 `fegetenv` 获取当前的 FPSCR 值。
      - 使用位移和掩码操作清除 FPSCR 中现有的舍入模式位。
      - 使用位移操作将 `__round` 的值移动到正确的位位置。
      - 使用按位或 (`|=`) 操作将新的舍入模式位设置到 FPSCR 中。
      - 最后，调用 `fesetenv` 将修改后的 FPSCR 值写回。

11. **`int feholdexcept(fenv_t* __envp)`**
    - **功能:** 保存当前的浮点环境，并清除所有的浮点异常标志。
    - **实现:**
      - 调用 `fegetenv` 获取当前的 FPSCR 值并存储到 `*__envp` 中。
      - 将获取的 FPSCR 值与 `~FE_ALL_EXCEPT` 进行按位与操作，`FE_ALL_EXCEPT` 是一个包含所有异常标志位的宏。这将清除所有的异常标志。
      - 调用 `fesetenv` 将修改后的 FPSCR 值写回，从而清除所有异常。

12. **`int feupdateenv(const fenv_t* __envp)`**
    - **功能:** 设置浮点环境为 `__envp` 指向的值，并触发之前被挂起的浮点异常。
    - **实现:**
      - 调用 `fegetenv` 获取当前的 FPSCR 值（用于保存当前的异常状态）。
      - 调用 `fesetenv` 将浮点环境设置为 `__envp` 指向的值。
      - 调用 `feraiseexcept` 触发之前保存的异常（通过与 `FE_ALL_EXCEPT` 进行按位与操作来提取）。这个函数通常用于在执行一段代码之前保存浮点环境，执行代码，然后在恢复环境的同时触发这段代码执行期间产生的异常。

13. **`int feenableexcept(int __mask __unused)`**
    - **功能:** 启用指定的浮点异常。
    - **实现:**  返回 `-1`。这表明在当前的 ARM 实现中，直接启用或禁用特定浮点异常的功能可能不受支持或者有其他机制来控制。通常，异常的使能和禁用是由硬件或操作系统级别的配置来管理的。 `__unused` 属性表示 `__mask` 参数在此实现中没有被使用。

14. **`int fedisableexcept(int __mask __unused)`**
    - **功能:** 禁用指定的浮点异常。
    - **实现:** 返回 `0`。 与 `feenableexcept` 类似，这表明直接禁用异常的功能可能不受支持。返回 `0` 可能意味着“操作成功”（即使实际上什么都没做）。

15. **`int fegetexcept(void)`**
    - **功能:** 获取当前启用的浮点异常。
    - **实现:** 返回 `0`。这与 `feenableexcept` 和 `fedisableexcept` 的行为一致，暗示了异常的使能和禁用可能不是通过这些函数直接控制的。

**Dynamic Linker 的功能和 SO 布局**

虽然 `fenv-arm.c` 本身是 C 代码，不直接涉及动态链接的过程，但它编译后会成为 `libm.so` 的一部分。让我们简要说明一下动态链接器的工作原理和 SO 布局：

**SO (Shared Object) 布局样本:**

```
libm.so:
    .interp         # 指向动态链接器的路径
    .note.android.ident
    .dynsym         # 动态符号表
    .dynstr         # 动态字符串表
    .hash           # 符号哈希表
    .gnu.version    # 版本信息
    .gnu.version_r  # 版本依赖信息
    .rel.plt        # PLT 重定位信息
    .rel.dyn        # 数据段重定位信息
    .plt            # 过程链接表 (Procedure Linkage Table)
    .text           # 代码段 (包含 fegetenv, fesetenv 等函数的机器码)
    .rodata         # 只读数据段 (例如 __fe_dfl_env)
    .data.rel.ro    # 可重定位的只读数据
    .data           # 已初始化的全局变量
    .bss            # 未初始化的全局变量
    .comment
    .ARM.attributes
```

**符号处理过程:**

1. **符号类型:**
   - **定义符号 (Defined Symbols):**  SO 中定义的函数和全局变量，例如 `fegetenv`，`__fe_dfl_env`。
   - **未定义符号 (Undefined Symbols):** SO 中引用但在其他 SO 中定义的符号。`fenv-arm.c` 内部可能不会有未定义符号，但如果它调用了其他库的函数，则会有。
   - **全局符号 (Global Symbols):** 可以被其他 SO 链接的符号，例如 `fegetenv`。
   - **本地符号 (Local Symbols):**  仅在当前 SO 内部可见的符号（通常带有 `static` 关键字）。

2. **动态链接过程:**
   - **加载 SO:** 当一个程序启动或通过 `dlopen` 加载 SO 时，动态链接器会将 SO 加载到内存中。
   - **符号解析:** 动态链接器会遍历 SO 的动态符号表 (`.dynsym`)，并使用符号哈希表 (`.hash`) 来查找未定义符号的定义。
   - **重定位:** 动态链接器会修改代码和数据段中的地址，以指向正确的符号地址。
     - **PLT (Procedure Linkage Table):** 用于延迟绑定函数调用。第一次调用外部函数时，会跳转到 PLT 中的桩代码，该代码会调用动态链接器来解析符号并更新 GOT (Global Offset Table)。后续调用会直接跳转到 GOT 中已解析的地址。
     - **GOT (Global Offset Table):** 存储全局变量和外部函数的地址。

3. **`fenv-arm.c` 中的符号处理:**
   - `fegetenv`, `fesetenv` 等函数会被编译成机器码并放入 `.text` 段，它们的符号会出现在 `.dynsym` 中，通常是全局符号，以便其他库或程序可以调用它们。
   - `__fe_dfl_env` 变量会被放入 `.rodata` 段（因为它是 `const`），其符号也会出现在 `.dynsym` 中。

**逻辑推理，假设输入与输出**

**示例：`fesetround` 函数**

* **假设输入:** `__round` 参数的值为 `FE_TOWARDZERO` (向零舍入，通常定义为 1)。
* **处理过程:**
    1. `fegetenv` 读取当前的 FPSCR 值，假设为 `0xXXXXXXXX`。
    2. 清除舍入模式位：`_fpscr &= ~(0x3 << FPSCR_RMODE_SHIFT);`
    3. 设置新的舍入模式位：`_fpscr |= (FE_TOWARDZERO << FPSCR_RMODE_SHIFT);`  假设 `FPSCR_RMODE_SHIFT` 为 22，则相当于 `_fpscr |= (1 << 22);`
    4. `fesetenv` 将修改后的 `_fpscr` 值写回 FPSCR 寄存器。
* **预期输出:**  FPSCR 寄存器中的舍入模式位被设置为向零舍入模式。后续的浮点运算将按照向零舍入的规则进行。

**用户或编程常见的使用错误**

1. **错误地假设 `feenableexcept` 和 `fedisableexcept` 的行为:**  开发者可能会尝试使用这两个函数来启用或禁用特定的浮点异常，但正如代码所示，它们并没有实际执行启用或禁用的操作。这可能导致程序在发生特定异常时没有按预期的方式处理。

   ```c
   // 错误示例：假设可以启用除零异常
   feenableexcept(FE_DIVBYZERO);
   float result = 1.0f / 0.0f; // 期望触发异常
   // ... 异常处理代码 ...
   ```

2. **不正确地操作异常标志:** 直接修改通过 `fegetenv` 获取的 FPSCR 值，而不使用 `fesetexceptflag` 等函数，可能会导致意外的行为或损坏浮点环境。

   ```c
   fenv_t env;
   fegetenv(&env);
   // 错误示例：直接修改 FPSCR 的位
   env |= FE_INVALID;
   fesetenv(&env);
   ```

3. **忘记保存和恢复浮点环境:** 在某些情况下，例如在调用可能修改浮点环境的第三方库函数之前，应该使用 `feholdexcept` 或 `fegetenv`/`fesetenv` 来保存和恢复浮点环境，以避免意外的副作用。

4. **混淆异常标志和异常使能:** 异常标志表示是否发生了某个异常，而异常使能（如果支持）控制当异常发生时是否会产生陷阱或信号。`fenv-arm.c` 中的实现主要关注异常标志的管理。

**Android Framework 或 NDK 如何到达这里**

作为调试线索，以下是代码执行路径的可能方式：

1. **NDK 中的 C/C++ 代码:**
   - 使用 `<fenv.h>` 中声明的浮点环境控制函数。
   - 例如，一个 NDK 模块可能需要设置特定的舍入模式来进行精确的数值计算。
   - 当 NDK 代码调用 `fesetround(FE_TOWARDZERO)` 时，最终会调用到 `bionic/libm/fenv-arm.c` 中的 `fesetround` 实现。

2. **Android Framework 的 Native 代码:**
   - Framework 的某些组件（例如，涉及图形、媒体处理的 native 代码）可能会直接或间接地使用 `libm` 中的浮点函数。
   - 例如，OpenGL ES 的实现依赖于 `libm` 中的数学函数，这些函数内部可能会影响或查询浮点环境。

3. **Java 代码通过 JNI 调用 Native 代码:**
   - Java 代码中的 `Math` 类的方法在底层通常会调用 native 实现，这些 native 实现可能位于 `libm.so` 中。
   - 虽然 Java 代码本身不直接操作浮点环境，但它调用的 native 代码可能会使用 `fenv` 函数。

**调试步骤示例:**

假设你在调试一个 Android 应用，怀疑浮点舍入模式导致了计算错误：

1. **设置断点:** 在 `bionic/libm/fenv-arm.c` 的 `fesetround` 函数入口处设置断点。
2. **运行应用:** 运行你的 Android 应用并触发相关的计算逻辑。
3. **观察调用栈:** 当断点命中时，查看调用栈，可以追溯到哪个模块或函数调用了 `fesetround`，以及传递的舍入模式参数是什么。
4. **单步执行:**  单步执行 `fesetround` 函数，观察 FPSCR 寄存器的变化。
5. **检查其他 `fenv` 函数:**  类似地，你可以在其他 `fenv` 函数上设置断点，例如 `fegetenv`，来查看当前的浮点环境状态。

通过以上分析，我们可以清晰地了解 `bionic/libm/fenv-arm.c` 文件的功能、实现细节以及它在 Android 系统中的作用。理解这些底层机制对于开发高质量的、数值稳定的 Android 应用至关重要。

Prompt: 
```
这是目录为bionic/libm/fenv-arm.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * Copyright (c) 2004 David Schultz <das@FreeBSD.ORG>
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
 *
 * $FreeBSD: src/lib/msun/arm/fenv.c,v 1.1 2004/06/06 10:03:59 das Exp $
 */

#include <fenv.h>

#define FPSCR_RMODE_SHIFT 22

const fenv_t __fe_dfl_env = 0;

int fegetenv(fenv_t* __envp) {
  fenv_t _fpscr;
  __asm__ __volatile__("vmrs %0,fpscr" : "=r"(_fpscr));
  *__envp = _fpscr;
  return 0;
}

int fesetenv(const fenv_t* __envp) {
  fenv_t _fpscr = *__envp;
  __asm__ __volatile__("vmsr fpscr,%0" : : "ri"(_fpscr));
  return 0;
}

int feclearexcept(int __excepts) {
  fexcept_t __fpscr;
  fegetenv(&__fpscr);
  __fpscr &= ~__excepts;
  fesetenv(&__fpscr);
  return 0;
}

int fegetexceptflag(fexcept_t* __flagp, int __excepts) {
  fexcept_t __fpscr;
  fegetenv(&__fpscr);
  *__flagp = __fpscr & __excepts;
  return 0;
}

int fesetexceptflag(const fexcept_t* __flagp, int __excepts) {
  fexcept_t __fpscr;
  fegetenv(&__fpscr);
  __fpscr &= ~__excepts;
  __fpscr |= *__flagp & __excepts;
  fesetenv(&__fpscr);
  return 0;
}

int feraiseexcept(int __excepts) {
  fexcept_t __ex = __excepts;
  fesetexceptflag(&__ex, __excepts);
  return 0;
}

int fetestexcept(int __excepts) {
  fexcept_t __fpscr;
  fegetenv(&__fpscr);
  return (__fpscr & __excepts);
}

int fegetround(void) {
  fenv_t _fpscr;
  fegetenv(&_fpscr);
  return ((_fpscr >> FPSCR_RMODE_SHIFT) & 0x3);
}

int fesetround(int __round) {
  fenv_t _fpscr;
  fegetenv(&_fpscr);
  _fpscr &= ~(0x3 << FPSCR_RMODE_SHIFT);
  _fpscr |= (__round << FPSCR_RMODE_SHIFT);
  fesetenv(&_fpscr);
  return 0;
}

int feholdexcept(fenv_t* __envp) {
  fenv_t __env;
  fegetenv(&__env);
  *__envp = __env;
  __env &= ~FE_ALL_EXCEPT;
  fesetenv(&__env);
  return 0;
}

int feupdateenv(const fenv_t* __envp) {
  fexcept_t __fpscr;
  fegetenv(&__fpscr);
  fesetenv(__envp);
  feraiseexcept(__fpscr & FE_ALL_EXCEPT);
  return 0;
}

int feenableexcept(int __mask __unused) {
  return -1;
}

int fedisableexcept(int __mask __unused) {
  return 0;
}

int fegetexcept(void) {
  return 0;
}

"""

```