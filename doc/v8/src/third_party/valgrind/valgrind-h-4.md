Response:
Let's break down the thought process for analyzing this C/C++ header file snippet.

1. **Identify the Core Purpose:** The filename `valgrind.h` immediately suggests a connection to the Valgrind tool. Knowing that Valgrind is a memory debugging and profiling tool is crucial. This hints that the code within will likely facilitate interaction with Valgrind. The path `v8/src/third_party/valgrind/` further confirms this – it's V8's way of using Valgrind's capabilities.

2. **Scan for Key Patterns:**  A quick skim reveals the repeated `CALL_FN_W_*` macros. This pattern strongly suggests a set of macros designed to call functions with a varying number of arguments. The `W` likely signifies "word" or "argument," and the number after it denotes the argument count.

3. **Analyze a Representative Macro:**  Let's pick a simple one, like `CALL_FN_W_W`. We can break down its components:

   * `do { ... } while(0)`: This is a common C/C++ idiom to create a block scope, allowing for local variable declarations and ensuring the macro behaves like a single statement.
   * `volatile OrigFn _orig = (orig);`: This line declares a local volatile variable `_orig` of type `OrigFn` and initializes it with the `orig` argument. The `volatile` keyword is important – it likely tells the compiler not to make assumptions about the value of `_orig`, which is relevant when interacting with external tools like Valgrind. We don't have the definition of `OrigFn`, but we can infer it holds information needed to call the original function.
   * `volatile unsigned long _argvec[2];`: An array to hold arguments. The size `2` aligns with `CALL_FN_W_W` implying one argument to the function being called, plus likely some overhead for Valgrind's internal use. `unsigned long` suggests we are dealing with memory addresses or integer values.
   * `volatile unsigned long _res;`: A variable to hold the return value.
   * `_argvec[0] = (unsigned long)_orig.nraddr;`:  This is interesting. `nraddr` is being assigned to the first element. Given the Valgrind context, `nraddr` likely stands for "no-redirection address" or something similar, hinting that Valgrind needs the original function's address to intercept the call.
   * `_argvec[1] = (unsigned long)(arg1);`: The actual function argument is placed in the next element.
   * `__asm__ volatile(...)`: This is inline assembly code. It's the core of the interaction with the underlying system.
     * `"ldr r0, [%1, #4] \n\t"`: Load the first argument (`arg1`) from the `_argvec` array into register `r0`. The offset `#4` suggests `unsigned long` is 4 bytes on this architecture (likely ARM).
     * `"ldr r4, [%1] \n\t"`: Load the target function address (`_orig.nraddr`) into register `r4`.
     * `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4`: This is a crucial macro. It's likely defined elsewhere and represents Valgrind's mechanism to intercept the function call at `r4`. "No-redirection" suggests Valgrind wants to observe the *original* call before any potential instrumentation.
     * `"mov %0, r0\n"`: Move the return value from register `r0` into the `_res` variable.
   * `: /*out*/   "=r" (_res)`:  Specifies `_res` as an output operand, linked to a register.
   * `: /*in*/    "0" (&_argvec[0])`: Specifies the memory location of `_argvec` as an input operand. The `"0"` links it to the `%1` placeholder in the assembly.
   * `: /*trash*/ "cc", "memory",  __CALLER_SAVED_REGS`:  Lists registers that the assembly code might modify (clobber). This is important for compiler optimization.
   * `lval = (__typeof__(lval)) _res;`:  Cast the result back to the original type and assign it to `lval`.

4. **Generalize the Findings:** Now that we've analyzed one macro, we can see the pattern across the others. They handle different numbers of arguments, placing them in registers according to the architecture's calling convention. The core logic of loading the target address and using `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R*` remains consistent.

5. **Identify Platform-Specific Sections:**  The `#if defined(PLAT_ppc64_linux)` and `#if defined(PLAT_arm_linux)` blocks indicate that this header file adapts to different processor architectures and operating systems. The assembly code within each block is specific to that platform's register usage and calling conventions.

6. **Infer the Overall Functionality:** Based on the macros and the Valgrind context, the primary function of this header is to provide a way to call functions while allowing Valgrind to intercept and monitor those calls. This is essential for Valgrind's memory debugging and profiling capabilities.

7. **Consider the ".tq" Case:** The prompt mentions the `.tq` extension. Knowing that Torque is V8's internal language for defining built-in functions, the implication is that if the file had that extension, it would contain Torque source code, which is a higher-level way of expressing similar low-level operations.

8. **Relate to JavaScript (if applicable):**  Since Valgrind is used to debug memory issues, and memory management is a critical aspect of JavaScript engines, these macros indirectly relate to JavaScript's stability and performance. While the macros themselves aren't directly used in JavaScript code, they're part of the underlying infrastructure that helps ensure the JavaScript engine (V8) works correctly. However, *in this specific code snippet*, there's no direct connection to specific JavaScript features or syntax. The connection is at a lower, engine level.

9. **Think About Common Programming Errors:**  The macros are designed to *help detect* errors. Common errors they might help uncover include memory leaks, use-after-free errors, and accessing uninitialized memory. Valgrind, using these hooks, can identify when these situations occur during program execution.

10. **Synthesize the Summary:**  Finally, put all the pieces together to summarize the file's purpose, emphasizing its role in Valgrind integration for memory debugging within the V8 JavaScript engine. Highlight the platform-specific nature and the function call interception mechanism.
好的，让我们来分析一下提供的这段C++头文件代码片段。

**文件功能归纳：**

这段 `valgrind.h` 头文件代码片段的核心功能是为 V8 JavaScript 引擎提供了一组宏定义，用于在特定架构（这里是 `ppc64_linux` 和 `arm_linux`）上调用函数，并允许 Valgrind 工具进行拦截和监控。  这些宏定义封装了与 Valgrind 集成的底层汇编代码，使得 V8 在运行时，Valgrind 能够追踪函数调用过程中的内存访问等行为，从而帮助开发者检测内存泄漏、非法内存访问等问题。

**详细功能拆解：**

1. **Valgrind 集成:**  从文件名和文件路径可以明确得知，此文件是 V8 引擎为了与 Valgrind 工具协同工作而存在的。Valgrind 是一个强大的内存调试和性能分析工具。

2. **平台特定性:** 代码中使用了 `#if defined(PLAT_ppc64_linux)` 和 `#if defined(PLAT_arm_linux)` 这样的预编译指令，表明这些宏定义是针对特定的处理器架构和操作系统进行的适配。  `ppc64_linux` 指的是 PowerPC 64 位架构的 Linux 系统，而 `arm_linux` 指的是 ARM 架构的 Linux 系统。

3. **`OrigFn` 类型:**  在每个宏定义中，都声明了一个 `volatile OrigFn _orig = (orig);`。虽然没有给出 `OrigFn` 的定义，但可以推断它是一个结构体或联合体，包含了被调用函数的原始地址 (`nraddr`) 和可能的其他信息 (`r2`)。`volatile` 关键字表明该变量的值可能会在编译器不可见的情况下被改变（例如，被 Valgrind 修改）。

4. **`CALL_FN_W_*W` 宏:**  这些宏是核心。它们的命名模式是 `CALL_FN_W_nW`，其中 `n` 代表被调用函数的参数数量。例如，`CALL_FN_W_5W` 用于调用有 5 个参数的函数。

5. **内联汇编 (`__asm__ volatile`)**:  每个宏定义的核心部分是内联汇编代码。这段汇编代码负责：
   - **保存和恢复上下文:**  例如，保存和恢复 `tocptr` (Table of Contents Pointer)，这在某些架构（如 PowerPC）上用于访问全局数据。
   - **加载参数到寄存器:**  根据目标架构的调用约定，将函数的参数加载到特定的寄存器中（例如，`r3` 到 `r10` 在 `ppc64_linux` 上）。
   - **调用 Valgrind 的入口点:**  使用 `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11` (在 `ppc64_linux` 上) 或 `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4` (在 `arm_linux` 上) 这样的宏，将控制权转移到 Valgrind，让 Valgrind 可以在函数调用前后执行它的检测逻辑。  "NOREDIR" 可能意味着 Valgrind 不会重定向到另一个函数，而是会监控原始的函数调用。
   - **获取返回值:**  从指定的寄存器中获取函数的返回值。

6. **参数传递:**  宏定义使用一个 `volatile unsigned long _argvec[]` 数组来传递参数。  参数被存储在这个数组中，然后汇编代码从数组中加载参数到寄存器。

7. **返回值处理:**  宏定义使用 `lval = (__typeof__(lval)) _res;` 将汇编代码中获取的返回值赋给 `lval` 变量。`__typeof__(lval)` 用于保持返回值的原始类型。

**如果 `v8/src/third_party/valgrind/valgrind.h` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码文件。Torque 是 V8 内部使用的一种领域特定语言，用于定义内置函数和运行时代码。在这种情况下，该文件会包含使用 Torque 语法编写的代码，而不是 C++ 宏和汇编。Torque 代码会被编译成 C++ 代码，最终集成到 V8 中。

**与 JavaScript 的功能关系：**

这段代码本身不是直接用 JavaScript 编写的，但它对 JavaScript 的功能至关重要。Valgrind 用于检测 V8 引擎自身的内存错误。当 V8 运行 JavaScript 代码时，底层的 C++ 代码（包括使用了这些宏的代码）会被执行。如果 V8 的 C++ 代码存在内存泄漏或其他内存错误，Valgrind 可以在开发和测试阶段检测出来，从而提高 V8 的稳定性和可靠性，最终让 JavaScript 代码能够在一个更健壮的环境中运行。

**JavaScript 示例（间接关系）：**

虽然这段 C++ 代码不直接操作 JavaScript 对象，但 Valgrind 检测出的 V8 引擎错误可能会影响 JavaScript 的行为。例如，一个 V8 的内存泄漏可能最终导致 JavaScript 应用程序的性能下降或崩溃。

```javascript
// 这是一个普通的 JavaScript 代码片段，
// 但如果在底层的 V8 引擎中存在内存泄漏（由 Valgrind 检测），
// 可能会导致以下问题：

let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push(i);
  // 如果 V8 的某些内部操作在每次循环中都发生内存泄漏，
  // 即使 largeArray 本身被正确管理，
  // 也会逐渐消耗系统资源。
}

// 理论上，当 largeArray 不再使用时，
// JavaScript 引擎的垃圾回收机制应该回收其占用的内存。
largeArray = null;

// 但如果 V8 自身存在内存泄漏，
// 即使 JavaScript 代码编写正确，
// 泄漏的内存仍然不会被释放。
```

**代码逻辑推理和假设输入输出：**

这段代码主要是宏定义，没有直接的输入输出逻辑。它的作用是 *封装* 函数调用过程，以便 Valgrind 可以介入。

**假设场景:**  假设有一个 C++ 函数 `int add(int a, int b)`，V8 内部需要调用它，并且希望 Valgrind 能够监控这次调用。

**假设输入:**
- `lval`: 一个用于接收返回值的 `int` 变量。
- `orig`: 一个 `OrigFn` 类型的变量，其 `nraddr` 成员指向 `add` 函数的地址。
- `arg1`: 整数值，例如 `5`。
- `arg2`: 整数值，例如 `10`。

**宏调用:**  V8 可能会使用类似 `CALL_FN_W_WW(lval, orig, 5, 10);` 的宏调用。

**代码逻辑推理:**
1. 宏展开后，`_argvec` 数组会被初始化，包含 `add` 函数的地址和参数 `5` 和 `10`。
2. 内联汇编会将函数地址加载到寄存器，并将参数加载到相应的寄存器。
3. `VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_*` 宏会将控制权交给 Valgrind。
4. Valgrind 可能会记录这次函数调用、参数值、内存访问等信息。
5. Valgrind 执行完毕后，控制权返回，`add` 函数被实际调用。
6. `add` 函数的返回值被存储在某个寄存器中，然后被汇编代码读取到 `_res` 变量。
7. `lval` 最终被赋值为 `_res` 的值 (15)。

**用户常见的编程错误（Valgrind 可以帮助检测）：**

Valgrind 主要用于检测与内存管理相关的错误，常见的编程错误包括：

1. **内存泄漏 (Memory Leaks):**  分配了内存但没有释放。

   ```c++
   // C++ 代码示例 (V8 引擎内部可能存在类似情况)
   void* ptr = malloc(1024);
   // ... 使用 ptr
   // 忘记 free(ptr); // 内存泄漏
   ```

2. **使用已释放的内存 (Use After Free):**  访问已经被释放的内存。

   ```c++
   void* ptr = malloc(1024);
   free(ptr);
   // ... 之后尝试访问 ptr 指向的内存
   // * (int*)ptr = 5; // 错误！
   ```

3. **访问未初始化的内存 (Use of Uninitialized Value):**  使用了尚未赋值的变量。

   ```c++
   int x;
   int y = x + 5; // x 的值未初始化，可能导致不可预测的结果
   ```

4. **无效的内存访问 (Invalid Memory Accesses):**  读写不属于程序分配的内存区域，例如数组越界。

   ```c++
   int arr[5];
   arr[10] = 10; // 数组越界访问
   ```

Valgrind 通过监控程序运行时的内存操作，可以有效地检测到这些错误，帮助 V8 引擎的开发者提高代码质量。

**总结一下它的功能 (作为第 5 部分)：**

作为系列的一部分，到目前为止，这段 `valgrind.h` 代码片段主要展示了 V8 引擎为了与 Valgrind 集成，在底层如何定义用于调用函数的宏。这些宏是平台特定的，并使用内联汇编来执行函数调用，同时允许 Valgrind 工具进行拦截和监控。其核心功能是为 Valgrind 提供必要的“钩子”，以便在 V8 运行时检测内存管理相关的错误。这部分代码是 V8 质量保证和调试流程中的一个关键组成部分。

### 提示词
```
这是目录为v8/src/third_party/valgrind/valgrind.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/third_party/valgrind/valgrind.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
gned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_6W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6)   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+6];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_7W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7)                            \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+7];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_8W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+8];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      _argvec[2+8] = (unsigned long)arg8;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  10, 64(11)\n\t" /* arg8->r10 */                     \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)" /* restore tocptr */                      \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_9W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8,arg9)                  \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+9];                        \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      _argvec[2+8] = (unsigned long)arg8;                         \
      _argvec[2+9] = (unsigned long)arg9;                         \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "addi 1,1,-128\n\t"  /* expand stack frame */            \
         /* arg9 */                                               \
         "ld  3,72(11)\n\t"                                       \
         "std 3,112(1)\n\t"                                       \
         /* args1-8 */                                            \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  10, 64(11)\n\t" /* arg8->r10 */                     \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)\n\t" /* restore tocptr */                  \
         "addi 1,1,128"     /* restore frame */                   \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_10W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+10];                       \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      _argvec[2+8] = (unsigned long)arg8;                         \
      _argvec[2+9] = (unsigned long)arg9;                         \
      _argvec[2+10] = (unsigned long)arg10;                       \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "addi 1,1,-128\n\t"  /* expand stack frame */            \
         /* arg10 */                                              \
         "ld  3,80(11)\n\t"                                       \
         "std 3,120(1)\n\t"                                       \
         /* arg9 */                                               \
         "ld  3,72(11)\n\t"                                       \
         "std 3,112(1)\n\t"                                       \
         /* args1-8 */                                            \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  10, 64(11)\n\t" /* arg8->r10 */                     \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)\n\t" /* restore tocptr */                  \
         "addi 1,1,128"     /* restore frame */                   \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_11W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10,arg11)     \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+11];                       \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      _argvec[2+8] = (unsigned long)arg8;                         \
      _argvec[2+9] = (unsigned long)arg9;                         \
      _argvec[2+10] = (unsigned long)arg10;                       \
      _argvec[2+11] = (unsigned long)arg11;                       \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "addi 1,1,-144\n\t"  /* expand stack frame */            \
         /* arg11 */                                              \
         "ld  3,88(11)\n\t"                                       \
         "std 3,128(1)\n\t"                                       \
         /* arg10 */                                              \
         "ld  3,80(11)\n\t"                                       \
         "std 3,120(1)\n\t"                                       \
         /* arg9 */                                               \
         "ld  3,72(11)\n\t"                                       \
         "std 3,112(1)\n\t"                                       \
         /* args1-8 */                                            \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  10, 64(11)\n\t" /* arg8->r10 */                     \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)\n\t" /* restore tocptr */                  \
         "addi 1,1,144"     /* restore frame */                   \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_12W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                arg7,arg8,arg9,arg10,arg11,arg12) \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3+12];                       \
      volatile unsigned long _res;                                \
      /* _argvec[0] holds current r2 across the call */           \
      _argvec[1]   = (unsigned long)_orig.r2;                     \
      _argvec[2]   = (unsigned long)_orig.nraddr;                 \
      _argvec[2+1] = (unsigned long)arg1;                         \
      _argvec[2+2] = (unsigned long)arg2;                         \
      _argvec[2+3] = (unsigned long)arg3;                         \
      _argvec[2+4] = (unsigned long)arg4;                         \
      _argvec[2+5] = (unsigned long)arg5;                         \
      _argvec[2+6] = (unsigned long)arg6;                         \
      _argvec[2+7] = (unsigned long)arg7;                         \
      _argvec[2+8] = (unsigned long)arg8;                         \
      _argvec[2+9] = (unsigned long)arg9;                         \
      _argvec[2+10] = (unsigned long)arg10;                       \
      _argvec[2+11] = (unsigned long)arg11;                       \
      _argvec[2+12] = (unsigned long)arg12;                       \
      __asm__ volatile(                                           \
         "mr 11,%1\n\t"                                           \
         "std 2,-16(11)\n\t"  /* save tocptr */                   \
         "ld   2,-8(11)\n\t"  /* use nraddr's tocptr */           \
         "addi 1,1,-144\n\t"  /* expand stack frame */            \
         /* arg12 */                                              \
         "ld  3,96(11)\n\t"                                       \
         "std 3,136(1)\n\t"                                       \
         /* arg11 */                                              \
         "ld  3,88(11)\n\t"                                       \
         "std 3,128(1)\n\t"                                       \
         /* arg10 */                                              \
         "ld  3,80(11)\n\t"                                       \
         "std 3,120(1)\n\t"                                       \
         /* arg9 */                                               \
         "ld  3,72(11)\n\t"                                       \
         "std 3,112(1)\n\t"                                       \
         /* args1-8 */                                            \
         "ld   3, 8(11)\n\t"  /* arg1->r3 */                      \
         "ld   4, 16(11)\n\t" /* arg2->r4 */                      \
         "ld   5, 24(11)\n\t" /* arg3->r5 */                      \
         "ld   6, 32(11)\n\t" /* arg4->r6 */                      \
         "ld   7, 40(11)\n\t" /* arg5->r7 */                      \
         "ld   8, 48(11)\n\t" /* arg6->r8 */                      \
         "ld   9, 56(11)\n\t" /* arg7->r9 */                      \
         "ld  10, 64(11)\n\t" /* arg8->r10 */                     \
         "ld  11, 0(11)\n\t"  /* target->r11 */                   \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                  \
         "mr 11,%1\n\t"                                           \
         "mr %0,3\n\t"                                            \
         "ld 2,-16(11)\n\t" /* restore tocptr */                  \
         "addi 1,1,144"     /* restore frame */                   \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "r" (&_argvec[2])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#endif /* PLAT_ppc64_linux */

/* ------------------------- arm-linux ------------------------- */

#if defined(PLAT_arm_linux)

/* These regs are trashed by the hidden call. */
#define __CALLER_SAVED_REGS "r0", "r1", "r2", "r3","r4","r14"

/* These CALL_FN_ macros assume that on arm-linux, sizeof(unsigned
   long) == 4. */

#define CALL_FN_W_v(lval, orig)                                   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[1];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      __asm__ volatile(                                           \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "mov %0, r0\n"                                           \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_W(lval, orig, arg1)                             \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[2];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      __asm__ volatile(                                           \
         "ldr r0, [%1, #4] \n\t"                                  \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "mov %0, r0\n"                                           \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory",  __CALLER_SAVED_REGS         \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WW(lval, orig, arg1,arg2)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      __asm__ volatile(                                           \
         "ldr r0, [%1, #4] \n\t"                                  \
         "ldr r1, [%1, #8] \n\t"                                  \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "mov %0, r0\n"                                           \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WWW(lval, orig, arg1,arg2,arg3)                 \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[4];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      __asm__ volatile(                                           \
         "ldr r0, [%1, #4] \n\t"                                  \
         "ldr r1, [%1, #8] \n\t"                                  \
         "ldr r2, [%1, #12] \n\t"                                 \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "mov %0, r0\n"                                           \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_WWWW(lval, orig, arg1,arg2,arg3,arg4)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[5];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      __asm__ volatile(                                           \
         "ldr r0, [%1, #4] \n\t"                                  \
         "ldr r1, [%1, #8] \n\t"                                  \
         "ldr r2, [%1, #12] \n\t"                                 \
         "ldr r3, [%1, #16] \n\t"                                 \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "mov %0, r0"                                             \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_5W(lval, orig, arg1,arg2,arg3,arg4,arg5)        \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[6];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      __asm__ volatile(                                           \
         "ldr r0, [%1, #20] \n\t"                                 \
         "push {r0} \n\t"                                         \
         "ldr r0, [%1, #4] \n\t"                                  \
         "ldr r1, [%1, #8] \n\t"                                  \
         "ldr r2, [%1, #12] \n\t"                                 \
         "ldr r3, [%1, #16] \n\t"                                 \
         "ldr r4, [%1] \n\t"  /* target->r4 */                    \
         VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                   \
         "add sp, sp, #4 \n\t"                                    \
         "mov %0, r0"                                             \
         : /*out*/   "=r" (_res)                                  \
         : /*in*/    "0" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_6W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6)   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[7];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      __asm
```