Response:
My thought process to analyze the provided C++ header file snippet went through these stages:

1. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recurring patterns and keywords. The most striking things were the numerous `#define CALL_FN_...` macros, the `OrigFn` type, the use of inline assembly (`__asm__ volatile`), and platform-specific `#ifdef` blocks. The `VALGRIND_CALL_NOREDIR_...` macros also stood out.

2. **Understanding the Macros:** I focused on the `CALL_FN_...` macros. The naming convention (`CALL_FN_v_WW`, `CALL_FN_W_WWW`, etc.) strongly suggested that these macros are for calling functions with different numbers of arguments and potentially different return value handling. The `v` likely meant `void` return, and `W` probably represented an argument (likely a word or pointer-sized argument, considering the target architectures).

3. **Analyzing the Inline Assembly:** The `__asm__ volatile` blocks were key. I noticed patterns like:
    * Moving the function address into a register (`movl (%%eax), %%eax` or `movq (%%rax), %%rax`).
    * Calling `VALGRIND_CALL_NOREDIR_EAX` or `VALGRIND_CALL_NOREDIR_RAX`. This clearly indicates interaction with Valgrind.
    * Manipulating the stack (`pushl`, `subl`, `addl` for x86; `subq`, `addq` for x64). This is necessary for passing arguments to the called function.
    * Specifying input/output/trash registers. This is crucial for the compiler to understand the side effects of the assembly.

4. **Inferring Valgrind's Role:** The presence of `VALGRIND_CALL_NOREDIR_...` strongly suggested that the header is designed to interface with Valgrind. The "NOREDIR" part hinted that Valgrind might be intercepting or monitoring function calls. The macros likely help V8 call functions in a way that Valgrind can observe.

5. **Platform-Specific Implementations:** The `#if defined(PLAT_x86_linux) ...` and `#if defined(PLAT_amd64_linux) ...` blocks showed that the implementation varies based on the target architecture and operating system. This is common in low-level code dealing with calling conventions.

6. **Connecting to Function Pointers:** The `OrigFn` type and the way the macros are used (taking `fnptr` as an argument) confirmed that these macros are designed for calling arbitrary function pointers.

7. **Considering the `.tq` Extension:**  The prompt mentioned that if the file ended in `.tq`, it would be Torque code. Since the provided snippet is a `.h` file, this point isn't directly relevant to the analysis of *this* specific code. However, it's important information for understanding the broader V8 codebase.

8. **JavaScript Relevance:** I considered how this low-level Valgrind integration could relate to JavaScript. While JavaScript itself doesn't directly deal with inline assembly or low-level calling conventions, V8 (the JavaScript engine) does. This header likely helps Valgrind analyze V8's execution, including calls to internal C++ functions triggered by JavaScript code. This led to the example of memory leaks in JavaScript triggering errors detected by Valgrind when running the V8 engine.

9. **Common Programming Errors:**  I thought about how using these macros incorrectly or having bugs in the called functions could lead to issues. Memory corruption, incorrect argument passing, and stack imbalances are common errors in C/C++ that Valgrind is designed to detect.

10. **Synthesizing the Functionality:**  Finally, I combined all the observations to formulate the core functionality: enabling Valgrind to monitor function calls within V8, particularly for memory-related issues.

11. **Addressing the "Part 2" Request:** I recognized that this was a part of a larger file and focused the summary on the provided snippet's functionality, acknowledging it's likely part of a broader Valgrind integration within V8. I avoided making assumptions about parts of the file that weren't provided.

Essentially, my process involved: recognizing patterns, understanding low-level programming concepts (like calling conventions and assembly), inferring the purpose based on keywords and context, and then connecting that purpose back to the broader V8 and Valgrind ecosystem. The prompt's hints (like the `.tq` extension and the connection to JavaScript) helped to guide the analysis.
好的，我们来归纳一下这段代码的功能。

**功能归纳：**

这段代码是 `v8/src/third_party/valgrind/valgrind.h` 文件的第二部分，主要定义了一系列用于在 x86 和 amd64 架构的 Linux 和 macOS 系统上调用函数的宏，并且这些宏特别设计为能够被 Valgrind 工具监控到。

**具体功能点：**

1. **定义了 `CALL_FN_W_...` 和 `CALL_FN_v_...` 系列宏:**
   - 这些宏用于调用函数指针 (`fnptr`)，并可以传递不同数量的参数 (`arg1`, `arg2`, ...) 到被调用的函数。
   - `CALL_FN_W_...` 宏假定被调用函数有返回值，并将返回值赋值给 `lval`。
   - `CALL_FN_v_...` 宏假定被调用函数没有返回值 (void)。

2. **平台特定实现 (x86 和 amd64):**
   - 代码针对 `PLAT_x86_linux`, `PLAT_x86_darwin`, `PLAT_amd64_linux`, 和 `PLAT_amd64_darwin` 定义了不同的宏实现。这是因为不同架构和操作系统有不同的函数调用约定（例如，参数如何传递到函数，返回值如何获取等）。

3. **Valgrind 集成:**
   - 关键在于 `VALGRIND_CALL_NOREDIR_EAX` 和 `VALGRIND_CALL_NOREDIR_RAX` 宏。这些宏是与 Valgrind 工具交互的关键点。它们的作用是通知 Valgrind 即将发生一个函数调用，以便 Valgrind 能够监控这个调用，检查是否存在内存泄漏、非法内存访问等问题。
   - "NOREDIR" 可能意味着这个调用不应该被 Valgrind 重定向或替换，而是直接执行原始的函数。

4. **使用内联汇编 (`__asm__ volatile`):**
   - 这些宏的核心实现使用了内联汇编。这是因为需要精确地控制函数调用的过程，以便与 Valgrind 进行交互，并且需要处理不同架构的调用约定。
   - 汇编代码会执行以下操作：
     - 将函数地址加载到寄存器 (`%eax` 或 `%rax`)。
     - 将参数压入栈中（对于 x86）或放入寄存器/栈中（对于 amd64）。
     - 调用 `VALGRIND_CALL_NOREDIR_EAX/RAX` 宏。
     - 清理栈（对于 x86）。
     - 将返回值从寄存器中取出（对于 `CALL_FN_W_...` 宏）。

5. **处理返回值:**
   - `CALL_FN_W_...` 宏会将函数的返回值存储在 `lval` 变量中。`(__typeof__(lval))` 用于确保类型安全。

6. **避免栈红区冲突 (amd64):**
   - 在 amd64 的实现中，可以看到 `subq $128,%%rsp` 和 `addq $128,%%rsp` 这样的操作。这是为了避免与栈红区（red zone）发生冲突。栈红区是栈指针下方的一小块区域，不应被普通函数使用。在调用可能被 Valgrind 监控的函数时，需要将栈指针下移，避免 Valgrind 的监控代码与红区发生干扰。

**关于 .tq 结尾：**

如果 `v8/src/third_party/valgrind/valgrind.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用于生成高效的运行时代码的领域特定语言。然而，当前提供的代码段是 `.h` 头文件，因此是 C/C++ 代码，而不是 Torque 代码。

**与 Javascript 的关系：**

虽然这段代码本身是 C/C++，并且直接与底层系统调用和架构相关，但它与 JavaScript 的功能有着密切的关系。

- **Valgrind 用于 V8 的调试和性能分析:** V8 团队使用 Valgrind 来检测 V8 引擎本身是否存在内存泄漏、内存错误等问题。这段头文件中的宏使得 V8 的 C++ 代码在被 Valgrind 监控时，能够正确地执行函数调用，并让 Valgrind 能够捕获潜在的错误。
- **间接影响 JavaScript 性能和稳定性:**  通过 Valgrind 发现并修复 V8 引擎中的问题，最终会提高 JavaScript 的执行效率和稳定性。

**Javascript 举例说明（概念性）：**

虽然不能直接用 JavaScript 调用这些 C++ 宏，但可以想象一下场景：

```javascript
// 假设 V8 内部有一个 C++ 函数负责分配内存
// 并且这个函数使用了上面定义的 CALL_FN_W 宏
function allocateMemoryInCpp(size) {
  // ... V8 内部调用 C++ 代码，使用 CALL_FN_W 宏调用真正的分配函数
  let address = _CallCppAllocateFunction(size);
  return address;
}

// 在 JavaScript 中调用这个函数
let buffer1 = allocateMemoryInCpp(1024);
let buffer2 = allocateMemoryInCpp(2048);

// ... 忘记释放 buffer1 导致的内存泄漏

// 当使用 Valgrind 运行 Node.js 或 Chrome 时，
// Valgrind 可以通过监控 CALL_FN_W 宏的调用，
// 追踪内存的分配和释放，从而检测到 buffer1 的内存泄漏。
```

在这个例子中，JavaScript 代码间接地触发了使用了 `CALL_FN_W` 宏的 C++ 代码的执行。Valgrind 可以监控这些调用，帮助开发者发现 JavaScript 代码（通过 V8 引擎）引起的底层内存问题。

**代码逻辑推理（假设输入与输出）：**

假设我们有以下 C++ 函数：

```c++
int add(int a, int b) {
  return a + b;
}
```

我们可以使用 `CALL_FN_W_WW` 宏来调用它：

```c++
typedef int (*AddFn)(int, int);
AddFn add_ptr = &add;
int result;
CALL_FN_W_WW(result, { .nraddr = (void*)add_ptr }, 5, 3);
// 假设输入 arg1 = 5, arg2 = 3
// 预期输出 result = 8
```

在这个例子中：

- **假设输入：** `add_ptr` 指向 `add` 函数，`arg1` 为 5，`arg2` 为 3。
- **代码逻辑：** `CALL_FN_W_WW` 宏会设置好参数，调用 `add` 函数，并将返回值存储在 `result` 变量中。
- **预期输出：** `result` 的值将是 8。

**涉及用户常见的编程错误：**

这些宏主要用于 V8 内部，普通 JavaScript 开发者不会直接使用。但是，如果 V8 引擎自身在使用这些宏时出现错误，可能会导致以下问题，这些问题最终会影响到 JavaScript 开发者：

1. **内存泄漏：** 如果 V8 内部的内存分配函数被 Valgrind 检测到泄漏，可能是因为 V8 在某个操作后没有正确释放内存。这会导致 Node.js 或 Chrome 的内存占用不断增加。

   ```javascript
   // 常见的 JavaScript 内存泄漏场景：闭包引用外部变量
   function createLeakyClosure() {
     let largeData = new Array(1000000).fill('*');
     return function() {
       console.log(largeData.length); // 闭包引用了 largeData
     };
   }

   let closure = createLeakyClosure();
   setInterval(closure, 1000); // 定时器一直持有 closure，导致 largeData 无法释放
   ```

   Valgrind 可以帮助 V8 开发者追踪这种泄漏的根源。

2. **非法内存访问（例如，读/写已释放的内存）：** 如果 V8 内部出现这样的错误，会导致程序崩溃或产生不可预测的行为。

   ```javascript
   // 例如，操作一个已经被删除的对象
   let obj = {};
   obj.name = "test";
   delete obj;
   console.log(obj.name); // 可能会导致错误，Valgrind 可以检测到 C++ 层的非法内存访问
   ```

3. **栈溢出：**  虽然这些宏本身不太可能直接导致栈溢出，但在某些复杂的调用链中，如果参数传递或栈管理不当，可能会导致栈溢出。

**总结这段代码的功能：**

这段代码的核心功能是为 V8 引擎提供一种与 Valgrind 工具集成的机制，用于在 x86 和 amd64 架构的 Linux 和 macOS 系统上安全且可监控地调用 C++ 函数。它定义了一系列宏，通过内联汇编精确控制函数调用过程，使得 Valgrind 能够拦截并分析这些调用，从而帮助 V8 开发者检测和修复内存管理相关的错误，最终提升 JavaScript 运行时的稳定性和性能。它是 V8 内部用于调试和质量保证的重要组成部分。

### 提示词
```
这是目录为v8/src/third_party/valgrind/valgrind.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/third_party/valgrind/valgrind.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
nk,fnptr,arg1,arg2); } while (0)

#define CALL_FN_v_WWW(fnptr, arg1,arg2,arg3)                      \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_WWW(_junk,fnptr,arg1,arg2,arg3); } while (0)

#define CALL_FN_v_WWWW(fnptr, arg1,arg2,arg3,arg4)                \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_WWWW(_junk,fnptr,arg1,arg2,arg3,arg4); } while (0)

#define CALL_FN_v_5W(fnptr, arg1,arg2,arg3,arg4,arg5)             \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_5W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5); } while (0)

#define CALL_FN_v_6W(fnptr, arg1,arg2,arg3,arg4,arg5,arg6)        \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_6W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5,arg6); } while (0)

#define CALL_FN_v_7W(fnptr, arg1,arg2,arg3,arg4,arg5,arg6,arg7)   \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_7W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5,arg6,arg7); } while (0)

/* ------------------------- x86-{linux,darwin} ---------------- */

#if defined(PLAT_x86_linux)  ||  defined(PLAT_x86_darwin)

/* These regs are trashed by the hidden call.  No need to mention eax
   as gcc can already see that, plus causes gcc to bomb. */
#define __CALLER_SAVED_REGS /*"eax"*/ "ecx", "edx"

/* These CALL_FN_ macros assume that on x86-linux, sizeof(unsigned
   long) == 4. */

#define CALL_FN_W_v(lval, orig)                                   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[1];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      __asm__ volatile(                                           \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
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
         "subl $12, %%esp\n\t"                                    \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $16, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
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
         "subl $8, %%esp\n\t"                                     \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $16, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
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
         "subl $4, %%esp\n\t"                                     \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $16, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
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
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $16, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
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
         "subl $12, %%esp\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $32, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
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
      __asm__ volatile(                                           \
         "subl $8, %%esp\n\t"                                     \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $32, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_7W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7)                            \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[8];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      __asm__ volatile(                                           \
         "subl $4, %%esp\n\t"                                     \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $32, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_8W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[9];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      __asm__ volatile(                                           \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $32, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_9W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8,arg9)                  \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[10];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      __asm__ volatile(                                           \
         "subl $12, %%esp\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $48, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_10W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[11];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      __asm__ volatile(                                           \
         "subl $8, %%esp\n\t"                                     \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $48, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_11W(lval, orig, arg1,arg2,arg3,arg4,arg5,       \
                                  arg6,arg7,arg8,arg9,arg10,      \
                                  arg11)                          \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[12];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      _argvec[11] = (unsigned long)(arg11);                       \
      __asm__ volatile(                                           \
         "subl $4, %%esp\n\t"                                     \
         "pushl 44(%%eax)\n\t"                                    \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $48, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#define CALL_FN_W_12W(lval, orig, arg1,arg2,arg3,arg4,arg5,       \
                                  arg6,arg7,arg8,arg9,arg10,      \
                                  arg11,arg12)                    \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[13];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      _argvec[11] = (unsigned long)(arg11);                       \
      _argvec[12] = (unsigned long)(arg12);                       \
      __asm__ volatile(                                           \
         "pushl 48(%%eax)\n\t"                                    \
         "pushl 44(%%eax)\n\t"                                    \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"  /* target->%eax */            \
         VALGRIND_CALL_NOREDIR_EAX                                \
         "addl $48, %%esp\n"                                      \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0])                            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS          \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)

#endif /* PLAT_x86_linux || PLAT_x86_darwin */

/* ------------------------ amd64-{linux,darwin} --------------- */

#if defined(PLAT_amd64_linux)  ||  defined(PLAT_amd64_darwin)

/* ARGREGS: rdi rsi rdx rcx r8 r9 (the rest on stack in R-to-L order) */

/* These regs are trashed by the hidden call. */
#define __CALLER_SAVED_REGS /*"rax",*/ "rcx", "rdx", "rsi",       \
                            "rdi", "r8", "r9", "r10", "r11"

/* This is all pretty complex.  It's so as to make stack unwinding
   work reliably.  See bug 243270.  The basic problem is the sub and
   add of 128 of %rsp in all of the following macros.  If gcc believes
   the CFA is in %rsp, then unwinding may fail, because what's at the
   CFA is not what gcc "expected" when it constructs the CFIs for the
   places where the macros are instantiated.

   But we can't just add a CFI annotation to increase the CFA offset
   by 128, to match the sub of 128 from %rsp, because we don't know
   whether gcc has chosen %rsp as the CFA at that point, or whether it
   has chosen some other register (eg, %rbp).  In the latter case,
   adding a CFI annotation to change the CFA offset is simply wrong.

   So the solution is to get hold of the CFA using
   __builtin_dwarf_cfa(), put it in a known register, and add a
   CFI annotation to say what the register is.  We choose %rbp for
   this (perhaps perversely), because:

   (1) %rbp is already subject to unwinding.  If a new register was
       chosen then the unwinder would have to unwind it in all stack
       traces, which is expensive, and

   (2) %rbp is already subject to precise exception updates in the
       JIT.  If a new register was chosen, we'd have to have precise
       exceptions for it too, which reduces performance of the
       generated code.

   However .. one extra complication.  We can't just whack the result
   of __builtin_dwarf_cfa() into %rbp and then add %rbp to the
   list of trashed registers at the end of the inline assembly
   fragments; gcc won't allow %rbp to appear in that list.  Hence
   instead we need to stash %rbp in %r15 for the duration of the asm,
   and say that %r15 is trashed instead.  gcc seems happy to go with
   that.

   Oh .. and this all needs to be conditionalised so that it is
   unchanged from before this commit, when compiled with older gccs
   that don't support __builtin_dwarf_cfa.  Furthermore, since
   this header file is freestanding, it has to be independent of
   config.h, and so the following conditionalisation cannot depend on
   configure time checks.

   Although it's not clear from
   'defined(__GNUC__) && defined(__GCC_HAVE_DWARF2_CFI_ASM)',
   this expression excludes Darwin.
   .cfi directives in Darwin assembly appear to be completely
   different and I haven't investigated how they work.

   For even more entertainment value, note we have to use the
   completely undocumented __builtin_dwarf_cfa(), which appears to
   really compute the CFA, whereas __builtin_frame_address(0) claims
   to but actually doesn't.  See
   https://bugs.kde.org/show_bug.cgi?id=243270#c47
*/
#if defined(__GNUC__) && defined(__GCC_HAVE_DWARF2_CFI_ASM)
#  define __FRAME_POINTER                                         \
      ,"r"(__builtin_dwarf_cfa())
#  define VALGRIND_CFI_PROLOGUE                                   \
      "movq %%rbp, %%r15\n\t"                                     \
      "movq %2, %%rbp\n\t"                                        \
      ".cfi_remember_state\n\t"                                   \
      ".cfi_def_cfa rbp, 0\n\t"
#  define VALGRIND_CFI_EPILOGUE                                   \
      "movq %%r15, %%rbp\n\t"                                     \
      ".cfi_restore_state\n\t"
#else
#  define __FRAME_POINTER
#  define VALGRIND_CFI_PROLOGUE
#  define VALGRIND_CFI_EPILOGUE
#endif


/* These CALL_FN_ macros assume that on amd64-linux, sizeof(unsigned
   long) == 8. */

/* NB 9 Sept 07.  There is a nasty kludge here in all these CALL_FN_
   macros.  In order not to trash the stack redzone, we need to drop
   %rsp by 128 before the hidden call, and restore afterwards.  The
   nastyness is that it is only by luck that the stack still appears
   to be unwindable during the hidden call - since then the behaviour
   of any routine using this macro does not match what the CFI data
   says.  Sigh.

   Why is this important?  Imagine that a wrapper has a stack
   allocated local, and passes to the hidden call, a pointer to it.
   Because gcc does not know about the hidden call, it may allocate
   that local in the redzone.  Unfortunately the hidden call may then
   trash it before it comes to use it.  So we must step clear of the
   redzone, for the duration of the hidden call, to make it safe.

   Probably the same problem afflicts the other redzone-style ABIs too
   (ppc64-linux); but for those, the stack is
   self describing (none of this CFI nonsense) so at least messing
   with the stack pointer doesn't give a danger of non-unwindable
   stack. */

#define CALL_FN_W_v(lval, orig)                                   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[1];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      __asm__ volatile(                                           \
         VALGRIND_CFI_PROLOGUE                                    \
         "subq $128,%%rsp\n\t"                                    \
         "movq (%%rax), %%rax\n\t"  /* target->%rax */            \
         VALGRIND_CALL_NOREDIR_RAX                                \
         "addq $128,%%rsp\n\t"                                    \
         VALGRIND_CFI_EPILOGUE                                    \
         : /*out*/   "=a" (_res)                                  \
         : /*in*/    "a" (&_argvec[0]) __FRAME_POINTER            \
         : /*trash*/ "cc", "memory", __CALLER_SAVED_REGS, "r15"   \
      );
```