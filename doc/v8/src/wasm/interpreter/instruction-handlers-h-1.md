Response:
The user is asking for a summary of the functionality of the provided C++ header file snippet, which defines a macro `FOREACH_INSTR_HANDLER`. This macro appears to expand to a list of other macros, each representing a different WebAssembly instruction handler.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core element:** The central piece of information is the `FOREACH_INSTR_HANDLER` macro and the various `V(...)` calls within it.

2. **Recognize the naming convention:** The `V(...)` calls with names like `r2r_I32Add`, `s2s_MemoryGrow`, `s2s_SimdF64x2Add`, etc., strongly suggest that each represents a specific WebAssembly instruction. The prefixes like `r2r`, `r2s`, `s2r`, `s2s` likely indicate the input and output types of the instruction (e.g., register to register, register to stack, stack to register, stack to stack). The `I32`, `I64`, `F32`, `F64`, `S128` indicate the data types involved.

3. **Infer the file's purpose:** Given the names, the file `instruction-handlers.h` is clearly related to handling different WebAssembly instructions within the V8 interpreter. The `.h` extension confirms it's a header file, likely defining interfaces or macros for these handlers.

4. **Address the ".tq" question:**  The prompt asks what it would mean if the file ended in `.tq`. Recall that `.tq` files in V8 are associated with Torque, V8's type-checked intermediate language for generating C++ code. So, a `.tq` extension would indicate the file is written in Torque.

5. **Connect to JavaScript:** WebAssembly is designed to be a compilation target for languages like C++, Rust, and potentially even as an optimization target for parts of JavaScript execution. Therefore, the instructions in this file directly relate to the execution of WebAssembly code that might be called from JavaScript.

6. **Provide JavaScript examples:**  Think of simple JavaScript code that would result in the execution of some of the listed WebAssembly instructions. Basic arithmetic operations (`+`, `-`, `*`, `/`) map to instructions like `I32Add`, `I32Sub`, etc. Memory access in WebAssembly is triggered by `ArrayBuffer` operations in JavaScript. Function calls in JavaScript can invoke WebAssembly functions.

7. **Illustrate code logic:**  Choose a few instructions and demonstrate their logic with hypothetical inputs and outputs. For instance, `I32Add` takes two 32-bit integers and produces their sum. `I32Eqz` checks if a 32-bit integer is zero and returns a boolean (represented as 1 or 0).

8. **Identify common errors:** Consider what mistakes developers might make when dealing with the concepts represented by these instructions. Type mismatches (e.g., trying to add a float and an integer without explicit conversion), integer overflow, and accessing memory out of bounds are all relevant.

9. **Handle the "part 2" aspect:** Since this is part 2 of a 2-part question, the focus should be on summarizing the overall functionality *based on the provided code snippet*. Avoid introducing entirely new concepts not suggested by the content.

10. **Structure the answer:** Organize the information into clear sections addressing each part of the prompt: file functionality, Torque, JavaScript connection, code logic, common errors, and the final summary.

11. **Refine and clarify:** Review the answer for accuracy, clarity, and completeness. Ensure the examples are simple and illustrative. For example,  initially, I might just say "arithmetic operations relate to these instructions," but adding concrete JavaScript examples makes it much clearer. Similarly, for common errors, providing specific scenarios like integer overflow adds value.
好的，这是第二部分的代码，与第一部分结合起来，我们可以归纳一下 `v8/src/wasm/interpreter/instruction-handlers.h` 的功能。

**归纳其功能：**

`v8/src/wasm/interpreter/instruction-handlers.h` 文件定义了一个宏 `FOREACH_INSTR_HANDLER`，这个宏展开后会包含所有 WebAssembly 解释器需要处理的指令。

具体来说，这个头文件的主要功能是：

1. **枚举和组织 WebAssembly 指令处理函数：** 它通过宏 `FOREACH_INSTR_HANDLER` （以及根据编译选项可能包含的 `FOREACH_LOAD_STORE_INSTR_HANDLER`, `FOREACH_LOAD_STORE_DUPLICATED_INSTR_HANDLER`, `FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER`, `FOREACH_TRACE_INSTR_HANDLER`）来集中列出所有需要在解释器中实现的 WebAssembly 指令的处理逻辑。 每一个 `V(...)` 宏调用都代表一个特定的指令，例如 `V(r2r_I32Add)` 代表处理两个寄存器中的 32 位整数相加的指令。

2. **提供指令处理函数的命名约定：**  从指令的命名可以看出一些规律，例如：
    * `r2r_`: 表示操作数在寄存器中，结果也在寄存器中。
    * `r2s_`: 表示操作数在寄存器中，结果在栈上。
    * `s2r_`: 表示操作数在栈上，结果在寄存器中。
    * `s2s_`: 表示操作数在栈上，结果也在栈上。
    * `I32`, `I64`, `F32`, `F64`: 表示操作数和结果的数据类型（32位整数，64位整数，32位浮点数，64位浮点数）。
    * 后缀如 `Add`, `Sub`, `Mul`, `Eqz` 等表示具体的指令操作。

3. **支持多种 WebAssembly 特性：** 从列出的指令可以看出，该文件涵盖了 WebAssembly 的核心功能以及一些扩展特性，包括：
    * **基本运算：**  整数和浮点数的算术、比较、位运算等。
    * **内存操作：**  加载、存储、内存增长、内存大小等。
    * **控制流：**  分支、调用、返回、循环等。
    * **类型转换：**  不同类型之间的转换，包括符号扩展和饱和截断。
    * **SIMD (Single Instruction, Multiple Data)：**  向量化运算。
    * **原子操作：**  用于多线程环境下的同步。
    * **异常处理：**  抛出和捕获异常。
    * **引用类型 (GC)：**  处理引用、结构体和数组。

4. **可配置的边界检查和追踪：**  通过宏定义 `V8_DRUMBRAKE_BOUNDS_CHECKS` 和 `V8_ENABLE_DRUMBRAKE_TRACING`，可以控制是否启用边界检查和指令追踪功能，这对于调试和性能分析很有用。

**总结来说，`v8/src/wasm/interpreter/instruction-handlers.h` 是 V8 的 WebAssembly 解释器中一个关键的头文件，它集中定义了所有需要解释执行的 WebAssembly 指令及其对应的处理逻辑，为解释器的实现提供了基础框架。**

**关于之前的问题：**

* **如果 `v8/src/wasm/interpreter/instruction-handlers.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  这意味着指令处理逻辑将使用 Torque 语言编写，Torque 是一种 V8 内部使用的类型化中间语言，用于生成高效的 C++ 代码。
* **它与 javascript 的功能有关系，请用 javascript 举例说明。**  是的，WebAssembly 的目的是在 Web 浏览器中提供接近原生性能的执行能力，JavaScript 可以加载、编译和执行 WebAssembly 模块。

   ```javascript
   // 假设有一个名为 'module.wasm' 的 WebAssembly 模块导出了一个名为 'add' 的函数
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.instantiate(bytes))
     .then(results => {
       const wasmModule = results.instance;
       const result = wasmModule.exports.add(5, 10); // 调用 WebAssembly 导出的函数
       console.log(result); // 输出 15

       // 在 wasmModule.exports.add 内部，解释器可能会处理类似于 r2r_I32Add 的指令
     });

   // 另一个例子，使用 ArrayBuffer 操作 WebAssembly 线性内存
   fetch('module.wasm')
     .then(response => response.arrayBuffer())
     .then(bytes => WebAssembly.instantiate(bytes, {})) // 空的 importObject
     .then(results => {
       const wasmMemory = results.instance.exports.memory; // 获取 wasm 的 Memory 对象
       const buffer = new Int32Array(wasmMemory.buffer);
       buffer[0] = 100; // 对应 wasm 的内存写操作，解释器可能处理类似于 s2s_I32Store 的指令
       console.log(buffer[0]); // 输出 100
     });
   ```

* **如果有代码逻辑推理，请给出假设输入与输出。**

   假设我们关注 `V(r2r_I32Eqz)`，它表示判断一个寄存器中的 32 位整数是否为零。

   **假设输入：**
   * 寄存器 R0 包含值 `0`

   **代码逻辑推理：**
   `r2r_I32Eqz` 指令会读取寄存器 R0 的值，判断它是否等于零。如果等于零，则将结果 `1`（表示真）写入目标寄存器（假设是 R1）；否则，将 `0`（表示假）写入目标寄存器 R1。

   **输出：**
   * 寄存器 R1 包含值 `1`

   假设我们关注 `V(s2s_I32Add)`，它表示从栈上弹出两个 32 位整数并将它们的和压回栈上。

   **假设输入：**
   * WebAssembly 解释器栈顶的两个元素分别是 `5` 和 `10` (先入栈的是 5，后入栈的是 10，所以栈顶是 10)

   **代码逻辑推理：**
   `s2s_I32Add` 指令会从栈顶弹出两个值，即 `10` 和 `5`。然后计算它们的和 `5 + 10 = 15`。最后，将结果 `15` 压回栈顶。

   **输出：**
   * WebAssembly 解释器栈顶的元素是 `15`

* **如果涉及用户常见的编程错误，请举例说明。**

   1. **类型不匹配：**  在 JavaScript 中调用 WebAssembly 函数时，如果传递的参数类型与 WebAssembly 函数期望的类型不符，会导致错误。例如，WebAssembly 函数期望一个 `i32` (32位整数)，但 JavaScript 传递了一个浮点数。这可能对应于 WebAssembly 解释器尝试处理类似 `r2r_I32Add` 但接收到错误类型的数据。

   2. **整数溢出：** WebAssembly 中的整数运算可能会溢出。例如，如果执行 `V(r2r_I32Add)` 并且两个 32 位整数的和超出了 32 位有符号整数的表示范围，结果会发生回绕。 这在 JavaScript 中可能不会直接报错，但会导致计算结果不正确。

      ```javascript
      // 假设 WebAssembly 有一个 add 函数
      // 并且我们传递了两个很大的正整数
      const result = wasmModule.exports.add(2147483647, 1); // 接近 i32 的最大值
      console.log(result); // 结果可能是 -2147483648，发生了溢出
      ```

   3. **内存访问越界：**  WebAssembly 模块可以访问其线性内存。如果 JavaScript 代码传递错误的偏移量或访问超出内存边界的地址，会导致运行时错误。这可能与 `FOREACH_LOAD_STORE_INSTR_HANDLER` 中定义的加载和存储指令相关，如果边界检查（如果启用）失败，则会抛出异常。

      ```javascript
      // 假设 wasmModule.exports.memory 是一个 ArrayBuffer
      const buffer = new Int32Array(wasmModule.exports.memory.buffer);
      const index = 1000000; // 假设这个索引超出了内存范围
      const value = buffer[index]; // 可能会导致错误
      ```

总而言之，这个头文件定义了 WebAssembly 解释器执行各种指令所需的构建块。理解这些指令及其行为对于深入了解 WebAssembly 的执行机制以及 V8 如何运行 WebAssembly 代码至关重要。

### 提示词
```
这是目录为v8/src/wasm/interpreter/instruction-handlers.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/instruction-handlers.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
\
  V(r2r_I32Eqz)                                 \
  V(r2r_I64Clz)                                 \
  V(r2r_I64Ctz)                                 \
  V(r2r_I64Popcnt)                              \
  V(r2r_I64Eqz)                                 \
  V(r2s_I32Clz)                                 \
  V(r2s_I32Ctz)                                 \
  V(r2s_I32Popcnt)                              \
  V(r2s_I32Eqz)                                 \
  V(r2s_I64Clz)                                 \
  V(r2s_I64Ctz)                                 \
  V(r2s_I64Popcnt)                              \
  V(r2s_I64Eqz)                                 \
  V(s2r_I32Clz)                                 \
  V(s2r_I32Ctz)                                 \
  V(s2r_I32Popcnt)                              \
  V(s2r_I32Eqz)                                 \
  V(s2r_I64Clz)                                 \
  V(s2r_I64Ctz)                                 \
  V(s2r_I64Popcnt)                              \
  V(s2r_I64Eqz)                                 \
  V(s2s_I32Clz)                                 \
  V(s2s_I32Ctz)                                 \
  V(s2s_I32Popcnt)                              \
  V(s2s_I32Eqz)                                 \
  V(s2s_I64Clz)                                 \
  V(s2s_I64Ctz)                                 \
  V(s2s_I64Popcnt)                              \
  V(s2s_I64Eqz)                                 \
  /* Sign extension operators. */               \
  V(r2r_I32SExtendI8)                           \
  V(r2r_I32SExtendI16)                          \
  V(r2r_I64SExtendI8)                           \
  V(r2r_I64SExtendI16)                          \
  V(r2r_I64SExtendI32)                          \
  V(r2s_I32SExtendI8)                           \
  V(r2s_I32SExtendI16)                          \
  V(r2s_I64SExtendI8)                           \
  V(r2s_I64SExtendI16)                          \
  V(r2s_I64SExtendI32)                          \
  V(s2r_I32SExtendI8)                           \
  V(s2r_I32SExtendI16)                          \
  V(s2r_I64SExtendI8)                           \
  V(s2r_I64SExtendI16)                          \
  V(s2r_I64SExtendI32)                          \
  V(s2s_I32SExtendI8)                           \
  V(s2s_I32SExtendI16)                          \
  V(s2s_I64SExtendI8)                           \
  V(s2s_I64SExtendI16)                          \
  V(s2s_I64SExtendI32)                          \
  /* Saturated truncation operators. */         \
  V(r2r_I32SConvertSatF32)                      \
  V(r2r_I32UConvertSatF32)                      \
  V(r2r_I32SConvertSatF64)                      \
  V(r2r_I32UConvertSatF64)                      \
  V(r2r_I64SConvertSatF32)                      \
  V(r2r_I64UConvertSatF32)                      \
  V(r2r_I64SConvertSatF64)                      \
  V(r2r_I64UConvertSatF64)                      \
  V(r2s_I32SConvertSatF32)                      \
  V(r2s_I32UConvertSatF32)                      \
  V(r2s_I32SConvertSatF64)                      \
  V(r2s_I32UConvertSatF64)                      \
  V(r2s_I64SConvertSatF32)                      \
  V(r2s_I64UConvertSatF32)                      \
  V(r2s_I64SConvertSatF64)                      \
  V(r2s_I64UConvertSatF64)                      \
  V(s2r_I32SConvertSatF32)                      \
  V(s2r_I32UConvertSatF32)                      \
  V(s2r_I32SConvertSatF64)                      \
  V(s2r_I32UConvertSatF64)                      \
  V(s2r_I64SConvertSatF32)                      \
  V(s2r_I64UConvertSatF32)                      \
  V(s2r_I64SConvertSatF64)                      \
  V(s2r_I64UConvertSatF64)                      \
  V(s2s_I32SConvertSatF32)                      \
  V(s2s_I32UConvertSatF32)                      \
  V(s2s_I32SConvertSatF64)                      \
  V(s2s_I32UConvertSatF64)                      \
  V(s2s_I64SConvertSatF32)                      \
  V(s2s_I64UConvertSatF32)                      \
  V(s2s_I64SConvertSatF64)                      \
  V(s2s_I64UConvertSatF64)                      \
  /* Other instruction handlers. */             \
  V(s2s_MemoryGrow)                             \
  V(s2s_MemorySize)                             \
  V(s2s_Return)                                 \
  V(s2s_Branch)                                 \
  V(r2s_BranchIf)                               \
  V(s2s_BranchIf)                               \
  V(r2s_BranchIfWithParams)                     \
  V(s2s_BranchIfWithParams)                     \
  V(r2s_If)                                     \
  V(s2s_If)                                     \
  V(s2s_Else)                                   \
  V(s2s_CallFunction)                           \
  V(s2s_ReturnCall)                             \
  V(s2s_CallImportedFunction)                   \
  V(s2s_ReturnCallImportedFunction)             \
  V(s2s_CallIndirect)                           \
  V(s2s_ReturnCallIndirect)                     \
  V(r2s_BrTable)                                \
  V(s2s_BrTable)                                \
  V(s2s_CopySlotMulti)                          \
  V(s2s_CopySlot_ll)                            \
  V(s2s_CopySlot_lq)                            \
  V(s2s_CopySlot_ql)                            \
  V(s2s_CopySlot_qq)                            \
  V(s2s_CopySlot32)                             \
  V(s2s_CopySlot32x2)                           \
  V(s2s_CopySlot64)                             \
  V(s2s_CopySlot64x2)                           \
  V(s2s_CopySlot128)                            \
  V(s2s_CopySlotRef)                            \
  V(s2s_PreserveCopySlot32)                     \
  V(s2s_PreserveCopySlot64)                     \
  V(s2s_PreserveCopySlot128)                    \
  V(s2s_PreserveCopySlotRef)                    \
  V(r2s_CopyR0ToSlot32)                         \
  V(r2s_CopyR0ToSlot64)                         \
  V(r2s_CopyFp0ToSlot32)                        \
  V(r2s_CopyFp0ToSlot64)                        \
  V(r2s_PreserveCopyR0ToSlot32)                 \
  V(r2s_PreserveCopyR0ToSlot64)                 \
  V(r2s_PreserveCopyFp0ToSlot32)                \
  V(r2s_PreserveCopyFp0ToSlot64)                \
  V(s2s_RefNull)                                \
  V(s2s_RefIsNull)                              \
  V(s2s_RefFunc)                                \
  V(s2s_RefEq)                                  \
  V(s2s_MemoryInit)                             \
  V(s2s_DataDrop)                               \
  V(s2s_MemoryCopy)                             \
  V(s2s_MemoryFill)                             \
  V(s2s_TableGet)                               \
  V(s2s_TableSet)                               \
  V(s2s_TableInit)                              \
  V(s2s_ElemDrop)                               \
  V(s2s_TableCopy)                              \
  V(s2s_TableGrow)                              \
  V(s2s_TableSize)                              \
  V(s2s_TableFill)                              \
  V(s2s_Unreachable)                            \
  V(s2s_Unwind)                                 \
  V(s2s_OnLoopBackwardJump)                     \
  V(s2s_Nop)                                    \
  /* Exception handling */                      \
  V(s2s_Throw)                                  \
  V(s2s_Rethrow)                                \
  V(s2s_Catch)                                  \
  /* Atomics */                                 \
  V(s2s_AtomicNotify)                           \
  V(s2s_I32AtomicWait)                          \
  V(s2s_I64AtomicWait)                          \
  V(s2s_AtomicFence)                            \
  V(s2s_I32AtomicAdd)                           \
  V(s2s_I32AtomicAdd8U)                         \
  V(s2s_I32AtomicAdd16U)                        \
  V(s2s_I32AtomicSub)                           \
  V(s2s_I32AtomicSub8U)                         \
  V(s2s_I32AtomicSub16U)                        \
  V(s2s_I32AtomicAnd)                           \
  V(s2s_I32AtomicAnd8U)                         \
  V(s2s_I32AtomicAnd16U)                        \
  V(s2s_I32AtomicOr)                            \
  V(s2s_I32AtomicOr8U)                          \
  V(s2s_I32AtomicOr16U)                         \
  V(s2s_I32AtomicXor)                           \
  V(s2s_I32AtomicXor8U)                         \
  V(s2s_I32AtomicXor16U)                        \
  V(s2s_I32AtomicExchange)                      \
  V(s2s_I32AtomicExchange8U)                    \
  V(s2s_I32AtomicExchange16U)                   \
  V(s2s_I64AtomicAdd)                           \
  V(s2s_I64AtomicAdd8U)                         \
  V(s2s_I64AtomicAdd16U)                        \
  V(s2s_I64AtomicAdd32U)                        \
  V(s2s_I64AtomicSub)                           \
  V(s2s_I64AtomicSub8U)                         \
  V(s2s_I64AtomicSub16U)                        \
  V(s2s_I64AtomicSub32U)                        \
  V(s2s_I64AtomicAnd)                           \
  V(s2s_I64AtomicAnd8U)                         \
  V(s2s_I64AtomicAnd16U)                        \
  V(s2s_I64AtomicAnd32U)                        \
  V(s2s_I64AtomicOr)                            \
  V(s2s_I64AtomicOr8U)                          \
  V(s2s_I64AtomicOr16U)                         \
  V(s2s_I64AtomicOr32U)                         \
  V(s2s_I64AtomicXor)                           \
  V(s2s_I64AtomicXor8U)                         \
  V(s2s_I64AtomicXor16U)                        \
  V(s2s_I64AtomicXor32U)                        \
  V(s2s_I64AtomicExchange)                      \
  V(s2s_I64AtomicExchange8U)                    \
  V(s2s_I64AtomicExchange16U)                   \
  V(s2s_I64AtomicExchange32U)                   \
  V(s2s_I32AtomicCompareExchange)               \
  V(s2s_I32AtomicCompareExchange8U)             \
  V(s2s_I32AtomicCompareExchange16U)            \
  V(s2s_I64AtomicCompareExchange)               \
  V(s2s_I64AtomicCompareExchange8U)             \
  V(s2s_I64AtomicCompareExchange16U)            \
  V(s2s_I64AtomicCompareExchange32U)            \
  V(s2s_I32AtomicLoad)                          \
  V(s2s_I32AtomicLoad8U)                        \
  V(s2s_I32AtomicLoad16U)                       \
  V(s2s_I64AtomicLoad)                          \
  V(s2s_I64AtomicLoad8U)                        \
  V(s2s_I64AtomicLoad16U)                       \
  V(s2s_I64AtomicLoad32U)                       \
  V(s2s_I32AtomicStore)                         \
  V(s2s_I32AtomicStore8U)                       \
  V(s2s_I32AtomicStore16U)                      \
  V(s2s_I64AtomicStore)                         \
  V(s2s_I64AtomicStore8U)                       \
  V(s2s_I64AtomicStore16U)                      \
  V(s2s_I64AtomicStore32U)                      \
  /* SIMD */                                    \
  V(s2s_SimdF64x2Splat)                         \
  V(s2s_SimdF32x4Splat)                         \
  V(s2s_SimdI64x2Splat)                         \
  V(s2s_SimdI32x4Splat)                         \
  V(s2s_SimdI16x8Splat)                         \
  V(s2s_SimdI8x16Splat)                         \
  V(s2s_SimdF64x2ExtractLane)                   \
  V(s2s_SimdF32x4ExtractLane)                   \
  V(s2s_SimdI64x2ExtractLane)                   \
  V(s2s_SimdI32x4ExtractLane)                   \
  V(s2s_SimdI16x8ExtractLaneS)                  \
  V(s2s_SimdI16x8ExtractLaneU)                  \
  V(s2s_SimdI8x16ExtractLaneS)                  \
  V(s2s_SimdI8x16ExtractLaneU)                  \
  V(s2s_SimdF64x2Add)                           \
  V(s2s_SimdF64x2Sub)                           \
  V(s2s_SimdF64x2Mul)                           \
  V(s2s_SimdF64x2Div)                           \
  V(s2s_SimdF64x2Min)                           \
  V(s2s_SimdF64x2Max)                           \
  V(s2s_SimdF64x2Pmin)                          \
  V(s2s_SimdF64x2Pmax)                          \
  V(s2s_SimdF32x4RelaxedMin)                    \
  V(s2s_SimdF32x4RelaxedMax)                    \
  V(s2s_SimdF64x2RelaxedMin)                    \
  V(s2s_SimdF64x2RelaxedMax)                    \
  V(s2s_SimdF32x4Add)                           \
  V(s2s_SimdF32x4Sub)                           \
  V(s2s_SimdF32x4Mul)                           \
  V(s2s_SimdF32x4Div)                           \
  V(s2s_SimdF32x4Min)                           \
  V(s2s_SimdF32x4Max)                           \
  V(s2s_SimdF32x4Pmin)                          \
  V(s2s_SimdF32x4Pmax)                          \
  V(s2s_SimdI64x2Add)                           \
  V(s2s_SimdI64x2Sub)                           \
  V(s2s_SimdI64x2Mul)                           \
  V(s2s_SimdI32x4Add)                           \
  V(s2s_SimdI32x4Sub)                           \
  V(s2s_SimdI32x4Mul)                           \
  V(s2s_SimdI32x4MinS)                          \
  V(s2s_SimdI32x4MinU)                          \
  V(s2s_SimdI32x4MaxS)                          \
  V(s2s_SimdI32x4MaxU)                          \
  V(s2s_SimdS128And)                            \
  V(s2s_SimdS128Or)                             \
  V(s2s_SimdS128Xor)                            \
  V(s2s_SimdS128AndNot)                         \
  V(s2s_SimdI16x8Add)                           \
  V(s2s_SimdI16x8Sub)                           \
  V(s2s_SimdI16x8Mul)                           \
  V(s2s_SimdI16x8MinS)                          \
  V(s2s_SimdI16x8MinU)                          \
  V(s2s_SimdI16x8MaxS)                          \
  V(s2s_SimdI16x8MaxU)                          \
  V(s2s_SimdI16x8AddSatS)                       \
  V(s2s_SimdI16x8AddSatU)                       \
  V(s2s_SimdI16x8SubSatS)                       \
  V(s2s_SimdI16x8SubSatU)                       \
  V(s2s_SimdI16x8RoundingAverageU)              \
  V(s2s_SimdI16x8Q15MulRSatS)                   \
  V(s2s_SimdI16x8RelaxedQ15MulRS)               \
  V(s2s_SimdI8x16Add)                           \
  V(s2s_SimdI8x16Sub)                           \
  V(s2s_SimdI8x16MinS)                          \
  V(s2s_SimdI8x16MinU)                          \
  V(s2s_SimdI8x16MaxS)                          \
  V(s2s_SimdI8x16MaxU)                          \
  V(s2s_SimdI8x16AddSatS)                       \
  V(s2s_SimdI8x16AddSatU)                       \
  V(s2s_SimdI8x16SubSatS)                       \
  V(s2s_SimdI8x16SubSatU)                       \
  V(s2s_SimdI8x16RoundingAverageU)              \
  V(s2s_SimdF64x2Abs)                           \
  V(s2s_SimdF64x2Neg)                           \
  V(s2s_SimdF64x2Sqrt)                          \
  V(s2s_SimdF64x2Ceil)                          \
  V(s2s_SimdF64x2Floor)                         \
  V(s2s_SimdF64x2Trunc)                         \
  V(s2s_SimdF64x2NearestInt)                    \
  V(s2s_SimdF32x4Abs)                           \
  V(s2s_SimdF32x4Neg)                           \
  V(s2s_SimdF32x4Sqrt)                          \
  V(s2s_SimdF32x4Ceil)                          \
  V(s2s_SimdF32x4Floor)                         \
  V(s2s_SimdF32x4Trunc)                         \
  V(s2s_SimdF32x4NearestInt)                    \
  V(s2s_SimdI64x2Neg)                           \
  V(s2s_SimdI32x4Neg)                           \
  V(s2s_SimdI64x2Abs)                           \
  V(s2s_SimdI32x4Abs)                           \
  V(s2s_SimdS128Not)                            \
  V(s2s_SimdI16x8Neg)                           \
  V(s2s_SimdI16x8Abs)                           \
  V(s2s_SimdI8x16Neg)                           \
  V(s2s_SimdI8x16Abs)                           \
  V(s2s_SimdI8x16Popcnt)                        \
  V(s2s_SimdI8x16BitMask)                       \
  V(s2s_SimdI16x8BitMask)                       \
  V(s2s_SimdI32x4BitMask)                       \
  V(s2s_SimdI64x2BitMask)                       \
  V(s2s_SimdF64x2Eq)                            \
  V(s2s_SimdF64x2Ne)                            \
  V(s2s_SimdF64x2Gt)                            \
  V(s2s_SimdF64x2Ge)                            \
  V(s2s_SimdF64x2Lt)                            \
  V(s2s_SimdF64x2Le)                            \
  V(s2s_SimdF32x4Eq)                            \
  V(s2s_SimdF32x4Ne)                            \
  V(s2s_SimdF32x4Gt)                            \
  V(s2s_SimdF32x4Ge)                            \
  V(s2s_SimdF32x4Lt)                            \
  V(s2s_SimdF32x4Le)                            \
  V(s2s_SimdI64x2Eq)                            \
  V(s2s_SimdI64x2Ne)                            \
  V(s2s_SimdI64x2LtS)                           \
  V(s2s_SimdI64x2GtS)                           \
  V(s2s_SimdI64x2LeS)                           \
  V(s2s_SimdI64x2GeS)                           \
  V(s2s_SimdI32x4Eq)                            \
  V(s2s_SimdI32x4Ne)                            \
  V(s2s_SimdI32x4GtS)                           \
  V(s2s_SimdI32x4GeS)                           \
  V(s2s_SimdI32x4LtS)                           \
  V(s2s_SimdI32x4LeS)                           \
  V(s2s_SimdI32x4GtU)                           \
  V(s2s_SimdI32x4GeU)                           \
  V(s2s_SimdI32x4LtU)                           \
  V(s2s_SimdI32x4LeU)                           \
  V(s2s_SimdI16x8Eq)                            \
  V(s2s_SimdI16x8Ne)                            \
  V(s2s_SimdI16x8GtS)                           \
  V(s2s_SimdI16x8GeS)                           \
  V(s2s_SimdI16x8LtS)                           \
  V(s2s_SimdI16x8LeS)                           \
  V(s2s_SimdI16x8GtU)                           \
  V(s2s_SimdI16x8GeU)                           \
  V(s2s_SimdI16x8LtU)                           \
  V(s2s_SimdI16x8LeU)                           \
  V(s2s_SimdI8x16Eq)                            \
  V(s2s_SimdI8x16Ne)                            \
  V(s2s_SimdI8x16GtS)                           \
  V(s2s_SimdI8x16GeS)                           \
  V(s2s_SimdI8x16LtS)                           \
  V(s2s_SimdI8x16LeS)                           \
  V(s2s_SimdI8x16GtU)                           \
  V(s2s_SimdI8x16GeU)                           \
  V(s2s_SimdI8x16LtU)                           \
  V(s2s_SimdI8x16LeU)                           \
  V(s2s_SimdF64x2ReplaceLane)                   \
  V(s2s_SimdF32x4ReplaceLane)                   \
  V(s2s_SimdI64x2ReplaceLane)                   \
  V(s2s_SimdI32x4ReplaceLane)                   \
  V(s2s_SimdI16x8ReplaceLane)                   \
  V(s2s_SimdI8x16ReplaceLane)                   \
  V(s2s_SimdS128LoadMem)                        \
  V(s2s_SimdS128StoreMem)                       \
  V(s2s_SimdI64x2Shl)                           \
  V(s2s_SimdI64x2ShrS)                          \
  V(s2s_SimdI64x2ShrU)                          \
  V(s2s_SimdI32x4Shl)                           \
  V(s2s_SimdI32x4ShrS)                          \
  V(s2s_SimdI32x4ShrU)                          \
  V(s2s_SimdI16x8Shl)                           \
  V(s2s_SimdI16x8ShrS)                          \
  V(s2s_SimdI16x8ShrU)                          \
  V(s2s_SimdI8x16Shl)                           \
  V(s2s_SimdI8x16ShrS)                          \
  V(s2s_SimdI8x16ShrU)                          \
  V(s2s_SimdI16x8ExtMulLowI8x16S)               \
  V(s2s_SimdI16x8ExtMulHighI8x16S)              \
  V(s2s_SimdI16x8ExtMulLowI8x16U)               \
  V(s2s_SimdI16x8ExtMulHighI8x16U)              \
  V(s2s_SimdI32x4ExtMulLowI16x8S)               \
  V(s2s_SimdI32x4ExtMulHighI16x8S)              \
  V(s2s_SimdI32x4ExtMulLowI16x8U)               \
  V(s2s_SimdI32x4ExtMulHighI16x8U)              \
  V(s2s_SimdI64x2ExtMulLowI32x4S)               \
  V(s2s_SimdI64x2ExtMulHighI32x4S)              \
  V(s2s_SimdI64x2ExtMulLowI32x4U)               \
  V(s2s_SimdI64x2ExtMulHighI32x4U)              \
  V(s2s_SimdF32x4SConvertI32x4)                 \
  V(s2s_SimdF32x4UConvertI32x4)                 \
  V(s2s_SimdI32x4SConvertF32x4)                 \
  V(s2s_SimdI32x4UConvertF32x4)                 \
  V(s2s_SimdI32x4RelaxedTruncF32x4S)            \
  V(s2s_SimdI32x4RelaxedTruncF32x4U)            \
  V(s2s_SimdI64x2SConvertI32x4Low)              \
  V(s2s_SimdI64x2SConvertI32x4High)             \
  V(s2s_SimdI64x2UConvertI32x4Low)              \
  V(s2s_SimdI64x2UConvertI32x4High)             \
  V(s2s_SimdI32x4SConvertI16x8High)             \
  V(s2s_SimdI32x4UConvertI16x8High)             \
  V(s2s_SimdI32x4SConvertI16x8Low)              \
  V(s2s_SimdI32x4UConvertI16x8Low)              \
  V(s2s_SimdI16x8SConvertI8x16High)             \
  V(s2s_SimdI16x8UConvertI8x16High)             \
  V(s2s_SimdI16x8SConvertI8x16Low)              \
  V(s2s_SimdI16x8UConvertI8x16Low)              \
  V(s2s_SimdF64x2ConvertLowI32x4S)              \
  V(s2s_SimdF64x2ConvertLowI32x4U)              \
  V(s2s_SimdI32x4TruncSatF64x2SZero)            \
  V(s2s_SimdI32x4TruncSatF64x2UZero)            \
  V(s2s_SimdI32x4RelaxedTruncF64x2SZero)        \
  V(s2s_SimdI32x4RelaxedTruncF64x2UZero)        \
  V(s2s_SimdF32x4DemoteF64x2Zero)               \
  V(s2s_SimdF64x2PromoteLowF32x4)               \
  V(s2s_SimdI16x8SConvertI32x4)                 \
  V(s2s_SimdI16x8UConvertI32x4)                 \
  V(s2s_SimdI8x16SConvertI16x8)                 \
  V(s2s_SimdI8x16UConvertI16x8)                 \
  V(s2s_SimdI8x16RelaxedLaneSelect)             \
  V(s2s_SimdI16x8RelaxedLaneSelect)             \
  V(s2s_SimdI32x4RelaxedLaneSelect)             \
  V(s2s_SimdI64x2RelaxedLaneSelect)             \
  V(s2s_SimdS128Select)                         \
  V(s2s_SimdI32x4DotI16x8S)                     \
  V(s2s_SimdI16x8DotI8x16I7x16S)                \
  V(s2s_SimdI32x4DotI8x16I7x16AddS)             \
  V(s2s_SimdI8x16RelaxedSwizzle)                \
  V(s2s_SimdI8x16Swizzle)                       \
  V(s2s_SimdV128AnyTrue)                        \
  V(s2s_SimdI8x16Shuffle)                       \
  V(s2s_SimdI64x2AllTrue)                       \
  V(s2s_SimdI32x4AllTrue)                       \
  V(s2s_SimdI16x8AllTrue)                       \
  V(s2s_SimdI8x16AllTrue)                       \
  V(s2s_SimdF32x4Qfma)                          \
  V(s2s_SimdF32x4Qfms)                          \
  V(s2s_SimdF64x2Qfma)                          \
  V(s2s_SimdF64x2Qfms)                          \
  V(s2s_SimdS128Load8Splat)                     \
  V(s2s_SimdS128Load16Splat)                    \
  V(s2s_SimdS128Load32Splat)                    \
  V(s2s_SimdS128Load64Splat)                    \
  V(s2s_SimdS128Load8x8S)                       \
  V(s2s_SimdS128Load8x8U)                       \
  V(s2s_SimdS128Load16x4S)                      \
  V(s2s_SimdS128Load16x4U)                      \
  V(s2s_SimdS128Load32x2S)                      \
  V(s2s_SimdS128Load32x2U)                      \
  V(s2s_SimdS128Load32Zero)                     \
  V(s2s_SimdS128Load64Zero)                     \
  V(s2s_SimdS128Load8Lane)                      \
  V(s2s_SimdS128Load16Lane)                     \
  V(s2s_SimdS128Load32Lane)                     \
  V(s2s_SimdS128Load64Lane)                     \
  V(s2s_SimdS128Store8Lane)                     \
  V(s2s_SimdS128Store16Lane)                    \
  V(s2s_SimdS128Store32Lane)                    \
  V(s2s_SimdS128Store64Lane)                    \
  V(s2s_SimdI32x4ExtAddPairwiseI16x8S)          \
  V(s2s_SimdI32x4ExtAddPairwiseI16x8U)          \
  V(s2s_SimdI16x8ExtAddPairwiseI8x16S)          \
  V(s2s_SimdI16x8ExtAddPairwiseI8x16U)          \
  /* GC */                                      \
  V(s2s_BranchOnNull)                           \
  V(s2s_BranchOnNullWithParams)                 \
  V(s2s_BranchOnNonNull)                        \
  V(s2s_BranchOnNonNullWithParams)              \
  V(s2s_BranchOnCast)                           \
  V(s2s_BranchOnCastFail)                       \
  V(s2s_StructNew)                              \
  V(s2s_StructNewDefault)                       \
  V(s2s_I8SStructGet)                           \
  V(s2s_I8UStructGet)                           \
  V(s2s_I16SStructGet)                          \
  V(s2s_I16UStructGet)                          \
  V(s2s_I32StructGet)                           \
  V(s2s_I64StructGet)                           \
  V(s2s_F32StructGet)                           \
  V(s2s_F64StructGet)                           \
  V(s2s_S128StructGet)                          \
  V(s2s_RefStructGet)                           \
  V(s2s_I8StructSet)                            \
  V(s2s_I16StructSet)                           \
  V(s2s_I32StructSet)                           \
  V(s2s_I64StructSet)                           \
  V(s2s_F32StructSet)                           \
  V(s2s_F64StructSet)                           \
  V(s2s_S128StructSet)                          \
  V(s2s_RefStructSet)                           \
  V(s2s_I8ArrayNew)                             \
  V(s2s_I16ArrayNew)                            \
  V(s2s_I32ArrayNew)                            \
  V(s2s_I64ArrayNew)                            \
  V(s2s_F32ArrayNew)                            \
  V(s2s_F64ArrayNew)                            \
  V(s2s_S128ArrayNew)                           \
  V(s2s_RefArrayNew)                            \
  V(s2s_ArrayNewDefault)                        \
  V(s2s_ArrayNewFixed)                          \
  V(s2s_ArrayNewData)                           \
  V(s2s_ArrayNewElem)                           \
  V(s2s_ArrayInitData)                          \
  V(s2s_ArrayInitElem)                          \
  V(s2s_ArrayLen)                               \
  V(s2s_ArrayCopy)                              \
  V(s2s_I8SArrayGet)                            \
  V(s2s_I8UArrayGet)                            \
  V(s2s_I16SArrayGet)                           \
  V(s2s_I16UArrayGet)                           \
  V(s2s_I32ArrayGet)                            \
  V(s2s_I64ArrayGet)                            \
  V(s2s_F32ArrayGet)                            \
  V(s2s_F64ArrayGet)                            \
  V(s2s_S128ArrayGet)                           \
  V(s2s_RefArrayGet)                            \
  V(s2s_I8ArraySet)                             \
  V(s2s_I16ArraySet)                            \
  V(s2s_I32ArraySet)                            \
  V(s2s_I64ArraySet)                            \
  V(s2s_F32ArraySet)                            \
  V(s2s_F64ArraySet)                            \
  V(s2s_S128ArraySet)                           \
  V(s2s_RefArraySet)                            \
  V(s2s_I8ArrayFill)                            \
  V(s2s_I16ArrayFill)                           \
  V(s2s_I32ArrayFill)                           \
  V(s2s_I64ArrayFill)                           \
  V(s2s_F32ArrayFill)                           \
  V(s2s_F64ArrayFill)                           \
  V(s2s_S128ArrayFill)                          \
  V(s2s_RefArrayFill)                           \
  V(s2s_RefI31)                                 \
  V(s2s_I31GetS)                                \
  V(s2s_I31GetU)                                \
  V(s2s_RefCast)                                \
  V(s2s_RefCastNull)                            \
  V(s2s_RefTest)                                \
  V(s2s_RefTestNull)                            \
  V(s2s_RefAsNonNull)                           \
  V(s2s_CallRef)                                \
  V(s2s_ReturnCallRef)                          \
  V(s2s_AnyConvertExtern)                       \
  V(s2s_ExternConvertAny)                       \
  V(s2s_AssertNullTypecheck)                    \
  V(s2s_AssertNotNullTypecheck)                 \
  V(s2s_TrapIllegalCast)                        \
  V(s2s_RefTestSucceeds)                        \
  V(s2s_RefTestFails)                           \
  V(s2s_RefIsNonNull)

#ifdef V8_DRUMBRAKE_BOUNDS_CHECKS
#define FOREACH_INSTR_HANDLER(V)                 \
  FOREACH_LOAD_STORE_INSTR_HANDLER(V)            \
  FOREACH_LOAD_STORE_DUPLICATED_INSTR_HANDLER(V) \
  FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER(V)
#else
#define FOREACH_INSTR_HANDLER(V)      \
  FOREACH_LOAD_STORE_INSTR_HANDLER(V) \
  FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER(V)
#endif  // V8_DRUMBRAKE_BOUNDS_CHECKS

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
#define FOREACH_TRACE_INSTR_HANDLER(V) \
  /* Tracing instruction handlers. */  \
  V(s2s_TraceInstruction)              \
  V(trace_UpdateStack)                 \
  V(trace_PushConstI32Slot)            \
  V(trace_PushConstI64Slot)            \
  V(trace_PushConstF32Slot)            \
  V(trace_PushConstF64Slot)            \
  V(trace_PushConstS128Slot)           \
  V(trace_PushConstRefSlot)            \
  V(trace_PushCopySlot)                \
  V(trace_PopSlot)                     \
  V(trace_SetSlotType)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

#endif  // V8_WASM_INTERPRETER_INSTRUCTION_HANDLERS_H_
```