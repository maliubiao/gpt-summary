Response:
The user wants a summary of the functionality of the provided C++ code snippet. The snippet defines several C preprocessor macros for generating S390 assembly code related to atomic operations.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Theme:** The macros all start with `ASSEMBLE_ATOMIC` or `ATOMIC_BIN_OP`. This strongly suggests the code is about implementing atomic operations.

2. **Analyze Individual Macros:** Go through each macro and understand its purpose based on the assembly instructions being generated.

    * `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_UINT8`:  This macro generates code for an atomic compare-and-exchange operation on a byte. It uses the `AtomicCmpExchangeU8` instruction. The `load_and_ext` part indicates it likely loads the old value and extends it (possibly zero-extends).

    * `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD`: Similar to the byte version, but for a half-word (2 bytes). It uses `AtomicCmpExchangeU16`. The `is_wasm_on_be(info())` conditional suggests special handling for WebAssembly on big-endian systems, involving byte swapping (`lrvr`) and shifting.

    * `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_WORD`: Handles atomic compare-and-exchange for a full word (4 bytes). It uses `CmpAndSwap`. Big-endian handling is present here too.

    * `ASSEMBLE_ATOMIC_BINOP_WORD`: This macro deals with atomic binary operations on words. It loads a value, performs an operation (`op`), and then uses `CmpAndSwap` to atomically update the memory location. The `is_wasm_on_be(info())` block again points to big-endian WebAssembly considerations, with explicit loading and storing of swapped bytes.

    * `ASSEMBLE_ATOMIC_BINOP_WORD64`: Similar to the word version, but operates on 64-bit values, using `CmpAndSwap64` and `lrvgr` (load reversed general register).

    * `ATOMIC_BIN_OP`: This appears to be a more general macro used by the byte and half-word binary operation macros. It involves loading a previous value, performing a binary operation using bit manipulation (`RotateInsertSelectBits`), and then atomically updating the memory with `CmpAndSwap`. The `reverse_bytes` logic is prominent.

    * `ATOMIC_BIN_OP_HALFWORD` and `ATOMIC_BIN_OP_BYTE`: These specialize `ATOMIC_BIN_OP` for half-word and byte operations, respectively. They calculate offsets and bit shifts based on the index, likely for operating on individual bytes or half-words within a larger word. The endianness is handled here with the conditional compilation based on `V8_TARGET_BIG_ENDIAN`.

    * `ASSEMBLE_ATOMIC_BINOP_HALFWORD`: This macro handles atomic binary operations on half-words, considering potential alignment issues (word boundary vs. half-word boundary) using `tmll` (test under mask logical long).

    * `ASSEMBLE_ATOMIC_BINOP_BYTE`: Handles atomic binary operations on bytes, also considering alignment (word, half-word, and byte boundaries).

    * `ASSEMBLE_ATOMIC64_COMP_EXCHANGE_WORD64`:  Similar to the 32-bit word compare-and-exchange, but for 64-bit values.

3. **Identify Common Patterns and Concepts:**

    * **Atomic Operations:** The central theme. These operations ensure that a sequence of instructions completes without interference from other threads or processes.
    * **Compare-and-Exchange (CAS):**  Many macros use `CmpAndSwap` or `AtomicCmpExchangeU*`, which are fundamental atomic primitives.
    * **Binary Operations:**  Macros like `ASSEMBLE_ATOMIC_BINOP_...` perform arithmetic or logical operations atomically.
    * **Memory Operands:**  The `MemOperand` class is used to specify the memory location for atomic operations.
    * **Endianness Handling:**  The frequent checks for `is_wasm_on_be(info())` and the byte-swapping instructions (`lrvr`, `lrvgr`) highlight the need to handle big-endian architectures correctly, especially for WebAssembly.
    * **Alignment:** Macros like `ASSEMBLE_ATOMIC_BINOP_HALFWORD` and `ASSEMBLE_ATOMIC_BINOP_BYTE` demonstrate awareness of memory alignment requirements and handle cases where the target data spans word or half-word boundaries.
    * **Scratch Registers:** The use of `kScratchReg`, `r0`, and `r1` as temporary registers is common in assembly code generation.

4. **Formulate the Summary:** Combine the observations into a concise summary, highlighting the key functionalities and the context within which this code operates (V8 compiler backend for the S390 architecture).

5. **Address Specific User Queries (from the initial prompt):**

    * **Functionality:**  Clearly state the macros' purpose in generating assembly for atomic operations.
    * **Torque:**  Explicitly state that the code is C++ and not Torque.
    * **JavaScript Relation:** Explain the connection to concurrency and atomicity in JavaScript, and provide a JavaScript example using `Atomics`.
    * **Code Logic Inference:**  Give a simplified example of a compare-and-exchange operation with assumed inputs and outputs.
    * **Common Programming Errors:**  Provide examples of common mistakes when dealing with atomics, like incorrect usage, race conditions, and ignoring return values.
    * **Overall Function:** This will be the main summary requested in this part.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive and accurate summary that addresses the user's request.
这是 V8 源代码 `v8/src/compiler/backend/s390/code-generator-s390.cc` 的一部分，定义了一些 C++ 宏，用于生成 S390 架构的汇编代码，以实现原子操作。

**功能归纳:**

这部分代码定义了一系列宏，这些宏的主要功能是为 S390 架构生成执行原子操作的汇编代码。原子操作是指在多线程或并发环境下，能够不被其他操作中断的不可分割的操作。这些宏涵盖了以下类型的原子操作：

* **原子比较并交换 (Compare and Exchange - CAS):**  用于原子地比较一个内存位置的值与预期值，如果相等则将该内存位置的值更新为新值。这包括针对字节 (`U8`)、半字 (`U16`) 和字 (`U32`, `U64`) 的操作。
* **原子二元运算:** 用于原子地对内存中的值执行二元运算（如加法、减法、位运算等）。这包括针对字 (`WORD`)、64 位字 (`WORD64`)、半字和字节的操作。

**更详细的功能解释:**

* **`ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_UINT8(load_and_ext)`:**  生成原子比较并交换一个字节的汇编代码。它接收一个加载并扩展字节的宏 (`load_and_ext`) 作为参数。
* **`ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(load_and_ext)`:** 生成原子比较并交换一个半字的汇编代码。它也处理了在 big-endian 系统上 WebAssembly 的特殊情况，需要进行字节交换。
* **`ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_WORD()`:** 生成原子比较并交换一个字的汇编代码，同样考虑了 big-endian 系统上的 WebAssembly。
* **`ASSEMBLE_ATOMIC_BINOP_WORD(load_and_op, op)`:** 生成原子二元运算（针对字）的汇编代码。它接收一个加载并执行操作的宏 (`load_and_op`) 和一个二元操作符 (`op`) 作为参数。针对 big-endian 系统的 WebAssembly 做了特殊处理。
* **`ASSEMBLE_ATOMIC_BINOP_WORD64(load_and_op, op)`:** 生成原子二元运算（针对 64 位字）的汇编代码，同样处理了 big-endian 系统上的 WebAssembly。
* **`ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end, maybe_reverse_bytes)`:**  这是一个更通用的宏，用于生成原子二元运算的汇编代码，可以处理字节序反转的情况。
* **`ATOMIC_BIN_OP_HALFWORD(bin_inst, index, extract_result)` 和 `ATOMIC_BIN_OP_BYTE(bin_inst, index, extract_result)`:**  基于 `ATOMIC_BIN_OP` 宏，分别用于生成原子二元运算（针对半字和字节）的汇编代码。它们考虑了字节序，并根据字节在字中的索引计算偏移量和位移量。
* **`ASSEMBLE_ATOMIC_BINOP_HALFWORD(bin_inst, extract_result)` 和 `ASSEMBLE_ATOMIC_BINOP_BYTE(bin_inst, extract_result)`:**  生成原子二元运算（针对半字和字节）的汇编代码，并处理了可能出现的内存对齐问题，即操作数可能跨越字边界。
* **`ASSEMBLE_ATOMIC64_COMP_EXCHANGE_WORD64()`:** 生成原子比较并交换一个 64 位字的汇编代码，同样考虑了 big-endian 系统上的 WebAssembly。

**关于源代码类型和 JavaScript 关系:**

* **`.tq 结尾`:**  代码以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 v8 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。
* **JavaScript 关系:** 这些宏生成的原子操作汇编代码与 JavaScript 的并发特性密切相关。JavaScript 中可以使用 `Atomics` 对象来进行原子操作，以实现线程安全的共享内存。

**JavaScript 举例说明:**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const view = new Int32Array(sab);

// 模拟两个线程同时尝试更新 view[0]

// 线程 1
Atomics.add(view, 0, 5); // 原子地将 view[0] 的值加上 5

// 线程 2
Atomics.compareExchange(view, 0, 10, 15); // 原子地比较 view[0] 的值是否为 10，如果是则设置为 15
```

在上述 JavaScript 代码中，`Atomics.add` 和 `Atomics.compareExchange` 等方法需要在底层通过高效的原子操作来实现，而 `code-generator-s390.cc` 中的这些宏正是为了在 S390 架构上生成实现这些原子操作的机器码。

**代码逻辑推理 (以 `ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_UINT8` 为例):**

**假设输入:**

* `i.InputRegister(0)` (old_value):  寄存器 `r2` 包含期望的旧值，例如 `0xA0`。
* `i.InputRegister(1)` (new_value):  寄存器 `r3` 包含要写入的新值，例如 `0xB0`。
* 内存地址 `op` 指向的内存位置的值为 `0xA0`。

**输出:**

* `i.OutputRegister()` (output): 寄存器，将包含内存位置的原始值。
* 内存地址 `op` 指向的内存位置的值将被更新为 `0xB0`。

**生成的汇编代码逻辑 (简化):**

1. 将内存地址 `op` 加载到 `kScratchReg` 寄存器 (`lay addr, op`)。
2. 执行原子比较并交换操作：比较 `kScratchReg` 指向的内存地址的值与 `old_value` (`r2`)，如果相等，则将 `new_value` (`r3`) 写入该内存地址，并将该内存地址的原始值加载到 `output` 寄存器。
3. 将 `output` 寄存器中的字节值加载并扩展（`load_and_ext`）。

**用户常见的编程错误 (与原子操作相关):**

1. **没有正确使用原子操作:**  在多线程环境下更新共享变量时，如果没有使用原子操作，可能导致数据竞争和不一致的结果。

   ```javascript
   // 错误示例 (非原子操作)
   let counter = 0;
   function increment() {
     counter++; // 多个线程同时执行可能导致 counter 的值不正确
   }

   // 正确示例 (使用原子操作)
   const sab = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
   function incrementAtomic() {
     Atomics.add(sab, 0, 1); // 原子地增加 sab[0] 的值
   }
   ```

2. **错误的比较值 (在 CAS 操作中):**  在使用 CAS 操作时，如果提供的期望旧值与内存中的实际值不符，更新操作将失败。开发者需要理解 CAS 操作的语义，并在必要时进行重试。

   ```javascript
   const sab = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
   sab[0] = 5;

   // 假设在某个时刻，另一个线程将 sab[0] 的值修改为 7

   // 当前线程尝试使用 CAS
   const oldValue = 5; // 假设当前线程认为旧值是 5
   const newValue = 10;
   const success = Atomics.compareExchange(sab, 0, oldValue, newValue);
   console.log(success); // 输出 false，因为实际的旧值是 7，不是 5
   ```

3. **死锁和活锁:** 虽然原子操作可以避免数据竞争，但如果使用不当，仍然可能导致死锁或活锁等并发问题。例如，多个线程尝试以相反的顺序获取锁，可能导致死锁。

总而言之，这部分 `code-generator-s390.cc` 代码的核心功能是为 V8 引擎在 S390 架构上执行原子操作提供底层的汇编代码生成支持，这对于实现 JavaScript 的并发特性至关重要。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/code-generator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
.InputRegister(1);                                  \
    Register output = i.OutputRegister();                                     \
    Register addr = kScratchReg;                                              \
    Register temp0 = r0;                                                      \
    Register temp1 = r1;                                                      \
    size_t index = 2;                                                         \
    AddressingMode mode = kMode_None;                                         \
    MemOperand op = i.MemoryOperand(&mode, &index);                           \
    __ lay(addr, op);                                                         \
    __ AtomicCmpExchangeU8(addr, output, old_value, new_value, temp0, temp1); \
    __ load_and_ext(output, output);                                          \
  } while (false)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(load_and_ext)           \
  do {                                                                    \
    Register old_value = i.InputRegister(0);                              \
    Register new_value = i.InputRegister(1);                              \
    Register output = i.OutputRegister();                                 \
    Register addr = kScratchReg;                                          \
    Register temp0 = r0;                                                  \
    Register temp1 = r1;                                                  \
    size_t index = 2;                                                     \
    AddressingMode mode = kMode_None;                                     \
    MemOperand op = i.MemoryOperand(&mode, &index);                       \
    __ lay(addr, op);                                                     \
    if (is_wasm_on_be(info())) {                                          \
      Register temp2 =                                                    \
          GetRegisterThatIsNotOneOf(output, old_value, new_value);        \
      Register temp3 =                                                    \
          GetRegisterThatIsNotOneOf(output, old_value, new_value, temp2); \
      __ Push(temp2, temp3);                                              \
      __ lrvr(temp2, old_value);                                          \
      __ lrvr(temp3, new_value);                                          \
      __ ShiftRightU32(temp2, temp2, Operand(16));                        \
      __ ShiftRightU32(temp3, temp3, Operand(16));                        \
      __ AtomicCmpExchangeU16(addr, output, temp2, temp3, temp0, temp1);  \
      __ lrvr(output, output);                                            \
      __ ShiftRightU32(output, output, Operand(16));                      \
      __ Pop(temp2, temp3);                                               \
    } else {                                                              \
      __ AtomicCmpExchangeU16(addr, output, old_value, new_value, temp0,  \
                              temp1);                                     \
    }                                                                     \
    __ load_and_ext(output, output);                                      \
  } while (false)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_WORD()         \
  do {                                                  \
    Register new_val = i.InputRegister(1);              \
    Register output = i.OutputRegister();               \
    Register addr = kScratchReg;                        \
    size_t index = 2;                                   \
    AddressingMode mode = kMode_None;                   \
    MemOperand op = i.MemoryOperand(&mode, &index);     \
    __ lay(addr, op);                                   \
    if (is_wasm_on_be(info())) {                        \
      __ lrvr(r0, output);                              \
      __ lrvr(r1, new_val);                             \
      __ CmpAndSwap(r0, r1, MemOperand(addr));          \
      __ lrvr(output, r0);                              \
    } else {                                            \
      __ CmpAndSwap(output, new_val, MemOperand(addr)); \
    }                                                   \
    __ LoadU32(output, output);                         \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP_WORD(load_and_op, op)    \
  do {                                                 \
    Register value = i.InputRegister(2);               \
    Register result = i.OutputRegister(0);             \
    Register addr = r1;                                \
    AddressingMode mode = kMode_None;                  \
    MemOperand op = i.MemoryOperand(&mode);            \
    __ lay(addr, op);                                  \
    if (is_wasm_on_be(info())) {                       \
      Label do_cs;                                     \
      __ bind(&do_cs);                                 \
      __ LoadU32(r0, MemOperand(addr));                \
      __ lrvr(ip, r0);                                 \
      __ op(ip, ip, value);                            \
      __ lrvr(ip, ip);                                 \
      __ CmpAndSwap(r0, ip, MemOperand(addr));         \
      __ bne(&do_cs, Label::kNear);                    \
      __ lrvr(result, r0);                             \
    } else {                                           \
      __ load_and_op(result, value, MemOperand(addr)); \
    }                                                  \
    __ LoadU32(result, result);                        \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP_WORD64(load_and_op, op) \
  do {                                                \
    Register value = i.InputRegister(2);              \
    Register result = i.OutputRegister(0);            \
    Register addr = r1;                               \
    AddressingMode mode = kMode_None;                 \
    MemOperand op = i.MemoryOperand(&mode);           \
    __ lay(addr, op);                                 \
    if (is_wasm_on_be(info())) {                      \
      Label do_cs;                                    \
      __ bind(&do_cs);                                \
      __ LoadU64(r0, MemOperand(addr));               \
      __ lrvgr(ip, r0);                               \
      __ op(ip, ip, value);                           \
      __ lrvgr(ip, ip);                               \
      __ CmpAndSwap64(r0, ip, MemOperand(addr));      \
      __ bne(&do_cs, Label::kNear);                   \
      __ lrvgr(result, r0);                           \
      break;                                          \
    }                                                 \
    __ load_and_op(result, value, MemOperand(addr));  \
  } while (false)

#define ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end,             \
                      maybe_reverse_bytes)                                    \
  do {                                                                        \
    /* At the moment this is only true when dealing with 2-byte values.*/     \
    bool reverse_bytes = maybe_reverse_bytes && is_wasm_on_be(info());        \
    USE(reverse_bytes);                                                       \
    Label do_cs;                                                              \
    __ LoadU32(prev, MemOperand(addr, offset));                               \
    __ bind(&do_cs);                                                          \
    if (reverse_bytes) {                                                      \
      Register temp2 = GetRegisterThatIsNotOneOf(value, result, prev);        \
      __ Push(temp2);                                                         \
      __ lrvr(temp2, prev);                                                   \
      __ RotateInsertSelectBits(temp2, temp2, Operand(start), Operand(end),   \
                                Operand(static_cast<intptr_t>(shift_amount)), \
                                true);                                        \
      __ RotateInsertSelectBits(temp, value, Operand(start), Operand(end),    \
                                Operand(static_cast<intptr_t>(shift_amount)), \
                                true);                                        \
      __ bin_inst(new_val, temp2, temp);                                      \
      __ lrvr(temp2, new_val);                                                \
      __ lr(temp, prev);                                                      \
      __ RotateInsertSelectBits(temp, temp2, Operand(start), Operand(end),    \
                                Operand(static_cast<intptr_t>(shift_amount)), \
                                false);                                       \
      __ Pop(temp2);                                                          \
    } else {                                                                  \
      __ RotateInsertSelectBits(temp, value, Operand(start), Operand(end),    \
                                Operand(static_cast<intptr_t>(shift_amount)), \
                                true);                                        \
      __ bin_inst(new_val, prev, temp);                                       \
      __ lr(temp, prev);                                                      \
      __ RotateInsertSelectBits(temp, new_val, Operand(start), Operand(end),  \
                                Operand::Zero(), false);                      \
    }                                                                         \
    __ CmpAndSwap(prev, temp, MemOperand(addr, offset));                      \
    __ bne(&do_cs, Label::kNear);                                             \
  } while (false)

#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_BIN_OP_HALFWORD(bin_inst, index, extract_result)      \
  {                                                                  \
    constexpr int offset = -(2 * index);                             \
    constexpr int shift_amount = 16 - (index * 16);                  \
    constexpr int start = 48 - shift_amount;                         \
    constexpr int end = start + 15;                                  \
    ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end, true); \
    extract_result();                                                \
  }
#define ATOMIC_BIN_OP_BYTE(bin_inst, index, extract_result)           \
  {                                                                   \
    constexpr int offset = -(index);                                  \
    constexpr int shift_amount = 24 - (index * 8);                    \
    constexpr int start = 56 - shift_amount;                          \
    constexpr int end = start + 7;                                    \
    ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end, false); \
    extract_result();                                                 \
  }
#else
#define ATOMIC_BIN_OP_HALFWORD(bin_inst, index, extract_result)       \
  {                                                                   \
    constexpr int offset = -(2 * index);                              \
    constexpr int shift_amount = index * 16;                          \
    constexpr int start = 48 - shift_amount;                          \
    constexpr int end = start + 15;                                   \
    ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end, false); \
    extract_result();                                                 \
  }
#define ATOMIC_BIN_OP_BYTE(bin_inst, index, extract_result)           \
  {                                                                   \
    constexpr int offset = -(index);                                  \
    constexpr int shift_amount = index * 8;                           \
    constexpr int start = 56 - shift_amount;                          \
    constexpr int end = start + 7;                                    \
    ATOMIC_BIN_OP(bin_inst, offset, shift_amount, start, end, false); \
    extract_result();                                                 \
  }
#endif  // V8_TARGET_BIG_ENDIAN

#define ASSEMBLE_ATOMIC_BINOP_HALFWORD(bin_inst, extract_result) \
  do {                                                           \
    Register value = i.InputRegister(2);                         \
    Register result = i.OutputRegister(0);                       \
    Register prev = i.TempRegister(0);                           \
    Register new_val = r0;                                       \
    Register addr = r1;                                          \
    Register temp = kScratchReg;                                 \
    AddressingMode mode = kMode_None;                            \
    MemOperand op = i.MemoryOperand(&mode);                      \
    Label two, done;                                             \
    __ lay(addr, op);                                            \
    __ tmll(addr, Operand(3));                                   \
    __ b(Condition(2), &two);                                    \
    /* word boundary */                                          \
    ATOMIC_BIN_OP_HALFWORD(bin_inst, 0, extract_result);         \
    __ b(&done);                                                 \
    __ bind(&two);                                               \
    /* halfword boundary */                                      \
    ATOMIC_BIN_OP_HALFWORD(bin_inst, 1, extract_result);         \
    __ bind(&done);                                              \
  } while (false)

#define ASSEMBLE_ATOMIC_BINOP_BYTE(bin_inst, extract_result) \
  do {                                                       \
    Register value = i.InputRegister(2);                     \
    Register result = i.OutputRegister(0);                   \
    Register addr = i.TempRegister(0);                       \
    Register prev = r0;                                      \
    Register new_val = r1;                                   \
    Register temp = kScratchReg;                             \
    AddressingMode mode = kMode_None;                        \
    MemOperand op = i.MemoryOperand(&mode);                  \
    Label done, one, two, three;                             \
    __ lay(addr, op);                                        \
    __ tmll(addr, Operand(3));                               \
    __ b(Condition(1), &three);                              \
    __ b(Condition(2), &two);                                \
    __ b(Condition(4), &one);                                \
    /* ending with 0b00 (word boundary) */                   \
    ATOMIC_BIN_OP_BYTE(bin_inst, 0, extract_result);         \
    __ b(&done);                                             \
    /* ending with 0b01 */                                   \
    __ bind(&one);                                           \
    ATOMIC_BIN_OP_BYTE(bin_inst, 1, extract_result);         \
    __ b(&done);                                             \
    /* ending with 0b10 (hw boundary) */                     \
    __ bind(&two);                                           \
    ATOMIC_BIN_OP_BYTE(bin_inst, 2, extract_result);         \
    __ b(&done);                                             \
    /* ending with 0b11 */                                   \
    __ bind(&three);                                         \
    ATOMIC_BIN_OP_BYTE(bin_inst, 3, extract_result);         \
    __ bind(&done);                                          \
  } while (false)

#define ASSEMBLE_ATOMIC64_COMP_EXCHANGE_WORD64()          \
  do {                                                    \
    Register new_val = i.InputRegister(1);                \
    Register output = i.OutputRegister();                 \
    Register addr = kScratchReg;                          \
    size_t index = 2;                                     \
    AddressingMode mode = kMode_None;                     \
    MemOperand op = i.MemoryOperand(&mode, &index);       \
    __ lay(addr, op);                                     \
    if (is_wasm_on_be(info())) {                          \
      __ lrvgr(r0, output);                               \
      __ lrvgr(r1, new_val);                              \
      __ CmpAndSwap64(r0, r1, MemOperand(addr));          \
      __ lrvgr(output, r0);                               \
    } else {                                              \
      __ CmpAndSwap64(output, new_val, MemOperand(addr)); \
    }                                                     \
  } while (false)

void CodeGenerator::AssembleDeconstructFrame() {
  __ LeaveFrame(StackFrame::MANUAL);
  unwinding_info_writer_.MarkFrameDeconstructed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ RestoreFrameStateForTailCall();
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->Push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize));
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    S390OperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  Register scratch = r1;
  __ ComputeCodeStartAddress(scratch);
  __ CmpS64(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void CodeGenerator::BailoutIfDeoptimized() {
  if (v8_flags.debug_code) {
    // Check that {kJavaScriptCallCodeStartRegister} is correct.
    __ ComputeCodeStartAddress(ip);
    __ CmpS64(ip, kJavaScriptCallCodeStartRegister);
    __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
  }

  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  __ LoadTaggedField(ip, MemOperand(kJavaScriptCallCodeStartRegister, offset),
                     r0);
  __ LoadU32(ip, FieldMemOperand(ip, Code::kFlagsOffset));
  __ TestBit(ip, Code::kMarkedForDeoptimizationBit);
  __ TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne);
}

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  S390OperandConverter i(this, instr);
  ArchOpcode opcode = ArchOpcodeField::decode(instr->opcode());

  switch (opcode) {
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchCallCodeObject: {
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      } else {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!instr->InputAt(0)->IsImmediate());
      Register builtin_index = i.InputRegister(0);
      Register target =
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister)
              ? kJavaScriptCallCodeStartRegister
              : builtin_index;
      __ CallBuiltinByIndex(builtin_index, target);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      } else {
        // We cannot use the constant pool to load the target since
        // we've already restored the caller's frame.
        ConstantPoolUnavailableScope constant_pool_unavailable(masm());
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ LoadTaggedField(kScratchReg,
                           FieldMemOperand(func, JSFunction::kContextOffset));
        __ CmpS64(cp, kScratchReg);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters,
                              kScratchReg);
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, ip, kReturnRegister0);
      DCHECK(IsAligned(bytes, kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      DCHECK(!caller_registers_saved_);
      caller_registers_saved_ = true;
      break;
    }
    case kArchRestoreCallerRegisters: {
      DCHECK(fp_mode_ ==
             static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode())));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // Don't overwrite the returned value.
      int bytes = __ PopCallerSaved(fp_mode_, ip, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const fp_param_field = FPParamField::decode(instr->opcode());
      int num_fp_parameters = fp_param_field;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
      Label return_location;
      bool has_function_descriptor = false;
#if ABI_USES_FUNCTION_DESCRIPTORS
      int kNumFPParametersMask = kHasFunctionDescriptorBitMask - 1;
      num_fp_parameters = kNumFPParametersMask & fp_param_field;
      has_function_descriptor =
          (fp_param_field & kHasFunctionDescriptorBitMask) != 0;
#endif
      // Put the return address in a stack slot.
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        __ larl(r0, &return_location);
        __ StoreU64(r0,
                    MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots,
                                     has_function_descriptor, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots,
                                     has_function_descriptor, &return_location);
      }
      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (opcode == kArchCallCFunctionWithFrameState);
      if (needs_frame_state) {
        RecordDeoptInfo(instr, pc_offset);
      }

      frame_access_state()->SetFrameAccessToDefault();
      // Ideally, we should decrement SP delta to match the change of stack
      // pointer in CallCFunction. However, for certain architectures (e.g.
      // ARM), there may be more strict alignment requirement, causing old SP
      // to be saved on the stack. In those cases, we can not calculate the SP
      // delta statically.
      frame_access_state()->ClearSPDelta();
      if (caller_registers_saved_) {
        // Need to re-sync SP delta introduced in kArchSaveCallerRegisters.
        // Here, we assume the sequence to be:
        //   kArchSaveCallerRegisters;
        //   kArchCallCFunction;
        //   kArchRestoreCallerRegisters;
        int bytes =
            __ RequiredStackSizeForCallerSaved(fp_mode_, kReturnRegister0);
        frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      }
      break;
    }
    case kArchJmp:
      AssembleArchJump(i.InputRpo(0));
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == r3);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ b(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mov(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = sp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ SubS64(
```