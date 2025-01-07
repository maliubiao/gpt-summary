Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

1. **Understanding the Request:** The core request is to analyze a C++ source code file (`wasm-interpreter.cc`) from the V8 JavaScript engine, focusing on its functionality, relationship to JavaScript, code logic, and common errors. The "part 2 of 15" suggests this is part of a larger file dealing with the WebAssembly interpreter. The key instruction is to summarize the functionality of this specific chunk.

2. **Initial Scan and Keyword Spotting:**  A quick scan reveals several recurring patterns and keywords:
    * `INSTRUCTION_HANDLER_FUNC`: This strongly indicates that the code defines functions responsible for handling specific WebAssembly instructions.
    * `LoadMem`, `StoreMem`: These clearly relate to memory access operations in WebAssembly.
    * `LocalSet`, `LocalGet`: These likely deal with accessing local variables within a Wasm function.
    * `Select`: This corresponds to the `select` instruction in Wasm.
    * Binary arithmetic operators (`Add`, `Sub`, `Mul`, `Div`, `Rem`, `And`, `Ior`, `Xor`).
    * Type names like `int32_t`, `uint64_t`, `float`, `double`, `Simd128`, `WasmRef`.
    * `push`, `pop`:  These suggest stack-based operations, common in interpreters.
    * `wasm_runtime`: This pointer suggests interaction with the overall Wasm runtime environment.
    * `memory_start`, `GetMemorySize`: These confirm memory access operations.
    * `TRAP(TrapReason::kTrapMemOutOfBounds)`, `TRAP(TrapReason::kTrapDivByZero)`, `TRAP(TrapReason::kTrapDivUnrepresentable)`:  These indicate error handling for out-of-bounds memory access and division errors.
    * `r2s_`, `s2r_`, `s2s_`, `r2r_`:  These prefixes likely denote different argument passing conventions (register-to-stack, stack-to-register, etc.).
    * Templates (`template <typename T, ...>`). This signifies code reuse for different data types.

3. **Grouping by Functionality:**  Based on the keywords, it's logical to group the code into functional blocks:
    * **Load Operations:**  Functions starting with `LoadMem` are clearly involved in reading data from WebAssembly memory. The variations (e.g., `I32LoadMem8S`, `F64LoadMem`) indicate different data types and sizes being loaded. The presence of `_LocalSet` variants suggests loading a value and then immediately storing it into a local variable.
    * **Store Operations:** Functions starting with `StoreMem` are involved in writing data to WebAssembly memory. Similar type variations exist. The `LocalGet_StoreMem` variant loads a local variable and then stores it into memory.
    * **Load and Store Combined:** The `LoadStoreMem` functions perform both a load from one memory location and a store to another.
    * **Select Operation:** The `Select` functions implement the conditional selection of values.
    * **Binary Arithmetic Operations:** The blocks starting with `#define FOREACH_ARITHMETIC_BINOP` and `#define FOREACH_TRAPPING_BINOP` implement various arithmetic operations. The "trapping" variants handle potential division by zero and overflow errors.

4. **Analyzing Function Signatures and Logic:** Examining the function signatures and the code within each function reveals the following:
    * **Argument Conventions:** The `r2s`, `s2r`, `s2s`, `r2r` prefixes indicate how operands are passed:
        * `r2s`:  One operand is in a register (`r0` or `fp0`), and the result is pushed onto the stack.
        * `s2r`: Operands are popped from the stack, and the result is placed in a register.
        * `s2s`: Operands are popped from the stack, and the result is pushed back onto the stack.
        * `r2r`: Operands are popped from the stack, and the result is placed back into a register.
    * **Memory Access Logic:** The `LoadMem` and `StoreMem` functions calculate an `effective_index` by adding an `offset` (read from the bytecode) to an `index`. They then perform bounds checking to prevent out-of-bounds memory access. `base::ReadUnalignedValue` and `base::WriteUnalignedValue` are used for reading and writing data, which is important for handling different data alignments.
    * **Stack Operations:** `push` and `pop` are used to manage the WebAssembly operand stack.
    * **Local Variable Access:** In the `_LocalSet` and `LocalGet_StoreMem` functions, `ReadI32(code)` is used to read the index of the local variable from the bytecode, and direct stack access (`sp + to`, `sp + from`) is performed.
    * **Select Logic:** The `Select` functions evaluate a condition and choose one of two input values based on the condition.
    * **Arithmetic Logic:** The arithmetic operation functions perform the corresponding arithmetic or bitwise operations. The "trapping" division operations include checks for division by zero and unrepresentable results.

5. **Connecting to JavaScript (Conceptual):** While the C++ code itself isn't directly executable JavaScript, its purpose is to *execute* WebAssembly code that can be generated by compiling JavaScript (or other languages). The connection is that this interpreter is part of how V8 runs Wasm modules that might have been created from JavaScript. Think of it as the "engine" that understands and executes the Wasm instructions. A simple JavaScript example would be calling a Wasm function that performs a memory load or arithmetic operation.

6. **Code Logic Reasoning (Example):** Take the `r2s_I32LoadMem` function. The input is a memory offset in the bytecode and an index in register `r0`. The output is the 32-bit integer value read from memory at the calculated address, pushed onto the stack. The bounds check ensures safety.

7. **Common Programming Errors:**  The bounds checking in the memory access functions directly addresses a very common WebAssembly programming error: trying to access memory outside the allocated bounds. The division-by-zero checks in the trapping arithmetic operations also point to common errors.

8. **Addressing the `.tq` Question:**  The code snippet is clearly C++, not Torque. The explanation about `.tq` files is important context for someone working with V8, but it doesn't apply to this specific file.

9. **Structuring the Response:** Organize the findings into clear sections: File Description, Functionality, Relationship to JavaScript, Code Logic Examples, Common Errors, and Summary. Use bullet points and code formatting to improve readability.

10. **Refining the Summary:** The summary should concisely capture the main purpose of the code: implementing the core logic for executing various WebAssembly instructions related to memory access, data manipulation, and control flow within the V8 interpreter.

11. **Self-Correction/Review:** After drafting the initial response, reread the code snippet and the response to ensure accuracy and completeness. Are there any nuances missed? Is the language clear and understandable?  For instance, initially, I might have just said "memory access," but specifying the different load/store types and the bounds checking adds more detail. Similarly, highlighting the different operand passing conventions (`r2s`, `s2r`, etc.) is crucial for understanding the code's structure.
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的V8源代码的第2部分，它主要负责实现WebAssembly解释器的核心功能，特别是关于**内存操作**和**选择操作**以及基本的**算术运算**。

**功能列表:**

1. **内存加载指令 (LoadMem):**
   - 提供多种模板函数 (`r2s_LoadMem`, `s2r_LoadMem`, `s2s_LoadMem`) 用于从 WebAssembly 线性内存中加载不同大小和类型的数值（i32, i64, f32, f64）并将其推送到栈上或存储到寄存器。
   - 支持有符号和无符号的字节、半字加载 (`I32LoadMem8S`, `I32LoadMem8U`, 等)。
   - `r2s_LoadMem`: 内存地址的偏移量由指令指定，基地址由寄存器 `r0` 提供，加载的值压入栈。
   - `s2r_LoadMemI`/`s2r_LoadMemF`: 内存地址的偏移量由指令指定，基地址从栈顶弹出，加载的值存入寄存器 `r0`/`fp0`。
   - `s2s_LoadMem`: 内存地址的偏移量由指令指定，基地址从栈顶弹出，加载的值压入栈。
   - **安全性：** 每个加载指令都包含边界检查，确保访问的内存地址在有效范围内，防止越界访问 (`TRAP(TrapReason::kTrapMemOutOfBounds)`).

2. **内存加载并本地设置指令 (LoadMem_LocalSet):**
   - 提供模板函数 (`r2s_LoadMem_LocalSet`, `s2s_LoadMem_LocalSet`)，用于从内存加载数据，并立即将其存储到本地变量中。
   - 从指令中读取本地变量的索引 (`ReadI32(code)`).
   - `r2s_LoadMem_LocalSet`: 内存地址计算方式同 `r2s_LoadMem`，加载的值直接写入栈上的指定本地变量位置。
   - `s2s_LoadMem_LocalSet`: 内存地址计算方式同 `s2s_LoadMem`，加载的值直接写入栈上的指定本地变量位置。

3. **内存存储指令 (StoreMem):**
   - 提供多种模板函数 (`r2s_StoreMemI`, `r2s_StoreMemF`, `s2s_StoreMem`) 用于将寄存器或栈顶的值存储到 WebAssembly 线性内存中。
   - 支持存储不同大小和类型的数值（i32, i64, f32, f64），并能存储字节和半字 (`I32StoreMem8`, `I64StoreMem16`, 等)。
   - `r2s_StoreMemI`/`r2s_StoreMemF`: 要存储的值在寄存器 `r0`/`fp0` 中，内存地址的偏移量由指令指定，基地址从栈顶弹出。
   - `s2s_StoreMem`: 要存储的值从栈顶弹出，内存地址的偏移量由指令指定，基地址也从栈顶弹出。
   - **安全性：** 同样包含边界检查，防止越界写入。

4. **本地获取并存储到内存指令 (LocalGet_StoreMem):**
   - 提供模板函数 (`s2s_LocalGet_StoreMem`)，用于读取本地变量的值，并将其存储到 WebAssembly 线性内存中。
   - 从指令中读取本地变量的索引 (`ReadI32(code)`).
   - 要存储的值来自本地变量，内存地址的偏移量由指令指定，基地址从栈顶弹出。

5. **加载并存储指令 (LoadStoreMem):**
   - 提供模板函数 (`r2s_LoadStoreMem`, `s2s_LoadStoreMem`)，用于从一个内存位置加载值，并立即将其存储到另一个内存位置。
   - 指令中包含加载和存储的偏移量。
   - `r2s_LoadStoreMem`: 加载的基地址来自寄存器 `r0`，存储的基地址从栈顶弹出。
   - `s2s_LoadStoreMem`: 加载和存储的基地址都从栈顶弹出。
   - **安全性：** 对加载和存储的地址都进行边界检查。

6. **选择指令 (Select):**
   - 提供多种模板函数 (`r2r_SelectI`, `r2r_SelectF`, `r2s_Select`, `s2r_SelectI`, `s2r_SelectF`, `s2s_Select`, `r2s_RefSelect`, `s2s_RefSelect`)，用于实现 WebAssembly 的 `select` 指令，根据条件选择两个值中的一个。
   - `r2r_SelectI`/`r2r_SelectF`: 条件在寄存器 `r0`，要选择的两个值从栈顶弹出，结果存回寄存器 `r0`/`fp0`。
   - `r2s_Select`: 条件在寄存器 `r0`，要选择的两个值从栈顶弹出，结果压入栈。
   - `s2r_SelectI`/`s2r_SelectF`: 条件从栈顶弹出，要选择的两个值也从栈顶弹出，结果存入寄存器 `r0`/`fp0`。
   - `s2s_Select`: 条件和要选择的两个值都从栈顶弹出，结果压入栈。
   - `r2s_RefSelect`/`s2s_RefSelect`:  处理引用类型的选择。

7. **二元算术运算符 (Binary arithmetic operators):**
   - 使用宏 `FOREACH_ARITHMETIC_BINOP` 和 `DEFINE_BINOP` 定义了多种二元算术运算指令的实现，包括加法 (`Add`)，减法 (`Sub`)，乘法 (`Mul`)，除法 (`Div`)，按位与 (`And`)，按位或 (`Ior`)，按位异或 (`Xor`)。
   - 提供了不同参数传递方式的实现 (`r2r_`, `r2s_`, `s2r_`, `s2s_`) 对应寄存器到寄存器，寄存器到栈，栈到寄存器，栈到栈的操作。
   - 支持整型 (i32, i64) 和浮点型 (f32, f64)。

8. **可能触发陷阱的二元算术运算符 (Binary arithmetic operators that can trap):**
   - 使用宏 `FOREACH_SIGNED_DIV_BINOP`, `FOREACH_UNSIGNED_DIV_BINOP`, `FOREACH_REM_BINOP`, `FOREACH_TRAPPING_BINOP` 和 `DEFINE_BINOP` 定义了可能触发陷阱的二元算术运算指令，主要是除法和取余运算。
   - 包括有符号除法 (`DivS`)，无符号除法 (`DivU`)，有符号取余 (`RemS`)，无符号取余 (`RemU`)。
   - **安全性：** 这些操作会检查除零错误 (`TRAP(TrapReason::kTrapDivByZero)`) 和有符号除法溢出错误 (`TRAP(TrapReason::kTrapDivUnrepresentable)`).

**关于是否为 Torque 源代码:**

这段代码是 **C++** 源代码。如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那它才是一个 V8 Torque 源代码。

**与 Javascript 的关系:**

这段代码是 V8 引擎中 WebAssembly 解释器的核心部分。当 JavaScript 代码执行 WebAssembly 模块时，如果 V8 没有选择将该模块编译成本地机器码（通过 TurboFan 等编译器），那么就会使用解释器来逐条执行 WebAssembly 的指令。

例如，如果 WebAssembly 代码中包含一个从内存中加载整数的指令，那么这段 C++ 代码中的某个 `r2s_I32LoadMem` 或类似的函数就会被调用来执行这个操作。

**JavaScript 示例:**

```javascript
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, // WASM header
  10, 7, 1, 6, 0, 65, 0, 11, // Code section: function definition
  0, 38, 2, 0, 0, 11          //  i32.const 0; local.get 0; i32.load offset=0
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });
const memory = new WebAssembly.Memory({ initial: 1 });

// 假设 WebAssembly 模块导出一个函数，该函数会执行 i32.load 指令
// 并尝试从内存地址 0 加载一个 i32 值

// 在 JavaScript 中设置内存的值
const memoryBuffer = new Uint32Array(memory.buffer);
memoryBuffer[0] = 12345;

// 调用 WebAssembly 导出的函数
// wasmInstance.exports.someFunction(); // 这个函数内部会执行到 i32.load

// 当执行到 i32.load 指令时，V8 的解释器（这段 C++ 代码）会被调用，
// 读取内存中地址 0 的值 (12345)，并将其放到 WebAssembly 的栈上。
```

**代码逻辑推理示例:**

**假设输入:**

- `code`: 指向当前执行的 WebAssembly 指令序列的指针，当前指令是 `I32LoadMem`，并且紧随其后的是一个 64 位的偏移量 `0x10`.
- `sp`: 指向 WebAssembly 栈顶的指针。
- `wasm_runtime->GetMemoryStart()`: 返回 WebAssembly 线性内存的起始地址，假设为 `0x1000`.
- `r0`: 寄存器 `r0` 的值为 `0x20`.
- `wasm_runtime->GetMemorySize()`: 返回 WebAssembly 线性内存的大小，假设为 `0x200`.

**执行 `r2s_I32LoadMem`:**

1. `offset = Read<uint64_t>(code)`: 从 `code` 中读取接下来的 8 个字节，得到偏移量 `0x10`.
2. `index = r0`: 将寄存器 `r0` 的值 `0x20` 赋给 `index`.
3. `effective_index = offset + index = 0x10 + 0x20 = 0x30`.
4. **边界检查:** `effective_index (0x30) + sizeof(int32_t) (4) <= wasm_runtime->GetMemorySize() (0x200)`，且 `effective_index >= 0`，假设检查通过。
5. `address = memory_start + effective_index = 0x1000 + 0x30 = 0x1030`.
6. `value = base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(address))`: 从内存地址 `0x1030` 读取一个 32 位的整数值。
7. `push<int32_t>(sp, code, wasm_runtime, value)`: 将读取到的 `value` 压入 WebAssembly 栈。
8. `NextOp()`: 执行下一条指令。

**假设输出:**

- WebAssembly 栈顶增加了一个 32 位的整数值，该值是从内存地址 `0x1030` 读取的。

**用户常见的编程错误示例:**

1. **内存越界访问:** 在 WebAssembly 代码中，尝试加载或存储超出已分配内存范围的数据。例如，如果内存大小为 64KB，但尝试访问偏移量为 70KB 的位置。这段 C++ 代码中的边界检查机制会捕获这种错误并触发 `kTrapMemOutOfBounds`。

   ```c++
   // 假设 wasm_runtime->GetMemorySize() 返回一个较小的值，
   // 导致 effective_index 超出范围
   uint64_t offset = Read<uint64_t>(code); // 假设 offset 很大
   uint64_t index = r0;
   uint64_t effective_index = offset + index;

   if (V8_UNLIKELY(effective_index < index ||
                   !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                               wasm_runtime->GetMemorySize()))) {
     TRAP(TrapReason::kTrapMemOutOfBounds) // 这里会触发错误
   }
   ```

2. **除零错误:** 在执行整数除法或取余操作时，除数为零。这段 C++ 代码中的 `r2r_I32DivS` 等函数会检查除数是否为零。

   ```c++
   INSTRUCTION_HANDLER_FUNC r2r_I32DivS(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
     int32_t rval = static_cast<int32_t>(r0);
     int32_t lval = pop<int32_t>(sp, code, wasm_runtime);
     if (rval == 0) {
       TRAP(TrapReason::kTrapDivByZero) // 这里会触发错误
     } else if (rval == -1 && lval == std::numeric_limits<int32_t>::min()) {
       TRAP(TrapReason::kTrapDivUnrepresentable)
     } else {
       r0 = static_cast<int32_t>(lval / rval);
     }
     NextOp();
   }
   ```

**归纳一下它的功能 (第2部分):**

这段代码主要实现了 WebAssembly 解释器中处理**内存访问**（加载和存储）、**数据选择**和基本的**算术运算**的核心逻辑。它定义了各种指令处理函数，负责从内存中读取数据、将数据写入内存、根据条件选择不同的值，以及执行基本的算术运算。  重要的是，这些实现都考虑了安全性，包含了防止内存越界访问和除零错误的检查机制。 这部分代码是 WebAssembly 解释器执行 WebAssembly 代码片段的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共15部分，请归纳一下它的功能

"""
CTION_HANDLER_FUNC r2s_LoadMem(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  push<T>(sp, code, wasm_runtime, value);

  NextOp();
}
static auto r2s_I32LoadMem8S = r2s_LoadMem<int32_t, int8_t>;
static auto r2s_I32LoadMem8U = r2s_LoadMem<int32_t, uint8_t>;
static auto r2s_I32LoadMem16S = r2s_LoadMem<int32_t, int16_t>;
static auto r2s_I32LoadMem16U = r2s_LoadMem<int32_t, uint16_t>;
static auto r2s_I64LoadMem8S = r2s_LoadMem<int64_t, int8_t>;
static auto r2s_I64LoadMem8U = r2s_LoadMem<int64_t, uint8_t>;
static auto r2s_I64LoadMem16S = r2s_LoadMem<int64_t, int16_t>;
static auto r2s_I64LoadMem16U = r2s_LoadMem<int64_t, uint16_t>;
static auto r2s_I64LoadMem32S = r2s_LoadMem<int64_t, int32_t>;
static auto r2s_I64LoadMem32U = r2s_LoadMem<int64_t, uint32_t>;
static auto r2s_I32LoadMem = r2s_LoadMem<int32_t>;
static auto r2s_I64LoadMem = r2s_LoadMem<int64_t>;
static auto r2s_F32LoadMem = r2s_LoadMem<float>;
static auto r2s_F64LoadMem = r2s_LoadMem<double>;

template <typename IntT, typename IntU = IntT>
INSTRUCTION_HANDLER_FUNC s2r_LoadMemI(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(IntU),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  r0 = static_cast<IntT>(
      base::ReadUnalignedValue<IntU>(reinterpret_cast<Address>(address)));

  NextOp();
}
static auto s2r_I32LoadMem8S = s2r_LoadMemI<int32_t, int8_t>;
static auto s2r_I32LoadMem8U = s2r_LoadMemI<int32_t, uint8_t>;
static auto s2r_I32LoadMem16S = s2r_LoadMemI<int32_t, int16_t>;
static auto s2r_I32LoadMem16U = s2r_LoadMemI<int32_t, uint16_t>;
static auto s2r_I64LoadMem8S = s2r_LoadMemI<int64_t, int8_t>;
static auto s2r_I64LoadMem8U = s2r_LoadMemI<int64_t, uint8_t>;
static auto s2r_I64LoadMem16S = s2r_LoadMemI<int64_t, int16_t>;
static auto s2r_I64LoadMem16U = s2r_LoadMemI<int64_t, uint16_t>;
static auto s2r_I64LoadMem32S = s2r_LoadMemI<int64_t, int32_t>;
static auto s2r_I64LoadMem32U = s2r_LoadMemI<int64_t, uint32_t>;
static auto s2r_I32LoadMem = s2r_LoadMemI<int32_t>;
static auto s2r_I64LoadMem = s2r_LoadMemI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC s2r_LoadMemF(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(FloatT),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  fp0 = static_cast<FloatT>(
      base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(address)));

  NextOp();
}
static auto s2r_F32LoadMem = s2r_LoadMemF<float>;
static auto s2r_F64LoadMem = s2r_LoadMemF<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LoadMem(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  push<T>(sp, code, wasm_runtime, value);

  NextOp();
}
static auto s2s_I32LoadMem8S = s2s_LoadMem<int32_t, int8_t>;
static auto s2s_I32LoadMem8U = s2s_LoadMem<int32_t, uint8_t>;
static auto s2s_I32LoadMem16S = s2s_LoadMem<int32_t, int16_t>;
static auto s2s_I32LoadMem16U = s2s_LoadMem<int32_t, uint16_t>;
static auto s2s_I64LoadMem8S = s2s_LoadMem<int64_t, int8_t>;
static auto s2s_I64LoadMem8U = s2s_LoadMem<int64_t, uint8_t>;
static auto s2s_I64LoadMem16S = s2s_LoadMem<int64_t, int16_t>;
static auto s2s_I64LoadMem16U = s2s_LoadMem<int64_t, uint16_t>;
static auto s2s_I64LoadMem32S = s2s_LoadMem<int64_t, int32_t>;
static auto s2s_I64LoadMem32U = s2s_LoadMem<int64_t, uint32_t>;
static auto s2s_I32LoadMem = s2s_LoadMem<int32_t>;
static auto s2s_I64LoadMem = s2s_LoadMem<int64_t>;
static auto s2s_F32LoadMem = s2s_LoadMem<float>;
static auto s2s_F64LoadMem = s2s_LoadMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LoadMem_LocalSet

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC r2s_LoadMem_LocalSet(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = r0;
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(sp + to),
                               static_cast<T>(value));

  NextOp();
}
static auto r2s_I32LoadMem8S_LocalSet = r2s_LoadMem_LocalSet<int32_t, int8_t>;
static auto r2s_I32LoadMem8U_LocalSet = r2s_LoadMem_LocalSet<int32_t, uint8_t>;
static auto r2s_I32LoadMem16S_LocalSet = r2s_LoadMem_LocalSet<int32_t, int16_t>;
static auto r2s_I32LoadMem16U_LocalSet =
    r2s_LoadMem_LocalSet<int32_t, uint16_t>;
static auto r2s_I64LoadMem8S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int8_t>;
static auto r2s_I64LoadMem8U_LocalSet = r2s_LoadMem_LocalSet<int64_t, uint8_t>;
static auto r2s_I64LoadMem16S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int16_t>;
static auto r2s_I64LoadMem16U_LocalSet =
    r2s_LoadMem_LocalSet<int64_t, uint16_t>;
static auto r2s_I64LoadMem32S_LocalSet = r2s_LoadMem_LocalSet<int64_t, int32_t>;
static auto r2s_I64LoadMem32U_LocalSet =
    r2s_LoadMem_LocalSet<int64_t, uint32_t>;
static auto r2s_I32LoadMem_LocalSet = r2s_LoadMem_LocalSet<int32_t>;
static auto r2s_I64LoadMem_LocalSet = r2s_LoadMem_LocalSet<int64_t>;
static auto r2s_F32LoadMem_LocalSet = r2s_LoadMem_LocalSet<float>;
static auto r2s_F64LoadMem_LocalSet = r2s_LoadMem_LocalSet<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LoadMem_LocalSet(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<int32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  U value = base::ReadUnalignedValue<U>(reinterpret_cast<Address>(address));

  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<T>(reinterpret_cast<Address>(sp + to),
                               static_cast<T>(value));

  NextOp();
}
static auto s2s_I32LoadMem8S_LocalSet = s2s_LoadMem_LocalSet<int32_t, int8_t>;
static auto s2s_I32LoadMem8U_LocalSet = s2s_LoadMem_LocalSet<int32_t, uint8_t>;
static auto s2s_I32LoadMem16S_LocalSet = s2s_LoadMem_LocalSet<int32_t, int16_t>;
static auto s2s_I32LoadMem16U_LocalSet =
    s2s_LoadMem_LocalSet<int32_t, uint16_t>;
static auto s2s_I64LoadMem8S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int8_t>;
static auto s2s_I64LoadMem8U_LocalSet = s2s_LoadMem_LocalSet<int64_t, uint8_t>;
static auto s2s_I64LoadMem16S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int16_t>;
static auto s2s_I64LoadMem16U_LocalSet =
    s2s_LoadMem_LocalSet<int64_t, uint16_t>;
static auto s2s_I64LoadMem32S_LocalSet = s2s_LoadMem_LocalSet<int64_t, int32_t>;
static auto s2s_I64LoadMem32U_LocalSet =
    s2s_LoadMem_LocalSet<int64_t, uint32_t>;
static auto s2s_I32LoadMem_LocalSet = s2s_LoadMem_LocalSet<int32_t>;
static auto s2s_I64LoadMem_LocalSet = s2s_LoadMem_LocalSet<int64_t>;
static auto s2s_F32LoadMem_LocalSet = s2s_LoadMem_LocalSet<float>;
static auto s2s_F64LoadMem_LocalSet = s2s_LoadMem_LocalSet<double>;

////////////////////////////////////////////////////////////////////////////////
// StoreMem

template <typename IntT, typename IntU = IntT>
INSTRUCTION_HANDLER_FUNC r2s_StoreMemI(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  IntT value = static_cast<IntT>(r0);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(IntU),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<IntU>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<IntU>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto r2s_I32StoreMem8 = r2s_StoreMemI<int32_t, int8_t>;
static auto r2s_I32StoreMem16 = r2s_StoreMemI<int32_t, int16_t>;
static auto r2s_I64StoreMem8 = r2s_StoreMemI<int64_t, int8_t>;
static auto r2s_I64StoreMem16 = r2s_StoreMemI<int64_t, int16_t>;
static auto r2s_I64StoreMem32 = r2s_StoreMemI<int64_t, int32_t>;
static auto r2s_I32StoreMem = r2s_StoreMemI<int32_t>;
static auto r2s_I64StoreMem = r2s_StoreMemI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2s_StoreMemF(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  FloatT value = static_cast<FloatT>(fp0);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(FloatT),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<FloatT>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<FloatT>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto r2s_F32StoreMem = r2s_StoreMemF<float>;
static auto r2s_F64StoreMem = r2s_StoreMemF<double>;

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StoreMem(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  T value = pop<T>(sp, code, wasm_runtime);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<U>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<U>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto s2s_I32StoreMem8 = s2s_StoreMem<int32_t, int8_t>;
static auto s2s_I32StoreMem16 = s2s_StoreMem<int32_t, int16_t>;
static auto s2s_I64StoreMem8 = s2s_StoreMem<int64_t, int8_t>;
static auto s2s_I64StoreMem16 = s2s_StoreMem<int64_t, int16_t>;
static auto s2s_I64StoreMem32 = s2s_StoreMem<int64_t, int32_t>;
static auto s2s_I32StoreMem = s2s_StoreMem<int32_t>;
static auto s2s_I64StoreMem = s2s_StoreMem<int64_t>;
static auto s2s_F32StoreMem = s2s_StoreMem<float>;
static auto s2s_F64StoreMem = s2s_StoreMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LocalGet_StoreMem

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_LocalGet_StoreMem(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  T value = base::ReadUnalignedValue<T>(reinterpret_cast<Address>(sp + from));

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(U),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;

  base::WriteUnalignedValue<U>(
      reinterpret_cast<Address>(address),
      base::ReadUnalignedValue<U>(reinterpret_cast<Address>(&value)));

  NextOp();
}
static auto s2s_LocalGet_I32StoreMem8 = s2s_LocalGet_StoreMem<int32_t, int8_t>;
static auto s2s_LocalGet_I32StoreMem16 =
    s2s_LocalGet_StoreMem<int32_t, int16_t>;
static auto s2s_LocalGet_I64StoreMem8 = s2s_LocalGet_StoreMem<int64_t, int8_t>;
static auto s2s_LocalGet_I64StoreMem16 =
    s2s_LocalGet_StoreMem<int64_t, int16_t>;
static auto s2s_LocalGet_I64StoreMem32 =
    s2s_LocalGet_StoreMem<int64_t, int32_t>;
static auto s2s_LocalGet_I32StoreMem = s2s_LocalGet_StoreMem<int32_t>;
static auto s2s_LocalGet_I64StoreMem = s2s_LocalGet_StoreMem<int64_t>;
static auto s2s_LocalGet_F32StoreMem = s2s_LocalGet_StoreMem<float>;
static auto s2s_LocalGet_F64StoreMem = s2s_LocalGet_StoreMem<double>;

////////////////////////////////////////////////////////////////////////////////
// LoadStoreMem

template <typename T>
INSTRUCTION_HANDLER_FUNC r2s_LoadStoreMem(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();

  uint64_t load_offset = Read<uint64_t>(code);
  uint64_t load_index = r0;
  uint64_t effective_load_index = load_offset + load_index;

  uint64_t store_offset = Read<uint64_t>(code);
  uint64_t store_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_store_index = store_offset + store_index;

  if (V8_UNLIKELY(effective_load_index < load_index ||
                  !base::IsInBounds<uint64_t>(effective_load_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()) ||
                  effective_store_index < store_offset ||
                  !base::IsInBounds<uint64_t>(effective_store_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* load_address = memory_start + effective_load_index;
  uint8_t* store_address = memory_start + effective_store_index;

  base::WriteUnalignedValue<T>(
      reinterpret_cast<Address>(store_address),
      base::ReadUnalignedValue<T>(reinterpret_cast<Address>(load_address)));

  NextOp();
}
static auto r2s_I32LoadStoreMem = r2s_LoadStoreMem<int32_t>;
static auto r2s_I64LoadStoreMem = r2s_LoadStoreMem<int64_t>;
static auto r2s_F32LoadStoreMem = r2s_LoadStoreMem<float>;
static auto r2s_F64LoadStoreMem = r2s_LoadStoreMem<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_LoadStoreMem(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();

  uint64_t load_offset = Read<uint64_t>(code);
  uint64_t load_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_load_index = load_offset + load_index;

  uint64_t store_offset = Read<uint64_t>(code);
  uint64_t store_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_store_index = store_offset + store_index;

  if (V8_UNLIKELY(effective_load_index < load_index ||
                  !base::IsInBounds<uint64_t>(effective_load_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()) ||
                  effective_store_index < store_offset ||
                  !base::IsInBounds<uint64_t>(effective_store_index, sizeof(T),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* load_address = memory_start + effective_load_index;
  uint8_t* store_address = memory_start + effective_store_index;

  base::WriteUnalignedValue<T>(
      reinterpret_cast<Address>(store_address),
      base::ReadUnalignedValue<T>(reinterpret_cast<Address>(load_address)));

  NextOp();
}
static auto s2s_I32LoadStoreMem = s2s_LoadStoreMem<int32_t>;
static auto s2s_I64LoadStoreMem = s2s_LoadStoreMem<int64_t>;
static auto s2s_F32LoadStoreMem = s2s_LoadStoreMem<float>;
static auto s2s_F64LoadStoreMem = s2s_LoadStoreMem<double>;

#endif  // V8_DRUMBRAKE_BOUNDS_CHECKS

////////////////////////////////////////////////////////////////////////////////
// Select

template <typename IntT>
INSTRUCTION_HANDLER_FUNC r2r_SelectI(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  IntT val2 = pop<IntT>(sp, code, wasm_runtime);
  IntT val1 = pop<IntT>(sp, code, wasm_runtime);

  // r0: condition
  r0 = r0 ? val1 : val2;

  NextOp();
}
static auto r2r_I32Select = r2r_SelectI<int32_t>;
static auto r2r_I64Select = r2r_SelectI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC r2r_SelectF(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  FloatT val2 = pop<FloatT>(sp, code, wasm_runtime);
  FloatT val1 = pop<FloatT>(sp, code, wasm_runtime);

  // r0: condition
  fp0 = r0 ? val1 : val2;

  NextOp();
}
static auto r2r_F32Select = r2r_SelectF<float>;
static auto r2r_F64Select = r2r_SelectF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC r2s_Select(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  T val2 = pop<T>(sp, code, wasm_runtime);
  T val1 = pop<T>(sp, code, wasm_runtime);

  push<T>(sp, code, wasm_runtime, r0 ? val1 : val2);

  NextOp();
}
static auto r2s_I32Select = r2s_Select<int32_t>;
static auto r2s_I64Select = r2s_Select<int64_t>;
static auto r2s_F32Select = r2s_Select<float>;
static auto r2s_F64Select = r2s_Select<double>;
static auto r2s_S128Select = r2s_Select<Simd128>;

INSTRUCTION_HANDLER_FUNC r2s_RefSelect(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  WasmRef val2 = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef val1 = pop<WasmRef>(sp, code, wasm_runtime);
  push<WasmRef>(sp, code, wasm_runtime, r0 ? val1 : val2);

  NextOp();
}

template <typename IntT>
INSTRUCTION_HANDLER_FUNC s2r_SelectI(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  IntT val2 = pop<IntT>(sp, code, wasm_runtime);
  IntT val1 = pop<IntT>(sp, code, wasm_runtime);

  r0 = cond ? val1 : val2;

  NextOp();
}
static auto s2r_I32Select = s2r_SelectI<int32_t>;
static auto s2r_I64Select = s2r_SelectI<int64_t>;

template <typename FloatT>
INSTRUCTION_HANDLER_FUNC s2r_SelectF(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  FloatT val2 = pop<FloatT>(sp, code, wasm_runtime);
  FloatT val1 = pop<FloatT>(sp, code, wasm_runtime);

  fp0 = cond ? val1 : val2;

  NextOp();
}
static auto s2r_F32Select = s2r_SelectF<float>;
static auto s2r_F64Select = s2r_SelectF<double>;

template <typename T>
INSTRUCTION_HANDLER_FUNC s2s_Select(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  T val2 = pop<T>(sp, code, wasm_runtime);
  T val1 = pop<T>(sp, code, wasm_runtime);

  push<T>(sp, code, wasm_runtime, cond ? val1 : val2);

  NextOp();
}
static auto s2s_I32Select = s2s_Select<int32_t>;
static auto s2s_I64Select = s2s_Select<int64_t>;
static auto s2s_F32Select = s2s_Select<float>;
static auto s2s_F64Select = s2s_Select<double>;
static auto s2s_S128Select = s2s_Select<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefSelect(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef val2 = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef val1 = pop<WasmRef>(sp, code, wasm_runtime);
  push<WasmRef>(sp, code, wasm_runtime, cond ? val1 : val2);

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// Binary arithmetic operators

#define FOREACH_ARITHMETIC_BINOP(V) \
  V(I32Add, uint32_t, r0, +, I32)   \
  V(I32Sub, uint32_t, r0, -, I32)   \
  V(I32Mul, uint32_t, r0, *, I32)   \
  V(I32And, uint32_t, r0, &, I32)   \
  V(I32Ior, uint32_t, r0, |, I32)   \
  V(I32Xor, uint32_t, r0, ^, I32)   \
  V(I64Add, uint64_t, r0, +, I64)   \
  V(I64Sub, uint64_t, r0, -, I64)   \
  V(I64Mul, uint64_t, r0, *, I64)   \
  V(I64And, uint64_t, r0, &, I64)   \
  V(I64Ior, uint64_t, r0, |, I64)   \
  V(I64Xor, uint64_t, r0, ^, I64)   \
  V(F32Add, float, fp0, +, F32)     \
  V(F32Sub, float, fp0, -, F32)     \
  V(F32Mul, float, fp0, *, F32)     \
  V(F32Div, float, fp0, /, F32)     \
  V(F64Add, double, fp0, +, F64)    \
  V(F64Sub, double, fp0, -, F64)    \
  V(F64Mul, double, fp0, *, F64)    \
  V(F64Div, double, fp0, /, F64)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(lval op rval);                                 \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, lval op rval);                      \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(lval op rval);                                 \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, lval op rval);                      \
    NextOp();                                                               \
  }
FOREACH_ARITHMETIC_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

////////////////////////////////////////////////////////////////////////////////
// Binary arithmetic operators that can trap

#define FOREACH_SIGNED_DIV_BINOP(V) \
  V(I32DivS, int32_t, r0, /, I32)   \
  V(I64DivS, int64_t, r0, /, I64)

#define FOREACH_UNSIGNED_DIV_BINOP(V) \
  V(I32DivU, uint32_t, r0, /, I32)    \
  V(I64DivU, uint64_t, r0, /, I64)

#define FOREACH_REM_BINOP(V)                 \
  V(I32RemS, int32_t, r0, ExecuteRemS, I32)  \
  V(I64RemS, int64_t, r0, ExecuteRemS, I64)  \
  V(I32RemU, uint32_t, r0, ExecuteRemU, I32) \
  V(I64RemU, uint64_t, r0, ExecuteRemU, I64)

#define FOREACH_TRAPPING_BINOP(V) \
  FOREACH_SIGNED_DIV_BINOP(V)     \
  FOREACH_UNSIGNED_DIV_BINOP(V)   \
  FOREACH_REM_BINOP(V)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else if (rval == -1 && lval == std::numeric_limits<ctype>::min()) {   \
      TRAP(TrapReason::kTrapDivUnrepresentable)                             \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }
FOREACH_SIGNED_DIV_BINOP(DEFI
"""


```