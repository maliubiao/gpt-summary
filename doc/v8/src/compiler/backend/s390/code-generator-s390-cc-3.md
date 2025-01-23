Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Function:** The code is within a `switch` statement based on `opcode`. This immediately suggests that the primary function of this code block is to handle different instruction types (`kS390_...`).

2. **Recognize the Context:** The filename `code-generator-s390.cc` and the presence of assembly instructions (`__ vlvg`, `__ lg`, `__ la`, etc.) strongly indicate this code is responsible for generating machine code for the s390 architecture within the V8 JavaScript engine's compiler.

3. **Group Instructions by Functionality:** I start scanning the `case` labels and the corresponding assembly instructions, looking for patterns and common themes. I see groups of instructions related to:
    * **Loading Data:** Instructions starting with `Load` (e.g., `kS390_LoadReverseSimd128`, `kS390_LoadWord64`, `kS390_LoadFloat32`).
    * **Storing Data:** Instructions starting with `Store` (e.g., `kS390_StoreWord8`, `kS390_StoreSimd128`).
    * **Atomic Operations:** Instructions starting with `Atomic` (e.g., `kAtomicExchangeInt8`, `kAtomicCompareExchangeWord32`).
    * **SIMD (Single Instruction, Multiple Data) Operations:**  A large number of instructions starting with `kS390_` followed by SIMD-related prefixes like `F64x2`, `I32x4`, `S128`. These perform parallel operations on vectors of data.
    * **Address Calculation:** `kS390_Lay` is used for loading addresses.
    * **Bitwise Operations:** `S128And`, `S128Or`, `S128Xor`.
    * **Conversions:** Instructions involving converting between different data types (e.g., `kS390_I32x4SConvertF32x4`).
    * **Shifting:**  Instructions like `I64x2Shl`, `I32x4ShrS`.

4. **Infer High-Level Functionality:** Based on these groupings, I can deduce the core responsibilities of this code:
    * **Memory Access:** Loading and storing various data types (integers, floats, SIMD vectors) from and to memory. The "reverse" variants suggest handling different endianness or specific data layout requirements.
    * **Atomic Operations:** Implementing thread-safe operations on memory locations, essential for concurrent programming.
    * **SIMD Support:**  Leveraging the s390's SIMD capabilities for optimized parallel processing, crucial for performance-intensive tasks like graphics or data manipulation.
    * **Address Manipulation:** Calculating memory addresses.
    * **Data Type Conversion:** Converting between different numerical representations.

5. **Address Specific Questions:**
    * **`.tq` extension:** The code explicitly checks for this. My answer is based directly on that check.
    * **Relationship to JavaScript:**  SIMD operations have a direct relationship to JavaScript's Typed Arrays and the WebAssembly SIMD proposal (now standardized). Atomic operations are relevant to shared memory concurrency in JavaScript/WebAssembly. Data loading/storing is fundamental to any language interacting with memory.
    * **Code Logic Reasoning:**  I pick a simpler case (like `kS390_LoadWord64`) and demonstrate the assumed input (an instruction object), the action (generating an `lg` assembly instruction), and the output (the generated assembly code).
    * **Common Programming Errors:** I focus on errors that relate to the *types* of operations being performed, like incorrect memory access patterns with SIMD or race conditions with atomic operations.

6. **Synthesize the Summary:** I combine the identified functionalities into a concise summary, emphasizing the code's role in generating s390 machine code for various operations, including memory access, atomics, and SIMD.

7. **Structure the Answer:** I organize my findings according to the prompt's requirements (functionality, `.tq` check, JavaScript relationship, code logic, common errors, and summary). This makes the answer clear and easy to follow.

Essentially, I'm working from the concrete (individual instructions) to the abstract (overall functionality), using my understanding of computer architecture, compilers, and JavaScript/WebAssembly concepts to interpret the code. The process involves pattern recognition, contextual awareness, and logical deduction.
这是V8 JavaScript引擎中s390架构的代码生成器的部分代码。它负责将高级的、与架构无关的中间表示（likely由V8的TurboFan优化编译器生成）转换为特定于s390架构的机器代码指令。

**功能归纳 (基于提供的代码片段):**

这段代码主要负责处理各种**数据加载、存储和原子操作**的指令生成，以及大量的**SIMD (Single Instruction, Multiple Data)** 向量运算指令的生成。  更具体地说，它包含了以下功能：

1. **加载指令生成:**
   - 加载各种大小的整数（8位、16位、32位、64位）。
   - 反向加载整数（用于处理字节序）。
   - 加载单精度和双精度浮点数。
   - 加载SIMD (128位) 向量数据。
   - 反向加载SIMD向量数据。
   - 特殊的加载指令，如 `Lay` (Load Address)，用于计算内存地址。
   - 带测试的加载指令 (`LoadAndTestWord32`, `LoadAndTestWord64`)。

2. **存储指令生成:**
   - 存储各种大小的整数。
   - 反向存储整数。
   - 存储单精度和双精度浮点数。
   - 存储SIMD向量数据。

3. **原子操作指令生成:**
   - 原子交换 (Exchange) 各种大小的整数。
   - 原子比较并交换 (Compare and Exchange) 各种大小的整数。
   - 原子加、减、与、或、异或 (Add, Sub, And, Or, Xor) 操作于 32 位和 64 位整数。

4. **SIMD 向量运算指令生成:**
   这段代码包含了大量的针对SIMD寄存器的操作，涵盖了：
   - **SIMD 加法、减法、乘法、除法、最小值、最大值、比较运算** (针对浮点数和整数的不同数据类型和精度)。
   - **SIMD 移位操作** (左移、算术右移、逻辑右移)。
   - **SIMD 单目运算** (绝对值、取反、平方根、ceil、floor、trunc、四舍五入到最近的整数)。
   - **SIMD 位运算** (与、或、异或、与非、非)。
   - **SIMD 车道 (Lane) 操作:**
     - 提取车道 (Extract Lane)。
     - 替换车道 (Replace Lane)。
   - **SIMD 扩展乘法** (ExtMul)。
   - **SIMD 全真 (All True) 检测。**
   - **SIMD 融合乘加/减 (QFM)。**
   - **SIMD 饱和加减 (AddSat, SubSat)。**
   - **SIMD 成对加法 (ExtAddPairwise)。**
   - **其他特定的SIMD指令** (例如 `I64x2Mul`, `I32x4GeU` 等)。
   - **SIMD 常量和零值加载。**
   - **SIMD 选择 (Select) 操作。**
   - **SIMD 数据类型转换。**
   - **SIMD 洗牌 (Shuffle) 和 混淆 (Swizzle)。**
   - **SIMD 位掩码 (BitMask)。**
   - **SIMD 点积 (Dot Product)。**
   - **SIMD 带符号饱和乘法并右移 (Q15MulRSatS)。**
   - **SIMD 计数设置位 (Popcnt)。**
   - **SIMD 数据类型提升和降级。**
   - **SIMD 截断到整数 (TruncSat)。**
   - **SIMD 从内存加载并填充 (LoadSplat)。**
   - **SIMD 从内存加载并扩展 (LoadExtend)。**
   - **SIMD 从内存加载并零扩展 (LoadZero)。**
   - **SIMD 从内存加载特定车道 (LoadLane)。**
   - **SIMD 存储特定车道 (StoreLane)。**

**关于文件扩展名和 JavaScript 关系:**

* **`.tq` 扩展名:**  你提供的代码是以 `.cc` 结尾的，所以它不是 Torque 源代码。Torque 是 V8 中用于生成高效内置函数的领域特定语言。如果文件以 `.tq` 结尾，那么它确实是 Torque 源代码。

* **与 JavaScript 的功能关系:**  这段代码与 JavaScript 的功能有着密切的关系，因为它负责生成执行 JavaScript 代码所需的机器码。
    - **数据加载和存储:** JavaScript 操作变量、对象属性等都需要从内存中加载数据和将数据存储回内存。
    - **原子操作:**  JavaScript 的 `SharedArrayBuffer` 和 `Atomics` 对象允许在共享内存上进行原子操作，这段代码就负责生成这些原子操作的机器码实现。
    - **SIMD 向量运算:**  JavaScript 的 WebAssembly SIMD 指令集允许开发者利用 SIMD 指令进行高性能的并行计算。这段代码实现了将 WebAssembly SIMD 指令翻译成 s390 架构的 SIMD 指令。

**JavaScript 示例 (与 SIMD 功能相关):**

```javascript
// 需要在支持 WebAssembly 和 SIMD 的环境中运行

const buffer = new SharedArrayBuffer(16);
const view = new Int32Array(buffer);

// WebAssembly 模块，使用 SIMD 指令
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 0, 13, 2, 1, 1, 96, 0, 1, 127, 1, 96, 0, 0, 3,
  2, 1, 0, 10, 11, 1, 9, 0, 65, 0, 253, 15, 0, 11
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 使用 Atomics 进行原子操作
Atomics.add(view, 0, 5);
console.log(view[0]); // 输出可能不是立即的 5，因为是原子操作

// 使用 SIMD (通过 WebAssembly)
// wasmCode 中 253, 15, 0 对应的是 i32x4.add 指令 (简化示例)
// 实际使用会更复杂，需要定义导入导出等
```

**代码逻辑推理 (假设输入与输出):**

假设输入一个表示 `kS390_LoadWord32` 指令的 `Instruction* instr` 对象，并且 `instr` 指定了要加载的内存地址在寄存器 `r2` 中，目标寄存器是 `r3`。

**假设输入:**
- `opcode` 为 `kS390_LoadWord32`
- `i.OutputRegister()` 返回 `r3`
- `i.MemoryOperand()` 返回一个 `MemOperand` 对象，其基址寄存器为 `r2`，偏移量为 0。

**预期输出 (生成的汇编指令):**
```assembly
l r3, 0(r2)
```

这段代码中的 `ASSEMBLE_LOAD_INTEGER(lg);` 宏会根据指令的大小选择合适的加载指令，对于 `kS390_LoadWord32` 来说，它会生成 `l` 指令。

**用户常见的编程错误 (与此代码生成的功能相关):**

1. **数据类型不匹配:**  在 JavaScript 或 WebAssembly 中，尝试将一个浮点数存储到整数类型的内存区域，或者反过来。这会导致类型错误或数据截断。这段代码生成了针对特定数据类型的加载和存储指令，如果高级代码中类型不匹配，可能会导致意外行为。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const intView = new Int32Array(buffer);
   const floatView = new Float32Array(buffer);

   floatView[0] = 3.14;
   console.log(intView[0]); // 错误: 尝试将浮点数解释为整数，结果不可预测

   intView[0] = 10;
   console.log(floatView[0]); // 错误: 尝试将整数解释为浮点数，可能会丢失精度
   ```

2. **原子操作的竞态条件 (不当使用):**  如果多个线程或 Web Workers 不正确地使用原子操作，仍然可能出现竞态条件。例如，在没有适当的同步机制下，多个线程可能同时尝试修改同一个内存位置，即使使用了原子操作，最终结果也可能不是预期的。

   ```javascript
   const sab = new SharedArrayBuffer(4);
   const view = new Int32Array(sab);

   // 线程 1
   Atomics.add(view, 0, 5);

   // 线程 2 (几乎同时)
   Atomics.add(view, 0, 10);

   // 最终 view[0] 的值应该是 15，但如果实现不正确，可能会出现错误。
   ```

3. **SIMD 操作中的数据对齐问题:**  在某些架构上，SIMD 指令对数据的内存对齐有要求。如果加载或存储的地址未对齐，可能会导致性能下降或程序崩溃。虽然 s390 架构对对齐要求相对宽松，但在其他架构上这是一个常见问题。

4. **SIMD 操作中向量长度不匹配:**  当使用 SIMD 指令时，操作数的向量长度必须匹配。例如，尝试将一个包含 4 个 32 位整数的向量与一个包含 8 个 16 位整数的向量进行加法运算，通常是不允许的，需要进行额外的转换或操作。

**这是第4部分，共5部分，请归纳一下它的功能:**

结合前文以及已知这是代码生成器的第四部分，可以推断这部分代码主要关注于**生成处理内存数据 (加载和存储) 以及执行并行计算 (SIMD) 和并发控制 (原子操作) 的机器码指令**。它是将高级的、架构无关的表示转换为可在 s390 架构上执行的低级指令的关键组成部分。它的功能是确保 JavaScript 代码能够有效地利用 s390 架构的特性，包括其向量处理能力和原子操作支持。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/code-generator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/code-generator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
(r1, r1);
      __ vlvg(i.OutputSimd128Register(), r0, MemOperand(r0, 1), Condition(3));
      __ vlvg(i.OutputSimd128Register(), r1, MemOperand(r0, 0), Condition(3));
      break;
    case kS390_LoadReverseSimd128: {
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      Simd128Register dst = i.OutputSimd128Register();
      if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
          is_uint12(operand.offset())) {
        __ vlbr(dst, operand, Condition(4));
      } else {
        __ lrvg(r0, operand);
        __ lrvg(r1, MemOperand(operand.rx(), operand.rb(),
                               operand.offset() + kSystemPointerSize));
        __ vlvgp(dst, r1, r0);
      }
      break;
    }
    case kS390_LoadWord64:
      ASSEMBLE_LOAD_INTEGER(lg);
      break;
    case kS390_LoadAndTestWord32: {
      ASSEMBLE_LOADANDTEST32(ltr, lt_z);
      break;
    }
    case kS390_LoadAndTestWord64: {
      ASSEMBLE_LOADANDTEST64(ltgr, ltg);
      break;
    }
    case kS390_LoadFloat32:
      ASSEMBLE_LOAD_FLOAT(LoadF32);
      break;
    case kS390_LoadDouble:
      ASSEMBLE_LOAD_FLOAT(LoadF64);
      break;
    case kS390_LoadSimd128: {
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode);
      __ vl(i.OutputSimd128Register(), operand, Condition(0));
      break;
    }
    case kS390_StoreWord8:
      ASSEMBLE_STORE_INTEGER(StoreU8);
      break;
    case kS390_StoreWord16:
      ASSEMBLE_STORE_INTEGER(StoreU16);
      break;
    case kS390_StoreWord32:
      ASSEMBLE_STORE_INTEGER(StoreU32);
      break;
    case kS390_StoreWord64:
      ASSEMBLE_STORE_INTEGER(StoreU64);
      break;
    case kS390_StoreReverse16:
      ASSEMBLE_STORE_INTEGER(strvh);
      break;
    case kS390_StoreReverse32:
      ASSEMBLE_STORE_INTEGER(strv);
      break;
    case kS390_StoreReverse64:
      ASSEMBLE_STORE_INTEGER(strvg);
      break;
    case kS390_StoreReverseSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
          is_uint12(operand.offset())) {
        __ vstbr(i.InputSimd128Register(index), operand, Condition(4));
      } else {
        __ vlgv(r0, i.InputSimd128Register(index), MemOperand(r0, 1),
                Condition(3));
        __ vlgv(r1, i.InputSimd128Register(index), MemOperand(r0, 0),
                Condition(3));
        __ strvg(r0, operand);
        __ strvg(r1, MemOperand(operand.rx(), operand.rb(),
                                operand.offset() + kSystemPointerSize));
      }
      break;
    }
    case kS390_StoreFloat32:
      ASSEMBLE_STORE_FLOAT32();
      break;
    case kS390_StoreDouble:
      ASSEMBLE_STORE_DOUBLE();
      break;
    case kS390_StoreSimd128: {
      size_t index = 0;
      AddressingMode mode = kMode_None;
      MemOperand operand = i.MemoryOperand(&mode, &index);
      __ vst(i.InputSimd128Register(index), operand, Condition(0));
      break;
    }
    case kS390_Lay: {
      MemOperand mem = i.MemoryOperand();
      if (!is_int20(mem.offset())) {
        // Add directly to the base register in case the index register (rx) is
        // r0.
        DCHECK(is_int32(mem.offset()));
        __ AddS64(ip, mem.rb(), Operand(mem.offset()));
        mem = MemOperand(mem.rx(), ip);
      }
      __ lay(i.OutputRegister(), mem);
      break;
    }
    case kAtomicExchangeInt8:
    case kAtomicExchangeUint8: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      __ la(r1, MemOperand(base, index));
      __ AtomicExchangeU8(r1, value, output, r0);
      if (opcode == kAtomicExchangeInt8) {
        __ LoadS8(output, output);
      } else {
        __ LoadU8(output, output);
      }
      break;
    }
    case kAtomicExchangeInt16:
    case kAtomicExchangeUint16: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      bool reverse_bytes = is_wasm_on_be(info());
      __ la(r1, MemOperand(base, index));
      Register value_ = value;
      if (reverse_bytes) {
        value_ = ip;
        __ lrvr(value_, value);
        __ ShiftRightU32(value_, value_, Operand(16));
      }
      __ AtomicExchangeU16(r1, value_, output, r0);
      if (reverse_bytes) {
        __ lrvr(output, output);
        __ ShiftRightU32(output, output, Operand(16));
      }
      if (opcode == kAtomicExchangeInt16) {
        __ lghr(output, output);
      } else {
        __ llghr(output, output);
      }
      break;
    }
    case kAtomicExchangeWord32: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      Label do_cs;
      bool reverse_bytes = is_wasm_on_be(info());
      __ lay(r1, MemOperand(base, index));
      Register value_ = value;
      if (reverse_bytes) {
        value_ = ip;
        __ lrvr(value_, value);
      }
      __ LoadU32(output, MemOperand(r1));
      __ bind(&do_cs);
      __ cs(output, value_, MemOperand(r1));
      __ bne(&do_cs, Label::kNear);
      if (reverse_bytes) {
        __ lrvr(output, output);
        __ LoadU32(output, output);
      }
      break;
    }
    case kAtomicCompareExchangeInt8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_BYTE(LoadS8);
      break;
    case kAtomicCompareExchangeUint8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_BYTE(LoadU8);
      break;
    case kAtomicCompareExchangeInt16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(LoadS16);
      break;
    case kAtomicCompareExchangeUint16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_HALFWORD(LoadU16);
      break;
    case kAtomicCompareExchangeWord32:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_WORD();
      break;
#define ATOMIC_BINOP_CASE(op, inst)                                          \
  case kAtomic##op##Int8:                                                    \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, [&]() {                                 \
      intptr_t shift_right = static_cast<intptr_t>(shift_amount);            \
      __ srlk(result, prev, Operand(shift_right));                           \
      __ LoadS8(result, result);                                             \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Uint8:                                                   \
    ASSEMBLE_ATOMIC_BINOP_BYTE(inst, [&]() {                                 \
      int rotate_left = shift_amount == 0 ? 0 : 64 - shift_amount;           \
      __ RotateInsertSelectBits(result, prev, Operand(56), Operand(63),      \
                                Operand(static_cast<intptr_t>(rotate_left)), \
                                true);                                       \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Int16:                                                   \
    ASSEMBLE_ATOMIC_BINOP_HALFWORD(inst, [&]() {                             \
      intptr_t shift_right = static_cast<intptr_t>(shift_amount);            \
      __ srlk(result, prev, Operand(shift_right));                           \
      if (is_wasm_on_be(info())) {                                           \
        __ lrvr(result, result);                                             \
        __ ShiftRightS32(result, result, Operand(16));                       \
      }                                                                      \
      __ LoadS16(result, result);                                            \
    });                                                                      \
    break;                                                                   \
  case kAtomic##op##Uint16:                                                  \
    ASSEMBLE_ATOMIC_BINOP_HALFWORD(inst, [&]() {                             \
      int rotate_left = shift_amount == 0 ? 0 : 64 - shift_amount;           \
      __ RotateInsertSelectBits(result, prev, Operand(48), Operand(63),      \
                                Operand(static_cast<intptr_t>(rotate_left)), \
                                true);                                       \
      if (is_wasm_on_be(info())) {                                           \
        __ lrvr(result, result);                                             \
        __ ShiftRightU32(result, result, Operand(16));                       \
      }                                                                      \
    });                                                                      \
    break;
      ATOMIC_BINOP_CASE(Add, AddS32)
      ATOMIC_BINOP_CASE(Sub, SubS32)
      ATOMIC_BINOP_CASE(And, And)
      ATOMIC_BINOP_CASE(Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor)
#undef ATOMIC_BINOP_CASE
    case kAtomicAddWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(laa, AddS32);
      break;
    case kAtomicSubWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(LoadAndSub32, SubS32);
      break;
    case kAtomicAndWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lan, AndP);
      break;
    case kAtomicOrWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lao, OrP);
      break;
    case kAtomicXorWord32:
      ASSEMBLE_ATOMIC_BINOP_WORD(lax, XorP);
      break;
    case kS390_Word64AtomicAddUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laag, AddS64);
      break;
    case kS390_Word64AtomicSubUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(LoadAndSub64, SubS64);
      break;
    case kS390_Word64AtomicAndUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(lang, AndP);
      break;
    case kS390_Word64AtomicOrUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laog, OrP);
      break;
    case kS390_Word64AtomicXorUint64:
      ASSEMBLE_ATOMIC_BINOP_WORD64(laxg, XorP);
      break;
    case kS390_Word64AtomicExchangeUint64: {
      Register base = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register output = i.OutputRegister();
      bool reverse_bytes = is_wasm_on_be(info());
      Label do_cs;
      Register value_ = value;
      __ la(r1, MemOperand(base, index));
      if (reverse_bytes) {
        value_ = ip;
        __ lrvgr(value_, value);
      }
      __ lg(output, MemOperand(r1));
      __ bind(&do_cs);
      __ csg(output, value_, MemOperand(r1));
      __ bne(&do_cs, Label::kNear);
      if (reverse_bytes) {
        __ lrvgr(output, output);
      }
      break;
    }
    case kS390_Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC64_COMP_EXCHANGE_WORD64();
      break;
      // Simd Support.
#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)

#define EMIT_SIMD_SHIFT(name)                                     \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputRegister(1), kScratchDoubleReg);               \
    break;                                                        \
  }
      SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Min)              \
  V(F64x2Max)              \
  V(F64x2Eq)               \
  V(F64x2Ne)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F64x2Pmin)             \
  V(F64x2Pmax)             \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Ne)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(F32x4Pmin)             \
  V(F32x4Pmax)             \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2Ne)               \
  V(I64x2GtS)              \
  V(I64x2GeS)              \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4Eq)               \
  V(I32x4Ne)               \
  V(I32x4GtS)              \
  V(I32x4GeS)              \
  V(I32x4GtU)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8Eq)               \
  V(I16x8Ne)               \
  V(I16x8GtS)              \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8RoundingAverageU) \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16Eq)               \
  V(I8x16Ne)               \
  V(I8x16GtS)              \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define EMIT_SIMD_BINOP(name)                                     \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1));                           \
    break;                                                        \
  }
      SIMD_BINOP_LIST(EMIT_SIMD_BINOP)
#undef EMIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_UNOP_LIST(V)                                     \
  V(F64x2Splat, Simd128Register, DoubleRegister)              \
  V(F64x2Abs, Simd128Register, Simd128Register)               \
  V(F64x2Neg, Simd128Register, Simd128Register)               \
  V(F64x2Sqrt, Simd128Register, Simd128Register)              \
  V(F64x2Ceil, Simd128Register, Simd128Register)              \
  V(F64x2Floor, Simd128Register, Simd128Register)             \
  V(F64x2Trunc, Simd128Register, Simd128Register)             \
  V(F64x2NearestInt, Simd128Register, Simd128Register)        \
  V(F32x4Splat, Simd128Register, DoubleRegister)              \
  V(F32x4Abs, Simd128Register, Simd128Register)               \
  V(F32x4Neg, Simd128Register, Simd128Register)               \
  V(F32x4Sqrt, Simd128Register, Simd128Register)              \
  V(F32x4Ceil, Simd128Register, Simd128Register)              \
  V(F32x4Floor, Simd128Register, Simd128Register)             \
  V(F32x4Trunc, Simd128Register, Simd128Register)             \
  V(F32x4NearestInt, Simd128Register, Simd128Register)        \
  V(I64x2Splat, Simd128Register, Register)                    \
  V(I64x2Abs, Simd128Register, Simd128Register)               \
  V(I64x2Neg, Simd128Register, Simd128Register)               \
  V(I64x2SConvertI32x4Low, Simd128Register, Simd128Register)  \
  V(I64x2SConvertI32x4High, Simd128Register, Simd128Register) \
  V(I64x2UConvertI32x4Low, Simd128Register, Simd128Register)  \
  V(I64x2UConvertI32x4High, Simd128Register, Simd128Register) \
  V(I32x4Splat, Simd128Register, Register)                    \
  V(I32x4Abs, Simd128Register, Simd128Register)               \
  V(I32x4Neg, Simd128Register, Simd128Register)               \
  V(I32x4SConvertI16x8Low, Simd128Register, Simd128Register)  \
  V(I32x4SConvertI16x8High, Simd128Register, Simd128Register) \
  V(I32x4UConvertI16x8Low, Simd128Register, Simd128Register)  \
  V(I32x4UConvertI16x8High, Simd128Register, Simd128Register) \
  V(I16x8Splat, Simd128Register, Register)                    \
  V(I16x8Abs, Simd128Register, Simd128Register)               \
  V(I16x8Neg, Simd128Register, Simd128Register)               \
  V(I16x8SConvertI8x16Low, Simd128Register, Simd128Register)  \
  V(I16x8SConvertI8x16High, Simd128Register, Simd128Register) \
  V(I16x8UConvertI8x16Low, Simd128Register, Simd128Register)  \
  V(I16x8UConvertI8x16High, Simd128Register, Simd128Register) \
  V(I8x16Splat, Simd128Register, Register)                    \
  V(I8x16Abs, Simd128Register, Simd128Register)               \
  V(I8x16Neg, Simd128Register, Simd128Register)               \
  V(S128Not, Simd128Register, Simd128Register)

#define EMIT_SIMD_UNOP(name, dtype, stype)         \
  case kS390_##name: {                             \
    __ name(i.Output##dtype(), i.Input##stype(0)); \
    break;                                         \
  }
      SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_EXTRACT_LANE_LIST(V)     \
  V(F64x2ExtractLane, DoubleRegister) \
  V(F32x4ExtractLane, DoubleRegister) \
  V(I64x2ExtractLane, Register)       \
  V(I32x4ExtractLane, Register)       \
  V(I16x8ExtractLaneU, Register)      \
  V(I16x8ExtractLaneS, Register)      \
  V(I8x16ExtractLaneU, Register)      \
  V(I8x16ExtractLaneS, Register)

#define EMIT_SIMD_EXTRACT_LANE(name, dtype)                               \
  case kS390_##name: {                                                    \
    __ name(i.Output##dtype(), i.InputSimd128Register(0), i.InputInt8(1), \
            kScratchReg);                                                 \
    break;                                                                \
  }
      SIMD_EXTRACT_LANE_LIST(EMIT_SIMD_EXTRACT_LANE)
#undef EMIT_SIMD_EXTRACT_LANE
#undef SIMD_EXTRACT_LANE_LIST

#define SIMD_REPLACE_LANE_LIST(V)     \
  V(F64x2ReplaceLane, DoubleRegister) \
  V(F32x4ReplaceLane, DoubleRegister) \
  V(I64x2ReplaceLane, Register)       \
  V(I32x4ReplaceLane, Register)       \
  V(I16x8ReplaceLane, Register)       \
  V(I8x16ReplaceLane, Register)

#define EMIT_SIMD_REPLACE_LANE(name, stype)                       \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.Input##stype(2), i.InputInt8(1), kScratchReg);      \
    break;                                                        \
  }
      SIMD_REPLACE_LANE_LIST(EMIT_SIMD_REPLACE_LANE)
#undef EMIT_SIMD_REPLACE_LANE
#undef SIMD_REPLACE_LANE_LIST

#define SIMD_EXT_MUL_LIST(V) \
  V(I64x2ExtMulLowI32x4S)    \
  V(I64x2ExtMulHighI32x4S)   \
  V(I64x2ExtMulLowI32x4U)    \
  V(I64x2ExtMulHighI32x4U)   \
  V(I32x4ExtMulLowI16x8S)    \
  V(I32x4ExtMulHighI16x8S)   \
  V(I32x4ExtMulLowI16x8U)    \
  V(I32x4ExtMulHighI16x8U)   \
  V(I16x8ExtMulLowI8x16S)    \
  V(I16x8ExtMulHighI8x16S)   \
  V(I16x8ExtMulLowI8x16U)    \
  V(I16x8ExtMulHighI8x16U)

#define EMIT_SIMD_EXT_MUL(name)                                   \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchDoubleReg);        \
    break;                                                        \
  }
      SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)

#define EMIT_SIMD_ALL_TRUE(name)                                        \
  case kS390_##name: {                                                  \
    __ name(i.OutputRegister(), i.InputSimd128Register(0), kScratchReg, \
            kScratchDoubleReg);                                         \
    break;                                                              \
  }
      SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)

#define EMIT_SIMD_QFM(name)                                        \
  case kS390_##name: {                                             \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0),  \
            i.InputSimd128Register(1), i.InputSimd128Register(2)); \
    break;                                                         \
  }
      SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_ADD_SUB_SAT_LIST(V) \
  V(I16x8AddSatS)                \
  V(I16x8SubSatS)                \
  V(I16x8AddSatU)                \
  V(I16x8SubSatU)                \
  V(I8x16AddSatS)                \
  V(I8x16SubSatS)                \
  V(I8x16AddSatU)                \
  V(I8x16SubSatU)

#define EMIT_SIMD_ADD_SUB_SAT(name)                               \
  case kS390_##name: {                                            \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0), \
            i.InputSimd128Register(1), kScratchDoubleReg,         \
            i.ToSimd128Register(instr->TempAt(0)));               \
    break;                                                        \
  }
      SIMD_ADD_SUB_SAT_LIST(EMIT_SIMD_ADD_SUB_SAT)
#undef EMIT_SIMD_ADD_SUB_SAT
#undef SIMD_ADD_SUB_SAT_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)

#define EMIT_SIMD_EXT_ADD_PAIRWISE(name)                               \
  case kS390_##name: {                                                 \
    __ name(i.OutputSimd128Register(), i.InputSimd128Register(0),      \
            kScratchDoubleReg, i.ToSimd128Register(instr->TempAt(0))); \
    break;                                                             \
  }
      SIMD_EXT_ADD_PAIRWISE_LIST(EMIT_SIMD_EXT_ADD_PAIRWISE)
#undef EMIT_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

    case kS390_I64x2Mul: {
      __ I64x2Mul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), r0, r1, ip);
      break;
    }
    case kS390_I32x4GeU: {
      __ I32x4GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I16x8GeU: {
      __ I16x8GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16GeU: {
      __ I8x16GeU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    // vector boolean unops
    case kS390_V128AnyTrue: {
      __ V128AnyTrue(i.OutputRegister(), i.InputSimd128Register(0),
                     kScratchReg);
      break;
    }
    // vector bitwise ops
    case kS390_S128Const: {
      uint64_t low = make_uint64(i.InputUint32(1), i.InputUint32(0));
      uint64_t high = make_uint64(i.InputUint32(3), i.InputUint32(2));
      __ S128Const(i.OutputSimd128Register(), high, low, r0, ip);
      break;
    }
    case kS390_S128Zero: {
      Simd128Register dst = i.OutputSimd128Register();
      __ S128Zero(dst, dst);
      break;
    }
    case kS390_S128AllOnes: {
      Simd128Register dst = i.OutputSimd128Register();
      __ S128AllOnes(dst, dst);
      break;
    }
    case kS390_S128Select: {
      Simd128Register dst = i.OutputSimd128Register();
      Simd128Register mask = i.InputSimd128Register(0);
      Simd128Register src1 = i.InputSimd128Register(1);
      Simd128Register src2 = i.InputSimd128Register(2);
      __ S128Select(dst, src1, src2, mask);
      break;
    }
    // vector conversions
    case kS390_I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_I32x4UConvertF32x4: {
      __ I32x4UConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_F32x4SConvertI32x4: {
      __ F32x4SConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_F32x4UConvertI32x4: {
      __ F32x4UConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchReg);
      break;
    }
    case kS390_I16x8SConvertI32x4: {
      __ I16x8SConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1));
      break;
    }
    case kS390_I8x16SConvertI16x8: {
      __ I8x16SConvertI16x8(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1));
      break;
    }
    case kS390_I16x8UConvertI32x4: {
      __ I16x8UConvertI32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16UConvertI16x8: {
      __ I8x16UConvertI16x8(i.OutputSimd128Register(),
                            i.InputSimd128Register(0),
                            i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I8x16Shuffle: {
      uint64_t low = make_uint64(i.InputUint32(3), i.InputUint32(2));
      uint64_t high = make_uint64(i.InputUint32(5), i.InputUint32(4));
      __ I8x16Shuffle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), high, low, r0, ip,
                      kScratchDoubleReg);
      break;
    }
    case kS390_I8x16Swizzle: {
      __ I8x16Swizzle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), r0, r1, kScratchDoubleReg);
      break;
    }
    case kS390_I64x2BitMask: {
      __ I64x2BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I32x4BitMask: {
      __ I32x4BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I16x8BitMask: {
      __ I16x8BitMask(i.OutputRegister(), i.InputSimd128Register(0),
                      kScratchReg, kScratchDoubleReg);
      break;
    }
    case kS390_I8x16BitMask: {
      __ I8x16BitMask(i.OutputRegister(), i.InputSimd128Register(0), r0, ip,
                      kScratchDoubleReg);
      break;
    }
    case kS390_I32x4DotI16x8S: {
      __ I32x4DotI16x8S(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }

    case kS390_I16x8DotI8x16S: {
      __ I16x8DotI8x16S(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kS390_I32x4DotI8x16AddS: {
      __ I32x4DotI8x16AddS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                           i.InputSimd128Register(1), i.InputSimd128Register(2),
                           kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kS390_I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg,
                          i.ToSimd128Register(instr->TempAt(0)),
                          i.ToSimd128Register(instr->TempAt(1)));
      break;
    }
    case kS390_I8x16Popcnt: {
      __ I8x16Popcnt(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2ConvertLowI32x4S: {
      __ F64x2ConvertLowI32x4S(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2ConvertLowI32x4U: {
      __ F64x2ConvertLowI32x4U(i.OutputSimd128Register(),
                               i.InputSimd128Register(0));
      break;
    }
    case kS390_F64x2PromoteLowF32x4: {
      __ F64x2PromoteLowF32x4(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), kScratchDoubleReg, r0,
                              r1, ip);
      break;
    }
    case kS390_F32x4DemoteF64x2Zero: {
      __ F32x4DemoteF64x2Zero(i.OutputSimd128Register(),
                              i.InputSimd128Register(0), kScratchDoubleReg, r0,
                              r1, ip);
      break;
    }
    case kS390_I32x4TruncSatF64x2SZero: {
      __ I32x4TruncSatF64x2SZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kS390_I32x4TruncSatF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
#define LOAD_SPLAT(type)                           \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadAndSplat##type##LE(dst, operand, kScratchReg);
    case kS390_S128Load64Splat: {
      LOAD_SPLAT(64x2);
      break;
    }
    case kS390_S128Load32Splat: {
      LOAD_SPLAT(32x4);
      break;
    }
    case kS390_S128Load16Splat: {
      LOAD_SPLAT(16x8);
      break;
    }
    case kS390_S128Load8Splat: {
      LOAD_SPLAT(8x16);
      break;
    }
#undef LOAD_SPLAT
#define LOAD_EXTEND(type)                          \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadAndExtend##type##LE(dst, operand, kScratchReg);
    case kS390_S128Load32x2U: {
      LOAD_EXTEND(32x2U);
      break;
    }
    case kS390_S128Load32x2S: {
      LOAD_EXTEND(32x2S);
      break;
    }
    case kS390_S128Load16x4U: {
      LOAD_EXTEND(16x4U);
      break;
    }
    case kS390_S128Load16x4S: {
      LOAD_EXTEND(16x4S);
      break;
    }
    case kS390_S128Load8x8U: {
      LOAD_EXTEND(8x8U);
      break;
    }
    case kS390_S128Load8x8S: {
      LOAD_EXTEND(8x8S);
      break;
    }
#undef LOAD_EXTEND
#define LOAD_AND_ZERO(type)                        \
  AddressingMode mode = kMode_None;                \
  MemOperand operand = i.MemoryOperand(&mode);     \
  Simd128Register dst = i.OutputSimd128Register(); \
  __ LoadV##type##ZeroLE(dst, operand, kScratchReg);
    case kS390_S128Load32Zero: {
      LOAD_AND_ZERO(32);
      break;
    }
    case kS390_S128Load64Zero: {
      LOAD_AND_ZERO(64);
      break;
    }
#undef LOAD_AND_ZERO
#undef LOAD_EXTEND
#define LOAD_LANE(type, lane)                          \
  AddressingMode mode = kMode_None;                    \
  size_t index = 2;                                    \
  MemOperand operand = i.MemoryOperand(&mode, &index); \
  Simd128Register dst = i.OutputSimd128Register();     \
  DCHECK_EQ(dst, i.InputSimd128Register(0));           \
  __ LoadLane##type##LE(dst, operand, lane, kScratchReg);
    case kS390_S128Load8Lane: {
      LOAD_LANE(8, 15 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load16Lane: {
      LOAD_LANE(16, 7 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load32Lane: {
      LOAD_LANE(32, 3 - i.InputUint8(1));
      break;
    }
    case kS390_S128Load64Lane: {
      LOAD_LANE(64, 1 - i.InputUint8(1));
      break;
    }
#undef LOAD_LANE
#define STORE_LANE(type, lane)                         \
  AddressingMode mode = kMode_None;                    \
  size_t index = 2;                                    \
  MemOperand operand = i.MemoryOperand(&mode, &index); \
  Simd128Register src = i.InputSimd128Register(0);     \
  __ StoreLane##type##LE(src, operand, lane, kScratchReg);
    case kS390_S128Store8Lane: {
      STORE_LANE(8, 15 - i.InputUint8(1));
      break;
    }
    case kS390_S128Store16Lane: {
      STORE_LANE(16, 7 - i.InputUint8(1));
      break;
    }
    case kS390_S128St
```