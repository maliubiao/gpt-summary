Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understanding the Request:** The core request is to analyze the functionality of the provided C++ code snippet from `v8/src/execution/arm/simulator-arm.cc`. Key aspects to identify are: its purpose, its relation to JavaScript (if any), code logic, potential errors, and a summary. The prompt also mentions it's part 4 of 7, implying a larger context (an ARM simulator within V8).

2. **Initial Scan and Keywords:** A quick scan reveals keywords like `Simulator`, `Instruction`, `DecodeType`, `register`, `ReadW`, `WriteW`, `VFP`, `Neon`, and specific ARM instruction mnemonics (e.g., `Uxtb`, `Rev`, `SMMUL`, `udiv`, `vmov`, `vadd`, `vmul`, `vcmp`). These immediately suggest the code is involved in simulating ARM instructions. The presence of "VFP" (Vector Floating Point) and "Neon" indicates support for SIMD and floating-point operations.

3. **Decomposition by `DecodeType` Functions:** The code is structured around `DecodeType` functions (e.g., `DecodeType0`, `DecodeType1`, etc.). This strongly suggests the structure mirrors the ARM instruction set encoding, where different bit patterns in the instruction correspond to different instruction types. The comments within each `case` block often describe specific ARM instructions. This is the primary way to understand the code's functionality.

4. **Focusing on Key Operations:**  Within each `DecodeType` function, observe the core actions:
    * **Fetching Operands:**  `get_register()`, `instr->RmValue()`, `instr->SImmed24Value()`, etc. These methods extract register values and immediate operands from the simulated instruction.
    * **Performing Operations:** Arithmetic (`+`, `-`, `*`, `/`), bitwise operations (`&`, `|`, `>>`, `<<`, `ByteReverse`, `ReverseBits`), comparisons, and floating-point operations (through `Float32`, `Float64`).
    * **Storing Results:** `set_register()`, `WriteW()`, `WriteB()`, `set_d_register()`, `set_s_register()`, `set_neon_register()`. These methods write results back to simulated registers or memory.
    * **Control Flow:** `set_pc()` (setting the program counter) indicates handling of branches.
    * **Specialized Units:** The code interacts with simulated VFP and Neon units, handling their specific instruction formats and register access.

5. **Identifying JavaScript Relevance:**  The connection to JavaScript isn't direct in this *specific* file. However, the context (`v8/src/execution`) strongly implies this simulator is used by V8 to execute JavaScript code on ARM architectures. When V8 encounters JavaScript code, it eventually translates it into machine code. On ARM, this code could be directly executed by the hardware *or* by this simulator, especially during development, testing, or when JIT compilation isn't yet active. Therefore, the *functionality* being simulated (arithmetic, memory access, etc.) directly relates to the underlying operations needed to run JavaScript. The floating-point and SIMD instructions are particularly relevant to JavaScript's number handling and potential for optimized operations.

6. **Inferring Code Logic and Examples:** By looking at individual `case` blocks and the ARM instruction mnemonics, it's possible to infer the logic:
    * **Example: `Uxtb`:** Unsigned Extend Byte. Takes the least significant byte of a register, zero-extends it to 32 bits, and stores it in another register. A simple JavaScript example would be something like `let x = 0xAABBCCDD; let y = x & 0xFF;` where the simulator needs to perform the equivalent bitwise AND and zero-extension.
    * **Example: `vadd`:** Vector Add. Adds two floating-point registers. A JavaScript example would be `let a = 1.0; let b = 2.0; let c = a + b;`, which might involve the simulator executing a `vadd` instruction.

7. **Considering User Programming Errors:**  The simulator needs to handle the effects of instructions, even if they are the result of programming errors. While the simulator itself doesn't *detect* user errors in the JavaScript source code, it *demonstrates* what happens at the machine level when such errors manifest. For instance:
    * **Integer Overflow:** If a JavaScript operation results in an integer overflow on ARM, the simulator will reflect the wraparound behavior of the underlying hardware.
    * **Floating-Point Errors (NaN, Infinity):**  The VFP simulation includes handling NaN and division by zero, mirroring how these are treated in JavaScript.

8. **Formulating Assumptions for Input and Output:**  For specific instruction sequences, we can make assumptions about register values and predict the output. This helps illustrate the step-by-step execution of the simulator.

9. **Summarizing the Functionality:** The key takeaway is that `simulator-arm.cc` provides a software-based emulation of the ARM architecture. It allows V8 developers to test and debug code without needing physical ARM hardware. It's crucial for porting V8 to ARM and ensuring correct behavior.

10. **Addressing the `.tq` Question:** The prompt explicitly asks about the `.tq` extension. Since the provided code is `.cc`, it's standard C++. Torque is a V8-specific language for defining built-in functions, often related to low-level operations. If the file *were* `.tq`, it would be written in Torque and would have a more direct connection to defining the behavior of JavaScript built-ins.

11. **Structure and Iteration:** The process isn't strictly linear. You might jump back and forth between identifying keywords, examining `DecodeType` functions, and thinking about the JavaScript connection. The structure of the provided analysis reflects a logical flow of understanding, starting from the general purpose and drilling down into specifics.
```
**这是第4部分，共7部分**

基于您提供的代码片段，我们可以归纳出 `v8/src/execution/arm/simulator-arm.cc` 的以下功能：

**核心功能：模拟 ARM 指令集的执行**

这个代码片段是 V8 JavaScript 引擎中 ARM 架构模拟器的核心部分。它的主要职责是**解码并执行各种 ARM 指令**。

**具体功能点：**

1. **指令类型分发：** 通过 `DecodeType` 函数（如 `DecodeType0`, `DecodeType1` 等）将 ARM 指令根据其编码格式分发到相应的处理逻辑。这对应于 ARM 指令集架构的不同指令类型。

2. **数据处理指令模拟 (DecodeType0, DecodeType1, DecodeType3, db_x, ib_x)：**
    *   **算术运算：** 模拟加法、减法等基本算术运算 (`set_register(rd, rn_val + static_cast<int16_t>(rm_val));`)。
    *   **逻辑运算：** 模拟位运算，如反转字节 (`ByteReverse`)、位反转 (`base::bits::ReverseBits`)。
    *   **移位和旋转：** 处理带移位的操作 (`rm_val >> 8`)。
    *   **乘法和乘加运算：** 模拟乘法 (`base::bits::SignedMulHigh32`) 和乘加 (`base::bits::SignedMulHighAndAdd32`) 指令。
    *   **除法运算：** 模拟有符号和无符号除法 (`base::bits::SignedDiv32`, `base::bits::UnsignedDiv32`)。
    *   **位域操作：** 模拟位域提取 (`ubfx`, `sbfx`)、位域清除/插入 (`bfc`, `bfi`) 指令。
    *   **数据加载和存储：** 模拟从内存加载数据 (`ReadB`, `ReadW`) 和将数据存储到内存 (`WriteB`, `WriteW`) 的操作。

3. **块数据传输指令模拟 (DecodeType4)：**
    *   模拟加载多个寄存器 (`ldm`) 和存储多个寄存器 (`stm`) 的指令 (`HandleRList`)。

4. **分支指令模拟 (DecodeType5)：**
    *   模拟无条件分支 (`b`) 和带链接分支 (`bl`) 指令，更新程序计数器 (`set_pc`) 和链接寄存器 (`set_register(lr, ...)`)。

5. **协处理器指令模拟 (DecodeType6, DecodeType7)：**
    *   处理与协处理器相关的指令，特别是：
        *   **VFP (Vector Floating Point) 指令 (DecodeTypeVFP)：** 模拟浮点运算，包括加法 (`vadd`)、减法 (`vsub`)、乘法 (`vmul`)、除法 (`vdiv`)、绝对值 (`vabs`)、取反 (`vneg`)、比较 (`vcmp`)、平方根 (`vsqrt`)、类型转换 (`vcvt`)，以及 VFP 寄存器和 ARM 核心寄存器之间的数据传输 (`DecodeVMOVBetweenCoreAndSinglePrecisionRegisters`)。
        *   **CP15 指令 (DecodeTypeCP15)：** 处理系统控制协处理器 CP15 的指令，例如内存屏障操作。

6. **软件中断指令模拟 (DecodeType7)：**
    *   模拟软件中断指令 (`SoftwareInterrupt`)。

**关于 .tq 结尾和 JavaScript 功能的关系：**

*   您提供的 `v8/src/execution/arm/simulator-arm.cc` 文件以 `.cc` 结尾，**不是 Torque 源代码**。它是标准的 C++ 源代码。
*   如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。Torque 是一种用于定义 V8 内置函数和运行时支持的领域特定语言。

**与 JavaScript 功能的关系：**

`v8/src/execution/arm/simulator-arm.cc` 模拟了在 ARM 架构上执行代码的过程。当 V8 引擎需要在 ARM 平台上运行 JavaScript 代码时，它可以：

1. **直接生成 ARM 机器码并由硬件执行（JIT 编译）：** 这是通常的高性能执行方式。
2. **使用模拟器执行：** 这通常用于开发、测试、调试或者在没有真实 ARM 硬件的环境中运行。

因此，`simulator-arm.cc` 中模拟的每一条 ARM 指令，都可能对应着 JavaScript 代码在底层执行时需要进行的某个操作。

**JavaScript 示例说明：**

```javascript
let a = 10;
let b = 5;
let sum = a + b;
let isGreater = a > b;
let reversedBytes = 0xAABBCCDD;
// ... 一些对 reversedBytes 进行字节操作的代码
```

在上面的 JavaScript 代码中：

*   `let sum = a + b;`  在模拟器中可能会对应模拟 ARM 的加法指令（如 `ADD`），由 `DecodeType0` 或 `DecodeType1` 中的逻辑处理。
*   `let isGreater = a > b;`  在模拟器中可能会对应模拟 ARM 的比较指令（如 `CMP`）以及后续的条件分支指令。
*   对 `reversedBytes` 的字节操作，在模拟器中可能会对应模拟字节反转指令（如 `REV`），由 `DecodeType1` 中的相关逻辑处理。
*   涉及浮点数的运算，例如：
    ```javascript
    let x = 1.5;
    let y = 2.5;
    let product = x * y;
    ```
    在模拟器中会涉及到 `DecodeTypeVFP` 中模拟的 VFP 乘法指令 (`vmul`)。

**代码逻辑推理 (假设输入与输出)：**

假设我们模拟执行以下 ARM 指令序列（简化表示）：

1. `MOV R0, #10`  // 将立即数 10 移动到寄存器 R0
2. `MOV R1, #5`   // 将立即数 5  移动到寄存器 R1
3. `ADD R2, R0, R1` // 将 R0 和 R1 的值相加，结果存入 R2

**假设输入：**

*   程序计数器 PC 指向第一条指令的地址。
*   寄存器 R0, R1, R2 的初始值为任意值（例如 0）。

**模拟执行过程：**

1. **执行 `MOV R0, #10`：**
    *   `DecodeType0` 或 `DecodeType1` 中的相应逻辑会被调用。
    *   模拟器会将值 10 写入到模拟的寄存器 R0 中。
    *   PC 指向下一条指令。
    *   **模拟器内部状态：** `registers_[0] = 10`

2. **执行 `MOV R1, #5`：**
    *   `DecodeType0` 或 `DecodeType1` 中的相应逻辑会被调用。
    *   模拟器会将值 5 写入到模拟的寄存器 R1 中。
    *   PC 指向下一条指令。
    *   **模拟器内部状态：** `registers_[0] = 10`, `registers_[1] = 5`

3. **执行 `ADD R2, R0, R1`：**
    *   `DecodeType0` 或 `DecodeType1` 中的相应逻辑会被调用。
    *   模拟器会读取 `registers_[0]` (10) 和 `registers_[1]` (5)。
    *   计算 10 + 5 = 15。
    *   将结果 15 写入到模拟的寄存器 R2 中。
    *   PC 指向下一条指令。
    *   **模拟器内部状态：** `registers_[0] = 10`, `registers_[1] = 5`, `registers_[2] = 15`

**假设输出：**

*   执行完成后，模拟器中寄存器 R0 的值为 10，R1 的值为 5，R2 的值为 15。
*   程序计数器 PC 指向指令序列之后的位置。

**用户常见的编程错误举例说明：**

虽然这个代码片段本身是模拟器代码，但它模拟的指令正是用户在编写低级代码（如汇编或编译器生成的代码）时可能犯错的地方。以下是一些例子：

*   **寄存器使用错误：** 错误地使用了未初始化的寄存器，例如在上面的例子中，如果 `ADD` 指令误写成使用了未赋值的 `R3`，模拟器会按照指令执行，但结果将是不可预测的。
*   **数据类型不匹配：**  例如，尝试将一个浮点数直接赋值给一个期望整数的内存位置，可能会导致数据截断或错误解释。在 VFP 模拟部分，如果 JavaScript 传递了错误的类型，模拟器会按照 VFP 指令的定义进行处理。
*   **内存访问错误：** 尝试访问未分配或超出范围的内存地址。模拟器需要有相应的机制来处理这些错误，尽管在提供的代码片段中没有直接展示内存访问错误的详细处理。
*   **浮点数精度问题：**  浮点运算可能存在精度损失。模拟器会尽可能精确地模拟浮点运算，以反映真实硬件的行为，这有助于开发者理解 JavaScript 中可能出现的浮点数精度问题。例如，在 `DecodeTypeVFP` 中，可以看到对 NaN 值的处理和 `canonicalizeNaN` 函数的使用，这反映了浮点数运算的复杂性。
*   **位运算错误：**  位运算的优先级或操作符使用错误，可能导致非预期的结果。模拟器会忠实地执行位运算指令，帮助开发者理解这些错误。

**归纳一下它的功能：**

`v8/src/execution/arm/simulator-arm.cc` 的这个代码片段是 V8 引擎中 ARM 架构模拟器的核心，负责**解码和执行 ARM 指令集中的各种指令，包括数据处理、块数据传输、分支、以及协处理器（特别是 VFP）指令**。它的存在使得 V8 能够在非 ARM 平台上进行开发、测试和调试，并且可以作为一种备选的执行路径。它模拟了底层硬件的行为，对于理解 JavaScript 代码在 ARM 架构上的执行过程至关重要。
```
Prompt: 
```
这是目录为v8/src/execution/arm/simulator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm/simulator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
                    break;
                    }
                    set_register(rd, rn_val + static_cast<int16_t>(rm_val));
                  }
                }
              } else if (instr->Bits(27, 16) == 0x6BF &&
                         instr->Bits(11, 4) == 0xF3) {
                // Rev.
                uint32_t rm_val = get_register(instr->RmValue());
                set_register(rd, ByteReverse(rm_val));
              } else {
                UNREACHABLE();
              }
              break;
            case 2:
              if ((instr->Bit(20) == 0) && (instr->Bits(9, 6) == 1)) {
                if (instr->Bits(19, 16) == 0xF) {
                  // Uxtb16.
                  uint32_t rm_val = get_register(instr->RmValue());
                  int32_t rotate = instr->Bits(11, 10);
                  switch (rotate) {
                    case 0:
                      break;
                    case 1:
                      rm_val = (rm_val >> 8) | (rm_val << 24);
                      break;
                    case 2:
                      rm_val = (rm_val >> 16) | (rm_val << 16);
                      break;
                    case 3:
                      rm_val = (rm_val >> 24) | (rm_val << 8);
                      break;
                  }
                  set_register(rd, (rm_val & 0xFF) | (rm_val & 0xFF0000));
                } else {
                  UNIMPLEMENTED();
                }
              } else {
                UNIMPLEMENTED();
              }
              break;
            case 3:
              if ((instr->Bits(9, 6) == 1)) {
                if (instr->Bit(20) == 0) {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Uxtb.
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, (rm_val & 0xFF));
                  } else {
                    // Uxtab.
                    uint32_t rn_val = get_register(rn);
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + (rm_val & 0xFF));
                  }
                } else {
                  if (instr->Bits(19, 16) == 0xF) {
                    // Uxth.
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, (rm_val & 0xFFFF));
                  } else {
                    // Uxtah.
                    uint32_t rn_val = get_register(rn);
                    uint32_t rm_val = get_register(instr->RmValue());
                    int32_t rotate = instr->Bits(11, 10);
                    switch (rotate) {
                      case 0:
                        break;
                      case 1:
                        rm_val = (rm_val >> 8) | (rm_val << 24);
                        break;
                      case 2:
                        rm_val = (rm_val >> 16) | (rm_val << 16);
                        break;
                      case 3:
                        rm_val = (rm_val >> 24) | (rm_val << 8);
                        break;
                    }
                    set_register(rd, rn_val + (rm_val & 0xFFFF));
                  }
                }
              } else {
                // PU == 0b01, BW == 0b11, Bits(9, 6) != 0b0001
                if ((instr->Bits(20, 16) == 0x1F) &&
                    (instr->Bits(11, 4) == 0xF3)) {
                  // Rbit.
                  uint32_t rm_val = get_register(instr->RmValue());
                  set_register(rd, base::bits::ReverseBits(rm_val));
                } else {
                  UNIMPLEMENTED();
                }
              }
              break;
          }
        }
        return;
      }
      break;
    }
    case db_x: {
      if (instr->Bits(22, 20) == 0x5) {
        if (instr->Bits(7, 4) == 0x1) {
          int rm = instr->RmValue();
          int32_t rm_val = get_register(rm);
          int rs = instr->RsValue();
          int32_t rs_val = get_register(rs);
          if (instr->Bits(15, 12) == 0xF) {
            // SMMUL (in V8 notation matching ARM ISA format)
            // Format(instr, "smmul'cond 'rn, 'rm, 'rs");
            rn_val = base::bits::SignedMulHigh32(rm_val, rs_val);
          } else {
            // SMMLA (in V8 notation matching ARM ISA format)
            // Format(instr, "smmla'cond 'rn, 'rm, 'rs, 'rd");
            int rd = instr->RdValue();
            int32_t rd_val = get_register(rd);
            rn_val = base::bits::SignedMulHighAndAdd32(rm_val, rs_val, rd_val);
          }
          set_register(rn, rn_val);
          return;
        }
      }
      if (instr->Bits(5, 4) == 0x1) {
        if ((instr->Bit(22) == 0x0) && (instr->Bit(20) == 0x1)) {
          // (s/u)div (in V8 notation matching ARM ISA format) rn = rm/rs
          // Format(instr, "'(s/u)div'cond'b 'rn, 'rm, 'rs);
          int rm = instr->RmValue();
          int32_t rm_val = get_register(rm);
          int rs = instr->RsValue();
          int32_t rs_val = get_register(rs);
          int32_t ret_val = 0;
          // udiv
          if (instr->Bit(21) == 0x1) {
            ret_val = base::bit_cast<int32_t>(
                base::bits::UnsignedDiv32(base::bit_cast<uint32_t>(rm_val),
                                          base::bit_cast<uint32_t>(rs_val)));
          } else {
            ret_val = base::bits::SignedDiv32(rm_val, rs_val);
          }
          set_register(rn, ret_val);
          return;
        }
      }
      // Format(instr, "'memop'cond'b 'rd, ['rn, -'shift_rm]'w");
      addr = rn_val - shifter_operand;
      if (instr->HasW()) {
        set_register(rn, addr);
      }
      break;
    }
    case ib_x: {
      if (instr->HasW() && (instr->Bits(6, 4) == 0x5)) {
        uint32_t widthminus1 = static_cast<uint32_t>(instr->Bits(20, 16));
        uint32_t lsbit = static_cast<uint32_t>(instr->Bits(11, 7));
        uint32_t msbit = widthminus1 + lsbit;
        if (msbit <= 31) {
          if (instr->Bit(22)) {
            // ubfx - unsigned bitfield extract.
            uint32_t rm_val =
                static_cast<uint32_t>(get_register(instr->RmValue()));
            uint32_t extr_val = rm_val << (31 - msbit);
            extr_val = extr_val >> (31 - widthminus1);
            set_register(instr->RdValue(), extr_val);
          } else {
            // sbfx - signed bitfield extract.
            int32_t rm_val = get_register(instr->RmValue());
            int32_t extr_val = static_cast<uint32_t>(rm_val) << (31 - msbit);
            extr_val = extr_val >> (31 - widthminus1);
            set_register(instr->RdValue(), extr_val);
          }
        } else {
          UNREACHABLE();
        }
        return;
      } else if (!instr->HasW() && (instr->Bits(6, 4) == 0x1)) {
        uint32_t lsbit = static_cast<uint32_t>(instr->Bits(11, 7));
        uint32_t msbit = static_cast<uint32_t>(instr->Bits(20, 16));
        if (msbit >= lsbit) {
          // bfc or bfi - bitfield clear/insert.
          uint32_t rd_val =
              static_cast<uint32_t>(get_register(instr->RdValue()));
          uint32_t bitcount = msbit - lsbit + 1;
          uint32_t mask = 0xFFFFFFFFu >> (32 - bitcount);
          rd_val &= ~(mask << lsbit);
          if (instr->RmValue() != 15) {
            // bfi - bitfield insert.
            uint32_t rm_val =
                static_cast<uint32_t>(get_register(instr->RmValue()));
            rm_val &= mask;
            rd_val |= rm_val << lsbit;
          }
          set_register(instr->RdValue(), rd_val);
        } else {
          UNREACHABLE();
        }
        return;
      } else {
        // Format(instr, "'memop'cond'b 'rd, ['rn, +'shift_rm]'w");
        addr = base::AddWithWraparound(rn_val, shifter_operand);
        if (instr->HasW()) {
          set_register(rn, addr);
        }
      }
      break;
    }
    default: {
      UNREACHABLE();
    }
  }
  if (instr->HasB()) {
    if (instr->HasL()) {
      uint8_t byte = ReadB(addr);
      set_register(rd, byte);
    } else {
      uint8_t byte = get_register(rd);
      WriteB(addr, byte);
    }
  } else {
    if (instr->HasL()) {
      set_register(rd, ReadW(addr));
    } else {
      WriteW(addr, get_register(rd));
    }
  }
}

void Simulator::DecodeType4(Instruction* instr) {
  DCHECK_EQ(instr->Bit(22), 0);  // only allowed to be set in privileged mode
  if (instr->HasL()) {
    // Format(instr, "ldm'cond'pu 'rn'w, 'rlist");
    HandleRList(instr, true);
  } else {
    // Format(instr, "stm'cond'pu 'rn'w, 'rlist");
    HandleRList(instr, false);
  }
}

void Simulator::DecodeType5(Instruction* instr) {
  // Format(instr, "b'l'cond 'target");
  int off =
      static_cast<int>(static_cast<uint32_t>(instr->SImmed24Value()) << 2);
  intptr_t pc_address = get_pc();
  if (instr->HasLink()) {
    set_register(lr, pc_address + kInstrSize);
  }
  int pc_reg = get_register(pc);
  set_pc(pc_reg + off);
}

void Simulator::DecodeType6(Instruction* instr) {
  DecodeType6CoprocessorIns(instr);
}

void Simulator::DecodeType7(Instruction* instr) {
  if (instr->Bit(24) == 1) {
    SoftwareInterrupt(instr);
  } else {
    switch (instr->CoprocessorValue()) {
      case 10:  // Fall through.
      case 11:
        DecodeTypeVFP(instr);
        break;
      case 15:
        DecodeTypeCP15(instr);
        break;
      default:
        UNIMPLEMENTED();
    }
  }
}

// void Simulator::DecodeTypeVFP(Instruction* instr)
// The Following ARMv7 VFPv instructions are currently supported.
// vmov :Sn = Rt
// vmov :Rt = Sn
// vcvt: Dd = Sm
// vcvt: Sd = Dm
// vcvt.f64.s32 Dd, Dd, #<fbits>
// Dd = vabs(Dm)
// Sd = vabs(Sm)
// Dd = vneg(Dm)
// Sd = vneg(Sm)
// Dd = vadd(Dn, Dm)
// Sd = vadd(Sn, Sm)
// Dd = vsub(Dn, Dm)
// Sd = vsub(Sn, Sm)
// Dd = vmul(Dn, Dm)
// Sd = vmul(Sn, Sm)
// Dd = vdiv(Dn, Dm)
// Sd = vdiv(Sn, Sm)
// vcmp(Dd, Dm)
// vcmp(Sd, Sm)
// Dd = vsqrt(Dm)
// Sd = vsqrt(Sm)
// vmrs
// vdup.size Qd, Rt.
void Simulator::DecodeTypeVFP(Instruction* instr) {
  DCHECK((instr->TypeValue() == 7) && (instr->Bit(24) == 0x0));
  DCHECK_EQ(instr->Bits(11, 9), 0x5);
  // Obtain single precision register codes.
  int m = instr->VFPMRegValue(kSinglePrecision);
  int d = instr->VFPDRegValue(kSinglePrecision);
  int n = instr->VFPNRegValue(kSinglePrecision);
  // Obtain double precision register codes.
  int vm = instr->VFPMRegValue(kDoublePrecision);
  int vd = instr->VFPDRegValue(kDoublePrecision);
  int vn = instr->VFPNRegValue(kDoublePrecision);

  if (instr->Bit(4) == 0) {
    if (instr->Opc1Value() == 0x7) {
      // Other data processing instructions
      if ((instr->Opc2Value() == 0x0) && (instr->Opc3Value() == 0x1)) {
        // vmov register to register.
        if (instr->SzValue() == 0x1) {
          uint32_t data[2];
          get_d_register(vm, data);
          set_d_register(vd, data);
        } else {
          set_s_register(d, get_s_register(m));
        }
      } else if ((instr->Opc2Value() == 0x0) && (instr->Opc3Value() == 0x3)) {
        // vabs
        if (instr->SzValue() == 0x1) {
          Float64 dm = get_double_from_d_register(vm);
          constexpr uint64_t kSignBit64 = uint64_t{1} << 63;
          Float64 dd = Float64::FromBits(dm.get_bits() & ~kSignBit64);
          dd = canonicalizeNaN(dd);
          set_d_register_from_double(vd, dd);
        } else {
          Float32 sm = get_float_from_s_register(m);
          constexpr uint32_t kSignBit32 = uint32_t{1} << 31;
          Float32 sd = Float32::FromBits(sm.get_bits() & ~kSignBit32);
          sd = canonicalizeNaN(sd);
          set_s_register_from_float(d, sd);
        }
      } else if ((instr->Opc2Value() == 0x1) && (instr->Opc3Value() == 0x1)) {
        // vneg
        if (instr->SzValue() == 0x1) {
          Float64 dm = get_double_from_d_register(vm);
          constexpr uint64_t kSignBit64 = uint64_t{1} << 63;
          Float64 dd = Float64::FromBits(dm.get_bits() ^ kSignBit64);
          dd = canonicalizeNaN(dd);
          set_d_register_from_double(vd, dd);
        } else {
          Float32 sm = get_float_from_s_register(m);
          constexpr uint32_t kSignBit32 = uint32_t{1} << 31;
          Float32 sd = Float32::FromBits(sm.get_bits() ^ kSignBit32);
          sd = canonicalizeNaN(sd);
          set_s_register_from_float(d, sd);
        }
      } else if ((instr->Opc2Value() == 0x7) && (instr->Opc3Value() == 0x3)) {
        DecodeVCVTBetweenDoubleAndSingle(instr);
      } else if ((instr->Opc2Value() == 0x8) && (instr->Opc3Value() & 0x1)) {
        DecodeVCVTBetweenFloatingPointAndInteger(instr);
      } else if ((instr->Opc2Value() == 0xA) && (instr->Opc3Value() == 0x3) &&
                 (instr->Bit(8) == 1)) {
        // vcvt.f64.s32 Dd, Dd, #<fbits>
        int fraction_bits = 32 - ((instr->Bits(3, 0) << 1) | instr->Bit(5));
        int fixed_value = get_sinteger_from_s_register(vd * 2);
        double divide = 1 << fraction_bits;
        set_d_register_from_double(vd, fixed_value / divide);
      } else if (((instr->Opc2Value() >> 1) == 0x6) &&
                 (instr->Opc3Value() & 0x1)) {
        DecodeVCVTBetweenFloatingPointAndInteger(instr);
      } else if (((instr->Opc2Value() == 0x4) || (instr->Opc2Value() == 0x5)) &&
                 (instr->Opc3Value() & 0x1)) {
        DecodeVCMP(instr);
      } else if (((instr->Opc2Value() == 0x1)) && (instr->Opc3Value() == 0x3)) {
        // vsqrt
        if (instr->SzValue() == 0x1) {
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = std::sqrt(dm_value);
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = std::sqrt(sm_value);
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else if (instr->Opc3Value() == 0x0) {
        // vmov immediate.
        if (instr->SzValue() == 0x1) {
          set_d_register_from_double(vd, instr->DoubleImmedVmov());
        } else {
          // Cast double to float.
          float value = instr->DoubleImmedVmov().get_scalar();
          set_s_register_from_float(d, value);
        }
      } else if (((instr->Opc2Value() == 0x6)) && (instr->Opc3Value() == 0x3)) {
        // vrintz - truncate
        if (instr->SzValue() == 0x1) {
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = trunc(dm_value);
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = truncf(sm_value);
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else {
        UNREACHABLE();  // Not used by V8.
      }
    } else if (instr->Opc1Value() == 0x3) {
      if (instr->Opc3Value() & 0x1) {
        // vsub
        if (instr->SzValue() == 0x1) {
          double dn_value = get_double_from_d_register(vn).get_scalar();
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = dn_value - dm_value;
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sn_value = get_float_from_s_register(n).get_scalar();
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = sn_value - sm_value;
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      } else {
        // vadd
        if (instr->SzValue() == 0x1) {
          double dn_value = get_double_from_d_register(vn).get_scalar();
          double dm_value = get_double_from_d_register(vm).get_scalar();
          double dd_value = dn_value + dm_value;
          dd_value = canonicalizeNaN(dd_value);
          set_d_register_from_double(vd, dd_value);
        } else {
          float sn_value = get_float_from_s_register(n).get_scalar();
          float sm_value = get_float_from_s_register(m).get_scalar();
          float sd_value = sn_value + sm_value;
          sd_value = canonicalizeNaN(sd_value);
          set_s_register_from_float(d, sd_value);
        }
      }
    } else if ((instr->Opc1Value() == 0x2) && !(instr->Opc3Value() & 0x1)) {
      // vmul
      if (instr->SzValue() == 0x1) {
        double dn_value = get_double_from_d_register(vn).get_scalar();
        double dm_value = get_double_from_d_register(vm).get_scalar();
        double dd_value = dn_value * dm_value;
        dd_value = canonicalizeNaN(dd_value);
        set_d_register_from_double(vd, dd_value);
      } else {
        float sn_value = get_float_from_s_register(n).get_scalar();
        float sm_value = get_float_from_s_register(m).get_scalar();
        float sd_value = sn_value * sm_value;
        sd_value = canonicalizeNaN(sd_value);
        set_s_register_from_float(d, sd_value);
      }
    } else if ((instr->Opc1Value() == 0x0)) {
      // vmla, vmls
      const bool is_vmls = (instr->Opc3Value() & 0x1);
      if (instr->SzValue() == 0x1) {
        const double dd_val = get_double_from_d_register(vd).get_scalar();
        const double dn_val = get_double_from_d_register(vn).get_scalar();
        const double dm_val = get_double_from_d_register(vm).get_scalar();

        // Note: we do the mul and add/sub in separate steps to avoid getting a
        // result with too high precision.
        const double res = dn_val * dm_val;
        set_d_register_from_double(vd, res);
        if (is_vmls) {
          set_d_register_from_double(vd, canonicalizeNaN(dd_val - res));
        } else {
          set_d_register_from_double(vd, canonicalizeNaN(dd_val + res));
        }
      } else {
        const float sd_val = get_float_from_s_register(d).get_scalar();
        const float sn_val = get_float_from_s_register(n).get_scalar();
        const float sm_val = get_float_from_s_register(m).get_scalar();

        // Note: we do the mul and add/sub in separate steps to avoid getting a
        // result with too high precision.
        const float res = sn_val * sm_val;
        set_s_register_from_float(d, res);
        if (is_vmls) {
          set_s_register_from_float(d, canonicalizeNaN(sd_val - res));
        } else {
          set_s_register_from_float(d, canonicalizeNaN(sd_val + res));
        }
      }
    } else if ((instr->Opc1Value() == 0x4) && !(instr->Opc3Value() & 0x1)) {
      // vdiv
      if (instr->SzValue() == 0x1) {
        double dn_value = get_double_from_d_register(vn).get_scalar();
        double dm_value = get_double_from_d_register(vm).get_scalar();
        double dd_value = base::Divide(dn_value, dm_value);
        div_zero_vfp_flag_ = (dm_value == 0);
        dd_value = canonicalizeNaN(dd_value);
        set_d_register_from_double(vd, dd_value);
      } else {
        float sn_value = get_float_from_s_register(n).get_scalar();
        float sm_value = get_float_from_s_register(m).get_scalar();
        float sd_value = base::Divide(sn_value, sm_value);
        div_zero_vfp_flag_ = (sm_value == 0);
        sd_value = canonicalizeNaN(sd_value);
        set_s_register_from_float(d, sd_value);
      }
    } else {
      UNIMPLEMENTED();  // Not used by V8.
    }
  } else {
    if ((instr->VCValue() == 0x0) && (instr->VAValue() == 0x0)) {
      DecodeVMOVBetweenCoreAndSinglePrecisionRegisters(instr);
    } else if ((instr->VLValue() == 0x0) && (instr->VCValue() == 0x1)) {
      if (instr->Bit(23) == 0) {
        // vmov (ARM core register to scalar)
        int vd = instr->VFPNRegValue(kDoublePrecision);
        int rt = instr->RtValue();
        int opc1_opc2 = (instr->Bits(22, 21) << 2) | instr->Bits(6, 5);
        if ((opc1_opc2 & 0xB) == 0) {
          // NeonS32/NeonU32
          uint32_t data[2];
          get_d_register(vd, data);
          data[instr->Bit(21)] = get_register(rt);
          set_d_register(vd, data);
        } else {
          uint64_t data;
          get_d_register(vd, &data);
          uint64_t rt_value = get_register(rt);
          if ((opc1_opc2 & 0x8) != 0) {
            // NeonS8 / NeonU8
            int i = opc1_opc2 & 0x7;
            int shift = i * kBitsPerByte;
            const uint64_t mask = 0xFF;
            data &= ~(mask << shift);
            data |= (rt_value & mask) << shift;
            set_d_register(vd, &data);
          } else if ((opc1_opc2 & 0x1) != 0) {
            // NeonS16 / NeonU16
            int i = (opc1_opc2 >> 1) & 0x3;
            int shift = i * kBitsPerByte * kShortSize;
            const uint64_t mask = 0xFFFF;
            data &= ~(mask << shift);
            data |= (rt_value & mask) << shift;
            set_d_register(vd, &data);
          } else {
            UNREACHABLE();  // Not used by V8.
          }
        }
      } else {
        // vdup.size Qd, Rt.
        NeonSize size = Neon32;
        if (instr->Bit(5) != 0)
          size = Neon16;
        else if (instr->Bit(22) != 0)
          size = Neon8;
        int vd = instr->VFPNRegValue(kSimd128Precision);
        int rt = instr->RtValue();
        uint32_t rt_value = get_register(rt);
        uint32_t q_data[4];
        switch (size) {
          case Neon8: {
            rt_value &= 0xFF;
            uint8_t* dst = reinterpret_cast<uint8_t*>(q_data);
            for (int i = 0; i < 16; i++) {
              dst[i] = rt_value;
            }
            break;
          }
          case Neon16: {
            // Perform pairwise op.
            rt_value &= 0xFFFFu;
            uint32_t rt_rt = (rt_value << 16) | (rt_value & 0xFFFFu);
            for (int i = 0; i < 4; i++) {
              q_data[i] = rt_rt;
            }
            break;
          }
          case Neon32: {
            for (int i = 0; i < 4; i++) {
              q_data[i] = rt_value;
            }
            break;
          }
          default:
            UNREACHABLE();
        }
        set_neon_register(vd, q_data);
      }
    } else if ((instr->VLValue() == 0x1) && (instr->VCValue() == 0x1)) {
      // vmov (scalar to ARM core register)
      int vn = instr->VFPNRegValue(kDoublePrecision);
      int rt = instr->RtValue();
      int opc1_opc2 = (instr->Bits(22, 21) << 2) | instr->Bits(6, 5);
      uint64_t data;
      get_d_register(vn, &data);
      if ((opc1_opc2 & 0xB) == 0) {
        // NeonS32 / NeonU32
        DCHECK_EQ(0, instr->Bit(23));
        int32_t int_data[2];
        memcpy(int_data, &data, sizeof(int_data));
        set_register(rt, int_data[instr->Bit(21)]);
      } else {
        uint64_t data;
        get_d_register(vn, &data);
        bool u = instr->Bit(23) != 0;
        if ((opc1_opc2 & 0x8) != 0) {
          // NeonS8 / NeonU8
          int i = opc1_opc2 & 0x7;
          int shift = i * kBitsPerByte;
          uint32_t scalar = (data >> shift) & 0xFFu;
          if (!u && (scalar & 0x80) != 0) scalar |= 0xFFFFFF00;
          set_register(rt, scalar);
        } else if ((opc1_opc2 & 0x1) != 0) {
          // NeonS16 / NeonU16
          int i = (opc1_opc2 >> 1) & 0x3;
          int shift = i * kBitsPerByte * kShortSize;
          uint32_t scalar = (data >> shift) & 0xFFFFu;
          if (!u && (scalar & 0x8000) != 0) scalar |= 0xFFFF0000;
          set_register(rt, scalar);
        } else {
          UNREACHABLE();  // Not used by V8.
        }
      }
    } else if ((instr->VLValue() == 0x1) && (instr->VCValue() == 0x0) &&
               (instr->VAValue() == 0x7) && (instr->Bits(19, 16) == 0x1)) {
      // vmrs
      uint32_t rt = instr->RtValue();
      if (rt == 0xF) {
        Copy_FPSCR_to_APSR();
      } else {
        // Emulate FPSCR from the Simulator flags.
        uint32_t fpscr = (n_flag_FPSCR_ << 31) | (z_flag_FPSCR_ << 30) |
                         (c_flag_FPSCR_ << 29) | (v_flag_FPSCR_ << 28) |
                         (FPSCR_default_NaN_mode_ << 25) |
                         (inexact_vfp_flag_ << 4) | (underflow_vfp_flag_ << 3) |
                         (overflow_vfp_flag_ << 2) | (div_zero_vfp_flag_ << 1) |
                         (inv_op_vfp_flag_ << 0) | (FPSCR_rounding_mode_);
        set_register(rt, fpscr);
      }
    } else if ((instr->VLValue() == 0x0) && (instr->VCValue() == 0x0) &&
               (instr->VAValue() == 0x7) && (instr->Bits(19, 16) == 0x1)) {
      // vmsr
      uint32_t rt = instr->RtValue();
      if (rt == pc) {
        UNREACHABLE();
      } else {
        uint32_t rt_value = get_register(rt);
        n_flag_FPSCR_ = (rt_value >> 31) & 1;
        z_flag_FPSCR_ = (rt_value >> 30) & 1;
        c_flag_FPSCR_ = (rt_value >> 29) & 1;
        v_flag_FPSCR_ = (rt_value >> 28) & 1;
        FPSCR_default_NaN_mode_ = (rt_value >> 25) & 1;
        inexact_vfp_flag_ = (rt_value >> 4) & 1;
        underflow_vfp_flag_ = (rt_value >> 3) & 1;
        overflow_vfp_flag_ = (rt_value >> 2) & 1;
        div_zero_vfp_flag_ = (rt_value >> 1) & 1;
        inv_op_vfp_flag_ = (rt_value >> 0) & 1;
        FPSCR_rounding_mode_ =
            static_cast<VFPRoundingMode>((rt_value)&kVFPRoundingModeMask);
      }
    } else {
      UNIMPLEMENTED();  // Not used by V8.
    }
  }
}

void Simulator::DecodeTypeCP15(Instruction* instr) {
  DCHECK((instr->TypeValue() == 7) && (instr->Bit(24) == 0x0));
  DCHECK_EQ(instr->CoprocessorValue(), 15);

  if (instr->Bit(4) == 1) {
    // mcr
    int crn = instr->Bits(19, 16);
    int crm = instr->Bits(3, 0);
    int opc1 = instr->Bits(23, 21);
    int opc2 = instr->Bits(7, 5);
    if ((opc1 == 0) && (crn == 7)) {
      // ARMv6 memory barrier operations.
      // Details available in ARM DDI 0406C.b, B3-1750.
      if (((crm == 10) && (opc2 == 5)) ||  // CP15DMB
          ((crm == 10) && (opc2 == 4)) ||  // CP15DSB
          ((crm == 5) && (opc2 == 4))) {   // CP15ISB
        // These are ignored by the simulator for now.
      } else {
        UNIMPLEMENTED();
      }
    }
  } else {
    UNIMPLEMENTED();
  }
}

void Simulator::DecodeVMOVBetweenCoreAndSinglePrecisionRegisters(
    Instruction* instr) {
  DCHECK((instr->Bit(4) == 1) && (instr->VCValue() == 0x0) &&
         (instr->VAValue() == 0x0));

  int t = instr->RtValue();
  int n = instr->VFPNRegValue(kSinglePrecision);
  bool to_arm_register = (instr->VLValue() == 0x1);

  if (to_arm_register) {
    int32_t int_value = get_sinteger_from_s_register(n);
    set_register(t, int_value);
  } else {
    int32_t rs_val = get_register(t);
    set_s_register_from_sinteger(n, rs_val);
  }
}

void Simulator::DecodeVCMP(Instruction* instr) {
  DCHECK((instr->Bit(4) == 0) && (instr->Opc1Value() == 0x7));
  DCHECK(((instr->Opc2Value() == 0x4) || (instr->Opc2Value() == 0x5)) &&
         (instr->Opc3Value() & 0x1));
  // Comparison.

  VFPRegPrecision precision = kSinglePrecision;
  if (instr->SzValue() == 0x1) {
    precision = kDoublePrecision;
  }

  int d = instr->VFPDRegValue(precision);
  int m = 0;
  if (instr->Opc2Value() == 0x4) {
    m = instr->VFPMRegValue(precision);
  }

  if (precision == kDoublePrecision) {
    double dd_value = get_double_from_d_register(d).get_scalar();
    double dm_value = 0.0;
    if (instr->Opc2Value() == 0x4) {
      dm_value = get_double_from_d_register(m).get_scalar();
    }

    // Raise exceptions for quiet NaNs if necessary.
    if (instr->Bit(7) == 1) {
      if (std::isnan(dd_value)) {
        inv_op_vfp_flag_ = true;
      }
    }

    Compute_FPSCR_Flags(dd_value, dm_value);
  } else {
    float sd_value = get_float_from_s_register(d).get_scalar();
    float sm_value = 0.0;
    if (instr->Opc2Value() == 0x4) {
      sm_value = get_float_from_s_register(m).get_scalar();
    }

    // Raise exceptions for quiet NaNs if necessary.
    if (instr->Bit(7) == 1) {
      if (std::isnan(sd_value)) {
        inv_op_vfp_flag_ = true;
      }
    }

    Compute_FPSCR_Flags(sd_value, sm_value);
  }
}

void Simulator::DecodeVCVTBetweenDoubleAndSingle(Instruction* instr) {
  DCHECK((instr->Bit(4) == 0) && (instr->Opc1Value() == 0x7));
  DCHECK((instr->Opc2Value() == 0x7) && (instr->Opc3Value() == 0x3));

  VFPRegPrecision dst_precision = kDoublePrecision;
  VFPRegPrecision src_precision = kSinglePrecision;
  if (instr->SzValue() == 1) {
    dst_precision = kSinglePrecision;
    src_precision = kDoublePrecision;
  }

  int dst = instr->VFPDRegValue(dst_precision);
  int src = instr->VFPMRegValue(src_precision);

  if (dst_precision == kSinglePrecision) {
    double val = get_double_from_d_register(src).get_scalar();
    set_s_register_from_float(dst, static_cast<float>(val));
  } else {
    float val = get_float_from_s_register(src).get_scalar();
    set_d_register_from_double(dst, static_cast<double>(val));
  }
}

bool get_inv_op_vfp_flag(VFPRoundingMode mode, double val, bool unsigned_) {
  DCHECK((mode == RN) || (mode == RM) || (mode == RZ));
  double max_uint = static_cast<double>(0xFFFFFFFFu);
  double max_int = static_cast<double>(kMaxInt);
  double min_int = static_cast<double>(kMinInt);

  // Check for NaN.
  if (val != val) {
    return true;
  }

  // Check for overflow. This code works because 32bit integers can be
  // exactly represented by ieee-754 64bit floating-point values.
  switch (mode) {
    case RN:
      return unsigned_ ? (val >= (max_uint + 0.5)) || (val < -0.5)
                       : (val >= (max_int + 0.5)) || (val < (min_int - 0.5));

    case RM:
      return unsigned_ ? (val >= (max_uint + 1.0)) || (val < 0)
                       : (val >= (max_int + 1.0)) || (val < min_int);

    case RZ:
      return unsigned_ ? (val >= (max_uint + 1.0)) || (val <= -1)
                       : (val >= (max_int + 1.0)) || (val <= (min_int - 1.0));
    default:
      UNREACHABLE();
  }
}

// We call this function only if we had a vfp invalid exception.
// It returns the correct saturated value.
int VFPConversionSaturate(double val, bool unsigned_res) {
  if (val != val) {
    return 0;
  } else {
    if (unsigned_res) {
      return (val < 0) ? 0 : 0xFFFFFFFFu;
    } else {
      return (val < 0) ? kMinInt : kMaxInt;
    }
  }
}

int32_t Simulator::ConvertDoubleToInt(double val, bool unsigned_integer,
                                      VFPRoundingMode mode) {
  int32_t result;
  if (unsigned_integer) {
    // The FastD2UI helper does not have the rounding behavior we want here
    // (it doesn't guarantee any particular rounding, and it doesn't check
    // for or handle overflow), so do the conversion by hand.
    using limits = std::numeric_limits<uint32_t>;
    if (val > limits::max()) {
      result = limits::max();
    } else if (!(val >= 0)) {  // Negation to catch NaNs.
      result = 0;
    } else {
      result = static_cast<uint32_t>(val);
    }
  } else {
    result = FastD2IChecked(val);
  }

  inv_op_vfp_flag_ = get_inv_op_vfp_flag(mode, val, unsigned_integer);

  double abs_diff = unsigned_integer
                        ? std::fabs(val - static_cast<uint32_t>(result))
                        : std::fabs(val - result);

  inexact_vfp_flag_ = (abs_diff != 0);

  if (inv_op_vfp_flag_) {
    result = VFPConv
"""


```