Response:
Let's break down the thought process for analyzing this RISC-V simulator code snippet.

1. **Understanding the Goal:** The request asks for a functional overview of the provided C++ code, specifically focusing on its role within the V8 JavaScript engine and its relation to RISC-V architecture simulation.

2. **Initial Scan for Keywords:**  I'd first quickly scan the code for significant keywords and patterns. This includes:
    * `case`:  Indicates a switch statement, implying different instruction types are being handled.
    * `RO_`:  Likely represents RISC-V opcode or instruction macros.
    * `set_pc`, `get_pc`, `set_rd`, `get_register`:  Suggests interaction with the processor's state (program counter, registers).
    * `ReadMem`, `WriteMem`, `ProbeMemory`:  Points to memory access operations.
    * `Builtin`: Implies calling pre-defined functions or runtime code within V8.
    * `PrintF`, `TraceMemRd`:  Indicates debugging or tracing functionalities.
    * `SoftwareInterrupt`, `DieOrDebug`: Signals events that deviate from normal execution.
    * `csr_reg`, `read_csr_value`, `write_csr_value`:  Suggests handling Control and Status Registers.
    * `Float32`, `Float64`: Indicates support for floating-point operations.
    * `CAN_USE_RVV_INSTRUCTIONS`, `DecodeRvv`:  Highlights support for the RISC-V Vector Extension.
    * `sat_add`, `sat_sub`: Suggests saturated arithmetic operations, common in SIMD/vector contexts.
    * Loop structures like `RVV_VI_VV_LOOP`: Further reinforces the presence of vector instruction handling.

3. **Grouping by Instruction Type:** The code is clearly structured around RISC-V instruction formats (R-type, I-type, S-type, B-type, U-type, J-type, and compressed instructions). This organization provides a natural way to categorize the functionality. I would mentally (or literally) group the `case` statements under these categories.

4. **Analyzing Individual Instruction Cases (Examples):** I'd pick a few representative examples from each category to understand the basic operations:
    * **I-type (e.g., `RO_ADDI`):**  Simple arithmetic operation (add immediate). The code retrieves the value from a register (`rs1()`), adds an immediate value (`imm12()`), and stores the result back into a register (`set_rd()`).
    * **Load/Store (e.g., `RO_LW`, `RO_SW`):** These involve memory access. The code calculates an address, checks if the address is valid (`ProbeMemory`), reads or writes data of a specific size (`ReadMem`, `WriteMem`), and potentially updates registers or memory.
    * **Branch (e.g., `RO_BEQ`):**  Conditional jumps based on register comparisons. The code compares register values and updates the program counter (`set_pc`) if the condition is met.
    * **Compressed Instructions (e.g., `RO_C_ADDI`):** Similar to their non-compressed counterparts but with a shorter encoding and potentially restricted operands.
    * **Vector Instructions (e.g., `RO_V_VADD_VV`):** These involve operations on vectors of data. The loops and macros like `RVV_VI_VV_LOOP` suggest processing multiple elements in parallel.

5. **Identifying Key Functions:** I'd note down the purpose of important functions like `set_pc`, `get_register`, `ReadMem`, `WriteMem`, as they are fundamental to the simulator's operation. The tracing functions (`TraceMemRd`, `PrintF`) are also important for debugging.

6. **Inferring High-Level Functionality:**  Based on the individual instruction handling, I can infer the overall purpose: *This code simulates the execution of RISC-V instructions.*  It fetches instructions (implicitly through the `case` structure and program counter manipulation), decodes them, and performs the corresponding actions on the simulated processor state (registers, memory, program counter).

7. **Addressing Specific Questions:**
    * **`.tq` extension:**  The code itself is C++, so the premise is false.
    * **JavaScript Relationship:**  The "Call to Builtin" section clearly links the simulator to V8's built-in functions. This is a crucial connection. An example of a JavaScript function calling a builtin would be a core language feature like `Array.push()`.
    * **Code Logic Reasoning:** The branch instructions (`RO_BEQ`, etc.) offer clear examples of conditional logic. I can create simple input scenarios (register values) and predict the output (program counter change).
    * **Common Programming Errors:** The `ProbeMemory` calls highlight a common error: accessing invalid memory addresses.

8. **Summarizing the Functionality (as requested in Part 7):**  The key is to synthesize the observations into a concise summary. Focus on the core role of the code: simulating RISC-V, supporting various instruction types, interacting with V8 builtins, and including debugging/tracing features.

9. **Review and Refine:**  Finally, I'd reread the analysis and ensure it accurately reflects the code's functionality and addresses all aspects of the request. I'd check for clarity and conciseness. For example, initially, I might just say "it handles instructions," but refining it to "simulates the *execution* of RISC-V instructions" is more precise. Similarly, explicitly mentioning the different instruction types (arithmetic, memory, control flow) adds detail.
好的，让我们来分析一下这段 `v8/src/execution/riscv/simulator-riscv.cc` 的代码片段。

**功能列举：**

这段代码是 V8 JavaScript 引擎中 RISC-V 架构的模拟器（Simulator）的一部分，负责模拟 RISC-V 指令的执行。它主要包含以下功能：

1. **指令解码和执行:**  代码通过 `switch` 语句针对不同的 RISC-V 指令类型（例如，I-type, S-type, B-type, U-type, J-type 以及压缩指令 C-type）进行解码和执行。每个 `case` 分支对应一种或一类 RISC-V 指令。

2. **寄存器操作:** 代码中使用了 `get_register()` 和 `set_register()` 函数来读取和写入 RISC-V 通用寄存器的值。对于浮点寄存器，则使用了 `get_fpu_register_*` 和 `set_frd`/`set_drd` 等函数。

3. **内存访问:** 代码包含了加载指令（例如 `RO_LB`, `RO_LW`, `RO_LD`）和存储指令（例如 `RO_SB`, `RO_SW`, `RO_SD`）的模拟。  `ReadMem` 函数用于从模拟内存中读取数据，`WriteMem` 函数用于向模拟内存中写入数据。 `ProbeMemory` 函数用于检查内存地址是否有效。

4. **程序计数器 (PC) 管理:**  `get_pc()` 用于获取当前的程序计数器值，`set_pc()` 用于设置程序计数器的值，从而控制模拟程序的执行流程。

5. **内置函数调用模拟:**  代码中存在对 V8 内置函数（Builtin）的调用模拟。当模拟器执行到特定的指令序列时，它会识别出这是一个对内置函数的调用，并打印相关信息，例如函数名和参数。这对于理解 V8 如何执行 JavaScript 代码至关重要。

6. **控制流指令模拟:** 代码实现了条件分支指令（例如 `RO_BEQ`, `RO_BNE`, `RO_BLT` 等）和跳转指令（例如 `RO_JAL`）的模拟，改变程序执行的顺序。

7. **CSR 寄存器操作:**  代码包含了对 RISC-V 控制和状态寄存器 (CSR) 的读写操作 (`RO_CSRRW`, `RO_CSRRS`, `RO_CSRRC` 等)。

8. **浮点运算模拟:**  代码包含了对单精度 (`RO_FLW`, `RO_FSW`) 和双精度浮点数 (`RO_FLD`, `RO_FSD`) 的加载和存储指令的模拟。

9. **RISC-V Vector Extension (RVV) 支持 (如果启用):** 代码片段中出现了 `#ifdef CAN_USE_RVV_INSTRUCTIONS` 和 `DecodeRvv*` 等，表明模拟器具备支持 RISC-V 向量扩展指令的能力。

10. **调试和追踪:**  `v8_flags.trace_sim` 条件下的 `PrintF` 和 `TraceMemRd*` 等函数用于在模拟过程中输出调试信息，帮助开发者理解指令执行过程。

11. **软件中断 (ECALL/EBREAK) 处理:** 代码模拟了 `ECALL` 和 `EBREAK` 指令，触发软件中断。

12. **压缩指令 (C-type) 支持:** 代码包含了对 RISC-V 压缩指令集的解码和执行。

13. **饱和算术 (Vector Extension):**  在 RVV 的部分，可以看到 `sat_add` 和 `sat_sub` 等函数，用于实现饱和算术，这是向量运算中常见的特性。

**关于文件扩展名和 Torque:**

如果 `v8/src/execution/riscv/simulator-riscv.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 运行时内置函数的领域特定语言。 然而，根据您提供的信息，该文件以 `.cc` 结尾，因此它是 C++ 源代码文件。

**与 JavaScript 功能的关系及举例:**

`v8/src/execution/riscv/simulator-riscv.cc` 的核心作用是模拟 RISC-V 指令的执行，而 V8 在某些运行环境中（例如没有硬件 RISC-V 支持时）会使用模拟器来执行 JavaScript 代码。

当 V8 需要执行一段 JavaScript 代码时，它会将其编译成 RISC-V 机器码（或其他支持的架构的机器码）。 如果 V8 运行在一个 RISC-V 架构的机器上，这些机器码可以直接由硬件执行。 但是，如果在非 RISC-V 架构的机器上运行，V8 的 RISC-V 模拟器就会派上用场。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result);
```

当 V8 执行这段代码时，`add` 函数会被编译成一系列 RISC-V 指令。 模拟器会逐条解释这些指令，模拟寄存器的变化、内存的读写等操作，最终得到 `result` 的值。

在 "内置函数调用模拟" 的部分，代码展示了当模拟器遇到对内置函数的调用时会打印信息。 许多 JavaScript 的核心功能，例如数组操作、对象创建等，都由 V8 的内置函数实现。  当 JavaScript 代码调用这些功能时，模拟器会模拟相应的内置函数调用。

**代码逻辑推理 (假设输入与输出):**

以 `RO_ADDI` (Add Immediate) 指令为例：

**假设输入:**

* `rs1_reg()` 返回寄存器 `t0` (假设其值为 `10`)
* `imm12()` 返回立即数 `5`
* `rd_reg()` 返回寄存器 `t1`

**代码逻辑:**

```c++
case RO_ADDI: {
  set_rd(sext_xlen(rs1() + imm12()));
  break;
}
```

**执行过程:**

1. `rs1()` 获取寄存器 `t0` 的值，为 `10`。
2. `imm12()` 获取立即数，为 `5`。
3. `rs1() + imm12()` 计算结果为 `10 + 5 = 15`。
4. `sext_xlen()` 将结果符号扩展到 RISC-V 的字长。
5. `set_rd(15)` 将值 `15` 写入寄存器 `t1`。

**预期输出:**

寄存器 `t1` 的值变为 `15`。

**用户常见的编程错误:**

模拟器代码中涉及到内存访问，因此用户常见的编程错误包括：

1. **访问无效内存地址:**  例如，尝试读取或写入未分配的内存。模拟器中的 `ProbeMemory` 函数会检测这类错误。

   ```javascript
   let arr = [1, 2, 3];
   console.log(arr[10]); // 访问越界
   ```

   在模拟器层面，这可能导致 `ProbeMemory` 返回失败，模拟器会采取相应的错误处理措施。

2. **类型错误导致的内存访问问题:** 例如，将一个指针强制转换为不兼容的类型，导致访问错误的内存区域。

3. **缓冲区溢出:**  向固定大小的缓冲区写入超出其容量的数据。

   ```javascript
   let str = "very long string";
   let buffer = new ArrayBuffer(5);
   let view = new Uint8Array(buffer);
   for (let i = 0; i < str.length; i++) {
     view[i] = str.charCodeAt(i); // 缓冲区溢出
   }
   ```

   模拟器中的存储指令模拟可能会检测到这类问题，或者导致写入到错误的模拟内存位置。

**归纳功能 (第7部分，共10部分):**

作为第7部分，这段代码主要负责 **RISC-V 指令集中算术逻辑运算、数据加载与存储、程序控制流指令以及部分压缩指令的模拟执行**。它处理了通用寄存器和内存的读写，并能识别和模拟对 V8 内置函数的调用。  此外，它还包含了对 CSR 寄存器的操作以及浮点运算指令的模拟。 如果启用了 RISC-V 向量扩展，这部分代码也会包含对向量指令的模拟。  整体而言，这部分代码构成了 RISC-V 模拟器核心执行逻辑的重要组成部分。

### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
& ~sreg_t(1);
      set_pc(next_pc);
      if (v8_flags.trace_sim) {
        Builtin builtin = LookUp((Address)get_pc());
        if (builtin != Builtin::kNoBuiltinId) {
          auto code = builtins_.code(builtin);
          if ((rs1_reg() != ra || imm12() != 0)) {
            if ((Address)get_pc() == code->instruction_start()) {
              sreg_t arg0 = get_register(a0);
              sreg_t arg1 = get_register(a1);
              sreg_t arg2 = get_register(a2);
              sreg_t arg3 = get_register(a3);
              sreg_t arg4 = get_register(a4);
              sreg_t arg5 = get_register(a5);
              sreg_t arg6 = get_register(a6);
              sreg_t arg7 = get_register(a7);
              sreg_t* stack_pointer =
                  reinterpret_cast<sreg_t*>(get_register(sp));
              sreg_t arg8 = stack_pointer[0];
              sreg_t arg9 = stack_pointer[1];
              PrintF(
                  "Call to Builtin at %s "
                  "a0 %08" REGIx_FORMAT " ,a1 %08" REGIx_FORMAT
                  " ,a2 %08" REGIx_FORMAT " ,a3 %08" REGIx_FORMAT
                  " ,a4 %08" REGIx_FORMAT " ,a5 %08" REGIx_FORMAT
                  " ,a6 %08" REGIx_FORMAT " ,a7 %08" REGIx_FORMAT
                  " ,0(sp) %08" REGIx_FORMAT " ,8(sp) %08" REGIx_FORMAT
                  " ,sp %08" REGIx_FORMAT ",fp %08" REGIx_FORMAT " \n",
                  builtins_.name(builtin), arg0, arg1, arg2, arg3, arg4, arg5,
                  arg6, arg7, arg8, arg9, get_register(sp), get_register(fp));
            }
          } else if (rd_reg() == zero_reg) {
            PrintF("Return to Builtin at %s \n", builtins_.name(builtin));
          }
        }
      }
      break;
    }
    case RO_LB: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int8_t))) return;
      int8_t val = ReadMem<int8_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LH: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int16_t))) return;
      int16_t val = ReadMem<int16_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LW: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      int32_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LBU: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int8_t))) return;
      uint8_t val = ReadMem<uint8_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LHU: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int16_t))) return;
      uint16_t val = ReadMem<uint16_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_LWU: {
      int64_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rd(zext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
    case RO_LD: {
      int64_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rd_reg()));
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    case RO_ADDI: {
      set_rd(sext_xlen(rs1() + imm12()));
      break;
    }
    case RO_SLTI: {
      set_rd(sreg_t(rs1()) < sreg_t(imm12()));
      break;
    }
    case RO_SLTIU: {
      set_rd(reg_t(rs1()) < reg_t(imm12()));
      break;
    }
    case RO_XORI: {
      set_rd(imm12() ^ rs1());
      break;
    }
    case RO_ORI: {
      set_rd(imm12() | rs1());
      break;
    }
    case RO_ANDI: {
      set_rd(imm12() & rs1());
      break;
    }
    case OP_SHL: {
      switch (instr_.Funct6FieldRaw() | OP_SHL) {
        case RO_SLLI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(rs1() << shamt6()));
          break;
        case RO_BCLRI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() & ~(1l << index));
          break;
        }
        case RO_BINVI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() ^ (1l << index));
          break;
        }
        case RO_BSETI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd(rs1() | (1l << index));
          break;
        }
        case OP_COUNT:
          switch (instr_.Shamt()) {
            case 0: {  // clz
              sreg_t x = rs1();
              int highest_setbit = -1;
              for (auto i = xlen - 1; i >= 0; i--) {
                if ((x & (1l << i))) {
                  highest_setbit = i;
                  break;
                }
              }
              set_rd(xlen - 1 - highest_setbit);
              break;
            }
            case 1: {  // ctz
              sreg_t x = rs1();
              int lowest_setbit = xlen;
              for (auto i = 0; i < xlen; i++) {
                if ((x & (1l << i))) {
                  lowest_setbit = i;
                  break;
                }
              }
              set_rd(lowest_setbit);
              break;
            }
            case 2: {  // cpop
              int i = 0;
              sreg_t n = rs1();
              while (n) {
                n &= (n - 1);
                i++;
              }
              set_rd(i);
              break;
            }
            case 4:
              set_rd(int8_t(rs1()));
              break;
            case 5:
              set_rd(int16_t(rs1()));
              break;
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case OP_SHR: {  //  RO_SRAI
      switch (instr_.Funct6FieldRaw() | OP_SHR) {
        case RO_SRLI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(zext_xlen(rs1()) >> shamt6()));
          break;
        case RO_SRAI:
          require(shamt6() < xlen);
          set_rd(sext_xlen(sext_xlen(rs1()) >> shamt6()));
          break;
        case RO_BEXTI: {
          require(shamt6() < xlen);
          sreg_t index = shamt6() & (xlen - 1);
          set_rd((rs1() >> index) & 1);
          break;
        }
        case RO_ORCB&(kFunct6Mask | OP_SHR): {
          reg_t rs1_val = rs1();
          reg_t result = 0;
          reg_t mask = 0xFF;
          reg_t step = 8;
          for (reg_t i = 0; i < xlen; i += step) {
            if ((rs1_val & mask) != 0) {
              result |= mask;
            }
            mask <<= step;
          }
          set_rd(result);
          break;
        }
        case RO_RORI: {
#ifdef V8_TARGET_ARCH_RISCV64
          int16_t shamt = shamt6();
#else
          int16_t shamt = shamt5();
#endif
          set_rd((reg_t(rs1()) >> shamt) | (reg_t(rs1()) << (xlen - shamt)));
          break;
        }
        case RO_REV8: {
          if (imm12() == RO_REV8_IMM12) {
            reg_t input = rs1();
            reg_t output = 0;
            reg_t j = xlen - 1;
            for (int i = 0; i < xlen; i += 8) {
              output |= ((input >> (j - 7)) & 0xff) << i;
              j -= 8;
            }
            set_rd(output);
            break;
          }
          UNSUPPORTED_RISCV();
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_ADDIW: {
      set_rd(sext32(rs1() + imm12()));
      break;
    }
    case OP_SHLW:
      switch (instr_.Funct7FieldRaw() | OP_SHLW) {
        case RO_SLLIW:
          set_rd(sext32(rs1() << shamt5()));
          break;
        case RO_SLLIUW:
          set_rd(zext32(rs1()) << shamt6());
          break;
        case OP_COUNTW: {
          switch (instr_.Shamt()) {
            case 0: {  // clzw
              sreg_t x = rs1();
              int highest_setbit = -1;
              for (auto i = 31; i >= 0; i--) {
                if ((x & (1l << i))) {
                  highest_setbit = i;
                  break;
                }
              }
              set_rd(31 - highest_setbit);
              break;
            }
            case 1: {  // ctzw
              sreg_t x = rs1();
              int lowest_setbit = 32;
              for (auto i = 0; i < 32; i++) {
                if ((x & (1l << i))) {
                  lowest_setbit = i;
                  break;
                }
              }
              set_rd(lowest_setbit);
              break;
            }
            case 2: {  // cpopw
              int i = 0;
              int32_t n = static_cast<int32_t>(rs1());
              while (n) {
                n &= (n - 1);
                i++;
              }
              set_rd(i);
              break;
            }
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case OP_SHRW: {  //  RO_SRAI
      switch (instr_.Funct7FieldRaw() | OP_SHRW) {
        case RO_SRLIW:
          set_rd(sext32(uint32_t(rs1()) >> shamt5()));
          break;
        case RO_SRAIW:
          set_rd(sext32(int32_t(rs1()) >> shamt5()));
          break;
        case RO_RORIW: {
          reg_t extz_rs1 = zext32(rs1());
          int16_t shamt = shamt5();
          set_rd(sext32((extz_rs1 >> shamt) | (extz_rs1 << (32 - shamt))));
          break;
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    case RO_FENCE: {
      // DO nothing in sumulator
      break;
    }
    case RO_ECALL: {                   // RO_EBREAK
      if (instr_.Imm12Value() == 0) {  // ECALL
        SoftwareInterrupt();
      } else if (instr_.Imm12Value() == 1) {  // EBREAK
        SoftwareInterrupt();
      } else {
        UNSUPPORTED();
      }
      break;
    }
      // TODO(riscv): use Zifencei Standard Extension macro block
    case RO_FENCE_I: {
      // spike: flush icache.
      break;
    }
      // TODO(riscv): use Zicsr Standard Extension macro block
    case RO_CSRRW: {
      if (rd_reg() != zero_reg) {
        set_rd(zext_xlen(read_csr_value(csr_reg())));
      }
      write_csr_value(csr_reg(), rs1());
      break;
    }
    case RO_CSRRS: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (rs1_reg() != zero_reg) {
        set_csr_bits(csr_reg(), rs1());
      }
      break;
    }
    case RO_CSRRC: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (rs1_reg() != zero_reg) {
        clear_csr_bits(csr_reg(), rs1());
      }
      break;
    }
    case RO_CSRRWI: {
      if (rd_reg() != zero_reg) {
        set_rd(zext_xlen(read_csr_value(csr_reg())));
      }
      write_csr_value(csr_reg(), imm5CSR());
      break;
    }
    case RO_CSRRSI: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (imm5CSR() != 0) {
        set_csr_bits(csr_reg(), imm5CSR());
      }
      break;
    }
    case RO_CSRRCI: {
      set_rd(zext_xlen(read_csr_value(csr_reg())));
      if (imm5CSR() != 0) {
        clear_csr_bits(csr_reg(), imm5CSR());
      }
      break;
    }
    // TODO(riscv): use F Extension macro block
    case RO_FLW: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(float))) return;
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_frd(Float32::FromBits(val), false);
      TraceMemRdFloat(addr, Float32::FromBits(val),
                      get_fpu_register(frd_reg()));
      break;
    }
    // TODO(riscv): use D Extension macro block
    case RO_FLD: {
      sreg_t addr = rs1() + imm12();
      if (!ProbeMemory(addr, sizeof(double))) return;
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_drd(Float64::FromBits(val), false);
      TraceMemRdDouble(addr, Float64::FromBits(val),
                       get_fpu_register(frd_reg()));
      break;
    }
    default: {
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (!DecodeRvvVL()) {
        UNSUPPORTED();
      }
      break;
#else
      UNSUPPORTED();
#endif
    }
  }
}

void Simulator::DecodeRVSType() {
  switch (instr_.InstructionBits() & kSTypeMask) {
    case RO_SB:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int8_t))) return;
      WriteMem<uint8_t>(rs1() + s_imm12(), (uint8_t)rs2(), instr_.instr());
      break;
    case RO_SH:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int16_t))) return;
      WriteMem<uint16_t>(rs1() + s_imm12(), (uint16_t)rs2(), instr_.instr());
      break;
    case RO_SW:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int32_t))) return;
      WriteMem<uint32_t>(rs1() + s_imm12(), (uint32_t)rs2(), instr_.instr());
      break;
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_SD:
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(int64_t))) return;
      WriteMem<uint64_t>(rs1() + s_imm12(), (uint64_t)rs2(), instr_.instr());
      break;
#endif /*V8_TARGET_ARCH_RISCV64*/
    // TODO(riscv): use F Extension macro block
    case RO_FSW: {
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(float))) return;
      WriteMem<Float32>(rs1() + s_imm12(),
                        get_fpu_register_Float32(rs2_reg(), false),
                        instr_.instr());
      break;
    }
    // TODO(riscv): use D Extension macro block
    case RO_FSD: {
      if (!ProbeMemory(rs1() + s_imm12(), sizeof(double))) return;
      WriteMem<Float64>(rs1() + s_imm12(), get_fpu_register_Float64(rs2_reg()),
                        instr_.instr());
      break;
    }
    default:
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (!DecodeRvvVS()) {
        UNSUPPORTED();
      }
      break;
#else
      UNSUPPORTED();
#endif
  }
}

void Simulator::DecodeRVBType() {
  switch (instr_.InstructionBits() & kBTypeMask) {
    case RO_BEQ:
      if (rs1() == rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BNE:
      if (rs1() != rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BLT:
      if (rs1() < rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BGE:
      if (rs1() >= rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BLTU:
      if ((reg_t)rs1() < (reg_t)rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    case RO_BGEU:
      if ((reg_t)rs1() >= (reg_t)rs2()) {
        int64_t next_pc = get_pc() + boffset();
        set_pc(next_pc);
      }
      break;
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeRVUType() {
  // U Type doesn't have additoinal mask
  switch (instr_.BaseOpcodeFieldRaw()) {
    case LUI:
      set_rd(u_imm20());
      break;
    case AUIPC:
      set_rd(sext_xlen(u_imm20() + get_pc()));
      break;
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeRVJType() {
  // J Type doesn't have additional mask
  switch (instr_.BaseOpcodeValue()) {
    case JAL: {
      set_rd(get_pc() + kInstrSize);
      int64_t next_pc = get_pc() + imm20J();
      set_pc(next_pc);
      break;
    }
    default:
      UNSUPPORTED();
  }
}
void Simulator::DecodeCRType() {
  switch (instr_.RvcFunct4Value()) {
    case 0b1000:
      if (instr_.RvcRs1Value() != 0 && instr_.RvcRs2Value() == 0) {  // c.jr
        set_pc(rvc_rs1());
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() != 0) {  // c.mv
        set_rvc_rd(sext_xlen(rvc_rs2()));
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case 0b1001:
      if (instr_.RvcRs1Value() == 0 && instr_.RvcRs2Value() == 0) {  // c.ebreak
        DieOrDebug();
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() == 0) {  // c.jalr
        set_register(ra, get_pc() + kShortInstrSize);
        set_pc(rvc_rs1());
      } else if (instr_.RvcRdValue() != 0 &&
                 instr_.RvcRs2Value() != 0) {  // c.add
        set_rvc_rd(sext_xlen(rvc_rs1() + rvc_rs2()));
      } else {
        UNSUPPORTED();
      }
      break;
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCAType() {
  switch (instr_.InstructionBits() & kCATypeMask) {
    case RO_C_SUB:
      set_rvc_rs1s(sext_xlen(rvc_rs1s() - rvc_rs2s()));
      break;
    case RO_C_XOR:
      set_rvc_rs1s(rvc_rs1s() ^ rvc_rs2s());
      break;
    case RO_C_OR:
      set_rvc_rs1s(rvc_rs1s() | rvc_rs2s());
      break;
    case RO_C_AND:
      set_rvc_rs1s(rvc_rs1s() & rvc_rs2s());
      break;
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SUBW:
      set_rvc_rs1s(sext32(rvc_rs1s() - rvc_rs2s()));
      break;
    case RO_C_ADDW:
      set_rvc_rs1s(sext32(rvc_rs1s() + rvc_rs2s()));
      break;
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCIType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_NOP_ADDI:
      if (instr_.RvcRdValue() == 0)  // c.nop
        break;
      else  // c.addi
        set_rvc_rd(sext_xlen(rvc_rs1() + rvc_imm6()));
      break;
#if V8_TARGET_ARCH_RISCV64
    case RO_C_ADDIW:
      set_rvc_rd(sext32(rvc_rs1() + rvc_imm6()));
      break;
#endif
    case RO_C_LI:
      set_rvc_rd(sext_xlen(rvc_imm6()));
      break;
    case RO_C_LUI_ADD:
      if (instr_.RvcRdValue() == 2) {
        // c.addi16sp
        int64_t value = get_register(sp) + rvc_imm6_addi16sp();
        set_register(sp, value);
      } else if (instr_.RvcRdValue() != 0 && instr_.RvcRdValue() != 2) {
        // c.lui
        set_rvc_rd(rvc_u_imm6());
      } else {
        UNSUPPORTED();
      }
      break;
    case RO_C_SLLI:
      set_rvc_rd(sext_xlen(rvc_rs1() << rvc_shamt6()));
      break;
    case RO_C_FLDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_rvc_drd(Float64::FromBits(val), false);
      TraceMemRdDouble(addr, Float64::FromBits(val),
                       get_fpu_register(rvc_frd_reg()));
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_LWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_lwsp();
      int64_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
    case RO_C_LDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case RO_C_FLWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_ldsp();
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rvc_frd(Float32::FromBits(val), false);
      TraceMemRdFloat(addr, Float32::FromBits(val),
                      get_fpu_register(rvc_frd_reg()));
      break;
    }
    case RO_C_LWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_lwsp();
      int32_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rd(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rd_reg()));
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCIWType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_ADDI4SPN: {
      set_rvc_rs2s(get_register(sp) + rvc_imm8_addi4spn());
      break;
      default:
        UNSUPPORTED();
    }
  }
}

void Simulator::DecodeCSSType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_FSDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<Float64>(addr, get_fpu_register_Float64(rvc_rs2_reg()),
                        instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV32
    case RO_C_FSWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<Float32>(addr, get_fpu_register_Float32(rvc_rs2_reg(), false),
                        instr_.instr());
      break;
    }
#endif
    case RO_C_SWSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_swsp();
      WriteMem<int32_t>(addr, (int32_t)rvc_rs2(), instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SDSP: {
      sreg_t addr = get_register(sp) + rvc_imm6_sdsp();
      WriteMem<int64_t>(addr, (int64_t)rvc_rs2(), instr_.instr());
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCLType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_LW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_w();
      int64_t val = ReadMem<int32_t>(addr, instr_.instr());
      set_rvc_rs2s(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rs2s_reg()));
      break;
    }
    case RO_C_FLD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      uint64_t val = ReadMem<uint64_t>(addr, instr_.instr());
      set_rvc_drs2s(Float64::FromBits(val), false);
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_LD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      int64_t val = ReadMem<int64_t>(addr, instr_.instr());
      set_rvc_rs2s(sext_xlen(val), false);
      TraceMemRd(addr, val, get_register(rvc_rs2s_reg()));
      break;
    }
#elif V8_TARGET_ARCH_RISCV32
    case RO_C_FLW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      uint32_t val = ReadMem<uint32_t>(addr, instr_.instr());
      set_rvc_frs2s(Float32::FromBits(val), false);
      break;
    }
#endif
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCSType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_SW: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_w();
      WriteMem<int32_t>(addr, (int32_t)rvc_rs2s(), instr_.instr());
      break;
    }
#if V8_TARGET_ARCH_RISCV64
    case RO_C_SD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      WriteMem<int64_t>(addr, (int64_t)rvc_rs2s(), instr_.instr());
      break;
    }
#endif
    case RO_C_FSD: {
      sreg_t addr = rvc_rs1s() + rvc_imm5_d();
      WriteMem<double>(addr, static_cast<double>(rvc_drs2s()), instr_.instr());
      break;
    }
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCJType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_J: {
      set_pc(get_pc() + instr_.RvcImm11CJValue());
      break;
    }
    default:
      UNSUPPORTED();
  }
}

void Simulator::DecodeCBType() {
  switch (instr_.RvcOpcode()) {
    case RO_C_BNEZ:
      if (rvc_rs1() != 0) {
        sreg_t next_pc = get_pc() + rvc_imm8_b();
        set_pc(next_pc);
      }
      break;
    case RO_C_BEQZ:
      if (rvc_rs1() == 0) {
        sreg_t next_pc = get_pc() + rvc_imm8_b();
        set_pc(next_pc);
      }
      break;
    case RO_C_MISC_ALU:
      if (instr_.RvcFunct2BValue() == 0b00) {  // c.srli
        set_rvc_rs1s(sext_xlen(sext_xlen(rvc_rs1s()) >> rvc_shamt6()));
      } else if (instr_.RvcFunct2BValue() == 0b01) {  // c.srai
        require(rvc_shamt6() < xlen);
        set_rvc_rs1s(sext_xlen(sext_xlen(rvc_rs1s()) >> rvc_shamt6()));
      } else if (instr_.RvcFunct2BValue() == 0b10) {  // c.andi
        set_rvc_rs1s(rvc_imm6() & rvc_rs1s());
      } else {
        UNSUPPORTED();
      }
      break;
    default:
      UNSUPPORTED();
  }
}

/**
 * RISCV-ISA-SIM
 *
 * @link      https://github.com/riscv/riscv-isa-sim/
 * @copyright Copyright (c)  The Regents of the University of California
 * @license   hhttps://github.com/riscv/riscv-isa-sim/blob/master/LICENSE
 */
// ref:  https://locklessinc.com/articles/sat_arithmetic/
template <typename T, typename UT>
static inline T sat_add(T x, T y, bool& sat) {
  UT ux = x;
  UT uy = y;
  UT res = ux + uy;
  sat = false;
  int sh = sizeof(T) * 8 - 1;

  /* Calculate overflowed result. (Don't change the sign bit of ux) */
  ux = (ux >> sh) + (((UT)0x1 << sh) - 1);

  /* Force compiler to use cmovns instruction */
  if ((T)((ux ^ uy) | ~(uy ^ res)) >= 0) {
    res = ux;
    sat = true;
  }

  return res;
}

template <typename T, typename UT>
static inline T sat_sub(T x, T y, bool& sat) {
  UT ux = x;
  UT uy = y;
  UT res = ux - uy;
  sat = false;
  int sh = sizeof(T) * 8 - 1;

  /* Calculate overflowed result. (Don't change the sign bit of ux) */
  ux = (ux >> sh) + (((UT)0x1 << sh) - 1);

  /* Force compiler to use cmovns instruction */
  if ((T)((ux ^ uy) & (ux ^ res)) < 0) {
    res = ux;
    sat = true;
  }

  return res;
}

template <typename T>
T sat_addu(T x, T y, bool& sat) {
  T res = x + y;
  sat = false;

  sat = res < x;
  res |= -(res < x);

  return res;
}

template <typename T>
T sat_subu(T x, T y, bool& sat) {
  T res = x - y;
  sat = false;

  sat = !(res <= x);
  res &= -(res <= x);

  return res;
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
void Simulator::DecodeRvvIVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 + vs2; });
      break;
    }
    case RO_V_VSADD_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VV:
      RVV_VI_VV_ULOOP({
        vd = vs2 + vs1;
        vd |= -(vd < vs2);
      })
      break;
    case RO_V_VSUB_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 - vs1; })
      break;
    }
    case RO_V_VSSUB_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_PARAMS(8);
          vd = sat_sub<int8_t, uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_PARAMS(16);
          vd = sat_sub<int16_t, uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_PARAMS(32);
          vd = sat_sub<int32_t, uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_PARAMS(64);
          vd = sat_sub<int64_t, uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSSUBU_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VV_UPARAMS(8);
          vd = sat_subu<uint8_t>(vs2, vs1, sat);
          break;
        }
        case E16: {
          VV_UPARAMS(16);
          vd = sat_subu<uint16_t>(vs2, vs1, sat);
          break;
        }
        case E32: {
          VV_UPARAMS(32);
          vd = sat_subu<uint32_t>(vs2, vs1, sat);
          break;
        }
        default: {
          VV_UPARAMS(64);
          vd = sat_subu<uint64_t>(vs2, vs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VAND_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 & vs2; })
      break;
    }
    case RO_V_VOR_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 | vs2; })
      break;
    }
    case RO_V_VXOR_VV: {
      RVV_VI_VV_LOOP({ vd = vs1 ^ vs2; })
      break;
    }
    case RO_V_VMAXU_VV: {
      RVV_VI_VV_ULOOP({
        if (vs1 <= vs2) {
          vd = vs2;
        } else {
          vd = vs1;
        }
      })
      break;
    }
    case RO_V_VMAX_VV: {
      RVV_VI_VV_LOOP({
        if (vs1 <= vs2) {
          vd = vs2;
        } else {
          vd = vs1;
        }
      })
      break;
    }
    case RO_V_VMINU_VV: {
      RVV_VI_VV_ULOOP({
        if (vs1 <= vs2) {
          vd = vs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMIN_VV: {
      RVV_VI_VV_LOOP({
        if (vs1 <= vs2) {
          vd = vs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMV_VV: {
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = vs1;
          USE(simm5);
          USE(vs2);
          USE(rs1);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? vs1 : vs2;
          USE(simm5);
          USE(rs1);
        });
      }
      break;
    }
    case RO_V_VMSEQ_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs1 == vs2; })
      break;
    }
    case RO_V_VMSNE_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs1 != vs2; })
      break;
    }
    case RO_V_VMSLTU_VV: {
      RVV_VI_VV_ULOOP_CMP({ res = vs2 < vs1; })
      break;
    }
    case RO_V_VMSLT_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs2 < vs1; })
      break;
    }
    case RO_V_VMSLE_VV: {
      RVV_VI_VV_LOOP_CMP({ res = vs2 <= vs1; })
      break;
    }
    case RO_V_VMSLEU_VV: {
      RVV_VI_VV_ULOOP_CMP({ res = vs2 <= vs1; })
      break;
    }
    case RO_V_VADC_VV:
      if (instr_.RvvVM()) {
        RVV_VI_VV_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = vs1 + vs2 + (v0 >> mpos) & 0x1;
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VSLL_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 << (vs1 & (rvv_sew() - 1)); })
      break;
    }
    case RO_V_VSRL_VV:
      RVV_VI_VV_ULOOP({ vd = vs2 >> (vs1 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSRA_VV:
      RVV_VI_VV_LOOP({ vd = vs2 >> (vs1 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSMUL_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      RVV_VI_LOOP_MASK_SKIP()
      if (rvv_vsew() == E8) {
        VV_PARAMS(8);
        int16_t result = (int16_t)vs1 * (int16_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 7);
        result = (result >> 7) + round;
        vd = signed_saturation<int16_t, int8_t>(result, 8);
      } else if (rvv_vsew() == E16) {
        VV_PARAMS(16);
        int32_t result = (int32_t)vs1 * (int32_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 15);
        result = (result >> 15) + round;
        vd = signed_saturation<int32_t, int16_t>(result, 16);
      } else if (rvv_vsew() == E32) {
        VV_PARAMS(32);
        int64_t result = (int64_t)vs1 * (int64_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 31);
        result = (result >> 31) + round;
        vd = signed_saturation<int64_t, int32_t>(result, 32);
      } else if (rvv_vsew() == E64) {
        VV_PARAMS(64);
        __int128_t result = (__int128_t)vs1 * (__int128_t)vs2;
        uint8_t round = get_round(static_cast<int>(rvv_vxrm()), result, 63);
        result = (result >> 63) + round;
        vd = signed_saturation<__int128_t, int64_t>(result, 64);
      } else {
        UNREACHABLE();
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
      break;
    }
    case RO_V_VRGATHER_VV: {
      RVV_VI_GENERAL_LOOP_BASE
      CHECK_NE(rvv_vs1_reg(), rvv_vd_reg());
      CHECK_NE(rvv_vs2_reg(), rvv_vd_reg());
      switch (rvv_vsew()) {
        case E8: {
          auto vs1 = Rvvelt<uint8_t>(rvv_vs1_reg(), i);
          // if (i > 255) continue;
          Rvvelt<uint8_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint8_t>(rvv_vs2_reg(), vs1);
          break;
        }
        case E16: {
          auto vs1 = Rvvelt<uint16_t>(rvv_vs1_reg(), i);
          Rvvelt<uint16_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint16_t>(rvv_vs2_reg(), vs1);
          break;
        }
        case E32: {
          auto vs1 = Rvvelt<uint32_t>(rvv_vs1_reg(), i);
          Rvvelt<uint32_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint32_t>(rvv_vs2_reg(), vs1);
          break;
        }
        default: {
          auto vs1 = Rvvelt<uint64_t>(rvv_vs1_reg(), i);
          Rvvelt<uint64_t>(rvv_vd_reg(), i, true) =
              vs1 >= rvv_vlmax() ? 0 : Rvvelt<uint64_t>(rvv_vs2_reg(), vs1);
          break;
        }
      }
      RVV_VI_LOOP_END;
      rvv_trace_vd();
      break;
    }
    default:
      // v8::base::Em
```