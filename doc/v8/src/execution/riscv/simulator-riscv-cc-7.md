Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Request:** The request asks for a functional summary of a specific V8 source file (`simulator-riscv.cc`), specifically focusing on its role in simulating RISC-V vector instructions (RVV). It also asks about potential Torque involvement, JavaScript connections, logical deductions, common errors, and a final summary considering this is part 8 of 10.

2. **Initial Scan for Keywords:**  Quickly scan the code for prominent keywords and patterns. I see:
    * `Simulator` (class name)
    * `DecodeRvv...` (multiple functions like `DecodeRvvIVI`, `DecodeRvvIVX`, etc.)
    * `instr_` (likely the current instruction being processed)
    * `RVV_...` (macros or function calls related to RVV)
    * `UNIMPLEMENTED_RISCV()` (suggests incomplete or placeholder functionality)
    * Loop structures with `RVV_VI_...LOOP` (likely iterating over vector elements)
    * Specific RISC-V vector instruction mnemonics (like `VADD`, `VMUL`, `VFDIV`, etc.)
    * `sat_add`, `sat_sub` (saturation arithmetic)
    * `set_rvv_...`, `get_rvv_...` (accessing simulator state)
    * Floating-point operations and checks (`is_invalid_fdiv`, `std::isnan`, `FclassHelper`)

3. **Identify Core Functionality:**  The `DecodeRvv...` functions and the presence of RVV instruction mnemonics strongly suggest that this code is responsible for *interpreting and executing* RISC-V vector instructions within the V8 simulator. The `Simulator` class reinforces this idea.

4. **Analyze `DecodeRvv...` Functions:** Notice the naming pattern: `DecodeRvvIVI`, `DecodeRvvIVX`, `DecodeRvvMVV`, `DecodeRvvMVX`, `DecodeRvvFVV`. This suggests a categorization of RVV instructions based on operand types (e.g., Immediate-Vector-Vector, Immediate-Vector-Scalar, Vector-Vector-Vector, etc.). The `switch` statements within each function, based on `instr_.InstructionBits() & kVTypeMask`, further confirm this, dispatching execution to specific instruction handlers.

5. **Focus on Common Patterns within Handlers:** Observe the prevalent loop structures (`RVV_VI_...LOOP`). These loops iterate over the elements of the vector registers, performing the operation defined by the specific instruction. The macros and helper functions (`RVV_VI_GENERAL_LOOP_BASE`, `VI_PARAMS`, `sat_add`) abstract away some of the low-level details of accessing and manipulating vector elements.

6. **Look for JavaScript Connections:**  There's no immediate, explicit connection to JavaScript code in this snippet. The code operates at a very low level, simulating machine instructions. The connection to JavaScript would be *indirect*: JavaScript code might eventually trigger the execution of these simulated instructions through the V8 engine's execution pipeline.

7. **Consider Torque:** The prompt mentions `.tq` files. This file ends in `.cc`, so it's C++, not Torque.

8. **Identify Logical Deductions and Examples:**
    * **Instruction Decoding:** The `switch` statements are the core of instruction decoding. The `instr_.InstructionBits()` are the input, and the execution of a specific code block is the output.
    * **Vector Operations:**  Simple examples can be constructed for instructions like `VADD` (vector addition). The input would be the contents of vector registers, and the output would be the resulting vector.
    * **Saturation Arithmetic:** The `sat_add` functions demonstrate how overflow/underflow are handled, clamping results to the maximum/minimum representable values.

9. **Think About Common Programming Errors:**  Given the low-level nature of the code, common errors in *this context* would relate to:
    * **Incorrect Instruction Encoding:** Providing an invalid instruction bit pattern.
    * **Register Access Errors:** Trying to access non-existent or incorrect vector registers.
    * **Vector Length Mismatches:**  Operations might have constraints on vector lengths.
    * **Type Mismatches:** Applying operations to incompatible data types within vectors (though the simulator handles type distinctions based on `rvv_vsew()`).

10. **Synthesize the Summary (Considering "Part 8 of 10"):**  Given that this is part 8 of 10, the functionality described here is likely a significant portion of the RISC-V vector instruction simulation within V8. The previous parts probably dealt with core simulator infrastructure, and the following parts might cover more specialized or less frequently used instructions, or perhaps integration with other V8 components.

11. **Refine and Organize:**  Structure the findings into the requested categories: Functionality, Torque, JavaScript relation, Logical deduction, Common errors, and Overall Summary. Use clear and concise language. Emphasize the key role of simulating RVV instructions. Acknowledge the "UNIMPLEMENTED" sections and the indirect connection to JavaScript.

By following this thought process, starting with a broad overview and then drilling down into specific details and patterns, we can arrive at a comprehensive and accurate understanding of the code's purpose and function.
这是 v8 引擎中用于 RISC-V 架构的模拟器部分源代码，专门处理 RISC-V 向量扩展（RVV）指令的模拟执行。

**功能归纳:**

这个代码片段（`simulator-riscv.cc` 的一部分）的主要功能是 **解码并模拟执行 RISC-V 向量指令 (RVV)**。 它针对不同的 RVV 指令格式和操作码提供了相应的处理逻辑。

更具体地说，它实现了以下功能：

1. **指令解码:**  通过检查指令的位模式（例如 `kBaseOpcodeMask`, `kFunct3Mask`, `kVTypeMask`），确定当前需要执行的 RVV 指令类型。
2. **向量操作模拟:**  针对各种 RVV 指令，如算术运算（加、减、乘、除）、逻辑运算（与、或、异或）、比较运算、移位操作、数据搬运、类型转换、规约操作等，提供了精确的模拟实现。
3. **处理不同的操作数类型:**  代码区分了立即数 (VI)、通用寄存器 (VX) 和向量寄存器 (VV) 作为操作数的不同指令格式，并进行相应的处理。
4. **支持不同的向量元素宽度 (SEW):**  代码中使用了 `rvv_vsew()` 来获取当前的向量元素宽度，并根据不同的宽度（E8, E16, E32, E64）执行相应的操作。
5. **处理向量掩码 (Masking):**  通过 `instr_.RvvVM()` 检查指令是否带有掩码，并在循环中根据掩码位决定是否执行当前元素的运算。
6. **处理向量长度 (VL) 和起始位置 (vstart):**  代码中使用了 `rvv_vl()` 和 `rvv_vstart()` 来获取和设置当前的向量长度和起始位置，以模拟向量操作的正确行为。
7. **支持饱和运算:**  对于带有 "S" 前缀的指令（如 `VSADD`），代码实现了饱和加减运算，防止溢出。
8. **支持浮点向量运算:**  `DecodeRvvFVV` 函数处理浮点向量指令，包括浮点数的加减乘除、类型转换、比较等操作，并考虑了 NaN、无穷大等特殊情况，以及浮点状态标志 (fflags) 的设置。
9. **处理规约操作:**  `DecodeRvvMVV` 中的 `VREDMAXU`, `VREDMAX`, `VREDMINU`, `VREDMIN` 等指令实现了向量的规约操作。
10. **处理压缩操作:** `VCOMPRESS_VV` 指令实现了根据掩码压缩向量的功能.
11. **未实现指令处理:**  对于尚未实现的指令，代码会调用 `UNIMPLEMENTED_RISCV()`，表明该功能还未完成。

**关于代码特性:**

* **`.tq` 结尾:**  `v8/src/execution/riscv/simulator-riscv.cc` 文件以 `.cc` 结尾，这意味着它是 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码的文件通常以 `.tq` 结尾。
* **与 JavaScript 的关系:**  此代码直接参与 V8 引擎的执行，而 V8 引擎是 JavaScript 的运行时环境。当 JavaScript 代码执行涉及到需要模拟的 RISC-V 向量指令时（例如，通过 WebAssembly 或某些需要底层优化的场景），V8 的解释器或编译器可能会生成这些指令，然后由这里的模拟器代码来执行。

**JavaScript 示例 (概念性):**

虽然无法直接用纯 JavaScript 展示这段 C++ 代码的功能，但可以想象一个概念性的例子，展示 RVV 指令在执行底层向量操作时的作用：

```javascript
// 假设 JavaScript 引擎内部使用了类似 RVV 的向量指令

function vectorAdd(a, b) {
  // 内部可能被编译成 RVV 的向量加法指令
  let result = new Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] + b[i];
  }
  return result;
}

let vector1 = [1, 2, 3, 4];
let vector2 = [5, 6, 7, 8];
let sum = vectorAdd(vector1, vector2);
console.log(sum); // 输出 [6, 8, 10, 12]
```

在 V8 内部，当执行 `vectorAdd` 函数时，如果目标架构支持 RVV，V8 可能会将循环内的加法操作编译成一条或几条 RVV 的向量加法指令。`simulator-riscv.cc` 中的代码就是负责模拟执行这些指令，得到正确的结果。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `instr_` 代表一条 RVV 加法指令 `vadd.vv v1, v2, v3`，其中：
    * `v1`, `v2`, `v3` 是向量寄存器编号。
    * `v2` 包含 `[10, 20, 30, 40]`
    * `v3` 包含 `[1, 2, 3, 4]`
    * 向量长度 `rvv_vl()` 为 4。

**模拟器执行的逻辑 (简化):**

```c++
// ... 在 DecodeRvvMVV 中的 RO_V_VADD_VV 分支 ...
RVV_VI_VV_LOOP({ vd = vs2 + vs1; }) // 假设 vd 对应 v1，vs2 对应 v2，vs1 对应 v3
```

**输出:**

* 向量寄存器 `v1` 的内容将被更新为 `[11, 22, 33, 44]`。

**用户常见的编程错误 (在 RVV 上):**

由于这段代码是模拟器的一部分，用户通常不会直接编写针对 RVV 的机器码。但如果用户在编写需要底层优化的代码（例如 WebAssembly 或通过编译器 intrinsics 使用向量指令），可能会遇到以下概念上的错误，这些错误会被模拟器捕捉或影响模拟结果：

1. **向量长度不匹配:** 假设两个向量的操作要求它们具有相同的长度，但实际提供的向量长度不同。模拟器会按照 `rvv_vl()` 定义的长度进行操作，可能导致结果不符合预期。
2. **访问越界:**  尝试访问向量寄存器中超出有效长度的元素。模拟器需要正确处理这种情况，可能产生未定义行为或错误。
3. **类型不匹配:**  对不同数据类型的向量进行操作，例如将浮点向量与整型向量相加。RVV 指令通常有严格的类型要求。
4. **掩码使用错误:**  错误地设置或理解掩码位，导致某些元素被错误地处理或跳过。例如，本意是要对部分元素进行操作，但掩码设置错误导致所有元素都被操作。
5. **不理解饱和运算:**  在期望环绕运算时使用了饱和运算指令，导致溢出被钳制在最大/最小值，而不是回绕。

**总结 (作为第 8 部分):**

作为 RISC-V 模拟器的第 8 部分，这个代码片段专注于 **RISC-V 向量扩展 (RVV) 指令的解码和执行**。它涵盖了多种 RVV 指令类型，包括整数和浮点向量运算，并处理了不同的操作数类型、向量长度、掩码等关键特性。这部分是实现完整 RISC-V 向量指令集模拟的关键组成部分，使得 V8 引擎能够在不支持硬件 RVV 的平台上正确执行相关的代码。考虑到这是第 8 部分，可以推测之前的部分可能涉及基础的 RISC-V 指令模拟框架、寄存器管理等，而后续的部分可能会涉及更复杂的 RVV 指令或与 V8 其他组件的集成。

### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
beddedVector<char, 256> buffer;
      // SNPrintF(trace_buf_, " ");
      // disasm::NameConverter converter;
      // disasm::Disassembler dasm(converter);
      // // Use a reasonably large buffer.
      // dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));

      // PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
      //        reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
  set_rvv_vstart(0);
}

void Simulator::DecodeRvvIVI() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVI);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 + vs2; })
      break;
    }
    case RO_V_VSADD_VI: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VI_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, simm5, sat);
          break;
        }
        case E16: {
          VI_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, simm5, sat);
          break;
        }
        case E32: {
          VI_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, simm5, sat);
          break;
        }
        default: {
          VI_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, simm5, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VI: {
      RVV_VI_VI_ULOOP({
        vd = vs2 + uimm5;
        vd |= -(vd < vs2);
      })
      break;
    }
    case RO_V_VRSUB_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 - vs2; })
      break;
    }
    case RO_V_VAND_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 & vs2; })
      break;
    }
    case RO_V_VOR_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 | vs2; })
      break;
    }
    case RO_V_VXOR_VI: {
      RVV_VI_VI_LOOP({ vd = simm5 ^ vs2; })
      break;
    }
    case RO_V_VMV_VI:
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = simm5;
          USE(vs1);
          USE(vs2);
          USE(rs1);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? simm5 : vs2;
          USE(vs1);
          USE(rs1);
        });
      }
      break;
    case RO_V_VMSEQ_VI:
      RVV_VI_VI_LOOP_CMP({ res = simm5 == vs2; })
      break;
    case RO_V_VMSNE_VI:
      RVV_VI_VI_LOOP_CMP({ res = simm5 != vs2; })
      break;
    case RO_V_VMSLEU_VI:
      RVV_VI_VI_ULOOP_CMP({ res = vs2 <= uimm5; })
      break;
    case RO_V_VMSLE_VI:
      RVV_VI_VI_LOOP_CMP({ res = vs2 <= simm5; })
      break;
    case RO_V_VMSGT_VI:
      RVV_VI_VI_LOOP_CMP({ res = vs2 > simm5; })
      break;
    case RO_V_VSLIDEDOWN_VI: {
      RVV_VI_CHECK_SLIDE(false);
      const uint8_t sh = instr_.RvvUimm5();
      RVV_VI_GENERAL_LOOP_BASE

      reg_t offset = 0;
      bool is_valid = (i + sh) < rvv_vlmax();

      if (is_valid) {
        offset = sh;
      }

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEDOWN_PARAMS(8, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E16: {
          VI_XI_SLIDEDOWN_PARAMS(16, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E32: {
          VI_XI_SLIDEDOWN_PARAMS(32, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        default: {
          VI_XI_SLIDEDOWN_PARAMS(64, offset);
          vd = is_valid ? vs2 : 0;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDEUP_VI: {
      RVV_VI_CHECK_SLIDE(true);

      const uint8_t offset = instr_.RvvUimm5();
      RVV_VI_GENERAL_LOOP_BASE
      if (rvv_vstart() < offset && i < offset) continue;

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEUP_PARAMS(8, offset);
          vd = vs2;
        } break;
        case E16: {
          VI_XI_SLIDEUP_PARAMS(16, offset);
          vd = vs2;
        } break;
        case E32: {
          VI_XI_SLIDEUP_PARAMS(32, offset);
          vd = vs2;
        } break;
        default: {
          VI_XI_SLIDEUP_PARAMS(64, offset);
          vd = vs2;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSRL_VI:
      RVV_VI_VI_ULOOP({ vd = vs2 >> (uimm5 & (rvv_sew() - 1)); })
      break;
    case RO_V_VSRA_VI:
      RVV_VI_VI_LOOP({ vd = vs2 >> (simm5 & (rvv_sew() - 1) & 0x1f); })
      break;
    case RO_V_VSLL_VI:
      RVV_VI_VI_ULOOP({ vd = vs2 << (uimm5 & (rvv_sew() - 1)); })
      break;
    case RO_V_VADC_VI:
      if (instr_.RvvVM()) {
        RVV_VI_XI_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = simm5 + vs2 + (v0 >> mpos) & 0x1;
          USE(rs1);
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VNCLIP_WI:
      RVV_VN_CLIP_VI_LOOP()
      break;
    case RO_V_VNCLIPU_WI:
      RVV_VN_CLIPU_VI_LOOP()
      break;
    default:
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvIVX() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVX);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 + vs2; })
      break;
    }
    case RO_V_VSADD_VX: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VX_PARAMS(8);
          vd = sat_add<int8_t, uint8_t>(vs2, rs1, sat);
          break;
        }
        case E16: {
          VX_PARAMS(16);
          vd = sat_add<int16_t, uint16_t>(vs2, rs1, sat);
          break;
        }
        case E32: {
          VX_PARAMS(32);
          vd = sat_add<int32_t, uint32_t>(vs2, rs1, sat);
          break;
        }
        default: {
          VX_PARAMS(64);
          vd = sat_add<int64_t, uint64_t>(vs2, rs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VSADDU_VX: {
      RVV_VI_VX_ULOOP({
        vd = vs2 + rs1;
        vd |= -(vd < vs2);
      })
      break;
    }
    case RO_V_VSUB_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 - rs1; })
      break;
    }
    case RO_V_VSSUB_VX: {
      RVV_VI_GENERAL_LOOP_BASE
      bool sat = false;
      switch (rvv_vsew()) {
        case E8: {
          VX_PARAMS(8);
          vd = sat_sub<int8_t, uint8_t>(vs2, rs1, sat);
          break;
        }
        case E16: {
          VX_PARAMS(16);
          vd = sat_sub<int16_t, uint16_t>(vs2, rs1, sat);
          break;
        }
        case E32: {
          VX_PARAMS(32);
          vd = sat_sub<int32_t, uint32_t>(vs2, rs1, sat);
          break;
        }
        default: {
          VX_PARAMS(64);
          vd = sat_sub<int64_t, uint64_t>(vs2, rs1, sat);
          break;
        }
      }
      set_rvv_vxsat(sat);
      RVV_VI_LOOP_END
      break;
    }
    case RO_V_VRSUB_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 - vs2; })
      break;
    }
    case RO_V_VAND_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 & vs2; })
      break;
    }
    case RO_V_VOR_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 | vs2; })
      break;
    }
    case RO_V_VXOR_VX: {
      RVV_VI_VX_LOOP({ vd = rs1 ^ vs2; })
      break;
    }
    case RO_V_VMAX_VX: {
      RVV_VI_VX_LOOP({
        if (rs1 <= vs2) {
          vd = vs2;
        } else {
          vd = rs1;
        }
      })
      break;
    }
    case RO_V_VMAXU_VX: {
      RVV_VI_VX_ULOOP({
        if (rs1 <= vs2) {
          vd = vs2;
        } else {
          vd = rs1;
        }
      })
      break;
    }
    case RO_V_VMINU_VX: {
      RVV_VI_VX_ULOOP({
        if (rs1 <= vs2) {
          vd = rs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMIN_VX: {
      RVV_VI_VX_LOOP({
        if (rs1 <= vs2) {
          vd = rs1;
        } else {
          vd = vs2;
        }
      })
      break;
    }
    case RO_V_VMV_VX:
      if (instr_.RvvVM()) {
        RVV_VI_VVXI_MERGE_LOOP({
          vd = rs1;
          USE(vs1);
          USE(vs2);
          USE(simm5);
        });
      } else {
        RVV_VI_VVXI_MERGE_LOOP({
          bool use_first = (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
          vd = use_first ? rs1 : vs2;
          USE(vs1);
          USE(simm5);
        });
      }
      break;
    case RO_V_VMSEQ_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 == rs1; })
      break;
    case RO_V_VMSNE_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 != rs1; })
      break;
    case RO_V_VMSLT_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 < rs1; })
      break;
    case RO_V_VMSLTU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 < rs1; })
      break;
    case RO_V_VMSLE_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 <= rs1; })
      break;
    case RO_V_VMSLEU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 <= rs1; })
      break;
    case RO_V_VMSGT_VX:
      RVV_VI_VX_LOOP_CMP({ res = vs2 > rs1; })
      break;
    case RO_V_VMSGTU_VX:
      RVV_VI_VX_ULOOP_CMP({ res = vs2 > rs1; })
      break;
    case RO_V_VSLIDEDOWN_VX: {
      RVV_VI_CHECK_SLIDE(false);

      const sreg_t sh = get_register(rs1_reg());
      RVV_VI_GENERAL_LOOP_BASE

      reg_t offset = 0;
      bool is_valid = (i + sh) < rvv_vlmax();

      if (is_valid) {
        offset = sh;
      }

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEDOWN_PARAMS(8, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E16: {
          VI_XI_SLIDEDOWN_PARAMS(16, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        case E32: {
          VI_XI_SLIDEDOWN_PARAMS(32, offset);
          vd = is_valid ? vs2 : 0;
        } break;
        default: {
          VI_XI_SLIDEDOWN_PARAMS(64, offset);
          vd = is_valid ? vs2 : 0;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDEUP_VX: {
      RVV_VI_CHECK_SLIDE(true);

      const reg_t offset = get_register(rs1_reg());
      RVV_VI_GENERAL_LOOP_BASE
      if (rvv_vstart() < offset && i < offset) continue;

      switch (rvv_vsew()) {
        case E8: {
          VI_XI_SLIDEUP_PARAMS(8, offset);
          vd = vs2;
        } break;
        case E16: {
          VI_XI_SLIDEUP_PARAMS(16, offset);
          vd = vs2;
        } break;
        case E32: {
          VI_XI_SLIDEUP_PARAMS(32, offset);
          vd = vs2;
        } break;
        default: {
          VI_XI_SLIDEUP_PARAMS(64, offset);
          vd = vs2;
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VADC_VX:
      if (instr_.RvvVM()) {
        RVV_VI_XI_LOOP_WITH_CARRY({
          auto& v0 = Rvvelt<uint64_t>(0, midx);
          vd = rs1 + vs2 + (v0 >> mpos) & 0x1;
          USE(simm5);
        })
      } else {
        UNREACHABLE();
      }
      break;
    case RO_V_VSLL_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 << (rs1 & (rvv_sew() - 1)); })
      break;
    }
    case RO_V_VSRL_VX: {
      RVV_VI_VX_ULOOP({ vd = (vs2 >> (rs1 & (rvv_sew() - 1))); })
      break;
    }
    case RO_V_VSRA_VX: {
      RVV_VI_VX_LOOP({ vd = ((vs2) >> (rs1 & (rvv_sew() - 1))); })
      break;
    }
    default:
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvMVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_MVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VMUNARY0: {
      if (instr_.Vs1Value() == VID_V) {
        CHECK(rvv_vsew() >= E8 && rvv_vsew() <= E64);
        uint8_t rd_num = rvv_vd_reg();
        require_align(rd_num, rvv_vflmul());
        require_vm;
        for (uint8_t i = rvv_vstart(); i < rvv_vl(); ++i) {
          RVV_VI_LOOP_MASK_SKIP();
          switch (rvv_vsew()) {
            case E8:
              Rvvelt<uint8_t>(rd_num, i, true) = i;
              break;
            case E16:
              Rvvelt<uint16_t>(rd_num, i, true) = i;
              break;
            case E32:
              Rvvelt<uint32_t>(rd_num, i, true) = i;
              break;
            default:
              Rvvelt<uint64_t>(rd_num, i, true) = i;
              break;
          }
        }
        set_rvv_vstart(0);
      } else {
        UNIMPLEMENTED_RISCV();
      }
      break;
    }
    case RO_V_VMUL_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 * vs1; })
      break;
    }
    case RO_V_VWMUL_VV: {
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, *, +, int);
        USE(vd);
      })
      break;
    }
    case RO_V_VWMULU_VV: {
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, *, +, uint);
        USE(vd);
      })
      break;
    }
    case RO_V_VMULHU_VV: {
      RVV_VI_VV_LOOP({ vd = ((__uint128_t)vs2 * vs1) >> rvv_sew(); })
      break;
    }
    case RO_V_VMULH_VV: {
      RVV_VI_VV_LOOP({ vd = ((__int128_t)vs2 * vs1) >> rvv_sew(); })
      break;
    }
    case RO_V_VDIV_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 / vs1; })
      break;
    }
    case RO_V_VDIVU_VV: {
      RVV_VI_VV_LOOP({ vd = vs2 / vs1; })
      break;
    }
    case RO_V_VWXUNARY0: {
      if (rvv_vs1_reg() == 0) {
        // vmv.x.s
        switch (rvv_vsew()) {
          case E8:
            set_rd(Rvvelt<type_sew_t<8>::type>(rvv_vs2_reg(), 0));
            break;
          case E16:
            set_rd(Rvvelt<type_sew_t<16>::type>(rvv_vs2_reg(), 0));
            break;
          case E32:
            set_rd(Rvvelt<type_sew_t<32>::type>(rvv_vs2_reg(), 0));
            break;
          case E64:
            set_rd(Rvvelt<type_sew_t<64>::type>(rvv_vs2_reg(), 0));
            break;
          default:
            UNREACHABLE();
        }
        set_rvv_vstart(0);
        rvv_trace_vd();
      } else if (rvv_vs1_reg() == 0b10000) {
        // vpopc
        reg_t cnt = 0;
        RVV_VI_GENERAL_LOOP_BASE
        RVV_VI_LOOP_MASK_SKIP()
        const uint8_t idx = i / 64;
        const uint8_t pos = i % 64;
        bool mask = (Rvvelt<uint64_t>(rvv_vs2_reg(), idx) >> pos) & 0x1;
        if (mask) cnt++;
        RVV_VI_LOOP_END
        set_register(rd_reg(), cnt);
        rvv_trace_vd();
      } else if (rvv_vs1_reg() == 0b10001) {
        // vfirst
        sreg_t index = -1;
        RVV_VI_GENERAL_LOOP_BASE
        RVV_VI_LOOP_MASK_SKIP()
        const uint8_t idx = i / 64;
        const uint8_t pos = i % 64;
        bool mask = (Rvvelt<uint64_t>(rvv_vs2_reg(), idx) >> pos) & 0x1;
        if (mask) {
          index = i;
          break;
        }
        RVV_VI_LOOP_END
        set_register(rd_reg(), index);
        rvv_trace_vd();
      } else {
        v8::base::EmbeddedVector<char, 256> buffer;
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
        PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
               reinterpret_cast<intptr_t>(&instr_), buffer.begin());
        UNIMPLEMENTED_RISCV();
      }
    } break;
    case RO_V_VREDMAXU:
      RVV_VI_VV_ULOOP_REDUCTION(
          { vd_0_res = (vd_0_res >= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMAX:
      RVV_VI_VV_LOOP_REDUCTION(
          { vd_0_res = (vd_0_res >= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMINU:
      RVV_VI_VV_ULOOP_REDUCTION(
          { vd_0_res = (vd_0_res <= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VREDMIN:
      RVV_VI_VV_LOOP_REDUCTION(
          { vd_0_res = (vd_0_res <= vs2) ? vd_0_res : vs2; })
      break;
    case RO_V_VXUNARY0:
      if (rvv_vs1_reg() == 0b00010) {
        RVV_VI_VIE_8_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00011) {
        RVV_VI_VIE_8_LOOP(true);
      } else if (rvv_vs1_reg() == 0b00100) {
        RVV_VI_VIE_4_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00101) {
        RVV_VI_VIE_4_LOOP(true);
      } else if (rvv_vs1_reg() == 0b00110) {
        RVV_VI_VIE_2_LOOP(false);
      } else if (rvv_vs1_reg() == 0b00111) {
        RVV_VI_VIE_2_LOOP(true);
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VWADDU_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, +, +, uint);
        USE(vd);
      })
      break;
    case RO_V_VWADD_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VV_LOOP_WIDEN({
        VI_WIDE_OP_AND_ASSIGN(vs2, vs1, 0, +, +, int);
        USE(vd);
      })
      break;
    case RO_V_VCOMPRESS_VV: {
      CHECK_EQ(rvv_vstart(), 0);
      require_align(rvv_vd_reg(), rvv_vflmul());
      require_align(rvv_vs2_reg(), rvv_vflmul());
      require(rvv_vd_reg() != rvv_vs2_reg());
      require_noover(rvv_vd_reg(), rvv_vflmul(), rvv_vs1_reg(), 1);

      reg_t pos = 0;

      RVV_VI_GENERAL_LOOP_BASE
      const uint64_t midx = i / 64;
      const uint64_t mpos = i % 64;

      bool do_mask = (Rvvelt<uint64_t>(rvv_vs1_reg(), midx) >> mpos) & 0x1;
      if (do_mask) {
        switch (rvv_vsew()) {
          case E8:
            Rvvelt<uint8_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint8_t>(rvv_vs2_reg(), i);
            break;
          case E16:
            Rvvelt<uint16_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint16_t>(rvv_vs2_reg(), i);
            break;
          case E32:
            Rvvelt<uint32_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint32_t>(rvv_vs2_reg(), i);
            break;
          default:
            Rvvelt<uint64_t>(rvv_vd_reg(), pos, true) =
                Rvvelt<uint64_t>(rvv_vs2_reg(), i);
            break;
        }

        ++pos;
      }
      RVV_VI_LOOP_END;
      rvv_trace_vd();
    } break;
    default:
      v8::base::EmbeddedVector<char, 256> buffer;
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
      PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
             reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvMVX() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_MVX);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VRXUNARY0:
      // vmv.s.x
      if (instr_.Vs2Value() == 0x0) {
        if (rvv_vl() > 0 && rvv_vstart() < rvv_vl()) {
          switch (rvv_vsew()) {
            case E8:
              Rvvelt<uint8_t>(rvv_vd_reg(), 0, true) =
                  (uint8_t)get_register(rs1_reg());
              break;
            case E16:
              Rvvelt<uint16_t>(rvv_vd_reg(), 0, true) =
                  (uint16_t)get_register(rs1_reg());
              break;
            case E32:
              Rvvelt<uint32_t>(rvv_vd_reg(), 0, true) =
                  (uint32_t)get_register(rs1_reg());
              break;
            case E64:
              Rvvelt<uint64_t>(rvv_vd_reg(), 0, true) =
                  (uint64_t)get_register(rs1_reg());
              break;
            default:
              UNREACHABLE();
          }
        }
        set_rvv_vstart(0);
        rvv_trace_vd();
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VDIV_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 / rs1; })
      break;
    }
    case RO_V_VDIVU_VX: {
      RVV_VI_VX_ULOOP({ vd = vs2 / rs1; })
      break;
    }
    case RO_V_VMUL_VX: {
      RVV_VI_VX_LOOP({ vd = vs2 * rs1; })
      break;
    }
    case RO_V_VWADDUW_VX: {
      RVV_VI_CHECK_DDS(false);
      RVV_VI_VX_LOOP_WIDEN({
        VI_WIDE_WVX_OP(rs1, +, uint);
        USE(vd);
        USE(vs2);
      })
      break;
    }
    case RO_V_VSLIDE1DOWN_VX: {
      RVV_VI_CHECK_SLIDE(false);
      RVV_VI_GENERAL_LOOP_BASE
      switch (rvv_vsew()) {
        case E8: {
          VX_SLIDE1DOWN_PARAMS(8, 1);
        } break;
        case E16: {
          VX_SLIDE1DOWN_PARAMS(16, 1);
        } break;
        case E32: {
          VX_SLIDE1DOWN_PARAMS(32, 1);
        } break;
        default: {
          VX_SLIDE1DOWN_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VSLIDE1UP_VX: {
      RVV_VI_CHECK_SLIDE(true);
      RVV_VI_GENERAL_LOOP_BASE
      if (i < rvv_vstart()) continue;
      switch (rvv_vsew()) {
        case E8: {
          VX_SLIDE1UP_PARAMS(8, 1);
        } break;
        case E16: {
          VX_SLIDE1UP_PARAMS(16, 1);
        } break;
        case E32: {
          VX_SLIDE1UP_PARAMS(32, 1);
        } break;
        default: {
          VX_SLIDE1UP_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    default:
      v8::base::EmbeddedVector<char, 256> buffer;
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_));
      PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
             reinterpret_cast<intptr_t>(&instr_), buffer.begin());
      UNIMPLEMENTED_RISCV();
      break;
  }
}

void Simulator::DecodeRvvFVV() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_FVV);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VFDIV_VV: {
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](float vs1, float vs2) {
              if (is_invalid_fdiv(vs1, vs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<float>::quiet_NaN();
              } else if (vs1 == 0.0f) {
                this->set_fflags(kDivideByZero);
                return (std::signbit(vs1) == std::signbit(vs2)
                            ? std::numeric_limits<float>::infinity()
                            : -std::numeric_limits<float>::infinity());
              } else {
                return vs2 / vs1;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
            }
            vd = alu_out;
          },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double vs1, double vs2) {
              if (is_invalid_fdiv(vs1, vs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else if (vs1 == 0.0f) {
                this->set_fflags(kDivideByZero);
                return (std::signbit(vs1) == std::signbit(vs2)
                            ? std::numeric_limits<double>::infinity()
                            : -std::numeric_limits<double>::infinity());
              } else {
                return vs2 / vs1;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<double>::quiet_NaN();
            }
            vd = alu_out;
          })
      break;
    }
    case RO_V_VFMUL_VV: {
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double drs1, double drs2) {
              if (is_invalid_fmul(drs1, drs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return drs1 * drs2;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
            }
            vd = alu_out;
          },
          {
            // TODO(riscv): use rm value (round mode)
            auto fn = [this](double drs1, double drs2) {
              if (is_invalid_fmul(drs1, drs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return drs1 * drs2;
              }
            };
            auto alu_out = fn(vs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(vs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<double>::quiet_NaN();
            }
            vd = alu_out;
          })
      break;
    }
    case RO_V_VFUNARY0:
      switch (instr_.Vs1Value()) {
        case VFCVT_X_F_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                Rvvelt<int32_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<int32_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              },
              {
                Rvvelt<int64_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<int64_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              })
          break;
        case VFCVT_XU_F_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                Rvvelt<uint32_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<uint32_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              },
              {
                Rvvelt<uint64_t>(rvv_vd_reg(), i) =
                    RoundF2IHelper<uint64_t>(vs2, read_csr_value(csr_frm));
                USE(vd);
                USE(fs1);
              })
          break;
        case VFCVT_F_XU_V:
          RVV_VI_VFP_VF_LOOP({ UNIMPLEMENTED(); },
                             {
                               auto vs2_i = Rvvelt<uint32_t>(rvv_vs2_reg(), i);
                               vd = static_cast<float>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             },
                             {
                               auto vs2_i = Rvvelt<uint64_t>(rvv_vs2_reg(), i);
                               vd = static_cast<double>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             })
          break;
        case VFCVT_F_X_V:
          RVV_VI_VFP_VF_LOOP({ UNIMPLEMENTED(); },
                             {
                               auto vs2_i = Rvvelt<int32_t>(rvv_vs2_reg(), i);
                               vd = static_cast<float>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             },
                             {
                               auto vs2_i = Rvvelt<int64_t>(rvv_vs2_reg(), i);
                               vd = static_cast<double>(vs2_i);
                               USE(vs2);
                               USE(fs1);
                             })
          break;
        case VFNCVT_F_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                Rvvelt<float>(rvv_vd_reg(), i, true) =
                    CanonicalizeDoubleToFloatOperation(
                        [](double drs) { return static_cast<float>(drs); },
                        vs2);
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() >= E16))
          break;
        case VFNCVT_X_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                int32_t& vd = Rvvelt<int32_t>(rvv_vd_reg(), i, true);
                vd = RoundF2IHelper<int32_t>(vs2, read_csr_value(csr_frm));
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() <= E32))
          break;
        case VFNCVT_XU_F_W:
          RVV_VI_VFP_CVT_SCALE(
              { UNREACHABLE(); }, { UNREACHABLE(); },
              {
                auto vs2 = Rvvelt<double>(rvv_vs2_reg(), i);
                uint32_t& vd = Rvvelt<uint32_t>(rvv_vd_reg(), i, true);
                vd = RoundF2IHelper<uint32_t>(vs2, read_csr_value(csr_frm));
              },
              { ; }, { ; }, { ; }, false, (rvv_vsew() <= E32))
          break;
        case VFWCVT_F_X_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<int16_t>(rvv_vs2_reg(), i);
                                 Rvvelt<float32_t>(rvv_vd_reg(), i, true) =
                                     static_cast<float>(vs2);
                               },
                               {
                                 auto vs2 = Rvvelt<int32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E8))
          break;
        case VFWCVT_F_XU_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<uint16_t>(rvv_vs2_reg(), i);
                                 Rvvelt<float32_t>(rvv_vd_reg(), i, true) =
                                     static_cast<float>(vs2);
                               },
                               {
                                 auto vs2 = Rvvelt<uint32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E8))
          break;
        case VFWCVT_XU_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<uint64_t>(rvv_vd_reg(), i, true) =
                                     static_cast<uint64_t>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        case VFWCVT_X_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<int64_t>(rvv_vd_reg(), i, true) =
                                     static_cast<int64_t>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        case VFWCVT_F_F_V:
          RVV_VI_VFP_CVT_SCALE({ UNREACHABLE(); }, { UNREACHABLE(); },
                               {
                                 auto vs2 = Rvvelt<float32_t>(rvv_vs2_reg(), i);
                                 Rvvelt<double>(rvv_vd_reg(), i, true) =
                                     static_cast<double>(vs2);
                               },
                               { ; }, { ; }, { ; }, true, (rvv_vsew() >= E16))
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case RO_V_VFUNARY1:
      switch (instr_.Vs1Value()) {
        case VFCLASS_V:
          RVV_VI_VFP_VF_LOOP(
              { UNIMPLEMENTED(); },
              {
                int32_t& vd_i = Rvvelt<int32_t>(rvv_vd_reg(), i, true);
                vd_i = int32_t(FclassHelper(vs2));
                USE(fs1);
                USE(vd);
              },
              {
                int64_t& vd_i = Rvvelt<int64_t>(rvv_vd_reg(), i, true);
                vd_i = FclassHelper(vs2);
                USE(fs1);
```