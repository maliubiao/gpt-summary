Response: Let's break down the thought process for summarizing this code snippet.

1. **Understand the Goal:** The request asks for a summary of a specific C++ file within the V8 JavaScript engine, focusing on its functionality and relationship to JavaScript. Crucially, it's labeled as "part 5 of 5," meaning this is likely the final piece dealing with instruction execution.

2. **Identify the Core Functionality:**  Scanning the code, a few key patterns emerge:
    * **`Simulator::DecodeRvv...` functions:** These clearly handle the decoding and execution of RISC-V Vector (RVV) instructions. The names suggest different categories of RVV instructions (integer-vector, floating-point vector, mask vector).
    * **`Simulator::DecodeVType()`:** This function acts as a dispatcher, calling the more specific `DecodeRvv...` functions based on the instruction's type.
    * **`Simulator::InstructionDecode()`:** This is the main entry point for instruction processing. It handles different instruction types (R-type, I-type, etc.) and, notably, calls `DecodeVType()` for RVV instructions.
    * **Loop Structures (`RVV_VI_..._LOOP` macros):**  These indicate the core logic of vector processing, iterating through vector elements.
    * **Floating-point operations (`std::sqrt`, `base::RecipSqrt`, `CompareFHelper`, `FMaxMinHelper`, `fsgnj32`, `fsgnj64`, arithmetic operations):**  A significant portion deals with floating-point calculations, including handling NaN and setting flags.
    * **FMA (Fused Multiply-Add) operations:** These are explicitly handled.
    * **Type conversions and widening operations:** Instructions like `VFWADD` suggest operations involving different data widths.
    * **Scalar-vector interactions:** Instructions like `VFMV_FS` and `VFMV_VF` handle moving data between scalar and vector registers.
    * **Slide operations:** `VFSLIDE1DOWN_VF` and `VFSLIDE1UP_VF` suggest shifting elements within vectors.
    * **The presence of `UNIMPLEMENTED()` and `UNSUPPORTED_RISCV()`:** This tells us the code is likely a work in progress or supports a subset of the RVV instruction set.
    * **Interaction with `set_fflags()`:**  This indicates the simulator models floating-point status flags.
    * **Interaction with `get_fpu_register...` and `set_fpu_register...`:**  This shows the simulation of floating-point registers.

3. **Infer the Overall Purpose:** Based on the identified functionalities, it's clear that this part of the simulator is responsible for *interpreting and executing RISC-V Vector instructions*. It's tightly coupled with floating-point operations, suggesting a focus on accelerating numerical computations within JavaScript.

4. **Establish the Link to JavaScript:** The code is part of the V8 engine, which executes JavaScript. The presence of floating-point operations and vector instructions strongly suggests that this code is used to optimize JavaScript code that performs numerical computations. Specifically, when JavaScript uses typed arrays or performs operations that can be vectorized, the V8 engine might translate those operations into RVV instructions, which this simulator then executes.

5. **Construct a JavaScript Example:**  To illustrate the connection, we need a JavaScript example that would benefit from vectorization. Operations on `Float32Array` or `Float64Array` are prime candidates. A simple example like adding two arrays element-wise clearly demonstrates how vector instructions could be used for optimization. The example should be concise and easy to understand.

6. **Refine the Summary:**  Organize the identified functionalities into logical categories. Emphasize the key aspects, such as RVV instruction decoding, floating-point support, and the connection to JavaScript's numerical capabilities. Clearly state that this part of the simulator handles the *execution* of these instructions.

7. **Address the "Part 5 of 5" Aspect:** This confirms that this snippet is the culmination of the simulation process, specifically focusing on the execution stage. It implies that previous parts likely handled instruction fetching, decoding of non-vector instructions, and other setup tasks.

8. **Self-Correction/Refinement:**  Initially, I might have focused too much on individual instruction names. However, realizing the "part 5 of 5" context and the broader goal of summarization, I shifted the focus to the overall purpose and the interaction with JavaScript. The inclusion of `UNIMPLEMENTED` is a crucial detail to include, as it provides a more accurate picture of the simulator's capabilities. Also, initially I might not have emphasized the *execution* aspect strongly enough, and later refined it to make it clearer.
这是 `v8/src/execution/riscv/simulator-riscv.cc` 文件的第五部分，也是最后一部分。结合前几部分的内容，我们可以归纳出这部分代码的主要功能是：

**核心功能：RISC-V 向量扩展 (RVV) 指令的解码和模拟执行。**

具体来说，这部分代码：

* **实现了对多种 RVV 指令的解码和执行逻辑。**  可以看到大量的 `case` 语句，针对不同的 RVV 指令操作码（例如 `VFSQRT_V`, `VFMADD_VV`, `VFMV_VF` 等）进行处理。
* **专注于浮点向量运算。**  代码中大量出现了与浮点数操作相关的函数和宏，如 `std::sqrt`, `base::RecipSqrt`, `CompareFHelper`, `FMaxMinHelper`, `fsgnj32`, `fsgnj64` 以及处理 NaN 和浮点标志位的逻辑 (`set_fflags`).
* **处理不同向量长度和元素宽度 (SEW)。**  代码中会根据 `rvv_vsew()` 的值 (例如 `E32`, `E64`) 来执行不同的操作，这对应于 RISC-V 向量扩展中可变的向量长度和元素宽度。
* **支持融合乘加 (FMA) 操作。**  例如 `RO_V_VFMADD_VV`, `RO_V_VFNMADD_VV` 等指令的处理。
* **处理向量与标量之间的移动。**  例如 `RO_V_VFMV_FS` 和 `RO_V_VFMV_VF` 指令。
* **实现向量的滑动操作。**  例如 `RO_V_VFSLIDE1DOWN_VF` 和 `RO_V_VFSLIDE1UP_VF` 指令。
* **包含了处理向量规约操作的代码。**  例如 `RO_V_VFREDMAX_VV` 和 `RO_V_VFWREDUSUM_VS`。
* **实现了向量比较操作。** 例如 `RO_V_VMFEQ_VV`, `RO_V_VMFLT_VV` 等。
* **涉及到对向量掩码 (VM) 的处理。**  例如在 `RO_V_VFMV_VF` 的处理中，会根据 `instr_.RvvVM()` 的值来决定是否使用掩码。
* **处理向量类型配置指令 (`VSETVLI`, `VSETVL`)。**  这些指令用于设置向量长度和元素宽度。
* **使用了大量的宏 (`RVV_VI_..._LOOP`) 来简化向量操作的循环展开和处理。** 这些宏封装了针对不同数据宽度和操作类型的通用循环结构。
* **对于尚未实现的指令，通常会标记为 `UNIMPLEMENTED()` 或 `UNSUPPORTED_RISCV()`。**

**与 JavaScript 功能的关系：**

这部分代码是 V8 引擎中用于模拟 RISC-V 架构上向量指令执行的关键部分。JavaScript 本身并没有直接的向量操作语法。然而，V8 引擎会尝试将 JavaScript 中的一些操作（特别是涉及到数组和数值计算的部分）优化成底层的向量指令，以提高执行效率。

**JavaScript 例子：**

假设我们在 JavaScript 中执行以下代码：

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = Math.sqrt(a[i]) + b[i];
}

console.log(c); // 输出类似 Float32Array [ 6, 7.4142135, 8.7320508, 10 ]
```

在这个例子中，我们对 `Float32Array` 中的元素进行了逐个操作，包括求平方根和加法。当 V8 引擎在支持 RISC-V 向量扩展的架构上执行这段代码时，它可能会将循环中的操作映射到相应的 RVV 指令，例如：

1. **`VFSQRT_V`**:  用于计算 `a` 数组元素的平方根。
2. **`VFADD_VV`**: 用于将平方根的结果与 `b` 数组的元素相加。

`simulator-riscv.cc` 中的这部分代码，特别是像 `case VFSQRT_V:` 和 `case RO_V_VFADD_VV:` 对应的代码，就是负责模拟这些 RVV 指令的执行过程。它会读取模拟的向量寄存器中的数据，执行相应的浮点运算，并将结果写回模拟的向量寄存器。

**总结这部分的功能：**

作为 `v8/src/execution/riscv/simulator-riscv.cc` 的最后一部分，这段代码完成了 RISC-V 向量扩展指令的模拟执行功能。它是 V8 引擎在 RISC-V 平台上支持高性能数值计算的关键组成部分，通过模拟执行 RVV 指令，使得 V8 能够优化 JavaScript 中涉及数组和数值计算的代码。这部分代码主要关注浮点向量运算，并处理了各种不同的 RVV 指令及其操作数类型和行为。

### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```
USE(vd);
              })
          break;
        case VFSQRT_V:
          RVV_VI_VFP_VF_LOOP({ UNIMPLEMENTED(); },
                             {
                               vd = std::sqrt(vs2);
                               USE(fs1);
                             },
                             {
                               vd = std::sqrt(vs2);
                               USE(fs1);
                             })
          break;
        case VFRSQRT7_V:
          RVV_VI_VFP_VF_LOOP(
              {},
              {
                vd = base::RecipSqrt(vs2);
                USE(fs1);
              },
              {
                vd = base::RecipSqrt(vs2);
                USE(fs1);
              })
          break;
        case VFREC7_V:
          RVV_VI_VFP_VF_LOOP(
              {},
              {
                vd = base::Recip(vs2);
                USE(fs1);
              },
              {
                vd = base::Recip(vs2);
                USE(fs1);
              })
          break;
        default:
          break;
      }
      break;
    case RO_V_VMFEQ_VV: {
      RVV_VI_VFP_LOOP_CMP({ UNIMPLEMENTED(); },
                          { res = CompareFHelper(vs2, vs1, EQ); },
                          { res = CompareFHelper(vs2, vs1, EQ); }, true)
    } break;
    case RO_V_VMFNE_VV: {
      RVV_VI_VFP_LOOP_CMP({ UNIMPLEMENTED(); },
                          { res = CompareFHelper(vs2, vs1, NE); },
                          { res = CompareFHelper(vs2, vs1, NE); }, true)
    } break;
    case RO_V_VMFLT_VV: {
      RVV_VI_VFP_LOOP_CMP({ UNIMPLEMENTED(); },
                          { res = CompareFHelper(vs2, vs1, LT); },
                          { res = CompareFHelper(vs2, vs1, LT); }, true)
    } break;
    case RO_V_VMFLE_VV: {
      RVV_VI_VFP_LOOP_CMP({ UNIMPLEMENTED(); },
                          { res = CompareFHelper(vs2, vs1, LE); },
                          { res = CompareFHelper(vs2, vs1, LE); }, true)
    } break;
    case RO_V_VFMAX_VV: {
      RVV_VI_VFP_VV_LOOP({ UNIMPLEMENTED(); },
                         { vd = FMaxMinHelper(vs2, vs1, MaxMinKind::kMax); },
                         { vd = FMaxMinHelper(vs2, vs1, MaxMinKind::kMax); })
      break;
    }
    case RO_V_VFREDMAX_VV: {
      RVV_VI_VFP_VV_LOOP_REDUCTION(
          { UNIMPLEMENTED(); },
          { vd_0 = FMaxMinHelper(vd_0, vs2, MaxMinKind::kMax); },
          { vd_0 = FMaxMinHelper(vd_0, vs2, MaxMinKind::kMax); })
      break;
    }
    case RO_V_VFMIN_VV: {
      RVV_VI_VFP_VV_LOOP({ UNIMPLEMENTED(); },
                         { vd = FMaxMinHelper(vs2, vs1, MaxMinKind::kMin); },
                         { vd = FMaxMinHelper(vs2, vs1, MaxMinKind::kMin); })
      break;
    }
    case RO_V_VFSGNJ_VV:
      RVV_VFSGNJ_VV_VF_LOOP({ UNIMPLEMENTED(); },
                            {
                              vd = fsgnj32(Float32::FromBits(vs2),
                                           Float32::FromBits(vs1), false, false)
                                       .get_bits();
                              USE(fs1);
                            },
                            {
                              vd = fsgnj64(Float64::FromBits(vs2),
                                           Float64::FromBits(vs1), false, false)
                                       .get_bits();
                              USE(fs1);
                            })
      break;
    case RO_V_VFSGNJN_VV:
      RVV_VFSGNJ_VV_VF_LOOP({ UNIMPLEMENTED(); },
                            {
                              vd = fsgnj32(Float32::FromBits(vs2),
                                           Float32::FromBits(vs1), true, false)
                                       .get_bits();
                              USE(fs1);
                            },
                            {
                              vd = fsgnj64(Float64::FromBits(vs2),
                                           Float64::FromBits(vs1), true, false)
                                       .get_bits();
                              USE(fs1);
                            })
      break;
    case RO_V_VFSGNJX_VV:
      RVV_VFSGNJ_VV_VF_LOOP({ UNIMPLEMENTED(); },
                            {
                              vd = fsgnj32(Float32::FromBits(vs2),
                                           Float32::FromBits(vs1), false, true)
                                       .get_bits();
                              USE(fs1);
                            },
                            {
                              vd = fsgnj64(Float64::FromBits(vs2),
                                           Float64::FromBits(vs1), false, true)
                                       .get_bits();
                              USE(fs1);
                            })
      break;
    case RO_V_VFADD_VV:
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            auto fn = [this](float frs1, float frs2) {
              if (is_invalid_fadd(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<float>::quiet_NaN();
              } else {
                return frs1 + frs2;
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
            auto fn = [this](double frs1, double frs2) {
              if (is_invalid_fadd(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return frs1 + frs2;
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
    case RO_V_VFSUB_VV:
      RVV_VI_VFP_VV_LOOP(
          { UNIMPLEMENTED(); },
          {
            auto fn = [this](float frs1, float frs2) {
              if (is_invalid_fsub(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<float>::quiet_NaN();
              } else {
                return frs2 - frs1;
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
            auto fn = [this](double frs1, double frs2) {
              if (is_invalid_fsub(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return frs2 - frs1;
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
    case RO_V_VFWADD_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN(
          {
            RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(double, is_invalid_fadd, +);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFWSUB_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN(
          {
            RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(double, is_invalid_fsub, -);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFWADD_W_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN(
          {
            RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(double, is_invalid_fadd, +);
            USE(vs3);
          },
          true)
      break;
    case RO_V_VFWSUB_W_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN(
          {
            RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(double, is_invalid_fsub, -);
            USE(vs3);
          },
          true)
      break;
    case RO_V_VFWMUL_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN(
          {
            RVV_VI_VFP_VV_ARITH_CHECK_COMPUTE(double, is_invalid_fmul, *);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFWREDUSUM_VS:
    case RO_V_VFWREDOSUM_VS:
      RVV_VI_CHECK_DSS(true);
      switch (rvv_vsew()) {
        case E16:
        case E64: {
          UNIMPLEMENTED();
        }
        case E32: {
          double& vd = Rvvelt<double>(rvv_vd_reg(), 0, true);
          double vs1 = Rvvelt<double>(rvv_vs1_reg(), 0);
          double alu_out = vs1;
          for (uint64_t i = rvv_vstart(); i < rvv_vl(); ++i) {
            double vs2 = static_cast<double>(Rvvelt<float>(rvv_vs2_reg(), i));
            if (is_invalid_fadd(alu_out, vs2)) {
              set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
              break;
            }
            alu_out = alu_out + vs2;
            if (std::isnan(alu_out) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(vs2)) set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
              break;
            }
          }
          vd = alu_out;
          break;
        }
        default:
          require(false);
          break;
      }
      rvv_trace_vd();
      break;
    case RO_V_VFMADD_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, vd, vs1, vs2)},
                             {RVV_VI_VFP_FMA(double, vd, vs1, vs2)})
      break;
    case RO_V_VFNMADD_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, -vd, vs1, -vs2)},
                             {RVV_VI_VFP_FMA(double, -vd, vs1, -vs2)})
      break;
    case RO_V_VFMSUB_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, vd, vs1, -vs2)},
                             {RVV_VI_VFP_FMA(double, vd, vs1, -vs2)})
      break;
    case RO_V_VFNMSUB_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, -vd, vs1, +vs2)},
                             {RVV_VI_VFP_FMA(double, -vd, vs1, +vs2)})
      break;
    case RO_V_VFMACC_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, vs2, vs1, vd)},
                             {RVV_VI_VFP_FMA(double, vs2, vs1, vd)})
      break;
    case RO_V_VFNMACC_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, -vs2, vs1, -vd)},
                             {RVV_VI_VFP_FMA(double, -vs2, vs1, -vd)})
      break;
    case RO_V_VFMSAC_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, vs2, vs1, -vd)},
                             {RVV_VI_VFP_FMA(double, vs2, vs1, -vd)})
      break;
    case RO_V_VFNMSAC_VV:
      RVV_VI_VFP_FMA_VV_LOOP({RVV_VI_VFP_FMA(float, -vs2, vs1, +vd)},
                             {RVV_VI_VFP_FMA(double, -vs2, vs1, +vd)})
      break;
    case RO_V_VFWMACC_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN({RVV_VI_VFP_FMA(double, vs2, vs1, vs3)}, false)
      break;
    case RO_V_VFWNMACC_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN({RVV_VI_VFP_FMA(double, -vs2, vs1, -vs3)}, false)
      break;
    case RO_V_VFWMSAC_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN({RVV_VI_VFP_FMA(double, vs2, vs1, -vs3)}, false)
      break;
    case RO_V_VFWNMSAC_VV:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VV_LOOP_WIDEN({RVV_VI_VFP_FMA(double, -vs2, vs1, +vs3)}, false)
      break;
    case RO_V_VFMV_FS:
      switch (rvv_vsew()) {
        case E16: {
          UNIMPLEMENTED();
        }
        case E32: {
          uint32_t fs2 = Rvvelt<uint32_t>(rvv_vs2_reg(), 0);
          set_frd(Float32::FromBits(fs2));
          break;
        }
        case E64: {
          uint64_t fs2 = Rvvelt<uint64_t>(rvv_vs2_reg(), 0);
          set_drd(Float64::FromBits(fs2));
          break;
        }
        default:
          require(0);
          break;
      }
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Simulator::DecodeRvvFVF() {
  DCHECK_EQ(instr_.InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_FVF);
  switch (instr_.InstructionBits() & kVTypeMask) {
    case RO_V_VFSGNJ_VF:
      RVV_VFSGNJ_VV_VF_LOOP(
          {},
          {
            vd = fsgnj32(Float32::FromBits(vs2), fs1, false, false).get_bits();
            USE(vs1);
          },
          {
            vd = fsgnj64(Float64::FromBits(vs2), fs1, false, false).get_bits();
            USE(vs1);
          })
      break;
    case RO_V_VFSGNJN_VF:
      RVV_VFSGNJ_VV_VF_LOOP(
          {},
          {
            vd = fsgnj32(Float32::FromBits(vs2), fs1, true, false).get_bits();
            USE(vs1);
          },
          {
            vd = fsgnj64(Float64::FromBits(vs2), fs1, true, false).get_bits();
            USE(vs1);
          })
      break;
    case RO_V_VFSGNJX_VF:
      RVV_VFSGNJ_VV_VF_LOOP(
          {},
          {
            vd = fsgnj32(Float32::FromBits(vs2), fs1, false, true).get_bits();
            USE(vs1);
          },
          {
            vd = fsgnj64(Float64::FromBits(vs2), fs1, false, true).get_bits();
            USE(vs1);
          })
      break;
    case RO_V_VFMV_VF:
      if (instr_.RvvVM()) {
        RVV_VI_VF_MERGE_LOOP(
            {},
            {
              vd = fs1;
              USE(vs2);
            },
            {
              vd = fs1;
              USE(vs2);
            });
      } else {
        RVV_VI_VF_MERGE_LOOP(
            {},
            {
              bool use_first =
                  (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
              vd = use_first ? fs1 : vs2;
            },
            {
              bool use_first =
                  (Rvvelt<uint64_t>(0, (i / 64)) >> (i % 64)) & 0x1;
              vd = use_first ? fs1 : vs2;
            });
      }
      break;
    case RO_V_VFADD_VF:
      RVV_VI_VFP_VF_LOOP(
          { UNIMPLEMENTED(); },
          {
            auto fn = [this](float frs1, float frs2) {
              if (is_invalid_fadd(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<float>::quiet_NaN();
              } else {
                return frs1 + frs2;
              }
            };
            auto alu_out = fn(fs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(fs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(fs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<float>::quiet_NaN();
            }
            vd = alu_out;
          },
          {
            auto fn = [this](double frs1, double frs2) {
              if (is_invalid_fadd(frs1, frs2)) {
                this->set_fflags(kInvalidOperation);
                return std::numeric_limits<double>::quiet_NaN();
              } else {
                return frs1 + frs2;
              }
            };
            auto alu_out = fn(fs1, vs2);
            // if any input or result is NaN, the result is quiet_NaN
            if (std::isnan(alu_out) || std::isnan(fs1) || std::isnan(vs2)) {
              // signaling_nan sets kInvalidOperation bit
              if (isSnan(alu_out) || isSnan(fs1) || isSnan(vs2))
                set_fflags(kInvalidOperation);
              alu_out = std::numeric_limits<double>::quiet_NaN();
            }
            vd = alu_out;
          })
      break;
    case RO_V_VFWADD_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN(
          {
            RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(double, is_invalid_fadd, +);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFWSUB_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN(
          {
            RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(double, is_invalid_fsub, -);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFWADD_W_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN(
          {
            RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(double, is_invalid_fadd, +);
            USE(vs3);
          },
          true)
      break;
    case RO_V_VFWSUB_W_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN(
          {
            RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(double, is_invalid_fsub, -);
            USE(vs3);
          },
          true)
      break;
    case RO_V_VFWMUL_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN(
          {
            RVV_VI_VFP_VF_ARITH_CHECK_COMPUTE(double, is_invalid_fmul, *);
            USE(vs3);
          },
          false)
      break;
    case RO_V_VFMADD_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, vd, fs1, vs2)},
                             {RVV_VI_VFP_FMA(double, vd, fs1, vs2)})
      break;
    case RO_V_VFNMADD_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, -vd, fs1, -vs2)},
                             {RVV_VI_VFP_FMA(double, -vd, fs1, -vs2)})
      break;
    case RO_V_VFMSUB_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, vd, fs1, -vs2)},
                             {RVV_VI_VFP_FMA(double, vd, fs1, -vs2)})
      break;
    case RO_V_VFNMSUB_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, -vd, fs1, vs2)},
                             {RVV_VI_VFP_FMA(double, -vd, fs1, vs2)})
      break;
    case RO_V_VFMACC_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, vs2, fs1, vd)},
                             {RVV_VI_VFP_FMA(double, vs2, fs1, vd)})
      break;
    case RO_V_VFNMACC_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, -vs2, fs1, -vd)},
                             {RVV_VI_VFP_FMA(double, -vs2, fs1, -vd)})
      break;
    case RO_V_VFMSAC_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, vs2, fs1, -vd)},
                             {RVV_VI_VFP_FMA(double, vs2, fs1, -vd)})
      break;
    case RO_V_VFNMSAC_VF:
      RVV_VI_VFP_FMA_VF_LOOP({RVV_VI_VFP_FMA(float, -vs2, fs1, vd)},
                             {RVV_VI_VFP_FMA(double, -vs2, fs1, vd)})
      break;
    case RO_V_VFWMACC_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN({RVV_VI_VFP_FMA(double, vs2, fs1, vs3)}, false)
      break;
    case RO_V_VFWNMACC_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN({RVV_VI_VFP_FMA(double, -vs2, fs1, -vs3)}, false)
      break;
    case RO_V_VFWMSAC_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN({RVV_VI_VFP_FMA(double, vs2, fs1, -vs3)}, false)
      break;
    case RO_V_VFWNMSAC_VF:
      RVV_VI_CHECK_DSS(true);
      RVV_VI_VFP_VF_LOOP_WIDEN({RVV_VI_VFP_FMA(double, -vs2, fs1, vs3)}, false)
      break;
    case RO_V_VFMV_SF: {
      if (instr_.Vs2Value() == 0x0) {
        if (rvv_vl() > 0 && rvv_vstart() < rvv_vl()) {
          switch (rvv_vsew()) {
            case E8:
              UNREACHABLE();
            case E16:
              UNREACHABLE();
            case E32:
              Rvvelt<uint32_t>(rvv_vd_reg(), 0, true) =
                  (uint32_t)(get_fpu_register_Float32(rs1_reg()).get_bits());
              break;
            case E64:
              Rvvelt<uint64_t>(rvv_vd_reg(), 0, true) =
                  (uint64_t)(get_fpu_register_Float64(rs1_reg()).get_bits());
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
    } break;
    case RO_V_VFSLIDE1DOWN_VF: {
      RVV_VI_CHECK_SLIDE(false);
      RVV_VI_GENERAL_LOOP_BASE
      switch (rvv_vsew()) {
        case E8: {
          UNSUPPORTED();
        }
        case E16: {
          UNSUPPORTED();
        }
        case E32: {
          VF_SLIDE1DOWN_PARAMS(32, 1);
        } break;
        default: {
          VF_SLIDE1DOWN_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    case RO_V_VFSLIDE1UP_VF: {
      RVV_VI_CHECK_SLIDE(true);
      RVV_VI_GENERAL_LOOP_BASE
      if (i < rvv_vstart()) continue;
      switch (rvv_vsew()) {
        case E8: {
          UNSUPPORTED();
        }
        case E16: {
          UNSUPPORTED();
        }
        case E32: {
          VF_SLIDE1UP_PARAMS(32, 1);
        } break;
        default: {
          VF_SLIDE1UP_PARAMS(64, 1);
        } break;
      }
      RVV_VI_LOOP_END
      rvv_trace_vd();
    } break;
    default:
      UNSUPPORTED_RISCV();
  }
}
void Simulator::DecodeVType() {
  switch (instr_.InstructionBits() & (kFunct3Mask | kBaseOpcodeMask)) {
    case OP_IVV:
      DecodeRvvIVV();
      return;
    case OP_FVV:
      DecodeRvvFVV();
      return;
    case OP_MVV:
      DecodeRvvMVV();
      return;
    case OP_IVI:
      DecodeRvvIVI();
      return;
    case OP_IVX:
      DecodeRvvIVX();
      return;
    case OP_FVF:
      DecodeRvvFVF();
      return;
    case OP_MVX:
      DecodeRvvMVX();
      return;
  }
  switch (instr_.InstructionBits() &
          (kBaseOpcodeMask | kFunct3Mask | 0x80000000)) {
    case RO_V_VSETVLI: {
      uint64_t avl;
      set_rvv_vtype(rvv_zimm());
      CHECK_GE(rvv_vsew(), E8);
      CHECK_LE(rvv_vsew(), E64);
      if (rs1_reg() != zero_reg) {
        avl = rs1();
      } else if (rd_reg() != zero_reg) {
        avl = ~0;
      } else {
        avl = rvv_vl();
      }
      avl = avl <= rvv_vlmax() ? avl : rvv_vlmax();
      set_rvv_vl(avl);
      set_rd(rvv_vl());
      set_rvv_vstart(0);
      rvv_trace_status();
      break;
    }
    case RO_V_VSETVL: {
      if (!(instr_.InstructionBits() & 0x40000000)) {
        uint64_t avl;
        set_rvv_vtype(rs2());
        CHECK_GE(rvv_sew(), E8);
        CHECK_LE(rvv_sew(), E64);
        if (rs1_reg() != zero_reg) {
          avl = rs1();
        } else if (rd_reg() != zero_reg) {
          avl = ~0;
        } else {
          avl = rvv_vl();
        }
        avl = avl <= rvv_vlmax()        ? avl
              : avl < (rvv_vlmax() * 2) ? avl / 2
                                        : rvv_vlmax();
        set_rvv_vl(avl);
        set_rd(rvv_vl());
        rvv_trace_status();
      } else {
        DCHECK_EQ(instr_.InstructionBits() &
                      (kBaseOpcodeMask | kFunct3Mask | 0xC0000000),
                  RO_V_VSETIVLI);
        uint64_t avl;
        set_rvv_vtype(rvv_zimm());
        avl = instr_.Rvvuimm();
        avl = avl <= rvv_vlmax()        ? avl
              : avl < (rvv_vlmax() * 2) ? avl / 2
                                        : rvv_vlmax();
        set_rvv_vl(avl);
        set_rd(rvv_vl());
        rvv_trace_status();
        break;
      }
      break;
    }
    default:
      FATAL("Error: Unsupport on FILE:%s:%d.", __FILE__, __LINE__);
  }
}
#endif

// Executes the current instruction.
void Simulator::InstructionDecode(Instruction* instr) {
  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }
  pc_modified_ = false;

  v8::base::EmbeddedVector<char, 256> buffer;

  if (v8_flags.trace_sim || v8_flags.debug_sim) {
    SNPrintF(trace_buf_, " ");
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // Use a reasonably large buffer.
    dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));

    // PrintF("EXECUTING  0x%08" PRIxPTR "   %-44s\n",
    //        reinterpret_cast<intptr_t>(instr), buffer.begin());
  }
  instr_ = instr;
  switch (instr_.InstructionType()) {
    case Instruction::kRType:
      DecodeRVRType();
      break;
    case Instruction::kR4Type:
      DecodeRVR4Type();
      break;
    case Instruction::kIType:
      DecodeRVIType();
      break;
    case Instruction::kSType:
      DecodeRVSType();
      break;
    case Instruction::kBType:
      DecodeRVBType();
      break;
    case Instruction::kUType:
      DecodeRVUType();
      break;
    case Instruction::kJType:
      DecodeRVJType();
      break;
    case Instruction::kCRType:
      DecodeCRType();
      break;
    case Instruction::kCAType:
      DecodeCAType();
      break;
    case Instruction::kCJType:
      DecodeCJType();
      break;
    case Instruction::kCBType:
      DecodeCBType();
      break;
    case Instruction::kCIType:
      DecodeCIType();
      break;
    case Instruction::kCIWType:
      DecodeCIWType();
      break;
    case Instruction::kCSSType:
      DecodeCSSType();
      break;
    case Instruction::kCLType:
      DecodeCLType();
      break;
    case Instruction::kCSType:
      DecodeCSType();
      break;
#ifdef CAN_USE_RVV_INSTRUCTIONS
    case Instruction::kVType:
      DecodeVType();
      break;
#endif
    default:
      if (1) {
        std::cout << "Unrecognized instruction [@pc=0x" << std::hex
                  << registers_[pc] << "]: 0x" << instr->InstructionBits()
                  << std::endl;
      }
      UNSUPPORTED();
  }

  if (v8_flags.trace_sim) {
    PrintF("  0x%012" PRIxPTR "      %-44s\t%s\n",
           reinterpret_cast<intptr_t>(instr), buffer.begin(),
           trace_buf_.begin());
  }

  if (!pc_modified_) {
    set_register(pc,
                 reinterpret_cast<sreg_t>(instr) + instr->InstructionSize());
  }

  if (watch_address_ != nullptr) {
    PrintF("  0x%012" PRIxPTR " :  0x%016" REGIx_FORMAT "  %14" REGId_FORMAT
           " ",
           reinterpret_cast<intptr_t>(watch_address_), *watch_address_,
           *watch_address_);
    // Object obj(*watch_address_);
    // Heap* current_heap = isolate_->heap();
    // if (obj.IsSmi() || IsValidHeapObject(current_heap,
    // Cast<HeapObject>(obj))) {
    //   PrintF(" (");
    //   if (obj.IsSmi()) {
    //     PrintF("smi %d", Smi::ToInt(obj));
    //   } else {
    //     ShortPrint(obj);
    //   }
    //   PrintF(")");
    // }
    PrintF("\n");
    if (watch_value_ != *watch_address_) {
      RiscvDebugger dbg(this);
      dbg.Debug();
      watch_value_ = *watch_address_;
    }
  }
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  sreg_t program_counter = get_pc();
  while (program_counter != end_sim_pc) {
    Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
    icount_++;
    if (icount_ == static_cast<sreg_t>(v8_flags.stop_sim_at)) {
      RiscvDebugger dbg(this);
      dbg.Debug();
    } else {
      InstructionDecode(instr);
    }
    CheckBreakpoints();
    program_counter = get_pc();
  }
}

void Simulator::CallInternal(Address entry) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry.
  set_register(pc, static_cast<sreg_t>(entry));
  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  set_register(ra, end_sim_pc);

  // Remember the values of callee-saved registers.
  sreg_t s0_val = get_register(s0);
  sreg_t s1_val = get_register(s1);
  sreg_t s2_val = get_register(s2);
  sreg_t s3_val = get_register(s3);
  sreg_t s4_val = get_register(s4);
  sreg_t s5_val = get_register(s5);
  sreg_t s6_val = get_register(s6);
  sreg_t s7_val = get_register(s7);
  sreg_t s8_val = get_register(s8);
  sreg_t s9_val = get_register(s9);
  sreg_t s10_val = get_register(s10);
  sreg_t s11_val = get_register(s11);
  sreg_t gp_val = get_register(gp);
  sreg_t sp_val = get_register(sp);

  // Set up the callee-saved registers with a known value. To be able to check
  // that they are preserved properly across JS execution. If this value is
  // small int, it should be SMI.
  sreg_t callee_saved_value = icount_ != 0 ? icount_ & ~kSmiTagMask : -1;
  set_register(s0, callee_saved_value);
  set_register(s1, callee_saved_value);
  set_register(s2, callee_saved_value);
  set_register(s3, callee_saved_value);
  set_register(s4, callee_saved_value);
  set_register(s5, callee_saved_value);
  set_register(s6, callee_saved_value);
  set_register(s7, callee_saved_value);
  set_register(s8, callee_saved_value);
  set_register(s9, callee_saved_value);
  set_register(s10, callee_saved_value);
  set_register(s11, callee_saved_value);
  set_register(gp, callee_saved_value);

  // Start the simulation.
  Execute();

  // Check that the callee-saved registers have been preserved.
  CHECK_EQ(callee_saved_value, get_register(s0));
  CHECK_EQ(callee_saved_value, get_register(s1));
  CHECK_EQ(callee_saved_value, get_register(s2));
  CHECK_EQ(callee_saved_value, get_register(s3));
  CHECK_EQ(callee_saved_value, get_register(s4));
  CHECK_EQ(callee_saved_value, get_register(s5));
  CHECK_EQ(callee_saved_value, get_register(s6));
  CHECK_EQ(callee_saved_value, get_register(s7));
  CHECK_EQ(callee_saved_value, get_register(s8));
  CHECK_EQ(callee_saved_value, get_register(s9));
  CHECK_EQ(callee_saved_value, get_register(s10));
  CHECK_EQ(callee_saved_value, get_register(s11));
  CHECK_EQ(callee_saved_value, get_register(gp));

  // Restore callee-saved registers with the original value.
  set_register(s0, s0_val);
  set_register(s1, s1_val);
  set_register(s2, s2_val);
  set_register(s3, s3_val);
  set_register(s4, s4_val);
  set_register(s5, s5_val);
  set_register(s6, s6_val);
  set_register(s7, s7_val);
  set_register(s8, s8_val);
  set_register(s9, s9_val);
  set_register(s10, s10_val);
  set_register(s11, s11_val);
  set_register(gp, gp_val);
  set_register(sp, sp_val);
}

#ifdef V8_TARGET_ARCH_RISCV64
void Simulator::CallImpl(Address entry, CallArgument* args) {
  int index_gp = 0;
  int index_fp = 0;
  std::vector<int64_t> stack_args(0);
  for (int i = 0; !args[i].IsEnd(); i++) {
    CallArgument arg = args[i];
    if (arg.IsGP() && (index_gp < 8)) {
      set_register(index_gp + kRegCode_a0, arg.bits());
      index_gp++;
    } else if (arg.IsFP() && (index_fp < 8)) {
      set_fpu_register(index_fp + kDoubleCode_fa0, arg.bits());
      index_fp++;
    } else {
      DCHECK(arg.IsFP() || arg.IsGP());
      stack_args.push_back(arg.bits());
    }
  }
  if (v8_flags.trace_sim) {
    std::cout << "CallImpl: reg_arg_count = " << index_fp + index_gp << std::hex
              << " entry-pc (JSEntry) = 0x" << entry
              << " a0 (Isolate-root) = 0x" << get_register(a0)
              << " a1 (orig_func/new_target) = 0x" << get_register(a1)
              << " a2 (func/target) = 0x" << get_register(a2)
              << " a3 (receiver) = 0x" << get_register(a3) << " a4 (argc) = 0x"
              << get_register(a4) << " a5 (argv) = 0x" << get_register(a5)
              << std::endl;
  }
  // Remaining arguments passed on stack.
  int64_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  int64_t stack_args_size =
      stack_args.size() * sizeof(stack_args[0]) + kCArgsSlotsSize;
  int64_t entry_stack = original_stack - stack_args_size;
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  char* stack_argument = reinterpret_cast<char*>(entry_stack);
  memcpy(stack_argument + kCArgSlotCount, stack_args.data(),
         stack_args.size() * sizeof(int64_t));
  set_register(sp, entry_stack);
  CallInternal(entry);
  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);
}
#else
intptr_t Simulator::CallImpl(Address entry, int argument_count,
                             const intptr_t* arguments) {
  constexpr int kRegisterPassedArguments = 8;
  // Set up arguments.
  // RISC-V 64G ISA has a0-a7 for passing arguments
  int reg_arg_count = std::min(kRegisterPassedArguments, argument_count);
  if (reg_arg_count > 0) set_register(a0, arguments[0]);
  if (reg_arg_count > 1) set_register(a1, arguments[1]);
  if (reg_arg_count > 2) set_register(a2, arguments[2]);
  if (reg_arg_count > 3) set_register(a3, arguments[3]);
  if (reg_arg_count > 4) set_register(a4, arguments[4]);
  if (reg_arg_count > 5) set_register(a5, arguments[5]);
  if (reg_arg_count > 6) set_register(a6, arguments[6]);
  if (reg_arg_count > 7) set_register(a7, arguments[7]);
  if (v8_flags.trace_sim) {
    std::cout << "CallImpl: reg_arg_count = " << reg_arg_count << std::hex
              << " entry-pc (JSEntry) = 0x" << entry
              << " a0 (Isolate-root) = 0x" << get_register(a0)
              << " a1 (orig_func/new_target) = 0x" << get_register(a1)
              << " a2 (func/target) = 0x" << get_register(a2)
              << " a3 (receiver) = 0x" << get_register(a3) << " a4 (argc) = 0x"
              << get_register(a4) << " a5 (argv) = 0x" << get_register(a5)
              << std::endl;
  }
  // Remaining arguments passed on stack.
  sreg_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  int stack_args_count = argument_count - reg_arg_count;
  int stack_args_size = stack_args_count * sizeof(*arguments) + kCArgsSlotsSize;
  sreg_t entry_stack = original_stack - stack_args_size;
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }
  // Store remaining arguments on stack, from low to high memory.
  intptr_t* stack_argument = reinterpret_cast<intptr_t*>(entry_stack);
  memcpy(stack_argument + kCArgSlotCount, arguments + reg_arg_count,
         stack_args_count * sizeof(*arguments));
  set_register(sp, entry_stack);
  CallInternal(entry);
  // Pop stack passed arguments.
  CHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);
  // return get_register(a0);
  // RISCV uses a0 to return result
  return get_register(a0);
}
#endif  // V8_TARGET_ARCH_RISCV64

double Simulator::CallFP(Address entry, double d0, double d1) {
  set_fpu_register_double(fa0, d0);
  set_fpu_register_double(fa1, d1);
  CallInternal(entry);
  return get_fpu_register_double(fa0);
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  int64_t new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  int64_t current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

Simulator::LocalMonitor::LocalMonitor()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      size_(TransactionSize::None) {}

void Simulator::LocalMonitor::Clear() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
  size_ = TransactionSize::None;
}

void Simulator::LocalMonitor::NotifyLoad() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non linked load could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on load.
    Clear();
  }
}

void Simulator::LocalMonitor::NotifyLoadLinked(uintptr_t addr,
                                               TransactionSize size) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
  size_ = size;
}

void Simulator::LocalMonitor::NotifyStore() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the local monitor. As a result, it's
    // most strict to unconditionally clear the local monitor on store.
    Clear();
  }
}

bool Simulator::LocalMonitor::NotifyStoreConditional(uintptr_t addr,
                                                     TransactionSize size) {
  if (access_state_ == MonitorAccess::RMW) {
    if (addr == tagged_addr_ && size_ == size) {
      Clear();
      return true;
    } else {
      return false;
    }
  } else {
    DCHECK(access_state_ == MonitorAccess::Open);
    return false;
  }
}

Simulator::GlobalMonitor::LinkedAddress::LinkedAddress()
    : access_state_(MonitorAccess::Open),
      tagged_addr_(0),
      next_(nullptr),
      prev_(nullptr),
      failure_counter_(0) {}

void Simulator::GlobalMonitor::LinkedAddress::Clear_Locked() {
  access_state_ = MonitorAccess::Open;
  tagged_addr_ = 0;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyLoadLinked_Locked(
    uintptr_t addr) {
  access_state_ = MonitorAccess::RMW;
  tagged_addr_ = addr;
}

void Simulator::GlobalMonitor::LinkedAddress::NotifyStore_Locked() {
  if (access_state_ == MonitorAccess::RMW) {
    // A non exclusive store could clear the global monitor. As a result, it's
    // most strict to unconditionally clear global monitors on store.
    Clear_Locked();
  }
}

bool Simulator::GlobalMonitor::LinkedAddress::NotifyStoreConditional_Locked(
    uintptr_t addr, bool is_requesting_thread) {
  if (access_state_ == MonitorAccess::RMW) {
    if (is_requesting_thread) {
      if (addr == tagged_addr_) {
        Clear_Locked();
        // Introduce occasional sc/scd failures. This is to simulate the
        // behavior of hardware, which can randomly fail due to background
        // cache evictions.
        if (failure_counter_++ >= kMaxFailureCounter) {
          failure_counter_ = 0;
          return false;
        } else {
          return true;
        }
      }
    } else if ((addr & kExclusiveTaggedAddrMask) ==
               (tagged_addr_ & kExclusiveTaggedAddrMask)) {
      // Check the masked addresses when responding to a successful lock by
      // another thread so the implementation is more conservative (i.e. the
      // granularity of locking is as large as possible.)
      Clear_Locked();
      return false;
    }
  }
  return false;
}

void Simulator::GlobalMonitor::NotifyLoadLinked_Locked(
    uintptr_t addr, LinkedAddress* linked_address) {
  linked_address->NotifyLoadLinked_Locked(addr);
  PrependProcessor_Locked(linked_address);
}

void Simulator::GlobalMonitor::NotifyStore_Locked(
    LinkedAddress* linked_address) {
  // Notify each thread of the store operation.
  for (LinkedAddress* iter = head_; iter; iter = iter->next_) {
    iter->NotifyStore_Locked();
  }
}

bool Simulator::GlobalMonitor::NotifyStoreConditional_Locked(
    uintptr_t addr, LinkedAddress* linked_address) {
  DCHECK(IsProcessorInLinkedList_Locked(linked_address));
  if (linked_address->NotifyStoreConditional_Locked(addr, true)) {
    // Notify the other processors that this StoreConditional succeeded.
    for (LinkedAddress* iter = head_; iter; iter = iter->next_) {
      if (iter != linked_address) {
        iter->NotifyStoreConditional_Locked(addr, false);
      }
    }
    return true;
  } else {
    return false;
  }
}

bool Simulator::GlobalMonitor::IsProcessorInLinkedList_Locked(
    LinkedAddress* linked_address) const {
  return head_ == linked_address || linked_address->next_ ||
         linked_address->prev_;
}

void Simulator::GlobalMonitor::PrependProcessor_Locked(
    LinkedAddress* linked_address) {
  if (IsProcessorInLinkedList_Locked(linked_address)) {
    return;
  }

  if (head_) {
    head_->prev_ = linked_address;
  }
  linked_address->prev_ = nullptr;
  linked_address->next_ = head_;
  head_ = linked_address;
}

void Simulator::GlobalMonitor::RemoveLinkedAddress(
    LinkedAddress* linked_address) {
  base::MutexGuard lock_guard(&mutex);
  if (!IsProcessorInLinkedList_Locked(linked_address)) {
    return;
  }

  if (linked_address->prev_) {
    linked_address->prev_->next_ = linked_address->next_;
  } else {
    head_ = linked_address->next_;
  }
  if (linked_address->next_) {
    linked_address->next_->prev_ = linked_address->prev_;
  }
  linked_address->prev_ = nullptr;
  linked_address->next_ = nullptr;
}

#undef SScanF
#undef BRACKETS

void Simulator::DoSwitchStackLimit(Instruction* instr) {
  const int64_t stack_limit = get_register(kSimulatorBreakArgument.code());
  // stack_limit represents js limit and adjusted by extra runaway gap.
  // Also, stack switching code reads js_limit generated by
  // {Simulator::StackLimit} and then resets it back here.
  // So without adjusting back incoming value by safety gap
  // {stack_limit_} will be shortened by kAdditionalStackMargin yielding
  // positive feedback loop.
  stack_limit_ = static_cast<uintptr_t>(stack_limit - kAdditionalStackMargin);
}

}  // namespace internal
}  // namespace v8

#endif  // USE_SIMULATOR
```