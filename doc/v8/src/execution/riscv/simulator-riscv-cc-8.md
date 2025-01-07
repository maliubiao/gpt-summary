Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's RISC-V simulator. They have specific questions framed as constraints:

1. **List Functionality:** Provide a general overview of what the code does.
2. **Torque Check:** Determine if the file would be a Torque file based on its extension.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's code logic, provide example inputs and outputs.
5. **Common Programming Errors:**  Point out any common programming errors the code might expose.
6. **Part Number:** Acknowledge that this is part 9 of 10.
7. **Summarize Functionality:**  Provide a concise summary of the code's purpose.

**Mental Model:**

The code seems to be implementing various RISC-V Vector (RVV) instructions within the V8 simulator. It focuses heavily on floating-point operations. The `RVV_VI_*` and `RVV_VFP_*` macros suggest handling vector instructions and floating-point vector operations, respectively. The code handles different instruction types (`OP_FVV`, `OP_IVV`, `OP_MVV`, `OP_FVF`, etc.) and dispatches to specific logic based on the instruction's opcode and function codes.

**Step-by-step thought process:**

1. **General Functionality:** The code simulates the execution of RISC-V Vector instructions, specifically focusing on floating-point operations. It iterates through vector elements, performing the specified operation.

2. **Torque Check:** The filename ends with `.cc`, not `.tq`. Therefore, it's not a Torque source file.

3. **JavaScript Relation:** These instructions directly support JavaScript's numerical computations when running on a RISC-V architecture with the RVV extension. For example, vector addition or multiplication would speed up array operations in JavaScript.

4. **Code Logic Inference:**  Let's take `RO_V_VFADD_VV` as an example. It performs vector addition of two floating-point vectors (`vs1`, `vs2`) and stores the result in `vd`. We can assume `vs1`, `vs2`, and `vd` represent vectors of floats or doubles. The `RVV_VI_VFP_VV_LOOP` macro likely handles iterating through the elements of these vectors. The code also includes NaN handling and setting floating-point flags (`set_fflags`).

5. **Common Programming Errors:** A common error exposed by this code is incorrect handling of NaN (Not-a-Number) values in floating-point operations. The code explicitly checks for and handles NaNs, showing the importance of this. Another could be incorrect usage of vector lengths or element types if the simulator isn't configured correctly.

6. **Part Number:** Acknowledge that this is part 9/10.

7. **Summarize Functionality:** This section of the simulator code is responsible for interpreting and executing RISC-V Vector instructions, particularly those involving floating-point arithmetic and comparisons, within the V8 engine.

**Pre-computation/Pre-analysis:**

* **RVV Instruction Set:**  Understanding the basic operations of the RVV instructions mentioned (e.g., `VFADD_V`, `VFSQRT_V`, `VMFEQ_VV`) is crucial.
* **V8 Simulator Structure:**  Knowing that this is part of a simulator within V8 helps contextualize its purpose.
* **Floating-point Arithmetic:** Familiarity with floating-point concepts like NaN and infinity is needed to understand the error handling.

**Refinement and Iteration:**

Initially, I might have focused too much on the low-level details of the macros. However, the prompt asks for functionality, so a higher-level explanation is better. For the JavaScript example, relating it to common array operations makes it more understandable. For the input/output example, choosing a simple vector addition makes it clearer. For common errors, highlighting NaN handling is a direct consequence of the code's checks.

Having gone through this thought process, I can now generate the response based on these insights.
```cpp
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
                              vd
Prompt: 
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共10部分，请归纳一下它的功能

"""
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
        
"""


```