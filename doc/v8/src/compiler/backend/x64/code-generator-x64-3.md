Response: Let's break down the thought process to summarize the functionality of this C++ code snippet.

1. **Initial Scan for Keywords and Patterns:** The first pass involves quickly scanning the code for recurring keywords and patterns. We see `case kX64...`, `__ Pmovzxdq`, `ASSEMBLE_SIMD_BINOP`, `CpuFeatureScope`, `XMMRegister`, `YMMRegister`, `Operand`, `__ lock()`, and various SIMD instruction names (e.g., `pminsb`, `pmaxsw`, `vpmovzxdq`). These immediately suggest that the code is dealing with:
    * **Instruction handling:** The `switch` statement based on `opcode` indicates it's processing different instruction types.
    * **x64 architecture:** The `kX64` prefix and specific x86/x64 instruction mnemonics (like `movsxbl`, `xchgb`, `cmpxchgl`) confirm this.
    * **SIMD (Single Instruction, Multiple Data) operations:**  The `Pmov`, `vpmov`, `ASSEMBLE_SIMD`, `XMMRegister`, and `YMMRegister` strongly point to SIMD instruction generation.
    * **CPU feature detection:** `CpuFeatureScope` suggests conditional code execution based on CPU capabilities (like AVX, AVX2, AVX_VNNI).
    * **Memory operations:**  `Operand` and instructions like `Pextrb(operand, ...)` indicate interaction with memory.
    * **Atomic operations:** `__ lock()`, `xchgb`, `cmpxchg` point to the implementation of atomic memory operations.

2. **Categorizing Instruction Types:**  As we look at the `case` labels, we can start to categorize the types of operations being handled. We see:
    * **Conversions:** `kX64I64x2UConvertI32x4High`, `kX64I32x4SConvertF32x4`, etc. –  These convert between different data types and sizes within SIMD registers.
    * **Arithmetic/Logical operations:** `kX64IMinS`, `kX64IMaxS`, `kX64IAddSatS`, `kX64SAnd`, `kX64SOr`, `kX64SXor`. These perform arithmetic (min, max, add with saturation) and logical (AND, OR, XOR) operations on SIMD vectors.
    * **Comparisons:** `kX64IGtU`, `kX64IGeU`. These compare elements within SIMD vectors.
    * **Dot products:** `kX64I32x4DotI16x8S`, `kX64I32x4DotI8x16I7x16AddS`. These perform dot product calculations on vector elements.
    * **Lane manipulation:** `kX64IExtractLaneS`, `kX64I32X4ShiftZeroExtendI8x16`, `kX64I8x16Swizzle`, `kX64I8x16Shuffle`. These extract, shift, and rearrange data within SIMD vectors.
    * **Constant loading:** `kX64S128Const`, `kX64SZero`, `kX64SAllOnes`. These load specific constant values into SIMD registers.
    * **Memory loads and stores:** `kX64S128Load8Splat`, `kX64Movdqu256`, `kAtomicStoreWord8`. These move data between memory and SIMD/general-purpose registers.
    * **Unpacking/Packing:** `kX64S64x2UnpackHigh`, `kX64I8x16SConvertI16x8`. These rearrange data by interleaving or combining elements from different vectors.
    * **Atomic operations:** `kAtomicExchangeInt8`, `kAtomicCompareExchangeWord32`, `kAtomicAddInt8`. These are atomic read-modify-write operations on memory.

3. **Identifying Higher-Level Functionality:**  Recognizing these categories, we can infer the broader purpose. This code isn't just about generating individual assembly instructions; it's about *implementing higher-level operations* using those instructions. Specifically, it seems to be implementing the semantics of various SIMD instructions (likely part of a larger instruction set architecture like WebAssembly's SIMD extensions) on the x64 platform. The atomic operations suggest support for concurrent programming primitives.

4. **Considering the Context (Part 4 of 5):** The prompt mentions "part 4 of 5". This implies the code is part of a larger code generation process. Knowing this helps refine the summary. This specific part likely focuses on the *implementation details* of a subset of instructions, building upon earlier stages that might handle instruction selection and register allocation, and feeding into later stages like code emission or optimization.

5. **Relating to JavaScript (if applicable):** The prompt asks about the relationship to JavaScript. V8 is the JavaScript engine for Chrome and Node.js. Therefore, this code is part of the *compilation pipeline* within V8. When JavaScript code uses SIMD-like operations (e.g., through typed arrays or potentially future SIMD language features), V8 needs to translate those high-level operations into efficient machine code for the target architecture. This code snippet is a crucial part of that translation for the x64 architecture.

6. **Crafting the Summary:** Based on these steps, we can now construct a comprehensive summary, focusing on the key aspects: instruction processing, SIMD operation implementation, CPU feature awareness, memory access, atomic operations, and its role within the V8 JavaScript engine's code generation for x64. The JavaScript example then serves to illustrate how the low-level code relates to a higher-level JavaScript concept.

7. **Refinement and Iteration (Self-Correction):**  After drafting the initial summary, review it for clarity, accuracy, and completeness. Are there any ambiguities? Is the language precise?  For example, initially, I might just say "it generates x64 instructions." But that's too vague. Adding "specifically for SIMD operations and atomic operations" is more informative. Also, explicitly linking it to V8 and JavaScript's execution improves the answer's relevance. Thinking about the "part 4 of 5" also helps to contextualize the code's role in the overall compilation process.
This C++ code snippet, being part 4 of 5 of `code-generator-x64.cc`, primarily focuses on **implementing the code generation logic for a specific set of SIMD (Single Instruction, Multiple Data) and atomic operations on the x64 architecture within the V8 JavaScript engine.**

Here's a breakdown of its functionalities:

* **SIMD Instruction Implementation:**  The majority of the code consists of `case` statements within a larger function (likely the main code generation function). Each `case` corresponds to a specific SIMD instruction (identified by `kX64...`). For each instruction, the code generates the appropriate x64 assembly instructions using the `__` macro (which likely wraps the V8 assembler).
    * **Data Type Conversions:**  Handles conversions between different integer and floating-point SIMD vector types (e.g., `kX64I64x2UConvertI32x4High`, `kX64I32x4SConvertF32x4`).
    * **Arithmetic and Logical Operations:** Implements operations like minimum, maximum, addition, subtraction, bitwise AND, OR, XOR on SIMD vectors (`kX64IMinS`, `kX64IMaxU`, `kX64IAddSatS`, `kX64SAnd`, `kX64SOr`, `kX64SXor`).
    * **Comparisons:** Generates code for comparing SIMD vectors (`kX64IGtU`, `kX64IGeU`).
    * **Lane Manipulation:** Includes operations for extracting and inserting lanes (elements) within SIMD vectors, shuffling, swizzling, and rotating (`kX64IExtractLaneS`, `kX64I8x16Swizzle`, `kX64S32x4Rotate`).
    * **Constant Loading:**  Handles loading constant values into SIMD registers (`kX64S128Const`, `kX64SZero`, `kX64SAllOnes`).
    * **Memory Operations:** Implements loading and storing SIMD data from/to memory with various strategies (e.g., splatting, loading specific numbers of elements) (`kX64S128Load8Splat`, `kX64Movdqu256`).
    * **Unpacking and Packing:** Generates instructions for interleaving and combining elements from SIMD vectors (`kX64S64x2UnpackHigh`, `kX64I8x16SConvertI16x8`).
    * **Advanced SIMD Operations:**  Includes more complex operations like dot products, extended multiplications, and saturated arithmetic.

* **Atomic Operation Implementation:** The code also includes `case` statements for various atomic memory operations. These operations ensure that memory updates are performed indivisibly, which is crucial for concurrent programming.
    * **Atomic Stores:** Implements atomic store operations for different data sizes (`kAtomicStoreWord8`, `kX64Word64AtomicStoreWord64`).
    * **Atomic Exchanges:**  Handles atomically exchanging a value in memory with a register value (`kAtomicExchangeInt8`, `kX64Word64AtomicExchangeUint64`).
    * **Atomic Compare-and-Exchange:** Implements the compare-and-swap (CAS) operation, which atomically updates a memory location only if its current value matches an expected value (`kAtomicCompareExchangeInt8`, `kX64Word64AtomicCompareExchangeUint64`).
    * **Atomic Arithmetic and Logical Operations:** Generates code for atomically performing arithmetic (add, sub) and logical (and, or, xor) operations on memory locations (`kAtomicAddInt8`, `kAtomicXorWord32`).

* **CPU Feature Detection:** The code uses `CpuFeatureScope` to conditionally execute certain instructions based on the availability of specific CPU features like AVX, AVX2, and AVX_VNNI. This ensures that the generated code can take advantage of advanced processor capabilities when available, while still functioning on older hardware.

* **Helper Macros:** The code uses various macros like `ASSEMBLE_SIMD_BINOP`, `ASSEMBLE_ATOMIC_BINOP`, etc., to simplify the generation of common assembly instruction patterns.

**Relationship to JavaScript:**

This code is directly related to how V8 executes JavaScript code that utilizes SIMD and shared memory features.

* **SIMD.js (Legacy):** While SIMD.js is deprecated, this code would have been responsible for generating the underlying x64 instructions when JavaScript code used `SIMD` types (like `SIMD.Int32x4`). For example:

```javascript
// (Hypothetical SIMD.js example before deprecation)
const a = SIMD.Int32x4(1, 2, 3, 4);
const b = SIMD.Int32x4(5, 6, 7, 8);
const sum = SIMD.add(a, b); // This would potentially trigger code generation handled by this file
```

* **WebAssembly SIMD:**  V8 also supports WebAssembly's SIMD instructions. When WebAssembly code with SIMD operations is executed, this C++ code is crucial for translating those Wasm instructions into native x64 instructions. For example, a WebAssembly instruction like `i32x4.add` would be implemented here.

* **SharedArrayBuffer and Atomics:**  The atomic operations are essential for implementing the semantics of `SharedArrayBuffer` and the `Atomics` object in JavaScript. These features allow for sharing memory between different JavaScript agents (threads or workers) and performing atomic operations to prevent race conditions.

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 4);
const view = new Int32Array(sab);

// In one thread/worker:
Atomics.add(view, 0, 5);

// In another thread/worker:
const value = Atomics.load(view, 0); // Guaranteed to see the updated value
```

**In summary, this part of the `code-generator-x64.cc` file is responsible for the low-level details of translating high-level SIMD and atomic operations (originating from JavaScript or WebAssembly) into efficient x64 machine code, enabling V8 to execute these features effectively on x64 processors.**  It bridges the gap between the abstract operations defined in the language specifications and the concrete instructions understood by the CPU.

### 提示词
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
__ Pmovzxdq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I64x2UConvertI32x4High: {
      __ I64x2UConvertI32x4High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I64x4UConvertI32x4: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxdq(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4SConvertF32x4: {
      __ I32x4SConvertF32x4(i.OutputSimd128Register(),
                            i.InputSimd128Register(0), kScratchDoubleReg,
                            kScratchRegister);
      break;
    }
    case kX64I32x8SConvertF32x8: {
      __ I32x8SConvertF32x8(i.OutputSimd256Register(),
                            i.InputSimd256Register(0), kScratchSimd256Reg,
                            kScratchRegister);
      break;
    }
    case kX64I32x4SConvertI16x8Low: {
      __ Pmovsxwd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4SConvertI16x8High: {
      __ I32x4SConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kX64I32x8SConvertI16x8: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxwd(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64IMinS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MinS
            ASSEMBLE_SIMD_BINOP(pminsb);
            break;
          }
          case kL16: {
            // I16x8MinS
            ASSEMBLE_SIMD_BINOP(pminsw);
            break;
          }
          case kL32: {
            // I32x4MinS
            ASSEMBLE_SIMD_BINOP(pminsd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MinS
            ASSEMBLE_SIMD256_BINOP(pminsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16MinS
            ASSEMBLE_SIMD256_BINOP(pminsw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MinS
            ASSEMBLE_SIMD256_BINOP(pminsd, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IMaxS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsb);
            break;
          }
          case kL16: {
            // I16x8MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsw);
            break;
          }
          case kL32: {
            // I32x4MaxS
            ASSEMBLE_SIMD_BINOP(pmaxsd);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MaxS
            ASSEMBLE_SIMD256_BINOP(pmaxsd, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I32x4UConvertF32x4: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp = i.TempSimd128Register(0);
      XMMRegister tmp2 = i.TempSimd128Register(1);
      __ I32x4TruncF32x4U(dst, dst, tmp, tmp2);
      break;
    }
    case kX64I32x8UConvertF32x8: {
      DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
      CpuFeatureScope avx_scope(masm(), AVX);
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      YMMRegister tmp1 = i.TempSimd256Register(0);
      YMMRegister tmp2 = i.TempSimd256Register(1);
      // NAN->0, negative->0
      __ vpxor(tmp2, tmp2, tmp2);
      __ vmaxps(dst, dst, tmp2);
      // scratch: float representation of max_signed
      __ vpcmpeqd(tmp2, tmp2, tmp2);
      __ vpsrld(tmp2, tmp2, uint8_t{1});  // 0x7fffffff
      __ vcvtdq2ps(tmp2, tmp2);           // 0x4f000000
      // tmp1: convert (src-max_signed).
      // Positive overflow lanes -> 0x7FFFFFFF
      // Negative lanes -> 0
      __ vmovaps(tmp1, dst);
      __ vsubps(tmp1, tmp1, tmp2);
      __ vcmpleps(tmp2, tmp2, tmp1);
      __ vcvttps2dq(tmp1, tmp1);
      __ vpxor(tmp1, tmp1, tmp2);
      __ vpxor(tmp2, tmp2, tmp2);
      __ vpmaxsd(tmp1, tmp1, tmp2);
      // convert. Overflow lanes above max_signed will be 0x80000000
      __ vcvttps2dq(dst, dst);
      // Add (src-max_signed) for overflow lanes.
      __ vpaddd(dst, dst, tmp1);
      break;
    }
    case kX64I32x4UConvertI16x8Low: {
      __ Pmovzxwd(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I32x4UConvertI16x8High: {
      __ I32x4UConvertI16x8High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I32x8UConvertI16x8: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxwd(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64IMinU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MinU
            ASSEMBLE_SIMD_BINOP(pminub);
            break;
          }
          case kL16: {
            // I16x8MinU
            ASSEMBLE_SIMD_BINOP(pminuw);
            break;
          }
          case kL32: {
            // I32x4MinU
            ASSEMBLE_SIMD_BINOP(pminud);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MinU
            ASSEMBLE_SIMD256_BINOP(pminub, AVX2);
            break;
          }
          case kL16: {
            // I16x16MinU
            ASSEMBLE_SIMD256_BINOP(pminuw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MinU
            ASSEMBLE_SIMD256_BINOP(pminud, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IMaxU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16MaxU
            ASSEMBLE_SIMD_BINOP(pmaxub);
            break;
          }
          case kL16: {
            // I16x8MaxU
            ASSEMBLE_SIMD_BINOP(pmaxuw);
            break;
          }
          case kL32: {
            // I32x4MaxU
            ASSEMBLE_SIMD_BINOP(pmaxud);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxub, AVX2);
            break;
          }
          case kL16: {
            // I16x16MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxuw, AVX2);
            break;
          }
          case kL32: {
            // I32x8MaxU
            ASSEMBLE_SIMD256_BINOP(pmaxud, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGtU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(1);
        switch (lane_size) {
          case kL8: {
            __ Pmaxub(dst, src);
            __ Pcmpeqb(dst, src);
            __ Pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL16: {
            // I16x8GtU
            __ Pmaxuw(dst, src);
            __ Pcmpeqw(dst, src);
            __ Pcmpeqw(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          case kL32: {
            // I32x4GtU
            __ Pmaxud(dst, src);
            __ Pcmpeqd(dst, src);
            __ Pcmpeqd(kScratchDoubleReg, kScratchDoubleReg);
            __ Pxor(dst, kScratchDoubleReg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32GtU
            __ vpmaxub(dst, dst, src);
            __ vpcmpeqb(dst, dst, src);
            __ vpcmpeqb(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL16: {
            // I16x16GtU
            __ vpmaxuw(dst, dst, src);
            __ vpcmpeqw(dst, dst, src);
            __ vpcmpeqw(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          case kL32: {
            // I32x8GtU
            __ vpmaxud(dst, dst, src);
            __ vpcmpeqd(dst, dst, src);
            __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                        kScratchSimd256Reg);
            __ vpxor(dst, dst, kScratchSimd256Reg);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IGeU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        XMMRegister dst = i.OutputSimd128Register();
        XMMRegister src = i.InputSimd128Register(1);
        switch (lane_size) {
          case kL8: {
            // I8x16GeU
            __ Pminub(dst, src);
            __ Pcmpeqb(dst, src);
            break;
          }
          case kL16: {
            // I16x8GeU
            __ Pminuw(dst, src);
            __ Pcmpeqw(dst, src);
            break;
          }
          case kL32: {
            // I32x4GeU
            __ Pminud(dst, src);
            __ Pcmpeqd(dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(0));
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        switch (lane_size) {
          case kL8: {
            // I8x32GeU
            __ vpminub(dst, dst, src);
            __ vpcmpeqb(dst, dst, src);
            break;
          }
          case kL16: {
            // I16x16GeU
            __ vpminuw(dst, dst, src);
            __ vpcmpeqw(dst, dst, src);
            break;
          }
          case kL32: {
            // I32x8GeU
            __ vpminud(dst, dst, src);
            __ vpcmpeqd(dst, dst, src);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I32x4DotI16x8S: {
      ASSEMBLE_SIMD_BINOP(pmaddwd);
      break;
    }
    case kX64I32x4DotI8x16I7x16AddS: {
      DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(2));
      // If AVX_VNNI supported, pass kScratchDoubleReg twice as unused
      // arguments.
      XMMRegister tmp = kScratchDoubleReg;
      if (!(CpuFeatures::IsSupported(AVX_VNNI) ||
            CpuFeatures::IsSupported(AVX_VNNI_INT8))) {
        tmp = i.TempSimd128Register(0);
      }
      __ I32x4DotI8x16I7x16AddS(
          i.OutputSimd128Register(), i.InputSimd128Register(0),
          i.InputSimd128Register(1), i.InputSimd128Register(2),
          kScratchDoubleReg, tmp);
      break;
    }
    case kX64I32x8DotI8x32I7x32AddS: {
      DCHECK_EQ(i.OutputSimd256Register(), i.InputSimd256Register(2));
      // If AVX_VNNI supported, pass kScratchSimd256Reg twice as unused
      // arguments.
      YMMRegister tmp = kScratchSimd256Reg;
      if (!CpuFeatures::IsSupported(AVX_VNNI)) {
        tmp = i.TempSimd256Register(0);
      }
      __ I32x8DotI8x32I7x32AddS(
          i.OutputSimd256Register(), i.InputSimd256Register(0),
          i.InputSimd256Register(1), i.InputSimd256Register(2),
          kScratchSimd256Reg, tmp);
      break;
    }
    case kX64I32x4ExtAddPairwiseI16x8S: {
      __ I32x4ExtAddPairwiseI16x8S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchRegister);
      break;
    }
    case kX64I32x8ExtAddPairwiseI16x16S: {
      __ I32x8ExtAddPairwiseI16x16S(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I32x4ExtAddPairwiseI16x8U: {
      __ I32x4ExtAddPairwiseI16x8U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0),
                                   kScratchDoubleReg);
      break;
    }
    case kX64I32x8ExtAddPairwiseI16x16U: {
      __ I32x8ExtAddPairwiseI16x16U(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I32X4ShiftZeroExtendI8x16: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      uint8_t shift = i.InputUint8(1);
      if (shift != 0) {
        __ Palignr(dst, src, shift);
        __ Pmovzxbd(dst, dst);
      } else {
        __ Pmovzxbd(dst, src);
      }
      break;
    }
    case kX64S128Const: {
      // Emit code for generic constants as all zeros, or ones cases will be
      // handled separately by the selector.
      XMMRegister dst = i.OutputSimd128Register();
      uint32_t imm[4] = {};
      for (int j = 0; j < 4; j++) {
        imm[j] = i.InputUint32(j);
      }
      SetupSimdImmediateInRegister(masm(), imm, dst);
      break;
    }
    case kX64SZero: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Zero
        XMMRegister dst = i.OutputSimd128Register();
        __ Pxor(dst, dst);
      } else if (vec_len == kV256) {  // S256Zero
        YMMRegister dst = i.OutputSimd256Register();
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpxor(dst, dst, dst);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SAllOnes: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128AllOnes
        XMMRegister dst = i.OutputSimd128Register();
        __ Pcmpeqd(dst, dst);
      } else if (vec_len == kV256) {  // S256AllOnes
        YMMRegister dst = i.OutputSimd256Register();
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpcmpeqd(dst, dst, dst);
      } else {
        UNREACHABLE();
      }
      break;
    }
    // case kX64I16x8ExtractLaneS: {
    case kX64IExtractLaneS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16ExtractLaneS
            Register dst = i.OutputRegister();
            __ Pextrb(dst, i.InputSimd128Register(0), i.InputUint8(1));
            __ movsxbl(dst, dst);
            break;
          }
          case kL16: {
            // I16x8ExtractLaneS
            Register dst = i.OutputRegister();
            __ Pextrw(dst, i.InputSimd128Register(0), i.InputUint8(1));
            __ movsxwl(dst, dst);
            break;
          }
          default:
            UNREACHABLE();
        }

      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8SConvertI8x16Low: {
      __ Pmovsxbw(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8SConvertI8x16High: {
      __ I16x8SConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0));
      break;
    }
    case kX64I16x16SConvertI8x16: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovsxbw(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8SConvertI32x4: {
      ASSEMBLE_SIMD_BINOP(packssdw);
      break;
    }
    case kX64IAddSatS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AddSatS
            ASSEMBLE_SIMD_BINOP(paddsb);
            break;
          }
          case kL16: {
            // I16x8AddSatS
            ASSEMBLE_SIMD_BINOP(paddsw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32AddSatS
            ASSEMBLE_SIMD256_BINOP(paddsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16AddSatS
            ASSEMBLE_SIMD256_BINOP(paddsw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISubSatS: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16SubSatS
            ASSEMBLE_SIMD_BINOP(psubsb);
            break;
          }
          case kL16: {
            // I16x8SubSatS
            ASSEMBLE_SIMD_BINOP(psubsw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32SubSatS
            ASSEMBLE_SIMD256_BINOP(psubsb, AVX2);
            break;
          }
          case kL16: {
            // I16x16SubSatS
            ASSEMBLE_SIMD256_BINOP(psubsw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8UConvertI8x16Low: {
      __ Pmovzxbw(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8UConvertI8x16High: {
      __ I16x8UConvertI8x16High(i.OutputSimd128Register(),
                                i.InputSimd128Register(0), kScratchDoubleReg);
      break;
    }
    case kX64I16x16UConvertI8x16: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpmovzxbw(i.OutputSimd256Register(), i.InputSimd128Register(0));
      break;
    }
    case kX64I16x8UConvertI32x4: {
      ASSEMBLE_SIMD_BINOP(packusdw);
      break;
    }
    case kX64IAddSatU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AddSatU
            ASSEMBLE_SIMD_BINOP(paddusb);
            break;
          }
          case kL16: {
            // I16x8AddSatU
            ASSEMBLE_SIMD_BINOP(paddusw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32AddSatU
            ASSEMBLE_SIMD256_BINOP(paddusb, AVX2);
            break;
          }
          case kL16: {
            // I16x16AddSatU
            ASSEMBLE_SIMD256_BINOP(paddusw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64ISubSatU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16SubSatU
            ASSEMBLE_SIMD_BINOP(psubusb);
            break;
          }
          case kL16: {
            // I16x8SubSatU
            ASSEMBLE_SIMD_BINOP(psubusw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32SubSatU
            ASSEMBLE_SIMD256_BINOP(psubusb, AVX2);
            break;
          }
          case kL16: {
            // I16x16SubSatU
            ASSEMBLE_SIMD256_BINOP(psubusw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64IRoundingAverageU: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16RoundingAverageU
            ASSEMBLE_SIMD_BINOP(pavgb);
            break;
          }
          case kL16: {
            // I16x8RoundingAverageU
            ASSEMBLE_SIMD_BINOP(pavgw);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL8: {
            // I8x32RoundingAverageU
            ASSEMBLE_SIMD256_BINOP(pavgb, AVX2);
            break;
          }
          case kL16: {
            // I16x16RoundingAverageU
            ASSEMBLE_SIMD256_BINOP(pavgw, AVX2);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I16x8ExtMulLowI8x16S: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/true);
      break;
    }
    case kX64I16x8ExtMulHighI8x16S: {
      __ I16x8ExtMulHighS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8ExtMulLowI8x16U: {
      __ I16x8ExtMulLow(i.OutputSimd128Register(), i.InputSimd128Register(0),
                        i.InputSimd128Register(1), kScratchDoubleReg,
                        /*is_signed=*/false);
      break;
    }
    case kX64I16x8ExtMulHighI8x16U: {
      __ I16x8ExtMulHighU(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8ExtAddPairwiseI8x16S: {
      __ I16x8ExtAddPairwiseI8x16S(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchDoubleReg,
                                   kScratchRegister);
      break;
    }
    case kX64I16x16ExtAddPairwiseI8x32S: {
      __ I16x16ExtAddPairwiseI8x32S(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I16x8ExtAddPairwiseI8x16U: {
      __ I16x8ExtAddPairwiseI8x16U(i.OutputSimd128Register(),
                                   i.InputSimd128Register(0), kScratchRegister);
      break;
    }
    case kX64I16x16ExtAddPairwiseI8x32U: {
      __ I16x16ExtAddPairwiseI8x32U(i.OutputSimd256Register(),
                                    i.InputSimd256Register(0),
                                    kScratchSimd256Reg);
      break;
    }
    case kX64I16x8Q15MulRSatS: {
      __ I16x8Q15MulRSatS(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          i.InputSimd128Register(1), kScratchDoubleReg);
      break;
    }
    case kX64I16x8RelaxedQ15MulRS: {
      __ Pmulhrsw(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1));
      break;
    }
    case kX64I16x8DotI8x16I7x16S: {
      __ I16x8DotI8x16I7x16S(i.OutputSimd128Register(),
                             i.InputSimd128Register(0),
                             i.InputSimd128Register(1));
      break;
    }
    case kX64I16x16DotI8x32I7x32S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      __ vpmaddubsw(i.OutputSimd256Register(), i.InputSimd256Register(1),
                    i.InputSimd256Register(0));
      break;
    }
    case kX64Pextrb: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      if (HasAddressingMode(instr)) {
        Operand operand = i.MemoryOperand(&index);
        __ Pextrb(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        __ Pextrb(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputUint8(1));
      }
      break;
    }
    case kX64Pextrw: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      if (HasAddressingMode(instr)) {
        Operand operand = i.MemoryOperand(&index);
        __ Pextrw(operand, i.InputSimd128Register(index),
                  i.InputUint8(index + 1));
      } else {
        __ Pextrw(i.OutputRegister(), i.InputSimd128Register(0),
                  i.InputUint8(1));
      }
      break;
    }
    case kX64Pinsrb: {
      ASSEMBLE_PINSR(Pinsrb);
      break;
    }
    case kX64Pinsrw: {
      ASSEMBLE_PINSR(Pinsrw);
      break;
    }
    case kX64Pinsrd: {
      ASSEMBLE_PINSR(Pinsrd);
      break;
    }
    case kX64Pinsrq: {
      ASSEMBLE_PINSR(Pinsrq);
      break;
    }
    case kX64I8x16SConvertI16x8: {
      ASSEMBLE_SIMD_BINOP(packsswb);
      break;
    }
    case kX64I8x16UConvertI16x8: {
      ASSEMBLE_SIMD_BINOP(packuswb);
      break;
    }
    case kX64I32x4ExtMulLowI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x4ExtMulHighI16x8S: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x4ExtMulLowI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/true,
                     /*is_signed=*/false);
      break;
    }
    case kX64I32x4ExtMulHighI16x8U: {
      __ I32x4ExtMul(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchDoubleReg,
                     /*low=*/false,
                     /*is_signed=*/false);
      break;
    }
    case kX64SAnd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128And
        ASSEMBLE_SIMD_BINOP(pand);
      } else if (vec_len == kV256) {  // S256And
        ASSEMBLE_SIMD256_BINOP(pand, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SOr: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Or
        ASSEMBLE_SIMD_BINOP(por);
      } else if (vec_len == kV256) {  // S256Or
        ASSEMBLE_SIMD256_BINOP(por, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SXor: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Xor
        ASSEMBLE_SIMD_BINOP(pxor);
      } else if (vec_len == kV256) {  // S256Xor
        ASSEMBLE_SIMD256_BINOP(pxor, AVX2);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SNot: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Not
        __ S128Not(i.OutputSimd128Register(), i.InputSimd128Register(0),
                   kScratchDoubleReg);
      } else if (vec_len == kV256) {  // S256Not
        __ S256Not(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   kScratchSimd256Reg);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SSelect: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128Select
        __ S128Select(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), i.InputSimd128Register(2),
                      kScratchDoubleReg);
      } else if (vec_len == kV256) {  // S256Select
        __ S256Select(i.OutputSimd256Register(), i.InputSimd256Register(0),
                      i.InputSimd256Register(1), i.InputSimd256Register(2),
                      kScratchSimd256Reg);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64SAndNot: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {  // S128AndNot
        // The inputs have been inverted by instruction selector, so we can call
        // andnps here without any modifications.
        ASSEMBLE_SIMD_BINOP(andnps);
      } else if (vec_len == kV256) {  // S256AndNot
        // The inputs have been inverted by instruction selector, so we can call
        // andnps here without any modifications.
        ASSEMBLE_SIMD256_BINOP(andnps, AVX);
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64I8x16Swizzle: {
      __ I8x16Swizzle(i.OutputSimd128Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchDoubleReg,
                      kScratchRegister, MiscField::decode(instr->opcode()));
      break;
    }
    case kX64Vpshufd: {
      if (instr->InputCount() == 2 && instr->InputAt(1)->IsImmediate()) {
        YMMRegister dst = i.OutputSimd256Register();
        YMMRegister src = i.InputSimd256Register(0);
        uint8_t imm = i.InputUint8(1);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpshufd(dst, src, imm);
      } else {
        UNIMPLEMENTED();
      }
      break;
    }
    case kX64I8x16Shuffle: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister tmp_simd = i.TempSimd128Register(0);
      DCHECK_NE(tmp_simd, i.InputSimd128Register(0));
      if (instr->InputCount() == 5) {  // only one input operand
        uint32_t mask[4] = {};
        DCHECK_EQ(i.OutputSimd128Register(), i.InputSimd128Register(0));
        for (int j = 4; j > 0; j--) {
          mask[j - 1] = i.InputUint32(j);
        }

        SetupSimdImmediateInRegister(masm(), mask, tmp_simd);
        __ Pshufb(dst, tmp_simd);
      } else {  // two input operands
        DCHECK_NE(tmp_simd, i.InputSimd128Register(1));
        DCHECK_EQ(6, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 0);
        uint32_t mask1[4] = {};
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask1[j - 2] |= (lane < kSimd128Size ? lane : 0x80) << k;
          }
        }
        SetupSimdImmediateInRegister(masm(), mask1, tmp_simd);
        __ Pshufb(kScratchDoubleReg, tmp_simd);
        uint32_t mask2[4] = {};
        if (instr->InputAt(1)->IsSimd128Register()) {
          XMMRegister src1 = i.InputSimd128Register(1);
          if (src1 != dst) __ Movdqa(dst, src1);
        } else {
          __ Movdqu(dst, i.InputOperand(1));
        }
        for (int j = 5; j > 1; j--) {
          uint32_t lanes = i.InputUint32(j);
          for (int k = 0; k < 32; k += 8) {
            uint8_t lane = lanes >> k;
            mask2[j - 2] |= (lane >= kSimd128Size ? (lane & 0x0F) : 0x80) << k;
          }
        }
        SetupSimdImmediateInRegister(masm(), mask2, tmp_simd);
        __ Pshufb(dst, tmp_simd);
        __ Por(dst, kScratchDoubleReg);
      }
      break;
    }
    case kX64I8x16Popcnt: {
      __ I8x16Popcnt(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     i.TempSimd128Register(0), kScratchDoubleReg,
                     kScratchRegister);
      break;
    }
    case kX64S128Load8Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load8Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                        kScratchDoubleReg);
      break;
    }
    case kX64S128Load16Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load16Splat(i.OutputSimd128Register(), i.MemoryOperand(),
                         kScratchDoubleReg);
      break;
    }
    case kX64S128Load32Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ S128Load32Splat(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load64Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Movddup(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load8x8S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load8x8U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxbw(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load16x4S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load16x4U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxwd(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load32x2S: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovsxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Load32x2U: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Pmovzxdq(i.OutputSimd128Register(), i.MemoryOperand());
      break;
    }
    case kX64S128Store32Lane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      uint8_t lane = i.InputUint8(index + 1);
      __ S128Store32Lane(operand, i.InputSimd128Register(index), lane);
      break;
    }
    case kX64S128Store64Lane: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      uint8_t lane = i.InputUint8(index + 1);
      __ S128Store64Lane(operand, i.InputSimd128Register(index), lane);
      break;
    }
    case kX64Shufps: {
      if (instr->Output()->IsSimd128Register()) {
        __ Shufps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                  i.InputSimd128Register(1), i.InputUint8(2));
      } else {
        DCHECK(instr->Output()->IsSimd256Register());
        DCHECK(CpuFeatures::IsSupported(AVX));
        CpuFeatureScope scope(masm(), AVX);
        __ vshufps(i.OutputSimd256Register(), i.InputSimd256Register(0),
                   i.InputSimd256Register(1), i.InputUint8(2));
      }
      break;
    }
    case kX64S32x4Rotate: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src = i.InputSimd128Register(0);
      uint8_t mask = i.InputUint8(1);
      if (dst == src) {
        // 1-byte shorter encoding than pshufd.
        __ Shufps(dst, src, src, mask);
      } else {
        __ Pshufd(dst, src, mask);
      }
      break;
    }
    case kX64S32x4Swizzle: {
      DCHECK_EQ(2, instr->InputCount());
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, i.OutputSimd128Register(), 0,
                              i.InputUint8(1));
      break;
    }
    case kX64S32x4Shuffle: {
      DCHECK_EQ(4, instr->InputCount());  // Swizzles should be handled above.
      uint8_t shuffle = i.InputUint8(2);
      DCHECK_NE(0xe4, shuffle);  // A simple blend should be handled below.
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, kScratchDoubleReg, 1, shuffle);
      ASSEMBLE_SIMD_IMM_INSTR(Pshufd, i.OutputSimd128Register(), 0, shuffle);
      __ Pblendw(i.OutputSimd128Register(), kScratchDoubleReg, i.InputUint8(3));
      break;
    }
    case kX64S16x8Blend: {
      ASSEMBLE_SIMD_IMM_SHUFFLE(pblendw, i.InputUint8(2));
      break;
    }
    case kX64S16x8HalfShuffle1: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t mask_lo = i.InputUint8(1);
      uint8_t mask_hi = i.InputUint8(2);
      if (mask_lo != 0xe4) {
        ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, mask_lo);
        if (mask_hi != 0xe4) __ Pshufhw(dst, dst, mask_hi);
      } else {
        DCHECK_NE(mask_hi, 0xe4);
        ASSEMBLE_SIMD_IMM_INSTR(Pshufhw, dst, 0, mask_hi);
      }
      break;
    }
    case kX64S16x8HalfShuffle2: {
      XMMRegister dst = i.OutputSimd128Register();
      ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, kScratchDoubleReg, 1, i.InputUint8(2));
      __ Pshufhw(kScratchDoubleReg, kScratchDoubleReg, i.InputUint8(3));
      ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, i.InputUint8(2));
      __ Pshufhw(dst, dst, i.InputUint8(3));
      __ Pblendw(dst, kScratchDoubleReg, i.InputUint8(4));
      break;
    }
    case kX64S8x16Alignr: {
      ASSEMBLE_SIMD_IMM_SHUFFLE(palignr, i.InputUint8(2));
      break;
    }
    case kX64S16x8Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t lane = i.InputInt8(1) & 0x7;
      uint8_t lane4 = lane & 0x3;
      uint8_t half_dup = lane4 | (lane4 << 2) | (lane4 << 4) | (lane4 << 6);
      if (lane < 4) {
        ASSEMBLE_SIMD_IMM_INSTR(Pshuflw, dst, 0, half_dup);
        __ Punpcklqdq(dst, dst);
      } else {
        ASSEMBLE_SIMD_IMM_INSTR(Pshufhw, dst, 0, half_dup);
        __ Punpckhqdq(dst, dst);
      }
      break;
    }
    case kX64S8x16Dup: {
      XMMRegister dst = i.OutputSimd128Register();
      uint8_t lane = i.InputInt8(1) & 0xf;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (lane < 8) {
        __ Punpcklbw(dst, dst);
      } else {
        __ Punpckhbw(dst, dst);
      }
      lane &= 0x7;
      uint8_t lane4 = lane & 0x3;
      uint8_t half_dup = lane4 | (lane4 << 2) | (lane4 << 4) | (lane4 << 6);
      if (lane < 4) {
        __ Pshuflw(dst, dst, half_dup);
        __ Punpcklqdq(dst, dst);
      } else {
        __ Pshufhw(dst, dst, half_dup);
        __ Punpckhqdq(dst, dst);
      }
      break;
    }
    case kX64S64x2UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhqdq);
      break;
    case kX64S32x4UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhdq);
      break;
    case kX64S32x8UnpackHigh: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpunpckhdq(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64S16x8UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhwd);
      break;
    case kX64S8x16UnpackHigh:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckhbw);
      break;
    case kX64S64x2UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklqdq);
      break;
    case kX64S32x4UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpckldq);
      break;
    case kX64S32x8UnpackLow: {
      CpuFeatureScope avx2_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpunpckldq(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64S16x8UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklwd);
      break;
    case kX64S8x16UnpackLow:
      ASSEMBLE_SIMD_PUNPCK_SHUFFLE(punpcklbw);
      break;
    case kX64S16x8UnzipHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrld(kScratchDoubleReg, uint8_t{16});
        src2 = kScratchDoubleReg;
      }
      __ Psrld(dst, uint8_t{16});
      __ Packusdw(dst, src2);
      break;
    }
    case kX64S16x8UnzipLow: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Pxor(kScratchDoubleReg, kScratchDoubleReg);
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_IMM_INSTR(Pblendw, kScratchDoubleReg, 1, uint8_t{0x55});
        src2 = kScratchDoubleReg;
      }
      __ Pblendw(dst, kScratchDoubleReg, uint8_t{0xaa});
      __ Packusdw(dst, src2);
      break;
    }
    case kX64S8x16UnzipHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
        src2 = kScratchDoubleReg;
      }
      __ Psrlw(dst, uint8_t{8});
      __ Packuswb(dst, src2);
      break;
    }
    case kX64S8x16UnzipLow: {
      XMMRegister dst = i.OutputSimd128Register();
      XMMRegister src2 = dst;
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (instr->InputCount() == 2) {
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psllw(kScratchDoubleReg, uint8_t{8});
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
        src2 = kScratchDoubleReg;
      }
      __ Psllw(dst, uint8_t{8});
      __ Psrlw(dst, uint8_t{8});
      __ Packuswb(dst, src2);
      break;
    }
    case kX64S8x16TransposeLow: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Psllw(dst, uint8_t{8});
      if (instr->InputCount() == 1) {
        __ Movdqa(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psllw(kScratchDoubleReg, uint8_t{8});
      }
      __ Psrlw(dst, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64S8x16TransposeHigh: {
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      __ Psrlw(dst, uint8_t{8});
      if (instr->InputCount() == 1) {
        __ Movdqa(kScratchDoubleReg, dst);
      } else {
        DCHECK_EQ(2, instr->InputCount());
        ASSEMBLE_SIMD_INSTR(Movdqu, kScratchDoubleReg, 1);
        __ Psrlw(kScratchDoubleReg, uint8_t{8});
      }
      __ Psllw(kScratchDoubleReg, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64S8x8Reverse:
    case kX64S8x4Reverse:
    case kX64S8x2Reverse: {
      DCHECK_EQ(1, instr->InputCount());
      XMMRegister dst = i.OutputSimd128Register();
      DCHECK_EQ(dst, i.InputSimd128Register(0));
      if (arch_opcode != kX64S8x2Reverse) {
        // First shuffle words into position.
        uint8_t shuffle_mask = arch_opcode == kX64S8x4Reverse ? 0xB1 : 0x1B;
        __ Pshuflw(dst, dst, shuffle_mask);
        __ Pshufhw(dst, dst, shuffle_mask);
      }
      __ Movdqa(kScratchDoubleReg, dst);
      __ Psrlw(kScratchDoubleReg, uint8_t{8});
      __ Psllw(dst, uint8_t{8});
      __ Por(dst, kScratchDoubleReg);
      break;
    }
    case kX64V128AnyTrue: {
      Register dst = i.OutputRegister();
      XMMRegister src = i.InputSimd128Register(0);

      __ xorq(dst, dst);
      __ Ptest(src, src);
      __ setcc(not_equal, dst);
      break;
    }
    // Need to split up all the different lane structures because the
    // comparison instruction used matters, e.g. given 0xff00, pcmpeqb returns
    // 0x0011, pcmpeqw returns 0x0000, ptest will set ZF to 0 and 1
    // respectively.
    case kX64IAllTrue: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL8: {
            // I8x16AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqb);
            break;
          }
          case kL16: {
            // I16x8AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqw);
            break;
          }
          case kL32: {
            // I32x4AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqd);
            break;
          }
          case kL64: {
            // I64x2AllTrue
            ASSEMBLE_SIMD_ALL_TRUE(Pcmpeqq);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Blendvpd: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Blendvpd(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vblendvpd(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64Blendvps: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Blendvps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vblendvps(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64Pblendvb: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Pblendvb(i.OutputSimd128Register(), i.InputSimd128Register(0),
                    i.InputSimd128Register(1), i.InputSimd128Register(2));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX2);
        __ vpblendvb(i.OutputSimd256Register(), i.InputSimd256Register(0),
                     i.InputSimd256Register(1), i.InputSimd256Register(2));
      }
      break;
    }
    case kX64I32x4TruncF64x2UZero: {
      __ I32x4TruncSatF64x2UZero(i.OutputSimd128Register(),
                                 i.InputSimd128Register(0), kScratchDoubleReg,
                                 kScratchRegister);
      break;
    }
    case kX64I32x4TruncF32x4U: {
      __ I32x4TruncF32x4U(i.OutputSimd128Register(), i.InputSimd128Register(0),
                          kScratchDoubleReg, i.TempSimd128Register(0));
      break;
    }
    case kX64I32x8TruncF32x8U: {
      __ I32x8TruncF32x8U(i.OutputSimd256Register(), i.InputSimd256Register(0),
                          kScratchSimd256Reg, i.TempSimd256Register(0));
      break;
    }
    case kX64Cvttps2dq: {
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        __ Cvttps2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      } else {
        DCHECK_EQ(vec_len, kV256);
        CpuFeatureScope avx_scope(masm(), AVX);
        __ vcvttps2dq(i.OutputSimd256Register(), i.InputSimd256Register(0));
      }
      break;
    }
    case kX64Cvttpd2dq: {
      __ Cvttpd2dq(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kAtomicStoreWord8: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord8);
      break;
    }
    case kAtomicStoreWord16: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord16);
      break;
    }
    case kAtomicStoreWord32: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord32);
      break;
    }
    case kX64Word64AtomicStoreWord64: {
      ASSEMBLE_SEQ_CST_STORE(MachineRepresentation::kWord64);
      break;
    }
    case kAtomicExchangeInt8: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgb(i.InputRegister(0), i.MemoryOperand(1));
      __ movsxbl(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint8: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgb(i.InputRegister(0), i.MemoryOperand(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxbl(i.InputRegister(0), i.InputRegister(0));
          break;
        case AtomicWidth::kWord64:
          __ movzxbq(i.InputRegister(0), i.InputRegister(0));
          break;
      }
      break;
    }
    case kAtomicExchangeInt16: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgw(i.InputRegister(0), i.MemoryOperand(1));
      __ movsxwl(i.InputRegister(0), i.InputRegister(0));
      break;
    }
    case kAtomicExchangeUint16: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgw(i.InputRegister(0), i.MemoryOperand(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxwl(i.InputRegister(0), i.InputRegister(0));
          break;
        case AtomicWidth::kWord64:
          __ movzxwq(i.InputRegister(0), i.InputRegister(0));
          break;
      }
      break;
    }
    case kAtomicExchangeWord32: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgl(i.InputRegister(0), i.MemoryOperand(1));
      break;
    }
    case kAtomicCompareExchangeInt8: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgb(i.MemoryOperand(2), i.InputRegister(1));
      __ movsxbl(rax, rax);
      break;
    }
    case kAtomicCompareExchangeUint8: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgb(i.MemoryOperand(2), i.InputRegister(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxbl(rax, rax);
          break;
        case AtomicWidth::kWord64:
          __ movzxbq(rax, rax);
          break;
      }
      break;
    }
    case kAtomicCompareExchangeInt16: {
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgw(i.MemoryOperand(2), i.InputRegister(1));
      __ movsxwl(rax, rax);
      break;
    }
    case kAtomicCompareExchangeUint16: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgw(i.MemoryOperand(2), i.InputRegister(1));
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ movzxwl(rax, rax);
          break;
        case AtomicWidth::kWord64:
          __ movzxwq(rax, rax);
          break;
      }
      break;
    }
    case kAtomicCompareExchangeWord32: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgl(i.MemoryOperand(2), i.InputRegister(1));
      if (AtomicWidthField::decode(opcode) == AtomicWidth::kWord64) {
        // Zero-extend the 32 bit value to 64 bit.
        __ movl(rax, rax);
      }
      break;
    }
    case kX64Word64AtomicExchangeUint64: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ xchgq(i.InputRegister(0), i.MemoryOperand(1));
      break;
    }
    case kX64Word64AtomicCompareExchangeUint64: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ lock();
      __ cmpxchgq(i.MemoryOperand(2), i.InputRegister(1));
      break;
    }
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP(inst32, movb, cmpxchgb);                     \
    __ movsxbl(rax, rax);                                              \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movb, cmpxchgb);                 \
        __ movzxbl(rax, rax);                                          \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movb, cmpxchgb);               \
        __ movzxbq(rax, rax);                                          \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP(inst32, movw, cmpxchgw);                     \
    __ movsxwl(rax, rax);                                              \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movw, cmpxchgw);                 \
        __ movzxwl(rax, rax);                                          \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movw, cmpxchgw);               \
        __ movzxwq(rax, rax);                                          \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Word32:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP(inst32, movl, cmpxchgl);                 \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC64_BINOP(inst64, movl, cmpxchgl);               \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kX64Word64Atomic##op##Uint64:                                   \
    ASSEMBLE_ATOMIC64_BINOP(inst64, movq, cmpxchgq);                   \
    break;
      ATOMIC_BINOP_CASE(Add, addl, addq)
      ATOMIC_BINOP_CASE(Sub, subl, subq)
      ATOMIC_BINOP_CASE(And, andl, andq)
      ATOMIC_BINOP_CASE(Or, orl, orq)
      ATOMIC_BINOP_CASE(Xor, xorl, xorq)
#undef ATOMIC_BINOP_CASE

    case kAtomicLoadInt8:
    case kAtomicLoadUint8:
    case kAtomicLoadInt16:
    case kAtomicLoadUint16:
    case kAtomicLoadWord32:
      UNREACHABLE();  // Won't be generated by instruction selector.

    case kX64I32x8DotI16x16S: {
      ASSEMBLE_SIMD256_BINOP(pmaddwd, AVX2);
      break;
    }
    case kX64S256Load8Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpbroadcastb(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx2_scope(masm(), AVX2);
      __ vpbroadcastw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vbroadcastss(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load64Splat: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      __ vbroadcastsd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64Movdqu256: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      CpuFeatureScope avx_scope(masm(), AVX);
      if (instr->HasOutput()) {
        __ vmovdqu(i.OutputSimd256Register(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ vmovdqu(operand, i.InputSimd256Register(index));
      }
      break;
    }
    case kX64I16x16SConvertI32x8: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackssdw(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I16x16UConvertI32x8: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackusdw(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I8x32SConvertI16x16: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpacksswb(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I8x32UConvertI16x16: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      YMMRegister dst = i.OutputSimd256Register();
      __ vpackuswb(dst, i.InputSimd256Register(0), i.InputSimd256Register(1));
      break;
    }
    case kX64I64x4ExtMulI32x4S: {
      __ I64x4ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/true);
      break;
    }
    case kX64I64x4ExtMulI32x4U: {
      __ I64x4ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/false);
      break;
    }
    case kX64I32x8ExtMulI16x8S: {
      __ I32x8ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/true);
      break;
    }
    case kX64I32x8ExtMulI16x8U: {
      __ I32x8ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                     i.InputSimd128Register(1), kScratchSimd256Reg,
                     /*is_signed=*/false);
      break;
    }
    case kX64I16x16ExtMulI8x16S: {
      __ I16x16ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchSimd256Reg,
                      /*is_signed=*/true);
      break;
    }
    case kX64I16x16ExtMulI8x16U: {
      __ I16x16ExtMul(i.OutputSimd256Register(), i.InputSimd128Register(0),
                      i.InputSimd128Register(1), kScratchSimd256Reg,
                      /*is_signed=*/false);
      break;
    }
    case kX64S256Load8x16S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxbw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load8x16U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxbw(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load8x8U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxbd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16x8S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxwd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load16x8U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxwd(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32x4S: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovsxdq(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Load32x4U: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ vpmovzxdq(i.OutputSimd256Register(), i.MemoryOperand());
      break;
    }
    case kX64S256Const: {
      // Emit code for generic constants as all zeros, or ones cases will be
      // handled separately by the selector.
      YMMRegister dst = i.OutputSimd256Register();
      uint32_t imm[8] = {};
      for (int j = 0; j < 8; j++) {
        imm[j] = i.InputUint32(j);
      }
      SetupSimd256ImmediateInRegister(masm(), imm, dst, kScratchDoubleReg);
      break;
    }
    case kX64ExtractF128: {
      CpuFeatureScope avx_scope(masm(), AVX);
      uint8_t lane = i.InputInt8(1);
      __ vextractf128(i.OutputSimd128Register(), i.InputSimd256Register(0),
                      lane);
      break;
    }
    case kX64InsertI128: {
      CpuFeatureScope avx_scope(masm(), AVX2);
      uint8_t imm = i.InputInt8(2);
      InstructionOperand* input0 = instr->InputAt(0);
      if (input0->IsSimd128Register()) {
        __ vinserti128(i.OutputSimd256Register(),
                       YMMRegister::from_xmm(i.InputSimd128Register(0)),
                       i.InputSimd128Register(1), imm);
      } else {
        DCHECK(instr->InputAt(0)->IsSimd256Register());
        __ vinserti128(i.OutputSimd256Register(), i.InputSimd256Register(0),
                       i.InputSimd128Register(1), imm);
      }
      break;
    }
  }
  return kSuccess;
}  // NOLadability/fn_size)

#undef ASSEMBLE_PINSR
#undef ASSEMBLE_UNOP
#undef ASSEMBLE_BINOP
#undef ASSEMBLE_COMPARE
#undef ASSEMBLE_MULT
#undef ASSEMBLE_SHIFT
#undef ASSEMBLE_MOVX
#undef ASSEMBLE_SSE_BINOP
#undef ASSEMBLE_SSE_UNOP
#undef ASSEMBLE_AVX_BINOP
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC64_BINOP
#undef ASSEMBLE_SIMD_INSTR
#undef ASSEMBLE_SIMD_IMM_INSTR
#undef ASSEMBLE_SIMD_PUNPCK_SHUFFLE
#undef ASSEMBLE_SIMD_IMM_SHUFFLE
#undef ASSEMBLE_SIMD_ALL_TRUE
#undef ASSEMBLE_SIMD_SHIFT
#undef ASSEMBLE_SEQ_CST_STORE

namespace {

constexpr Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kUnorderedEqual:
    case kEqual:
      return equal;
    case kUnorderedNotEqual:
    case kNotEqual:
      return not_equal;
    case kSignedLessThan:
      return less;
    case kSignedGreaterThanOrEqual:
      return greater_equal;
    case kSignedLessThanOrEqual:
      return less_equal;
    case kSignedGreaterThan:
      return greater;
    case kUnsignedLessThan:
      return below;
    case kUnsignedGreaterThanOrEqual:
      return above_equal;
    case kUnsignedLessThanOrEqual:
      return below_equal;
    case kUnsignedGreaterThan:
      return above;
    case kOverflow:
      return overflow;
    case kNotOverflow:
      return no_overflow;
    case kIsNaN:
      return parity_even;
    case kIsNotNaN:
      return parity_odd;
    default:
      break;
  }
  UNREACHABLE();
}

}  // namespace

// Assembl
```