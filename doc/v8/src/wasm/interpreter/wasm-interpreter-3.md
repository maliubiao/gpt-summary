Response: The user wants a summary of the C++ code in the file `v8/src/wasm/interpreter/wasm-interpreter.cc`. This is part 4 of 8, which likely means it continues the implementation of the WebAssembly interpreter. The code seems to be handling various WebAssembly instructions, especially those related to SIMD (Single Instruction Multiple Data) and GC (Garbage Collection).

Here's a breakdown of the code snippets:

1. **SIMD Store:** The first function stores a `Simd128` value to memory. It performs bounds checking and writes the value unaligned.
2. **SIMD Shift Operations:** The `SHIFT_CASE` macro defines handlers for various SIMD shift instructions (left shift, signed right shift, unsigned right shift) for different data types (i64x2, i32x4, i16x8, i8x16). These instructions shift the bits of each lane in the SIMD vector by a specified amount.
3. **SIMD Extended Multiply:** The `SHIFT_CASE` macro defines handlers for extended multiplication operations. These take two SIMD vectors, multiply corresponding narrow elements, and store the wider result in a new SIMD vector. There are variants for signed and unsigned integers, and for low and high parts of the result.
4. **SIMD Convert Operations:** The `CONVERT_CASE` macro defines handlers for converting between different SIMD types (e.g., i32x4 to f32x4, f64x2 to i32x4). These conversions might involve saturation or truncation.
5. **SIMD Pack Operations:** The `PACK_CASE` macro defines handlers for packing elements from two wider SIMD vectors into a narrower SIMD vector with saturation.
6. **SIMD Select:** The `s2s_DoSimdSelect` function implements the `select` instruction, which chooses elements from two SIMD vectors based on a boolean mask.
7. **SIMD Dot Product:** Functions like `s2s_SimdI32x4DotI16x8S` and `s2s_SimdI16x8DotI8x16I7x16S` calculate the dot product of elements in two SIMD vectors.
8. **SIMD Swizzle and Shuffle:** `s2s_SimdI8x16Swizzle` rearranges the bytes in a SIMD vector based on an index vector. `s2s_SimdI8x16Shuffle` combines elements from two SIMD vectors based on an index vector.
9. **SIMD Any/All True:** `s2s_SimdV128AnyTrue` checks if any lane in a SIMD vector is true. The `REDUCTION_CASE` macro defines handlers for checking if all lanes in a SIMD vector are true.
10. **SIMD Fused Multiply-Add/Subtract:** The `QFM_CASE` macro defines handlers for fused multiply-add and multiply-subtract operations on SIMD floating-point vectors.
11. **SIMD Load Splat:** The `s2s_DoSimdLoadSplat` function loads a single scalar value from memory and replicates it across all lanes of a SIMD vector.
12. **SIMD Load Extend:** The `s2s_DoSimdLoadExtend` function loads a smaller scalar value from memory and extends it to a wider type in a SIMD vector.
13. **SIMD Load Zero Extend:** The `s2s_DoSimdLoadZeroExtend` function loads a scalar value and places it in the first lane of a SIMD vector, with the other lanes set to zero.
14. **SIMD Load/Store Lane:**  `s2s_DoSimdLoadLane` loads a single element from memory into a specific lane of a SIMD vector. `s2s_DoSimdStoreLane` stores a specific lane of a SIMD vector to memory.
15. **SIMD Extended Add Pairwise:** The `s2s_DoSimdExtAddPairwise` function adds adjacent pairs of elements in a SIMD vector and stores the wider results in a new SIMD vector.
16. **Exception Handling:** `s2s_Throw` and `s2s_Rethrow` handle throwing and re-throwing exceptions in the interpreter.
17. **GC Branching:** Functions like `s2s_BranchOnNull`, `s2s_BranchOnNonNull`, `s2s_BranchOnCast`, and `s2s_BranchOnCastFail` implement conditional branching based on the nullness or type of references.
18. **GC CallRef and ReturnCallRef:** These functions handle indirect function calls through references.
19. **GC Struct Operations:** Functions like `s2s_StructNew`, `s2s_StructNewDefault`, `s2s_StructGet`, `s2s_StructSet`, and `s2s_RefStructSet` implement operations for creating, reading, and writing fields of struct objects.
20. **GC Array Operations:** Functions like `s2s_ArrayNew`, `s2s_ArrayNewFixed`, `s2s_ArrayNewDefault`, `s2s_ArrayNewSegment`, `s2s_ArrayInitSegment`, `s2s_ArrayLen`, `s2s_ArrayCopy`, `s2s_ArrayGet`, `s2s_ArraySet`, and `s2s_ArrayFill` implement operations for creating, initializing, accessing, and modifying array objects.
21. **GC RefI31:**  The last function `s2s_RefI31` seems to be related to creating a reference to a 31-bit integer.

The code heavily uses macros to generate similar instruction handlers for different data types, which is a common practice in interpreters for performance and code conciseness.
This C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc` (part 4 of 8) primarily focuses on implementing **WebAssembly instructions related to SIMD (Single Instruction, Multiple Data) operations and Garbage Collection (GC)**.

Here's a breakdown of the functionalities:

**1. SIMD Operations:**

* **Storing SIMD values to memory:** The code includes a function to write a 128-bit SIMD value to a specified memory location, ensuring it stays within bounds.
* **Bitwise Shift Operations:** It implements various shift instructions (left shift, signed right shift, unsigned right shift) for different SIMD vector types (e.g., 64-bit integers x 2, 32-bit integers x 4, etc.). These operations shift the bits of each element within the SIMD vector.
* **Extended Multiplication:**  It provides functions for performing widening multiplication. For example, multiplying pairs of 8-bit integers to get 16-bit results, or 16-bit integers to get 32-bit results, storing them in a larger SIMD vector. It handles both signed and unsigned extensions.
* **Type Conversions:**  The code implements conversions between different SIMD types, like converting a vector of 32-bit integers to a vector of single-precision floats, or vice-versa. These conversions might involve saturation (clamping values within a range) or truncation.
* **Packing:** It includes instructions to pack elements from two larger SIMD vectors into a smaller one, potentially with saturation.
* **Selection (Conditional Lane Selection):**  A `select` operation is implemented, where elements from two SIMD vectors are chosen based on a boolean mask.
* **Dot Product:** Functions are defined to calculate the dot product of integer SIMD vectors.
* **Swizzle and Shuffle:** These instructions allow for rearranging the elements within a SIMD vector (`swizzle`) or combining elements from two SIMD vectors into a new one based on an index vector (`shuffle`).
* **Any True / All True:**  Functions check if any or all elements in a SIMD vector are considered "true" (non-zero).
* **Fused Multiply-Add/Subtract (QFM):**  It implements fused multiply-add and multiply-subtract operations for floating-point SIMD vectors, improving precision and performance.
* **Load Splat:**  Instructions to load a single scalar value from memory and replicate it across all lanes of a SIMD vector.
* **Load Extend:** Instructions to load a smaller integer value from memory and extend it (either by sign or zero) to a larger integer type within a SIMD vector.
* **Load Zero Extend:** Instructions to load a smaller integer value and place it in the lower lanes of a SIMD vector, filling the other lanes with zeros.
* **Load and Store Lane:** Instructions to load a single element from memory into a specific lane of a SIMD vector, or to store a specific lane of a SIMD vector to memory.
* **Extended Add Pairwise:** Instructions to add adjacent pairs of elements within a SIMD vector and store the results in a wider SIMD vector.

**2. Garbage Collection (GC) Operations:**

* **Exception Handling:** Functions to throw and re-throw exceptions within the Wasm interpreter.
* **Conditional Branching based on References:**
    * `BranchOnNull`: Branches if a reference is null.
    * `BranchOnNonNull`: Branches if a reference is not null.
    * `BranchOnCast`: Branches if a reference can be successfully cast to a specific type.
    * `BranchOnCastFail`: Branches if a reference cannot be cast to a specific type.
* **Indirect Function Calls (`CallRef`, `ReturnCallRef`):**  Functions to call functions indirectly through function references. `ReturnCallRef` likely handles tail calls.
* **Structure (Object) Operations:**
    * `StructNew`: Creates a new struct (object) of a given type, taking initial values from the stack.
    * `StructNewDefault`: Creates a new struct with default (zero or null) values for its fields.
    * `StructGet`: Reads a field from a struct.
    * `StructSet`: Writes a value to a field in a struct.
    * `RefStructSet`: Writes a reference value to a field in a struct.
* **Array Operations:**
    * `ArrayNew`: Creates a new array of a given type and size, initializing all elements with a given value.
    * `ArrayNewFixed`: Creates a new array and initializes its elements with values popped from the stack.
    * `ArrayNewDefault`: Creates a new array with default values for its elements.
    * `ArrayNewSegment`: Creates a new array by copying a segment from a data or element segment.
    * `ArrayInitSegment`: Initializes a portion of an array with data from a data or element segment.
    * `ArrayLen`: Gets the length of an array.
    * `ArrayCopy`: Copies a portion of one array to another.
    * `ArrayGet`: Reads an element from an array.
    * `ArraySet`: Writes a value to an element in an array.
    * `ArrayFill`: Fills a range of elements in an array with a specific value.
* **`RefI31`:**  Creates a reference to a 31-bit integer.

**Relationship to JavaScript:**

This C++ code is a low-level implementation of the WebAssembly virtual machine within the V8 JavaScript engine. When JavaScript code executes WebAssembly, the V8 engine uses this interpreter (or a more optimized compiler like TurboFan) to run the Wasm instructions.

**JavaScript Example (Illustrative):**

While you don't directly interact with these C++ functions in JavaScript, the **SIMD operations** have a direct counterpart in the JavaScript **WebAssembly SIMD API**.

```javascript
// Example of WebAssembly SIMD in JavaScript

const wasmCode = `
  (module
    (memory (export "memory") 1)
    (func (export "add_vectors") (param $a v128) (param $b v128) (result v128)
      local.get $a
      local.get $b
      i32x4.add  // WebAssembly instruction corresponding to a C++ function here
    )
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });
const { add_vectors, memory } = wasmInstance.exports;

// Create SIMD values (i32x4) in JavaScript
const vectorA = new Uint32Array([1, 2, 3, 4]);
const vectorB = new Uint32Array([5, 6, 7, 8]);
const simdA = SIMD.int32x4(...vectorA);
const simdB = SIMD.int32x4(...vectorB);

// Call the WebAssembly function from JavaScript
const resultSIMD = add_vectors(simdA, simdB);

// Extract the results back to a JavaScript array
const resultArray = [resultSIMD.x, resultSIMD.y, resultSIMD.z, resultSIMD.w];
console.log(resultArray); // Output: [6, 8, 10, 12]
```

In this JavaScript example, the `i32x4.add` instruction in the WebAssembly code would be handled by a corresponding C++ function (likely generated by a macro similar to the ones seen in the snippet) in the V8 interpreter. The JavaScript SIMD API provides a way to create and manipulate these SIMD values, which are then passed to the underlying WebAssembly code executed by V8.

Similarly, the **GC operations** in the C++ code are used when WebAssembly code interacts with JavaScript objects or creates its own managed objects. You don't directly call these C++ functions from JavaScript, but they are the underlying mechanisms that enable Wasm's memory management and interaction with the JavaScript environment.

**In summary, this part of the `wasm-interpreter.cc` file is crucial for executing SIMD instructions efficiently and managing memory (including objects and arrays) within the WebAssembly environment provided by the V8 JavaScript engine.**

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```
effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(Simd128),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  base::WriteUnalignedValue<Simd128>(reinterpret_cast<Address>(address), val);

  NextOp();
}

#define SHIFT_CASE(op, name, stype, count, expr)                              \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    uint32_t shift = pop<uint32_t>(sp, code, wasm_runtime);                   \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype res;                                                                \
    for (size_t i = 0; i < count; ++i) {                                      \
      auto a = s.val[LANE(i, s)];                                             \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
SHIFT_CASE(I64x2Shl, i64x2, int64x2, 2,
           static_cast<uint64_t>(a) << (shift % 64))
SHIFT_CASE(I64x2ShrS, i64x2, int64x2, 2, a >> (shift % 64))
SHIFT_CASE(I64x2ShrU, i64x2, int64x2, 2,
           static_cast<uint64_t>(a) >> (shift % 64))
SHIFT_CASE(I32x4Shl, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) << (shift % 32))
SHIFT_CASE(I32x4ShrS, i32x4, int32x4, 4, a >> (shift % 32))
SHIFT_CASE(I32x4ShrU, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) >> (shift % 32))
SHIFT_CASE(I16x8Shl, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) << (shift % 16))
SHIFT_CASE(I16x8ShrS, i16x8, int16x8, 8, a >> (shift % 16))
SHIFT_CASE(I16x8ShrU, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) >> (shift % 16))
SHIFT_CASE(I8x16Shl, i8x16, int8x16, 16, static_cast<uint8_t>(a) << (shift % 8))
SHIFT_CASE(I8x16ShrS, i8x16, int8x16, 16, a >> (shift % 8))
SHIFT_CASE(I8x16ShrU, i8x16, int8x16, 16,
           static_cast<uint8_t>(a) >> (shift % 8))
#undef SHIFT_CASE

template <typename s_type, typename d_type, typename narrow, typename wide,
          uint32_t start>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdExtMul(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  s_type s2 = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();
  s_type s1 = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();
  auto end = start + (kSimd128Size / sizeof(wide));
  d_type res;
  uint32_t i = start;
  for (size_t dst = 0; i < end; ++i, ++dst) {
    // Need static_cast for unsigned narrow types.
    res.val[LANE(dst, res)] =
        MultiplyLong<wide>(static_cast<narrow>(s1.val[LANE(start, s1)]),
                           static_cast<narrow>(s2.val[LANE(start, s2)]));
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
static auto s2s_SimdI16x8ExtMulLowI8x16S =
    s2s_DoSimdExtMul<int8x16, int16x8, int8_t, int16_t, 0>;
static auto s2s_SimdI16x8ExtMulHighI8x16S =
    s2s_DoSimdExtMul<int8x16, int16x8, int8_t, int16_t, 8>;
static auto s2s_SimdI16x8ExtMulLowI8x16U =
    s2s_DoSimdExtMul<int8x16, int16x8, uint8_t, uint16_t, 0>;
static auto s2s_SimdI16x8ExtMulHighI8x16U =
    s2s_DoSimdExtMul<int8x16, int16x8, uint8_t, uint16_t, 8>;
static auto s2s_SimdI32x4ExtMulLowI16x8S =
    s2s_DoSimdExtMul<int16x8, int32x4, int16_t, int32_t, 0>;
static auto s2s_SimdI32x4ExtMulHighI16x8S =
    s2s_DoSimdExtMul<int16x8, int32x4, int16_t, int32_t, 4>;
static auto s2s_SimdI32x4ExtMulLowI16x8U =
    s2s_DoSimdExtMul<int16x8, int32x4, uint16_t, uint32_t, 0>;
static auto s2s_SimdI32x4ExtMulHighI16x8U =
    s2s_DoSimdExtMul<int16x8, int32x4, uint16_t, uint32_t, 4>;
static auto s2s_SimdI64x2ExtMulLowI32x4S =
    s2s_DoSimdExtMul<int32x4, int64x2, int32_t, int64_t, 0>;
static auto s2s_SimdI64x2ExtMulHighI32x4S =
    s2s_DoSimdExtMul<int32x4, int64x2, int32_t, int64_t, 2>;
static auto s2s_SimdI64x2ExtMulLowI32x4U =
    s2s_DoSimdExtMul<int32x4, int64x2, uint32_t, uint64_t, 0>;
static auto s2s_SimdI64x2ExtMulHighI32x4U =
    s2s_DoSimdExtMul<int32x4, int64x2, uint32_t, uint64_t, 2>;
#undef EXT_MUL_CASE

#define CONVERT_CASE(op, src_type, name, dst_type, count, start_index, ctype, \
                     expr)                                                    \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    src_type s = pop<Simd128>(sp, code, wasm_runtime).to_##name();            \
    dst_type res = {0};                                                       \
    for (size_t i = 0; i < count; ++i) {                                      \
      ctype a = s.val[LANE(start_index + i, s)];                              \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
CONVERT_CASE(F32x4SConvertI32x4, int32x4, i32x4, float32x4, 4, 0, int32_t,
             static_cast<float>(a))
CONVERT_CASE(F32x4UConvertI32x4, int32x4, i32x4, float32x4, 4, 0, uint32_t,
             static_cast<float>(a))
CONVERT_CASE(I32x4SConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4UConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF32x4S, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF32x4U, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I64x2SConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0, int32_t, a)
CONVERT_CASE(I64x2SConvertI32x4High, int32x4, i32x4, int64x2, 2, 2, int32_t, a)
CONVERT_CASE(I64x2UConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0, uint32_t, a)
CONVERT_CASE(I64x2UConvertI32x4High, int32x4, i32x4, int64x2, 2, 2, uint32_t, a)
CONVERT_CASE(I32x4SConvertI16x8High, int16x8, i16x8, int32x4, 4, 4, int16_t, a)
CONVERT_CASE(I32x4UConvertI16x8High, int16x8, i16x8, int32x4, 4, 4, uint16_t, a)
CONVERT_CASE(I32x4SConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0, int16_t, a)
CONVERT_CASE(I32x4UConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0, uint16_t, a)
CONVERT_CASE(I16x8SConvertI8x16High, int8x16, i8x16, int16x8, 8, 8, int8_t, a)
CONVERT_CASE(I16x8UConvertI8x16High, int8x16, i8x16, int16x8, 8, 8, uint8_t, a)
CONVERT_CASE(I16x8SConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0, int8_t, a)
CONVERT_CASE(I16x8UConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0, uint8_t, a)
CONVERT_CASE(F64x2ConvertLowI32x4S, int32x4, i32x4, float64x2, 2, 0, int32_t,
             static_cast<double>(a))
CONVERT_CASE(F64x2ConvertLowI32x4U, int32x4, i32x4, float64x2, 2, 0, uint32_t,
             static_cast<double>(a))
CONVERT_CASE(I32x4TruncSatF64x2SZero, float64x2, f64x2, int32x4, 2, 0, double,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4TruncSatF64x2UZero, float64x2, f64x2, int32x4, 2, 0, double,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF64x2SZero, float64x2, f64x2, int32x4, 2, 0,
             double, base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF64x2UZero, float64x2, f64x2, int32x4, 2, 0,
             double, base::saturated_cast<uint32_t>(a))
CONVERT_CASE(F32x4DemoteF64x2Zero, float64x2, f64x2, float32x4, 2, 0, float,
             DoubleToFloat32(a))
CONVERT_CASE(F64x2PromoteLowF32x4, float32x4, f32x4, float64x2, 2, 0, float,
             static_cast<double>(a))
#undef CONVERT_CASE

#define PACK_CASE(op, src_type, name, dst_type, count, dst_ctype)             \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    src_type s2 = pop<Simd128>(sp, code, wasm_runtime).to_##name();           \
    src_type s1 = pop<Simd128>(sp, code, wasm_runtime).to_##name();           \
    dst_type res;                                                             \
    for (size_t i = 0; i < count; ++i) {                                      \
      int64_t v = i < count / 2 ? s1.val[LANE(i, s1)]                         \
                                : s2.val[LANE(i - count / 2, s2)];            \
      res.val[LANE(i, res)] = base::saturated_cast<dst_ctype>(v);             \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
PACK_CASE(I16x8SConvertI32x4, int32x4, i32x4, int16x8, 8, int16_t)
PACK_CASE(I16x8UConvertI32x4, int32x4, i32x4, int16x8, 8, uint16_t)
PACK_CASE(I8x16SConvertI16x8, int16x8, i16x8, int8x16, 16, int8_t)
PACK_CASE(I8x16UConvertI16x8, int16x8, i16x8, int8x16, 16, uint8_t)
#undef PACK_CASE

INSTRUCTION_HANDLER_FUNC s2s_DoSimdSelect(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  int32x4 bool_val = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 res;
  for (size_t i = 0; i < 4; ++i) {
    res.val[LANE(i, res)] =
        v2.val[LANE(i, v2)] ^ ((v1.val[LANE(i, v1)] ^ v2.val[LANE(i, v2)]) &
                               bool_val.val[LANE(i, bool_val)]);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
// Do these 5 instructions really have the same implementation?
static auto s2s_SimdI8x16RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI16x8RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI32x4RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI64x2RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdS128Select = s2s_DoSimdSelect;

INSTRUCTION_HANDLER_FUNC s2s_SimdI32x4DotI16x8S(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int16x8 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i16x8();
  int16x8 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i16x8();
  int32x4 res;
  for (size_t i = 0; i < 4; i++) {
    int32_t lo = (v1.val[LANE(i * 2, v1)] * v2.val[LANE(i * 2, v2)]);
    int32_t hi = (v1.val[LANE(i * 2 + 1, v1)] * v2.val[LANE(i * 2 + 1, v2)]);
    res.val[LANE(i, res)] = base::AddWithWraparound(lo, hi);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI16x8DotI8x16I7x16S(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int16x8 res;
  for (size_t i = 0; i < 8; i++) {
    int16_t lo = (v1.val[LANE(i * 2, v1)] * v2.val[LANE(i * 2, v2)]);
    int16_t hi = (v1.val[LANE(i * 2 + 1, v1)] * v2.val[LANE(i * 2 + 1, v2)]);
    res.val[LANE(i, res)] = base::AddWithWraparound(lo, hi);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI32x4DotI8x16I7x16AddS(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int32x4 v3 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int32x4 res;
  for (size_t i = 0; i < 4; i++) {
    int32_t a = (v1.val[LANE(i * 4, v1)] * v2.val[LANE(i * 4, v2)]);
    int32_t b = (v1.val[LANE(i * 4 + 1, v1)] * v2.val[LANE(i * 4 + 1, v2)]);
    int32_t c = (v1.val[LANE(i * 4 + 2, v1)] * v2.val[LANE(i * 4 + 2, v2)]);
    int32_t d = (v1.val[LANE(i * 4 + 3, v1)] * v2.val[LANE(i * 4 + 3, v2)]);
    int32_t acc = v3.val[LANE(i, v3)];
    // a + b + c + d should not wrap
    res.val[LANE(i, res)] = base::AddWithWraparound(a + b + c + d, acc);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI8x16Swizzle(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 res;
  for (size_t i = 0; i < kSimd128Size; ++i) {
    int lane = v2.val[LANE(i, v2)];
    res.val[LANE(i, res)] =
        lane < kSimd128Size && lane >= 0 ? v1.val[LANE(lane, v1)] : 0;
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
static auto s2s_SimdI8x16RelaxedSwizzle = s2s_SimdI8x16Swizzle;

INSTRUCTION_HANDLER_FUNC s2s_SimdI8x16Shuffle(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 value = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 res;
  for (size_t i = 0; i < kSimd128Size; ++i) {
    int lane = value.val[i];
    res.val[LANE(i, res)] = lane < kSimd128Size
                                ? v1.val[LANE(lane, v1)]
                                : v2.val[LANE(lane - kSimd128Size, v2)];
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdV128AnyTrue(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int32x4 s = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  bool res = s.val[LANE(0, s)] | s.val[LANE(1, s)] | s.val[LANE(2, s)] |
             s.val[LANE(3, s)];
  push<int32_t>(sp, code, wasm_runtime, res);
  NextOp();
}

#define REDUCTION_CASE(op, name, stype, count)                                \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    bool res = true;                                                          \
    for (size_t i = 0; i < count; ++i) {                                      \
      res = res & static_cast<bool>(s.val[LANE(i, s)]);                       \
    }                                                                         \
    push<int32_t>(sp, code, wasm_runtime, res);                               \
    NextOp();                                                                 \
  }
REDUCTION_CASE(I64x2AllTrue, i64x2, int64x2, 2)
REDUCTION_CASE(I32x4AllTrue, i32x4, int32x4, 4)
REDUCTION_CASE(I16x8AllTrue, i16x8, int16x8, 8)
REDUCTION_CASE(I8x16AllTrue, i8x16, int8x16, 16)
#undef REDUCTION_CASE

#define QFM_CASE(op, name, stype, count, operation)                           \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype c = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype b = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype a = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype res;                                                                \
    for (size_t i = 0; i < count; i++) {                                      \
      res.val[LANE(i, res)] =                                                 \
          operation(a.val[LANE(i, a)] * b.val[LANE(i, b)]) +                  \
          c.val[LANE(i, c)];                                                  \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
QFM_CASE(F32x4Qfma, f32x4, float32x4, 4, +)
QFM_CASE(F32x4Qfms, f32x4, float32x4, 4, -)
QFM_CASE(F64x2Qfma, f64x2, float64x2, 2, +)
QFM_CASE(F64x2Qfms, f64x2, float64x2, 2, -)
#undef QFM_CASE

template <typename s_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadSplat(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  load_type v =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  s_type s;
  for (size_t i = 0; i < arraysize(s.val); i++) {
    s.val[LANE(i, s)] = v;
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load8Splat = s2s_DoSimdLoadSplat<int8x16, int8_t>;
static auto s2s_SimdS128Load16Splat = s2s_DoSimdLoadSplat<int16x8, int16_t>;
static auto s2s_SimdS128Load32Splat = s2s_DoSimdLoadSplat<int32x4, int32_t>;
static auto s2s_SimdS128Load64Splat = s2s_DoSimdLoadSplat<int64x2, int64_t>;

template <typename s_type, typename wide_type, typename narrow_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadExtend(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  static_assert(sizeof(wide_type) == sizeof(narrow_type) * 2,
                "size mismatch for wide and narrow types");
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(uint64_t),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  uint64_t v =
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(address));
  constexpr int lanes = kSimd128Size / sizeof(wide_type);
  s_type s;
  for (int i = 0; i < lanes; i++) {
    uint8_t shift = i * (sizeof(narrow_type) * 8);
    narrow_type el = static_cast<narrow_type>(v >> shift);
    s.val[LANE(i, s)] = static_cast<wide_type>(el);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load8x8S =
    s2s_DoSimdLoadExtend<int16x8, int16_t, int8_t>;
static auto s2s_SimdS128Load8x8U =
    s2s_DoSimdLoadExtend<int16x8, uint16_t, uint8_t>;
static auto s2s_SimdS128Load16x4S =
    s2s_DoSimdLoadExtend<int32x4, int32_t, int16_t>;
static auto s2s_SimdS128Load16x4U =
    s2s_DoSimdLoadExtend<int32x4, uint32_t, uint16_t>;
static auto s2s_SimdS128Load32x2S =
    s2s_DoSimdLoadExtend<int64x2, int64_t, int32_t>;
static auto s2s_SimdS128Load32x2U =
    s2s_DoSimdLoadExtend<int64x2, uint64_t, uint32_t>;

template <typename s_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadZeroExtend(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  load_type v =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  s_type s;
  // All lanes are 0.
  for (size_t i = 0; i < arraysize(s.val); i++) {
    s.val[LANE(i, s)] = 0;
  }
  // Lane 0 is set to the loaded value.
  s.val[LANE(0, s)] = v;
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load32Zero =
    s2s_DoSimdLoadZeroExtend<int32x4, uint32_t>;
static auto s2s_SimdS128Load64Zero =
    s2s_DoSimdLoadZeroExtend<int64x2, uint64_t>;

template <typename s_type, typename result_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadLane(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  s_type value = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  result_type loaded =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  uint16_t lane = Read<uint16_t>(code);
  value.val[LANE(lane, value)] = loaded;
  push<Simd128>(sp, code, wasm_runtime, Simd128(value));

  NextOp();
}
static auto s2s_SimdS128Load8Lane =
    s2s_DoSimdLoadLane<int8x16, int32_t, int8_t>;
static auto s2s_SimdS128Load16Lane =
    s2s_DoSimdLoadLane<int16x8, int32_t, int16_t>;
static auto s2s_SimdS128Load32Lane =
    s2s_DoSimdLoadLane<int32x4, int32_t, int32_t>;
static auto s2s_SimdS128Load64Lane =
    s2s_DoSimdLoadLane<int64x2, int64_t, int64_t>;

template <typename s_type, typename result_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdStoreLane(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // Extract a single lane, push it onto the stack, then store the lane.
  s_type value = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }
  uint8_t* address = memory_start + effective_index;

  uint16_t lane = Read<uint16_t>(code);
  result_type res = value.val[LANE(lane, value)];
  base::WriteUnalignedValue<result_type>(reinterpret_cast<Address>(address),
                                         res);

  NextOp();
}
static auto s2s_SimdS128Store8Lane =
    s2s_DoSimdStoreLane<int8x16, int32_t, int8_t>;
static auto s2s_SimdS128Store16Lane =
    s2s_DoSimdStoreLane<int16x8, int32_t, int16_t>;
static auto s2s_SimdS128Store32Lane =
    s2s_DoSimdStoreLane<int32x4, int32_t, int32_t>;
static auto s2s_SimdS128Store64Lane =
    s2s_DoSimdStoreLane<int64x2, int64_t, int64_t>;

template <typename DstSimdType, typename SrcSimdType, typename Wide,
          typename Narrow>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdExtAddPairwise(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  constexpr int lanes = kSimd128Size / sizeof(DstSimdType::val[0]);
  auto v = pop<Simd128>(sp, code, wasm_runtime).to<SrcSimdType>();
  DstSimdType res;
  for (int i = 0; i < lanes; ++i) {
    res.val[LANE(i, res)] =
        AddLong<Wide>(static_cast<Narrow>(v.val[LANE(i * 2, v)]),
                      static_cast<Narrow>(v.val[LANE(i * 2 + 1, v)]));
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));

  NextOp();
}
static auto s2s_SimdI32x4ExtAddPairwiseI16x8S =
    s2s_DoSimdExtAddPairwise<int32x4, int16x8, int32_t, int16_t>;
static auto s2s_SimdI32x4ExtAddPairwiseI16x8U =
    s2s_DoSimdExtAddPairwise<int32x4, int16x8, uint32_t, uint16_t>;
static auto s2s_SimdI16x8ExtAddPairwiseI8x16S =
    s2s_DoSimdExtAddPairwise<int16x8, int8x16, int16_t, int8_t>;
static auto s2s_SimdI16x8ExtAddPairwiseI8x16U =
    s2s_DoSimdExtAddPairwise<int16x8, int8x16, uint16_t, uint8_t>;

////////////////////////////////////////////////////////////////////////////////

INSTRUCTION_HANDLER_FUNC s2s_Throw(const uint8_t* code, uint32_t* sp,
                                   WasmInterpreterRuntime* wasm_runtime,
                                   int64_t r0, double fp0) {
  uint32_t tag_index = ReadI32(code);

  // This will advance the code pointer.
  wasm_runtime->ThrowException(code, sp, tag_index);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Rethrow(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint32_t catch_block_index = ReadI32(code);
  wasm_runtime->RethrowException(code, sp, catch_block_index);

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// GC instruction handlers.

int StructFieldOffset(const StructType* struct_type, int field_index) {
  return wasm::ObjectAccess::ToTagged(WasmStruct::kHeaderSize +
                                      struct_type->field_offset(field_index));
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNull(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  // TODO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_null_offset = ReadI32(code);
  if (wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is true (ref is null), jump to the target branch.
    code += (if_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

/*
 * Notice that in s2s_BranchOnNullWithParams the branch happens when the
 * condition is false, not true, as follows:
 *
 *   > s2s_BranchOnNullWithParams
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if NOT NULL)  ----+
 *   > s2s_CopySlot                       |
 *       ....                             |
 *   > s2s_Branch (gets here if NULL)     |
 *       branch_offset                    |
 *   > (next instruction) <---------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnNullWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_null_offset = ReadI32(code);
  if (!wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is false (ref is not null), jump to the false branch.
    code += (if_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNonNull(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_non_null_offset = ReadI32(code);
  if (!wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is true (ref is not null), jump to the target branch.
    code += (if_non_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNonNullWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_non_null_offset = ReadI32(code);
  if (wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is false (ref is null), jump to the false branch.
    code += (if_non_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

bool DoRefCast(WasmRef ref, ValueType ref_type, HeapType target_type,
               bool null_succeeds, WasmInterpreterRuntime* wasm_runtime) {
  if (target_type.is_index()) {
    Handle<Map> rtt = wasm_runtime->RttCanon(target_type.ref_index());
    return wasm_runtime->SubtypeCheck(ref, ref_type, rtt,
                                      ValueType::Rtt(target_type.ref_index()),
                                      null_succeeds);
  } else {
    switch (target_type.representation()) {
      case HeapType::kEq:
        return wasm_runtime->RefIsEq(ref, ref_type, null_succeeds);
      case HeapType::kI31:
        return wasm_runtime->RefIsI31(ref, ref_type, null_succeeds);
      case HeapType::kStruct:
        return wasm_runtime->RefIsStruct(ref, ref_type, null_succeeds);
      case HeapType::kArray:
        return wasm_runtime->RefIsArray(ref, ref_type, null_succeeds);
      case HeapType::kString:
        return wasm_runtime->RefIsString(ref, ref_type, null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
        DCHECK(null_succeeds);
        return wasm_runtime->IsNullTypecheck(ref, ref_type);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }
}

/*
 * Notice that in s2s_BranchOnCast the branch happens when the condition is
 * false, not true, as follows:
 *
 *   > s2s_BranchOnCast
 *       i32: null_succeeds
 *       i32: target_type HeapType representation
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if CAST FAILS) --------+
 *   > s2s_CopySlot                            |
 *       ....                                  |
 *   > s2s_Branch (gets here if CAST SUCCEEDS) |
 *       branch_offset                         |
 *   > (next instruction) <--------------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnCast(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  bool null_succeeds = ReadI32(code);
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  push<WasmRef>(sp, code, wasm_runtime, ref);
  int32_t no_branch_offset = ReadI32(code);

  if (!DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime)) {
    // If condition is not true, jump to the 'false' branch.
    code += (no_branch_offset - kCodeOffsetSize);
  }

  NextOp();
}

/*
 * Notice that in s2s_BranchOnCastFail the branch happens when the condition is
 * false, not true, as follows:
 *
 *   > s2s_BranchOnCastFail
 *       i32: null_succeeds
 *       i32: target_type HeapType representation
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if CAST SUCCEEDS) --+
 *   > s2s_CopySlot                         |
 *       ....                               |
 *   > s2s_Branch (gets here if CAST FAILS) |
 *       branch_offset                      |
 *   > (next instruction) <-----------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnCastFail(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  bool null_succeeds = ReadI32(code);
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  push<WasmRef>(sp, code, wasm_runtime, ref);
  int32_t branch_offset = ReadI32(code);

  if (DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime)) {
    // If condition is true, jump to the 'true' branch.
    code += (branch_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CallRef(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  WasmRef func_ref = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(func_ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  // This can trap.
  wasm_runtime->ExecuteCallRef(code, func_ref, sig_index, stack_pos, sp,
                               ref_stack_fp_offset, slot_offset,
                               return_slot_offset, false);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ReturnCallRef(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  uint32_t rets_size = ReadI32(code);
  uint32_t args_size = ReadI32(code);
  uint32_t rets_refs = ReadI32(code);
  uint32_t args_refs = ReadI32(code);

  WasmRef func_ref = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(func_ref))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  // Moves back the stack frame to the caller stack frame.
  wasm_runtime->UnwindCurrentStackFrame(sp, slot_offset, rets_size, args_size,
                                        rets_refs, args_refs,
                                        ref_stack_fp_offset);

  // TODO(paolosev@microsoft.com) - This calls adds a new C++ stack frame, which
  // is not ideal in a tail-call.
  wasm_runtime->ExecuteCallRef(code, func_ref, sig_index, stack_pos, sp, 0, 0,
                               return_slot_offset, true);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_StructNew(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);
  std::pair<Handle<WasmStruct>, const StructType*> struct_new_result =
      wasm_runtime->StructNewUninitialized(index);
  Handle<Object> struct_obj = struct_new_result.first;
  const StructType* struct_type = struct_new_result.second;

  {
    // The new struct is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    for (uint32_t i = struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(struct_type, i);
      Address field_addr = (*struct_obj).ptr() + offset;

      ValueKind kind = struct_type->field(i).kind();
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(field_addr) =
              pop<int32_t>(sp, code, wasm_runtime);
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(
              field_addr, pop<int32_t>(sp, code, wasm_runtime));
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(
              field_addr, pop<int32_t>(sp, code, wasm_runtime));
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(
              field_addr, pop<int64_t>(sp, code, wasm_runtime));
          break;
        case kF32:
          base::WriteUnalignedValue<float>(field_addr,
                                           pop<float>(sp, code, wasm_runtime));
          break;
        case kF64:
          base::WriteUnalignedValue<double>(
              field_addr, pop<double>(sp, code, wasm_runtime));
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(
              field_addr, pop<Simd128>(sp, code, wasm_runtime));
          break;
        case kRef:
        case kRefNull: {
          WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
          base::WriteUnalignedValue<Tagged_t>(
              field_addr,
              V8HeapCompressionScheme::CompressObject((*ref).ptr()));
          break;
        }
        default:
          UNREACHABLE();
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, struct_obj);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_StructNewDefault(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);
  std::pair<Handle<WasmStruct>, const StructType*> struct_new_result =
      wasm_runtime->StructNewUninitialized(index);
  Handle<Object> struct_obj = struct_new_result.first;
  const StructType* struct_type = struct_new_result.second;

  {
    // The new struct is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    for (uint32_t i = struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(struct_type, i);
      Address field_addr = (*struct_obj).ptr() + offset;

      const ValueType value_type = struct_type->field(i);
      const ValueKind kind = value_type.kind();
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(field_addr) = int8_t{};
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(field_addr, int16_t{});
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(field_addr, int32_t{});
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(field_addr, int64_t{});
          break;
        case kF32:
          base::WriteUnalignedValue<float>(field_addr, float{});
          break;
        case kF64:
          base::WriteUnalignedValue<double>(field_addr, double{});
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(field_addr, Simd128{});
          break;
        case kRef:
        case kRefNull:
          base::WriteUnalignedValue<Tagged_t>(
              field_addr, static_cast<Tagged_t>(
                              wasm_runtime->GetNullValue(value_type).ptr()));
          break;
        default:
          UNREACHABLE();
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, struct_obj);

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StructGet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);

  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  int offset = ReadI32(code);
  Address field_addr = (*struct_obj).ptr() + offset;
  push<T>(sp, code, wasm_runtime, base::ReadUnalignedValue<U>(field_addr));

  NextOp();
}
static auto s2s_I8SStructGet = s2s_StructGet<int32_t, int8_t>;
static auto s2s_I8UStructGet = s2s_StructGet<uint32_t, uint8_t>;
static auto s2s_I16SStructGet = s2s_StructGet<int32_t, int16_t>;
static auto s2s_I16UStructGet = s2s_StructGet<uint32_t, uint16_t>;
static auto s2s_I32StructGet = s2s_StructGet<int32_t>;
static auto s2s_I64StructGet = s2s_StructGet<int64_t>;
static auto s2s_F32StructGet = s2s_StructGet<float>;
static auto s2s_F64StructGet = s2s_StructGet<double>;
static auto s2s_S128StructGet = s2s_StructGet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefStructGet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  int offset = ReadI32(code);
  Address field_addr = (*struct_obj).ptr() + offset;
  // DrumBrake expects pointer compression.
  Tagged_t ref_tagged = base::ReadUnalignedValue<uint32_t>(field_addr);
  Isolate* isolate = wasm_runtime->GetIsolate();
  Tagged<Object> ref_uncompressed(
      V8HeapCompressionScheme::DecompressTagged(isolate, ref_tagged));
  WasmRef ref_handle = handle(ref_uncompressed, isolate);
  push<WasmRef>(sp, code, wasm_runtime, ref_handle);

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_StructSet(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  int offset = ReadI32(code);
  T value = pop<T>(sp, code, wasm_runtime);
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  Address field_addr = (*struct_obj).ptr() + offset;
  base::WriteUnalignedValue<U>(field_addr, value);

  NextOp();
}
static auto s2s_I8StructSet = s2s_StructSet<int32_t, int8_t>;
static auto s2s_I16StructSet = s2s_StructSet<int32_t, int16_t>;
static auto s2s_I32StructSet = s2s_StructSet<int32_t>;
static auto s2s_I64StructSet = s2s_StructSet<int64_t>;
static auto s2s_F32StructSet = s2s_StructSet<float>;
static auto s2s_F64StructSet = s2s_StructSet<double>;
static auto s2s_S128StructSet = s2s_StructSet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefStructSet(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  int offset = ReadI32(code);
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef struct_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(struct_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  Address field_addr = (*struct_obj).ptr() + offset;
  base::WriteUnalignedValue<Tagged_t>(
      field_addr, V8HeapCompressionScheme::CompressObject((*ref).ptr()));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayNew(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);
  const T value = pop<T>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    const ArrayType* array_type = array_new_result.second;
    const ValueKind kind = array_type->element_type().kind();
    const uint32_t element_size = value_kind_size(kind);
    DCHECK_EQ(element_size, sizeof(U));

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      base::WriteUnalignedValue<U>(element_addr, value);
      element_addr += element_size;
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}
static auto s2s_I8ArrayNew = s2s_ArrayNew<int32_t, int8_t>;
static auto s2s_I16ArrayNew = s2s_ArrayNew<int32_t, int16_t>;
static auto s2s_I32ArrayNew = s2s_ArrayNew<int32_t>;
static auto s2s_I64ArrayNew = s2s_ArrayNew<int64_t>;
static auto s2s_F32ArrayNew = s2s_ArrayNew<float>;
static auto s2s_F64ArrayNew = s2s_ArrayNew<double>;
static auto s2s_S128ArrayNew = s2s_ArrayNew<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayNew(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);
  const WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

#if DEBUG
  const ArrayType* array_type = array_new_result.second;
  DCHECK_EQ(value_kind_size(array_type->element_type().kind()),
            sizeof(Tagged_t));
#endif

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      base::WriteUnalignedValue<Tagged_t>(
          element_addr,
          V8HeapCompressionScheme::CompressObject((*value).ptr()));
      element_addr += sizeof(Tagged_t);
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ArrayNewFixed(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = ReadI32(code);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    if (elem_count > 0) {
      const ArrayType* array_type = array_new_result.second;
      const ValueKind kind = array_type->element_type().kind();
      const uint32_t element_size = value_kind_size(kind);

      Address element_addr = array->ElementAddress(elem_count - 1);
      for (uint32_t i = 0; i < elem_count; i++) {
        switch (kind) {
          case kI8:
            *reinterpret_cast<int8_t*>(element_addr) =
                pop<int32_t>(sp, code, wasm_runtime);
            break;
          case kI16:
            base::WriteUnalignedValue<int16_t>(
                element_addr, pop<int32_t>(sp, code, wasm_runtime));
            break;
          case kI32:
            base::WriteUnalignedValue<int32_t>(
                element_addr, pop<int32_t>(sp, code, wasm_runtime));
            break;
          case kI64:
            base::WriteUnalignedValue<int64_t>(
                element_addr, pop<int64_t>(sp, code, wasm_runtime));
            break;
          case kF32:
            base::WriteUnalignedValue<float>(
                element_addr, pop<float>(sp, code, wasm_runtime));
            break;
          case kF64:
            base::WriteUnalignedValue<double>(
                element_addr, pop<double>(sp, code, wasm_runtime));
            break;
          case kS128:
            base::WriteUnalignedValue<Simd128>(
                element_addr, pop<Simd128>(sp, code, wasm_runtime));
            break;
          case kRef:
          case kRefNull: {
            WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
            base::WriteUnalignedValue<Tagged_t>(
                element_addr,
                V8HeapCompressionScheme::CompressObject((*ref).ptr()));
            break;
          }
          default:
            UNREACHABLE();
        }
        element_addr -= element_size;
      }
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC
s2s_ArrayNewDefault(const uint8_t* code, uint32_t* sp,
                    WasmInterpreterRuntime* wasm_runtime, int64_t r0,
                    double fp0) {
  const uint32_t array_index = ReadI32(code);
  const uint32_t elem_count = pop<int32_t>(sp, code, wasm_runtime);

  std::pair<Handle<WasmArray>, const ArrayType*> array_new_result =
      wasm_runtime->ArrayNewUninitialized(elem_count, array_index);
  Handle<WasmArray> array = array_new_result.first;
  if (V8_UNLIKELY(array.is_null())) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  {
    // The new array is uninitialized, which means GC might fail until
    // initialization.
    DisallowHeapAllocation no_gc;

    const ArrayType* array_type = array_new_result.second;
    const ValueType element_type = array_type->element_type();
    const ValueKind kind = element_type.kind();
    const uint32_t element_size = value_kind_size(kind);

    Address element_addr = array->ElementAddress(0);
    for (uint32_t i = 0; i < elem_count; i++) {
      switch (kind) {
        case kI8:
          *reinterpret_cast<int8_t*>(element_addr) = int8_t{};
          break;
        case kI16:
          base::WriteUnalignedValue<int16_t>(element_addr, int16_t{});
          break;
        case kI32:
          base::WriteUnalignedValue<int32_t>(element_addr, int32_t{});
          break;
        case kI64:
          base::WriteUnalignedValue<int64_t>(element_addr, int64_t{});
          break;
        case kF32:
          base::WriteUnalignedValue<float>(element_addr, float{});
          break;
        case kF64:
          base::WriteUnalignedValue<double>(element_addr, double{});
          break;
        case kS128:
          base::WriteUnalignedValue<Simd128>(element_addr, Simd128{});
          break;
        case kRef:
        case kRefNull:
          base::WriteUnalignedValue<Tagged_t>(
              element_addr,
              static_cast<Tagged_t>(
                  wasm_runtime->GetNullValue(element_type).ptr()));
          break;
        default:
          UNREACHABLE();
      }
      element_addr += element_size;
    }
  }

  push<WasmRef>(sp, code, wasm_runtime, array);

  NextOp();
}

template <TrapReason OutOfBoundsError>
INSTRUCTION_HANDLER_FUNC s2s_ArrayNewSegment(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  const uint32_t data_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(data_index))) {
    TRAP(OutOfBoundsError)
  }

  uint32_t length = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t offset = pop<int32_t>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(!Smi::IsValid(offset))) {
    TRAP(OutOfBoundsError)
  }
  if (V8_UNLIKELY(length >= static_cast<uint32_t>(WasmArray::MaxLength(
                                wasm_runtime->GetArrayType(array_index))))) {
    TRAP(TrapReason::kTrapArrayTooLarge)
  }

  WasmRef result = wasm_runtime->WasmArrayNewSegment(array_index, data_index,
                                                     offset, length);
  if (V8_UNLIKELY(result.is_null())) {
    wasm::TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }
  push<WasmRef>(sp, code, wasm_runtime, result);

  NextOp();
}
// The instructions array.new_data and array.new_elem have the same
// implementation after validation. The only difference is that array.init_elem
// is used with arrays that contain elements of reference types, and
// array.init_data with arrays that contain elements of numeric types.
static auto s2s_ArrayNewData = s2s_ArrayNewSegment<kTrapDataSegmentOutOfBounds>;
static auto s2s_ArrayNewElem =
    s2s_ArrayNewSegment<kTrapElementSegmentOutOfBounds>;

template <bool init_data>
INSTRUCTION_HANDLER_FUNC s2s_ArrayInitSegment(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  const uint32_t array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  const uint32_t data_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(data_index))) {
    TRAP(TrapReason::kTrapElementSegmentOutOfBounds)
  }

  uint32_t size = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t src_offset = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t dest_offset = pop<int32_t>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(!Smi::IsValid(size)) || !Smi::IsValid(dest_offset)) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }
  if (V8_UNLIKELY(!Smi::IsValid(src_offset))) {
    TrapReason reason = init_data ? TrapReason::kTrapDataSegmentOutOfBounds
                                  : TrapReason::kTrapElementSegmentOutOfBounds;
    INLINED_TRAP(reason);
  }

  WasmRef array = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array))) {
    TRAP(TrapReason::kTrapNullDereference)
  }

  bool ok = wasm_runtime->WasmArrayInitSegment(data_index, array, dest_offset,
                                               src_offset, size);
  if (V8_UNLIKELY(!ok)) {
    TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }

  NextOp();
}
// The instructions array.init_data and array.init_elem have the same
// implementation after validation. The only difference is that array.init_elem
// is used with arrays that contain elements of reference types, and
// array.init_data with arrays that contain elements of numeric types.
static auto s2s_ArrayInitData = s2s_ArrayInitSegment<true>;
static auto s2s_ArrayInitElem = s2s_ArrayInitSegment<false>;

INSTRUCTION_HANDLER_FUNC s2s_ArrayLen(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  push<int32_t>(sp, code, wasm_runtime, array->length());

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ArrayCopy(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  const uint32_t dest_array_index = ReadI32(code);
  const uint32_t src_array_index = ReadI32(code);
  // TODO(paolosev@microsoft.com): already validated?
  if (V8_UNLIKELY(!Smi::IsValid(dest_array_index) ||
                  !Smi::IsValid(src_array_index))) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  uint32_t size = pop<int32_t>(sp, code, wasm_runtime);
  uint32_t src_offset = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef src_array = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t dest_offset = pop<int32_t>(sp, code, wasm_runtime);
  WasmRef dest_array = pop<WasmRef>(sp, code, wasm_runtime);

  if (V8_UNLIKELY(!Smi::IsValid(src_offset)) || !Smi::IsValid(dest_offset)) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  } else if (V8_UNLIKELY(wasm_runtime->IsRefNull(dest_array))) {
    TRAP(TrapReason::kTrapNullDereference)
  } else if (V8_UNLIKELY(dest_offset + size >
                         Cast<WasmArray>(*dest_array)->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  } else if (V8_UNLIKELY(wasm_runtime->IsRefNull(src_array))) {
    TRAP(TrapReason::kTrapNullDereference)
  } else if (V8_UNLIKELY(src_offset + size >
                         Cast<WasmArray>(*src_array)->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  bool ok = true;
  if (size > 0) {
    ok = wasm_runtime->WasmArrayCopy(dest_array, dest_offset, src_array,
                                     src_offset, size);
  }

  if (V8_UNLIKELY(!ok)) {
    wasm::TrapReason reason = WasmInterpreterThread::GetRuntimeLastWasmError(
        wasm_runtime->GetIsolate());
    INLINED_TRAP(reason)
  }

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayGet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  push<T>(sp, code, wasm_runtime, base::ReadUnalignedValue<U>(element_addr));

  NextOp();
}
static auto s2s_I8SArrayGet = s2s_ArrayGet<int32_t, int8_t>;
static auto s2s_I8UArrayGet = s2s_ArrayGet<uint32_t, uint8_t>;
static auto s2s_I16SArrayGet = s2s_ArrayGet<int32_t, int16_t>;
static auto s2s_I16UArrayGet = s2s_ArrayGet<uint32_t, uint16_t>;
static auto s2s_I32ArrayGet = s2s_ArrayGet<int32_t>;
static auto s2s_I64ArrayGet = s2s_ArrayGet<int64_t>;
static auto s2s_F32ArrayGet = s2s_ArrayGet<float>;
static auto s2s_F64ArrayGet = s2s_ArrayGet<double>;
static auto s2s_S128ArrayGet = s2s_ArrayGet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayGet(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  push<WasmRef>(sp, code, wasm_runtime,
                wasm_runtime->GetWasmArrayRefElement(array, index));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArraySet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  const T value = pop<T>(sp, code, wasm_runtime);
  const uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  base::WriteUnalignedValue<U>(element_addr, value);

  NextOp();
}
static auto s2s_I8ArraySet = s2s_ArraySet<int32_t, int8_t>;
static auto s2s_I16ArraySet = s2s_ArraySet<int32_t, int16_t>;
static auto s2s_I32ArraySet = s2s_ArraySet<int32_t>;
static auto s2s_I64ArraySet = s2s_ArraySet<int64_t>;
static auto s2s_F32ArraySet = s2s_ArraySet<float>;
static auto s2s_F64ArraySet = s2s_ArraySet<double>;
static auto s2s_S128ArraySet = s2s_ArraySet<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArraySet(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t index = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(index >= array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(index);
  base::WriteUnalignedValue<Tagged_t>(
      element_addr, V8HeapCompressionScheme::CompressObject((*ref).ptr()));

  NextOp();
}

template <typename T, typename U = T>
INSTRUCTION_HANDLER_FUNC s2s_ArrayFill(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t size = pop<uint32_t>(sp, code, wasm_runtime);
  T value = pop<U>(sp, code, wasm_runtime);
  uint32_t offset = pop<uint32_t>(sp, code, wasm_runtime);

  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(static_cast<uint64_t>(offset) + size > array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(offset);
  for (uint32_t i = 0; i < size; i++) {
    base::WriteUnalignedValue<T>(element_addr, value);
    element_addr += sizeof(T);
  }

  NextOp();
}
static auto s2s_I8ArrayFill = s2s_ArrayFill<int8_t, int32_t>;
static auto s2s_I16ArrayFill = s2s_ArrayFill<int16_t, int32_t>;
static auto s2s_I32ArrayFill = s2s_ArrayFill<int32_t>;
static auto s2s_I64ArrayFill = s2s_ArrayFill<int64_t>;
static auto s2s_F32ArrayFill = s2s_ArrayFill<float>;
static auto s2s_F64ArrayFill = s2s_ArrayFill<double>;
static auto s2s_S128ArrayFill = s2s_ArrayFill<Simd128>;

INSTRUCTION_HANDLER_FUNC s2s_RefArrayFill(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  // DrumBrake currently only works with pointer compression.
  static_assert(COMPRESS_POINTERS_BOOL);

  uint32_t size = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);
  Tagged<Object> tagged_value = *value;
  uint32_t offset = pop<uint32_t>(sp, code, wasm_runtime);

  WasmRef array_obj = pop<WasmRef>(sp, code, wasm_runtime);
  if (V8_UNLIKELY(wasm_runtime->IsRefNull(array_obj))) {
    TRAP(TrapReason::kTrapNullDereference)
  }
  DCHECK(IsWasmArray(*array_obj));

  Tagged<WasmArray> array = Cast<WasmArray>(*array_obj);
  if (V8_UNLIKELY(static_cast<uint64_t>(offset) + size > array->length())) {
    TRAP(TrapReason::kTrapArrayOutOfBounds)
  }

  Address element_addr = array->ElementAddress(offset);
  for (uint32_t i = 0; i < size; i++) {
    // Only stores the lower 32-bit.
    base::WriteUnalignedValue<Tagged_t>(
        element_addr, static_cast<Tagged_t>(tagged_value.ptr()));
    element_addr += kTaggedSize;
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefI31(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  uint32_t value = pop<int32_t>(sp, code, wasm_runtime);

  // Trunc
```