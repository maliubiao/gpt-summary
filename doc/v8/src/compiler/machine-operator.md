Response: The user wants to understand the functionality of the C++ code provided. The code defines several structures and functions related to machine-level operations within the V8 JavaScript engine.

Here's a breakdown of the code and its potential relation to JavaScript:

1. **Data Structures for Machine Operations:** The code defines structures like `StoreRepresentation`, `AtomicStoreParameters`, `AtomicLoadParameters`, `AtomicOpParameters`, `LoadTransformParameters`, `LoadLaneParameters`, and `StoreLaneParameters`. These structures likely represent the different types of low-level memory access and manipulation operations the V8 compiler can generate.

2. **Operator Overloading for Equality, Inequality, Hashing, and Output:**  The code overloads operators like `==`, `!=`, and `<<` (for output stream) and provides `hash_value` functions for these structures. This allows for easy comparison, hashing (important for using these structures as keys in hash maps), and debugging output of these machine operation parameters.

3. **Enums for Representing Different Kinds of Operations:**  Enums like `MemoryAccessKind`, `LoadTransformation`, and `ShiftKind` are used to categorize different variations of machine operations. For example, `MemoryAccessKind` distinguishes between normal, unaligned, and protected memory accesses.

4. **Functions to Extract Parameters from Operators:** Functions like `LoadRepresentationOf`, `AtomicLoadParametersOf`, etc., are defined to extract the specific parameters associated with a given machine-level operation (`Operator`). This suggests the existence of an `Operator` class or structure within the V8 compiler infrastructure.

5. **Lists of Pure Machine Operations:** Macros like `PURE_BINARY_OP_LIST_32`, `PURE_BINARY_OP_LIST_64`, `PURE_SIMD_OP_LIST`, and `MACHINE_PURE_OP_LIST` list various low-level CPU instructions or operations that the V8 compiler can use. These include arithmetic operations, bitwise operations, SIMD (Single Instruction, Multiple Data) operations, and type conversions.

6. **Optional and Overflow Operations:**  `PURE_OPTIONAL_OP_LIST` and `OVERFLOW_OP_LIST` list operations that might have optional behavior or can result in overflows.

7. **Machine Types and Representations:**  `MACHINE_TYPE_LIST` and `MACHINE_REPRESENTATION_LIST` define the primitive data types and their low-level representations that the V8 compiler works with (e.g., Float32, Int32, kWord32, kTagged).

8. **Store Pair Representations:** `STORE_PAIR_MACHINE_REPRESENTATION_LIST` deals with storing pairs of data with different representations. This is likely related to how V8 handles object properties and other complex data structures in memory.

9. **Atomic Operations Lists:** Macros like `ATOMIC_TAGGED_TYPE_LIST`, `ATOMIC_REPRESENTATION_LIST`, and `ATOMIC_PAIR_BINOP_LIST` define types and operations related to atomic memory access, ensuring thread safety in concurrent JavaScript execution.

**Relationship to JavaScript:**

This code is part of the V8 compiler, which takes JavaScript code and translates it into efficient machine code that the CPU can execute. The structures and operations defined here represent the low-level building blocks that the compiler uses during this translation process.

For example:

* **`StoreRepresentation` and `LoadRepresentation`:** When you assign a value to a JavaScript variable (store) or access a variable's value (load), the V8 compiler will generate machine instructions corresponding to these operations. The `StoreRepresentation` and `LoadRepresentation` specify the data type being stored or loaded (e.g., a 32-bit integer, a 64-bit floating-point number, a tagged pointer to a JavaScript object).

* **`AtomicStoreParameters` and `AtomicLoadParameters`:**  JavaScript has features like `SharedArrayBuffer` and `Atomics` that allow for low-level, shared memory access between different JavaScript contexts (like Web Workers). These structures are directly related to how V8 implements these features, ensuring atomic operations on shared memory.

* **`PURE_BINARY_OP_LIST_32` and `PURE_BINARY_OP_LIST_64`:** When you perform arithmetic or bitwise operations in JavaScript (e.g., `x + y`, `a & b`), the V8 compiler might translate these directly into the corresponding machine instructions listed in these macros.

* **SIMD Operations:** JavaScript has the WebAssembly SIMD API, allowing for parallel operations on vectors of data. The `PURE_SIMD_OP_LIST` directly reflects the SIMD instructions supported by the underlying hardware and exposed through this API.

**JavaScript Example:**

```javascript
// Simple arithmetic operation
let a = 10;
let b = 5;
let sum = a + b; // V8 might use an Int32Add operation

// Accessing an object property
const obj = { x: 42 };
let value = obj.x; // V8 will use a Load operation with appropriate representation

// Using SharedArrayBuffer and Atomics
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5); // V8 will use an atomic add operation

// WebAssembly SIMD (example, might require specific setup)
// const i32x4 = wasmModule.exports.create_i32x4(1, 2, 3, 4);
// const result = wasmModule.exports.add_i32x4(i32x4, i32x4); // V8 will use SIMD add instructions
```

**Summary of Functionality (Part 1):**

This part of the `machine-operator.cc` file defines data structures, enums, and functions that represent **machine-level operations and their parameters** within the V8 JavaScript engine's compiler. It lays the groundwork for describing the various low-level instructions and memory access patterns that the compiler can generate when translating JavaScript code into machine code. It is directly related to JavaScript functionality, particularly in areas involving primitive data types, arithmetic operations, memory access, concurrency (atomics), and WebAssembly SIMD.

```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator.h"

#include <optional>

#include "src/base/lazy-instance.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"

namespace v8 {
namespace internal {
namespace compiler {

bool operator==(StoreRepresentation lhs, StoreRepresentation rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.write_barrier_kind() == rhs.write_barrier_kind();
}

bool operator!=(StoreRepresentation lhs, StoreRepresentation rhs) {
  return !(lhs == rhs);
}

size_t hash_value(StoreRepresentation rep) {
  return base::hash_combine(rep.representation(), rep.write_barrier_kind());
}

std::ostream& operator<<(std::ostream& os, StoreRepresentation rep) {
  return os << rep.representation() << ", " << rep.write_barrier_kind();
}

bool operator==(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return lhs.store_representation() == rhs.store_representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicStoreParameters params) {
  return base::hash_combine(hash_value(params.store_representation()),
                            params.order(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicStoreParameters params) {
  return os << params.store_representation() << ", " << params.order();
}

bool operator==(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicLoadParameters params) {
  return base::hash_combine(params.representation(), params.order(),
                            params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicLoadParameters params) {
  return os << params.representation() << ", " << params.order();
}

bool operator==(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return lhs.type() == rhs.type() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicOpParameters params) {
  return base::hash_combine(params.type(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicOpParameters params) {
  return os << params.type() << ", " << params.kind();
}

size_t hash_value(MemoryAccessKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, MemoryAccessKind kind) {
  switch (kind) {
    case MemoryAccessKind::kNormal:
      return os << "kNormal";
    case MemoryAccessKind::kUnaligned:
      return os << "kUnaligned";
    case MemoryAccessKind::kProtectedByTrapHandler:
      return os << "kProtected";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformation rep) { return static_cast<size_t>(rep); }

std::ostream& operator<<(std::ostream& os, LoadTransformation rep) {
  switch (rep) {
    case LoadTransformation::kS128Load8Splat:
      return os << "kS128Load8Splat";
    case LoadTransformation::kS128Load16Splat:
      return os << "kS128Load16Splat";
    case LoadTransformation::kS128Load32Splat:
      return os << "kS128Load32Splat";
    case LoadTransformation::kS128Load64Splat:
      return os << "kS128Load64Splat";
    case LoadTransformation::kS128Load8x8S:
      return os << "kS128Load8x8S";
    case LoadTransformation::kS128Load8x8U:
      return os << "kS128Load8x8U";
    case LoadTransformation::kS128Load16x4S:
      return os << "kS128Load16x4S";
    case LoadTransformation::kS128Load16x4U:
      return os << "kS128Load16x4U";
    case LoadTransformation::kS128Load32x2S:
      return os << "kS128Load32x2S";
    case LoadTransformation::kS128Load32x2U:
      return os << "kS128Load32x2U";
    case LoadTransformation::kS128Load32Zero:
      return os << "kS128Load32Zero";
    case LoadTransformation::kS128Load64Zero:
      return os << "kS128Load64Zero";
    // Simd256
    case LoadTransformation::kS256Load8Splat:
      return os << "kS256Load8Splat";
    case LoadTransformation::kS256Load16Splat:
      return os << "kS256Load16Splat";
    case LoadTransformation::kS256Load32Splat:
      return os << "kS256Load32Splat";
    case LoadTransformation::kS256Load64Splat:
      return os << "kS256Load64Splat";
    case LoadTransformation::kS256Load8x16S:
      return os << "kS256Load8x16S";
    case LoadTransformation::kS256Load8x16U:
      return os << "kS256Load8x16U";
    case LoadTransformation::kS256Load8x8U:
      return os << "kS256Load8x8U";
    case LoadTransformation::kS256Load16x8S:
      return os << "kS256Load16x8S";
    case LoadTransformation::kS256Load16x8U:
      return os << "kS256Load16x8U";
    case LoadTransformation::kS256Load32x4S:
      return os << "kS256Load32x4S";
    case LoadTransformation::kS256Load32x4U:
      return os << "kS256Load32x4U";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformParameters params) {
  return base::hash_combine(params.kind, params.transformation);
}

std::ostream& operator<<(std::ostream& os, LoadTransformParameters params) {
  return os << "(" << params.kind << " " << params.transformation << ")";
}

#if V8_ENABLE_WEBASSEMBLY
LoadTransformParameters const& LoadTransformParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadTransform, op->opcode());
  return OpParameter<LoadTransformParameters>(op);
}

bool operator==(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return lhs.transformation == rhs.transformation && lhs.kind == rhs.kind;
}

bool operator!=(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(LoadLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, LoadLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<uint32_t>(params.laneidx) << ")";
}

LoadLaneParameters const& LoadLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadLane, op->opcode());
  return OpParameter<LoadLaneParameters>(op);
}

bool operator==(LoadLaneParameters lhs, LoadLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}

size_t hash_value(StoreLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, StoreLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<unsigned int>(params.laneidx) << ")";
}

StoreLaneParameters const& StoreLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStoreLane, op->opcode());
  return OpParameter<StoreLaneParameters>(op);
}

bool operator==(StoreLaneParameters lhs, StoreLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}
#endif  // V8_ENABLE_WEBASSEMBLY

LoadRepresentation LoadRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kLoad == op->opcode() ||
         IrOpcode::kProtectedLoad == op->opcode() ||
         IrOpcode::kLoadTrapOnNull == op->opcode() ||
         IrOpcode::kUnalignedLoad == op->opcode() ||
         IrOpcode::kLoadImmutable == op->opcode());
  return OpParameter<LoadRepresentation>(op);
}

AtomicLoadParameters AtomicLoadParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicLoad == op->opcode() ||
         IrOpcode::kWord64AtomicLoad == op->opcode());
  return OpParameter<AtomicLoadParameters>(op);
}

AtomicOpParameters AtomicOpParametersOf(Operator const* op) {
  DCHECK(IrOpcode::isAtomicOpOpcode(IrOpcode::Value(op->opcode())));
  return OpParameter<AtomicOpParameters>(op);
}

StoreRepresentation const& StoreRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStore == op->opcode() ||
         IrOpcode::kProtectedStore == op->opcode() ||
         IrOpcode::kStoreTrapOnNull == op->opcode() ||
         IrOpcode::kStoreIndirectPointer == op->opcode());
  return OpParameter<StoreRepresentation>(op);
}

StorePairRepresentation const& StorePairRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStorePair == op->opcode());
  return OpParameter<StorePairRepresentation>(op);
}

AtomicStoreParameters const& AtomicStoreParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicStore == op->opcode() ||
         IrOpcode::kWord64AtomicStore == op->opcode());
  return OpParameter<AtomicStoreParameters>(op);
}

UnalignedStoreRepresentation const& UnalignedStoreRepresentationOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kUnalignedStore, op->opcode());
  return OpParameter<UnalignedStoreRepresentation>(op);
}

bool operator==(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return lhs.size() == rhs.size() && lhs.alignment() == rhs.alignment();
}

bool operator!=(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return !(lhs == rhs);
}

size_t hash_value(StackSlotRepresentation rep) {
  return base::hash_combine(rep.size(), rep.alignment());
}

std::ostream& operator<<(std::ostream& os, StackSlotRepresentation rep) {
  return os << rep.size() << ", " << rep.alignment();
}

StackSlotRepresentation const& StackSlotRepresentationOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStackSlot, op->opcode());
  return OpParameter<StackSlotRepresentation>(op);
}

MachineType AtomicOpType(Operator const* op) {
  const AtomicOpParameters params = OpParameter<AtomicOpParameters>(op);
  return params.type();
}

size_t hash_value(ShiftKind kind) { return static_cast<size_t>(kind); }
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os, ShiftKind kind) {
  switch (kind) {
    case ShiftKind::kNormal:
      return os << "Normal";
    case ShiftKind::kShiftOutZeros:
      return os << "ShiftOutZeros";
  }
}

ShiftKind ShiftKindOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32Sar == op->opcode() ||
         IrOpcode::kWord64Sar == op->opcode());
  return OpParameter<ShiftKind>(op);
}

size_t hash_value(TruncateKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return os << "kArchitectureDefault";
    case TruncateKind::kSetOverflowToMin:
      return os << "kSetOverflowToMin";
  }
}

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_32(V)                                           \
  V(Word32And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word32Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Shl, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Shr, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Ror, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Equal, Operator::kCommutative, 2, 0, 1)                           \
  V(Int32Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32Sub, Operator::kNoProperties, 2, 0, 1)                             \
  V(Int32Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Int32Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Int32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                 \
  V(Uint32Div, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32LessThan, Operator::kNoProperties, 2, 0, 1)                       \
  V(Uint32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                \
  V(Uint32Mod, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_64(V)                                            \
  V(Word64And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Word64Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Shl, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Shr, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Ror, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64RorLowerable, Operator::kNoProperties, 2, 1, 1)                    \
  V(Word64Equal, Operator::kCommutative, 2, 0, 1)                            \
  V(Int64Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64Sub, Operator::kNoProperties, 2, 0, 1)                              \
  V(Int64Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Int64Div, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64Mod, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64LessThan, Operator::kNoProperties, 2, 0, 1)                         \
  V(Int64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                  \
  V(Uint64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Uint64Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Uint64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_SIMD_OP_LIST(V)                                                   \
  IF_WASM(V, F64x2Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F64x2ConvertLowI32x4S, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2ConvertLowI32x4U, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2PromoteLowF32x4, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F32x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4SConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4UConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F32x4DemoteF64x2Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F16x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
Prompt: 
```
这是目录为v8/src/compiler/machine-operator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator.h"

#include <optional>

#include "src/base/lazy-instance.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"

namespace v8 {
namespace internal {
namespace compiler {

bool operator==(StoreRepresentation lhs, StoreRepresentation rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.write_barrier_kind() == rhs.write_barrier_kind();
}


bool operator!=(StoreRepresentation lhs, StoreRepresentation rhs) {
  return !(lhs == rhs);
}


size_t hash_value(StoreRepresentation rep) {
  return base::hash_combine(rep.representation(), rep.write_barrier_kind());
}


std::ostream& operator<<(std::ostream& os, StoreRepresentation rep) {
  return os << rep.representation() << ", " << rep.write_barrier_kind();
}

bool operator==(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return lhs.store_representation() == rhs.store_representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicStoreParameters params) {
  return base::hash_combine(hash_value(params.store_representation()),
                            params.order(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicStoreParameters params) {
  return os << params.store_representation() << ", " << params.order();
}

bool operator==(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicLoadParameters params) {
  return base::hash_combine(params.representation(), params.order(),
                            params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicLoadParameters params) {
  return os << params.representation() << ", " << params.order();
}

bool operator==(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return lhs.type() == rhs.type() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicOpParameters params) {
  return base::hash_combine(params.type(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicOpParameters params) {
  return os << params.type() << ", " << params.kind();
}

size_t hash_value(MemoryAccessKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, MemoryAccessKind kind) {
  switch (kind) {
    case MemoryAccessKind::kNormal:
      return os << "kNormal";
    case MemoryAccessKind::kUnaligned:
      return os << "kUnaligned";
    case MemoryAccessKind::kProtectedByTrapHandler:
      return os << "kProtected";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformation rep) { return static_cast<size_t>(rep); }

std::ostream& operator<<(std::ostream& os, LoadTransformation rep) {
  switch (rep) {
    case LoadTransformation::kS128Load8Splat:
      return os << "kS128Load8Splat";
    case LoadTransformation::kS128Load16Splat:
      return os << "kS128Load16Splat";
    case LoadTransformation::kS128Load32Splat:
      return os << "kS128Load32Splat";
    case LoadTransformation::kS128Load64Splat:
      return os << "kS128Load64Splat";
    case LoadTransformation::kS128Load8x8S:
      return os << "kS128Load8x8S";
    case LoadTransformation::kS128Load8x8U:
      return os << "kS128Load8x8U";
    case LoadTransformation::kS128Load16x4S:
      return os << "kS128Load16x4S";
    case LoadTransformation::kS128Load16x4U:
      return os << "kS128Load16x4U";
    case LoadTransformation::kS128Load32x2S:
      return os << "kS128Load32x2S";
    case LoadTransformation::kS128Load32x2U:
      return os << "kS128Load32x2U";
    case LoadTransformation::kS128Load32Zero:
      return os << "kS128Load32Zero";
    case LoadTransformation::kS128Load64Zero:
      return os << "kS128Load64Zero";
    // Simd256
    case LoadTransformation::kS256Load8Splat:
      return os << "kS256Load8Splat";
    case LoadTransformation::kS256Load16Splat:
      return os << "kS256Load16Splat";
    case LoadTransformation::kS256Load32Splat:
      return os << "kS256Load32Splat";
    case LoadTransformation::kS256Load64Splat:
      return os << "kS256Load64Splat";
    case LoadTransformation::kS256Load8x16S:
      return os << "kS256Load8x16S";
    case LoadTransformation::kS256Load8x16U:
      return os << "kS256Load8x16U";
    case LoadTransformation::kS256Load8x8U:
      return os << "kS256Load8x8U";
    case LoadTransformation::kS256Load16x8S:
      return os << "kS256Load16x8S";
    case LoadTransformation::kS256Load16x8U:
      return os << "kS256Load16x8U";
    case LoadTransformation::kS256Load32x4S:
      return os << "kS256Load32x4S";
    case LoadTransformation::kS256Load32x4U:
      return os << "kS256Load32x4U";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformParameters params) {
  return base::hash_combine(params.kind, params.transformation);
}

std::ostream& operator<<(std::ostream& os, LoadTransformParameters params) {
  return os << "(" << params.kind << " " << params.transformation << ")";
}

#if V8_ENABLE_WEBASSEMBLY
LoadTransformParameters const& LoadTransformParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadTransform, op->opcode());
  return OpParameter<LoadTransformParameters>(op);
}

bool operator==(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return lhs.transformation == rhs.transformation && lhs.kind == rhs.kind;
}

bool operator!=(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(LoadLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, LoadLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<uint32_t>(params.laneidx) << ")";
}

LoadLaneParameters const& LoadLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadLane, op->opcode());
  return OpParameter<LoadLaneParameters>(op);
}

bool operator==(LoadLaneParameters lhs, LoadLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}

size_t hash_value(StoreLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, StoreLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<unsigned int>(params.laneidx) << ")";
}

StoreLaneParameters const& StoreLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStoreLane, op->opcode());
  return OpParameter<StoreLaneParameters>(op);
}

bool operator==(StoreLaneParameters lhs, StoreLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}
#endif  // V8_ENABLE_WEBASSEMBLY

LoadRepresentation LoadRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kLoad == op->opcode() ||
         IrOpcode::kProtectedLoad == op->opcode() ||
         IrOpcode::kLoadTrapOnNull == op->opcode() ||
         IrOpcode::kUnalignedLoad == op->opcode() ||
         IrOpcode::kLoadImmutable == op->opcode());
  return OpParameter<LoadRepresentation>(op);
}

AtomicLoadParameters AtomicLoadParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicLoad == op->opcode() ||
         IrOpcode::kWord64AtomicLoad == op->opcode());
  return OpParameter<AtomicLoadParameters>(op);
}

AtomicOpParameters AtomicOpParametersOf(Operator const* op) {
  DCHECK(IrOpcode::isAtomicOpOpcode(IrOpcode::Value(op->opcode())));
  return OpParameter<AtomicOpParameters>(op);
}

StoreRepresentation const& StoreRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStore == op->opcode() ||
         IrOpcode::kProtectedStore == op->opcode() ||
         IrOpcode::kStoreTrapOnNull == op->opcode() ||
         IrOpcode::kStoreIndirectPointer == op->opcode());
  return OpParameter<StoreRepresentation>(op);
}

StorePairRepresentation const& StorePairRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStorePair == op->opcode());
  return OpParameter<StorePairRepresentation>(op);
}

AtomicStoreParameters const& AtomicStoreParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicStore == op->opcode() ||
         IrOpcode::kWord64AtomicStore == op->opcode());
  return OpParameter<AtomicStoreParameters>(op);
}

UnalignedStoreRepresentation const& UnalignedStoreRepresentationOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kUnalignedStore, op->opcode());
  return OpParameter<UnalignedStoreRepresentation>(op);
}

bool operator==(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return lhs.size() == rhs.size() && lhs.alignment() == rhs.alignment();
}

bool operator!=(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return !(lhs == rhs);
}

size_t hash_value(StackSlotRepresentation rep) {
  return base::hash_combine(rep.size(), rep.alignment());
}

std::ostream& operator<<(std::ostream& os, StackSlotRepresentation rep) {
  return os << rep.size() << ", " << rep.alignment();
}

StackSlotRepresentation const& StackSlotRepresentationOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStackSlot, op->opcode());
  return OpParameter<StackSlotRepresentation>(op);
}

MachineType AtomicOpType(Operator const* op) {
  const AtomicOpParameters params = OpParameter<AtomicOpParameters>(op);
  return params.type();
}

size_t hash_value(ShiftKind kind) { return static_cast<size_t>(kind); }
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os, ShiftKind kind) {
  switch (kind) {
    case ShiftKind::kNormal:
      return os << "Normal";
    case ShiftKind::kShiftOutZeros:
      return os << "ShiftOutZeros";
  }
}

ShiftKind ShiftKindOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32Sar == op->opcode() ||
         IrOpcode::kWord64Sar == op->opcode());
  return OpParameter<ShiftKind>(op);
}

size_t hash_value(TruncateKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return os << "kArchitectureDefault";
    case TruncateKind::kSetOverflowToMin:
      return os << "kSetOverflowToMin";
  }
}

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_32(V)                                           \
  V(Word32And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word32Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Shl, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Shr, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Ror, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Equal, Operator::kCommutative, 2, 0, 1)                           \
  V(Int32Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32Sub, Operator::kNoProperties, 2, 0, 1)                             \
  V(Int32Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Int32Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Int32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                 \
  V(Uint32Div, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32LessThan, Operator::kNoProperties, 2, 0, 1)                       \
  V(Uint32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                \
  V(Uint32Mod, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_64(V)                                            \
  V(Word64And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Word64Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Shl, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Shr, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Ror, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64RorLowerable, Operator::kNoProperties, 2, 1, 1)                    \
  V(Word64Equal, Operator::kCommutative, 2, 0, 1)                            \
  V(Int64Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64Sub, Operator::kNoProperties, 2, 0, 1)                              \
  V(Int64Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Int64Div, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64Mod, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64LessThan, Operator::kNoProperties, 2, 0, 1)                         \
  V(Int64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                  \
  V(Uint64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Uint64Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Uint64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_SIMD_OP_LIST(V)                                                   \
  IF_WASM(V, F64x2Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F64x2ConvertLowI32x4S, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2ConvertLowI32x4U, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2PromoteLowF32x4, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F32x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4SConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4UConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F32x4DemoteF64x2Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F16x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F16x8Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F16x8Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F16x8Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F16x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F16x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F16x8Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F16x8Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F16x8SConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F16x8UConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I16x8UConvertF16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I16x8SConvertF16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F16x8DemoteF32x4Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8DemoteF64x2Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F32x4PromoteLowF16x8, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F16x8Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, I64x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I64x2Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I64x2SplatI32Pair, Operator::kNoProperties, 2, 0, 1)              \
  IF_WASM(V, I64x2Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I64x2Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I64x2SConvertI32x4Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I64x2SConvertI32x4High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I64x2UConvertI32x4Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I64x2UConvertI32x4High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I64x2BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I64x2Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I64x2Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x2Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x2Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x2Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x2GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I64x2ExtMulLowI32x4S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I64x2ExtMulHighI32x4S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I64x2ExtMulLowI32x4U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I64x2ExtMulHighI32x4U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I32x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I32x4SConvertF32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x4SConvertI16x8Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I32x4SConvertI16x8High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I32x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I32x4Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x4MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4MaxS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x4GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4UConvertF32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x4UConvertI16x8Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I32x4UConvertI16x8High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I32x4ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x4MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I32x4BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I32x4DotI16x8S, Operator::kCommutative, 2, 0, 1)                  \
  IF_WASM(V, I32x4ExtMulLowI16x8S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I32x4ExtMulHighI16x8S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x4ExtMulLowI16x8U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I32x4ExtMulHighI16x8U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8S, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8U, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I32x4TruncSatF64x2SZero, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I32x4TruncSatF64x2UZero, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I16x16Splat, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I16x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I16x8SConvertI8x16Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I16x8SConvertI8x16High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I16x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I16x8Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x8SConvertI32x4, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I16x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x8AddSatS, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8SubSatS, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I16x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x8MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8MaxS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I16x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I16x8GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8UConvertI8x16Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I16x8UConvertI8x16High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I16x8ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x8UConvertI32x4, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I16x8AddSatU, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x8SubSatU, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I16x8MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8RoundingAverageU, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8Q15MulRSatS, Operator::kCommutative, 2, 0, 1)                \
  IF_WASM(V, I16x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I16x8BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I16x8ExtMulLowI8x16S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I16x8ExtMulHighI8x16S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8ExtMulLowI8x16U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I16x8ExtMulHighI8x16U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16S, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16U, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I8x32Splat, Operator::kNoProperties, 1, 0, 1)                     \
  V(I8x16Splat, Operator::kNoProperties, 1, 0, 1)                              \
  IF_WASM(V, F64x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I8x16Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I8x16Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x16SConvertI16x8, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I8x16Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I8x16AddSatS, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I8x16Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16SubSatS, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I8x16MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16MaxS, Operator::kCommutative, 2, 0, 1)                       \
  V(I8x16Eq, Operator::kCommutative, 2, 0, 1)                                  \
  IF_WASM(V, I8x16Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I8x16GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x16UConvertI16x8, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I8x16AddSatU, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I8x16SubSatU, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I8x16MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16RoundingAverageU, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I8x16Popcnt, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I8x16Abs, Operator::kNoProperties, 1, 0, 1)                       \
  V(I8x16BitMask, Operator::kNoProperties, 1, 0, 1)                            \
  IF_WASM(V, S128Zero, Operator::kNoProperties, 0, 0, 1)                       \
  IF_WASM(V, S128And, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S128Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  IF_WASM(V, S128Xor, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S128Not, Operator::kNoProperties, 1, 0, 1)                        \
  IF_WASM(V, S128Select, Operator::kNoProperties, 3, 0, 1)                     \
  IF_WASM(V, S128AndNot, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, V128AnyTrue, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I64x2AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I32x4AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I16x8AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I8x16AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I8x16RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I16x8RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I32x4RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I64x2RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, F32x4RelaxedMin, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F32x4RelaxedMax, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F64x2RelaxedMin, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F64x2RelaxedMax, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F32x8RelaxedMin, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F32x8RelaxedMax, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F64x4RelaxedMin, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, F64x4RelaxedMax, Operator::kNoProperties, 2, 0, 1)                \
  IF_WASM(V, I32x4RelaxedTruncF32x4S, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I32x4RelaxedTruncF32x4U, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I32x4RelaxedTruncF64x2SZero, Operator::kNoProperties, 1, 0, 1)    \
  IF_WASM(V, I32x4RelaxedTruncF64x2UZero, Operator::kNoProperties, 1, 0, 1)    \
  IF_WASM(V, I16x8RelaxedQ15MulRS, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I16x8DotI8x16I7x16S, Operator::kNoProperties, 2, 0, 1)            \
  IF_WASM(V, I32x4DotI8x16I7x16AddS, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, F64x4Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x4Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x4Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x8Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x16Add, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x32Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x16Sub, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x32Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x16Mul, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, F64x4Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x8Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x16AddSatS, Operator::kCommutative, 2, 0, 1)                   \
  IF_WASM(V, I8x32AddSatS, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x16AddSatU, Operator::kCommutative, 2, 0, 1)                   \
  IF_WASM(V, I8x32AddSatU, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x16SubSatS, Operator::kNoProperties, 2, 0, 1)                  \
  IF_WASM(V, I8x32SubSatS, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I16x16SubSatU, Operator::kNoProperties, 2, 0, 1)                  \
  IF_WASM(V, I8x32SubSatU, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, F32x8Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x8Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x8Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x8Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I16x16Eq, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I8x32Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x4GtS, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x8GtS, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x16GtS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x32GtS, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x4Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x8Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x4Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x8Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, I32x8MinS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16MinS, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I8x32MinS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x8MinU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16MinU, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I8x32MinU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x8MaxS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16MaxS, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I8x32MaxS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x8MaxU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16MaxU, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I8x32MaxU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I64x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x4GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x8GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x16Ne, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x16GtU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16GeS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16GeU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x32Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I8x32GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x32GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x32GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8SConvertF32x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x8UConvertF32x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F64x4ConvertI32x4S, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x8SConvertI32x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x8UConvertI32x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4DemoteF64x4, Operator::kNoProperties, 1, 0, 1)               \
  IF_WASM(V, I64x4SConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I64x4UConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x8SConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x8UConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I16x16SConvertI8x16, Operator::kNoProperties, 1, 0, 1)            \
  IF_WASM(V, I16x16UConvertI8x16, Operator::kNoProperties, 1, 0, 1)            \
  IF_WASM(V, I16x16SConvertI32x8, Operator::kNoProperties, 2, 0, 1)            \
  IF_WASM(V, I16x16UConvertI32x8, Operator::kNoProperties, 2, 0, 1)            \
  IF_WASM(V, I8x32SConvertI16x16, Operator::kNoProperties, 2, 0, 1)            \
  IF_WASM(V, I8x32UConvertI16x16, Operator::kNoProperties, 2, 0, 1)            \
  IF_WASM(V, I32x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I32x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I16x16Neg, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, I16x16Abs, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, I8x32Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I8x32Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I64x4Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x4ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x8Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x8ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x8ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16Shl, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x16ShrS, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I16x16ShrU, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, I32x8DotI16x16S, Operator::kCommutative, 2, 0, 1)                 \
  IF_WASM(V, I16x16RoundingAverageU, Operator::kCommutative, 2, 0, 1)          \
  IF_WASM(V, I8x32RoundingAverageU, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I64x4ExtMulI32x4S, Operator::kCommutative, 2, 0, 1)               \
  IF_WASM(V, I64x4ExtMulI32x4U, Operator::kCommutative, 2, 0, 1)               \
  IF_WASM(V, I32x8ExtMulI16x8S, Operator::kCommutative, 2, 0, 1)               \
  IF_WASM(V, I32x8ExtMulI16x8U, Operator::kCommutative, 2, 0, 1)               \
  IF_WASM(V, I16x16ExtMulI8x16S, Operator::kCommutative, 2, 0, 1)              \
  IF_WASM(V, I16x16ExtMulI8x16U, Operator::kCommutative, 2, 0, 1)              \
  IF_WASM(V, I32x8ExtAddPairwiseI16x16S, Operator::kNoProperties, 1, 0, 1)     \
  IF_WASM(V, I32x8ExtAddPairwiseI16x16U, Operator::kNoProperties, 1, 0, 1)     \
  IF_WASM(V, I16x16ExtAddPairwiseI8x32S, Operator::kNoProperties, 1, 0, 1)     \
  IF_WASM(V, I16x16ExtAddPairwiseI8x32U, Operator::kNoProperties, 1, 0, 1)     \
  IF_WASM(V, F64x4Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x4Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, S256Zero, Operator::kNoProperties, 0, 0, 1)                       \
  IF_WASM(V, S256And, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S256Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  IF_WASM(V, S256Xor, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S256Not, Operator::kNoProperties, 1, 0, 1)                        \
  IF_WASM(V, S256Select, Operator::kNoProperties, 3, 0, 1)                     \
  IF_WASM(V, S256AndNot, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, F32x8Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x8Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x4Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x4Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, I64x4RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I32x8RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I16x16RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)        \
  IF_WASM(V, I8x32RelaxedLaneSelect, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I32x8DotI8x32I7x32AddS, Operator::kNoProperties, 3, 0, 1)         \
  IF_WASM(V, I16x16DotI8x32I7x32S, Operator::kNoProperties, 2, 0, 1)           \
  IF_WASM(V, I32x8RelaxedTruncF32x8S, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I32x8RelaxedTruncF32x8U, Operator::kNoProperties, 1, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define MACHINE_PURE_OP_LIST(V)                                            \
  PURE_BINARY_OP_LIST_32(V)                                                \
  PURE_BINARY_OP_LIST_64(V)                                                \
  PURE_SIMD_OP_LIST(V)                                                     \
  V(Word32Clz, Operator::kNoProperties, 1, 0, 1)                           \
  V(Word64Clz, Operator::kNoProperties, 1, 0, 1)                           \
  V(Word64ClzLowerable, Operator::kNoProperties, 1, 1, 1)                  \
  V(Word32ReverseBytes, Operator::kNoProperties, 1, 0, 1)                  \
  V(Word64ReverseBytes, Operator::kNoProperties, 1, 0, 1)                  \
  V(Simd128ReverseBytes, Operator::kNoProperties, 1, 0, 1)                 \
  V(BitcastTaggedToWordForTagAndSmiBits, Operator::kNoProperties, 1, 0, 1) \
  V(BitcastWordToTaggedSigned, Operator::kNoProperties, 1, 0, 1)           \
  V(TruncateFloat64ToWord32, Operator::kNoProperties, 1, 0, 1)             \
  V(ChangeFloat32ToFloat64, Operator::kNoProperties, 1, 0, 1)              \
  V(ChangeFloat64ToInt32, Operator::kNoProperties, 1, 0, 1)                \
  V(ChangeFloat64ToInt64, Operator::kNoProperties, 1, 0, 1)                \
  V(ChangeFloat64ToUint32, Operator::kNoProperties, 1, 0, 1)               \
  V(ChangeFloat64ToUint64, Operator::kNoProperties, 1, 0, 1)               \
  V(TruncateFloat64ToUint32, Operator::kNoProperties, 1, 0, 1)             \
  V(TryTruncateFloat32ToInt64, Operator::kNoProperties, 1, 0, 2)           \
  V(TryTruncateFloat64ToInt64, Operator::kNoProperties, 1, 0, 2)           \
  V(TryTruncateFloat32ToUint64, Operator::kNoProperties, 1, 0, 2)          \
  V(TryTruncateFloat64ToUint64, Operator::kNoProperties, 1, 0, 2)          \
  V(TryTruncateFloat64ToInt32, Operator::kNoProperties, 1, 0, 2)           \
  V(TryTruncateFloat64ToUint32, Operator::kNoProperties, 1, 0, 2)          \
  V(ChangeInt32ToFloat64, Operator::kNoProperties, 1, 0, 1)                \
  V(ChangeInt64ToFloat64, Operator::kNoProperties, 1, 0, 1)                \
  V(Float64SilenceNaN, Operator::kNoProperties, 1, 0, 1)                   \
  V(RoundFloat64ToInt32, Operator::kNoProperties, 1, 0, 1)                 \
  V(RoundInt32ToFloat32, Operator::kNoProperties, 1, 0, 1)                 \
  V(RoundInt64ToFloat32, Operator::kNoProperties, 1, 0, 1)                 \
  V(RoundInt64ToFloat64, Operator::kNoProperties, 1, 0, 1)                 \
  V(RoundUint32ToFloat32, Operator::kNoProperties, 1, 0, 1)                \
  V(RoundUint64ToFloat32, Operator::kNoProperties, 1, 0, 1)                \
  V(RoundUint64ToFloat64, Operator::kNoProperties, 1, 0, 1)                \
  V(BitcastWord32ToWord64, Operator::kNoProperties, 1, 0, 1)               \
  V(ChangeInt32ToInt64, Operator::kNoProperties, 1, 0, 1)                  \
  V(ChangeUint32ToFloat64, Operator::kNoProperties, 1, 0, 1)               \
  V(ChangeUint32ToUint64, Operator::kNoProperties, 1, 0, 1)                \
  V(TruncateFloat64ToFloat32, Operator::kNoProperties, 1, 0, 1)            \
  V(TruncateInt64ToInt32, Operator::kNoProperties, 1, 0, 1)                \
  V(BitcastFloat32ToInt32, Operator::kNoProperties, 1, 0, 1)               \
  V(BitcastFloat64ToInt64, Operator::kNoProperties, 1, 0, 1)               \
  V(BitcastInt32ToFloat32, Operator::kNoProperties, 1, 0, 1)               \
  V(BitcastInt64ToFloat64, Operator::kNoProperties, 1, 0, 1)               \
  V(SignExtendWord8ToInt32, Operator::kNoProperties, 1, 0, 1)              \
  V(SignExtendWord16ToInt32, Operator::kNoProperties, 1, 0, 1)             \
  V(SignExtendWord8ToInt64, Operator::kNoProperties, 1, 0, 1)              \
  V(SignExtendWord16ToInt64, Operator::kNoProperties, 1, 0, 1)             \
  V(SignExtendWord32ToInt64, Operator::kNoProperties, 1, 0, 1)             \
  V(Float32Abs, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float32Add, Operator::kCommutative, 2, 0, 1)                           \
  V(Float32Sub, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float32Mul, Operator::kCommutative, 2, 0, 1)                           \
  V(Float32Div, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float32Neg, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float32Sqrt, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float32Max, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Float32Min, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Float64Abs, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Acos, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Acosh, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Asin, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Asinh, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Atan, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Atan2, Operator::kNoProperties, 2, 0, 1)                        \
  V(Float64Atanh, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Cbrt, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Cos, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Cosh, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Exp, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Expm1, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Log, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Log1p, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Log2, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Log10, Operator::kNoProperties, 1, 0, 1)                        \
  V(Float64Max, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Float64Min, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Float64Neg, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Add, Operator::kCommutative, 2, 0, 1)                           \
  V(Float64Sub, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float64Mul, Operator::kCommutative, 2, 0, 1)                           \
  V(Float64Div, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float64Mod, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float64Pow, Operator::kNoProperties, 2, 0, 1)                          \
  V(Float64Sin, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Sinh, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Sqrt, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float64Tan, Operator::kNoProperties, 1, 0, 1)                          \
  V(Float64Tanh, Operator::kNoProperties, 1, 0, 1)                         \
  V(Float32Equal, Operator::kCommutative, 2, 0, 1)                         \
  V(Float32LessThan, Operator::kNoProperties, 2, 0, 1)                     \
  V(Float32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)              \
  V(Float64Equal, Operator::kCommutative, 2, 0, 1)                         \
  V(Float64LessThan, Operator::kNoProperties, 2, 0, 1)                     \
  V(Float64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)              \
  V(Float64ExtractLowWord32, Operator::kNoProperties, 1, 0, 1)             \
  V(Float64ExtractHighWord32, Operator::kNoProperties, 1, 0, 1)            \
  V(Float64InsertLowWord32, Operator::kNoProperties, 2, 0, 1)              \
  V(Float64InsertHighWord32, Operator::kNoProperties, 2, 0, 1)             \
  V(LoadStackCheckOffset, Operator::kNoProperties, 0, 0, 1)                \
  V(LoadFramePointer, Operator::kNoProperties, 0, 0, 1)                    \
  V(LoadRootRegister, Operator::kNoProperties, 0, 0, 1)                    \
  V(LoadParentFramePointer, Operator::kNoProperties, 0, 0, 1)              \
  V(Int32PairAdd, Operator::kNoProperties, 4, 0, 2)                        \
  V(Int32PairSub, Operator::kNoProperties, 4, 0, 2)                        \
  V(Int32PairMul, Operator::kNoProperties, 4, 0, 2)                        \
  V(Word32PairShl, Operator::kNoProperties, 3, 0, 2)                       \
  V(Word32PairShr, Operator::kNoProperties, 3, 0, 2)                       \
  V(Word32PairSar, Operator::kNoProperties, 3, 0, 2)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_OPTIONAL_OP_LIST(V)                            \
  V(Word32Ctz, Operator::kNoProperties, 1, 0, 1)            \
  V(Word64Ctz, Operator::kNoProperties, 1, 0, 1)            \
  V(Word64CtzLowerable, Operator::kNoProperties, 1, 1, 1)   \
  V(Word32Rol, Operator::kNoProperties, 2, 0, 1)            \
  V(Word64Rol, Operator::kNoProperties, 2, 0, 1)            \
  V(Word64RolLowerable, Operator::kNoProperties, 2, 1, 1)   \
  V(Word32ReverseBits, Operator::kNoProperties, 1, 0, 1)    \
  V(Word64ReverseBits, Operator::kNoProperties, 1, 0, 1)    \
  V(Int32AbsWithOverflow, Operator::kNoProperties, 1, 0, 2) \
  V(Int64AbsWithOverflow, Operator::kNoProperties, 1, 0, 2) \
  V(Word32Popcnt, Operator::kNoProperties, 1, 0, 1)         \
  V(Word64Popcnt, Operator::kNoProperties, 1, 0, 1)         \
  V(Float32RoundDown, Operator::kNoProperties, 1, 0, 1)     \
  V(Float64RoundDown, Operator::kNoProperties, 1, 0, 1)     \
  V(Float32RoundUp, Operator::kNoProperties, 1, 0, 1)       \
  V(Float64RoundUp, Operator::kNoProperties, 1, 0, 1)       \
  V(Float32RoundTruncate, Operator::kNoProperties, 1, 0, 1) \
  V(Float64RoundTruncate, Operator::kNoProperties, 1, 0, 1) \
  V(Float64RoundTiesAway, Operator::kNoProperties, 1, 0, 1) \
  V(Float32RoundTiesEven, Operator::kNoProperties, 1, 0, 1) \
  V(Float64RoundTiesEven, Operator::kNoProperties, 1, 0, 1) \
  V(Word32Select, Operator::kNoProperties, 3, 0, 1)         \
  V(Word64Select, Operator::kNoProperties, 3, 0, 1)         \
  V(Float32Select, Operator::kNoProperties, 3, 0, 1)        \
  V(Float64Select, Operator::kNoProperties, 3, 0, 1)        \
  V(TruncateFloat64ToFloat16RawBits, Operator::kNoProperties, 1, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define OVERFLOW_OP_LIST(V)                                                \
  V(Int32AddWithOverflow, Operator::kAssociative | Operator::kCommutative) \
  V(Int32SubWithOverflow, Operator::kNoProperties)                         \
  V(Int32MulWithOverflow, Operator::kAssociative | Operator::kCommutative) \
  V(Int64AddWithOverflow, Operator::kAssociative | Operator::kCommutative) \
  V(Int64SubWithOverflow, Operator::kNoProperties)                         \
  V(Int64MulWithOverflow, Operator::kAssociative | Operator::kCommutative)

#define MACHINE_TYPE_LIST(V) \
  V(Float16)                 \
  V(Float32)                 \
  V(Float64)                 \
  V(Simd128)                 \
  V(Int8)                    \
  V(Uint8)                   \
  V(Int16)                   \
  V(Uint16)                  \
  V(Int32)                   \
  V(Uint32)                  \
  V(Int64)                   \
  V(Uint64)                  \
  V(Pointer)                 \
  V(TaggedSigned)            \
  V(TaggedPointer)           \
  V(MapInHeader)             \
  V(AnyTagged)               \
  V(CompressedPointer)       \
  V(ProtectedPointer)        \
  V(SandboxedPointer)        \
  V(AnyCompressed)           \
  V(Simd256)

#define MACHINE_REPRESENTATION_LIST(V) \
  V(kFloat16)                          \
  V(kFloat32)                          \
  V(kFloat64)                          \
  V(kSimd128)                          \
  V(kWord8)                            \
  V(kWord16)                           \
  V(kWord32)                           \
  V(kWord64)                           \
  V(kMapWord)                          \
  V(kTaggedSigned)                     \
  V(kTaggedPointer)                    \
  V(kTagged)                           \
  V(kCompressedPointer)                \
  V(kSandboxedPointer)                 \
  V(kCompressed)                       \
  V(kSimd256)

#ifdef V8_TARGET_ARCH_64_BIT

#ifdef V8_COMPRESS_POINTERS

#define STORE_PAIR_MACHINE_REPRESENTATION_LIST(V) \
  V(kWord32, kWord32)                             \
  V(kWord32, kTagged)                             \
  V(kWord32, kTaggedSigned)                       \
  V(kWord32, kTaggedPointer)                      \
  V(kWord32, kCompressed)                         \
  V(kWord32, kCompressedPointer)                  \
  V(kTagged, kWord32)                             \
  V(kTagged, kTagged)                             \
  V(kTagged, kTaggedSigned)                       \
  V(kTagged, kTaggedPointer)                      \
  V(kTagged, kCompressed)                         \
  V(kTagged, kCompressedPointer)                  \
  V(kTaggedSigned, kWord32)                       \
  V(kTaggedSigned, kTagged)                       \
  V(kTaggedSigned, kTaggedSigned)                 \
  V(kTaggedSigned, kTaggedPointer)                \
  V(kTaggedSigned, kCompressed)                   \
  V(kTaggedSigned, kCompressedPointer)            \
  V(kTaggedPointer, kWord32)                      \
  V(kTaggedPointer, kTagged)                      \
  V(kTaggedPointer, kTaggedSigned)                \
  V(kTaggedPointer, kTaggedPointer)               \
  V(kTaggedPointer, kCompressed)                  \
  V(kTaggedPointer, kCompressedPointer)           \
  V(kCompressed, kWord32)                         \
  V(kCompressed, kTagged)                         \
  V(kCompressed, kTaggedSigned)                   \
  V(kCompressed, kTaggedPointer)                  \
  V(kCompressed, kCompressed)                     \
  V(kCompressed, kCompressedPointer)              \
  V(kCompressedPointer, kWord32)                  \
  V(kCompressedPointer, kTagged)                  \
  V(kCompressedPointer, kTaggedSigned)            \
  V(kCompressedPointer, kTaggedPointer)           \
  V(kCompressedPointer, kCompressed)              \
  V(kCompressedPointer, kCompressedPointer)       \
  V(kWord64, kWord64)

#else

#define STORE_PAIR_MACHINE_REPRESENTATION_LIST(V) \
  V(kWord32, kWord32)                             \
  V(kWord64, kWord64)                             \
  V(kWord64, kTagged)                             \
  V(kWord64, kTaggedSigned)                       \
  V(kWord64, kTaggedPointer)                      \
  V(kTagged, kWord64)                             \
  V(kTagged, kTagged)                             \
  V(kTagged, kTaggedSigned)                       \
  V(kTagged, kTaggedPointer)                      \
  V(kTaggedSigned, kWord64)                       \
  V(kTaggedSigned, kTagged)                       \
  V(kTaggedSigned, kTaggedSigned)                 \
  V(kTaggedSigned, kTaggedPointer)                \
  V(kTaggedPointer, kWord64)                      \
  V(kTaggedPointer, kTagged)                      \
  V(kTaggedPointer, kTaggedSigned)                \
  V(kTaggedPointer, kTaggedPointer)

#endif  // V8_COMPRESS_POINTERS

#else

#define STORE_PAIR_MACHINE_REPRESENTATION_LIST(V)

#endif  // V8_TARGET_ARCH_64_BIT

#define LOAD_TRANSFORM_LIST(V) \
  V(S128Load8Splat)            \
  V(S128Load16Splat)           \
  V(S128Load32Splat)           \
  V(S128Load64Splat)           \
  V(S128Load8x8S)              \
  V(S128Load8x8U)              \
  V(S128Load16x4S)             \
  V(S128Load16x4U)             \
  V(S128Load32x2S)             \
  V(S128Load32x2U)             \
  V(S128Load32Zero)            \
  V(S128Load64Zero)            \
  V(S256Load8Splat)            \
  V(S256Load16Splat)           \
  V(S256Load32Splat)           \
  V(S256Load64Splat)           \
  V(S256Load8x16S)             \
  V(S256Load8x16U)             \
  V(S256Load16x8S)             \
  V(S256Load16x8U)             \
  V(S256Load32x4S)             \
  V(S256Load32x4U)

#if TAGGED_SIZE_8_BYTES

#define ATOMIC_TAGGED_TYPE_LIST(V)

#define ATOMIC64_TAGGED_TYPE_LIST(V) \
  V(TaggedSigned)                    \
  V(TaggedPointer)                   \
  V(AnyTagged)                       \
  V(CompressedPointer)               \
  V(AnyCompressed)

#else

#define ATOMIC_TAGGED_TYPE_LIST(V) \
  V(TaggedSigned)                  \
  V(TaggedPointer)                 \
  V(AnyTagged)                     \
  V(CompressedPointer)             \
  V(AnyCompressed)

#define ATOMIC64_TAGGED_TYPE_LIST(V)

#endif  // TAGGED_SIZE_8_BYTES

#define ATOMIC_U32_TYPE_LIST(V) \
  V(Uint8)                      \
  V(Uint16)                     \
  V(Uint32)

#define ATOMIC_TYPE_LIST(V) \
  ATOMIC_U32_TYPE_LIST(V)   \
  V(Int8)                   \
  V(Int16)                  \
  V(Int32)

#define ATOMIC_U64_TYPE_LIST(V) \
  ATOMIC_U32_TYPE_LIST(V)       \
  V(Uint64)

#if TAGGED_SIZE_8_BYTES

#define ATOMIC_TAGGED_REPRESENTATION_LIST(V)

#define ATOMIC64_TAGGED_REPRESENTATION_LIST(V) \
  V(kTaggedSigned)                             \
  V(kTaggedPointer)                            \
  V(kTagged)

#else

#define ATOMIC_TAGGED_REPRESENTATION_LIST(V) \
  V(kTaggedSigned)                           \
  V(kTaggedPointer)                          \
  V(kTagged)                                 \
  V(kCompressedPointer)                      \
  V(kCompressed)

#define ATOMIC64_TAGGED_REPRESENTATION_LIST(V)

#endif  // TAGGED_SIZE_8_BYTES

#define ATOMIC_REPRESENTATION_LIST(V) \
  V(kWord8)                           \
  V(kWord16)                          \
  V(kWord32)

#define ATOMIC64_REPRESENTATION_LIST(V) \
  ATOMIC_REPRESENTATION_LIST(V)         \
  V(kWord64)

#define ATOMIC_PAIR_BINOP_LIST(V) \
  V(Add)                          \
  V(Sub)                          \
  V(And)                          \
  V(Or)                           \
  V(Xor)                          \
  V(Exchange)

#define SIMD_LANE_OP_LIST(V) \
  V(F64x2, 2)                \
  V(F32x4, 4)                \
  V(I64x2, 2)                \
  V(I32x4, 4)                \
  V(F16x8, 8)                \
  V(I16x8, 8)                \
  V(I8x16, 16)

#define SIMD_I64x2_LANES(V) V(0) V(1)

#define SIMD_I32x4_LANES(V) SIMD_I64x2_LANES(V) V(2) V(3)

#define SIMD_I16x8_LANES(V) SIMD_I32x4_LANES(V) V(4) V(5) V(6) V(7)

#define SIMD_I8x16_LANES(V) \
  SIMD_I16x8_LANES(V) V(8) V(9) V(10) V(11) V(12) V(13) V(14) V(15)

#define STACK_SLOT_CACHED_SIZES_ALIGNMENTS_LIST(V) \
  V(4, 0, false)                                   \
  V(8, 0, false) V(16, 0, false) V(4, 4, false) V(8, 8, false) V(16, 16, false)

struct StackSlotOperator : public Operator1<StackSlotRepresentation> {
  explicit StackSlotOperator(int size, int alignment, bool is_tagged)
      : Operator1<StackSlotRepresentation>(
        
"""


```