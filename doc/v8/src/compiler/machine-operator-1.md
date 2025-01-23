Response: The user wants to understand the functionality of the C++ code provided, which is the second part of a three-part file. This part seems to define a `MachineOperatorGlobalCache` struct that holds various `Operator` objects. These operators likely represent low-level machine instructions or operations used in the V8 compiler's intermediate representation (IR).

To summarize the functionality, I need to:
1. **Identify the core purpose of the `MachineOperatorGlobalCache` struct.** It appears to be a central repository for predefined machine operators.
2. **Analyze the types of operators defined.**  There are operators for loads, stores, atomic operations, bitcasts, stack manipulation, and more.
3. **Determine the relationship between these operators and JavaScript.**  These operators are used internally by the V8 engine to translate JavaScript code into machine code. Certain JavaScript operations will correspond to specific sequences of these low-level operators.
4. **Provide a JavaScript example.** I need to choose a simple JavaScript snippet and explain how it might relate to some of the defined operators. Memory access and atomic operations are good candidates.
Based on the C++ code snippet provided, this second part of `v8/src/compiler/machine-operator.cc` primarily focuses on **defining and caching a global collection of machine-level operators**.

Here's a breakdown of its functionality:

* **`MachineOperatorGlobalCache` Struct:** This struct acts as a central repository or cache for various pre-defined `Operator` objects. These `Operator` objects represent fundamental machine-level operations that the V8 compiler uses during the intermediate representation (IR) generation and optimization phases.

* **Operator Definitions:**  The code uses macros (`PURE`, `OVERFLOW_OP`, `LOAD`, `STORE`, `ATOMIC_OP`, etc.) to define different categories of machine operators. Each operator has specific properties like:
    * **`IrOpcode`:**  An identifier for the type of operation (e.g., `kLoad`, `kStore`, `kWord32AtomicAdd`).
    * **Properties:** Flags indicating characteristics of the operator (e.g., `kPure`, `kEliminatable`, `kNoDeopt`, `kNoThrow`).
    * **Name:** A descriptive string for the operator.
    * **Input/Output Counts:** The number of value inputs, control inputs, and outputs.
    * **Specific Parameters:** Some operators have additional parameters (e.g., `LoadRepresentation`, `StoreRepresentation`, `AtomicLoadParameters`).

* **Categories of Operators:** The defined operators cover a wide range of machine-level actions, including:
    * **Memory Access:** `Load`, `Store`, `UnalignedLoad`, `UnalignedStore`, `ProtectedLoad`, `ProtectedStore`, `LoadTrapOnNull`. These handle reading and writing data to memory.
    * **Stack Operations:** `StackSlot`. Represents allocation on the stack.
    * **Arithmetic and Logical Operations:**  While not explicitly in this snippet, the `MACHINE_PURE_OP_LIST` likely defines basic arithmetic and logical operations in other parts of the file. The `Word32Sar` and `Word64Sar` operators for bitwise shifts are present.
    * **Type Conversions:** `TruncateFloat32ToUint32`, `TruncateFloat64ToInt64`, `TruncateFloat32ToInt32`. These handle conversions between different numeric types.
    * **Atomic Operations:** `Word32AtomicLoad`, `Word32AtomicStore`, `Word32AtomicAdd`, `Word32AtomicCompareExchange`, etc. These provide thread-safe operations on memory locations.
    * **Bitwise Operations:** `BitcastWordToTagged`, `BitcastTaggedToWord`. These handle reinterpreting the bits of a value as a different type.
    * **Debugging and Control Flow:** `DebugBreak`, `Comment`, `MemoryBarrier`.
    * **WebAssembly Specific Operators:**  Operators with names like `I8x16Swizzle` and `LoadTransform` suggest support for WebAssembly features.

* **Global Caching:** By storing these operators in a global cache, the V8 compiler avoids repeatedly creating the same operator objects, improving efficiency.

**Relationship to JavaScript and Example:**

These machine operators are the building blocks that the V8 compiler uses to translate JavaScript code into executable machine instructions. When you write JavaScript code, the V8 engine parses it, creates an abstract syntax tree (AST), and then lowers it to an intermediate representation (IR) which uses these machine operators. Finally, this IR is translated into actual machine code for the target architecture.

Let's take an example involving memory access and a potential atomic operation:

**JavaScript Example:**

```javascript
let sharedArray = new Int32Array(new SharedArrayBuffer(4));
let index = 0;
sharedArray[index] = 10; // Store operation

// Potentially an atomic operation if multiple threads are involved
Atomics.add(sharedArray, index, 5);
console.log(sharedArray[index]); // Load operation
```

**How it relates to the C++ code:**

1. **`sharedArray[index] = 10;` (Store Operation):** This JavaScript statement will likely be translated into a sequence of machine operators. A key operator involved here would be a `Store` operator. Since `sharedArray` is an `Int32Array`, the specific operator might be something like `kStoreWord32NoWriteBarrier` (if no write barrier is needed in this context). The inputs to this operator would be the address of the element in `sharedArray`, and the value `10`.

2. **`Atomics.add(sharedArray, index, 5);` (Atomic Operation):** The `Atomics.add()` function in JavaScript directly corresponds to atomic operations at the machine level. This will be translated into a `Word32AtomicAdd` operator. The specific variant used might be `kWord32AtomicAddInt32Normal` (or `ProtectedByTrapHandler` depending on the context and platform). The inputs would be the address in `sharedArray`, and the value `5`.

3. **`console.log(sharedArray[index]);` (Load Operation):**  Accessing `sharedArray[index]` for reading involves a `Load` operator. Since it's an `Int32Array`, the operator might be `kLoadWord32`. The input would be the address of the element in `sharedArray`.

**In summary, this part of the `machine-operator.cc` file defines the vocabulary of low-level operations that the V8 compiler uses to represent and manipulate data and control flow during the compilation of JavaScript code.** It provides a set of fundamental building blocks that are essential for translating high-level JavaScript into efficient machine code.

### 提示词
```
这是目录为v8/src/compiler/machine-operator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
IrOpcode::kStackSlot, Operator::kNoDeopt | Operator::kNoThrow,
            "StackSlot", 0, 0, 0, 1, 0, 0,
            StackSlotRepresentation(size, alignment, is_tagged)) {}
};

struct MachineOperatorGlobalCache {
#define PURE(Name, properties, value_input_count, control_input_count,         \
             output_count)                                                     \
  struct Name##Operator final : public Operator {                              \
    Name##Operator()                                                           \
        : Operator(IrOpcode::k##Name, Operator::kPure | properties, #Name,     \
                   value_input_count, 0, control_input_count, output_count, 0, \
                   0) {}                                                       \
  };                                                                           \
  Name##Operator k##Name;
  MACHINE_PURE_OP_LIST(PURE)
  struct NormalWord32SarOperator final : public Operator1<ShiftKind> {
    NormalWord32SarOperator()
        : Operator1<ShiftKind>(IrOpcode::kWord32Sar, Operator::kPure,
                               "Word32Sar", 2, 0, 0, 1, 0, 0,
                               ShiftKind::kNormal) {}
  };
  NormalWord32SarOperator kNormalWord32Sar;
  struct ShiftOutZerosWord32SarOperator final : public Operator1<ShiftKind> {
    ShiftOutZerosWord32SarOperator()
        : Operator1<ShiftKind>(IrOpcode::kWord32Sar, Operator::kPure,
                               "Word32Sar", 2, 0, 0, 1, 0, 0,
                               ShiftKind::kShiftOutZeros) {}
  };
  ShiftOutZerosWord32SarOperator kShiftOutZerosWord32Sar;
  struct NormalWord64SarOperator final : public Operator1<ShiftKind> {
    NormalWord64SarOperator()
        : Operator1<ShiftKind>(IrOpcode::kWord64Sar, Operator::kPure,
                               "Word64Sar", 2, 0, 0, 1, 0, 0,
                               ShiftKind::kNormal) {}
  };
  NormalWord64SarOperator kNormalWord64Sar;
  struct ShiftOutZerosWord64SarOperator final : public Operator1<ShiftKind> {
    ShiftOutZerosWord64SarOperator()
        : Operator1<ShiftKind>(IrOpcode::kWord64Sar, Operator::kPure,
                               "Word64Sar", 2, 0, 0, 1, 0, 0,
                               ShiftKind::kShiftOutZeros) {}
  };
  ShiftOutZerosWord64SarOperator kShiftOutZerosWord64Sar;

  struct ArchitectureDefaultTruncateFloat32ToUint32Operator final
      : public Operator1<TruncateKind> {
    ArchitectureDefaultTruncateFloat32ToUint32Operator()
        : Operator1<TruncateKind>(IrOpcode::kTruncateFloat32ToUint32,
                                  Operator::kPure, "TruncateFloat32ToUint32", 1,
                                  0, 0, 1, 0, 0,
                                  TruncateKind::kArchitectureDefault) {}
  };
  ArchitectureDefaultTruncateFloat32ToUint32Operator
      kArchitectureDefaultTruncateFloat32ToUint32;
  struct SetOverflowToMinTruncateFloat32ToUint32Operator final
      : public Operator1<TruncateKind> {
    SetOverflowToMinTruncateFloat32ToUint32Operator()
        : Operator1<TruncateKind>(IrOpcode::kTruncateFloat32ToUint32,
                                  Operator::kPure, "TruncateFloat32ToUint32", 1,
                                  0, 0, 1, 0, 0,
                                  TruncateKind::kSetOverflowToMin) {}
  };
  SetOverflowToMinTruncateFloat32ToUint32Operator
      kSetOverflowToMinTruncateFloat32ToUint32;

  struct ArchitectureDefaultTruncateFloat32ToInt32Operator final
      : public Operator1<TruncateKind> {
    ArchitectureDefaultTruncateFloat32ToInt32Operator()
        : Operator1<TruncateKind>(IrOpcode::kTruncateFloat32ToInt32,
                                  Operator::kPure, "TruncateFloat32ToInt32", 1,
                                  0, 0, 1, 0, 0,
                                  TruncateKind::kArchitectureDefault) {}
  };
  ArchitectureDefaultTruncateFloat32ToInt32Operator
      kArchitectureDefaultTruncateFloat32ToInt32;
  struct SetOverflowToMinTruncateFloat32ToInt32Operator final
      : public Operator1<TruncateKind> {
    SetOverflowToMinTruncateFloat32ToInt32Operator()
        : Operator1<TruncateKind>(IrOpcode::kTruncateFloat32ToInt32,
                                  Operator::kPure, "TruncateFloat32ToInt32", 1,
                                  0, 0, 1, 0, 0,
                                  TruncateKind::kSetOverflowToMin) {}
  };
  SetOverflowToMinTruncateFloat32ToInt32Operator
      kSetOverflowToMinTruncateFloat32ToInt32;

  struct ArchitectureDefaultTruncateFloat64ToInt64Operator final
      : public Operator1<TruncateKind> {
    ArchitectureDefaultTruncateFloat64ToInt64Operator()
        : Operator1(IrOpcode::kTruncateFloat64ToInt64, Operator::kPure,
                    "TruncateFloat64ToInt64", 1, 0, 0, 1, 0, 0,
                    TruncateKind::kArchitectureDefault) {}
  };
  ArchitectureDefaultTruncateFloat64ToInt64Operator
      kArchitectureDefaultTruncateFloat64ToInt64;
  struct SetOverflowToMinTruncateFloat64ToInt64Operator final
      : public Operator1<TruncateKind> {
    SetOverflowToMinTruncateFloat64ToInt64Operator()
        : Operator1(IrOpcode::kTruncateFloat64ToInt64, Operator::kPure,
                    "TruncateFloat64ToInt64", 1, 0, 0, 1, 0, 0,
                    TruncateKind::kSetOverflowToMin) {}
  };
  SetOverflowToMinTruncateFloat64ToInt64Operator
      kSetOverflowToMinTruncateFloat64ToInt64;
  PURE_OPTIONAL_OP_LIST(PURE)
#undef PURE

#define OVERFLOW_OP(Name, properties)                                        \
  struct Name##Operator final : public Operator {                            \
    Name##Operator()                                                         \
        : Operator(IrOpcode::k##Name,                                        \
                   Operator::kEliminatable | Operator::kNoRead | properties, \
                   #Name, 2, 0, 1, 2, 0, 0) {}                               \
  };                                                                         \
  Name##Operator k##Name;
  OVERFLOW_OP_LIST(OVERFLOW_OP)
#undef OVERFLOW_OP

// ProtectedLoad and LoadTrapOnNull are not marked kNoWrite, so potentially
// trapping loads are not eliminated if their result is unused.
#define LOAD(Type)                                                             \
  struct Load##Type##Operator final : public Operator1<LoadRepresentation> {   \
    Load##Type##Operator()                                                     \
        : Operator1<LoadRepresentation>(IrOpcode::kLoad,                       \
                                        Operator::kEliminatable, "Load", 2, 1, \
                                        1, 1, 1, 0, MachineType::Type()) {}    \
  };                                                                           \
  struct UnalignedLoad##Type##Operator final                                   \
      : public Operator1<LoadRepresentation> {                                 \
    UnalignedLoad##Type##Operator()                                            \
        : Operator1<LoadRepresentation>(                                       \
              IrOpcode::kUnalignedLoad, Operator::kEliminatable,               \
              "UnalignedLoad", 2, 1, 1, 1, 1, 0, MachineType::Type()) {}       \
  };                                                                           \
  struct ProtectedLoad##Type##Operator final                                   \
      : public Operator1<LoadRepresentation> {                                 \
    ProtectedLoad##Type##Operator()                                            \
        : Operator1<LoadRepresentation>(                                       \
              IrOpcode::kProtectedLoad,                                        \
              Operator::kNoDeopt | Operator::kNoThrow, "ProtectedLoad", 2, 1,  \
              1, 1, 1, 0, MachineType::Type()) {}                              \
  };                                                                           \
  struct LoadTrapOnNull##Type##Operator final                                  \
      : public Operator1<LoadRepresentation> {                                 \
    LoadTrapOnNull##Type##Operator()                                           \
        : Operator1<LoadRepresentation>(                                       \
              IrOpcode::kLoadTrapOnNull,                                       \
              Operator::kNoDeopt | Operator::kNoThrow, "LoadTrapOnNull", 2, 1, \
              1, 1, 1, 0, MachineType::Type()) {}                              \
  };                                                                           \
  struct LoadImmutable##Type##Operator final                                   \
      : public Operator1<LoadRepresentation> {                                 \
    LoadImmutable##Type##Operator()                                            \
        : Operator1<LoadRepresentation>(IrOpcode::kLoadImmutable,              \
                                        Operator::kPure, "LoadImmutable", 2,   \
                                        0, 0, 1, 0, 0, MachineType::Type()) {} \
  };                                                                           \
  Load##Type##Operator kLoad##Type;                                            \
  UnalignedLoad##Type##Operator kUnalignedLoad##Type;                          \
  ProtectedLoad##Type##Operator kProtectedLoad##Type;                          \
  LoadTrapOnNull##Type##Operator kLoadTrapOnNull##Type;                        \
  LoadImmutable##Type##Operator kLoadImmutable##Type;
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD

#if V8_ENABLE_WEBASSEMBLY
#define LOAD_TRANSFORM_KIND(TYPE, KIND)                                \
  struct KIND##LoadTransform##TYPE##Operator final                     \
      : public Operator1<LoadTransformParameters> {                    \
    KIND##LoadTransform##TYPE##Operator()                              \
        : Operator1<LoadTransformParameters>(                          \
              IrOpcode::kLoadTransform,                                \
              MemoryAccessKind::k##KIND ==                             \
                      MemoryAccessKind::kProtectedByTrapHandler        \
                  ? Operator::kNoDeopt | Operator::kNoThrow            \
                  : Operator::kEliminatable,                           \
              #KIND "LoadTransform", 2, 1, 1, 1, 1, 0,                 \
              LoadTransformParameters{MemoryAccessKind::k##KIND,       \
                                      LoadTransformation::k##TYPE}) {} \
  };                                                                   \
  KIND##LoadTransform##TYPE##Operator k##KIND##LoadTransform##TYPE;

#define LOAD_TRANSFORM(TYPE)           \
  LOAD_TRANSFORM_KIND(TYPE, Normal)    \
  LOAD_TRANSFORM_KIND(TYPE, Unaligned) \
  LOAD_TRANSFORM_KIND(TYPE, ProtectedByTrapHandler)

  LOAD_TRANSFORM_LIST(LOAD_TRANSFORM)
#undef LOAD_TRANSFORM
#undef LOAD_TRANSFORM_KIND
#endif  // V8_ENABLE_WEBASSEMBLY

#define STACKSLOT(Size, Alignment, IsTagged)                               \
  struct StackSlotOfSize##Size##OfAlignment##Alignment##IsTagged##Operator \
      final : public StackSlotOperator {                                   \
    StackSlotOfSize##Size##OfAlignment##Alignment##IsTagged##Operator()    \
        : StackSlotOperator(Size, Alignment, IsTagged) {}                  \
  };                                                                       \
  StackSlotOfSize##Size##OfAlignment##Alignment##IsTagged##Operator        \
      kStackSlotOfSize##Size##OfAlignment##Alignment##IsTagged;
  STACK_SLOT_CACHED_SIZES_ALIGNMENTS_LIST(STACKSLOT)
#undef STACKSLOT

#define STORE(Type)                                                        \
  struct Store##Type##Operator : public Operator1<StoreRepresentation> {   \
    explicit Store##Type##Operator(WriteBarrierKind write_barrier_kind)    \
        : Operator1<StoreRepresentation>(                                  \
              IrOpcode::kStore,                                            \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "Store", 3, 1, 1, 0, 1, 0,                                   \
              StoreRepresentation(MachineRepresentation::Type,             \
                                  write_barrier_kind)) {}                  \
  };                                                                       \
  struct Store##Type##NoWriteBarrier##Operator final                       \
      : public Store##Type##Operator {                                     \
    Store##Type##NoWriteBarrier##Operator()                                \
        : Store##Type##Operator(kNoWriteBarrier) {}                        \
  };                                                                       \
  struct Store##Type##AssertNoWriteBarrier##Operator final                 \
      : public Store##Type##Operator {                                     \
    Store##Type##AssertNoWriteBarrier##Operator()                          \
        : Store##Type##Operator(kAssertNoWriteBarrier) {}                  \
  };                                                                       \
  struct Store##Type##MapWriteBarrier##Operator final                      \
      : public Store##Type##Operator {                                     \
    Store##Type##MapWriteBarrier##Operator()                               \
        : Store##Type##Operator(kMapWriteBarrier) {}                       \
  };                                                                       \
  struct Store##Type##PointerWriteBarrier##Operator final                  \
      : public Store##Type##Operator {                                     \
    Store##Type##PointerWriteBarrier##Operator()                           \
        : Store##Type##Operator(kPointerWriteBarrier) {}                   \
  };                                                                       \
  struct Store##Type##EphemeronKeyWriteBarrier##Operator final             \
      : public Store##Type##Operator {                                     \
    Store##Type##EphemeronKeyWriteBarrier##Operator()                      \
        : Store##Type##Operator(kEphemeronKeyWriteBarrier) {}              \
  };                                                                       \
  struct Store##Type##FullWriteBarrier##Operator final                     \
      : public Store##Type##Operator {                                     \
    Store##Type##FullWriteBarrier##Operator()                              \
        : Store##Type##Operator(kFullWriteBarrier) {}                      \
  };                                                                       \
  struct UnalignedStore##Type##Operator final                              \
      : public Operator1<UnalignedStoreRepresentation> {                   \
    UnalignedStore##Type##Operator()                                       \
        : Operator1<UnalignedStoreRepresentation>(                         \
              IrOpcode::kUnalignedStore,                                   \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "UnalignedStore", 3, 1, 1, 0, 1, 0,                          \
              MachineRepresentation::Type) {}                              \
  };                                                                       \
  struct ProtectedStore##Type##Operator                                    \
      : public Operator1<StoreRepresentation> {                            \
    explicit ProtectedStore##Type##Operator()                              \
        : Operator1<StoreRepresentation>(                                  \
              IrOpcode::kProtectedStore,                                   \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "ProtectedStore", 3, 1, 1, 0, 1, 0,                          \
              StoreRepresentation(MachineRepresentation::Type,             \
                                  kNoWriteBarrier)) {}                     \
  };                                                                       \
  struct StoreTrapOnNull##Type##FullWriteBarrier##Operator                 \
      : public Operator1<StoreRepresentation> {                            \
    explicit StoreTrapOnNull##Type##FullWriteBarrier##Operator()           \
        : Operator1<StoreRepresentation>(                                  \
              IrOpcode::kStoreTrapOnNull,                                  \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "StoreTrapOnNull", 3, 1, 1, 0, 1, 0,                         \
              StoreRepresentation(MachineRepresentation::Type,             \
                                  kFullWriteBarrier)) {}                   \
  };                                                                       \
  struct StoreTrapOnNull##Type##NoWriteBarrier##Operator                   \
      : public Operator1<StoreRepresentation> {                            \
    explicit StoreTrapOnNull##Type##NoWriteBarrier##Operator()             \
        : Operator1<StoreRepresentation>(                                  \
              IrOpcode::kStoreTrapOnNull,                                  \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "StoreTrapOnNull", 3, 1, 1, 0, 1, 0,                         \
              StoreRepresentation(MachineRepresentation::Type,             \
                                  kNoWriteBarrier)) {}                     \
  };                                                                       \
  Store##Type##NoWriteBarrier##Operator kStore##Type##NoWriteBarrier;      \
  Store##Type##AssertNoWriteBarrier##Operator                              \
      kStore##Type##AssertNoWriteBarrier;                                  \
  Store##Type##MapWriteBarrier##Operator kStore##Type##MapWriteBarrier;    \
  Store##Type##PointerWriteBarrier##Operator                               \
      kStore##Type##PointerWriteBarrier;                                   \
  Store##Type##EphemeronKeyWriteBarrier##Operator                          \
      kStore##Type##EphemeronKeyWriteBarrier;                              \
  Store##Type##FullWriteBarrier##Operator kStore##Type##FullWriteBarrier;  \
  UnalignedStore##Type##Operator kUnalignedStore##Type;                    \
  ProtectedStore##Type##Operator kProtectedStore##Type;                    \
  StoreTrapOnNull##Type##FullWriteBarrier##Operator                        \
      kStoreTrapOnNull##Type##FullWriteBarrier;                            \
  StoreTrapOnNull##Type##NoWriteBarrier##Operator                          \
      kStoreTrapOnNull##Type##NoWriteBarrier;
  MACHINE_REPRESENTATION_LIST(STORE)
#undef STORE

  friend std::ostream& operator<<(std::ostream& out,
                                  const StorePairRepresentation rep) {
    out << rep.first << "," << rep.second;
    return out;
  }

#define STORE_PAIR(Type1, Type2)                                           \
  struct StorePair##Type1##Type2##Operator                                 \
      : public Operator1<StorePairRepresentation> {                        \
    explicit StorePair##Type1##Type2##Operator(                            \
        WriteBarrierKind write_barrier_kind1,                              \
        WriteBarrierKind write_barrier_kind2)                              \
        : Operator1<StorePairRepresentation>(                              \
              IrOpcode::kStorePair,                                        \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "StorePair", 4, 1, 1, 0, 1, 0,                               \
              {                                                            \
                  StoreRepresentation(MachineRepresentation::Type1,        \
                                      write_barrier_kind1),                \
                  StoreRepresentation(MachineRepresentation::Type2,        \
                                      write_barrier_kind2),                \
              }) {}                                                        \
  };                                                                       \
  struct StorePair##Type1##Type2##NoWriteBarrier##Operator final           \
      : public StorePair##Type1##Type2##Operator {                         \
    StorePair##Type1##Type2##NoWriteBarrier##Operator()                    \
        : StorePair##Type1##Type2                                          \
          ##Operator(kNoWriteBarrier, kNoWriteBarrier) {}                  \
  };                                                                       \
  StorePair##Type1##Type2##NoWriteBarrier##Operator                        \
      kStorePair##Type1##Type2##NoWriteBarrier;

  STORE_PAIR_MACHINE_REPRESENTATION_LIST(STORE_PAIR)
#undef STORE_PAIR

  // Indirect pointer stores have an additional value input (the
  // IndirectPointerTag associated with the field being stored to), but
  // otherwise are identical to regular stores.
  struct StoreIndirectPointerOperator : public Operator1<StoreRepresentation> {
    explicit StoreIndirectPointerOperator(WriteBarrierKind write_barrier_kind)
        : Operator1<StoreRepresentation>(
              IrOpcode::kStoreIndirectPointer,
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow,
              "StoreIndirectPointer", 4, 1, 1, 0, 1, 0,
              StoreRepresentation(MachineRepresentation::kIndirectPointer,
                                  write_barrier_kind)) {}
  };
  struct StoreIndirectPointerNoWriteBarrierOperator final
      : public StoreIndirectPointerOperator {
    StoreIndirectPointerNoWriteBarrierOperator()
        : StoreIndirectPointerOperator(kNoWriteBarrier) {}
  };
  struct StoreIndirectPointerWithIndirectPointerWriteBarrierOperator final
      : public StoreIndirectPointerOperator {
    StoreIndirectPointerWithIndirectPointerWriteBarrierOperator()
        : StoreIndirectPointerOperator(kIndirectPointerWriteBarrier) {}
  };

  StoreIndirectPointerNoWriteBarrierOperator
      kStoreIndirectPointerNoWriteBarrier;
  StoreIndirectPointerWithIndirectPointerWriteBarrierOperator
      kStoreIndirectPointerIndirectPointerWriteBarrier;

#define ATOMIC_LOAD_WITH_KIND(Type, Kind)                           \
  struct Word32SeqCstLoad##Type##Kind##Operator                     \
      : public Operator1<AtomicLoadParameters> {                    \
    Word32SeqCstLoad##Type##Kind##Operator()                        \
        : Operator1<AtomicLoadParameters>(                          \
              IrOpcode::kWord32AtomicLoad, Operator::kNoProperties, \
              "Word32AtomicLoad", 2, 1, 1, 1, 1, 0,                 \
              AtomicLoadParameters(MachineType::Type(),             \
                                   AtomicMemoryOrder::kSeqCst,      \
                                   MemoryAccessKind::k##Kind)) {}   \
  };                                                                \
  Word32SeqCstLoad##Type##Kind##Operator kWord32SeqCstLoad##Type##Kind;
#define ATOMIC_LOAD(Type)             \
  ATOMIC_LOAD_WITH_KIND(Type, Normal) \
  ATOMIC_LOAD_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(ATOMIC_LOAD)
#undef ATOMIC_LOAD_WITH_KIND
#undef ATOMIC_LOAD

#define ATOMIC_LOAD_WITH_KIND(Type, Kind)                           \
  struct Word64SeqCstLoad##Type##Kind##Operator                     \
      : public Operator1<AtomicLoadParameters> {                    \
    Word64SeqCstLoad##Type##Kind##Operator()                        \
        : Operator1<AtomicLoadParameters>(                          \
              IrOpcode::kWord64AtomicLoad, Operator::kNoProperties, \
              "Word64AtomicLoad", 2, 1, 1, 1, 1, 0,                 \
              AtomicLoadParameters(MachineType::Type(),             \
                                   AtomicMemoryOrder::kSeqCst,      \
                                   MemoryAccessKind::k##Kind)) {}   \
  };                                                                \
  Word64SeqCstLoad##Type##Kind##Operator kWord64SeqCstLoad##Type##Kind;
#define ATOMIC_LOAD(Type)             \
  ATOMIC_LOAD_WITH_KIND(Type, Normal) \
  ATOMIC_LOAD_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(ATOMIC_LOAD)
#undef ATOMIC_LOAD_WITH_KIND
#undef ATOMIC_LOAD

#define ATOMIC_STORE_WITH_KIND(Type, Kind)                                 \
  struct Word32SeqCstStore##Type##Kind##Operator                           \
      : public Operator1<AtomicStoreParameters> {                          \
    Word32SeqCstStore##Type##Kind##Operator()                              \
        : Operator1<AtomicStoreParameters>(                                \
              IrOpcode::kWord32AtomicStore,                                \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "Word32AtomicStore", 3, 1, 1, 0, 1, 0,                       \
              AtomicStoreParameters(MachineRepresentation::Type,           \
                                    kNoWriteBarrier,                       \
                                    AtomicMemoryOrder::kSeqCst,            \
                                    MemoryAccessKind::k##Kind)) {}         \
  };                                                                       \
  Word32SeqCstStore##Type##Kind##Operator kWord32SeqCstStore##Type##Kind;
#define ATOMIC_STORE(Type)             \
  ATOMIC_STORE_WITH_KIND(Type, Normal) \
  ATOMIC_STORE_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_REPRESENTATION_LIST(ATOMIC_STORE)
#undef ATOMIC_STORE_WITH_KIND
#undef ATOMIC_STORE

#define ATOMIC_STORE_WITH_KIND(Type, Kind)                                 \
  struct Word64SeqCstStore##Type##Kind##Operator                           \
      : public Operator1<AtomicStoreParameters> {                          \
    Word64SeqCstStore##Type##Kind##Operator()                              \
        : Operator1<AtomicStoreParameters>(                                \
              IrOpcode::kWord64AtomicStore,                                \
              Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
              "Word64AtomicStore", 3, 1, 1, 0, 1, 0,                       \
              AtomicStoreParameters(MachineRepresentation::Type,           \
                                    kNoWriteBarrier,                       \
                                    AtomicMemoryOrder::kSeqCst,            \
                                    MemoryAccessKind::k##Kind)) {}         \
  };                                                                       \
  Word64SeqCstStore##Type##Kind##Operator kWord64SeqCstStore##Type##Kind;
#define ATOMIC_STORE(Type)             \
  ATOMIC_STORE_WITH_KIND(Type, Normal) \
  ATOMIC_STORE_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC64_REPRESENTATION_LIST(ATOMIC_STORE)
#undef ATOMIC_STORE_WITH_KIND
#undef ATOMIC_STORE

#define ATOMIC_OP(op, type, kind)                                              \
  struct op##type##kind##Operator : public Operator1<AtomicOpParameters> {     \
    op##type##kind##Operator()                                                 \
        : Operator1<AtomicOpParameters>(IrOpcode::k##op,                       \
                                 Operator::kNoDeopt | Operator::kNoThrow, #op, \
                                 3, 1, 1, 1, 1, 0,                             \
                                 AtomicOpParameters(MachineType::type(),       \
                                                    MemoryAccessKind::k##kind) \
                                 ){}                                           \
  };                                                                           \
  op##type##kind##Operator k##op##type##kind;
#define ATOMIC_OP_LIST_WITH_KIND(type, kind) \
  ATOMIC_OP(Word32AtomicAdd, type, kind)     \
  ATOMIC_OP(Word32AtomicSub, type, kind)     \
  ATOMIC_OP(Word32AtomicAnd, type, kind)     \
  ATOMIC_OP(Word32AtomicOr, type, kind)      \
  ATOMIC_OP(Word32AtomicXor, type, kind)     \
  ATOMIC_OP(Word32AtomicExchange, type, kind)
#define ATOMIC_OP_LIST(type)             \
  ATOMIC_OP_LIST_WITH_KIND(type, Normal) \
  ATOMIC_OP_LIST_WITH_KIND(type, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(ATOMIC_OP_LIST)
#undef ATOMIC_OP_LIST_WITH_KIND
#undef ATOMIC_OP_LIST
#define ATOMIC64_OP_LIST_WITH_KIND(type, kind) \
  ATOMIC_OP(Word64AtomicAdd, type, kind)       \
  ATOMIC_OP(Word64AtomicSub, type, kind)       \
  ATOMIC_OP(Word64AtomicAnd, type, kind)       \
  ATOMIC_OP(Word64AtomicOr, type, kind)        \
  ATOMIC_OP(Word64AtomicXor, type, kind)       \
  ATOMIC_OP(Word64AtomicExchange, type, kind)
#define ATOMIC64_OP_LIST(type)             \
  ATOMIC64_OP_LIST_WITH_KIND(type, Normal) \
  ATOMIC64_OP_LIST_WITH_KIND(type, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(ATOMIC64_OP_LIST)
#undef ATOMIC64_OP_LIST_WITH_KIND
#undef ATOMIC64_OP_LIST
#undef ATOMIC_OP

#define ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, Kind)                          \
  struct Word32AtomicCompareExchange##Type##Kind##Operator                     \
      : public Operator1<AtomicOpParameters> {                                 \
    Word32AtomicCompareExchange##Type##Kind##Operator()                        \
        : Operator1<AtomicOpParameters>(                                       \
                                 IrOpcode::kWord32AtomicCompareExchange,       \
                                 Operator::kNoDeopt | Operator::kNoThrow,      \
                                 "Word32AtomicCompareExchange", 4, 1, 1, 1, 1, \
                                 0,                                            \
                                 AtomicOpParameters(MachineType::Type(),       \
                                                    MemoryAccessKind::k##Kind) \
          ) {}                                                                 \
  };                                                                           \
  Word32AtomicCompareExchange##Type##Kind##Operator                            \
      kWord32AtomicCompareExchange##Type##Kind;
#define ATOMIC_COMPARE_EXCHANGE(Type)             \
  ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, Normal) \
  ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(ATOMIC_COMPARE_EXCHANGE)
#undef ATOMIC_COMPARE_EXCHANGE_WITH_KIND
#undef ATOMIC_COMPARE_EXCHANGE

#define ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, Kind)                          \
  struct Word64AtomicCompareExchange##Type##Kind##Operator                     \
      : public Operator1<AtomicOpParameters> {                                 \
    Word64AtomicCompareExchange##Type##Kind##Operator()                        \
        : Operator1<AtomicOpParameters>(                                       \
                                 IrOpcode::kWord64AtomicCompareExchange,       \
                                 Operator::kNoDeopt | Operator::kNoThrow,      \
                                 "Word64AtomicCompareExchange", 4, 1, 1, 1, 1, \
                                 0,                                            \
                                 AtomicOpParameters(MachineType::Type(),       \
                                                    MemoryAccessKind::k##Kind) \
          ) {}                                                                 \
  };                                                                           \
  Word64AtomicCompareExchange##Type##Kind##Operator                            \
      kWord64AtomicCompareExchange##Type##Kind;
#define ATOMIC_COMPARE_EXCHANGE(Type)             \
  ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, Normal) \
  ATOMIC_COMPARE_EXCHANGE_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(ATOMIC_COMPARE_EXCHANGE)
#undef ATOMIC_COMPARE_EXCHANGE_WITH_KIND
#undef ATOMIC_COMPARE_EXCHANGE

  struct Word32SeqCstPairLoadOperator : public Operator1<AtomicMemoryOrder> {
    Word32SeqCstPairLoadOperator()
        : Operator1<AtomicMemoryOrder>(IrOpcode::kWord32AtomicPairLoad,
                                       Operator::kNoDeopt | Operator::kNoThrow,
                                       "Word32AtomicPairLoad", 2, 1, 1, 2, 1, 0,
                                       AtomicMemoryOrder::kSeqCst) {}
  };
  Word32SeqCstPairLoadOperator kWord32SeqCstPairLoad;

  struct Word32SeqCstPairStoreOperator : public Operator1<AtomicMemoryOrder> {
    Word32SeqCstPairStoreOperator()
        : Operator1<AtomicMemoryOrder>(IrOpcode::kWord32AtomicPairStore,
                                       Operator::kNoDeopt | Operator::kNoThrow,
                                       "Word32AtomicPairStore", 4, 1, 1, 0, 1,
                                       0, AtomicMemoryOrder::kSeqCst) {}
  };
  Word32SeqCstPairStoreOperator kWord32SeqCstPairStore;

#define ATOMIC_PAIR_OP(op)                                      \
  struct Word32AtomicPair##op##Operator : public Operator {     \
    Word32AtomicPair##op##Operator()                            \
        : Operator(IrOpcode::kWord32AtomicPair##op,             \
                   Operator::kNoDeopt | Operator::kNoThrow,     \
                   "Word32AtomicPair" #op, 4, 1, 1, 2, 1, 0) {} \
  };                                                            \
  Word32AtomicPair##op##Operator kWord32AtomicPair##op;
  ATOMIC_PAIR_BINOP_LIST(ATOMIC_PAIR_OP)
#undef ATOMIC_PAIR_OP
#undef ATOMIC_PAIR_BINOP_LIST

  struct Word32AtomicPairCompareExchangeOperator : public Operator {
    Word32AtomicPairCompareExchangeOperator()
        : Operator(IrOpcode::kWord32AtomicPairCompareExchange,
                   Operator::kNoDeopt | Operator::kNoThrow,
                   "Word32AtomicPairCompareExchange", 6, 1, 1, 2, 1, 0) {}
  };
  Word32AtomicPairCompareExchangeOperator kWord32AtomicPairCompareExchange;

  template <AtomicMemoryOrder order>
  struct MemoryBarrierOperator : public Operator1<AtomicMemoryOrder> {
    MemoryBarrierOperator()
        : Operator1<AtomicMemoryOrder>(
              IrOpcode::kMemoryBarrier, Operator::kNoDeopt | Operator::kNoThrow,
              "SeqCstMemoryBarrier", 0, 1, 1, 0, 1, 0, order) {}
  };
  MemoryBarrierOperator<AtomicMemoryOrder::kSeqCst> kSeqCstMemoryBarrier;
  MemoryBarrierOperator<AtomicMemoryOrder::kAcqRel> kAcqRelMemoryBarrier;

  // The {BitcastWordToTagged} operator must not be marked as pure (especially
  // not idempotent), because otherwise the splitting logic in the Scheduler
  // might decide to split these operators, thus potentially creating live
  // ranges of allocation top across calls or other things that might allocate.
  // See https://bugs.chromium.org/p/v8/issues/detail?id=6059 for more details.
  struct BitcastWordToTaggedOperator : public Operator {
    BitcastWordToTaggedOperator()
        : Operator(IrOpcode::kBitcastWordToTagged,
                   Operator::kEliminatable | Operator::kNoWrite,
                   "BitcastWordToTagged", 1, 1, 1, 1, 1, 0) {}
  };
  BitcastWordToTaggedOperator kBitcastWordToTagged;

  struct BitcastTaggedToWordOperator : public Operator {
    BitcastTaggedToWordOperator()
        : Operator(IrOpcode::kBitcastTaggedToWord,
                   Operator::kEliminatable | Operator::kNoWrite,
                   "BitcastTaggedToWord", 1, 1, 1, 1, 1, 0) {}
  };
  BitcastTaggedToWordOperator kBitcastTaggedToWord;

  struct BitcastMaybeObjectToWordOperator : public Operator {
    BitcastMaybeObjectToWordOperator()
        : Operator(IrOpcode::kBitcastTaggedToWord,
                   Operator::kEliminatable | Operator::kNoWrite,
                   "BitcastMaybeObjectToWord", 1, 1, 1, 1, 1, 0) {}
  };
  BitcastMaybeObjectToWordOperator kBitcastMaybeObjectToWord;

  struct AbortCSADcheckOperator : public Operator {
    AbortCSADcheckOperator()
        : Operator(IrOpcode::kAbortCSADcheck, Operator::kNoThrow,
                   "AbortCSADcheck", 1, 1, 1, 0, 1, 0) {}
  };
  AbortCSADcheckOperator kAbortCSADcheck;

  struct DebugBreakOperator : public Operator {
    DebugBreakOperator()
        : Operator(IrOpcode::kDebugBreak, Operator::kNoThrow, "DebugBreak", 0,
                   1, 1, 0, 1, 0) {}
  };
  DebugBreakOperator kDebugBreak;

  struct StackPointerGreaterThanOperator : public Operator1<StackCheckKind> {
    explicit StackPointerGreaterThanOperator(StackCheckKind kind)
        : Operator1<StackCheckKind>(
              IrOpcode::kStackPointerGreaterThan, Operator::kEliminatable,
              "StackPointerGreaterThan", 1, 1, 0, 1, 1, 0, kind) {}
  };
#define STACK_POINTER_GREATER_THAN(Kind)                              \
  struct StackPointerGreaterThan##Kind##Operator final                \
      : public StackPointerGreaterThanOperator {                      \
    StackPointerGreaterThan##Kind##Operator()                         \
        : StackPointerGreaterThanOperator(StackCheckKind::k##Kind) {} \
  };                                                                  \
  StackPointerGreaterThan##Kind##Operator kStackPointerGreaterThan##Kind;

  STACK_POINTER_GREATER_THAN(JSFunctionEntry)
  STACK_POINTER_GREATER_THAN(CodeStubAssembler)
  STACK_POINTER_GREATER_THAN(Wasm)
#undef STACK_POINTER_GREATER_THAN

#if V8_ENABLE_WEBASSEMBLY
  struct I8x16SwizzleOperator final : public Operator1<bool> {
    I8x16SwizzleOperator()
        : Operator1<bool>(IrOpcode::kI8x16Swizzle, Operator::kPure,
                          "I8x16Swizzle", 2, 0, 0, 1, 0, 0, false) {}
  };
  I8x16SwizzleOperator kI8x16Swizzle;
  struct I8x16RelaxedSwizzleOperator final : public Operator1<bool> {
    I8x16RelaxedSwizzleOperator()
        : Operator1<bool>(IrOpcode::kI8x16Swizzle, Operator::kPure,
                          "I8x16RelaxedSwizzle", 2, 0, 0, 1, 0, 0, true) {}
  };
  I8x16RelaxedSwizzleOperator kI8x16RelaxedSwizzle;
#endif  // V8_ENABLE_WEBASSEMBLY
};

struct CommentOperator : public Operator1<const char*> {
  explicit CommentOperator(const char* msg)
      : Operator1<const char*>(IrOpcode::kComment,
                               Operator::kNoThrow | Operator::kNoWrite,
                               "Comment", 0, 1, 1, 0, 1, 0, msg) {}
};

namespace {
DEFINE_LAZY_LEAKY_OBJECT_GETTER(MachineOperatorGlobalCache,
                                GetMachineOperatorGlobalCache)
}

MachineOperatorBuilder::MachineOperatorBuilder(
    Zone* zone, MachineRepresentation word, Flags flags,
    AlignmentRequirements alignmentRequirements)
    : zone_(zone),
      cache_(*GetMachineOperatorGlobalCache()),
      word_(word),
      flags_(flags),
      alignment_requirements_(alignmentRequirements) {
  DCHECK(word == MachineRepresentation::kWord32 ||
         word == MachineRepresentation::kWord64);
}

const Operator* MachineOperatorBuilder::UnalignedLoad(LoadRepresentation rep) {
#define LOAD(Type)                       \
  if (rep == MachineType::Type()) {      \
    return &cache_.kUnalignedLoad##Type; \
  }
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::UnalignedStore(
    UnalignedStoreRepresentation rep) {
  switch (rep) {
#define STORE(kRep)                 \
  case MachineRepresentation::kRep: \
    return &cache_.kUnalignedStore##kRep;
    MACHINE_REPRESENTATION_LIST(STORE)
#undef STORE
    case MachineRepresentation::kBit:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

#define PURE(Name, properties, value_input_count, control_input_count, \
             output_count)                                             \
  const Operator* MachineOperatorBuilder::Name() { return &cache_.k##Name; }
MACHINE_PURE_OP_LIST(PURE)
#undef PURE

const Operator* MachineOperatorBuilder::Word32Sar(ShiftKind kind) {
  switch (kind) {
    case ShiftKind::kNormal:
      return &cache_.kNormalWord32Sar;
    case ShiftKind::kShiftOutZeros:
      return &cache_.kShiftOutZerosWord32Sar;
  }
}

const Operator* MachineOperatorBuilder::Word64Sar(ShiftKind kind) {
  switch (kind) {
    case ShiftKind::kNormal:
      return &cache_.kNormalWord64Sar;
    case ShiftKind::kShiftOutZeros:
      return &cache_.kShiftOutZerosWord64Sar;
  }
}

const Operator* MachineOperatorBuilder::TruncateFloat32ToUint32(
    TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return &cache_.kArchitectureDefaultTruncateFloat32ToUint32;
    case TruncateKind::kSetOverflowToMin:
      return &cache_.kSetOverflowToMinTruncateFloat32ToUint32;
  }
}

const Operator* MachineOperatorBuilder::TruncateFloat64ToInt64(
    TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return &cache_.kArchitectureDefaultTruncateFloat64ToInt64;
    case TruncateKind::kSetOverflowToMin:
      return &cache_.kSetOverflowToMinTruncateFloat64ToInt64;
  }
}

const Operator* MachineOperatorBuilder::TruncateFloat32ToInt32(
    TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return &cache_.kArchitectureDefaultTruncateFloat32ToInt32;
    case TruncateKind::kSetOverflowToMin:
      return &cache_.kSetOverflowToMinTruncateFloat32ToInt32;
  }
}

#define PURE(Name, properties, value_input_count, control_input_count, \
             output_count)                                             \
  const OptionalOperator MachineOperatorBuilder::Name() {              \
    return OptionalOperator(flags_ & k##Name, &cache_.k##Name);        \
  }
PURE_OPTIONAL_OP_LIST(PURE)
#undef PURE

#define OVERFLOW_OP(Name, properties) \
  const Operator* MachineOperatorBuilder::Name() { return &cache_.k##Name; }
OVERFLOW_OP_LIST(OVERFLOW_OP)
#undef OVERFLOW_OP

const Operator* MachineOperatorBuilder::TraceInstruction(uint32_t markid) {
  return zone_->New<Operator1<uint32_t>>(
      IrOpcode::kTraceInstruction, Operator::kNoDeopt | Operator::kNoThrow,
      "TraceInstruction", 0, 1, 1, 0, 1, 0, markid);
}

const Operator* MachineOperatorBuilder::Load(LoadRepresentation rep) {
  DCHECK(!rep.IsMapWord());
#define LOAD(Type)                  \
  if (rep == MachineType::Type()) { \
    return &cache_.kLoad##Type;     \
  }
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD
  UNREACHABLE();
}

// Represents a load from a position in memory that is known to be immutable,
// e.g. an immutable IsolateRoot or an immutable field of a WasmInstanceObject.
// Because the returned value cannot change through the execution of a function,
// LoadImmutable is a pure operator and does not have effect or control edges.
// Requires that the memory in question has been initialized at function start
// even through inlining.
const Operator* MachineOperatorBuilder::LoadImmutable(LoadRepresentation rep) {
#define LOAD(Type)                       \
  if (rep == MachineType::Type()) {      \
    return &cache_.kLoadImmutable##Type; \
  }
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::ProtectedLoad(LoadRepresentation rep) {
#define LOAD(Type)                       \
  if (rep == MachineType::Type()) {      \
    return &cache_.kProtectedLoad##Type; \
  }
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::LoadTrapOnNull(LoadRepresentation rep) {
#define LOAD(Type)                        \
  if (rep == MachineType::Type()) {       \
    return &cache_.kLoadTrapOnNull##Type; \
  }
  MACHINE_TYPE_LIST(LOAD)
#undef LOAD
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY
const Operator* MachineOperatorBuilder::LoadTransform(
    MemoryAccessKind kind, LoadTransformation transform) {
#define LOAD_TRANSFORM_KIND(TYPE, KIND)           \
  if (kind == MemoryAccessKind::k##KIND &&        \
      transform == LoadTransformation::k##TYPE) { \
    return &cache_.k##KIND##LoadTransform##TYPE;  \
  }
#define LOAD_TRANSFORM(TYPE)           \
  LOAD_TRANSFORM_KIND(TYPE, Normal)    \
  LOAD_TRANSFORM_KIND(TYPE, Unaligned) \
  LOAD_TRANSFORM_KIND(TYPE, ProtectedByTrapHandler)

  LOAD_TRANSFORM_LIST(LOAD_TRANSFORM)
#undef LOAD_TRANSFORM
#undef LOAD_TRANSFORM_KIND
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::LoadLane(MemoryAccessKind kind,
                                                 LoadRepresentation rep,
                                                 uint8_t laneidx) {
#define LOAD_LANE_KIND(TYPE, KIND, LANEIDX)                                    \
  if (kind == MemoryAccessKind::k##KIND && rep == MachineType::TYPE() &&       \
      laneidx == LANEIDX) {                                                    \
    return zone_->New<Operator1<LoadLaneParameters>>(                          \
        IrOpcode::kLoadLane,                                                   \
        MemoryAccessKind::k##KIND == MemoryAccessKind::kProtectedByTrapHandler \
            ? Operator::kNoDeopt | Operator::kNoThrow                          \
            : Operator::kEliminatable,                                         \
        "LoadLane", 3, 1, 1, 1, 1, 0,                                          \
        LoadLaneParameters{MemoryAccessKind::k##KIND,                          \
                           LoadRepresentation::TYPE(), LANEIDX});              \
  }

#define LOAD_LANE_T(T, LANE)         \
  LOAD_LANE_KIND(T, Normal, LANE)    \
  LOAD_LANE_KIND(T, Unaligned, LANE) \
  LOAD_LANE_KIND(T, ProtectedByTrapHandler, LANE)

#define LOAD_LANE_INT8(LANE) LOAD_LANE_T(Int8, LANE)
#define LOAD_LANE_INT16(LANE) LOAD_LANE_T(Int16, LANE)
#define LOAD_LANE_INT32(LANE) LOAD_LANE_T(Int32, LANE)
#define LOAD_LANE_INT64(LANE) LOAD_LANE_T(Int64, LANE)

  // Semicolons unnecessary, but helps formatting.
  SIMD_I8x16_LANES(LOAD_LANE_INT8);
  SIMD_I16x8_LANES(LOAD_LANE_INT16);
  SIMD_I32x4_LANES(LOAD_LANE_INT32);
  SIMD_I64x2_LANES(LOAD_LANE_INT64);
#undef LOAD_LANE_INT8
#undef LOAD_LANE_INT16
#undef LOAD_LANE_INT32
#undef LOAD_LANE_INT64
#undef LOAD_LANE_KIND
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::StoreLane(MemoryAccessKind kind,
                                                  MachineRepresentation rep,
                                                  uint8_t laneidx) {
#define STORE_LANE_KIND(REP, KIND, LANEIDX)                          \
  if (kind == MemoryAccessKind::k##KIND &&                           \
      rep == MachineRepresentation::REP && laneidx == LANEIDX) {     \
    return zone_->New<Operator1<StoreLaneParameters>>(               \
        IrOpcode::kStoreLane,                                        \
        Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
        "StoreLane", 3, 1, 1, 0, 1, 0,                               \
        StoreLaneParameters{MemoryAccessKind::k##KIND,               \
                            MachineRepresentation::REP, LANEIDX});   \
  }

#define STORE_LANE_T(T, LANE)         \
  STORE_LANE_KIND(T, Normal, LANE)    \
  STORE_LANE_KIND(T, Unaligned, LANE) \
  STORE_LANE_KIND(T, ProtectedByTrapHandler, LANE)

#define STORE_LANE_WORD8(LANE) STORE_LANE_T(kWord8, LANE)
#define STORE_LANE_WORD16(LANE) STORE_LANE_T(kWord16, LANE)
#define STORE_LANE_WORD32(LANE) STORE_LANE_T(kWord32, LANE)
#define STORE_LANE_WORD64(LANE) STORE_LANE_T(kWord64, LANE)

  // Semicolons unnecessary, but helps formatting.
  SIMD_I8x16_LANES(STORE_LANE_WORD8);
  SIMD_I16x8_LANES(STORE_LANE_WORD16);
  SIMD_I32x4_LANES(STORE_LANE_WORD32);
  SIMD_I64x2_LANES(STORE_LANE_WORD64);
#undef STORE_LANE_WORD8
#undef STORE_LANE_WORD16
#undef STORE_LANE_WORD32
#undef STORE_LANE_WORD64
#undef STORE_LANE_KIND
  UNREACHABLE();
}
#endif  // V8_ENABLE_WEBASSEMBLY

const Operator* MachineOperatorBuilder::StackSlot(int size, int alignment,
                                                  bool is_tagged) {
  DCHECK_LE(0, size);
  DCHECK(alignment == 0 || alignment == 4 || alignment == 8 || alignment == 16);
#define CASE_CACHED_SIZE(Size, Alignment, IsTagged)                          \
  if (size == Size && alignment == Alignment && is_tagged == IsTagged) {     \
    return &cache_.kStackSlotOfSize##Size##OfAlignment##Alignment##IsTagged; \
  }

  STACK_SLOT_CACHED_SIZES_ALIGNMENTS_LIST(CASE_CACHED_SIZE)

#undef CASE_CACHED_SIZE
  return zone_->New<StackSlotOperator>(size, alignment, is_tagged);
}

const Operator* MachineOperatorBuilder::StackSlot(MachineRepresentation rep,
                                                  int alignment) {
  return StackSlot(1 << ElementSizeLog2Of(rep), alignment);
}

const Operator* MachineOperatorBuilder::Store(StoreRepresentation store_rep) {
  DCHECK_NE(store_rep.representation(), MachineRepresentation::kMapWord);
  DCHECK_NE(store_rep.representation(),
            MachineRepresentation::kIndirectPointer);
  switch (store_rep.representation()) {
#define STORE(kRep)                                              \
  case MachineRepresentation::kRep:                              \
    switch (store_rep.write_barrier_kind()) {                    \
      case kNoWriteBarrier:                                      \
        return &cache_.k##Store##kRep##NoWriteBarrier;           \
      case kAssertNoWriteBarrier:                                \
        return &cache_.k##Store##kRep##AssertNoWriteBarrier;     \
      case kMapWriteBarrier:                                     \
        return &cache_.k##Store##kRep##MapWriteBarrier;          \
      case kPointerWriteBarrier:                                 \
        return &cache_.k##Store##kRep##PointerWriteBarrier;      \
      case kIndirectPointerWriteBarrier:                         \
        UNREACHABLE();                                           \
      case kEphemeronKeyWriteBarrier:                            \
        return &cache_.k##Store##kRep##EphemeronKeyWriteBarrier; \
      case kFullWriteBarrier:                                    \
        return &cache_.k##Store##kRep##FullWriteBarrier;         \
    }                                                            \
    break;
    MACHINE_REPRESENTATION_LIST(STORE)
#undef STORE
    case MachineRepresentation::kBit:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

const Operator* MachineOperatorBuilder::StoreIndirectPointer(
    WriteBarrierKind write_barrier_kind) {
  switch (write_barrier_kind) {
    case kNoWriteBarrier:
      return &cache_.kStoreIndirectPointerNoWriteBarrier;
    case kIndirectPointerWriteBarrier:
      return &cache_.kStoreIndirectPointerIndirectPointerWriteBarrier;
    default:
      UNREACHABLE();
  }
}

std::optional<const Operator*> MachineOperatorBuilder::TryStorePair(
    StoreRepresentation store_rep1, StoreRepresentation store_rep2) {
  DCHECK_NE(store_rep1.representation(), MachineRepresentation::kMapWord);

#define STORE(kRep1, kRep2)                                          \
  static_assert(ElementSizeLog2Of(MachineRepresentation::kRep1) ==   \
                ElementSizeLog2Of(MachineRepresentation::kRep2));    \
  if (MachineRepresentation::kRep1 == store_rep1.representation() && \
      MachineRepresentation::kRep2 == store_rep2.representation()) { \
    if (store_rep1.write_barrier_kind() != kNoWriteBarrier ||        \
        store_rep2.write_barrier_kind() != kNoWriteBarrier) {        \
      return {};                                                     \
    }                                                                \
    return &cache_.k##StorePair##kRep1##kRep2##NoWriteBarrier;       \
  }
  STORE_PAIR_MACHINE_REPRESENTATION_LIST(STORE);
#undef STORE
  return {};
}

const Operator* MachineOperatorBuilder::ProtectedStore(
    MachineRepresentation rep) {
  switch (rep) {
#define STORE(kRep)                 \
  case MachineRepresentation::kRep: \
    return &cache_.kProtectedStore##kRep;
    MACHINE_REPRESENTATION_LIST(STORE)
#undef STORE
    case MachineRepresentation::kBit:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

const Operator* MachineOperatorBuilder::StoreTrapOnNull(
    StoreRepresentation rep) {
  switch (rep.representation()) {
#define STORE(kRep)                                          \
  case MachineRepresentation::kRep:                          \
    if (rep.write_barrier_kind() == kNoWriteBarrier) {       \
      return &cache_.kStoreTrapOnNull##kRep##NoWriteBarrier; \
    }                                                        \
    DCHECK_EQ(kFullWriteBarrier, rep.write_barrier_kind());  \
    return &cache_.kStoreTrapOnNull##kRep##FullWriteBarrier;
    MACHINE_REPRESENTATION_LIST(STORE)
#undef STORE
    case MachineRepresentation::kBit:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

const Operator* MachineOperatorBuilder::StackPointerGreaterThan(
    StackCheckKind kind) {
  switch (kind) {
    case StackCheckKind::kJSFunctionEntry:
      return &cache_.kStackPointerGreaterThanJSFunctionEntry;
    case StackCheckKind::kCodeStubAssembler:
      return &cache_.kStackPointerGreaterThanCodeStubAssembler;
    case StackCheckKind::kWasm:
      return &cache_.kStackPointerGreaterThanWasm;
    case StackCheckKind::kJSIterationBody:
      UNREACHABLE();
  }
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::BitcastWordToTagged() {
  return &cache_.kBitcastWordToTagged;
}

const Operator* MachineOperatorBuilder::BitcastTaggedToWord() {
  return &cache_.kBitcastTaggedToWord;
}

const Operator* MachineOperatorBuilder::BitcastMaybeObjectToWord() {
  return &cache_.kBitcastMaybeObjectToWord;
}

const Operator* MachineOperatorBuilder::AbortCSADcheck() {
  return &cache_.kAbortCSADcheck;
}

const Operator* MachineOperatorBuilder::DebugBreak() {
  return &cache_.kDebugBreak;
}

const Operator* MachineOperatorBuilder::Comment(const char* msg) {
  return zone_->New<CommentOperator>(msg);
}

const Operator* MachineOperatorBuilder::MemoryBarrier(AtomicMemoryOrder order) {
  switch (order) {
    case AtomicMemoryOrder::kSeqCst:
      return &cache_.kSeqCstMemoryBarrier;
    case AtomicMemoryOrder::kAcqRel:
      return &cache_.kAcqRelMemoryBarrier;
    default:
      UNREACHABLE();
  }
}

const Operator* MachineOperatorBuilder::Word32AtomicLoad(
    AtomicLoadParameters params) {
#define CACHED_LOAD_WITH_KIND(Type, Kind)               \
  if (params.representation() == MachineType::Type() && \
      params.order() == AtomicMemoryOrder::kSeqCst &&   \
      params.kind() == MemoryAccessKind::k##Kind) {     \
    return &cache_.kWord32SeqCstLoad##Type##Kind;       \
  }
#define CACHED_LOAD(Type)             \
  CACHED_LOAD_WITH_KIND(Type, Normal) \
  CACHED_LOAD_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(CACHED_LOAD)
#undef CACHED_LOAD_WITH_KIND
#undef CACHED_LOAD

#define LOAD(Type)                                            \
  if (params.representation() == MachineType::Type()) {       \
    return zone_->New<Operator1<AtomicLoadParameters>>(       \
        IrOpcode::kWord32AtomicLoad, Operator::kNoProperties, \
        "Word32AtomicLoad", 2, 1, 1, 1, 1, 0, params);        \
  }
  ATOMIC_TYPE_LIST(LOAD)
  ATOMIC_TAGGED_TYPE_LIST(LOAD)
#undef LOAD

  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicStore(
    AtomicStoreParameters params) {
#define CACHED_STORE_WITH_KIND(kRep, Kind)                      \
  if (params.representation() == MachineRepresentation::kRep && \
      params.order() == AtomicMemoryOrder::kSeqCst &&           \
      params.kind() == MemoryAccessKind::k##Kind) {             \
    return &cache_.kWord32SeqCstStore##kRep##Kind;              \
  }
#define CACHED_STORE(kRep)             \
  CACHED_STORE_WITH_KIND(kRep, Normal) \
  CACHED_STORE_WITH_KIND(kRep, ProtectedByTrapHandler)
  ATOMIC_REPRESENTATION_LIST(CACHED_STORE)
#undef CACHED_STORE_WITH_KIND
#undef CACHED_STORE

#define STORE(kRep)                                                  \
  if (params.representation() == MachineRepresentation::kRep) {      \
    return zone_->New<Operator1<AtomicStoreParameters>>(             \
        IrOpcode::kWord32AtomicStore,                                \
        Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
        "Word32AtomicStore", 3, 1, 1, 0, 1, 0, params);              \
  }
  ATOMIC_REPRESENTATION_LIST(STORE)
  ATOMIC_TAGGED_REPRESENTATION_LIST(STORE)
#undef STORE
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicExchange(
    AtomicOpParameters params) {
#define EXCHANGE_WITH_KIND(kType, Kind)                \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicExchange##kType##Kind; \
  }
#define EXCHANGE(kType)             \
  EXCHANGE_WITH_KIND(kType, Normal) \
  EXCHANGE_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(EXCHANGE)
#undef EXCHANGE_WITH_KIND
#undef EXCHANGE
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicCompareExchange(
    AtomicOpParameters params) {
#define COMPARE_EXCHANGE_WITH_KIND(kType, Kind)               \
  if (params.type() == MachineType::kType()                   \
      && params.kind() == MemoryAccessKind::k##Kind) {        \
    return &cache_.kWord32AtomicCompareExchange##kType##Kind; \
  }
#define COMPARE_EXCHANGE(kType)             \
  COMPARE_EXCHANGE_WITH_KIND(kType, Normal) \
  COMPARE_EXCHANGE_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(COMPARE_EXCHANGE)
#undef COMPARE_EXCHANGE_WITH_KIND
#undef COMPARE_EXCHANGE
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicAdd(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicAdd##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicSub(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicSub##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicAnd(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicAnd##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicOr(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicOr##kType##Kind;       \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word32AtomicXor(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord32AtomicXor##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicLoad(
    AtomicLoadParameters params) {
#define CACHED_LOAD_WITH_KIND(Type, Kind)               \
  if (params.representation() == MachineType::Type() && \
      params.order() == AtomicMemoryOrder::kSeqCst &&   \
      params.kind() == MemoryAccessKind::k##Kind) {     \
    return &cache_.kWord64SeqCstLoad##Type##Kind;       \
  }
#define CACHED_LOAD(Type)             \
  CACHED_LOAD_WITH_KIND(Type, Normal) \
  CACHED_LOAD_WITH_KIND(Type, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(CACHED_LOAD)
#undef CACHED_LOAD_WITH_KIND
#undef CACHED_LOAD

#define LOAD(Type)                                            \
  if (params.representation() == MachineType::Type()) {       \
    return zone_->New<Operator1<AtomicLoadParameters>>(       \
        IrOpcode::kWord64AtomicLoad, Operator::kNoProperties, \
        "Word64AtomicLoad", 2, 1, 1, 1, 1, 0, params);        \
  }
  ATOMIC_U64_TYPE_LIST(LOAD)
  ATOMIC64_TAGGED_TYPE_LIST(LOAD)
#undef LOAD

  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicStore(
    AtomicStoreParameters params) {
#define CACHED_STORE_WITH_KIND(kRep, Kind)                      \
  if (params.representation() == MachineRepresentation::kRep && \
      params.order() == AtomicMemoryOrder::kSeqCst &&           \
      params.kind() == MemoryAccessKind::k##Kind) {             \
    return &cache_.kWord64SeqCstStore##kRep##Kind;              \
  }
#define CACHED_STORE(kRep)             \
  CACHED_STORE_WITH_KIND(kRep, Normal) \
  CACHED_STORE_WITH_KIND(kRep, ProtectedByTrapHandler)
  ATOMIC64_REPRESENTATION_LIST(CACHED_STORE)
#undef CACHED_STORE_WITH_KIND
#undef CACHED_STORE

#define STORE(kRep)                                                  \
  if (params.representation() == MachineRepresentation::kRep) {      \
    return zone_->New<Operator1<AtomicStoreParameters>>(             \
        IrOpcode::kWord64AtomicStore,                                \
        Operator::kNoDeopt | Operator::kNoRead | Operator::kNoThrow, \
        "Word64AtomicStore", 3, 1, 1, 0, 1, 0, params);              \
  }
  ATOMIC64_REPRESENTATION_LIST(STORE)
  ATOMIC64_TAGGED_REPRESENTATION_LIST(STORE)
#undef STORE

  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicAdd(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord64AtomicAdd##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicSub(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord64AtomicSub##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicAnd(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord64AtomicAnd##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicOr(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord64AtomicOr##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicXor(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                      \
  if (params.type() == MachineType::kType()            \
      && params.kind() == MemoryAccessKind::k##Kind) { \
    return &cache_.kWord64AtomicXor##kType##Kind;      \
  }
#define OP(kType)             \
  OP_WITH_KIND(kType, Normal) \
  OP_WITH_KIND(kType, ProtectedByTrapHandler)
  ATOMIC_U64_TYPE_LIST(OP)
#undef OP_WITH_KIND
#undef OP
  UNREACHABLE();
}

const Operator* MachineOperatorBuilder::Word64AtomicExchange(
    AtomicOpParameters params) {
#define OP_WITH_KIND(kType, Kind)                           \
  if (params.type() == MachineType::kType()                 \
```