Response:
The user provided a snippet of C++ code from the `v8/src/compiler/turboshaft/assembler.h` file and wants to understand its functionality.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the file type:** The filename `assembler.h` strongly suggests this is a header file for an assembler. The comment explicitly states it's a V8 source code file. The prompt also mentions checking for `.tq` extension for Torque, but since the filename is `.h`, it's C++.

2. **General purpose of an assembler:** An assembler's primary function is to generate machine code or an intermediate representation of machine code. In the context of a compiler like V8, this assembler will be part of the backend that transforms high-level code into executable instructions.

3. **Examine the provided code snippet:** The code mainly defines a class or struct (likely within the `v8::internal::compiler::turboshaft` namespace, based on the file path). It contains various methods that seem to manipulate values and memory.

4. **Analyze individual methods and groups of methods:**

   * **Constant Loading Methods:**  Functions like `HeapConstant`, `HeapConstantNoHole`, `HeapConstantHole`, `BuiltinCode`, `CompressedHeapConstant`, `ExternalConstant`, `IsolateField`, and the `RelocatableConstant` family all seem to be about creating representations of constant values in the generated code. The different variations likely handle different types of constants (heap objects, built-in functions, external references, etc.). The "Hole" variations likely relate to uninitialized values in V8.

   * **Type Conversion/Casting Methods:** The `DECL_CHANGE_V` and `DECL_TRY_CHANGE_V` macros, along with the numerous functions they define (e.g., `BitcastWord32ToWord64`, `ChangeInt32ToFloat64`, `TruncateFloat64ToWord32`), are clearly for performing type conversions and casting operations on the values being manipulated by the assembler. The "Try" versions likely indicate conversions that might fail or need special handling.

   * **Smi Manipulation:** The `TagSmi` and `UntagSmi` functions deal with Small Integers (Smis), a compact representation of integers used by V8.

   * **Atomic Operations:**  The `AtomicRMW`, `AtomicCompareExchange`, and `AtomicWord32Pair` family of functions indicate support for atomic read-modify-write operations, which are crucial for concurrent programming.

   * **Memory Access (Load/Store):**  The `Load` and `Store` functions, along with their variations like `LoadOffHeap`, `LoadFixedArrayElement`, `StoreField`, etc., are fundamental for reading and writing data to memory. The different variations handle different memory locations and access patterns (e.g., fields of objects, array elements, raw memory). The "ProtectedPointerField" and "TrustedPointerField" likely relate to V8's security mechanisms and object representation.

   * **Change Or Deopt:** The `ChangeOrDeopt` family of functions suggests a mechanism for changing the representation of a value and potentially triggering a deoptimization if the change is not safe. This is a common optimization technique in JIT compilers.

5. **Look for patterns and abstractions:** The use of templates and macros (`DECL_CHANGE_V`, `DECL_TRY_CHANGE_V`, `DECL_SIGNED_FLOAT_TRUNCATE`, `DECL_UNSIGNED_FLOAT_TRUNCATE`) suggests an attempt to create reusable code patterns for similar operations. The `ReduceIfReachable...` prefixes on many methods likely indicate optimizations related to constant folding or dead code elimination.

6. **Relate to JavaScript functionality:**  Since V8 is the JavaScript engine for Chrome and Node.js, these low-level operations are the foundation for executing JavaScript code. For example, loading a property of an object in JavaScript will eventually translate to `LoadField` operations. Performing arithmetic operations will use the type conversion functions.

7. **Consider common programming errors:** The type conversion functions and the memory access functions are potential sources of errors. Incorrectly casting between types or accessing memory out of bounds are common issues.

8. **Address the specific questions in the prompt:**

   * **Functionality Listing:** Summarize the identified functionalities based on the method analysis.
   * **Torque Source:** Confirm that the `.h` extension means it's not a Torque file.
   * **JavaScript Relationship:** Provide JavaScript examples to illustrate how the assembler's functions relate to high-level JavaScript operations.
   * **Code Logic and Examples:** Create simple examples with hypothetical inputs and outputs for some of the functions.
   * **Common Errors:** Give examples of programming errors related to type conversions and memory access.
   * **Part 4 of 8:** Note the context provided in the prompt.
   * **Summary:** Condense the main functionalities into a concise summary.

By following these steps, we can analyze the provided code snippet and generate a comprehensive explanation of its functionality. The key is to understand the role of an assembler in a compiler and then to carefully examine the provided methods and their names to infer their purpose.
好的，让我们来分析一下这段 `v8/src/compiler/turboshaft/assembler.h` 代码片段的功能。

**功能归纳:**

这段代码是 V8 Turboshaft 编译器的汇编器（Assembler）头文件的一部分，主要负责提供构建 Turboshaft 中间表示（IR）指令的接口。它定义了一系列方法，用于生成表示各种操作的节点，例如加载常量、进行类型转换、执行原子操作、进行内存访问等。

**具体功能列举:**

1. **加载常量 (Constant Loading):**
   - `HeapConstant`: 加载堆上的常量对象。
   - `HeapConstantNoHole`: 加载已知不是 "hole" 值的堆常量。
   - `HeapConstantHole`: 加载 "hole" 值的堆常量。
   - `BuiltinCode`: 加载内置函数的代码对象。
   - `CompressedHeapConstant`: 加载压缩的堆常量。
   - `TrustedHeapConstant`: 加载受信任的堆常量。
   - `ExternalConstant`: 加载外部常量引用。
   - `IsolateField`: 加载 Isolate 对象的字段。
   - `RelocatableConstant`: 加载需要重定位的常量，主要用于 WASM。
   - `RelocatableWasmBuiltinCallTarget`: 加载 WASM 内置函数调用的目标地址。
   - `RelocatableWasmCanonicalSignatureId`: 加载 WASM 规范签名 ID。
   - `RelocatableWasmIndirectCallTarget`: 加载 WASM 间接调用目标。
   - `NoContextConstant`: 加载表示没有上下文的常量。
   - `CEntryStubConstant`: 加载 C++ 入口桩的常量。

2. **类型转换 (Type Conversion):**
   - 使用宏 `DECL_CHANGE_V` 和 `DECL_TRY_CHANGE_V` 定义了大量的类型转换函数，例如：
     - `BitcastWord32ToWord64`: 将 32 位字按位转换为 64 位字。
     - `ChangeUint32ToUint64`: 将无符号 32 位整数扩展为无符号 64 位整数。
     - `ChangeInt32ToFloat64`: 将有符号 32 位整数转换为 64 位浮点数。
     - `TruncateFloat64ToFloat32`: 将 64 位浮点数截断为 32 位浮点数。
     - 等等。
   - 这些函数允许在不同的数据类型和表示之间进行转换，例如整数到浮点数，不同位宽的整数之间，以及位级别的重新解释。

3. **Smi 操作 (Smi Operations):**
   - `TagSmi`: 将一个 32 位整数标记为 Smi (Small Integer)。
   - `UntagSmi`: 从一个 Smi 中提取原始的 32 位整数值。

4. **原子操作 (Atomic Operations):**
   - `AtomicRMW`: 执行原子读-修改-写操作。
   - `AtomicCompareExchange`: 执行原子比较并交换操作。
   - `AtomicWord32Pair`: 执行 64 位原子操作（基于两个 32 位字）。
   - `MemoryBarrier`: 插入内存屏障，用于保证内存操作的顺序性。

5. **内存访问 (Memory Access):**
   - `Load`: 从内存中加载数据。
   - `Store`: 将数据存储到内存中。
   - `LoadOffHeap`: 从堆外内存加载数据。
   - `StoreOffHeap`: 将数据存储到堆外内存。
   - `LoadField`: 加载对象的字段。
   - `StoreField`: 存储对象的字段。
   - `LoadFixedArrayElement`: 加载固定数组的元素。
   - `StoreFixedArrayElement`: 存储固定数组的元素。
   - `LoadFixedDoubleArrayElement`: 加载双精度浮点数固定数组的元素。
   - `StoreFixedDoubleArrayElement`: 存储双精度浮点数固定数组的元素。
   - `LoadProtectedPointerField`: 加载受保护的指针字段。
   - `LoadTrustedPointerField`: 加载受信任的指针字段。

6. **Deopt 相关操作 (Deoptimization Related Operations):**
   - `ChangeOrDeopt`: 执行类型转换，如果转换失败则触发反优化 (deoptimization)。
   - `ChangeFloat64ToInt32OrDeopt` 等系列函数：特定类型的带反优化的转换。

**关于文件类型和 JavaScript 关系:**

- **`.tq` 结尾:** 你说的是对的，如果 `v8/src/compiler/turboshaft/assembler.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。但根据你提供的文件名，它是一个 C++ 头文件 (`.h`)。
- **与 JavaScript 的关系:**  `assembler.h` 中定义的功能是编译 JavaScript 代码的核心组成部分。当 V8 编译 JavaScript 代码时，Turboshaft 编译器会生成一系列操作，这些操作最终会通过这里的 Assembler 类生成底层的机器码或者中间表示。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

const obj = { x: 10 };
const y = obj.x;

const arr = [1.5, 2.5];
const firstElement = arr[0];
```

在 Turboshaft 编译 `add` 函数时，可能会用到以下 `assembler.h` 中的功能：

- 加载局部变量 `a` 和 `b` 的值。
- 执行加法操作（可能涉及类型转换，例如 `ChangeInt32ToFloat64` 如果是浮点数加法）。
- 返回结果。

编译访问 `obj.x` 时，可能会用到：

- `LoadField` 加载对象 `obj` 的 `x` 字段。

编译访问 `arr[0]` 时，可能会用到：

- `LoadFixedDoubleArrayElement` 加载双精度浮点数数组的元素。

**代码逻辑推理和假设输入输出:**

假设我们有以下代码：

```c++
Assembler assembler(...); // 假设已创建 Assembler 对象
Handle<Smi> smi_handle = isolate->factory()->NewSmi(10);
auto smi_value = assembler.HeapConstant(smi_handle);
auto untagged_value = assembler.UntagSmi(smi_value);
```

**假设输入:**

- `smi_handle` 指向一个值为 10 的 Smi 对象。

**输出:**

- `smi_value` 将会是一个表示加载 `smi_handle` 指向的 Smi 常量的 `OpIndex` 或 `V<Smi>`。
- `untagged_value` 将会是一个 `V<Word32>`，其值是 10 (Smi 被解标签后的原始整数值)。

**用户常见的编程错误示例:**

1. **错误的类型转换:**

   ```c++
   V<Float64> float_val = assembler.Float64Constant(3.14);
   V<Word32> int_val = assembler.BitcastFloat64ToWord32(float_val);
   ```
   这个例子中，直接将一个浮点数的位表示解释为一个整数，而不是进行数值转换。这会导致 `int_val` 的值与 3.14 的整数部分 (3) 完全不同。应该使用 `assembler.TruncateFloat64ToWord32` 来进行浮点数到整数的截断。

2. **不正确的内存访问偏移量:**

   ```c++
   V<FixedArray> array = ...;
   // 假设数组元素是 Tagged 指针
   V<Object> element = assembler.Load(array, LoadOp::Kind::TaggedBase(), MemoryRepresentation::AnyTagged(), 100);
   ```
   如果固定数组的元素偏移量不是 100 字节，那么这将导致访问错误的内存位置，可能读取到无效的数据甚至导致程序崩溃。正确的偏移量应该使用 `FixedArray::OffsetOfElementAt(index)`。

**第 4 部分功能归纳:**

作为第 4 部分，这段代码主要关注的是 **值的表示和基本操作**。它提供了创建和操作各种类型值的接口，包括常量、基本数据类型以及堆上的对象。核心功能围绕着如何将高级语言的概念转化为编译器内部的低级表示，并提供进行必要转换和操作的工具。这部分是构建更复杂操作的基础，例如算术运算、对象属性访问和数组元素访问等，这些功能很可能会在后续的部分中出现。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
ntMaybeHole(Handle<T> value) {
    return __ HeapConstant(value);
  }
  template <typename T,
            typename = std::enable_if_t<is_subtype_v<T, HeapObject>>>
  V<T> HeapConstantNoHole(Handle<T> value) {
    CHECK(!IsAnyHole(*value));
    return __ HeapConstant(value);
  }
  V<HeapObject> HeapConstantHole(Handle<HeapObject> value) {
    DCHECK(IsAnyHole(*value));
    return __ HeapConstant(value);
  }
  V<Code> BuiltinCode(Builtin builtin, Isolate* isolate) {
    return HeapConstant(BuiltinCodeHandle(builtin, isolate));
  }
  OpIndex CompressedHeapConstant(Handle<HeapObject> value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kHeapObject, value);
  }
  OpIndex TrustedHeapConstant(Handle<HeapObject> value) {
    DCHECK(IsTrustedObject(*value));
    return ReduceIfReachableConstant(ConstantOp::Kind::kTrustedHeapObject,
                                     value);
  }
  OpIndex ExternalConstant(ExternalReference value) {
    return ReduceIfReachableConstant(ConstantOp::Kind::kExternal, value);
  }
  OpIndex IsolateField(IsolateFieldId id) {
    return ExternalConstant(ExternalReference::Create(id));
  }
  V<WordPtr> RelocatableConstant(int64_t value, RelocInfo::Mode mode) {
    DCHECK_EQ(mode, any_of(RelocInfo::WASM_CALL, RelocInfo::WASM_STUB_CALL));
    return ReduceIfReachableConstant(
        mode == RelocInfo::WASM_CALL
            ? ConstantOp::Kind::kRelocatableWasmCall
            : ConstantOp::Kind::kRelocatableWasmStubCall,
        static_cast<uint64_t>(value));
  }

  V<WordPtr> RelocatableWasmBuiltinCallTarget(Builtin builtin) {
    return RelocatableConstant(static_cast<int64_t>(builtin),
                               RelocInfo::WASM_STUB_CALL);
  }

  V<Word32> RelocatableWasmCanonicalSignatureId(uint32_t canonical_id) {
    return ReduceIfReachableConstant(
        ConstantOp::Kind::kRelocatableWasmCanonicalSignatureId,
        static_cast<uint64_t>(canonical_id));
  }

  V<WasmCodePtr> RelocatableWasmIndirectCallTarget(uint32_t function_index) {
    return ReduceIfReachableConstant(
        ConstantOp::Kind::kRelocatableWasmIndirectCallTarget, function_index);
  }

  V<Context> NoContextConstant() {
    return V<Context>::Cast(TagSmi(Context::kNoContext));
  }

  // TODO(nicohartmann@): Might want to get rid of the isolate when supporting
  // Wasm.
  V<Code> CEntryStubConstant(Isolate* isolate, int result_size,
                             ArgvMode argv_mode = ArgvMode::kStack,
                             bool builtin_exit_frame = false) {
    if (argv_mode != ArgvMode::kStack) {
      return HeapConstant(CodeFactory::CEntry(isolate, result_size, argv_mode,
                                              builtin_exit_frame));
    }

    DCHECK(result_size >= 1 && result_size <= 3);
    DCHECK_IMPLIES(builtin_exit_frame, result_size == 1);
    const int index = builtin_exit_frame ? 0 : result_size;
    if (cached_centry_stub_constants_[index].is_null()) {
      cached_centry_stub_constants_[index] = CodeFactory::CEntry(
          isolate, result_size, argv_mode, builtin_exit_frame);
    }
    return HeapConstant(cached_centry_stub_constants_[index].ToHandleChecked());
  }

#define DECL_CHANGE_V(name, kind, assumption, from, to)                  \
  V<to> name(ConstOrV<from> input) {                                     \
    return ReduceIfReachableChange(resolve(input), ChangeOp::Kind::kind, \
                                   ChangeOp::Assumption::assumption,     \
                                   V<from>::rep, V<to>::rep);            \
  }
#define DECL_TRY_CHANGE_V(name, kind, from, to)                       \
  V<turboshaft::Tuple<to, Word32>> name(V<from> input) {              \
    return ReduceIfReachableTryChange(input, TryChangeOp::Kind::kind, \
                                      V<from>::rep, V<to>::rep);      \
  }

  DECL_CHANGE_V(BitcastWord32ToWord64, kBitcast, kNoAssumption, Word32, Word64)
  DECL_CHANGE_V(BitcastFloat32ToWord32, kBitcast, kNoAssumption, Float32,
                Word32)
  DECL_CHANGE_V(BitcastWord32ToFloat32, kBitcast, kNoAssumption, Word32,
                Float32)
  DECL_CHANGE_V(BitcastFloat64ToWord64, kBitcast, kNoAssumption, Float64,
                Word64)
  DECL_CHANGE_V(BitcastWord64ToFloat64, kBitcast, kNoAssumption, Word64,
                Float64)
  DECL_CHANGE_V(ChangeUint32ToUint64, kZeroExtend, kNoAssumption, Word32,
                Word64)
  DECL_CHANGE_V(ChangeInt32ToInt64, kSignExtend, kNoAssumption, Word32, Word64)
  DECL_CHANGE_V(ChangeInt32ToFloat64, kSignedToFloat, kNoAssumption, Word32,
                Float64)
  DECL_CHANGE_V(ChangeInt64ToFloat64, kSignedToFloat, kNoAssumption, Word64,
                Float64)
  DECL_CHANGE_V(ChangeInt32ToFloat32, kSignedToFloat, kNoAssumption, Word32,
                Float32)
  DECL_CHANGE_V(ChangeInt64ToFloat32, kSignedToFloat, kNoAssumption, Word64,
                Float32)
  DECL_CHANGE_V(ChangeUint32ToFloat32, kUnsignedToFloat, kNoAssumption, Word32,
                Float32)
  DECL_CHANGE_V(ChangeUint64ToFloat32, kUnsignedToFloat, kNoAssumption, Word64,
                Float32)
  DECL_CHANGE_V(ReversibleInt64ToFloat64, kSignedToFloat, kReversible, Word64,
                Float64)
  DECL_CHANGE_V(ChangeUint64ToFloat64, kUnsignedToFloat, kNoAssumption, Word64,
                Float64)
  DECL_CHANGE_V(ReversibleUint64ToFloat64, kUnsignedToFloat, kReversible,
                Word64, Float64)
  DECL_CHANGE_V(ChangeUint32ToFloat64, kUnsignedToFloat, kNoAssumption, Word32,
                Float64)
  DECL_CHANGE_V(TruncateFloat64ToFloat32, kFloatConversion, kNoAssumption,
                Float64, Float32)
  DECL_CHANGE_V(TruncateFloat64ToFloat16RawBits, kJSFloat16TruncateWithBitcast,
                kNoAssumption, Float64, Word32)
  DECL_CHANGE_V(ChangeFloat32ToFloat64, kFloatConversion, kNoAssumption,
                Float32, Float64)
  DECL_CHANGE_V(JSTruncateFloat64ToWord32, kJSFloatTruncate, kNoAssumption,
                Float64, Word32)
  DECL_CHANGE_V(TruncateWord64ToWord32, kTruncate, kNoAssumption, Word64,
                Word32)
  V<Word> ZeroExtendWord32ToRep(V<Word32> value, WordRepresentation rep) {
    if (rep == WordRepresentation::Word32()) return value;
    DCHECK_EQ(rep, WordRepresentation::Word64());
    return ChangeUint32ToUint64(value);
  }
  V<Word32> TruncateWordPtrToWord32(ConstOrV<WordPtr> input) {
    if constexpr (Is64()) {
      return TruncateWord64ToWord32(input);
    } else {
      DCHECK_EQ(WordPtr::bits, Word32::bits);
      return V<Word32>::Cast(resolve(input));
    }
  }
  V<WordPtr> ChangeInt32ToIntPtr(V<Word32> input) {
    if constexpr (Is64()) {
      return ChangeInt32ToInt64(input);
    } else {
      DCHECK_EQ(WordPtr::bits, Word32::bits);
      return V<WordPtr>::Cast(input);
    }
  }
  V<WordPtr> ChangeUint32ToUintPtr(V<Word32> input) {
    if constexpr (Is64()) {
      return ChangeUint32ToUint64(input);
    } else {
      DCHECK_EQ(WordPtr::bits, Word32::bits);
      return V<WordPtr>::Cast(input);
    }
  }

  V<Word64> ChangeIntPtrToInt64(V<WordPtr> input) {
    if constexpr (Is64()) {
      DCHECK_EQ(WordPtr::bits, Word64::bits);
      return V<Word64>::Cast(input);
    } else {
      return ChangeInt32ToInt64(input);
    }
  }

  V<Word64> ChangeUintPtrToUint64(V<WordPtr> input) {
    if constexpr (Is64()) {
      DCHECK_EQ(WordPtr::bits, Word64::bits);
      return V<Word64>::Cast(input);
    } else {
      return ChangeUint32ToUint64(input);
    }
  }

  V<Word32> IsSmi(V<Object> object) {
    if constexpr (COMPRESS_POINTERS_BOOL) {
      return Word32Equal(Word32BitwiseAnd(V<Word32>::Cast(object), kSmiTagMask),
                         kSmiTag);
    } else {
      return WordPtrEqual(
          WordPtrBitwiseAnd(V<WordPtr>::Cast(object), kSmiTagMask), kSmiTag);
    }
  }

#define DECL_SIGNED_FLOAT_TRUNCATE(FloatBits, ResultBits)                    \
  DECL_CHANGE_V(                                                             \
      TruncateFloat##FloatBits##ToInt##ResultBits##OverflowUndefined,        \
      kSignedFloatTruncateOverflowToMin, kNoOverflow, Float##FloatBits,      \
      Word##ResultBits)                                                      \
  DECL_TRY_CHANGE_V(TryTruncateFloat##FloatBits##ToInt##ResultBits,          \
                    kSignedFloatTruncateOverflowUndefined, Float##FloatBits, \
                    Word##ResultBits)

  DECL_SIGNED_FLOAT_TRUNCATE(64, 64)
  DECL_SIGNED_FLOAT_TRUNCATE(64, 32)
  DECL_SIGNED_FLOAT_TRUNCATE(32, 64)
  DECL_SIGNED_FLOAT_TRUNCATE(32, 32)
#undef DECL_SIGNED_FLOAT_TRUNCATE
  DECL_CHANGE_V(TruncateFloat64ToInt64OverflowToMin,
                kSignedFloatTruncateOverflowToMin, kNoAssumption, Float64,
                Word64)
  DECL_CHANGE_V(TruncateFloat32ToInt32OverflowToMin,
                kSignedFloatTruncateOverflowToMin, kNoAssumption, Float32,
                Word32)

#define DECL_UNSIGNED_FLOAT_TRUNCATE(FloatBits, ResultBits)                    \
  DECL_CHANGE_V(                                                               \
      TruncateFloat##FloatBits##ToUint##ResultBits##OverflowUndefined,         \
      kUnsignedFloatTruncateOverflowToMin, kNoOverflow, Float##FloatBits,      \
      Word##ResultBits)                                                        \
  DECL_CHANGE_V(TruncateFloat##FloatBits##ToUint##ResultBits##OverflowToMin,   \
                kUnsignedFloatTruncateOverflowToMin, kNoAssumption,            \
                Float##FloatBits, Word##ResultBits)                            \
  DECL_TRY_CHANGE_V(TryTruncateFloat##FloatBits##ToUint##ResultBits,           \
                    kUnsignedFloatTruncateOverflowUndefined, Float##FloatBits, \
                    Word##ResultBits)

  DECL_UNSIGNED_FLOAT_TRUNCATE(64, 64)
  DECL_UNSIGNED_FLOAT_TRUNCATE(64, 32)
  DECL_UNSIGNED_FLOAT_TRUNCATE(32, 64)
  DECL_UNSIGNED_FLOAT_TRUNCATE(32, 32)
#undef DECL_UNSIGNED_FLOAT_TRUNCATE

  DECL_CHANGE_V(ReversibleFloat64ToInt32, kSignedFloatTruncateOverflowToMin,
                kReversible, Float64, Word32)
  DECL_CHANGE_V(ReversibleFloat64ToUint32, kUnsignedFloatTruncateOverflowToMin,
                kReversible, Float64, Word32)
  DECL_CHANGE_V(ReversibleFloat64ToInt64, kSignedFloatTruncateOverflowToMin,
                kReversible, Float64, Word64)
  DECL_CHANGE_V(ReversibleFloat64ToUint64, kUnsignedFloatTruncateOverflowToMin,
                kReversible, Float64, Word64)
  DECL_CHANGE_V(Float64ExtractLowWord32, kExtractLowHalf, kNoAssumption,
                Float64, Word32)
  DECL_CHANGE_V(Float64ExtractHighWord32, kExtractHighHalf, kNoAssumption,
                Float64, Word32)
#undef DECL_CHANGE_V
#undef DECL_TRY_CHANGE_V

  V<Untagged> ChangeOrDeopt(V<Untagged> input,
                            V<turboshaft::FrameState> frame_state,
                            ChangeOrDeoptOp::Kind kind,
                            CheckForMinusZeroMode minus_zero_mode,
                            const FeedbackSource& feedback) {
    return ReduceIfReachableChangeOrDeopt(input, frame_state, kind,
                                          minus_zero_mode, feedback);
  }

  V<Word32> ChangeFloat64ToInt32OrDeopt(V<Float64> input,
                                        V<turboshaft::FrameState> frame_state,
                                        CheckForMinusZeroMode minus_zero_mode,
                                        const FeedbackSource& feedback) {
    return V<Word32>::Cast(ChangeOrDeopt(input, frame_state,
                                         ChangeOrDeoptOp::Kind::kFloat64ToInt32,
                                         minus_zero_mode, feedback));
  }
  V<Word32> ChangeFloat64ToUint32OrDeopt(V<Float64> input,
                                         V<turboshaft::FrameState> frame_state,
                                         CheckForMinusZeroMode minus_zero_mode,
                                         const FeedbackSource& feedback) {
    return V<Word32>::Cast(ChangeOrDeopt(
        input, frame_state, ChangeOrDeoptOp::Kind::kFloat64ToUint32,
        minus_zero_mode, feedback));
  }
  V<Word64> ChangeFloat64ToInt64OrDeopt(V<Float64> input,
                                        V<turboshaft::FrameState> frame_state,
                                        CheckForMinusZeroMode minus_zero_mode,
                                        const FeedbackSource& feedback) {
    return V<Word64>::Cast(ChangeOrDeopt(input, frame_state,
                                         ChangeOrDeoptOp::Kind::kFloat64ToInt64,
                                         minus_zero_mode, feedback));
  }

  V<Smi> TagSmi(ConstOrV<Word32> input) {
    constexpr int kSmiShiftBits = kSmiShiftSize + kSmiTagSize;
    // Do shift on 32bit values if Smis are stored in the lower word.
    if constexpr (Is64() && SmiValuesAre31Bits()) {
      V<Word32> shifted = Word32ShiftLeft(resolve(input), kSmiShiftBits);
      // In pointer compression, we smi-corrupt. Then, the upper bits are not
      // important.
      return BitcastWord32ToSmi(shifted);
    } else {
      return BitcastWordPtrToSmi(
          WordPtrShiftLeft(ChangeInt32ToIntPtr(resolve(input)), kSmiShiftBits));
    }
  }

  V<Word32> UntagSmi(V<Smi> input) {
    constexpr int kSmiShiftBits = kSmiShiftSize + kSmiTagSize;
    if constexpr (Is64() && SmiValuesAre31Bits()) {
      return Word32ShiftRightArithmeticShiftOutZeros(BitcastSmiToWord32(input),
                                                     kSmiShiftBits);
    }
    return TruncateWordPtrToWord32(WordPtrShiftRightArithmeticShiftOutZeros(
        BitcastSmiToWordPtr(input), kSmiShiftBits));
  }

  OpIndex AtomicRMW(V<WordPtr> base, V<WordPtr> index, OpIndex value,
                    AtomicRMWOp::BinOp bin_op,
                    RegisterRepresentation in_out_rep,
                    MemoryRepresentation memory_rep,
                    MemoryAccessKind memory_access_kind) {
    DCHECK_NE(bin_op, AtomicRMWOp::BinOp::kCompareExchange);
    return ReduceIfReachableAtomicRMW(base, index, value, OpIndex::Invalid(),
                                      bin_op, in_out_rep, memory_rep,
                                      memory_access_kind);
  }

  OpIndex AtomicCompareExchange(V<WordPtr> base, V<WordPtr> index,
                                OpIndex expected, OpIndex new_value,
                                RegisterRepresentation result_rep,
                                MemoryRepresentation input_rep,
                                MemoryAccessKind memory_access_kind) {
    return ReduceIfReachableAtomicRMW(
        base, index, new_value, expected, AtomicRMWOp::BinOp::kCompareExchange,
        result_rep, input_rep, memory_access_kind);
  }

  OpIndex AtomicWord32Pair(V<WordPtr> base, OptionalV<WordPtr> index,
                           OptionalV<Word32> value_low,
                           OptionalV<Word32> value_high,
                           OptionalV<Word32> expected_low,
                           OptionalV<Word32> expected_high,
                           AtomicWord32PairOp::Kind op_kind, int32_t offset) {
    return ReduceIfReachableAtomicWord32Pair(base, index, value_low, value_high,
                                             expected_low, expected_high,
                                             op_kind, offset);
  }

  OpIndex AtomicWord32PairLoad(V<WordPtr> base, OptionalV<WordPtr> index,
                               int32_t offset) {
    return AtomicWord32Pair(base, index, {}, {}, {}, {},
                            AtomicWord32PairOp::Kind::kLoad, offset);
  }
  OpIndex AtomicWord32PairStore(V<WordPtr> base, OptionalV<WordPtr> index,
                                V<Word32> value_low, V<Word32> value_high,
                                int32_t offset) {
    return AtomicWord32Pair(base, index, value_low, value_high, {}, {},
                            AtomicWord32PairOp::Kind::kStore, offset);
  }
  OpIndex AtomicWord32PairCompareExchange(
      V<WordPtr> base, OptionalV<WordPtr> index, V<Word32> value_low,
      V<Word32> value_high, V<Word32> expected_low, V<Word32> expected_high,
      int32_t offset = 0) {
    return AtomicWord32Pair(base, index, value_low, value_high, expected_low,
                            expected_high,
                            AtomicWord32PairOp::Kind::kCompareExchange, offset);
  }
  OpIndex AtomicWord32PairBinop(V<WordPtr> base, OptionalV<WordPtr> index,
                                V<Word32> value_low, V<Word32> value_high,
                                AtomicRMWOp::BinOp bin_op, int32_t offset = 0) {
    return AtomicWord32Pair(base, index, value_low, value_high, {}, {},
                            AtomicWord32PairOp::KindFromBinOp(bin_op), offset);
  }

  OpIndex MemoryBarrier(AtomicMemoryOrder memory_order) {
    return ReduceIfReachableMemoryBarrier(memory_order);
  }

  OpIndex Load(OpIndex base, OptionalOpIndex index, LoadOp::Kind kind,
               MemoryRepresentation loaded_rep,
               RegisterRepresentation result_rep, int32_t offset = 0,
               uint8_t element_size_log2 = 0) {
    return ReduceIfReachableLoad(base, index, kind, loaded_rep, result_rep,
                                 offset, element_size_log2);
  }

  OpIndex Load(OpIndex base, OptionalOpIndex index, LoadOp::Kind kind,
               MemoryRepresentation loaded_rep, int32_t offset = 0,
               uint8_t element_size_log2 = 0) {
    return Load(base, index, kind, loaded_rep,
                loaded_rep.ToRegisterRepresentation(), offset,
                element_size_log2);
  }
  OpIndex Load(OpIndex base, LoadOp::Kind kind, MemoryRepresentation loaded_rep,
               int32_t offset = 0) {
    return Load(base, OpIndex::Invalid(), kind, loaded_rep, offset);
  }
  OpIndex LoadOffHeap(OpIndex address, MemoryRepresentation rep) {
    return LoadOffHeap(address, 0, rep);
  }
  OpIndex LoadOffHeap(OpIndex address, int32_t offset,
                      MemoryRepresentation rep) {
    return Load(address, LoadOp::Kind::RawAligned(), rep, offset);
  }
  OpIndex LoadOffHeap(OpIndex address, OptionalOpIndex index, int32_t offset,
                      MemoryRepresentation rep) {
    return Load(address, index, LoadOp::Kind::RawAligned(), rep, offset,
                rep.SizeInBytesLog2());
  }

  // Load a protected (trusted -> trusted) pointer field. The read value is
  // either a Smi or a TrustedObject.
  V<Object> LoadProtectedPointerField(
      V<Object> base, OptionalV<WordPtr> index,
      LoadOp::Kind kind = LoadOp::Kind::TaggedBase(), int offset = 0,
      int element_size_log2 = kTaggedSizeLog2) {
    return Load(base, index, kind,
                V8_ENABLE_SANDBOX_BOOL
                    ? MemoryRepresentation::ProtectedPointer()
                    : MemoryRepresentation::AnyTagged(),
                offset, index.valid() ? element_size_log2 : 0);
  }

  // Load a protected (trusted -> trusted) pointer field. The read value is
  // either a Smi or a TrustedObject.
  V<Object> LoadProtectedPointerField(V<Object> base, LoadOp::Kind kind,
                                      int32_t offset) {
    return LoadProtectedPointerField(base, OpIndex::Invalid(), kind, offset);
  }

  // Load a trusted (indirect) pointer. Returns Smi or ExposedTrustedObject.
  V<Object> LoadTrustedPointerField(V<HeapObject> base, OptionalV<Word32> index,
                                    LoadOp::Kind kind, IndirectPointerTag tag,
                                    int offset = 0) {
#if V8_ENABLE_SANDBOX
    static_assert(COMPRESS_POINTERS_BOOL);
    V<Word32> handle =
        Load(base, index, kind, MemoryRepresentation::Uint32(), offset);
    V<Word32> table_index =
        Word32ShiftRightLogical(handle, kTrustedPointerHandleShift);
    V<Word64> table_offset = __ ChangeUint32ToUint64(
        Word32ShiftLeft(table_index, kTrustedPointerTableEntrySizeLog2));
    V<WordPtr> table =
        Load(LoadRootRegister(), LoadOp::Kind::RawAligned().Immutable(),
             MemoryRepresentation::UintPtr(),
             IsolateData::trusted_pointer_table_offset() +
                 Internals::kTrustedPointerTableBasePointerOffset);
    V<WordPtr> decoded_ptr =
        Load(table, table_offset, LoadOp::Kind::RawAligned(),
             MemoryRepresentation::UintPtr());

    // Untag the pointer and remove the marking bit in one operation.
    decoded_ptr =
        __ Word64BitwiseAnd(decoded_ptr, ~(tag | kTrustedPointerTableMarkBit));

    // Bitcast to tagged to this gets scanned by the GC properly.
    return BitcastWordPtrToTagged(decoded_ptr);
#else
    return Load(base, index, kind, MemoryRepresentation::TaggedPointer(),
                offset);
#endif  // V8_ENABLE_SANDBOX
  }

  // Load a trusted (indirect) pointer. Returns Smi or ExposedTrustedObject.
  V<Object> LoadTrustedPointerField(V<HeapObject> base, LoadOp::Kind kind,
                                    IndirectPointerTag tag, int offset = 0) {
    return LoadTrustedPointerField(base, OpIndex::Invalid(), kind, tag, offset);
  }

  V<Object> LoadFixedArrayElement(V<FixedArray> array, int index) {
    return Load(array, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::AnyTagged(),
                FixedArray::OffsetOfElementAt(index));
  }
  V<Object> LoadFixedArrayElement(V<FixedArray> array, V<WordPtr> index) {
    return Load(array, index, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::AnyTagged(),
                FixedArray::OffsetOfElementAt(0), kTaggedSizeLog2);
  }

  V<Float64> LoadFixedDoubleArrayElement(V<FixedDoubleArray> array, int index) {
    return Load(array, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::Float64(),
                FixedDoubleArray::OffsetOfElementAt(index));
  }
  V<Float64> LoadFixedDoubleArrayElement(V<FixedDoubleArray> array,
                                         V<WordPtr> index) {
    static_assert(ElementsKindToShiftSize(PACKED_DOUBLE_ELEMENTS) ==
                  ElementsKindToShiftSize(HOLEY_DOUBLE_ELEMENTS));
    return Load(array, index, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::Float64(),
                FixedDoubleArray::OffsetOfElementAt(0),
                ElementsKindToShiftSize(PACKED_DOUBLE_ELEMENTS));
  }

  V<Object> LoadProtectedFixedArrayElement(V<ProtectedFixedArray> array,
                                           V<WordPtr> index) {
    return LoadProtectedPointerField(array, index, LoadOp::Kind::TaggedBase(),
                                     ProtectedFixedArray::OffsetOfElementAt(0));
  }

  V<Object> LoadProtectedFixedArrayElement(V<ProtectedFixedArray> array,
                                           int index) {
    return LoadProtectedPointerField(
        array, LoadOp::Kind::TaggedBase(),
        ProtectedFixedArray::OffsetOfElementAt(index));
  }

  void Store(
      OpIndex base, OptionalOpIndex index, OpIndex value, StoreOp::Kind kind,
      MemoryRepresentation stored_rep, WriteBarrierKind write_barrier,
      int32_t offset = 0, uint8_t element_size_log2 = 0,
      bool maybe_initializing_or_transitioning = false,
      IndirectPointerTag maybe_indirect_pointer_tag = kIndirectPointerNullTag) {
    ReduceIfReachableStore(base, index, value, kind, stored_rep, write_barrier,
                           offset, element_size_log2,
                           maybe_initializing_or_transitioning,
                           maybe_indirect_pointer_tag);
  }
  void Store(
      OpIndex base, OpIndex value, StoreOp::Kind kind,
      MemoryRepresentation stored_rep, WriteBarrierKind write_barrier,
      int32_t offset = 0, bool maybe_initializing_or_transitioning = false,
      IndirectPointerTag maybe_indirect_pointer_tag = kIndirectPointerNullTag) {
    Store(base, OpIndex::Invalid(), value, kind, stored_rep, write_barrier,
          offset, 0, maybe_initializing_or_transitioning,
          maybe_indirect_pointer_tag);
  }

  template <typename T>
  void Initialize(Uninitialized<T>& object, OpIndex value,
                  MemoryRepresentation stored_rep,
                  WriteBarrierKind write_barrier, int32_t offset = 0) {
    return Store(object.object(), value,
                 StoreOp::Kind::Aligned(BaseTaggedness::kTaggedBase),
                 stored_rep, write_barrier, offset, true);
  }

  void StoreOffHeap(OpIndex address, OpIndex value, MemoryRepresentation rep,
                    int32_t offset = 0) {
    Store(address, value, StoreOp::Kind::RawAligned(), rep,
          WriteBarrierKind::kNoWriteBarrier, offset);
  }
  void StoreOffHeap(OpIndex address, OptionalOpIndex index, OpIndex value,
                    MemoryRepresentation rep, int32_t offset) {
    Store(address, index, value, StoreOp::Kind::RawAligned(), rep,
          WriteBarrierKind::kNoWriteBarrier, offset, rep.SizeInBytesLog2());
  }

  template <typename Rep = Any>
  V<Rep> LoadField(V<Object> object, const compiler::FieldAccess& access) {
    DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kTaggedBase);
    return LoadFieldImpl<Rep>(object, access);
  }

  template <typename Rep = Any>
  V<Rep> LoadField(V<WordPtr> raw_base, const compiler::FieldAccess& access) {
    DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kUntaggedBase);
    return LoadFieldImpl<Rep>(raw_base, access);
  }

  template <typename Obj, typename Class, typename T,
            typename = std::enable_if_t<v_traits<
                Class>::template implicitly_constructible_from<Obj>::value>>
  V<T> LoadField(V<Obj> object, const FieldAccessTS<Class, T>& field) {
    return LoadFieldImpl<T>(object, field);
  }

  template <typename Rep>
  V<Rep> LoadFieldImpl(OpIndex object, const compiler::FieldAccess& access) {
    MachineType machine_type = access.machine_type;
    if (machine_type.IsMapWord()) {
      machine_type = MachineType::TaggedPointer();
#ifdef V8_MAP_PACKING
      UNIMPLEMENTED();
#endif
    }
    MemoryRepresentation rep =
        MemoryRepresentation::FromMachineType(machine_type);
#ifdef V8_ENABLE_SANDBOX
    bool is_sandboxed_external =
        access.type.Is(compiler::Type::ExternalPointer());
    if (is_sandboxed_external) {
      // Fields for sandboxed external pointer contain a 32-bit handle, not a
      // 64-bit raw pointer.
      rep = MemoryRepresentation::Uint32();
    }
#endif  // V8_ENABLE_SANDBOX
    LoadOp::Kind kind = LoadOp::Kind::Aligned(access.base_is_tagged);
    if (access.is_immutable) {
      kind = kind.Immutable();
    }
    V<Rep> value = Load(object, kind, rep, access.offset);
#ifdef V8_ENABLE_SANDBOX
    if (is_sandboxed_external) {
      value = DecodeExternalPointer(value, access.external_pointer_tag);
    }
    if (access.is_bounded_size_access) {
      DCHECK(!is_sandboxed_external);
      value = ShiftRightLogical(value, kBoundedSizeShift,
                                WordRepresentation::WordPtr());
    }
#endif  // V8_ENABLE_SANDBOX
    return value;
  }

  // Helpers to read the most common fields.
  // TODO(nicohartmann@): Strengthen this to `V<HeapObject>`.
  V<Map> LoadMapField(V<Object> object) {
    return LoadField<Map>(object, AccessBuilder::ForMap());
  }

  V<Word32> LoadInstanceTypeField(V<Map> map) {
    return LoadField<Word32>(map, AccessBuilder::ForMapInstanceType());
  }

  V<Word32> HasInstanceType(V<Object> object, InstanceType instance_type) {
    return Word32Equal(LoadInstanceTypeField(LoadMapField(object)),
                       Word32Constant(instance_type));
  }

  V<Float64> LoadHeapNumberValue(V<HeapNumber> heap_number) {
    return __ template LoadField<HeapNumber, HeapNumber, Float64>(
        heap_number, AccessBuilderTS::ForHeapNumberValue());
  }

  template <typename Type = Object,
            typename = std::enable_if_t<is_subtype_v<Type, Object>>>
  V<Type> LoadTaggedField(V<Object> object, int field_offset) {
    return Load(object, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::AnyTagged(), field_offset);
  }

  template <typename Base>
  void StoreField(V<Base> object, const FieldAccess& access, V<Any> value) {
    StoreFieldImpl(object, access, value,
                   access.maybe_initializing_or_transitioning_store);
  }

  template <typename Object, typename Class, typename T>
  void InitializeField(Uninitialized<Object>& object,
                       const FieldAccessTS<Class, T>& access,
                       maybe_const_or_v_t<T> value) {
    static_assert(is_subtype_v<Object, Class>);
    StoreFieldImpl(object.object(), access, resolve(value), true);
  }

  // TODO(nicohartmann): Remove `InitializeField` once fully transitioned to
  // `FieldAccess`.
  template <typename T>
  void InitializeField(Uninitialized<T>& object, const FieldAccess& access,
                       V<Any> value) {
    StoreFieldImpl(object.object(), access, value, true);
  }

  template <typename Base>
  void StoreFieldImpl(V<Base> object, const FieldAccess& access, V<Any> value,
                      bool maybe_initializing_or_transitioning) {
    if constexpr (is_taggable_v<Base>) {
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kTaggedBase);
    } else {
      static_assert(std::is_same_v<Base, WordPtr>);
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kUntaggedBase);
    }
    // External pointer must never be stored by optimized code.
    DCHECK(!access.type.Is(compiler::Type::ExternalPointer()) ||
           !V8_ENABLE_SANDBOX_BOOL);
    // SandboxedPointers are not currently stored by optimized code.
    DCHECK(!access.type.Is(compiler::Type::SandboxedPointer()));

#ifdef V8_ENABLE_SANDBOX
    if (access.is_bounded_size_access) {
      value =
          ShiftLeft(value, kBoundedSizeShift, WordRepresentation::WordPtr());
    }
#endif  // V8_ENABLE_SANDBOX

    StoreOp::Kind kind = StoreOp::Kind::Aligned(access.base_is_tagged);
    MachineType machine_type = access.machine_type;
    if (machine_type.IsMapWord()) {
      machine_type = MachineType::TaggedPointer();
#ifdef V8_MAP_PACKING
      UNIMPLEMENTED();
#endif
    }
    MemoryRepresentation rep =
        MemoryRepresentation::FromMachineType(machine_type);
    Store(object, value, kind, rep, access.write_barrier_kind, access.offset,
          maybe_initializing_or_transitioning);
  }

  void StoreFixedArrayElement(V<FixedArray> array, int index, V<Object> value,
                              compiler::WriteBarrierKind write_barrier) {
    Store(array, value, LoadOp::Kind::TaggedBase(),
          MemoryRepresentation::AnyTagged(), write_barrier,
          FixedArray::OffsetOfElementAt(index));
  }

  void StoreFixedArrayElement(V<FixedArray> array, V<WordPtr> index,
                              V<Object> value,
                              compiler::WriteBarrierKind write_barrier) {
    Store(array, index, value, LoadOp::Kind::TaggedBase(),
          MemoryRepresentation::AnyTagged(), write_barrier,
          OFFSET_OF_DATA_START(FixedArray), kTaggedSizeLog2);
  }
  void StoreFixedDoubleArrayElement(V<FixedDoubleArray> array, V<WordPtr> index,
                                    V<Float64> value) {
    static_assert(ElementsKindToShiftSize(PACKED_DOUBLE_ELEMENTS) ==
                  ElementsKindToShiftSize(HOLEY_DOUBLE_ELEMENTS));
    Store(array, index, value, LoadOp::Kind::TaggedBase(),
          MemoryRepresentation::Float64(), WriteBarrierKind::kNoWriteBarrier,
          sizeof(FixedDoubleArray::Header),
          ElementsKindToShiftSize(PACKED_DOUBLE_ELEMENTS));
  }

  template <typename Class, typename T>
  V<T> LoadElement(V<Class> object, const ElementAccessTS<Class, T>& access,
                   V<WordPtr> index) {
    return LoadElement<T>(object, access, index, access.is_array_buffer_load);
  }

  // TODO(nicohartmann): Remove `LoadArrayBufferElement` once fully transitioned
  // to `ElementAccess`.
  template <typename T = Any, typename Base>
  V<T> LoadArrayBufferElement(V<Base> object, const ElementAccess& access,
                              V<WordPtr> index) {
    return LoadElement<T>(object, access, index, true);
  }
  // TODO(nicohartmann): Remove `LoadNonArrayBufferElement` once fully
  // transitioned to `ElementAccess`.
  template <typename T = Any, typename Base>
  V<T> LoadNonArrayBufferElement(V<Base> object, const ElementAccess& access,
                                 V<WordPtr> index) {
    return LoadElement<T>(object, access, index, false);
  }
  template <typename Base>
  V<WordPtr> GetElementStartPointer(V<Base> object,
                                    const ElementAccess& access) {
    return WordPtrAdd(BitcastHeapObjectToWordPtr(object),
                      access.header_size - access.tag());
  }

  template <typename Base>
  void StoreArrayBufferElement(V<Base> object, const ElementAccess& access,
                               V<WordPtr> index, V<Any> value) {
    return StoreElement(obje
"""


```