Response: The user wants to understand the functionality of the C++ source code file `builtins-internal-gen.cc` located in the `v8/src/builtins` directory.

The request has two parts:
1. Summarize the functionality of the code.
2. If the code relates to JavaScript functionality, provide JavaScript examples.

The file name `builtins-internal-gen.cc` suggests that it contains generated code for internal built-in functions in V8. Looking at the includes, it interacts with code generation (`codegen`), runtime functions (`runtime`), object manipulation (`objects`), and memory management (`heap`). The presence of `TF_BUILTIN` macros indicates the use of TurboFan, V8's optimizing compiler.

Let's break down the code snippets and identify their purpose:

- **`CopyFastSmiOrObjectElements`**:  This builtin seems to create a copy of the elements of a `JSObject`. It loads the elements, clones them, and stores the clone back into the object. This is likely related to array manipulation or object property access.
- **`GrowFastDoubleElements` and `GrowFastSmiOrObjectElements`**: These builtins handle increasing the capacity of an object's elements. They try to grow the element array and, if that fails, call a runtime function (`Runtime::kGrowArrayElements`). This is crucial for efficiently handling dynamic arrays in JavaScript.
- **`ReturnReceiver`**:  A simple builtin that returns the receiver object. This is used in function calls to access the `this` value.
- **`DebugBreakTrampoline`**:  This handles breakpoints set at the entry of a function. It checks a flag and calls the debugger runtime function if necessary before executing the actual function code.
- **`WriteBarrierCodeStubAssembler`**: This class implements write barriers for the garbage collector. Write barriers are essential for maintaining the integrity of the heap during garbage collection by tracking object references. It includes functions for checking marking status, inserting into remembered sets, and different types of write barriers (generational, shared, incremental).
- **`TSANRelaxedStoreCodeStubAssembler`, `TSANSeqCstStoreCodeStubAssembler`, `TSANRelaxedLoadCodeStubAssembler`**: These assemblers deal with thread safety annotations (TSAN) for memory access. They interact with external functions to handle relaxed and sequentially consistent memory stores and loads, crucial for concurrent JavaScript execution in workers.
- **`DeletePropertyBaseAssembler`**:  This class handles the `delete` operator in JavaScript. It includes logic for deleting properties from dictionaries (hash maps) and potentially shrinking them.
- **`SetOrCopyDataPropertiesAssembler`**: This assembler is responsible for copying or setting data properties from one object to another, as seen in `Object.assign()` and similar operations. It handles different object types and potential optimizations.
- **`ForInEnumerate`, `ForInPrepare`, `ForInFilter`**: These builtins are involved in the `for...in` loop in JavaScript, handling the enumeration of object properties.
- **`SameValue`, `SameValueNumbersOnly`**: These implement the `Object.is()` method and a similar operation that only compares numbers.
- **`CppBuiltinsAdaptorAssembler`**: This assembler generates adaptors for calling C++ built-in functions from JavaScript. It handles argument passing and stack setup.
- **Allocation builtins (`NewHeapNumber`, `AllocateInYoungGeneration`, `AllocateInOldGeneration`, `WasmAllocateInYoungGeneration`, `WasmAllocateInOldGeneration`)**:  These handle the allocation of different types of memory on the V8 heap.
- **`Abort`, `AbortCSADcheck`**: These builtins are used for terminating execution due to errors or debugging assertions.
- **`CEntry` related functions**: These are low-level entry points for calling C++ functions from JavaScript.
- **`BaselineLeaveFrame`, `MaglevOnStackReplacement`, `MaglevOptimizeCodeOrTailCallOptimizedCodeSlot`, `MaglevFunctionEntryStackCheck`**: These relate to V8's different compilation tiers (Baseline, Maglev) and on-stack replacement (OSR).
- **`GetProperty`, `GetPropertyWithReceiver`**: These implement the JavaScript property access (`object.property` or `object['property']`). They handle prototype chain lookup and proxy objects.
- **`SetProperty`**: Implements setting a JavaScript property.
- **`CreateDataProperty`**: A specialized version of setting a property used during object initialization.
- **`InstantiateAsmJs`**:  Handles the instantiation of WebAssembly modules (specifically the older asm.js subset).

Based on this analysis, the primary function of this file is to provide optimized implementations for various internal operations and built-in functions used by the V8 JavaScript engine. These implementations are written using the CodeStubAssembler (CSA), a low-level assembly-like language within V8, and often interact with V8's internal data structures and runtime system.
`v8/src/builtins/builtins-internal-gen.cc` 是 V8 JavaScript 引擎中一个关键的 C++ 源代码文件，其主要功能是**定义和实现 V8 引擎内部使用的一些内置函数 (builtins)**。

这些内置函数通常是性能关键的操作，例如对象属性访问、数组操作、内存管理、调试支持、以及与垃圾回收相关的操作。 由于它们是内部使用的，因此通常比开发者直接调用的 JavaScript 全局对象 (例如 `Array.prototype.push`) 的内置函数更底层。

**具体来说，这个文件的功能可以归纳为：**

1. **定义 TurboFan Builtins:** 使用 `TF_BUILTIN` 宏定义了一系列由 V8 的优化编译器 TurboFan 生成代码时使用的内置函数。这些内置函数通常是用 CodeStubAssembler (CSA) 编写的，这是一种底层的、类似汇编的语言，允许精细地控制代码生成，从而实现高性能。
2. **实现核心操作:**  文件中实现了诸如复制数组元素、扩展数组容量、获取函数接收者 (receiver，即 `this` 值)、调试断点处理等核心操作。
3. **提供垃圾回收支持:**  `WriteBarrierCodeStubAssembler` 类定义了写屏障 (write barrier) 的实现。写屏障是垃圾回收机制的关键部分，用于在对象属性被修改时通知垃圾回收器，以确保内存安全。
4. **处理线程安全:**  在启用了线程安全的情况下，文件中包含了处理原子操作的内置函数，例如 `TSANRelaxedStoreCodeStubAssembler` 和 `TSANSeqCstStoreCodeStubAssembler`，这些与 ThreadSanitizer (TSAN) 有关，用于检测多线程程序的竞争条件。
5. **实现属性操作:**  `DeletePropertyBaseAssembler` 实现了 `delete` 操作符的逻辑，而 `SetOrCopyDataPropertiesAssembler` 则实现了对象属性的复制和设置，例如在 `Object.assign()` 中使用。
6. **支持 `for...in` 循环:** 文件中包含了 `ForInEnumerate`、`ForInPrepare` 和 `ForInFilter` 等内置函数，用于实现 JavaScript 的 `for...in` 循环。
7. **实现值比较:**  `SameValue` 和 `SameValueNumbersOnly` 实现了 JavaScript 中值的比较操作，类似于 `Object.is()`。
8. **提供 C++ 内置函数的适配器:** `CppBuiltinsAdaptorAssembler` 用于生成将 C++ 实现的内置函数适配到 JavaScript 调用约定所需的代码。
9. **内存分配:**  文件中定义了用于在新生代和老生代堆中分配内存的内置函数，例如 `NewHeapNumber`、`AllocateInYoungGeneration` 和 `AllocateInOldGeneration`。
10. **异常处理和断言:**  `Abort` 和 `AbortCSADcheck` 等内置函数用于处理错误和执行内部断言。
11. **与编译管道集成:** 文件中还包含了一些与 V8 的编译管道 (例如 Baseline 和 Maglev) 相关的内置函数，用于支持不同的优化级别和执行策略。
12. **实现属性的获取和设置:** `GetProperty` 和 `SetProperty` 等内置函数实现了 JavaScript 中属性的获取和设置操作，包括原型链查找和 Proxy 对象的处理。
13. **支持 WebAssembly:** 文件中包含 `InstantiateAsmJs` 等内置函数，用于处理 WebAssembly 模块的实例化 (特别是早期的 asm.js 子集)。

**与 JavaScript 功能的关系及示例:**

这个文件中的内置函数是 JavaScript 引擎内部实现的基础，虽然开发者通常不会直接调用它们，但它们支撑着各种 JavaScript 语言特性的运行。

**示例 1: `CopyFastSmiOrObjectElements` 与数组复制**

JavaScript 中的数组 `slice()` 方法可以创建一个数组的浅拷贝。当数组元素是小的整数 (Smi) 或对象时，V8 可能会使用 `CopyFastSmiOrObjectElements` 这样的内置函数来高效地完成复制操作。

```javascript
const arr1 = [1, 2, { a: 1 }];
const arr2 = arr1.slice(); // 创建 arr1 的浅拷贝

console.log(arr2); // 输出: [ 1, 2, { a: 1 } ]
console.log(arr1 === arr2); // 输出: false (arr1 和 arr2 是不同的数组)
console.log(arr1[2] === arr2[2]); // 输出: true (但它们包含相同的对象引用)
```

**示例 2: `GrowFastDoubleElements` 与动态数组增长**

JavaScript 数组可以动态增长。当向一个存储浮点数的数组中添加元素，并且当前数组容量不足时，V8 可能会调用 `GrowFastDoubleElements` 这样的内置函数来扩展数组的内部存储。

```javascript
const arr = [1.1, 2.2];
arr.push(3.3); // 当数组需要扩展容量时，V8 内部会调用相应的内置函数
console.log(arr); // 输出: [ 1.1, 2.2, 3.3 ]
```

**示例 3: `DeleteProperty` 与 `delete` 操作符**

JavaScript 的 `delete` 操作符用于删除对象的属性。 V8 内部的 `DeleteProperty` 内置函数实现了这个操作符的逻辑，包括查找属性、更新对象的内部表示等。

```javascript
const obj = { a: 1, b: 2 };
delete obj.a;
console.log(obj); // 输出: { b: 2 }
console.log('a' in obj); // 输出: false
```

**示例 4: `GetProperty` 与属性访问**

当你访问一个对象的属性时，例如 `obj.property`，V8 内部会使用 `GetProperty` 这样的内置函数来查找属性，包括遍历原型链。

```javascript
const proto = { z: 3 };
const obj = { x: 1, y: 2, __proto__: proto };

console.log(obj.x); // V8 内部使用 GetProperty 获取 obj 的属性 x
console.log(obj.z); // V8 内部使用 GetProperty 沿着原型链查找属性 z
```

总而言之，`v8/src/builtins/builtins-internal-gen.cc` 文件定义了 V8 引擎执行 JavaScript 代码时所需的核心、底层的操作，这些操作是 JavaScript 语言特性的幕后功臣。开发者虽然不直接调用它们，但所有的 JavaScript 代码执行都依赖于这些内置函数的实现。

### 提示词
```
这是目录为v8/src/builtins/builtins-internal-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/api/api.h"
#include "src/baseline/baseline.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/ic/accessor-assembler.h"
#include "src/ic/keyed-store-generic.h"
#include "src/logging/counters.h"
#include "src/objects/debug-objects.h"
#include "src/objects/scope-info.h"
#include "src/objects/shared-function-info.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// -----------------------------------------------------------------------------
// TurboFan support builtins.

TF_BUILTIN(CopyFastSmiOrObjectElements, CodeStubAssembler) {
  auto js_object = Parameter<JSObject>(Descriptor::kObject);

  // Load the {object}s elements.
  TNode<FixedArrayBase> source =
      CAST(LoadObjectField(js_object, JSObject::kElementsOffset));
  TNode<FixedArrayBase> target =
      CloneFixedArray(source, ExtractFixedArrayFlag::kFixedArrays);
  StoreObjectField(js_object, JSObject::kElementsOffset, target);
  Return(target);
}

TF_BUILTIN(GrowFastDoubleElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements = TryGrowElementsCapacity(object, elements, PACKED_DOUBLE_ELEMENTS,
                                     key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(GrowFastSmiOrObjectElements, CodeStubAssembler) {
  auto object = Parameter<JSObject>(Descriptor::kObject);
  auto key = Parameter<Smi>(Descriptor::kKey);

  Label runtime(this, Label::kDeferred);
  TNode<FixedArrayBase> elements = LoadElements(object);
  elements =
      TryGrowElementsCapacity(object, elements, PACKED_ELEMENTS, key, &runtime);
  Return(elements);

  BIND(&runtime);
  TailCallRuntime(Runtime::kGrowArrayElements, NoContextConstant(), object,
                  key);
}

TF_BUILTIN(ReturnReceiver, CodeStubAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  Return(receiver);
}

TF_BUILTIN(DebugBreakTrampoline, CodeStubAssembler) {
  Label tailcall_to_shared(this);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  auto arg_count =
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
#ifdef V8_ENABLE_LEAPTIERING
  auto dispatch_handle =
      UncheckedParameter<JSDispatchHandleT>(Descriptor::kJSDispatchHandle);
#else
  auto dispatch_handle = InvalidDispatchHandleConstant();
#endif
  auto function = Parameter<JSFunction>(Descriptor::kJSTarget);

  // Check break-at-entry flag on the debug info.
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::debug_break_at_entry_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  TNode<SharedFunctionInfo> shared =
      CAST(LoadObjectField(function, JSFunction::kSharedFunctionInfoOffset));
  TNode<IntPtrT> result = UncheckedCast<IntPtrT>(
      CallCFunction(f, MachineType::UintPtr(),
                    std::make_pair(MachineType::Pointer(), isolate_ptr),
                    std::make_pair(MachineType::TaggedPointer(), shared)));
  GotoIf(IntPtrEqual(result, IntPtrConstant(0)), &tailcall_to_shared);

  CallRuntime(Runtime::kDebugBreakAtEntry, context, function);
  Goto(&tailcall_to_shared);

  BIND(&tailcall_to_shared);
  // Tail call into code object on the SharedFunctionInfo.
  // TODO(saelo): this is not safe. We either need to validate the parameter
  // count here or obtain the code from the dispatch table.
  TNode<Code> code = GetSharedFunctionInfoCode(shared);
  TailCallJSCode(code, context, function, new_target, arg_count,
                 dispatch_handle);
}

class WriteBarrierCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit WriteBarrierCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<BoolT> IsMarking() {
    TNode<ExternalReference> is_marking_addr = ExternalConstant(
        ExternalReference::heap_is_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_marking_addr), Int32Constant(0));
  }

  TNode<BoolT> IsMinorMarking() {
    TNode<ExternalReference> is_minor_marking_addr = ExternalConstant(
        ExternalReference::heap_is_minor_marking_flag_address(this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_minor_marking_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsSharedSpaceIsolate() {
    TNode<ExternalReference> is_shared_space_isolate_addr = ExternalConstant(
        ExternalReference::is_shared_space_isolate_flag_address(
            this->isolate()));
    return Word32NotEqual(Load<Uint8T>(is_shared_space_isolate_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> UsesSharedHeap() {
    TNode<ExternalReference> uses_shared_heap_addr =
        IsolateField(IsolateFieldId::kUsesSharedHeapFlag);
    return Word32NotEqual(Load<Uint8T>(uses_shared_heap_addr),
                          Int32Constant(0));
  }

  TNode<BoolT> IsUnmarked(TNode<IntPtrT> object) {
    TNode<IntPtrT> cell;
    TNode<IntPtrT> mask;
    GetMarkBit(object, &cell, &mask);
    // Marked only requires checking a single bit here.
    return WordEqual(WordAnd(Load<IntPtrT>(cell), mask), IntPtrConstant(0));
  }

  void InsertIntoRememberedSet(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                               SaveFPRegsMode fp_mode) {
    Label slow_path(this), next(this);
    TNode<IntPtrT> chunk = MemoryChunkFromAddress(object);
    TNode<IntPtrT> page = PageMetadataFromMemoryChunk(chunk);

    // Load address of SlotSet
    TNode<IntPtrT> slot_set = LoadSlotSet(page, &slow_path);
    TNode<IntPtrT> slot_offset = IntPtrSub(slot, chunk);
    TNode<IntPtrT> num_buckets_address =
        IntPtrSub(slot_set, IntPtrConstant(SlotSet::kNumBucketsSize));
    TNode<IntPtrT> num_buckets = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), num_buckets_address, IntPtrConstant(0)));

    // Load bucket
    TNode<IntPtrT> bucket =
        LoadBucket(slot_set, slot_offset, num_buckets, &slow_path);

    // Update cell
    SetBitInCell(bucket, slot_offset);
    Goto(&next);

    BIND(&slow_path);
    {
      TNode<ExternalReference> function =
          ExternalConstant(ExternalReference::insert_remembered_set_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, page),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot_offset));
      Goto(&next);
    }

    BIND(&next);
  }

  TNode<IntPtrT> LoadSlotSet(TNode<IntPtrT> page, Label* slow_path) {
    TNode<IntPtrT> slot_set = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), page,
             IntPtrConstant(MutablePageMetadata::SlotSetOffset(
                 RememberedSetType::OLD_TO_NEW))));
    GotoIf(WordEqual(slot_set, IntPtrConstant(0)), slow_path);
    return slot_set;
  }

  TNode<IntPtrT> LoadBucket(TNode<IntPtrT> slot_set, TNode<WordT> slot_offset,
                            TNode<IntPtrT> num_buckets, Label* slow_path) {
    TNode<WordT> bucket_index =
        WordShr(slot_offset, SlotSet::kBitsPerBucketLog2 + kTaggedSizeLog2);
    CSA_CHECK(this, IntPtrLessThan(bucket_index, num_buckets));
    TNode<IntPtrT> bucket = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), slot_set,
             WordShl(bucket_index, kSystemPointerSizeLog2)));
    GotoIf(WordEqual(bucket, IntPtrConstant(0)), slow_path);
    return bucket;
  }

  void SetBitInCell(TNode<IntPtrT> bucket, TNode<WordT> slot_offset) {
    // Load cell value
    TNode<WordT> cell_offset = WordAnd(
        WordShr(slot_offset, SlotSet::kBitsPerCellLog2 + kTaggedSizeLog2 -
                                 SlotSet::kCellSizeBytesLog2),
        IntPtrConstant((SlotSet::kCellsPerBucket - 1)
                       << SlotSet::kCellSizeBytesLog2));
    TNode<IntPtrT> cell_address =
        UncheckedCast<IntPtrT>(IntPtrAdd(bucket, cell_offset));
    TNode<IntPtrT> old_cell_value =
        ChangeInt32ToIntPtr(Load<Int32T>(cell_address));

    // Calculate new cell value
    TNode<WordT> bit_index = WordAnd(WordShr(slot_offset, kTaggedSizeLog2),
                                     IntPtrConstant(SlotSet::kBitsPerCell - 1));
    TNode<IntPtrT> new_cell_value = UncheckedCast<IntPtrT>(
        WordOr(old_cell_value, WordShl(IntPtrConstant(1), bit_index)));

    // Update cell value
    StoreNoWriteBarrier(MachineRepresentation::kWord32, cell_address,
                        TruncateIntPtrToInt32(new_cell_value));
  }

  void WriteBarrier(SaveFPRegsMode fp_mode) {
    Label marking_is_on(this), marking_is_off(this), next(this);

    auto slot =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    Branch(IsMarking(), &marking_is_on, &marking_is_off);

    BIND(&marking_is_off);
    GenerationalOrSharedBarrierSlow(slot, &next, fp_mode);

    BIND(&marking_is_on);
    WriteBarrierDuringMarking(slot, &next, fp_mode);

    BIND(&next);
  }

  void IndirectPointerWriteBarrier(SaveFPRegsMode fp_mode) {
    CSA_DCHECK(this, IsMarking());

    // For this barrier, the slot contains an index into a pointer table and not
    // directly a pointer to a HeapObject. Further, the slot address is tagged
    // with the indirect pointer tag of the slot, so it cannot directly be
    // dereferenced but needs to be decoded first.
    TNode<IntPtrT> slot = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(UncheckedParameter<Object>(
        IndirectPointerWriteBarrierDescriptor::kObject));
    TNode<IntPtrT> tag = UncheckedParameter<IntPtrT>(
        IndirectPointerWriteBarrierDescriptor::kIndirectPointerTag);

    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::
            write_barrier_indirect_pointer_marking_from_code_function());
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot),
        std::make_pair(MachineTypeOf<IntPtrT>::value, tag));
  }

  void GenerationalOrSharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                                       SaveFPRegsMode fp_mode) {
    // When incremental marking is not on, the fast and out-of-line fast path of
    // the write barrier already checked whether we need to run the generational
    // or shared barrier slow path.
    Label generational_barrier(this), shared_barrier(this);

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    InYoungGeneration(value, &generational_barrier, &shared_barrier);

    BIND(&generational_barrier);
    if (!v8_flags.sticky_mark_bits) {
      CSA_DCHECK(this,
                 IsPageFlagSet(value, MemoryChunk::kIsInYoungGenerationMask));
    }
    GenerationalBarrierSlow(slot, next, fp_mode);

    // TODO(333906585): With sticky-mark bits and without the shared barrier
    // support, we actually never jump here. Don't put it under the flag though,
    // since the assert below has been useful.
    BIND(&shared_barrier);
    CSA_DCHECK(this, IsPageFlagSet(value, MemoryChunk::kInSharedHeap));
    SharedBarrierSlow(slot, next, fp_mode);
  }

  void GenerationalBarrierSlow(TNode<IntPtrT> slot, Label* next,
                               SaveFPRegsMode fp_mode) {
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    InsertIntoRememberedSet(object, slot, fp_mode);
    Goto(next);
  }

  void SharedBarrierSlow(TNode<IntPtrT> slot, Label* next,
                         SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::shared_barrier_from_code_function());
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
    Goto(next);
  }

  void WriteBarrierDuringMarking(TNode<IntPtrT> slot, Label* next,
                                 SaveFPRegsMode fp_mode) {
    // When incremental marking is on, we need to perform generational, shared
    // and incremental marking write barrier.
    Label incremental_barrier(this);

    GenerationalOrSharedBarrierDuringMarking(slot, &incremental_barrier,
                                             fp_mode);

    BIND(&incremental_barrier);
    IncrementalWriteBarrier(slot, fp_mode);
    Goto(next);
  }

  void GenerationalOrSharedBarrierDuringMarking(TNode<IntPtrT> slot,
                                                Label* next,
                                                SaveFPRegsMode fp_mode) {
    Label generational_barrier_check(this), shared_barrier_check(this),
        shared_barrier_slow(this), generational_barrier_slow(this);

    // During incremental marking we always reach this slow path, so we need to
    // check whether this is an old-to-new or old-to-shared reference.
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to check the age.
      InYoungGeneration(object, next, &generational_barrier_check);

      BIND(&generational_barrier_check);
    }

    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits we know everything will be old after the GC so no
      // need to track old-to-new references.
      InYoungGeneration(value, &generational_barrier_slow,
                        &shared_barrier_check);

      BIND(&generational_barrier_slow);
      GenerationalBarrierSlow(slot, next, fp_mode);

      BIND(&shared_barrier_check);
    }

    InSharedHeap(value, &shared_barrier_slow, next);

    BIND(&shared_barrier_slow);

    SharedBarrierSlow(slot, next, fp_mode);
  }

  void InYoungGeneration(TNode<IntPtrT> object, Label* true_label,
                         Label* false_label) {
    if (v8_flags.sticky_mark_bits) {
      // This method is currently only used when marking is disabled. Checking
      // markbits while marking is active may result in unexpected results.
      CSA_DCHECK(this, Word32Equal(IsMarking(), BoolConstant(false)));

      Label not_read_only(this);

      TNode<BoolT> is_read_only_page =
          IsPageFlagSet(object, MemoryChunk::kIsOnlyOldOrMajorGCInProgressMask);
      Branch(is_read_only_page, false_label, &not_read_only);

      BIND(&not_read_only);
      Branch(IsUnmarked(object), true_label, false_label);
    } else {
      TNode<BoolT> object_is_young =
          IsPageFlagSet(object, MemoryChunk::kIsInYoungGenerationMask);
      Branch(object_is_young, true_label, false_label);
    }
  }

  void InSharedHeap(TNode<IntPtrT> object, Label* true_label,
                    Label* false_label) {
    TNode<BoolT> object_is_young =
        IsPageFlagSet(object, MemoryChunk::kInSharedHeap);

    Branch(object_is_young, true_label, false_label);
  }

  void IncrementalWriteBarrierMinor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label check_is_unmarked(this, Label::kDeferred);

    if (!v8_flags.sticky_mark_bits) {
      // With sticky markbits, InYoungGeneration and IsUnmarked below are
      // equivalent.
      InYoungGeneration(value, &check_is_unmarked, next);

      BIND(&check_is_unmarked);
    }

    GotoIfNot(IsUnmarked(value), next);

    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IncrementalWriteBarrierMajor(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &marking_cpp_slow_path, next);

    BIND(&marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_marking_from_code_function());
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));
      Goto(next);
    }
  }

  void IsValueUnmarkedOrRecordSlot(TNode<IntPtrT> value, Label* true_label,
                                   Label* false_label) {
    // This code implements the following condition:
    // IsUnmarked(value) ||
    //   OnEvacuationCandidate(value) &&
    //   !SkipEvacuationCandidateRecording(value)

    // 1) IsUnmarked(value) || ....
    GotoIf(IsUnmarked(value), true_label);

    // 2) OnEvacuationCandidate(value) &&
    //    !SkipEvacuationCandidateRecording(value)
    GotoIfNot(IsPageFlagSet(value, MemoryChunk::kEvacuationCandidateMask),
              false_label);

    {
      TNode<IntPtrT> object = BitcastTaggedToWord(
          UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
      Branch(
          IsPageFlagSet(object, MemoryChunk::kSkipEvacuationSlotsRecordingMask),
          false_label, true_label);
    }
  }

  void IncrementalWriteBarrier(TNode<IntPtrT> slot, SaveFPRegsMode fp_mode) {
    Label next(this), write_into_shared_object(this),
        write_into_local_object(this),
        local_object_and_value(this, Label::kDeferred);

    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));
    TNode<IntPtrT> value = BitcastTaggedToWord(Load<HeapObject>(slot));

    // Without a shared heap, all objects are local. This is the fast path
    // always used when no shared heap exists.
    GotoIfNot(UsesSharedHeap(), &local_object_and_value);

    // From the point-of-view of the shared space isolate (= the main isolate)
    // shared heap objects are just local objects.
    GotoIf(IsSharedSpaceIsolate(), &local_object_and_value);

    // These checks here are now only reached by client isolates (= worker
    // isolates). Now first check whether incremental marking is activated for
    // that particular object's space. Incrementally marking might only be
    // enabled for either local or shared objects on client isolates.
    GotoIfNot(IsPageFlagSet(object, MemoryChunk::kIncrementalMarking), &next);

    // We now know that incremental marking is enabled for the given object.
    // Decide whether to run the shared or local incremental marking barrier.
    InSharedHeap(object, &write_into_shared_object, &write_into_local_object);

    BIND(&write_into_shared_object);

    // Run the shared incremental marking barrier.
    IncrementalWriteBarrierShared(object, slot, value, fp_mode, &next);

    BIND(&write_into_local_object);

    // When writing into a local object we can ignore stores of shared object
    // values since for those no slot recording or marking is required.
    InSharedHeap(value, &next, &local_object_and_value);

    // Both object and value are now guaranteed to be local objects, run the
    // local incremental marking barrier.
    BIND(&local_object_and_value);
    IncrementalWriteBarrierLocal(slot, value, fp_mode, &next);

    BIND(&next);
  }

  void IncrementalWriteBarrierShared(TNode<IntPtrT> object, TNode<IntPtrT> slot,
                                     TNode<IntPtrT> value,
                                     SaveFPRegsMode fp_mode, Label* next) {
    Label shared_marking_cpp_slow_path(this);

    IsValueUnmarkedOrRecordSlot(value, &shared_marking_cpp_slow_path, next);

    BIND(&shared_marking_cpp_slow_path);
    {
      TNode<ExternalReference> function = ExternalConstant(
          ExternalReference::write_barrier_shared_marking_from_code_function());
      CallCFunctionWithCallerSavedRegisters(
          function, MachineTypeOf<Int32T>::value, fp_mode,
          std::make_pair(MachineTypeOf<IntPtrT>::value, object),
          std::make_pair(MachineTypeOf<IntPtrT>::value, slot));

      Goto(next);
    }
  }

  void IncrementalWriteBarrierLocal(TNode<IntPtrT> slot, TNode<IntPtrT> value,
                                    SaveFPRegsMode fp_mode, Label* next) {
    Label is_minor(this), is_major(this);
    Branch(IsMinorMarking(), &is_minor, &is_major);

    BIND(&is_minor);
    IncrementalWriteBarrierMinor(slot, value, fp_mode, next);

    BIND(&is_major);
    IncrementalWriteBarrierMajor(slot, value, fp_mode, next);
  }

  void GenerateRecordWrite(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    WriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateIndirectPointerBarrier(SaveFPRegsMode fp_mode) {
    if (V8_DISABLE_WRITE_BARRIERS_BOOL) {
      Return(TrueConstant());
      return;
    }

    if (!V8_ENABLE_SANDBOX_BOOL) {
      Unreachable();
      return;
    }

    IndirectPointerWriteBarrier(fp_mode);
    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }

  void GenerateEphemeronKeyBarrier(SaveFPRegsMode fp_mode) {
    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::ephemeron_key_write_barrier_function());
    TNode<ExternalReference> isolate_constant =
        ExternalConstant(ExternalReference::isolate_address());
    // In this method we limit the allocatable registers so we have to use
    // UncheckedParameter. Parameter does not work because the checked cast
    // needs more registers.
    auto address =
        UncheckedParameter<IntPtrT>(WriteBarrierDescriptor::kSlotAddress);
    TNode<IntPtrT> object = BitcastTaggedToWord(
        UncheckedParameter<Object>(WriteBarrierDescriptor::kObject));

    CallCFunctionWithCallerSavedRegisters(
        function, MachineTypeOf<Int32T>::value, fp_mode,
        std::make_pair(MachineTypeOf<IntPtrT>::value, object),
        std::make_pair(MachineTypeOf<IntPtrT>::value, address),
        std::make_pair(MachineTypeOf<ExternalReference>::value,
                       isolate_constant));

    IncrementCounter(isolate()->counters()->write_barriers(), 1);
    Return(TrueConstant());
  }
};

TF_BUILTIN(RecordWriteSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kSave);
}

TF_BUILTIN(RecordWriteIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateRecordWrite(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(IndirectPointerBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(IndirectPointerBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateIndirectPointerBarrier(SaveFPRegsMode::kIgnore);
}

TF_BUILTIN(EphemeronKeyBarrierSaveFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kSave);
}

TF_BUILTIN(EphemeronKeyBarrierIgnoreFP, WriteBarrierCodeStubAssembler) {
  GenerateEphemeronKeyBarrier(SaveFPRegsMode::kIgnore);
}

#ifdef V8_IS_TSAN
class TSANRelaxedStoreCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANRelaxedStoreCodeStubAssembler(
      compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt8Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_8_bits());
    } else if (size == kInt16Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_16_bits());
    } else if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_relaxed_store_function_64_bits());
    }
  }

  void GenerateTSANRelaxedStore(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANStoreDescriptor::kAddress);
    TNode<IntPtrT> value = BitcastTaggedToWord(
        UncheckedParameter<Object>(TSANStoreDescriptor::kValue));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address),
        std::make_pair(MachineType::IntPtr(), value));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANRelaxedStore8IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt8Size);
}

TF_BUILTIN(TSANRelaxedStore8SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt8Size);
}

TF_BUILTIN(TSANRelaxedStore16IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt16Size);
}

TF_BUILTIN(TSANRelaxedStore16SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt16Size);
}

TF_BUILTIN(TSANRelaxedStore32IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANRelaxedStore32SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANRelaxedStore64IgnoreFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANRelaxedStore64SaveFP, TSANRelaxedStoreCodeStubAssembler) {
  GenerateTSANRelaxedStore(SaveFPRegsMode::kSave, kInt64Size);
}

class TSANSeqCstStoreCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANSeqCstStoreCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt8Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_8_bits());
    } else if (size == kInt16Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_16_bits());
    } else if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_seq_cst_store_function_64_bits());
    }
  }

  void GenerateTSANSeqCstStore(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANStoreDescriptor::kAddress);
    TNode<IntPtrT> value = BitcastTaggedToWord(
        UncheckedParameter<Object>(TSANStoreDescriptor::kValue));
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address),
        std::make_pair(MachineType::IntPtr(), value));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANSeqCstStore8IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt8Size);
}

TF_BUILTIN(TSANSeqCstStore8SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt8Size);
}

TF_BUILTIN(TSANSeqCstStore16IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt16Size);
}

TF_BUILTIN(TSANSeqCstStore16SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt16Size);
}

TF_BUILTIN(TSANSeqCstStore32IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANSeqCstStore32SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANSeqCstStore64IgnoreFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANSeqCstStore64SaveFP, TSANSeqCstStoreCodeStubAssembler) {
  GenerateTSANSeqCstStore(SaveFPRegsMode::kSave, kInt64Size);
}

class TSANRelaxedLoadCodeStubAssembler : public CodeStubAssembler {
 public:
  explicit TSANRelaxedLoadCodeStubAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<ExternalReference> GetExternalReference(int size) {
    if (size == kInt32Size) {
      return ExternalConstant(
          ExternalReference::tsan_relaxed_load_function_32_bits());
    } else {
      CHECK_EQ(size, kInt64Size);
      return ExternalConstant(
          ExternalReference::tsan_relaxed_load_function_64_bits());
    }
  }

  void GenerateTSANRelaxedLoad(SaveFPRegsMode fp_mode, int size) {
    TNode<ExternalReference> function = GetExternalReference(size);
    auto address = UncheckedParameter<IntPtrT>(TSANLoadDescriptor::kAddress);
    CallCFunctionWithCallerSavedRegisters(
        function, MachineType::Int32(), fp_mode,
        std::make_pair(MachineType::IntPtr(), address));
    Return(UndefinedConstant());
  }
};

TF_BUILTIN(TSANRelaxedLoad32IgnoreFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kIgnore, kInt32Size);
}

TF_BUILTIN(TSANRelaxedLoad32SaveFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kSave, kInt32Size);
}

TF_BUILTIN(TSANRelaxedLoad64IgnoreFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kIgnore, kInt64Size);
}

TF_BUILTIN(TSANRelaxedLoad64SaveFP, TSANRelaxedLoadCodeStubAssembler) {
  GenerateTSANRelaxedLoad(SaveFPRegsMode::kSave, kInt64Size);
}
#endif  // V8_IS_TSAN

class DeletePropertyBaseAssembler : public AccessorAssembler {
 public:
  explicit DeletePropertyBaseAssembler(compiler::CodeAssemblerState* state)
      : AccessorAssembler(state) {}

  void DictionarySpecificDelete(TNode<JSReceiver> receiver,
                                TNode<NameDictionary> properties,
                                TNode<IntPtrT> key_index,
                                TNode<Context> context) {
    // Overwrite the entry itself (see NameDictionary::SetEntry).
    TNode<Hole> filler = TheHoleConstant();
    DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kTheHoleValue));
    StoreFixedArrayElement(properties, key_index, filler, SKIP_WRITE_BARRIER);
    StoreValueByKeyIndex<NameDictionary>(properties, key_index, filler,
                                         SKIP_WRITE_BARRIER);
    StoreDetailsByKeyIndex<NameDictionary>(properties, key_index,
                                           SmiConstant(0));

    // Update bookkeeping information (see NameDictionary::ElementRemoved).
    TNode<Smi> nof = GetNumberOfElements<NameDictionary>(properties);
    TNode<Smi> new_nof = SmiSub(nof, SmiConstant(1));
    SetNumberOfElements<NameDictionary>(properties, new_nof);
    TNode<Smi> num_deleted =
        GetNumberOfDeletedElements<NameDictionary>(properties);
    TNode<Smi> new_deleted = SmiAdd(num_deleted, SmiConstant(1));
    SetNumberOfDeletedElements<NameDictionary>(properties, new_deleted);

    // Shrink the dictionary if necessary (see NameDictionary::Shrink).
    Label shrinking_done(this);
    TNode<Smi> capacity = GetCapacity<NameDictionary>(properties);
    GotoIf(SmiGreaterThan(new_nof, SmiShr(capacity, 2)), &shrinking_done);
    GotoIf(SmiLessThan(new_nof, SmiConstant(16)), &shrinking_done);

    TNode<NameDictionary> new_properties =
        CAST(CallRuntime(Runtime::kShrinkNameDictionary, context, properties));

    StoreJSReceiverPropertiesOrHash(receiver, new_properties);

    Goto(&shrinking_done);
    BIND(&shrinking_done);
  }

  void DictionarySpecificDelete(TNode<JSReceiver> receiver,
                                TNode<SwissNameDictionary> properties,
                                TNode<IntPtrT> key_index,
                                TNode<Context> context) {
    Label shrunk(this), done(this);
    TVARIABLE(SwissNameDictionary, shrunk_table);

    SwissNameDictionaryDelete(properties, key_index, &shrunk, &shrunk_table);
    Goto(&done);
    BIND(&shrunk);
    StoreJSReceiverPropertiesOrHash(receiver, shrunk_table.value());
    Goto(&done);

    BIND(&done);
  }

  template <typename Dictionary>
  void DeleteDictionaryProperty(TNode<JSReceiver> receiver,
                                TNode<Dictionary> properties, TNode<Name> name,
                                TNode<Context> context, Label* dont_delete,
                                Label* notfound) {
    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index);
    NameDictionaryLookup<Dictionary>(properties, name, &dictionary_found,
                                     &var_name_index, notfound);

    BIND(&dictionary_found);
    TNode<IntPtrT> key_index = var_name_index.value();
    TNode<Uint32T> details = LoadDetailsByKeyIndex(properties, key_index);
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesDontDeleteMask),
           dont_delete);

    DictionarySpecificDelete(receiver, properties, key_index, context);

    Return(TrueConstant());
  }
};

TF_BUILTIN(DeleteProperty, DeletePropertyBaseAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto language_mode = Parameter<Smi>(Descriptor::kLanguageMode);
  auto context = Parameter<Context>(Descriptor::kContext);

  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);
  Label if_index(this, &var_index), if_unique_name(this), if_notunique(this),
      if_notfound(this), slow(this), if_proxy(this);

  GotoIf(TaggedIsSmi(receiver), &slow);
  TNode<Map> receiver_map = LoadMap(CAST(receiver));
  TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
  GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), &if_proxy);
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), &slow);
  TryToName(key, &if_index, &var_index, &if_unique_name, &var_unique, &slow,
            &if_notunique);

  BIND(&if_index);
  {
    Comment("integer index");
    Goto(&slow);  // TODO(jkummerow): Implement more smarts here.
  }

  BIND(&if_unique_name);
  {
    Comment("key is unique name");
    CheckForAssociatedProtector(var_unique.value(), &slow);

    Label dictionary(this), dont_delete(this);
    GotoIf(IsDictionaryMap(receiver_map), &dictionary);

    // Fast properties need to clear recorded slots and mark the deleted
    // property as mutable, which can only be done in C++.
    Goto(&slow);

    BIND(&dictionary);
    {
      InvalidateValidityCellIfPrototype(receiver_map);

      TNode<PropertyDictionary> properties =
          CAST(LoadSlowProperties(CAST(receiver)));
      DeleteDictionaryProperty(CAST(receiver), properties, var_unique.value(),
                               context, &dont_delete, &if_notfound);
    }

    BIND(&dont_delete);
    {
      static_assert(LanguageModeSize == 2);
      GotoIf(SmiNotEqual(language_mode, SmiConstant(LanguageMode::kSloppy)),
             &slow);
      Return(FalseConstant());
    }
  }

  BIND(&if_notunique);
  {
    // If the string was not found in the string table, then no object can
    // have a property with that name.
    TryInternalizeString(CAST(key), &if_index, &var_index, &if_unique_name,
                         &var_unique, &if_notfound, &slow);
  }

  BIND(&if_notfound);
  Return(TrueConstant());

  BIND(&if_proxy);
  {
    TNode<Name> name = CAST(CallBuiltin(Builtin::kToName, context, key));
    GotoIf(IsPrivateSymbol(name), &slow);
    TailCallBuiltin(Builtin::kProxyDeleteProperty, context, receiver, name,
                    language_mode);
  }

  BIND(&slow);
  {
    TailCallRuntime(Runtime::kDeleteProperty, context, receiver, key,
                    language_mode);
  }
}

namespace {

class SetOrCopyDataPropertiesAssembler : public CodeStubAssembler {
 public:
  explicit SetOrCopyDataPropertiesAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

 protected:
  TNode<JSObject> AllocateJsObjectTarget(TNode<Context> context) {
    const TNode<NativeContext> native_context = LoadNativeContext(context);
    const TNode<JSFunction> object_function = Cast(
        LoadContextElement(native_context, Context::OBJECT_FUNCTION_INDEX));
    const TNode<Map> map =
        Cast(LoadJSFunctionPrototypeOrInitialMap(object_function));
    const TNode<JSObject> target = AllocateJSObjectFromMap(map);
    return target;
  }
  TNode<Object> SetOrCopyDataProperties(
      TNode<Context> context, TNode<JSReceiver> target, TNode<Object> source,
      Label* if_runtime,
      std::optional<TNode<IntPtrT>> excluded_property_count = std::nullopt,
      std::optional<TNode<IntPtrT>> excluded_property_base = std::nullopt,
      bool use_set = true) {
    Label if_done(this), if_noelements(this),
        if_sourcenotjsobject(this, Label::kDeferred);

    // JSPrimitiveWrapper wrappers for numbers don't have any enumerable own
    // properties, so we can immediately skip the whole operation if {source} is
    // a Smi.
    GotoIf(TaggedIsSmi(source), &if_done);

    // Otherwise check if {source} is a proper JSObject, and if not, defer
    // to testing for non-empty strings below.
    TNode<Map> source_map = LoadMap(CAST(source));
    TNode<Uint16T> source_instance_type = LoadMapInstanceType(source_map);
    GotoIfNot(IsJSObjectInstanceType(source_instance_type),
              &if_sourcenotjsobject);

    TNode<FixedArrayBase> source_elements = LoadElements(CAST(source));
    GotoIf(IsEmptyFixedArray(source_elements), &if_noelements);
    Branch(IsEmptySlowElementDictionary(source_elements), &if_noelements,
           if_runtime);

    BIND(&if_noelements);
    {
      // If the target is deprecated, the object will be updated on first
      // store. If the source for that store equals the target, this will
      // invalidate the cached representation of the source. Handle this case
      // in runtime.
      TNode<Map> target_map = LoadMap(target);
      GotoIf(IsDeprecatedMap(target_map), if_runtime);
      if (use_set) {
        TNode<BoolT> target_is_simple_receiver = IsSimpleObjectMap(target_map);
        ForEachEnumerableOwnProperty(
            context, source_map, CAST(source), kEnumerationOrder,
            [=, this](TNode<Name> key, LazyNode<Object> value) {
              KeyedStoreGenericGenerator::SetProperty(
                  state(), context, target, target_is_simple_receiver, key,
                  value(), LanguageMode::kStrict);
            },
            if_runtime);
      } else {
        ForEachEnumerableOwnProperty(
            context, source_map, CAST(source), kEnumerationOrder,
            [=, this](TNode<Name> key, LazyNode<Object> value) {
              Label skip(this);
              if (excluded_property_count.has_value()) {
                BuildFastLoop<IntPtrT>(
                    IntPtrConstant(0), excluded_property_count.value(),
                    [&](TNode<IntPtrT> index) {
                      auto offset = Signed(TimesSystemPointerSize(index));
                      TNode<IntPtrT> location = Signed(
                          IntPtrSub(excluded_property_base.value(), offset));
                      auto property = LoadFullTagged(location);

                      Label continue_label(this);
                      BranchIfSameValue(key, property, &skip, &continue_label);
                      Bind(&continue_label);
                    },
                    1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);
              }

              CallBuiltin(Builtin::kCreateDataProperty, context, target, key,
                          value());
              Goto(&skip);
              Bind(&skip);
            },
            if_runtime);
      }
      Goto(&if_done);
    }

    BIND(&if_sourcenotjsobject);
    {
      // Handle other JSReceivers in the runtime.
      GotoIf(IsJSReceiverInstanceType(source_instance_type), if_runtime);

      // Non-empty strings are the only non-JSReceivers that need to be
      // handled explicitly by Object.assign() and CopyDataProperties.
      GotoIfNot(IsStringInstanceType(source_instance_type), &if_done);
      TNode<Uint32T> source_length = LoadStringLengthAsWord32(CAST(source));
      Branch(Word32Equal(source_length, Uint32Constant(0)), &if_done,
             if_runtime);
    }

    BIND(&if_done);
    return target;
  }
};

}  // namespace

TF_BUILTIN(CopyDataPropertiesWithExcludedPropertiesOnStack,
           SetOrCopyDataPropertiesAssembler) {
  auto source = UncheckedParameter<Object>(Descriptor::kSource);
  auto excluded_property_count =
      UncheckedParameter<IntPtrT>(Descriptor::kExcludedPropertyCount);
  auto excluded_properties =
      UncheckedParameter<IntPtrT>(Descriptor::kExcludedPropertyBase);
  auto context = Parameter<Context>(Descriptor::kContext);

  // first check undefine or null
  Label if_runtime(this, Label::kDeferred);
  GotoIf(IsNullOrUndefined(source), &if_runtime);

  TNode<JSReceiver> target = AllocateJsObjectTarget(context);
  Return(SetOrCopyDataProperties(context, target, source, &if_runtime,
                                 excluded_property_count, excluded_properties,
                                 false));

  BIND(&if_runtime);
  // The excluded_property_base is passed as a raw stack pointer, but is
  // bitcasted to a Smi . This is safe because the stack pointer is aligned, so
  // it looks like a Smi to the GC.
  CSA_DCHECK(this, IntPtrEqual(WordAnd(excluded_properties,
                                       IntPtrConstant(kSmiTagMask)),
                               IntPtrConstant(kSmiTag)));
  TailCallRuntime(Runtime::kCopyDataPropertiesWithExcludedPropertiesOnStack,
                  context, source, SmiTag(excluded_property_count),
                  BitcastWordToTaggedSigned(excluded_properties));
}

TF_BUILTIN(CopyDataPropertiesWithExcludedProperties,
           SetOrCopyDataPropertiesAssembler) {
  auto source = UncheckedParameter<Object>(Descriptor::kSource);

  auto excluded_property_count_smi =
      UncheckedParameter<Smi>(Descriptor::kExcludedPropertyCount);
  auto context = Parameter<Context>(Descriptor::kContext);

  auto excluded_property_count = SmiToIntPtr(excluded_property_count_smi);
  CodeStubArguments arguments(this, excluded_property_count);

  TNode<IntPtrT> excluded_properties =
      ReinterpretCast<IntPtrT>(arguments.AtIndexPtr(
          IntPtrSub(excluded_property_count, IntPtrConstant(2))));

  arguments.PopAndReturn(CallBuiltin(
      Builtin::kCopyDataPropertiesWithExcludedPropertiesOnStack, context,
      source, excluded_property_count, excluded_properties));
}

// ES #sec-copydataproperties
TF_BUILTIN(CopyDataProperties, SetOrCopyDataPropertiesAssembler) {
  auto target = Parameter<JSObject>(Descriptor::kTarget);
  auto source = Parameter<Object>(Descriptor::kSource);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, TaggedNotEqual(target, source));

  Label if_runtime(this, Label::kDeferred);
  SetOrCopyDataProperties(context, target, source, &if_runtime, std::nullopt,
                          std::nullopt, false);
  Return(UndefinedConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kCopyDataProperties, context, target, source);
}

TF_BUILTIN(SetDataProperties, SetOrCopyDataPropertiesAssembler) {
  auto target = Parameter<JSReceiver>(Descriptor::kTarget);
  auto source = Parameter<Object>(Descriptor::kSource);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_runtime(this, Label::kDeferred);
  GotoIfForceSlowPath(&if_runtime);
  SetOrCopyDataProperties(context, target, source, &if_runtime, std::nullopt,
                          std::nullopt, true);
  Return(UndefinedConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kSetDataProperties, context, target, source);
}

TF_BUILTIN(ForInEnumerate, CodeStubAssembler) {
  auto receiver = Parameter<JSReceiver>(Descriptor::kReceiver);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_empty(this), if_runtime(this, Label::kDeferred);
  TNode<Map> receiver_map = CheckEnumCache(receiver, &if_empty, &if_runtime);
  Return(receiver_map);

  BIND(&if_empty);
  Return(EmptyFixedArrayConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kForInEnumerate, context, receiver);
}

TF_BUILTIN(ForInPrepare, CodeStubAssembler) {
  // The {enumerator} is either a Map or a FixedArray.
  auto enumerator = Parameter<HeapObject>(Descriptor::kEnumerator);
  auto index = Parameter<TaggedIndex>(Descriptor::kVectorIndex);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  TNode<UintPtrT> vector_index = Unsigned(TaggedIndexToIntPtr(index));

  TNode<FixedArray> cache_array;
  TNode<Smi> cache_length;
  ForInPrepare(enumerator, vector_index, feedback_vector, &cache_array,
               &cache_length, UpdateFeedbackMode::kGuaranteedFeedback);
  Return(cache_array, cache_length);
}

TF_BUILTIN(ForInFilter, CodeStubAssembler) {
  auto key = Parameter<String>(Descriptor::kKey);
  auto object = Parameter<HeapObject>(Descriptor::kObject);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_true(this), if_false(this);
  TNode<Oddball> result = HasProperty(context, object, key, kForInHasProperty);
  Branch(IsTrue(result), &if_true, &if_false);

  BIND(&if_true);
  Return(key);

  BIND(&if_false);
  Return(UndefinedConstant());
}

TF_BUILTIN(SameValue, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);

  Label if_true(this), if_false(this);
  BranchIfSameValue(lhs, rhs, &if_true, &if_false);

  BIND(&if_true);
  Return(TrueConstant());

  BIND(&if_false);
  Return(FalseConstant());
}

TF_BUILTIN(SameValueNumbersOnly, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);

  Label if_true(this), if_false(this);
  BranchIfSameValue(lhs, rhs, &if_true, &if_false, SameValueMode::kNumbersOnly);

  BIND(&if_true);
  Return(TrueConstant());

  BIND(&if_false);
  Return(FalseConstant());
}

class CppBuiltinsAdaptorAssembler : public CodeStubAssembler {
 public:
  using Descriptor = CppBuiltinAdaptorDescriptor;

  explicit CppBuiltinsAdaptorAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  void GenerateAdaptor(int formal_parameter_count);
};

void CppBuiltinsAdaptorAssembler::GenerateAdaptor(int formal_parameter_count) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto target = Parameter<JSFunction>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto c_function = UncheckedParameter<WordT>(Descriptor::kCFunction);
  auto actual_argc =
      UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);

  // The logic contained here is mirrored for TurboFan inlining in
  // JSTypedLowering::ReduceJSCall{Function,Construct}. Keep these in sync.

  // Make sure we operate in the context of the called function.
  CSA_DCHECK(this, TaggedEqual(context, LoadJSFunctionContext(target)));

  static_assert(kDontAdaptArgumentsSentinel == 0);
  // The code below relies on |actual_argc| to include receiver.
  static_assert(i::JSParameterCount(0) == 1);
  TVARIABLE(Int32T, pushed_argc, actual_argc);

  // It's guaranteed that the receiver is pushed to the stack, thus both
  // kDontAdaptArgumentsSentinel and JSParameterCount(0) cases don't require
  // arguments adaptation. Just use the latter version for consistency.
  DCHECK_NE(kDontAdaptArgumentsSentinel, formal_parameter_count);
  if (formal_parameter_count > i::JSParameterCount(0)) {
    TNode<Int32T> formal_count = Int32Constant(formal_parameter_count);

    // The number of arguments pushed is the maximum of actual arguments count
    // and formal parameters count.
    Label done_argc(this);
    GotoIf(Int32GreaterThanOrEqual(pushed_argc.value(), formal_count),
           &done_argc);
    // Update pushed args.
    pushed_argc = formal_count;
    Goto(&done_argc);
    BIND(&done_argc);
  }

  // Update arguments count for CEntry to contain the number of arguments
  // including the receiver and the extra arguments.
  TNode<Int32T> argc =
      Int32Add(pushed_argc.value(),
               Int32Constant(BuiltinExitFrameConstants::kNumExtraArgs));

  const bool builtin_exit_frame = true;
  const bool switch_to_central_stack = false;
  Builtin centry = Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame,
                                    switch_to_central_stack);

  static_assert(BuiltinArguments::kNewTargetIndex == 0);
  static_assert(BuiltinArguments::kTargetIndex == 1);
  static_assert(BuiltinArguments::kArgcIndex == 2);
  static_assert(BuiltinArguments::kPaddingIndex == 3);

  // Unconditionally push argc, target and new target as extra stack arguments.
  // They will be used by stack frame iterators when constructing stack trace.
  TailCallBuiltin(centry, context,     // standard arguments for TailCallBuiltin
                  argc, c_function,    // register arguments
                  TheHoleConstant(),   // additional stack argument 1 (padding)
                  SmiFromInt32(argc),  // additional stack argument 2
                  target,              // additional stack argument 3
                  new_target);         // additional stack argument 4
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame0, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(0));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame1, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(1));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame2, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(2));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame3, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(3));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame4, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(4));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame5, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(5));
}

TF_BUILTIN(NewHeapNumber, CodeStubAssembler) {
  auto val = UncheckedParameter<Float64T>(Descriptor::kValue);
  Return(ChangeFloat64ToTagged(val));
}

TF_BUILTIN(AllocateInYoungGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> allocation_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), allocation_flags);
}

TF_BUILTIN(AllocateInOldGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> runtime_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), runtime_flags);
}

#if V8_ENABLE_WEBASSEMBLY
TF_BUILTIN(WasmAllocateInYoungGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> allocation_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), allocation_flags);
}

TF_BUILTIN(WasmAllocateInOldGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> runtime_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), runtime_flags);
}
#endif

TF_BUILTIN(Abort, CodeStubAssembler) {
  auto message_id = Parameter<Smi>(Descriptor::kMessageOrMessageId);
  TailCallRuntime(Runtime::kAbort, NoContextConstant(), message_id);
}

TF_BUILTIN(AbortCSADcheck, CodeStubAssembler) {
  auto message = Parameter<String>(Descriptor::kMessageOrMessageId);
  TailCallRuntime(Runtime::kAbortCSADcheck, NoContextConstant(), message);
}

void Builtins::Generate_CEntry_Return1_ArgvOnStack_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, false, false);
}

void Builtins::Generate_CEntry_Return1_ArgvOnStack_BuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, true, false);
}

void Builtins::Generate_CEntry_Return1_ArgvInRegister_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kRegister, false, false);
}

void Builtins::Generate_CEntry_Return2_ArgvOnStack_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kStack, false, false);
}

void Builtins::Generate_CEntry_Return2_ArgvOnStack_BuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kStack, true, false);
}

void Builtins::Generate_CEntry_Return2_ArgvInRegister_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kRegister, false, false);
}

void Builtins::Generate_WasmCEntry(MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, false, true);
}

#if !defined(V8_TARGET_ARCH_ARM)
void Builtins::Generate_MemCopyUint8Uint8(MacroAssembler* masm) {
  masm->CallBuiltin(Builtin::kIllegal);
}
#endif  // !defined(V8_TARGET_ARCH_ARM)

#ifndef V8_TARGET_ARCH_IA32
void Builtins::Generate_MemMove(MacroAssembler* masm) {
  masm->CallBuiltin(Builtin::kIllegal);
}
#endif  // V8_TARGET_ARCH_IA32

void Builtins::Generate_BaselineLeaveFrame(MacroAssembler* masm) {
#ifdef V8_ENABLE_SPARKPLUG
  EmitReturnBaseline(masm);
#else
  masm->Trap();
#endif  // V8_ENABLE_SPARKPLUG
}

// TODO(v8:11421): Remove #if once the Maglev compiler is ported to other
// architectures.
#ifndef V8_TARGET_ARCH_X64
void Builtins::Generate_MaglevOnStackReplacement(MacroAssembler* masm) {
  using D =
      i::CallInterfaceDescriptorFor<Builtin::kMaglevOnStackReplacement>::type;
  static_assert(D::kParameterCount == 1);
  masm->Trap();
}
#endif  // V8_TARGET_ARCH_X64

#if defined(V8_ENABLE_MAGLEV) && !defined(V8_ENABLE_LEAPTIERING)
void Builtins::Generate_MaglevOptimizeCodeOrTailCallOptimizedCodeSlot(
    MacroAssembler* masm) {
  using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
  Register flags = D::GetRegisterParameter(D::kFlags);
  Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
  Register temporary = D::GetRegisterParameter(D::kTemporary);
  masm->AssertFeedbackVector(feedback_vector, temporary);
  masm->OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
  masm->Trap();
}
#else
void Builtins::Generate_MaglevOptimizeCodeOrTailCallOptimizedCodeSlot(
    MacroAssembler* masm) {
  masm->Trap();
}
#endif  // V8_ENABLE_MAGLEV && !V8_ENABLE_LEAPTIERING

#ifndef V8_ENABLE_MAGLEV
// static
void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  masm->Trap();
}
#endif  // !V8_ENABLE_MAGLEV

void Builtins::Generate_MaglevFunctionEntryStackCheck_WithoutNewTarget(
    MacroAssembler* masm) {
  Generate_MaglevFunctionEntryStackCheck(masm, false);
}

void Builtins::Generate_MaglevFunctionEntryStackCheck_WithNewTarget(
    MacroAssembler* masm) {
  Generate_MaglevFunctionEntryStackCheck(masm, true);
}

// ES6 [[Get]] operation.
TF_BUILTIN(GetProperty, CodeStubAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);
  // TODO(duongn): consider tailcalling to GetPropertyWithReceiver(object,
  // object, key, OnNonExistent::kReturnUndefined).
  Label if_notfound(this), if_proxy(this, Label::kDeferred),
      if_slow(this, Label::kDeferred);

  CodeStubAssembler::LookupPropertyInHolder lookup_property_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<Name> unique_name, Label* next_holder,
                Label* if_bailout) {
        TVARIABLE(Object, var_value);
        Label if_found(this);
        // If we get here then it's guaranteed that |object| (and thus the
        // |receiver|) is a JSReceiver.
        TryGetOwnProperty(context, receiver, CAST(holder), holder_map,
                          holder_instance_type, unique_name, &if_found,
                          &var_value, next_holder, if_bailout,
                          kExpectingJSReceiver);
        BIND(&if_found);
        Return(var_value.value());
      };

  CodeStubAssembler::LookupElementInHolder lookup_element_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<IntPtrT> index, Label* next_holder, Label* if_bailout) {
        // Not supported yet.
        Use(next_holder);
        Goto(if_bailout);
      };

  TryPrototypeChainLookup(object, object, key, lookup_property_in_holder,
                          lookup_element_in_holder, &if_notfound, &if_slow,
                          &if_proxy);

  BIND(&if_notfound);
  Return(UndefinedConstant());

  BIND(&if_slow);
  TailCallRuntime(Runtime::kGetProperty, context, object, key);

  BIND(&if_proxy);
  {
    // Convert the {key} to a Name first.
    TNode<Object> name = CallBuiltin(Builtin::kToName, context, key);

    // The {object} is a JSProxy instance, look up the {name} on it, passing
    // {object} both as receiver and holder. If {name} is absent we can safely
    // return undefined from here.
    TailCallBuiltin(Builtin::kProxyGetProperty, context, object, name, object,
                    SmiConstant(OnNonExistent::kReturnUndefined));
  }
}

// ES6 [[Get]] operation with Receiver.
TF_BUILTIN(GetPropertyWithReceiver, CodeStubAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto on_non_existent = Parameter<Object>(Descriptor::kOnNonExistent);
  Label if_notfound(this), if_proxy(this, Label::kDeferred),
      if_slow(this, Label::kDeferred);

  CodeStubAssembler::LookupPropertyInHolder lookup_property_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<Name> unique_name, Label* next_holder,
                Label* if_bailout) {
        TVARIABLE(Object, var_value);
        Label if_found(this);
        TryGetOwnProperty(context, receiver, CAST(holder), holder_map,
                          holder_instance_type, unique_name, &if_found,
                          &var_value, next_holder, if_bailout,
                          kExpectingAnyReceiver);
        BIND(&if_found);
        Return(var_value.value());
      };

  CodeStubAssembler::LookupElementInHolder lookup_element_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<IntPtrT> index, Label* next_holder, Label* if_bailout) {
        // Not supported yet.
        Use(next_holder);
        Goto(if_bailout);
      };

  TryPrototypeChainLookup(receiver, object, key, lookup_property_in_holder,
                          lookup_element_in_holder, &if_notfound, &if_slow,
                          &if_proxy);

  BIND(&if_notfound);
  Label throw_reference_error(this);
  GotoIf(TaggedEqual(on_non_existent,
                     SmiConstant(OnNonExistent::kThrowReferenceError)),
         &throw_reference_error);
  CSA_DCHECK(this, TaggedEqual(on_non_existent,
                               SmiConstant(OnNonExistent::kReturnUndefined)));
  Return(UndefinedConstant());

  BIND(&throw_reference_error);
  Return(CallRuntime(Runtime::kThrowReferenceError, context, key));

  BIND(&if_slow);
  TailCallRuntime(Runtime::kGetPropertyWithReceiver, context, object, key,
                  receiver, on_non_existent);

  BIND(&if_proxy);
  {
    // Convert the {key} to a Name first.
    TNode<Name> name = CAST(CallBuiltin(Builtin::kToName, context, key));

    // Proxy cannot handle private symbol so bailout.
    GotoIf(IsPrivateSymbol(name), &if_slow);

    // The {object} is a JSProxy instance, look up the {name} on it, passing
    // {object} both as receiver and holder. If {name} is absent we can safely
    // return undefined from here.
    TailCallBuiltin(Builtin::kProxyGetProperty, context, object, name, receiver,
                    on_non_existent);
  }
}

// ES6 [[Set]] operation.
TF_BUILTIN(SetProperty, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  KeyedStoreGenericGenerator::SetProperty(state(), context, receiver, key,
                                          value, LanguageMode::kStrict);
}

// ES6 CreateDataProperty(), specialized for the case where objects are still
// being initialized, and have not yet been made accessible to the user. Thus,
// any operation here should be unobservable until after the object has been
// returned.
TF_BUILTIN(CreateDataProperty, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  KeyedStoreGenericGenerator::CreateDataProperty(state(), context, receiver,
                                                 key, value);
}

TF_BUILTIN(InstantiateAsmJs, CodeStubAssembler) {
  Label tailcall_to_function(this);
  auto function = Parameter<JSFunction>(Descriptor::kTarget);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto arg_count =
      UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
#ifdef V8_ENABLE_LEAPTIERING
  auto dispatch_handle =
      UncheckedParameter<JSDispatchHandleT>(Descriptor::kDispatchHandle);
#else
  auto dispatch_handle = InvalidDispatchHandleConstant();
#endif

  // This builtin is used on functions with different parameter counts.
  SetSupportsDynamicParameterCount(function, dispatch_handle);

  // Retrieve arguments from caller (stdlib, foreign, heap).
  CodeStubArguments args(this, arg_count);

  TNode<Object> stdlib = args.GetOptionalArgumentValue(0);
  TNode<Object> foreign = args.GetOptionalArgumentValue(1);
  TNode<Object> heap = args.GetOptionalArgumentValue(2);

  // Call runtime, on success just pass the result to the caller and pop all
  // arguments. A smi 0 is returned on failure, an object on success.
  TNode<Object> maybe_result_or_smi_zero = CallRuntime(
      Runtime::kInstantiateAsmJs, context, function, stdlib, foreign, heap);
  GotoIf(TaggedIsSmi(maybe_result_or_smi_zero), &tailcall_to_function);
  args.PopAndReturn(maybe_result_or_smi_zero);

  BIND(&tailcall_to_function);
  // On failure, tail call back to regular JavaScript by re-calling the given
  // function which has been reset to the compile lazy builtin.

  TNode<Code> code = LoadJSFunctionCode(function);
  TailCallJSCode(code, context, function, new_target, arg_count,
                 disp
```