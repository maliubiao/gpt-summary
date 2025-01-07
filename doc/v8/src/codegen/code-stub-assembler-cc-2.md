Response:
My thinking process to analyze the provided C++ code snippet and generate the summary involved these steps:

1. **Understand the Goal:** The request asks for a functional summary of the given C++ code, specifically within the context of V8's `code-stub-assembler.cc`. It also mentions potential `.tq` files (Torque) and connections to JavaScript. Crucially, it identifies this as part 3 of 23, implying a broader system at play.

2. **Initial Scan for Key Areas:** I first skimmed the code looking for recurring patterns, function names, and preprocessor directives (`#ifdef`). This quickly highlighted several important areas:
    * **Memory Access:**  Functions like `LoadObjectField`, `StoreObjectField`, `Load`, `StoreNoWriteBarrier`.
    * **Tagged Pointers and Untagging:** Functions like `LoadAndUntagPositiveSmiObjectField`, `SmiToInt32`, `BitcastWordToTagged`.
    * **Sandboxing (`V8_ENABLE_SANDBOX`):**  Large portions of the code are conditionally compiled based on this flag.
    * **External Pointers:** Functions involving `ExternalPointerTableAddress`, `LoadExternalPointerFromObject`, `StoreExternalPointerToObject`.
    * **Indirect Pointers and Tables:** Functions related to `IndirectPointerHandleT`, `ResolveIndirectPointerHandle`, `code_pointer_table_address`, `trusted_pointer_table_base_address`.
    * **JSDispatch Tables:** Functions like `LoadCodeObjectFromJSDispatchTable`, `ComputeJSDispatchTableEntryOffset`.
    * **Object Property Access:**  Functions for loading properties from various object types (JSReceiver, JSArray, FixedArrayBase, etc.).
    * **Map Handling:** Functions for loading and inspecting `Map` objects (`LoadMap`, `LoadInstanceType`, `LoadMapBitField`, etc.).
    * **Name Hashing:** Functions for loading and computing name hashes.
    * **String Handling:** Functions for loading string lengths.
    * **MaybeObject Handling:** Functions dealing with potentially weak or cleared references.

3. **Focus on the Core Functionality:** I realized the central theme is providing low-level primitives for accessing and manipulating objects in V8's heap. The `CodeStubAssembler` appears to be a tool for generating machine code stubs, and these functions are helpers within that process.

4. **Analyze Conditional Compilation (`#ifdef V8_ENABLE_SANDBOX`):** The extensive use of `#ifdef V8_ENABLE_SANDBOX` is a critical observation. This indicates that a significant part of the code deals with memory safety and isolation when sandboxing is enabled. The code provides different implementations based on whether sandboxing is active.

5. **Identify Potential JavaScript Relationships:**  While the code itself is C++, its purpose is to support JavaScript execution. The functions for accessing object properties, handling maps, and dealing with strings and numbers directly relate to how JavaScript objects are represented and manipulated in memory. I looked for concepts directly mirroring JavaScript behavior.

6. **Code Logic and Data Structures:**  I examined specific function implementations to understand their logic. For example, the functions for loading external and indirect pointers reveal the existence of tables and handle mechanisms for managing these pointers, particularly in the context of sandboxing. The bitwise operations and shifts are important for understanding how data is packed and interpreted.

7. **Common Programming Errors:**  Based on the functionality, I considered potential errors. Incorrect offsets, type mismatches, and failing to handle weak or cleared references are all possibilities when working with low-level memory access.

8. **Relate to the Broader Context (Part 3 of 23):**  Knowing this is part of a larger system, I inferred that this section likely focuses on the *low-level memory access and object manipulation primitives* used by other parts of the `CodeStubAssembler` and potentially higher-level code generation within V8.

9. **Formulate the Summary:** I started drafting the summary by grouping related functionalities. I highlighted the core purpose of providing low-level access primitives. I then specifically addressed the points raised in the prompt:
    * **Functionality:**  List the key capabilities identified in the analysis.
    * **Torque:** Mention the `.tq` possibility and its implications.
    * **JavaScript Relationship:** Provide concrete JavaScript examples demonstrating how the C++ code's functionality manifests in JavaScript.
    * **Code Logic:**  Provide a simplified example to illustrate the interaction of the sandboxing code.
    * **Common Errors:** Give examples of typical programming mistakes related to the functions.
    * **Part 3 Summary:**  Summarize the role of this section within the larger project.

10. **Refine and Organize:** I reviewed the summary for clarity, accuracy, and completeness, ensuring it addressed all aspects of the prompt and presented the information logically. I made sure to use clear language and avoid overly technical jargon where possible. I emphasized the sandboxing aspect due to its prominence in the code.

By following these steps, I was able to analyze the provided C++ code and construct a comprehensive and informative summary that addresses the specific requirements of the prompt. The iterative process of scanning, analyzing, connecting to JavaScript concepts, and considering potential errors allowed me to build a complete picture of the code's purpose and functionality within the V8 engine.
这是 V8 源代码 `v8/src/codegen/code-stub-assembler.cc` 的一部分，主要关注于**从 V8 堆中的对象加载和存储数据，特别是针对沙箱环境下的特殊处理**。

**功能归纳:**

这部分代码提供了一系列 `CodeStubAssembler` 类的方法，用于安全且高效地从 V8 堆中的对象读取和写入各种类型的数据。 考虑到沙箱环境 (`V8_ENABLE_SANDBOX`)，这些方法实现了额外的安全机制，例如：

* **有界大小 (Bounded Size) 的加载和存储:**  `LoadBoundedSizeFromObject` 和 `StoreBoundedSizeToObject` 用于处理大小受限制的数据，在沙箱模式下会对数据进行编码和解码，以确保安全性。
* **外部指针 (External Pointer) 的加载和存储:** `LoadExternalPointerFromObject` 和 `StoreExternalPointerToObject` 用于处理指向外部内存的指针。在沙箱模式下，这些指针通过一个间接的外部指针表进行访问，增加了安全性。
* **受信任指针 (Trusted Pointer) 和代码指针 (Code Pointer) 的加载:**  `LoadTrustedPointerFromObject` 和 `LoadCodePointerFromObject` 用于加载指向受信任对象和代码对象的指针。在沙箱模式下，使用了间接指针表 (`IndirectPointerHandleT`) 来管理这些指针。
* **JS 调度表 (JSDispatch Table) 的访问:** 提供了 `LoadCodeObjectFromJSDispatchTable` 和 `LoadParameterCountFromJSDispatchTable` 等方法，用于从 JS 调度表中加载代码对象和参数计数。
* **从不同类型的对象中加载各种属性:**  提供了大量方法用于加载不同类型对象（如 `JSArgumentsObject`, `JSArray`, `FixedArrayBase`, `Map`, `String` 等）的特定字段，例如长度、元素、Map、哈希值等。 这些方法通常包含 `Load...` 的前缀。
* **Map 相关的操作:**  提供了加载和检查 `Map` 对象属性的方法，例如 `LoadMap`, `LoadInstanceType`, `HasInstanceType`, `LoadMapBitField` 等，这些方法对于理解对象的结构和类型至关重要。
* **名字哈希 (Name Hash) 的加载:** `LoadNameHash` 和 `LoadNameRawHash` 用于加载对象的名称哈希值。
* **处理 MaybeObject:** `DispatchMaybeObject` 用于处理可能包含强引用、弱引用或已被清除的 `MaybeObject`。

**关于 .tq 文件:**

如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它的确是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。 然而，根据您提供的文件名，它是一个 `.cc` 文件，表明它是 **手写的 C++ 代码**，而不是 Torque 生成的。

**与 JavaScript 的关系 (及其示例):**

这些 C++ 代码的功能直接支撑着 JavaScript 的执行。 JavaScript 对象的内存布局和属性访问是由这些底层的 C++ 代码实现的。

**例如:**

在 JavaScript 中访问对象的属性：

```javascript
const obj = { name: 'Alice', age: 30 };
console.log(obj.name); // 输出 "Alice"
```

在 V8 的底层，类似 `LoadObjectField` 的函数会被调用来读取 `obj` 对象中 `name` 属性对应的值。具体来说，V8 会：

1. **获取 `obj` 对象的内存地址。**
2. **确定 `name` 属性在对象内存布局中的偏移量。**  这通常涉及到查找对象的 `Map` (描述对象的结构和类型)。
3. **使用偏移量从对象的内存地址中加载数据。**  这可能就是 `LoadObjectField` 或类似功能的函数所做的事情。

**再例如，JavaScript 数组的长度:**

```javascript
const arr = [1, 2, 3];
console.log(arr.length); // 输出 3
```

在 V8 的底层，`LoadFastJSArrayLength` (如果数组是快速数组) 或类似的函数会被用来读取 `arr` 对象的长度字段。

**代码逻辑推理 (假设输入与输出):**

考虑 `LoadBoundedSizeFromObject` 函数：

**假设输入:**

* `object`: 指向 V8 堆中某个对象的指针 (例如，一个 `JSArray`)。
* `field_offset`:  `JSArray` 对象中存储有界大小值的字段的偏移量 (例如，存储数组元素数量的字段)。

**在非沙箱模式下 ( `#else` 分支):**

* **输出:**  直接从 `object` 的 `field_offset` 处加载并返回 `UintPtrT` 类型的值。

**在沙箱模式下 ( `#ifdef V8_ENABLE_SANDBOX` 分支):**

* **假设 `kBoundedSizeShift` 是 3 (仅作为示例):**
* **假设 `raw_value` (从对象字段加载的值) 是二进制 `0b101000` (十进制 40)。**
* `shift_amount` 将是 3。
* `decoded_value` 将是 `raw_value` 右移 3 位，即 `0b101` (十进制 5)。
* **输出:** 返回 `decoded_value`，即 5。

**这个逻辑表明，在沙箱模式下，存储的有界大小值是被编码过的 (左移)，而加载时需要解码 (右移)。这可能是为了在沙箱边界处限制直接访问，增加安全性。**

**用户常见的编程错误 (可能与这些函数相关的):**

1. **错误的偏移量:**  如果传递给 `LoadObjectField` 或类似函数的 `field_offset` 不正确，会导致读取到错误的内存位置，可能导致程序崩溃或产生未定义的行为。

   ```javascript
   // 假设我们错误地猜测了某个属性的偏移量
   // 这在 JavaScript 中不可直接操作，但在 C++ 开发中是可能发生的
   // 并导致访问错误的内存
   // ... (C++ 代码)
   TNode<IntPtrT> wrong_offset = IntPtrConstant(1000); // 假设这是错误的偏移量
   TNode<Object> value = LoadObjectField(my_object, wrong_offset);
   ```

2. **类型不匹配:**  使用错误的模板参数调用 `LoadObjectField`，导致将内存中的数据解释为错误的类型。

   ```javascript
   // 假设某个字段存储的是一个 Smi (小整数)，但我们尝试将其加载为 HeapObject
   // ... (C++ 代码)
   TNode<HeapObject> wrong_type = LoadObjectField<HeapObject>(my_object, my_smi_field_offset);
   // 这会导致类型错误，因为 Smi 不是 HeapObject
   ```

3. **在沙箱环境下不理解编码/解码:**  如果在沙箱模式下直接加载或存储有界大小的值，而不使用 `LoadBoundedSizeFromObject` 和 `StoreBoundedSizeToObject`，会导致数据不一致。

   ```javascript
   // 在沙箱模式下，直接加载编码后的值
   // ... (C++ 代码)
   TNode<UintPtrT> raw_value = LoadObjectField<UintPtrT>(object, field_offset); // 错误！应该使用 LoadBoundedSizeFromObject
   ```

**作为第 3 部分 (共 23 部分) 的功能归纳:**

考虑到这是 `CodeStubAssembler` 实现的一部分，并且是整个代码库的第 3 部分，可以推断：

这部分代码主要提供了 `CodeStubAssembler` 中用于 **低级别内存访问和数据操作的核心原语**。 它是构建更高级抽象和操作的基础。 其他部分可能会在此基础上构建更复杂的代码生成逻辑，例如实现 JavaScript 运算符、函数调用、对象创建等。

这部分代码的重点是 **安全性和效率**，特别是在考虑沙箱环境时。 它提供了一种结构化的方式来与 V8 的堆内存交互，避免了直接的、可能不安全的指针操作。  它为后续的代码生成步骤提供了可靠的 building blocks。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共23部分，请归纳一下它的功能

"""
pObject> object, TNode<IntPtrT> field_offset) {
#ifdef V8_ENABLE_SANDBOX
  TNode<Uint64T> raw_value = LoadObjectField<Uint64T>(object, field_offset);
  TNode<Uint64T> shift_amount = Uint64Constant(kBoundedSizeShift);
  TNode<Uint64T> decoded_value = Word64Shr(raw_value, shift_amount);
  return ReinterpretCast<UintPtrT>(decoded_value);
#else
  return LoadObjectField<UintPtrT>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreBoundedSizeToObject(TNode<HeapObject> object,
                                                 TNode<IntPtrT> offset,
                                                 TNode<UintPtrT> value) {
#ifdef V8_ENABLE_SANDBOX
  CSA_DCHECK(this, UintPtrLessThanOrEqual(
                       value, IntPtrConstant(kMaxSafeBufferSizeForSandbox)));
  TNode<Uint64T> raw_value = ReinterpretCast<Uint64T>(value);
  TNode<Uint64T> shift_amount = Uint64Constant(kBoundedSizeShift);
  TNode<Uint64T> encoded_value = Word64Shl(raw_value, shift_amount);
  StoreObjectFieldNoWriteBarrier<Uint64T>(object, offset, encoded_value);
#else
  StoreObjectFieldNoWriteBarrier<UintPtrT>(object, offset, value);
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_ENABLE_SANDBOX
TNode<RawPtrT> CodeStubAssembler::ExternalPointerTableAddress(
    ExternalPointerTag tag) {
  if (IsSharedExternalPointerType(tag)) {
    TNode<ExternalReference> table_address_address = ExternalConstant(
        ExternalReference::shared_external_pointer_table_address_address(
            isolate()));
    return UncheckedCast<RawPtrT>(
        Load(MachineType::Pointer(), table_address_address));
  }
  return ExternalConstant(
      ExternalReference::external_pointer_table_address(isolate()));
}
#endif  // V8_ENABLE_SANDBOX

TNode<RawPtrT> CodeStubAssembler::LoadExternalPointerFromObject(
    TNode<HeapObject> object, TNode<IntPtrT> offset, ExternalPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  TNode<RawPtrT> external_pointer_table_address =
      ExternalPointerTableAddress(tag);
  TNode<RawPtrT> table = UncheckedCast<RawPtrT>(
      Load(MachineType::Pointer(), external_pointer_table_address,
           UintPtrConstant(Internals::kExternalPointerTableBasePointerOffset)));

  TNode<ExternalPointerHandleT> handle =
      LoadObjectField<ExternalPointerHandleT>(object, offset);

  // Use UniqueUint32Constant instead of Uint32Constant here in order to ensure
  // that the graph structure does not depend on the configuration-specific
  // constant value (Uint32Constant uses cached nodes).
  TNode<Uint32T> index =
      Word32Shr(handle, UniqueUint32Constant(kExternalPointerIndexShift));
  TNode<IntPtrT> table_offset = ElementOffsetFromIndex(
      ChangeUint32ToWord(index), SYSTEM_POINTER_ELEMENTS, 0);

  TNode<UintPtrT> entry = Load<UintPtrT>(table, table_offset);
  entry = UncheckedCast<UintPtrT>(WordAnd(entry, UintPtrConstant(~tag)));
  return UncheckedCast<RawPtrT>(UncheckedCast<WordT>(entry));
#else
  return LoadObjectField<RawPtrT>(object, offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreExternalPointerToObject(TNode<HeapObject> object,
                                                     TNode<IntPtrT> offset,
                                                     TNode<RawPtrT> pointer,
                                                     ExternalPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  TNode<RawPtrT> external_pointer_table_address =
      ExternalPointerTableAddress(tag);
  TNode<RawPtrT> table = UncheckedCast<RawPtrT>(
      Load(MachineType::Pointer(), external_pointer_table_address,
           UintPtrConstant(Internals::kExternalPointerTableBasePointerOffset)));
  TNode<ExternalPointerHandleT> handle =
      LoadObjectField<ExternalPointerHandleT>(object, offset);

  // Use UniqueUint32Constant instead of Uint32Constant here in order to ensure
  // that the graph structure does not depend on the configuration-specific
  // constant value (Uint32Constant uses cached nodes).
  TNode<Uint32T> index =
      Word32Shr(handle, UniqueUint32Constant(kExternalPointerIndexShift));
  TNode<IntPtrT> table_offset = ElementOffsetFromIndex(
      ChangeUint32ToWord(index), SYSTEM_POINTER_ELEMENTS, 0);

  TNode<UintPtrT> value = UncheckedCast<UintPtrT>(pointer);
  value = UncheckedCast<UintPtrT>(WordOr(pointer, UintPtrConstant(tag)));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), table, table_offset,
                      value);
#else
  StoreObjectFieldNoWriteBarrier<RawPtrT>(object, offset, pointer);
#endif  // V8_ENABLE_SANDBOX
}

TNode<TrustedObject> CodeStubAssembler::LoadTrustedPointerFromObject(
    TNode<HeapObject> object, int field_offset, IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  return LoadIndirectPointerFromObject(object, field_offset, tag);
#else
  return LoadObjectField<TrustedObject>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

TNode<Code> CodeStubAssembler::LoadCodePointerFromObject(
    TNode<HeapObject> object, int field_offset) {
  return UncheckedCast<Code>(LoadTrustedPointerFromObject(
      object, field_offset, kCodeIndirectPointerTag));
}

#ifdef V8_ENABLE_SANDBOX
TNode<TrustedObject> CodeStubAssembler::LoadIndirectPointerFromObject(
    TNode<HeapObject> object, int field_offset, IndirectPointerTag tag) {
  TNode<IndirectPointerHandleT> handle =
      LoadObjectField<IndirectPointerHandleT>(object, field_offset);
  return ResolveIndirectPointerHandle(handle, tag);
}

TNode<BoolT> CodeStubAssembler::IsTrustedPointerHandle(
    TNode<IndirectPointerHandleT> handle) {
  return Word32Equal(Word32And(handle, Int32Constant(kCodePointerHandleMarker)),
                     Int32Constant(0));
}

TNode<TrustedObject> CodeStubAssembler::ResolveIndirectPointerHandle(
    TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    return Select<TrustedObject>(
        IsTrustedPointerHandle(handle),
        [=, this] { return ResolveTrustedPointerHandle(handle, tag); },
        [=, this] { return ResolveCodePointerHandle(handle); });
  } else if (tag == kCodeIndirectPointerTag) {
    return ResolveCodePointerHandle(handle);
  } else {
    return ResolveTrustedPointerHandle(handle, tag);
  }
}

#ifdef V8_ENABLE_LEAPTIERING
TNode<Code> CodeStubAssembler::LoadCodeObjectFromJSDispatchTable(
    TNode<JSDispatchHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::js_dispatch_table_address());
  TNode<UintPtrT> offset = ComputeJSDispatchTableEntryOffset(handle);
  offset =
      UintPtrAdd(offset, UintPtrConstant(JSDispatchEntry::kCodeObjectOffset));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // The LSB is used as marking bit by the js dispatch table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  value = UncheckedCast<UintPtrT>(WordOr(
      WordShr(value, UintPtrConstant(JSDispatchEntry::kObjectPointerShift)),
      UintPtrConstant(kHeapObjectTag)));
  return CAST(BitcastWordToTagged(value));
}

TNode<Uint16T> CodeStubAssembler::LoadParameterCountFromJSDispatchTable(
    TNode<JSDispatchHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::js_dispatch_table_address());
  TNode<UintPtrT> offset = ComputeJSDispatchTableEntryOffset(handle);
  offset =
      UintPtrAdd(offset, UintPtrConstant(JSDispatchEntry::kCodeObjectOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  return Load<Uint16T>(table, offset);
}
#endif  // V8_ENABLE_LEAPTIERING

TNode<Code> CodeStubAssembler::ResolveCodePointerHandle(
    TNode<IndirectPointerHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::code_pointer_table_address());
  TNode<UintPtrT> offset = ComputeCodePointerTableEntryOffset(handle);
  offset = UintPtrAdd(offset,
                      UintPtrConstant(kCodePointerTableEntryCodeObjectOffset));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  value =
      UncheckedCast<UintPtrT>(WordOr(value, UintPtrConstant(kHeapObjectTag)));
  return CAST(BitcastWordToTagged(value));
}

TNode<TrustedObject> CodeStubAssembler::ResolveTrustedPointerHandle(
    TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag) {
  TNode<RawPtrT> table = ExternalConstant(
      ExternalReference::trusted_pointer_table_base_address(isolate()));
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kTrustedPointerHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kTrustedPointerTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kTrustedPointerTableEntrySizeLog2)));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // Untag the pointer and remove the marking bit in one operation.
  value = UncheckedCast<UintPtrT>(
      WordAnd(value, UintPtrConstant(~(tag | kTrustedPointerTableMarkBit))));
  return CAST(BitcastWordToTagged(value));
}

TNode<UintPtrT> CodeStubAssembler::ComputeJSDispatchTableEntryOffset(
    TNode<JSDispatchHandleT> handle) {
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kJSDispatchHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kJSDispatchTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kJSDispatchTableEntrySizeLog2)));
  return offset;
}

TNode<UintPtrT> CodeStubAssembler::ComputeCodePointerTableEntryOffset(
    TNode<IndirectPointerHandleT> handle) {
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kCodePointerHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kCodePointerTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kCodePointerTableEntrySizeLog2)));
  return offset;
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeEntrypointViaCodePointerField(
    TNode<HeapObject> object, TNode<IntPtrT> field_offset,
    CodeEntrypointTag tag) {
  TNode<IndirectPointerHandleT> handle =
      LoadObjectField<IndirectPointerHandleT>(object, field_offset);
  return LoadCodeEntryFromIndirectPointerHandle(handle, tag);
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeEntryFromIndirectPointerHandle(
    TNode<IndirectPointerHandleT> handle, CodeEntrypointTag tag) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::code_pointer_table_address());
  TNode<UintPtrT> offset = ComputeCodePointerTableEntryOffset(handle);
  TNode<UintPtrT> entry = Load<UintPtrT>(table, offset);
  if (tag != 0) {
    entry = UncheckedCast<UintPtrT>(WordXor(entry, UintPtrConstant(tag)));
  }
  return UncheckedCast<RawPtrT>(UncheckedCast<WordT>(entry));
}

#endif  // V8_ENABLE_SANDBOX

void CodeStubAssembler::SetSupportsDynamicParameterCount(
    TNode<JSFunction> callee, TNode<JSDispatchHandleT> dispatch_handle) {
  TNode<Uint16T> dynamic_parameter_count;
#ifdef V8_ENABLE_LEAPTIERING
  dynamic_parameter_count =
      LoadParameterCountFromJSDispatchTable(dispatch_handle);
#else
  TNode<SharedFunctionInfo> shared = LoadJSFunctionSharedFunctionInfo(callee);
  dynamic_parameter_count =
      LoadSharedFunctionInfoFormalParameterCountWithReceiver(shared);
#endif
  SetDynamicJSParameterCount(dynamic_parameter_count);
}

TNode<JSDispatchHandleT> CodeStubAssembler::InvalidDispatchHandleConstant() {
  return UncheckedCast<JSDispatchHandleT>(
      Uint32Constant(kInvalidDispatchHandle));
}

TNode<Object> CodeStubAssembler::LoadFromParentFrame(int offset) {
  TNode<RawPtrT> frame_pointer = LoadParentFramePointer();
  return LoadFullTagged(frame_pointer, IntPtrConstant(offset));
}

TNode<Uint8T> CodeStubAssembler::LoadUint8Ptr(TNode<RawPtrT> ptr,
                                              TNode<IntPtrT> offset) {
  return Load<Uint8T>(IntPtrAdd(ReinterpretCast<IntPtrT>(ptr), offset));
}

TNode<Uint64T> CodeStubAssembler::LoadUint64Ptr(TNode<RawPtrT> ptr,
                                                TNode<IntPtrT> index) {
  return Load<Uint64T>(
      IntPtrAdd(ReinterpretCast<IntPtrT>(ptr),
                IntPtrMul(index, IntPtrConstant(sizeof(uint64_t)))));
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagPositiveSmiObjectField(
    TNode<HeapObject> object, int offset) {
  TNode<Int32T> value = LoadAndUntagToWord32ObjectField(object, offset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Signed(ChangeUint32ToWord(value));
}

TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32ObjectField(
    TNode<HeapObject> object, int offset) {
  // Please use LoadMap(object) instead.
  DCHECK_NE(offset, HeapObject::kMapOffset);
  if (SmiValuesAre32Bits()) {
#if V8_TARGET_LITTLE_ENDIAN
    offset += 4;
#endif
    return LoadObjectField<Int32T>(object, offset);
  } else {
    return SmiToInt32(LoadObjectField<Smi>(object, offset));
  }
}

TNode<Float64T> CodeStubAssembler::LoadHeapNumberValue(
    TNode<HeapObject> object) {
  CSA_DCHECK(this, Word32Or(IsHeapNumber(object), IsTheHole(object)));
  static_assert(offsetof(HeapNumber, value_) == Hole::kRawNumericValueOffset);
  return LoadObjectField<Float64T>(object, offsetof(HeapNumber, value_));
}

TNode<Map> CodeStubAssembler::GetInstanceTypeMap(InstanceType instance_type) {
  RootIndex map_idx = Map::TryGetMapRootIdxFor(instance_type).value();
  return HeapConstantNoHole(
      i::Cast<Map>(ReadOnlyRoots(isolate()).handle_at(map_idx)));
}

TNode<Map> CodeStubAssembler::LoadMap(TNode<HeapObject> object) {
  TNode<Map> map = LoadObjectField<Map>(object, HeapObject::kMapOffset);
#ifdef V8_MAP_PACKING
  // Check the loaded map is unpacked. i.e. the lowest two bits != 0b10
  CSA_DCHECK(this,
             WordNotEqual(WordAnd(BitcastTaggedToWord(map),
                                  IntPtrConstant(Internals::kMapWordXorMask)),
                          IntPtrConstant(Internals::kMapWordSignature)));
#endif
  return map;
}

TNode<Uint16T> CodeStubAssembler::LoadInstanceType(TNode<HeapObject> object) {
  return LoadMapInstanceType(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::HasInstanceType(TNode<HeapObject> object,
                                                InstanceType instance_type) {
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected_map =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      TNode<Map> map = LoadMap(object);
      return TaggedEqual(map, LoadRoot(*expected_map));
    }
  }
  return InstanceTypeEqual(LoadInstanceType(object), instance_type);
}

TNode<BoolT> CodeStubAssembler::DoesntHaveInstanceType(
    TNode<HeapObject> object, InstanceType instance_type) {
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected_map =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      TNode<Map> map = LoadMap(object);
      return TaggedNotEqual(map, LoadRoot(*expected_map));
    }
  }
  return Word32NotEqual(LoadInstanceType(object), Int32Constant(instance_type));
}

TNode<BoolT> CodeStubAssembler::TaggedDoesntHaveInstanceType(
    TNode<HeapObject> any_tagged, InstanceType type) {
  /* return Phi <TaggedIsSmi(val), DoesntHaveInstanceType(val, type)> */
  TNode<BoolT> tagged_is_smi = TaggedIsSmi(any_tagged);
  return Select<BoolT>(
      tagged_is_smi, [=]() { return tagged_is_smi; },
      [=, this]() { return DoesntHaveInstanceType(any_tagged, type); });
}

TNode<BoolT> CodeStubAssembler::IsSpecialReceiverMap(TNode<Map> map) {
  TNode<BoolT> is_special =
      IsSpecialReceiverInstanceType(LoadMapInstanceType(map));
  uint32_t mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                  Map::Bits1::IsAccessCheckNeededBit::kMask;
  USE(mask);
  // Interceptors or access checks imply special receiver.
  CSA_DCHECK(this,
             SelectConstant<BoolT>(IsSetWord32(LoadMapBitField(map), mask),
                                   is_special, Int32TrueConstant()));
  return is_special;
}

TNode<Word32T> CodeStubAssembler::IsStringWrapperElementsKind(TNode<Map> map) {
  TNode<Int32T> kind = LoadMapElementsKind(map);
  return Word32Or(
      Word32Equal(kind, Int32Constant(FAST_STRING_WRAPPER_ELEMENTS)),
      Word32Equal(kind, Int32Constant(SLOW_STRING_WRAPPER_ELEMENTS)));
}

void CodeStubAssembler::GotoIfMapHasSlowProperties(TNode<Map> map,
                                                   Label* if_slow) {
  GotoIf(IsStringWrapperElementsKind(map), if_slow);
  GotoIf(IsSpecialReceiverMap(map), if_slow);
  GotoIf(IsDictionaryMap(map), if_slow);
}

TNode<HeapObject> CodeStubAssembler::LoadFastProperties(
    TNode<JSReceiver> object, bool skip_empty_check) {
  CSA_SLOW_DCHECK(this, Word32BinaryNot(IsDictionaryMap(LoadMap(object))));
  TNode<Object> properties = LoadJSReceiverPropertiesOrHash(object);
  if (skip_empty_check) {
    return CAST(properties);
  } else {
    // TODO(ishell): use empty_property_array instead of empty_fixed_array here.
    return Select<HeapObject>(
        TaggedIsSmi(properties),
        [=, this] { return EmptyFixedArrayConstant(); },
        [=, this] { return CAST(properties); });
  }
}

TNode<HeapObject> CodeStubAssembler::LoadSlowProperties(
    TNode<JSReceiver> object) {
  CSA_SLOW_DCHECK(this, IsDictionaryMap(LoadMap(object)));
  TNode<Object> properties = LoadJSReceiverPropertiesOrHash(object);
  NodeGenerator<HeapObject> make_empty = [=, this]() -> TNode<HeapObject> {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      return EmptySwissPropertyDictionaryConstant();
    } else {
      return EmptyPropertyDictionaryConstant();
    }
  };
  NodeGenerator<HeapObject> cast_properties = [=, this] {
    TNode<HeapObject> dict = CAST(properties);
    CSA_DCHECK(this,
               Word32Or(IsPropertyDictionary(dict), IsGlobalDictionary(dict)));
    return dict;
  };
  return Select<HeapObject>(TaggedIsSmi(properties), make_empty,
                            cast_properties);
}

TNode<Object> CodeStubAssembler::LoadJSArgumentsObjectLength(
    TNode<Context> context, TNode<JSArgumentsObject> array) {
  CSA_DCHECK(this, IsJSArgumentsObjectWithLength(context, array));
  constexpr int offset = JSStrictArgumentsObject::kLengthOffset;
  static_assert(offset == JSSloppyArgumentsObject::kLengthOffset);
  return LoadObjectField(array, offset);
}

TNode<Smi> CodeStubAssembler::LoadFastJSArrayLength(TNode<JSArray> array) {
  TNode<Number> length = LoadJSArrayLength(array);
  CSA_DCHECK(this, Word32Or(IsFastElementsKind(LoadElementsKind(array)),
                            IsElementsKindInRange(
                                LoadElementsKind(array),
                                FIRST_ANY_NONEXTENSIBLE_ELEMENTS_KIND,
                                LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)));
  // JSArray length is always a positive Smi for fast arrays.
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));
  return CAST(length);
}

TNode<Smi> CodeStubAssembler::LoadFixedArrayBaseLength(
    TNode<FixedArrayBase> array) {
  CSA_SLOW_DCHECK(this, IsNotWeakFixedArraySubclass(array));
  return LoadObjectField<Smi>(array, FixedArrayBase::kLengthOffset);
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagFixedArrayBaseLength(
    TNode<FixedArrayBase> array) {
  return LoadAndUntagPositiveSmiObjectField(array,
                                            FixedArrayBase::kLengthOffset);
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagFixedArrayBaseLengthAsUint32(
    TNode<FixedArrayBase> array) {
  TNode<Int32T> value =
      LoadAndUntagToWord32ObjectField(array, FixedArrayBase::kLengthOffset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Unsigned(value);
}

TNode<IntPtrT> CodeStubAssembler::LoadFeedbackVectorLength(
    TNode<FeedbackVector> vector) {
  TNode<Int32T> length =
      LoadObjectField<Int32T>(vector, FeedbackVector::kLengthOffset);
  return ChangePositiveInt32ToIntPtr(length);
}

TNode<Smi> CodeStubAssembler::LoadWeakFixedArrayLength(
    TNode<WeakFixedArray> array) {
  return LoadObjectField<Smi>(array, offsetof(WeakFixedArray, length_));
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagWeakFixedArrayLength(
    TNode<WeakFixedArray> array) {
  return LoadAndUntagPositiveSmiObjectField(array,
                                            offsetof(WeakFixedArray, length_));
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagWeakFixedArrayLengthAsUint32(
    TNode<WeakFixedArray> array) {
  TNode<Int32T> length =
      LoadAndUntagToWord32ObjectField(array, offsetof(WeakFixedArray, length_));
  CSA_DCHECK(this, Int32GreaterThanOrEqual(length, Int32Constant(0)));
  return Unsigned(length);
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagBytecodeArrayLength(
    TNode<BytecodeArray> array) {
  TNode<Int32T> value =
      LoadAndUntagToWord32ObjectField(array, BytecodeArray::kLengthOffset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Unsigned(value);
}

TNode<Int32T> CodeStubAssembler::LoadNumberOfDescriptors(
    TNode<DescriptorArray> array) {
  return UncheckedCast<Int32T>(LoadObjectField<Int16T>(
      array, DescriptorArray::kNumberOfDescriptorsOffset));
}

TNode<Int32T> CodeStubAssembler::LoadNumberOfOwnDescriptors(TNode<Map> map) {
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  return UncheckedCast<Int32T>(
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3));
}

TNode<Int32T> CodeStubAssembler::LoadMapBitField(TNode<Map> map) {
  return UncheckedCast<Int32T>(
      LoadObjectField<Uint8T>(map, Map::kBitFieldOffset));
}

TNode<Int32T> CodeStubAssembler::LoadMapBitField2(TNode<Map> map) {
  return UncheckedCast<Int32T>(
      LoadObjectField<Uint8T>(map, Map::kBitField2Offset));
}

TNode<Uint32T> CodeStubAssembler::LoadMapBitField3(TNode<Map> map) {
  return LoadObjectField<Uint32T>(map, Map::kBitField3Offset);
}

TNode<Uint16T> CodeStubAssembler::LoadMapInstanceType(TNode<Map> map) {
  return LoadObjectField<Uint16T>(map, Map::kInstanceTypeOffset);
}

TNode<Int32T> CodeStubAssembler::LoadMapElementsKind(TNode<Map> map) {
  TNode<Int32T> bit_field2 = LoadMapBitField2(map);
  return Signed(DecodeWord32<Map::Bits2::ElementsKindBits>(bit_field2));
}

TNode<Int32T> CodeStubAssembler::LoadElementsKind(TNode<HeapObject> object) {
  return LoadMapElementsKind(LoadMap(object));
}

TNode<DescriptorArray> CodeStubAssembler::LoadMapDescriptors(TNode<Map> map) {
  return LoadObjectField<DescriptorArray>(map, Map::kInstanceDescriptorsOffset);
}

TNode<HeapObject> CodeStubAssembler::LoadMapPrototype(TNode<Map> map) {
  return LoadObjectField<HeapObject>(map, Map::kPrototypeOffset);
}

TNode<IntPtrT> CodeStubAssembler::LoadMapInstanceSizeInWords(TNode<Map> map) {
  return ChangeInt32ToIntPtr(
      LoadObjectField<Uint8T>(map, Map::kInstanceSizeInWordsOffset));
}

TNode<IntPtrT> CodeStubAssembler::LoadMapInobjectPropertiesStartInWords(
    TNode<Map> map) {
  // See Map::GetInObjectPropertiesStartInWords() for details.
  CSA_DCHECK(this, IsJSObjectMap(map));
  return ChangeInt32ToIntPtr(LoadObjectField<Uint8T>(
      map, Map::kInobjectPropertiesStartOrConstructorFunctionIndexOffset));
}

TNode<IntPtrT> CodeStubAssembler::MapUsedInstanceSizeInWords(TNode<Map> map) {
  TNode<IntPtrT> used_or_unused =
      ChangeInt32ToIntPtr(LoadMapUsedOrUnusedInstanceSizeInWords(map));

  return Select<IntPtrT>(
      UintPtrGreaterThanOrEqual(used_or_unused,
                                IntPtrConstant(JSObject::kFieldsAdded)),
      [=] { return used_or_unused; },
      [=, this] { return LoadMapInstanceSizeInWords(map); });
}

TNode<IntPtrT> CodeStubAssembler::MapUsedInObjectProperties(TNode<Map> map) {
  return IntPtrSub(MapUsedInstanceSizeInWords(map),
                   LoadMapInobjectPropertiesStartInWords(map));
}

TNode<IntPtrT> CodeStubAssembler::LoadMapConstructorFunctionIndex(
    TNode<Map> map) {
  // See Map::GetConstructorFunctionIndex() for details.
  CSA_DCHECK(this, IsPrimitiveInstanceType(LoadMapInstanceType(map)));
  return ChangeInt32ToIntPtr(LoadObjectField<Uint8T>(
      map, Map::kInobjectPropertiesStartOrConstructorFunctionIndexOffset));
}

TNode<Object> CodeStubAssembler::LoadMapConstructor(TNode<Map> map) {
  TVARIABLE(Object, result,
            LoadObjectField(
                map, Map::kConstructorOrBackPointerOrNativeContextOffset));

  Label done(this), loop(this, &result);
  Goto(&loop);
  BIND(&loop);
  {
    GotoIf(TaggedIsSmi(result.value()), &done);
    TNode<BoolT> is_map_type =
        InstanceTypeEqual(LoadInstanceType(CAST(result.value())), MAP_TYPE);
    GotoIfNot(is_map_type, &done);
    result =
        LoadObjectField(CAST(result.value()),
                        Map::kConstructorOrBackPointerOrNativeContextOffset);
    Goto(&loop);
  }
  BIND(&done);
  return result.value();
}

TNode<Uint32T> CodeStubAssembler::LoadMapEnumLength(TNode<Map> map) {
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  return DecodeWord32<Map::Bits3::EnumLengthBits>(bit_field3);
}

TNode<Object> CodeStubAssembler::LoadMapBackPointer(TNode<Map> map) {
  TNode<HeapObject> object = CAST(LoadObjectField(
      map, Map::kConstructorOrBackPointerOrNativeContextOffset));
  return Select<Object>(
      IsMap(object), [=] { return object; },
      [=, this] { return UndefinedConstant(); });
}

TNode<Uint32T> CodeStubAssembler::EnsureOnlyHasSimpleProperties(
    TNode<Map> map, TNode<Int32T> instance_type, Label* bailout) {
  // This check can have false positives, since it applies to any
  // JSPrimitiveWrapper type.
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), bailout);

  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  GotoIf(IsSetWord32(bit_field3, Map::Bits3::IsDictionaryMapBit::kMask),
         bailout);

  return bit_field3;
}

TNode<Uint32T> CodeStubAssembler::LoadJSReceiverIdentityHash(
    TNode<JSReceiver> receiver, Label* if_no_hash) {
  TVARIABLE(Uint32T, var_hash);
  Label done(this), if_smi(this), if_property_array(this),
      if_swiss_property_dictionary(this), if_property_dictionary(this),
      if_fixed_array(this);

  TNode<Object> properties_or_hash =
      LoadObjectField(receiver, JSReceiver::kPropertiesOrHashOffset);
  GotoIf(TaggedIsSmi(properties_or_hash), &if_smi);

  TNode<HeapObject> properties = CAST(properties_or_hash);
  TNode<Uint16T> properties_instance_type = LoadInstanceType(properties);

  GotoIf(InstanceTypeEqual(properties_instance_type, PROPERTY_ARRAY_TYPE),
         &if_property_array);
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    GotoIf(
        InstanceTypeEqual(properties_instance_type, SWISS_NAME_DICTIONARY_TYPE),
        &if_swiss_property_dictionary);
  }
  Branch(InstanceTypeEqual(properties_instance_type, NAME_DICTIONARY_TYPE),
         &if_property_dictionary, &if_fixed_array);

  BIND(&if_fixed_array);
  {
    var_hash = Uint32Constant(PropertyArray::kNoHashSentinel);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    var_hash = PositiveSmiToUint32(CAST(properties_or_hash));
    Goto(&done);
  }

  BIND(&if_property_array);
  {
    TNode<Int32T> length_and_hash = LoadAndUntagToWord32ObjectField(
        properties, PropertyArray::kLengthAndHashOffset);
    var_hash = DecodeWord32<PropertyArray::HashField>(length_and_hash);
    Goto(&done);
  }
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    BIND(&if_swiss_property_dictionary);
    {
      var_hash = LoadSwissNameDictionaryHash(CAST(properties));
      CSA_DCHECK(this, Uint32LessThanOrEqual(var_hash.value(),
                                             Uint32Constant(Smi::kMaxValue)));
      Goto(&done);
    }
  }

  BIND(&if_property_dictionary);
  {
    var_hash = PositiveSmiToUint32(CAST(LoadFixedArrayElement(
        CAST(properties), NameDictionary::kObjectHashIndex)));
    Goto(&done);
  }

  BIND(&done);
  if (if_no_hash != nullptr) {
    GotoIf(Word32Equal(var_hash.value(),
                       Uint32Constant(PropertyArray::kNoHashSentinel)),
           if_no_hash);
  }
  return var_hash.value();
}

TNode<Uint32T> CodeStubAssembler::LoadNameHashAssumeComputed(TNode<Name> name) {
  TNode<Uint32T> hash_field = LoadNameRawHash(name);
  CSA_DCHECK(this, IsClearWord32(hash_field, Name::kHashNotComputedMask));
  return DecodeWord32<Name::HashBits>(hash_field);
}

TNode<Uint32T> CodeStubAssembler::LoadNameHash(TNode<Name> name,
                                               Label* if_hash_not_computed) {
  TNode<Uint32T> raw_hash_field = LoadNameRawHashField(name);
  if (if_hash_not_computed != nullptr) {
    GotoIf(IsSetWord32(raw_hash_field, Name::kHashNotComputedMask),
           if_hash_not_computed);
  }
  return DecodeWord32<Name::HashBits>(raw_hash_field);
}

TNode<Uint32T> CodeStubAssembler::LoadNameRawHash(TNode<Name> name) {
  TVARIABLE(Uint32T, var_raw_hash);

  Label if_forwarding_index(this, Label::kDeferred), done(this);

  TNode<Uint32T> raw_hash_field = LoadNameRawHashField(name);
  GotoIf(IsSetWord32(raw_hash_field, Name::kHashNotComputedMask),
         &if_forwarding_index);

  var_raw_hash = raw_hash_field;
  Goto(&done);

  BIND(&if_forwarding_index);
  {
    CSA_DCHECK(this,
               IsEqualInWord32<Name::HashFieldTypeBits>(
                   raw_hash_field, Name::HashFieldType::kForwardingIndex));
    TNode<ExternalReference> function =
        ExternalConstant(ExternalReference::raw_hash_from_forward_table());
    const TNode<ExternalReference> isolate_ptr =
        ExternalConstant(ExternalReference::isolate_address());
    TNode<Uint32T> result = UncheckedCast<Uint32T>(CallCFunction(
        function, MachineType::Uint32(),
        std::make_pair(MachineType::Pointer(), isolate_ptr),
        std::make_pair(
            MachineType::Int32(),
            DecodeWord32<Name::ForwardingIndexValueBits>(raw_hash_field))));

    var_raw_hash = result;
    Goto(&done);
  }

  BIND(&done);
  return var_raw_hash.value();
}

TNode<Smi> CodeStubAssembler::LoadStringLengthAsSmi(TNode<String> string) {
  return SmiFromIntPtr(LoadStringLengthAsWord(string));
}

TNode<IntPtrT> CodeStubAssembler::LoadStringLengthAsWord(TNode<String> string) {
  return Signed(ChangeUint32ToWord(LoadStringLengthAsWord32(string)));
}

TNode<Uint32T> CodeStubAssembler::LoadStringLengthAsWord32(
    TNode<String> string) {
  return LoadObjectField<Uint32T>(string, offsetof(String, length_));
}

TNode<Object> CodeStubAssembler::LoadJSPrimitiveWrapperValue(
    TNode<JSPrimitiveWrapper> object) {
  return LoadObjectField(object, JSPrimitiveWrapper::kValueOffset);
}

void CodeStubAssembler::DispatchMaybeObject(TNode<MaybeObject> maybe_object,
                                            Label* if_smi, Label* if_cleared,
                                            Label* if_weak, Label* if_strong,
                                            TVariable<Object>* extracted) {
  Label inner_if_smi(this), inner_if_strong(this);

  GotoIf(TaggedIsSmi(maybe_object), &inner_if_smi);

  GotoIf(IsCleared(maybe_object), if_cleared);

  TNode<HeapObjectReference> object_ref = CAST(maybe_object);

  GotoIf(IsStrong(object_ref), &inner_if_strong);

  *extracted = GetHeapObjectAssumeWeak(maybe_object);
  Goto(if_weak);

  BIND(&inner_if_smi);
  *extracted = CAST(maybe_object);
  Goto(if_smi);

  BIND(&inner_if_strong);
  *extracted = CAST(maybe_object);
  Goto(if_strong);
}

void CodeStubAssembler::DcheckHasValidMap(TNode<HeapObject> object) {
#ifdef V8_MAP_PACKING
  // Test if the map is an unpacked and valid map
  CSA_DCHECK(this, IsMap(LoadMap(object)));
#endif
}

TNode<BoolT> CodeStubAssembler::IsStrong(TNode<MaybeObject> value) {
  return Word32Equal(Word32And(TruncateIntPtrToInt32(
                                   BitcastTaggedToWordForTagAndSmiBits(value)),
                               Int32Constant(kHeapObjectTagMask)),
                     Int32Constant(kHeapObjectTag));
}

TNode<BoolT> CodeStubAssembler::IsStrong(TNode<HeapObjectReference> value) {
  return IsNotSetWord32(
      TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
      kHeapObjectReferenceTagMask);
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectIfStrong(
    TNode<MaybeObjec
"""


```