Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick scan for recognizable patterns and keywords. I see things like:

* `CodeStubAssembler`: This immediately tells me it's low-level code generation, likely interacting directly with the V8 engine's internals.
* `TNode<...>`: These are Torque nodes, confirming the guess that this is related to V8's code generation pipeline.
* `ByteArray`, `SwissNameDictionary`, `Object`, `Map`, `Context`: These are V8's internal data structures, hinting at the code's purpose.
* `Load...`, `Store...`, `Allocate...`:  These are common operations for manipulating memory and objects.
* `GotoIf`, `Label`, `Bind`: These are control flow constructs within the assembler.
* `Runtime::k...`: Calls to V8's runtime functions, usually for operations that can't be efficiently done in the code stub.
* `MetaTable`, `CtrlTable`, `DataTable`, `PropertyDetails`:  These specific table names within `SwissNameDictionary` are key to understanding its internal organization.
* `memcpy`: A standard C library function for memory copying, indicating potential optimization or bulk data handling.
* `SIMD`:  Mentions of Single Instruction Multiple Data, suggesting possible performance optimizations.

**2. Identifying the Core Data Structure:**

The recurring mention of `SwissNameDictionary` and its associated functions (`LoadSwissNameDictionary...`, `StoreSwissNameDictionary...`, `AllocateSwissNameDictionary...`) strongly suggests that this code snippet is primarily concerned with the implementation and manipulation of this data structure.

**3. Understanding `SwissNameDictionary`'s Purpose (Inferring from the Code):**

Based on the operations performed, I can start to infer what a `SwissNameDictionary` is for:

* **Key-Value Pairs:** The presence of `LoadSwissNameDictionaryKey`, `StoreSwissNameDictionaryKeyAndValue` clearly points to it being a dictionary-like structure.
* **Hashing:**  `LoadSwissNameDictionaryHash` suggests it uses hashing for efficient lookups.
* **Capacity:**  Functions dealing with capacity (`AllocateSwissNameDictionaryWithCapacity`, `LoadSwissNameDictionaryCapacity`) indicate it's a resizable data structure.
* **Meta-information:** The `MetaTable` seems to store counts of elements and deleted elements.
* **Control and Data:** Separate `CtrlTable` and `DataTable` suggest a specific internal organization, likely for performance reasons (e.g., separating control information for faster lookups).
* **Property Details:** `PropertyDetails` suggests it's used to store additional information associated with the key-value pairs, likely related to object properties in JavaScript.

**4. Deconstructing Key Functionalities:**

Now, I examine the main functions and code blocks to understand their specific roles:

* **Allocation (`AllocateSwissNameDictionary`, `AllocateSwissNameDictionaryWithCapacity`):** This involves calculating the necessary memory, allocating it, and initializing the different internal tables (meta, control, data). The checks for `MaxCapacity` and potential out-of-memory errors are important.
* **Copying (`CopySwissNameDictionary`):**  This demonstrates how to create a duplicate of an existing dictionary, using `memcpy` for efficiency.
* **Accessing Elements (`LoadSwissNameDictionaryKey`, `StoreSwissNameDictionaryKeyAndValue`):**  These functions calculate offsets into the `DataTable` based on the entry index.
* **Managing Counts (`LoadSwissNameDictionaryNumberOfElements`, `LoadSwissNameDictionaryNumberOfDeletedElements`, `SwissNameDictionaryIncreaseElementCountOrBailout`, `SwissNameDictionaryUpdateCountsForDeletion`):** These operations manipulate the meta-information about the dictionary's state.
* **Finding Entries (`SwissNameDictionaryFindEntry`, `SwissNameDictionaryFindEntryPortable`, `SwissNameDictionaryFindEntrySIMD`):** This highlights the core lookup mechanism, with potentially optimized SIMD versions.
* **Adding Elements (`SwissNameDictionaryAdd`, `SwissNameDictionaryAddPortable`, `SwissNameDictionaryAddSIMD`):**  This function is responsible for inserting new key-value pairs, with checks for resizing.
* **Meta Table Access (`MetaTableAccessor`, `GenerateMetaTableAccess`):**  This complex part provides an abstraction layer for reading and writing to the `MetaTable`, handling different entry sizes efficiently.

**5. Connecting to JavaScript (Hypothesizing):**

Knowing that `SwissNameDictionary` is about storing key-value pairs, I consider where such a structure might be used in JavaScript. The most obvious connection is to **object properties**. JavaScript objects are essentially dictionaries mapping property names (strings or Symbols) to values. Therefore, `SwissNameDictionary` is likely a part of V8's internal representation of JavaScript objects, particularly for objects with a large number of properties.

**6. Identifying Potential Issues and Errors:**

Based on the code, I can anticipate some potential problems:

* **Out-of-Memory:** The allocation code explicitly checks for exceeding maximum capacity and handles out-of-memory situations.
* **Incorrect Capacity Calculations:**  Errors in calculating the sizes of the internal tables could lead to crashes or memory corruption.
* **Race Conditions (If Concurrent Access):** Although not explicitly shown in the snippet, dictionary implementations often need careful synchronization if accessed concurrently.
* **Hash Collisions (Implicit):** While not directly in this code, the efficiency of a dictionary relies on a good hashing function to minimize collisions. Poor hashing could lead to performance degradation.

**7. Summarization and Structure:**

Finally, I organize my findings into a clear and structured summary, addressing the specific questions asked in the prompt:

* **Functionality:**  Describe the main purpose of the code, focusing on `SwissNameDictionary`.
* **Torque:** Confirm that `.cc` means it's not Torque.
* **JavaScript Relation:** Explain the connection to JavaScript objects and property storage. Provide a simple example.
* **Logic Inference:** Create a plausible scenario with input and expected output for a function like `LoadSwissNameDictionaryNumberOfElements`.
* **Common Errors:** Give concrete examples of programming mistakes related to dictionary usage.
* **Overall Function (Part 22/23):**  Emphasize that this part focuses on the implementation details of a specific data structure used by V8.

This iterative process of scanning, identifying, inferring, deconstructing, connecting, and summarizing allows for a comprehensive understanding of the provided code snippet, even without prior deep knowledge of V8's internals.
这是一个V8源代码文件，实现了`CodeStubAssembler` 类的一些功能，特别是关于 `SwissNameDictionary` 的操作。

**主要功能归纳:**

这段代码的主要功能是提供了在V8的CodeStubAssembler框架下操作 `SwissNameDictionary` (瑞士名称字典) 的底层方法。`SwissNameDictionary` 是V8中用于高效存储和查找对象属性的一种哈希表实现。

具体来说，这段代码实现了以下功能：

1. **检查属性是否被修改 (`CheckPrototypeChanges`):**  这个函数用于检查对象的原型链上的属性是否在期望值之后被修改过。这在某些优化场景中用于验证假设。

2. **抽象的元数据表访问 (`MetaTableAccessor`, `GenerateMetaTableAccess`):**  为了处理 `SwissNameDictionary` 中元数据表的不同条目大小，定义了一个 `MetaTableAccessor` 类来提供加载和存储的抽象接口。`GenerateMetaTableAccess` 函数根据字典的容量选择合适的元数据表条目大小，并执行提供的操作。

3. **加载和存储 `SwissNameDictionary` 的元数据:**
   - `LoadSwissNameDictionaryNumberOfElements`: 加载字典中元素的数量。
   - `LoadSwissNameDictionaryNumberOfDeletedElements`: 加载字典中已删除元素的数量。
   - `StoreSwissNameDictionaryEnumToEntryMapping`: 存储枚举索引到字典条目的映射。
   - `SwissNameDictionaryIncreaseElementCountOrBailout`: 增加元素计数，如果超过容量则跳出。
   - `SwissNameDictionaryUpdateCountsForDeletion`: 更新删除元素后的元素和已删除元素计数。

4. **分配 `SwissNameDictionary` (`AllocateSwissNameDictionary`, `AllocateSwissNameDictionaryWithCapacity`):**
   - 提供了分配新的 `SwissNameDictionary` 对象的函数，可以指定初始容量。
   - 详细地初始化了字典的各个部分，包括元数据表、控制表（`CtrlTable`）和数据表（`DataTable`）。

5. **复制 `SwissNameDictionary` (`CopySwissNameDictionary`):**
   - 实现了将一个 `SwissNameDictionary` 对象复制到另一个新分配的对象的函数。
   - 使用 `memcpy` 等底层操作来高效地复制数据。

6. **计算 `SwissNameDictionary` 内部不同表的偏移量:**
   - `SwissNameDictionaryOffsetIntoDataTableMT`: 计算数据表中指定索引的偏移量。
   - `SwissNameDictionaryOffsetIntoPropertyDetailsTableMT`: 计算属性详情表中指定索引的偏移量。

7. **存储 `SwissNameDictionary` 的容量 (`StoreSwissNameDictionaryCapacity`):**  存储字典的容量值。

8. **加载 `SwissNameDictionary` 的键和属性详情:**
   - `LoadSwissNameDictionaryKey`: 加载指定条目的键。
   - `LoadSwissNameDictionaryPropertyDetails`: 加载指定条目的属性详情。

9. **存储 `SwissNameDictionary` 的属性详情:**
   - `StoreSwissNameDictionaryPropertyDetails`: 存储指定条目的属性详情。

10. **存储 `SwissNameDictionary` 的键和值 (`StoreSwissNameDictionaryKeyAndValue`):**  存储指定条目的键和值。

11. **加载 `SwissNameDictionary` 的控制表组 (`LoadSwissNameDictionaryCtrlTableGroup`):**  加载控制表中的一组数据，用于快速查找。

12. **设置 `SwissNameDictionary` 的控制信息 (`SwissNameDictionarySetCtrl`):**  设置控制表中指定条目的控制字节。

13. **查找 `SwissNameDictionary` 中的条目 (`SwissNameDictionaryFindEntry`, `SwissNameDictionaryFindEntryPortable`, `SwissNameDictionaryFindEntrySIMD`):**  提供了查找键在字典中位置的函数，包括基于SIMD优化的版本。

14. **向 `SwissNameDictionary` 添加条目 (`SwissNameDictionaryAdd`, `SwissNameDictionaryAddPortable`, `SwissNameDictionaryAddSIMD`):**  提供了向字典中添加键值对的函数，包括基于SIMD优化的版本。

15. **共享值屏障 (`SharedValueBarrier`):**  确保值可以在不同的Isolate之间共享。这涉及到检查值的类型和所在内存区域。

16. **分配 `ArrayList` (`AllocateArrayList`):**  提供了一个分配 `ArrayList` 对象的函数。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 用于定义运行时内置函数和一些底层操作的领域特定语言。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 的关系及示例:**

`SwissNameDictionary` 是 V8 引擎内部用于实现 JavaScript 对象的属性存储的机制之一。当你创建一个 JavaScript 对象并添加属性时，V8 可能会使用 `SwissNameDictionary` 来存储这些属性。

**JavaScript 示例:**

```javascript
const obj = {};
obj.a = 1;
obj.b = 'hello';
obj.c = true;
```

在 V8 内部，`obj` 的属性 `a`, `b`, `c` 可能会存储在一个 `SwissNameDictionary` 中。`SwissNameDictionary` 提供了高效的查找，使得访问 `obj.a` 等操作能够快速完成。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个已分配的 `SwissNameDictionary` `table`，并且我们想加载它的元素数量。

**假设输入:**
- `table`: 一个指向 `SwissNameDictionary` 对象的指针。
- `capacity`: `table` 的容量。

**代码逻辑:**
`LoadSwissNameDictionaryNumberOfElements(table, capacity)` 函数会：
1. 加载 `table` 的元数据表 (`meta_table`)。
2. 根据 `capacity` 的大小，确定元数据表中元素计数器的大小（可能是 1, 2 或 4 字节）。
3. 从 `meta_table` 中读取元素计数器的值。

**假设输出:**
假设 `table` 当前存储了 5 个元素，那么该函数将返回表示 5 的 `IntPtrT`。

**用户常见的编程错误:**

虽然这段代码是 V8 引擎内部的实现，但与它相关的用户编程错误可能发生在与对象属性操作相关的场景中：

1. **过度添加属性到对象:**  虽然 `SwissNameDictionary` 可以动态调整大小，但过度添加大量属性可能会导致性能下降，因为 V8 需要进行哈希表扩容等操作。

   ```javascript
   const massiveObject = {};
   for (let i = 0; i < 100000; i++) {
     massiveObject[`property_${i}`] = i;
   }
   ```

2. **频繁删除和添加属性:** 频繁地删除和添加对象的属性可能会导致 `SwissNameDictionary` 的内部结构频繁变化，可能影响性能。

   ```javascript
   const obj = { a: 1 };
   for (let i = 0; i < 1000; i++) {
     delete obj.a;
     obj.a = i;
   }
   ```

3. **依赖属性的特定顺序:**  JavaScript 对象在 ES6 规范中保留了属性插入的顺序，但在某些早期的 V8 实现中或在某些优化场景下，属性的顺序可能不完全保证。依赖属性的特定顺序进行编程可能导致不可靠的行为。

**第22部分的功能归纳:**

作为第22部分，这段代码主要关注 **`SwissNameDictionary` 数据结构的实现细节和操作方法**。它提供了在 V8 的代码生成阶段操作这种关键数据结构的底层工具。这部分代码是 V8 引擎高效管理对象属性的基础，为 JavaScript 对象的快速属性访问提供了支撑。它涉及到内存管理、哈希表操作、性能优化（如 SIMD）等多个方面。理解这部分代码有助于深入了解 V8 引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第22部分，共23部分，请归纳一下它的功能

"""
riptorArrayGetDetails(descriptors, Uint32Constant(descriptor));
      TVARIABLE(Uint32T, var_details, details);
      TVARIABLE(Object, var_value);

      const int key_index = DescriptorArray::ToKeyIndex(descriptor);
      LoadPropertyFromFastObject(prototype, prototype_map, descriptors,
                                 IntPtrConstant(key_index), &var_details,
                                 &var_value);

      TNode<Object> actual_value = var_value.value();
      TNode<Object> expected_value =
          LoadContextElement(native_context_, p.expected_value_context_index);
      GotoIfNot(TaggedEqual(actual_value, expected_value), if_modified);
    }

    Goto(if_unmodified);
  }
}

//
// Begin of SwissNameDictionary macros
//

namespace {

// Provides load and store functions that abstract over the details of accessing
// the meta table in memory. Instead they allow using logical indices that are
// independent from the underlying entry size in the meta table of a
// SwissNameDictionary.
class MetaTableAccessor {
 public:
  MetaTableAccessor(CodeStubAssembler& csa, MachineType mt)
      : csa{csa}, mt{mt} {}

  TNode<Uint32T> Load(TNode<ByteArray> meta_table, TNode<IntPtrT> index) {
    TNode<IntPtrT> offset = OverallOffset(meta_table, index);

    return csa.UncheckedCast<Uint32T>(
        csa.LoadFromObject(mt, meta_table, offset));
  }

  TNode<Uint32T> Load(TNode<ByteArray> meta_table, int index) {
    return Load(meta_table, csa.IntPtrConstant(index));
  }

  void Store(TNode<ByteArray> meta_table, TNode<IntPtrT> index,
             TNode<Uint32T> data) {
    TNode<IntPtrT> offset = OverallOffset(meta_table, index);

#ifdef DEBUG
    int bits = mt.MemSize() * 8;
    TNode<UintPtrT> max_value = csa.UintPtrConstant((1ULL << bits) - 1);

    CSA_DCHECK(&csa, csa.UintPtrLessThanOrEqual(csa.ChangeUint32ToWord(data),
                                                max_value));
#endif

    csa.StoreToObject(mt.representation(), meta_table, offset, data,
                      StoreToObjectWriteBarrier::kNone);
  }

  void Store(TNode<ByteArray> meta_table, int index, TNode<Uint32T> data) {
    Store(meta_table, csa.IntPtrConstant(index), data);
  }

 private:
  TNode<IntPtrT> OverallOffset(TNode<ByteArray> meta_table,
                               TNode<IntPtrT> index) {
    // TODO(v8:11330): consider using ElementOffsetFromIndex().

    int offset_to_data_minus_tag =
        OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag;

    TNode<IntPtrT> overall_offset;
    int size = mt.MemSize();
    intptr_t constant;
    if (csa.TryToIntPtrConstant(index, &constant)) {
      intptr_t index_offset = constant * size;
      overall_offset =
          csa.IntPtrConstant(offset_to_data_minus_tag + index_offset);
    } else {
      TNode<IntPtrT> index_offset =
          csa.IntPtrMul(index, csa.IntPtrConstant(size));
      overall_offset = csa.IntPtrAdd(
          csa.IntPtrConstant(offset_to_data_minus_tag), index_offset);
    }

#ifdef DEBUG
    TNode<IntPtrT> byte_array_data_bytes =
        csa.SmiToIntPtr(csa.LoadFixedArrayBaseLength(meta_table));
    TNode<IntPtrT> max_allowed_offset = csa.IntPtrAdd(
        byte_array_data_bytes, csa.IntPtrConstant(offset_to_data_minus_tag));
    CSA_DCHECK(&csa, csa.UintPtrLessThan(overall_offset, max_allowed_offset));
#endif

    return overall_offset;
  }

  CodeStubAssembler& csa;
  MachineType mt;
};

// Type of functions that given a MetaTableAccessor, use its load and store
// functions to generate code for operating on the meta table.
using MetaTableAccessFunction = std::function<void(MetaTableAccessor&)>;

// Helper function for macros operating on the meta table of a
// SwissNameDictionary. Given a MetaTableAccessFunction, generates branching
// code and uses the builder to generate code for each of the three possible
// sizes per entry a meta table can have.
void GenerateMetaTableAccess(CodeStubAssembler* csa, TNode<IntPtrT> capacity,
                             MetaTableAccessFunction builder) {
  MetaTableAccessor mta8 = MetaTableAccessor(*csa, MachineType::Uint8());
  MetaTableAccessor mta16 = MetaTableAccessor(*csa, MachineType::Uint16());
  MetaTableAccessor mta32 = MetaTableAccessor(*csa, MachineType::Uint32());

  using Label = compiler::CodeAssemblerLabel;
  Label small(csa), medium(csa), done(csa);

  csa->GotoIf(
      csa->IntPtrLessThanOrEqual(
          capacity,
          csa->IntPtrConstant(SwissNameDictionary::kMax1ByteMetaTableCapacity)),
      &small);
  csa->GotoIf(
      csa->IntPtrLessThanOrEqual(
          capacity,
          csa->IntPtrConstant(SwissNameDictionary::kMax2ByteMetaTableCapacity)),
      &medium);

  builder(mta32);
  csa->Goto(&done);

  csa->Bind(&medium);
  builder(mta16);
  csa->Goto(&done);

  csa->Bind(&small);
  builder(mta8);
  csa->Goto(&done);
  csa->Bind(&done);
}

}  // namespace

TNode<IntPtrT> CodeStubAssembler::LoadSwissNameDictionaryNumberOfElements(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);

  TVARIABLE(Uint32T, nof, Uint32Constant(0));
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    nof = mta.Load(meta_table,
                   SwissNameDictionary::kMetaTableElementCountFieldIndex);
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return ChangeInt32ToIntPtr(nof.value());
}

TNode<IntPtrT>
CodeStubAssembler::LoadSwissNameDictionaryNumberOfDeletedElements(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);

  TVARIABLE(Uint32T, nod, Uint32Constant(0));
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return ChangeInt32ToIntPtr(nod.value());
}

void CodeStubAssembler::StoreSwissNameDictionaryEnumToEntryMapping(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> enum_index, TNode<Int32T> entry) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);
  TNode<IntPtrT> meta_table_index = IntPtrAdd(
      IntPtrConstant(SwissNameDictionary::kMetaTableEnumerationDataStartIndex),
      enum_index);

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    mta.Store(meta_table, meta_table_index, Unsigned(entry));
  };

  GenerateMetaTableAccess(this, capacity, builder);
}

TNode<Uint32T>
CodeStubAssembler::SwissNameDictionaryIncreaseElementCountOrBailout(
    TNode<ByteArray> meta_table, TNode<IntPtrT> capacity,
    TNode<Uint32T> max_usable_capacity, Label* bailout) {
  TVARIABLE(Uint32T, used_var, Uint32Constant(0));

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    TNode<Uint32T> nof = mta.Load(
        meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex);
    TNode<Uint32T> nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);
    TNode<Uint32T> used = Uint32Add(nof, nod);
    GotoIf(Uint32GreaterThanOrEqual(used, max_usable_capacity), bailout);
    TNode<Uint32T> inc_nof = Uint32Add(nof, Uint32Constant(1));
    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              inc_nof);
    used_var = used;
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return used_var.value();
}

TNode<Uint32T> CodeStubAssembler::SwissNameDictionaryUpdateCountsForDeletion(
    TNode<ByteArray> meta_table, TNode<IntPtrT> capacity) {
  TVARIABLE(Uint32T, new_nof_var, Uint32Constant(0));

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    TNode<Uint32T> nof = mta.Load(
        meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex);
    TNode<Uint32T> nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);

    TNode<Uint32T> new_nof = Uint32Sub(nof, Uint32Constant(1));
    TNode<Uint32T> new_nod = Uint32Add(nod, Uint32Constant(1));

    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              new_nof);
    mta.Store(meta_table,
              SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex,
              new_nod);

    new_nof_var = new_nof;
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return new_nof_var.value();
}

TNode<SwissNameDictionary> CodeStubAssembler::AllocateSwissNameDictionary(
    TNode<IntPtrT> at_least_space_for) {
  // Note that as AllocateNameDictionary, we return a table with initial
  // (non-zero) capacity even if |at_least_space_for| is 0.

  TNode<IntPtrT> capacity =
      IntPtrMax(IntPtrConstant(SwissNameDictionary::kInitialCapacity),
                SwissNameDictionaryCapacityFor(at_least_space_for));

  return AllocateSwissNameDictionaryWithCapacity(capacity);
}

TNode<SwissNameDictionary> CodeStubAssembler::AllocateSwissNameDictionary(
    int at_least_space_for) {
  return AllocateSwissNameDictionary(IntPtrConstant(at_least_space_for));
}

TNode<SwissNameDictionary>
CodeStubAssembler::AllocateSwissNameDictionaryWithCapacity(
    TNode<IntPtrT> capacity) {
  Comment("[ AllocateSwissNameDictionaryWithCapacity");
  CSA_DCHECK(this, WordIsPowerOfTwo(capacity));
  CSA_DCHECK(this, UintPtrGreaterThanOrEqual(
                       capacity,
                       IntPtrConstant(SwissNameDictionary::kInitialCapacity)));
  CSA_DCHECK(this,
             UintPtrLessThanOrEqual(
                 capacity, IntPtrConstant(SwissNameDictionary::MaxCapacity())));

  Comment("Size check.");
  intptr_t capacity_constant;
  if (ToParameterConstant(capacity, &capacity_constant)) {
    CHECK_LE(capacity_constant, SwissNameDictionary::MaxCapacity());
  } else {
    Label if_out_of_memory(this, Label::kDeferred), next(this);
    Branch(UintPtrGreaterThan(
               capacity, IntPtrConstant(SwissNameDictionary::MaxCapacity())),
           &if_out_of_memory, &next);

    BIND(&if_out_of_memory);
    CallRuntime(Runtime::kFatalProcessOutOfMemoryInAllocateRaw,
                NoContextConstant());
    Unreachable();

    BIND(&next);
  }

  // TODO(v8:11330) Consider adding dedicated handling for constant capacties,
  // similar to AllocateOrderedHashTableWithCapacity.

  // We must allocate the ByteArray first. Otherwise, allocating the ByteArray
  // may trigger GC, which may try to verify the un-initialized
  // SwissNameDictionary.
  Comment("Meta table allocation.");
  TNode<IntPtrT> meta_table_payload_size =
      SwissNameDictionaryMetaTableSizeFor(capacity);

  TNode<ByteArray> meta_table =
      AllocateNonEmptyByteArray(Unsigned(meta_table_payload_size));

  Comment("SwissNameDictionary allocation.");
  TNode<IntPtrT> total_size = SwissNameDictionarySizeFor(capacity);

  TNode<SwissNameDictionary> table =
      UncheckedCast<SwissNameDictionary>(Allocate(total_size));

  StoreMapNoWriteBarrier(table, RootIndex::kSwissNameDictionaryMap);

  Comment(
      "Initialize the hash, capacity, meta table pointer, and number of "
      "(deleted) elements.");

  StoreSwissNameDictionaryHash(table,
                               Uint32Constant(PropertyArray::kNoHashSentinel));
  StoreSwissNameDictionaryCapacity(table, TruncateIntPtrToInt32(capacity));
  StoreSwissNameDictionaryMetaTable(table, meta_table);

  // Set present and deleted element count without doing branching needed for
  // meta table access twice.
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              Uint32Constant(0));
    mta.Store(meta_table,
              SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex,
              Uint32Constant(0));
  };
  GenerateMetaTableAccess(this, capacity, builder);

  Comment("Initialize the ctrl table.");

  TNode<IntPtrT> ctrl_table_start_offset_minus_tag =
      SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  TNode<IntPtrT> table_address_with_tag = BitcastTaggedToWord(table);
  TNode<IntPtrT> ctrl_table_size_bytes =
      IntPtrAdd(capacity, IntPtrConstant(SwissNameDictionary::kGroupWidth));
  TNode<IntPtrT> ctrl_table_start_ptr =
      IntPtrAdd(table_address_with_tag, ctrl_table_start_offset_minus_tag);
  TNode<IntPtrT> ctrl_table_end_ptr =
      IntPtrAdd(ctrl_table_start_ptr, ctrl_table_size_bytes);

  // |ctrl_table_size_bytes| (= capacity + kGroupWidth) is divisble by four:
  static_assert(SwissNameDictionary::kGroupWidth % 4 == 0);
  static_assert(SwissNameDictionary::kInitialCapacity % 4 == 0);

  // TODO(v8:11330) For all capacities except 4, we know that
  // |ctrl_table_size_bytes| is divisible by 8. Consider initializing the ctrl
  // table with WordTs in those cases. Alternatively, always initialize as many
  // bytes as possbible with WordT and then, if necessary, the remaining 4 bytes
  // with Word32T.

  constexpr uint8_t kEmpty = swiss_table::Ctrl::kEmpty;
  constexpr uint32_t kEmpty32 =
      (kEmpty << 24) | (kEmpty << 16) | (kEmpty << 8) | kEmpty;
  TNode<Int32T> empty32 = Int32Constant(kEmpty32);
  BuildFastLoop<IntPtrT>(
      ctrl_table_start_ptr, ctrl_table_end_ptr,
      [=, this](TNode<IntPtrT> current) {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kWord32, current,
                                  empty32);
      },
      sizeof(uint32_t), LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);

  Comment("Initialize the data table.");

  TNode<IntPtrT> data_table_start_offset_minus_tag =
      SwissNameDictionaryDataTableStartOffsetMT();
  TNode<IntPtrT> data_table_ptr =
      IntPtrAdd(table_address_with_tag, data_table_start_offset_minus_tag);
  TNode<IntPtrT> data_table_size = IntPtrMul(
      IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize),
      capacity);

  StoreFieldsNoWriteBarrier(data_table_ptr,
                            IntPtrAdd(data_table_ptr, data_table_size),
                            TheHoleConstant());

  Comment("AllocateSwissNameDictionaryWithCapacity ]");

  return table;
}

TNode<SwissNameDictionary> CodeStubAssembler::CopySwissNameDictionary(
    TNode<SwissNameDictionary> original) {
  Comment("[ CopySwissNameDictionary");

  TNode<IntPtrT> capacity =
      Signed(ChangeUint32ToWord(LoadSwissNameDictionaryCapacity(original)));

  // We must allocate the ByteArray first. Otherwise, allocating the ByteArray
  // may trigger GC, which may try to verify the un-initialized
  // SwissNameDictionary.
  Comment("Meta table allocation.");
  TNode<IntPtrT> meta_table_payload_size =
      SwissNameDictionaryMetaTableSizeFor(capacity);

  TNode<ByteArray> meta_table =
      AllocateNonEmptyByteArray(Unsigned(meta_table_payload_size));

  Comment("SwissNameDictionary allocation.");
  TNode<IntPtrT> total_size = SwissNameDictionarySizeFor(capacity);

  TNode<SwissNameDictionary> table =
      UncheckedCast<SwissNameDictionary>(Allocate(total_size));

  StoreMapNoWriteBarrier(table, RootIndex::kSwissNameDictionaryMap);

  Comment("Copy the hash and capacity.");

  StoreSwissNameDictionaryHash(table, LoadSwissNameDictionaryHash(original));
  StoreSwissNameDictionaryCapacity(table, TruncateIntPtrToInt32(capacity));
  StoreSwissNameDictionaryMetaTable(table, meta_table);
  // Not setting up number of (deleted elements), copying whole meta table
  // instead.

  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());

  TNode<IntPtrT> old_table_address_with_tag = BitcastTaggedToWord(original);
  TNode<IntPtrT> new_table_address_with_tag = BitcastTaggedToWord(table);

  TNode<IntPtrT> ctrl_table_start_offset_minus_tag =
      SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  TNode<IntPtrT> ctrl_table_size_bytes =
      IntPtrAdd(capacity, IntPtrConstant(SwissNameDictionary::kGroupWidth));

  Comment("Copy the ctrl table.");
  {
    TNode<IntPtrT> old_ctrl_table_start_ptr = IntPtrAdd(
        old_table_address_with_tag, ctrl_table_start_offset_minus_tag);
    TNode<IntPtrT> new_ctrl_table_start_ptr = IntPtrAdd(
        new_table_address_with_tag, ctrl_table_start_offset_minus_tag);

    CallCFunction(
        memcpy, MachineType::Pointer(),
        std::make_pair(MachineType::Pointer(), new_ctrl_table_start_ptr),
        std::make_pair(MachineType::Pointer(), old_ctrl_table_start_ptr),
        std::make_pair(MachineType::UintPtr(), ctrl_table_size_bytes));
  }

  Comment("Copy the data table.");
  {
    TNode<IntPtrT> start_offset =
        IntPtrConstant(SwissNameDictionary::DataTableStartOffset());
    TNode<IntPtrT> data_table_size = IntPtrMul(
        IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize),
        capacity);

    BuildFastLoop<IntPtrT>(
        start_offset, IntPtrAdd(start_offset, data_table_size),
        [=, this](TNode<IntPtrT> offset) {
          TNode<Object> table_field = LoadObjectField(original, offset);
          StoreObjectField(table, offset, table_field);
        },
        kTaggedSize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }

  Comment("Copy the meta table");
  {
    TNode<IntPtrT> old_meta_table_address_with_tag =
        BitcastTaggedToWord(LoadSwissNameDictionaryMetaTable(original));
    TNode<IntPtrT> new_meta_table_address_with_tag =
        BitcastTaggedToWord(meta_table);

    TNode<IntPtrT> meta_table_size =
        SwissNameDictionaryMetaTableSizeFor(capacity);

    TNode<IntPtrT> old_data_start = IntPtrAdd(
        old_meta_table_address_with_tag,
        IntPtrConstant(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));
    TNode<IntPtrT> new_data_start = IntPtrAdd(
        new_meta_table_address_with_tag,
        IntPtrConstant(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));

    CallCFunction(memcpy, MachineType::Pointer(),
                  std::make_pair(MachineType::Pointer(), new_data_start),
                  std::make_pair(MachineType::Pointer(), old_data_start),
                  std::make_pair(MachineType::UintPtr(), meta_table_size));
  }

  Comment("Copy the PropertyDetails table");
  {
    TNode<IntPtrT> property_details_start_offset_minus_tag =
        SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                            IntPtrConstant(0));

    // Offset to property details entry
    TVARIABLE(IntPtrT, details_table_offset_minus_tag,
              property_details_start_offset_minus_tag);

    TNode<IntPtrT> start = ctrl_table_start_offset_minus_tag;

    VariableList in_loop_variables({&details_table_offset_minus_tag}, zone());
    BuildFastLoop<IntPtrT>(
        in_loop_variables, start, IntPtrAdd(start, ctrl_table_size_bytes),
        [&](TNode<IntPtrT> ctrl_table_offset) {
          TNode<Uint8T> ctrl = Load<Uint8T>(original, ctrl_table_offset);

          // TODO(v8:11330) Entries in the PropertyDetails table may be
          // uninitialized if the corresponding buckets in the data/ctrl table
          // are empty. Therefore, to avoid accessing un-initialized memory
          // here, we need to check the ctrl table to determine whether we
          // should copy a certain PropertyDetails entry or not.
          // TODO(v8:11330) If this function becomes performance-critical, we
          // may consider always initializing the PropertyDetails table entirely
          // during allocation, to avoid the branching during copying.
          Label done(this);
          // |kNotFullMask| catches kEmpty and kDeleted, both of which indicate
          // entries that we don't want to copy the PropertyDetails for.
          GotoIf(IsSetWord32(ctrl, swiss_table::kNotFullMask), &done);

          TNode<Uint8T> details =
              Load<Uint8T>(original, details_table_offset_minus_tag.value());

          StoreToObject(MachineRepresentation::kWord8, table,
                        details_table_offset_minus_tag.value(), details,
                        StoreToObjectWriteBarrier::kNone);
          Goto(&done);
          BIND(&done);

          details_table_offset_minus_tag =
              IntPtrAdd(details_table_offset_minus_tag.value(),
                        IntPtrConstant(kOneByteSize));
        },
        kOneByteSize, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);
  }

  Comment("CopySwissNameDictionary ]");

  return table;
}

TNode<IntPtrT> CodeStubAssembler::SwissNameDictionaryOffsetIntoDataTableMT(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> index, int field_index) {
  TNode<IntPtrT> data_table_start = SwissNameDictionaryDataTableStartOffsetMT();

  TNode<IntPtrT> offset_within_data_table = IntPtrMul(
      index,
      IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize));

  if (field_index != 0) {
    offset_within_data_table = IntPtrAdd(
        offset_within_data_table, IntPtrConstant(field_index * kTaggedSize));
  }

  return IntPtrAdd(data_table_start, offset_within_data_table);
}

TNode<IntPtrT>
CodeStubAssembler::SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> capacity,
    TNode<IntPtrT> index) {
  CSA_DCHECK(this,
             WordEqual(capacity, ChangeUint32ToWord(
                                     LoadSwissNameDictionaryCapacity(dict))));

  TNode<IntPtrT> data_table_start = SwissNameDictionaryDataTableStartOffsetMT();

  TNode<IntPtrT> gw = IntPtrConstant(SwissNameDictionary::kGroupWidth);
  TNode<IntPtrT> data_and_ctrl_table_size = IntPtrAdd(
      IntPtrMul(capacity,
                IntPtrConstant(kOneByteSize +
                               SwissNameDictionary::kDataTableEntryCount *
                                   kTaggedSize)),
      gw);

  TNode<IntPtrT> property_details_table_start =
      IntPtrAdd(data_table_start, data_and_ctrl_table_size);

  CSA_DCHECK(
      this,
      WordEqual(FieldSliceSwissNameDictionaryPropertyDetailsTable(dict).offset,
                // Our calculation subtracted the tag, Torque's offset didn't.
                IntPtrAdd(property_details_table_start,
                          IntPtrConstant(kHeapObjectTag))));

  TNode<IntPtrT> offset_within_details_table = index;
  return IntPtrAdd(property_details_table_start, offset_within_details_table);
}

void CodeStubAssembler::StoreSwissNameDictionaryCapacity(
    TNode<SwissNameDictionary> table, TNode<Int32T> capacity) {
  StoreObjectFieldNoWriteBarrier<Word32T>(
      table, SwissNameDictionary::CapacityOffset(), capacity);
}

TNode<Name> CodeStubAssembler::LoadSwissNameDictionaryKey(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> entry) {
  TNode<IntPtrT> offset_minus_tag = SwissNameDictionaryOffsetIntoDataTableMT(
      dict, entry, SwissNameDictionary::kDataTableKeyEntryIndex);

  // TODO(v8:11330) Consider using LoadObjectField here.
  return CAST(Load<Object>(dict, offset_minus_tag));
}

TNode<Uint8T> CodeStubAssembler::LoadSwissNameDictionaryPropertyDetails(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry) {
  TNode<IntPtrT> offset_minus_tag =
      SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                          entry);
  // TODO(v8:11330) Consider using LoadObjectField here.
  return Load<Uint8T>(table, offset_minus_tag);
}

void CodeStubAssembler::StoreSwissNameDictionaryPropertyDetails(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry, TNode<Uint8T> details) {
  TNode<IntPtrT> offset_minus_tag =
      SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                          entry);

  // TODO(v8:11330) Consider using StoreObjectField here.
  StoreToObject(MachineRepresentation::kWord8, table, offset_minus_tag, details,
                StoreToObjectWriteBarrier::kNone);
}

void CodeStubAssembler::StoreSwissNameDictionaryKeyAndValue(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> entry, TNode<Object> key,
    TNode<Object> value) {
  static_assert(SwissNameDictionary::kDataTableKeyEntryIndex == 0);
  static_assert(SwissNameDictionary::kDataTableValueEntryIndex == 1);

  // TODO(v8:11330) Consider using StoreObjectField here.
  TNode<IntPtrT> key_offset_minus_tag =
      SwissNameDictionaryOffsetIntoDataTableMT(
          dict, entry, SwissNameDictionary::kDataTableKeyEntryIndex);
  StoreToObject(MachineRepresentation::kTagged, dict, key_offset_minus_tag, key,
                StoreToObjectWriteBarrier::kFull);

  TNode<IntPtrT> value_offset_minus_tag =
      IntPtrAdd(key_offset_minus_tag, IntPtrConstant(kTaggedSize));
  StoreToObject(MachineRepresentation::kTagged, dict, value_offset_minus_tag,
                value, StoreToObjectWriteBarrier::kFull);
}

TNode<Uint64T> CodeStubAssembler::LoadSwissNameDictionaryCtrlTableGroup(
    TNode<IntPtrT> address) {
  TNode<RawPtrT> ptr = ReinterpretCast<RawPtrT>(address);
  TNode<Uint64T> data = UnalignedLoad<Uint64T>(ptr, IntPtrConstant(0));

#ifdef V8_TARGET_LITTLE_ENDIAN
  return data;
#else
  // Reverse byte order.
  // TODO(v8:11330) Doing this without using dedicated instructions (which we
  // don't have access to here) will destroy any performance benefit Swiss
  // Tables have. So we just support this so that we don't have to disable the
  // test suite for SwissNameDictionary on big endian platforms.

  TNode<Uint64T> result = Uint64Constant(0);
  constexpr int count = sizeof(uint64_t);
  for (int i = 0; i < count; ++i) {
    int src_offset = i * 8;
    int dest_offset = (count - i - 1) * 8;

    TNode<Uint64T> mask = Uint64Constant(0xffULL << src_offset);
    TNode<Uint64T> src_data = Word64And(data, mask);

    TNode<Uint64T> shifted =
        src_offset < dest_offset
            ? Word64Shl(src_data, Uint64Constant(dest_offset - src_offset))
            : Word64Shr(src_data, Uint64Constant(src_offset - dest_offset));
    result = Unsigned(Word64Or(result, shifted));
  }
  return result;
#endif
}

void CodeStubAssembler::SwissNameDictionarySetCtrl(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry, TNode<Uint8T> ctrl) {
  CSA_DCHECK(this,
             WordEqual(capacity, ChangeUint32ToWord(
                                     LoadSwissNameDictionaryCapacity(table))));
  CSA_DCHECK(this, UintPtrLessThan(entry, capacity));

  TNode<IntPtrT> one = IntPtrConstant(1);
  TNode<IntPtrT> offset = SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  CSA_DCHECK(this,
             WordEqual(FieldSliceSwissNameDictionaryCtrlTable(table).offset,
                       IntPtrAdd(offset, one)));

  TNode<IntPtrT> offset_entry = IntPtrAdd(offset, entry);
  StoreToObject(MachineRepresentation::kWord8, table, offset_entry, ctrl,
                StoreToObjectWriteBarrier::kNone);

  TNode<IntPtrT> mask = IntPtrSub(capacity, one);
  TNode<IntPtrT> group_width = IntPtrConstant(SwissNameDictionary::kGroupWidth);

  // See SwissNameDictionary::SetCtrl for description of what's going on here.

  // ((entry - Group::kWidth) & mask) + 1
  TNode<IntPtrT> copy_entry_lhs =
      IntPtrAdd(WordAnd(IntPtrSub(entry, group_width), mask), one);
  // ((Group::kWidth - 1) & mask)
  TNode<IntPtrT> copy_entry_rhs = WordAnd(IntPtrSub(group_width, one), mask);
  TNode<IntPtrT> copy_entry = IntPtrAdd(copy_entry_lhs, copy_entry_rhs);
  TNode<IntPtrT> offset_copy_entry = IntPtrAdd(offset, copy_entry);

  // |entry| < |kGroupWidth| implies |copy_entry| == |capacity| + |entry|
  CSA_DCHECK(this, Word32Or(UintPtrGreaterThanOrEqual(entry, group_width),
                            WordEqual(copy_entry, IntPtrAdd(capacity, entry))));

  // |entry| >= |kGroupWidth| implies |copy_entry| == |entry|
  CSA_DCHECK(this, Word32Or(UintPtrLessThan(entry, group_width),
                            WordEqual(copy_entry, entry)));

  // TODO(v8:11330): consider using StoreObjectFieldNoWriteBarrier here.
  StoreToObject(MachineRepresentation::kWord8, table, offset_copy_entry, ctrl,
                StoreToObjectWriteBarrier::kNone);
}

void CodeStubAssembler::SwissNameDictionaryFindEntry(
    TNode<SwissNameDictionary> table, TNode<Name> key, Label* found,
    TVariable<IntPtrT>* var_found_entry, Label* not_found) {
  if (SwissNameDictionary::kUseSIMD) {
    SwissNameDictionaryFindEntrySIMD(table, key, found, var_found_entry,
                                     not_found);
  } else {
    SwissNameDictionaryFindEntryPortable(table, key, found, var_found_entry,
                                         not_found);
  }
}

void CodeStubAssembler::SwissNameDictionaryAdd(TNode<SwissNameDictionary> table,
                                               TNode<Name> key,
                                               TNode<Object> value,
                                               TNode<Uint8T> property_details,
                                               Label* needs_resize) {
  if (SwissNameDictionary::kUseSIMD) {
    SwissNameDictionaryAddSIMD(table, key, value, property_details,
                               needs_resize);
  } else {
    SwissNameDictionaryAddPortable(table, key, value, property_details,
                                   needs_resize);
  }
}

void CodeStubAssembler::SharedValueBarrier(
    TNode<Context> context, TVariable<Object>* var_shared_value) {
  // The barrier ensures that the value can be shared across Isolates.
  // The fast paths should be kept in sync with Object::Share.

  TNode<Object> value = var_shared_value->value();
  Label check_in_shared_heap(this), slow(this), skip_barrier(this), done(this);

  // Fast path: Smis are trivially shared.
  GotoIf(TaggedIsSmi(value), &done);
  // Fast path: Shared memory features imply shared RO space, so RO objects are
  // trivially shared.
  CSA_DCHECK(this, BoolConstant(ReadOnlyHeap::IsReadOnlySpaceShared()));
  TNode<IntPtrT> page_flags = LoadMemoryChunkFlags(CAST(value));
  GotoIf(WordNotEqual(
             WordAnd(page_flags, IntPtrConstant(MemoryChunk::READ_ONLY_HEAP)),
             IntPtrConstant(0)),
         &skip_barrier);

  // Fast path: Check if the HeapObject is already shared.
  TNode<Uint16T> value_instance_type =
      LoadMapInstanceType(LoadMap(CAST(value)));
  GotoIf(IsSharedStringInstanceType(value_instance_type), &skip_barrier);
  GotoIf(IsAlwaysSharedSpaceJSObjectInstanceType(value_instance_type),
         &skip_barrier);
  GotoIf(IsHeapNumberInstanceType(value_instance_type), &check_in_shared_heap);
  Goto(&slow);

  BIND(&check_in_shared_heap);
  {
    Branch(WordNotEqual(
               WordAnd(page_flags,
                       IntPtrConstant(MemoryChunk::IN_WRITABLE_SHARED_SPACE)),
               IntPtrConstant(0)),
           &skip_barrier, &slow);
  }

  // Slow path: Call out to runtime to share primitives and to throw on
  // non-shared JS objects.
  BIND(&slow);
  {
    *var_shared_value =
        CallRuntime(Runtime::kSharedValueBarrierSlow, context, value);
    Goto(&skip_barrier);
  }

  BIND(&skip_barrier);
  {
    CSA_DCHECK(
        this,
        WordNotEqual(
            WordAnd(LoadMemoryChunkFlags(CAST(var_shared_value->value())),
                    IntPtrConstant(MemoryChunk::READ_ONLY_HEAP |
                                   MemoryChunk::IN_WRITABLE_SHARED_SPACE)),
            IntPtrConstant(0)));
    Goto(&done);
  }

  BIND(&done);
}

TNode<ArrayList> CodeStubAssembler::AllocateArrayList(TNode<Smi> capacity) {
  TVARIABLE(ArrayList, result);
  Label empty(this), nonempty(this), done(this);

  Branch(SmiEqual(capacity, SmiConstant(0)), &empty, &nonempty);

  BIND(&nonempty);
  {
    CSA_DCHECK(this, SmiGreaterThan(capacity, SmiConstant(0)));

    intptr_t capacity_constant;
    if (ToParameterConstant(capacity, &capacity_constant)) {
      CHECK_LE(capacity_constant, ArrayList::kMaxCapacity);
    } else {
      Label if_out_of_memory(this, Label::kDeferred), next(this);
      Branch(SmiGreaterThan(capacity, SmiConstant(ArrayList::kMaxCapacity)),
             &if_out_of_memory, &next);

      BIND(&if_out_of_memory);
      CallRuntime(Runtime::kFatalProcessOutOfMemoryInvalidArrayLength,
                  NoContextConstant());
      Unreachable();

      BIND(&next);
    }

    TNode<IntPtrT> total_size = GetArrayAllocationSize(
        capacity, PACKED_ELEMENTS, OFFSET_OF_DATA_START(ArrayList));
    TNode<HeapObject> array = Allocate(total_size);
    RootIndex map_index = RootIndex::kArrayListMap;
    DCHECK(RootsTable::IsImmortalImmovable(map_index));
    StoreMapNoWriteBarrier(array, map_index);
    StoreObjectFieldNoWriteBarrier(array, offsetof(ArrayList, capacity_),
                                   capacity);
    StoreObjectFieldNoWriteBarrier(array, offsetof(
"""


```