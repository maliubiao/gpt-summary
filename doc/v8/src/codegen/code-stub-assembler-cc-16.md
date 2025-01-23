Response:
My thought process for analyzing the provided V8 `code-stub-assembler.cc` snippet goes through these stages:

1. **Identify the Core Functionality:** I first scanned the code for recurring patterns and keywords. The names like `TrapAllocationMemento`, `GrowElementsCapacity`, `CreateAllocationSiteInFeedbackVector`, `BuildFastLoop`, `BranchIfNumberRelationalComparison`, and `RelationalComparison` immediately stood out. These names strongly suggest the code is involved in memory management, object allocation, array manipulation, and implementing JavaScript comparison operators.

2. **Categorize the Functions:**  Based on the identified keywords, I began grouping related functions:
    * **Allocation and Memory Management:** `TrapAllocationMemento`, `MemoryChunkFromAddress`, `PageMetadataFromMemoryChunk`, `PageMetadataFromAddress`, `GrowElementsCapacity`, `GotoIfFixedArraySizeDoesntFitInNewSpace`. These seem to deal with low-level memory operations, tracking allocations, and ensuring sufficient space.
    * **Feedback Vectors and Optimization:** `CreateAllocationSiteInFeedbackVector`, `StoreWeakReferenceInFeedbackVector`, `HasBoilerplate`, `LoadTransitionInfo`, `LoadBoilerplate`, `LoadElementsKind`, `LoadNestedAllocationSite`. These point to a mechanism for gathering runtime information about object usage to optimize future operations. The "allocation site" concept is a key indicator here.
    * **Looping Constructs:** `BuildFastLoop`, `BuildFastArrayForEach`. These are helper functions to efficiently iterate over arrays and memory regions. The template nature suggests they're designed for different data types.
    * **Type Checking and Conversions (Implicit):**  While not explicitly named "conversion" functions, the presence of `BranchIfNumberRelationalComparison` and `RelationalComparison` indicates the code handles JavaScript's implicit type conversions during comparisons (e.g., comparing a number and a string). The `SmiToFloat64` function confirms this.
    * **Context and Scope:** `GotoIfHasContextExtensionUpToDepth`. This function suggests the code interacts with JavaScript's scope and context mechanisms.
    * **BigInt Support:** `BigInt64Comparison`. This function clearly deals with comparisons involving BigInts, a more recent addition to JavaScript.

3. **Infer Relationships and Context:** I then considered how these categorized functions might interact. For example, `TrapAllocationMemento` likely works in conjunction with the allocation process to mark objects for tracking. `CreateAllocationSiteInFeedbackVector` likely uses the allocation functions to create the allocation site objects. The "feedback vector" suggests that the information gathered is used to inform later code execution paths.

4. **Consider the ".cc" Extension:** The prompt explicitly states that if the file had a ".tq" extension, it would be a Torque file. The ".cc" extension means it's C++, which is consistent with the low-level memory manipulation and code generation aspects of the functions.

5. **Address the JavaScript Relationship:**  The prompt asked to connect the C++ code to JavaScript functionality. The comparison functions (`BranchIfNumberRelationalComparison`, `RelationalComparison`, `BigInt64Comparison`) directly implement JavaScript's comparison operators (`>`, `<`, `>=`, `<=`, `==`, `!=`, `===`, `!==`). The array manipulation functions relate to how JavaScript arrays are handled internally. The allocation site and feedback vector concepts are behind-the-scenes optimizations for how JavaScript objects are created and used.

6. **Construct Examples:** For the JavaScript examples, I chose simple, direct illustrations of the concepts identified in the C++ code. For instance, comparisons using different data types demonstrate the implicit conversions handled by the C++ comparison functions. Array manipulations and object creation showcase the underlying mechanisms the C++ code supports.

7. **Address Potential Errors:** I thought about common JavaScript errors related to the functionalities I identified. Type errors in comparisons (e.g., comparing incompatible types) and performance issues with large arrays are relevant.

8. **Synthesize the Summary:**  Finally, I combined all the observations into a concise summary that highlights the key functionalities: low-level memory management, optimization through feedback, implementation of JavaScript features, and its role within the V8 engine. I also noted the ".cc" extension and its implications.

Essentially, I approached this like reverse engineering: examining the code's structure and function names to deduce its purpose and then connecting those deductions to the higher-level concepts of JavaScript and the V8 engine. The prompt's hints about Torque were also useful for confirming the C++ nature of the code.
好的，让我们来分析一下 `v8/src/codegen/code-stub-assembler.cc` 的这段代码。

**功能列举:**

这段代码片段主要涉及以下功能：

1. **对象属性和 Map 的修改和管理:**
   - `TransitionElementsKind`:  改变对象的 elements kind（例如，从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_DOUBLE_ELEMENTS` 或 `HOLEY_ELEMENTS`）。这涉及到调整对象的内部结构以适应不同类型的元素存储。
   - `StoreMap`:  修改对象的 Map (也称为 hidden class)，这会改变对象的结构和属性查找方式。

2. **Allocation Memento 的处理:**
   - `TrapAllocationMemento`:  用于检测对象是否分配了 Allocation Memento。Allocation Memento 是 V8 用来跟踪对象分配情况的一种机制，尤其是在进行对象字面量优化时。

3. **内存管理相关的辅助函数:**
   - `MemoryChunkFromAddress`:  根据给定的地址，计算出该地址所属的内存块 (MemoryChunk) 的起始地址。
   - `PageMetadataFromMemoryChunk`:  从内存块的地址获取页面元数据 (PageMetadata)。
   - `PageMetadataFromAddress`:  从地址获取页面元数据。

4. **AllocationSite 的创建和管理 (用于优化):**
   - `CreateAllocationSiteInFeedbackVector`: 在 FeedbackVector 中创建一个 AllocationSite。AllocationSite 用于记录对象分配的信息，帮助 V8 进行优化，例如内联缓存 (Inline Caches)。
   - `StoreWeakReferenceInFeedbackVector`: 在 FeedbackVector 中存储一个对对象的弱引用。
   - `HasBoilerplate`: 检查 AllocationSite 是否关联了 boilerplate（预编译的代码）。
   - `LoadTransitionInfo`: 加载 AllocationSite 的转换信息。
   - `LoadBoilerplate`: 加载 AllocationSite 关联的 boilerplate 代码。
   - `LoadElementsKind(AllocationSite)`: 从 AllocationSite 加载 elements kind。
   - `LoadNestedAllocationSite`: 加载嵌套的 AllocationSite。

5. **高效循环构建:**
   - `BuildFastLoop`:  提供了一种构建高效循环的模板方法，可以指定循环的起始、结束、步长、展开模式等。
   - `BuildFastArrayForEach`:  专门用于遍历快速数组（FixedArray 或 PropertyArray）的元素，并对每个元素执行操作。

6. **内存空间判断:**
   - `GotoIfFixedArraySizeDoesntFitInNewSpace`:  判断指定大小的 FixedArray 是否能放入新生代 (new space) 中。

7. **对象字段初始化:**
   - `InitializeFieldsWithRoot`:  使用指定的 Root 对象填充对象的字段。

8. **数字比较:**
   - `BranchIfNumberRelationalComparison`:  根据给定的比较操作符，比较两个数字（可以是 Smi 或 HeapNumber），并跳转到相应的标签。
   - `GotoIfNumberGreaterThanOrEqual`:  如果左边的数字大于等于右边的数字，则跳转到指定的标签。

9. **上下文 (Context) 扩展链遍历:**
   - `GotoIfHasContextExtensionUpToDepth`:  检查当前上下文的扩展链上是否存在扩展对象，直到指定的深度。

10. **BigInt 比较:**
    - `BigInt64Comparison`:  比较两个 BigInt 类型的值。

11. **关系比较:**
    - `RelationalComparison`:  实现 JavaScript 的关系比较操作符（如 `<`, `>`, `<=`, `>=`），处理不同类型的值，包括 Smi、HeapNumber 和 BigInt，并更新类型反馈。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它就是 **V8 Torque 源代码**。Torque 是一种 V8 自研的类型化的领域特定语言，用于生成高效的 C++ 代码。Torque 代码通常更易于阅读和维护，并且可以进行静态类型检查。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这段代码与 JavaScript 的许多核心功能息息相关，因为它涉及到对象的创建、属性的修改、数组的操作以及比较运算符的实现。

**示例 1: 对象属性修改和 ElementsKind 转换**

```javascript
const arr = [1, 2, 3]; // 初始是 PACKED_SMI_ELEMENTS

arr.push(4.5); // 触发 ElementsKind 转换为 PACKED_DOUBLE_ELEMENTS
```

在 V8 内部，当执行 `arr.push(4.5)` 时，由于要存储浮点数，数组的 elements kind 会从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_DOUBLE_ELEMENTS`。`TransitionElementsKind` 函数就可能参与了这个过程。

**示例 2: 对象 Map 的修改**

```javascript
const obj = { x: 1 }; // 初始有一个 Map

obj.y = 2; // 添加新的属性可能会导致 Map 的转换
```

当向对象添加新属性时，如果 V8 没有找到合适的现有 Map 来描述新结构，它可能会创建一个新的 Map 并更新对象的 Map。`StoreMap` 函数就负责更新对象的 Map 指针。

**示例 3: 关系比较**

```javascript
console.log(5 > 3);   // true
console.log(5 > '4'); // true (字符串 '4' 被转换为数字 4)
console.log(10n > 5);  // true (BigInt 与 Number 比较)
```

`BranchIfNumberRelationalComparison` 和 `RelationalComparison`  这类函数负责实现 JavaScript 中大于、小于等比较操作符的行为，包括处理不同类型之间的隐式转换。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (对于 `TransitionElementsKind`):**

- `object`: 一个 JavaScript 数组对象，其 elements kind 为 `PACKED_SMI_ELEMENTS`。
- `map`:  目标 Map，其对应的 elements kind 为 `PACKED_DOUBLE_ELEMENTS`。
- `to_kind`: `PACKED_DOUBLE_ELEMENTS`。
- `bailout`: 一个标签，用于在操作失败时跳转。

**可能的输出:**

- 如果数组内部存储的都是小的整数，并且没有空洞，那么 `GrowElementsCapacity` 可能会被调用，以便为存储浮点数扩展数组的容量。
- 对象的 Map 会被更新为 `map`。
- 对象的 elements kind 会变为 `PACKED_DOUBLE_ELEMENTS`。

**涉及用户常见的编程错误:**

1. **类型不一致导致的性能问题:**

   ```javascript
   const arr = [];
   for (let i = 0; i < 1000; i++) {
     if (i % 2 === 0) {
       arr.push(i); // 整数
     } else {
       arr.push("hello"); // 字符串
     }
   }
   ```

   在这个例子中，数组 `arr` 中混合了数字和字符串。这会导致 V8 难以优化数组的存储，可能会多次触发 elements kind 的转换，降低性能。开发者应该尽量保持数组中元素的类型一致。

2. **频繁添加或删除属性导致 Map 不断变化:**

   ```javascript
   const obj = {};
   for (let i = 0; i < 10; i++) {
     obj[`prop${i}`] = i;
   }
   ```

   虽然动态添加属性是 JavaScript 的特性，但如果在一个循环中频繁地向同一个对象添加不同的属性，可能会导致 V8 不断地创建新的 Map，影响性能。预先确定对象的结构或使用固定的属性可以帮助 V8 进行优化。

3. **在比较中没有注意到隐式类型转换:**

   ```javascript
   console.log(5 > "3");  // true
   console.log(5 > "hello"); // false (因为 "hello" 转换为 NaN)
   console.log(5 > null);  // true (因为 null 转换为 0)
   ```

   开发者需要理解 JavaScript 比较操作符的隐式类型转换规则，避免出现意料之外的结果。

**归纳其功能 (作为第 17 部分，共 23 部分):**

作为 V8 代码生成器 (codegen) 的一部分，`code-stub-assembler.cc` 的这个片段专注于 **运行时对象结构的管理和优化** 以及 **基础运算的实现**。它提供了用于修改对象内部结构（如 elements kind 和 Map）、管理内存分配信息（通过 Allocation Memento 和 AllocationSite）、构建高效循环以及实现基本运算（如数字和关系比较）的底层工具。

在整个代码生成流程中，这个部分负责确保在运行时能够高效地表示和操作 JavaScript 对象，并根据运行时的反馈信息进行优化。它连接了高级的 JavaScript 语义和底层的机器指令，是 V8 性能优化的关键组成部分。这段代码的功能是为后续的代码生成和优化步骤提供必要的构建块和运行时支持。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第17部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
ElementsKind to_kind,
                                               Label* bailout) {
  DCHECK(!IsHoleyElementsKind(from_kind) || IsHoleyElementsKind(to_kind));
  if (AllocationSite::ShouldTrack(from_kind, to_kind)) {
    TrapAllocationMemento(object, bailout);
  }

  if (!IsSimpleMapChangeTransition(from_kind, to_kind)) {
    Comment("Non-simple map transition");
    TNode<FixedArrayBase> elements = LoadElements(object);

    Label done(this);
    GotoIf(TaggedEqual(elements, EmptyFixedArrayConstant()), &done);

    // TODO(ishell): Use BInt for elements_length and array_length.
    TNode<IntPtrT> elements_length = LoadAndUntagFixedArrayBaseLength(elements);
    TNode<IntPtrT> array_length = Select<IntPtrT>(
        IsJSArray(object),
        [=, this]() {
          CSA_DCHECK(this, IsFastElementsKind(LoadElementsKind(object)));
          return PositiveSmiUntag(LoadFastJSArrayLength(CAST(object)));
        },
        [=]() { return elements_length; });

    CSA_DCHECK(this, WordNotEqual(elements_length, IntPtrConstant(0)));

    GrowElementsCapacity(object, elements, from_kind, to_kind, array_length,
                         elements_length, bailout);
    Goto(&done);
    BIND(&done);
  }

  StoreMap(object, map);
}

void CodeStubAssembler::TrapAllocationMemento(TNode<JSObject> object,
                                              Label* memento_found) {
  DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
  Comment("[ TrapAllocationMemento");
  Label no_memento_found(this);
  Label top_check(this), map_check(this);

  TNode<ExternalReference> new_space_top_address = ExternalConstant(
      ExternalReference::new_space_allocation_top_address(isolate()));
  const int kMementoMapOffset =
      ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize);
  const int kMementoLastWordOffset =
      kMementoMapOffset + AllocationMemento::kSize - kTaggedSize;

  // Bail out if the object is not in new space.
  TNode<IntPtrT> object_word = BitcastTaggedToWord(object);
  // TODO(v8:11641): Skip TrapAllocationMemento when allocation-site
  // tracking is disabled.
  TNode<IntPtrT> object_page_header = MemoryChunkFromAddress(object_word);
  {
    TNode<IntPtrT> page_flags = Load<IntPtrT>(
        object_page_header, IntPtrConstant(MemoryChunk::FlagsOffset()));
    if (v8_flags.sticky_mark_bits) {
      // Pages with only old objects contain no mementos.
      GotoIfNot(
          WordEqual(WordAnd(page_flags,
                            IntPtrConstant(MemoryChunk::CONTAINS_ONLY_OLD)),
                    IntPtrConstant(0)),
          &no_memento_found);
    } else {
      GotoIf(WordEqual(
                 WordAnd(page_flags,
                         IntPtrConstant(MemoryChunk::kIsInYoungGenerationMask)),
                 IntPtrConstant(0)),
             &no_memento_found);
    }
    // TODO(v8:11799): Support allocation memento for a large object by
    // allocating additional word for the memento after the large object.
    GotoIf(WordNotEqual(WordAnd(page_flags,
                                IntPtrConstant(MemoryChunk::kIsLargePageMask)),
                        IntPtrConstant(0)),
           &no_memento_found);
  }

  TNode<IntPtrT> memento_last_word = IntPtrAdd(
      object_word, IntPtrConstant(kMementoLastWordOffset - kHeapObjectTag));
  TNode<IntPtrT> memento_last_word_page_header =
      MemoryChunkFromAddress(memento_last_word);

  TNode<IntPtrT> new_space_top = Load<IntPtrT>(new_space_top_address);
  TNode<IntPtrT> new_space_top_page_header =
      MemoryChunkFromAddress(new_space_top);

  // If the object is in new space, we need to check whether respective
  // potential memento object is on the same page as the current top.
  GotoIf(WordEqual(memento_last_word_page_header, new_space_top_page_header),
         &top_check);

  // The object is on a different page than allocation top. Bail out if the
  // object sits on the page boundary as no memento can follow and we cannot
  // touch the memory following it.
  Branch(WordEqual(object_page_header, memento_last_word_page_header),
         &map_check, &no_memento_found);

  // If top is on the same page as the current object, we need to check whether
  // we are below top.
  BIND(&top_check);
  {
    Branch(UintPtrGreaterThanOrEqual(memento_last_word, new_space_top),
           &no_memento_found, &map_check);
  }

  // Memento map check.
  BIND(&map_check);
  {
    TNode<AnyTaggedT> maybe_mapword =
        LoadObjectField(object, kMementoMapOffset);
    TNode<AnyTaggedT> memento_mapword =
        LoadRootMapWord(RootIndex::kAllocationMementoMap);
    Branch(TaggedEqual(maybe_mapword, memento_mapword), memento_found,
           &no_memento_found);
  }
  BIND(&no_memento_found);
  Comment("] TrapAllocationMemento");
}

TNode<IntPtrT> CodeStubAssembler::MemoryChunkFromAddress(
    TNode<IntPtrT> address) {
  return WordAnd(address,
                 IntPtrConstant(~MemoryChunk::GetAlignmentMaskForAssembler()));
}

TNode<IntPtrT> CodeStubAssembler::PageMetadataFromMemoryChunk(
    TNode<IntPtrT> address) {
#ifdef V8_ENABLE_SANDBOX
  TNode<RawPtrT> table = ExternalConstant(
      ExternalReference::memory_chunk_metadata_table_address());
  TNode<Uint32T> index = Load<Uint32T>(
      address, IntPtrConstant(MemoryChunk::MetadataIndexOffset()));
  index = Word32And(
      index, UniqueUint32Constant(MemoryChunk::kMetadataPointerTableSizeMask));
  TNode<IntPtrT> offset = ChangeInt32ToIntPtr(
      Word32Shl(index, UniqueUint32Constant(kSystemPointerSizeLog2)));
  TNode<IntPtrT> metadata = Load<IntPtrT>(table, offset);
  // Check that the Metadata belongs to this Chunk, since an attacker with write
  // inside the sandbox could've swapped the index.
  TNode<IntPtrT> metadata_chunk = MemoryChunkFromAddress(Load<IntPtrT>(
      metadata, IntPtrConstant(MemoryChunkMetadata::AreaStartOffset())));
  CSA_CHECK(this, WordEqual(metadata_chunk, address));
  return metadata;
#else
  return Load<IntPtrT>(address, IntPtrConstant(MemoryChunk::MetadataOffset()));
#endif
}

TNode<IntPtrT> CodeStubAssembler::PageMetadataFromAddress(
    TNode<IntPtrT> address) {
  return PageMetadataFromMemoryChunk(MemoryChunkFromAddress(address));
}

TNode<AllocationSite> CodeStubAssembler::CreateAllocationSiteInFeedbackVector(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot) {
  TNode<IntPtrT> size = IntPtrConstant(AllocationSite::kSizeWithWeakNext);
  TNode<HeapObject> site = Allocate(size, AllocationFlag::kPretenured);
  StoreMapNoWriteBarrier(site, RootIndex::kAllocationSiteWithWeakNextMap);
  // Should match AllocationSite::Initialize.
  TNode<WordT> field = UpdateWord<AllocationSite::ElementsKindBits>(
      IntPtrConstant(0), UintPtrConstant(GetInitialFastElementsKind()));
  StoreObjectFieldNoWriteBarrier(
      site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
      SmiTag(Signed(field)));

  // Unlike literals, constructed arrays don't have nested sites
  TNode<Smi> zero = SmiConstant(0);
  StoreObjectFieldNoWriteBarrier(site, AllocationSite::kNestedSiteOffset, zero);

  // Pretenuring calculation field.
  StoreObjectFieldNoWriteBarrier(site, AllocationSite::kPretenureDataOffset,
                                 Int32Constant(0));

  // Pretenuring memento creation count field.
  StoreObjectFieldNoWriteBarrier(
      site, AllocationSite::kPretenureCreateCountOffset, Int32Constant(0));

  // Store an empty fixed array for the code dependency.
  StoreObjectFieldRoot(site, AllocationSite::kDependentCodeOffset,
                       DependentCode::kEmptyDependentCode);

  // Link the object to the allocation site list
  TNode<ExternalReference> site_list = ExternalConstant(
      ExternalReference::allocation_sites_list_address(isolate()));
  TNode<Object> next_site =
      LoadBufferObject(ReinterpretCast<RawPtrT>(site_list), 0);

  // TODO(mvstanton): This is a store to a weak pointer, which we may want to
  // mark as such in order to skip the write barrier, once we have a unified
  // system for weakness. For now we decided to keep it like this because having
  // an initial write barrier backed store makes this pointer strong until the
  // next GC, and allocation sites are designed to survive several GCs anyway.
  StoreObjectField(site, AllocationSite::kWeakNextOffset, next_site);
  StoreFullTaggedNoWriteBarrier(site_list, site);

  StoreFeedbackVectorSlot(feedback_vector, slot, site);
  return CAST(site);
}

TNode<MaybeObject> CodeStubAssembler::StoreWeakReferenceInFeedbackVector(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
    TNode<HeapObject> value, int additional_offset) {
  TNode<HeapObjectReference> weak_value = MakeWeak(value);
  StoreFeedbackVectorSlot(feedback_vector, slot, weak_value,
                          UPDATE_WRITE_BARRIER, additional_offset);
  return weak_value;
}

TNode<BoolT> CodeStubAssembler::HasBoilerplate(
    TNode<Object> maybe_literal_site) {
  return TaggedIsNotSmi(maybe_literal_site);
}

TNode<Smi> CodeStubAssembler::LoadTransitionInfo(
    TNode<AllocationSite> allocation_site) {
  TNode<Smi> transition_info = CAST(LoadObjectField(
      allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset));
  return transition_info;
}

TNode<JSObject> CodeStubAssembler::LoadBoilerplate(
    TNode<AllocationSite> allocation_site) {
  TNode<JSObject> boilerplate = CAST(LoadObjectField(
      allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset));
  return boilerplate;
}

TNode<Int32T> CodeStubAssembler::LoadElementsKind(
    TNode<AllocationSite> allocation_site) {
  TNode<Smi> transition_info = LoadTransitionInfo(allocation_site);
  TNode<Int32T> elements_kind =
      Signed(DecodeWord32<AllocationSite::ElementsKindBits>(
          SmiToInt32(transition_info)));
  CSA_DCHECK(this, IsFastElementsKind(elements_kind));
  return elements_kind;
}

TNode<Object> CodeStubAssembler::LoadNestedAllocationSite(
    TNode<AllocationSite> allocation_site) {
  return LoadObjectField(allocation_site, AllocationSite::kNestedSiteOffset);
}

template <typename TIndex>
void CodeStubAssembler::BuildFastLoop(
    const VariableList& vars, TVariable<TIndex>& var_index,
    TNode<TIndex> start_index, TNode<TIndex> end_index,
    const FastLoopBody<TIndex>& body, TNode<TIndex> increment,
    LoopUnrollingMode unrolling_mode, IndexAdvanceMode advance_mode,
    IndexAdvanceDirection advance_direction) {
  // Update the index comparisons below in case we'd ever want to use Smi
  // indexes.
  static_assert(
      !std::is_same<TIndex, Smi>::value,
      "Smi indices are currently not supported because it's not clear whether "
      "the use case allows unsigned comparisons or not");
  var_index = start_index;
  VariableList vars_copy(vars.begin(), vars.end(), zone());
  vars_copy.push_back(&var_index);
  Label loop(this, vars_copy);
  Label after_loop(this), done(this);

  auto loop_body = [&]() {
    if (advance_mode == IndexAdvanceMode::kPre) {
      var_index = IntPtrOrSmiAdd(var_index.value(), increment);
    }
    body(var_index.value());
    if (advance_mode == IndexAdvanceMode::kPost) {
      var_index = IntPtrOrSmiAdd(var_index.value(), increment);
    }
  };
  // The loops below are generated using the following trick:
  // Introduce an explicit second check of the termination condition before
  // the loop that helps turbofan generate better code. If there's only a
  // single check, then the CodeStubAssembler forces it to be at the beginning
  // of the loop requiring a backwards branch at the end of the loop (it's not
  // possible to force the loop header check at the end of the loop and branch
  // forward to it from the pre-header). The extra branch is slower in the
  // case that the loop actually iterates.
  if (unrolling_mode == LoopUnrollingMode::kNo) {
    TNode<BoolT> first_check = UintPtrOrSmiEqual(var_index.value(), end_index);
    int32_t first_check_val;
    if (TryToInt32Constant(first_check, &first_check_val)) {
      if (first_check_val) return;
      Goto(&loop);
    } else {
      Branch(first_check, &done, &loop);
    }

    BIND(&loop);
    {
      loop_body();
      CSA_DCHECK(
          this,
          advance_direction == IndexAdvanceDirection::kUp
              ? UintPtrOrSmiLessThanOrEqual(var_index.value(), end_index)
              : UintPtrOrSmiLessThanOrEqual(end_index, var_index.value()));
      Branch(UintPtrOrSmiNotEqual(var_index.value(), end_index), &loop, &done);
    }
    BIND(&done);
  } else {
    // Check if there are at least two elements between start_index and
    // end_index.
    DCHECK_EQ(unrolling_mode, LoopUnrollingMode::kYes);
    switch (advance_direction) {
      case IndexAdvanceDirection::kUp:
        CSA_DCHECK(this, UintPtrOrSmiLessThanOrEqual(start_index, end_index));
        GotoIfNot(UintPtrOrSmiLessThanOrEqual(
                      IntPtrOrSmiAdd(start_index, increment), end_index),
                  &done);
        break;
      case IndexAdvanceDirection::kDown:

        CSA_DCHECK(this, UintPtrOrSmiLessThanOrEqual(end_index, start_index));
        GotoIfNot(UintPtrOrSmiLessThanOrEqual(
                      IntPtrOrSmiSub(end_index, increment), start_index),
                  &done);
        break;
    }

    TNode<TIndex> last_index = IntPtrOrSmiSub(end_index, increment);
    TNode<BoolT> first_check =
        advance_direction == IndexAdvanceDirection::kUp
            ? UintPtrOrSmiLessThan(start_index, last_index)
            : UintPtrOrSmiGreaterThan(start_index, last_index);
    int32_t first_check_val;
    if (TryToInt32Constant(first_check, &first_check_val)) {
      if (first_check_val) {
        Goto(&loop);
      } else {
        Goto(&after_loop);
      }
    } else {
      Branch(first_check, &loop, &after_loop);
    }

    BIND(&loop);
    {
      Comment("Unrolled Loop");
      loop_body();
      loop_body();
      TNode<BoolT> loop_check =
          advance_direction == IndexAdvanceDirection::kUp
              ? UintPtrOrSmiLessThan(var_index.value(), last_index)
              : UintPtrOrSmiGreaterThan(var_index.value(), last_index);
      Branch(loop_check, &loop, &after_loop);
    }
    BIND(&after_loop);
    {
      GotoIfNot(UintPtrOrSmiEqual(var_index.value(), last_index), &done);
      // Iteration count is odd.
      loop_body();
      Goto(&done);
    }
    BIND(&done);
  }
}

template <typename TIndex>
void CodeStubAssembler::BuildFastLoop(
    const VariableList& vars, TVariable<TIndex>& var_index,
    TNode<TIndex> start_index, TNode<TIndex> end_index,
    const FastLoopBody<TIndex>& body, int increment,
    LoopUnrollingMode unrolling_mode, IndexAdvanceMode advance_mode) {
  DCHECK_NE(increment, 0);
  BuildFastLoop(vars, var_index, start_index, end_index, body,
                IntPtrOrSmiConstant<TIndex>(increment), unrolling_mode,
                advance_mode,
                increment > 0 ? IndexAdvanceDirection::kUp
                              : IndexAdvanceDirection::kDown);
}

// Instantiate BuildFastLoop for IntPtrT, UintPtrT and RawPtrT.
template V8_EXPORT_PRIVATE void CodeStubAssembler::BuildFastLoop<IntPtrT>(
    const VariableList& vars, TVariable<IntPtrT>& var_index,
    TNode<IntPtrT> start_index, TNode<IntPtrT> end_index,
    const FastLoopBody<IntPtrT>& body, int increment,
    LoopUnrollingMode unrolling_mode, IndexAdvanceMode advance_mode);
template V8_EXPORT_PRIVATE void CodeStubAssembler::BuildFastLoop<UintPtrT>(
    const VariableList& vars, TVariable<UintPtrT>& var_index,
    TNode<UintPtrT> start_index, TNode<UintPtrT> end_index,
    const FastLoopBody<UintPtrT>& body, int increment,
    LoopUnrollingMode unrolling_mode, IndexAdvanceMode advance_mode);
template V8_EXPORT_PRIVATE void CodeStubAssembler::BuildFastLoop<RawPtrT>(
    const VariableList& vars, TVariable<RawPtrT>& var_index,
    TNode<RawPtrT> start_index, TNode<RawPtrT> end_index,
    const FastLoopBody<RawPtrT>& body, int increment,
    LoopUnrollingMode unrolling_mode, IndexAdvanceMode advance_mode);

template <typename TIndex>
void CodeStubAssembler::BuildFastArrayForEach(
    TNode<UnionOf<UnionOf<FixedArray, PropertyArray>, HeapObject>> array,
    ElementsKind kind, TNode<TIndex> first_element_inclusive,
    TNode<TIndex> last_element_exclusive, const FastArrayForEachBody& body,
    LoopUnrollingMode loop_unrolling_mode, ForEachDirection direction) {
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  CSA_SLOW_DCHECK(this, Word32Or(IsFixedArrayWithKind(array, kind),
                                 IsPropertyArray(array)));

  intptr_t first_val;
  bool constant_first =
      TryToIntPtrConstant(first_element_inclusive, &first_val);
  intptr_t last_val;
  bool constent_last = TryToIntPtrConstant(last_element_exclusive, &last_val);
  if (constant_first && constent_last) {
    intptr_t delta = last_val - first_val;
    DCHECK_GE(delta, 0);
    if (delta <= kElementLoopUnrollThreshold) {
      if (direction == ForEachDirection::kForward) {
        for (intptr_t i = first_val; i < last_val; ++i) {
          TNode<IntPtrT> index = IntPtrConstant(i);
          TNode<IntPtrT> offset = ElementOffsetFromIndex(
              index, kind, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
          body(array, offset);
        }
      } else {
        for (intptr_t i = last_val - 1; i >= first_val; --i) {
          TNode<IntPtrT> index = IntPtrConstant(i);
          TNode<IntPtrT> offset = ElementOffsetFromIndex(
              index, kind, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
          body(array, offset);
        }
      }
      return;
    }
  }

  TNode<IntPtrT> start =
      ElementOffsetFromIndex(first_element_inclusive, kind,
                             OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  TNode<IntPtrT> limit =
      ElementOffsetFromIndex(last_element_exclusive, kind,
                             OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  if (direction == ForEachDirection::kReverse) std::swap(start, limit);

  int increment = IsDoubleElementsKind(kind) ? kDoubleSize : kTaggedSize;
  BuildFastLoop<IntPtrT>(
      start, limit, [&](TNode<IntPtrT> offset) { body(array, offset); },
      direction == ForEachDirection::kReverse ? -increment : increment,
      loop_unrolling_mode,
      direction == ForEachDirection::kReverse ? IndexAdvanceMode::kPre
                                              : IndexAdvanceMode::kPost);
}

template <typename TIndex>
void CodeStubAssembler::GotoIfFixedArraySizeDoesntFitInNewSpace(
    TNode<TIndex> element_count, Label* doesnt_fit, int base_size) {
  GotoIf(FixedArraySizeDoesntFitInNewSpace(element_count, base_size),
         doesnt_fit);
}

void CodeStubAssembler::InitializeFieldsWithRoot(TNode<HeapObject> object,
                                                 TNode<IntPtrT> start_offset,
                                                 TNode<IntPtrT> end_offset,
                                                 RootIndex root_index) {
  CSA_SLOW_DCHECK(this, TaggedIsNotSmi(object));
  start_offset = IntPtrAdd(start_offset, IntPtrConstant(-kHeapObjectTag));
  end_offset = IntPtrAdd(end_offset, IntPtrConstant(-kHeapObjectTag));
  TNode<AnyTaggedT> root_value;
  if (root_index == RootIndex::kOnePointerFillerMap) {
    root_value = LoadRootMapWord(root_index);
  } else {
    root_value = LoadRoot(root_index);
  }
  BuildFastLoop<IntPtrT>(
      end_offset, start_offset,
      [=, this](TNode<IntPtrT> current) {
        StoreNoWriteBarrier(MachineRepresentation::kTagged, object, current,
                            root_value);
      },
      -kTaggedSize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPre);
}

void CodeStubAssembler::BranchIfNumberRelationalComparison(Operation op,
                                                           TNode<Number> left,
                                                           TNode<Number> right,
                                                           Label* if_true,
                                                           Label* if_false) {
  Label do_float_comparison(this);
  TVARIABLE(Float64T, var_left_float);
  TVARIABLE(Float64T, var_right_float);

  Branch(
      TaggedIsSmi(left),
      [&] {
        TNode<Smi> smi_left = CAST(left);

        Branch(
            TaggedIsSmi(right),
            [&] {
              TNode<Smi> smi_right = CAST(right);

              // Both {left} and {right} are Smi, so just perform a fast
              // Smi comparison.
              switch (op) {
                case Operation::kEqual:
                  BranchIfSmiEqual(smi_left, smi_right, if_true, if_false);
                  break;
                case Operation::kLessThan:
                  BranchIfSmiLessThan(smi_left, smi_right, if_true, if_false);
                  break;
                case Operation::kLessThanOrEqual:
                  BranchIfSmiLessThanOrEqual(smi_left, smi_right, if_true,
                                             if_false);
                  break;
                case Operation::kGreaterThan:
                  BranchIfSmiLessThan(smi_right, smi_left, if_true, if_false);
                  break;
                case Operation::kGreaterThanOrEqual:
                  BranchIfSmiLessThanOrEqual(smi_right, smi_left, if_true,
                                             if_false);
                  break;
                default:
                  UNREACHABLE();
              }
            },
            [&] {
              var_left_float = SmiToFloat64(smi_left);
              var_right_float = LoadHeapNumberValue(CAST(right));
              Goto(&do_float_comparison);
            });
      },
      [&] {
        var_left_float = LoadHeapNumberValue(CAST(left));

        Branch(
            TaggedIsSmi(right),
            [&] {
              var_right_float = SmiToFloat64(CAST(right));
              Goto(&do_float_comparison);
            },
            [&] {
              var_right_float = LoadHeapNumberValue(CAST(right));
              Goto(&do_float_comparison);
            });
      });

  BIND(&do_float_comparison);
  {
    switch (op) {
      case Operation::kEqual:
        Branch(Float64Equal(var_left_float.value(), var_right_float.value()),
               if_true, if_false);
        break;
      case Operation::kLessThan:
        Branch(Float64LessThan(var_left_float.value(), var_right_float.value()),
               if_true, if_false);
        break;
      case Operation::kLessThanOrEqual:
        Branch(Float64LessThanOrEqual(var_left_float.value(),
                                      var_right_float.value()),
               if_true, if_false);
        break;
      case Operation::kGreaterThan:
        Branch(
            Float64GreaterThan(var_left_float.value(), var_right_float.value()),
            if_true, if_false);
        break;
      case Operation::kGreaterThanOrEqual:
        Branch(Float64GreaterThanOrEqual(var_left_float.value(),
                                         var_right_float.value()),
               if_true, if_false);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void CodeStubAssembler::GotoIfNumberGreaterThanOrEqual(TNode<Number> left,
                                                       TNode<Number> right,
                                                       Label* if_true) {
  Label if_false(this);
  BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual, left,
                                     right, if_true, &if_false);
  BIND(&if_false);
}

namespace {
Operation Reverse(Operation op) {
  switch (op) {
    case Operation::kLessThan:
      return Operation::kGreaterThan;
    case Operation::kLessThanOrEqual:
      return Operation::kGreaterThanOrEqual;
    case Operation::kGreaterThan:
      return Operation::kLessThan;
    case Operation::kGreaterThanOrEqual:
      return Operation::kLessThanOrEqual;
    default:
      break;
  }
  UNREACHABLE();
}
}  // anonymous namespace

TNode<Context> CodeStubAssembler::GotoIfHasContextExtensionUpToDepth(
    TNode<Context> context, TNode<Uint32T> depth, Label* target) {
  TVARIABLE(Context, cur_context, context);
  TVARIABLE(Uint32T, cur_depth, depth);

  Label context_search(this, {&cur_depth, &cur_context});
  Label exit_loop(this);
  Label no_extension(this);

  // Loop until the depth is 0.
  CSA_DCHECK(this, Word32NotEqual(cur_depth.value(), Int32Constant(0)));
  Goto(&context_search);
  BIND(&context_search);
  {
#if DEBUG
    // Const tracking let data is stored in the extension slot of a
    // ScriptContext - however, it's unrelated to the sloppy eval variable
    // extension. We should never iterate through a ScriptContext here.
    auto scope_info = LoadScopeInfo(cur_context.value());
    TNode<Uint32T> flags =
        LoadObjectField<Uint32T>(scope_info, ScopeInfo::kFlagsOffset);
    auto scope_type = DecodeWord32<ScopeInfo::ScopeTypeBits>(flags);
    CSA_DCHECK(this, Word32NotEqual(scope_type,
                                    Int32Constant(ScopeType::SCRIPT_SCOPE)));
    CSA_DCHECK(this, Word32NotEqual(scope_type,
                                    Int32Constant(ScopeType::REPL_MODE_SCOPE)));
#endif

    // Check if context has an extension slot.
    TNode<BoolT> has_extension =
        LoadScopeInfoHasExtensionField(LoadScopeInfo(cur_context.value()));
    GotoIfNot(has_extension, &no_extension);

    // Jump to the target if the extension slot is not an undefined value.
    TNode<Object> extension_slot =
        LoadContextElement(cur_context.value(), Context::EXTENSION_INDEX);
    Branch(TaggedNotEqual(extension_slot, UndefinedConstant()), target,
           &no_extension);

    BIND(&no_extension);
    {
      cur_depth = Unsigned(Int32Sub(cur_depth.value(), Int32Constant(1)));
      cur_context = CAST(
          LoadContextElement(cur_context.value(), Context::PREVIOUS_INDEX));

      Branch(Word32NotEqual(cur_depth.value(), Int32Constant(0)),
             &context_search, &exit_loop);
    }
  }
  BIND(&exit_loop);
  return cur_context.value();
}

void CodeStubAssembler::BigInt64Comparison(Operation op, TNode<Object>& left,
                                           TNode<Object>& right,
                                           Label* return_true,
                                           Label* return_false) {
  TVARIABLE(UintPtrT, left_raw);
  TVARIABLE(UintPtrT, right_raw);
  BigIntToRawBytes(CAST(left), &left_raw, &left_raw);
  BigIntToRawBytes(CAST(right), &right_raw, &right_raw);
  TNode<WordT> left_raw_value = left_raw.value();
  TNode<WordT> right_raw_value = right_raw.value();

  TNode<BoolT> condition;
  switch (op) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      condition = WordEqual(left_raw_value, right_raw_value);
      break;
    case Operation::kLessThan:
      condition = IntPtrLessThan(left_raw_value, right_raw_value);
      break;
    case Operation::kLessThanOrEqual:
      condition = IntPtrLessThanOrEqual(left_raw_value, right_raw_value);
      break;
    case Operation::kGreaterThan:
      condition = IntPtrGreaterThan(left_raw_value, right_raw_value);
      break;
    case Operation::kGreaterThanOrEqual:
      condition = IntPtrGreaterThanOrEqual(left_raw_value, right_raw_value);
      break;
    default:
      UNREACHABLE();
  }
  Branch(condition, return_true, return_false);
}

TNode<Boolean> CodeStubAssembler::RelationalComparison(
    Operation op, TNode<Object> left, TNode<Object> right,
    const LazyNode<Context>& context, TVariable<Smi>* var_type_feedback) {
  Label return_true(this), return_false(this), do_float_comparison(this),
      end(this);
  TVARIABLE(Boolean, var_result);
  TVARIABLE(Float64T, var_left_float);
  TVARIABLE(Float64T, var_right_float);

  // We might need to loop several times due to ToPrimitive and/or ToNumeric
  // conversions.
  TVARIABLE(Object, var_left, left);
  TVARIABLE(Object, var_right, right);
  VariableList loop_variable_list({&var_left, &var_right}, zone());
  if (var_type_feedback != nullptr) {
    // Initialize the type feedback to None. The current feedback is combined
    // with the previous feedback.
    *var_type_feedback = SmiConstant(CompareOperationFeedback::kNone);
    loop_variable_list.push_back(var_type_feedback);
  }
  Label loop(this, loop_variable_list);
  Goto(&loop);
  BIND(&loop);
  {
    left = var_left.value();
    right = var_right.value();

    Label if_left_smi(this), if_left_not_smi(this);
    Branch(TaggedIsSmi(left), &if_left_smi, &if_left_not_smi);

    BIND(&if_left_smi);
    {
      TNode<Smi> smi_left = CAST(left);
      Label if_right_smi(this), if_right_heapnumber(this),
          if_right_bigint(this, Label::kDeferred),
          if_right_not_numeric(this, Label::kDeferred);
      GotoIf(TaggedIsSmi(right), &if_right_smi);
      TNode<Map> right_map = LoadMap(CAST(right));
      GotoIf(IsHeapNumberMap(right_map), &if_right_heapnumber);
      TNode<Uint16T> right_instance_type = LoadMapInstanceType(right_map);
      Branch(IsBigIntInstanceType(right_instance_type), &if_right_bigint,
             &if_right_not_numeric);

      BIND(&if_right_smi);
      {
        TNode<Smi> smi_right = CAST(right);
        CombineFeedback(var_type_feedback,
                        CompareOperationFeedback::kSignedSmall);
        switch (op) {
          case Operation::kLessThan:
            BranchIfSmiLessThan(smi_left, smi_right, &return_true,
                                &return_false);
            break;
          case Operation::kLessThanOrEqual:
            BranchIfSmiLessThanOrEqual(smi_left, smi_right, &return_true,
                                       &return_false);
            break;
          case Operation::kGreaterThan:
            BranchIfSmiLessThan(smi_right, smi_left, &return_true,
                                &return_false);
            break;
          case Operation::kGreaterThanOrEqual:
            BranchIfSmiLessThanOrEqual(smi_right, smi_left, &return_true,
                                       &return_false);
            break;
          default:
            UNREACHABLE();
        }
      }

      BIND(&if_right_heapnumber);
      {
        CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
        var_left_float = SmiToFloat64(smi_left);
        var_right_float = LoadHeapNumberValue(CAST(right));
        Goto(&do_float_comparison);
      }

      BIND(&if_right_bigint);
      {
        OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kAny);
        var_result = CAST(CallRuntime(Runtime::kBigIntCompareToNumber,
                                      NoContextConstant(),
                                      SmiConstant(Reverse(op)), right, left));
        Goto(&end);
      }

      BIND(&if_right_not_numeric);
      {
        OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kAny);
        // Convert {right} to a Numeric; we don't need to perform the
        // dedicated ToPrimitive(right, hint Number) operation, as the
        // ToNumeric(right) will by itself already invoke ToPrimitive with
        // a Number hint.
        var_right = CallBuiltin(Builtin::kNonNumberToNumeric, context(), right);
        Goto(&loop);
      }
    }

    BIND(&if_left_not_smi);
    {
      TNode<Map> left_map = LoadMap(CAST(left));

      Label if_right_smi(this), if_right_not_smi(this);
      Branch(TaggedIsSmi(right), &if_right_smi, &if_right_not_smi);

      BIND(&if_right_smi);
      {
        Label if_left_heapnumber(this), if_left_bigint(this, Label::kDeferred),
            if_left_not_numeric(this, Label::kDeferred);
        GotoIf(IsHeapNumberMap(left_map), &if_left_heapnumber);
        TNode<Uint16T> left_instance_type = LoadMapInstanceType(left_map);
        Branch(IsBigIntInstanceType(left_instance_type), &if_left_bigint,
               &if_left_not_numeric);

        BIND(&if_left_heapnumber);
        {
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
          var_left_float = LoadHeapNumberValue(CAST(left));
          var_right_float = SmiToFloat64(CAST(right));
          Goto(&do_float_comparison);
        }

        BIND(&if_left_bigint);
        {
          OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kAny);
          var_result = CAST(CallRuntime(Runtime::kBigIntCompareToNumber,
                                        NoContextConstant(), SmiConstant(op),
                                        left, right));
          Goto(&end);
        }

        BIND(&if_left_not_numeric);
        {
          OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kAny);
          // Convert {left} to a Numeric; we don't need to perform the
          // dedicated ToPrimitive(left, hint
```