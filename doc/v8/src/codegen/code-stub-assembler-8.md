Response: The user wants a summary of the C++ code in `v8/src/codegen/code-stub-assembler.cc`, specifically part 9 of 12. The summary should focus on its functionality and its relation to JavaScript, with JavaScript examples if applicable.

Here's a breakdown of the code's content and my thought process to arrive at the summary:

1. **`ElementsKind` Transition:** The initial part of the code deals with changing the `ElementsKind` of a JavaScript object. This involves checking for allocation mementos and potentially growing the object's elements array. This directly relates to how JavaScript arrays and objects store their elements and how V8 optimizes these storage mechanisms.

2. **`TrapAllocationMemento`:** This function checks if an object has an allocation memento. Allocation mementos are used for tracking object allocation sites, which is important for performance optimizations and potentially for debugging or profiling. This is an internal V8 mechanism not directly exposed in JavaScript but influences its performance.

3. **Memory Management Functions:**  Functions like `MemoryChunkFromAddress`, `PageMetadataFromMemoryChunk`, and `PageMetadataFromAddress` deal with V8's internal memory management structures. These are low-level operations not directly visible in JavaScript but crucial for V8's operation.

4. **`CreateAllocationSiteInFeedbackVector`:** This function creates an `AllocationSite` and links it into a feedback vector. `AllocationSite`s store information about where objects are allocated, and feedback vectors are used by V8's optimizing compiler (TurboFan) to make informed decisions about code optimization. This has a significant impact on JavaScript performance.

5. **`StoreWeakReferenceInFeedbackVector`:** This function stores a weak reference to an object in a feedback vector. Weak references are a way to hold a reference to an object without preventing it from being garbage collected. This is an advanced topic but can affect memory management in JavaScript applications in subtle ways, although it's more common in native addons.

6. **`HasBoilerplate`, `LoadTransitionInfo`, `LoadBoilerplate`, `LoadElementsKind`, `LoadNestedAllocationSite`:** These functions access information stored within `AllocationSite` objects. This information is used by V8's runtime and optimizing compiler.

7. **`BuildFastLoop`:** This is a templated function for creating optimized loops in the assembler. It allows for loop unrolling and different ways of incrementing the loop index. This is a performance-critical component of the code, used to generate efficient machine code for JavaScript loops.

8. **`BuildFastArrayForEach`:** This function provides a way to iterate over elements in a fast array (either `FixedArray` or `PropertyArray`). It handles different element kinds and loop directions. This directly supports efficient iteration over JavaScript arrays.

9. **`GotoIfFixedArraySizeDoesntFitInNewSpace`:** This function checks if the size of a `FixedArray` exceeds the available space in the "new space" heap. New space is where newly allocated objects reside, and this check is related to V8's generational garbage collection.

10. **`InitializeFieldsWithRoot`:** This function initializes fields of a heap object with a specific root value. This is a low-level operation used during object creation and initialization.

11. **Number Relational Comparisons (`BranchIfNumberRelationalComparison`, `GotoIfNumberGreaterThanOrEqual`):** These functions handle comparisons between JavaScript numbers, including Smis and HeapNumbers. They deal with the intricacies of JavaScript's type coercion and NaN handling during comparisons.

12. **Context Extension Search (`GotoIfHasContextExtensionUpToDepth`):** This function searches up the context chain for a context with an extension. This is related to how JavaScript's scope and variable resolution work, especially with `eval`.

13. **BigInt Comparisons (`BigInt64Comparison`):** This function implements comparisons for 64-bit BigInts. BigInts are a relatively recent addition to JavaScript.

14. **General Relational Comparison (`RelationalComparison`):** This is a complex function handling all sorts of JavaScript relational comparisons (`<`, `>`, `<=`, `>=`). It deals with type coercion, primitive conversion, and specific handling for numbers, strings, and BigInts.

15. **Equality Comparisons (`GenerateEqual_Same`, `Equal`, `StrictEqual`):** These functions implement JavaScript's abstract (`==`) and strict (`===`) equality comparisons. They handle type coercion (for `==`), NaN, and different object types.

Based on this analysis, I can now formulate a summary that covers the key functionalities and their connections to JavaScript, providing illustrative JavaScript examples where appropriate. The focus will be on the areas that have a more direct and understandable link to JavaScript behavior.

这个C++代码文件（`code-stub-assembler.cc`）是V8 JavaScript引擎中CodeStubAssembler的一部分，主要负责**生成用于执行特定JavaScript操作的底层机器码（代码桩）**。这是V8编译流水线中的一个关键组件，用于构建高效的运行时代码。

**第9部分主要关注以下功能：**

1. **对象元素类型（ElementsKind）转换和内存管理：**
   - 提供了将JS对象的元素存储类型从一种 `ElementsKind` 转换为另一种的方法（例如，从 `PACKED_SMI_ELEMENTS` 转换为 `PACKED_ELEMENTS`）。
   - 在转换过程中，它会检查是否需要分配更大的内存空间来存储新的元素，并执行必要的内存扩展操作（`GrowElementsCapacity`）。
   - 涉及到 `AllocationSite` 的跟踪，这对于V8的性能优化（例如，对象预分配和内联缓存）至关重要。
   - `TrapAllocationMemento` 函数用于检测对象是否附加了分配备忘录，这与对象的生命周期和垃圾回收有关。
   - 提供了一些底层的内存管理辅助函数，如 `MemoryChunkFromAddress` 和 `PageMetadataFromMemoryChunk`，用于在V8的堆内存结构中导航。

2. **反馈向量和分配站点的管理：**
   - 提供了创建和管理 `AllocationSite` 的功能（`CreateAllocationSiteInFeedbackVector`）。`AllocationSite` 记录了对象分配的位置和类型信息，用于类型反馈优化。
   - 可以将对象的弱引用存储在反馈向量中（`StoreWeakReferenceInFeedbackVector`），这允许在不阻止对象被垃圾回收的情况下跟踪它们。
   - 提供了加载 `AllocationSite` 中各种信息的方法，例如是否有所谓的“样板”（`HasBoilerplate`）、转换信息（`LoadTransitionInfo`）、样板本身（`LoadBoilerplate`）、元素类型（`LoadElementsKind`）和嵌套的分配站点（`LoadNestedAllocationSite`）。

3. **构建快速循环的工具：**
   - 提供了通用的 `BuildFastLoop` 模板函数，用于在生成的机器码中创建高效的循环结构。这个函数支持循环展开等优化技术。
   - 针对数组遍历提供了 `BuildFastArrayForEach` 函数，能够高效地遍历不同类型的快速数组。

4. **内存分配判断：**
   - `GotoIfFixedArraySizeDoesntFitInNewSpace` 函数用于判断指定大小的 `FixedArray` 是否能容纳在新生代（new space）中。

5. **字段初始化：**
   - `InitializeFieldsWithRoot` 函数用于将对象的多个字段初始化为特定的根对象（例如，填充器）。

6. **数字比较：**
   - 提供了处理JavaScript中数字关系比较的函数 (`BranchIfNumberRelationalComparison`, `GotoIfNumberGreaterThanOrEqual`)，包括Smi（小整数）和HeapNumber（堆分配的数字）的比较。

7. **上下文扩展搜索：**
   - `GotoIfHasContextExtensionUpToDepth` 函数用于在作用域链中向上查找具有扩展对象的上下文。这与 `with` 语句和 `eval` 函数的作用域处理有关。

8. **BigInt比较：**
   - 提供了用于比较BigInt（任意精度整数）的函数 (`BigInt64Comparison`)。

9. **关系和相等性比较：**
   - 实现了JavaScript中各种关系比较运算符（`<`、`>`、`<=`、`>=`）的逻辑 (`RelationalComparison`)，包括类型转换和各种类型的处理（数字、字符串、BigInt等）。
   - 实现了抽象相等 (`==`) 和严格相等 (`===`) 运算符的逻辑 (`Equal`, `StrictEqual`)，处理了各种类型之间的比较规则，包括类型转换和 NaN 的特殊情况。

**与JavaScript的功能关系和示例：**

这个文件中的代码直接对应于JavaScript引擎在底层执行某些操作的方式。虽然开发者通常不会直接接触到这些C++代码，但它的行为决定了JavaScript代码的执行效率和语义。

**示例：对象元素类型转换**

```javascript
const arr = [1, 2, 3]; // 初始可能是 PACKED_SMI_ELEMENTS

arr.push("hello"); // 可能会触发元素类型转换为 PACKED_ELEMENTS
```

在上面的例子中，当向一个只包含整数的数组 `arr` 中添加一个字符串时，V8 需要更改数组的内部存储方式以容纳不同类型的元素。 `CodeStubAssembler` 中的相关代码就负责生成执行这种转换的机器码。

**示例：分配站点和类型反馈**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

const p1 = new Point(1, 2);
const p2 = new Point(3, 4);
```

当多次创建 `Point` 类型的对象时，V8会记录这些对象的分配信息（通过 `AllocationSite`）。这些信息用于类型反馈，帮助V8的优化编译器判断 `Point` 对象的属性类型，从而生成更高效的代码。 `CreateAllocationSiteInFeedbackVector` 等函数就参与了这个过程。

**示例：数字比较**

```javascript
const a = 10;
const b = 5;

if (a > b) {
  console.log("a is greater than b");
}
```

`BranchIfNumberRelationalComparison` 和 `GotoIfNumberGreaterThanOrEqual` 等函数会生成用于执行 `a > b` 比较的机器码。V8需要区分 `a` 和 `b` 是 Smi 还是 HeapNumber，并根据不同的类型执行相应的比较操作。

**示例：相等性比较**

```javascript
const x = 5;
const y = "5";

console.log(x == y); // true (抽象相等，会进行类型转换)
console.log(x === y); // false (严格相等，不会进行类型转换)
```

`Equal` 和 `StrictEqual` 函数生成的机器码负责实现 `==` 和 `===` 这两种不同的相等性比较规则。

总而言之，这个代码文件的功能是为V8引擎的运行时生成高效的、底层的机器码，以支持各种JavaScript操作，尤其是在对象管理、内存操作、循环控制和类型比较等方面。它是JavaScript引擎高效执行的核心组成部分。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第9部分，共12部分，请归纳一下它的功能

"""
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
          // dedicated ToPrimitive(left, hint Number) operation, as the
          // ToNumeric(left) will by itself already invoke ToPrimitive with
          // a Number hint.
          var_left = CallBuiltin(Builtin::kNonNumberToNumeric, context(), left);
          Goto(&loop);
        }
      }

      BIND(&if_right_not_smi);
      {
        TNode<Map> right_map = LoadMap(CAST(right));

        Label if_left_heapnumber(this), if_left_bigint(this, Label::kDeferred),
            if_left_string(this, Label::kDeferred),
            if_left_other(this, Label::kDeferred);
        GotoIf(IsHeapNumberMap(left_map), &if_left_heapnumber);
        TNode<Uint16T> left_instance_type = LoadMapInstanceType(left_map);
        GotoIf(IsBigIntInstanceType(left_instance_type), &if_left_bigint);
        Branch(IsStringInstanceType(left_instance_type), &if_left_string,
               &if_left_other);

        BIND(&if_left_heapnumber);
        {
          Label if_right_heapnumber(this),
              if_right_bigint(this, Label::kDeferred),
              if_right_not_numeric(this, Label::kDeferred);
          GotoIf(TaggedEqual(right_map, left_map), &if_right_heapnumber);
          TNode<Uint16T> right_instance_type = LoadMapInstanceType(right_map);
          Branch(IsBigIntInstanceType(right_instance_type), &if_right_bigint,
                 &if_right_not_numeric);

          BIND(&if_right_heapnumber);
          {
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kNumber);
            var_left_float = LoadHeapNumberValue(CAST(left));
            var_right_float = LoadHeapNumberValue(CAST(right));
            Goto(&do_float_comparison);
          }

          BIND(&if_right_bigint);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            var_result = CAST(CallRuntime(
                Runtime::kBigIntCompareToNumber, NoContextConstant(),
                SmiConstant(Reverse(op)), right, left));
            Goto(&end);
          }

          BIND(&if_right_not_numeric);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            // Convert {right} to a Numeric; we don't need to perform
            // dedicated ToPrimitive(right, hint Number) operation, as the
            // ToNumeric(right) will by itself already invoke ToPrimitive with
            // a Number hint.
            var_right =
                CallBuiltin(Builtin::kNonNumberToNumeric, context(), right);
            Goto(&loop);
          }
        }

        BIND(&if_left_bigint);
        {
          Label if_right_heapnumber(this), if_right_bigint(this),
              if_right_string(this), if_right_other(this);
          GotoIf(IsHeapNumberMap(right_map), &if_right_heapnumber);
          TNode<Uint16T> right_instance_type = LoadMapInstanceType(right_map);
          GotoIf(IsBigIntInstanceType(right_instance_type), &if_right_bigint);
          Branch(IsStringInstanceType(right_instance_type), &if_right_string,
                 &if_right_other);

          BIND(&if_right_heapnumber);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            var_result = CAST(CallRuntime(Runtime::kBigIntCompareToNumber,
                                          NoContextConstant(), SmiConstant(op),
                                          left, right));
            Goto(&end);
          }

          BIND(&if_right_bigint);
          {
            if (Is64()) {
              Label if_both_bigint(this);
              GotoIfLargeBigInt(CAST(left), &if_both_bigint);
              GotoIfLargeBigInt(CAST(right), &if_both_bigint);

              CombineFeedback(var_type_feedback,
                              CompareOperationFeedback::kBigInt64);
              BigInt64Comparison(op, left, right, &return_true, &return_false);
              BIND(&if_both_bigint);
            }

            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kBigInt);
            var_result = CAST(CallBuiltin(BigIntComparisonBuiltinOf(op),
                                          NoContextConstant(), left, right));
            Goto(&end);
          }

          BIND(&if_right_string);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            var_result = CAST(CallRuntime(Runtime::kBigIntCompareToString,
                                          NoContextConstant(), SmiConstant(op),
                                          left, right));
            Goto(&end);
          }

          // {right} is not a Number, BigInt, or String.
          BIND(&if_right_other);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            // Convert {right} to a Numeric; we don't need to perform
            // dedicated ToPrimitive(right, hint Number) operation, as the
            // ToNumeric(right) will by itself already invoke ToPrimitive with
            // a Number hint.
            var_right =
                CallBuiltin(Builtin::kNonNumberToNumeric, context(), right);
            Goto(&loop);
          }
        }

        BIND(&if_left_string);
        {
          TNode<Uint16T> right_instance_type = LoadMapInstanceType(right_map);

          Label if_right_not_string(this, Label::kDeferred);
          GotoIfNot(IsStringInstanceType(right_instance_type),
                    &if_right_not_string);

          // Both {left} and {right} are strings.
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kString);
          Builtin builtin;
          switch (op) {
            case Operation::kLessThan:
              builtin = Builtin::kStringLessThan;
              break;
            case Operation::kLessThanOrEqual:
              builtin = Builtin::kStringLessThanOrEqual;
              break;
            case Operation::kGreaterThan:
              builtin = Builtin::kStringGreaterThan;
              break;
            case Operation::kGreaterThanOrEqual:
              builtin = Builtin::kStringGreaterThanOrEqual;
              break;
            default:
              UNREACHABLE();
          }
          var_result = CAST(CallBuiltin(builtin, TNode<Object>(), left, right));
          Goto(&end);

          BIND(&if_right_not_string);
          {
            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            // {left} is a String, while {right} isn't. Check if {right} is
            // a BigInt, otherwise call ToPrimitive(right, hint Number) if
            // {right} is a receiver, or ToNumeric(left) and then
            // ToNumeric(right) in the other cases.
            static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
            Label if_right_bigint(this),
                if_right_receiver(this, Label::kDeferred);
            GotoIf(IsBigIntInstanceType(right_instance_type), &if_right_bigint);
            GotoIf(IsJSReceiverInstanceType(right_instance_type),
                   &if_right_receiver);

            var_left =
                CallBuiltin(Builtin::kNonNumberToNumeric, context(), left);
            var_right = CallBuiltin(Builtin::kToNumeric, context(), right);
            Goto(&loop);

            BIND(&if_right_bigint);
            {
              var_result = CAST(CallRuntime(
                  Runtime::kBigIntCompareToString, NoContextConstant(),
                  SmiConstant(Reverse(op)), right, left));
              Goto(&end);
            }

            BIND(&if_right_receiver);
            {
              Builtin builtin =
                  Builtins::NonPrimitiveToPrimitive(ToPrimitiveHint::kNumber);
              var_right = CallBuiltin(builtin, context(), right);
              Goto(&loop);
            }
          }
        }

        BIND(&if_left_other);
        {
          // {left} is neither a Numeric nor a String, and {right} is not a Smi.
          if (var_type_feedback != nullptr) {
            // Collect NumberOrOddball feedback if {left} is an Oddball
            // and {right} is either a HeapNumber or Oddball. Otherwise collect
            // Any feedback.
            Label collect_any_feedback(this), collect_oddball_feedback(this),
                collect_feedback_done(this);
            GotoIfNot(InstanceTypeEqual(left_instance_type, ODDBALL_TYPE),
                      &collect_any_feedback);

            GotoIf(IsHeapNumberMap(right_map), &collect_oddball_feedback);
            TNode<Uint16T> right_instance_type = LoadMapInstanceType(right_map);
            Branch(InstanceTypeEqual(right_instance_type, ODDBALL_TYPE),
                   &collect_oddball_feedback, &collect_any_feedback);

            BIND(&collect_oddball_feedback);
            {
              CombineFeedback(var_type_feedback,
                              CompareOperationFeedback::kNumberOrOddball);
              Goto(&collect_feedback_done);
            }

            BIND(&collect_any_feedback);
            {
              OverwriteFeedback(var_type_feedback,
                                CompareOperationFeedback::kAny);
              Goto(&collect_feedback_done);
            }

            BIND(&collect_feedback_done);
          }

          // If {left} is a receiver, call ToPrimitive(left, hint Number).
          // Otherwise call ToNumeric(right) and then ToNumeric(left), the
          // order here is important as it's observable by user code.
          static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
          Label if_left_receiver(this, Label::kDeferred);
          GotoIf(IsJSReceiverInstanceType(left_instance_type),
                 &if_left_receiver);

          var_right = CallBuiltin(Builtin::kToNumeric, context(), right);
          var_left = CallBuiltin(Builtin::kNonNumberToNumeric, context(), left);
          Goto(&loop);

          BIND(&if_left_receiver);
          {
            Builtin builtin =
                Builtins::NonPrimitiveToPrimitive(ToPrimitiveHint::kNumber);
            var_left = CallBuiltin(builtin, context(), left);
            Goto(&loop);
          }
        }
      }
    }
  }

  BIND(&do_float_comparison);
  {
    switch (op) {
      case Operation::kLessThan:
        Branch(Float64LessThan(var_left_float.value(), var_right_float.value()),
               &return_true, &return_false);
        break;
      case Operation::kLessThanOrEqual:
        Branch(Float64LessThanOrEqual(var_left_float.value(),
                                      var_right_float.value()),
               &return_true, &return_false);
        break;
      case Operation::kGreaterThan:
        Branch(
            Float64GreaterThan(var_left_float.value(), var_right_float.value()),
            &return_true, &return_false);
        break;
      case Operation::kGreaterThanOrEqual:
        Branch(Float64GreaterThanOrEqual(var_left_float.value(),
                                         var_right_float.value()),
               &return_true, &return_false);
        break;
      default:
        UNREACHABLE();
    }
  }

  BIND(&return_true);
  {
    var_result = TrueConstant();
    Goto(&end);
  }

  BIND(&return_false);
  {
    var_result = FalseConstant();
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Smi> CodeStubAssembler::CollectFeedbackForString(
    TNode<Int32T> instance_type) {
  TNode<Smi> feedback = SelectSmiConstant(
      Word32Equal(
          Word32And(instance_type, Int32Constant(kIsNotInternalizedMask)),
          Int32Constant(kInternalizedTag)),
      CompareOperationFeedback::kInternalizedString,
      CompareOperationFeedback::kString);
  return feedback;
}

void CodeStubAssembler::GenerateEqual_Same(TNode<Object> value, Label* if_equal,
                                           Label* if_notequal,
                                           TVariable<Smi>* var_type_feedback) {
  // In case of abstract or strict equality checks, we need additional checks
  // for NaN values because they are not considered equal, even if both the
  // left and the right hand side reference exactly the same value.

  Label if_smi(this), if_heapnumber(this);
  GotoIf(TaggedIsSmi(value), &if_smi);

  TNode<HeapObject> value_heapobject = CAST(value);
  TNode<Map> value_map = LoadMap(value_heapobject);
  GotoIf(IsHeapNumberMap(value_map), &if_heapnumber);

  // For non-HeapNumbers, all we do is collect type feedback.
  if (var_type_feedback != nullptr) {
    TNode<Uint16T> instance_type = LoadMapInstanceType(value_map);

    Label if_string(this), if_receiver(this), if_oddball(this), if_symbol(this),
        if_bigint(this);
    GotoIf(IsStringInstanceType(instance_type), &if_string);
    GotoIf(IsJSReceiverInstanceType(instance_type), &if_receiver);
    GotoIf(IsOddballInstanceType(instance_type), &if_oddball);
    Branch(IsBigIntInstanceType(instance_type), &if_bigint, &if_symbol);

    BIND(&if_string);
    {
      CSA_DCHECK(this, IsString(value_heapobject));
      CombineFeedback(var_type_feedback,
                      CollectFeedbackForString(instance_type));
      Goto(if_equal);
    }

    BIND(&if_symbol);
    {
      CSA_DCHECK(this, IsSymbol(value_heapobject));
      CombineFeedback(var_type_feedback, CompareOperationFeedback::kSymbol);
      Goto(if_equal);
    }

    BIND(&if_receiver);
    {
      CSA_DCHECK(this, IsJSReceiver(value_heapobject));
      CombineFeedback(var_type_feedback, CompareOperationFeedback::kReceiver);
      Goto(if_equal);
    }

    BIND(&if_bigint);
    {
      CSA_DCHECK(this, IsBigInt(value_heapobject));

      if (Is64()) {
        Label if_large_bigint(this);
        GotoIfLargeBigInt(CAST(value_heapobject), &if_large_bigint);
        CombineFeedback(var_type_feedback, CompareOperationFeedback::kBigInt64);
        Goto(if_equal);
        BIND(&if_large_bigint);
      }
      CombineFeedback(var_type_feedback, CompareOperationFeedback::kBigInt);
      Goto(if_equal);
    }

    BIND(&if_oddball);
    {
      CSA_DCHECK(this, IsOddball(value_heapobject));
      Label if_boolean(this), if_not_boolean(this);
      Branch(IsBooleanMap(value_map), &if_boolean, &if_not_boolean);

      BIND(&if_boolean);
      {
        CombineFeedback(var_type_feedback, CompareOperationFeedback::kBoolean);
        Goto(if_equal);
      }

      BIND(&if_not_boolean);
      {
        CSA_DCHECK(this, IsNullOrUndefined(value_heapobject));
        CombineFeedback(var_type_feedback,
                        CompareOperationFeedback::kReceiverOrNullOrUndefined);
        Goto(if_equal);
      }
    }
  } else {
    Goto(if_equal);
  }

  BIND(&if_heapnumber);
  {
    CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
    TNode<Float64T> number_value = LoadHeapNumberValue(value_heapobject);
    BranchIfFloat64IsNaN(number_value, if_notequal, if_equal);
  }

  BIND(&if_smi);
  {
    CombineFeedback(var_type_feedback, CompareOperationFeedback::kSignedSmall);
    Goto(if_equal);
  }
}

// ES6 section 7.2.12 Abstract Equality Comparison
TNode<Boolean> CodeStubAssembler::Equal(TNode<Object> left, TNode<Object> right,
                                        const LazyNode<Context>& context,
                                        TVariable<Smi>* var_type_feedback) {
  // This is a slightly optimized version of Object::Equals. Whenever you
  // change something functionality wise in here, remember to update the
  // Object::Equals method as well.

  Label if_equal(this), if_notequal(this), do_float_comparison(this),
      do_right_stringtonumber(this, Label::kDeferred), end(this);
  TVARIABLE(Boolean, result);
  TVARIABLE(Float64T, var_left_float);
  TVARIABLE(Float64T, var_right_float);

  // We can avoid code duplication by exploiting the fact that abstract equality
  // is symmetric.
  Label use_symmetry(this);

  // We might need to loop several times due to ToPrimitive and/or ToNumber
  // conversions.
  TVARIABLE(Object, var_left, left);
  TVARIABLE(Object, var_right, right);
  VariableList loop_variable_list({&var_left, &var_right}, zone());
  if (var_type_feedback != nullptr) {
    // Initialize the type feedback to None. The current feedback will be
    // combined with the previous feedback.
    OverwriteFeedback(var_type_feedback, CompareOperationFeedback::kNone);
    loop_variable_list.push_back(var_type_feedback);
  }
  Label loop(this, loop_variable_list);
  Goto(&loop);
  BIND(&loop);
  {
    left = var_left.value();
    right = var_right.value();

    Label if_notsame(this);
    GotoIf(TaggedNotEqual(left, right), &if_notsame);
    {
      // {left} and {right} reference the exact same value, yet we need special
      // treatment for HeapNumber, as NaN is not equal to NaN.
      GenerateEqual_Same(left, &if_equal, &if_notequal, var_type_feedback);
    }

    BIND(&if_notsame);
    Label if_left_smi(this), if_left_not_smi(this);
    Branch(TaggedIsSmi(left), &if_left_smi, &if_left_not_smi);

    BIND(&if_left_smi);
    {
      Label if_right_smi(this), if_right_not_smi(this);
      CombineFeedback(var_type_feedback,
                      CompareOperationFeedback::kSignedSmall);
      Branch(TaggedIsSmi(right), &if_right_smi, &if_right_not_smi);

      BIND(&if_right_smi);
      {
        // We have already checked for {left} and {right} being the same value,
        // so when we get here they must be different Smis.
        Goto(&if_notequal);
      }

      BIND(&if_right_not_smi);
      {
        TNode<Map> right_map = LoadMap(CAST(right));
        Label if_right_heapnumber(this), if_right_oddball(this),
            if_right_bigint(this, Label::kDeferred),
            if_right_receiver(this, Label::kDeferred);
        GotoIf(IsHeapNumberMap(right_map), &if_right_heapnumber);

        // {left} is Smi and {right} is not HeapNumber or Smi.
        TNode<Uint16T> right_type = LoadMapInstanceType(right_map);
        GotoIf(IsStringInstanceType(right_type), &do_right_stringtonumber);
        GotoIf(IsOddballInstanceType(right_type), &if_right_oddball);
        GotoIf(IsBigIntInstanceType(right_type), &if_right_bigint);
        GotoIf(IsJSReceiverInstanceType(right_type), &if_right_receiver);
        CombineFeedback(var_type_feedback, CompareOperationFeedback::kAny);
        Goto(&if_notequal);

        BIND(&if_right_heapnumber);
        {
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
          var_left_float = SmiToFloat64(CAST(left));
          var_right_float = LoadHeapNumberValue(CAST(right));
          Goto(&do_float_comparison);
        }

        BIND(&if_right_oddball);
        {
          Label if_right_boolean(this);
          GotoIf(IsBooleanMap(right_map), &if_right_boolean);
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kOddball);
          Goto(&if_notequal);

          BIND(&if_right_boolean);
          {
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kBoolean);
            var_right =
                LoadObjectField(CAST(right), offsetof(Oddball, to_number_));
            Goto(&loop);
          }
        }

        BIND(&if_right_bigint);
        {
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kBigInt);
          result = CAST(CallRuntime(Runtime::kBigIntEqualToNumber,
                                    NoContextConstant(), right, left));
          Goto(&end);
        }

        BIND(&if_right_receiver);
        {
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kReceiver);
          var_right = CallBuiltin(Builtins::NonPrimitiveToPrimitive(),
                                  context(), right);
          Goto(&loop);
        }
      }
    }

    BIND(&if_left_not_smi);
    {
      GotoIf(TaggedIsSmi(right), &use_symmetry);

      Label if_left_symbol(this), if_left_number(this),
          if_left_string(this, Label::kDeferred),
          if_left_bigint(this, Label::kDeferred), if_left_oddball(this),
          if_left_receiver(this);

      TNode<Map> left_map = LoadMap(CAST(left));
      TNode<Map> right_map = LoadMap(CAST(right));
      TNode<Uint16T> left_type = LoadMapInstanceType(left_map);
      TNode<Uint16T> right_type = LoadMapInstanceType(right_map);

      GotoIf(IsStringInstanceType(left_type), &if_left_string);
      GotoIf(IsSymbolInstanceType(left_type), &if_left_symbol);
      GotoIf(IsHeapNumberInstanceType(left_type), &if_left_number);
      GotoIf(IsOddballInstanceType(left_type), &if_left_oddball);
      Branch(IsBigIntInstanceType(left_type), &if_left_bigint,
             &if_left_receiver);

      BIND(&if_left_string);
      {
        GotoIfNot(IsStringInstanceType(right_type), &use_symmetry);
        Label combine_feedback(this);
        BranchIfStringEqual(CAST(left), CAST(right), &combine_feedback,
                            &combine_feedback, &result);
        BIND(&combine_feedback);
        {
          CombineFeedback(var_type_feedback,
                          SmiOr(CollectFeedbackForString(left_type),
                                CollectFeedbackForString(right_type)));
          Goto(&end);
        }
      }

      BIND(&if_left_number);
      {
        Label if_right_not_number(this);

        CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
        GotoIf(Word32NotEqual(left_type, right_type), &if_right_not_number);

        var_left_float = LoadHeapNumberValue(CAST(left));
        var_right_float = LoadHeapNumberValue(CAST(right));
        Goto(&do_float_comparison);

        BIND(&if_right_not_number);
        {
          Label if_right_oddball(this);

          GotoIf(IsStringInstanceType(right_type), &do_right_stringtonumber);
          GotoIf(IsOddballInstanceType(right_type), &if_right_oddball);
          GotoIf(IsBigIntInstanceType(right_type), &use_symmetry);
          GotoIf(IsJSReceiverInstanceType(right_type), &use_symmetry);
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kAny);
          Goto(&if_notequal);

          BIND(&if_right_oddball);
          {
            Label if_right_boolean(this);
            GotoIf(IsBooleanMap(right_map), &if_right_boolean);
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kOddball);
            Goto(&if_notequal);

            BIND(&if_right_boolean);
            {
              CombineFeedback(var_type_feedback,
                              CompareOperationFeedback::kBoolean);
              var_right =
                  LoadObjectField(CAST(right), offsetof(Oddball, to_number_));
              Goto(&loop);
            }
          }
        }
      }

      BIND(&if_left_bigint);
      {
        Label if_right_heapnumber(this), if_right_bigint(this),
            if_right_string(this), if_right_boolean(this);
        CombineFeedback(var_type_feedback, CompareOperationFeedback::kBigInt);

        GotoIf(IsHeapNumberMap(right_map), &if_right_heapnumber);
        GotoIf(IsBigIntInstanceType(right_type), &if_right_bigint);
        GotoIf(IsStringInstanceType(right_type), &if_right_string);
        GotoIf(IsBooleanMap(right_map), &if_right_boolean);
        Branch(IsJSReceiverInstanceType(right_type), &use_symmetry,
               &if_notequal);

        BIND(&if_right_heapnumber);
        {
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kNumber);
          result = CAST(CallRuntime(Runtime::kBigIntEqualToNumber,
                                    NoContextConstant(), left, right));
          Goto(&end);
        }

        BIND(&if_right_bigint);
        {
          if (Is64()) {
            Label if_both_bigint(this);
            GotoIfLargeBigInt(CAST(left), &if_both_bigint);
            GotoIfLargeBigInt(CAST(right), &if_both_bigint);

            OverwriteFeedback(var_type_feedback,
                              CompareOperationFeedback::kBigInt64);
            BigInt64Comparison(Operation::kEqual, left, right, &if_equal,
                               &if_notequal);
            BIND(&if_both_bigint);
          }

          CombineFeedback(var_type_feedback, CompareOperationFeedback::kBigInt);
          result = CAST(CallBuiltin(Builtin::kBigIntEqual, NoContextConstant(),
                                    left, right));
          Goto(&end);
        }

        BIND(&if_right_string);
        {
          CombineFeedback(var_type_feedback, CompareOperationFeedback::kString);
          result = CAST(CallRuntime(Runtime::kBigIntEqualToString,
                                    NoContextConstant(), left, right));
          Goto(&end);
        }

        BIND(&if_right_boolean);
        {
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kBoolean);
          var_right =
              LoadObjectField(CAST(right), offsetof(Oddball, to_number_));
          Goto(&loop);
        }
      }

      BIND(&if_left_oddball);
      {
        Label if_left_boolean(this), if_left_not_boolean(this);
        GotoIf(IsBooleanMap(left_map), &if_left_boolean);
        if (var_type_feedback != nullptr) {
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kNullOrUndefined);
          GotoIf(IsUndetectableMap(left_map), &if_left_not_boolean);
        }
        Goto(&if_left_not_boolean);

        BIND(&if_left_not_boolean);
        {
          // {left} is either Null or Undefined. Check if {right} is
          // undetectable (which includes Null and Undefined).
          Label if_right_undetectable(this), if_right_number(this),
              if_right_oddball(this),
              if_right_not_number_or_oddball_or_undetectable(this);
          GotoIf(IsUndetectableMap(right_map), &if_right_undetectable);
          GotoIf(IsHeapNumberInstanceType(right_type), &if_right_number);
          GotoIf(IsOddballInstanceType(right_type), &if_right_oddball);
          Goto(&if_right_not_number_or_oddball_or_undetectable);

          BIND(&if_right_undetectable);
          {
            // If {right} is undetectable, it must be either also
            // Null or Undefined, or a Receiver (aka document.all).
            CombineFeedback(
                var_type_feedback,
                CompareOperationFeedback::kReceiverOrNullOrUndefined);
            Goto(&if_equal);
          }

          BIND(&if_right_number);
          {
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kNumber);
            Goto(&if_notequal);
          }

          BIND(&if_right_oddball);
          {
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kOddball);
            Goto(&if_notequal);
          }

          BIND(&if_right_not_number_or_oddball_or_undetectable);
          {
            if (var_type_feedback != nullptr) {
              // Track whether {right} is Null, Undefined or Receiver.
              CombineFeedback(
                  var_type_feedback,
                  CompareOperationFeedback::kReceiverOrNullOrUndefined);
              GotoIf(IsJSReceiverInstanceType(right_type), &if_notequal);
              CombineFeedback(var_type_feedback,
                              CompareOperationFeedback::kAny);
            }
            Goto(&if_notequal);
          }
        }

        BIND(&if_left_boolean);
        {
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kBoolean);

          // If {right} is a Boolean too, it must be a different Boolean.
          GotoIf(TaggedEqual(right_map, left_map), &if_notequal);

          // Otherwise, convert {left} to number and try again.
          var_left = LoadObjectField(CAST(left), offsetof(Oddball, to_number_));
          Goto(&loop);
        }
      }

      BIND(&if_left_symbol);
      {
        Label if_right_receiver(this);
        GotoIf(IsJSReceiverInstanceType(right_type), &if_right_receiver);
        // {right} is not a JSReceiver and also not the same Symbol as {left},
        // so the result is "not equal".
        if (var_type_feedback != nullptr) {
          Label if_right_symbol(this);
          GotoIf(IsSymbolInstanceType(right_type), &if_right_symbol);
          *var_type_feedback = SmiConstant(CompareOperationFeedback::kAny);
          Goto(&if_notequal);

          BIND(&if_right_symbol);
          {
            CombineFeedback(var_type_feedback,
                            CompareOperationFeedback::kSymbol);
            Goto(&if_notequal);
          }
        } else {
          Goto(&if_notequal);
        }

        BIND(&if_right_receiver);
        {
          // {left} is a Primitive and {right} is a JSReceiver, so swapping
          // the order is not observable.
          if (var_type_feedback != nullptr) {
            *var_type_feedback = SmiConstant(CompareOperationFeedback::kAny);
          }
          Goto(&use_symmetry);
        }
      }

      BIND(&if_left_receiver);
      {
        CSA_DCHECK(this, IsJSReceiverInstanceType(left_type));
        Label if_right_receiver(this), if_right_not_receiver(this);
        Branch(IsJSReceiverInstanceType(right_type), &if_right_receiver,
               &if_right_not_receiver);

        BIND(&if_right_receiver);
        {
          // {left} and {right} are different JSReceiver references.
          CombineFeedback(var_type_feedback,
                          CompareOperationFeedback::kReceiver);
          Goto(&if_notequal);
        }

        BIND(&if_right_not_receiver);
        {
          // Check if {right} is undetectable, which means it must be Null
          // or Undefined, since we already ruled out Receiver for {right}.
          Label if_right_undetectable(this),
              if_right_not_undetectable(this, Label::kDeferred);
          Branch(IsUndetectableMap(right_map), &if_right_undetectable,
                 &if_right_not_undetectable);

          BIND(&if_right_undetectable);
          {
            // When we get here, {right} must be either Null or Undefined.
            CSA_DCHECK(this, IsNullOrUndefined(right));
            if (var_type_feedback != nullptr) {
              *var_type_feedback = SmiConstant(
                  CompareOperationFeedback::kReceiverOrNullOrUndefined);
            }
            Branch(IsUndetectableMap(left_map), &if_equal, &if_notequal);
          }

          BIND(&if_right_not_undetectable);
          {
            // {right} is a Primitive, and neither Null or Undefined;
            // convert {left} to Primitive too.
            CombineFeedback(var_type_feedback, CompareOperationFeedback::kAny);
            var_left = CallBuiltin(Builtins::NonPrimitiveToPrimitive(),
                                   context(), left);
            Goto(&loop);
          }
        }
      }
    }

    BIND(&do_right_stringtonumber);
    {
      if (var_type_feedback != nullptr) {
        TNode<Map> right_map = LoadMap(CAST(right));
        TNode<Uint16T> right_type = LoadMapInstanceType(right_map);
        CombineFeedback(var_type_feedback,
                        CollectFeedbackForString(right_type));
      }
      var_right = CallBuiltin(Builtin::kStringToNumber, context(), right);
      Goto(&loop);
    }

    BIND(&use_symmetry);
    {
      var_left = right;
      var_right = left;
      Goto(&loop);
    }
  }

  BIND(&do_float_comparison);
  {
    Branch(Float64Equal(var_left_float.value(), var_right_float.value()),
           &if_equal, &if_notequal);
  }

  BIND(&if_equal);
  {
    result = TrueConstant();
    Goto(&end);
  }

  BIND(&if_notequal);
  {
    result = FalseConstant();
    Goto(&end);
  }

  BIND(&end);
  return result.value();
}

TNode<Boolean> CodeStubAssembler::StrictEqual(
    TNode<Object> lhs, TNode<Object> rhs, TVariable<Smi>* var_type_feedback) {
  // Pseudo-code for the algorithm below:
  //
  // if (lhs == rhs) {
  //   if (lhs->IsHeapNumber()) return Cast<HeapNumber>(lhs)->value() != NaN;
  //   return true;
  // }
  // if (!IsSmi(lhs)) {
  //   if (lhs->IsHeapNumber()) {
  //     if (IsSmi(rhs)) {
  //       return Smi::ToInt(rhs) == Cast<HeapNumber>(lhs)->value();
  //     } else if (rhs->IsHeapNumber()) {
  //       return Cast<HeapNumber>(rhs)->value() ==
  //       Cast<HeapNumber>(lhs)->value();
  //     } else {
  //       return false;
  //     }
  //   } else {
  //     if (IsSmi(rhs)) {
  //       return false;
  //     } else {
  //       if (lhs->IsString()) {
  //         if (rhs->IsString()) {
  //           return %StringEqual(lhs, rhs);
  //         } else {
  /
"""


```