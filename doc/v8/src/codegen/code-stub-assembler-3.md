Response: The user wants a summary of the C++ code in `v8/src/codegen/code-stub-assembler.cc`. This is part 4 of 12, suggesting the user wants a summary of this specific chunk. The summary should focus on the functionality implemented in this part of the file and highlight any connections to JavaScript.

**Plan:**

1. **Identify Key Functions and Templates:** Scan the code for function and template definitions.
2. **Group Related Functionality:** Group functions based on the data structures or operations they handle (e.g., array allocation, element manipulation, type conversion).
3. **Summarize Each Group:**  For each group, describe the core functionality provided by the functions.
4. **Find JavaScript Connections:** Identify how these C++ functions might be used to implement JavaScript features. This often involves array operations, type conversions, and memory management related to JavaScript objects.
5. **Provide JavaScript Examples:** For significant connections, provide simple JavaScript code snippets that would likely utilize the described C++ functionality.
这个C++代码文件（`v8/src/codegen/code-stub-assembler.cc` 的第 4 部分）主要包含了一系列用于在V8引擎中操作和管理内存中数据结构（特别是数组）的低级操作。它提供了一组构建块，供CodeStubAssembler（CSA）使用，以生成高效的机器码。

以下是这个部分的主要功能归纳：

**1. 数组操作（JSArray 和 FixedArray）：**

*   **`AllocateJSArray`:**  分配一个新的 JavaScript 数组对象。它会根据提供的元素类型（`ElementsKind`）和长度，选择合适的 `Map` 对象，并分配存储元素的 `FixedArrayBase`。
*   **`AllocateFixedArray`:** 分配一个 `FixedArrayBase`，这是用于存储数组元素的底层数据结构。可以指定元素类型 (`ElementsKind`)、容量和分配标志。
*   **`ExtractToFixedArray` 和 `ExtractFixedArray`:**  从现有的 `FixedArrayBase` 中提取一部分元素到一个新的 `FixedArrayBase` 中。可以控制是否复制写时复制（COW）数组，以及如何处理空洞（holes）。
*   **`ExtractFixedDoubleArrayFillingHoles`:**  专门用于从 `FixedDoubleArray` 中提取元素，并将空洞转换为 `undefined`。
*   **`InitializePropertyArrayLength` 和 `AllocatePropertyArray`:**  用于分配和初始化 `PropertyArray`，这是一种用于存储对象属性的特殊数组。
*   **`FillPropertyArrayWithUndefined` 和 `FillFixedArrayWithValue`:**  使用 `undefined` 或指定的值填充数组的指定范围。
*   **`StoreDoubleHole` 和 `StoreFixedDoubleArrayHole`:**  在 `FixedDoubleArray` 中存储表示空洞的特殊值。
*   **`FillFixedArrayWithSmiZero` 和 `FillFixedDoubleArrayWithZero`:** 使用零值填充数组的指定范围，针对Smi和double类型进行了优化。
*   **`MoveElements` 和 `CopyElements`:**  在 `FixedArrayBase` 内部或之间移动和复制元素。
*   **`CopyRange`:** 复制堆对象中的一段数据到另一个堆对象。
*   **`CopyFixedArrayElements`:**  复制 `FixedArrayBase` 之间的元素，可以进行类型转换和空洞处理。
*   **`HeapObjectToFixedArray`:**  将 `HeapObject` 转换为 `FixedArray`，如果类型不匹配则跳转到失败标签。
*   **`CopyPropertyArrayValues`:**  复制 `PropertyArray` 中的值到另一个 `PropertyArray`。
*   **`CloneFixedArray`:**  创建一个 `FixedArrayBase` 的副本。
*   **`LoadElementAndPrepareForStore`:**  加载数组元素，并根据目标类型进行必要的转换（例如，从double到HeapNumber）。
*   **`CalculateNewElementsCapacity` 和 `TryGrowElementsCapacity` 和 `GrowElementsCapacity`:**  用于计算和尝试增加数组的容量。

**2. 类型转换和检查:**

*   **`TryTaggedToInt32AsIntPtr`:** 尝试将一个Tagged值转换为IntPtr，如果不能转换为有效的int32则跳转。
*   **`TryTaggedToFloat64`:** 尝试将一个Tagged值转换为Float64，如果不是数字则跳转。
*   **`TruncateTaggedToFloat64` 和 `TruncateTaggedToWord32`:** 将Tagged值截断为 Float64 或 Word32。
*   **`TaggedToWord32OrBigInt` 和 相关函数:** 尝试将Tagged值转换为 Word32 或 BigInt。
*   **`TruncateNumberToWord32` 和 `TruncateHeapNumberValueToWord32`:** 将 Number 对象截断为 Word32。
*   **`TryHeapNumberToSmi` 和 `TryFloat32ToSmi` 和 `TryFloat64ToSmi`:** 尝试将 HeapNumber 或浮点数转换为 Smi。
*   **`TruncateFloat64ToFloat16`:** 将 Float64 截断为 Float16。

**3. 其他辅助功能:**

*   **`InitializeAllocationMemento` 和 `InnerAllocateMemento`:**  用于初始化和分配分配Memento对象，用于跟踪对象的分配站点信息，用于性能优化。
*   **`JumpIfPointersFromHereAreInteresting`:** 检查一个对象所在的内存页是否包含需要进行写屏障处理的指针。

**与 JavaScript 的关系和示例：**

这个文件中的函数是 V8 引擎内部实现 JavaScript 数组和数值操作的基础。当你在 JavaScript 中执行与数组或数值相关的操作时，V8 引擎可能会调用这些底层的 C++ 函数来完成任务。

**JavaScript 示例：**

1. **数组创建和增长：**

    ```javascript
    const arr = [1, 2, 3];
    arr.push(4); // 当数组容量不足时，V8 会调用类似 `GrowElementsCapacity` 的函数来分配更大的存储空间。
    ```

2. **数组元素访问和修改：**

    ```javascript
    const arr = [1.5, 2.7];
    const first = arr[0]; // V8 内部会根据数组的元素类型（例如 PACKED_DOUBLE_ELEMENTS）使用相应的加载操作。
    arr[1] = 3.14;      // V8 内部会使用相应的存储操作。
    ```

3. **数组方法 (例如 `slice`)：**

    ```javascript
    const arr = [1, 2, 3, 4, 5];
    const subArray = arr.slice(1, 4); // V8 会调用类似 `ExtractFixedArray` 的函数来创建新的子数组。
    ```

4. **类型转换：**

    ```javascript
    const num = 10;
    const floatNum = parseFloat(num); // V8 内部可能会使用类似 `TryTaggedToFloat64` 的函数。
    const intNum = parseInt(floatNum);  // V8 内部可能会使用类似 `TruncateTaggedToWord32` 的函数。
    ```

5. **大整数操作：**

    ```javascript
    const bigInt = 9007199254740991n;
    const result = bigInt + 1n; // V8 内部可能会使用与 BigInt 相关的函数。
    ```

**总结来说，这个代码片段提供了 V8 引擎中处理数组和数值类型的核心低级操作。它是 JavaScript 引擎高效运行的关键组成部分，使得 JavaScript 能够进行各种数组操作和数值计算。**

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共12部分，请归纳一下它的功能
```

### 源代码
```
ts
  // protector is invalid. This function should be renamed to reflect its uses.

  TNode<Number> length = LoadJSArrayLength(array);
  TNode<FixedArrayBase> new_elements;
  TVARIABLE(FixedArrayBase, var_new_elements);
  TVARIABLE(Int32T, var_elements_kind, LoadMapElementsKind(LoadMap(array)));

  Label allocate_jsarray(this), holey_extract(this),
      allocate_jsarray_main(this);

  bool need_conversion =
      convert_holes == HoleConversionMode::kConvertToUndefined;
  if (need_conversion) {
    // We need to take care of holes, if the array is of holey elements kind.
    GotoIf(IsHoleyFastElementsKindForRead(var_elements_kind.value()),
           &holey_extract);
  }

  // Simple extraction that preserves holes.
  new_elements = ExtractFixedArray(
      LoadElements(array),
      std::optional<TNode<BInt>>(IntPtrOrSmiConstant<BInt>(0)),
      std::optional<TNode<BInt>>(TaggedToParameter<BInt>(CAST(length))),
      std::optional<TNode<BInt>>(std::nullopt),
      ExtractFixedArrayFlag::kAllFixedArraysDontCopyCOW, nullptr,
      var_elements_kind.value());
  var_new_elements = new_elements;
  Goto(&allocate_jsarray);

  if (need_conversion) {
    BIND(&holey_extract);
    // Convert holes to undefined.
    TVARIABLE(BoolT, var_holes_converted, Int32FalseConstant());
    // Copy |array|'s elements store. The copy will be compatible with the
    // original elements kind unless there are holes in the source. Any holes
    // get converted to undefined, hence in that case the copy is compatible
    // only with PACKED_ELEMENTS and HOLEY_ELEMENTS, and we will choose
    // PACKED_ELEMENTS. Also, if we want to replace holes, we must not use
    // ExtractFixedArrayFlag::kDontCopyCOW.
    new_elements = ExtractFixedArray(
        LoadElements(array),
        std::optional<TNode<BInt>>(IntPtrOrSmiConstant<BInt>(0)),
        std::optional<TNode<BInt>>(TaggedToParameter<BInt>(CAST(length))),
        std::optional<TNode<BInt>>(std::nullopt),
        ExtractFixedArrayFlag::kAllFixedArrays, &var_holes_converted);
    var_new_elements = new_elements;
    // If the array type didn't change, use the original elements kind.
    GotoIfNot(var_holes_converted.value(), &allocate_jsarray);
    // Otherwise use PACKED_ELEMENTS for the target's elements kind.
    var_elements_kind = Int32Constant(PACKED_ELEMENTS);
    Goto(&allocate_jsarray);
  }

  BIND(&allocate_jsarray);

  // Handle any nonextensible elements kinds
  CSA_DCHECK(this, IsElementsKindLessThanOrEqual(
                       var_elements_kind.value(),
                       LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND));
  GotoIf(IsElementsKindLessThanOrEqual(var_elements_kind.value(),
                                       LAST_FAST_ELEMENTS_KIND),
         &allocate_jsarray_main);
  var_elements_kind = Int32Constant(PACKED_ELEMENTS);
  Goto(&allocate_jsarray_main);

  BIND(&allocate_jsarray_main);
  // Use the cannonical map for the chosen elements kind.
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> array_map =
      LoadJSArrayElementsMap(var_elements_kind.value(), native_context);

  TNode<JSArray> result = AllocateJSArray(array_map, var_new_elements.value(),
                                          CAST(length), allocation_site);
  return result;
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::AllocateFixedArray(
    ElementsKind kind, TNode<TIndex> capacity, AllocationFlags flags,
    std::optional<TNode<Map>> fixed_array_map) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT capacity is allowed");
  Comment("AllocateFixedArray");
  CSA_DCHECK(this,
             IntPtrOrSmiGreaterThan(capacity, IntPtrOrSmiConstant<TIndex>(0)));

  const intptr_t kMaxLength = IsDoubleElementsKind(kind)
                                  ? FixedDoubleArray::kMaxLength
                                  : FixedArray::kMaxLength;
  intptr_t capacity_constant;
  if (ToParameterConstant(capacity, &capacity_constant)) {
    CHECK_LE(capacity_constant, kMaxLength);
  } else {
    Label if_out_of_memory(this, Label::kDeferred), next(this);
    Branch(IntPtrOrSmiGreaterThan(capacity, IntPtrOrSmiConstant<TIndex>(
                                                static_cast<int>(kMaxLength))),
           &if_out_of_memory, &next);

    BIND(&if_out_of_memory);
    CallRuntime(Runtime::kFatalProcessOutOfMemoryInvalidArrayLength,
                NoContextConstant());
    Unreachable();

    BIND(&next);
  }

  TNode<IntPtrT> total_size = GetFixedArrayAllocationSize(capacity, kind);

  if (IsDoubleElementsKind(kind)) flags |= AllocationFlag::kDoubleAlignment;
  TNode<HeapObject> array = Allocate(total_size, flags);
  if (fixed_array_map) {
    // Conservatively only skip the write barrier if there are no allocation
    // flags, this ensures that the object hasn't ended up in LOS. Note that the
    // fixed array map is currently always immortal and technically wouldn't
    // need the write barrier even in LOS, but it's better to not take chances
    // in case this invariant changes later, since it's difficult to enforce
    // locally here.
    if (flags == AllocationFlag::kNone) {
      StoreMapNoWriteBarrier(array, *fixed_array_map);
    } else {
      StoreMap(array, *fixed_array_map);
    }
  } else {
    RootIndex map_index = IsDoubleElementsKind(kind)
                              ? RootIndex::kFixedDoubleArrayMap
                              : RootIndex::kFixedArrayMap;
    DCHECK(RootsTable::IsImmortalImmovable(map_index));
    StoreMapNoWriteBarrier(array, map_index);
  }
  StoreObjectFieldNoWriteBarrier(array, FixedArrayBase::kLengthOffset,
                                 ParameterToTagged(capacity));
  return UncheckedCast<FixedArrayBase>(array);
}

// There is no need to export the Smi version since it is only used inside
// code-stub-assembler.
template V8_EXPORT_PRIVATE TNode<FixedArrayBase>
    CodeStubAssembler::AllocateFixedArray<IntPtrT>(ElementsKind, TNode<IntPtrT>,
                                                   AllocationFlags,
                                                   std::optional<TNode<Map>>);

template <typename TIndex>
TNode<FixedArray> CodeStubAssembler::ExtractToFixedArray(
    TNode<FixedArrayBase> source, TNode<TIndex> first, TNode<TIndex> count,
    TNode<TIndex> capacity, TNode<Map> source_map, ElementsKind from_kind,
    AllocationFlags allocation_flags, ExtractFixedArrayFlags extract_flags,
    HoleConversionMode convert_holes, TVariable<BoolT>* var_holes_converted,
    std::optional<TNode<Int32T>> source_elements_kind) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT first, count, and capacity are allowed");

  DCHECK(extract_flags & ExtractFixedArrayFlag::kFixedArrays);
  CSA_DCHECK(this,
             IntPtrOrSmiNotEqual(IntPtrOrSmiConstant<TIndex>(0), capacity));
  CSA_DCHECK(this, TaggedEqual(source_map, LoadMap(source)));

  TVARIABLE(FixedArrayBase, var_result);
  TVARIABLE(Map, var_target_map, source_map);

  Label done(this, {&var_result}), is_cow(this),
      new_space_handler(this, {&var_target_map});

  // If source_map is either FixedDoubleArrayMap, or FixedCOWArrayMap but
  // we can't just use COW, use FixedArrayMap as the target map. Otherwise, use
  // source_map as the target map.
  if (IsDoubleElementsKind(from_kind)) {
    CSA_DCHECK(this, IsFixedDoubleArrayMap(source_map));
    var_target_map = FixedArrayMapConstant();
    Goto(&new_space_handler);
  } else {
    CSA_DCHECK(this, Word32BinaryNot(IsFixedDoubleArrayMap(source_map)));
    Branch(TaggedEqual(var_target_map.value(), FixedCOWArrayMapConstant()),
           &is_cow, &new_space_handler);

    BIND(&is_cow);
    {
      // |source| is a COW array, so we don't actually need to allocate a new
      // array unless:
      // 1) |extract_flags| forces us to, or
      // 2) we're asked to extract only part of the |source| (|first| != 0).
      if (extract_flags & ExtractFixedArrayFlag::kDontCopyCOW) {
        Branch(IntPtrOrSmiNotEqual(IntPtrOrSmiConstant<TIndex>(0), first),
               &new_space_handler, [&] {
                 var_result = source;
                 Goto(&done);
               });
      } else {
        var_target_map = FixedArrayMapConstant();
        Goto(&new_space_handler);
      }
    }
  }

  BIND(&new_space_handler);
  {
    Comment("Copy FixedArray in young generation");
    // We use PACKED_ELEMENTS to tell AllocateFixedArray and
    // CopyFixedArrayElements that we want a FixedArray.
    const ElementsKind to_kind = PACKED_ELEMENTS;
    TNode<FixedArrayBase> to_elements = AllocateFixedArray(
        to_kind, capacity, allocation_flags, var_target_map.value());
    var_result = to_elements;

#if !defined(V8_ENABLE_SINGLE_GENERATION) && !V8_ENABLE_STICKY_MARK_BITS_BOOL
#ifdef DEBUG
    TNode<IntPtrT> object_word = BitcastTaggedToWord(to_elements);
    TNode<IntPtrT> object_page_header = MemoryChunkFromAddress(object_word);
    TNode<IntPtrT> page_flags = Load<IntPtrT>(
        object_page_header, IntPtrConstant(MemoryChunk::FlagsOffset()));
    CSA_DCHECK(
        this,
        WordNotEqual(
            WordAnd(page_flags,
                    IntPtrConstant(MemoryChunk::kIsInYoungGenerationMask)),
            IntPtrConstant(0)));
#endif
#endif

    if (convert_holes == HoleConversionMode::kDontConvert &&
        !IsDoubleElementsKind(from_kind)) {
      // We can use CopyElements (memcpy) because we don't need to replace or
      // convert any values. Since {to_elements} is in new-space, CopyElements
      // will efficiently use memcpy.
      FillFixedArrayWithValue(to_kind, to_elements, count, capacity,
                              RootIndex::kTheHoleValue);
      CopyElements(to_kind, to_elements, IntPtrConstant(0), source,
                   ParameterToIntPtr(first), ParameterToIntPtr(count),
                   SKIP_WRITE_BARRIER);
    } else {
      CopyFixedArrayElements(from_kind, source, to_kind, to_elements, first,
                             count, capacity, SKIP_WRITE_BARRIER, convert_holes,
                             var_holes_converted);
    }
    Goto(&done);
  }

  BIND(&done);
  return UncheckedCast<FixedArray>(var_result.value());
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::ExtractFixedDoubleArrayFillingHoles(
    TNode<FixedArrayBase> from_array, TNode<TIndex> first, TNode<TIndex> count,
    TNode<TIndex> capacity, TNode<Map> fixed_array_map,
    TVariable<BoolT>* var_holes_converted, AllocationFlags allocation_flags,
    ExtractFixedArrayFlags extract_flags) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT first, count, and capacity are allowed");

  DCHECK_NE(var_holes_converted, nullptr);
  CSA_DCHECK(this, IsFixedDoubleArrayMap(fixed_array_map));

  TVARIABLE(FixedArrayBase, var_result);
  const ElementsKind kind = PACKED_DOUBLE_ELEMENTS;
  TNode<FixedArrayBase> to_elements =
      AllocateFixedArray(kind, capacity, allocation_flags, fixed_array_map);
  var_result = to_elements;
  // We first try to copy the FixedDoubleArray to a new FixedDoubleArray.
  // |var_holes_converted| is set to False preliminarily.
  *var_holes_converted = Int32FalseConstant();

  // The construction of the loop and the offsets for double elements is
  // extracted from CopyFixedArrayElements.
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(from_array, kind));
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));

  Comment("[ ExtractFixedDoubleArrayFillingHoles");

  // This copy can trigger GC, so we pre-initialize the array with holes.
  FillFixedArrayWithValue(kind, to_elements, IntPtrOrSmiConstant<TIndex>(0),
                          capacity, RootIndex::kTheHoleValue);

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> first_from_element_offset =
      ElementOffsetFromIndex(first, kind, 0);
  TNode<IntPtrT> limit_offset = IntPtrAdd(first_from_element_offset,
                                          IntPtrConstant(first_element_offset));
  TVARIABLE(IntPtrT, var_from_offset,
            ElementOffsetFromIndex(IntPtrOrSmiAdd(first, count), kind,
                                   first_element_offset));

  Label decrement(this, {&var_from_offset}), done(this);
  TNode<IntPtrT> to_array_adjusted =
      IntPtrSub(BitcastTaggedToWord(to_elements), first_from_element_offset);

  Branch(WordEqual(var_from_offset.value(), limit_offset), &done, &decrement);

  BIND(&decrement);
  {
    TNode<IntPtrT> from_offset =
        IntPtrSub(var_from_offset.value(), IntPtrConstant(kDoubleSize));
    var_from_offset = from_offset;

    TNode<IntPtrT> to_offset = from_offset;

    Label if_hole(this);

    TNode<Float64T> value = LoadDoubleWithHoleCheck(
        from_array, var_from_offset.value(), &if_hole, MachineType::Float64());

    StoreNoWriteBarrier(MachineRepresentation::kFloat64, to_array_adjusted,
                        to_offset, value);

    TNode<BoolT> compare = WordNotEqual(from_offset, limit_offset);
    Branch(compare, &decrement, &done);

    BIND(&if_hole);
    // We are unlucky: there are holes! We need to restart the copy, this time
    // we will copy the FixedDoubleArray to a new FixedArray with undefined
    // replacing holes. We signal this to the caller through
    // |var_holes_converted|.
    *var_holes_converted = Int32TrueConstant();
    to_elements =
        ExtractToFixedArray(from_array, first, count, capacity, fixed_array_map,
                            kind, allocation_flags, extract_flags,
                            HoleConversionMode::kConvertToUndefined);
    var_result = to_elements;
    Goto(&done);
  }

  BIND(&done);
  Comment("] ExtractFixedDoubleArrayFillingHoles");
  return var_result.value();
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::ExtractFixedArray(
    TNode<FixedArrayBase> source, std::optional<TNode<TIndex>> first,
    std::optional<TNode<TIndex>> count, std::optional<TNode<TIndex>> capacity,
    ExtractFixedArrayFlags extract_flags, TVariable<BoolT>* var_holes_converted,
    std::optional<TNode<Int32T>> source_elements_kind) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT first, count, and capacity are allowed");
  DCHECK(extract_flags & ExtractFixedArrayFlag::kFixedArrays ||
         extract_flags & ExtractFixedArrayFlag::kFixedDoubleArrays);
  // If we want to replace holes, ExtractFixedArrayFlag::kDontCopyCOW should
  // not be used, because that disables the iteration which detects holes.
  DCHECK_IMPLIES(var_holes_converted != nullptr,
                 !(extract_flags & ExtractFixedArrayFlag::kDontCopyCOW));
  HoleConversionMode convert_holes =
      var_holes_converted != nullptr ? HoleConversionMode::kConvertToUndefined
                                     : HoleConversionMode::kDontConvert;
  TVARIABLE(FixedArrayBase, var_result);
  auto allocation_flags = AllocationFlag::kNone;
  if (!first) {
    first = IntPtrOrSmiConstant<TIndex>(0);
  }
  if (!count) {
    count = IntPtrOrSmiSub(
        TaggedToParameter<TIndex>(LoadFixedArrayBaseLength(source)), *first);

    CSA_DCHECK(this, IntPtrOrSmiLessThanOrEqual(IntPtrOrSmiConstant<TIndex>(0),
                                                *count));
  }
  if (!capacity) {
    capacity = *count;
  } else {
    CSA_DCHECK(this, Word32BinaryNot(IntPtrOrSmiGreaterThan(
                         IntPtrOrSmiAdd(*first, *count), *capacity)));
  }

  Label if_fixed_double_array(this), empty(this), done(this, &var_result);
  TNode<Map> source_map = LoadMap(source);
  GotoIf(IntPtrOrSmiEqual(IntPtrOrSmiConstant<TIndex>(0), *capacity), &empty);

  if (extract_flags & ExtractFixedArrayFlag::kFixedDoubleArrays) {
    if (extract_flags & ExtractFixedArrayFlag::kFixedArrays) {
      GotoIf(IsFixedDoubleArrayMap(source_map), &if_fixed_double_array);
    } else {
      CSA_DCHECK(this, IsFixedDoubleArrayMap(source_map));
    }
  }

  if (extract_flags & ExtractFixedArrayFlag::kFixedArrays) {
    // Here we can only get |source| as FixedArray, never FixedDoubleArray.
    // PACKED_ELEMENTS is used to signify that the source is a FixedArray.
    TNode<FixedArray> to_elements = ExtractToFixedArray(
        source, *first, *count, *capacity, source_map, PACKED_ELEMENTS,
        allocation_flags, extract_flags, convert_holes, var_holes_converted,
        source_elements_kind);
    var_result = to_elements;
    Goto(&done);
  }

  if (extract_flags & ExtractFixedArrayFlag::kFixedDoubleArrays) {
    BIND(&if_fixed_double_array);
    Comment("Copy FixedDoubleArray");

    if (convert_holes == HoleConversionMode::kConvertToUndefined) {
      TNode<FixedArrayBase> to_elements = ExtractFixedDoubleArrayFillingHoles(
          source, *first, *count, *capacity, source_map, var_holes_converted,
          allocation_flags, extract_flags);
      var_result = to_elements;
    } else {
      // We use PACKED_DOUBLE_ELEMENTS to signify that both the source and
      // the target are FixedDoubleArray. That it is PACKED or HOLEY does not
      // matter.
      ElementsKind kind = PACKED_DOUBLE_ELEMENTS;
      TNode<FixedArrayBase> to_elements =
          AllocateFixedArray(kind, *capacity, allocation_flags, source_map);
      FillFixedArrayWithValue(kind, to_elements, *count, *capacity,
                              RootIndex::kTheHoleValue);
      CopyElements(kind, to_elements, IntPtrConstant(0), source,
                   ParameterToIntPtr(*first), ParameterToIntPtr(*count));
      var_result = to_elements;
    }

    Goto(&done);
  }

  BIND(&empty);
  {
    Comment("Copy empty array");

    var_result = EmptyFixedArrayConstant();
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

template V8_EXPORT_PRIVATE TNode<FixedArrayBase>
CodeStubAssembler::ExtractFixedArray<Smi>(
    TNode<FixedArrayBase>, std::optional<TNode<Smi>>, std::optional<TNode<Smi>>,
    std::optional<TNode<Smi>>, ExtractFixedArrayFlags, TVariable<BoolT>*,
    std::optional<TNode<Int32T>>);

template V8_EXPORT_PRIVATE TNode<FixedArrayBase>
CodeStubAssembler::ExtractFixedArray<IntPtrT>(
    TNode<FixedArrayBase>, std::optional<TNode<IntPtrT>>,
    std::optional<TNode<IntPtrT>>, std::optional<TNode<IntPtrT>>,
    ExtractFixedArrayFlags, TVariable<BoolT>*, std::optional<TNode<Int32T>>);

void CodeStubAssembler::InitializePropertyArrayLength(
    TNode<PropertyArray> property_array, TNode<IntPtrT> length) {
  CSA_DCHECK(this, IntPtrGreaterThan(length, IntPtrConstant(0)));
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(
                 length, IntPtrConstant(PropertyArray::LengthField::kMax)));
  StoreObjectFieldNoWriteBarrier(
      property_array, PropertyArray::kLengthAndHashOffset, SmiTag(length));
}

TNode<PropertyArray> CodeStubAssembler::AllocatePropertyArray(
    TNode<IntPtrT> capacity) {
  CSA_DCHECK(this, IntPtrGreaterThan(capacity, IntPtrConstant(0)));
  TNode<IntPtrT> total_size = GetPropertyArrayAllocationSize(capacity);

  TNode<HeapObject> array = Allocate(total_size, AllocationFlag::kNone);
  RootIndex map_index = RootIndex::kPropertyArrayMap;
  DCHECK(RootsTable::IsImmortalImmovable(map_index));
  StoreMapNoWriteBarrier(array, map_index);
  TNode<PropertyArray> property_array = CAST(array);
  InitializePropertyArrayLength(property_array, capacity);
  return property_array;
}

void CodeStubAssembler::FillPropertyArrayWithUndefined(
    TNode<PropertyArray> array, TNode<IntPtrT> from_index,
    TNode<IntPtrT> to_index) {
  ElementsKind kind = PACKED_ELEMENTS;
  TNode<Undefined> value = UndefinedConstant();
  BuildFastArrayForEach(
      array, kind, from_index, to_index,
      [this, value](TNode<HeapObject> array, TNode<IntPtrT> offset) {
        StoreNoWriteBarrier(MachineRepresentation::kTagged, array, offset,
                            value);
      },
      LoopUnrollingMode::kYes);
}

template <typename TIndex>
void CodeStubAssembler::FillFixedArrayWithValue(ElementsKind kind,
                                                TNode<FixedArrayBase> array,
                                                TNode<TIndex> from_index,
                                                TNode<TIndex> to_index,
                                                RootIndex value_root_index) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT from and to are allowed");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKind(array, kind));
  DCHECK(value_root_index == RootIndex::kTheHoleValue ||
         value_root_index == RootIndex::kUndefinedValue);

  // Determine the value to initialize the {array} based
  // on the {value_root_index} and the elements {kind}.
  TNode<Object> value = LoadRoot(value_root_index);
  TNode<Float64T> float_value;
  if (IsDoubleElementsKind(kind)) {
    float_value = LoadHeapNumberValue(CAST(value));
  }

  BuildFastArrayForEach(
      array, kind, from_index, to_index,
      [this, value, float_value, kind](TNode<HeapObject> array,
                                       TNode<IntPtrT> offset) {
        if (IsDoubleElementsKind(kind)) {
          StoreNoWriteBarrier(MachineRepresentation::kFloat64, array, offset,
                              float_value);
        } else {
          StoreNoWriteBarrier(MachineRepresentation::kTagged, array, offset,
                              value);
        }
      },
      LoopUnrollingMode::kYes);
}

template V8_EXPORT_PRIVATE void
    CodeStubAssembler::FillFixedArrayWithValue<IntPtrT>(ElementsKind,
                                                        TNode<FixedArrayBase>,
                                                        TNode<IntPtrT>,
                                                        TNode<IntPtrT>,
                                                        RootIndex);
template V8_EXPORT_PRIVATE void CodeStubAssembler::FillFixedArrayWithValue<Smi>(
    ElementsKind, TNode<FixedArrayBase>, TNode<Smi>, TNode<Smi>, RootIndex);

void CodeStubAssembler::StoreDoubleHole(TNode<HeapObject> object,
                                        TNode<IntPtrT> offset) {
  TNode<UintPtrT> double_hole =
      Is64() ? ReinterpretCast<UintPtrT>(Int64Constant(kHoleNanInt64))
             : ReinterpretCast<UintPtrT>(Int32Constant(kHoleNanLower32));
  // TODO(danno): When we have a Float32/Float64 wrapper class that
  // preserves double bits during manipulation, remove this code/change
  // this to an indexed Float64 store.
  if (Is64()) {
    StoreNoWriteBarrier(MachineRepresentation::kWord64, object, offset,
                        double_hole);
  } else {
    StoreNoWriteBarrier(MachineRepresentation::kWord32, object, offset,
                        double_hole);
    StoreNoWriteBarrier(MachineRepresentation::kWord32, object,
                        IntPtrAdd(offset, IntPtrConstant(kInt32Size)),
                        double_hole);
  }
}

void CodeStubAssembler::StoreFixedDoubleArrayHole(TNode<FixedDoubleArray> array,
                                                  TNode<IntPtrT> index) {
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS,
                             OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  CSA_DCHECK(this,
             IsOffsetInBounds(offset, LoadAndUntagFixedArrayBaseLength(array),
                              OFFSET_OF_DATA_START(FixedDoubleArray),
                              PACKED_DOUBLE_ELEMENTS));
  StoreDoubleHole(array, offset);
}

void CodeStubAssembler::FillFixedArrayWithSmiZero(ElementsKind kind,
                                                  TNode<FixedArray> array,
                                                  TNode<IntPtrT> start,
                                                  TNode<IntPtrT> length) {
  DCHECK(IsSmiOrObjectElementsKind(kind));
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(IntPtrAdd(start, length),
                                   LoadAndUntagFixedArrayBaseLength(array)));

  TNode<IntPtrT> byte_length = TimesTaggedSize(length);
  CSA_DCHECK(this, UintPtrLessThan(length, byte_length));

  static const int32_t fa_base_data_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(start, kind, fa_base_data_offset);
  TNode<IntPtrT> backing_store = IntPtrAdd(BitcastTaggedToWord(array), offset);

  // Call out to memset to perform initialization.
  TNode<ExternalReference> memset =
      ExternalConstant(ExternalReference::libc_memset_function());
  static_assert(kSizetSize == kIntptrSize);
  CallCFunction(memset, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), backing_store),
                std::make_pair(MachineType::IntPtr(), IntPtrConstant(0)),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void CodeStubAssembler::FillFixedDoubleArrayWithZero(
    TNode<FixedDoubleArray> array, TNode<IntPtrT> start,
    TNode<IntPtrT> length) {
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(IntPtrAdd(start, length),
                                   LoadAndUntagFixedArrayBaseLength(array)));

  TNode<IntPtrT> byte_length = TimesDoubleSize(length);
  CSA_DCHECK(this, UintPtrLessThan(length, byte_length));

  static const int32_t fa_base_data_offset =
      OFFSET_OF_DATA_START(FixedDoubleArray) - kHeapObjectTag;
  TNode<IntPtrT> offset = ElementOffsetFromIndex(start, PACKED_DOUBLE_ELEMENTS,
                                                 fa_base_data_offset);
  TNode<IntPtrT> backing_store = IntPtrAdd(BitcastTaggedToWord(array), offset);

  // Call out to memset to perform initialization.
  TNode<ExternalReference> memset =
      ExternalConstant(ExternalReference::libc_memset_function());
  static_assert(kSizetSize == kIntptrSize);
  CallCFunction(memset, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), backing_store),
                std::make_pair(MachineType::IntPtr(), IntPtrConstant(0)),
                std::make_pair(MachineType::UintPtr(), byte_length));
}

void CodeStubAssembler::JumpIfPointersFromHereAreInteresting(
    TNode<Object> object, Label* interesting) {
  Label finished(this);
  TNode<IntPtrT> object_word = BitcastTaggedToWord(object);
  TNode<IntPtrT> object_page_header = MemoryChunkFromAddress(object_word);
  TNode<IntPtrT> page_flags =
      UncheckedCast<IntPtrT>(Load(MachineType::IntPtr(), object_page_header,
                                  IntPtrConstant(MemoryChunk::FlagsOffset())));
  Branch(
      WordEqual(WordAnd(page_flags,
                        IntPtrConstant(
                            MemoryChunk::kPointersFromHereAreInterestingMask)),
                IntPtrConstant(0)),
      &finished, interesting);
  BIND(&finished);
}

void CodeStubAssembler::MoveElements(ElementsKind kind,
                                     TNode<FixedArrayBase> elements,
                                     TNode<IntPtrT> dst_index,
                                     TNode<IntPtrT> src_index,
                                     TNode<IntPtrT> length) {
  Label finished(this);
  Label needs_barrier(this);
#ifdef V8_DISABLE_WRITE_BARRIERS
  const bool needs_barrier_check = false;
#else
  const bool needs_barrier_check = !IsDoubleElementsKind(kind);
#endif  // V8_DISABLE_WRITE_BARRIERS

  DCHECK(IsFastElementsKind(kind));
  CSA_DCHECK(this, IsFixedArrayWithKind(elements, kind));
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(IntPtrAdd(dst_index, length),
                                   LoadAndUntagFixedArrayBaseLength(elements)));
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(IntPtrAdd(src_index, length),
                                   LoadAndUntagFixedArrayBaseLength(elements)));

  // The write barrier can be ignored if {dst_elements} is in new space, or if
  // the elements pointer is FixedDoubleArray.
  if (needs_barrier_check) {
    JumpIfPointersFromHereAreInteresting(elements, &needs_barrier);
  }

  const TNode<IntPtrT> source_byte_length =
      IntPtrMul(length, IntPtrConstant(ElementsKindToByteSize(kind)));
  static const int32_t fa_base_data_offset =
      FixedArrayBase::kHeaderSize - kHeapObjectTag;
  TNode<IntPtrT> elements_intptr = BitcastTaggedToWord(elements);
  TNode<IntPtrT> target_data_ptr =
      IntPtrAdd(elements_intptr,
                ElementOffsetFromIndex(dst_index, kind, fa_base_data_offset));
  TNode<IntPtrT> source_data_ptr =
      IntPtrAdd(elements_intptr,
                ElementOffsetFromIndex(src_index, kind, fa_base_data_offset));
  TNode<ExternalReference> memmove =
      ExternalConstant(ExternalReference::libc_memmove_function());
  CallCFunction(memmove, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), target_data_ptr),
                std::make_pair(MachineType::Pointer(), source_data_ptr),
                std::make_pair(MachineType::UintPtr(), source_byte_length));

  if (needs_barrier_check) {
    Goto(&finished);

    BIND(&needs_barrier);
    {
      const TNode<IntPtrT> begin = src_index;
      const TNode<IntPtrT> end = IntPtrAdd(begin, length);

      // If dst_index is less than src_index, then walk forward.
      const TNode<IntPtrT> delta =
          IntPtrMul(IntPtrSub(dst_index, begin),
                    IntPtrConstant(ElementsKindToByteSize(kind)));
      auto loop_body = [&](TNode<HeapObject> array, TNode<IntPtrT> offset) {
        const TNode<AnyTaggedT> element = Load<AnyTaggedT>(array, offset);
        const TNode<WordT> delta_offset = IntPtrAdd(offset, delta);
        Store(array, delta_offset, element);
      };

      Label iterate_forward(this);
      Label iterate_backward(this);
      Branch(IntPtrLessThan(delta, IntPtrConstant(0)), &iterate_forward,
             &iterate_backward);
      BIND(&iterate_forward);
      {
        // Make a loop for the stores.
        BuildFastArrayForEach(elements, kind, begin, end, loop_body,
                              LoopUnrollingMode::kYes,
                              ForEachDirection::kForward);
        Goto(&finished);
      }

      BIND(&iterate_backward);
      {
        BuildFastArrayForEach(elements, kind, begin, end, loop_body,
                              LoopUnrollingMode::kYes,
                              ForEachDirection::kReverse);
        Goto(&finished);
      }
    }
    BIND(&finished);
  }
}

void CodeStubAssembler::CopyElements(ElementsKind kind,
                                     TNode<FixedArrayBase> dst_elements,
                                     TNode<IntPtrT> dst_index,
                                     TNode<FixedArrayBase> src_elements,
                                     TNode<IntPtrT> src_index,
                                     TNode<IntPtrT> length,
                                     WriteBarrierMode write_barrier) {
  Label finished(this);
  Label needs_barrier(this);
#ifdef V8_DISABLE_WRITE_BARRIERS
  const bool needs_barrier_check = false;
#else
  const bool needs_barrier_check = !IsDoubleElementsKind(kind);
#endif  // V8_DISABLE_WRITE_BARRIERS

  DCHECK(IsFastElementsKind(kind));
  CSA_DCHECK(this, IsFixedArrayWithKind(dst_elements, kind));
  CSA_DCHECK(this, IsFixedArrayWithKind(src_elements, kind));
  CSA_DCHECK(this, IntPtrLessThanOrEqual(
                       IntPtrAdd(dst_index, length),
                       LoadAndUntagFixedArrayBaseLength(dst_elements)));
  CSA_DCHECK(this, IntPtrLessThanOrEqual(
                       IntPtrAdd(src_index, length),
                       LoadAndUntagFixedArrayBaseLength(src_elements)));
  CSA_DCHECK(this, Word32Or(TaggedNotEqual(dst_elements, src_elements),
                            IntPtrEqual(length, IntPtrConstant(0))));

  // The write barrier can be ignored if {dst_elements} is in new space, or if
  // the elements pointer is FixedDoubleArray.
  if (needs_barrier_check) {
    JumpIfPointersFromHereAreInteresting(dst_elements, &needs_barrier);
  }

  TNode<IntPtrT> source_byte_length =
      IntPtrMul(length, IntPtrConstant(ElementsKindToByteSize(kind)));
  static const int32_t fa_base_data_offset =
      FixedArrayBase::kHeaderSize - kHeapObjectTag;
  TNode<IntPtrT> src_offset_start =
      ElementOffsetFromIndex(src_index, kind, fa_base_data_offset);
  TNode<IntPtrT> dst_offset_start =
      ElementOffsetFromIndex(dst_index, kind, fa_base_data_offset);
  TNode<IntPtrT> src_elements_intptr = BitcastTaggedToWord(src_elements);
  TNode<IntPtrT> source_data_ptr =
      IntPtrAdd(src_elements_intptr, src_offset_start);
  TNode<IntPtrT> dst_elements_intptr = BitcastTaggedToWord(dst_elements);
  TNode<IntPtrT> dst_data_ptr =
      IntPtrAdd(dst_elements_intptr, dst_offset_start);
  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());
  CallCFunction(memcpy, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), dst_data_ptr),
                std::make_pair(MachineType::Pointer(), source_data_ptr),
                std::make_pair(MachineType::UintPtr(), source_byte_length));

  if (needs_barrier_check) {
    Goto(&finished);

    BIND(&needs_barrier);
    {
      const TNode<IntPtrT> begin = src_index;
      const TNode<IntPtrT> end = IntPtrAdd(begin, length);
      const TNode<IntPtrT> delta =
          IntPtrMul(IntPtrSub(dst_index, src_index),
                    IntPtrConstant(ElementsKindToByteSize(kind)));
      BuildFastArrayForEach(
          src_elements, kind, begin, end,
          [&](TNode<HeapObject> array, TNode<IntPtrT> offset) {
            const TNode<AnyTaggedT> element = Load<AnyTaggedT>(array, offset);
            const TNode<WordT> delta_offset = IntPtrAdd(offset, delta);
            if (write_barrier == SKIP_WRITE_BARRIER) {
              StoreNoWriteBarrier(MachineRepresentation::kTagged, dst_elements,
                                  delta_offset, element);
            } else {
              Store(dst_elements, delta_offset, element);
            }
          },
          LoopUnrollingMode::kYes, ForEachDirection::kForward);
      Goto(&finished);
    }
    BIND(&finished);
  }
}

void CodeStubAssembler::CopyRange(TNode<HeapObject> dst_object, int dst_offset,
                                  TNode<HeapObject> src_object, int src_offset,
                                  TNode<IntPtrT> length_in_tagged,
                                  WriteBarrierMode mode) {
  // TODO(jgruber): This could be a lot more involved (e.g. better code when
  // write barriers can be skipped). Extend as needed.
  BuildFastLoop<IntPtrT>(
      IntPtrConstant(0), length_in_tagged,
      [=, this](TNode<IntPtrT> index) {
        TNode<IntPtrT> current_src_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(src_offset));
        TNode<Object> value = LoadObjectField(src_object, current_src_offset);
        TNode<IntPtrT> current_dst_offset =
            IntPtrAdd(TimesTaggedSize(index), IntPtrConstant(dst_offset));
        if (mode == SKIP_WRITE_BARRIER) {
          StoreObjectFieldNoWriteBarrier(dst_object, current_dst_offset, value);
        } else {
          StoreObjectField(dst_object, current_dst_offset, value);
        }
      },
      1, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
}

template <typename TIndex>
void CodeStubAssembler::CopyFixedArrayElements(
    ElementsKind from_kind, TNode<FixedArrayBase> from_array,
    ElementsKind to_kind, TNode<FixedArrayBase> to_array,
    TNode<TIndex> first_element, TNode<TIndex> element_count,
    TNode<TIndex> capacity, WriteBarrierMode barrier_mode,
    HoleConversionMode convert_holes, TVariable<BoolT>* var_holes_converted) {
  DCHECK_IMPLIES(var_holes_converted != nullptr,
                 convert_holes == HoleConversionMode::kConvertToUndefined);
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(from_array, from_kind));
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(to_array, to_kind));
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  Comment("[ CopyFixedArrayElements");

  // Typed array elements are not supported.
  DCHECK(!IsTypedArrayElementsKind(from_kind));
  DCHECK(!IsTypedArrayElementsKind(to_kind));

  Label done(this);
  bool from_double_elements = IsDoubleElementsKind(from_kind);
  bool to_double_elements = IsDoubleElementsKind(to_kind);
  bool doubles_to_objects_conversion =
      IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind);
  bool needs_write_barrier =
      doubles_to_objects_conversion ||
      (barrier_mode == UPDATE_WRITE_BARRIER && IsObjectElementsKind(to_kind));
  bool element_offset_matches =
      !needs_write_barrier &&
      (kTaggedSize == kDoubleSize ||
       IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind));
  TNode<UintPtrT> double_hole =
      Is64() ? ReinterpretCast<UintPtrT>(Int64Constant(kHoleNanInt64))
             : ReinterpretCast<UintPtrT>(Int32Constant(kHoleNanLower32));

  // If copying might trigger a GC, we pre-initialize the FixedArray such that
  // it's always in a consistent state.
  if (convert_holes == HoleConversionMode::kConvertToUndefined) {
    DCHECK(IsObjectElementsKind(to_kind));
    // Use undefined for the part that we copy and holes for the rest.
    // Later if we run into a hole in the source we can just skip the writing
    // to the target and are still guaranteed that we get an undefined.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            element_count, RootIndex::kUndefinedValue);
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  } else if (doubles_to_objects_conversion) {
    // Pre-initialized the target with holes so later if we run into a hole in
    // the source we can just skip the writing to the target.
    FillFixedArrayWithValue(to_kind, to_array, IntPtrOrSmiConstant<TIndex>(0),
                            capacity, RootIndex::kTheHoleValue);
  } else if (element_count != capacity) {
    FillFixedArrayWithValue(to_kind, to_array, element_count, capacity,
                            RootIndex::kTheHoleValue);
  }

  TNode<IntPtrT> first_from_element_offset =
      ElementOffsetFromIndex(first_element, from_kind, 0);
  TNode<IntPtrT> limit_offset = Signed(IntPtrAdd(
      first_from_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_from_offset,
            ElementOffsetFromIndex(IntPtrOrSmiAdd(first_element, element_count),
                                   from_kind, first_element_offset));
  // This second variable is used only when the element sizes of source and
  // destination arrays do not match.
  TVARIABLE(IntPtrT, var_to_offset);
  if (element_offset_matches) {
    var_to_offset = var_from_offset.value();
  } else {
    var_to_offset =
        ElementOffsetFromIndex(element_count, to_kind, first_element_offset);
  }

  VariableList vars({&var_from_offset, &var_to_offset}, zone());
  if (var_holes_converted != nullptr) vars.push_back(var_holes_converted);
  Label decrement(this, vars);

  TNode<IntPtrT> to_array_adjusted =
      element_offset_matches
          ? IntPtrSub(BitcastTaggedToWord(to_array), first_from_element_offset)
          : ReinterpretCast<IntPtrT>(to_array);

  Branch(WordEqual(var_from_offset.value(), limit_offset), &done, &decrement);

  BIND(&decrement);
  {
    TNode<IntPtrT> from_offset = Signed(IntPtrSub(
        var_from_offset.value(),
        IntPtrConstant(from_double_elements ? kDoubleSize : kTaggedSize)));
    var_from_offset = from_offset;

    TNode<IntPtrT> to_offset;
    if (element_offset_matches) {
      to_offset = from_offset;
    } else {
      to_offset = IntPtrSub(
          var_to_offset.value(),
          IntPtrConstant(to_double_elements ? kDoubleSize : kTaggedSize));
      var_to_offset = to_offset;
    }

    Label next_iter(this), store_double_hole(this), signal_hole(this);
    Label* if_hole;
    if (convert_holes == HoleConversionMode::kConvertToUndefined) {
      // The target elements array is already preinitialized with undefined
      // so we only need to signal that a hole was found and continue the loop.
      if_hole = &signal_hole;
    } else if (doubles_to_objects_conversion) {
      // The target elements array is already preinitialized with holes, so we
      // can just proceed with the next iteration.
      if_hole = &next_iter;
    } else if (IsDoubleElementsKind(to_kind)) {
      if_hole = &store_double_hole;
    } else {
      // In all the other cases don't check for holes and copy the data as is.
      if_hole = nullptr;
    }

    if (to_double_elements) {
      DCHECK(!needs_write_barrier);
      TNode<Float64T> value = LoadElementAndPrepareForStore<Float64T>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, to_array_adjusted,
                          to_offset, value);
    } else {
      TNode<Object> value = LoadElementAndPrepareForStore<Object>(
          from_array, var_from_offset.value(), from_kind, to_kind, if_hole);
      if (needs_write_barrier) {
        CHECK_EQ(to_array, to_array_adjusted);
        Store(to_array_adjusted, to_offset, value);
      } else {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged,
                                  to_array_adjusted, to_offset, value);
      }
    }

    Goto(&next_iter);

    if (if_hole == &store_double_hole) {
      BIND(&store_double_hole);
      // Don't use doubles to store the hole double, since manipulating the
      // signaling NaN used for the hole in C++, e.g. with base::bit_cast,
      // will change its value on ia32 (the x87 stack is used to return values
      // and stores to the stack silently clear the signalling bit).
      //
      // TODO(danno): When we have a Float32/Float64 wrapper class that
      // preserves double bits during manipulation, remove this code/change
      // this to an indexed Float64 store.
      if (Is64()) {
        StoreNoWriteBarrier(MachineRepresentation::kWord64, to_array_adjusted,
                            to_offset, double_hole);
      } else {
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            to_offset, double_hole);
        StoreNoWriteBarrier(MachineRepresentation::kWord32, to_array_adjusted,
                            IntPtrAdd(to_offset, IntPtrConstant(kInt32Size)),
                            double_hole);
      }
      Goto(&next_iter);
    } else if (if_hole == &signal_hole) {
      // This case happens only when IsObjectElementsKind(to_kind).
      BIND(&signal_hole);
      if (var_holes_converted != nullptr) {
        *var_holes_converted = Int32TrueConstant();
      }
      Goto(&next_iter);
    }

    BIND(&next_iter);
    TNode<BoolT> compare = WordNotEqual(from_offset, limit_offset);
    Branch(compare, &decrement, &done);
  }

  BIND(&done);
  Comment("] CopyFixedArrayElements");
}

TNode<FixedArray> CodeStubAssembler::HeapObjectToFixedArray(
    TNode<HeapObject> base, Label* cast_fail) {
  Label fixed_array(this);
  TNode<Map> map = LoadMap(base);
  GotoIf(TaggedEqual(map, FixedArrayMapConstant()), &fixed_array);
  GotoIf(TaggedNotEqual(map, FixedCOWArrayMapConstant()), cast_fail);
  Goto(&fixed_array);
  BIND(&fixed_array);
  return UncheckedCast<FixedArray>(base);
}

void CodeStubAssembler::CopyPropertyArrayValues(TNode<HeapObject> from_array,
                                                TNode<PropertyArray> to_array,
                                                TNode<IntPtrT> property_count,
                                                WriteBarrierMode barrier_mode,
                                                DestroySource destroy_source) {
  CSA_SLOW_DCHECK(this, Word32Or(IsPropertyArray(from_array),
                                 IsEmptyFixedArray(from_array)));
  Comment("[ CopyPropertyArrayValues");

  bool needs_write_barrier = barrier_mode == UPDATE_WRITE_BARRIER;

  if (destroy_source == DestroySource::kNo) {
    // PropertyArray may contain mutable HeapNumbers, which will be cloned on
    // the heap, requiring a write barrier.
    needs_write_barrier = true;
  }

  TNode<IntPtrT> start = IntPtrConstant(0);
  ElementsKind kind = PACKED_ELEMENTS;
  BuildFastArrayForEach(
      from_array, kind, start, property_count,
      [this, to_array, needs_write_barrier, destroy_source](
          TNode<HeapObject> array, TNode<IntPtrT> offset) {
        TNode<AnyTaggedT> value = Load<AnyTaggedT>(array, offset);

        if (destroy_source == DestroySource::kNo) {
          value = CloneIfMutablePrimitive(CAST(value));
        }

        if (needs_write_barrier) {
          Store(to_array, offset, value);
        } else {
          StoreNoWriteBarrier(MachineRepresentation::kTagged, to_array, offset,
                              value);
        }
      },
      LoopUnrollingMode::kYes);

#ifdef DEBUG
  // Zap {from_array} if the copying above has made it invalid.
  if (destroy_source == DestroySource::kYes) {
    Label did_zap(this);
    GotoIf(IsEmptyFixedArray(from_array), &did_zap);
    FillPropertyArrayWithUndefined(CAST(from_array), start, property_count);

    Goto(&did_zap);
    BIND(&did_zap);
  }
#endif
  Comment("] CopyPropertyArrayValues");
}

TNode<FixedArrayBase> CodeStubAssembler::CloneFixedArray(
    TNode<FixedArrayBase> source, ExtractFixedArrayFlags flags) {
  return ExtractFixedArray(
      source, std::optional<TNode<BInt>>(IntPtrOrSmiConstant<BInt>(0)),
      std::optional<TNode<BInt>>(std::nullopt),
      std::optional<TNode<BInt>>(std::nullopt), flags);
}

template <>
TNode<Object> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(!IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    TNode<Float64T> value =
        LoadDoubleWithHoleCheck(array, offset, if_hole, MachineType::Float64());
    return AllocateHeapNumberWithValue(value);
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    return value;
  }
}

template <>
TNode<Float64T> CodeStubAssembler::LoadElementAndPrepareForStore(
    TNode<FixedArrayBase> array, TNode<IntPtrT> offset, ElementsKind from_kind,
    ElementsKind to_kind, Label* if_hole) {
  CSA_DCHECK(this, IsFixedArrayWithKind(array, from_kind));
  DCHECK(IsDoubleElementsKind(to_kind));
  if (IsDoubleElementsKind(from_kind)) {
    return LoadDoubleWithHoleCheck(array, offset, if_hole,
                                   MachineType::Float64());
  } else {
    TNode<Object> value = Load<Object>(array, offset);
    if (if_hole) {
      GotoIf(TaggedEqual(value, TheHoleConstant()), if_hole);
    }
    if (IsSmiElementsKind(from_kind)) {
      return SmiToFloat64(CAST(value));
    }
    return LoadHeapNumberValue(CAST(value));
  }
}

template <typename TIndex>
TNode<TIndex> CodeStubAssembler::CalculateNewElementsCapacity(
    TNode<TIndex> old_capacity) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT old_capacity is allowed");
  Comment("TryGrowElementsCapacity");
  TNode<TIndex> half_old_capacity = WordOrSmiShr(old_capacity, 1);
  TNode<TIndex> new_capacity = IntPtrOrSmiAdd(half_old_capacity, old_capacity);
  TNode<TIndex> padding =
      IntPtrOrSmiConstant<TIndex>(JSObject::kMinAddedElementsCapacity);
  return IntPtrOrSmiAdd(new_capacity, padding);
}

template V8_EXPORT_PRIVATE TNode<IntPtrT>
    CodeStubAssembler::CalculateNewElementsCapacity<IntPtrT>(TNode<IntPtrT>);
template V8_EXPORT_PRIVATE TNode<Smi>
    CodeStubAssembler::CalculateNewElementsCapacity<Smi>(TNode<Smi>);

TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<Smi> key, Label* bailout) {
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));
  TNode<Smi> capacity = LoadFixedArrayBaseLength(elements);

  return TryGrowElementsCapacity(object, elements, kind,
                                 TaggedToParameter<BInt>(key),
                                 TaggedToParameter<BInt>(capacity), bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::TryGrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<TIndex> key, TNode<TIndex> capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT key and capacity nodes are allowed");
  Comment("TryGrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, kind));

  // If the gap growth is too big, fall back to the runtime.
  TNode<TIndex> max_gap = IntPtrOrSmiConstant<TIndex>(JSObject::kMaxGap);
  TNode<TIndex> max_capacity = IntPtrOrSmiAdd(capacity, max_gap);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(key, max_capacity), bailout);

  // Calculate the capacity of the new backing store.
  TNode<TIndex> new_capacity = CalculateNewElementsCapacity(
      IntPtrOrSmiAdd(key, IntPtrOrSmiConstant<TIndex>(1)));

  return GrowElementsCapacity(object, elements, kind, kind, capacity,
                              new_capacity, bailout);
}

template <typename TIndex>
TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements,
    ElementsKind from_kind, ElementsKind to_kind, TNode<TIndex> capacity,
    TNode<TIndex> new_capacity, Label* bailout) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT capacities are allowed");
  Comment("[ GrowElementsCapacity");
  CSA_SLOW_DCHECK(this, IsFixedArrayWithKindOrEmpty(elements, from_kind));

  // If size of the allocation for the new capacity doesn't fit in a page
  // that we can bump-pointer allocate from, fall back to the runtime.
  int max_size = FixedArrayBase::GetMaxLengthForNewSpaceAllocation(to_kind);
  GotoIf(UintPtrOrSmiGreaterThanOrEqual(new_capacity,
                                        IntPtrOrSmiConstant<TIndex>(max_size)),
         bailout);

  // Allocate the new backing store.
  TNode<FixedArrayBase> new_elements =
      AllocateFixedArray(to_kind, new_capacity);

  // Copy the elements from the old elements store to the new.
  // The size-check above guarantees that the |new_elements| is allocated
  // in new space so we can skip the write barrier.
  CopyFixedArrayElements(from_kind, elements, to_kind, new_elements, capacity,
                         new_capacity, SKIP_WRITE_BARRIER);

  StoreObjectField(object, JSObject::kElementsOffset, new_elements);
  Comment("] GrowElementsCapacity");
  return new_elements;
}

template TNode<FixedArrayBase> CodeStubAssembler::GrowElementsCapacity<IntPtrT>(
    TNode<HeapObject>, TNode<FixedArrayBase>, ElementsKind, ElementsKind,
    TNode<IntPtrT>, TNode<IntPtrT>, compiler::CodeAssemblerLabel*);

namespace {

// Helper function for folded memento allocation.
// Memento objects are designed to be put right after the objects they are
// tracking on. So memento allocations have to be folded together with previous
// object allocations.
TNode<HeapObject> InnerAllocateMemento(CodeStubAssembler* csa,
                                       TNode<HeapObject> previous,
                                       TNode<IntPtrT> offset) {
  return csa->UncheckedCast<HeapObject>(csa->BitcastWordToTagged(
      csa->IntPtrAdd(csa->BitcastTaggedToWord(previous), offset)));
}

}  // namespace

void CodeStubAssembler::InitializeAllocationMemento(
    TNode<HeapObject> base, TNode<IntPtrT> base_allocation_size,
    TNode<AllocationSite> allocation_site) {
  DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
  Comment("[Initialize AllocationMemento");
  TNode<HeapObject> memento =
      InnerAllocateMemento(this, base, base_allocation_size);
  StoreMapNoWriteBarrier(memento, RootIndex::kAllocationMementoMap);
  StoreObjectFieldNoWriteBarrier(
      memento, AllocationMemento::kAllocationSiteOffset, allocation_site);
  if (v8_flags.allocation_site_pretenuring) {
    TNode<Int32T> count = LoadObjectField<Int32T>(
        allocation_site, AllocationSite::kPretenureCreateCountOffset);

    TNode<Int32T> incremented_count = Int32Add(count, Int32Constant(1));
    StoreObjectFieldNoWriteBarrier(allocation_site,
                                   AllocationSite::kPretenureCreateCountOffset,
                                   incremented_count);
  }
  Comment("]");
}

TNode<IntPtrT> CodeStubAssembler::TryTaggedToInt32AsIntPtr(
    TNode<Object> acc, Label* if_not_possible) {
  TVARIABLE(IntPtrT, acc_intptr);
  Label is_not_smi(this), have_int32(this);

  GotoIfNot(TaggedIsSmi(acc), &is_not_smi);
  acc_intptr = SmiUntag(CAST(acc));
  Goto(&have_int32);

  BIND(&is_not_smi);
  GotoIfNot(IsHeapNumber(CAST(acc)), if_not_possible);
  TNode<Float64T> value = LoadHeapNumberValue(CAST(acc));
  TNode<Int32T> value32 = RoundFloat64ToInt32(value);
  TNode<Float64T> value64 = ChangeInt32ToFloat64(value32);
  GotoIfNot(Float64Equal(value, value64), if_not_possible);
  acc_intptr = ChangeInt32ToIntPtr(value32);
  Goto(&have_int32);

  BIND(&have_int32);
  return acc_intptr.value();
}

TNode<Float64T> CodeStubAssembler::TryTaggedToFloat64(
    TNode<Object> value, Label* if_valueisnotnumber) {
  return Select<Float64T>(
      TaggedIsSmi(value), [&]() { return SmiToFloat64(CAST(value)); },
      [&]() {
        GotoIfNot(IsHeapNumber(CAST(value)), if_valueisnotnumber);
        return LoadHeapNumberValue(CAST(value));
      });
}

TNode<Float64T> CodeStubAssembler::TruncateTaggedToFloat64(
    TNode<Context> context, TNode<Object> value) {
  // We might need to loop once due to ToNumber conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Float64T, var_result);
  Label loop(this, &var_value), done_loop(this, &var_result);
  Goto(&loop);
  BIND(&loop);
  {
    Label if_valueisnotnumber(this, Label::kDeferred);

    // Load the current {value}.
    value = var_value.value();

    // Convert {value} to Float64 if it is a number and convert it to a number
    // otherwise.
    var_result = TryTaggedToFloat64(value, &if_valueisnotnumber);
    Goto(&done_loop);

    BIND(&if_valueisnotnumber);
    {
      // Convert the {value} to a Number first.
      var_value = CallBuiltin(Builtin::kNonNumberToNumber, context, value);
      Goto(&loop);
    }
  }
  BIND(&done_loop);
  return var_result.value();
}

TNode<Word32T> CodeStubAssembler::TruncateTaggedToWord32(TNode<Context> context,
                                                         TNode<Object> value) {
  TVARIABLE(Word32T, var_result);
  Label done(this);
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumber>(
      context, value, &done, &var_result, IsKnownTaggedPointer::kNo, {});
  BIND(&done);
  return var_result.value();
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}.
void CodeStubAssembler::TaggedToWord32OrBigInt(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo, {},
      if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {value} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, value, if_number, var_word32, IsKnownTaggedPointer::kNo,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

// Truncate {pointer} to word32 and jump to {if_number} if it is a Number,
// or find that it is a BigInt and jump to {if_bigint}. In either case,
// store the type feedback in {var_feedback}.
void CodeStubAssembler::TaggedPointerToWord32OrBigIntWithFeedback(
    TNode<Context> context, TNode<HeapObject> pointer, Label* if_number,
    TVariable<Word32T>* var_word32, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint, const FeedbackValues& feedback) {
  TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumeric>(
      context, pointer, if_number, var_word32, IsKnownTaggedPointer::kYes,
      feedback, if_bigint, if_bigint64, var_maybe_bigint);
}

template <Object::Conversion conversion>
void CodeStubAssembler::TaggedToWord32OrBigIntImpl(
    TNode<Context> context, TNode<Object> value, Label* if_number,
    TVariable<Word32T>* var_word32,
    IsKnownTaggedPointer is_known_tagged_pointer,
    const FeedbackValues& feedback, Label* if_bigint, Label* if_bigint64,
    TVariable<BigInt>* var_maybe_bigint) {
  // We might need to loop after conversion.
  TVARIABLE(Object, var_value, value);
  TVARIABLE(Object, var_exception);
  OverwriteFeedback(feedback.var_feedback, BinaryOperationFeedback::kNone);
  VariableList loop_vars({&var_value}, zone());
  if (feedback.var_feedback != nullptr) {
    loop_vars.push_back(feedback.var_feedback);
  }
  Label loop(this, loop_vars);
  Label if_exception(this, Label::kDeferred);
  if (is_known_tagged_pointer == IsKnownTaggedPointer::kNo) {
    GotoIf(TaggedIsNotSmi(value), &loop);

    // {value} is a Smi.
    *var_word32 = SmiToInt32(CAST(value));
    CombineFeedback(feedback.var_feedback,
                    BinaryOperationFeedback::kSignedSmall);
    Goto(if_number);
  } else {
    Goto(&loop);
  }
  BIND(&loop);
  {
    value = var_value.value();
    Label not_smi(this), is_heap_number(this), is_oddball(this),
        maybe_bigint64(this), is_bigint(this), check_if_smi(this);

    TNode<HeapObject> value_heap_object = CAST(value);
    TNode<Map> map = LoadMap(value_heap_object);
    GotoIf(IsHeapNumberMap(map), &is_heap_number);
    TNode<Uint16T> instance_type = LoadMapInstanceType(map);
    if (conversion == Object::Conversion::kToNumeric) {
      if (Is64() && if_bigint64) {
        GotoIf(IsBigIntInstanceType(instance_type), &maybe_bigint64);
      } else {
        GotoIf(IsBigIntInstanceType(instance_type), &is_bigint);
      }
    }

    // Not HeapNumber (or BigInt if conversion == kToNumeric).
    {
      if (feedback.var_feedback != nullptr) {
        // We do not require an Or with earlier feedback here because once we
        // convert the value to a Numeric, we cannot reach this path. We can
        // only reach this path on the first pass when the feedback is kNone.
        CSA_DCHECK(this, SmiEqual(feedback.var_feedback->value(),
                                  SmiConstant(BinaryOperationFeedback::kNone)));
      }
      GotoIf(InstanceTypeEqual(instance_type, ODDBALL_TYPE), &is_oddball);
      // Not an oddball either -> convert.
      auto builtin = conversion == Object::Conversion::kToNumeric
                         ? Builtin::kNonNumberToNumeric
                         : Builtin::kNonNumberToNumber;
      if (feedback.var_feedback != nullptr) {
        ScopedExceptionHandler handler(this, &if_exception, &var_exception);
        var_value = CallBuiltin(builtin, context, value);
      } else {
        var_value = CallBuiltin(builtin, context, value);
      }
      OverwriteFeedback(feedback.var_feedback, BinaryOperationFeedback::kAny);
      Goto(&check_if_smi);

      if (feedback.var_feedback != nullptr) {
        BIND(&if_exception);
        DCHECK(feedback.slot != nullptr);
        DCHECK(feedback.maybe_feedback_vector != nullptr);
        UpdateFeedback(SmiConstant(BinaryOperationFeedback::kAny),
                       (*feedback.maybe_feedback_vector)(), *feedback.slot,
                       feedback.update_mode);
        CallRuntime(Runtime::kReThrow, context, var_exception.value());
        Unreachable();
      }

      BIND(&is_oddball);
      var_value =
          LoadObjectField(value_heap_object, offsetof(Oddball, to_number_));
      OverwriteFeedback(feedback.var_feedback,
                        BinaryOperationFeedback::kNumberOrOddball);
      Goto(&check_if_smi);
    }

    BIND(&is_heap_number);
    *var_word32 = TruncateHeapNumberValueToWord32(CAST(value));
    CombineFeedback(feedback.var_feedback, BinaryOperationFeedback::kNumber);
    Goto(if_number);

    if (conversion == Object::Conversion::kToNumeric) {
      if (Is64() && if_bigint64) {
        BIND(&maybe_bigint64);
        GotoIfLargeBigInt(CAST(value), &is_bigint);
        if (var_maybe_bigint) {
          *var_maybe_bigint = CAST(value);
        }
        CombineFeedback(feedback.var_feedback,
                        BinaryOperationFeedback::kBigInt64);
        Goto(if_bigint64);
      }

      BIND(&is_bigint);
      if (var_maybe_bigint) {
        *var_maybe_bigint = CAST(value);
      }
      CombineFeedback(feedback.var_feedback, BinaryOperationFeedback::kBigInt);
      Goto(if_bigint);
    }

    BIND(&check_if_smi);
    value = var_value.value();
    GotoIf(TaggedIsNotSmi(value), &loop);

    // {value} is a Smi.
    *var_word32 = SmiToInt32(CAST(value));
    CombineFeedback(feedback.var_feedback,
                    BinaryOperationFeedback::kSignedSmall);
    Goto(if_number);
  }
}

TNode<Int32T> CodeStubAssembler::TruncateNumberToWord32(TNode<Number> number) {
  TVARIABLE(Int32T, var_result);
  Label done(this), if_heapnumber(this);
  GotoIfNot(TaggedIsSmi(number), &if_heapnumber);
  var_result = SmiToInt32(CAST(number));
  Goto(&done);

  BIND(&if_heapnumber);
  TNode<Float64T> value = LoadHeapNumberValue(CAST(number));
  var_result = Signed(TruncateFloat64ToWord32(value));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<Int32T> CodeStubAssembler::TruncateHeapNumberValueToWord32(
    TNode<HeapNumber> object) {
  TNode<Float64T> value = LoadHeapNumberValue(object);
  return Signed(TruncateFloat64ToWord32(value));
}

TNode<Smi> CodeStubAssembler::TryHeapNumberToSmi(TNode<HeapNumber> number,
                                                 Label* not_smi) {
  TNode<Float64T> value = LoadHeapNumberValue(number);
  return TryFloat64ToSmi(value, not_smi);
}

TNode<Smi> CodeStubAssembler::TryFloat32ToSmi(TNode<Float32T> value,
                                              Label* not_smi) {
  TNode<Int32T> ivalue = TruncateFloat32ToInt32(value);
  TNode<Float32T> fvalue = RoundInt32ToFloat32(ivalue);

  Label if_int32(this);

  GotoIfNot(Float32Equal(value, fvalue), not_smi);
  GotoIfNot(Word32Equal(ivalue, Int32Constant(0)), &if_int32);
  // if (value == -0.0)
  Branch(Int32LessThan(UncheckedCast<Int32T>(BitcastFloat32ToInt32(value)),
                       Int32Constant(0)),
         not_smi, &if_int32);

  BIND(&if_int32);
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(ivalue));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(ivalue, ivalue);
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, not_smi);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(Projection<0>(pair)));
  }
}

TNode<Smi> CodeStubAssembler::TryFloat64ToSmi(TNode<Float64T> value,
                                              Label* not_smi) {
  TNode<Int32T> value32 = RoundFloat64ToInt32(value);
  TNode<Float64T> value64 = ChangeInt32ToFloat64(value32);

  Label if_int32(this);
  GotoIfNot(Float64Equal(value, value64), not_smi);
  GotoIfNot(Word32Equal(value32, Int32Constant(0)), &if_int32);
  Branch(Int32LessThan(UncheckedCast<Int32T>(Float64ExtractHighWord32(value)),
                       Int32Constant(0)),
         not_smi, &if_int32);

  TVARIABLE(Number, var_result);
  BIND(&if_int32);
  if (SmiValuesAre32Bits()) {
    return SmiTag(ChangeInt32ToIntPtr(value32));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(value32, value32);
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, not_smi);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(Projection<0>(pair)));
  }
}

TNode<Float16RawBitsT> CodeStubAssembler::TruncateFloat64ToFloat16(
    TNode<Float64T> value) {
  TVARIABLE(Float16RawBitsT, float16_out);
  Label truncate_op_supported(this), truncate_op_fallback(this),
      return_out(this);
  // See Float64Ceil for the reason there is a branch for the static constant
  // (PGO profiles).
  Branch(UniqueInt32Constant(IsT
```