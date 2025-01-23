Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Initial Understanding and Core Task Identification:**

The first step is to recognize the context: a C++ source file (`.cc`) for V8's code generation, specifically the `CodeStubAssembler`. The prompt asks for its functionality, how it relates to JavaScript, examples, logical reasoning, common errors, and a summary of this specific part (part 7 of 23). The crucial additional piece of information is the note about `.tq` files and Torque, which immediately suggests this isn't a Torque file.

**2. High-Level Functionality Scan:**

I'd quickly scan the code for keywords and patterns that indicate the general purpose. Terms like `AllocateJSArray`, `AllocateFixedArray`, `ExtractFixedArray`, `CopyElements`, `Store`, `Load`, `Label`, `GotoIf`, `Branch`, and `CallRuntime` stand out. These suggest memory management, array manipulation, conditional execution, and calls to runtime functions. The `CodeStubAssembler` name itself hints at generating low-level code stubs.

**3. Deeper Dive into Key Functions:**

I'd then focus on the most prominent functions.

* **`CreateJSArray()`:** This clearly deals with creating JavaScript arrays. The logic involving holey arrays (`holey_extract`), element kind conversion, and allocation suggests it handles different array types and potential optimizations.

* **`AllocateFixedArray()`:**  This is about allocating fixed-size arrays, which are fundamental building blocks in V8's internal representation of arrays and other data structures. The size checks and `kMaxLength` constant are important details.

* **`ExtractToFixedArray()` and `ExtractFixedArray()`:** These functions are about creating new fixed arrays based on existing ones, potentially copying elements. The flags (`ExtractFixedArrayFlags`), hole handling (`HoleConversionMode`), and special handling for COW arrays (`FixedCOWArrayMapConstant`) are key features.

* **`CopyElements()` and `MoveElements()`:** These handle the low-level copying of data within arrays, with considerations for write barriers (for garbage collection).

* **`FillFixedArrayWithValue()`:**  Initializing array elements with a specific value.

**4. Identifying Relationships to JavaScript:**

The prompt specifically asks about the connection to JavaScript. The function `CreateJSArray()` is the most direct link. I'd think about common JavaScript array operations that this code might support:

* Array creation (e.g., `[]`, `new Array(n)`)
* Array slicing/copying (e.g., `arr.slice()`)
* Array manipulation that might involve converting between holey and packed arrays.

**5. Crafting JavaScript Examples:**

Based on the identified JavaScript relationships, I'd create simple, illustrative examples. The examples for array creation, slicing, and hole handling are direct results of the code's functionality.

**6. Logical Reasoning - Input and Output:**

For logical reasoning, I'd choose a relatively simple but illustrative function, like `ExtractFixedArray`. I'd define a specific input (a fixed array with certain properties) and trace the code's likely path based on the input. This helps demonstrate the function's behavior and potential outputs. Considering both packed and holey array scenarios is important.

**7. Common Programming Errors:**

Thinking about how these low-level operations relate to user-level JavaScript helps identify potential errors. Trying to access out-of-bounds elements or unexpectedly encountering `undefined` due to hole conversion are relevant examples.

**8. Addressing the `.tq` Note:**

It's essential to explicitly state that the given code is C++ (`.cc`), not Torque (`.tq`), based on the file extension.

**9. Summarizing Functionality (Part 7 of 23):**

The prompt highlights this is part 7 of a larger file. Based on the functions analyzed, I'd summarize the focus of this section: primarily on the creation and manipulation of arrays (both JavaScript arrays and their underlying fixed-size storage), including handling different array types (packed, holey, double arrays, COW arrays) and memory management considerations.

**10. Structuring the Response:**

Finally, I'd organize the information logically, using headings and bullet points for clarity. The structure should mirror the prompt's requests.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `CodeStubAssembler` is just about creating simple function calls.
* **Correction:**  Looking deeper, it's evident it's involved in much more complex array management, including memory allocation and copying.

* **Initial thought:**  Focus heavily on the assembly aspects.
* **Correction:** While important, the prompt also asks about the JavaScript connection, so balancing the low-level details with the high-level implications is crucial.

* **Initial thought:**  Only give one JavaScript example.
* **Correction:** Providing multiple examples for different functionalities (creation, slicing, holes) makes the explanation more comprehensive.

By following this structured approach, combining high-level understanding with detailed code analysis, and constantly relating the C++ code back to JavaScript concepts, it's possible to generate a thorough and accurate response.
好的，让我们来分析一下这段 V8 源代码 `v8/src/codegen/code-stub-assembler.cc` 的第 7 部分。

**功能概览:**

这段代码主要集中在 **数组的创建、分配和内容提取** 上，特别是针对 `JSArray` 和底层的 `FixedArrayBase` 以及 `FixedDoubleArray`。它提供了多种用于创建和操作这些数组的底层方法，并考虑了数组的不同元素类型（如 packed, holey, double）。

**详细功能分解:**

1. **`CreateJSArray(TNode<Context> context, TNode<JSArray> array, HoleConversionMode convert_holes, TNode<AllocationSite> allocation_site)`:**
   - **功能:**  创建一个新的 `JSArray`，其内容是现有 `array` 的浅拷贝。
   - **Hole 处理:**  关键在于 `HoleConversionMode` 参数，它决定了如何处理源数组中的空洞（holes，即没有被赋值的索引）。
     - `HoleConversionMode::kConvertToUndefined`: 将空洞转换为 `undefined` 值。
     - `HoleConversionMode::kDontConvert`: 保留空洞。
   - **元素类型:**  根据源数组的元素类型 (`elements_kind`) 来决定新数组的元素类型。如果需要转换空洞，并且源数组是 holey 的，则新数组通常会变为 packed 元素类型。
   - **内存分配:**  为新数组的元素分配 `FixedArrayBase` 或 `FixedDoubleArray`。
   - **示例 (JavaScript):**
     ```javascript
     const arr1 = [1, , 3]; // arr1 有一个空洞
     const arr2 = [...arr1]; // 使用展开运算符创建 arr1 的浅拷贝
     console.log(arr2); // 输出: [ 1, undefined, 3 ]，空洞被转换为 undefined

     const arr3 = arr1.slice(); // 使用 slice 创建浅拷贝
     console.log(arr3); // 输出: [ 1, <1 empty item>, 3 ]，空洞被保留
     ```
   - **代码逻辑推理 (假设输入与输出):**
     - **假设输入:** `array` 是 `[1, , 3]` (JSArray，HOLEY_ELEMENTS)，`convert_holes` 是 `HoleConversionMode::kConvertToUndefined`。
     - **输出:** 新的 `JSArray`，其元素为 `[1, undefined, 3]` (JSArray，PACKED_ELEMENTS)。
     - **假设输入:** `array` 是 `[1, , 3]` (JSArray，HOLEY_ELEMENTS)，`convert_holes` 是 `HoleConversionMode::kDontConvert`。
     - **输出:** 新的 `JSArray`，其内部 `elements` 可能仍然是 holey 的。

2. **`AllocateFixedArray(ElementsKind kind, TNode<TIndex> capacity, AllocationFlags flags, std::optional<TNode<Map>> fixed_array_map)`:**
   - **功能:**  分配一个指定 `kind` (元素类型) 和 `capacity` 的 `FixedArrayBase` 或 `FixedDoubleArray`。
   - **容量限制:**  检查容量是否超过最大允许长度。
   - **内存分配:**  使用 `Allocate()` 方法分配内存。
   - **Map 设置:**  设置新分配的数组的 `Map` (对象类型信息)。
   - **长度设置:**  设置数组的长度。
   - **示例 (JavaScript - 虽然不能直接调用此底层方法，但其效果体现在数组的创建上):**
     ```javascript
     const arr = new Array(10); // 内部会分配一个容量为 10 的 FixedArray
     const floatArr = new Float64Array(5); // 内部会分配一个容量为 5 的 FixedDoubleArray
     ```
   - **代码逻辑推理 (假设输入与输出):**
     - **假设输入:** `kind` 是 `PACKED_SMI_ELEMENTS`，`capacity` 是 5。
     - **输出:**  一个指向新分配的 `FixedArray` 的指针，其长度字段为 5。

3. **`ExtractToFixedArray(...)` 和 `ExtractFixedArray(...)`:**
   - **功能:**  从现有的 `FixedArrayBase` 或 `FixedDoubleArray` 中提取一部分元素创建一个新的 `FixedArray` 或 `FixedDoubleArray`。
   - **参数:** 允许指定提取的起始位置 (`first`)，数量 (`count`)，以及新数组的容量 (`capacity`)。
   - **COW (Copy-on-Write) 优化:**  对于 `FixedCOWArrayMap`，会尝试避免实际复制，除非必要（例如需要修改内容或提取部分元素）。
   - **Hole 处理:**  `ExtractToFixedArray` 也会根据 `HoleConversionMode` 处理空洞。
   - **元素类型转换:**  如果需要，可以将 `FixedDoubleArray` 的内容提取到 `FixedArray` 中（此时空洞会转换为 `undefined`）。
   - **示例 (JavaScript):**
     ```javascript
     const arr = [1, 2, 3, 4, 5];
     const slice1 = arr.slice(1, 4); // 提取索引 1 到 3 的元素，结果为 [2, 3, 4]
     ```
   - **代码逻辑推理 (假设输入与输出):**
     - **假设输入:** `source` 是 `[1, 2, 3, 4, 5]` (FixedArray)，`first` 是 1，`count` 是 3，`capacity` 是 3。
     - **输出:**  一个新的 `FixedArray`，其内容为 `[2, 3, 4]`。
     - **假设输入:** `source` 是 `[1.1, , 3.3]` (FixedDoubleArray，包含空洞)，`convert_holes` 是 `HoleConversionMode::kConvertToUndefined`。
     - **输出:**  一个新的 `FixedArray`，其内容为 `[1.1, undefined, 3.3]`。

4. **`AllocatePropertyArray(TNode<IntPtrT> capacity)`:**
   - **功能:**  分配一个 `PropertyArray`，用于存储对象的属性。
   - **容量设置:**  根据 `capacity` 参数设置数组的初始容量。

5. **`FillPropertyArrayWithUndefined(...)` 和 `FillFixedArrayWithValue(...)`:**
   - **功能:**  用特定的值（例如 `undefined` 或洞 `the_hole`）填充数组的指定范围。
   - **优化:**  `BuildFastArrayForEach` 可能包含循环展开等优化。

6. **`StoreDoubleHole(...)` 和 `StoreFixedDoubleArrayHole(...)`:**
   - **功能:**  在 `FixedDoubleArray` 中存储表示空洞的特殊 NaN 值。

7. **`FillFixedArrayWithSmiZero(...)` 和 `FillFixedDoubleArrayWithZero(...)`:**
   - **功能:**  使用 `memset` 等底层函数高效地将 `FixedArray` 或 `FixedDoubleArray` 的指定范围填充为零值。

8. **`MoveElements(...)` 和 `CopyElements(...)`:**
   - **功能:**  在数组内部移动或复制元素。
   - **写屏障 (Write Barrier):**  考虑了垃圾回收的写屏障，确保在移动或复制对象引用时，垃圾回收器能正确追踪。对于双精度浮点数数组，通常不需要写屏障。
   - **优化:**  可能使用 `memmove` 或 `memcpy` 等高效的内存操作函数。

**与 JavaScript 的关系:**

这段代码是 V8 引擎实现 JavaScript 数组功能的底层基础。JavaScript 中的数组操作，例如：

- 创建数组 (`[]`, `new Array()`)
- 访问数组元素 (`arr[i]`)
- 修改数组元素 (`arr[i] = value`)
- 数组方法 (`slice()`, `map()`, `filter()`, 等等)

最终都会通过 V8 的内部机制调用到类似这样的底层代码。例如，`Array.prototype.slice()` 的实现就可能涉及到 `CreateJSArray` 或 `ExtractFixedArray`。

**用户常见的编程错误 (虽然此代码是底层实现，但可以反映一些 JavaScript 错误):**

- **访问未初始化的数组元素 (导致读取到空洞):**
  ```javascript
  const arr = new Array(5);
  console.log(arr[0]); // 输出: undefined (因为数组是稀疏的，可能包含空洞)
  ```
- **修改或访问超出数组边界的元素:**  虽然这段代码中有限制，但在 JavaScript 中会导致 `undefined` 或错误。
- **假设数组总是 packed 的:**  在某些操作后，数组可能会变成 holey 的，导致性能下降或意外行为。

**代码逻辑推理 (更复杂的例子):**

**假设输入:** 一个 JavaScript 数组 `arr = [1, , 3, 4.5]`。

1. 当你执行 `arr.slice(1)` 时，V8 可能会调用类似 `CreateJSArray` 或 `ExtractFixedArray` 的函数。
2. 如果 V8 决定创建一个新的 packed 数组，并且需要转换空洞，那么 `convert_holes` 参数会被设置为 `HoleConversionMode::kConvertToUndefined`。
3. 代码会加载源数组 `arr` 的元素，检测到索引 1 处是空洞。
4. 新的 `FixedArray` 或 `FixedDoubleArray` 会被分配。
5. 元素会被复制到新的数组中，空洞会被替换为 `undefined`。
6. 最终返回一个新的 `JSArray`，其内容可能是 `[undefined, 3, 4.5]` (如果元素类型统一为 double) 或需要更复杂的类型处理。

**第 7 部分的功能归纳:**

这段代码是 V8 代码生成器中处理 **JavaScript 数组创建、分配、复制和元素操作** 的核心部分。它提供了用于创建和操作 `JSArray` 以及其底层存储结构 (`FixedArrayBase`, `FixedDoubleArray`) 的基本工具。这部分代码特别关注了 **不同元素类型的处理 (packed, holey, double)**，以及在数组复制和提取过程中 **如何处理空洞**，并且考虑了 **内存分配、容量限制和垃圾回收的写屏障** 等底层细节。它为实现各种 JavaScript 数组操作提供了必要的 Building Blocks。

如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那它将是 V8 的 Torque 源代码。Torque 是一种用于 V8 的领域特定语言，用于定义运行时函数的实现。然而，当前文件以 `.cc` 结尾，表明它是 C++ 源代码。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  TNo
```