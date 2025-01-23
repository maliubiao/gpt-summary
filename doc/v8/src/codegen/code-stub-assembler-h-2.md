Response:
My thinking process to arrive at the summary of the `code-stub-assembler.h` file went through these stages:

1. **Initial Skim and Keyword Identification:** I quickly scanned the provided code snippet, looking for recurring keywords and patterns. Words like `Load`, `Store`, `Allocate`, `Check`, `Array`, `Object`, `Map`, `FixedArray`, `JSArray`, `Context`, `Function`, `BigInt`, `String`, `Element`, etc., immediately stood out. These provided a high-level understanding of the operations being performed.

2. **Categorization of Functionality:** Based on the keywords, I started mentally grouping related functions. For instance, functions starting with `Load` seemed to be about retrieving data, `Store` about setting data, and `Allocate` about creating new objects. Specific data structures like `FixedArray`, `JSArray`, and `Map` also formed distinct categories.

3. **Identifying Core Abstractions:** I noticed functions dealing with memory management (allocation), data access (loading and storing), type checking (e.g., `FixedArrayBoundsCheck`), and object manipulation (e.g., loading/storing fields, map operations). These represent the core abstractions provided by the assembler.

4. **Inferring Purpose from Names:**  Function names are often self-explanatory. `LoadArrayLength`, `StoreObjectField`, `AllocateHeapNumber`, `FixedArrayBoundsCheck` clearly indicate their purpose. This helped in confirming my initial categorization and adding more detail.

5. **Recognizing Common Patterns:** I observed patterns in function signatures, particularly the use of `TNode<>` and specific types like `IntPtrT`, `UintPtrT`, `Smi`, `Object`, etc. This hinted at the underlying type system and the low-level nature of the assembler. The presence of `Label*` parameters suggested control flow mechanisms (branching, jumps).

6. **Focusing on the "Why":** I moved beyond just listing the functions and started thinking about *why* these functions exist. The functions related to arrays (loading, storing, bounds checking) are clearly for working with array data. The functions related to `Map` and object fields are for managing object properties and structure. The functions dealing with `Context` are for accessing and manipulating the execution environment.

7. **Considering the Context (Filename and Path):** The filename `code-stub-assembler.h` and path `v8/src/codegen/` strongly suggested that this code is part of V8's code generation process. "Code stubs" are small pieces of generated machine code. This provided a crucial context for understanding the purpose of the assembler – it's a tool for building these code stubs.

8. **Addressing Specific Instructions:** I specifically looked for mentions of ".tq" files and JavaScript relevance, as requested by the prompt. The prompt itself provided the information about `.tq` files. The connection to JavaScript is implicit since V8 is a JavaScript engine, but specific examples would require analyzing the *usage* of the assembler, which isn't present in the header file itself. I noted this limitation.

9. **Handling Logic and Assumptions:** The request about "code logic inference" and "assumptions" is more about the *usage* of these functions than the header file's definition. I recognized that I could only make general assumptions based on the function names (e.g., `FixedArrayBoundsCheck` assumes an array and an index).

10. **Considering Common Errors:**  The prompt about "common programming errors" also points to potential issues when *using* the assembler. I considered examples like out-of-bounds access (related to the bounds-checking functions) and type errors (due to the low-level nature).

11. **Synthesizing the Summary:** Finally, I combined all these observations into a concise summary, focusing on the key functionalities, the purpose within V8, and the relationship to code generation. I tried to use clear and descriptive language, avoiding excessive technical jargon where possible. I also explicitly addressed the constraints and questions from the prompt (like the `.tq` and JavaScript connection).

Essentially, I followed a top-down approach, starting with a broad overview and progressively drilling down into more specific details, constantly relating the observed elements back to the overall purpose of the code within the V8 engine.

这是 `v8/src/codegen/code-stub-assembler.h` 文件第三部分的功能归纳：

**核心功能： 提供访问和操作 V8 堆中各种对象的底层接口**

这部分代码继续定义了 `CodeStubAssembler` 类的方法，这些方法专注于**加载 (Load)** 和 **存储 (Store)**  V8 堆中各种对象的属性和数据。它提供了更细粒度的控制，通常用于性能关键的代码片段中，直接操作内存地址和对象结构。

**具体功能点：**

1. **数组元素访问 (Load/Store):**
   - 提供了多种加载和存储数组元素的方法，包括 `FixedArray`, `PropertyArray`, `FixedDoubleArray`, `WeakFixedArray` 等不同类型的数组。
   - 区分了安全（带边界检查）和非安全（不带边界检查）的操作，后者需要开发者自行确保索引的有效性。
   - 提供了加载和存储特定类型元素的方法，例如 `LoadAndUntagToWord32FixedArrayElement` (加载并去除标签转换为 32 位字)。
   - 针对 `FixedDoubleArray` 提供了处理 "hole" (空洞) 的机制。
   - 针对 TypedArray 提供了加载方法 (`LoadFixedTypedArrayElementAsTagged`)。

2. **反馈向量操作 (Load):**
   - 提供了加载 `FeedbackVector` 中槽位 (slot) 的方法，用于访问运行时反馈信息。

3. **双精度浮点数操作 (Load/Store):**
   - 提供了带有 "hole" 检查的加载双精度浮点数的方法 (`LoadDoubleWithHoleCheck`)。
   - 提供了存储双精度浮点数 "hole" 的方法 (`StoreDoubleHole`, `StoreFixedDoubleArrayHole`)。

4. **作用域信息操作 (Load):**
   - 提供了加载 `ScopeInfo` 及其属性的方法，用于访问变量作用域信息。

5. **上下文操作 (Load/Store):**
   - 提供了加载和存储 `Context` 中元素的方法，包括加载 `NativeContext` 和 `ModuleContext`。
   - 提供了检查上下文元素是否相等的方法 (`GotoIfContextElementEqual`)。
   - 提供了加载特定全局对象初始 Map 的方法 (`LoadObjectFunctionInitialMap`, `LoadSlowObjectWithNullPrototypeMap`)。

6. **JS 函数操作 (Load):**
   - 提供了加载 `JSFunction` 的各种属性的方法，如 `LoadFunctionKind`, `LoadJSFunctionPrototype`, `LoadJSFunctionCode`。
   - 提供了检查函数原型链和内置 ID 的方法。

7. **共享函数信息操作 (Load):**
   - 提供了加载 `SharedFunctionInfo` 中各种数据的方法，如信任数据、非信任数据、字节码数组等。

8. **字节码数组操作 (Load):**
   - 提供了加载 `BytecodeArray` 参数个数的方法。

9. **对象字段操作 (Store):**
   - 提供了多种存储对象字段的方法 (`StoreObjectField`)，区分了是否需要写屏障 (Write Barrier)，以及存储不同类型的值 (Smi, Object)。
   - 提供了存储间接指针字段和受信任指针字段的方法，这与 V8 的垃圾回收和安全机制有关。
   - 提供了存储代码指针字段的方法 (`StoreCodePointerField`)。
   - 提供了不带写屏障的存储方法 (`StoreObjectFieldNoWriteBarrier`)，用于已知无需写屏障的场景以提升性能。
   - 提供了存储对象 Map 的方法 (`StoreMap`, `StoreMapNoWriteBarrier`)。

10. **固定数组元素操作 (Store):**
    - 提供了多种存储 `FixedArray` 元素的方法 (`StoreFixedArrayElement`)，同样区分了是否需要写屏障和是否进行边界检查。
    - 提供了非安全版本的存储方法 (`UnsafeStoreFixedArrayElement`)。

11. **属性数组元素操作 (Store):**
    - 提供了存储 `PropertyArray` 元素的方法 (`StorePropertyArrayElement`)。

12. **固定双精度数组元素操作 (Store):**
    - 提供了存储 `FixedDoubleArray` 元素的方法 (`StoreFixedDoubleArrayElement`)。

13. **反馈向量槽位操作 (Store):**
    - 提供了存储 `FeedbackVector` 槽位的方法 (`StoreFeedbackVectorSlot`)。

14. **共享对象字段操作 (Store):**
    - 提供了存储共享对象字段的方法 (`StoreSharedObjectField`)。

15. **JS 共享结构体属性数组元素操作 (Store):**
    - 提供了存储 `JSSharedStructPropertyArray` 元素的方法 (`StoreJSSharedStructPropertyArrayElement`)。

16. **数组可推送性检查:**
    - 提供了 `EnsureArrayPushable` 方法，用于检查数组是否可以安全地进行 `push` 操作。

17. **尝试存储数组元素:**
    - 提供了 `TryStoreArrayElement` 方法，用于尝试存储数组元素，并可以在失败时跳转到指定标签。

18. **构建和追加 JS 数组:**
    - 提供了 `BuildAppendJSArray` 方法，用于高效地向 JS 数组追加元素。

19. **无写屏障批量存储字段:**
    - 提供了 `StoreFieldsNoWriteBarrier` 方法，用于批量存储字段，跳过写屏障。

20. **标记固定数组为写入时复制 (COW):**
    - 提供了 `MakeFixedArrayCOW` 方法，用于将 `FixedArray` 标记为写入时复制。

21. **Cell 对象操作 (Allocate/Load/Store):**
    - 提供了分配 `Cell` 对象并设置初始值的方法 (`AllocateCellWithValue`, `AllocateSmiCell`)。
    - 提供了加载和存储 `Cell` 值的方法 (`LoadCellValue`, `StoreCellValue`)。

22. **HeapNumber 对象操作 (Allocate):**
    - 提供了分配 `HeapNumber` 对象的方法，可以指定初始值 (`AllocateHeapNumber`, `AllocateHeapNumberWithValue`)。

23. **BigInt 对象操作 (Allocate/Store/Load):**
    - 提供了分配 `BigInt` 对象的方法 (`AllocateBigInt`, `AllocateRawBigInt`)。
    - 提供了存储和加载 `BigInt` 内部数据的方法 (`StoreBigIntBitfield`, `StoreBigIntDigit`, `LoadBigIntBitfield`, `LoadBigIntDigit`)。

24. **ByteArray 对象操作 (Allocate):**
    - 提供了分配 `ByteArray` 对象的方法 (`AllocateNonEmptyByteArray`, `AllocateByteArray`)。

25. **字符串对象操作 (Allocate):**
    - 提供了分配各种字符串对象的方法，如 `SeqOneByteString`, `SeqTwoByteString`, `SlicedOneByteString`, `SlicedTwoByteString`。

26. **字典对象操作 (Allocate/Copy):**
    - 提供了分配 `NameDictionary` 和 `PropertyDictionary` 对象的方法 (`AllocateNameDictionary`, `AllocatePropertyDictionary`)。
    - 提供了复制 `NameDictionary` 的方法 (`CopyNameDictionary`)。

27. **集合对象操作 (Allocate):**
    - 提供了分配 `OrderedHashSet` 和 `OrderedHashMap` 对象的方法。

28. **有序名字字典对象操作 (Allocate):**
    - 提供了分配 `OrderedNameDictionary` 对象的方法 (`AllocateOrderedNameDictionary`)。

29. **JSObject 对象操作 (Allocate/Initialize):**
    - 提供了从 Map 分配 `JSObject` 对象的方法 (`AllocateJSObjectFromMap`)。
    - 提供了初始化 `JSObject` 对象的方法 (`InitializeJSObjectFromMap`, `InitializeJSObjectBodyWithSlackTracking`, `InitializeJSObjectBodyNoSlackTracking`)。

30. **JSArray 对象操作 (Allocate/Clone/Extract):**
    - 提供了分配 `JSArray` 对象的方法，可以指定元素类型、Map、长度、容量等 (`AllocateUninitializedJSArrayWithElements`, `AllocateJSArray`)。
    - 提供了克隆快速 `JSArray` 的方法 (`CloneFastJSArray`)，可以控制是否将 "hole" 转换为 `undefined`。
    - 提供了提取 `JSArray` 子数组的方法 (`ExtractFastJSArray`)。

31. **固定数组分配:**
    - 提供了分配 `FixedArrayBase` 的方法 (`AllocateFixedArray`)。

32. **快速克隆 JSObject:**
    - 提供了快速克隆 `JSObject` 的方法 (`FastCloneJSObject`)。

33. **获取创建上下文:**
    - 提供了从 Map 或 JSReceiver 获取创建上下文的方法 (`GetCreationContextFromMap`, `GetCreationContext`)。
    - 提供了获取函数 Realm 的方法 (`GetFunctionRealm`)。

34. **获取构造函数:**
    - 提供了获取 Map 的构造函数的方法 (`GetConstructor`)。

**与 JavaScript 的关系：**

这部分代码的功能是 V8 引擎执行 JavaScript 代码的基础。例如：

- **数组操作:** 当 JavaScript 代码访问或修改数组元素时，V8 可能会使用这里的 `LoadFixedArrayElement` 或 `StoreFixedArrayElement` 等方法。
  ```javascript
  const arr = [1, 2, 3];
  const firstElement = arr[0]; // V8 可能使用 LoadFixedArrayElement
  arr[1] = 4; // V8 可能使用 StoreFixedArrayElement
  ```
- **对象属性访问:** 当 JavaScript 代码访问或修改对象属性时，V8 可能会使用这里的 `LoadObjectField` 或 `StoreObjectField` 等方法。
  ```javascript
  const obj = { a: 1 };
  const value = obj.a; // V8 可能使用 LoadObjectField
  obj.b = 2; // V8 可能使用 StoreObjectField
  ```
- **函数调用:**  加载 `JSFunction` 的原型 (`LoadJSFunctionPrototype`) 和代码 (`LoadJSFunctionCode`) 是函数调用过程中的关键步骤。
- **闭包:** `LoadContextElement` 用于访问闭包中捕获的变量。

**代码逻辑推理 (假设):**

**假设输入：**
- `array`: 一个指向 `FixedArray` 对象的 `TNode<FixedArray>`。
- `index`: 一个表示要访问的索引的 `TNode<IntPtrT>`，其值为 `1`。
- `additional_offset`:  `0`。

**输出：**
- `LoadFixedArrayElement(array, index, additional_offset)` 将返回 `FixedArray` 中索引为 1 的元素的值，作为一个 `TNode<Object>`。

**用户常见的编程错误：**

- **数组越界访问：** 在使用不带边界检查的 `UnsafeLoadFixedArrayElement` 或 `UnsafeStoreFixedArrayElement` 时，如果 `index` 超出数组范围，会导致严重的内存错误或程序崩溃。
  ```javascript
  const arr = [1, 2, 3];
  // 错误：访问越界索引
  const element = arr[10]; // 在底层可能对应 UnsafeLoadFixedArrayElement，如果 V8 没有做其他优化
  ```
- **类型错误：** 尝试将错误类型的值存储到特定类型的数组中。
  ```javascript
  const doubleArray = new Float64Array(1);
  // 错误：尝试将字符串存储到 Float64Array
  doubleArray[0] = "hello"; // 在底层尝试使用 StoreFixedDoubleArrayElement 存储非数字类型
  ```
- **忘记写屏障：** 在修改对象之间的引用时，如果使用了 `StoreObjectFieldNoWriteBarrier`，可能会导致垃圾回收器无法正确追踪对象，从而引发内存泄漏或悬挂指针等问题。这通常发生在开发者试图手动优化性能，但对 V8 的内存管理机制理解不足的情况下。

**归纳总结：**

这部分 `code-stub-assembler.h` 文件定义了 `CodeStubAssembler` 的核心功能，提供了用于在 V8 引擎的底层代码中**加载和存储各种 V8 堆对象的数据**的方法。它涵盖了数组、对象属性、函数信息、上下文、以及其他 V8 内部数据结构的访问和修改，并区分了安全操作和非安全操作，为性能关键的代码提供了更精细的控制。理解这部分代码的功能对于深入了解 V8 引擎的内部工作原理至关重要。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
ional_offset);
  }

  void FixedArrayBoundsCheck(TNode<FixedArrayBase> array, TNode<UintPtrT> index,
                             int additional_offset) {
    FixedArrayBoundsCheck(array, Signed(index), additional_offset);
  }

  void FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                             TNode<TaggedIndex> index, int additional_offset);
  void FixedArrayBoundsCheck(TNode<FixedArray> array, TNode<TaggedIndex> index,
                             int additional_offset) {
    FixedArrayBoundsCheck(UncheckedCast<FixedArrayBase>(array), index,
                          additional_offset);
  }

  // Array is any array-like type that has a fixed header followed by
  // tagged elements.
  template <typename Array>
  TNode<IntPtrT> LoadArrayLength(TNode<Array> array);

  // Array is any array-like type that has a fixed header followed by
  // tagged elements.
  template <typename Array, typename TIndex, typename TValue = MaybeObject>
  TNode<TValue> LoadArrayElement(TNode<Array> array, int array_header_size,
                                 TNode<TIndex> index,
                                 int additional_offset = 0);
  template <typename Array, typename TIndex>
  TNode<typename Array::Shape::ElementT> LoadArrayElement(
      TNode<Array> array, TNode<TIndex> index, int additional_offset = 0) {
    return LoadArrayElement<Array, TIndex, typename Array::Shape::ElementT>(
        array, OFFSET_OF_DATA_START(Array), index, additional_offset);
  }

  template <typename TIndex>
  TNode<Object> LoadFixedArrayElement(
      TNode<FixedArray> object, TNode<TIndex> index, int additional_offset = 0,
      CheckBounds check_bounds = CheckBounds::kAlways);

  // This doesn't emit a bounds-check. As part of the security-performance
  // tradeoff, only use it if it is performance critical.
  TNode<Object> UnsafeLoadFixedArrayElement(TNode<FixedArray> object,
                                            TNode<IntPtrT> index,
                                            int additional_offset = 0) {
    return LoadFixedArrayElement(object, index, additional_offset,
                                 CheckBounds::kDebugOnly);
  }

  TNode<Object> LoadFixedArrayElement(TNode<FixedArray> object, int index,
                                      int additional_offset = 0) {
    return LoadFixedArrayElement(object, IntPtrConstant(index),
                                 additional_offset);
  }
  // This doesn't emit a bounds-check. As part of the security-performance
  // tradeoff, only use it if it is performance critical.
  TNode<Object> UnsafeLoadFixedArrayElement(TNode<FixedArray> object, int index,
                                            int additional_offset = 0) {
    return LoadFixedArrayElement(object, IntPtrConstant(index),
                                 additional_offset, CheckBounds::kDebugOnly);
  }

  TNode<Object> LoadPropertyArrayElement(TNode<PropertyArray> object,
                                         TNode<IntPtrT> index);
  TNode<IntPtrT> LoadPropertyArrayLength(TNode<PropertyArray> object);

  // Load an element from an array and untag it and return it as Word32.
  // Array is any array-like type that has a fixed header followed by
  // tagged elements.
  template <typename Array>
  TNode<Int32T> LoadAndUntagToWord32ArrayElement(TNode<Array> array,
                                                 int array_header_size,
                                                 TNode<IntPtrT> index,
                                                 int additional_offset = 0);

  // Load an array element from a FixedArray, untag it and return it as Word32.
  TNode<Int32T> LoadAndUntagToWord32FixedArrayElement(
      TNode<FixedArray> object, TNode<IntPtrT> index,
      int additional_offset = 0);

  // Load an array element from a WeakFixedArray.
  TNode<MaybeObject> LoadWeakFixedArrayElement(TNode<WeakFixedArray> object,
                                               TNode<IntPtrT> index,
                                               int additional_offset = 0);

  // Load an array element from a FixedDoubleArray.
  TNode<Float64T> LoadFixedDoubleArrayElement(
      TNode<FixedDoubleArray> object, TNode<IntPtrT> index,
      Label* if_hole = nullptr,
      MachineType machine_type = MachineType::Float64());

  // Load an array element from a FixedArray, FixedDoubleArray or a
  // NumberDictionary (depending on the |elements_kind|) and return
  // it as a tagged value. Assumes that the |index| passed a length
  // check before. Bails out to |if_accessor| if the element that
  // was found is an accessor, or to |if_hole| if the element at
  // the given |index| is not found in |elements|.
  TNode<Object> LoadFixedArrayBaseElementAsTagged(
      TNode<FixedArrayBase> elements, TNode<IntPtrT> index,
      TNode<Int32T> elements_kind, Label* if_accessor, Label* if_hole);

  // Load a feedback slot from a FeedbackVector.
  template <typename TIndex>
  TNode<MaybeObject> LoadFeedbackVectorSlot(
      TNode<FeedbackVector> feedback_vector, TNode<TIndex> slot,
      int additional_offset = 0);

  TNode<IntPtrT> LoadFeedbackVectorLength(TNode<FeedbackVector>);
  TNode<Float64T> LoadDoubleWithHoleCheck(TNode<FixedDoubleArray> array,
                                          TNode<IntPtrT> index,
                                          Label* if_hole = nullptr);

  TNode<BoolT> IsDoubleHole(TNode<Object> base, TNode<IntPtrT> offset);
  // Load Float64 value by |base| + |offset| address. If the value is a double
  // hole then jump to |if_hole|. If |machine_type| is None then only the hole
  // check is generated.
  TNode<Float64T> LoadDoubleWithHoleCheck(
      TNode<Object> base, TNode<IntPtrT> offset, Label* if_hole,
      MachineType machine_type = MachineType::Float64());
  TNode<Numeric> LoadFixedTypedArrayElementAsTagged(TNode<RawPtrT> data_pointer,
                                                    TNode<UintPtrT> index,
                                                    ElementsKind elements_kind);
  TNode<Numeric> LoadFixedTypedArrayElementAsTagged(
      TNode<RawPtrT> data_pointer, TNode<UintPtrT> index,
      TNode<Int32T> elements_kind);
  // Parts of the above, factored out for readability:
  TNode<BigInt> LoadFixedBigInt64ArrayElementAsTagged(
      TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset);
  TNode<BigInt> LoadFixedBigUint64ArrayElementAsTagged(
      TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset);
  // 64-bit platforms only:
  TNode<BigInt> BigIntFromInt64(TNode<IntPtrT> value);
  TNode<BigInt> BigIntFromUint64(TNode<UintPtrT> value);
  // 32-bit platforms only:
  TNode<BigInt> BigIntFromInt32Pair(TNode<IntPtrT> low, TNode<IntPtrT> high);
  TNode<BigInt> BigIntFromUint32Pair(TNode<UintPtrT> low, TNode<UintPtrT> high);

  // ScopeInfo:
  TNode<ScopeInfo> LoadScopeInfo(TNode<Context> context);
  TNode<BoolT> LoadScopeInfoHasExtensionField(TNode<ScopeInfo> scope_info);
  TNode<BoolT> LoadScopeInfoClassScopeHasPrivateBrand(
      TNode<ScopeInfo> scope_info);

  // Context manipulation:
  void StoreContextElementNoWriteBarrier(TNode<Context> context, int slot_index,
                                         TNode<Object> value);
  TNode<NativeContext> LoadNativeContext(TNode<Context> context);
  // Calling this is only valid if there's a module context in the chain.
  TNode<Context> LoadModuleContext(TNode<Context> context);

  TNode<Object> GetImportMetaObject(TNode<Context> context);

  void GotoIfContextElementEqual(TNode<Object> value,
                                 TNode<NativeContext> native_context,
                                 int slot_index, Label* if_equal) {
    GotoIf(TaggedEqual(value, LoadContextElement(native_context, slot_index)),
           if_equal);
  }

  // Loads the initial map of the the Object constructor.
  TNode<Map> LoadObjectFunctionInitialMap(TNode<NativeContext> native_context);
  TNode<Map> LoadSlowObjectWithNullPrototypeMap(
      TNode<NativeContext> native_context);
  TNode<Map> LoadCachedMap(TNode<NativeContext> native_context,
                           TNode<IntPtrT> number_of_properties, Label* runtime);

  TNode<Map> LoadJSArrayElementsMap(ElementsKind kind,
                                    TNode<NativeContext> native_context);
  TNode<Map> LoadJSArrayElementsMap(TNode<Int32T> kind,
                                    TNode<NativeContext> native_context);

  TNode<BoolT> IsJSFunctionWithPrototypeSlot(TNode<HeapObject> object);
  TNode<Uint32T> LoadFunctionKind(TNode<JSFunction> function);
  TNode<BoolT> IsGeneratorFunction(TNode<JSFunction> function);
  void BranchIfHasPrototypeProperty(TNode<JSFunction> function,
                                    TNode<Int32T> function_map_bit_field,
                                    Label* if_true, Label* if_false);
  void GotoIfPrototypeRequiresRuntimeLookup(TNode<JSFunction> function,
                                            TNode<Map> map, Label* runtime);
  // Load the "prototype" property of a JSFunction.
  TNode<HeapObject> LoadJSFunctionPrototype(TNode<JSFunction> function,
                                            Label* if_bailout);

  // Load the "code" property of a JSFunction.
  TNode<Code> LoadJSFunctionCode(TNode<JSFunction> function);

  TNode<Object> LoadSharedFunctionInfoTrustedData(
      TNode<SharedFunctionInfo> sfi);
  TNode<Object> LoadSharedFunctionInfoUntrustedData(
      TNode<SharedFunctionInfo> sfi);

  TNode<BoolT> SharedFunctionInfoHasBaselineCode(TNode<SharedFunctionInfo> sfi);

  TNode<Smi> LoadSharedFunctionInfoBuiltinId(TNode<SharedFunctionInfo> sfi);

  TNode<BytecodeArray> LoadSharedFunctionInfoBytecodeArray(
      TNode<SharedFunctionInfo> sfi);

#ifdef V8_ENABLE_WEBASSEMBLY
  TNode<WasmFunctionData> LoadSharedFunctionInfoWasmFunctionData(
      TNode<SharedFunctionInfo> sfi);
  TNode<WasmExportedFunctionData>
  LoadSharedFunctionInfoWasmExportedFunctionData(TNode<SharedFunctionInfo> sfi);
  TNode<WasmJSFunctionData> LoadSharedFunctionInfoWasmJSFunctionData(
      TNode<SharedFunctionInfo> sfi);
#endif  // V8_ENABLE_WEBASSEMBLY

  TNode<Int32T> LoadBytecodeArrayParameterCount(
      TNode<BytecodeArray> bytecode_array);
  TNode<Int32T> LoadBytecodeArrayParameterCountWithoutReceiver(
      TNode<BytecodeArray> bytecode_array);

  void StoreObjectByteNoWriteBarrier(TNode<HeapObject> object, int offset,
                                     TNode<Word32T> value);

  // Store the floating point value of a HeapNumber.
  void StoreHeapNumberValue(TNode<HeapNumber> object, TNode<Float64T> value);

  // Store a field to an object on the heap.
  void StoreObjectField(TNode<HeapObject> object, int offset, TNode<Smi> value);
  void StoreObjectField(TNode<HeapObject> object, TNode<IntPtrT> offset,
                        TNode<Smi> value);
  void StoreObjectField(TNode<HeapObject> object, int offset,
                        TNode<Object> value);
  void StoreObjectField(TNode<HeapObject> object, TNode<IntPtrT> offset,
                        TNode<Object> value);

  // Store to an indirect pointer field. This involves loading the index for
  // the pointer table entry owned by the pointed-to object (which points back
  // to it) and storing that into the specified field.
  // Stores that may require a write barrier also need to know the indirect
  // pointer tag for the field. Otherwise, it is not needed
  void StoreIndirectPointerField(TNode<HeapObject> object, int offset,
                                 IndirectPointerTag tag,
                                 TNode<ExposedTrustedObject> value);
  void StoreIndirectPointerFieldNoWriteBarrier(
      TNode<HeapObject> object, int offset, IndirectPointerTag tag,
      TNode<ExposedTrustedObject> value);

  // Store a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void StoreTrustedPointerField(TNode<HeapObject> object, int offset,
                                IndirectPointerTag tag,
                                TNode<ExposedTrustedObject> value);
  void StoreTrustedPointerFieldNoWriteBarrier(
      TNode<HeapObject> object, int offset, IndirectPointerTag tag,
      TNode<ExposedTrustedObject> value);

  void ClearTrustedPointerField(TNode<HeapObject> object, int offset);

  // Store a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  void StoreCodePointerField(TNode<HeapObject> object, int offset,
                             TNode<Code> value) {
    StoreTrustedPointerField(object, offset, kCodeIndirectPointerTag, value);
  }
  void StoreCodePointerFieldNoWriteBarrier(TNode<HeapObject> object, int offset,
                                           TNode<Code> value) {
    StoreTrustedPointerFieldNoWriteBarrier(object, offset,
                                           kCodeIndirectPointerTag, value);
  }

  template <class T>
  void StoreObjectFieldNoWriteBarrier(TNode<HeapObject> object,
                                      TNode<IntPtrT> offset, TNode<T> value) {
    int const_offset;
    if (TryToInt32Constant(offset, &const_offset)) {
      return StoreObjectFieldNoWriteBarrier<T>(object, const_offset, value);
    }
    StoreNoWriteBarrier(MachineRepresentationOf<T>::value, object,
                        IntPtrSub(offset, IntPtrConstant(kHeapObjectTag)),
                        value);
  }
  template <class T>
  void StoreObjectFieldNoWriteBarrier(TNode<HeapObject> object, int offset,
                                      TNode<T> value) {
    if (CanBeTaggedPointer(MachineRepresentationOf<T>::value)) {
      OptimizedStoreFieldAssertNoWriteBarrier(MachineRepresentationOf<T>::value,
                                              object, offset, value);
    } else {
      OptimizedStoreFieldUnsafeNoWriteBarrier(MachineRepresentationOf<T>::value,
                                              object, offset, value);
    }
  }

  void UnsafeStoreObjectFieldNoWriteBarrier(TNode<HeapObject> object,
                                            int offset, TNode<Object> value);

  // Store the Map of an HeapObject.
  void StoreMap(TNode<HeapObject> object, TNode<Map> map);
  void StoreMapNoWriteBarrier(TNode<HeapObject> object,
                              RootIndex map_root_index);
  void StoreMapNoWriteBarrier(TNode<HeapObject> object, TNode<Map> map);
  void StoreObjectFieldRoot(TNode<HeapObject> object, int offset,
                            RootIndex root);

  // Store an array element to a FixedArray.
  void StoreFixedArrayElement(
      TNode<FixedArray> object, int index, TNode<Object> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      CheckBounds check_bounds = CheckBounds::kAlways) {
    return StoreFixedArrayElement(object, IntPtrConstant(index), value,
                                  barrier_mode, 0, check_bounds);
  }

  void StoreFixedArrayElement(TNode<FixedArray> object, int index,
                              TNode<Smi> value,
                              CheckBounds check_bounds = CheckBounds::kAlways) {
    return StoreFixedArrayElement(object, IntPtrConstant(index),
                                  TNode<Object>{value},
                                  UNSAFE_SKIP_WRITE_BARRIER, 0, check_bounds);
  }

  template <typename TIndex>
  void StoreFixedArrayElement(
      TNode<FixedArray> array, TNode<TIndex> index, TNode<Object> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0,
      CheckBounds check_bounds = CheckBounds::kAlways) {
    // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
    static_assert(std::is_same<TIndex, Smi>::value ||
                      std::is_same<TIndex, UintPtrT>::value ||
                      std::is_same<TIndex, IntPtrT>::value,
                  "Only Smi, UintPtrT or IntPtrT index is allowed");
    if (NeedsBoundsCheck(check_bounds)) {
      FixedArrayBoundsCheck(array, index, additional_offset);
    }
    StoreFixedArrayOrPropertyArrayElement(array, index, value, barrier_mode,
                                          additional_offset);
  }

  template <typename TIndex>
  void StoreFixedArrayElement(TNode<FixedArray> array, TNode<TIndex> index,
                              TNode<Smi> value, int additional_offset = 0) {
    static_assert(std::is_same<TIndex, Smi>::value ||
                      std::is_same<TIndex, IntPtrT>::value,
                  "Only Smi or IntPtrT indeces is allowed");
    StoreFixedArrayElement(array, index, TNode<Object>{value},
                           UNSAFE_SKIP_WRITE_BARRIER, additional_offset);
  }

  // These don't emit a bounds-check. As part of the security-performance
  // tradeoff, only use it if it is performance critical.
  void UnsafeStoreFixedArrayElement(
      TNode<FixedArray> object, int index, TNode<Object> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER) {
    return StoreFixedArrayElement(object, IntPtrConstant(index), value,
                                  barrier_mode, 0, CheckBounds::kDebugOnly);
  }
  template <typename Array>
  void UnsafeStoreArrayElement(
      TNode<Array> object, int index,
      TNode<typename Array::Shape::ElementT> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER) {
    DCHECK(barrier_mode == SKIP_WRITE_BARRIER ||
           barrier_mode == UNSAFE_SKIP_WRITE_BARRIER ||
           barrier_mode == UPDATE_WRITE_BARRIER);
    // TODO(jgruber): This is just a barebones implementation taken from
    // StoreFixedArrayOrPropertyArrayElement. We can make it more robust and
    // generic if needed.
    int offset = Array::OffsetOfElementAt(index);
    if (barrier_mode == UNSAFE_SKIP_WRITE_BARRIER) {
      UnsafeStoreObjectFieldNoWriteBarrier(object, offset, value);
    } else if (barrier_mode == SKIP_WRITE_BARRIER) {
      StoreObjectFieldNoWriteBarrier(object, offset, value);
    } else if (barrier_mode == UPDATE_WRITE_BARRIER) {
      StoreObjectField(object, offset, value);
    } else {
      UNREACHABLE();
    }
  }
  template <typename Array>
  void UnsafeStoreArrayElement(
      TNode<Array> object, TNode<Smi> index,
      TNode<typename Array::Shape::ElementT> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER) {
    DCHECK(barrier_mode == SKIP_WRITE_BARRIER ||
           barrier_mode == UPDATE_WRITE_BARRIER);
    // TODO(jgruber): This is just a barebones implementation taken from
    // StoreFixedArrayOrPropertyArrayElement. We can make it more robust and
    // generic if needed.
    TNode<IntPtrT> offset = ElementOffsetFromIndex(index, PACKED_ELEMENTS,
                                                   OFFSET_OF_DATA_START(Array));
    if (barrier_mode == SKIP_WRITE_BARRIER) {
      StoreObjectFieldNoWriteBarrier(object, offset, value);
    } else if (barrier_mode == UPDATE_WRITE_BARRIER) {
      StoreObjectField(object, offset, value);
    } else {
      UNREACHABLE();
    }
  }

  void UnsafeStoreFixedArrayElement(TNode<FixedArray> object, int index,
                                    TNode<Smi> value) {
    return StoreFixedArrayElement(object, IntPtrConstant(index), value,
                                  UNSAFE_SKIP_WRITE_BARRIER, 0,
                                  CheckBounds::kDebugOnly);
  }

  void UnsafeStoreFixedArrayElement(
      TNode<FixedArray> array, TNode<IntPtrT> index, TNode<Object> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0) {
    return StoreFixedArrayElement(array, index, value, barrier_mode,
                                  additional_offset, CheckBounds::kDebugOnly);
  }

  void UnsafeStoreFixedArrayElement(TNode<FixedArray> array,
                                    TNode<IntPtrT> index, TNode<Smi> value,
                                    int additional_offset) {
    return StoreFixedArrayElement(array, index, value,
                                  UNSAFE_SKIP_WRITE_BARRIER, additional_offset,
                                  CheckBounds::kDebugOnly);
  }

  void StorePropertyArrayElement(TNode<PropertyArray> array,
                                 TNode<IntPtrT> index, TNode<Object> value) {
    StoreFixedArrayOrPropertyArrayElement(array, index, value,
                                          UPDATE_WRITE_BARRIER);
  }

  template <typename TIndex>
  void StoreFixedDoubleArrayElement(
      TNode<FixedDoubleArray> object, TNode<TIndex> index,
      TNode<Float64T> value, CheckBounds check_bounds = CheckBounds::kAlways);

  void StoreDoubleHole(TNode<HeapObject> object, TNode<IntPtrT> offset);
  void StoreFixedDoubleArrayHole(TNode<FixedDoubleArray> array,
                                 TNode<IntPtrT> index);
  void StoreFeedbackVectorSlot(
      TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
      TNode<AnyTaggedT> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0);

  void StoreSharedObjectField(TNode<HeapObject> object, TNode<IntPtrT> offset,
                              TNode<Object> value);

  void StoreJSSharedStructPropertyArrayElement(TNode<PropertyArray> array,
                                               TNode<IntPtrT> index,
                                               TNode<Object> value) {
    StoreFixedArrayOrPropertyArrayElement(array, index, value);
  }

  // EnsureArrayPushable verifies that receiver with this map is:
  //   1. Is not a prototype.
  //   2. Is not a dictionary.
  //   3. Has a writeable length property.
  // It returns ElementsKind as a node for further division into cases.
  TNode<Int32T> EnsureArrayPushable(TNode<Context> context, TNode<Map> map,
                                    Label* bailout);

  void TryStoreArrayElement(ElementsKind kind, Label* bailout,
                            TNode<FixedArrayBase> elements, TNode<BInt> index,
                            TNode<Object> value);
  // Consumes args into the array, and returns tagged new length.
  TNode<Smi> BuildAppendJSArray(ElementsKind kind, TNode<JSArray> array,
                                CodeStubArguments* args,
                                TVariable<IntPtrT>* arg_index, Label* bailout);
  // Pushes value onto the end of array.
  void BuildAppendJSArray(ElementsKind kind, TNode<JSArray> array,
                          TNode<Object> value, Label* bailout);

  void StoreFieldsNoWriteBarrier(TNode<IntPtrT> start_address,
                                 TNode<IntPtrT> end_address,
                                 TNode<Object> value);

  // Marks the FixedArray copy-on-write without moving it.
  void MakeFixedArrayCOW(TNode<FixedArray> array);

  TNode<Cell> AllocateCellWithValue(
      TNode<Object> value, WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  TNode<Cell> AllocateSmiCell(int value = 0) {
    return AllocateCellWithValue(SmiConstant(value), SKIP_WRITE_BARRIER);
  }

  TNode<Object> LoadCellValue(TNode<Cell> cell);

  void StoreCellValue(TNode<Cell> cell, TNode<Object> value,
                      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  // Allocate a HeapNumber without initializing its value.
  TNode<HeapNumber> AllocateHeapNumber();
  // Allocate a HeapNumber with a specific value.
  TNode<HeapNumber> AllocateHeapNumberWithValue(TNode<Float64T> value);
  TNode<HeapNumber> AllocateHeapNumberWithValue(double value) {
    return AllocateHeapNumberWithValue(Float64Constant(value));
  }

  // Allocate a BigInt with {length} digits. Sets the sign bit to {false}.
  // Does not initialize the digits.
  TNode<BigInt> AllocateBigInt(TNode<IntPtrT> length);
  // Like above, but allowing custom bitfield initialization.
  TNode<BigInt> AllocateRawBigInt(TNode<IntPtrT> length);
  void StoreBigIntBitfield(TNode<BigInt> bigint, TNode<Word32T> bitfield);
  void StoreBigIntDigit(TNode<BigInt> bigint, intptr_t digit_index,
                        TNode<UintPtrT> digit);
  void StoreBigIntDigit(TNode<BigInt> bigint, TNode<IntPtrT> digit_index,
                        TNode<UintPtrT> digit);

  TNode<Word32T> LoadBigIntBitfield(TNode<BigInt> bigint);
  TNode<UintPtrT> LoadBigIntDigit(TNode<BigInt> bigint, intptr_t digit_index);
  TNode<UintPtrT> LoadBigIntDigit(TNode<BigInt> bigint,
                                  TNode<IntPtrT> digit_index);

  // Allocate a ByteArray with the given non-zero length.
  TNode<ByteArray> AllocateNonEmptyByteArray(
      TNode<UintPtrT> length, AllocationFlags flags = AllocationFlag::kNone);

  // Allocate a ByteArray with the given length.
  TNode<ByteArray> AllocateByteArray(
      TNode<UintPtrT> length, AllocationFlags flags = AllocationFlag::kNone);

  // Allocate a SeqOneByteString with the given length.
  TNode<String> AllocateSeqOneByteString(
      uint32_t length, AllocationFlags flags = AllocationFlag::kNone);
  using TorqueGeneratedExportedMacrosAssembler::AllocateSeqOneByteString;

  // Allocate a SeqTwoByteString with the given length.
  TNode<String> AllocateSeqTwoByteString(
      uint32_t length, AllocationFlags flags = AllocationFlag::kNone);
  using TorqueGeneratedExportedMacrosAssembler::AllocateSeqTwoByteString;

  // Allocate a SlicedOneByteString with the given length, parent and offset.
  // |length| and |offset| are expected to be tagged.

  TNode<String> AllocateSlicedOneByteString(TNode<Uint32T> length,
                                            TNode<String> parent,
                                            TNode<Smi> offset);
  // Allocate a SlicedTwoByteString with the given length, parent and offset.
  // |length| and |offset| are expected to be tagged.
  TNode<String> AllocateSlicedTwoByteString(TNode<Uint32T> length,
                                            TNode<String> parent,
                                            TNode<Smi> offset);

  TNode<NameDictionary> AllocateNameDictionary(int at_least_space_for);
  TNode<NameDictionary> AllocateNameDictionary(
      TNode<IntPtrT> at_least_space_for,
      AllocationFlags = AllocationFlag::kNone);
  TNode<NameDictionary> AllocateNameDictionaryWithCapacity(
      TNode<IntPtrT> capacity, AllocationFlags = AllocationFlag::kNone);

  TNode<PropertyDictionary> AllocatePropertyDictionary(int at_least_space_for);
  TNode<PropertyDictionary> AllocatePropertyDictionary(
      TNode<IntPtrT> at_least_space_for,
      AllocationFlags = AllocationFlag::kNone);
  TNode<PropertyDictionary> AllocatePropertyDictionaryWithCapacity(
      TNode<IntPtrT> capacity, AllocationFlags = AllocationFlag::kNone);

  TNode<NameDictionary> CopyNameDictionary(TNode<NameDictionary> dictionary,
                                           Label* large_object_fallback);

  TNode<OrderedHashSet> AllocateOrderedHashSet();
  TNode<OrderedHashSet> AllocateOrderedHashSet(TNode<IntPtrT> capacity);

  TNode<OrderedHashMap> AllocateOrderedHashMap();

  // Allocates an OrderedNameDictionary of the given capacity. This guarantees
  // that |capacity| entries can be added without reallocating.
  TNode<OrderedNameDictionary> AllocateOrderedNameDictionary(
      TNode<IntPtrT> capacity);
  TNode<OrderedNameDictionary> AllocateOrderedNameDictionary(int capacity);

  TNode<JSObject> AllocateJSObjectFromMap(
      TNode<Map> map,
      std::optional<TNode<HeapObject>> properties = std::nullopt,
      std::optional<TNode<FixedArray>> elements = std::nullopt,
      AllocationFlags flags = AllocationFlag::kNone,
      SlackTrackingMode slack_tracking_mode = kNoSlackTracking);

  void InitializeJSObjectFromMap(
      TNode<HeapObject> object, TNode<Map> map, TNode<IntPtrT> instance_size,
      std::optional<TNode<HeapObject>> properties = std::nullopt,
      std::optional<TNode<FixedArray>> elements = std::nullopt,
      SlackTrackingMode slack_tracking_mode = kNoSlackTracking);

  void InitializeJSObjectBodyWithSlackTracking(TNode<HeapObject> object,
                                               TNode<Map> map,
                                               TNode<IntPtrT> instance_size);
  void InitializeJSObjectBodyNoSlackTracking(
      TNode<HeapObject> object, TNode<Map> map, TNode<IntPtrT> instance_size,
      int start_offset = JSObject::kHeaderSize);

  TNode<BoolT> IsValidFastJSArrayCapacity(TNode<IntPtrT> capacity);

  //
  // Allocate and return a JSArray with initialized header fields and its
  // uninitialized elements.
  std::pair<TNode<JSArray>, TNode<FixedArrayBase>>
  AllocateUninitializedJSArrayWithElements(
      ElementsKind kind, TNode<Map> array_map, TNode<Smi> length,
      std::optional<TNode<AllocationSite>> allocation_site,
      TNode<IntPtrT> capacity,
      AllocationFlags allocation_flags = AllocationFlag::kNone,
      int array_header_size = JSArray::kHeaderSize);

  // Allocate a JSArray and fill elements with the hole.
  TNode<JSArray> AllocateJSArray(
      ElementsKind kind, TNode<Map> array_map, TNode<IntPtrT> capacity,
      TNode<Smi> length, std::optional<TNode<AllocationSite>> allocation_site,
      AllocationFlags allocation_flags = AllocationFlag::kNone);
  TNode<JSArray> AllocateJSArray(
      ElementsKind kind, TNode<Map> array_map, TNode<Smi> capacity,
      TNode<Smi> length, std::optional<TNode<AllocationSite>> allocation_site,
      AllocationFlags allocation_flags = AllocationFlag::kNone) {
    return AllocateJSArray(kind, array_map, PositiveSmiUntag(capacity), length,
                           allocation_site, allocation_flags);
  }
  TNode<JSArray> AllocateJSArray(
      ElementsKind kind, TNode<Map> array_map, TNode<Smi> capacity,
      TNode<Smi> length,
      AllocationFlags allocation_flags = AllocationFlag::kNone) {
    return AllocateJSArray(kind, array_map, PositiveSmiUntag(capacity), length,
                           std::nullopt, allocation_flags);
  }
  TNode<JSArray> AllocateJSArray(
      ElementsKind kind, TNode<Map> array_map, TNode<IntPtrT> capacity,
      TNode<Smi> length,
      AllocationFlags allocation_flags = AllocationFlag::kNone) {
    return AllocateJSArray(kind, array_map, capacity, length, std::nullopt,
                           allocation_flags);
  }

  // Allocate a JSArray and initialize the header fields.
  TNode<JSArray> AllocateJSArray(
      TNode<Map> array_map, TNode<FixedArrayBase> elements, TNode<Smi> length,
      std::optional<TNode<AllocationSite>> allocation_site = std::nullopt,
      int array_header_size = JSArray::kHeaderSize);

  enum class HoleConversionMode { kDontConvert, kConvertToUndefined };
  // Clone a fast JSArray |array| into a new fast JSArray.
  // |convert_holes| tells the function to convert holes into undefined or not.
  // If |convert_holes| is set to kConvertToUndefined, but the function did not
  // find any hole in |array|, the resulting array will have the same elements
  // kind as |array|. If the function did find a hole, it will convert holes in
  // |array| to undefined in the resulting array, who will now have
  // PACKED_ELEMENTS kind.
  // If |convert_holes| is set kDontConvert, holes are also copied to the
  // resulting array, who will have the same elements kind as |array|. The
  // function generates significantly less code in this case.
  TNode<JSArray> CloneFastJSArray(
      TNode<Context> context, TNode<JSArray> array,
      std::optional<TNode<AllocationSite>> allocation_site = std::nullopt,
      HoleConversionMode convert_holes = HoleConversionMode::kDontConvert);

  TNode<JSArray> ExtractFastJSArray(TNode<Context> context,
                                    TNode<JSArray> array, TNode<BInt> begin,
                                    TNode<BInt> count);

  template <typename TIndex>
  TNode<FixedArrayBase> AllocateFixedArray(
      ElementsKind kind, TNode<TIndex> capacity,
      AllocationFlags flags = AllocationFlag::kNone,
      std::optional<TNode<Map>> fixed_array_map = std::nullopt);

  template <typename Function>
  TNode<Object> FastCloneJSObject(TNode<HeapObject> source,
                                  TNode<Map> source_map, TNode<Map> target_map,
                                  const Function& materialize_target,
                                  bool target_is_new);

  TNode<NativeContext> GetCreationContextFromMap(TNode<Map> map,
                                                 Label* if_bailout);
  TNode<NativeContext> GetCreationContext(TNode<JSReceiver> receiver,
                                          Label* if_bailout);
  TNode<NativeContext> GetFunctionRealm(TNode<Context> context,
                                        TNode<JSReceiver> receiver,
                                        Label* if_bailout);
  TNode<Object> GetConstructor(TNode<Map> map);

  void FindNonDefaultConstructor(TNode<JSFunction> this_function,
```