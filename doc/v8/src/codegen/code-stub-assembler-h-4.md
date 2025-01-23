Response:
My thinking process to answer the request went something like this:

1. **Understand the Core Request:** The user wants a summary of the functionality of the provided C++ header file (`code-stub-assembler.h`) from the V8 JavaScript engine. They also have some specific constraints related to `.tq` files, JavaScript examples, logical reasoning, common errors, and being part 5 of 8.

2. **Initial Scan for Clues:** I quickly scanned the provided C++ code. Keywords like `Is...`, `To...`, `Load...`, `Store...`, `Get...`, `Set...`, and names like `String`, `Number`, `Object`, `Map`, `Dictionary` jumped out. This immediately suggested the file deals with type checking, type conversion, memory access, and data structure manipulation within V8's internal representation of JavaScript objects.

3. **Categorize Functionality:** I started grouping the functions based on their prefixes and purpose:
    * **`Is...` functions:**  These are clearly type checking predicates. They determine if an object or value conforms to a specific V8 internal type (e.g., `IsSmi`, `IsString`, `IsJSObject`).
    * **`To...` functions:** These are type conversion functions (e.g., `StringToNumber`, `ToBigInt`, `ToObject`).
    * **`Load...` and `Store...` functions:** These relate to memory access within V8's heap (e.g., `LoadMap`, `StoreFixedArrayElement`).
    * **`Get...` and `Set...` functions:** These provide access to specific properties or fields of V8 internal objects (e.g., `GetNumberOfElements`, `SetNumberOfElements`).
    * **Dictionary-related functions:**  There's a significant block dealing with hash tables and dictionaries (`NameDictionaryLookup`, `NumberDictionaryLookup`, `AddToDictionary`).
    * **Property access functions:** Functions like `TryHasOwnProperty` and `TryGetOwnProperty` deal with accessing object properties.
    * **Bit manipulation functions:** The `DecodeWord`, `UpdateWord`, `IsSetWord`, `IsClearWord` family of functions indicate low-level bitfield manipulation.
    * **Runtime flag access:**  The `LoadRuntimeFlag` functions are for checking internal V8 feature flags.
    * **Counters:** The `SetCounter`, `IncrementCounter`, `DecrementCounter` functions are for performance monitoring.

4. **Address Specific Constraints:**

    * **`.tq` files:** The prompt mentions `.tq` files. I recognized this relates to Torque, V8's internal language for code generation. Since the provided code is `.h`, it's *not* a Torque file. I made sure to state this explicitly.
    * **Relationship to JavaScript:**  I considered how the C++ functions relate to JavaScript concepts. The type checking and conversion functions directly correspond to JavaScript's dynamic typing and type coercion. Property access is fundamental to how JavaScript objects work. I looked for opportunities to provide simple JavaScript examples.
    * **Logical Reasoning:**  For functions like the dictionary lookups, I outlined the possible outcomes (found, not found) and the variables that would be set.
    * **Common Errors:** I thought about common JavaScript mistakes that these underlying functions might help prevent or handle (e.g., trying to use a non-object as an object, accessing non-existent properties).
    * **Part 5 of 8:**  This implies the file covers a specific area within the broader CodeStubAssembler functionality. I focused on the core themes I identified.

5. **Synthesize the Summary:**  I structured the summary logically, starting with a high-level overview and then going into more detail about the different categories of functions. I made sure to address all the specific constraints in the prompt. I used clear and concise language, avoiding overly technical jargon where possible.

6. **Refine and Review:** I reviewed my summary to ensure accuracy, completeness (within the scope of the provided code snippet), and clarity. I double-checked that I had addressed all the points raised in the user's request. I tried to make the JavaScript examples simple and illustrative.

Essentially, my process involved: understanding the request, analyzing the code, categorizing the functionality, addressing specific constraints, and synthesizing a coherent summary. The iterative nature of looking at the code, identifying patterns, and then relating those patterns back to JavaScript concepts was key.
好的，让我们来分析一下提供的 V8 源代码片段 `v8/src/codegen/code-stub-assembler.h` 的功能。

**功能归纳:**

从提供的代码片段来看，`code-stub-assembler.h` 文件定义了一系列用于在 V8 的 CodeStubAssembler 中进行**类型检查、类型转换、内存操作和数据结构访问**的辅助方法。  这些方法主要用于生成高效的机器代码来执行 JavaScript 代码。

具体来说，它包含了：

1. **类型判断函数 (Is...):**  大量的 `Is...` 开头的函数，用于判断一个对象或值是否属于特定的 V8 内部类型。例如：
   - 判断是否为特定类型的 JavaScript 对象 (如 `IsJSArray`, `IsJSFunction`)
   - 判断是否为特定的 V8 内部表示类型 (如 `IsSmi`, `IsHeapNumber`, `IsMap`)
   - 判断字符串的编码方式 (如 `IsOneByteStringInstanceType`, `IsSequentialStringMap`)
   - 判断是否为特定的内部数据结构 (如 `IsPropertyArray`, `IsNumberDictionary`)
   - 判断是否为特定的保护器单元失效 (如 `IsPromiseResolveProtectorCellInvalid`)

2. **类型转换函数 (To...):**  一系列 `To...` 开头的函数，用于将一个对象或值转换为另一种类型。例如：
   - 字符串和数字之间的转换 (`StringToNumber`, `NumberToString`)
   - 将任意对象转换为数字 (`ToNumber`) 或字符串 (`ToString_Inline`)
   - 将对象转换为 `JSReceiver` (`ToObject`)
   - 将值转换为长度 (`ToLength_Inline`)
   - 执行 `OrdinaryToPrimitive` 抽象操作

3. **内存操作函数 (Load.../Store...):**  用于加载和存储内存中特定位置的值。例如：
   - `LoadMap`: 加载对象的 Map (类型信息)
   - `LoadMemoryChunkFlags`: 加载内存块的标志
   - `StoreFixedArrayElement`: 存储固定数组的元素

4. **位操作函数 (DecodeWord.../UpdateWord.../IsSetWord...):** 用于读取和修改字 (Word) 中的位字段。这通常用于访问和操作 V8 内部对象的一些标志位。

5. **运行时标志访问函数 (LoadRuntimeFlag...):**  用于读取 V8 的运行时标志，这些标志控制着 V8 的一些行为和特性。

6. **数值判断函数:**  判断数字的各种属性 (如 `IsNumeric`, `IsNumberPositive`, `IsSafeInteger`)。

7. **元素类型 (ElementsKind) 辅助函数:**  用于判断和比较数组的元素类型 (如 `IsFastElementsKind`, `IsDoubleElementsKind`).

8. **字符串辅助函数:**  用于处理字符串，例如获取指定位置的字符 (`StringCharCodeAt`)，创建单字符字符串 (`StringFromSingleCharCode`)。

9. **哈希表和字典操作函数:**  用于在 V8 内部的哈希表和字典结构中进行查找、插入等操作 (如 `TryInternalizeString`, `NameDictionaryLookup`, `NumberDictionaryLookup`).

10. **属性访问辅助函数:**  用于尝试获取对象的自有属性 (`TryHasOwnProperty`, `TryGetOwnProperty`).

11. **计数器操作函数 (SetCounter, IncrementCounter, DecrementCounter):** 用于操作性能统计计数器。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  你提供的信息表明这是一个 `.h` 文件，即 C++ 头文件。 因此，它不是以 `.tq` 结尾的 V8 Torque 源代码。 Torque 文件会定义更高级的、声明式的代码生成逻辑。 `code-stub-assembler.h` 提供了 Torque 生成的 C++ 代码所使用的底层工具函数。

* **与 JavaScript 的关系:**  这个头文件中的函数与 JavaScript 的功能有着非常紧密的联系。 实际上，这些函数是 V8 引擎将 JavaScript 代码转换为高效机器码的关键构建块。

**JavaScript 举例说明:**

许多 `Is...` 和 `To...` 函数直接对应于 JavaScript 的类型检查和类型转换行为。

```javascript
// JavaScript 示例

const arr = [1, 2, 3];
const str = "hello";
const num = 123;
const obj = {};

// 在 V8 内部，当执行类似的操作时，可能会用到 code-stub-assembler.h 中的函数
console.log(Array.isArray(arr)); // 对应可能的 IsJSArray 函数
console.log(typeof str === 'string'); // 对应可能的 IsString 函数
console.log(num.toFixed(2)); // 内部可能涉及到 NumberToString 函数
console.log(Number(str)); // 内部可能涉及到 StringToNumber 函数
console.log(obj.hasOwnProperty('prototype')); // 对应可能的 TryHasOwnProperty 函数
```

**代码逻辑推理和假设输入/输出:**

以 `IsSmi(TNode<Object> object)` 函数为例：

* **假设输入:** 一个表示 JavaScript 值的 `TNode<Object>`。
* **内部逻辑推理:**  该函数会检查该 `TNode<Object>` 是否被编码为 V8 的 Smi (Small Integer) 类型。Smi 是一种高效地表示小整数的方式。
* **输出:** 一个 `TNode<BoolT>`，表示输入对象是否为 Smi。 如果是，则输出为真，否则为假。

以 `StringToNumber(TNode<String> input)` 函数为例：

* **假设输入:** 一个表示 JavaScript 字符串的 `TNode<String>`。
* **内部逻辑推理:** 该函数会尝试将输入的字符串解析为数字。这涉及到处理各种情况，例如空格、正负号、小数点、指数等。
* **输出:** 一个 `TNode<Number>`，表示转换后的数字。如果转换失败（例如，字符串不是有效的数字表示），可能会抛出错误或返回一个特殊的 NaN 值（在 V8 内部表示）。

**用户常见的编程错误:**

这些底层的函数也与用户常见的编程错误相关。例如：

```javascript
// 常见的错误

const notAnObject = null;
// 尝试访问 null 的属性会导致错误
// notAnObject.toString(); // TypeError: Cannot read properties of null (reading 'toString')

const notANumber = "abc";
// 对非数字字符串进行算术运算可能导致意想不到的结果
console.log(notANumber + 1); // 输出 "abc1" (字符串拼接)
console.log(notANumber * 1); // 输出 NaN (Not a Number)
```

在 V8 内部，当遇到 `notAnObject.toString()` 时，引擎可能会使用 `IsNullOrJSReceiver` 等函数来判断 `notAnObject` 是否可以安全地进行属性访问。 当遇到字符串到数字的转换时，如果字符串格式不正确，`StringToNumber` 会返回 NaN，这最终会导致 JavaScript 中的 `NaN` 结果。

**作为第 5 部分的归纳:**

考虑到这是 8 部分中的第 5 部分，我们可以推断出 `code-stub-assembler.h` 文件是 V8 代码生成器 (CodeStubAssembler) 核心组件的一部分。  前几部分可能介绍了 CodeStubAssembler 的基本框架和节点类型定义，而这部分则深入到了一些关键的辅助功能，这些功能用于处理 JavaScript 值的类型和转换，这是生成正确且高效代码的关键。  后续的部分可能会涉及更高级的代码生成模式、调用约定、以及与 V8 运行时环境的交互等。

**总结 `code-stub-assembler.h` 的功能:**

`v8/src/codegen/code-stub-assembler.h` 文件是 V8 引擎中 CodeStubAssembler 的重要组成部分，它提供了一组底层的、用于类型检查、类型转换、内存操作和数据结构访问的 C++ 辅助函数。 这些函数是 V8 将 JavaScript 代码编译成高效机器码的关键工具，直接支持着 JavaScript 的动态类型、类型转换、以及对象和数据结构的操作。  它不是 Torque 源代码，而是 Torque 生成的 C++ 代码所使用的基础库。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
HeapObject> object);
  TNode<BoolT> IsJSTypedArrayInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSTypedArrayMap(TNode<Map> map);
  TNode<BoolT> IsJSTypedArray(TNode<HeapObject> object);
  TNode<BoolT> IsJSGeneratorMap(TNode<Map> map);
  TNode<BoolT> IsJSPrimitiveWrapperInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSPrimitiveWrapperMap(TNode<Map> map);
  TNode<BoolT> IsJSPrimitiveWrapper(TNode<HeapObject> object);
  TNode<BoolT> IsJSSharedArrayInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSSharedArrayMap(TNode<Map> map);
  TNode<BoolT> IsJSSharedArray(TNode<HeapObject> object);
  TNode<BoolT> IsJSSharedArray(TNode<Object> object);
  TNode<BoolT> IsJSSharedStructInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsJSSharedStructMap(TNode<Map> map);
  TNode<BoolT> IsJSSharedStruct(TNode<HeapObject> object);
  TNode<BoolT> IsJSSharedStruct(TNode<Object> object);
  TNode<BoolT> IsJSWrappedFunction(TNode<HeapObject> object);
  TNode<BoolT> IsMap(TNode<HeapObject> object);
  TNode<BoolT> IsName(TNode<HeapObject> object);
  TNode<BoolT> IsNameInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsNullOrJSReceiver(TNode<HeapObject> object);
  TNode<BoolT> IsNullOrUndefined(TNode<Object> object);
  TNode<BoolT> IsNumberDictionary(TNode<HeapObject> object);
  TNode<BoolT> IsOneByteStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsSeqOneByteStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsPrimitiveInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsPrivateName(TNode<Symbol> symbol);
  TNode<BoolT> IsPropertyArray(TNode<HeapObject> object);
  TNode<BoolT> IsPropertyCell(TNode<HeapObject> object);
  TNode<BoolT> IsPromiseReactionJobTask(TNode<HeapObject> object);
  TNode<BoolT> IsPrototypeInitialArrayPrototype(TNode<Context> context,
                                                TNode<Map> map);
  TNode<BoolT> IsPrototypeTypedArrayPrototype(TNode<Context> context,
                                              TNode<Map> map);

  TNode<BoolT> IsFastAliasedArgumentsMap(TNode<Context> context,
                                         TNode<Map> map);
  TNode<BoolT> IsSlowAliasedArgumentsMap(TNode<Context> context,
                                         TNode<Map> map);
  TNode<BoolT> IsSloppyArgumentsMap(TNode<Context> context, TNode<Map> map);
  TNode<BoolT> IsStrictArgumentsMap(TNode<Context> context, TNode<Map> map);

  TNode<BoolT> IsSequentialStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsUncachedExternalStringInstanceType(
      TNode<Int32T> instance_type);
  TNode<BoolT> IsSpecialReceiverInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsCustomElementsReceiverInstanceType(
      TNode<Int32T> instance_type);
  TNode<BoolT> IsSpecialReceiverMap(TNode<Map> map);
  TNode<BoolT> IsStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsString(TNode<HeapObject> object);
  TNode<Word32T> IsStringWrapper(TNode<HeapObject> object);
  TNode<BoolT> IsSeqOneByteString(TNode<HeapObject> object);

  TNode<BoolT> IsSequentialStringMap(TNode<Map> map);
  TNode<BoolT> IsExternalStringMap(TNode<Map> map);
  TNode<BoolT> IsUncachedExternalStringMap(TNode<Map> map);
  TNode<BoolT> IsOneByteStringMap(TNode<Map> map);

  TNode<BoolT> IsSymbolInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsInternalizedStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsSharedStringInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsTemporalInstantInstanceType(TNode<Int32T> instance_type);
  TNode<BoolT> IsUniqueName(TNode<HeapObject> object);
  TNode<BoolT> IsUniqueNameNoIndex(TNode<HeapObject> object);
  TNode<BoolT> IsUniqueNameNoCachedIndex(TNode<HeapObject> object);
  TNode<BoolT> IsUndetectableMap(TNode<Map> map);
  TNode<BoolT> IsNotWeakFixedArraySubclass(TNode<HeapObject> object);
  TNode<BoolT> IsZeroOrContext(TNode<Object> object);

  TNode<BoolT> IsPromiseResolveProtectorCellInvalid();
  TNode<BoolT> IsPromiseThenProtectorCellInvalid();
  TNode<BoolT> IsArraySpeciesProtectorCellInvalid();
  TNode<BoolT> IsIsConcatSpreadableProtectorCellInvalid();
  TNode<BoolT> IsTypedArraySpeciesProtectorCellInvalid();
  TNode<BoolT> IsRegExpSpeciesProtectorCellInvalid();
  TNode<BoolT> IsPromiseSpeciesProtectorCellInvalid();
  TNode<BoolT> IsNumberStringNotRegexpLikeProtectorCellInvalid();
  TNode<BoolT> IsSetIteratorProtectorCellInvalid();
  TNode<BoolT> IsMapIteratorProtectorCellInvalid();
  void InvalidateStringWrapperToPrimitiveProtector();

  TNode<IntPtrT> LoadMemoryChunkFlags(TNode<HeapObject> object);

  TNode<BoolT> LoadRuntimeFlag(ExternalReference address_of_flag) {
    TNode<Word32T> flag_value = UncheckedCast<Word32T>(
        Load(MachineType::Uint8(), ExternalConstant(address_of_flag)));
    return Word32NotEqual(Word32And(flag_value, Int32Constant(0xFF)),
                          Int32Constant(0));
  }

  TNode<BoolT> IsMockArrayBufferAllocatorFlag() {
    return LoadRuntimeFlag(
        ExternalReference::address_of_mock_arraybuffer_allocator_flag());
  }

  TNode<BoolT> HasBuiltinSubclassingFlag() {
    return LoadRuntimeFlag(
        ExternalReference::address_of_builtin_subclassing_flag());
  }

  TNode<BoolT> HasSharedStringTableFlag() {
    return LoadRuntimeFlag(
        ExternalReference::address_of_shared_string_table_flag());
  }

  TNode<BoolT> IsScriptContextMutableHeapNumberFlag() {
    return LoadRuntimeFlag(
        ExternalReference::script_context_mutable_heap_number_flag());
  }

  // True iff |object| is a Smi or a HeapNumber or a BigInt.
  TNode<BoolT> IsNumeric(TNode<Object> object);

  // True iff |number| is either a Smi, or a HeapNumber whose value is not
  // within Smi range.
  TNode<BoolT> IsNumberNormalized(TNode<Number> number);
  TNode<BoolT> IsNumberPositive(TNode<Number> number);
  TNode<BoolT> IsHeapNumberPositive(TNode<HeapNumber> number);

  // True iff {number} is non-negative and less or equal than 2**53-1.
  TNode<BoolT> IsNumberNonNegativeSafeInteger(TNode<Number> number);

  // True iff {number} represents an integer value.
  TNode<BoolT> IsInteger(TNode<Object> number);
  TNode<BoolT> IsInteger(TNode<HeapNumber> number);

  // True iff abs({number}) <= 2**53 -1
  TNode<BoolT> IsSafeInteger(TNode<Object> number);
  TNode<BoolT> IsSafeInteger(TNode<HeapNumber> number);

  // True iff {number} represents a valid uint32t value.
  TNode<BoolT> IsHeapNumberUint32(TNode<HeapNumber> number);

  // True iff {number} is a positive number and a valid array index in the range
  // [0, 2^32-1).
  TNode<BoolT> IsNumberArrayIndex(TNode<Number> number);

  template <typename TIndex>
  TNode<BoolT> FixedArraySizeDoesntFitInNewSpace(TNode<TIndex> element_count,
                                                 int base_size);

  // ElementsKind helpers:
  TNode<BoolT> ElementsKindEqual(TNode<Int32T> a, TNode<Int32T> b) {
    return Word32Equal(a, b);
  }
  bool ElementsKindEqual(ElementsKind a, ElementsKind b) { return a == b; }
  TNode<BoolT> IsFastElementsKind(TNode<Int32T> elements_kind);
  bool IsFastElementsKind(ElementsKind kind) {
    return v8::internal::IsFastElementsKind(kind);
  }
  TNode<BoolT> IsFastPackedElementsKind(TNode<Int32T> elements_kind);
  bool IsFastPackedElementsKind(ElementsKind kind) {
    return v8::internal::IsFastPackedElementsKind(kind);
  }
  TNode<BoolT> IsFastOrNonExtensibleOrSealedElementsKind(
      TNode<Int32T> elements_kind);

  TNode<BoolT> IsDictionaryElementsKind(TNode<Int32T> elements_kind) {
    return ElementsKindEqual(elements_kind, Int32Constant(DICTIONARY_ELEMENTS));
  }
  TNode<BoolT> IsDoubleElementsKind(TNode<Int32T> elements_kind);
  bool IsDoubleElementsKind(ElementsKind kind) {
    return v8::internal::IsDoubleElementsKind(kind);
  }
  TNode<BoolT> IsFastSmiOrTaggedElementsKind(TNode<Int32T> elements_kind);
  TNode<BoolT> IsFastSmiElementsKind(TNode<Int32T> elements_kind);
  TNode<BoolT> IsHoleyFastElementsKind(TNode<Int32T> elements_kind);
  TNode<BoolT> IsHoleyFastElementsKindForRead(TNode<Int32T> elements_kind);
  TNode<BoolT> IsElementsKindGreaterThan(TNode<Int32T> target_kind,
                                         ElementsKind reference_kind);
  TNode<BoolT> IsElementsKindGreaterThanOrEqual(TNode<Int32T> target_kind,
                                                ElementsKind reference_kind);
  TNode<BoolT> IsElementsKindLessThanOrEqual(TNode<Int32T> target_kind,
                                             ElementsKind reference_kind);
  // Check if lower_reference_kind <= target_kind <= higher_reference_kind.
  TNode<BoolT> IsElementsKindInRange(TNode<Int32T> target_kind,
                                     ElementsKind lower_reference_kind,
                                     ElementsKind higher_reference_kind) {
    return IsInRange(target_kind, lower_reference_kind, higher_reference_kind);
  }
  TNode<Int32T> GetNonRabGsabElementsKind(TNode<Int32T> elements_kind);

  // String helpers.
  // Load a character from a String (might flatten a ConsString).
  TNode<Uint16T> StringCharCodeAt(TNode<String> string, TNode<UintPtrT> index);
  // Return the single character string with only {code}.
  TNode<String> StringFromSingleCharCode(TNode<Int32T> code);

  // Type conversion helpers.
  enum class BigIntHandling { kConvertToNumber, kThrow };
  // Convert a String to a Number.
  TNode<Number> StringToNumber(TNode<String> input);
  // Convert a Number to a String.
  TNode<String> NumberToString(TNode<Number> input);
  TNode<String> NumberToString(TNode<Number> input, Label* bailout);

  // Convert a Non-Number object to a Number.
  TNode<Number> NonNumberToNumber(
      TNode<Context> context, TNode<HeapObject> input,
      BigIntHandling bigint_handling = BigIntHandling::kThrow);
  // Convert a Non-Number object to a Numeric.
  TNode<Numeric> NonNumberToNumeric(TNode<Context> context,
                                    TNode<HeapObject> input);
  // Convert any object to a Number.
  // Conforms to ES#sec-tonumber if {bigint_handling} == kThrow.
  // With {bigint_handling} == kConvertToNumber, matches behavior of
  // tc39.github.io/proposal-bigint/#sec-number-constructor-number-value.
  TNode<Number> ToNumber(
      TNode<Context> context, TNode<Object> input,
      BigIntHandling bigint_handling = BigIntHandling::kThrow);
  TNode<Number> ToNumber_Inline(TNode<Context> context, TNode<Object> input);
  TNode<Numeric> ToNumberOrNumeric(
      LazyNode<Context> context, TNode<Object> input,
      TVariable<Smi>* var_type_feedback, Object::Conversion mode,
      BigIntHandling bigint_handling = BigIntHandling::kThrow);
  // Convert any plain primitive to a Number. No need to handle BigInts since
  // they are not plain primitives.
  TNode<Number> PlainPrimitiveToNumber(TNode<Object> input);

  // Try to convert an object to a BigInt. Throws on failure (e.g. for Numbers).
  // https://tc39.github.io/proposal-bigint/#sec-to-bigint
  TNode<BigInt> ToBigInt(TNode<Context> context, TNode<Object> input);
  // Try to convert any object to a BigInt, including Numbers.
  TNode<BigInt> ToBigIntConvertNumber(TNode<Context> context,
                                      TNode<Object> input);

  // Converts |input| to one of 2^32 integer values in the range 0 through
  // 2^32-1, inclusive.
  // ES#sec-touint32
  TNode<Number> ToUint32(TNode<Context> context, TNode<Object> input);

  // No-op on 32-bit, otherwise zero extend.
  TNode<IntPtrT> ChangePositiveInt32ToIntPtr(TNode<Int32T> input) {
    CSA_DCHECK(this, Int32GreaterThanOrEqual(input, Int32Constant(0)));
    return Signed(ChangeUint32ToWord(input));
  }

  // Convert any object to a String.
  TNode<String> ToString_Inline(TNode<Context> context, TNode<Object> input);

  TNode<JSReceiver> ToObject(TNode<Context> context, TNode<Object> input);

  // Same as ToObject but avoids the Builtin call if |input| is already a
  // JSReceiver.
  TNode<JSReceiver> ToObject_Inline(TNode<Context> context,
                                    TNode<Object> input);

  // ES6 7.1.15 ToLength, but with inlined fast path.
  TNode<Number> ToLength_Inline(TNode<Context> context, TNode<Object> input);

  TNode<Object> OrdinaryToPrimitive(TNode<Context> context, TNode<Object> input,
                                    OrdinaryToPrimitiveHint hint);

  // Returns a node that contains a decoded (unsigned!) value of a bit
  // field |BitField| in |word32|. Returns result as an uint32 node.
  template <typename BitField>
  TNode<Uint32T> DecodeWord32(TNode<Word32T> word32) {
    return DecodeWord32(word32, BitField::kShift, BitField::kMask);
  }

  // Returns a node that contains a decoded (unsigned!) value of a bit
  // field |BitField| in |word|. Returns result as a word-size node.
  template <typename BitField>
  TNode<UintPtrT> DecodeWord(TNode<WordT> word) {
    return DecodeWord(word, BitField::kShift, BitField::kMask);
  }

  // Returns a node that contains a decoded (unsigned!) value of a bit
  // field |BitField| in |word32|. Returns result as a word-size node.
  template <typename BitField>
  TNode<UintPtrT> DecodeWordFromWord32(TNode<Word32T> word32) {
    return DecodeWord<BitField>(ChangeUint32ToWord(word32));
  }

  // Returns a node that contains a decoded (unsigned!) value of a bit
  // field |BitField| in |word|. Returns result as an uint32 node.
  template <typename BitField>
  TNode<Uint32T> DecodeWord32FromWord(TNode<WordT> word) {
    return UncheckedCast<Uint32T>(
        TruncateIntPtrToInt32(Signed(DecodeWord<BitField>(word))));
  }

  // Decodes an unsigned (!) value from |word32| to an uint32 node.
  TNode<Uint32T> DecodeWord32(TNode<Word32T> word32, uint32_t shift,
                              uint32_t mask);

  // Decodes an unsigned (!) value from |word| to a word-size node.
  TNode<UintPtrT> DecodeWord(TNode<WordT> word, uint32_t shift, uintptr_t mask);

  // Returns a node that contains the updated values of a |BitField|.
  template <typename BitField>
  TNode<Word32T> UpdateWord32(TNode<Word32T> word, TNode<Uint32T> value,
                              bool starts_as_zero = false) {
    return UpdateWord32(word, value, BitField::kShift, BitField::kMask,
                        starts_as_zero);
  }

  // Returns a node that contains the updated values of a |BitField|.
  template <typename BitField>
  TNode<WordT> UpdateWord(TNode<WordT> word, TNode<UintPtrT> value,
                          bool starts_as_zero = false) {
    return UpdateWord(word, value, BitField::kShift, BitField::kMask,
                      starts_as_zero);
  }

  // Returns a node that contains the updated values of a |BitField|.
  template <typename BitField>
  TNode<Word32T> UpdateWordInWord32(TNode<Word32T> word, TNode<UintPtrT> value,
                                    bool starts_as_zero = false) {
    return UncheckedCast<Uint32T>(
        TruncateIntPtrToInt32(Signed(UpdateWord<BitField>(
            ChangeUint32ToWord(word), value, starts_as_zero))));
  }

  // Returns a node that contains the updated values of a |BitField|.
  template <typename BitField>
  TNode<WordT> UpdateWord32InWord(TNode<WordT> word, TNode<Uint32T> value,
                                  bool starts_as_zero = false) {
    return UpdateWord<BitField>(word, ChangeUint32ToWord(value),
                                starts_as_zero);
  }

  // Returns a node that contains the updated {value} inside {word} starting
  // at {shift} and fitting in {mask}.
  TNode<Word32T> UpdateWord32(TNode<Word32T> word, TNode<Uint32T> value,
                              uint32_t shift, uint32_t mask,
                              bool starts_as_zero = false);

  // Returns a node that contains the updated {value} inside {word} starting
  // at {shift} and fitting in {mask}.
  TNode<WordT> UpdateWord(TNode<WordT> word, TNode<UintPtrT> value,
                          uint32_t shift, uintptr_t mask,
                          bool starts_as_zero = false);

  // Returns true if any of the |T|'s bits in given |word32| are set.
  template <typename T>
  TNode<BoolT> IsSetWord32(TNode<Word32T> word32) {
    return IsSetWord32(word32, T::kMask);
  }

  // Returns true if none of the |T|'s bits in given |word32| are set.
  template <typename T>
  TNode<BoolT> IsNotSetWord32(TNode<Word32T> word32) {
    return IsNotSetWord32(word32, T::kMask);
  }

  // Returns true if any of the mask's bits in given |word32| are set.
  TNode<BoolT> IsSetWord32(TNode<Word32T> word32, uint32_t mask) {
    return Word32NotEqual(Word32And(word32, Int32Constant(mask)),
                          Int32Constant(0));
  }

  // Returns true if none of the mask's bits in given |word32| are set.
  TNode<BoolT> IsNotSetWord32(TNode<Word32T> word32, uint32_t mask) {
    return Word32Equal(Word32And(word32, Int32Constant(mask)),
                       Int32Constant(0));
  }

  // Returns true if all of the mask's bits in a given |word32| are set.
  TNode<BoolT> IsAllSetWord32(TNode<Word32T> word32, uint32_t mask) {
    TNode<Int32T> const_mask = Int32Constant(mask);
    return Word32Equal(Word32And(word32, const_mask), const_mask);
  }

  // Returns true if the bit field |BitField| in |word32| is equal to a given
  // constant |value|. Avoids a shift compared to using DecodeWord32.
  template <typename BitField>
  TNode<BoolT> IsEqualInWord32(TNode<Word32T> word32,
                               typename BitField::FieldType value) {
    TNode<Word32T> masked_word32 =
        Word32And(word32, Int32Constant(BitField::kMask));
    return Word32Equal(masked_word32, Int32Constant(BitField::encode(value)));
  }

  // Checks if two values of non-overlapping bitfields are both set.
  template <typename BitField1, typename BitField2>
  TNode<BoolT> IsBothEqualInWord32(TNode<Word32T> word32,
                                   typename BitField1::FieldType value1,
                                   typename BitField2::FieldType value2) {
    static_assert((BitField1::kMask & BitField2::kMask) == 0);
    TNode<Word32T> combined_masked_word32 =
        Word32And(word32, Int32Constant(BitField1::kMask | BitField2::kMask));
    TNode<Int32T> combined_value =
        Int32Constant(BitField1::encode(value1) | BitField2::encode(value2));
    return Word32Equal(combined_masked_word32, combined_value);
  }

  // Returns true if the bit field |BitField| in |word32| is not equal to a
  // given constant |value|. Avoids a shift compared to using DecodeWord32.
  template <typename BitField>
  TNode<BoolT> IsNotEqualInWord32(TNode<Word32T> word32,
                                  typename BitField::FieldType value) {
    return Word32BinaryNot(IsEqualInWord32<BitField>(word32, value));
  }

  // Returns true if any of the |T|'s bits in given |word| are set.
  template <typename T>
  TNode<BoolT> IsSetWord(TNode<WordT> word) {
    return IsSetWord(word, T::kMask);
  }

  // Returns true if any of the mask's bits in given |word| are set.
  TNode<BoolT> IsSetWord(TNode<WordT> word, uint32_t mask) {
    return WordNotEqual(WordAnd(word, IntPtrConstant(mask)), IntPtrConstant(0));
  }

  // Returns true if any of the mask's bit are set in the given Smi.
  // Smi-encoding of the mask is performed implicitly!
  TNode<BoolT> IsSetSmi(TNode<Smi> smi, int untagged_mask) {
    intptr_t mask_word = base::bit_cast<intptr_t>(Smi::FromInt(untagged_mask));
    return WordNotEqual(WordAnd(BitcastTaggedToWordForTagAndSmiBits(smi),
                                IntPtrConstant(mask_word)),
                        IntPtrConstant(0));
  }

  // Returns true if all of the |T|'s bits in given |word32| are clear.
  template <typename T>
  TNode<BoolT> IsClearWord32(TNode<Word32T> word32) {
    return IsClearWord32(word32, T::kMask);
  }

  // Returns true if all of the mask's bits in given |word32| are clear.
  TNode<BoolT> IsClearWord32(TNode<Word32T> word32, uint32_t mask) {
    return Word32Equal(Word32And(word32, Int32Constant(mask)),
                       Int32Constant(0));
  }

  // Returns true if all of the |T|'s bits in given |word| are clear.
  template <typename T>
  TNode<BoolT> IsClearWord(TNode<WordT> word) {
    return IsClearWord(word, T::kMask);
  }

  // Returns true if all of the mask's bits in given |word| are clear.
  TNode<BoolT> IsClearWord(TNode<WordT> word, uint32_t mask) {
    return IntPtrEqual(WordAnd(word, IntPtrConstant(mask)), IntPtrConstant(0));
  }

  void SetCounter(StatsCounter* counter, int value);
  void IncrementCounter(StatsCounter* counter, int delta);
  void DecrementCounter(StatsCounter* counter, int delta);

  template <typename TIndex>
  void Increment(TVariable<TIndex>* variable, int value = 1);

  template <typename TIndex>
  void Decrement(TVariable<TIndex>* variable, int value = 1) {
    Increment(variable, -value);
  }

  // Generates "if (false) goto label" code. Useful for marking a label as
  // "live" to avoid assertion failures during graph building. In the resulting
  // code this check will be eliminated.
  void Use(Label* label);

  // Various building blocks for stubs doing property lookups.

  // |if_notinternalized| is optional; |if_bailout| will be used by default.
  // Note: If |key| does not yet have a hash, |if_notinternalized| will be taken
  // even if |key| is an array index. |if_keyisunique| will never
  // be taken for array indices.
  void TryToName(TNode<Object> key, Label* if_keyisindex,
                 TVariable<IntPtrT>* var_index, Label* if_keyisunique,
                 TVariable<Name>* var_unique, Label* if_bailout,
                 Label* if_notinternalized = nullptr);

  // Call non-allocating runtime String::WriteToFlat using fast C-calls.
  void StringWriteToFlatOneByte(TNode<String> source, TNode<RawPtrT> sink,
                                TNode<Int32T> start, TNode<Int32T> length);
  void StringWriteToFlatTwoByte(TNode<String> source, TNode<RawPtrT> sink,
                                TNode<Int32T> start, TNode<Int32T> length);

  // Calls External{One,Two}ByteString::GetChars with a fast C-call.
  TNode<RawPtr<Uint8T>> ExternalOneByteStringGetChars(
      TNode<ExternalOneByteString> string);
  TNode<RawPtr<Uint16T>> ExternalTwoByteStringGetChars(
      TNode<ExternalTwoByteString> string);

  TNode<RawPtr<Uint8T>> IntlAsciiCollationWeightsL1();
  TNode<RawPtr<Uint8T>> IntlAsciiCollationWeightsL3();

  // Performs a hash computation and string table lookup for the given string,
  // and jumps to:
  // - |if_index| if the string is an array index like "123"; |var_index|
  //              will contain the intptr representation of that index.
  // - |if_internalized| if the string exists in the string table; the
  //                     internalized version will be in |var_internalized|.
  // - |if_not_internalized| if the string is not in the string table (but
  //                         does not add it).
  // - |if_bailout| for unsupported cases (e.g. uncachable array index).
  void TryInternalizeString(TNode<String> string, Label* if_index,
                            TVariable<IntPtrT>* var_index,
                            Label* if_internalized,
                            TVariable<Name>* var_internalized,
                            Label* if_not_internalized, Label* if_bailout);

  // Calculates array index for given dictionary entry and entry field.
  // See Dictionary::EntryToIndex().
  template <typename Dictionary>
  TNode<IntPtrT> EntryToIndex(TNode<IntPtrT> entry, int field_index);
  template <typename Dictionary>
  TNode<IntPtrT> EntryToIndex(TNode<IntPtrT> entry) {
    return EntryToIndex<Dictionary>(entry, Dictionary::kEntryKeyIndex);
  }

  // Loads the details for the entry with the given key_index.
  // Returns an untagged int32.
  template <class ContainerType>
  TNode<Uint32T> LoadDetailsByKeyIndex(TNode<ContainerType> container,
                                       TNode<IntPtrT> key_index);

  // Loads the value for the entry with the given key_index.
  // Returns a tagged value.
  template <class ContainerType>
  TNode<Object> LoadValueByKeyIndex(TNode<ContainerType> container,
                                    TNode<IntPtrT> key_index);

  // Stores the details for the entry with the given key_index.
  // |details| must be a Smi.
  template <class ContainerType>
  void StoreDetailsByKeyIndex(TNode<ContainerType> container,
                              TNode<IntPtrT> key_index, TNode<Smi> details);

  // Stores the value for the entry with the given key_index.
  template <class ContainerType>
  void StoreValueByKeyIndex(
      TNode<ContainerType> container, TNode<IntPtrT> key_index,
      TNode<Object> value,
      WriteBarrierMode write_barrier = UPDATE_WRITE_BARRIER);

  // Calculate a valid size for the a hash table.
  TNode<IntPtrT> HashTableComputeCapacity(TNode<IntPtrT> at_least_space_for);

  TNode<IntPtrT> NameToIndexHashTableLookup(TNode<NameToIndexHashTable> table,
                                            TNode<Name> name, Label* not_found);

  template <class Dictionary>
  TNode<Smi> GetNumberOfElements(TNode<Dictionary> dictionary);

  TNode<Smi> GetNumberDictionaryNumberOfElements(
      TNode<NumberDictionary> dictionary) {
    return GetNumberOfElements<NumberDictionary>(dictionary);
  }

  template <class Dictionary>
  void SetNumberOfElements(TNode<Dictionary> dictionary,
                           TNode<Smi> num_elements_smi) {
    // Not supposed to be used for SwissNameDictionary.
    static_assert(!(std::is_same<Dictionary, SwissNameDictionary>::value));

    StoreFixedArrayElement(dictionary, Dictionary::kNumberOfElementsIndex,
                           num_elements_smi, SKIP_WRITE_BARRIER);
  }

  template <class Dictionary>
  TNode<Smi> GetNumberOfDeletedElements(TNode<Dictionary> dictionary) {
    // Not supposed to be used for SwissNameDictionary.
    static_assert(!(std::is_same<Dictionary, SwissNameDictionary>::value));

    return CAST(LoadFixedArrayElement(
        dictionary, Dictionary::kNumberOfDeletedElementsIndex));
  }

  template <class Dictionary>
  void SetNumberOfDeletedElements(TNode<Dictionary> dictionary,
                                  TNode<Smi> num_deleted_smi) {
    // Not supposed to be used for SwissNameDictionary.
    static_assert(!(std::is_same<Dictionary, SwissNameDictionary>::value));

    StoreFixedArrayElement(dictionary,
                           Dictionary::kNumberOfDeletedElementsIndex,
                           num_deleted_smi, SKIP_WRITE_BARRIER);
  }

  template <class Dictionary>
  TNode<Smi> GetCapacity(TNode<Dictionary> dictionary) {
    // Not supposed to be used for SwissNameDictionary.
    static_assert(!(std::is_same<Dictionary, SwissNameDictionary>::value));

    return CAST(
        UnsafeLoadFixedArrayElement(dictionary, Dictionary::kCapacityIndex));
  }

  template <class Dictionary>
  TNode<Smi> GetNextEnumerationIndex(TNode<Dictionary> dictionary) {
    return CAST(LoadFixedArrayElement(dictionary,
                                      Dictionary::kNextEnumerationIndexIndex));
  }

  template <class Dictionary>
  void SetNextEnumerationIndex(TNode<Dictionary> dictionary,
                               TNode<Smi> next_enum_index_smi) {
    StoreFixedArrayElement(dictionary, Dictionary::kNextEnumerationIndexIndex,
                           next_enum_index_smi, SKIP_WRITE_BARRIER);
  }

  template <class Dictionary>
  TNode<Smi> GetNameDictionaryFlags(TNode<Dictionary> dictionary);
  template <class Dictionary>
  void SetNameDictionaryFlags(TNode<Dictionary>, TNode<Smi> flags);

  enum LookupMode {
    kFindExisting,
    kFindInsertionIndex,
    kFindExistingOrInsertionIndex
  };

  template <typename Dictionary>
  TNode<HeapObject> LoadName(TNode<HeapObject> key);

  // Looks up an entry in a NameDictionaryBase successor.
  // If the entry is found control goes to {if_found} and {var_name_index}
  // contains an index of the key field of the entry found.
  // If the key is not found control goes to {if_not_found}. If mode is
  // {kFindExisting}, {var_name_index} might contain garbage, otherwise
  // {var_name_index} contains the index of the key field to insert the given
  // name at.
  template <typename Dictionary>
  void NameDictionaryLookup(TNode<Dictionary> dictionary,
                            TNode<Name> unique_name, Label* if_found,
                            TVariable<IntPtrT>* var_name_index,
                            Label* if_not_found,
                            LookupMode mode = kFindExisting);
  // Slow lookup for unique_names with forwarding index.
  // Both resolving the actual hash and the lookup are handled via runtime.
  template <typename Dictionary>
  void NameDictionaryLookupWithForwardIndex(TNode<Dictionary> dictionary,
                                            TNode<Name> unique_name,
                                            Label* if_found,
                                            TVariable<IntPtrT>* var_name_index,
                                            Label* if_not_found,
                                            LookupMode mode = kFindExisting);

  TNode<Word32T> ComputeSeededHash(TNode<IntPtrT> key);

  // Looks up an entry in a NameDictionaryBase successor. If the entry is found
  // control goes to {if_found} and {var_name_index} contains an index of the
  // key field of the entry found. If the key is not found control goes to
  // {if_not_found}.
  void NumberDictionaryLookup(TNode<NumberDictionary> dictionary,
                              TNode<IntPtrT> intptr_index, Label* if_found,
                              TVariable<IntPtrT>* var_entry,
                              Label* if_not_found);

  TNode<Object> BasicLoadNumberDictionaryElement(
      TNode<NumberDictionary> dictionary, TNode<IntPtrT> intptr_index,
      Label* not_data, Label* if_hole);

  template <class Dictionary>
  void FindInsertionEntry(TNode<Dictionary> dictionary, TNode<Name> key,
                          TVariable<IntPtrT>* var_key_index);

  template <class Dictionary>
  void InsertEntry(TNode<Dictionary> dictionary, TNode<Name> key,
                   TNode<Object> value, TNode<IntPtrT> index,
                   TNode<Smi> enum_index);

  template <class Dictionary>
  void AddToDictionary(
      TNode<Dictionary> dictionary, TNode<Name> key, TNode<Object> value,
      Label* bailout,
      std::optional<TNode<IntPtrT>> insertion_index = std::nullopt);

  // Tries to check if {object} has own {unique_name} property.
  void TryHasOwnProperty(TNode<HeapObject> object, TNode<Map> map,
                         TNode<Int32T> instance_type, TNode<Name> unique_name,
                         Label* if_found, Label* if_not_found,
                         Label* if_bailout);

  // Operating mode for TryGetOwnProperty and CallGetterIfAccessor
  enum GetOwnPropertyMode {
    // kCallJSGetterDontUseCachedName is used when we want to get the result of
    // the getter call, and don't use cached_name_property when the getter is
    // the function template and it has cached_property_name, which would just
    // bailout for the IC system to create a named property handler
    kCallJSGetterDontUseCachedName,
    // kCallJSGetterUseCachedName is used when we want to get the result of
    // the getter call, and use cached_name_property when the getter is
    // the function template and it has cached_property_name, which would call
    // GetProperty rather than bailout for Generic/NoFeedback load
    kCallJSGetterUseCachedName,
    // kReturnAccessorPair is used when we're only getting the property
    // descriptor
    kReturnAccessorPair
  };
  // Receiver handling mode for TryGetOwnProperty and CallGetterIfAccessor.
  enum ExpectedReceiverMode {
    // The receiver is guaranteed to be JSReceiver, no conversion is necessary
    // in case a function callback template has to be called.
    kExpectingJSReceiver,
    // The receiver can be anything, it has to be converted to JSReceiver
    // in case a function callback template has to be called.
    kExpectingAnyReceiver,
  };
  // Tries to get {object}'s own {unique_name} property value. If the property
  // is an accessor then it also calls a getter. If the property is a double
  // field it re-wraps value in an immutable heap number. {unique_name} must be
  // a unique name (Symbol or InternalizedString) that is not an array index.
  void TryGetOwnProperty(
      TNode<Context> context, TNode<Object> receiver, TNode<JSReceiver> object,
      TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
      Label* if_found_value, TVariable<Object>* var_value, Label* if_not_found,
      Label* if_bailout,
      ExpectedReceiverMode expected_receiver_mode = kExpectingAnyReceiver);
  void TryGetOwnProperty(
      TNode<Context> context, TNode
```