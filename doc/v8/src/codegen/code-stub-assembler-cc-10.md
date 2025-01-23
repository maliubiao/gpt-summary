Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Initial Understanding - Core Purpose:** The filename `code-stub-assembler.cc` immediately suggests this code is about generating low-level machine code stubs within the V8 engine. The `CodeStubAssembler` class is likely a helper for this process, providing an abstraction layer over direct machine code manipulation.

2. **Scanning for Key Functionalities:**  A quick skim reveals methods related to:
    * **Type checking:** `IsSmi`, `IsHeapNumber`, `IsString`, `IsNumberArrayIndex`, etc. These are fundamental for dynamic languages like JavaScript.
    * **Memory access:** `Load`, `Store`, `LoadMemoryChunkFlags`. This confirms the low-level nature and interaction with V8's heap management.
    * **String manipulation:** `StringCharCodeAt`, `StringFromSingleCharCode`, `ToDirectStringAssembler`. String operations are crucial in JavaScript.
    * **Number conversion:** `StringToNumber`, `NumberToString`, `ToNumber`, `ToUint32`, `ToBigInt`. JavaScript's type coercion rules make these essential.
    * **Runtime calls:** `CallRuntime`, `CallBuiltin`. This indicates interaction with higher-level parts of the V8 runtime.
    * **Control flow:** `Label`, `Branch`, `Goto`, `Switch`. This is how the code assembler constructs control flow in the generated stubs.

3. **Categorization and Grouping:**  To structure the analysis, it's helpful to group related functions:

    * **Type System & Checks:**  Functions like `IsSmi`, `IsHeapNumber`, `TaggedIsSmi`, `IsString`, `IsNumberArrayIndex`, `IsBigInt`. These are the building blocks for type-aware code generation.
    * **String Handling:** `StringCharCodeAt`, `StringFromSingleCharCode`, `ToDirectStringAssembler`. This seems to optimize common string operations by directly accessing string internals.
    * **Number Conversions:** `StringToNumber`, `NumberToString`, `ToNumber`, `ToUint32`, `ToBigInt`, `NonNumberToNumber`. This is a complex area due to JavaScript's implicit conversions.
    * **Memory and Object Access:** `Load`, `Store`, `LoadMemoryChunkFlags`, `UnsafeLoadFixedArrayElement`. This is where the assembler interacts with the V8 heap.
    * **Control Flow and Optimization:** `Label`, `Branch`, `Goto`, `Switch`,  `TryToDirect`. `TryToDirect` appears to be an optimization for accessing string data directly.
    * **Runtime Integration:** `CallRuntime`, `CallBuiltin`. Bridges between generated code and the V8 runtime.

4. **Detailed Examination of Key Functions (with examples):**  For each category, pick out representative functions and think about their behavior:

    * **`IsNumberArrayIndex`:**  This checks if a `Number` can be used as an array index.
        * *JavaScript Example:* `const arr = []; arr[0] = 5; arr['0'] = 10;` (demonstrates implicit string-to-number conversion for indexing).
        * *Logic:* Checks if it's a positive Smi or a HeapNumber that represents a valid Uint32.
    * **`StringCharCodeAt`:** Gets the character code at a specific index in a string.
        * *JavaScript Example:* `"abc".charCodeAt(1)` would return 98.
        * *Logic:* Handles different string encodings (one-byte vs. two-byte) and potentially falls back to runtime for complex cases.
    * **`StringToNumber`:** Converts a string to a number.
        * *JavaScript Example:* `"123"` becomes `123`, `"abc"` becomes `NaN`.
        * *Logic:* Tries to use a cached array index if available for optimization, otherwise calls the runtime.
    * **`NumberToString`:** Converts a number to a string.
        * *JavaScript Example:* `123` becomes `"123"`.
        * *Logic:* Uses a cache for common numbers and falls back to runtime for more complex cases.
    * **`ToNumber`:** Converts a JavaScript value to a number.
        * *JavaScript Example:* `ToNumber("42")` is `42`, `ToNumber(true)` is `1`, `ToNumber(null)` is `0`.
        * *Logic:* Handles Smis, HeapNumbers, and non-numeric types (calling `NonNumberToNumber`).
    * **`ToDirectStringAssembler`:** This is clearly for optimizing direct access to string data, skipping layers of abstraction.

5. **Considering `.tq` Files (Torque):** The prompt mentions `.tq`. If this were a `.tq` file, it would indicate a higher-level, type-safe language (Torque) used for generating C++ code for V8. This `.cc` file is the *output* of potentially some Torque code, or directly written C++.

6. **User Errors:** Think about common mistakes related to the functionalities:

    * **Type errors in array indexing:** Trying to use non-numeric strings as array indices (e.g., `arr["hello"]`).
    * **Implicit type conversions:**  Not understanding how JavaScript converts strings to numbers (e.g., `"1" + 1` vs. `1 + "1"`).
    * **Loss of precision with `ToUint32`:**  Not realizing that `ToUint32` performs modulo 2<sup>32</sup>.
    * **Incorrect assumptions about `ToBigInt`:**  Trying to convert non-numeric strings to BigInt.

7. **Logic Inference (Example):**

    * **Function:** `IsNumberArrayIndex(number)`
    * **Hypothesis:** Input is a `Number` object.
    * **Scenario 1 (Input: Smi 5):**
        * `TaggedIsSmi(5)` is true.
        * `TaggedIsPositiveSmi(5)` is true.
        * **Output:** `true`
    * **Scenario 2 (Input: HeapNumber -3.14):**
        * `TaggedIsSmi(-3.14)` is false.
        * `IsHeapNumberUint32(-3.14)` is false (not a valid unsigned 32-bit integer).
        * **Output:** `false`
    * **Scenario 3 (Input: HeapNumber 10):**
        * `TaggedIsSmi(10)` is false.
        * `IsHeapNumberUint32(10)` is true.
        * **Output:** `true`

8. **Summarization (Based on the Segment):** Focus on what the *provided* code does. It's heavily focused on type checking, string manipulation optimizations, and number conversions. The memory access functions are present but not the central theme of this particular segment.

By following these steps, you can systematically analyze a piece of V8 source code, understand its functionality, and provide relevant examples and insights.
好的，让我们来分析一下 `v8/src/codegen/code-stub-assembler.cc` 的这个代码片段的功能。

**核心功能归纳：**

这个代码片段是 `CodeStubAssembler` 类的一部分，`CodeStubAssembler` 是 V8 中用于生成优化的、特定功能的机器码 "代码桩 (code stub)" 的核心工具。 这个片段主要关注以下几个方面：

1. **类型判断与转换:**  提供了多种用于判断和转换 JavaScript 值的类型的工具函数。例如，判断是否是 Smi (小整数), HeapNumber (堆上的数字), String (字符串)，以及将字符串转换为数字，数字转换为字符串等等。

2. **字符串操作优化:** 包含了一些用于优化字符串操作的逻辑，例如 `ToDirectStringAssembler` 类，它旨在直接访问字符串的内部数据，避免不必要的间接操作，提高性能。

3. **内存访问:**  提供了一些底层的内存访问函数，例如 `Load` 和 `Store`，用于在生成的代码桩中直接读取和写入内存。

4. **控制流:**  使用了 `Label`, `Branch`, `Goto`, `Switch` 等来实现代码的条件分支和跳转，这是代码生成的基础。

5. **运行时调用:**  通过 `CallRuntime` 和 `CallBuiltin` 函数，可以从生成的代码桩中调用 V8 的运行时函数和内建函数，以处理更复杂的操作或不常见的场景。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾：**

如果这个文件以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码。Torque 是 V8 开发的一种领域特定语言，用于以更高级、类型安全的方式生成 C++ 代码，特别是用于实现内置函数和运行时功能。 `.tq` 文件会被编译成 `.cc` 文件。

**与 Javascript 功能的关系及 Javascript 示例：**

这个代码片段中的功能与 JavaScript 的许多基本操作息息相关，因为它负责生成执行这些操作的底层代码。以下是一些示例：

* **类型判断:** 当 JavaScript 引擎需要判断一个变量的类型时（例如，在 `typeof` 运算符或类型比较中），`IsSmi`, `IsHeapNumber`, `IsString` 等函数生成的代码会被执行。

  ```javascript
  const num = 10;
  const str = "hello";
  console.log(typeof num); // "number"
  console.log(typeof str); // "string"
  ```

* **字符串操作:**  `StringCharCodeAt` 和 `StringFromSingleCharCode` 等函数生成的代码用于实现 `String.prototype.charCodeAt()` 和 `String.fromCharCode()` 等方法。

  ```javascript
  const text = "abc";
  console.log(text.charCodeAt(1)); // 98
  console.log(String.fromCharCode(65)); // "A"
  ```

* **类型转换:** `StringToNumber`, `NumberToString`, `ToNumber`, `ToUint32` 等函数生成的代码用于实现 JavaScript 中的隐式或显式类型转换。

  ```javascript
  console.log("10" + 5);   // "105" (字符串连接，涉及到 NumberToString)
  console.log(parseInt("10")); // 10  (显式转换，涉及到 StringToNumber)
  console.log(+"5");      // 5   (一元加号，涉及到 ToNumber)
  console.log(2**32 - 1); // 4294967295
  console.log(2**32);     // 4294967296
  console.log(2**32 >>> 0); // 0  (无符号右移，涉及到 ToUint32)
  ```

* **数组索引:** `IsNumberArrayIndex` 用于判断一个数字是否可以作为数组的有效索引。

  ```javascript
  const arr = [1, 2, 3];
  console.log(arr[0]);   // 1
  console.log(arr["0"]);  // 1 (字符串 "0" 会被转换为数字 0)
  console.log(arr[1.5]); // undefined (1.5 不是有效的数组索引)
  console.log(arr[-1]);  // undefined (-1 不是有效的数组索引)
  ```

**代码逻辑推理 (假设输入与输出)：**

以 `IsNumberArrayIndex(TNode<Number> number)` 为例：

**假设输入 1:** `number` 是一个 Smi，值为 `5`。
* `TaggedIsSmi(number)` 返回 `true`。
* 执行 lambda 表达式 `[=, this] { return TaggedIsPositiveSmi(number); }`。
* `TaggedIsPositiveSmi(number)` 返回 `true` (因为 5 是正数)。
* **输出:** `true`

**假设输入 2:** `number` 是一个 HeapNumber，值为 `-3.14`。
* `TaggedIsSmi(number)` 返回 `false`。
* 执行 lambda 表达式 `[=, this] { return IsHeapNumberUint32(CAST(number)); }`。
* `IsHeapNumberUint32(CAST(number))` 会检查 `-3.14` 是否可以安全地转换为 Uint32，结果是 `false`。
* **输出:** `false`

**假设输入 3:** `number` 是一个 HeapNumber，值为 `10`。
* `TaggedIsSmi(number)` 返回 `false`。
* 执行 lambda 表达式 `[=, this] { return IsHeapNumberUint32(CAST(number)); }`。
* `IsHeapNumberUint32(CAST(number))` 会检查 `10` 是否可以安全地转换为 Uint32，结果是 `true`。
* **输出:** `true`

**用户常见的编程错误及示例：**

* **错误地假设字符串到数字的转换：**

  ```javascript
  const input = "abc";
  const result = parseInt(input); // NaN
  if (result) { // 用户可能错误地认为非 NaN 的值是 true
    console.log("Conversion successful");
  } else {
    console.log("Conversion failed"); // 实际会执行这里
  }
  ```
  `StringToNumber` 或 `parseInt` 会将非数字字符串转换为 `NaN`，而 `NaN` 在布尔上下文中被认为是 `false`。

* **对 `ToUint32` 的误解：**

  ```javascript
  const largeNumber = 4294967296; // 2**32
  console.log(largeNumber >>> 0); // 0
  ```
  `ToUint32` 会将数字转换为无符号 32 位整数，这意味着会进行模 2<sup>32</sup> 运算，导致超出范围的值被截断。

* **类型转换的意外行为：**

  ```javascript
  console.log(0.1 + 0.2 === 0.3); // false
  ```
  浮点数在二进制表示中存在精度问题，这会导致一些看似简单的加法运算结果不精确。`CodeStubAssembler` 中处理数字的逻辑需要考虑这些精度问题。

**第 11 部分，共 23 部分的功能归纳：**

结合代码片段的内容，第 11 部分的 `v8/src/codegen/code-stub-assembler.cc` 主要集中在：

* **基础的类型判断和转换操作的实现。**
* **针对字符串操作的优化手段的构建。**
* **提供底层的内存访问能力，以便生成高效的代码。**
* **构建代码的控制流结构，实现条件执行和跳转。**
* **提供与 V8 运行时环境交互的接口。**

总的来说，这个代码片段是 V8 代码生成器的重要组成部分，它提供了构建高性能 JavaScript 执行代码所需的各种低级工具和抽象。它负责将高级的 JavaScript 操作转化为具体的机器指令序列。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
mber);
        TNode<Uint32T> int_value = TruncateFloat64ToWord32(value);
        return Float64Equal(value, ChangeUint32ToFloat64(int_value));
      },
      [=, this] { return Int32FalseConstant(); });
}

TNode<BoolT> CodeStubAssembler::IsNumberArrayIndex(TNode<Number> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return TaggedIsPositiveSmi(number); },
      [=, this] { return IsHeapNumberUint32(CAST(number)); });
}

TNode<IntPtrT> CodeStubAssembler::LoadMemoryChunkFlags(
    TNode<HeapObject> object) {
  TNode<IntPtrT> object_word = BitcastTaggedToWord(object);
  TNode<IntPtrT> page_header = MemoryChunkFromAddress(object_word);
  return UncheckedCast<IntPtrT>(
      Load(MachineType::Pointer(), page_header,
           IntPtrConstant(MemoryChunk::FlagsOffset())));
}

template <typename TIndex>
TNode<BoolT> CodeStubAssembler::FixedArraySizeDoesntFitInNewSpace(
    TNode<TIndex> element_count, int base_size) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT element_count is allowed");
  int max_newspace_elements =
      (kMaxRegularHeapObjectSize - base_size) / kTaggedSize;
  return IntPtrOrSmiGreaterThan(
      element_count, IntPtrOrSmiConstant<TIndex>(max_newspace_elements));
}

TNode<Uint16T> CodeStubAssembler::StringCharCodeAt(TNode<String> string,
                                                   TNode<UintPtrT> index) {
  CSA_DCHECK(this, UintPtrLessThan(index, LoadStringLengthAsWord(string)));

  TVARIABLE(Uint16T, var_result);

  Label return_result(this), if_runtime(this, Label::kDeferred),
      if_stringistwobyte(this), if_stringisonebyte(this);

  ToDirectStringAssembler to_direct(state(), string);
  to_direct.TryToDirect(&if_runtime);
  const TNode<UintPtrT> offset =
      UintPtrAdd(index, Unsigned(to_direct.offset()));
  const TNode<BoolT> is_one_byte = to_direct.IsOneByte();
  const TNode<RawPtrT> string_data = to_direct.PointerToData(&if_runtime);

  // Check if the {string} is a TwoByteSeqString or a OneByteSeqString.
  Branch(is_one_byte, &if_stringisonebyte, &if_stringistwobyte);

  BIND(&if_stringisonebyte);
  {
    var_result = Load<Uint8T>(string_data, offset);
    Goto(&return_result);
  }

  BIND(&if_stringistwobyte);
  {
    var_result = Load<Uint16T>(string_data, WordShl(offset, IntPtrConstant(1)));
    Goto(&return_result);
  }

  BIND(&if_runtime);
  {
    TNode<Object> result =
        CallRuntime(Runtime::kStringCharCodeAt, NoContextConstant(), string,
                    ChangeUintPtrToTagged(index));
    var_result = UncheckedCast<Uint16T>(SmiToInt32(CAST(result)));
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<String> CodeStubAssembler::StringFromSingleCharCode(TNode<Int32T> code) {
  TVARIABLE(String, var_result);

  // Check if the {code} is a one-byte char code.
  Label if_codeisonebyte(this), if_codeistwobyte(this, Label::kDeferred),
      if_done(this);
  Branch(Int32LessThanOrEqual(code, Int32Constant(String::kMaxOneByteCharCode)),
         &if_codeisonebyte, &if_codeistwobyte);
  BIND(&if_codeisonebyte);
  {
    // Load the isolate wide single character string cache.
    TNode<FixedArray> cache = SingleCharacterStringTableConstant();
    TNode<IntPtrT> code_index = Signed(ChangeUint32ToWord(code));

    TNode<Object> entry = UnsafeLoadFixedArrayElement(cache, code_index);
    CSA_DCHECK(this, Word32BinaryNot(IsUndefined(entry)));

    // Return the entry from the {cache}.
    var_result = CAST(entry);
    Goto(&if_done);
  }

  BIND(&if_codeistwobyte);
  {
    // Allocate a new SeqTwoByteString for {code}.
    TNode<String> result = AllocateSeqTwoByteString(1);
    StoreNoWriteBarrier(
        MachineRepresentation::kWord16, result,
        IntPtrConstant(OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag),
        code);
    var_result = result;
    Goto(&if_done);
  }

  BIND(&if_done);
  return var_result.value();
}

ToDirectStringAssembler::ToDirectStringAssembler(
    compiler::CodeAssemblerState* state, TNode<String> string, Flags flags)
    : CodeStubAssembler(state),
      var_string_(string, this),
#if V8_STATIC_ROOTS_BOOL
      var_map_(LoadMap(string), this),
#else
      var_instance_type_(LoadInstanceType(string), this),
#endif
      var_offset_(IntPtrConstant(0), this),
      var_is_external_(Int32Constant(0), this),
      flags_(flags) {
}

TNode<String> ToDirectStringAssembler::TryToDirect(Label* if_bailout) {
  Label dispatch(this, {&var_string_, &var_offset_,
#if V8_STATIC_ROOTS_BOOL
                        &var_map_
#else
                        &var_instance_type_
#endif
                       });
  Label if_iscons(this);
  Label if_isexternal(this);
  Label if_issliced(this);
  Label if_isthin(this);
  Label out(this);

#if V8_STATIC_ROOTS_BOOL
  // The seq string check is in the dispatch.
  Goto(&dispatch);
#else
  Branch(IsSequentialStringInstanceType(var_instance_type_.value()), &out,
         &dispatch);
#endif

  // Dispatch based on string representation.
  BIND(&dispatch);
  {
#if V8_STATIC_ROOTS_BOOL
    TNode<Int32T> map_bits =
        TruncateIntPtrToInt32(BitcastTaggedToWord(var_map_.value()));

    using StringTypeRange = InstanceTypeChecker::kUniqueMapRangeOfStringType;
    // Check the string map ranges in dense increasing order, to avoid needing
    // to subtract away the lower bound. Do these couple of range checks instead
    // of a switch, since we can make them all single dense compares.
    static_assert(StringTypeRange::kSeqString.first == 0);
    GotoIf(Uint32LessThanOrEqual(
               map_bits, Int32Constant(StringTypeRange::kSeqString.second)),
           &out);

    static_assert(StringTypeRange::kSeqString.second + Map::kSize ==
                  StringTypeRange::kExternalString.first);
    GotoIf(
        Uint32LessThanOrEqual(
            map_bits, Int32Constant(StringTypeRange::kExternalString.second)),
        &if_isexternal);

    static_assert(StringTypeRange::kExternalString.second + Map::kSize ==
                  StringTypeRange::kConsString.first);
    GotoIf(Uint32LessThanOrEqual(
               map_bits, Int32Constant(StringTypeRange::kConsString.second)),
           &if_iscons);

    static_assert(StringTypeRange::kConsString.second + Map::kSize ==
                  StringTypeRange::kSlicedString.first);
    GotoIf(Uint32LessThanOrEqual(
               map_bits, Int32Constant(StringTypeRange::kSlicedString.second)),
           &if_issliced);

    static_assert(StringTypeRange::kSlicedString.second + Map::kSize ==
                  StringTypeRange::kThinString.first);
    // No need to check for thin strings, they're the last string map.
    static_assert(StringTypeRange::kThinString.second ==
                  InstanceTypeChecker::kStringMapUpperBound);
    Goto(&if_isthin);
#else
    int32_t values[] = {
        kSeqStringTag,    kConsStringTag, kExternalStringTag,
        kSlicedStringTag, kThinStringTag,
    };
    Label* labels[] = {
        &out, &if_iscons, &if_isexternal, &if_issliced, &if_isthin,
    };
    static_assert(arraysize(values) == arraysize(labels));

    const TNode<Int32T> representation = Word32And(
        var_instance_type_.value(), Int32Constant(kStringRepresentationMask));
    Switch(representation, if_bailout, values, labels, arraysize(values));
#endif
  }

  // Cons string.  Check whether it is flat, then fetch first part.
  // Flat cons strings have an empty second part.
  BIND(&if_iscons);
  {
    const TNode<String> string = var_string_.value();
    GotoIfNot(IsEmptyString(LoadObjectField<String>(
                  string, offsetof(ConsString, second_))),
              if_bailout);

    const TNode<String> lhs =
        LoadObjectField<String>(string, offsetof(ConsString, first_));
    var_string_ = lhs;
#if V8_STATIC_ROOTS_BOOL
    var_map_ = LoadMap(lhs);
#else
    var_instance_type_ = LoadInstanceType(lhs);
#endif

    Goto(&dispatch);
  }

  // Sliced string. Fetch parent and correct start index by offset.
  BIND(&if_issliced);
  {
    if (!v8_flags.string_slices || (flags_ & kDontUnpackSlicedStrings)) {
      Goto(if_bailout);
    } else {
      const TNode<String> string = var_string_.value();
      const TNode<IntPtrT> sliced_offset = LoadAndUntagPositiveSmiObjectField(
          string, offsetof(SlicedString, offset_));
      var_offset_ = IntPtrAdd(var_offset_.value(), sliced_offset);

      const TNode<String> parent =
          LoadObjectField<String>(string, offsetof(SlicedString, parent_));
      var_string_ = parent;
#if V8_STATIC_ROOTS_BOOL
      var_map_ = LoadMap(parent);
#else
      var_instance_type_ = LoadInstanceType(parent);
#endif

      Goto(&dispatch);
    }
  }

  // Thin string. Fetch the actual string.
  BIND(&if_isthin);
  {
    const TNode<String> string = var_string_.value();
    const TNode<String> actual_string =
        LoadObjectField<String>(string, offsetof(ThinString, actual_));

    var_string_ = actual_string;
#if V8_STATIC_ROOTS_BOOL
    var_map_ = LoadMap(actual_string);
#else
    var_instance_type_ = LoadInstanceType(actual_string);
#endif

    Goto(&dispatch);
  }

  // External string.
  BIND(&if_isexternal);
  var_is_external_ = Int32Constant(1);
  Goto(&out);

  BIND(&out);
  return var_string_.value();
}

TNode<String> ToDirectStringAssembler::ToDirect() {
  Label flatten_in_runtime(this, Label::kDeferred),
      unreachable(this, Label::kDeferred), out(this);

  TryToDirect(&flatten_in_runtime);
  Goto(&out);

  BIND(&flatten_in_runtime);
  var_string_ = CAST(CallRuntime(Runtime::kFlattenString, NoContextConstant(),
                                 var_string_.value()));
#if V8_STATIC_ROOTS_BOOL
  var_map_ = LoadMap(var_string_.value());
#else
  var_instance_type_ = LoadInstanceType(var_string_.value());
#endif

  TryToDirect(&unreachable);
  Goto(&out);

  BIND(&unreachable);
  Unreachable();

  BIND(&out);
  return var_string_.value();
}

TNode<BoolT> ToDirectStringAssembler::IsOneByte() {
#if V8_STATIC_ROOTS_BOOL
  return IsOneByteStringMap(var_map_.value());
#else
  return IsOneByteStringInstanceType(var_instance_type_.value());
#endif
}

TNode<RawPtrT> ToDirectStringAssembler::TryToSequential(
    StringPointerKind ptr_kind, Label* if_bailout) {
  CHECK(ptr_kind == PTR_TO_DATA || ptr_kind == PTR_TO_STRING);

  TVARIABLE(RawPtrT, var_result);
  Label out(this), if_issequential(this), if_isexternal(this, Label::kDeferred);
  Branch(is_external(), &if_isexternal, &if_issequential);

  BIND(&if_issequential);
  {
    static_assert(OFFSET_OF_DATA_START(SeqOneByteString) ==
                  OFFSET_OF_DATA_START(SeqTwoByteString));
    TNode<RawPtrT> result =
        ReinterpretCast<RawPtrT>(BitcastTaggedToWord(var_string_.value()));
    if (ptr_kind == PTR_TO_DATA) {
      result = RawPtrAdd(result,
                         IntPtrConstant(OFFSET_OF_DATA_START(SeqOneByteString) -
                                        kHeapObjectTag));
    }
    var_result = result;
    Goto(&out);
  }

  BIND(&if_isexternal);
  {
#if V8_STATIC_ROOTS_BOOL
    GotoIf(IsUncachedExternalStringMap(var_map_.value()), if_bailout);
#else
    GotoIf(IsUncachedExternalStringInstanceType(var_instance_type_.value()),
           if_bailout);
#endif

    TNode<String> string = var_string_.value();
    TNode<RawPtrT> result = LoadExternalStringResourceDataPtr(CAST(string));
    if (ptr_kind == PTR_TO_STRING) {
      result = RawPtrSub(result,
                         IntPtrConstant(OFFSET_OF_DATA_START(SeqOneByteString) -
                                        kHeapObjectTag));
    }
    var_result = result;
    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::StringToNumber(TNode<String> input) {
  Label runtime(this, Label::kDeferred);
  Label end(this);

  TVARIABLE(Number, var_result);

  // Check if string has a cached array index.
  TNode<Uint32T> raw_hash_field = LoadNameRawHashField(input);
  GotoIf(IsSetWord32(raw_hash_field, Name::kDoesNotContainCachedArrayIndexMask),
         &runtime);

  var_result = SmiTag(Signed(
      DecodeWordFromWord32<String::ArrayIndexValueBits>(raw_hash_field)));
  Goto(&end);

  BIND(&runtime);
  {
    var_result =
        CAST(CallRuntime(Runtime::kStringToNumber, NoContextConstant(), input));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<String> CodeStubAssembler::NumberToString(TNode<Number> input,
                                                Label* bailout) {
  TVARIABLE(String, result);
  TVARIABLE(Smi, smi_input);
  Label if_smi(this), not_smi(this), if_heap_number(this), done(this, &result);

  // Load the number string cache.
  TNode<FixedArray> number_string_cache = NumberStringCacheConstant();

  // Make the hash mask from the length of the number string cache. It
  // contains two elements (number and string) for each cache entry.
  TNode<Uint32T> number_string_cache_length =
      LoadAndUntagFixedArrayBaseLengthAsUint32(number_string_cache);
  TNode<Int32T> one = Int32Constant(1);
  TNode<Word32T> mask =
      Int32Sub(Word32Shr(number_string_cache_length, one), one);

  GotoIfNot(TaggedIsSmi(input), &if_heap_number);
  smi_input = CAST(input);
  Goto(&if_smi);

  BIND(&if_heap_number);
  TNode<HeapNumber> heap_number_input = CAST(input);
  {
    Comment("NumberToString - HeapNumber");
    // Try normalizing the HeapNumber.
    smi_input = TryHeapNumberToSmi(heap_number_input, &not_smi);
    Goto(&if_smi);
  }
  BIND(&if_smi);
  {
    Comment("NumberToString - Smi");
    // Load the smi key, make sure it matches the smi we're looking for.
    TNode<Word32T> hash = Word32And(SmiToInt32(smi_input.value()), mask);
    TNode<IntPtrT> entry_index =
        Signed(ChangeUint32ToWord(Int32Add(hash, hash)));
    TNode<Object> smi_key =
        UnsafeLoadFixedArrayElement(number_string_cache, entry_index);
    Label if_smi_cache_missed(this);
    GotoIf(TaggedNotEqual(smi_key, smi_input.value()), &if_smi_cache_missed);

    // Smi match, return value from cache entry.
    result = CAST(UnsafeLoadFixedArrayElement(number_string_cache, entry_index,
                                              kTaggedSize));
    Goto(&done);

    BIND(&if_smi_cache_missed);
    {
      Label store_to_cache(this);

      // Bailout when the cache is not full-size.
      const int kFullCacheSize =
          isolate()->heap()->MaxNumberToStringCacheSize();
      Branch(Uint32LessThan(number_string_cache_length,
                            Uint32Constant(kFullCacheSize)),
             bailout, &store_to_cache);

      BIND(&store_to_cache);
      {
        // Generate string and update string hash field.
        result = IntToDecimalString(SmiToInt32(smi_input.value()));

        // Store string into cache.
        StoreFixedArrayElement(number_string_cache, entry_index,
                               smi_input.value());
        StoreFixedArrayElement(number_string_cache,
                               IntPtrAdd(entry_index, IntPtrConstant(1)),
                               result.value());
        Goto(&done);
      }
    }
  }

  BIND(&not_smi);
  {
    // Make a hash from the two 32-bit values of the double.
    TNode<Int32T> low = LoadObjectField<Int32T>(heap_number_input,
                                                offsetof(HeapNumber, value_));
    TNode<Int32T> high = LoadObjectField<Int32T>(
        heap_number_input, offsetof(HeapNumber, value_) + kIntSize);
    TNode<Word32T> hash = Word32And(Word32Xor(low, high), mask);
    TNode<IntPtrT> entry_index =
        Signed(ChangeUint32ToWord(Int32Add(hash, hash)));

    // Cache entry's key must be a heap number
    TNode<Object> number_key =
        UnsafeLoadFixedArrayElement(number_string_cache, entry_index);
    GotoIf(TaggedIsSmi(number_key), bailout);
    TNode<HeapObject> number_key_heap_object = CAST(number_key);
    GotoIfNot(IsHeapNumber(number_key_heap_object), bailout);

    // Cache entry's key must match the heap number value we're looking for.
    TNode<Int32T> low_compare = LoadObjectField<Int32T>(
        number_key_heap_object, offsetof(HeapNumber, value_));
    TNode<Int32T> high_compare = LoadObjectField<Int32T>(
        number_key_heap_object, offsetof(HeapNumber, value_) + kIntSize);
    GotoIfNot(Word32Equal(low, low_compare), bailout);
    GotoIfNot(Word32Equal(high, high_compare), bailout);

    // Heap number match, return value from cache entry.
    result = CAST(UnsafeLoadFixedArrayElement(number_string_cache, entry_index,
                                              kTaggedSize));
    Goto(&done);
  }
  BIND(&done);
  return result.value();
}

TNode<String> CodeStubAssembler::NumberToString(TNode<Number> input) {
  TVARIABLE(String, result);
  Label runtime(this, Label::kDeferred), done(this, &result);

  GotoIfForceSlowPath(&runtime);

  result = NumberToString(input, &runtime);
  Goto(&done);

  BIND(&runtime);
  {
    // No cache entry, go to the runtime.
    result = CAST(
        CallRuntime(Runtime::kNumberToStringSlow, NoContextConstant(), input));
    Goto(&done);
  }
  BIND(&done);
  return result.value();
}

TNode<Numeric> CodeStubAssembler::NonNumberToNumberOrNumeric(
    TNode<Context> context, TNode<HeapObject> input, Object::Conversion mode,
    BigIntHandling bigint_handling) {
  CSA_DCHECK(this, Word32BinaryNot(IsHeapNumber(input)));

  TVARIABLE(HeapObject, var_input, input);
  TVARIABLE(Numeric, var_result);
  TVARIABLE(Uint16T, instance_type, LoadInstanceType(var_input.value()));
  Label end(this), if_inputisreceiver(this, Label::kDeferred),
      if_inputisnotreceiver(this);

  // We need to handle JSReceiver first since we might need to do two
  // conversions due to ToPritmive.
  Branch(IsJSReceiverInstanceType(instance_type.value()), &if_inputisreceiver,
         &if_inputisnotreceiver);

  BIND(&if_inputisreceiver);
  {
    // The {var_input.value()} is a JSReceiver, we need to convert it to a
    // Primitive first using the ToPrimitive type conversion, preferably
    // yielding a Number.
    Builtin builtin =
        Builtins::NonPrimitiveToPrimitive(ToPrimitiveHint::kNumber);
    TNode<Object> result = CallBuiltin(builtin, context, var_input.value());

    // Check if the {result} is already a Number/Numeric.
    Label if_done(this), if_notdone(this);
    Branch(mode == Object::Conversion::kToNumber ? IsNumber(result)
                                                 : IsNumeric(result),
           &if_done, &if_notdone);

    BIND(&if_done);
    {
      // The ToPrimitive conversion already gave us a Number/Numeric, so
      // we're done.
      var_result = CAST(result);
      Goto(&end);
    }

    BIND(&if_notdone);
    {
      // We now have a Primitive {result}, but it's not yet a
      // Number/Numeric.
      var_input = CAST(result);
      // We have a new input. Redo the check and reload instance_type.
      CSA_DCHECK(this, Word32BinaryNot(IsHeapNumber(var_input.value())));
      instance_type = LoadInstanceType(var_input.value());
      Goto(&if_inputisnotreceiver);
    }
  }

  BIND(&if_inputisnotreceiver);
  {
    Label not_plain_primitive(this), if_inputisbigint(this),
        if_inputisother(this, Label::kDeferred);

    // String and Oddball cases.
    TVARIABLE(Number, var_result_number);
    TryPlainPrimitiveNonNumberToNumber(var_input.value(), &var_result_number,
                                       &not_plain_primitive);
    var_result = var_result_number.value();
    Goto(&end);

    BIND(&not_plain_primitive);
    {
      Branch(IsBigIntInstanceType(instance_type.value()), &if_inputisbigint,
             &if_inputisother);

      BIND(&if_inputisbigint);
      {
        if (mode == Object::Conversion::kToNumeric) {
          var_result = CAST(var_input.value());
          Goto(&end);
        } else {
          DCHECK_EQ(mode, Object::Conversion::kToNumber);
          if (bigint_handling == BigIntHandling::kThrow) {
            Goto(&if_inputisother);
          } else {
            DCHECK_EQ(bigint_handling, BigIntHandling::kConvertToNumber);
            var_result = CAST(CallRuntime(Runtime::kBigIntToNumber, context,
                                          var_input.value()));
            Goto(&end);
          }
        }
      }

      BIND(&if_inputisother);
      {
        // The {var_input.value()} is something else (e.g. Symbol), let the
        // runtime figure out the correct exception. Note: We cannot tail call
        // to the runtime here, as js-to-wasm trampolines also use this code
        // currently, and they declare all outgoing parameters as untagged,
        // while we would push a tagged object here.
        auto function_id = mode == Object::Conversion::kToNumber
                               ? Runtime::kToNumber
                               : Runtime::kToNumeric;
        var_result = CAST(CallRuntime(function_id, context, var_input.value()));
        Goto(&end);
      }
    }
  }

  BIND(&end);
  if (mode == Object::Conversion::kToNumber) {
    CSA_DCHECK(this, IsNumber(var_result.value()));
  }
  return var_result.value();
}

TNode<Number> CodeStubAssembler::NonNumberToNumber(
    TNode<Context> context, TNode<HeapObject> input,
    BigIntHandling bigint_handling) {
  return CAST(NonNumberToNumberOrNumeric(
      context, input, Object::Conversion::kToNumber, bigint_handling));
}

void CodeStubAssembler::TryPlainPrimitiveNonNumberToNumber(
    TNode<HeapObject> input, TVariable<Number>* var_result, Label* if_bailout) {
  CSA_DCHECK(this, Word32BinaryNot(IsHeapNumber(input)));
  Label done(this);

  // Dispatch on the {input} instance type.
  TNode<Uint16T> input_instance_type = LoadInstanceType(input);
  Label if_inputisstring(this);
  GotoIf(IsStringInstanceType(input_instance_type), &if_inputisstring);
  GotoIfNot(InstanceTypeEqual(input_instance_type, ODDBALL_TYPE), if_bailout);

  // The {input} is an Oddball, we just need to load the Number value of it.
  *var_result = LoadObjectField<Number>(input, offsetof(Oddball, to_number_));
  Goto(&done);

  BIND(&if_inputisstring);
  {
    // The {input} is a String, use the fast stub to convert it to a Number.
    *var_result = StringToNumber(CAST(input));
    Goto(&done);
  }

  BIND(&done);
}

TNode<Numeric> CodeStubAssembler::NonNumberToNumeric(TNode<Context> context,
                                                     TNode<HeapObject> input) {
  return NonNumberToNumberOrNumeric(context, input,
                                    Object::Conversion::kToNumeric);
}

TNode<Number> CodeStubAssembler::ToNumber(TNode<Context> context,
                                          TNode<Object> input,
                                          BigIntHandling bigint_handling) {
  return CAST(ToNumberOrNumeric([context] { return context; }, input, nullptr,
                                Object::Conversion::kToNumber,
                                bigint_handling));
}

TNode<Number> CodeStubAssembler::ToNumber_Inline(TNode<Context> context,
                                                 TNode<Object> input) {
  TVARIABLE(Number, var_result);
  Label end(this), not_smi(this, Label::kDeferred);

  GotoIfNot(TaggedIsSmi(input), &not_smi);
  var_result = CAST(input);
  Goto(&end);

  BIND(&not_smi);
  {
    var_result = Select<Number>(
        IsHeapNumber(CAST(input)), [=, this] { return CAST(input); },
        [=, this] {
          return CAST(CallBuiltin(Builtin::kNonNumberToNumber, context, input));
        });
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

TNode<Numeric> CodeStubAssembler::ToNumberOrNumeric(
    LazyNode<Context> context, TNode<Object> input,
    TVariable<Smi>* var_type_feedback, Object::Conversion mode,
    BigIntHandling bigint_handling) {
  TVARIABLE(Numeric, var_result);
  Label end(this);

  Label not_smi(this, Label::kDeferred);
  GotoIfNot(TaggedIsSmi(input), &not_smi);
  TNode<Smi> input_smi = CAST(input);
  var_result = input_smi;
  if (var_type_feedback) {
    *var_type_feedback = SmiConstant(BinaryOperationFeedback::kSignedSmall);
  }
  Goto(&end);

  BIND(&not_smi);
  {
    Label not_heap_number(this, Label::kDeferred);
    TNode<HeapObject> input_ho = CAST(input);
    GotoIfNot(IsHeapNumber(input_ho), &not_heap_number);

    TNode<HeapNumber> input_hn = CAST(input_ho);
    var_result = input_hn;
    if (var_type_feedback) {
      *var_type_feedback = SmiConstant(BinaryOperationFeedback::kNumber);
    }
    Goto(&end);

    BIND(&not_heap_number);
    {
      if (mode == Object::Conversion::kToNumeric) {
        // Special case for collecting BigInt feedback.
        Label not_bigint(this);
        GotoIfNot(IsBigInt(input_ho), &not_bigint);
        {
          var_result = CAST(input_ho);
          *var_type_feedback = SmiConstant(BinaryOperationFeedback::kBigInt);
          Goto(&end);
        }
        BIND(&not_bigint);
      }
      var_result = NonNumberToNumberOrNumeric(context(), input_ho, mode,
                                              bigint_handling);
      if (var_type_feedback) {
        *var_type_feedback = SmiConstant(BinaryOperationFeedback::kAny);
      }
      Goto(&end);
    }
  }

  BIND(&end);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::PlainPrimitiveToNumber(TNode<Object> input) {
  TVARIABLE(Number, var_result);
  Label end(this), fallback(this);

  Label not_smi(this, Label::kDeferred);
  GotoIfNot(TaggedIsSmi(input), &not_smi);
  TNode<Smi> input_smi = CAST(input);
  var_result = input_smi;
  Goto(&end);

  BIND(&not_smi);
  {
    Label not_heap_number(this, Label::kDeferred);
    TNode<HeapObject> input_ho = CAST(input);
    GotoIfNot(IsHeapNumber(input_ho), &not_heap_number);

    TNode<HeapNumber> input_hn = CAST(input_ho);
    var_result = input_hn;
    Goto(&end);

    BIND(&not_heap_number);
    {
      TryPlainPrimitiveNonNumberToNumber(input_ho, &var_result, &fallback);
      Goto(&end);
      BIND(&fallback);
      Unreachable();
    }
  }

  BIND(&end);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::ToBigInt(TNode<Context> context,
                                          TNode<Object> input) {
  TVARIABLE(BigInt, var_result);
  Label if_bigint(this), done(this), if_throw(this);

  GotoIf(TaggedIsSmi(input), &if_throw);
  GotoIf(IsBigInt(CAST(input)), &if_bigint);
  var_result = CAST(CallRuntime(Runtime::kToBigInt, context, input));
  Goto(&done);

  BIND(&if_bigint);
  var_result = CAST(input);
  Goto(&done);

  BIND(&if_throw);
  ThrowTypeError(context, MessageTemplate::kBigIntFromObject, input);

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::ToBigIntConvertNumber(TNode<Context> context,
                                                       TNode<Object> input) {
  TVARIABLE(BigInt, var_result);
  Label if_bigint(this), if_not_bigint(this), done(this);

  GotoIf(TaggedIsSmi(input), &if_not_bigint);
  GotoIf(IsBigInt(CAST(input)), &if_bigint);
  Goto(&if_not_bigint);

  BIND(&if_bigint);
  var_result = CAST(input);
  Goto(&done);

  BIND(&if_not_bigint);
  var_result =
      CAST(CallRuntime(Runtime::kToBigIntConvertNumber, context, input));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

void CodeStubAssembler::TaggedToBigInt(TNode<Context> context,
                                       TNode<Object> value,
                                       Label* if_not_bigint, Label* if_bigint,
                                       Label* if_bigint64,
                                       TVariable<BigInt>* var_bigint,
                                       TVariable<Smi>* var_feedback) {
  Label done(this), is_smi(this), is_heapnumber(this), maybe_bigint64(this),
      is_bigint(this), is_oddball(this);
  GotoIf(TaggedIsSmi(value), &is_smi);
  TNode<HeapObject> heap_object_value = CAST(value);
  TNode<Map> map = LoadMap(heap_object_value);
  GotoIf(IsHeapNumberMap(map), &is_heapnumber);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  if (Is64() && if_bigint64) {
    GotoIf(IsBigIntInstanceType(instance_type), &maybe_bigint64);
  } else {
    GotoIf(IsBigIntInstanceType(instance_type), &is_bigint);
  }

  // {heap_object_value} is not a Numeric yet.
  GotoIf(Word32Equal(instance_type, Int32Constant(ODDBALL_TYPE)), &is_oddball);
  TNode<Numeric> numeric_value = CAST(
      CallBuiltin(Builtin::kNonNumberToNumeric, context, heap_object_value));
  OverwriteFeedback(var_feedback, BinaryOperationFeedback::kAny);
  GotoIf(TaggedIsSmi(numeric_value), if_not_bigint);
  GotoIfNot(IsBigInt(CAST(numeric_value)), if_not_bigint);
  *var_bigint = CAST(numeric_value);
  Goto(if_bigint);

  BIND(&is_smi);
  OverwriteFeedback(var_feedback, BinaryOperationFeedback::kSignedSmall);
  Goto(if_not_bigint);

  BIND(&is_heapnumber);
  OverwriteFeedback(var_feedback, BinaryOperationFeedback::kNumber);
  Goto(if_not_bigint);

  if (Is64() && if_bigint64) {
    BIND(&maybe_bigint64);
    GotoIfLargeBigInt(CAST(value), &is_bigint);
    *var_bigint = CAST(value);
    OverwriteFeedback(var_feedback, BinaryOperationFeedback::kBigInt64);
    Goto(if_bigint64);
  }

  BIND(&is_bigint);
  *var_bigint = CAST(value);
  OverwriteFeedback(var_feedback, BinaryOperationFeedback::kBigInt);
  Goto(if_bigint);

  BIND(&is_oddball);
  OverwriteFeedback(var_feedback, BinaryOperationFeedback::kNumberOrOddball);
  Goto(if_not_bigint);
}

// ES#sec-touint32
TNode<Number> CodeStubAssembler::ToUint32(TNode<Context> context,
                                          TNode<Object> input) {
  const TNode<Float64T> float_zero = Float64Constant(0.0);
  const TNode<Float64T> float_two_32 =
      Float64Constant(static_cast<double>(1ULL << 32));

  Label out(this);

  TVARIABLE(Object, var_result, input);

  // Early exit for positive smis.
  {
    // TODO(jgruber): This branch and the recheck below can be removed once we
    // have a ToNumber with multiple exits.
    Label next(this, Label::kDeferred);
    Branch(TaggedIsPositiveSmi(input), &out, &next);
    BIND(&next);
  }

  const TNode<Number> number = ToNumber(context, input);
  var_result = number;

  // Perhaps we have a positive smi now.
  {
    Label next(this, Label::kDeferred);
    Branch(TaggedIsPositiveSmi(number), &out, &next);
    BIND(&next);
  }

  Label if_isnegativesmi(this), if_isheapnumber(this);
  Branch(TaggedIsSmi(number), &if_isnegativesmi, &if_isheapnumber);

  BIND(&if_isnegativesmi);
  {
    const TNode<Int32T> uint32_value = SmiToInt32(CAST(number));
    TNode<Float64T> float64_value = ChangeUint32ToFloat64(uint32_value);
    var_result = AllocateHeapNumberWithValue(float64_value);
    Goto(&out);
  }

  BIND(&if_isheapnumber);
  {
    Label return_zero(this);
    const TNode<Float64T> value = LoadHeapNumberValue(CAST(number));

    {
      // +-0.
      Label next(this);
      Branch(Float64Equal(value, float_zero), &return_zero, &next);
      BIND(&next);
    }

    {
      // NaN.
      Label next(this);
      Branch(Float64Equal(value, value), &next, &return_zero);
      BIND(&next);
    }

    {
      // +Infinity.
      Label next(this);
      const TNode<Float64T> positive_infinity =
          Float64Constant(std::numeric_limits<double>::infinity());
      Branch(Float64Equal(value, positive_infinity), &return_zero, &next);
      BIND(&next);
    }

    {
      // -Infinity.
      Label next(this);
      const TNode<Float64T> negative_infinity =
          Float64Constant(-1.0 * std::numeric_limits<double>::infinity());
      Branch(Float64Equal(value, negative_infinity), &return_zero, &next);
      BIND(&next);
    }

    // * Let int be the mathematical value that is the same sign as number and
    //   whose magnitude is floor(abs(number)).
    // * Let int32bit be int modulo 2^32.
    // * Return int32bit.
    {
      TNode<Float64T> x = Float64Trunc(value);
      x = Float64Mod(x, float_two_32);
      x = Float64Add(x, float_two_32);
      x = Float64Mod(x, float_two_32);

      const TNode<Number> result = ChangeFloat64ToTagged(x);
      var_result = result;
      Goto(&out);
    }

    BIND(&return_zero);
    {
      var_result = SmiConstant(0);
      Goto(&out);
    }
  }

  BIND(&out);
  return CAST(var_result.value());
}

TNode<String> CodeStubAssembler::ToString_Inline(TNode<Context> context,
                                                 TNode<Object> input) {
  TVARIABLE(Object, var_result, input);
  Label stub_call(this, Label::kDeferred), out(this);

  GotoIf(TaggedIsSmi(input), &stub_call);
  Branch(IsString(CAST(input)), &out, &stub_call);

  BIND(&stub_call);
  var_result = CallBuiltin(Builtin::kToString, context, input);
  Goto(&out);

  BIND(&out);
  return CAST(var_result.value());
}

TNode<JSReceiver> CodeStubAssembler::ToObject(TNode<Context> context,
```