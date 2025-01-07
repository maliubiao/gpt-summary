Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request went like this:

1. **Understand the Context:** The prompt states this is part of `v8/src/codegen/code-stub-assembler.cc`. This immediately tells me we're dealing with low-level code generation within the V8 JavaScript engine. The "CodeStubAssembler" part strongly suggests this code is about creating snippets of machine code dynamically.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code, looking for recognizable patterns and keywords. Things that jumped out:
    * `TNode`: This is a key type in the CodeStubAssembler, representing nodes in an abstract syntax tree (or a similar intermediate representation) used during code generation.
    * `Builtin::k...`, `Builtins::...`:  These clearly indicate calls to built-in JavaScript functions or internal V8 routines.
    * `CallBuiltin`, `CallCFunction`:  These confirm we're generating code that interacts with existing V8 functionality and potentially external C++ functions.
    * `Label`, `Goto`, `BranchIf`:  These are control flow constructs used in the assembler.
    * `Load...`, `Store...`: These indicate memory access operations.
    * `IntPtrT`, `Word32T`, `Uint32T`: These are low-level data types (pointers and integers).
    * `StatsCounter`: This suggests performance monitoring and statistics.
    * `TryToName`, `TryInternalizeString`: These functions appear to deal with string interning and potentially converting strings to indices.
    * `Dictionary`, `DescriptorArray`, `HashTable`: These point to V8's internal data structures for object properties and lookups.
    * `Template`:  This indicates generic programming, where the same code can work with different types.

3. **Categorize Functionality:**  Based on the keywords and patterns, I started grouping the functions by their apparent purpose:
    * **Type Conversion:**  Functions like `ToObject`, `ToObject_Inline`, `ToLength_Inline`, `OrdinaryToPrimitive`.
    * **Bit Manipulation:**  Functions like `DecodeWord32`, `DecodeWord`, `UpdateWord32`, `UpdateWord`.
    * **Performance Counters:**  `SetCounter`, `IncrementCounter`, `DecrementCounter`.
    * **Control Flow/Utility:** `Use`, `Increment` (for variables).
    * **String Handling/Interning:** `TryToName`, `StringWriteToFlatOneByte`, `StringWriteToFlatTwoByte`, `ExternalOneByteStringGetChars`, `ExternalTwoByteStringGetChars`, `TryInternalizeString`.
    * **Dictionary/Property Access:** `EntryToIndex`, `LoadDescriptorArrayElement`, `LoadKeyByKeyIndex`, `LoadDetailsByKeyIndex`, `LoadValueByKeyIndex`, `StoreDetailsByKeyIndex`, `StoreValueByKeyIndex`, `DescriptorEntryToIndex`, `LoadKeyByDescriptorEntry`, `LoadDetailsByDescriptorEntry`, `LoadValueByDescriptorEntry`, `NameDictionaryLookup`, `NameToIndexHashTableLookup`.
    * **Hash Table Utilities:** `HashTableComputeCapacity`, `IntPtrMax`, `IntPtrMin`, `UintPtrMin`.

4. **Infer High-Level Functionality:** By looking at the categorized functions, I could infer the high-level goal of this code: It provides a set of building blocks for generating efficient machine code for common JavaScript operations. It handles type conversions, property access, string manipulation, and performance monitoring at a very low level.

5. **Address Specific Requirements:** I then went through the specific requests in the prompt:

    * **List Functionality:** This was largely covered by the categorization step. I aimed for concise descriptions of what each function or group of functions does.
    * **Torque Source:** I checked for the `.tq` extension. Since it's `.cc`, it's C++, not Torque.
    * **Relationship to JavaScript (with examples):**  This required connecting the low-level functions to higher-level JavaScript concepts. For example, `ToObject` is directly related to the JavaScript `ToObject()` abstract operation. I chose simple, illustrative JavaScript examples.
    * **Code Logic Reasoning (with input/output):** I picked a couple of functions with clear logic, like `DecodeWord32` and `UpdateWord32`, and provided simple integer inputs and expected outputs to demonstrate their bit manipulation.
    * **Common Programming Errors:**  I thought about how the low-level nature of this code could lead to errors if used incorrectly. Type mismatches, incorrect assumptions about data layout, and issues with write barriers came to mind.
    * **Part 12 of 23 Summary:**  Given that this section focuses on core utilities for code generation, I summarized its role as providing essential tools for implementing various JavaScript features efficiently. I also noted the focus on type conversion, object property access, and string handling.

6. **Refine and Organize:**  Finally, I reviewed and organized my thoughts, ensuring the language was clear, concise, and accurate. I aimed for a structured output that addressed all parts of the prompt effectively. I used headings and bullet points to improve readability.

Essentially, my process involved moving from the concrete (the code itself) to the abstract (the high-level functionality), then back to the concrete (specific examples and error scenarios) to illustrate the concepts. The key was understanding the context of the code within the V8 engine.
这是一个 V8 引擎源代码文件 `v8/src/codegen/code-stub-assembler.cc` 的代码片段。`CodeStubAssembler` 是 V8 中用于生成机器码的一种抽象层，它允许开发者以一种更高级的方式编写代码，而无需直接操作机器指令。

**功能列表:**

这个代码片段主要提供了一系列用于在 `CodeStubAssembler` 中进行常见操作的工具函数，可以大致归纳为以下几类：

1. **类型转换和检查:**
   - `ToObject`: 将一个值转换为对象。如果输入已经是 JSReceiver (对象或函数)，则直接返回；否则，根据 ECMAScript 规范执行转换（例如，将原始值转换为其对应的包装对象）。
   - `ToObject_Inline`:  `ToObject` 的内联版本，先检查输入是否已经是 JSReceiver，避免不必要的函数调用。
   - `ToLength_Inline`: 将一个值转换为适合用作数组长度的整数。
   - `OrdinaryToPrimitive`: 执行标准的 `ToPrimitive` 抽象操作。

2. **位操作:**
   - `DecodeWord32`, `DecodeWord`: 从一个 Word32 或 Word (机器字) 中解码指定位范围的值。
   - `UpdateWord32`, `UpdateWord`: 更新一个 Word32 或 Word 中指定位范围的值。

3. **性能计数器:**
   - `SetCounter`, `IncrementCounter`, `DecrementCounter`: 用于在生成的代码中操作性能计数器，以便进行性能分析。

4. **控制流和变量操作:**
   - `Increment`:  原子地增加一个变量的值。
   - `Use`:  强制使用一个标签，即使没有直接的跳转到该标签。

5. **名称查找和字符串处理:**
   - `TryToName`: 尝试将一个对象键转换为 `Name` 类型 (字符串或 Symbol)。它会尝试将键转换为数字索引，或者检查是否是唯一的字符串（已内部化）。
   - `StringWriteToFlatOneByte`, `StringWriteToFlatTwoByte`: 将字符串内容写入到一块连续的内存区域。
   - `ExternalOneByteStringGetChars`, `ExternalTwoByteStringGetChars`: 获取外部字符串的字符指针。
   - `IntlAsciiCollationWeightsL1`, `IntlAsciiCollationWeightsL3`: 获取用于国际化排序的 ASCII 权重。
   - `TryInternalizeString`: 尝试将字符串内部化，如果成功则返回内部化的字符串或其索引。

6. **字典和属性访问:**
   - `EntryToIndex`: 计算字典中某个条目的索引。
   - `LoadDescriptorArrayElement`, `LoadKeyByKeyIndex`, `LoadDetailsByKeyIndex`, `LoadValueByKeyIndex`, `LoadFieldTypeByKeyIndex`: 从 `DescriptorArray` 中加载键、详细信息、值和字段类型。
   - `DescriptorEntryToIndex`, `LoadKeyByDescriptorEntry`, `LoadDetailsByDescriptorEntry`, `LoadValueByDescriptorEntry`, `LoadFieldTypeByDescriptorEntry`: 通过描述符条目索引从 `DescriptorArray` 中加载信息。
   - `LoadValueByKeyIndex` (针对不同字典类型): 从 `NameDictionary` 和 `SwissNameDictionary` 中加载值。
   - `LoadDetailsByKeyIndex` (针对不同字典类型): 从 `NameDictionary` 和 `SwissNameDictionary` 中加载详细信息。
   - `StoreDetailsByKeyIndex` (针对不同字典类型): 向 `NameDictionary` 和 `SwissNameDictionary` 存储详细信息。
   - `StoreValueByKeyIndex` (针对不同字典类型): 向 `NameDictionary` 和 `SwissNameDictionary` 存储值。
   - `NameDictionaryLookup`: 在 `NameDictionary` 中查找键。
   - `NameToIndexHashTableLookup`: 在 `NameToIndexHashTable` 中查找名称对应的索引。

7. **哈希表工具:**
   - `HashTableComputeCapacity`: 计算哈希表的容量。
   - `IntPtrMax`, `IntPtrMin`, `UintPtrMin`: 返回两个 `IntPtrT` 或 `UintPtrT` 中的最大值或最小值。

8. **加载名称:**
   - `LoadName` (针对不同字典类型): 从不同类型的字典中加载名称。

**关于 `.tq` 扩展名:**

正如代码注释中提到的，如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 中用于定义运行时内置函数和编译器辅助函数的一种领域特定语言。由于该文件以 `.cc` 结尾，所以它是 C++ 代码。

**与 JavaScript 的关系及示例:**

`CodeStubAssembler` 生成的代码最终会执行 JavaScript 代码。这里列举一些函数与 JavaScript 功能的关系：

* **`ToObject(context, input)`:**  对应 JavaScript 中的 `Object(input)`。
   ```javascript
   console.log(Object(1)); // 输出: [Number: 1]
   console.log(Object("hello")); // 输出: [String: hello]
   console.log(Object({})); // 输出: {}
   ```

* **`ToLength_Inline(context, input)`:** 对应 JavaScript 中访问数组 `length` 属性时的内部转换。
   ```javascript
   function testLength(len) {
       const arr = new Array(len);
       return arr.length;
   }
   console.log(testLength(5)); // 输出: 5
   console.log(testLength(3.7)); // 内部会转换为 3
   console.log(testLength(-1)); // 内部会转换为 0
   console.log(testLength(Infinity)); // 内部会转换为 Number.MAX_SAFE_INTEGER
   ```

* **`OrdinaryToPrimitive(context, input, hint)`:** 对应 JavaScript 中的类型转换，例如在 `+` 运算符中。
   ```javascript
   console.log(1 + {}); // 输出: "1[object Object]" (hint 为 "default")
   console.log({ valueOf: () => 3 } + 2); // 输出: 5 (hint 为 "number")
   console.log({ toString: () => "hello" } + ""); // 输出: "hello" (hint 为 "string")
   ```

* **字典和属性访问函数:** 这些函数与 JavaScript 中对象属性的查找和访问密切相关。例如，当你执行 `object.property` 或 `object['property']` 时，V8 内部会使用类似的机制来查找属性。

**代码逻辑推理 (假设输入与输出):**

* **`DecodeWord32(word32, shift, mask)`:**
   假设 `word32` 的二进制表示为 `0b11010110`，`shift` 为 2，`mask` 为 `0b00001100`。
   1. 右移 `word32` 两位：`0b00110101`
   2. 与 `mask >> shift` (即 `0b00000011`) 进行与操作： `0b00000001`
   输出将是十进制的 `1`。

* **`UpdateWord32(word, value, shift, mask, starts_as_zero)`:**
   假设 `word` 的二进制表示为 `0b11110000`，`value` 为十进制的 `3` (二进制 `0b11`)，`shift` 为 2，`mask` 为 `0b00001100`，`starts_as_zero` 为 `false`。
   1. 将 `value` 左移 `shift` 位： `0b00001100`
   2. 将 `mask` 取反： `0b11110011`
   3. 将 `word` 与取反后的 `mask` 进行与操作： `0b11110000 & 0b11110011 = 0b11110000`
   4. 将步骤 1 和步骤 3 的结果进行或操作： `0b00001100 | 0b11110000 = 0b11111100`
   输出将是二进制的 `0b11111100`。

**用户常见的编程错误:**

虽然这些是 V8 内部的代码，但理解其背后的概念可以帮助避免 JavaScript 编程中的一些常见错误：

* **类型转换错误:**  不理解 JavaScript 的隐式类型转换规则可能导致意外的结果。例如，尝试对一个非对象的值访问属性会报错，因为内部的 `ToObject` 操作无法将其转换为对象。
   ```javascript
   let num = 5;
   console.log(num.toString()); // 可以正常工作，因为 JavaScript 会自动将 num 转换为 Number 对象

   let nothing = null;
   // console.log(nothing.toString()); // TypeError: Cannot read properties of null (reading 'toString')
   // 内部的 ToObject(null) 会抛出错误
   ```

* **数组长度的误用:**  不理解 `ToLength` 的转换规则可能导致创建意外大小的数组。
   ```javascript
   const arr1 = new Array(3.7); // 相当于 new Array(3)
   console.log(arr1.length); // 输出: 3

   const arr2 = new Array(-1); // 报错: Invalid array length
   ```

* **对象键的类型错误:**  在访问对象属性时，如果使用了非字符串或 Symbol 的键，可能会导致意外的行为或错误，因为内部的键查找机制依赖于这些类型。
   ```javascript
   const obj = {};
   const key = { key: 'value' };
   obj[key] = 123;
   console.log(obj["[object Object]"]); // 输出: 123，因为对象键会被转换为字符串 "[object Object]"
   ```

**功能归纳 (第 12 部分，共 23 部分):**

作为第 12 部分，这个代码片段很可能集中在提供 `CodeStubAssembler` 中用于**基本类型转换、位操作、性能监控、字符串处理以及对象属性访问**的核心工具函数。这些是构建更复杂代码片段的基础，用于实现各种 JavaScript 语言特性和内置功能。可以推测，后续的部分可能会涉及更高级的操作，例如函数调用、控制流、对象创建等等。  这部分的主要目标是提供构建 blocks，以便在后续阶段能够高效地生成针对特定 JavaScript 操作的机器码。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共23部分，请归纳一下它的功能

"""
                        TNode<Object> input) {
  return CAST(CallBuiltin(Builtin::kToObject, context, input));
}

TNode<JSReceiver> CodeStubAssembler::ToObject_Inline(TNode<Context> context,
                                                     TNode<Object> input) {
  TVARIABLE(JSReceiver, result);
  Label if_isreceiver(this), if_isnotreceiver(this, Label::kDeferred);
  Label done(this);

  BranchIfJSReceiver(input, &if_isreceiver, &if_isnotreceiver);

  BIND(&if_isreceiver);
  {
    result = CAST(input);
    Goto(&done);
  }

  BIND(&if_isnotreceiver);
  {
    result = ToObject(context, input);
    Goto(&done);
  }

  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::ToLength_Inline(TNode<Context> context,
                                                 TNode<Object> input) {
  TNode<Smi> smi_zero = SmiConstant(0);
  return Select<Number>(
      TaggedIsSmi(input), [=, this] { return SmiMax(CAST(input), smi_zero); },
      [=, this] {
        return CAST(CallBuiltin(Builtin::kToLength, context, input));
      });
}

TNode<Object> CodeStubAssembler::OrdinaryToPrimitive(
    TNode<Context> context, TNode<Object> input, OrdinaryToPrimitiveHint hint) {
  return CallBuiltin(Builtins::OrdinaryToPrimitive(hint), context, input);
}

TNode<Uint32T> CodeStubAssembler::DecodeWord32(TNode<Word32T> word32,
                                               uint32_t shift, uint32_t mask) {
  DCHECK_EQ((mask >> shift) << shift, mask);
  if ((std::numeric_limits<uint32_t>::max() >> shift) ==
      ((std::numeric_limits<uint32_t>::max() & mask) >> shift)) {
    return Unsigned(Word32Shr(word32, static_cast<int>(shift)));
  } else {
    return Unsigned(Word32And(Word32Shr(word32, static_cast<int>(shift)),
                              Int32Constant(mask >> shift)));
  }
}

TNode<UintPtrT> CodeStubAssembler::DecodeWord(TNode<WordT> word, uint32_t shift,
                                              uintptr_t mask) {
  DCHECK_EQ((mask >> shift) << shift, mask);
  if ((std::numeric_limits<uintptr_t>::max() >> shift) ==
      ((std::numeric_limits<uintptr_t>::max() & mask) >> shift)) {
    return Unsigned(WordShr(word, static_cast<int>(shift)));
  } else {
    return Unsigned(WordAnd(WordShr(word, static_cast<int>(shift)),
                            IntPtrConstant(mask >> shift)));
  }
}

TNode<Word32T> CodeStubAssembler::UpdateWord32(TNode<Word32T> word,
                                               TNode<Uint32T> value,
                                               uint32_t shift, uint32_t mask,
                                               bool starts_as_zero) {
  DCHECK_EQ((mask >> shift) << shift, mask);
  // Ensure the {value} fits fully in the mask.
  CSA_DCHECK(this, Uint32LessThanOrEqual(value, Uint32Constant(mask >> shift)));
  TNode<Word32T> encoded_value = Word32Shl(value, Int32Constant(shift));
  TNode<Word32T> masked_word;
  if (starts_as_zero) {
    CSA_DCHECK(this, Word32Equal(Word32And(word, Int32Constant(~mask)), word));
    masked_word = word;
  } else {
    masked_word = Word32And(word, Int32Constant(~mask));
  }
  return Word32Or(masked_word, encoded_value);
}

TNode<WordT> CodeStubAssembler::UpdateWord(TNode<WordT> word,
                                           TNode<UintPtrT> value,
                                           uint32_t shift, uintptr_t mask,
                                           bool starts_as_zero) {
  DCHECK_EQ((mask >> shift) << shift, mask);
  // Ensure the {value} fits fully in the mask.
  CSA_DCHECK(this,
             UintPtrLessThanOrEqual(value, UintPtrConstant(mask >> shift)));
  TNode<WordT> encoded_value = WordShl(value, static_cast<int>(shift));
  TNode<WordT> masked_word;
  if (starts_as_zero) {
    CSA_DCHECK(this, WordEqual(WordAnd(word, UintPtrConstant(~mask)), word));
    masked_word = word;
  } else {
    masked_word = WordAnd(word, UintPtrConstant(~mask));
  }
  return WordOr(masked_word, encoded_value);
}

void CodeStubAssembler::SetCounter(StatsCounter* counter, int value) {
  if (v8_flags.native_code_counters && counter->Enabled()) {
    TNode<ExternalReference> counter_address =
        ExternalConstant(ExternalReference::Create(counter));
    StoreNoWriteBarrier(MachineRepresentation::kWord32, counter_address,
                        Int32Constant(value));
  }
}

void CodeStubAssembler::IncrementCounter(StatsCounter* counter, int delta) {
  DCHECK_GT(delta, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    TNode<ExternalReference> counter_address =
        ExternalConstant(ExternalReference::Create(counter));
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    TNode<Int32T> value = Load<Int32T>(counter_address);
    value = Int32Add(value, Int32Constant(delta));
    StoreNoWriteBarrier(MachineRepresentation::kWord32, counter_address, value);
  }
}

void CodeStubAssembler::DecrementCounter(StatsCounter* counter, int delta) {
  DCHECK_GT(delta, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    TNode<ExternalReference> counter_address =
        ExternalConstant(ExternalReference::Create(counter));
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    TNode<Int32T> value = Load<Int32T>(counter_address);
    value = Int32Sub(value, Int32Constant(delta));
    StoreNoWriteBarrier(MachineRepresentation::kWord32, counter_address, value);
  }
}

template <typename TIndex>
void CodeStubAssembler::Increment(TVariable<TIndex>* variable, int value) {
  *variable =
      IntPtrOrSmiAdd(variable->value(), IntPtrOrSmiConstant<TIndex>(value));
}

// Instantiate Increment for Smi and IntPtrT.
// TODO(v8:9708): Consider renaming to [Smi|IntPtrT|RawPtrT]Increment.
template void CodeStubAssembler::Increment<Smi>(TVariable<Smi>* variable,
                                                int value);
template void CodeStubAssembler::Increment<IntPtrT>(
    TVariable<IntPtrT>* variable, int value);
template void CodeStubAssembler::Increment<RawPtrT>(
    TVariable<RawPtrT>* variable, int value);

void CodeStubAssembler::Use(Label* label) {
  GotoIf(Word32Equal(Int32Constant(0), Int32Constant(1)), label);
}

void CodeStubAssembler::TryToName(TNode<Object> key, Label* if_keyisindex,
                                  TVariable<IntPtrT>* var_index,
                                  Label* if_keyisunique,
                                  TVariable<Name>* var_unique,
                                  Label* if_bailout,
                                  Label* if_notinternalized) {
  Comment("TryToName");

  TVARIABLE(Int32T, var_instance_type);
  Label if_keyisnotindex(this);
  *var_index = TryToIntptr(key, &if_keyisnotindex, &var_instance_type);
  Goto(if_keyisindex);

  BIND(&if_keyisnotindex);
  {
    Label if_symbol(this), if_string(this),
        if_keyisother(this, Label::kDeferred);

    // Symbols are unique.
    GotoIf(IsSymbolInstanceType(var_instance_type.value()), &if_symbol);

    // Miss if |key| is not a String.
    static_assert(FIRST_NAME_TYPE == FIRST_TYPE);
    Branch(IsStringInstanceType(var_instance_type.value()), &if_string,
           &if_keyisother);

    // Symbols are unique.
    BIND(&if_symbol);
    {
      *var_unique = CAST(key);
      Goto(if_keyisunique);
    }

    BIND(&if_string);
    {
      TVARIABLE(Uint32T, var_raw_hash);
      Label check_string_hash(this, {&var_raw_hash});

      // TODO(v8:12007): LoadNameRawHashField() should be an acquire load.
      var_raw_hash = LoadNameRawHashField(CAST(key));
      Goto(&check_string_hash);
      BIND(&check_string_hash);
      {
        Label if_thinstring(this), if_has_cached_index(this),
            if_forwarding_index(this, Label::kDeferred);

        TNode<Uint32T> raw_hash_field = var_raw_hash.value();
        GotoIf(IsClearWord32(raw_hash_field,
                             Name::kDoesNotContainCachedArrayIndexMask),
               &if_has_cached_index);
        // No cached array index. If the string knows that it contains an index,
        // then it must be an uncacheable index. Handle this case in the
        // runtime.
        GotoIf(IsEqualInWord32<Name::HashFieldTypeBits>(
                   raw_hash_field, Name::HashFieldType::kIntegerIndex),
               if_bailout);

        static_assert(base::bits::CountPopulation(kThinStringTagBit) == 1);
        GotoIf(IsSetWord32(var_instance_type.value(), kThinStringTagBit),
               &if_thinstring);

        // Check if the hash field encodes a forwarding index.
        GotoIf(IsEqualInWord32<Name::HashFieldTypeBits>(
                   raw_hash_field, Name::HashFieldType::kForwardingIndex),
               &if_forwarding_index);

        // Finally, check if |key| is internalized.
        static_assert(kNotInternalizedTag != 0);
        GotoIf(IsSetWord32(var_instance_type.value(), kIsNotInternalizedMask),
               if_notinternalized != nullptr ? if_notinternalized : if_bailout);

        *var_unique = CAST(key);
        Goto(if_keyisunique);

        BIND(&if_thinstring);
        {
          *var_unique =
              LoadObjectField<String>(CAST(key), offsetof(ThinString, actual_));
          Goto(if_keyisunique);
        }

        BIND(&if_forwarding_index);
        {
          Label if_external(this), if_internalized(this);
          Branch(IsEqualInWord32<Name::IsExternalForwardingIndexBit>(
                     raw_hash_field, true),
                 &if_external, &if_internalized);
          BIND(&if_external);
          {
            // We know nothing about external forwarding indices, so load the
            // forwarded hash and check all possiblities again.
            TNode<ExternalReference> function = ExternalConstant(
                ExternalReference::raw_hash_from_forward_table());
            const TNode<ExternalReference> isolate_ptr =
                ExternalConstant(ExternalReference::isolate_address());
            TNode<Uint32T> result = UncheckedCast<Uint32T>(CallCFunction(
                function, MachineType::Uint32(),
                std::make_pair(MachineType::Pointer(), isolate_ptr),
                std::make_pair(MachineType::Int32(),
                               DecodeWord32<Name::ForwardingIndexValueBits>(
                                   raw_hash_field))));

            var_raw_hash = result;
            Goto(&check_string_hash);
          }

          BIND(&if_internalized);
          {
            // Integer indices are not overwritten with internalized forwarding
            // indices, so we are guaranteed forwarding to a unique name.
            CSA_DCHECK(this,
                       IsEqualInWord32<Name::IsExternalForwardingIndexBit>(
                           raw_hash_field, false));
            TNode<ExternalReference> function = ExternalConstant(
                ExternalReference::string_from_forward_table());
            const TNode<ExternalReference> isolate_ptr =
                ExternalConstant(ExternalReference::isolate_address());
            TNode<Object> result = CAST(CallCFunction(
                function, MachineType::AnyTagged(),
                std::make_pair(MachineType::Pointer(), isolate_ptr),
                std::make_pair(MachineType::Int32(),
                               DecodeWord32<Name::ForwardingIndexValueBits>(
                                   raw_hash_field))));

            *var_unique = CAST(result);
            Goto(if_keyisunique);
          }
        }

        BIND(&if_has_cached_index);
        {
          TNode<IntPtrT> index =
              Signed(DecodeWordFromWord32<String::ArrayIndexValueBits>(
                  raw_hash_field));
          CSA_DCHECK(this, IntPtrLessThan(index, IntPtrConstant(INT_MAX)));
          *var_index = index;
          Goto(if_keyisindex);
        }
      }
    }

    BIND(&if_keyisother);
    {
      GotoIfNot(InstanceTypeEqual(var_instance_type.value(), ODDBALL_TYPE),
                if_bailout);
      *var_unique =
          LoadObjectField<String>(CAST(key), offsetof(Oddball, to_string_));
      Goto(if_keyisunique);
    }
  }
}

void CodeStubAssembler::StringWriteToFlatOneByte(TNode<String> source,
                                                 TNode<RawPtrT> sink,
                                                 TNode<Int32T> start,
                                                 TNode<Int32T> length) {
  TNode<ExternalReference> function =
      ExternalConstant(ExternalReference::string_write_to_flat_one_byte());
  CallCFunction(function, std::nullopt,
                std::make_pair(MachineType::AnyTagged(), source),
                std::make_pair(MachineType::Pointer(), sink),
                std::make_pair(MachineType::Int32(), start),
                std::make_pair(MachineType::Int32(), length));
}

void CodeStubAssembler::StringWriteToFlatTwoByte(TNode<String> source,
                                                 TNode<RawPtrT> sink,
                                                 TNode<Int32T> start,
                                                 TNode<Int32T> length) {
  TNode<ExternalReference> function =
      ExternalConstant(ExternalReference::string_write_to_flat_two_byte());
  CallCFunction(function, std::nullopt,
                std::make_pair(MachineType::AnyTagged(), source),
                std::make_pair(MachineType::Pointer(), sink),
                std::make_pair(MachineType::Int32(), start),
                std::make_pair(MachineType::Int32(), length));
}

TNode<RawPtr<Uint8T>> CodeStubAssembler::ExternalOneByteStringGetChars(
    TNode<ExternalOneByteString> string) {
  TNode<ExternalReference> function =
      ExternalConstant(ExternalReference::external_one_byte_string_get_chars());
  return UncheckedCast<RawPtr<Uint8T>>(
      CallCFunction(function, MachineType::Pointer(),
                    std::make_pair(MachineType::AnyTagged(), string)));
}

TNode<RawPtr<Uint16T>> CodeStubAssembler::ExternalTwoByteStringGetChars(
    TNode<ExternalTwoByteString> string) {
  TNode<ExternalReference> function =
      ExternalConstant(ExternalReference::external_two_byte_string_get_chars());
  return UncheckedCast<RawPtr<Uint16T>>(
      CallCFunction(function, MachineType::Pointer(),
                    std::make_pair(MachineType::AnyTagged(), string)));
}

TNode<RawPtr<Uint8T>> CodeStubAssembler::IntlAsciiCollationWeightsL1() {
#ifdef V8_INTL_SUPPORT
  TNode<RawPtrT> ptr =
      ExternalConstant(ExternalReference::intl_ascii_collation_weights_l1());
  return ReinterpretCast<RawPtr<Uint8T>>(ptr);
#else
  UNREACHABLE();
#endif
}
TNode<RawPtr<Uint8T>> CodeStubAssembler::IntlAsciiCollationWeightsL3() {
#ifdef V8_INTL_SUPPORT
  TNode<RawPtrT> ptr =
      ExternalConstant(ExternalReference::intl_ascii_collation_weights_l3());
  return ReinterpretCast<RawPtr<Uint8T>>(ptr);
#else
  UNREACHABLE();
#endif
}

void CodeStubAssembler::TryInternalizeString(
    TNode<String> string, Label* if_index, TVariable<IntPtrT>* var_index,
    Label* if_internalized, TVariable<Name>* var_internalized,
    Label* if_not_internalized, Label* if_bailout) {
  TNode<ExternalReference> function = ExternalConstant(
      ExternalReference::try_string_to_index_or_lookup_existing());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  TNode<Object> result =
      CAST(CallCFunction(function, MachineType::AnyTagged(),
                         std::make_pair(MachineType::Pointer(), isolate_ptr),
                         std::make_pair(MachineType::AnyTagged(), string)));
  Label internalized(this);
  GotoIf(TaggedIsNotSmi(result), &internalized);
  TNode<IntPtrT> word_result = SmiUntag(CAST(result));
  GotoIf(IntPtrEqual(word_result, IntPtrConstant(ResultSentinel::kNotFound)),
         if_not_internalized);
  GotoIf(IntPtrEqual(word_result, IntPtrConstant(ResultSentinel::kUnsupported)),
         if_bailout);
  *var_index = word_result;
  Goto(if_index);

  BIND(&internalized);
  *var_internalized = CAST(result);
  Goto(if_internalized);
}

template <typename Dictionary>
TNode<IntPtrT> CodeStubAssembler::EntryToIndex(TNode<IntPtrT> entry,
                                               int field_index) {
  TNode<IntPtrT> entry_index =
      IntPtrMul(entry, IntPtrConstant(Dictionary::kEntrySize));
  return IntPtrAdd(entry_index, IntPtrConstant(Dictionary::kElementsStartIndex +
                                               field_index));
}

template <typename T>
TNode<T> CodeStubAssembler::LoadDescriptorArrayElement(
    TNode<DescriptorArray> object, TNode<IntPtrT> index,
    int additional_offset) {
  return LoadArrayElement<DescriptorArray, IntPtrT, T>(
      object, DescriptorArray::kHeaderSize, index, additional_offset);
}

TNode<Name> CodeStubAssembler::LoadKeyByKeyIndex(
    TNode<DescriptorArray> container, TNode<IntPtrT> key_index) {
  return CAST(LoadDescriptorArrayElement<HeapObject>(container, key_index, 0));
}

TNode<Uint32T> CodeStubAssembler::LoadDetailsByKeyIndex(
    TNode<DescriptorArray> container, TNode<IntPtrT> key_index) {
  const int kKeyToDetailsOffset =
      DescriptorArray::kEntryDetailsOffset - DescriptorArray::kEntryKeyOffset;
  return Unsigned(LoadAndUntagToWord32ArrayElement(
      container, DescriptorArray::kHeaderSize, key_index, kKeyToDetailsOffset));
}

TNode<Object> CodeStubAssembler::LoadValueByKeyIndex(
    TNode<DescriptorArray> container, TNode<IntPtrT> key_index) {
  const int kKeyToValueOffset =
      DescriptorArray::kEntryValueOffset - DescriptorArray::kEntryKeyOffset;
  return LoadDescriptorArrayElement<Object>(container, key_index,
                                            kKeyToValueOffset);
}

TNode<MaybeObject> CodeStubAssembler::LoadFieldTypeByKeyIndex(
    TNode<DescriptorArray> container, TNode<IntPtrT> key_index) {
  const int kKeyToValueOffset =
      DescriptorArray::kEntryValueOffset - DescriptorArray::kEntryKeyOffset;
  return LoadDescriptorArrayElement<MaybeObject>(container, key_index,
                                                 kKeyToValueOffset);
}

TNode<IntPtrT> CodeStubAssembler::DescriptorEntryToIndex(
    TNode<IntPtrT> descriptor_entry) {
  return IntPtrMul(descriptor_entry,
                   IntPtrConstant(DescriptorArray::kEntrySize));
}

TNode<Name> CodeStubAssembler::LoadKeyByDescriptorEntry(
    TNode<DescriptorArray> container, TNode<IntPtrT> descriptor_entry) {
  return CAST(LoadDescriptorArrayElement<HeapObject>(
      container, DescriptorEntryToIndex(descriptor_entry),
      DescriptorArray::ToKeyIndex(0) * kTaggedSize));
}

TNode<Name> CodeStubAssembler::LoadKeyByDescriptorEntry(
    TNode<DescriptorArray> container, int descriptor_entry) {
  return CAST(LoadDescriptorArrayElement<HeapObject>(
      container, IntPtrConstant(0),
      DescriptorArray::ToKeyIndex(descriptor_entry) * kTaggedSize));
}

TNode<Uint32T> CodeStubAssembler::LoadDetailsByDescriptorEntry(
    TNode<DescriptorArray> container, TNode<IntPtrT> descriptor_entry) {
  return Unsigned(LoadAndUntagToWord32ArrayElement(
      container, DescriptorArray::kHeaderSize,
      DescriptorEntryToIndex(descriptor_entry),
      DescriptorArray::ToDetailsIndex(0) * kTaggedSize));
}

TNode<Uint32T> CodeStubAssembler::LoadDetailsByDescriptorEntry(
    TNode<DescriptorArray> container, int descriptor_entry) {
  return Unsigned(LoadAndUntagToWord32ArrayElement(
      container, DescriptorArray::kHeaderSize, IntPtrConstant(0),
      DescriptorArray::ToDetailsIndex(descriptor_entry) * kTaggedSize));
}

TNode<Object> CodeStubAssembler::LoadValueByDescriptorEntry(
    TNode<DescriptorArray> container, TNode<IntPtrT> descriptor_entry) {
  return LoadDescriptorArrayElement<Object>(
      container, DescriptorEntryToIndex(descriptor_entry),
      DescriptorArray::ToValueIndex(0) * kTaggedSize);
}

TNode<Object> CodeStubAssembler::LoadValueByDescriptorEntry(
    TNode<DescriptorArray> container, int descriptor_entry) {
  return LoadDescriptorArrayElement<Object>(
      container, IntPtrConstant(0),
      DescriptorArray::ToValueIndex(descriptor_entry) * kTaggedSize);
}

TNode<MaybeObject> CodeStubAssembler::LoadFieldTypeByDescriptorEntry(
    TNode<DescriptorArray> container, TNode<IntPtrT> descriptor_entry) {
  return LoadDescriptorArrayElement<MaybeObject>(
      container, DescriptorEntryToIndex(descriptor_entry),
      DescriptorArray::ToValueIndex(0) * kTaggedSize);
}

// Loads the value for the entry with the given key_index.
// Returns a tagged value.
template <class ContainerType>
TNode<Object> CodeStubAssembler::LoadValueByKeyIndex(
    TNode<ContainerType> container, TNode<IntPtrT> key_index) {
  static_assert(!std::is_same<ContainerType, DescriptorArray>::value,
                "Use the non-templatized version for DescriptorArray");
  const int kKeyToValueOffset =
      (ContainerType::kEntryValueIndex - ContainerType::kEntryKeyIndex) *
      kTaggedSize;
  return LoadFixedArrayElement(container, key_index, kKeyToValueOffset);
}

template <>
V8_EXPORT_PRIVATE TNode<Object> CodeStubAssembler::LoadValueByKeyIndex(
    TNode<SwissNameDictionary> container, TNode<IntPtrT> key_index) {
  TNode<IntPtrT> offset_minus_tag = SwissNameDictionaryOffsetIntoDataTableMT(
      container, key_index, SwissNameDictionary::kDataTableValueEntryIndex);

  return Load<Object>(container, offset_minus_tag);
}

template <class ContainerType>
TNode<Uint32T> CodeStubAssembler::LoadDetailsByKeyIndex(
    TNode<ContainerType> container, TNode<IntPtrT> key_index) {
  static_assert(!std::is_same<ContainerType, DescriptorArray>::value,
                "Use the non-templatized version for DescriptorArray");
  const int kKeyToDetailsOffset =
      (ContainerType::kEntryDetailsIndex - ContainerType::kEntryKeyIndex) *
      kTaggedSize;
  return Unsigned(LoadAndUntagToWord32FixedArrayElement(container, key_index,
                                                        kKeyToDetailsOffset));
}

template <>
V8_EXPORT_PRIVATE TNode<Uint32T> CodeStubAssembler::LoadDetailsByKeyIndex(
    TNode<SwissNameDictionary> container, TNode<IntPtrT> key_index) {
  TNode<IntPtrT> capacity =
      ChangeInt32ToIntPtr(LoadSwissNameDictionaryCapacity(container));
  return LoadSwissNameDictionaryPropertyDetails(container, capacity, key_index);
}

// Stores the details for the entry with the given key_index.
// |details| must be a Smi.
template <class ContainerType>
void CodeStubAssembler::StoreDetailsByKeyIndex(TNode<ContainerType> container,
                                               TNode<IntPtrT> key_index,
                                               TNode<Smi> details) {
  const int kKeyToDetailsOffset =
      (ContainerType::kEntryDetailsIndex - ContainerType::kEntryKeyIndex) *
      kTaggedSize;
  StoreFixedArrayElement(container, key_index, details, kKeyToDetailsOffset);
}

template <>
V8_EXPORT_PRIVATE void CodeStubAssembler::StoreDetailsByKeyIndex(
    TNode<SwissNameDictionary> container, TNode<IntPtrT> key_index,
    TNode<Smi> details) {
  TNode<IntPtrT> capacity =
      ChangeInt32ToIntPtr(LoadSwissNameDictionaryCapacity(container));
  TNode<Uint8T> details_byte = UncheckedCast<Uint8T>(SmiToInt32(details));
  StoreSwissNameDictionaryPropertyDetails(container, capacity, key_index,
                                          details_byte);
}

// Stores the value for the entry with the given key_index.
template <class ContainerType>
void CodeStubAssembler::StoreValueByKeyIndex(TNode<ContainerType> container,
                                             TNode<IntPtrT> key_index,
                                             TNode<Object> value,
                                             WriteBarrierMode write_barrier) {
  const int kKeyToValueOffset =
      (ContainerType::kEntryValueIndex - ContainerType::kEntryKeyIndex) *
      kTaggedSize;
  StoreFixedArrayElement(container, key_index, value, write_barrier,
                         kKeyToValueOffset);
}

template <>
V8_EXPORT_PRIVATE void CodeStubAssembler::StoreValueByKeyIndex(
    TNode<SwissNameDictionary> container, TNode<IntPtrT> key_index,
    TNode<Object> value, WriteBarrierMode write_barrier) {
  TNode<IntPtrT> offset_minus_tag = SwissNameDictionaryOffsetIntoDataTableMT(
      container, key_index, SwissNameDictionary::kDataTableValueEntryIndex);

  StoreToObjectWriteBarrier mode;
  switch (write_barrier) {
    case UNSAFE_SKIP_WRITE_BARRIER:
    case SKIP_WRITE_BARRIER:
      mode = StoreToObjectWriteBarrier::kNone;
      break;
    case UPDATE_WRITE_BARRIER:
      mode = StoreToObjectWriteBarrier::kFull;
      break;
    default:
      // We shouldn't see anything else.
      UNREACHABLE();
  }
  StoreToObject(MachineRepresentation::kTagged, container, offset_minus_tag,
                value, mode);
}

template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::EntryToIndex<NameDictionary>(TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::EntryToIndex<GlobalDictionary>(TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::EntryToIndex<NumberDictionary>(TNode<IntPtrT>, int);

template TNode<Object> CodeStubAssembler::LoadValueByKeyIndex(
    TNode<NameDictionary> container, TNode<IntPtrT> key_index);
template TNode<Object> CodeStubAssembler::LoadValueByKeyIndex(
    TNode<GlobalDictionary> container, TNode<IntPtrT> key_index);
template TNode<Uint32T> CodeStubAssembler::LoadDetailsByKeyIndex(
    TNode<NameDictionary> container, TNode<IntPtrT> key_index);
template void CodeStubAssembler::StoreDetailsByKeyIndex(
    TNode<NameDictionary> container, TNode<IntPtrT> key_index,
    TNode<Smi> details);
template void CodeStubAssembler::StoreValueByKeyIndex(
    TNode<NameDictionary> container, TNode<IntPtrT> key_index,
    TNode<Object> value, WriteBarrierMode write_barrier);

// This must be kept in sync with HashTableBase::ComputeCapacity().
TNode<IntPtrT> CodeStubAssembler::HashTableComputeCapacity(
    TNode<IntPtrT> at_least_space_for) {
  TNode<IntPtrT> capacity = IntPtrRoundUpToPowerOfTwo32(
      IntPtrAdd(at_least_space_for, WordShr(at_least_space_for, 1)));
  return IntPtrMax(capacity, IntPtrConstant(HashTableBase::kMinCapacity));
}

TNode<IntPtrT> CodeStubAssembler::IntPtrMax(TNode<IntPtrT> left,
                                            TNode<IntPtrT> right) {
  intptr_t left_constant;
  intptr_t right_constant;
  if (TryToIntPtrConstant(left, &left_constant) &&
      TryToIntPtrConstant(right, &right_constant)) {
    return IntPtrConstant(std::max(left_constant, right_constant));
  }
  return SelectConstant<IntPtrT>(IntPtrGreaterThanOrEqual(left, right), left,
                                 right);
}

TNode<IntPtrT> CodeStubAssembler::IntPtrMin(TNode<IntPtrT> left,
                                            TNode<IntPtrT> right) {
  intptr_t left_constant;
  intptr_t right_constant;
  if (TryToIntPtrConstant(left, &left_constant) &&
      TryToIntPtrConstant(right, &right_constant)) {
    return IntPtrConstant(std::min(left_constant, right_constant));
  }
  return SelectConstant<IntPtrT>(IntPtrLessThanOrEqual(left, right), left,
                                 right);
}

TNode<UintPtrT> CodeStubAssembler::UintPtrMin(TNode<UintPtrT> left,
                                              TNode<UintPtrT> right) {
  intptr_t left_constant;
  intptr_t right_constant;
  if (TryToIntPtrConstant(left, &left_constant) &&
      TryToIntPtrConstant(right, &right_constant)) {
    return UintPtrConstant(std::min(static_cast<uintptr_t>(left_constant),
                                    static_cast<uintptr_t>(right_constant)));
  }
  return SelectConstant<UintPtrT>(UintPtrLessThanOrEqual(left, right), left,
                                  right);
}

template <>
TNode<HeapObject> CodeStubAssembler::LoadName<NameDictionary>(
    TNode<HeapObject> key) {
  CSA_DCHECK(this, Word32Or(IsTheHole(key), IsName(key)));
  return key;
}

template <>
TNode<HeapObject> CodeStubAssembler::LoadName<GlobalDictionary>(
    TNode<HeapObject> key) {
  TNode<PropertyCell> property_cell = CAST(key);
  return CAST(LoadObjectField(property_cell, PropertyCell::kNameOffset));
}

template <>
TNode<HeapObject> CodeStubAssembler::LoadName<NameToIndexHashTable>(
    TNode<HeapObject> key) {
  CSA_DCHECK(this, IsName(key));
  return key;
}

// The implementation should be in sync with NameToIndexHashTable::Lookup.
TNode<IntPtrT> CodeStubAssembler::NameToIndexHashTableLookup(
    TNode<NameToIndexHashTable> table, TNode<Name> name, Label* not_found) {
  TVARIABLE(IntPtrT, var_entry);
  Label index_found(this, {&var_entry});
  NameDictionaryLookup<NameToIndexHashTable>(table, name, &index_found,
                                             &var_entry, not_found,
                                             LookupMode::kFindExisting);
  BIND(&index_found);
  TNode<Smi> value =
      CAST(LoadValueByKeyIndex<NameToIndexHashTable>(table, var_entry.value()));
  return SmiToIntPtr(value);
}

template <typename Dictionary>
void CodeStubAssembler::NameDictionaryLookup(
    TNode<Dictionary> dictionary, TNode<Name> unique_name, Label* if_found,
    TVariable<IntPtrT>* var_name_index, Label* if_not_found, LookupMode mode) {
  static_assert(std::is_same<Dictionary, NameDictionary>::value ||
                    std::is_same<Dictionary, GlobalDictionary>::value ||
                    std::is_same<Dictionary, NameToIndexHashTable>::value,
                "Unexpected NameDictionary");
  DCHECK_IMPLIES(var_name_index != nullptr,
                 MachineType::PointerRepresentation() == var_name_index->rep());
  DCHECK_IMPLIES(mode == kFindInsertionIndex, if_found == nullptr);
  Comment("NameDictionaryLookup");
  CSA_DCHECK(this, IsUniqueName(unique_name));

  Label if_not_computed(this, Label::kDeferred);

  TNode<IntPtrT> capacity =
      PositiveSmiUntag(GetCapacity<Dictionary>(dictionary));
  TNode<IntPtrT> mask = IntPtrSub(capacity, IntPtrConstant(1));
  TNode<UintPtrT> hash =
      ChangeUint32ToWord(LoadNameHash(unique_name, &if_not_computed));

  // See Dictionary::FirstProbe().
  TNode<IntPtrT> count = IntPtrConstant(0);
  TNode<IntPtrT> initial_entry = Signed(WordAnd(hash, mask));
  TNode<Undefined> undefined = UndefinedConstant();

  // Appease the variable merging algorithm for "Goto(&loop)" below.
  if (var_name_index) *var_name_index = IntPtrConstant(0);

  TVARIABLE(IntPtrT, var_count, count);
  TVARIABLE(IntPtrT, var_entry, initial_entry);
  VariableList loop_vars({&var_count, &var_entry}, zone());
  if (var_name_index) loop_vars.push_back(var_name_index);
  Label loop(this, loop_vars);
  Goto(&loop);
  BIND(&loop);
  {
    Label next_probe(this);
    TNode<IntPtrT> entry = var_entry.value();

    TNode<IntPtrT> index = EntryToIndex<Dictionary>(entry);
    if (var_name_index) *var_name_index = index;

    TNode<HeapObject> current =
        CAST(UnsafeLoadFixedArrayElement(dictionary, index));
    GotoIf(TaggedEqual(current, undefined), if_not_found);
    switch (mode) {
      case kFindInsertionIndex:
        GotoIf(TaggedEqual(current, TheHoleConstant()), if_not_found);
        break;
      case kFindExisting:
      case kFindExistingOrInsertionIndex:
        if (Dictionary::TodoShape::kMatchNeedsHoleCheck) {
          GotoIf(TaggedEqual(current, TheHoleConstant()), &next_probe);
        }
        current = LoadName<Dictionary>(current);
        GotoIf(TaggedEqual(current, unique_name), if_found);
        break;
    }
    Goto(&next_probe);

    BIND(&next_probe);
    // See Dictionary::NextProbe().
    Increment(&var_count);
    entry = Signed(WordAnd(IntPtrAdd(entry, var_count.value()), mask));

    var_entry = entry;
    Goto(&loop);
  }

  BIND(&if_not_computed);
  {
    // Strings will only have the forwarding index with experimental shared
    // memory features turned on. To minimize affecting the fast path, the
    // forwarding index branch defers both fetching the actual hash value and
    // the dictionary lookup to the runtime.
    NameDictionaryLookupWithForwardIndex(dictionary, unique_name, if_found,
                                         var_name_index, if_not_found, mode);
  }
}

// Instantiate template methods to workaround GCC compilation issue.
template V8_EXPORT_PRIVATE void
CodeStubAssembler::NameDictionaryLookup<NameDictionary>(TNode<NameDictionary>,
                                                        TNode<Name>, Label*,
                                                        TVariable<IntPtrT>*,
                                                        Label*, LookupMode);
template V8_EXPORT_PRIVATE void CodeStubAssembler::NameDictionaryLookup<
    GlobalDictionary>(TNode<GlobalDiction
"""


```