Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/builtins-string-gen.cc`. I need to analyze each function within the snippet and explain its purpose. I also need to consider the user's specific requests about `.tq` files, JavaScript relevance, code logic, and common programming errors.

Here's a breakdown of the functions and their potential functionalities:

1. **`StringBuiltinsAssembler::Generate_StringPrototypeSubstring`**: This function seems to implement the `substring` method for JavaScript strings. It likely takes a string and start/end indices as input and returns a new substring.

2. **`StringBuiltinsAssembler::LoadSurrogatePairAt`**: This function appears to handle retrieval of Unicode code points, specifically considering surrogate pairs in UTF-16 encoding.

3. **`StringBuiltinsAssembler::HasUnpairedSurrogate`**: This function probably checks if a string contains unpaired surrogate code points, which are invalid in UTF-16.

4. **`StringBuiltinsAssembler::ReplaceUnpairedSurrogates`**: This function likely replaces any unpaired surrogate code points in a string, possibly with a replacement character.

5. **`StringBuiltinsAssembler::BranchIfStringPrimitiveWithNoCustomIteration`**: This function checks if an object is a primitive string and if its iterator has not been modified. This is probably related to ensuring standard string iteration behavior.

6. **`StringBuiltinsAssembler::CopyStringCharacters`**: This is a template function likely responsible for efficiently copying characters between strings, handling different encoding types (one-byte and two-byte).

7. **`StringBuiltinsAssembler::AllocAndCopyStringCharacters`**: This template function allocates a new string and copies characters into it from an existing string, considering the encoding.

8. **`StringBuiltinsAssembler::SubString`**: This function implements the core logic for creating substrings, handling various string types (sequential, external, sliced) and optimizations.

Now, let's address the user's specific points:

*   **`.tq` files:** If the file ended in `.tq`, it would be a Torque source file, a domain-specific language used in V8. The provided file ends in `.cc`, so it's standard C++.
*   **JavaScript relevance:** Many of these functions directly relate to JavaScript string methods like `substring`, character access, and iteration.
*   **Code logic:**  I need to analyze the control flow within each function, especially conditional branches and loops, to understand the input and output based on different scenarios.
*   **Common programming errors:** I should think about common mistakes developers make when working with strings in JavaScript, such as incorrect index handling or not considering surrogate pairs.

Finally, I need to summarize the overall functionality of this code snippet in the context of V8's string implementation.
这是 `v8/src/builtins/builtins-string-gen.cc` 源代码文件的第三部分，它主要包含以下功能：

**1. 实现 JavaScript 的 `String.prototype.substring()` 方法:**

*   `Generate_StringPrototypeSubstring` 函数是为 JavaScript 的 `String.prototype.substring()` 方法生成代码的入口点。它接收一个字符串和起始、结束索引作为参数，并返回一个新的子字符串。
*   `SubString` 函数是实现 `substring` 功能的核心逻辑。它处理各种情况，例如：
    *   子字符串长度为 0 时，返回空字符串。
    *   子字符串长度为 1 时，直接通过字符码创建字符串。
    *   子字符串长度等于原字符串长度时，返回原字符串（如果索引是 0 和原字符串长度）。
    *   对于较短的子字符串，可能会选择复制字符而不是创建切片字符串 (SlicedString) 以提高性能。
    *   对于外部字符串 (ExternalString)，需要先获取其指向的实际数据。
    *   如果所有优化路径都不满足，则会回退到调用运行时函数 `Runtime::kStringSubstring`。

**JavaScript 示例:**

```javascript
const str = "Hello World";
const sub1 = str.substring(6); // "World"
const sub2 = str.substring(0, 5); // "Hello"
const sub3 = str.substring(2, 2); // ""
const sub4 = str.substring(0, str.length); // "Hello World"
```

**2. 处理 Unicode 代理对:**

*   `LoadSurrogatePairAt` 函数用于加载指定索引处的 32 位 Unicode 代码点，它会检查是否为代理对，并将其合并为一个代码点。
*   `HasUnpairedSurrogate` 函数检查字符串中是否存在未配对的代理项。这通常发生在 UTF-16 编码中，表示一个不完整的字符。
*   `ReplaceUnpairedSurrogates` 函数用于替换字符串中的未配对代理项。这通常用于处理可能包含无效 Unicode 的字符串。

**JavaScript 关联:**

虽然 JavaScript 本身处理 Unicode 代理对是透明的，但在底层实现中，V8 需要处理这些细节以正确表示和操作字符串。例如，当计算字符串长度或访问特定字符时，需要正确处理代理对。

**3. 字符串字符复制优化:**

*   `CopyStringCharacters` 是一组模板函数，用于高效地在字符串之间复制字符。它针对单字节和双字节编码进行了优化。
*   `AllocAndCopyStringCharacters` 用于分配新的字符串并从源字符串复制指定范围的字符。它会根据源字符串的编码选择合适的分配方式，并尝试优化为单字节字符串如果复制的字符都是单字节字符。

**4. 检查字符串迭代器的有效性:**

*   `BranchIfStringPrimitiveWithNoCustomIteration` 函数用于检查一个对象是否是原始字符串，并且其默认迭代器是否没有被修改。这在某些优化场景下很重要，以确保可以安全地使用优化的字符串迭代方式。

**代码逻辑推理 - `SubString` 函数示例:**

**假设输入:**

*   `string`:  一个值为 "abcdefg" 的 JavaScript 字符串。
*   `from`: 2 (IntPtrT)
*   `to`: 5 (IntPtrT)

**预期输出:**

*   返回一个新的 JavaScript 字符串，其值为 "cde"。

**推理过程:**

1. `substr_length` 计算为 `to - from`，即 `5 - 2 = 3`。
2. `string_length` 为 7。
3. 由于 `substr_length` (3) 小于 `string_length` (7)，代码进入 "A real substring" 分支。
4. 由于 `substr_length` (3) 不等于 0 或 1，跳过 "empty" 和 "single_char" 分支。
5. `ToDirectStringAssembler` 尝试将字符串转换为直接字符串表示。
6. `offset` 计算为 `from + to_direct.offset()`，假设 `to_direct.offset()` 为 0，则 `offset` 为 2。
7. 假设字符串是顺序存储的，代码会根据 `v8_flags.string_slices` 的设置决定是否创建切片字符串。
8. 如果 `v8_flags.string_slices` 为 true 且 `substr_length` 大于 `SlicedString::kMinLength`，则会创建一个切片字符串，指向原始字符串的指定范围。
9. 否则，会调用 `AllocAndCopyStringCharacters` 分配一个新的字符串并复制字符 "c"、"d" 和 "e"。
10. 最终返回新的字符串 "cde"。

**用户常见的编程错误举例:**

*   **索引越界:**  在 `substring()` 中使用超出字符串长度的索引会导致难以预测的结果。例如：

    ```javascript
    const str = "abc";
    const sub = str.substring(1, 10); // 不会报错，但结果可能不是预期的，通常会截取到字符串末尾
    ```

*   **混淆 `substring()` 和 `slice()` 的负数索引行为:**  `substring()` 将负数索引视为 0，而 `slice()` 支持从末尾开始的负数索引。

    ```javascript
    const str = "abc";
    const sub1 = str.substring(-1, 2); // 等价于 str.substring(0, 2)，结果是 "ab"
    const sub2 = str.slice(-1, 2);    // 结果是 "c"
    ```

*   **不理解 Unicode 代理对:**  在处理包含非基本多文种平面字符的字符串时，如果按单个字符处理，可能会错误地拆分代理对，导致显示错误或程序错误。

    ```javascript
    const str = "😂"; // Unicode 字符 U+1F602，由一个代理对表示
    console.log(str.length); // 输出 2，因为 JavaScript 将其视为两个 UTF-16 码元
    console.log(str[0]);    // 输出一个代理项，可能显示为乱码
    console.log(str[1]);    // 输出另一个代理项，可能显示为乱码
    ```

**总结其功能:**

`v8/src/builtins/builtins-string-gen.cc` 的这部分代码主要负责实现 JavaScript 中与提取子字符串和处理 Unicode 相关的核心功能。它包含了 `String.prototype.substring()` 方法的生成代码，以及用于高效复制字符和处理 Unicode 代理对的底层工具函数。这些功能是 V8 引擎正确和高效地处理 JavaScript 字符串的关键组成部分。

### 提示词
```
这是目录为v8/src/builtins/builtins-string-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-string-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
riptor::kFrom);
  auto to = UncheckedParameter<IntPtrT>(Descriptor::kTo);

  Return(SubString(string, from, to));
}


// Return the |word32| codepoint at {index}. Supports SeqStrings and
// ExternalStrings.
// TODO(v8:9880): Use UintPtrT here.
TNode<Int32T> StringBuiltinsAssembler::LoadSurrogatePairAt(
    TNode<String> string, TNode<IntPtrT> length, TNode<IntPtrT> index,
    UnicodeEncoding encoding) {
  Label handle_surrogate_pair(this), return_result(this);
  TVARIABLE(Int32T, var_result);
  TVARIABLE(Int32T, var_trail);
  var_result = StringCharCodeAt(string, Unsigned(index));
  var_trail = Int32Constant(0);

  GotoIf(Word32NotEqual(Word32And(var_result.value(), Int32Constant(0xFC00)),
                        Int32Constant(0xD800)),
         &return_result);
  TNode<IntPtrT> next_index = IntPtrAdd(index, IntPtrConstant(1));

  GotoIfNot(IntPtrLessThan(next_index, length), &return_result);
  var_trail = StringCharCodeAt(string, Unsigned(next_index));
  Branch(Word32Equal(Word32And(var_trail.value(), Int32Constant(0xFC00)),
                     Int32Constant(0xDC00)),
         &handle_surrogate_pair, &return_result);

  BIND(&handle_surrogate_pair);
  {
    TNode<Int32T> lead = var_result.value();
    TNode<Int32T> trail = var_trail.value();

    // Check that this path is only taken if a surrogate pair is found
    CSA_SLOW_DCHECK(this,
                    Uint32GreaterThanOrEqual(lead, Int32Constant(0xD800)));
    CSA_SLOW_DCHECK(this, Uint32LessThan(lead, Int32Constant(0xDC00)));
    CSA_SLOW_DCHECK(this,
                    Uint32GreaterThanOrEqual(trail, Int32Constant(0xDC00)));
    CSA_SLOW_DCHECK(this, Uint32LessThan(trail, Int32Constant(0xE000)));

    switch (encoding) {
      case UnicodeEncoding::UTF16:
        var_result = Word32Or(
// Need to swap the order for big-endian platforms
#if V8_TARGET_BIG_ENDIAN
            Word32Shl(lead, Int32Constant(16)), trail);
#else
            Word32Shl(trail, Int32Constant(16)), lead);
#endif
        break;

      case UnicodeEncoding::UTF32: {
        // Convert UTF16 surrogate pair into |word32| code point, encoded as
        // UTF32.
        TNode<Int32T> surrogate_offset =
            Int32Constant(0x10000 - (0xD800 << 10) - 0xDC00);

        // (lead << 10) + trail + SURROGATE_OFFSET
        var_result = Int32Add(Word32Shl(lead, Int32Constant(10)),
                              Int32Add(trail, surrogate_offset));
        break;
      }
    }
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<BoolT> StringBuiltinsAssembler::HasUnpairedSurrogate(TNode<String> string,
                                                           Label* if_indirect) {
  TNode<Uint16T> instance_type = LoadInstanceType(string);
  CSA_DCHECK(this, Word32Equal(Word32And(instance_type,
                                         Int32Constant(kStringEncodingMask)),
                               Int32Constant(kTwoByteStringTag)));
  GotoIfNot(Word32Equal(Word32And(instance_type,
                                  Int32Constant(kIsIndirectStringMask |
                                                kUncachedExternalStringMask)),
                        Int32Constant(0)),
            if_indirect);

  TNode<RawPtrT> string_data = DirectStringData(string, instance_type);
  TNode<IntPtrT> length = LoadStringLengthAsWord(string);

  const TNode<ExternalReference> has_unpaired_surrogate =
      ExternalConstant(ExternalReference::has_unpaired_surrogate());
  return UncheckedCast<BoolT>(
      CallCFunction(has_unpaired_surrogate, MachineType::Uint32(),
                    std::make_pair(MachineType::Pointer(), string_data),
                    std::make_pair(MachineType::IntPtr(), length)));
}

void StringBuiltinsAssembler::ReplaceUnpairedSurrogates(TNode<String> source,
                                                        TNode<String> dest,
                                                        Label* if_indirect) {
  TNode<Uint16T> source_instance_type = LoadInstanceType(source);
  CSA_DCHECK(this, Word32Equal(Word32And(source_instance_type,
                                         Int32Constant(kStringEncodingMask)),
                               Int32Constant(kTwoByteStringTag)));
  GotoIfNot(Word32Equal(Word32And(source_instance_type,
                                  Int32Constant(kIsIndirectStringMask |
                                                kUncachedExternalStringMask)),
                        Int32Constant(0)),
            if_indirect);

  TNode<RawPtrT> source_data = DirectStringData(source, source_instance_type);
  // The destination string is a freshly allocated SeqString, and so is always
  // direct.
  TNode<Uint16T> dest_instance_type = LoadInstanceType(dest);
  CSA_DCHECK(this, Word32Equal(Word32And(dest_instance_type,
                                         Int32Constant(kStringEncodingMask)),
                               Int32Constant(kTwoByteStringTag)));
  TNode<RawPtrT> dest_data = DirectStringData(dest, dest_instance_type);
  TNode<IntPtrT> length = LoadStringLengthAsWord(source);
  CSA_DCHECK(this, IntPtrEqual(length, LoadStringLengthAsWord(dest)));

  const TNode<ExternalReference> replace_unpaired_surrogates =
      ExternalConstant(ExternalReference::replace_unpaired_surrogates());
  CallCFunction(replace_unpaired_surrogates, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), source_data),
                std::make_pair(MachineType::Pointer(), dest_data),
                std::make_pair(MachineType::IntPtr(), length));
}

void StringBuiltinsAssembler::BranchIfStringPrimitiveWithNoCustomIteration(
    TNode<Object> object, TNode<Context> context, Label* if_true,
    Label* if_false) {
  GotoIf(TaggedIsSmi(object), if_false);
  GotoIfNot(IsString(CAST(object)), if_false);

  // Check that the String iterator hasn't been modified in a way that would
  // affect iteration.
  TNode<PropertyCell> protector_cell = StringIteratorProtectorConstant();
  DCHECK(i::IsPropertyCell(isolate()->heap()->string_iterator_protector()));
  Branch(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorValid)),
      if_true, if_false);
}

// Instantiate template due to shared library requirements.
template V8_EXPORT_PRIVATE void StringBuiltinsAssembler::CopyStringCharacters(
    TNode<String> from_string, TNode<String> to_string,
    TNode<IntPtrT> from_index, TNode<IntPtrT> to_index,
    TNode<IntPtrT> character_count, String::Encoding from_encoding,
    String::Encoding to_encoding);

template V8_EXPORT_PRIVATE void StringBuiltinsAssembler::CopyStringCharacters(
    TNode<RawPtrT> from_string, TNode<String> to_string,
    TNode<IntPtrT> from_index, TNode<IntPtrT> to_index,
    TNode<IntPtrT> character_count, String::Encoding from_encoding,
    String::Encoding to_encoding);

template <typename T>
void StringBuiltinsAssembler::CopyStringCharacters(
    TNode<T> from_string, TNode<String> to_string, TNode<IntPtrT> from_index,
    TNode<IntPtrT> to_index, TNode<IntPtrT> character_count,
    String::Encoding from_encoding, String::Encoding to_encoding) {
  // from_string could be either a String or a RawPtrT in the case we pass in
  // faked sequential strings when handling external subject strings.
  bool from_one_byte = from_encoding == String::ONE_BYTE_ENCODING;
  bool to_one_byte = to_encoding == String::ONE_BYTE_ENCODING;
  Comment("CopyStringCharacters ",
          from_one_byte ? "ONE_BYTE_ENCODING" : "TWO_BYTE_ENCODING", " -> ",
          to_one_byte ? "ONE_BYTE_ENCODING" : "TWO_BYTE_ENCODING");

  ElementsKind from_kind = from_one_byte ? UINT8_ELEMENTS : UINT16_ELEMENTS;
  ElementsKind to_kind = to_one_byte ? UINT8_ELEMENTS : UINT16_ELEMENTS;
  static_assert(OFFSET_OF_DATA_START(SeqOneByteString) ==
                OFFSET_OF_DATA_START(SeqTwoByteString));
  int header_size = OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag;
  TNode<IntPtrT> from_offset =
      ElementOffsetFromIndex(from_index, from_kind, header_size);
  TNode<IntPtrT> to_offset =
      ElementOffsetFromIndex(to_index, to_kind, header_size);
  TNode<IntPtrT> byte_count =
      ElementOffsetFromIndex(character_count, from_kind);
  TNode<IntPtrT> limit_offset = IntPtrAdd(from_offset, byte_count);

  // Prepare the fast loop.
  MachineType type =
      from_one_byte ? MachineType::Uint8() : MachineType::Uint16();
  MachineRepresentation rep = to_one_byte ? MachineRepresentation::kWord8
                                          : MachineRepresentation::kWord16;
  int from_increment = 1 << ElementsKindToShiftSize(from_kind);
  int to_increment = 1 << ElementsKindToShiftSize(to_kind);

  TVARIABLE(IntPtrT, current_to_offset, to_offset);
  VariableList vars({&current_to_offset}, zone());
  int to_index_constant = 0, from_index_constant = 0;
  bool index_same = (from_encoding == to_encoding) &&
                    (from_index == to_index ||
                     (TryToInt32Constant(from_index, &from_index_constant) &&
                      TryToInt32Constant(to_index, &to_index_constant) &&
                      from_index_constant == to_index_constant));
  BuildFastLoop<IntPtrT>(
      vars, from_offset, limit_offset,
      [&](TNode<IntPtrT> offset) {
        compiler::Node* value = Load(type, from_string, offset);
#if DEBUG
        // Copying two-byte characters to one-byte is okay if callers have
        // checked that this loses no information.
        if (v8_flags.debug_code && !from_one_byte && to_one_byte) {
          CSA_DCHECK(this, Uint32LessThanOrEqual(UncheckedCast<Uint32T>(value),
                                                 Uint32Constant(0xFF)));
        }
#endif
        StoreNoWriteBarrier(rep, to_string,
                            index_same ? offset : current_to_offset.value(),
                            value);
        if (!index_same) {
          Increment(&current_to_offset, to_increment);
        }
      },
      from_increment, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
}

// A wrapper around CopyStringCharacters which determines the correct string
// encoding, allocates a corresponding sequential string, and then copies the
// given character range using CopyStringCharacters.
// |from_string| must be a sequential string.
// 0 <= |from_index| <= |from_index| + |character_count| < from_string.length.
template <typename T>
TNode<String> StringBuiltinsAssembler::AllocAndCopyStringCharacters(
    TNode<T> from, TNode<BoolT> from_is_one_byte, TNode<IntPtrT> from_index,
    TNode<IntPtrT> character_count) {
  Label end(this), one_byte_sequential(this), two_byte_sequential(this);
  TVARIABLE(String, var_result);

  Branch(from_is_one_byte, &one_byte_sequential, &two_byte_sequential);

  // The subject string is a sequential one-byte string.
  BIND(&one_byte_sequential);
  {
    TNode<String> result = AllocateSeqOneByteString(
        Unsigned(TruncateIntPtrToInt32(character_count)));
    CopyStringCharacters<T>(from, result, from_index, IntPtrConstant(0),
                            character_count, String::ONE_BYTE_ENCODING,
                            String::ONE_BYTE_ENCODING);
    var_result = result;
    Goto(&end);
  }

  // The subject string is a sequential two-byte string.
  BIND(&two_byte_sequential);
  {
    // Check if the to-be-copied range happens to contain only one-byte
    // characters, and copy it to a one-byte string if so.
    // If the range is long enough, we check 8 characters at a time, to reduce
    // the amount of branching.
    // For a more readable version of this logic, see {StringFromTwoByteSlice}
    // in wasm.tq.
    TNode<IntPtrT> start_offset = ElementOffsetFromIndex(
        from_index, UINT16_ELEMENTS,
        OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag);
    TNode<IntPtrT> end_offset = IntPtrAdd(
        start_offset, ElementOffsetFromIndex(character_count, UINT16_ELEMENTS));
    TNode<IntPtrT> eight_char_loop_end = IntPtrSub(
        end_offset, ElementOffsetFromIndex(IntPtrConstant(8), UINT16_ELEMENTS));

    TVARIABLE(IntPtrT, var_cursor, start_offset);
    TNode<RawPtrT> raw_from;
    if constexpr (std::is_same_v<T, RawPtrT>) {
      raw_from = from;
    } else {
      raw_from = ReinterpretCast<RawPtrT>(BitcastTaggedToWord(from));
    }
    Label first_loop(this, &var_cursor), second_loop(this, &var_cursor);
    Label twobyte(this);
    Branch(IntPtrLessThanOrEqual(start_offset, eight_char_loop_end),
           &first_loop, &second_loop);
    BIND(&first_loop);
    {
      TNode<RawPtrT> chunk = RawPtrAdd(raw_from, var_cursor.value());
      TNode<Uint32T> c1 = Load<Uint16T>(chunk);
      TNode<Uint32T> c2 = Load<Uint16T>(chunk, IntPtrConstant(2));
      TNode<Uint32T> bits = Word32Or(c1, c2);
      TNode<Uint32T> c3 = Load<Uint16T>(chunk, IntPtrConstant(4));
      bits = Word32Or(bits, c3);
      TNode<Uint32T> c4 = Load<Uint16T>(chunk, IntPtrConstant(6));
      bits = Word32Or(bits, c4);
      TNode<Uint32T> c5 = Load<Uint16T>(chunk, IntPtrConstant(8));
      bits = Word32Or(bits, c5);
      TNode<Uint32T> c6 = Load<Uint16T>(chunk, IntPtrConstant(10));
      bits = Word32Or(bits, c6);
      TNode<Uint32T> c7 = Load<Uint16T>(chunk, IntPtrConstant(12));
      bits = Word32Or(bits, c7);
      TNode<Uint32T> c8 = Load<Uint16T>(chunk, IntPtrConstant(14));
      bits = Word32Or(bits, c8);
      GotoIf(Uint32GreaterThan(bits, Uint32Constant(0xFF)), &twobyte);
      Increment(&var_cursor, 8 * sizeof(uint16_t));
      Branch(IntPtrLessThanOrEqual(var_cursor.value(), eight_char_loop_end),
             &first_loop, &second_loop);
    }

    BIND(&second_loop);
    TVARIABLE(Uint32T, var_bits, Uint32Constant(0));
    VariableList vars({&var_bits}, zone());
    FastLoopBody<IntPtrT> one_char_loop = [&](TNode<IntPtrT> offset) {
      TNode<Uint32T> c = Load<Uint16T>(from, offset);
      var_bits = Word32Or(var_bits.value(), c);
    };
    BuildFastLoop<IntPtrT>(vars, var_cursor, var_cursor.value(), end_offset,
                           one_char_loop, sizeof(uint16_t),
                           LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);
    GotoIf(Uint32GreaterThan(var_bits.value(), Uint32Constant(0xFF)), &twobyte);
    // Fallthrough: only one-byte characters in the to-be-copied range.
    {
      TNode<String> result = AllocateSeqOneByteString(
          Unsigned(TruncateIntPtrToInt32(character_count)));
      CopyStringCharacters<T>(from, result, from_index, IntPtrConstant(0),
                              character_count, String::TWO_BYTE_ENCODING,
                              String::ONE_BYTE_ENCODING);
      var_result = result;
      Goto(&end);
    }

    BIND(&twobyte);
    {
      TNode<String> result = AllocateSeqTwoByteString(
          Unsigned(TruncateIntPtrToInt32(character_count)));
      CopyStringCharacters<T>(from, result, from_index, IntPtrConstant(0),
                              character_count, String::TWO_BYTE_ENCODING,
                              String::TWO_BYTE_ENCODING);
      var_result = result;
      Goto(&end);
    }
  }

  BIND(&end);
  return var_result.value();
}

// TODO(v8:9880): Use UintPtrT here.
TNode<String> StringBuiltinsAssembler::SubString(TNode<String> string,
                                                 TNode<IntPtrT> from,
                                                 TNode<IntPtrT> to) {
  TVARIABLE(String, var_result);
  ToDirectStringAssembler to_direct(state(), string);
  Label end(this), runtime(this);

  const TNode<IntPtrT> substr_length = IntPtrSub(to, from);
  const TNode<IntPtrT> string_length = LoadStringLengthAsWord(string);

  // Begin dispatching based on substring length.

  Label original_string_or_invalid_length(this);
  GotoIf(UintPtrGreaterThanOrEqual(substr_length, string_length),
         &original_string_or_invalid_length);

  // A real substring (substr_length < string_length).
  Label empty(this);
  GotoIf(IntPtrEqual(substr_length, IntPtrConstant(0)), &empty);

  Label single_char(this);
  GotoIf(IntPtrEqual(substr_length, IntPtrConstant(1)), &single_char);

  // Deal with different string types: update the index if necessary
  // and extract the underlying string.

  TNode<String> direct_string = to_direct.TryToDirect(&runtime);
  TNode<IntPtrT> offset = IntPtrAdd(from, to_direct.offset());
  const TNode<BoolT> is_one_byte = to_direct.IsOneByte();

  // The subject string can only be external or sequential string of either
  // encoding at this point.
  Label external_string(this);
  {
    if (v8_flags.string_slices) {
      Label next(this);

      // Short slice.  Copy instead of slicing.
      GotoIf(IntPtrLessThan(substr_length,
                            IntPtrConstant(SlicedString::kMinLength)),
             &next);

      // Allocate new sliced string.
      Label one_byte_slice(this), two_byte_slice(this);
      Branch(is_one_byte, &one_byte_slice, &two_byte_slice);

      BIND(&one_byte_slice);
      {
        var_result = AllocateSlicedOneByteString(
            Unsigned(TruncateIntPtrToInt32(substr_length)), direct_string,
            SmiTag(offset));
        Goto(&end);
      }

      BIND(&two_byte_slice);
      {
        var_result = AllocateSlicedTwoByteString(
            Unsigned(TruncateIntPtrToInt32(substr_length)), direct_string,
            SmiTag(offset));
        Goto(&end);
      }

      BIND(&next);
    }

    // The subject string can only be external or sequential string of either
    // encoding at this point.
    GotoIf(to_direct.is_external(), &external_string);

    var_result = AllocAndCopyStringCharacters(direct_string, is_one_byte,
                                              offset, substr_length);
    Goto(&end);
  }

  // Handle external string.
  BIND(&external_string);
  {
    const TNode<RawPtrT> fake_sequential_string =
        to_direct.PointerToString(&runtime);

    var_result = AllocAndCopyStringCharacters(
        fake_sequential_string, is_one_byte, offset, substr_length);

    Goto(&end);
  }

  BIND(&empty);
  {
    var_result = EmptyStringConstant();
    Goto(&end);
  }

  // Substrings of length 1 are generated through CharCodeAt and FromCharCode.
  BIND(&single_char);
  {
    TNode<Int32T> char_code = StringCharCodeAt(string, Unsigned(from));
    var_result = StringFromSingleCharCode(char_code);
    Goto(&end);
  }

  BIND(&original_string_or_invalid_length);
  {
    CSA_DCHECK(this, IntPtrEqual(substr_length, string_length));

    // Equal length - check if {from, to} == {0, str.length}.
    GotoIf(UintPtrGreaterThan(from, IntPtrConstant(0)), &runtime);

    // Return the original string (substr_length == string_length).
    var_result = string;
    Goto(&end);
  }

  // Fall back to a runtime call.
  BIND(&runtime);
  {
    var_result =
        CAST(CallRuntime(Runtime::kStringSubstring, NoContextConstant(), string,
                         SmiTag(from), SmiTag(to)));
    Goto(&end);
  }

  BIND(&end);
  return var_result.value();
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```