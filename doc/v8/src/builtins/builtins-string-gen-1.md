Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of `v8/src/builtins/builtins-string-gen.cc`. I also need to explain its relation to JavaScript and provide JavaScript examples if applicable.

Based on the code, it seems to be a collection of helper functions used in the implementation of JavaScript string built-in methods. It uses the V8 internal assembler (`StringBuiltinsAssembler`) to generate optimized code.

Here's a breakdown of the functions I can identify:

- **`SubString`**: This function likely implements the `String.prototype.substring()` method in JavaScript. It handles different string types (sequential, external, sliced) and optimizes for common cases like empty substrings or single-character substrings.
- **`LoadSurrogatePairAt`**:  Deals with Unicode surrogate pairs, which are used to represent code points outside the basic multilingual plane (BMP). This is related to how JavaScript handles Unicode.
- **`HasUnpairedSurrogate`**: Checks if a string has an unpaired surrogate, which is an invalid Unicode sequence.
- **`ReplaceUnpairedSurrogates`**: Replaces unpaired surrogates in a string, potentially with a replacement character.
- **`BranchIfStringPrimitiveWithNoCustomIteration`**:  Checks if an object is a string primitive and if its iterator hasn't been modified. This is important for efficient iteration in JavaScript loops.
- **`CopyStringCharacters`**:  A low-level function to copy characters between strings, handling different encodings (one-byte and two-byte).
- **`AllocAndCopyStringCharacters`**: Allocates a new string and copies a range of characters from another string. It optimizes for the case where a two-byte string slice contains only one-byte characters.

Let's consider how to illustrate the relationship with JavaScript using examples. The `SubString` function is a direct implementation of `substring()`. The surrogate pair functions relate to how JavaScript's `charCodeAt()` and string iteration work with non-BMP characters. The iteration function is relevant to `for...of` loops and other iteration mechanisms.
这是 `v8/src/builtins/builtins-string-gen.cc` 文件的一部分，主要包含了一系列用于实现 JavaScript 内置 `String` 对象相关功能的辅助函数。 这些函数通常由汇编器代码 (`StringBuiltinsAssembler`) 调用，以执行底层的字符串操作。

**功能归纳:**

这部分代码主要关注以下功能：

1. **提取子字符串 (`SubString`)**:  实现了高效地创建字符串子串的逻辑。它会根据子串的长度、原始字符串的类型（例如，是否为外部字符串或切片字符串）选择不同的优化路径。

2. **加载代理对 (`LoadSurrogatePairAt`)**:  处理 Unicode 代理对。JavaScript 使用代理对来表示超出基本多文种平面 (BMP) 的字符。此函数负责从给定索引处加载完整的 32 位代码点，即使它由两个 16 位字符（代理项）组成。

3. **检查未配对的代理项 (`HasUnpairedSurrogate`)**: 确定字符串中是否存在未配对的 Unicode 代理项。未配对的代理项通常表示格式错误的 Unicode 字符串。

4. **替换未配对的代理项 (`ReplaceUnpairedSurrogates`)**:  用于替换字符串中的未配对代理项，通常用于清理或规范化字符串数据。

5. **检查字符串原始值且没有自定义迭代器 (`BranchIfStringPrimitiveWithNoCustomIteration`)**:  用于优化字符串的迭代。它检查一个对象是否是原始字符串类型，并且其默认的迭代器没有被修改过。这允许 V8 执行更快的迭代操作。

6. **复制字符串字符 (`CopyStringCharacters`)**:  一个底层的字符复制函数，用于在两个字符串之间复制指定范围的字符。它支持不同的字符编码（单字节和双字节）。

7. **分配并复制字符串字符 (`AllocAndCopyStringCharacters`)**:  组合了分配新字符串和复制字符的操作。它根据源字符串的编码高效地创建并填充新的顺序字符串。

**与 JavaScript 功能的关系及示例:**

这些 C++ 函数是 JavaScript 内置 `String` 对象方法的底层实现。 例如：

1. **`SubString` 与 `String.prototype.substring()`:**

   ```javascript
   const str = "Hello World";
   const sub = str.substring(6, 11); // "World"
   ```

   `builtins-string-gen.cc` 中的 `SubString` 函数负责在 V8 引擎内部高效地实现 `substring()` 方法的功能，包括处理各种字符串类型和边界条件。

2. **`LoadSurrogatePairAt` 与 `String.prototype.charCodeAt()` 和字符串迭代:**

   ```javascript
   const str = "😊"; // 一个包含代理对的 Emoji
   console.log(str.length); // 2 (因为由两个 UTF-16 编码单元组成)
   console.log(str.charCodeAt(0)); // 55357 (高位代理)
   console.log(str.charCodeAt(1)); // 56842 (低位代理)
   console.log(str.codePointAt(0)); // 128522 (完整的 Unicode 代码点)

   for (const char of str) {
       console.log(char); // "😊"
   }
   ```

   `LoadSurrogatePairAt` 函数在内部被用于实现 `codePointAt()` 和某些迭代器，以正确处理由代理对表示的字符。

3. **`HasUnpairedSurrogate` 与字符串的有效性:**

   虽然 JavaScript 不会直接暴露检查未配对代理项的 API，但引擎内部会使用此功能来确保字符串的正确性，特别是在处理外部数据或进行字符串操作时。

4. **`ReplaceUnpairedSurrogates` 与字符串的清理或规范化:**

   ```javascript
   // 某些情况下，可能会遇到包含未配对代理项的字符串
   const invalidStr = "高位代理\uD83D低位缺失";
   // JavaScript 没有直接的内置方法来替换，但引擎内部可能用到类似逻辑
   // 可以手动实现替换逻辑
   const replacedStr = invalidStr.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, '\uFFFD'); // 替换高位未配对
   const replacedStr2 = replacedStr.replace(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD'); // 替换低位未配对
   console.log(replacedStr2);
   ```

   `ReplaceUnpairedSurrogates` 函数提供了引擎内部替换这些无效字符的能力，例如替换为 Unicode 替换字符 (`\uFFFD`).

5. **`BranchIfStringPrimitiveWithNoCustomIteration` 与 `for...of` 循环的优化:**

   ```javascript
   const str = "abc";
   for (const char of str) {
       console.log(char);
   }
   ```

   `BranchIfStringPrimitiveWithNoCustomIteration` 允许 V8 在执行 `for...of` 循环时，如果确定字符串的迭代行为没有被修改，则可以采用更高效的迭代策略。

6. **`CopyStringCharacters` 和 `AllocAndCopyStringCharacters` 是许多字符串操作的基础:**

   这些底层函数被用于实现各种字符串操作，例如字符串拼接、切片等，在需要创建新的字符串并将一部分现有字符串复制到新字符串时发挥作用。

总而言之，这部分 C++ 代码是 V8 引擎实现 JavaScript 字符串功能的核心组成部分，它提供了高性能的底层操作，确保 JavaScript 字符串操作的效率和正确性。

### 提示词
```
这是目录为v8/src/builtins/builtins-string-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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