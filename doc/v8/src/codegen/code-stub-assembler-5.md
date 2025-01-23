Response: My goal is to analyze the given C++ code and summarize its functionality, relating it to JavaScript where applicable, as requested by the user. This is part 6 of a 12-part series, so I need to keep the scope of this part in mind.

Here's my thought process:

1. **Understand the context:** The file `v8/src/codegen/code-stub-assembler.cc` suggests this code is related to V8's code generation, specifically using the `CodeStubAssembler`. This assembler is used to generate machine code for various runtime functions and built-in methods.

2. **Scan for key functionalities:** I'll read through the code, looking for patterns, function names, and comments that indicate the purpose of different sections. I'll focus on the methods defined within the `CodeStubAssembler` class.

3. **Group related functionalities:** I'll group the methods based on their apparent purpose. For example, I see a cluster of methods related to string manipulation (`StringCharCodeAt`, `StringFromSingleCharCode`, `ToDirectStringAssembler`). Another group seems to deal with number conversions (`StringToNumber`, `NumberToString`, `ToNumber`, `ToUint32`).

4. **Summarize each group:** For each group, I'll write a concise summary of what it does. I'll try to use more general terms to capture the overall functionality.

5. **Identify JavaScript connections:**  As I summarize each group, I'll think about how these C++ functions relate to JavaScript's behavior. For example, string manipulation in C++ directly supports JavaScript's string operations. Number conversions in C++ are the underlying mechanisms for JavaScript's type coercion and arithmetic.

6. **Provide JavaScript examples:** For the identified JavaScript connections, I'll create simple, illustrative JavaScript code snippets that demonstrate the functionality being implemented in the C++ code. I'll focus on clear and basic examples.

7. **Address the "part 6 of 12" constraint:** I'll review the summarized functionalities to ensure they are within a reasonable scope for a single part. Since this part seems heavily focused on string and number conversions, it fits well within the scope.

8. **Refine and organize:** I'll review my summaries and examples for clarity, accuracy, and conciseness. I'll organize the information logically.

**Pre-computation/Analysis of the code:**

* **String manipulation:**  I see functions for getting character codes, creating strings from single characters, and the `ToDirectStringAssembler` which handles efficient string access by potentially flattening or unpacking different string representations (ConsString, SlicedString, ThinString, ExternalString).
* **Number conversion:**  There are functions for converting strings to numbers, numbers to strings (including caching), and various `ToNumber` and `ToUint32` functions with different handling of BigInts and potential runtime calls.
* **Type checking:**  Functions like `IsNumberArrayIndex` are used to determine the nature of a numeric value.
* **Memory management:**  `LoadMemoryChunkFlags` hints at interaction with V8's memory management.
* **Array size calculations:** `FixedArraySizeDoesntFitInNewSpace` suggests checks related to allocating arrays in specific memory regions.
* **Helper functions:** There are utility functions like `DecodeWord32`, `UpdateWord32`, and `IncrementCounter`.
* **Dictionary operations:** Towards the end, there's code related to looking up entries in different types of dictionaries (`NameDictionary`, `GlobalDictionary`, `SwissNameDictionary`).

**Drafting the summary:**

Based on the code analysis, I'll draft summaries for each of these areas and then connect them to JavaScript with examples.

**Self-correction/Refinement during drafting:**

* Initially, I might have overemphasized the low-level memory operations. I'll adjust to focus on the higher-level functionalities and their connection to JavaScript.
* I'll ensure my JavaScript examples are simple and directly related to the C++ functions. I want to avoid overly complex scenarios.
* I'll double-check the meaning of specific terms like "Smi," "HeapNumber," and different string types within V8 to ensure accurate explanations.
* I'll ensure the summary correctly reflects that this is part 6 of a larger set and therefore focuses on specific aspects of the `CodeStubAssembler`.

By following this thought process, I can arrive at the desired summary and JavaScript examples.
This C++ code snippet from `v8/src/codegen/code-stub-assembler.cc` (part 6 of 12) primarily focuses on implementing fundamental **type conversion and manipulation operations** within V8's code generation framework. It provides building blocks for converting between different JavaScript types (like numbers and strings) and performing low-level operations on them.

Here's a breakdown of its key functionalities:

**1. Number Handling and Conversion:**

* **`IsNumberArrayIndex(TNode<Number> number)`:** Checks if a given JavaScript number can be used as an array index (i.e., a non-negative integer within the array bounds).
* **`StringToNumber(TNode<String> input)`:**  Converts a JavaScript string to a Number. It attempts to use a cached array index if available for faster conversion.
* **`NumberToString(TNode<Number> input, Label* bailout)` and `NumberToString(TNode<Number> input)`:** Converts a JavaScript Number to a String. It utilizes a number string cache for optimization.
* **`NonNumberToNumberOrNumeric(TNode<Context> context, TNode<HeapObject> input, Object::Conversion mode, BigIntHandling bigint_handling)` and related functions (`NonNumberToNumber`, `TryPlainPrimitiveNonNumberToNumber`, `NonNumberToNumeric`):**  Handles the conversion of non-number JavaScript values (like strings, booleans, null, undefined, symbols, and BigInts) to either a Number or a Numeric (Number or BigInt). It manages different conversion modes and BigInt handling strategies.
* **`ToNumber(TNode<Context> context, TNode<Object> input, BigIntHandling bigint_handling)` and `ToNumber_Inline`:**  Converts any JavaScript value to a Number.
* **`ToNumberOrNumeric(...)`:**  A general conversion function to either Number or Numeric, with support for type feedback.
* **`PlainPrimitiveToNumber(TNode<Object> input)`:** Converts primitive JavaScript values (Smi, HeapNumber, String, Oddball) to a Number.
* **`ToBigInt(TNode<Context> context, TNode<Object> input)` and `ToBigIntConvertNumber(...)`:** Converts JavaScript values to BigInts.
* **`TaggedToBigInt(...)`:** Checks if a tagged JavaScript value is a BigInt and handles different feedback scenarios.
* **`ToUint32(TNode<Context> context, TNode<Object> input)`:** Converts a JavaScript value to an unsigned 32-bit integer (following the `ToUint32` specification).
* **`ToLength_Inline(TNode<Context> context, TNode<Object> input)`:** Converts a JavaScript value to a valid array length.

**2. String Handling and Manipulation:**

* **`StringCharCodeAt(TNode<String> string, TNode<UintPtrT> index)`:** Retrieves the character code at a specific index within a JavaScript string. It efficiently handles different string encodings (one-byte and two-byte).
* **`StringFromSingleCharCode(TNode<Int32T> code)`:** Creates a JavaScript string from a single character code, potentially using a cache for one-byte characters.
* **`ToDirectStringAssembler`:** A helper class that optimizes access to the underlying character data of a JavaScript string by flattening or unpacking various string representations (like ConsString, SlicedString, etc.) to provide a direct pointer to the data.
* **`StringWriteToFlatOneByte(...)` and `StringWriteToFlatTwoByte(...)`:**  Writes the content of a JavaScript string to a flat memory buffer with a specific encoding.
* **`ExternalOneByteStringGetChars(...)` and `ExternalTwoByteStringGetChars(...)`:**  Retrieves pointers to the character data of external string objects.
* **`TryInternalizeString(...)`:** Attempts to find an existing internalized string or index for a given string.

**3. Object and Receiver Handling:**

* **`ToObject(TNode<Context> context, TNode<Object> input)` and `ToObject_Inline(...)`:** Converts a JavaScript value to an Object (following the `ToObject` specification).
* **`OrdinaryToPrimitive(TNode<Context> context, TNode<Object> input, OrdinaryToPrimitiveHint hint)`:** Implements the `OrdinaryToPrimitive` abstract operation used in type conversion.

**4. Helper and Utility Functions:**

* **`FixedArraySizeDoesntFitInNewSpace(...)`:** Checks if the size required for a fixed array exceeds the limits of new space allocation.
* **`LoadMemoryChunkFlags(...)`:** Loads flags associated with a memory chunk.
* **`DecodeWord32(...)`, `DecodeWord(...)`, `UpdateWord32(...)`, `UpdateWord(...)`:**  Functions for manipulating bitfields within words.
* **`SetCounter(...)`, `IncrementCounter(...)`, `DecrementCounter(...)`:** Functions for updating performance counters.
* **`Increment(...)`:**  A template function to increment a variable of type `Smi`, `IntPtrT`, or `RawPtrT`.
* **`Use(Label* label)`:**  A utility function likely used for forcing the inclusion of a label in the generated code.
* **`TryToName(...)`:** Attempts to convert a JavaScript object (likely used as a key) into a Name (String or Symbol), efficiently handling different key types and their properties (like cached array indices or internalization).
* **`IntlAsciiCollationWeightsL1()` and `IntlAsciiCollationWeightsL3()`:**  Functions to get pointers to internationalization collation weights (when enabled).
* **Functions related to Dictionary operations (`EntryToIndex`, `LoadDescriptorArrayElement`, `LoadKeyByKeyIndex`, `LoadDetailsByKeyIndex`, `LoadValueByKeyIndex`, `StoreDetailsByKeyIndex`, `StoreValueByKeyIndex`, `DescriptorEntryToIndex`, `LoadKeyByDescriptorEntry`, `LoadDetailsByDescriptorEntry`, `LoadValueByDescriptorEntry`, `LoadFieldTypeByDescriptorEntry`, `HashTableComputeCapacity`, `IntPtrMax`, `IntPtrMin`, `UintPtrMin`, `LoadName`, `NameToIndexHashTableLookup`, `NameDictionaryLookup`):**  These functions provide the foundation for working with different types of dictionaries used within V8 to store object properties and other data structures.

**Relationship to JavaScript and Examples:**

This C++ code directly underpins many fundamental JavaScript operations. Here are some examples:

**JavaScript `Number()` and `valueOf()`:**

```javascript
// JavaScript:
Number("123"); // Returns 123
Number(true);  // Returns 1
Number(null);  // Returns 0
Number(undefined); // Returns NaN

const obj = { valueOf: () => 42 };
Number(obj); // Returns 42
```

The C++ functions like `StringToNumber`, `NonNumberToNumber`, and `ToNumber` are the underlying implementations that handle these JavaScript conversions.

**JavaScript String Methods (e.g., `charCodeAt()`):**

```javascript
// JavaScript:
const str = "Hello";
str.charCodeAt(1); // Returns 101 (Unicode value of 'e')
```

The C++ function `StringCharCodeAt` provides the low-level logic to access the character code at a given index within the string's internal representation.

**JavaScript `String()`:**

```javascript
// JavaScript:
String(123);   // Returns "123"
String(true);  // Returns "true"
String(null);  // Returns "null"
String(undefined); // Returns "undefined"
```

The C++ functions `NumberToString` and potentially `NonNumberToNumberOrNumeric` (when converting non-numeric types first) are involved in these string conversions.

**JavaScript Array Indexing:**

```javascript
// JavaScript:
const arr = [1, 2, 3];
arr[1]; // Accessing element at index 1
```

The `IsNumberArrayIndex` function (or similar logic within V8) would be used to validate that the provided index `1` is a valid array index before accessing the element.

**JavaScript `parseInt()` and `parseFloat()` (implicitly):**

While not a direct 1:1 mapping, the logic within `StringToNumber` is crucial for the initial parsing and conversion that happens when JavaScript attempts to convert strings to numbers, which is a part of how `parseInt` and `parseFloat` work.

**JavaScript `BigInt()`:**

```javascript
// JavaScript:
BigInt(10); // Returns 10n
BigInt("12345678901234567890"); // Returns 12345678901234567890n
```

The `ToBigInt` and `ToBigIntConvertNumber` functions in the C++ code handle the conversion of JavaScript values to the BigInt type.

**In summary, this part of the `code-stub-assembler.cc` file provides essential low-level routines for type conversion and manipulation that are fundamental to how JavaScript operates within the V8 engine.** It demonstrates the close interaction between the C++ implementation of V8 and the behavior of JavaScript at a language level.

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共12部分，请归纳一下它的功能
```

### 源代码
```
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
```