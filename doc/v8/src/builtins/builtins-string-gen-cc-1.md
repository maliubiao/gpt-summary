Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code seems to implement built-in string methods for V8, the JavaScript engine.

Here's a plan to break down the analysis:

1. **Identify core functionalities:** Look for function names prefixed with `TF_BUILTIN` as they likely represent the implementation of JavaScript string methods.
2. **Analyze individual built-ins:**  For each built-in, determine its purpose based on its name and the operations within its code.
3. **Check for Torque usage:**  Examine the code for syntax that suggests Torque (like `TNode`, `Label`, `Goto`, `BIND`). The presence of these indicates it's *not* a `.tq` file but uses Torque syntax within a `.cc` file.
4. **Relate to JavaScript:** If a built-in corresponds to a JavaScript method, provide a JavaScript example.
5. **Identify logic and edge cases:** Look for conditional statements and loops that indicate different execution paths and potential edge cases. Provide hypothetical inputs and outputs for logical parts.
6. **Look for common errors:**  Consider scenarios where developers might misuse these string methods.
7. **Synthesize a summary:** Combine the findings from the previous steps into a concise overview of the file's purpose.
这是 V8 引擎中 `v8/src/builtins/builtins-string-gen.cc` 文件的代码片段，它定义了一些内置的字符串操作的生成器函数。这些函数使用 V8 的 TurboFan 编译器框架来高效地实现 JavaScript 的字符串方法。

以下是代码片段中列举的功能的归纳：

1. **字符串比较 (`StringEqual`, `StringLessThan`, `StringLessThanOrEqual`, `StringGreaterThan`, `StringGreaterThanOrEqual`, `StringCompare`)**:
   - 实现了 JavaScript 中的字符串比较运算符 (`==`, `<`, `<=`, `>`, `>=`) 和 `String.prototype.localeCompare()` 的核心逻辑（虽然 `String.prototype.localeCompare()` 最终会调用运行时函数）。
   - 代码首先尝试对单字节字符串进行快速比较，逐字符比较直到遇到不同的字符或到达较短字符串的末尾。
   - 如果两个字符串都是单字节序列字符串，则会进行快速的逐字节比较。
   - 如果不是两个单字节序列字符串，它会尝试解包间接字符串，如果解包成功，则重新进行比较。
   - 对于非单字节字符串的比较，会调用 V8 运行时函数 (`Runtime::kStringLessThan`, `Runtime::kStringGreaterThan`, `Runtime::kStringCompare` 等) 来处理。
   - **JavaScript 例子:**
     ```javascript
     "abc" == "abc"; // true
     "abc" < "abd";  // true
     "abc" > "abb";  // true
     "abc".localeCompare("abd"); // -1 (在 "abd" 之前)
     ```
   - **代码逻辑推理 (假设输入与输出):**
     - **输入:** `lhs = "apple"`, `rhs = "banana"`, `op = StringComparison::kLessThan`
     - **输出:** `TrueConstant()` (因为 "apple" 小于 "banana")
     - **输入:** `lhs = "test"`, `rhs = "test"`, `op = StringComparison::kCompare`
     - **输出:** `SmiConstant(0)` (因为 "test" 等于 "test")
   - **用户常见的编程错误:** 可能会错误地使用 `==` 比较字符串对象，而不是比较字符串的值。应该使用 `===` 或明确的值比较。

2. **`StringFromCodePointAt`**:
   - 实现了 `String.fromCodePoint()` 的一部分功能，用于从给定的 Unicode 码点创建一个字符串。
   - 它从接收器的指定位置加载字符代码，并使用 `StringFromSingleUTF16EncodedCodePoint` 创建字符串。
   - **JavaScript 例子:**
     ```javascript
     String.fromCodePoint(65);   // "A"
     String.fromCodePoint(0x1F600); // "😀"
     ```

3. **`StringFromCharCode`**:
   - 实现了 `String.fromCharCode()`，用于从给定的 UTF-16 代码单元序列创建一个字符串。
   - 对于单个参数的情况，会进行快速的单字符字符串缓存查找。
   - 对于多个参数的情况，它会先尝试分配一个单字节字符串，如果遇到需要双字节表示的字符，则会分配一个双字节字符串并将之前的字符复制过去。
   - **JavaScript 例子:**
     ```javascript
     String.fromCharCode(65, 66, 67); // "ABC"
     String.fromCharCode(0xD83D, 0xDE00); // "😀" (代理对)
     ```
   - **用户常见的编程错误:** `String.fromCharCode` 只能处理 UTF-16 代码单元，对于超出 U+FFFF 的字符，需要使用代理对。直接传入超出范围的数字可能会导致意外的结果。

4. **`MaybeCallFunctionAtSymbol`**:
   - 这是一个辅助函数，用于检查对象上是否存在特定的 Symbol 方法（例如 `Symbol.replace`、`Symbol.matchAll`、`Symbol.split`），如果存在则调用它。
   - 它考虑了原型链上的查找，并针对正则表达式进行了优化，以提高性能。
   - 这段代码是实现可以自定义行为的字符串方法的关键部分，例如通过在对象上定义 `[Symbol.replace]` 方法来覆盖默认的替换行为。

5. **`IndexOfDollarChar`**:
   - 这是一个辅助函数，用于查找字符串中 `$` 字符的索引，通常用于字符串替换操作。

6. **`GetSubstitution`**:
   - 这是一个辅助函数，用于处理字符串替换时的替换字符串，特别是处理 `$` 符号的特殊含义（例如 `$$` 表示插入 `$`，`$&` 表示插入匹配的子串等）。
   - 如果替换字符串中没有 `$`，则直接返回替换字符串。否则，会调用运行时函数 `Runtime::kGetSubstitution` 来处理。

7. **`StringPrototypeReplace`**:
   - 实现了 `String.prototype.replace()` 方法，用于替换字符串中的部分内容。
   - 它首先检查 `search` 参数是否有 `@@replace` 方法（即 `Symbol.replace`），如果有则调用它。
   - 否则，它将 `receiver` 和 `search` 参数转换为字符串，并查找 `search` 字符串在 `receiver` 字符串中的第一个匹配项。
   - 如果找到匹配项，则根据 `replace` 参数的类型（字符串或函数）进行替换。
   - 如果 `replace` 是一个函数，则调用该函数并使用其返回值进行替换。
   - 如果 `replace` 是一个字符串，则会处理其中的特殊 `$` 符号。
   - **JavaScript 例子:**
     ```javascript
     "abcde".replace("cd", "XX"); // "abXXe"
     "abcde".replace(/c/, "XX");  // "abXXde"
     "abcde".replace(/(c)(d)/, "$2$1"); // "abdc" (交换捕获组)
     ```
   - **用户常见的编程错误:**  忘记正则表达式的 `g` 标志会导致只替换第一个匹配项。混淆替换字符串中 `$` 的特殊含义。

8. **`StringPrototypeMatchAll`**:
   - 实现了 `String.prototype.matchAll()` 方法，用于返回一个包含所有匹配正则表达式的结果的迭代器。
   - 它首先检查 `regexp` 参数是否有 `@@matchAll` 方法（即 `Symbol.matchAll`），如果有则调用它。
   - 否则，它确保 `regexp` 参数是全局正则表达式，如果不是则抛出 `TypeError`。
   - 然后，它使用 `RegExp.prototype[@@matchAll]` 来执行匹配。
   - **JavaScript 例子:**
     ```javascript
     const string = 'test1test2';
     const regex = /t(e)(st(\d?))/g;
     const matches = string[Symbol.matchAll](regex);
     for (const match of matches) {
       console.log(match);
     }
     ```
   - **用户常见的编程错误:**  在使用 `matchAll` 时忘记正则表达式的 `g` 标志会导致抛出异常。

9. **`StringToArray`**:
   - 这是一个辅助函数，用于将字符串转换为数组，通常用于 `String.prototype.split()` 的实现。
   - 它尝试对单字节字符串进行优化，直接将字符复制到数组中。
   - 如果字符串是双字节的，或者优化失败，则会调用运行时函数 `Runtime::kStringToArray`。

10. **`StringPrototypeSplit`**:
    - 实现了 `String.prototype.split()` 方法，用于将字符串分割成子字符串数组。
    - 它首先检查 `separator` 参数是否有 `@@split` 方法（即 `Symbol.split`），如果有则调用它。
    - 如果 `separator` 是 `undefined`，则返回包含整个字符串的数组。
    - 如果 `separator` 是空字符串，则将字符串分割成单个字符的数组。
    - 否则，调用运行时函数 `Runtime::kStringSplit` 来执行分割。
    - **JavaScript 例子:**
      ```javascript
      "a,b,c".split(","); // ["a", "b", "c"]
      "abc".split("");    // ["a", "b", "c"]
      "abc".split();     // ["abc"]
      ```
    - **用户常见的编程错误:**  没有理解 `split()` 方法的第二个可选参数 `limit`，它限制了返回数组的长度。

11. **`StringSubstring`**:
    - 这是函数签名的开始，暗示了 `String.prototype.substring()` 的实现，但代码片段在这里被截断了。

**关于 `.tq` 结尾：**

你提供的代码是以 `.cc` 结尾的，所以它不是一个 V8 Torque 源代码。如果 `v8/src/builtins/builtins-string-gen.cc` 文件以 `.tq` 结尾，那么它将是一个用 V8 的 Torque 语言编写的源代码。Torque 是一种用于定义 V8 内置函数的领域特定语言，它可以生成 C++ 代码。

**总结一下 `v8/src/builtins/builtins-string-gen.cc` 的功能 (基于提供的代码片段)：**

该文件包含了使用 V8 的 TurboFan 编译器框架生成的 C++ 代码，用于实现各种 JavaScript 内置的字符串操作，例如比较、从字符码创建字符串、`replace`、`matchAll` 和 `split`。它旨在提供高效的字符串操作实现，并处理了各种边界情况和优化策略，例如对单字节字符串的快速路径处理。该文件还包括辅助函数，用于处理 Symbol 方法的调用和字符串替换的特殊逻辑。

Prompt: 
```
这是目录为v8/src/builtins/builtins-string-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-string-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
);
      Goto(&chunk_loop);
    }

    BIND(&char_loop);
    {
      GotoIf(WordEqual(var_offset.value(), end), &if_done);

      TNode<Uint8T> lhs_char = Load<Uint8T>(lhs, var_offset.value());
      TNode<Uint8T> rhs_char = Load<Uint8T>(rhs, var_offset.value());

      Label if_charsdiffer(this);
      GotoIf(Word32NotEqual(lhs_char, rhs_char), &if_charsdiffer);

      var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(1));
      Goto(&char_loop);

      BIND(&if_charsdiffer);
      Branch(Uint32LessThan(lhs_char, rhs_char), &if_less, &if_greater);
    }

    BIND(&if_done);
    {
      // All characters up to the min length are equal, decide based on
      // string length.
      GotoIf(IntPtrEqual(lhs_length, rhs_length), &if_equal);
      Branch(IntPtrLessThan(lhs_length, rhs_length), &if_less, &if_greater);
    }
  }

  BIND(&if_notbothonebyteseqstrings);
  {
    // Try to unwrap indirect strings, restart the above attempt on success.
    MaybeDerefIndirectStrings(&var_left, lhs_instance_type, &var_right,
                              rhs_instance_type, &restart);
    // TODO(bmeurer): Add support for two byte string relational comparisons.
    switch (op) {
      case StringComparison::kLessThan:
        TailCallRuntime(Runtime::kStringLessThan, NoContextConstant(), lhs,
                        rhs);
        break;
      case StringComparison::kLessThanOrEqual:
        TailCallRuntime(Runtime::kStringLessThanOrEqual, NoContextConstant(),
                        lhs, rhs);
        break;
      case StringComparison::kGreaterThan:
        TailCallRuntime(Runtime::kStringGreaterThan, NoContextConstant(), lhs,
                        rhs);
        break;
      case StringComparison::kGreaterThanOrEqual:
        TailCallRuntime(Runtime::kStringGreaterThanOrEqual, NoContextConstant(),
                        lhs, rhs);
        break;
      case StringComparison::kCompare:
        TailCallRuntime(Runtime::kStringCompare, NoContextConstant(), lhs, rhs);
        break;
    }
  }

  BIND(&if_less);
  switch (op) {
    case StringComparison::kLessThan:
    case StringComparison::kLessThanOrEqual:
      Return(TrueConstant());
      break;

    case StringComparison::kGreaterThan:
    case StringComparison::kGreaterThanOrEqual:
      Return(FalseConstant());
      break;

    case StringComparison::kCompare:
      Return(SmiConstant(-1));
      break;
  }

  BIND(&if_equal);
  switch (op) {
    case StringComparison::kLessThan:
    case StringComparison::kGreaterThan:
      Return(FalseConstant());
      break;

    case StringComparison::kLessThanOrEqual:
    case StringComparison::kGreaterThanOrEqual:
      Return(TrueConstant());
      break;

    case StringComparison::kCompare:
      Return(SmiConstant(0));
      break;
  }

  BIND(&if_greater);
  switch (op) {
    case StringComparison::kLessThan:
    case StringComparison::kLessThanOrEqual:
      Return(FalseConstant());
      break;

    case StringComparison::kGreaterThan:
    case StringComparison::kGreaterThanOrEqual:
      Return(TrueConstant());
      break;

    case StringComparison::kCompare:
      Return(SmiConstant(1));
      break;
  }
}

TF_BUILTIN(StringEqual, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  auto length = UncheckedParameter<IntPtrT>(Descriptor::kLength);
  // Callers must handle the case where {lhs} and {rhs} refer to the same
  // String object.
  CSA_DCHECK(this, TaggedNotEqual(left, right));
  GenerateStringEqual(left, right, length);
}

TF_BUILTIN(StringLessThan, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  GenerateStringRelationalComparison(left, right, StringComparison::kLessThan);
}

TF_BUILTIN(StringLessThanOrEqual, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  GenerateStringRelationalComparison(left, right,
                                     StringComparison::kLessThanOrEqual);
}

TF_BUILTIN(StringGreaterThan, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  GenerateStringRelationalComparison(left, right,
                                     StringComparison::kGreaterThan);
}

TF_BUILTIN(StringCompare, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  GenerateStringRelationalComparison(left, right, StringComparison::kCompare);
}

TF_BUILTIN(StringGreaterThanOrEqual, StringBuiltinsAssembler) {
  auto left = Parameter<String>(Descriptor::kLeft);
  auto right = Parameter<String>(Descriptor::kRight);
  GenerateStringRelationalComparison(left, right,
                                     StringComparison::kGreaterThanOrEqual);
}

#ifndef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS

// NOTE: This needs to be kept in sync with the Turboshaft implementation in
// `builtins-string-tsa.cc`.
TF_BUILTIN(StringFromCodePointAt, StringBuiltinsAssembler) {
  auto receiver = Parameter<String>(Descriptor::kReceiver);
  auto position = UncheckedParameter<IntPtrT>(Descriptor::kPosition);

  // TODO(sigurds) Figure out if passing length as argument pays off.
  TNode<IntPtrT> length = LoadStringLengthAsWord(receiver);
  // Load the character code at the {position} from the {receiver}.
  TNode<Int32T> code =
      LoadSurrogatePairAt(receiver, length, position, UnicodeEncoding::UTF16);
  // Create a String from the UTF16 encoded code point
  TNode<String> result = StringFromSingleUTF16EncodedCodePoint(code);
  Return(result);
}

// -----------------------------------------------------------------------------
// ES6 section 21.1 String Objects

// ES6 #sec-string.fromcharcode
// NOTE: This needs to be kept in sync with the Turboshaft implementation in
// `builtins-string-tsa.cc`.
TF_BUILTIN(StringFromCharCode, StringBuiltinsAssembler) {
  // TODO(ishell): use constants from Descriptor once the JSFunction linkage
  // arguments are reordered.
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);

  CodeStubArguments arguments(this, argc);
  TNode<Uint32T> unsigned_argc =
      Unsigned(TruncateIntPtrToInt32(arguments.GetLengthWithoutReceiver()));
  // Check if we have exactly one argument (plus the implicit receiver), i.e.
  // if the parent frame is not an inlined arguments frame.
  Label if_oneargument(this), if_notoneargument(this);
  Branch(IntPtrEqual(arguments.GetLengthWithoutReceiver(), IntPtrConstant(1)),
         &if_oneargument, &if_notoneargument);

  BIND(&if_oneargument);
  {
    // Single argument case, perform fast single character string cache lookup
    // for one-byte code units, or fall back to creating a single character
    // string on the fly otherwise.
    TNode<Object> code = arguments.AtIndex(0);
    TNode<Word32T> code32 = TruncateTaggedToWord32(context, code);
    TNode<Int32T> code16 =
        Signed(Word32And(code32, Int32Constant(String::kMaxUtf16CodeUnit)));
    TNode<String> result = StringFromSingleCharCode(code16);
    arguments.PopAndReturn(result);
  }

  TNode<Word32T> code16;
  BIND(&if_notoneargument);
  {
    Label two_byte(this);
    // Assume that the resulting string contains only one-byte characters.
    TNode<String> one_byte_result = AllocateSeqOneByteString(unsigned_argc);

    TVARIABLE(IntPtrT, var_max_index, IntPtrConstant(0));

    // Iterate over the incoming arguments, converting them to 8-bit character
    // codes. Stop if any of the conversions generates a code that doesn't fit
    // in 8 bits.
    CodeStubAssembler::VariableList vars({&var_max_index}, zone());
    arguments.ForEach(vars, [&](TNode<Object> arg) {
      TNode<Word32T> code32 = TruncateTaggedToWord32(context, arg);
      code16 = Word32And(code32, Int32Constant(String::kMaxUtf16CodeUnit));

      GotoIf(
          Int32GreaterThan(code16, Int32Constant(String::kMaxOneByteCharCode)),
          &two_byte);

      // The {code16} fits into the SeqOneByteString {one_byte_result}.
      TNode<IntPtrT> offset = ElementOffsetFromIndex(
          var_max_index.value(), UINT8_ELEMENTS,
          OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag);
      StoreNoWriteBarrier(MachineRepresentation::kWord8, one_byte_result,
                          offset, code16);
      var_max_index = IntPtrAdd(var_max_index.value(), IntPtrConstant(1));
    });
    arguments.PopAndReturn(one_byte_result);

    BIND(&two_byte);

    // At least one of the characters in the string requires a 16-bit
    // representation.  Allocate a SeqTwoByteString to hold the resulting
    // string.
    TNode<String> two_byte_result = AllocateSeqTwoByteString(unsigned_argc);

    // Copy the characters that have already been put in the 8-bit string into
    // their corresponding positions in the new 16-bit string.
    TNode<IntPtrT> zero = IntPtrConstant(0);
    CopyStringCharacters(one_byte_result, two_byte_result, zero, zero,
                         var_max_index.value(), String::ONE_BYTE_ENCODING,
                         String::TWO_BYTE_ENCODING);

    // Write the character that caused the 8-bit to 16-bit fault.
    TNode<IntPtrT> max_index_offset = ElementOffsetFromIndex(
        var_max_index.value(), UINT16_ELEMENTS,
        OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag);
    StoreNoWriteBarrier(MachineRepresentation::kWord16, two_byte_result,
                        max_index_offset, code16);
    var_max_index = IntPtrAdd(var_max_index.value(), IntPtrConstant(1));

    // Resume copying the passed-in arguments from the same place where the
    // 8-bit copy stopped, but this time copying over all of the characters
    // using a 16-bit representation.
    arguments.ForEach(
        vars,
        [&](TNode<Object> arg) {
          TNode<Word32T> code32 = TruncateTaggedToWord32(context, arg);
          TNode<Word32T> code16 =
              Word32And(code32, Int32Constant(String::kMaxUtf16CodeUnit));

          TNode<IntPtrT> offset = ElementOffsetFromIndex(
              var_max_index.value(), UINT16_ELEMENTS,
              OFFSET_OF_DATA_START(SeqTwoByteString) - kHeapObjectTag);
          StoreNoWriteBarrier(MachineRepresentation::kWord16, two_byte_result,
                              offset, code16);
          var_max_index = IntPtrAdd(var_max_index.value(), IntPtrConstant(1));
        },
        var_max_index.value());

    arguments.PopAndReturn(two_byte_result);
  }
}

#endif  // V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS

void StringBuiltinsAssembler::MaybeCallFunctionAtSymbol(
    const TNode<Context> context, const TNode<Object> object,
    const TNode<Object> maybe_string, Handle<Symbol> symbol,
    DescriptorIndexNameValue additional_property_to_check,
    const NodeFunction0& regexp_call, const NodeFunction1& generic_call) {
  Label out(this), no_protector(this), object_is_heapobject(this);
  Label get_property_lookup(this);

  // The protector guarantees that that the Number and String wrapper
  // prototypes do not contain Symbol.{matchAll|replace|split} (aka.
  // @@matchAll, @@replace @@split).
  GotoIf(IsNumberStringNotRegexpLikeProtectorCellInvalid(), &no_protector);
  // Smi is safe thanks to the protector.
  GotoIf(TaggedIsSmi(object), &out);
  // String is safe thanks to the protector.
  GotoIf(IsString(CAST(object)), &out);
  // HeapNumber is safe thanks to the protector.
  Branch(IsHeapNumber(CAST(object)), &out, &object_is_heapobject);

  BIND(&no_protector);
  // Smis have to go through the GetProperty lookup in case Number.prototype or
  // Object.prototype was modified.
  Branch(TaggedIsSmi(object), &get_property_lookup, &object_is_heapobject);

  // Take the fast path for RegExps.
  // There's two conditions: {object} needs to be a fast regexp, and
  // {maybe_string} must be a string (we can't call ToString on the fast path
  // since it may mutate {object}).
  {
    Label stub_call(this), slow_lookup(this);

    BIND(&object_is_heapobject);
    TNode<HeapObject> heap_object = CAST(object);

    GotoIf(TaggedIsSmi(maybe_string), &slow_lookup);
    GotoIfNot(IsString(CAST(maybe_string)), &slow_lookup);

    // Note we don't run a full (= permissive) check here, because passing the
    // check implies calling the fast variants of target builtins, which assume
    // we've already made their appropriate fast path checks. This is not the
    // case though; e.g.: some of the target builtins access flag getters.
    // TODO(jgruber): Handle slow flag accesses on the fast path and make this
    // permissive.
    RegExpBuiltinsAssembler regexp_asm(state());
    regexp_asm.BranchIfFastRegExp(
        context, heap_object, LoadMap(heap_object),
        PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
        additional_property_to_check, &stub_call, &slow_lookup);

    BIND(&stub_call);
    // TODO(jgruber): Add a no-JS scope once it exists.
    regexp_call();

    BIND(&slow_lookup);
    // Special case null and undefined to skip the property lookup.
    Branch(IsNullOrUndefined(heap_object), &out, &get_property_lookup);
  }

  // Fall back to a slow lookup of {heap_object[symbol]}.
  //
  // The spec uses GetMethod({heap_object}, {symbol}), which has a few quirks:
  // * null values are turned into undefined, and
  // * an exception is thrown if the value is not undefined, null, or callable.
  // We handle the former by jumping to {out} for null values as well, while
  // the latter is already handled by the Call({maybe_func}) operation.

  BIND(&get_property_lookup);
  const TNode<Object> maybe_func = GetProperty(context, object, symbol);
  GotoIf(IsUndefined(maybe_func), &out);
  GotoIf(IsNull(maybe_func), &out);

  // Attempt to call the function.
  generic_call(maybe_func);

  BIND(&out);
}

TNode<Smi> StringBuiltinsAssembler::IndexOfDollarChar(
    const TNode<Context> context, const TNode<String> string) {
  const TNode<String> dollar_string = HeapConstantNoHole(
      isolate()->factory()->LookupSingleCharacterStringFromCode('$'));
  const TNode<Smi> dollar_ix = CAST(CallBuiltin(
      Builtin::kStringIndexOf, context, string, dollar_string, SmiConstant(0)));
  return dollar_ix;
}

TNode<String> StringBuiltinsAssembler::GetSubstitution(
    TNode<Context> context, TNode<String> subject_string,
    TNode<Smi> match_start_index, TNode<Smi> match_end_index,
    TNode<String> replace_string) {
  CSA_DCHECK(this, TaggedIsPositiveSmi(match_start_index));
  CSA_DCHECK(this, TaggedIsPositiveSmi(match_end_index));

  TVARIABLE(String, var_result, replace_string);
  Label runtime(this), out(this);

  // In this primitive implementation we simply look for the next '$' char in
  // {replace_string}. If it doesn't exist, we can simply return
  // {replace_string} itself. If it does, then we delegate to
  // String::GetSubstitution, passing in the index of the first '$' to avoid
  // repeated scanning work.
  // TODO(jgruber): Possibly extend this in the future to handle more complex
  // cases without runtime calls.

  TNode<Smi> dollar_index = IndexOfDollarChar(context, replace_string);
  Branch(SmiIsNegative(dollar_index), &out, &runtime);

  BIND(&runtime);
  {
    CSA_DCHECK(this, TaggedIsPositiveSmi(dollar_index));

    const TNode<Object> matched =
        CallBuiltin(Builtin::kStringSubstring, context, subject_string,
                    SmiUntag(match_start_index), SmiUntag(match_end_index));
    const TNode<String> replacement_string = CAST(
        CallRuntime(Runtime::kGetSubstitution, context, matched, subject_string,
                    match_start_index, replace_string, dollar_index));
    var_result = replacement_string;

    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

// ES6 #sec-string.prototype.replace
TF_BUILTIN(StringPrototypeReplace, StringBuiltinsAssembler) {
  Label out(this);

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto search = Parameter<Object>(Descriptor::kSearch);
  const auto replace = Parameter<Object>(Descriptor::kReplace);
  auto context = Parameter<Context>(Descriptor::kContext);

  const TNode<Smi> smi_zero = SmiConstant(0);

  RequireObjectCoercible(context, receiver, "String.prototype.replace");

  // Redirect to replacer method if {search[@@replace]} is not undefined.
  {
    Label next(this);

    MaybeCallFunctionAtSymbol(
        context, search, receiver, isolate()->factory()->replace_symbol(),
        DescriptorIndexNameValue{
            JSRegExp::kSymbolReplaceFunctionDescriptorIndex,
            RootIndex::kreplace_symbol, Context::REGEXP_REPLACE_FUNCTION_INDEX},
        [=, this]() {
          Return(CallBuiltin(Builtin::kRegExpReplace, context, search, receiver,
                             replace));
        },
        [=, this](TNode<Object> fn) {
          Return(Call(context, fn, search, receiver, replace));
        });
    Goto(&next);

    BIND(&next);
  }

  // Convert {receiver} and {search} to strings.

  const TNode<String> subject_string = ToString_Inline(context, receiver);
  const TNode<String> search_string = ToString_Inline(context, search);

  const TNode<IntPtrT> subject_length = LoadStringLengthAsWord(subject_string);
  const TNode<IntPtrT> search_length = LoadStringLengthAsWord(search_string);

  // Fast-path single-char {search}, long cons {receiver}, and simple string
  // {replace}.
  {
    Label next(this);

    GotoIfNot(WordEqual(search_length, IntPtrConstant(1)), &next);
    GotoIfNot(IntPtrGreaterThan(subject_length, IntPtrConstant(0xFF)), &next);
    GotoIf(TaggedIsSmi(replace), &next);
    GotoIfNot(IsString(CAST(replace)), &next);

    TNode<String> replace_string = CAST(replace);
    const TNode<Uint16T> subject_instance_type =
        LoadInstanceType(subject_string);
    GotoIfNot(IsConsStringInstanceType(subject_instance_type), &next);

    GotoIf(TaggedIsPositiveSmi(IndexOfDollarChar(context, replace_string)),
           &next);

    // Searching by traversing a cons string tree and replace with cons of
    // slices works only when the replaced string is a single character, being
    // replaced by a simple string and only pays off for long strings.
    // TODO(jgruber): Reevaluate if this is still beneficial.
    // TODO(jgruber): TailCallRuntime when it correctly handles adapter frames.
    Return(CallRuntime(Runtime::kStringReplaceOneCharWithString, context,
                       subject_string, search_string, replace_string));

    BIND(&next);
  }

  // TODO(jgruber): Extend StringIndexOf to handle two-byte strings and
  // longer substrings - we can handle up to 8 chars (one-byte) / 4 chars
  // (2-byte).

  const TNode<Smi> match_start_index =
      CAST(CallBuiltin(Builtin::kStringIndexOf, context, subject_string,
                       search_string, smi_zero));

  // Early exit if no match found.
  {
    Label next(this), return_subject(this);

    GotoIfNot(SmiIsNegative(match_start_index), &next);

    // The spec requires to perform ToString(replace) if the {replace} is not
    // callable even if we are going to exit here.
    // Since ToString() being applied to Smi does not have side effects for
    // numbers we can skip it.
    GotoIf(TaggedIsSmi(replace), &return_subject);
    GotoIf(IsCallableMap(LoadMap(CAST(replace))), &return_subject);

    // TODO(jgruber): Could introduce ToStringSideeffectsStub which only
    // performs observable parts of ToString.
    ToString_Inline(context, replace);
    Goto(&return_subject);

    BIND(&return_subject);
    Return(subject_string);

    BIND(&next);
  }

  const TNode<Smi> match_end_index =
      SmiAdd(match_start_index, SmiFromIntPtr(search_length));

  TVARIABLE(String, var_result, EmptyStringConstant());

  // Compute the prefix.
  {
    Label next(this);

    GotoIf(SmiEqual(match_start_index, smi_zero), &next);
    const TNode<String> prefix =
        CAST(CallBuiltin(Builtin::kStringSubstring, context, subject_string,
                         IntPtrConstant(0), SmiUntag(match_start_index)));
    var_result = prefix;

    Goto(&next);
    BIND(&next);
  }

  // Compute the string to replace with.

  Label if_iscallablereplace(this), if_notcallablereplace(this);
  GotoIf(TaggedIsSmi(replace), &if_notcallablereplace);
  Branch(IsCallableMap(LoadMap(CAST(replace))), &if_iscallablereplace,
         &if_notcallablereplace);

  BIND(&if_iscallablereplace);
  {
    const TNode<Object> replacement =
        Call(context, replace, UndefinedConstant(), search_string,
             match_start_index, subject_string);
    const TNode<String> replacement_string =
        ToString_Inline(context, replacement);
    var_result = CAST(CallBuiltin(Builtin::kStringAdd_CheckNone, context,
                                  var_result.value(), replacement_string));
    Goto(&out);
  }

  BIND(&if_notcallablereplace);
  {
    const TNode<String> replace_string = ToString_Inline(context, replace);
    const TNode<Object> replacement =
        GetSubstitution(context, subject_string, match_start_index,
                        match_end_index, replace_string);
    var_result = CAST(CallBuiltin(Builtin::kStringAdd_CheckNone, context,
                                  var_result.value(), replacement));
    Goto(&out);
  }

  BIND(&out);
  {
    const TNode<Object> suffix =
        CallBuiltin(Builtin::kStringSubstring, context, subject_string,
                    SmiUntag(match_end_index), subject_length);
    const TNode<Object> result = CallBuiltin(
        Builtin::kStringAdd_CheckNone, context, var_result.value(), suffix);
    Return(result);
  }
}

// ES #sec-string.prototype.matchAll
TF_BUILTIN(StringPrototypeMatchAll, StringBuiltinsAssembler) {
  char const* method_name = "String.prototype.matchAll";

  auto context = Parameter<Context>(Descriptor::kContext);
  auto maybe_regexp = Parameter<Object>(Descriptor::kRegexp);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  TNode<NativeContext> native_context = LoadNativeContext(context);

  // 1. Let O be ? RequireObjectCoercible(this value).
  RequireObjectCoercible(context, receiver, method_name);

  RegExpMatchAllAssembler regexp_asm(state());
  {
    Label fast(this), slow(this, Label::kDeferred),
        throw_exception(this, Label::kDeferred),
        throw_flags_exception(this, Label::kDeferred), next(this);

    // 2. If regexp is neither undefined nor null, then
    //   a. Let isRegExp be ? IsRegExp(regexp).
    //   b. If isRegExp is true, then
    //     i. Let flags be ? Get(regexp, "flags").
    //    ii. Perform ? RequireObjectCoercible(flags).
    //   iii. If ? ToString(flags) does not contain "g", throw a
    //        TypeError exception.
    GotoIf(TaggedIsSmi(maybe_regexp), &next);
    TNode<HeapObject> heap_maybe_regexp = CAST(maybe_regexp);
    regexp_asm.BranchIfFastRegExpForMatch(context, heap_maybe_regexp, &fast,
                                          &slow);

    BIND(&fast);
    {
      TNode<BoolT> is_global = regexp_asm.FlagGetter(context, heap_maybe_regexp,
                                                     JSRegExp::kGlobal, true);
      Branch(is_global, &next, &throw_exception);
    }

    BIND(&slow);
    {
      GotoIfNot(regexp_asm.IsRegExp(native_context, heap_maybe_regexp), &next);

      TNode<Object> flags = GetProperty(context, heap_maybe_regexp,
                                        isolate()->factory()->flags_string());
      // TODO(syg): Implement a RequireObjectCoercible with more flexible error
      // messages.
      GotoIf(IsNullOrUndefined(flags), &throw_flags_exception);

      TNode<String> flags_string = ToString_Inline(context, flags);
      TNode<String> global_char_string = StringConstant("g");
      TNode<Smi> global_ix =
          CAST(CallBuiltin(Builtin::kStringIndexOf, context, flags_string,
                           global_char_string, SmiConstant(0)));
      Branch(SmiEqual(global_ix, SmiConstant(-1)), &throw_exception, &next);
    }

    BIND(&throw_exception);
    ThrowTypeError(context, MessageTemplate::kRegExpGlobalInvokedOnNonGlobal,
                   method_name);

    BIND(&throw_flags_exception);
    ThrowTypeError(context,
                   MessageTemplate::kStringMatchAllNullOrUndefinedFlags);

    BIND(&next);
  }
  //   a. Let matcher be ? GetMethod(regexp, @@matchAll).
  //   b. If matcher is not undefined, then
  //     i. Return ? Call(matcher, regexp, « O »).
  auto if_regexp_call = [&] {
    // MaybeCallFunctionAtSymbol guarantees fast path is chosen only if
    // maybe_regexp is a fast regexp and receiver is a string.
    TNode<String> s = CAST(receiver);

    Return(
        RegExpPrototypeMatchAllImpl(context, native_context, maybe_regexp, s));
  };
  auto if_generic_call = [=, this](TNode<Object> fn) {
    Return(Call(context, fn, maybe_regexp, receiver));
  };
  MaybeCallFunctionAtSymbol(
      context, maybe_regexp, receiver, isolate()->factory()->match_all_symbol(),
      DescriptorIndexNameValue{JSRegExp::kSymbolMatchAllFunctionDescriptorIndex,
                               RootIndex::kmatch_all_symbol,
                               Context::REGEXP_MATCH_ALL_FUNCTION_INDEX},
      if_regexp_call, if_generic_call);

  // 3. Let S be ? ToString(O).
  TNode<String> s = ToString_Inline(context, receiver);

  // 4. Let rx be ? RegExpCreate(R, "g").
  TNode<Object> rx = regexp_asm.RegExpCreate(context, native_context,
                                             maybe_regexp, StringConstant("g"));

  // 5. Return ? Invoke(rx, @@matchAll, « S »).
  TNode<Object> match_all_func =
      GetProperty(context, rx, isolate()->factory()->match_all_symbol());
  Return(Call(context, match_all_func, rx, s));
}

TNode<JSArray> StringBuiltinsAssembler::StringToArray(
    TNode<NativeContext> context, TNode<String> subject_string,
    TNode<Smi> subject_length, TNode<Number> limit_number) {
  CSA_DCHECK(this, SmiGreaterThan(subject_length, SmiConstant(0)));

  Label done(this), call_runtime(this, Label::kDeferred),
      fill_thehole_and_call_runtime(this, Label::kDeferred);
  TVARIABLE(JSArray, result_array);

  TNode<Uint16T> instance_type = LoadInstanceType(subject_string);
  GotoIfNot(IsOneByteStringInstanceType(instance_type), &call_runtime);

  // Try to use cached one byte characters.
  {
    TNode<Smi> length_smi = Select<Smi>(
        TaggedIsSmi(limit_number),
        [=, this] { return SmiMin(CAST(limit_number), subject_length); },
        [=] { return subject_length; });
    TNode<IntPtrT> length = SmiToIntPtr(length_smi);

    ToDirectStringAssembler to_direct(state(), subject_string);
    to_direct.TryToDirect(&call_runtime);

    // The extracted direct string may be two-byte even though the wrapping
    // string is one-byte.
    GotoIfNot(to_direct.IsOneByte(), &call_runtime);

    TNode<FixedArray> elements =
        CAST(AllocateFixedArray(PACKED_ELEMENTS, length));
    // Don't allocate anything while {string_data} is live!
    TNode<RawPtrT> string_data =
        to_direct.PointerToData(&fill_thehole_and_call_runtime);
    TNode<IntPtrT> string_data_offset = to_direct.offset();
    TNode<FixedArray> cache = SingleCharacterStringTableConstant();

    BuildFastLoop<IntPtrT>(
        IntPtrConstant(0), length,
        [&](TNode<IntPtrT> index) {
          // TODO(jkummerow): Implement a CSA version of
          // DisallowGarbageCollection and use that to guard
          // ToDirectStringAssembler.PointerToData().
          CSA_DCHECK(this, WordEqual(to_direct.PointerToData(&call_runtime),
                                     string_data));
          TNode<Int32T> char_code =
              UncheckedCast<Int32T>(Load(MachineType::Uint8(), string_data,
                                         IntPtrAdd(index, string_data_offset)));
          TNode<UintPtrT> code_index = ChangeUint32ToWord(char_code);
          TNode<Object> entry = LoadFixedArrayElement(cache, code_index);

          CSA_DCHECK(this, Word32BinaryNot(IsUndefined(entry)));

          StoreFixedArrayElement(elements, index, entry);
        },
        1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

    TNode<Map> array_map = LoadJSArrayElementsMap(PACKED_ELEMENTS, context);
    result_array = AllocateJSArray(array_map, elements, length_smi);
    Goto(&done);

    BIND(&fill_thehole_and_call_runtime);
    {
      FillFixedArrayWithValue(PACKED_ELEMENTS, elements, IntPtrConstant(0),
                              length, RootIndex::kTheHoleValue);
      Goto(&call_runtime);
    }
  }

  BIND(&call_runtime);
  {
    result_array = CAST(CallRuntime(Runtime::kStringToArray, context,
                                    subject_string, limit_number));
    Goto(&done);
  }

  BIND(&done);
  return result_array.value();
}

// ES6 section 21.1.3.19 String.prototype.split ( separator, limit )
TF_BUILTIN(StringPrototypeSplit, StringBuiltinsAssembler) {
  const int kSeparatorArg = 0;
  const int kLimitArg = 1;

  const TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  const TNode<Object> separator = args.GetOptionalArgumentValue(kSeparatorArg);
  const TNode<Object> limit = args.GetOptionalArgumentValue(kLimitArg);
  auto context = Parameter<NativeContext>(Descriptor::kContext);

  TNode<Smi> smi_zero = SmiConstant(0);

  RequireObjectCoercible(context, receiver, "String.prototype.split");

  // Redirect to splitter method if {separator[@@split]} is not undefined.

  MaybeCallFunctionAtSymbol(
      context, separator, receiver, isolate()->factory()->split_symbol(),
      DescriptorIndexNameValue{JSRegExp::kSymbolSplitFunctionDescriptorIndex,
                               RootIndex::ksplit_symbol,
                               Context::REGEXP_SPLIT_FUNCTION_INDEX},
      [&]() {
        args.PopAndReturn(CallBuiltin(Builtin::kRegExpSplit, context, separator,
                                      receiver, limit));
      },
      [&](TNode<Object> fn) {
        args.PopAndReturn(Call(context, fn, separator, receiver, limit));
      });

  // String and integer conversions.

  TNode<String> subject_string = ToString_Inline(context, receiver);
  TNode<Number> limit_number = Select<Number>(
      IsUndefined(limit), [=, this] { return NumberConstant(kMaxUInt32); },
      [=, this] { return ToUint32(context, limit); });
  const TNode<String> separator_string = ToString_Inline(context, separator);

  Label return_empty_array(this);

  // Shortcut for {limit} == 0.
  GotoIf(TaggedEqual(limit_number, smi_zero), &return_empty_array);

  // ECMA-262 says that if {separator} is undefined, the result should
  // be an array of size 1 containing the entire string.
  {
    Label next(this);
    GotoIfNot(IsUndefined(separator), &next);

    const ElementsKind kind = PACKED_ELEMENTS;
    const TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);

    TNode<Smi> length = SmiConstant(1);
    TNode<IntPtrT> capacity = IntPtrConstant(1);
    TNode<JSArray> result = AllocateJSArray(kind, array_map, capacity, length);

    TNode<FixedArray> fixed_array = CAST(LoadElements(result));
    StoreFixedArrayElement(fixed_array, 0, subject_string);

    args.PopAndReturn(result);

    BIND(&next);
  }

  // If the separator string is empty then return the elements in the subject.
  {
    Label next(this);
    GotoIfNot(SmiEqual(LoadStringLengthAsSmi(separator_string), smi_zero),
              &next);

    TNode<Smi> subject_length = LoadStringLengthAsSmi(subject_string);
    GotoIf(SmiEqual(subject_length, smi_zero), &return_empty_array);

    args.PopAndReturn(
        StringToArray(context, subject_string, subject_length, limit_number));

    BIND(&next);
  }

  const TNode<Object> result =
      CallRuntime(Runtime::kStringSplit, context, subject_string,
                  separator_string, limit_number);
  args.PopAndReturn(result);

  BIND(&return_empty_array);
  {
    const ElementsKind kind = PACKED_ELEMENTS;
    const TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);

    TNode<Smi> length = smi_zero;
    TNode<IntPtrT> capacity = IntPtrConstant(0);
    TNode<JSArray> result_array =
        AllocateJSArray(kind, array_map, capacity, length);

    args.PopAndReturn(result_array);
  }
}

TF_BUILTIN(StringSubstring, StringBuiltinsAssembler) {
  auto string = Parameter<String>(Descriptor::kString);
  auto from = UncheckedParameter<IntPtrT>(Desc
"""


```