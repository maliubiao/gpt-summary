Response:
Let's break down the thought process to analyze the provided C++ code snippet for `v8/src/builtins/builtins-intl-gen.cc`.

1. **Initial Scan and Understanding the Context:**

   - The file name `builtins-intl-gen.cc` immediately suggests it's related to the implementation of built-in JavaScript functionalities, specifically those related to internationalization (`intl`). The `.cc` extension confirms it's C++ code.
   - The `#ifndef V8_INTL_SUPPORT` block indicates that this code is only compiled if internationalization support is enabled in the V8 build. This is a crucial piece of information.
   - The `#include` directives tell us that this code interacts with other parts of V8, particularly:
     - Iterator built-ins (`builtins-iterator-gen.h`)
     - Utility built-ins (`builtins-utils-gen.h`)
     - Code generation (`code-stub-assembler-inl.h`, `define-code-stub-assembler-macros.inc`, `undef-code-stub-assembler-macros.inc`) - this suggests a lower-level implementation, likely involving the Torque compiler (though the file extension doesn't end in `.tq`).
     - Internal object representations (`js-list-format-inl.h`, `js-list-format.h`, `objects-inl.h`, `objects.h`).

2. **Identifying the Core Class: `IntlBuiltinsAssembler`:**

   - The code defines a class `IntlBuiltinsAssembler` that inherits from `CodeStubAssembler`. This is a key class in V8's implementation of built-in functions. `CodeStubAssembler` provides a way to generate machine code directly within the V8 engine.

3. **Analyzing Key Methods and Functions:**

   - **`ListFormatCommon`:** The name and parameters (`context`, `argc`, `format_func_id`, `method_name`) strongly suggest this is a common implementation for the `Intl.ListFormat` methods (like `format` and `formatToParts`). It takes a receiver, checks if it's a `JSListFormat` object, retrieves a list of strings, and then calls a runtime function to do the actual formatting.

   - **`AllocateEmptyJSArray`:** This function does exactly what its name suggests: allocates an empty JavaScript array.

   - **String Manipulation Functions (`PointerToSeqStringData`, `GetChar`, `JumpIfStartsWithIgnoreCase`, `IsNonAlpha`):** These functions indicate that the code deals with string manipulation at a relatively low level, working with the internal representation of strings (likely one-byte strings based on the naming). `JumpIfStartsWithIgnoreCase` suggests optimization based on common locale prefixes.

   - **`ToLowerCaseImpl`:** This is a more complex function. It handles the core logic for converting strings to lowercase, potentially with locale awareness. The presence of "fast paths" (checking for simple cases, using lookup tables for short strings) and a fallback to a C function (`ConvertOneByteToLower`) and runtime calls (`kStringToLocaleLowerCase`, `kStringToLowerCaseIntl`) suggests an optimized implementation.

4. **Identifying the Torque Connection (and the "trick" in the question):**

   - The question specifically asks about the `.tq` extension. While this file *doesn't* have that extension, the inclusion of `define-code-stub-assembler-macros.inc` strongly hints at Torque's involvement. Torque is a language used within V8 to generate code for built-in functions. The macros provided by this include file are used within Torque-generated code. So, while the `.cc` file itself isn't a Torque file, it's likely that *other* `.tq` files generate code that ends up calling functions within this `.cc` file.

5. **Connecting to JavaScript Functionality:**

   - The names of the `TF_BUILTIN` functions (`StringToLowerCaseIntl`, `StringPrototypeToLowerCaseIntl`, `StringPrototypeToLocaleLowerCase`, `ListFormatPrototypeFormat`, `ListFormatPrototypeFormatToParts`) directly map to JavaScript methods. This confirms the file's role in implementing these built-in functionalities.

6. **Inferring Code Logic and Examples:**

   - Based on the function names and the `ListFormatCommon` logic, it's clear that the `format` and `formatToParts` methods of `Intl.ListFormat` are being implemented.
   - The `ToLowerCaseImpl` function, with its handling of locales, clearly relates to `String.prototype.toLowerCase()` and `String.prototype.toLocaleLowerCase()`.

7. **Considering Potential Programming Errors:**

   - The checks in `ListFormatCommon` (for the receiver type and the initialized internal slot) suggest that a common error would be calling `format` or `formatToParts` on a non-`Intl.ListFormat` object.
   - The complexity of `ToLowerCaseImpl` and the fast paths suggest that locale handling and string type are important considerations, and incorrect locale inputs or unexpected string types might lead to slower paths or unexpected results.

8. **Structuring the Answer:**

   - Start with a high-level summary of the file's purpose.
   - List the key functionalities, breaking them down by the major functions.
   - Address the Torque question, explaining the likely indirect connection.
   - Provide JavaScript examples for the related functionalities.
   - Give examples of potential programming errors based on the code's checks and logic.
   - If applicable, illustrate code logic with input/output examples (though the C++ code itself is more about implementation than high-level logic).

This step-by-step approach, combining code analysis with knowledge of V8's architecture and JavaScript's internationalization features, allows for a comprehensive understanding of the given code snippet.
好的，让我们来分析一下 `v8/src/builtins/builtins-intl-gen.cc` 文件的功能。

**主要功能：**

这个 C++ 文件定义了 V8 JavaScript 引擎中与国际化 (Intl) 相关的内置函数 (built-ins)。它使用了 V8 的 CodeStubAssembler (CSA) 框架来高效地生成机器码，从而实现这些内置功能。  具体来说，从代码中可以看出，它主要负责以下几个方面的功能：

1. **字符串大小写转换 (toLowerCase/toLocaleLowerCase):**
   - 提供了 `StringToLowerCaseIntl` 和 `StringPrototypeToLowerCaseIntl` 这两个内置函数，用于实现字符串到小写的转换。
   - 提供了 `StringPrototypeToLocaleLowerCase` 内置函数，用于实现根据特定区域设置将字符串转换为小写。
   - `ToLowerCaseImpl` 函数是实现这些功能的底层逻辑，它会尝试使用优化的快速路径（例如，对于短的 ASCII 字符串，直接查表转换），并在必要时调用 C++ 的国际化库或者 JavaScript 运行时函数。

2. **列表格式化 (ListFormat):**
   - 提供了 `ListFormatPrototypeFormat` 和 `ListFormatPrototypeFormatToParts` 这两个内置函数，对应于 `Intl.ListFormat.prototype.format()` 和 `Intl.ListFormat.prototype.formatToParts()` 方法。
   - `ListFormatCommon` 函数是这两个内置函数共享的通用逻辑，负责检查接收者是否为 `Intl.ListFormat` 实例，并将输入的列表转换为字符串列表，最终调用运行时函数执行格式化。

**关于 .tq 扩展名:**

正如你所指出的，如果 `v8/src/builtins/builtins-intl-gen.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内置函数的领域特定语言，它会被编译成 C++ 代码。

**当前文件的情况：**

由于该文件以 `.cc` 结尾，它是一个纯粹的 C++ 文件，直接使用 CodeStubAssembler 来生成代码。尽管如此，它所实现的功能很可能与由 Torque 定义的其他 Intl 相关 built-ins 协同工作。

**与 JavaScript 功能的关系 (附带 JavaScript 例子):**

该文件中的 C++ 代码直接实现了 JavaScript 的 `String.prototype.toLowerCase()`, `String.prototype.toLocaleLowerCase()`, `Intl.ListFormat.prototype.format()`, 和 `Intl.ListFormat.prototype.formatToParts()` 方法。

**JavaScript 例子：**

```javascript
// 字符串大小写转换
const str = "HeLlO wOrLd";
console.log(str.toLowerCase());       // 输出: hello world
console.log(str.toLocaleLowerCase()); // 输出: hello world (通常情况下与 toLowerCase 结果相同，但会考虑语言环境)
console.log(str.toLocaleLowerCase('tr')); // 在土耳其语环境下，I 会变成 ı

// 列表格式化
const list = ["apple", "banana", "orange"];
const formatter = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' });
console.log(formatter.format(list)); // 输出: apple, banana, and orange

const partsFormatter = new Intl.ListFormat('en', { style: 'short', type: 'disjunction' });
console.log(partsFormatter.formatToParts(list));
// 输出:
// [
//   { type: 'element', value: 'apple' },
//   { type: 'literal', value: ' or ' },
//   { type: 'element', value: 'banana' },
//   { type: 'literal', value: ' or ' },
//   { type: 'element', value: 'orange' }
// ]
```

**代码逻辑推理 (假设输入与输出):**

**假设 `ToLowerCaseImpl` 函数接收一个字符串 "AbCdEf" 并执行不区分区域设置的小写转换 (`ToLowerCaseKind::kToLowerCase`)。**

* **输入:**
    * `string`: "AbCdEf"
    * `maybe_locales`:  (在这种情况下会被忽略)
    * `context`:  当前的 JavaScript 执行上下文
    * `kind`: `ToLowerCaseKind::kToLowerCase`
* **输出:**
    * 返回一个新的字符串 "abcdef"

**代码逻辑简述:**

1. `ToLowerCaseImpl` 首先会尝试将字符串解包成直接字符串表示。
2. 由于 `kind` 是 `kToLowerCase`，会跳过区域设置相关的检查。
3. 检查字符串是否为空，如果为空则直接返回。
4. 检查字符串是否为单字节字符串。
5. 对于较短的字符串（长度小于 `kMaxShortStringLength`），它会使用一个查找表进行快速转换。每个字符都会通过查找表转换为小写形式。
6. 如果字符串较长，则会调用 C++ 的 `intl_convert_one_byte_to_lower()` 函数进行转换。
7. 最后，返回转换后的字符串。

**假设 `ListFormatCommon` 函数接收一个 `Intl.ListFormat` 实例和一个包含字符串的数组 `["one", "two", "three"]`，并调用 `Runtime::kFormatList`。**

* **输入:**
    * `context`: 当前的 JavaScript 执行上下文
    * `argc`: 参数数量
    * `format_func_id`: `Runtime::kFormatList`
    * `method_name`: "Intl.ListFormat.prototype.format"
    * `receiver`: 一个 `Intl.ListFormat` 实例
    * `list` (作为参数传入): `["one", "two", "three"]`
* **输出:**
    * 取决于 `Intl.ListFormat` 实例的配置（例如，`locale`, `type`, `style`），输出可能类似于 "one, two, and three"。

**代码逻辑简述:**

1. `ListFormatCommon` 检查 `receiver` 是否为 `JS_LIST_FORMAT_TYPE` 的实例。
2. 调用 `Builtin::kStringListFromIterable` 将输入的 `list` 转换为 V8 内部的字符串列表表示。
3. 调用运行时函数 `Runtime::kFormatList`，传入 `Intl.ListFormat` 实例和字符串列表，执行实际的格式化操作。
4. 返回格式化后的字符串。

**涉及用户常见的编程错误:**

1. **在非字符串上调用字符串方法:**
   ```javascript
   let num = 123;
   // 错误：number 没有 toLowerCase 方法
   // num.toLowerCase();

   // 正确的做法是先转换为字符串
   num.toString().toLowerCase();
   ```

2. **在非 `Intl.ListFormat` 对象上调用 `format` 或 `formatToParts`:**
   ```javascript
   const notAListFormatter = {};
   const myList = ["a", "b", "c"];

   // 错误：notAListFormatter 没有内部的 [[InitializedListFormat]] 插槽
   // notAListFormatter.format(myList);

   const formatter = new Intl.ListFormat('en');
   formatter.format(myList); // 正确
   ```

3. **向 `toLocaleLowerCase` 传递无效的 locale 参数:**
   ```javascript
   const text = "HELLO";
   // 可能会导致错误或使用默认 locale
   text.toLocaleLowerCase("invalid-locale");

   text.toLocaleLowerCase("en-US"); // 正确
   ```

4. **假设 `toLowerCase` 和 `toLocaleLowerCase` 总是产生相同的结果:** 虽然通常情况下是这样，但在某些语言环境中（例如土耳其语对 'I' 的处理），它们的结果可能不同。

总之，`v8/src/builtins/builtins-intl-gen.cc` 是 V8 引擎中实现关键国际化功能的底层 C++ 代码，它通过高效的代码生成和与 V8 运行时的交互，使得 JavaScript 能够处理各种与语言和文化相关的操作。

Prompt: 
```
这是目录为v8/src/builtins/builtins-intl-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-intl-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/builtins/builtins-iterator-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/objects/js-list-format-inl.h"
#include "src/objects/js-list-format.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class IntlBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit IntlBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  void ListFormatCommon(TNode<Context> context, TNode<Int32T> argc,
                        Runtime::FunctionId format_func_id,
                        const char* method_name);

  TNode<JSArray> AllocateEmptyJSArray(TNode<Context> context);

  TNode<IntPtrT> PointerToSeqStringData(TNode<String> seq_string) {
    CSA_DCHECK(this,
               IsSequentialStringInstanceType(LoadInstanceType(seq_string)));
    static_assert(OFFSET_OF_DATA_START(SeqOneByteString) ==
                  OFFSET_OF_DATA_START(SeqTwoByteString));
    return IntPtrAdd(BitcastTaggedToWord(seq_string),
                     IntPtrConstant(OFFSET_OF_DATA_START(SeqOneByteString) -
                                    kHeapObjectTag));
  }

  TNode<Uint8T> GetChar(TNode<SeqOneByteString> seq_string, int index) {
    size_t effective_offset = OFFSET_OF_DATA_START(SeqOneByteString) +
                              sizeof(SeqOneByteString::Char) * index -
                              kHeapObjectTag;
    return Load<Uint8T>(seq_string, IntPtrConstant(effective_offset));
  }

  // Jumps to {target} if the first two characters of {seq_string} equal
  // {pattern} ignoring case.
  void JumpIfStartsWithIgnoreCase(TNode<SeqOneByteString> seq_string,
                                  const char* pattern, Label* target) {
    size_t effective_offset =
        OFFSET_OF_DATA_START(SeqOneByteString) - kHeapObjectTag;
    TNode<Uint16T> raw =
        Load<Uint16T>(seq_string, IntPtrConstant(effective_offset));
    DCHECK_EQ(strlen(pattern), 2);
#if V8_TARGET_BIG_ENDIAN
    int raw_pattern = (pattern[0] << 8) + pattern[1];
#else
    int raw_pattern = pattern[0] + (pattern[1] << 8);
#endif
    GotoIf(Word32Equal(Word32Or(raw, Int32Constant(0x2020)),
                       Int32Constant(raw_pattern)),
           target);
  }

  TNode<BoolT> IsNonAlpha(TNode<Uint8T> character) {
    return Uint32GreaterThan(
        Int32Sub(Word32Or(character, Int32Constant(0x20)), Int32Constant('a')),
        Int32Constant('z' - 'a'));
  }

  enum class ToLowerCaseKind {
    kToLowerCase,
    kToLocaleLowerCase,
  };
  void ToLowerCaseImpl(TNode<String> string, TNode<Object> maybe_locales,
                       TNode<Context> context, ToLowerCaseKind kind,
                       std::function<void(TNode<Object>)> ReturnFct);
};

TF_BUILTIN(StringToLowerCaseIntl, IntlBuiltinsAssembler) {
  const auto string = Parameter<String>(Descriptor::kString);
  ToLowerCaseImpl(string, TNode<Object>() /*maybe_locales*/, TNode<Context>(),
                  ToLowerCaseKind::kToLowerCase,
                  [this](TNode<Object> ret) { Return(ret); });
}

TF_BUILTIN(StringPrototypeToLowerCaseIntl, IntlBuiltinsAssembler) {
  auto maybe_string = Parameter<Object>(Descriptor::kReceiver);
  auto context = Parameter<Context>(Descriptor::kContext);

  TNode<String> string =
      ToThisString(context, maybe_string, "String.prototype.toLowerCase");

  Return(CallBuiltin(Builtin::kStringToLowerCaseIntl, context, string));
}

TF_BUILTIN(StringPrototypeToLocaleLowerCase, IntlBuiltinsAssembler) {
  TNode<Int32T> argc =
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  CodeStubArguments args(this, argc);
  TNode<Object> maybe_string = args.GetReceiver();
  TNode<Context> context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> maybe_locales = args.GetOptionalArgumentValue(0);
  TNode<String> string =
      ToThisString(context, maybe_string, "String.prototype.toLocaleLowerCase");
  ToLowerCaseImpl(string, maybe_locales, context,
                  ToLowerCaseKind::kToLocaleLowerCase,
                  [&args](TNode<Object> ret) { args.PopAndReturn(ret); });
}

void IntlBuiltinsAssembler::ToLowerCaseImpl(
    TNode<String> string, TNode<Object> maybe_locales, TNode<Context> context,
    ToLowerCaseKind kind, std::function<void(TNode<Object>)> ReturnFct) {
  Label call_c(this), return_string(this), runtime(this, Label::kDeferred);

  // Unpack strings if possible, and bail to runtime unless we get a one-byte
  // flat string.
  ToDirectStringAssembler to_direct(
      state(), string, ToDirectStringAssembler::kDontUnpackSlicedStrings);
  to_direct.TryToDirect(&runtime);

  if (kind == ToLowerCaseKind::kToLocaleLowerCase) {
    Label fast(this), check_locale(this);
    // Check for fast locales.
    GotoIf(IsUndefined(maybe_locales), &fast);
    // Passing a Smi as locales requires performing a ToObject conversion
    // followed by reading the length property and the "indexed" properties of
    // it until a valid locale is found.
    GotoIf(TaggedIsSmi(maybe_locales), &runtime);
    GotoIfNot(IsString(CAST(maybe_locales)), &runtime);
    GotoIfNot(IsSeqOneByteString(CAST(maybe_locales)), &runtime);
    TNode<SeqOneByteString> locale = CAST(maybe_locales);
    TNode<Uint32T> locale_length = LoadStringLengthAsWord32(locale);
    GotoIf(Int32LessThan(locale_length, Int32Constant(2)), &runtime);
    GotoIf(IsNonAlpha(GetChar(locale, 0)), &runtime);
    GotoIf(IsNonAlpha(GetChar(locale, 1)), &runtime);
    GotoIf(Word32Equal(locale_length, Int32Constant(2)), &check_locale);
    GotoIf(Word32NotEqual(locale_length, Int32Constant(5)), &runtime);
    GotoIf(Word32NotEqual(GetChar(locale, 2), Int32Constant('-')), &runtime);
    GotoIf(IsNonAlpha(GetChar(locale, 3)), &runtime);
    GotoIf(IsNonAlpha(GetChar(locale, 4)), &runtime);
    Goto(&check_locale);

    Bind(&check_locale);
    JumpIfStartsWithIgnoreCase(locale, "az", &runtime);
    JumpIfStartsWithIgnoreCase(locale, "el", &runtime);
    JumpIfStartsWithIgnoreCase(locale, "lt", &runtime);
    JumpIfStartsWithIgnoreCase(locale, "tr", &runtime);
    Goto(&fast);

    Bind(&fast);
  }

  // Early exit on empty string.
  const TNode<Uint32T> length = LoadStringLengthAsWord32(string);
  GotoIf(Word32Equal(length, Uint32Constant(0)), &return_string);

  const TNode<BoolT> is_one_byte = to_direct.IsOneByte();
  GotoIfNot(is_one_byte, &runtime);

  // For short strings, do the conversion in CSA through the lookup table.

  const TNode<String> dst = AllocateSeqOneByteString(length);

  const int kMaxShortStringLength = 24;  // Determined empirically.
  GotoIf(Uint32GreaterThan(length, Uint32Constant(kMaxShortStringLength)),
         &call_c);

  {
    const TNode<IntPtrT> dst_ptr = PointerToSeqStringData(dst);
    TVARIABLE(IntPtrT, var_cursor, IntPtrConstant(0));

    const TNode<IntPtrT> start_address =
        ReinterpretCast<IntPtrT>(to_direct.PointerToData(&call_c));
    const TNode<IntPtrT> end_address =
        Signed(IntPtrAdd(start_address, ChangeUint32ToWord(length)));

    const TNode<ExternalReference> to_lower_table_addr =
        ExternalConstant(ExternalReference::intl_to_latin1_lower_table());

    TVARIABLE(Word32T, var_did_change, Int32Constant(0));

    VariableList push_vars({&var_cursor, &var_did_change}, zone());
    BuildFastLoop<IntPtrT>(
        push_vars, start_address, end_address,
        [&](TNode<IntPtrT> current) {
          TNode<Uint8T> c = Load<Uint8T>(current);
          TNode<Uint8T> lower =
              Load<Uint8T>(to_lower_table_addr, ChangeInt32ToIntPtr(c));
          StoreNoWriteBarrier(MachineRepresentation::kWord8, dst_ptr,
                              var_cursor.value(), lower);

          var_did_change =
              Word32Or(Word32NotEqual(c, lower), var_did_change.value());

          Increment(&var_cursor);
        },
        kCharSize, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

    // Return the original string if it remained unchanged in order to preserve
    // e.g. internalization and private symbols (such as the preserved object
    // hash) on the source string.
    GotoIfNot(var_did_change.value(), &return_string);

    ReturnFct(dst);
  }

  // Call into C for case conversion. The signature is:
  // String ConvertOneByteToLower(String src, String dst);
  BIND(&call_c);
  {
    const TNode<String> src = to_direct.string();

    const TNode<ExternalReference> function_addr =
        ExternalConstant(ExternalReference::intl_convert_one_byte_to_lower());

    MachineType type_tagged = MachineType::AnyTagged();

    const TNode<String> result = CAST(CallCFunction(
        function_addr, type_tagged, std::make_pair(type_tagged, src),
        std::make_pair(type_tagged, dst)));

    ReturnFct(result);
  }

  BIND(&return_string);
  ReturnFct(string);

  BIND(&runtime);
  if (kind == ToLowerCaseKind::kToLocaleLowerCase) {
    ReturnFct(CallRuntime(Runtime::kStringToLocaleLowerCase, context, string,
                          maybe_locales));
  } else {
    DCHECK_EQ(kind, ToLowerCaseKind::kToLowerCase);
    ReturnFct(CallRuntime(Runtime::kStringToLowerCaseIntl, NoContextConstant(),
                          string));
  }
}

void IntlBuiltinsAssembler::ListFormatCommon(TNode<Context> context,
                                             TNode<Int32T> argc,
                                             Runtime::FunctionId format_func_id,
                                             const char* method_name) {
  CodeStubArguments args(this, argc);

  // Label has_list(this);
  // 1. Let lf be this value.
  // 2. If Type(lf) is not Object, throw a TypeError exception.
  TNode<Object> receiver = args.GetReceiver();

  // 3. If lf does not have an [[InitializedListFormat]] internal slot, throw a
  // TypeError exception.
  ThrowIfNotInstanceType(context, receiver, JS_LIST_FORMAT_TYPE, method_name);
  TNode<JSListFormat> list_format = CAST(receiver);

  TNode<Object> list = args.GetOptionalArgumentValue(0);
  {
    // 4. Let stringList be ? StringListFromIterable(list).
    TNode<Object> string_list =
        CallBuiltin(Builtin::kStringListFromIterable, context, list);

    // 6. Return ? FormatList(lf, stringList).
    args.PopAndReturn(
        CallRuntime(format_func_id, context, list_format, string_list));
  }
}

TNode<JSArray> IntlBuiltinsAssembler::AllocateEmptyJSArray(
    TNode<Context> context) {
  return CodeStubAssembler::AllocateJSArray(
      PACKED_ELEMENTS,
      LoadJSArrayElementsMap(PACKED_ELEMENTS, LoadNativeContext(context)),
      IntPtrConstant(0), SmiConstant(0));
}

TF_BUILTIN(ListFormatPrototypeFormat, IntlBuiltinsAssembler) {
  ListFormatCommon(
      Parameter<Context>(Descriptor::kContext),
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount),
      Runtime::kFormatList, "Intl.ListFormat.prototype.format");
}

TF_BUILTIN(ListFormatPrototypeFormatToParts, IntlBuiltinsAssembler) {
  ListFormatCommon(
      Parameter<Context>(Descriptor::kContext),
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount),
      Runtime::kFormatListToParts, "Intl.ListFormat.prototype.formatToParts");
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```