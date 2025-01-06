Response: The user wants a summary of the C++ source code file `v8/src/builtins/builtins-intl-gen.cc`. The summary should focus on the file's functionality. Additionally, if the code relates to JavaScript features, a JavaScript example illustrating this connection is requested.

**Plan:**

1. **Identify the main purpose:** Analyze the file name and included headers to understand the high-level goal. The name suggests it handles built-in internationalization functionalities.
2. **Examine key classes and functions:** Look for prominent classes and functions, paying attention to their names and parameters.
3. **Focus on JavaScript integration:** Identify functions prefixed with `TF_BUILTIN`, as these are the entry points for JavaScript calls.
4. **Summarize functionality:** Describe the core functionalities implemented in the file, based on the analysis of classes and functions.
5. **Find JavaScript examples:**  Based on the identified `TF_BUILTIN` functions, construct JavaScript examples that would invoke these functionalities. Specifically, look for examples related to string case conversion and list formatting.
这个C++源代码文件 `v8/src/builtins/builtins-intl-gen.cc` 是 V8 JavaScript 引擎的一部分，**负责实现 ECMAScript 国际化 API (ECMA-402) 中 `Intl` 对象的一些内置功能**。它使用了 CodeStubAssembler (CSA) 框架，这是一种在 V8 中高效生成机器码的方式。

**主要功能归纳:**

1. **字符串大小写转换 (toLocaleLowerCase, toLowerCase):**
   - 实现了 `String.prototype.toLocaleLowerCase()` 和 `String.prototype.toLowerCase()` 方法的国际化版本。
   - 针对单字节字符串进行了优化，对于短字符串直接在 CSA 中进行转换，利用预先计算的查找表。
   - 对于较长的单字节字符串，会调用 C++ 函数 `intl_convert_one_byte_to_lower()` 进行转换。
   - 对于其他情况（例如，非单字节字符串或需要更复杂的区域设置处理），会回退到运行时 (Runtime) 调用。

2. **列表格式化 (ListFormat):**
   - 实现了 `Intl.ListFormat.prototype.format()` 和 `Intl.ListFormat.prototype.formatToParts()` 方法。
   - 这些方法用于将一个字符串数组格式化成符合特定语言习惯的列表字符串。
   - 内部会调用运行时函数 `kFormatList` 和 `kFormatListToParts` 来完成实际的格式化操作。
   - 提供了 `ListFormatCommon` 函数来处理 `format` 和 `formatToParts` 方法的通用逻辑，包括参数校验和调用运行时函数。

**与 JavaScript 的关系及示例:**

这个文件直接实现了 JavaScript 的 `Intl` 对象上的一些方法。以下是一些 JavaScript 示例，展示了这些 C++ 代码是如何被调用的：

**1. 字符串大小写转换:**

```javascript
// String.prototype.toLocaleLowerCase()
const str1 = 'ALPHABET';
console.log(str1.toLocaleLowerCase()); // 输出 "alphabet"

const str2 = 'İstanbul';
console.log(str2.toLocaleLowerCase('tr')); // 输出 "istanbul" (土耳其语的特殊处理)

// String.prototype.toLowerCase()
const str3 = 'MixedCase';
console.log(str3.toLowerCase()); // 输出 "mixedcase"
```

当你在 JavaScript 中调用 `toLocaleLowerCase()` 或 `toLowerCase()` 方法时，V8 引擎最终会执行 `builtins-intl-gen.cc` 文件中对应的 `TF_BUILTIN` 函数 (`StringPrototypeToLocaleLowerCase` 或 `StringPrototypeToLowerCaseIntl`)。这些 C++ 函数会根据字符串的类型和区域设置等信息，选择合适的转换策略，有些情况下会直接在 C++ 代码中完成，有些情况下会调用更底层的运行时函数。

**2. 列表格式化:**

```javascript
// Intl.ListFormat
const list = ['Apple', 'Banana', 'Orange'];

const formatter1 = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' });
console.log(formatter1.format(list)); // 输出 "Apple, Banana, and Orange"

const formatter2 = new Intl.ListFormat('de', { style: 'short', type: 'disjunction' });
console.log(formatter2.format(list)); // 输出 "Apple, Banana oder Orange"

const formatter3 = new Intl.ListFormat('en', { style: 'unit', type: 'unit' });
console.log(formatter3.format(list)); // 输出 "Apple, Banana, Orange"

const formatter4 = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' });
console.log(formatter4.formatToParts(list));
// 输出:
// [
//   { type: 'element', value: 'Apple' },
//   { type: 'literal', value: ', ' },
//   { type: 'element', value: 'Banana' },
//   { type: 'literal', value: ', and ' },
//   { type: 'element', value: 'Orange' }
// ]
```

当你创建 `Intl.ListFormat` 实例并调用其 `format()` 或 `formatToParts()` 方法时，`builtins-intl-gen.cc` 文件中的 `TF_BUILTIN` 函数 (`ListFormatPrototypeFormat` 或 `ListFormatPrototypeFormatToParts`) 会被调用。这些 C++ 代码会获取 `Intl.ListFormat` 实例和要格式化的列表，然后调用运行时函数来执行实际的列表格式化，并返回格式化后的字符串或包含分段信息的数组。

总而言之，`v8/src/builtins/builtins-intl-gen.cc` 是 V8 引擎中实现国际化相关 JavaScript 内置功能的重要组成部分，它通过高效的 C++ 代码和 CSA 框架，为 JavaScript 开发者提供了强大的国际化支持。

Prompt: 
```
这是目录为v8/src/builtins/builtins-intl-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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