Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the `string.tq` file, relate it to JavaScript, provide examples, and highlight potential user errors.

2. **Initial Scan and Keywords:**  Start by quickly scanning the file for keywords and structures. Keywords like `class`, `extern`, `macro`, `builtin`, `enum`, `struct`, `extends`, `bitfield`, `const`, `type`, and comments like "Corresponds to..." are crucial. These give hints about the file's purpose: defining data structures and operations related to strings within V8.

3. **Identify Core Data Structures:** The `class String` and its subclasses are central. Notice the inheritance: `String` is abstract, and various concrete string types inherit from it: `ConsString`, `ExternalString`, `InternalizedString`, `SeqString`, `SlicedString`, and `ThinString`. Each likely represents a different way a string can be stored in memory. The `StringInstanceType` bitfield provides metadata about these strings.

4. **Infer Purpose of Each Structure:** Based on the names and fields, try to deduce the purpose of each string type:
    * `SeqString`: Seems like a standard, sequential string. The `SeqOneByteString` and `SeqTwoByteString` variations suggest handling different character encodings (ASCII/Latin-1 vs. UTF-16).
    * `ConsString`: Likely represents concatenated strings, storing references to the parts. The `first` and `second` fields confirm this.
    * `ExternalString`: Holds data outside of V8's heap, referenced by pointers. This is often used for strings from external sources.
    * `SlicedString`: Represents a substring of another string, storing a reference to the parent and an offset. This avoids copying the string data.
    * `ThinString`: An indirection, pointing to the "actual" string. This might be used for optimizations or special cases.
    * `InternalizedString`:  Likely strings that are stored in a canonical form for faster comparison.
    * `StringInstanceType`: Holds flags about the string's representation, encoding, and whether it's internalized, etc.

5. **Analyze Macros and Builtins:** Macros and builtins define the operations on these string structures.
    * `Allocate...String`: These macros are for creating new string objects of different types. The `<Iterator: type>` suggests they can be initialized with data.
    * `Flatten`: This macro seems to convert composite string types (like `ConsString` and `ThinString`) into a basic `SeqString`. This is a common operation when the actual string content is needed.
    * `StringToSlice`: This is interesting! It aims to get a direct pointer to the string data, handling different string representations. The `labels OneByte(...)`, `TwoByte(...)` indicate branching based on encoding.
    * `TwoStringsToSlices`: This macro takes two strings and a function, obtaining slices for both before calling the function. This pattern suggests operations comparing or processing two strings.
    * `AbstractStringIndexOf`, `StringIndexOf`: These are clearly related to finding the index of a substring within a string, similar to JavaScript's `indexOf()`. The multiple definitions of `AbstractStringIndexOf` likely handle different string encodings.

6. **Connect to JavaScript:**  Think about how these internal string representations and operations relate to JavaScript's string behavior.
    * String concatenation (`+`) could create `ConsString`s internally.
    * `substring()` or `slice()` could result in `SlicedString`s.
    * Strings loaded from external sources might be `ExternalString`s.
    * The concept of string interning in JavaScript is related to `InternalizedString`.
    * The `indexOf()` method directly corresponds to the `StringIndexOf` builtin.

7. **Illustrate with JavaScript Examples:** Provide simple JavaScript code snippets that demonstrate the *observable* behavior related to the internal mechanisms. Focus on functionality, not direct internal representation (which isn't exposed in JavaScript).

8. **Infer Logic and Provide Examples (Hypothetical Input/Output):**  For key macros like `Flatten` and `StringToSlice`, create hypothetical scenarios to demonstrate their behavior. For `Flatten`, show how a `ConsString` becomes a `SeqString`. For `StringToSlice`, show how different string types resolve to a memory slice.

9. **Identify Potential Programming Errors:**  Think about common mistakes JavaScript developers make with strings that might relate to these internal structures:
    * Excessive string concatenation in loops can lead to many `ConsString`s, potentially impacting performance if not flattened.
    *  Assuming string comparison is always fast – internal representations might matter.
    * Incorrectly handling character encodings (though V8 generally manages this well).
    * Performance implications of frequent substring operations on large strings (leading to many `SlicedString`s).

10. **Structure the Output:** Organize the analysis logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the key data structures and their roles.
    * Explain the functionality of important macros and builtins.
    * Provide JavaScript examples to connect to user-level behavior.
    * Illustrate code logic with hypothetical inputs and outputs.
    * Highlight common programming errors.

11. **Refine and Review:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need further explanation. For example, initially, I might not have explicitly connected `InternalizedString` to JavaScript string interning, but upon review, I'd add that connection. Similarly, clarifying the role of `StringInstanceType` is important.

This iterative process of scanning, deducing, connecting, illustrating, and refining helps to thoroughly understand and summarize the functionality of the given Torque source code.
这个v8 Torque文件 `string.tq` 定义了 V8 引擎中字符串对象的内部表示和相关操作。它主要关注字符串的内存布局、不同类型的字符串以及用于操作这些字符串的底层宏和内置函数。

**功能归纳：**

1. **定义了字符串对象的内部结构：**  文件定义了 `String` 类及其子类，用于表示不同类型的字符串，例如：
    * `SeqString`:  连续存储的字符串。
    * `ConsString`: 由两个字符串连接而成的逻辑字符串，避免立即复制。
    * `ExternalString`: 字符串数据存储在 V8 堆外。
    * `SlicedString`:  表示现有字符串的一个切片，共享原始字符串的数据。
    * `ThinString`:  一个指向另一个字符串的瘦包装器。
    * `InternalizedString`:  存储在内部字符串池中的字符串，用于快速比较。

2. **定义了字符串的元数据：**  `StringInstanceType` 结构体使用位域来存储关于字符串的属性，如编码方式（单字节或双字节）、是否被内部化、是否是共享的等。

3. **提供了创建不同类型字符串的宏：**  例如 `AllocateNonEmptySeqOneByteString` 和 `AllocateNonEmptySeqTwoByteString` 用于分配连续存储的字符串。

4. **定义了操作字符串的底层宏和内置函数：**
    * `Flatten`: 将 `ConsString` 或 `ThinString` 转换为 `SeqString`，即将逻辑上的连接或包装展开为实际的连续存储。
    * `StringToSlice`: 获取字符串数据的原始内存切片，根据不同的字符串类型选择合适的访问方式。
    * `TwoStringsToSlices`:  为两个字符串获取内存切片，并调用一个函数来处理这两个切片。
    * `StringWriteToFlatOneByte` 和 `StringWriteToFlatTwoByte`:  将字符串数据写入到新分配的连续内存中。
    * `StringIndexOf`:  实现了字符串查找子串的功能。

**与 JavaScript 的关系及举例：**

这个文件中的定义和操作是 V8 引擎实现 JavaScript 字符串的基础。JavaScript 中的字符串操作，例如拼接、截取、查找等，在底层都会涉及到这里定义的字符串类型和操作。

* **字符串拼接 (`+`)：**  在某些情况下，特别是当拼接操作不频繁或涉及多个字符串时，V8 可能会使用 `ConsString` 来延迟实际的内存复制，提高性能。

   ```javascript
   let str1 = "hello";
   let str2 = " world";
   let combined = str1 + str2; // 内部可能创建 ConsString
   console.log(combined); // "hello world"
   ```

* **字符串切片 (`slice()`, `substring()`)：** 这些方法可能会创建 `SlicedString`，它们不会复制整个字符串，而是创建一个新的字符串对象，指向原始字符串的某个范围。

   ```javascript
   let longString = "This is a long string";
   let slice = longString.slice(5, 9); // 内部可能创建 SlicedString
   console.log(slice); // "is a"
   ```

* **字符串查找 (`indexOf()`)：**  `StringIndexOf` 内置函数直接对应 JavaScript 的 `indexOf()` 方法。

   ```javascript
   let text = "hello world";
   let index = text.indexOf("world"); // 底层会调用 StringIndexOf 或类似的实现
   console.log(index); // 6
   ```

* **字符串内部化 (`intern()` - 非标准但概念相关)：** 尽管 JavaScript 没有直接的 `intern()` 方法，但 V8 内部会对一些字符串进行内部化，例如字面量字符串。当多个地方使用相同的字符串字面量时，它们可能指向内存中的同一个 `InternalizedString` 对象，从而节省内存并加快比较速度。

   ```javascript
   let strA = "test";
   let strB = "test";
   // V8 内部可能会将 "test" 内部化，使得 strA 和 strB 指向同一个内存地址
   console.log(strA === strB); // true
   ```

**代码逻辑推理及假设输入与输出：**

以 `Flatten` 宏为例：

**假设输入：** 一个 `ConsString` 对象 `cons`，其 `first` 属性指向字符串 "hello"，`second` 属性指向字符串 " world"。

**代码逻辑：** `Flatten(cons)` 会检查 `cons` 是否已经是扁平的（`IsFlat()`，即 `second.length == 0`）。如果不是，则调用 `StringSlowFlatten`。`StringSlowFlatten` 会分配一个新的 `SeqOneByteString`（如果两个子字符串都是单字节），并将 "hello" 和 " world" 的内容复制到新的连续内存中。最后，将 `cons` 的 `first` 指向这个新的扁平字符串，并将 `second` 设置为空字符串。

**输出：**  `Flatten(cons)` 返回一个新的 `SeqOneByteString` 对象，其内容为 "hello world"。  原始的 `ConsString` 对象的 `first` 和 `second` 属性也会被修改。

以 `StringToSlice` 宏为例：

**假设输入 1：** 一个 `SeqOneByteString` 对象 `s`，内容为 "abc"。

**输出 1：**  `StringToSlice(s)` 会跳转到 `OneByte` 标签，并生成一个 `ConstSlice<char8>`，指向 `s` 对象内部存储字符 'a', 'b', 'c' 的内存区域。

**假设输入 2：** 一个 `ConsString` 对象 `cons`，`first` 为 "part1"，`second` 为 "part2"。

**输出 2：** `StringToSlice(cons)` 会首先调用 `Flatten(cons)` 将其转换为 `SeqString` (假设是 `SeqOneByteString` "part1part2")，然后像输入 1 那样返回一个指向 "part1part2" 内存的 `ConstSlice<char8>`.

**涉及用户常见的编程错误及举例：**

了解这些底层的字符串表示可以帮助理解某些性能问题和最佳实践：

1. **过度使用字符串拼接：** 在循环中频繁使用 `+` 拼接字符串，尤其是在不确定循环次数的情况下，可能会导致创建大量的 `ConsString` 对象，最终需要执行多次 `Flatten` 操作，影响性能。

   ```javascript
   let result = "";
   for (let i = 0; i < 1000; i++) {
     result += "a"; // 每次循环可能创建一个新的 ConsString
   }
   console.log(result);
   ```
   **推荐做法：**  使用数组的 `join()` 方法或模板字符串来高效地构建字符串。

   ```javascript
   const parts = [];
   for (let i = 0; i < 1000; i++) {
     parts.push("a");
   }
   const result = parts.join("");
   console.log(result);

   // 或者使用模板字符串
   let result2 = "";
   for (let i = 0; i < 1000; i++) {
     result2 = `${result2}a`; // 现代引擎对此有优化，但理解底层原理有益
   }
   console.log(result2);
   ```

2. **不必要的字符串切片：**  虽然 `SlicedString` 可以节省内存，但在某些情况下，如果频繁地对同一个大字符串进行多次切片操作，可能会导致维护多个 `SlicedString` 对象，增加对象的管理开销。

3. **在性能敏感的代码中进行大量的字符串比较：**  虽然 V8 内部对字符串比较进行了优化，尤其是对于 `InternalizedString`，但对于非内部化的长字符串，比较操作仍然可能比较耗时。理解字符串的内部表示可以帮助开发者意识到某些比较操作可能不是简单的指针比较。

4. **假设字符串是可变的：**  JavaScript 中的字符串是不可变的。任何看似修改字符串的操作（如 `slice`、`substring`、`toUpperCase` 等）都会返回一个新的字符串对象。 初学者可能会错误地认为可以直接修改原始字符串，这与底层的字符串表示是相符的，因为多数情况下操作会创建新的字符串对象。

总而言之，`v8/src/objects/string.tq` 文件是 V8 引擎中关于字符串对象的核心定义，它规定了字符串在内存中的组织方式和可以执行的底层操作。理解这个文件的内容有助于深入理解 JavaScript 字符串的性能特性和行为。

Prompt: 
```
这是目录为v8/src/objects/string.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-string-gen.h'

@abstract
@reserveBitsInInstanceType(7)
@cppObjectLayoutDefinition
extern class String extends Name {
  macro StringInstanceType(): StringInstanceType {
    return %RawDownCast<StringInstanceType>(
        Convert<uint16>(this.map.instance_type));
  }

  macro IsNotInternalized(): bool {
    return this.StringInstanceType().is_not_internalized;
  }

  macro IsOneByteRepresentation(): bool {
    return IsOneByteStringMap(this.map);
  }

  const length: int32;
}

extern enum StringRepresentationTag extends uint32 {
  kSeqStringTag,
  kConsStringTag,
  kExternalStringTag,
  kSlicedStringTag,
  kThinStringTag
}

bitfield struct StringInstanceType extends uint16 {
  representation: StringRepresentationTag: 3 bit;
  is_one_byte: bool: 1 bit;
  is_uncached: bool: 1 bit;
  is_not_internalized: bool: 1 bit;
  is_shared: bool: 1 bit;
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class ConsString extends String {
  // Corresponds to String::IsFlat() in the C++ runtime.
  macro IsFlat(): bool {
    return this.second.length == 0;
  }

  first: String;
  second: String;
}

@abstract
@doNotGenerateCast
@cppObjectLayoutDefinition
extern class ExternalString extends String {
  resource: ExternalPointer;
  // WARNING: This field is missing for uncached external strings.
  resource_data: ExternalPointer;
}

extern operator '.resource_ptr' macro LoadExternalStringResourcePtr(
    ExternalString): RawPtr;
extern operator '.resource_data_ptr' macro LoadExternalStringResourceDataPtr(
    ExternalString): RawPtr;
extern operator '.resource_data_ptr' macro LoadExternalStringResourceDataPtr(
    ExternalOneByteString): RawPtr<char8>;
extern operator '.resource_data_ptr' macro LoadExternalStringResourceDataPtr(
    ExternalTwoByteString): RawPtr<char16>;

extern macro ExternalOneByteStringGetChars(ExternalOneByteString):
    RawPtr<char8>;
extern macro ExternalTwoByteStringGetChars(ExternalTwoByteString):
    RawPtr<char16>;

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class ExternalOneByteString extends ExternalString {
  macro GetChars(): RawPtr<char8> {
    if (this.StringInstanceType().is_uncached) {
      return ExternalOneByteStringGetChars(this);
    } else {
      return this.resource_data_ptr;
    }
  }
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class ExternalTwoByteString extends ExternalString {
  macro GetChars(): RawPtr<char16> {
    if (this.StringInstanceType().is_uncached) {
      return ExternalTwoByteStringGetChars(this);
    } else {
      return this.resource_data_ptr;
    }
  }
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class InternalizedString extends String {}

@abstract
@doNotGenerateCast
@cppObjectLayoutDefinition
extern class SeqString extends String {}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class SeqOneByteString extends SeqString {
  const chars[length]: char8;
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class SeqTwoByteString extends SeqString {
  const chars[length]: char16;
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class SlicedString extends String {
  parent: String;
  offset: Smi;
}

@doNotGenerateCast
@cppObjectLayoutDefinition
extern class ThinString extends String {
  actual: String;
}

// A direct string can be accessed directly through CSA without going into the
// C++ runtime. See also: ToDirectStringAssembler.
type DirectString extends String;

macro AllocateNonEmptySeqOneByteString<Iterator: type>(
    length: uint32, content: Iterator): SeqOneByteString {
  dcheck(length != 0 && length <= kStringMaxLength);
  return new (ClearPadding) SeqOneByteString{
    map: kSeqOneByteStringMap,
    raw_hash_field: kNameEmptyHashField,
    length: Signed(length),
    chars: ...content
  };
}

macro AllocateNonEmptySeqTwoByteString<Iterator: type>(
    length: uint32, content: Iterator): SeqTwoByteString {
  dcheck(length > 0 && length <= kStringMaxLength);
  return new (ClearPadding) SeqTwoByteString{
    map: kSeqTwoByteStringMap,
    raw_hash_field: kNameEmptyHashField,
    length: Signed(length),
    chars: ...content
  };
}

macro AllocateNonEmptySeqOneByteString(length: uint32): SeqOneByteString {
  return AllocateNonEmptySeqOneByteString(length, UninitializedIterator{});
}
macro AllocateNonEmptySeqTwoByteString(length: uint32): SeqTwoByteString {
  return AllocateNonEmptySeqTwoByteString(length, UninitializedIterator{});
}

macro AllocateSeqOneByteString<Iterator: type>(
    length: uint32, content: Iterator): SeqOneByteString|EmptyString {
  if (length == 0) return kEmptyString;
  return AllocateNonEmptySeqOneByteString(length, content);
}

macro AllocateSeqTwoByteString<Iterator: type>(
    length: uint32, content: Iterator): SeqTwoByteString|EmptyString {
  if (length == 0) return kEmptyString;
  return AllocateNonEmptySeqTwoByteString(length, content);
}

@export
macro AllocateSeqOneByteString(length: uint32): SeqOneByteString|
    EmptyString {
  return AllocateSeqOneByteString(length, UninitializedIterator{});
}

@export
macro AllocateSeqTwoByteString(length: uint32): SeqTwoByteString|
    EmptyString {
  return AllocateSeqTwoByteString(length, UninitializedIterator{});
}

extern macro StringWriteToFlatOneByte(
    String, RawPtr<char8>, int32, int32): void;
extern macro StringWriteToFlatTwoByte(
    String, RawPtr<char16>, int32, int32): void;

// Corresponds to String::SlowFlatten in the C++ runtime.
builtin StringSlowFlatten(cons: ConsString): String {
  // TurboFan can create cons strings with empty first parts.
  let cons = cons;
  while (cons.first.length == 0) {
    // We do not want to call this function recursively. Therefore we call
    // String::Flatten only in those cases where String::SlowFlatten is not
    // called again.
    try {
      const second = Cast<ConsString>(cons.second) otherwise FoundFlatString;
      if (second.IsFlat()) goto FoundFlatString;
      cons = second;
    } label FoundFlatString {
      return Flatten(cons.second);
    }
  }

  let flat: String;
  if (cons.map == kConsOneByteStringMap) {
    const allocated = AllocateNonEmptySeqOneByteString(Unsigned(cons.length));
    StringWriteToFlatOneByte(
        cons, (&allocated.chars).GCUnsafeStartPointer(), 0, cons.length);
    flat = allocated;
  } else {
    const allocated = UnsafeCast<SeqTwoByteString>(
        AllocateNonEmptySeqTwoByteString(Unsigned(cons.length)));
    StringWriteToFlatTwoByte(
        cons, (&allocated.chars).GCUnsafeStartPointer(), 0, cons.length);
    flat = allocated;
  }
  cons.first = flat;
  cons.second = kEmptyString;
  return flat;
}

// Corresponds to String::Flatten in the C++ runtime.
macro Flatten(string: String): String {
  typeswitch (string) {
    case (cons: ConsString): {
      return Flatten(cons);
    }
    case (thin: ThinString): {
      dcheck(!Is<ConsString>(thin.actual));
      return thin.actual;
    }
    case (other: String): {
      return other;
    }
  }
}
macro Flatten(cons: ConsString): String {
  if (cons.IsFlat()) return cons.first;
  return StringSlowFlatten(cons);
}

// Get a slice to the string data, flatten only if unavoidable for this.
macro StringToSlice(string: String): never labels OneByte(ConstSlice<char8>),
    TwoByte(ConstSlice<char16>) {
  let string = string;
  let offset: intptr = 0;
  const length = Convert<intptr>(string.length);
  while (true) {
    typeswitch (string) {
      case (s: SeqOneByteString): {
        goto OneByte(Subslice(&s.chars, offset, length) otherwise unreachable);
      }
      case (s: SeqTwoByteString): {
        goto TwoByte(Subslice(&s.chars, offset, length) otherwise unreachable);
      }
      case (s: ThinString): {
        string = s.actual;
      }
      case (s: ConsString): {
        string = Flatten(s);
      }
      case (s: SlicedString): {
        offset += Convert<intptr>(s.offset);
        string = s.parent;
      }
      case (s: ExternalOneByteString): {
        const data = torque_internal::unsafe::NewOffHeapConstSlice(
            s.GetChars(), Convert<intptr>(s.length));
        goto OneByte(Subslice(data, offset, length) otherwise unreachable);
      }
      case (s: ExternalTwoByteString): {
        const data = torque_internal::unsafe::NewOffHeapConstSlice(
            s.GetChars(), Convert<intptr>(s.length));
        goto TwoByte(Subslice(data, offset, length) otherwise unreachable);
      }
      case (String): {
        unreachable;
      }
    }
  }
  VerifiedUnreachable();
}

// Dispatch on the slice type of two different strings.
macro TwoStringsToSlices<Result: type, Functor: type>(
    s1: String, s2: String, f: Functor): Result {
  try {
    StringToSlice(s1) otherwise FirstOneByte, FirstTwoByte;
  } label FirstOneByte(s1Slice: ConstSlice<char8>) {
    try {
      StringToSlice(s2) otherwise SecondOneByte, SecondTwoByte;
    } label SecondOneByte(s2Slice: ConstSlice<char8>) {
      return Call(f, s1Slice, s2Slice);
    } label SecondTwoByte(s2Slice: ConstSlice<char16>) {
      return Call(f, s1Slice, s2Slice);
    }
  } label FirstTwoByte(s1Slice: ConstSlice<char16>) {
    try {
      StringToSlice(s2) otherwise SecondOneByte, SecondTwoByte;
    } label SecondOneByte(s2Slice: ConstSlice<char8>) {
      return Call(f, s1Slice, s2Slice);
    } label SecondTwoByte(s2Slice: ConstSlice<char16>) {
      return Call(f, s1Slice, s2Slice);
    }
  }
}

macro StaticAssertStringLengthFitsSmi(): void {
  const kMaxStringLengthFitsSmi: constexpr bool =
      kStringMaxLengthUintptr < kSmiMaxValue;
  static_assert(kMaxStringLengthFitsSmi);
}

extern macro StringBuiltinsAssembler::SearchOneByteStringInTwoByteString(
    RawPtr<char16>, intptr, RawPtr<char8>, intptr, intptr): intptr;
extern macro StringBuiltinsAssembler::SearchOneByteStringInOneByteString(
    RawPtr<char8>, intptr, RawPtr<char8>, intptr, intptr): intptr;
extern macro StringBuiltinsAssembler::SearchTwoByteStringInTwoByteString(
    RawPtr<char16>, intptr, RawPtr<char16>, intptr, intptr): intptr;
extern macro StringBuiltinsAssembler::SearchTwoByteStringInOneByteString(
    RawPtr<char8>, intptr, RawPtr<char16>, intptr, intptr): intptr;
extern macro StringBuiltinsAssembler::SearchOneByteInOneByteString(
    RawPtr<char8>, intptr, RawPtr<char8>, intptr): intptr;

macro AbstractStringIndexOf(
    subject: RawPtr<char16>, subjectLen: intptr, search: RawPtr<char8>,
    searchLen: intptr, fromIndex: intptr): intptr {
  return SearchOneByteStringInTwoByteString(
      subject, subjectLen, search, searchLen, fromIndex);
}
macro AbstractStringIndexOf(
    subject: RawPtr<char8>, subjectLen: intptr, search: RawPtr<char8>,
    searchLen: intptr, fromIndex: intptr): intptr {
  if (searchLen == 1) {
    return SearchOneByteInOneByteString(subject, subjectLen, search, fromIndex);
  }
  return SearchOneByteStringInOneByteString(
      subject, subjectLen, search, searchLen, fromIndex);
}
macro AbstractStringIndexOf(
    subject: RawPtr<char16>, subjectLen: intptr, search: RawPtr<char16>,
    searchLen: intptr, fromIndex: intptr): intptr {
  return SearchTwoByteStringInTwoByteString(
      subject, subjectLen, search, searchLen, fromIndex);
}
macro AbstractStringIndexOf(
    subject: RawPtr<char8>, subjectLen: intptr, search: RawPtr<char16>,
    searchLen: intptr, fromIndex: intptr): intptr {
  return SearchTwoByteStringInOneByteString(
      subject, subjectLen, search, searchLen, fromIndex);
}

struct AbstractStringIndexOfFunctor {
  fromIndex: Smi;
}
// Ideally, this would be a method of AbstractStringIndexOfFunctor, but
// currently methods don't support templates.
macro Call<A: type, B: type>(
    self: AbstractStringIndexOfFunctor, string: ConstSlice<A>,
    searchStr: ConstSlice<B>): Smi {
  return Convert<Smi>(AbstractStringIndexOf(
      string.GCUnsafeStartPointer(), string.length,
      searchStr.GCUnsafeStartPointer(), searchStr.length,
      Convert<intptr>(self.fromIndex)));
}

macro AbstractStringIndexOf(
    implicit context: Context)(string: String, searchString: String,
    fromIndex: Smi): Smi {
  // Special case the empty string.
  const searchStringLength = searchString.length_intptr;
  const stringLength = string.length_intptr;
  if (searchStringLength == 0 && SmiUntag(fromIndex) <= stringLength) {
    return fromIndex;
  }

  // Don't bother to search if the searchString would go past the end
  // of the string. This is actually necessary because of runtime
  // checks.
  if (SmiUntag(fromIndex) + searchStringLength > stringLength) {
    return -1;
  }

  return TwoStringsToSlices<Smi>(
      string, searchString, AbstractStringIndexOfFunctor{fromIndex: fromIndex});
}

builtin StringIndexOf(s: String, searchString: String, start: Smi): Smi {
  return AbstractStringIndexOf(s, searchString, SmiMax(start, 0));
}

"""

```