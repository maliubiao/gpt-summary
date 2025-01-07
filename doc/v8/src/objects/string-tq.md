Response:
Let's break down the thought process for analyzing this Torque file.

**1. Initial Understanding: The Filename and Extension**

The filename `string.tq` and the `.tq` extension immediately signal that this is a Torque file related to string objects in V8. The prompt itself reinforces this. Torque is V8's internal language for defining object layouts and generating code for built-in functions.

**2. High-Level Purpose Identification**

The initial comments and the declaration of the `String` class tell us the core purpose:  defining the structure and behavior of string objects within V8. We know strings are fundamental, so this file is likely a crucial part of V8's object system.

**3. Identifying Key Concepts and Data Structures**

* **Inheritance:** The `String` class extends `Name`, indicating a hierarchy. This suggests `Name` likely holds common properties for identifiers, and `String` adds string-specific details.
* **Instance Types:** The `StringInstanceType` enum and bitfield are critical. They encode important metadata about the string's representation (one-byte, two-byte, etc.) and its properties (internalized, shared, etc.). This is a common V8 pattern for efficient object representation.
* **String Representations:**  The `StringRepresentationTag` enum reveals the different ways V8 stores string data: `SeqString`, `ConsString`, `ExternalString`, `SlicedString`, `ThinString`. This is a key area to understand for performance considerations.
* **Specific String Classes:**  The definitions of `ConsString`, `ExternalString`, `SeqOneByteString`, etc., flesh out the different representation types. Noticing the fields within each (e.g., `first`, `second` in `ConsString`) gives clues about their purpose.
* **Macros:** The abundance of `macro` definitions points to utility functions and abstractions for working with strings. The names often suggest their function (e.g., `AllocateNonEmptySeqOneByteString`, `Flatten`, `StringToSlice`).
* **Builtins:** The `builtin` keyword marks functions that are exposed to JavaScript. `StringSlowFlatten` and `StringIndexOf` are direct examples.

**4. Analyzing Each Section (Iterative Process)**

I would go through the file section by section, trying to understand the purpose of each declaration or block.

* **`String` Class:**  Focus on the `StringInstanceType` macro and its implications. The `IsNotInternalized` and `IsOneByteRepresentation` macros are basic checks. The `length` field is fundamental.
* **`StringRepresentationTag` and `StringInstanceType`:**  Understand how the bitfield is structured and what each bit represents. This directly impacts memory layout and runtime behavior.
* **`ConsString`:** The `first` and `second` fields suggest a way to represent concatenated strings without immediately copying. The `IsFlat` macro checks if it's been fully resolved.
* **`ExternalString`:**  The `resource` and `resource_data` fields indicate strings whose data is stored outside the regular V8 heap (e.g., from native code). The "WARNING" comment is important.
* **External String Getters:**  The `LoadExternalStringResourceDataPtr` and `GetChars` macros handle accessing the external data, considering uncached scenarios.
* **`InternalizedString`, `SeqString`, `SeqOneByteString`, `SeqTwoByteString`:** These are straightforward representations of strings stored directly in V8's heap. Note the `chars` array.
* **`SlicedString`:** The `parent` and `offset` suggest a substring mechanism without copying the underlying data.
* **`ThinString`:** The `actual` field points to the real string data, likely used for deduplication or temporary views.
* **`Allocate...` Macros:** These are factory functions for creating different types of `SeqString` objects. The `UninitializedIterator` is a detail about memory initialization.
* **`StringWriteToFlat...` Macros:** These are low-level operations for copying string data into a flat representation.
* **`StringSlowFlatten` and `Flatten`:**  These are crucial for understanding how V8 resolves `ConsString`s into contiguous strings. The iterative approach in `StringSlowFlatten` is interesting.
* **`StringToSlice`:** This is a complex but essential macro for accessing the underlying character data of a string, handling all the different string representations. The `typeswitch` is key to understanding its logic. The labels (`OneByte`, `TwoByte`) are for escaping the macro.
* **`TwoStringsToSlices`:** This builds on `StringToSlice` to handle operations involving two strings with potentially different representations.
* **`AbstractStringIndexOf` and `StringIndexOf`:** These functions implement the core string search functionality, dispatching based on the string representations. The `TwoStringsToSlices` macro is used here to handle different encoding combinations.

**5. Connecting to JavaScript**

After understanding the internal structures and macros, the next step is to connect them to JavaScript features. Think about which JavaScript string operations would rely on these internal mechanisms. Concatenation (`+`), slicing (`substring`, `slice`), and searching (`indexOf`) are prime candidates.

**6. Code Logic Reasoning and Examples**

For macros like `Flatten` or `StringToSlice`, consider specific examples of how they would behave with different input string types. This helps solidify understanding and can be used to generate "assumed input/output" examples.

**7. Identifying Common Programming Errors**

Think about how the internal string representations might relate to common JavaScript errors. For example, excessive string concatenation in older JavaScript engines could lead to performance issues due to the creation of many intermediate `ConsString` objects. Understanding `Flatten` helps explain why this can be inefficient.

**8. Refinement and Organization**

Finally, organize the findings into a clear and structured explanation, as demonstrated in the provided good answer. Use headings, bullet points, and code examples to make the information accessible. Review and refine the explanation for clarity and accuracy.

**Self-Correction/Refinement During the Process:**

* **Initial Overlook:**  I might initially focus too much on individual structures and miss the bigger picture of how they work together. Realizing the role of `StringToSlice` in unifying access across different string types is a key insight.
* **Complexity of Macros:**  Some macros, like `StringToSlice`, can be initially confusing due to the `typeswitch` and labels. Breaking down the logic step-by-step and tracing the flow for different string types is crucial.
* **Connecting to Builtins:**  Realizing that `StringSlowFlatten` and `StringIndexOf` are directly linked to JavaScript built-in methods solidifies the connection between the Torque code and JavaScript behavior.

By following this systematic approach, combining code analysis with knowledge of JavaScript string operations and V8's architecture, one can effectively understand the purpose and functionality of a file like `string.tq`.
这个文件 `v8/src/objects/string.tq` 是 V8 引擎中关于 **字符串对象** 的 Torque 源代码定义。它详细描述了 V8 内部如何表示和操作各种类型的字符串。

以下是它的功能列表：

**核心功能：定义字符串对象的内部结构和元数据**

1. **定义抽象基类 `String`:**  声明了所有 V8 字符串对象都继承的抽象基类 `String`，并定义了所有字符串共有的属性，例如：
   - `length`: 字符串的长度。
   - `StringInstanceType()` 宏：用于获取字符串的实例类型信息。
   - `IsNotInternalized()` 宏：判断字符串是否被内部化。
   - `IsOneByteRepresentation()` 宏：判断字符串是否使用单字节编码。

2. **定义字符串实例类型 `StringInstanceType`:** 使用位域结构 `StringInstanceType` 来高效存储字符串的各种属性，包括：
   - `representation`: 使用 `StringRepresentationTag` 枚举表示字符串的具体存储方式（例如，连续存储、拼接、外部存储等）。
   - `is_one_byte`:  指示字符串是否使用单字节编码（例如 Latin-1）。
   - `is_uncached`:  指示外部字符串的数据是否被缓存。
   - `is_not_internalized`: 指示字符串是否是内部化字符串。
   - `is_shared`: 指示字符串是否被多个上下文共享。

3. **定义不同的字符串表示形式:**  定义了各种具体的字符串类型，每种类型都有其特定的存储方式和优化策略：
   - **`SeqString` (Sequential String):**  最基本的字符串表示，字符数据连续存储。
     - `SeqOneByteString`:  单字节顺序字符串。
     - `SeqTwoByteString`: 双字节顺序字符串（例如 UTF-16）。
   - **`ConsString` (Concatenated String):**  表示由两个或多个字符串拼接而成的字符串，延迟拼接操作，避免立即复制大量数据。
     - `first`: 指向拼接的前半部分字符串。
     - `second`: 指向拼接的后半部分字符串。
     - `IsFlat()` 宏：判断 `ConsString` 是否已经被展平（即拼接操作已经完成）。
   - **`ExternalString`:**  表示字符串数据存储在 V8 堆外部。常用于与外部资源（如 C++ 代码）交互。
     - `resource`: 指向外部资源的指针。
     - `resource_data`: 指向字符串实际数据的指针（可能缺失）。
     - 派生出 `ExternalOneByteString` 和 `ExternalTwoByteString`。
   - **`SlicedString`:** 表示原始字符串的一个切片，共享原始字符串的数据，只记录偏移量和长度。
     - `parent`: 指向原始字符串。
     - `offset`: 切片的起始偏移量。
   - **`ThinString`:**  一种特殊的字符串，通常指向另一个 "实际" 的字符串，可能用于某些优化场景。
     - `actual`: 指向实际的字符串。
   - **`InternalizedString`:**  表示被内部化的字符串，相同的内部化字符串在内存中只保留一份，用于优化性能。
   - **`DirectString`:** 一种可以直接通过 CSA（CodeStubAssembler）访问的字符串，无需进入 C++ 运行时。

**辅助功能：字符串的创建、转换和操作**

4. **分配字符串的宏:** 提供了一系列 `Allocate...` 宏，用于在堆上分配不同类型的顺序字符串 (`SeqOneByteString` 和 `SeqTwoByteString`)。
   - 可以指定长度和初始内容。
   - 区分了非空字符串和允许为空字符串的分配。

5. **字符串展平 (Flattening):**  定义了 `Flatten` 宏和 `StringSlowFlatten` 内置函数，用于将 `ConsString` 等非连续存储的字符串转换为连续存储的 `SeqString`。
   - `StringSlowFlatten`:  处理 `ConsString` 的展平操作。
   - `Flatten`:  一个更通用的展平入口，可以处理 `ConsString` 和 `ThinString`。

6. **获取字符串切片:** 定义了 `StringToSlice` 宏，用于获取字符串的底层字符数据切片，并处理各种字符串表示形式。这避免了不必要的复制。

7. **比较字符串的宏:** 定义了 `TwoStringsToSlices` 宏，用于将两个字符串转换为字符数据切片，并调用提供的函数进行比较或其他操作，支持不同编码的字符串比较。

8. **字符串查找 (IndexOf):**
   - 定义了底层的 `AbstractStringIndexOf` 宏，它根据字符串的编码类型调用不同的 C++ 运行时函数进行查找。
   - 定义了 `StringIndexOf` 内置函数，它是 JavaScript `String.prototype.indexOf` 方法的 V8 内部实现，它调用 `AbstractStringIndexOf` 来执行实际的查找操作。

**其他功能**

9. **静态断言:** `StaticAssertStringLengthFitsSmi` 宏用于静态地断言字符串的最大长度可以放入一个 Smi (Small Integer)。

10. **与 C++ Builtins 的交互:**  声明了与 C++ Builtins Assembler 相关的宏，用于执行底层的字符串操作，例如 `SearchOneByteStringInTwoByteString` 等。

**与 JavaScript 功能的关系及示例**

这个 `.tq` 文件直接影响着 JavaScript 中字符串的各种操作，因为它定义了 V8 内部如何表示和处理字符串。

**示例 1: 字符串拼接 (Concatenation)**

当你在 JavaScript 中使用 `+` 运算符拼接字符串时，V8 可能会创建 `ConsString` 对象，特别是当拼接操作比较频繁时。

```javascript
let str1 = "hello";
let str2 = " world";
let result = str1 + str2; // 内部可能创建 ConsString
console.log(result); // "hello world"
```

在这个例子中，`result` 在 V8 内部可能最初是一个 `ConsString`，它引用了 `"hello"` 和 `" world"` 两个字符串。当需要访问 `result` 的字符数据时（例如，计算长度或进行比较），V8 可能会调用 `Flatten` 将其转换为 `SeqOneByteString` 或 `SeqTwoByteString`。

**示例 2: 字符串切片 (Slicing)**

JavaScript 的 `substring` 或 `slice` 方法在 V8 内部很可能会创建 `SlicedString` 对象。

```javascript
let str = "abcdefg";
let slice = str.substring(2, 5); // 内部可能创建 SlicedString
console.log(slice); // "cde"
```

`slice` 对象在 V8 内部可能是一个 `SlicedString`，它指向原始字符串 `"abcdefg"`，并记录了偏移量 `2` 和长度 `3`。这避免了复制 "cde" 的字符数据，节省了内存。

**示例 3: 字符串查找 (indexOf)**

JavaScript 的 `indexOf` 方法直接对应到 `StringIndexOf` 这个 Torque 内置函数。

```javascript
let str = "hello world";
let index = str.indexOf("world"); // 调用 StringIndexOf
console.log(index); // 6
```

当调用 `str.indexOf("world")` 时，V8 内部会调用 `StringIndexOf`，它最终会使用 `AbstractStringIndexOf` 和相关的 C++ Builtins 来在 `str` 的字符数据中查找 `"world"` 子字符串。

**代码逻辑推理与假设输入输出**

**场景：`Flatten` 宏处理 `ConsString`**

**假设输入:** 一个 `ConsString` 对象，其 `first` 指向 `"abc"` (SeqOneByteString)，`second` 指向 `"def"` (SeqOneByteString)。

**代码逻辑推理 (简化):**

1. `Flatten(cons: ConsString)` 被调用。
2. `cons.IsFlat()` 返回 `false` (因为 `second.length` 不为 0)。
3. 调用 `StringSlowFlatten(cons)`。
4. `StringSlowFlatten` 分配一个新的 `SeqOneByteString`，长度为 `cons.length` (3 + 3 = 6)。
5. 使用 `StringWriteToFlatOneByte` 将 `cons.first` 和 `cons.second` 的字符数据复制到新分配的 `SeqOneByteString` 中。
6. 更新 `cons.first` 指向新分配的 `SeqOneByteString`。
7. 更新 `cons.second` 指向 `kEmptyString`。
8. 返回新分配的 `SeqOneByteString`。

**假设输出:** 一个新的 `SeqOneByteString` 对象，其字符数据为 `"abcdef"`。

**用户常见的编程错误**

1. **过度使用字符串拼接导致性能问题 (尤其是在旧的 JavaScript 引擎中):**  在循环中频繁使用 `+` 运算符拼接字符串，可能会创建大量的中间 `ConsString` 对象，最终需要进行多次展平操作，影响性能。

   ```javascript
   let result = "";
   for (let i = 0; i < 10000; i++) {
     result += "a"; // 可能会创建大量的 ConsString
   }
   ```

   **V8 的优化:** 现代 V8 引擎对字符串拼接做了一些优化，例如 ropes (类似于 `ConsString`)，可以延迟拼接操作，避免立即复制大量数据。但是，在性能敏感的场景下，仍然建议使用数组的 `join` 方法进行字符串拼接。

2. **不理解字符串的不可变性:**  JavaScript 中的字符串是不可变的。对字符串进行修改的操作（例如 `substring`, `slice`, `toUpperCase`）会返回新的字符串对象，而不会修改原始字符串。初学者可能会错误地认为这些操作会修改原始字符串。

   ```javascript
   let str = "hello";
   str.toUpperCase(); // 返回 "HELLO"，但 str 仍然是 "hello"
   console.log(str); // "hello"

   let upperStr = str.toUpperCase();
   console.log(upperStr); // "HELLO"
   ```

**总结**

`v8/src/objects/string.tq` 文件是 V8 引擎中定义字符串对象内部结构和行为的关键文件。它定义了各种字符串的表示形式，以及用于创建、转换和操作字符串的底层机制。理解这个文件有助于深入了解 JavaScript 字符串的性能特性以及 V8 引擎的内部工作原理。

Prompt: 
```
这是目录为v8/src/objects/string.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/string.tq以.tq结尾，那它是个v8 torque源代码，
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