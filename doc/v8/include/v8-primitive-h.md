Response:
Let's break down the thought process for analyzing the provided C++ header file `v8-primitive.h`.

**1. Initial Scan and Overall Impression:**

* **Keywords:** `#ifndef`, `#define`, `class`, `enum`, `namespace`, `public`, `private`, `static`, `virtual`, `V8_EXPORT`, `V8_INLINE`, `Local`, `Isolate`. These immediately flag it as a C++ header file defining classes and interfaces, likely part of a larger system.
* **Filename:** `v8-primitive.h` strongly suggests it deals with fundamental data types (primitives) within the V8 JavaScript engine.
* **Copyright:** The copyright notice confirms it's part of the V8 project.
* **Includes:**  The included headers (`v8-data.h`, `v8-internal.h`, etc.) indicate dependencies on other V8 internal components. The `// NOLINT(build/include_directory)` comments hint at specific project coding style requirements.

**2. Identifying Core Concepts:**

* **`Primitive` Class:**  The first defined class, `Primitive`, and the comment "The superclass of primitive values. See ECMA-262 4.3.2." immediately establish the central theme. This class serves as a base for other primitive types, mirroring the concept of primitives in JavaScript.
* **Specific Primitive Subclasses:**  Following `Primitive`, we see `Boolean`, `String`, `Symbol`, `Number`, `BigInt`, etc. These directly correspond to JavaScript's primitive data types.
* **`Local<T>`:**  The frequent use of `Local<T>` suggests a handle system for managing V8 objects, likely to prevent direct pointer manipulation and aid garbage collection.
* **`Isolate`:** The presence of `Isolate*` parameters in many methods points to the concept of isolates in V8 – independent instances of the engine.
* **`V8_EXPORT` and `V8_INLINE`:** These macros control visibility and inlining, typical for library headers.
* **External Resources:** The `ExternalStringResource` and `ExternalOneByteStringResource` classes indicate a mechanism for integrating strings managed outside the V8 heap.

**3. Analyzing Individual Classes and Members:**

* **`Boolean`:**  Straightforward, with a `Value()` method to get the underlying boolean and a `New()` static method for creation.
* **`PrimitiveArray`:** Represents an array of primitives, likely used for specific internal purposes like passing options.
* **`Name`:** A base class for `String` and `Symbol`, suggesting shared characteristics like identity hash.
* **`String`:**  This is the most complex class, reflecting the multifaceted nature of strings in JavaScript. Key aspects include:
    * **Encoding:** `Encoding` enum and methods like `IsOneByte()`, `ContainsOnlyOneByte()` highlight V8's handling of different string encodings.
    * **Writing to Buffers:** The `Write`, `WriteOneByte`, `WriteUtf8`, and their `V2` counterparts are crucial for interacting with string data.
    * **External Strings:** The `ExternalStringResource` family of classes and associated methods (`NewExternalTwoByte`, `MakeExternal`) are important for memory management and interoperability.
    * **String Creation:** `NewFromUtf8`, `NewFromOneByte`, `NewFromTwoByte` are the standard ways to create `String` objects.
    * **`Utf8Value` and `Value` (deprecated):**  Provide ways to convert V8 strings to C++ string representations, but with caveats about copying.
    * **`ValueView`:** A more efficient, zero-copy way to access string data, but with restrictions on garbage collection.
* **`Symbol`:** Represents ES6 symbols, with methods for creating global symbols (`For`, `ForApi`).
* **`Numeric`, `Number`, `Integer`, `Int32`, `Uint32`, `BigInt`:** These classes represent the various numeric types in JavaScript, with methods for creating and accessing their values.

**4. Identifying Functionality and Relationships:**

* **Creation of Primitive Values:**  Most primitive classes have static `New()` methods for creating instances.
* **Accessing Values:**  Methods like `Value()` (for booleans and numbers) provide access to the underlying primitive values.
* **String Manipulation:** The `String` class offers a rich set of methods for working with string data, including length, encoding, writing to buffers, concatenation, and external string management.
* **Type Checking/Casting:**  The `Cast()` methods and `CheckCast()` (under `#ifdef V8_ENABLE_CHECKS`) are for type safety and downcasting.
* **Memory Management (Implicit):** The use of `Local` and the existence of external string resources hint at V8's memory management strategies.

**5. Considering the `.tq` Question:**

The prompt specifically asks about `.tq` files. Knowing that Torque is V8's internal language for implementing built-in functions, the conclusion that this is *not* a Torque file is straightforward since it's a `.h` header file.

**6. Connecting to JavaScript:**

For each primitive type, it's relatively easy to provide a corresponding JavaScript example. The key is understanding the direct mapping between the C++ classes and the JavaScript language constructs.

**7. Identifying Potential Errors:**

Thinking about common programming errors involves considering:

* **Memory Management with External Resources:**  Incorrectly managing the lifetime of external string resources.
* **Buffer Overflows:**  When using the `Write` methods, not allocating enough buffer space.
* **Encoding Issues:**  Mismatches between expected and actual string encodings.
* **Type Errors:**  Trying to cast a `Data*` to the wrong primitive type.
* **Garbage Collection Issues with `ValueView`:**  Violating the constraints on GC while using a `ValueView`.

**8. Structuring the Output:**

The final step involves organizing the gathered information into a clear and structured answer, covering the requested points:

* **Functionality Summary:** A high-level overview of the header file's purpose.
* **Torque Check:**  Explicitly address the `.tq` question.
* **JavaScript Relationship:**  Provide JavaScript examples for each relevant class.
* **Code Logic/Assumptions:**  Offer examples of how the methods might be used with sample input and output.
* **Common Errors:**  Illustrate potential pitfalls with code snippets.
* **Summary (Part 1):** A concise recap of the identified functionalities.

This iterative process of scanning, identifying concepts, analyzing details, and connecting to broader knowledge allows for a comprehensive understanding of the C++ header file and its role within the V8 engine.
这是对V8源代码文件 `v8/include/v8-primitive.h` 的分析。

**功能归纳：**

`v8/include/v8-primitive.h` 文件定义了 V8 JavaScript 引擎中**原始类型 (primitive types)** 的 C++ 接口。它声明了表示 JavaScript 中基本数据类型（如布尔值、字符串、符号、数字和 BigInt）的 C++ 类。 这些类提供了与这些 JavaScript 值交互的方法，例如获取其值、创建新实例以及执行其他相关操作。

**详细功能列表：**

1. **定义原始类型的基类 `Primitive`:**  作为所有原始类型 C++ 类的基类。
2. **定义布尔类型 `Boolean`:**
   - 提供 `Value()` 方法获取布尔值的 C++ `bool` 表示。
   - 提供 `New()` 静态方法创建新的 `Boolean` 实例。
3. **定义 `PrimitiveArray`:**
   - 用于存储原始值的数组，主要用于引擎内部，例如传递编译选项。
   - 提供创建、获取长度、设置和获取元素的静态和成员方法。
4. **定义 `Name` 类:**
   - 作为 `String` 和 `Symbol` 的基类，表示可以作为属性名称的值。
   - 提供 `GetIdentityHash()` 方法获取对象的标识哈希值。
5. **定义字符串类型 `String`:**
   - 提供多种方法来获取字符串的长度（字符数和 UTF-8 字节数）。
   - 提供检查字符串编码（单字节或双字节）的方法。
   - 提供将字符串内容写入外部缓冲区的多种 `Write` 方法（支持不同的编码和选项）。
   - 提供创建空字符串的静态方法 `Empty()`。
   - 提供检查字符串是否为外部字符串（数据在 V8 堆外）的方法。
   - 定义了 `ExternalStringResourceBase`, `ExternalStringResource`, 和 `ExternalOneByteStringResource` 类，用于管理 V8 堆外部的字符串数据。
   - 提供创建和关联外部字符串的静态方法 (`NewExternalTwoByte`, `NewExternalOneByte`, `MakeExternal`)。
   - 提供比较字符串是否相等的 `StringEquals()` 方法。
   - 定义了 `Utf8Value` 和 `Value` 类，用于将 V8 字符串转换为 C++ 的 UTF-8 或 UTF-16 字符串（注意：`Value` 已被标记为过时）。
   - 定义了 `ValueView` 类，提供对字符串内容的零拷贝访问。
   - 提供多种静态方法来从不同的数据源（UTF-8, Latin-1, UTF-16）创建新的 `String` 实例。
   - 提供连接两个字符串的静态方法 `Concat()`。
6. **定义符号类型 `Symbol`:**
   - 提供 `Description()` 方法获取符号的描述字符串。
   - 提供创建新符号的静态方法 `New()`。
   - 提供访问全局符号注册表的静态方法 `For()` 和 `ForApi()`。
   - 提供访问预定义的 well-known symbols 的静态方法 (例如 `GetAsyncIterator`, `GetIterator`)。
7. **定义数字类型的基类 `Numeric`:** 作为 `Number` 和 `BigInt` 的基类。
8. **定义数字类型 `Number`:**
   - 提供 `Value()` 方法获取数字的 `double` 值。
   - 提供 `New()` 静态方法创建新的 `Number` 实例。
9. **定义整数类型 `Integer`:**
   - 提供 `Value()` 方法获取整数的 64 位有符号整数值。
   - 提供 `New()` 和 `NewFromUnsigned()` 静态方法创建新的 `Integer` 实例。
10. **定义 32 位整数类型 `Int32` 和 `Uint32`:**
    - 提供 `Value()` 方法获取 32 位有符号和无符号整数值。
11. **定义 BigInt 类型 `BigInt`:**
    - 提供 `New()` 和 `NewFromUnsigned()` 静态方法创建新的 `BigInt` 实例。
    - 提供 `NewFromWords()` 方法从字 (words) 创建 BigInt。
    - 提供获取 BigInt 值的多种方法 (`Uint64Value`, `Int64Value`)。
    - 提供获取 BigInt 字数和将 BigInt 写入字数组的方法 (`WordCount`, `ToWordsArray`)。
12. **定义 `ExternalResourceVisitor` 接口:** 用于迭代堆中的所有外部资源。

**关于 `.tq` 后缀：**

如果 `v8/include/v8-primitive.h` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。但是，根据您提供的文件名，它以 `.h` 结尾，因此这是一个 **C++ 头文件**，而不是 Torque 文件。 Torque 文件通常用于定义 V8 的内置函数和运行时库。

**与 JavaScript 功能的关系及示例：**

这个头文件中定义的 C++ 类直接对应 JavaScript 中的原始类型。以下是一些 JavaScript 示例以及它们与 C++ 类的关系：

* **Boolean:**
  ```javascript
  const myBool = true;
  const anotherBool = false;
  ```
  对应 C++ 的 `v8::Boolean` 类。

* **String:**
  ```javascript
  const myString = "hello";
  const emptyString = "";
  const multiLine = `This is a
  multi-line string`;
  ```
  对应 C++ 的 `v8::String` 类。  `NewFromUtf8`, `NewFromOneByte`, `NewFromTwoByte` 等方法用于在 V8 内部创建 JavaScript 字符串。

* **Symbol:**
  ```javascript
  const mySymbol = Symbol("mySymbol");
  const globalSymbol = Symbol.for("globalSymbol");
  const iteratorSymbol = Symbol.iterator;
  ```
  对应 C++ 的 `v8::Symbol` 类。 `New()`, `For()`, `GetIterator()` 等方法对应 JavaScript 中创建和访问符号的方式。

* **Number:**
  ```javascript
  const myNumber = 10;
  const floatNumber = 3.14;
  const negativeNumber = -5;
  ```
  对应 C++ 的 `v8::Number` 类。

* **BigInt:**
  ```javascript
  const bigIntValue = 9007199254740991n;
  const anotherBigInt = BigInt(12345678901234567890);
  ```
  对应 C++ 的 `v8::BigInt` 类。

**代码逻辑推理及假设输入输出：**

假设我们有一个 V8 的 `Isolate` 实例 `isolate`。

**示例 1：创建和获取布尔值**

```c++
v8::Local<v8::Boolean> trueValue = v8::Boolean::New(isolate, true);
bool cValue = trueValue->Value(); // 假设输入 isolate，输出 cValue 为 true
```

**示例 2：创建和获取字符串长度**

```c++
v8::Local<v8::String> myV8String = v8::String::NewFromUtf8(isolate, "example").ToLocalChecked();
int length = myV8String->Length(); // 假设输入 isolate 和字符串 "example"，输出 length 为 7
```

**示例 3：将字符串写入缓冲区**

```c++
v8::Local<v8::String> myV8String = v8::String::NewFromUtf8(isolate, "test").ToLocalChecked();
char buffer[5]; // 注意缓冲区大小
size_t written = myV8String->WriteUtf8V2(isolate, buffer, 5); // 假设输入 isolate 和字符串 "test"，输出 written 为 5 (包括空终止符)，buffer 内容为 "test\0"
```

**用户常见的编程错误：**

1. **缓冲区溢出：** 在使用 `Write` 系列函数时，提供的缓冲区大小不足以容纳字符串内容，可能导致内存错误。

   ```c++
   v8::Local<v8::String> longString = v8::String::NewFromUtf8(isolate, "This is a very long string").ToLocalChecked();
   char buffer[10];
   // 错误：缓冲区太小
   longString->WriteUtf8(isolate, buffer); // 可能导致缓冲区溢出
   ```

2. **未正确管理外部字符串资源的生命周期：**  如果使用 `ExternalStringResource`，需要确保资源在 V8 不再使用时被释放，避免内存泄漏。

   ```c++
   class MyStringResource : public v8::String::ExternalStringResource {
   public:
       MyStringResource(const uint16_t* data, size_t length) : data_(data), length_(length) {}
       ~MyStringResource() override { delete[] data_; } // 正确释放内存
       const uint16_t* data() const override { return data_; }
       size_t length() const override { return length_; }
   private:
       const uint16_t* data_;
       size_t length_;
   };

   // ...
   uint16_t* externalData = new uint16_t[5] { 'h', 'e', 'l', 'l', 'o' };
   v8::String::ExternalStringResource* resource = new MyStringResource(externalData, 5);
   v8::MaybeLocal<v8::String> externalString = v8::String::NewExternalTwoByte(isolate, resource);
   // ... 当 externalString 不再使用时，resource 会被 V8 内部释放，从而调用 ~MyStringResource()
   ```

3. **假设 `ValueView` 的数据一直有效：** `ValueView` 提供了零拷贝访问，但其指向的内存可能被垃圾回收器移动或释放，因此在使用 `ValueView` 时需要特别小心，确保在 `ValueView` 的生命周期内不会发生可能导致字符串对象被移动的垃圾回收。

   ```c++
   v8::Local<v8::String> myString = v8::String::NewFromUtf8(isolate, "data").ToLocalChecked();
   v8::String::ValueView view(isolate, myString);
   // ... 进行一些可能触发垃圾回收的操作 ...
   // 错误：此时 view 中的数据可能已经失效
   // const char* data = reinterpret_cast<const char*>(view.data8());
   ```

**这是第1部分，共2部分，请归纳一下它的功能**

总而言之，`v8/include/v8-primitive.h` 的主要功能是：

* **定义了 V8 中用于表示 JavaScript 原始值的 C++ 接口。**
* **提供了创建、访问和操作这些原始值的方法。**
* **抽象了不同类型的字符串表示和操作。**
* **为外部字符串数据提供了管理机制。**
* **为其他 V8 组件提供了与 JavaScript 原始值交互的基础。**

这个头文件是 V8 引擎核心类型系统的关键组成部分，使得 C++ 代码能够有效地与 JavaScript 的基本数据类型进行交互。

### 提示词
```
这是目录为v8/include/v8-primitive.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-primitive.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_PRIMITIVE_H_
#define INCLUDE_V8_PRIMITIVE_H_

#include "v8-data.h"          // NOLINT(build/include_directory)
#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-value.h"         // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class Context;
class Isolate;
class String;

namespace internal {
class ExternalString;
class ScopedExternalStringLock;
class StringForwardingTable;
}  // namespace internal

/**
 * The superclass of primitive values.  See ECMA-262 4.3.2.
 */
class V8_EXPORT Primitive : public Value {};

/**
 * A primitive boolean value (ECMA-262, 4.3.14).  Either the true
 * or false value.
 */
class V8_EXPORT Boolean : public Primitive {
 public:
  bool Value() const;
  V8_INLINE static Boolean* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Boolean*>(data);
  }

  V8_INLINE static Local<Boolean> New(Isolate* isolate, bool value);

 private:
  static void CheckCast(v8::Data* that);
};

/**
 * An array to hold Primitive values. This is used by the embedder to
 * pass host defined options to the ScriptOptions during compilation.
 *
 * This is passed back to the embedder as part of
 * HostImportModuleDynamicallyCallback for module loading.
 */
class V8_EXPORT PrimitiveArray : public Data {
 public:
  static Local<PrimitiveArray> New(Isolate* isolate, int length);
  int Length() const;
  void Set(Isolate* isolate, int index, Local<Primitive> item);
  Local<Primitive> Get(Isolate* isolate, int index);

  V8_INLINE static PrimitiveArray* Cast(Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return reinterpret_cast<PrimitiveArray*>(data);
  }

 private:
  static void CheckCast(Data* obj);
};

/**
 * A superclass for symbols and strings.
 */
class V8_EXPORT Name : public Primitive {
 public:
  /**
   * Returns the identity hash for this object. The current implementation
   * uses an inline property on the object to store the identity hash.
   *
   * The return value will never be 0. Also, it is not guaranteed to be
   * unique.
   */
  int GetIdentityHash();

  V8_INLINE static Name* Cast(Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Name*>(data);
  }

 private:
  static void CheckCast(Data* that);
};

/**
 * A flag describing different modes of string creation.
 *
 * Aside from performance implications there are no differences between the two
 * creation modes.
 */
enum class NewStringType {
  /**
   * Create a new string, always allocating new storage memory.
   */
  kNormal,

  /**
   * Acts as a hint that the string should be created in the
   * old generation heap space and be deduplicated if an identical string
   * already exists.
   */
  kInternalized
};

/**
 * A JavaScript string value (ECMA-262, 4.3.17).
 */
class V8_EXPORT String : public Name {
 public:
  static constexpr int kMaxLength =
      internal::kApiSystemPointerSize == 4 ? (1 << 28) - 16 : (1 << 29) - 24;

  enum Encoding {
    UNKNOWN_ENCODING = 0x1,
    TWO_BYTE_ENCODING = 0x0,
    ONE_BYTE_ENCODING = 0x8
  };
  /**
   * Returns the number of characters (UTF-16 code units) in this string.
   */
  int Length() const;

  /**
   * Returns the number of bytes in the UTF-8 encoded
   * representation of this string.
   */
  V8_DEPRECATE_SOON("Use Utf8LengthV2 instead.")
  int Utf8Length(Isolate* isolate) const;

  /**
   * Returns the number of bytes needed for the Utf8 encoding of this string.
   */
  size_t Utf8LengthV2(Isolate* isolate) const;

  /**
   * Returns whether this string is known to contain only one byte data,
   * i.e. ISO-8859-1 code points.
   * Does not read the string.
   * False negatives are possible.
   */
  bool IsOneByte() const;

  /**
   * Returns whether this string contain only one byte data,
   * i.e. ISO-8859-1 code points.
   * Will read the entire string in some cases.
   */
  bool ContainsOnlyOneByte() const;

  /**
   * Write the contents of the string to an external buffer.
   * If no arguments are given, expects the buffer to be large
   * enough to hold the entire string and NULL terminator. Copies
   * the contents of the string and the NULL terminator into the
   * buffer.
   *
   * WriteUtf8 will not write partial UTF-8 sequences, preferring to stop
   * before the end of the buffer.
   *
   * Copies up to length characters into the output buffer.
   * Only null-terminates if there is enough space in the buffer.
   *
   * \param buffer The buffer into which the string will be copied.
   * \param start The starting position within the string at which
   * copying begins.
   * \param length The number of characters to copy from the string.  For
   *    WriteUtf8 the number of bytes in the buffer.
   * \param nchars_ref The number of characters written, can be NULL.
   * \param options Various options that might affect performance of this or
   *    subsequent operations.
   * \return The number of characters copied to the buffer excluding the null
   *    terminator.  For WriteUtf8: The number of bytes copied to the buffer
   *    including the null terminator (if written).
   */
  enum WriteOptions {
    NO_OPTIONS = 0,
    HINT_MANY_WRITES_EXPECTED = 1,
    NO_NULL_TERMINATION = 2,
    PRESERVE_ONE_BYTE_NULL = 4,
    // Used by WriteUtf8 to replace orphan surrogate code units with the
    // unicode replacement character. Needs to be set to guarantee valid UTF-8
    // output.
    REPLACE_INVALID_UTF8 = 8
  };

  // 16-bit character codes.
  V8_DEPRECATE_SOON("Use WriteV2 instead.")
  int Write(Isolate* isolate, uint16_t* buffer, int start = 0, int length = -1,
            int options = NO_OPTIONS) const;
  // One byte characters.
  V8_DEPRECATE_SOON("Use WriteOneByteV2 instead.")
  int WriteOneByte(Isolate* isolate, uint8_t* buffer, int start = 0,
                   int length = -1, int options = NO_OPTIONS) const;
  // UTF-8 encoded characters.
  V8_DEPRECATE_SOON("Use WriteUtf8V2 instead.")
  int WriteUtf8(Isolate* isolate, char* buffer, int length = -1,
                int* nchars_ref = nullptr, int options = NO_OPTIONS) const;

  struct WriteFlags {
    enum {
      kNone = 0,
      // Indicates that the output string should be null-terminated. In that
      // case, the output buffer must include sufficient space for the
      // additional null character.
      kNullTerminate = 1,
      // Used by WriteUtf8 to replace orphan surrogate code units with the
      // unicode replacement character. Needs to be set to guarantee valid UTF-8
      // output.
      kReplaceInvalidUtf8 = 2
    };
  };

  /**
   * Write the contents of the string to an external buffer.
   *
   * Copies length characters into the output buffer starting at offset. The
   * output buffer must have sufficient space for all characters and the null
   * terminator if null termination is requested through the flags.
   *
   * \param offset The position within the string at which copying begins.
   * \param length The number of characters to copy from the string.
   * \param buffer The buffer into which the string will be copied.
   * \param flags Various flags that influence the behavior of this operation.
   */
  void WriteV2(Isolate* isolate, uint32_t offset, uint32_t length,
               uint16_t* buffer, int flags = WriteFlags::kNone) const;
  void WriteOneByteV2(Isolate* isolate, uint32_t offset, uint32_t length,
                      uint8_t* buffer, int flags = WriteFlags::kNone) const;

  /**
   * Encode the contents of the string as Utf8 into an external buffer.
   *
   * Encodes the characters of this string as Utf8 and writes them into the
   * output buffer until either all characters were encoded or the buffer is
   * full. Will not write partial UTF-8 sequences, preferring to stop before
   * the end of the buffer. If null termination is requested, the output buffer
   * will always be null terminated even if not all characters fit. In that
   * case, the capacity must be at least one. The required size of the output
   * buffer can be determined using Utf8Length().
   *
   * \param buffer The buffer into which the string will be written.
   * \param capacity The number of bytes available in the output buffer.
   * \param flags Various flags that influence the behavior of this operation.
   * \return The number of bytes copied to the buffer including the null
   * terminator (if written).
   */
  size_t WriteUtf8V2(Isolate* isolate, char* buffer, size_t capacity,
                     int flags = WriteFlags::kNone) const;

  /**
   * A zero length string.
   */
  V8_INLINE static Local<String> Empty(Isolate* isolate);

  /**
   * Returns true if the string is external.
   */
  bool IsExternal() const;

  /**
   * Returns true if the string is both external and two-byte.
   */
  bool IsExternalTwoByte() const;

  /**
   * Returns true if the string is both external and one-byte.
   */
  bool IsExternalOneByte() const;

  /**
   * Returns the internalized string. See `NewStringType::kInternalized` for
   * details on internalized strings.
   */
  Local<String> InternalizeString(Isolate* isolate);

  class V8_EXPORT ExternalStringResourceBase {
   public:
    virtual ~ExternalStringResourceBase() = default;

    /**
     * If a string is cacheable, the value returned by
     * ExternalStringResource::data() may be cached, otherwise it is not
     * expected to be stable beyond the current top-level task.
     */
    virtual bool IsCacheable() const { return true; }

    /**
     * Internally V8 will call this Unaccount method when the external string
     * resource should be unaccounted for. This method can be overridden in
     * subclasses to control how allocated external bytes are accounted.
     */
    virtual void Unaccount(Isolate* isolate) {}

    // Disallow copying and assigning.
    ExternalStringResourceBase(const ExternalStringResourceBase&) = delete;
    void operator=(const ExternalStringResourceBase&) = delete;

   protected:
    ExternalStringResourceBase() = default;

    /**
     * Internally V8 will call this Dispose method when the external string
     * resource is no longer needed. The default implementation will use the
     * delete operator. This method can be overridden in subclasses to
     * control how allocated external string resources are disposed.
     */
    virtual void Dispose() { delete this; }

    /**
     * For a non-cacheable string, the value returned by
     * |ExternalStringResource::data()| has to be stable between |Lock()| and
     * |Unlock()|, that is the string must behave as is |IsCacheable()| returned
     * true.
     *
     * These two functions must be thread-safe, and can be called from anywhere.
     * They also must handle lock depth, in the sense that each can be called
     * several times, from different threads, and unlocking should only happen
     * when the balance of Lock() and Unlock() calls is 0.
     */
    virtual void Lock() const {}

    /**
     * Unlocks the string.
     */
    virtual void Unlock() const {}

   private:
    friend class internal::ExternalString;
    friend class v8::String;
    friend class internal::StringForwardingTable;
    friend class internal::ScopedExternalStringLock;
  };

  /**
   * An ExternalStringResource is a wrapper around a two-byte string
   * buffer that resides outside V8's heap. Implement an
   * ExternalStringResource to manage the life cycle of the underlying
   * buffer.  Note that the string data must be immutable.
   */
  class V8_EXPORT ExternalStringResource : public ExternalStringResourceBase {
   public:
    /**
     * Override the destructor to manage the life cycle of the underlying
     * buffer.
     */
    ~ExternalStringResource() override = default;

    /**
     * The string data from the underlying buffer. If the resource is cacheable
     * then data() must return the same value for all invocations.
     */
    virtual const uint16_t* data() const = 0;

    /**
     * The length of the string. That is, the number of two-byte characters.
     */
    virtual size_t length() const = 0;

    /**
     * Returns the cached data from the underlying buffer. This method can be
     * called only for cacheable resources (i.e. IsCacheable() == true) and only
     * after UpdateDataCache() was called.
     */
    const uint16_t* cached_data() const {
      CheckCachedDataInvariants();
      return cached_data_;
    }

    /**
     * Update {cached_data_} with the data from the underlying buffer. This can
     * be called only for cacheable resources.
     */
    void UpdateDataCache();

   protected:
    ExternalStringResource() = default;

   private:
    void CheckCachedDataInvariants() const;

    const uint16_t* cached_data_ = nullptr;
  };

  /**
   * An ExternalOneByteStringResource is a wrapper around an one-byte
   * string buffer that resides outside V8's heap. Implement an
   * ExternalOneByteStringResource to manage the life cycle of the
   * underlying buffer.  Note that the string data must be immutable
   * and that the data must be Latin-1 and not UTF-8, which would require
   * special treatment internally in the engine and do not allow efficient
   * indexing.  Use String::New or convert to 16 bit data for non-Latin1.
   */

  class V8_EXPORT ExternalOneByteStringResource
      : public ExternalStringResourceBase {
   public:
    /**
     * Override the destructor to manage the life cycle of the underlying
     * buffer.
     */
    ~ExternalOneByteStringResource() override = default;

    /**
     * The string data from the underlying buffer. If the resource is cacheable
     * then data() must return the same value for all invocations.
     */
    virtual const char* data() const = 0;

    /** The number of Latin-1 characters in the string.*/
    virtual size_t length() const = 0;

    /**
     * Returns the cached data from the underlying buffer. If the resource is
     * uncacheable or if UpdateDataCache() was not called before, it has
     * undefined behaviour.
     */
    const char* cached_data() const {
      CheckCachedDataInvariants();
      return cached_data_;
    }

    /**
     * Update {cached_data_} with the data from the underlying buffer. This can
     * be called only for cacheable resources.
     */
    void UpdateDataCache();

   protected:
    ExternalOneByteStringResource() = default;

   private:
    void CheckCachedDataInvariants() const;

    const char* cached_data_ = nullptr;
  };

  /**
   * If the string is an external string, return the ExternalStringResourceBase
   * regardless of the encoding, otherwise return NULL.  The encoding of the
   * string is returned in encoding_out.
   */
  V8_INLINE ExternalStringResourceBase* GetExternalStringResourceBase(
      v8::Isolate* isolate, Encoding* encoding_out) const;
  V8_INLINE ExternalStringResourceBase* GetExternalStringResourceBase(
      Encoding* encoding_out) const;

  /**
   * Get the ExternalStringResource for an external string.  Returns
   * NULL if IsExternal() doesn't return true.
   */
  V8_INLINE ExternalStringResource* GetExternalStringResource() const;

  /**
   * Get the ExternalOneByteStringResource for an external one-byte string.
   * Returns NULL if IsExternalOneByte() doesn't return true.
   */
  const ExternalOneByteStringResource* GetExternalOneByteStringResource() const;

  V8_INLINE static String* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<String*>(data);
  }

  /**
   * Allocates a new string from a UTF-8 literal. This is equivalent to calling
   * String::NewFromUtf(isolate, "...").ToLocalChecked(), but without the check
   * overhead.
   *
   * When called on a string literal containing '\0', the inferred length is the
   * length of the input array minus 1 (for the final '\0') and not the value
   * returned by strlen.
   **/
  template <int N>
  static V8_WARN_UNUSED_RESULT Local<String> NewFromUtf8Literal(
      Isolate* isolate, const char (&literal)[N],
      NewStringType type = NewStringType::kNormal) {
    static_assert(N <= kMaxLength, "String is too long");
    return NewFromUtf8Literal(isolate, literal, type, N - 1);
  }

  /** Allocates a new string from UTF-8 data. Only returns an empty value when
   * length > kMaxLength. **/
  static V8_WARN_UNUSED_RESULT MaybeLocal<String> NewFromUtf8(
      Isolate* isolate, const char* data,
      NewStringType type = NewStringType::kNormal, int length = -1);

  /** Allocates a new string from Latin-1 data.  Only returns an empty value
   * when length > kMaxLength. **/
  static V8_WARN_UNUSED_RESULT MaybeLocal<String> NewFromOneByte(
      Isolate* isolate, const uint8_t* data,
      NewStringType type = NewStringType::kNormal, int length = -1);

  /** Allocates a new string from UTF-16 data. Only returns an empty value when
   * length > kMaxLength. **/
  static V8_WARN_UNUSED_RESULT MaybeLocal<String> NewFromTwoByte(
      Isolate* isolate, const uint16_t* data,
      NewStringType type = NewStringType::kNormal, int length = -1);

  /**
   * Creates a new string by concatenating the left and the right strings
   * passed in as parameters.
   */
  static Local<String> Concat(Isolate* isolate, Local<String> left,
                              Local<String> right);

  /**
   * Creates a new external string using the data defined in the given
   * resource. When the external string is no longer live on V8's heap the
   * resource will be disposed by calling its Dispose method. The caller of
   * this function should not otherwise delete or modify the resource. Neither
   * should the underlying buffer be deallocated or modified except through the
   * destructor of the external string resource.
   */
  static V8_WARN_UNUSED_RESULT MaybeLocal<String> NewExternalTwoByte(
      Isolate* isolate, ExternalStringResource* resource);

  /**
   * Associate an external string resource with this string by transforming it
   * in place so that existing references to this string in the JavaScript heap
   * will use the external string resource. The external string resource's
   * character contents need to be equivalent to this string.
   * Returns true if the string has been changed to be an external string.
   * The string is not modified if the operation fails. See NewExternal for
   * information on the lifetime of the resource.
   */
  V8_DEPRECATE_SOON("Use the version with the isolate argument instead.")
  bool MakeExternal(ExternalStringResource* resource);

  /**
   * Associate an external string resource with this string by transforming it
   * in place so that existing references to this string in the JavaScript heap
   * will use the external string resource. The external string resource's
   * character contents need to be equivalent to this string.
   * Returns true if the string has been changed to be an external string.
   * The string is not modified if the operation fails. See NewExternal for
   * information on the lifetime of the resource.
   */
  bool MakeExternal(Isolate* isolate, ExternalStringResource* resource);

  /**
   * Creates a new external string using the one-byte data defined in the given
   * resource. When the external string is no longer live on V8's heap the
   * resource will be disposed by calling its Dispose method. The caller of
   * this function should not otherwise delete or modify the resource. Neither
   * should the underlying buffer be deallocated or modified except through the
   * destructor of the external string resource.
   */
  static V8_WARN_UNUSED_RESULT MaybeLocal<String> NewExternalOneByte(
      Isolate* isolate, ExternalOneByteStringResource* resource);

  /**
   * Associate an external string resource with this string by transforming it
   * in place so that existing references to this string in the JavaScript heap
   * will use the external string resource. The external string resource's
   * character contents need to be equivalent to this string.
   * Returns true if the string has been changed to be an external string.
   * The string is not modified if the operation fails. See NewExternal for
   * information on the lifetime of the resource.
   */
  V8_DEPRECATE_SOON("Use the version with the isolate argument instead.")
  bool MakeExternal(ExternalOneByteStringResource* resource);

  /**
   * Associate an external string resource with this string by transforming it
   * in place so that existing references to this string in the JavaScript heap
   * will use the external string resource. The external string resource's
   * character contents need to be equivalent to this string.
   * Returns true if the string has been changed to be an external string.
   * The string is not modified if the operation fails. See NewExternal for
   * information on the lifetime of the resource.
   */
  bool MakeExternal(Isolate* isolate, ExternalOneByteStringResource* resource);

  /**
   * Returns true if this string can be made external, given the encoding for
   * the external string resource.
   */
  bool CanMakeExternal(Encoding encoding) const;

  /**
   * Returns true if the strings values are equal. Same as JS ==/===.
   */
  bool StringEquals(Local<String> str) const;

  /**
   * Converts an object to a UTF-8-encoded character array.  Useful if
   * you want to print the object.  If conversion to a string fails
   * (e.g. due to an exception in the toString() method of the object)
   * then the length() method returns 0 and the * operator returns
   * NULL.
   *
   * WARNING: This will unconditionally copy the contents of the JavaScript
   * string, and should be avoided in situations where performance is a concern.
   * Consider using WriteUtf8() instead.
   */
  class V8_EXPORT Utf8Value {
   public:
    Utf8Value(Isolate* isolate, Local<v8::Value> obj,
              WriteOptions options = REPLACE_INVALID_UTF8);
    ~Utf8Value();
    char* operator*() { return str_; }
    const char* operator*() const { return str_; }
    size_t length() const { return length_; }

    // Disallow copying and assigning.
    Utf8Value(const Utf8Value&) = delete;
    void operator=(const Utf8Value&) = delete;

   private:
    char* str_;
    size_t length_;
  };

  /**
   * Converts an object to a two-byte (UTF-16-encoded) string.
   *
   * If conversion to a string fails (eg. due to an exception in the toString()
   * method of the object) then the length() method returns 0 and the * operator
   * returns NULL.
   *
   * WARNING: This will unconditionally copy the contents of the JavaScript
   * string, and should be avoided in situations where performance is a concern.
   */
  class V8_EXPORT Value {
   public:
    V8_DEPRECATE_SOON(
        "Prefer using String::ValueView if you can, or string->Write to a "
        "buffer if you cannot.")
    Value(Isolate* isolate, Local<v8::Value> obj);
    ~Value();
    uint16_t* operator*() { return str_; }
    const uint16_t* operator*() const { return str_; }
    uint32_t length() const { return length_; }

    // Disallow copying and assigning.
    Value(const Value&) = delete;
    void operator=(const Value&) = delete;

   private:
    uint16_t* str_;
    uint32_t length_;
  };

  /**
   * Returns a view onto a string's contents.
   *
   * WARNING: This does not copy the string's contents, and will therefore be
   * invalidated if the GC can move the string while the ValueView is alive. It
   * is therefore required that no GC or allocation can happen while there is an
   * active ValueView. This requirement may be relaxed in the future.
   *
   * V8 strings are either encoded as one-byte or two-bytes per character.
   */
  class V8_EXPORT ValueView {
   public:
    ValueView(Isolate* isolate, Local<v8::String> str);
    ~ValueView();
    const uint8_t* data8() const {
#if V8_ENABLE_CHECKS
      CheckOneByte(true);
#endif
      return data8_;
    }
    const uint16_t* data16() const {
#if V8_ENABLE_CHECKS
      CheckOneByte(false);
#endif
      return data16_;
    }
    uint32_t length() const { return length_; }
    bool is_one_byte() const { return is_one_byte_; }

    // Disallow copying and assigning.
    ValueView(const ValueView&) = delete;
    void operator=(const ValueView&) = delete;

   private:
    void CheckOneByte(bool is_one_byte) const;

    Local<v8::String> flat_str_;
    union {
      const uint8_t* data8_;
      const uint16_t* data16_;
    };
    uint32_t length_;
    bool is_one_byte_;
    // Avoid exposing the internal DisallowGarbageCollection scope.
    alignas(internal::Internals::
                kDisallowGarbageCollectionAlign) char no_gc_debug_scope_
        [internal::Internals::kDisallowGarbageCollectionSize];
  };

 private:
  void VerifyExternalStringResourceBase(ExternalStringResourceBase* v,
                                        Encoding encoding) const;
  void VerifyExternalStringResource(ExternalStringResource* val) const;
  ExternalStringResource* GetExternalStringResourceSlow() const;
  ExternalStringResourceBase* GetExternalStringResourceBaseSlow(
      String::Encoding* encoding_out) const;

  static Local<v8::String> NewFromUtf8Literal(Isolate* isolate,
                                              const char* literal,
                                              NewStringType type, int length);

  static void CheckCast(v8::Data* that);
};

// Zero-length string specialization (templated string size includes
// terminator).
template <>
inline V8_WARN_UNUSED_RESULT Local<String> String::NewFromUtf8Literal(
    Isolate* isolate, const char (&literal)[1], NewStringType type) {
  return String::Empty(isolate);
}

/**
 * Interface for iterating through all external resources in the heap.
 */
class V8_EXPORT ExternalResourceVisitor {
 public:
  virtual ~ExternalResourceVisitor() = default;
  virtual void VisitExternalString(Local<String> string) {}
};

/**
 * A JavaScript symbol (ECMA-262 edition 6)
 */
class V8_EXPORT Symbol : public Name {
 public:
  /**
   * Returns the description string of the symbol, or undefined if none.
   */
  Local<Value> Description(Isolate* isolate) const;

  /**
   * Create a symbol. If description is not empty, it will be used as the
   * description.
   */
  static Local<Symbol> New(Isolate* isolate,
                           Local<String> description = Local<String>());

  /**
   * Access global symbol registry.
   * Note that symbols created this way are never collected, so
   * they should only be used for statically fixed properties.
   * Also, there is only one global name space for the descriptions used as
   * keys.
   * To minimize the potential for clashes, use qualified names as keys.
   */
  static Local<Symbol> For(Isolate* isolate, Local<String> description);

  /**
   * Retrieve a global symbol. Similar to |For|, but using a separate
   * registry that is not accessible by (and cannot clash with) JavaScript code.
   */
  static Local<Symbol> ForApi(Isolate* isolate, Local<String> description);

  // Well-known symbols
  static Local<Symbol> GetAsyncIterator(Isolate* isolate);
  static Local<Symbol> GetHasInstance(Isolate* isolate);
  static Local<Symbol> GetIsConcatSpreadable(Isolate* isolate);
  static Local<Symbol> GetIterator(Isolate* isolate);
  static Local<Symbol> GetMatch(Isolate* isolate);
  static Local<Symbol> GetReplace(Isolate* isolate);
  static Local<Symbol> GetSearch(Isolate* isolate);
  static Local<Symbol> GetSplit(Isolate* isolate);
  static Local<Symbol> GetToPrimitive(Isolate* isolate);
  static Local<Symbol> GetToStringTag(Isolate* isolate);
  static Local<Symbol> GetUnscopables(Isolate* isolate);

  V8_INLINE static Symbol* Cast(Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Symbol*>(data);
  }

 private:
  Symbol();
  static void CheckCast(Data* that);
};

/**
 * A JavaScript numeric value (either Number or BigInt).
 * https://tc39.es/ecma262/#sec-numeric-types
 */
class V8_EXPORT Numeric : public Primitive {
 private:
  Numeric();
  static void CheckCast(v8::Data* that);
};

/**
 * A JavaScript number value (ECMA-262, 4.3.20)
 */
class V8_EXPORT Number : public Numeric {
 public:
  double Value() const;
  static Local<Number> New(Isolate* isolate, double value);
  V8_INLINE static Number* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Number*>(data);
  }

 private:
  Number();
  static void CheckCast(v8::Data* that);
};

/**
 * A JavaScript value representing a signed integer.
 */
class V8_EXPORT Integer : public Number {
 public:
  static Local<Integer> New(Isolate* isolate, int32_t value);
  static Local<Integer> NewFromUnsigned(Isolate* isolate, uint32_t value);
  int64_t Value() const;
  V8_INLINE static Integer* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Integer*>(data);
  }

 private:
  Integer();
  static void CheckCast(v8::Data* that);
};

/**
 * A JavaScript value representing a 32-bit signed integer.
 */
class V8_EXPORT Int32 : public Integer {
 public:
  int32_t Value() const;
  V8_INLINE static Int32* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Int32*>(data);
  }

 private:
  Int32();
  static void CheckCast(v8::Data* that);
};

/**
 * A JavaScript value representing a 32-bit unsigned integer.
 */
class V8_EXPORT Uint32 : public Integer {
 public:
  uint32_t Value() const;
  V8_INLINE static Uint32* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<Uint32*>(data);
  }

 private:
  Uint32();
  static void CheckCast(v8::Data* that);
};

/**
 * A JavaScript BigInt value (https://tc39.github.io/proposal-bigint)
 */
class V8_EXPORT BigInt : public Numeric {
 public:
  static Local<BigInt> New(Isolate* isolate, int64_t value);
  static Local<BigInt> NewFromUnsigned(Isolate* isolate, uint64_t value);
  /**
   * Creates a new BigInt object using a specified sign bit and a
   * specified list of digits/words.
   * The resulting number is calculated as:
   *
   * (-1)^sign_bit * (words[0] * (2^64)^0 + words[1] * (2^64)^1 + ...)
   */
  static MaybeLocal<BigInt> NewFromWords(Local<Context> context, int sign_bit,
                                         int word_count, const uint64_t* words);

  /**
   * Returns the value of this BigInt as an unsigned 64-bit integer.
   * If `lossless` is provided, it will reflect whether the return value was
   * truncated or wrapped around. In particular, it is set to `false` if this
   * BigInt is negative.
   */
  uint64_t Uint64Value(bool* lossless = nullptr) const;

  /**
   * Returns the value of this BigInt as a signed 64-bit integer.
   * If `lossless` is provided, it will reflect whether this BigInt was
   * truncated or not.
   */
  int64_t Int64Value(bool* lossless = nullptr) const;

  /**
   * Returns the number of 64-bit words needed to store the result of
   * ToWordsArray().
   */
  int WordCount() const;

  /**
   * Writes the contents of this BigInt to a specified memory location.
   * `sign_bit` must be provided and will be set to 1 if this BigInt is
   * negative.
   * `*word_count` has to be initialized to the length of the `words` array.
   * Upon return, it will be set to the actual number of words that would
   * be needed to store this BigInt (i.e. the return value of `WordCount()`).
   */
  void ToWordsArray(int* sign_bit, int* word_count, uint64_t* words) const;

  V8_INLINE static BigInt* Cast(v8::Data* data) {
#ifdef V8_ENABLE_CHECKS
    CheckCast(data);
#endif
    return static_cast<BigInt*>(data);
  }

 private:
  BigInt();
  static void CheckCast(v8::Data* that);
};

Local<String> String::Empty(Isolate* isolate) {
  using S = internal::Address;
  using I = internal::Internals;
  I::CheckInitialized(isolate);
  S* slot = I::GetRootSlot(isolate, I::kEmptyStringRootIndex);
  return Local<String>::FromSlot(slot);
}

String::ExternalStringResource* String::GetExternalStringResource() const {
  using A = internal::Address;
  using I = internal::Internals;
  A obj = internal::ValueHelper::ValueAsAddress(this);

  ExternalStringResource* result;
  if (I::IsExternalTwoByteString(I::GetInstanceType(obj))) {
    Isolate* isolate = I::GetIsolateForSandbox(obj);
    A value = I::ReadExternalPointerField<internal::kExternalStringResourceTag>(
        isolate, obj, I::kStringResourceOffset);
    result = reinterpret_cast<String::ExternalStringResource*>(value);
  }
```