Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/api/api.cc` file. I need to analyze the code and identify its key responsibilities.

Here's a breakdown of the code's functionality:

1. **Function Compilation Check:** The initial function `IsAsyncFunction` checks if a given JavaScript function is an empty async function by inspecting its bytecode.
2. **Function Prototype to String:** The `FunctionProtoToString` function retrieves the string representation of a function's prototype by calling an internal V8 built-in.
3. **String Properties:**  Several functions (`GetIdentityHash`, `Length`, `IsOneByte`) provide access to basic properties of V8 strings.
4. **One-Byte String Optimization:** The `ContainsOnlyOneByteHelper` class and the `ContainsOnlyOneByte` method implement an optimization to efficiently check if a string contains only single-byte characters. This involves checking both flat and cons (concatenated) strings.
5. **UTF-8 Length Calculation:** The `Utf8Length` and `Utf8LengthV2` functions calculate the length of a V8 string when encoded in UTF-8. They handle both one-byte and two-byte string representations.
6. **UTF-8 Writing:** The `WriteUtf8Impl` template function and the `WriteUtf8` method provide functionality to write the contents of a V8 string to a character buffer as UTF-8. They handle buffer capacity limitations and options like null termination and replacing invalid UTF-8 sequences.
7. **String Writing (One-Byte and Two-Byte):** The `WriteHelper`, `WriteOneByte`, and `Write` functions allow writing the raw character data of a V8 string (either one-byte or two-byte) to a buffer.
8. **String Writing V2 (One-Byte and Two-Byte):** The `WriteHelperV2`, `WriteV2`, and `WriteOneByteV2` functions provide an alternative API for writing string data to a buffer with offset and length parameters.
9. **UTF-8 Writing V2:** The `WriteUtf8V2` function provides an alternative API for writing a string to a UTF-8 buffer with flags for null termination and invalid character replacement.
10. **External String Handling:** Several functions (`HasExternalStringResource`, `GetExternalResourceFromForwardingTable`, `IsExternal`, `IsExternalTwoByte`, `IsExternalOneByte`, `InternalizeString`, `VerifyExternalStringResource`, `VerifyExternalStringResourceBase`, `GetExternalStringResourceSlow`, `GetExternalStringResourceBaseSlow`, `GetExternalOneByteStringResource`) deal with strings that have their underlying data stored externally (outside of V8's heap). This is a mechanism for efficient handling of large strings.
11. **External String Resource Management:**  The `ExternalStringResource`, `ExternalOneByteStringResource` classes, and their methods (`UpdateDataCache`, `CheckCachedDataInvariants`) manage the lifecycle and caching of data for external strings.
12. **Symbol Description:** The `Description` method for `Symbol` retrieves the description associated with a symbol.
13. **Private Symbol Name:** The `Name` method for `Private` (a type of symbol) retrieves its name (which is its description).
14. **Value Retrieval for Primitive Types:** Functions like `Value` for `Number`, `Boolean`, `Integer`, `Int32`, and `Uint32` extract the primitive value from these V8 objects.
15. **Object Internal Fields:**  Functions like `InternalFieldCount`, `SlowGetInternalField`, `SetInternalField`, `SlowGetAlignedPointerFromInternalField`, and `SetAlignedPointerInInternalField`, `SetAlignedPointerInInternalFields` provide access to and manipulation of internal fields of V8 objects, which can be used by embedders to associate native data with JavaScript objects.
16. **Object Wrapping and Unwrapping:** The `Wrap` and `Unwrap` functions facilitate the association of C++ objects with JavaScript objects.
17. **Platform Initialization and Disposal:** The `InitializePlatform` and `DisposePlatform` functions manage the interaction with the underlying platform.
18. **V8 Initialization:** The `Initialize` function performs crucial initialization steps for the V8 engine, including checking for build configuration mismatches between the embedder and V8.

Given that this is part 8 of 15, it likely focuses on a specific set of related functionalities within the broader V8 API. This section seems to heavily concentrate on **string manipulation and handling, especially regarding different encodings and external string resources, as well as access to object internals and basic primitive value retrieval.**

Regarding the format and potential questions:

*   **.tq extension:** The code is in `.cc`, so it's standard C++ source code, not Torque.
*   **JavaScript relationship:** Many of the functions directly relate to how JavaScript strings and functions are represented and manipulated within the V8 engine.
*   **Code logic and assumptions:** Some functions involve bitwise operations and pointer manipulations, which rely on the internal memory layout of V8 objects.
*   **Common programming errors:** Incorrect buffer sizes when writing strings, mismanaging external string resources, and out-of-bounds access to internal fields are potential errors.
这是 `v8/src/api/api.cc` 文件的第 8 部分，主要关注 V8 API 中关于 **函数、字符串和对象** 的操作。

**主要功能归纳:**

1. **函数（Function）:**
    *   **`IsAsyncFunction`:**  检查一个 JavaScript 函数是否是简单的 `async function() {}` 形式。它通过检查函数的字节码来实现。
    *   **`FunctionProtoToString`:** 获取函数原型对象的字符串表示形式，相当于在 JavaScript 中调用 `Function.prototype.toString()`。

2. **字符串（String）:**
    *   **`GetIdentityHash`:** 获取字符串的标识哈希值。
    *   **`Length`:** 获取字符串的长度（字符数）。
    *   **`IsOneByte`:** 判断字符串是否使用单字节编码（Latin-1）。
    *   **`ContainsOnlyOneByte`:**  更高效地检查字符串是否只包含单字节字符，包括处理由多个字符串片段组成的 `ConsString`。
    *   **`Utf8Length` 和 `Utf8LengthV2`:** 计算字符串以 UTF-8 编码时的字节长度。
    *   **`WriteUtf8`:** 将字符串的内容以 UTF-8 编码写入到指定的缓冲区。可以控制是否添加 null 终止符，并处理无效的 UTF-8 字符。
    *   **`WriteOneByte` 和 `Write`:**  将字符串的内容以单字节或双字节（取决于字符串的编码）形式写入到指定的缓冲区。
    *   **`WriteV2` 和 `WriteOneByteV2`:**  提供更灵活的字符串写入方式，可以指定写入的偏移量和长度。
    *   **`WriteUtf8V2`:** 类似于 `WriteUtf8`，但使用不同的标志位来控制行为。
    *   **`IsExternal`，`IsExternalTwoByte`，`IsExternalOneByte`:** 判断字符串是否是外部字符串（其数据存储在 V8 堆外）。
    *   **`InternalizeString`:** 将字符串添加到 V8 内部字符串池中，如果池中已存在相同的字符串，则返回池中的引用。
    *   **`VerifyExternalStringResource` 和 `VerifyExternalStringResourceBase`:** 验证外部字符串的资源是否与预期一致。
    *   **`GetExternalStringResourceSlow` 和 `GetExternalStringResourceBaseSlow`:** 获取外部字符串的资源指针。
    *   **`GetExternalOneByteStringResource`:** 获取单字节外部字符串的资源指针。
    *   **`ExternalStringResource` 和 `ExternalOneByteStringResource` 相关的成员函数:** 用于管理外部字符串资源的缓存。

3. **符号（Symbol）和私有属性（Private）:**
    *   **`Description` (Symbol):** 获取符号的描述信息。
    *   **`Name` (Private):** 获取私有属性的名称（实际上也是其描述信息）。

4. **原始值类型（Number, Boolean, Integer, Int32, Uint32）:**
    *   **`Value`:**  提供获取这些类型对象对应原始值的方法。

5. **对象（Object）:**
    *   **`InternalFieldCount`:** 获取对象的内部字段数量（用于嵌入器数据）。
    *   **`SlowGetInternalField` 和 `SetInternalField`:** 获取和设置对象的内部字段值。
    *   **`SlowGetAlignedPointerFromInternalField` 和 `SetAlignedPointerInInternalField`，`SetAlignedPointerInInternalFields`:**  获取和设置对象内部字段中对齐的指针。这通常用于存储 C++ 对象的指针。
    *   **`Unwrap`:**  从 JavaScript 对象中解包之前用 `Wrap` 包装的 C++ 对象。
    *   **`Wrap`:** 将 C++ 对象包装到 JavaScript 对象中，以便在 JavaScript 中访问。

6. **环境（Environment）:**
    *   **`InitializePlatform` 和 `DisposePlatform`:**  用于初始化和清理 V8 使用的平台抽象层。
    *   **`Initialize`:**  执行 V8 引擎的初始化工作，包括检查编译配置。

**如果 `v8/src/api/api.cc` 以 `.tq` 结尾:**

这将意味着该文件是用 **Torque** 编写的。Torque 是 V8 用来定义其内置函数和类型的一种领域特定语言。如果文件是 `.tq`，那么其中的代码将会是 Torque 语法，而不是 C++。然而，根据您提供的信息，该文件是 `.cc`，所以它是 C++ 源代码。

**与 JavaScript 功能的关系及示例:**

许多函数都直接对应于 JavaScript 中可执行的操作或表示的概念：

*   **`FunctionProtoToString`:**

    ```javascript
    function myFunction() {}
    console.log(myFunction.prototype.toString()); // 输出 "[object Object]" (默认情况)
    ```

*   **`String::Length`:**

    ```javascript
    const str = "hello";
    console.log(str.length); // 输出 5
    ```

*   **`String::IsOneByte` 和 `String::ContainsOnlyOneByte`:**  虽然 JavaScript 没有直接的方法来检查字符串的内部编码，但 V8 内部会根据字符串的内容使用不同的表示。

*   **`String::WriteUtf8`:**  类似于在 Node.js 中使用 `Buffer.from(str, 'utf8')`。

*   **`Symbol::Description`:**

    ```javascript
    const mySymbol = Symbol("my description");
    console.log(mySymbol.description); // 输出 "my description"
    ```

*   **`Object::InternalFieldCount`，`SlowGetInternalField`，`SetInternalField`:**  这些功能与 Node.js 中的 `process.binding('util').getInternalProperties(obj)` 获取的内部属性类似，但更底层，通常由嵌入器使用。

*   **`Object::Wrap` 和 `Object::Unwrap`:**  这在 Node.js 的 C++ 插件开发中很常见，用于在 JavaScript 和 C++ 之间传递对象。

**代码逻辑推理及假设输入输出:**

*   **`IsAsyncFunction` 示例:**
    *   **假设输入:** 一个表示 JavaScript 函数 `async function() {}` 的 `v8::Function` 对象。
    *   **输出:** `true`，因为该函数的字节码符合预期的模式（加载 undefined 并返回）。
    *   **假设输入:** 一个表示 JavaScript 函数 `async function foo() { await Promise.resolve(); }` 的 `v8::Function` 对象。
    *   **输出:** `false`，因为该函数的字节码会更复杂。

*   **`ContainsOnlyOneByte` 示例:**
    *   **假设输入:** 一个表示字符串 `"hello"` 的 `v8::String` 对象。
    *   **输出:** `true`，因为所有字符都是单字节的。
    *   **假设输入:** 一个表示字符串 `"你好"` 的 `v8::String` 对象。
    *   **输出:** `false`，因为包含双字节字符。

*   **`Utf8Length` 示例:**
    *   **假设输入:** 一个表示字符串 `"hello"` 的 `v8::String` 对象。
    *   **输出:** `5`。
    *   **假设输入:** 一个表示字符串 `"你好"` 的 `v8::String` 对象。
    *   **输出:** `6` (每个汉字通常占用 3 个 UTF-8 字节)。

**用户常见的编程错误:**

*   在使用 `WriteUtf8` 等函数时，提供的缓冲区大小不足以容纳字符串的内容，导致数据截断或缓冲区溢出。
*   在处理外部字符串时，没有正确管理外部资源的生命周期，可能导致悬挂指针或内存泄漏。
*   错误地计算或使用内部字段的索引，导致访问越界。
*   在 `Wrap` 和 `Unwrap` C++ 对象时，类型转换错误或生命周期管理不当。

**总结第 8 部分的功能:**

第 8 部分的 `v8/src/api/api.cc` 主要提供了 V8 API 中用于操作 **函数、字符串和对象** 的核心功能。它涵盖了字符串的属性获取、编码转换、内容写入，以及对外部字符串的管理。此外，它还包括了访问对象内部字段、关联 C++ 对象与 JavaScript 对象的功能，以及对基本原始值类型的操作。这些功能是 V8 引擎暴露给嵌入器（如 Node.js 或 Chrome）的关键接口，用于实现 JavaScript 的底层操作和与 C++ 代码的互操作。

### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
if (!is_compiled_scope.is_compiled() &&
      !i::Compiler::Compile(i_isolate, i::handle(sfi, i_isolate),
                            i::Compiler::CLEAR_EXCEPTION, &is_compiled_scope)) {
    return false;
  }
  DCHECK(is_compiled_scope.is_compiled());
  // Since |sfi| can be GC'ed, we get it again.
  sfi = i::Cast<i::JSFunction>(*self)->shared();
  if (!sfi->HasBytecodeArray()) return false;
  i::Handle<i::BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate),
                                             i_isolate);
  i::interpreter::BytecodeArrayIterator it(bytecode_array, 0);
  if (it.current_bytecode() != i::interpreter::Bytecode::kLdaUndefined) {
    return false;
  }
  it.Advance();
  DCHECK(!it.done());
  if (it.current_bytecode() != i::interpreter::Bytecode::kReturn) return false;
  it.Advance();
  DCHECK(it.done());
  return true;
}

MaybeLocal<String> v8::Function::FunctionProtoToString(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, Function, FunctionProtoToString);
  auto self = Utils::OpenHandle(this);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallBuiltin(i_isolate, i_isolate->function_to_string(),
                                self, 0, nullptr),
      &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(Local<String>::Cast(result));
}

int Name::GetIdentityHash() {
  return static_cast<int>(Utils::OpenDirectHandle(this)->EnsureHash());
}

int String::Length() const {
  return static_cast<int>(Utils::OpenDirectHandle(this)->length());
}

bool String::IsOneByte() const {
  return Utils::OpenDirectHandle(this)->IsOneByteRepresentation();
}

// Helpers for ContainsOnlyOneByteHelper
template <size_t size>
struct OneByteMask;
template <>
struct OneByteMask<4> {
  static const uint32_t value = 0xFF00FF00;
};
template <>
struct OneByteMask<8> {
  static const uint64_t value = 0xFF00'FF00'FF00'FF00;
};
static const uintptr_t kOneByteMask = OneByteMask<sizeof(uintptr_t)>::value;
static const uintptr_t kAlignmentMask = sizeof(uintptr_t) - 1;
static inline bool Unaligned(const uint16_t* chars) {
  return reinterpret_cast<const uintptr_t>(chars) & kAlignmentMask;
}

static inline const uint16_t* Align(const uint16_t* chars) {
  return reinterpret_cast<uint16_t*>(reinterpret_cast<uintptr_t>(chars) &
                                     ~kAlignmentMask);
}

class ContainsOnlyOneByteHelper {
 public:
  ContainsOnlyOneByteHelper() : is_one_byte_(true) {}
  ContainsOnlyOneByteHelper(const ContainsOnlyOneByteHelper&) = delete;
  ContainsOnlyOneByteHelper& operator=(const ContainsOnlyOneByteHelper&) =
      delete;
  bool Check(i::Tagged<i::String> string) {
    i::Tagged<i::ConsString> cons_string =
        i::String::VisitFlat(this, string, 0);
    if (cons_string.is_null()) return is_one_byte_;
    return CheckCons(cons_string);
  }
  void VisitOneByteString(const uint8_t* chars, int length) {
    // Nothing to do.
  }
  void VisitTwoByteString(const uint16_t* chars, int length) {
    // Accumulated bits.
    uintptr_t acc = 0;
    // Align to uintptr_t.
    const uint16_t* end = chars + length;
    while (Unaligned(chars) && chars != end) {
      acc |= *chars++;
    }
    // Read word aligned in blocks,
    // checking the return value at the end of each block.
    const uint16_t* aligned_end = Align(end);
    const int increment = sizeof(uintptr_t) / sizeof(uint16_t);
    const int inner_loops = 16;
    while (chars + inner_loops * increment < aligned_end) {
      for (int i = 0; i < inner_loops; i++) {
        acc |= *reinterpret_cast<const uintptr_t*>(chars);
        chars += increment;
      }
      // Check for early return.
      if ((acc & kOneByteMask) != 0) {
        is_one_byte_ = false;
        return;
      }
    }
    // Read the rest.
    while (chars != end) {
      acc |= *chars++;
    }
    // Check result.
    if ((acc & kOneByteMask) != 0) is_one_byte_ = false;
  }

 private:
  bool CheckCons(i::Tagged<i::ConsString> cons_string) {
    while (true) {
      // Check left side if flat.
      i::Tagged<i::String> left = cons_string->first();
      i::Tagged<i::ConsString> left_as_cons =
          i::String::VisitFlat(this, left, 0);
      if (!is_one_byte_) return false;
      // Check right side if flat.
      i::Tagged<i::String> right = cons_string->second();
      i::Tagged<i::ConsString> right_as_cons =
          i::String::VisitFlat(this, right, 0);
      if (!is_one_byte_) return false;
      // Standard recurse/iterate trick.
      if (!left_as_cons.is_null() && !right_as_cons.is_null()) {
        if (left->length() < right->length()) {
          CheckCons(left_as_cons);
          cons_string = right_as_cons;
        } else {
          CheckCons(right_as_cons);
          cons_string = left_as_cons;
        }
        // Check fast return.
        if (!is_one_byte_) return false;
        continue;
      }
      // Descend left in place.
      if (!left_as_cons.is_null()) {
        cons_string = left_as_cons;
        continue;
      }
      // Descend right in place.
      if (!right_as_cons.is_null()) {
        cons_string = right_as_cons;
        continue;
      }
      // Terminate.
      break;
    }
    return is_one_byte_;
  }
  bool is_one_byte_;
};

bool String::ContainsOnlyOneByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (str->IsOneByteRepresentation()) return true;
  ContainsOnlyOneByteHelper helper;
  return helper.Check(*str);
}

int String::Utf8Length(Isolate* v8_isolate) const {
  auto str = Utils::OpenHandle(this);
  str = i::String::Flatten(reinterpret_cast<i::Isolate*>(v8_isolate), str);
  int length = str->length();
  if (length == 0) return 0;
  i::DisallowGarbageCollection no_gc;
  i::String::FlatContent flat = str->GetFlatContent(no_gc);
  DCHECK(flat.IsFlat());
  int utf8_length = 0;
  if (flat.IsOneByte()) {
    for (uint8_t c : flat.ToOneByteVector()) {
      utf8_length += c >> 7;
    }
    utf8_length += length;
  } else {
    int last_character = unibrow::Utf16::kNoPreviousCharacter;
    for (uint16_t c : flat.ToUC16Vector()) {
      utf8_length += unibrow::Utf8::Length(c, last_character);
      last_character = c;
    }
  }
  return utf8_length;
}

size_t String::Utf8LengthV2(Isolate* v8_isolate) const {
  auto str = Utils::OpenHandle(this);
  return i::String::Utf8Length(reinterpret_cast<i::Isolate*>(v8_isolate), str);
}

namespace {
// Writes the flat content of a string to a buffer. This is done in two phases.
// The first phase calculates a pessimistic estimate (writable_length) on how
// many code units can be safely written without exceeding the buffer capacity
// and without leaving at a lone surrogate. The estimated number of code units
// is then written out in one go, and the reported byte usage is used to
// correct the estimate. This is repeated until the estimate becomes <= 0 or
// all code units have been written out. The second phase writes out code
// units until the buffer capacity is reached, would be exceeded by the next
// unit, or all code units have been written out.
template <typename Char>
static int WriteUtf8Impl(base::Vector<const Char> string, char* write_start,
                         int write_capacity, int options,
                         int* utf16_chars_read_out) {
  bool write_null = !(options & v8::String::NO_NULL_TERMINATION);
  bool replace_invalid_utf8 = (options & v8::String::REPLACE_INVALID_UTF8);
  char* current_write = write_start;
  const Char* read_start = string.begin();
  int read_index = 0;
  int read_length = string.length();
  int prev_char = unibrow::Utf16::kNoPreviousCharacter;
  // Do a fast loop where there is no exit capacity check.
  // Need enough space to write everything but one character.
  static_assert(unibrow::Utf16::kMaxExtraUtf8BytesForOneUtf16CodeUnit == 3);
  static const int kMaxSizePerChar = sizeof(Char) == 1 ? 2 : 3;
  while (read_index < read_length) {
    int up_to = read_length;
    if (write_capacity != -1) {
      int remaining_capacity =
          write_capacity - static_cast<int>(current_write - write_start);
      int writable_length =
          (remaining_capacity - kMaxSizePerChar) / kMaxSizePerChar;
      // Need to drop into slow loop.
      if (writable_length <= 0) break;
      up_to = std::min(up_to, read_index + writable_length);
    }
    // Write the characters to the stream.
    if (sizeof(Char) == 1) {
      // Simply memcpy if we only have ASCII characters.
      uint8_t char_mask = 0;
      for (int i = read_index; i < up_to; i++) char_mask |= read_start[i];
      if ((char_mask & 0x80) == 0) {
        int copy_length = up_to - read_index;
        memcpy(current_write, read_start + read_index, copy_length);
        current_write += copy_length;
        read_index = up_to;
      } else {
        for (; read_index < up_to; read_index++) {
          current_write += unibrow::Utf8::EncodeOneByte(
              current_write, static_cast<uint8_t>(read_start[read_index]));
          DCHECK(write_capacity == -1 ||
                 (current_write - write_start) <= write_capacity);
        }
      }
    } else {
      for (; read_index < up_to; read_index++) {
        uint16_t character = read_start[read_index];
        current_write += unibrow::Utf8::Encode(current_write, character,
                                               prev_char, replace_invalid_utf8);
        prev_char = character;
        DCHECK(write_capacity == -1 ||
               (current_write - write_start) <= write_capacity);
      }
    }
  }
  if (read_index < read_length) {
    DCHECK_NE(-1, write_capacity);
    // Aborted due to limited capacity. Check capacity on each iteration.
    int remaining_capacity =
        write_capacity - static_cast<int>(current_write - write_start);
    DCHECK_GE(remaining_capacity, 0);
    for (; read_index < read_length && remaining_capacity > 0; read_index++) {
      uint32_t character = read_start[read_index];
      int written = 0;
      // We can't use a local buffer here because Encode needs to modify
      // previous characters in the stream.  We know, however, that
      // exactly one character will be advanced.
      if (unibrow::Utf16::IsSurrogatePair(prev_char, character)) {
        written = unibrow::Utf8::Encode(current_write, character, prev_char,
                                        replace_invalid_utf8);
        DCHECK_EQ(written, 1);
      } else {
        // Use a scratch buffer to check the required characters.
        char temp_buffer[unibrow::Utf8::kMaxEncodedSize];
        // Encoding a surrogate pair to Utf8 always takes 4 bytes.
        static const int kSurrogatePairEncodedSize =
            static_cast<int>(unibrow::Utf8::kMaxEncodedSize);
        // For REPLACE_INVALID_UTF8, catch the case where we cut off in the
        // middle of a surrogate pair. Abort before encoding the pair instead.
        if (replace_invalid_utf8 &&
            remaining_capacity < kSurrogatePairEncodedSize &&
            unibrow::Utf16::IsLeadSurrogate(character) &&
            read_index + 1 < read_length &&
            unibrow::Utf16::IsTrailSurrogate(read_start[read_index + 1])) {
          write_null = false;
          break;
        }
        // Can't encode using prev_char as gcc has array bounds issues.
        written = unibrow::Utf8::Encode(temp_buffer, character,
                                        unibrow::Utf16::kNoPreviousCharacter,
                                        replace_invalid_utf8);
        if (written > remaining_capacity) {
          // Won't fit. Abort and do not null-terminate the result.
          write_null = false;
          break;
        }
        // Copy over the character from temp_buffer.
        for (int i = 0; i < written; i++) current_write[i] = temp_buffer[i];
      }

      current_write += written;
      remaining_capacity -= written;
      prev_char = character;
    }
  }

  // Write out number of utf16 characters written to the stream.
  if (utf16_chars_read_out != nullptr) *utf16_chars_read_out = read_index;

  // Only null-terminate if there's space.
  if (write_null && (write_capacity == -1 ||
                     (current_write - write_start) < write_capacity)) {
    *current_write++ = '\0';
  }
  return static_cast<int>(current_write - write_start);
}
}  // anonymous namespace

int String::WriteUtf8(Isolate* v8_isolate, char* buffer, int capacity,
                      int* nchars_ref, int options) const {
  auto str = Utils::OpenHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, String, WriteUtf8);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  str = i::String::Flatten(i_isolate, str);
  i::DisallowGarbageCollection no_gc;
  i::String::FlatContent content = str->GetFlatContent(no_gc);
  if (content.IsOneByte()) {
    return WriteUtf8Impl<uint8_t>(content.ToOneByteVector(), buffer, capacity,
                                  options, nchars_ref);
  } else {
    return WriteUtf8Impl<uint16_t>(content.ToUC16Vector(), buffer, capacity,
                                   options, nchars_ref);
  }
}

template <typename CharType>
static inline int WriteHelper(i::Isolate* i_isolate, const String* string,
                              CharType* buffer, int start, int length,
                              int options) {
  API_RCS_SCOPE(i_isolate, String, Write);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(start >= 0 && length >= -1);
  auto str = Utils::OpenHandle(string);
  int end = start + length;
  if ((length == -1) || (static_cast<uint32_t>(length) > str->length() - start))
    end = str->length();
  if (end < 0) return 0;
  int write_length = end - start;
  if (start < end) i::String::WriteToFlat(*str, buffer, start, write_length);
  if (!(options & String::NO_NULL_TERMINATION) &&
      (length == -1 || write_length < length)) {
    buffer[write_length] = '\0';
  }
  return write_length;
}

int String::WriteOneByte(Isolate* v8_isolate, uint8_t* buffer, int start,
                         int length, int options) const {
  return WriteHelper(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer,
                     start, length, options);
}

int String::Write(Isolate* v8_isolate, uint16_t* buffer, int start, int length,
                  int options) const {
  return WriteHelper(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer,
                     start, length, options);
}

template <typename CharType>
static inline void WriteHelperV2(i::Isolate* i_isolate, const String* string,
                                 CharType* buffer, uint32_t offset,
                                 uint32_t length, int flags) {
  API_RCS_SCOPE(i_isolate, String, Write);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  DCHECK_LE(length, string->Length());
  DCHECK_LE(offset, string->Length() - length);

  auto str = Utils::OpenHandle(string);
  str = i::String::Flatten(i_isolate, str);
  i::String::WriteToFlat(*str, buffer, offset, length);
  if (flags & String::WriteFlags::kNullTerminate) {
    buffer[length] = '\0';
  }
}

void String::WriteV2(Isolate* v8_isolate, uint32_t offset, uint32_t length,
                     uint16_t* buffer, int flags) const {
  WriteHelperV2(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer, offset,
                length, flags);
}

void String::WriteOneByteV2(Isolate* v8_isolate, uint32_t offset,
                            uint32_t length, uint8_t* buffer, int flags) const {
  DCHECK(IsOneByte());
  WriteHelperV2(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer, offset,
                length, flags);
}

size_t String::WriteUtf8V2(Isolate* v8_isolate, char* buffer, size_t capacity,
                           int flags) const {
  auto str = Utils::OpenHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, String, WriteUtf8);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::String::Utf8EncodingFlags i_flags;
  if (flags & String::WriteFlags::kNullTerminate) {
    i_flags |= i::String::Utf8EncodingFlag::kNullTerminate;
  }
  if (flags & String::WriteFlags::kReplaceInvalidUtf8) {
    i_flags |= i::String::Utf8EncodingFlag::kReplaceInvalid;
  }
  return i::String::WriteUtf8(i_isolate, str, buffer, capacity, i_flags);
}

namespace {

bool HasExternalStringResource(i::Tagged<i::String> string) {
  return i::StringShape(string).IsExternal() ||
         string->HasExternalForwardingIndex(kAcquireLoad);
}

v8::String::ExternalStringResourceBase* GetExternalResourceFromForwardingTable(
    i::Tagged<i::String> string, uint32_t raw_hash, bool* is_one_byte) {
  DCHECK(i::String::IsExternalForwardingIndex(raw_hash));
  const int index = i::String::ForwardingIndexValueBits::decode(raw_hash);
  // Note that with a shared heap the main and worker isolates all share the
  // same forwarding table.
  auto resource =
      i::Isolate::Current()->string_forwarding_table()->GetExternalResource(
          index, is_one_byte);
  DCHECK_NOT_NULL(resource);
  return resource;
}

}  // namespace

bool v8::String::IsExternal() const {
  return HasExternalStringResource(*Utils::OpenDirectHandle(this));
}

bool v8::String::IsExternalTwoByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (i::StringShape(*str).IsExternalTwoByte()) return true;
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    GetExternalResourceFromForwardingTable(*str, raw_hash_field, &is_one_byte);
    return !is_one_byte;
  }
  return false;
}

bool v8::String::IsExternalOneByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (i::StringShape(*str).IsExternalOneByte()) return true;
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    GetExternalResourceFromForwardingTable(*str, raw_hash_field, &is_one_byte);
    return is_one_byte;
  }
  return false;
}

Local<v8::String> v8::String::InternalizeString(Isolate* v8_isolate) {
  auto* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto str = Utils::OpenDirectHandle(this);
  return Utils::ToLocal(isolate->factory()->InternalizeString(str));
}

void v8::String::VerifyExternalStringResource(
    v8::String::ExternalStringResource* value) const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  const v8::String::ExternalStringResource* expected;

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalTwoByte()) {
    const void* resource = i::Cast<i::ExternalTwoByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResource*>(resource);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      auto resource = GetExternalResourceFromForwardingTable(
          str, raw_hash_field, &is_one_byte);
      if (!is_one_byte) {
        expected = reinterpret_cast<const ExternalStringResource*>(resource);
      }
    } else {
      expected = nullptr;
    }
  }
  CHECK_EQ(expected, value);
}

void v8::String::VerifyExternalStringResourceBase(
    v8::String::ExternalStringResourceBase* value, Encoding encoding) const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  const v8::String::ExternalStringResourceBase* expected;
  Encoding expectedEncoding;

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalOneByte()) {
    const void* resource = i::Cast<i::ExternalOneByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResourceBase*>(resource);
    expectedEncoding = ONE_BYTE_ENCODING;
  } else if (i::StringShape(str).IsExternalTwoByte()) {
    const void* resource = i::Cast<i::ExternalTwoByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResourceBase*>(resource);
    expectedEncoding = TWO_BYTE_ENCODING;
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      expected = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                        &is_one_byte);
      expectedEncoding = is_one_byte ? ONE_BYTE_ENCODING : TWO_BYTE_ENCODING;
    } else {
      expected = nullptr;
      expectedEncoding = str->IsOneByteRepresentation() ? ONE_BYTE_ENCODING
                                                        : TWO_BYTE_ENCODING;
    }
  }
  CHECK_EQ(expected, value);
  CHECK_EQ(expectedEncoding, encoding);
}

String::ExternalStringResource* String::GetExternalStringResourceSlow() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalTwoByte()) {
    Isolate* isolate = i::Internals::GetIsolateForSandbox(str.ptr());
    i::Address value =
        i::Internals::ReadExternalPointerField<i::kExternalStringResourceTag>(
            isolate, str.ptr(), i::Internals::kStringResourceOffset);
    return reinterpret_cast<String::ExternalStringResource*>(value);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      auto resource = GetExternalResourceFromForwardingTable(
          str, raw_hash_field, &is_one_byte);
      if (!is_one_byte) {
        return reinterpret_cast<ExternalStringResource*>(resource);
      }
    }
  }
  return nullptr;
}

void String::ExternalStringResource::UpdateDataCache() {
  DCHECK(IsCacheable());
  cached_data_ = data();
}

void String::ExternalStringResource::CheckCachedDataInvariants() const {
  DCHECK(IsCacheable() && cached_data_ != nullptr);
}

void String::ExternalOneByteStringResource::UpdateDataCache() {
  DCHECK(IsCacheable());
  cached_data_ = data();
}

void String::ExternalOneByteStringResource::CheckCachedDataInvariants() const {
  DCHECK(IsCacheable() && cached_data_ != nullptr);
}

String::ExternalStringResourceBase* String::GetExternalStringResourceBaseSlow(
    String::Encoding* encoding_out) const {
  i::DisallowGarbageCollection no_gc;
  ExternalStringResourceBase* resource = nullptr;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  internal::Address string = str.ptr();
  int type = i::Internals::GetInstanceType(string) &
             i::Internals::kStringRepresentationAndEncodingMask;
  *encoding_out =
      static_cast<Encoding>(type & i::Internals::kStringEncodingMask);
  if (i::StringShape(str).IsExternalOneByte() ||
      i::StringShape(str).IsExternalTwoByte()) {
    Isolate* isolate = i::Internals::GetIsolateForSandbox(string);
    i::Address value =
        i::Internals::ReadExternalPointerField<i::kExternalStringResourceTag>(
            isolate, string, i::Internals::kStringResourceOffset);
    resource = reinterpret_cast<ExternalStringResourceBase*>(value);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field();
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      resource = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                        &is_one_byte);
      *encoding_out = is_one_byte ? Encoding::ONE_BYTE_ENCODING
                                  : Encoding::TWO_BYTE_ENCODING;
    }
  }
  return resource;
}

const v8::String::ExternalOneByteStringResource*
v8::String::GetExternalOneByteStringResource() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  if (i::StringShape(str).IsExternalOneByte()) {
    return i::Cast<i::ExternalOneByteString>(str)->resource();
  } else if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
    if (i::StringShape(str).IsExternalOneByte()) {
      return i::Cast<i::ExternalOneByteString>(str)->resource();
    }
  }
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    auto resource = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                           &is_one_byte);
    if (is_one_byte) {
      return reinterpret_cast<ExternalOneByteStringResource*>(resource);
    }
  }
  return nullptr;
}

Local<Value> Symbol::Description(Isolate* v8_isolate) const {
  auto sym = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return Utils::ToLocal(i::direct_handle(sym->description(), isolate));
}

Local<Value> Private::Name() const {
  const Symbol* sym = reinterpret_cast<const Symbol*>(this);
  auto i_sym = Utils::OpenDirectHandle(sym);
  // v8::Private symbols are created by API and are therefore writable, so we
  // can always recover an Isolate.
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*i_sym);
  return sym->Description(reinterpret_cast<Isolate*>(i_isolate));
}

double Number::Value() const {
  return i::Object::NumberValue(*Utils::OpenDirectHandle(this));
}

bool Boolean::Value() const {
  return i::IsTrue(*Utils::OpenDirectHandle(this));
}

int64_t Integer::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<int64_t>(i::Object::NumberValue(obj));
  }
}

int32_t Int32::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<int32_t>(i::Object::NumberValue(obj));
  }
}

uint32_t Uint32::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<uint32_t>(i::Object::NumberValue(obj));
  }
}

int v8::Object::InternalFieldCount() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSObject(self)) return 0;
  return i::Cast<i::JSObject>(self)->GetEmbedderFieldCount();
}

static V8_INLINE bool InternalFieldOK(i::DirectHandle<i::JSReceiver> obj,
                                      int index, const char* location) {
  return Utils::ApiCheck(
      IsJSObject(*obj) &&
          (index < i::Cast<i::JSObject>(*obj)->GetEmbedderFieldCount()),
      location, "Internal field out of bounds");
}

Local<Data> v8::Object::SlowGetInternalField(int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetInternalField()";
  if (!InternalFieldOK(obj, index, location)) return Local<Value>();
  i::Isolate* isolate = obj->GetIsolate();
  return ToApiHandle<Data>(i::direct_handle(
      i::Cast<i::JSObject>(*obj)->GetEmbedderField(index), isolate));
}

void v8::Object::SetInternalField(int index, v8::Local<Data> value) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::SetInternalField()";
  if (!InternalFieldOK(obj, index, location)) return;
  auto val = Utils::OpenDirectHandle(*value);
  i::Cast<i::JSObject>(obj)->SetEmbedderField(index, *val);
}

void* v8::Object::SlowGetAlignedPointerFromInternalField(v8::Isolate* isolate,
                                                         int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetAlignedPointerFromInternalField()";
  if (!InternalFieldOK(obj, index, location)) return nullptr;
  void* result;
  Utils::ApiCheck(
      i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
          .ToAlignedPointer(reinterpret_cast<i::Isolate*>(isolate), &result),
      location, "Unaligned pointer");
  return result;
}

void* v8::Object::SlowGetAlignedPointerFromInternalField(int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetAlignedPointerFromInternalField()";
  if (!InternalFieldOK(obj, index, location)) return nullptr;
  void* result;
  Utils::ApiCheck(i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
                      .ToAlignedPointer(obj->GetIsolate(), &result),
                  location, "Unaligned pointer");
  return result;
}

void v8::Object::SetAlignedPointerInInternalField(int index, void* value) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::SetAlignedPointerInInternalField()";
  if (!InternalFieldOK(obj, index, location)) return;

  i::DisallowGarbageCollection no_gc;
  Utils::ApiCheck(i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
                      .store_aligned_pointer(obj->GetIsolate(), *obj, value),
                  location, "Unaligned pointer");
  DCHECK_EQ(value, GetAlignedPointerFromInternalField(index));
}

void v8::Object::SetAlignedPointerInInternalFields(int argc, int indices[],
                                                   void* values[]) {
  auto obj = Utils::OpenDirectHandle(this);
  if (!IsJSObject(*obj)) return;
  i::DisallowGarbageCollection no_gc;
  const char* location = "v8::Object::SetAlignedPointerInInternalFields()";
  auto js_obj = i::Cast<i::JSObject>(*obj);
  int nof_embedder_fields = js_obj->GetEmbedderFieldCount();
  for (int i = 0; i < argc; i++) {
    int index = indices[i];
    if (!Utils::ApiCheck(index < nof_embedder_fields, location,
                         "Internal field out of bounds")) {
      return;
    }
    void* value = values[i];
    Utils::ApiCheck(i::EmbedderDataSlot(js_obj, index)
                        .store_aligned_pointer(obj->GetIsolate(), *obj, value),
                    location, "Unaligned pointer");
    DCHECK_EQ(value, GetAlignedPointerFromInternalField(index));
  }
}

// static
void* v8::Object::Unwrap(v8::Isolate* isolate, i::Address wrapper_obj,
                         CppHeapPointerTagRange tag_range) {
  DCHECK_LE(tag_range.lower_bound, tag_range.upper_bound);
  return i::JSApiWrapper(
             i::Cast<i::JSObject>(i::Tagged<i::Object>(wrapper_obj)))
      .GetCppHeapWrappable(reinterpret_cast<i::Isolate*>(isolate), tag_range);
}

// static
void v8::Object::Wrap(v8::Isolate* isolate, i::Address wrapper_obj,
                      CppHeapPointerTag tag, void* wrappable) {
  return i::JSApiWrapper(
             i::Cast<i::JSObject>(i::Tagged<i::Object>(wrapper_obj)))
      .SetCppHeapWrappable(reinterpret_cast<i::Isolate*>(isolate), wrappable,
                           tag);
}

// --- E n v i r o n m e n t ---

void v8::V8::InitializePlatform(Platform* platform) {
  i::V8::InitializePlatform(platform);
}

void v8::V8::DisposePlatform() { i::V8::DisposePlatform(); }

bool v8::V8::Initialize(const int build_config) {
  const bool kEmbedderPointerCompression =
      (build_config & kPointerCompression) != 0;
  if (kEmbedderPointerCompression != COMPRESS_POINTERS_BOOL) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "pointer compression is %s while on V8 side it's %s.",
        kEmbedderPointerCompression ? "ENABLED" : "DISABLED",
        COMPRESS_POINTERS_BOOL ? "ENABLED" : "DISABLED");
  }

  const int kEmbedderSmiValueSize = (build_config & k31BitSmis) ? 31 : 32;
  if (kEmbedderSmiValueSize != internal::kSmiValueSize) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "Smi value size is %d while on V8 side it's %d.",
        kEmbedderSmiValueSize, internal::kSmiValueSize);
  }

  const bool kEmbedderSandbox = (build_config & kSandbox) != 0;
  if (kEmbedderSandbox != V8_ENABLE_SANDBOX_BOOL) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "sandbox is %s while on V8 side it's %s.",
        kEmbedderSandbox ? "ENABLED" : "DISABLED",
        V8_ENABLE_SANDBOX_BOOL ? "ENABLED" : "DISABLED");
  }

  const bool kEmbedderTargetOsIsAndroid =
      (build_config & kTargetOsIsAndroid) != 0;
#ifdef V8_TARGET_OS_ANDROID
  const bool kV8TargetOsIsAndroid = true;
#else
  const bool kV8TargetOsIsAndroid = false;
#endif
  if (kEmbedderTargetOsIsAndroid != kV8TargetOsIsAndroid) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "target OS is %s while on V8 side it's %s.",
        kEmbedderTargetOsIsAndroid ? "Android" : "not Android",
        kV8TargetOsIsAndroid ? "Android" : "not Android");
  }

  const bool kEmbedderEnableChecks = (build_config & kEnableChecks) != 0;
#ifdef V8_ENABLE_CHECKS
  const bool kV8EnableChe
```