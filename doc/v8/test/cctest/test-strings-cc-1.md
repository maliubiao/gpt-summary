Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a V8 test file (`v8/test/cctest/test-strings.cc`).

Here's a breakdown of the code's functionalities:

1. **String Conversion and Performance:** Measures the time it takes to write different types of strings (ASCII, one-byte, two-byte, surrogate pairs) to a UTF-8 buffer using `WriteUtf8V2`. This likely tests the performance of string encoding in V8.

2. **External String Creation and Manipulation:** Focuses on creating and manipulating "external" strings, which are strings backed by external memory. It tests:
    - Creation of one-byte and two-byte external strings.
    - Concatenation of external strings with other external and internal strings.
    - Verification of the resulting string content after concatenation.

3. **Invalid UTF-8 Handling:** Tests how V8 handles invalid UTF-8 sequences during string conversion using `WriteUtf8V2` with the `kReplaceInvalidUtf8` flag. It checks if invalid sequences are replaced with the Unicode replacement character (U+FFFD).

4. **JSON Stringification of Surrogate Pairs:** Checks how `JSON.stringify` handles lone surrogate code points, ensuring they are correctly encoded as escaped Unicode sequences. It also verifies that parsing and re-stringifying these escaped sequences results in the original string.

5. **String Hash Collision Handling:** Tests a specific bug related to string hashing and array indexing where strings with large numerical values could be incorrectly treated as array indices.

6. **String Slicing:** Explores string slicing operations, particularly with `ConsString` (concatenated strings) and external strings. It verifies that slicing produces `SlicedString` objects and checks the parent-child relationships between the original and sliced strings. It also checks if trivial slices (slices that include the entire parent string) avoid creating new string objects.

7. **Internalization of External Strings:** Tests the process of "internalizing" external strings, which means adding them to V8's internal string table to optimize memory usage and comparisons.

8. **Edge Cases with External Strings:** Checks scenarios involving external strings, including:
    - Creating external strings with pre-computed hashes that collide with existing internalized strings.
    - Slicing of external strings.
    - Externalizing a string during the `JSON.stringify` process.

9. **String Joining Edge Case:** Tests a scenario where joining a large array of strings can lead to integer overflow when calculating the total length.

10. **Use Counter for BreakIterator:** Tests the usage tracking of the `Intl.v8BreakIterator` API.

11. **String Replacement and Representation:** Checks if replacing characters in a one-byte string with a two-byte character results in a two-byte string.

12. **ASCII and One-Byte String Checks:**  Tests utility functions `String::IsAscii` and `String::IsOneByte`.

13. **Latin-1 Case Conversion (Conditional):** If `V8_INTL_SUPPORT` is not defined, it performs tests related to case conversion and canonical equivalence for Latin-1 characters.

14. **Handling of Invalid External Strings:** Tests the behavior when attempting to create external strings with invalid resources (e.g., null data pointers).

15. **Out-of-Memory Handling for String Creation:** Checks how V8 handles out-of-memory conditions when creating strings from UTF-8 or one-byte data.

16. **Message Formatting:** Tests the `MessageFormatter` class, which is used for creating formatted error messages.

17. **`String.fromCharCode` Behavior:**  Verifies that `String.fromCharCode` creates one-byte strings for ASCII characters and two-byte strings for characters outside the ASCII range.

18. **`indexOf` on External Strings:** Tests the functionality of `indexOf` when called on external strings.

**Overall, the code snippet focuses on rigorously testing various aspects of V8's string implementation, including performance, memory management (especially with external strings), handling of different string encodings, and compliance with JavaScript string semantics.**
目录 `v8/test/cctest/test-strings.cc` 的第 2 部分主要关注 V8 中字符串的各种操作和特性，尤其是与性能、外部字符串、编码以及一些边界情况相关的测试。

以下是该部分代码功能的归纳：

1. **字符串写入性能测试:**  测试了将不同类型的字符串（ASCII，单字节，双字节，代理对）写入 UTF-8 缓冲区的性能。这可以帮助评估 V8 在字符串编码方面的效率。

2. **外部短字符串的拼接:** 测试了如何拼接外部存储的短字符串。它创建了一些外部存储的单字节和双字节字符串，并将它们与普通的 JavaScript 字符串进行拼接，并验证结果的正确性。

3. **替换无效的 UTF-8 字符:**  测试了使用 `WriteUtf8V2` 函数以及 `kReplaceInvalidUtf8` 标志来处理字符串中无效 UTF-8 字符的情况。它验证了无效字符是否被正确地替换为 Unicode 替换字符。

4. **JSON 字符串化对格式良好的 Unicode 字符的处理:**  测试了 `JSON.stringify` 方法如何处理单独的代理对字符。它确保这些字符被正确地转义为 Unicode 编码，并且可以被 `JSON.parse` 正确解析。

5. **缓存哈希溢出问题的回归测试:**  这是一个回归测试，用于修复一个之前存在的 Bug，该 Bug 涉及到字符串的哈希值计算和数组索引。该 Bug 导致某些数值型的字符串被错误地当作数组索引处理。

6. **从 ConsString 切片:**  测试了从 `ConsString`（由多个字符串拼接而成的字符串）创建切片的操作。它验证了切片后的字符串类型为 `SlicedString`，并检查了父字符串是否被正确地标记为扁平 (flat)。

7. **外部字符串的内部化:** 测试了将外部字符串内部化的过程。内部化是将外部字符串添加到 V8 的字符串表，以便进行更高效的查找和比较。

8. **Regress1402187 回归测试:**  这是一个回归测试，确保在内部化与已存在字符串具有相同哈希值的外部字符串时不会出现问题。

9. **从外部字符串切片:**  测试了从外部字符串创建切片的操作。与从 `ConsString` 切片类似，它验证了切片后的字符串类型和父字符串类型。

10. **在 JSON 字符串化期间外部化字符串:**  测试了一个复杂的场景，在 `JSON.stringify` 的回调函数中，尝试将一个字符串外部化。这测试了 V8 在执行 JSON 序列化时的灵活性和对外部字符串的支持。

11. **简单的字符串切片:**  测试了对字符串进行切片操作，特别是当切片的范围与原字符串相同时，是否会创建一个新的字符串对象（应该不会）。

12. **从切片后的字符串再次切片:** 测试了对已经切片过的字符串再次进行切片操作，验证其结果的正确性。

13. **大数组连接的内存溢出测试 (UNINITIALIZED_TEST):**  这是一个可能导致内存溢出的测试用例，用于测试连接大量字符串时的边界情况，特别是当计算总长度时可能发生整数溢出。

14. **计数 BreakIterator 的使用:**  测试了 V8 中 `Intl.v8BreakIterator` 的使用计数功能。它检查了是否正确地记录了 `BreakIterator` 的使用次数。

15. **字符串替换产生双字节结果:**  测试了使用 `replace` 方法替换单字节字符串中的字符，使其结果成为双字节字符串的情况。

16. **判断字符串是否为 ASCII:**  测试了 `String::IsAscii` 和 `String::IsOneByte` 这两个实用函数。

17. **Latin-1 字符的大小写转换 (条件编译):**  如果未定义 `V8_INTL_SUPPORT`，则会进行 Latin-1 字符的大小写转换测试。

18. **无效外部字符串的处理:** 测试了当尝试创建长度过长的外部字符串时，V8 的处理机制，预期会抛出异常。

19. **字符串内存溢出测试:**  测试了在尝试创建非常大的字符串时，V8 的内存溢出处理机制。

20. **格式化消息:** 测试了 `MessageFormatter` 类，用于格式化错误消息。

21. **Regress609831 回归测试:** 这是一个回归测试，确保 `String.fromCharCode` 正确创建单字节和双字节字符串。

22. **外部字符串的 `indexOf` 方法:**  测试了在外部字符串上调用 `indexOf` 方法的功能。

**总结第 2 部分的功能:**

这段代码主要关注 V8 引擎中字符串的底层实现和功能测试，涵盖了字符串的性能、不同类型的字符串（特别是外部字符串）的处理、字符编码的转换、以及一些可能导致错误或性能问题的边界情况。 这些测试旨在确保 V8 能够高效且正确地处理各种字符串操作，并对潜在的 Bug 进行回归测试。

### 提示词
```
这是目录为v8/test/cctest/test-strings.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-strings.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
CompileRun("'\\u0255\\u0254\\u0253'.repeat(1E6)").As<v8::String>();
  v8::Local<v8::String> two_byte_string =
      CompileRun("'\\u2255\\u2254\\u2253'.repeat(1E6)").As<v8::String>();
  v8::Local<v8::String> surrogate_string =
      CompileRun("'\\u{12345}\\u2244'.repeat(1E6)").As<v8::String>();
  int size = 1E7;
  char* buffer = new char[4 * size];
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    ascii_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("ascii string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    ascii_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("ascii string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    ascii_string->WriteUtf8V2(CcTest::isolate(), buffer, 4 * size);
    printf("ascii string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }

  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    one_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("one byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    one_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("one byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    one_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, 4 * size);
    printf("one byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }

  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    two_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("two byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    two_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("two byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    two_byte_string->WriteUtf8V2(CcTest::isolate(), buffer, 4 * size);
    printf("two byte string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }

  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    surrogate_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("surrogate string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    surrogate_string->WriteUtf8V2(CcTest::isolate(), buffer, size);
    printf("surrogate string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  {
    v8::base::ElapsedTimer timer;
    timer.Start();
    surrogate_string->WriteUtf8V2(CcTest::isolate(), buffer, 4 * size);
    printf("surrogate string %0.3f\n", timer.Elapsed().InMillisecondsF());
    timer.Stop();
  }
  delete[] buffer;
}

TEST(ExternalShortStringAdd) {
  LocalContext context;
  v8::HandleScope handle_scope(CcTest::isolate());

  // Make sure we cover all always-flat lengths and at least one above.
  static const int kMaxLength = 20;
  CHECK_GT(kMaxLength, i::ConsString::kMinLength);

  // Allocate two JavaScript arrays for holding short strings.
  v8::Local<v8::Array> one_byte_external_strings =
      v8::Array::New(CcTest::isolate(), kMaxLength + 1);
  v8::Local<v8::Array> non_one_byte_external_strings =
      v8::Array::New(CcTest::isolate(), kMaxLength + 1);

  // Generate short one-byte and two-byte external strings.
  for (int i = 0; i <= kMaxLength; i++) {
    char* one_byte = NewArray<char>(i + 1);
    for (int j = 0; j < i; j++) {
      one_byte[j] = 'a';
    }
    // Terminating '\0' is left out on purpose. It is not required for external
    // string data.
    OneByteResource* one_byte_resource = new OneByteResource(one_byte, i);
    v8::Local<v8::String> one_byte_external_string =
        v8::String::NewExternalOneByte(CcTest::isolate(), one_byte_resource)
            .ToLocalChecked();

    one_byte_external_strings
        ->Set(context.local(), v8::Integer::New(CcTest::isolate(), i),
              one_byte_external_string)
        .FromJust();
    base::uc16* non_one_byte = NewArray<base::uc16>(i + 1);
    for (int j = 0; j < i; j++) {
      non_one_byte[j] = 0x1234;
    }
    // Terminating '\0' is left out on purpose. It is not required for external
    // string data.
    Resource* resource = new Resource(non_one_byte, i);
    v8::Local<v8::String> non_one_byte_external_string =
        v8::String::NewExternalTwoByte(CcTest::isolate(), resource)
            .ToLocalChecked();
    non_one_byte_external_strings
        ->Set(context.local(), v8::Integer::New(CcTest::isolate(), i),
              non_one_byte_external_string)
        .FromJust();
  }

  // Add the arrays with the short external strings in the global object.
  v8::Local<v8::Object> global = context->Global();
  global
      ->Set(context.local(), v8_str("external_one_byte"),
            one_byte_external_strings)
      .FromJust();
  global
      ->Set(context.local(), v8_str("external_non_one_byte"),
            non_one_byte_external_strings)
      .FromJust();
  global
      ->Set(context.local(), v8_str("max_length"),
            v8::Integer::New(CcTest::isolate(), kMaxLength))
      .FromJust();

  // Add short external one-byte and two-byte strings checking the result.
  static const char* source =
      "function test() {"
      "  var one_byte_chars = 'aaaaaaaaaaaaaaaaaaaa';"
      "  var non_one_byte_chars = "
      "'\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1"
      "234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\u1234\\"
      "u1234';"
      "  if (one_byte_chars.length != max_length) return 1;"
      "  if (non_one_byte_chars.length != max_length) return 2;"
      "  var one_byte = Array(max_length + 1);"
      "  var non_one_byte = Array(max_length + 1);"
      "  for (var i = 0; i <= max_length; i++) {"
      "    one_byte[i] = one_byte_chars.substring(0, i);"
      "    non_one_byte[i] = non_one_byte_chars.substring(0, i);"
      "  };"
      "  for (var i = 0; i <= max_length; i++) {"
      "    if (one_byte[i] != external_one_byte[i]) return 3;"
      "    if (non_one_byte[i] != external_non_one_byte[i]) return 4;"
      "    for (var j = 0; j < i; j++) {"
      "      if (external_one_byte[i] !="
      "          (external_one_byte[j] + external_one_byte[i - j])) return "
      "5;"
      "      if (external_non_one_byte[i] !="
      "          (external_non_one_byte[j] + external_non_one_byte[i - "
      "j])) return 6;"
      "      if (non_one_byte[i] != (non_one_byte[j] + non_one_byte[i - "
      "j])) return 7;"
      "      if (one_byte[i] != (one_byte[j] + one_byte[i - j])) return 8;"
      "      if (one_byte[i] != (external_one_byte[j] + one_byte[i - j])) "
      "return 9;"
      "      if (one_byte[i] != (one_byte[j] + external_one_byte[i - j])) "
      "return 10;"
      "      if (non_one_byte[i] !="
      "          (external_non_one_byte[j] + non_one_byte[i - j])) return "
      "11;"
      "      if (non_one_byte[i] !="
      "          (non_one_byte[j] + external_non_one_byte[i - j])) return "
      "12;"
      "    }"
      "  }"
      "  return 0;"
      "};"
      "test()";
  CHECK_EQ(0, CompileRun(source)->Int32Value(context.local()).FromJust());
}

TEST(ReplaceInvalidUtf8) {
  LocalContext context;
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::Local<v8::String> string = CompileRun("'ab\\ud800cd'").As<v8::String>();
  char buffer[7];
  memset(buffer, 0, 7);
  size_t size =
      string->WriteUtf8V2(CcTest::isolate(), buffer, 7,
                          v8::String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(7, size);
  CHECK_EQ(0, memcmp("\x61\x62\xef\xbf\xbd\x63\x64", buffer, 7));

  memset(buffer, 0, 7);
  size = string->WriteUtf8V2(CcTest::isolate(), buffer, 6,
                             v8::String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(6, size);
  CHECK_EQ(0, memcmp("\x61\x62\xef\xbf\xbd\x63", buffer, 6));
}

TEST(JSONStringifyWellFormed) {
  CcTest::InitializeVM();
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();

  // Test some leading surrogates (U+D800 to U+DBFF).
  {  // U+D800
    CHECK_EQ(
        0, strcmp("\"\\ud800\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uD800')"))));
    v8::Local<v8::String> json = v8_str("\"\\ud800\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }

  {  // U+DAAA
    CHECK_EQ(
        0, strcmp("\"\\udaaa\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uDAAA')"))));
    v8::Local<v8::String> json = v8_str("\"\\udaaa\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }

  {  // U+DBFF
    CHECK_EQ(
        0, strcmp("\"\\udbff\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uDBFF')"))));
    v8::Local<v8::String> json = v8_str("\"\\udbff\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }

  // Test some trailing surrogates (U+DC00 to U+DFFF).
  {  // U+DC00
    CHECK_EQ(
        0, strcmp("\"\\udc00\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uDC00')"))));
    v8::Local<v8::String> json = v8_str("\"\\udc00\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }

  {  // U+DDDD
    CHECK_EQ(
        0, strcmp("\"\\udddd\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uDDDD')"))));
    v8::Local<v8::String> json = v8_str("\"\\udddd\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }

  {  // U+DFFF
    CHECK_EQ(
        0, strcmp("\"\\udfff\"", *v8::String::Utf8Value(
                                     CcTest::isolate(),
                                     CompileRun("JSON.stringify('\\uDFFF')"))));
    v8::Local<v8::String> json = v8_str("\"\\udfff\"");
    v8::Local<v8::Value> parsed =
        v8::JSON::Parse(context, json).ToLocalChecked();
    CHECK(v8::JSON::Stringify(context, parsed)
              .ToLocalChecked()
              ->Equals(context, json)
              .FromJust());
  }
}

TEST(CachedHashOverflow) {
  CcTest::InitializeVM();
  // We incorrectly allowed strings to be tagged as array indices even if their
  // values didn't fit in the hash field.
  // See http://code.google.com/p/v8/issues/detail?id=728
  Isolate* isolate = CcTest::i_isolate();

  v8::HandleScope handle_scope(CcTest::isolate());
  // Lines must be executed sequentially. Combining them into one script
  // makes the bug go away.
  const char* lines[] = {"var x = [];", "x[4] = 42;", "var s = \"1073741828\";",
                         "x[s];",       "x[s] = 37;", "x[4];",
                         "x[s];"};

  Handle<Smi> fortytwo(Smi::FromInt(42), isolate);
  Handle<Smi> thirtyseven(Smi::FromInt(37), isolate);
  Handle<Object> results[] = {
      isolate->factory()->undefined_value(),
      fortytwo,
      isolate->factory()->undefined_value(),
      isolate->factory()->undefined_value(),
      thirtyseven,
      fortytwo,
      thirtyseven  // Bug yielded 42 here.
  };

  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  for (size_t i = 0; i < arraysize(lines); i++) {
    const char* line = lines[i];
    printf("%s\n", line);
    v8::Local<v8::Value> result =
        v8::Script::Compile(
            context,
            v8::String::NewFromUtf8(CcTest::isolate(), line).ToLocalChecked())
            .ToLocalChecked()
            ->Run(context)
            .ToLocalChecked();
    CHECK_EQ(IsUndefined(*results[i], CcTest::i_isolate()),
             result->IsUndefined());
    CHECK_EQ(IsNumber(*results[i]), result->IsNumber());
    if (result->IsNumber()) {
      int32_t value = 0;
      CHECK(Object::ToInt32(*results[i], &value));
      CHECK_EQ(value, result->ToInt32(context).ToLocalChecked()->Value());
    }
  }
}

TEST(SliceFromCons) {
  if (!v8_flags.string_slices) return;
  CcTest::InitializeVM();
  Factory* factory = CcTest::i_isolate()->factory();
  v8::HandleScope scope(CcTest::isolate());
  Handle<String> string =
      factory->NewStringFromStaticChars("parentparentparent");
  Handle<String> parent =
      factory->NewConsString(string, string).ToHandleChecked();
  CHECK(IsConsString(*parent));
  CHECK(!parent->IsFlat());
  DirectHandle<String> slice = factory->NewSubString(parent, 1, 25);
  // After slicing, the original string becomes a flat cons.
  CHECK(parent->IsFlat());
  CHECK(IsSlicedString(*slice));
  // TODO(leszeks): Remove Tagged cast when .first() returns a Tagged.
  static_assert(kTaggedCanConvertToRawObjects);
  CHECK_EQ(Cast<SlicedString>(*slice)->parent(),
           // Parent could have been short-circuited.
           IsConsString(*parent) ? Tagged(Cast<ConsString>(*parent)->first())
                                 : *parent);
  CHECK(IsSeqString(Cast<SlicedString>(*slice)->parent()));
  CHECK(slice->IsFlat());
}

class OneByteVectorResource : public v8::String::ExternalOneByteStringResource {
 public:
  explicit OneByteVectorResource(v8::base::Vector<const char> vector)
      : data_(vector) {}
  ~OneByteVectorResource() override = default;
  size_t length() const override { return data_.length(); }
  const char* data() const override { return data_.begin(); }

 private:
  v8::base::Vector<const char> data_;
};

TEST(InternalizeExternal) {
  v8_flags.stress_incremental_marking = false;
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  i::Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  // This won't leak; the external string mechanism will call Dispose() on it.
  OneByteVectorResource* resource =
      new OneByteVectorResource(v8::base::Vector<const char>("prop-1234", 9));
  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::String> ext_string =
        v8::String::NewExternalOneByte(CcTest::isolate(), resource)
            .ToLocalChecked();
    Handle<String> string = v8::Utils::OpenHandle(*ext_string);
    CHECK(IsExternalString(*string));
    CHECK(!IsInternalizedString(*string));
    CHECK(!i::HeapLayout::InYoungGeneration(*string));
    CHECK_EQ(isolate->string_table()->TryStringToIndexOrLookupExisting(
                 isolate, string->ptr()),
             Smi::FromInt(ResultSentinel::kNotFound).ptr());
    factory->InternalizeName(string);
    CHECK(IsExternalString(*string));
    CHECK(IsInternalizedString(*string));
    CHECK(!i::HeapLayout::InYoungGeneration(*string));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}

TEST(Regress1402187) {
  CcTest::InitializeVM();
  i::Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  // This won't leak; the external string mechanism will call Dispose() on it.
  const char ext_string_content[] = "prop-1234567890asdf";
  OneByteVectorResource* resource =
      new OneByteVectorResource(v8::base::Vector<const char>(
          ext_string_content, strlen(ext_string_content)));
  const uint32_t fake_hash =
      String::CreateHashFieldValue(4711, String::HashFieldType::kHash);
  {
    v8::HandleScope scope(CcTest::isolate());
    // Internalize a string with the same hash to ensure collision.
    Handle<String> intern = factory->NewStringFromAsciiChecked(
        "internalized1234567", AllocationType::kOld);
    intern->set_raw_hash_field(fake_hash);
    factory->InternalizeName(intern);
    CHECK(IsInternalizedString(*intern));

    v8::Local<v8::String> ext_string =
        Utils::ToLocal(factory->NewStringFromAsciiChecked(
            ext_string_content, AllocationType::kOld));
    CHECK(ext_string->MakeExternal(CcTest::isolate(), resource));
    Handle<String> string = v8::Utils::OpenHandle(*ext_string);
    string->set_raw_hash_field(fake_hash);
    CHECK(IsExternalString(*string));
    CHECK(!StringShape(*string).IsUncachedExternal());
    CHECK(!IsInternalizedString(*string));
    CHECK(!String::Equals(isolate, string, intern));
    CHECK_EQ(string->hash(), intern->hash());
    CHECK_EQ(string->length(), intern->length());

    CHECK_EQ(isolate->string_table()->TryStringToIndexOrLookupExisting(
                 isolate, string->ptr()),
             Smi::FromInt(ResultSentinel::kNotFound).ptr());
    string = factory->InternalizeString(string);
    CHECK(IsExternalString(*string));
    CHECK(IsInternalizedString(*string));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}

TEST(SliceFromExternal) {
  if (!v8_flags.string_slices) return;
  CcTest::InitializeVM();
  Factory* factory = CcTest::i_isolate()->factory();
  v8::HandleScope scope(CcTest::isolate());
  OneByteVectorResource resource(
      v8::base::Vector<const char>("abcdefghijklmnopqrstuvwxyz", 26));
  Handle<String> string =
      factory->NewExternalStringFromOneByte(&resource).ToHandleChecked();
  CHECK(IsExternalString(*string));
  DirectHandle<String> slice = factory->NewSubString(string, 1, 25);
  CHECK(IsSlicedString(*slice));
  CHECK(IsExternalString(*string));
  CHECK_EQ(Cast<SlicedString>(*slice)->parent(), *string);
  CHECK(IsExternalString(Cast<SlicedString>(*slice)->parent()));
  CHECK(slice->IsFlat());
  // This avoids the GC from trying to free stack allocated resources.
  i::Cast<i::ExternalOneByteString>(string)->SetResource(CcTest::i_isolate(),
                                                         nullptr);
}

static void ExternalizeDuringJsonStringifyCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Value> key = v8_compile("p")
                                 ->Run(CcTest::isolate()->GetCurrentContext())
                                 .ToLocalChecked();
  static const char ext_string_content[] = "prop-1234567890asdf";
  OneByteVectorResource* resource =
      new OneByteVectorResource(v8::base::Vector<const char>(
          ext_string_content, strlen(ext_string_content)));
  CHECK(v8::String::Cast(*key)->MakeExternal(CcTest::isolate(), resource));
}

TEST(ExternalizeDuringJsonStringify) {
  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  const char script[] = R"(
    var p = "prop-1234567890asdf";
    JSON.stringify([
      { [p]: 3 },
      { toJSON: callExternal },
      { [p]: 4 },
    ]);
  )";
  v8::Local<v8::ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "callExternal",
              v8::FunctionTemplate::New(
                  isolate, ExternalizeDuringJsonStringifyCallback));
  LocalContext context(nullptr, global);
  v8::Local<v8::Value> stringified =
      v8_compile(script)->Run(context.local()).ToLocalChecked();
  CHECK(v8::String::NewFromUtf8Literal(
            isolate,
            R"([{"prop-1234567890asdf":3},null,{"prop-1234567890asdf":4}])")
            ->Equals(context.local(), stringified)
            .FromJust());
}

TEST(TrivialSlice) {
  // This tests whether a slice that contains the entire parent string
  // actually creates a new string (it should not).
  if (!v8_flags.string_slices) return;
  CcTest::InitializeVM();
  Factory* factory = CcTest::i_isolate()->factory();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Value> result;
  Handle<String> string;
  const char* init = "var str = 'abcdefghijklmnopqrstuvwxyz';";
  const char* check = "str.slice(0,26)";
  const char* crosscheck = "str.slice(1,25)";

  CompileRun(init);

  result = CompileRun(check);
  CHECK(result->IsString());
  string = v8::Utils::OpenHandle(v8::String::Cast(*result));
  CHECK(!IsSlicedString(*string));

  string = factory->NewSubString(string, 0, 26);
  CHECK(!IsSlicedString(*string));
  result = CompileRun(crosscheck);
  CHECK(result->IsString());
  string = v8::Utils::OpenHandle(v8::String::Cast(*result));
  CHECK(IsSlicedString(*string));
  CHECK_EQ(0, strcmp("bcdefghijklmnopqrstuvwxy", string->ToCString().get()));
}

TEST(SliceFromSlice) {
  // This tests whether a slice that contains the entire parent string
  // actually creates a new string (it should not).
  if (!v8_flags.string_slices) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Value> result;
  DirectHandle<String> string;
  const char* init = "var str = 'abcdefghijklmnopqrstuvwxyz';";
  const char* slice = "var slice = ''; slice = str.slice(1,-1); slice";
  const char* slice_from_slice = "slice.slice(1,-1);";

  CompileRun(init);
  result = CompileRun(slice);
  CHECK(result->IsString());
  string = v8::Utils::OpenDirectHandle(v8::String::Cast(*result));
  CHECK(IsSlicedString(*string));
  CHECK(IsSeqString(Cast<SlicedString>(*string)->parent()));
  CHECK_EQ(0, strcmp("bcdefghijklmnopqrstuvwxy", string->ToCString().get()));

  result = CompileRun(slice_from_slice);
  CHECK(result->IsString());
  string = v8::Utils::OpenDirectHandle(v8::String::Cast(*result));
  CHECK(IsSlicedString(*string));
  CHECK(IsSeqString(Cast<SlicedString>(*string)->parent()));
  CHECK_EQ(0, strcmp("cdefghijklmnopqrstuvwx", string->ToCString().get()));
}

UNINITIALIZED_TEST(OneByteArrayJoin) {
  v8::Isolate::CreateParams create_params;
  // Set heap limits.
  create_params.constraints.set_max_young_generation_size_in_bytes(3 * MB);
#ifdef DEBUG
  create_params.constraints.set_max_old_generation_size_in_bytes(20 * MB);
#else
  create_params.constraints.set_max_old_generation_size_in_bytes(7 * MB);
#endif
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  {
    // String s is made of 2^17 = 131072 'c' characters and a is an array
    // starting with 'bad', followed by 2^14 times the string s. That means the
    // total length of the concatenated strings is 2^31 + 3. So on 32bit systems
    // summing the lengths of the strings (as Smis) overflows and wraps.
    LocalContext context(isolate);
    v8::HandleScope scope(isolate);
    v8::TryCatch try_catch(isolate);
    CHECK(CompileRun("var two_14 = Math.pow(2, 14);"
                     "var two_17 = Math.pow(2, 17);"
                     "var s = Array(two_17 + 1).join('c');"
                     "var a = ['bad'];"
                     "for (var i = 1; i <= two_14; i++) a.push(s);"
                     "a.join("
                     ");")
              .IsEmpty());
    CHECK(try_catch.HasCaught());
  }
  isolate->Exit();
  isolate->Dispose();
}  // namespace
namespace {

int* global_use_counts = nullptr;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  ++global_use_counts[feature];
}
}  // namespace

TEST(CountBreakIterator) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  LocalContext context;
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  CcTest::isolate()->SetUseCounterCallback(MockUseCounterCallback);
  CHECK_EQ(0, use_counts[v8::Isolate::kBreakIterator]);
  v8::Local<v8::Value> result = CompileRun(
      "(function() {"
      "  if (!this.Intl) return 0;"
      "  var iterator = Intl.v8BreakIterator(['en']);"
      "  iterator.adoptText('Now is the time');"
      "  iterator.next();"
      "  return iterator.next();"
      "})();");
  CHECK(result->IsNumber());
  int uses =
      result->ToInt32(context.local()).ToLocalChecked()->Value() == 0 ? 0 : 1;
  CHECK_EQ(uses, use_counts[v8::Isolate::kBreakIterator]);
  // Make sure GC cleans up the break iterator, so we don't get a memory leak
  // reported by ASAN.
  CcTest::isolate()->LowMemoryNotification();
}

TEST(StringReplaceAtomTwoByteResult) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  LocalContext context;
  v8::Local<v8::Value> result = CompileRun(
      "var subject = 'one_byte~only~string~'; "
      "var replace = '\x80';            "
      "subject.replace(/~/g, replace);  ");
  CHECK(result->IsString());
  DirectHandle<String> string =
      v8::Utils::OpenDirectHandle(v8::String::Cast(*result));
  CHECK(string->IsTwoByteRepresentation());

  v8::Local<v8::String> expected = v8_str("one_byte\x80only\x80string\x80");
  CHECK(expected->Equals(context.local(), result).FromJust());
}

TEST(IsAscii) {
  CHECK(String::IsAscii(static_cast<char*>(nullptr), 0));
  CHECK(String::IsOneByte(static_cast<base::uc16*>(nullptr), 0));
}

template <typename Op, bool return_first>
static uint16_t ConvertLatin1(uint16_t c) {
  uint32_t result[Op::kMaxWidth];
  int chars;
  chars = Op::Convert(c, 0, result, nullptr);
  if (chars == 0) return 0;
  CHECK_LE(chars, static_cast<int>(sizeof(result)));
  if (!return_first && chars > 1) {
    return 0;
  }
  return result[0];
}

#ifndef V8_INTL_SUPPORT
static void CheckCanonicalEquivalence(uint16_t c, uint16_t test) {
  uint16_t expect = ConvertLatin1<unibrow::Ecma262UnCanonicalize, true>(c);
  if (expect > unibrow::Latin1::kMaxChar || expect == 0) expect = c;
  CHECK_EQ(expect, test);
}

static inline uint16_t TryConvertToLatin1(uint16_t c) {
  switch (c) {
    // This are equivalent characters in unicode.
    case 0x39c:
    case 0x3bc:
      return 0xb5;
    // This is an uppercase of a Latin-1 character
    // outside of Latin-1.
    case 0x178:
      return 0xff;
  }
  return c;
}

TEST(Latin1IgnoreCase) {
  for (uint16_t c = unibrow::Latin1::kMaxChar + 1; c != 0; c++) {
    uint16_t lower = ConvertLatin1<unibrow::ToLowercase, false>(c);
    uint16_t upper = ConvertLatin1<unibrow::ToUppercase, false>(c);
    uint16_t test = TryConvertToLatin1(c);
    // Filter out all character whose upper is not their lower or vice versa.
    if (lower == 0 && upper == 0) {
      CheckCanonicalEquivalence(c, test);
      continue;
    }
    if (lower > unibrow::Latin1::kMaxChar &&
        upper > unibrow::Latin1::kMaxChar) {
      CheckCanonicalEquivalence(c, test);
      continue;
    }
    if (lower == 0 && upper != 0) {
      lower = ConvertLatin1<unibrow::ToLowercase, false>(upper);
    }
    if (upper == 0 && lower != c) {
      upper = ConvertLatin1<unibrow::ToUppercase, false>(lower);
    }
    if (lower > unibrow::Latin1::kMaxChar &&
        upper > unibrow::Latin1::kMaxChar) {
      CheckCanonicalEquivalence(c, test);
      continue;
    }
    if (upper != c && lower != c) {
      CheckCanonicalEquivalence(c, test);
      continue;
    }
    CHECK_EQ(std::min(upper, lower), test);
  }
}
#endif

class DummyResource : public v8::String::ExternalStringResource {
 public:
  const uint16_t* data() const override { return nullptr; }
  size_t length() const override { return 1 << 30; }
};

class DummyOneByteResource : public v8::String::ExternalOneByteStringResource {
 public:
  const char* data() const override { return nullptr; }
  size_t length() const override { return 1 << 30; }
};

TEST(InvalidExternalString) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  {
    HandleScope scope(isolate);
    DummyOneByteResource r;
    CHECK(isolate->factory()->NewExternalStringFromOneByte(&r).is_null());
    CHECK(isolate->has_exception());
    isolate->clear_exception();
  }

  {
    HandleScope scope(isolate);
    DummyResource r;
    CHECK(isolate->factory()->NewExternalStringFromTwoByte(&r).is_null());
    CHECK(isolate->has_exception());
    isolate->clear_exception();
  }
}

#define INVALID_STRING_TEST(FUN, TYPE)                                   \
  TEST(StringOOM##FUN) {                                                 \
    CcTest::InitializeVM();                                              \
    LocalContext context;                                                \
    Isolate* isolate = CcTest::i_isolate();                              \
    static_assert(String::kMaxLength < kMaxInt);                         \
    static const int invalid = String::kMaxLength + 1;                   \
    HandleScope scope(isolate);                                          \
    v8::base::Vector<TYPE> dummy = v8::base::Vector<TYPE>::New(invalid); \
    memset(dummy.begin(), 0x0, dummy.length() * sizeof(TYPE));           \
    CHECK(isolate->factory()->FUN(dummy).is_null());                     \
    memset(dummy.begin(), 0x20, dummy.length() * sizeof(TYPE));          \
    CHECK(isolate->has_exception());                                     \
    isolate->clear_exception();                                          \
    dummy.Dispose();                                                     \
  }

INVALID_STRING_TEST(NewStringFromUtf8, char)
INVALID_STRING_TEST(NewStringFromOneByte, uint8_t)

#undef INVALID_STRING_TEST

TEST(FormatMessage) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  DirectHandle<String> arg0 =
      isolate->factory()->NewStringFromAsciiChecked("arg0");
  DirectHandle<String> arg1 =
      isolate->factory()->NewStringFromAsciiChecked("arg1");
  DirectHandle<String> arg2 =
      isolate->factory()->NewStringFromAsciiChecked("arg2");
  Handle<String> result = MessageFormatter::TryFormat(
                              isolate, MessageTemplate::kPropertyNotFunction,
                              base::VectorOf({arg0, arg1, arg2}))
                              .ToHandleChecked();
  Handle<String> expected = isolate->factory()->NewStringFromAsciiChecked(
      "'arg0' returned for property 'arg1' of object 'arg2' is not a function");
  CHECK(String::Equals(isolate, result, expected));
}

TEST(Regress609831) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  {
    HandleScope scope(isolate);
    v8::Local<v8::Value> result = CompileRun(
        "String.fromCharCode(32, 32, 32, 32, 32, "
        "32, 32, 32, 32, 32, 32, 32, 32, 32, 32, "
        "32, 32, 32, 32, 32, 32, 32, 32, 32, 32)");
    CHECK(IsSeqOneByteString(*v8::Utils::OpenDirectHandle(*result)));
  }
  {
    HandleScope scope(isolate);
    v8::Local<v8::Value> result = CompileRun(
        "String.fromCharCode(432, 432, 432, 432, 432, "
        "432, 432, 432, 432, 432, 432, 432, 432, 432, "
        "432, 432, 432, 432, 432, 432, 432, 432, 432)");
    CHECK(IsSeqTwoByteString(*v8::Utils::OpenDirectHandle(*result)));
  }
}

TEST(ExternalStringIndexOf) {
  CcTest::InitializeVM();
  LocalContext context;
  v8::HandleScope scope(CcTest::isolate());

  const char* raw_string = "abcdefghijklmnopqrstuvwxyz";
  v8::Local<v8::String> string =
      v8::String::NewExternalOneByte(CcTest::isolate(),
                                     new StaticOneByteResource(raw_string))
          .ToLocalChecked();
  v8::Local<v8::Object> global = context->Global();
  global->Set(context.local(), v8_str("external"), string).FromJust();

  char source[] = "external.indexOf('%')";
  for (size_t i = 0; i < strlen(raw_string); i++) {
    source[18] = raw_string[i];
    int result_position = static_cast<int>(i);
    CHECK_EQ(result_position,
             CompileRun(source)->Int32Value(context.local()).FromJust());
  }
  CHECK_EQ(-1,
           CompileRun("external.indexOf('abcdefghijklmnopqrstuvwxyz%%%%%%')")
               ->Int32Value(context.local())
               .FromJust());
  CHECK_EQ(1, CompileRun("external.indexOf('', 1)")
                  ->Int32Value(context.local())
```