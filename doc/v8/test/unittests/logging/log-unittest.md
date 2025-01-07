Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/unittests/logging/log-unittest.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename and the `#include "src/logging/log.h"` clearly indicate that this code is for testing the logging functionality in V8.

2. **Examine the `TEST_F` Macros:** These are Google Test macros defining individual test cases. Each test case focuses on a specific aspect of the logging.

3. **Analyze `ScopedLoggerInitializer`:** This class seems crucial for setting up and tearing down the logging environment for each test. It likely handles enabling logging, capturing the log output, and providing methods to analyze the log.

4. **Look for Specific Logging Scenarios:** The test names and the code within each `TEST_F` block will reveal what specific logging features are being tested. Examples: logging callbacks, logging accessor callbacks, logging code creation events, etc.

5. **Check for Conditional Compilation and Flags:** The code uses `i::v8_flags` extensively. Note which flags are being set in `SetUpTestSuite` and within individual tests, as this affects the logging behavior being tested.

6. **Consider the `Split` Function:** This utility function suggests that the tests analyze the log output by splitting it into lines and then searching for specific patterns.

7. **Look for Interactions with JavaScript:** Some tests might involve running JavaScript code to trigger logging events.

8. **Pay attention to helper classes like `TestCodeEventHandler` and `FakeCodeEventLogger`:** These are likely used for more advanced testing of code events.

9. **Address the specific questions in the prompt:**
    * Is it Torque?  No, it's C++.
    * Relationship to JavaScript? Yes, some tests execute JavaScript to generate log entries.
    * Code logic and input/output?  The tests generally don't involve complex data transformations but focus on verifying the presence or absence of specific log entries based on actions. The "input" is the V8 configuration and the actions performed, and the "output" is the generated log.
    * Common programming errors?  This test file itself isn't about *user* programming errors, but it tests V8's ability to handle various scenarios correctly in its logging. One test specifically addresses a crash scenario related to disposed external strings.

10. **Structure the summary:** Organize the findings logically, starting with the overall purpose and then detailing the specific functionalities tested.
好的，这是对V8源代码文件 `v8/test/unittests/logging/log-unittest.cc` 第一部分的分析和功能归纳。

**文件功能概述:**

`v8/test/unittests/logging/log-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 V8 引擎的日志记录 (logging) 功能。它通过各种测试用例来验证 `src/logging/log.h` 中定义的日志记录功能是否按预期工作，能够正确记录各种 V8 内部事件。

**主要功能点:**

1. **测试日志基础设施:**  该文件搭建了一个测试环境，用于启用日志记录功能，并捕获生成的日志信息。 `ScopedLoggerInitializer` 类是核心，它负责设置日志标志，创建临时日志文件，执行测试代码，并最终读取和分析生成的日志内容。

2. **测试不同类型的日志事件:**  文件中包含多个 `TEST_F` 测试用例，每个用例都针对特定的日志记录场景进行测试，例如：
    * **代码创建事件 (Code Creation Events):** 测试当 JavaScript 代码被编译、生成时，是否生成了相应的日志记录。
    * **回调函数日志 (Log Callbacks):** 测试当 C++ 回调函数被 V8 调用时，是否能正确记录其信息。
    * **访问器回调日志 (Log Accessor Callbacks):** 测试当属性的 getter 和 setter 被调用时，是否能正确记录。
    * **V8 版本日志 (Log Version):** 测试 V8 引擎的版本信息是否能被记录。
    * **优化和反优化日志 (Log All - 包括 deopt):** 测试在代码优化和反优化过程中是否生成了相应的日志。
    * **解释执行帧的本地栈信息 (Log Interpreted Frames Native Stack):** 测试在解释执行 JavaScript 代码时，是否能记录本地栈信息。
    * **Map 对象日志 (Log Maps):** 测试 V8 的内部 Map 对象（用于存储对象属性）的创建和转换是否被记录。

3. **验证日志内容:**  测试用例通过检查生成的日志内容是否包含预期的字符串或模式来验证日志记录的正确性。`ContainsLine` 和 `ContainsLinesInOrder` 等方法用于在捕获的日志中查找特定的行。

4. **处理外部字符串资源:**  其中一个测试用例 (`Issue23768`) 专门测试了当脚本的外部字符串资源被释放后，日志记录功能是否能正常工作，防止崩溃。

5. **测试外部日志监听器 (External Log Event Listener):**  `TestCodeEventHandler` 类实现了一个自定义的代码事件监听器，用于测试在不启用 V8 内部日志文件的情况下，是否可以接收到代码事件通知。

6. **测试代码缓存与日志 (Code Caching and Logging):**  部分测试用例涉及到代码缓存，验证了在代码缓存被使用时，日志记录的行为是否正确。

**与 JavaScript 的关系:**

该测试文件与 JavaScript 功能紧密相关，因为它测试的是 V8 引擎在执行 JavaScript 代码过程中产生的日志。很多测试用例会执行一段 JavaScript 代码来触发特定的 V8 内部事件，然后检查是否生成了相应的日志记录。

**JavaScript 示例:**

例如，`LogCallbacks` 测试用例执行了以下 JavaScript 代码：

```javascript
Obj.prototype.method1.toString();
```

这段代码会触发 `Obj.prototype.method1` 这个函数的调用，从而触发 V8 记录与该回调函数相关的信息。测试用例会检查日志中是否包含了 `ObjMethod1` 这个 C++ 函数的地址和名称。

**代码逻辑推理 (假设输入与输出):**

假设 `LogCallbacks` 测试用例成功执行，且 `ObjMethod1` 函数的入口地址为 `0x12345678`。

**假设输入:**  启用了 `log` 和 `log_code` 标志，并且执行了上述 JavaScript 代码，创建了一个名为 `Obj` 的对象，并在其原型上定义了一个名为 `method1` 的方法（绑定了 C++ 函数 `ObjMethod1`）。

**预期输出:**  在生成的日志文件中，应该包含类似于以下内容的行：

```
code-creation,Callback,-2,0x12345678,1,method1
```

* `code-creation`:  表示这是一个代码创建事件。
* `Callback`: 表示这是关于回调函数的日志。
* `-2`:  可能表示某种内部 ID 或类型信息。
* `0x12345678`: 是 `ObjMethod1` 函数在内存中的入口地址 (实际地址会不同)。
* `1`:  可能表示某种标志或状态。
* `method1`: 是回调函数的名称。

**涉及用户常见的编程错误 (测试角度):**

虽然这个文件本身是 V8 的测试代码，但它所测试的功能与用户在使用 JavaScript 时可能遇到的一些问题相关，例如：

* **性能问题排查:**  日志可以帮助开发者理解 V8 如何编译和优化代码，哪些函数被优化或反优化，从而帮助排查性能瓶颈。
* **内存泄漏或过度分配:**  虽然这个文件没有直接测试内存相关的日志，但 V8 的其他日志功能（例如 GC 日志）可以帮助开发者分析内存使用情况。
* **理解 V8 内部行为:**  日志提供了 V8 引擎内部操作的可见性，帮助开发者更深入地理解 JavaScript 代码的执行过程。

**功能归纳 (第 1 部分):**

`v8/test/unittests/logging/log-unittest.cc` 的第一部分主要关注于 **基础的日志记录功能测试**。它涵盖了多种基本类型的日志事件，例如代码创建、回调函数、访问器回调等，并验证了在不同场景下日志记录的正确性。  核心是确保 V8 能够记录关键的执行信息，这对于性能分析、调试和理解 V8 的内部运作至关重要。  它还包含了一些针对特定问题的测试用例，例如处理外部字符串资源，以及初步测试了外部日志监听器的功能。

Prompt: 
```
这是目录为v8/test/unittests/logging/log-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/logging/log-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2006-2009 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Tests of logging functions from log.h

#include "src/logging/log.h"

#include <unordered_set>
#include <vector>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/builtins/builtins.h"
#include "src/codegen/compilation-cache.h"
#include "src/execution/vm-state-inl.h"
#include "src/init/v8.h"
#include "src/logging/log-file.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/cpu-profiler.h"
#include "src/utils/ostreams.h"
#include "src/utils/version.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using v8::base::EmbeddedVector;
using v8::internal::Address;
using v8::internal::V8FileLogger;

namespace v8 {
namespace {

class LogTest : public TestWithIsolate {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.log = true;
    i::v8_flags.prof = true;
    i::v8_flags.log_code = true;
    i::v8_flags.logfile = i::LogFile::kLogToTemporaryFile;
    i::v8_flags.logfile_per_isolate = false;
    TestWithIsolate::SetUpTestSuite();
  }
};

static std::vector<std::string> Split(const std::string& s, char delimiter) {
  std::vector<std::string> result;
  std::string line;
  std::istringstream stream(s);
  while (std::getline(stream, line, delimiter)) {
    result.push_back(line);
  }
  return result;
}

class V8_NODISCARD ScopedLoggerInitializer {
 public:
  explicit ScopedLoggerInitializer(v8::Isolate* isolate)
      : temp_file_(nullptr),
        isolate_(isolate),
        isolate_scope_(isolate),
        scope_(isolate),
        env_(v8::Context::New(isolate)) {
    env_->Enter();
  }

  ~ScopedLoggerInitializer() {
    env_->Exit();
    FILE* log_file = v8_file_logger()->TearDownAndGetLogFile();
    if (log_file != nullptr) fclose(log_file);
  }

  ScopedLoggerInitializer(const ScopedLoggerInitializer&) = delete;
  ScopedLoggerInitializer& operator=(const ScopedLoggerInitializer&) = delete;

  v8::Local<v8::Context>& env() { return env_; }

  v8::Isolate* isolate() { return isolate_; }

  i::Isolate* i_isolate() { return reinterpret_cast<i::Isolate*>(isolate()); }

  V8FileLogger* v8_file_logger() { return i_isolate()->v8_file_logger(); }

  i::Logger* logger() { return i_isolate()->logger(); }

  v8::Local<v8::String> GetLogString() {
    int length = static_cast<int>(raw_log_.size());
    return v8::String::NewFromUtf8(isolate_, raw_log_.c_str(),
                                   v8::NewStringType::kNormal, length)
        .ToLocalChecked();
  }

  void PrintLog() {
    i::StdoutStream os;
    os << raw_log_ << std::flush;
  }

  void StopLogging() {
    bool exists = false;
    raw_log_ = i::ReadFile(StopLoggingGetTempFile(), &exists, true);
    log_ = Split(raw_log_, '\n');
    CHECK(exists);
  }

  // Searches |log_| for a line which contains all the strings in |search_terms|
  // as substrings, starting from the index |start|, and returns the index of
  // the found line. Returns std::string::npos if no line is found.
  size_t IndexOfLine(const std::vector<std::string>& search_terms,
                     size_t start = 0) {
    for (size_t i = start; i < log_.size(); ++i) {
      const std::string& line = log_.at(i);
      bool all_terms_found = true;
      for (const std::string& term : search_terms) {
        all_terms_found &= line.find(term) != std::string::npos;
      }
      if (all_terms_found) return i;
    }
    return std::string::npos;
  }

  bool ContainsLine(const std::vector<std::string>& search_terms,
                    size_t start = 0) {
    return IndexOfLine(search_terms, start) != std::string::npos;
  }

  // Calls IndexOfLine for each set of substring terms in
  // |all_line_search_terms|, in order. Returns true if they're all found.
  bool ContainsLinesInOrder(
      const std::vector<std::vector<std::string>>& all_line_search_terms,
      size_t start = 0) {
    CHECK_GT(log_.size(), 0);
    for (auto& search_terms : all_line_search_terms) {
      size_t next = IndexOfLine(search_terms, start);
      if (next == std::string::npos) {
        for (size_t i = 0; i < search_terms.size(); ++i) {
          printf("%s ", search_terms[i].c_str());
        }
        printf(" -- mismatch\n");
        printf("Log contents:\n");
        for (size_t i = start; i < log_.size(); ++i) {
          printf("%s\n", log_.at(start).c_str());
        }
        return false;
      }
      start = next + 1;  // Skip the found line.
    }
    return true;
  }

  std::unordered_set<uintptr_t> ExtractLogAddresses(std::string search_term,
                                                    size_t address_column,
                                                    bool allow_duplicates) {
    CHECK_GT(log_.size(), 0);
    // Map addresses of Maps to log_lines.
    std::unordered_map<uintptr_t, std::string> map;
    size_t current = 0;
    while (true) {
      current = IndexOfLine({search_term}, current);
      if (current == std::string::npos) break;
      std::string current_line = log_.at(current);
      std::vector<std::string> columns = Split(current_line, ',');
      ++current;  // Skip the found line.
      // TODO(crbug.com/v8/8084): These two continue lines should really be
      // errors. But on Windows the log is sometimes mysteriously cut off at the
      // end. If the cut-off point happens to fall in the address field, the
      // conditions will be triggered.
      if (address_column >= columns.size()) continue;
      uintptr_t address =
          strtoull(columns.at(address_column).c_str(), nullptr, 16);
      if (address == 0) continue;
      if (!allow_duplicates) {
        auto match = map.find(address);
        // Ignore same address but different log line.
        if (match != map.end() && match->second.compare(current_line) == 0) {
          for (size_t i = 0; i < current; i++) {
            printf("%s\n", log_.at(i).c_str());
          }
          printf("%zu\n", current);
          FATAL("%s, ... %p apperead twice:\n    %s", search_term.c_str(),
                reinterpret_cast<void*>(address), current_line.c_str());
        }
      }
      map.insert({address, current_line});
    }
    // Extract all keys.
    std::unordered_set<uintptr_t> result;
    for (auto key_value : map) {
      result.insert(key_value.first);
    }
    return result;
  }

  void LogCodeObjects() { v8_file_logger()->LogCodeObjects(); }
  void LogCompiledFunctions() { v8_file_logger()->LogCompiledFunctions(); }

  void StringEvent(const char* name, const char* value) {
    v8_file_logger()->StringEvent(name, value);
  }

 private:
  FILE* StopLoggingGetTempFile() {
    temp_file_ = v8_file_logger()->TearDownAndGetLogFile();
    CHECK(temp_file_);
    rewind(temp_file_);
    return temp_file_;
  }

  FILE* temp_file_;
  v8::Isolate* isolate_;
  v8::Isolate::Scope isolate_scope_;
  v8::HandleScope scope_;
  v8::Local<v8::Context> env_;

  std::string raw_log_;
  std::vector<std::string> log_;
};

class TestCodeEventHandler : public v8::CodeEventHandler {
 public:
  explicit TestCodeEventHandler(v8::Isolate* isolate)
      : v8::CodeEventHandler(isolate), isolate_(isolate) {}

  size_t CountLines(std::string prefix, std::string suffix = std::string()) {
    if (event_log_.empty()) return 0;

    size_t match = 0;
    for (const std::string& line : event_log_) {
      size_t prefix_pos = line.find(prefix);
      if (prefix_pos == std::string::npos) continue;
      size_t suffix_pos = line.rfind(suffix);
      if (suffix_pos == std::string::npos) continue;
      if (suffix_pos != line.length() - suffix.length()) continue;
      if (prefix_pos >= suffix_pos) continue;
      match++;
    }

    return match;
  }

  void Handle(v8::CodeEvent* code_event) override {
    std::string log_line = "";
    log_line += v8::CodeEvent::GetCodeEventTypeName(code_event->GetCodeType());
    log_line += " ";
    log_line += FormatName(code_event);
    event_log_.push_back(log_line);
  }

 private:
  std::string FormatName(v8::CodeEvent* code_event) {
    std::string name = std::string(code_event->GetComment());
    if (name.empty()) {
      v8::Local<v8::String> functionName = code_event->GetFunctionName();
      size_t buffer_size = functionName->Utf8LengthV2(isolate_) + 1;
      std::string buffer(buffer_size, 0);
      functionName->WriteUtf8V2(isolate_, &buffer[0], buffer_size,
                                String::WriteFlags::kNullTerminate);
      // Sanitize name, removing unwanted \0 resulted from WriteUtf8
      name = std::string(buffer.c_str());
    }

    return name;
  }

  std::vector<std::string> event_log_;
  v8::Isolate* isolate_;
};

}  // namespace

// Test for issue http://crbug.com/23768 in Chromium.
// Heap can contain scripts with already disposed external sources.
// We need to verify that LogCompiledFunctions doesn't crash on them.
namespace {

class SimpleExternalString : public v8::String::ExternalStringResource {
 public:
  explicit SimpleExternalString(const char* source)
      : utf_source_(
            v8::base::OwnedVector<uint16_t>::Of(v8::base::CStrVector(source))) {
  }
  ~SimpleExternalString() override = default;
  size_t length() const override { return utf_source_.size(); }
  const uint16_t* data() const override { return utf_source_.begin(); }

 private:
  v8::base::OwnedVector<uint16_t> utf_source_;
};

}  // namespace

TEST_F(TestWithIsolate, Issue23768) {
  v8::HandleScope scope(isolate());
  v8::Local<v8::Context> env = v8::Context::New(isolate());
  env->Enter();

  SimpleExternalString source_ext_str("(function ext() {})();");
  v8::Local<v8::String> source =
      v8::String::NewExternalTwoByte(isolate(), &source_ext_str)
          .ToLocalChecked();
  // Script needs to have a name in order to trigger InitLineEnds execution.
  v8::Local<v8::String> origin =
      v8::String::NewFromUtf8Literal(isolate(), "issue-23768-test");
  v8::Local<v8::Script> evil_script = CompileWithOrigin(source, origin, false);
  CHECK(!evil_script.IsEmpty());
  CHECK(!evil_script->Run(env).IsEmpty());
  i::DirectHandle<i::ExternalTwoByteString> i_source(
      i::Cast<i::ExternalTwoByteString>(*v8::Utils::OpenDirectHandle(*source)),
      i_isolate());
  // This situation can happen if source was an external string disposed
  // by its owner.
  i_source->SetResource(i_isolate(), nullptr);

  // Must not crash.
  i_isolate()->v8_file_logger()->LogCompiledFunctions();
}

static void ObjMethod1(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
}

TEST_F(LogTest, LogCallbacks) {
  {
    ScopedLoggerInitializer logger(isolate());

    v8::Local<v8::FunctionTemplate> obj = v8::Local<v8::FunctionTemplate>::New(
        isolate(), v8::FunctionTemplate::New(isolate()));
    obj->SetClassName(NewString("Obj"));
    v8::Local<v8::ObjectTemplate> proto = obj->PrototypeTemplate();
    v8::Local<v8::Signature> signature = v8::Signature::New(isolate(), obj);
    proto->Set(NewString("method1"),
               v8::FunctionTemplate::New(isolate(), ObjMethod1,
                                         v8::Local<v8::Value>(), signature),
               static_cast<v8::PropertyAttribute>(v8::DontDelete));

    logger.env()
        ->Global()
        ->Set(logger.env(), NewString("Obj"),
              obj->GetFunction(logger.env()).ToLocalChecked())
        .FromJust();
    RunJS("Obj.prototype.method1.toString();");

    logger.LogCompiledFunctions();
    logger.StopLogging();

    Address ObjMethod1_entry = reinterpret_cast<Address>(ObjMethod1);
#if USES_FUNCTION_DESCRIPTORS
    ObjMethod1_entry = *FUNCTION_ENTRYPOINT_ADDRESS(ObjMethod1_entry);
#endif
    v8::base::EmbeddedVector<char, 100> suffix_buffer;
    v8::base::SNPrintF(suffix_buffer, ",0x%" V8PRIxPTR ",1,method1",
                       ObjMethod1_entry);
    CHECK(logger.ContainsLine(
        {"code-creation,Callback,-2,", std::string(suffix_buffer.begin())}));
  }
}

static void Prop1Getter(v8::Local<v8::Name> property,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {}

static void Prop1Setter(v8::Local<v8::Name> property,
                        v8::Local<v8::Value> value,
                        const v8::PropertyCallbackInfo<void>& info) {}

static void Prop2Getter(v8::Local<v8::Name> property,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {}

TEST_F(LogTest, LogAccessorCallbacks) {
  {
    ScopedLoggerInitializer logger(isolate());

    v8::Local<v8::FunctionTemplate> obj = v8::Local<v8::FunctionTemplate>::New(
        isolate(), v8::FunctionTemplate::New(isolate()));
    obj->SetClassName(NewString("Obj"));
    v8::Local<v8::ObjectTemplate> inst = obj->InstanceTemplate();
    inst->SetNativeDataProperty(NewString("prop1"), Prop1Getter, Prop1Setter);
    inst->SetNativeDataProperty(NewString("prop2"), Prop2Getter);

    logger.v8_file_logger()->LogAccessorCallbacks();

    logger.StopLogging();

    Address Prop1Getter_entry = reinterpret_cast<Address>(Prop1Getter);
#if USES_FUNCTION_DESCRIPTORS
    Prop1Getter_entry = *FUNCTION_ENTRYPOINT_ADDRESS(Prop1Getter_entry);
#endif
    v8::base::EmbeddedVector<char, 100> prop1_getter_record;
    v8::base::SNPrintF(prop1_getter_record, ",0x%" V8PRIxPTR ",1,get prop1",
                       Prop1Getter_entry);
    CHECK(logger.ContainsLine({"code-creation,Callback,-2,",
                               std::string(prop1_getter_record.begin())}));

    Address Prop1Setter_entry = reinterpret_cast<Address>(Prop1Setter);
#if USES_FUNCTION_DESCRIPTORS
    Prop1Setter_entry = *FUNCTION_ENTRYPOINT_ADDRESS(Prop1Setter_entry);
#endif
    v8::base::EmbeddedVector<char, 100> prop1_setter_record;
    v8::base::SNPrintF(prop1_setter_record, ",0x%" V8PRIxPTR ",1,set prop1",
                       Prop1Setter_entry);
    CHECK(logger.ContainsLine({"code-creation,Callback,-2,",
                               std::string(prop1_setter_record.begin())}));

    Address Prop2Getter_entry = reinterpret_cast<Address>(Prop2Getter);
#if USES_FUNCTION_DESCRIPTORS
    Prop2Getter_entry = *FUNCTION_ENTRYPOINT_ADDRESS(Prop2Getter_entry);
#endif
    v8::base::EmbeddedVector<char, 100> prop2_getter_record;
    v8::base::SNPrintF(prop2_getter_record, ",0x%" V8PRIxPTR ",1,get prop2",
                       Prop2Getter_entry);
    CHECK(logger.ContainsLine({"code-creation,Callback,-2,",
                               std::string(prop2_getter_record.begin())}));
  }
}

TEST_F(LogTest, LogVersion) {
  {
    ScopedLoggerInitializer logger(isolate());
    logger.StopLogging();

    v8::base::EmbeddedVector<char, 100> line_buffer;
    v8::base::SNPrintF(line_buffer, "%d,%d,%d,%d,%d", i::Version::GetMajor(),
                       i::Version::GetMinor(), i::Version::GetBuild(),
                       i::Version::GetPatch(), i::Version::IsCandidate());
    CHECK(
        logger.ContainsLine({"v8-version,", std::string(line_buffer.begin())}));
  }
}

// https://crbug.com/539892
// CodeCreateEvents with really large names should not crash.
TEST_F(LogTest, Issue539892) {
  i::FakeCodeEventLogger code_event_logger(i_isolate());

  {
    ScopedLoggerInitializer logger(isolate());
    logger.logger()->AddListener(&code_event_logger);

    // Function with a really large name.
    const char* source_text =
        "(function "
        "baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
        "(){})();";

    RunJS(source_text);

    // Must not crash.
    logger.LogCompiledFunctions();
    logger.logger()->RemoveListener(&code_event_logger);
  }
}

class LogAllTest : public LogTest {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.log_all = true;
    i::v8_flags.log_deopt = true;
    i::v8_flags.turbo_inlining = false;
    i::v8_flags.log_timer_events = true;
    i::v8_flags.allow_natives_syntax = true;
    LogTest::SetUpTestSuite();
  }
};

TEST_F(LogAllTest, LogAll) {
  {
    ScopedLoggerInitializer logger(isolate());

    const char* source_text = R"(
        function testAddFn(a,b) {
          return a + b
        };
        let result;

        // Warm up the ICs.
        %PrepareFunctionForOptimization(testAddFn);
        for (let i = 0; i < 100000; i++) {
          result = testAddFn(i, i);
        };

        // Enforce optimization.
        %OptimizeFunctionOnNextCall(testAddFn);
        result = testAddFn(1, 1);

        // Cause deopt.
        testAddFn('1', 1)
        for (let i = 0; i < 100000; i++) {
          result = testAddFn('1', i);
        }
      )";
    RunJS(source_text);

    logger.StopLogging();

    // We should find at least one code-creation even for testAddFn();
    CHECK(logger.ContainsLine({"timer-event-start", "V8.CompileCode"}));
    CHECK(logger.ContainsLine({"timer-event-end", "V8.CompileCode"}));
    CHECK(logger.ContainsLine({"code-creation,Script", ":1:1"}));
    CHECK(logger.ContainsLine({"code-creation,JS,", "testAddFn"}));

    if (i::v8_flags.turbofan && !i::v8_flags.always_turbofan) {
      CHECK(logger.ContainsLine({"code-deopt,", "not a Smi"}));
      CHECK(logger.ContainsLine({"timer-event-start", "V8.DeoptimizeCode"}));
      CHECK(logger.ContainsLine({"timer-event-end", "V8.DeoptimizeCode"}));
    }
  }
}

class LogInterpretedFramesNativeStackTest : public LogTest {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.interpreted_frames_native_stack = true;
    LogTest::SetUpTestSuite();
  }
};

TEST_F(LogInterpretedFramesNativeStackTest, LogInterpretedFramesNativeStack) {
  {
    ScopedLoggerInitializer logger(isolate());

    const char* source_text =
        "function testLogInterpretedFramesNativeStack(a,b) { return a + b };"
        "testLogInterpretedFramesNativeStack('1', 1);";
    RunJS(source_text);

    logger.StopLogging();

    CHECK(logger.ContainsLinesInOrder(
        {{"JS", "testLogInterpretedFramesNativeStack"},
         {"JS", "testLogInterpretedFramesNativeStack"}}));
  }
}

class LogInterpretedFramesNativeStackWithSerializationTest
    : public TestWithPlatform {
 public:
  LogInterpretedFramesNativeStackWithSerializationTest()
      : array_buffer_allocator_(
            v8::ArrayBuffer::Allocator::NewDefaultAllocator()) {}
  static void SetUpTestSuite() {
    i::v8_flags.log = true;
    i::v8_flags.prof = true;
    i::v8_flags.log_code = true;
    i::v8_flags.logfile = i::LogFile::kLogToTemporaryFile;
    i::v8_flags.logfile_per_isolate = false;
    i::v8_flags.interpreted_frames_native_stack = true;
    i::v8_flags.always_turbofan = false;
    TestWithPlatform::SetUpTestSuite();
  }

  v8::Local<v8::String> NewString(const char* source) {
    return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), source)
        .ToLocalChecked();
  }

  v8::ArrayBuffer::Allocator* array_buffer_allocator() {
    return array_buffer_allocator_.get();
  }

 private:
  std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator_;
};

TEST_F(LogInterpretedFramesNativeStackWithSerializationTest,
       LogInterpretedFramesNativeStackWithSerialization) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = array_buffer_allocator();

  v8::ScriptCompiler::CachedData* cache = nullptr;

  bool has_cache = cache != nullptr;
  // NOTE(mmarchini): Runs the test two times. The first time it will compile
  // our script and will create a code cache for it. The second time we'll
  // deserialize the cache and check if our function was logged correctly.
  // We disallow compilation on the second run to ensure we're loading from
  // cache.
  do {
    v8::Isolate* isolate = v8::Isolate::New(create_params);

    {
      ScopedLoggerInitializer logger(isolate);

      has_cache = cache != nullptr;
      v8::ScriptCompiler::CompileOptions options =
          has_cache ? v8::ScriptCompiler::kConsumeCodeCache
                    : v8::ScriptCompiler::kEagerCompile;

      v8::HandleScope scope(isolate);
      v8::Isolate::Scope isolate_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Local<v8::String> source = NewString(
          "function eyecatcher() { return a * a; } return eyecatcher();");
      v8::Local<v8::String> arg_str = NewString("a");
      v8::ScriptOrigin origin(NewString("filename"));

      i::DisallowCompilation* no_compile_expected =
          has_cache ? new i::DisallowCompilation(
                          reinterpret_cast<i::Isolate*>(isolate))
                    : nullptr;

      v8::ScriptCompiler::Source script_source(source, origin, cache);
      v8::Local<v8::Function> fun =
          v8::ScriptCompiler::CompileFunction(context, &script_source, 1,
                                              &arg_str, 0, nullptr, options)
              .ToLocalChecked();
      if (has_cache) {
        logger.StopLogging();
        logger.PrintLog();
        // Function is logged twice: once as interpreted, and once as the
        // interpreter entry trampoline builtin.
        CHECK(logger.ContainsLinesInOrder(
            {{"JS", "eyecatcher"}, {"JS", "eyecatcher"}}));
      }
      v8::Local<v8::Value> arg = Number::New(isolate, 3);
      v8::Local<v8::Value> result =
          fun->Call(context, v8::Undefined(isolate), 1, &arg).ToLocalChecked();
      CHECK_EQ(9, result->Int32Value(context).FromJust());
      cache = v8::ScriptCompiler::CreateCodeCacheForFunction(fun);

      if (no_compile_expected != nullptr) delete no_compile_expected;
    }

    isolate->Dispose();
  } while (!has_cache);
  delete cache;
}

class LogExternalLogEventListenerTest : public TestWithIsolate {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.log = false;
    i::v8_flags.prof = false;
    TestWithIsolate::SetUpTestSuite();
  }
};

TEST_F(LogExternalLogEventListenerTest, ExternalLogEventListener) {
  {
    v8::HandleScope scope(isolate());
    v8::Isolate::Scope isolate_scope(isolate());
    v8::Local<v8::Context> context = v8::Context::New(isolate());
    v8::Context::Scope context_scope(context);

    TestCodeEventHandler code_event_handler(isolate());

    const char* source_text_before_start =
        "function testLogEventListenerBeforeStart(a,b) { return a + b };"
        "testLogEventListenerBeforeStart('1', 1);";
    RunJS(source_text_before_start);

    CHECK_EQ(code_event_handler.CountLines("Function",
                                           "testLogEventListenerBeforeStart"),
             0);
    // We no longer log LazyCompile.
    CHECK_EQ(code_event_handler.CountLines("LazyCompile",
                                           "testLogEventListenerBeforeStart"),
             0);

    code_event_handler.Enable();

    CHECK_GE(code_event_handler.CountLines("Function",
                                           "testLogEventListenerBeforeStart"),
             1);

    const char* source_text_after_start =
        "function testLogEventListenerAfterStart(a,b) { return a + b };"
        "testLogEventListenerAfterStart('1', 1);";
    RunJS(source_text_after_start);

    CHECK_GE(code_event_handler.CountLines("Function",
                                           "testLogEventListenerAfterStart"),
             1);
    // We no longer log LazyCompile.
    CHECK_GE(code_event_handler.CountLines("LazyCompile",
                                           "testLogEventListenerAfterStart"),
             0);
  }
}

class LogExternalLogEventListenerInnerFunctionTest : public TestWithPlatform {
 public:
  LogExternalLogEventListenerInnerFunctionTest()
      : array_buffer_allocator_(
            v8::ArrayBuffer::Allocator::NewDefaultAllocator()) {}
  static void SetUpTestSuite() {
    i::v8_flags.log = false;
    i::v8_flags.prof = false;
    TestWithPlatform::SetUpTestSuite();
  }

  v8::ArrayBuffer::Allocator* array_buffer_allocator() {
    return array_buffer_allocator_.get();
  }
  v8::Local<v8::String> NewString(const char* source) {
    return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), source)
        .ToLocalChecked();
  }

 private:
  std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator_;
};

TEST_F(LogExternalLogEventListenerInnerFunctionTest,
       ExternalLogEventListenerInnerFunctions) {
  v8::ScriptCompiler::CachedData* cache;
  static const char* source_cstring =
      "(function f1() { return (function f2() {}); })()";

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = array_buffer_allocator();

  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  {  // Test that we emit the correct code events from eagerly compiling.
    v8::HandleScope scope(isolate1);
    v8::Isolate::Scope isolate_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope context_scope(context);

    TestCodeEventHandler code_event_handler(isolate1);
    code_event_handler.Enable();

    v8::Local<v8::String> source_string = NewString(source_cstring);
    v8::ScriptOrigin origin(NewString("test"));
    v8::ScriptCompiler::Source source(source_string, origin);
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(isolate1, &source)
            .ToLocalChecked();
    CHECK_EQ(code_event_handler.CountLines("Function", "f1"),
             1 + (i::v8_flags.stress_background_compile ? 1 : 0) +
                 (i::v8_flags.always_sparkplug ? 1 : 0));
    CHECK_EQ(code_event_handler.CountLines("Function", "f2"),
             1 + (i::v8_flags.stress_background_compile ? 1 : 0) +
                 (i::v8_flags.always_sparkplug ? 1 : 0));
    cache = v8::ScriptCompiler::CreateCodeCache(script);
  }
  isolate1->Dispose();

  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  {  // Test that we emit the correct code events from deserialization.
    v8::HandleScope scope(isolate2);
    v8::Isolate::Scope isolate_scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope context_scope(context);

    TestCodeEventHandler code_event_handler(isolate2);
    code_event_handler.Enable();

    v8::Local<v8::String> source_string = NewString(source_cstring);
    v8::ScriptOrigin origin(NewString("test"));
    v8::ScriptCompiler::Source source(source_string, origin, cache);
    {
      i::DisallowCompilation no_compile_expected(
          reinterpret_cast<i::Isolate*>(isolate2));
      v8::ScriptCompiler::CompileUnboundScript(
          isolate2, &source, v8::ScriptCompiler::kConsumeCodeCache)
          .ToLocalChecked();
    }
    CHECK_EQ(code_event_handler.CountLines("Function", "f1"), 1);
    CHECK_EQ(code_event_handler.CountLines("Function", "f2"), 1);
  }
  isolate2->Dispose();
}

#ifndef V8_TARGET_ARCH_ARM

class LogExternalInterpretedFramesNativeStackTest : public TestWithIsolate {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.log = false;
    i::v8_flags.prof = false;
    i::v8_flags.interpreted_frames_native_stack = true;
    TestWithIsolate::SetUpTestSuite();
  }
};
TEST_F(LogExternalInterpretedFramesNativeStackTest,
       ExternalLogEventListenerWithInterpretedFramesNativeStack) {
  {
    v8::HandleScope scope(isolate());
    v8::Isolate::Scope isolate_scope(isolate());
    v8::Local<v8::Context> context = v8::Context::New(isolate());
    context->Enter();

    i::FakeCodeEventLogger code_event_logger(i_isolate());
    CHECK(i_isolate()->logger()->AddListener(&code_event_logger));

    TestCodeEventHandler code_event_handler(isolate());

    const char* source_text_before_start =
        "function testLogEventListenerBeforeStart(a,b) { return a + b };"
        "testLogEventListenerBeforeStart('1', 1);";
    RunJS(source_text_before_start);

    CHECK_EQ(code_event_handler.CountLines("Function",
                                           "testLogEventListenerBeforeStart"),
             0);

    code_event_handler.Enable();

    CHECK_GE(code_event_handler.CountLines("Function",
                                           "testLogEventListenerBeforeStart"),
             2);

    const char* source_text_after_start =
        "function testLogEventListenerAfterStart(a,b) { return a + b };"
        "testLogEventListenerAfterStart('1', 1);";
    RunJS(source_text_after_start);

    CHECK_GE(code_event_handler.CountLines("Function",
                                           "testLogEventListenerAfterStart"),
             2);

    CHECK_EQ(
        code_event_handler.CountLines("Builtin", "InterpreterEntryTrampoline"),
        1);

    context->Exit();
    CHECK(i_isolate()->logger()->RemoveListener(&code_event_logger));
  }
}
#endif  // V8_TARGET_ARCH_ARM

class LogMapsTest : public LogTest {
 public:
  static void SetUpTestSuite() {
    i::v8_flags.log_maps = true;
    LogTest::SetUpTestSuite();
  }
};
TEST_F(LogMapsTest, TraceMaps) {
  {
    ScopedLoggerInitializer logger(isolate());
    // Try to create many different kind of maps to make sure the logging won't
    // crash. More detailed tests are implemented separately.
    const char* source_text = R"(
      let a = {};
      for (let i = 0; i < 500; i++) {
        a['p'+i] = i
      };
      class Test {
        constructor(i) {
          this.a = 1;
          this['p'+i] = 1;
        }
      };
      let t = new Test();
      t.b = 1; t.c = 1; t.d = 3;
      for (let i = 0; i < 100; i++) {
        t = new Test(i)
      };
      t.b = {};
    )";
    RunJS(source_text);

    logger.StopLogging();

    // Mostly superficial checks.
    CHECK(logger.ContainsLine({"map,InitialMap", ",0x"}));
    CHECK(logger.ContainsLine({"map,Transition", ",0x"}));
    CHECK(logger.ContainsLine({"map-details", ",0x"}));
  }
}

namespace {
// Ensure that all Maps found on the heap have a single corresponding map-create
// and map-details entry in the v8.log.
void ValidateMapDetailsLogging(v8::Isolate* isolate,
                               ScopedLoggerInitializer* logger) {
  // map-create might have duplicates if a Map address is reused after a gc.
  std::unordered_set<uintpt
"""


```