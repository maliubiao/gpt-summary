Response:
The user is asking for a summary of the functionality of the C++ source code file `net/log/file_net_log_observer_unittest.cc`. They also want to know:
1. **Relationship to Javascript:** If the code has any connection to Javascript functionality.
2. **Logical Inference:**  If the code performs logical reasoning, with example inputs and outputs.
3. **Common User/Programming Errors:**  Examples of mistakes related to this code.
4. **Debugging Steps:** How a user's actions might lead to this code being executed during debugging.
5. **Overall Functionality Summary:** A concise summary of the code's purpose.

Let's break down the code to address each of these points.

**Code Analysis:**

The code is a unit test file (`_unittest.cc`). Its purpose is to test the functionality of `net/log/file_net_log_observer.h` and `net/log/file_net_log_observer.cc`. This class is responsible for writing network logging information to a file.

**1. Functionality:**

The test suite covers various aspects of `FileNetLogObserver`:

* **Initialization:**  Testing how the observer is created in both bounded (limited file size/number of files) and unbounded modes. It also tests scenarios with pre-existing files and invalid file paths.
* **Event Logging:**  Verifying that network events are correctly written to the log file. This includes testing with zero, one, and multiple events, and ensuring the JSON format is valid.
* **File Handling (Bounded Mode):** Thoroughly testing the bounded mode's behavior regarding file size limits, the number of files, and how the observer handles filling, truncating, and overwriting log files. This involves checking if events are dropped or if older files are overwritten as expected.
* **Concurrency:** Testing how the observer handles concurrent event additions from multiple threads.
* **Custom Constants:** Verifying that custom constants provided during initialization are included in the log file.
* **Polled Data:** Ensuring that additional polled data provided when stopping the observer is also written to the log.
* **Capture Mode:** Checking that the configured capture mode is recorded in the log file's constants.
* **Error Handling:**  Testing how the observer behaves when provided with an invalid output path or a pre-existing file that cannot be opened.
* **Resource Management:** Implicitly testing that resources (like file handles) are properly managed and released.

**2. Relationship to Javascript:**

The code itself is C++ and doesn't directly execute Javascript. However, it's part of Chromium's network stack, which is heavily involved in handling web requests initiated by Javascript code running in a web page.

* **Example:** When a Javascript `fetch()` API call is made, it triggers network requests handled by the Chromium network stack. Events related to this request (DNS lookup, TCP connection, HTTP headers, etc.) can be logged by `FileNetLogObserver` if it's active.

**3. Logical Inference:**

The tests involve logical reasoning about how the observer should behave under different conditions, especially in bounded mode.

* **Hypothesis:**  In bounded mode, when the total log size exceeds the limit, older events will be dropped or older files will be overwritten.
* **Input:** Configure the observer with a limited file size and send more events than can fit.
* **Output:** The generated log file will contain only the most recent events, or the older log files will have been overwritten with newer events. The tests use `VerifyEventsInLog` to assert this.

**4. Common User/Programming Errors:**

* **Providing an invalid file path:** If a user (or the program) provides a path where the necessary directories don't exist and the process doesn't have permissions to create them, the log file won't be created. The test `InitLogWithInvalidPath` covers this.
* **Not calling `StopObserving()`:** If the observer is destroyed without explicitly stopping it, any partially written files in bounded mode might be deleted. The tests `ObserverDestroyedWithoutStopObserving` and `ObserverDestroyedWithoutStopObservingPreExisting` demonstrate this.
* **Incorrectly calculating file sizes in bounded mode:**  Developers need to be mindful of the configured `total_file_size` and `num_files` in bounded mode. Sending too few or too many events might lead to unexpected log file contents. The various bounded mode tests illustrate this.

**5. User Operation to Reach This Code (Debugging):**

A user interacting with a Chromium-based browser could indirectly lead to this code being relevant during debugging in several ways:

* **Network Issues:** If a user experiences problems with web page loading, network connectivity, or specific website behavior, a developer might enable network logging to diagnose the issue. This involves setting flags in the browser (like `--log-net-log=netlog.json`) or using the `chrome://net-export/` interface.
* **Performance Analysis:** To analyze network performance, a developer might capture a network log to identify bottlenecks or inefficiencies in the network requests.
* **Bug Reporting:** When reporting a network-related bug, providing a network log can be crucial for developers to understand the sequence of network events leading to the problem.

**Debugging Steps:**

1. **User encounters a network issue (e.g., website fails to load).**
2. **Developer (or advanced user) decides to capture a network log.**
3. **They configure Chromium to start network logging, which internally instantiates a `FileNetLogObserver`.**
4. **The user reproduces the network issue.**
5. **Chromium writes network events to the log file via the `FileNetLogObserver`.**
6. **The developer examines the generated log file (`netlog.json`) to understand the network events.**
7. **If the `FileNetLogObserver` has bugs or unexpected behavior, the unit tests in `file_net_log_observer_unittest.cc` would be used to identify and fix those issues.**

**Functionality Summary:**

The `file_net_log_observer_unittest.cc` file contains unit tests for the `FileNetLogObserver` class in Chromium's network stack. These tests comprehensively validate the observer's ability to write network logging information to files, focusing on various scenarios like bounded/unbounded logging, file size limits, concurrency, custom data, and error handling. It ensures the reliability and correctness of the network logging mechanism.

这是目录为 `net/log/file_net_log_observer_unittest.cc` 的 Chromium 网络栈的源代码文件，它是 `FileNetLogObserver` 类的单元测试文件。 `FileNetLogObserver` 负责将网络日志信息写入文件。以下是该文件的功能归纳：

**主要功能:**

1. **测试 `FileNetLogObserver` 类的各种功能:** 该文件包含了大量的测试用例，用于验证 `FileNetLogObserver` 类的各种方法和在不同场景下的行为是否符合预期。
2. **覆盖有界和无界日志记录模式:**  测试用例分别针对 `FileNetLogObserver` 的有界模式（日志文件大小和数量有限制）和无界模式（日志文件大小无限制）进行测试。
3. **测试日志事件的添加和写入:**  测试用例模拟添加各种网络日志事件，并验证这些事件是否被正确地写入到日志文件中，包括事件的顺序和内容。
4. **验证日志文件的格式:**  测试用例会读取生成的日志文件，并验证其是否符合预期的 JSON 格式。
5. **测试日志文件的大小和数量限制 (有界模式):**  针对有界模式，测试用例会验证日志文件是否按照配置的大小和数量限制进行滚动和覆盖。
6. **测试并发写入:**  测试用例模拟多个线程同时向日志记录器写入事件，验证其并发安全性。
7. **测试自定义常量和轮询数据:**  测试用例验证用户提供的自定义常量和轮询数据是否被正确地包含在日志文件中。
8. **测试不同的日志捕获模式:**  测试用例验证不同的日志捕获模式（例如：`kEverything`, `kIncludeSensitive`, `kDefault`）是否被正确地记录在日志文件中。
9. **测试错误处理:**  测试用例验证在遇到错误情况（例如：无效的文件路径，无法打开文件等）时，`FileNetLogObserver` 的行为是否符合预期。
10. **测试 `StopObserving` 的行为:**  测试用例验证在调用 `StopObserving` 后，日志文件是否被正确地关闭和保存。

**与 Javascript 的关系:**

该 C++ 测试文件本身不包含任何 Javascript 代码，但它测试的网络日志记录器 `FileNetLogObserver` 可以记录由 Javascript 发起的网络请求的相关事件。

**举例说明:**

假设一个网页上的 Javascript 代码使用 `fetch()` API 发起一个 HTTP 请求。这个请求在 Chromium 的网络栈中会被处理，并可能产生一系列的日志事件，例如：

* DNS 查询开始和结束
* TCP 连接建立
* TLS 握手
* HTTP 请求头和响应头的发送和接收
* HTTP 响应体的数据传输

如果 `FileNetLogObserver` 正在运行，它会将这些事件记录到文件中。因此，虽然这个测试文件本身不是 Javascript，但它测试的代码直接服务于记录由 Javascript 触发的网络行为。

**逻辑推理的假设输入与输出:**

**假设输入 (针对有界模式测试):**

* `total_file_size`: 10000 字节
* `num_files`: 2
* 添加 15 个大小为 800 字节的日志事件。

**逻辑推理:**

* 每个日志文件的平均大小为 10000 / 2 = 5000 字节。
* 每个日志文件可以容纳大约 5000 / 800 = 6 个事件。
* 第一个日志文件将写入 6 个事件。
* 第二个日志文件将写入接下来的 6 个事件。
* 由于总共有 15 个事件，最早的 3 个事件将被覆盖掉。

**预期输出:**

生成的日志文件将包含最后写入的 12 个事件。最早的 3 个事件将不会出现在最终的日志中。  `VerifyEventsInLog` 等函数会验证这一点。

**用户或编程常见的使用错误:**

1. **提供无效的文件路径:** 用户或程序可能提供一个无法写入的路径（例如，目录不存在，没有写入权限）。在这种情况下，`FileNetLogObserver` 可能无法创建或写入日志文件。测试用例 `InitLogWithInvalidPath` 验证了这种情况。
2. **在未调用 `StopObserving` 的情况下销毁 `FileNetLogObserver`:**  如果 `FileNetLogObserver` 在没有显式调用 `StopObserving` 的情况下被销毁，可能会导致部分日志数据丢失或文件未正确关闭。测试用例 `ObserverDestroyedWithoutStopObserving` 和 `ObserverDestroyedWithoutStopObservingPreExisting` 验证了这种情况。
3. **在有界模式下，配置的日志文件大小过小:** 如果配置的 `total_file_size` 太小，可能很快就会被填满，导致大量旧事件被覆盖，用户可能无法获取到完整的日志信息。
4. **并发写入时未考虑线程安全:**  虽然 `FileNetLogObserver` 应该处理并发写入，但如果用户在其他部分的代码中不正确地操作与日志相关的资源，仍然可能导致问题。测试用例 `AddEventsFromMultipleThreads` 验证了 `FileNetLogObserver` 的线程安全性。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户遇到网络问题:** 用户在使用 Chromium 浏览器时，可能会遇到网页加载缓慢、连接失败、资源加载错误等网络问题。
2. **用户或开发者启用网络日志记录:** 为了诊断问题，用户或开发者可能会通过以下方式启用网络日志记录：
    * 在启动 Chromium 时添加命令行标志 `--log-net-log=netlog.json`。
    * 使用 `chrome://net-export/` 页面进行网络日志导出。
3. **Chromium 创建并启动 `FileNetLogObserver`:** 当网络日志记录被启用时，Chromium 会创建 `FileNetLogObserver` 的实例，并开始监听网络事件。
4. **用户重现网络问题:** 用户在浏览器中执行操作，导致网络问题再次发生。
5. **`FileNetLogObserver` 记录网络事件:** 在问题发生期间，`FileNetLogObserver` 会将相关的网络事件信息写入到指定的日志文件中。
6. **开发者分析日志文件:** 开发者会查看生成的 `netlog.json` 文件，分析其中的事件序列，寻找导致问题的根源。
7. **如果 `FileNetLogObserver` 本身存在缺陷:**  如果在分析日志时发现日志信息不完整、格式错误或其他异常，开发者可能会怀疑是 `FileNetLogObserver` 的问题。此时，他们会查阅和运行 `file_net_log_observer_unittest.cc` 中的测试用例，以验证 `FileNetLogObserver` 的行为是否符合预期，从而帮助定位和修复 bug。

**功能归纳 (第 1 部分):**

该文件的主要功能是 **作为 `FileNetLogObserver` 类的单元测试套件，验证其在各种场景下的日志记录功能是否正确可靠，包括有界和无界模式、事件添加、文件大小限制、并发写入、自定义数据以及错误处理等。** 它确保了 Chromium 网络栈中日志记录机制的正确性。

Prompt: 
```
这是目录为net/log/file_net_log_observer_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/log/file_net_log_observer.h"

#include <string>
#include <vector>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/test/gmock_expected_support.h"
#include "base/threading/thread.h"
#include "base/types/expected.h"
#include "base/types/expected_macros.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log.h"
#include "net/log/net_log_entry.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_util.h"
#include "net/log/net_log_values.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Indicates the number of event files used in test cases.
const int kTotalNumFiles = 10;

// Used to set the total file size maximum in test cases where the file size
// doesn't matter.
const int kLargeFileSize = 100000000;

// Used to set the size of events to be sent to the observer in test cases
// where event size doesn't matter.
const size_t kDummyEventSize = 150;

// Adds |num_entries| to |logger|. The "inverse" of this is VerifyEventsInLog().
void AddEntries(FileNetLogObserver* logger,
                int num_entries,
                size_t entry_size) {
  // Get base size of event.
  const int kDummyId = 0;
  NetLogSource source(NetLogSourceType::HTTP2_SESSION, kDummyId);
  NetLogEntry base_entry(NetLogEventType::PAC_JAVASCRIPT_ERROR, source,
                         NetLogEventPhase::BEGIN, base::TimeTicks::Now(),
                         NetLogParamsWithString("message", ""));
  base::Value::Dict value = base_entry.ToDict();
  std::string json;
  base::JSONWriter::Write(value, &json);
  size_t base_entry_size = json.size();

  // The maximum value of base::TimeTicks::Now() will be the maximum value of
  // int64_t, and if the maximum number of digits are included, the
  // |base_entry_size| could be up to 136 characters. Check that the event
  // format does not include additional padding.
  DCHECK_LE(base_entry_size, 136u);

  // |entry_size| should be at least as big as the largest possible base
  // entry.
  EXPECT_GE(entry_size, 136u);

  // |entry_size| cannot be smaller than the minimum event size.
  EXPECT_GE(entry_size, base_entry_size);

  for (int i = 0; i < num_entries; i++) {
    source = NetLogSource(NetLogSourceType::HTTP2_SESSION, i);
    std::string id = base::NumberToString(i);

    // String size accounts for the number of digits in id so that all events
    // are the same size.
    std::string message =
        std::string(entry_size - base_entry_size - id.size() + 1, 'x');
    NetLogEntry entry(NetLogEventType::PAC_JAVASCRIPT_ERROR, source,
                      NetLogEventPhase::BEGIN, base::TimeTicks::Now(),
                      NetLogParamsWithString("message", message));
    logger->OnAddEntry(entry);
  }
}

// ParsedNetLog holds the parsed contents of a NetLog file (constants, events,
// and polled data).
struct ParsedNetLog {
  base::expected<void, std::string> InitFromFileContents(
      const std::string& input);
  const base::Value::Dict* GetEvent(size_t i) const;

  // Initializes the ParsedNetLog by parsing a JSON file.
  // Owner for the Value tree and a dictionary for the entire netlog.
  base::Value root;

  // The constants dictionary.
  raw_ptr<const base::Value::Dict> constants = nullptr;

  // The events list.
  raw_ptr<const base::Value::List> events = nullptr;

  // The optional polled data (may be nullptr).
  raw_ptr<const base::Value::Dict> polled_data = nullptr;
};

base::expected<void, std::string> ParsedNetLog::InitFromFileContents(
    const std::string& input) {
  if (input.empty()) {
    return base::unexpected("input is empty");
  }

  ASSIGN_OR_RETURN(root, base::JSONReader::ReadAndReturnValueWithError(input),
                   &base::JSONReader::Error::message);

  const base::Value::Dict* dict = root.GetIfDict();
  if (!dict) {
    return base::unexpected("Not a dictionary");
  }

  events = dict->FindListByDottedPath("events");
  if (!events) {
    return base::unexpected("No events list");
  }

  constants = dict->FindDictByDottedPath("constants");
  if (!constants) {
    return base::unexpected("No constants dictionary");
  }

  // Polled data is optional (ignore success).
  polled_data = dict->FindDictByDottedPath("polledData");

  return base::ok();
}

// Returns the event at index |i|, or nullptr if there is none.
const base::Value::Dict* ParsedNetLog::GetEvent(size_t i) const {
  if (!events || i >= events->size())
    return nullptr;

  return (*events)[i].GetIfDict();
}

// Creates a ParsedNetLog by reading a NetLog from a file. Returns nullptr on
// failure.
base::expected<std::unique_ptr<ParsedNetLog>, std::string> ReadNetLogFromDisk(
    const base::FilePath& log_path) {
  std::string input;
  if (!base::ReadFileToString(log_path, &input)) {
    return base::unexpected("Failed reading file: " +
                            base::UTF16ToUTF8(log_path.LossyDisplayName()));
  }

  std::unique_ptr<ParsedNetLog> result = std::make_unique<ParsedNetLog>();

  RETURN_IF_ERROR(result->InitFromFileContents(input));
  return result;
}

// Checks that |log| contains events as emitted by AddEntries() above.
// |num_events_emitted| corresponds to |num_entries| of AddEntries(). Whereas
// |num_events_saved| is the expected number of events that have actually been
// written to the log (post-truncation).
void VerifyEventsInLog(const ParsedNetLog* log,
                       size_t num_events_emitted,
                       size_t num_events_saved) {
  ASSERT_TRUE(log);
  ASSERT_LE(num_events_saved, num_events_emitted);
  ASSERT_EQ(num_events_saved, log->events->size());

  // The last |num_events_saved| should all be sequential, with the last one
  // being numbered |num_events_emitted - 1|.
  for (size_t i = 0; i < num_events_saved; ++i) {
    const base::Value::Dict* event = log->GetEvent(i);
    ASSERT_TRUE(event);

    size_t expected_source_id = num_events_emitted - num_events_saved + i;

    std::optional<int> id_value = event->FindIntByDottedPath("source.id");
    ASSERT_EQ(static_cast<int>(expected_source_id), id_value);
  }
}

// Helper that checks whether |dict| has a string property at |key| having
// |value|.
void ExpectDictionaryContainsProperty(const base::Value::Dict& dict,
                                      const std::string& key,
                                      const std::string& value) {
  const std::string* actual_value = dict.FindStringByDottedPath(key);
  ASSERT_EQ(value, *actual_value);
}

// Used for tests that are common to both bounded and unbounded modes of the
// the FileNetLogObserver. The param is true if bounded mode is used.
class FileNetLogObserverTest : public ::testing::TestWithParam<bool>,
                               public WithTaskEnvironment {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_path_ = temp_dir_.GetPath().AppendASCII("net-log.json");
  }

  void TearDown() override {
    logger_.reset();
    // FileNetLogObserver destructor might post to message loop.
    RunUntilIdle();
  }

  bool IsBounded() const { return GetParam(); }

  void CreateAndStartObserving(
      std::unique_ptr<base::Value::Dict> constants,
      NetLogCaptureMode capture_mode = NetLogCaptureMode::kDefault) {
    if (IsBounded()) {
      logger_ = FileNetLogObserver::CreateBoundedForTests(
          log_path_, kLargeFileSize, kTotalNumFiles, capture_mode,
          std::move(constants));
    } else {
      logger_ = FileNetLogObserver::CreateUnbounded(log_path_, capture_mode,
                                                    std::move(constants));
    }

    logger_->StartObserving(NetLog::Get());
  }

  void CreateAndStartObservingBoundedFile(
      int max_file_size,
      std::unique_ptr<base::Value::Dict> constants) {
    base::File file(log_path_,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
    // Stick in some nonsense to make sure the file gets cleared properly
    file.Write(0, "not json", 8);

    logger_ = FileNetLogObserver::CreateBoundedFile(
        std::move(file), max_file_size, NetLogCaptureMode::kDefault,
        std::move(constants));

    logger_->StartObserving(NetLog::Get());
  }

  void CreateAndStartObservingPreExisting(
      std::unique_ptr<base::Value::Dict> constants) {
    ASSERT_TRUE(scratch_dir_.CreateUniqueTempDir());

    base::File file(log_path_,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
    // Stick in some nonsense to make sure the file gets cleared properly
    file.Write(0, "not json", 8);

    if (IsBounded()) {
      logger_ = FileNetLogObserver::CreateBoundedPreExisting(
          scratch_dir_.GetPath(), std::move(file), kLargeFileSize,
          NetLogCaptureMode::kDefault, std::move(constants));
    } else {
      logger_ = FileNetLogObserver::CreateUnboundedPreExisting(
          std::move(file), NetLogCaptureMode::kDefault, std::move(constants));
    }

    logger_->StartObserving(NetLog::Get());
  }

  bool LogFileExists() {
    // The log files are written by a sequenced task runner. Drain all the
    // scheduled tasks to ensure that the file writing ones have run before
    // checking if they exist.
    base::ThreadPoolInstance::Get()->FlushForTesting();
    return base::PathExists(log_path_);
  }

 protected:
  std::unique_ptr<FileNetLogObserver> logger_;
  base::ScopedTempDir temp_dir_;
  base::ScopedTempDir scratch_dir_;  // used for bounded + preexisting
  base::FilePath log_path_;
};

// Used for tests that are exclusive to the bounded mode of FileNetLogObserver.
class FileNetLogObserverBoundedTest : public ::testing::Test,
                                      public WithTaskEnvironment {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    log_path_ = temp_dir_.GetPath().AppendASCII("net-log.json");
  }

  void TearDown() override {
    logger_.reset();
    // FileNetLogObserver destructor might post to message loop.
    RunUntilIdle();
  }

  void CreateAndStartObserving(std::unique_ptr<base::Value::Dict> constants,
                               uint64_t total_file_size,
                               int num_files) {
    logger_ = FileNetLogObserver::CreateBoundedForTests(
        log_path_, total_file_size, num_files, NetLogCaptureMode::kDefault,
        std::move(constants));
    logger_->StartObserving(NetLog::Get());
  }

  // Returns the path for an internally directory created for bounded logs (this
  // needs to be kept in sync with the implementation).
  base::FilePath GetInprogressDirectory() const {
    return log_path_.AddExtension(FILE_PATH_LITERAL(".inprogress"));
  }

  base::FilePath GetEventFilePath(int index) const {
    return GetInprogressDirectory().AppendASCII(
        "event_file_" + base::NumberToString(index) + ".json");
  }

  base::FilePath GetEndNetlogPath() const {
    return GetInprogressDirectory().AppendASCII("end_netlog.json");
  }

  base::FilePath GetConstantsPath() const {
    return GetInprogressDirectory().AppendASCII("constants.json");
  }


 protected:
  std::unique_ptr<FileNetLogObserver> logger_;
  base::FilePath log_path_;

 private:
  base::ScopedTempDir temp_dir_;
};

// Instantiates each FileNetLogObserverTest to use bounded and unbounded modes.
INSTANTIATE_TEST_SUITE_P(All,
                         FileNetLogObserverTest,
                         ::testing::Values(true, false));

// Tests deleting a FileNetLogObserver without first calling StopObserving().
TEST_P(FileNetLogObserverTest, ObserverDestroyedWithoutStopObserving) {
  CreateAndStartObserving(nullptr);

  // Send dummy event
  AddEntries(logger_.get(), 1, kDummyEventSize);

  // The log files should have been started.
  ASSERT_TRUE(LogFileExists());

  logger_.reset();

  // When the logger is re-set without having called StopObserving(), the
  // partially written log files are deleted.
  ASSERT_FALSE(LogFileExists());
}

// Same but with pre-existing file.
TEST_P(FileNetLogObserverTest,
       ObserverDestroyedWithoutStopObservingPreExisting) {
  CreateAndStartObservingPreExisting(nullptr);

  // Send dummy event
  AddEntries(logger_.get(), 1, kDummyEventSize);

  // The log files should have been started.
  ASSERT_TRUE(LogFileExists());

  // Should also have the scratch dir, if bounded. (Can be checked since
  // LogFileExists flushed the thread pool).
  if (IsBounded()) {
    ASSERT_TRUE(base::PathExists(scratch_dir_.GetPath()));
  }

  logger_.reset();

  // Unlike in the non-preexisting case, the output file isn't deleted here,
  // since the process running the observer likely won't have the sandbox
  // permission to do so.
  ASSERT_TRUE(LogFileExists());
  if (IsBounded()) {
    ASSERT_FALSE(base::PathExists(scratch_dir_.GetPath()));
  }
}

// Tests calling StopObserving() with a null closure.
TEST_P(FileNetLogObserverTest, StopObservingNullClosure) {
  CreateAndStartObserving(nullptr);

  // Send dummy event
  AddEntries(logger_.get(), 1, kDummyEventSize);

  // The log files should have been started.
  ASSERT_TRUE(LogFileExists());

  logger_->StopObserving(nullptr, base::OnceClosure());

  logger_.reset();

  // Since the logger was explicitly stopped, its files should still exist.
  ASSERT_TRUE(LogFileExists());
}

// Tests creating a FileNetLogObserver using an invalid (can't be written to)
// path.
TEST_P(FileNetLogObserverTest, InitLogWithInvalidPath) {
  // Use a path to a non-existent directory.
  log_path_ = temp_dir_.GetPath().AppendASCII("bogus").AppendASCII("path");

  CreateAndStartObserving(nullptr);

  // Send dummy event
  AddEntries(logger_.get(), 1, kDummyEventSize);

  // No log files should have been written, as the log writer will not create
  // missing directories.
  ASSERT_FALSE(LogFileExists());

  logger_->StopObserving(nullptr, base::OnceClosure());

  logger_.reset();

  // There should still be no files.
  ASSERT_FALSE(LogFileExists());
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithNoEvents) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(0u, log->events->size());
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithOneEvent) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  // Send dummy event.
  AddEntries(logger_.get(), 1, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(1u, log->events->size());
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithOneEventPreExisting) {
  TestClosure closure;

  CreateAndStartObservingPreExisting(nullptr);

  // Send dummy event.
  AddEntries(logger_.get(), 1, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(1u, log->events->size());
}

TEST_P(FileNetLogObserverTest,
       GeneratesValidJSONWithNoEventsCreateBoundedFile) {
  TestClosure closure;

  CreateAndStartObservingBoundedFile(kLargeFileSize, nullptr);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(0u, log->events->size());
}

TEST_P(FileNetLogObserverTest,
       GeneratesValidJSONWithOneEventCreateBoundedFile) {
  TestClosure closure;

  CreateAndStartObservingBoundedFile(kLargeFileSize, nullptr);

  // Send dummy event.
  AddEntries(logger_.get(), 1, kDummyEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(1u, log->events->size());
}

// Sends exactly enough events to the observer to completely fill the file.
TEST_P(FileNetLogObserverTest, BoundedFileFillsFile) {
  const int kTotalFileSize = 10000;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize;
  const int kNumEvents = kFileSize / kEventSize;
  TestClosure closure;

  CreateAndStartObservingBoundedFile(kTotalFileSize, nullptr);

  // Send dummy events.
  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

// Sends twice as many events as will fill the file to the observer
TEST_P(FileNetLogObserverTest, BoundedFileTruncatesEventsAfterLimit) {
  const int kTotalFileSize = 10000;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize;
  const int kNumEvents = kFileSize / kEventSize;
  TestClosure closure;

  CreateAndStartObservingBoundedFile(kTotalFileSize, nullptr);

  // Send dummy events.
  AddEntries(logger_.get(), kNumEvents * 2, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

TEST_P(FileNetLogObserverTest, PreExistingFileBroken) {
  // Test that pre-existing output file not being successfully open is
  // tolerated.
  ASSERT_TRUE(scratch_dir_.CreateUniqueTempDir());
  base::File file;
  EXPECT_FALSE(file.IsValid());
  if (IsBounded())
    logger_ = FileNetLogObserver::CreateBoundedPreExisting(
        scratch_dir_.GetPath(), std::move(file), kLargeFileSize,
        NetLogCaptureMode::kDefault, nullptr);
  else
    logger_ = FileNetLogObserver::CreateUnboundedPreExisting(
        std::move(file), NetLogCaptureMode::kDefault, nullptr);
  logger_->StartObserving(NetLog::Get());

  // Send dummy event.
  AddEntries(logger_.get(), 1, kDummyEventSize);
  TestClosure closure;
  logger_->StopObserving(nullptr, closure.closure());
  closure.WaitForResult();
}

TEST_P(FileNetLogObserverTest, CustomConstants) {
  TestClosure closure;

  const char kConstantKey[] = "magic";
  const char kConstantString[] = "poney";
  base::Value::Dict constants;
  constants.SetByDottedPath(kConstantKey, kConstantString);

  CreateAndStartObserving(
      std::make_unique<base::Value::Dict>(std::move(constants)));

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));

  // Check that custom constant was correctly printed.
  ExpectDictionaryContainsProperty(*log->constants, kConstantKey,
                                   kConstantString);
}

TEST_P(FileNetLogObserverTest, GeneratesValidJSONWithPolledData) {
  TestClosure closure;

  CreateAndStartObserving(nullptr);

  // Create dummy polled data
  const char kDummyPolledDataPath[] = "dummy_path";
  const char kDummyPolledDataString[] = "dummy_info";
  base::Value::Dict dummy_polled_data;
  dummy_polled_data.SetByDottedPath(kDummyPolledDataPath,
                                    kDummyPolledDataString);

  logger_->StopObserving(
      std::make_unique<base::Value>(std::move(dummy_polled_data)),
      closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  ASSERT_EQ(0u, log->events->size());

  // Make sure additional information is present and validate it.
  ASSERT_TRUE(log->polled_data);
  ExpectDictionaryContainsProperty(*log->polled_data, kDummyPolledDataPath,
                                   kDummyPolledDataString);
}

// Ensure that the Capture Mode is recorded as a constant in the NetLog.
TEST_P(FileNetLogObserverTest, LogModeRecorded) {
  struct TestCase {
    NetLogCaptureMode capture_mode;
    const char* expected_value;
  } test_cases[] = {// Challenges that result in success results.
                    {NetLogCaptureMode::kEverything, "Everything"},
                    {NetLogCaptureMode::kIncludeSensitive, "IncludeSensitive"},
                    {NetLogCaptureMode::kDefault, "Default"}};

  TestClosure closure;
  for (const auto& test_case : test_cases) {
    CreateAndStartObserving(nullptr, test_case.capture_mode);
    logger_->StopObserving(nullptr, closure.closure());
    closure.WaitForResult();
    ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                         ReadNetLogFromDisk(log_path_));
    ExpectDictionaryContainsProperty(*log->constants, "logCaptureMode",
                                     test_case.expected_value);
  }
}

// Adds events concurrently from several different threads. The exact order of
// events seen by this test is non-deterministic.
TEST_P(FileNetLogObserverTest, AddEventsFromMultipleThreads) {
  const size_t kNumThreads = 10;
  std::vector<std::unique_ptr<base::Thread>> threads(kNumThreads);

#if BUILDFLAG(IS_FUCHSIA)
  // TODO(crbug.com/40625862): Diagnosting logging to determine where
  // this test sometimes hangs.
  LOG(ERROR) << "Create and start threads.";
#endif

  // Start all the threads. Waiting for them to start is to hopefuly improve
  // the odds of hitting interesting races once events start being added.
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i] = std::make_unique<base::Thread>("WorkerThread" +
                                                base::NumberToString(i));
    threads[i]->Start();
    threads[i]->WaitUntilThreadStarted();
  }

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Create and start observing.";
#endif

  CreateAndStartObserving(nullptr);

  const size_t kNumEventsAddedPerThread = 200;

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Posting tasks.";
#endif

  // Add events in parallel from all the threads.
  for (size_t i = 0; i < kNumThreads; ++i) {
    threads[i]->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&AddEntries, base::Unretained(logger_.get()),
                                  kNumEventsAddedPerThread, kDummyEventSize));
  }

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Joining all threads.";
#endif

  // Join all the threads.
  threads.clear();

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Stop observing.";
#endif

  // Stop observing.
  TestClosure closure;
  logger_->StopObserving(nullptr, closure.closure());
  closure.WaitForResult();

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Read log from disk and verify.";
#endif

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  // Check that the expected number of events were written to disk.
  EXPECT_EQ(kNumEventsAddedPerThread * kNumThreads, log->events->size());

#if BUILDFLAG(IS_FUCHSIA)
  LOG(ERROR) << "Teardown.";
#endif
}

// Sends enough events to the observer to completely fill one file, but not
// write any events to an additional file. Checks the file bounds.
TEST_F(FileNetLogObserverBoundedTest, EqualToOneFile) {
  // The total size of the events is equal to the size of one file.
  // |kNumEvents| * |kEventSize| = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 5000;
  const int kNumEvents = 2;
  const int kEventSize = 250;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);
  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

// Sends enough events to fill one file, and partially fill a second file.
// Checks the file bounds and writing to a new file.
TEST_F(FileNetLogObserverBoundedTest, OneEventOverOneFile) {
  // The total size of the events is greater than the size of one file, and
  // less than the size of two files. The total size of all events except one
  // is equal to the size of one file, so the last event will be the only event
  // in the second file.
  // (|kNumEvents| - 1) * kEventSize = |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 4;
  const int kEventSize = 200;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

// Sends enough events to the observer to completely fill two files.
TEST_F(FileNetLogObserverBoundedTest, EqualToTwoFiles) {
  // The total size of the events is equal to the total size of two files.
  // |kNumEvents| * |kEventSize| = 2 * |kTotalFileSize| / |kTotalNumEvents|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 6;
  const int kEventSize = 200;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

// Sends exactly enough events to the observer to completely fill all files,
// so that all events fit into the event files and no files need to be
// overwritten.
TEST_F(FileNetLogObserverBoundedTest, FillAllFilesNoOverwriting) {
  // The total size of events is equal to the total size of all files.
  // |kEventSize| * |kNumEvents| = |kTotalFileSize|
  const int kTotalFileSize = 10000;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  const int kNumEvents = kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1);
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents, kNumEvents);
}

// Sends more events to the observer than will fill the WriteQueue, forcing the
// queue to drop an event. Checks that the queue drops the oldest event.
TEST_F(FileNetLogObserverBoundedTest, DropOldEventsFromWriteQueue) {
  // The total size of events is greater than the WriteQueue's memory limit, so
  // the oldest event must be dropped from the queue and not written to any
  // file.
  // |kNumEvents| * |kEventSize| > |kTotalFileSize| * 2
  const int kTotalFileSize = 1000;
  const int kNumEvents = 11;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(
      log.get(), kNumEvents,
      static_cast<size_t>(kTotalNumFiles * ((kFileSize - 1) / kEventSize + 1)));
}

// Sends twice as many events as will fill all files to the observer, so that
// all of the event files will be filled twice, and every file will be
// overwritten.
TEST_F(FileNetLogObserverBoundedTest, OverwriteAllFiles) {
  // The total size of the events is much greater than twice the number of
  // events that can fit in the event files, to make sure that the extra events
  // are written to a file, not just dropped from the queue.
  // |kNumEvents| * |kEventSize| >= 2 * |kTotalFileSize|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 60;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Check that the minimum number of events that should fit in event files
  // have been written to all files.
  int events_per_file = (kFileSize - 1) / kEventSize + 1;
  int events_in_last_file = (kNumEvents - 1) % events_per_file + 1;

  // Indicates the total number of events that should be written to all files.
  int num_events_in_files =
      (kTotalNumFiles - 1) * events_per_file + events_in_last_file;

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents,
                    static_cast<size_t>(num_events_in_files));
}

// Sends enough events to the observer to fill all event files, plus overwrite
// some files, without overwriting all of them. Checks that the FileWriter
// overwrites the file with the oldest events.
TEST_F(FileNetLogObserverBoundedTest, PartiallyOverwriteFiles) {
  // The number of events sent to the observer is greater than the number of
  // events that can fit into the event files, but the events can fit in less
  // than twice the number of event files, so not every file will need to be
  // overwritten.
  // |kTotalFileSize| < |kNumEvents| * |kEventSize|
  // |kNumEvents| * |kEventSize| <= (2 * |kTotalNumFiles| - 1) * |kFileSize|
  const int kTotalFileSize = 6000;
  const int kNumEvents = 50;
  const int kEventSize = 200;
  const int kFileSize = kTotalFileSize / kTotalNumFiles;
  TestClosure closure;

  CreateAndStartObserving(nullptr, kTotalFileSize, kTotalNumFiles);

  AddEntries(logger_.get(), kNumEvents, kEventSize);

  logger_->StopObserving(nullptr, closure.closure());

  closure.WaitForResult();

  // Check that the minimum number of events that should fit in event files
  // have been written to a file.
  int events_per_file = (kFileSize - 1) / kEventSize + 1;
  int events_in_last_file = kNumEvents % events_per_file;
  if (!events_in_last_file)
    events_in_last_file = events_per_file;
  int num_events_in_files =
      (kTotalNumFiles - 1) * events_per_file + events_in_last_file;

  // Verify the written log.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ParsedNetLog> log,
                       ReadNetLogFromDisk(log_path_));
  VerifyEventsInLog(log.get(), kNumEvents,
                    static_cast<size_t>(num_events_in_files));
}

// Start logging in bounded mode. Create directories in places where the logger
// expects to create files, in order to cause that file creation to fail.
//
//   constants.json      -- succeess
//   event_file_0.json   -- fails to open
// 
"""


```