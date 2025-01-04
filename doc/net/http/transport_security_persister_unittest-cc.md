Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core purpose of this file (`transport_security_persister_unittest.cc`) is to test the functionality of `TransportSecurityPersister`. This class likely handles the saving and loading of transport security settings (like HSTS) to/from disk. The "unittest" suffix is a strong indicator of this.

2. **Identify Key Classes:**  The included headers immediately point to the main classes involved:
    * `net/http/transport_security_persister.h`:  The class being tested.
    * `net/http/transport_security_state.h`:  Likely the class that holds the in-memory representation of the transport security state. The persister's job is to move data between this state and persistent storage.

3. **Analyze the Test Fixture:** The `TransportSecurityPersisterTest` class is a test fixture. This means it sets up a consistent environment for each test. Key things to notice here:
    * `WithTaskEnvironment`: This suggests asynchronous operations and the need for a controlled environment for testing them. The `TimeSource::MOCK_TIME` is crucial – it allows tests to control the passage of time, which is vital for testing features like expiration.
    * `temp_dir_`:  A temporary directory is created. This is good practice for file-based testing, ensuring tests don't interfere with the user's system.
    * `transport_security_file_path_`:  The path to the file where the persister will read/write data.
    * `state_`: An instance of `TransportSecurityState`, the object being persisted.
    * `persister_`: The instance of `TransportSecurityPersister` being tested. It's initialized with the `state_`, a background task runner (for asynchronous file operations), and the file path.

4. **Examine Individual Test Cases:** Now, go through each `TEST_F` function:
    * **`LoadEntriesClearsExistingState`:** This test verifies that loading data overwrites the existing *dynamic* (non-static) entries in `TransportSecurityState`. This is an important behavior to confirm.
    * **`SerializeData1`, `SerializeData2`:** These tests focus on the serialization and deserialization process. They check if serializing, then deserializing, and then serializing again produces the same output, confirming the process is reversible and consistent. `SerializeData2` also verifies that the deserialized data correctly updates the `TransportSecurityState`.
    * **`SerializeData3`:** This test goes a step further by actually writing the serialized data to disk and then reading it back. It verifies that the persisted data matches the serialized data and that loading from the file restores the correct state.
    * **`DeserializeBadData`:** This tests error handling. It checks that the persister gracefully handles invalid input without crashing or corrupting the state.
    * **`DeserializeDataOldWithoutCreationDate`, `DeserializeDataOldMergedDictionary`:** These tests specifically address handling older data formats. This is common in software with evolving data structures. The key takeaway here is that these *older* formats are *not* supported and should result in no entries being loaded.
    * **`DeserializeLegacyExpectCTData`:**  This test focuses on handling a specific legacy data format involving Expect-CT. It verifies that while the data might be present in the file, the *current* loading logic might ignore or migrate it, as indicated by the comment and the fact that no Expect-CT entries are expected after loading.
    * **`TransportSecurityPersisterCommitTest`:** This is a parameterized test, meaning it runs the same test logic with different input values. The parameter here is a string representing the commit interval for writing to disk. This section tests the asynchronous writing behavior of the persister and how it respects the commit interval. The tests confirm that writes happen after the interval or when explicitly triggered by `WriteNow`.

5. **Look for JavaScript Connections:** While analyzing the tests, consider where this functionality might interact with JavaScript in a browser. HSTS and Expect-CT are security features that affect how a browser communicates with websites. The persister ensures these settings are remembered across browser sessions. JavaScript running in a webpage can trigger network requests, and the browser's underlying network stack (which includes this code) will use the persisted transport security state to enforce these policies.

6. **Identify Potential User/Programming Errors:**  Think about common mistakes when dealing with persistent storage and security settings. For instance, users might manually edit the persistence file (which is discouraged). Developers might misunderstand how the commit interval works or might not handle asynchronous operations correctly.

7. **Trace User Actions:** Consider how a user's actions might lead to this code being executed. Visiting HTTPS websites that set HSTS headers or Expect-CT headers is a primary way. Browser restarts and updates also trigger loading of this persistent data.

8. **Synthesize the Information:** Finally, organize the gathered information into a coherent summary, covering the functionality, JavaScript connections, logical inferences, potential errors, and debugging clues. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This just saves and loads data."
* **Correction:** "It's not just simple saving and loading. It handles different data versions, asynchronous operations, and specific security features like HSTS and Expect-CT."

* **Initial thought:** "JavaScript interacts directly with this C++ code."
* **Correction:** "JavaScript doesn't directly interact. It's the browser's network stack (written in C++) that uses this persisted data when making network requests initiated by JavaScript."

* **Initial thought:** "The commit interval is just a simple timer."
* **Correction:** "The commit interval is managed by `ImportantFileWriter`, which likely has its own optimizations and logic for batching writes."

By following these steps, combining code analysis with an understanding of the broader context of a web browser, you can effectively analyze and explain the functionality of a C++ source file like this one.
这个文件 `net/http/transport_security_persister_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `TransportSecurityPersister` 类的功能。`TransportSecurityPersister` 的主要职责是将 `TransportSecurityState` 中的数据持久化到磁盘，并在启动时从磁盘加载数据。`TransportSecurityState` 存储了关于网站安全策略的信息，例如 HTTP Strict Transport Security (HSTS) 和 Expect-CT。

**功能列表:**

1. **加载持久化的安全策略:** 测试 `LoadEntries()` 方法，该方法从存储的文件中读取安全策略数据并更新 `TransportSecurityState`。
2. **持久化安全策略:** 测试 `SerializeData()` 方法，该方法将 `TransportSecurityState` 的当前状态序列化为字符串，以便可以保存到文件中。同时也测试了 `WriteNow()` 方法，该方法将当前状态立即写入文件。
3. **数据一致性:** 测试序列化和反序列化过程的正确性，确保将数据序列化后再反序列化回 `TransportSecurityState` 后，数据保持不变。
4. **处理错误数据:** 测试 `LoadEntries()` 方法在遇到格式错误或无效数据时的处理能力，确保不会因此崩溃或产生错误状态。
5. **处理旧版本数据:** 测试 `LoadEntries()` 方法处理旧版本持久化数据格式的能力，以及是否能正确忽略或处理这些旧数据。
6. **提交间隔控制:** 测试 `TransportSecurityPersister` 的写入操作是否按照预设的提交间隔进行，以优化性能，避免频繁写入磁盘。
7. **立即写入:** 测试 `WriteNow()` 方法是否能立即将数据写入磁盘，即使在提交间隔尚未到达时。
8. **清除现有状态:** 测试加载新数据时，是否会清除 `TransportSecurityState` 中已有的非静态（动态添加的）条目。

**与 JavaScript 的关系:**

`TransportSecurityPersister` 本身是用 C++ 编写的，与 JavaScript 没有直接的交互。然而，它存储和加载的安全策略信息（如 HSTS）会影响浏览器如何与网站建立连接，而这些连接通常是由 JavaScript 发起的。

**举例说明:**

假设一个网站 `example.com` 通过 HTTPS 响应头设置了 HSTS 策略，指示浏览器在一段时间内始终通过 HTTPS 连接该网站。当用户首次通过 HTTPS 访问 `example.com` 时，Chromium 的网络栈会接收到这个 HSTS 策略，并将其存储在 `TransportSecurityState` 中。`TransportSecurityPersister` 会在后台将这个信息持久化到磁盘。

之后，即使 JavaScript 代码尝试通过 `http://example.com` 发起请求（例如，通过 `fetch` 或 `XMLHttpRequest`），浏览器也会根据持久化的 HSTS 策略，自动将请求升级为 `https://example.com`。这个过程对 JavaScript 代码来说是透明的，但 `TransportSecurityPersister` 确保了即使浏览器重启，这个安全策略仍然有效。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `SerializeData` 和 `LoadEntries`):**

1. 用户通过 HTTPS 访问了 `secure.example.com`，该网站设置了包含子域名的 HSTS 策略，有效期为 30 天。
2. 用户稍后访问了 `expect-ct.example.net`，该网站设置了 Expect-CT 策略。

**输出 (序列化后的数据，简化表示):**

```json
{
  "version": 2,
  "sts": [
    {
      "host": "secure.example.com",
      "mode": "force-https",
      "sts_include_subdomains": true,
      "sts_observed": <timestamp>,
      "expiry": <timestamp + 30 days>
    }
  ],
  "expect_ct": [
    {
      "host": "expect-ct.example.net",
      "expect_ct_observed": <timestamp>,
      "expect_ct_expiry": <timestamp>,
      "expect_ct_enforce": true,
      "expect_ct_report_uri": "..."
    }
  ]
}
```

**假设输入 (针对 `LoadEntriesClearsExistingState`):**

1. `TransportSecurityState` 中已经存在一个动态添加的 HSTS 条目，例如 `legacy.example.org`。
2. `TransportSecurityPersister` 加载了新的持久化数据，其中不包含 `legacy.example.org` 的条目。

**输出:**

加载完成后，`TransportSecurityState` 中 `legacy.example.org` 的 HSTS 条目将被清除。

**用户或编程常见的使用错误:**

1. **手动编辑持久化文件:** 用户可能会尝试手动编辑 `TransportSecurity` 文件，但这可能会导致文件格式错误，导致浏览器无法加载安全策略，或者更糟的情况是，引入安全漏洞。测试中的 `DeserializeBadData` 就验证了浏览器在这种情况下不会崩溃。
2. **误解提交间隔:** 开发者在测试或调试时，可能会期望每次修改 `TransportSecurityState` 后立即写入磁盘。然而，为了性能考虑，默认情况下 `TransportSecurityPersister` 会按照一定的间隔批量写入。开发者可以使用 `WriteNow()` 方法强制立即写入，但过度使用可能会影响性能。`TransportSecurityPersisterCommitTest` 就是为了测试这种间隔机制。
3. **文件权限问题:** 如果运行 Chromium 的用户没有读写持久化文件的权限，`TransportSecurityPersister` 将无法正常工作。这会导致安全策略无法保存和加载，可能会导致用户访问网站时没有应用预期的安全保护。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户首次访问启用了 HSTS 的网站 (例如 `https://mybank.com`)：**
   - 浏览器建立 HTTPS 连接。
   - 服务器响应头中包含 `Strict-Transport-Security`。
   - Chromium 的网络栈解析该头部，并将 `mybank.com` 及其 HSTS 策略添加到 `TransportSecurityState`。
   - `TransportSecurityPersister` 在后台将这个信息写入持久化文件。

2. **用户关闭并重新打开浏览器：**
   - Chromium 启动时，`TransportSecurityPersister` 会读取持久化文件。
   - `LoadEntries()` 方法被调用，将之前保存的 `mybank.com` 的 HSTS 策略加载到 `TransportSecurityState` 中。

3. **用户尝试访问 `http://mybank.com` (可能是用户手动输入或点击了旧的链接):**
   - 在发起网络请求之前，浏览器会检查 `TransportSecurityState`。
   - 找到 `mybank.com` 的 HSTS 策略。
   - 浏览器自动将请求升级为 `https://mybank.com`，阻止了可能的中间人攻击。

4. **开发者想要测试 HSTS 的持久化：**
   - 开发者可能会修改代码，添加或修改 HSTS 条目到 `TransportSecurityState`。
   - 为了确保修改被正确保存，开发者可能会调用 `persister_->WriteNow(state_.get(), run_loop.QuitClosure());` 来强制立即写入。
   - 开发者可能会检查持久化文件的内容，验证 HSTS 条目是否被正确写入。
   - 如果遇到问题，开发者可能会设置断点在 `SerializeData()` 或 `LoadEntries()` 等方法中，查看数据的序列化和反序列化过程，或者检查文件读写的操作是否成功。

总而言之，`transport_security_persister_unittest.cc` 通过各种测试用例，确保 `TransportSecurityPersister` 能够可靠地将关键的安全策略信息持久化和加载，从而保障用户的网络安全。这对于浏览器记住网站的 HTTPS 配置至关重要，即使在浏览器重启后也能有效防止降级攻击。

Prompt: 
```
这是目录为net/http/transport_security_persister_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/transport_security_persister.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_writer.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/task/current_thread.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/http/transport_security_state.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

const char kReportUri[] = "http://www.example.test/report";

class TransportSecurityPersisterTest : public ::testing::Test,
                                       public WithTaskEnvironment {
 public:
  TransportSecurityPersisterTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    // Mock out time so that entries with hard-coded json data can be
    // successfully loaded. Use a large enough value that dynamically created
    // entries have at least somewhat interesting expiration times.
    FastForwardBy(base::Days(3660));
  }

  ~TransportSecurityPersisterTest() override {
    EXPECT_TRUE(base::CurrentIOThread::IsSet());
    base::RunLoop().RunUntilIdle();
  }

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    transport_security_file_path_ =
        temp_dir_.GetPath().AppendASCII("TransportSecurity");
    ASSERT_TRUE(base::CurrentIOThread::IsSet());
    scoped_refptr<base::SequencedTaskRunner> background_runner(
        base::ThreadPool::CreateSequencedTaskRunner(
            {base::MayBlock(), base::TaskPriority::BEST_EFFORT,
             base::TaskShutdownBehavior::BLOCK_SHUTDOWN}));
    state_ = std::make_unique<TransportSecurityState>();
    persister_ = std::make_unique<TransportSecurityPersister>(
        state_.get(), std::move(background_runner),
        transport_security_file_path_);
  }

 protected:
  base::FilePath transport_security_file_path_;
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<TransportSecurityState> state_;
  std::unique_ptr<TransportSecurityPersister> persister_;
};

// Tests that LoadEntries() clears existing non-static entries.
TEST_F(TransportSecurityPersisterTest, LoadEntriesClearsExistingState) {
  TransportSecurityState::STSState sts_state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  static const char kYahooDomain[] = "yahoo.com";

  EXPECT_FALSE(state_->GetDynamicSTSState(kYahooDomain, &sts_state));

  state_->AddHSTS(kYahooDomain, expiry, false /* include subdomains */);
  EXPECT_TRUE(state_->GetDynamicSTSState(kYahooDomain, &sts_state));

  persister_->LoadEntries("{\"version\":2}");

  EXPECT_FALSE(state_->GetDynamicSTSState(kYahooDomain, &sts_state));
}

// Tests that serializing -> deserializing -> reserializing results in the same
// output.
TEST_F(TransportSecurityPersisterTest, SerializeData1) {
  std::optional<std::string> output = persister_->SerializeData();

  ASSERT_TRUE(output);
  persister_->LoadEntries(*output);

  std::optional<std::string> output2 = persister_->SerializeData();
  ASSERT_TRUE(output2);
  EXPECT_EQ(output, output2);
}

TEST_F(TransportSecurityPersisterTest, SerializeData2) {
  TransportSecurityState::STSState sts_state;
  const base::Time current_time(base::Time::Now());
  const base::Time expiry = current_time + base::Seconds(1000);
  static const char kYahooDomain[] = "yahoo.com";

  EXPECT_FALSE(state_->GetDynamicSTSState(kYahooDomain, &sts_state));

  bool include_subdomains = true;
  state_->AddHSTS(kYahooDomain, expiry, include_subdomains);

  std::optional<std::string> output = persister_->SerializeData();
  ASSERT_TRUE(output);
  persister_->LoadEntries(*output);

  EXPECT_TRUE(state_->GetDynamicSTSState(kYahooDomain, &sts_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  EXPECT_TRUE(state_->GetDynamicSTSState("foo.yahoo.com", &sts_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  EXPECT_TRUE(state_->GetDynamicSTSState("foo.bar.yahoo.com", &sts_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
  EXPECT_TRUE(state_->GetDynamicSTSState("foo.bar.baz.yahoo.com", &sts_state));
  EXPECT_EQ(sts_state.upgrade_mode,
            TransportSecurityState::STSState::MODE_FORCE_HTTPS);
}

TEST_F(TransportSecurityPersisterTest, SerializeData3) {
  const GURL report_uri(kReportUri);
  // Add an entry.
  base::Time expiry = base::Time::Now() + base::Seconds(1000);
  bool include_subdomains = false;
  state_->AddHSTS("www.example.com", expiry, include_subdomains);

  // Add another entry.
  expiry = base::Time::Now() + base::Seconds(3000);
  state_->AddHSTS("www.example.net", expiry, include_subdomains);

  // Save a copy of everything.
  std::set<TransportSecurityState::HashedHost> sts_saved;
  TransportSecurityState::STSStateIterator sts_iter(*state_);
  while (sts_iter.HasNext()) {
    sts_saved.insert(sts_iter.hostname());
    sts_iter.Advance();
  }

  std::optional<std::string> serialized = persister_->SerializeData();
  ASSERT_TRUE(serialized);

  // Persist the data to the file.
  base::RunLoop run_loop;
  persister_->WriteNow(state_.get(), run_loop.QuitClosure());
  run_loop.Run();

  // Read the data back.
  std::string persisted;
  EXPECT_TRUE(
      base::ReadFileToString(transport_security_file_path_, &persisted));
  EXPECT_EQ(persisted, serialized);
  persister_->LoadEntries(persisted);

  // Check that states are the same as saved.
  size_t count = 0;
  TransportSecurityState::STSStateIterator sts_iter2(*state_);
  while (sts_iter2.HasNext()) {
    count++;
    sts_iter2.Advance();
  }
  EXPECT_EQ(count, sts_saved.size());
}

// Tests that deserializing bad data shouldn't result in any STS entries being
// added to the transport security state.
TEST_F(TransportSecurityPersisterTest, DeserializeBadData) {
  persister_->LoadEntries("");
  EXPECT_EQ(0u, state_->num_sts_entries());

  persister_->LoadEntries("Foopy");
  EXPECT_EQ(0u, state_->num_sts_entries());

  persister_->LoadEntries("15");
  EXPECT_EQ(0u, state_->num_sts_entries());

  persister_->LoadEntries("[15]");
  EXPECT_EQ(0u, state_->num_sts_entries());

  persister_->LoadEntries("{\"version\":1}");
  EXPECT_EQ(0u, state_->num_sts_entries());
}

TEST_F(TransportSecurityPersisterTest, DeserializeDataOldWithoutCreationDate) {
  // This is an old-style piece of transport state JSON, which has no creation
  // date.
  const std::string kInput =
      "{ "
      "\"G0EywIek2XnIhLrUjaK4TrHBT1+2TcixDVRXwM3/CCo=\": {"
      "\"expiry\": 1266815027.983453, "
      "\"include_subdomains\": false, "
      "\"mode\": \"strict\" "
      "}"
      "}";
  persister_->LoadEntries(kInput);
  EXPECT_EQ(0u, state_->num_sts_entries());
}

TEST_F(TransportSecurityPersisterTest, DeserializeDataOldMergedDictionary) {
  // This is an old-style piece of transport state JSON, which uses a single
  // unversioned host-keyed dictionary of merged ExpectCT and HSTS data.
  const std::string kInput =
      "{"
      "   \"CxLbri+JPdi5pZ8/a/2rjyzq+IYs07WJJ1yxjB4Lpw0=\": {"
      "      \"expect_ct\": {"
      "         \"expect_ct_enforce\": true,"
      "         \"expect_ct_expiry\": 1590512843.283966,"
      "         \"expect_ct_observed\": 1590511843.284064,"
      "         \"expect_ct_report_uri\": \"https://expect_ct.test/report_uri\""
      "      },"
      "      \"expiry\": 0.0,"
      "      \"mode\": \"default\","
      "      \"sts_include_subdomains\": false,"
      "      \"sts_observed\": 0.0"
      "   },"
      "   \"DkgjGShIBmYtgJcJf5lfX3rTr2S6dqyF+O8IAgjuleE=\": {"
      "      \"expiry\": 1590512843.283966,"
      "      \"mode\": \"force-https\","
      "      \"sts_include_subdomains\": false,"
      "      \"sts_observed\": 1590511843.284025"
      "   },"
      "   \"M5lkNV3JBeoPMlKrTOKRYT+mrUsZCS5eoQWsc9/r1MU=\": {"
      "      \"expect_ct\": {"
      "         \"expect_ct_enforce\": true,"
      "         \"expect_ct_expiry\": 1590512843.283966,"
      "         \"expect_ct_observed\": 1590511843.284098,"
      "         \"expect_ct_report_uri\": \"\""
      "      },"
      "      \"expiry\": 1590512843.283966,"
      "      \"mode\": \"force-https\","
      "      \"sts_include_subdomains\": true,"
      "      \"sts_observed\": 1590511843.284091"
      "   }"
      "}";

  persister_->LoadEntries(kInput);
  EXPECT_EQ(0u, state_->num_sts_entries());
}

TEST_F(TransportSecurityPersisterTest, DeserializeLegacyExpectCTData) {
  const std::string kHost = "CxLbri+JPdi5pZ8/a/2rjyzq+IYs07WJJ1yxjB4Lpw0=";
  const std::string kInput =
      R"({"version":2, "sts": [{ "host": ")" + kHost +
      R"(", "mode": "force-https", "sts_include_subdomains": false, )"
      R"("sts_observed": 0.0, "expiry": 4825336765.0}], "expect_ct": [{"host":)"
      R"("CxLbri+JPdi5pZ8/a/2rjyzq+IYs07WJJ1yxjB4Lpw0=", "nak": "test", )"
      R"("expect_ct_observed": 0.0, "expect_ct_expiry": 4825336765.0, )"
      R"("expect_ct_enforce": true, "expect_ct_report_uri": ""}]})";
  LOG(ERROR) << kInput;
  persister_->LoadEntries(kInput);
  FastForwardBy(TransportSecurityPersister::GetCommitInterval() +
                base::Seconds(1));
  EXPECT_EQ(1u, state_->num_sts_entries());
  // Now read the data and check that there are no Expect-CT entries.
  std::string persisted;
  ASSERT_TRUE(
      base::ReadFileToString(transport_security_file_path_, &persisted));
  // Smoke test that the file contains some data as expected...
  ASSERT_NE(std::string::npos, persisted.find(kHost));
  // But it shouldn't contain any Expect-CT data.
  EXPECT_EQ(std::string::npos, persisted.find("expect_ct"));
}

class TransportSecurityPersisterCommitTest
    : public TransportSecurityPersisterTest,
      public ::testing::WithParamInterface<std::string> {
 public:
  TransportSecurityPersisterCommitTest() {
    if (GetParam().empty()) {
      feature_list_.InitAndDisableFeature(kTransportSecurityFileWriterSchedule);
    } else {
      feature_list_.InitAndEnableFeatureWithParameters(
          kTransportSecurityFileWriterSchedule,
          {{"commit_interval", GetParam()}});
    }
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    All,
    TransportSecurityPersisterCommitTest,
    ::testing::Values(
        // The ImportantFileWriter default.
        "10s",
        // Anything less should use the default.
        "9s",
        "0",
        "-10s",
        "-inf",
        // Valid values.
        "1m",
        "10m",
        // Anything greater should use the max.
        "11m",
        "+inf",
        // Disable the feature. Should use the default interval.
        ""));

TEST_P(TransportSecurityPersisterCommitTest, CommitIntervalIsValid) {
  EXPECT_GE(TransportSecurityPersister::GetCommitInterval(), base::Seconds(10));
  EXPECT_LE(TransportSecurityPersister::GetCommitInterval(), base::Minutes(10));
}

TEST_P(TransportSecurityPersisterCommitTest, WriteAtCommitInterval) {
  const auto kLongExpiry = base::Time::Now() + base::Days(10);
  const bool kIncludeSubdomains = false;

  // Make sure the file starts empty.
  ASSERT_TRUE(base::WriteFile(transport_security_file_path_, ""));

  // Add an entry. Expect the persister NOT to write before the commit interval,
  // for performance.
  state_->AddHSTS("www.example.com", kLongExpiry, kIncludeSubdomains);
  FastForwardBy(TransportSecurityPersister::GetCommitInterval() / 2);
  std::string persisted;
  EXPECT_TRUE(
      base::ReadFileToString(transport_security_file_path_, &persisted));
  EXPECT_TRUE(persisted.empty());

  // Add another entry. After the commit interval passes, both should be
  // written.
  state_->AddHSTS("www.example.net", kLongExpiry, kIncludeSubdomains);
  FastForwardBy(TransportSecurityPersister::GetCommitInterval() / 2);
  EXPECT_TRUE(
      base::ReadFileToString(transport_security_file_path_, &persisted));
  EXPECT_FALSE(persisted.empty());

  // Ensure that state comes from the persisted file.
  persister_->LoadEntries("");
  TransportSecurityState::STSState dummy_state;
  ASSERT_FALSE(state_->GetDynamicSTSState("www.example.com", &dummy_state));
  ASSERT_FALSE(state_->GetDynamicSTSState("www.example.net", &dummy_state));

  // Check that both entries were persisted.
  persister_->LoadEntries(persisted);
  EXPECT_TRUE(state_->GetDynamicSTSState("www.example.com", &dummy_state));
  EXPECT_TRUE(state_->GetDynamicSTSState("www.example.net", &dummy_state));

  // Add a third entry and force a write before the commit interval
  state_->AddHSTS("www.example.org", kLongExpiry, kIncludeSubdomains);

  const auto time_before_write = base::TimeTicks::Now();
  base::RunLoop run_loop;
  persister_->WriteNow(state_.get(), run_loop.QuitClosure());
  run_loop.Run();
  EXPECT_LT(base::TimeTicks::Now() - time_before_write,
            TransportSecurityPersister::GetCommitInterval());
  EXPECT_TRUE(
      base::ReadFileToString(transport_security_file_path_, &persisted));
  EXPECT_FALSE(persisted.empty());

  // Ensure that state comes from the persisted file.
  persister_->LoadEntries("");
  ASSERT_FALSE(state_->GetDynamicSTSState("www.example.com", &dummy_state));
  ASSERT_FALSE(state_->GetDynamicSTSState("www.example.net", &dummy_state));
  ASSERT_FALSE(state_->GetDynamicSTSState("www.example.org", &dummy_state));

  // Check that all entries were persisted.
  persister_->LoadEntries(persisted);
  EXPECT_TRUE(state_->GetDynamicSTSState("www.example.com", &dummy_state));
  EXPECT_TRUE(state_->GetDynamicSTSState("www.example.net", &dummy_state));
  EXPECT_TRUE(state_->GetDynamicSTSState("www.example.org", &dummy_state));
}

}  // namespace

}  // namespace net

"""

```