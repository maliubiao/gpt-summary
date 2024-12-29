Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ source code file (`nsswitch_reader_unittest.cc`) and explain its functionality. This involves identifying the purpose of the tests, how they work, and any relevant connections to JavaScript (though likely minimal). Crucially, the request also asks for examples of logical inference, common user errors, and debugging context.

**2. Initial Code Scan and Class Identification:**

The first step is to quickly scan the code and identify the key components. We can see:

* **Includes:** Standard C++ headers (`string`, `utility`, `vector`), Google Test (`gmock.h`, `gtest.h`), and a Chromium-specific header (`base/functional/bind.h`, `net/dns/nsswitch_reader.h`). This immediately suggests this is a unit test for the `NsswitchReader` class.
* **Namespaces:**  `net` and an anonymous namespace. This is typical Chromium style.
* **Classes:** `TestFileReader` and `NsswitchReaderTest`. The `Test` suffix strongly indicates `NsswitchReaderTest` is the test fixture. `TestFileReader` looks like a helper class for simulating file reading.
* **Test Macros:** `TEST_F`. This confirms the use of Google Test and that each `TEST_F` defines an individual test case within the `NsswitchReaderTest` fixture.

**3. Analyzing `TestFileReader`:**

This class is straightforward. It takes a string as input and provides a `GetFileReadCall` method which returns a `base::RepeatingCallback`. This callback, when invoked, returns the stored string. The `already_read_` flag ensures the "file" can only be read once per `TestFileReader` instance, mimicking actual file reading behavior.

**4. Analyzing `NsswitchReaderTest`:**

This class inherits from `testing::Test`, the foundation of Google Test fixtures. It contains a protected member `NsswitchReader reader_`, which is the class being tested.

**5. Analyzing Individual Test Cases (`TEST_F` blocks):**

This is the core of understanding the file's functionality. For each test case:

* **Identify the test name:** This usually gives a good hint about what's being tested (e.g., `ActualReadAndParseHosts`, `FileReadErrorResultsInDefault`).
* **Understand the setup:**  Often, a `TestFileReader` is instantiated with specific content, and `reader_.set_file_read_call_for_testing()` is used to inject this mock file reader into the `NsswitchReader`. This is a common pattern for isolating the unit being tested from external dependencies like the actual file system.
* **Understand the action:** The `reader_.ReadAndParseHosts()` method is called. This is the method under test.
* **Understand the assertions:**  `EXPECT_THAT` is used with Google Mock matchers (e.g., `testing::SizeIs`, `testing::ElementsAre`). These assertions verify the expected behavior of `ReadAndParseHosts()` given the specific input provided by the `TestFileReader`. Pay close attention to what the matchers are checking.

**6. Inferring `NsswitchReader` Functionality:**

By looking at the test cases and the assertions, we can infer the core functionality of `NsswitchReader::ReadAndParseHosts()`:

* **Reading `/etc/nsswitch.conf` (or a simulated file):**  The tests manipulate the content read from the file.
* **Parsing the file:** The tests cover various scenarios of valid and invalid file content, including different services, actions, statuses, whitespace, comments, and capitalization.
* **Extracting service specifications:** The output is a `std::vector<NsswitchReader::ServiceSpecification>`, indicating that the parser extracts information about which services should be used for host name resolution.
* **Handling errors and defaults:**  Tests check how the reader behaves when the file is empty or missing the "hosts:" entry.

**7. Addressing the Specific Requirements of the Prompt:**

* **Functionality Listing:** Summarize the inferred functionalities of the `NsswitchReader` based on the tests.
* **JavaScript Relationship:**  Actively consider the connection. While this C++ code directly doesn't interact with JavaScript, it's part of the Chromium network stack, which *does* impact how web browsers (which run JavaScript) resolve hostnames. Explain this indirect relationship.
* **Logical Inference (Input/Output):**  Select a few representative test cases and clearly state the simulated input (the `kFile` content) and the expected output (the `EXPECT_THAT` assertion). This demonstrates how different inputs lead to different parsing results.
* **Common User Errors:**  Think about how a user (or a system administrator configuring the nsswitch.conf file) could make mistakes that would be caught by these tests. Focus on syntax errors, typos, and incorrect configurations.
* **Debugging Context:** Explain how a developer might end up investigating this code. Focus on scenarios where hostname resolution is failing or behaving unexpectedly, leading them to examine the nsswitch configuration and the code that parses it.

**8. Refining the Explanation:**

After the initial analysis, review and refine the explanation for clarity, accuracy, and completeness. Use clear and concise language. Ensure that the examples are easy to understand.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file directly interacts with a JavaScript API.
* **Correction:**  After reviewing the includes and the nature of the tests, it's clear this is a low-level C++ component. The JavaScript connection is indirect, through the browser's network stack.
* **Initial thought:** Focus on the specific syntax of nsswitch.conf.
* **Refinement:** While syntax is important, also emphasize the *purpose* of `nsswitch.conf` and how `NsswitchReader` helps the browser understand it. Connect it to the bigger picture of hostname resolution.
* **Initial thought:**  Just list the test names as functionalities.
* **Refinement:**  Group related tests and describe the underlying functionality they are verifying (e.g., parsing services, parsing actions, handling errors).

By following this structured approach, which combines code analysis, understanding testing methodologies, and addressing the specific prompt requirements, we can generate a comprehensive and informative explanation of the `nsswitch_reader_unittest.cc` file.
这个文件 `net/dns/nsswitch_reader_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/dns/nsswitch_reader.h` 中定义的 `NsswitchReader` 类的功能。 `NsswitchReader` 类的主要作用是读取和解析系统上的 `nsswitch.conf` 文件。该文件用于配置主机名解析的行为，例如，指定哪些服务（如 `files`, `dns`, `mdns`）应该被用来查找主机名。

以下是 `nsswitch_reader_unittest.cc` 的功能列表：

1. **测试实际的 `nsswitch.conf` 文件读取和解析:**  `ActualReadAndParseHosts` 测试用例尝试读取运行测试的机器上的实际 `nsswitch.conf` 文件，并对其解析结果进行基本合理性检查，例如服务数量和每个服务的动作数量不会超过某个上限。

2. **测试文件读取错误处理:** `FileReadErrorResultsInDefault` 测试用例模拟文件读取失败的情况，验证 `NsswitchReader` 是否会回退到默认配置（通常是使用 `files` 和 `dns` 服务）。

3. **测试缺少 `hosts` 配置项的处理:** `MissingHostsResultsInDefault` 测试用例提供一个不包含 `hosts:` 配置行的文件内容，验证 `NsswitchReader` 在缺少关键配置时是否会使用默认配置。

4. **测试解析所有已知的服务类型:** `ParsesAllKnownServices` 测试用例提供包含所有已知服务名称的配置，验证 `NsswitchReader` 是否能正确解析这些服务。

5. **测试解析重复的服务类型:** `ParsesRepeatedServices` 测试用例验证 `NsswitchReader` 是否能处理并记录重复出现的服务名称。

6. **测试解析所有已知的动作:** `ParsesAllKnownActions` 测试用例验证 `NsswitchReader` 是否能正确解析与服务关联的不同动作，例如 `[UNAVAIL=RETURN]`, `[UNAVAIL=CONTINUE]`, `[UNAVAIL=MERGE]`。

7. **测试解析所有已知的状态:** `ParsesAllKnownStatuses` 测试用例验证 `NsswitchReader` 是否能正确解析动作关联的不同状态，例如 `SUCCESS`, `NOTFOUND`, `UNAVAIL`, `TRYAGAIN`。

8. **测试解析重复的动作:** `ParsesRepeatedActions` 测试用例验证 `NsswitchReader` 是否能处理并记录重复出现的动作。

9. **测试解析组合的动作列表:** `ParsesCombinedActionLists` 测试用例验证 `NsswitchReader` 是否能正确解析在同一对方括号内组合的多个动作。

10. **测试处理异常的空白字符:** `HandlesAtypicalWhitespace` 和 `HandlesAtypicalWhitespaceInActions` 测试用例验证 `NsswitchReader` 在解析配置时是否能正确处理不同类型的空白字符（空格、制表符、换行符）。

11. **测试解析没有服务的动作:** `ParsesActionsWithoutService` 测试用例验证 `NsswitchReader` 是否能处理只包含动作而没有明确服务的情况。

12. **测试解析否定动作:** `ParsesNegatedActions` 测试用例验证 `NsswitchReader` 是否能正确解析带有否定前缀 `!` 的动作。

13. **测试将无法识别的服务解析为未知:** `ParsesUnrecognizedServiceAsUnknown` 测试用例验证 `NsswitchReader` 对于未知的服务名称是否会将其标记为未知类型。

14. **测试将无法识别的状态解析为未知:** `ParsesUnrecognizedStatusAsUnknown` 测试用例验证 `NsswitchReader` 对于未知的状态是否会将其标记为未知类型。

15. **测试将无法识别的动作解析为未知:** `ParsesUnrecognizedActionAsUnknown` 测试用例验证 `NsswitchReader` 对于未知的动作是否会将其标记为未知类型。

16. **测试将无效的动作解析为未知:** `ParsesInvalidActionsAsUnknown` 测试用例验证 `NsswitchReader` 对于格式不正确的动作是否会将其标记为未知类型。

17. **测试忽略未正确关闭的动作:** `IgnoresInvalidlyClosedActions` 测试用例验证 `NsswitchReader` 是否能处理并忽略未正确关闭的动作。

18. **测试将未正确关闭的动作后的服务解析为未知:** `ParsesServicesAfterInvalidlyClosedActionsAsUnknown` 测试用例验证在遇到未正确关闭的动作后，后续的服务是否会被正确处理或标记为未知。

19. **测试忽略注释:** `IgnoresComments` 和 `IgnoresEndOfLineComments` 测试用例验证 `NsswitchReader` 是否能正确忽略以 `#` 开头的整行注释以及行尾的注释。

20. **测试忽略大小写:** `IgnoresCapitalization` 测试用例验证 `NsswitchReader` 在解析服务、状态和动作时是否忽略大小写。

21. **测试忽略空动作:** `IgnoresEmptyActions` 测试用例验证 `NsswitchReader` 是否能处理并忽略空的动作定义 `[]`。

22. **测试忽略重复的动作括号:** `IgnoresRepeatedActionBrackets` 和 `IgnoresRepeatedActionBracketsWithWhitespace` 测试用例验证 `NsswitchReader` 是否能处理重复出现的动作括号。

23. **测试拒绝不合逻辑的动作括号:** `RejectsNonSensicalActionBrackets` 测试用例验证 `NsswitchReader` 是否能处理不合逻辑的括号使用。

24. **测试拒绝带有括号的服务名:** `RejectsServicesWithBrackets` 测试用例验证 `NsswitchReader` 是否能处理服务名称中包含括号的情况。

25. **测试拒绝嵌套的动作括号:** `RejectsNestedActionBrackets` 测试用例验证 `NsswitchReader` 是否能处理嵌套的动作括号。

26. **测试忽略带有重复括号的空动作:** `IgnoresEmptyActionWithRepeatedBrackets` 测试用例验证 `NsswitchReader` 是否能处理带有重复括号的空动作。

27. **测试忽略字符串末尾的空动作:** `IgnoresEmptyActionAtEndOfString` 测试用例验证 `NsswitchReader` 是否能处理位于字符串末尾的未完成的动作定义。

**与 JavaScript 的关系：**

`nsswitch_reader.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有代码级别的交互。然而，它所实现的功能对运行在 Chromium 浏览器中的 JavaScript 代码有间接的影响。

* **主机名解析:**  当 JavaScript 代码尝试进行网络请求（例如，使用 `fetch()` 或 `XMLHttpRequest`）时，浏览器需要将主机名解析为 IP 地址。 `nsswitch.conf` 配置了系统进行主机名解析的方式。`NsswitchReader` 负责读取和解析这个配置文件，从而影响浏览器如何查找与给定主机名关联的 IP 地址。

**举例说明：**

假设 `nsswitch.conf` 文件配置为首先使用本地文件 (`files`)，然后使用 DNS (`dns`) 进行主机名解析：

```
hosts: files dns
```

当 JavaScript 代码尝试访问 `www.example.com` 时，Chromium 的网络栈会使用 `NsswitchReader` 解析的配置。浏览器首先会查找本地的 hosts 文件。如果找不到对应的条目，则会使用 DNS 服务器进行查询。

如果 `nsswitch.conf` 配置为：

```
hosts: mdns dns
```

则浏览器会首先尝试使用 Multicast DNS (mDNS) 协议在本地网络中查找主机，然后再尝试使用传统的 DNS 查询。

**逻辑推理 (假设输入与输出):**

假设输入以下 `nsswitch.conf` 内容：

```
hosts: files [NOTFOUND=return] dns
```

**假设输入:**  上述字符串作为 `TestFileReader` 的输入。

**逻辑推理:** `NsswitchReader` 会解析 `hosts` 配置项。它会识别出 `files` 服务，并且会解析与 `files` 关联的动作 `[NOTFOUND=return]`。这意味着如果使用 `files` 服务查找主机名失败（状态为 `NOTFOUND`），则应该立即返回结果，不再尝试后续的服务。然后，它会识别出 `dns` 服务。

**预期输出:**  `ReadAndParseHosts()` 方法应该返回一个包含两个 `ServiceSpecification` 对象的向量。第一个对象代表 `files` 服务，并且其 `actions` 列表包含一个条目，表示当状态为 `NOTFOUND` 时，动作是 `RETURN`。第二个对象代表 `dns` 服务，没有显式的关联动作。

**常见的使用错误：**

1. **语法错误:** 用户在编辑 `nsswitch.conf` 文件时可能犯语法错误，例如拼写错误的服务名、状态或动作，或者括号不匹配。例如：

   ```
   hosts: filess dns  # 服务名拼写错误
   hosts: files [UNAVAL=return] # 状态名拼写错误
   hosts: files [NOTFOUND= # 括号不匹配
   ```

   `nsswitch_reader_unittest.cc` 中的测试用例，如 `ParsesUnrecognizedServiceAsUnknown`, `ParsesUnrecognizedStatusAsUnknown`, `IgnoresInvalidlyClosedActions` 等，就是为了确保 `NsswitchReader` 能妥善处理这些错误，不会崩溃，并且能提供合理的默认行为或将错误标记出来。

2. **配置错误:**  用户可能配置了不合理的解析顺序，导致主机名解析失败或效率低下。例如，如果将一个不可靠或缓慢的服务放在解析列表的前面。虽然 `NsswitchReader` 不会直接阻止这种配置，但其解析结果会影响到网络请求的行为。

**用户操作到达此处的调试线索：**

通常，用户不会直接与 `nsswitch_reader.cc` 这个文件交互。这个文件是开发者进行单元测试用的。以下是一些可能导致开发者需要查看或调试 `NsswitchReader` 相关代码的场景：

1. **主机名解析问题:** 用户报告浏览器无法解析某些主机名。开发者可能会怀疑是 `nsswitch.conf` 的配置问题，或者 `NsswitchReader` 解析该文件时出现了错误。

2. **网络请求行为异常:**  网络请求的行为与预期不符，例如连接超时、使用了错误的 DNS 服务器等。开发者可能会检查 Chromium 如何读取和应用 `nsswitch.conf` 的配置。

3. **新功能开发或修改:**  当 Chromium 的网络栈需要支持新的主机名解析方式或需要修改现有解析逻辑时，开发者可能会需要修改 `NsswitchReader` 或其相关的测试代码。

**调试步骤 (假设用户遇到主机名解析问题):**

1. **用户报告问题:** 用户反馈无法访问特定的网站。

2. **初步排查:** 开发者首先会检查用户的网络连接是否正常，DNS 服务器配置是否正确。

3. **怀疑 `nsswitch.conf`:** 如果初步排查没有发现问题，开发者可能会怀疑系统的主机名解析配置 (`nsswitch.conf`) 是否有问题。

4. **查看 `NsswitchReader` 代码:** 开发者可能会查看 `net/dns/nsswitch_reader.cc` 和 `net/dns/nsswitch_reader.h` 的代码，了解 `NsswitchReader` 如何读取和解析 `nsswitch.conf` 文件。

5. **运行单元测试:** 开发者可能会运行 `nsswitch_reader_unittest.cc` 中的单元测试，确保 `NsswitchReader` 的解析逻辑是正确的。如果发现某个测试用例失败，则表明 `NsswitchReader` 在处理某种特定的 `nsswitch.conf` 配置时存在 bug。

6. **模拟用户配置:** 开发者可能会尝试在测试环境中模拟用户的 `nsswitch.conf` 配置，然后运行相关的网络请求代码，观察是否会出现同样的问题。

7. **添加日志或断点:** 如果问题难以定位，开发者可能会在 `NsswitchReader` 的代码中添加日志输出或设置断点，以便在程序运行时观察 `nsswitch.conf` 的解析过程，找出错误的原因。

总而言之，`nsswitch_reader_unittest.cc` 是保证 `NsswitchReader` 类正确性的关键部分，它通过大量的测试用例覆盖了各种可能的 `nsswitch.conf` 配置及其中的语法细节，确保 Chromium 能够可靠地进行主机名解析。虽然普通用户不会直接接触到这个文件，但其背后的功能对用户的网络体验至关重要。

Prompt: 
```
这是目录为net/dns/nsswitch_reader_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/nsswitch_reader.h"

#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/bind.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

class TestFileReader {
 public:
  explicit TestFileReader(std::string text) : text_(std::move(text)) {}
  TestFileReader(const TestFileReader&) = delete;
  TestFileReader& operator=(const TestFileReader&) = delete;

  NsswitchReader::FileReadCall GetFileReadCall() {
    return base::BindRepeating(&TestFileReader::ReadFile,
                               base::Unretained(this));
  }

  std::string ReadFile() {
    CHECK(!already_read_);

    already_read_ = true;
    return text_;
  }

 private:
  std::string text_;
  bool already_read_ = false;
};

class NsswitchReaderTest : public testing::Test {
 public:
  NsswitchReaderTest() = default;
  NsswitchReaderTest(const NsswitchReaderTest&) = delete;
  NsswitchReaderTest& operator=(const NsswitchReaderTest&) = delete;

 protected:
  NsswitchReader reader_;
};

// Attempt to load the actual nsswitch.conf for the test machine and run
// rationality checks for the result.
TEST_F(NsswitchReaderTest, ActualReadAndParseHosts) {
  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  // Assume nobody will ever run this on a machine with more than 1000
  // configured services.
  EXPECT_THAT(services, testing::SizeIs(testing::Le(1000u)));

  // Assume no service will ever have more than 10 configured actions per
  // service.
  for (const NsswitchReader::ServiceSpecification& service : services) {
    EXPECT_THAT(service.actions, testing::SizeIs(testing::Le(10u)));
  }
}

TEST_F(NsswitchReaderTest, FileReadErrorResultsInDefault) {
  TestFileReader file_reader("");
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  // Expect "files dns".
  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)));
}

TEST_F(NsswitchReaderTest, MissingHostsResultsInDefault) {
  const std::string kFile =
      "passwd: files ldap\nshadow: files\ngroup: files ldap\n";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  // Expect "files dns".
  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)));
}

TEST_F(NsswitchReaderTest, ParsesAllKnownServices) {
  const std::string kFile =
      "hosts: files dns mdns mdns4 mdns6 mdns_minimal mdns4_minimal "
      "mdns6_minimal myhostname resolve nis";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns4),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns6),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdnsMinimal),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdns4Minimal),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdns6Minimal),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMyHostname),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kResolve),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kNis)));
}

TEST_F(NsswitchReaderTest, ParsesRepeatedServices) {
  const std::string kFile = "hosts: mdns4 mdns6 mdns6 myhostname";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns4),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns6),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns6),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMyHostname)));
}

TEST_F(NsswitchReaderTest, ParsesAllKnownActions) {
  const std::string kFile =
      "hosts: files [UNAVAIL=RETURN] [UNAVAIL=CONTINUE] [UNAVAIL=MERGE]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kFiles,
                  {{/*negated=*/false, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kContinue},
                   {/*negated=*/false, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kMerge}})));
}

TEST_F(NsswitchReaderTest, ParsesAllKnownStatuses) {
  const std::string kFile =
      "hosts: dns [SUCCESS=RETURN] [NOTFOUND=RETURN] [UNAVAIL=RETURN] "
      "[TRYAGAIN=RETURN]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kDns,
                  {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kNotFound,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kTryAgain,
                    NsswitchReader::Action::kReturn}})));
}

TEST_F(NsswitchReaderTest, ParsesRepeatedActions) {
  const std::string kFile =
      "hosts: nis [!SUCCESS=RETURN] [NOTFOUND=RETURN] [NOTFOUND=RETURN] "
      "[!UNAVAIL=RETURN]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kNis,
                  {{/*negated=*/true, NsswitchReader::Status::kSuccess,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kNotFound,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kNotFound,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/true, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kReturn}})));
}

TEST_F(NsswitchReaderTest, ParsesCombinedActionLists) {
  const std::string kFile =
      "hosts: dns [SUCCESS=RETURN !NOTFOUND=RETURN UNAVAIL=RETURN] files";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kDns,
                      {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                        NsswitchReader::Action::kReturn},
                       {/*negated=*/true, NsswitchReader::Status::kNotFound,
                        NsswitchReader::Action::kReturn},
                       {/*negated=*/false, NsswitchReader::Status::kUnavailable,
                        NsswitchReader::Action::kReturn}}),
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kFiles)));
}

TEST_F(NsswitchReaderTest, HandlesAtypicalWhitespace) {
  const std::string kFile =
      " database:  service   \n\n   hosts: files\tdns   mdns4 \t mdns6    \t  "
      "\t\n\t\n";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kMdns4),
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdns6)));
}

TEST_F(NsswitchReaderTest, HandlesAtypicalWhitespaceInActions) {
  const std::string kFile =
      "hosts: dns [ !UNAVAIL=MERGE \t NOTFOUND=RETURN\t][ UNAVAIL=CONTINUE]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kDns,
                  {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kMerge},
                   {/*negated=*/false, NsswitchReader::Status::kNotFound,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kContinue}})));
}

TEST_F(NsswitchReaderTest, ParsesActionsWithoutService) {
  const std::string kFile = "hosts: [SUCCESS=RETURN]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kUnknown,
                  {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                    NsswitchReader::Action::kReturn}})));
}

TEST_F(NsswitchReaderTest, ParsesNegatedActions) {
  const std::string kFile =
      "hosts: mdns_minimal [!UNAVAIL=RETURN] [NOTFOUND=CONTINUE] "
      "[!TRYAGAIN=CONTINUE]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMdnsMinimal,
                  {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kReturn},
                   {/*negated=*/false, NsswitchReader::Status::kNotFound,
                    NsswitchReader::Action::kContinue},
                   {/*negated=*/true, NsswitchReader::Status::kTryAgain,
                    NsswitchReader::Action::kContinue}})));
}

TEST_F(NsswitchReaderTest, ParsesUnrecognizedServiceAsUnknown) {
  const std::string kFile =
      "passwd: files\nhosts: files super_awesome_service myhostname";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kFiles),
                                   NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kUnknown),
                                   NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kMyHostname)));
}

TEST_F(NsswitchReaderTest, ParsesUnrecognizedStatusAsUnknown) {
  const std::string kFile =
      "hosts: nis [HELLO=CONTINUE]\nshadow: service\ndatabase: cheese";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kNis,
                  {{/*negated=*/false, NsswitchReader::Status::kUnknown,
                    NsswitchReader::Action::kContinue}})));
}

TEST_F(NsswitchReaderTest, ParsesUnrecognizedActionAsUnknown) {
  const std::string kFile =
      "more: service\nhosts: mdns6 [!UNAVAIL=HI]\nshadow: service";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMdns6,
                  {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kUnknown}})));
}

TEST_F(NsswitchReaderTest, ParsesInvalidActionsAsUnknown) {
  const std::string kFile = "hosts: mdns_minimal [a=b=c] nis";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdnsMinimal,
              {{/*negated=*/false, NsswitchReader::Status::kUnknown,
                NsswitchReader::Action::kUnknown}}),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kNis)));
}

TEST_F(NsswitchReaderTest, IgnoresInvalidlyClosedActions) {
  const std::string kFile = "hosts: myhostname [SUCCESS=MERGE";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMyHostname,
                  {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                    NsswitchReader::Action::kMerge}})));
}

TEST_F(NsswitchReaderTest, ParsesServicesAfterInvalidlyClosedActionsAsUnknown) {
  const std::string kFile = "hosts: resolve [SUCCESS=CONTINUE dns";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kResolve,
                  {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                    NsswitchReader::Action::kContinue},
                   {/*negated=*/false, NsswitchReader::Status::kUnknown,
                    NsswitchReader::Action::kUnknown}})));
}

TEST_F(NsswitchReaderTest, IgnoresComments) {
  const std::string kFile =
      "#hosts: files super_awesome_service myhostname\nnetmask: service";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  // Expect "files dns" due to not finding an uncommented "hosts:" row.
  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kFiles),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)));
}

TEST_F(NsswitchReaderTest, IgnoresEndOfLineComments) {
  const std::string kFile =
      "hosts: files super_awesome_service myhostname # dns";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kFiles),
                                   NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kUnknown),
                                   NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kMyHostname)));
}

TEST_F(NsswitchReaderTest, IgnoresCapitalization) {
  const std::string kFile = "HoStS: mDNS6 [!uNaVaIl=MeRgE]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMdns6,
                  {{/*negated=*/true, NsswitchReader::Status::kUnavailable,
                    NsswitchReader::Action::kMerge}})));
}

TEST_F(NsswitchReaderTest, IgnoresEmptyActions) {
  const std::string kFile = "hosts: mdns_minimal [ \t ][] [ ]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMdnsMinimal)));
}

TEST_F(NsswitchReaderTest, IgnoresRepeatedActionBrackets) {
  const std::string kFile = "hosts: mdns [[SUCCESS=RETURN]]]dns";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(
      services,
      testing::ElementsAre(
          NsswitchReader::ServiceSpecification(
              NsswitchReader::Service::kMdns,
              {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                NsswitchReader::Action::kReturn}}),
          NsswitchReader::ServiceSpecification(NsswitchReader::Service::kDns)));
}

TEST_F(NsswitchReaderTest, IgnoresRepeatedActionBracketsWithWhitespace) {
  const std::string kFile = "hosts: mdns [ [ SUCCESS=RETURN ]\t] ]\t  mdns6";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kMdns,
                      {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                        NsswitchReader::Action::kReturn}}),
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kMdns6)));
}

TEST_F(NsswitchReaderTest, RejectsNonSensicalActionBrackets) {
  const std::string kFile = "hosts: mdns4 [UNAVAIL[=MERGE]]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kMdns4,
                  {{/*negated=*/false, NsswitchReader::Status::kUnknown,
                    NsswitchReader::Action::kMerge}})));
}

TEST_F(NsswitchReaderTest, RejectsServicesWithBrackets) {
  const std::string kFile = "hosts: se]r[vice[name";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kUnknown)));
}

// Other than the case of repeating opening brackets, nested brackets are not
// valid and should just get treated as part of an action label.
TEST_F(NsswitchReaderTest, RejectsNestedActionBrackets) {
  const std::string kFile =
      "hosts: nis [SUCCESS=RETURN [NOTFOUND=CONTINUE] UNAVAIL=MERGE]";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kNis,
                      {{/*negated=*/false, NsswitchReader::Status::kSuccess,
                        NsswitchReader::Action::kReturn},
                       {/*negated=*/false, NsswitchReader::Status::kUnknown,
                        NsswitchReader::Action::kContinue}}),
                  NsswitchReader::ServiceSpecification(
                      NsswitchReader::Service::kUnknown)));
}

TEST_F(NsswitchReaderTest, IgnoresEmptyActionWithRepeatedBrackets) {
  const std::string kFile = "hosts: files [[[]]]] mdns";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kFiles),
                                   NsswitchReader::ServiceSpecification(
                                       NsswitchReader::Service::kMdns)));
}

TEST_F(NsswitchReaderTest, IgnoresEmptyActionAtEndOfString) {
  const std::string kFile = "hosts: dns [[";
  TestFileReader file_reader(kFile);
  reader_.set_file_read_call_for_testing(file_reader.GetFileReadCall());

  std::vector<NsswitchReader::ServiceSpecification> services =
      reader_.ReadAndParseHosts();

  EXPECT_THAT(services,
              testing::ElementsAre(NsswitchReader::ServiceSpecification(
                  NsswitchReader::Service::kDns)));
}

}  // namespace
}  // namespace net

"""

```