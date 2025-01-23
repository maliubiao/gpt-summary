Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the C++ file `websocket_deflate_parameters_test.cc`, its relation to JavaScript (if any), logical reasoning with inputs/outputs, common usage errors, and debugging context.

**2. High-Level Overview of the File:**

The file name strongly suggests it's a test suite for a class or functionality related to WebSocket deflate parameters. The `.cc` extension confirms it's a C++ source file. The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately tells us this file uses the Google Test framework. This means the core structure will involve `TEST()` and potentially `TEST_P()` macros.

**3. Deconstructing the Code - Section by Section:**

* **Includes:**  The included headers (`websocket_deflate_parameters.h`, standard library headers like `<string>`, `<vector>`, and `websocket_extension_parser.h`) give clues about the dependencies and the domain. We can infer that there's a `WebSocketDeflateParameters` class and a parser for WebSocket extensions.

* **Namespaces:** The `net` namespace indicates this code is part of the networking stack. The anonymous namespace `namespace { ... }` is common in C++ for creating internal helpers and test fixtures that don't pollute the global namespace.

* **Helper Function `CheckExtension`:** This function is clearly used to assert the properties of a `WebSocketExtension` generated from a `WebSocketDeflateParameters` object. It checks the name ("permessage-deflate") and the presence and values of a single parameter. This hints at the structure of the `WebSocketDeflateParameters` class and its interaction with `WebSocketExtension`.

* **Individual `TEST` Cases:** These are the core of the tests. Each `TEST()` function focuses on testing a specific aspect of `WebSocketDeflateParameters`:
    * `Empty`: Tests the default constructor and initial state.
    * `ServerContextTakeover`, `ClientContextTakeover`: Test setting specific flags and verifying the resulting extension.
    * `ServerMaxWindowBits`: Tests setting a numeric parameter.
    * `ClientMaxWindowBitsWithoutValue`, `ClientMaxWindowBitsWithValue`: Test different ways of setting the `client_max_window_bits` parameter and how it affects validity as a response.

* **Parameterized Tests (`TEST_P`):**  The `WebSocketDeflateParametersInitializeTest` and `WebSocketDeflateParametersCompatibilityTest` use parameterized testing. This is a powerful technique to run the same test logic with different sets of input data.
    * `InitializeTestParameter` and `CompatibilityTestParameter` structs define the input data structures for these tests.
    * `PrintTo` overloads allow for better logging of test parameters.
    * The `Initialize` test checks the parsing and initialization of `WebSocketDeflateParameters` from a string representation.
    * The `CheckCompatiblity` test checks if a request's deflate parameters are compatible with a response's parameters.

* **Helper Functions for Parameterized Tests:** `Duplicate` and `Invalid` help create the expected failure messages for the initialization tests.

* **Data for Parameterized Tests:** `InitializeTestParameters()` and `kCompatibilityTestParameters` provide the actual input data for the parameterized tests, covering various valid and invalid scenarios.

* **Instantiation of Parameterized Tests:** `INSTANTIATE_TEST_SUITE_P` connects the test classes with the data providers.

**4. Identifying Key Functionality and Concepts:**

From the test cases, we can deduce the following functionality of `WebSocketDeflateParameters`:

* **Managing deflate parameters:**  Specifically, server/client context takeover and maximum window bits.
* **Representing parameters as a WebSocket extension:**  The `AsExtension()` method.
* **Parsing and initialization from a WebSocket extension:** The `Initialize()` method.
* **Validation:** `IsValidAsRequest()` and `IsValidAsResponse()`.
* **Compatibility checking:** `IsCompatibleWith()`.

**5. Analyzing the Relationship with JavaScript:**

WebSockets are a client-server protocol. JavaScript is commonly used in the browser (client-side) to establish and manage WebSocket connections. The deflate parameters negotiated here *directly impact* how the WebSocket messages are compressed and decompressed in the browser.

**6. Constructing Logical Reasoning Examples:**

For the `Initialize` test, we can pick examples from the provided data. For `Compatibility`, the test cases themselves provide good examples.

**7. Identifying Potential Usage Errors:**

By examining the test cases that check for `IsValidAsResponse` and the negative test cases in `InitializeTestParameters`, we can infer common errors, like providing invalid values for parameters or inconsistencies between request and response parameters.

**8. Developing Debugging Context:**

Thinking about how a developer might encounter this code leads to scenarios like investigating compression issues or connection failures. Tracing the WebSocket handshake process and examining the negotiated extensions would be natural steps.

**9. Structuring the Output:**

Finally, organize the findings into the requested sections: Functionality, JavaScript Relation, Logical Reasoning, Usage Errors, and Debugging Context. Use clear and concise language, and provide concrete examples where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the file is just about parsing.
* **Correction:** The tests also cover validation and compatibility, so it's more than just parsing.
* **Initial thought:** The JavaScript connection is indirect.
* **Correction:** It's a direct impact on the compression mechanism used in the browser's WebSocket implementation.

By following this methodical approach, combining code analysis with an understanding of the broader WebSocket context, we can arrive at a comprehensive and accurate description of the test file's purpose and its implications.
这个C++源代码文件 `websocket_deflate_parameters_test.cc` 是 Chromium 网络栈中用于测试 `WebSocketDeflateParameters` 类的单元测试文件。  `WebSocketDeflateParameters` 类负责管理 WebSocket 协议中用于 "permessage-deflate" 扩展的参数。这个扩展允许在 WebSocket 连接上使用压缩来减少传输的数据量。

以下是该文件的功能分解：

**1. 测试 `WebSocketDeflateParameters` 类的各种功能:**

* **构造和默认值测试 (`Empty`):** 验证 `WebSocketDeflateParameters` 对象的默认构造行为，例如：
    *  服务器和客户端上下文接管模式默认为 `TAKE_OVER_CONTEXT`。
    *  服务器和客户端最大窗口比特数未指定。
    *  作为请求和响应都是有效的。
    *  转换为扩展时，名称是 "permessage-deflate" 且没有参数。

* **设置和获取参数测试 (`ServerContextTakeover`, `ClientContextTakeover`, `ServerMaxWindowBits`, `ClientMaxWindowBitsWithoutValue`, `ClientMaxWindowBitsWithValue`):**
    * 测试设置不同的 deflate 参数，例如 `server_no_context_takeover`，`client_no_context_takeover`，`server_max_window_bits` 和 `client_max_window_bits`。
    * 验证设置参数后，`WebSocketDeflateParameters` 对象转换为 `WebSocketExtension` 时的参数是否正确。
    * 检查不同参数组合下，作为请求和响应的有效性。例如，`client_max_window_bits` 作为响应必须有值。

* **参数化初始化测试 (`WebSocketDeflateParametersInitializeTest`):**
    * 使用 `TEST_P` 宏进行参数化测试，测试使用不同的 "permessage-deflate" 扩展字符串初始化 `WebSocketDeflateParameters` 对象。
    * 验证初始化是否成功，并检查初始化后的对象与原始扩展是否等价。
    * 测试各种有效的和无效的参数组合，例如：
        *  空字符串。
        *  包含 `server_no_context_takeover` 或 `client_no_context_takeover`。
        *  包含有效的和无效的 `server_max_window_bits` 和 `client_max_window_bits` 值。
        *  包含重复的参数。
        *  包含未知的参数。
    * 针对每种情况验证预期的初始化结果（成功或失败）和失败消息。

* **兼容性测试 (`WebSocketDeflateParametersCompatibilityTest`):**
    * 使用 `TEST_P` 宏进行参数化测试，测试请求端的 `WebSocketDeflateParameters` 是否与响应端的 `WebSocketDeflateParameters` 兼容。
    * 模拟客户端发送的 "permessage-deflate" 请求头和服务器返回的 "permessage-deflate" 响应头，并检查它们的兼容性。
    * 测试各种兼容和不兼容的参数组合，例如：
        *  上下文接管模式的匹配。
        *  最大窗口比特数的协商。

**2. 与 JavaScript 的关系和举例说明:**

该文件本身是用 C++ 编写的，直接与 JavaScript 没有代码上的联系。但是，它测试的网络栈功能 **直接影响** 浏览器中 JavaScript WebSocket API 的行为。

当 JavaScript 代码使用 WebSocket API 连接到服务器并请求或接收压缩数据时，浏览器底层的网络栈（用 C++ 实现）会处理 "permessage-deflate" 扩展的协商和数据压缩/解压缩。

**举例说明:**

假设以下 JavaScript 代码用于创建一个 WebSocket 连接：

```javascript
const websocket = new WebSocket('wss://example.com', ['permessage-deflate']);

websocket.onopen = () => {
  console.log('WebSocket connection opened');
  websocket.send('Hello, server!');
};

websocket.onmessage = (event) => {
  console.log('Received message:', event.data);
};
```

当这个 JavaScript 代码尝试建立连接时，浏览器会发送一个包含 "permessage-deflate" 扩展的请求头，例如：

```
Sec-WebSocket-Extensions: permessage-deflate
```

服务器可能会在响应头中接受这个扩展，并提供自己的参数，例如：

```
Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_max_window_bits=10
```

`websocket_deflate_parameters_test.cc` 中测试的 `WebSocketDeflateParameters` 类就负责解析和管理这些协商的参数。例如，它会解析出 `server_no_context_takeover` 和 `client_max_window_bits=10`，并确定双方是否可以使用压缩，以及使用哪种压缩模式。

**3. 逻辑推理和假设输入/输出:**

**假设输入 (针对 `Initialize` 测试):**

* **输入字符串:**  `; server_max_window_bits=11; client_no_context_takeover`

**逻辑推理:**

1. `WebSocketExtensionParser` 会解析这个字符串，提取出 "permessage-deflate" 扩展和其参数。
2. `WebSocketDeflateParameters::Initialize` 方法会被调用，传入解析出的扩展对象。
3. 方法会检查 `server_max_window_bits` 的值 11 是否在允许的范围内 (8-15)。
4. 方法会识别 `client_no_context_takeover` 参数。

**假设输出:**

* **初始化结果:** `true` (初始化成功)
* **`WebSocketDeflateParameters` 对象状态:**
    * `server_context_take_over_mode()`:  `TAKE_OVER_CONTEXT` (默认值)
    * `client_context_take_over_mode()`: `NO_TAKE_OVER_CONTEXT`
    * `is_server_max_window_bits_specified()`: `true`
    * `server_max_window_bits()`: `11`
    * `is_client_max_window_bits_specified()`: `false`

**假设输入 (针对 `Compatibility` 测试):**

* **请求参数字符串:** `; server_max_window_bits=13`
* **响应参数字符串:** `; server_max_window_bits=12`

**逻辑推理:**

1. 请求端声明它可以接受服务器使用最大窗口比特数为 13 的压缩。
2. 响应端声明它将使用最大窗口比特数为 12 的压缩。
3. 因为响应端的窗口比特数 (12) 小于或等于请求端声明的最大值 (13)，所以它们是兼容的。

**假设输出:**

* **`IsCompatibleWith()` 返回值:** `true`

**4. 用户或编程常见的使用错误:**

* **服务器配置错误:** 服务器可能配置了不正确的 "permessage-deflate" 扩展参数，导致浏览器无法正确解析或协商。例如，服务器可能发送 `client_max_window_bits` 但没有提供值。测试中的 `ClientMaxWindowBitsWithoutValue` 就模拟了这种情况，并验证了作为响应是无效的。

* **手动构建错误的请求头:**  虽然浏览器通常会自动处理 WebSocket 扩展头的构建，但在某些调试或测试场景下，开发者可能会尝试手动构建请求头。如果构建的头字符串格式错误或者包含无效的参数值，`WebSocketDeflateParameters::Initialize` 方法将会返回错误。测试中的各种 `InitializeTestParameter` 覆盖了这些错误场景，例如无效的 `server_max_window_bits` 值 ("a", "09", "+9", "9a", 小于 8 或大于 15)。

* **不理解兼容性要求:** 开发者可能不清楚请求和响应之间 "permessage-deflate" 参数的兼容性要求。例如，客户端请求 `server_no_context_takeover`，但服务器没有提供这个参数，会导致不兼容。 `CompatibilityTestParameter` 中的测试用例就覆盖了这些兼容性场景。

**5. 用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器浏览某个网站时遇到了 WebSocket 连接压缩相关的问题，例如：

1. **用户访问网站:** 用户在 Chrome 浏览器中输入网址并访问一个使用了 WebSocket 的网站。
2. **WebSocket 连接建立:** 网站的 JavaScript 代码尝试使用 WebSocket API 连接到服务器。
3. **压缩协商失败或异常:** 在 WebSocket 握手过程中，"permessage-deflate" 扩展的协商可能失败，或者在连接建立后，压缩/解压缩过程中出现异常。
4. **开发者工具检查:** 开发者打开 Chrome 的开发者工具 (通常按 F12)，切换到 "Network" (网络) 或 "Application" (应用) 标签，查看 WebSocket 连接的详细信息。
5. **检查请求和响应头:** 开发者可能会看到 `Sec-WebSocket-Extensions` 请求头和响应头，并注意到 "permessage-deflate" 扩展及其参数。
6. **怀疑参数问题:** 如果发现协商的参数看起来有问题，或者压缩行为异常，开发者可能会怀疑 `WebSocketDeflateParameters` 类的实现可能存在 bug，或者服务器的配置不正确。
7. **搜索 Chromium 源代码:**  开发者可能会在 Chromium 的源代码中搜索 `permessage-deflate` 或 `WebSocketDeflateParameters`，最终找到 `websocket_deflate_parameters_test.cc` 这个测试文件。
8. **分析测试用例:** 开发者可以分析这个测试文件中的各种测试用例，了解 `WebSocketDeflateParameters` 类的预期行为，以及各种参数组合的有效性和兼容性。这可以帮助开发者判断是浏览器端的实现有问题，还是服务器端的配置有问题。
9. **可能的调试步骤:**
    * **检查服务器配置:** 确认服务器发送的 `Sec-WebSocket-Extensions` 响应头是否符合规范。
    * **使用不同的浏览器或客户端:**  对比不同浏览器或客户端的行为，排除特定浏览器实现的问题。
    * **查看 Chromium 网络日志:** 启用 Chromium 的网络日志，查看更底层的 WebSocket 握手和数据传输细节。
    * **单步调试 Chromium 源代码:**  如果怀疑是浏览器端的问题，开发者可能需要编译 Chromium 源代码，并在调试器中单步执行与 WebSocket 压缩相关的代码，例如 `WebSocketDeflateParameters::Initialize` 和 `IsCompatibleWith` 方法，来查找问题根源。

总而言之，`websocket_deflate_parameters_test.cc` 是保证 Chromium 网络栈中 WebSocket 压缩功能正确性的关键部分。通过分析这个测试文件，开发者可以理解 WebSocket 压缩参数的处理逻辑，并为调试相关问题提供有价值的线索。

### 提示词
```
这是目录为net/websockets/websocket_deflate_parameters_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_deflate_parameters.h"

#include <iterator>
#include <ostream>
#include <string>
#include <vector>

#include "net/websockets/websocket_extension_parser.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

void CheckExtension(const WebSocketDeflateParameters& params,
                    const std::string& name,
                    const std::string& value) {
  WebSocketExtension e = params.AsExtension();
  EXPECT_EQ("permessage-deflate", e.name());
  if (e.parameters().size() != 1)
    FAIL() << "parameters must have one element.";
  EXPECT_EQ(name, e.parameters()[0].name());
  EXPECT_EQ(value, e.parameters()[0].value());
}

TEST(WebSocketDeflateParametersTest, Empty) {
  WebSocketDeflateParameters r;

  EXPECT_EQ(WebSocketDeflater::TAKE_OVER_CONTEXT,
            r.server_context_take_over_mode());
  EXPECT_EQ(WebSocketDeflater::TAKE_OVER_CONTEXT,
            r.client_context_take_over_mode());
  EXPECT_FALSE(r.is_server_max_window_bits_specified());
  EXPECT_FALSE(r.is_client_max_window_bits_specified());
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_TRUE(r.IsValidAsResponse());
  WebSocketExtension e = r.AsExtension();
  EXPECT_EQ("permessage-deflate", e.name());
  EXPECT_TRUE(e.parameters().empty());
}

TEST(WebSocketDeflateParametersTest, ServerContextTakeover) {
  WebSocketDeflateParameters r;

  r.SetServerNoContextTakeOver();
  CheckExtension(r, "server_no_context_takeover", "");
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_TRUE(r.IsValidAsResponse());
}

TEST(WebSocketDeflateParametersTest, ClientContextTakeover) {
  WebSocketDeflateParameters r;

  r.SetClientNoContextTakeOver();
  CheckExtension(r, "client_no_context_takeover", "");
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_TRUE(r.IsValidAsResponse());
}

TEST(WebSocketDeflateParametersTest, ServerMaxWindowBits) {
  WebSocketDeflateParameters r;

  r.SetServerMaxWindowBits(13);
  CheckExtension(r, "server_max_window_bits", "13");
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_TRUE(r.IsValidAsResponse());
}

TEST(WebSocketDeflateParametersTest, ClientMaxWindowBitsWithoutValue) {
  WebSocketDeflateParameters r;
  std::string failure_message;

  r.SetClientMaxWindowBits();
  CheckExtension(r, "client_max_window_bits", "");
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_FALSE(r.IsValidAsResponse(&failure_message));
  EXPECT_EQ("client_max_window_bits must have value", failure_message);
}

TEST(WebSocketDeflateParametersTest, ClientMaxWindowBitsWithValue) {
  WebSocketDeflateParameters r;

  r.SetClientMaxWindowBits(12);
  CheckExtension(r, "client_max_window_bits", "12");
  EXPECT_TRUE(r.IsValidAsRequest());
  EXPECT_TRUE(r.IsValidAsResponse());
}

struct InitializeTestParameter {
  const std::string query;
  struct Expectation {
    bool result;
    std::string failure_message;
  } const expected;
};

void PrintTo(const InitializeTestParameter& p, std::ostream* o) {
  *o << p.query;
}

class WebSocketDeflateParametersInitializeTest
    : public ::testing::TestWithParam<InitializeTestParameter> {};

TEST_P(WebSocketDeflateParametersInitializeTest, Initialize) {
  const std::string query = GetParam().query;
  const bool expected = GetParam().expected.result;
  const std::string expected_failure_message =
      GetParam().expected.failure_message;

  WebSocketExtensionParser parser;
  ASSERT_TRUE(parser.Parse("permessage-deflate" + query));
  ASSERT_EQ(1u, parser.extensions().size());
  WebSocketExtension extension = parser.extensions()[0];

  WebSocketDeflateParameters parameters;
  std::string failure_message;
  bool actual = parameters.Initialize(extension, &failure_message);

  if (expected) {
    EXPECT_TRUE(actual);
    EXPECT_TRUE(extension.Equivalent(parameters.AsExtension()));
  } else {
    EXPECT_FALSE(actual);
  }
  EXPECT_EQ(expected_failure_message, failure_message);
}

struct CompatibilityTestParameter {
  const char* request_query;
  const char* response_query;
  const bool expected;
};

void PrintTo(const CompatibilityTestParameter& p, std::ostream* o) {
  *o << "req = \"" << p.request_query << "\", res = \"" << p.response_query
     << "\"";
}

class WebSocketDeflateParametersCompatibilityTest
    : public ::testing::TestWithParam<CompatibilityTestParameter> {};

TEST_P(WebSocketDeflateParametersCompatibilityTest, CheckCompatiblity) {
  const std::string request_query = GetParam().request_query;
  const std::string response_query = GetParam().response_query;
  const bool expected = GetParam().expected;

  std::string message;
  WebSocketDeflateParameters request, response;

  WebSocketExtensionParser request_parser;
  ASSERT_TRUE(request_parser.Parse("permessage-deflate" + request_query));
  ASSERT_EQ(1u, request_parser.extensions().size());
  ASSERT_TRUE(request.Initialize(request_parser.extensions()[0], &message));
  ASSERT_TRUE(request.IsValidAsRequest(&message));

  WebSocketExtensionParser response_parser;
  ASSERT_TRUE(response_parser.Parse("permessage-deflate" + response_query));
  ASSERT_EQ(1u, response_parser.extensions().size());
  ASSERT_TRUE(response.Initialize(response_parser.extensions()[0], &message));
  ASSERT_TRUE(response.IsValidAsResponse(&message));

  EXPECT_EQ(expected, request.IsCompatibleWith(response));
}

InitializeTestParameter::Expectation Duplicate(const std::string& name) {
  return {false,
          "Received duplicate permessage-deflate extension parameter " + name};
}

InitializeTestParameter::Expectation Invalid(const std::string& name) {
  return {false, "Received invalid " + name + " parameter"};
}

// We need this function in order to avoid global non-pod variables.
std::vector<InitializeTestParameter> InitializeTestParameters() {
  const InitializeTestParameter::Expectation kInitialized = {true, ""};
  const InitializeTestParameter::Expectation kUnknownParameter = {
      false, "Received an unexpected permessage-deflate extension parameter"};

  const InitializeTestParameter parameters[] = {
      {"", kInitialized},
      {"; server_no_context_takeover", kInitialized},
      {"; server_no_context_takeover=0", Invalid("server_no_context_takeover")},
      {"; server_no_context_takeover; server_no_context_takeover",
       Duplicate("server_no_context_takeover")},
      {"; client_no_context_takeover", kInitialized},
      {"; client_no_context_takeover=0", Invalid("client_no_context_takeover")},
      {"; client_no_context_takeover; client_no_context_takeover",
       Duplicate("client_no_context_takeover")},
      {"; server_max_window_bits=8", kInitialized},
      {"; server_max_window_bits=15", kInitialized},
      {"; server_max_window_bits=15; server_max_window_bits=15",
       Duplicate("server_max_window_bits")},
      {"; server_max_window_bits=a", Invalid("server_max_window_bits")},
      {"; server_max_window_bits=09", Invalid("server_max_window_bits")},
      {"; server_max_window_bits=+9", Invalid("server_max_window_bits")},
      {"; server_max_window_bits=9a", Invalid("server_max_window_bits")},
      {"; server_max_window_bits", Invalid("server_max_window_bits")},
      {"; server_max_window_bits=7", Invalid("server_max_window_bits")},
      {"; server_max_window_bits=16", Invalid("server_max_window_bits")},
      {"; client_max_window_bits=8", kInitialized},
      {"; client_max_window_bits=15", kInitialized},
      {"; client_max_window_bits=15; client_max_window_bits=15",
       Duplicate("client_max_window_bits")},
      {"; client_max_window_bits=a", Invalid("client_max_window_bits")},
      {"; client_max_window_bits=09", Invalid("client_max_window_bits")},
      {"; client_max_window_bits=+9", Invalid("client_max_window_bits")},
      {"; client_max_window_bits=9a", Invalid("client_max_window_bits")},
      {"; client_max_window_bits", kInitialized},
      {"; client_max_window_bits=7", Invalid("client_max_window_bits")},
      {"; client_max_window_bits=16", Invalid("client_max_window_bits")},
      {"; server_no_context_takeover; client_no_context_takeover"
       "; server_max_window_bits=12; client_max_window_bits=13",
       kInitialized},
      {"; hogefuga", kUnknownParameter},
  };
  return std::vector<InitializeTestParameter>(
      parameters, parameters + std::size(parameters));
}

constexpr CompatibilityTestParameter kCompatibilityTestParameters[] = {
    {"", "", true},
    // server_no_context_takeover
    {"", "; server_no_context_takeover", true},
    {"; server_no_context_takeover", "", false},
    {"; server_no_context_takeover", "; server_no_context_takeover", true},
    // client_no_context_takeover
    {"", "; client_no_context_takeover", true},
    {"; client_no_context_takeover", "", true},
    {"; client_no_context_takeover", "; client_no_context_takeover", true},
    // server_max_window_bits
    {"", "; server_max_window_bits=14", true},
    {"; server_max_window_bits=12", "", false},
    {"; server_max_window_bits=12", "; server_max_window_bits=12", true},
    {"; server_max_window_bits=12", "; server_max_window_bits=11", true},
    {"; server_max_window_bits=12", "; server_max_window_bits=13", false},
    // client_max_window_bits
    {"", "; client_max_window_bits=14", false},
    {"; client_max_window_bits", "", true},
    {"; client_max_window_bits", "; client_max_window_bits=15", true},
    {"; client_max_window_bits=12", "", true},
    {"; client_max_window_bits=12", "; client_max_window_bits=12", true},
    {"; client_max_window_bits=12", "; client_max_window_bits=11", true},
    {"; client_max_window_bits=12", "; client_max_window_bits=13", true},
};

INSTANTIATE_TEST_SUITE_P(WebSocketDeflateParametersInitializeTest,
                         WebSocketDeflateParametersInitializeTest,
                         ::testing::ValuesIn(InitializeTestParameters()));

INSTANTIATE_TEST_SUITE_P(WebSocketDeflateParametersCompatibilityTest,
                         WebSocketDeflateParametersCompatibilityTest,
                         ::testing::ValuesIn(kCompatibilityTestParameters));

}  // namespace

}  // namespace net
```