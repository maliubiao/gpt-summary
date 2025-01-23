Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The first step is to understand *why* this file exists. The file name `noop_header_validator_test.cc` within the `net/third_party/quiche/src/quiche/http2/adapter/` directory gives a strong clue. It's a test file for a header validator, and the "noop" part suggests this validator doesn't actually do much validation.

2. **Identify the Subject Under Test:** Look for the `#include` directive that includes the implementation. We see `#include "quiche/http2/adapter/noop_header_validator.h"`. This tells us the class being tested is `NoopHeaderValidator`.

3. **Analyze the Test Structure:**  The file uses Google Test (`#include "quiche/common/platform/api/quiche_test.h"`). This means the tests are structured as `TEST(TestSuiteName, TestName) { ... }`. We can identify the test suite (`NoopHeaderValidatorTest`) and the individual test cases (e.g., `HeaderNameEmpty`, `HeaderValueEmpty`, etc.).

4. **Examine Individual Test Cases:** Go through each `TEST` block and understand what it's verifying. Look for the following:
    * **Setup:** How is the `NoopHeaderValidator` object created? (`NoopHeaderValidator v;`)
    * **Actions:** What methods are being called on the validator? (`v.ValidateSingleHeader(...)`, `v.SetMaxFieldSize(...)`, `v.StartHeaderBlock()`, `v.FinishHeaderBlock(...)`)
    * **Assertions:** What are the expected outcomes? (`EXPECT_EQ(...)`, `EXPECT_TRUE(...)`) What values are being compared?

5. **Infer Functionality from Tests:**  Based on the test cases, deduce the intended behavior of the `NoopHeaderValidator`. Notice how almost all tests expect `NoopHeaderValidator::HEADER_OK`. This immediately suggests the validator doesn't perform strict validation.

6. **Look for Edge Cases and Specific Scenarios:** Pay attention to tests with descriptive names. For example, `ExceedsMaxSize` hints at a size limit (though the test shows it's *not* enforced). `RequestHostAndAuthority`, `RequestPseudoHeaders`, `ResponsePseudoHeaders` indicate handling of HTTP/2 specific headers.

7. **Address the "Noop" Aspect:** The repeated expectation of `HEADER_OK` for various potentially invalid inputs (like missing or repeated pseudo-headers, invalid characters, etc.) confirms that this validator's primary purpose is *not* to strictly enforce HTTP/2 header rules. It seems to act as a placeholder or a way to disable validation.

8. **Relate to JavaScript (or Front-End):**  Consider where header validation is relevant in a web context. Browsers and front-end JavaScript interact with HTTP headers. Think about potential connections:
    * **Security:**  Strict header validation is crucial for preventing attacks. A "noop" validator wouldn't provide this security.
    * **Interoperability:** Standard header formats ensure different systems can communicate. A "noop" validator might allow non-standard headers, potentially causing issues.
    * **Performance:**  While this validator doesn't add validation overhead, a *real* validator might have performance implications.

9. **Construct Example Scenarios and Debugging Paths:** Imagine how a developer might end up using this "noop" validator. It could be a deliberate choice during development, or it might be a configuration setting. Think about the steps a user would take in a browser to trigger an HTTP request that would pass through this validator on the server side.

10. **Consider Potential User Errors:** Think about common mistakes developers might make regarding HTTP headers (e.g., incorrect casing, missing required headers, invalid values). Explain how the "noop" validator would *not* catch these errors.

11. **Structure the Output:** Organize the findings logically into the requested categories: functionality, relationship to JavaScript, logical reasoning (input/output), common errors, and debugging paths. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe "noop" means it only validates *some* things.
* **Correction:** After reviewing the tests, it's clear it validates *nothing* strictly. The `HEADER_OK` is consistently returned.

* **Initial thought:**  Focus heavily on the technical details of each test case.
* **Refinement:** Step back and focus on the *overall purpose* and implications of a no-op validator. Why would such a thing exist?  What are its trade-offs?

* **Initial thought:**  The JavaScript connection might be very direct.
* **Refinement:**  The connection is more conceptual. JavaScript running in a browser generates requests with headers, and the server (using this code) might *not* validate them if this "noop" validator is in place.

By following this systematic process of code analysis, test examination, and contextual reasoning, we can arrive at a comprehensive understanding of the provided C++ file and its implications.
The C++ source file `noop_header_validator_test.cc` is part of the Chromium network stack, specifically within the QUIC implementation (indicated by the `quiche` directory). It contains unit tests for a class named `NoopHeaderValidator`. Let's break down its functionalities and address your specific points:

**Functionality of `noop_header_validator_test.cc`:**

This file tests the behavior of the `NoopHeaderValidator` class. The key characteristic of a "noop" validator is that it performs **minimal to no actual validation** of HTTP/2 headers. The tests in this file confirm this behavior by checking that the `ValidateSingleHeader` method of `NoopHeaderValidator` almost always returns `NoopHeaderValidator::HEADER_OK`, regardless of the header name and value provided.

Here's a summary of what the tests verify:

* **Basic Cases:**
    * Empty header names and values are considered valid.
    * Header sizes exceeding a set maximum are still considered valid (demonstrating the "noop" nature).
* **Character Validity:**
    * Any character in header names and values is considered valid. This includes characters that might be invalid according to strict HTTP/2 specifications.
* **Pseudo-headers:**
    * The presence, absence, or repetition of mandatory pseudo-headers (like `:authority`, `:method`, `:path`, `:scheme` for requests, and `:status` for responses) does not cause validation to fail.
    *  Specific pseudo-headers like `:protocol` for WebSockets are also allowed without specific validation.
    * The `:path` pseudo-header can have arbitrary values, including empty strings or values not starting with a slash.
* **Status Codes:**
    * Any value for the `:status` pseudo-header is considered valid.
* **`Host` and `:authority`:**
    * The presence and values of both the `Host` header and the `:authority` pseudo-header are allowed, even if they differ.
* **Response Specifics:**
    *  Responses are considered valid even if `:status` is missing or repeated.
    *  The presence of the `Host` header in a response is allowed.
    *  Responses with status codes like 204 (No Content) and 100 (Continue) are allowed with or without `Content-Length` headers (even potentially contradictory ones, highlighting the lack of validation).
* **Content-Length:**
    * Invalid `Content-Length` values (empty, non-numeric, negative) are still considered valid.
    * Multiple `Content-Length` headers with differing values are also allowed.
* **`Te` Header:**
    *  The `Te` header with values like "trailers" is considered valid.
* **Connection-Specific Headers:**
    * Connection-specific headers like `Connection`, `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, and `Upgrade` are allowed, even though they are generally discouraged or have specific semantics in HTTP/2.

**Relationship to JavaScript:**

While this C++ code doesn't directly interact with JavaScript code at runtime, it plays a crucial role in how a browser (which uses Chromium's network stack) handles HTTP/2 requests and responses initiated by JavaScript.

**Example:**

Imagine a JavaScript application running in a browser makes an HTTP/2 request with an invalid header, like:

```javascript
fetch('https://www.example.com/api', {
  headers: {
    'invalid-header!@#': 'some value'
  }
});
```

If the server receiving this request (and using the Chromium network stack with `NoopHeaderValidator` in place) were to use this validator, the `NoopHeaderValidator` would **not** flag `'invalid-header!@#'` as an invalid header name. It would consider it `HEADER_OK`.

In a system using a *strict* header validator, this request might be rejected by the server or lead to unexpected behavior. The `NoopHeaderValidator` essentially bypasses this kind of server-side validation.

**Why have a `NoopHeaderValidator`?**

There are several reasons why such a validator might exist:

* **Development/Testing:** It can be useful during development or testing phases to temporarily disable strict header validation and focus on other aspects of the system.
* **Flexibility/Compatibility:** In some scenarios, a more permissive approach to headers might be desired for interoperability with older or non-standard HTTP/2 implementations.
* **Performance:**  Skipping validation can offer a slight performance improvement, although the trade-off is reduced robustness.
* **Abstract Interface:**  The `NoopHeaderValidator` could be a concrete implementation of a more general `HeaderValidator` interface, allowing different validation strategies to be plugged in.

**Logical Reasoning (Hypothetical Input and Output):**

**Assumption:** We are calling the `ValidateSingleHeader` method of an instance of `NoopHeaderValidator`.

**Input 1:**

* Header Name: `"Content-Length"`
* Header Value: `"abc"`

**Output 1:** `NoopHeaderValidator::HEADER_OK`

**Input 2:**

* Header Name: `":status"`
* Header Value: `"invalid_status"`

**Output 2:** `NoopHeaderValidator::HEADER_OK`

**Input 3:**

* Header Name: `""` (empty string)
* Header Value: `"some_value"`

**Output 3:** `NoopHeaderValidator::HEADER_OK`

**Common User or Programming Errors and How `NoopHeaderValidator` Ignores Them:**

A developer might make several mistakes when dealing with HTTP headers. Here are a few examples and how `NoopHeaderValidator` would treat them:

1. **Incorrect Header Name Characters:**
   * **Error:** Using invalid characters like spaces or special symbols in header names (e.g., `"User Agent"` instead of `"User-Agent"`).
   * **`NoopHeaderValidator` Behavior:**  Returns `HEADER_OK`.

2. **Missing Mandatory Pseudo-Headers:**
   * **Error:** Sending an HTTP/2 request without the `:authority` pseudo-header.
   * **`NoopHeaderValidator` Behavior:** Returns `HEADER_OK` when validating individual headers and when finishing the header block.

3. **Invalid `:status` Code:**
   * **Error:**  A server responding with `:status: 999`.
   * **`NoopHeaderValidator` Behavior:** Returns `HEADER_OK`.

4. **Conflicting `Content-Length` Headers:**
   * **Error:** Sending a response with two `Content-Length` headers having different values.
   * **`NoopHeaderValidator` Behavior:** Returns `HEADER_OK` for both headers.

5. **Using Connection-Specific Headers:**
   * **Error:**  A client sending a `Connection: keep-alive` header in an HTTP/2 request.
   * **`NoopHeaderValidator` Behavior:** Returns `HEADER_OK`.

**User Operation Steps to Reach This Code (Debugging Clues):**

To understand how a user action might lead to this code being executed, consider a scenario where a developer is debugging an HTTP/2 connection issue within a Chromium-based browser or a server using Chromium's network stack.

1. **User Action:** A user interacts with a web page, triggering a network request (e.g., clicking a link, submitting a form, or a JavaScript application making an API call).

2. **Browser Processing (Client-Side):**
   * The browser's rendering engine (Blink) initiates a network request based on the user's action.
   * The request includes HTTP headers.

3. **Network Stack (Client-Side):**
   * The request is handled by Chromium's network stack, specifically the QUIC or HTTP/2 implementation.
   * If the connection is over HTTP/2, the headers need to be validated (or in this case, the `NoopHeaderValidator` is used).

4. **Server Processing (Potentially):**
   * The request travels over the network to the server.
   * If the server is also using Chromium's network stack (or a system derived from it), the incoming HTTP/2 headers will be processed.

5. **Debugging Scenario:**
   * A developer might suspect a header validation issue is causing problems.
   * They might set breakpoints or logging within the `NoopHeaderValidator::ValidateSingleHeader` function to observe the headers being processed and confirm that no actual validation is taking place.
   * Alternatively, if a *different* header validator were in use, they might be investigating why a specific header is being rejected and comparing it to the behavior of the `NoopHeaderValidator`.

**In essence, this test file serves as a confirmation that the `NoopHeaderValidator` does *not* enforce strict HTTP/2 header rules. It's a useful tool for understanding this specific validator's behavior and contrasting it with more rigorous validation implementations.**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/noop_header_validator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/noop_header_validator.h"

#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

using ::testing::Optional;

using Header = std::pair<absl::string_view, absl::string_view>;
constexpr Header kSampleRequestPseudoheaders[] = {{":authority", "www.foo.com"},
                                                  {":method", "GET"},
                                                  {":path", "/foo"},
                                                  {":scheme", "https"}};

TEST(NoopHeaderValidatorTest, HeaderNameEmpty) {
  NoopHeaderValidator v;
  NoopHeaderValidator::HeaderStatus status =
      v.ValidateSingleHeader("", "value");
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK, status);
}

TEST(NoopHeaderValidatorTest, HeaderValueEmpty) {
  NoopHeaderValidator v;
  NoopHeaderValidator::HeaderStatus status = v.ValidateSingleHeader("name", "");
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK, status);
}

TEST(NoopHeaderValidatorTest, ExceedsMaxSize) {
  NoopHeaderValidator v;
  v.SetMaxFieldSize(64u);
  NoopHeaderValidator::HeaderStatus status =
      v.ValidateSingleHeader("name", "value");
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK, status);
  status = v.ValidateSingleHeader(
      "name2",
      "Antidisestablishmentariansism is supercalifragilisticexpialodocious.");
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK, status);
}

TEST(NoopHeaderValidatorTest, AnyNameCharIsValid) {
  NoopHeaderValidator v;
  char pseudo_name[] = ":met hod";
  char name[] = "na me";
  for (int i = std::numeric_limits<char>::min();
       i < std::numeric_limits<char>::max(); ++i) {
    char c = static_cast<char>(i);
    // Test a pseudo-header name with this char.
    pseudo_name[3] = c;
    auto sv = absl::string_view(pseudo_name, 8);
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(sv, "value"));
    // Test a regular header name with this char.
    name[2] = c;
    sv = absl::string_view(name, 5);
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(sv, "value"));
  }
}

TEST(NoopHeaderValidatorTest, AnyValueCharIsValid) {
  NoopHeaderValidator v;
  char value[] = "val ue";
  for (int i = std::numeric_limits<char>::min();
       i < std::numeric_limits<char>::max(); ++i) {
    char c = static_cast<char>(i);
    value[3] = c;
    auto sv = absl::string_view(value, 6);
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader("name", sv));
  }
}

TEST(NoopHeaderValidatorTest, AnyStatusIsValid) {
  NoopHeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "bar"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));

    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "10"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));

    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "9000"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));

    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "400"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
  }
}

TEST(NoopHeaderValidatorTest, AnyAuthorityCharIsValid) {
  char value[] = "ho st.example.com";
  for (int i = std::numeric_limits<char>::min();
       i < std::numeric_limits<char>::max(); ++i) {
    char c = static_cast<char>(i);
    value[2] = c;
    auto sv = absl::string_view(value, 17);
    for (absl::string_view key : {":authority", "host"}) {
      NoopHeaderValidator v;
      v.StartHeaderBlock();
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(key, sv));
    }
  }
}

TEST(NoopHeaderValidatorTest, RequestHostAndAuthority) {
  NoopHeaderValidator v;
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // If both "host" and ":authority" have the same value, validation succeeds.
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "www.foo.com"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // If "host" and ":authority" have different values, validation still
  // succeeds.
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "www.bar.com"));
}

TEST(NoopHeaderValidatorTest, RequestPseudoHeaders) {
  NoopHeaderValidator v;
  for (Header to_skip : kSampleRequestPseudoheaders) {
    v.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add != to_skip) {
        EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    // Even if a pseudo-header is missing, final validation will succeed.
    EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }

  // When all pseudo-headers are present, final validation will succeed.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When an extra pseudo-header is present, final validation will still
  // succeed.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":extra", "blah"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When a required pseudo-header is repeated, final validation will succeed.
  for (Header to_repeat : kSampleRequestPseudoheaders) {
    v.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
      if (to_add == to_repeat) {
        EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }
}

TEST(NoopHeaderValidatorTest, WebsocketPseudoHeaders) {
  NoopHeaderValidator v;
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // Validation always succeeds.
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // This is a no-op for NoopHeaderValidator.
  v.SetAllowExtendedConnect();

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // The validator does not check for a CONNECT request.
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":method") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "CONNECT"));
    } else {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // After allowing the method, `:protocol` is acepted for CONNECT requests.
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(NoopHeaderValidatorTest, AsteriskPathPseudoHeader) {
  NoopHeaderValidator v;

  // The validator does not perform any path validation.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "*"));
    } else {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "*"));
    } else if (to_add.first == ":method") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "OPTIONS"));
    } else {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(NoopHeaderValidatorTest, InvalidPathPseudoHeader) {
  NoopHeaderValidator v;

  // An empty path is allowed.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, ""));
    } else {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // A path that does not start with a slash is allowed.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "shawarma"));
    } else {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(NoopHeaderValidatorTest, ResponsePseudoHeaders) {
  NoopHeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` is missing, validation succeeds.
    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader("foo", "bar"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));

    // When all pseudo-headers are present, final validation succeeds.
    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
    EXPECT_EQ("199", v.status_header());

    // When `:status` is repeated, validation succeeds.
    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "299"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));

    // When an extra pseudo-header is present, final validation succeeds.
    v.StartHeaderBlock();
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":extra", "blorp"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
  }
}

TEST(NoopHeaderValidatorTest, ResponseWithHost) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "myserver.com"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(NoopHeaderValidatorTest, Response204) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(NoopHeaderValidatorTest, ResponseWithMultipleIdenticalContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "13"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "13"));
}

TEST(NoopHeaderValidatorTest, ResponseWithMultipleDifferingContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "13"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "17"));
}

TEST(NoopHeaderValidatorTest, Response204WithContentLengthZero) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "0"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(NoopHeaderValidatorTest, Response204WithContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "1"));
}

TEST(NoopHeaderValidatorTest, Response100) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(NoopHeaderValidatorTest, Response100WithContentLengthZero) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "0"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(NoopHeaderValidatorTest, Response100WithContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "1"));
}

TEST(NoopHeaderValidatorTest, ResponseTrailerPseudoHeaders) {
  NoopHeaderValidator v;

  // When no pseudo-headers are present, validation will succeed.
  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("foo", "bar"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));

  // When a pseudo-header is present, validation will succeed.
  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("foo", "bar"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));
}

TEST(NoopHeaderValidatorTest, ValidContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "41"));
  EXPECT_EQ(v.content_length(), std::nullopt);

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_EQ(v.content_length(), std::nullopt);
}

TEST(NoopHeaderValidatorTest, InvalidContentLength) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", ""));
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "nan"));
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "-42"));
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_EQ(v.content_length(), std::nullopt);
}

TEST(NoopHeaderValidatorTest, TeHeader) {
  NoopHeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("te", "trailers"));

  v.StartHeaderBlock();
  EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("te", "trailers, deflate"));
}

TEST(NoopHeaderValidatorTest, ConnectionSpecificHeaders) {
  const std::vector<Header> connection_headers = {
      {"connection", "keep-alive"}, {"proxy-connection", "keep-alive"},
      {"keep-alive", "timeout=42"}, {"transfer-encoding", "chunked"},
      {"upgrade", "h2c"},
  };
  for (const auto& [connection_key, connection_value] : connection_headers) {
    NoopHeaderValidator v;
    v.StartHeaderBlock();
    for (const auto& [sample_key, sample_value] : kSampleRequestPseudoheaders) {
      EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(sample_key, sample_value));
    }
    EXPECT_EQ(NoopHeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(connection_key, connection_value));
  }
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
```