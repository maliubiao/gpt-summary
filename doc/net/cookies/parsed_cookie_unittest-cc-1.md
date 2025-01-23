Response:
Let's break down the request and the provided code to fulfill the user's needs.

**1. Understanding the Goal:**

The user wants a summary of the functionality of `parsed_cookie_unittest.cc`, specifically the second part of the file. They also want to know:

* **Relationship with JavaScript:** How does this C++ code relate to client-side JavaScript cookie handling?
* **Logical Reasoning (Input/Output):**  Provide examples of how the code behaves with specific inputs.
* **Common User/Programming Errors:**  Highlight potential pitfalls in using cookies that this code addresses.
* **Debugging Context:** Explain how a user's actions could lead to this code being executed.

**2. Analyzing the Code - Second Part:**

I'll go through each `TEST` function and identify its purpose:

* **`CookieSameSiteStringEnum`:** Tests the parsing and setting of the `SameSite` attribute, focusing on the conversion between string representations and enum values (`CookieSameSite`, `CookieSameSiteString`).
* **`SettersInputValidation`:** Checks the input validation logic for setters like `SetPath` and `SetDomain`, verifying that they handle whitespace and reject invalid characters.
* **`ToCookieLineSpecialTokens`:**  Focuses on how special cookie attributes like `secure` and `httponly` are handled when parsing and generating the cookie string. It checks their behavior in different positions and with repeated occurrences. It also touches upon `partitioned`.
* **`SameSiteValues`:**  Tests the basic parsing of `SameSite` with various valid and invalid string values and verifies the corresponding `CookieSameSite` enum.
* **`InvalidNonAlphanumericChars`:** Verifies that the parsing logic correctly identifies and rejects cookies with invalid control characters (specifically those *excluding* HT).
* **`ValidNonAlphanumericChars`:**  Demonstrates that the parser correctly handles valid non-ASCII characters in cookie names and values.
* **`PreviouslyTruncatingCharInCookieLine`:**  Tests how control characters (including those that used to truncate cookies) are now handled, specifically checking if they lead to invalid cookies.
* **`HtabInNameOrValue`:** Checks for the presence of horizontal tabs (HTAB) within cookie names and values.

**3. Connecting to the First Part (Implied):**

While the user only provided the second part, I know the first part likely contains tests for basic parsing, name/value extraction, expiration dates, and other fundamental cookie attributes. The tests in the second part build upon this foundation.

**4. Addressing the Specific Requirements:**

* **Functionality Summary:** I need to synthesize the purpose of each test into a concise summary for the second part.
* **JavaScript Relationship:** Cookies are a fundamental part of web communication. I need to explain how JavaScript uses `document.cookie` to interact with these HTTP headers and how the C++ code relates to the browser's internal handling.
* **Input/Output Examples:**  For each relevant test, I'll choose a specific input and the expected outcome (e.g., `ParsedCookie("name=value; SameSite=Strict")` should result in `SameSite()` returning `STRICT_MODE`).
* **Common Errors:**  I'll link the tests to common mistakes developers make when setting cookie attributes (e.g., using invalid characters, incorrect `SameSite` values).
* **User Operations & Debugging:** I need to map user actions (like visiting a website, clicking links) to the browser's internal processes that would trigger cookie parsing and validation.

**5. Structuring the Answer:**

I'll organize my answer into the sections requested by the user, providing clear explanations and examples. The structure will be:

* **Overall Functionality of the Second Part:** A high-level summary.
* **Relationship with JavaScript:** Explanation and examples.
* **Logical Reasoning (Input/Output Examples):**  Specific examples from the tests.
* **Common User/Programming Errors:**  Listing common mistakes and how the code prevents them.
* **User Operations and Debugging:**  A step-by-step explanation of how a user reaches this code.
* **Summary of Functionality (Second Part):** A concise recap.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus solely on the C++ code.
* **Correction:** Remember the user's request to connect to JavaScript. This requires explaining the client-server interaction of cookies.
* **Initial thought:** Provide very technical explanations of each test.
* **Correction:**  Balance technical details with more accessible language and relatable examples for a broader audience.
* **Initial thought:**  List all possible input/output combinations.
* **Correction:** Select representative examples that effectively illustrate the functionality of each test.
* **Initial thought:**  Assume the user understands the Chromium architecture.
* **Correction:** Provide a simplified explanation of how network requests and cookie handling fit into the browser.

By following this structured approach and continuously refining my understanding, I can generate a comprehensive and helpful answer that addresses all aspects of the user's request.
这是 `net/cookies/parsed_cookie_unittest.cc` 文件的第二部分，该文件是 Chromium 网络栈的一部分，专门用于测试 `ParsedCookie` 类的功能。`ParsedCookie` 类负责解析和操作 HTTP Cookie 字符串。

**本部分的功能归纳：**

这部分主要测试了 `ParsedCookie` 类在处理特定 Cookie 属性和边缘情况下的行为，包括：

* **`SameSite` 属性的字符串枚举转换：** 验证 `SameSite` 属性的不同字符串值（"Strict", "Lax", "None", 以及无效值）如何正确地转换为内部的 `CookieSameSite` 枚举值，以及反向转换。
* **Setters 的输入验证：** 测试 `ParsedCookie` 类的 setter 方法（如 `SetPath` 和 `SetDomain`）是否能够正确地处理和拒绝无效的输入，例如包含空格、换行符或其他非法字符的路径或域名。
* **特殊 Token 的处理 (secure, httponly, partitioned)：**  检验当 "secure" 和 "httponly" 这些特殊 token 出现在 Cookie 字符串的不同位置时，`ParsedCookie` 类的解析和序列化行为是否符合预期。重点在于区分它们作为属性名和属性值时的处理方式。
* **`SameSite` 属性的值解析：** 进一步测试 `SameSite` 属性不同字符串值的解析，包括有效值和无效值，并验证解析后的 `CookieSameSite` 枚举值是否正确。
* **无效的非字母数字字符的处理：** 检查当 Cookie 的名称或值中包含某些特定的非字母数字控制字符时，`ParsedCookie` 类是否能够正确地识别并标记 Cookie 为无效。
* **有效的非字母数字字符的处理：** 验证 `ParsedCookie` 类是否能够正确处理和保留 Cookie 名称和值中的有效的非 ASCII 字符。
* **早期会截断 Cookie 的字符处理：** 测试当 Cookie 字符串中包含一些早期版本浏览器可能会用来截断 Cookie 的控制字符时，`ParsedCookie` 类的处理方式。
* **制表符 (HTAB) 的处理：**  检查 Cookie 的名称或值中是否包含水平制表符，并提供方法判断是否存在。

**与 JavaScript 功能的关系：**

HTTP Cookie 是 Web 开发中重要的组成部分，JavaScript 可以通过 `document.cookie` API 来读取、设置和操作客户端存储的 Cookie。 `ParsedCookie` 类在 Chromium 浏览器内部负责解析从 HTTP 响应头中接收到的 `Set-Cookie` 字段，以及将浏览器中存储的 Cookie 序列化为发送到服务器的 `Cookie` 请求头。

**举例说明：**

1. **`SameSite` 属性：**
   - **C++ (ParsedCookie):**  当 Chromium 接收到服务器发送的响应头 `Set-Cookie: mycookie=value; SameSite=Strict` 时，`ParsedCookie` 类会解析这个字符串，并将 `SameSite` 属性的值存储为 `CookieSameSite::STRICT_MODE`。
   - **JavaScript:** 在浏览器中，可以通过 `document.cookie` 看到或设置 Cookie，但 JavaScript 无法直接获取或操作 `SameSite` 等属性的内部表示。`SameSite` 属性主要影响浏览器在不同场景下是否会发送该 Cookie，这由浏览器内部逻辑（包括 `ParsedCookie` 解析的结果）控制。

2. **输入验证：**
   - **C++ (ParsedCookie):** 如果 JavaScript 尝试设置一个包含非法字符的路径，例如通过某种方式绕过了浏览器的内置限制，或者服务器错误地发送了一个包含非法字符的 `Set-Cookie` 头，`ParsedCookie` 的 `SetPath` 方法会返回 `false`，表明设置失败。
   - **JavaScript:** 通常情况下，浏览器会限制 JavaScript 设置包含某些非法字符的 Cookie 属性。例如，直接使用 `document.cookie = "mycookie=value; path=bad\npath"` 可能会被浏览器阻止或转义。

**逻辑推理（假设输入与输出）：**

* **假设输入:**  `ParsedCookie pc("name=value; SameSite=Lax")`
   * **输出:** `pc.SameSite()` 将返回 `CookieSameSite::LAX_MODE`。 `actual` 参数在调用 `pc.SameSite(&actual)` 后会被设置为 `CookieSameSiteString::kLax`。
* **假设输入:** `ParsedCookie pc("mycookie=test"); pc.SetPath("/my path/")`
   * **输出:** `pc.ToCookieLine()` 将返回 `"mycookie=test; path=/my path/"` (注意：前后空格会被移除)。
* **假设输入:** `ParsedCookie pc("data=important; secure=true")`
   * **输出:** `pc.IsSecure()` 将返回 `true`。 `pc.ToCookieLine()` 将返回 `"data=important; secure"` (注意：`secure` 属性没有值)。

**用户或编程常见的使用错误：**

1. **在 Cookie 属性值中使用非法字符：**
   - **错误示例:** 服务器发送 `Set-Cookie: user=john\nDoe`。
   - **后果:** `ParsedCookie` 会将此 Cookie 标记为无效，因为它包含换行符。浏览器可能拒绝存储或使用此 Cookie。
2. **错误地设置 `SameSite` 属性的值：**
   - **错误示例:**  服务器发送 `Set-Cookie: sessionid=123; SameSite=anythingelse`。
   - **后果:** `ParsedCookie` 会将 `SameSite` 视为未指定 (`CookieSameSite::UNSPECIFIED`)，因为 "anythingelse" 不是有效的 `SameSite` 值。这可能导致 Cookie 的行为不符合预期，例如在跨站请求中被错误地发送或阻止。
3. **在 Cookie 路径或域名中使用控制字符：**
   - **错误示例:**  尝试设置 `document.cookie = "mycookie=value; path=/my\tpath"`。
   - **后果:**  虽然浏览器可能会尝试处理，但在内部，`ParsedCookie` 可能会因为路径包含制表符而认为它是无效的。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中访问一个网站 (例如 `example.com`)。**
2. **网站的服务器发送一个 HTTP 响应，其中包含 `Set-Cookie` 头部。** 例如：`Set-Cookie: session_id=abcdefg; Path=/; Secure; HttpOnly; SameSite=Strict`。
3. **Chromium 浏览器接收到这个响应。**
4. **网络栈的代码开始处理这个响应头。**
5. **`net::HttpResponseHeaders::EnumerateHeader` 等函数会被调用来提取 `Set-Cookie` 的值。**
6. **`net::cookies::ParsedCookie::ParseSetCookieAttribute` 或类似的函数会被调用，以解析 `Set-Cookie` 字符串的各个属性。** 这会创建 `ParsedCookie` 对象。
7. **在 `ParsedCookie` 的解析过程中，会调用各种方法（例如 `SetNameValuePair`，`SetAttribute`），这些方法内部的逻辑就包含在 `parsed_cookie_unittest.cc` 中测试的那些行为。** 例如，如果 `SameSite` 的值是 "Strict"，则会调用相应的逻辑将其转换为 `CookieSameSite::STRICT_MODE`。
8. **如果 Cookie 的格式不正确，例如包含无效字符，那么在 `ParsedCookie` 的解析过程中，`IsValid()` 方法可能会返回 `false`，并且设置 `CookieInclusionStatus` 来记录排除原因。**
9. **浏览器最终会根据解析后的 `ParsedCookie` 对象的信息来决定是否存储这个 Cookie，并记录其属性。**

**调试线索：**

* 如果用户报告网站的 Cookie 没有按预期工作（例如，会话在跨站跳转后丢失，或者某些功能无法使用），开发者可以检查浏览器开发者工具的 "Application" 或 "Storage" 面板中的 "Cookies" 部分，查看浏览器实际存储的 Cookie 及其属性。
* 如果发现 Cookie 的属性值不正确，或者某些 Cookie 没有被存储，开发者可以检查服务器发送的 `Set-Cookie` 头部是否符合规范。
* 通过在 Chromium 的网络栈代码中设置断点（例如在 `ParsedCookie::Parse` 或相关的 setter 方法中），开发者可以跟踪 Cookie 的解析过程，查看 `ParsedCookie` 对象是如何被创建和填充的，以及在哪个环节出现了问题。`parsed_cookie_unittest.cc` 中的测试用例可以帮助开发者理解 `ParsedCookie` 的预期行为，从而更好地定位问题。

**总结 (第二部分功能)：**

`parsed_cookie_unittest.cc` 的第二部分专注于测试 `ParsedCookie` 类对 Cookie 特定属性（如 `SameSite`，`secure`，`httponly`）以及各种边缘情况（如无效字符，特殊 token）的处理逻辑，确保 Cookie 的解析和操作符合 HTTP Cookie 规范，并且能够有效地防止由于不规范的 Cookie 字符串导致的错误。这些测试对于保证 Chromium 浏览器正确地处理和管理 HTTP Cookie 至关重要，从而维护用户的会话状态、安全性和隐私。

### 提示词
```
这是目录为net/cookies/parsed_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
value is returned for the SameSite attribute
// string.
TEST(ParsedCookieTest, CookieSameSiteStringEnum) {
  ParsedCookie pc("name=value; SameSite");
  CookieSameSiteString actual = CookieSameSiteString::kLax;
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kEmptyString, actual);

  pc.SetSameSite("Strict");
  EXPECT_EQ(CookieSameSite::STRICT_MODE, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kStrict, actual);

  pc.SetSameSite("Lax");
  EXPECT_EQ(CookieSameSite::LAX_MODE, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kLax, actual);

  pc.SetSameSite("None");
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kNone, actual);

  pc.SetSameSite("Extended");
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kExtended, actual);

  pc.SetSameSite("Bananas");
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, pc.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kUnrecognized, actual);

  ParsedCookie pc2("no_samesite=1");
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, pc2.SameSite(&actual));
  EXPECT_EQ(CookieSameSiteString::kUnspecified, actual);
}

TEST(ParsedCookieTest, SettersInputValidation) {
  ParsedCookie pc("name=foobar");
  EXPECT_TRUE(pc.SetPath("baz"));
  EXPECT_EQ(pc.ToCookieLine(), "name=foobar; path=baz");

  EXPECT_TRUE(pc.SetPath("  baz "));
  EXPECT_EQ(pc.ToCookieLine(), "name=foobar; path=baz");

  EXPECT_TRUE(pc.SetPath("     "));
  EXPECT_EQ(pc.ToCookieLine(), "name=foobar");

  EXPECT_TRUE(pc.SetDomain("  baz "));
  EXPECT_EQ(pc.ToCookieLine(), "name=foobar; domain=baz");

  // Invalid characters
  EXPECT_FALSE(pc.SetPath("  baz\n "));
  EXPECT_FALSE(pc.SetPath("f;oo"));
  EXPECT_FALSE(pc.SetPath("\r"));
  EXPECT_FALSE(pc.SetPath("\a"));
  EXPECT_FALSE(pc.SetPath("\t"));
  EXPECT_FALSE(pc.SetSameSite("\r"));
}

TEST(ParsedCookieTest, ToCookieLineSpecialTokens) {
  // Special tokens "secure", "httponly" should be treated as
  // any other name when they are in the first position.
  {
    ParsedCookie pc("");
    pc.SetName("secure");
    EXPECT_EQ(pc.ToCookieLine(), "secure=");
  }
  {
    ParsedCookie pc("secure");
    EXPECT_EQ(pc.ToCookieLine(), "=secure");
  }
  {
    ParsedCookie pc("secure=foo");
    EXPECT_EQ(pc.ToCookieLine(), "secure=foo");
  }
  {
    ParsedCookie pc("foo=secure");
    EXPECT_EQ(pc.ToCookieLine(), "foo=secure");
  }
  {
    ParsedCookie pc("httponly=foo");
    EXPECT_EQ(pc.ToCookieLine(), "httponly=foo");
  }
  {
    ParsedCookie pc("foo");
    pc.SetName("secure");
    EXPECT_EQ(pc.ToCookieLine(), "secure=foo");
  }
  {
    ParsedCookie pc("bar");
    pc.SetName("httponly");
    EXPECT_EQ(pc.ToCookieLine(), "httponly=bar");
  }
  {
    ParsedCookie pc("foo=bar; baz=bob");
    EXPECT_EQ(pc.ToCookieLine(), "foo=bar; baz=bob");
  }
  // Outside of the first position, the value associated with a special name
  // should not be printed.
  {
    ParsedCookie pc("name=foo; secure");
    EXPECT_EQ(pc.ToCookieLine(), "name=foo; secure");
  }
  {
    ParsedCookie pc("name=foo; secure=bar");
    EXPECT_EQ(pc.ToCookieLine(), "name=foo; secure");
  }
  {
    ParsedCookie pc("name=foo; httponly=baz");
    EXPECT_EQ(pc.ToCookieLine(), "name=foo; httponly");
  }
  {
    ParsedCookie pc("name=foo; bar=secure");
    EXPECT_EQ(pc.ToCookieLine(), "name=foo; bar=secure");
  }
  // Repeated instances of the special tokens are also fine.
  {
    ParsedCookie pc("name=foo; secure; secure=yesplease; secure; secure");
    EXPECT_TRUE(pc.IsValid());
    EXPECT_TRUE(pc.IsSecure());
    EXPECT_FALSE(pc.IsHttpOnly());
  }
  {
    ParsedCookie pc("partitioned=foo");
    EXPECT_EQ("partitioned", pc.Name());
    EXPECT_EQ("foo", pc.Value());
    EXPECT_FALSE(pc.IsPartitioned());
  }
  {
    ParsedCookie pc("partitioned=");
    EXPECT_EQ("partitioned", pc.Name());
    EXPECT_EQ("", pc.Value());
    EXPECT_FALSE(pc.IsPartitioned());
  }
  {
    ParsedCookie pc("=partitioned");
    EXPECT_EQ("", pc.Name());
    EXPECT_EQ("partitioned", pc.Value());
    EXPECT_FALSE(pc.IsPartitioned());
  }
  {
    ParsedCookie pc(
        "partitioned; partitioned; secure; httponly; httponly; secure");
    EXPECT_EQ("", pc.Name());
    EXPECT_EQ("partitioned", pc.Value());
    EXPECT_TRUE(pc.IsPartitioned());
  }
}

TEST(ParsedCookieTest, SameSiteValues) {
  struct TestCase {
    const char* cookie;
    bool valid;
    CookieSameSite mode;
  } cases[]{{"n=v; samesite=strict", true, CookieSameSite::STRICT_MODE},
            {"n=v; samesite=lax", true, CookieSameSite::LAX_MODE},
            {"n=v; samesite=none", true, CookieSameSite::NO_RESTRICTION},
            {"n=v; samesite=boo", true, CookieSameSite::UNSPECIFIED},
            {"n=v; samesite", true, CookieSameSite::UNSPECIFIED},
            {"n=v", true, CookieSameSite::UNSPECIFIED}};

  for (const auto& test : cases) {
    SCOPED_TRACE(test.cookie);
    ParsedCookie pc(test.cookie);
    EXPECT_EQ(test.valid, pc.IsValid());
    EXPECT_EQ(test.mode, pc.SameSite());
  }
}

TEST(ParsedCookieTest, InvalidNonAlphanumericChars) {
  // clang-format off
  const char* cases[] = {
      "name=\x05",
      "name=foo\x1c" "bar",
      "name=foobar\x11",
      "name=\x02" "foobar",
      "\x05=value",
      "foo\x05" "bar=value",
      "foobar\x05" "=value",
      "\x05" "foobar=value",
      "foo\x05" "bar=foo\x05" "bar",
      "foo=ba,ba\x05" "z=boo",
      "foo=ba,baz=bo\x05" "o",
      "foo=ba,ba\05" "z=bo\x05" "o",
      "foo=ba,ba\x7F" "z=bo",
      "fo\x7F" "o=ba,z=bo",
      "foo=bar\x7F" ";z=bo",
  };
  // clang-format on

  for (size_t i = 0; i < std::size(cases); i++) {
    SCOPED_TRACE(testing::Message()
                 << "Test case #" << base::NumberToString(i + 1));
    CookieInclusionStatus status;
    ParsedCookie pc(cases[i], &status);
    EXPECT_FALSE(pc.IsValid());
    EXPECT_TRUE(status.HasOnlyExclusionReason(
        CookieInclusionStatus::ExclusionReason::EXCLUDE_DISALLOWED_CHARACTER));
  }
}

TEST(ParsedCookieTest, ValidNonAlphanumericChars) {
  // Note that some of these words are pasted backwords thanks to poor vim
  // bidi support. This should not affect the tests, however.
  const char pc1_literal[] = "name=العربية";
  const char pc2_literal[] = "name=普通話";
  const char pc3_literal[] = "name=ภาษาไทย";
  const char pc4_literal[] = "name=עִבְרִית";
  const char pc5_literal[] = "العربية=value";
  const char pc6_literal[] = "普通話=value";
  const char pc7_literal[] = "ภาษาไทย=value";
  const char pc8_literal[] = "עִבְרִית=value";
  const char pc9_literal[] = "@foo=bar";

  ParsedCookie pc1(pc1_literal);
  ParsedCookie pc2(pc2_literal);
  ParsedCookie pc3(pc3_literal);
  ParsedCookie pc4(pc4_literal);
  ParsedCookie pc5(pc5_literal);
  ParsedCookie pc6(pc6_literal);
  ParsedCookie pc7(pc7_literal);
  ParsedCookie pc8(pc8_literal);
  ParsedCookie pc9(pc9_literal);

  EXPECT_TRUE(pc1.IsValid());
  EXPECT_EQ(pc1_literal, pc1.ToCookieLine());
  EXPECT_TRUE(pc2.IsValid());
  EXPECT_EQ(pc2_literal, pc2.ToCookieLine());
  EXPECT_TRUE(pc3.IsValid());
  EXPECT_EQ(pc3_literal, pc3.ToCookieLine());
  EXPECT_TRUE(pc4.IsValid());
  EXPECT_EQ(pc4_literal, pc4.ToCookieLine());
  EXPECT_TRUE(pc5.IsValid());
  EXPECT_EQ(pc5_literal, pc5.ToCookieLine());
  EXPECT_TRUE(pc6.IsValid());
  EXPECT_EQ(pc6_literal, pc6.ToCookieLine());
  EXPECT_TRUE(pc7.IsValid());
  EXPECT_EQ(pc7_literal, pc7.ToCookieLine());
  EXPECT_TRUE(pc8.IsValid());
  EXPECT_EQ(pc8_literal, pc8.ToCookieLine());
  EXPECT_TRUE(pc9.IsValid());
  EXPECT_EQ(pc9_literal, pc9.ToCookieLine());

  EXPECT_TRUE(pc1.SetValue(pc1.Value()));
  EXPECT_EQ(pc1_literal, pc1.ToCookieLine());
  EXPECT_TRUE(pc1.IsValid());
  EXPECT_TRUE(pc2.SetValue(pc2.Value()));
  EXPECT_EQ(pc2_literal, pc2.ToCookieLine());
  EXPECT_TRUE(pc2.IsValid());
  EXPECT_TRUE(pc3.SetValue(pc3.Value()));
  EXPECT_EQ(pc3_literal, pc3.ToCookieLine());
  EXPECT_TRUE(pc3.IsValid());
  EXPECT_TRUE(pc4.SetValue(pc4.Value()));
  EXPECT_EQ(pc4_literal, pc4.ToCookieLine());
  EXPECT_TRUE(pc4.IsValid());
  EXPECT_TRUE(pc5.SetName(pc5.Name()));
  EXPECT_EQ(pc5_literal, pc5.ToCookieLine());
  EXPECT_TRUE(pc5.IsValid());
  EXPECT_TRUE(pc6.SetName(pc6.Name()));
  EXPECT_EQ(pc6_literal, pc6.ToCookieLine());
  EXPECT_TRUE(pc6.IsValid());
  EXPECT_TRUE(pc7.SetName(pc7.Name()));
  EXPECT_EQ(pc7_literal, pc7.ToCookieLine());
  EXPECT_TRUE(pc7.IsValid());
  EXPECT_TRUE(pc8.SetName(pc8.Name()));
  EXPECT_EQ(pc8_literal, pc8.ToCookieLine());
  EXPECT_TRUE(pc8.IsValid());
  EXPECT_TRUE(pc9.SetName(pc9.Name()));
  EXPECT_EQ(pc9_literal, pc9.ToCookieLine());
  EXPECT_TRUE(pc9.IsValid());
}

TEST(ParsedCookieTest, PreviouslyTruncatingCharInCookieLine) {
  // Test scenarios where a control char may appear at start, middle and end of
  // a cookie line. Control char array with NULL (\x0), CR (\xD), LF (xA),
  // HT (\x9) and BS (\x1B).
  const struct {
    const char ctlChar;
    bool invalid_character;
  } kTests[] = {{'\x0', true},
                {'\xD', true},
                {'\xA', true},
                {'\x9', false},
                {'\x1B', false}};

  for (const auto& test : kTests) {
    SCOPED_TRACE(testing::Message() << "Using test.ctlChar == "
                                    << base::NumberToString(test.ctlChar));
    std::string ctl_string(1, test.ctlChar);
    std::string ctl_at_start_cookie_string =
        base::StrCat({ctl_string, "foo=bar"});
    ParsedCookie ctl_at_start_cookie(ctl_at_start_cookie_string);
    // Lots of factors determine whether IsValid() is true here:
    //
    //  - For the tab character ('\x9), leading whitespace is valid and the
    //  spec indicates that it should just be removed and the cookie parsed
    //  normally. Thus, in this case the cookie is always valid.
    //
    //  - For control characters that historically truncated the cookie, they
    //  now cause the cookie to be deemed invalid.
    //
    //  - For other control characters the cookie is always treated as invalid.
    EXPECT_EQ(ctl_at_start_cookie.IsValid(), test.ctlChar == '\x9');

    std::string ctl_at_middle_cookie_string =
        base::StrCat({"foo=bar;", ctl_string, "secure"});
    ParsedCookie ctl_at_middle_cookie(ctl_at_middle_cookie_string);
    if (test.invalid_character) {
      EXPECT_EQ(ctl_at_middle_cookie.IsValid(), false);
    }

    std::string ctl_at_end_cookie_string =
        base::StrCat({"foo=bar;", "secure;", ctl_string});
    ParsedCookie ctl_at_end_cookie(ctl_at_end_cookie_string);
    if (test.invalid_character) {
      EXPECT_EQ(ctl_at_end_cookie.IsValid(), false);
    }
  }

  // Test if there are multiple control characters that terminate.
  std::string ctls_cookie_string = "foo=bar;\xA\xD";
  ParsedCookie ctls_cookie(ctls_cookie_string);
  EXPECT_EQ(ctls_cookie.IsValid(), false);
}

TEST(ParsedCookieTest, HtabInNameOrValue) {
  std::string no_htab_string = "foo=bar";
  ParsedCookie no_htab(no_htab_string);
  EXPECT_FALSE(no_htab.HasInternalHtab());

  std::string htab_leading_trailing_string = "\tfoo=bar\t";
  ParsedCookie htab_leading_trailing(htab_leading_trailing_string);
  EXPECT_FALSE(htab_leading_trailing.HasInternalHtab());

  std::string htab_name_string = "f\too=bar";
  ParsedCookie htab_name(htab_name_string);
  EXPECT_TRUE(htab_name.HasInternalHtab());

  std::string htab_value_string = "foo=b\tar";
  ParsedCookie htab_value(htab_value_string);
  EXPECT_TRUE(htab_value.HasInternalHtab());
}

}  // namespace net
```