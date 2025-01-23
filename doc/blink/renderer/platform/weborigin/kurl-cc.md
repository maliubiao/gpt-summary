Response:
The user wants a summary of the functionality of the `kurl.cc` file in the Chromium Blink engine, specifically focusing on its relationship with JavaScript, HTML, and CSS, including examples, logical inferences with hypothetical inputs and outputs, and common user/programming errors. This is the first part of a two-part request, so the response should focus on summarizing the file's overall purpose.

**Plan:**

1. **Identify the core purpose of `kurl.cc`**:  The filename and the initial copyright information suggest it's related to URL handling.
2. **Analyze the included headers**: These will provide clues about the file's dependencies and the types of operations it performs (e.g., string manipulation, web origin concepts, URL parsing).
3. **Examine the major classes and functions**:  Focus on the `KURL` class and its methods, as well as any helper functions.
4. **Relate the functionality to web technologies**:  Consider how URL manipulation impacts JavaScript (e.g., `window.location`), HTML (e.g., `<a>` tag `href`), and CSS (e.g., `url()` function).
5. **Look for explicit mentions or implicit connections to these technologies**: The presence of functions like `UrlStrippedForUseAsReferrer` or methods for setting URL components suggests interaction with web content loading and security.
6. **Identify potential logical inferences and edge cases**:  Consider scenarios like relative URL resolution or handling of invalid URLs.
7. **Scan for error handling or security considerations**: Look for checks for valid protocols, URL syntax, or potential security vulnerabilities related to URL manipulation.
8. **Synthesize the findings into a concise summary of the file's functionality.**
这个 `kurl.cc` 文件是 Chromium Blink 引擎中用于处理和操作 URL（Uniform Resource Locator）的核心组件。它定义了 `KURL` 类，提供了创建、解析、修改和比较 URL 的功能。

**功能归纳:**

1. **URL 的表示和存储:** `KURL` 类用于表示一个 URL，它内部存储了 URL 字符串及其解析后的各个组成部分（协议、用户名、密码、主机、端口、路径、查询参数、片段标识符等）。

2. **URL 的创建和初始化:**  提供了多种构造函数来创建 `KURL` 对象，包括：
    * 从一个表示绝对 URL 的字符串创建。
    * 从一个 `GURL` 对象转换而来。
    * 基于一个基础 URL 和一个相对 URL 创建。
    * 基于一个基础 URL、相对 URL 和指定的字符编码创建（用于编码查询参数）。
    * 从预先解析的 URL 字符串和解析结果创建。

3. **URL 的解析:** `KURL` 内部使用了 Chromium 的 `url` 库进行 URL 的解析，将 URL 字符串分解成各个组成部分。

4. **URL 组成部分的访问:** 提供了各种方法来访问 URL 的各个组成部分，例如 `Protocol()`, `Host()`, `Port()`, `GetPath()`, `Query()`, `FragmentIdentifier()` 等。

5. **URL 组成部分的修改:** 提供了方法来修改 URL 的各个组成部分，例如 `SetProtocol()`, `SetHost()`, `SetPort()`, `SetPath()`, `SetQuery()`, `SetFragmentIdentifier()` 等。

6. **URL 的规范化:** 在创建和修改 URL 时，`KURL` 会进行 URL 的规范化处理，例如去除多余的斜杠、转换主机名到 Punycode（如果需要）等。

7. **URL 的比较:**  提供了比较两个 `KURL` 对象是否相等的方法，以及忽略片段标识符的比较方法。

8. **判断 URL 的属性:** 提供了判断 URL 各种属性的方法，例如 `IsValid()`（是否是有效 URL）, `IsLocalFile()`（是否是本地文件 URL）, `ProtocolIsJavaScript()`（是否是 JavaScript URL）, `IsAboutBlankURL()`, `IsAboutSrcdocURL()` 等。

9. **为特定用途剥离 URL 信息:**  提供了方法来获取适用于特定场景的 URL 变体，例如：
    * `UrlStrippedForUseAsReferrer()`:  移除用户名、密码和片段标识符，用于作为 Referer 请求头。
    * `StrippedForUseAsHref()`: 移除用户名和密码，用于作为 HTML 链接的 `href` 属性值。

10. **URL 的编码和解码:** 提供了 `DecodeURLEscapeSequences()` 和 `EncodeWithURLEscapeSequences()` 函数用于 URL 转义序列的解码和编码。

11. **处理特殊类型的 URL:**  定义了 `BlankURL()` 和 `SrcdocURL()` 函数来获取 `about:blank` 和 `about:srcdoc` 的 `KURL` 对象。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

* **JavaScript:**
    * 当 JavaScript 代码中访问 `window.location` 的属性（如 `window.location.href`, `window.location.protocol`, `window.location.host` 等）时，Blink 引擎会使用 `KURL` 对象来表示和操作当前的 URL。
    * 当 JavaScript 调用 `new URL(relativeURL, baseURL)` 或直接赋值给 `window.location.href` 时，Blink 引擎会使用 `KURL` 来解析和构建新的 URL。
    * 假设输入：JavaScript 代码 `window.location.href = 'https://example.com/path?query#frag';`，Blink 引擎会创建一个 `KURL` 对象，其各个组成部分会被解析并存储。输出：`kurl.cc` 中的 `KURL` 对象会包含协议 "https", 主机 "example.com", 路径 "/path", 查询参数 "query", 片段标识符 "frag"。
    * 常见错误：在 JavaScript 中赋值不合法的 URL 字符串给 `window.location.href`，例如 `window.location.href = 'invalidscheme://host';`，`KURL::SetProtocol()` 方法会尝试解析协议，如果解析失败会返回 `false`，但不会修改 URL。

* **HTML:**
    * HTML 元素的属性，如 `<a>` 标签的 `href` 属性，`<img>` 标签的 `src` 属性，`<form>` 标签的 `action` 属性等，其值都是 URL。Blink 引擎会使用 `KURL` 来解析和处理这些 URL。
    * 假设输入：HTML 代码 `<a href="/another-page">Link</a>`，当用户点击链接时，Blink 引擎会基于当前页面的 URL 和链接中的相对 URL `/another-page` 创建一个新的 `KURL` 对象。输出：如果当前页面是 `https://example.com/current-page`，那么新创建的 `KURL` 对象将是 `https://example.com/another-page`。
    * 常见错误：在 HTML 中提供格式错误的 URL，例如 `<img src="not a url">`，`KURL` 在解析时可能会将其标记为无效 (`isValid_` 为 `false`)。

* **CSS:**
    * CSS 的 `url()` 函数用于引用外部资源，如背景图片、字体文件等。Blink 引擎会使用 `KURL` 来解析和处理这些 URL。
    * 假设输入：CSS 样式 `body { background-image: url('images/bg.png'); }`，如果当前页面的 URL 是 `https://example.com/page.html`，Blink 引擎会创建一个 `KURL` 对象来表示背景图片的 URL。输出：该 `KURL` 对象将是 `https://example.com/images/bg.png`。
    * 常见错误：在 CSS 的 `url()` 函数中使用相对路径时，如果 CSS 文件本身是通过 `@import` 引入的，相对路径的解析可能会出现意想不到的结果。`KURL` 在解析相对 URL 时会依赖于基础 URL。

**逻辑推理的假设输入与输出:**

假设输入：一个基础 URL `https://example.com/path/` 和一个相对 URL `../another/page?q=test#hash`。
`KURL` 的相对 URL 解析逻辑会根据基础 URL 和相对 URL 计算出完整的 URL。
输出：`KURL` 对象表示的完整 URL 将是 `https://example.com/another/page?q=test#hash`。

假设输入：一个包含特殊字符的主机名 "ex--ample.com" 需要进行 IDNA 转换。
`KURL` 在创建或设置主机名时，会检测并进行 Punycode 编码。
输出：`KURL` 对象中存储的规范化主机名可能是 "xn--ex-ample-90a.com"。

**涉及用户或者编程常见的使用错误举例说明:**

1. **不正确的 URL 编码:** 用户或程序员可能手动构建 URL 时忘记或错误地进行 URL 编码，导致 URL 解析错误。例如，在查询参数中直接使用空格而不是 `%20`。`KURL` 在解析时可能会尝试纠正一些错误，但无法保证所有情况都能正确处理。

2. **混淆绝对 URL 和相对 URL:** 在需要绝对 URL 的地方提供了相对 URL，或者反之。这会导致资源加载失败或链接跳转错误。`KURL` 的相对 URL 解析功能依赖于正确的基础 URL。

3. **修改 URL 组件的顺序错误:** 程序员可能尝试先设置路径，然后再设置协议，这可能会导致解析错误或意外的行为。`KURL` 的内部状态在修改后会重新进行规范化。

4. **假设所有的 URL 都是有效的:** 程序员可能会直接使用 `KURL` 对象而不检查其 `IsValid()` 状态，导致程序在处理无效 URL 时出现异常。

5. **在设置端口时提供非数字字符串:**  `KURL::SetPort()` 会尝试将字符串转换为数字，如果转换失败则不会设置端口。

**总结 `kurl.cc` 的功能 (第 1 部分):**

总而言之，`blink/renderer/platform/weborigin/kurl.cc` 文件定义了 `KURL` 类，它是 Blink 引擎中用于处理和操作 URL 的核心抽象。它负责 URL 的创建、解析、规范化、修改、比较以及提供对 URL 各个组成部分的访问。`KURL` 与 JavaScript, HTML, CSS 等 Web 技术紧密相关，为这些技术提供了 URL 处理的基础能力，确保了 Web 内容的正确加载和交互。该文件还包含了对常见 URL 使用错误的防范和处理机制。

### 提示词
```
这是目录为blink/renderer/platform/weborigin/kurl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2007, 2008, 2011, 2012 Apple Inc. All rights reserved.
 * Copyright (C) 2012 Research In Motion Limited. All rights reserved.
 * Copyright (C) 2008, 2009, 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/weborigin/kurl.h"

#include <algorithm>
#include <string_view>

#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_statics.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/perfetto/include/perfetto/tracing/traced_value.h"
#include "url/gurl.h"
#include "url/url_constants.h"
#include "url/url_features.h"
#include "url/url_util.h"
#ifndef NDEBUG
#include <stdio.h>
#endif

namespace blink {

namespace {

#if DCHECK_IS_ON()
void AssertProtocolIsGood(const StringView protocol) {
  DCHECK(protocol != "");
  DCHECK(std::ranges::all_of(protocol.Span8(), [](const LChar c) {
    return c > ' ' && c < 0x7F && !(c >= 'A' && c <= 'Z');
  }));
}
#endif

// Note: You must ensure that |spec| is a valid canonicalized URL before calling
// this function.
const char* AsURLChar8Subtle(const String& spec) {
  DCHECK(spec.Is8Bit());
  // characters8 really return characters in Latin-1, but because we
  // canonicalize URL strings, we know that everything before the fragment
  // identifier will actually be ASCII, which means this cast is safe as long as
  // you don't look at the fragment component.
  return reinterpret_cast<const char*>(spec.Characters8());
}

// Returns the characters for the given string, or a pointer to a static empty
// string if the input string is null. This will always ensure we have a non-
// null character pointer since ReplaceComponents has special meaning for null.
const char* CharactersOrEmpty(const StringUTF8Adaptor& string) {
  static const char kZero = 0;
  return string.data() ? string.data() : &kZero;
}

bool IsSchemeFirstChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool IsSchemeChar(char c) {
  return IsSchemeFirstChar(c) || (c >= '0' && c <= '9') || c == '.' ||
         c == '-' || c == '+';
}

bool IsUnicodeEncoding(const WTF::TextEncoding* encoding) {
  return encoding->EncodingForFormSubmission() == UTF8Encoding();
}

class KURLCharsetConverter final : public url::CharsetConverter {
  DISALLOW_NEW();

 public:
  // The encoding parameter may be 0, but in this case the object must not be
  // called.
  explicit KURLCharsetConverter(const WTF::TextEncoding* encoding)
      : encoding_(encoding) {}

  void ConvertFromUTF16(std::u16string_view input,
                        url::CanonOutput* output) override {
    std::string encoded = encoding_->Encode(
        String(input), WTF::kURLEncodedEntitiesForUnencodables);
    output->Append(encoded);
  }

 private:
  raw_ptr<const WTF::TextEncoding> encoding_;
};

}  // namespace

bool IsValidProtocol(const String& protocol) {
  // RFC3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  if (protocol.empty())
    return false;
  if (!IsSchemeFirstChar(protocol[0]))
    return false;
  unsigned protocol_length = protocol.length();
  for (unsigned i = 1; i < protocol_length; i++) {
    if (!IsSchemeChar(protocol[i]))
      return false;
  }
  return true;
}

KURL KURL::UrlStrippedForUseAsReferrer() const {
  if (!SchemeRegistry::ShouldTreatURLSchemeAsAllowedForReferrer(Protocol()))
    return KURL();

  KURL referrer(*this);

  referrer.SetUser(String());
  referrer.SetPass(String());
  referrer.RemoveFragmentIdentifier();

  return referrer;
}

String KURL::StrippedForUseAsReferrer() const {
  return UrlStrippedForUseAsReferrer().GetString();
}

String KURL::StrippedForUseAsHref() const {
  if (parsed_.username.is_nonempty() || parsed_.password.is_nonempty()) {
    KURL href(*this);
    href.SetUser(String());
    href.SetPass(String());
    return href.GetString();
  }
  return GetString();
}

bool KURL::IsLocalFile() const {
  // Including feed here might be a bad idea since drag and drop uses this check
  // and including feed would allow feeds to potentially let someone's blog
  // read the contents of the clipboard on a drag, even without a drop.
  // Likewise with using the FrameLoader::shouldTreatURLAsLocal() function.
  return ProtocolIs(url::kFileScheme);
}

bool ProtocolIsJavaScript(const String& url) {
  return ProtocolIs(url, url::kJavaScriptScheme);
}

const KURL& BlankURL() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(KURL, blank_url,
                                  (AtomicString(url::kAboutBlankURL)));
  return blank_url;
}

const KURL& SrcdocURL() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(KURL, srcdoc_url,
                                  (AtomicString(url::kAboutSrcdocURL)));
  return srcdoc_url;
}

bool KURL::IsAboutURL(const char* allowed_path) const {
  if (!ProtocolIsAbout())
    return false;

  // Using `is_nonempty` for `host` and `is_valid` for `username` and `password`
  // to replicate how GURL::IsAboutURL (and GURL::has_host vs
  // GURL::has_username) works.
  if (parsed_.host.is_nonempty() || parsed_.username.is_valid() ||
      parsed_.password.is_valid() || HasPort()) {
    return false;
  }

  StringView path = ComponentStringView(parsed_.path);
  StringUTF8Adaptor path_utf8(path);
  return GURL::IsAboutPath(path_utf8.AsStringView(), allowed_path);
}

bool KURL::IsAboutBlankURL() const {
  return IsAboutURL(url::kAboutBlankPath);
}

bool KURL::IsAboutSrcdocURL() const {
  return IsAboutURL(url::kAboutSrcdocPath);
}

const KURL& NullURL() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(KURL, static_null_url, ());
  return static_null_url;
}

String KURL::ElidedString() const {
  const WTF::String& string = string_;
  if (string.length() <= 1024) {
    return string;
  }

  return string.Left(511) + "..." + string.Right(510);
}

KURL::KURL()
    : is_valid_(false),
      protocol_is_in_http_family_(false),
      has_idna2008_deviation_character_(false) {}

// Initializes with a string representing an absolute URL. No encoding
// information is specified. This generally happens when a KURL is converted
// to a string and then converted back. In this case, the URL is already
// canonical and in proper escaped form so needs no encoding. We treat it as
// UTF-8 just in case.
KURL::KURL(const String& url) {
  if (!url.IsNull()) {
    Init(NullURL(), url, nullptr);
    AssertStringSpecIsASCII();
  } else {
    // WebCore expects us to preserve the nullness of strings when this
    // constructor is used. In all other cases, it expects a non-null
    // empty string, which is what Init() will create.
    is_valid_ = false;
    protocol_is_in_http_family_ = false;
    has_idna2008_deviation_character_ = false;
  }
}

// Initializes with a GURL. This is used to covert from a GURL to a KURL.
KURL::KURL(const GURL& gurl) {
  Init(NullURL() /* base */, String(gurl.spec()) /* relative */,
       nullptr /* query_encoding */);
  AssertStringSpecIsASCII();
}

// Constructs a new URL given a base URL and a possibly relative input URL.
// This assumes UTF-8 encoding.
KURL::KURL(const KURL& base, const String& relative) {
  Init(base, relative, nullptr);
  AssertStringSpecIsASCII();
}

// Constructs a new URL given a base URL and a possibly relative input URL.
// Any query portion of the relative URL will be encoded in the given encoding.
KURL::KURL(const KURL& base,
           const String& relative,
           const WTF::TextEncoding& encoding) {
  Init(base, relative, &encoding.EncodingForFormSubmission());
  AssertStringSpecIsASCII();
}

KURL::KURL(const AtomicString& canonical_string,
           const url::Parsed& parsed,
           bool is_valid)
    : is_valid_(is_valid),
      protocol_is_in_http_family_(false),
      has_idna2008_deviation_character_(false),
      parsed_(parsed),
      string_(canonical_string) {
  InitProtocolMetadata();
  InitInnerURL();
  // For URLs with non-ASCII hostnames canonical_string will be in punycode.
  // We can't check has_idna2008_deviation_character_ without decoding punycode.
  // here.
  AssertStringSpecIsASCII();
}

KURL::KURL(const KURL& other)
    : is_valid_(other.is_valid_),
      protocol_is_in_http_family_(other.protocol_is_in_http_family_),
      has_idna2008_deviation_character_(
          other.has_idna2008_deviation_character_),
      protocol_(other.protocol_),
      parsed_(other.parsed_),
      string_(other.string_) {
  if (other.inner_url_.get())
    inner_url_ = std::make_unique<KURL>(*other.inner_url_);
}

KURL::~KURL() = default;

KURL& KURL::operator=(const KURL& other) {
  is_valid_ = other.is_valid_;
  protocol_is_in_http_family_ = other.protocol_is_in_http_family_;
  has_idna2008_deviation_character_ = other.has_idna2008_deviation_character_;
  protocol_ = other.protocol_;
  parsed_ = other.parsed_;
  string_ = other.string_;
  if (other.inner_url_)
    inner_url_ = std::make_unique<KURL>(*other.inner_url_);
  else
    inner_url_.reset();
  return *this;
}

bool KURL::IsNull() const {
  return string_.IsNull();
}

bool KURL::IsEmpty() const {
  return string_.empty();
}

bool KURL::IsValid() const {
  return is_valid_;
}

bool KURL::HasPort() const {
  return HostEnd() < PathStart();
}

bool KURL::ProtocolIsJavaScript() const {
  return ComponentStringView(parsed_.scheme) == url::kJavaScriptScheme;
}

bool KURL::ProtocolIsInHTTPFamily() const {
  return protocol_is_in_http_family_;
}

bool KURL::HasIDNA2008DeviationCharacter() const {
  return has_idna2008_deviation_character_;
}

bool KURL::HasPath() const {
  // Note that http://www.google.com/" has a path, the path is "/". This can
  // return false only for invalid or nonstandard URLs.
  return parsed_.path.is_valid();
}

StringView KURL::LastPathComponent() const {
  if (!is_valid_) {
    return StringViewForInvalidComponent();
  }
  DCHECK(!string_.IsNull());

  // When the output ends in a slash, WebCore has different expectations than
  // the GoogleURL library. For "/foo/bar/" the library will return the empty
  // string, but WebCore wants "bar".
  url::Component path = parsed_.path;
  if (path.is_nonempty() && string_[path.end() - 1] == '/')
    path.len--;

  url::Component file;
  if (string_.Is8Bit()) {
    url::ExtractFileName(AsURLChar8Subtle(string_), path, &file);
  } else {
    url::ExtractFileName(string_.Characters16(), path, &file);
  }

  // Bug: https://bugs.webkit.org/show_bug.cgi?id=21015 this function returns
  // a null string when the path is empty, which we duplicate here.
  if (file.is_empty()) {
    return StringView();
  }
  return ComponentStringView(file);
}

String KURL::Protocol() const {
  DCHECK_EQ(ComponentString(parsed_.scheme), protocol_);
  return protocol_;
}

StringView KURL::Host() const {
  return ComponentStringView(parsed_.host);
}

uint16_t KURL::Port() const {
  if (!is_valid_ || parsed_.port.is_empty())
    return 0;
  DCHECK(!string_.IsNull());
  int port = string_.Is8Bit()
                 ? url::ParsePort(AsURLChar8Subtle(string_), parsed_.port)
                 : url::ParsePort(string_.Characters16(), parsed_.port);
  DCHECK_NE(port, url::PORT_UNSPECIFIED);  // Checked port.len <= 0 already.
  DCHECK_NE(port, url::PORT_INVALID);      // Checked is_valid_ already.

  return static_cast<uint16_t>(port);
}

StringView KURL::Pass() const {
  if (!parsed_.password.is_valid()) {
    return StringView();
  }

  return ComponentStringView(parsed_.password);
}

StringView KURL::User() const {
  if (!parsed_.username.is_valid()) {
    return StringView();
  }
  return ComponentStringView(parsed_.username);
}

StringView KURL::FragmentIdentifier() const {
  // Empty but present refs ("foo.com/bar#") should result in the empty
  // string, which ComponentStringView will produce. Nonexistent refs
  // should be the null string.
  if (!parsed_.ref.is_valid()) {
    return StringView();
  }
  return ComponentStringView(parsed_.ref);
}

StringView KURL::FragmentIdentifierWithLeadingNumberSign() const {
  if (!parsed_.ref.is_valid()) {
    return StringView();
  }
  if (!is_valid_ || parsed_.ref.is_empty()) {
    return StringViewForInvalidComponent();
  }
  return StringView(GetString(), parsed_.ref.begin - 1, parsed_.ref.len + 1);
}

bool KURL::HasFragmentIdentifier() const {
  return parsed_.ref.is_valid();
}

StringView KURL::BaseAsString() const {
  return StringView(string_.GetString(), 0, PathAfterLastSlash());
}

StringView KURL::Query() const {
  if (!parsed_.query.is_valid()) {
    return StringView();
  }
  return ComponentStringView(parsed_.query);
}

StringView KURL::QueryWithLeadingQuestionMark() const {
  if (!parsed_.query.is_valid()) {
    return StringView();
  }
  if (!is_valid_ || parsed_.query.is_empty()) {
    return StringViewForInvalidComponent();
  }
  return StringView(GetString(), parsed_.query.begin - 1,
                    parsed_.query.len + 1);
}

StringView KURL::GetPath() const {
  return ComponentStringView(parsed_.path);
}

namespace {

bool IsASCIITabOrNewline(UChar ch) {
  return ch == '\t' || ch == '\r' || ch == '\n';
}

// See https://url.spec.whatwg.org/#concept-basic-url-parser:
// 3. Remove all ASCII tab or newline from |input|.
//
// Matches url::RemoveURLWhitespace.
String RemoveURLWhitespace(const String& input) {
  return input.RemoveCharacters(IsASCIITabOrNewline);
}

}  // namespace

bool KURL::SetProtocol(const String& protocol) {
  // We should remove whitespace from |protocol| according to spec, but Firefox
  // and Safari don't do it.
  // - https://url.spec.whatwg.org/#dom-url-protocol
  // - https://github.com/whatwg/url/issues/609

  // Firefox and IE remove everything after the first ':'.
  wtf_size_t separator_position = protocol.find(':');
  String new_protocol = protocol.Substring(0, separator_position);
  StringUTF8Adaptor new_protocol_utf8(new_protocol);

  // If KURL is given an invalid scheme, it returns failure without modifying
  // the URL at all. This is in contrast to most other setters which modify
  // the URL and set "m_isValid."
  url::RawCanonOutputT<char> canon_protocol;
  url::Component protocol_component;
  if (!url::CanonicalizeScheme(new_protocol_utf8.data(),
                               url::Component(0, new_protocol_utf8.size()),
                               &canon_protocol, &protocol_component) ||
      protocol_component.is_empty())
    return false;

  DCHECK_EQ(protocol_component.begin, 0);
  const wtf_size_t protocol_length =
      base::checked_cast<wtf_size_t>(protocol_component.len);
  const String new_protocol_canon =
      String(base::span(canon_protocol.view()).first(protocol_length));

  if (SchemeRegistry::IsSpecialScheme(Protocol())) {
    // https://url.spec.whatwg.org/#scheme-state
    // 2.1.1 If url’s scheme is a special scheme and buffer is not a special
    //       scheme, then return.
    if (!SchemeRegistry::IsSpecialScheme(new_protocol_canon)) {
      return true;
    }

    // The protocol is lower-cased during canonicalization.
    const bool new_protocol_is_file = new_protocol_canon == url::kFileScheme;
    const bool old_protocol_is_file = ProtocolIs(url::kFileScheme);

    // https://url.spec.whatwg.org/#scheme-state
    // 3. If url includes credentials or has a non-null port, and buffer is
    //    "file", then return.
    if (new_protocol_is_file && !old_protocol_is_file &&
        (HasPort() || parsed_.username.is_nonempty() ||
         parsed_.password.is_nonempty())) {
      // This fails silently, which is weird, but necessary to give the expected
      // behaviour when setting location.protocol. See
      // https://html.spec.whatwg.org/multipage/history.html#dom-location-protocol.
      return true;
    }

    // 4. If url’s scheme is "file" and its host is an empty host, then return.
    if (!new_protocol_is_file && old_protocol_is_file &&
        parsed_.host.is_empty()) {
      // This fails silently as above.
      return true;
    }
  }

  url::Replacements<char> replacements;
  replacements.SetScheme(CharactersOrEmpty(new_protocol_utf8),
                         url::Component(0, new_protocol_utf8.size()));
  ReplaceComponents(replacements);

  // isValid could be false but we still return true here. This is because
  // WebCore or JS scripts can build up a URL by setting individual
  // components, and a JS exception is based on the return value of this
  // function. We want to throw the exception and stop the script only when
  // its trying to set a bad protocol, and not when it maybe just hasn't
  // finished building up its final scheme.
  return true;
}

namespace {

String ParsePortFromStringPosition(const String& value, unsigned port_start) {
  // "008080junk" needs to be treated as port "8080" and "000" as "0".
  size_t length = value.length();
  unsigned port_end = port_start;
  while (IsASCIIDigit(value[port_end]) && port_end < length)
    ++port_end;
  while (value[port_start] == '0' && port_start < port_end - 1)
    ++port_start;

  return value.Substring(port_start, port_end - port_start);
}

// Align with https://url.spec.whatwg.org/#host-state step 3, and also with the
// IsAuthorityTerminator() function in //url/third_party/mozilla/url_parse.cc.
bool IsEndOfHost(UChar ch) {
  return ch == '/' || ch == '?' || ch == '#';
}

bool IsEndOfHostSpecial(UChar ch) {
  return IsEndOfHost(ch) || ch == '\\';
}

wtf_size_t FindHostEnd(const String& host, bool is_special) {
  wtf_size_t end = host.Find(is_special ? IsEndOfHostSpecial : IsEndOfHost);
  if (end == kNotFound)
    end = host.length();
  return end;
}

}  // namespace

void KURL::SetHost(const String& input) {
  String host = RemoveURLWhitespace(input);
  wtf_size_t value_end = FindHostEnd(host, IsStandard());
  String truncated_host = host.Substring(0, value_end);
  StringUTF8Adaptor host_utf8(truncated_host);
  url::Replacements<char> replacements;
  replacements.SetHost(CharactersOrEmpty(host_utf8),
                       url::Component(0, host_utf8.size()));
  ReplaceComponents(replacements);
}

void KURL::SetHostAndPort(const String& input) {
  // This method intentionally does very sloppy parsing for backwards
  // compatibility. See https://url.spec.whatwg.org/#host-state for what we
  // theoretically should be doing.

  String orig_host_and_port = RemoveURLWhitespace(input);
  wtf_size_t value_end = FindHostEnd(orig_host_and_port, IsStandard());
  String host_and_port = orig_host_and_port.Substring(0, value_end);

  // This logic for handling IPv6 addresses is adapted from ParseServerInfo in
  // //url/third_party/mozilla/url_parse.cc. There's a slight behaviour
  // difference for compatibility with the tests: the first colon after the
  // address is considered to start the port, instead of the last.
  wtf_size_t ipv6_terminator = host_and_port.ReverseFind(']');
  if (ipv6_terminator == kNotFound) {
    ipv6_terminator =
        host_and_port.StartsWith('[') ? host_and_port.length() : 0;
  }

  wtf_size_t colon = host_and_port.find(':', ipv6_terminator);

  // Legacy behavior: ignore input if host part is empty
  if (colon == 0)
    return;

  String host;
  String port;
  if (colon == kNotFound) {
    host = host_and_port;
  } else {
    host = host_and_port.Substring(0, colon);
    port = ParsePortFromStringPosition(host_and_port, colon + 1);
  }

  // Replace host and port separately in order to maintain the original port if
  // a valid host and invalid port are provided together.

  // Replace host first.
  {
    url::Replacements<char> replacements;
    StringUTF8Adaptor host_utf8(host);
    replacements.SetHost(CharactersOrEmpty(host_utf8),
                         url::Component(0, host_utf8.size()));
    ReplaceComponents(replacements);
  }

  // Replace port next.
  if (is_valid_ && !port.empty()) {
    url::Replacements<char> replacements;
    StringUTF8Adaptor port_utf8(port);
    replacements.SetPort(CharactersOrEmpty(port_utf8),
                         url::Component(0, port_utf8.size()));
    ReplaceComponents(replacements, /*preserve_validity=*/true);
  }
}

void KURL::RemovePort() {
  if (!HasPort())
    return;
  url::Replacements<char> replacements;
  replacements.ClearPort();
  ReplaceComponents(replacements);
}

void KURL::SetPort(const String& input) {
  String port = RemoveURLWhitespace(input);
  String parsed_port = ParsePortFromStringPosition(port, 0);
  if (parsed_port.empty()) {
    return;
  }
  bool to_uint_ok;
  unsigned port_value = parsed_port.ToUInt(&to_uint_ok);
  if (port_value > UINT16_MAX || !to_uint_ok) {
    return;
  }
  SetPort(port_value);
}

void KURL::SetPort(uint16_t port) {
  if (IsDefaultPortForProtocol(port, Protocol())) {
    RemovePort();
    return;
  }

  String port_string = String::Number(port);
  DCHECK(port_string.Is8Bit());

  url::Replacements<char> replacements;
  replacements.SetPort(reinterpret_cast<const char*>(port_string.Characters8()),
                       url::Component(0, port_string.length()));
  ReplaceComponents(replacements);
}

void KURL::SetUser(const String& user) {
  // This function is commonly called to clear the username, which we
  // normally don't have, so we optimize this case.
  if (user.empty() && !parsed_.username.is_valid())
    return;

  // The canonicalizer will clear any usernames that are empty, so we
  // don't have to explicitly call ClearUsername() here.
  //
  // Unlike other setters, we do not remove whitespace per spec:
  // https://url.spec.whatwg.org/#dom-url-username
  StringUTF8Adaptor user_utf8(user);
  url::Replacements<char> replacements;
  replacements.SetUsername(CharactersOrEmpty(user_utf8),
                           url::Component(0, user_utf8.size()));
  ReplaceComponents(replacements);
}

void KURL::SetPass(const String& pass) {
  // This function is commonly called to clear the password, which we
  // normally don't have, so we optimize this case.
  if (pass.empty() && !parsed_.password.is_valid())
    return;

  // The canonicalizer will clear any passwords that are empty, so we
  // don't have to explicitly call ClearUsername() here.
  //
  // Unlike other setters, we do not remove whitespace per spec:
  // https://url.spec.whatwg.org/#dom-url-password
  StringUTF8Adaptor pass_utf8(pass);
  url::Replacements<char> replacements;
  replacements.SetPassword(CharactersOrEmpty(pass_utf8),
                           url::Component(0, pass_utf8.size()));
  ReplaceComponents(replacements);
}

void KURL::SetFragmentIdentifier(const String& input) {
  // This function is commonly called to clear the ref, which we
  // normally don't have, so we optimize this case.
  if (input.IsNull() && !parsed_.ref.is_valid())
    return;

  String fragment = RemoveURLWhitespace(input);
  StringUTF8Adaptor fragment_utf8(fragment);

  url::Replacements<char> replacements;
  if (fragment.IsNull()) {
    replacements.ClearRef();
  } else {
    replacements.SetRef(CharactersOrEmpty(fragment_utf8),
                        url::Component(0, fragment_utf8.size()));
  }
  ReplaceComponents(replacements);
}

void KURL::RemoveFragmentIdentifier() {
  url::Replacements<char> replacements;
  replacements.ClearRef();
  ReplaceComponents(replacements);
}

void KURL::SetQuery(const String& input) {
  String query = RemoveURLWhitespace(input);
  StringUTF8Adaptor query_utf8(query);
  url::Replacements<char> replacements;
  if (query.IsNull()) {
    // KURL.cpp sets to null to clear any query.
    replacements.ClearQuery();
  } else if (query.length() > 0 && query[0] == '?') {
    // WebCore expects the query string to begin with a question mark, but
    // GoogleURL doesn't. So we trim off the question mark when setting.
    replacements.SetQuery(CharactersOrEmpty(query_utf8),
                          url::Component(1, query_utf8.size() - 1));
  } else {
    // When set with the empty string or something that doesn't begin with
    // a question mark, KURL.cpp will add a question mark for you. The only
    // way this isn't compatible is if you call this function with an empty
    // string. KURL.cpp will leave a '?' with nothing following it in the
    // URL, whereas we'll clear it.
    // FIXME We should eliminate this difference.
    replacements.SetQuery(CharactersOrEmpty(query_utf8),
                          url::Component(0, query_utf8.size()));
  }
  ReplaceComponents(replacements);
}

void KURL::SetPath(const String& input) {
  // Empty paths will be canonicalized to "/", so we don't have to worry
  // about calling ClearPath().
  String path = RemoveURLWhitespace(input);
  StringUTF8Adaptor path_utf8(path);
  url::Replacements<char> replacements;
  replacements.SetPath(CharactersOrEmpty(path_utf8),
                       url::Component(0, path_utf8.size()));
  ReplaceComponents(replacements);
}

String DecodeURLEscapeSequences(const StringView& string, DecodeURLMode mode) {
  StringUTF8Adaptor string_utf8(string);
  url::RawCanonOutputT<char16_t> unescaped;
  url::DecodeURLEscapeSequences(string_utf8.AsStringView(), mode, &unescaped);
  return StringImpl::Create8BitIfPossible(unescaped.view());
}

String EncodeWithURLEscapeSequences(const StringView& not_encoded_string) {
  std::string utf8 =
      UTF8Encoding().Encode(not_encoded_string, WTF::kNoUnencodables);

  url::RawCanonOutputT<char> buffer;
  size_t input_length = utf8.length();
  if (buffer.capacity() < input_length * 3)
    buffer.Resize(input_length * 3);

  url::EncodeURIComponent(utf8, &buffer);
  String escaped(base::span(buffer.view()));
  // Unescape '/'; it's safe and much prettier.
  escaped.Replace("%2F", "/");
  return escaped;
}

bool HasInvalidURLEscapeSequences(const String& string) {
  StringUTF8Adaptor string_utf8(string);
  return url::HasInvalidURLEscapeSequences(string_utf8.AsStringView());
}

bool KURL::CanSetHostOrPort() const {
  return IsHierarchical();
}

bool KURL::CanSetPathname() const {
  return IsHierarchical();
}

bool KURL::CanRemoveHost() const {
  if (url::IsUsingStandardCompliantNonSpecialSchemeURLParsing()) {
    return IsHierarchical() && !IncludesCredentials() && !HasPort();
  }
  return false;
}

bool KURL::IsHierarchical() const {
  if (url::IsUsingStandardCompliantNonSpecialSchemeURLParsing()) {
    return IsStandard() || (IsValid() && !HasOpaquePath());
  }
  return IsStandard();
}

bool KURL::IsStandard() const {
  if (string_.IsNull() || parsed_.scheme.is_empty())
    return false;
  return string_.Is8Bit()
             ? url::IsStandard(AsURLChar8Subtle(string_), parsed_.scheme)
             : url::IsStandard(string_.Characters16(), parsed_.scheme);
}

bool EqualIgnoringFragmentIdentifier(const KURL& a, const KURL& b) {
  // Compute the length of each URL without its ref. Note that the reference
  // begin (if it exists) points to the character *after* the '#', so we need
  // to subtract one.
  int a_length = a.string_.length();
  if (a.parsed_.ref.is_valid())
    a_length = a.parsed_.ref.begin - 1;

  int b_length = b.string_.length();
  if (b.parsed_.ref.is_valid())
    b_length = b.parsed_.ref.begin - 1;

  if (a_length != b_length)
    return false;

  const String& a_string = a.string_;
  const String& b_string = b.string_;
  // FIXME: Abstraction this into a function in WTFString.h.
  for (int i = 0; i < a_length; ++i) {
    if (a_string[i] != b_string[i])
      return false;
  }
  return true;
}

unsigned KURL::HostStart() const {
  return parsed_.CountCharactersBefore(url::Parsed::HOST, false);
}

unsigned KURL::HostEnd() const {
  return parsed_.CountCharactersBefore(url::Parsed::PORT, true);
}

unsigned KURL::PathStart() const {
  return parsed_.CountCharactersBefore(url::Parsed::PATH, false);
}

unsigned KURL::PathEnd() const {
  return parsed_.CountCharactersBefore(url::Parsed::QUERY, true);
}

unsigned KURL::PathAfterLastSlash() const {
  if (string_.IsNull())
    return 0;
  if (!is_valid_ || !parsed_.path.is_valid())
    return parsed_.CountCharactersBefore(url::Parsed::PATH, false);
  url::Component filename;
  if (string_.Is8Bit()) {
    url::ExtractFileName(AsURLChar8Subtle(string_), parsed_.path, &filename);
  } else {
    url::ExtractFileName(string_.Characters16(), parsed_.path, &filename);
  }
  return filename.begin;
}

bool ProtocolIs(const String& url, const char* protocol) {
#if DCHECK_IS_ON()
  AssertProtocolIsGood(protocol);
#endif
  if (url.IsNull())
    return false;
  if (url.Is8Bit()) {
    return url::FindAndCompareScheme(AsURLChar8Subtle(url), url.length(),
                                     protocol, nullptr);
  }
  return url::FindAndCompareScheme(url.Characters16(), url.length(), protocol,
                                   nullptr);
}

void KURL::Init(const KURL& base,
                const String& relative,
                const WTF::TextEncoding* query_encoding) {
  // As a performance optimization, we do not use the charset converter
  // if encoding is UTF-8 or other Unicode encodings. Note that this is
  // per HTML5 2.5.3 (resolving URL). The URL canonicalizer will be more
  // efficient with no charset converter object because it can do UTF-8
  // internally with no extra copies.

  StringUTF8Adaptor base_utf8(base.GetString());

  // We feel free to make the charset converter object every time since it's
  // just a wrapper around a reference.
  KURLCharsetConverter charset_converter_object(query_encoding);
  KURLCharsetConverter* charset_converter =
      (!query_encoding || IsUnicodeEncoding(query_encoding))
          ? nullptr
          : &charset_converter_object;

  // Clamp to int max to avoid overflow.
  url::RawCanonOutputT<char> output;
  if (!relative.IsNull() && relative.Is8Bit()) {
    StringUTF8Adaptor relative_utf8(relative);
    is_valid_ = url::ResolveRelative(base_utf8.data(), base_utf8.size(),
                                     base.parsed_, relative_utf8.data(),
                                     ClampTo<int>(relative_utf8.size()),
                                     charset_converter, &output, &parsed_);
  } else {
    is_valid_ = url::ResolveRelative(base_utf8.data(), base_utf8.size(),
                                     base.parsed_, relative.Characters16(),
                                     ClampTo<int>(relative.length()),
                                     charset_converter, &output, &parsed_);
  }

  // Constructing an AtomicString will re-hash the raw output and check the
  // AtomicStringTable (addWithTranslator) for the string. This can be very
  // expensive for large URLs. However, since many URLs are generated from
  // existing AtomicStrings (which already have their hashes computed), the fast
  // path can often avoid this work.
  const auto output_url_span = base::as_byte_span(output.view());
  if (!relative.IsNull() && StringView(output_url_span) == relative) {
    string_ = AtomicString(relative.Impl());
  } else {
    string_ = AtomicString(output_url_span);
  }

  InitProtocolMetadata();
  InitInnerURL();
  AssertStringSpecIsASCII();

  if (!url::IsUsingStandardCompliantNonSpecialSchemeURLParsing()) {
    // This assertion implicitly assumes that "jav
```