Response:
The user wants to understand the functionality of the `url_pattern.cc` file in the Chromium Blink engine. I need to analyze the code and identify its core responsibilities. The request also asks for connections to JavaScript, HTML, and CSS, example inputs and outputs for logical inferences, common usage errors, and debugging steps. Finally, I need to summarize the functionality in this first part of the response.

**Plan:**

1. **Identify Core Functionality:** Analyze the included headers, namespaces, classes, and methods to determine the primary purpose of the file. It seems related to matching URLs against patterns.
2. **Relationship to Web Technologies:**  Look for interactions with concepts related to JavaScript (V8 bindings), HTML (URLs, structure), and CSS (less likely, but I'll keep it in mind).
3. **Logical Reasoning:** Identify functions that perform transformations or comparisons based on input, and create hypothetical input/output scenarios.
4. **Common Errors:**  Think about how developers might misuse the `URLPattern` API based on the available methods and parameters.
5. **User Operations:**  Trace back how a user's action in a browser could lead to the execution of this code.
6. **Summarize Functionality:** Condense the findings into a concise description.
```
URLPattern::URLPattern(Component* protocol,
                       Component* username,
                       Component* password,
                       Component* hostname,
                       Component* port,
                       Component* pathname,
                       Component* search,
                       Component* hash,
                       Options options,
                       base::PassKey<URLPattern> key)
    : protocol_(protocol),
      username_(username),
      password_(password),
      hostname_(hostname),
      port_(port),
      pathname_(pathname),
      search_(search),
      hash_(hash),
      options_(options) {}

bool URLPattern::test(ScriptState* script_state,
                      const V8URLPatternInput* input,
                      const String& base_url,
                      ExceptionState& exception_state) const {
  return Match(script_state, input, base_url, /*result=*/nullptr,
               exception_state);
}

bool URLPattern::test(ScriptState* script_state,
                      const V8URLPatternInput* input,
                      ExceptionState& exception_state) const {
  return test(script_state, input, /*base_url=*/String(), exception_state);
}

URLPatternResult* URLPattern::exec(ScriptState* script_state,
                                   const V8URLPatternInput* input,
                                   const String& base_url,
                                   ExceptionState& exception_state) const {
  URLPatternResult* result = URLPatternResult::Create();
  if (!Match(script_state, input, base_url, result, exception_state))
    return nullptr;
  return result;
}

URLPatternResult* URLPattern::exec(ScriptState* script_state,
                                   const V8URLPatternInput* input,
                                   ExceptionState& exception_state) const {
  return exec(script_state, input, /*base_url=*/String(), exception_state);
}

String URLPattern::protocol() const {
  return protocol_->GeneratePatternString();
}

String URLPattern::username() const {
  return username_->GeneratePatternString();
}

String URLPattern::password() const {
  return password_->GeneratePatternString();
}

String URLPattern::hostname() const {
  return hostname_->GeneratePatternString();
}

String URLPattern::port() const {
  return port_->GeneratePatternString();
}

String URLPattern::pathname() const {
  return pathname_->GeneratePatternString();
}

String URLPattern::search() const {
  return search_->GeneratePatternString();
}

String URLPattern::hash() const {
  return hash_->GeneratePatternString();
}

bool URLPattern::hasRegExpGroups() const {
  const url_pattern::Component* components[] = {protocol_, username_, password_,
                                                hostname_, port_,     pathname_,
                                                search_,   hash_};
  return base::ranges::any_of(components,
                              &url_pattern::Component::HasRegExpGroups);
}

// static
int URLPattern::compareComponent(const V8URLPatternComponent& component,
                                 const URLPattern* left,
                                 const URLPattern* right) {
  switch (component.AsEnum()) {
    case V8URLPatternComponent::Enum::kProtocol:
      return url_pattern::Component::Compare(*left->protocol_,
                                             *right->protocol_);
    case V8URLPatternComponent::Enum::kUsername:
      return url_pattern::Component::Compare(*left->username_,
                                             *right->username_);
    case V8URLPatternComponent::Enum::kPassword:
      return url_pattern::Component::Compare(*left->password_,
                                             *right->password_);
    case V8URLPatternComponent::Enum::kHostname:
      return url_pattern::Component::Compare(*left->hostname_,
                                             *right->hostname_);
    case V8URLPatternComponent::Enum::kPort:
      return url_pattern::Component::Compare(*left->port_, *right->port_);
    case V8URLPatternComponent::Enum::kPathname:
      return url_pattern::Component::Compare(*left->pathname_,
                                             *right->pathname_);
    case V8URLPatternComponent::Enum::kSearch:
      return url_pattern::Component::Compare(*left->search_, *right->search_);
    case V8URLPatternComponent::Enum::kHash:
      return url_pattern::Component::Compare(*left->hash_, *right->hash_);
  }
  NOTREACHED();
}

std::optional<SafeUrlPattern> URLPattern::ToSafeUrlPattern(
    ExceptionState& exception_state) const {
  const std::pair<const url_pattern::Component*, const char*>
      components_with_names[] = {
          {protocol_, "protocol"}, {username_, "username"},
          {password_, "password"}, {hostname_, "hostname"},
          {port_, "port"},         {pathname_, "pathname"},
          {search_, "search"},     {hash_, "hash"}};
  String components_with_regexp;
  for (auto [component, name] : components_with_names) {
    if (component->HasRegExpGroups()) {
      components_with_regexp = components_with_regexp +
                               (components_with_regexp.IsNull() ? "" : ", ") +
                               name + " (" +
                               component->GeneratePatternString() + ")";
    }
  }
  if (!components_with_regexp.IsNull()) {
    exception_state.ThrowTypeError(
        "The pattern cannot contain regexp groups, but did in the following "
        "components: " +
        components_with_regexp);
    return std::nullopt;
  }

  SafeUrlPattern safe_pattern;
  if (protocol_)
    safe_pattern.SetProtocol(protocol_->pattern());
  if (username_)
    safe_pattern.SetUsername(username_->pattern());
  if (password_)
    safe_pattern.SetPassword(password_->pattern());
  if (hostname_)
    safe_pattern.SetHostname(hostname_->pattern());
  if (port_)
    safe_pattern.SetPort(port_->pattern());
  if (pathname_)
    safe_pattern.SetPathname(pathname_->pattern());
  if (search_)
    safe_pattern.SetSearch(search_->pattern());
  if (hash_)
    safe_pattern.SetHash(hash_->pattern());

  return safe_pattern;
}

bool URLPattern::Match(ScriptState* script_state,
                       const V8URLPatternInput* input,
                       const String& base_url,
                       URLPatternResult* result,
                       ExceptionState& exception_state) const {
  KURL url;
  if (input->GetContentType() == V8URLPatternInput::ContentType::kUSVString) {
    url = KURL(NullURL(), input->GetAsUSVString());
    if (!url.IsValid()) {
      exception_state.ThrowTypeError("Invalid URL '" + input->GetAsUSVString() +
                                     "'.");
      return false;
    }
  } else {
    const URLPatternInit* init = input->GetAsURLPatternInit();
    String protocol;
    String username;
    String password;
    String hostname;
    String port;
    String pathname;
    String search;
    String hash;

    ApplyInit(init, ValueType::kURL, protocol, username, password, hostname, port,
              pathname, search, hash, exception_state);
    if (exception_state.HadException())
      return false;

    StringBuilder builder;
    if (!protocol.IsNull()) {
      builder.Append(protocol);
      builder.AppendLiteral("://");
    }
    if (!username.IsNull()) {
      builder.Append(username);
      if (!password.IsNull()) {
        builder.AppendLiteral(":");
        builder.Append(password);
      }
      builder.AppendLiteral("@");
    }
    if (!hostname.IsNull())
      builder.Append(hostname);
    if (!port.IsNull()) {
      builder.AppendLiteral(":");
      builder.Append(port);
    }
    if (!pathname.IsNull())
      builder.Append(pathname);
    if (!search.IsNull()) {
      builder.AppendLiteral("?");
      builder.Append(search);
    }
    if (!hash.IsNull()) {
      builder.AppendLiteral("#");
      builder.Append(hash);
    }
    url = KURL(NullURL(), builder.ToString());
  }

  // Extract the component strings to match against.
  String protocol = url.Protocol();
  String username = url.User();
  String password = url.Pass();
  String host = url.Host();
  String port = String::Number(url.Port());
  String pathname = url.GetPath();
  String search = url.Query();
  String hash = url.FragmentIdentifier();

  // Perform the component pattern matching.
  bool matched_protocol = protocol_->Match(script_state, protocol);
  bool matched_username = username_->Match(script_state, username);
  bool matched_password = password_->Match(script_state, password);
  bool matched_hostname = hostname_->Match(script_state, host);
  bool matched_port = port_->Match(script_state, port);
  bool matched_pathname = pathname_->Match(script_state, pathname);
  bool matched_search = search_->Match(script_state, search);
  bool matched_hash = hash_->Match(script_state, hash);

  const bool overall_match =
      matched_protocol && matched_username && matched_password &&
      matched_hostname && matched_port && matched_pathname && matched_search &&
      matched_hash;

  if (result && overall_match) {
    result->setProtocolResult(MakeURLPatternComponentResult(
        script_state, protocol, protocol_->MatchGroups()));
    result->setUsernameResult(MakeURLPatternComponentResult(
        script_state, username, username_->MatchGroups()));
    result->setPasswordResult(MakeURLPatternComponentResult(
        script_state, password, password_->MatchGroups()));
    result->setHostnameResult(
        MakeURLPatternComponentResult(script_state, host, hostname_->MatchGroups()));
    result->setPortResult(
        MakeURLPatternComponentResult(script_state, port, port_->MatchGroups()));
    result->setPathnameResult(MakeURLPatternComponentResult(
        script_state, pathname, pathname_->MatchGroups()));
    result->setSearchResult(
        MakeURLPatternComponentResult(script_state, search, search_->MatchGroups()));
    result->setHashResult(
        MakeURLPatternComponentResult(script_state, hash, hash_->MatchGroups()));
  }

  return overall_match;
}

}  // namespace blink
```

### 功能列举

`blink/renderer/core/url_pattern/url_pattern.cc` 文件的主要功能是实现 **URL 模式匹配**。它提供了一种机制，用于将 URL 与定义的模式进行匹配，并可以提取匹配到的 URL 组件中的分组信息。 具体来说，该文件实现了 `URLPattern` 类，该类允许：

1. **创建 URL 模式:**  可以通过传入一个字符串或者一个包含各个 URL 组件的初始化对象 (`URLPatternInit`) 来创建 `URLPattern` 对象。模式字符串可以包含通配符和正则表达式。
2. **匹配 URL:**  使用 `test()` 方法检查给定的 URL 是否与该模式匹配。
3. **执行匹配并提取结果:** 使用 `exec()` 方法执行匹配，如果匹配成功，则返回一个 `URLPatternResult` 对象，其中包含匹配的各个 URL 组件以及正则表达式分组捕获的值。
4. **获取模式组件:**  提供方法 (`protocol()`, `username()`, `password()`, `hostname()`, `port()`, `pathname()`, `search()`, `hash()`) 来获取组成 URL 模式的各个组件的模式字符串。
5. **判断是否包含正则表达式组:**  使用 `hasRegExpGroups()` 方法判断模式的任何组件是否包含正则表达式分组。
6. **比较 URL 模式组件:**  提供静态方法 `compareComponent()` 用于比较两个 `URLPattern` 对象的指定组件。
7. **转换为安全 URL 模式:**  提供 `ToSafeUrlPattern()` 方法将 `URLPattern` 对象转换为 `SafeUrlPattern` 对象，前提是该模式不包含正则表达式分组。

### 与 JavaScript, HTML, CSS 的关系

该文件与 JavaScript 和 HTML 有着密切的关系：

*   **JavaScript:**
    *   **V8 绑定:** 文件中大量使用了 `third_party/blink/renderer/bindings/core/v8` 目录下的头文件，例如 `v8_url_pattern_init.h`，这表明 `URLPattern` 类及其相关接口会被暴露给 JavaScript。开发者可以在 JavaScript 中创建 `URLPattern` 对象，并使用其 `test()` 和 `exec()` 方法进行 URL 匹配。
    *   **API 使用:**  Web API (如 `URLPattern` 接口) 在 JavaScript 中被使用，而 Blink 引擎的 C++ 代码负责实现这些 API 的底层逻辑。该文件就是 `URLPattern` API 的核心实现部分。
    *   **事件处理/路由:**  `URLPattern` 可以用于实现客户端的路由逻辑，例如在 Service Workers 或 Navigation API 中，根据 URL 匹配来决定如何处理请求或导航。

    **举例说明:**

    ```javascript
    // JavaScript 示例
    const pattern = new URLPattern({ pathname: '/articles/:id' });
    const url = new URL('/articles/123', 'https://example.com');
    const matchResult = pattern.exec(url);

    if (matchResult) {
      console.log(matchResult.pathname.groups.id); // 输出 "123"
    }
    ```

*   **HTML:**
    *   **URL 解析:**  `URLPattern` 的功能是处理和匹配 URL，而 HTML 中 `<a>` 标签、`<link>` 标签、`<script>` 标签等都包含 URL。当浏览器处理这些 HTML 元素时，可能会涉及到 URL 的解析和匹配，而 `URLPattern` 提供的能力可以用于更灵活的 URL 匹配场景。
    *   **Service Workers 和 Navigation API:**  这些 Web API 允许开发者拦截和处理网络请求和页面导航，而 `URLPattern` 正是这些 API 中用于定义匹配范围的关键工具。

    **举例说明:**

    在 Service Worker 中：

    ```javascript
    // Service Worker 示例
    self.addEventListener('fetch', event => {
      const pattern = new URLPattern('https://example.com/api/*');
      if (pattern.test(event.request.url)) {
        // 拦截对 https://example.com/api/ 下所有 URL 的请求
        event.respondWith(fetch('/mock-api-response'));
      }
    });
    ```

*   **CSS:**  该文件与 CSS 的关系相对较弱。CSS 主要关注样式和布局，而 `URLPattern` 专注于 URL 的匹配。虽然 CSS 中也可能包含 URL (例如，`background-image: url(...)`)，但 `url_pattern.cc` 的主要职责不是处理 CSS 内部的 URL 匹配。更可能是用于更高层次的逻辑，例如判断哪些 CSS 资源可以被特定的 Service Worker 拦截。

### 逻辑推理举例

假设输入一个 `URLPatternInit` 对象，并创建一个 `URLPattern` 对象：

**假设输入:**

```cpp
URLPatternInit init;
init.setProtocol("https");
init.setHostname("*.example.com");
init.setPathname("/articles/*");
```

**逻辑推理:**

`URLPattern::Create()` 方法会根据 `init` 对象中的值编译出各个组件的匹配器。 `hostname` 组件的模式 `"*.example.com"` 将被编译成一个可以匹配 `example.com` 的所有子域的模式。 `pathname` 组件的模式 `"/articles/*"` 将被编译成匹配以 `/articles/` 开头的任何路径的模式.

**可能的输出 (通过 `pattern->protocol()`, `pattern->hostname()`, `pattern->pathname()` 等方法获取):**

```
protocol(): "https"
hostname(): "*.example.com"
pathname(): "/articles/*"
```

假设使用创建的 `URLPattern` 对象匹配一个 URL：

**假设输入:**

```javascript
const pattern = new URLPattern({ hostname: '*.example.com', pathname: '/articles/:id' });
const url = new URL('https://blog.example.com/articles/456');
const matchResult = pattern.exec(url);
```

**逻辑推理:**

`pattern.exec(url)` 方法会分别匹配 URL 的各个组件。 `blog.example.com` 匹配 `*.example.com`，`/articles/456` 匹配 `/articles/:id`，并且正则表达式组 `:id` 会捕获到 `456`。

**可能的输出 (JavaScript 中的 `matchResult` 对象):**

```javascript
{
  hash: { input: "", groups: {} },
  hostname: { input: "blog.example.com", groups: {} },
  password: { input: "", groups: {} },
  pathname: { input: "/articles/456", groups: { id: "456" } },
  port: { input: "", groups: {} },
  protocol: { input: "https", groups: {} },
  search: { input: "", groups: {} },
  username: { input: "", groups: {} }
}
```

### 用户或编程常见的使用错误举例

1. **在 `URLPatternInit` 中同时指定 `baseURL` 和其他组件的绝对值:**

    ```javascript
    // 错误示例
    const pattern = new URLPattern({
      baseURL: 'https://example.com/api/',
      pathname: '/users' // 期望匹配 https://example.com/users，但实际会匹配 /users 相对于 baseURL 的路径
    });
    ```

    **说明:**  如果提供了 `baseURL`，并且同时提供了如 `pathname` 这样的组件，那么 `pathname` 会被视为相对于 `baseURL` 的路径。用户可能期望 `pathname` 是一个绝对路径，导致匹配错误。

2. **在构造函数字符串中使用了错误的语法:**

    ```javascript
    // 错误示例
    const pattern = new URLPattern('https://example.com/api/[a-z'); // 正则表达式未闭合
    ```

    **说明:** `URLPattern` 的构造函数字符串有特定的语法规则，如果使用了错误的语法（例如，未闭合的正则表达式），会导致解析错误并抛出异常。

3. **混淆 `test()` 和 `exec()` 的使用场景:**

    ```javascript
    // 错误示例
    const pattern = new URLPattern('/articles/:id');
    const url = '/articles/123';
    const matchResult = pattern.test(url); // test() 只返回布尔值，不会提供分组信息
    console.log(matchResult.pathname.groups.id); // 报错，因为 test() 返回的是 boolean
    ```

    **说明:** 用户可能期望使用 `test()` 方法也能获取匹配结果的分组信息，但 `test()` 方法只用于检查是否匹配，不返回详细的匹配结果。应该使用 `exec()` 方法来获取包含分组信息的 `URLPatternResult` 对象.

### 用户操作如何一步步到达这里 (调试线索)

1. **用户在浏览器地址栏输入 URL 并访问网页:**  浏览器会解析输入的 URL。
2. **网页 JavaScript 代码创建 `URLPattern` 对象:**  例如，在 Service Worker 的 `fetch` 事件监听器中，或者在使用了 Navigation API 的网页中。
3. **JavaScript 代码使用 `URLPattern` 对象的 `test()` 或 `exec()` 方法:**  尝试将某个 URL 与创建的模式进行匹配。
4. **Blink 引擎执行相应的 C++ 代码:**  当 JavaScript 调用 `URLPattern` 的方法时，V8 引擎会调用对应的 C++ 实现，即 `blink/renderer/core/url_pattern/url_pattern.cc` 中的代码。
5. **如果在创建 `URLPattern` 对象时提供了无效的模式字符串或 `URLPatternInit` 对象，或者在匹配过程中发生错误，则可能会在此文件中触发异常或断点。**

**调试线索:**

*   在 Chrome 开发者工具中，可以在 Service Worker 或网页的 JavaScript 代码中设置断点，查看 `URLPattern` 对象的创建和使用情况。
*   如果怀疑是 C++ 代码中的问题，可以使用 Chromium 的调试工具（如 gdb 或 lldb）附加到渲染进程，并在 `url_pattern.cc` 文件中设置断点，例如在 `URLPattern::Create()` 或 `URLPattern::Match()` 方法中，来跟踪代码执行流程和变量值。
*   检查控制台输出的错误信息，特别是与 `URLPattern` 相关的类型错误或解析错误。

### 功能归纳 (第 1 部分)

总而言之，`blink/renderer/core/url_pattern/url_pattern.cc` 文件的主要功能是实现了 Web API 中的 `URLPattern` 接口，该接口允许开发者在客户端使用类似 URL 匹配的功能。它负责解析 URL 模式字符串或 `URLPatternInit` 对象，将其编译成内部的匹配结构，并提供方法来测试 URL 是否符合该模式以及提取匹配到的组件和分组信息。该文件是连接 JavaScript 的 `URLPattern` API 和 Blink 引擎底层 URL 处理逻辑的关键桥梁。

### 提示词
```
这是目录为blink/renderer/core/url_pattern/url_pattern.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/url_pattern/url_pattern.h"

#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "third_party/blink/public/common/safe_url_pattern.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_urlpattern_urlpatterninit_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_urlpatterninit_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_pattern_component_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_pattern_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_pattern_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_pattern_result.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/url_pattern/url_pattern_canon.h"
#include "third_party/blink/renderer/core/url_pattern/url_pattern_component.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/liburlpattern/constructor_string_parser.h"
#include "third_party/liburlpattern/pattern.h"
#include "third_party/liburlpattern/tokenize.h"
#include "third_party/liburlpattern/utils.h"

namespace blink {

using url_pattern::Component;
using url_pattern::ValueType;
using ComponentSet = base::EnumSet<Component::Type,
                                   Component::Type::kProtocol,
                                   Component::Type::kHash>;

namespace {

// Utility function to determine if a pathname is absolute or not.  For
// kURL values this mainly consists of a check for a leading slash.  For
// patterns we do some additional checking for escaped or grouped slashes.
bool IsAbsolutePathname(const String& pathname, ValueType type) {
  if (pathname.empty())
    return false;

  if (pathname[0] == '/')
    return true;

  if (type == ValueType::kURL)
    return false;

  if (pathname.length() < 2)
    return false;

  // Patterns treat escaped slashes and slashes within an explicit grouping as
  // valid leading slashes.  For example, "\/foo" or "{/foo}".  Patterns do
  // not consider slashes within a custom regexp group as valid for the leading
  // pathname slash for now.  To support that we would need to be able to
  // detect things like ":name_123(/foo)" as a valid leading group in a pattern,
  // but that is considered too complex for now.
  if ((pathname[0] == '\\' || pathname[0] == '{') && pathname[1] == '/') {
    return true;
  }

  return false;
}

// Utility function to determine if the default port for the given protocol
// matches the given port number.
bool IsProtocolDefaultPort(const String& protocol, const String& port) {
  if (protocol.empty() || port.empty())
    return false;

  bool port_ok = false;
  int port_number = port.Impl()->ToInt(WTF::NumberParsingOptions(), &port_ok);
  if (!port_ok)
    return false;

  StringUTF8Adaptor protocol_utf8(protocol);
  int default_port = url::DefaultPortForScheme(protocol_utf8.AsStringView());
  return default_port != url::PORT_UNSPECIFIED && default_port == port_number;
}

// Base URL values that include pattern string characters should not blow
// up pattern parsing.  Automatically escape them.  We must not escape inputs
// for non-pattern base URLs, though.
String EscapeBaseURLString(const StringView& input, ValueType type) {
  if (input.empty()) {
    return g_empty_string;
  }

  if (type != ValueType::kPattern) {
    return input.ToString();
  }

  std::string result;
  result.reserve(input.length());

  StringUTF8Adaptor utf8(input);
  liburlpattern::EscapePatternStringAndAppend(utf8.AsStringView(), result);

  return String::FromUTF8(result);
}

// A utility method that takes a URLPatternInit, splits it apart, and applies
// the individual component values in the given set of strings.  The strings
// are only applied if a value is present in the init structure.
void ApplyInit(const URLPatternInit* init,
               ValueType type,
               String& protocol,
               String& username,
               String& password,
               String& hostname,
               String& port,
               String& pathname,
               String& search,
               String& hash,
               ExceptionState& exception_state) {
  // If there is a baseURL we need to apply its component values first.  The
  // rest of the URLPatternInit structure will then later override these
  // values.  Note, the baseURL will always set either an empty string or
  // longer value for each considered component.  We do not allow null strings
  // to persist for these components past this phase since they should no
  // longer be treated as wildcards.
  KURL base_url;
  if (init->hasBaseURL()) {
    base_url = KURL(init->baseURL());
    if (!base_url.IsValid() || base_url.IsEmpty()) {
      exception_state.ThrowTypeError("Invalid baseURL '" + init->baseURL() +
                                     "'.");
      return;
    }

    // Components are only inherited from the base URL if no "earlier" component
    // is specified in |init|.  Furthermore, when the base URL is being used as
    // the basis of a pattern (not a URL being matched against), usernames and
    // passwords are always wildcarded unless explicitly specified otherwise,
    // because they usually do not affect which resource is requested (though
    // they do often affect whether access is authorized).
    //
    // Even though they appear earlier than the hostname in a URL, the username
    // and password are treated as appearing after it because they typically
    // refer to credentials within a realm on an origin, rather than being used
    // across all hostnames.
    //
    // This partial ordering is represented by the following diagram:
    //
    //                                 +-> pathname --> search --> hash
    // protocol --> hostname --> port -|
    //                                 +-> username --> password
    protocol = init->hasProtocol()
                   ? String()
                   : EscapeBaseURLString(base_url.Protocol(), type);
    username = (type == ValueType::kPattern ||
                (init->hasProtocol() || init->hasHostname() ||
                 init->hasPort() || init->hasUsername()))
                   ? String()
                   : EscapeBaseURLString(base_url.User(), type);
    password = (type == ValueType::kPattern ||
                (init->hasProtocol() || init->hasHostname() ||
                 init->hasPort() || init->hasUsername() || init->hasPassword()))
                   ? String()
                   : EscapeBaseURLString(base_url.Pass(), type);
    hostname = (init->hasProtocol() || init->hasHostname())
                   ? String()
                   : EscapeBaseURLString(base_url.Host(), type);
    port = (init->hasProtocol() || init->hasHostname() || init->hasPort())
               ? String()
           : base_url.Port() > 0 ? String::Number(base_url.Port())
                                 : g_empty_string;
    pathname = (init->hasProtocol() || init->hasHostname() || init->hasPort() ||
                init->hasPathname())
                   ? String()
                   : EscapeBaseURLString(base_url.GetPath(), type);
    search = (init->hasProtocol() || init->hasHostname() || init->hasPort() ||
              init->hasPathname() || init->hasSearch())
                 ? String()
                 : EscapeBaseURLString(base_url.Query(), type);
    hash = (init->hasProtocol() || init->hasHostname() || init->hasPort() ||
            init->hasPathname() || init->hasSearch() || init->hasHash())
               ? String()
           : base_url.HasFragmentIdentifier()
               ? EscapeBaseURLString(base_url.FragmentIdentifier(), type)
               : g_empty_string;
  }

  // Apply the URLPatternInit component values on top of the default and
  // baseURL values.
  if (init->hasProtocol()) {
    protocol = url_pattern::CanonicalizeProtocol(init->protocol(), type,
                                                 exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasUsername() || init->hasPassword()) {
    String init_username = init->hasUsername() ? init->username() : String();
    String init_password = init->hasPassword() ? init->password() : String();
    url_pattern::CanonicalizeUsernameAndPassword(init_username, init_password,
                                                 type, username, password,
                                                 exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasHostname()) {
    hostname = url_pattern::CanonicalizeHostname(init->hostname(), type,
                                                 exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasPort()) {
    port = url_pattern::CanonicalizePort(init->port(), type, protocol,
                                         exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasPathname()) {
    pathname = init->pathname();
    if (base_url.IsValid() && base_url.IsHierarchical() &&
        !IsAbsolutePathname(pathname, type)) {
      // Find the last slash in the baseURL pathname.  Since the URL is
      // hierarchical it should have a slash to be valid, but we are cautious
      // and check.  If there is no slash then we cannot use resolve the
      // relative pathname and just treat the init pathname as an absolute
      // value.
      String base_path = EscapeBaseURLString(base_url.GetPath(), type);
      auto slash_index = base_path.ReverseFind("/");
      if (slash_index != kNotFound) {
        // Extract the baseURL path up to and including the first slash.  Append
        // the relative init pathname to it.
        pathname = base_path.Substring(0, slash_index + 1) + pathname;
      }
    }
    pathname = url_pattern::CanonicalizePathname(protocol, pathname, type,
                                                 exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasSearch()) {
    search =
        url_pattern::CanonicalizeSearch(init->search(), type, exception_state);
    if (exception_state.HadException())
      return;
  }
  if (init->hasHash()) {
    hash = url_pattern::CanonicalizeHash(init->hash(), type, exception_state);
    if (exception_state.HadException())
      return;
  }
}

URLPatternComponentResult* MakeURLPatternComponentResult(
    ScriptState* script_state,
    const String& input,
    const Vector<std::pair<String, String>>& group_values) {
  auto* result = URLPatternComponentResult::Create();
  result->setInput(input);

  // Convert null WTF::String values to v8::Undefined.  We have to do this
  // manually because the webidl compiler compiler does not currently
  // support `(USVString or undefined)` in a record value.
  // TODO(crbug.com/1293259): Use webidl `(USVString or undefined)` when
  //                          available in the webidl compiler.
  HeapVector<std::pair<String, ScriptValue>> v8_group_values;
  v8_group_values.reserve(group_values.size());
  for (const auto& pair : group_values) {
    v8::Local<v8::Value> v8_value;
    if (pair.second.IsNull()) {
      v8_value = v8::Undefined(script_state->GetIsolate());
    } else {
      v8_value = ToV8Traits<IDLUSVString>::ToV8(script_state, pair.second);
    }
    v8_group_values.emplace_back(
        pair.first,
        ScriptValue(script_state->GetIsolate(), std::move(v8_value)));
  }

  result->setGroups(std::move(v8_group_values));
  return result;
}

URLPatternInit* MakeURLPatternInit(
    const liburlpattern::ConstructorStringParser::Result& result) {
  auto* init = URLPatternInit::Create();
  if (result.protocol) {
    init->setProtocol(String::FromUTF8(*result.protocol));
  }
  if (result.username) {
    init->setUsername(String::FromUTF8(*result.username));
  }
  if (result.password) {
    init->setPassword(String::FromUTF8(*result.password));
  }
  if (result.hostname) {
    init->setHostname(String::FromUTF8(*result.hostname));
  }
  if (result.port) {
    init->setPort(String::FromUTF8(*result.port));
  }
  if (result.pathname) {
    init->setPathname(String::FromUTF8(*result.pathname));
  }
  if (result.search) {
    init->setSearch(String::FromUTF8(*result.search));
  }
  if (result.hash) {
    init->setHash(String::FromUTF8(*result.hash));
  }
  return init;
}

ComponentSet ToURLPatternComponentSet(
    const liburlpattern::ConstructorStringParser::ComponentSet&
        present_components) {
  ComponentSet result;
  if (present_components.protocol) {
    result.Put(Component::Type::kProtocol);
  }
  if (present_components.username) {
    result.Put(Component::Type::kUsername);
  }
  if (present_components.password) {
    result.Put(Component::Type::kPassword);
  }
  if (present_components.hostname) {
    result.Put(Component::Type::kHostname);
  }
  if (present_components.port) {
    result.Put(Component::Type::kPort);
  }
  if (present_components.pathname) {
    result.Put(Component::Type::kPathname);
  }
  if (present_components.search) {
    result.Put(Component::Type::kSearch);
  }
  if (present_components.hash) {
    result.Put(Component::Type::kHash);
  }
  return result;
}

}  // namespace

URLPattern* URLPattern::From(v8::Isolate* isolate,
                             const V8URLPatternCompatible* compatible,
                             const KURL& base_url,
                             ExceptionState& exception_state) {
  switch (compatible->GetContentType()) {
    case V8URLPatternCompatible::ContentType::kURLPattern:
      return compatible->GetAsURLPattern();
    case V8URLPatternCompatible::ContentType::kURLPatternInit: {
      URLPatternInit* original_init = compatible->GetAsURLPatternInit();
      URLPatternInit* init;
      if (original_init->hasBaseURL()) {
        init = original_init;
      } else {
        init = URLPatternInit::Create();
        if (original_init->hasProtocol()) {
          init->setProtocol(original_init->protocol());
        }
        if (original_init->hasUsername()) {
          init->setUsername(original_init->username());
        }
        if (original_init->hasPassword()) {
          init->setPassword(original_init->password());
        }
        if (original_init->hasHostname()) {
          init->setHostname(original_init->hostname());
        }
        if (original_init->hasPort()) {
          init->setPort(original_init->port());
        }
        if (original_init->hasPathname()) {
          init->setPathname(original_init->pathname());
        }
        if (original_init->hasSearch()) {
          init->setSearch(original_init->search());
        }
        if (original_init->hasHash()) {
          init->setHash(original_init->hash());
        }
        init->setBaseURL(base_url.GetString());
      }
      return Create(isolate, init, /*precomputed_protocol_component=*/nullptr,
                    MakeGarbageCollected<URLPatternOptions>(), exception_state);
    }
    case V8URLPatternCompatible::ContentType::kUSVString:
      return Create(
          isolate,
          MakeGarbageCollected<V8URLPatternInput>(compatible->GetAsUSVString()),
          base_url.GetString(), MakeGarbageCollected<URLPatternOptions>(),
          exception_state);
  }
}

URLPattern* URLPattern::Create(v8::Isolate* isolate,
                               const V8URLPatternInput* input,
                               const String& base_url,
                               const URLPatternOptions* options,
                               ExceptionState& exception_state) {
  if (input->GetContentType() ==
      V8URLPatternInput::ContentType::kURLPatternInit) {
    exception_state.ThrowTypeError(
        "Invalid second argument baseURL '" + base_url +
        "' provided with a URLPatternInit input. Use the "
        "URLPatternInit.baseURL property instead.");
    return nullptr;
  }

  const auto& input_string = input->GetAsUSVString();
  const StringUTF8Adaptor utf8_string(input_string);
  liburlpattern::ConstructorStringParser constructor_string_parser(
      utf8_string.AsStringView());

  Component* protocol_component = nullptr;
  absl::Status status = constructor_string_parser.Parse(
      [=, &protocol_component, &exception_state](
          std::string_view protocol_string) -> absl::StatusOr<bool> {
        protocol_component = Component::Compile(
            isolate, String::FromUTF8(protocol_string),
            Component::Type::kProtocol,
            /*protocol_component=*/nullptr, *options, exception_state);
        if (exception_state.HadException()) {
          return absl::InvalidArgumentError("Failed to compile protocol");
        }
        return protocol_component &&
               protocol_component->ShouldTreatAsStandardURL();
      });

  if (exception_state.HadException()) {
    return nullptr;
  }
  if (!status.ok()) {
    exception_state.ThrowTypeError("Invalid input string '" + input_string +
                                   "'. It unexpectedly fails to tokenize.");
    return nullptr;
  }
  URLPatternInit* init =
      MakeURLPatternInit(constructor_string_parser.GetResult());

  if (!base_url && !init->hasProtocol()) {
    exception_state.ThrowTypeError(
        "Relative constructor string '" + input_string +
        "' must have a base URL passed as the second argument.");
    return nullptr;
  }

  if (base_url)
    init->setBaseURL(base_url);

  URLPattern* result =
      Create(isolate, init, protocol_component, options, exception_state);
  if (result) {
    URLPattern::ComponentSet present = ToURLPatternComponentSet(
        constructor_string_parser.GetPresentComponents());
    URLPattern::ComponentSet wildcard_with_string_format_change =
        URLPattern::ComponentSet::All();
    wildcard_with_string_format_change.RemoveAll(present);
    if (present.Has(Component::Type::kUsername)) {
      wildcard_with_string_format_change.RemoveAll({Component::Type::kProtocol,
                                                    Component::Type::kHostname,
                                                    Component::Type::kPort});
    }
    if (present.Has(Component::Type::kPassword)) {
      wildcard_with_string_format_change.RemoveAll(
          {Component::Type::kProtocol, Component::Type::kHostname,
           Component::Type::kPort, Component::Type::kUsername});
    }
    if (present.Has(Component::Type::kHostname)) {
      // As a special case, don't wildcard the port if the host is present, even
      // with no path.
      wildcard_with_string_format_change.RemoveAll(
          {Component::Type::kProtocol, Component::Type::kPort});
    }
    if (present.Has(Component::Type::kPort)) {
      wildcard_with_string_format_change.RemoveAll(
          {Component::Type::kProtocol, Component::Type::kHostname});
    }
    if (present.Has(Component::Type::kPathname)) {
      wildcard_with_string_format_change.RemoveAll({Component::Type::kProtocol,
                                                    Component::Type::kHostname,
                                                    Component::Type::kPort});
    }
    if (present.Has(Component::Type::kSearch)) {
      wildcard_with_string_format_change.RemoveAll(
          {Component::Type::kProtocol, Component::Type::kHostname,
           Component::Type::kPort, Component::Type::kPathname});
    }
    if (present.Has(Component::Type::kHash)) {
      wildcard_with_string_format_change.RemoveAll(
          {Component::Type::kProtocol, Component::Type::kHostname,
           Component::Type::kPort, Component::Type::kPathname,
           Component::Type::kSearch});
    }
    result->wildcard_with_string_format_change_ =
        wildcard_with_string_format_change;
  }
  return result;
}

URLPattern* URLPattern::Create(v8::Isolate* isolate,
                               const V8URLPatternInput* input,
                               const String& base_url,
                               ExceptionState& exception_state) {
  return Create(isolate, input, base_url,
                MakeGarbageCollected<URLPatternOptions>(), exception_state);
}

URLPattern* URLPattern::Create(v8::Isolate* isolate,
                               const V8URLPatternInput* input,
                               const URLPatternOptions* options,
                               ExceptionState& exception_state) {
  if (input->IsURLPatternInit()) {
    return URLPattern::Create(isolate, input->GetAsURLPatternInit(),
                              /*precomputed_protocol_component=*/nullptr,
                              options, exception_state);
  }
  return Create(isolate, input, /*base_url=*/String(), options,
                exception_state);
}

URLPattern* URLPattern::Create(v8::Isolate* isolate,
                               const V8URLPatternInput* input,
                               ExceptionState& exception_state) {
  if (input->IsURLPatternInit()) {
    return URLPattern::Create(isolate, input->GetAsURLPatternInit(),
                              /*precomputed_protocol_component=*/nullptr,
                              MakeGarbageCollected<URLPatternOptions>(),
                              exception_state);
  }

  return Create(isolate, input, /*base_url=*/String(), exception_state);
}

URLPattern* URLPattern::Create(v8::Isolate* isolate,
                               const URLPatternInit* init,
                               Component* precomputed_protocol_component,
                               const URLPatternOptions* options,
                               ExceptionState& exception_state) {
  // Each component defaults to a wildcard matching any input.  We use
  // the null string as a shorthand for the default.
  String protocol;
  String username;
  String password;
  String hostname;
  String port;
  String pathname;
  String search;
  String hash;

  // Apply the input URLPatternInit on top of the default values.
  ApplyInit(init, ValueType::kPattern, protocol, username, password, hostname,
            port, pathname, search, hash, exception_state);
  if (exception_state.HadException())
    return nullptr;

  // Manually canonicalize port patterns that exactly match the default
  // port for the protocol.  We must do this separately from the compile
  // since the liburlpattern::Parse() method will invoke encoding callbacks
  // for partial values within the pattern and this transformation must apply
  // to the entire value.
  if (IsProtocolDefaultPort(protocol, port))
    port = "";

  // Compile each component pattern into a Component structure that
  // can be used for matching.

  auto* protocol_component = precomputed_protocol_component;
  if (!protocol_component) {
    protocol_component = Component::Compile(
        isolate, protocol, Component::Type::kProtocol,
        /*protocol_component=*/nullptr, *options, exception_state);
  }
  if (exception_state.HadException())
    return nullptr;

  auto* username_component =
      Component::Compile(isolate, username, Component::Type::kUsername,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* password_component =
      Component::Compile(isolate, password, Component::Type::kPassword,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* hostname_component =
      Component::Compile(isolate, hostname, Component::Type::kHostname,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* port_component =
      Component::Compile(isolate, port, Component::Type::kPort,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* pathname_component =
      Component::Compile(isolate, pathname, Component::Type::kPathname,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* search_component =
      Component::Compile(isolate, search, Component::Type::kSearch,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  auto* hash_component =
      Component::Compile(isolate, hash, Component::Type::kHash,
                         protocol_component, *options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  Options urlpattern_options;
  urlpattern_options.ignore_case = options->ignoreCase();

  URLPattern* result = MakeGarbageCollected<URLPattern>(
      protocol_component, username_component, password_component,
      hostname_component, port_component, pathname_component, search_component,
      hash_component, urlpattern_options, base::PassKey<URLPattern>());
  if (init->hasBaseURL()) {
    auto& would_be_wildcard = result->wildcard_with_base_url_change_;
    if (!init->hasUsername() &&
        (init->hasProtocol() || init->hasHostname() || init->hasPort())) {
      would_be_wildcard.Put(Component::Type::kUsername);
    }
    if (!init->hasPassword() && (init->hasProtocol() || init->hasHostname() ||
                                 init->hasPort() || init->hasUsername())) {
      would_be_wildcard.Put(Component::Type::kPassword);
    }
    if (!init->hasHostname() && init->hasProtocol()) {
      would_be_wildcard.Put(Component::Type::kHostname);
    }
    if (!init->hasPort() && (init->hasProtocol() || init->hasHostname())) {
      would_be_wildcard.Put(Component::Type::kPort);
    }
    if (!init->hasPathname() &&
        (init->hasProtocol() || init->hasHostname() || init->hasPort())) {
      would_be_wildcard.Put(Component::Type::kPathname);
    }
    if (!init->hasSearch() && (init->hasProtocol() || init->hasHostname() ||
                               init->hasPort() || init->hasPathname())) {
      would_be_wildcard.Put(Component::Type::kSearch);
    }
    if (!init->hasHash() &&
        (init->hasProtocol() || init->hasHostname() || init->hasPort() ||
         init->hasPathname() || init->hasSearch())) {
      would_be_wildcard.Put(Component::Type::kHash);
    }
  }
  return result;
}

URLPattern::URLPattern(Component* protocol,
                       Component* username,
                       Component* password,
                       Component* hostname,
                       Component* port,
                       Component* pathname,
                       Component* search,
                       Component* hash,
                       Options options,
                       base::PassKey<URLPattern> key)
    : protocol_(protocol),
      username_(username),
      password_(password),
      hostname_(hostname),
      port_(port),
      pathname_(pathname),
      search_(search),
      hash_(hash),
      options_(options) {}

bool URLPattern::test(ScriptState* script_state,
                      const V8URLPatternInput* input,
                      const String& base_url,
                      ExceptionState& exception_state) const {
  return Match(script_state, input, base_url, /*result=*/nullptr,
               exception_state);
}

bool URLPattern::test(ScriptState* script_state,
                      const V8URLPatternInput* input,
                      ExceptionState& exception_state) const {
  return test(script_state, input, /*base_url=*/String(), exception_state);
}

URLPatternResult* URLPattern::exec(ScriptState* script_state,
                                   const V8URLPatternInput* input,
                                   const String& base_url,
                                   ExceptionState& exception_state) const {
  URLPatternResult* result = URLPatternResult::Create();
  if (!Match(script_state, input, base_url, result, exception_state))
    return nullptr;
  return result;
}

URLPatternResult* URLPattern::exec(ScriptState* script_state,
                                   const V8URLPatternInput* input,
                                   ExceptionState& exception_state) const {
  return exec(script_state, input, /*base_url=*/String(), exception_state);
}

String URLPattern::protocol() const {
  return protocol_->GeneratePatternString();
}

String URLPattern::username() const {
  return username_->GeneratePatternString();
}

String URLPattern::password() const {
  return password_->GeneratePatternString();
}

String URLPattern::hostname() const {
  return hostname_->GeneratePatternString();
}

String URLPattern::port() const {
  return port_->GeneratePatternString();
}

String URLPattern::pathname() const {
  return pathname_->GeneratePatternString();
}

String URLPattern::search() const {
  return search_->GeneratePatternString();
}

String URLPattern::hash() const {
  return hash_->GeneratePatternString();
}

bool URLPattern::hasRegExpGroups() const {
  const url_pattern::Component* components[] = {protocol_, username_, password_,
                                                hostname_, port_,     pathname_,
                                                search_,   hash_};
  return base::ranges::any_of(components,
                              &url_pattern::Component::HasRegExpGroups);
}

// static
int URLPattern::compareComponent(const V8URLPatternComponent& component,
                                 const URLPattern* left,
                                 const URLPattern* right) {
  switch (component.AsEnum()) {
    case V8URLPatternComponent::Enum::kProtocol:
      return url_pattern::Component::Compare(*left->protocol_,
                                             *right->protocol_);
    case V8URLPatternComponent::Enum::kUsername:
      return url_pattern::Component::Compare(*left->username_,
                                             *right->username_);
    case V8URLPatternComponent::Enum::kPassword:
      return url_pattern::Component::Compare(*left->password_,
                                             *right->password_);
    case V8URLPatternComponent::Enum::kHostname:
      return url_pattern::Component::Compare(*left->hostname_,
                                             *right->hostname_);
    case V8URLPatternComponent::Enum::kPort:
      return url_pattern::Component::Compare(*left->port_, *right->port_);
    case V8URLPatternComponent::Enum::kPathname:
      return url_pattern::Component::Compare(*left->pathname_,
                                             *right->pathname_);
    case V8URLPatternComponent::Enum::kSearch:
      return url_pattern::Component::Compare(*left->search_, *right->search_);
    case V8URLPatternComponent::Enum::kHash:
      return url_pattern::Component::Compare(*left->hash_, *right->hash_);
  }
  NOTREACHED();
}

std::optional<SafeUrlPattern> URLPattern::ToSafeUrlPattern(
    ExceptionState& exception_state) const {
  const std::pair<const url_pattern::Component*, const char*>
      components_with_names[] = {
          {protocol_, "protocol"}, {username_, "username"},
          {password_, "password"}, {hostname_, "hostname"},
          {port_, "port"},         {pathname_, "pathname"},
          {search_, "search"},     {hash_, "hash"}};
  String components_with_regexp;
  for (auto [component, name] : components_with_names) {
    if (component->HasRegExpGroups()) {
      components_with_regexp = components_with_regexp +
                               (components_with_regexp.IsNull() ? "" : ", ") +
                               name + " (" +
                               component->GeneratePatternString() + ")";
    }
  }
  if (!components_with_regexp.IsNull()) {
    exception_state.ThrowTypeError(
        "The pattern cannot contain regexp groups, but did in the following "
        "components: " +
        compo
```