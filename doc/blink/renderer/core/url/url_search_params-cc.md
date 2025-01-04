Response:
Let's break down the thought process to analyze the `URLSearchParams.cc` file.

1. **Understand the Goal:** The primary objective is to understand the functionality of this file within the Blink rendering engine and its relationship to web technologies (JavaScript, HTML, CSS). We also need to consider potential user errors, debugging insights, and any implicit logic.

2. **Initial Code Scan and High-Level Identification:**  Read through the code, paying attention to class names, function names, included headers, and namespaces. Keywords like `URLSearchParams`, `DOMURL`, `String`, `Vector`, `append`, `get`, `set`, `delete`, `sort`, `toString`, `FormDataEncoder`, and `DecodeURLEscapeSequences` immediately stand out. The inclusion of headers like `v8_union_usvstring_usvstringsequencesequence_usvstringusvstringrecord.h` hints at interactions with JavaScript.

3. **Core Functionality Identification:** Based on the names and keywords, we can infer the core responsibility:  managing and manipulating URL query parameters. This includes:
    * Storing key-value pairs of parameters.
    * Adding, removing, and modifying parameters.
    * Encoding and decoding parameter values.
    * Representing the parameters as a string.
    * Integrating with the `DOMURL` object to update the URL.

4. **Relating to Web Technologies:**

    * **JavaScript:** The class is clearly designed to implement the JavaScript `URLSearchParams` interface. The `Create` methods taking different input types (`USVString`, sequences, records) directly correspond to the ways `URLSearchParams` can be constructed in JavaScript. The methods like `append`, `delete`, `get`, `getAll`, `has`, `set`, `sort`, and `toString` have direct counterparts in the JavaScript API. The iteration logic (`URLSearchParamsIterationSource`) is used for JavaScript iteration (`for...of`).
    * **HTML:** Query parameters are a fundamental part of URLs, which are used extensively in HTML (e.g., `<a href="...">`, `<form action="...">`). The `URLSearchParams` object helps parse and manipulate these parameters.
    * **CSS:** While not directly related to CSS *styling*, URLs with query parameters can be used to fetch CSS resources. `URLSearchParams` could be involved in constructing these URLs.

5. **Detailed Method Analysis:** Go through each method and understand its purpose:

    * **`Create` methods:**  Handle different ways to initialize `URLSearchParams` (from a query string, an array of pairs, or a record). Note the error handling for invalid input.
    * **Constructor:** Takes a query string and a `DOMURL` object (for updates).
    * **`RunUpdateSteps`:**  Crucially links the `URLSearchParams` object to the underlying URL, updating it when changes are made.
    * **`SetInputWithoutUpdate`:** Parses a query string into key-value pairs.
    * **`toString`:**  Serializes the parameters back into a query string.
    * **`size`:** Returns the number of parameters.
    * **`append`:** Adds a new parameter.
    * **`deleteAllWithNameOrTuple`:** Removes parameters by name (and optionally by value). Note the conditional logic based on the `URLSearchParamsHasAndDeleteMultipleArgsEnabled` feature flag and the use counter.
    * **`get`:** Retrieves the first value associated with a name.
    * **`getAll`:** Retrieves all values associated with a name.
    * **`has`:** Checks if a parameter with a given name (and optionally value) exists. Again, note the feature flag and use counter.
    * **`set`:** Sets the value of the first parameter with a given name, or appends a new one.
    * **`sort`:** Sorts the parameters alphabetically by name.
    * **`EncodeAsFormData`:**  Encodes the parameters for form submission.
    * **`ToEncodedFormData`:**  Returns the encoded data as an `EncodedFormData` object.
    * **`CreateIterationSource`:** Provides the iterator for the object.

6. **Logic and Assumptions:**

    * **Decoding:**  The use of `DecodeURLEscapeSequences` with `DecodeURLMode::kUTF8` shows the expectation of UTF-8 encoding.
    * **Order:** The `sort` method explicitly sorts the parameters, indicating that the order might matter in some contexts. However, the default behavior is to preserve insertion order.
    * **Updating the URL:** The connection to `DOMURL` and `RunUpdateSteps` highlights the important side effect of modifying the URL object when `URLSearchParams` changes.

7. **User and Programming Errors:**

    * **Incorrect Initialization:** Providing an array of arrays where inner arrays don't have exactly two elements.
    * **Missing `?`:**  When manually constructing a query string, forgetting the leading `?`.
    * **Encoding Issues:**  Not properly encoding or decoding special characters in parameter names or values (though the code handles basic decoding).
    * **Unexpected Behavior with Feature Flags:** The `deleteAll` and `has` methods have different behaviors depending on the state of a feature flag, which could lead to confusion if the developer isn't aware of it.

8. **Debugging and User Interaction:**

    * **JavaScript Interaction:** The primary way users interact with this code is through JavaScript's `URLSearchParams` API. Any manipulation of `window.location.search` or creation of `URLSearchParams` objects in JavaScript will eventually lead to the execution of this C++ code.
    * **HTML Forms:** Submitting HTML forms with the `GET` method generates URLs with query parameters, which are then parsed by this code.
    * **Debugging Steps:**  Simulate JavaScript interactions or analyze network requests to see how query parameters are being formed and processed. Setting breakpoints in the C++ code can help track the flow of execution when JavaScript manipulates `URLSearchParams`.

9. **Refine and Organize:**  Structure the findings into logical categories (functionality, relationships, logic, errors, debugging) and provide specific examples. Use the code snippets to illustrate points. Ensure clarity and conciseness.

10. **Review and Iterate:** Read through the analysis to ensure accuracy and completeness. Are there any missing aspects?  Is the explanation clear and easy to understand?  For example, initially, I might have overlooked the significance of the feature flags, but a closer look at the `deleteAll` and `has` methods would highlight their importance.

This iterative process of scanning, identifying, analyzing, relating, and refining allows for a comprehensive understanding of the given source code.
这个文件 `blink/renderer/core/url/url_search_params.cc` 是 Chromium Blink 引擎中 `URLSearchParams` 接口的 C++ 实现。 `URLSearchParams` 接口用于处理 URL 的查询字符串（query string）。

以下是它的主要功能：

**核心功能：管理和操作 URL 查询参数**

* **解析查询字符串:**  能够将一个 URL 的查询字符串解析成一系列的键值对。
* **存储键值对:**  内部使用 `std::vector<std::pair<String, String>>`  `params_` 来存储查询参数的键值对。
* **添加参数:** 提供 `append()` 方法来添加新的查询参数。
* **删除参数:** 提供 `deleteAllWithNameOrTuple()` 方法来删除指定名称的参数，或者在特定 Feature Flag 开启时，可以删除指定名称和值的参数对。
* **获取参数:**
    * `get()`: 获取指定名称的第一个参数的值。
    * `getAll()`: 获取指定名称的所有参数的值，返回一个字符串向量。
* **检查参数是否存在:** `has()` 方法用于检查是否存在指定名称的参数，或者在特定 Feature Flag 开启时，可以检查是否存在指定名称和值的参数对。
* **设置参数:** `set()` 方法用于设置指定名称的参数的值。如果存在同名参数，则更新第一个，删除其余的。如果不存在，则添加新的参数。
* **排序参数:** `sort()` 方法用于按照参数名称的 Unicode 码位进行排序。
* **序列化为查询字符串:** `toString()` 方法将内部存储的键值对序列化回符合 URL 编码规范的查询字符串。
* **编码为 `EncodedFormData`:** `ToEncodedFormData()` 方法将查询参数编码成 `EncodedFormData` 对象，这通常用于表单数据的处理。
* **迭代器支持:** 提供了迭代器接口，允许使用 JavaScript 的 `for...of` 循环来遍历查询参数。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

**1. 与 JavaScript 的关系最为密切：**

* **JavaScript `URLSearchParams` API 的 C++ 实现:**  这个 C++ 文件是浏览器提供给 JavaScript 的 `URLSearchParams` API 的底层实现。JavaScript 通过这个 API 来创建、读取、修改 URL 的查询参数。

   **举例:**

   ```javascript
   // JavaScript 代码
   const url = new URL('https://example.com/search?q=keyword&category=books');
   const params = url.searchParams;

   console.log(params.get('q')); // 输出: keyword
   params.append('sort', 'relevance');
   console.log(url.href); // 输出: https://example.com/search?q=keyword&category=books&sort=relevance

   params.delete('category');
   console.log(url.href); // 输出: https://example.com/search?q=keyword&sort=relevance

   for (const [key, value] of params) {
     console.log(`${key}: ${value}`);
   }
   // 输出:
   // q: keyword
   // sort: relevance
   ```

   当 JavaScript 执行这些操作时，Blink 引擎会调用 `url_search_params.cc` 中相应的 C++ 方法。例如，`params.get('q')` 会最终调用 `URLSearchParams::get()`。

* **事件处理和数据传递:** JavaScript 可以通过 `URLSearchParams` 对象来构建 URL，用于发起网络请求、提交表单等。

**2. 与 HTML 的关系：**

* **解析 HTML 中链接和表单的查询参数:** 当浏览器解析 HTML 文档时，会使用 `URLSearchParams` 相关的逻辑来解析 `<a>` 标签的 `href` 属性或 `<form>` 标签的 `action` 属性中包含的查询参数。

   **举例:**

   ```html
   <!-- HTML 代码 -->
   <a href="/page?id=123&type=product">商品详情</a>

   <form action="/submit" method="GET">
     <input type="text" name="search" value="example">
     <button type="submit">搜索</button>
   </form>
   ```

   当用户点击链接或提交表单时，浏览器会创建一个包含查询参数的 URL。Blink 引擎会使用 `URLSearchParams` 相关的代码来处理这些参数。

**3. 与 CSS 的关系 (间接关系):**

* **CSS 中 `url()` 函数的使用:** CSS 中可以使用 `url()` 函数引用外部资源，例如图片、字体等。这些 URL 可能包含查询参数。`URLSearchParams` 的解析逻辑会间接地应用于这些 URL。

   **举例:**

   ```css
   /* CSS 代码 */
   .icon {
     background-image: url("/images/icon.png?version=1");
   }
   ```

   虽然 CSS 本身不直接操作 `URLSearchParams` 对象，但当浏览器加载 CSS 文件并遇到带有查询参数的 URL 时，底层的 URL 解析和处理逻辑（部分由 `url_search_params.cc` 实现）会被调用。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个 `URLSearchParams` 对象被初始化为查询字符串 `a=1&b=2&a=3`。

**方法调用及预期输出:**

* `params.get('a')`: 输出 `"1"` (返回第一个匹配的键的值)
* `params.getAll('a')`: 输出 `["1", "3"]` (返回所有匹配的键的值的数组)
* `params.has('b')`: 输出 `true`
* `params.has('c')`: 输出 `false`
* `params.size`: 输出 `3`
* `params.toString()`: 输出 `"a=1&b=2&a=3"` (顺序可能不保证，但键值对内容一致)
* `params.sort()` 后 `params.toString()`: 输出 `"a=1&a=3&b=2"` (按键名排序)
* `params.delete('a')` 后 `params.toString()`: 输出 `"b=2"` (删除所有键名为 "a" 的参数)
* `params.append('c', '4')` 后 `params.toString()`: 输出 `"a=1&b=2&a=3&c=4"` (添加新的键值对)
* `params.set('a', '5')` 后 `params.toString()`: 输出 `"a=5&b=2"` (将第一个 "a" 的值设置为 "5"，并删除后续的 "a")

**用户或编程常见的使用错误:**

1. **手动拼接查询字符串错误:**  开发者可能会尝试手动拼接查询字符串，容易出错，例如忘记 URL 编码、参数顺序错误等。使用 `URLSearchParams` 可以避免这些问题。

   **错误示例 (JavaScript):**
   ```javascript
   // 错误的做法
   const baseUrl = 'https://example.com/search?';
   const params = { q: 'search term', category: 'books' };
   let queryString = '';
   for (const key in params) {
     queryString += `${key}=${params[key]}&`; // 可能忘记 URL 编码
   }
   const url = baseUrl + queryString.slice(0, -1); // 可能出现顺序问题
   ```

   **正确做法:**
   ```javascript
   const url = new URL('https://example.com/search');
   const params = url.searchParams;
   params.append('q', 'search term');
   params.append('category', 'books');
   console.log(url.href);
   ```

2. **假设参数顺序:**  在没有明确排序的情况下，不应该假设查询参数的顺序。`URLSearchParams` 提供了 `sort()` 方法来明确排序。

3. **忘记 URL 编码:**  如果直接拼接字符串作为参数值，可能会包含需要 URL 编码的字符，导致解析错误。`URLSearchParams` 会自动处理编码。

4. **对 `get()` 和 `getAll()` 的误解:**  开发者可能会误以为 `get()` 会返回所有匹配的值，而忽略了 `getAll()` 的存在。

5. **在不支持 `URLSearchParams` 的旧浏览器中使用:** 需要进行兼容性处理或使用 polyfill。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并访问:** 当用户在地址栏输入包含查询参数的 URL 并按下回车键时，浏览器会解析这个 URL，包括查询参数部分。`URLSearchParams` 相关的代码会被用来解析这些参数。

2. **网页上的 JavaScript 代码创建 `URLSearchParams` 对象:** 网页上的 JavaScript 代码可以使用 `new URLSearchParams()` 构造函数创建 `URLSearchParams` 对象。例如：
   ```javascript
   const params = new URLSearchParams(window.location.search);
   ```
   这会触发 `url_search_params.cc` 中的构造函数。

3. **网页上的 JavaScript 代码操作 `URLSearchParams` 对象的方法:** 当 JavaScript 代码调用 `append()`, `get()`, `set()`, `delete()` 等方法时，会直接调用 `url_search_params.cc` 中对应的 C++ 方法。

4. **用户点击包含查询参数的链接:** 当用户点击一个 `<a>` 标签，其 `href` 属性包含查询参数时，浏览器会解析这个 URL，并可能在内部使用 `URLSearchParams` 来处理这些参数。

5. **用户提交 HTML 表单 (GET 方法):** 当用户提交一个使用 GET 方法的 HTML 表单时，浏览器会将表单数据编码到 URL 的查询字符串中。这个过程涉及到 `URLSearchParams` 相关的编码逻辑。

**调试线索:**

* **设置断点:** 在 `url_search_params.cc` 中设置断点，例如在 `append()`, `get()`, `SetInputWithoutUpdate()` 等方法中，可以跟踪 JavaScript 代码对 `URLSearchParams` 的操作是如何在 C++ 层执行的。
* **查看 V8 堆栈:**  当在 JavaScript 中调用 `URLSearchParams` 的方法时，可以查看 V8 的调用堆栈，以了解调用是如何传递到 C++ 层的。
* **使用 Chrome 的开发者工具:**
    * **Sources 面板:** 查看 JavaScript 代码的执行流程。
    * **Network 面板:** 观察网络请求的 URL，包括查询参数，以验证是否符合预期。
    * **Console 面板:**  在 JavaScript 中打印 `URLSearchParams` 对象的内容或调用其方法的结果。
* **检查 Feature Flags:** 注意代码中使用了 `RuntimeEnabledFeatures::URLSearchParamsHasAndDeleteMultipleArgsEnabled()` 等 Feature Flags，这些标志会影响某些方法的行为。调试时需要考虑这些标志的状态。

总而言之，`blink/renderer/core/url/url_search_params.cc` 是 Blink 引擎中处理 URL 查询参数的核心组件，它为 JavaScript 提供了 `URLSearchParams` API 的底层实现，并参与了浏览器对 HTML 中 URL 的解析和处理过程。 理解这个文件的功能对于理解浏览器如何处理 URL 以及如何调试与 URL 查询参数相关的 Web 应用问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/url/url_search_params.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/url/url_search_params.h"

#include <algorithm>
#include <utility>

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_usvstring_usvstringsequencesequence_usvstringusvstringrecord.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/url/dom_url.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/network/form_data_encoder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

namespace blink {

namespace {

class URLSearchParamsIterationSource final
    : public PairSyncIterable<URLSearchParams>::IterationSource {
 public:
  explicit URLSearchParamsIterationSource(URLSearchParams* params)
      : params_(params), current_(0) {}

  bool FetchNextItem(ScriptState*,
                     String& key,
                     String& value,
                     ExceptionState&) override {
    if (current_ >= params_->Params().size())
      return false;

    key = params_->Params()[current_].first;
    value = params_->Params()[current_].second;
    current_++;
    return true;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(params_);
    PairSyncIterable<URLSearchParams>::IterationSource::Trace(visitor);
  }

 private:
  Member<URLSearchParams> params_;
  wtf_size_t current_;
};

bool CompareParams(const std::pair<String, String>& a,
                   const std::pair<String, String>& b) {
  return WTF::CodeUnitCompareLessThan(a.first, b.first);
}

}  // namespace

URLSearchParams* URLSearchParams::Create(const URLSearchParamsInit* init,
                                         ExceptionState& exception_state) {
  DCHECK(init);
  switch (init->GetContentType()) {
    case URLSearchParamsInit::ContentType::kUSVString: {
      const String& query_string = init->GetAsUSVString();
      if (query_string.StartsWith('?'))
        return MakeGarbageCollected<URLSearchParams>(query_string.Substring(1));
      return MakeGarbageCollected<URLSearchParams>(query_string);
    }
    case URLSearchParamsInit::ContentType::kUSVStringSequenceSequence:
      return URLSearchParams::Create(init->GetAsUSVStringSequenceSequence(),
                                     exception_state);
    case URLSearchParamsInit::ContentType::kUSVStringUSVStringRecord:
      return URLSearchParams::Create(init->GetAsUSVStringUSVStringRecord(),
                                     exception_state);
  }
  NOTREACHED();
}

URLSearchParams* URLSearchParams::Create(const Vector<Vector<String>>& init,
                                         ExceptionState& exception_state) {
  URLSearchParams* instance = MakeGarbageCollected<URLSearchParams>(String());
  if (!init.size())
    return instance;
  for (unsigned i = 0; i < init.size(); ++i) {
    const Vector<String>& pair = init[i];
    if (pair.size() != 2) {
      exception_state.ThrowTypeError(ExceptionMessages::FailedToConstruct(
          "URLSearchParams",
          "Sequence initializer must only contain pair elements"));
      return nullptr;
    }
    instance->AppendWithoutUpdate(pair[0], pair[1]);
  }
  return instance;
}

URLSearchParams::URLSearchParams(const String& query_string, DOMURL* url_object)
    : url_object_(url_object) {
  if (!query_string.empty())
    SetInputWithoutUpdate(query_string);
}

URLSearchParams* URLSearchParams::Create(
    const Vector<std::pair<String, String>>& init,
    ExceptionState& exception_state) {
  URLSearchParams* instance = MakeGarbageCollected<URLSearchParams>(String());
  if (init.empty())
    return instance;
  for (const auto& item : init)
    instance->AppendWithoutUpdate(item.first, item.second);
  return instance;
}

URLSearchParams::~URLSearchParams() = default;

void URLSearchParams::Trace(Visitor* visitor) const {
  visitor->Trace(url_object_);
  ScriptWrappable::Trace(visitor);
}

#if DCHECK_IS_ON()
DOMURL* URLSearchParams::UrlObject() const {
  return url_object_;
}
#endif

void URLSearchParams::RunUpdateSteps() {
  if (!url_object_)
    return;

  if (url_object_->IsInUpdate())
    return;

  url_object_->SetSearchInternal(toString());
}

static String DecodeString(String input) {
  // |DecodeURLMode::kUTF8| is used because "UTF-8 decode without BOM" should
  // be performed (see https://url.spec.whatwg.org/#concept-urlencoded-parser).
  return DecodeURLEscapeSequences(input.Replace('+', ' '),
                                  DecodeURLMode::kUTF8);
}

void URLSearchParams::SetInputWithoutUpdate(const String& query_string) {
  params_.clear();

  wtf_size_t start = 0;
  wtf_size_t query_string_length = query_string.length();
  while (start < query_string_length) {
    wtf_size_t name_start = start;
    wtf_size_t name_value_end = query_string.find('&', start);
    if (name_value_end == kNotFound)
      name_value_end = query_string_length;
    if (name_value_end > start) {
      wtf_size_t end_of_name = query_string.find('=', start);
      if (end_of_name == kNotFound || end_of_name > name_value_end)
        end_of_name = name_value_end;
      String name = DecodeString(
          query_string.Substring(name_start, end_of_name - name_start));
      String value;
      if (end_of_name != name_value_end)
        value = DecodeString(query_string.Substring(
            end_of_name + 1, name_value_end - end_of_name - 1));
      if (value.IsNull())
        value = "";
      AppendWithoutUpdate(name, value);
    }
    start = name_value_end + 1;
  }
}

String URLSearchParams::toString() const {
  Vector<char> encoded_data;
  EncodeAsFormData(encoded_data);
  return String(encoded_data);
}

uint32_t URLSearchParams::size() const {
  return params_.size();
}

void URLSearchParams::AppendWithoutUpdate(const String& name,
                                          const String& value) {
  params_.push_back(std::make_pair(name, value));
}

void URLSearchParams::append(const String& name, const String& value) {
  AppendWithoutUpdate(name, value);
  RunUpdateSteps();
}

void URLSearchParams::deleteAllWithNameOrTuple(
    ExecutionContext* execution_context,
    const String& name) {
  deleteAllWithNameOrTuple(execution_context, name, String());
}

void URLSearchParams::deleteAllWithNameOrTuple(
    ExecutionContext* execution_context,
    const String& name,
    const String& val) {
  String value = val;
  if (!RuntimeEnabledFeatures::
          URLSearchParamsHasAndDeleteMultipleArgsEnabled()) {
    value = String();
  }
  // TODO(debadree333): Remove the code to count
  // kURLSearchParamsDeleteFnBehaviourDiverged in October 2023.
  Vector<wtf_size_t, 1u> indices_to_remove_with_name_value;
  Vector<wtf_size_t, 1u> indices_to_remove_with_name;

  for (wtf_size_t i = 0; i < params_.size(); i++) {
    if (params_[i].first == name) {
      indices_to_remove_with_name.push_back(i);
      if (params_[i].second == value || value.IsNull()) {
        indices_to_remove_with_name_value.push_back(i);
      }
    }
  }

  if (indices_to_remove_with_name_value != indices_to_remove_with_name) {
    UseCounter::Count(execution_context,
                      WebFeature::kURLSearchParamsDeleteFnBehaviourDiverged);
  }

  for (auto it = indices_to_remove_with_name_value.rbegin();
       it != indices_to_remove_with_name_value.rend(); ++it) {
    params_.EraseAt(*it);
  }

  RunUpdateSteps();
}

String URLSearchParams::get(const String& name) const {
  for (const auto& param : params_) {
    if (param.first == name) {
      return param.second;
    }
  }
  return String();
}

Vector<String> URLSearchParams::getAll(const String& name) const {
  Vector<String> result;
  for (const auto& param : params_) {
    if (param.first == name) {
      result.push_back(param.second);
    }
  }
  return result;
}

bool URLSearchParams::has(ExecutionContext* execution_context,
                          const String& name) const {
  return has(execution_context, name, String());
}

bool URLSearchParams::has(ExecutionContext* execution_context,
                          const String& name,
                          const String& val) const {
  String value = val;
  if (!RuntimeEnabledFeatures::
          URLSearchParamsHasAndDeleteMultipleArgsEnabled()) {
    value = String();
  }
  // TODO(debadree333): Remove the code to count
  // kURLSearchParamsHasFnBehaviourDiverged in October 2023.
  bool found_match_using_name_and_value = false;
  bool found_match_using_name = false;
  for (const auto& param : params_) {
    const bool name_matched = (param.first == name);
    if (name_matched) {
      found_match_using_name = true;
    }
    if (name_matched && (value.IsNull() || param.second == value)) {
      found_match_using_name_and_value = true;
      break;
    }
  }

  if (found_match_using_name_and_value != found_match_using_name) {
    UseCounter::Count(execution_context,
                      WebFeature::kURLSearchParamsHasFnBehaviourDiverged);
  }
  return found_match_using_name_and_value;
}

void URLSearchParams::set(const String& name, const String& value) {
  bool found_match = false;
  for (wtf_size_t i = 0; i < params_.size();) {
    // If there are any name-value whose name is 'name', set
    // the value of the first such name-value pair to 'value'
    // and remove the others.
    if (params_[i].first == name) {
      if (!found_match) {
        params_[i++].second = value;
        found_match = true;
      } else {
        params_.EraseAt(i);
      }
    } else {
      i++;
    }
  }
  // Otherwise, append a new name-value pair to the list.
  if (!found_match) {
    append(name, value);
  } else {
    RunUpdateSteps();
  }
}

void URLSearchParams::sort() {
  std::stable_sort(params_.begin(), params_.end(), CompareParams);
  RunUpdateSteps();
}

void URLSearchParams::EncodeAsFormData(Vector<char>& encoded_data) const {
  for (const auto& param : params_) {
    FormDataEncoder::AddKeyValuePairAsFormData(
        encoded_data, param.first.Utf8(), param.second.Utf8(),
        EncodedFormData::kFormURLEncoded, FormDataEncoder::kDoNotNormalizeCRLF);
  }
}

scoped_refptr<EncodedFormData> URLSearchParams::ToEncodedFormData() const {
  Vector<char> encoded_data;
  EncodeAsFormData(encoded_data);
  return EncodedFormData::Create(encoded_data);
}

PairSyncIterable<URLSearchParams>::IterationSource*
URLSearchParams::CreateIterationSource(ScriptState*, ExceptionState&) {
  return MakeGarbageCollected<URLSearchParamsIterationSource>(this);
}

}  // namespace blink

"""

```