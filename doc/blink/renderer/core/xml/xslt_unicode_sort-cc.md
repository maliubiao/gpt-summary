Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its function and its relationship to web technologies.

1. **Initial Skim and Keywords:**  The first step is a quick read-through, looking for obvious keywords and structure. I see: `xslt`, `unicode`, `sort`, `collator`, `libxslt`, `icu`, `javascript`, `html`, `css`. This immediately tells me it's about sorting, likely for XML/XSLT, and involves Unicode. The presence of `libxslt` and `icu` are strong indicators.

2. **Copyright Notice:**  The copyright notice points to Apple, which is relevant as it's part of the Blink engine (originated from WebKit).

3. **Include Headers:**  The included headers provide vital clues:
    * `xslt_unicode_sort.h`:  This file defines the interface of the code.
    * `libxslt/templates.h`, `libxslt/xsltutils.h`:  Confirms the XSLT context.
    * `<array>`, `<memory>`: Standard C++ for data structures and memory management.
    * `third_party/blink/renderer/platform/wtf/text/wtf_string.h`:  Indicates Blink's string handling.
    * `third_party/icu/source/common/unicode/uloc.h`, `third_party/icu/source/i18n/unicode/ucol.h`:  Crucial. This signifies the use of the International Components for Unicode (ICU) library for advanced internationalization features, specifically collation (sorting).

4. **Namespace:** The code is within the `blink` namespace, confirming it's part of the Blink rendering engine.

5. **Internal Helper Class (`UCollatorDeleter`, `UCollatorHolder`):**  These are implementation details. `UCollatorDeleter` is for proper resource cleanup of ICU collators. `UCollatorHolder` seems to be a mechanism for caching collators to improve performance, storing the collator itself and its associated locale information.

6. **`ToXMLChar` Function:** A simple helper to cast `char*` to `xmlChar*`.

7. **Core Function: `XsltUnicodeSortFunction`:**  This is the heart of the code. The function signature `xsltTransformContextPtr ctxt, xmlNodePtr* sorts, int nbsorts` strongly suggests this is a custom sorting function used within the libxslt transformation process. The parameters hint at the context of the transformation and the sorting criteria.

8. **Dissecting `XsltUnicodeSortFunction`:**
    * **Input Validation:** The initial checks (`!ctxt`, `!sorts`, etc.) ensure the input is valid.
    * **Retrieving Sort Information:** The code retrieves sorting parameters (data type, order, language) from the `sorts` array, which represents `<xsl:sort>` elements in the XSLT stylesheet.
    * **Handling `data-type`:**  It checks for the `data-type` attribute (`text` or `number`) to determine if the sorting should be lexicographical or numerical.
    * **Handling `order`:** It checks for the `order` attribute (`ascending` or `descending`).
    * **Locale Handling (ICU):** This is a key part. It fetches the language information from the XSLT and uses `ucol_getFunctionalEquivalent` to get the appropriate locale for sorting. It also uses the `cached_collator` to potentially reuse an existing ICU collator instance, which is an optimization. It sets collation attributes like `UCOL_CASE_FIRST` (for case-sensitive sorting) and `UCOL_NORMALIZATION_MODE`.
    * **Sorting Algorithm (Shell Sort):** The core sorting logic is implemented using a Shell sort algorithm.
    * **Comparison Logic:** Inside the sort, the code compares elements:
        * **Numerical comparison:** If `data-type="number"`, it compares floating-point values, handling NaN according to the XSLT specification.
        * **Unicode string comparison:** If `data-type="text"` (or default), it uses `ucol_strcoll` from ICU to perform a locale-aware Unicode string comparison.
    * **Multi-level Sorting:** The code handles multiple `<xsl:sort>` elements by iterating through the `sorts` array and refining the sort order based on subsequent criteria if the initial comparison is equal.
    * **Tie-breaking:** If all sorting criteria are equal, it uses the original document order (`results[j]->index > results[j + incr]->index`) as a tiebreaker.
    * **Memory Management:** The code carefully manages memory, freeing allocated resources.

9. **Connecting to Web Technologies (JavaScript, HTML, CSS):** This is where we bridge the gap.
    * **XSLT and HTML:** XSLT transformations are often used server-side to transform XML data into HTML for display in the browser.
    * **JavaScript and XSLT:** JavaScript can trigger XSLT transformations in the browser or on the server. The results are then used to dynamically update the HTML content.
    * **CSS and XSLT:**  While CSS doesn't directly interact with this sorting logic, the final sorted HTML will be styled using CSS.

10. **Hypothetical Input/Output:**  Creating simple examples helps illustrate the functionality.

11. **Common Usage Errors:** Thinking about how developers might misuse XSLT sorting helps identify potential pitfalls.

12. **Debugging Scenario:**  Tracing a user action back to this code helps understand its role in the overall rendering process.

13. **Refining and Organizing:** Finally, structuring the analysis with clear headings and explanations makes it easier to understand. I tried to use terms like "Functionality," "Relationship to Web Technologies," "Logic Reasoning," "Common Usage Errors," and "Debugging Clues" to match the prompt's requirements.
这个文件 `blink/renderer/core/xml/xslt_unicode_sort.cc` 实现了 **XSLT 转换过程中对 XML 数据进行 Unicode 感知的排序功能**。  它主要负责处理 XSLT 样式表中的 `<xsl:sort>` 指令，并使用 ICU (International Components for Unicode) 库来进行准确的、与语言环境相关的字符串比较。

**功能详细说明:**

1. **处理 XSLT 排序指令:** 当 XSLT 引擎在转换 XML 文档时遇到 `<xsl:sort>` 元素时，会调用 `XsltUnicodeSortFunction` 来执行排序。这个函数接收转换上下文 (`xsltTransformContextPtr`)、排序节点列表 (`xmlNodePtr* sorts`) 和排序节点数量 (`nbsorts`) 作为参数。

2. **提取排序参数:** 函数会解析 `<xsl:sort>` 元素中的属性，例如：
   - `data-type`:  指定排序的数据类型，可以是 "text" (默认) 或 "number"。
   - `order`: 指定排序顺序，可以是 "ascending" (默认) 或 "descending"。
   - `lang`: 指定排序使用的语言环境。
   - 其他 ICU 相关的排序属性 (虽然代码中只直接使用了 `lang` 和 `case-order` 的映射，但 libxslt 的底层可能支持更多)。

3. **使用 ICU 进行 Unicode 比较:** 
   - **创建 ICU Collator:**  根据 `<xsl:sort>` 中指定的 `lang` 属性，函数会创建一个 ICU `UCollator` 对象。 `UCollator` 负责执行与特定语言规则相符的字符串比较。
   - **处理语言环境:**  代码尝试获取与指定 `lang` 最匹配的 ICU locale。如果找不到完全匹配的，会回退到 "root" locale。
   - **设置排序属性:**  根据 `<xsl:sort>` 的属性，设置 `UCollator` 的属性，例如 `UCOL_CASE_FIRST` 来控制大小写排序的优先级 (映射自 Blink 特有的 `lower-first` 属性)。
   - **执行比较:**  对于要排序的每个节点，函数会提取其用于排序的字符串值（通过 `xsltComputeSortResult`），然后使用 `ucol_strcoll` 函数进行 Unicode 感知的字符串比较。对于 `data-type="number"` 的情况，会进行数值比较，并特殊处理 NaN 值。

4. **多级排序支持:**  如果 XSLT 样式表中有多个 `<xsl:sort>` 元素，`XsltUnicodeSortFunction` 会按照它们出现的顺序进行多级排序。只有当两个节点在前一个排序级别比较相等时，才会使用下一个排序级别进行比较。

5. **Shell 排序算法:**  代码内部使用了 Shell 排序算法来对节点列表进行排序。

**与 JavaScript, HTML, CSS 的关系举例说明:**

这个 C++ 代码本身并不直接与 JavaScript, HTML, CSS 交互。它位于 Blink 引擎的底层，负责处理 XML 和 XSLT 的转换。然而，它的功能是 **支撑** 这些 Web 技术的正确运行，尤其是在涉及到国际化和本地化时。

**举例说明:**

假设我们有一个包含书籍信息的 XML 文档，需要按照书名排序，并且要正确处理不同语言的排序规则。

**XML 数据 (books.xml):**

```xml
<books>
  <book title="Äpfel" lang="de"/>
  <book title="Bananas" lang="en"/>
  <book title="Cerises" lang="fr"/>
  <book title="Zucchine" lang="it"/>
</books>
```

**XSLT 样式表 (sort.xsl):**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/books">
    <html>
      <head>
        <title>Sorted Books</title>
      </head>
      <body>
        <h1>Sorted Books</h1>
        <ul>
          <xsl:for-each select="book">
            <xsl:sort select="@title" data-type="text" lang="{@lang}"/>
            <li><xsl:value-of select="@title"/></li>
          </xsl:for-each>
        </ul>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**用户操作和代码关系:**

1. **用户访问网页:** 用户在浏览器中打开一个网页，该网页可能通过 JavaScript 加载 XML 数据并应用 XSLT 转换。
2. **JavaScript 执行 XSLT 转换 (可能):**  JavaScript 可以使用 `XSLTProcessor` 对象来加载 `books.xml` 和 `sort.xsl`，并执行转换。
3. **Blink 引擎处理 XSLT:** 当浏览器渲染网页时，Blink 引擎会解析 XSLT 样式表。
4. **遇到 `<xsl:sort>`:** 当遇到 `<xsl:sort select="@title" data-type="text" lang="{@lang}"/>` 时，Blink 引擎会调用 `XsltUnicodeSortFunction`。
5. **`XsltUnicodeSortFunction` 执行排序:**
   - 它会针对每个 `<book>` 元素，提取其 `title` 属性的值。
   - 它会根据 `<book>` 元素的 `lang` 属性，例如 "de"、"en"、"fr" 等，创建对应的 ICU `UCollator`。
   - 它会使用 ICU 的排序规则来比较书名，例如，德语中 "Ä" 会被正确地放在 "A" 和 "B" 之间。
   - 它会将 `<book>` 元素按照书名进行排序。
6. **生成 HTML:** XSLT 转换完成后，会生成排序后的 HTML 代码。
7. **浏览器渲染 HTML:** 浏览器接收到排序后的 HTML，并将其渲染到页面上，用户看到的是按照书名正确排序的书籍列表。

**输出示例 (生成的 HTML):**

```html
<html>
  <head>
    <title>Sorted Books</title>
  </head>
  <body>
    <h1>Sorted Books</h1>
    <ul>
      <li>Äpfel</li>
      <li>Bananas</li>
      <li>Cerises</li>
      <li>Zucchine</li>
    </ul>
  </body>
</html>
```

**逻辑推理 (假设输入与输出):**

**假设输入 (来自 `<xsl:sort>`):**

- `select`: "@title"
- `data-type`: "text"
- `lang`: "de" (对于 "Äpfel") 和 "en" (对于 "Bananas")

**代码逻辑推理:**

1. 对于 "Äpfel" (lang="de") 和 "Bananas" (lang="en")，`XsltUnicodeSortFunction` 会分别创建德语和英语的 `UCollator` 对象。
2. 使用德语的 `UCollator` 比较 "Äpfel" 和 "Bananas"。根据德语排序规则，"Ä" 通常排在 "A" 和 "B" 之间。
3. 因此，"Äpfel" 会排在 "Bananas" 之前。

**假设输出 (比较结果):**

- `ucol_strcoll` 函数比较 "Äpfel" 和 "Bananas" (使用德语 collator) 返回一个负数，表示 "Äpfel" 小于 "Bananas"。

**常见的使用错误及举例说明:**

1. **未指定 `lang` 属性:** 如果 `<xsl:sort>` 元素没有指定 `lang` 属性，代码可能会使用默认的 locale (通常是 "en") 进行排序，这可能导致非英语文本的排序不正确。

   ```xml
   <!-- 缺少 lang 属性，可能导致排序错误 -->
   <xsl:sort select="@title" data-type="text"/>
   ```

   **错误结果:** 包含非英语字符的书名可能不会按照其语言的正确顺序排序。

2. **`data-type` 设置不正确:** 如果要排序的是数字，但 `data-type` 设置为 "text"，则会进行字符串比较，导致排序不符合预期。

   ```xml
   <!-- 假设 price 属性是数字，但 data-type 设置为 text -->
   <xsl:sort select="@price" data-type="text"/>
   ```

   **错误结果:**  字符串比较 "10" 会小于 "2"，而不是数值比较的结果。

3. **locale 名称拼写错误:**  如果在 `lang` 属性中使用了错误的 locale 名称，ICU 可能无法找到对应的 collator，或者回退到默认 locale，导致排序不符合预期。

   ```xml
   <!-- 错误的 locale 名称 "de-GERMANY" -->
   <xsl:sort select="@title" data-type="text" lang="de-GERMANY"/>
   ```

   **错误结果:**  排序可能按照与预期不同的规则进行。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载包含 XSLT 转换的网页:** 用户在地址栏输入网址或点击链接，浏览器开始加载网页。
2. **浏览器解析 HTML 并发现需要执行 XSLT 转换:** 网页的 HTML 可能包含内联的 XSLT 样式表，或者 JavaScript 代码指示浏览器需要对某些 XML 数据应用 XSLT 转换。
3. **Blink 引擎启动 XSLT 处理流程:** Blink 引擎的 XML 解析器和 XSLT 处理器开始工作。
4. **XSLT 处理器遇到 `<xsl:sort>` 元素:**  在解析和执行 XSLT 样式表的过程中，遇到了需要对节点进行排序的指令 `<xsl:sort>`。
5. **调用 `XsltUnicodeSortFunction`:** Blink 引擎会调用 `blink/renderer/core/xml/xslt_unicode_sort.cc` 中实现的 `XsltUnicodeSortFunction` 来执行排序操作。
6. **`XsltUnicodeSortFunction` 内部逻辑执行:** 函数会根据 `<xsl:sort>` 的属性，使用 ICU 库进行 Unicode 感知的比较和排序。

**作为调试线索:**

- 如果在网页上发现 XML 数据排序不正确，尤其是在涉及到非英语字符时，可以怀疑是 `XsltUnicodeSortFunction` 的行为不符合预期。
- 可以检查 XSLT 样式表中 `<xsl:sort>` 元素的属性，例如 `lang` 和 `data-type` 是否设置正确。
- 可以尝试使用不同的 `lang` 值来观察排序结果的变化，以确定是否是 locale 设置的问题。
- 如果怀疑是 ICU 库的问题，可以尝试使用其他 XSLT 处理器来比较排序结果。
- 在 Blink 引擎的调试版本中，可以设置断点在 `XsltUnicodeSortFunction` 内部，查看 ICU collator 的创建、属性设置以及字符串比较的结果，以深入了解排序过程。
- 检查控制台或日志输出，看是否有与 XSLT 转换或 ICU 相关的错误或警告信息。

总而言之，`blink/renderer/core/xml/xslt_unicode_sort.cc` 是 Blink 引擎中一个关键的组件，它确保了在进行 XSLT 转换时，能够对 XML 数据进行准确的、国际化的排序，这对于构建支持多语言内容的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/xml/xslt_unicode_sort.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2007, 2008, 2009 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/xml/xslt_unicode_sort.h"

#include <libxslt/templates.h>
#include <libxslt/xsltutils.h>

#include <array>
#include <memory>

#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/icu/source/common/unicode/uloc.h"
#include "third_party/icu/source/i18n/unicode/ucol.h"

namespace blink {

namespace {

class UCollatorDeleter {
 public:
  void operator()(UCollator* collator) { ucol_close(collator); }
};

struct UCollatorHolder {
  std::unique_ptr<UCollator, UCollatorDeleter> collator;
  char equivalent_locale[ULOC_FULLNAME_CAPACITY];
  bool lower_first = false;

  operator UCollator*() const { return collator.get(); }
};

}  // namespace

inline const xmlChar* ToXMLChar(const char* string) {
  return reinterpret_cast<const xmlChar*>(string);
}

// Based on default implementation from libxslt 1.1.22 and xsltICUSort.c
// example.
void XsltUnicodeSortFunction(xsltTransformContextPtr ctxt,
                             xmlNodePtr* sorts,
                             int nbsorts) {
#ifdef XSLT_REFACTORED
  xsltStyleItemSortPtr comp;
#else
  xsltStylePreCompPtr comp;
#endif
  xmlXPathObjectPtr* results_tab[XSLT_MAX_SORT];
  xmlXPathObjectPtr* results = nullptr;
  xmlNodeSetPtr list = nullptr;
  int depth;
  xmlNodePtr node;
  std::array<int, XSLT_MAX_SORT> tempstype, temporder;

  if (!ctxt || !sorts || nbsorts <= 0 || nbsorts >= XSLT_MAX_SORT)
    return;
  if (!sorts[0])
    return;
  comp = static_cast<xsltStylePreComp*>(sorts[0]->psvi);
  if (!comp)
    return;

  list = ctxt->nodeList;
  if (!list || list->nodeNr <= 1)
    return;  // Nothing to do.

  for (int j = 0; j < nbsorts; ++j) {
    comp = static_cast<xsltStylePreComp*>(sorts[j]->psvi);
    tempstype[j] = 0;
    if (!comp->stype && comp->has_stype) {
      comp->stype = xsltEvalAttrValueTemplate(
          ctxt, sorts[j], ToXMLChar("data-type"), XSLT_NAMESPACE);
      if (comp->stype) {
        tempstype[j] = 1;
        if (xmlStrEqual(comp->stype, ToXMLChar("text"))) {
          comp->number = 0;
        } else if (xmlStrEqual(comp->stype, ToXMLChar("number"))) {
          comp->number = 1;
        } else {
          xsltTransformError(
              ctxt, nullptr, sorts[j],
              "xsltDoSortFunction: no support for data-type = %s\n",
              comp->stype);
          comp->number = 0;  // Use default.
        }
      }
    }
    temporder[j] = 0;
    if (!comp->order && comp->has_order) {
      comp->order = xsltEvalAttrValueTemplate(
          ctxt, sorts[j], ToXMLChar("order"), XSLT_NAMESPACE);
      if (comp->order) {
        temporder[j] = 1;
        if (xmlStrEqual(comp->order, ToXMLChar("ascending"))) {
          comp->descending = 0;
        } else if (xmlStrEqual(comp->order, ToXMLChar("descending"))) {
          comp->descending = 1;
        } else {
          xsltTransformError(ctxt, nullptr, sorts[j],
                             "xsltDoSortFunction: invalid value %s for order\n",
                             comp->order);
          comp->descending = 0;  // Use default.
        }
      }
    }
  }

  int len = list->nodeNr;

  results_tab[0] = xsltComputeSortResult(ctxt, sorts[0]);
  for (int i = 1; i < XSLT_MAX_SORT; ++i)
    results_tab[i] = nullptr;

  results = results_tab[0];

  comp = static_cast<xsltStylePreComp*>(sorts[0]->psvi);
  int descending = comp->descending;
  int number = comp->number;
  if (!results)
    return;

  // We are passing a language identifier to a function that expects a locale
  // identifier. The implementation of Collator should be lenient, and accept
  // both "en-US" and "en_US", for example. This lets an author to really
  // specify sorting rules, e.g. "de_DE@collation=phonebook", which isn't
  // possible with language alone.
  const char* lang =
      comp->has_lang ? reinterpret_cast<const char*>(comp->lang) : "en";

  UErrorCode status = U_ZERO_ERROR;
  char equivalent_locale[ULOC_FULLNAME_CAPACITY];
  UBool is_available;
  ucol_getFunctionalEquivalent(equivalent_locale, ULOC_FULLNAME_CAPACITY,
                               "collation", lang, &is_available, &status);
  if (U_FAILURE(status)) {
    strcpy(equivalent_locale, "root");
    status = U_ZERO_ERROR;
  }

  DEFINE_STATIC_LOCAL(std::unique_ptr<UCollatorHolder>, cached_collator, ());
  std::unique_ptr<UCollatorHolder> collator;
  if (cached_collator &&
      !strcmp(cached_collator->equivalent_locale, equivalent_locale) &&
      cached_collator->lower_first == comp->lower_first) {
    collator = std::move(cached_collator);
  } else {
    collator = std::make_unique<UCollatorHolder>();
    strncpy(collator->equivalent_locale, equivalent_locale,
            ULOC_FULLNAME_CAPACITY);
    collator->lower_first = comp->lower_first;

    collator->collator.reset(ucol_open(lang, &status));
    if (U_FAILURE(status)) {
      status = U_ZERO_ERROR;
      collator->collator.reset(ucol_open("", &status));
    }
    DCHECK(U_SUCCESS(status));
    ucol_setAttribute(*collator, UCOL_CASE_FIRST,
                      comp->lower_first ? UCOL_LOWER_FIRST : UCOL_UPPER_FIRST,
                      &status);
    DCHECK(U_SUCCESS(status));
    ucol_setAttribute(*collator, UCOL_NORMALIZATION_MODE, UCOL_ON, &status);
    DCHECK(U_SUCCESS(status));
  }

  // Shell's sort of node-set.
  for (int incr = len / 2; incr > 0; incr /= 2) {
    for (int i = incr; i < len; ++i) {
      int j = i - incr;
      if (!results[i])
        continue;

      while (j >= 0) {
        int tst;
        if (!results[j]) {
          tst = 1;
        } else {
          if (number) {
            // We make NaN smaller than number in accordance with
            // XSLT spec.
            if (xmlXPathIsNaN(results[j]->floatval)) {
              if (xmlXPathIsNaN(results[j + incr]->floatval))
                tst = 0;
              else
                tst = -1;
            } else if (xmlXPathIsNaN(results[j + incr]->floatval)) {
              tst = 1;
            } else if (results[j]->floatval == results[j + incr]->floatval) {
              tst = 0;
            } else if (results[j]->floatval > results[j + incr]->floatval) {
              tst = 1;
            } else {
              tst = -1;
            }
          } else {
            Vector<UChar> string1;
            Vector<UChar> string2;
            String::FromUTF8(
                reinterpret_cast<const char*>(results[j]->stringval))
                .AppendTo(string1);
            String::FromUTF8(
                reinterpret_cast<const char*>(results[j + incr]->stringval))
                .AppendTo(string2);
            tst = ucol_strcoll(*collator, string1.data(), string1.size(),
                               string2.data(), string2.size());
          }
          if (descending)
            tst = -tst;
        }
        if (tst == 0) {
          // Okay we need to use multi level sorts.
          depth = 1;
          while (depth < nbsorts) {
            if (!sorts[depth])
              break;
            comp = static_cast<xsltStylePreComp*>(sorts[depth]->psvi);
            if (!comp)
              break;
            int desc = comp->descending;
            int numb = comp->number;

            // Compute the result of the next level for the full
            // set, this might be optimized ... or not
            if (!results_tab[depth])
              results_tab[depth] = xsltComputeSortResult(ctxt, sorts[depth]);
            xmlXPathObjectPtr* res = results_tab[depth];
            if (!res)
              break;
            if (!res[j]) {
              if (res[j + incr])
                tst = 1;
            } else {
              if (numb) {
                // We make NaN smaller than number in accordance
                // with XSLT spec.
                if (xmlXPathIsNaN(res[j]->floatval)) {
                  if (xmlXPathIsNaN(res[j + incr]->floatval))
                    tst = 0;
                  else
                    tst = -1;
                } else if (xmlXPathIsNaN(res[j + incr]->floatval)) {
                  tst = 1;
                } else if (res[j]->floatval == res[j + incr]->floatval) {
                  tst = 0;
                } else if (res[j]->floatval > res[j + incr]->floatval) {
                  tst = 1;
                } else {
                  tst = -1;
                }
              } else {
                Vector<UChar> string1;
                Vector<UChar> string2;
                String::FromUTF8(
                    reinterpret_cast<const char*>(res[j]->stringval))
                    .AppendTo(string1);
                String::FromUTF8(
                    reinterpret_cast<const char*>(res[j + incr]->stringval))
                    .AppendTo(string2);
                tst = ucol_strcoll(*collator, string1.data(), string1.size(),
                                   string2.data(), string2.size());
              }
              if (desc)
                tst = -tst;
            }

            // if we still can't differenciate at this level try one
            // level deeper.
            if (tst != 0)
              break;
            depth++;
          }
        }
        if (tst == 0) {
          tst = results[j]->index > results[j + incr]->index;
        }
        if (tst > 0) {
          xmlXPathObjectPtr tmp = results[j];
          results[j] = results[j + incr];
          results[j + incr] = tmp;
          node = list->nodeTab[j];
          list->nodeTab[j] = list->nodeTab[j + incr];
          list->nodeTab[j + incr] = node;
          depth = 1;
          while (depth < nbsorts) {
            if (!sorts[depth])
              break;
            if (!results_tab[depth])
              break;
            xmlXPathObjectPtr* res = results_tab[depth];
            tmp = res[j];
            res[j] = res[j + incr];
            res[j + incr] = tmp;
            depth++;
          }
          j -= incr;
        } else {
          break;
        }
      }
    }
  }

  for (int j = 0; j < nbsorts; ++j) {
    comp = static_cast<xsltStylePreComp*>(sorts[j]->psvi);
    if (tempstype[j] == 1) {
      // The data-type needs to be recomputed each time.
      xmlFree(const_cast<xmlChar*>(comp->stype));
      comp->stype = nullptr;
    }
    if (temporder[j] == 1) {
      // The order needs to be recomputed each time.
      xmlFree(const_cast<xmlChar*>(comp->order));
      comp->order = nullptr;
    }
    if (results_tab[j]) {
      for (int i = 0; i < len; ++i)
        xmlXPathFreeObject(results_tab[j][i]);
      xmlFree(results_tab[j]);
    }
  }

  cached_collator = std::move(collator);
}

}  // namespace blink

"""

```