Response:
Let's break down the thought process for analyzing the `counter_style_map.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies, examples, logical reasoning (with input/output), common usage errors, and how a user might trigger its execution.

2. **Initial Scan for Keywords and Structure:**  Look for key terms like `CounterStyleMap`, `CounterStyle`, `RuleSet`, `Document`, `TreeScope`, and mentions of CSS properties like `extends` and `fallback`. Notice the `#include` directives, which reveal dependencies on other Blink components. The class structure and methods like `AddCounterStyles`, `FindCounterStyleAcrossScopes`, `ResolveExtendsFor`, etc., provide clues about the file's purpose.

3. **Identify Core Functionality:** The name `CounterStyleMap` immediately suggests it's a container or manager for `CounterStyle` objects. The methods related to "add," "find," and "resolve" indicate it's involved in the lifecycle and management of these styles.

4. **Connect to Web Technologies:** The presence of terms like "CSS," "Document," and the handling of rules (`RuleSet`, `StyleRuleCounterStyle`) strongly imply a connection to CSS counter styles. Think about how CSS counter styles work (`@counter-style` rule) and how they might be managed in a browser engine.

5. **Explain the Core Functionality Concisely:** Summarize the main purpose of the `CounterStyleMap`: to manage and resolve `@counter-style` rules defined in CSS. Highlight its role in storing, retrieving, and handling inheritance (`extends`) and fallback mechanisms.

6. **Illustrate with Examples (CSS, HTML, JavaScript):**
    * **CSS:**  Provide a concrete `@counter-style` rule example to show how it's defined.
    * **HTML:** Show how these counter styles are applied to list items using `list-style-type`. This connects the backend management to the user-visible rendering.
    * **JavaScript:** Explain that while direct manipulation is less common, JavaScript's ability to modify CSS (e.g., through `document.styleSheets`) indirectly affects the `CounterStyleMap`.

7. **Logical Reasoning (Hypothetical Input/Output):**
    * **Input:**  Define a scenario where a new `@counter-style` rule is added.
    * **Process:** Explain how the `AddCounterStyles` method would handle this, including checking for overrides.
    * **Output:**  Describe the state of the `counter_styles_` map after the addition. This demonstrates how the code manipulates its internal data structures. Similarly, create an example for `FindCounterStyleAcrossScopes` demonstrating the hierarchical lookup.

8. **Common Usage Errors:**  Think about what could go wrong when defining `@counter-style` rules:
    * **Name Conflicts:** Two rules with the same name.
    * **Circular `extends`:** A -> extends B -> extends A.
    * **Missing `extends` or `fallback`:** Referencing a non-existent style.
    * **Incorrect Syntax:**  While the C++ code doesn't directly catch CSS syntax errors (that's the parser's job), understand how invalid CSS can lead to issues *handled* by this code (e.g., defaulting to `decimal`).

9. **Debugging Scenario (User Operations):**  Trace a typical user interaction that leads to the execution of this code:
    * User opens a web page.
    * Browser parses HTML and CSS.
    * During CSS parsing, `@counter-style` rules are encountered.
    * These rules are added to the `CounterStyleMap`.
    * When rendering lists, the browser needs to resolve the applied counter style. This involves the `FindCounterStyleAcrossScopes` and resolution methods.

10. **Consider Edge Cases and Advanced Concepts:**  The code mentions "user agent stylesheet," "author stylesheet," and "scoped stylesheets." Briefly touch upon how these different origins of CSS rules interact within the `CounterStyleMap`. The concept of cascade layers is also important, as seen in the `CounterStyleShouldOverride` function.

11. **Review and Refine:** Read through the explanation, ensuring clarity, accuracy, and completeness. Check for any jargon that needs explanation. Make sure the examples are easy to understand. Ensure the connection between the C++ code and the user's experience is clear. For instance, explicitly state *why* this file is important – it enables the correct rendering of lists with custom numbering.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on individual methods in isolation.
* **Correction:** Shift focus to the overall *purpose* and *workflow* of the `CounterStyleMap`. How do the methods work together?
* **Initial thought:**  Assume the reader has deep knowledge of Blink internals.
* **Correction:** Explain concepts like "TreeScope," "Document," and "StyleEngine" briefly to provide context.
* **Initial thought:** Overlook the debugging aspect of the request.
* **Correction:**  Add a detailed step-by-step user interaction scenario to illustrate how the code is reached.
* **Initial thought:** Not provide concrete examples.
* **Correction:**  Add clear CSS, HTML, and (indirectly) JavaScript examples to make the concepts tangible.

By following this structured approach and engaging in self-correction, we can generate a comprehensive and informative explanation of the `counter_style_map.cc` file.
这个文件是 Chromium Blink 渲染引擎中的 `counter_style_map.cc`，它主要负责**管理和解析 CSS `@counter-style` 规则**。

**核心功能:**

1. **存储 `@counter-style` 规则:**  它维护了一个映射表 (`counter_styles_`)，用于存储在 CSS 中定义的 `@counter-style` 规则。每个规则都与一个 `CounterStyle` 对象关联，该对象封装了规则的各种属性（例如 `system`, `symbols`, `range`, `prefix`, `suffix`, `extends`, `fallback` 等）。

2. **管理不同作用域的 `@counter-style` 规则:**  它区分用户代理（UA）、用户（user）和作者（author）定义的 `@counter-style` 规则，并且能够处理作用域样式（scoped styles）。不同的作用域可能定义了同名的 `@counter-style` 规则，`CounterStyleMap` 需要决定哪个规则生效。

3. **解析和解决 `extends` 引用:**  `@counter-style` 规则可以使用 `extends` 属性继承其他 `@counter-style` 规则的属性。`CounterStyleMap` 负责找到被继承的规则，并将继承关系解析到 `CounterStyle` 对象中。它还需要处理循环继承的情况。

4. **解析和解决 `fallback` 引用:**  `@counter-style` 规则可以使用 `fallback` 属性指定当自身无法生成计数器标记时的备用计数器样式。`CounterStyleMap` 负责找到备用的 `CounterStyle` 对象。

5. **解析和解决 `speak-as` 引用:**  `@counter-style` 规则可以使用 `speak-as` 属性指定如何将计数器值转换为语音输出。`CounterStyleMap` 负责找到引用的 `CounterStyle` 并处理循环引用的情况。

6. **确定哪个 `@counter-style` 规则生效:** 当多个 `@counter-style` 规则具有相同的名称时，`CounterStyleMap` 根据 CSS 层叠规则（例如，来源、重要性、顺序等）来决定哪个规则生效。 `CounterStyleShouldOverride` 函数就体现了这种逻辑，它会比较新规则和现有规则的层叠层级。

7. **标记需要更新的计数器样式:** 当 CSS 样式发生变化，例如添加、删除或修改了 `@counter-style` 规则时，`CounterStyleMap` 会标记相关的 `CounterStyle` 对象为“脏”（dirty），表示需要重新解析和应用这些样式。

8. **提供查找计数器样式的方法:**  提供了 `FindCounterStyleAcrossScopes` 方法，用于根据名称在当前作用域及其祖先作用域中查找生效的 `CounterStyle` 对象。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:**  `counter_style_map.cc` 直接处理 CSS 的 `@counter-style` 规则。这些规则定义了如何格式化列表项的编号或计数器的外观。
    * **例子:**  CSS 中定义 `@counter-style` 规则：
      ```css
      @counter-style thumbs {
        system: cyclic;
        symbols: "👍" "👎";
        suffix: " ";
      }

      ol {
        list-style-type: thumbs;
      }
      ```
      当浏览器解析到这段 CSS 时，`CounterStyleMap::AddCounterStyles` 方法会被调用，将 `thumbs` 规则的信息存储起来。

* **HTML:**  HTML 中的有序列表 (`<ol>`) 和可以使用计数器的元素，通过 CSS 的 `list-style-type` 属性或者 `counter()` 函数来引用 `@counter-style` 中定义的样式。
    * **例子:**  上述 CSS 代码中，`ol` 元素使用了名为 `thumbs` 的计数器样式。当渲染这个 `ol` 列表时，渲染引擎会通过 `CounterStyleMap` 找到 `thumbs` 对应的 `CounterStyle` 对象，并使用其定义的符号 "👍" 和 "👎" 来显示列表项的编号。

* **JavaScript:**  虽然 JavaScript 不直接操作 `counter_style_map.cc` 中的 C++ 对象，但 JavaScript 可以通过修改 DOM 元素的样式或动态添加 CSS 规则来间接影响 `CounterStyleMap` 的行为。
    * **例子:**  JavaScript 可以动态添加一个包含 `@counter-style` 规则的 `<style>` 标签到 HTML 文档中。这将触发浏览器的 CSS 解析过程，并导致 `CounterStyleMap` 更新其存储的计数器样式。
      ```javascript
      const style = document.createElement('style');
      style.textContent = `
        @counter-style stars {
          system: fixed;
          symbols: "*" "**" "***";
          suffix: ". ";
        }
        ol.stars {
          list-style-type: stars;
        }
      `;
      document.head.appendChild(style);
      ```
      这段 JavaScript 代码会创建一个名为 `stars` 的 `@counter-style`，并将其应用到一个带有 `stars` 类名的有序列表上。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **CSS 规则:**
   ```css
   @counter-style lower-roman-extended {
     system: extends lower-roman;
     prefix: "(";
     suffix: ")";
   }

   @counter-style lower-roman {
     system: additive;
     symbols: i v x l c d m;
     range: 1 3999;
   }
   ```

2. **HTML:**
   ```html
   <ol style="list-style-type: lower-roman-extended;">
     <li>Item 1</li>
     <li>Item 2</li>
   </ol>
   ```

**处理过程:**

1. 当浏览器解析 CSS 时，`CounterStyleMap::AddCounterStyles` 会被调用。
2. 首先添加 `lower-roman` 规则到 `counter_styles_`。
3. 然后添加 `lower-roman-extended` 规则。由于它使用了 `extends lower-roman`，`CounterStyleMap::ResolveExtendsFor` 方法会被调用。
4. `ResolveExtendsFor` 会查找名为 `lower-roman` 的 `CounterStyle` 对象。
5. 它会将 `lower-roman-extended` 的 `extends` 属性指向 `lower-roman`。

**输出:**

当渲染 `<ol>` 列表时，会应用 `lower-roman-extended` 计数器样式，其行为将基于 `lower-roman`，并添加了前缀 "(" 和后缀 ")"。列表项将显示为 "(i)" 和 "(ii)"。

**假设输入 (循环 extends):**

1. **CSS 规则:**
   ```css
   @counter-style style-a {
     system: extends style-b;
   }

   @counter-style style-b {
     system: extends style-a;
   }
   ```

**处理过程:**

1. 当解析这两个规则时，`CounterStyleMap::ResolveExtendsFor` 会检测到循环依赖。

**输出:**

根据代码中的注释，在这种情况下，参与循环的计数器样式将被视为继承了 `'decimal'` 计数器样式。因此，使用 `style-a` 或 `style-b` 的列表将回退到使用十进制数字编号。控制台可能会有警告信息。

**用户或编程常见的使用错误:**

1. **`@counter-style` 名称冲突:**  在同一个作用域内定义了两个相同名称的 `@counter-style` 规则。浏览器会根据层叠规则选择其中一个生效，可能会导致意想不到的样式。
   * **例子:**
     ```css
     @counter-style my-style { /* ... */ }
     @counter-style my-style { /* ... 不同的定义 */ }
     ```

2. **`extends` 或 `fallback` 指向不存在的 `@counter-style`:**  如果 `@counter-style` 规则的 `extends` 或 `fallback` 属性引用的名称在当前或祖先作用域中不存在，则该规则的行为可能不符合预期，通常会回退到默认的 `'decimal'` 样式。
   * **例子:**
     ```css
     @counter-style my-style {
       system: extends non-existent-style;
     }
     ```

3. **`extends` 造成循环依赖:**  如上面的逻辑推理示例所示，如果 `@counter-style` 规则之间形成了循环继承关系，浏览器会尝试打破循环，通常回退到 `'decimal'`。

4. **错误的 `@counter-style` 语法:** 虽然 `counter_style_map.cc` 不负责 CSS 语法解析，但如果 CSS 语法错误，相关的 `StyleRuleCounterStyle` 对象可能为空或包含错误信息，导致 `CounterStyleMap` 无法正确创建 `CounterStyle` 对象。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个包含 CSS 的网页。**
2. **浏览器开始解析 HTML 文档，构建 DOM 树。**
3. **当浏览器遇到 `<link>` 标签引用的外部 CSS 文件或 `<style>` 标签内的 CSS 代码时，开始解析 CSS。**
4. **CSS 解析器识别出 `@counter-style` 规则。**
5. **对于每个有效的 `@counter-style` 规则，浏览器会创建一个 `StyleRuleCounterStyle` 对象来表示该规则。**
6. **`StyleEngine` 将这些 `StyleRuleCounterStyle` 对象传递给 `CounterStyleMap` 的 `AddCounterStyles` 方法。**
7. **`AddCounterStyles` 方法会将这些规则存储到 `counter_styles_` 映射表中，并创建对应的 `CounterStyle` 对象。**
8. **如果 `@counter-style` 规则使用了 `extends` 或 `fallback` 属性，后续在样式计算阶段，`CounterStyleMap` 的 `ResolveExtendsFor` 和 `ResolveFallbackFor` 方法会被调用来解析这些引用。**
9. **当渲染引擎需要显示使用这些自定义计数器样式的列表或其他元素时，会调用 `CounterStyleMap::FindCounterStyleAcrossScopes` 来查找生效的 `CounterStyle` 对象。**

**调试线索:**

* **查看 "Styles" 面板:**  在 Chrome 开发者工具的 "Elements" 面板中，选择一个使用了自定义计数器样式的元素（例如 `<li>`）。在 "Styles" 面板中，可以查看该元素的 `list-style-type` 属性，以及是否成功应用了自定义的 `@counter-style`。如果应用失败，可能会显示默认的 `decimal` 或其他回退样式。
* **搜索 `@counter-style` 规则:**  在 "Sources" 面板中，可以搜索 CSS 文件中的 `@counter-style` 规则，检查其定义是否正确。
* **使用 "Computed" 面板:**  在 "Elements" 面板的 "Computed" 标签中，可以查看元素最终计算出的样式属性，虽然不会直接显示 `@counter-style` 的细节，但可以观察 `list-style-type` 的值。
* **断点调试:** 如果需要深入了解 `CounterStyleMap` 的工作原理，可以在 `counter_style_map.cc` 中的关键方法（例如 `AddCounterStyles`, `ResolveExtendsFor`, `FindCounterStyleAcrossScopes`）设置断点，并加载包含自定义计数器样式的网页，观察代码的执行流程和变量的值。
* **查看控制台警告/错误:**  浏览器控制台可能会输出关于无效 `@counter-style` 规则或循环 `extends` 的警告信息。

总而言之，`counter_style_map.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责解析、管理和应用 CSS `@counter-style` 规则，使得开发者能够创建自定义的列表编号和计数器样式，从而丰富网页的视觉呈现效果。

### 提示词
```
这是目录为blink/renderer/core/css/counter_style_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/counter_style_map.h"

#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule_counter_style.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"

namespace blink {

namespace {

bool CounterStyleShouldOverride(Document& document,
                                const TreeScope* tree_scope,
                                const StyleRuleCounterStyle& new_rule,
                                const StyleRuleCounterStyle& existing_rule) {
  const CascadeLayerMap* cascade_layer_map =
      tree_scope ? tree_scope->GetScopedStyleResolver()->GetCascadeLayerMap()
                 : document.GetStyleEngine().GetUserCascadeLayerMap();
  if (!cascade_layer_map) {
    return true;
  }
  return cascade_layer_map->CompareLayerOrder(existing_rule.GetCascadeLayer(),
                                              new_rule.GetCascadeLayer()) <= 0;
}

}  // namespace

// static
CounterStyleMap* CounterStyleMap::GetUserCounterStyleMap(Document& document) {
  return document.GetStyleEngine().GetUserCounterStyleMap();
}

// static
CounterStyleMap* CounterStyleMap::GetAuthorCounterStyleMap(
    const TreeScope& scope) {
  if (!scope.GetScopedStyleResolver()) {
    return nullptr;
  }
  return scope.GetScopedStyleResolver()->GetCounterStyleMap();
}

// static
CounterStyleMap* CounterStyleMap::CreateUserCounterStyleMap(
    Document& document) {
  return MakeGarbageCollected<CounterStyleMap>(&document, nullptr);
}

// static
CounterStyleMap* CounterStyleMap::CreateAuthorCounterStyleMap(
    TreeScope& tree_scope) {
  return MakeGarbageCollected<CounterStyleMap>(&tree_scope.GetDocument(),
                                               &tree_scope);
}

CounterStyleMap::CounterStyleMap(Document* document, TreeScope* tree_scope)
    : owner_document_(document), tree_scope_(tree_scope) {
#if DCHECK_IS_ON()
  if (tree_scope) {
    DCHECK_EQ(document, &tree_scope->GetDocument());
  }
#endif
}

void CounterStyleMap::AddCounterStyles(const RuleSet& rule_set) {
  DCHECK(owner_document_);

  if (!rule_set.CounterStyleRules().size()) {
    return;
  }

  for (StyleRuleCounterStyle* rule : rule_set.CounterStyleRules()) {
    AtomicString name = rule->GetName();
    auto replaced_iter = counter_styles_.find(name);
    if (replaced_iter != counter_styles_.end()) {
      if (!CounterStyleShouldOverride(*owner_document_, tree_scope_, *rule,
                                      replaced_iter->value->GetStyleRule())) {
        continue;
      }
    }
    CounterStyle* counter_style = CounterStyle::Create(*rule);
    if (!counter_style) {
      continue;
    }
    if (replaced_iter != counter_styles_.end()) {
      replaced_iter->value->SetIsDirty();
    }
    counter_styles_.Set(rule->GetName(), counter_style);
  }

  owner_document_->GetStyleEngine().MarkCounterStylesNeedUpdate();
}

CounterStyleMap* CounterStyleMap::GetAncestorMap() const {
  if (tree_scope_) {
    // Resursively walk up to parent scope to find an author CounterStyleMap.
    for (TreeScope* scope = tree_scope_->ParentTreeScope(); scope;
         scope = scope->ParentTreeScope()) {
      if (CounterStyleMap* map = GetAuthorCounterStyleMap(*scope)) {
        return map;
      }
    }

    // Fallback to user counter style map
    if (CounterStyleMap* user_map = GetUserCounterStyleMap(*owner_document_)) {
      return user_map;
    }
  }

  // Author and user counter style maps fall back to UA
  if (owner_document_) {
    return GetUACounterStyleMap();
  }

  // UA counter style map doesn't have any fallback
  return nullptr;
}

CounterStyle* CounterStyleMap::FindCounterStyleAcrossScopes(
    const AtomicString& name) const {
  if (!owner_document_) {
    const auto& iter = counter_styles_.find(name);
    if (iter == counter_styles_.end()) {
      return nullptr;
    }
    if (iter->value) {
      return iter->value.Get();
    }
    return &const_cast<CounterStyleMap*>(this)->CreateUACounterStyle(name);
  }
  auto it = counter_styles_.find(name);
  if (it != counter_styles_.end()) {
    return it->value.Get();
  }
  return GetAncestorMap()->FindCounterStyleAcrossScopes(name);
}

void CounterStyleMap::ResolveExtendsFor(CounterStyle& counter_style) {
  DCHECK(counter_style.HasUnresolvedExtends());

  HeapVector<Member<CounterStyle>, 2> extends_chain;
  HeapHashSet<Member<CounterStyle>> unresolved_styles;
  extends_chain.push_back(&counter_style);
  do {
    unresolved_styles.insert(extends_chain.back());
    AtomicString extends_name = extends_chain.back()->GetExtendsName();
    extends_chain.push_back(FindCounterStyleAcrossScopes(extends_name));
  } while (extends_chain.back() &&
           extends_chain.back()->HasUnresolvedExtends() &&
           !unresolved_styles.Contains(extends_chain.back()));

  // If one or more @counter-style rules form a cycle with their extends values,
  // all of the counter styles participating in the cycle must be treated as if
  // they were extending the 'decimal' counter style instead.
  if (extends_chain.back() && extends_chain.back()->HasUnresolvedExtends()) {
    // Predefined counter styles should not have 'extends' cycles, otherwise
    // we'll enter an infinite recursion to look for 'decimal'.
    DCHECK(owner_document_)
        << "'extends' cycle detected for predefined counter style "
        << counter_style.GetName();
    CounterStyle* cycle_start = extends_chain.back();
    do {
      extends_chain.back()->ResolveExtends(CounterStyle::GetDecimal());
      extends_chain.pop_back();
    } while (extends_chain.back() != cycle_start);
  }

  CounterStyle* next = extends_chain.back();
  while (extends_chain.size() > 1u) {
    extends_chain.pop_back();
    if (next) {
      extends_chain.back()->ResolveExtends(*next);
    } else {
      // Predefined counter styles should not use inexistent 'extends' names,
      // otherwise we'll enter an infinite recursion to look for 'decimal'.
      DCHECK(owner_document_) << "Can't resolve 'extends: "
                              << extends_chain.back()->GetExtendsName()
                              << "' for predefined counter style "
                              << extends_chain.back()->GetName();
      extends_chain.back()->ResolveExtends(CounterStyle::GetDecimal());
      extends_chain.back()->SetHasInexistentReferences();
    }

    next = extends_chain.back();
  }
}

void CounterStyleMap::ResolveFallbackFor(CounterStyle& counter_style) {
  DCHECK(counter_style.HasUnresolvedFallback());
  AtomicString fallback_name = counter_style.GetFallbackName();
  CounterStyle* fallback_style = FindCounterStyleAcrossScopes(fallback_name);
  if (fallback_style) {
    counter_style.ResolveFallback(*fallback_style);
  } else {
    // UA counter styles shouldn't use inexistent fallback style names,
    // otherwise we'll enter an infinite recursion to look for 'decimal'.
    DCHECK(owner_document_)
        << "Can't resolve fallback " << fallback_name
        << " for predefined counter style " << counter_style.GetName();
    counter_style.ResolveFallback(CounterStyle::GetDecimal());
    counter_style.SetHasInexistentReferences();
  }
}

void CounterStyleMap::ResolveSpeakAsReferenceFor(CounterStyle& counter_style) {
  DCHECK(counter_style.HasUnresolvedSpeakAsReference());

  HeapVector<Member<CounterStyle>, 2> speak_as_chain;
  HeapHashSet<Member<CounterStyle>> unresolved_styles;
  speak_as_chain.push_back(&counter_style);
  do {
    unresolved_styles.insert(speak_as_chain.back());
    AtomicString speak_as_name = speak_as_chain.back()->GetSpeakAsName();
    speak_as_chain.push_back(FindCounterStyleAcrossScopes(speak_as_name));
  } while (speak_as_chain.back() &&
           speak_as_chain.back()->HasUnresolvedSpeakAsReference() &&
           !unresolved_styles.Contains(speak_as_chain.back()));

  if (!speak_as_chain.back()) {
    // If the specified style does not exist, this value is treated as 'auto'.
    DCHECK_GE(speak_as_chain.size(), 2u);
    speak_as_chain.pop_back();
    speak_as_chain.back()->ResolveInvalidSpeakAsReference();
    speak_as_chain.back()->SetHasInexistentReferences();
  } else if (speak_as_chain.back()->HasUnresolvedSpeakAsReference()) {
    // If a loop is detected when following 'speak-as' references, this value is
    // treated as 'auto' for the counter styles participating in the loop.
    CounterStyle* cycle_start = speak_as_chain.back();
    do {
      speak_as_chain.back()->ResolveInvalidSpeakAsReference();
      speak_as_chain.pop_back();
    } while (speak_as_chain.back() != cycle_start);
  }

  CounterStyle* back = speak_as_chain.back();
  while (speak_as_chain.size() > 1u) {
    speak_as_chain.pop_back();
    speak_as_chain.back()->ResolveSpeakAsReference(*back);
  }
}

void CounterStyleMap::ResolveReferences(
    HeapHashSet<Member<CounterStyleMap>>& visited_maps) {
  if (visited_maps.Contains(this)) {
    return;
  }
  visited_maps.insert(this);

  // References in ancestor scopes must be resolved first.
  if (CounterStyleMap* ancestor_map = GetAncestorMap()) {
    ancestor_map->ResolveReferences(visited_maps);
  }

  for (CounterStyle* counter_style : counter_styles_.Values()) {
    if (counter_style->HasUnresolvedExtends()) {
      ResolveExtendsFor(*counter_style);
    }
    if (counter_style->HasUnresolvedFallback()) {
      ResolveFallbackFor(*counter_style);
    }
    if (RuntimeEnabledFeatures::
            CSSAtRuleCounterStyleSpeakAsDescriptorEnabled()) {
      if (counter_style->HasUnresolvedSpeakAsReference()) {
        ResolveSpeakAsReferenceFor(*counter_style);
      }
    }
  }
}

void CounterStyleMap::MarkDirtyCounterStyles(
    HeapHashSet<Member<CounterStyle>>& visited_counter_styles) {
  for (CounterStyle* counter_style : counter_styles_.Values()) {
    counter_style->TraverseAndMarkDirtyIfNeeded(visited_counter_styles);
  }

  // Replace dirty CounterStyles by clean ones with unresolved references.
  for (Member<CounterStyle>& counter_style_ref : counter_styles_.Values()) {
    if (counter_style_ref->IsDirty()) {
      CounterStyle* clean_style =
          MakeGarbageCollected<CounterStyle>(counter_style_ref->GetStyleRule());
      counter_style_ref = clean_style;
    }
  }
}

// static
void CounterStyleMap::MarkAllDirtyCounterStyles(
    Document& document,
    const HeapHashSet<Member<TreeScope>>& active_tree_scopes) {
  // Traverse all CounterStyle objects in the document to mark dirtiness.
  // We assume that there are not too many CounterStyle objects, so this won't
  // be a performance bottleneck.
  TRACE_EVENT0("blink", "CounterStyleMap::MarkAllDirtyCounterStyles");

  HeapHashSet<Member<CounterStyle>> visited_counter_styles;

  if (CounterStyleMap* user_map = GetUserCounterStyleMap(document)) {
    user_map->MarkDirtyCounterStyles(visited_counter_styles);
  }

  if (CounterStyleMap* document_map = GetAuthorCounterStyleMap(document)) {
    document_map->MarkDirtyCounterStyles(visited_counter_styles);
  }

  for (const TreeScope* scope : active_tree_scopes) {
    if (CounterStyleMap* scoped_map = GetAuthorCounterStyleMap(*scope)) {
      scoped_map->MarkDirtyCounterStyles(visited_counter_styles);
    }
  }
}

// static
void CounterStyleMap::ResolveAllReferences(
    Document& document,
    const HeapHashSet<Member<TreeScope>>& active_tree_scopes) {
  // Traverse all counter style maps to find and update CounterStyles that are
  // dirty or have unresolved references. We assume there are not too many
  // CounterStyles, so that this won't be a performance bottleneck.
  TRACE_EVENT0("blink", "CounterStyleMap::ResolveAllReferences");

  HeapHashSet<Member<CounterStyleMap>> visited_maps;
  visited_maps.insert(GetUACounterStyleMap());

  if (CounterStyleMap* user_map = GetUserCounterStyleMap(document)) {
    user_map->ResolveReferences(visited_maps);
  }

  if (CounterStyleMap* document_map = GetAuthorCounterStyleMap(document)) {
    document_map->ResolveReferences(visited_maps);
  }

  for (const TreeScope* scope : active_tree_scopes) {
    if (CounterStyleMap* scoped_map = GetAuthorCounterStyleMap(*scope)) {
      scoped_map->ResolveReferences(visited_maps);

#if DCHECK_IS_ON()
      for (CounterStyle* counter_style : scoped_map->counter_styles_.Values()) {
        DCHECK(!counter_style->IsDirty());
        DCHECK(!counter_style->HasUnresolvedExtends());
        DCHECK(!counter_style->HasUnresolvedFallback());
        DCHECK(!counter_style->HasUnresolvedSpeakAsReference());
      }
#endif
    }
  }
}

void CounterStyleMap::Dispose() {
  if (!counter_styles_.size()) {
    return;
  }

  for (CounterStyle* counter_style : counter_styles_.Values()) {
    counter_style->SetIsDirty();
  }
  counter_styles_.clear();

  if (owner_document_) {
    owner_document_->GetStyleEngine().MarkCounterStylesNeedUpdate();
  }
}

void CounterStyleMap::Trace(Visitor* visitor) const {
  visitor->Trace(owner_document_);
  visitor->Trace(tree_scope_);
  visitor->Trace(counter_styles_);
}

}  // namespace blink
```