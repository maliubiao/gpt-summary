Response:
Let's break down the thought process to analyze this C++ code.

1. **Understand the Goal:** The request asks for a functional description of `js_event_handler_for_content_attribute.cc`, its relationship to web technologies, logical reasoning, common errors, and how user actions lead to this code.

2. **Initial Read and Identify Key Concepts:**  A quick scan reveals terms like "event handler," "content attribute," "JavaScript," "HTML," "V8," "compilation," and "script." This immediately suggests a connection to how HTML attributes (like `onclick`) trigger JavaScript execution.

3. **Focus on the Class Name:** The class name `JSEventHandlerForContentAttribute` is highly descriptive. It strongly implies that this code manages event handlers defined *directly within HTML attributes*.

4. **Analyze the `Create` Method:**  The `Create` method is the entry point for creating instances of this class. The checks for `context`, script execution ability, and a non-null `value` are important. The `HandlerType` parameter hints at different types of event handlers.

5. **Examine the Constructor:** The constructor initializes key members like `script_body_`, `source_url_`, and `position_`. The `script_body_` clearly stores the JavaScript code from the attribute. `source_url_` and `position_` indicate where this code originated, crucial for debugging.

6. **Investigate `GetListenerObject`:** This method is central to how the event handler is actually invoked. The logic involving `HasCompiledHandler()` and `did_compile_` suggests a lazy compilation mechanism – the JavaScript is only compiled when needed.

7. **Deep Dive into `GetCompiledHandler`:** This is the core of the compilation process. Key steps include:
    * Checking `did_compile_` to avoid redundant compilation.
    * Obtaining the execution context (`ExecutionContext`).
    * Getting the V8 context (`v8::Context`).
    * Determining the `EventTarget` (element or window).
    * Checking if scripting is enabled (`document->AllowInlineEventHandler`). This is a security measure.
    * Identifying the `formOwner`.
    * Constructing the parameter list for the JavaScript function (handling the `onerror` case).
    * Defining the JavaScript function's scope (global, form, element).
    * Creating a `v8::ScriptOrigin` for debugging information.
    * **Crucially:** Using `v8::ScriptCompiler::CompileFunction` to compile the JavaScript code.
    * Handling compilation errors.
    * Creating a Web IDL `EventHandler` callback object.

8. **Connect to Web Technologies:**
    * **HTML:** The entire purpose is to handle event handlers defined *in HTML attributes* (e.g., `onclick="alert('hello')"`, `onload="init()"`, `onerror="handleError()"`, etc.).
    * **JavaScript:** The code directly deals with compiling and executing JavaScript code extracted from HTML attributes.
    * **CSS (Indirect):** While not directly related to CSS *syntax*, CSS can influence which elements have event handlers attached, and therefore indirectly trigger this code. For example, a CSS `:hover` pseudo-class might trigger a JavaScript event handler if it's defined on the element.
    * **V8:** The code heavily uses the V8 JavaScript engine's API for compilation (`v8::ScriptCompiler::CompileFunction`), context management (`v8::Context`), and string manipulation (`v8::String`).

9. **Logical Reasoning and Examples:**  Based on the code analysis, construct scenarios:
    * **Successful Compilation:**  Input: `onclick="alert('hello')"`. Output: A compiled JavaScript function object.
    * **Compilation Error:** Input: `onclick="alert("oops")"`. Output:  An error reported to the console, the event handler is likely set to null.
    * **No Scripting:** Input: `onclick="alert('hello')"` in a context where scripting is disabled. Output: Compilation is skipped, the handler remains uncompiled or null.

10. **Common User/Programming Errors:** Think about what mistakes developers commonly make with inline event handlers:
    * Syntax errors in the JavaScript.
    * Referencing undefined variables (scope issues).
    * Security vulnerabilities (though this code has checks against some).

11. **User Actions and Debugging:** Trace the user's interaction:
    * User interacts with the webpage (e.g., clicks a button).
    * The browser identifies the event target and the relevant event handler attribute.
    * Blink fetches the JavaScript code from the attribute.
    * `JSEventHandlerForContentAttribute::GetListenerObject` is called.
    * If not already compiled, `GetCompiledHandler` is invoked.
    * The JavaScript code is compiled and executed.
    * During debugging, breakpoints within `GetCompiledHandler` or the compiled JavaScript function are crucial. Inspecting `script_body_`, `source_url_`, and the V8 context can help.

12. **Structure and Refine:** Organize the findings into clear sections (Functionality, Relationships, Logical Reasoning, Errors, Debugging). Use code snippets from the original file to illustrate specific points. Ensure the language is accessible and avoids overly technical jargon where possible.

13. **Review and Verify:**  Read through the entire analysis to ensure accuracy and completeness. Double-check the connection between the code and the web technologies.

This iterative process of reading, analyzing, connecting, and constructing examples allows for a comprehensive understanding of the code's purpose and its role in the Blink rendering engine. The key is to focus on the core functionalities and how they relate to the user's experience and common developer practices.
好的，让我们来详细分析一下 `blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.cc` 这个文件的功能。

**功能概述**

`JSEventHandlerForContentAttribute` 类的主要功能是**处理定义在 HTML 元素属性中的 JavaScript 事件处理程序**。  当 HTML 元素（例如按钮、链接等）的属性中定义了像 `onclick="myFunction()"` 这样的事件处理程序时，这个类负责解析、编译和执行这些 JavaScript 代码。

**与 JavaScript, HTML, CSS 的关系**

这个文件与 Web 前端的三大核心技术都有着密切的关系：

* **HTML (HyperText Markup Language):**  该文件的核心作用是处理 HTML 元素属性中定义的事件处理程序。例如，当你在 HTML 标签中写 `onclick="alert('Hello!')"` 时，`JSEventHandlerForContentAttribute` 就负责处理这个 `onclick` 属性的值（即 JavaScript 代码 `alert('Hello!')`）。
    * **例子：**
        ```html
        <button onclick="console.log('Button clicked!');">Click Me</button>
        <a href="#" onmouseover="this.style.color = 'red';">Hover Me</a>
        <body onload="init();"></body>
        ```
        在这个例子中，`onclick`、`onmouseover` 和 `onload` 属性的值都由 `JSEventHandlerForContentAttribute` 处理。

* **JavaScript:** 这个文件直接处理和执行 JavaScript 代码。它负责将属性值中的 JavaScript 代码编译成 V8 引擎可以执行的函数。
    * **例子：** 当用户点击一个带有 `onclick="myFunction(this)"` 的按钮时，`JSEventHandlerForContentAttribute` 会将字符串 `"myFunction(this)"` 编译成一个 JavaScript 函数，并在适当的时候执行它。

* **CSS (Cascading Style Sheets):** 虽然这个文件本身不直接处理 CSS，但通过 JavaScript 事件处理程序，它可以间接地与 CSS 交互。例如，事件处理程序可以修改元素的 `style` 属性，从而改变元素的样式。
    * **例子：** 在上面的 `<a>` 标签的 `onmouseover` 属性中，JavaScript 代码 `this.style.color = 'red'` 就直接操作了元素的 CSS 样式。

**逻辑推理 (假设输入与输出)**

假设有以下 HTML 代码：

```html
<div id="myDiv" onmouseover="this.textContent = 'Mouse Over';" onmouseout="this.textContent = 'Mouse Out';">Hover Me</div>
<script>
  function init() {
    console.log('Page loaded.');
  }
</script>
<body onload="init();"></body>
```

**场景 1: 鼠标悬停在 `div` 上**

* **假设输入:**
    * 事件类型: `mouseover`
    * 目标元素:  `HTMLDivElement` (id="myDiv")
    * 属性名: `onmouseover`
    * 属性值: `"this.textContent = 'Mouse Over';"`

* **逻辑推理:**
    1. Blink 引擎检测到 `mouseover` 事件发生在 `myDiv` 上。
    2. 引擎查找 `myDiv` 元素的 `onmouseover` 属性。
    3. 创建或获取与该属性关联的 `JSEventHandlerForContentAttribute` 实例。
    4. 如果这是第一次执行该事件处理程序，`GetCompiledHandler` 方法会被调用，将 `"this.textContent = 'Mouse Over';"` 编译成一个 V8 函数。
    5. 当事件触发时，编译后的函数会在 `myDiv` 的上下文中执行，`this` 指向 `myDiv` 元素。
    6. `myDiv` 的 `textContent` 属性被设置为 `"Mouse Over"`。

* **预期输出:**  `div` 元素的文本内容变为 "Mouse Over"。

**场景 2: 页面加载完成**

* **假设输入:**
    * 事件类型: `load`
    * 目标元素: `HTMLBodyElement`
    * 属性名: `onload`
    * 属性值: `"init();"`

* **逻辑推理:**
    1. 浏览器完成页面加载。
    2. `load` 事件在 `body` 元素上触发。
    3. 引擎查找 `body` 元素的 `onload` 属性。
    4. 创建或获取与该属性关联的 `JSEventHandlerForContentAttribute` 实例。
    5. 如果这是第一次执行，`GetCompiledHandler` 将 `"init();"` 编译成 V8 函数。
    6. 编译后的函数在全局作用域中执行，调用 `init()` 函数。

* **预期输出:**  控制台输出 "Page loaded."

**用户或编程常见的使用错误**

1. **语法错误:** 在 HTML 属性中编写的 JavaScript 代码如果存在语法错误，会导致编译失败，事件处理程序无法正常工作。
    * **例子:** `<button onclick="alert('错误的引号)">Click</button>`  （引号不匹配）
    * **结果:** 点击按钮可能没有任何反应，或者在开发者控制台中显示 JavaScript 错误。

2. **作用域问题:**  在 HTML 属性中编写的 JavaScript 代码的作用域可能与预期不同，导致访问变量或函数时出错。
    * **例子:**
        ```html
        <script>
          function greet(name) {
            alert('Hello, ' + name + '!');
          }
        </script>
        <button onclick="greet('User');">Greet</button>
        ```
        这个例子通常是没问题的，因为 `greet` 函数在全局作用域中。但如果 `greet` 函数定义在更严格的作用域中（例如模块内部），可能会导致找不到该函数。

3. **`this` 关键字的理解错误:** 在事件处理程序中，`this` 关键字的指向取决于事件绑定和执行的上下文。在 HTML 属性中定义的事件处理程序中，`this` 通常指向触发事件的 HTML 元素。
    * **例子:** `<button onclick="console.log(this.tagName);">Log Tag</button>`  （`this` 指向 `button` 元素）。
    * **错误用法:** 错误地认为 `this` 指向全局对象或其他对象。

4. **安全风险 (内联脚本):**  过度依赖内联事件处理程序会增加 XSS (跨站脚本攻击) 的风险。如果用户输入的数据未经充分转义就直接插入到 HTML 属性中，可能会被恶意利用。

**用户操作是如何一步步的到达这里，作为调试线索**

让我们以一个简单的点击事件为例，说明用户操作如何触发 `JSEventHandlerForContentAttribute` 的执行，并提供调试线索：

1. **用户操作:** 用户在浏览器中打开一个网页，并点击了一个带有 `onclick` 属性的按钮。

2. **事件分发:**
   * 浏览器的事件监听机制捕获到用户的点击事件。
   * 事件冒泡或捕获阶段会将事件传递到相关的 DOM 元素（在本例中是按钮元素）。

3. **查找事件处理程序:**
   * Blink 渲染引擎检查按钮元素上注册的事件监听器。
   * 对于通过 HTML 属性定义的事件处理程序（例如 `onclick`），引擎会找到对应的 `JSEventHandlerForContentAttribute` 实例。

4. **获取 Listener 对象 (`GetListenerObject`):**
   * 当需要执行事件处理程序时，会调用 `JSEventHandlerForContentAttribute` 的 `GetListenerObject` 方法。
   * 这个方法会检查事件处理程序是否已经被编译。

5. **编译事件处理程序 (`GetCompiledHandler`):**
   * 如果事件处理程序尚未编译（`did_compile_` 为 false），或者需要重新获取，`GetCompiledHandler` 方法会被调用。
   * 在 `GetCompiledHandler` 中：
     * 获取执行上下文 (`ExecutionContext`)。
     * 获取 V8 上下文 (`v8::Context`)。
     * 检查是否允许内联脚本。
     * 使用 V8 的 `ScriptCompiler::CompileFunction` 将属性值中的 JavaScript 代码编译成 V8 函数。
     * 如果编译失败，会报告错误。

6. **执行事件处理程序:**
   * `GetListenerObject` 返回编译后的 V8 函数。
   * V8 引擎在适当的上下文中执行该函数。

**调试线索:**

* **在 `JSEventHandlerForContentAttribute::Create` 设置断点:**  可以观察何时以及如何创建这个类的实例。参数 `name` 和 `value` 可以告诉你正在处理哪个事件和哪个属性值。
* **在 `JSEventHandlerForContentAttribute::GetListenerObject` 设置断点:**  可以查看何时尝试获取事件处理程序的监听器对象，以及是否已经编译。
* **在 `JSEventHandlerForContentAttribute::GetCompiledHandler` 设置断点:**  这是编译过程的核心。可以查看传入的 JavaScript 代码、作用域信息以及编译是否成功。
* **查看开发者控制台的错误信息:** 如果 HTML 属性中的 JavaScript 代码有语法错误，V8 引擎通常会在控制台中输出错误信息，提供文件名、行号和列号，有助于定位问题。
* **使用 "Event Listener Breakpoints" (Chrome DevTools):**  在 Chrome 开发者工具的 "Sources" 面板中，可以设置事件监听器断点，例如 "click" 事件。当点击事件发生时，调试器会暂停，可以查看调用栈，追踪到 `JSEventHandlerForContentAttribute` 的执行。

总而言之，`js_event_handler_for_content_attribute.cc` 在 Blink 引擎中扮演着关键角色，它连接了 HTML 中声明式的事件绑定和 JavaScript 的动态执行，使得用户与网页的交互成为可能。理解它的工作原理对于开发和调试 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"

#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"

namespace blink {

JSEventHandlerForContentAttribute* JSEventHandlerForContentAttribute::Create(
    ExecutionContext* context,
    const QualifiedName& name,
    const AtomicString& value,
    HandlerType type) {
  if (!context || !context->CanExecuteScripts(kAboutToExecuteScript))
    return nullptr;
  if (value.IsNull())
    return nullptr;
  DCHECK(IsA<LocalDOMWindow>(context));
  return MakeGarbageCollected<JSEventHandlerForContentAttribute>(context, name,
                                                                 value, type);
}

JSEventHandlerForContentAttribute::JSEventHandlerForContentAttribute(
    ExecutionContext* context,
    const QualifiedName& name,
    const AtomicString& value,
    HandlerType type)
    : JSEventHandler(type),
      did_compile_(false),
      function_name_(name.LocalName()),
      script_body_(value),
      source_url_(context->Url().GetString()),
      position_(To<LocalDOMWindow>(context)
                    ->GetScriptController()
                    .EventHandlerPosition()),
      isolate_(context->GetIsolate()) {}

v8::Local<v8::Value> JSEventHandlerForContentAttribute::GetListenerObject(
    EventTarget& event_target) {
  // Step 3. of get the current value of the event handler should be executed
  // only if EventHandler's value is an internal raw uncompiled handler and it
  // has never tried to get compiled.
  if (HasCompiledHandler())
    return JSEventHandler::GetListenerObject(event_target);
  if (did_compile_)
    return v8::Null(GetIsolate());

  return GetCompiledHandler(event_target);
}

// Implements Step 3. of "get the current value of the event handler"
// https://html.spec.whatwg.org/C/#getting-the-current-value-of-the-event-handler
v8::Local<v8::Value> JSEventHandlerForContentAttribute::GetCompiledHandler(
    EventTarget& event_target) {
  // Do not compile the same code twice.
  DCHECK(!did_compile_);
  did_compile_ = true;

  ExecutionContext* execution_context_of_event_target =
      event_target.GetExecutionContext();
  if (!execution_context_of_event_target)
    return v8::Null(GetIsolate());

  v8::Local<v8::Context> v8_context_of_event_target =
      ToV8Context(execution_context_of_event_target, GetWorld());
  if (v8_context_of_event_target.IsEmpty())
    return v8::Null(GetIsolate());

  ScriptState* script_state_of_event_target =
      ScriptState::From(GetIsolate(), v8_context_of_event_target);
  if (!script_state_of_event_target->ContextIsValid())
    return v8::Null(GetIsolate());

  // Step 1. If eventTarget is an element, then let element be eventTarget, and
  // document be element's node document. Otherwise, eventTarget is a Window
  // object, let element be null, and document be eventTarget's associated
  // Document.
  Element* element = nullptr;
  const LocalDOMWindow* window = nullptr;
  Document* document = nullptr;
  if (Node* node = event_target.ToNode()) {
    if (node->IsDocumentNode()) {
      // Some of content attributes for |HTMLBodyElement| are treated as ones
      // for |Document| unlike the definition in HTML standard.  Those content
      // attributes are not listed in the Window-reflecting body element event
      // handler set.
      // https://html.spec.whatwg.org/C/#window-reflecting-body-element-event-handler-set
      document = &node->GetDocument();
    } else {
      element = To<Element>(node);
      document = &node->GetDocument();
    }
    // EventTarget::GetExecutionContext() sometimes returns the document which
    // created the EventTarget, and sometimes returns the document to which
    // the EventTarget is currently attached.  The former might be different
    // from |document|.
  } else {
    window = event_target.ToLocalDOMWindow();
    DCHECK(window);
    DCHECK_EQ(window, execution_context_of_event_target);
    document = window->document();
  }
  DCHECK(document);

  // Step 6. Let settings object be the relevant settings object of document.
  // Step 9. Push settings object's realm execution context onto the JavaScript
  // execution context stack; it is now the running JavaScript execution
  // context.
  //
  // |document->AllowInlineEventHandler()| checks the world of current context,
  // so this scope needs to be defined before calling it.
  v8::Context::Scope event_target_context_scope(v8_context_of_event_target);

  // Step 2. If scripting is disabled for document, then return null.
  if (!document->AllowInlineEventHandler(element, this, source_url_,
                                         position_.line_))
    return v8::Null(GetIsolate());

  // Step 5. If element is not null and element has a form owner, let form owner
  // be that form owner. Otherwise, let form owner be null.
  HTMLFormElement* form_owner = nullptr;
  if (auto* html_element = DynamicTo<HTMLElement>(element)) {
    form_owner = html_element->formOwner();

    // https://html.spec.whatwg.org/C/#window-reflecting-body-element-event-handler-set
    // The Event handlers on HTMLBodyElement and HTMLFrameSetElement which are
    // listed in the Window-reflecting body element event handler set should be
    // treated as if they are the corresponding event handlers of the window
    // object.
    if (html_element->IsHTMLBodyElement() ||
        html_element->IsHTMLFrameSetElement()) {
      window = To<LocalDOMWindow>(execution_context_of_event_target);
    }
  }

  // Step 10. Let function be the result of calling FunctionCreate, with
  // arguments:
  //   kind
  //     Normal
  //   ParameterList
  //     If eventHandler is an onerror event handler of a Window object
  //       Let the function have five arguments, named event, source, lineno,
  //       colno, and error.
  //     Otherwise
  //       Let the function have a single argument called event.
  //   Body
  //     The result of parsing body above.
  //   Scope
  //     1. If eventHandler is an element's event handler, then let Scope be
  //        NewObjectEnvironment(document, the global environment). Otherwise,
  //        eventHandler is a Window object's event handler: let Scope be the
  //        global environment.
  //     2. If form owner is not null, let Scope be NewObjectEnvironment(form
  //        owner, Scope).
  //     3. If element is not null, let Scope be NewObjectEnvironment(element,
  //        Scope).
  //   Strict
  //     The value of strict.
  //
  // Note: Strict is set by V8.
  v8::Isolate* isolate = script_state_of_event_target->GetIsolate();
  v8::Local<v8::String> parameter_list[5];
  size_t parameter_list_size = 0;
  if (IsOnErrorEventHandler() && window) {
    // SVG requires to introduce evt as an alias to event in event handlers.
    // See ANNOTATION 3: https://www.w3.org/TR/SVG/interact.html#SVGEvents
    parameter_list[parameter_list_size++] =
        V8String(isolate, element && element->IsSVGElement() ? "evt" : "event");
    parameter_list[parameter_list_size++] = V8String(isolate, "source");
    parameter_list[parameter_list_size++] = V8String(isolate, "lineno");
    parameter_list[parameter_list_size++] = V8String(isolate, "colno");
    parameter_list[parameter_list_size++] = V8String(isolate, "error");
  } else {
    // SVG requires to introduce evt as an alias to event in event handlers.
    // See ANNOTATION 3: https://www.w3.org/TR/SVG/interact.html#SVGEvents
    parameter_list[parameter_list_size++] =
        V8String(isolate, element && element->IsSVGElement() ? "evt" : "event");
  }
  DCHECK_LE(parameter_list_size, std::size(parameter_list));

  v8::Local<v8::Object> scopes[3];
  size_t scopes_size = 0;
  if (element) {
    scopes[scopes_size++] =
        ToV8Traits<Document>::ToV8(script_state_of_event_target, document)
            .As<v8::Object>();
  }
  if (form_owner) {
    scopes[scopes_size++] = ToV8Traits<HTMLFormElement>::ToV8(
                                script_state_of_event_target, form_owner)
                                .As<v8::Object>();
  }
  if (element) {
    scopes[scopes_size++] =
        ToV8Traits<Element>::ToV8(script_state_of_event_target, element)
            .As<v8::Object>();
  }
  DCHECK_LE(scopes_size, std::size(scopes));

  v8::ScriptOrigin origin(
      V8String(isolate, source_url_), position_.line_.ZeroBasedInt(),
      position_.column_.ZeroBasedInt(),
      true);  // true as |SanitizeScriptErrors::kDoNotSanitize|
  v8::ScriptCompiler::Source source(V8String(isolate, script_body_), origin);

  v8::Local<v8::Function> compiled_function;
  {
    v8::TryCatch block(isolate);
    block.SetVerbose(true);
    v8::MaybeLocal<v8::Function> maybe_result =
        v8::ScriptCompiler::CompileFunction(v8_context_of_event_target, &source,
                                            parameter_list_size, parameter_list,
                                            scopes_size, scopes);

    // Step 7. If body is not parsable as FunctionBody or if parsing detects an
    // early error, then follow these substeps:
    //   1. Set eventHandler's value to null.
    //   2. Report the error for the appropriate script and with the appropriate
    //      position (line number and column number) given by location, using
    //      settings object's global object. If the error is still not handled
    //      after this, then the error may be reported to a developer console.
    //   3. Return null.
    if (!maybe_result.ToLocal(&compiled_function))
      return v8::Null(isolate);
  }

  // Step 12. Set eventHandler's value to the result of creating a Web IDL
  // EventHandler callback function object whose object reference is function
  // and whose callback context is settings object.
  compiled_function->SetName(V8String(isolate, function_name_));
  SetCompiledHandler(script_state_of_event_target, compiled_function);

  return JSEventHandler::GetListenerObject(event_target);
}

std::unique_ptr<SourceLocation>
JSEventHandlerForContentAttribute::GetSourceLocation(EventTarget& target) {
  auto source_location = JSEventHandler::GetSourceLocation(target);
  if (source_location)
    return source_location;
  // Fallback to uncompiled source info.
  return std::make_unique<SourceLocation>(
      source_url_, String(), position_.line_.ZeroBasedInt(),
      position_.column_.ZeroBasedInt(), nullptr);
}

}  // namespace blink
```