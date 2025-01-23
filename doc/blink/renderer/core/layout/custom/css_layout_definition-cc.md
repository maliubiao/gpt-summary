Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request is to understand the functionality of `css_layout_definition.cc`, its relation to web technologies (HTML, CSS, JavaScript), provide examples, and highlight potential user/programmer errors.

2. **Identify Key Components and Data Structures:**  The first step is to scan the code for important keywords and data structures. This helps in understanding the purpose and the elements involved. I see:
    * `#include` directives: These reveal dependencies and give hints about the code's domain (e.g., `renderer`, `layout`, `bindings`, `v8`).
    * Class name: `CSSLayoutDefinition`. This is the central entity.
    * Member variables: `script_state_`, `constructor_`, `intrinsic_sizes_`, `layout_`, `native_invalidation_properties_`, `custom_invalidation_properties_`, etc. These hold the data and functionalities.
    * Methods: `Layout`, `IntrinsicSizes`, `CreateInstance`. These are the main actions the class performs.
    * Inner classes/structs: `Instance`. This suggests a pattern where the definition is a template, and `Instance` represents a concrete usage.
    * V8 types:  `V8NoArgumentConstructor`, `V8IntrinsicSizesCallback`, `V8LayoutCallback`, `v8::Local<v8::Value>`, `v8::Promise`. This strongly indicates interaction with JavaScript.
    * Layout-related types: `BlockNode`, `ConstraintSpace`, `CustomLayoutChild`, `CustomLayoutConstraints`, `CustomLayoutEdges`, `CustomLayoutFragment`. This confirms its role in the layout engine.
    * CSS-related types: `CSSPropertyID`, `AtomicString`, `StylePropertyMapReadOnly`. This links it to CSS concepts.

3. **Infer High-Level Functionality:** Based on the identified components, I can start forming a high-level understanding:
    * The file is about defining custom layout behaviors within the Blink rendering engine.
    * It uses JavaScript functions (`intrinsicSizes` and `layout`) to determine the layout.
    * It interacts with the CSS style system.

4. **Analyze Key Methods in Detail:**  Focus on the `Layout` and `IntrinsicSizes` methods, as they seem to be the core functionalities.
    * **`Layout`:**
        * Takes layout constraints, the DOM node, and existing layout information as input.
        * Gathers children of the node.
        * Creates JavaScript objects (`CustomLayoutEdges`, `CustomLayoutConstraints`, `StylePropertyMapReadOnly`) to pass to the JavaScript layout function.
        * Invokes the JavaScript `layout` function using the provided arguments.
        * Handles the JavaScript promise returned by the `layout` function.
        * Processes the result of the JavaScript function, including potential serialization of data.
        * Deals with microtasks.
    * **`IntrinsicSizes`:**
        * Similar structure to `Layout`, but invokes the `intrinsicSizes` JavaScript function.
        * Handles a different set of inputs and outputs related to calculating intrinsic sizes.

5. **Connect to Web Technologies:** Now, relate the findings to HTML, CSS, and JavaScript:
    * **CSS:** The `CSSLayoutDefinition` is triggered by a CSS property (likely `layout: custom(...)`). The `native_invalidation_properties_` and `custom_invalidation_properties_` directly relate to CSS properties that can trigger a re-layout.
    * **JavaScript:** The core logic of the custom layout is defined in JavaScript functions (`layout` and `intrinsicSizes`). The code explicitly interacts with V8, the JavaScript engine.
    * **HTML:** The layout is applied to HTML elements. The `BlockNode` represents an HTML element.

6. **Construct Examples:**  Create concrete examples to illustrate the interaction:
    * **CSS:** Show how to define a custom layout name in CSS and link it to the JavaScript definition.
    * **JavaScript:** Provide simple examples of the `layout` and `intrinsicSizes` functions, showcasing how they receive data and return layout information.
    * **HTML:** Demonstrate how to apply the custom layout to an HTML element.

7. **Identify Potential Errors:** Think about common mistakes developers might make:
    * **JavaScript errors:** Incorrect function signatures, not returning a promise, promise not resolving, returning incorrect data types.
    * **CSS errors:**  Misspelling the custom layout name, not defining the custom layout correctly.
    * **Asynchronous issues:** Forgetting that the JavaScript functions are asynchronous.

8. **Logical Reasoning and Assumptions:**  When explaining the code, explicitly state any assumptions or logical deductions. For example, assuming that the `custom` value for the `layout` CSS property triggers this mechanism.

9. **Structure the Explanation:** Organize the information logically:
    * Start with a high-level overview of the file's purpose.
    * Detail the functionality, explaining the key methods.
    * Connect to HTML, CSS, and JavaScript with examples.
    * Highlight potential errors.
    * Summarize the key takeaways.

10. **Refine and Elaborate:** Review the explanation and add details where necessary. For instance, explain the role of microtasks, the purpose of serialization, and the significance of the different V8 types.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  The code might be solely about layout calculations.
* **Correction:** Realized the significant interaction with JavaScript and the CSS style system.
* **Initial thought:**  The examples could be very complex.
* **Correction:** Focused on simple, illustrative examples to convey the core concepts.
* **Initial thought:** Just list the errors.
* **Correction:**  Provide context and explain *why* these are errors and what the consequences are.

By following this structured approach, including detailed analysis and relating the code to the broader web development context, it becomes possible to generate a comprehensive and helpful explanation.
这个文件 `css_layout_definition.cc` 是 Chromium Blink 引擎中负责定义和管理 **CSS 自定义布局（CSS Custom Layout API，也称为 Layout Worklets）** 的核心组件。它连接了 CSS 样式系统和 JavaScript 代码，使得开发者可以使用 JavaScript 来编写自定义的布局算法。

以下是它的主要功能：

1. **定义自定义布局的接口：**  `CSSLayoutDefinition` 类存储了与一个特定自定义布局相关的各种信息，包括：
    * **JavaScript 构造函数 (`constructor_`)：**  用于创建自定义布局工作单元的实例。
    * **JavaScript `intrinsicSizes` 回调函数 (`intrinsic_sizes_`)：**  一个 JavaScript 函数，用于计算自定义布局元素的固有大小（例如，最小内容大小、首选大小）。
    * **JavaScript `layout` 回调函数 (`layout_`)：**  一个 JavaScript 函数，包含自定义布局的核心逻辑，负责确定元素及其子元素的布局位置和尺寸。
    * **CSS 属性无效化列表：**
        * `native_invalidation_properties_`:  原生 CSS 属性列表，当这些属性的值发生变化时，会触发自定义布局的重新计算。
        * `custom_invalidation_properties_`: 自定义 CSS 属性名称列表，同样用于触发重新计算。
        * `child_native_invalidation_properties_`:  子元素的原生 CSS 属性列表，当子元素的这些属性变化时，会触发父元素自定义布局的重新计算。
        * `child_custom_invalidation_properties_`: 子元素的自定义 CSS 属性名称列表，用于触发父元素自定义布局的重新计算。
    * **脚本状态 (`script_state_`)：**  用于执行 JavaScript 代码。

2. **管理自定义布局的实例：** `CSSLayoutDefinition::Instance` 类表示自定义布局工作单元的一个具体实例。每个使用了该自定义布局的元素都会创建一个 `Instance`。

3. **调用 JavaScript 回调函数：**  当需要计算元素的固有大小时，`IntrinsicSizes` 方法会调用 JavaScript 的 `intrinsicSizes` 函数。当需要进行实际布局时，`Layout` 方法会调用 JavaScript 的 `layout` 函数。这些方法负责将必要的布局信息（如约束、子元素、样式等）传递给 JavaScript 代码。

4. **处理 JavaScript 返回的结果：** `Layout` 方法接收 JavaScript `layout` 函数返回的 Promise，并解析其结果。这个结果包含了自定义布局的输出，例如子元素的位置和尺寸，以及可能需要传递给父布局的额外数据。

5. **处理微任务（Microtasks）：** 自定义布局的 JavaScript 代码可能会创建微任务。`Layout` 和 `IntrinsicSizes` 方法在执行 JavaScript 代码前后会处理这些微任务，以确保布局的正确性和性能。

6. **与其他 Blink 组件交互：** 该文件与 Blink 的其他布局组件（如 `BlockNode`, `ConstraintSpace`）以及 CSS 样式系统紧密集成，以便获取布局所需的上下文信息，并将自定义布局的结果应用到渲染树中。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  自定义布局是通过 CSS 的 `layout: custom(...)` 属性来声明和使用的。 `CSSLayoutDefinition` 负责解析 CSS 中指定的自定义布局名称，并将其与对应的 JavaScript 定义关联起来。
    * **例子：** 在 CSS 中，你可以这样定义一个使用名为 `my-grid-layout` 的自定义布局：
      ```css
      .container {
        layout: custom(my-grid-layout);
        /* 其他 CSS 属性 */
      }
      ```
      `CSSLayoutDefinition` 会查找名为 `my-grid-layout` 的自定义布局定义。

* **JavaScript:**  自定义布局的核心逻辑是通过 JavaScript 定义的。开发者需要注册一个全局的 `LayoutWorklet` 模块，其中包含 `intrinsicSizes` 和 `layout` 函数。
    * **例子：**  `intrinsicSizes` 函数接收元素的约束和子元素信息，并返回元素的固有大小：
      ```javascript
      // my-grid-layout.js
      registerLayout('my-grid-layout', class {
        static get inputProperties() { return []; } // 需要监听的 CSS 属性
        static get childrenInputProperties() { return []; } // 需要监听的子元素 CSS 属性

        async intrinsicSizes(children, edges, style) {
          // 计算元素的固有大小
          return { minContentSize: ..., preferredSize: ... };
        }

        async layout(children, edges, constraints, style, ...args) {
          // 执行自定义布局逻辑，计算子元素的位置和大小
          const childFragments = children.map(child => {
            return {
              style: {},
              size: { width: ..., height: ... },
              offset: { x: ..., y: ... },
            };
          });
          return { childFragments };
        }
      });
      ```
      `CSSLayoutDefinition` 会调用这些 JavaScript 函数。

* **HTML:**  自定义布局应用于 HTML 元素。当一个 HTML 元素的 CSS `layout` 属性被设置为 `custom(...)` 时，Blink 引擎会使用相应的 `CSSLayoutDefinition` 来执行布局。
    * **例子：**
      ```html
      <div class="container">
        <div>Item 1</div>
        <div>Item 2</div>
      </div>
      ```
      如果 `.container` 的 CSS `layout` 属性设置为自定义布局，那么 `CSSLayoutDefinition` 会负责计算其子元素（"Item 1" 和 "Item 2"）的布局。

**逻辑推理与假设输入输出：**

假设我们有一个使用了 `my-grid-layout` 自定义布局的容器元素。

**假设输入 (在 `Layout` 方法中)：**

* `space`: 包含了布局约束的信息，例如可用宽度和高度。
* `document`: 当前文档对象。
* `node`: 代表容器元素的 `BlockNode` 对象。
* `border_box_size`: 容器元素的边框盒大小。
* `border_scrollbar_padding`: 容器元素的边框、滚动条和内边距信息。
* `custom_layout_scope`: 用于管理自定义布局的上下文。

**输出 (由 JavaScript `layout` 函数返回，并由 `Layout` 方法处理)：**

* `fragment_result_options`: 一个包含布局结果的对象，例如子元素的位置和大小，以及可能传递给父布局的额外数据。
    * 假设 JavaScript `layout` 函数返回：
      ```javascript
      return {
        childFragments: [
          { style: {}, size: { width: 100, height: 50 }, offset: { x: 0, y: 0 } },
          { style: {}, size: { width: 100, height: 50 }, offset: { x: 100, y: 0 } }
        ],
        data: { key: 'value' }
      };
      ```
    * 那么 `fragment_result_options` 将包含这些信息，`Layout` 方法会将其转换为 Blink 内部的数据结构。

**用户或编程常见的使用错误举例说明：**

1. **JavaScript `layout` 或 `intrinsicSizes` 函数未返回 Promise 或不是异步函数：**
   * **错误：**  JavaScript 代码定义 `layout` 函数如下：
     ```javascript
     layout(children, edges, constraints, style) {
       // ... 计算布局 ...
       return { childFragments: [...] }; // 直接返回对象，而不是 Promise
     }
     ```
   * **结果：**  `CSSLayoutDefinition::Instance::Layout` 方法会检测到返回值不是 Promise，并在控制台输出错误信息："The layout function must be async or return a promise, falling back to block layout."，最终会回退到默认的块级布局。

2. **JavaScript `layout` 或 `intrinsicSizes` 函数返回的 Promise 没有 resolve：**
   * **错误：**  JavaScript 代码中的 Promise 没有调用 `resolve()`：
     ```javascript
     async layout(children, edges, constraints, style) {
       return new Promise(() => {
         // ... 进行一些异步操作，但忘记调用 resolve() ...
       });
     }
     ```
   * **结果：**  `CSSLayoutDefinition::Instance::Layout` 方法会检测到 Promise 的状态不是 `fulfilled`，并在控制台输出错误信息："The layout function promise must resolve, falling back to block layout."，导致回退到默认布局。

3. **JavaScript `layout` 函数返回的结果格式不正确：**
   * **错误：**  JavaScript 代码返回的对象的属性名或类型与预期不符：
     ```javascript
     async layout(children, edges, constraints, style) {
       return { items: [...] }; // 应该返回 childFragments
     }
     ```
   * **结果：**  `CSSLayoutDefinition::Instance::Layout` 方法在尝试将 JavaScript 对象转换为 `FragmentResultOptions` 时会失败，并在控制台输出错误信息："Unable to parse the layout function result, falling back to block layout."，导致回退。

4. **无法序列化 `layout` 函数返回的 `data` 属性：**
   * **错误：**  `data` 属性包含了无法被序列化的 JavaScript 对象（例如，包含循环引用的对象）。
   * **结果：**  `CSSLayoutDefinition::Instance::Layout` 方法在尝试序列化 `data` 时会抛出异常，并在控制台输出错误信息："Unable to serialize the data provided in the result, falling back to block layout."，导致回退。

5. **CSS 中指定的自定义布局名称与 JavaScript 中注册的名称不匹配：**
   * **错误：** CSS 中使用了 `layout: custom(my-grid);`，但 JavaScript 中注册的是 `registerLayout('my-grid-layout', ...);`。
   * **结果：**  Blink 引擎无法找到对应的自定义布局定义，可能会导致布局错误或回退到默认布局。

总而言之，`css_layout_definition.cc` 是 Blink 引擎中实现 CSS 自定义布局的关键部分，它连接了 CSS 声明和 JavaScript 代码，使得开发者能够灵活地定义元素的布局方式。理解这个文件的功能有助于深入理解浏览器如何处理自定义布局以及如何避免常见的错误。

### 提示词
```
这是目录为blink/renderer/core/layout/custom/css_layout_definition.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/custom/css_layout_definition.h"

#include <memory>

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_iterator.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fragment_result_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intrinsic_sizes_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intrinsic_sizes_result_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_layout_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_no_argument_constructor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/core/css/cssom/prepopulated_computed_style_property_map.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_child.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_constraints.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_edges.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_fragment.h"
#include "third_party/blink/renderer/core/layout/custom/custom_layout_scope.h"
#include "third_party/blink/renderer/core/layout/layout_input_node.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

void GatherChildren(const BlockNode& node,
                    CustomLayoutScope* custom_layout_scope,
                    HeapVector<Member<CustomLayoutChild>>* children) {
  // TODO(ikilpatrick): Determine if knowing the size of the array ahead of
  // time improves performance in any noticeable way.
  for (LayoutInputNode child = node.FirstChild(); child;
       child = child.NextSibling()) {
    if (child.IsOutOfFlowPositioned())
      continue;

    CustomLayoutChild* layout_child = child.GetCustomLayoutChild();
    layout_child->SetCustomLayoutToken(custom_layout_scope->Token());
    DCHECK(layout_child);
    children->push_back(layout_child);
  }
}

}  // anonymous namespace

CSSLayoutDefinition::CSSLayoutDefinition(
    ScriptState* script_state,
    V8NoArgumentConstructor* constructor,
    V8IntrinsicSizesCallback* intrinsic_sizes,
    V8LayoutCallback* layout,
    const Vector<CSSPropertyID>& native_invalidation_properties,
    const Vector<AtomicString>& custom_invalidation_properties,
    const Vector<CSSPropertyID>& child_native_invalidation_properties,
    const Vector<AtomicString>& child_custom_invalidation_properties)
    : script_state_(script_state),
      constructor_(constructor),
      intrinsic_sizes_(intrinsic_sizes),
      layout_(layout),
      native_invalidation_properties_(native_invalidation_properties),
      custom_invalidation_properties_(custom_invalidation_properties),
      child_native_invalidation_properties_(
          child_native_invalidation_properties),
      child_custom_invalidation_properties_(
          child_custom_invalidation_properties) {}

CSSLayoutDefinition::~CSSLayoutDefinition() = default;

CSSLayoutDefinition::Instance::Instance(CSSLayoutDefinition* definition,
                                        v8::Local<v8::Value> instance)
    : definition_(definition),
      instance_(definition->GetScriptState()->GetIsolate(), instance) {}

bool CSSLayoutDefinition::Instance::Layout(
    const ConstraintSpace& space,
    const Document& document,
    const BlockNode& node,
    const LogicalSize& border_box_size,
    const BoxStrut& border_scrollbar_padding,
    CustomLayoutScope* custom_layout_scope,
    FragmentResultOptions*& fragment_result_options,
    scoped_refptr<SerializedScriptValue>* fragment_result_data) {
  ScriptState* script_state = definition_->GetScriptState();
  v8::Isolate* isolate = script_state->GetIsolate();

  if (!script_state->ContextIsValid())
    return false;

  ScriptState::Scope scope(script_state);

  HeapVector<Member<CustomLayoutChild>> children;
  GatherChildren(node, custom_layout_scope, &children);

  CustomLayoutEdges* edges =
      MakeGarbageCollected<CustomLayoutEdges>(border_scrollbar_padding);

  CustomLayoutConstraints* constraints =
      MakeGarbageCollected<CustomLayoutConstraints>(
          border_box_size, space.CustomLayoutData(), isolate);

  // TODO(ikilpatrick): Instead of creating a new style_map each time here,
  // store on LayoutCustom, and update when the style changes.
  StylePropertyMapReadOnly* style_map =
      MakeGarbageCollected<PrepopulatedComputedStylePropertyMap>(
          document, node.Style(), definition_->native_invalidation_properties_,
          definition_->custom_invalidation_properties_);

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  v8::MicrotaskQueue* microtask_queue = ToMicrotaskQueue(execution_context);
  DCHECK(microtask_queue);

  ScriptValue return_value;
  {
    v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                         v8::MicrotasksScope::kRunMicrotasks);
    if (!definition_->layout_
             ->Invoke(instance_.Get(isolate), children, edges, constraints,
                      style_map)
             .To(&return_value)) {
      return false;
    }
  }

  v8::Local<v8::Value> v8_return_value = return_value.V8Value();
  if (v8_return_value.IsEmpty() || !v8_return_value->IsPromise()) {
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "The layout function must be async or return a "
        "promise, falling back to block layout."));
    return false;
  }

  // Run the work queue until exhaustion.
  auto& queue = *custom_layout_scope->Queue();
  while (!queue.empty()) {
    {
      v8::MicrotasksScope microtasks_scope(
          isolate, microtask_queue, v8::MicrotasksScope::kDoNotRunMicrotasks);
      // The queue may mutate (re-allocating the vector) while running a task.
      for (wtf_size_t index = 0; index < queue.size(); ++index) {
        auto task = queue[index];
        task->Run(space, node.Style(), border_box_size.block_size);
      }
      queue.clear();
    }
    microtask_queue->PerformCheckpoint(isolate);
  }

  v8::Local<v8::Promise> v8_result_promise =
      v8::Local<v8::Promise>::Cast(v8_return_value);

  if (v8_result_promise->State() != v8::Promise::kFulfilled) {
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "The layout function promise must resolve, "
        "falling back to block layout."));
    return false;
  }
  v8::Local<v8::Value> inner_value = v8_result_promise->Result();

  // Attempt to convert the result.
  v8::TryCatch try_catch(isolate);
  fragment_result_options =
      NativeValueTraits<FragmentResultOptions>::NativeValue(
          isolate, inner_value, PassThroughException(isolate));

  if (try_catch.HasCaught()) {
    V8ScriptRunner::ReportException(isolate, try_catch.Exception());
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "Unable to parse the layout function "
        "result, falling back to block layout."));
    return false;
  }

  // Serialize any extra data provided by the web-developer to potentially pass
  // up to the parent custom layout.
  if (fragment_result_options->hasData()) {
    v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                         v8::MicrotasksScope::kRunMicrotasks);
    // We serialize "kForStorage" so that SharedArrayBuffers can't be shared
    // between LayoutWorkletGlobalScopes.
    *fragment_result_data = SerializedScriptValue::Serialize(
        isolate, fragment_result_options->data().V8Value(),
        SerializedScriptValue::SerializeOptions(
            SerializedScriptValue::kForStorage),
        PassThroughException(isolate));
  }

  if (try_catch.HasCaught()) {
    V8ScriptRunner::ReportException(isolate, try_catch.Exception());
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "Unable to serialize the data provided in the "
        "result, falling back to block layout."));
    return false;
  }

  return true;
}

bool CSSLayoutDefinition::Instance::IntrinsicSizes(
    const ConstraintSpace& space,
    const Document& document,
    const BlockNode& node,
    const LogicalSize& border_box_size,
    const BoxStrut& border_scrollbar_padding,
    const LayoutUnit child_available_block_size,
    CustomLayoutScope* custom_layout_scope,
    IntrinsicSizesResultOptions** intrinsic_sizes_result_options,
    bool* child_depends_on_block_constraints) {
  ScriptState* script_state = definition_->GetScriptState();
  v8::Isolate* isolate = script_state->GetIsolate();

  if (!script_state->ContextIsValid())
    return false;

  ScriptState::Scope scope(script_state);

  HeapVector<Member<CustomLayoutChild>> children;
  GatherChildren(node, custom_layout_scope, &children);

  CustomLayoutEdges* edges =
      MakeGarbageCollected<CustomLayoutEdges>(border_scrollbar_padding);

  // TODO(ikilpatrick): Instead of creating a new style_map each time here,
  // store on LayoutCustom, and update when the style changes.
  StylePropertyMapReadOnly* style_map =
      MakeGarbageCollected<PrepopulatedComputedStylePropertyMap>(
          document, node.Style(), definition_->native_invalidation_properties_,
          definition_->custom_invalidation_properties_);

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  v8::MicrotaskQueue* microtask_queue = ToMicrotaskQueue(execution_context);
  DCHECK(microtask_queue);

  ScriptValue return_value;
  {
    v8::MicrotasksScope microtasks_scope(isolate, microtask_queue,
                                         v8::MicrotasksScope::kRunMicrotasks);
    if (!definition_->intrinsic_sizes_
             ->Invoke(instance_.Get(isolate), children, edges, style_map)
             .To(&return_value)) {
      return false;
    }
  }

  v8::Local<v8::Value> v8_return_value = return_value.V8Value();
  if (v8_return_value.IsEmpty() || !v8_return_value->IsPromise()) {
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "The intrinsicSizes function must be async or return a "
        "promise, falling back to block layout."));
    return false;
  }

  // Run the work queue until exhaustion.
  auto& queue = *custom_layout_scope->Queue();
  while (!queue.empty()) {
    {
      v8::MicrotasksScope microtasks_scope(
          isolate, microtask_queue, v8::MicrotasksScope::kDoNotRunMicrotasks);
      // The queue may mutate (re-allocating the vector) while running a task.
      for (wtf_size_t index = 0; index < queue.size(); ++index) {
        auto task = queue[index];
        task->Run(space, node.Style(), child_available_block_size,
                  child_depends_on_block_constraints);
      }
      queue.clear();
    }
    microtask_queue->PerformCheckpoint(isolate);
  }

  v8::Local<v8::Promise> v8_result_promise =
      v8::Local<v8::Promise>::Cast(v8_return_value);

  if (v8_result_promise->State() != v8::Promise::kFulfilled) {
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "The intrinsicSizes function promise must resolve, "
        "falling back to block layout."));
    return false;
  }
  v8::Local<v8::Value> inner_value = v8_result_promise->Result();

  // Attempt to convert the result.
  v8::TryCatch try_catch(isolate);
  *intrinsic_sizes_result_options =
      NativeValueTraits<IntrinsicSizesResultOptions>::NativeValue(
          isolate, inner_value, PassThroughException(isolate));

  if (try_catch.HasCaught()) {
    V8ScriptRunner::ReportException(isolate, try_catch.Exception());
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kInfo,
        "Unable to parse the intrinsicSizes function "
        "result, falling back to block layout."));
    return false;
  }

  return true;
}

CSSLayoutDefinition::Instance* CSSLayoutDefinition::CreateInstance() {
  if (constructor_has_failed_)
    return nullptr;

  // Ensure that we don't create an instance on a detached context.
  if (!GetScriptState()->ContextIsValid())
    return nullptr;

  ScriptState::Scope scope(GetScriptState());

  ScriptValue instance;
  if (!constructor_->Construct().To(&instance)) {
    constructor_has_failed_ = true;
    return nullptr;
  }

  return MakeGarbageCollected<Instance>(this, instance.V8Value());
}

void CSSLayoutDefinition::Instance::Trace(Visitor* visitor) const {
  visitor->Trace(definition_);
  visitor->Trace(instance_);
}

void CSSLayoutDefinition::Trace(Visitor* visitor) const {
  visitor->Trace(constructor_);
  visitor->Trace(intrinsic_sizes_);
  visitor->Trace(layout_);
  visitor->Trace(script_state_);
}

}  // namespace blink
```