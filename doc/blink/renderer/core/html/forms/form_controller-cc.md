Response:
Let's break down the thought process for analyzing this `form_controller.cc` file.

1. **Understand the Goal:** The core request is to analyze the functionality of this Chromium Blink engine source file (`form_controller.cc`) and relate it to web technologies (JavaScript, HTML, CSS). We also need to look for logical reasoning (input/output) and common user/programming errors.

2. **Initial Scan and Keyword Spotting:**  Quickly scan the file for prominent keywords and concepts. Things that jump out:

    * `FormController` (obviously central)
    * `FormControlState` (related to form data)
    * `SavedFormState` (persistence of form data)
    * `HTMLFormElement`, `HTMLInputElement` (HTML elements)
    * `SerializeTo`, `Deserialize` (data handling)
    * `RestoreControlState` (core function)
    * `DocumentState` (tied to the document lifecycle)
    * `FormKeyGenerator` (identifying forms)
    * Mentions of "dirty control" and user editing.

3. **Identify Core Responsibilities of `FormController`:** Based on the initial scan, the primary responsibility seems to be managing the *state* of HTML forms and their controls. This includes saving and restoring this state.

4. **Deconstruct Key Classes and Their Roles:**

    * **`FormControlState`:**  This is the fundamental unit of data. It holds the *values* of form controls. The serialization/deserialization methods indicate how this data is stored and retrieved.

    * **`SavedFormState`:**  This acts as a container for multiple `FormControlState` objects. It appears to group states related to a specific form (or controls without a form). The `ControlKey` structure within it hints at how individual controls are identified (name and type).

    * **`FormKeyGenerator`:** This is crucial for uniquely identifying forms. It uses the form's `action` URL and the names of some of its controls to create a unique key. This is essential for correctly associating saved state with the right form, especially when multiple forms exist on a page.

    * **`DocumentState`:**  This class seems to manage the overall form state for the *entire document*. It holds a list of stateful form controls and orchestrates the saving of their states.

    * **`FormController` (itself):** This is the orchestrator. It manages the `DocumentState`, uses `FormKeyGenerator`, and interacts with `SavedFormState` to save and restore form data. It's the entry point for interacting with form state management.

5. **Relate to Web Technologies (HTML, JavaScript, CSS):**

    * **HTML:** The code directly deals with HTML form elements (`<form>`, `<input>`, etc.). The saving and restoring of state are directly linked to how users interact with these HTML elements.

    * **JavaScript:**  While the C++ code doesn't directly *execute* JavaScript, its functionality has a significant impact on how JavaScript interacts with forms. For instance, if a form's state is restored, JavaScript event handlers might be triggered or the initial values set by JavaScript might be overridden. Also, JavaScript can programmatically change form values, and the `FormController` likely plays a role in tracking or responding to these changes (though this file primarily focuses on persistence).

    * **CSS:** CSS is less directly involved. The *styling* of form elements doesn't directly affect the *data* they hold. However, CSS might influence how a user *perceives* the state (e.g., a disabled field appearing grayed out).

6. **Identify Logical Reasoning and Input/Output:** Focus on the `SerializeTo` and `Deserialize` methods of `FormControlState` and `SavedFormState`. The serialization format is clearly defined, allowing us to infer the input (control values) and the output (a serialized string representation). The `FormKeyGenerator` also uses a specific logic (form action and control names) to generate the form key.

7. **Look for Potential User/Programming Errors:**  Consider scenarios where things might go wrong:

    * **Conflicting form names/IDs:**  While the `FormKeyGenerator` tries to handle this, very similar forms might still cause issues.
    * **Incorrect serialization/deserialization:**  Errors in the format could lead to data loss or corruption.
    * **Assumptions about "dirtiness":** The logic for determining if a control has been edited might not be foolproof, especially for custom elements.
    * **Race conditions:** If form state is being restored while the page is still loading or being manipulated by scripts, there could be unexpected behavior.

8. **Structure the Answer:** Organize the findings logically:

    * Start with a high-level overview of the file's purpose.
    * Detail the core functionalities.
    * Provide specific examples related to HTML, JavaScript, and CSS.
    * Explain the logical reasoning with input/output examples.
    * Discuss potential errors and provide illustrative scenarios.

9. **Refine and Elaborate:** Review the generated answer. Add more details, clarify ambiguities, and ensure the language is precise and easy to understand. For instance, explicitly explain *why* the `FormKeyGenerator` is necessary (to handle multiple forms). Provide concrete examples for user errors (like relying on browser history without proper form state management).

Self-Correction during the process:

* **Initial thought:** Focus heavily on the individual control states.
* **Correction:** Realize the importance of the `SavedFormState` and `FormKeyGenerator` in organizing and identifying these states. The context of the form is crucial.
* **Initial thought:**  Assume a direct link to JavaScript execution.
* **Correction:**  Recognize that the C++ code *manages* the state, which *influences* how JavaScript behaves, but doesn't directly execute JavaScript.
* **Initial thought:**  Overlook the "dirty control" logic.
* **Correction:**  Identify this as an important aspect of avoiding overwriting user input.

By following these steps, iteratively analyzing the code, and refining the understanding, we can arrive at a comprehensive and accurate explanation of the `form_controller.cc` file's functionality.
根据提供的 Chromium Blink 引擎源代码文件 `blink/renderer/core/html/forms/form_controller.cc`，我们可以列举出它的主要功能如下：

**核心功能：管理和维护 HTML 表单控件的状态**

`FormController` 的核心职责是负责在浏览器中保存和恢复 HTML 表单控件的状态。 这使得用户在页面刷新、前进/后退导航等操作后，表单中的数据能够被保留，提升用户体验。

**具体功能点：**

1. **状态序列化 (Serialization)：**
   - 将表单控件的当前状态（例如，输入框中的文本、复选框的选中状态、下拉框的选择等）转换成一种可以存储的格式 (字符串向量 `Vector<String>`)。
   - 这包括遍历文档中的所有支持状态恢复的表单控件。
   - 使用 `FormControlState` 类来存储单个控件的状态。
   - 使用 `SavedFormState` 类来管理一组属于同一个表单的 `FormControlState`。
   - 使用 `FormKeyGenerator` 来为每个表单生成唯一的键值，以便在恢复状态时能够正确地关联控件和其对应的状态数据。

2. **状态反序列化 (Deserialization)：**
   - 将存储的表单控件状态数据 (字符串向量) 转换回 `FormControlState` 对象。
   - 这发生在页面加载或导航恢复时。
   - 根据生成的表单键值，从存储的数据中找到对应的 `SavedFormState`，然后从中提取特定控件的 `FormControlState`。

3. **状态恢复 (Restoration)：**
   - 将反序列化得到的 `FormControlState` 应用到对应的 HTML 表单控件上，使其恢复到之前的状态。
   - 这会更新控件的值、选中状态等。
   - `RestoreControlStateFor` 方法处理没有 `form` 属性的控件。
   - `RestoreControlStateIn` 方法处理属于特定 `HTMLFormElement` 的控件。
   - `RestoreControlStateInternal` 是执行实际恢复操作的核心方法。

4. **表单识别和管理：**
   - 使用 `FormKeyGenerator` 根据表单的 `action` 属性和部分控件的名称生成唯一的键值，以便区分不同的表单。
   - 管理没有 `form` 属性的控件的状态。

5. **处理 "dirty" 状态：**
   - 避免覆盖用户已经编辑过的表单控件的值。
   - `IsDirtyControl` 函数判断控件是否被用户编辑过。

6. **异步恢复：**
   - 使用任务队列 (`TaskQueue`) 异步地恢复表单状态，避免阻塞主线程，提升页面加载性能。
   - `ScheduleRestore` 和 `RestoreImmediately` 方法控制恢复的时机。

7. **获取引用的文件路径：**
   - `GetReferencedFilePaths` 方法用于从保存的状态中提取 `<input type="file">` 控件引用的文件路径。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  `FormController` 直接操作 HTML 表单元素 (`HTMLFormElement`) 和表单控件元素 (`HTMLInputElement` 等)。它的主要目的是维护这些 HTML 元素的状态。
    * **举例：** 当用户在一个文本输入框中输入 "hello"，然后刷新页面。`FormController` 会保存这个 "hello" 状态。当页面重新加载时，`FormController` 会将 "hello" 恢复到该输入框中。
* **JavaScript:** `FormController` 的行为会影响 JavaScript 与表单的交互。
    * **举例：** JavaScript 可能会监听表单的 `change` 或 `input` 事件。当 `FormController` 恢复状态时，可能会触发这些事件，如同用户手动操作一样。
    * **举例：** JavaScript 代码可能会预先设置表单的值。`FormController` 的恢复操作可能会覆盖这些 JavaScript 设置的值，这取决于恢复的时机和 "dirty" 状态的判断。
* **CSS:**  `FormController` 与 CSS 的关系较弱，主要体现在 CSS 可能会影响表单控件的显示状态，例如禁用状态 (`disabled`) 或只读状态 (`readonly`)。`FormController` 在恢复状态时会考虑这些状态。
    * **举例：** 如果一个输入框设置了 `disabled` 属性，`FormController` 在恢复状态时通常不会恢复其值，因为禁用状态意味着用户无法修改。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

1. 一个包含以下 HTML 表单的页面：
    ```html
    <form action="/submit">
      <input type="text" name="username" value="">
      <input type="checkbox" name="remember" checked>
      <select name="country">
        <option value="us">USA</option>
        <option value="cn" selected>China</option>
      </select>
    </form>
    ```
2. 用户在文本框中输入 "JohnDoe"。
3. 用户取消选中了复选框。
4. 用户保持选择了 "China"。
5. 用户刷新了页面。

**逻辑推理过程：**

1. `FormController` 在页面卸载前会捕获表单控件的状态。
2. `FormKeyGenerator` 会为该表单生成一个键值（基于 `action="/submit"` 和可能的控件名称）。
3. `FormControlState` 会为每个控件保存状态：
    - `username`: 值 "JohnDoe"
    - `remember`: 值 "false" (未选中)
    - `country`: 值 "cn" (选中)
4. 这些 `FormControlState` 会被组织到 `SavedFormState` 中，并与表单的键值关联。
5. 当页面重新加载时，`FormController` 会根据表单键值找到之前保存的 `SavedFormState`。
6. `FormController` 将反序列化 `FormControlState`。
7. `FormController` 调用 `RestoreControlStateInternal` 方法。

**预期输出：**

1. 页面加载后，文本输入框的值仍然是 "JohnDoe"。
2. 复选框处于未选中状态。
3. 下拉框仍然选中 "China"。

**涉及用户或编程常见的使用错误：**

1. **程序员假设状态总是会被恢复：**  开发者不能完全依赖浏览器自动恢复表单状态，尤其是在复杂的单页应用中。 某些情况下，例如跨域导航或使用 JavaScript 动态修改表单结构，浏览器的默认行为可能不会按预期工作。开发者可能需要手动管理表单状态。
    * **举例：** 一个使用 JavaScript 动态添加或删除表单控件的应用，如果仅仅依赖浏览器的默认状态恢复，可能会遇到控件状态丢失或恢复错误的情况。

2. **用户期望所有表单数据都被持久化：**  用户可能认为所有在表单中输入的数据都会被保存，但实际上，浏览器通常只保存简单的表单控件状态。对于复杂控件或自定义行为，可能需要开发者自己实现持久化逻辑。
    * **举例：** 用户在一个富文本编辑器中输入了大量内容，然后刷新页面，可能会发现内容丢失，因为浏览器的默认表单状态恢复机制可能无法处理这种复杂的控件。

3. **依赖浏览器的后退/前进缓存而没有考虑到状态恢复：** 开发者可能会依赖浏览器的后退/前进缓存来恢复页面状态，但如果没有正确理解 `FormController` 的工作方式，可能会导致表单状态不一致。
    * **举例：** 用户在一个多步骤表单中填写了数据，然后点击“后退”按钮。如果开发者没有考虑到状态恢复，用户可能会看到之前填写的数据丢失，或者表单状态与页面的其他部分不一致。

4. **在禁用或只读控件上期望状态被恢复：** 用户或开发者可能会期望禁用或只读的控件在页面刷新后能够记住之前的值。虽然 `FormController` 会保存这些控件的状态，但在恢复时通常会跳过这些控件，因为它们在当前状态下无法被用户修改。
    * **举例：**  一个禁用的输入框，用户可能希望刷新后仍然能看到之前的值，但 `FormController` 可能会因为控件被禁用而跳过恢复。

总而言之，`blink/renderer/core/html/forms/form_controller.cc` 文件是 Chromium 浏览器引擎中负责核心表单状态管理的关键组件，它在幕后默默地工作，为用户提供更好的浏览体验。理解其功能有助于开发者更好地理解浏览器的行为，并避免在开发过程中犯一些常见的错误。

### 提示词
```
这是目录为blink/renderer/core/html/forms/form_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2008, 2009, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2010, 2011, 2012 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/html/forms/form_controller.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/file_chooser.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/listed_element.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/hash_table_deleted_value_type.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

inline HTMLFormElement* OwnerFormForState(const ListedElement& control) {
  // Assume controls with form attribute have no owners because we restore
  // state during parsing and form owners of such controls might be
  // indeterminate.
  return control.ToHTMLElement().FastHasAttribute(html_names::kFormAttr)
             ? nullptr
             : control.Form();
}

const AtomicString& ControlType(const ListedElement& control) {
  if (auto* control_element = DynamicTo<HTMLFormControlElement>(control))
    return control_element->type();
  return To<ElementInternals>(control).Target().localName();
}

bool IsDirtyControl(const ListedElement& control) {
  if (auto* form_control_element =
          DynamicTo<HTMLFormControlElementWithState>(control))
    return form_control_element->UserHasEditedTheField();
  if (control.IsElementInternals()) {
    // We have no ways to know the dirtiness of a form-associated custom
    // element.  Assume it is dirty if it has focus.
    // TODO(tkent): If this approach is not enough, we should check existence
    // of past user-input events such as 'mousedown', 'keydown', 'touchstart'.
    return control.ToHTMLElement().HasFocusWithin();
  }
  DCHECK(!control.ClassSupportsStateRestore());
  return false;
}

}  // namespace

// ----------------------------------------------------------------------------

// Serilized form of FormControlState:
//  (',' means strings around it are separated in stateVector.)
//
// SerializedControlState ::= SkipState | RestoreState
// SkipState ::= '0'
// RestoreState ::= UnsignedNumber, ControlValue+
// UnsignedNumber ::= [0-9]+
// ControlValue ::= arbitrary string
//
// RestoreState has a sequence of ControlValues. The length of the
// sequence is represented by UnsignedNumber.

void FormControlState::SerializeTo(Vector<String>& state_vector) const {
  DCHECK(!IsFailure());
  state_vector.push_back(String::Number(values_.size()));
  for (const auto& value : values_)
    state_vector.push_back(value.IsNull() ? g_empty_string : value);
}

FormControlState FormControlState::Deserialize(
    const Vector<String>& state_vector,
    wtf_size_t& index) {
  if (index >= state_vector.size())
    return FormControlState(kTypeFailure);
  unsigned value_size = state_vector[index++].ToUInt();
  if (!value_size)
    return FormControlState();
  if (index + value_size > state_vector.size())
    return FormControlState(kTypeFailure);
  FormControlState state;
  state.values_.reserve(value_size);
  for (unsigned i = 0; i < value_size; ++i)
    state.Append(state_vector[index++]);
  return state;
}

// ----------------------------------------------------------------------------

class ControlKey {
 public:
  ControlKey(StringImpl* = nullptr, StringImpl* = nullptr);
  ~ControlKey();
  ControlKey(const ControlKey&);
  ControlKey& operator=(const ControlKey&);

  StringImpl* GetName() const { return name_; }
  StringImpl* GetType() const { return type_; }

  // Hash table deleted values, which are only constructed and never copied or
  // destroyed.
  ControlKey(WTF::HashTableDeletedValueType) : name_(HashTableDeletedValue()) {}
  bool IsHashTableDeletedValue() const {
    return name_ == HashTableDeletedValue();
  }

 private:
  void Ref() const;
  void Deref() const;

  static StringImpl* HashTableDeletedValue() {
    return reinterpret_cast<StringImpl*>(-1);
  }

  StringImpl* name_;
  StringImpl* type_;
};

ControlKey::ControlKey(StringImpl* name, StringImpl* type)
    : name_(name), type_(type) {
  Ref();
}

ControlKey::~ControlKey() {
  Deref();
}

ControlKey::ControlKey(const ControlKey& other)
    : name_(other.GetName()), type_(other.GetType()) {
  Ref();
}

ControlKey& ControlKey::operator=(const ControlKey& other) {
  other.Ref();
  Deref();
  name_ = other.GetName();
  type_ = other.GetType();
  return *this;
}

void ControlKey::Ref() const {
  if (GetName())
    GetName()->AddRef();
  if (GetType())
    GetType()->AddRef();
}

void ControlKey::Deref() const {
  if (GetName())
    GetName()->Release();
  if (GetType())
    GetType()->Release();
}

inline bool operator==(const ControlKey& a, const ControlKey& b) {
  return a.GetName() == b.GetName() && a.GetType() == b.GetType();
}

struct ControlKeyHashTraits : SimpleClassHashTraits<ControlKey> {
  static unsigned GetHash(const ControlKey& key) {
    return StringHasher::HashMemory(base::byte_span_from_ref(key));
  }
};

// ----------------------------------------------------------------------------

// SavedFormState represents a set of FormControlState.
// It typically manages controls associated to a single <form>.  Controls
// without owner forms are managed by a dedicated SavedFormState.
class SavedFormState {
  USING_FAST_MALLOC(SavedFormState);

 public:
  SavedFormState() : control_state_count_(0) {}
  SavedFormState(const SavedFormState&) = delete;
  SavedFormState& operator=(const SavedFormState&) = delete;

  static std::unique_ptr<SavedFormState> Deserialize(const Vector<String>&,
                                                     wtf_size_t& index);
  void SerializeTo(Vector<String>&) const;
  bool IsEmpty() const { return state_for_new_controls_.empty(); }
  void AppendControlState(const AtomicString& name,
                          const AtomicString& type,
                          const FormControlState&);
  FormControlState TakeControlState(const AtomicString& name,
                                    const AtomicString& type);

  Vector<String> GetReferencedFilePaths() const;

 private:
  using ControlStateMap =
      HashMap<ControlKey, Deque<FormControlState>, ControlKeyHashTraits>;
  ControlStateMap state_for_new_controls_;
  wtf_size_t control_state_count_;
};

static bool IsNotFormControlTypeCharacter(UChar ch) {
  return ch != '-' && (ch > 'z' || ch < 'a');
}

std::unique_ptr<SavedFormState> SavedFormState::Deserialize(
    const Vector<String>& state_vector,
    wtf_size_t& index) {
  if (index >= state_vector.size())
    return nullptr;
  // FIXME: We need String::toSizeT().
  wtf_size_t item_count = state_vector[index++].ToUInt();
  if (!item_count)
    return nullptr;
  std::unique_ptr<SavedFormState> saved_form_state =
      base::WrapUnique(new SavedFormState);
  while (item_count--) {
    if (index + 1 >= state_vector.size())
      return nullptr;
    String name = state_vector[index++];
    String type = state_vector[index++];
    FormControlState state = FormControlState::Deserialize(state_vector, index);
    if (type.empty() ||
        (type.Find(IsNotFormControlTypeCharacter) != kNotFound &&
         !CustomElement::IsValidName(AtomicString(type))) ||
        state.IsFailure())
      return nullptr;
    saved_form_state->AppendControlState(AtomicString(name), AtomicString(type),
                                         state);
  }
  return saved_form_state;
}

void SavedFormState::SerializeTo(Vector<String>& state_vector) const {
  state_vector.push_back(String::Number(control_state_count_));
  for (const auto& form_control : state_for_new_controls_) {
    const ControlKey& key = form_control.key;
    const Deque<FormControlState>& queue = form_control.value;
    for (const FormControlState& form_control_state : queue) {
      state_vector.push_back(key.GetName());
      state_vector.push_back(key.GetType());
      form_control_state.SerializeTo(state_vector);
    }
  }
}

void SavedFormState::AppendControlState(const AtomicString& name,
                                        const AtomicString& type,
                                        const FormControlState& state) {
  ControlKey key(name.Impl(), type.Impl());
  ControlStateMap::iterator it = state_for_new_controls_.find(key);
  if (it != state_for_new_controls_.end()) {
    it->value.push_back(state);
  } else {
    Deque<FormControlState> state_list;
    state_list.push_back(state);
    state_for_new_controls_.Set(key, state_list);
  }
  control_state_count_++;
}

FormControlState SavedFormState::TakeControlState(const AtomicString& name,
                                                  const AtomicString& type) {
  if (state_for_new_controls_.empty())
    return FormControlState();
  ControlStateMap::iterator it =
      state_for_new_controls_.find(ControlKey(name.Impl(), type.Impl()));
  if (it == state_for_new_controls_.end())
    return FormControlState();
  DCHECK_GT(it->value.size(), 0u);
  FormControlState state = it->value.TakeFirst();
  control_state_count_--;
  if (it->value.empty())
    state_for_new_controls_.erase(it);
  return state;
}

Vector<String> SavedFormState::GetReferencedFilePaths() const {
  Vector<String> to_return;
  for (const auto& form_control : state_for_new_controls_) {
    const ControlKey& key = form_control.key;
    if (!Equal(key.GetType(), base::span_from_cstring("file"))) {
      continue;
    }
    const Deque<FormControlState>& queue = form_control.value;
    for (const FormControlState& form_control_state : queue) {
      to_return.AppendVector(
          HTMLInputElement::FilesFromFileInputFormControlState(
              form_control_state));
    }
  }
  return to_return;
}

// ----------------------------------------------------------------------------

class FormKeyGenerator final : public GarbageCollected<FormKeyGenerator> {
 public:
  FormKeyGenerator() = default;
  FormKeyGenerator(const FormKeyGenerator&) = delete;
  FormKeyGenerator& operator=(const FormKeyGenerator&) = delete;

  void Trace(Visitor* visitor) const { visitor->Trace(form_to_key_map_); }
  const AtomicString& FormKey(const ListedElement&);
  void WillDeleteForm(HTMLFormElement*);

 private:
  using FormToKeyMap = HeapHashMap<Member<HTMLFormElement>, AtomicString>;
  using FormSignatureToNextIndexMap = HashMap<String, unsigned>;
  FormToKeyMap form_to_key_map_;
  FormSignatureToNextIndexMap form_signature_to_next_index_map_;
};

static inline void RecordFormStructure(const HTMLFormElement& form,
                                       StringBuilder& builder) {
  // 2 is enough to distinguish forms in webkit.org/b/91209#c0
  const wtf_size_t kNamedControlsToBeRecorded = 2;
  const ListedElement::List& controls = form.ListedElements();
  builder.Append(" [");
  for (wtf_size_t i = 0, named_controls = 0;
       i < controls.size() && named_controls < kNamedControlsToBeRecorded;
       ++i) {
    ListedElement& control = *controls[i];
    if (!control.ClassSupportsStateRestore())
      continue;
    // The resultant string will be fragile if it contains a name of a
    // form-associated custom element. It's associated to the |form| only if its
    // custom element definition is available.  It's not associated if the
    // definition is unavailable though the element structure is identical.
    if (control.IsElementInternals())
      continue;
    if (!OwnerFormForState(control))
      continue;
    AtomicString name = control.GetName();
    if (name.empty())
      continue;
    named_controls++;
    builder.Append(name);
    builder.Append(' ');
  }
  builder.Append(']');
}

String FormSignature(const HTMLFormElement& form) {
  KURL action_url = form.GetURLAttributeAsKURL(html_names::kActionAttr);
  // Remove the query part because it might contain volatile parameters such
  // as a session key.
  if (!action_url.IsEmpty())
    action_url.SetQuery(String());

  StringBuilder builder;
  if (!action_url.IsEmpty())
    builder.Append(action_url.GetString());

  RecordFormStructure(form, builder);
  return builder.ToString();
}

const AtomicString& FormKeyGenerator::FormKey(const ListedElement& control) {
  HTMLFormElement* form = OwnerFormForState(control);
  if (!form) {
    DEFINE_STATIC_LOCAL(const AtomicString, form_key_for_no_owner,
                        ("No owner"));
    return form_key_for_no_owner;
  }
  FormToKeyMap::const_iterator it = form_to_key_map_.find(form);
  if (it != form_to_key_map_.end())
    return it->value;

  String signature = FormSignature(*form);
  DCHECK(!signature.IsNull());
  FormSignatureToNextIndexMap::AddResult result =
      form_signature_to_next_index_map_.insert(signature, 0);
  unsigned next_index = result.stored_value->value++;

  StringBuilder form_key_builder;
  form_key_builder.Append(signature);
  form_key_builder.Append(" #");
  form_key_builder.AppendNumber(next_index);
  FormToKeyMap::AddResult add_form_keyresult =
      form_to_key_map_.insert(form, form_key_builder.ToAtomicString());
  return add_form_keyresult.stored_value->value;
}

void FormKeyGenerator::WillDeleteForm(HTMLFormElement* form) {
  DCHECK(form);
  form_to_key_map_.erase(form);
}

// ----------------------------------------------------------------------------

DocumentState::DocumentState(Document& document) : document_(document) {}

void DocumentState::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(control_list_);
}

void DocumentState::InvalidateControlList() {
  if (is_control_list_dirty_)
    return;
  control_list_.resize(0);
  is_control_list_dirty_ = true;
}

const DocumentState::ControlList& DocumentState::GetControlList() {
  if (is_control_list_dirty_) {
    for (auto& element : Traversal<Element>::DescendantsOf(*document_)) {
      if (auto* control = ListedElement::From(element)) {
        if (control->ClassSupportsStateRestore())
          control_list_.push_back(control);
      }
    }
    is_control_list_dirty_ = false;
  }
  return control_list_;
}

static String FormStateSignature() {
  // In the legacy version of serialized state, the first item was a name
  // attribute value of a form control. The following string literal should
  // contain some characters which are rarely used for name attribute values.
  DEFINE_STATIC_LOCAL(String, signature,
                      ("\n\r?% Blink serialized form state version 10 \n\r=&"));
  return signature;
}

Vector<String> DocumentState::ToStateVector() {
  auto* key_generator = MakeGarbageCollected<FormKeyGenerator>();
  std::unique_ptr<SavedFormStateMap> state_map =
      base::WrapUnique(new SavedFormStateMap);
  for (auto& control : GetControlList()) {
    DCHECK(control->ToHTMLElement().isConnected());
    if (!control->ShouldSaveAndRestoreFormControlState())
      continue;
    SavedFormStateMap::AddResult result =
        state_map->insert(key_generator->FormKey(*control), nullptr);
    if (result.is_new_entry)
      result.stored_value->value = std::make_unique<SavedFormState>();
    result.stored_value->value->AppendControlState(
        control->GetName(), ControlType(*control),
        control->SaveFormControlState());
  }

  Vector<String> state_vector;
  state_vector.ReserveInitialCapacity(GetControlList().size() * 4);
  state_vector.push_back(FormStateSignature());
  for (const auto& saved_form_state : *state_map) {
    state_vector.push_back(saved_form_state.key);
    saved_form_state.value->SerializeTo(state_vector);
  }
  bool has_only_signature = state_vector.size() == 1;
  if (has_only_signature)
    state_vector.clear();
  return state_vector;
}

// ----------------------------------------------------------------------------

FormController::FormController(Document& document)
    : document_(document),
      document_state_(MakeGarbageCollected<DocumentState>(document)) {}

FormController::~FormController() = default;

void FormController::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(document_state_);
  visitor->Trace(form_key_generator_);
}

DocumentState* FormController::ControlStates() const {
  return document_state_.Get();
}

void FormController::SetStateForNewControls(
    const Vector<String>& state_vector) {
  ControlStatesFromStateVector(state_vector, saved_form_state_map_);
}

bool FormController::HasControlStates() const {
  return !saved_form_state_map_.empty();
}

FormControlState FormController::TakeStateForControl(
    const ListedElement& control) {
  if (saved_form_state_map_.empty())
    return FormControlState();
  if (!form_key_generator_)
    form_key_generator_ = MakeGarbageCollected<FormKeyGenerator>();
  SavedFormStateMap::iterator it =
      saved_form_state_map_.find(form_key_generator_->FormKey(control));
  if (it == saved_form_state_map_.end())
    return FormControlState();
  FormControlState state =
      it->value->TakeControlState(control.GetName(), ControlType(control));
  if (it->value->IsEmpty())
    saved_form_state_map_.erase(it);
  return state;
}

void FormController::ControlStatesFromStateVector(
    const Vector<String>& state_vector,
    SavedFormStateMap& map) {
  map.clear();

  wtf_size_t i = 0;
  if (state_vector.size() < 1 || state_vector[i++] != FormStateSignature())
    return;

  while (i + 1 < state_vector.size()) {
    AtomicString form_key = AtomicString(state_vector[i++]);
    std::unique_ptr<SavedFormState> state =
        SavedFormState::Deserialize(state_vector, i);
    if (!state) {
      i = 0;
      break;
    }
    map.insert(form_key, std::move(state));
  }
  if (i != state_vector.size())
    map.clear();
}

void FormController::WillDeleteForm(HTMLFormElement* form) {
  if (form_key_generator_)
    form_key_generator_->WillDeleteForm(form);
}

void FormController::RestoreControlStateFor(ListedElement& control) {
  if (!document_->HasFinishedParsing())
    return;
  if (OwnerFormForState(control))
    return;
  RestoreControlStateInternal(control);
}

void FormController::RestoreControlStateIn(HTMLFormElement& form) {
  if (!document_->HasFinishedParsing())
    return;
  EventQueueScope scope;
  const ListedElement::List& elements = form.ListedElements();
  for (const auto& control : elements) {
    if (!control->ClassSupportsStateRestore())
      continue;
    if (OwnerFormForState(*control) != &form)
      continue;
    RestoreControlStateInternal(*control);
  }
}

void FormController::RestoreControlStateInternal(ListedElement& control) {
  // We don't save state of a control with
  // ShouldSaveAndRestoreFormControlState() == false. But we need to skip
  // restoring process too because a control in another form might have the same
  // pair of name and type and saved its state.
  if (!control.ShouldSaveAndRestoreFormControlState())
    return;
  FormControlState state = TakeStateForControl(control);
  if (state.ValueSize() <= 0)
    return;
  HTMLElement& element = control.ToHTMLElement();
  if (element.IsDisabledFormControl() ||
      element.FastHasAttribute(html_names::kReadonlyAttr))
    return;
  // If a user already edited the control, we should not overwrite it.
  if (IsDirtyControl(control))
    return;
  // RestoreFormControlState might dispatch input/change events.
  control.RestoreFormControlState(state);
}

void FormController::RestoreControlStateOnUpgrade(ListedElement& control) {
  DCHECK(control.ClassSupportsStateRestore());
  if (!control.ShouldSaveAndRestoreFormControlState())
    return;
  FormControlState state = TakeStateForControl(control);
  if (state.ValueSize() > 0)
    control.RestoreFormControlState(state);
}

void FormController::ScheduleRestore() {
  document_->GetTaskRunner(TaskType::kInternalLoading)
      ->PostTask(
          FROM_HERE,
          WTF::BindOnce(&FormController::RestoreAllControlsInDocumentOrder,
                        WrapPersistent(this)));
}

void FormController::RestoreImmediately() {
  if (did_restore_all_ || !HasControlStates())
    return;
  RestoreAllControlsInDocumentOrder();
}

void FormController::RestoreAllControlsInDocumentOrder() {
  if (!document_->IsActive() || did_restore_all_)
    return;
  HeapHashSet<Member<HTMLFormElement>> finished_forms;
  EventQueueScope scope;
  for (auto& control : document_state_->GetControlList()) {
    auto* owner = OwnerFormForState(*control);
    if (!owner)
      RestoreControlStateFor(*control);
    else if (finished_forms.insert(owner).is_new_entry)
      RestoreControlStateIn(*owner);
  }
  did_restore_all_ = true;
}

Vector<String> FormController::GetReferencedFilePaths(
    const Vector<String>& state_vector) {
  Vector<String> to_return;
  SavedFormStateMap map;
  ControlStatesFromStateVector(state_vector, map);
  for (const auto& saved_form_state : map)
    to_return.AppendVector(saved_form_state.value->GetReferencedFilePaths());
  return to_return;
}

void FormController::InvalidateStatefulFormControlList() {
  document_state_->InvalidateControlList();
}

}  // namespace blink
```