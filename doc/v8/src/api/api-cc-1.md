Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understanding the Request:** The core request is to analyze a specific C++ source file (`v8/src/api/api.cc`, specifically a segment of it) and explain its functionality. Key constraints include identifying if it's a Torque file (based on extension), its relationship to JavaScript, providing JavaScript examples, demonstrating code logic with examples, highlighting common errors, and finally summarizing the functionality of this specific part.

2. **Initial Scan for Clues:**  The first thing I do is quickly scan the code for keywords and patterns that provide immediate insights.

    * **`HandleScope`:**  This immediately stands out. Handle scopes are fundamental to V8's memory management and the API. The presence of `HandleScope`, `EscapableHandleScopeBase`, and `SealHandleScope` strongly suggests this section deals with managing V8 objects and preventing garbage collection issues.
    * **`Isolate`:** The frequent use of `Isolate` reinforces the idea that this code interacts directly with the V8 engine's core. `Isolate` represents an isolated instance of the V8 JavaScript engine.
    * **`Context`:** The `Context` class is present, and methods like `Enter()` and `Exit()` are clear indicators of managing execution contexts within V8.
    * **`Template` and `FunctionTemplate`:** These classes are central to V8's object and function creation mechanisms in the API. Methods like `Set`, `SetAccessorProperty`, `Inherit`, `New`, `SetCallHandler`, `InstanceTemplate`, etc., are typical of template manipulation.
    * **`Utils::ApiCheck`:** This pattern signifies runtime assertions and error checking within the V8 API.
    * **No `.tq` extension mentioned:** The prompt explicitly asks to check if the file ends with `.tq`. Since the provided snippet is `.cc`, it's C++ and not Torque.
    * **Comments:**  The comments are helpful, often explaining the purpose of certain blocks of code.

3. **Deconstructing Key Classes:**  I then focus on the major classes and their methods:

    * **`HandleScope`:**
        * Constructor/Destructor:  These likely manage the allocation and deallocation of handles (pointers to V8 objects).
        * `Initialize()`:  Sets up the handle scope. The locking check is important for thread safety.
        * `CloseScope()`: Cleans up the handle scope.
        * `CreateHandle()`:  Creates a new handle.
        * The overloaded `new` and `delete` operators calling `base::OS::Abort()` indicate that `HandleScope` objects are intended to be stack-allocated and not dynamically allocated.
        * `NumberOfHandles()`:  Returns the number of handles within the scope.
    * **`EscapableHandleScopeBase`:**  The "Escapable" part suggests this allows handles created within the scope to persist beyond the scope's lifetime. `EscapeSlot` confirms this.
    * **`SealHandleScope`:**  The name implies a restriction on creating new handles within this scope. The code manipulating `limit` and `sealed_level` supports this.
    * **`Data`:**  Simple methods like `IsModule`, `IsFixedArray`, `IsValue`, `IsPrivate`, `IsObjectTemplate`, `IsFunctionTemplate`, `IsContext` suggest it's a base class for representing various V8 data types.
    * **`Context`:**
        * `Enter()`/`Exit()`: Manage entering and exiting JavaScript execution contexts. The interaction with `HandleScopeImplementer` is a detail, but the core function is clear.
        * `BackupIncumbentScope`: Deals with tracking the "incumbent" context, which is relevant for debugging and stack traces.
        * `GetNumberOfEmbedderDataFields()`/`GetEmbedderData()`/`SetEmbedderData()`/`GetAlignedPointerFromEmbedderData()`/`SetAlignedPointerInEmbedderData()`: These methods manage "embedder data," which allows the embedding application to associate custom data with a V8 context.
    * **`Template`:**
        * `Set()`/`SetPrivate()`:  Define properties on the template.
        * `SetAccessorProperty()`:  Defines accessor properties (with getter and setter functions).
    * **`FunctionTemplate`:**
        * `PrototypeTemplate()`:  Gets or creates the prototype template.
        * `SetPrototypeProviderTemplate()`: Allows specifying a function to provide the prototype.
        * `Inherit()`: Sets up inheritance between function templates.
        * `New()`: Creates a new function template. The various overloads handle different options like signatures and C++ function callbacks.
        * `SetCallHandler()`:  Associates a JavaScript function (or a C++ callback) with the function template.
        * `InstanceTemplate()`: Gets the template for instances of the function.
        * `SetLength()`/`SetClassName()`/`SetInterfaceName()`/`SetExceptionContext()`/`SetAcceptAnyReceiver()`/`ReadOnlyPrototype()`/`RemovePrototype()`: These methods configure various aspects of the function template.
    * **`ObjectTemplate`:**
        * `New()`: Creates a new object template.
        * `SetNativeDataProperty()`/`SetLazyDataProperty()`/`SetIntrinsicDataProperty()`: Define properties on the object template, including native accessors and intrinsics.

4. **Identifying JavaScript Relationships:**  Once I understand the C++ API, I connect it back to JavaScript concepts.

    * `HandleScope`:  While not directly exposed in JS, it's crucial for the V8 engine to manage JS object lifetimes. Incorrect handle usage can lead to crashes or memory leaks.
    * `Context`: Maps directly to the concept of a JavaScript execution context (global object, etc.).
    * `Template`/`ObjectTemplate`: Used to create blueprints for JavaScript objects.
    * `FunctionTemplate`: Used to create blueprints for JavaScript functions (constructors).
    * Accessor properties, prototypes, inheritance, etc., all have direct counterparts in JavaScript.

5. **Crafting Examples:**  For each relevant C++ construct, I think of the equivalent JavaScript code. This clarifies the purpose of the C++ API.

6. **Code Logic and Examples:**  For the more involved parts (like `HandleScope`), I consider simplified scenarios and the expected behavior. The handle count example illustrates the nesting and behavior of handle scopes.

7. **Common Programming Errors:** I think about how developers might misuse these API elements, especially those new to V8 or C++ extensions. Forgetting to use `HandleScope`, incorrect locking, and confusion about template lifecycles are common pitfalls.

8. **Summarization:** Finally, I synthesize the information gathered into a concise summary that captures the main functions of the code snippet. The key here is to focus on the overall purpose rather than individual method details.

9. **Iteration and Refinement:**  Throughout this process, I might revisit earlier steps if I gain new understanding. For instance, realizing that `HandleScope`'s overloaded operators abort the program clarifies its intended usage. I also refine the language of my explanations to be clear and accurate.

By following this structured approach, I can effectively analyze the C++ code and provide a comprehensive explanation as requested.
```javascript
// 假设我们有一个简单的 JavaScript 函数
function greet(name) {
  return "Hello, " + name + "!";
}

// 我们可以使用 V8 API (在 C++ 中) 来创建和调用这个函数
// 这部分的功能在 api.cc 中有所体现
```

## 功能归纳 (第 2 部分):

这部分代码主要关注 V8 C++ API 中与**内存管理**、**执行上下文**以及**模板（Template）**相关的核心功能。具体来说，它定义了以下关键组成部分：

1. **内存管理 (Handles):**
   - 提供了 `HandleScope` 类，用于管理 V8 对象的生命周期。`HandleScope` 的作用域内创建的 `Handle` 会自动释放，防止内存泄漏。
   - 提供了 `EscapableHandleScopeBase` 类，允许将作用域内创建的 `Handle` "逃逸" 到外部作用域，使其生命周期延长。
   - 提供了 `SealHandleScope` 类，用于在特定作用域内禁止创建新的 `Handle`，用于性能优化或确保某些操作的原子性。

2. **执行上下文 (Contexts):**
   - 提供了 `Context` 类，代表一个 JavaScript 执行上下文（例如，一个全局作用域）。
   - 提供了 `Enter()` 和 `Exit()` 方法，用于进入和退出一个 `Context`，这在嵌入 V8 时执行 JavaScript 代码至关重要。
   - 提供了 `BackupIncumbentScope` 类，用于备份和恢复当前的 "incumbent" 上下文，这与 JavaScript 错误处理和调试有关。
   - 提供了 `GetNumberOfEmbedderDataFields()`、`GetEmbedderData()` 和 `SetEmbedderData()` 等方法，允许嵌入器（使用 V8 的应用程序）在 `Context` 中存储和检索自定义数据。

3. **模板 (Templates):**
   - 提供了 `Template` 类，是 `ObjectTemplate` 和 `FunctionTemplate` 的基类，用于定义 JavaScript 对象的结构和行为。
   - 提供了 `Set()` 和 `SetPrivate()` 方法，用于在模板上设置属性。
   - 提供了 `SetAccessorProperty()` 方法，用于定义具有 getter 和 setter 函数的访问器属性。

4. **函数模板 (Function Templates):**
   - 提供了 `FunctionTemplate` 类，用于创建 JavaScript 函数的蓝图。
   - 提供了 `PrototypeTemplate()` 方法，获取或创建函数原型对象的模板。
   - 提供了 `SetPrototypeProviderTemplate()` 方法，允许自定义原型对象的提供方式。
   - 提供了 `Inherit()` 方法，实现函数模板之间的继承。
   - 提供了 `New()` 方法，创建新的 `FunctionTemplate` 实例。
   - 提供了 `SetCallHandler()` 方法，设置函数被调用时的 C++ 回调函数。
   - 提供了 `InstanceTemplate()` 方法，获取函数实例的模板。
   - 提供了 `SetLength()`、`SetClassName()`、`SetInterfaceName()` 等方法，用于设置函数的相关属性。

5. **对象模板 (Object Templates):**
   - 提供了 `ObjectTemplate` 类，用于创建普通 JavaScript 对象的蓝图。
   - 提供了 `New()` 方法，创建新的 `ObjectTemplate` 实例。
   - 提供了 `SetNativeDataProperty()` 和 `SetLazyDataProperty()` 方法，用于定义由 C++ 代码实现的属性。
   - 提供了 `SetIntrinsicDataProperty()` 方法，用于定义内置的 JavaScript 属性。

**如果 `v8/src/api/api.cc` 以 `.tq` 结尾：**

如果 `v8/src/api/api.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 用于定义内置函数和运行时代码的领域特定语言。这段代码将使用 Torque 的语法来描述 V8 内部操作的实现细节，例如对象创建、属性访问等。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这段 C++ 代码直接支撑了 V8 引擎提供的 JavaScript 功能。以下是一些示例：

* **`HandleScope`:** 虽然 JavaScript 开发者不会直接使用 `HandleScope`，但 V8 引擎内部大量使用它来管理 JavaScript 对象的内存。例如，当 JavaScript 函数返回一个对象时，V8 会在内部使用 `HandleScope` 来确保该对象在返回后仍然有效。

* **`Context`:** JavaScript 的执行总是发生在一个上下文中。每个浏览器窗口或 Node.js 进程通常都有一个或多个上下文。`Context::Enter()` 和 `Context::Exit()` 允许嵌入器在 C++ 中切换到特定的 JavaScript 上下文并执行代码。

  ```javascript
  // 假设在 C++ 中，我们已经获得了一个 v8::Context 对象 context
  // 在 C++ 中调用 context->Enter();

  // 现在我们在这个上下文中执行 JavaScript 代码
  console.log("Hello from the V8 context!");

  // 在 C++ 中调用 context->Exit();
  ```

* **`Template` 和 `FunctionTemplate`:**  当我们定义 JavaScript 类或构造函数时，V8 内部会使用 `FunctionTemplate` 来表示这个构造函数，并使用 `ObjectTemplate` 来表示实例对象的结构。

  ```javascript
  // JavaScript 类定义
  class MyClass {
    constructor(value) {
      this.myValue = value;
    }

    getValue() {
      return this.myValue;
    }
  }

  // 在 V8 内部，会使用 FunctionTemplate 创建 MyClass 的构造函数
  // 并使用 ObjectTemplate 创建 MyClass 实例的结构
  ```

* **`ObjectTemplate::SetNativeDataProperty`:**  允许 C++ 代码向 JavaScript 对象添加由 C++ 代码实现的属性。

  ```cpp
  // 假设我们有一个 ObjectTemplate 实例 object_template
  // 和一个 C++ 函数 GetCurrentTime() 返回当前时间戳

  // 在 C++ 中设置一个名为 'currentTime' 的原生属性
  // object_template->SetNativeDataProperty(
  //     v8::String::NewFromUtf8(isolate, "currentTime").ToLocalChecked(),
  //     GetCurrentTime, // getter 函数
  //     nullptr         // 没有 setter
  // );
  ```

  ```javascript
  // 在 JavaScript 中访问原生属性
  let myObject = new MyClassObjectCreatedFromTemplate();
  console.log(myObject.currentTime); // 将会调用 C++ 的 GetCurrentTime()
  ```

**代码逻辑推理和假设输入/输出：**

**示例：`HandleScope`**

**假设输入:** 在一个 `Isolate` 中连续创建多个 V8 对象。

**代码逻辑:**  每次创建对象时，都需要在一个活动的 `HandleScope` 内进行。`HandleScope` 维护着一个栈，用于存储创建的 `Handle`。当 `HandleScope` 离开作用域时，它会释放其管理的所有 `Handle`。

**假设输入代码 (C++):**

```cpp
v8::Isolate* isolate = ...;
{
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::String> str1 = v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked();
  v8::Local<v8::String> str2 = v8::String::NewFromUtf8(isolate, "world").ToLocalChecked();
  // 在 handle_scope 结束时，str1 和 str2 指向的 V8 对象会被释放
}
// 此时，如果尝试使用 str1 或 str2，将会导致错误。
```

**输出:** 在 `HandleScope` 结束时，`str1` 和 `str2` 不再指向有效的 V8 对象。

**示例：`Context::Enter()` 和 `Context::Exit()`**

**假设输入:** 一个已经创建的 `v8::Context` 对象 `context`。

**代码逻辑:** `Context::Enter()` 会将指定的 `Context` 设置为当前线程的活动上下文。在此之后执行的所有 JavaScript 代码都会在这个上下文中运行。`Context::Exit()` 会恢复之前的上下文。

**假设输入代码 (C++):**

```cpp
v8::Isolate* isolate = ...;
v8::Local<v8::Context> context = v8::Context::New(isolate);

{
  v8::Context::Scope context_scope(context); // 相当于调用 context->Enter()
  v8::Local<v8::String> code = v8::String::NewFromUtf8(isolate, "console.log('Inside the context');").ToLocalChecked();
  v8::Local<v8::Script> script = v8::Script::Compile(context, code).ToLocalChecked();
  script->Run(context); // 在指定的上下文中运行脚本
  // context_scope 结束时，相当于调用 context->Exit()
}
```

**输出:**  控制台会输出 "Inside the context"。

**用户常见的编程错误：**

* **忘记使用 `HandleScope`:**  在创建 V8 对象时，如果没有活动的 `HandleScope`，V8 将无法跟踪这些对象，可能导致内存泄漏或程序崩溃。

  ```cpp
  v8::Isolate* isolate = ...;
  // 错误：没有使用 HandleScope
  v8::Local<v8::String> str = v8::String::NewFromUtf8(isolate, "error").ToLocalChecked();
  // 尝试使用 str 可能会导致问题
  ```

* **在错误的 `Context` 中执行代码:**  如果在没有调用 `Context::Enter()` 的情况下尝试在一个 `Context` 中运行脚本，或者在错误的 `Context` 中运行脚本，可能会导致变量未定义或其他运行时错误。

  ```cpp
  v8::Isolate* isolate = ...;
  v8::Local<v8::Context> context = v8::Context::New(isolate);
  v8::Local<v8::String> code = v8::String::NewFromUtf8(isolate, "console.log(globalVar);").ToLocalChecked();
  v8::Local<v8::Script> script = v8::Script::Compile(context, code).ToLocalChecked();
  // 错误：没有调用 context->Enter()，globalVar 可能未定义
  // script->Run(context);
  ```

* **模板生命周期管理不当:**  `Template` 对象通常在 `Isolate` 的生命周期内有效。如果过早地释放了 `Template` 对象，可能会导致后续使用它的代码崩溃。

**总结第 2 部分的功能:**

这部分 `v8/src/api/api.cc` 源代码定义了 V8 C++ API 中用于**核心内存管理 (使用 Handles)**、**管理 JavaScript 执行上下文 (Contexts)** 以及**创建 JavaScript 对象和函数的蓝图 (Templates, FunctionTemplates, ObjectTemplates)** 的关键类和方法。这些是嵌入 V8 引擎并与其交互的基础构建块，允许 C++ 代码创建和操作 JavaScript 对象、函数和执行环境。

### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
"Internal field out of bounds");
}

}  // namespace api_internal

// --- H a n d l e s ---

HandleScope::HandleScope(Isolate* v8_isolate) { Initialize(v8_isolate); }

void HandleScope::Initialize(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  // We do not want to check the correct usage of the Locker class all over the
  // place, so we do it only here: Without a HandleScope, an embedder can do
  // almost nothing, so it is enough to check in this central place.
  // We make an exception if the serializer is enabled, which means that the
  // Isolate is exclusively used to create a snapshot.
  Utils::ApiCheck(!i_isolate->was_locker_ever_used() ||
                      i_isolate->thread_manager()->IsLockedByCurrentThread() ||
                      i_isolate->serializer_enabled(),
                  "HandleScope::HandleScope",
                  "Entering the V8 API without proper locking in place");
  i::HandleScopeData* current = i_isolate->handle_scope_data();
  i_isolate_ = i_isolate;
  prev_next_ = current->next;
  prev_limit_ = current->limit;
  current->level++;
#ifdef V8_ENABLE_CHECKS
  scope_level_ = current->level;
#endif
}

HandleScope::~HandleScope() {
#ifdef V8_ENABLE_CHECKS
  CHECK_EQ(scope_level_, i_isolate_->handle_scope_data()->level);
#endif
  i::HandleScope::CloseScope(i_isolate_, prev_next_, prev_limit_);
}

void* HandleScope::operator new(size_t) { base::OS::Abort(); }
void* HandleScope::operator new[](size_t) { base::OS::Abort(); }
void HandleScope::operator delete(void*, size_t) { base::OS::Abort(); }
void HandleScope::operator delete[](void*, size_t) { base::OS::Abort(); }

int HandleScope::NumberOfHandles(Isolate* v8_isolate) {
  return i::HandleScope::NumberOfHandles(
      reinterpret_cast<i::Isolate*>(v8_isolate));
}

i::Address* HandleScope::CreateHandle(i::Isolate* i_isolate, i::Address value) {
  return i::HandleScope::CreateHandle(i_isolate, value);
}

#ifdef V8_ENABLE_DIRECT_HANDLE

i::Address* HandleScope::CreateHandleForCurrentIsolate(i::Address value) {
  i::Isolate* i_isolate = i::Isolate::Current();
  return i::HandleScope::CreateHandle(i_isolate, value);
}

#endif  // V8_ENABLE_DIRECT_HANDLE

EscapableHandleScopeBase::EscapableHandleScopeBase(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  escape_slot_ = CreateHandle(
      i_isolate, i::ReadOnlyRoots(i_isolate).the_hole_value().ptr());
  Initialize(v8_isolate);
}

i::Address* EscapableHandleScopeBase::EscapeSlot(i::Address* escape_value) {
  DCHECK_NOT_NULL(escape_value);
  DCHECK(i::IsTheHole(i::Tagged<i::Object>(*escape_slot_),
                      reinterpret_cast<i::Isolate*>(GetIsolate())));
  *escape_slot_ = *escape_value;
  return escape_slot_;
}

SealHandleScope::SealHandleScope(Isolate* v8_isolate)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)) {
  i::HandleScopeData* current = i_isolate_->handle_scope_data();
  prev_limit_ = current->limit;
  current->limit = current->next;
  prev_sealed_level_ = current->sealed_level;
  current->sealed_level = current->level;
}

SealHandleScope::~SealHandleScope() {
  i::HandleScopeData* current = i_isolate_->handle_scope_data();
  DCHECK_EQ(current->next, current->limit);
  current->limit = prev_limit_;
  DCHECK_EQ(current->level, current->sealed_level);
  current->sealed_level = prev_sealed_level_;
}

bool Data::IsModule() const {
  return i::IsModule(*Utils::OpenDirectHandle(this));
}
bool Data::IsFixedArray() const {
  return i::IsFixedArray(*Utils::OpenDirectHandle(this));
}

bool Data::IsValue() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::Object> self = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(self)) return true;
  i::Tagged<i::HeapObject> heap_object = i::Cast<i::HeapObject>(self);
  DCHECK(!IsTheHole(heap_object));
  if (i::IsSymbol(heap_object)) {
    return !i::Cast<i::Symbol>(heap_object)->is_private();
  }
  return IsPrimitiveHeapObject(heap_object) || IsJSReceiver(heap_object);
}

bool Data::IsPrivate() const {
  return i::IsPrivateSymbol(*Utils::OpenDirectHandle(this));
}

bool Data::IsObjectTemplate() const {
  return i::IsObjectTemplateInfo(*Utils::OpenDirectHandle(this));
}

bool Data::IsFunctionTemplate() const {
  return i::IsFunctionTemplateInfo(*Utils::OpenDirectHandle(this));
}

bool Data::IsContext() const {
  return i::IsContext(*Utils::OpenDirectHandle(this));
}

void Context::Enter() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::NativeContext> env = *Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  impl->EnterContext(env);
  impl->SaveContext(i_isolate->context());
  i_isolate->set_context(env);
}

void Context::Exit() {
  auto env = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  if (!Utils::ApiCheck(impl->LastEnteredContextWas(*env), "v8::Context::Exit()",
                       "Cannot exit non-entered context")) {
    return;
  }
  impl->LeaveContext();
  i_isolate->set_context(impl->RestoreContext());
}

Context::BackupIncumbentScope::BackupIncumbentScope(
    Local<Context> backup_incumbent_context)
    : backup_incumbent_context_(backup_incumbent_context) {
  DCHECK(!backup_incumbent_context_.IsEmpty());

  auto env = Utils::OpenDirectHandle(*backup_incumbent_context_);
  i::Isolate* i_isolate = env->GetIsolate();

  js_stack_comparable_address_ =
      i::SimulatorStack::RegisterJSStackComparableAddress(i_isolate);

  prev_ = i_isolate->top_backup_incumbent_scope();
  i_isolate->set_top_backup_incumbent_scope(this);
  // Enforce slow incumbent computation in order to make it find this
  // BackupIncumbentScope.
  i_isolate->clear_topmost_script_having_context();
}

Context::BackupIncumbentScope::~BackupIncumbentScope() {
  auto env = Utils::OpenDirectHandle(*backup_incumbent_context_);
  i::Isolate* i_isolate = env->GetIsolate();

  i::SimulatorStack::UnregisterJSStackComparableAddress(i_isolate);

  i_isolate->set_top_backup_incumbent_scope(prev_);
}

static_assert(i::Internals::kEmbedderDataSlotSize == i::kEmbedderDataSlotSize);
static_assert(i::Internals::kEmbedderDataSlotExternalPointerOffset ==
              i::EmbedderDataSlot::kExternalPointerOffset);

static i::Handle<i::EmbedderDataArray> EmbedderDataFor(Context* context,
                                                       int index, bool can_grow,
                                                       const char* location) {
  auto env = Utils::OpenDirectHandle(context);
  i::Isolate* i_isolate = env->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  bool ok = Utils::ApiCheck(i::IsNativeContext(*env), location,
                            "Not a native context") &&
            Utils::ApiCheck(index >= 0, location, "Negative index");
  if (!ok) return i::Handle<i::EmbedderDataArray>();
  // TODO(ishell): remove cast once embedder_data slot has a proper type.
  i::Handle<i::EmbedderDataArray> data(
      i::Cast<i::EmbedderDataArray>(env->embedder_data()), i_isolate);
  if (index < data->length()) return data;
  if (!Utils::ApiCheck(can_grow && index < i::EmbedderDataArray::kMaxLength,
                       location, "Index too large")) {
    return i::Handle<i::EmbedderDataArray>();
  }
  data = i::EmbedderDataArray::EnsureCapacity(i_isolate, data, index);
  env->set_embedder_data(*data);
  return data;
}

uint32_t Context::GetNumberOfEmbedderDataFields() {
  auto context = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(context->GetIsolate());
  Utils::ApiCheck(i::IsNativeContext(*context),
                  "Context::GetNumberOfEmbedderDataFields",
                  "Not a native context");
  // TODO(ishell): remove cast once embedder_data slot has a proper type.
  return static_cast<uint32_t>(
      i::Cast<i::EmbedderDataArray>(context->embedder_data())->length());
}

v8::Local<v8::Value> Context::SlowGetEmbedderData(int index) {
  const char* location = "v8::Context::GetEmbedderData()";
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, false, location);
  if (data.is_null()) return Local<Value>();
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  return Utils::ToLocal(i::direct_handle(
      i::EmbedderDataSlot(*data, index).load_tagged(), i_isolate));
}

void Context::SetEmbedderData(int index, v8::Local<Value> value) {
  const char* location = "v8::Context::SetEmbedderData()";
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, true, location);
  if (data.is_null()) return;
  auto val = Utils::OpenDirectHandle(*value);
  i::EmbedderDataSlot::store_tagged(*data, index, *val);
  DCHECK_EQ(*Utils::OpenDirectHandle(*value),
            *Utils::OpenDirectHandle(*GetEmbedderData(index)));
}

void* Context::SlowGetAlignedPointerFromEmbedderData(int index) {
  const char* location = "v8::Context::GetAlignedPointerFromEmbedderData()";
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  i::HandleScope handle_scope(i_isolate);
  i::Handle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, false, location);
  if (data.is_null()) return nullptr;
  void* result;
  Utils::ApiCheck(
      i::EmbedderDataSlot(*data, index).ToAlignedPointer(i_isolate, &result),
      location, "Pointer is not aligned");
  return result;
}

void Context::SetAlignedPointerInEmbedderData(int index, void* value) {
  const char* location = "v8::Context::SetAlignedPointerInEmbedderData()";
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  i::DirectHandle<i::EmbedderDataArray> data =
      EmbedderDataFor(this, index, true, location);
  bool ok = i::EmbedderDataSlot(*data, index)
                .store_aligned_pointer(i_isolate, *data, value);
  Utils::ApiCheck(ok, location, "Pointer is not aligned");
  DCHECK_EQ(value, GetAlignedPointerFromEmbedderData(index));
}

// --- T e m p l a t e ---

void Template::Set(v8::Local<Name> name, v8::Local<Data> value,
                   v8::PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  i::Isolate* i_isolate = templ->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto value_obj = Utils::OpenHandle(*value);

  Utils::ApiCheck(!IsJSReceiver(*value_obj) || IsTemplateInfo(*value_obj),
                  "v8::Template::Set",
                  "Invalid value, must be a primitive or a Template");

  // The template cache only performs shallow clones, if we set an
  // ObjectTemplate as a property value then we can not cache the receiver
  // template.
  if (i::IsObjectTemplateInfo(*value_obj)) {
    templ->set_serial_number(i::TemplateInfo::kDoNotCache);
  }

  i::ApiNatives::AddDataProperty(i_isolate, templ, Utils::OpenHandle(*name),
                                 value_obj,
                                 static_cast<i::PropertyAttributes>(attribute));
}

void Template::SetPrivate(v8::Local<Private> name, v8::Local<Data> value,
                          v8::PropertyAttribute attribute) {
  Set(Local<Name>::Cast(name), value, attribute);
}

void Template::SetAccessorProperty(v8::Local<v8::Name> name,
                                   v8::Local<FunctionTemplate> getter,
                                   v8::Local<FunctionTemplate> setter,
                                   v8::PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  auto i_isolate = templ->GetIsolateChecked();
  i::Handle<i::FunctionTemplateInfo> i_getter;
  if (!getter.IsEmpty()) {
    i_getter = Utils::OpenHandle(*getter);
    Utils::ApiCheck(i_getter->has_callback(i_isolate),
                    "v8::Template::SetAccessorProperty",
                    "Getter must have a call handler");
  }
  i::Handle<i::FunctionTemplateInfo> i_setter;
  if (!setter.IsEmpty()) {
    i_setter = Utils::OpenHandle(*setter);
    Utils::ApiCheck(i_setter->has_callback(i_isolate),
                    "v8::Template::SetAccessorProperty",
                    "Setter must have a call handler");
  }
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(!name.IsEmpty());
  DCHECK(!getter.IsEmpty() || !setter.IsEmpty());
  i::HandleScope scope(i_isolate);
  i::ApiNatives::AddAccessorProperty(
      i_isolate, templ, Utils::OpenHandle(*name), i_getter, i_setter,
      static_cast<i::PropertyAttributes>(attribute));
}

// --- F u n c t i o n   T e m p l a t e ---

Local<ObjectTemplate> FunctionTemplate::PrototypeTemplate() {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::HeapObject> heap_obj(self->GetPrototypeTemplate(),
                                          i_isolate);
  if (i::IsUndefined(*heap_obj, i_isolate)) {
    // Do not cache prototype objects.
    constexpr bool do_not_cache = true;
    i::Handle<i::ObjectTemplateInfo> proto_template =
        i_isolate->factory()->NewObjectTemplateInfo(
            i::Handle<i::FunctionTemplateInfo>(), do_not_cache);
    i::FunctionTemplateInfo::SetPrototypeTemplate(i_isolate, self,
                                                  proto_template);
    return Utils::ToLocal(proto_template);
  }
  return ToApiHandle<ObjectTemplate>(heap_obj);
}

void FunctionTemplate::SetPrototypeProviderTemplate(
    Local<FunctionTemplate> prototype_provider) {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> result =
      Utils::OpenDirectHandle(*prototype_provider);
  Utils::ApiCheck(i::IsUndefined(self->GetPrototypeTemplate(), i_isolate),
                  "v8::FunctionTemplate::SetPrototypeProviderTemplate",
                  "Protoype must be undefined");
  Utils::ApiCheck(i::IsUndefined(self->GetParentTemplate(), i_isolate),
                  "v8::FunctionTemplate::SetPrototypeProviderTemplate",
                  "Prototype provider must be empty");
  i::FunctionTemplateInfo::SetPrototypeProviderTemplate(i_isolate, self,
                                                        result);
}

namespace {
static void EnsureNotPublished(i::DirectHandle<i::FunctionTemplateInfo> info,
                               const char* func) {
  DCHECK_IMPLIES(info->instantiated(), info->published());
  Utils::ApiCheck(!info->published(), func,
                  "FunctionTemplate already instantiated");
}

i::Handle<i::FunctionTemplateInfo> FunctionTemplateNew(
    i::Isolate* i_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    bool do_not_cache,
    v8::Local<Private> cached_property_name = v8::Local<Private>(),
    SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
    const MemorySpan<const CFunction>& c_function_overloads = {}) {
  i::Handle<i::FunctionTemplateInfo> obj =
      i_isolate->factory()->NewFunctionTemplateInfo(length, do_not_cache);
  {
    // Disallow GC until all fields of obj have acceptable types.
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::FunctionTemplateInfo> raw = *obj;
    if (!signature.IsEmpty()) {
      raw->set_signature(*Utils::OpenDirectHandle(*signature));
    }
    if (!cached_property_name.IsEmpty()) {
      raw->set_cached_property_name(
          *Utils::OpenDirectHandle(*cached_property_name));
    }
    if (behavior == ConstructorBehavior::kThrow) {
      raw->set_remove_prototype(true);
    }
  }
  if (callback != nullptr) {
    Utils::ToLocal(obj)->SetCallHandler(callback, data, side_effect_type,
                                        c_function_overloads);
  }
  return obj;
}
}  // namespace

void FunctionTemplate::Inherit(v8::Local<FunctionTemplate> value) {
  auto info = Utils::OpenHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::Inherit");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(
      i::IsUndefined(info->GetPrototypeProviderTemplate(), i_isolate),
      "v8::FunctionTemplate::Inherit", "Protoype provider must be empty");
  i::FunctionTemplateInfo::SetParentTemplate(i_isolate, info,
                                             Utils::OpenHandle(*value));
}

Local<FunctionTemplate> FunctionTemplate::New(
    Isolate* v8_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    SideEffectType side_effect_type, const CFunction* c_function,
    uint16_t instance_type, uint16_t allowed_receiver_instance_type_range_start,
    uint16_t allowed_receiver_instance_type_range_end) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  // Changes to the environment cannot be captured in the snapshot. Expect no
  // function templates when the isolate is created for serialization.
  API_RCS_SCOPE(i_isolate, FunctionTemplate, New);

  if (!Utils::ApiCheck(
          !c_function || behavior == ConstructorBehavior::kThrow,
          "FunctionTemplate::New",
          "Fast API calls are not supported for constructor functions")) {
    return Local<FunctionTemplate>();
  }

  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, behavior, false,
      Local<Private>(), side_effect_type,
      c_function ? MemorySpan<const CFunction>{c_function, 1}
                 : MemorySpan<const CFunction>{});

  if (instance_type) {
    if (!Utils::ApiCheck(
            base::IsInRange(static_cast<int>(instance_type),
                            i::Internals::kFirstEmbedderJSApiObjectType,
                            i::Internals::kLastEmbedderJSApiObjectType),
            "FunctionTemplate::New",
            "instance_type is outside the range of valid JSApiObject types")) {
      return Local<FunctionTemplate>();
    }
    templ->SetInstanceType(instance_type);
  }

  if (allowed_receiver_instance_type_range_start ||
      allowed_receiver_instance_type_range_end) {
    if (!Utils::ApiCheck(i::Internals::kFirstEmbedderJSApiObjectType <=
                                 allowed_receiver_instance_type_range_start &&
                             allowed_receiver_instance_type_range_start <=
                                 allowed_receiver_instance_type_range_end &&
                             allowed_receiver_instance_type_range_end <=
                                 i::Internals::kLastEmbedderJSApiObjectType,
                         "FunctionTemplate::New",
                         "allowed receiver instance type range is outside the "
                         "range of valid JSApiObject types")) {
      return Local<FunctionTemplate>();
    }
    templ->SetAllowedReceiverInstanceTypeRange(
        allowed_receiver_instance_type_range_start,
        allowed_receiver_instance_type_range_end);
  }
  return Utils::ToLocal(templ);
}

Local<FunctionTemplate> FunctionTemplate::NewWithCFunctionOverloads(
    Isolate* v8_isolate, FunctionCallback callback, v8::Local<Value> data,
    v8::Local<Signature> signature, int length, ConstructorBehavior behavior,
    SideEffectType side_effect_type,
    const MemorySpan<const CFunction>& c_function_overloads) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, FunctionTemplate, New);

  // Check that all overloads of the fast API callback have different numbers of
  // parameters. Since the number of overloads is supposed to be small, just
  // comparing them with each other should be fine.
  for (size_t i = 0; i < c_function_overloads.size(); ++i) {
    for (size_t j = i + 1; j < c_function_overloads.size(); ++j) {
      CHECK_NE(c_function_overloads.data()[i].ArgumentCount(),
               c_function_overloads.data()[j].ArgumentCount());
    }
  }

  if (!Utils::ApiCheck(
          c_function_overloads.empty() ||
              behavior == ConstructorBehavior::kThrow,
          "FunctionTemplate::NewWithCFunctionOverloads",
          "Fast API calls are not supported for constructor functions")) {
    return Local<FunctionTemplate>();
  }

  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, behavior, false,
      Local<Private>(), side_effect_type, c_function_overloads);
  return Utils::ToLocal(templ);
}

Local<FunctionTemplate> FunctionTemplate::NewWithCache(
    Isolate* v8_isolate, FunctionCallback callback,
    Local<Private> cache_property, Local<Value> data,
    Local<Signature> signature, int length, SideEffectType side_effect_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, FunctionTemplate, NewWithCache);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::FunctionTemplateInfo> templ = FunctionTemplateNew(
      i_isolate, callback, data, signature, length, ConstructorBehavior::kAllow,
      false, cache_property, side_effect_type);
  return Utils::ToLocal(templ);
}

Local<Signature> Signature::New(Isolate* v8_isolate,
                                Local<FunctionTemplate> receiver) {
  return Local<Signature>::Cast(receiver);
}

#define SET_FIELD_WRAPPED(i_isolate, obj, setter, cdata, tag) \
  do {                                                        \
    i::DirectHandle<i::UnionOf<i::Smi, i::Foreign>> foreign = \
        FromCData<tag>(i_isolate, cdata);                     \
    (obj)->setter(*foreign);                                  \
  } while (false)

void FunctionTemplate::SetCallHandler(
    FunctionCallback callback, v8::Local<Value> data,
    SideEffectType side_effect_type,
    const MemorySpan<const CFunction>& c_function_overloads) {
  auto info = Utils::OpenHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetCallHandler");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  info->set_has_side_effects(side_effect_type !=
                             SideEffectType::kHasNoSideEffect);
  info->set_callback(i_isolate, reinterpret_cast<i::Address>(callback));
  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  // "Release" callback and callback data fields.
  info->set_callback_data(*Utils::OpenDirectHandle(*data), kReleaseStore);

  if (!c_function_overloads.empty()) {
    // Stores the data for a sequence of CFunction overloads into a single
    // FixedArray, as [address_0, signature_0, ... address_n-1, signature_n-1].
    i::DirectHandle<i::FixedArray> function_overloads =
        i_isolate->factory()->NewFixedArray(static_cast<int>(
            c_function_overloads.size() *
            i::FunctionTemplateInfo::kFunctionOverloadEntrySize));
    int function_count = static_cast<int>(c_function_overloads.size());
    for (int i = 0; i < function_count; i++) {
      const CFunction& c_function = c_function_overloads.data()[i];
      i::DirectHandle<i::Object> address = FromCData<internal::kCFunctionTag>(
          i_isolate, c_function.GetAddress());
      function_overloads->set(
          i::FunctionTemplateInfo::kFunctionOverloadEntrySize * i, *address);
      i::DirectHandle<i::Object> signature =
          FromCData<internal::kCFunctionInfoTag>(i_isolate,
                                                 c_function.GetTypeInfo());
      function_overloads->set(
          i::FunctionTemplateInfo::kFunctionOverloadEntrySize * i + 1,
          *signature);
    }
    i::FunctionTemplateInfo::SetCFunctionOverloads(i_isolate, info,
                                                   function_overloads);
  }
}

namespace {

template <typename Getter, typename Setter>
i::Handle<i::AccessorInfo> MakeAccessorInfo(i::Isolate* i_isolate,
                                            v8::Local<Name> name, Getter getter,
                                            Setter setter,
                                            v8::Local<Value> data,
                                            bool replace_on_access) {
  i::Handle<i::AccessorInfo> obj = i_isolate->factory()->NewAccessorInfo();
  obj->set_getter(i_isolate, reinterpret_cast<i::Address>(getter));
  DCHECK_IMPLIES(replace_on_access, setter == nullptr);
  if (setter == nullptr) {
    setter = reinterpret_cast<Setter>(&i::Accessors::ReconfigureToDataProperty);
  }
  obj->set_setter(i_isolate, reinterpret_cast<i::Address>(setter));

  auto accessor_name = Utils::OpenHandle(*name);
  if (!IsUniqueName(*accessor_name)) {
    accessor_name = i_isolate->factory()->InternalizeString(
        i::Cast<i::String>(accessor_name));
  }
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::AccessorInfo> raw_obj = *obj;
  if (data.IsEmpty()) {
    raw_obj->set_data(i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    raw_obj->set_data(*Utils::OpenDirectHandle(*data));
  }
  raw_obj->set_name(*accessor_name);
  raw_obj->set_replace_on_access(replace_on_access);
  raw_obj->set_initial_property_attributes(i::NONE);
  return obj;
}

}  // namespace

Local<ObjectTemplate> FunctionTemplate::InstanceTemplate() {
  auto constructor = Utils::OpenHandle(this, true);
  if (!Utils::ApiCheck(!constructor.is_null(),
                       "v8::FunctionTemplate::InstanceTemplate()",
                       "Reading from empty handle")) {
    return Local<ObjectTemplate>();
  }
  i::Isolate* i_isolate = constructor->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto maybe_templ = constructor->GetInstanceTemplate();
  if (!i::IsUndefined(maybe_templ, i_isolate)) {
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::ObjectTemplateInfo>(maybe_templ), i_isolate));
  }
  constexpr bool do_not_cache = false;
  i::Handle<i::ObjectTemplateInfo> templ =
      i_isolate->factory()->NewObjectTemplateInfo(constructor, do_not_cache);
  i::FunctionTemplateInfo::SetInstanceTemplate(i_isolate, constructor, templ);
  return Utils::ToLocal(templ);
}

void FunctionTemplate::SetLength(int length) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetLength");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_length(length);
}

void FunctionTemplate::SetClassName(Local<String> name) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetClassName");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_class_name(*Utils::OpenDirectHandle(*name));
}

void FunctionTemplate::SetInterfaceName(Local<String> name) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetInterfaceName");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_interface_name(*Utils::OpenDirectHandle(*name));
}

void FunctionTemplate::SetExceptionContext(ExceptionContext context) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetExceptionContext");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_exception_context(static_cast<uint32_t>(context));
}

void FunctionTemplate::SetAcceptAnyReceiver(bool value) {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::SetAcceptAnyReceiver");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_accept_any_receiver(value);
}

void FunctionTemplate::ReadOnlyPrototype() {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::ReadOnlyPrototype");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_read_only_prototype(true);
}

void FunctionTemplate::RemovePrototype() {
  auto info = Utils::OpenDirectHandle(this);
  EnsureNotPublished(info, "v8::FunctionTemplate::RemovePrototype");
  i::Isolate* i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  info->set_remove_prototype(true);
}

// --- O b j e c t T e m p l a t e ---

Local<ObjectTemplate> ObjectTemplate::New(
    Isolate* v8_isolate, v8::Local<FunctionTemplate> constructor) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ObjectTemplate, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  constexpr bool do_not_cache = false;
  i::Handle<i::ObjectTemplateInfo> obj =
      i_isolate->factory()->NewObjectTemplateInfo(
          Utils::OpenDirectHandle(*constructor, true), do_not_cache);
  return Utils::ToLocal(obj);
}

namespace {
// Ensure that the object template has a constructor.  If no
// constructor is available we create one.
i::Handle<i::FunctionTemplateInfo> EnsureConstructor(
    i::Isolate* i_isolate, ObjectTemplate* object_template) {
  i::Tagged<i::Object> obj =
      Utils::OpenDirectHandle(object_template)->constructor();
  if (!IsUndefined(obj, i_isolate)) {
    i::Tagged<i::FunctionTemplateInfo> info =
        i::Cast<i::FunctionTemplateInfo>(obj);
    return i::Handle<i::FunctionTemplateInfo>(info, i_isolate);
  }
  Local<FunctionTemplate> templ =
      FunctionTemplate::New(reinterpret_cast<Isolate*>(i_isolate));
  auto constructor = Utils::OpenHandle(*templ);
  i::FunctionTemplateInfo::SetInstanceTemplate(
      i_isolate, constructor, Utils::OpenHandle(object_template));
  Utils::OpenDirectHandle(object_template)->set_constructor(*constructor);
  return constructor;
}

template <typename Getter, typename Setter, typename Data, typename Template>
void TemplateSetAccessor(Template* template_obj, v8::Local<Name> name,
                         Getter getter, Setter setter, Data data,
                         PropertyAttribute attribute, bool replace_on_access,
                         SideEffectType getter_side_effect_type,
                         SideEffectType setter_side_effect_type) {
  auto info = Utils::OpenHandle(template_obj);
  auto i_isolate = info->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::AccessorInfo> accessor_info = MakeAccessorInfo(
      i_isolate, name, getter, setter, data, replace_on_access);
  {
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::AccessorInfo> raw = *accessor_info;
    raw->set_initial_property_attributes(
        static_cast<i::PropertyAttributes>(attribute));
    raw->set_getter_side_effect_type(getter_side_effect_type);
    raw->set_setter_side_effect_type(setter_side_effect_type);
  }
  i::ApiNatives::AddNativeDataProperty(i_isolate, info, accessor_info);
}
}  // namespace

void Template::SetNativeDataProperty(v8::Local<Name> name,
                                     AccessorNameGetterCallback getter,
                                     AccessorNameSetterCallback setter,
                                     v8::Local<Value> data,
                                     PropertyAttribute attribute,
                                     SideEffectType getter_side_effect_type,
                                     SideEffectType setter_side_effect_type) {
  TemplateSetAccessor(this, name, getter, setter, data, attribute, false,
                      getter_side_effect_type, setter_side_effect_type);
}

void Template::SetLazyDataProperty(v8::Local<Name> name,
                                   AccessorNameGetterCallback getter,
                                   v8::Local<Value> data,
                                   PropertyAttribute attribute,
                                   SideEffectType getter_side_effect_type,
                                   SideEffectType setter_side_effect_type) {
  TemplateSetAccessor(
      this, name, getter, static_cast<AccessorNameSetterCallback>(nullptr),
      data, attribute, true, getter_side_effect_type, setter_side_effect_type);
}

void Template::SetIntrinsicDataProperty(Local<Name> name, Intrinsic intrinsic,
                                        PropertyAttribute attribute) {
  auto templ = Utils::OpenHandle(this);
  i::Isolate* i_isolate = templ->GetIsolateChecked();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::ApiNatives::AddDataProperty(i_isolate, templ, Utils::OpenH
```