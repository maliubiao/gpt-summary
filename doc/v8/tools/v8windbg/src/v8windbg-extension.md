Response:
Let's break down the thought process for analyzing this V8 Windbg extension code.

**1. Initial Understanding of the Context:**

The first clue is the file path: `v8/tools/v8windbg/src/v8windbg-extension.cc`. This immediately tells us it's related to debugging V8 using WinDbg. The `.cc` extension confirms it's C++ code. The name "extension" suggests it adds functionality to the base WinDbg debugger.

**2. Core Functionality Identification (High-Level):**

I start by scanning the code for keywords and recognizable patterns related to debugger extensions.

* **`CreateExtension()` and `DestroyExtension()`:** These are standard entry and exit points for debugger extensions. They likely handle initialization and cleanup.
* **`Extension::current_extension_`:** A singleton pattern for the extension object.
* **`pcur_isolate`, `pjs_stack`, `pv8_object`:**  These look like command names or aliases that the extension will register. Their prefixes (`p`) might indicate pointers to strings.
* **Includes:**  The included headers (`cur-isolate.h`, `js-stack.h`, `local-variables.h`, `object-inspection.h`) strongly suggest the core functionalities: inspecting the current V8 isolate, the JavaScript stack, local variables, and V8 objects.
* **`IDebugHost...` types:**  These are COM interfaces from the Windows Debugging Host (DbgHost) API, confirming this is a proper WinDbg extension.
* **Data Model related code (`sp_data_model_manager`, `CreateDataModelObject`, `SetConcept`, `RegisterModelForTypeSignature`):** This points to the extension leveraging WinDbg's data model to provide richer views of V8 data structures.

**3. Deeper Dive into Specific Features:**

Now, I examine the functions and their implementations.

* **`CreateExtension()`/`DestroyExtension()`:** Basic setup and teardown, ensuring only one instance.
* **`GetV8TaggedObjectType()` and `GetTypeFromV8Module()`:**  These functions are about resolving V8 types within the debugger. The caching mechanism in `GetTypeFromV8Module` is an optimization. The search for types in `v8::internal::`, `v8::`, and the unqualified name highlights the complexities of C++ namespace lookup within the debugger.
* **`IsV8Module()`:**  A simple check to identify if a loaded module contains V8 symbols based on the presence of a specific symbol. This is a common way to identify the target process's V8 instance.
* **`GetV8Module()`:**  This function is responsible for locating the V8 module in the debuggee process. It tries known module names first for efficiency and then iterates through all modules as a fallback. The comment about comparing contexts and the workaround using `proc_id` is a crucial detail, indicating a potential limitation or ongoing API development in WinDbg.
* **`Extension::Initialize()`:** This is where the bulk of the extension setup happens. I look for patterns related to the identified core functionalities:
    * **Data Model for `Tagged<T>`:** Creating a data model (`V8ObjectDataModel`) to provide custom views for `v8::internal::Tagged<*>`. This is essential for inspecting V8 objects. The `IStringDisplayableConcept` and `IDynamicKeyProviderConcept` concepts indicate the data model will allow custom string representations and dynamic property access.
    * **Data Model for indexed fields:** Setting up a data model (`IndexedFieldParent`) for collections or array-like structures. The `IIndexableConcept` and `IIterableConcept` indicate the data model supports indexing and iteration.
    * **Data Model for `v8::Local<*>`:** Similar to `Tagged<T>`, this sets up a data model (`V8LocalDataModel`) for smart pointers like `v8::Local` and `v8::Handle`.
    * **Registering type signatures:**  The code registers the created data models for specific C++ type patterns (`v8::internal::Tagged<*>`, `v8::Local<*>`, etc.). This tells WinDbg how to use the custom data models when these types are encountered.
    * **Adding the `Value` property to `v8::Local`:**  This makes it easy to access the underlying V8 object pointed to by a `v8::Local`.
    * **Registering function aliases:** The `CreateMethod` and `CreateFunctionAlias` calls register the commands (`curisolate`, `jsstack`, `v8object`) that users can type in the WinDbg console.
    * **Overriding "LocalVariables" and "Parameters":** This is a key feature, allowing the extension to provide more V8-specific information about local variables and function parameters in stack frames.
    * **Adding `node_id` and `bitset_name` properties:**  These add specific, helpful properties for debugging compiler-related structures.
* **`OverrideLocalsGetter()`:**  This function intercepts the default WinDbg mechanism for getting local variables and provides a custom implementation (`V8LocalVariables`).
* **Templates (`RegisterAndAddPropertyForClass`):** A helper function to simplify adding properties to data models for specific classes.

**4. Answering the Specific Questions:**

With a good understanding of the code, I can now address the prompt's questions:

* **Functionality:** List the identified core features.
* **Torque Source:** Check the file extension. It's `.cc`, so it's C++, not Torque.
* **JavaScript Relation and Example:** Identify features related to JavaScript (stack, variables, objects) and provide a simple JavaScript code snippet to illustrate how the debugger extension could be used.
* **Code Logic Inference (Hypothetical Input/Output):** Focus on a specific function, like `GetV8Module`. Imagine the debugger attaching to a process and list potential module names and whether the function would find the V8 module.
* **Common Programming Errors:**  Think about potential issues when debugging JavaScript or V8 and how this extension might help, relating it back to common mistakes (e.g., accessing undefined variables).

**5. Refinement and Organization:**

Finally, I organize the analysis into a clear and readable format, using headings, bullet points, and code examples where appropriate. I ensure the language is precise and avoids jargon where possible. I also double-check that all parts of the original prompt have been addressed.
好的，让我们来分析一下 `v8/tools/v8windbg/src/v8windbg-extension.cc` 这个 V8 源代码文件。

**功能列举:**

这个 C++ 文件实现了一个 WinDbg 扩展，旨在增强在 WinDbg 中调试 V8 JavaScript 引擎的能力。其主要功能包括：

1. **V8 Isolate 相关功能 (`curisolate` 命令):**
   - 提供一个名为 `curisolate` 的 WinDbg 命令别名，允许用户方便地获取和查看当前 V8 Isolate 的信息。这涉及到 `CurrIsolateAlias` 类。

2. **JavaScript 堆栈跟踪 (`jsstack` 命令):**
   - 提供一个名为 `jsstack` 的 WinDbg 命令别名，用于打印当前 JavaScript 的调用堆栈。这涉及到 `JSStackAlias` 类。

3. **V8 对象检查 (`v8object` 命令):**
   - 提供一个名为 `v8object` 的 WinDbg 命令别名，允许用户检查 V8 堆中的对象。这涉及到 `InspectV8ObjectMethod` 类。

4. **改进 `Tagged<T>` 类型的显示:**
   - 通过创建和注册数据模型 (`V8ObjectDataModel`)，为 `v8::internal::Tagged<*>` 类型的变量提供更友好的调试视图，包括字符串显示和动态属性访问。

5. **改进 `v8::Local<*>` 等类型的显示:**
   - 创建和注册数据模型 (`V8LocalDataModel`)，为 `v8::Local<*>`, `v8::MaybeLocal<*>`, `v8::internal::Handle<*>`, `v8::internal::MaybeHandle<*>` 等表示 V8 对象的智能指针类型提供更好的调试体验。
   - 为这些类型添加了一个名为 "Value" 的属性，可以直接访问到它们所指向的 V8 对象。

6. **自定义局部变量和参数的显示:**
   - 通过重写 WinDbg 默认的 "LocalVariables" 和 "Parameters" 获取器，使用 `V8LocalVariables` 类提供更贴合 V8 的局部变量和函数参数信息。

7. **查找和识别 V8 模块:**
   - 提供了 `GetV8Module` 函数，用于在调试目标进程中查找 V8 模块。它会尝试一些常见的 V8 模块名称，并会检查模块中是否存在特定的 V8 符号来确认。

8. **为特定 V8 类型添加自定义属性:**
   - 为 `v8::internal::compiler::Node` 类型添加了 `node_id` 属性。
   - 为 `v8::internal::compiler::Type` 类型添加了 `bitset_name` 属性。

**关于 .tq 结尾:**

如果 `v8/tools/v8windbg/src/v8windbg-extension.cc` 的文件名以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种用于生成 V8 内部代码（如内置函数）的领域特定语言。然而，根据提供的文件名，它以 `.cc` 结尾，所以这是一个 C++ 文件。

**与 JavaScript 功能的关系和 JavaScript 示例:**

这个扩展直接服务于调试运行 JavaScript 代码的 V8 引擎。它提供的功能都旨在帮助开发者在调试器中理解 JavaScript 代码的执行状态和 V8 内部结构。

例如，假设我们有以下 JavaScript 代码：

```javascript
function add(a, b) {
  const sum = a + b;
  debugger; // 在这里设置断点
  return sum;
}

const result = add(5, 3);
console.log(result);
```

当我们在 WinDbg 中调试这个程序，并在 `debugger;` 语句处中断时，这个扩展提供的功能就能发挥作用：

- **`!curisolate`:**  可以查看当前正在执行 JavaScript 代码的 V8 Isolate 的信息，例如堆的状态、上下文等。
- **`!jsstack`:**  可以查看当前 JavaScript 的调用堆栈，看到 `add` 函数在被调用的位置。
- **`dv` (WinDbg 命令) 并结合扩展:** 可以查看局部变量 `a`, `b`, `sum` 的值。由于扩展的存在，这些变量如果是 V8 对象（例如字符串、对象），可能会以更友好的方式显示。
- **`!v8object sum`:**  如果 `sum` 是一个 V8 对象，可以使用这个命令来检查其内部结构，例如属性、类型等。

**代码逻辑推理 (假设输入与输出):**

让我们关注 `GetV8Module` 函数，它负责查找 V8 模块。

**假设输入:**

1. WinDbg 附加到一个正在运行 Node.js 应用程序的进程。
2. 该进程加载了名为 `v8.dll` 的 V8 引擎。

**代码逻辑推理:**

- `GetV8Module` 首先会尝试从缓存中获取 V8 模块，如果存在且上下文相同则直接返回。
- 如果缓存中没有，或者上下文不同，它会尝试使用预定义的模块名称列表 (`known_names`) 来查找模块。
- 列表包含 `L"v8"`, `L"node"` 等常见名称。
- `sp_debug_host_symbols->FindModuleByName(sp_ctx.Get(), name, &sp_module)` 会尝试根据名称查找模块。
- 如果找到了名为 `node.dll` 的模块，`IsV8Module(sp_module.Get())` 会被调用。
- `IsV8Module` 会尝试在模块中查找符号 `v8::internal::Isolate::PushStackTraceAndDie`。
- 如果在 `node.dll` 中找到了这个符号（这取决于 Node.js 的构建方式，它可能将 V8 符号包含在自身中），`IsV8Module` 返回 `true`。
- `GetV8Module` 将 `node.dll` 存储为 V8 模块，并返回该模块的接口。

**假设输出:**

`GetV8Module` 函数成功找到 V8 模块，并返回指向 `node.dll` (或 `v8.dll`，取决于实际情况) 对应的 `IDebugHostModule` 接口的指针。

**涉及用户常见的编程错误 (举例说明):**

这个扩展本身是为了帮助调试，所以它不直接涉及用户编写 JavaScript 代码的错误。但是，它可以帮助开发者诊断由以下常见编程错误导致的问题：

1. **访问 `undefined` 或 `null` 属性:**

   ```javascript
   const obj = { name: 'Alice' };
   console.log(obj.age.toFixed(2)); // 错误：obj.age 是 undefined
   ```

   在 WinDbg 中，当程序因为这个错误抛出异常时，可以使用 `!jsstack` 查看调用堆栈，定位到出错的代码行。使用 `!v8object obj` 可以检查 `obj` 的属性，确认 `age` 确实不存在。

2. **类型错误:**

   ```javascript
   function greet(name) {
     return "Hello, " + name.toUpperCase(); // 如果 name 不是字符串会出错
   }
   greet(123);
   ```

   当执行到 `toUpperCase()` 时，如果 `name` 不是字符串，会抛出类型错误。WinDbg 中，可以使用 `dv name` 查看 `name` 的值和类型。结合扩展，如果 `name` 是一个 V8 对象，可以更详细地检查其类型信息。

3. **作用域问题和闭包:**

   ```javascript
   function createCounter() {
     let count = 0;
     return function() {
       count++;
       return count;
     };
   }

   const counter = createCounter();
   counter();
   counter();
   debugger; // 在这里查看 count 的值
   ```

   在 `debugger` 处，可以使用 WinDbg 的局部变量查看功能 (配合扩展提供的自定义显示) 来观察闭包中 `count` 的值，帮助理解作用域和闭包的行为。

4. **性能问题和内存泄漏 (间接相关):**

   虽然扩展不直接检测内存泄漏，但通过 `!curisolate` 查看堆的统计信息，或者使用 `!v8object` 检查大量对象的属性，可以帮助开发者分析内存使用情况，从而间接发现潜在的内存泄漏问题。

总而言之，`v8/tools/v8windbg/src/v8windbg-extension.cc` 是一个非常有用的工具，它通过增强 WinDbg 的功能，使得开发者能够更深入地了解 V8 引擎的内部状态和 JavaScript 代码的执行情况，从而更有效地进行调试和问题排查。

### 提示词
```
这是目录为v8/tools/v8windbg/src/v8windbg-extension.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/v8windbg/src/v8windbg-extension.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/v8windbg/src/v8windbg-extension.h"

#include <iostream>

#include "tools/v8windbg/base/utilities.h"
#include "tools/v8windbg/src/cur-isolate.h"
#include "tools/v8windbg/src/js-stack.h"
#include "tools/v8windbg/src/local-variables.h"
#include "tools/v8windbg/src/object-inspection.h"

std::unique_ptr<Extension> Extension::current_extension_ = nullptr;
const wchar_t* pcur_isolate = L"curisolate";
const wchar_t* pjs_stack = L"jsstack";
const wchar_t* pv8_object = L"v8object";

HRESULT CreateExtension() {
  if (Extension::Current() != nullptr || sp_data_model_manager == nullptr ||
      sp_debug_host == nullptr) {
    return E_FAIL;
  } else {
    std::unique_ptr<Extension> new_extension(new (std::nothrow) Extension());
    if (new_extension == nullptr) return E_FAIL;
    RETURN_IF_FAIL(new_extension->Initialize());
    Extension::SetExtension(std::move(new_extension));
    return S_OK;
  }
}

void DestroyExtension() { Extension::SetExtension(nullptr); }

WRL::ComPtr<IDebugHostType> Extension::GetV8TaggedObjectType(
    WRL::ComPtr<IDebugHostContext>& sp_ctx) {
  return GetTypeFromV8Module(sp_ctx, kTaggedObjectU);
}

WRL::ComPtr<IDebugHostType> Extension::GetTypeFromV8Module(
    WRL::ComPtr<IDebugHostContext>& sp_ctx, const char16_t* type_name) {
  bool is_equal;
  if (sp_v8_module_ctx_ == nullptr ||
      !SUCCEEDED(sp_v8_module_ctx_->IsEqualTo(sp_ctx.Get(), &is_equal)) ||
      !is_equal) {
    // Context changed; clear the dictionary.
    cached_v8_module_types_.clear();
  }

  GetV8Module(sp_ctx);  // Will force the correct module to load
  if (sp_v8_module_ == nullptr) return nullptr;

  auto& dictionary_entry = cached_v8_module_types_[type_name];
  if (dictionary_entry == nullptr) {
    const std::wstring type_name_w(reinterpret_cast<const wchar_t*>(type_name));
    // The contract from debug_helper functions is to provide type names that
    // would be valid if used in C++ code within the v8::internal namespace.
    // They might be fully qualified but aren't required to be. Thus, we must
    // simluate an "unqualified name lookup" here, by searching for the type
    // starting in the innermost namespace and working outward.
    if (SUCCEEDED(sp_v8_module_->FindTypeByName(
            (L"v8::internal::" + type_name_w).c_str(), &dictionary_entry))) {
      return dictionary_entry;
    }
    if (SUCCEEDED(sp_v8_module_->FindTypeByName((L"v8::" + type_name_w).c_str(),
                                                &dictionary_entry))) {
      return dictionary_entry;
    }
    sp_v8_module_->FindTypeByName(reinterpret_cast<PCWSTR>(type_name),
                                  &dictionary_entry);
  }
  return dictionary_entry;
}

namespace {

// Returns whether the given module appears to have symbols for V8 code.
bool IsV8Module(IDebugHostModule* module) {
  WRL::ComPtr<IDebugHostSymbol> sp_isolate_sym;
  // The below symbol is specific to the main V8 module and is specified with
  // V8_NOINLINE, so it should always be present.
  if (FAILED(module->FindSymbolByName(
          L"v8::internal::Isolate::PushStackTraceAndDie", &sp_isolate_sym))) {
    return false;
  }
  return true;
}

}  // namespace

WRL::ComPtr<IDebugHostModule> Extension::GetV8Module(
    WRL::ComPtr<IDebugHostContext>& sp_ctx) {
  // Return the cached version if it exists and the context is the same

  // Note: Context will often have the CUSTOM flag set, which never compares
  // equal. So for now DON'T compare by context, but by proc_id. (An API is in
  // progress to compare by address space, which should be usable when shipped).
  /*
  if (sp_v8_module_ != nullptr) {
    bool is_equal;
    if (SUCCEEDED(sp_v8_module_ctx_->IsEqualTo(sp_ctx.Get(), &is_equal)) &&
  is_equal) { return sp_v8_module_; } else { sp_v8_module_ = nullptr;
      sp_v8_module_ctx_ = nullptr;
    }
  }
  */
  WRL::ComPtr<IDebugSystemObjects> sp_sys_objects;
  ULONG proc_id = 0;
  if (SUCCEEDED(sp_debug_control.As(&sp_sys_objects))) {
    if (SUCCEEDED(sp_sys_objects->GetCurrentProcessSystemId(&proc_id))) {
      if (proc_id == v8_module_proc_id_ && sp_v8_module_ != nullptr)
        return sp_v8_module_;
    }
  }

  // Search first for a few known module names, to avoid loading symbols for
  // unrelated modules if we can easily avoid it. Generally, failing to find a
  // module is fast but failing to find a symbol within a module is slow. Note
  // that "v8" is listed first because it's highly likely to be the correct
  // module if it exists. The others might include V8 symbols depending on the
  // build configuration.
  std::vector<const wchar_t*> known_names = {
      L"v8", L"v8_for_testing", L"cctest_exe", L"chrome",
      L"d8", L"msedge",         L"node",       L"v8_unittests_exe"};
  for (const wchar_t* name : known_names) {
    WRL::ComPtr<IDebugHostModule> sp_module;
    if (SUCCEEDED(sp_debug_host_symbols->FindModuleByName(sp_ctx.Get(), name,
                                                          &sp_module))) {
      if (IsV8Module(sp_module.Get())) {
        sp_v8_module_ = sp_module;
        sp_v8_module_ctx_ = sp_ctx;
        v8_module_proc_id_ = proc_id;
        return sp_v8_module_;
      }
    }
  }

  // Loop through all modules looking for the one that holds a known symbol.
  WRL::ComPtr<IDebugHostSymbolEnumerator> sp_enum;
  if (SUCCEEDED(
          sp_debug_host_symbols->EnumerateModules(sp_ctx.Get(), &sp_enum))) {
    HRESULT hr = S_OK;
    while (true) {
      WRL::ComPtr<IDebugHostSymbol> sp_mod_sym;
      hr = sp_enum->GetNext(&sp_mod_sym);
      // hr == E_BOUNDS : hit the end of the enumerator
      // hr == E_ABORT  : a user interrupt was requested
      if (FAILED(hr)) break;
      WRL::ComPtr<IDebugHostModule> sp_module;
      if (SUCCEEDED(sp_mod_sym.As(&sp_module))) /* should always succeed */
      {
        if (IsV8Module(sp_module.Get())) {
          sp_v8_module_ = sp_module;
          sp_v8_module_ctx_ = sp_ctx;
          v8_module_proc_id_ = proc_id;
          break;
        }
      }
    }
  }
  // This will be the located module, or still nullptr if above fails
  return sp_v8_module_;
}

Extension::Extension() = default;

HRESULT Extension::Initialize() {
  // Create an instance of the DataModel parent for Tagged<T> types.
  auto object_data_model{WRL::Make<V8ObjectDataModel>()};
  RETURN_IF_FAIL(sp_data_model_manager->CreateDataModelObject(
      object_data_model.Get(), &sp_object_data_model_));
  RETURN_IF_FAIL(sp_object_data_model_->SetConcept(
      __uuidof(IStringDisplayableConcept),
      static_cast<IStringDisplayableConcept*>(object_data_model.Get()),
      nullptr));
  RETURN_IF_FAIL(sp_object_data_model_->SetConcept(
      __uuidof(IDynamicKeyProviderConcept),
      static_cast<IDynamicKeyProviderConcept*>(object_data_model.Get()),
      nullptr));

  // Register that parent model for Tagged<T>.
  WRL::ComPtr<IDebugHostTypeSignature> sp_tagged_type_signature;
  RETURN_IF_FAIL(sp_debug_host_symbols->CreateTypeSignature(
      L"v8::internal::Tagged<*>", nullptr, &sp_tagged_type_signature));
  RETURN_IF_FAIL(sp_data_model_manager->RegisterModelForTypeSignature(
      sp_tagged_type_signature.Get(), sp_object_data_model_.Get()));
  registered_types_.push_back(
      {sp_tagged_type_signature.Get(), sp_object_data_model_.Get()});

  // Create an instance of the DataModel parent for custom iterable fields.
  auto indexed_field_model{WRL::Make<IndexedFieldParent>()};
  RETURN_IF_FAIL(sp_data_model_manager->CreateDataModelObject(
      indexed_field_model.Get(), &sp_indexed_field_model_));
  RETURN_IF_FAIL(sp_indexed_field_model_->SetConcept(
      __uuidof(IIndexableConcept),
      static_cast<IIndexableConcept*>(indexed_field_model.Get()), nullptr));
  RETURN_IF_FAIL(sp_indexed_field_model_->SetConcept(
      __uuidof(IIterableConcept),
      static_cast<IIterableConcept*>(indexed_field_model.Get()), nullptr));

  // Create an instance of the DataModel parent class for v8::Local<*> types.
  auto local_data_model{WRL::Make<V8LocalDataModel>()};
  RETURN_IF_FAIL(sp_data_model_manager->CreateDataModelObject(
      local_data_model.Get(), &sp_local_data_model_));

  // Register that parent model for all known types that act like v8::Local.
  std::vector<const wchar_t*> handle_class_names = {
      L"v8::Local<*>", L"v8::MaybeLocal<*>", L"v8::internal::Handle<*>",
      L"v8::internal::MaybeHandle<*>"};
  for (const wchar_t* name : handle_class_names) {
    WRL::ComPtr<IDebugHostTypeSignature> signature;
    RETURN_IF_FAIL(
        sp_debug_host_symbols->CreateTypeSignature(name, nullptr, &signature));
    RETURN_IF_FAIL(sp_data_model_manager->RegisterModelForTypeSignature(
        signature.Get(), sp_local_data_model_.Get()));
    registered_types_.push_back({signature.Get(), sp_local_data_model_.Get()});
  }

  // Add the 'Value' property to the parent model.
  auto local_value_property{WRL::Make<V8LocalValueProperty>()};
  WRL::ComPtr<IModelObject> sp_local_value_property_model;
  RETURN_IF_FAIL(CreateProperty(sp_data_model_manager.Get(),
                                local_value_property.Get(),
                                &sp_local_value_property_model));
  RETURN_IF_FAIL(sp_local_data_model_->SetKey(
      L"Value", sp_local_value_property_model.Get(), nullptr));

  // Register all function aliases.
  std::vector<std::pair<const wchar_t*, WRL::ComPtr<IModelMethod>>> functions =
      {{pcur_isolate, WRL::Make<CurrIsolateAlias>()},
       {pjs_stack, WRL::Make<JSStackAlias>()},
       {pv8_object, WRL::Make<InspectV8ObjectMethod>()}};
  for (const auto& function : functions) {
    WRL::ComPtr<IModelObject> method;
    RETURN_IF_FAIL(CreateMethod(sp_data_model_manager.Get(),
                                function.second.Get(), &method));
    RETURN_IF_FAIL(sp_debug_host_extensibility->CreateFunctionAlias(
        function.first, method.Get()));
  }

  // Register a handler for supplying stack frame locals. It has to override the
  // getter functions for "LocalVariables" and "Parameters".
  WRL::ComPtr<IModelObject> stack_frame;
  RETURN_IF_FAIL(sp_data_model_manager->AcquireNamedModel(
      L"Debugger.Models.StackFrame", &stack_frame));
  RETURN_IF_FAIL(OverrideLocalsGetter(stack_frame.Get(), L"LocalVariables",
                                      /*is_parameters=*/false));
  RETURN_IF_FAIL(OverrideLocalsGetter(stack_frame.Get(), L"Parameters",
                                      /*is_parameters=*/true));

  // Add node_id property for v8::internal::compiler::Node.
  RETURN_IF_FAIL(
      RegisterAndAddPropertyForClass<V8InternalCompilerNodeIdProperty>(
          L"v8::internal::compiler::Node", L"node_id",
          sp_compiler_node_data_model_));

  // Add bitset_name property for v8::internal::compiler::Type.
  RETURN_IF_FAIL(
      RegisterAndAddPropertyForClass<V8InternalCompilerBitsetNameProperty>(
          L"v8::internal::compiler::Type", L"bitset_name",
          sp_compiler_type_data_model_));

  return S_OK;
}

template <class PropertyClass>
HRESULT Extension::RegisterAndAddPropertyForClass(
    const wchar_t* class_name, const wchar_t* property_name,
    WRL::ComPtr<IModelObject> sp_data_model) {
  // Create an instance of the DataModel parent class.
  auto instance_data_model{WRL::Make<V8LocalDataModel>()};
  RETURN_IF_FAIL(sp_data_model_manager->CreateDataModelObject(
      instance_data_model.Get(), &sp_data_model));

  // Register that parent model.
  WRL::ComPtr<IDebugHostTypeSignature> class_signature;
  RETURN_IF_FAIL(sp_debug_host_symbols->CreateTypeSignature(class_name, nullptr,
                                                            &class_signature));
  RETURN_IF_FAIL(sp_data_model_manager->RegisterModelForTypeSignature(
      class_signature.Get(), sp_data_model.Get()));
  registered_types_.push_back({class_signature.Get(), sp_data_model.Get()});

  // Add the property to the parent model.
  auto property{WRL::Make<PropertyClass>()};
  WRL::ComPtr<IModelObject> sp_property_model;
  RETURN_IF_FAIL(CreateProperty(sp_data_model_manager.Get(), property.Get(),
                                &sp_property_model));
  RETURN_IF_FAIL(
      sp_data_model->SetKey(property_name, sp_property_model.Get(), nullptr));

  return S_OK;
}

HRESULT Extension::OverrideLocalsGetter(IModelObject* stack_frame,
                                        const wchar_t* key_name,
                                        bool is_parameters) {
  WRL::ComPtr<IModelObject> original_boxed_getter;
  WRL::ComPtr<IKeyStore> original_getter_metadata;
  RETURN_IF_FAIL(stack_frame->GetKey(key_name, &original_boxed_getter,
                                     &original_getter_metadata));
  WRL::ComPtr<IModelPropertyAccessor> original_getter;
  RETURN_IF_FAIL(UnboxProperty(original_boxed_getter.Get(), &original_getter));
  auto new_getter{WRL::Make<V8LocalVariables>(original_getter, is_parameters)};
  WRL::ComPtr<IModelObject> new_boxed_getter;
  RETURN_IF_FAIL(CreateProperty(sp_data_model_manager.Get(), new_getter.Get(),
                                &new_boxed_getter));
  RETURN_IF_FAIL(stack_frame->SetKey(key_name, new_boxed_getter.Get(),
                                     original_getter_metadata.Get()));
  overridden_properties_.push_back(
      {stack_frame, reinterpret_cast<const char16_t*>(key_name),
       original_boxed_getter.Get(), original_getter_metadata.Get()});
  return S_OK;
}

Extension::PropertyOverride::PropertyOverride() = default;
Extension::PropertyOverride::PropertyOverride(IModelObject* parent,
                                              std::u16string key_name,
                                              IModelObject* original_value,
                                              IKeyStore* original_metadata)
    : parent(parent),
      key_name(std::move(key_name)),
      original_value(original_value),
      original_metadata(original_metadata) {}
Extension::PropertyOverride::~PropertyOverride() = default;
Extension::PropertyOverride::PropertyOverride(const PropertyOverride&) =
    default;
Extension::PropertyOverride& Extension::PropertyOverride::operator=(
    const PropertyOverride&) = default;

Extension::RegistrationType::RegistrationType() = default;
Extension::RegistrationType::RegistrationType(
    IDebugHostTypeSignature* sp_signature, IModelObject* sp_data_model)
    : sp_signature(sp_signature), sp_data_model(sp_data_model) {}
Extension::RegistrationType::~RegistrationType() = default;
Extension::RegistrationType::RegistrationType(const RegistrationType&) =
    default;
Extension::RegistrationType& Extension::RegistrationType::operator=(
    const RegistrationType&) = default;

Extension::~Extension() {
  sp_debug_host_extensibility->DestroyFunctionAlias(pcur_isolate);
  sp_debug_host_extensibility->DestroyFunctionAlias(pjs_stack);
  sp_debug_host_extensibility->DestroyFunctionAlias(pv8_object);

  for (const auto& registered : registered_types_) {
    sp_data_model_manager->UnregisterModelForTypeSignature(
        registered.sp_data_model.Get(), registered.sp_signature.Get());
  }

  for (const auto& override : overridden_properties_) {
    override.parent->SetKey(
        reinterpret_cast<const wchar_t*>(override.key_name.c_str()),
        override.original_value.Get(), override.original_metadata.Get());
  }
}
```