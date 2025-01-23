Response:
The user wants a summary of the functionalities present in the provided C++ code snippet. The code is a unit test file for V8's module system. I need to identify the different test cases and the specific features they are testing.

Here's a breakdown of the test cases and their functionalities:

1. **ModuleInstantiationFailures1**: Tests scenarios where module instantiation fails due to unresolved dependencies. It checks the state of the module and verifies the error message.
2. **ModuleInstantiationWithImportAttributes**: Tests module instantiation with import attributes, introduced with the `with` clause in import statements. It verifies the parsing and passing of these attributes to the resolve callback.
3. **ModuleInstantiationFailures2**: Further tests module instantiation failures, focusing on how the failure of one module in a dependency graph affects other modules.
4. **ModuleEvaluation**: Tests successful module evaluation after instantiation. It checks the final state of the module and the result of the evaluation.
5. **ModuleEvaluationError1**: Tests module evaluation that results in an error during execution. It verifies the module's error state and the captured exception.
6. **ModuleEvaluationError2**: Tests module evaluation errors in a dependency graph, where an error in one module propagates to dependent modules.
7. **ModuleEvaluationCompletion1 & ModuleEvaluationCompletion2**: Test successful module evaluation and ensure that subsequent evaluations return the same fulfilled promise. They cover various types of module declarations and statements.
8. **ModuleNamespace**: Tests the module namespace object, which provides access to the module's exports. It checks the state of exported variables before and after evaluation.
9. **ModuleEvaluationTopLevelAwait**: Tests module evaluation involving top-level `await`. It verifies that the module evaluation results in a fulfilled promise.
10. **ModuleEvaluationTopLevelAwaitError**: Tests module evaluation with top-level `await` that results in an error. It verifies that the module evaluation results in a rejected promise and captures the exception.

Based on these observations, I can summarize the main functionalities of the code.
好的，根据您提供的V8源代码文件 `v8/test/unittests/objects/modules-unittest.cc` 的第一部分，我可以归纳一下它的主要功能：

**主要功能归纳：**

这个C++源代码文件是一个V8的单元测试文件，专门用于测试V8引擎中 **模块（Modules）** 相关的各种功能。 它主要关注以下几个方面：

1. **模块的实例化 (Instantiation)：**
   - 测试模块在尝试实例化时可能出现的各种失败情况，例如：
     - 依赖模块无法解析（通过 `ResolveCallback` 模拟解析失败）。
     - 依赖模块自身实例化失败。
   - 测试带有 **导入属性 (Import Attributes)** 的模块实例化过程，验证属性是否被正确解析和传递。

2. **模块的编译 (Compilation)：**
   - 通过 `ScriptCompiler::CompileModule` 编译模块源代码。
   - 检查编译后的模块状态 (例如 `kUninstantiated`)。
   - 检查模块的请求 (Module Requests)，例如 `import` 和 `export from` 语句，包括：
     - 请求的模块标识符 (Specifier)。
     - 源代码偏移量 (Source Offset)。
     - 导入属性 (Import Attributes，如果存在)。
   - 能够将源代码偏移量转换为行列号 (`SourceOffsetToLocation`)。

3. **模块的解析回调 (Resolve Callback)：**
   - 定义了一个 `ResolveCallback` 函数，用于模拟模块的解析过程，并控制依赖模块的解析结果（成功或失败）。
   - `ResolveCallbackWithImportAttributes` 特别用于测试带有导入属性的模块解析。

4. **模块的状态管理：**
   - 测试模块在不同阶段的状态变化，例如 `kUninstantiated`（未实例化）, `kInstantiated`（已实例化）, `kEvaluated` (已求值), `kErrored` (出错)。

5. **模块的求值 (Evaluation)：**
   - 虽然在第一部分中没有详细的求值测试，但为后续的求值测试奠定了基础，例如，通过实例化模块，为后续的 `Evaluate` 调用做准备。

**关于代码特征的说明：**

*   **`.tq` 结尾：**  `v8/test/unittests/objects/modules-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。
*   **与 JavaScript 的关系：** 这个 C++ 代码测试的是 V8 引擎中对 JavaScript 模块的支持。JavaScript 的 `import` 和 `export` 语法是这个测试的核心关注点。

**JavaScript 示例 (与功能相关):**

```javascript
// 模块 A (./dep1.js)
export const message = "Hello from dep1!";

// 模块 B (./main.js)
import { message } from './dep1.js';
console.log(message);

// 带有导入属性的模块 (./bar.js)
export {};

// 使用导入属性的模块 (./main_with_attributes.js)
import {} from './bar.js' with { type: 'JSON' };
```

**代码逻辑推理示例 (假设输入与输出):**

假设有以下模块：

```javascript
// moduleA.js
export let count = 0;

// moduleB.js
import { count } from './moduleA.js';
count++; // 尝试修改导入的变量
export { count };
```

**测试代码逻辑 (简化版):**

```c++
// 假设已经编译并获取了 moduleA 和 moduleB

// 实例化 moduleB
CHECK(moduleB->InstantiateModule(context(), ResolveCallback).FromJust());

// 求值 moduleB
moduleB->Evaluate(context());

// 获取 moduleA 的命名空间
Local<v8::Object> nsA = moduleA->GetModuleNamespace().As<v8::Object>();

// 尝试读取 moduleA 中的 count 变量
Local<v8::Value> countAValue = nsA->Get(context(), NewString("count")).ToLocalChecked();

// 输出 (假设)
// countAValue 应该仍然是 0，因为导入的变量是只读的绑定。
```

**用户常见的编程错误示例:**

用户在编写 JavaScript 模块时，常见的错误包括：

1. **模块标识符错误：** `import` 或 `export from` 的路径不正确。
    ```javascript
    // 错误示例
    import { data } from './dat.js'; // 文件名拼写错误
    ```

2. **循环依赖：** 模块之间相互依赖，导致加载死循环。
    ```javascript
    // a.js
    import { b } from './b.js';
    export const a = 1;

    // b.js
    import { a } from './a.js';
    export const b = 2;
    ```

3. **导入未导出的成员：** 尝试导入模块中没有 `export` 的变量或函数。
    ```javascript
    // module.js
    const secret = 42; // 没有 export

    // main.js
    import { secret } from './module.js'; // 错误，secret 未导出
    ```

4. **`export default` 的混淆：**  对默认导出的理解不正确。
    ```javascript
    // module.js
    export default function myFunction() { return 1; }

    // main.js
    import myFunction from './module.js'; // 正确
    import { myFunction } from './module.js'; // 错误，不是命名导出
    ```

**总结：**

总而言之，`v8/test/unittests/objects/modules-unittest.cc` 的第一部分主要关注 V8 引擎中 JavaScript 模块的 **编译和实例化** 过程的正确性，特别是针对各种可能导致实例化失败的情况以及对导入属性的处理进行了详细的测试。它确保了 V8 引擎能够按照 JavaScript 模块规范正确地处理模块的加载和依赖关系。

### 提示词
```
这是目录为v8/test/unittests/objects/modules-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/modules-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-function.h"
#include "src/flags/flags.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

using ModuleTest = v8::TestWithContext;

using v8::Context;
using v8::Data;
using v8::FixedArray;
using v8::HandleScope;
using v8::Int32;
using v8::Isolate;
using v8::Local;
using v8::Location;
using v8::MaybeLocal;
using v8::Module;
using v8::ModuleRequest;
using v8::Promise;
using v8::ScriptCompiler;
using v8::ScriptOrigin;
using v8::String;
using v8::Value;

ScriptOrigin ModuleOrigin(Local<v8::Value> resource_name, Isolate* isolate) {
  ScriptOrigin origin(resource_name, 0, 0, false, -1, Local<v8::Value>(), false,
                      false, true);
  return origin;
}

static v8::Global<Module> dep1_global;
static v8::Global<Module> dep2_global;
MaybeLocal<Module> ResolveCallback(Local<Context> context,
                                   Local<String> specifier,
                                   Local<FixedArray> import_attributes,
                                   Local<Module> referrer) {
  CHECK_EQ(0, import_attributes->Length());
  Isolate* isolate = context->GetIsolate();
  if (specifier->StrictEquals(
          String::NewFromUtf8(isolate, "./dep1.js").ToLocalChecked())) {
    return dep1_global.Get(isolate);
  } else if (specifier->StrictEquals(
                 String::NewFromUtf8(isolate, "./dep2.js").ToLocalChecked())) {
    return dep2_global.Get(isolate);
  } else {
    isolate->ThrowException(
        String::NewFromUtf8(isolate, "boom").ToLocalChecked());
    return MaybeLocal<Module>();
  }
}

TEST_F(ModuleTest, ModuleInstantiationFailures1) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<Module> module;
  {
    Local<String> source_text = NewString(
        "import './foo.js';\n"
        "export {} from './bar.js';");
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    module = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    Local<FixedArray> module_requests = module->GetModuleRequests();
    CHECK_EQ(2, module_requests->Length());
    Local<ModuleRequest> module_request_0 =
        module_requests->Get(context(), 0).As<ModuleRequest>();
    CHECK(
        NewString("./foo.js")->StrictEquals(module_request_0->GetSpecifier()));
    int offset = module_request_0->GetSourceOffset();
    CHECK_EQ(7, offset);
    Location loc = module->SourceOffsetToLocation(offset);
    CHECK_EQ(0, loc.GetLineNumber());
    CHECK_EQ(7, loc.GetColumnNumber());
    CHECK_EQ(0, module_request_0->GetImportAttributes()->Length());

    Local<ModuleRequest> module_request_1 =
        module_requests->Get(context(), 1).As<ModuleRequest>();
    CHECK(
        NewString("./bar.js")->StrictEquals(module_request_1->GetSpecifier()));
    offset = module_request_1->GetSourceOffset();
    CHECK_EQ(34, offset);
    loc = module->SourceOffsetToLocation(offset);
    CHECK_EQ(1, loc.GetLineNumber());
    CHECK_EQ(15, loc.GetColumnNumber());
    CHECK_EQ(0, module_request_1->GetImportAttributes()->Length());
  }

  // Instantiation should fail.
  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(module->InstantiateModule(context(), ResolveCallback).IsNothing());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()->StrictEquals(NewString("boom")));
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
  }

  // Start over again...
  {
    Local<String> source_text = NewString(
        "import './dep1.js';\n"
        "export {} from './bar.js';");
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    module = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
  }

  // dep1.js
  {
    Local<String> source_text = NewString("");
    ScriptOrigin origin = ModuleOrigin(NewString("dep1.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> dep1 =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    dep1_global.Reset(isolate(), dep1);
  }

  // Instantiation should fail because a sub-module fails to resolve.
  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(module->InstantiateModule(context(), ResolveCallback).IsNothing());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()->StrictEquals(NewString("boom")));
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
  }

  CHECK(!try_catch.HasCaught());

  dep1_global.Reset();
}

static v8::Global<Module> fooModule_global;
static v8::Global<Module> barModule_global;
MaybeLocal<Module> ResolveCallbackWithImportAttributes(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  Isolate* isolate = context->GetIsolate();
  if (specifier->StrictEquals(
          String::NewFromUtf8(isolate, "./foo.js").ToLocalChecked())) {
    CHECK_EQ(0, import_attributes->Length());

    return fooModule_global.Get(isolate);
  } else if (specifier->StrictEquals(
                 String::NewFromUtf8(isolate, "./bar.js").ToLocalChecked())) {
    CHECK_EQ(3, import_attributes->Length());
    Local<String> attribute_key =
        import_attributes->Get(context, 0).As<Value>().As<String>();
    CHECK(String::NewFromUtf8(isolate, "a")
              .ToLocalChecked()
              ->StrictEquals(attribute_key));
    Local<String> attribute_value =
        import_attributes->Get(context, 1).As<Value>().As<String>();
    CHECK(String::NewFromUtf8(isolate, "b")
              .ToLocalChecked()
              ->StrictEquals(attribute_value));
    Local<Data> attribute_source_offset_object =
        import_attributes->Get(context, 2);
    Local<Int32> attribute_source_offset_int32 =
        attribute_source_offset_object.As<Value>()
            ->ToInt32(context)
            .ToLocalChecked();
    int32_t attribute_source_offset = attribute_source_offset_int32->Value();
    CHECK_EQ(61, attribute_source_offset);
    Location loc = referrer->SourceOffsetToLocation(attribute_source_offset);
    CHECK_EQ(1, loc.GetLineNumber());
    CHECK_EQ(33, loc.GetColumnNumber());

    return barModule_global.Get(isolate);
  } else {
    isolate->ThrowException(
        String::NewFromUtf8(isolate, "boom").ToLocalChecked());
    return MaybeLocal<Module>();
  }
}

TEST_F(ModuleTest, ModuleInstantiationWithImportAttributes) {
  bool prev_import_attributes = i::v8_flags.harmony_import_attributes;
  i::v8_flags.harmony_import_attributes = true;
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<Module> module;
  {
    Local<String> source_text = NewString(
        "import './foo.js' with { };\n"
        "export {} from './bar.js' with { a: 'b' };");
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    module = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    Local<FixedArray> module_requests = module->GetModuleRequests();
    CHECK_EQ(2, module_requests->Length());
    Local<ModuleRequest> module_request_0 =
        module_requests->Get(context(), 0).As<ModuleRequest>();
    CHECK(
        NewString("./foo.js")->StrictEquals(module_request_0->GetSpecifier()));
    int offset = module_request_0->GetSourceOffset();
    CHECK_EQ(7, offset);
    Location loc = module->SourceOffsetToLocation(offset);
    CHECK_EQ(0, loc.GetLineNumber());
    CHECK_EQ(7, loc.GetColumnNumber());
    CHECK_EQ(0, module_request_0->GetImportAttributes()->Length());

    Local<ModuleRequest> module_request_1 =
        module_requests->Get(context(), 1).As<ModuleRequest>();
    CHECK(
        NewString("./bar.js")->StrictEquals(module_request_1->GetSpecifier()));
    offset = module_request_1->GetSourceOffset();
    CHECK_EQ(43, offset);
    loc = module->SourceOffsetToLocation(offset);
    CHECK_EQ(1, loc.GetLineNumber());
    CHECK_EQ(15, loc.GetColumnNumber());

    Local<FixedArray> import_attributes_1 =
        module_request_1->GetImportAttributes();
    CHECK_EQ(3, import_attributes_1->Length());
    Local<String> attribute_key =
        import_attributes_1->Get(context(), 0).As<String>();
    CHECK(NewString("a")->StrictEquals(attribute_key));
    Local<String> attribute_value =
        import_attributes_1->Get(context(), 1).As<String>();
    CHECK(NewString("b")->StrictEquals(attribute_value));
    int32_t attribute_source_offset =
        import_attributes_1->Get(context(), 2).As<Int32>()->Value();
    CHECK_EQ(61, attribute_source_offset);
    loc = module->SourceOffsetToLocation(attribute_source_offset);
    CHECK_EQ(1, loc.GetLineNumber());
    CHECK_EQ(33, loc.GetColumnNumber());
  }

  // foo.js
  {
    Local<String> source_text = NewString("Object.expando = 40");
    ScriptOrigin origin = ModuleOrigin(NewString("foo.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> fooModule =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    fooModule_global.Reset(isolate(), fooModule);
  }

  // bar.js
  {
    Local<String> source_text = NewString("Object.expando += 2");
    ScriptOrigin origin = ModuleOrigin(NewString("bar.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> barModule =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    barModule_global.Reset(isolate(), barModule);
  }

  CHECK(
      module->InstantiateModule(context(), ResolveCallbackWithImportAttributes)
          .FromJust());
  CHECK_EQ(Module::kInstantiated, module->GetStatus());

  MaybeLocal<Value> result = module->Evaluate(context());
  CHECK_EQ(Module::kEvaluated, module->GetStatus());
  Local<Promise> promise = Local<Promise>::Cast(result.ToLocalChecked());
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());

  // TODO(v8:12781): One IsInt32 matcher be added in
  // gmock-support.h, we could use IsInt32 to replace
  // this.
  {
    Local<Value> result = RunJS("Object.expando");
    CHECK(result->IsInt32());
    CHECK_EQ(42, result->Int32Value(context()).FromJust());
  }
  CHECK(!try_catch.HasCaught());
  i::v8_flags.harmony_import_attributes = prev_import_attributes;

  fooModule_global.Reset();
  barModule_global.Reset();
}

TEST_F(ModuleTest, ModuleInstantiationFailures2) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  // root1.js
  Local<Module> root;
  {
    Local<String> source_text =
        NewString("import './dep1.js'; import './dep2.js'");
    ScriptOrigin origin = ModuleOrigin(NewString("root1.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    root = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
  }

  // dep1.js
  Local<Module> dep1;
  {
    Local<String> source_text = NewString("export let x = 42");
    ScriptOrigin origin = ModuleOrigin(NewString("dep1.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    dep1 = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    dep1_global.Reset(isolate(), dep1);
  }

  // dep2.js
  Local<Module> dep2;
  {
    Local<String> source_text = NewString("import {foo} from './dep3.js'");
    ScriptOrigin origin = ModuleOrigin(NewString("dep2.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    dep2 = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    dep2_global.Reset(isolate(), dep2);
  }

  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(root->InstantiateModule(context(), ResolveCallback).IsNothing());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()->StrictEquals(NewString("boom")));
    CHECK_EQ(Module::kUninstantiated, root->GetStatus());
    CHECK_EQ(Module::kUninstantiated, dep1->GetStatus());
    CHECK_EQ(Module::kUninstantiated, dep2->GetStatus());
  }

  // Change dep2.js
  {
    Local<String> source_text = NewString("import {foo} from './dep2.js'");
    ScriptOrigin origin = ModuleOrigin(NewString("dep2.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    dep2 = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    dep2_global.Reset(isolate(), dep2);
  }

  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(root->InstantiateModule(context(), ResolveCallback).IsNothing());
    CHECK(inner_try_catch.HasCaught());
    CHECK(!inner_try_catch.Exception()->StrictEquals(NewString("boom")));
    CHECK_EQ(Module::kUninstantiated, root->GetStatus());
    CHECK_EQ(Module::kInstantiated, dep1->GetStatus());
    CHECK_EQ(Module::kUninstantiated, dep2->GetStatus());
  }

  // Change dep2.js again
  {
    Local<String> source_text = NewString("import {foo} from './dep3.js'");
    ScriptOrigin origin = ModuleOrigin(NewString("dep2.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    dep2 = ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    dep2_global.Reset(isolate(), dep2);
  }

  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(root->InstantiateModule(context(), ResolveCallback).IsNothing());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()->StrictEquals(NewString("boom")));
    CHECK_EQ(Module::kUninstantiated, root->GetStatus());
    CHECK_EQ(Module::kInstantiated, dep1->GetStatus());
    CHECK_EQ(Module::kUninstantiated, dep2->GetStatus());
  }

  dep1_global.Reset();
  dep2_global.Reset();
}

static MaybeLocal<Module> CompileSpecifierAsModuleResolveCallback(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  CHECK_EQ(0, import_attributes->Length());
  Isolate* isolate = context->GetIsolate();
  ScriptOrigin origin = ModuleOrigin(
      String::NewFromUtf8(isolate, "module.js").ToLocalChecked(), isolate);
  ScriptCompiler::Source source(specifier, origin);
  return ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
}

TEST_F(ModuleTest, ModuleEvaluation) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<String> source_text = NewString(
      "import 'Object.expando = 5';"
      "import 'Object.expando *= 2';");
  ScriptOrigin origin = ModuleOrigin(
      String::NewFromUtf8(isolate(), "file.js").ToLocalChecked(), isolate());

  ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
  CHECK_EQ(Module::kUninstantiated, module->GetStatus());
  CHECK(module
            ->InstantiateModule(context(),
                                CompileSpecifierAsModuleResolveCallback)
            .FromJust());
  CHECK_EQ(Module::kInstantiated, module->GetStatus());

  MaybeLocal<Value> result = module->Evaluate(context());
  CHECK_EQ(Module::kEvaluated, module->GetStatus());
  Local<Promise> promise = result.ToLocalChecked().As<Promise>();
  CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
  CHECK(promise->Result()->IsUndefined());
  // TODO(v8:12781): One IsInt32 matcher be added in
  // gmock-support.h, we could use IsInt32 to replace
  // this.
  {
    Local<Value> result = RunJS("Object.expando");
    CHECK(result->IsInt32());
    CHECK_EQ(10, result->Int32Value(context()).FromJust());
  }
  CHECK(!try_catch.HasCaught());
}

TEST_F(ModuleTest, ModuleEvaluationError1) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<String> source_text =
      NewString("Object.x = (Object.x || 0) + 1; throw 'boom';");
  ScriptOrigin origin = ModuleOrigin(
      String::NewFromUtf8(isolate(), "file.js").ToLocalChecked(), isolate());

  ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
  CHECK_EQ(Module::kUninstantiated, module->GetStatus());
  CHECK(module
            ->InstantiateModule(context(),
                                CompileSpecifierAsModuleResolveCallback)
            .FromJust());
  CHECK_EQ(Module::kInstantiated, module->GetStatus());

  {
    v8::TryCatch inner_try_catch(isolate());
    MaybeLocal<Value> result = module->Evaluate(context());
    CHECK_EQ(Module::kErrored, module->GetStatus());
    Local<Value> exception = module->GetException();
    CHECK(exception->StrictEquals(NewString("boom")));
    // TODO(v8:12781): One IsInt32 matcher be added in
    // gmock-support.h, we could use IsInt32 to replace
    // this.
    {
      Local<Value> result = RunJS("Object.x");
      CHECK(result->IsInt32());
      CHECK_EQ(1, result->Int32Value(context()).FromJust());
    }
    // With top level await, we do not throw and errored evaluation returns
    // a rejected promise with the exception.
    CHECK(!inner_try_catch.HasCaught());
    Local<Promise> promise = result.ToLocalChecked().As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kRejected);
    CHECK_EQ(promise->Result(), module->GetException());
  }

  {
    v8::TryCatch inner_try_catch(isolate());
    MaybeLocal<Value> result = module->Evaluate(context());
    CHECK_EQ(Module::kErrored, module->GetStatus());
    Local<Value> exception = module->GetException();
    CHECK(exception->StrictEquals(NewString("boom")));
    // TODO(v8:12781): One IsInt32 matcher be added in
    // gmock-support.h, we could use IsInt32 to replace
    // this.
    {
      Local<Value> result = RunJS("Object.x");
      CHECK(result->IsInt32());
      CHECK_EQ(1, result->Int32Value(context()).FromJust());
    }

    // With top level await, we do not throw and errored evaluation returns
    // a rejected promise with the exception.
    CHECK(!inner_try_catch.HasCaught());
    Local<Promise> promise = result.ToLocalChecked().As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kRejected);
    CHECK_EQ(promise->Result(), module->GetException());
  }

  CHECK(!try_catch.HasCaught());
}

static v8::Global<Module> failure_module_global;
static v8::Global<Module> dependent_module_global;
MaybeLocal<Module> ResolveCallbackForModuleEvaluationError2(
    Local<Context> context, Local<String> specifier,
    Local<FixedArray> import_attributes, Local<Module> referrer) {
  CHECK_EQ(0, import_attributes->Length());
  Isolate* isolate = context->GetIsolate();
  if (specifier->StrictEquals(
          String::NewFromUtf8(isolate, "./failure.js").ToLocalChecked())) {
    return failure_module_global.Get(isolate);
  } else {
    CHECK(specifier->StrictEquals(
        String::NewFromUtf8(isolate, "./dependent.js").ToLocalChecked()));
    return dependent_module_global.Get(isolate);
  }
}

TEST_F(ModuleTest, ModuleEvaluationError2) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<String> failure_text = NewString("throw 'boom';");
  ScriptOrigin failure_origin =
      ModuleOrigin(NewString("failure.js"), isolate());
  ScriptCompiler::Source failure_source(failure_text, failure_origin);
  Local<Module> failure_module =
      ScriptCompiler::CompileModule(isolate(), &failure_source)
          .ToLocalChecked();
  failure_module_global.Reset(isolate(), failure_module);
  CHECK_EQ(Module::kUninstantiated, failure_module->GetStatus());
  CHECK(failure_module
            ->InstantiateModule(context(),
                                ResolveCallbackForModuleEvaluationError2)
            .FromJust());
  CHECK_EQ(Module::kInstantiated, failure_module->GetStatus());

  {
    v8::TryCatch inner_try_catch(isolate());
    MaybeLocal<Value> result = failure_module->Evaluate(context());
    CHECK_EQ(Module::kErrored, failure_module->GetStatus());
    Local<Value> exception = failure_module->GetException();
    CHECK(exception->StrictEquals(NewString("boom")));

    // With top level await, we do not throw and errored evaluation returns
    // a rejected promise with the exception.
    CHECK(!inner_try_catch.HasCaught());
    Local<Promise> promise = result.ToLocalChecked().As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kRejected);
    CHECK_EQ(promise->Result(), failure_module->GetException());
  }

  Local<String> dependent_text =
      NewString("import './failure.js'; export const c = 123;");
  ScriptOrigin dependent_origin =
      ModuleOrigin(NewString("dependent.js"), isolate());
  ScriptCompiler::Source dependent_source(dependent_text, dependent_origin);
  Local<Module> dependent_module =
      ScriptCompiler::CompileModule(isolate(), &dependent_source)
          .ToLocalChecked();
  dependent_module_global.Reset(isolate(), dependent_module);
  CHECK_EQ(Module::kUninstantiated, dependent_module->GetStatus());
  CHECK(dependent_module
            ->InstantiateModule(context(),
                                ResolveCallbackForModuleEvaluationError2)
            .FromJust());
  CHECK_EQ(Module::kInstantiated, dependent_module->GetStatus());

  {
    v8::TryCatch inner_try_catch(isolate());
    MaybeLocal<Value> result = dependent_module->Evaluate(context());
    CHECK_EQ(Module::kErrored, dependent_module->GetStatus());
    Local<Value> exception = dependent_module->GetException();
    CHECK(exception->StrictEquals(NewString("boom")));
    CHECK_EQ(exception, failure_module->GetException());

    // With top level await, we do not throw and errored evaluation returns
    // a rejected promise with the exception.
    CHECK(!inner_try_catch.HasCaught());
    Local<Promise> promise = result.ToLocalChecked().As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kRejected);
    CHECK_EQ(promise->Result(), failure_module->GetException());
    CHECK(failure_module->GetException()->StrictEquals(NewString("boom")));
  }

  CHECK(!try_catch.HasCaught());

  failure_module_global.Reset();
  dependent_module_global.Reset();
}

TEST_F(ModuleTest, ModuleEvaluationCompletion1) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  const char* sources[] = {
      "",
      "var a = 1",
      "import '42'",
      "export * from '42'",
      "export {} from '42'",
      "export {}",
      "var a = 1; export {a}",
      "export function foo() {}",
      "export class C extends null {}",
      "export let a = 1",
      "export default 1",
      "export default function foo() {}",
      "export default function () {}",
      "export default (function () {})",
      "export default class C extends null {}",
      "export default (class C extends null {})",
      "for (var i = 0; i < 5; ++i) {}",
  };

  for (auto src : sources) {
    Local<String> source_text = NewString(src);
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> module =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    CHECK(module
              ->InstantiateModule(context(),
                                  CompileSpecifierAsModuleResolveCallback)
              .FromJust());
    CHECK_EQ(Module::kInstantiated, module->GetStatus());

    // Evaluate twice.
    Local<Value> result_1 = module->Evaluate(context()).ToLocalChecked();
    CHECK_EQ(Module::kEvaluated, module->GetStatus());
    Local<Value> result_2 = module->Evaluate(context()).ToLocalChecked();
    CHECK_EQ(Module::kEvaluated, module->GetStatus());

    Local<Promise> promise = result_1.As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
    CHECK(promise->Result()->IsUndefined());

    // Second evaluation should return the same promise.
    Local<Promise> promise_too = result_2.As<Promise>();
    CHECK_EQ(promise, promise_too);
    CHECK_EQ(promise_too->State(), v8::Promise::kFulfilled);
    CHECK(promise_too->Result()->IsUndefined());
  }
  CHECK(!try_catch.HasCaught());
}

TEST_F(ModuleTest, ModuleEvaluationCompletion2) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  const char* sources[] = {
      "'gaga'; ",
      "'gaga'; var a = 1",
      "'gaga'; import '42'",
      "'gaga'; export * from '42'",
      "'gaga'; export {} from '42'",
      "'gaga'; export {}",
      "'gaga'; var a = 1; export {a}",
      "'gaga'; export function foo() {}",
      "'gaga'; export class C extends null {}",
      "'gaga'; export let a = 1",
      "'gaga'; export default 1",
      "'gaga'; export default function foo() {}",
      "'gaga'; export default function () {}",
      "'gaga'; export default (function () {})",
      "'gaga'; export default class C extends null {}",
      "'gaga'; export default (class C extends null {})",
  };

  for (auto src : sources) {
    Local<String> source_text = NewString(src);
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> module =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    CHECK(module
              ->InstantiateModule(context(),
                                  CompileSpecifierAsModuleResolveCallback)
              .FromJust());
    CHECK_EQ(Module::kInstantiated, module->GetStatus());

    Local<Value> result_1 = module->Evaluate(context()).ToLocalChecked();
    CHECK_EQ(Module::kEvaluated, module->GetStatus());

    Local<Value> result_2 = module->Evaluate(context()).ToLocalChecked();
    CHECK_EQ(Module::kEvaluated, module->GetStatus());
    Local<Promise> promise = result_1.As<Promise>();
    CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
    CHECK(promise->Result()->IsUndefined());

    // Second Evaluation should return the same promise.
    Local<Promise> promise_too = result_2.As<Promise>();
    CHECK_EQ(promise, promise_too);
    CHECK_EQ(promise_too->State(), v8::Promise::kFulfilled);
    CHECK(promise_too->Result()->IsUndefined());
  }
  CHECK(!try_catch.HasCaught());
}

TEST_F(ModuleTest, ModuleNamespace) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());

  Local<v8::Object> ReferenceError =
      RunJS("ReferenceError")->ToObject(context()).ToLocalChecked();

  Local<String> source_text = NewString(
      "import {a, b} from 'export var a = 1; export let b = 2';"
      "export function geta() {return a};"
      "export function getb() {return b};"
      "export let radio = 3;"
      "export var gaga = 4;");
  ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
  ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
  CHECK_EQ(Module::kUninstantiated, module->GetStatus());
  CHECK(module
            ->InstantiateModule(context(),
                                CompileSpecifierAsModuleResolveCallback)
            .FromJust());
  CHECK_EQ(Module::kInstantiated, module->GetStatus());
  Local<Value> ns = module->GetModuleNamespace();
  CHECK_EQ(Module::kInstantiated, module->GetStatus());
  Local<v8::Object> nsobj = ns->ToObject(context()).ToLocalChecked();
  CHECK_EQ(nsobj->GetCreationContext(isolate()).ToLocalChecked(), context());

  // a, b
  CHECK(nsobj->Get(context(), NewString("a")).ToLocalChecked()->IsUndefined());
  CHECK(nsobj->Get(context(), NewString("b")).ToLocalChecked()->IsUndefined());

  // geta
  {
    auto geta = nsobj->Get(context(), NewString("geta")).ToLocalChecked();
    auto a = geta.As<v8::Function>()
                 ->Call(context(), geta, 0, nullptr)
                 .ToLocalChecked();
    CHECK(a->IsUndefined());
  }

  // getb
  {
    v8::TryCatch inner_try_catch(isolate());
    auto getb = nsobj->Get(context(), NewString("getb")).ToLocalChecked();
    CHECK(getb.As<v8::Function>()->Call(context(), getb, 0, nullptr).IsEmpty());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()
              ->InstanceOf(context(), ReferenceError)
              .FromJust());
  }

  // radio
  {
    v8::TryCatch inner_try_catch(isolate());
    CHECK(nsobj->Get(context(), NewString("radio")).IsEmpty());
    CHECK(inner_try_catch.HasCaught());
    CHECK(inner_try_catch.Exception()
              ->InstanceOf(context(), ReferenceError)
              .FromJust());
  }

  // gaga
  {
    auto gaga = nsobj->Get(context(), NewString("gaga")).ToLocalChecked();
    CHECK(gaga->IsUndefined());
  }

  CHECK(!try_catch.HasCaught());
  CHECK_EQ(Module::kInstantiated, module->GetStatus());
  module->Evaluate(context()).ToLocalChecked();
  CHECK_EQ(Module::kEvaluated, module->GetStatus());

  // geta
  {
    auto geta = nsobj->Get(context(), NewString("geta")).ToLocalChecked();
    auto a = geta.As<v8::Function>()
                 ->Call(context(), geta, 0, nullptr)
                 .ToLocalChecked();
    CHECK_EQ(1, a->Int32Value(context()).FromJust());
  }

  // getb
  {
    auto getb = nsobj->Get(context(), NewString("getb")).ToLocalChecked();
    auto b = getb.As<v8::Function>()
                 ->Call(context(), getb, 0, nullptr)
                 .ToLocalChecked();
    CHECK_EQ(2, b->Int32Value(context()).FromJust());
  }

  // radio
  {
    auto radio = nsobj->Get(context(), NewString("radio")).ToLocalChecked();
    CHECK_EQ(3, radio->Int32Value(context()).FromJust());
  }

  // gaga
  {
    auto gaga = nsobj->Get(context(), NewString("gaga")).ToLocalChecked();
    CHECK_EQ(4, gaga->Int32Value(context()).FromJust());
  }
  CHECK(!try_catch.HasCaught());
}

TEST_F(ModuleTest, ModuleEvaluationTopLevelAwait) {
  HandleScope scope(isolate());
  v8::TryCatch try_catch(isolate());
  const char* sources[] = {
      "await 42",
      "import 'await 42';",
      "import '42'; import 'await 42';",
  };

  for (auto src : sources) {
    Local<String> source_text = NewString(src);
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> module =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    CHECK(module
              ->InstantiateModule(context(),
                                  CompileSpecifierAsModuleResolveCallback)
              .FromJust());
    CHECK_EQ(Module::kInstantiated, module->GetStatus());
    Local<Promise> promise =
        Local<Promise>::Cast(module->Evaluate(context()).ToLocalChecked());
    CHECK_EQ(Module::kEvaluated, module->GetStatus());
    CHECK_EQ(promise->State(), v8::Promise::kFulfilled);
    CHECK(promise->Result()->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }
}

TEST_F(ModuleTest, ModuleEvaluationTopLevelAwaitError) {
  HandleScope scope(isolate());
  const char* sources[] = {
      "await 42; throw 'boom';",
      "import 'await 42; throw \"boom\";';",
      "import '42'; import 'await 42; throw \"boom\";';",
  };

  for (auto src : sources) {
    v8::TryCatch try_catch(isolate());
    Local<String> source_text = NewString(src);
    ScriptOrigin origin = ModuleOrigin(NewString("file.js"), isolate());
    ScriptCompiler::Source source(source_text, origin);
    Local<Module> module =
        ScriptCompiler::CompileModule(isolate(), &source).ToLocalChecked();
    CHECK_EQ(Module::kUninstantiated, module->GetStatus());
    CHECK(module
              ->InstantiateModule(context(),
                                  CompileSpecifierAsModuleResolveCallback)
              .FromJust());
    CHECK_EQ(Module::kInstantiated, module->GetStatus());
    Local<Promise> promise =
        Local<Promise>::Cast(module->Evaluate(context()).ToLocalChecked());
    CHECK_EQ(Module::kErrored, module->GetStatus());
    CHECK_EQ(promise->State(), v8::Promise::kRejected);
    CHECK(promise->Result()->StrictEquals(NewString("boom")));
    CHECK(module->GetException()->StrictEquals(NewString("boom")));

    // TODO(cbruni) I am not sure, but this might not be supposed to throw
    // because it is async.
    CHECK(!try_catch.HasCaught());
  }
}

namespace {
struct DynamicImportData {
  DynamicImportData(Isolate* isolate_, Local<Promise::Resolver> resolver_,
                    Local<Context> context_, bool should_resolve_)
      : isolate(isolate_), should_resolve(should_resolve_) {
    resolver.Reset(isolate, resolver_);
    context.Reset(isolate, context_);
  }

  Isolate* isolate;
  v8::Global<Promise::Resolver> resolver;
  v8::Global<Contex
```