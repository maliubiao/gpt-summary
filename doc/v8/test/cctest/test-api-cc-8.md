Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. I need to analyze the functionality of each test case and provide a high-level overview.

Here's a breakdown of the tests:

*   **`NativeDataProperty`**:  Focuses on using `SetNativeDataProperty` to associate native data with object properties. It tests the getter and setter behavior, including the case where no getter is provided.
*   **`MultiContexts`**: Demonstrates the creation and interaction of multiple independent V8 contexts, including sharing a global object and using security tokens.
*   **`FunctionPrototypeAcrossContexts`**: Checks that function prototypes in different contexts don't accidentally share properties.
*   **`Regress892105`**: Similar to the previous test, but for object and array literals. It ensures that modifications to `Object.prototype` or `Array.prototype` in one context don't affect other contexts.
*   **`UndetectableObject`**: Explores the behavior of objects marked as "undetectable". These objects behave like `undefined` in many contexts (e.g., `typeof`, boolean coercion) but are still valid objects.
*   **`VoidLiteral`**: Tests the equivalence and behavior of `void 0` (which evaluates to `undefined`) compared to explicitly declared `undefined` and undetectable objects.
*   **`ExtensibleOnUndetectable`**: Checks if properties can be added to undetectable objects and if `Object.preventExtensions` works on them.
*   **`ConstructCallWithUndetectable`**: Verifies that undetectable objects cannot be used as constructors.
*   **`SetCallAsFunctionHandlerConstructor`**: Tests setting a function handler that acts as a constructor when an object is created using `new`.
*   **`PersistentHandles`**:  A basic test likely for type checking, demonstrating the creation and resetting of persistent handles for various V8 types.
*   **`GlobalObjectTemplate`**: Shows how to create a context with a custom global object template, adding a native function.
*   **`SimpleExtensions`**: Introduces the concept of V8 extensions and how to register and use them to add custom JavaScript functionality.
*   **`StackTraceInExtension`**: Checks that stack traces within extensions include the correct call frames.
*   **`NullExtensions`**: Tests registering an extension with a null source, verifying it doesn't cause issues.
*   **`ExtensionMissingSourceLength`**: Tests the scenario where the provided source length for an extension is incorrect.
*   **`ExtensionWithSourceLength`**: Verifies that extensions with the correct source length are loaded properly.
*   **`UseEvalFromExtension`**: Tests the use of `eval()` within V8 extensions.
*   **`UseWithFromExtension`**: Tests the use of the `with` statement within V8 extensions.
*   **`AutoExtensions`**: Demonstrates how to create extensions that are automatically enabled when a context is created.
*   **`SyntaxErrorExtensions`**: Checks how V8 handles syntax errors within extension code during context creation.
*   **`ExceptionExtensions`**:  Verifies the behavior when an exception is thrown during extension initialization.
*   **`NativeCallInExtensions`**: Shows that extensions can call internal V8 runtime functions.
*   **`NativeFunctionDeclaration`**: Demonstrates declaring native JavaScript functions within extensions using the `native function` syntax.
*   **`NativeFunctionDeclarationError`**: Tests error handling for syntax errors in native function declarations within extensions.
*   **`NativeFunctionDeclarationErrorEscape`**: Checks how escape sequences within "native" keyword affect parsing.
*   **`ExtensionDependency`**: Explores how to define dependencies between extensions and ensure they are loaded in the correct order.
*   **`FunctionLookup`**: Tests how V8 looks up native functions declared in extensions.
*   **`NativeFunctionConstructCall`**: Verifies that native functions in extensions can be used as constructors.
*   **`ErrorReporting`**: Tests the fatal error handler in cases of circular extension dependencies.
*   **`DcheckErrorHandler`**: Shows how to set and use a custom dcheck error handler (primarily for debugging builds).
*   **`ErrorWithMissingScriptInfo`**: Tests the behavior of error messages when script information is missing.

Based on this analysis, I can now formulate the summary.
这个V8源代码文件 `v8/test/cctest/test-api.cc` 的第9部分主要包含了一系列针对 V8 C++ API 功能的测试用例，特别是关于 **上下文（Contexts）**、**对象模板（Object Templates）**、**属性访问控制** 和 **V8 扩展（Extensions）** 的功能测试。

**功能归纳：**

*   **测试自定义属性的设置和访问：**  演示了如何使用 `SetNativeDataProperty` 设置具有原生数据关联的属性，并测试了在 JavaScript 中访问和修改这些属性的行为，包括设置访问器（setter）的情况。
*   **测试无访问器的原生数据属性：** 验证了当只设置原生数据属性而没有设置访问器时，对其进行赋值操作的行为。
*   **测试多上下文环境：**  展示了如何创建和管理多个独立的 V8 上下文，以及如何在这些上下文之间共享或隔离全局对象和属性。这包括了设置安全令牌来隔离上下文。
*   **测试跨上下文的对象原型隔离：**  验证了在不同上下文创建的函数，其原型链上的属性是相互隔离的，避免了意外的跨上下文数据共享。
*   **测试跨上下文的对象和数组字面量隔离：**  类似于函数原型测试，确保在不同上下文中修改 `Object.prototype` 或 `Array.prototype` 不会影响其他上下文。
*   **测试不可检测对象（Undetectable Objects）：** 探索了使用 `MarkAsUndetectable()` 创建的特殊对象的行为，这些对象在某些场景下（例如 `typeof`）表现得像 `undefined`，但在其他情况下仍然是对象。
*   **测试 `void` 运算符的行为：**  验证了 `void 0` 与 `undefined` 以及不可检测对象的相等性判断。
*   **测试不可检测对象的扩展性：**  检查了是否可以给不可检测对象添加属性，以及 `Object.preventExtensions` 是否对其生效。
*   **测试不可检测对象作为构造函数的行为：**  确认了不可检测对象不能作为构造函数使用。
*   **测试设置函数调用处理器作为构造函数：**  展示了如何通过 `SetCallAsFunctionHandler` 将一个函数设置为构造函数，并在创建对象时执行。
*   **测试持久句柄（Persistent Handles）：**  演示了如何创建和重置持久句柄，主要用于类型检查。
*   **测试全局对象模板：**  展示了如何使用 `ObjectTemplate` 创建自定义的全局对象，并在其中添加原生函数。
*   **测试简单的扩展：**  介绍了 V8 扩展的基本用法，允许在 JavaScript 环境中注入自定义的 JavaScript 代码。
*   **测试扩展中的堆栈跟踪：**  验证了在扩展中抛出错误时，堆栈跟踪信息是否正确。
*   **测试空的扩展：**  测试注册一个内容为空的扩展是否会引发问题。
*   **测试扩展缺少或包含错误的源代码长度：**  验证了 V8 如何处理扩展源代码长度不匹配的情况。
*   **测试在扩展中使用 `eval`：**  展示了在 V8 扩展中调用 `eval` 函数的能力。
*   **测试在扩展中使用 `with` 语句：**  展示了在 V8 扩展中使用 `with` 语句的能力。
*   **测试自动启用的扩展：**  演示了如何创建在上下文创建时自动启用的扩展。
*   **测试扩展中的语法错误：**  验证了当扩展代码存在语法错误时，V8 的处理方式，通常会导致上下文创建失败。
*   **测试扩展中的异常：**  验证了当扩展初始化过程中抛出异常时，V8 的处理方式，通常也会导致上下文创建失败。
*   **测试在扩展中调用原生运行时函数：**  展示了如何在 V8 扩展中调用 V8 内部的运行时函数。
*   **测试原生函数声明：**  介绍了在扩展中使用 `native function` 语法声明原生 JavaScript 函数的方法。
*   **测试原生函数声明错误：**  验证了当原生函数声明存在语法错误时 V8 的处理方式。
*   **测试原生函数声明错误（转义字符）：** 演示了在 `native` 关键字中使用转义字符导致其不被识别为关键字的情况。
*   **测试扩展依赖：**  展示了如何定义扩展之间的依赖关系，并确保它们按照正确的顺序加载。
*   **测试函数查找：**  验证了 V8 如何在扩展中查找和调用原生函数。
*   **测试原生函数的构造调用：**  验证了在扩展中声明的原生函数可以作为构造函数使用。
*   **测试错误报告：**  测试了循环依赖的扩展配置导致致命错误时，V8 的错误处理机制。
*   **测试 Dcheck 错误处理程序：**  展示了如何设置自定义的 Dcheck 错误处理程序（通常在调试版本中使用）。
*   **测试缺少脚本信息的错误：**  验证了当错误消息缺少脚本信息时的处理方式。

**该部分的代码没有以 `.tq` 结尾，因此不是 Torque 源代码。**

**与 JavaScript 功能的关系及举例说明：**

大部分测试都直接关联到 JavaScript 的特性和 V8 的 API 如何暴露这些特性。以下是一些例子：

1. **自定义属性的设置和访问 (`NativeDataProperty`)**

    ```javascript
    let obj = {};
    // 假设在 C++ 中，'obj' 被关联了一个名为 'x' 的原生数据属性
    // 并设置了 SetXValue 作为 setter

    obj.x = 4; // 触发 C++ 的 SetXValue 函数
    console.log(obj.x); // 触发 C++ 的 getter (如果存在)
    ```

2. **多上下文环境 (`MultiContexts`)**

    ```javascript
    // 假设 context0 和 context1 是两个不同的 V8 上下文

    // 在 context0 中
    globalThis.custom = 1234;
    console.log(globalThis.custom); // 输出 1234

    // 在 context1 中
    console.log(globalThis.custom); // 输出 undefined，因为是独立的上下文
    ```

3. **不可检测对象 (`UndetectableObject`)**

    ```javascript
    // 假设 'undetectable' 是一个在 C++ 中创建的不可检测对象

    console.log(typeof undetectable); // 输出 "undefined"
    if (undetectable) {
      console.log("This won't be printed");
    } else {
      console.log("This will be printed");
    }
    console.log(undetectable == null); // 输出 true
    ```

4. **V8 扩展 (`SimpleExtensions`)**

    ```javascript
    // 假设注册了一个名为 'simpletest' 的扩展，其中定义了函数 Foo
    console.log(Foo()); // 输出 4，因为扩展注入了 Foo 函数
    ```

**代码逻辑推理和假设输入输出：**

以 `NativeDataProperty` 测试为例：

**假设输入：**

*   在 C++ 中，创建了一个 `ObjectTemplate`，并使用 `SetNativeDataProperty` 设置了名为 "x" 的属性，关联了 `SetXValue` 作为 setter，初始值为 "donut"。
*   执行 JavaScript 代码 `obj.x = 4; obj.x`。

**代码逻辑推理：**

1. 当执行 `obj.x = 4;` 时，由于设置了 `SetXValue`，V8 会调用该 C++ 函数。
2. `SetXValue` 函数会将传入的值（4）存储到 `xValue` 变量中（注意这里假设了 `xValue` 是一个在 C++ 中定义的变量用来存储设置的值）。
3. 当执行 `obj.x` 时，如果定义了 getter，则会调用 getter。 在这个测试用例的初始部分，getter 返回的是 `xValue`。
4. 在循环中，代码会检查 `xValue` 是否为空，然后运行脚本，之后检查 `xValue` 是否等于 4。

**假设输出：**

*   在循环的第一次迭代中，`xValue` 初始为空。
*   脚本运行后，`xValue` 的值变为 4。
*   `CHECK(v8_num(4)->Equals(...))` 断言会成功，因为 `xValue` 确实是 4。
*   `xValue.Reset()` 会清空 `xValue`，为下一次迭代做准备。

对于 `NoAccessors` 测试，当没有设置 getter 时，`obj.x` 的读取操作将不会调用任何 C++ 函数，也不会返回之前设置的初始值 "donut"。 JavaScript 引擎会按照默认的对象属性访问规则处理。

**用户常见的编程错误示例：**

1. **跨上下文对象混用：**  在不同的 V8 上下文中创建的对象和函数，如果直接传递给另一个上下文使用，可能会导致错误或意外的行为，因为它们的内部状态和原型链可能不兼容。

    ```javascript
    // Context A
    let objA = {};

    // Context B
    function processObject(obj) {
      // 假设 objA 被错误地传递到这里
      console.log(obj.someMethod()); // 如果 objA 在 Context B 中没有 someMethod，则会报错
    }

    // 错误地尝试在 Context B 中处理 Context A 的对象
    // processObject(objA);
    ```

2. **不理解不可检测对象的行为：**  开发者可能会错误地认为不可检测对象完全等同于 `undefined` 或 `null`，导致在条件判断或类型检查时出现意外。

    ```javascript
    let undetectable; // 假设这是 C++ 创建的不可检测对象

    if (undetectable) { // 错误地认为会执行
      console.log("This might not be printed as expected");
    }

    if (undetectable == null) { // 正确的判断方式
      console.log("Undetectable is loosely equal to null");
    }
    ```

**总结该部分的功能：**

总而言之，`v8/test/cctest/test-api.cc` 的这一部分主要负责测试 V8 C++ API 中关于上下文管理、对象属性的自定义、以及 V8 扩展机制的正确性和隔离性。它涵盖了从基础的属性设置和访问，到更复杂的跨上下文交互和扩展功能，确保了 V8 API 的稳定性和可靠性。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
al<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), nullptr, SetXValue,
                               v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x = 4; obj.x");
  for (int i = 0; i < 10; i++) {
    CHECK(xValue.IsEmpty());
    script->Run(context.local()).ToLocalChecked();
    CHECK(v8_num(4)
              ->Equals(context.local(),
                       Local<Value>::New(CcTest::isolate(), xValue))
              .FromJust());
    xValue.Reset();
  }
}


THREADED_TEST(NoAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(
      v8_str("x"), static_cast<v8::AccessorNameGetterCallback>(nullptr),
      nullptr, v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x = 4; obj.x");
  for (int i = 0; i < 10; i++) {
    script->Run(context.local()).ToLocalChecked();
  }
}


THREADED_TEST(MultiContexts) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "dummy",
             v8::FunctionTemplate::New(isolate, DummyCallHandler));

  Local<String> password = v8_str("Password");

  // Create an environment
  LocalContext context0(nullptr, templ);
  context0->SetSecurityToken(password);
  v8::Local<v8::Object> global0 = context0->Global();
  CHECK(global0->Set(context0.local(), v8_str("custom"), v8_num(1234))
            .FromJust());
  CHECK_EQ(1234, global0->Get(context0.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context0.local())
                     .FromJust());

  // Create an independent environment
  LocalContext context1(nullptr, templ);
  context1->SetSecurityToken(password);
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1.local(), v8_str("custom"), v8_num(1234))
            .FromJust());
  CHECK(!global0->Equals(context1.local(), global1).FromJust());
  CHECK_EQ(1234, global0->Get(context1.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context0.local())
                     .FromJust());
  CHECK_EQ(1234, global1->Get(context1.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context1.local())
                     .FromJust());

  // Now create a new context with the old global
  LocalContext context2(nullptr, templ, global1);
  context2->SetSecurityToken(password);
  v8::Local<v8::Object> global2 = context2->Global();
  CHECK(global1->Equals(context2.local(), global2).FromJust());
  CHECK_EQ(0, global1->Get(context2.local(), v8_str("custom"))
                  .ToLocalChecked()
                  ->Int32Value(context1.local())
                  .FromJust());
  CHECK_EQ(0, global2->Get(context2.local(), v8_str("custom"))
                  .ToLocalChecked()
                  ->Int32Value(context2.local())
                  .FromJust());
}


THREADED_TEST(FunctionPrototypeAcrossContexts) {
  // Make sure that functions created by cloning boilerplates cannot
  // communicate through their __proto__ field.

  v8::HandleScope scope(CcTest::isolate());

  LocalContext env0;
  v8::Local<v8::Object> global0 = env0->Global();
  v8::Local<v8::Object> object0 = global0->Get(env0.local(), v8_str("Object"))
                                      .ToLocalChecked()
                                      .As<v8::Object>();
  v8::Local<v8::Object> tostring0 =
      object0->Get(env0.local(), v8_str("toString"))
          .ToLocalChecked()
          .As<v8::Object>();
  v8::Local<v8::Object> proto0 =
      tostring0->Get(env0.local(), v8_str("__proto__"))
          .ToLocalChecked()
          .As<v8::Object>();
  CHECK(proto0->Set(env0.local(), v8_str("custom"), v8_num(1234)).FromJust());

  LocalContext env1;
  v8::Local<v8::Object> global1 = env1->Global();
  v8::Local<v8::Object> object1 = global1->Get(env1.local(), v8_str("Object"))
                                      .ToLocalChecked()
                                      .As<v8::Object>();
  v8::Local<v8::Object> tostring1 =
      object1->Get(env1.local(), v8_str("toString"))
          .ToLocalChecked()
          .As<v8::Object>();
  v8::Local<v8::Object> proto1 =
      tostring1->Get(env1.local(), v8_str("__proto__"))
          .ToLocalChecked()
          .As<v8::Object>();
  CHECK(!proto1->Has(env1.local(), v8_str("custom")).FromJust());
}


THREADED_TEST(Regress892105) {
  // Make sure that object and array literals created by cloning
  // boilerplates cannot communicate through their __proto__
  // field. This is rather difficult to check, but we try to add stuff
  // to Object.prototype and Array.prototype and create a new
  // environment. This should succeed.

  v8::HandleScope scope(CcTest::isolate());

  Local<String> source = v8_str(
      "Object.prototype.obj = 1234;"
      "Array.prototype.arr = 4567;"
      "8901");

  LocalContext env0;
  Local<Script> script0 = v8_compile(source);
  CHECK_EQ(8901.0, script0->Run(env0.local())
                       .ToLocalChecked()
                       ->NumberValue(env0.local())
                       .FromJust());

  LocalContext env1;
  Local<Script> script1 = v8_compile(source);
  CHECK_EQ(8901.0, script1->Run(env1.local())
                       .ToLocalChecked()
                       ->NumberValue(env1.local())
                       .FromJust());
}

static void ReturnThis(const v8::FunctionCallbackInfo<v8::Value>& args) {
  args.GetReturnValue().Set(args.This());
}

THREADED_TEST(UndetectableObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  Local<v8::FunctionTemplate> desc =
      v8::FunctionTemplate::New(env->GetIsolate());
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();

  CHECK(obj->IsUndetectable());

  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  ExpectString("undetectable.toString()", "[object Object]");
  ExpectString("typeof undetectable", "undefined");
  ExpectString("typeof(undetectable)", "undefined");
  ExpectBoolean("typeof undetectable == 'undefined'", true);
  ExpectBoolean("typeof undetectable == 'object'", false);
  ExpectBoolean("if (undetectable) { true; } else { false; }", false);
  ExpectBoolean("!undetectable", true);

  ExpectObject("true&&undetectable", obj);
  ExpectBoolean("false&&undetectable", false);
  ExpectBoolean("true||undetectable", true);
  ExpectObject("false||undetectable", obj);

  ExpectObject("undetectable&&true", obj);
  ExpectObject("undetectable&&false", obj);
  ExpectBoolean("undetectable||true", true);
  ExpectBoolean("undetectable||false", false);

  ExpectBoolean("undetectable==null", true);
  ExpectBoolean("null==undetectable", true);
  ExpectBoolean("undetectable==undefined", true);
  ExpectBoolean("undefined==undetectable", true);
  ExpectBoolean("undetectable==undetectable", true);


  ExpectBoolean("undetectable===null", false);
  ExpectBoolean("null===undetectable", false);
  ExpectBoolean("undetectable===undefined", false);
  ExpectBoolean("undefined===undetectable", false);
  ExpectBoolean("undetectable===undetectable", true);
}


THREADED_TEST(VoidLiteral) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  ExpectBoolean("undefined == void 0", true);
  ExpectBoolean("undetectable == void 0", true);
  ExpectBoolean("null == void 0", true);
  ExpectBoolean("undefined === void 0", true);
  ExpectBoolean("undetectable === void 0", false);
  ExpectBoolean("null === void 0", false);

  ExpectBoolean("void 0 == undefined", true);
  ExpectBoolean("void 0 == undetectable", true);
  ExpectBoolean("void 0 == null", true);
  ExpectBoolean("void 0 === undefined", true);
  ExpectBoolean("void 0 === undetectable", false);
  ExpectBoolean("void 0 === null", false);

  ExpectString(
      "(function() {"
      "  try {"
      "    return x === void 0;"
      "  } catch(e) {"
      "    return e.toString();"
      "  }"
      "})()",
      "ReferenceError: x is not defined");
  ExpectString(
      "(function() {"
      "  try {"
      "    return void 0 === x;"
      "  } catch(e) {"
      "    return e.toString();"
      "  }"
      "})()",
      "ReferenceError: x is not defined");
}


THREADED_TEST(ExtensibleOnUndetectable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  Local<String> source = v8_str(
      "undetectable.x = 42;"
      "undetectable.x");

  Local<Script> script = v8_compile(source);

  CHECK(v8::Integer::New(isolate, 42)
            ->Equals(env.local(), script->Run(env.local()).ToLocalChecked())
            .FromJust());

  ExpectBoolean("Object.isExtensible(undetectable)", true);

  source = v8_str("Object.preventExtensions(undetectable);");
  script = v8_compile(source);
  script->Run(env.local()).ToLocalChecked();
  ExpectBoolean("Object.isExtensible(undetectable)", false);

  source = v8_str("undetectable.y = 2000;");
  script = v8_compile(source);
  script->Run(env.local()).ToLocalChecked();
  ExpectBoolean("undetectable.y == undefined", true);
}

THREADED_TEST(ConstructCallWithUndetectable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  // Undetectable object cannot be called as constructor.
  v8::TryCatch try_catch(env->GetIsolate());
  CHECK(CompileRun("new undetectable()").IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(env->GetIsolate(), try_catch.Exception());
  CHECK_EQ(0, strcmp("TypeError: undetectable is not a constructor",
                     *exception_value));
}

static int increment_callback_counter = 0;

static void IncrementCounterConstructCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  increment_callback_counter++;
  CHECK(Local<Object>::Cast(args.NewTarget())
            ->Set(args.GetIsolate()->GetCurrentContext(), v8_str("counter"),
                  v8_num(increment_callback_counter))
            .FromJust());
  args.GetReturnValue().Set(args.NewTarget());
}

THREADED_TEST(SetCallAsFunctionHandlerConstructor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->SetCallAsFunctionHandler(
      IncrementCounterConstructCallback);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("Counter"), obj).FromJust());

  ExpectInt32("(new Counter()).counter", 1);
  CHECK_EQ(1, increment_callback_counter);
  ExpectInt32("(new Counter()).counter", 2);
  CHECK_EQ(2, increment_callback_counter);
}
// The point of this test is type checking. We run it only so compilers
// don't complain about an unused function.
TEST(PersistentHandles) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<String> str = v8_str("foo");
  v8::Persistent<String> p_str(isolate, str);
  p_str.Reset();
  Local<Script> scr = v8_compile("");
  v8::Persistent<Script> p_scr(isolate, scr);
  p_scr.Reset();
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  v8::Persistent<ObjectTemplate> p_templ(isolate, templ);
  p_templ.Reset();
}


static void HandleLogDelegator(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
}


THREADED_TEST(GlobalObjectTemplate) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  global_template->Set(isolate, "JSNI_Log",
                       v8::FunctionTemplate::New(isolate, HandleLogDelegator));
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  CompileRun("JSNI_Log('LOG')");
}


static const char* kSimpleExtensionSource =
    "function Foo() {"
    "  return 4;"
    "}";


TEST(SimpleExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("simpletest", kSimpleExtensionSource));
  const char* extension_names[] = {"simpletest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("Foo()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}


static const char* kStackTraceFromExtensionSource =
    "function foo() {"
    "  throw new Error();"
    "}"
    "function bar() {"
    "  foo();"
    "}";


TEST(StackTraceInExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>(
      "stacktracetest", kStackTraceFromExtensionSource));
  const char* extension_names[] = {"stacktracetest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  CompileRun(
      "function user() { bar(); }"
      "var error;"
      "try{ user(); } catch (e) { error = e; }");
  CHECK_EQ(-1, v8_run_int32value(v8_compile("error.stack.indexOf('foo')")));
  CHECK_EQ(-1, v8_run_int32value(v8_compile("error.stack.indexOf('bar')")));
  CHECK_NE(-1, v8_run_int32value(v8_compile("error.stack.indexOf('user')")));
}


TEST(NullExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>("nulltest", nullptr));
  const char* extension_names[] = {"nulltest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("1+3");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}

static const char* kEmbeddedExtensionSource =
    "function Ret54321(){return 54321;}~~@@$"
    "$%% THIS IS A SERIES OF NON-nullptr-TERMINATED STRINGS.";
static const int kEmbeddedExtensionSourceValidLen = 34;


TEST(ExtensionMissingSourceLength) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("srclentest_fail", kEmbeddedExtensionSource));
  const char* extension_names[] = {"srclentest_fail"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


TEST(ExtensionWithSourceLength) {
  for (int source_len = kEmbeddedExtensionSourceValidLen - 1;
       source_len <= kEmbeddedExtensionSourceValidLen + 1; ++source_len) {
    v8::HandleScope handle_scope(CcTest::isolate());
    v8::base::ScopedVector<char> extension_name(32);
    v8::base::SNPrintF(extension_name, "ext #%d", source_len);
    v8::RegisterExtension(std::make_unique<Extension>(extension_name.begin(),
                                                      kEmbeddedExtensionSource,
                                                      0, nullptr, source_len));
    const char* extension_names[1] = {extension_name.begin()};
    v8::ExtensionConfiguration extensions(1, extension_names);
    v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
    if (source_len == kEmbeddedExtensionSourceValidLen) {
      Context::Scope lock(context);
      v8::Local<Value> result = CompileRun("Ret54321()");
      CHECK(v8::Integer::New(CcTest::isolate(), 54321)
                ->Equals(context, result)
                .FromJust());
    } else {
      // Anything but exactly the right length should fail to compile.
      CHECK(context.IsEmpty());
    }
  }
}


static const char* kEvalExtensionSource1 =
    "function UseEval1() {"
    "  var x = 42;"
    "  return eval('x');"
    "}";


static const char* kEvalExtensionSource2 =
    "(function() {"
    "  var x = 42;"
    "  function e() {"
    "    return eval('x');"
    "  }"
    "  this.UseEval2 = e;"
    "})()";


TEST(UseEvalFromExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("evaltest1", kEvalExtensionSource1));
  v8::RegisterExtension(
      std::make_unique<Extension>("evaltest2", kEvalExtensionSource2));
  const char* extension_names[] = {"evaltest1", "evaltest2"};
  v8::ExtensionConfiguration extensions(2, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("UseEval1()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
  result = CompileRun("UseEval2()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
}


static const char* kWithExtensionSource1 =
    "function UseWith1() {"
    "  var x = 42;"
    "  with({x:87}) { return x; }"
    "}";


static const char* kWithExtensionSource2 =
    "(function() {"
    "  var x = 42;"
    "  function e() {"
    "    with ({x:87}) { return x; }"
    "  }"
    "  this.UseWith2 = e;"
    "})()";


TEST(UseWithFromExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("withtest1", kWithExtensionSource1));
  v8::RegisterExtension(
      std::make_unique<Extension>("withtest2", kWithExtensionSource2));
  const char* extension_names[] = {"withtest1", "withtest2"};
  v8::ExtensionConfiguration extensions(2, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("UseWith1()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 87))
            .FromJust());
  result = CompileRun("UseWith2()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 87))
            .FromJust());
}


TEST(AutoExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  auto extension =
      std::make_unique<Extension>("autotest", kSimpleExtensionSource);
  extension->set_auto_enable(true);
  v8::RegisterExtension(std::move(extension));
  v8::Local<Context> context = Context::New(CcTest::isolate());
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("Foo()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}


static const char* kSyntaxErrorInExtensionSource = "[";


// Test that a syntax error in an extension does not cause a fatal
// error but results in an empty context.
TEST(SyntaxErrorExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>(
      "syntaxerror", kSyntaxErrorInExtensionSource));
  const char* extension_names[] = {"syntaxerror"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


static const char* kExceptionInExtensionSource = "throw 42";


// Test that an exception when installing an extension does not cause
// a fatal error but results in an empty context.
TEST(ExceptionExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("exception", kExceptionInExtensionSource));
  const char* extension_names[] = {"exception"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}

static const char* kNativeCallInExtensionSource =
    "function call_runtime_last_index_of(x) {"
    "  return %StringLastIndexOf(x, 'bob');"
    "}";

static const char* kNativeCallTest =
    "call_runtime_last_index_of('bobbobboellebobboellebobbob');";

// Test that a native runtime calls are supported in extensions.
TEST(NativeCallInExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("nativecall", kNativeCallInExtensionSource));
  const char* extension_names[] = {"nativecall"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun(kNativeCallTest);
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 24))
            .FromJust());
}


class NativeFunctionExtension : public Extension {
 public:
  NativeFunctionExtension(const char* name, const char* source,
                          v8::FunctionCallback fun = &Echo)
      : Extension(name, source), function_(fun) {}

  v8::Local<v8::FunctionTemplate> GetNativeFunctionTemplate(
      v8::Isolate* isolate, v8::Local<v8::String> name) override {
    return v8::FunctionTemplate::New(isolate, function_);
  }

  static void Echo(const v8::FunctionCallbackInfo<v8::Value>& args) {
    if (args.Length() >= 1) args.GetReturnValue().Set(args[0]);
  }

 private:
  v8::FunctionCallback function_;
};


TEST(NativeFunctionDeclaration) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedecl";
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "native function foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("foo(42);");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
}


TEST(NativeFunctionDeclarationError) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedeclerr";
  // Syntax error in extension code.
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "native\nfunction foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


TEST(NativeFunctionDeclarationErrorEscape) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedeclerresc";
  // Syntax error in extension code - escape code in "native" means that
  // it's not treated as a keyword.
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "nativ\\u0065 function foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


static void CheckDependencies(const char* name, const char* expected) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::ExtensionConfiguration config(1, &name);
  LocalContext context(&config);
  CHECK(
      v8_str(expected)
          ->Equals(context.local(), context->Global()
                                        ->Get(context.local(), v8_str("loaded"))
                                        .ToLocalChecked())
          .FromJust());
}


/*
 * Configuration:
 *
 *     /-- B <--\
 * A <-          -- D <-- E
 *     \-- C <--/
 */
THREADED_TEST(ExtensionDependency) {
  static const char* kEDeps[] = {"D"};
  v8::RegisterExtension(
      std::make_unique<Extension>("E", "this.loaded += 'E';", 1, kEDeps));
  static const char* kDDeps[] = {"B", "C"};
  v8::RegisterExtension(
      std::make_unique<Extension>("D", "this.loaded += 'D';", 2, kDDeps));
  static const char* kBCDeps[] = {"A"};
  v8::RegisterExtension(
      std::make_unique<Extension>("B", "this.loaded += 'B';", 1, kBCDeps));
  v8::RegisterExtension(
      std::make_unique<Extension>("C", "this.loaded += 'C';", 1, kBCDeps));
  v8::RegisterExtension(
      std::make_unique<Extension>("A", "this.loaded += 'A';"));
  CheckDependencies("A", "undefinedA");
  CheckDependencies("B", "undefinedAB");
  CheckDependencies("C", "undefinedAC");
  CheckDependencies("D", "undefinedABCD");
  CheckDependencies("E", "undefinedABCDE");
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[2] = {"C", "E"};
  v8::ExtensionConfiguration config(2, exts);
  LocalContext context(&config);
  CHECK(
      v8_str("undefinedACBDE")
          ->Equals(context.local(), context->Global()
                                        ->Get(context.local(), v8_str("loaded"))
                                        .ToLocalChecked())
          .FromJust());
}


static const char* kExtensionTestScript =
    "native function A();"
    "native function B();"
    "native function C();"
    "function Foo(i) {"
    "  if (i == 0) return A();"
    "  if (i == 1) return B();"
    "  if (i == 2) return C();"
    "}";


static void CallFun(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  if (args.IsConstructCall()) {
    CHECK(args.This()
              ->Set(args.GetIsolate()->GetCurrentContext(), v8_str("data"),
                    args.Data())
              .FromJust());
    args.GetReturnValue().SetNull();
    return;
  }
  args.GetReturnValue().Set(args.Data());
}


class FunctionExtension : public Extension {
 public:
  FunctionExtension() : Extension("functiontest", kExtensionTestScript) {}
  v8::Local<v8::FunctionTemplate> GetNativeFunctionTemplate(
      v8::Isolate* isolate, v8::Local<String> name) override;
};


static int lookup_count = 0;
v8::Local<v8::FunctionTemplate> FunctionExtension::GetNativeFunctionTemplate(
    v8::Isolate* isolate, v8::Local<String> name) {
  lookup_count++;
  if (name->StrictEquals(v8_str("A"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 8));
  } else if (name->StrictEquals(v8_str("B"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 7));
  } else if (name->StrictEquals(v8_str("C"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 6));
  } else {
    return v8::Local<v8::FunctionTemplate>();
  }
}


THREADED_TEST(FunctionLookup) {
  v8::RegisterExtension(std::make_unique<FunctionExtension>());
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[1] = {"functiontest"};
  v8::ExtensionConfiguration config(1, exts);
  LocalContext context(&config);
  CHECK_EQ(3, lookup_count);
  CHECK(v8::Integer::New(CcTest::isolate(), 8)
            ->Equals(context.local(), CompileRun("Foo(0)"))
            .FromJust());
  CHECK(v8::Integer::New(CcTest::isolate(), 7)
            ->Equals(context.local(), CompileRun("Foo(1)"))
            .FromJust());
  CHECK(v8::Integer::New(CcTest::isolate(), 6)
            ->Equals(context.local(), CompileRun("Foo(2)"))
            .FromJust());
}


THREADED_TEST(NativeFunctionConstructCall) {
  v8::RegisterExtension(std::make_unique<FunctionExtension>());
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[1] = {"functiontest"};
  v8::ExtensionConfiguration config(1, exts);
  LocalContext context(&config);
  for (int i = 0; i < 10; i++) {
    // Run a few times to ensure that allocation of objects doesn't
    // change behavior of a constructor function.
    CHECK(v8::Integer::New(CcTest::isolate(), 8)
              ->Equals(context.local(), CompileRun("(new A()).data"))
              .FromJust());
    CHECK(v8::Integer::New(CcTest::isolate(), 7)
              ->Equals(context.local(), CompileRun("(new B()).data"))
              .FromJust());
    CHECK(v8::Integer::New(CcTest::isolate(), 6)
              ->Equals(context.local(), CompileRun("(new C()).data"))
              .FromJust());
  }
}


static const char* last_location;
static const char* last_message;
void StoringErrorCallback(const char* location, const char* message) {
  if (last_location == nullptr) {
    last_location = location;
    last_message = message;
  }
}


// ErrorReporting creates a circular extensions configuration and
// tests that the fatal error handler gets called.  This renders V8
// unusable and therefore this test cannot be run in parallel.
TEST(ErrorReporting) {
  CcTest::isolate()->SetFatalErrorHandler(StoringErrorCallback);
  static const char* aDeps[] = {"B"};
  v8::RegisterExtension(std::make_unique<Extension>("A", "", 1, aDeps));
  static const char* bDeps[] = {"A"};
  v8::RegisterExtension(std::make_unique<Extension>("B", "", 1, bDeps));
  last_location = nullptr;
  v8::ExtensionConfiguration config(1, bDeps);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &config);
  CHECK(context.IsEmpty());
  CHECK(last_location);
}

static size_t dcheck_count;
void DcheckErrorCallback(const char* file, int line, const char* message) {
  last_message = message;
  ++dcheck_count;
}

TEST(DcheckErrorHandler) {
  V8::SetDcheckErrorHandler(DcheckErrorCallback);

  last_message = nullptr;
  dcheck_count = 0;

  DCHECK(false && "w00t");
#ifdef DEBUG
  CHECK_EQ(dcheck_count, 1);
  CHECK(last_message);
  CHECK(std::string(last_message).find("w00t") != std::string::npos);
#else
  // The DCHECK should be a noop in non-DEBUG builds.
  CHECK_EQ(dcheck_count, 0);
#endif
}

static void MissingScriptInfoMessageListener(v8::Local<v8::Message> message,
                                             v8::Local<Value> data) {
  v8::Isolate* isolate = CcTest::isolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK(message->GetScriptOrigin().ResourceName()->IsUndefined());
  CHECK(v8::Undefined(isolate)
            ->Equals(context, message->GetScriptOrigin().ResourceName())
            .FromJust());
  message->GetLineNumber(context).FromJust();
  message->GetSourceLine(context).ToLocalChecked();
}


THREADED_TEST(ErrorWithMissingScriptInfo) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->AddMessageListener(MissingScriptInfoMessageListener);
  CompileRun("throw Error()")
```