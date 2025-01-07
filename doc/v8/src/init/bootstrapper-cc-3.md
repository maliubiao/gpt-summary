Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

1. **Understanding the Goal:** The request asks for the functionality of the provided C++ code, specifically within the context of V8's bootstrapping process. It also prompts for connections to JavaScript, potential errors, and a summary given its position as part 4 of 11.

2. **Initial Code Scan - High-Level Observations:**  A quick scan reveals patterns:
    * Lots of `factory->NewMapWithMetaMap(...)` calls. These seem to be creating different types of context maps.
    * Calls to `native_context()->set_*_context_map(...)`, associating these maps with the native context.
    * Blocks of code starting with `// --- O b j e c t ---`, `// --- F u n c t i o n ---`, `// --- A r r a y ---`, etc. These clearly relate to setting up fundamental JavaScript objects and their prototypes.
    * Numerous `SimpleInstallFunction` and `SimpleInstallGetterSetter` calls. These are likely installing built-in JavaScript methods and accessors on the respective prototypes.
    *  References to `Builtin::k...` constants, suggesting calls to pre-compiled or native functions.

3. **Focusing on Context Maps:** The first part of the code is repetitive but crucial. The core operation is creating maps associated with different JavaScript execution contexts (function, catch, with, debug eval, block, module, await, script, eval). The key is understanding *why* these different context types exist. This links to how JavaScript manages scope and execution environments.

4. **Connecting Context Maps to JavaScript:**  How do these context types manifest in JavaScript?  Consider the following:
    * **Function Context:**  Every function call creates one.
    * **Catch Context:**  Created by `try...catch`.
    * **With Context:**  The (now discouraged) `with` statement.
    * **Block Context:** Introduced by `let` and `const`.
    * **Module Context:** For JavaScript modules.
    * **Await Context:**  Used with `async/await`.
    * **Script Context:**  Top-level code in a `<script>` tag or file.
    * **Eval Context:**  When using `eval()`.

5. **Analyzing Object, Function, Array, etc. Blocks:**  These sections are about initializing core JavaScript built-in objects. The pattern is:
    * Get or create the constructor function (e.g., `Object`, `Function`, `Array`).
    * Install static methods on the constructor itself (e.g., `Object.assign`, `Array.isArray`).
    * Get or create the prototype object (`Object.prototype`, `Function.prototype`, `Array.prototype`).
    * Install methods on the prototype (e.g., `Object.prototype.toString`, `Array.prototype.push`).
    * Often, there's special handling for certain properties like `length` on `Array` and `String`.

6. **Relating Built-ins to JavaScript:**  For each `SimpleInstallFunction` call, consider the corresponding JavaScript method. For example:
    * `SimpleInstallFunction(..., "push", Builtin::kArrayPrototypePush, ...)` maps directly to `Array.prototype.push()`.

7. **Identifying Potential Errors:** Common programming errors often involve misunderstanding how these built-in objects and their prototypes work. Examples:
    * Incorrectly trying to modify non-writable properties.
    * Expecting methods to exist on primitive values directly (they exist on the wrapper object prototypes).
    * Misunderstanding the behavior of methods like `Object.defineProperty`.

8. **Code Logic and Assumptions:** While the code itself is about *setting up* the environment, there isn't much complex *algorithmic* logic. The main assumption is that the underlying V8 structures (factories, isolates, native contexts, maps) are correctly initialized before this code runs. The input is essentially a partially initialized V8 environment, and the output is a more fully initialized one with core JavaScript objects ready.

9. **Considering the "Part 4 of 11" Context:**  This suggests that previous parts likely dealt with even more fundamental setup (like creating the isolate and the initial heap), and later parts will build upon this foundation to initialize more complex features. Part 4 focuses on the basic object model and built-in types.

10. **Structuring the Response:**  Organize the findings logically:
    * Start with the high-level goal of the code.
    * Explain the context map initialization and its relation to JavaScript.
    * Detail the initialization of `Object`, `Function`, `Array`, `Number`, `Boolean`, and `String`, highlighting key methods and properties.
    * Provide JavaScript examples to illustrate the functionality.
    * Give examples of common programming errors related to these concepts.
    * Summarize the functionality based on it being part 4.

11. **Refinement and Clarity:** Review the generated response for clarity, accuracy, and completeness. Ensure that the JavaScript examples are concise and relevant. Make sure the explanation of context maps is understandable.

**(Self-Correction during the Process):**

* **Initial thought:** Maybe the context map stuff is just internal V8 details.
* **Correction:** Realized the context maps directly relate to JavaScript's scope and execution model, so that connection is important.
* **Initial thought:** Just list the installed functions.
* **Correction:**  Explain *what* those functions do in JavaScript and why they are being installed here.
* **Initial thought:**  Focus solely on the C++ code.
* **Correction:**  The prompt specifically asks for JavaScript connections, so those need to be prominent.

By following these steps, combining code analysis with understanding of JavaScript concepts and the V8 architecture, a comprehensive and accurate response can be generated.
好的，让我们来分析一下这段 v8 源代码 `v8/src/init/bootstrapper.cc` 的功能。

**功能列举:**

这段代码的主要功能是 **初始化 V8 引擎的核心 JavaScript 环境**。具体来说，它负责创建和配置一些最基础的 JavaScript 对象、函数和原型，这些是所有 JavaScript 代码运行的基础。

分解来看，这段代码做了以下几件事：

1. **设置不同类型的执行上下文 (Contexts):**
   - 它创建了各种类型的上下文映射 (Maps)，例如 `FUNCTION_CONTEXT_TYPE`, `CATCH_CONTEXT_TYPE`, `WITH_CONTEXT_TYPE` 等。
   - 这些上下文类型代表了 JavaScript 代码执行的不同环境，例如函数调用、`try...catch` 块、`with` 语句等。
   - 它将这些映射与 `native_context()` 关联起来，`native_context()` 是一个代表全局执行环境的核心对象。

2. **安装全局对象 (Object):**
   - 获取或创建 `Object` 构造函数 (`object_function`) 和全局对象 (`global_object`)。
   - 在 `Object` 构造函数上安装静态方法，例如 `assign`, `getOwnPropertyDescriptor`, `create`, `defineProperty` 等。这些方法可以直接在 `Object` 上调用，例如 `Object.assign()`.
   - 在 `Object.prototype` 上安装原型方法，例如 `toString`, `valueOf`, `hasOwnProperty`, `isPrototypeOf` 等。这些方法可以被所有继承自 `Object` 的对象调用。

3. **安装函数对象 (Function):**
   - 获取或创建 `Function` 构造函数 (`function_fun`)。
   - 设置 `Function` 构造函数的原型 (`prototype`)。
   - 在 `Function.prototype` 上安装方法，例如 `apply`, `bind`, `call`, `toString`。
   - 安装 `Symbol.hasInstance` 方法。
   - 配置不同类型的函数映射 (sloppy, strict, class)。

4. **安装数组对象 (Array):**
   - 获取或创建 `Array` 构造函数 (`array_function`)。
   - 在 `Array` 构造函数上安装静态方法，例如 `isArray`, `from`, `of`.
   - 创建和设置 `Array.prototype`。
   - 在 `Array.prototype` 上安装数组的原型方法，例如 `push`, `pop`, `slice`, `splice`, `map`, `filter`, `reduce` 等。
   - 设置迭代器相关的方法 (`keys`, `entries`, `values`, `forEach`).
   - 设置 `@@unscopables` 符号属性。

5. **安装数组迭代器对象 (Array Iterator):**
   - 创建 `Array Iterator` 的原型 (`array_iterator_prototype`)。
   - 在原型上安装 `next` 方法。

6. **安装数字对象 (Number):**
   - 获取或创建 `Number` 构造函数 (`number_fun`)。
   - 创建和设置 `Number.prototype`。
   - 在 `Number.prototype` 上安装原型方法，例如 `toExponential`, `toFixed`, `toString`, `valueOf`。
   - 在 `Number` 构造函数上安装静态方法，例如 `isFinite`, `isInteger`, `isNaN`, `parseFloat`, `parseInt`。
   - 安装 `Number` 的常量，例如 `MAX_VALUE`, `MIN_VALUE`, `NaN`, `Infinity`。
   - 将 `Infinity` 和 `NaN` 安装为全局属性。

7. **安装布尔对象 (Boolean):**
   - 获取或创建 `Boolean` 构造函数 (`boolean_fun`)。
   - 创建和设置 `Boolean.prototype`。
   - 在 `Boolean.prototype` 上安装原型方法，例如 `toString`, `valueOf`。

8. **安装字符串对象 (String):**
   - 获取或创建 `String` 构造函数 (`string_fun`)。
   - 在 `String` 构造函数上安装静态方法，例如 `fromCharCode`, `fromCodePoint`, `raw`.
   - 创建和设置 `String.prototype`。
   - 在 `String.prototype` 上安装字符串的原型方法，例如 `charAt`, `charCodeAt`, `indexOf`, `slice`, `toUpperCase`, `toLowerCase` 等。

**关于文件扩展名 `.tq`:**

如果 `v8/src/init/bootstrapper.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 内部使用的类型安全语言，用于定义内置函数和类型。然而，从你提供的文件名来看，它是 `.cc` 文件，这意味着它是 **C++ 源代码**。

**与 JavaScript 功能的关系及示例:**

这段 C++ 代码的功能直接关系到 JavaScript 的核心功能。它初始化了 JavaScript 中最基础的对象和方法，这些对象和方法在任何 JavaScript 代码中都会被使用。

**JavaScript 示例:**

```javascript
// 这些对象和方法都在 v8/src/init/bootstrapper.cc 中被初始化

// 使用 Object 构造函数和其静态方法
const obj1 = new Object();
const obj2 = { a: 1 };
const mergedObj = Object.assign({}, obj1, obj2); // Object.assign 被初始化

// 使用 Function 构造函数和原型方法
function myFunction() { console.log("Hello"); }
myFunction.call(null); // Function.prototype.call 被初始化

// 使用 Array 构造函数和原型方法
const arr = [1, 2, 3];
arr.push(4); // Array.prototype.push 被初始化
arr.map(x => x * 2); // Array.prototype.map 被初始化

// 使用 Number 构造函数和静态/原型方法
const num = 10;
console.log(num.toFixed(2)); // Number.prototype.toFixed 被初始化
console.log(Number.isNaN(NaN)); // Number.isNaN 被初始化

// 使用 Boolean 构造函数和原型方法
const bool = true;
console.log(bool.toString()); // Boolean.prototype.toString 被初始化

// 使用 String 构造函数和静态/原型方法
const str = "hello";
console.log(str.toUpperCase()); // String.prototype.toUpperCase 被初始化
console.log(String.fromCharCode(65)); // String.fromCharCode 被初始化
```

**代码逻辑推理 (假设输入与输出):**

这段代码主要是进行初始化操作，而不是执行复杂的逻辑推理。

**假设输入:** 一个 V8 引擎实例，其核心组件（如 `Isolate`, `Factory`）已经被创建，但 JavaScript 的内置对象和原型尚未完全初始化。

**输出:**  V8 引擎实例，其中包含了基本的 JavaScript 内置对象（`Object`, `Function`, `Array`, `Number`, `Boolean`, `String`）及其构造函数、原型和方法。这些对象和方法已经准备好供 JavaScript 代码使用。

**用户常见的编程错误:**

这段代码初始化的是底层的对象和方法，与它直接相关的常见编程错误通常涉及对 JavaScript 内置对象的误解或不当使用：

1. **修改不可配置或不可写的属性:**  例如，尝试删除或修改某些内置对象的 `prototype` 属性，这些属性通常被设置为不可配置或不可写。

   ```javascript
   // 尝试修改 Function 的 prototype (通常会失败或产生意外行为)
   Function.prototype = {};
   ```

2. **错误地扩展内置对象的原型:** 虽然 JavaScript 允许扩展内置对象的原型，但过度或不当的扩展可能导致命名冲突和代码维护问题。

   ```javascript
   // 不推荐的用法
   Array.prototype.myCustomMethod = function() { ... };
   ```

3. **混淆原始值和包装对象:**  例如，尝试在原始值上直接调用原型方法，而忘记 JavaScript 会自动将其转换为包装对象。

   ```javascript
   const str = "hello";
   // 实际上 JavaScript 会将 str 转换为 new String("hello") 再调用 toUpperCase
   console.log(str.toUpperCase());
   ```

4. **误解 `this` 的指向:**  在某些通过 `call`, `apply`, `bind` 安装的内置方法中，`this` 的指向可能需要特别注意。

**功能归纳 (第 4 部分，共 11 部分):**

作为 V8 引擎初始化过程的第 4 部分，这段代码的核心功能是 **奠定 JavaScript 对象模型的基础**。它创建并配置了最基本的内置对象和类型，例如 `Object`, `Function`, `Array`, `Number`, `Boolean`, `String` 及其原型和核心方法。这些是后续更高级的 JavaScript 功能（例如类、Promise、模块等）构建的基础。可以认为，这一部分完成了 JavaScript 世界中 "基本粒子" 的创建和组装。后续的步骤将会在此基础上构建更复杂的结构和行为。

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共11部分，请归纳一下它的功能

"""
 map->set_native_context(*native_context());
    native_context()->set_function_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, CATCH_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_catch_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, WITH_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_with_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, DEBUG_EVALUATE_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_debug_evaluate_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, BLOCK_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_block_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, MODULE_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_module_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, AWAIT_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_await_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, SCRIPT_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_script_context_map(*map);

    map = factory->NewMapWithMetaMap(meta_map, EVAL_CONTEXT_TYPE,
                                     kVariableSizeSentinel);
    map->set_native_context(*native_context());
    native_context()->set_eval_context_map(*map);

    DirectHandle<ScriptContextTable> script_context_table =
        factory->NewScriptContextTable();
    native_context()->set_script_context_table(*script_context_table);
    InstallGlobalThisBinding();
  }

  {  // --- O b j e c t ---
    Handle<String> object_name = factory->Object_string();
    Handle<JSFunction> object_function = isolate_->object_function();
    JSObject::AddProperty(isolate_, global_object, object_name, object_function,
                          DONT_ENUM);

    SimpleInstallFunction(isolate_, object_function, "assign",
                          Builtin::kObjectAssign, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, object_function, "getOwnPropertyDescriptor",
                          Builtin::kObjectGetOwnPropertyDescriptor, 2,
                          kDontAdapt);
    SimpleInstallFunction(
        isolate_, object_function, "getOwnPropertyDescriptors",
        Builtin::kObjectGetOwnPropertyDescriptors, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, object_function, "getOwnPropertyNames",
                          Builtin::kObjectGetOwnPropertyNames, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "getOwnPropertySymbols",
                          Builtin::kObjectGetOwnPropertySymbols, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, object_function, "hasOwn",
                          Builtin::kObjectHasOwn, 2, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "is", Builtin::kObjectIs,
                          2, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "preventExtensions",
                          Builtin::kObjectPreventExtensions, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "seal",
                          Builtin::kObjectSeal, 1, kDontAdapt);

    SimpleInstallFunction(isolate_, object_function, "create",
                          Builtin::kObjectCreate, 2, kDontAdapt);

    SimpleInstallFunction(isolate_, object_function, "defineProperties",
                          Builtin::kObjectDefineProperties, 2, kAdapt);

    SimpleInstallFunction(isolate_, object_function, "defineProperty",
                          Builtin::kObjectDefineProperty, 3, kAdapt);

    SimpleInstallFunction(isolate_, object_function, "freeze",
                          Builtin::kObjectFreeze, 1, kDontAdapt);

    SimpleInstallFunction(isolate_, object_function, "getPrototypeOf",
                          Builtin::kObjectGetPrototypeOf, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "setPrototypeOf",
                          Builtin::kObjectSetPrototypeOf, 2, kAdapt);

    SimpleInstallFunction(isolate_, object_function, "isExtensible",
                          Builtin::kObjectIsExtensible, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "isFrozen",
                          Builtin::kObjectIsFrozen, 1, kDontAdapt);

    SimpleInstallFunction(isolate_, object_function, "isSealed",
                          Builtin::kObjectIsSealed, 1, kDontAdapt);

    SimpleInstallFunction(isolate_, object_function, "keys",
                          Builtin::kObjectKeys, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "entries",
                          Builtin::kObjectEntries, 1, kAdapt);
    SimpleInstallFunction(isolate_, object_function, "fromEntries",
                          Builtin::kObjectFromEntries, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, object_function, "values",
                          Builtin::kObjectValues, 1, kAdapt);

    SimpleInstallFunction(isolate_, object_function, "groupBy",
                          Builtin::kObjectGroupBy, 2, kAdapt);

    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "__defineGetter__", Builtin::kObjectDefineGetter, 2,
                          kAdapt);
    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "__defineSetter__", Builtin::kObjectDefineSetter, 2,
                          kAdapt);
    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "hasOwnProperty",
                          Builtin::kObjectPrototypeHasOwnProperty, 1, kAdapt);
    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "__lookupGetter__", Builtin::kObjectLookupGetter, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "__lookupSetter__", Builtin::kObjectLookupSetter, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "isPrototypeOf",
                          Builtin::kObjectPrototypeIsPrototypeOf, 1, kAdapt);
    SimpleInstallFunction(
        isolate_, isolate_->initial_object_prototype(), "propertyIsEnumerable",
        Builtin::kObjectPrototypePropertyIsEnumerable, 1, kDontAdapt);
    DirectHandle<JSFunction> object_to_string = SimpleInstallFunction(
        isolate_, isolate_->initial_object_prototype(), "toString",
        Builtin::kObjectPrototypeToString, 0, kAdapt);
    native_context()->set_object_to_string(*object_to_string);
    DirectHandle<JSFunction> object_value_of = SimpleInstallFunction(
        isolate_, isolate_->initial_object_prototype(), "valueOf",
        Builtin::kObjectPrototypeValueOf, 0, kAdapt);
    native_context()->set_object_value_of_function(*object_value_of);

    SimpleInstallGetterSetter(
        isolate_, isolate_->initial_object_prototype(), factory->proto_string(),
        Builtin::kObjectPrototypeGetProto, Builtin::kObjectPrototypeSetProto);

    SimpleInstallFunction(isolate_, isolate_->initial_object_prototype(),
                          "toLocaleString",
                          Builtin::kObjectPrototypeToLocaleString, 0, kAdapt);
  }

  Handle<JSObject> global(native_context()->global_object(), isolate());

  {  // --- F u n c t i o n ---
    Handle<JSFunction> prototype = empty_function;
    Handle<JSFunction> function_fun =
        InstallFunction(isolate_, global, "Function", JS_FUNCTION_TYPE,
                        JSFunction::kSizeWithPrototype, 0, prototype,
                        Builtin::kFunctionConstructor, 1, kDontAdapt);
    // Function instances are sloppy by default.
    function_fun->set_prototype_or_initial_map(*isolate_->sloppy_function_map(),
                                               kReleaseStore);
    InstallWithIntrinsicDefaultProto(isolate_, function_fun,
                                     Context::FUNCTION_FUNCTION_INDEX);
    native_context()->set_function_prototype(*prototype);

    // Setup the methods on the %FunctionPrototype%.
    JSObject::AddProperty(isolate_, prototype, factory->constructor_string(),
                          function_fun, DONT_ENUM);
    DirectHandle<JSFunction> function_prototype_apply =
        SimpleInstallFunction(isolate_, prototype, "apply",
                              Builtin::kFunctionPrototypeApply, 2, kDontAdapt);
    native_context()->set_function_prototype_apply(*function_prototype_apply);
    SimpleInstallFunction(isolate_, prototype, "bind",
                          Builtin::kFastFunctionPrototypeBind, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "call",
                          Builtin::kFunctionPrototypeCall, 1, kDontAdapt);
    DirectHandle<JSFunction> function_to_string = SimpleInstallFunction(
        isolate_, prototype, "toString", Builtin::kFunctionPrototypeToString, 0,
        kDontAdapt);
    native_context()->set_function_to_string(*function_to_string);

    // Install the @@hasInstance function.
    DirectHandle<JSFunction> has_instance = InstallFunctionAtSymbol(
        isolate_, prototype, factory->has_instance_symbol(),
        "[Symbol.hasInstance]", Builtin::kFunctionPrototypeHasInstance, 1,
        kAdapt,
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY));
    native_context()->set_function_has_instance(*has_instance);

    // Complete setting up function maps.
    {
      isolate_->sloppy_function_map()->SetConstructor(*function_fun);
      isolate_->sloppy_function_with_name_map()->SetConstructor(*function_fun);
      isolate_->sloppy_function_with_readonly_prototype_map()->SetConstructor(
          *function_fun);
      isolate_->sloppy_function_without_prototype_map()->SetConstructor(
          *function_fun);

      isolate_->strict_function_map()->SetConstructor(*function_fun);
      isolate_->strict_function_with_name_map()->SetConstructor(*function_fun);
      isolate_->strict_function_with_readonly_prototype_map()->SetConstructor(
          *function_fun);
      isolate_->strict_function_without_prototype_map()->SetConstructor(
          *function_fun);

      isolate_->class_function_map()->SetConstructor(*function_fun);
    }
  }

  DirectHandle<JSFunction> array_prototype_to_string_fun;
  {  // --- A r r a y ---
    // This seems a bit hackish, but we need to make sure Array.length is 1.
    int length = 1;
    Handle<JSFunction> array_function = InstallFunction(
        isolate_, global, "Array", JS_ARRAY_TYPE, JSArray::kHeaderSize, 0,
        isolate_->initial_object_prototype(), Builtin::kArrayConstructor,
        length, kDontAdapt);

    Handle<Map> initial_map(array_function->initial_map(), isolate());

    // This assert protects an optimization in
    // HGraphBuilder::JSArrayBuilder::EmitMapCode()
    DCHECK(initial_map->elements_kind() == GetInitialFastElementsKind());
    Map::EnsureDescriptorSlack(isolate_, initial_map, 1);

    PropertyAttributes attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);

    static_assert(JSArray::kLengthDescriptorIndex == 0);
    {  // Add length.
      Descriptor d = Descriptor::AccessorConstant(
          factory->length_string(), factory->array_length_accessor(), attribs);
      initial_map->AppendDescriptor(isolate(), &d);
    }

    InstallWithIntrinsicDefaultProto(isolate_, array_function,
                                     Context::ARRAY_FUNCTION_INDEX);
    InstallSpeciesGetter(isolate_, array_function);

    // Create the initial array map for Array.prototype which is required by
    // the used ArrayConstructorStub.
    // This is repeated after properly instantiating the Array.prototype.
    InitializeJSArrayMaps(isolate_, native_context(), initial_map);

    // Set up %ArrayPrototype%.
    // The %ArrayPrototype% has TERMINAL_FAST_ELEMENTS_KIND in order to ensure
    // that constant functions stay constant after turning prototype to setup
    // mode and back.
    Handle<JSArray> proto = factory->NewJSArray(0, TERMINAL_FAST_ELEMENTS_KIND,
                                                AllocationType::kOld);
    JSFunction::SetPrototype(array_function, proto);
    native_context()->set_initial_array_prototype(*proto);

    InitializeJSArrayMaps(isolate_, native_context(),
                          handle(array_function->initial_map(), isolate_));
    SimpleInstallFunction(isolate_, array_function, "isArray",
                          Builtin::kArrayIsArray, 1, kAdapt);
    SimpleInstallFunction(isolate_, array_function, "from", Builtin::kArrayFrom,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate(), array_function, "fromAsync",
                          Builtin::kArrayFromAsync, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, array_function, "of", Builtin::kArrayOf, 0,
                          kDontAdapt);
    SetConstructorInstanceType(isolate_, array_function,
                               JS_ARRAY_CONSTRUCTOR_TYPE);

    JSObject::AddProperty(isolate_, proto, factory->constructor_string(),
                          array_function, DONT_ENUM);

    SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, proto, "concat",
                          Builtin::kArrayPrototypeConcat, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "copyWithin",
                          Builtin::kArrayPrototypeCopyWithin, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "fill", Builtin::kArrayPrototypeFill,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "find", Builtin::kArrayPrototypeFind,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "findIndex",
                          Builtin::kArrayPrototypeFindIndex, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "findLast",
                          Builtin::kArrayPrototypeFindLast, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "findLastIndex",
                          Builtin::kArrayPrototypeFindLastIndex, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "lastIndexOf",
                          Builtin::kArrayPrototypeLastIndexOf, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "pop", Builtin::kArrayPrototypePop,
                          0, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "push", Builtin::kArrayPrototypePush,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "reverse",
                          Builtin::kArrayPrototypeReverse, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "shift",
                          Builtin::kArrayPrototypeShift, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "unshift",
                          Builtin::kArrayPrototypeUnshift, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "slice",
                          Builtin::kArrayPrototypeSlice, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "sort", Builtin::kArrayPrototypeSort,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "splice",
                          Builtin::kArrayPrototypeSplice, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "includes", Builtin::kArrayIncludes,
                          1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "indexOf", Builtin::kArrayIndexOf, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "join", Builtin::kArrayPrototypeJoin,
                          1, kDontAdapt);

    {  // Set up iterator-related properties.
      DirectHandle<JSFunction> keys = InstallFunctionWithBuiltinId(
          isolate_, proto, "keys", Builtin::kArrayPrototypeKeys, 0, kAdapt);
      native_context()->set_array_keys_iterator(*keys);

      DirectHandle<JSFunction> entries = InstallFunctionWithBuiltinId(
          isolate_, proto, "entries", Builtin::kArrayPrototypeEntries, 0,
          kAdapt);
      native_context()->set_array_entries_iterator(*entries);

      DirectHandle<JSFunction> values = InstallFunctionWithBuiltinId(
          isolate_, proto, "values", Builtin::kArrayPrototypeValues, 0, kAdapt);
      JSObject::AddProperty(isolate_, proto, factory->iterator_symbol(), values,
                            DONT_ENUM);
      native_context()->set_array_values_iterator(*values);
    }

    DirectHandle<JSFunction> for_each_fun = SimpleInstallFunction(
        isolate_, proto, "forEach", Builtin::kArrayForEach, 1, kDontAdapt);
    native_context()->set_array_for_each_iterator(*for_each_fun);
    SimpleInstallFunction(isolate_, proto, "filter", Builtin::kArrayFilter, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "flat", Builtin::kArrayPrototypeFlat,
                          0, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "flatMap",
                          Builtin::kArrayPrototypeFlatMap, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "map", Builtin::kArrayMap, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "every", Builtin::kArrayEvery, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "some", Builtin::kArraySome, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "reduce", Builtin::kArrayReduce, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "reduceRight",
                          Builtin::kArrayReduceRight, 1, kDontAdapt);

    SimpleInstallFunction(isolate_, proto, "toReversed",
                          Builtin::kArrayPrototypeToReversed, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "toSorted",
                          Builtin::kArrayPrototypeToSorted, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "toSpliced",
                          Builtin::kArrayPrototypeToSpliced, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, proto, "with", Builtin::kArrayPrototypeWith,
                          2, kAdapt);

    SimpleInstallFunction(isolate_, proto, "toLocaleString",
                          Builtin::kArrayPrototypeToLocaleString, 0,
                          kDontAdapt);
    array_prototype_to_string_fun =
        SimpleInstallFunction(isolate_, proto, "toString",
                              Builtin::kArrayPrototypeToString, 0, kDontAdapt);

    Handle<JSObject> unscopables = factory->NewJSObjectWithNullProto();
    InstallTrueValuedProperty(isolate_, unscopables, "at");
    InstallTrueValuedProperty(isolate_, unscopables, "copyWithin");
    InstallTrueValuedProperty(isolate_, unscopables, "entries");
    InstallTrueValuedProperty(isolate_, unscopables, "fill");
    InstallTrueValuedProperty(isolate_, unscopables, "find");
    InstallTrueValuedProperty(isolate_, unscopables, "findIndex");
    InstallTrueValuedProperty(isolate_, unscopables, "findLast");
    InstallTrueValuedProperty(isolate_, unscopables, "findLastIndex");
    InstallTrueValuedProperty(isolate_, unscopables, "flat");
    InstallTrueValuedProperty(isolate_, unscopables, "flatMap");
    InstallTrueValuedProperty(isolate_, unscopables, "includes");
    InstallTrueValuedProperty(isolate_, unscopables, "keys");
    InstallTrueValuedProperty(isolate_, unscopables, "toReversed");
    InstallTrueValuedProperty(isolate_, unscopables, "toSorted");
    InstallTrueValuedProperty(isolate_, unscopables, "toSpliced");
    InstallTrueValuedProperty(isolate_, unscopables, "values");

    JSObject::MigrateSlowToFast(unscopables, 0, "Bootstrapping");
    JSObject::AddProperty(
        isolate_, proto, factory->unscopables_symbol(), unscopables,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    DirectHandle<Map> map(proto->map(), isolate_);
    Map::SetShouldBeFastPrototypeMap(map, true, isolate_);
  }

  {  // --- A r r a y I t e r a t o r ---
    Handle<JSObject> iterator_prototype(
        native_context()->initial_iterator_prototype(), isolate());

    Handle<JSObject> array_iterator_prototype =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate(), array_iterator_prototype,
                                iterator_prototype);
    CHECK_NE(array_iterator_prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    array_iterator_prototype->map()->set_instance_type(
        JS_ARRAY_ITERATOR_PROTOTYPE_TYPE);

    InstallToStringTag(isolate_, array_iterator_prototype,
                       factory->ArrayIterator_string());

    InstallFunctionWithBuiltinId(isolate_, array_iterator_prototype, "next",
                                 Builtin::kArrayIteratorPrototypeNext, 0,
                                 kAdapt);

    DirectHandle<JSFunction> array_iterator_function = CreateFunction(
        isolate_, factory->ArrayIterator_string(), JS_ARRAY_ITERATOR_TYPE,
        JSArrayIterator::kHeaderSize, 0, array_iterator_prototype,
        Builtin::kIllegal, 0, kDontAdapt);
    array_iterator_function->shared()->set_native(false);

    native_context()->set_initial_array_iterator_map(
        array_iterator_function->initial_map());
    native_context()->set_initial_array_iterator_prototype(
        *array_iterator_prototype);
  }

  {  // --- N u m b e r ---
    Handle<JSFunction> number_fun =
        InstallFunction(isolate_, global, "Number", JS_PRIMITIVE_WRAPPER_TYPE,
                        JSPrimitiveWrapper::kHeaderSize, 0,
                        isolate_->initial_object_prototype(),
                        Builtin::kNumberConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, number_fun,
                                     Context::NUMBER_FUNCTION_INDEX);

    // Create the %NumberPrototype%
    Handle<JSPrimitiveWrapper> prototype = Cast<JSPrimitiveWrapper>(
        factory->NewJSObject(number_fun, AllocationType::kOld));
    prototype->set_value(Smi::zero());
    JSFunction::SetPrototype(number_fun, prototype);

    // Install the "constructor" property on the {prototype}.
    JSObject::AddProperty(isolate_, prototype, factory->constructor_string(),
                          number_fun, DONT_ENUM);

    // Install the Number.prototype methods.
    SimpleInstallFunction(isolate_, prototype, "toExponential",
                          Builtin::kNumberPrototypeToExponential, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toFixed",
                          Builtin::kNumberPrototypeToFixed, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toPrecision",
                          Builtin::kNumberPrototypeToPrecision, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toString",
                          Builtin::kNumberPrototypeToString, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "valueOf",
                          Builtin::kNumberPrototypeValueOf, 0, kAdapt);

    SimpleInstallFunction(isolate_, prototype, "toLocaleString",
                          Builtin::kNumberPrototypeToLocaleString, 0,
                          kDontAdapt);

    // Install the Number functions.
    SimpleInstallFunction(isolate_, number_fun, "isFinite",
                          Builtin::kNumberIsFinite, 1, kAdapt);
    SimpleInstallFunction(isolate_, number_fun, "isInteger",
                          Builtin::kNumberIsInteger, 1, kAdapt);
    SimpleInstallFunction(isolate_, number_fun, "isNaN", Builtin::kNumberIsNaN,
                          1, kAdapt);
    SimpleInstallFunction(isolate_, number_fun, "isSafeInteger",
                          Builtin::kNumberIsSafeInteger, 1, kAdapt);

    // Install Number.parseFloat and Global.parseFloat.
    DirectHandle<JSFunction> parse_float_fun =
        SimpleInstallFunction(isolate_, number_fun, "parseFloat",
                              Builtin::kNumberParseFloat, 1, kAdapt);
    JSObject::AddProperty(isolate_, global_object, "parseFloat",
                          parse_float_fun, DONT_ENUM);
    native_context()->set_global_parse_float_fun(*parse_float_fun);

    // Install Number.parseInt and Global.parseInt.
    DirectHandle<JSFunction> parse_int_fun = SimpleInstallFunction(
        isolate_, number_fun, "parseInt", Builtin::kNumberParseInt, 2, kAdapt);
    JSObject::AddProperty(isolate_, global_object, "parseInt", parse_int_fun,
                          DONT_ENUM);
    native_context()->set_global_parse_int_fun(*parse_int_fun);

    // Install Number constants
    const double kMaxValue = 1.7976931348623157e+308;
    const double kMinValue = 5e-324;
    const double kEPS = 2.220446049250313e-16;

    InstallConstant(isolate_, number_fun, "MAX_VALUE",
                    factory->NewNumber(kMaxValue));
    InstallConstant(isolate_, number_fun, "MIN_VALUE",
                    factory->NewNumber(kMinValue));
    InstallConstant(isolate_, number_fun, "NaN", factory->nan_value());
    InstallConstant(isolate_, number_fun, "NEGATIVE_INFINITY",
                    factory->NewNumber(-V8_INFINITY));
    InstallConstant(isolate_, number_fun, "POSITIVE_INFINITY",
                    factory->infinity_value());
    InstallConstant(isolate_, number_fun, "MAX_SAFE_INTEGER",
                    factory->NewNumber(kMaxSafeInteger));
    InstallConstant(isolate_, number_fun, "MIN_SAFE_INTEGER",
                    factory->NewNumber(kMinSafeInteger));
    InstallConstant(isolate_, number_fun, "EPSILON", factory->NewNumber(kEPS));

    InstallConstant(isolate_, global, "Infinity", factory->infinity_value());
    InstallConstant(isolate_, global, "NaN", factory->nan_value());
    InstallConstant(isolate_, global, "undefined", factory->undefined_value());
  }

  {  // --- B o o l e a n ---
    Handle<JSFunction> boolean_fun =
        InstallFunction(isolate_, global, "Boolean", JS_PRIMITIVE_WRAPPER_TYPE,
                        JSPrimitiveWrapper::kHeaderSize, 0,
                        isolate_->initial_object_prototype(),
                        Builtin::kBooleanConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, boolean_fun,
                                     Context::BOOLEAN_FUNCTION_INDEX);

    // Create the %BooleanPrototype%
    Handle<JSPrimitiveWrapper> prototype = Cast<JSPrimitiveWrapper>(
        factory->NewJSObject(boolean_fun, AllocationType::kOld));
    prototype->set_value(ReadOnlyRoots(isolate_).false_value());
    JSFunction::SetPrototype(boolean_fun, prototype);

    // Install the "constructor" property on the {prototype}.
    JSObject::AddProperty(isolate_, prototype, factory->constructor_string(),
                          boolean_fun, DONT_ENUM);

    // Install the Boolean.prototype methods.
    SimpleInstallFunction(isolate_, prototype, "toString",
                          Builtin::kBooleanPrototypeToString, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "valueOf",
                          Builtin::kBooleanPrototypeValueOf, 0, kAdapt);
  }

  {  // --- S t r i n g ---
    Handle<JSFunction> string_fun =
        InstallFunction(isolate_, global, "String", JS_PRIMITIVE_WRAPPER_TYPE,
                        JSPrimitiveWrapper::kHeaderSize, 0,
                        isolate_->initial_object_prototype(),
                        Builtin::kStringConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, string_fun,
                                     Context::STRING_FUNCTION_INDEX);

    DirectHandle<Map> string_map(
        native_context()->string_function()->initial_map(), isolate());
    string_map->set_elements_kind(FAST_STRING_WRAPPER_ELEMENTS);
    Map::EnsureDescriptorSlack(isolate_, string_map, 1);

    PropertyAttributes attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

    {  // Add length.
      Descriptor d = Descriptor::AccessorConstant(
          factory->length_string(), factory->string_length_accessor(), attribs);
      string_map->AppendDescriptor(isolate(), &d);
    }

    // Install the String.fromCharCode function.
    SimpleInstallFunction(isolate_, string_fun, "fromCharCode",
                          Builtin::kStringFromCharCode, 1, kDontAdapt);

    // Install the String.fromCodePoint function.
    SimpleInstallFunction(isolate_, string_fun, "fromCodePoint",
                          Builtin::kStringFromCodePoint, 1, kDontAdapt);

    // Install the String.raw function.
    SimpleInstallFunction(isolate_, string_fun, "raw", Builtin::kStringRaw, 1,
                          kDontAdapt);

    // Create the %StringPrototype%
    Handle<JSPrimitiveWrapper> prototype = Cast<JSPrimitiveWrapper>(
        factory->NewJSObject(string_fun, AllocationType::kOld));
    prototype->set_value(ReadOnlyRoots(isolate_).empty_string());
    JSFunction::SetPrototype(string_fun, prototype);
    native_context()->set_initial_string_prototype(*prototype);

    // Install the "constructor" property on the {prototype}.
    JSObject::AddProperty(isolate_, prototype, factory->constructor_string(),
                          string_fun, DONT_ENUM);

    // Install the String.prototype methods.
    SimpleInstallFunction(isolate_, prototype, "anchor",
                          Builtin::kStringPrototypeAnchor, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "at",
                          Builtin::kStringPrototypeAt, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "big",
                          Builtin::kStringPrototypeBig, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "blink",
                          Builtin::kStringPrototypeBlink, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "bold",
                          Builtin::kStringPrototypeBold, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "charAt",
                          Builtin::kStringPrototypeCharAt, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "charCodeAt",
                          Builtin::kStringPrototypeCharCodeAt, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "codePointAt",
                          Builtin::kStringPrototypeCodePointAt, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "concat",
                          Builtin::kStringPrototypeConcat, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "endsWith",
                          Builtin::kStringPrototypeEndsWith, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "fontcolor",
                          Builtin::kStringPrototypeFontcolor, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "fontsize",
                          Builtin::kStringPrototypeFontsize, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "fixed",
                          Builtin::kStringPrototypeFixed, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "includes",
                          Builtin::kStringPrototypeIncludes, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "indexOf",
                          Builtin::kStringPrototypeIndexOf, 1, kDontAdapt);
    SimpleInstallFunction(isolate(), prototype, "isWellFormed",
                          Builtin::kStringPrototypeIsWellFormed, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "italics",
                          Builtin::kStringPrototypeItalics, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "lastIndexOf",
                          Builtin::kStringPrototypeLastIndexOf, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "link",
                          Builtin::kStringPrototypeLink, 1, kDontAdapt);
#ifdef V8_INTL_SUPPORT
    SimpleInstallFunction(isolate_, prototype, "localeCompare",
                          Builtin::kStringPrototypeLocaleCompareIntl, 1,
                          kDontAdapt);
#else
    SimpleInstallFunction(isolate_, prototype, "localeCompare",
                          Builtin::kStringPrototypeLocaleCompare, 1, kAdapt);
#endif  // V8_INTL_SUP
"""


```