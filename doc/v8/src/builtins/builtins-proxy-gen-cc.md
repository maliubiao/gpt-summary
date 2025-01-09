Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to understand what this specific V8 source file (`builtins-proxy-gen.cc`) does. The prompt also asks about its relation to JavaScript, potential for Torque implementation, common errors, and provides examples.

2. **Initial Code Scan (Keywords and Structure):**
   - Immediately notice the `#include` directives. These point to other V8 internal files, hinting at dependencies and areas of focus (builtins, codegen, objects, etc.).
   - The `namespace v8 { namespace internal { ... } }` structure confirms this is internal V8 code.
   - Look for class definitions: `ProxiesCodeStubAssembler`. The name strongly suggests it's responsible for generating code related to proxies.
   - Spot function definitions within the class. These will be the core functionalities. Functions like `AllocateProxy`, `CreateProxyRevokeFunctionContext`, `CallProxy`, `ConstructProxy`, `CheckGetSetTrapResult`, `CheckHasTrapResult`, `CheckDeleteTrapResult` are strong indicators of proxy-related operations.
   - Notice the use of `TNode<>`, `TVARIABLE`, `Label`, `Goto`, `Branch`, `BIND`. These are characteristic of V8's CodeStubAssembler (CSA), a low-level code generation framework.
   - See mentions of `JSProxy`, `JSReceiver`, `Context`, `Map`, `JSArray`, which are fundamental V8 object types.
   - Keywords like `ThrowTypeError`, `CallRuntime`, `TailCallBuiltin` indicate interaction with the runtime and other built-in functionalities.

3. **Function-by-Function Analysis:** Go through each function and try to understand its purpose based on its name and the operations it performs.

   - **`AllocateProxy`:**  This clearly deals with creating `JSProxy` objects. The logic differentiates between callable, constructor, and plain object targets, leading to the selection of different `Map` objects for the proxy. This reflects the different behaviors of proxies based on their target.
   - **`CreateProxyRevokeFunctionContext` and `AllocateProxyRevokeFunction`:** These functions create a special context and function for revoking a proxy. The "revoke" aspect is a key feature of proxies.
   - **`CallProxy`:**  This function handles the `[[Call]]` internal method of a proxy. It involves getting the "apply" trap from the handler, calling it, or falling back to the target's `[[Call]]` method. The check for a revoked handler is also crucial.
   - **`ConstructProxy`:**  Similar to `CallProxy`, but handles the `[[Construct]]` operation. It gets the "construct" trap and calls it, or falls back to the target's constructor. It also checks if the constructed object is indeed an object.
   - **`CheckGetSetTrapResult`, `CheckHasTrapResult`, `CheckDeleteTrapResult`:** These are validation functions. They ensure that the results of the proxy's trap methods adhere to certain invariants and don't violate the properties of the underlying target object (e.g., trying to set a non-configurable property through a proxy).

4. **Identify Core Functionality:**  Based on the function analysis, it's clear that `builtins-proxy-gen.cc` is responsible for the core mechanics of how proxies work in V8. This includes:
   - Creating proxy objects.
   - Handling function calls (`apply` trap).
   - Handling constructor calls (`construct` trap).
   - Validating the results of proxy trap methods to maintain consistency and prevent unexpected behavior.
   - Managing proxy revocation.

5. **Torque Consideration:** The prompt explicitly asks about Torque. The comment about `.tq` files is a direct hint. While this specific file is `.cc`, the code *uses* CodeStubAssembler, which is often a precursor or alternative to Torque. The prompt intends for you to understand that *similar* proxy functionality could be implemented in Torque.

6. **JavaScript Relationship and Examples:** Since proxies are a JavaScript language feature, the C++ code directly implements their behavior. To illustrate this, map the C++ functions to their JavaScript counterparts:
   - `AllocateProxy` relates to `new Proxy(target, handler)`.
   - `CallProxy` relates to calling a proxy like a function: `proxy(...)`.
   - `ConstructProxy` relates to using a proxy with `new`: `new proxy(...)`.
   - The "check" functions relate to the invariants that JavaScript enforces when using proxy traps (e.g., the `get`, `set`, `has`, `deleteProperty` traps). Provide concrete JavaScript examples showing how these traps work and how errors occur when invariants are violated.

7. **Code Logic Reasoning (Assumptions and Outputs):**  Focus on a specific function, like `AllocateProxy`. Provide different scenarios for `target` (callable, constructor, plain object) and explain how the code branches and selects the appropriate `Map`.

8. **Common Programming Errors:** Think about how developers might misuse proxies, leading to errors. The most common scenarios involve:
   - Forgetting to handle traps, leading to default behavior.
   - Implementing traps incorrectly, violating invariants, and causing TypeErrors.
   - Not understanding the implications of proxy revocation.

9. **Structure and Refine:** Organize the findings into clear sections based on the prompt's requirements (functionality, Torque, JavaScript examples, logic reasoning, errors). Use clear and concise language. Provide specific code snippets for both C++ and JavaScript.

**Self-Correction/Refinement During the Process:**

- **Initial thought:**  Might focus too much on the low-level details of CSA.
- **Correction:** Realize the prompt asks for a high-level understanding of the *functionality*. While mentioning CSA is important, explaining *what* the code does is more crucial than *how* it does it at the assembly level.
- **Initial thought:** Might not immediately connect the C++ code to JavaScript concepts.
- **Correction:** Explicitly draw the parallels between the C++ functions and the corresponding JavaScript proxy behaviors and traps. This is key to answering the prompt effectively.
- **Initial thought:**  Might provide overly simplistic JavaScript examples.
- **Correction:**  Create more illustrative examples that showcase the interaction between the proxy, the handler, and the target, and demonstrate potential errors.

By following this structured approach, combining code analysis with an understanding of JavaScript proxy semantics, and iteratively refining the explanation, we can arrive at a comprehensive and accurate answer to the prompt.
好的，让我们来分析一下 `v8/src/builtins/builtins-proxy-gen.cc` 这个文件的功能。

**文件功能概述**

`v8/src/builtins/builtins-proxy-gen.cc` 文件是 V8 JavaScript 引擎中负责生成与 `Proxy` 对象相关的内置函数的代码。它使用 CodeStubAssembler (CSA) 这个 V8 内部的汇编器框架来高效地实现这些内置函数。  简单来说，这个文件定义了当 JavaScript 代码与 `Proxy` 对象进行交互时，V8 引擎实际执行的底层操作。

**具体功能分解**

1. **代理对象的分配 (`AllocateProxy`)**
   - 此函数负责在堆上分配一个新的 `JSProxy` 对象。
   - 它根据目标对象 (`target`) 的类型（是否可调用、是否是构造函数）选择合适的 `Map` 对象（用于描述对象的结构）。
   - 初始化代理对象的内部槽位，包括目标对象 (`target`) 和处理程序对象 (`handler`)。

2. **创建代理撤销函数上下文和函数 (`CreateProxyRevokeFunctionContext`, `AllocateProxyRevokeFunction`)**
   - 当创建一个 `Proxy` 对象时，会同时创建一个与其关联的撤销函数。
   - 这部分代码负责创建这个撤销函数所需的上下文和一个实际的函数对象。
   - 撤销函数用于使代理对象失效。

3. **处理 `Proxy` 对象的函数调用 (`TF_BUILTIN(CallProxy, ProxiesCodeStubAssembler)`)**
   - 当 JavaScript 代码调用一个 `Proxy` 对象时（例如 `proxy(...)`），这个内置函数会被执行。
   - 它首先获取代理对象的处理程序 (`handler`) 和目标对象 (`target`)。
   - **关键逻辑：**
     - 尝试从处理程序对象中获取 `apply` 陷阱（trap）方法。
     - 如果 `apply` 陷阱存在，则调用该陷阱，并将目标对象、接收者（`this`）、以及调用参数传递给它。
     - 如果 `apply` 陷阱不存在，则直接调用目标对象。
   - 如果处理程序已被撤销（为 `null`），则抛出 `TypeError`。

4. **处理 `Proxy` 对象的构造函数调用 (`TF_BUILTIN(ConstructProxy, ProxiesCodeStubAssembler)`)**
   - 当 JavaScript 代码使用 `new` 关键字调用一个 `Proxy` 对象时（例如 `new proxy(...)`），这个内置函数会被执行。
   - 类似 `CallProxy`，它获取处理程序和目标对象。
   - **关键逻辑：**
     - 尝试从处理程序对象中获取 `construct` 陷阱方法。
     - 如果 `construct` 陷阱存在，则调用该陷阱，并将目标对象、构造参数、以及 `new.target` 传递给它。
     - 如果 `construct` 陷阱不存在，则直接使用目标对象作为构造函数进行构造。
   - 对 `construct` 陷阱的返回值进行类型检查，如果不是对象则抛出 `TypeError`。
   - 如果处理程序已被撤销，则抛出 `TypeError`。

5. **检查代理陷阱的结果 (`CheckGetSetTrapResult`, `CheckHasTrapResult`, `CheckDeleteTrapResult`)**
   - 这些函数用于验证代理的 `get`, `set`, `has`, `deleteProperty` 等陷阱的返回值是否符合规范，以确保代理的行为不会违反底层目标对象的属性特征。
   - 例如，如果目标对象的一个属性是不可配置的，那么代理的 `get` 陷阱返回的值必须与该属性的原始值相同。

**关于 Torque**

根据您的描述，如果 `v8/src/builtins/builtins-proxy-gen.cc` 以 `.tq` 结尾，那么它会是一个 V8 Torque 源代码文件。Torque 是一种 V8 开发的领域特定语言，用于更安全、更易于维护地编写内置函数。

当前这个文件是 `.cc` 结尾，意味着它是使用 C++ 和 CodeStubAssembler 编写的。不过，V8 正在逐步将内置函数迁移到 Torque，所以未来可能会有对应的 `.tq` 版本。

**与 JavaScript 的关系和示例**

`v8/src/builtins/builtins-proxy-gen.cc` 中的代码直接实现了 JavaScript `Proxy` 对象的行为。以下是一些 JavaScript 示例，展示了这些 C++ 代码所实现的功能：

```javascript
// 对应 AllocateProxy：创建一个简单的 Proxy
const target = {};
const handler = {};
const proxy = new Proxy(target, handler);

// 对应 CallProxy：调用 Proxy 对象
const callableTarget = () => 'Hello from target';
const callHandler = {
  apply: function(target, thisArg, argumentsList) {
    console.log('apply trap called');
    return target.apply(thisArg, argumentsList);
  }
};
const callableProxy = new Proxy(callableTarget, callHandler);
callableProxy(); // 输出 "apply trap called" 和 "Hello from target"

// 对应 ConstructProxy：使用 new 调用 Proxy 对象
class MyClass {
  constructor(value) {
    this.value = value;
  }
}
const constructHandler = {
  construct: function(target, argArray, newTarget) {
    console.log('construct trap called');
    return new target(...argArray);
  }
};
const constructProxy = new Proxy(MyClass, constructHandler);
const instance = new constructProxy(10); // 输出 "construct trap called"
console.log(instance.value); // 输出 10

// 对应 CheckGetSetTrapResult：get 陷阱的校验
const nonConfigurableTarget = {};
Object.defineProperty(nonConfigurableTarget, 'prop', {
  value: 'original value',
  configurable: false
});
const getHandler = {
  get: function(target, prop, receiver) {
    console.log('get trap called');
    return 'modified value'; // 违反了不可配置属性的约束
  }
};
const getProxy = new Proxy(nonConfigurableTarget, getHandler);
try {
  getProxy.prop; // 可能会抛出 TypeError，具体取决于 V8 的优化
} catch (e) {
  console.error(e); // 例如：TypeError: 'get' on proxy: property 'prop' is a non-configurable data property; trap returned a different value
}
```

**代码逻辑推理：`AllocateProxy` 示例**

**假设输入：**

- `context`: 当前的 JavaScript 执行上下文。
- `target`: 一个 JavaScript 对象，例如 `{ a: 1 }` 或一个函数 `() => {}`。
- `handler`: 一个 JavaScript 对象，例如 `{ get() { ... } }`。

**输出：**

- 一个指向新分配的 `JSProxy` 对象的指针。

**逻辑推理：**

1. 代码首先加载 NativeContext。
2. 使用 `IsCallable(target)` 检查 `target` 是否可调用。
3. **如果 `target` 可调用：**
   - 使用 `IsConstructor(target)` 进一步检查是否是构造函数。
   - **如果是构造函数：** 从 NativeContext 加载 `PROXY_CONSTRUCTOR_MAP_INDEX` 对应的 Map 对象。
   - **如果不是构造函数：** 从 NativeContext 加载 `PROXY_CALLABLE_MAP_INDEX` 对应的 Map 对象。
4. **如果 `target` 不可调用：** 从 NativeContext 加载 `PROXY_MAP_INDEX` 对应的 Map 对象。
5. 使用选定的 Map 对象分配 `JSProxy` 对象。
6. 初始化代理对象的内部字段：
   - 设置一个空的属性字典。
   - 存储 `target` 和 `handler`。

**用户常见的编程错误**

1. **忘记处理所有相关的陷阱：**  如果处理程序没有定义某个陷阱（例如 `get`），则会回退到目标对象的默认行为，这可能不是预期的。

   ```javascript
   const target = { name: 'old' };
   const handler = {}; // 缺少 get 陷阱
   const proxy = new Proxy(target, handler);
   console.log(proxy.name); // 输出 "old"，可能期望通过代理修改行为
   ```

2. **陷阱的返回值违反不变性：**  如上面 `CheckGetSetTrapResult` 的例子所示，代理陷阱的返回值必须遵守目标对象属性的特性（例如，不可配置属性的值不能被更改）。

   ```javascript
   const target = {};
   Object.defineProperty(target, 'constant', { value: 42, configurable: false });
   const handler = {
     get(target, prop) {
       return 100; // 尝试返回与不可配置属性不同的值
     }
   };
   const proxy = new Proxy(target, handler);
   try {
     console.log(proxy.constant); // 可能会抛出 TypeError
   } catch (e) {
     console.error(e);
   }
   ```

3. **在 `construct` 陷阱中返回非对象：**  `construct` 陷阱必须返回一个对象，否则会抛出 `TypeError`。

   ```javascript
   const target = function() {};
   const handler = {
     construct(target, args) {
       return 10; // 返回一个数字，而不是对象
     }
   };
   const proxy = new Proxy(target, handler);
   try {
     new proxy(); // 抛出 TypeError
   } catch (e) {
     console.error(e);
   }
   ```

4. **在已撤销的代理上操作：**  一旦代理被撤销，任何对其进行的操作都会抛出 `TypeError`。

   ```javascript
   const target = {};
   const handler = {};
   const { proxy, revoke } = Proxy.revocable(target, handler);
   revoke();
   try {
     proxy.someProp; // 抛出 TypeError
   } catch (e) {
     console.error(e);
   }
   ```

总而言之，`v8/src/builtins/builtins-proxy-gen.cc` 是 V8 引擎中实现 JavaScript `Proxy` 对象核心功能的关键文件。它使用底层的 CSA 框架来高效地处理代理对象的创建、方法调用、构造函数调用以及陷阱结果的验证，确保了 `Proxy` 对象的行为符合 JavaScript 规范。理解这个文件有助于深入了解 V8 引擎如何执行 JavaScript 代码中与 `Proxy` 相关的操作。

Prompt: 
```
这是目录为v8/src/builtins/builtins-proxy-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-proxy-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-proxy-gen.h"

#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins-utils.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/common/globals.h"
#include "src/logging/counters.h"
#include "src/objects/js-proxy.h"
#include "src/objects/objects-inl.h"
#include "torque-generated/exported-macros-assembler.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

TNode<JSProxy> ProxiesCodeStubAssembler::AllocateProxy(
    TNode<Context> context, TNode<JSReceiver> target,
    TNode<JSReceiver> handler) {
  TVARIABLE(Map, map);

  Label callable_target(this), constructor_target(this), none_target(this),
      create_proxy(this);

  TNode<NativeContext> nativeContext = LoadNativeContext(context);

  Branch(IsCallable(target), &callable_target, &none_target);

  BIND(&callable_target);
  {
    // Every object that is a constructor is implicitly callable
    // so it's okay to nest this check here
    GotoIf(IsConstructor(target), &constructor_target);
    map = CAST(
        LoadContextElement(nativeContext, Context::PROXY_CALLABLE_MAP_INDEX));
    Goto(&create_proxy);
  }
  BIND(&constructor_target);
  {
    map = CAST(LoadContextElement(nativeContext,
                                  Context::PROXY_CONSTRUCTOR_MAP_INDEX));
    Goto(&create_proxy);
  }
  BIND(&none_target);
  {
    map = CAST(LoadContextElement(nativeContext, Context::PROXY_MAP_INDEX));
    Goto(&create_proxy);
  }

  BIND(&create_proxy);
  TNode<HeapObject> proxy = Allocate(JSProxy::kSize);
  StoreMapNoWriteBarrier(proxy, map.value());
  RootIndex empty_dict = V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL
                             ? RootIndex::kEmptySwissPropertyDictionary
                             : RootIndex::kEmptyPropertyDictionary;
  StoreObjectFieldRoot(proxy, JSProxy::kPropertiesOrHashOffset, empty_dict);
  StoreObjectFieldNoWriteBarrier(proxy, JSProxy::kTargetOffset, target);
  StoreObjectFieldNoWriteBarrier(proxy, JSProxy::kHandlerOffset, handler);

  return CAST(proxy);
}

TNode<Context> ProxiesCodeStubAssembler::CreateProxyRevokeFunctionContext(
    TNode<JSProxy> proxy, TNode<NativeContext> native_context) {
  const TNode<Context> context = AllocateSyntheticFunctionContext(
      native_context, ProxyRevokeFunctionContextSlot::kProxyContextLength);
  StoreContextElementNoWriteBarrier(
      context, ProxyRevokeFunctionContextSlot::kProxySlot, proxy);
  return context;
}

TNode<JSFunction> ProxiesCodeStubAssembler::AllocateProxyRevokeFunction(
    TNode<Context> context, TNode<JSProxy> proxy) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Context> proxy_context =
      CreateProxyRevokeFunctionContext(proxy, native_context);
  return AllocateRootFunctionWithContext(RootIndex::kProxyRevokeSharedFun,
                                         proxy_context, native_context);
}

TF_BUILTIN(CallProxy, ProxiesCodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  TNode<IntPtrT> argc_ptr = ChangeInt32ToIntPtr(argc);
  auto proxy = Parameter<JSProxy>(Descriptor::kFunction);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, IsCallable(proxy));

  PerformStackCheck(context);

  Label throw_proxy_handler_revoked(this, Label::kDeferred),
      trap_undefined(this);

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  TNode<HeapObject> handler =
      CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));

  // 2. If handler is null, throw a TypeError exception.
  CSA_DCHECK(this, IsNullOrJSReceiver(handler));
  GotoIfNot(JSAnyIsNotPrimitive(handler), &throw_proxy_handler_revoked);

  // 3. Assert: Type(handler) is Object.
  CSA_DCHECK(this, IsJSReceiver(handler));

  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  TNode<Object> target = LoadObjectField(proxy, JSProxy::kTargetOffset);

  // 5. Let trap be ? GetMethod(handler, "apply").
  // 6. If trap is undefined, then
  Handle<Name> trap_name = factory()->apply_string();
  TNode<Object> trap = GetMethod(context, handler, trap_name, &trap_undefined);

  CodeStubArguments args(this, argc_ptr);
  TNode<Object> receiver = args.GetReceiver();

  // 7. Let argArray be CreateArrayFromList(argumentsList).
  TNode<JSArray> array = EmitFastNewAllArguments(
      UncheckedCast<Context>(context),
      UncheckedCast<RawPtrT>(LoadFramePointer()),
      UncheckedCast<IntPtrT>(args.GetLengthWithoutReceiver()));

  // 8. Return Call(trap, handler, «target, thisArgument, argArray»).
  TNode<Object> result = Call(context, trap, handler, target, receiver, array);
  args.PopAndReturn(result);

  BIND(&trap_undefined);
  {
    // 6.a. Return Call(target, thisArgument, argumentsList).
    TailCallBuiltin(Builtins::Call(), context, target, argc);
  }

  BIND(&throw_proxy_handler_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "apply"); }
}

TF_BUILTIN(ConstructProxy, ProxiesCodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  TNode<IntPtrT> argc_ptr = ChangeInt32ToIntPtr(argc);
  auto proxy = Parameter<JSProxy>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, IsCallable(proxy));

  PerformStackCheck(context);

  Label throw_proxy_handler_revoked(this, Label::kDeferred),
      trap_undefined(this), not_an_object(this, Label::kDeferred);

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  TNode<HeapObject> handler =
      CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));

  // 2. If handler is null, throw a TypeError exception.
  CSA_DCHECK(this, IsNullOrJSReceiver(handler));
  GotoIfNot(JSAnyIsNotPrimitive(handler), &throw_proxy_handler_revoked);

  // 3. Assert: Type(handler) is Object.
  CSA_DCHECK(this, IsJSReceiver(handler));

  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  TNode<Object> target = LoadObjectField(proxy, JSProxy::kTargetOffset);

  // 5. Let trap be ? GetMethod(handler, "construct").
  // 6. If trap is undefined, then
  Handle<Name> trap_name = factory()->construct_string();
  TNode<Object> trap = GetMethod(context, handler, trap_name, &trap_undefined);

  CodeStubArguments args(this, argc_ptr);

  // 7. Let argArray be CreateArrayFromList(argumentsList).
  TNode<JSArray> array = EmitFastNewAllArguments(
      UncheckedCast<Context>(context),
      UncheckedCast<RawPtrT>(LoadFramePointer()),
      UncheckedCast<IntPtrT>(args.GetLengthWithoutReceiver()));

  // 8. Let newObj be ? Call(trap, handler, « target, argArray, newTarget »).
  TNode<Object> new_obj =
      Call(context, trap, handler, target, array, new_target);

  // 9. If Type(newObj) is not Object, throw a TypeError exception.
  GotoIf(TaggedIsSmi(new_obj), &not_an_object);
  GotoIfNot(JSAnyIsNotPrimitive(CAST(new_obj)), &not_an_object);

  // 10. Return newObj.
  args.PopAndReturn(new_obj);

  BIND(&not_an_object);
  {
    ThrowTypeError(context, MessageTemplate::kProxyConstructNonObject, new_obj);
  }

  BIND(&trap_undefined);
  {
    // 6.a. Assert: target has a [[Construct]] internal method.
    CSA_DCHECK(this, IsConstructor(CAST(target)));

    // 6.b. Return ? Construct(target, argumentsList, newTarget).
    TailCallBuiltin(Builtin::kConstruct, context, target, new_target, argc);
  }

  BIND(&throw_proxy_handler_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "construct"); }
}

void ProxiesCodeStubAssembler::CheckGetSetTrapResult(
    TNode<Context> context, TNode<JSReceiver> target, TNode<JSProxy> proxy,
    TNode<Name> name, TNode<Object> trap_result,
    JSProxy::AccessKind access_kind) {
  // TODO(mslekova): Think of a better name for the trap_result param.
  TNode<Map> map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this), check_in_runtime(this, Label::kDeferred),
      check_passed(this);

  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  BIND(&if_found_value);
  {
    Label throw_non_configurable_data(this, Label::kDeferred),
        throw_non_configurable_accessor(this, Label::kDeferred),
        check_accessor(this), check_data(this);

    // If targetDesc is not undefined and targetDesc.[[Configurable]] is
    // false, then:
    GotoIfNot(IsSetWord32(var_details.value(),
                          PropertyDetails::kAttributesDontDeleteMask),
              &check_passed);

    // If IsDataDescriptor(targetDesc) is true and
    // targetDesc.[[Writable]] is false, then:
    BranchIfAccessorPair(var_raw_value.value(), &check_accessor, &check_data);

    BIND(&check_data);
    {
      TNode<BoolT> read_only = IsSetWord32(
          var_details.value(), PropertyDetails::kAttributesReadOnlyMask);
      GotoIfNot(read_only, &check_passed);

      // If SameValue(trapResult, targetDesc.[[Value]]) is false,
      // throw a TypeError exception.
      BranchIfSameValue(trap_result, var_value.value(), &check_passed,
                        &throw_non_configurable_data);
    }

    BIND(&check_accessor);
    {
      TNode<HeapObject> accessor_pair = CAST(var_raw_value.value());

      if (access_kind == JSProxy::kGet) {
        Label continue_check(this, Label::kDeferred);
        // 10.b. If IsAccessorDescriptor(targetDesc) is true and
        // targetDesc.[[Get]] is undefined, then:
        TNode<Object> getter =
            LoadObjectField(accessor_pair, AccessorPair::kGetterOffset);
        // Here we check for null as well because if the getter was never
        // defined it's set as null.
        GotoIf(IsUndefined(getter), &continue_check);
        GotoIf(IsNull(getter), &continue_check);
        Goto(&check_passed);

        // 10.b.i. If trapResult is not undefined, throw a TypeError exception.
        BIND(&continue_check);
        GotoIfNot(IsUndefined(trap_result), &throw_non_configurable_accessor);
      } else {
        // 11.b.i. If targetDesc.[[Set]] is undefined, throw a TypeError
        // exception.
        TNode<Object> setter =
            LoadObjectField(accessor_pair, AccessorPair::kSetterOffset);
        GotoIf(IsUndefined(setter), &throw_non_configurable_accessor);
        GotoIf(IsNull(setter), &throw_non_configurable_accessor);
      }
      Goto(&check_passed);
    }

    BIND(&throw_non_configurable_data);
    {
      if (access_kind == JSProxy::kGet) {
        ThrowTypeError(context, MessageTemplate::kProxyGetNonConfigurableData,
                       name, var_value.value(), trap_result);
      } else {
        ThrowTypeError(context, MessageTemplate::kProxySetFrozenData, name);
      }
    }

    BIND(&throw_non_configurable_accessor);
    {
      if (access_kind == JSProxy::kGet) {
        ThrowTypeError(context,
                       MessageTemplate::kProxyGetNonConfigurableAccessor, name,
                       trap_result);
      } else {
        ThrowTypeError(context, MessageTemplate::kProxySetFrozenAccessor, name);
      }
    }

    BIND(&check_in_runtime);
    {
      CallRuntime(Runtime::kCheckProxyGetSetTrapResult, context, name, target,
                  trap_result, SmiConstant(access_kind));
      Goto(&check_passed);
    }

    BIND(&check_passed);
  }
}

void ProxiesCodeStubAssembler::CheckHasTrapResult(TNode<Context> context,
                                                  TNode<JSReceiver> target,
                                                  TNode<JSProxy> proxy,
                                                  TNode<Name> name) {
  TNode<Map> target_map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this, Label::kDeferred),
      throw_non_configurable(this, Label::kDeferred),
      throw_non_extensible(this, Label::kDeferred), check_passed(this),
      check_in_runtime(this, Label::kDeferred);

  // 9.a. Let targetDesc be ? target.[[GetOwnProperty]](P).
  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, target_map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  // 9.b. If targetDesc is not undefined, then (see 9.b.i. below).
  BIND(&if_found_value);
  {
    // 9.b.i. If targetDesc.[[Configurable]] is false, throw a TypeError
    // exception.
    TNode<BoolT> non_configurable = IsSetWord32(
        var_details.value(), PropertyDetails::kAttributesDontDeleteMask);
    GotoIf(non_configurable, &throw_non_configurable);

    // 9.b.ii. Let extensibleTarget be ? IsExtensible(target).
    TNode<BoolT> target_extensible = IsExtensibleMap(target_map);

    // 9.b.iii. If extensibleTarget is false, throw a TypeError exception.
    GotoIfNot(target_extensible, &throw_non_extensible);
    Goto(&check_passed);
  }

  BIND(&throw_non_configurable);
  { ThrowTypeError(context, MessageTemplate::kProxyHasNonConfigurable, name); }

  BIND(&throw_non_extensible);
  { ThrowTypeError(context, MessageTemplate::kProxyHasNonExtensible, name); }

  BIND(&check_in_runtime);
  {
    CallRuntime(Runtime::kCheckProxyHasTrapResult, context, name, target);
    Goto(&check_passed);
  }

  BIND(&check_passed);
}

void ProxiesCodeStubAssembler::CheckDeleteTrapResult(TNode<Context> context,
                                                     TNode<JSReceiver> target,
                                                     TNode<JSProxy> proxy,
                                                     TNode<Name> name) {
  TNode<Map> target_map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this, Label::kDeferred),
      throw_non_configurable(this, Label::kDeferred),
      throw_non_extensible(this, Label::kDeferred), check_passed(this),
      check_in_runtime(this, Label::kDeferred);

  // 10. Let targetDesc be ? target.[[GetOwnProperty]](P).
  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, target_map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  // 11. If targetDesc is undefined, return true.
  BIND(&if_found_value);
  {
    // 12. If targetDesc.[[Configurable]] is false, throw a TypeError exception.
    TNode<BoolT> non_configurable = IsSetWord32(
        var_details.value(), PropertyDetails::kAttributesDontDeleteMask);
    GotoIf(non_configurable, &throw_non_configurable);

    // 13. Let extensibleTarget be ? IsExtensible(target).
    TNode<BoolT> target_extensible = IsExtensibleMap(target_map);

    // 14. If extensibleTarget is false, throw a TypeError exception.
    GotoIfNot(target_extensible, &throw_non_extensible);
    Goto(&check_passed);
  }

  BIND(&throw_non_configurable);
  {
    ThrowTypeError(context,
                   MessageTemplate::kProxyDeletePropertyNonConfigurable, name);
  }

  BIND(&throw_non_extensible);
  {
    ThrowTypeError(context, MessageTemplate::kProxyDeletePropertyNonExtensible,
                   name);
  }

  BIND(&check_in_runtime);
  {
    CallRuntime(Runtime::kCheckProxyDeleteTrapResult, context, name, target);
    Goto(&check_passed);
  }

  BIND(&check_passed);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```