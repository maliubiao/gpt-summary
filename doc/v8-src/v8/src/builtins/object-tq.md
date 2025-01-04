Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality, connections to JavaScript, examples, logic inference, and common programming errors.

2. **Identify the Core Subject:** The file path `v8/src/builtins/object.tq` immediately suggests it's related to the `Object` built-in in JavaScript. The `#include 'src/builtins/builtins-object-gen.h'` further confirms this.

3. **High-Level Scan for Keywords:** Look for familiar JavaScript `Object` methods and concepts. Keywords like `isExtensible`, `preventExtensions`, `getPrototypeOf`, `setPrototypeOf`, `create`, `toString`, `valueOf`, `toLocaleString`, and terms like "property descriptor" stand out. This gives an initial roadmap of the file's contents.

4. **Group Related Code Blocks:**  Notice the structure of the file. There are sections for:
    * `runtime` extern declarations (interfacing with lower-level runtime functions).
    * Torque macros (`transitioning macro`). These are essentially inlined functions within the Torque code.
    * Torque builtins (`transitioning builtin`). These are more substantial functions written in Torque.
    * JavaScript builtins (`transitioning javascript builtin`). These are the entry points called directly from JavaScript.
    * Constant declarations (for property descriptor offsets).
    * `ToPropertyDescriptor` related logic.
    * `FromPropertyDescriptor` related logic.

5. **Analyze Each Section (and individual functions/macros):**

    * **`runtime` externs:** These indicate calls to lower-level C++ runtime functions. While we don't have the C++ code here, the names are descriptive (`ObjectIsExtensible`, `JSReceiverPreventExtensionsThrow`, etc.). They handle the core logic.

    * **Torque Macros:** These often act as wrappers or implement specific behavior on top of the `runtime` functions, potentially handling `JSProxy` cases separately. For instance, `ObjectIsExtensibleImpl` checks if the object is a `JSProxy` and calls `proxy::ProxyIsExtensible` if it is; otherwise, it calls the runtime function.

    * **Torque Builtins:** `CreateObjectWithoutProperties` implements a specialized object creation, optimizing for cases where properties are not immediately added. The `typeswitch` statement is key to understanding its different code paths depending on the `prototype`.

    * **JavaScript Builtins:** These are the main entry points that JavaScript code directly interacts with (e.g., `Object.isExtensible`). They often call the corresponding Torque macros or builtins. Notice the direct mapping between JavaScript methods and these builtins.

    * **Property Descriptor Constants:** These define offsets used to access fields within property descriptor objects in memory. This is internal V8 detail but relevant to the `ToPropertyDescriptor` macro.

    * **`ToPropertyDescriptor`:** This macro is crucial for understanding how JavaScript objects are converted into property descriptor objects, which represent the attributes of a property (value, writable, enumerable, configurable, getter, setter). The logic handles both pre-existing descriptor objects (`DATA_PROPERTY_DESCRIPTOR_MAP_INDEX`, `ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX`) and general objects by inspecting their properties.

    * **`FromPropertyDescriptor`:** This seems to be an external reference, indicating the reverse process (creating a JavaScript object from a property descriptor) happens elsewhere.

6. **Connect to JavaScript Functionality:**  For each JavaScript builtin, think about its corresponding JavaScript behavior and provide a simple example. For example, `ObjectIsExtensible` in the Torque code directly relates to the `Object.isExtensible()` method in JavaScript.

7. **Identify Logic and Infer Input/Output:** Focus on the macros and builtins. For `ObjectIsExtensibleImpl`, if the input is a non-proxy object, the output will be the result of the `runtime::ObjectIsExtensible` call. For `CreateObjectWithoutProperties`, the input is a prototype; the output is a new object (or a runtime error if the prototype isn't valid).

8. **Look for Potential Errors:** The code explicitly throws `TypeError` in certain situations (e.g., `Object.setPrototypeOf` with a non-object/null prototype, `ToPropertyDescriptor` with a non-object/undefined input). These are prime examples of common programming errors. Think about scenarios where developers might misuse these functions.

9. **Structure the Answer:** Organize the information logically, starting with the overall functionality, then breaking it down into specific methods/concepts, providing JavaScript examples, explaining the logic, and finally addressing potential errors. Use clear headings and bullet points for readability.

10. **Refine and Review:** Read through the generated answer. Are there any ambiguities?  Is the language clear and concise? Have all parts of the prompt been addressed? For instance, initially, I might have focused too heavily on the Torque syntax. Reviewing would prompt me to ensure the JavaScript connections and examples are prominent. I might also realize I haven't explicitly stated the *purpose* of these operations (managing object structure and properties).

By following this structured approach, one can effectively analyze and understand the functionality of a complex code file like this Torque source.
这个V8 Torque源代码文件 `v8/src/builtins/object.tq` 实现了 JavaScript 中 `Object` 构造函数的一些静态方法和原型方法的核心功能。 Torque 是一种 V8 使用的用于定义 built-in 函数的 DSL (Domain Specific Language)。

**主要功能归纳:**

该文件主要负责实现以下 `Object` 的相关操作：

1. **对象的可扩展性 (Extensibility):**
   - `Object.isExtensible(obj)`: 检查一个对象是否可以添加新的属性。
   - `Object.preventExtensions(obj)`:  阻止一个对象添加新的属性。

2. **原型链 (Prototype Chain):**
   - `Object.getPrototypeOf(obj)`: 获取一个对象的原型 (`__proto__`)。
   - `Object.setPrototypeOf(obj, prototype)`: 设置一个对象的原型 (`__proto__`)。

3. **对象创建 (Object Creation):**
   - 内部的 `CreateObjectWithoutProperties(prototype)`:  创建一个没有自身属性的新对象，可以指定原型。

4. **`Object.prototype` 的方法:**
   - `Object.prototype.toString()`: 返回对象的字符串表示。
   - `Object.prototype.valueOf()`: 返回对象的原始值（通常是对象自身）。
   - `Object.prototype.toLocaleString()`: 返回对象的本地化字符串表示。

5. **属性描述符 (Property Descriptors):**
   - `ToPropertyDescriptor(obj)`: 将一个对象转换为属性描述符对象。
   - `FromPropertyDescriptor(desc)`: (虽然这里是 `extern transitioning macro`,  意味着它的实现可能在其他地方)  将属性描述符对象转换为普通对象。

**与 JavaScript 功能的关系及示例:**

```javascript
// 对象的可扩展性
const obj1 = {};
console.log(Object.isExtensible(obj1)); // true
Object.preventExtensions(obj1);
console.log(Object.isExtensible(obj1)); // false
obj1.newProp = 'test'; // 在 strict mode 下会报错，非 strict mode 下静默失败
console.log(obj1.newProp); // undefined

// 原型链
const parent = { name: 'Parent' };
const child = Object.create(parent);
console.log(Object.getPrototypeOf(child) === parent); // true
Object.setPrototypeOf(child, null);
console.log(Object.getPrototypeOf(child)); // null

// 对象创建 (内部的 CreateObjectWithoutProperties 对应的是类似 Object.create(null) 的行为)
const objWithoutProto = Object.create(null);
console.log(Object.getPrototypeOf(objWithoutProto)); // null

// Object.prototype 的方法
const myObj = { value: 10 };
console.log(myObj.toString());       // "[object Object]" (默认情况下)
console.log(myObj.valueOf() === myObj); // true

const date = new Date();
console.log(date.toLocaleString()); // 根据本地环境格式化日期

// 属性描述符
const descObj = {
  value: 42,
  writable: false,
  enumerable: true,
  configurable: false
};
// Object.defineProperty 或 Object.defineProperties 内部会用到属性描述符的概念
Object.defineProperty(myObj, 'answer', descObj);
console.log(Object.getOwnPropertyDescriptor(myObj, 'answer'));
// 输出类似: { value: 42, writable: false, enumerable: true, configurable: false }
```

**代码逻辑推理 (假设输入与输出):**

**`ObjectIsExtensibleImpl(object: JSAny)`:**

* **假设输入:** 一个普通的 JavaScript 对象 `obj = { a: 1 }`
* **推理:**
    1. `Cast<JSReceiver>(object)` 会成功，因为 `obj` 是一个对象。
    2. `Cast<JSProxy>(objectJSReceiver)` 会失败，因为 `obj` 不是一个 Proxy 对象。
    3. 执行 `runtime::ObjectIsExtensible(objectJSReceiver)`，这个运行时函数会检查对象的内部标志，判断其是否可扩展。
* **假设输出:** `true` (如果对象没有被 `Object.preventExtensions` 阻止扩展)

* **假设输入:** 一个被阻止扩展的对象 `frozenObj = Object.preventExtensions({})`
* **推理:** 逻辑与上面类似，但 `runtime::ObjectIsExtensible` 会返回 `false`。
* **假设输出:** `false`

**`CreateObjectWithoutProperties(prototype: JSAny)`:**

* **假设输入:** `prototype = null`
* **推理:**
    1. `typeswitch (prototype)` 进入 `case (Null)` 分支。
    2. 从 NativeContext 中获取用于创建 `null` 原型对象的 `Map`。
    3. 分配一个空的 `NameDictionary` 或 `SwissNameDictionary` 用于存储属性 (初始为空)。
    4. 调用 `AllocateJSObjectFromMap` 创建对象。
* **假设输出:** 一个新创建的 JavaScript 对象，其原型为 `null`，且没有自身属性。

* **假设输入:** `prototype = { custom: 'proto' }`
* **推理:**
    1. `typeswitch (prototype)` 进入 `case (prototype: JSReceiver)` 分支。
    2. `properties` 被设置为 `kEmptyFixedArray` (因为新创建的对象没有自身属性)。
    3. 获取 `Object` 构造函数的 `prototype` 的 `Map`。
    4. 如果 `prototype` 与 `Object.prototype` 不同，则尝试查找可能的共享 `Map` 优化。
    5. 调用 `AllocateJSObjectFromMap` 创建对象。
* **假设输出:** 一个新创建的 JavaScript 对象，其原型为 `{ custom: 'proto' }`，且没有自身属性。

**涉及用户常见的编程错误:**

1. **尝试设置不可扩展对象的属性:**
   ```javascript
   const obj = Object.preventExtensions({});
   obj.newProp = 10; // 在 strict mode 下会抛出 TypeError
   ```
   V8 的 `ObjectPreventExtensionsThrow` (如果需要抛出异常) 或 `ObjectPreventExtensionsDontThrow` 会处理这种情况。

2. **尝试设置不可配置属性的特性 (如 writable, enumerable, configurable):**
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'readOnly', { value: 42, writable: false });
   // 尝试修改 writable 会抛出 TypeError
   Object.defineProperty(obj, 'readOnly', { writable: true });
   ```
   虽然这个文件没有直接处理 `Object.defineProperty` 的底层逻辑，但它处理了属性描述符的转换，这些转换是 `Object.defineProperty` 的基础。

3. **在 `Object.setPrototypeOf` 中使用非对象或 null 的原型:**
   ```javascript
   const obj = {};
   Object.setPrototypeOf(obj, 'string'); // TypeError: Object prototype may only be an Object or null
   ```
   `ObjectSetPrototypeOf` 内的 `typeswitch` 语句会捕获这种情况并抛出 `TypeError`。

4. **在需要对象的地方传递 null 或 undefined (例如 `Object.getPrototypeOf`)**:
   ```javascript
   Object.getPrototypeOf(null); // TypeError: Cannot convert undefined or null to object
   ```
   虽然 `ObjectGetPrototypeOfImpl` 接收 `JSAny`，但在内部的 `ToObject_Inline` 调用会处理 `null` 和 `undefined` 并抛出错误。

5. **误解 `Object.create(null)` 的行为:**  开发者可能期望 `Object.create(null)` 创建的对象拥有 `Object.prototype` 上的方法，但实际上这类对象没有原型，因此不能直接调用如 `toString` 等方法。

**总结:**

这个 Torque 文件是 V8 引擎中 `Object` built-in 功能的核心实现部分。 它定义了对象可扩展性、原型链操作、对象创建以及属性描述符处理等关键行为。通过 Torque 这种高性能的 DSL，V8 能够高效地执行这些底层的 JavaScript 操作。 理解这个文件的内容有助于深入了解 JavaScript 对象的内部工作机制。

Prompt: 
```
这是目录为v8/src/builtins/object.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-object-gen.h'

namespace runtime {
extern transitioning runtime ObjectIsExtensible(
    implicit context: Context)(JSAny): JSAny;

extern transitioning runtime JSReceiverPreventExtensionsThrow(
    implicit context: Context)(JSReceiver): JSAny;

extern transitioning runtime JSReceiverPreventExtensionsDontThrow(
    implicit context: Context)(JSReceiver): JSAny;

extern transitioning runtime JSReceiverGetPrototypeOf(
    implicit context: Context)(JSReceiver): JSAny;

extern transitioning runtime JSReceiverSetPrototypeOfThrow(
    implicit context: Context)(JSReceiver, JSAny): JSAny;

extern transitioning runtime JSReceiverSetPrototypeOfDontThrow(
    implicit context: Context)(JSReceiver, JSAny): JSAny;

extern transitioning runtime ObjectCreate(
    implicit context: Context)(JSAny, JSAny): JSAny;
}  // namespace runtime

namespace object {
transitioning macro ObjectIsExtensibleImpl(
    implicit context: Context)(object: JSAny): JSAny {
  const objectJSReceiver = Cast<JSReceiver>(object) otherwise return False;
  const objectJSProxy = Cast<JSProxy>(objectJSReceiver)
      otherwise return runtime::ObjectIsExtensible(objectJSReceiver);
  return proxy::ProxyIsExtensible(objectJSProxy);
}

transitioning macro ObjectPreventExtensionsThrow(
    implicit context: Context)(object: JSAny): JSAny {
  const objectJSReceiver = Cast<JSReceiver>(object) otherwise return object;
  const objectJSProxy = Cast<JSProxy>(objectJSReceiver)
      otherwise return runtime::JSReceiverPreventExtensionsThrow(objectJSReceiver);
  proxy::ProxyPreventExtensions(objectJSProxy, True);
  return objectJSReceiver;
}

transitioning macro ObjectPreventExtensionsDontThrow(
    implicit context: Context)(object: JSAny): JSAny {
  const objectJSReceiver = Cast<JSReceiver>(object) otherwise return False;
  const objectJSProxy = Cast<JSProxy>(objectJSReceiver)
      otherwise return runtime::JSReceiverPreventExtensionsDontThrow(
      objectJSReceiver);
  return proxy::ProxyPreventExtensions(objectJSProxy, False);
}

transitioning macro ObjectGetPrototypeOfImpl(
    implicit context: Context)(object: JSAny): JSAny {
  const objectJSReceiver: JSReceiver = ToObject_Inline(context, object);
  return object::JSReceiverGetPrototypeOf(objectJSReceiver);
}

transitioning macro JSReceiverGetPrototypeOf(
    implicit context: Context)(object: JSReceiver): JSAny {
  const objectJSProxy = Cast<JSProxy>(object)
      otherwise return runtime::JSReceiverGetPrototypeOf(object);
  return proxy::ProxyGetPrototypeOf(objectJSProxy);
}

transitioning macro ObjectSetPrototypeOfThrow(
    implicit context: Context)(object: JSAny, proto: JSReceiver|Null): JSAny {
  const objectJSReceiver = Cast<JSReceiver>(object) otherwise return object;
  const objectJSProxy = Cast<JSProxy>(objectJSReceiver)
      otherwise return runtime::JSReceiverSetPrototypeOfThrow(
      objectJSReceiver, proto);
  proxy::ProxySetPrototypeOf(objectJSProxy, proto, True);
  return objectJSReceiver;
}

transitioning macro ObjectSetPrototypeOfDontThrow(
    implicit context: Context)(object: JSAny, proto: JSReceiver|Null): JSAny {
  const objectJSReceiver = Cast<JSReceiver>(object) otherwise return False;
  const objectJSProxy = Cast<JSProxy>(objectJSReceiver)
      otherwise return runtime::JSReceiverSetPrototypeOfDontThrow(
      objectJSReceiver, proto);
  return proxy::ProxySetPrototypeOf(objectJSProxy, proto, False);
}

transitioning builtin CreateObjectWithoutProperties(
    implicit context: Context)(prototype: JSAny): JSAny {
  try {
    let map: Map;
    let properties: NameDictionary|SwissNameDictionary|EmptyFixedArray;
    typeswitch (prototype) {
      case (Null): {
        map = *NativeContextSlot(
            ContextSlot::SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP);
        @if(V8_ENABLE_SWISS_NAME_DICTIONARY) {
          properties =
              AllocateSwissNameDictionary(kSwissNameDictionaryInitialCapacity);
        }
        @ifnot(V8_ENABLE_SWISS_NAME_DICTIONARY) {
          properties = AllocateNameDictionary(kNameDictionaryInitialCapacity);
        }
      }
      case (prototype: JSReceiver): {
        properties = kEmptyFixedArray;
        const objectFunction =
            *NativeContextSlot(ContextSlot::OBJECT_FUNCTION_INDEX);
        map = UnsafeCast<Map>(objectFunction.prototype_or_initial_map);
        if (prototype != map.prototype) {
          const prototypeInfo = prototype.map.PrototypeInfo() otherwise Runtime;
          typeswitch (prototypeInfo.derived_maps) {
            case (Undefined): {
              goto Runtime;
            }
            case (derived_maps: WeakArrayList): {
              const theMap = MaybeObjectToStrong(derived_maps.objects[0])
                  otherwise Runtime;
              map = UnsafeCast<Map>(theMap);
            }
          }
        }
      }
      case (JSAny): {
        goto Runtime;
      }
    }
    return AllocateJSObjectFromMap(map, properties);
  } label Runtime deferred {
    return runtime::ObjectCreate(prototype, Undefined);
  }
}

// ES6 section 19.1.2.11 Object.isExtensible ( O )
transitioning javascript builtin ObjectIsExtensible(
    js-implicit context: NativeContext)(object: JSAny): JSAny {
  return object::ObjectIsExtensibleImpl(object);
}

// ES6 section 19.1.2.18 Object.preventExtensions ( O )
transitioning javascript builtin ObjectPreventExtensions(
    js-implicit context: NativeContext)(object: JSAny): JSAny {
  return object::ObjectPreventExtensionsThrow(object);
}

// ES6 section 19.1.2.9 Object.getPrototypeOf ( O )
transitioning javascript builtin ObjectGetPrototypeOf(
    js-implicit context: NativeContext)(object: JSAny): JSAny {
  return object::ObjectGetPrototypeOfImpl(object);
}

// ES6 section 19.1.2.21 Object.setPrototypeOf ( O, proto )
transitioning javascript builtin ObjectSetPrototypeOf(
    js-implicit context: NativeContext)(object: JSAny, proto: JSAny): JSAny {
  // 1. Set O to ? RequireObjectCoercible(O).
  RequireObjectCoercible(object, 'Object.setPrototypeOf');

  // 2. If Type(proto) is neither Object nor Null, throw a TypeError
  // exception.
  // 3. If Type(O) is not Object, return O.
  // 4. Let status be ? O.[[SetPrototypeOf]](proto).
  // 5. If status is false, throw a TypeError exception.
  // 6. Return O.
  typeswitch (proto) {
    case (proto: JSReceiver|Null): {
      return object::ObjectSetPrototypeOfThrow(object, proto);
    }
    case (JSAny): {
      ThrowTypeError(MessageTemplate::kProtoObjectOrNull, proto);
    }
  }
}

// ES #sec-object.prototype.tostring
transitioning javascript builtin ObjectPrototypeToString(
    js-implicit context: Context, receiver: JSAny)(): String {
  return ObjectToString(context, receiver);
}

// ES #sec-object.prototype.valueof
transitioning javascript builtin ObjectPrototypeValueOf(
    js-implicit context: Context, receiver: JSAny)(): JSReceiver {
  // 1. Return ? ToObject(this value).
  return ToObject_Inline(context, receiver);
}

// ES #sec-object.prototype.tolocalestring
transitioning javascript builtin ObjectPrototypeToLocaleString(
    js-implicit context: Context, receiver: JSAny)(): JSAny {
  // 1. Let O be the this value.
  // 2. Return ? Invoke(O, "toString").
  if (receiver == Null || receiver == Undefined) deferred {
      ThrowTypeError(
          MessageTemplate::kCalledOnNullOrUndefined,
          'Object.prototype.toLocaleString');
    }
  const method = GetProperty(receiver, 'toString');
  return Call(context, method, receiver);
}

// JSDataPropertyDescriptor constants
const kJSDataPropertyDescriptorWritableOffset: constexpr int31
    generates 'JSDataPropertyDescriptor::kWritableOffset';
const kJSDataPropertyDescriptorEnumerableOffset: constexpr int31
    generates 'JSDataPropertyDescriptor::kEnumerableOffset';
const kJSDataPropertyDescriptorConfigurableOffset: constexpr int31
    generates 'JSDataPropertyDescriptor::kConfigurableOffset';
const kJSDataPropertyDescriptorValueOffset: constexpr int31
    generates 'JSDataPropertyDescriptor::kValueOffset';

// JSAccessorPropertyDescriptor constants
const kJSAccessorPropertyDescriptorEnumerableOffset: constexpr int31
    generates 'JSAccessorPropertyDescriptor::kEnumerableOffset';
const kJSAccessorPropertyDescriptorConfigurableOffset: constexpr int31
    generates 'JSAccessorPropertyDescriptor::kConfigurableOffset';
const kJSAccessorPropertyDescriptorGetOffset: constexpr int31
    generates 'JSAccessorPropertyDescriptor::kGetOffset';
const kJSAccessorPropertyDescriptorSetOffset: constexpr int31
    generates 'JSAccessorPropertyDescriptor::kSetOffset';

// ToPropertyDescriptor (https://tc39.es/ecma262/#sec-topropertydescriptor)
transitioning macro ToPropertyDescriptor(
    implicit context: Context)(object: JSReceiver): PropertyDescriptorObject {
  const result: PropertyDescriptorObject = AllocatePropertyDescriptorObject();

  if (object.map == *NativeContextSlot<Map>(
          context, ContextSlot::DATA_PROPERTY_DESCRIPTOR_MAP_INDEX)) {
    const writable = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSDataPropertyDescriptorWritableOffset));
    result.flags.has_writable = true;
    result.flags.is_writable = ToBoolean(writable);

    const enumerable = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSDataPropertyDescriptorEnumerableOffset));
    result.flags.has_enumerable = true;
    result.flags.is_enumerable = ToBoolean(enumerable);

    const configurable = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSDataPropertyDescriptorConfigurableOffset));
    result.flags.has_configurable = true;
    result.flags.is_configurable = ToBoolean(configurable);

    result.flags.has_value = true;
    result.value = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSDataPropertyDescriptorValueOffset));
  } else if (
      object.map == *NativeContextSlot<Map>(
          context, ContextSlot::ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX)) {
    const enumerable = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSAccessorPropertyDescriptorEnumerableOffset));
    result.flags.has_enumerable = true;
    result.flags.is_enumerable = ToBoolean(enumerable);

    const configurable = UnsafeCast<JSAny>(LoadObjectField(
        object, kJSAccessorPropertyDescriptorConfigurableOffset));
    result.flags.has_configurable = true;
    result.flags.is_configurable = ToBoolean(configurable);

    result.flags.has_get = true;
    result.get = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSAccessorPropertyDescriptorGetOffset));

    result.flags.has_set = true;
    result.set = UnsafeCast<JSAny>(
        LoadObjectField(object, kJSAccessorPropertyDescriptorSetOffset));
  } else {
    const hasEnumerable = HasProperty(object, 'enumerable');
    if (hasEnumerable == True) {
      const enumerable = ToBoolean(GetProperty(object, 'enumerable'));
      result.flags.has_enumerable = true;
      result.flags.is_enumerable = enumerable;
    }

    const hasConfigurable = HasProperty(object, 'configurable');
    if (hasConfigurable == True) {
      const configurable = ToBoolean(GetProperty(object, 'configurable'));
      result.flags.has_configurable = true;
      result.flags.is_configurable = configurable;
    }

    const hasValue = HasProperty(object, 'value');
    if (hasValue == True) {
      const value = GetProperty(object, 'value');
      result.flags.has_value = true;
      result.value = value;
    }

    const hasWritable = HasProperty(object, 'writable');
    if (hasWritable == True) {
      const writable = ToBoolean(GetProperty(object, 'writable'));
      result.flags.has_writable = true;
      result.flags.is_writable = writable;
    }

    const hasGet = HasProperty(object, 'get');
    if (hasGet == True) {
      let getter = GetProperty(object, 'get');
      if (!Is<Undefined>(getter) && !Is<FunctionTemplateInfo>(getter)) {
        getter = Cast<Callable>(getter) otherwise ThrowTypeError(
            MessageTemplate::kObjectGetterCallable, getter);
      }
      result.flags.has_get = true;
      result.get = getter;
    }

    const hasSet = HasProperty(object, 'set');
    if (hasSet == True) {
      let setter = GetProperty(object, 'set');
      if (!Is<Undefined>(setter) && !Is<FunctionTemplateInfo>(setter)) {
        setter = Cast<Callable>(setter) otherwise ThrowTypeError(
            MessageTemplate::kObjectSetterCallable, setter);
      }
      result.flags.has_set = true;
      result.set = setter;
    }
  }
  return result;
}

@export
transitioning macro ToPropertyDescriptor(
    implicit context: Context)(object: JSAny): PropertyDescriptorObject
    |Undefined {
  typeswitch (object) {
    case (Undefined): {
      return Undefined;
    }
    case (receiver: JSReceiver): {
      return ToPropertyDescriptor(receiver);
    }
    case (JSAny): {
      ThrowTypeError(MessageTemplate::kPropertyDescObject, object);
    }
  }
}

extern transitioning macro ObjectBuiltinsAssembler::FromPropertyDescriptor(
    Context, JSAny): JSAny;

@export
transitioning macro FromPropertyDescriptor(
    implicit context: Context)(object: JSAny): JSAny {
  return FromPropertyDescriptor(context, object);
}

}  // namespace object

"""

```