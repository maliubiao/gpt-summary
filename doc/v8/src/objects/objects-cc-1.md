Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/objects.cc`. I need to analyze the code and describe its purpose. The prompt also has several specific instructions:

1. **List the functionalities:** I need to identify the main tasks performed by the code.
2. **.tq extension:**  Confirm that `.cc` means it's not Torque code.
3. **Relationship to JavaScript:** If the code relates to JavaScript concepts, I need to provide JavaScript examples.
4. **Code logic and reasoning:**  For logical parts, provide example inputs and outputs.
5. **Common programming errors:** Point out potential user errors.
6. **Part of a larger set:**  Acknowledge that this is part 2 of 8.
7. **Summarize the functionality:** Provide a concise overview of the code's purpose.

Let's break down the code and identify its functions:

- **`Equals(Isolate* isolate, Handle<Object> x, Handle<Object> y)`:** This function implements the loose equality (`==`) comparison in JavaScript. It handles different types (numbers, strings, symbols, BigInts, objects) and type coercion.
- **`StrictEquals(Tagged<Object> obj, Tagged<Object> that)`:** This function implements the strict equality (`===`) comparison in JavaScript. It checks for type equality before comparing values.
- **`TypeOf(Isolate* isolate, DirectHandle<Object> object)`:** This function implements the `typeof` operator in JavaScript, returning a string representing the type of the object.
- **`Add(Isolate* isolate, Handle<Object> lhs, Handle<Object> rhs)`:** This function implements the addition operator (`+`) in JavaScript, handling both numeric addition and string concatenation, including type coercion.
- **`OrdinaryHasInstance(Isolate* isolate, Handle<JSAny> callable, Handle<JSAny> object)`:** This function is part of the `instanceof` operator implementation, checking if an object inherits from a constructor's prototype.
- **`InstanceOf(Isolate* isolate, Handle<JSAny> object, Handle<JSAny> callable)`:** This function implements the `instanceof` operator in JavaScript, including handling the `@@hasInstance` symbol.
- **`GetMethod(Isolate* isolate, Handle<JSReceiver> receiver, Handle<Name> name)`:** This function retrieves a method (a callable property) from an object.
- **`CreateListFromArrayLike(Isolate* isolate, Handle<Object> object, ElementTypes element_types)`:** This function converts an array-like object into a `FixedArray`, used in various JavaScript APIs.
- **`GetLengthFromArrayLike(Isolate* isolate, Handle<JSReceiver> object)`:** This helper function gets the `length` property of an array-like object.
- **`GetProperty(LookupIterator* it, bool is_global_reference)`:** This function is a core part of property access in V8, handling different property lookup scenarios (proxies, interceptors, accessors, etc.).
- **`JSProxy::GetProperty(Isolate* isolate, DirectHandle<JSProxy> proxy, Handle<Name> name, Handle<JSAny> receiver, bool* was_found)`:** This function handles property access on JavaScript Proxy objects, invoking the `get` trap.
- **`JSProxy::CheckGetSetTrapResult(Isolate* isolate, Handle<Name> name, Handle<JSReceiver> target, Handle<Object> trap_result, AccessKind access_kind)`:** This function validates the result of a Proxy's `get` or `set` trap.
- **`ToInt32(Tagged<Object> obj, int32_t* value)`:** This function attempts to convert a V8 object to a 32-bit integer.
- **`JSProxy::GetPrototype(DirectHandle<JSProxy> proxy)`:** This function handles getting the prototype of a JavaScript Proxy, invoking the `getPrototypeOf` trap.
- **`GetPropertyWithAccessor(LookupIterator* it)`:** This function handles property access when the property is defined by an accessor (getter).
- **`SetPropertyWithAccessor(LookupIterator* it, Handle<Object> value, Maybe<ShouldThrow> maybe_should_throw)`:** This function handles property assignment when the property is defined by an accessor (setter).
- **`GetPropertyWithDefinedGetter(Handle<JSAny> receiver, Handle<JSReceiver> getter)`:** This function calls a getter function.
- **`SetPropertyWithDefinedSetter(Handle<JSAny> receiver, Handle<JSReceiver> setter, Handle<Object> value, Maybe<ShouldThrow> should_throw)`:** This function calls a setter function.
- **`GetPrototypeChainRootMap(Tagged<Object> obj, Isolate* isolate)`:**  This function finds the root map of an object's prototype chain.
- **`GetOrCreateHash(Tagged<Object> obj, Isolate* isolate)`:** This function gets or creates a hash for an object.
- **`SameValue(Tagged<Object> obj, Tagged<Object> other)`:** This function implements the `Object.is()` method in JavaScript, performing a SameValue comparison.
- **`SameValueZero(Tagged<Object> obj, Tagged<Object> other)`:** This function implements the SameValueZero comparison, used in certain JavaScript operations (e.g., `Map` and `Set` key comparisons).
- **`ArraySpeciesConstructor(Isolate* isolate, Handle<JSAny> original_array)`:** This function determines the constructor to use when creating new arrays in methods like `Array.prototype.map` and `Array.prototype.slice`.

Now, I'll structure the response based on the prompt's requirements.
这是 `v8/src/objects/objects.cc` 文件的第二部分，主要包含 V8 引擎中与 JavaScript 对象操作相关的核心功能实现。以下是其功能的归纳：

**核心功能归纳:**

这部分代码主要负责实现 JavaScript 中关于对象比较、类型判断、属性访问、运算符重载以及原型链操作等核心语义。 具体来说，它涵盖了以下关键功能：

1. **对象比较:**
    *   实现了 JavaScript 的 **宽松相等 ( `==` )** 比较运算符，包括处理不同类型之间的隐式转换和比较逻辑。
    *   实现了 JavaScript 的 **严格相等 ( `===` )** 比较运算符，不进行类型转换，直接比较值和类型。
    *   实现了 JavaScript 的 `Object.is()` 方法的语义，即 **SameValue** 比较，用于判断两个值是否在所有上下文中都“相同”。
    *   实现了用于某些特定场景的 **SameValueZero** 比较，例如用于 `Map` 和 `Set` 的键比较，它与 SameValue 的不同之处在于它认为 `+0` 等于 `-0`。

2. **类型判断:**
    *   实现了 JavaScript 的 `typeof` 运算符，返回表示操作数类型的字符串。

3. **运算符重载:**
    *   实现了 JavaScript 的 **加法运算符 ( `+` )** 的语义，包括数值相加和字符串连接，以及操作数到原始类型的转换。

4. **`instanceof` 运算符:**
    *   实现了 JavaScript 的 `instanceof` 运算符，用于检查对象是否属于某个构造函数的实例或其原型链中是否存在该构造函数的 `prototype` 属性。

5. **属性访问:**
    *   提供了获取对象属性的方法 `GetProperty`，该方法会处理各种情况，包括原型链查找、代理对象 (Proxy)、拦截器 (Interceptor) 和访问器属性 (Accessor)。
    *   提供了获取对象方法的方法 `GetMethod`，它在获取属性的基础上，还会检查该属性是否可调用。
    *   针对 JavaScript Proxy 对象，实现了 `GetProperty` 方法的特殊处理，会调用 Proxy 对象的 `get` 陷阱 (trap)。
    *   实现了访问器属性（getter 和 setter）的获取和设置逻辑，包括对 API 样式的回调函数的处理。

6. **数组操作:**
    *   提供了将类数组对象转换为 `FixedArray` 的方法 `CreateListFromArrayLike`，这是许多 JavaScript API 的基础操作。
    *   提供了获取类数组对象 `length` 属性的方法 `GetLengthFromArrayLike`。
    *   提供了确定数组衍生构造函数的方法 `ArraySpeciesConstructor`，用于控制 `Array.prototype.map` 等方法返回的数组类型。

7. **原型链操作:**
    *   提供了获取对象原型链根 Map 的方法 `GetPrototypeChainRootMap`。
    *   针对 JavaScript Proxy 对象，实现了获取原型的方法 `GetPrototype`，会调用 Proxy 对象的 `getPrototypeOf` 陷阱 (trap)。

8. **哈希值:**
    *   提供了获取或创建对象哈希值的方法 `GetOrCreateHash`，用于对象的快速比较和存储。

**关于文件扩展名和 Torque:**

正如你所说，如果 `v8/src/objects/objects.cc` 以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。 由于它以 `.cc` 结尾，所以它是 **C++ 源代码**。 Torque 是一种用于生成 V8 代码的领域特定语言，通常用于实现性能关键的内置函数。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码直接对应着许多核心的 JavaScript 语言特性。以下是一些 JavaScript 示例，说明了 `objects.cc` 中实现的功能：

*   **宽松相等 ( `==` ) 和严格相等 ( `===` )：**

    ```javascript
    console.log(1 == "1");   // true (宽松相等，会进行类型转换)
    console.log(1 === "1");  // false (严格相等，类型不同)
    console.log(null == undefined); // true
    console.log(null === undefined); // false
    ```
    `Equals` 和 `StrictEquals` 函数实现了这些行为。

*   **`typeof` 运算符：**

    ```javascript
    console.log(typeof 42);         // "number"
    console.log(typeof "hello");    // "string"
    console.log(typeof {});         // "object"
    console.log(typeof null);       // "object"
    console.log(typeof undefined);  // "undefined"
    ```
    `TypeOf` 函数实现了 `typeof` 运算符的逻辑。

*   **加法运算符 ( `+` )：**

    ```javascript
    console.log(2 + 3);       // 5 (数值相加)
    console.log("hello" + " world"); // "hello world" (字符串连接)
    console.log(1 + "2");     // "12" (类型转换后字符串连接)
    ```
    `Add` 函数实现了加法运算符的语义。

*   **`instanceof` 运算符：**

    ```javascript
    function MyClass() {}
    const instance = new MyClass();
    console.log(instance instanceof MyClass);  // true
    console.log(instance instanceof Object);   // true (因为 MyClass 继承自 Object)
    ```
    `InstanceOf` 和 `OrdinaryHasInstance` 函数实现了 `instanceof` 运算符的逻辑。

*   **属性访问：**

    ```javascript
    const obj = { a: 1, b: () => console.log("hello") };
    console.log(obj.a);     // 1
    obj.b();             // "hello"

    const proxy = new Proxy({}, {
      get(target, prop) {
        console.log(`Getting property: ${prop}`);
        return target[prop];
      }
    });
    proxy.c; // 会触发 Proxy 的 get 陷阱
    ```
    `GetProperty` 和 `JSProxy::GetProperty` 等函数处理属性的获取。

*   **类数组对象转换为数组：**

    ```javascript
    function myFunction() {
      console.log(Array.from(arguments));
    }
    myFunction(1, 2, 3); // [1, 2, 3]
    ```
    `CreateListFromArrayLike` 函数是 `Array.from` 等方法的基础。

*   **`Object.is()`：**

    ```javascript
    console.log(Object.is(NaN, NaN));       // true
    console.log(Object.is(+0, -0));      // false
    console.log(Object.is(5, 5));         // true
    console.log(Object.is({}, {}));       // false (引用不同)
    ```
    `SameValue` 函数实现了 `Object.is()` 的比较逻辑。

**代码逻辑推理 (假设输入与输出):**

**示例 1: `Equals` 函数 (宽松相等)**

*   **假设输入:**
    *   `x` 是一个包含数值 `1` 的 `Handle<Object>`。
    *   `y` 是一个包含字符串 `"1"` 的 `Handle<Object>`。
*   **代码逻辑推理:** `Equals` 函数会先检查类型，发现类型不同。然后，它会尝试将字符串 `"1"` 转换为数字 `1`。转换成功后，它会比较两个数字 `1`，结果为相等。
*   **预期输出:** `Just(true)`

**示例 2: `StrictEquals` 函数 (严格相等)**

*   **假设输入:**
    *   `obj` 是一个包含数值 `1` 的 `Tagged<Object>`。
    *   `that` 是一个包含字符串 `"1"` 的 `Tagged<Object>`。
*   **代码逻辑推理:** `StrictEquals` 函数首先检查类型，发现 `obj` 是 Number，`that` 是 String，类型不同，直接返回 `false`。
*   **预期输出:** `false`

**示例 3: `Add` 函数 (加法运算)**

*   **假设输入:**
    *   `lhs` 是一个包含数值 `2` 的 `Handle<Object>`。
    *   `rhs` 是一个包含数值 `3` 的 `Handle<Object>`。
*   **代码逻辑推理:** `Add` 函数会检测到两个操作数都是数字，然后将它们的值相加。
*   **预期输出:** 一个包含数值 `5` 的 `MaybeHandle<Object>`。

*   **假设输入:**
    *   `lhs` 是一个包含字符串 `"Hello"` 的 `Handle<Object>`。
    *   `rhs` 是一个包含字符串 `" World"` 的 `Handle<Object>`。
*   **代码逻辑推理:** `Add` 函数会检测到两个操作数都是字符串，然后将它们连接起来。
*   **预期输出:** 一个包含字符串 `"Hello World"` 的 `MaybeHandle<Object>`。

**用户常见的编程错误:**

*   **混淆宽松相等和严格相等:**  开发者经常不清楚 `==` 和 `===` 的区别，导致在需要类型一致的比较场景下使用了 `==`，或者在允许类型转换的场景下错误地使用了 `===`。

    ```javascript
    if (document.getElementById("myElement").value == 0) {
      // 错误：如果 value 是 "0" (字符串)，这个条件仍然会成立
    }

    if (document.getElementById("myElement").value === 0) {
      // 正确：只有当 value 是数字 0 时条件才成立
    }
    ```

*   **不理解 `typeof null` 的结果:**  `typeof null` 返回 `"object"` 是 JavaScript 的一个历史遗留问题，容易让开发者感到困惑。

    ```javascript
    const myVar = null;
    if (typeof myVar === 'object') {
      // 错误：这里会进入判断，但 myVar 是 null 而不是一个对象
    }

    if (myVar === null) {
      // 正确的 null 值判断方式
    }
    ```

*   **在需要数值相加时进行了字符串连接:**  当一个操作数是字符串时，加法运算符会执行字符串连接。

    ```javascript
    const count = 5;
    const message = "You have " + count + " items."; // 正确，但可以用模板字符串
    const wrongSum = "5" + 5; // "55" (字符串连接，不是数值相加)
    const correctSum = parseInt("5", 10) + 5; // 10 (数值相加)
    ```

*   **错误地使用 `instanceof` 进行类型检查:**  `instanceof` 用于检查原型链关系，不适用于基本类型。

    ```javascript
    const str = "hello";
    console.log(str instanceof String); // false (基本类型不是对象)

    const strObj = new String("hello");
    console.log(strObj instanceof String); // true (对象类型)

    // 使用 typeof 进行基本类型检查
    console.log(typeof str === 'string'); // true
    ```

**总结:**

`v8/src/objects/objects.cc` 的这部分代码是 V8 引擎中实现 JavaScript 对象核心操作的基础，涵盖了对象比较、类型判断、运算符重载、属性访问和原型链操作等关键功能，直接关系到 JavaScript 代码的执行语义。理解这部分代码的功能有助于深入理解 JavaScript 的运行机制。

Prompt: 
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
lse);
      }
    } else if (IsSymbol(*x)) {
      if (IsSymbol(*y)) {
        return Just(x.is_identical_to(y));
      } else if (IsJSReceiver(*y)) {
        if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(y))
                 .ToHandle(&y)) {
          return Nothing<bool>();
        }
      } else {
        return Just(false);
      }
    } else if (IsBigInt(*x)) {
      if (IsBigInt(*y)) {
        return Just(BigInt::EqualToBigInt(Cast<BigInt>(*x), Cast<BigInt>(*y)));
      }
      return Equals(isolate, y, x);
    } else if (IsJSReceiver(*x)) {
      if (IsJSReceiver(*y)) {
        return Just(x.is_identical_to(y));
      } else if (IsUndetectable(*y)) {
        return Just(IsUndetectable(*x));
      } else if (IsBoolean(*y)) {
        y = Oddball::ToNumber(isolate, Cast<Oddball>(y));
      } else if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(x))
                      .ToHandle(&x)) {
        return Nothing<bool>();
      }
    } else {
      return Just(IsUndetectable(*x) && IsUndetectable(*y));
    }
  }
}

// static
bool Object::StrictEquals(Tagged<Object> obj, Tagged<Object> that) {
  if (IsNumber(obj)) {
    if (!IsNumber(that)) return false;
    return StrictNumberEquals(Cast<Number>(obj), Cast<Number>(that));
  } else if (IsString(obj)) {
    if (!IsString(that)) return false;
    return Cast<String>(obj)->Equals(Cast<String>(that));
  } else if (IsBigInt(obj)) {
    if (!IsBigInt(that)) return false;
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(that));
  }
  return obj == that;
}

// static
Handle<String> Object::TypeOf(Isolate* isolate, DirectHandle<Object> object) {
  if (IsNumber(*object)) return isolate->factory()->number_string();
  if (IsOddball(*object))
    return handle(Cast<Oddball>(*object)->type_of(), isolate);
  if (IsUndetectable(*object)) {
    return isolate->factory()->undefined_string();
  }
  if (IsString(*object)) return isolate->factory()->string_string();
  if (IsSymbol(*object)) return isolate->factory()->symbol_string();
  if (IsBigInt(*object)) return isolate->factory()->bigint_string();
  if (IsCallable(*object)) return isolate->factory()->function_string();
  return isolate->factory()->object_string();
}

// static
MaybeHandle<Object> Object::Add(Isolate* isolate, Handle<Object> lhs,
                                Handle<Object> rhs) {
  if (IsNumber(*lhs) && IsNumber(*rhs)) {
    return isolate->factory()->NewNumber(
        Object::NumberValue(Cast<Number>(*lhs)) +
        Object::NumberValue(Cast<Number>(*rhs)));
  } else if (IsString(*lhs) && IsString(*rhs)) {
    return isolate->factory()->NewConsString(Cast<String>(lhs),
                                             Cast<String>(rhs));
  }
  ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs, Object::ToPrimitive(isolate, lhs));
  ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs, Object::ToPrimitive(isolate, rhs));
  if (IsString(*lhs) || IsString(*rhs)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs, Object::ToString(isolate, rhs));
    ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs, Object::ToString(isolate, lhs));
    return isolate->factory()->NewConsString(Cast<String>(lhs),
                                             Cast<String>(rhs));
  }
  Handle<Number> lhs_number;
  Handle<Number> rhs_number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs_number,
                             Object::ToNumber(isolate, rhs));
  ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs_number,
                             Object::ToNumber(isolate, lhs));
  return isolate->factory()->NewNumber(Object::NumberValue(*lhs_number) +
                                       Object::NumberValue(*rhs_number));
}

// static
MaybeHandle<Object> Object::OrdinaryHasInstance(Isolate* isolate,
                                                Handle<JSAny> callable,
                                                Handle<JSAny> object) {
  // The {callable} must have a [[Call]] internal method.
  if (!IsCallable(*callable)) return isolate->factory()->false_value();

  // Check if {callable} is a bound function, and if so retrieve its
  // [[BoundTargetFunction]] and use that instead of {callable}.
  if (IsJSBoundFunction(*callable)) {
    // Since there is a mutual recursion here, we might run out of stack
    // space for long chains of bound functions.
    STACK_CHECK(isolate, MaybeHandle<Object>());
    Handle<JSCallable> bound_callable(
        Cast<JSBoundFunction>(callable)->bound_target_function(), isolate);
    return Object::InstanceOf(isolate, object, bound_callable);
  }

  // If {object} is not a receiver, return false.
  if (!IsJSReceiver(*object)) return isolate->factory()->false_value();

  // Get the "prototype" of {callable}; raise an error if it's not a receiver.
  Handle<Object> prototype;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, prototype,
      Object::GetProperty(isolate, callable,
                          isolate->factory()->prototype_string()));
  if (!IsJSReceiver(*prototype)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kInstanceofNonobjectProto, prototype));
  }

  // Return whether or not {prototype} is in the prototype chain of {object}.
  Maybe<bool> result = JSReceiver::HasInPrototypeChain(
      isolate, Cast<JSReceiver>(object), prototype);
  if (result.IsNothing()) return MaybeHandle<Object>();
  return isolate->factory()->ToBoolean(result.FromJust());
}

// static
MaybeHandle<Object> Object::InstanceOf(Isolate* isolate, Handle<JSAny> object,
                                       Handle<JSAny> callable) {
  // The {callable} must be a receiver.
  if (!IsJSReceiver(*callable)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kNonObjectInInstanceOfCheck));
  }

  // Lookup the @@hasInstance method on {callable}.
  Handle<Object> inst_of_handler;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, inst_of_handler,
      Object::GetMethod(isolate, Cast<JSReceiver>(callable),
                        isolate->factory()->has_instance_symbol()));
  if (!IsUndefined(*inst_of_handler, isolate)) {
    // Call the {inst_of_handler} on the {callable}.
    Handle<Object> result;
    Handle<Object> args[] = {object};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        Execution::Call(isolate, inst_of_handler, callable, 1, args));
    return isolate->factory()->ToBoolean(
        Object::BooleanValue(*result, isolate));
  }

  // The {callable} must have a [[Call]] internal method.
  if (!IsCallable(*callable)) {
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kNonCallableInInstanceOfCheck));
  }

  // Fall back to OrdinaryHasInstance with {callable} and {object}.
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result, Object::OrdinaryHasInstance(isolate, callable, object));
  return result;
}

// static
MaybeHandle<Object> Object::GetMethod(Isolate* isolate,
                                      Handle<JSReceiver> receiver,
                                      Handle<Name> name) {
  Handle<Object> func;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, func,
                             JSReceiver::GetProperty(isolate, receiver, name));
  if (IsNullOrUndefined(*func, isolate)) {
    return isolate->factory()->undefined_value();
  }
  if (!IsCallable(*func)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kPropertyNotFunction,
                                          func, name, receiver));
  }
  return func;
}

namespace {

MaybeHandle<FixedArray> CreateListFromArrayLikeFastPath(
    Isolate* isolate, Handle<Object> object, ElementTypes element_types) {
  if (element_types == ElementTypes::kAll) {
    if (IsJSArray(*object)) {
      Handle<JSArray> array = Cast<JSArray>(object);
      uint32_t length;
      if (!array->HasArrayPrototype(isolate) ||
          !Object::ToUint32(array->length(), &length) ||
          !array->HasFastElements() ||
          !JSObject::PrototypeHasNoElements(isolate, *array)) {
        return MaybeHandle<FixedArray>();
      }
      return array->GetElementsAccessor()->CreateListFromArrayLike(
          isolate, array, length);
    } else if (IsJSTypedArray(*object)) {
      Handle<JSTypedArray> array = Cast<JSTypedArray>(object);
      size_t length = array->GetLength();
      if (array->IsDetachedOrOutOfBounds() ||
          length > static_cast<size_t>(FixedArray::kMaxLength)) {
        return MaybeHandle<FixedArray>();
      }
      static_assert(FixedArray::kMaxLength <=
                    std::numeric_limits<uint32_t>::max());
      return array->GetElementsAccessor()->CreateListFromArrayLike(
          isolate, array, static_cast<uint32_t>(length));
    }
  }
  return MaybeHandle<FixedArray>();
}

}  // namespace

// static
MaybeHandle<FixedArray> Object::CreateListFromArrayLike(
    Isolate* isolate, Handle<Object> object, ElementTypes element_types) {
  // Fast-path for JSArray and JSTypedArray.
  MaybeHandle<FixedArray> fast_result =
      CreateListFromArrayLikeFastPath(isolate, object, element_types);
  if (!fast_result.is_null()) return fast_result;
  // 1. ReturnIfAbrupt(object).
  // 2. (default elementTypes -- not applicable.)
  // 3. If Type(obj) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "CreateListFromArrayLike")));
  }

  // 4. Let len be ? ToLength(? Get(obj, "length")).
  Handle<JSReceiver> receiver = Cast<JSReceiver>(object);
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, raw_length_number,
                             Object::GetLengthFromArrayLike(isolate, receiver));
  uint32_t len;
  if (!Object::ToUint32(*raw_length_number, &len) ||
      len > static_cast<uint32_t>(FixedArray::kMaxLength)) {
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kInvalidArrayLength));
  }
  // 5. Let list be an empty List.
  Handle<FixedArray> list = isolate->factory()->NewFixedArray(len);
  // 6. Let index be 0.
  // 7. Repeat while index < len:
  for (uint32_t index = 0; index < len; ++index) {
    // 7a. Let indexName be ToString(index).
    // 7b. Let next be ? Get(obj, indexName).
    Handle<Object> next;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, next, JSReceiver::GetElement(isolate, receiver, index));
    switch (element_types) {
      case ElementTypes::kAll:
        // Nothing to do.
        break;
      case ElementTypes::kStringAndSymbol: {
        // 7c. If Type(next) is not an element of elementTypes, throw a
        //     TypeError exception.
        if (!IsName(*next)) {
          THROW_NEW_ERROR(
              isolate, NewTypeError(MessageTemplate::kNotPropertyName, next));
        }
        // 7d. Append next as the last element of list.
        // Internalize on the fly so we can use pointer identity later.
        next = isolate->factory()->InternalizeName(Cast<Name>(next));
        break;
      }
    }
    list->set(index, *next);
    // 7e. Set index to index + 1. (See loop header.)
  }
  // 8. Return list.
  return list;
}

// static
MaybeHandle<Object> Object::GetLengthFromArrayLike(Isolate* isolate,
                                                   Handle<JSReceiver> object) {
  Handle<Object> val;
  Handle<Name> key = isolate->factory()->length_string();
  ASSIGN_RETURN_ON_EXCEPTION(isolate, val,
                             JSReceiver::GetProperty(isolate, object, key));
  return Object::ToLength(isolate, val);
}

// static
MaybeHandle<Object> Object::GetProperty(LookupIterator* it,
                                        bool is_global_reference) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::JSPROXY: {
        bool was_found;
        Handle<JSAny> receiver = it->GetReceiver();
        // In case of global IC, the receiver is the global object. Replace by
        // the global proxy.
        if (IsJSGlobalObject(*receiver)) {
          receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(),
                            it->isolate());
        }
        if (is_global_reference) {
          Maybe<bool> maybe = JSProxy::HasProperty(
              it->isolate(), it->GetHolder<JSProxy>(), it->GetName());
          if (maybe.IsNothing()) return {};
          if (!maybe.FromJust()) {
            it->NotFound();
            return it->isolate()->factory()->undefined_value();
          }
        }
        MaybeHandle<JSAny> result =
            JSProxy::GetProperty(it->isolate(), it->GetHolder<JSProxy>(),
                                 it->GetName(), receiver, &was_found);
        if (!was_found && !is_global_reference) it->NotFound();
        return result;
      }
      case LookupIterator::WASM_OBJECT:
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::INTERCEPTOR: {
        bool done;
        Handle<JSAny> result;
        ASSIGN_RETURN_ON_EXCEPTION(
            it->isolate(), result,
            JSObject::GetPropertyWithInterceptor(it, &done));
        if (done) return result;
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        return JSObject::GetPropertyWithFailedAccessCheck(it);
      case LookupIterator::ACCESSOR:
        return GetPropertyWithAccessor(it);
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::DATA:
        return it->GetDataValue();
      case LookupIterator::NOT_FOUND:
        if (it->IsPrivateName()) {
          auto private_symbol = Cast<Symbol>(it->name());
          Handle<String> name_string(
              Cast<String>(private_symbol->description()), it->isolate());
          if (private_symbol->is_private_brand()) {
            Handle<String> class_name =
                (name_string->length() == 0)
                    ? it->isolate()->factory()->anonymous_string()
                    : name_string;
            THROW_NEW_ERROR(
                it->isolate(),
                NewTypeError(MessageTemplate::kInvalidPrivateBrandInstance,
                             class_name));
          }
          THROW_NEW_ERROR(
              it->isolate(),
              NewTypeError(MessageTemplate::kInvalidPrivateMemberRead,
                           name_string));
        }

        return it->isolate()->factory()->undefined_value();
    }
    UNREACHABLE();
  }
}

// static
MaybeHandle<JSAny> JSProxy::GetProperty(Isolate* isolate,
                                        DirectHandle<JSProxy> proxy,
                                        Handle<Name> name,
                                        Handle<JSAny> receiver,
                                        bool* was_found) {
  *was_found = true;

  DCHECK(!name->IsPrivate());
  STACK_CHECK(isolate, kNullMaybeHandle);
  Handle<Name> trap_name = isolate->factory()->get_string();
  // 1. Assert: IsPropertyKey(P) is true.
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<UnionOf<JSReceiver, Null>> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "get").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name));
  // 7. If trap is undefined, then
  if (IsUndefined(*trap, isolate)) {
    // 7.a Return target.[[Get]](P, Receiver).
    PropertyKey key(isolate, name);
    LookupIterator it(isolate, receiver, key, target);
    MaybeHandle<JSAny> result = Cast<JSAny>(Object::GetProperty(&it));
    *was_found = it.IsFound();
    return result;
  }
  // 8. Let trapResult be ? Call(trap, handler, «target, P, Receiver»).
  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name, receiver};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args));

  MaybeHandle<JSAny> result =
      JSProxy::CheckGetSetTrapResult(isolate, name, target, trap_result, kGet);
  if (result.is_null()) {
    return result;
  }

  // 11. Return trap_result
  return Cast<JSAny>(trap_result);
}

// static
MaybeHandle<JSAny> JSProxy::CheckGetSetTrapResult(Isolate* isolate,
                                                  Handle<Name> name,
                                                  Handle<JSReceiver> target,
                                                  Handle<Object> trap_result,
                                                  AccessKind access_kind) {
  // 9. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN_NULL(target_found);
  // 10. If targetDesc is not undefined, then
  if (target_found.FromJust()) {
    // 10.a. If IsDataDescriptor(targetDesc) and targetDesc.[[Configurable]] is
    //       false and targetDesc.[[Writable]] is false, then
    // 10.a.i. If SameValue(trapResult, targetDesc.[[Value]]) is false,
    //        throw a TypeError exception.
    bool inconsistent = PropertyDescriptor::IsDataDescriptor(&target_desc) &&
                        !target_desc.configurable() &&
                        !target_desc.writable() &&
                        !Object::SameValue(*trap_result, *target_desc.value());
    if (inconsistent) {
      if (access_kind == kGet) {
        THROW_NEW_ERROR(
            isolate, NewTypeError(MessageTemplate::kProxyGetNonConfigurableData,
                                  name, target_desc.value(), trap_result));
      } else {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxySetFrozenData, name));
        return {};
      }
    }
    // 10.b. If IsAccessorDescriptor(targetDesc) and targetDesc.[[Configurable]]
    //       is false and targetDesc.[[Get]] is undefined, then
    // 10.b.i. If trapResult is not undefined, throw a TypeError exception.
    if (access_kind == kGet) {
      inconsistent = PropertyDescriptor::IsAccessorDescriptor(&target_desc) &&
                     !target_desc.configurable() &&
                     IsUndefined(*target_desc.get(), isolate) &&
                     !IsUndefined(*trap_result, isolate);
    } else {
      inconsistent = PropertyDescriptor::IsAccessorDescriptor(&target_desc) &&
                     !target_desc.configurable() &&
                     IsUndefined(*target_desc.set(), isolate);
    }
    if (inconsistent) {
      if (access_kind == kGet) {
        THROW_NEW_ERROR(
            isolate,
            NewTypeError(MessageTemplate::kProxyGetNonConfigurableAccessor,
                         name, trap_result));
      } else {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxySetFrozenAccessor, name));
        return {};
      }
    }
  }
  return isolate->factory()->undefined_value();
}

// static
bool Object::ToInt32(Tagged<Object> obj, int32_t* value) {
  if (IsSmi(obj)) {
    *value = Smi::ToInt(obj);
    return true;
  }
  if (IsHeapNumber(obj)) {
    double num = Cast<HeapNumber>(obj)->value();
    // Check range before conversion to avoid undefined behavior.
    if (num >= kMinInt && num <= kMaxInt && FastI2D(FastD2I(num)) == num) {
      *value = FastD2I(num);
      return true;
    }
  }
  return false;
}

// ES6 9.5.1
// static
MaybeHandle<JSPrototype> JSProxy::GetPrototype(DirectHandle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  Handle<String> trap_name = isolate->factory()->getPrototypeOf_string();

  STACK_CHECK(isolate, {});

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot.
  // 2. If handler is null, throw a TypeError exception.
  // 3. Assert: Type(handler) is Object.
  // 4. Let target be the value of the [[ProxyTarget]] internal slot.
  if (proxy->IsRevoked()) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  // 5. Let trap be ? GetMethod(handler, "getPrototypeOf").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, trap,
                             Object::GetMethod(isolate, handler, trap_name));
  // 6. If trap is undefined, then return target.[[GetPrototypeOf]]().
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::GetPrototype(isolate, target);
  }
  // 7. Let handlerProto be ? Call(trap, handler, «target»).
  Handle<Object> argv[] = {target};
  Handle<Object> handler_proto_result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, handler_proto_result,
      Execution::Call(isolate, trap, handler, arraysize(argv), argv));
  // 8. If Type(handlerProto) is neither Object nor Null, throw a TypeError.
  Handle<JSPrototype> handler_proto;
  if (!TryCast(handler_proto_result, &handler_proto)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyGetPrototypeOfInvalid));
  }
  // 9. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> is_extensible = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(is_extensible, {});
  // 10. If extensibleTarget is true, return handlerProto.
  if (is_extensible.FromJust()) return handler_proto;
  // 11. Let targetProto be ? target.[[GetPrototypeOf]]().
  Handle<JSPrototype> target_proto;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, target_proto,
                             JSReceiver::GetPrototype(isolate, target));
  // 12. If SameValue(handlerProto, targetProto) is false, throw a TypeError.
  if (!Object::SameValue(*handler_proto, *target_proto)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kProxyGetPrototypeOfNonExtensible));
  }
  // 13. Return handlerProto.
  return handler_proto;
}

MaybeHandle<JSAny> Object::GetPropertyWithAccessor(LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<Object> structure = it->GetAccessors();
  Handle<JSAny> receiver = it->GetReceiver();
  // In case of global IC, the receiver is the global object. Replace by the
  // global proxy.
  if (IsJSGlobalObject(*receiver)) {
    receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(), isolate);
  }

  // We should never get here to initialize a const with the hole value since a
  // const declaration would conflict with the getter.
  DCHECK(!IsForeign(*structure));

  // API style callbacks.
  Handle<JSObject> holder = it->GetHolder<JSObject>();
  if (IsAccessorInfo(*structure)) {
    Handle<Name> name = it->GetName();
    auto info = Cast<AccessorInfo>(structure);

    if (!info->has_getter(isolate)) {
      return isolate->factory()->undefined_value();
    }

    if (info->is_sloppy() && !IsJSReceiver(*receiver)) {
      ASSIGN_RETURN_ON_EXCEPTION(isolate, receiver,
                                 Object::ConvertReceiver(isolate, receiver));
    }

    PropertyCallbackArguments args(isolate, info->data(), *receiver, *holder,
                                   Just(kDontThrow));
    Handle<JSAny> result = args.CallAccessorGetter(info, name);
    RETURN_EXCEPTION_IF_EXCEPTION(isolate);
    Handle<JSAny> reboxed_result = handle(*result, isolate);
    if (info->replace_on_access() && IsJSReceiver(*receiver)) {
      RETURN_ON_EXCEPTION(isolate,
                          Accessors::ReplaceAccessorWithDataProperty(
                              isolate, receiver, holder, name, result));
    }
    return reboxed_result;
  }

  auto accessor_pair = Cast<AccessorPair>(structure);
  // AccessorPair with 'cached' private property.
  if (it->TryLookupCachedProperty(accessor_pair)) {
    return Cast<JSAny>(Object::GetProperty(it));
  }

  // Regular accessor.
  Handle<Object> getter(accessor_pair->getter(), isolate);
  if (IsFunctionTemplateInfo(*getter)) {
    SaveAndSwitchContext save(isolate, holder->GetCreationContext().value());
    return Cast<JSAny>(Builtins::InvokeApiFunction(
        isolate, false, Cast<FunctionTemplateInfo>(getter), receiver, 0,
        nullptr, isolate->factory()->undefined_value()));
  } else if (IsCallable(*getter)) {
    // TODO(rossberg): nicer would be to cast to some JSCallable here...
    return Object::GetPropertyWithDefinedGetter(receiver,
                                                Cast<JSReceiver>(getter));
  }
  // Getter is not a function.
  return isolate->factory()->undefined_value();
}

Maybe<bool> Object::SetPropertyWithAccessor(
    LookupIterator* it, Handle<Object> value,
    Maybe<ShouldThrow> maybe_should_throw) {
  Isolate* isolate = it->isolate();
  Handle<Object> structure = it->GetAccessors();
  Handle<JSAny> receiver = it->GetReceiver();
  // In case of global IC, the receiver is the global object. Replace by the
  // global proxy.
  if (IsJSGlobalObject(*receiver)) {
    receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(), isolate);
  }

  // We should never get here to initialize a const with the hole value since a
  // const declaration would conflict with the setter.
  DCHECK(!IsForeign(*structure));

  // API style callbacks.
  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  if (IsAccessorInfo(*structure)) {
    Handle<Name> name = it->GetName();
    auto info = Cast<AccessorInfo>(structure);

    if (!info->has_setter(isolate)) {
      // TODO(verwaest): We should not get here anymore once all AccessorInfos
      // are marked as special_data_property. They cannot both be writable and
      // not have a setter.
      return Just(true);
    }

    if (info->is_sloppy() && !IsJSReceiver(*receiver)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, receiver, Object::ConvertReceiver(isolate, receiver),
          Nothing<bool>());
    }

    PropertyCallbackArguments args(isolate, info->data(), *receiver, *holder,
                                   maybe_should_throw);
    bool result = args.CallAccessorSetter(info, name, value);
    RETURN_VALUE_IF_EXCEPTION(isolate, Nothing<bool>());
    // Ensure the setter callback respects the "should throw" value - it's
    // allowed to fail without throwing only in case of kDontThrow.
    DCHECK_IMPLIES(!result,
                   GetShouldThrow(isolate, maybe_should_throw) == kDontThrow);
    return Just(result);
  }

  // Regular accessor.
  Handle<Object> setter(Cast<AccessorPair>(*structure)->setter(), isolate);
  if (IsFunctionTemplateInfo(*setter)) {
    SaveAndSwitchContext save(isolate, holder->GetCreationContext().value());
    Handle<Object> argv[] = {value};
    RETURN_ON_EXCEPTION_VALUE(
        isolate,
        Builtins::InvokeApiFunction(
            isolate, false, Cast<FunctionTemplateInfo>(setter), receiver,
            arraysize(argv), argv, isolate->factory()->undefined_value()),
        Nothing<bool>());
    return Just(true);
  } else if (IsCallable(*setter)) {
    // TODO(rossberg): nicer would be to cast to some JSCallable here...
    return SetPropertyWithDefinedSetter(receiver, Cast<JSReceiver>(setter),
                                        value, maybe_should_throw);
  }

  RETURN_FAILURE(isolate, GetShouldThrow(isolate, maybe_should_throw),
                 NewTypeError(MessageTemplate::kNoSetterInCallback,
                              it->GetName(), it->GetHolder<JSObject>()));
}

MaybeHandle<JSAny> Object::GetPropertyWithDefinedGetter(
    Handle<JSAny> receiver, Handle<JSReceiver> getter) {
  Isolate* isolate = getter->GetIsolate();

  // Platforms with simulators like arm/arm64 expose a funny issue. If the
  // simulator has a separate JS stack pointer from the C++ stack pointer, it
  // can miss C++ stack overflows in the stack guard at the start of JavaScript
  // functions. It would be very expensive to check the C++ stack pointer at
  // that location. The best solution seems to be to break the impasse by
  // adding checks at possible recursion points. What's more, we don't put
  // this stack check behind the USE_SIMULATOR define in order to keep
  // behavior the same between hardware and simulators.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed()) {
    isolate->StackOverflow();
    return kNullMaybeHandle;
  }

  return Cast<JSAny>(Execution::Call(isolate, getter, receiver, 0, nullptr));
}

Maybe<bool> Object::SetPropertyWithDefinedSetter(
    Handle<JSAny> receiver, Handle<JSReceiver> setter, Handle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = setter->GetIsolate();

  Handle<Object> argv[] = {value};
  RETURN_ON_EXCEPTION_VALUE(
      isolate,
      Execution::Call(isolate, setter, receiver, arraysize(argv), argv),
      Nothing<bool>());
  return Just(true);
}

// static
Tagged<Map> Object::GetPrototypeChainRootMap(Tagged<Object> obj,
                                             Isolate* isolate) {
  DisallowGarbageCollection no_alloc;
  if (IsSmi(obj)) {
    Tagged<Context> native_context = isolate->context()->native_context();
    return native_context->number_function()->initial_map();
  }

  const Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  return heap_object->map()->GetPrototypeChainRootMap(isolate);
}

// static
Tagged<Smi> Object::GetOrCreateHash(Tagged<Object> obj, Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> hash = Object::GetSimpleHash(obj);
  if (IsSmi(hash)) return Cast<Smi>(hash);

  DCHECK(IsJSReceiver(obj));
  return Cast<JSReceiver>(obj)->GetOrCreateIdentityHash(isolate);
}

// static
bool Object::SameValue(Tagged<Object> obj, Tagged<Object> other) {
  if (other == obj) return true;

  if (IsNumber(obj) && IsNumber(other)) {
    return SameNumberValue(Object::NumberValue(Cast<Number>(obj)),
                           Object::NumberValue(Cast<Number>(other)));
  }
  if (IsString(obj) && IsString(other)) {
    return Cast<String>(obj)->Equals(Cast<String>(other));
  }
  if (IsBigInt(obj) && IsBigInt(other)) {
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(other));
  }
  return false;
}

// static
bool Object::SameValueZero(Tagged<Object> obj, Tagged<Object> other) {
  if (other == obj) return true;

  if (IsNumber(obj) && IsNumber(other)) {
    double this_value = Object::NumberValue(Cast<Number>(obj));
    double other_value = Object::NumberValue(Cast<Number>(other));
    // +0 == -0 is true
    return this_value == other_value ||
           (std::isnan(this_value) && std::isnan(other_value));
  }
  if (IsString(obj) && IsString(other)) {
    return Cast<String>(obj)->Equals(Cast<String>(other));
  }
  if (IsBigInt(obj) && IsBigInt(other)) {
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(other));
  }
  return false;
}

MaybeHandle<Object> Object::ArraySpeciesConstructor(
    Isolate* isolate, Handle<JSAny> original_array) {
  Handle<Object> default_species = isolate->array_function();
  if (!v8_flags.builtin_subclassing) return default_species;
  if (IsJSArray(*original_array) &&
      Cast<JSArray>(original_array)->HasArrayPrototype(isolate) &&
      Protectors::IsArraySpeciesLookupChainIntact(isolate)) {
    return default_species;
  }
  Handle<Object> constructor = isolate->factory()->undefined_value();
  Maybe<bool> is_array = IsArray(original_array);
  MAYBE_RETURN_NULL(is_array);
  if (is_array.FromJust()) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, constructor,
        Object::GetProperty(isolate, original_array,
                            isolate->factory()->constructor_string()));
    if (IsConstructor(*constructor)) {
      Handle<NativeContext> constructor_context;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, constructor_context,
          JSReceiver::GetFunctionRealm(Cast<JSReceiver>(constructor)));
      if (*constructor_context != *isolate->native_context() &&
          *constructor == constructor_context->array_function()) {
        constructor = isolate->factory()->undefined_value();
      }
    }
    if (IsJSReceiver(*constructor)) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, constructor,
          JSReceiver::GetProperty(isolate, Cast<JSReceiver>(constructor),
                                  isolate->factory()->species_symbol()));
      if (IsNull(*constructor, isola
"""


```