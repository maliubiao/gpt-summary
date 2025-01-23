Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/init/bootstrapper.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Functionality:**  The code is primarily involved in setting up built-in objects and functions within the V8 JavaScript engine's initial environment. This includes error handling mechanisms and the new Temporal API.

2. **Analyze the `InstallError` Function:** This function is clearly about setting up error objects. Key aspects to note are:
    * Creating a `JSFunction` for the error constructor.
    * Setting up the prototype object (`%XXXErrorPrototype%`).
    * Installing properties like `name` and `message` on the prototype.
    * Installing the `toString` method on the `Error.prototype`.
    * Handling inheritance for different error types.
    * Setting up internal symbols for `stack` and `message`.

3. **Analyze the `InitializeTemporal` Function:** This function focuses on setting up the ECMAScript Temporal API. Key observations:
    * It checks if the Temporal object has already been initialized.
    * It creates a `Temporal` global object.
    * It installs nested objects like `Temporal.Now`.
    * It defines and installs constructors for various Temporal types (`PlainDate`, `PlainTime`, etc.).
    * It installs methods (getters and regular functions) on the prototypes of these Temporal types.

4. **Determine the File Type:** The prompt explicitly states to check the file extension. Since the extension is `.cc`, it's a C++ source file, not a Torque file.

5. **Relate to JavaScript Functionality:**  Connect the C++ code to its JavaScript equivalents.
    * `InstallError` relates to the creation and behavior of `Error`, `TypeError`, `RangeError`, etc. in JavaScript.
    * `InitializeTemporal` directly relates to the usage of the `Temporal` API in JavaScript.

6. **Provide JavaScript Examples:**  Illustrate the C++ functionality with concrete JavaScript examples. Show how to create and use error objects and Temporal objects.

7. **Address Code Logic and Assumptions:** For `InstallError`, the logic is primarily about setting up the object structure. We can infer assumptions about the input (isolate, global object, error name, etc.) and the resulting output (a properly constructed error constructor and prototype). For `InitializeTemporal`, the logic is about registering the Temporal API objects and their methods within the V8 environment.

8. **Identify Common Programming Errors:** Think about typical mistakes developers might make related to errors and the Temporal API.
    * Incorrectly throwing or catching errors.
    * Misunderstanding the immutability of Temporal objects.
    * Using incorrect arguments or methods with Temporal objects.

9. **Summarize the Functionality:**  Provide a concise summary of the code's purpose based on the analysis.

10. **Structure the Response:**  Organize the information clearly with headings for each aspect of the request (Functionality, File Type, JavaScript Relation, Examples, Logic, Errors, Summary). Use bullet points and code formatting to enhance readability.

11. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Make any necessary corrections or additions. For instance, initially, I might have focused solely on the instantiation aspect but realizing the importance of method installation within `InitializeTemporal` is crucial for a complete understanding. Similarly, detailing the prototype chain setup in `InstallError` provides more depth.
这是对 V8 源代码文件 `v8/src/init/bootstrapper.cc` 的第三部分分析，主要关注了两个核心功能：**安装错误对象**和**初始化 Temporal API**。

**1. 功能列举:**

* **`InstallWithIntrinsicDefaultProto(Isolate* isolate, Handle<JSFunction> function, int context_index)`:**
    * 为给定的 JavaScript 函数设置一个内部的 `native_context_index_symbol` 属性，用于关联函数和 NativeContext。
    * 将该函数存储在 NativeContext 的指定索引位置。

* **`InstallError(Isolate* isolate, Handle<JSObject> global, Handle<String> name, int context_index, Builtin error_constructor, int error_function_length)`:**
    * 在全局对象上安装一个新的错误构造函数（例如 `Error`, `TypeError`）。
    * 创建错误构造函数对象，并设置其类型为 `JS_ERROR_TYPE`。
    * 如果是 `Error` 构造函数，还会安装 `captureStackTrace` 方法。
    * 调用 `InstallWithIntrinsicDefaultProto` 设置内部属性。
    * 设置错误构造函数的原型对象 (`%XXXErrorPrototype%`)。
    * 在原型对象上添加 `name` 和 `message` 属性，并设置为不可枚举。
    * 如果是 `Error` 构造函数，还会安装 `toString` 方法并设置初始的 error prototype。
    * 如果不是 `Error` 构造函数，则将其原型链连接到全局的 `Error` 构造函数及其原型。
    * 在错误构造函数的初始 Map 中预留空间并添加用于存储 `stack` 和 `message` 的内部符号，以及可访问的 `stack` 属性 (通过 getter/setter)。

* **`InitializeTemporal(Isolate* isolate)`:**
    * 初始化 ECMAScript 的 Temporal API。
    * 创建全局对象 `Temporal`，如果已经初始化则直接返回。
    * 在 `Temporal` 对象上安装 `Now` 子对象，包含获取当前日期和时间的不同方法（例如 `timeZone`, `instant`, `plainDateTime` 等）。
    * 为 `Temporal` API 中的各种类（例如 `PlainDate`, `PlainTime`, `PlainDateTime`, `ZonedDateTime`, `Duration`, `Instant`, `PlainYearMonth`, `PlainMonthDay`, `TimeZone`, `Calendar`）安装构造函数和原型对象。
    * 在每个 Temporal 类的原型对象上安装各种方法，例如 `from`, `compare`, `add`, `subtract`, `with`, `toString`, `toJSON` 等。
    * 创建内部使用的函数 `StringFixedArrayFromIterable` 和 `TemporalInstantFixedArrayFromIterable`。
    * 将初始化后的 `Temporal` 对象存储在 NativeContext 中。

* **`LazyInitializeDateToTemporalInstant(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)`:**
    * 一个延迟初始化的回调函数，当访问 `Date.prototype.toTemporalInstant` 时被调用。
    * 确保 `Temporal` API 已初始化。
    * 创建并返回 `Date.prototype.toTemporalInstant` 函数。

* **`LazyInitializeGlobalThisTemporal(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)`:**
    * 一个延迟初始化的回调函数，当访问全局的 `Temporal` 对象时被调用。
    * 确保 `Temporal` API 已初始化。
    * 返回初始化后的 `Temporal` 对象。

* **`Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object, Handle<JSFunction> empty_function)`:**
    *  在非快照模式下初始化全局对象时被调用。
    *  设置 NativeContext 的扩展和全局对象。
    *  设置 NativeContext 的安全令牌。
    *  创建和设置 Context 相关的 Map。

**2. 文件类型判断:**

`v8/src/init/bootstrapper.cc` 的后缀是 `.cc`，因此它是一个 **V8 C++ 源代码文件**。它不是以 `.tq` 结尾，所以不是 V8 Torque 源代码。

**3. 与 JavaScript 功能的关系及示例:**

* **`InstallError` 与 JavaScript 的 `Error` 对象及其子类型 (`TypeError`, `RangeError` 等) 的创建和行为息息相关。**

   ```javascript
   // 当 JavaScript 代码抛出一个错误时，例如：
   throw new Error('Something went wrong!');

   // 或者使用内置的错误类型：
   throw new TypeError('Invalid type!');

   // 这些错误对象会继承自 Error.prototype，拥有 name 和 message 属性
   try {
       // 一些可能抛出错误的代码
   } catch (e) {
       console.log(e.name);    // 输出 "Error" 或 "TypeError"
       console.log(e.message); // 输出错误消息
       console.log(e.stack);   // 输出调用堆栈信息
   }

   // Error.captureStackTrace 方法允许手动捕获堆栈信息
   const error = new Error('My Error');
   Error.captureStackTrace(error, Error); // 通常排除 Error 构造函数自身
   console.log(error.stack);
   ```

* **`InitializeTemporal` 负责初始化 JavaScript 中新的 `Temporal` API，用于处理日期和时间。**

   ```javascript
   // 获取当前时间
   const now = Temporal.Now.plainDateTimeISO();
   console.log(now.toString());

   // 创建一个特定的日期
   const date = new Temporal.PlainDate(2023, 10, 26);
   console.log(date.toString());

   // 使用 Temporal.Duration 表示时间间隔
   const duration = new Temporal.Duration(1, 2, 0, 5); // 1年, 2个月, 5天
   console.log(duration.toString());

   // 在日期上添加时间间隔
   const futureDate = date.add(duration);
   console.log(futureDate.toString());

   // 将 JavaScript Date 对象转换为 Temporal.Instant
   const jsDate = new Date();
   const temporalInstant = jsDate.toTemporalInstant();
   console.log(temporalInstant.toString());
   ```

**4. 代码逻辑推理及假设输入输出:**

**`InstallError` 示例:**

* **假设输入:**
    * `isolate`: 当前 V8 引擎的隔离环境。
    * `global`: 全局对象（例如 `window` 或 Node.js 的 `global`）。
    * `name`: 字符串 "TypeError"。
    * `context_index`: `Context::TYPE_ERROR_FUNCTION_INDEX`。
    * `error_constructor`:  `Builtin::kTypeErrorConstructor`。
    * `error_function_length`: 1 (TypeError 构造函数通常接受一个参数，即错误消息)。

* **推理逻辑:**
    1. 创建一个名为 "TypeError" 的 `JSFunction` 对象。
    2. 将其与 `Context::TYPE_ERROR_FUNCTION_INDEX` 关联。
    3. 创建 "TypeError.prototype" 对象。
    4. 在 "TypeError.prototype" 上设置 `name` 为 "TypeError" 和 `message` 为空字符串。
    5. 将 "TypeError" 构造函数的原型链指向全局的 `Error` 构造函数及其原型，实现继承。
    6. 在 "TypeError" 构造函数的初始 Map 中添加用于存储 `stack` 和 `message` 的内部符号，并设置可访问的 `stack` 属性。

* **预期输出:**
    * 全局对象上新增一个 `TypeError` 属性，指向新创建的错误构造函数。
    * `TypeError` 是一个函数对象。
    * `TypeError.prototype` 是一个对象，拥有 `name` 和 `message` 属性，并且其 `[[Prototype]]` 指向 `Error.prototype`。

**`InitializeTemporal` 示例:**

* **假设输入:**
    * `isolate`: 当前 V8 引擎的隔离环境。

* **推理逻辑:**
    1. 检查 NativeContext 中是否已存在 `temporal_object`。如果存在，直接返回。
    2. 创建一个新的 `JSObject` 作为全局的 `Temporal` 对象。
    3. 在 `Temporal` 对象上添加名为 "Now" 的子对象。
    4. 为 `Temporal.Now` 对象添加各种获取当前时间的方法，例如 `timeZone`, `instant` 等，这些方法会关联到不同的内置函数（Builtin）。
    5. 创建并安装 `Temporal.PlainDate` 构造函数及其原型，并在原型上安装诸如 `from`, `add`, `toString` 等方法，这些方法也会关联到相应的内置函数。
    6. 对 `Temporal` API 中的其他类重复上述过程。
    7. 将创建的 `Temporal` 对象存储到 NativeContext 中。

* **预期输出:**
    * NativeContext 中 `temporal_object` 被设置为新创建的 `Temporal` 对象。
    * 全局作用域中将会存在 `Temporal` 对象，可以通过 JavaScript 代码访问。
    * `Temporal` 对象拥有各种子对象和构造函数，以及它们的原型对象和方法。

**5. 涉及用户常见的编程错误:**

* **对于错误处理:**
    * **不正确地抛出错误类型:** 用户可能抛出一个通用的 `Error` 对象，而不是更具体的错误类型（如 `TypeError` 或 `RangeError`），导致错误信息不够明确。
      ```javascript
      // 错误示例
      function process(input) {
          if (typeof input !== 'number') {
              throw new Error('Input must be a number'); // 应该抛出 TypeError
          }
          // ...
      }
      ```
    * **没有正确捕获和处理错误:**  用户可能忘记使用 `try...catch` 语句来捕获可能发生的错误，导致程序崩溃。
      ```javascript
      // 错误示例
      function mightFail() {
          // ... 一些可能抛出错误的代码
      }
      mightFail(); // 如果 mightFail 抛出错误，程序会崩溃
      ```
    * **滥用 `throw` 语句抛出非 `Error` 对象:** 虽然 JavaScript 允许抛出任何类型的值，但通常建议抛出 `Error` 对象或其子类的实例，以便提供更一致的错误信息和堆栈跟踪。
      ```javascript
      // 不推荐
      throw 'Something went wrong';
      throw 123;
      ```

* **对于 Temporal API:**
    * **直接修改 Temporal 对象:**  Temporal API 中的对象是不可变的。尝试直接修改其属性会导致错误或无效的操作。用户应该使用 `with` 方法创建新的修改后的对象。
      ```javascript
      const date = new Temporal.PlainDate(2023, 10, 26);
      // 错误示例：直接修改属性
      // date.month = 11; // 这样做不会生效

      // 正确做法：使用 with 方法
      const newDate = date.with({ month: 11 });
      console.log(newDate.toString());
      ```
    * **使用不正确的单位或参数:**  Temporal API 的方法通常对参数类型和单位有严格的要求。使用错误的单位或参数会导致错误。
      ```javascript
      const date = new Temporal.PlainDate(2023, 10, 26);
      // 错误示例：使用字符串作为月份
      // const invalidDate = date.with({ month: 'November' }); // 可能会抛出错误

      // 正确做法：使用数字表示月份
      const validDate = date.with({ month: 11 });
      ```
    * **混淆不同的 Temporal 类型:**  用户可能会混淆 `PlainDate`, `PlainTime`, `Instant`, `ZonedDateTime` 等不同的 Temporal 类型，并在不适用的场景下使用它们。

**6. 功能归纳:**

作为第 3 部分，`v8/src/init/bootstrapper.cc` 的这段代码主要负责 V8 引擎启动时的关键初始化工作：

* **建立了 JavaScript 错误处理的基础设施，**包括 `Error` 构造函数及其子类型的创建、原型链的设置以及堆栈信息的管理。这确保了 JavaScript 代码可以正常地抛出和捕获错误。
* **引入并初始化了新的 ECMAScript Temporal API，**为 JavaScript 提供了现代化的日期和时间处理能力。这涉及到创建 `Temporal` 全局对象，注册各种 Temporal 类及其方法，使得开发者可以在 JavaScript 中使用这些新的日期和时间 API。

总而言之，这部分代码是 V8 引擎构建其核心 JavaScript 环境的重要组成部分，为错误处理和现代日期时间操作提供了必要的支持。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
the constructor has
// non-instance prototype.
static void InstallWithIntrinsicDefaultProto(Isolate* isolate,
                                             Handle<JSFunction> function,
                                             int context_index) {
  DirectHandle<Smi> index(Smi::FromInt(context_index), isolate);
  JSObject::AddProperty(isolate, function,
                        isolate->factory()->native_context_index_symbol(),
                        index, NONE);
  isolate->native_context()->set(context_index, *function, UPDATE_WRITE_BARRIER,
                                 kReleaseStore);
}

static void InstallError(Isolate* isolate, Handle<JSObject> global,
                         Handle<String> name, int context_index,
                         Builtin error_constructor = Builtin::kErrorConstructor,
                         int error_function_length = 1) {
  Factory* factory = isolate->factory();

  // Most Error objects consist of a message, a stack trace, and possibly a
  // cause. Reserve three in-object properties for these.
  const int in_object_properties = 3;
  const int kErrorObjectSize =
      JSObject::kHeaderSize + in_object_properties * kTaggedSize;
  Handle<JSFunction> error_fun =
      InstallFunction(isolate, global, name, JS_ERROR_TYPE, kErrorObjectSize,
                      in_object_properties, factory->the_hole_value(),
                      error_constructor, error_function_length, kDontAdapt);

  if (context_index == Context::ERROR_FUNCTION_INDEX) {
    SimpleInstallFunction(isolate, error_fun, "captureStackTrace",
                          Builtin::kErrorCaptureStackTrace, 2, kDontAdapt);
  }

  InstallWithIntrinsicDefaultProto(isolate, error_fun, context_index);

  {
    // Setup %XXXErrorPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(error_fun->instance_prototype()),
                               isolate);

    JSObject::AddProperty(isolate, prototype, factory->name_string(), name,
                          DONT_ENUM);
    JSObject::AddProperty(isolate, prototype, factory->message_string(),
                          factory->empty_string(), DONT_ENUM);

    if (context_index == Context::ERROR_FUNCTION_INDEX) {
      DirectHandle<JSFunction> to_string_fun =
          SimpleInstallFunction(isolate, prototype, "toString",
                                Builtin::kErrorPrototypeToString, 0, kAdapt);
      isolate->native_context()->set_error_to_string(*to_string_fun);
      isolate->native_context()->set_initial_error_prototype(*prototype);
    } else {
      Handle<JSFunction> global_error = isolate->error_function();
      CHECK(JSReceiver::SetPrototype(isolate, error_fun, global_error, false,
                                     kThrowOnError)
                .FromMaybe(false));
      CHECK(JSReceiver::SetPrototype(isolate, prototype,
                                     handle(global_error->prototype(), isolate),
                                     false, kThrowOnError)
                .FromMaybe(false));
    }
  }

  DirectHandle<Map> initial_map(error_fun->initial_map(), isolate);
  Map::EnsureDescriptorSlack(isolate, initial_map, 3);
  const int kJSErrorErrorStackSymbolIndex = 0;
  const int kJSErrorErrorMessageSymbolIndex = 1;

  {  // error_stack_symbol
    Descriptor d = Descriptor::DataField(isolate, factory->error_stack_symbol(),
                                         kJSErrorErrorStackSymbolIndex,
                                         DONT_ENUM, Representation::Tagged());
    initial_map->AppendDescriptor(isolate, &d);
  }
  {
    // error_message_symbol
    Descriptor d = Descriptor::DataField(
        isolate, factory->error_message_symbol(),
        kJSErrorErrorMessageSymbolIndex, DONT_ENUM, Representation::Tagged());
    initial_map->AppendDescriptor(isolate, &d);
  }
  {  // stack
    Handle<AccessorPair> new_pair = factory->NewAccessorPair();
    new_pair->set_getter(*factory->error_stack_getter_fun_template());
    new_pair->set_setter(*factory->error_stack_setter_fun_template());

    Descriptor d = Descriptor::AccessorConstant(factory->stack_string(),
                                                new_pair, DONT_ENUM);
    initial_map->AppendDescriptor(isolate, &d);
  }
}

namespace {

Handle<JSObject> InitializeTemporal(Isolate* isolate) {
  DirectHandle<NativeContext> native_context = isolate->native_context();

  // Already initialized?
  Handle<HeapObject> maybe_temporal(native_context->temporal_object(), isolate);
  if (IsJSObject(*maybe_temporal)) {
    return Cast<JSObject>(maybe_temporal);
  }

  isolate->CountUsage(v8::Isolate::kTemporalObject);

  // -- T e m p o r a l
  // #sec-temporal-objects
  Handle<JSObject> temporal = isolate->factory()->NewJSObject(
      isolate->object_function(), AllocationType::kOld);

  // The initial value of the @@toStringTag property is the string value
  // *"Temporal"*.
  // https://github.com/tc39/proposal-temporal/issues/1539
  InstallToStringTag(isolate, temporal, "Temporal");

  {  // -- N o w
    // #sec-temporal-now-object
    Handle<JSObject> now = isolate->factory()->NewJSObject(
        isolate->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate, temporal, "Now", now, DONT_ENUM);
    InstallToStringTag(isolate, now, "Temporal.Now");

    // Note: There are NO Temporal.Now.plainTime
    // See https://github.com/tc39/proposal-temporal/issues/1540
#define NOW_LIST(V)                        \
  V(timeZone, TimeZone, 0)                 \
  V(instant, Instant, 0)                   \
  V(plainDateTime, PlainDateTime, 1)       \
  V(plainDateTimeISO, PlainDateTimeISO, 0) \
  V(zonedDateTime, ZonedDateTime, 1)       \
  V(zonedDateTimeISO, ZonedDateTimeISO, 0) \
  V(plainDate, PlainDate, 1)               \
  V(plainDateISO, PlainDateISO, 0)         \
  V(plainTimeISO, PlainTimeISO, 0)

#define INSTALL_NOW_FUNC(p, N, n)                                      \
  SimpleInstallFunction(isolate, now, #p, Builtin::kTemporalNow##N, n, \
                        kDontAdapt);

    NOW_LIST(INSTALL_NOW_FUNC)
#undef INSTALL_NOW_FUNC
#undef NOW_LIST
  }
#define INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(N, U, NUM_ARGS)                    \
  Handle<JSFunction> obj_func = InstallFunction(                               \
      isolate, temporal, #N, JS_TEMPORAL_##U##_TYPE,                           \
      JSTemporal##N::kHeaderSize, 0, isolate->factory()->the_hole_value(),     \
      Builtin::kTemporal##N##Constructor, NUM_ARGS, kDontAdapt);               \
  InstallWithIntrinsicDefaultProto(isolate, obj_func,                          \
                                   Context::JS_TEMPORAL_##U##_FUNCTION_INDEX); \
  Handle<JSObject> prototype(Cast<JSObject>(obj_func->instance_prototype()),   \
                             isolate);                                         \
  InstallToStringTag(isolate, prototype, "Temporal." #N);

#define INSTALL_TEMPORAL_FUNC(T, name, N, arg)                              \
  SimpleInstallFunction(isolate, obj_func, #name, Builtin::kTemporal##T##N, \
                        arg, kDontAdapt);

  {  // -- P l a i n D a t e
     // #sec-temporal-plaindate-objects
     // #sec-temporal.plaindate
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(PlainDate, PLAIN_DATE, 3)
    INSTALL_TEMPORAL_FUNC(PlainDate, from, From, 1)
    INSTALL_TEMPORAL_FUNC(PlainDate, compare, Compare, 2)

#ifdef V8_INTL_SUPPORT
#define PLAIN_DATE_GETTER_LIST_INTL(V) \
  V(era, Era)                          \
  V(eraYear, EraYear)
#else
#define PLAIN_DATE_GETTER_LIST_INTL(V)
#endif  // V8_INTL_SUPPORT

#define PLAIN_DATE_GETTER_LIST(V) \
  PLAIN_DATE_GETTER_LIST_INTL(V)  \
  V(calendar, Calendar)           \
  V(year, Year)                   \
  V(month, Month)                 \
  V(monthCode, MonthCode)         \
  V(day, Day)                     \
  V(dayOfWeek, DayOfWeek)         \
  V(dayOfYear, DayOfYear)         \
  V(weekOfYear, WeekOfYear)       \
  V(daysInWeek, DaysInWeek)       \
  V(daysInMonth, DaysInMonth)     \
  V(daysInYear, DaysInYear)       \
  V(monthsInYear, MonthsInYear)   \
  V(inLeapYear, InLeapYear)

#define INSTALL_PLAIN_DATE_GETTER_FUNC(p, N)                                \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalPlainDatePrototype##N, kAdapt);

    PLAIN_DATE_GETTER_LIST(INSTALL_PLAIN_DATE_GETTER_FUNC)
#undef PLAIN_DATE_GETTER_LIST
#undef PLAIN_DATE_GETTER_LIST_INTL
#undef INSTALL_PLAIN_DATE_GETTER_FUNC

#define PLAIN_DATE_FUNC_LIST(V)            \
  V(toPlainYearMonth, ToPlainYearMonth, 0) \
  V(toPlainMonthDay, ToPlainMonthDay, 0)   \
  V(getISOFiels, GetISOFields, 0)          \
  V(add, Add, 1)                           \
  V(subtract, Subtract, 1)                 \
  V(with, With, 1)                         \
  V(withCalendar, WithCalendar, 1)         \
  V(until, Until, 1)                       \
  V(since, Since, 1)                       \
  V(equals, Equals, 1)                     \
  V(getISOFields, GetISOFields, 0)         \
  V(toLocaleString, ToLocaleString, 0)     \
  V(toPlainDateTime, ToPlainDateTime, 0)   \
  V(toZonedDateTime, ToZonedDateTime, 1)   \
  V(toString, ToString, 0)                 \
  V(toJSON, ToJSON, 0)                     \
  V(valueOf, ValueOf, 0)

#define INSTALL_PLAIN_DATE_FUNC(p, N, min)                            \
  SimpleInstallFunction(isolate, prototype, #p,                       \
                        Builtin::kTemporalPlainDatePrototype##N, min, \
                        kDontAdapt);
    PLAIN_DATE_FUNC_LIST(INSTALL_PLAIN_DATE_FUNC)
#undef PLAIN_DATE_FUNC_LIST
#undef INSTALL_PLAIN_DATE_FUNC
  }
  {  // -- P l a i n T i m e
     // #sec-temporal-plaintime-objects
     // #sec-temporal.plaintime
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(PlainTime, PLAIN_TIME, 0)
    INSTALL_TEMPORAL_FUNC(PlainTime, from, From, 1)
    INSTALL_TEMPORAL_FUNC(PlainTime, compare, Compare, 2)

#define PLAIN_TIME_GETTER_LIST(V) \
  V(calendar, Calendar)           \
  V(hour, Hour)                   \
  V(minute, Minute)               \
  V(second, Second)               \
  V(millisecond, Millisecond)     \
  V(microsecond, Microsecond)     \
  V(nanosecond, Nanosecond)

#define INSTALL_PLAIN_TIME_GETTER_FUNC(p, N)                                \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalPlainTimePrototype##N, kAdapt);

    PLAIN_TIME_GETTER_LIST(INSTALL_PLAIN_TIME_GETTER_FUNC)
#undef PLAIN_TIME_GETTER_LIST
#undef INSTALL_PLAIN_TIME_GETTER_FUNC

#define PLAIN_TIME_FUNC_LIST(V)          \
  V(add, Add, 1)                         \
  V(subtract, Subtract, 1)               \
  V(with, With, 1)                       \
  V(until, Until, 1)                     \
  V(since, Since, 1)                     \
  V(round, Round, 1)                     \
  V(equals, Equals, 1)                   \
  V(toPlainDateTime, ToPlainDateTime, 1) \
  V(toZonedDateTime, ToZonedDateTime, 1) \
  V(getISOFields, GetISOFields, 0)       \
  V(toLocaleString, ToLocaleString, 0)   \
  V(toString, ToString, 0)               \
  V(toJSON, ToJSON, 0)                   \
  V(valueOf, ValueOf, 0)

#define INSTALL_PLAIN_TIME_FUNC(p, N, min)                            \
  SimpleInstallFunction(isolate, prototype, #p,                       \
                        Builtin::kTemporalPlainTimePrototype##N, min, \
                        kDontAdapt);
    PLAIN_TIME_FUNC_LIST(INSTALL_PLAIN_TIME_FUNC)
#undef PLAIN_TIME_FUNC_LIST
#undef INSTALL_PLAIN_TIME_FUNC
  }
  {  // -- P l a i n D a t e T i m e
    // #sec-temporal-plaindatetime-objects
    // #sec-temporal.plaindatetime
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(PlainDateTime, PLAIN_DATE_TIME, 3)
    INSTALL_TEMPORAL_FUNC(PlainDateTime, from, From, 1)
    INSTALL_TEMPORAL_FUNC(PlainDateTime, compare, Compare, 2)

#ifdef V8_INTL_SUPPORT
#define PLAIN_DATE_TIME_GETTER_LIST_INTL(V) \
  V(era, Era)                               \
  V(eraYear, EraYear)
#else
#define PLAIN_DATE_TIME_GETTER_LIST_INTL(V)
#endif  // V8_INTL_SUPPORT

#define PLAIN_DATE_TIME_GETTER_LIST(V) \
  PLAIN_DATE_TIME_GETTER_LIST_INTL(V)  \
  V(calendar, Calendar)                \
  V(year, Year)                        \
  V(month, Month)                      \
  V(monthCode, MonthCode)              \
  V(day, Day)                          \
  V(hour, Hour)                        \
  V(minute, Minute)                    \
  V(second, Second)                    \
  V(millisecond, Millisecond)          \
  V(microsecond, Microsecond)          \
  V(nanosecond, Nanosecond)            \
  V(dayOfWeek, DayOfWeek)              \
  V(dayOfYear, DayOfYear)              \
  V(weekOfYear, WeekOfYear)            \
  V(daysInWeek, DaysInWeek)            \
  V(daysInMonth, DaysInMonth)          \
  V(daysInYear, DaysInYear)            \
  V(monthsInYear, MonthsInYear)        \
  V(inLeapYear, InLeapYear)

#define INSTALL_PLAIN_DATE_TIME_GETTER_FUNC(p, N)                           \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalPlainDateTimePrototype##N, kAdapt);

    PLAIN_DATE_TIME_GETTER_LIST(INSTALL_PLAIN_DATE_TIME_GETTER_FUNC)
#undef PLAIN_DATE_TIME_GETTER_LIST
#undef PLAIN_DATE_TIME_GETTER_LIST_INTL
#undef INSTALL_PLAIN_DATE_TIME_GETTER_FUNC

#define PLAIN_DATE_TIME_FUNC_LIST(V)       \
  V(with, With, 1)                         \
  V(withPlainTime, WithPlainTime, 0)       \
  V(withPlainDate, WithPlainDate, 1)       \
  V(withCalendar, WithCalendar, 1)         \
  V(add, Add, 1)                           \
  V(subtract, Subtract, 1)                 \
  V(until, Until, 1)                       \
  V(since, Since, 1)                       \
  V(round, Round, 1)                       \
  V(equals, Equals, 1)                     \
  V(toLocaleString, ToLocaleString, 0)     \
  V(toJSON, ToJSON, 0)                     \
  V(toString, ToString, 0)                 \
  V(valueOf, ValueOf, 0)                   \
  V(toZonedDateTime, ToZonedDateTime, 1)   \
  V(toPlainDate, ToPlainDate, 0)           \
  V(toPlainYearMonth, ToPlainYearMonth, 0) \
  V(toPlainMonthDay, ToPlainMonthDay, 0)   \
  V(toPlainTime, ToPlainTime, 0)           \
  V(getISOFields, GetISOFields, 0)

#define INSTALL_PLAIN_DATE_TIME_FUNC(p, N, min)                           \
  SimpleInstallFunction(isolate, prototype, #p,                           \
                        Builtin::kTemporalPlainDateTimePrototype##N, min, \
                        kDontAdapt);
    PLAIN_DATE_TIME_FUNC_LIST(INSTALL_PLAIN_DATE_TIME_FUNC)
#undef PLAIN_DATE_TIME_FUNC_LIST
#undef INSTALL_PLAIN_DATE_TIME_FUNC
  }
  {  // -- Z o n e d D a t e T i m e
    // #sec-temporal-zoneddatetime-objects
    // #sec-temporal.zoneddatetime
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(ZonedDateTime, ZONED_DATE_TIME, 2)
    INSTALL_TEMPORAL_FUNC(ZonedDateTime, from, From, 1)
    INSTALL_TEMPORAL_FUNC(ZonedDateTime, compare, Compare, 2)

#ifdef V8_INTL_SUPPORT
#define ZONED_DATE_TIME_GETTER_LIST_INTL(V) \
  V(era, Era)                               \
  V(eraYear, EraYear)
#else
#define ZONED_DATE_TIME_GETTER_LIST_INTL(V)
#endif  // V8_INTL_SUPPORT

#define ZONED_DATE_TIME_GETTER_LIST(V)    \
  ZONED_DATE_TIME_GETTER_LIST_INTL(V)     \
  V(calendar, Calendar)                   \
  V(timeZone, TimeZone)                   \
  V(year, Year)                           \
  V(month, Month)                         \
  V(monthCode, MonthCode)                 \
  V(day, Day)                             \
  V(hour, Hour)                           \
  V(minute, Minute)                       \
  V(second, Second)                       \
  V(millisecond, Millisecond)             \
  V(microsecond, Microsecond)             \
  V(nanosecond, Nanosecond)               \
  V(epochSeconds, EpochSeconds)           \
  V(epochMilliseconds, EpochMilliseconds) \
  V(epochMicroseconds, EpochMicroseconds) \
  V(epochNanoseconds, EpochNanoseconds)   \
  V(dayOfWeek, DayOfWeek)                 \
  V(dayOfYear, DayOfYear)                 \
  V(weekOfYear, WeekOfYear)               \
  V(hoursInDay, HoursInDay)               \
  V(daysInWeek, DaysInWeek)               \
  V(daysInMonth, DaysInMonth)             \
  V(daysInYear, DaysInYear)               \
  V(monthsInYear, MonthsInYear)           \
  V(inLeapYear, InLeapYear)               \
  V(offsetNanoseconds, OffsetNanoseconds) \
  V(offset, Offset)

#define INSTALL_ZONED_DATE_TIME_GETTER_FUNC(p, N)                           \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalZonedDateTimePrototype##N, kAdapt);

    ZONED_DATE_TIME_GETTER_LIST(INSTALL_ZONED_DATE_TIME_GETTER_FUNC)
#undef ZONED_DATE_TIME_GETTER_LIST
#undef ZONED_DATE_TIME_GETTER_LIST_INTL
#undef INSTALL_ZONED_DATE_TIME_GETTER_FUNC

#define ZONED_DATE_TIME_FUNC_LIST(V)       \
  V(with, With, 1)                         \
  V(withPlainTime, WithPlainTime, 0)       \
  V(withPlainDate, WithPlainDate, 1)       \
  V(withTimeZone, WithTimeZone, 1)         \
  V(withCalendar, WithCalendar, 1)         \
  V(add, Add, 1)                           \
  V(subtract, Subtract, 1)                 \
  V(until, Until, 1)                       \
  V(since, Since, 1)                       \
  V(round, Round, 1)                       \
  V(equals, Equals, 1)                     \
  V(toLocaleString, ToLocaleString, 0)     \
  V(toString, ToString, 0)                 \
  V(toJSON, ToJSON, 0)                     \
  V(valueOf, ValueOf, 0)                   \
  V(startOfDay, StartOfDay, 0)             \
  V(toInstant, ToInstant, 0)               \
  V(toPlainDate, ToPlainDate, 0)           \
  V(toPlainTime, ToPlainTime, 0)           \
  V(toPlainDateTime, ToPlainDateTime, 0)   \
  V(toPlainYearMonth, ToPlainYearMonth, 0) \
  V(toPlainMonthDay, ToPlainMonthDay, 0)   \
  V(getISOFields, GetISOFields, 0)

#define INSTALL_ZONED_DATE_TIME_FUNC(p, N, min)                           \
  SimpleInstallFunction(isolate, prototype, #p,                           \
                        Builtin::kTemporalZonedDateTimePrototype##N, min, \
                        kDontAdapt);
    ZONED_DATE_TIME_FUNC_LIST(INSTALL_ZONED_DATE_TIME_FUNC)
#undef ZONED_DATE_TIME_FUNC_LIST
#undef INSTALL_ZONED_DATE_TIME_FUNC
  }
  {  // -- D u r a t i o n
    // #sec-temporal-duration-objects
    // #sec-temporal.duration
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(Duration, DURATION, 0)
    INSTALL_TEMPORAL_FUNC(Duration, from, From, 1)
    INSTALL_TEMPORAL_FUNC(Duration, compare, Compare, 2)

#define DURATION_GETTER_LIST(V) \
  V(years, Years)               \
  V(months, Months)             \
  V(weeks, Weeks)               \
  V(days, Days)                 \
  V(hours, Hours)               \
  V(minutes, Minutes)           \
  V(seconds, Seconds)           \
  V(milliseconds, Milliseconds) \
  V(microseconds, Microseconds) \
  V(nanoseconds, Nanoseconds)   \
  V(sign, Sign)                 \
  V(blank, Blank)

#define INSTALL_DURATION_GETTER_FUNC(p, N)                                  \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalDurationPrototype##N, kAdapt);

    DURATION_GETTER_LIST(INSTALL_DURATION_GETTER_FUNC)
#undef DURATION_GETTER_LIST
#undef INSTALL_DURATION_GETTER_FUNC

#define DURATION_FUNC_LIST(V)          \
  V(with, With, 1)                     \
  V(negated, Negated, 0)               \
  V(abs, Abs, 0)                       \
  V(add, Add, 1)                       \
  V(subtract, Subtract, 1)             \
  V(round, Round, 1)                   \
  V(total, Total, 1)                   \
  V(toLocaleString, ToLocaleString, 0) \
  V(toString, ToString, 0)             \
  V(toJSON, ToJSON, 0)                 \
  V(valueOf, ValueOf, 0)

#define INSTALL_DURATION_FUNC(p, N, min)                             \
  SimpleInstallFunction(isolate, prototype, #p,                      \
                        Builtin::kTemporalDurationPrototype##N, min, \
                        kDontAdapt);
    DURATION_FUNC_LIST(INSTALL_DURATION_FUNC)
#undef DURATION_FUNC_LIST
#undef INSTALL_DURATION_FUNC
  }
  {  // -- I n s t a n t
    // #sec-temporal-instant-objects
    // #sec-temporal.instant
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(Instant, INSTANT, 1)
    INSTALL_TEMPORAL_FUNC(Instant, from, From, 1)
    INSTALL_TEMPORAL_FUNC(Instant, compare, Compare, 2)
    INSTALL_TEMPORAL_FUNC(Instant, fromEpochSeconds, FromEpochSeconds, 1)
    INSTALL_TEMPORAL_FUNC(Instant, fromEpochMilliseconds, FromEpochMilliseconds,
                          1)
    INSTALL_TEMPORAL_FUNC(Instant, fromEpochMicroseconds, FromEpochMicroseconds,
                          1)
    INSTALL_TEMPORAL_FUNC(Instant, fromEpochNanoseconds, FromEpochNanoseconds,
                          1)

#define INSTANT_GETTER_LIST(V)            \
  V(epochSeconds, EpochSeconds)           \
  V(epochMilliseconds, EpochMilliseconds) \
  V(epochMicroseconds, EpochMicroseconds) \
  V(epochNanoseconds, EpochNanoseconds)

#define INSTALL_INSTANT_GETTER_FUNC(p, N)                                   \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalInstantPrototype##N, kAdapt);

    INSTANT_GETTER_LIST(INSTALL_INSTANT_GETTER_FUNC)
#undef INSTANT_GETTER_LIST
#undef INSTALL_INSTANT_GETTER_FUNC

#define INSTANT_FUNC_LIST(V)             \
  V(add, Add, 1)                         \
  V(subtract, Subtract, 1)               \
  V(until, Until, 1)                     \
  V(since, Since, 1)                     \
  V(round, Round, 1)                     \
  V(equals, Equals, 1)                   \
  V(toLocaleString, ToLocaleString, 0)   \
  V(toString, ToString, 0)               \
  V(toJSON, ToJSON, 0)                   \
  V(valueOf, ValueOf, 0)                 \
  V(toZonedDateTime, ToZonedDateTime, 1) \
  V(toZonedDateTimeISO, ToZonedDateTimeISO, 1)

#define INSTALL_INSTANT_FUNC(p, N, min)                             \
  SimpleInstallFunction(isolate, prototype, #p,                     \
                        Builtin::kTemporalInstantPrototype##N, min, \
                        kDontAdapt);
    INSTANT_FUNC_LIST(INSTALL_INSTANT_FUNC)
#undef INSTANT_FUNC_LIST
#undef INSTALL_INSTANT_FUNC
  }
  {  // -- P l a i n Y e a r M o n t h
    // #sec-temporal-plainyearmonth-objects
    // #sec-temporal.plainyearmonth
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(PlainYearMonth, PLAIN_YEAR_MONTH, 2)
    INSTALL_TEMPORAL_FUNC(PlainYearMonth, from, From, 1)
    INSTALL_TEMPORAL_FUNC(PlainYearMonth, compare, Compare, 2)

#ifdef V8_INTL_SUPPORT
#define PLAIN_YEAR_MONTH_GETTER_LIST_INTL(V) \
  V(era, Era)                                \
  V(eraYear, EraYear)
#else
#define PLAIN_YEAR_MONTH_GETTER_LIST_INTL(V)
#endif  // V8_INTL_SUPPORT

#define PLAIN_YEAR_MONTH_GETTER_LIST(V) \
  PLAIN_YEAR_MONTH_GETTER_LIST_INTL(V)  \
  V(calendar, Calendar)                 \
  V(year, Year)                         \
  V(month, Month)                       \
  V(monthCode, MonthCode)               \
  V(daysInYear, DaysInYear)             \
  V(daysInMonth, DaysInMonth)           \
  V(monthsInYear, MonthsInYear)         \
  V(inLeapYear, InLeapYear)

#define INSTALL_PLAIN_YEAR_MONTH_GETTER_FUNC(p, N)                          \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalPlainYearMonthPrototype##N, kAdapt);

    PLAIN_YEAR_MONTH_GETTER_LIST(INSTALL_PLAIN_YEAR_MONTH_GETTER_FUNC)
#undef PLAIN_YEAR_MONTH_GETTER_LIST
#undef PLAIN_YEAR_MONTH_GETTER_LIST_INTL
#undef INSTALL_PLAIN_YEAR_MONTH_GETTER_FUNC

#define PLAIN_YEAR_MONTH_FUNC_LIST(V)  \
  V(with, With, 1)                     \
  V(add, Add, 1)                       \
  V(subtract, Subtract, 1)             \
  V(until, Until, 1)                   \
  V(since, Since, 1)                   \
  V(equals, Equals, 1)                 \
  V(toLocaleString, ToLocaleString, 0) \
  V(toString, ToString, 0)             \
  V(toJSON, ToJSON, 0)                 \
  V(valueOf, ValueOf, 0)               \
  V(toPlainDate, ToPlainDate, 1)       \
  V(getISOFields, GetISOFields, 0)

#define INSTALL_PLAIN_YEAR_MONTH_FUNC(p, N, min)                           \
  SimpleInstallFunction(isolate, prototype, #p,                            \
                        Builtin::kTemporalPlainYearMonthPrototype##N, min, \
                        kDontAdapt);
    PLAIN_YEAR_MONTH_FUNC_LIST(INSTALL_PLAIN_YEAR_MONTH_FUNC)
#undef PLAIN_YEAR_MONTH_FUNC_LIST
#undef INSTALL_PLAIN_YEAR_MONTH_FUNC
  }
  {  // -- P l a i n M o n t h D a y
    // #sec-temporal-plainmonthday-objects
    // #sec-temporal.plainmonthday
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(PlainMonthDay, PLAIN_MONTH_DAY, 2)
    INSTALL_TEMPORAL_FUNC(PlainMonthDay, from, From, 1)
    // Notice there are no Temporal.PlainMonthDay.compare in the spec.

#define PLAIN_MONTH_DAY_GETTER_LIST(V) \
  V(calendar, Calendar)                \
  V(monthCode, MonthCode)              \
  V(day, Day)

#define INSTALL_PLAIN_MONTH_DAY_GETTER_FUNC(p, N)                           \
  SimpleInstallGetter(isolate, prototype, isolate->factory()->p##_string(), \
                      Builtin::kTemporalPlainMonthDayPrototype##N, kAdapt);

    PLAIN_MONTH_DAY_GETTER_LIST(INSTALL_PLAIN_MONTH_DAY_GETTER_FUNC)
#undef PLAIN_MONTH_DAY_GETTER_LIST
#undef INSTALL_PLAIN_MONTH_DAY_GETTER_FUNC

#define PLAIN_MONTH_DAY_FUNC_LIST(V)   \
  V(with, With, 1)                     \
  V(equals, Equals, 1)                 \
  V(toLocaleString, ToLocaleString, 0) \
  V(toString, ToString, 0)             \
  V(toJSON, ToJSON, 0)                 \
  V(valueOf, ValueOf, 0)               \
  V(toPlainDate, ToPlainDate, 1)       \
  V(getISOFields, GetISOFields, 0)

#define INSTALL_PLAIN_MONTH_DAY_FUNC(p, N, min)                           \
  SimpleInstallFunction(isolate, prototype, #p,                           \
                        Builtin::kTemporalPlainMonthDayPrototype##N, min, \
                        kDontAdapt);
    PLAIN_MONTH_DAY_FUNC_LIST(INSTALL_PLAIN_MONTH_DAY_FUNC)
#undef PLAIN_MONTH_DAY_FUNC_LIST
#undef INSTALL_PLAIN_MONTH_DAY_FUNC
  }
  {  // -- T i m e Z o n e
    // #sec-temporal-timezone-objects
    // #sec-temporal.timezone
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(TimeZone, TIME_ZONE, 1)
    INSTALL_TEMPORAL_FUNC(TimeZone, from, From, 1)

    // #sec-get-temporal.timezone.prototype.id
    SimpleInstallGetter(isolate, prototype, isolate->factory()->id_string(),
                        Builtin::kTemporalTimeZonePrototypeId, kAdapt);

#define TIME_ZONE_FUNC_LIST(V)                           \
  V(getOffsetNanosecondsFor, GetOffsetNanosecondsFor, 1) \
  V(getOffsetStringFor, GetOffsetStringFor, 1)           \
  V(getPlainDateTimeFor, GetPlainDateTimeFor, 1)         \
  V(getInstantFor, GetInstantFor, 1)                     \
  V(getPossibleInstantsFor, GetPossibleInstantsFor, 1)   \
  V(getNextTransition, GetNextTransition, 1)             \
  V(getPreviousTransition, GetPreviousTransition, 1)     \
  V(toString, ToString, 0)                               \
  V(toJSON, ToJSON, 0)

#define INSTALL_TIME_ZONE_FUNC(p, N, min)                            \
  SimpleInstallFunction(isolate, prototype, #p,                      \
                        Builtin::kTemporalTimeZonePrototype##N, min, \
                        kDontAdapt);
    TIME_ZONE_FUNC_LIST(INSTALL_TIME_ZONE_FUNC)
#undef TIME_ZONE_FUNC_LIST
#undef INSTALL_TIME_ZONE_FUNC
  }
  {  // -- C a l e n d a r
    // #sec-temporal-calendar-objects
    // #sec-temporal.calendar
    INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE(Calendar, CALENDAR, 1)
    INSTALL_TEMPORAL_FUNC(Calendar, from, From, 1)

    // #sec-get-temporal.calendar.prototype.id
    SimpleInstallGetter(isolate, prototype, isolate->factory()->id_string(),
                        Builtin::kTemporalCalendarPrototypeId, kAdapt);

#ifdef V8_INTL_SUPPORT
#define CALENDAR_FUNC_LIST_INTL(V) \
  V(era, Era, 1, kDontAdapt)       \
  V(eraYear, EraYear, 1, kDontAdapt)
#else
#define CALENDAR_FUNC_LIST_INTL(V)
#endif  // V8_INTL_SUPPORT

#define CALENDAR_FUNC_LIST(V)                                \
  CALENDAR_FUNC_LIST_INTL(V)                                 \
  V(dateFromFields, DateFromFields, 1, kDontAdapt)           \
  V(yearMonthFromFields, YearMonthFromFields, 1, kDontAdapt) \
  V(monthDayFromFields, MonthDayFromFields, 1, kDontAdapt)   \
  V(dateAdd, DateAdd, 2, kDontAdapt)                         \
  V(dateUntil, DateUntil, 2, kDontAdapt)                     \
  V(year, Year, 1, kDontAdapt)                               \
  V(month, Month, 1, kDontAdapt)                             \
  V(monthCode, MonthCode, 1, kDontAdapt)                     \
  V(day, Day, 1, kDontAdapt)                                 \
  V(dayOfWeek, DayOfWeek, 1, kDontAdapt)                     \
  V(dayOfYear, DayOfYear, 1, kDontAdapt)                     \
  V(weekOfYear, WeekOfYear, 1, kDontAdapt)                   \
  V(daysInWeek, DaysInWeek, 1, kDontAdapt)                   \
  V(daysInMonth, DaysInMonth, 1, kDontAdapt)                 \
  V(daysInYear, DaysInYear, 1, kDontAdapt)                   \
  V(monthsInYear, MonthsInYear, 1, kDontAdapt)               \
  V(inLeapYear, InLeapYear, 1, kDontAdapt)                   \
  V(fields, Fields, 1, kAdapt)                               \
  V(mergeFields, MergeFields, 2, kDontAdapt)                 \
  V(toString, ToString, 0, kDontAdapt)                       \
  V(toJSON, ToJSON, 0, kDontAdapt)

#define INSTALL_CALENDAR_FUNC(p, N, min, adapt) \
  SimpleInstallFunction(isolate, prototype, #p, \
                        Builtin::kTemporalCalendarPrototype##N, min, adapt);
    CALENDAR_FUNC_LIST(INSTALL_CALENDAR_FUNC)
#undef CALENDAR_FUNC_LIST
#undef CALENDAR_FUNC_LIST_INTL
#undef INSTALL_CALENDAE_FUNC
  }
#undef INSTALL_TEMPORAL_CTOR_AND_PROTOTYPE
#undef INSTALL_TEMPORAL_FUNC

  // The StringListFromIterable functions is created but not
  // exposed, as it is used internally by CalendarFields.
  {
    DirectHandle<JSFunction> func =
        SimpleCreateFunction(isolate,
                             isolate->factory()->InternalizeUtf8String(
                                 "StringFixedArrayFromIterable"),
                             Builtin::kStringFixedArrayFromIterable, 1, kAdapt);
    native_context->set_string_fixed_array_from_iterable(*func);
  }
  // The TemporalInsantFixedArrayFromIterable functions is created but not
  // exposed, as it is used internally by GetPossibleInstantsFor.
  {
    DirectHandle<JSFunction> func = SimpleCreateFunction(
        isolate,
        isolate->factory()->InternalizeUtf8String(
            "TemporalInstantFixedArrayFromIterable"),
        Builtin::kTemporalInstantFixedArrayFromIterable, 1, kAdapt);
    native_context->set_temporal_instant_fixed_array_from_iterable(*func);
  }

  native_context->set_temporal_object(*temporal);
  return temporal;
}

void LazyInitializeDateToTemporalInstant(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  Isolate* isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
  InitializeTemporal(isolate);
  Handle<JSFunction> function = SimpleCreateFunction(
      isolate, isolate->factory()->InternalizeUtf8String("toTemporalInstant"),
      Builtin::kDatePrototypeToTemporalInstant, 0, kDontAdapt);
  info.GetReturnValue().Set(v8::Utils::ToLocal(function));
}

void LazyInitializeGlobalThisTemporal(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  Isolate* isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
  Handle<JSObject> temporal = InitializeTemporal(isolate);
  info.GetReturnValue().Set(v8::Utils::ToLocal(temporal));
}

}  // namespace

// This is only called if we are not using snapshots.  The equivalent
// work in the snapshot case is done in HookUpGlobalObject.
void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                               Handle<JSFunction> empty_function) {
  // --- N a t i v e   C o n t e x t ---
  // Set extension and global object.
  native_context()->set_extension(*global_object);
  // Security setup: Set the security token of the native context to the global
  // object. This makes the security check between two different contexts fail
  // by default even in case of global object reinitialization.
  native_context()->set_security_token(*global_object);

  Factory* factory = isolate_->factory();

  {  // -- C o n t e x t
    Handle<Map> meta_map(native_context()->meta_map(), isolate());

    DirectHandle<Map> map = factory->NewMapWithMetaMap(
        meta_map, FUNCTION_CONTEXT_TYPE, kVariableSizeSentinel);
```