Response: The user wants to understand the functionality of the provided C++ code snippet from `v8/src/init/bootstrapper.cc`. This is the second part of a six-part file, suggesting the code is responsible for initializing parts of the V8 JavaScript engine.

Looking at the code, it focuses on:

1. **Error Object Setup**: The `InstallError` function configures the `Error` object in JavaScript, including its prototype and properties like `message` and `stack`. It also sets up the `captureStackTrace` and `toString` methods for error objects.

2. **Temporal API Initialization**: The `InitializeTemporal` function initializes the experimental Temporal API in V8. This involves creating the `Temporal` global object and its various sub-objects like `Now`, `PlainDate`, `PlainTime`, etc. It defines constructors, prototype methods, and getters for these Temporal objects.

3. **Lazy Initialization**: The `LazyInitializeDateToTemporalInstant` and `LazyInitializeGlobalThisTemporal` functions are used for the lazy initialization of the Temporal API. They ensure the Temporal API is only initialized when it's actually accessed.

4. **Global Object Initialization**: The `Genesis::InitializeGlobal` function is responsible for setting up the global object and its fundamental properties and constructors like `Object`, `Function`, `Array`, `Number`, `Boolean`, and `String`. It also installs prototype methods for these built-in objects.

Therefore, the main functionalities of this part of the `bootstrapper.cc` file are:

- Setting up the `Error` object and its related functionalities.
- Initializing the experimental Temporal API, which provides modern date and time functionalities.
- Initializing core JavaScript built-in objects and their prototypes on the global object.

To demonstrate the relationship with JavaScript, I'll provide examples showing how these C++ functions manifest in the JavaScript environment.
这个C++代码片段的主要功能是**初始化JavaScript的内置对象和构造函数，特别是关于错误对象 (`Error`) 和实验性的 `Temporal` API**。

具体来说，这段代码做了以下事情：

1. **定义了创建和配置错误对象的方法 (`InstallError`)**:  这个函数负责在全局对象上安装 `Error` 构造函数及其原型对象。它设置了 `message` 和 `stack` 属性，以及 `captureStackTrace` 和 `toString` 方法。它还处理了不同类型的错误构造函数（如 `TypeError`, `RangeError` 等，虽然这里只显示了基础的 `Error`）。

2. **定义了初始化实验性的 `Temporal` API 的方法 (`InitializeTemporal`)**: 这个函数负责创建 `Temporal` 全局对象，并注册其下的各种日期和时间相关的构造函数，例如 `PlainDate`, `PlainTime`, `ZonedDateTime` 等。它为这些构造函数安装了原型方法（例如 `add`, `subtract`, `with`, `toString` 等）和 getter 属性（例如 `year`, `month`, `hour` 等）。

3. **定义了延迟初始化 `Temporal` API 的方法 (`LazyInitializeDateToTemporalInstant`, `LazyInitializeGlobalThisTemporal`)**: 这两个函数实现了 `Temporal` API 的延迟初始化。`LazyInitializeGlobalThisTemporal` 负责在全局对象上创建一个 `Temporal` 属性，当首次访问时触发 `InitializeTemporal` 进行初始化。`LazyInitializeDateToTemporalInstant` 可能是为 `Date.prototype` 添加 `toTemporalInstant` 方法做准备。

4. **定义了初始化全局对象的方法 (`Genesis::InitializeGlobal`)**: 这个函数负责在全局对象上安装各种核心的 JavaScript 内置对象和构造函数，例如 `Object`, `Function`, `Array`, `Number`, `Boolean`, `String` 等。它还设置了这些对象的原型及其上的方法。

**与 JavaScript 的关系和示例**

这段 C++ 代码直接影响了你在 JavaScript 中使用的各种内置对象和功能。

**`Error` 对象示例：**

C++ 代码中的 `InstallError` 函数确保了你在 JavaScript 中可以创建和使用 `Error` 对象：

```javascript
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error(e.message); // "Something went wrong!"
  console.error(e.stack);   // 输出错误堆栈信息
  console.log(e.toString()); // "Error: Something went wrong!"
}

// 调用 captureStackTrace (虽然 JavaScript 中通常不直接调用，但它是 Error 对象功能的一部分)
function myFunction() {
  const error = new Error("Another error");
  Error.captureStackTrace(error, myFunction);
  console.log(error.stack);
}
myFunction();
```

**`Temporal` API 示例：**

C++ 代码中的 `InitializeTemporal` 函数使得你在 JavaScript 中可以使用实验性的 `Temporal` API 来处理日期和时间（需要 V8 引擎支持并启用实验性功能）。

```javascript
// 注意：Temporal API 是实验性的，可能需要特定的 V8 版本和标志才能运行
const today = Temporal.PlainDate.today();
console.log(today.toString()); // 例如：2023-10-27

const now = Temporal.Now.plainDateTimeISO();
console.log(now.toString()); // 例如：2023-10-27T10:30:00

const future = today.add({ days: 7 });
console.log(future.toString()); // 一周后的日期

const timeZone = Temporal.TimeZone.from("America/Los_Angeles");
const zonedNow = Temporal.Now.zonedDateTimeISO(timeZone);
console.log(zonedNow.toString());
```

**内置对象示例 (`Object`, `Function`, `Array`, 等):**

C++ 代码中的 `Genesis::InitializeGlobal` 函数确保了这些基础对象和方法在 JavaScript 中可用：

```javascript
// Object 构造函数和方法
const obj = new Object();
obj.name = "example";
console.log(obj.hasOwnProperty("name")); // true

// Function 构造函数和方法
const myFunction = new Function('a', 'b', 'return a + b;');
console.log(myFunction(5, 3)); // 8

// Array 构造函数和方法
const arr = [1, 2, 3];
arr.push(4);
console.log(arr.length); // 4
console.log(arr.map(x => x * 2)); // [2, 4, 6, 8]

// Number 构造函数和方法
const num = new Number(10);
console.log(num.toFixed(2)); // "10.00"
console.log(Number.isNaN(NaN)); // true

// String 构造函数和方法
const str = "hello";
console.log(str.toUpperCase()); // "HELLO"
console.log(str.charAt(0));   // "h"
```

总而言之，这段 C++ 代码是 V8 引擎启动过程中的关键部分，负责为 JavaScript 环境构建最基础的对象和功能，使得 JavaScript 代码能够运行。 它就像是搭建舞台并准备好演员和道具，为 JavaScript 代码的执行奠定基础。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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
```