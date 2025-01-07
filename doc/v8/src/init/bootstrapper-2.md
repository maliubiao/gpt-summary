Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `bootstrapper.cc` file in the V8 JavaScript engine. Specifically, this is part 3 of 6.

The code appears to be installing built-in JavaScript objects and their associated methods and properties. Given the names of the functions being installed, this part seems to focus on:

1. **String Prototype Methods**:  Functions available on string objects.
2. **String Iterator**: The object returned when iterating over a string.
3. **Symbol**: The Symbol constructor and its static properties and prototype methods.
4. **Date**: The Date constructor and its static properties and prototype methods.
5. **Promise**: The Promise constructor and its static methods and prototype methods.
6. **RegExp**: The RegExp constructor and its static properties and prototype methods.
7. **RegExp String Iterator**: The object returned when iterating over the results of a RegExp match.
8. **Error Types**:  Installation of various built-in error constructors.
9. **globalThis**: Making the globalThis object available.
10. **JSON**: The JSON object and its methods.
11. **Math**: The Math object and its mathematical functions and constants.
12. **Intl**: (If `V8_INTL_SUPPORT` is defined) The Intl object and its related constructors like `DateTimeFormat`, `NumberFormat`, `Collator`, etc.

I need to summarize these points concisely and provide a JavaScript example illustrating the connection. Since the code installs prototype methods, a good example would be calling one of these methods on a string object.
这段C++代码的主要功能是**初始化和注册 V8 JavaScript 引擎中的内置对象及其属性和方法，特别是 `String`，`Symbol`，`Date`，`Promise`，`RegExp`，`Error` 以及 `JSON` 和 `Math` 等全局对象。**  考虑到这是第3部分，它延续了之前部分的工作，继续构建 JavaScript 的核心对象和功能。

具体来说，这段代码做了以下事情：

* **为 `String.prototype` 安装内置方法**:  例如 `match`, `matchAll`, `normalize`, `padEnd`, `padStart`, `repeat`, `replace`, `replaceAll`, `search`, `slice`, `split`, `startsWith`, `endsWith`, `trim`, `toLowerCase`, `toUpperCase` 等字符串操作方法。  它还为 `trimStart` 和 `trimEnd` 安装了别名 `trimLeft` 和 `trimRight`。
* **创建和初始化 `String` 迭代器**:  用于 `for...of` 循环等迭代字符串场景。
* **初始化 `Symbol` 构造函数及其静态属性和原型方法**:  包括 well-known symbols (如 `Symbol.iterator`, `Symbol.match` 等) 以及 `Symbol.for` 和 `Symbol.keyFor` 等静态方法。
* **初始化 `Date` 构造函数及其静态方法和原型方法**:  例如 `Date.now`, `Date.parse`, `Date.UTC` 以及 `getDate`, `setDate`, `getFullYear`, `setFullYear`, `toISOString` 等日期操作方法。
* **初始化 `Promise` 构造函数及其静态方法和原型方法**:  例如 `Promise.all`, `Promise.race`, `Promise.resolve`, `Promise.reject` 以及 `then`, `catch`, `finally` 等 Promise 操作方法。
* **初始化 `RegExp` (正则表达式) 构造函数及其静态属性和原型方法**: 包括 `exec`, `test`, `compile` 以及与 `Symbol.match`, `Symbol.replace` 等相关的符号方法。
* **创建和初始化 `RegExp` 字符串迭代器**: 用于迭代正则表达式匹配的结果。
* **初始化各种内置错误类型**:  例如 `Error`, `TypeError`, `ReferenceError` 等。
* **初始化 `globalThis`**:  使其指向全局对象。
* **初始化 `JSON` 对象及其方法**:  包括 `parse`, `stringify`, `rawJSON`, `isRawJSON`。
* **初始化 `Math` 对象及其数学函数和常量**:  例如 `abs`, `sin`, `cos`, `sqrt`, `pow`, `PI`, `E` 等。
* **如果定义了 `V8_INTL_SUPPORT`，则初始化 `Intl` 对象及其相关功能**:  例如 `DateTimeFormat`, `NumberFormat`, `Collator` 等国际化相关的构造函数。

**与 Javascript 的关系及示例:**

这段 C++ 代码的功能是为 JavaScript 提供了底层实现。 它定义了 JavaScript 中可以直接使用的各种内置对象和方法。

例如，代码中安装了 `String.prototype.trim()` 方法。在 JavaScript 中，我们可以这样使用它：

```javascript
const str = "   Hello World!   ";
const trimmedStr = str.trim();
console.log(trimmedStr); // 输出: "Hello World!"
```

在这个例子中，`trim()` 方法的功能就是在 C++ 代码中通过 `SimpleInstallFunction` 注册的 `Builtin::kStringPrototypeTrim` 函数实现的。 当 JavaScript 引擎执行 `str.trim()` 时，最终会调用到 V8 引擎中对应的 C++ 代码来完成字符串的去除首尾空格操作。

其他的内置方法，例如 `Array.prototype.map()`, `Object.keys()` 等，虽然没有在这段代码中展示，但其原理是类似的，都是在 V8 的 `bootstrapper.cc` 文件或其他相关文件中通过 C++ 代码进行初始化和注册的，从而使得 JavaScript 能够拥有这些强大的内置功能。

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
PORT
    SimpleInstallFunction(isolate_, prototype, "match",
                          Builtin::kStringPrototypeMatch, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "matchAll",
                          Builtin::kStringPrototypeMatchAll, 1, kAdapt);
#ifdef V8_INTL_SUPPORT
    SimpleInstallFunction(isolate_, prototype, "normalize",
                          Builtin::kStringPrototypeNormalizeIntl, 0,
                          kDontAdapt);
#else
    SimpleInstallFunction(isolate_, prototype, "normalize",
                          Builtin::kStringPrototypeNormalize, 0, kDontAdapt);
#endif  // V8_INTL_SUPPORT
    SimpleInstallFunction(isolate_, prototype, "padEnd",
                          Builtin::kStringPrototypePadEnd, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "padStart",
                          Builtin::kStringPrototypePadStart, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "repeat",
                          Builtin::kStringPrototypeRepeat, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "replace",
                          Builtin::kStringPrototypeReplace, 2, kAdapt);
    SimpleInstallFunction(isolate(), prototype, "replaceAll",
                          Builtin::kStringPrototypeReplaceAll, 2, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "search",
                          Builtin::kStringPrototypeSearch, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "slice",
                          Builtin::kStringPrototypeSlice, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "small",
                          Builtin::kStringPrototypeSmall, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "split",
                          Builtin::kStringPrototypeSplit, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "strike",
                          Builtin::kStringPrototypeStrike, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "sub",
                          Builtin::kStringPrototypeSub, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "substr",
                          Builtin::kStringPrototypeSubstr, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "substring",
                          Builtin::kStringPrototypeSubstring, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "sup",
                          Builtin::kStringPrototypeSup, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "startsWith",
                          Builtin::kStringPrototypeStartsWith, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toString",
                          Builtin::kStringPrototypeToString, 0, kAdapt);
    SimpleInstallFunction(isolate(), prototype, "toWellFormed",
                          Builtin::kStringPrototypeToWellFormed, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "trim",
                          Builtin::kStringPrototypeTrim, 0, kDontAdapt);

    // Install `String.prototype.trimStart` with `trimLeft` alias.
    DirectHandle<JSFunction> trim_start_fun = SimpleInstallFunction(
        isolate_, prototype, "trimStart", Builtin::kStringPrototypeTrimStart, 0,
        kDontAdapt);
    JSObject::AddProperty(isolate_, prototype, "trimLeft", trim_start_fun,
                          DONT_ENUM);

    // Install `String.prototype.trimEnd` with `trimRight` alias.
    DirectHandle<JSFunction> trim_end_fun =
        SimpleInstallFunction(isolate_, prototype, "trimEnd",
                              Builtin::kStringPrototypeTrimEnd, 0, kDontAdapt);
    JSObject::AddProperty(isolate_, prototype, "trimRight", trim_end_fun,
                          DONT_ENUM);

    SimpleInstallFunction(isolate_, prototype, "toLocaleLowerCase",
                          Builtin::kStringPrototypeToLocaleLowerCase, 0,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleUpperCase",
                          Builtin::kStringPrototypeToLocaleUpperCase, 0,
                          kDontAdapt);
#ifdef V8_INTL_SUPPORT
    SimpleInstallFunction(isolate_, prototype, "toLowerCase",
                          Builtin::kStringPrototypeToLowerCaseIntl, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "toUpperCase",
                          Builtin::kStringPrototypeToUpperCaseIntl, 0,
                          kDontAdapt);
#else
    SimpleInstallFunction(isolate_, prototype, "toLowerCase",
                          Builtin::kStringPrototypeToLowerCase, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toUpperCase",
                          Builtin::kStringPrototypeToUpperCase, 0, kDontAdapt);
#endif
    SimpleInstallFunction(isolate_, prototype, "valueOf",
                          Builtin::kStringPrototypeValueOf, 0, kAdapt);

    InstallFunctionAtSymbol(
        isolate_, prototype, factory->iterator_symbol(), "[Symbol.iterator]",
        Builtin::kStringPrototypeIterator, 0, kAdapt, DONT_ENUM);
  }

  {  // --- S t r i n g I t e r a t o r ---
    Handle<JSObject> iterator_prototype(
        native_context()->initial_iterator_prototype(), isolate());

    Handle<JSObject> string_iterator_prototype =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate(), string_iterator_prototype,
                                iterator_prototype);
    CHECK_NE(string_iterator_prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    string_iterator_prototype->map()->set_instance_type(
        JS_STRING_ITERATOR_PROTOTYPE_TYPE);
    InstallToStringTag(isolate_, string_iterator_prototype, "String Iterator");

    InstallFunctionWithBuiltinId(isolate_, string_iterator_prototype, "next",
                                 Builtin::kStringIteratorPrototypeNext, 0,
                                 kAdapt);

    DirectHandle<JSFunction> string_iterator_function = CreateFunction(
        isolate_, factory->InternalizeUtf8String("StringIterator"),
        JS_STRING_ITERATOR_TYPE, JSStringIterator::kHeaderSize, 0,
        string_iterator_prototype, Builtin::kIllegal, 0, kDontAdapt);
    string_iterator_function->shared()->set_native(false);
    native_context()->set_initial_string_iterator_map(
        string_iterator_function->initial_map());
    native_context()->set_initial_string_iterator_prototype(
        *string_iterator_prototype);
  }

  {  // --- S y m b o l ---
    Handle<JSFunction> symbol_fun = InstallFunction(
        isolate_, global, "Symbol", JS_PRIMITIVE_WRAPPER_TYPE,
        JSPrimitiveWrapper::kHeaderSize, 0, factory->the_hole_value(),
        Builtin::kSymbolConstructor, 0, kDontAdapt);
    native_context()->set_symbol_function(*symbol_fun);

    // Install the Symbol.for and Symbol.keyFor functions.
    SimpleInstallFunction(isolate_, symbol_fun, "for", Builtin::kSymbolFor, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, symbol_fun, "keyFor",
                          Builtin::kSymbolKeyFor, 1, kDontAdapt);

    // Install well-known symbols.
    InstallConstant(isolate_, symbol_fun, "asyncIterator",
                    factory->async_iterator_symbol());
    InstallConstant(isolate_, symbol_fun, "hasInstance",
                    factory->has_instance_symbol());
    InstallConstant(isolate_, symbol_fun, "isConcatSpreadable",
                    factory->is_concat_spreadable_symbol());
    InstallConstant(isolate_, symbol_fun, "iterator",
                    factory->iterator_symbol());
    InstallConstant(isolate_, symbol_fun, "match", factory->match_symbol());
    InstallConstant(isolate_, symbol_fun, "matchAll",
                    factory->match_all_symbol());
    InstallConstant(isolate_, symbol_fun, "replace", factory->replace_symbol());
    InstallConstant(isolate_, symbol_fun, "search", factory->search_symbol());
    InstallConstant(isolate_, symbol_fun, "species", factory->species_symbol());
    InstallConstant(isolate_, symbol_fun, "split", factory->split_symbol());
    InstallConstant(isolate_, symbol_fun, "toPrimitive",
                    factory->to_primitive_symbol());
    InstallConstant(isolate_, symbol_fun, "toStringTag",
                    factory->to_string_tag_symbol());
    InstallConstant(isolate_, symbol_fun, "unscopables",
                    factory->unscopables_symbol());
    InstallConstant(isolate_, symbol_fun, "dispose", factory->dispose_symbol());
    InstallConstant(isolate_, symbol_fun, "asyncDispose",
                    factory->async_dispose_symbol());

    // Setup %SymbolPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(symbol_fun->instance_prototype()),
                               isolate());

    InstallToStringTag(isolate_, prototype, "Symbol");

    // Install the Symbol.prototype methods.
    InstallFunctionWithBuiltinId(isolate_, prototype, "toString",
                                 Builtin::kSymbolPrototypeToString, 0, kAdapt);
    InstallFunctionWithBuiltinId(isolate_, prototype, "valueOf",
                                 Builtin::kSymbolPrototypeValueOf, 0, kAdapt);

    // Install the Symbol.prototype.description getter.
    SimpleInstallGetter(isolate_, prototype,
                        factory->InternalizeUtf8String("description"),
                        Builtin::kSymbolPrototypeDescriptionGetter, kAdapt);

    // Install the @@toPrimitive function.
    InstallFunctionAtSymbol(
        isolate_, prototype, factory->to_primitive_symbol(),
        "[Symbol.toPrimitive]", Builtin::kSymbolPrototypeToPrimitive, 1, kAdapt,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  }

  {  // --- D a t e ---
    Handle<JSFunction> date_fun = InstallFunction(
        isolate_, global, "Date", JS_DATE_TYPE, JSDate::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kDateConstructor, 7, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, date_fun,
                                     Context::DATE_FUNCTION_INDEX);

    // Install the Date.now, Date.parse and Date.UTC functions.
    SimpleInstallFunction(isolate_, date_fun, "now", Builtin::kDateNow, 0,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, date_fun, "parse", Builtin::kDateParse, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, date_fun, "UTC", Builtin::kDateUTC, 7,
                          kDontAdapt);

    // Setup %DatePrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(date_fun->instance_prototype()),
                               isolate());

    // Install the Date.prototype methods.
    SimpleInstallFunction(isolate_, prototype, "toString",
                          Builtin::kDatePrototypeToString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toDateString",
                          Builtin::kDatePrototypeToDateString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toTimeString",
                          Builtin::kDatePrototypeToTimeString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toISOString",
                          Builtin::kDatePrototypeToISOString, 0, kDontAdapt);
    DirectHandle<JSFunction> to_utc_string = SimpleInstallFunction(
        isolate_, prototype, "toUTCString", Builtin::kDatePrototypeToUTCString,
        0, kDontAdapt);
    JSObject::AddProperty(isolate_, prototype, "toGMTString", to_utc_string,
                          DONT_ENUM);
    SimpleInstallFunction(isolate_, prototype, "getDate",
                          Builtin::kDatePrototypeGetDate, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setDate",
                          Builtin::kDatePrototypeSetDate, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getDay",
                          Builtin::kDatePrototypeGetDay, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "getFullYear",
                          Builtin::kDatePrototypeGetFullYear, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setFullYear",
                          Builtin::kDatePrototypeSetFullYear, 3, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getHours",
                          Builtin::kDatePrototypeGetHours, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setHours",
                          Builtin::kDatePrototypeSetHours, 4, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getMilliseconds",
                          Builtin::kDatePrototypeGetMilliseconds, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setMilliseconds",
                          Builtin::kDatePrototypeSetMilliseconds, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getMinutes",
                          Builtin::kDatePrototypeGetMinutes, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setMinutes",
                          Builtin::kDatePrototypeSetMinutes, 3, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getMonth",
                          Builtin::kDatePrototypeGetMonth, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setMonth",
                          Builtin::kDatePrototypeSetMonth, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getSeconds",
                          Builtin::kDatePrototypeGetSeconds, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setSeconds",
                          Builtin::kDatePrototypeSetSeconds, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getTime",
                          Builtin::kDatePrototypeGetTime, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setTime",
                          Builtin::kDatePrototypeSetTime, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getTimezoneOffset",
                          Builtin::kDatePrototypeGetTimezoneOffset, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCDate",
                          Builtin::kDatePrototypeGetUTCDate, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCDate",
                          Builtin::kDatePrototypeSetUTCDate, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCDay",
                          Builtin::kDatePrototypeGetUTCDay, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCFullYear",
                          Builtin::kDatePrototypeGetUTCFullYear, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCFullYear",
                          Builtin::kDatePrototypeSetUTCFullYear, 3, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCHours",
                          Builtin::kDatePrototypeGetUTCHours, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCHours",
                          Builtin::kDatePrototypeSetUTCHours, 4, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCMilliseconds",
                          Builtin::kDatePrototypeGetUTCMilliseconds, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCMilliseconds",
                          Builtin::kDatePrototypeSetUTCMilliseconds, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCMinutes",
                          Builtin::kDatePrototypeGetUTCMinutes, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCMinutes",
                          Builtin::kDatePrototypeSetUTCMinutes, 3, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCMonth",
                          Builtin::kDatePrototypeGetUTCMonth, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCMonth",
                          Builtin::kDatePrototypeSetUTCMonth, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUTCSeconds",
                          Builtin::kDatePrototypeGetUTCSeconds, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUTCSeconds",
                          Builtin::kDatePrototypeSetUTCSeconds, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "valueOf",
                          Builtin::kDatePrototypeValueOf, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "getYear",
                          Builtin::kDatePrototypeGetYear, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "setYear",
                          Builtin::kDatePrototypeSetYear, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toJSON",
                          Builtin::kDatePrototypeToJson, 1, kDontAdapt);

#ifdef V8_INTL_SUPPORT
    SimpleInstallFunction(isolate_, prototype, "toLocaleString",
                          Builtin::kDatePrototypeToLocaleString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleDateString",
                          Builtin::kDatePrototypeToLocaleDateString, 0,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleTimeString",
                          Builtin::kDatePrototypeToLocaleTimeString, 0,
                          kDontAdapt);
#else
    // Install Intl fallback functions.
    SimpleInstallFunction(isolate_, prototype, "toLocaleString",
                          Builtin::kDatePrototypeToString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleDateString",
                          Builtin::kDatePrototypeToDateString, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleTimeString",
                          Builtin::kDatePrototypeToTimeString, 0, kDontAdapt);
#endif  // V8_INTL_SUPPORT

    // Install the @@toPrimitive function.
    InstallFunctionAtSymbol(
        isolate_, prototype, factory->to_primitive_symbol(),
        "[Symbol.toPrimitive]", Builtin::kDatePrototypeToPrimitive, 1, kAdapt,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  }

  {  // -- P r o m i s e
    Handle<JSFunction> promise_fun = InstallFunction(
        isolate_, global, "Promise", JS_PROMISE_TYPE,
        JSPromise::kSizeWithEmbedderFields, 0, factory->the_hole_value(),
        Builtin::kPromiseConstructor, 1, kAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, promise_fun,
                                     Context::PROMISE_FUNCTION_INDEX);

    InstallSpeciesGetter(isolate_, promise_fun);

    DirectHandle<JSFunction> promise_all = InstallFunctionWithBuiltinId(
        isolate_, promise_fun, "all", Builtin::kPromiseAll, 1, kAdapt);
    native_context()->set_promise_all(*promise_all);

    DirectHandle<JSFunction> promise_all_settled =
        InstallFunctionWithBuiltinId(isolate_, promise_fun, "allSettled",
                                     Builtin::kPromiseAllSettled, 1, kAdapt);
    native_context()->set_promise_all_settled(*promise_all_settled);

    DirectHandle<JSFunction> promise_any = InstallFunctionWithBuiltinId(
        isolate_, promise_fun, "any", Builtin::kPromiseAny, 1, kAdapt);
    native_context()->set_promise_any(*promise_any);

    InstallFunctionWithBuiltinId(isolate_, promise_fun, "race",
                                 Builtin::kPromiseRace, 1, kAdapt);

    DirectHandle<JSFunction> promise_resolve = InstallFunctionWithBuiltinId(
        isolate_, promise_fun, "resolve", Builtin::kPromiseResolveTrampoline, 1,
        kAdapt);
    native_context()->set_promise_resolve(*promise_resolve);

    InstallFunctionWithBuiltinId(isolate_, promise_fun, "reject",
                                 Builtin::kPromiseReject, 1, kAdapt);

    std::array<Handle<Name>, 3> fields{factory->promise_string(),
                                       factory->resolve_string(),
                                       factory->reject_string()};
    DirectHandle<Map> result_map =
        CreateLiteralObjectMapFromCache(isolate_, fields);
    native_context()->set_promise_withresolvers_result_map(*result_map);
    InstallFunctionWithBuiltinId(isolate_, promise_fun, "withResolvers",
                                 Builtin::kPromiseWithResolvers, 0, kAdapt);

    SetConstructorInstanceType(isolate_, promise_fun,
                               JS_PROMISE_CONSTRUCTOR_TYPE);

    // Setup %PromisePrototype%.
    Handle<JSObject> prototype(
        Cast<JSObject>(promise_fun->instance_prototype()), isolate());
    native_context()->set_promise_prototype(*prototype);

    InstallToStringTag(isolate_, prototype, factory->Promise_string());

    DirectHandle<JSFunction> promise_then = InstallFunctionWithBuiltinId(
        isolate_, prototype, "then", Builtin::kPromisePrototypeThen, 2, kAdapt);
    native_context()->set_promise_then(*promise_then);

    DirectHandle<JSFunction> perform_promise_then =
        SimpleCreateFunction(isolate_, factory->empty_string(),
                             Builtin::kPerformPromiseThenFunction, 2, kAdapt);
    native_context()->set_perform_promise_then(*perform_promise_then);

    InstallFunctionWithBuiltinId(isolate_, prototype, "catch",
                                 Builtin::kPromisePrototypeCatch, 1, kAdapt);

    InstallFunctionWithBuiltinId(isolate_, prototype, "finally",
                                 Builtin::kPromisePrototypeFinally, 1, kAdapt);

    DCHECK(promise_fun->HasFastProperties());

    DirectHandle<Map> prototype_map(prototype->map(), isolate());
    Map::SetShouldBeFastPrototypeMap(prototype_map, true, isolate_);
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_PROMISE_PROTOTYPE_TYPE);

    DCHECK(promise_fun->HasFastProperties());
  }

  {  // -- R e g E x p
    // Builtin functions for RegExp.prototype.
    Handle<JSFunction> regexp_fun = InstallFunction(
        isolate_, global, "RegExp", JS_REG_EXP_TYPE,
        JSRegExp::kHeaderSize + JSRegExp::kInObjectFieldCount * kTaggedSize,
        JSRegExp::kInObjectFieldCount, factory->the_hole_value(),
        Builtin::kRegExpConstructor, 2, kAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, regexp_fun,
                                     Context::REGEXP_FUNCTION_INDEX);

    {
      // Setup %RegExpPrototype%.
      Handle<JSObject> prototype(
          Cast<JSObject>(regexp_fun->instance_prototype()), isolate());
      native_context()->set_regexp_prototype(*prototype);

      {
        DirectHandle<JSFunction> fun =
            SimpleInstallFunction(isolate_, prototype, "exec",
                                  Builtin::kRegExpPrototypeExec, 1, kAdapt);
        native_context()->set_regexp_exec_function(*fun);
        DCHECK_EQ(JSRegExp::kExecFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      SimpleInstallGetter(isolate_, prototype, factory->dotAll_string(),
                          Builtin::kRegExpPrototypeDotAllGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->flags_string(),
                          Builtin::kRegExpPrototypeFlagsGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->global_string(),
                          Builtin::kRegExpPrototypeGlobalGetter, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->hasIndices_string(),
                          Builtin::kRegExpPrototypeHasIndicesGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->ignoreCase_string(),
                          Builtin::kRegExpPrototypeIgnoreCaseGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->multiline_string(),
                          Builtin::kRegExpPrototypeMultilineGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->source_string(),
                          Builtin::kRegExpPrototypeSourceGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->sticky_string(),
                          Builtin::kRegExpPrototypeStickyGetter, kAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->unicode_string(),
                          Builtin::kRegExpPrototypeUnicodeGetter, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->unicodeSets_string(),
                          Builtin::kRegExpPrototypeUnicodeSetsGetter, kAdapt);

      SimpleInstallFunction(isolate_, prototype, "compile",
                            Builtin::kRegExpPrototypeCompile, 2, kAdapt);
      SimpleInstallFunction(isolate_, prototype, "toString",
                            Builtin::kRegExpPrototypeToString, 0, kDontAdapt);
      SimpleInstallFunction(isolate_, prototype, "test",
                            Builtin::kRegExpPrototypeTest, 1, kAdapt);

      {
        DirectHandle<JSFunction> fun = InstallFunctionAtSymbol(
            isolate_, prototype, factory->match_symbol(), "[Symbol.match]",
            Builtin::kRegExpPrototypeMatch, 1, kAdapt);
        native_context()->set_regexp_match_function(*fun);
        DCHECK_EQ(JSRegExp::kSymbolMatchFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      {
        DirectHandle<JSFunction> fun = InstallFunctionAtSymbol(
            isolate_, prototype, factory->match_all_symbol(),
            "[Symbol.matchAll]", Builtin::kRegExpPrototypeMatchAll, 1, kAdapt);
        native_context()->set_regexp_match_all_function(*fun);
        DCHECK_EQ(JSRegExp::kSymbolMatchAllFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      {
        DirectHandle<JSFunction> fun = InstallFunctionAtSymbol(
            isolate_, prototype, factory->replace_symbol(), "[Symbol.replace]",
            Builtin::kRegExpPrototypeReplace, 2, kDontAdapt);
        native_context()->set_regexp_replace_function(*fun);
        DCHECK_EQ(JSRegExp::kSymbolReplaceFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      {
        DirectHandle<JSFunction> fun = InstallFunctionAtSymbol(
            isolate_, prototype, factory->search_symbol(), "[Symbol.search]",
            Builtin::kRegExpPrototypeSearch, 1, kAdapt);
        native_context()->set_regexp_search_function(*fun);
        DCHECK_EQ(JSRegExp::kSymbolSearchFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      {
        DirectHandle<JSFunction> fun = InstallFunctionAtSymbol(
            isolate_, prototype, factory->split_symbol(), "[Symbol.split]",
            Builtin::kRegExpPrototypeSplit, 2, kDontAdapt);
        native_context()->set_regexp_split_function(*fun);
        DCHECK_EQ(JSRegExp::kSymbolSplitFunctionDescriptorIndex,
                  prototype->map()->LastAdded().as_int());
      }

      DirectHandle<Map> prototype_map(prototype->map(), isolate());
      Map::SetShouldBeFastPrototypeMap(prototype_map, true, isolate_);
      CHECK_NE((*prototype_map).ptr(),
               isolate_->initial_object_prototype()->map().ptr());
      prototype_map->set_instance_type(JS_REG_EXP_PROTOTYPE_TYPE);

      // Store the initial RegExp.prototype map. This is used in fast-path
      // checks. Do not alter the prototype after this point.
      native_context()->set_regexp_prototype_map(*prototype_map);
    }

    {
      // RegExp getters and setters.

      InstallSpeciesGetter(isolate_, regexp_fun);

      // Static properties set by a successful match.

      SimpleInstallGetterSetter(isolate_, regexp_fun, factory->input_string(),
                                Builtin::kRegExpInputGetter,
                                Builtin::kRegExpInputSetter);
      SimpleInstallGetterSetter(isolate_, regexp_fun, "$_",
                                Builtin::kRegExpInputGetter,
                                Builtin::kRegExpInputSetter);

      SimpleInstallGetterSetter(isolate_, regexp_fun, "lastMatch",
                                Builtin::kRegExpLastMatchGetter,
                                Builtin::kEmptyFunction1);
      SimpleInstallGetterSetter(isolate_, regexp_fun, "$&",
                                Builtin::kRegExpLastMatchGetter,
                                Builtin::kEmptyFunction1);

      SimpleInstallGetterSetter(isolate_, regexp_fun, "lastParen",
                                Builtin::kRegExpLastParenGetter,
                                Builtin::kEmptyFunction1);
      SimpleInstallGetterSetter(isolate_, regexp_fun, "$+",
                                Builtin::kRegExpLastParenGetter,
                                Builtin::kEmptyFunction1);

      SimpleInstallGetterSetter(isolate_, regexp_fun, "leftContext",
                                Builtin::kRegExpLeftContextGetter,
                                Builtin::kEmptyFunction1);
      SimpleInstallGetterSetter(isolate_, regexp_fun, "$`",
                                Builtin::kRegExpLeftContextGetter,
                                Builtin::kEmptyFunction1);

      SimpleInstallGetterSetter(isolate_, regexp_fun, "rightContext",
                                Builtin::kRegExpRightContextGetter,
                                Builtin::kEmptyFunction1);
      SimpleInstallGetterSetter(isolate_, regexp_fun, "$'",
                                Builtin::kRegExpRightContextGetter,
                                Builtin::kEmptyFunction1);

#define INSTALL_CAPTURE_GETTER(i)                               \
  SimpleInstallGetterSetter(isolate_, regexp_fun, "$" #i,       \
                            Builtin::kRegExpCapture##i##Getter, \
                            Builtin::kEmptyFunction1)
      INSTALL_CAPTURE_GETTER(1);
      INSTALL_CAPTURE_GETTER(2);
      INSTALL_CAPTURE_GETTER(3);
      INSTALL_CAPTURE_GETTER(4);
      INSTALL_CAPTURE_GETTER(5);
      INSTALL_CAPTURE_GETTER(6);
      INSTALL_CAPTURE_GETTER(7);
      INSTALL_CAPTURE_GETTER(8);
      INSTALL_CAPTURE_GETTER(9);
#undef INSTALL_CAPTURE_GETTER
    }
    SetConstructorInstanceType(isolate_, regexp_fun,
                               JS_REG_EXP_CONSTRUCTOR_TYPE);

    DCHECK(regexp_fun->has_initial_map());
    DirectHandle<Map> initial_map(regexp_fun->initial_map(), isolate());

    DCHECK_EQ(1, initial_map->GetInObjectProperties());

    Map::EnsureDescriptorSlack(isolate_, initial_map, 1);

    // ECMA-262, section 15.10.7.5.
    PropertyAttributes writable =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE);
    Descriptor d = Descriptor::DataField(isolate(), factory->lastIndex_string(),
                                         JSRegExp::kLastIndexFieldIndex,
                                         writable, Representation::Tagged());
    initial_map->AppendDescriptor(isolate(), &d);

    // Create the last match info.
    DirectHandle<RegExpMatchInfo> last_match_info =
        RegExpMatchInfo::New(isolate(), RegExpMatchInfo::kMinCapacity);
    native_context()->set_regexp_last_match_info(*last_match_info);

    // Install the species protector cell.
    DirectHandle<PropertyCell> cell = factory->NewProtector();
    native_context()->set_regexp_species_protector(*cell);

    DCHECK(regexp_fun->HasFastProperties());
  }

  {  // --- R e g E x p S t r i n g  I t e r a t o r ---
    Handle<JSObject> iterator_prototype(
        native_context()->initial_iterator_prototype(), isolate());

    Handle<JSObject> regexp_string_iterator_prototype = factory->NewJSObject(
        isolate()->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate(), regexp_string_iterator_prototype,
                                iterator_prototype);

    InstallToStringTag(isolate(), regexp_string_iterator_prototype,
                       "RegExp String Iterator");

    SimpleInstallFunction(isolate(), regexp_string_iterator_prototype, "next",
                          Builtin::kRegExpStringIteratorPrototypeNext, 0,
                          kAdapt);

    DirectHandle<JSFunction> regexp_string_iterator_function = CreateFunction(
        isolate(), "RegExpStringIterator", JS_REG_EXP_STRING_ITERATOR_TYPE,
        JSRegExpStringIterator::kHeaderSize, 0,
        regexp_string_iterator_prototype, Builtin::kIllegal, 0, kDontAdapt);
    regexp_string_iterator_function->shared()->set_native(false);
    native_context()->set_initial_regexp_string_iterator_prototype_map(
        regexp_string_iterator_function->initial_map());
  }

  // -- E r r o r
  InstallError(isolate_, global, factory->Error_string(),
               Context::ERROR_FUNCTION_INDEX);

  // -- A g g r e g a t e E r r o r
  InstallError(isolate_, global, factory->AggregateError_string(),
               Context::AGGREGATE_ERROR_FUNCTION_INDEX,
               Builtin::kAggregateErrorConstructor, 2);

  // -- E v a l E r r o r
  InstallError(isolate_, global, factory->EvalError_string(),
               Context::EVAL_ERROR_FUNCTION_INDEX);

  // -- R a n g e E r r o r
  InstallError(isolate_, global, factory->RangeError_string(),
               Context::RANGE_ERROR_FUNCTION_INDEX);

  // -- R e f e r e n c e E r r o r
  InstallError(isolate_, global, factory->ReferenceError_string(),
               Context::REFERENCE_ERROR_FUNCTION_INDEX);

  // -- S y n t a x E r r o r
  InstallError(isolate_, global, factory->SyntaxError_string(),
               Context::SYNTAX_ERROR_FUNCTION_INDEX);

  // -- T y p e E r r o r
  InstallError(isolate_, global, factory->TypeError_string(),
               Context::TYPE_ERROR_FUNCTION_INDEX);

  // -- U R I E r r o r
  InstallError(isolate_, global, factory->URIError_string(),
               Context::URI_ERROR_FUNCTION_INDEX);

  {  // -- C o m p i l e E r r o r
    Handle<JSObject> dummy = factory->NewJSObject(isolate_->object_function());
    InstallError(isolate_, dummy, factory->CompileError_string(),
                 Context::WASM_COMPILE_ERROR_FUNCTION_INDEX);

    // -- L i n k E r r o r
    InstallError(isolate_, dummy, factory->LinkError_string(),
                 Context::WASM_LINK_ERROR_FUNCTION_INDEX);

    // -- R u n t i m e E r r o r
    InstallError(isolate_, dummy, factory->RuntimeError_string(),
                 Context::WASM_RUNTIME_ERROR_FUNCTION_INDEX);
  }

  // Initialize the embedder data slot.
  // TODO(ishell): microtask queue pointer will be moved from native context
  // to the embedder data array so we don't need an empty embedder data array.
  DirectHandle<EmbedderDataArray> embedder_data =
      factory->NewEmbedderDataArray(0);
  native_context()->set_embedder_data(*embedder_data);

  {  // -- g l o b a l T h i s
    DirectHandle<JSGlobalProxy> global_proxy(native_context()->global_proxy(),
                                             isolate_);
    JSObject::AddProperty(isolate_, global, factory->globalThis_string(),
                          global_proxy, DONT_ENUM);
  }

  {  // -- J S O N
    DirectHandle<Map> raw_json_map = factory->NewContextfulMapForCurrentContext(
        JS_RAW_JSON_TYPE, JSRawJson::kInitialSize, TERMINAL_FAST_ELEMENTS_KIND,
        1);
    Map::EnsureDescriptorSlack(isolate_, raw_json_map, 1);
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory->raw_json_string(),
          JSRawJson::kRawJsonInitialIndex, NONE, Representation::Tagged());
      raw_json_map->AppendDescriptor(isolate(), &d);
    }
    raw_json_map->SetPrototype(isolate(), raw_json_map, factory->null_value());
    raw_json_map->SetConstructor(native_context()->object_function());
    native_context()->set_js_raw_json_map(*raw_json_map);

    Handle<JSObject> json_object =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate_, global, "JSON", json_object, DONT_ENUM);
    SimpleInstallFunction(isolate_, json_object, "parse", Builtin::kJsonParse,
                          2, kDontAdapt);
    SimpleInstallFunction(isolate_, json_object, "stringify",
                          Builtin::kJsonStringify, 3, kAdapt);
    SimpleInstallFunction(isolate_, json_object, "rawJSON",
                          Builtin::kJsonRawJson, 1, kAdapt);
    SimpleInstallFunction(isolate_, json_object, "isRawJSON",
                          Builtin::kJsonIsRawJson, 1, kAdapt);
    InstallToStringTag(isolate_, json_object, "JSON");
    native_context()->set_json_object(*json_object);
  }

  {  // -- M a t h
    Handle<JSObject> math =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate_, global, "Math", math, DONT_ENUM);
    SimpleInstallFunction(isolate_, math, "abs", Builtin::kMathAbs, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "acos", Builtin::kMathAcos, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "acosh", Builtin::kMathAcosh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "asin", Builtin::kMathAsin, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "asinh", Builtin::kMathAsinh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "atan", Builtin::kMathAtan, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "atanh", Builtin::kMathAtanh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "atan2", Builtin::kMathAtan2, 2,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "ceil", Builtin::kMathCeil, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "cbrt", Builtin::kMathCbrt, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "expm1", Builtin::kMathExpm1, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "clz32", Builtin::kMathClz32, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "cos", Builtin::kMathCos, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "cosh", Builtin::kMathCosh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "exp", Builtin::kMathExp, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "floor", Builtin::kMathFloor, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "fround", Builtin::kMathFround, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "hypot", Builtin::kMathHypot, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, math, "imul", Builtin::kMathImul, 2,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "log", Builtin::kMathLog, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "log1p", Builtin::kMathLog1p, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "log2", Builtin::kMathLog2, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "log10", Builtin::kMathLog10, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "max", Builtin::kMathMax, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, math, "min", Builtin::kMathMin, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, math, "pow", Builtin::kMathPow, 2, kAdapt);
    SimpleInstallFunction(isolate_, math, "random", Builtin::kMathRandom, 0,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "round", Builtin::kMathRound, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "sign", Builtin::kMathSign, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "sin", Builtin::kMathSin, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "sinh", Builtin::kMathSinh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "sqrt", Builtin::kMathSqrt, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "tan", Builtin::kMathTan, 1, kAdapt);
    SimpleInstallFunction(isolate_, math, "tanh", Builtin::kMathTanh, 1,
                          kAdapt);
    SimpleInstallFunction(isolate_, math, "trunc", Builtin::kMathTrunc, 1,
                          kAdapt);

    // Install math constants.
    double const kE = base::ieee754::exp(1.0);
    double const kPI = 3.1415926535897932;
    InstallConstant(isolate_, math, "E", factory->NewNumber(kE));
    InstallConstant(isolate_, math, "LN10",
                    factory->NewNumber(base::ieee754::log(10.0)));
    InstallConstant(isolate_, math, "LN2",
                    factory->NewNumber(base::ieee754::log(2.0)));
    InstallConstant(isolate_, math, "LOG10E",
                    factory->NewNumber(base::ieee754::log10(kE)));
    InstallConstant(isolate_, math, "LOG2E",
                    factory->NewNumber(base::ieee754::log2(kE)));
    InstallConstant(isolate_, math, "PI", factory->NewNumber(kPI));
    InstallConstant(isolate_, math, "SQRT1_2",
                    factory->NewNumber(std::sqrt(0.5)));
    InstallConstant(isolate_, math, "SQRT2",
                    factory->NewNumber(std::sqrt(2.0)));
    InstallToStringTag(isolate_, math, "Math");
  }

#ifdef V8_INTL_SUPPORT
  {  // -- I n t l
    Handle<JSObject> intl =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate_, global, "Intl", intl, DONT_ENUM);

    // ecma402 #sec-Intl-toStringTag
    // The initial value of the @@toStringTag property is the string value
    // *"Intl"*.
    InstallToStringTag(isolate_, intl, "Intl");

    SimpleInstallFunction(isolate(), intl, "getCanonicalLocales",
                          Builtin::kIntlGetCanonicalLocales, 1, kDontAdapt);

    SimpleInstallFunction(isolate(), intl, "supportedValuesOf",
                          Builtin::kIntlSupportedValuesOf, 1, kDontAdapt);

    {  // -- D a t e T i m e F o r m a t
      Handle<JSFunction> date_time_format_constructor = InstallFunction(
          isolate_, intl, "DateTimeFormat", JS_DATE_TIME_FORMAT_TYPE,
          JSDateTimeFormat::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kDateTimeFormatConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate_, date_time_format_constructor,
          Context::INTL_DATE_TIME_FORMAT_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), date_time_format_constructor, "supportedLocalesOf",
          Builtin::kDateTimeFormatSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(date_time_format_constructor->prototype()), isolate_);

      InstallToStringTag(isolate_, prototype, "Intl.DateTimeFormat");

      SimpleInstallFunction(isolate_, prototype, "resolvedOptions",
                            Builtin::kDateTimeFormatPrototypeResolvedOptions, 0,
                            kDontAdapt);

      SimpleInstallFunction(isolate_, prototype, "formatToParts",
                            Builtin::kDateTimeFormatPrototypeFormatToParts, 1,
                            kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->format_string(),
                          Builtin::kDateTimeFormatPrototypeFormat, kDontAdapt);

      SimpleInstallFunction(isolate_, prototype, "formatRange",
                            Builtin::kDateTimeFormatPrototypeFormatRange, 2,
                            kDontAdapt);
      SimpleInstallFunction(isolate_, prototype, "formatRangeToParts",
                            Builtin::kDateTimeFormatPrototypeFormatRangeToParts,
                            2, kDontAdapt);
    }

    {  // -- N u m b e r F o r m a t
      Handle<JSFunction> number_format_constructor = InstallFunction(
          isolate_, intl, "NumberFormat", JS_NUMBER_FORMAT_TYPE,
          JSNumberFormat::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kNumberFormatConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate_, number_format_constructor,
          Context::INTL_NUMBER_FORMAT_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), number_format_constructor, "supportedLocalesOf",
          Builtin::kNumberFormatSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(number_format_constructor->prototype()), isolate_);

      InstallToStringTag(isolate_, prototype, "Intl.NumberFormat");

      SimpleInstallFunction(isolate_, prototype, "resolvedOptions",
                            Builtin::kNumberFormatPrototypeResolvedOptions, 0,
                            kDontAdapt);

      SimpleInstallFunction(isolate_, prototype, "formatToParts",
                            Builtin::kNumberFormatPrototypeFormatToParts, 1,
                            kDontAdapt);
      SimpleInstallGetter(isolate_, prototype, factory->format_string(),
                          Builtin::kNumberFormatPrototypeFormatNumber,
                          kDontAdapt);

      SimpleInstallFunction(isolate(), prototype, "formatRange",
                            Builtin::kNumberFormatPrototypeFormatRange, 2,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "formatRangeToParts",
                            Builtin::kNumberFormatPrototypeFormatRangeToParts,
                            2, kDontAdapt);
    }

    {  // -- C o l l a t o r
      Handle<JSFunction> collator_constructor =
          InstallFunction(isolate_, intl, "Collator", JS_COLLATOR_TYPE,
                          JSCollator::kHeaderSize, 0, factory->the_hole_value(),
                          Builtin::kCollatorConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(isolate_, collator_constructor,
                                       Context::INTL_COLLATOR_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), collator_constructor, "supportedLocalesOf",
          Builtin::kCollatorSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(collator_constructor->prototype()), isolate_);

      InstallToStringTag(isolate_, prototype, "Intl.Collator");

      SimpleInstallFunction(isolate_, prototype, "resolvedOptions",
                            Builtin::kCollatorPrototypeResolvedOptions, 0,
                            kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->compare_string(),
                          Builtin::kCollatorPrototypeCompare, kDontAdapt);
    }

    {  // -- V 8 B r e a k I t e r a t o r
      Handle<JSFunction> v8_break_iterator_constructor = InstallFunction(
          isolate_, intl, "v8BreakIterator", JS_V8_BREAK_ITERATOR_TYPE,
          JSV8BreakIterator::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kV8BreakIteratorConstructor, 0, kDontAdapt);

      SimpleInstallFunction(
          isolate_, v8_break_iterator_constructor, "supportedLocalesOf",
          Builtin::kV8BreakIteratorSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(v8_break_iterator_constructor->prototype()), isolate_);

      InstallToStringTag(isolate_, prototype, factory->Object_string());

      SimpleInstallFunction(isolate_, prototype, "resolvedOptions",
                            Builtin::kV8BreakIteratorPrototypeResolvedOptions,
                            0, kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->adoptText_string(),
                          Builtin::kV8BreakIteratorPrototypeAdoptText,
                          kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->first_string(),
                          Builtin::kV8BreakIteratorPrototypeFirst, kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->next_string(),
                          Builtin::kV8BreakIteratorPrototypeNext, kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->current_string(),
                          Builtin::kV8BreakIteratorPrototypeCurrent,
                          kDontAdapt);

      SimpleInstallGetter(isolate_, prototype, factory->breakType_string(),
                          Builtin::kV8BreakIteratorPrototypeBreakType,
                          kDontAdapt);
    }

    {  // -- P l u r a l R u l e s
      Handle<JSFunction> plural_rules_constructor = InstallFunction(
          isolate_, intl, "PluralRules", JS_PLURAL_RULES_TYPE,
          JSPluralRules::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kPluralRulesConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate_, plural_rules_constructor,
          Context::INTL_PLURAL_RULES_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), plural_rules_constructor, "supportedLocalesOf",
          Builtin::kPluralRulesSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(plural_rules_constructor->prototype()), isolate_);

      InstallToStringTag(isolate_, prototype, "Intl.PluralRules");

      SimpleInstallFunction(isolate_, prototype, "resolvedOptions",
                            Builtin::kPluralRulesPrototypeResolvedOptions, 0,
                            kDontAdapt);

      SimpleInstallFunction(isolate_, prototype, "select",
                            Builtin::kPluralRulesPrototypeSelect, 1,
                            kDontAdapt);

      SimpleInstallFunction(isolate(), prototype, "selectRange",
                            Builtin::kPluralRulesPrototypeSelectRange, 2,
                            kDontAdapt);
    }

    {  // -- R e l a t i v e T i m e F o r m a t
      Handle<JSFunction> relative_time_format_fun = InstallFunction(
          isolate(), intl, "RelativeTimeFormat", JS_RELATIVE_TIME_FORMAT_TYPE,
          JSRelativeTimeFormat::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kRelativeTimeFormatConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate_, relative_time_format_fun,
          Context::INTL_RELATIVE_TIME_FORMAT_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), relative_time_format_fun, "supportedLocalesOf",
          Builtin::kRelativeTimeFormatSupportedLocalesOf, 1, kDontAdapt);

      // Setup %RelativeTimeFormatPrototype%.
      Handle<JSObject> prototype(
          Cast<JSObject>(relative_time_format_fun->instance_prototype()),
          isolate());

      InstallToStringTag(isolate(), prototype, "Intl.RelativeTimeFormat");

      SimpleInstallFunction(
          isolate(), prototype, "resolvedOptions",
          Builtin::kRelativeTimeFormatPrototypeResolvedOptions, 0, kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "format",
                            Builtin::kRelativeTimeFormatPrototypeFormat, 2,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "formatToParts",
                            Builtin::kRelativeTimeFormatPrototypeFormatToParts,
                            2, kDontAdapt);
    }

    {  // -- L i s t F o r m a t
      Handle<JSFunction> list_format_fun = InstallFunction(
          isolate(), intl, "ListFormat", JS_LIST_FORMAT_TYPE,
          JSListFormat::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kListFormatConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate_, list_format_fun, Context::INTL_LIST_FORMAT_FUNCTION_INDEX);

      SimpleInstallFunction(isolate(), list_format_fun, "supportedLocalesOf",
                            Builtin::kListFormatSupportedLocalesOf, 1,
                            kDontAdapt);

      // Setup %ListFormatPrototype%.
      Handle<JSObject> prototype(
          Cast<JSObject>(list_format_fun->instance_prototype()), isolate());

      InstallToStringTag(isolate(), prototype, "Intl.ListFormat");

      SimpleInstallFunction(isolate(), prototype, "resolvedOptions",
                            Builtin::kListFormatPrototypeResolvedOptions, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "format",
                            Builtin::kListFormatPrototypeFormat, 1, kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "formatToParts",
                            Builtin::kListFormatPrototypeFormatToParts, 1,
                            kDontAdapt);
    }

    {  // -- L o c a l e
      Handle<JSFunction> locale_fun =
          InstallFunction(isolate(), intl, "Locale", JS_LOCALE_TYPE,
                          JSLocale::kHeaderSize, 0, factory->the_hole_value(),
                          Builtin::kLocaleConstructor, 1, kDontAdapt);
      InstallWithIntrinsicDefaultProto(isolate(), locale_fun,
                                       Context::INTL_LOCALE_FUNCTION_INDEX);

      // Setup %LocalePrototype%.
      Handle<JSObject> prototype(
          Cast<JSObject>(locale_fun->instance_prototype()), isolate());

      InstallToStringTag(isolate(), prototype, "Intl.Locale");

      SimpleInstallFunction(isolate(), prototype, "toString",
                            Builtin::kLocalePrototypeToString, 0, kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "maximize",
                            Builtin::kLocalePrototypeMaximize, 0, kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "minimize",
                            Builtin::kLocalePrototypeMinimize, 0, kDontAdapt);
      // Base locale getters.
      SimpleInstallGetter(isolate(), prototype, factory->language_string(),
                          Builtin::kLocalePrototypeLanguage, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->script_string(),
                          Builtin::kLocalePrototypeScript, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->region_string(),
                          Builtin::kLocalePrototypeRegion, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->baseName_string(),
                          Builtin::kLocalePrototypeBaseName, kAdapt);
      // Unicode extension getters.
      SimpleInstallGetter(isolate(), prototype, factory->calendar_string(),
                          Builtin::kLocalePrototypeCalendar, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->caseFirst_string(),
                          Builtin::kLocalePrototypeCaseFirst, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->collation_string(),
                          Builtin::kLocalePrototypeCollation, kAdapt);
      SimpleInstallGetter(isolate(), prototype,
                          factory->firstDayOfWeek_string(),
                          Builtin::kLocalePrototypeFirstDayOfWeek, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->hourCycle_string(),
                          Builtin::kLocalePrototypeHourCycle, kAdapt);
      SimpleInstallGetter(isolate(), prototype, factory->numeric_string(),
                          Builtin::kLocalePrototypeNumeric, kAdapt);
      SimpleInstallGetter(isolate(), prototype,
                          factory->numberingSystem_string(),
                          Builtin::kLocalePrototypeNumberingSystem, kAdapt);

      if (!v8_flags.harmony_remove_intl_locale_info_getters) {
        // Intl Locale Info functions
        SimpleInstallGetter(isolate(), prototype, factory->calendars_string(),
                            Builtin::kLocalePrototypeCalendars, kAdapt);
        SimpleInstallGetter(isolate(), prototype, factory->collations_string(),
                            Builtin::kLocalePrototypeCollations, kAdapt);
        SimpleInstallGetter(isolate(), prototype, factory->hourCycles_string(),
                            Builtin::kLocalePrototypeHourCycles, kAdapt);
        SimpleInstallGetter(isolate(), prototype,
                            factory->numberingSystems_string(),
                            Builtin::kLocalePrototypeNumberingSystems, kAdapt);
        SimpleInstallGetter(isolate(), prototype, factory->textInfo_string(),
                            Builtin::kLocalePrototypeTextInfo, kAdapt);
        SimpleInstallGetter(isolate(), prototype, factory->timeZones_string(),
                            Builtin::kLocalePrototypeTimeZones, kAdapt);
        SimpleInstallGetter(isolate(), prototype, factory->weekInfo_string(),
                            Builtin::kLocalePrototypeWeekInfo, kAdapt);
      }

      SimpleInstallFunction(isolate(), prototype, "getCalendars",
                            Builtin::kLocalePrototypeGetCalendars, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getCollations",
                            Builtin::kLocalePrototypeGetCollations, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getHourCycles",
                            Builtin::kLocalePrototypeGetHourCycles, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getNumberingSystems",
                            Builtin::kLocalePrototypeGetNumberingSystems, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getTimeZones",
                            Builtin::kLocalePrototypeGetTimeZones, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getTextInfo",
                            Builtin::kLocalePrototypeGetTextInfo, 0,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "getWeekInfo",
                            Builtin::kLocalePrototypeGetWeekInfo, 0,
                            kDontAdapt);
    }

    {  // -- D i s p l a y N a m e s
      Handle<JSFunction> display_names_fun = InstallFunction(
          isolate(), intl, "DisplayNames", JS_DISPLAY_NAMES_TYPE,
          JSDisplayNames::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kDisplayNamesConstructor, 2, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate(), display_names_fun,
          Context::INTL_DISPLAY_NAMES_FUNCTION_INDEX);

      SimpleInstallFunction(isolate(), display_names_fun, "supportedLocalesOf",
                            Builtin::kDisplayNamesSupportedLocalesOf, 1,
                            kDontAdapt);

      {
        // Setup %DisplayNamesPrototype%.
        Handle<JSObject> prototype(
            Cast<JSObject>(display_names_fun->instance_prototype()), isolate());

        InstallToStringTag(isolate(), prototype, "Intl.DisplayNames");

        SimpleInstallFunction(isolate(), prototype, "resolvedOptions",
                              Builtin::kDisplayNamesPrototypeResolvedOptions, 0,
                              kDontAdapt);

        SimpleInstallFunction(isolate(), prototype, "of",
                              Builtin::kDisplayNamesPrototypeOf, 1, kDontAdapt);
      }
    }

    {  // -- S e g m e n t e r
      Handle<JSFunction> segmenter_fun = InstallFunction(
          isolate(), intl, "Segmenter", JS_SEGMENTER_TYPE,
          JSSegmenter::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kSegmenterConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(isolate_, segmenter_fun,
                                       Context::INTL_SEGMENTER_FUNCTION_INDEX);
      SimpleInstallFunction(isolate(), segmenter_fun, "supportedLocalesOf",
                            Builtin::kSegmenterSupportedLocalesOf, 1,
                            kDontAdapt);
      {
        // Setup %SegmenterPrototype%.
        Handle<JSObject> prototype(
            Cast<JSObject>(segmenter_fun->instance_prototype()), isolate());
        // #sec-intl.segmenter.prototype-@@tostringtag
        //
        // Intl.Segmenter.prototype [ @@toStringTag ]
        //
        // The initial value of the @@toStringTag property is the String value
        // "Intl.Segmenter".
        InstallToStringTag(isolate(), prototype, "Intl.Segmenter");
        SimpleInstallFunction(isolate(), prototype, "resolvedOptions",
                              Builtin::kSegmenterPrototypeResolvedOptions, 0,
                              kDontAdapt);
        SimpleInstallFunction(isolate(), prototype, "segment",
                              Builtin::kSegmenterPrototypeSegment, 1,
                              kDontAdapt);
      }
      {
        // Setup %SegmentsPrototype%.
        Handle<JSObject> prototype = factory->NewJSObject(
            isolate()->object_function(), AllocationType::kOld);
        Handle<String> name_string =
            Name::ToFunctionName(isolate(), factory->Segments_string())
                .ToHandleChecked();
        DirectHandle<JSFunction> segments_fun = CreateFunction(
            isolate(), name_string, JS_SEGMENTS_TYPE, JSSegments::kHeaderSize,
            0, prototype, Builtin::kIllegal, 0, kDontAdapt);
        segments_fun->shared()->set_native(false);
        SimpleInstallFunction(isolate(), prototype, "containing",
                              Builtin::kSegmentsPrototypeContaining, 1,
                              kDontAdapt);
        InstallFunctionAtSymbol(isolate_, prototype, factory->iterator_symbol(),
                                "[Symbol.iterator]",
                                Builtin::kSegmentsPrototypeIterator, 0, kAdapt,
                                DONT_ENUM);
        DirectHandle<Map> segments_map(segments_fun->initial_map(), isolate());
        native_context()->set_intl_segments_map(*segments_map);
      }
      {
        // Setup %SegmentIteratorPrototype%.
        Handle<JSObject> iterator_prototype(
            native_context()->initial_iterator_prototype(), isolate());
        Handle<JSObject> prototype = factory->NewJSObject(
            isolate()->object_function(), AllocationType::kOld);
        JSObject::ForceSetPrototype(isolate(), prototype, iterator_prototype);
        // #sec-%segmentiteratorprototype%.@@tostringtag
        //
        // %SegmentIteratorPrototype% [ @@toStringTag ]
        //
        // The initial value of the @@toStringTag property is the String value
        // "Segmenter String Iterator".
        InstallToStringTag(isolate(), prototype, "Segmenter String Iterator");
        SimpleInstallFunction(isolate(), prototype, "next",
                              Builtin::kSegmentIteratorPrototypeNext, 0,
                              kDontAdapt);
        // Setup SegmentIterator constructor.
        Handle<String> name_string =
            Name::ToFunctionName(isolate(), factory->SegmentIterator_string())
                .ToHandleChecked();
        DirectHandle<JSFunction> segment_iterator_fun =
            CreateFunction(isolate(), name_string, JS_SEGMENT_ITERATOR_TYPE,
                           JSSegmentIterator::kHeaderSize, 0, prototype,
                           Builtin::kIllegal, 0, kDontAdapt);
        segment_iterator_fun->shared()->set_native(false);
        DirectHandle<Map> segment_iterator_map(
            segment_iterator_fun->initial_map(), isolate());
        native_context()->set_intl_segment_iterator_map(*segment_iterator_map);
      }
      {
        // Set up the maps for SegmentDataObjects, with and without "isWordLike"
        // property.
        constexpr int kNumProperties = 3;
        constexpr int kNumPropertiesWithWordlike = kNumProperties + 1;
        constexpr int kInstanceSize =
            JSObject::kHeaderSize + kNumProperties * kTaggedSize;
        constexpr int kInstanceSizeWithWordlike =
            JSObject::kHeaderSize + kNumPropertiesWithWordlike * kTaggedSize;
        DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
            JS_OBJECT_TYPE, kInstanceSize, TERMINAL_FAST_ELEMENTS_KIND,
            kNumProperties);
        DirectHandle<Map> map_with_wordlike =
            factory->NewContextfulMapForCurrentContext(
                JS_OBJECT_TYPE, kInstanceSizeWithWordlike,
                TERMINAL_FAST_ELEMENTS_KIND, kNumPropertiesWithWordlike);
        map->SetConstructor(native_context()->object_function());
        map_with_wordlike->SetConstructor(native_context()->object_function());
        map->set_prototype(*isolate_->initial_object_prototype());
        map_with_wordlike->set_prototype(*isolate_->initial_object_prototype());
        Map::EnsureDescriptorSlack(isolate_, map, kNumProperties);
        Map::EnsureDescriptorSlack(isolate_, map_with_wordlike,
                                   kNumPropertiesWithWordlike);
        int index = 0;
        {  // segment
          Descriptor d =
              Descriptor::DataField(isolate_, factory->segment_string(),
                                    index++, NONE, Representation::Tagged());
          map->AppendDescriptor(isolate_, &d);
          map_with_wordlike->AppendDescriptor(isolate_, &d);
        }
        {  // index
          Descriptor d =
              Descriptor::DataField(isolate_, factory->index_string(), index++,
                                    NONE, Representation::Tagged());
          map->AppendDescriptor(isolate_, &d);
          map_with_wordlike->AppendDescriptor(isolate_, &d);
        }
        {  // input
          Descriptor d =
              Descriptor::DataField(isolate_, factory->input_string(), index++,
                                    NONE, Representation::Tagged());
          map->AppendDescriptor(isolate_, &d);
          map_with_wordlike->AppendDescriptor(isolate_, &d);
        }
        DCHECK_EQ(index, kNumProperties);
        {  // isWordLike
          Descriptor d =
              Descriptor::DataField(isolate_, factory->isWordLike_string(),
                                    index++, NONE, Representation::Tagged());
          map_with_wordlike->AppendDescriptor(isolate_, &d);
        }
        DCHECK_EQ(index, kNumPropertiesWithWordlike);
        DCHECK(!map->is_dictionary_map());
        DCHECK(!map_with_wordlike->is_dictionary_
"""


```