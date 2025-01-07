Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The code is within a function likely related to initializing or setting up JavaScript built-in objects in the V8 engine. The frequent calls to `SimpleInstallFunction`, `InstallFunction`, `InstallConstant`, and similar functions clearly indicate the registration of JavaScript functionalities. The names of the installed functions (like `match`, `replace`, `Date`, `Promise`, `RegExp`) strongly suggest this is related to setting up core JavaScript objects and their methods.

2. **Focus on the `SimpleInstallFunction` Calls:**  This function appears to be a key mechanism for attaching JavaScript functions to prototype objects. The parameters suggest it takes the `isolate` (V8's execution context), the `prototype` object, the JavaScript function name (e.g., "match"), a `Builtin` enum value (likely a C++ implementation detail), an arity, and an adaptation flag.

3. **Analyze the Sections Separately:**  The code is organized into blocks delimited by comments like `// --- S t r i n g ---`, `// --- S y m b o l ---`, etc. This suggests that each block is responsible for setting up the properties of a specific JavaScript built-in object.

4. **String Block Breakdown:**
   - It targets `String.prototype`.
   - It installs methods like `match`, `matchAll`, `normalize`, `padEnd`, `padStart`, `repeat`, `replace`, `replaceAll`, `search`, `slice`, `small`, `split`, `strike`, `sub`, `substr`, `substring`, `sup`, `startsWith`, `toString`, `toWellFormed`, `trim`, `trimStart` (with `trimLeft` alias), `trimEnd` (with `trimRight` alias), `toLocaleLowerCase`, `toLocaleUpperCase`, `toLowerCase`, `toUpperCase`, `valueOf`, and the `Symbol.iterator`.
   - The `#ifdef V8_INTL_SUPPORT` indicates conditional inclusion of internationalization-related functions.

5. **Symbol Block Breakdown:**
   - It installs the `Symbol` constructor function on the global object.
   - It installs static methods like `Symbol.for` and `Symbol.keyFor`.
   - It installs well-known symbols like `Symbol.asyncIterator`, `Symbol.hasInstance`, etc. as constants on the `Symbol` constructor.
   - It sets up `Symbol.prototype` with methods like `toString`, `valueOf`, and a getter for `description`.
   - It installs the `Symbol.toPrimitive` method.

6. **Date Block Breakdown:**
   - It installs the `Date` constructor function on the global object.
   - It installs static methods like `Date.now`, `Date.parse`, and `Date.UTC`.
   - It sets up `Date.prototype` with a large number of methods for getting and setting date components, converting dates to strings in various formats, and the `Symbol.toPrimitive` method. Again, `#ifdef V8_INTL_SUPPORT` shows conditional inclusion for internationalization.

7. **Promise Block Breakdown:**
   - It installs the `Promise` constructor function.
   - It installs static methods like `Promise.all`, `Promise.allSettled`, `Promise.any`, `Promise.race`, `Promise.resolve`, `Promise.reject`, and `Promise.withResolvers`.
   - It sets up `Promise.prototype` with methods like `then`, `catch`, and `finally`.

8. **RegExp Block Breakdown:**
   - It installs the `RegExp` constructor function.
   - It sets up `RegExp.prototype` with methods like `exec`, `compile`, `toString`, `test`, and methods associated with well-known symbols (`Symbol.match`, `Symbol.matchAll`, etc.). It also includes getters for properties like `dotAll`, `flags`, `global`, etc.
   - It installs static getter/setter properties on the `RegExp` constructor related to the last match (e.g., `input`, `lastMatch`).

9. **RegExp String Iterator Block Breakdown:**
   - It sets up the `RegExp String Iterator` prototype, used for iterating over the results of `RegExp.prototype.exec` with the `g` flag.

10. **Error Block and Aggregate Error Block Breakdown:**
    - It installs the `Error` and `AggregateError` constructor functions. The `InstallError` function seems like a helper.

11. **Infer General Functionality:**  Based on the individual block analyses, the overall function appears to be responsible for the initial setup of core JavaScript built-in objects and their associated methods and properties. This is a crucial part of the V8 engine's bootstrapping process.

12. **Address Specific Questions:**
   - **.tq suffix:** The code is C++, so it's not a Torque file.
   - **JavaScript Relationship:**  Each installed function directly corresponds to a JavaScript built-in method. I can easily provide examples for methods like `String.prototype.match`, `Date.now`, `Promise.resolve`, `RegExp.prototype.test`, etc.
   - **Code Logic Reasoning:** The logic is primarily about registering functions and properties. The conditional compilation with `#ifdef V8_INTL_SUPPORT` is a specific piece of conditional logic.
   - **User Errors:** I can provide examples of common mistakes when using these built-in functions (e.g., incorrect arguments to `slice`, misunderstandings about `replace` vs. `replaceAll`).

13. **Summarize the Functionality:**  The core function is to initialize and install the fundamental JavaScript built-in objects (String, Symbol, Date, Promise, RegExp, Error) and their prototypes with their respective methods and properties during V8's startup. This makes these essential JavaScript features available for use.

By following these steps, I can systematically dissect the C++ code, understand its purpose within the V8 engine, and answer the specific questions posed in the prompt, including providing relevant JavaScript examples and common user errors.
好的，让我们来分析一下这段 V8 源代码的功能。

**功能概括:**

这段代码的主要功能是 **在 V8 引擎启动时，为 JavaScript 的内置对象 `String`, `Symbol`, `Date`, `Promise`, `RegExp`, `Error`, `AggregateError` 等创建和安装它们的构造函数、原型对象以及原型方法和属性。**  它将 C++ 的内置函数与 JavaScript 的内置方法关联起来，使得 JavaScript 代码能够调用这些底层实现。

**详细功能分解:**

1. **为 `String` 对象安装属性和方法:**
   - 这段代码块针对 `String.prototype`，为字符串对象安装了大量的内置方法。
   - `SimpleInstallFunction` 是一个用于将 C++ 的内置函数（`Builtin::kStringPrototype...`）关联到 `String.prototype` 上的 JavaScript 方法的辅助函数。
   - 示例中的每个 `SimpleInstallFunction` 调用都对应着 `String.prototype` 的一个方法，例如 `match`, `matchAll`, `normalize`, `padEnd`, `padStart`, `repeat`, `replace`, `replaceAll`, `search`, `slice`, `split` 等。
   - 针对 `trimStart` 和 `trimEnd`，还安装了别名 `trimLeft` 和 `trimRight`。
   -  还包括了 `toLocaleLowerCase`, `toLocaleUpperCase`, `toLowerCase`, `toUpperCase`, `valueOf` 以及作为迭代器的 `Symbol.iterator`。

2. **为 `String Iterator` 对象安装属性和方法:**
   -  创建了 `String Iterator` 的原型对象，并安装了 `next` 方法，这是迭代器协议的核心。

3. **为 `Symbol` 对象安装属性和方法:**
   - 安装了 `Symbol` 构造函数。
   - 安装了静态方法 `Symbol.for` 和 `Symbol.keyFor`。
   - 安装了许多预定义的 well-known symbols，例如 `Symbol.asyncIterator`, `Symbol.hasInstance`, `Symbol.iterator` 等。
   - 为 `Symbol.prototype` 安装了 `toString`, `valueOf` 方法以及 `description` 的 getter。
   - 安装了 `Symbol.prototype[Symbol.toPrimitive]` 方法。

4. **为 `Date` 对象安装属性和方法:**
   - 安装了 `Date` 构造函数。
   - 安装了静态方法 `Date.now`, `Date.parse`, `Date.UTC`。
   - 为 `Date.prototype` 安装了大量的日期操作方法，例如 `toString`, `toDateString`, `toTimeString`, `toISOString`, `getDate`, `setDate`, `getFullYear`, `setFullYear`, `getHours`, `setHours` 等等。
   - 同样也包括了 `toLocaleString`, `toLocaleDateString`, `toLocaleTimeString` 以及 `Symbol.prototype[Symbol.toPrimitive]`。

5. **为 `Promise` 对象安装属性和方法:**
   - 安装了 `Promise` 构造函数。
   - 安装了静态方法 `Promise.all`, `Promise.allSettled`, `Promise.any`, `Promise.race`, `Promise.resolve`, `Promise.reject`, `Promise.withResolvers`。
   - 为 `Promise.prototype` 安装了 `then`, `catch`, `finally` 方法。

6. **为 `RegExp` 对象安装属性和方法:**
   - 安装了 `RegExp` 构造函数。
   - 为 `RegExp.prototype` 安装了正则表达式操作的方法，例如 `exec`, `compile`, `test` 以及通过 Symbol 定义的方法 `Symbol.match`, `Symbol.matchAll`, `Symbol.replace`, `Symbol.search`, `Symbol.split`。
   - 安装了 `RegExp` 的一些 getter 方法，例如 `dotAll`, `flags`, `global`, `ignoreCase`, `multiline`, `source`, `sticky`, `unicode`, `unicodeSets`。
   - 安装了 `RegExp` 的静态属性的 getter 和 setter，例如 `input`, `lastMatch`, `lastParen`, `leftContext`, `rightContext` 以及捕获组的 getter (`$1` 到 `$9`)。

7. **为 `RegExp String Iterator` 对象安装属性和方法:**
   - 创建了 `RegExp String Iterator` 的原型对象，并安装了 `next` 方法。

8. **为 `Error` 和 `AggregateError` 对象安装属性和方法:**
   - 调用 `InstallError` 函数安装了 `Error` 和 `AggregateError` 构造函数。

**关于 `.tq` 后缀:**

如果 `v8/src/init/bootstrapper.cc` 以 `.tq` 结尾，那么它的确是 V8 的 Torque 源代码。Torque 是一种用于定义 V8 内置函数的领域特定语言。然而，根据你提供的文件名是 `.cc`，**它是一个 C++ 源代码文件**。

**与 JavaScript 功能的关系 (以及 JavaScript 示例):**

这段 C++ 代码直接关联着 JavaScript 的内置对象和方法。它定义了这些方法在 V8 引擎底层的实现。当你在 JavaScript 中使用这些方法时，V8 引擎会调用这里安装的对应的 C++ 内置函数。

**JavaScript 示例:**

```javascript
// String 方法
const str = "hello world";
console.log(str.match(/o/));        // 调用了 Builtin::kStringPrototypeMatch
console.log(str.replace("world", "javascript")); // 调用了 Builtin::kStringPrototypeReplace

// Symbol 方法
const mySymbol = Symbol("mySymbol");
console.log(mySymbol.toString());   // 调用了 Builtin::kSymbolPrototypeToString

// Date 方法
const now = new Date();
console.log(now.getFullYear());     // 调用了 Builtin::kDatePrototypeGetFullYear

// Promise 方法
const promise = Promise.resolve(5);
promise.then(value => console.log(value)); // 调用了 Builtin::kPromisePrototypeThen

// RegExp 方法
const regex = /pattern/;
console.log(regex.test("some pattern")); // 调用了 Builtin::kRegExpPrototypeTest
```

**代码逻辑推理 (假设输入与输出):**

这里的代码逻辑主要是 **注册** 和 **关联**。`SimpleInstallFunction` 等函数接收一些参数（如 `isolate_`, `prototype`, 方法名字符串, `Builtin::k...` 等），并将 JavaScript 方法名与底层的 C++ 实现关联起来。

**假设输入:**  V8 引擎启动，需要初始化 JavaScript 环境。
**输出:**  `String.prototype`, `Symbol.prototype`, `Date.prototype`, `Promise.prototype`, `RegExp.prototype` 等对象上都安装好了对应的 JavaScript 方法，这些方法背后关联着高效的 C++ 实现。

**涉及用户常见的编程错误:**

用户在使用这些内置方法时可能会犯各种错误，例如：

- **类型错误:** 传递了错误类型的参数，例如 `String.prototype.slice(1, "abc")` (第二个参数应该是数字)。
- **参数个数错误:** 传递了过多或过少的参数。
- **对 `replace` 和 `replaceAll` 的混淆:**  `replace` 默认只替换第一个匹配项，而 `replaceAll` 替换所有匹配项。
  ```javascript
  const text = "ababab";
  console.log(text.replace("a", "c"));   // 输出 "cbabab"
  console.log(text.replaceAll("a", "c")); // 输出 "cbcbcb"
  ```
- **正则表达式的使用错误:**  例如正则表达式的语法错误，或者在使用 `match` 等方法时对返回值的理解不正确。
- **日期操作的复杂性:** `Date` 对象的操作容易出错，例如时区问题、月份从 0 开始计数等。

**归纳功能 (第 5 部分，共 11 部分):**

考虑到这是第 5 部分，并且前面的部分很可能已经初始化了 V8 引擎的核心结构和一些基础对象，那么这部分的功能是 **继续构建核心 JavaScript 环境，具体而言是安装和初始化 `String`, `Symbol`, `Date`, `Promise`, `RegExp` 和 `Error` 等关键的内置对象及其方法。**  这为后续 JavaScript 代码的执行提供了必要的基石。可以推测，后续的部分可能会涉及其他内置对象、全局对象、模块系统等的初始化。

总而言之，`v8/src/init/bootstrapper.cc` 的这一部分是 V8 引擎启动过程中至关重要的一步，它负责将 JavaScript 的语言特性与 V8 引擎的底层实现连接起来，使得 JavaScript 代码能够在 V8 上高效运行。

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共11部分，请归纳一下它的功能

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
  InstallError(isolate_, global, f
"""


```