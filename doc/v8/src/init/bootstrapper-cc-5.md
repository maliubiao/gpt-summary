Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

**1. Initial Understanding of the Context:**

The prompt states this is part 6 of 11 of the `v8/src/init/bootstrapper.cc` file. The name "bootstrapper" strongly suggests initialization. The file path reinforces this, placing it within the initialization phase of V8. The prompt also mentions `.tq` files and their relation to Torque, which is relevant context for other parts of the bootstrapper but not directly this snippet.

**2. High-Level Scan for Key Operations:**

I quickly scan the code looking for repeated patterns and recognizable V8 API calls. Several things jump out:

* **`InstallError(...)`:** This function is called repeatedly for different error types (RangeError, ReferenceError, etc.). This strongly suggests setting up standard JavaScript error objects.
* **`factory->..._string()`:**  Calls to `factory` with `_string` suffixes indicate the retrieval of internalized strings (likely names of properties or objects).
* **`NewJSObject(...)`:**  This clearly creates JavaScript objects.
* **`AddProperty(...)`:**  This adds properties to JavaScript objects.
* **`SimpleInstallFunction(...)`:**  This installs built-in JavaScript functions (like `Math.abs`, `JSON.parse`). The `Builtin::k...` argument confirms this.
* **`InstallConstant(...)`:**  Installs constants (like `Math.PI`, `Math.E`).
* **`InstallToStringTag(...)`:**  Sets the `@@toStringTag` symbol on objects, which affects how they are represented as strings.
* **The large block related to "Intl":**  This section clearly deals with the ECMAScript Internationalization API.

**3. Grouping Related Operations:**

I start to group the operations by the JavaScript globals or objects they are manipulating:

* **Errors:** All the `InstallError` calls form a logical group.
* **`globalThis`:** The section dealing with `globalThis` is self-contained.
* **`JSON`:** The code block for `JSON` is clearly setting up the `JSON` global object and its methods.
* **`Math`:**  The extensive `Math` block installs various mathematical functions and constants.
* **`Intl`:** The large `Intl` block initializes the various components of the Internationalization API (DateTimeFormat, NumberFormat, Collator, etc.).

**4. Inferring Functionality for Each Group:**

Now, I analyze each group to determine its purpose:

* **Errors:**  The `InstallError` calls clearly register the standard JavaScript error constructors within the global object. This allows JavaScript code to throw and catch these specific error types.
* **`globalThis`:** This sets up the `globalThis` property to point to the global proxy object. This is a standard JavaScript feature for accessing the global scope.
* **`JSON`:** This code initializes the `JSON` global object and its core methods: `parse`, `stringify`, `rawJSON`, and `isRawJSON`. This makes the `JSON` API available in JavaScript.
* **`Math`:**  This populates the `Math` global object with common mathematical functions and constants.
* **`Intl`:** This is the most complex part. I recognize the pattern of installing constructors and prototype methods for various `Intl` objects. This makes the Internationalization API available, enabling locale-sensitive formatting, comparisons, and other operations.

**5. Answering Specific Questions from the Prompt:**

* **Functionality:** Based on the grouping and analysis, I can now list the core functionalities.
* **`.tq` files:** I note that this file is `.cc`, not `.tq`, and explain the significance of `.tq` for Torque.
* **Relationship to JavaScript:** I explicitly connect the C++ code to the JavaScript features being initialized (e.g., `JSON.parse`, `Math.sin`, `Intl.DateTimeFormat`).
* **JavaScript Examples:** I create simple JavaScript code snippets to demonstrate the functionality being set up (throwing errors, using `JSON`, `Math`, and `Intl`).
* **Code Logic Inference (Input/Output):**  For the error installation, I can provide a simple example of a JavaScript error being thrown and caught. For `Math` and `JSON`, input/output examples are straightforward. The `Intl` API's behavior is heavily dependent on locale, so a simple example showing formatting differences is useful.
* **Common Programming Errors:** I think about typical mistakes related to the initialized objects (e.g., `JSON.parse` with invalid input, incorrect usage of `Math` functions, and locale errors with `Intl`).
* **Summary of Functionality (Part 6):** I consolidate the findings into a concise summary focusing on setting up core JavaScript globals and the Internationalization API.

**6. Iteration and Refinement:**

After the initial analysis, I review my answers to ensure they are accurate, clear, and well-organized. I might rephrase sentences or add more specific details. For instance, I might initially just say "installs error objects" but then refine it to "registers standard JavaScript error constructors within the global object, making them available for use in JavaScript code."

This methodical approach, combining high-level scanning with detailed analysis of code blocks and relating it back to the JavaScript context, allows for a comprehensive understanding of the functionality of this V8 bootstrapper code snippet.
这是对 `v8/src/init/bootstrapper.cc` 源代码片段的功能分析，重点关注提供的第 6 部分。

**主要功能归纳 (基于提供的代码片段):**

这段代码的主要功能是 **在 V8 引擎启动时，初始化并配置一些重要的 JavaScript 全局对象和构造函数，特别是与错误处理、JSON 和 Math 对象以及国际化 (Intl) API 相关的部分。**

**具体功能分解：**

1. **初始化标准错误对象：**
   - 代码通过 `InstallError` 函数，将 JavaScript 的标准错误构造函数（`RangeError`, `ReferenceError`, `SyntaxError`, `TypeError`, `URIError`）添加到全局对象中。
   - 同时也初始化了 WebAssembly 相关的错误构造函数 (`CompileError`, `LinkError`, `RuntimeError`)，但将它们安装到一个临时的 `dummy` 对象上，这可能表明这些错误的处理方式稍有不同或在后续步骤中会关联到特定的 WebAssembly 上下文。

2. **初始化 Embedder Data Slot:**
   -  创建了一个空的 `EmbedderDataArray` 并将其设置到 `native_context` 中。这为嵌入器（例如 Chrome）提供了存储自身数据的空间。

3. **设置 `globalThis`:**
   - 将一个名为 `globalThis` 的属性添加到全局对象，使其指向全局代理对象本身。这是 ES6 引入的标准特性，用于明确获取全局对象。

4. **初始化 `JSON` 对象:**
   - 创建并初始化了全局 `JSON` 对象。
   - 在 `JSON` 对象上安装了 `parse`、`stringify`、`rawJSON` 和 `isRawJSON` 等方法。
   - 设置了 `JSON` 对象的 `@@toStringTag` 为 "JSON"。

5. **初始化 `Math` 对象:**
   - 创建并初始化了全局 `Math` 对象。
   - 在 `Math` 对象上安装了大量的数学函数，例如 `abs`, `acos`, `sin`, `cos`, `log`, `random` 等。
   - 安装了一些数学常量，例如 `E`, `PI`, `LN2` 等。
   - 设置了 `Math` 对象的 `@@toStringTag` 为 "Math"。

6. **初始化国际化 (Intl) API:**
   - 如果启用了国际化支持 (`#ifdef V8_INTL_SUPPORT`)，代码会创建并初始化全局 `Intl` 对象。
   - 在 `Intl` 对象上安装了各种国际化相关的构造函数，例如 `DateTimeFormat`（日期和时间格式化）、`NumberFormat`（数字格式化）、`Collator`（字符串比较）、`v8BreakIterator`（文本分段）、`PluralRules`（复数规则）、`RelativeTimeFormat`（相对时间格式化）、`ListFormat`（列表格式化）、`Locale`（区域设置）和 `DisplayNames`（展示名称）。
   - 对于每个 Intl API 的构造函数，都会进行以下操作：
     - 创建构造函数并将其添加到 `Intl` 对象。
     - 设置原型对象。
     - 在原型对象上安装各种方法（例如 `resolvedOptions`, `format`, `compare` 等）和 getter (例如 `format`)。
     - 设置 `@@toStringTag` 以便正确识别对象类型。
   - 特别地，对于 `Segmenter` API，还涉及到 `Segments` 和 `SegmentIterator` 的初始化，用于文本分段迭代。

**关于 `.tq` 文件：**

您是正确的。如果 `v8/src/init/bootstrapper.cc` 文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的类型安全的 DSL（领域特定语言），用于编写高效的内置函数。 然而，根据您提供的文件路径和扩展名 `.cc`，这表明它是一个标准的 C++ 源文件。

**与 JavaScript 功能的关系及示例：**

这段 C++ 代码直接负责在 JavaScript 运行时环境中创建和配置一些核心的全局对象和功能。以下是一些 JavaScript 示例，展示了这些代码初始化的功能：

**错误处理:**

```javascript
try {
  parseInt("abc"); // 导致 NaN，可能在某些操作中抛出错误
  let arr = [];
  arr[10].toString(); // 访问不存在的索引，抛出 RangeError 或类似错误
} catch (e) {
  if (e instanceof ReferenceError) {
    console.error("ReferenceError caught:", e.message);
  } else if (e instanceof TypeError) {
    console.error("TypeError caught:", e.message);
  }
  // ... 其他错误类型
}
```

**JSON:**

```javascript
const jsonString = '{"name": "John", "age": 30}';
const jsonObject = JSON.parse(jsonString);
console.log(jsonObject.name); // 输出: John

const obj = { city: "New York" };
const jsonOutput = JSON.stringify(obj);
console.log(jsonOutput); // 输出: {"city":"New York"}
```

**Math:**

```javascript
console.log(Math.abs(-5));     // 输出: 5
console.log(Math.sqrt(16));    // 输出: 4
console.log(Math.random());    // 输出: 0 到 1 之间的随机数
console.log(Math.PI);        // 输出: 3.141592653589793
```

**Intl (如果启用):**

```javascript
const now = new Date();
const dateFormatter = new Intl.DateTimeFormat('zh-CN');
console.log(dateFormatter.format(now)); // 输出: 类似 "2023/10/27" 的中文日期

const number = 1234567.89;
const numberFormatter = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });
console.log(numberFormatter.format(number)); // 输出: "$1,234,567.89"

const list = ['apple', 'banana', 'orange'];
const listFormatter = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' });
console.log(listFormatter.format(list)); // 输出: "apple, banana, and orange"
```

**代码逻辑推理 (假设输入与输出):**

这段代码主要是初始化操作，而不是执行具体的业务逻辑。因此，直接用假设输入和输出来描述不太适用。更准确地说，它的“输入”是 V8 引擎的启动过程和编译后的代码，“输出”是初始化好的 JavaScript 运行环境，包含了这些全局对象和函数。

例如，对于错误处理部分：

- **假设输入：** V8 引擎启动，执行到 `bootstrapper.cc` 的这段代码。
- **输出：** 全局对象 `global`（或在浏览器环境中是 `window`）上拥有了 `RangeError`, `ReferenceError` 等属性，这些属性指向对应的错误构造函数。

**用户常见的编程错误举例：**

由于这段代码涉及到全局对象的初始化，用户常见的编程错误通常是 **误用或覆盖这些全局对象或其属性**。

1. **错误地重新赋值全局对象：**
   ```javascript
   // 错误的做法，会导致问题
   JSON = null;
   Math = {};
   ```
   这样做会破坏 V8 引擎的内置功能，导致程序崩溃或行为异常。

2. **错误地修改全局对象的属性：**
   ```javascript
   // 错误的做法，可能会影响其他代码
   Math.PI = 4;
   ```
   修改内置常量的行为是不可预测且危险的。

3. **在使用 Intl API 时指定了无效的 locale 或选项：**
   ```javascript
   // 可能导致运行时错误
   const formatter = new Intl.NumberFormat('invalid-locale');
   ```
   V8 会尝试处理这种情况，但可能会抛出异常或使用默认值。

**总结第 6 部分的功能：**

总而言之，`v8/src/init/bootstrapper.cc` 的第 6 部分代码负责在 V8 引擎启动时，至关重要地初始化了 JavaScript 的标准错误处理机制、核心的 `JSON` 和 `Math` 全局对象，以及提供了国际化 (Intl) API 的基础。这为后续的 JavaScript 代码执行奠定了基础，使得开发者可以使用这些预定义的全局对象和功能。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
actory->RangeError_string(),
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
```