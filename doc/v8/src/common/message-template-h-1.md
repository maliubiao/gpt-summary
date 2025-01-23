Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understanding the Goal:** The request asks for the functionality of the `message-template.h` file in V8, along with specific considerations for Torque, JavaScript relevance, code logic, and common programming errors. It's part 2 of a larger analysis, so a summary is also needed.

2. **Initial Scan and Keyword Identification:**  I'll first read through the file, looking for obvious patterns and keywords. I see a large macro `MESSAGE_TEMPLATES`, an enum `MessageTemplate`, and a function `MessageTemplateFromInt`. The macro lists many entries that look like error messages.

3. **Dissecting the `MESSAGE_TEMPLATES` Macro:** This is the core of the file. The `#define TEMPLATE(NAME, STRING)` and the subsequent `#undef TEMPLATE` strongly suggest this is a preprocessor trick to generate code based on the list. The `T(Name, "String")` pattern within `MESSAGE_TEMPLATES` reinforces this. It looks like it's defining pairs of a name and a string.

4. **Connecting to the `MessageTemplate` Enum:** The `MESSAGE_TEMPLATES(TEMPLATE)` line within the `enum class MessageTemplate` declaration is the key connection. The `TEMPLATE` macro is being applied to each entry in the `MESSAGE_TEMPLATES` list. Specifically, it's being used to create enum constants. So, `T(OutOfMemory, "%: Out of memory")` becomes `kOutOfMemory,`. This means the enum `MessageTemplate` is essentially a list of all the possible error/message types.

5. **Analyzing `MessageTemplateFromInt`:** This function takes an integer and converts it to a `MessageTemplate` enum value. The `DCHECK_LT` suggests it's a debug assertion to ensure the input integer is within the valid range of the enum. This confirms the enum is likely indexed or has a sequential representation.

6. **Inferring Functionality:** Based on the above, the primary function of this header file is to define a centralized and easily maintainable list of message templates (mostly error messages) used within the V8 engine. The enum provides a way to refer to these messages programmatically. The `MessageTemplateFromInt` function helps in converting numeric IDs (potentially stored elsewhere) back into the specific message template.

7. **Addressing the Torque Question:** The prompt asks if the file is a Torque source if it ended in `.tq`. Since this file ends in `.h`, it's a C++ header file. Torque files are different and have their own syntax for defining types and builtins.

8. **Considering JavaScript Relevance:** These message templates are the foundation for the error messages that JavaScript developers see. When a JavaScript runtime error occurs, V8 uses these templates to construct the error message.

9. **Providing JavaScript Examples:** To illustrate the JavaScript connection, it's important to show how these template names relate to actual JavaScript errors. Mapping some of the `T(...)` entries to common JavaScript errors (e.g., `TypeError`, `SyntaxError`, `ReferenceError`) and showing how the template strings appear in those errors is crucial. I'd choose examples that are readily understandable by JavaScript developers.

10. **Thinking about Code Logic Inference:**  The file itself doesn't contain complex logic. The main logic is the mapping between the template names and their string representations. The input is the `MessageTemplate` enum value (or its integer representation), and the output is the corresponding string template. I'd create an example showing how `MessageTemplateFromInt` could be used (hypothetically) to retrieve the string.

11. **Identifying Common Programming Errors:** The message templates themselves often describe common JavaScript programming errors. I would pick a few examples from the list that directly correspond to frequent mistakes developers make (e.g., `TypeError: Cannot read properties of undefined`, `SyntaxError: Unexpected token`).

12. **Writing the Summary (Part 2):** The summary should reiterate the main function of the file: providing a central repository for message templates. It should also emphasize the benefits of this approach (consistency, maintainability, localization potential).

13. **Review and Refine:** Finally, I'd reread my analysis to ensure accuracy, clarity, and completeness. I'd double-check that I've addressed all parts of the prompt and provided clear explanations and examples. I'd also ensure the formatting is easy to read. For instance, using code blocks for examples enhances readability. Making sure to explicitly state what isn't the case (like the Torque part) is also important.
好的，让我们来分析一下 `v8/src/common/message-template.h` 这个文件的功能。

**功能列举:**

1. **定义了一系列预定义的错误和警告消息模板:**  这个头文件通过宏 `MESSAGE_TEMPLATES` 定义了大量的消息模板。每个模板都有一个唯一的名称（例如 `OutOfMemory`，`InvalidLhsInAssignment`）和一个与之关联的字符串（例如 `"%: Out of memory"`，`"Invalid left-hand side in assignment"`）。

2. **使用枚举 `MessageTemplate` 来管理消息模板:**  通过枚举类型 `MessageTemplate`，V8 可以使用枚举常量（如 `kOutOfMemory`）来引用这些消息模板，而不是直接使用字符串。这提高了代码的可读性和维护性。

3. **提供了一个将整数 ID 转换为 `MessageTemplate` 枚举值的函数:**  `MessageTemplateFromInt` 函数可以将一个整数类型的消息 ID 转换为对应的 `MessageTemplate` 枚举值。这在内部处理消息时非常有用，可以使用数字 ID 进行传递和存储，然后在需要时转换回枚举类型。

**关于 `.tq` 结尾:**

如果 `v8/src/common/message-template.h` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义内置函数和类型系统的领域特定语言。在这种情况下，该文件会包含使用 Torque 语法定义的类型信息或者内置函数的实现，而当前的文件是 C++ 头文件。

**与 JavaScript 的功能关系 (以及 JavaScript 示例):**

`v8/src/common/message-template.h` 中定义的消息模板直接对应于 JavaScript 运行时可能抛出的各种错误和警告信息。当 JavaScript 代码执行过程中遇到错误时，V8 引擎会使用这些模板来生成用户看到的错误消息。

**JavaScript 示例:**

```javascript
// 对应 MessageTemplate::kOutOfMemory
try {
  // 尝试分配一个非常大的数组，可能导致内存溢出
  const hugeArray = new Array(Number.MAX_SAFE_INTEGER);
} catch (error) {
  console.error(error.message); // 输出类似于 "Allocation failed - JavaScript heap out of memory" 的消息，其中 "Allocation failed - JavaScript heap out of memory" 是基于 OutOfMemory 模板生成的
}

// 对应 MessageTemplate::kTypeErrorNotAFunction
function callMeMaybe(callback) {
  if (typeof callback === 'function') {
    callback();
  } else {
    // 如果 callback 不是函数，V8 会使用相应的消息模板抛出 TypeError
    throw new TypeError();
  }
}

try {
  callMeMaybe(123);
} catch (error) {
  console.error(error.message); // 输出类似于 "callback is not a function" 的消息
}

// 对应 MessageTemplate::kSyntaxErrorUnexpectedToken
try {
  eval('const a = ;'); // 语法错误，缺少赋值
} catch (error) {
  console.error(error.message); // 输出类似于 "Unexpected token ';'" 的消息
}
```

在这些例子中，当 JavaScript 代码触发特定的错误条件时，V8 内部会使用 `message-template.h` 中定义的相应模板，并将具体的错误信息（例如，哪个变量未定义，哪个位置出现了意外的符号）填充到模板中的占位符（例如 `%`）中，最终生成开发者看到的错误消息。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个整数消息 ID `10`，我们想知道它对应哪个消息模板。

**假设输入:** `message_id = 10`

**代码逻辑:**

`MessageTemplateFromInt(10)` 函数会执行以下操作：

1. 检查 `10` 是否小于 `MessageTemplate::kMessageCount` (假设 `kMessageCount` 大于 10)。
2. 将 `10` 强制转换为 `MessageTemplate` 枚举类型。

**假设输出:**  根据 `MESSAGE_TEMPLATES` 宏的定义顺序，我们可以推断出 `10` 对应的可能是某个 `k...` 枚举常量，比如 `kInvalidReceiver`. （注意：实际的对应关系需要查看完整的 `MESSAGE_TEMPLATES` 定义）。

如果我们想获取 `kOutOfMemory` 对应的消息字符串，在 V8 内部的代码中可能会有类似这样的逻辑：

```c++
// 假设已经确定了错误类型是 MessageTemplate::kOutOfMemory
MessageTemplate template_id = MessageTemplate::kOutOfMemory;

// 在 V8 内部，可能会有一个函数根据 MessageTemplate 获取对应的字符串
const char* GetMessageString(MessageTemplate id) {
  switch (id) {
    // ... 其他 case ...
    case MessageTemplate::kOutOfMemory:
      return "%: Out of memory";
    // ...
    default:
      return "Unknown error";
  }
}

const char* message_format = GetMessageString(template_id);
// message_format 现在指向字符串 "%: Out of memory"
```

然后，V8 会使用这个格式字符串，结合具体的错误信息（例如，具体的内存分配失败的原因），来生成最终的错误消息。

**涉及用户常见的编程错误:**

`message-template.h` 中定义的许多消息模板都直接对应于用户在编写 JavaScript 代码时容易犯的错误：

* **`TypeError: Cannot read properties of undefined (reading '...')` (可能对应 `kPropertyOfNonObject`)**: 尝试访问 `undefined` 或 `null` 类型的属性。
  ```javascript
  let obj = undefined;
  console.log(obj.name); // TypeError
  ```
* **`ReferenceError: ... is not defined` (可能对应 `kVariableNotFound`)**: 尝试使用未声明的变量。
  ```javascript
  console.log(unknownVariable); // ReferenceError
  ```
* **`SyntaxError: Unexpected token '...'` (对应多种 `kSyntaxError...` 模板)**: 代码中存在语法错误。
  ```javascript
  const a = ; // SyntaxError
  ```
* **`TypeError: ... is not a function` (对应 `kTypeErrorNotAFunction`)**: 尝试调用一个非函数类型的值。
  ```javascript
  let notAFunction = 123;
  notAFunction(); // TypeError
  ```
* **`RangeError: Maximum call stack size exceeded` (对应 `kStackOverflow`)**:  函数递归调用过深，导致堆栈溢出。
  ```javascript
  function recursive() {
    recursive();
  }
  recursive(); // RangeError
  ```

**归纳一下它的功能 (第 2 部分总结):**

`v8/src/common/message-template.h`  是 V8 JavaScript 引擎中一个至关重要的组成部分，它集中定义了所有预定义的错误和警告消息模板。通过使用枚举 `MessageTemplate` 来管理这些模板，V8 实现了以下关键功能：

* **统一的错误消息管理:**  提供了一个中心化的位置来定义和维护所有可能的错误和警告消息，确保了 V8 内部错误信息的一致性。
* **提高代码可读性和维护性:**  使用枚举常量代替硬编码的字符串，使代码更加清晰易懂，也方便了后续的修改和维护。
* **支持本地化:**  这些消息模板为未来的本地化（国际化）提供了基础，可以将这些模板翻译成不同的语言。
* **方便错误处理:**  V8 内部可以方便地根据错误类型（`MessageTemplate` 枚举值）来获取对应的错误消息模板，并填充具体的错误信息。
* **关联 JavaScript 错误:**  这些模板直接对应于开发者在编写 JavaScript 代码时可能遇到的各种运行时错误和语法错误，帮助开发者理解和调试代码。

总而言之，`v8/src/common/message-template.h`  就像是 V8 错误消息的“词典”，它定义了 V8 与 JavaScript 开发者沟通错误信息的“语言”。

### 提示词
```
这是目录为v8/src/common/message-template.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/message-template.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
tiple of %")            \
  T(InvalidTypedArrayIndex, "Invalid typed array index")                       \
  T(InvalidTypedArrayLength, "Invalid typed array length: %")                  \
  T(LetInLexicalBinding, "let is disallowed as a lexically bound name")        \
  T(LocaleMatcher, "Illegal value for localeMatcher:%")                        \
  T(MaximumFractionDigitsNotEqualMinimumFractionDigits,                        \
    "maximumFractionDigits not equal to minimumFractionDigits")                \
  T(NormalizationForm, "The normalization form should be one of %.")           \
  T(OutOfMemory, "%: Out of memory")                                           \
  T(ZeroDigitNumericSeparator,                                                 \
    "Numeric separator can not be used after leading 0.")                      \
  T(NumberFormatRange, "% argument must be between 0 and 100")                 \
  T(TrailingNumericSeparator,                                                  \
    "Numeric separators are not allowed at the end of numeric literals")       \
  T(ContinuousNumericSeparator,                                                \
    "Only one underscore is allowed as numeric separator")                     \
  T(PropertyValueOutOfRange, "% value is out of range.")                       \
  T(StackOverflow, "Maximum call stack size exceeded")                         \
  T(ToPrecisionFormatRange,                                                    \
    "toPrecision() argument must be between 1 and 100")                        \
  T(ToRadixFormatRange, "toString() radix argument must be between 2 and 36")  \
  T(SharedArraySizeOutOfRange, "SharedArray length out of range")              \
  T(StructFieldCountOutOfRange,                                                \
    "Struct field count out of range (maximum of 999 allowed)")                \
  T(TypedArraySetOffsetOutOfBounds, "offset is out of bounds")                 \
  T(TypedArraySetSourceTooLarge, "Source is too large")                        \
  T(TypedArrayTooLargeToSort,                                                  \
    "Custom comparefn not supported for huge TypedArrays")                     \
  T(ValueOutOfRange, "Value % out of range for % options property %")          \
  T(CollectionGrowFailed, "% maximum size exceeded")                           \
  T(MustBePositive, "% must be positive")                                      \
  T(ArgumentIsNotUndefinedOrInteger,                                           \
    "% argument must be undefined or an integer")                              \
  /* SyntaxError */                                                            \
  T(AmbiguousExport,                                                           \
    "The requested module '%' contains conflicting star exports for name '%'") \
  T(BadGetterArity, "Getter must not have any formal parameters.")             \
  T(BadSetterArity, "Setter must have exactly one formal parameter.")          \
  T(BigIntInvalidString, "Invalid BigInt string")                              \
  T(ConstructorIsAccessor, "Class constructor may not be an accessor")         \
  T(ConstructorIsGenerator, "Class constructor may not be a generator")        \
  T(ConstructorIsAsync, "Class constructor may not be an async method")        \
  T(ConstructorIsPrivate, "Class constructor may not be a private method")     \
  T(DerivedConstructorReturnedNonObject,                                       \
    "Derived constructors may only return object or undefined")                \
  T(DuplicateConstructor, "A class may only have one constructor")             \
  T(DuplicateExport, "Duplicate export of '%'")                                \
  T(DuplicateProto,                                                            \
    "Duplicate __proto__ fields are not allowed in object literals")           \
  T(ForInOfLoopInitializer,                                                    \
    "% loop variable declaration may not have an initializer.")                \
  T(ForOfLet, "The left-hand side of a for-of loop may not start with 'let'.") \
  T(ForOfAsync, "The left-hand side of a for-of loop may not be 'async'.")     \
  T(ForInOfLoopMultiBindings,                                                  \
    "Invalid left-hand side in % loop: Must have a single binding.")           \
  T(GeneratorInSingleStatementContext,                                         \
    "Generators can only be declared at the top level or inside a block.")     \
  T(AsyncFunctionInSingleStatementContext,                                     \
    "Async functions can only be declared at the top level or inside a "       \
    "block.")                                                                  \
  T(IllegalBreak, "Illegal break statement")                                   \
  T(ModuleExportNameWithoutFromClause,                                         \
    "String literal module export names must be followed by a 'from' clause")  \
  T(NoIterationStatement,                                                      \
    "Illegal continue statement: no surrounding iteration statement")          \
  T(IllegalContinue,                                                           \
    "Illegal continue statement: '%' does not denote an iteration statement")  \
  T(IllegalLanguageModeDirective,                                              \
    "Illegal '%' directive in function with non-simple parameter list")        \
  T(IllegalReturn, "Illegal return statement")                                 \
  T(IntrinsicWithSpread, "Intrinsic calls do not support spread arguments")    \
  T(InvalidRestBindingPattern,                                                 \
    "`...` must be followed by an identifier in declaration contexts")         \
  T(InvalidPropertyBindingPattern, "Illegal property in declaration context")  \
  T(InvalidRestAssignmentPattern,                                              \
    "`...` must be followed by an assignable reference in assignment "         \
    "contexts")                                                                \
  T(InvalidEscapedReservedWord, "Keyword must not contain escaped characters") \
  T(InvalidEscapedMetaProperty, "'%' must not contain escaped characters")     \
  T(InvalidLhsInAssignment, "Invalid left-hand side in assignment")            \
  T(InvalidCoverInitializedName, "Invalid shorthand property initializer")     \
  T(InvalidDestructuringTarget, "Invalid destructuring assignment target")     \
  T(InvalidLhsInFor, "Invalid left-hand side in for-loop")                     \
  T(InvalidLhsInPostfixOp,                                                     \
    "Invalid left-hand side expression in postfix operation")                  \
  T(InvalidLhsInPrefixOp,                                                      \
    "Invalid left-hand side expression in prefix operation")                   \
  T(InvalidModuleExportName,                                                   \
    "Invalid module export name: contains unpaired surrogate")                 \
  T(InvalidRegExpFlags, "Invalid flags supplied to RegExp constructor '%'")    \
  T(InvalidOrUnexpectedToken, "Invalid or unexpected token")                   \
  T(InvalidPrivateBrandInstance, "Receiver must be an instance of class %")    \
  T(InvalidPrivateBrandStatic, "Receiver must be class %")                     \
  T(InvalidPrivateBrandReinitialization,                                       \
    "Cannot initialize private methods of class % twice on the same object")   \
  T(InvalidPrivateFieldReinitialization,                                       \
    "Cannot initialize % twice on the same object")                            \
  T(InvalidPrivateFieldResolution,                                             \
    "Private field '%' must be declared in an enclosing class")                \
  T(InvalidPrivateMemberRead,                                                  \
    "Cannot read private member % from an object whose class did not declare " \
    "it")                                                                      \
  T(InvalidPrivateMemberWrite,                                                 \
    "Cannot write private member % to an object whose class did not declare "  \
    "it")                                                                      \
  T(InvalidPrivateMethodWrite, "Private method '%' is not writable")           \
  T(InvalidPrivateGetterAccess, "'%' was defined without a getter")            \
  T(InvalidPrivateSetterAccess, "'%' was defined without a setter")            \
  T(InvalidSizeValue, "'%' is an invalid size")                                \
  T(InvalidUnusedPrivateStaticMethodAccessedByDebugger,                        \
    "Unused static private method '%' cannot be accessed at debug time")       \
  T(InvalidUsingInForInLoop, "Invalid 'using' in for-in loop")                 \
  T(JsonParseUnexpectedEOS, "Unexpected end of JSON input")                    \
  T(JsonParseUnexpectedTokenNumber,                                            \
    "Unexpected number in JSON at position % (line % column %)")               \
  T(JsonParseUnexpectedTokenString,                                            \
    "Unexpected string in JSON at position % (line % column %)")               \
  T(JsonParseUnterminatedString,                                               \
    "Unterminated string in JSON at position % (line % column %)")             \
  T(JsonParseExpectedPropNameOrRBrace,                                         \
    "Expected property name or '}' in JSON at position % (line % column %)")   \
  T(JsonParseExpectedCommaOrRBrack,                                            \
    "Expected ',' or ']' after array element in JSON at position % (line % "   \
    "column %)")                                                               \
  T(JsonParseExpectedCommaOrRBrace,                                            \
    "Expected ',' or '}' after property value in JSON at position "            \
    "% (line % column %)")                                                     \
  T(JsonParseExpectedDoubleQuotedPropertyName,                                 \
    "Expected double-quoted property name in JSON at position % (line % "      \
    "column %)")                                                               \
  T(JsonParseExponentPartMissingNumber,                                        \
    "Exponent part is missing a number in JSON at position % (line % column "  \
    "%)")                                                                      \
  T(JsonParseExpectedColonAfterPropertyName,                                   \
    "Expected ':' after property name in JSON at position % (line % column "   \
    "%)")                                                                      \
  T(JsonParseUnterminatedFractionalNumber,                                     \
    "Unterminated fractional number in JSON at position % (line % column %)")  \
  T(JsonParseUnexpectedNonWhiteSpaceCharacter,                                 \
    "Unexpected non-whitespace character after JSON at position "              \
    "% (line % column %)")                                                     \
  T(JsonParseBadEscapedCharacter,                                              \
    "Bad escaped character in JSON at position % (line % column %)")           \
  T(JsonParseBadControlCharacter,                                              \
    "Bad control character in string literal in JSON at position % (line % "   \
    "column %)")                                                               \
  T(JsonParseBadUnicodeEscape,                                                 \
    "Bad Unicode escape in JSON at position % (line % column %)")              \
  T(JsonParseNoNumberAfterMinusSign,                                           \
    "No number after minus sign in JSON at position % (line % column %)")      \
  T(JsonParseShortString, "\"%\" is not valid JSON")                           \
  T(JsonParseUnexpectedTokenShortString,                                       \
    "Unexpected token '%', \"%\" is not valid JSON")                           \
  T(JsonParseUnexpectedTokenSurroundStringWithContext,                         \
    "Unexpected token '%', ...\"%\"... is not valid JSON")                     \
  T(JsonParseUnexpectedTokenEndStringWithContext,                              \
    "Unexpected token '%', ...\"%\" is not valid JSON")                        \
  T(JsonParseUnexpectedTokenStartStringWithContext,                            \
    "Unexpected token '%', \"%\"... is not valid JSON")                        \
  T(LabelRedeclaration, "Label '%' has already been declared")                 \
  T(LabelledFunctionDeclaration,                                               \
    "Labelled function declaration not allowed as the body of a control flow " \
    "structure")                                                               \
  T(MalformedArrowFunParamList, "Malformed arrow function parameter list")     \
  T(MalformedRegExp, "Invalid regular expression: /%/%: %")                    \
  T(MalformedRegExpFlags, "Invalid regular expression flags")                  \
  T(ModuleExportUndefined, "Export '%' is not defined in module")              \
  T(MissingFunctionName, "Function statements require a function name")        \
  T(HtmlCommentInModule, "HTML comments are not allowed in modules")           \
  T(MultipleDefaultsInSwitch,                                                  \
    "More than one default clause in switch statement")                        \
  T(NewlineAfterThrow, "Illegal newline after throw")                          \
  T(NoCatchOrFinally, "Missing catch or finally after try")                    \
  T(ParamAfterRest, "Rest parameter must be last formal parameter")            \
  T(FlattenPastSafeLength,                                                     \
    "Flattening % elements on an array-like of length % "                      \
    "is disallowed, as the total surpasses 2**53-1")                           \
  T(PushPastSafeLength,                                                        \
    "Pushing % elements on an array-like of length % "                         \
    "is disallowed, as the total surpasses 2**53-1")                           \
  T(ElementAfterRest, "Rest element must be last element")                     \
  T(BadSetterRestParameter,                                                    \
    "Setter function argument must not be a rest parameter")                   \
  T(ParamDupe, "Duplicate parameter name not allowed in this context")         \
  T(ArgStringTerminatesParametersEarly,                                        \
    "Arg string terminates parameters early")                                  \
  T(UnexpectedEndOfArgString, "Unexpected end of arg string")                  \
  T(RestDefaultInitializer,                                                    \
    "Rest parameter may not have a default initializer")                       \
  T(RuntimeWrongNumArgs, "Runtime function given wrong number of arguments")   \
  T(SuperNotCalled,                                                            \
    "Must call super constructor in derived class before accessing 'this' or " \
    "returning from derived constructor")                                      \
  T(SingleFunctionLiteral, "Single function literal required")                 \
  T(SloppyFunction,                                                            \
    "In non-strict mode code, functions can only be declared at top level, "   \
    "inside a block, or as the body of an if statement.")                      \
  T(SpeciesNotConstructor,                                                     \
    "object.constructor[Symbol.species] is not a constructor")                 \
  T(StrictDelete, "Delete of an unqualified identifier in strict mode.")       \
  T(StrictEvalArguments, "Unexpected eval or arguments in strict mode")        \
  T(StrictFunction,                                                            \
    "In strict mode code, functions can only be declared at top level or "     \
    "inside a block.")                                                         \
  T(StrictOctalLiteral, "Octal literals are not allowed in strict mode.")      \
  T(StrictDecimalWithLeadingZero,                                              \
    "Decimals with leading zeros are not allowed in strict mode.")             \
  T(StrictOctalEscape,                                                         \
    "Octal escape sequences are not allowed in strict mode.")                  \
  T(Strict8Or9Escape, "\\8 and \\9 are not allowed in strict mode.")           \
  T(StrictWith, "Strict mode code may not include a with statement")           \
  T(TemplateOctalLiteral,                                                      \
    "Octal escape sequences are not allowed in template strings.")             \
  T(Template8Or9Escape, "\\8 and \\9 are not allowed in template strings.")    \
  T(ThisFormalParameter, "'this' is not a valid formal parameter name")        \
  T(AwaitBindingIdentifier,                                                    \
    "'await' is not a valid identifier name in an async function")             \
  T(AwaitExpressionFormalParameter,                                            \
    "Illegal await-expression in formal parameters of async function")         \
  T(TooManyArguments,                                                          \
    "Too many arguments in function call (only 65535 allowed)")                \
  T(TooManyParameters,                                                         \
    "Too many parameters in function definition (only 65534 allowed)")         \
  T(TooManyProperties, "Too many properties to enumerate")                     \
  T(TooManySpreads,                                                            \
    "Literal containing too many nested spreads (up to 65534 allowed)")        \
  T(TooManyVariables, "Too many variables declared (only 4194303 allowed)")    \
  T(TooManyElementsInPromiseCombinator,                                        \
    "Too many elements passed to Promise.%")                                   \
  T(TypedArrayTooShort,                                                        \
    "Derived TypedArray constructor created an array which was too small")     \
  T(UnexpectedEOS, "Unexpected end of input")                                  \
  T(UnexpectedPrivateField, "Unexpected private field")                        \
  T(UnexpectedReserved, "Unexpected reserved word")                            \
  T(UnexpectedStrictReserved, "Unexpected strict mode reserved word")          \
  T(UnexpectedSuper, "'super' keyword unexpected here")                        \
  T(UnexpectedNewTarget, "new.target expression is not allowed here")          \
  T(UnexpectedTemplateString, "Unexpected template string")                    \
  T(UnexpectedToken, "Unexpected token '%'")                                   \
  T(UnexpectedTokenUnaryExponentiation,                                        \
    "Unary operator used immediately before exponentiation expression. "       \
    "Parenthesis must be used to disambiguate operator precedence")            \
  T(UnexpectedTokenIdentifier, "Unexpected identifier '%'")                    \
  T(UnexpectedTokenNumber, "Unexpected number")                                \
  T(UnexpectedTokenString, "Unexpected string")                                \
  T(UnexpectedTokenRegExp, "Unexpected regular expression")                    \
  T(UnexpectedLexicalDeclaration,                                              \
    "Lexical declaration cannot appear in a single-statement context")         \
  T(UnknownLabel, "Undefined label '%'")                                       \
  T(UnresolvableExport,                                                        \
    "The requested module '%' does not provide an export named '%'")           \
  T(UnterminatedArgList, "missing ) after argument list")                      \
  T(UnterminatedRegExp, "Invalid regular expression: missing /")               \
  T(UnterminatedTemplate, "Unterminated template literal")                     \
  T(UnterminatedTemplateExpr, "Missing } in template expression")              \
  T(FoundNonCallableHasInstance, "Found non-callable @@hasInstance")           \
  T(InvalidHexEscapeSequence, "Invalid hexadecimal escape sequence")           \
  T(InvalidUnicodeEscapeSequence, "Invalid Unicode escape sequence")           \
  T(UndefinedUnicodeCodePoint, "Undefined Unicode code-point")                 \
  T(YieldInParameter, "Yield expression not allowed in formal parameter")      \
  /* EvalError */                                                              \
  T(CodeGenFromStrings, "%")                                                   \
  T(NoSideEffectDebugEvaluate, "Possible side-effect in debug-evaluate")       \
  /* URIError */                                                               \
  T(URIMalformed, "URI malformed")                                             \
  /* Wasm errors (currently Error) */                                          \
  T(WasmTrapUnreachable, "unreachable")                                        \
  T(WasmTrapMemOutOfBounds, "memory access out of bounds")                     \
  T(WasmTrapUnalignedAccess, "operation does not support unaligned accesses")  \
  T(WasmTrapDivByZero, "divide by zero")                                       \
  T(WasmTrapDivUnrepresentable, "divide result unrepresentable")               \
  T(WasmTrapRemByZero, "remainder by zero")                                    \
  T(WasmTrapFloatUnrepresentable, "float unrepresentable in integer range")    \
  T(WasmTrapTableOutOfBounds, "table index is out of bounds")                  \
  T(WasmTrapFuncSigMismatch, "null function or function signature mismatch")   \
  T(WasmTrapMultiReturnLengthMismatch, "multi-return length mismatch")         \
  T(WasmTrapJSTypeError, "type incompatibility when transforming from/to JS")  \
  T(WasmTrapDataSegmentOutOfBounds, "data segment out of bounds")              \
  T(WasmTrapElementSegmentOutOfBounds, "element segment out of bounds")        \
  T(WasmTrapRethrowNull, "rethrowing null value")                              \
  T(WasmTrapNullDereference, "dereferencing a null pointer")                   \
  T(WasmTrapIllegalCast, "illegal cast")                                       \
  T(WasmTrapArrayOutOfBounds, "array element access out of bounds")            \
  T(WasmTrapArrayTooLarge, "requested new array is too large")                 \
  T(WasmTrapStringInvalidUtf8, "invalid UTF-8 string")                         \
  T(WasmTrapStringInvalidWtf8, "invalid WTF-8 string")                         \
  T(WasmTrapStringOffsetOutOfBounds, "string offset out of bounds")            \
  T(WasmTrapBadSuspender,                                                      \
    "attempting to suspend without a WebAssembly.promising export")            \
  T(WasmTrapStringIsolatedSurrogate,                                           \
    "Failed to encode string as UTF-8: contains unpaired surrogate")           \
  T(WasmTrapSuspendJSFrames, "trying to suspend JS frames")                    \
  T(WasmExceptionError, "wasm exception")                                      \
  T(WasmObjectsAreOpaque, "WebAssembly objects are opaque")                    \
  /* Asm.js validation related */                                              \
  T(AsmJsInvalid, "Invalid asm.js: %")                                         \
  T(AsmJsCompiled, "Converted asm.js to WebAssembly: %")                       \
  T(AsmJsInstantiated, "Instantiated asm.js: %")                               \
  T(AsmJsLinkingFailed, "Linking failure in asm.js: %")                        \
  /* DataCloneError messages */                                                \
  T(DataCloneError, "% could not be cloned.")                                  \
  T(DataCloneErrorOutOfMemory, "Data cannot be cloned, out of memory.")        \
  T(DataCloneErrorDetachedArrayBuffer,                                         \
    "An ArrayBuffer is detached and could not be cloned.")                     \
  T(DataCloneErrorNonDetachableArrayBuffer,                                    \
    "ArrayBuffer is not detachable and could not be cloned.")                  \
  T(DataCloneErrorSharedArrayBufferTransferred,                                \
    "A SharedArrayBuffer could not be cloned. SharedArrayBuffer must not be "  \
    "transferred.")                                                            \
  T(DataCloneDeserializationError, "Unable to deserialize cloned data.")       \
  T(DataCloneDeserializationVersionError,                                      \
    "Unable to deserialize cloned data due to invalid or unsupported "         \
    "version.")                                                                \
  /* Builtins-Trace Errors */                                                  \
  T(TraceEventCategoryError, "Trace event category must be a string.")         \
  T(TraceEventNameError, "Trace event name must be a string.")                 \
  T(TraceEventNameLengthError,                                                 \
    "Trace event name must not be an empty string.")                           \
  T(TraceEventPhaseError, "Trace event phase must be a number.")               \
  T(TraceEventIDError, "Trace event id must be a number.")                     \
  /* Weak refs */                                                              \
  T(InvalidWeakRefsUnregisterToken, "Invalid unregisterToken ('%')")           \
  T(WeakRefsCleanupMustBeCallable,                                             \
    "FinalizationRegistry: cleanup must be callable")                          \
  T(InvalidWeakRefsRegisterTarget,                                             \
    "FinalizationRegistry.prototype.register: invalid target")                 \
  T(WeakRefsRegisterTargetAndHoldingsMustNotBeSame,                            \
    "FinalizationRegistry.prototype.register: target and holdings must not "   \
    "be same")                                                                 \
  T(InvalidWeakRefsWeakRefConstructorTarget, "WeakRef: invalid target")        \
  T(OptionalChainingNoNew, "Invalid optional chain from new expression")       \
  T(OptionalChainingNoSuper, "Invalid optional chain from super property")     \
  T(OptionalChainingNoTemplate, "Invalid tagged template on optional chain")   \
  /* AggregateError */                                                         \
  T(AllPromisesRejected, "All promises were rejected")                         \
  T(CannotDeepFreezeObject, "Cannot DeepFreeze object of type %")              \
  T(CannotDeepFreezeValue, "Cannot DeepFreeze non-const value %")              \
  /* SuppressedError */                                                        \
  T(SuppressedErrorDuringDisposal, "An error was suppressed during disposal")  \
  T(ExpectAnObjectWithUsing,                                                   \
    "An object is expected with `using` "                                      \
    "declarations")

enum class MessageTemplate {
#define TEMPLATE(NAME, STRING) k##NAME,
  MESSAGE_TEMPLATES(TEMPLATE)
#undef TEMPLATE
      kMessageCount
};

inline MessageTemplate MessageTemplateFromInt(int message_id) {
  DCHECK_LT(static_cast<unsigned>(message_id),
            static_cast<unsigned>(MessageTemplate::kMessageCount));
  return static_cast<MessageTemplate>(message_id);
}

}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_MESSAGE_TEMPLATE_H_
```