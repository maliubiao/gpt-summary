Response:
Let's break down the thought process for analyzing this Torque parser code.

1. **Understanding the Goal:** The core request is to understand the *functionality* of the given C++ code. The additional instructions provide helpful context about Torque and its relationship to JavaScript. The request is specifically for *part 4* and asks for a summary.

2. **Initial Code Scan (Keywords and Structure):**  A quick skim reveals common parser-related concepts:
    * `Symbol`: This likely represents a grammar rule.
    * `Rule`:  A specific pattern within a grammar rule.
    * `Token`:  Basic building blocks of the language (like keywords, operators, identifiers).
    * `List`, `Optional`, `Sequence`: Combinators for building more complex rules.
    * `Make...`: Functions that create AST (Abstract Syntax Tree) nodes.
    * Keywords like `class`, `struct`, `macro`, `builtin`, `if`, `while`, `return`, etc. These hint at the language features Torque can parse.

3. **Identifying the Core Task:** The code is clearly defining a grammar for the Torque language. It's using a parsing framework (likely internal to V8 or a custom one). The `Symbol` and `Rule` constructs are the heart of this grammar definition.

4. **Working Through Key Grammar Rules:**  To understand functionality, it's useful to pick out representative rules and analyze what they parse:

    * **Basic building blocks:** `identifier`, `integerLiteral`, `stringLiteral`. These are the atoms of the language.
    * **Expressions:** `primaryExpression`, `unaryExpression`, `multiplicativeExpression`, etc. These rules define how expressions are formed with operators and operands. The hierarchy of these rules (e.g., `multiplicativeExpression` using `unaryExpression`) reflects operator precedence.
    * **Statements:** `statement`, `block`, `ifStatement`, `whileStatement`, `returnStatement`. These represent actions or control flow constructs.
    * **Declarations:** `declaration`, `method`, `classDeclaration`, `structDeclaration`, `macroDeclaration`, `builtinDeclaration`. These rules handle the definition of types, functions, and other language entities.
    * **Top-level structure:** `file`, `declarationList`. These define how a complete Torque source file is structured.

5. **Connecting to the Instructions:** Now, let's address the specific points in the request:

    * **Functionality:**  It's a parser for the Torque language. It takes Torque source code as input and likely produces an Abstract Syntax Tree (AST) as output. The `Make...` functions suggest AST node creation.
    * **`.tq` extension:** The code confirms the instruction's hint that `.tq` files are Torque source code.
    * **Relationship to JavaScript (and examples):** Since Torque is used in V8, it's related to JavaScript. The examples should show how Torque might define the implementation details of JavaScript features. The initial thought might be to show a direct translation, but that's not quite accurate. Torque *implements* parts of JavaScript's semantics. A better example shows a low-level Torque function implementing something a JavaScript developer might use, like accessing an object property.
    * **Code Logic and Input/Output:**  Choose a relatively simple rule (like `integerLiteral` or a basic expression) and demonstrate the parsing process. Input: a string matching the rule. Output:  an indication of the parsed structure (e.g., "Parsed Integer Literal: 123"). For more complex rules, the output would be a representation of the AST node.
    * **Common Programming Errors:** Think about typical errors when writing code in a language with these features. Type errors, syntax errors, incorrect operator usage are good examples. Map these to potential errors the *parser* would detect.
    * **Part 4 Summary:**  Focus on the top-level grammar rules (`declarationList`, `file`). Emphasize that this part ties together all the previously defined rules to parse complete Torque files and handle imports.

6. **Refining the Examples:** Ensure the JavaScript examples are accurate and illustrative of Torque's purpose. Avoid oversimplification. The key is showing how Torque provides the *implementation* layer for JavaScript concepts.

7. **Structuring the Output:** Organize the information clearly with headings and bullet points to address each part of the request.

8. **Self-Correction/Review:**  Read through the generated explanation. Does it make sense?  Are the examples clear?  Is the summary accurate?  For instance, initially, I might focus too much on individual rules. The "Part 4 Summary" forces me to step back and consider the broader picture of how these rules are combined. I also need to ensure I've correctly interpreted the purpose of Torque and its connection to JavaScript.

By following these steps, systematically analyzing the code, and relating it to the provided instructions, we arrive at a comprehensive and accurate explanation of the `torque-parser.cc` functionality.
这是 `v8/src/torque/torque-parser.cc` 源代码的第四部分，也是最后一部分。 结合前三部分，我们可以归纳出这个文件的完整功能。

**归纳 `v8/src/torque/torque-parser.cc` 的功能:**

`v8/src/torque/torque-parser.cc` 文件是 V8 引擎中 Torque 语言的解析器实现。Torque 是一种用于在 V8 内部定义运行时代码（例如内置函数、类型系统和对象布局）的领域特定语言 (DSL)。

**其主要功能包括:**

1. **定义 Torque 语言的语法:**  通过一系列的 `Symbol` 和 `Rule` 对象，这个文件定义了 Torque 语言的文法规则。这些规则描述了 Torque 代码的合法结构，包括各种声明（类、结构体、宏、内置函数等）、语句（赋值、返回、条件判断、循环等）和表达式。

2. **将 Torque 源代码解析成抽象语法树 (AST):**  解析器的核心任务是将输入的 Torque 源代码字符串转换成一个结构化的表示形式，即抽象语法树（AST）。AST 能够更方便地进行后续的语义分析、代码生成等处理。  代码中大量的 `Make...` 函数（例如 `MakeNameAndType`, `MakeBinaryOperator`, `MakeBlockStatement` 等）负责创建不同类型的 AST 节点。

3. **处理 Torque 语言的各种语法结构:**  文件中定义了各种语法结构的解析规则，包括：
    * **类型声明:**  解析 `class`, `struct`, `type`, `enum` 等关键字定义的类型。
    * **函数/宏/内置函数声明:** 解析 `macro`, `builtin`, `intrinsic` 等关键字定义的函数或宏。
    * **语句:** 解析各种控制流语句，如 `if`, `while`, `for`, `return`, `break`, `continue` 等。
    * **表达式:** 解析各种类型的表达式，包括算术运算、逻辑运算、函数调用、对象访问等。
    * **注解:** 解析 `@` 符号开头的注解信息。
    * **泛型:** 解析尖括号 `<>` 内的泛型参数。
    * **标签:** 解析冒号 `:` 定义的标签。
    * **命名空间:** 解析 `namespace` 关键字定义的命名空间。
    * **导入:** 解析 `import` 关键字导入其他 Torque 文件。

4. **支持错误处理和诊断信息:** 虽然这部分代码没有直接展示错误处理的逻辑，但解析器通常会包含错误处理机制，用于在解析过程中检测到语法错误并报告给用户。

**如果 `v8/src/torque/torque-parser.cc` 以 `.tq` 结尾:**

如果 `v8/src/torque/torque-parser.cc` 以 `.tq` 结尾，那么它本身就是 **Torque 源代码** 文件。但是，实际上 `torque-parser.cc` 是一个 **C++ 源代码** 文件，它 *解析* 以 `.tq` 结尾的 Torque 源代码文件。

**Torque 与 JavaScript 的关系及示例:**

Torque 用于定义 V8 引擎内部的实现细节，很多 JavaScript 的内置功能实际上是用 Torque 编写的。

**JavaScript 示例:**

```javascript
// JavaScript 代码
const arr = [1, 2, 3];
arr.push(4); // 调用 JavaScript 的 push 方法
```

**Torque 的可能实现 (简化示例):**

在 V8 内部，`Array.prototype.push` 方法的实现可能（简化地）使用 Torque 编写，如下所示：

```torque
// Torque 代码 (简化示例，实际情况更复杂)
transitioning macro ArrayPush<T>(implicit context: NativeContext, receiver: JSArray, ...items: T): Number {
  // ... 检查 receiver 是否为 JSArray ...
  // ... 获取 receiver 的长度 ...
  // ... 遍历 items 并添加到 receiver 中 ...
  // ... 更新 receiver 的长度 ...
  return new_length: Number;
}
```

这个 Torque 宏 `ArrayPush` 描述了 `push` 操作的底层实现逻辑，包括类型检查、内存操作等。

**代码逻辑推理和假设输入/输出:**

**假设输入 (Torque 表达式):** `"hello" + " world"`

**解析器可能输出的 AST (简化表示):**

```
BinaryOperator {
  operator: "+"
  left: StringLiteral { value: "hello" }
  right: StringLiteral { value: " world" }
}
```

这个 AST 表示一个二元操作，操作符是 `+`，左操作数是一个字符串字面量 `"hello"`，右操作数是字符串字面量 `" world"`。

**用户常见的编程错误 (在 Torque 中):**

1. **类型错误:**  例如，将一个不兼容的类型赋值给变量。

   ```torque
   let x: Number = "hello"; // 错误：字符串不能赋值给 Number 类型
   ```

   解析器会检测到类型不匹配的错误。

2. **语法错误:**  例如，缺少分号、括号不匹配等。

   ```torque
   let x: Number = 10 // 错误：缺少分号
   ```

   解析器会报告语法错误。

3. **未声明的变量或函数:**  在没有声明的情况下使用变量或函数。

   ```torque
   y = 20; // 错误：y 未声明
   ```

   解析器会报告未声明的标识符。

4. **宏或内置函数参数错误:**  传递给宏或内置函数的参数类型或数量不正确。

   ```torque
   // 假设有宏 PrintNumber(n: Number)
   PrintNumber("abc"); // 错误：参数类型不匹配
   ```

   解析器会根据宏的签名进行参数检查。

**总结第 4 部分的功能:**

这部分代码定义了 Torque 语言中更复杂的语法结构，并将它们组合起来构建完整的程序结构。具体来说，它涵盖了：

* **语句 (Statement):** 定义了各种可以执行的操作，例如块语句、返回语句、条件语句、循环语句、变量声明等。
* **声明 (Declaration):** 定义了程序中的各种实体，例如常量、类型、函数、宏、内置函数、外部声明等。
* **文件结构 (file, declarationList):** 定义了 Torque 源文件的组织方式，包括导入其他文件和包含一系列声明。

通过定义这些规则，解析器能够理解完整的 Torque 代码，并将其转换成可以被后续步骤处理的 AST。 这部分是整个解析器中最核心和最全面的部分，因为它将所有小的语法元素组合成了有意义的程序结构。

Prompt: 
```
这是目录为v8/src/torque/torque-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/torque-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
arameter, Token(","))}))};

  // Result: std::vector<Statement*>
  Symbol* optionalOtherwise{TryOrDefault<std::vector<Statement*>>(
      Sequence({Token("otherwise"),
                NonemptyList<Statement*>(&atomarStatement, Token(","))}))};

  // Result: NameAndTypeExpression
  Symbol nameAndType = {Rule({&name, Token(":"), &type}, MakeNameAndType)};

  // Result: std::optional<Expression*>
  Symbol* optionalArraySpecifier =
      Optional<Expression*>(Sequence({Token("["), expression, Token("]")}));

  // Result: ClassFieldExpression
  Symbol classField = {
      Rule({annotations, CheckIf(Token("weak")), CheckIf(Token("const")), &name,
            CheckIf(Token("?")), optionalArraySpecifier, Token(":"), &type,
            Token(";")},
           MakeClassField)};

  // Result: StructFieldExpression
  Symbol structField = {
      Rule({CheckIf(Token("const")), &name, Token(":"), &type, Token(";")},
           MakeStructField)};

  // Result: BitFieldDeclaration
  Symbol bitFieldDeclaration = {Rule({&name, Token(":"), &type, Token(":"),
                                      &int32Literal, Token("bit"), Token(";")},
                                     MakeBitFieldDeclaration)};

  // Result: ParameterList
  Symbol parameterListNoVararg = {
      Rule({optionalImplicitParameterList, Token("("),
            List<NameAndTypeExpression>(&nameAndType, Token(",")), Token(")")},
           MakeParameterList<false, true>)};

  // Result: ParameterList
  Symbol parameterListAllowVararg = {
      Rule({&parameterListNoVararg}),
      Rule({optionalImplicitParameterList, Token("("),
            List<NameAndTypeExpression>(Sequence({&nameAndType, Token(",")})),
            Token("..."), &identifier, Token(")")},
           MakeParameterList<true, true>)};

  // Result: Identifier*
  Symbol* OneOf(const std::vector<std::string>& alternatives) {
    Symbol* result = NewSymbol();
    for (const std::string& s : alternatives) {
      result->AddRule(Rule({Token(s)}, MakeIdentifierFromMatchedInput));
    }
    return result;
  }

  // Result: Expression*
  Symbol* BinaryOperator(Symbol* nextLevel, Symbol* op) {
    Symbol* result = NewSymbol();
    *result = {Rule({nextLevel}),
               Rule({result, op, nextLevel}, MakeBinaryOperator)};
    return result;
  }

  // Result: IncrementDecrementOperator
  Symbol incrementDecrementOperator = {
      Rule({Token("++")},
           YieldIntegralConstant<IncrementDecrementOperator,
                                 IncrementDecrementOperator::kIncrement>),
      Rule({Token("--")},
           YieldIntegralConstant<IncrementDecrementOperator,
                                 IncrementDecrementOperator::kDecrement>)};

  // Result: Expression*
  Symbol identifierExpression = {
      Rule({&namespaceQualification, &name,
            TryOrDefault<TypeList>(&genericSpecializationTypeList)},
           MakeIdentifierExpression),
  };

  // Result: std::vector<Expression*>
  Symbol argumentList = {Rule(
      {Token("("), List<Expression*>(expression, Token(",")), Token(")")})};

  // Result: Expression*
  Symbol callExpression = {Rule(
      {&identifierExpression, &argumentList, optionalOtherwise}, MakeCall)};

  // Result: Expression*
  Symbol callMethodExpression = {Rule(
      {&primaryExpression, Token("."), &name, &argumentList, optionalOtherwise},
      MakeMethodCall)};

  // Result: NameAndExpression
  Symbol namedExpression = {
      Rule({&name, Token(":"), expression}, MakeNameAndExpression),
      Rule({expression}, MakeNameAndExpressionFromExpression)};

  // Result: std::vector<NameAndExpression>
  Symbol initializerList = {
      Rule({Token("{"), List<NameAndExpression>(&namedExpression, Token(",")),
            Token("}")})};

  // Result: Expression*
  Symbol intrinsicCallExpression = {Rule(
      {&intrinsicName, TryOrDefault<TypeList>(&genericSpecializationTypeList),
       &argumentList},
      MakeIntrinsicCallExpression)};

  // Result: Expression*
  Symbol newExpression = {
      Rule({Token("new"),
            CheckIf(Sequence({Token("("), Token("Pretenured"), Token(")")})),
            CheckIf(Sequence({Token("("), Token("ClearPadding"), Token(")")})),
            &simpleType, &initializerList},
           MakeNewExpression)};

  // Result: Expression*
  Symbol primaryExpression = {
      Rule({&callExpression}),
      Rule({&callMethodExpression}),
      Rule({&intrinsicCallExpression}),
      Rule({&identifierExpression}),
      Rule({&primaryExpression, Token("."), &name}, MakeFieldAccessExpression),
      Rule({&primaryExpression, Token("->"), &name},
           MakeReferenceFieldAccessExpression),
      Rule({&primaryExpression, Token("["), expression, Token("]")},
           MakeElementAccessExpression),
      Rule({&integerLiteral}, MakeIntegerLiteralExpression),
      Rule({&floatingPointLiteral}, MakeFloatingPointLiteralExpression),
      Rule({&stringLiteral}, MakeStringLiteralExpression),
      Rule({&simpleType, &initializerList}, MakeStructExpression),
      Rule({&newExpression}),
      Rule({Token("("), expression, Token(")")})};

  // Result: Expression*
  Symbol unaryExpression = {
      Rule({&primaryExpression}),
      Rule({OneOf({"+", "-", "!", "~", "&"}), &unaryExpression},
           MakeUnaryOperator),
      Rule({Token("*"), &unaryExpression}, MakeDereferenceExpression),
      Rule({Token("..."), &unaryExpression}, MakeSpreadExpression),
      Rule({&incrementDecrementOperator, &unaryExpression},
           MakeIncrementDecrementExpressionPrefix),
      Rule({&unaryExpression, &incrementDecrementOperator},
           MakeIncrementDecrementExpressionPostfix)};

  // Result: Expression*
  Symbol* multiplicativeExpression =
      BinaryOperator(&unaryExpression, OneOf({"*", "/", "%"}));

  // Result: Expression*
  Symbol* additiveExpression =
      BinaryOperator(multiplicativeExpression, OneOf({"+", "-"}));

  // Result: Identifier*
  Symbol shiftOperator = {
      Rule({Token("<<")}, MakeIdentifierFromMatchedInput),
      Rule({Token(">"), Token(">")}, MakeRightShiftIdentifier),
      Rule({Token(">"), Token(">"), Token(">")}, MakeRightShiftIdentifier)};

  // Result: Expression*
  Symbol* shiftExpression = BinaryOperator(additiveExpression, &shiftOperator);

  // Do not allow expressions like a < b > c because this is never
  // useful and ambiguous with template parameters.
  // Result: Expression*
  Symbol relationalExpression = {
      Rule({shiftExpression}),
      Rule({shiftExpression, OneOf({"<", ">", "<=", ">="}), shiftExpression},
           MakeBinaryOperator)};

  // Result: Expression*
  Symbol* equalityExpression =
      BinaryOperator(&relationalExpression, OneOf({"==", "!="}));

  // Result: Expression*
  Symbol* bitwiseExpression =
      BinaryOperator(equalityExpression, OneOf({"&", "|"}));

  // Result: Expression*
  Symbol logicalAndExpression = {
      Rule({bitwiseExpression}),
      Rule({&logicalAndExpression, Token("&&"), bitwiseExpression},
           MakeLogicalAndExpression)};

  // Result: Expression*
  Symbol logicalOrExpression = {
      Rule({&logicalAndExpression}),
      Rule({&logicalOrExpression, Token("||"), &logicalAndExpression},
           MakeLogicalOrExpression)};

  // Result: Expression*
  Symbol conditionalExpression = {
      Rule({&logicalOrExpression}),
      Rule({&logicalOrExpression, Token("?"), expression, Token(":"),
            &conditionalExpression},
           MakeConditionalExpression)};

  // Result: std::optional<std::string>
  Symbol assignmentOperator = {
      Rule({Token("=")}, YieldDefaultValue<std::optional<std::string>>),
      Rule({OneOf({"*=", "/=", "%=", "+=", "-=", "<<=", ">>=", ">>>=", "&=",
                   "^=", "|="})},
           ExtractAssignmentOperator)};

  // Result: Expression*
  Symbol assignmentExpression = {
      Rule({&conditionalExpression}),
      Rule({&conditionalExpression, &assignmentOperator, &assignmentExpression},
           MakeAssignmentExpression)};

  // Result: Statement*
  Symbol block = {
      Rule({CheckIf(Token("deferred")), Token("{"),
            ListAllowIfAnnotation<Statement*>(&statement), Token("}")},
           MakeBlockStatement)};

  // Result: TryHandler*
  Symbol tryHandler = {
      Rule({Token("label"), &name,
            TryOrDefault<ParameterList>(&parameterListNoVararg), &block},
           MakeLabelBlock),
      Rule({Token("catch"), Token("("),
            List<std::string>(&identifier, Token(",")), Token(")"), &block},
           MakeCatchBlock)};

  // Result: ExpressionWithSource
  Symbol expressionWithSource = {Rule({expression}, MakeExpressionWithSource)};

  Symbol* optionalTypeSpecifier =
      Optional<TypeExpression*>(Sequence({Token(":"), &type}));

  // Result: EnumEntry
  Symbol enumEntry = {
      Rule({annotations, &name, optionalTypeSpecifier}, MakeEnumEntry)};

  // Result: Statement*
  Symbol varDeclaration = {
      Rule({OneOf({"let", "const"}), &name, optionalTypeSpecifier},
           MakeVarDeclarationStatement)};

  // Result: Statement*
  Symbol varDeclarationWithInitialization = {
      Rule({OneOf({"let", "const"}), &name, optionalTypeSpecifier, Token("="),
            expression},
           MakeVarDeclarationStatement)};

  // Result: Statement*
  Symbol atomarStatement = {
      Rule({expression}, MakeExpressionStatement),
      Rule({Token("return"), Optional<Expression*>(expression)},
           MakeReturnStatement),
      Rule({Token("tail"), &callExpression}, MakeTailCallStatement),
      Rule({Token("break")}, MakeBreakStatement),
      Rule({Token("continue")}, MakeContinueStatement),
      Rule({Token("goto"), &name,
            TryOrDefault<std::vector<Expression*>>(&argumentList)},
           MakeGotoStatement),
      Rule({OneOf({"debug", "unreachable"})}, MakeDebugStatement)};

  // Result: Statement*
  Symbol statement = {
      Rule({&block}),
      Rule({&atomarStatement, Token(";")}),
      Rule({&varDeclaration, Token(";")}),
      Rule({&varDeclarationWithInitialization, Token(";")}),
      Rule({Token("if"), CheckIf(Token("constexpr")), Token("("), expression,
            Token(")"), &statement,
            Optional<Statement*>(Sequence({Token("else"), &statement}))},
           MakeIfStatement),
      Rule(
          {
              Token("typeswitch"),
              Token("("),
              expression,
              Token(")"),
              Token("{"),
              NonemptyListAllowIfAnnotation<TypeswitchCase>(&typeswitchCase),
              Token("}"),
          },
          MakeTypeswitchStatement),
      Rule({Token("try"), &block, List<TryHandler*>(&tryHandler)},
           MakeTryLabelExpression),
      Rule({OneOf({"dcheck", "check", "sbxcheck", "static_assert"}), Token("("),
            &expressionWithSource, Token(")"), Token(";")},
           MakeAssertStatement),
      Rule({Token("while"), Token("("), expression, Token(")"), &statement},
           MakeWhileStatement),
      Rule({Token("for"), Token("("),
            Optional<Statement*>(&varDeclarationWithInitialization), Token(";"),
            Optional<Expression*>(expression), Token(";"),
            Optional<Expression*>(expression), Token(")"), &statement},
           MakeForLoopStatement)};

  // Result: TypeswitchCase
  Symbol typeswitchCase = {
      Rule({Token("case"), Token("("),
            Optional<Identifier*>(Sequence({&name, Token(":")})), &type,
            Token(")"), Token(":"), &block},
           MakeTypeswitchCase)};

  // Result: std::optional<Statement*>
  Symbol optionalBody = {
      Rule({&block}, CastParseResult<Statement*, std::optional<Statement*>>),
      Rule({Token(";")}, YieldDefaultValue<std::optional<Statement*>>)};

  // Result: Declaration*
  Symbol method = {Rule(
      {CheckIf(Token("transitioning")),
       Optional<std::string>(Sequence({Token("operator"), &externalString})),
       Token("macro"), &name, &parameterListNoVararg, &returnType,
       optionalLabelList, &block},
      MakeMethodDeclaration)};

  // Result: std::optional<ClassBody*>
  Symbol optionalClassBody = {
      Rule({Token("{"), List<Declaration*>(&method),
            List<ClassFieldExpression>(&classField), Token("}")},
           MakeClassBody),
      Rule({Token(";")}, YieldDefaultValue<std::optional<ClassBody*>>)};

  // Result: std::vector<Declaration*>
  Symbol declaration = {
      Rule({Token("const"), &name, Token(":"), &type, Token("="), expression,
            Token(";")},
           AsSingletonVector<Declaration*, MakeConstDeclaration>()),
      Rule({Token("const"), &name, Token(":"), &type, Token("generates"),
            &externalString, Token(";")},
           AsSingletonVector<Declaration*, MakeExternConstDeclaration>()),
      Rule({annotations, CheckIf(Token("extern")), CheckIf(Token("transient")),
            OneOf({"class", "shape"}), &name, Token("extends"), &type,
            Optional<std::string>(
                Sequence({Token("generates"), &externalString})),
            &optionalClassBody},
           MakeClassDeclaration),
      Rule({annotations, Token("struct"), &name,
            TryOrDefault<GenericParameters>(&genericParameters), Token("{"),
            ListAllowIfAnnotation<Declaration*>(&method),
            ListAllowIfAnnotation<StructFieldExpression>(&structField),
            Token("}")},
           AsSingletonVector<Declaration*, MakeStructDeclaration>()),
      Rule({Token("bitfield"), Token("struct"), &name, Token("extends"), &type,
            Token("{"),
            ListAllowIfAnnotation<BitFieldDeclaration>(&bitFieldDeclaration),
            Token("}")},
           AsSingletonVector<Declaration*, MakeBitFieldStructDeclaration>()),
      Rule({annotations, CheckIf(Token("transient")), Token("type"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            Optional<TypeExpression*>(Sequence({Token("extends"), &type})),
            Optional<std::string>(
                Sequence({Token("generates"), &externalString})),
            Optional<std::string>(
                Sequence({Token("constexpr"), &externalString})),
            Token(";")},
           MakeAbstractTypeDeclaration),
      Rule({annotations, Token("type"), &name, Token("="), &type, Token(";")},
           MakeTypeAliasDeclaration),
      Rule({Token("intrinsic"), &intrinsicName,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListNoVararg, &returnType, &optionalBody},
           AsSingletonVector<Declaration*, MakeIntrinsicDeclaration>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")),
            Optional<std::string>(
                Sequence({Token("operator"), &externalString})),
            Token("macro"),
            Optional<std::string>(Sequence({&identifier, Token("::")})), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &typeListMaybeVarArgs, &returnType, optionalLabelList, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalMacro>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")),
            CheckIf(Token("javascript")), Token("builtin"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &typeListMaybeVarArgs, &returnType, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalBuiltin>()),
      Rule({Token("extern"), CheckIf(Token("transitioning")), Token("runtime"),
            &name, &typeListMaybeVarArgs, &returnType, Token(";")},
           AsSingletonVector<Declaration*, MakeExternalRuntime>()),
      Rule({annotations, CheckIf(Token("transitioning")),
            Optional<std::string>(
                Sequence({Token("operator"), &externalString})),
            Token("macro"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListNoVararg, &returnType, optionalLabelList,
            &optionalBody},
           AsSingletonVector<Declaration*, MakeTorqueMacroDeclaration>()),
      Rule({annotations, CheckIf(Token("transitioning")),
            CheckIf(Token("javascript")), Token("builtin"), &name,
            TryOrDefault<GenericParameters>(&genericParameters),
            &parameterListAllowVararg, &returnType, &optionalBody},
           MakeTorqueBuiltinDeclaration),
      Rule({CheckIf(Token("transitioning")), &name,
            &genericSpecializationTypeList, &parameterListAllowVararg,
            &returnType, optionalLabelList, &block},
           AsSingletonVector<Declaration*, MakeSpecializationDeclaration>()),
      Rule({Token("#include"), &externalString},
           AsSingletonVector<Declaration*, MakeCppIncludeDeclaration>()),
      Rule({CheckIf(Token("extern")), Token("enum"), &name,
            Optional<TypeExpression*>(Sequence({Token("extends"), &type})),
            Optional<std::string>(
                Sequence({Token("constexpr"), &externalString})),
            Token("{"),
            NonemptyListAllowIfAnnotation<EnumEntry>(&enumEntry, Token(",")),
            CheckIf(Sequence({Token(","), Token("...")})), Token("}")},
           MakeEnumDeclaration),
      Rule({Token("namespace"), &identifier, Token("{"), &declarationList,
            Token("}")},
           AsSingletonVector<Declaration*, MakeNamespaceDeclaration>())};

  // Result: std::vector<Declaration*>
  Symbol declarationList = {
      Rule({List<std::vector<Declaration*>>(&declaration)}, ConcatList)};

  Symbol file = {Rule({&file, Token("import"), &externalString},
                      ProcessTorqueImportDeclaration),
                 Rule({&file, &declaration}, AddGlobalDeclarations), Rule({})};
};

}  // namespace

void ParseTorque(const std::string& input) {
  BuildFlags::Scope build_flags_scope;
  TorqueGrammar().Parse(input);
}

}  // namespace v8::internal::torque

"""


```