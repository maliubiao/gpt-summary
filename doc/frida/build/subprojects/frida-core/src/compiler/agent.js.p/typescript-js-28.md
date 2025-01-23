Response:
The user wants a summary of the functionality of the provided TypeScript code snippet. The code seems to be part of the TypeScript compiler, specifically dealing with syntax tree manipulation and analysis.

Here's a breakdown of the steps to provide a comprehensive answer:

1. **Identify the Core Purpose:** Scan the code for recurring themes and function names. The presence of functions like `getParseTreeNode`, `escapeLeadingUnderscores`, `symbolName`, `getNameOfDeclaration`, `getJSDocTags`, and various `is...` functions strongly suggests this code is about inspecting and manipulating the structure of TypeScript code.

2. **Categorize Functionality:** Group related functions together to identify broader areas of responsibility. For example, functions related to JSDoc annotations form one category. Functions for identifying node types form another.

3. **Look for Binary/Kernel Interactions (and likely absence):** Based on the function names and the context of a TypeScript compiler (which operates on source code), direct interaction with the binary level or Linux kernel is highly improbable. The code operates on an abstract syntax tree (AST). Acknowledge this absence clearly.

4. **Consider Debugging Implications:** If the code manipulates the AST, it's likely used in debugging tools or compiler internals. Think about how a debugger might use this information to inspect variables or navigate code. Since the code *itself* isn't a debugger, the request to "replicate with lldb" is tricky. Focus on what aspects of the *data* this code extracts could be examined with lldb. For instance, if the code identifies a variable name, lldb could be used to examine the *value* of that variable in a running process.

5. **Address Logic and Input/Output:** For functions that perform transformations or extractions, consider simple examples of what the input might be (e.g., a TypeScript identifier) and what the output would be (e.g., the unescaped name).

6. **Identify Potential User Errors:** Think about how a developer writing TypeScript might make mistakes that this code could encounter or help diagnose. For example, incorrectly formatted JSDoc comments or using reserved keywords as identifiers.

7. **Trace User Operations (as debugging context):**  Imagine the steps a user would take to trigger this code. They are likely writing TypeScript code, and this code is part of the compilation process, or potentially used by an IDE for code analysis and tooling.

8. **Summarize Overall Functionality:** Combine the categorized functionalities into a concise overview, keeping in mind that this is part 29 of a larger codebase.

9. **Address the "Part 29" Aspect:** Acknowledge that this snippet is a part of a larger whole and focus on the local functionalities while hinting at the broader context.

**Self-Correction/Refinement During Thinking:**

* **Initial thought:**  Could this be involved in generating assembly code?  **Correction:** Unlikely at this stage. The focus is on the AST, which is a higher-level representation. Assembly generation happens later in the compilation process.
* **Initial thought:**  How can lldb replicate this *specific* code? **Correction:** lldb works at a lower level. This code works on the TypeScript AST. The better approach is to consider what *information* this code extracts and how that information could be relevant to debugging with lldb (e.g., variable names).
* **Initial thought:** Focus heavily on every single function. **Correction:**  Prioritize the most significant and frequently used functions to provide a good overview without getting bogged down in excessive detail. The `is...` functions, name extraction functions, and JSDoc-related functions are key.

By following these steps and iteratively refining the understanding, a comprehensive and accurate answer can be generated.这是frida动态Instrumentation工具中`frida-core`项目下`src/compiler/agent.js.p/typescript.js`文件的第29部分，共197部分。从提供的代码片段来看，这部分代码主要负责**处理和分析 TypeScript 语法树 (Abstract Syntax Tree, AST) 的节点信息**，并提供了一系列工具函数来**识别、提取和操作 AST 节点的不同属性和特征**。

由于这是 TypeScript 编译器的代码，其核心工作是理解和转换 TypeScript 代码，因此**它主要在高层次的抽象语法树上工作，并不直接涉及二进制底层或 Linux 内核的操作**。

**主要功能归纳：**

这部分代码提供了一组实用函数，用于：

1. **识别 AST 节点类型：** 提供了大量的 `is...` 函数，例如 `isParseTreeNode`, `isIdentifier`, `isFunctionLike`, `isClassLike` 等，用于判断给定的 AST 节点是否属于特定的类型。
2. **提取 AST 节点信息：** 提供了函数来提取节点的各种属性，例如：
    * `getParseTreeNode`: 获取节点的解析树节点。
    * `escapeLeadingUnderscores`/`unescapeLeadingUnderscores`: 处理标识符中的前导下划线。
    * `idText`: 获取标识符的文本内容。
    * `identifierToKeywordKind`: 将标识符转换为关键字类型。
    * `symbolName`: 获取符号的名称。
    * `getNameOfDeclaration`: 获取声明的名称。
    * `getDecorators`/`getModifiers`: 获取装饰器和修饰符。
    * `getJSDocParameterTags`/`getJSDocTypeParameterTags`/`getJSDocTags`: 获取与节点相关的 JSDoc 注释信息。
    * `getTextOfJSDocComment`: 获取 JSDoc 注释的文本内容。
    * `getEffectiveTypeParameterDeclarations`/`getEffectiveConstraintOfTypeParameter`: 获取类型参数的声明和约束。
3. **判断节点特征：** 提供了函数来判断节点是否具有某些特征，例如 `nodeHasName`, `isOptionalChain`, `isNullishCoalesce`, `isConstTypeReference` 等。
4. **处理 Optional Chaining:** 提供了 `isOptionalChain`, `isOptionalChainRoot`, `isOutermostOptionalChain` 等函数来识别和处理可选链操作符。
5. **辅助处理 JSDoc 注释：**  提供了大量函数来提取和分析 JSDoc 注释中的信息，例如参数、类型参数、返回类型、标记 (tags) 等。

**二进制底层，Linux内核举例：**

由于这部分代码是 TypeScript 编译器的逻辑，它主要操作的是 TypeScript 源代码的抽象表示，而不是直接与二进制底层或 Linux 内核交互。Frida 在运行时动态地修改进程的行为，但这些修改是基于对进程内存的修改和函数Hook等技术，而编译器的代码主要负责生成这些修改的指令。

**假设输入与输出（逻辑推理）：**

假设有以下 TypeScript 代码片段：

```typescript
/**
 * @param {string} name - The name of the person.
 * @returns {string} A greeting message.
 */
function greet(name: string): string {
  return `Hello, ${name}!`;
}
```

对于 `getJSDocParameterTags(greet)`，**假设输入**是表示 `greet` 函数的 AST 节点，**输出**可能是包含一个 `JSDocParameterTag` 对象的数组，该对象包含了参数名 "name" 和类型 "string" 的信息。

对于 `getNameOfDeclaration(greet)`，**假设输入**是表示 `greet` 函数的 AST 节点，**输出**是表示标识符 "greet" 的 AST 节点。

**用户或编程常见的使用错误举例：**

1. **JSDoc 注释格式错误：**  如果用户在 JSDoc 注释中使用了错误的标记或格式，例如 `@paramn` 而不是 `@param`，相关的 `getJSDoc...` 函数可能会返回 `undefined` 或不正确的结果。
2. **类型声明错误：** 如果用户在 TypeScript 代码中声明了错误的类型，例如将一个数字类型的变量声明为字符串类型，编译器在分析 AST 时可能会发现类型不匹配，这部分代码可能参与到这种错误的识别过程中。
3. **使用了保留关键字作为标识符：** 如果用户尝试使用 TypeScript 的保留关键字（例如 `class`, `function`）作为变量名，编译器在解析 AST 时会报错，相关的标识符识别函数可能会返回特殊的错误标记。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户编写 TypeScript 代码：**  用户在编辑器中编写 `.ts` 文件。
2. **调用 TypeScript 编译器：** 用户使用 `tsc` 命令或 IDE 的编译功能来编译 TypeScript 代码。
3. **编译器解析代码：** 编译器首先会对 TypeScript 代码进行词法分析和语法分析，生成抽象语法树 (AST)。
4. **遍历和分析 AST：**  编译器内部的逻辑会遍历和分析生成的 AST，以进行类型检查、代码优化、代码生成等操作。
5. **执行到 `agent.js.p/typescript.js` 的代码：** 在遍历和分析 AST 的过程中，可能需要获取和处理特定节点的属性和特征，例如获取函数的参数信息、JSDoc 注释等，这时就会调用 `agent.js.p/typescript.js` 中的相关函数。

**功能归纳（针对第29部分）：**

总的来说，这部分代码是 TypeScript 编译器用于**理解和操作 TypeScript 代码结构的关键组成部分**。它提供了一系列用于**识别、提取和分析 AST 节点信息的工具函数**，为编译器的后续处理（例如类型检查、代码生成等）提供了基础。虽然不直接涉及底层操作，但它是构建 Frida 这样动态 Instrumentation 工具的基础，因为 Frida 需要理解目标程序的代码结构才能进行精确的修改和Hook。

### 提示词
```
这是目录为frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第29部分，共197部分，请归纳一下它的功能
```

### 源代码
```javascript
sized */) === 0;
    }
    function getParseTreeNode(node, nodeTest) {
      if (node === void 0 || isParseTreeNode(node)) {
        return node;
      }
      node = node.original;
      while (node) {
        if (isParseTreeNode(node)) {
          return !nodeTest || nodeTest(node) ? node : void 0;
        }
        node = node.original;
      }
    }
    function escapeLeadingUnderscores(identifier) {
      return identifier.length >= 2 && identifier.charCodeAt(0) === 95 /* _ */ && identifier.charCodeAt(1) === 95 /* _ */ ? "_" + identifier : identifier;
    }
    function unescapeLeadingUnderscores(identifier) {
      const id = identifier;
      return id.length >= 3 && id.charCodeAt(0) === 95 /* _ */ && id.charCodeAt(1) === 95 /* _ */ && id.charCodeAt(2) === 95 /* _ */ ? id.substr(1) : id;
    }
    function idText(identifierOrPrivateName) {
      return unescapeLeadingUnderscores(identifierOrPrivateName.escapedText);
    }
    function identifierToKeywordKind(node) {
      const token = stringToToken(node.escapedText);
      return token ? tryCast(token, isKeyword) : void 0;
    }
    function symbolName(symbol) {
      if (symbol.valueDeclaration && isPrivateIdentifierClassElementDeclaration(symbol.valueDeclaration)) {
        return idText(symbol.valueDeclaration.name);
      }
      return unescapeLeadingUnderscores(symbol.escapedName);
    }
    function nameForNamelessJSDocTypedef(declaration) {
      const hostNode = declaration.parent.parent;
      if (!hostNode) {
        return void 0;
      }
      if (isDeclaration(hostNode)) {
        return getDeclarationIdentifier(hostNode);
      }
      switch (hostNode.kind) {
        case 242 /* VariableStatement */:
          if (hostNode.declarationList && hostNode.declarationList.declarations[0]) {
            return getDeclarationIdentifier(hostNode.declarationList.declarations[0]);
          }
          break;
        case 243 /* ExpressionStatement */:
          let expr = hostNode.expression;
          if (expr.kind === 225 /* BinaryExpression */ && expr.operatorToken.kind === 64 /* EqualsToken */) {
            expr = expr.left;
          }
          switch (expr.kind) {
            case 210 /* PropertyAccessExpression */:
              return expr.name;
            case 211 /* ElementAccessExpression */:
              const arg = expr.argumentExpression;
              if (isIdentifier(arg)) {
                return arg;
              }
          }
          break;
        case 216 /* ParenthesizedExpression */: {
          return getDeclarationIdentifier(hostNode.expression);
        }
        case 255 /* LabeledStatement */: {
          if (isDeclaration(hostNode.statement) || isExpression(hostNode.statement)) {
            return getDeclarationIdentifier(hostNode.statement);
          }
          break;
        }
      }
    }
    function getDeclarationIdentifier(node) {
      const name = getNameOfDeclaration(node);
      return name && isIdentifier(name) ? name : void 0;
    }
    function nodeHasName(statement, name) {
      if (isNamedDeclaration(statement) && isIdentifier(statement.name) && idText(statement.name) === idText(name)) {
        return true;
      }
      if (isVariableStatement(statement) && some(statement.declarationList.declarations, (d) => nodeHasName(d, name))) {
        return true;
      }
      return false;
    }
    function getNameOfJSDocTypedef(declaration) {
      return declaration.name || nameForNamelessJSDocTypedef(declaration);
    }
    function isNamedDeclaration(node) {
      return !!node.name;
    }
    function getNonAssignedNameOfDeclaration(declaration) {
      switch (declaration.kind) {
        case 80 /* Identifier */:
          return declaration;
        case 354 /* JSDocPropertyTag */:
        case 347 /* JSDocParameterTag */: {
          const { name } = declaration;
          if (name.kind === 165 /* QualifiedName */) {
            return name.right;
          }
          break;
        }
        case 212 /* CallExpression */:
        case 225 /* BinaryExpression */: {
          const expr2 = declaration;
          switch (getAssignmentDeclarationKind(expr2)) {
            case 1 /* ExportsProperty */:
            case 4 /* ThisProperty */:
            case 5 /* Property */:
            case 3 /* PrototypeProperty */:
              return getElementOrPropertyAccessArgumentExpressionOrName(expr2.left);
            case 7 /* ObjectDefinePropertyValue */:
            case 8 /* ObjectDefinePropertyExports */:
            case 9 /* ObjectDefinePrototypeProperty */:
              return expr2.arguments[1];
            default:
              return void 0;
          }
        }
        case 352 /* JSDocTypedefTag */:
          return getNameOfJSDocTypedef(declaration);
        case 346 /* JSDocEnumTag */:
          return nameForNamelessJSDocTypedef(declaration);
        case 276 /* ExportAssignment */: {
          const { expression } = declaration;
          return isIdentifier(expression) ? expression : void 0;
        }
        case 211 /* ElementAccessExpression */:
          const expr = declaration;
          if (isBindableStaticElementAccessExpression(expr)) {
            return expr.argumentExpression;
          }
      }
      return declaration.name;
    }
    function getNameOfDeclaration(declaration) {
      if (declaration === void 0)
        return void 0;
      return getNonAssignedNameOfDeclaration(declaration) || (isFunctionExpression(declaration) || isArrowFunction(declaration) || isClassExpression(declaration) ? getAssignedName(declaration) : void 0);
    }
    function getAssignedName(node) {
      if (!node.parent) {
        return void 0;
      } else if (isPropertyAssignment(node.parent) || isBindingElement(node.parent)) {
        return node.parent.name;
      } else if (isBinaryExpression(node.parent) && node === node.parent.right) {
        if (isIdentifier(node.parent.left)) {
          return node.parent.left;
        } else if (isAccessExpression(node.parent.left)) {
          return getElementOrPropertyAccessArgumentExpressionOrName(node.parent.left);
        }
      } else if (isVariableDeclaration(node.parent) && isIdentifier(node.parent.name)) {
        return node.parent.name;
      }
    }
    function getDecorators(node) {
      if (hasDecorators(node)) {
        return filter(node.modifiers, isDecorator);
      }
    }
    function getModifiers(node) {
      if (hasSyntacticModifier(node, 126975 /* Modifier */)) {
        return filter(node.modifiers, isModifier);
      }
    }
    function getJSDocParameterTagsWorker(param, noCache) {
      if (param.name) {
        if (isIdentifier(param.name)) {
          const name = param.name.escapedText;
          return getJSDocTagsWorker(param.parent, noCache).filter((tag) => isJSDocParameterTag(tag) && isIdentifier(tag.name) && tag.name.escapedText === name);
        } else {
          const i = param.parent.parameters.indexOf(param);
          Debug.assert(i > -1, "Parameters should always be in their parents' parameter list");
          const paramTags = getJSDocTagsWorker(param.parent, noCache).filter(isJSDocParameterTag);
          if (i < paramTags.length) {
            return [paramTags[i]];
          }
        }
      }
      return emptyArray;
    }
    function getJSDocParameterTags(param) {
      return getJSDocParameterTagsWorker(
        param,
        /*noCache*/
        false
      );
    }
    function getJSDocParameterTagsNoCache(param) {
      return getJSDocParameterTagsWorker(
        param,
        /*noCache*/
        true
      );
    }
    function getJSDocTypeParameterTagsWorker(param, noCache) {
      const name = param.name.escapedText;
      return getJSDocTagsWorker(param.parent, noCache).filter((tag) => isJSDocTemplateTag(tag) && tag.typeParameters.some((tp) => tp.name.escapedText === name));
    }
    function getJSDocTypeParameterTags(param) {
      return getJSDocTypeParameterTagsWorker(
        param,
        /*noCache*/
        false
      );
    }
    function getJSDocTypeParameterTagsNoCache(param) {
      return getJSDocTypeParameterTagsWorker(
        param,
        /*noCache*/
        true
      );
    }
    function hasJSDocParameterTags(node) {
      return !!getFirstJSDocTag(node, isJSDocParameterTag);
    }
    function getJSDocAugmentsTag(node) {
      return getFirstJSDocTag(node, isJSDocAugmentsTag);
    }
    function getJSDocImplementsTags(node) {
      return getAllJSDocTags(node, isJSDocImplementsTag);
    }
    function getJSDocClassTag(node) {
      return getFirstJSDocTag(node, isJSDocClassTag);
    }
    function getJSDocPublicTag(node) {
      return getFirstJSDocTag(node, isJSDocPublicTag);
    }
    function getJSDocPublicTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocPublicTag,
        /*noCache*/
        true
      );
    }
    function getJSDocPrivateTag(node) {
      return getFirstJSDocTag(node, isJSDocPrivateTag);
    }
    function getJSDocPrivateTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocPrivateTag,
        /*noCache*/
        true
      );
    }
    function getJSDocProtectedTag(node) {
      return getFirstJSDocTag(node, isJSDocProtectedTag);
    }
    function getJSDocProtectedTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocProtectedTag,
        /*noCache*/
        true
      );
    }
    function getJSDocReadonlyTag(node) {
      return getFirstJSDocTag(node, isJSDocReadonlyTag);
    }
    function getJSDocReadonlyTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocReadonlyTag,
        /*noCache*/
        true
      );
    }
    function getJSDocOverrideTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocOverrideTag,
        /*noCache*/
        true
      );
    }
    function getJSDocDeprecatedTag(node) {
      return getFirstJSDocTag(node, isJSDocDeprecatedTag);
    }
    function getJSDocDeprecatedTagNoCache(node) {
      return getFirstJSDocTag(
        node,
        isJSDocDeprecatedTag,
        /*noCache*/
        true
      );
    }
    function getJSDocEnumTag(node) {
      return getFirstJSDocTag(node, isJSDocEnumTag);
    }
    function getJSDocThisTag(node) {
      return getFirstJSDocTag(node, isJSDocThisTag);
    }
    function getJSDocReturnTag(node) {
      return getFirstJSDocTag(node, isJSDocReturnTag);
    }
    function getJSDocTemplateTag(node) {
      return getFirstJSDocTag(node, isJSDocTemplateTag);
    }
    function getJSDocSatisfiesTag(node) {
      return getFirstJSDocTag(node, isJSDocSatisfiesTag);
    }
    function getJSDocTypeTag(node) {
      const tag = getFirstJSDocTag(node, isJSDocTypeTag);
      if (tag && tag.typeExpression && tag.typeExpression.type) {
        return tag;
      }
      return void 0;
    }
    function getJSDocType(node) {
      let tag = getFirstJSDocTag(node, isJSDocTypeTag);
      if (!tag && isParameter(node)) {
        tag = find(getJSDocParameterTags(node), (tag2) => !!tag2.typeExpression);
      }
      return tag && tag.typeExpression && tag.typeExpression.type;
    }
    function getJSDocReturnType(node) {
      const returnTag = getJSDocReturnTag(node);
      if (returnTag && returnTag.typeExpression) {
        return returnTag.typeExpression.type;
      }
      const typeTag = getJSDocTypeTag(node);
      if (typeTag && typeTag.typeExpression) {
        const type = typeTag.typeExpression.type;
        if (isTypeLiteralNode(type)) {
          const sig = find(type.members, isCallSignatureDeclaration);
          return sig && sig.type;
        }
        if (isFunctionTypeNode(type) || isJSDocFunctionType(type)) {
          return type.type;
        }
      }
    }
    function getJSDocTagsWorker(node, noCache) {
      if (!canHaveJSDoc(node))
        return emptyArray;
      let tags = node.jsDoc?.jsDocCache;
      if (tags === void 0 || noCache) {
        const comments = getJSDocCommentsAndTags(node, noCache);
        Debug.assert(comments.length < 2 || comments[0] !== comments[1]);
        tags = flatMap(comments, (j) => isJSDoc(j) ? j.tags : j);
        if (!noCache) {
          node.jsDoc ?? (node.jsDoc = []);
          node.jsDoc.jsDocCache = tags;
        }
      }
      return tags;
    }
    function getJSDocTags(node) {
      return getJSDocTagsWorker(
        node,
        /*noCache*/
        false
      );
    }
    function getJSDocTagsNoCache(node) {
      return getJSDocTagsWorker(
        node,
        /*noCache*/
        true
      );
    }
    function getFirstJSDocTag(node, predicate, noCache) {
      return find(getJSDocTagsWorker(node, noCache), predicate);
    }
    function getAllJSDocTags(node, predicate) {
      return getJSDocTags(node).filter(predicate);
    }
    function getAllJSDocTagsOfKind(node, kind) {
      return getJSDocTags(node).filter((doc) => doc.kind === kind);
    }
    function getTextOfJSDocComment(comment) {
      return typeof comment === "string" ? comment : comment?.map((c) => c.kind === 327 /* JSDocText */ ? c.text : formatJSDocLink(c)).join("");
    }
    function formatJSDocLink(link) {
      const kind = link.kind === 330 /* JSDocLink */ ? "link" : link.kind === 331 /* JSDocLinkCode */ ? "linkcode" : "linkplain";
      const name = link.name ? entityNameToString(link.name) : "";
      const space = link.name && link.text.startsWith("://") ? "" : " ";
      return `{@${kind} ${name}${space}${link.text}}`;
    }
    function getEffectiveTypeParameterDeclarations(node) {
      if (isJSDocSignature(node)) {
        if (isJSDocOverloadTag(node.parent)) {
          const jsDoc = getJSDocRoot(node.parent);
          if (jsDoc && length(jsDoc.tags)) {
            return flatMap(jsDoc.tags, (tag) => isJSDocTemplateTag(tag) ? tag.typeParameters : void 0);
          }
        }
        return emptyArray;
      }
      if (isJSDocTypeAlias(node)) {
        Debug.assert(node.parent.kind === 326 /* JSDoc */);
        return flatMap(node.parent.tags, (tag) => isJSDocTemplateTag(tag) ? tag.typeParameters : void 0);
      }
      if (node.typeParameters) {
        return node.typeParameters;
      }
      if (canHaveIllegalTypeParameters(node) && node.typeParameters) {
        return node.typeParameters;
      }
      if (isInJSFile(node)) {
        const decls = getJSDocTypeParameterDeclarations(node);
        if (decls.length) {
          return decls;
        }
        const typeTag = getJSDocType(node);
        if (typeTag && isFunctionTypeNode(typeTag) && typeTag.typeParameters) {
          return typeTag.typeParameters;
        }
      }
      return emptyArray;
    }
    function getEffectiveConstraintOfTypeParameter(node) {
      return node.constraint ? node.constraint : isJSDocTemplateTag(node.parent) && node === node.parent.typeParameters[0] ? node.parent.constraint : void 0;
    }
    function isMemberName(node) {
      return node.kind === 80 /* Identifier */ || node.kind === 81 /* PrivateIdentifier */;
    }
    function isGetOrSetAccessorDeclaration(node) {
      return node.kind === 177 /* SetAccessor */ || node.kind === 176 /* GetAccessor */;
    }
    function isPropertyAccessChain(node) {
      return isPropertyAccessExpression(node) && !!(node.flags & 32 /* OptionalChain */);
    }
    function isElementAccessChain(node) {
      return isElementAccessExpression(node) && !!(node.flags & 32 /* OptionalChain */);
    }
    function isCallChain(node) {
      return isCallExpression(node) && !!(node.flags & 32 /* OptionalChain */);
    }
    function isOptionalChain(node) {
      const kind = node.kind;
      return !!(node.flags & 32 /* OptionalChain */) && (kind === 210 /* PropertyAccessExpression */ || kind === 211 /* ElementAccessExpression */ || kind === 212 /* CallExpression */ || kind === 234 /* NonNullExpression */);
    }
    function isOptionalChainRoot(node) {
      return isOptionalChain(node) && !isNonNullExpression(node) && !!node.questionDotToken;
    }
    function isExpressionOfOptionalChainRoot(node) {
      return isOptionalChainRoot(node.parent) && node.parent.expression === node;
    }
    function isOutermostOptionalChain(node) {
      return !isOptionalChain(node.parent) || isOptionalChainRoot(node.parent) || node !== node.parent.expression;
    }
    function isNullishCoalesce(node) {
      return node.kind === 225 /* BinaryExpression */ && node.operatorToken.kind === 61 /* QuestionQuestionToken */;
    }
    function isConstTypeReference(node) {
      return isTypeReferenceNode(node) && isIdentifier(node.typeName) && node.typeName.escapedText === "const" && !node.typeArguments;
    }
    function skipPartiallyEmittedExpressions(node) {
      return skipOuterExpressions(node, 8 /* PartiallyEmittedExpressions */);
    }
    function isNonNullChain(node) {
      return isNonNullExpression(node) && !!(node.flags & 32 /* OptionalChain */);
    }
    function isBreakOrContinueStatement(node) {
      return node.kind === 251 /* BreakStatement */ || node.kind === 250 /* ContinueStatement */;
    }
    function isNamedExportBindings(node) {
      return node.kind === 279 /* NamespaceExport */ || node.kind === 278 /* NamedExports */;
    }
    function isUnparsedTextLike(node) {
      switch (node.kind) {
        case 308 /* UnparsedText */:
        case 309 /* UnparsedInternalText */:
          return true;
        default:
          return false;
      }
    }
    function isUnparsedNode(node) {
      return isUnparsedTextLike(node) || node.kind === 306 /* UnparsedPrologue */ || node.kind === 310 /* UnparsedSyntheticReference */;
    }
    function isJSDocPropertyLikeTag(node) {
      return node.kind === 354 /* JSDocPropertyTag */ || node.kind === 347 /* JSDocParameterTag */;
    }
    function isNode(node) {
      return isNodeKind(node.kind);
    }
    function isNodeKind(kind) {
      return kind >= 165 /* FirstNode */;
    }
    function isTokenKind(kind) {
      return kind >= 0 /* FirstToken */ && kind <= 164 /* LastToken */;
    }
    function isToken(n) {
      return isTokenKind(n.kind);
    }
    function isNodeArray(array) {
      return hasProperty(array, "pos") && hasProperty(array, "end");
    }
    function isLiteralKind(kind) {
      return 9 /* FirstLiteralToken */ <= kind && kind <= 15 /* LastLiteralToken */;
    }
    function isLiteralExpression(node) {
      return isLiteralKind(node.kind);
    }
    function isLiteralExpressionOfObject(node) {
      switch (node.kind) {
        case 209 /* ObjectLiteralExpression */:
        case 208 /* ArrayLiteralExpression */:
        case 14 /* RegularExpressionLiteral */:
        case 217 /* FunctionExpression */:
        case 230 /* ClassExpression */:
          return true;
      }
      return false;
    }
    function isTemplateLiteralKind(kind) {
      return 15 /* FirstTemplateToken */ <= kind && kind <= 18 /* LastTemplateToken */;
    }
    function isTemplateLiteralToken(node) {
      return isTemplateLiteralKind(node.kind);
    }
    function isTemplateMiddleOrTemplateTail(node) {
      const kind = node.kind;
      return kind === 17 /* TemplateMiddle */ || kind === 18 /* TemplateTail */;
    }
    function isImportOrExportSpecifier(node) {
      return isImportSpecifier(node) || isExportSpecifier(node);
    }
    function isTypeOnlyImportDeclaration(node) {
      switch (node.kind) {
        case 275 /* ImportSpecifier */:
          return node.isTypeOnly || node.parent.parent.isTypeOnly;
        case 273 /* NamespaceImport */:
          return node.parent.isTypeOnly;
        case 272 /* ImportClause */:
        case 270 /* ImportEqualsDeclaration */:
          return node.isTypeOnly;
      }
      return false;
    }
    function isTypeOnlyExportDeclaration(node) {
      switch (node.kind) {
        case 280 /* ExportSpecifier */:
          return node.isTypeOnly || node.parent.parent.isTypeOnly;
        case 277 /* ExportDeclaration */:
          return node.isTypeOnly && !!node.moduleSpecifier && !node.exportClause;
        case 279 /* NamespaceExport */:
          return node.parent.isTypeOnly;
      }
      return false;
    }
    function isTypeOnlyImportOrExportDeclaration(node) {
      return isTypeOnlyImportDeclaration(node) || isTypeOnlyExportDeclaration(node);
    }
    function isAssertionKey(node) {
      return isStringLiteral(node) || isIdentifier(node);
    }
    function isStringTextContainingNode(node) {
      return node.kind === 11 /* StringLiteral */ || isTemplateLiteralKind(node.kind);
    }
    function isGeneratedIdentifier(node) {
      return isIdentifier(node) && node.emitNode?.autoGenerate !== void 0;
    }
    function isGeneratedPrivateIdentifier(node) {
      return isPrivateIdentifier(node) && node.emitNode?.autoGenerate !== void 0;
    }
    function isPrivateIdentifierClassElementDeclaration(node) {
      return (isPropertyDeclaration(node) || isMethodOrAccessor(node)) && isPrivateIdentifier(node.name);
    }
    function isPrivateIdentifierPropertyAccessExpression(node) {
      return isPropertyAccessExpression(node) && isPrivateIdentifier(node.name);
    }
    function isModifierKind(token) {
      switch (token) {
        case 128 /* AbstractKeyword */:
        case 129 /* AccessorKeyword */:
        case 134 /* AsyncKeyword */:
        case 87 /* ConstKeyword */:
        case 138 /* DeclareKeyword */:
        case 90 /* DefaultKeyword */:
        case 95 /* ExportKeyword */:
        case 103 /* InKeyword */:
        case 125 /* PublicKeyword */:
        case 123 /* PrivateKeyword */:
        case 124 /* ProtectedKeyword */:
        case 148 /* ReadonlyKeyword */:
        case 126 /* StaticKeyword */:
        case 147 /* OutKeyword */:
        case 163 /* OverrideKeyword */:
          return true;
      }
      return false;
    }
    function isParameterPropertyModifier(kind) {
      return !!(modifierToFlag(kind) & 16476 /* ParameterPropertyModifier */);
    }
    function isClassMemberModifier(idToken) {
      return isParameterPropertyModifier(idToken) || idToken === 126 /* StaticKeyword */ || idToken === 163 /* OverrideKeyword */ || idToken === 129 /* AccessorKeyword */;
    }
    function isModifier(node) {
      return isModifierKind(node.kind);
    }
    function isEntityName(node) {
      const kind = node.kind;
      return kind === 165 /* QualifiedName */ || kind === 80 /* Identifier */;
    }
    function isPropertyName(node) {
      const kind = node.kind;
      return kind === 80 /* Identifier */ || kind === 81 /* PrivateIdentifier */ || kind === 11 /* StringLiteral */ || kind === 9 /* NumericLiteral */ || kind === 166 /* ComputedPropertyName */;
    }
    function isBindingName(node) {
      const kind = node.kind;
      return kind === 80 /* Identifier */ || kind === 205 /* ObjectBindingPattern */ || kind === 206 /* ArrayBindingPattern */;
    }
    function isFunctionLike(node) {
      return !!node && isFunctionLikeKind(node.kind);
    }
    function isFunctionLikeOrClassStaticBlockDeclaration(node) {
      return !!node && (isFunctionLikeKind(node.kind) || isClassStaticBlockDeclaration(node));
    }
    function isFunctionLikeDeclaration(node) {
      return node && isFunctionLikeDeclarationKind(node.kind);
    }
    function isBooleanLiteral(node) {
      return node.kind === 112 /* TrueKeyword */ || node.kind === 97 /* FalseKeyword */;
    }
    function isFunctionLikeDeclarationKind(kind) {
      switch (kind) {
        case 261 /* FunctionDeclaration */:
        case 173 /* MethodDeclaration */:
        case 175 /* Constructor */:
        case 176 /* GetAccessor */:
        case 177 /* SetAccessor */:
        case 217 /* FunctionExpression */:
        case 218 /* ArrowFunction */:
          return true;
        default:
          return false;
      }
    }
    function isFunctionLikeKind(kind) {
      switch (kind) {
        case 172 /* MethodSignature */:
        case 178 /* CallSignature */:
        case 329 /* JSDocSignature */:
        case 179 /* ConstructSignature */:
        case 180 /* IndexSignature */:
        case 183 /* FunctionType */:
        case 323 /* JSDocFunctionType */:
        case 184 /* ConstructorType */:
          return true;
        default:
          return isFunctionLikeDeclarationKind(kind);
      }
    }
    function isFunctionOrModuleBlock(node) {
      return isSourceFile(node) || isModuleBlock(node) || isBlock(node) && isFunctionLike(node.parent);
    }
    function isClassElement(node) {
      const kind = node.kind;
      return kind === 175 /* Constructor */ || kind === 171 /* PropertyDeclaration */ || kind === 173 /* MethodDeclaration */ || kind === 176 /* GetAccessor */ || kind === 177 /* SetAccessor */ || kind === 180 /* IndexSignature */ || kind === 174 /* ClassStaticBlockDeclaration */ || kind === 239 /* SemicolonClassElement */;
    }
    function isClassLike(node) {
      return node && (node.kind === 262 /* ClassDeclaration */ || node.kind === 230 /* ClassExpression */);
    }
    function isAccessor(node) {
      return node && (node.kind === 176 /* GetAccessor */ || node.kind === 177 /* SetAccessor */);
    }
    function isAutoAccessorPropertyDeclaration(node) {
      return isPropertyDeclaration(node) && hasAccessorModifier(node);
    }
    function isMethodOrAccessor(node) {
      switch (node.kind) {
        case 173 /* MethodDeclaration */:
        case 176 /* GetAccessor */:
        case 177 /* SetAccessor */:
          return true;
        default:
          return false;
      }
    }
    function isNamedClassElement(node) {
      switch (node.kind) {
        case 173 /* MethodDeclaration */:
        case 176 /* GetAccessor */:
        case 177 /* SetAccessor */:
        case 171 /* PropertyDeclaration */:
          return true;
        default:
          return false;
      }
    }
    function isModifierLike(node) {
      return isModifier(node) || isDecorator(node);
    }
    function isTypeElement(node) {
      const kind = node.kind;
      return kind === 179 /* ConstructSignature */ || kind === 178 /* CallSignature */ || kind === 170 /* PropertySignature */ || kind === 172 /* MethodSignature */ || kind === 180 /* IndexSignature */ || kind === 176 /* GetAccessor */ || kind === 177 /* SetAccessor */;
    }
    function isClassOrTypeElement(node) {
      return isTypeElement(node) || isClassElement(node);
    }
    function isObjectLiteralElementLike(node) {
      const kind = node.kind;
      return kind === 302 /* PropertyAssignment */ || kind === 303 /* ShorthandPropertyAssignment */ || kind === 304 /* SpreadAssignment */ || kind === 173 /* MethodDeclaration */ || kind === 176 /* GetAccessor */ || kind === 177 /* SetAccessor */;
    }
    function isTypeNode(node) {
      return isTypeNodeKind(node.kind);
    }
    function isFunctionOrConstructorTypeNode(node) {
      switch (node.kind) {
        case 183 /* FunctionType */:
        case 184 /* ConstructorType */:
          return true;
      }
      return false;
    }
    function isBindingPattern(node) {
      if (node) {
        const kind = node.kind;
        return kind === 206 /* ArrayBindingPattern */ || kind === 205 /* ObjectBindingPattern */;
      }
      return false;
    }
    function isAssignmentPattern(node) {
      const kind = node.kind;
      return kind === 208 /* ArrayLiteralExpression */ || kind === 209 /* ObjectLiteralExpression */;
    }
    function isArrayBindingElement(node) {
      const kind = node.kind;
      return kind === 207 /* BindingElement */ || kind === 231 /* OmittedExpression */;
    }
    function isDeclarationBindingElement(bindingElement) {
      switch (bindingElement.kind) {
        case 259 /* VariableDeclaration */:
        case 168 /* Parameter */:
        case 207 /* BindingElement */:
          return true;
      }
      return false;
    }
    function isBindingOrAssignmentElement(node) {
      return isVariableDeclaration(node) || isParameter(node) || isObjectBindingOrAssignmentElement(node) || isArrayBindingOrAssignmentElement(node);
    }
    function isBindingOrAssignmentPattern(node) {
      return isObjectBindingOrAssignmentPattern(node) || isArrayBindingOrAssignmentPattern(node);
    }
    function isObjectBindingOrAssignmentPattern(node) {
      switch (node.kind) {
        case 205 /* ObjectBindingPattern */:
        case 209 /* ObjectLiteralExpression */:
          return true;
      }
      return false;
    }
    function isObjectBindingOrAssignmentElement(node) {
      switch (node.kind) {
        case 207 /* BindingElement */:
        case 302 /* PropertyAssignment */:
        case 303 /* ShorthandPropertyAssignment */:
        case 304 /* SpreadAssignment */:
          return true;
      }
      return false;
    }
    function isArrayBindingOrAssignmentPattern(node) {
      switch (node.kind) {
        case 206 /* ArrayBindingPattern */:
        case 208 /* ArrayLiteralExpression */:
          return true;
      }
      return false;
    }
    function isArrayBindingOrAssignmentElement(node) {
      switch (node.kind) {
        case 207 /* BindingElement */:
        case 231 /* OmittedExpression */:
        case 229 /* SpreadElement */:
        case 208 /* ArrayLiteralExpression */:
        case 209 /* ObjectLiteralExpression */:
        case 80 /* Identifier */:
        case 210 /* PropertyAccessExpression */:
        case 211 /* ElementAccessExpression */:
          return true;
      }
      return isAssignmentExpression(
        node,
        /*excludeCompoundAssignment*/
        true
      );
    }
    function isPropertyAccessOrQualifiedNameOrImportTypeNode(node) {
      const kind = node.kind;
      return kind === 210 /* PropertyAccessExpression */ || kind === 165 /* QualifiedName */ || kind === 204 /* ImportType */;
    }
    function isPropertyAccessOrQualifiedName(node) {
      const kind = node.kind;
      return kind === 210 /* PropertyAccessExpression */ || kind === 165 /* QualifiedName */;
    }
    function isCallLikeExpression(node) {
      switch (node.kind) {
        case 285 /* JsxOpeningElement */:
        case 284 /* JsxSelfClosingElement */:
        case 212 /* CallExpression */:
        case 213 /* NewExpression */:
        case 214 /* TaggedTemplateExpression */:
        case 169 /* Decorator */:
          return true;
        default:
          return false;
      }
    }
    function isCallOrNewExpression(node) {
      return node.kind === 212 /* CallExpression */ || node.kind === 213 /* NewExpression */;
    }
    function isTemplateLiteral(node) {
      const kind = node.kind;
      return kind === 227 /* TemplateExpression */ || kind === 15 /* NoSubstitutionTemplateLiteral */;
    }
    function isLeftHandSideExpression(node) {
      return isLeftHandSideExpressionKind(skipPartiallyEmittedExpressions(node).kind);
    }
    function isLeftHandSideExpressionKind(kind) {
      switch (kind) {
        case 210 /* PropertyAccessExpression */:
        case 211 /* ElementAccessExpression */:
        case 213 /* NewExpression */:
        case 212 /* CallExpression */:
        case 283 /* JsxElement */:
        case 284 /* JsxSelfClosingElement */:
        case 287 /* JsxFragment */:
        case 214 /* TaggedTemplateExpression */:
        case 208 /* ArrayLiteralExpression */:
        case 216 /* ParenthesizedExpression */:
        case 209 /* ObjectLiteralExpression */:
        case 230 /* ClassExpression */:
        case 217 /* FunctionExpression */:
        case 80 /* Identifier */:
        case 81 /* PrivateIdentifier */:
        case 14 /* RegularExpressionLiteral */:
        case 9 /* NumericLiteral */:
        case 10 /* BigIntLiteral */:
        case 11 /* StringLiteral */:
        case 15 /* NoSubstitutionTemplateLiteral */:
        case 227 /* TemplateExpression */:
        case 97 /* FalseKeyword */:
        case 106 /* NullKeyword */:
        case 110 /* ThisKeyword */:
        case 112 /* TrueKeyword */:
        case 108 /* SuperKeyword */:
        case 234 /* NonNullExpression */:
        case 232 /* ExpressionWithTypeArguments */:
        case 235 /* MetaProperty */:
        case 102 /* ImportKeyword */:
        case 281 /* MissingDeclaration */:
          return true;
        default:
          return false;
      }
    }
    function isUnaryExpression(node) {
      return isUnaryExpressionKind(skipPartiallyEmittedExpressions(node).kind);
    }
    function isUnaryExpressionKind(kind) {
      switch (kind) {
        case 223 /* PrefixUnaryExpression */:
        case 224 /* PostfixUnaryExpression */:
        case 219 /* DeleteExpression */:
        case 220 /* TypeOfExpression */:
        case 221 /* VoidExpression */:
        case 222 /* AwaitExpression */:
        case 215 /* TypeAssertionExpression */:
          return true;
        default:
```