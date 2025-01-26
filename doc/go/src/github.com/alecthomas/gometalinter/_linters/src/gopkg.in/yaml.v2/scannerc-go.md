Response:
My thought process to answer the question about the `scannerc.go` file goes like this:

1. **Understand the Request:** The core request is to analyze a Go code snippet from a YAML library and explain its functionality. The prompt specifically asks for function, potential Go feature implementation, example code with input/output, command-line argument handling (if any), common mistakes, and a summary of its function for this first part.

2. **Initial Scan and Keywords:** I quickly scan the code for key terms and patterns. I see comments mentioning "Scanner," "Parser," "tokens," and various YAML-related terms like "STREAM-START," "SCALAR," "BLOCK-SEQUENCE-START," etc. The function names like `yaml_parser_scan`, `yaml_parser_fetch_more_tokens`, `yaml_parser_fetch_next_token` are also indicative.

3. **Identify Core Functionality:**  The introductory comments explicitly state that this code deals with the "Scanning" phase of YAML processing. It transforms the input stream into a sequence of tokens. This is the fundamental function.

4. **Token Analysis:**  The code provides a comprehensive list of tokens. I analyze this list and categorize them into:
    * **Stream Markers:** `STREAM-START`, `STREAM-END`
    * **Directives:** `VERSION-DIRECTIVE`, `TAG-DIRECTIVE`
    * **Document Markers:** `DOCUMENT-START`, `DOCUMENT-END`
    * **Collection Markers (Block and Flow):** `BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START`, `FLOW-SEQUENCE-START`, `FLOW-MAPPING-START`, `BLOCK-END`, `FLOW-SEQUENCE-END`, `FLOW-MAPPING-END`
    * **Entry Markers:** `BLOCK-ENTRY`, `FLOW-ENTRY`
    * **Key/Value Markers:** `KEY`, `VALUE`
    * **Content Markers:** `ALIAS`, `ANCHOR`, `TAG`, `SCALAR`

5. **Connect Code to Functionality:** I start linking the function names and logic to the identified functionality.
    * `yaml_parser_scan`:  This seems to be the main function for getting the next token.
    * `yaml_parser_fetch_more_tokens`: Implies a need to buffer or pre-fetch tokens.
    * `yaml_parser_fetch_next_token`: The core dispatcher for identifying and creating different token types.
    * Functions starting with `yaml_parser_fetch_`:  These are clearly responsible for recognizing specific YAML constructs and generating the corresponding tokens. For example, `yaml_parser_fetch_stream_start` creates a `yaml_STREAM_START_TOKEN`.
    * Functions like `cache`, `skip`, `read`, `read_line`: These are low-level buffer management functions.
    * Functions like `yaml_parser_roll_indent`, `yaml_parser_unroll_indent`:  These handle indentation, crucial for block structures in YAML.
    * Functions involving `simple_keys`: This relates to YAML's concept of implicit keys.

6. **Infer Go Feature Implementation:** Based on the tokenization process and the library's name (`gopkg.in/yaml.v2`), it's clear that this code implements a **lexer** or **scanner** for the YAML language. This is a standard component of any parser.

7. **Code Example (Conceptual):** Since the code doesn't provide a direct entry point for using the scanner, and it's deeply integrated into a larger parsing process, a direct "runnable" example is difficult within this snippet alone. Instead, I focus on demonstrating the *concept* of the scanner by showing how different YAML input would be transformed into a sequence of tokens. I choose simple examples to illustrate basic token types like `STREAM-START`, `SCALAR`, `BLOCK-SEQUENCE-START`, etc. I provide both the YAML input and the expected token output.

8. **Command-Line Arguments:** I carefully review the code and notice *no* direct handling of command-line arguments. This makes sense as this is a library component, not a standalone executable.

9. **Common Mistakes:**  Thinking about how a *user* of a YAML library might interact with the *results* of this scanner, I identify potential pitfalls:
    * **Assuming specific token order:** Users shouldn't rely on the *exact* sequence of tokens for complex YAML structures, as the scanner might have some flexibility.
    * **Misinterpreting "KEY" tokens:**  Understanding the difference between explicit (`? key:`) and implicit (`key:`) keys is important.

10. **Summarize Functionality (Part 1):**  I consolidate my understanding into a concise summary, focusing on the core task of transforming YAML text into a stream of tokens for further processing by a parser.

11. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, addressing all parts of the prompt. I use clear and concise language, avoiding jargon where possible, and providing concrete examples. I make sure to explicitly state when something is an inference or an educated guess based on the code.

This iterative process of scanning, analyzing, connecting, and synthesizing information allows me to understand the functionality of the provided code snippet and address the specific requirements of the prompt. The key is to break down the problem into smaller, manageable parts and then integrate the findings into a coherent explanation.
## 功能归纳：go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/scannerc.go (第1部分)

**这个Go语言文件的主要功能是实现 YAML 规范中的** **扫描器 (Scanner)**。

**具体来说，它的功能是：**

1. **将输入的 YAML 文本流转换成一系列的词法单元 (Tokens)**。 这些 Tokens 是构成 YAML 结构的基本 building blocks，例如：
    *  流的开始和结束 (`STREAM-START`, `STREAM-END`)
    *  指令 (`VERSION-DIRECTIVE`, `TAG-DIRECTIVE`)
    *  文档的开始和结束 (`DOCUMENT-START`, `DOCUMENT-END`)
    *  块和流集合的开始和结束 (`BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START`, `FLOW-SEQUENCE-START`, `FLOW-MAPPING-START`, `BLOCK-END`, `FLOW-SEQUENCE-END`, `FLOW-MAPPING-END`)
    *  条目 (`BLOCK-ENTRY`, `FLOW-ENTRY`)
    *  键和值的指示符 (`KEY`, `VALUE`)
    *  别名和锚点 (`ALIAS`, `ANCHOR`)
    *  标签 (`TAG`)
    *  标量值 (`SCALAR`)

2. **识别并处理 YAML 的各种语法元素**，例如指令、文档分隔符、不同类型的集合（序列和映射）、标量以及它们的样式（如单引号、双引号、字面量等）。

3. **维护扫描过程中的状态**，例如当前的缩进级别、是否处于流上下文中，以及潜在的简单键。

4. **处理输入流的缓冲**，确保可以读取足够的字符来识别下一个 Token。

5. **检测并报告扫描过程中的错误**，例如遇到无法识别的字符或语法错误。

**总而言之，这个文件的核心职责是将原始的 YAML 文本转化为结构化的 Token 流，为后续的解析器 (Parser) 提供输入，以便构建 YAML 的抽象语法树。**

---

接下来是针对你提出的其他问题的详细分析：

**它是什么go语言功能的实现？请用go代码举例说明**

这个文件主要实现了 **词法分析 (Lexical Analysis)** 或 **扫描 (Scanning)** 功能。在编译器或解释器设计中，扫描器负责将输入的字符序列分解成有意义的词法单元（Token）。

**Go 代码举例说明（概念性）：**

由于这部分代码是 YAML 解析器内部的组件，直接调用它进行演示比较复杂。但是，我们可以用一个简化的例子来说明扫描器的功能。

**假设输入 YAML 字符串：**

```yaml
name: Alice
age: 30
```

**假设的扫描器输出的 Token 序列（简化）：**

```
STREAM-START(utf-8)
BLOCK-MAPPING-START
KEY
SCALAR("name", plain)
VALUE
SCALAR("Alice", plain)
KEY
SCALAR("age", plain)
VALUE
SCALAR("30", plain)
BLOCK-END
STREAM-END
```

**解释：**

* `STREAM-START`: 表示 YAML 流的开始。
* `BLOCK-MAPPING-START`: 表示一个块映射的开始。
* `KEY`: 表示一个键。
* `SCALAR("name", plain)`: 表示一个标量值 "name"，样式为 plain (无引号)。
* `VALUE`: 表示一个值。
* `SCALAR("Alice", plain)`: 表示一个标量值 "Alice"，样式为 plain。
* ... 以此类推。
* `BLOCK-END`: 表示块映射的结束。
* `STREAM-END`: 表示 YAML 流的结束。

**注意：**  这只是一个简化的例子。实际的 `scannerc.go` 会生成更详细的 Token 信息，并且处理更复杂的 YAML 结构。

**如果涉及代码推理，需要带上假设的输入与输出**

上面的例子已经展示了代码推理的概念。  `scannerc.go` 的核心逻辑就是根据输入的字符序列（假设的 YAML 字符串），识别出符合 YAML 语法规则的模式，并将其转换成相应的 Token。

**假设输入 YAML 片段：**

```yaml
- item1
- item2
```

**推理出的 Token 序列：**

```
BLOCK-SEQUENCE-START
BLOCK-ENTRY
SCALAR("item1", plain)
BLOCK-ENTRY
SCALAR("item2", plain)
BLOCK-END
```

**解释：**

扫描器识别到 `-` 开头的行，并且后续是文本，因此推断这是一个块序列 (`BLOCK-SEQUENCE-START`)，每行一个条目 (`BLOCK-ENTRY`)，条目的内容是标量 (`SCALAR`)。

**如果涉及命令行参数的具体处理，请详细介绍一下**

**这个 `scannerc.go` 文件本身并不直接处理命令行参数。**  它是 `gopkg.in/yaml.v2` 库内部的组成部分，负责底层的 YAML 扫描工作。

通常，使用 `gopkg.in/yaml.v2` 库的应用程序会读取 YAML 文件或字符串作为输入，然后调用库提供的解析函数，这些函数内部会使用扫描器进行词法分析。

例如，一个使用 `gopkg.in/yaml.v2` 解析 YAML 文件的简单 Go 程序可能如下所示：

```go
package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string `yaml:"name"`
	Age  int    `yaml:"age"`
}

func main() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		panic(err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Name: %s, Age: %d\n", config.Name, config.Age)
}
```

在这个例子中，命令行参数是 `go run main.go`，而 YAML 数据是从 `config.yaml` 文件中读取的。 `yaml.Unmarshal` 函数内部会调用扫描器来处理 `config.yaml` 文件的内容。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明**

虽然 `scannerc.go` 是库的内部实现，使用者不会直接操作它，但理解扫描过程有助于避免一些在使用 `gopkg.in/yaml.v2` 时可能犯的错误：

1. **缩进错误：** YAML 依赖于缩进表示层级关系。 扫描器会根据缩进识别 `BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START`, 和 `BLOCK-END` 等 Token。 错误的缩进会导致扫描器产生意料之外的 Token 序列，最终导致解析错误。

   **错误示例 YAML：**
   ```yaml
   name: Alice
   age:
   30  # 错误：缩进不一致
   ```

   扫描器可能会将 `30` 识别为与 `name` 同级的键，导致解析失败。

2. **未转义的特殊字符：**  在某些情况下，YAML 中的特殊字符（如 `:`、`-`、`#` 等）需要被正确转义才能被识别为普通文本。如果未正确转义，扫描器可能会将其识别为 Token 指示符。

   **错误示例 YAML：**
   ```yaml
   message: This is a # comment  # 错误：# 被识别为注释开始
   ```

   扫描器会将 `# comment` 识别为注释的开始，而不是 `message` 键的值的一部分。

3. **混淆流式和块式集合的语法：**  扫描器会根据 `[]`、`{}` 和缩进来区分流式和块式集合。  错误地混合使用这两种语法可能会导致扫描器产生错误的 Token。

   **错误示例 YAML：**
   ```yaml
   items:
   - item1, item2  # 错误：块序列中使用了流式序列的逗号分隔符
   ```

   扫描器可能会将 `, item2` 识别为 `item1` 标量的一部分，而不是一个新的序列条目。

**功能归纳 (针对第1部分):**

这个 `scannerc.go` 文件的第 1 部分主要 **介绍了 YAML 扫描器的概念和它生成的各种 Token 类型**。它详细列举了每种 Token 的名称和简要描述，并通过一些简单的 YAML 示例展示了扫描器如何将 YAML 文本转换成 Token 序列。 此外，它也开始涉及扫描器实现的一些核心函数，例如缓冲管理 (`cache`, `skip`, `read`) 和基本的 Token 获取 (`yaml_parser_scan`). 这部分为理解后续扫描器的具体实现逻辑奠定了基础。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
package yaml

import (
	"bytes"
	"fmt"
)

// Introduction
// ************
//
// The following notes assume that you are familiar with the YAML specification
// (http://yaml.org/spec/1.2/spec.html).  We mostly follow it, although in
// some cases we are less restrictive that it requires.
//
// The process of transforming a YAML stream into a sequence of events is
// divided on two steps: Scanning and Parsing.
//
// The Scanner transforms the input stream into a sequence of tokens, while the
// parser transform the sequence of tokens produced by the Scanner into a
// sequence of parsing events.
//
// The Scanner is rather clever and complicated. The Parser, on the contrary,
// is a straightforward implementation of a recursive-descendant parser (or,
// LL(1) parser, as it is usually called).
//
// Actually there are two issues of Scanning that might be called "clever", the
// rest is quite straightforward.  The issues are "block collection start" and
// "simple keys".  Both issues are explained below in details.
//
// Here the Scanning step is explained and implemented.  We start with the list
// of all the tokens produced by the Scanner together with short descriptions.
//
// Now, tokens:
//
//      STREAM-START(encoding)          # The stream start.
//      STREAM-END                      # The stream end.
//      VERSION-DIRECTIVE(major,minor)  # The '%YAML' directive.
//      TAG-DIRECTIVE(handle,prefix)    # The '%TAG' directive.
//      DOCUMENT-START                  # '---'
//      DOCUMENT-END                    # '...'
//      BLOCK-SEQUENCE-START            # Indentation increase denoting a block
//      BLOCK-MAPPING-START             # sequence or a block mapping.
//      BLOCK-END                       # Indentation decrease.
//      FLOW-SEQUENCE-START             # '['
//      FLOW-SEQUENCE-END               # ']'
//      BLOCK-SEQUENCE-START            # '{'
//      BLOCK-SEQUENCE-END              # '}'
//      BLOCK-ENTRY                     # '-'
//      FLOW-ENTRY                      # ','
//      KEY                             # '?' or nothing (simple keys).
//      VALUE                           # ':'
//      ALIAS(anchor)                   # '*anchor'
//      ANCHOR(anchor)                  # '&anchor'
//      TAG(handle,suffix)              # '!handle!suffix'
//      SCALAR(value,style)             # A scalar.
//
// The following two tokens are "virtual" tokens denoting the beginning and the
// end of the stream:
//
//      STREAM-START(encoding)
//      STREAM-END
//
// We pass the information about the input stream encoding with the
// STREAM-START token.
//
// The next two tokens are responsible for tags:
//
//      VERSION-DIRECTIVE(major,minor)
//      TAG-DIRECTIVE(handle,prefix)
//
// Example:
//
//      %YAML   1.1
//      %TAG    !   !foo
//      %TAG    !yaml!  tag:yaml.org,2002:
//      ---
//
// The correspoding sequence of tokens:
//
//      STREAM-START(utf-8)
//      VERSION-DIRECTIVE(1,1)
//      TAG-DIRECTIVE("!","!foo")
//      TAG-DIRECTIVE("!yaml","tag:yaml.org,2002:")
//      DOCUMENT-START
//      STREAM-END
//
// Note that the VERSION-DIRECTIVE and TAG-DIRECTIVE tokens occupy a whole
// line.
//
// The document start and end indicators are represented by:
//
//      DOCUMENT-START
//      DOCUMENT-END
//
// Note that if a YAML stream contains an implicit document (without '---'
// and '...' indicators), no DOCUMENT-START and DOCUMENT-END tokens will be
// produced.
//
// In the following examples, we present whole documents together with the
// produced tokens.
//
//      1. An implicit document:
//
//          'a scalar'
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          SCALAR("a scalar",single-quoted)
//          STREAM-END
//
//      2. An explicit document:
//
//          ---
//          'a scalar'
//          ...
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          DOCUMENT-START
//          SCALAR("a scalar",single-quoted)
//          DOCUMENT-END
//          STREAM-END
//
//      3. Several documents in a stream:
//
//          'a scalar'
//          ---
//          'another scalar'
//          ---
//          'yet another scalar'
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          SCALAR("a scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("another scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("yet another scalar",single-quoted)
//          STREAM-END
//
// We have already introduced the SCALAR token above.  The following tokens are
// used to describe aliases, anchors, tag, and scalars:
//
//      ALIAS(anchor)
//      ANCHOR(anchor)
//      TAG(handle,suffix)
//      SCALAR(value,style)
//
// The following series of examples illustrate the usage of these tokens:
//
//      1. A recursive sequence:
//
//          &A [ *A ]
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          ANCHOR("A")
//          FLOW-SEQUENCE-START
//          ALIAS("A")
//          FLOW-SEQUENCE-END
//          STREAM-END
//
//      2. A tagged scalar:
//
//          !!float "3.14"  # A good approximation.
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          TAG("!!","float")
//          SCALAR("3.14",double-quoted)
//          STREAM-END
//
//      3. Various scalar styles:
//
//          --- # Implicit empty plain scalars do not produce tokens.
//          --- a plain scalar
//          --- 'a single-quoted scalar'
//          --- "a double-quoted scalar"
//          --- |-
//            a literal scalar
//          --- >-
//            a folded
//            scalar
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          DOCUMENT-START
//          DOCUMENT-START
//          SCALAR("a plain scalar",plain)
//          DOCUMENT-START
//          SCALAR("a single-quoted scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("a double-quoted scalar",double-quoted)
//          DOCUMENT-START
//          SCALAR("a literal scalar",literal)
//          DOCUMENT-START
//          SCALAR("a folded scalar",folded)
//          STREAM-END
//
// Now it's time to review collection-related tokens. We will start with
// flow collections:
//
//      FLOW-SEQUENCE-START
//      FLOW-SEQUENCE-END
//      FLOW-MAPPING-START
//      FLOW-MAPPING-END
//      FLOW-ENTRY
//      KEY
//      VALUE
//
// The tokens FLOW-SEQUENCE-START, FLOW-SEQUENCE-END, FLOW-MAPPING-START, and
// FLOW-MAPPING-END represent the indicators '[', ']', '{', and '}'
// correspondingly.  FLOW-ENTRY represent the ',' indicator.  Finally the
// indicators '?' and ':', which are used for denoting mapping keys and values,
// are represented by the KEY and VALUE tokens.
//
// The following examples show flow collections:
//
//      1. A flow sequence:
//
//          [item 1, item 2, item 3]
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          FLOW-SEQUENCE-START
//          SCALAR("item 1",plain)
//          FLOW-ENTRY
//          SCALAR("item 2",plain)
//          FLOW-ENTRY
//          SCALAR("item 3",plain)
//          FLOW-SEQUENCE-END
//          STREAM-END
//
//      2. A flow mapping:
//
//          {
//              a simple key: a value,  # Note that the KEY token is produced.
//              ? a complex key: another value,
//          }
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          FLOW-MAPPING-START
//          KEY
//          SCALAR("a simple key",plain)
//          VALUE
//          SCALAR("a value",plain)
//          FLOW-ENTRY
//          KEY
//          SCALAR("a complex key",plain)
//          VALUE
//          SCALAR("another value",plain)
//          FLOW-ENTRY
//          FLOW-MAPPING-END
//          STREAM-END
//
// A simple key is a key which is not denoted by the '?' indicator.  Note that
// the Scanner still produce the KEY token whenever it encounters a simple key.
//
// For scanning block collections, the following tokens are used (note that we
// repeat KEY and VALUE here):
//
//      BLOCK-SEQUENCE-START
//      BLOCK-MAPPING-START
//      BLOCK-END
//      BLOCK-ENTRY
//      KEY
//      VALUE
//
// The tokens BLOCK-SEQUENCE-START and BLOCK-MAPPING-START denote indentation
// increase that precedes a block collection (cf. the INDENT token in Python).
// The token BLOCK-END denote indentation decrease that ends a block collection
// (cf. the DEDENT token in Python).  However YAML has some syntax pecularities
// that makes detections of these tokens more complex.
//
// The tokens BLOCK-ENTRY, KEY, and VALUE are used to represent the indicators
// '-', '?', and ':' correspondingly.
//
// The following examples show how the tokens BLOCK-SEQUENCE-START,
// BLOCK-MAPPING-START, and BLOCK-END are emitted by the Scanner:
//
//      1. Block sequences:
//
//          - item 1
//          - item 2
//          -
//            - item 3.1
//            - item 3.2
//          -
//            key 1: value 1
//            key 2: value 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-ENTRY
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 3.1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 3.2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
//      2. Block mappings:
//
//          a simple key: a value   # The KEY token is produced here.
//          ? a complex key
//          : another value
//          a mapping:
//            key 1: value 1
//            key 2: value 2
//          a sequence:
//            - item 1
//            - item 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("a simple key",plain)
//          VALUE
//          SCALAR("a value",plain)
//          KEY
//          SCALAR("a complex key",plain)
//          VALUE
//          SCALAR("another value",plain)
//          KEY
//          SCALAR("a mapping",plain)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          KEY
//          SCALAR("a sequence",plain)
//          VALUE
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
// YAML does not always require to start a new block collection from a new
// line.  If the current line contains only '-', '?', and ':' indicators, a new
// block collection may start at the current line.  The following examples
// illustrate this case:
//
//      1. Collections in a sequence:
//
//          - - item 1
//            - item 2
//          - key 1: value 1
//            key 2: value 2
//          - ? complex key
//            : complex value
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("complex key")
//          VALUE
//          SCALAR("complex value")
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
//      2. Collections in a mapping:
//
//          ? a sequence
//          : - item 1
//            - item 2
//          ? a mapping
//          : key 1: value 1
//            key 2: value 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("a sequence",plain)
//          VALUE
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          KEY
//          SCALAR("a mapping",plain)
//          VALUE
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
// YAML also permits non-indented sequences if they are included into a block
// mapping.  In this case, the token BLOCK-SEQUENCE-START is not produced:
//
//      key:
//      - item 1    # BLOCK-SEQUENCE-START is NOT produced here.
//      - item 2
//
// Tokens:
//
//      STREAM-START(utf-8)
//      BLOCK-MAPPING-START
//      KEY
//      SCALAR("key",plain)
//      VALUE
//      BLOCK-ENTRY
//      SCALAR("item 1",plain)
//      BLOCK-ENTRY
//      SCALAR("item 2",plain)
//      BLOCK-END
//

// Ensure that the buffer contains the required number of characters.
// Return true on success, false on failure (reader error or memory error).
func cache(parser *yaml_parser_t, length int) bool {
	// [Go] This was inlined: !cache(A, B) -> unread < B && !update(A, B)
	return parser.unread >= length || yaml_parser_update_buffer(parser, length)
}

// Advance the buffer pointer.
func skip(parser *yaml_parser_t) {
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
}

func skip_line(parser *yaml_parser_t) {
	if is_crlf(parser.buffer, parser.buffer_pos) {
		parser.mark.index += 2
		parser.mark.column = 0
		parser.mark.line++
		parser.unread -= 2
		parser.buffer_pos += 2
	} else if is_break(parser.buffer, parser.buffer_pos) {
		parser.mark.index++
		parser.mark.column = 0
		parser.mark.line++
		parser.unread--
		parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
	}
}

// Copy a character to a string buffer and advance pointers.
func read(parser *yaml_parser_t, s []byte) []byte {
	w := width(parser.buffer[parser.buffer_pos])
	if w == 0 {
		panic("invalid character sequence")
	}
	if len(s) == 0 {
		s = make([]byte, 0, 32)
	}
	if w == 1 && len(s)+w <= cap(s) {
		s = s[:len(s)+1]
		s[len(s)-1] = parser.buffer[parser.buffer_pos]
		parser.buffer_pos++
	} else {
		s = append(s, parser.buffer[parser.buffer_pos:parser.buffer_pos+w]...)
		parser.buffer_pos += w
	}
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	return s
}

// Copy a line break character to a string buffer and advance pointers.
func read_line(parser *yaml_parser_t, s []byte) []byte {
	buf := parser.buffer
	pos := parser.buffer_pos
	switch {
	case buf[pos] == '\r' && buf[pos+1] == '\n':
		// CR LF . LF
		s = append(s, '\n')
		parser.buffer_pos += 2
		parser.mark.index++
		parser.unread--
	case buf[pos] == '\r' || buf[pos] == '\n':
		// CR|LF . LF
		s = append(s, '\n')
		parser.buffer_pos += 1
	case buf[pos] == '\xC2' && buf[pos+1] == '\x85':
		// NEL . LF
		s = append(s, '\n')
		parser.buffer_pos += 2
	case buf[pos] == '\xE2' && buf[pos+1] == '\x80' && (buf[pos+2] == '\xA8' || buf[pos+2] == '\xA9'):
		// LS|PS . LS|PS
		s = append(s, buf[parser.buffer_pos:pos+3]...)
		parser.buffer_pos += 3
	default:
		return s
	}
	parser.mark.index++
	parser.mark.column = 0
	parser.mark.line++
	parser.unread--
	return s
}

// Get the next token.
func yaml_parser_scan(parser *yaml_parser_t, token *yaml_token_t) bool {
	// Erase the token object.
	*token = yaml_token_t{} // [Go] Is this necessary?

	// No tokens after STREAM-END or error.
	if parser.stream_end_produced || parser.error != yaml_NO_ERROR {
		return true
	}

	// Ensure that the tokens queue contains enough tokens.
	if !parser.token_available {
		if !yaml_parser_fetch_more_tokens(parser) {
			return false
		}
	}

	// Fetch the next token from the queue.
	*token = parser.tokens[parser.tokens_head]
	parser.tokens_head++
	parser.tokens_parsed++
	parser.token_available = false

	if token.typ == yaml_STREAM_END_TOKEN {
		parser.stream_end_produced = true
	}
	return true
}

// Set the scanner error and return false.
func yaml_parser_set_scanner_error(parser *yaml_parser_t, context string, context_mark yaml_mark_t, problem string) bool {
	parser.error = yaml_SCANNER_ERROR
	parser.context = context
	parser.context_mark = context_mark
	parser.problem = problem
	parser.problem_mark = parser.mark
	return false
}

func yaml_parser_set_scanner_tag_error(parser *yaml_parser_t, directive bool, context_mark yaml_mark_t, problem string) bool {
	context := "while parsing a tag"
	if directive {
		context = "while parsing a %TAG directive"
	}
	return yaml_parser_set_scanner_error(parser, context, context_mark, problem)
}

func trace(args ...interface{}) func() {
	pargs := append([]interface{}{"+++"}, args...)
	fmt.Println(pargs...)
	pargs = append([]interface{}{"---"}, args...)
	return func() { fmt.Println(pargs...) }
}

// Ensure that the tokens queue contains at least one token which can be
// returned to the Parser.
func yaml_parser_fetch_more_tokens(parser *yaml_parser_t) bool {
	// While we need more tokens to fetch, do it.
	for {
		// Check if we really need to fetch more tokens.
		need_more_tokens := false

		if parser.tokens_head == len(parser.tokens) {
			// Queue is empty.
			need_more_tokens = true
		} else {
			// Check if any potential simple key may occupy the head position.
			if !yaml_parser_stale_simple_keys(parser) {
				return false
			}

			for i := range parser.simple_keys {
				simple_key := &parser.simple_keys[i]
				if simple_key.possible && simple_key.token_number == parser.tokens_parsed {
					need_more_tokens = true
					break
				}
			}
		}

		// We are finished.
		if !need_more_tokens {
			break
		}
		// Fetch the next token.
		if !yaml_parser_fetch_next_token(parser) {
			return false
		}
	}

	parser.token_available = true
	return true
}

// The dispatcher for token fetchers.
func yaml_parser_fetch_next_token(parser *yaml_parser_t) bool {
	// Ensure that the buffer is initialized.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	// Check if we just started scanning.  Fetch STREAM-START then.
	if !parser.stream_start_produced {
		return yaml_parser_fetch_stream_start(parser)
	}

	// Eat whitespaces and comments until we reach the next token.
	if !yaml_parser_scan_to_next_token(parser) {
		return false
	}

	// Remove obsolete potential simple keys.
	if !yaml_parser_stale_simple_keys(parser) {
		return false
	}

	// Check the indentation level against the current column.
	if !yaml_parser_unroll_indent(parser, parser.mark.column) {
		return false
	}

	// Ensure that the buffer contains at least 4 characters.  4 is the length
	// of the longest indicators ('--- ' and '... ').
	if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
		return false
	}

	// Is it the end of the stream?
	if is_z(parser.buffer, parser.buffer_pos) {
		return yaml_parser_fetch_stream_end(parser)
	}

	// Is it a directive?
	if parser.mark.column == 0 && parser.buffer[parser.buffer_pos] == '%' {
		return yaml_parser_fetch_directive(parser)
	}

	buf := parser.buffer
	pos := parser.buffer_pos

	// Is it the document start indicator?
	if parser.mark.column == 0 && buf[pos] == '-' && buf[pos+1] == '-' && buf[pos+2] == '-' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_START_TOKEN)
	}

	// Is it the document end indicator?
	if parser.mark.column == 0 && buf[pos] == '.' && buf[pos+1] == '.' && buf[pos+2] == '.' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_END_TOKEN)
	}

	// Is it the flow sequence start indicator?
	if buf[pos] == '[' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_SEQUENCE_START_TOKEN)
	}

	// Is it the flow mapping start indicator?
	if parser.buffer[parser.buffer_pos] == '{' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_MAPPING_START_TOKEN)
	}

	// Is it the flow sequence end indicator?
	if parser.buffer[parser.buffer_pos] == ']' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_SEQUENCE_END_TOKEN)
	}

	// Is it the flow mapping end indicator?
	if parser.buffer[parser.buffer_pos] == '}' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_MAPPING_END_TOKEN)
	}

	// Is it the flow entry indicator?
	if parser.buffer[parser.buffer_pos] == ',' {
		return yaml_parser_fetch_flow_entry(parser)
	}

	// Is it the block entry indicator?
	if parser.buffer[parser.buffer_pos] == '-' && is_blankz(parser.buffer, parser.buffer_pos+1) {
		return yaml_parser_fetch_block_entry(parser)
	}

	// Is it the key indicator?
	if parser.buffer[parser.buffer_pos] == '?' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_key(parser)
	}

	// Is it the value indicator?
	if parser.buffer[parser.buffer_pos] == ':' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_value(parser)
	}

	// Is it an alias?
	if parser.buffer[parser.buffer_pos] == '*' {
		return yaml_parser_fetch_anchor(parser, yaml_ALIAS_TOKEN)
	}

	// Is it an anchor?
	if parser.buffer[parser.buffer_pos] == '&' {
		return yaml_parser_fetch_anchor(parser, yaml_ANCHOR_TOKEN)
	}

	// Is it a tag?
	if parser.buffer[parser.buffer_pos] == '!' {
		return yaml_parser_fetch_tag(parser)
	}

	// Is it a literal scalar?
	if parser.buffer[parser.buffer_pos] == '|' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, true)
	}

	// Is it a folded scalar?
	if parser.buffer[parser.buffer_pos] == '>' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, false)
	}

	// Is it a single-quoted scalar?
	if parser.buffer[parser.buffer_pos] == '\'' {
		return yaml_parser_fetch_flow_scalar(parser, true)
	}

	// Is it a double-quoted scalar?
	if parser.buffer[parser.buffer_pos] == '"' {
		return yaml_parser_fetch_flow_scalar(parser, false)
	}

	// Is it a plain scalar?
	//
	// A plain scalar may start with any non-blank characters except
	//
	//      '-', '?', ':', ',', '[', ']', '{', '}',
	//      '#', '&', '*', '!', '|', '>', '\'', '\"',
	//      '%', '@', '`'.
	//
	// In the block context (and, for the '-' indicator, in the flow context
	// too), it may also start with the characters
	//
	//      '-', '?', ':'
	//
	// if it is followed by a non-space character.
	//
	// The last rule is more restrictive than the specification requires.
	// [Go] Make this logic more reasonable.
	//switch parser.buffer[parser.buffer_pos] {
	//case '-', '?', ':', ',', '?', '-', ',', ':', ']', '[', '}', '{', '&', '#', '!', '*', '>', '|', '"', '\'', '@', '%', '-', '`':
	//}
	if !(is_blankz(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == '-' ||
		parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':' ||
		parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == '[' ||
		parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '{' ||
		parser.buffer[parser.buffer_pos] == '}' || parser.buffer[parser.buffer_pos] == '#' ||
		parser.buffer[parser.buffer_pos] == '&' || parser.buffer[parser.buffer_pos] == '*' ||
		parser.buffer[parser.buffer_pos] == '!' || parser.buffer[parser.buffer_pos] == '|' ||
		parser.buffer[parser.buffer_pos] == '>' || parser.buffer[parser.buffer_pos] == '\'' ||
		parser.buffer[parser.buffer_pos] == '"' || parser.buffer[parser.buffer_pos] == '%' ||
		parser.buffer[parser.buffer_pos] == '@' || parser.buffer[parser.buffer_pos] == '`') ||
		(parser.buffer[parser.buffer_pos] == '-' && !is_blank(parser.buffer, parser.buffer_pos+1)) ||
		(parser.flow_level == 0 &&
			(parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':') &&
			!is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_plain_scalar(parser)
	}

	// If we don't determine the token type so far, it is an error.
	return yaml_parser_set_scanner_error(parser,
		"while scanning for the next token", parser.mark,
		"found character that cannot start any token")
}

// Check the list of potential simple keys and remove the positions that
// cannot contain simple keys anymore.
func yaml_parser_stale_simple_keys(parser *yaml_parser_t) bool {
	// Check for a potential simple key for each flow level.
	for i := range parser.simple_keys {
		simple_key := &parser.simple_keys[i]

		// The specification requires that a simple key
		//
		//  - is limited to a single line,
		//  - is shorter than 1024 characters.
		if simple_key.possible && (simple_key.mark.line < parser.mark.line || simple_key.mark.index+1024 < parser.mark.index) {

			// Check if the potential simple key to be removed is required.
			if simple_key.required {
				return yaml_parser_set_scanner_error(parser,
					"while scanning a simple key", simple_key.mark,
					"could not find expected ':'")
			}
			simple_key.possible = false
		}
	}
	return true
}

// Check if a simple key may start at the current position and add it if
// needed.
func yaml_parser_save_simple_key(parser *yaml_parser_t) bool {
	// A simple key is required at the current position if the scanner is in
	// the block context and the current column coincides with the indentation
	// level.

	required := parser.flow_level == 0 && parser.indent == parser.mark.column

	//
	// If the current position may start a simple key, save it.
	//
	if parser.simple_key_allowed {
		simple_key := yaml_simple_key_t{
			possible:     true,
			required:     required,
			token_number: parser.tokens_parsed + (len(parser.tokens) - parser.tokens_head),
		}
		simple_key.mark = parser.mark

		if !yaml_parser_remove_simple_key(parser) {
			return false
		}
		parser.simple_keys[len(parser.simple_keys)-1] = simple_key
	}
	return true
}

// Remove a potential simple key at the current flow level.
func yaml_parser_remove_simple_key(parser *yaml_parser_t) bool {
	i := len(parser.simple_keys) - 1
	if parser.simple_keys[i].possible {
		// If the key is required, it is an error.
		if parser.simple_keys[i].required {
			return yaml_parser_set_scanner_error(parser,
				"while scanning a simple key", parser.simple_keys[i].mark,
				"could not find expected ':'")
		}
	}
	// Remove the key from the stack.
	parser.simple_keys[i].possible = false
	return true
}

// Increase the flow level and resize the simple key list if needed.
func yaml_parser_increase_flow_level(parser *yaml_parser_t) bool {
	// Reset the simple key on the next level.
	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{})

	// Increase the flow level.
	parser.flow_level++
	return true
}

// Decrease the flow level.
func yaml_parser_decrease_flow_level(parser *yaml_parser_t) bool {
	if parser.flow_level > 0 {
		parser.flow_level--
		parser.simple_keys = parser.simple_keys[:len(parser.simple_keys)-1]
	}
	return true
}

// Push the current indentation level to the stack and set the new level
// the current column is greater than the indentation level.  In this case,
// append or insert the specified token into the token queue.
func yaml_parser_roll_indent(parser *yaml_parser_t, column, number int, typ yaml_token_type_t, mark yaml_mark_t) bool {
	// In the flow context, do nothing.
	if parser.flow_level > 0 {
		return true
	}

	if parser.indent < column {
		// Push the current indentation level to the stack and set the new
		// indentation level.
		parser.indents = append(parser.indents, parser.indent)
		parser.indent = column

		// Create a token and insert it into the queue.
		token := yaml_token_t{
			typ:        typ,
			start_mark: mark,
			end_mark:   mark,
		}
		if number > -1 {
			number -= parser.tokens_parsed
		}
		yaml_insert_token(parser, number, &token)
	}
	return true
}

// Pop indentation levels from the indents stack until the current level
// becomes less or equal to the column.  For each indentation level, append
// the BLOCK-END token.
func yaml_parser_unroll_indent(parser *yaml_parser_t, column int) bool {
	// In the flow context, do nothing.
	if parser.flow_level > 0 {
		return true
	}

	// Loop through the indentation levels in the stack.
	for parser.indent > column {
		// Create a token and append it to the queue.
		token := yaml_token_t{
			typ:        yaml_BLOCK_END_TOKEN,
			start_mark: parser.mark,
			end_mark:   parser.mark,
		}
		yaml_insert_token(parser, -1, &token)

		// Pop the indentation level.
		parser.indent = parser.indents[len(parser.indents)-1]
		parser.indents = parser.indents[:len(parser.indents)-1]
	}
	return true
}

// Initialize the scanner and produce the STREAM-START token.
func yaml_parser_fetch_stream_start(parser *yaml_parser_t) bool {

	// Set the initial indentation.
	parser.indent = -1

	// Initialize the simple key stack.
	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{})

	// A simple key is allowed at the beginning of the stream.
	parser.simple_key_allowed = true

	// We have started.
	parser.stream_start_produced = true

	// Create the STREAM-START token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_STREAM_START_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
		encoding:   parser.encoding,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the STREAM-END token and shut down the scanner.
func yaml_parser_fetch_stream_end(parser *yaml_parser_t) bool {

	// Force new line.
	if parser.mark.column != 0 {
		parser.mark.column = 0
		parser.mark.line++
	}

	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Create the STREAM-END token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_STREAM_END_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce a VERSION-DIRECTIVE or TAG-DIRECTIVE token.
func yaml_parser_fetch_directive(parser *yaml_parser_t) bool {
	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Create the YAML-DIRECTIVE or TAG-DIRECTIVE token.
	token := yaml_token_t{}
	if !yaml_parser_scan_directive(parser, &token) {
		return false
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the DOCUMENT-START or DOCUMENT-END token.
func yaml_parser_fetch_document_indicator(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Consume the token.
	start_mark := parser.mark

	skip(parser)
	skip(parser)
	skip(parser)

	end_mark := parser.mark

	// Create the DOCUMENT-START or DOCUMENT-END token.
	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the FLOW-SEQUENCE-START or FLOW-MAPPING-START token.
func yaml_parser_fetch_flow_collection_start(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// The indicators '[' and '{' may start a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// Increase the flow level.
	if !yaml_parser_increase_flow_level(parser) {
		return false
	}

	// A simple key may follow the indicators '[' and '{'.
	parser.simple_key_allowed = true

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the FLOW-SEQUENCE-START of FLOW-MAPPING-START token.
	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the
"""




```