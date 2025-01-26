Response:
我的思考过程如下：

1. **理解目标:** 目标是分析给定的 Go 代码片段，这个片段是 TOML 解析器的一部分。需要提取其功能，可能的 Go 功能实现方式，代码推理（带输入输出），命令行参数处理，以及使用者容易犯的错误。

2. **代码概览:**  快速浏览代码，识别关键结构体和函数。我看到了 `parser` 结构体，它包含解析所需的状态信息（例如，解析结果 `mapping`，类型信息 `types`，词法分析器 `lx` 等）。`parse` 函数是入口点，`topLevel` 处理顶层元素，`value` 处理值的解析，`setValue` 设置解析结果，`setType` 记录类型信息等等。

3. **功能分解:**  逐个分析关键函数的功能：
    * **`parse(data string)`:**  这是主要的解析入口。它初始化 `parser` 结构体，然后循环调用 `p.next()` 获取 token，并根据 token 类型调用不同的处理函数 (`topLevel`)。循环在遇到 `itemEOF` 时结束。  可以推断这是实现了将 TOML 字符串解析成 Go 数据结构的功能。
    * **`topLevel(item item)`:**  处理 TOML 文件的顶层元素，例如表（`[table]`），数组表（`[[array of tables]]`），和键值对。
    * **`value(it item)`:**  将词法分析器返回的 `item` 转换为 Go 的值。  这里处理了字符串、数字、布尔值、日期时间、数组和内联表等 TOML 支持的数据类型。
    * **`setValue(key string, value interface{})`:** 将解析出的键值对存储到 `p.mapping` 中。它还负责处理重复键的错误。
    * **`setType(key string, typ tomlType)`:**  记录每个键对应的值的类型。
    * **其他辅助函数:**  `panicf`, `next`, `expect`, `assertEqual`, `bug`, `keyString`, `establishContext`, `addImplicit`, `removeImplicit`, `isImplicit`, `current`, `stripFirstNewline`, `stripEscapedWhitespace`, `replaceEscapes`, `asciiEscapeToUnicode`, `numUnderscoresOK`, `numPeriodsOK`, `isStringType` 等是辅助解析的工具函数，例如错误处理、token 获取、类型检查、字符串处理等。

4. **Go 功能推断与示例:**
    * **结构体与方法:**  `parser` 结构体封装了解析状态，方法如 `parse`、`topLevel` 操作这些状态。
    * **Map:**  `p.mapping` 是 `map[string]interface{}`，用于存储解析后的 TOML 数据，键是字符串，值可以是各种 Go 类型。
    * **Slice:** `p.ordered` 是 `[]Key`，存储键的顺序。数组在 `value` 函数中用于处理 TOML 数组。
    * **错误处理:**  `panic` 和 `recover` 用于处理解析错误。 `parseError` 类型定义了自定义的错误类型。
    * **字符串处理:**  `strings` 包用于处理字符串，例如去除空白，替换字符等。
    * **类型转换:** `strconv` 包用于字符串到数字的转换。
    * **时间处理:** `time` 包用于解析和处理日期时间。
    * **Unicode:** `unicode/utf8` 用于处理 UTF-8 编码。

    **示例代码:**  演示如何使用 `parse` 函数。

5. **代码推理 (带输入输出):**  选择一个简单的场景进行推理，例如解析一个包含字符串和整数的键值对。

6. **命令行参数处理:**  仔细阅读代码，没有发现直接处理命令行参数的逻辑。词法分析器 `lexer` 的输入是字符串，而不是从命令行读取。

7. **易犯错误:**  根据代码逻辑，考虑使用者可能遇到的问题，例如重复定义键，以及隐式表和显式表的冲突。

8. **组织答案:**  将以上分析组织成结构化的中文答案，包括功能列表、Go 功能示例、代码推理、命令行参数处理和易犯错误点。使用清晰的语言和代码示例。

9. **审阅和完善:** 重新阅读答案，检查是否有遗漏或不清晰的地方，进行修正和补充。 例如，最初我可能没有完全注意到隐式表处理的逻辑，在审阅时需要补充。  同时也要确保代码示例的正确性和可读性。

通过以上步骤，我能够比较全面地分析给定的 Go 代码片段，并用中文清晰地表达出来。

这段 Go 语言代码是 TOML 格式解析器的一部分。它实现了将 TOML 格式的字符串解析成 Go 语言中的数据结构（主要是 `map[string]interface{}`）。

**功能列表:**

1. **解析 TOML 数据:** 核心功能是将 TOML 格式的字符串 `data` 解析成一个 Go 语言的 `map[string]interface{}`，其中键是 TOML 的键，值是对应的 Go 类型的值（字符串、数字、布尔值、日期时间、数组、嵌套的 map）。
2. **处理不同的 TOML 数据类型:**  能够识别和解析 TOML 规范中定义的各种数据类型，包括字符串（普通字符串、多行字符串、原始字符串）、整数、浮点数、布尔值、日期和时间、数组以及内联表。
3. **处理 TOML 表（Tables）:** 解析 `[table]` 形式的表头，并将后续的键值对存储到相应的嵌套 map 中。
4. **处理 TOML 数组表（Array of Tables）:** 解析 `[[array of tables]]` 形式的数组表头，并将后续的键值对存储到 map 的 slice 中。
5. **处理内联表（Inline Tables）:** 解析 `{ key = "value", ... }` 形式的内联表。
6. **处理注释:** 跳过 TOML 文件中的注释行。
7. **记录键的顺序:**  维护一个 `ordered` 列表，记录 TOML 文件中键出现的顺序。这在某些需要保持顺序的应用场景中很有用。
8. **跟踪上下文:** 使用 `context` 变量来跟踪当前解析的表或数组表的路径，以便正确地将键值对添加到嵌套的数据结构中。
9. **错误处理:**  当遇到不符合 TOML 规范的语法时，会抛出 `parseError` 类型的 panic，其中包含了错误发生的行号和相关的上下文信息。
10. **处理转义字符:**  正确解析字符串中的转义字符，例如 `\n`, `\t`, `\uXXXX` 等。
11. **处理数字中的下划线:**  允许数字中使用下划线作为分隔符以提高可读性（例如 `1_000_000`），并在解析时移除。
12. **处理隐式表:**  能够处理隐式创建的表，例如 `a.b.c = 1` 会隐式创建表 `a` 和 `b`。

**Go 语言功能实现示例:**

这段代码主要使用了以下 Go 语言功能：

* **结构体 (Structs):** `parser` 结构体用于存储解析器的状态信息。
* **Map:** `mapping` 字段是一个 `map[string]interface{}`，用于存储解析后的 TOML 数据。`types` 字段用于存储每个键对应的值的类型。
* **Slice:** `ordered` 字段是一个 `[]Key`，用于存储键的顺序。
* **错误处理 (Panic/Recover):** 使用 `panic` 抛出解析错误，并在 `parse` 函数中使用 `recover` 捕获 panic 并返回错误。
* **字符串操作 (strings 包):**  用于字符串的查找、替换、分割等操作，例如处理转义字符、去除空白。
* **类型转换 (strconv 包):**  用于将字符串转换为数字类型（整数、浮点数）。
* **时间处理 (time 包):**  用于解析 TOML 中的日期和时间。
* **Unicode 处理 (unicode/utf8 包):** 用于处理 UTF-8 编码的字符。
* **方法 (Methods):**  与 `parser` 结构体关联的函数，例如 `parse`, `topLevel`, `value` 等。

```go
package main

import (
	"fmt"
	"github.com/BurntSushi/toml" // 假设你已经安装了这个库
)

func main() {
	tomlData := `
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00-08:00

[database]
enabled = true
ports = [ 8000, 8001, 8002 ]
data = [ ["gamma", "delta"], [1, 2] ]

[servers]

  [servers.alpha]
  ip = "10.0.0.1"
  dc = "eqdc10"

  [servers.beta]
  ip = "10.0.0.2"
  dc = "eqdc10"
`

	result, err := toml.Parse(tomlData)
	if err != nil {
		fmt.Println("Error parsing TOML:", err)
		return
	}

	// result 是一个 *toml.Table 类型，你可以通过它的方法访问解析后的数据
	// 例如获取 title
	title, ok := result.GetString("title")
	if ok {
		fmt.Println("Title:", title)
	}

	// 获取 owner.name
	owner, ok := result.Get("owner").(*toml.Table)
	if ok {
		name, _ := owner.GetString("name")
		fmt.Println("Owner Name:", name)
	}

	// 获取 database.ports
	database, _ := result.Get("database").(*toml.Table)
	ports, _ := database.GetArray("ports")
	fmt.Println("Database Ports:", ports)
}
```

**假设的输入与输出（代码推理）:**

**假设输入 (TOML 字符串):**

```toml
name = "example"
count = 123
enabled = true
```

**使用 `parse` 函数后 (假设 `parse` 函数返回 `*parser`):**

```go
// ... (假设 p 是 parse 函数返回的 *parser)

fmt.Println(p.mapping["name"])    // 输出: example
fmt.Println(p.types["name"])      // 输出: string
fmt.Println(p.mapping["count"])   // 输出: 123
fmt.Println(p.types["count"])     // 输出: integer
fmt.Println(p.mapping["enabled"]) // 输出: true
fmt.Println(p.types["enabled"])   // 输出: bool
```

**更复杂的例子：**

**假设输入 (TOML 字符串):**

```toml
[server]
ip = "192.168.1.1"
ports = [ 80, 8080 ]
```

**使用 `parse` 函数后:**

```go
// ... (假设 p 是 parse 函数返回的 *parser)

serverMap, ok := p.mapping["server"].(map[string]interface{})
if ok {
    fmt.Println(serverMap["ip"])    // 输出: 192.168.1.1
    fmt.Println(p.types["server.ip"]) // 输出: string

    portsSlice, ok := serverMap["ports"].([]interface{})
    if ok {
        fmt.Println(portsSlice[0]) // 输出: 80
        fmt.Println(p.types["server.ports"]) // 输出: array
    }
}
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它的输入是一个字符串 `data`，这个字符串通常是从文件读取的，或者在程序中硬编码。如果需要从命令行读取 TOML 数据，你需要编写额外的代码来实现，例如使用 `os` 包读取文件内容，或者使用 `flag` 包解析命令行参数。

**使用者易犯错的点:**

1. **重复定义键:** TOML 规范不允许在同一个表或全局作用域内重复定义相同的键。例如：

   ```toml
   name = "a"
   name = "b"  # 错误：重复定义
   ```

   解析器会抛出错误，提示键已经被定义。

2. **类型不匹配:**  当尝试将 TOML 数据映射到 Go 结构体时，如果类型不匹配，可能会导致错误。例如，如果 TOML 中一个键的值是字符串，但 Go 结构体中对应的字段是整数。

3. **隐式表和显式表的冲突:** 如果先定义了一个隐式表，然后又尝试显式定义同名的表，可能会导致错误。例如：

   ```toml
   a.b = 1

   [a]  # 错误：'a' 已经作为内联表存在
   c = 2
   ```

   或者：

   ```toml
   [a]
   c = 2

   a.b = 1 # 错误：'a' 已经定义为一个表
   ```

   这段代码中的 `setValue` 函数会检查这种情况并抛出 panic。

4. **数组类型不一致:** TOML 数组中的元素必须是相同的类型。例如：

   ```toml
   mixed_array = [ 1, "a" ] # 错误：数组元素类型不一致
   ```

   解析器会在解析 `value` 函数中的数组时进行类型检查。

总而言之，这段代码是 `BurntSushi/toml` 库中负责实际解析 TOML 文本的核心部分，它将 TOML 的文本表示转换为易于在 Go 语言中操作的数据结构。 理解其功能有助于理解 TOML 解析的过程和可能遇到的问题。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/BurntSushi/toml/parse.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package toml

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type parser struct {
	mapping map[string]interface{}
	types   map[string]tomlType
	lx      *lexer

	// A list of keys in the order that they appear in the TOML data.
	ordered []Key

	// the full key for the current hash in scope
	context Key

	// the base key name for everything except hashes
	currentKey string

	// rough approximation of line number
	approxLine int

	// A map of 'key.group.names' to whether they were created implicitly.
	implicits map[string]bool
}

type parseError string

func (pe parseError) Error() string {
	return string(pe)
}

func parse(data string) (p *parser, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(parseError); ok {
				return
			}
			panic(r)
		}
	}()

	p = &parser{
		mapping:   make(map[string]interface{}),
		types:     make(map[string]tomlType),
		lx:        lex(data),
		ordered:   make([]Key, 0),
		implicits: make(map[string]bool),
	}
	for {
		item := p.next()
		if item.typ == itemEOF {
			break
		}
		p.topLevel(item)
	}

	return p, nil
}

func (p *parser) panicf(format string, v ...interface{}) {
	msg := fmt.Sprintf("Near line %d (last key parsed '%s'): %s",
		p.approxLine, p.current(), fmt.Sprintf(format, v...))
	panic(parseError(msg))
}

func (p *parser) next() item {
	it := p.lx.nextItem()
	if it.typ == itemError {
		p.panicf("%s", it.val)
	}
	return it
}

func (p *parser) bug(format string, v ...interface{}) {
	panic(fmt.Sprintf("BUG: "+format+"\n\n", v...))
}

func (p *parser) expect(typ itemType) item {
	it := p.next()
	p.assertEqual(typ, it.typ)
	return it
}

func (p *parser) assertEqual(expected, got itemType) {
	if expected != got {
		p.bug("Expected '%s' but got '%s'.", expected, got)
	}
}

func (p *parser) topLevel(item item) {
	switch item.typ {
	case itemCommentStart:
		p.approxLine = item.line
		p.expect(itemText)
	case itemTableStart:
		kg := p.next()
		p.approxLine = kg.line

		var key Key
		for ; kg.typ != itemTableEnd && kg.typ != itemEOF; kg = p.next() {
			key = append(key, p.keyString(kg))
		}
		p.assertEqual(itemTableEnd, kg.typ)

		p.establishContext(key, false)
		p.setType("", tomlHash)
		p.ordered = append(p.ordered, key)
	case itemArrayTableStart:
		kg := p.next()
		p.approxLine = kg.line

		var key Key
		for ; kg.typ != itemArrayTableEnd && kg.typ != itemEOF; kg = p.next() {
			key = append(key, p.keyString(kg))
		}
		p.assertEqual(itemArrayTableEnd, kg.typ)

		p.establishContext(key, true)
		p.setType("", tomlArrayHash)
		p.ordered = append(p.ordered, key)
	case itemKeyStart:
		kname := p.next()
		p.approxLine = kname.line
		p.currentKey = p.keyString(kname)

		val, typ := p.value(p.next())
		p.setValue(p.currentKey, val)
		p.setType(p.currentKey, typ)
		p.ordered = append(p.ordered, p.context.add(p.currentKey))
		p.currentKey = ""
	default:
		p.bug("Unexpected type at top level: %s", item.typ)
	}
}

// Gets a string for a key (or part of a key in a table name).
func (p *parser) keyString(it item) string {
	switch it.typ {
	case itemText:
		return it.val
	case itemString, itemMultilineString,
		itemRawString, itemRawMultilineString:
		s, _ := p.value(it)
		return s.(string)
	default:
		p.bug("Unexpected key type: %s", it.typ)
		panic("unreachable")
	}
}

// value translates an expected value from the lexer into a Go value wrapped
// as an empty interface.
func (p *parser) value(it item) (interface{}, tomlType) {
	switch it.typ {
	case itemString:
		return p.replaceEscapes(it.val), p.typeOfPrimitive(it)
	case itemMultilineString:
		trimmed := stripFirstNewline(stripEscapedWhitespace(it.val))
		return p.replaceEscapes(trimmed), p.typeOfPrimitive(it)
	case itemRawString:
		return it.val, p.typeOfPrimitive(it)
	case itemRawMultilineString:
		return stripFirstNewline(it.val), p.typeOfPrimitive(it)
	case itemBool:
		switch it.val {
		case "true":
			return true, p.typeOfPrimitive(it)
		case "false":
			return false, p.typeOfPrimitive(it)
		}
		p.bug("Expected boolean value, but got '%s'.", it.val)
	case itemInteger:
		if !numUnderscoresOK(it.val) {
			p.panicf("Invalid integer %q: underscores must be surrounded by digits",
				it.val)
		}
		val := strings.Replace(it.val, "_", "", -1)
		num, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			// Distinguish integer values. Normally, it'd be a bug if the lexer
			// provides an invalid integer, but it's possible that the number is
			// out of range of valid values (which the lexer cannot determine).
			// So mark the former as a bug but the latter as a legitimate user
			// error.
			if e, ok := err.(*strconv.NumError); ok &&
				e.Err == strconv.ErrRange {

				p.panicf("Integer '%s' is out of the range of 64-bit "+
					"signed integers.", it.val)
			} else {
				p.bug("Expected integer value, but got '%s'.", it.val)
			}
		}
		return num, p.typeOfPrimitive(it)
	case itemFloat:
		parts := strings.FieldsFunc(it.val, func(r rune) bool {
			switch r {
			case '.', 'e', 'E':
				return true
			}
			return false
		})
		for _, part := range parts {
			if !numUnderscoresOK(part) {
				p.panicf("Invalid float %q: underscores must be "+
					"surrounded by digits", it.val)
			}
		}
		if !numPeriodsOK(it.val) {
			// As a special case, numbers like '123.' or '1.e2',
			// which are valid as far as Go/strconv are concerned,
			// must be rejected because TOML says that a fractional
			// part consists of '.' followed by 1+ digits.
			p.panicf("Invalid float %q: '.' must be followed "+
				"by one or more digits", it.val)
		}
		val := strings.Replace(it.val, "_", "", -1)
		num, err := strconv.ParseFloat(val, 64)
		if err != nil {
			if e, ok := err.(*strconv.NumError); ok &&
				e.Err == strconv.ErrRange {

				p.panicf("Float '%s' is out of the range of 64-bit "+
					"IEEE-754 floating-point numbers.", it.val)
			} else {
				p.panicf("Invalid float value: %q", it.val)
			}
		}
		return num, p.typeOfPrimitive(it)
	case itemDatetime:
		var t time.Time
		var ok bool
		var err error
		for _, format := range []string{
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05",
			"2006-01-02",
		} {
			t, err = time.ParseInLocation(format, it.val, time.Local)
			if err == nil {
				ok = true
				break
			}
		}
		if !ok {
			p.panicf("Invalid TOML Datetime: %q.", it.val)
		}
		return t, p.typeOfPrimitive(it)
	case itemArray:
		array := make([]interface{}, 0)
		types := make([]tomlType, 0)

		for it = p.next(); it.typ != itemArrayEnd; it = p.next() {
			if it.typ == itemCommentStart {
				p.expect(itemText)
				continue
			}

			val, typ := p.value(it)
			array = append(array, val)
			types = append(types, typ)
		}
		return array, p.typeOfArray(types)
	case itemInlineTableStart:
		var (
			hash         = make(map[string]interface{})
			outerContext = p.context
			outerKey     = p.currentKey
		)

		p.context = append(p.context, p.currentKey)
		p.currentKey = ""
		for it := p.next(); it.typ != itemInlineTableEnd; it = p.next() {
			if it.typ != itemKeyStart {
				p.bug("Expected key start but instead found %q, around line %d",
					it.val, p.approxLine)
			}
			if it.typ == itemCommentStart {
				p.expect(itemText)
				continue
			}

			// retrieve key
			k := p.next()
			p.approxLine = k.line
			kname := p.keyString(k)

			// retrieve value
			p.currentKey = kname
			val, typ := p.value(p.next())
			// make sure we keep metadata up to date
			p.setType(kname, typ)
			p.ordered = append(p.ordered, p.context.add(p.currentKey))
			hash[kname] = val
		}
		p.context = outerContext
		p.currentKey = outerKey
		return hash, tomlHash
	}
	p.bug("Unexpected value type: %s", it.typ)
	panic("unreachable")
}

// numUnderscoresOK checks whether each underscore in s is surrounded by
// characters that are not underscores.
func numUnderscoresOK(s string) bool {
	accept := false
	for _, r := range s {
		if r == '_' {
			if !accept {
				return false
			}
			accept = false
			continue
		}
		accept = true
	}
	return accept
}

// numPeriodsOK checks whether every period in s is followed by a digit.
func numPeriodsOK(s string) bool {
	period := false
	for _, r := range s {
		if period && !isDigit(r) {
			return false
		}
		period = r == '.'
	}
	return !period
}

// establishContext sets the current context of the parser,
// where the context is either a hash or an array of hashes. Which one is
// set depends on the value of the `array` parameter.
//
// Establishing the context also makes sure that the key isn't a duplicate, and
// will create implicit hashes automatically.
func (p *parser) establishContext(key Key, array bool) {
	var ok bool

	// Always start at the top level and drill down for our context.
	hashContext := p.mapping
	keyContext := make(Key, 0)

	// We only need implicit hashes for key[0:-1]
	for _, k := range key[0 : len(key)-1] {
		_, ok = hashContext[k]
		keyContext = append(keyContext, k)

		// No key? Make an implicit hash and move on.
		if !ok {
			p.addImplicit(keyContext)
			hashContext[k] = make(map[string]interface{})
		}

		// If the hash context is actually an array of tables, then set
		// the hash context to the last element in that array.
		//
		// Otherwise, it better be a table, since this MUST be a key group (by
		// virtue of it not being the last element in a key).
		switch t := hashContext[k].(type) {
		case []map[string]interface{}:
			hashContext = t[len(t)-1]
		case map[string]interface{}:
			hashContext = t
		default:
			p.panicf("Key '%s' was already created as a hash.", keyContext)
		}
	}

	p.context = keyContext
	if array {
		// If this is the first element for this array, then allocate a new
		// list of tables for it.
		k := key[len(key)-1]
		if _, ok := hashContext[k]; !ok {
			hashContext[k] = make([]map[string]interface{}, 0, 5)
		}

		// Add a new table. But make sure the key hasn't already been used
		// for something else.
		if hash, ok := hashContext[k].([]map[string]interface{}); ok {
			hashContext[k] = append(hash, make(map[string]interface{}))
		} else {
			p.panicf("Key '%s' was already created and cannot be used as "+
				"an array.", keyContext)
		}
	} else {
		p.setValue(key[len(key)-1], make(map[string]interface{}))
	}
	p.context = append(p.context, key[len(key)-1])
}

// setValue sets the given key to the given value in the current context.
// It will make sure that the key hasn't already been defined, account for
// implicit key groups.
func (p *parser) setValue(key string, value interface{}) {
	var tmpHash interface{}
	var ok bool

	hash := p.mapping
	keyContext := make(Key, 0)
	for _, k := range p.context {
		keyContext = append(keyContext, k)
		if tmpHash, ok = hash[k]; !ok {
			p.bug("Context for key '%s' has not been established.", keyContext)
		}
		switch t := tmpHash.(type) {
		case []map[string]interface{}:
			// The context is a table of hashes. Pick the most recent table
			// defined as the current hash.
			hash = t[len(t)-1]
		case map[string]interface{}:
			hash = t
		default:
			p.bug("Expected hash to have type 'map[string]interface{}', but "+
				"it has '%T' instead.", tmpHash)
		}
	}
	keyContext = append(keyContext, key)

	if _, ok := hash[key]; ok {
		// Typically, if the given key has already been set, then we have
		// to raise an error since duplicate keys are disallowed. However,
		// it's possible that a key was previously defined implicitly. In this
		// case, it is allowed to be redefined concretely. (See the
		// `tests/valid/implicit-and-explicit-after.toml` test in `toml-test`.)
		//
		// But we have to make sure to stop marking it as an implicit. (So that
		// another redefinition provokes an error.)
		//
		// Note that since it has already been defined (as a hash), we don't
		// want to overwrite it. So our business is done.
		if p.isImplicit(keyContext) {
			p.removeImplicit(keyContext)
			return
		}

		// Otherwise, we have a concrete key trying to override a previous
		// key, which is *always* wrong.
		p.panicf("Key '%s' has already been defined.", keyContext)
	}
	hash[key] = value
}

// setType sets the type of a particular value at a given key.
// It should be called immediately AFTER setValue.
//
// Note that if `key` is empty, then the type given will be applied to the
// current context (which is either a table or an array of tables).
func (p *parser) setType(key string, typ tomlType) {
	keyContext := make(Key, 0, len(p.context)+1)
	for _, k := range p.context {
		keyContext = append(keyContext, k)
	}
	if len(key) > 0 { // allow type setting for hashes
		keyContext = append(keyContext, key)
	}
	p.types[keyContext.String()] = typ
}

// addImplicit sets the given Key as having been created implicitly.
func (p *parser) addImplicit(key Key) {
	p.implicits[key.String()] = true
}

// removeImplicit stops tagging the given key as having been implicitly
// created.
func (p *parser) removeImplicit(key Key) {
	p.implicits[key.String()] = false
}

// isImplicit returns true if the key group pointed to by the key was created
// implicitly.
func (p *parser) isImplicit(key Key) bool {
	return p.implicits[key.String()]
}

// current returns the full key name of the current context.
func (p *parser) current() string {
	if len(p.currentKey) == 0 {
		return p.context.String()
	}
	if len(p.context) == 0 {
		return p.currentKey
	}
	return fmt.Sprintf("%s.%s", p.context, p.currentKey)
}

func stripFirstNewline(s string) string {
	if len(s) == 0 || s[0] != '\n' {
		return s
	}
	return s[1:]
}

func stripEscapedWhitespace(s string) string {
	esc := strings.Split(s, "\\\n")
	if len(esc) > 1 {
		for i := 1; i < len(esc); i++ {
			esc[i] = strings.TrimLeftFunc(esc[i], unicode.IsSpace)
		}
	}
	return strings.Join(esc, "")
}

func (p *parser) replaceEscapes(str string) string {
	var replaced []rune
	s := []byte(str)
	r := 0
	for r < len(s) {
		if s[r] != '\\' {
			c, size := utf8.DecodeRune(s[r:])
			r += size
			replaced = append(replaced, c)
			continue
		}
		r += 1
		if r >= len(s) {
			p.bug("Escape sequence at end of string.")
			return ""
		}
		switch s[r] {
		default:
			p.bug("Expected valid escape code after \\, but got %q.", s[r])
			return ""
		case 'b':
			replaced = append(replaced, rune(0x0008))
			r += 1
		case 't':
			replaced = append(replaced, rune(0x0009))
			r += 1
		case 'n':
			replaced = append(replaced, rune(0x000A))
			r += 1
		case 'f':
			replaced = append(replaced, rune(0x000C))
			r += 1
		case 'r':
			replaced = append(replaced, rune(0x000D))
			r += 1
		case '"':
			replaced = append(replaced, rune(0x0022))
			r += 1
		case '\\':
			replaced = append(replaced, rune(0x005C))
			r += 1
		case 'u':
			// At this point, we know we have a Unicode escape of the form
			// `uXXXX` at [r, r+5). (Because the lexer guarantees this
			// for us.)
			escaped := p.asciiEscapeToUnicode(s[r+1 : r+5])
			replaced = append(replaced, escaped)
			r += 5
		case 'U':
			// At this point, we know we have a Unicode escape of the form
			// `uXXXX` at [r, r+9). (Because the lexer guarantees this
			// for us.)
			escaped := p.asciiEscapeToUnicode(s[r+1 : r+9])
			replaced = append(replaced, escaped)
			r += 9
		}
	}
	return string(replaced)
}

func (p *parser) asciiEscapeToUnicode(bs []byte) rune {
	s := string(bs)
	hex, err := strconv.ParseUint(strings.ToLower(s), 16, 32)
	if err != nil {
		p.bug("Could not parse '%s' as a hexadecimal number, but the "+
			"lexer claims it's OK: %s", s, err)
	}
	if !utf8.ValidRune(rune(hex)) {
		p.panicf("Escaped character '\\u%s' is not valid UTF-8.", s)
	}
	return rune(hex)
}

func isStringType(ty itemType) bool {
	return ty == itemString || ty == itemMultilineString ||
		ty == itemRawString || ty == itemRawMultilineString
}

"""



```