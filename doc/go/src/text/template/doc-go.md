Response:
我的目标是理解并总结 `go/src/text/template/doc.go` 文件的功能，并给出相应的代码示例和使用注意事项。

**1. 理解文件内容:**

仔细阅读文件中的注释，特别是 `Package template` 部分的描述。  可以发现这个文件实际上是 `text/template` 包的文档，它详细介绍了模板引擎的功能、语法和用法。

**2. 识别核心功能:**

根据文档，模板引擎的核心功能是：

* **数据驱动的文本生成:**  通过将模板应用于数据结构来生成文本输出。
* **动作 (Actions):**  使用 `{{` 和 `}}` 分隔的特殊指令，用于数据评估、控制流等。
* **参数 (Arguments):**  模板中使用的简单值，可以是常量、变量、字段、键、方法或函数。
* **管道 (Pipelines):**  命令序列，用于处理数据，并将结果传递给下一个命令。
* **变量 (Variables):**  用于存储管道结果并在模板中使用。
* **函数 (Functions):**  预定义的或用户自定义的函数，可以在模板中调用。
* **关联模板 (Associated templates):**  允许一个模板调用其他模板，实现代码复用。
* **嵌套模板定义 (Nested template definitions):**  允许在主模板中定义子模板。

**3. 总结功能点:**

基于上述理解，我可以总结出以下功能点：

* **模板解析与执行:**  将模板字符串解析成可执行的结构，并根据提供的数据执行模板生成文本。
* **数据访问:**  通过点号 `.` 访问当前上下文的数据（称为 "dot"），以及通过字段名或键名访问数据结构的成员。
* **控制流:**  提供 `if`、`else`、`range`、`with` 等控制结构，用于条件判断和循环迭代。
* **变量赋值与使用:**  允许在模板中声明和使用变量。
* **函数调用:**  支持调用预定义的全局函数和用户自定义的函数。
* **模板组合与复用:**  通过 `template` 和 `block` 动作实现模板的组合和复用。
* **空白控制:**  提供 `-` 符号来控制输出中的空白字符。
* **注释:**  支持在模板中添加注释。

**4. 代码示例构思:**

根据文档中提到的功能，构思一些能够演示这些功能的 Go 代码示例。  需要包含：

* **基本模板执行:**  展示如何解析和执行一个简单的模板。
* **控制流示例:**  演示 `if`、`range` 和 `with` 的用法。
* **变量使用示例:**  展示如何声明和使用变量。
* **函数调用示例:**  演示如何调用预定义的函数。
* **模板嵌套示例:**  展示如何定义和调用嵌套模板。

**5. 代码编写与测试:**

编写 Go 代码示例，并进行测试，确保代码能够正确运行并产生预期的输出。  在编写代码时，需要考虑：

* **输入数据:**  为每个示例设计合适的输入数据结构。
* **模板字符串:**  编写能够演示特定功能的模板字符串。
* **输出结果:**  预测并验证代码的输出结果。

**6. 推理 Go 语言功能:**

通过文档的描述和代码示例，可以推断出 `text/template` 包是 Go 语言提供的**文本模板引擎**的实现。它允许开发者将数据和模板分离，从而更方便地生成动态文本内容。

**7. 命令行参数处理:**

文档本身没有涉及到命令行参数的处理。`text/template` 包本身专注于模板的解析和执行，不负责处理命令行参数。  命令行参数的处理通常需要在调用模板引擎的应用程序中进行。

**8. 易犯错误点分析:**

根据文档内容和自身经验，思考用户在使用 `text/template` 时可能犯的错误：

* **点号 `.` 的理解:**  容易混淆 `.` 的含义，尤其是在嵌套的控制结构中。
* **变量作用域:**  不清楚变量的作用域，导致变量访问错误。
* **函数调用错误:**  参数类型不匹配或函数不存在。
* **模板命名冲突:**  在定义和调用模板时，名称冲突可能导致错误。
* **空白控制理解错误:**  不清楚 `-` 符号的作用范围。
* **HTML 转义:**  在生成 HTML 内容时，没有使用 `html/template` 导致安全问题。

**9. 组织答案:**

将以上思考结果组织成清晰、易懂的中文答案，包括功能列表、代码示例、功能推理、命令行参数说明以及易犯错误点。  在代码示例中，明确指出输入和输出，方便理解。

通过以上思考过程，我可以生成符合要求的答案。


`go/src/text/template/doc.go` 文件是 Go 语言 `text/template` 包的文档注释。它详细描述了该包的功能和使用方法。以下是该文件的主要功能：

**1. 模板解析与执行:**

`text/template` 包实现了数据驱动的文本模板引擎。它的核心功能是将包含特定标记的模板字符串解析成可执行的结构，然后将该结构与数据结构结合，生成文本输出。

**示例代码:**

```go
package main

import (
	"os"
	"text/template"
)

type Person struct {
	Name string
	Age  int
}

func main() {
	tmplStr := "My name is {{.Name}} and I am {{.Age}} years old."
	tmpl, err := template.New("person").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	person := Person{Name: "Alice", Age: 30}
	err = tmpl.Execute(os.Stdout, person)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入:** `Person{Name: "Alice", Age: 30}`

**输出:** `My name is Alice and I am 30 years old.`

**2. 模板动作 (Actions):**

文档详细列举了各种模板动作，这些动作用 `{{` 和 `}}` 包围，用于执行数据评估、控制流程等操作。例如：

* **输出管道值:** `{{.FieldName}}` 或 `{{functionCall .}}`
* **条件判断:** `{{if .Condition}}...{{end}}`, `{{if .Condition}}...{{else}}...{{end}}`
* **循环迭代:** `{{range .Slice}}...{{end}}`, `{{range $index, $element := .Slice}}...{{end}}`
* **包含其他模板:** `{{template "otherTemplate" .Data}}`
* **设置上下文:** `{{with .SubStruct}}...{{end}}`
* **定义模板:** `{{define "templateName"}}...{{end}}`

**示例代码 (演示 `if` 和 `range`):**

```go
package main

import (
	"os"
	"text/template"
)

type Items struct {
	Names []string
}

func main() {
	tmplStr := `{{if .Names}}Items:{{range .Names}}
- {{.}}{{end}}{{else}}No items found.{{end}}`
	tmpl, err := template.New("items").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	items1 := Items{Names: []string{"apple", "banana", "cherry"}}
	err = tmpl.Execute(os.Stdout, items1)
	if err != nil {
		panic(err)
	}

	items2 := Items{}
	err = tmpl.Execute(os.Stdout, items2)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入 1:** `Items{Names: []string{"apple", "banana", "cherry"}}`

**输出 1:**
```
Items:
- apple
- banana
- cherry
```

**假设的输入 2:** `Items{}`

**输出 2:** `No items found.`

**3. 模板参数 (Arguments):**

文档解释了模板中可以使用的参数类型，包括常量、`.` (当前上下文)、变量 (`$variable`)、字段访问 (`.FieldName`)、键访问 (`.KeyName`)、方法调用 (`.Method`) 和函数调用 (`functionName`)。

**示例代码 (演示变量和字段访问):**

```go
package main

import (
	"os"
	"text/template"
)

type Product struct {
	Name  string
	Price float64
}

func main() {
	tmplStr := `{{$p := .}}{{printf "Product: %s, Price: %.2f" $p.Name $p.Price}}`
	tmpl, err := template.New("product").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	product := Product{Name: "Laptop", Price: 1200.50}
	err = tmpl.Execute(os.Stdout, product)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入:** `Product{Name: "Laptop", Price: 1200.50}`

**输出:** `Product: Laptop, Price: 1200.50`

**4. 模板管道 (Pipelines):**

文档描述了管道的概念，允许将一个命令的输出作为下一个命令的输入。

**示例代码 (演示管道):**

```go
package main

import (
	"os"
	"strings"
	"text/template"
)

func toUpper(s string) string {
	return strings.ToUpper(s)
}

func main() {
	funcMap := template.FuncMap{
		"upper": toUpper,
	}
	tmplStr := `{{.| upper}}`
	tmpl, err := template.New("pipeline").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	data := "hello"
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入:** `"hello"`

**输出:** `HELLO`

**5. 模板函数 (Functions):**

文档列出了预定义的全局函数（如 `and`, `call`, `html`, `index`, `len`, `not`, `or`, `print`, `printf`, `println`, `urlquery`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`）以及如何使用 `Funcs` 方法添加自定义函数。

**示例代码 (演示自定义函数):**  见上面的管道示例。

**6. 关联模板和嵌套模板定义:**

文档解释了如何定义和调用关联的模板，以及如何在模板中嵌套定义其他模板。这允许模板的模块化和重用。

**示例代码 (演示嵌套模板):**

```go
package main

import (
	"os"
	"text/template"
)

func main() {
	tmplStr := `{{define "header"}}<h1>{{.Title}}</h1>{{end}}
{{define "content"}}<p>{{.Body}}</p>{{end}}
{{define "page"}}
{{template "header" .}}
{{template "content" .}}
{{end}}
{{template "page" .}}`

	tmpl, err := template.New("page").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	data := map[string]string{"Title": "My Page", "Body": "This is the content."}
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入:** `map[string]string{"Title": "My Page", "Body": "This is the content."}`

**输出:**
```html
<h1>My Page</h1>
<p>This is the content.</p>
```

**该文件是 Go 语言文本模板功能的实现文档，它定义了如何使用 `text/template` 包来生成动态文本。**

**命令行参数的具体处理:**

`text/template` 包本身并不直接处理命令行参数。命令行参数的处理通常在调用模板引擎的应用程序中完成。应用程序会解析命令行参数，并将相关数据传递给模板引擎进行渲染。

例如，一个简单的命令行工具可能会使用 `flag` 包来解析命令行参数，然后将解析后的数据传递给模板进行处理：

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"text/template"
)

func main() {
	name := flag.String("name", "World", "The name to say hello to.")
	flag.Parse()

	tmplStr := "Hello, {{.Name}}!"
	tmpl, err := template.New("greeting").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	data := map[string]string{"Name": *name}
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

在这个例子中，`-name` 是一个命令行参数，`flag` 包负责解析它，然后将其值传递给模板引擎。

**使用者易犯错的点:**

1. **对 `.` (dot) 的理解不透彻:**  `.` 的含义会根据当前的上下文而变化，在不同的控制结构中代表不同的数据。初学者容易混淆。

   **示例:**

   ```go
   package main

   import (
   	"os"
   	"text/template"
   )

   func main() {
   	tmplStr := `{{with .Person}}{{.Name}} is {{.Age}}{{end}}`
   	tmpl, err := template.New("person").Parse(tmplStr)
   	if err != nil {
   		panic(err)
   	}

   	data := map[string]interface{}{
   		"Person": map[string]interface{}{
   			"Name": "Bob",
   			"Age":  40,
   		},
   	}
   	err = tmpl.Execute(os.Stdout, data)
   	if err != nil {
   		panic(err)
   	}
   }
   ```
   在这个例子中，外部的 `.` 代表整个 `data` map，而 `{{with .Person}}` 内部的 `.` 代表 `data["Person"]` 的值。

2. **变量作用域的混淆:**  变量的作用域限定在声明它的控制结构内部。在外部访问会出错。

   **示例:**

   ```go
   package main

   import (
   	"os"
   	"text/template"
   )

   func main() {
   	tmplStr := `{{range .}}{{$name := .}}{{end}}{{$name}}` // 错误：$name 在 range 外部不可访问
   	tmpl, err := template.New("names").Parse(tmplStr)
   	if err != nil {
   		panic(err)
   	}

   	names := []string{"Alice", "Bob"}
   	err = tmpl.Execute(os.Stdout, names)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

3. **函数调用错误:**  调用不存在的函数或传递了错误类型的参数给函数。

   **示例:**

   ```go
   package main

   import (
   	"os"
   	"text/template"
   )

   func main() {
   	tmplStr := `{{undefinedFunc .}}` // 错误：undefinedFunc 未定义
   	tmpl, err := template.New("error").Parse(tmplStr)
   	if err != nil {
   		panic(err)
   	}

   	data := "some data"
   	err = tmpl.Execute(os.Stdout, data)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

4. **HTML 转义问题:**  在使用 `text/template` 生成 HTML 时，需要注意手动进行 HTML 转义以防止跨站脚本攻击。更好的做法是使用 `html/template` 包，它会自动进行转义。

   **示例 (text/template，可能存在安全问题):**

   ```go
   package main

   import (
   	"os"
   	"text/template"
   )

   func main() {
   	tmplStr := `<div>{{.UserInput}}</div>`
   	tmpl, err := template.New("html").Parse(tmplStr)
   	if err != nil {
   		panic(err)
   	}

   	data := map[string]string{"UserInput": "<script>alert('evil')</script>"}
   	err = tmpl.Execute(os.Stdout, data)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

   输出会直接包含 `<script>alert('evil')</script>`，可能导致安全问题。应该使用 `html/template`。

Prompt: 
```
这是路径为go/src/text/template/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package template implements data-driven templates for generating textual output.

To generate HTML output, see [html/template], which has the same interface
as this package but automatically secures HTML output against certain attacks.

Templates are executed by applying them to a data structure. Annotations in the
template refer to elements of the data structure (typically a field of a struct
or a key in a map) to control execution and derive values to be displayed.
Execution of the template walks the structure and sets the cursor, represented
by a period '.' and called "dot", to the value at the current location in the
structure as execution proceeds.

The input text for a template is UTF-8-encoded text in any format.
"Actions"--data evaluations or control structures--are delimited by
"{{" and "}}"; all text outside actions is copied to the output unchanged.

Once parsed, a template may be executed safely in parallel, although if parallel
executions share a Writer the output may be interleaved.

Here is a trivial example that prints "17 items are made of wool".

	type Inventory struct {
		Material string
		Count    uint
	}
	sweaters := Inventory{"wool", 17}
	tmpl, err := template.New("test").Parse("{{.Count}} items are made of {{.Material}}")
	if err != nil { panic(err) }
	err = tmpl.Execute(os.Stdout, sweaters)
	if err != nil { panic(err) }

More intricate examples appear below.

Text and spaces

By default, all text between actions is copied verbatim when the template is
executed. For example, the string " items are made of " in the example above
appears on standard output when the program is run.

However, to aid in formatting template source code, if an action's left
delimiter (by default "{{") is followed immediately by a minus sign and white
space, all trailing white space is trimmed from the immediately preceding text.
Similarly, if the right delimiter ("}}") is preceded by white space and a minus
sign, all leading white space is trimmed from the immediately following text.
In these trim markers, the white space must be present:
"{{- 3}}" is like "{{3}}" but trims the immediately preceding text, while
"{{-3}}" parses as an action containing the number -3.

For instance, when executing the template whose source is

	"{{23 -}} < {{- 45}}"

the generated output would be

	"23<45"

For this trimming, the definition of white space characters is the same as in Go:
space, horizontal tab, carriage return, and newline.

Actions

Here is the list of actions. "Arguments" and "pipelines" are evaluations of
data, defined in detail in the corresponding sections that follow.

*/
//	{{/* a comment */}}
//	{{- /* a comment with white space trimmed from preceding and following text */ -}}
//		A comment; discarded. May contain newlines.
//		Comments do not nest and must start and end at the
//		delimiters, as shown here.
/*

	{{pipeline}}
		The default textual representation (the same as would be
		printed by fmt.Print) of the value of the pipeline is copied
		to the output.

	{{if pipeline}} T1 {{end}}
		If the value of the pipeline is empty, no output is generated;
		otherwise, T1 is executed. The empty values are false, 0, any
		nil pointer or interface value, and any array, slice, map, or
		string of length zero.
		Dot is unaffected.

	{{if pipeline}} T1 {{else}} T0 {{end}}
		If the value of the pipeline is empty, T0 is executed;
		otherwise, T1 is executed. Dot is unaffected.

	{{if pipeline}} T1 {{else if pipeline}} T0 {{end}}
		To simplify the appearance of if-else chains, the else action
		of an if may include another if directly; the effect is exactly
		the same as writing
			{{if pipeline}} T1 {{else}}{{if pipeline}} T0 {{end}}{{end}}

	{{range pipeline}} T1 {{end}}
		The value of the pipeline must be an array, slice, map, iter.Seq,
		iter.Seq2, integer or channel.
		If the value of the pipeline has length zero, nothing is output;
		otherwise, dot is set to the successive elements of the array,
		slice, or map and T1 is executed. If the value is a map and the
		keys are of basic type with a defined order, the elements will be
		visited in sorted key order.

	{{range pipeline}} T1 {{else}} T0 {{end}}
		The value of the pipeline must be an array, slice, map, iter.Seq,
		iter.Seq2, integer or channel.
		If the value of the pipeline has length zero, dot is unaffected and
		T0 is executed; otherwise, dot is set to the successive elements
		of the array, slice, or map and T1 is executed.

	{{break}}
		The innermost {{range pipeline}} loop is ended early, stopping the
		current iteration and bypassing all remaining iterations.

	{{continue}}
		The current iteration of the innermost {{range pipeline}} loop is
		stopped, and the loop starts the next iteration.

	{{template "name"}}
		The template with the specified name is executed with nil data.

	{{template "name" pipeline}}
		The template with the specified name is executed with dot set
		to the value of the pipeline.

	{{block "name" pipeline}} T1 {{end}}
		A block is shorthand for defining a template
			{{define "name"}} T1 {{end}}
		and then executing it in place
			{{template "name" pipeline}}
		The typical use is to define a set of root templates that are
		then customized by redefining the block templates within.

	{{with pipeline}} T1 {{end}}
		If the value of the pipeline is empty, no output is generated;
		otherwise, dot is set to the value of the pipeline and T1 is
		executed.

	{{with pipeline}} T1 {{else}} T0 {{end}}
		If the value of the pipeline is empty, dot is unaffected and T0
		is executed; otherwise, dot is set to the value of the pipeline
		and T1 is executed.

	{{with pipeline}} T1 {{else with pipeline}} T0 {{end}}
		To simplify the appearance of with-else chains, the else action
		of a with may include another with directly; the effect is exactly
		the same as writing
			{{with pipeline}} T1 {{else}}{{with pipeline}} T0 {{end}}{{end}}


Arguments

An argument is a simple value, denoted by one of the following.

	- A boolean, string, character, integer, floating-point, imaginary
	  or complex constant in Go syntax. These behave like Go's untyped
	  constants. Note that, as in Go, whether a large integer constant
	  overflows when assigned or passed to a function can depend on whether
	  the host machine's ints are 32 or 64 bits.
	- The keyword nil, representing an untyped Go nil.
	- The character '.' (period):

		.

	  The result is the value of dot.
	- A variable name, which is a (possibly empty) alphanumeric string
	  preceded by a dollar sign, such as

		$piOver2

	  or

		$

	  The result is the value of the variable.
	  Variables are described below.
	- The name of a field of the data, which must be a struct, preceded
	  by a period, such as

		.Field

	  The result is the value of the field. Field invocations may be
	  chained:

	    .Field1.Field2

	  Fields can also be evaluated on variables, including chaining:

	    $x.Field1.Field2
	- The name of a key of the data, which must be a map, preceded
	  by a period, such as

		.Key

	  The result is the map element value indexed by the key.
	  Key invocations may be chained and combined with fields to any
	  depth:

	    .Field1.Key1.Field2.Key2

	  Although the key must be an alphanumeric identifier, unlike with
	  field names they do not need to start with an upper case letter.
	  Keys can also be evaluated on variables, including chaining:

	    $x.key1.key2
	- The name of a niladic method of the data, preceded by a period,
	  such as

		.Method

	  The result is the value of invoking the method with dot as the
	  receiver, dot.Method(). Such a method must have one return value (of
	  any type) or two return values, the second of which is an error.
	  If it has two and the returned error is non-nil, execution terminates
	  and an error is returned to the caller as the value of Execute.
	  Method invocations may be chained and combined with fields and keys
	  to any depth:

	    .Field1.Key1.Method1.Field2.Key2.Method2

	  Methods can also be evaluated on variables, including chaining:

	    $x.Method1.Field
	- The name of a niladic function, such as

		fun

	  The result is the value of invoking the function, fun(). The return
	  types and values behave as in methods. Functions and function
	  names are described below.
	- A parenthesized instance of one the above, for grouping. The result
	  may be accessed by a field or map key invocation.

		print (.F1 arg1) (.F2 arg2)
		(.StructValuedMethod "arg").Field

Arguments may evaluate to any type; if they are pointers the implementation
automatically indirects to the base type when required.
If an evaluation yields a function value, such as a function-valued
field of a struct, the function is not invoked automatically, but it
can be used as a truth value for an if action and the like. To invoke
it, use the call function, defined below.

Pipelines

A pipeline is a possibly chained sequence of "commands". A command is a simple
value (argument) or a function or method call, possibly with multiple arguments:

	Argument
		The result is the value of evaluating the argument.
	.Method [Argument...]
		The method can be alone or the last element of a chain but,
		unlike methods in the middle of a chain, it can take arguments.
		The result is the value of calling the method with the
		arguments:
			dot.Method(Argument1, etc.)
	functionName [Argument...]
		The result is the value of calling the function associated
		with the name:
			function(Argument1, etc.)
		Functions and function names are described below.

A pipeline may be "chained" by separating a sequence of commands with pipeline
characters '|'. In a chained pipeline, the result of each command is
passed as the last argument of the following command. The output of the final
command in the pipeline is the value of the pipeline.

The output of a command will be either one value or two values, the second of
which has type error. If that second value is present and evaluates to
non-nil, execution terminates and the error is returned to the caller of
Execute.

Variables

A pipeline inside an action may initialize a variable to capture the result.
The initialization has syntax

	$variable := pipeline

where $variable is the name of the variable. An action that declares a
variable produces no output.

Variables previously declared can also be assigned, using the syntax

	$variable = pipeline

If a "range" action initializes a variable, the variable is set to the
successive elements of the iteration. Also, a "range" may declare two
variables, separated by a comma:

	range $index, $element := pipeline

in which case $index and $element are set to the successive values of the
array/slice index or map key and element, respectively. Note that if there is
only one variable, it is assigned the element; this is opposite to the
convention in Go range clauses.

A variable's scope extends to the "end" action of the control structure ("if",
"with", or "range") in which it is declared, or to the end of the template if
there is no such control structure. A template invocation does not inherit
variables from the point of its invocation.

When execution begins, $ is set to the data argument passed to Execute, that is,
to the starting value of dot.

Examples

Here are some example one-line templates demonstrating pipelines and variables.
All produce the quoted word "output":

	{{"\"output\""}}
		A string constant.
	{{`"output"`}}
		A raw string constant.
	{{printf "%q" "output"}}
		A function call.
	{{"output" | printf "%q"}}
		A function call whose final argument comes from the previous
		command.
	{{printf "%q" (print "out" "put")}}
		A parenthesized argument.
	{{"put" | printf "%s%s" "out" | printf "%q"}}
		A more elaborate call.
	{{"output" | printf "%s" | printf "%q"}}
		A longer chain.
	{{with "output"}}{{printf "%q" .}}{{end}}
		A with action using dot.
	{{with $x := "output" | printf "%q"}}{{$x}}{{end}}
		A with action that creates and uses a variable.
	{{with $x := "output"}}{{printf "%q" $x}}{{end}}
		A with action that uses the variable in another action.
	{{with $x := "output"}}{{$x | printf "%q"}}{{end}}
		The same, but pipelined.

Functions

During execution functions are found in two function maps: first in the
template, then in the global function map. By default, no functions are defined
in the template but the Funcs method can be used to add them.

Predefined global functions are named as follows.

	and
		Returns the boolean AND of its arguments by returning the
		first empty argument or the last argument. That is,
		"and x y" behaves as "if x then y else x."
		Evaluation proceeds through the arguments left to right
		and returns when the result is determined.
	call
		Returns the result of calling the first argument, which
		must be a function, with the remaining arguments as parameters.
		Thus "call .X.Y 1 2" is, in Go notation, dot.X.Y(1, 2) where
		Y is a func-valued field, map entry, or the like.
		The first argument must be the result of an evaluation
		that yields a value of function type (as distinct from
		a predefined function such as print). The function must
		return either one or two result values, the second of which
		is of type error. If the arguments don't match the function
		or the returned error value is non-nil, execution stops.
	html
		Returns the escaped HTML equivalent of the textual
		representation of its arguments. This function is unavailable
		in html/template, with a few exceptions.
	index
		Returns the result of indexing its first argument by the
		following arguments. Thus "index x 1 2 3" is, in Go syntax,
		x[1][2][3]. Each indexed item must be a map, slice, or array.
	slice
		slice returns the result of slicing its first argument by the
		remaining arguments. Thus "slice x 1 2" is, in Go syntax, x[1:2],
		while "slice x" is x[:], "slice x 1" is x[1:], and "slice x 1 2 3"
		is x[1:2:3]. The first argument must be a string, slice, or array.
	js
		Returns the escaped JavaScript equivalent of the textual
		representation of its arguments.
	len
		Returns the integer length of its argument.
	not
		Returns the boolean negation of its single argument.
	or
		Returns the boolean OR of its arguments by returning the
		first non-empty argument or the last argument, that is,
		"or x y" behaves as "if x then x else y".
		Evaluation proceeds through the arguments left to right
		and returns when the result is determined.
	print
		An alias for fmt.Sprint
	printf
		An alias for fmt.Sprintf
	println
		An alias for fmt.Sprintln
	urlquery
		Returns the escaped value of the textual representation of
		its arguments in a form suitable for embedding in a URL query.
		This function is unavailable in html/template, with a few
		exceptions.

The boolean functions take any zero value to be false and a non-zero
value to be true.

There is also a set of binary comparison operators defined as
functions:

	eq
		Returns the boolean truth of arg1 == arg2
	ne
		Returns the boolean truth of arg1 != arg2
	lt
		Returns the boolean truth of arg1 < arg2
	le
		Returns the boolean truth of arg1 <= arg2
	gt
		Returns the boolean truth of arg1 > arg2
	ge
		Returns the boolean truth of arg1 >= arg2

For simpler multi-way equality tests, eq (only) accepts two or more
arguments and compares the second and subsequent to the first,
returning in effect

	arg1==arg2 || arg1==arg3 || arg1==arg4 ...

(Unlike with || in Go, however, eq is a function call and all the
arguments will be evaluated.)

The comparison functions work on any values whose type Go defines as
comparable. For basic types such as integers, the rules are relaxed:
size and exact type are ignored, so any integer value, signed or unsigned,
may be compared with any other integer value. (The arithmetic value is compared,
not the bit pattern, so all negative integers are less than all unsigned integers.)
However, as usual, one may not compare an int with a float32 and so on.

Associated templates

Each template is named by a string specified when it is created. Also, each
template is associated with zero or more other templates that it may invoke by
name; such associations are transitive and form a name space of templates.

A template may use a template invocation to instantiate another associated
template; see the explanation of the "template" action above. The name must be
that of a template associated with the template that contains the invocation.

Nested template definitions

When parsing a template, another template may be defined and associated with the
template being parsed. Template definitions must appear at the top level of the
template, much like global variables in a Go program.

The syntax of such definitions is to surround each template declaration with a
"define" and "end" action.

The define action names the template being created by providing a string
constant. Here is a simple example:

	{{define "T1"}}ONE{{end}}
	{{define "T2"}}TWO{{end}}
	{{define "T3"}}{{template "T1"}} {{template "T2"}}{{end}}
	{{template "T3"}}

This defines two templates, T1 and T2, and a third T3 that invokes the other two
when it is executed. Finally it invokes T3. If executed this template will
produce the text

	ONE TWO

By construction, a template may reside in only one association. If it's
necessary to have a template addressable from multiple associations, the
template definition must be parsed multiple times to create distinct *Template
values, or must be copied with [Template.Clone] or [Template.AddParseTree].

Parse may be called multiple times to assemble the various associated templates;
see [ParseFiles], [ParseGlob], [Template.ParseFiles] and [Template.ParseGlob]
for simple ways to parse related templates stored in files.

A template may be executed directly or through [Template.ExecuteTemplate], which executes
an associated template identified by name. To invoke our example above, we
might write,

	err := tmpl.Execute(os.Stdout, "no data needed")
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}

or to invoke a particular template explicitly by name,

	err := tmpl.ExecuteTemplate(os.Stdout, "T2", "no data needed")
	if err != nil {
		log.Fatalf("execution failed: %s", err)
	}

*/
package template

"""



```