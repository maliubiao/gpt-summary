Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The overarching goal is to understand the functionality of the `escape.go` file within the `html/template` package in Go. The prompt specifically asks for a list of functions, their purpose, how they work, and potential pitfalls.

2. **Identify Key Functions:**  Start by scanning the code for function definitions. This immediately highlights functions like `escapeTemplate`, `evalArgs`, and the `funcMap` declaration.

3. **Analyze `escapeTemplate`:**
   - **Signature:** `func escapeTemplate(tmpl *Template, node parse.Node, name string) error` suggests it operates on a template, a node within that template, and the template's name. It returns an error, indicating potential issues during the escaping process.
   - **Core Logic:**  It calls `tmpl.esc.escapeTree`, which hints at a recursive process of analyzing the template's structure. It also checks for errors (`c.err`) and the final state of the escaping process (`c.state`).
   - **Error Handling:** The code explicitly sets `t.escapeErr` and clears `t.Tree` if an error occurs, preventing execution of unsafe templates.
   - **Commitment:**  The call to `tmpl.esc.commit()` suggests that changes are buffered and applied at the end.
   - **Inference:**  The name "escapeTemplate" strongly implies that its function is to ensure the output of templates is safe for HTML context by applying escaping rules.

4. **Analyze `evalArgs`:**
   - **Signature:** `func evalArgs(args ...any) string` suggests it takes a variable number of arguments of any type and returns a string.
   - **Core Logic:** It handles a special case for a single string argument. It then iterates through the arguments, calling `indirectToStringerOrError`, before finally using `fmt.Sprint`.
   - **Inference:** This function seems to prepare arguments for output in templates, potentially by converting them to strings. The "indirectToStringerOrError" suggests it handles pointers and types that implement `String()` or `Error()`.

5. **Analyze `funcMap`:**
   - **Declaration:** `var funcMap = template.FuncMap{...}` clearly indicates this is a map of function names to their implementations.
   - **Contents:** The names of the functions (e.g., `_html_template_attrescaper`, `_html_template_htmlescaper`) strongly suggest that this map defines the various escaping and filtering functions used within the template engine. The prefixes `_html_template_` and suffixes like `escaper` and `filter` are strong cues.
   - **Inference:** This map is likely used by the template engine to access and apply the correct escaping function based on the context.

6. **Analyze `escaper` struct:**
   - **Fields:** The fields like `output`, `derived`, `called`, `actionNodeEdits`, `templateNodeEdits`, and `textNodeEdits` provide insight into the internal state of the escaping process.
   - **Inference:** It manages the context of template calls, tracks derived templates, records edits to the template's AST, and handles potential recursive calls.

7. **Analyze `makeEscaper`:**
   - **Functionality:**  It initializes an `escaper` struct.

8. **Analyze `filterFailsafe`:**
   - **Purpose:**  The comment explains it's used as a placeholder for unsafe values.

9. **Analyze `escape`:**
   - **Core Logic:** This function uses a `switch` statement to handle different types of template nodes (Action, If, Range, Template, Text, etc.). This confirms that the escaping process is done by traversing the template's Abstract Syntax Tree (AST).

10. **Deep Dive into `escapeAction`:**
    - **Purpose:** Handles escaping for action nodes (e.g., `{{ . }}`).
    - **Predefined Escapers:**  The code checks for predefined escapers ("html", "urlquery") and disallows certain uses, highlighting a safety mechanism.
    - **Context-Specific Escaping:** The `switch c.state` demonstrates that the escaping applied depends heavily on the current HTML context (URL, JS, CSS, text, attribute, etc.). It selects different escaping functions from `funcMap` based on the context.
    - **Pipeline Manipulation:** The calls to `e.editActionNode` and the later `ensurePipelineContains` show that the escaping process modifies the template's execution pipeline by inserting calls to the appropriate escaping functions.

11. **Analyze Other `escape*` Functions:**  Quickly go through the other `escape*` functions (e.g., `escapeBranch`, `escapeList`, `escapeTemplate`, `escapeText`) to understand how they handle different parts of the template structure and how they contribute to the overall escaping process. Notice the recursive nature of the escaping process as they call each other.

12. **Analyze `commit`:**
    - **Purpose:**  Applies the accumulated edits to the template.
    - **Key Actions:**  It adds the escaping functions from `funcMap` to the template's function map, adds derived templates, and modifies the AST based on the recorded edits.

13. **Identify Potential Pitfalls (Based on Code):**
    - **Ambiguous Contexts:** The `urlPartUnknown` error in `escapeAction` indicates that placing certain template actions in ambiguous URL contexts can lead to errors.
    - **Branching Contexts:** The `join` function's error handling for branches (`ErrBranchEnd`) highlights the risk of different branches ending in different escaping contexts.
    - **Range Loop Re-entry:** The specific checks within `escapeBranch` for "range" loops indicate that the context must be consistent across loop iterations.
    - **Unquoted Attributes:** The check in `contextAfterText` for characters like `"'<=`` in unquoted attributes reveals a potential vulnerability.
    - **Shared Nodes:** The panics in `editActionNode`, `editTemplateNode`, and `editTextNode` if a node is shared between templates suggests that this isn't a supported scenario and could lead to unexpected behavior.
    - **Incomplete or Empty Templates:** The error message in `escapeTree` points out that calling incomplete templates will result in an error.

14. **Structure the Answer:** Organize the findings into the requested sections: functionality, Go feature implementation, code examples (with assumptions and outputs), command-line arguments (if applicable, and in this case, not directly), and potential pitfalls. Use clear and concise language.

15. **Refine and Review:**  Read through the answer to ensure accuracy, completeness, and clarity. Double-check any assumptions made during the analysis. Ensure the code examples are relevant and illustrate the described functionality.

This systematic approach of identifying key components, analyzing their purpose and interaction, and drawing inferences based on the code's structure and naming conventions helps in understanding the functionality of a complex piece of code like this. Paying attention to error handling and specific checks also provides valuable insights into potential issues and edge cases.
这是 `go/src/html/template/escape.go` 文件的一部分，主要负责 **HTML 模板的上下文感知转义 (Contextual Auto-escaping)**。

更具体地说，它的功能是：

1. **静态分析模板结构：** 它会分析 HTML 模板的抽象语法树 (AST)，理解模板的结构，例如文本节点、动作节点（例如 `{{ . }}`）、条件语句、循环语句和模板调用等。

2. **推断执行上下文：**  根据模板的语法结构，它会尝试推断出每个部分在最终渲染时所处的 HTML 上下文。例如，判断一个动作节点是在 HTML 标签内部、属性值内部、JavaScript 代码内部、CSS 代码内部还是 URL 内部。

3. **自动插入转义函数：**  根据推断出的上下文，它会自动在模板的管道 (pipeline) 中插入合适的转义函数，以确保输出的内容符合该上下文的安全要求，防止跨站脚本攻击 (XSS) 等安全问题。例如，如果在 JavaScript 上下文中，会插入 JavaScript 转义函数；如果在 HTML 属性上下文中，会插入 HTML 属性转义函数。

4. **处理模板调用：**  对于模板调用 `{{ template "name" . }}`，它会跟踪模板之间的调用关系，并确保被调用的模板也在正确的上下文中进行转义。

5. **处理分支和循环：**  对于 `if`、`range` 和 `with` 等控制结构，它会分析所有分支的上下文，并确保它们最终都处于兼容的上下文中。

6. **错误检测：** 如果在分析过程中发现模板的结构可能导致不安全的输出，或者无法确定其上下文，它会返回错误。

**它是什么Go语言功能的实现？**

这部分代码主要实现了 `html/template` 包的核心安全特性：**上下文感知自动转义 (Contextual Auto-escaping)**。这是 Go 语言为了提高 Web 应用安全性而引入的一项重要功能。

**Go代码举例说明：**

假设我们有以下 HTML 模板：

```go
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {

### 提示词
```
这是路径为go/src/html/template/escape.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"fmt"
	"html"
	"internal/godebug"
	"io"
	"maps"
	"regexp"
	"text/template"
	"text/template/parse"
)

// escapeTemplate rewrites the named template, which must be
// associated with t, to guarantee that the output of any of the named
// templates is properly escaped. If no error is returned, then the named templates have
// been modified. Otherwise the named templates have been rendered
// unusable.
func escapeTemplate(tmpl *Template, node parse.Node, name string) error {
	c, _ := tmpl.esc.escapeTree(context{}, node, name, 0)
	var err error
	if c.err != nil {
		err, c.err.Name = c.err, name
	} else if c.state != stateText {
		err = &Error{ErrEndContext, nil, name, 0, fmt.Sprintf("ends in a non-text context: %v", c)}
	}
	if err != nil {
		// Prevent execution of unsafe templates.
		if t := tmpl.set[name]; t != nil {
			t.escapeErr = err
			t.text.Tree = nil
			t.Tree = nil
		}
		return err
	}
	tmpl.esc.commit()
	if t := tmpl.set[name]; t != nil {
		t.escapeErr = escapeOK
		t.Tree = t.text.Tree
	}
	return nil
}

// evalArgs formats the list of arguments into a string. It is equivalent to
// fmt.Sprint(args...), except that it dereferences all pointers.
func evalArgs(args ...any) string {
	// Optimization for simple common case of a single string argument.
	if len(args) == 1 {
		if s, ok := args[0].(string); ok {
			return s
		}
	}
	for i, arg := range args {
		args[i] = indirectToStringerOrError(arg)
	}
	return fmt.Sprint(args...)
}

// funcMap maps command names to functions that render their inputs safe.
var funcMap = template.FuncMap{
	"_html_template_attrescaper":      attrEscaper,
	"_html_template_commentescaper":   commentEscaper,
	"_html_template_cssescaper":       cssEscaper,
	"_html_template_cssvaluefilter":   cssValueFilter,
	"_html_template_htmlnamefilter":   htmlNameFilter,
	"_html_template_htmlescaper":      htmlEscaper,
	"_html_template_jsregexpescaper":  jsRegexpEscaper,
	"_html_template_jsstrescaper":     jsStrEscaper,
	"_html_template_jstmpllitescaper": jsTmplLitEscaper,
	"_html_template_jsvalescaper":     jsValEscaper,
	"_html_template_nospaceescaper":   htmlNospaceEscaper,
	"_html_template_rcdataescaper":    rcdataEscaper,
	"_html_template_srcsetescaper":    srcsetFilterAndEscaper,
	"_html_template_urlescaper":       urlEscaper,
	"_html_template_urlfilter":        urlFilter,
	"_html_template_urlnormalizer":    urlNormalizer,
	"_eval_args_":                     evalArgs,
}

// escaper collects type inferences about templates and changes needed to make
// templates injection safe.
type escaper struct {
	// ns is the nameSpace that this escaper is associated with.
	ns *nameSpace
	// output[templateName] is the output context for a templateName that
	// has been mangled to include its input context.
	output map[string]context
	// derived[c.mangle(name)] maps to a template derived from the template
	// named name templateName for the start context c.
	derived map[string]*template.Template
	// called[templateName] is a set of called mangled template names.
	called map[string]bool
	// xxxNodeEdits are the accumulated edits to apply during commit.
	// Such edits are not applied immediately in case a template set
	// executes a given template in different escaping contexts.
	actionNodeEdits   map[*parse.ActionNode][]string
	templateNodeEdits map[*parse.TemplateNode]string
	textNodeEdits     map[*parse.TextNode][]byte
	// rangeContext holds context about the current range loop.
	rangeContext *rangeContext
}

// rangeContext holds information about the current range loop.
type rangeContext struct {
	outer     *rangeContext // outer loop
	breaks    []context     // context at each break action
	continues []context     // context at each continue action
}

// makeEscaper creates a blank escaper for the given set.
func makeEscaper(n *nameSpace) escaper {
	return escaper{
		n,
		map[string]context{},
		map[string]*template.Template{},
		map[string]bool{},
		map[*parse.ActionNode][]string{},
		map[*parse.TemplateNode]string{},
		map[*parse.TextNode][]byte{},
		nil,
	}
}

// filterFailsafe is an innocuous word that is emitted in place of unsafe values
// by sanitizer functions. It is not a keyword in any programming language,
// contains no special characters, is not empty, and when it appears in output
// it is distinct enough that a developer can find the source of the problem
// via a search engine.
const filterFailsafe = "ZgotmplZ"

// escape escapes a template node.
func (e *escaper) escape(c context, n parse.Node) context {
	switch n := n.(type) {
	case *parse.ActionNode:
		return e.escapeAction(c, n)
	case *parse.BreakNode:
		c.n = n
		e.rangeContext.breaks = append(e.rangeContext.breaks, c)
		return context{state: stateDead}
	case *parse.CommentNode:
		return c
	case *parse.ContinueNode:
		c.n = n
		e.rangeContext.continues = append(e.rangeContext.continues, c)
		return context{state: stateDead}
	case *parse.IfNode:
		return e.escapeBranch(c, &n.BranchNode, "if")
	case *parse.ListNode:
		return e.escapeList(c, n)
	case *parse.RangeNode:
		return e.escapeBranch(c, &n.BranchNode, "range")
	case *parse.TemplateNode:
		return e.escapeTemplate(c, n)
	case *parse.TextNode:
		return e.escapeText(c, n)
	case *parse.WithNode:
		return e.escapeBranch(c, &n.BranchNode, "with")
	}
	panic("escaping " + n.String() + " is unimplemented")
}

var debugAllowActionJSTmpl = godebug.New("jstmpllitinterp")

// escapeAction escapes an action template node.
func (e *escaper) escapeAction(c context, n *parse.ActionNode) context {
	if len(n.Pipe.Decl) != 0 {
		// A local variable assignment, not an interpolation.
		return c
	}
	c = nudge(c)
	// Check for disallowed use of predefined escapers in the pipeline.
	for pos, idNode := range n.Pipe.Cmds {
		node, ok := idNode.Args[0].(*parse.IdentifierNode)
		if !ok {
			// A predefined escaper "esc" will never be found as an identifier in a
			// Chain or Field node, since:
			// - "esc.x ..." is invalid, since predefined escapers return strings, and
			//   strings do not have methods, keys or fields.
			// - "... .esc" is invalid, since predefined escapers are global functions,
			//   not methods or fields of any types.
			// Therefore, it is safe to ignore these two node types.
			continue
		}
		ident := node.Ident
		if _, ok := predefinedEscapers[ident]; ok {
			if pos < len(n.Pipe.Cmds)-1 ||
				c.state == stateAttr && c.delim == delimSpaceOrTagEnd && ident == "html" {
				return context{
					state: stateError,
					err:   errorf(ErrPredefinedEscaper, n, n.Line, "predefined escaper %q disallowed in template", ident),
				}
			}
		}
	}
	s := make([]string, 0, 3)
	switch c.state {
	case stateError:
		return c
	case stateURL, stateCSSDqStr, stateCSSSqStr, stateCSSDqURL, stateCSSSqURL, stateCSSURL:
		switch c.urlPart {
		case urlPartNone:
			s = append(s, "_html_template_urlfilter")
			fallthrough
		case urlPartPreQuery:
			switch c.state {
			case stateCSSDqStr, stateCSSSqStr:
				s = append(s, "_html_template_cssescaper")
			default:
				s = append(s, "_html_template_urlnormalizer")
			}
		case urlPartQueryOrFrag:
			s = append(s, "_html_template_urlescaper")
		case urlPartUnknown:
			return context{
				state: stateError,
				err:   errorf(ErrAmbigContext, n, n.Line, "%s appears in an ambiguous context within a URL", n),
			}
		default:
			panic(c.urlPart.String())
		}
	case stateJS:
		s = append(s, "_html_template_jsvalescaper")
		// A slash after a value starts a div operator.
		c.jsCtx = jsCtxDivOp
	case stateJSDqStr, stateJSSqStr:
		s = append(s, "_html_template_jsstrescaper")
	case stateJSTmplLit:
		s = append(s, "_html_template_jstmpllitescaper")
	case stateJSRegexp:
		s = append(s, "_html_template_jsregexpescaper")
	case stateCSS:
		s = append(s, "_html_template_cssvaluefilter")
	case stateText:
		s = append(s, "_html_template_htmlescaper")
	case stateRCDATA:
		s = append(s, "_html_template_rcdataescaper")
	case stateAttr:
		// Handled below in delim check.
	case stateAttrName, stateTag:
		c.state = stateAttrName
		s = append(s, "_html_template_htmlnamefilter")
	case stateSrcset:
		s = append(s, "_html_template_srcsetescaper")
	default:
		if isComment(c.state) {
			s = append(s, "_html_template_commentescaper")
		} else {
			panic("unexpected state " + c.state.String())
		}
	}
	switch c.delim {
	case delimNone:
		// No extra-escaping needed for raw text content.
	case delimSpaceOrTagEnd:
		s = append(s, "_html_template_nospaceescaper")
	default:
		s = append(s, "_html_template_attrescaper")
	}
	e.editActionNode(n, s)
	return c
}

// ensurePipelineContains ensures that the pipeline ends with the commands with
// the identifiers in s in order. If the pipeline ends with a predefined escaper
// (i.e. "html" or "urlquery"), merge it with the identifiers in s.
func ensurePipelineContains(p *parse.PipeNode, s []string) {
	if len(s) == 0 {
		// Do not rewrite pipeline if we have no escapers to insert.
		return
	}
	// Precondition: p.Cmds contains at most one predefined escaper and the
	// escaper will be present at p.Cmds[len(p.Cmds)-1]. This precondition is
	// always true because of the checks in escapeAction.
	pipelineLen := len(p.Cmds)
	if pipelineLen > 0 {
		lastCmd := p.Cmds[pipelineLen-1]
		if idNode, ok := lastCmd.Args[0].(*parse.IdentifierNode); ok {
			if esc := idNode.Ident; predefinedEscapers[esc] {
				// Pipeline ends with a predefined escaper.
				if len(p.Cmds) == 1 && len(lastCmd.Args) > 1 {
					// Special case: pipeline is of the form {{ esc arg1 arg2 ... argN }},
					// where esc is the predefined escaper, and arg1...argN are its arguments.
					// Convert this into the equivalent form
					// {{ _eval_args_ arg1 arg2 ... argN | esc }}, so that esc can be easily
					// merged with the escapers in s.
					lastCmd.Args[0] = parse.NewIdentifier("_eval_args_").SetTree(nil).SetPos(lastCmd.Args[0].Position())
					p.Cmds = appendCmd(p.Cmds, newIdentCmd(esc, p.Position()))
					pipelineLen++
				}
				// If any of the commands in s that we are about to insert is equivalent
				// to the predefined escaper, use the predefined escaper instead.
				dup := false
				for i, escaper := range s {
					if escFnsEq(esc, escaper) {
						s[i] = idNode.Ident
						dup = true
					}
				}
				if dup {
					// The predefined escaper will already be inserted along with the
					// escapers in s, so do not copy it to the rewritten pipeline.
					pipelineLen--
				}
			}
		}
	}
	// Rewrite the pipeline, creating the escapers in s at the end of the pipeline.
	newCmds := make([]*parse.CommandNode, pipelineLen, pipelineLen+len(s))
	insertedIdents := make(map[string]bool)
	for i := 0; i < pipelineLen; i++ {
		cmd := p.Cmds[i]
		newCmds[i] = cmd
		if idNode, ok := cmd.Args[0].(*parse.IdentifierNode); ok {
			insertedIdents[normalizeEscFn(idNode.Ident)] = true
		}
	}
	for _, name := range s {
		if !insertedIdents[normalizeEscFn(name)] {
			// When two templates share an underlying parse tree via the use of
			// AddParseTree and one template is executed after the other, this check
			// ensures that escapers that were already inserted into the pipeline on
			// the first escaping pass do not get inserted again.
			newCmds = appendCmd(newCmds, newIdentCmd(name, p.Position()))
		}
	}
	p.Cmds = newCmds
}

// predefinedEscapers contains template predefined escapers that are equivalent
// to some contextual escapers. Keep in sync with equivEscapers.
var predefinedEscapers = map[string]bool{
	"html":     true,
	"urlquery": true,
}

// equivEscapers matches contextual escapers to equivalent predefined
// template escapers.
var equivEscapers = map[string]string{
	// The following pairs of HTML escapers provide equivalent security
	// guarantees, since they all escape '\000', '\'', '"', '&', '<', and '>'.
	"_html_template_attrescaper":   "html",
	"_html_template_htmlescaper":   "html",
	"_html_template_rcdataescaper": "html",
	// These two URL escapers produce URLs safe for embedding in a URL query by
	// percent-encoding all the reserved characters specified in RFC 3986 Section
	// 2.2
	"_html_template_urlescaper": "urlquery",
	// These two functions are not actually equivalent; urlquery is stricter as it
	// escapes reserved characters (e.g. '#'), while _html_template_urlnormalizer
	// does not. It is therefore only safe to replace _html_template_urlnormalizer
	// with urlquery (this happens in ensurePipelineContains), but not the otherI've
	// way around. We keep this entry around to preserve the behavior of templates
	// written before Go 1.9, which might depend on this substitution taking place.
	"_html_template_urlnormalizer": "urlquery",
}

// escFnsEq reports whether the two escaping functions are equivalent.
func escFnsEq(a, b string) bool {
	return normalizeEscFn(a) == normalizeEscFn(b)
}

// normalizeEscFn(a) is equal to normalizeEscFn(b) for any pair of names of
// escaper functions a and b that are equivalent.
func normalizeEscFn(e string) string {
	if norm := equivEscapers[e]; norm != "" {
		return norm
	}
	return e
}

// redundantFuncs[a][b] implies that funcMap[b](funcMap[a](x)) == funcMap[a](x)
// for all x.
var redundantFuncs = map[string]map[string]bool{
	"_html_template_commentescaper": {
		"_html_template_attrescaper": true,
		"_html_template_htmlescaper": true,
	},
	"_html_template_cssescaper": {
		"_html_template_attrescaper": true,
	},
	"_html_template_jsregexpescaper": {
		"_html_template_attrescaper": true,
	},
	"_html_template_jsstrescaper": {
		"_html_template_attrescaper": true,
	},
	"_html_template_jstmpllitescaper": {
		"_html_template_attrescaper": true,
	},
	"_html_template_urlescaper": {
		"_html_template_urlnormalizer": true,
	},
}

// appendCmd appends the given command to the end of the command pipeline
// unless it is redundant with the last command.
func appendCmd(cmds []*parse.CommandNode, cmd *parse.CommandNode) []*parse.CommandNode {
	if n := len(cmds); n != 0 {
		last, okLast := cmds[n-1].Args[0].(*parse.IdentifierNode)
		next, okNext := cmd.Args[0].(*parse.IdentifierNode)
		if okLast && okNext && redundantFuncs[last.Ident][next.Ident] {
			return cmds
		}
	}
	return append(cmds, cmd)
}

// newIdentCmd produces a command containing a single identifier node.
func newIdentCmd(identifier string, pos parse.Pos) *parse.CommandNode {
	return &parse.CommandNode{
		NodeType: parse.NodeCommand,
		Args:     []parse.Node{parse.NewIdentifier(identifier).SetTree(nil).SetPos(pos)}, // TODO: SetTree.
	}
}

// nudge returns the context that would result from following empty string
// transitions from the input context.
// For example, parsing:
//
//	`<a href=`
//
// will end in context{stateBeforeValue, attrURL}, but parsing one extra rune:
//
//	`<a href=x`
//
// will end in context{stateURL, delimSpaceOrTagEnd, ...}.
// There are two transitions that happen when the 'x' is seen:
// (1) Transition from a before-value state to a start-of-value state without
//
//	consuming any character.
//
// (2) Consume 'x' and transition past the first value character.
// In this case, nudging produces the context after (1) happens.
func nudge(c context) context {
	switch c.state {
	case stateTag:
		// In `<foo {{.}}`, the action should emit an attribute.
		c.state = stateAttrName
	case stateBeforeValue:
		// In `<foo bar={{.}}`, the action is an undelimited value.
		c.state, c.delim, c.attr = attrStartStates[c.attr], delimSpaceOrTagEnd, attrNone
	case stateAfterName:
		// In `<foo bar {{.}}`, the action is an attribute name.
		c.state, c.attr = stateAttrName, attrNone
	}
	return c
}

// join joins the two contexts of a branch template node. The result is an
// error context if either of the input contexts are error contexts, or if the
// input contexts differ.
func join(a, b context, node parse.Node, nodeName string) context {
	if a.state == stateError {
		return a
	}
	if b.state == stateError {
		return b
	}
	if a.state == stateDead {
		return b
	}
	if b.state == stateDead {
		return a
	}
	if a.eq(b) {
		return a
	}

	c := a
	c.urlPart = b.urlPart
	if c.eq(b) {
		// The contexts differ only by urlPart.
		c.urlPart = urlPartUnknown
		return c
	}

	c = a
	c.jsCtx = b.jsCtx
	if c.eq(b) {
		// The contexts differ only by jsCtx.
		c.jsCtx = jsCtxUnknown
		return c
	}

	// Allow a nudged context to join with an unnudged one.
	// This means that
	//   <p title={{if .C}}{{.}}{{end}}
	// ends in an unquoted value state even though the else branch
	// ends in stateBeforeValue.
	if c, d := nudge(a), nudge(b); !(c.eq(a) && d.eq(b)) {
		if e := join(c, d, node, nodeName); e.state != stateError {
			return e
		}
	}

	return context{
		state: stateError,
		err:   errorf(ErrBranchEnd, node, 0, "{{%s}} branches end in different contexts: %v, %v", nodeName, a, b),
	}
}

// escapeBranch escapes a branch template node: "if", "range" and "with".
func (e *escaper) escapeBranch(c context, n *parse.BranchNode, nodeName string) context {
	if nodeName == "range" {
		e.rangeContext = &rangeContext{outer: e.rangeContext}
	}
	c0 := e.escapeList(c, n.List)
	if nodeName == "range" {
		if c0.state != stateError {
			c0 = joinRange(c0, e.rangeContext)
		}
		e.rangeContext = e.rangeContext.outer
		if c0.state == stateError {
			return c0
		}

		// The "true" branch of a "range" node can execute multiple times.
		// We check that executing n.List once results in the same context
		// as executing n.List twice.
		e.rangeContext = &rangeContext{outer: e.rangeContext}
		c1, _ := e.escapeListConditionally(c0, n.List, nil)
		c0 = join(c0, c1, n, nodeName)
		if c0.state == stateError {
			e.rangeContext = e.rangeContext.outer
			// Make clear that this is a problem on loop re-entry
			// since developers tend to overlook that branch when
			// debugging templates.
			c0.err.Line = n.Line
			c0.err.Description = "on range loop re-entry: " + c0.err.Description
			return c0
		}
		c0 = joinRange(c0, e.rangeContext)
		e.rangeContext = e.rangeContext.outer
		if c0.state == stateError {
			return c0
		}
	}
	c1 := e.escapeList(c, n.ElseList)
	return join(c0, c1, n, nodeName)
}

func joinRange(c0 context, rc *rangeContext) context {
	// Merge contexts at break and continue statements into overall body context.
	// In theory we could treat breaks differently from continues, but for now it is
	// enough to treat them both as going back to the start of the loop (which may then stop).
	for _, c := range rc.breaks {
		c0 = join(c0, c, c.n, "range")
		if c0.state == stateError {
			c0.err.Line = c.n.(*parse.BreakNode).Line
			c0.err.Description = "at range loop break: " + c0.err.Description
			return c0
		}
	}
	for _, c := range rc.continues {
		c0 = join(c0, c, c.n, "range")
		if c0.state == stateError {
			c0.err.Line = c.n.(*parse.ContinueNode).Line
			c0.err.Description = "at range loop continue: " + c0.err.Description
			return c0
		}
	}
	return c0
}

// escapeList escapes a list template node.
func (e *escaper) escapeList(c context, n *parse.ListNode) context {
	if n == nil {
		return c
	}
	for _, m := range n.Nodes {
		c = e.escape(c, m)
		if c.state == stateDead {
			break
		}
	}
	return c
}

// escapeListConditionally escapes a list node but only preserves edits and
// inferences in e if the inferences and output context satisfy filter.
// It returns the best guess at an output context, and the result of the filter
// which is the same as whether e was updated.
func (e *escaper) escapeListConditionally(c context, n *parse.ListNode, filter func(*escaper, context) bool) (context, bool) {
	e1 := makeEscaper(e.ns)
	e1.rangeContext = e.rangeContext
	// Make type inferences available to f.
	maps.Copy(e1.output, e.output)
	c = e1.escapeList(c, n)
	ok := filter != nil && filter(&e1, c)
	if ok {
		// Copy inferences and edits from e1 back into e.
		maps.Copy(e.output, e1.output)
		maps.Copy(e.derived, e1.derived)
		maps.Copy(e.called, e1.called)
		for k, v := range e1.actionNodeEdits {
			e.editActionNode(k, v)
		}
		for k, v := range e1.templateNodeEdits {
			e.editTemplateNode(k, v)
		}
		for k, v := range e1.textNodeEdits {
			e.editTextNode(k, v)
		}
	}
	return c, ok
}

// escapeTemplate escapes a {{template}} call node.
func (e *escaper) escapeTemplate(c context, n *parse.TemplateNode) context {
	c, name := e.escapeTree(c, n, n.Name, n.Line)
	if name != n.Name {
		e.editTemplateNode(n, name)
	}
	return c
}

// escapeTree escapes the named template starting in the given context as
// necessary and returns its output context.
func (e *escaper) escapeTree(c context, node parse.Node, name string, line int) (context, string) {
	// Mangle the template name with the input context to produce a reliable
	// identifier.
	dname := c.mangle(name)
	e.called[dname] = true
	if out, ok := e.output[dname]; ok {
		// Already escaped.
		return out, dname
	}
	t := e.template(name)
	if t == nil {
		// Two cases: The template exists but is empty, or has never been mentioned at
		// all. Distinguish the cases in the error messages.
		if e.ns.set[name] != nil {
			return context{
				state: stateError,
				err:   errorf(ErrNoSuchTemplate, node, line, "%q is an incomplete or empty template", name),
			}, dname
		}
		return context{
			state: stateError,
			err:   errorf(ErrNoSuchTemplate, node, line, "no such template %q", name),
		}, dname
	}
	if dname != name {
		// Use any template derived during an earlier call to escapeTemplate
		// with different top level templates, or clone if necessary.
		dt := e.template(dname)
		if dt == nil {
			dt = template.New(dname)
			dt.Tree = &parse.Tree{Name: dname, Root: t.Root.CopyList()}
			e.derived[dname] = dt
		}
		t = dt
	}
	return e.computeOutCtx(c, t), dname
}

// computeOutCtx takes a template and its start context and computes the output
// context while storing any inferences in e.
func (e *escaper) computeOutCtx(c context, t *template.Template) context {
	// Propagate context over the body.
	c1, ok := e.escapeTemplateBody(c, t)
	if !ok {
		// Look for a fixed point by assuming c1 as the output context.
		if c2, ok2 := e.escapeTemplateBody(c1, t); ok2 {
			c1, ok = c2, true
		}
		// Use c1 as the error context if neither assumption worked.
	}
	if !ok && c1.state != stateError {
		return context{
			state: stateError,
			err:   errorf(ErrOutputContext, t.Tree.Root, 0, "cannot compute output context for template %s", t.Name()),
		}
	}
	return c1
}

// escapeTemplateBody escapes the given template assuming the given output
// context, and returns the best guess at the output context and whether the
// assumption was correct.
func (e *escaper) escapeTemplateBody(c context, t *template.Template) (context, bool) {
	filter := func(e1 *escaper, c1 context) bool {
		if c1.state == stateError {
			// Do not update the input escaper, e.
			return false
		}
		if !e1.called[t.Name()] {
			// If t is not recursively called, then c1 is an
			// accurate output context.
			return true
		}
		// c1 is accurate if it matches our assumed output context.
		return c.eq(c1)
	}
	// We need to assume an output context so that recursive template calls
	// take the fast path out of escapeTree instead of infinitely recurring.
	// Naively assuming that the input context is the same as the output
	// works >90% of the time.
	e.output[t.Name()] = c
	return e.escapeListConditionally(c, t.Tree.Root, filter)
}

// delimEnds maps each delim to a string of characters that terminate it.
var delimEnds = [...]string{
	delimDoubleQuote: `"`,
	delimSingleQuote: "'",
	// Determined empirically by running the below in various browsers.
	// var div = document.createElement("DIV");
	// for (var i = 0; i < 0x10000; ++i) {
	//   div.innerHTML = "<span title=x" + String.fromCharCode(i) + "-bar>";
	//   if (div.getElementsByTagName("SPAN")[0].title.indexOf("bar") < 0)
	//     document.write("<p>U+" + i.toString(16));
	// }
	delimSpaceOrTagEnd: " \t\n\f\r>",
}

var (
	// Per WHATWG HTML specification, section 4.12.1.3, there are extremely
	// complicated rules for how to handle the set of opening tags <!--,
	// <script, and </script when they appear in JS literals (i.e. strings,
	// regexs, and comments). The specification suggests a simple solution,
	// rather than implementing the arcane ABNF, which involves simply escaping
	// the opening bracket with \x3C. We use the below regex for this, since it
	// makes doing the case-insensitive find-replace much simpler.
	specialScriptTagRE          = regexp.MustCompile("(?i)<(script|/script|!--)")
	specialScriptTagReplacement = []byte("\\x3C$1")
)

func containsSpecialScriptTag(s []byte) bool {
	return specialScriptTagRE.Match(s)
}

func escapeSpecialScriptTags(s []byte) []byte {
	return specialScriptTagRE.ReplaceAll(s, specialScriptTagReplacement)
}

var doctypeBytes = []byte("<!DOCTYPE")

// escapeText escapes a text template node.
func (e *escaper) escapeText(c context, n *parse.TextNode) context {
	s, written, i, b := n.Text, 0, 0, new(bytes.Buffer)
	for i != len(s) {
		c1, nread := contextAfterText(c, s[i:])
		i1 := i + nread
		if c.state == stateText || c.state == stateRCDATA {
			end := i1
			if c1.state != c.state {
				for j := end - 1; j >= i; j-- {
					if s[j] == '<' {
						end = j
						break
					}
				}
			}
			for j := i; j < end; j++ {
				if s[j] == '<' && !bytes.HasPrefix(bytes.ToUpper(s[j:]), doctypeBytes) {
					b.Write(s[written:j])
					b.WriteString("&lt;")
					written = j + 1
				}
			}
		} else if isComment(c.state) && c.delim == delimNone {
			switch c.state {
			case stateJSBlockCmt:
				// https://es5.github.io/#x7.4:
				// "Comments behave like white space and are
				// discarded except that, if a MultiLineComment
				// contains a line terminator character, then
				// the entire comment is considered to be a
				// LineTerminator for purposes of parsing by
				// the syntactic grammar."
				if bytes.ContainsAny(s[written:i1], "\n\r\u2028\u2029") {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
			case stateCSSBlockCmt:
				b.WriteByte(' ')
			}
			written = i1
		}
		if c.state != c1.state && isComment(c1.state) && c1.delim == delimNone {
			// Preserve the portion between written and the comment start.
			cs := i1 - 2
			if c1.state == stateHTMLCmt || c1.state == stateJSHTMLOpenCmt {
				// "<!--" instead of "/*" or "//"
				cs -= 2
			} else if c1.state == stateJSHTMLCloseCmt {
				// "-->" instead of "/*" or "//"
				cs -= 1
			}
			b.Write(s[written:cs])
			written = i1
		}
		if isInScriptLiteral(c.state) && containsSpecialScriptTag(s[i:i1]) {
			b.Write(s[written:i])
			b.Write(escapeSpecialScriptTags(s[i:i1]))
			written = i1
		}
		if i == i1 && c.state == c1.state {
			panic(fmt.Sprintf("infinite loop from %v to %v on %q..%q", c, c1, s[:i], s[i:]))
		}
		c, i = c1, i1
	}

	if written != 0 && c.state != stateError {
		if !isComment(c.state) || c.delim != delimNone {
			b.Write(n.Text[written:])
		}
		e.editTextNode(n, b.Bytes())
	}
	return c
}

// contextAfterText starts in context c, consumes some tokens from the front of
// s, then returns the context after those tokens and the unprocessed suffix.
func contextAfterText(c context, s []byte) (context, int) {
	if c.delim == delimNone {
		c1, i := tSpecialTagEnd(c, s)
		if i == 0 {
			// A special end tag (`</script>`) has been seen and
			// all content preceding it has been consumed.
			return c1, 0
		}
		// Consider all content up to any end tag.
		return transitionFunc[c.state](c, s[:i])
	}

	// We are at the beginning of an attribute value.

	i := bytes.IndexAny(s, delimEnds[c.delim])
	if i == -1 {
		i = len(s)
	}
	if c.delim == delimSpaceOrTagEnd {
		// https://www.w3.org/TR/html5/syntax.html#attribute-value-(unquoted)-state
		// lists the runes below as error characters.
		// Error out because HTML parsers may differ on whether
		// "<a id= onclick=f("     ends inside id's or onclick's value,
		// "<a class=`foo "        ends inside a value,
		// "<a style=font:'Arial'" needs open-quote fixup.
		// IE treats '`' as a quotation character.
		if j := bytes.IndexAny(s[:i], "\"'<=`"); j >= 0 {
			return context{
				state: stateError,
				err:   errorf(ErrBadHTML, nil, 0, "%q in unquoted attr: %q", s[j:j+1], s[:i]),
			}, len(s)
		}
	}
	if i == len(s) {
		// Remain inside the attribute.
		// Decode the value so non-HTML rules can easily handle
		//     <button onclick="alert(&quot;Hi!&quot;)">
		// without having to entity decode token boundaries.
		for u := []byte(html.UnescapeString(string(s))); len(u) != 0; {
			c1, i1 := transitionFunc[c.state](c, u)
			c, u = c1, u[i1:]
		}
		return c, len(s)
	}

	element := c.element

	// If this is a non-JS "type" attribute inside "script" tag, do not treat the contents as JS.
	if c.state == stateAttr && c.element == elementScript && c.attr == attrScriptType && !isJSType(string(s[:i])) {
		element = elementNone
	}

	if c.delim != delimSpaceOrTagEnd {
		// Consume any quote.
		i++
	}
	// On exiting an attribute, we discard all state information
	// except the state and element.
	return context{state: stateTag, element: element}, i
}

// editActionNode records a change to an action pipeline for later commit.
func (e *escaper) editActionNode(n *parse.ActionNode, cmds []string) {
	if _, ok := e.actionNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.actionNodeEdits[n] = cmds
}

// editTemplateNode records a change to a {{template}} callee for later commit.
func (e *escaper) editTemplateNode(n *parse.TemplateNode, callee string) {
	if _, ok := e.templateNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.templateNodeEdits[n] = callee
}

// editTextNode records a change to a text node for later commit.
func (e *escaper) editTextNode(n *parse.TextNode, text []byte) {
	if _, ok := e.textNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.textNodeEdits[n] = text
}

// commit applies changes to actions and template calls needed to contextually
// autoescape content and adds any derived templates to the set.
func (e *escaper) commit() {
	for name := range e.output {
		e.template(name).Funcs(funcMap)
	}
	// Any template from the name space associated with this escaper can be used
	// to add derived templates to the underlying text/template name space.
	tmpl := e.arbitraryTemplate()
	for _, t := range e.derived {
		if _, err := tmpl.text.AddParseTree(t.Name(), t.Tree); err != nil {
			panic("error adding derived template")
		}
	}
	for n, s := range e.actionNodeEdits {
		ensurePipelineContains(n.Pipe, s)
	}
	for n, name := range e.templateNodeEdits {
		n.Name = name
	}
	for n, s := range e.textNodeEdits {
		n.Text = s
	}
	// Reset state that is specific to this commit so that the same changes are
	// not re-applied to the template on subsequent calls to commit.
	e.called = make(map[string]bool)
	e.actionNodeEdits = make(map[*parse.ActionNode][]string)
	e.templateNodeEdits = make(map[*parse.TemplateNode]string)
	e.textNodeEdits = make(map[*parse.TextNode][]byte)
}

// template returns the named template given a mangled template name.
func (e *escaper) template(name string) *template.Template {
	// Any template from the name space associated with this escaper can be used
	// to look up templates in the underlying text/template name space.
	t := e.arbitraryTemplate().text.Lookup(name)
	if t == nil {
		t = e.derived[name]
	}
	return t
}

// arbitraryTemplate returns an arbitrary template from the name space
// associated with e and panics if no templates are found.
func (e *escaper) arbitraryTemplate() *Template {
	for _, t := range e.ns.set {
		return t
	}
	panic("no templates in name space")
}

// Forwarding functions so that clients need only import this package
// to reach the general escaping functions of text/template.

// HTMLEscape writes to w the escaped HTML equivalent of the plain text data b.
func HTMLEscape(w io.Writer, b []byte) {
	template.HTMLEscape(w, b)
}

// HTMLEscapeString returns the escaped HTML equivalent of the plain text data s.
func HTMLEscapeString(s string) string {
	return template.HTMLEscapeString(s)
}

// HTMLEscaper returns the escaped HTML equivalent of the textual
// representation of its arguments.
func HTMLEscaper(args ...any) string {
	return template.HTMLEscaper(args...)
}

// JSEscape writes to w the escaped JavaScript equivalent of the plain text data b.
func JSEscape(w io.Writer, b []byte) {
	template.JSEscape(w, b)
}

// JSEscapeString returns the escaped JavaScript equivalent of the plain text data s.
func JSEscapeString(s string) string {
	return template.JSEscapeString(s)
}

// JSEscaper returns the escaped JavaScript equivalent of the textual
// representation of it
```