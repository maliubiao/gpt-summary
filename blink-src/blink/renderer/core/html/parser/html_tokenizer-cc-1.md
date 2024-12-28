Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the HTML tokenizer in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code implements the state machine for parsing HTML attributes and related elements (like comments and DOCTYPE).

2. **Analyze the state transitions:**  Each `HTML_BEGIN_STATE` block represents a state in the tokenizer. The code within each state handles different characters and determines the next state.

3. **Relate to HTML, CSS, and JavaScript:** Consider how the code contributes to the parsing of these languages. For instance, attribute values can contain JavaScript or CSS.

4. **Look for error handling:**  The `ParseError()` function indicates the detection of invalid HTML.

5. **Identify assumptions and potential issues:** The code uses `DCHECK` for internal consistency checks, and might have assumptions about input.

6. **Consider user errors:** Think about common mistakes developers make when writing HTML that this code would handle.

7. **Provide examples:**  Illustrate the functionality with concrete input and output scenarios.

8. **Summarize the overall function:** Condense the analysis into a concise description.

**Detailed thought process:**

* **States related to attributes:**  `kAttributeNameState`, `kAfterAttributeNameState`, `kBeforeAttributeValueState`, `kAttributeValueDoubleQuotedState`, `kAttributeValueSingleQuotedState`, `kAttributeValueUnquotedState`, `kCharacterReferenceInAttributeValueState`, `kAfterAttributeValueQuotedState`. These states handle the parsing of attribute names and values, including different quoting mechanisms and character references.

* **States related to comments:** `kBogusCommentState`, `kContinueBogusCommentState`, `kCommentStartState`, `kCommentStartDashState`, `kCommentState`, `kCommentEndDashState`, `kCommentEndState`, `kCommentEndBangState`. These manage the parsing of HTML comments.

* **States related to DOCTYPE:** `kDOCTYPEState`, `kBeforeDOCTYPENameState`, `kDOCTYPENameState`, `kAfterDOCTYPENameState`, `kAfterDOCTYPEPublicKeywordState`, `kBeforeDOCTYPEPublicIdentifierState`, `kDOCTYPEPublicIdentifierDoubleQuotedState`, `kDOCTYPEPublicIdentifierSingleQuotedState`, `kAfterDOCTYPEPublicIdentifierState`, `kBetweenDOCTYPEPublicAndSystemIdentifiersState`, `kAfterDOCTYPESystemKeywordState`, `kBeforeDOCTYPESystemIdentifierState`, `kDOCTYPESystemIdentifierDoubleQuotedState`, `kDOCTYPESystemIdentifierSingleQuotedState`, `kAfterDOCTYPESystemIdentifierState`, `kBogusDOCTYPEState`. These states parse the DOCTYPE declaration.

* **States related to CDATA:** `kCDATASectionState`, `kCDATASectionBracketState`, `kCDATASectionEndState`. These handle CDATA sections.

* **Self-closing tags:** `kSelfClosingStartTagState` handles tags like `<br/>`.

* **Error handling:** The numerous `ParseError()` calls indicate how the tokenizer deals with invalid HTML.

* **DOM Parts:** The mentions of `ShouldAllowDOMParts()`, `kNodePartMarker`, and `kAttributePartMarker` suggest support for a templating or component system.

* **Character References:** `kCharacterReferenceInAttributeValueState` handles HTML entities within attribute values.

* **Input/Output:** The tokenizer consumes a stream of characters (`SegmentedString& source`) and produces tokens. The `EmitAndResumeInDataState` functions suggest emitting a token and returning to the main data parsing state.

* **Relationship to web technologies:**
    * **HTML:**  The core function is parsing HTML structure (tags, attributes, comments, DOCTYPE).
    * **JavaScript:** Attribute values can contain JavaScript code (e.g., event handlers like `onclick`).
    * **CSS:** Attribute values can contain CSS styles (e.g., the `style` attribute).

* **User errors:**  The code handles cases like missing quotes around attribute values, incorrect DOCTYPE declarations, and malformed comments.

* **Assumptions:** The code assumes a character-by-character processing model. It uses lookahead (`source.LookAhead()`) for certain patterns.

By systematically analyzing the code in this way, we can arrive at a comprehensive summary of its functionality.
Based on the provided code snippet, here's a summary of the `HTMLTokenizer::RunStateMachine` function's functionality in this part:

**Core Functionality:**

This section of the `HTMLTokenizer::RunStateMachine` function is primarily responsible for parsing **attributes** within HTML start tags, as well as handling **comments**, **DOCTYPE declarations**, and **CDATA sections**. It operates as a state machine, transitioning between different states based on the characters encountered in the input stream.

**Specific functionalities within this part:**

* **Parsing Attributes:**
    * **`kAttributeNameState`**: Reads the name of an attribute.
    * **`kAfterAttributeNameState`**: Handles whitespace after an attribute name.
    * **`kBeforeAttributeValueState`**: Handles whitespace or the start of an attribute value.
    * **`kAttributeValueDoubleQuotedState`**: Reads attribute values enclosed in double quotes.
    * **`kAttributeValueSingleQuotedState`**: Reads attribute values enclosed in single quotes.
    * **`kAttributeValueUnquotedState`**: Reads attribute values without quotes.
    * **`kCharacterReferenceInAttributeValueState`**: Handles HTML character entities (like `&amp;`) within attribute values.
    * **`kAfterAttributeValueQuotedState`**: Handles whitespace or the end of a quoted attribute value.
* **Handling Self-Closing Tags:**
    * **`kSelfClosingStartTagState`**: Detects the closing `/` in a self-closing tag like `<br />`.
* **Parsing Comments:**
    * **`kBogusCommentState`**: Enters this state when an unexpected `<!` or `<` is encountered and treats the rest as a comment.
    * **`kContinueBogusCommentState`**: Reads the content of a bogus comment.
    * **`kCommentStartState`**: Begins parsing a valid comment (`<!--`).
    * **`kCommentStartDashState`**: Handles the second dash in `<!--`.
    * **`kCommentState`**: Reads the content of a comment.
    * **`kCommentEndDashState`**: Handles a dash encountered while looking for the end of a comment.
    * **`kCommentEndState`**: Handles the final two dashes in the comment end (`--`).
    * **`kCommentEndBangState`**: Handles a `!` after the double dashes in a comment end (an error case).
* **Parsing DOCTYPE Declarations:**
    * **`kDOCTYPEState`**:  Initial state for parsing a DOCTYPE.
    * **`kBeforeDOCTYPENameState`**: Handles whitespace before the DOCTYPE name.
    * **`kDOCTYPENameState`**: Reads the DOCTYPE name (e.g., `html`).
    * **`kAfterDOCTYPENameState`**: Handles whitespace after the DOCTYPE name.
    * **States related to Public and System Identifiers**: (`kAfterDOCTYPEPublicKeywordState`, `kBeforeDOCTYPEPublicIdentifierState`, etc.) Parse the `PUBLIC` and `SYSTEM` identifiers within the DOCTYPE declaration.
    * **`kBogusDOCTYPEState`**:  Handles invalid DOCTYPE declarations.
* **Parsing CDATA Sections:**
    * **`kCDATASectionState`**: Reads the content of a CDATA section (`<![CDATA[`).
    * **`kCDATASectionBracketState`**: Handles a `]` character within a CDATA section.
    * **`kCDATASectionEndState`**: Handles the closing `]]>` of a CDATA section.

**Relationship to JavaScript, HTML, and CSS:**

* **HTML:** This code is fundamental to parsing the structure of HTML documents, recognizing tags, attributes, comments, and the DOCTYPE declaration.
* **JavaScript:** Attribute values can contain JavaScript code (e.g., event handlers like `onclick="alert('hello')" `). This code parses the attribute value, which later might be interpreted as JavaScript. The handling of character references is also important as JavaScript code within HTML can contain entities.
* **CSS:** Similarly, attribute values, especially the `style` attribute, can contain CSS. The tokenizer parses these values, which are then further processed by the CSS parser.

**Examples with Assumptions and Outputs:**

**Assumption:** `source` contains the following HTML fragment: `<div id="my-id" class='container'>`

* **Input:** The tokenizer is in the `kTagNameState` (from the previous part) and has just finished parsing `div`. The next character is a space.
* **State Transition:** Moves to `kBeforeAttributeNameState`.
* **Input:** `id`
* **State Transition:** Moves to `kAttributeNameState`, `token_.AppendToAttributeName('i')`, `token_.AppendToAttributeName('d')`.
* **Input:** `=`
* **State Transition:** Moves to `kBeforeAttributeValueState`.
* **Input:** `"`
* **State Transition:** Moves to `kAttributeValueDoubleQuotedState`.
* **Input:** `my-id`
* **State Transition:** Remains in `kAttributeValueDoubleQuotedState`, appending characters to the attribute value.
* **Input:** `"`
* **State Transition:** Moves to `kAfterAttributeValueQuotedState`.
* **Input:** (whitespace)
* **State Transition:** Moves to `kBeforeAttributeNameState`.
* **Input:** `class`
* **State Transition:** Moves to `kAttributeNameState`, appending characters.
* **Input:** `=`
* **State Transition:** Moves to `kBeforeAttributeValueState`.
* **Input:** `'`
* **State Transition:** Moves to `kAttributeValueSingleQuotedState`.
* **Input:** `container`
* **State Transition:** Remains in `kAttributeValueSingleQuotedState`, appending characters.
* **Input:** `'`
* **State Transition:** Moves to `kAfterAttributeValueQuotedState`.
* **Output:** The `token_` object will contain the parsed start tag with its attributes: `name="div"`, `attributes=[{name="id", value="my-id"}, {name="class", value="container"}]`.

**Assumption:** `source` contains the HTML comment: `<!-- This is a comment -->`

* **Input:** The tokenizer is in `kTagOpenState` and encounters `!`.
* **State Transition:** Moves to `kMarkupDeclarationOpenState`.
* **Input:** `-`
* **State Transition:**  The lookahead matches `--`, so it moves to `kCommentStartState`.
* **Input:** ` `
* **State Transition:** Moves to `kCommentState`, `token_.AppendToComment(' ')`.
* **Input:** `This is a comment `
* **State Transition:** Remains in `kCommentState`, appending characters to the comment.
* **Input:** `-`
* **State Transition:** Moves to `kCommentEndDashState`.
* **Input:** `-`
* **State Transition:** Moves to `kCommentEndState`.
* **Input:** `>`
* **State Transition:** Moves to `kDataState`, emitting a comment token.
* **Output:** A comment token will be emitted with the data " This is a comment ".

**User or Programming Common Usage Errors:**

* **Missing quotes around attribute values:**
    * **Input:** `<div id=myid>`
    * **Behavior:** The tokenizer will enter `kAttributeValueUnquotedState` and might consume subsequent characters until a whitespace or `>` is encountered, potentially leading to unexpected attribute values. A `ParseError()` will likely be generated.
* **Incorrectly nested comments:** HTML comments cannot be nested.
    * **Input:** `<!-- outer <!-- inner --> -->`
    * **Behavior:** The first `-->` will close the outer comment. The remaining ` -->` will be treated as regular content or might lead to errors in subsequent parsing.
* **Malformed DOCTYPE declarations:**
    * **Input:** `<!DOCTYPE html  >` (extra space before the closing `>`)
    * **Behavior:** The tokenizer will likely handle this, but might issue a `ParseError()`. More significant errors in the DOCTYPE declaration can lead to the tokenizer entering the `kBogusDOCTYPEState` and potentially triggering "quirks mode" in the browser.
* **Unclosed CDATA sections:**
    * **Input:** `<![CDATA[ Some unclosed CDATA`
    * **Behavior:** The tokenizer will continue in the `kCDATASectionState` until the end of the input or a closing `]]>` is found. If the end of the file is reached, it will transition back to the `kDataState`, potentially leading to unexpected interpretation of the content.

**Summary of Functionality:**

In summary, this part of the `HTMLTokenizer::RunStateMachine` function is crucial for dissecting the internal structure of HTML tags by parsing attributes and handling special declarations like comments, DOCTYPE, and CDATA sections. It meticulously steps through the input, character by character, guided by a state machine to correctly identify and interpret these HTML elements. This process is fundamental to building the Document Object Model (DOM) and enabling the browser to understand and render web pages.

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_tokenizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
feredCharacterToken();
      }
      if (IsTokenizerWhitespace(cc)) {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeName(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_TO(kAfterAttributeNameState);
      } else if (cc == '/') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeName(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kSelfClosingStartTagState);
      } else if (cc == '=') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeName(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBeforeAttributeValueState);
      } else if (cc == '>') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeName(
              source.NumberOfCharactersConsumed());
        }
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeName(
              source.NumberOfCharactersConsumed());
        }
        HTML_RECONSUME_IN(kDataState);
      } else {
        DCHECK(cc == '"' || cc == '\'' || cc == '<' || cc == '=');
        ParseError();
        token_.AppendToAttributeName(ToLowerCaseIfAlpha(cc));
        HTML_CONSUME_NON_NEWLINE(kAttributeNameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterAttributeNameState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '/') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kSelfClosingStartTagState);
      } else if (cc == '=') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBeforeAttributeValueState);
      } else if (cc == '>') {
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else if (cc == '{' && ShouldAllowDOMParts() &&
                 source.LookAhead(kNodePartMarker) ==
                     SegmentedString::kDidMatch) {
        token_.SetNeedsNodePart();
        // Need to skip ahead here so we don't get {{}} as an attribute.
        ADVANCE_PAST_MULTIPLE_NO_NEWLINE(sizeof(kNodePartMarker) - 1,
                                         kAfterAttributeNameState);
      } else if (cc == '"' || cc == '\'' || cc == '<') {
        ParseError();
      }
      token_.AddNewAttribute(ToLowerCaseIfAlpha(cc));
      if (track_attributes_ranges_) {
        attributes_ranges_.AddAttribute(source.NumberOfCharactersConsumed());
      }
      HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAttributeNameState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kBeforeAttributeValueState) {
      if (IsTokenizerWhitespace(cc))
        HTML_CONSUME(kBeforeAttributeValueState);
      else if (cc == '"') {
        if (track_attributes_ranges_) {
          attributes_ranges_.BeginAttributeValue(
              source.NumberOfCharactersConsumed() + 1);
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAttributeValueDoubleQuotedState);
      } else if (cc == '&') {
        if (track_attributes_ranges_) {
          attributes_ranges_.BeginAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_RECONSUME_IN(kAttributeValueUnquotedState);
      } else if (cc == '\'') {
        if (track_attributes_ranges_) {
          attributes_ranges_.BeginAttributeValue(
              source.NumberOfCharactersConsumed() + 1);
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAttributeValueSingleQuotedState);
      } else if (cc == '>') {
        ParseError();
        return EmitAndResumeInDataState(source);

      } else if (cc == '{' && ShouldAllowDOMParts() &&
                 source.LookAhead(kAttributePartMarker) ==
                     SegmentedString::kDidMatch) {
        static_assert(kAttributePartMarker[0] == '{');
        token_.SetNeedsAttributePart();
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        // Skip ahead so we don't get {{}} in the attribute value.
        ADVANCE_PAST_MULTIPLE_NO_NEWLINE(sizeof(kAttributePartMarker) - 1,
                                         kBeforeAttributeNameState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        if (cc == '<' || cc == '=' || cc == '`')
          ParseError();
        if (track_attributes_ranges_) {
          attributes_ranges_.BeginAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        token_.AppendToAttributeValue(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAttributeValueUnquotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAttributeValueDoubleQuotedState) {
      if (cc == '"') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterAttributeValueQuotedState);
      } else if (cc == '&') {
        additional_allowed_character_ = '"';
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kCharacterReferenceInAttributeValueState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_RECONSUME_IN(kDataState);
      } else {
        token_.AppendToAttributeValue(cc);
        HTML_CONSUME(kAttributeValueDoubleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAttributeValueSingleQuotedState) {
      if (cc == '\'') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterAttributeValueQuotedState);
      } else if (cc == '&') {
        additional_allowed_character_ = '\'';
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kCharacterReferenceInAttributeValueState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_RECONSUME_IN(kDataState);
      } else {
        token_.AppendToAttributeValue(cc);
        HTML_CONSUME(kAttributeValueSingleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAttributeValueUnquotedState) {
      if (IsTokenizerWhitespace(cc)) {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_ADVANCE_TO(kBeforeAttributeNameState);
      } else if (cc == '&') {
        additional_allowed_character_ = '>';
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kCharacterReferenceInAttributeValueState);
      } else if (cc == '>') {
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        if (track_attributes_ranges_) {
          attributes_ranges_.EndAttributeValue(
              source.NumberOfCharactersConsumed());
        }
        HTML_RECONSUME_IN(kDataState);
      } else {
        if (cc == '"' || cc == '\'' || cc == '<' || cc == '=' || cc == '`')
          ParseError();
        token_.AppendToAttributeValue(cc);
        HTML_CONSUME_NON_NEWLINE(kAttributeValueUnquotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCharacterReferenceInAttributeValueState) {
      bool not_enough_characters = false;
      DecodedHTMLEntity decoded_entity;
      bool success =
          ConsumeHTMLEntity(source, decoded_entity, not_enough_characters,
                            additional_allowed_character_);
      if (not_enough_characters)
        return HaveBufferedCharacterToken();
      if (!success) {
        DCHECK(decoded_entity.IsEmpty());
        token_.AppendToAttributeValue('&');
      } else {
        for (unsigned i = 0; i < decoded_entity.length; ++i)
          token_.AppendToAttributeValue(decoded_entity.data[i]);
      }
      // We're supposed to switch back to the attribute value state that
      // we were in when we were switched into this state. Rather than
      // keeping track of this explictly, we observe that the previous
      // state can be determined by additional_allowed_character_.
      if (additional_allowed_character_ == '"') {
        HTML_SWITCH_TO(kAttributeValueDoubleQuotedState);
      } else if (additional_allowed_character_ == '\'') {
        HTML_SWITCH_TO(kAttributeValueSingleQuotedState);
      } else if (additional_allowed_character_ == '>') {
        HTML_SWITCH_TO(kAttributeValueUnquotedState);
      } else {
        NOTREACHED();
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterAttributeValueQuotedState) {
      if (IsTokenizerWhitespace(cc))
        HTML_ADVANCE_TO(kBeforeAttributeNameState);
      else if (cc == '/')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kSelfClosingStartTagState);
      else if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        ParseError();
        HTML_RECONSUME_IN(kBeforeAttributeNameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kSelfClosingStartTagState) {
      if (cc == '>') {
        token_.SetSelfClosing();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        ParseError();
        HTML_RECONSUME_IN(kBeforeAttributeNameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBogusCommentState) {
      token_.BeginComment();
      HTML_RECONSUME_IN(kContinueBogusCommentState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kContinueBogusCommentState) {
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == kEndOfFileMarker)
        return EmitAndReconsumeInDataState();
      else {
        token_.AppendToComment(cc);
        HTML_CONSUME(kContinueBogusCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kMarkupDeclarationOpenState) {
      if (cc == '-') {
        SegmentedString::LookAheadResult result =
            source.LookAhead(html_tokenizer_names::kDashDash);
        if (result == SegmentedString::kDidMatch) {
          source.AdvanceAndASSERT('-');
          source.AdvanceAndASSERT('-');
          token_.BeginComment();
          HTML_SWITCH_TO(kCommentStartState);
        } else if (result == SegmentedString::kNotEnoughCharacters)
          return HaveBufferedCharacterToken();
      } else if (cc == 'D' || cc == 'd') {
        SegmentedString::LookAheadResult result =
            source.LookAheadIgnoringCase(html_tokenizer_names::kDoctype);
        if (result == SegmentedString::kDidMatch) {
          AdvanceStringAndASSERTIgnoringCase(source, "doctype");
          HTML_SWITCH_TO(kDOCTYPEState);
        } else if (result == SegmentedString::kNotEnoughCharacters)
          return HaveBufferedCharacterToken();
      } else if (cc == '[' && ShouldAllowCDATA()) {
        SegmentedString::LookAheadResult result =
            source.LookAhead(html_tokenizer_names::kCdata);
        if (result == SegmentedString::kDidMatch) {
          AdvanceStringAndASSERT(source, "[CDATA[");
          HTML_SWITCH_TO(kCDATASectionState);
        } else if (result == SegmentedString::kNotEnoughCharacters)
          return HaveBufferedCharacterToken();
      }
      ParseError();
      HTML_RECONSUME_IN(kBogusCommentState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentStartState) {
      if (cc == '-')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentStartDashState);
      else if (cc == '>') {
        ParseError();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToComment(cc);
        HTML_ADVANCE_TO(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentStartDashState) {
      if (cc == '-')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentEndState);
      else if (cc == '>') {
        ParseError();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToComment('-');
        token_.AppendToComment(cc);
        HTML_ADVANCE_TO(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentState) {
      if (cc == '-')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentEndDashState);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToComment(cc);
        HTML_CONSUME(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentEndDashState) {
      if (cc == '-')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentEndState);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToComment('-');
        token_.AppendToComment(cc);
        HTML_ADVANCE_TO(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentEndState) {
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == '!') {
        ParseError();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentEndBangState);
      } else if (cc == '-') {
        ParseError();
        token_.AppendToComment('-');
        HTML_CONSUME_NON_NEWLINE(kCommentEndState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.AppendToComment('-');
        token_.AppendToComment('-');
        token_.AppendToComment(cc);
        HTML_ADVANCE_TO(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCommentEndBangState) {
      if (cc == '-') {
        token_.AppendToComment('-');
        token_.AppendToComment('-');
        token_.AppendToComment('!');
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCommentEndDashState);
      } else if (cc == '>') {
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToComment('-');
        token_.AppendToComment('-');
        token_.AppendToComment('!');
        token_.AppendToComment(cc);
        HTML_ADVANCE_TO(kCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPEState) {
      if (IsTokenizerWhitespace(cc))
        HTML_ADVANCE_TO(kBeforeDOCTYPENameState);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.BeginDOCTYPE();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        HTML_RECONSUME_IN(kBeforeDOCTYPENameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBeforeDOCTYPENameState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '>') {
        ParseError();
        token_.BeginDOCTYPE();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.BeginDOCTYPE();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.BeginDOCTYPE(ToLowerCaseIfAlpha(cc));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kDOCTYPENameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPENameState) {
      if (IsTokenizerWhitespace(cc)) {
        HTML_ADVANCE_TO(kAfterDOCTYPENameState);
      } else if (cc == '>') {
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToName(ToLowerCaseIfAlpha(cc));
        HTML_CONSUME_NON_NEWLINE(kDOCTYPENameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterDOCTYPENameState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        if (cc == 'P' || cc == 'p') {
          SegmentedString::LookAheadResult result =
              source.LookAheadIgnoringCase(html_tokenizer_names::kPublic);
          if (result == SegmentedString::kDidMatch) {
            AdvanceStringAndASSERTIgnoringCase(source, "public");
            HTML_SWITCH_TO(kAfterDOCTYPEPublicKeywordState);
          } else if (result == SegmentedString::kNotEnoughCharacters)
            return HaveBufferedCharacterToken();
        } else if (cc == 'S' || cc == 's') {
          SegmentedString::LookAheadResult result =
              source.LookAheadIgnoringCase(html_tokenizer_names::kSystem);
          if (result == SegmentedString::kDidMatch) {
            AdvanceStringAndASSERTIgnoringCase(source, "system");
            HTML_SWITCH_TO(kAfterDOCTYPESystemKeywordState);
          } else if (result == SegmentedString::kNotEnoughCharacters)
            return HaveBufferedCharacterToken();
        }
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterDOCTYPEPublicKeywordState) {
      if (IsTokenizerWhitespace(cc))
        HTML_ADVANCE_TO(kBeforeDOCTYPEPublicIdentifierState);
      else if (cc == '"') {
        ParseError();
        token_.SetPublicIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPEPublicIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        ParseError();
        token_.SetPublicIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPEPublicIdentifierSingleQuotedState);
      } else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBeforeDOCTYPEPublicIdentifierState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '"') {
        token_.SetPublicIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPEPublicIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        token_.SetPublicIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPEPublicIdentifierSingleQuotedState);
      } else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPEPublicIdentifierDoubleQuotedState) {
      if (cc == '"')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterDOCTYPEPublicIdentifierState);
      else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToPublicIdentifier(cc);
        HTML_CONSUME(kDOCTYPEPublicIdentifierDoubleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPEPublicIdentifierSingleQuotedState) {
      if (cc == '\'')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterDOCTYPEPublicIdentifierState);
      else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToPublicIdentifier(cc);
        HTML_CONSUME(kDOCTYPEPublicIdentifierSingleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterDOCTYPEPublicIdentifierState) {
      if (IsTokenizerWhitespace(cc))
        HTML_ADVANCE_TO(kBetweenDOCTYPEPublicAndSystemIdentifiersState);
      else if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == '"') {
        ParseError();
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        ParseError();
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierSingleQuotedState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBetweenDOCTYPEPublicAndSystemIdentifiersState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == '"') {
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierSingleQuotedState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterDOCTYPESystemKeywordState) {
      if (IsTokenizerWhitespace(cc))
        HTML_ADVANCE_TO(kBeforeDOCTYPESystemIdentifierState);
      else if (cc == '"') {
        ParseError();
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        ParseError();
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierSingleQuotedState);
      } else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBeforeDOCTYPESystemIdentifierState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '"') {
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierDoubleQuotedState);
      } else if (cc == '\'') {
        token_.SetSystemIdentifierToEmptyString();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kDOCTYPESystemIdentifierSingleQuotedState);
      } else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        token_.SetForceQuirks();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPESystemIdentifierDoubleQuotedState) {
      if (cc == '"')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterDOCTYPESystemIdentifierState);
      else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToSystemIdentifier(cc);
        HTML_CONSUME(kDOCTYPESystemIdentifierDoubleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kDOCTYPESystemIdentifierSingleQuotedState) {
      if (cc == '\'')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAfterDOCTYPESystemIdentifierState);
      else if (cc == '>') {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        token_.AppendToSystemIdentifier(cc);
        HTML_CONSUME(kDOCTYPESystemIdentifierSingleQuotedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kAfterDOCTYPESystemIdentifierState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        token_.SetForceQuirks();
        return EmitAndReconsumeInDataState();
      } else {
        ParseError();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kBogusDOCTYPEState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kBogusDOCTYPEState) {
      if (cc == '>')
        return EmitAndResumeInDataState(source);
      else if (cc == kEndOfFileMarker)
        return EmitAndReconsumeInDataState();
      HTML_CONSUME(kBogusDOCTYPEState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kCDATASectionState) {
      if (cc == ']')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCDATASectionBracketState);
      else if (cc == kEndOfFileMarker)
        HTML_RECONSUME_IN(kDataState);
      else {
        BufferCharacter(cc);
        HTML_CONSUME(kCDATASectionState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCDATASectionBracketState) {
      if (cc == ']')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCDATASectionEndState);
      else {
        BufferCharacter(']');
        HTML_RECONSUME_IN(kCDATASectionState);
      }
    }

    HTML_BEGIN_STATE(kCDATASectionEndState) {
      if (cc == ']') {
        BufferCharacter(']');
        HTML_CONSUME_NON_NEWLINE(kCDATASectionEndState);
      } else if (cc == '>') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kDataState);
      } else {
        BufferCharacter(']');
        BufferCharacter(']');
        HTML_RECONSUME_IN(kCDATASectionState);
      }
    }
    END_STATE()
  }

  NOTREACHED();
}

bool HTMLTokenizer::SkipWhitespaces(SegmentedString& source, UChar& cc) {
  // The character `cc` is usually not a whitespace, so we check it here
  // first, before calling the helper.
  if (!CheckScanFlag(cc, ScanFlags::kWhitespace))
    return true;
  return SkipWhitespacesHelper(source, cc);
}

bool HTMLTokenizer::SkipWhitespacesHelper(SegmentedString& source, UChar& cc) {
  DCHECK(!source.IsEmpty());
  DCHECK(IsTokenizerWhitespace(cc));
  cc = source.CurrentChar();
  while (true) {
    while (CheckScanFlag(cc, ScanFlags::kWhitespaceNotNewline)) {
      cc = source.AdvancePastNonNewline();
    }
    switch (cc) {
      case '\n':
        cc = source.AdvancePastNewlineAndUpdateLineNumber();
        break;
      case '\r':
        if (!input_stream_preprocessor_.AdvancePastCarriageReturn(source, cc))
          return false;
        break;
      case '\0':
        if (!input_stream_preprocessor_.ProcessNullCharacter(source, cc))
          return false;
        if (cc == kEndOfFileMarker)
          return true;
        break;
      default:
        return true;
    }
  }
}

bool HTMLTokenizer::EmitData(SegmentedString& source, UChar cc) {
  token_.EnsureIsCharacterToken();
  if (cc == '\n')  // We could be pointing to '\r'.
    cc = source.CurrentChar();
  while (true) {
    while (!CheckScanFlag(cc, ScanFlags::kCharacterTokenSpecial)) {
      token_.AppendToCharacter(cc);
      cc = source.AdvancePastNonNewline();
    }
    switch (cc) {
      case '&':
        state_ = kCharacterReferenceInDataState;
        source.AdvanceAndASSERT('&');
        if (!ProcessEntity(source))
          return true;
        state_ = kDataState;
        if (source.IsEmpty())
          return true;
        cc = source.CurrentChar();
        break;
      case '\n':
        token_.AppendToCharacter(cc);
        cc = source.AdvancePastNewlineAndUpdateLineNumber();
        break;
      case '\r':
        token_.AppendToCharacter('\n');  // Canonize newline.
        if (!input_stream_preprocessor_.AdvancePastCarriageReturn(source, cc))
          return true;
        break;
      case '<':
        return true;
      case '\0':
        if (!input_stream_preprocessor_.ProcessNullCharacter(source, cc))
          return true;
        if (cc == kEndOfFileMarker)
          return EmitEndOfFile(source);
        break;
      case '{':
        DCHECK_EQ(strlen(kChildNodePartStartMarker),
                  strlen(kChildNodePartEndMarker));
        static_assert(kChildNodePartStartMarker[0] == '{');
        static_assert(kChildNodePartEndMarker[0] == '{');
        if (ShouldAllowDOMParts()) {
          auto result = source.LookAhead(kChildNodePartStartMarker);
          if (result == SegmentedString::kDidMatch) {
            state_ = kChildNodePartStartState;
            if (token_.Characters().IsEmpty()) {
              // TODO(crbug.com/1453291) If we have `<div parseparts>{{#}}`,
              // then we will be in a character token that is empty, which is
              // not good. Add a space for now to get around this, but it'd
              // be better to not get to EmitData at all from kDataState at all
              // in this case and just go directly to kChildNodePartStartState.
              token_.AppendToCharacter(' ');
            }
            // Emit the character data up to this point, then switch to
            // kChildNodePartStartState.
            return true;
          } else if (result == SegmentedString::kNotEnoughCharacters) {
            // TODO(crbug.com/1453291) If we never receive the rest of the start
            // marker, we'll get in an infinite loop here. This might be the
            // same problem that happens for <!DOCTYPE>, in crbug.com/1141343
            // and crbug.com/985307.
            return false;
          }
          result = source.LookAhead(kChildNodePartEndMarker);
          if (result == SegmentedString::kDidMatch) {
            state_ = kChildNodePartEndState;
            if (token_.Characters().IsEmpty()) {
              // TODO(crbug.com/1453291) If we have `{{#}}{{/}}`, then we will
              // be in a character token that is empty (between the markers),
              // which is not good. Add a space for now to get around this, but
              // it'd be better to not get to EmitData at all from kDataState at
              // all in this case and just go directly to
              // kChildNodePartEndState.
              token_.AppendToCharacter(' ');
            }
            // Emit the character data up to this point, then switch to
            // kChildNodePartEndState.
            return true;
          } else if (result == SegmentedString::kNotEnoughCharacters) {
            return false;
          }
        }
        token_.AppendToCharacter(cc);
        cc = source.AdvancePastNonNewline();
        break
"""


```