Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its function, particularly within the context of the Frida dynamic instrumentation tool and how it relates to reverse engineering, low-level systems, and common programming errors.

**1. Initial Skim and Keyword Spotting:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. Immediately, terms like "Parser," "TOMLDocument," "Key," "String," "Integer," "Float," "Array," "Table," and exception names like "ParseError," "UnexpectedCharError," and "InvalidNumberError" stand out. This strongly suggests the code is responsible for parsing TOML (Tom's Obvious, Minimal Language) files.

**2. Identifying the Core Functionality:**

The presence of a `Parser` class with methods like `parse`, `_parse_item`, `_parse_key_value`, `_parse_string`, `_parse_table`, etc., reinforces the idea that this code is a parser. The `parse()` method seems to be the entry point, taking a string or bytes as input and returning a `TOMLDocument`. The other `_parse_` methods likely handle the parsing of specific TOML elements (keys, values, tables, arrays, strings, etc.).

**3. Understanding TOML and its Purpose:**

Knowing that TOML is a configuration file format is crucial. This means the parser's job is to take textual TOML data and convert it into a structured data representation that can be easily accessed and used by a program.

**4. Connecting to Frida and Reverse Engineering:**

The prompt specifies this code is part of Frida. Thinking about how Frida works (dynamic instrumentation), TOML files could be used for:

* **Configuration:** Frida itself might use TOML files to configure its behavior (e.g., which processes to attach to, which scripts to load, logging levels).
* **Instrumentation Scripts:**  While Frida scripts are typically written in JavaScript, TOML could be used to provide configuration data *within* those scripts or to configure how the scripts are used.

In the context of reverse engineering, configuration files often define targets, parameters, or actions. A parser like this would be essential for Frida to understand these configurations.

**5. Identifying Relationships with Low-Level Systems:**

The code deals with character manipulation, control characters (like tabs and newlines), and string encoding (UTF-8). These are fundamental concepts in computer science and are relevant to how operating systems, including Linux and Android, handle text and data. While this specific parser might not directly interact with kernel structures, the *purpose* of Frida – to interact with running processes – involves deep interaction with the OS kernel (for process control, memory access, etc.). The TOML parser helps configure *that* low-level interaction.

**6. Recognizing Logical Reasoning:**

The parser uses conditional logic (if/elif/else statements) and loops (while loops) to analyze the input string character by character. It makes decisions based on the current character and potentially the next few characters (using `_peek`). The different `_parse_` methods represent distinct parsing rules for different TOML syntax elements. The code also performs checks for syntax errors and raises exceptions when it encounters invalid TOML.

**7. Identifying Potential User Errors:**

Based on the exception types, common user errors would include:

* **Syntax errors:**  Incorrectly formatted TOML (e.g., missing quotes, mismatched brackets, invalid characters).
* **Type errors:**  Providing values in the wrong format (e.g., a string where a number is expected).
* **Logical errors:**  Configuration that doesn't make sense in the context of Frida's operation.

**8. Tracing the Execution Flow (Debugging Clues):**

The prompt asks how a user might reach this code. A user interacting with Frida would likely:

1. **Write a Frida script:** This script might contain or reference configuration data.
2. **Create a TOML configuration file:**  If the script or Frida's own configuration uses TOML.
3. **Run Frida with the script and/or configuration:** Frida would then load and parse the TOML file using this `parser.py` code.

**9. Structuring the Explanation:**

Finally, the information gathered needs to be organized logically. The prompt itself provides a good structure:

* **Functionality:**  Start with the core purpose: parsing TOML.
* **Relationship to Reverse Engineering:** Explain how TOML can be used in Frida for configuration and how this parser is essential.
* **Relationship to Low-Level Systems:** Connect the code to fundamental concepts and acknowledge Frida's deeper system interaction.
* **Logical Reasoning:** Describe the conditional logic and parsing rules.
* **User Errors:** List common mistakes based on the exception types.
* **User Operations (Debugging Clues):** Outline the steps a user would take to involve this code.
* **Summary of Functionality:**  Provide a concise recap.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This might be directly interacting with memory or kernel structures."  **Correction:**  While Frida *does*, this specific *parser* is more about *configuring* that interaction through TOML.
* **Initial thought:**  Focusing too much on the low-level *implementation details* of the parser. **Correction:**  Shift focus to the *high-level purpose* and how it fits into Frida's workflow and reverse engineering tasks.
* **Realizing the importance of TOML:** Emphasize that TOML is a *configuration format*, which explains the parser's role in making Frida configurable.
This is the first part of the source code for the TOML parser within the `tomlkit` library, which is used by Frida's Node.js bindings for handling TOML configuration files. Let's break down its functionality:

**Core Functionality of `parser.py` (Part 1):**

This part of the `Parser` class in `tomlkit/parser.py` is primarily responsible for the **lexical analysis and initial parsing** of a TOML document. It takes a raw string or bytes representing TOML content and begins the process of breaking it down into meaningful tokens and structures. Here's a breakdown of its key functions:

1. **Initialization:**
   - The `__init__` method initializes the parser with the input TOML string (after decoding it to Unicode).
   - It uses a `Source` object (`self._src`) to manage the input string, track the current position, and provide helper methods for accessing and manipulating the input.
   - `self._aot_stack` is initialized as an empty list, likely used to keep track of Array of Tables (AoT) contexts during parsing.

2. **Input Management (via `Source`):**
   - It provides properties (`_state`, `_idx`, `_current`, `_marker`) to access the internal state of the `Source` object (likely the current parsing state, index, current character, and a marker for extracting substrings).
   - It offers methods like `extract()`, `inc()`, `inc_n()`, `consume()`, `end()`, and `mark()` which are wrappers around the `Source` object's methods. These methods are fundamental for navigating the input string, advancing the parser, and extracting relevant portions.

3. **Error Handling:**
   - The `parse_error()` method is a helper to create and raise specific `ParseError` exceptions when invalid TOML syntax is encountered. It utilizes the `Source` object's ability to pinpoint the error location.

4. **Top-Level Parsing (`parse()`):**
   - The `parse()` method is the main entry point for parsing the entire TOML document.
   - It initializes an empty `TOMLDocument` object to store the parsed data.
   - It first parses key-value pairs that are outside of any explicit tables or Array of Tables.
   - It then enters a loop to parse tables (standard tables and Array of Tables).
   - It uses `_parse_item()` to handle individual key-value pairs outside of tables.
   - It uses `_parse_table()` to handle the parsing of table headers.
   - It uses `_parse_aot()` (likely in the next part of the code) to handle the parsing of multiple tables within an Array of Tables.
   - Finally, it sets the `parsing` flag of the `TOMLDocument` to `False`, indicating the parsing is complete.

5. **Parsing Items (`_parse_item()`):**
   - This method attempts to parse the next "item" in the TOML document, which can be a key-value pair, whitespace, or a comment.
   - It handles leading whitespace and comments before attempting to parse a key-value pair using `_parse_key_value()`.
   - If it encounters a `[` character, it assumes it's the start of a table and returns.

6. **Comment and Whitespace Handling (`_parse_comment_trail()`, `_merge_ws()`):**
   - `_parse_comment_trail()` extracts the whitespace before a comment, the comment itself, and any trailing whitespace/newlines after the comment. It performs checks for invalid control characters within comments.
   - `_merge_ws()` attempts to merge consecutive whitespace items in the parsed document, likely for efficiency or structural consistency.

7. **Key-Value Pair Parsing (`_parse_key_value()`):**
   - This method parses a key-value pair.
   - It extracts leading whitespace (indentation).
   - It calls `_parse_key()` to parse the key.
   - It looks for the `=` separator between the key and the value, handling potential whitespace around it.
   - It calls `_parse_value()` to parse the value.
   - It optionally parses comments following the value.

8. **Key Parsing (`_parse_key()`, `_parse_quoted_key()`, `_parse_bare_key()`):**
   - `_parse_key()` is the main method for parsing a key. It determines if the key is a bare key or a quoted key.
   - `_parse_quoted_key()` handles keys enclosed in single or double quotes.
   - `_parse_bare_key()` handles unquoted keys, checking for valid characters and spaces.
   - Both quoted and bare key parsing can handle dotted keys (representing nested tables).

9. **Value Parsing (`_parse_value()`):**
   - This is a crucial method that attempts to parse various TOML value types based on the current character:
     - Strings (basic and literal) using `_parse_basic_string()` and `_parse_literal_string()`.
     - Booleans using `_parse_true()` and `_parse_false()`.
     - Arrays using `_parse_array()`.
     - Inline tables using `_parse_inline_table()`.
     - Numbers (integers and floats), dates, times, and datetimes. It uses regular expressions (`RFC_3339_LOOSE`) to identify date/time formats and calls `parse_rfc3339()` to parse them. If it's not a date/time, it attempts to parse it as a number using `_parse_number()`.
   - It raises `UnexpectedCharError` if it encounters a character that cannot start a valid value.

10. **Boolean Parsing (`_parse_true()`, `_parse_false()`, `_parse_bool()`):**
    - These methods parse boolean values (`true` and `false`).

11. **Array Parsing (`_parse_array()`):**
    - Parses TOML arrays, handling whitespace, comments, and commas between elements.

12. **Inline Table Parsing (`_parse_inline_table()`):**
    - Parses inline tables (tables defined within curly braces `{}`). It handles whitespace, commas, and key-value pairs within the inline table.

13. **Number Parsing (`_parse_number()`):**
    - Attempts to parse a raw string as either an integer or a float.
    - It handles signs, different number bases (binary, octal, hexadecimal), and underscores as separators.
    - It performs checks for invalid leading zeros and misplaced decimal points.

14. **String Parsing (`_parse_literal_string()`, `_parse_basic_string()`, `_parse_escaped_char()`, `_parse_string()`):**
    - `_parse_literal_string()` handles literal strings (no escape sequences).
    - `_parse_basic_string()` handles basic strings with escape sequences.
    - `_parse_escaped_char()` parses the escape sequences within basic strings.
    - `_parse_string()` is the main method for parsing both types of strings, handling delimiters (single/double quotes, triple quotes for multiline strings), and calling the appropriate helper methods. It also performs checks for invalid control characters within strings.

15. **Table Parsing (`_parse_table()`):**
    - Parses table headers (e.g., `[table_name]` or `[section.subsection]`).
    - It identifies if it's a standard table or an element of an Array of Tables (`[[array_of_tables]]`).
    - It parses the table name (which can be a dotted key).
    - It handles comments following the table header.
    - It deals with the creation of nested tables if the table name is dotted.

**Relationship to Reverse Engineering:**

While this specific code doesn't directly perform reverse engineering tasks like disassembling or memory manipulation, it's a crucial component in the Frida ecosystem, which is heavily used for dynamic instrumentation in reverse engineering.

* **Configuration of Frida:** Reverse engineers often need to configure Frida's behavior, such as specifying target processes, scripts to load, breakpoints, etc. TOML files are a common way to store these configurations, and this parser is essential for Frida to understand those settings.
* **Configuration of Instrumentation Scripts:**  Frida scripts themselves might need configuration data. TOML files could be used to provide parameters, target function names, or other settings to the scripts. This parser would allow those scripts (or the Frida runtime) to read and use that configuration.
* **Analyzing Configuration Files of Applications:**  Sometimes, the target application itself uses TOML for its configuration. Reverse engineers might need to parse these configuration files to understand the application's behavior, settings, and potential vulnerabilities. Frida, using this parser, could be used to read and analyze these configuration files dynamically.

**Examples Related to Reverse Engineering:**

* **Scenario:** A reverse engineer wants to intercept and modify network requests made by an Android application. They might write a Frida script and configure it using a TOML file to specify the target application's package name and the specific functions related to network communication to hook. This `parser.py` would be used by Frida to read that TOML configuration.
* **Scenario:** A reverse engineer is analyzing a Linux binary and discovers that it reads its configuration from a `config.toml` file. They can use Frida and a simple script (potentially using `tomlkit` directly or indirectly through Frida's features) to parse this configuration file while the application is running to understand its current settings.

**Relationship to Binary底层, Linux, Android 内核及框架:**

This parser operates at the application layer, dealing with text-based configuration files. It doesn't directly interact with the binary level, kernel, or framework. However, the *purpose* of Frida, which uses this parser, is deeply intertwined with these low-level aspects:

* **Frida's Instrumentation:** Frida instruments processes at runtime by injecting code and hooking functions. This involves direct interaction with the operating system's process management, memory management, and potentially kernel calls. The TOML parser helps configure *which* parts of the system Frida should interact with.
* **Android Framework Interaction:** When used on Android, Frida can hook into the Android framework (e.g., Java APIs, native libraries). The TOML parser can be used to configure which framework components or APIs to target for instrumentation.
* **Linux Kernel Interaction:** Similarly, on Linux, Frida can interact with the kernel through system calls and kernel modules. TOML configuration could specify which kernel functions or modules to target.

**Examples Related to Binary 底层, Linux, Android 内核及框架:**

* **Scenario:** A reverse engineer wants to trace system calls made by a specific Android application. They could use a Frida script and a TOML configuration to specify the application's package name and a list of system call names to monitor. Frida, using this parser, would then know which system calls to intercept at the kernel level.
* **Scenario:** A security researcher wants to analyze the behavior of a Linux kernel module. They might use Frida and a TOML configuration to specify the module's name and specific functions within the module to hook and analyze.

**Logical Reasoning with Input and Output:**

**Assumption:** The input is a valid TOML string.

**Example 1 (Simple Key-Value):**

* **Input:**
  ```toml
  name = "Frida"
  version = 16.3
  ```
* **Output (Conceptual - `TOMLDocument` structure):**
  ```
  TOMLDocument({
      "name": String("Frida"),
      "version": Float(16.3)
  })
  ```

**Example 2 (Table):**

* **Input:**
  ```toml
  [package]
  name = "com.example.app"
  version = "1.0"
  ```
* **Output (Conceptual):**
  ```
  TOMLDocument({
      "package": Table({
          "name": String("com.example.app"),
          "version": String("1.0")
      })
  })
  ```

**Example 3 (Array):**

* **Input:**
  ```toml
  ports = [ 80, 8080, 9000 ]
  ```
* **Output (Conceptual):**
  ```
  TOMLDocument({
      "ports": Array([ Integer(80), Integer(8080), Integer(9000) ])
  })
  ```

**User or Programming Common Usage Errors:**

This parser is designed to be robust against syntax errors. Here are some examples of user errors that would lead to exceptions:

1. **Syntax Errors:**
   - **Missing Quotes:** `name = Frida` (results in `ParseError`)
   - **Mismatched Brackets:** `[table` (results in `UnexpectedEofError` or `UnexpectedCharError`)
   - **Invalid Characters:** `key! = "value"` (results in `UnexpectedCharError`)
   - **Incorrect Date/Time Format:** `date = 2023-13-01` (results in `InvalidDateError`)
   - **Invalid Number Format:** `version = 1.0.2` (results in `InvalidNumberError`)

2. **Type Errors (though TOML is loosely typed, structure matters):**
   - Trying to define the same table twice without using Array of Tables will lead to errors when appending to the `TOMLDocument`.

3. **Logical Errors (from the perspective of the user of the parsed data):**
   - While the parser won't catch these, the *meaning* of the configuration might be wrong for Frida's purposes. For example, specifying a non-existent process name.

**User Operation Steps to Reach This Code (as a Debugging Clue):**

1. **User writes a Frida script (JavaScript).**
2. **The script needs configuration data.**
3. **The user creates a TOML file (e.g., `config.toml`) containing the configuration.**
4. **The Frida script (or Frida itself) uses a mechanism to load and parse this TOML file.** This likely involves the `tomlkit` library.
5. **When the script or Frida attempts to parse the `config.toml` file, the `Parser` class in `tomlkit/parser.py` is instantiated and its `parse()` method is called.**
6. **The `parse()` method then proceeds to call the various `_parse_*` methods within the class to break down the TOML content.**
7. **If there are syntax errors in the `config.toml` file, the parser will raise exceptions (like `ParseError`, `UnexpectedCharError`, etc.), providing debugging information about the location of the error.**

**Summary of Functionality (Part 1):**

The first part of `tomlkit/parser.py` provides the foundational logic for parsing TOML documents. It handles the initial scanning and tokenization of the input string, recognizing basic elements like whitespace, comments, keys, and initiating the parsing of various value types (strings, numbers, booleans, arrays, inline tables) and table headers. It sets the stage for the subsequent parts of the parsing process, which will build the complete hierarchical representation of the TOML data.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tomlkit/parser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
from __future__ import annotations

import datetime
import re
import string

from tomlkit._compat import decode
from tomlkit._utils import RFC_3339_LOOSE
from tomlkit._utils import _escaped
from tomlkit._utils import parse_rfc3339
from tomlkit.container import Container
from tomlkit.exceptions import EmptyKeyError
from tomlkit.exceptions import EmptyTableNameError
from tomlkit.exceptions import InternalParserError
from tomlkit.exceptions import InvalidCharInStringError
from tomlkit.exceptions import InvalidControlChar
from tomlkit.exceptions import InvalidDateError
from tomlkit.exceptions import InvalidDateTimeError
from tomlkit.exceptions import InvalidNumberError
from tomlkit.exceptions import InvalidTimeError
from tomlkit.exceptions import InvalidUnicodeValueError
from tomlkit.exceptions import ParseError
from tomlkit.exceptions import UnexpectedCharError
from tomlkit.exceptions import UnexpectedEofError
from tomlkit.items import AoT
from tomlkit.items import Array
from tomlkit.items import Bool
from tomlkit.items import BoolType
from tomlkit.items import Comment
from tomlkit.items import Date
from tomlkit.items import DateTime
from tomlkit.items import Float
from tomlkit.items import InlineTable
from tomlkit.items import Integer
from tomlkit.items import Item
from tomlkit.items import Key
from tomlkit.items import KeyType
from tomlkit.items import Null
from tomlkit.items import SingleKey
from tomlkit.items import String
from tomlkit.items import StringType
from tomlkit.items import Table
from tomlkit.items import Time
from tomlkit.items import Trivia
from tomlkit.items import Whitespace
from tomlkit.source import Source
from tomlkit.toml_char import TOMLChar
from tomlkit.toml_document import TOMLDocument


CTRL_I = 0x09  # Tab
CTRL_J = 0x0A  # Line feed
CTRL_M = 0x0D  # Carriage return
CTRL_CHAR_LIMIT = 0x1F
CHR_DEL = 0x7F


class Parser:
    """
    Parser for TOML documents.
    """

    def __init__(self, string: str | bytes) -> None:
        # Input to parse
        self._src = Source(decode(string))

        self._aot_stack: list[Key] = []

    @property
    def _state(self):
        return self._src.state

    @property
    def _idx(self):
        return self._src.idx

    @property
    def _current(self):
        return self._src.current

    @property
    def _marker(self):
        return self._src.marker

    def extract(self) -> str:
        """
        Extracts the value between marker and index
        """
        return self._src.extract()

    def inc(self, exception: type[ParseError] | None = None) -> bool:
        """
        Increments the parser if the end of the input has not been reached.
        Returns whether or not it was able to advance.
        """
        return self._src.inc(exception=exception)

    def inc_n(self, n: int, exception: type[ParseError] | None = None) -> bool:
        """
        Increments the parser by n characters
        if the end of the input has not been reached.
        """
        return self._src.inc_n(n=n, exception=exception)

    def consume(self, chars, min=0, max=-1):
        """
        Consume chars until min/max is satisfied is valid.
        """
        return self._src.consume(chars=chars, min=min, max=max)

    def end(self) -> bool:
        """
        Returns True if the parser has reached the end of the input.
        """
        return self._src.end()

    def mark(self) -> None:
        """
        Sets the marker to the index's current position
        """
        self._src.mark()

    def parse_error(self, exception=ParseError, *args, **kwargs):
        """
        Creates a generic "parse error" at the current position.
        """
        return self._src.parse_error(exception, *args, **kwargs)

    def parse(self) -> TOMLDocument:
        body = TOMLDocument(True)

        # Take all keyvals outside of tables/AoT's.
        while not self.end():
            # Break out if a table is found
            if self._current == "[":
                break

            # Otherwise, take and append one KV
            item = self._parse_item()
            if not item:
                break

            key, value = item
            if (key is not None and key.is_multi()) or not self._merge_ws(value, body):
                # We actually have a table
                try:
                    body.append(key, value)
                except Exception as e:
                    raise self.parse_error(ParseError, str(e)) from e

            self.mark()

        while not self.end():
            key, value = self._parse_table()
            if isinstance(value, Table) and value.is_aot_element():
                # This is just the first table in an AoT. Parse the rest of the array
                # along with it.
                value = self._parse_aot(value, key)

            try:
                body.append(key, value)
            except Exception as e:
                raise self.parse_error(ParseError, str(e)) from e

        body.parsing(False)

        return body

    def _merge_ws(self, item: Item, container: Container) -> bool:
        """
        Merges the given Item with the last one currently in the given Container if
        both are whitespace items.

        Returns True if the items were merged.
        """
        last = container.last_item()
        if not last:
            return False

        if not isinstance(item, Whitespace) or not isinstance(last, Whitespace):
            return False

        start = self._idx - (len(last.s) + len(item.s))
        container.body[-1] = (
            container.body[-1][0],
            Whitespace(self._src[start : self._idx]),
        )

        return True

    def _is_child(self, parent: Key, child: Key) -> bool:
        """
        Returns whether a key is strictly a child of another key.
        AoT siblings are not considered children of one another.
        """
        parent_parts = tuple(parent)
        child_parts = tuple(child)

        if parent_parts == child_parts:
            return False

        return parent_parts == child_parts[: len(parent_parts)]

    def _parse_item(self) -> tuple[Key | None, Item] | None:
        """
        Attempts to parse the next item and returns it, along with its key
        if the item is value-like.
        """
        self.mark()
        with self._state as state:
            while True:
                c = self._current
                if c == "\n":
                    # Found a newline; Return all whitespace found up to this point.
                    self.inc()

                    return None, Whitespace(self.extract())
                elif c in " \t\r":
                    # Skip whitespace.
                    if not self.inc():
                        return None, Whitespace(self.extract())
                elif c == "#":
                    # Found a comment, parse it
                    indent = self.extract()
                    cws, comment, trail = self._parse_comment_trail()

                    return None, Comment(Trivia(indent, cws, comment, trail))
                elif c == "[":
                    # Found a table, delegate to the calling function.
                    return
                else:
                    # Beginning of a KV pair.
                    # Return to beginning of whitespace so it gets included
                    # as indentation for the KV about to be parsed.
                    state.restore = True
                    break

        return self._parse_key_value(True)

    def _parse_comment_trail(self, parse_trail: bool = True) -> tuple[str, str, str]:
        """
        Returns (comment_ws, comment, trail)
        If there is no comment, comment_ws and comment will
        simply be empty.
        """
        if self.end():
            return "", "", ""

        comment = ""
        comment_ws = ""
        self.mark()

        while True:
            c = self._current

            if c == "\n":
                break
            elif c == "#":
                comment_ws = self.extract()

                self.mark()
                self.inc()  # Skip #

                # The comment itself
                while not self.end() and not self._current.is_nl():
                    code = ord(self._current)
                    if code == CHR_DEL or code <= CTRL_CHAR_LIMIT and code != CTRL_I:
                        raise self.parse_error(InvalidControlChar, code, "comments")

                    if not self.inc():
                        break

                comment = self.extract()
                self.mark()

                break
            elif c in " \t\r":
                self.inc()
            else:
                raise self.parse_error(UnexpectedCharError, c)

            if self.end():
                break

        trail = ""
        if parse_trail:
            while self._current.is_spaces() and self.inc():
                pass

            if self._current == "\r":
                self.inc()

            if self._current == "\n":
                self.inc()

            if self._idx != self._marker or self._current.is_ws():
                trail = self.extract()

        return comment_ws, comment, trail

    def _parse_key_value(self, parse_comment: bool = False) -> tuple[Key, Item]:
        # Leading indent
        self.mark()

        while self._current.is_spaces() and self.inc():
            pass

        indent = self.extract()

        # Key
        key = self._parse_key()

        self.mark()

        found_equals = self._current == "="
        while self._current.is_kv_sep() and self.inc():
            if self._current == "=":
                if found_equals:
                    raise self.parse_error(UnexpectedCharError, "=")
                else:
                    found_equals = True
        if not found_equals:
            raise self.parse_error(UnexpectedCharError, self._current)

        if not key.sep:
            key.sep = self.extract()
        else:
            key.sep += self.extract()

        # Value
        val = self._parse_value()
        # Comment
        if parse_comment:
            cws, comment, trail = self._parse_comment_trail()
            meta = val.trivia
            if not meta.comment_ws:
                meta.comment_ws = cws

            meta.comment = comment
            meta.trail = trail
        else:
            val.trivia.trail = ""

        val.trivia.indent = indent

        return key, val

    def _parse_key(self) -> Key:
        """
        Parses a Key at the current position;
        WS before the key must be exhausted first at the callsite.
        """
        self.mark()
        while self._current.is_spaces() and self.inc():
            # Skip any leading whitespace
            pass
        if self._current in "\"'":
            return self._parse_quoted_key()
        else:
            return self._parse_bare_key()

    def _parse_quoted_key(self) -> Key:
        """
        Parses a key enclosed in either single or double quotes.
        """
        # Extract the leading whitespace
        original = self.extract()
        quote_style = self._current
        key_type = next((t for t in KeyType if t.value == quote_style), None)

        if key_type is None:
            raise RuntimeError("Should not have entered _parse_quoted_key()")

        key_str = self._parse_string(
            StringType.SLB if key_type == KeyType.Basic else StringType.SLL
        )
        if key_str._t.is_multiline():
            raise self.parse_error(UnexpectedCharError, key_str._t.value)
        original += key_str.as_string()
        self.mark()
        while self._current.is_spaces() and self.inc():
            pass
        original += self.extract()
        key = SingleKey(str(key_str), t=key_type, sep="", original=original)
        if self._current == ".":
            self.inc()
            key = key.concat(self._parse_key())

        return key

    def _parse_bare_key(self) -> Key:
        """
        Parses a bare key.
        """
        while (
            self._current.is_bare_key_char() or self._current.is_spaces()
        ) and self.inc():
            pass

        original = self.extract()
        key = original.strip()
        if not key:
            # Empty key
            raise self.parse_error(EmptyKeyError)

        if " " in key:
            # Bare key with spaces in it
            raise self.parse_error(ParseError, f'Invalid key "{key}"')

        key = SingleKey(key, KeyType.Bare, "", original)

        if self._current == ".":
            self.inc()
            key = key.concat(self._parse_key())

        return key

    def _parse_value(self) -> Item:
        """
        Attempts to parse a value at the current position.
        """
        self.mark()
        c = self._current
        trivia = Trivia()

        if c == StringType.SLB.value:
            return self._parse_basic_string()
        elif c == StringType.SLL.value:
            return self._parse_literal_string()
        elif c == BoolType.TRUE.value[0]:
            return self._parse_true()
        elif c == BoolType.FALSE.value[0]:
            return self._parse_false()
        elif c == "[":
            return self._parse_array()
        elif c == "{":
            return self._parse_inline_table()
        elif c in "+-" or self._peek(4) in {
            "+inf",
            "-inf",
            "inf",
            "+nan",
            "-nan",
            "nan",
        }:
            # Number
            while self._current not in " \t\n\r#,]}" and self.inc():
                pass

            raw = self.extract()

            item = self._parse_number(raw, trivia)
            if item is not None:
                return item

            raise self.parse_error(InvalidNumberError)
        elif c in string.digits:
            # Integer, Float, Date, Time or DateTime
            while self._current not in " \t\n\r#,]}" and self.inc():
                pass

            raw = self.extract()

            m = RFC_3339_LOOSE.match(raw)
            if m:
                if m.group(1) and m.group(5):
                    # datetime
                    try:
                        dt = parse_rfc3339(raw)
                        assert isinstance(dt, datetime.datetime)
                        return DateTime(
                            dt.year,
                            dt.month,
                            dt.day,
                            dt.hour,
                            dt.minute,
                            dt.second,
                            dt.microsecond,
                            dt.tzinfo,
                            trivia,
                            raw,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidDateTimeError)

                if m.group(1):
                    try:
                        dt = parse_rfc3339(raw)
                        assert isinstance(dt, datetime.date)
                        date = Date(dt.year, dt.month, dt.day, trivia, raw)
                        self.mark()
                        while self._current not in "\t\n\r#,]}" and self.inc():
                            pass

                        time_raw = self.extract()
                        time_part = time_raw.rstrip()
                        trivia.comment_ws = time_raw[len(time_part) :]
                        if not time_part:
                            return date

                        dt = parse_rfc3339(raw + time_part)
                        assert isinstance(dt, datetime.datetime)
                        return DateTime(
                            dt.year,
                            dt.month,
                            dt.day,
                            dt.hour,
                            dt.minute,
                            dt.second,
                            dt.microsecond,
                            dt.tzinfo,
                            trivia,
                            raw + time_part,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidDateError)

                if m.group(5):
                    try:
                        t = parse_rfc3339(raw)
                        assert isinstance(t, datetime.time)
                        return Time(
                            t.hour,
                            t.minute,
                            t.second,
                            t.microsecond,
                            t.tzinfo,
                            trivia,
                            raw,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidTimeError)

            item = self._parse_number(raw, trivia)
            if item is not None:
                return item

            raise self.parse_error(InvalidNumberError)
        else:
            raise self.parse_error(UnexpectedCharError, c)

    def _parse_true(self):
        return self._parse_bool(BoolType.TRUE)

    def _parse_false(self):
        return self._parse_bool(BoolType.FALSE)

    def _parse_bool(self, style: BoolType) -> Bool:
        with self._state:
            style = BoolType(style)

            # only keep parsing for bool if the characters match the style
            # try consuming rest of chars in style
            for c in style:
                self.consume(c, min=1, max=1)

            return Bool(style, Trivia())

    def _parse_array(self) -> Array:
        # Consume opening bracket, EOF here is an issue (middle of array)
        self.inc(exception=UnexpectedEofError)

        elems: list[Item] = []
        prev_value = None
        while True:
            # consume whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES + TOMLChar.NL)
            indent = self._src[mark : self._idx]
            newline = set(TOMLChar.NL) & set(indent)
            if newline:
                elems.append(Whitespace(indent))
                continue

            # consume comment
            if self._current == "#":
                cws, comment, trail = self._parse_comment_trail(parse_trail=False)
                elems.append(Comment(Trivia(indent, cws, comment, trail)))
                continue

            # consume indent
            if indent:
                elems.append(Whitespace(indent))
                continue

            # consume value
            if not prev_value:
                try:
                    elems.append(self._parse_value())
                    prev_value = True
                    continue
                except UnexpectedCharError:
                    pass

            # consume comma
            if prev_value and self._current == ",":
                self.inc(exception=UnexpectedEofError)
                elems.append(Whitespace(","))
                prev_value = False
                continue

            # consume closing bracket
            if self._current == "]":
                # consume closing bracket, EOF here doesn't matter
                self.inc()
                break

            raise self.parse_error(UnexpectedCharError, self._current)

        try:
            res = Array(elems, Trivia())
        except ValueError:
            pass
        else:
            return res

    def _parse_inline_table(self) -> InlineTable:
        # consume opening bracket, EOF here is an issue (middle of array)
        self.inc(exception=UnexpectedEofError)

        elems = Container(True)
        trailing_comma = None
        while True:
            # consume leading whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES)
            raw = self._src[mark : self._idx]
            if raw:
                elems.add(Whitespace(raw))

            if not trailing_comma:
                # None: empty inline table
                # False: previous key-value pair was not followed by a comma
                if self._current == "}":
                    # consume closing bracket, EOF here doesn't matter
                    self.inc()
                    break

                if (
                    trailing_comma is False
                    or trailing_comma is None
                    and self._current == ","
                ):
                    # Either the previous key-value pair was not followed by a comma
                    # or the table has an unexpected leading comma.
                    raise self.parse_error(UnexpectedCharError, self._current)
            else:
                # True: previous key-value pair was followed by a comma
                if self._current == "}" or self._current == ",":
                    raise self.parse_error(UnexpectedCharError, self._current)

            key, val = self._parse_key_value(False)
            elems.add(key, val)

            # consume trailing whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES)
            raw = self._src[mark : self._idx]
            if raw:
                elems.add(Whitespace(raw))

            # consume trailing comma
            trailing_comma = self._current == ","
            if trailing_comma:
                # consume closing bracket, EOF here is an issue (middle of inline table)
                self.inc(exception=UnexpectedEofError)

        return InlineTable(elems, Trivia())

    def _parse_number(self, raw: str, trivia: Trivia) -> Item | None:
        # Leading zeros are not allowed
        sign = ""
        if raw.startswith(("+", "-")):
            sign = raw[0]
            raw = raw[1:]

        if len(raw) > 1 and (
            raw.startswith("0")
            and not raw.startswith(("0.", "0o", "0x", "0b", "0e"))
            or sign
            and raw.startswith(".")
        ):
            return None

        if raw.startswith(("0o", "0x", "0b")) and sign:
            return None

        digits = "[0-9]"
        base = 10
        if raw.startswith("0b"):
            digits = "[01]"
            base = 2
        elif raw.startswith("0o"):
            digits = "[0-7]"
            base = 8
        elif raw.startswith("0x"):
            digits = "[0-9a-f]"
            base = 16

        # Underscores should be surrounded by digits
        clean = re.sub(f"(?i)(?<={digits})_(?={digits})", "", raw).lower()

        if "_" in clean:
            return None

        if (
            clean.endswith(".")
            or not clean.startswith("0x")
            and clean.split("e", 1)[0].endswith(".")
        ):
            return None

        try:
            return Integer(int(sign + clean, base), trivia, sign + raw)
        except ValueError:
            try:
                return Float(float(sign + clean), trivia, sign + raw)
            except ValueError:
                return None

    def _parse_literal_string(self) -> String:
        with self._state:
            return self._parse_string(StringType.SLL)

    def _parse_basic_string(self) -> String:
        with self._state:
            return self._parse_string(StringType.SLB)

    def _parse_escaped_char(self, multiline):
        if multiline and self._current.is_ws():
            # When the last non-whitespace character on a line is
            # a \, it will be trimmed along with all whitespace
            # (including newlines) up to the next non-whitespace
            # character or closing delimiter.
            # """\
            #     hello \
            #     world"""
            tmp = ""
            while self._current.is_ws():
                tmp += self._current
                # consume the whitespace, EOF here is an issue
                # (middle of string)
                self.inc(exception=UnexpectedEofError)
                continue

            # the escape followed by whitespace must have a newline
            # before any other chars
            if "\n" not in tmp:
                raise self.parse_error(InvalidCharInStringError, self._current)

            return ""

        if self._current in _escaped:
            c = _escaped[self._current]

            # consume this char, EOF here is an issue (middle of string)
            self.inc(exception=UnexpectedEofError)

            return c

        if self._current in {"u", "U"}:
            # this needs to be a unicode
            u, ue = self._peek_unicode(self._current == "U")
            if u is not None:
                # consume the U char and the unicode value
                self.inc_n(len(ue) + 1)

                return u

            raise self.parse_error(InvalidUnicodeValueError)

        raise self.parse_error(InvalidCharInStringError, self._current)

    def _parse_string(self, delim: StringType) -> String:
        # only keep parsing for string if the current character matches the delim
        if self._current != delim.unit:
            raise self.parse_error(
                InternalParserError,
                f"Invalid character for string type {delim}",
            )

        # consume the opening/first delim, EOF here is an issue
        # (middle of string or middle of delim)
        self.inc(exception=UnexpectedEofError)

        if self._current == delim.unit:
            # consume the closing/second delim, we do not care if EOF occurs as
            # that would simply imply an empty single line string
            if not self.inc() or self._current != delim.unit:
                # Empty string
                return String(delim, "", "", Trivia())

            # consume the third delim, EOF here is an issue (middle of string)
            self.inc(exception=UnexpectedEofError)

            delim = delim.toggle()  # convert delim to multi delim

        self.mark()  # to extract the original string with whitespace and all
        value = ""

        # A newline immediately following the opening delimiter will be trimmed.
        if delim.is_multiline():
            if self._current == "\n":
                # consume the newline, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)
            else:
                cur = self._current
                with self._state(restore=True):
                    if self.inc():
                        cur += self._current
                if cur == "\r\n":
                    self.inc_n(2, exception=UnexpectedEofError)

        escaped = False  # whether the previous key was ESCAPE
        while True:
            code = ord(self._current)
            if (
                delim.is_singleline()
                and not escaped
                and (code == CHR_DEL or code <= CTRL_CHAR_LIMIT and code != CTRL_I)
            ) or (
                delim.is_multiline()
                and not escaped
                and (
                    code == CHR_DEL
                    or code <= CTRL_CHAR_LIMIT
                    and code not in [CTRL_I, CTRL_J, CTRL_M]
                )
            ):
                raise self.parse_error(InvalidControlChar, code, "strings")
            elif not escaped and self._current == delim.unit:
                # try to process current as a closing delim
                original = self.extract()

                close = ""
                if delim.is_multiline():
                    # Consume the delimiters to see if we are at the end of the string
                    close = ""
                    while self._current == delim.unit:
                        close += self._current
                        self.inc()

                    if len(close) < 3:
                        # Not a triple quote, leave in result as-is.
                        # Adding back the characters we already consumed
                        value += close
                        continue

                    if len(close) == 3:
                        # We are at the end of the string
                        return String(delim, value, original, Trivia())

                    if len(close) >= 6:
                        raise self.parse_error(InvalidCharInStringError, self._current)

                    value += close[:-3]
                    original += close[:-3]

                    return String(delim, value, original, Trivia())
                else:
                    # consume the closing delim, we do not care if EOF occurs as
                    # that would simply imply the end of self._src
                    self.inc()

                return String(delim, value, original, Trivia())
            elif delim.is_basic() and escaped:
                # attempt to parse the current char as an escaped value, an exception
                # is raised if this fails
                value += self._parse_escaped_char(delim.is_multiline())

                # no longer escaped
                escaped = False
            elif delim.is_basic() and self._current == "\\":
                # the next char is being escaped
                escaped = True

                # consume this char, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)
            else:
                # this is either a literal string where we keep everything as is,
                # or this is not a special escaped char in a basic string
                value += self._current

                # consume this char, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)

    def _parse_table(
        self, parent_name: Key | None = None, parent: Table | None = None
    ) -> tuple[Key, Table | AoT]:
        """
        Parses a table element.
        """
        if self._current != "[":
            raise self.parse_error(
                InternalParserError, "_parse_table() called on non-bracket character."
            )

        indent = self.extract()
        self.inc()  # Skip opening bracket

        if self.end():
            raise self.parse_error(UnexpectedEofError)

        is_aot = False
        if self._current == "[":
            if not self.inc():
                raise self.parse_error(UnexpectedEofError)

            is_aot = True
        try:
            key = self._parse_key()
        except EmptyKeyError:
            raise self.parse_error(EmptyTableNameError) from None
        if self.end():
            raise self.parse_error(UnexpectedEofError)
        elif self._current != "]":
            raise self.parse_error(UnexpectedCharError, self._current)

        key.sep = ""
        full_key = key
        name_parts = tuple(key)
        if any(" " in part.key.strip() and part.is_bare() for part in name_parts):
            raise self.parse_error(
                ParseError, f'Invalid table name "{full_key.as_string()}"'
            )

        missing_table = False
        if parent_name:
            parent_name_parts = tuple(parent_name)
        else:
            parent_name_parts = ()

        if len(name_parts) > len(parent_name_parts) + 1:
            missing_table = True

        name_parts = name_parts[len(parent_name_parts) :]

        values = Container(True)

        self.inc()  # Skip closing bracket
        if is_aot:
            # TODO: Verify close bracket
            self.inc()

        cws, comment, trail = self._parse_comment_trail()

        result = Null()
        table = Table(
            values,
            Trivia(indent, cws, comment, trail),
            is_aot,
            name=name_parts[0].key if name_parts else key.key,
            display_name=full_key.as_string(),
            is_super_table=False,
        )

        if len(name_parts) > 1:
            if missing_table:
                # Missing super table
                # i.e. a table initialized like this: [foo.bar]
                # without initializing [foo]
                #
                # So we have to create the parent tables
                table = Table(
                    Container(True),
                    Trivia("", cws, comment, trail),
                    is_aot and name_parts[0] in self._aot_stack,
                    is_super_table=True,
                    name=name_parts[0].key,
                )

            result = table
            key = name_parts[0]

            for i, _name in enumerate(name_parts[1:]):
                child = table.get(
                    _name,
                    Table(
                        Container(True),
                        Trivia(indent, cws, comment, trail),
                        is_aot and i == len(name_parts) - 2,
                        is_super_table=i < len(name_parts) - 2,
                        name=_name.key,
                        display_name=full_key.as_string()
                        if i == len(name_parts) - 2
                        else None,
                    ),
                )
```