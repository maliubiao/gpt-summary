Response:
The user wants a summary of the functionality of the provided C++ code snippet from `editor_command.cc`. This is the third part of a four-part series. I need to:

1. **Identify the primary function:** The code defines and manages editor commands in the Chromium Blink engine.
2. **List key functionalities based on the code:** This involves mapping command names to their corresponding execution functions and related properties.
3. **Explain relationships with web technologies:**  Connect the commands to user interactions with HTML, CSS, and JavaScript.
4. **Provide examples of input and output:**  Illustrate how these commands might be triggered and their effects.
5. **Highlight common usage errors:**  Mention potential issues users or developers might encounter.
6. **Describe the user journey:** Explain how user actions lead to the execution of these commands.
7. **Summarize the specific content of this part:** Focus on the large table defining the commands and their properties.

**Plan:**

* **Functionality:** Focus on the table of `kEditorCommands` and how it maps command names to actions and properties.
* **Web technology relationship:**  Relate specific commands (like `bold`, `italic`, text navigation, paste) to their impact on HTML structure and CSS styles, and how JavaScript can trigger them.
* **Input/Output:** Use examples like pressing "Ctrl+B" (input) leading to bold text (output).
* **Usage errors:** Think about scenarios where commands might not work as expected (e.g., trying to bold text in a non-editable area).
* **User journey:** Describe clicking menu items, pressing keyboard shortcuts, or JavaScript calls triggering commands.
* **Part summary:** Emphasize that this section details the definitions of various editing commands and their associated attributes.
这是 `blink/renderer/core/editing/commands/editor_command.cc` 文件的第三部分，主要功能是**定义和配置各种可执行的编辑命令**。

**功能归纳:**

这部分代码的核心是一个名为 `kEditorCommands` 的静态常量数组。这个数组定义了 Blink 引擎中支持的各种编辑命令，以及与这些命令相关的属性和行为。 数组中的每个元素都描述了一个特定的编辑命令，包含了以下信息：

* **`EditingCommandType`**:  枚举类型，唯一标识一个编辑命令。
* **执行函数**:  指向实际执行该命令的 C++ 函数的指针，例如 `StyleCommands::ExecuteBold`, `MoveCommands::ExecuteMoveForward`, `ClipboardCommands::ExecutePaste` 等。这些函数分布在不同的命名空间下，根据命令的类型进行组织（样式、移动、剪贴板等）。
* **支持性标志**:  布尔标志，指示该命令是否可以通过菜单或快捷键 (`SupportedFromMenuOrKeyBinding`) 以及 DOM (`Supported`) 触发。
* **启用条件**:  枚举类型，定义了命令可以被执行的条件，例如 `EnabledInRichlyEditableText` (在富文本可编辑区域启用), `EnabledVisibleSelection` (当有可见选中内容时启用), `EnabledInEditableTextOrCaretBrowsing` (在可编辑文本区域或光标浏览模式下启用) 等。
* **状态查询函数**:  指向查询命令当前状态（例如是否已应用）的 C++ 函数的指针，例如 `StyleCommands::StateBold` 返回当前选中文本是否为粗体。
* **值查询函数**:  指向获取命令相关值的 C++ 函数的指针。
* **是否为文本插入**:  布尔标志，指示该命令是否属于文本插入操作。
* **禁用时是否可执行**: 布尔标志，指示命令在禁用状态下是否可以执行。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些编辑命令直接影响用户在网页上的文本编辑行为，因此与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **HTML**:  许多命令直接修改 HTML 结构或内容。
    * **例子**: `InsertText` 命令会将文本插入到 HTML 文档中。`Delete` 命令会删除 HTML 节点或文本内容。`MakeUnorderedList` 或 `MakeOrderedList` 命令会将选中的文本转换为无序或有序列表，修改 HTML 标签结构。
* **CSS**:  样式相关的命令会修改元素的 CSS 属性，从而改变文本的显示效果。
    * **例子**: `ToggleBold` 命令会添加或移除 `font-weight: bold` 样式。`ForeColor` 命令会改变文本的 `color` 属性。`JustifyCenter` 命令会设置文本的 `text-align: center` 属性。
* **JavaScript**:  JavaScript 可以通过 `document.execCommand()` 方法来触发这些编辑命令。
    * **例子**:  `document.execCommand('bold')`  相当于触发 `ToggleBold` 命令。开发者可以编写 JavaScript 代码来实现自定义的工具栏按钮或快捷键来执行这些命令。

**逻辑推理 (假设输入与输出):**

假设用户在一个可编辑的 `div` 元素中选中了一段文本 "hello"，并且：

* **假设输入**: 用户按下 "Ctrl + B" 快捷键（通常映射到 `ToggleBold` 命令）。
* **逻辑推理**:
    1. 浏览器识别到快捷键 "Ctrl + B"。
    2. 浏览器查找与该快捷键关联的编辑命令，通常是 `ToggleBold`。
    3. `Editor::ExecuteCommand("ToggleBold")` 被调用。
    4. `InternalCommand("ToggleBold")` 返回指向 `kEditorCommands` 数组中 `EditingCommandType::kToggleBold` 对应项的指针。
    5. 检查 `ToggleBold` 命令的启用条件 (`EnabledInRichlyEditableText`) 是否满足。
    6. 调用 `StyleCommands::ExecuteToggleBold` 函数，该函数会修改选中文本的样式，添加或移除 `<b>` 标签或相应的 CSS 样式。
* **输出**: 选中的文本 "hello" 会变为粗体显示。

**用户或编程常见的使用错误举例说明:**

* **在非可编辑区域执行编辑命令**: 用户尝试在非 `contenteditable` 的元素上使用编辑相关的快捷键或调用 `document.execCommand()`，这些命令通常不会生效或者会抛出异常。
    * **例子**: 用户在一个普通的 `<div>` 元素中选中文字，并按下 "Ctrl + B"，文本不会变为粗体。
* **JavaScript 调用 `document.execCommand()` 时使用了错误的命令名称**:  如果传递给 `execCommand()` 的字符串与 `kEditorCommands` 中定义的命令名称不匹配，命令将不会被执行。
    * **例子**: `document.execCommand('blod')` (拼写错误) 不会使文本变为粗体。
* **依赖于特定的命令在所有浏览器中的行为一致**: 虽然 Blink 实现了这些标准编辑命令，但其他浏览器引擎的实现可能存在细微差异，开发者需要注意跨浏览器兼容性问题。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户交互**: 用户进行了某些操作，例如：
    * **键盘输入**:  按下快捷键 (例如 "Ctrl+C", "Ctrl+V", "Ctrl+B", 方向键等)。
    * **鼠标操作**:  点击编辑菜单项 (例如 "复制", "粘贴", "加粗" 等)。
    * **JavaScript 调用**:  网页上的 JavaScript 代码调用了 `document.execCommand()` 方法。
2. **事件捕获**: 浏览器捕获到这些用户交互产生的事件 (例如 `keydown`, `mouseup`, 用户自定义事件等)。
3. **事件处理**: 浏览器的事件处理机制识别出这些事件与编辑操作相关。
4. **命令查找**: 浏览器根据事件类型或 `document.execCommand()` 的参数，查找对应的 `EditingCommandType`。
5. **`Editor::ExecuteCommand()` 调用**:  通常会调用 `Editor::ExecuteCommand()` 函数，并将命令名称作为参数传递进去。
6. **`InternalCommand()` 调用**: `Editor::ExecuteCommand()` 内部会调用 `InternalCommand()` 函数，根据命令名称在 `kEditorCommands` 数组中查找对应的命令定义。
7. **执行函数调用**:  找到对应的命令定义后，会调用该定义中指定的执行函数 (例如 `StyleCommands::ExecuteBold`) 来执行具体的编辑操作。

在调试过程中，如果需要追踪某个编辑命令的执行流程，可以在 `Editor::ExecuteCommand()` 或相关的执行函数中设置断点，观察参数和执行过程。

**本部分功能总结:**

这部分代码的核心作用是**维护一个包含了所有 Blink 引擎支持的编辑命令的注册表**。它将命令名称映射到具体的执行函数、启用条件、状态查询等信息，为浏览器的文本编辑功能提供了基础框架。当用户进行编辑操作时，浏览器会根据这个注册表来确定应该执行哪个命令以及如何执行。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/editor_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
alueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMakeTextWritingDirectionLeftToRight,
       StyleCommands::ExecuteMakeTextWritingDirectionLeftToRight,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateTextWritingDirectionLeftToRight, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMakeTextWritingDirectionNatural,
       StyleCommands::ExecuteMakeTextWritingDirectionNatural,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateTextWritingDirectionNatural, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMakeTextWritingDirectionRightToLeft,
       StyleCommands::ExecuteMakeTextWritingDirectionRightToLeft,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateTextWritingDirectionRightToLeft, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveBackward, MoveCommands::ExecuteMoveBackward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveBackwardAndModifySelection,
       MoveCommands::ExecuteMoveBackwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveDown, MoveCommands::ExecuteMoveDown,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveDownAndModifySelection,
       MoveCommands::ExecuteMoveDownAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveForward, MoveCommands::ExecuteMoveForward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveForwardAndModifySelection,
       MoveCommands::ExecuteMoveForwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveLeft, MoveCommands::ExecuteMoveLeft,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveLeftAndModifySelection,
       MoveCommands::ExecuteMoveLeftAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMovePageDown, MoveCommands::ExecuteMovePageDown,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMovePageDownAndModifySelection,
       MoveCommands::ExecuteMovePageDownAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMovePageUp, MoveCommands::ExecuteMovePageUp,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMovePageUpAndModifySelection,
       MoveCommands::ExecuteMovePageUpAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveParagraphBackward,
       MoveCommands::ExecuteMoveParagraphBackward,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveParagraphBackwardAndModifySelection,
       MoveCommands::ExecuteMoveParagraphBackwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveParagraphForward,
       MoveCommands::ExecuteMoveParagraphForward, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveParagraphForwardAndModifySelection,
       MoveCommands::ExecuteMoveParagraphForwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveRight, MoveCommands::ExecuteMoveRight,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveRightAndModifySelection,
       MoveCommands::ExecuteMoveRightAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfDocument,
       MoveCommands::ExecuteMoveToBeginningOfDocument,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfDocumentAndModifySelection,
       MoveCommands::ExecuteMoveToBeginningOfDocumentAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfLine,
       MoveCommands::ExecuteMoveToBeginningOfLine,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfLineAndModifySelection,
       MoveCommands::ExecuteMoveToBeginningOfLineAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfParagraph,
       MoveCommands::ExecuteMoveToBeginningOfParagraph,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfParagraphAndModifySelection,
       MoveCommands::ExecuteMoveToBeginningOfParagraphAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfSentence,
       MoveCommands::ExecuteMoveToBeginningOfSentence,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToBeginningOfSentenceAndModifySelection,
       MoveCommands::ExecuteMoveToBeginningOfSentenceAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfDocument,
       MoveCommands::ExecuteMoveToEndOfDocument, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfDocumentAndModifySelection,
       MoveCommands::ExecuteMoveToEndOfDocumentAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfLine,
       MoveCommands::ExecuteMoveToEndOfLine, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfLineAndModifySelection,
       MoveCommands::ExecuteMoveToEndOfLineAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfParagraph,
       MoveCommands::ExecuteMoveToEndOfParagraph, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfParagraphAndModifySelection,
       MoveCommands::ExecuteMoveToEndOfParagraphAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfSentence,
       MoveCommands::ExecuteMoveToEndOfSentence, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToEndOfSentenceAndModifySelection,
       MoveCommands::ExecuteMoveToEndOfSentenceAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToLeftEndOfLine,
       MoveCommands::ExecuteMoveToLeftEndOfLine, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToLeftEndOfLineAndModifySelection,
       MoveCommands::ExecuteMoveToLeftEndOfLineAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToRightEndOfLine,
       MoveCommands::ExecuteMoveToRightEndOfLine, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveToRightEndOfLineAndModifySelection,
       MoveCommands::ExecuteMoveToRightEndOfLineAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveUp, MoveCommands::ExecuteMoveUp,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveUpAndModifySelection,
       MoveCommands::ExecuteMoveUpAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordBackward,
       MoveCommands::ExecuteMoveWordBackward, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordBackwardAndModifySelection,
       MoveCommands::ExecuteMoveWordBackwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordForward,
       MoveCommands::ExecuteMoveWordForward, SupportedFromMenuOrKeyBinding,
       EnabledInEditableTextOrCaretBrowsing, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordForwardAndModifySelection,
       MoveCommands::ExecuteMoveWordForwardAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordLeft, MoveCommands::ExecuteMoveWordLeft,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordLeftAndModifySelection,
       MoveCommands::ExecuteMoveWordLeftAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordRight, MoveCommands::ExecuteMoveWordRight,
       SupportedFromMenuOrKeyBinding, EnabledInEditableTextOrCaretBrowsing,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kMoveWordRightAndModifySelection,
       MoveCommands::ExecuteMoveWordRightAndModifySelection,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kOutdent, ExecuteOutdent, Supported,
       EnabledInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kOverWrite, ExecuteToggleOverwrite,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kPaste, ClipboardCommands::ExecutePaste,
       ClipboardCommands::PasteSupported, ClipboardCommands::EnabledPaste,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       ClipboardCommands::CanReadClipboard},
      {EditingCommandType::kPasteAndMatchStyle,
       ClipboardCommands::ExecutePasteAndMatchStyle, Supported,
       ClipboardCommands::EnabledPaste, StateNone, ValueStateOrNull,
       kNotTextInsertion, ClipboardCommands::CanReadClipboard},
      {EditingCommandType::kPasteGlobalSelection,
       ClipboardCommands::ExecutePasteGlobalSelection,
       SupportedFromMenuOrKeyBinding, ClipboardCommands::EnabledPaste,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       ClipboardCommands::CanReadClipboard},
      {EditingCommandType::kPrint, ExecutePrint, Supported, Enabled, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kRedo, ExecuteRedo, Supported, EnabledRedo,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kRemoveFormat, ExecuteRemoveFormat, Supported,
       EnabledRangeInEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollPageBackward, ExecuteScrollPageBackward,
       SupportedFromMenuOrKeyBinding, Enabled, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollPageForward, ExecuteScrollPageForward,
       SupportedFromMenuOrKeyBinding, Enabled, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollLineUp, ExecuteScrollLineUp,
       SupportedFromMenuOrKeyBinding, Enabled, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollLineDown, ExecuteScrollLineDown,
       SupportedFromMenuOrKeyBinding, Enabled, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollToBeginningOfDocument,
       ExecuteScrollToBeginningOfDocument, SupportedFromMenuOrKeyBinding,
       Enabled, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kScrollToEndOfDocument, ExecuteScrollToEndOfDocument,
       SupportedFromMenuOrKeyBinding, Enabled, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectAll, ExecuteSelectAll, Supported,
       EnabledSelectAll, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectLine, ExecuteSelectLine,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectParagraph, ExecuteSelectParagraph,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectSentence, ExecuteSelectSentence,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectToMark, ExecuteSelectToMark,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelectionAndMark, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSelectWord, ExecuteSelectWord,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSetMark, ExecuteSetMark,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelection, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kStrikethrough, StyleCommands::ExecuteStrikethrough,
       Supported, EnabledInRichlyEditableText,
       StyleCommands::StateStrikethrough, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kStyleWithCSS, StyleCommands::ExecuteStyleWithCSS,
       Supported, Enabled, StyleCommands::StateStyleWithCSS, ValueEmpty,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSubscript, StyleCommands::ExecuteSubscript,
       Supported, EnabledInRichlyEditableText, StyleCommands::StateSubscript,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSuperscript, StyleCommands::ExecuteSuperscript,
       Supported, EnabledInRichlyEditableText, StyleCommands::StateSuperscript,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kSwapWithMark, ExecuteSwapWithMark,
       SupportedFromMenuOrKeyBinding, EnabledVisibleSelectionAndMark, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kToggleBold, StyleCommands::ExecuteToggleBold,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateBold, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kToggleItalic, StyleCommands::ExecuteToggleItalic,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateItalic, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kToggleUnderline, StyleCommands::ExecuteUnderline,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText,
       StyleCommands::StateUnderline, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kTranspose, ExecuteTranspose, Supported,
       EnableCaretInEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kUnderline, StyleCommands::ExecuteUnderline,
       Supported, EnabledInRichlyEditableText, StyleCommands::StateUnderline,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kUndo, ExecuteUndo, Supported, EnabledUndo,
       StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kUnlink, ExecuteUnlink, Supported,
       EnabledRangeInRichlyEditableText, StateNone, ValueStateOrNull,
       kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kUnscript, StyleCommands::ExecuteUnscript,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kUnselect, ExecuteUnselect, Supported,
       EnabledUnselect, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kUseCSS, StyleCommands::ExecuteUseCSS, Supported,
       Enabled, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kYank, ExecuteYank, SupportedFromMenuOrKeyBinding,
       EnabledInEditableText, StateNone, ValueStateOrNull, kNotTextInsertion,
       CanNotExecuteWhenDisabled},
      {EditingCommandType::kYankAndSelect, ExecuteYankAndSelect,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kAlignCenter, ExecuteJustifyCenter,
       SupportedFromMenuOrKeyBinding, EnabledInRichlyEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
      {EditingCommandType::kPasteFromImageURL,
       ClipboardCommands::ExecutePasteFromImageURL,
       SupportedFromMenuOrKeyBinding, EnabledInEditableText, StateNone,
       ValueStateOrNull, kNotTextInsertion, CanNotExecuteWhenDisabled},
  });
  // Handles all commands except EditingCommandType::Invalid.
  static_assert(
      std::size(kEditorCommands) + 1 ==
          static_cast<size_t>(EditingCommandType::kNumberOfCommandTypes),
      "must handle all valid EditingCommandType");

  EditingCommandType command_type =
      EditingCommandTypeFromCommandName(command_name);
  if (command_type == EditingCommandType::kInvalid)
    return nullptr;

  int command_index = static_cast<int>(command_type) - 1;
  DCHECK(command_index >= 0 &&
         command_index < static_cast<int>(std::size(kEditorCommands)));
  return &kEditorCommands[command_index];
}

EditorCommand Editor::CreateCommand(const String& command_name) const {
  return EditorCommand(InternalCommand(command_name),
                       EditorCommandSource::kMenuOrKeyBinding, frame_);
}

EditorCommand Editor::CreateCommand(const String& command_name,
                                    EditorCommandSource source) const {
  return EditorCommand(InternalCommand(command_name), source, frame_);
}

bool Editor::ExecuteCommand(const String& command_name) {
  // Specially handling commands that Editor::execCommand does not directly
  // support.
  DCHECK(GetFrame().GetDocument()->IsActive());
  if (command_name == "DeleteToEndOfParagraph") {
    if (!DeleteWithDirection(GetFrame(), DeleteDirection::kForward,
                             TextGranularity::kParagraphBoundary, true,
                             false)) {
      DeleteWithDirection(GetFrame(), DeleteDirection::kForward,
                          TextGranularity::kCharacter, true, false);
    }
    return true;
  }
  if (command_name == "DeleteBackward")
    return CreateCommand(AtomicString("BackwardDelete")).Execute();
  if (command_name == "DeleteForward")
    return CreateCommand(AtomicString("ForwardDelete")).Execute();
  if (command_name == "AdvanceToNextMisspelling") {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited. see http://crbug.com/590369 for more details.
    GetFrame().GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);

    // We need to pass false here or else the currently selected word will never
    // be skipped.
    GetSpellChecker().AdvanceToNextMisspelling(false);
    return true;
  }
  if (command_name == "ToggleSpellPanel") {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited.
    // see http://crbug.com/590369 for more details.
    GetFrame().GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);

    GetSpellChecker().ShowSpellingGuessPanel();
    return true;
  }
  return CreateCommand(command_name).Execute();
}

bool Editor::ExecuteCommand(const String& command_name, const String& value) {
  // moveToBeginningOfDocument and moveToEndfDocument are only handled by WebKit
  // for editable nodes.
  DCHECK(GetFrame().GetDocument()->IsActive());
  if (!CanEdit() && command_name == "moveToBeginningOfDocument") {
    return GetFrame().GetEventHandler().BubblingScroll(
        mojom::blink::ScrollDirection::kScrollUpIgnoringWritingMode,
        ui::ScrollGranularity::kScrollByDocument);
  }

  if (!CanEdit() && command_name == "moveToEndOfDocument") {
    return GetFrame().GetEventHandler().BubblingScroll(
        mojom::blink::ScrollDirection::kScrollDownIgnoringWritingMode,
        ui::ScrollGranularity::kScrollByDocument);
  }

  if (command_name == "ToggleSpellPanel") {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited. see http://crbug.com/590369 for more details.
    GetFrame().GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);

    GetSpellChecker().ShowSpellingGuessPanel();
    return true;
  }

  return CreateCommand(command_name).Execute(value);
}

bool Editor::IsCommandEnabled(const String& command_name) const {
  return CreateCommand(command_name).IsEnabled();
}

EditorCommand::EditorCommand()
    : command_(nullptr),
      source_(EditorCommandSource::kMenuOrKeyBinding),
      frame_(nullptr) {}

EditorCommand::EditorCommand(const EditorInternalCommand* command,
                             EditorCommandSource source,
                             LocalFrame* frame)
    : command_(command), source_(source), frame_(command ? frame : nullptr) {
  // Use separate assertions so we can tell which bad thing happened.
  if (!command)
    DCHECK(!frame_);
  else
    DCHECK(frame_);
}

LocalFrame& EditorCommand::GetFrame() const {
  DCHECK(frame_);
  return *frame_;
}

bool EditorCommand::Execute(const String& parameter,
                            Event* triggering_event) const {
  if (!CanExecute(triggering_event))
    return false;

  if (source_ == EditorCommandSource::kMenuOrKeyBinding) {
    InputEvent::InputType input_type =
        InputTypeFromCommandType(command_->command_type, *frame_);
    if (input_type != InputEvent::InputType::kNone) {
      UndoStep* undo_step = nullptr;
      // The node associated with the Undo/Redo command may not necessarily be
      // the currently focused node. See
      // https://issues.chromium.org/issues/326117120 for more details.
      if (RuntimeEnabledFeatures::
              UseUndoStepElementDispatchBeforeInputEnabled()) {
        if (command_->command_type == EditingCommandType::kUndo &&
            frame_->GetEditor().CanUndo()) {
          undo_step = *frame_->GetEditor().GetUndoStack().UndoSteps().begin();
        } else if (command_->command_type == EditingCommandType::kRedo &&
                   frame_->GetEditor().CanRedo()) {
          undo_step = *frame_->GetEditor().GetUndoStack().RedoSteps().begin();
        }
      }
      Node* target_node =
          undo_step ? undo_step->StartingRootEditableElement()
                    : EventTargetNodeForDocument(frame_->GetDocument());
      if (DispatchBeforeInputEditorCommand(target_node, input_type,
                                           GetTargetRanges()) !=
          DispatchEventResult::kNotCanceled) {
        return true;
      }
      // 'beforeinput' event handler may destroy target frame.
      if (frame_->GetDocument()->GetFrame() != frame_)
        return false;
    }

    // If EditContext is active, we may return early and not execute the
    // command.
    if (auto* edit_context =
            frame_->GetInputMethodController().GetActiveEditContext()) {
      // From EditContext's point of view, there are 3 kinds of commands:
      switch (command_->command_type) {
        case EditingCommandType::kToggleBold:
        case EditingCommandType::kToggleItalic:
        case EditingCommandType::kToggleUnderline:
        case EditingCommandType::kInsertTab:
        case EditingCommandType::kInsertBacktab:
        case EditingCommandType::kInsertNewline:
        case EditingCommandType::kInsertLineBreak:
          // 1) BeforeInput event only, ex ctrl+B or <enter>.
          return true;
        case EditingCommandType::kDeleteBackward:
          // 2) BeforeInput event + EditContext behavior, ex. backspace/delete.
          edit_context->DeleteBackward();
          return true;
        case EditingCommandType::kDeleteForward:
          edit_context->DeleteForward();
          return true;
        case EditingCommandType::kDeleteWordBackward:
          edit_context->DeleteWordBackward();
          return true;
        case EditingCommandType::kDeleteWordForward:
          edit_context->DeleteWordForward();
          return true;
        default:
          // 3) BeforeInput event + default DOM behavior, ex. caret navigation.
          // In this case, it's no-op for EditContext.
          break;
      }
    }
  }

  // We need to force unlock activatable DisplayLocks for Editor::FindString
  // before the following call to UpdateStyleAndLayout. Otherwise,
  // ExecuteFindString/Editor::FindString will hit bad style/layout data.
  std::optional<DisplayLockDocumentState::ScopedForceActivatableDisplayLocks>
      forced_locks;
  if (command_->command_type == EditingCommandType::kFindString) {
    forced_locks = GetFrame()
                       .GetDocument()
                       ->GetDisplayLockDocumentState()
                       .GetScopedForceActivatableLocks();
  }

  GetFrame().GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kEditing);
  base::UmaHistogramSparse("WebCore.Editing.Commands",
                           static_cast<int>(command_->command_type));
  return command_->execute(*frame_, triggering_event, source_, parameter);
}

bool EditorCommand::Execute(Event* triggering_event) const {
  return Execute(String(), triggering_event);
}

bool EditorCommand::CanExecute(Event* triggering_event) const {
  if (IsEnabled(triggering_event))
    return true;
  return IsSupported() && frame_ && command_->can_execute(*frame_, source_);
}

bool EditorCommand::IsSupported() const {
  if (!command_)
    return false;
  switch (source_) {
    case EditorCommandSource::kMenuOrKeyBinding:
      return true;
    case EditorCommandSource::kDOM:
      return command_->is_supported_from_dom(frame_);
  }
  NOTREACHED();
}

bool EditorCommand::IsEnabled(Event* triggering_event) const {
  if (!IsSupported() || !frame_)
    return false;
  return command_->is_enabled(*frame_, triggering_event, source_);
}

EditingTriState EditorCommand::GetState(Event* triggering_event) const {
  if (!IsSupported() || !frame_)
    return EditingTriState::kFalse;
  return command_->state(*frame_, triggering_event);
}

String EditorCommand::Value(Event* triggering_event) const {
  if (!IsSupported() || !frame_)
    return String();
  return command_->value(*command_, *frame_, triggering_event);
}

bool EditorCommand::IsTextInsertion() const {
  return command_ && command_->is_text_insertion;
}

bool EditorCommand::IsValueInterpretedAsHTML() const {
  return IsSupported() &&
         command_->command_type == EditingCommandType::kInsertHTML;
}

int EditorCommand::IdForHistogram() const {
  return IsSupported() ? static_cast<int>(command_->command_type) : 0;
}

const StaticRangeVector* EditorCommand::GetTargetRanges() const {
  const Node* target = EventTargetNodeForDocument(frame_->GetDocument());
  if (!IsSupported() || !frame_ || !target || !IsRichlyEditable(*target))
    return nullptr;

  switch (command_->command_type) {
    case EditingCommandType::kDelete:
    case EditingCommandType::kDeleteBackward:
      return RangesFromCurrentSelectionOrExtendCaret(
          *frame_, SelectionModifyDirection::kBackward,
          TextGranularity::kCharacter);
    case EditingCommandType::kDeleteForward:
      return RangesFromCurrentSelectionOrExtendCaret(
          *frame_, SelectionModifyDirection::kForward,
          TextGranularity::kCharacter);
   
"""


```