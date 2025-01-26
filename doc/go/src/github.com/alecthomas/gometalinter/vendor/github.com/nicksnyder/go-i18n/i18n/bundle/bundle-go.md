Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the given Go code, which is part of an i18n (internationalization) library. The path hints at its role within a larger context. The primary goal is to manage translations for different languages.

**2. High-Level Overview (Skimming the Code):**

A quick scan reveals key data structures and functions:

*   `Bundle` struct:  This is the core structure, holding translations. It contains `translations` and `fallbackTranslations` maps, suggesting a mechanism for language matching and fallbacks.
*   `New()`: Creates an empty `Bundle`.
*   `LoadTranslationFile()` and `ParseTranslationFileBytes()`:  These functions load translation data from files or byte slices, supporting JSON and YAML formats. The filename parsing for language codes is a key detail.
*   `AddTranslation()`: Allows adding translations programmatically.
*   `Tfunc()` and `TfuncAndLanguage()`:  These are likely the main functions used to retrieve translated strings based on language preferences.
*   Helper functions like `parseTranslations()`, `supportedLanguage()`, `translatedLanguage()`, `translate()`, `translation()`.

**3. Deeper Dive into Key Functions and Structures:**

*   **`Bundle` struct:**  The two maps (`translations` and `fallbackTranslations`) are crucial. The comments indicate the primary translations are in `translations`, and `fallbackTranslations` are used when an exact match isn't found. The `sync.RWMutex` indicates thread-safe access, important for concurrent applications.

*   **`LoadTranslationFile()`/`ParseTranslationFileBytes()`:**  The filename parsing logic is interesting: `language.Parse(basename)`. This suggests the library expects language codes within the filename (e.g., `en-US.json`). The support for JSON and YAML via `json.Unmarshal` and `yaml.Unmarshal` is clear. The loop in `parseTranslations()` iterates through the loaded data and creates `translation.Translation` objects.

*   **`AddTranslation()`:**  The merging logic (`currentTranslation.Merge(newTranslation)`) is worth noting. This indicates the ability to update or override existing translations. The fallback logic based on `lang.MatchingTags()` is important for handling language variations (e.g., `en` falling back to `en-US`).

*   **`Tfunc()` family:** The function signatures suggest they return a `TranslateFunc`. This function likely takes a translation ID and arguments, returning the translated string. The logic in `TfuncAndLanguage()` for finding the "supported language" based on preferences (`pref` and `prefs`) is key.

*   **`translate()`:** This function performs the actual translation lookup. It handles pluralization based on the "Count" argument and uses templates (`translation.Template(p).Execute(data)`).

*   **Helper Functions:** Understanding the purpose of `supportedLanguage`, `translatedLanguage`, and `translation` is crucial to grasp how language preferences are resolved and translations are retrieved.

**4. Inferring Functionality and Providing Examples:**

Based on the analysis, the core functionality is managing and retrieving translations based on language preferences. Now, construct examples to demonstrate this.

*   **Loading translations:** Show loading from JSON and YAML files, emphasizing the filename convention.
*   **Retrieving translations:** Demonstrate `Tfunc` and passing a translation ID. Include examples with and without arguments (for placeholders).
*   **Language fallback:** Create an example showing how a less specific language preference (e.g., "en") can use translations for a more specific one (e.g., "en-US").
*   **Pluralization:** Demonstrate how the "Count" argument triggers different plural forms based on the language.

**5. Identifying Potential Pitfalls:**

Think about common mistakes developers might make when using this library.

*   **Incorrect filename format:** Emphasize the importance of including the language code in the filename.
*   **Missing translation IDs:** Explain what happens when a requested ID doesn't exist (likely returns the ID itself).
*   **Case sensitivity:** Point out if translation IDs are case-sensitive. (In this case, it seems they are treated as strings, so they likely *are* case-sensitive).
*   **Incorrect argument passing:** Show examples of passing arguments and the potential for errors if the types or order are wrong.

**6. Command-Line Arguments (If Applicable):**

The provided code doesn't directly handle command-line arguments. State this clearly. If there *were* command-line flags to control aspects like loading directories or default languages, those would need to be documented precisely.

**7. Structuring the Answer:**

Organize the findings logically:

*   Start with a concise summary of the bundle's purpose.
*   Detail each function's role.
*   Provide code examples with clear inputs and outputs.
*   Address potential pitfalls with illustrative examples.
*   Discuss command-line arguments (or lack thereof).

**Self-Correction/Refinement:**

*   Initially, I might have just focused on the core loading and retrieval. But the request asks for *reasoning* about the Go features used. Therefore, highlighting concepts like maps, structs, interfaces, error handling, and concurrency (using `sync.RWMutex`) is important.
*   Double-check the code to ensure the examples are accurate and directly reflect the functionality.
*   Ensure the language is clear, concise, and avoids jargon where possible. The target audience is likely developers.

By following this thought process, the comprehensive and accurate answer generated earlier becomes achievable. The key is to go beyond just describing what the code *does* and explain *how* it does it and what implications that has for developers using the library.
这段代码是 `go-i18n` 库中 `bundle` 包的一部分，其核心功能是 **管理和存储多语言的翻译数据**。它可以加载不同格式（JSON, YAML）的翻译文件，并根据用户的语言偏好返回相应的翻译文本。

更具体地说，它的功能包括：

1. **存储翻译数据:**  `Bundle` 结构体使用两个 `map` 来存储翻译数据：
    *   `translations`: 存储特定语言的精确翻译，键是语言标签（例如 "en-US"），值是该语言所有翻译的 `map`，其中键是翻译 ID，值是 `translation.Translation` 接口的实现。
    *   `fallbackTranslations`: 存储可以用于回退的翻译。当找不到精确匹配的语言翻译时，会尝试使用这些回退翻译。

2. **加载翻译文件:**  提供了多种加载翻译文件的方式：
    *   `LoadTranslationFile(filename string)`: 从指定的文件路径加载翻译，并根据文件名解析语言标签。
    *   `MustLoadTranslationFile(filename string)`: 与 `LoadTranslationFile` 功能相同，但如果发生错误会 `panic`。
    *   `ParseTranslationFileBytes(filename string, buf []byte)`: 从字节切片中解析翻译数据，适用于嵌入在程序中的翻译文件（例如使用 `go-bindata`）。

3. **添加翻译数据:**
    *   `AddTranslation(lang *language.Language, translations ...translation.Translation)`:  允许以编程方式添加翻译数据，当翻译数据不以文件形式存在或需要动态生成时很有用。

4. **检索翻译数据:**
    *   `Translations()`: 返回 bundle 中所有的翻译数据，以 `map[string]map[string]translation.Translation` 的形式。
    *   `LanguageTags()`: 返回 bundle 中所有已加载语言的标签列表。
    *   `LanguageTranslationIDs(languageTag string)`: 返回指定语言的所有翻译 ID 列表。

5. **获取翻译函数:**
    *   `Tfunc(pref string, prefs ...string)`:  根据提供的语言偏好（例如 "en-US", "en"），返回一个 `TranslateFunc` 类型的函数。这个返回的函数可以用于实际的翻译操作。如果找不到支持的语言，则返回错误。
    *   `MustTfunc(pref string, prefs ...string)`: 与 `Tfunc` 功能相同，但如果找不到支持的语言会 `panic`。
    *   `TfuncAndLanguage(pref string, prefs ...string)`: 除了返回 `TranslateFunc`，还会返回匹配到的 `language.Language` 对象。
    *   `MustTfuncAndLanguage(pref string, prefs ...string)`: 与 `TfuncAndLanguage` 功能相同，但如果找不到支持的语言会 `panic`。

6. **实际翻译操作:**  `translate(lang *language.Language, translationID string, args ...interface{})` 函数负责根据指定的语言和翻译 ID，以及可能的参数，返回最终的翻译文本。它会处理复数形式（通过 `lang.Plural(count)`）和模板渲染。

7. **线程安全:** 使用 `sync.RWMutex` 保证了对翻译数据的并发安全访问。

**它是什么 go 语言功能的实现？**

这个 `bundle` 包主要实现了 **国际化 (i18n)** 功能，允许开发者在应用程序中支持多种语言。它利用了 Go 语言的以下特性：

*   **结构体 (struct):** `Bundle` 结构体用于组织和管理翻译数据。
*   **映射 (map):**  `translations` 和 `fallbackTranslations` 使用 `map` 来高效地存储和检索翻译。
*   **接口 (interface):** `translation.Translation` 是一个接口，允许不同的翻译实现。
*   **函数作为值:** `TranslateFunc` 是一个函数类型，可以作为返回值传递，方便进行翻译操作。
*   **可变参数 (...):** `Tfunc` 和 `AddTranslation` 等函数使用了可变参数，提高了灵活性。
*   **错误处理:**  函数使用 `error` 类型来报告加载和查找翻译时的错误。
*   **并发控制:** 使用 `sync.RWMutex` 来实现对共享数据的并发安全访问。
*   **反射 (reflect):** `toMap` 和 `structToMap` 函数使用了反射来将结构体转换为 `map[string]interface{}`，这在处理模板参数时非常有用。

**Go 代码举例说明:**

假设我们有以下两个翻译文件：

*   `en-US.json`:
    ```json
    [
      {
        "id": "welcome_message",
        "translation": "Hello, {{.Name}}!"
      },
      {
        "id": "item_count",
        "translation": {
          "zero": "You have no items.",
          "one": "You have one item.",
          "other": "You have {{.Count}} items."
        }
      }
    ]
    ```
*   `zh-CN.yaml`:
    ```yaml
    - id: welcome_message
      translation: "你好，{{.Name}}！"
    - id: item_count
      translation:
        zero: "你没有任何物品。"
        one: "你有一个物品。"
        other: "你有 {{.Count}} 个物品。"
    ```

```go
package main

import (
	"fmt"
	"log"

	"github.com/nicksnyder/go-i18n/i18n/bundle"
)

func main() {
	b := bundle.New()

	// 加载翻译文件
	b.MustLoadTranslationFile("en-US.json")
	b.MustLoadTranslationFile("zh-CN.yaml")

	// 获取英文的翻译函数
	tfuncEn, err := b.Tfunc("en-US")
	if err != nil {
		log.Fatal(err)
	}

	// 使用英文翻译函数
	welcomeEn := tfuncEn("welcome_message", map[string]interface{}{"Name": "World"})
	itemCountEnZero := tfuncEn("item_count", map[string]interface{}{"Count": 0})
	itemCountEnMultiple := tfuncEn("item_count", map[string]interface{}{"Count": 5})

	fmt.Println(welcomeEn)         // Output: Hello, World!
	fmt.Println(itemCountEnZero)    // Output: You have no items.
	fmt.Println(itemCountEnMultiple) // Output: You have 5 items.

	// 获取中文的翻译函数
	tfuncZh, err := b.Tfunc("zh-CN")
	if err != nil {
		log.Fatal(err)
	}

	// 使用中文翻译函数
	welcomeZh := tfuncZh("welcome_message", map[string]interface{}{"Name": "世界"})
	itemCountZhOne := tfuncZh("item_count", map[string]interface{}{"Count": 1})

	fmt.Println(welcomeZh)     // Output: 你好，世界！
	fmt.Println(itemCountZhOne) // Output: 你有一个物品。

	// 使用语言偏好列表
	tfuncAuto, lang, err := b.TfuncAndLanguage("fr-CA", "zh-TW", "zh-CN", "en-US")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("选择的语言:", lang.Tag) // Output: 选择的语言: zh-CN (因为 zh-CN 是列表中第一个找到的)
	welcomeAuto := tfuncAuto("welcome_message", map[string]interface{}{"Name": "自动选择"})
	fmt.Println(welcomeAuto) // Output: 你好，自动选择！ (使用中文翻译)
}
```

**假设的输入与输出:**

上面的代码示例已经包含了假设的输入（翻译文件内容和调用的语言偏好）以及预期的输出。

**命令行参数的具体处理:**

这段代码本身**没有直接处理命令行参数**。 它的主要职责是加载和管理翻译数据。  在实际应用中，命令行参数的处理通常在应用程序的主入口点完成，例如使用 `flag` 包来解析用户提供的语言偏好或指定翻译文件路径。  `go-i18n` 库的使用者可能会编写类似下面的代码来根据命令行参数加载翻译：

```go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/nicksnyder/go-i18n/i18n/bundle"
)

func main() {
	defaultLanguage := flag.String("lang", "en-US", "Default language for the application")
	translationDir := flag.String("translations", "./i18n", "Directory containing translation files")
	flag.Parse()

	b := bundle.New()

	// 假设翻译文件命名为：en-US.json, zh-CN.yaml 等
	translationFiles := []string{
		fmt.Sprintf("%s/en-US.json", *translationDir),
		fmt.Sprintf("%s/zh-CN.yaml", *translationDir),
		// ... 其他语言文件
	}

	for _, file := range translationFiles {
		b.MustLoadTranslationFile(file)
	}

	tfunc, err := b.Tfunc(*defaultLanguage)
	if err != nil {
		log.Fatalf("Failed to load translations for %s: %v", *defaultLanguage, err)
	}

	message := tfunc("welcome_message", map[string]interface{}{"Name": "User"})
	fmt.Println(message)
}
```

在这个例子中，`flag` 包被用来定义 `lang` 和 `translations` 两个命令行参数。应用程序会根据用户提供的参数加载相应的翻译文件并设置默认语言。

**使用者易犯错的点:**

1. **翻译文件命名不规范:**  `LoadTranslationFile` 依赖于文件名来解析语言标签。 如果文件名不符合预期（例如缺少语言代码或者格式不正确），会导致加载失败或者关联到错误的语言。  例如，如果将英文翻译文件命名为 `messages.json` 而不是 `en-US.json`，则 `language.Parse` 将无法识别语言。

2. **忘记加载所有需要的语言文件:**  如果应用程序需要支持多种语言，开发者需要确保加载了所有这些语言对应的翻译文件。 遗漏某些语言的文件会导致用户在切换到这些语言时看不到翻译或看到默认的翻译 ID。

3. **翻译 ID 不一致:** 在不同的语言文件中，同一个概念的翻译应该使用相同的翻译 ID。 如果 ID 不一致，那么在切换语言时可能找不到对应的翻译。 例如，英文中使用 `"welcome_message"`，中文中使用 `"shouye_wenzi"`，会导致逻辑混乱。

4. **模板语法错误:**  在翻译文本中使用模板时（例如 `{{.Name}}`），需要确保语法正确，并且传递的参数与模板中的字段匹配。  例如，模板是 `Hello, {{.UserName}}!`，但是传递的参数是 `map[string]interface{}{"Name": "World"}`，就会导致模板渲染失败。

5. **复数形式处理不当:**  不同的语言有不同的复数规则。 `go-i18n` 依赖于正确配置和使用复数形式的翻译条目。 如果在翻译文件中没有提供正确的 `zero`, `one`, `two`, `few`, `many`, `other` 等复数形式，或者在使用 `Tfunc` 时没有传递 `Count` 参数，可能会导致复数形式显示错误。

例如，如果英文翻译中 `item_count` 的定义如下，并且希望根据 Count 的值显示不同的文本：

```json
{
  "id": "item_count",
  "translation": {
    "zero": "You have no items.",
    "one": "You have one item.",
    "other": "You have {{.Count}} items."
  }
}
```

使用者可能会犯错，直接使用 `tfunc("item_count")` 而不传递 `Count` 参数，导致始终匹配到默认的 "other" 分支，即使物品数量为 0 或 1。 正确的使用方式是 `tfunc("item_count", map[string]interface{}{"Count": 0})` 或 `tfunc("item_count", map[string]interface{}{"Count": 1})` 等。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/github.com/nicksnyder/go-i18n/i18n/bundle/bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package bundle manages translations for multiple languages.
package bundle

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/nicksnyder/go-i18n/i18n/language"
	"github.com/nicksnyder/go-i18n/i18n/translation"
	"gopkg.in/yaml.v2"
)

// TranslateFunc is a copy of i18n.TranslateFunc to avoid a circular dependency.
type TranslateFunc func(translationID string, args ...interface{}) string

// Bundle stores the translations for multiple languages.
type Bundle struct {
	// The primary translations for a language tag and translation id.
	translations map[string]map[string]translation.Translation

	// Translations that can be used when an exact language match is not possible.
	fallbackTranslations map[string]map[string]translation.Translation

	sync.RWMutex
}

// New returns an empty bundle.
func New() *Bundle {
	return &Bundle{
		translations:         make(map[string]map[string]translation.Translation),
		fallbackTranslations: make(map[string]map[string]translation.Translation),
	}
}

// MustLoadTranslationFile is similar to LoadTranslationFile
// except it panics if an error happens.
func (b *Bundle) MustLoadTranslationFile(filename string) {
	if err := b.LoadTranslationFile(filename); err != nil {
		panic(err)
	}
}

// LoadTranslationFile loads the translations from filename into memory.
//
// The language that the translations are associated with is parsed from the filename (e.g. en-US.json).
//
// Generally you should load translation files once during your program's initialization.
func (b *Bundle) LoadTranslationFile(filename string) error {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return b.ParseTranslationFileBytes(filename, buf)
}

// ParseTranslationFileBytes is similar to LoadTranslationFile except it parses the bytes in buf.
//
// It is useful for parsing translation files embedded with go-bindata.
func (b *Bundle) ParseTranslationFileBytes(filename string, buf []byte) error {
	basename := filepath.Base(filename)
	langs := language.Parse(basename)
	switch l := len(langs); {
	case l == 0:
		return fmt.Errorf("no language found in %q", basename)
	case l > 1:
		return fmt.Errorf("multiple languages found in filename %q: %v; expected one", basename, langs)
	}
	translations, err := parseTranslations(filename, buf)
	if err != nil {
		return err
	}
	b.AddTranslation(langs[0], translations...)
	return nil
}

func parseTranslations(filename string, buf []byte) ([]translation.Translation, error) {
	var unmarshalFunc func([]byte, interface{}) error
	switch format := filepath.Ext(filename); format {
	case ".json":
		unmarshalFunc = json.Unmarshal
	case ".yaml":
		unmarshalFunc = yaml.Unmarshal
	default:
		return nil, fmt.Errorf("unsupported file extension %s", format)
	}

	var translationsData []map[string]interface{}
	if len(buf) > 0 {
		if err := unmarshalFunc(buf, &translationsData); err != nil {
			return nil, fmt.Errorf("failed to load %s because %s", filename, err)
		}
	}

	translations := make([]translation.Translation, 0, len(translationsData))
	for i, translationData := range translationsData {
		t, err := translation.NewTranslation(translationData)
		if err != nil {
			return nil, fmt.Errorf("unable to parse translation #%d in %s because %s\n%v", i, filename, err, translationData)
		}
		translations = append(translations, t)
	}
	return translations, nil
}

// AddTranslation adds translations for a language.
//
// It is useful if your translations are in a format not supported by LoadTranslationFile.
func (b *Bundle) AddTranslation(lang *language.Language, translations ...translation.Translation) {
	b.Lock()
	defer b.Unlock()
	if b.translations[lang.Tag] == nil {
		b.translations[lang.Tag] = make(map[string]translation.Translation, len(translations))
	}
	currentTranslations := b.translations[lang.Tag]
	for _, newTranslation := range translations {
		if currentTranslation := currentTranslations[newTranslation.ID()]; currentTranslation != nil {
			currentTranslations[newTranslation.ID()] = currentTranslation.Merge(newTranslation)
		} else {
			currentTranslations[newTranslation.ID()] = newTranslation
		}
	}

	// lang can provide translations for less specific language tags.
	for _, tag := range lang.MatchingTags() {
		b.fallbackTranslations[tag] = currentTranslations
	}
}

// Translations returns all translations in the bundle.
func (b *Bundle) Translations() map[string]map[string]translation.Translation {
	t := make(map[string]map[string]translation.Translation)
	b.RLock()
	for tag, translations := range b.translations {
		t[tag] = make(map[string]translation.Translation)
		for id, translation := range translations {
			t[tag][id] = translation
		}
	}
	b.RUnlock()
	return t
}

// LanguageTags returns the tags of all languages that that have been added.
func (b *Bundle) LanguageTags() []string {
	var tags []string
	b.RLock()
	for k := range b.translations {
		tags = append(tags, k)
	}
	b.RUnlock()
	return tags
}

// LanguageTranslationIDs returns the ids of all translations that have been added for a given language.
func (b *Bundle) LanguageTranslationIDs(languageTag string) []string {
	var ids []string
	b.RLock()
	for id := range b.translations[languageTag] {
		ids = append(ids, id)
	}
	b.RUnlock()
	return ids
}

// MustTfunc is similar to Tfunc except it panics if an error happens.
func (b *Bundle) MustTfunc(pref string, prefs ...string) TranslateFunc {
	tfunc, err := b.Tfunc(pref, prefs...)
	if err != nil {
		panic(err)
	}
	return tfunc
}

// MustTfuncAndLanguage is similar to TfuncAndLanguage except it panics if an error happens.
func (b *Bundle) MustTfuncAndLanguage(pref string, prefs ...string) (TranslateFunc, *language.Language) {
	tfunc, language, err := b.TfuncAndLanguage(pref, prefs...)
	if err != nil {
		panic(err)
	}
	return tfunc, language
}

// Tfunc is similar to TfuncAndLanguage except is doesn't return the Language.
func (b *Bundle) Tfunc(pref string, prefs ...string) (TranslateFunc, error) {
	tfunc, _, err := b.TfuncAndLanguage(pref, prefs...)
	return tfunc, err
}

// TfuncAndLanguage returns a TranslateFunc for the first Language that
// has a non-zero number of translations in the bundle.
//
// The returned Language matches the the first language preference that could be satisfied,
// but this may not strictly match the language of the translations used to satisfy that preference.
//
// For example, the user may request "zh". If there are no translations for "zh" but there are translations
// for "zh-cn", then the translations for "zh-cn" will be used but the returned Language will be "zh".
//
// It can parse languages from Accept-Language headers (RFC 2616),
// but it assumes weights are monotonically decreasing.
func (b *Bundle) TfuncAndLanguage(pref string, prefs ...string) (TranslateFunc, *language.Language, error) {
	lang := b.supportedLanguage(pref, prefs...)
	var err error
	if lang == nil {
		err = fmt.Errorf("no supported languages found %#v", append(prefs, pref))
	}
	return func(translationID string, args ...interface{}) string {
		return b.translate(lang, translationID, args...)
	}, lang, err
}

// supportedLanguage returns the first language which
// has a non-zero number of translations in the bundle.
func (b *Bundle) supportedLanguage(pref string, prefs ...string) *language.Language {
	lang := b.translatedLanguage(pref)
	if lang == nil {
		for _, pref := range prefs {
			lang = b.translatedLanguage(pref)
			if lang != nil {
				break
			}
		}
	}
	return lang
}

func (b *Bundle) translatedLanguage(src string) *language.Language {
	langs := language.Parse(src)
	b.RLock()
	defer b.RUnlock()
	for _, lang := range langs {
		if len(b.translations[lang.Tag]) > 0 ||
			len(b.fallbackTranslations[lang.Tag]) > 0 {
			return lang
		}
	}
	return nil
}

func (b *Bundle) translate(lang *language.Language, translationID string, args ...interface{}) string {
	if lang == nil {
		return translationID
	}

	translation := b.translation(lang, translationID)
	if translation == nil {
		return translationID
	}

	var data interface{}
	var count interface{}
	if argc := len(args); argc > 0 {
		if isNumber(args[0]) {
			count = args[0]
			if argc > 1 {
				data = args[1]
			}
		} else {
			data = args[0]
		}
	}

	if count != nil {
		if data == nil {
			data = map[string]interface{}{"Count": count}
		} else {
			dataMap := toMap(data)
			dataMap["Count"] = count
			data = dataMap
		}
	} else {
		dataMap := toMap(data)
		if c, ok := dataMap["Count"]; ok {
			count = c
		}
	}

	p, _ := lang.Plural(count)
	template := translation.Template(p)
	if template == nil {
		return translationID
	}

	s := template.Execute(data)
	if s == "" {
		return translationID
	}
	return s
}

func (b *Bundle) translation(lang *language.Language, translationID string) translation.Translation {
	b.RLock()
	defer b.RUnlock()
	translations := b.translations[lang.Tag]
	if translations == nil {
		translations = b.fallbackTranslations[lang.Tag]
		if translations == nil {
			return nil
		}
	}
	return translations[translationID]
}

func isNumber(n interface{}) bool {
	switch n.(type) {
	case int, int8, int16, int32, int64, string:
		return true
	}
	return false
}

func toMap(input interface{}) map[string]interface{} {
	if data, ok := input.(map[string]interface{}); ok {
		return data
	}
	v := reflect.ValueOf(input)
	switch v.Kind() {
	case reflect.Ptr:
		return toMap(v.Elem().Interface())
	case reflect.Struct:
		return structToMap(v)
	default:
		return nil
	}
}

// Converts the top level of a struct to a map[string]interface{}.
// Code inspired by github.com/fatih/structs.
func structToMap(v reflect.Value) map[string]interface{} {
	out := make(map[string]interface{})
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			// unexported field. skip.
			continue
		}
		out[field.Name] = v.FieldByName(field.Name).Interface()
	}
	return out
}

"""



```