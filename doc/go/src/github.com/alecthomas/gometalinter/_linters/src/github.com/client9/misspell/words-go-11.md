Response:
我的目标是理解并归纳给定的Go代码片段的功能。这是一个很长的字符串字面量，包含了大量的键值对，键和值都是字符串。根据上下文，这个文件名为 `words.go`，并且位于 `misspell` 这个包下，可以推断出这个字符串很可能是一个**拼写错误校正**的词典。

以下是我的思考过程：

1. **识别数据结构：**  这段代码的核心是一个很长的字符串字面量。观察其结构，可以发现它是由成对出现的字符串组成，每个字符串用双引号包围，并以逗号分隔。这很像一个简单的键值对列表。

2. **文件名与路径分析：** 文件名是 `words.go`，路径是 `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/client9/misspell/words.go`。  `misspell` 这个名字非常具有暗示性，它很可能是一个用于检查和纠正拼写错误的工具。 `words.go` 文件名也进一步印证了这一点，它很可能包含了该工具需要用到的单词列表。

3. **键值对的含义推测：**  每一对字符串，例如 `"ls"`, `"lists"`，很可能代表一个常见的拼写错误（左边的字符串）和其正确的拼写（右边的字符串）。 `misspell` 工具很可能会使用这个列表来查找文本中的拼写错误，并将错误拼写替换为正确的拼写。

4. **功能归纳：** 基于以上分析，我认为这个 Go 代码片段的主要功能是**提供一个拼写错误到正确拼写的映射表**，用于拼写检查和校正。

5. **Go 语言功能推断：** 这个字符串字面量很可能被 `misspell` 包内的其他 Go 代码解析并存储到某种数据结构中，例如 `map[string]string`。这样可以方便快速地查找和替换拼写错误。

6. **代码示例：**  为了说明这个功能，可以创建一个简单的 Go 代码示例，演示如何使用这个字符串。假设这个字符串被解析后存储在名为 `corrections` 的 `map[string]string` 变量中。

7. **命令行参数处理：**  虽然这段代码本身没有直接处理命令行参数，但是考虑到它是一个拼写检查工具的一部分，可以推测 `misspell` 工具可能会有命令行参数来指定要检查的文件、输出格式等。

8. **易犯错误点：** 考虑到这是一个人工维护的词典，容易出现以下错误：
    * **遗漏常见的拼写错误：** 并非所有的拼写错误都被收录。
    * **错误的校正：**  可能存在将正确的单词误认为错误并进行校正的情况。
    * **大小写问题：** 需要考虑拼写错误和正确拼写的大小写匹配问题。

9. **归纳总结 (针对第12部分)：**  因为这是第12部分，可以推断之前的部分可能定义了 `misspell` 工具的框架、读取文件、处理文本等功能。而当前部分的功能是**提供拼写错误校正的核心数据**。

经过以上思考，我形成了最终的答案。
这是一个Go语言实现的片段，位于 `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/client9/misspell/words.go` 路径下，从路径和文件名 `words.go` 可以推断，这个文件的作用是为 `misspell` 这个拼写检查工具提供**拼写错误的单词及其对应的正确拼写**的映射关系。

**功能归纳:**

这段代码定义了一个很长的字符串字面量，该字符串内部存储着一系列用双引号括起来的字符串对。每一对字符串都代表一个常见的拼写错误（第一个字符串）以及其对应的正确拼写（第二个字符串）。这个字符串字面量可以被理解为一个**硬编码的拼写错误词典**。

**Go语言功能实现推断与代码示例:**

这个字符串很可能被 `misspell` 包内的其他Go代码解析，并存储到一种更方便查找的数据结构中，例如 `map[string]string`。这样，当 `misspell` 工具扫描代码或文本时，就可以快速地查找是否存在已知的拼写错误，并将其替换为正确的拼写。

```go
package main

import (
	"fmt"
	"strings"
)

// 假设这是从 words.go 文件中提取出来的字符串
var wordsData = `
"ls", "lists",
"capitalits", "capitalists",
"capitalsim", "capitalism",
// ... 更多拼写错误和正确拼写
`

func main() {
	// 假设我们有一个函数可以将上面的字符串解析成 map
	corrections := parseWordsData(wordsData)

	text := "This is a sentense with some missspellings like capitalits and capitalsim."
	words := strings.Split(text, " ")
	correctedWords := make([]string, 0)

	for _, word := range words {
		if correction, ok := corrections[strings.ToLower(word)]; ok {
			correctedWords = append(correctedWords, correction)
		} else {
			correctedWords = append(correctedWords, word)
		}
	}

	correctedText := strings.Join(correctedWords, " ")
	fmt.Println("原始文本:", text)
	fmt.Println("修正后文本:", correctedText)
}

// 简单的解析函数示例，实际实现可能更复杂
func parseWordsData(data string) map[string]string {
	corrections := make(map[string]string)
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ",") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) == 2 {
			wrong := strings.Trim(parts[0], `" `)
			correct := strings.Trim(parts[1], `" `)
			corrections[wrong] = correct
		}
	}
	return corrections
}

// 假设的输入与输出：
// 假设输入 text 为 "This is a sentense with some missspellings like capitalits and capitalsim."
// 输出 correctedText 为 "This is a sentence with some misspellings like capitalists and capitalism."
```

**命令行参数的具体处理:**

这个代码片段本身不涉及命令行参数的处理。命令行参数的处理通常会在 `misspell` 工具的主程序入口文件中进行。可能的命令行参数包括：

* **-w (write):**  直接修改源文件，将拼写错误替换为正确的拼写。
* **-v (verbose):**  输出详细的检查信息，例如找到的拼写错误及其位置。
* **-diff:**  生成一个 diff 格式的输出，显示哪些地方被修改了。
* **-locale <locale>:**  指定使用的语言区域，可能会影响拼写检查的规则。
* **<files or directories>:**  指定要检查的文件或目录。

**使用者易犯错的点:**

使用者在使用 `misspell` 工具时，可能容易犯以下错误：

* **过度依赖自动修复:**  不加 review 地使用 `-w` 参数可能会引入新的错误，因为自动替换有时可能不符合语境。
* **忽略输出信息:**  没有仔细查看 `misspell` 的输出信息，可能忽略了一些重要的拼写错误或潜在的问题。
* **没有根据项目需求配置:**  `misspell` 的默认配置可能不适合所有项目，例如对于某些特定的缩写或专业术语，可能需要进行自定义配置。

**总结 (针对第12部分):**

作为整个 `misspell` 工具的一部分，这个 `words.go` 文件，特别是这段代码，其核心功能是**提供了一个预定义的拼写错误及其正确拼写的静态数据集**。它是 `misspell` 工具进行拼写检查和校正的基础数据来源。可以认为这是 `misspell` 工具的“词汇表”或者“纠错知识库”的一部分。之前的其他部分可能负责读取文件、解析代码、调用此数据进行比对和替换等操作。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/client9/misspell/words.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第12部分，共28部分，请归纳一下它的功能

"""
ls",
	"capitalits", "capitalists",
	"capitalsim", "capitalism",
	"capitalsit", "capitalists",
	"capitarist", "capitalist",
	"capitilism", "capitalism",
	"capitilist", "capitalist",
	"capitilize", "capitalize",
	"capitlaism", "capitalism",
	"capitlaist", "capitalist",
	"capitlaize", "capitalized",
	"capitolism", "capitalism",
	"capitolist", "capitalist",
	"capitolize", "capitalize",
	"captainers", "captains",
	"captialism", "capitalism",
	"captialist", "capitalist",
	"captialize", "capitalize",
	"captivitiy", "captivity",
	"caraciture", "caricature",
	"carciature", "caricature",
	"cardinales", "cardinals",
	"cardinalis", "cardinals",
	"carefullly", "carefully",
	"cariacture", "caricature",
	"caricatore", "caricature",
	"cariciture", "caricature",
	"caricuture", "caricature",
	"carismatic", "charismatic",
	"carribbean", "caribbean",
	"cartdridge", "cartridge",
	"cartdriges", "cartridges",
	"carthagian", "carthaginian",
	"cartilidge", "cartilage",
	"cartirdges", "cartridges",
	"cartrdiges", "cartridges",
	"cartriages", "cartridges",
	"cartrigdes", "cartridges",
	"casaulties", "casualties",
	"cassowarry", "cassowary",
	"casualites", "casualties",
	"casualries", "casualties",
	"casulaties", "casualties",
	"cataclysim", "cataclysm",
	"cataclysym", "cataclysm",
	"catagories", "categories",
	"catapillar", "caterpillar",
	"catapiller", "caterpillar",
	"catastrope", "catastrophe",
	"catastrphe", "catastrophe",
	"categorice", "categorize",
	"categoried", "categorized",
	"categoriei", "categorize",
	"cateogrize", "categorized",
	"catepillar", "caterpillar",
	"caterpilar", "caterpillar",
	"catholicsm", "catholicism",
	"catholicus", "catholics",
	"catholisim", "catholicism",
	"cativating", "activating",
	"cattleship", "battleship",
	"causalties", "casualties",
	"cautionsly", "cautiously",
	"celebratin", "celebration",
	"celebrites", "celebrities",
	"celebritiy", "celebrity",
	"cellpading", "cellpadding",
	"cellulaire", "cellular",
	"cemetaries", "cemeteries",
	"censorhsip", "censorship",
	"censurship", "censorship",
	"centipedle", "centipede",
	"ceremonias", "ceremonies",
	"ceremoniis", "ceremonies",
	"ceremonije", "ceremonies",
	"cerimonial", "ceremonial",
	"cerimonies", "ceremonies",
	"certainity", "certainty",
	"certainlyt", "certainty",
	"chairtable", "charitable",
	"chalenging", "challenging",
	"challanged", "challenged",
	"challanges", "challenges",
	"challegner", "challenger",
	"challender", "challenger",
	"challengue", "challenger",
	"challengur", "challenger",
	"challening", "challenging",
	"challneger", "challenger",
	"chanceller", "chancellor",
	"chancillor", "chancellor",
	"chansellor", "chancellor",
	"charachter", "character",
	"charactere", "characterize",
	"characterz", "characterize",
	"charactors", "characters",
	"charakters", "characters",
	"charatable", "charitable",
	"charecters", "characters",
	"charistics", "characteristics",
	"charitible", "charitable",
	"chartiable", "charitable",
	"chechpoint", "checkpoint",
	"checkpiont", "checkpoint",
	"checkpoins", "checkpoints",
	"checkponts", "checkpoints",
	"cheesecase", "cheesecake",
	"cheesecave", "cheesecake",
	"cheeseface", "cheesecake",
	"cheezecake", "cheesecake",
	"chemcially", "chemically",
	"chidlbirth", "childbirth",
	"chihuahuha", "chihuahua",
	"childbrith", "childbirth",
	"childrends", "childrens",
	"childrenis", "childrens",
	"childrents", "childrens",
	"chirstians", "christians",
	"chocalates", "chocolates",
	"chocloates", "chocolates",
	"chocoaltes", "chocolates",
	"chocolatie", "chocolates",
	"chocolatos", "chocolates",
	"chocolatte", "chocolates",
	"chocolotes", "chocolates",
	"cholestrol", "cholesterol",
	"chormosome", "chromosome",
	"chornicles", "chronicles",
	"chrisitans", "christians",
	"christains", "christians",
	"christiaan", "christian",
	"christimas", "christians",
	"christinas", "christians",
	"christines", "christians",
	"christmans", "christians",
	"chromasome", "chromosome",
	"chromesome", "chromosome",
	"chromisome", "chromosome",
	"chromosmes", "chromosomes",
	"chromosoms", "chromosomes",
	"chromosone", "chromosome",
	"chromosoom", "chromosome",
	"chromozome", "chromosome",
	"chronciles", "chronicles",
	"chronicals", "chronicles",
	"chronicels", "chronicles",
	"chronocles", "chronicles",
	"chronosome", "chromosome",
	"chrsitians", "christians",
	"cigarattes", "cigarettes",
	"cigerattes", "cigarettes",
	"cincinatti", "cincinnati",
	"cinncinati", "cincinnati",
	"circulaire", "circular",
	"circulaton", "circulation",
	"circumsice", "circumcised",
	"circumsied", "circumcised",
	"circumwent", "circumvent",
	"circunvent", "circumvent",
	"cirruculum", "curriculum",
	"claculator", "calculator",
	"clairfying", "clarifying",
	"clasically", "classically",
	"classicals", "classics",
	"classrooom", "classroom",
	"cleanliess", "cleanliness",
	"cleareance", "clearance",
	"cleverleys", "cleverly",
	"cliffhager", "cliffhanger",
	"climateers", "climates",
	"climatiser", "climates",
	"clincially", "clinically",
	"clitoridis", "clitoris",
	"clitorious", "clitoris",
	"co-incided", "coincided",
	"cockroachs", "cockroaches",
	"cockroahes", "cockroaches",
	"coefficent", "coefficient",
	"cognatious", "contagious",
	"cognitivie", "cognitive",
	"coincidnce", "coincide",
	"colelctive", "collective",
	"colelctors", "collectors",
	"collapsers", "collapses",
	"collaquial", "colloquial",
	"collasping", "collapsing",
	"collataral", "collateral",
	"collaterol", "collateral",
	"collatoral", "collateral",
	"collcetion", "collections",
	"colleauges", "colleagues",
	"colleciton", "collection",
	"collectems", "collects",
	"collectief", "collective",
	"collecties", "collects",
	"collectifs", "collects",
	"collectivo", "collection",
	"collectoin", "collections",
	"collectons", "collections",
	"collectros", "collects",
	"collegaues", "colleagues",
	"collequial", "colloquial",
	"colleteral", "collateral",
	"colliquial", "colloquial",
	"collission", "collisions",
	"collitions", "collisions",
	"colloqiual", "colloquial",
	"colloquail", "colloquial",
	"colloqueal", "colloquial",
	"collpasing", "collapsing",
	"colonialsm", "colonialism",
	"colorblend", "colorblind",
	"coloublind", "colorblind",
	"columbidae", "columbia",
	"comapnions", "companions",
	"comaprable", "comparable",
	"comaprison", "comparison",
	"comaptible", "compatible",
	"combatabts", "combatants",
	"combatents", "combatants",
	"combinatin", "combinations",
	"combinaton", "combination",
	"comediants", "comedians",
	"comepndium", "compendium",
	"comferting", "comforting",
	"comforming", "comforting",
	"comfortbly", "comfortably",
	"comisioned", "commissioned",
	"comisioner", "commissioner",
	"comissions", "commissions",
	"commandbox", "commando",
	"commandent", "commandment",
	"commandeur", "commanders",
	"commandore", "commanders",
	"commandpod", "commando",
	"commanists", "communists",
	"commemters", "commenters",
	"commencera", "commerce",
	"commenciez", "commence",
	"commentaar", "commentary",
	"commentare", "commenter",
	"commentars", "commenters",
	"commentart", "commentator",
	"commentery", "commentary",
	"commentsry", "commenters",
	"commercail", "commercials",
	"commercent", "commence",
	"commerical", "commercial",
	"comminists", "communists",
	"commisison", "commissions",
	"commissons", "commissions",
	"commiteted", "commited",
	"commodites", "commodities",
	"commtiment", "commitments",
	"communicae", "communicated",
	"communisim", "communism",
	"communiste", "communities",
	"communites", "communities",
	"communters", "commenters",
	"compadible", "compatible",
	"compagnons", "companions",
	"compainons", "companions",
	"compairson", "comparison",
	"compalined", "complained",
	"compandium", "compendium",
	"companians", "companions",
	"companines", "companions",
	"compansate", "compensate",
	"comparabil", "comparable",
	"comparason", "comparison",
	"comparaste", "compares",
	"comparatie", "comparative",
	"compareble", "comparable",
	"comparemos", "compares",
	"comparions", "comparison",
	"compariosn", "comparisons",
	"comparisen", "compares",
	"comparitve", "comparative",
	"comparsion", "comparison",
	"compartent", "compartment",
	"compartmet", "compartment",
	"compatibel", "compatible",
	"compatibil", "compatible",
	"compeating", "completing",
	"compeditor", "competitor",
	"compednium", "compendium",
	"compeeting", "completing",
	"compeltely", "completely",
	"compelting", "completing",
	"compeltion", "completion",
	"compemdium", "compendium",
	"compenduim", "compendium",
	"compenents", "components",
	"compenidum", "compendium",
	"compensare", "compensate",
	"comperable", "comparable",
	"comperhend", "comprehend",
	"compession", "compassion",
	"competance", "competence",
	"competator", "competitor",
	"competenet", "competence",
	"competense", "competence",
	"competenze", "competence",
	"competeted", "competed",
	"competetor", "competitor",
	"competidor", "competitor",
	"competiors", "competitors",
	"competitie", "competitive",
	"competitin", "competitions",
	"competitio", "competitor",
	"competiton", "competition",
	"competitve", "competitive",
	"compilance", "compliance",
	"compilaton", "compilation",
	"compinsate", "compensate",
	"compitable", "compatible",
	"compitance", "compliance",
	"complacant", "complacent",
	"complaince", "compliance",
	"complaines", "complaints",
	"complainig", "complaining",
	"complainte", "complained",
	"complation", "completion",
	"compleatly", "completely",
	"complecate", "complicate",
	"completeds", "completes",
	"completent", "complement",
	"completily", "complexity",
	"completito", "completion",
	"completley", "completely",
	"complexers", "complexes",
	"complexety", "complexity",
	"complianed", "compliance",
	"compliants", "complaints",
	"complicaed", "complicate",
	"complicare", "complicate",
	"complicati", "complicit",
	"complicato", "complication",
	"complicite", "complicate",
	"complicted", "complicated",
	"complience", "compliance",
	"complimate", "complicate",
	"complition", "completion",
	"complusion", "compulsion",
	"complusive", "compulsive",
	"complusory", "compulsory",
	"compolsive", "compulsive",
	"compolsory", "compulsory",
	"compolsury", "compulsory",
	"componants", "components",
	"componenet", "components",
	"componsate", "compensate",
	"comporable", "comparable",
	"compositae", "composite",
	"compositie", "composite",
	"compositon", "composition",
	"compraison", "comparisons",
	"compramise", "compromise",
	"comprassem", "compress",
	"comprehand", "comprehend",
	"compresion", "compression",
	"compresors", "compressor",
	"compresser", "compressor",
	"compressio", "compressor",
	"compresson", "compression",
	"comprihend", "comprehend",
	"comprimise", "compromise",
	"compromiss", "compromises",
	"compromize", "compromise",
	"compromsie", "compromises",
	"comprossor", "compressor",
	"compteting", "completing",
	"comptetion", "completion",
	"compulisve", "compulsive",
	"compulosry", "compulsory",
	"compulsary", "compulsory",
	"compulsery", "compulsory",
	"compulsing", "compulsion",
	"compulsivo", "compulsion",
	"compulsury", "compulsory",
	"compuslion", "compulsion",
	"compuslive", "compulsive",
	"compuslory", "compulsory",
	"compustion", "compulsion",
	"computanti", "computation",
	"conatiners", "containers",
	"concedendo", "conceded",
	"concedered", "conceded",
	"conceitual", "conceptual",
	"concentate", "concentrate",
	"concenting", "connecting",
	"conceptial", "conceptual",
	"conceptuel", "conceptual",
	"concersion", "concession",
	"concesions", "concession",
	"concidered", "considered",
	"conciously", "consciously",
	"concission", "concession",
	"conclsuion", "concussion",
	"conclusies", "conclusive",
	"conclution", "conclusion",
	"concorrent", "concurrent",
	"concsience", "conscience",
	"conculsion", "conclusion",
	"conculsive", "conclusive",
	"concurment", "concurrent",
	"concurrant", "concurrent",
	"concurrect", "concurrent",
	"concusions", "concussion",
	"concusison", "concussions",
	"condamning", "condemning",
	"condemming", "condemning",
	"condencing", "condemning",
	"condenming", "condemning",
	"condensend", "condensed",
	"condidtion", "condition",
	"conditinal", "conditional",
	"conditiner", "conditioner",
	"conditiond", "conditioned",
	"conditiong", "conditioning",
	"condmening", "condemning",
	"conduiting", "conducting",
	"conencting", "connecting",
	"conenction", "connection",
	"conenctors", "connectors",
	"conesencus", "consensus",
	"confedarcy", "confederacy",
	"confedence", "conference",
	"confedercy", "confederacy",
	"conferance", "conference",
	"conferenze", "conference",
	"conferming", "confirming",
	"confernece", "conferences",
	"confessino", "confessions",
	"confidance", "confidence",
	"confidenly", "confidently",
	"confidense", "confidence",
	"confidenty", "confidently",
	"conflcting", "conflating",
	"conflicing", "conflicting",
	"conflictos", "conflicts",
	"confliting", "conflating",
	"confriming", "confirming",
	"confussion", "confession",
	"congratule", "congratulate",
	"congresman", "congressman",
	"congresmen", "congressmen",
	"congressen", "congressmen",
	"conjecutre", "conjecture",
	"conjuction", "conjunction",
	"conjuncion", "conjunction",
	"conlcusion", "conclusion",
	"conncetion", "connections",
	"conneciton", "connection",
	"connecties", "connects",
	"connectins", "connects",
	"connectivy", "connectivity",
	"connectpro", "connector",
	"conneticut", "connecticut",
	"connotaion", "connotation",
	"conpsiracy", "conspiracy",
	"conqeuring", "conquering",
	"conqouring", "conquering",
	"conquerers", "conquerors",
	"conquoring", "conquering",
	"consciense", "conscience",
	"consciouly", "consciously",
	"consdiered", "considered",
	"consending", "consenting",
	"consensuel", "consensual",
	"consenusal", "consensual",
	"consequece", "consequence",
	"consequnce", "consequence",
	"conservare", "conserve",
	"conservato", "conservation",
	"conservice", "conserve",
	"conservies", "conserve",
	"conservite", "conserve",
	"consicence", "conscience",
	"consideras", "considers",
	"consideret", "considerate",
	"consipracy", "conspiracy",
	"consistant", "consistent",
	"consistens", "consists",
	"consisteny", "consistency",
	"consitency", "consistency",
	"consituted", "constituted",
	"conslutant", "consultant",
	"consluting", "consulting",
	"consolidad", "consolidated",
	"consonents", "consonants",
	"consorcium", "consortium",
	"conspirace", "conspiracies",
	"conspiricy", "conspiracy",
	"conspriacy", "conspiracy",
	"constaints", "constraints",
	"constatnly", "constantly",
	"constently", "constantly",
	"constitude", "constitute",
	"constitued", "constitute",
	"constituem", "constitute",
	"constituer", "constitute",
	"constitues", "constitutes",
	"constituie", "constitute",
	"constituit", "constitute",
	"constitutn", "constituents",
	"constituye", "constitute",
	"constnatly", "constantly",
	"constracts", "constructs",
	"constraits", "constraints",
	"constransi", "constraints",
	"constrants", "constraints",
	"construced", "constructed",
	"constructo", "construction",
	"construint", "constraint",
	"construits", "constructs",
	"construted", "constructed",
	"consueling", "consulting",
	"consultata", "consultant",
	"consultate", "consultant",
	"consultati", "consultant",
	"consultato", "consultation",
	"consultent", "consultant",
	"consumated", "consummated",
	"consumbale", "consumables",
	"consuments", "consumes",
	"consumirem", "consumerism",
	"consumires", "consumerism",
	"consumirse", "consumerism",
	"consumiste", "consumes",
	"consumpion", "consumption",
	"contaction", "contacting",
	"contageous", "contagious",
	"contagiosa", "contagious",
	"contagioso", "contagious",
	"contaigous", "contagious",
	"containors", "containers",
	"contaminen", "containment",
	"contanting", "contacting",
	"contection", "contention",
	"contectual", "contextual",
	"conteiners", "contenders",
	"contempate", "contemplate",
	"contemplat", "contempt",
	"contempory", "contemporary",
	"contenants", "continents",
	"contencion", "contention",
	"contendors", "contenders",
	"contenents", "continents",
	"conteneurs", "contenders",
	"contengent", "contingent",
	"contension", "contention",
	"contentino", "contention",
	"contentios", "contentious",
	"contentous", "contentious",
	"contestais", "contests",
	"contestans", "contests",
	"contestase", "contests",
	"contestion", "contention",
	"contestors", "contests",
	"contextful", "contextual",
	"contextuel", "contextual",
	"contextura", "contextual",
	"contianers", "containers",
	"contianing", "containing",
	"contibuted", "contributed",
	"contibutes", "contributes",
	"contigents", "continents",
	"contigious", "contagious",
	"contignent", "contingent",
	"continants", "continents",
	"continenal", "continental",
	"continenet", "continents",
	"contineous", "continuous",
	"continetal", "continental",
	"contingecy", "contingency",
	"contingeny", "contingency",
	"continient", "contingent",
	"continious", "continuous",
	"continiuty", "continuity",
	"contintent", "contingent",
	"continualy", "continually",
	"continuare", "continue",
	"continuati", "continuity",
	"continuato", "continuation",
	"continuent", "contingent",
	"continuety", "continuity",
	"continunes", "continents",
	"continuons", "continuous",
	"continutiy", "continuity",
	"continuuum", "continuum",
	"contitnent", "contingent",
	"contiuning", "containing",
	"contiunity", "continuity",
	"contorller", "controllers",
	"contracing", "contracting",
	"contractar", "contractor",
	"contracter", "contractor",
	"contractin", "contraction",
	"contractos", "contracts",
	"contradice", "contradicted",
	"contradics", "contradicts",
	"contredict", "contradict",
	"contribued", "contributed",
	"contribuem", "contribute",
	"contribuer", "contribute",
	"contribues", "contributes",
	"contribuie", "contribute",
	"contribuit", "contribute",
	"contributo", "contribution",
	"contributs", "contributes",
	"contribuye", "contribute",
	"contricted", "contracted",
	"contridict", "contradict",
	"contriubte", "contributes",
	"controlelr", "controllers",
	"controlers", "controls",
	"controling", "controlling",
	"controlles", "controls",
	"controvery", "controversy",
	"controvesy", "controversy",
	"contrubite", "contributes",
	"contrubute", "contribute",
	"contuining", "continuing",
	"contuinity", "continuity",
	"convaluted", "convoluted",
	"convcition", "convictions",
	"conveinent", "convenient",
	"conveluted", "convoluted",
	"convencion", "convention",
	"conveniant", "convenient",
	"conveniece", "convenience",
	"convenince", "convenience",
	"convential", "conventional",
	"converesly", "conversely",
	"convergens", "converse",
	"converison", "conversions",
	"converning", "converting",
	"conversare", "converse",
	"conversino", "conversions",
	"conversley", "conversely",
	"conversoin", "conversions",
	"conversons", "conversions",
	"convertion", "conversion",
	"convertire", "converter",
	"converying", "converting",
	"conveyered", "conveyed",
	"conviccion", "conviction",
	"conviciton", "conviction",
	"convienent", "convenient",
	"conviluted", "convoluted",
	"convincted", "convince",
	"convinsing", "convincing",
	"convinving", "convincing",
	"convoluded", "convoluted",
	"convoulted", "convoluted",
	"convulated", "convoluted",
	"convuluted", "convoluted",
	"cooperatve", "cooperative",
	"coordenate", "coordinate",
	"coordiante", "coordinate",
	"coordinare", "coordinate",
	"coordinato", "coordination",
	"coordinats", "coordinates",
	"coordonate", "coordinate",
	"cooridnate", "coordinate",
	"copehnagen", "copenhagen",
	"copenaghen", "copenhagen",
	"copenahgen", "copenhagen",
	"copengagen", "copenhagen",
	"copengahen", "copenhagen",
	"copenhagan", "copenhagen",
	"copenhague", "copenhagen",
	"copenhagun", "copenhagen",
	"copenhaven", "copenhagen",
	"copenhegan", "copenhagen",
	"copyrighed", "copyrighted",
	"copyrigted", "copyrighted",
	"corinthans", "corinthians",
	"corinthias", "corinthians",
	"corinthins", "corinthians",
	"cornmitted", "committed",
	"corporatie", "corporate",
	"corralated", "correlated",
	"corralates", "correlates",
	"correccion", "correction",
	"correciton", "corrections",
	"correcters", "correctors",
	"correctess", "correctness",
	"correctivo", "correction",
	"correctons", "corrections",
	"corregated", "correlated",
	"correkting", "correcting",
	"correlatas", "correlates",
	"correlatie", "correlated",
	"correlatos", "correlates",
	"correspend", "correspond",
	"corrilated", "correlated",
	"corrilates", "correlates",
	"corrispond", "correspond",
	"corrolated", "correlated",
	"corrolates", "correlates",
	"corrospond", "correspond",
	"corrpution", "corruption",
	"corrulates", "correlates",
	"corrupcion", "corruption",
	"cosmeticas", "cosmetics",
	"cosmeticos", "cosmetics",
	"costumized", "customized",
	"counceling", "counseling",
	"councellor", "councillor",
	"councelors", "counselors",
	"councilers", "councils",
	"counselers", "counselors",
	"counsellng", "counselling",
	"counsilers", "counselors",
	"counsiling", "counseling",
	"counsilors", "counselors",
	"counsolers", "counselors",
	"counsoling", "counseling",
	"countepart", "counteract",
	"counteratk", "counteract",
	"counterbat", "counteract",
	"countercat", "counteract",
	"countercut", "counteract",
	"counteries", "counters",
	"countoring", "countering",
	"countryies", "countryside",
	"countrying", "countering",
	"courcework", "coursework",
	"coursefork", "coursework",
	"courthosue", "courthouse",
	"courtrooom", "courtroom",
	"cousnelors", "counselors",
	"coutneract", "counteract",
	"coutnering", "countering",
	"covenental", "covenant",
	"cranberrry", "cranberry",
	"creationis", "creations",
	"creationsm", "creationism",
	"creationst", "creationist",
	"creativily", "creatively",
	"creativley", "creatively",
	"credibilty", "credibility",
	"creeperest", "creepers",
	"crimanally", "criminally",
	"criminalty", "criminally",
	"criminalul", "criminally",
	"criticable", "critical",
	"criticarlo", "critical",
	"criticiing", "criticising",
	"criticisim", "criticism",
	"criticisme", "criticise",
	"criticisng", "criticising",
	"criticists", "critics",
	"criticisze", "criticise",
	"criticizms", "criticisms",
	"criticizng", "criticizing",
	"critisiced", "criticized",
	"critisicms", "criticisms",
	"critisicsm", "criticisms",
	"critisiscm", "criticisms",
	"critisisms", "criticisms",
	"critisizes", "criticises",
	"critisizms", "criticisms",
	"critiziced", "criticized",
	"critizised", "criticized",
	"critizisms", "criticisms",
	"critizized", "criticized",
	"crocodille", "crocodile",
	"crossfiter", "crossfire",
	"crutchetts", "crutches",
	"crystalens", "crystals",
	"crystalisk", "crystals",
	"crystallis", "crystals",
	"cuatiously", "cautiously",
	"culterally", "culturally",
	"cultrually", "culturally",
	"culumative", "cumulative",
	"culutrally", "culturally",
	"cumbersone", "cumbersome",
	"cumbursome", "cumbersome",
	"cumpolsory", "compulsory",
	"cumulitive", "cumulative",
	"currancies", "currencies",
	"currenctly", "currency",
	"currenices", "currencies",
	"currentfps", "currents",
	"currentlys", "currents",
	"currentpos", "currents",
	"currentusa", "currents",
	"curriculem", "curriculum",
	"curriculim", "curriculum",
	"curriences", "currencies",
	"curroption", "corruption",
	"custimized", "customized",
	"customzied", "customized",
	"custumized", "customized",
	"cutscences", "cutscene",
	"cutscenses", "cutscene",
	"dangerouly", "dangerously",
	"dealerhsip", "dealerships",
	"deathamtch", "deathmatch",
	"deathmacth", "deathmatch",
	"debateable", "debatable",
	"decembeard", "december",
	"decendants", "descendants",
	"decendents", "descendants",
	"decideable", "decidable",
	"deciptions", "depictions",
	"decisiones", "decisions",
	"declarasen", "declares",
	"declaraste", "declares",
	"declaremos", "declares",
	"decomposit", "decompose",
	"decoracion", "decoration",
	"decorativo", "decoration",
	"decoritive", "decorative",
	"decroative", "decorative",
	"decsending", "descending",
	"dedicacion", "dedication",
	"dedikation", "dedication",
	"deducatble", "deductible",
	"deducitble", "deductible",
	"defacation", "defamation",
	"defamating", "defamation",
	"defanitely", "definately",
	"defelction", "deflection",
	"defendeers", "defender",
	"defendents", "defendants",
	"defenderes", "defenders",
	"defenesman", "defenseman",
	"defenselss", "defenseless",
	"defensivly", "defensively",
	"defianetly", "definately",
	"defiantely", "definately",
	"defiantley", "definately",
	"defibately", "definately",
	"deficately", "definately",
	"deficiancy", "deficiency",
	"deficience", "deficiencies",
	"deficienct", "deficient",
	"deficienty", "deficiency",
	"defiintely", "definately",
	"definaetly", "definately",
	"definaitly", "definately",
	"definaltey", "definately",
	"definataly", "definately",
	"definateky", "definately",
	"definately", "definitely",
	"definatily", "definately",
	"defination", "definition",
	"definative", "definitive",
	"definatlly", "definately",
	"definatrly", "definately",
	"definayely", "definately",
	"defineatly", "definately",
	"definetaly", "definately",
	"definetely", "definitely",
	"definetily", "definately",
	"definetlly", "definetly",
	"definettly", "definately",
	"definicion", "definition",
	"definietly", "definitely",
	"definining", "defining",
	"definitaly", "definately",
	"definiteyl", "definitly",
	"definitivo", "definition",
	"definitley", "definitely",
	"definitlly", "definitly",
	"definitlry", "definitly",
	"definitlty", "definitly",
	"definjtely", "definately",
	"definltely", "definately",
	"definotely", "definately",
	"definstely", "definately",
	"defintaley", "definately",
	"defintiely", "definitely",
	"defintiion", "definitions",
	"definutely", "definately",
	"deflaction", "deflection",
	"defleciton", "deflection",
	"deflektion", "deflection",
	"defniately", "definately",
	"degenarate", "degenerate",
	"degenerare", "degenerate",
	"degenerite", "degenerate",
	"degoratory", "derogatory",
	"degraderad", "degraded",
	"dehydraded", "dehydrated",
	"dehyrdated", "dehydrated",
	"deifnately", "definately",
	"deisgnated", "designated",
	"delaership", "dealership",
	"delearship", "dealership",
	"delegaties", "delegate",
	"delegative", "delegate",
	"delfection", "deflection",
	"delibarate", "deliberate",
	"deliberant", "deliberate",
	"delibirate", "deliberate",
	"deligthful", "delightful",
	"deliverate", "deliberate",
	"deliverees", "deliveries",
	"deliviered", "delivered",
	"deliviring", "delivering",
	"delporable", "deplorable",
	"delpoyment", "deployment",
	"delutional", "delusional",
	"dementieva", "dementia",
	"deminsions", "dimensions",
	"democracis", "democracies",
	"democracts", "democrat",
	"democratas", "democrats",
	"democrates", "democrats",
	"demograhic", "demographic",
	"demographs", "demographics",
	"demograpic", "demographic",
	"demolation", "demolition",
	"demolicion", "demolition",
	"demolision", "demolition",
	"demolitian", "demolition",
	"demoliting", "demolition",
	"demoloshed", "demolished",
	"demolution", "demolition",
	"demonished", "demolished",
	"demonstate", "demonstrate",
	"demonstras", "demonstrates",
	"demorcracy", "democracy",
	"denegerate", "degenerate",
	"denominato", "denomination",
	"denomintor", "denominator",
	"deocrative", "decorative",
	"deomcratic", "democratic",
	"deparments", "departments",
	"departmens", "departments",
	"departmnet", "departments",
	"depcitions", "depictions",
	"depdending", "depending",
	"depencency", "dependency",
	"dependance", "dependence",
	"dependancy", "dependency",
	"dependandt", "dependant",
	"dependends", "depended",
	"dependened", "depended",
	"dependenta", "dependant",
	"dependente", "dependence",
	"depicitons", "depictions",
	"deplorabel", "deplorable",
	"deplorabil", "deplorable",
	"deplorible", "deplorable",
	"deplyoment", "deployment",
	"depolyment", "deployment",
	"depositers", "deposits",
	"depressief", "depressive",
	"depressies", "depressive",
	"deprivaton", "deprivation",
	"deragotory", "derogatory",
	"derivaties", "derivatives",
	"deriviated", "derived",
	"derivitave", "derivative",
	"derivitive", "derivative",
	"derogatary", "derogatory",
	"derogatery", "derogatory",
	"derogetory", "derogatory",
	"derogitory", "derogatory",
	"derogotary", "derogatory",
	"derogotory", "derogatory",
	"derviative", "derivative",
	"descendats", "descendants",
	"descendend", "descended",
	"descenting", "descending",
	"descerning", "descending",
	"descipable", "despicable",
	"descisions", "decisions",
	"descriibes", "describes",
	"descripton", "description",
	"desginated", "designated",
	"desigining", "designing",
	"desireable", "desirable",
	"desktopbsd", "desktops",
	"despciable", "despicable",
	"desperatly", "desperately",
	"desperetly", "desperately",
	"despicaple", "despicable",
	"despicible", "despicable",
	"dessicated", "desiccated",
	"destinatin", "destinations",
	"destinaton", "destination",
	"destoryers", "destroyers",
	"destorying", "destroying",
	"destroyeds", "destroyers",
	"destroyeer", "destroyers",
	"destrucion", "destruction",
	"destrucive", "destructive",
	"destryoing", "destroying",
	"detectarlo", "detector",
	"detectaron", "detector",
	"detectoare", "detector",
	"determinas", "determines",
	"determinig", "determining",
	"determinsm", "determinism",
	"deutschand", "deutschland",
	"devastaded", "devastated",
	"devastaing", "devastating",
	"devastanti", "devastating",
	"devasteted", "devastated",
	"develepors", "developers",
	"develoeprs", "developers",
	"developmet", "developments",
	"developors", "develops",
	"developped", "developed",
	"developres", "develops",
	"develpment", "development",
	"devestated", "devastated",
	"devolvendo", "devolved",
	"deyhdrated", "dehydrated",
	"diagnosied", "diagnose",
	"diagnosies", "diagnosis",
	"diagnositc", "diagnostic",
	"diagnossed", "diagnose",
	"diagnosted", "diagnose",
	"diagnotics", "diagnostic",
	"diagonstic", "diagnostic",
	"dichotomoy", "dichotomy",
	"dicitonary", "dictionary",
	"diconnects", "disconnects",
	"dicovering", "discovering",
	"dictateurs", "dictates",
	"dictionare", "dictionaries",
	"differance", "difference",
	"differenly", "differently",
	"differense", "differences",
	"differente", "difference",
	"differentl", "differential",
	"differenty", "differently",
	"differnece", "difference",
	"difficulte", "difficulties",
	"difficults", "difficulties",
	"difficutly", "difficulty",
	"diffuculty", "difficulty",
	"diganostic", "diagnostic",
	"dimensinal", "dimensional",
	"dimentions", "dimensions",
	"dimesnions", "dimensions",
	"dimineshes", "diminishes",
	"diminising", "diminishing",
	"dimunitive", "diminutive",
	"dinosaures", "dinosaurs",
	"dinosaurus", "dinosaurs",
	"dipections", "depictions",
	"diplimatic", "diplomatic",
	"diplomacia", "diplomatic",
	"diplomancy", "diplomacy",
	"dipolmatic", "diplomatic",
	"directinla", "directional",
	"directionl", "directional",
	"directivos", "directions",
	"directores", "directors",
	"directorys", "directors",
	"directsong", "directions",
	"disaapoint", "disappoint",
	"disagreeed", "disagreed",
	"disapeared", "disappeared",
	"disappeard", "disappeared",
	"disappered", "disappeared",
	"disappiont", "disappoint",
	"disaproval", "disapproval",
	"disastorus", "disastrous",
	"disastrosa", "disastrous",
	"disastrose", "disastrous",
	"disastrosi", "disastrous",
	"disastroso", "disastrous",
	"disaterous", "disastrous",
	"discalimer", "disclaimer",
	"discapline", "discipline",
	"discepline", "discipline",
	"disception", "discretion",
	"discharded", "discharged",
	"disciplers", "disciples",
	"disciplies", "disciplines",
	"disciplins", "disciplines",
	"disciprine", "discipline",
	"disclamier", "disclaimer",
	"discliamer", "disclaimer",
	"disclipine", "discipline",
	"disclousre", "disclosure",
	"disclsoure", "disclosure",
	"discograhy", "discography",
	"discograpy", "discography",
	"discolsure", "disclosure",
	"disconenct", "disconnect",
	"disconncet", "disconnects",
	"disconnets", "disconnects",
	"discontued", "discounted",
	"discoruage", "discourages",
	"discources", "discourse",
	"discourgae", "discourages",
	"discourges", "discourages",
	"discoveres", "discovers",
	"discoveryd", "discovered",
	"discoverys", "discovers",
	"discrecion", "discretion",
	"discreddit", "discredited",
	"discrepany", "discrepancy",
	"discresion", "discretion",
	"discreting", "discretion",
	"discribing", "describing",
	"discrimine", "discriminate",
	"discrouage", "discourages",
	"discrption", "discretion",
	"discusison", "discussions",
	"discusting", "discussing",
	"disgracful", "disgraceful",
	"disgrunted", "disgruntled",
	"disgruntld", "disgruntled",
	"disguisted", "disguise",
	"disgustiny", "disgustingly",
	"disgustosa", "disgusts",
	"disgustose", "disgusts",
	"disgustosi", "disgusts",
	"disgustoso", "disgusts",
	"dishcarged", "discharged",
	"dishinored", "dishonored",
	"disicpline", "discipline",
	"disiplined", "disciplined",
	"dislcaimer", "disclaimer",
	"dismanteld", "dismantled",
	"dismanting", "dismantling",
	"dismentled", "dismantled",
	"dispecable", 
"""




```