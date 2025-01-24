syntax_map  ={
  "syntax_mapping": [
    {
      "extension": ".c",
      "language": "C",
      "markdown_identifier": "c"
    },
    {
      "extension": ".cc",
      "language": "C++",
      "markdown_identifier": ["cpp", "c++"]
    },
    {
      "extension": ".cpp",
      "language": "C++",
      "markdown_identifier": ["cpp", "c++"]
    },
    {
      "extension": ".h",
      "language": "C/C++ Header",
      "markdown_identifier": ["c", "cpp"]
    },
    {
      "extension": ".java",
      "language": "Java",
      "markdown_identifier": "java"
    },
    {
      "extension": ".py",
      "language": "Python",
      "markdown_identifier": ["python", "py"]
    },
    {
      "extension": ".js",
      "language": "JavaScript",
      "markdown_identifier": ["javascript", "js"]
    },
    {
      "extension": ".ts",
      "language": "TypeScript",
      "markdown_identifier": ["typescript", "ts"]
    },
    {
      "extension": ".html",
      "language": "HTML",
      "markdown_identifier": "html"
    },
    {
      "extension": ".css",
      "language": "CSS",
      "markdown_identifier": "css"
    },
    {
      "extension": ".php",
      "language": "PHP",
      "markdown_identifier": "php"
    },
    {
      "extension": ".rb",
      "language": "Ruby",
      "markdown_identifier": "ruby"
    },
    {
      "extension": ".go",
      "language": "Go",
      "markdown_identifier": "go"
    },
    {
      "extension": ".rs",
      "language": "Rust",
      "markdown_identifier": "rust"
    },
    {
      "extension": ".swift",
      "language": "Swift",
      "markdown_identifier": "swift"
    },
    {
      "extension": ".kt",
      "language": "Kotlin",
      "markdown_identifier": "kotlin"
    },
    {
      "extension": ".m",
      "language": "Objective-C",
      "markdown_identifier": "objectivec"
    },
    {
      "extension": ".sh",
      "language": "Shell/Bash",
      "markdown_identifier": ["bash", "sh"]
    },
    {
      "extension": ".sql",
      "language": "SQL",
      "markdown_identifier": "sql"
    },
    {
      "extension": ".json",
      "language": "JSON",
      "markdown_identifier": "json"
    },
    {
      "extension": ".xml",
      "language": "XML",
      "markdown_identifier": "xml"
    },
    {
      "extension": ".md",
      "language": "Markdown",
      "markdown_identifier": "markdown"
    },
    {
      "extension": ".yaml",
      "language": "YAML",
      "markdown_identifier": "yaml"
    },
    {
      "extension": ".vue",
      "language": "Vue.js",
      "markdown_identifier": "vue"
    },
    {
      "extension": ".lua",
      "language": "Lua",
      "markdown_identifier": "lua"
    }
  ],
  "notes": [
    "Markdown 标识符不区分大小写（如 `CPP` 和 `cpp` 等效）",
    "标识符为数组时，表示支持多个别名（优先使用第一个）",
    "未列出的扩展名可尝试语言全称或通用简称"
  ]
}


def get_language_identifier(file_ext):
    """根据文件扩展名获取对应的Markdown语法标识符"""
    for mapping in syntax_map:
        if file_ext == mapping['extension']:
            if isinstance(mapping['markdown_identifier'], list):
                return mapping['markdown_identifier'][0]  # 使用第一个别名
            return mapping['markdown_identifier']
    return '' # 默认c语言
