import os
import re
import json
import pdb

# 加载语法映射配置
with open('markdown_syntax_map.py', 'r', encoding='utf-8') as f:
    syntax_map = json.load(f)['syntax_mapping']



def fix_markdown_syntax(doc_dir):
    # 遍历doc目录
    for root, dirs, files in os.walk(doc_dir):
        for file in files:
            # 只处理.md文件
            if not file.endswith('.md'):
                continue
                
            file_path = os.path.join(root, file)
            
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            # 匹配Prompt和源代码部分
            pattern = r'Prompt:\s*```(.*?)\s*"""\s*(.*?)\s*"""\s*```'
            matches = re.findall(pattern, content, re.DOTALL)
            
            if not matches:
                continue
                
            # 获取文件名对应的源代码类型
            base_name = os.path.splitext(file)[0]
            if '-' in base_name:
                # 处理拆分文件的情况，如 a-c.md 和 a-c-1.md 都使用 .c
                parts = base_name.split('-')
                # 取倒数第二个部分作为文件扩展名
                if len(parts) > 1:
                    file_ext = '.' + parts[-2] if parts[-1].isdigit() else '.' + parts[-1]
                else:
                    file_ext = '.' + parts[-1]
                lang = get_language_identifier(file_ext)
            else:
                lang = ''
            # 替换格式
            new_content = re.sub(
                pattern,
                r'### 提示词\n```\1\n```\n\n### 源代码\n```' + lang + r'\n\2\n```',
                content,
                flags=re.DOTALL
            )
            # 写回文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(file_path)

if __name__ == '__main__':
    doc_dir = 'doc'  # 指定doc目录路径
    fix_markdown_syntax(doc_dir)
