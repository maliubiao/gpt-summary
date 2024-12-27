import os
import argparse
import pdb
import asyncio
from gpt_lsp import AsyncOpenAIClient, add_arguments

def read_prompt_template(prompt_template_path):
    """读取提示词模板文件"""
    with open(prompt_template_path, 'r', encoding='utf-8') as f:
        return f.read()

def should_skip_file(file_path, exclude_dirs, file_suffixes):
    """判断是否应该跳过当前文件"""
    if any(exclude_dir in file_path.split(os.sep) for exclude_dir in exclude_dirs):
        return True
    if "gay-" in os.path.basename(file_path) or "_tests" in file_path:
        return True
    if not any(file_path.endswith(suffix) for suffix in file_suffixes):
        return True
    return False

def process_file_content(file_path, directory, chunk_size=32*1024):
    """处理文件内容，返回文件信息和分块内容"""
    relative_path = os.path.relpath(file_path, directory)
    dir_last_part = os.path.basename(os.path.normpath(directory))
    modified_relative_path = os.path.join(dir_last_part, relative_path)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()
    
    if len(file_content) > chunk_size:
        chunks = [file_content[i:i + chunk_size] for i in range(0, len(file_content), chunk_size)]
        return [
            (modified_relative_path, 
             f"这是第{i+1}部分，共{len(chunks)}部分，请归纳一下它的功能\n",
             chunk, "\n", i)
            for i, chunk in enumerate(chunks)
        ]
    else:
        return [(modified_relative_path, "", file_content, "", 0)]

def generate_output_path(output_dir, filepath, idx, file_suffix):
    """生成输出文件路径"""
    base_path = os.path.join(output_dir, os.path.splitext(filepath)[0] + f"-{file_suffix}")
    return f"{base_path}.md" if idx == 0 else f"{base_path}-{idx}.md"

async def stream_response(prompt, output_file_path):
    """流式处理响应并保存结果"""
    response_text = ""
    async for chunk in openai_client.ask_stream(prompt):
        print(chunk, end="")
        response_text += chunk
    markdown_content = f"Response:\n{response_text}\nPrompt: \n```\n{prompt}\n```"
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write(markdown_content)

def process_single_file(file_info, prompt_template, output_dir):
    """处理单个文件"""
    filepath, prefix, file_content, suffix, idx = file_info
    file_suffix = os.path.splitext(filepath)[1].strip(".")
    prompt = prompt_template.format(
        filepath=filepath,
        prefix=prefix,
        file_content=file_content,
        suffix=suffix
    )
    output_file_path = generate_output_path(output_dir, filepath, idx, file_suffix)
    
    if os.path.exists(output_file_path):
        logger.info(f"已经存在{output_file_path}")
        return
    
    try:
        asyncio.run(stream_response(prompt, output_file_path))
    except ValueError:
        pass

def generate_file_list_and_content(directory, prompt_template_path, output_dir, file_suffixes, exclude_dirs):
    """主函数：生成文件列表并处理内容"""
    prompt_template = read_prompt_template(prompt_template_path)
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if should_skip_file(file_path, exclude_dirs, file_suffixes):
                continue
                
            file_infos = process_file_content(file_path, directory)
            for file_info in file_infos:
                process_single_file(file_info, prompt_template, output_dir)

if __name__ == "__main__":
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s - Line: %(lineno)d')

    parser = argparse.ArgumentParser(description="Generate prompts for source files in a directory.")
    parser.add_argument('--dir', required=True, help='Directory to walk')
    parser.add_argument('--prompt-template', required=True, help='Path to the prompt template file')
    parser.add_argument('--output-dir', default="src", help='Output directory for generated files')
    parser.add_argument('--file-suffixes', nargs='+', default=['.go', ".cc"], help='List of file suffixes to filter source files')
    parser.add_argument('--exclude', nargs='+', default=[], help='List of directories to exclude')
    add_arguments(parser)
    args = parser.parse_args()

    openai_client = AsyncOpenAIClient(
        args.api_base,
        args.model_name,
        args.api_token,
        args.gemini,
        args.gemini_token,
        args.gemini_model
    )
    test_response = asyncio.run(openai_client.ask("hello"))
    generate_file_list_and_content(args.dir, args.prompt_template, args.output_dir, args.file_suffixes, args.exclude)
