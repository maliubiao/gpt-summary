import requests
from markdown import markdown
from weasyprint import HTML

def test_query_endpoint():
    url = "http://localhost:8080/query"
    params = {"keyword": "textDocument/hover"}
    response = requests.get(url, params=params)
    
    assert response.status_code == 200
    result = response.json()
    assert "result" in result
    
    # Render markdown to HTML
    html_content = markdown(result["result"])
    
    # Convert HTML to PDF
    import re
    safe_keyword = re.sub(r'[\\/*?:"<>|]', '_', params["keyword"])
    HTML(string=html_content).write_pdf(f"{safe_keyword}.pdf")
    
    print("PDF saved as keyword.pdf")
    # 这里可以添加更多的断言来验证结果的正确性

if __name__ == '__main__':
    test_query_endpoint()
