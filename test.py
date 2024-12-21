import requests

def test_query_endpoint():
    url = "http://localhost:8080/query"
    params = {"keyword": "someFeatureE"}
    response = requests.get(url, params=params)
    
    assert response.status_code == 200
    result = response.json()
    assert "result" in result
    print(result)
    # 这里可以添加更多的断言来验证结果的正确性

if __name__ == '__main__':
    test_query_endpoint()

