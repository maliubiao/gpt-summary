import React, { useState, useEffect, useRef } from 'react';
import SearchBar from './components/SearchBar';
import LoadingAnimation from './components/LoadingAnimation';
import ReactMarkdown from 'react-markdown';
import html2canvas from 'html2canvas';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { dark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import './App.css';

function App() {
  const [keyword, setKeyword] = useState('');
  const [filePath, setFilePath] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [markdownContent, setMarkdownContent] = useState('');
  const [error, setError] = useState(null);
  const markdownContainerRef = useRef(null);
  const [renderTrigger, setRenderTrigger] = useState(0); // State to trigger re-render

  // Save to local storage when keyword or filePath changes
  useEffect(() => {
    localStorage.setItem('keyword', keyword);
  }, [keyword]);

  useEffect(() => {
    localStorage.setItem('filePath', filePath);
  }, [filePath]);

  useEffect(() => {
    if (markdownContainerRef.current) {
      markdownContainerRef.current.scrollTop = markdownContainerRef.current.scrollHeight;
    }
  }, [markdownContent, renderTrigger]); // Include renderTrigger

  const handleSearch = async (searchKeyword, searchFilePath) => {
    setKeyword(searchKeyword);
    setFilePath(searchFilePath);
    setIsLoading(true);
    setMarkdownContent('');
    setError(null);
    setRenderTrigger(0); // Reset renderTrigger on new search

    const ws = new WebSocket(`ws://localhost:8080/query_ws`);

    ws.onopen = () => {
      console.log("WebSocket connected");
      const payload = { keyword: searchKeyword, filepath: searchFilePath };
      ws.send(JSON.stringify(payload));
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'stream' && message.content) {
        setMarkdownContent((prevContent) => prevContent + message.content);
      } else if (message.type === 'result' && message.content) {
        setMarkdownContent(message.content);
      } else if (message.type === 'done') {
        console.log("WebSocket closed by server");
        setIsLoading(false);
        setRenderTrigger(prev => prev + 1); // Trigger re-render after stream is done
        ws.close();
      } else if (message.type === 'error' && message.content) {
        setError(message.content);
        setIsLoading(false);
        ws.close();
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      setError("Failed to connect to the server.");
      setIsLoading(false);
    };

    ws.onclose = () => {
      console.log("WebSocket disconnected");
      if (isLoading) {
        setIsLoading(false);
      }
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  };

  const generatePng = () => {
    const input = document.getElementById('markdown-container');
    if (!input) {
      console.error("Markdown container not found.");
      return;
    }

    setIsLoading(true);
    html2canvas(input, { scale: 2 })
      .then((canvas) => {
        const imgData = canvas.toDataURL('image/png');
        const link = document.createElement('a');
        link.href = imgData;
        link.download = `${keyword.replace(/[\\/*?:"<>|]/g, '_')}.png`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      })
      .catch((error) => {
        console.error("Error generating PNG:", error);
        setError("Failed to generate PNG.");
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <SearchBar onSearch={handleSearch} />
      </header>
      <main className="app-main">
        {isLoading && <LoadingAnimation />}
        {error && <div className="error-message">{error}</div>}
        {markdownContent && (
          <div>
            <button onClick={generatePng} disabled={isLoading}>
              {isLoading ? 'Generating PNG...' : 'Generate PNG'}
            </button>
            <div id="markdown-container" className="markdown-body" ref={markdownContainerRef} style={{ overflowY: 'auto' }}>
              <ReactMarkdown
                key={renderTrigger} // Add the key prop
                components={{
                  code({ node, inline, className, children, ...props }) {
                    const match = /language-(\w+)/.exec(className || '');
                    return !inline && match ? (
                      <SyntaxHighlighter
                        children={String(children).replace(/\n$/, '')}
                        style={dark}
                        language={match[1]}
                        PreTag="div"
                        {...props}
                      />
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    );
                  },
                }}
              >
                {markdownContent}
              </ReactMarkdown>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;