import React, { useState, useEffect, useRef } from 'react';
import SearchBar from './components/SearchBar';
import LoadingAnimation from './components/LoadingAnimation';
import ReactMarkdown from 'react-markdown';
import { jsPDF } from 'jspdf';
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
  const markdownContainerRef = useRef(null); // Ref for the markdown container

  useEffect(() => {
    if (markdownContainerRef.current) {
      // Scroll to the bottom after the content updates
      markdownContainerRef.current.scrollTop = markdownContainerRef.current.scrollHeight;
    }
  }, [markdownContent]);

  const handleSearch = async (searchKeyword, searchFilePath) => {
    setKeyword(searchKeyword);
    setFilePath(searchFilePath);
    setIsLoading(true);
    setMarkdownContent('');
    setError(null);

    const ws = new WebSocket(`ws://localhost:8080/query_ws`);

    ws.onopen = () => {
      console.log("WebSocket connected");
      const payload = { keyword: searchKeyword };
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
        setIsLoading(false); // Ensure loading is turned off if connection closes unexpectedly
      }
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  };

  const generatePdf = () => {
    const input = document.getElementById('markdown-container');
    if (!input) {
      console.error("Markdown container not found.");
      return;
    }

    setIsLoading(true);
    html2canvas(input, { scale: 2 })
      .then((canvas) => {
        const pdf = new jsPDF('p', 'mm', 'a4');
        const imgData = canvas.toDataURL('image/png');
        const imgProps = pdf.getImageProperties(imgData);
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = pdf.internal.pageSize.getHeight();

        let yOffset = 0;
        while (yOffset < imgProps.height) {
          const sHght = pdfHeight * imgProps.width / pdfWidth;
          const sY = imgProps.height - yOffset > sHght ? yOffset : imgProps.height - sHght;
          pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight, undefined, 'FAST', 0);
          yOffset += sHght;
          if (yOffset < imgProps.height) {
            pdf.addPage();
          }
        }
        pdf.save(`${keyword.replace(/[\\/*?:"<>|]/g, '_')}.pdf`);
      })
      .catch((error) => {
        console.error("Error generating PDF:", error);
        setError("Failed to generate PDF.");
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
            <button onClick={generatePdf} disabled={isLoading}>
              {isLoading ? 'Generating PDF...' : 'Generate PDF'}
            </button>
            <div id="markdown-container" className="markdown-body" ref={markdownContainerRef} style={{ overflowY: 'auto' }}>
              <ReactMarkdown
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