import React, { useState } from 'react';
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
  const [filePath, setFilePath] = useState(''); // Add state for filepath
  const [isLoading, setIsLoading] = useState(false);
  const [markdownContent, setMarkdownContent] = useState('');
  const [error, setError] = useState(null);

  const handleSearch = async (searchKeyword, searchFilePath) => { // Receive filepath here
    setKeyword(searchKeyword);
    setFilePath(searchFilePath); // Update the filePath state
    setIsLoading(true);
    setMarkdownContent('');
    setError(null);

    let url = `http://localhost:8080/query?keyword=${searchKeyword}`;
    if (searchFilePath) {
      url += `&filepath=${searchFilePath}`; // Add filepath to the query
    }

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      if (data && data.result) {
        setMarkdownContent(data.result);
      } else {
        setError("No result found.");
      }
    } catch (e) {
      console.error("Error fetching data:", e);
      setError("Failed to fetch search results.");
    } finally {
      setIsLoading(false);
    }
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
        const pdfHeight = pdf.internal.pageSize.getHeight(); // Use full page height

        let yOffset = 0;
        let currentPage = 1;

        while (yOffset < imgProps.height) {
          const sourceY = yOffset;
          const sourceHeight = Math.min(pdfHeight * imgProps.width / pdfWidth, imgProps.height - yOffset); // Ensure we don't go beyond the image height

          const canvasForPage = document.createElement('canvas');
          const context = canvasForPage.getContext('2d');
          canvasForPage.width = canvas.width;
          canvasForPage.height = sourceHeight * (canvas.width / imgProps.width);

          context.drawImage(
            canvas,
            0,
            sourceY,
            imgProps.width,
            sourceHeight,
            0,
            0,
            canvasForPage.width,
            canvasForPage.height
          );

          const pageImgData = canvasForPage.toDataURL('image/png');
          pdf.addImage(pageImgData, 'PNG', 0, 0, pdfWidth, pdfHeight);

          yOffset += sourceHeight;

          if (yOffset < imgProps.height) {
            pdf.addPage();
            currentPage++;
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
            <button onClick={generatePdf}>Generate PDF</button>
            <div id="markdown-container" className="markdown-body">
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