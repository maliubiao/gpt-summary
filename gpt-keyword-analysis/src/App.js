import React, { useState } from 'react';
import SearchBar from './components/SearchBar';
import LoadingAnimation from './components/LoadingAnimation';
import ReactMarkdown from 'react-markdown';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';
import './App.css';

function App() {
  const [keyword, setKeyword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [markdownContent, setMarkdownContent] = useState('');
  const [error, setError] = useState(null);

  const handleSearch = async (searchKeyword) => {
    setKeyword(searchKeyword);
    setIsLoading(true);
    setMarkdownContent('');
    setError(null);

    try {
      const response = await fetch(`http://localhost:8080/query?keyword=${searchKeyword}`);
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
    const input = document.getElementById('markdown-container'); // ID of the div containing rendered markdown
    if (!input) {
      console.error("Markdown container not found.");
      return;
    }

    setIsLoading(true); // Show loading while generating PDF
    html2canvas(input, { scale: 2 }) // Increase scale for better resolution
      .then((canvas) => {
        const pdf = new jsPDF('p', 'mm', 'a4');
        const imgData = canvas.toDataURL('image/png');
        const imgProps = pdf.getImageProperties(imgData);
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;

        let currentPageHeight = 0;
        let currentYOffset = 10; // Initial Y offset

        while (currentPageHeight < imgProps.height) {
          pdf.addImage(imgData, 'PNG', 0, currentYOffset, pdfWidth, pdfHeight);
          currentPageHeight += pdfHeight;
          if (currentPageHeight < imgProps.height) {
            pdf.addPage();
            currentYOffset = 10; // Reset Y offset for new page
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
              <ReactMarkdown>{markdownContent}</ReactMarkdown>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;