import React from 'react';

function PdfViewer({ pdfUrl }) {
  return (
    <iframe
      src={pdfUrl}
      title="PDF Viewer"
      width="100%"
      height="600px" // Adjust as needed
    />
  );
}

export default PdfViewer;