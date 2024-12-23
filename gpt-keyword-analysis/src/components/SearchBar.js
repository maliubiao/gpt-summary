import React, { useState, useEffect } from 'react';
import './SearchBar.css'; // Import styles for the search bar

function SearchBar({ onSearch }) {
  const [searchText, setSearchText] = useState('');
  const [filePath, setFilePath] = useState('');
  const [isKeywordValid, setIsKeywordValid] = useState(true); // State for keyword validation

  useEffect(() => {
    const storedKeyword = localStorage.getItem('keyword');
    const storedFilePath = localStorage.getItem('filePath');
    if (storedKeyword) {
      setSearchText(storedKeyword);
    }
    if (storedFilePath) {
      setFilePath(storedFilePath);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem('keyword', searchText);
  }, [searchText]);

  useEffect(() => {
    localStorage.setItem('filePath', filePath);
  }, [filePath]);

  const validateKeyword = (text) => {
    // Define your regex for valid "ag search" keywords here
    // For example, this regex requires at least one non-whitespace character:
    try {
      new RegExp(text);
      return true;
    } catch (e) {
      console.error("Regex compilation failed:", e);
      return false; // Test failed if regex compilation fails
    }
  };

  const handleSearchTextChange = (e) => {
    const newText = e.target.value;
    setSearchText(newText);
    setIsKeywordValid(validateKeyword(newText)); // Validate on change
  };

  const handleFilePathChange = (e) => {
    setFilePath(e.target.value);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isKeywordValid) {
      onSearch(searchText, filePath);
    } else {
      // Provide feedback to the user if the keyword is invalid
      alert("Please enter a valid keyword for ag search.");
    }
  };

  return (
    <form className="search-form" onSubmit={handleSubmit}>
      <div className="search-bar-container">
        <input
          type="text"
          className="filepath-input"
          placeholder="Optional Filepath"
          value={filePath}
          onChange={handleFilePathChange}
        />
        <input
          type="text"
          className={`search-input ${isKeywordValid ? '' : 'invalid'}`} // Apply 'invalid' class
          placeholder="Search..."
          value={searchText}
          onChange={handleSearchTextChange}
        />
        <button type="submit" className="search-button" disabled={!isKeywordValid}>
          Search
        </button>
      </div>
      {/* {!isKeywordValid && (
        <div className="invalid-feedback">Please enter a valid keyword.</div>
      )} */}
    </form>
  );
}

export default SearchBar;