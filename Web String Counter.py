import requests
from bs4 import BeautifulSoup
import re

def download_and_count_text(url, search_terms):
    # 1. Physically download the HTML content
    print(f"Downloading from {url}...")
    headers = {'User-Agent': 'Mozilla/5.0'}  # Helps bypass some bot blocks
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    # 2. Parse HTML and ignore images, videos, scripts, and styles
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Remove non-text elements
    for element in soup(["script", "style", "img", "video", "canvas", "header", "footer"]):
        element.extract() # Physically remove these from the data

    # Get clean text content
    clean_text = soup.get_text(separator=' ') 
    
    # Save the cleaned text to a physical file
    with open("page_text_only.txt", "w", encoding="utf-8") as f:
        f.write(clean_text)
    print("Cleaned text saved to 'page_text_only.txt'")

    # 3. Search and Map counts (Case-insensitive)
    results = {}
    for term in search_terms:
        # re.findall counts occurrences of the term in the cleaned text
        matches = re.findall(re.escape(term), clean_text, re.IGNORECASE)
        results[term] = len(matches)

    return results

# --- INPUTS ---
search_array = ["dog", "cat", "science"]
target_url = "https://en.wikipedia.org"

# --- EXECUTION ---
final_output = download_and_count_text(target_url, search_array)
print("\nFinal Key-Value Mapping:")
print(final_output)

# install requirements
# pip install requests beautifulsoup4
