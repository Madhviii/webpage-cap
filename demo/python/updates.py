import requests
from bs4 import BeautifulSoup

# Send a request to the Microsoft Update Catalog website
url = 'https://www.catalog.update.microsoft.com/Home.aspx'
response = requests.get(url)

# Parse the HTML content of the website using Beautiful Soup
soup = BeautifulSoup(response.content, 'html.parser')

# Find all the link tags that match a specific pattern or criteria
links = soup.find_all('a', {'class': 'lnkViewDetails'})

# Print the extracted links for testing
for link in links:
    print(link['href'])