# 

#Set the URL of the Microsoft Update Catalog for Windows Server 2008
$url = 'https://www.catalog.update.microsoft.com/Search.aspx?q=Windows+Server+2008'

# Send a GET request to the catalog and save the response to a variable
$response = Invoke-WebRequest $url

# Extract the links and titles for each update using regular expressions
$regex = '<a.*?href="(?<link>.*?)".*?>(?<title>.*?)<\/a>'
$matches = [regex]::Matches($response.Content, $regex)

# Store the links and titles in a hashtable
$links = @{}
foreach ($match in $matches) {
    $link = $match.Groups['link'].Value
    $title = $match.Groups['title'].Value
    $links[$title] = $link
}

# Print the links for each update
foreach ($title in $links.Keys) {
    Write-Host "${title}: $($links[$title])"
}

# You can now use the $links hashtable to dynamically update the links on your website