# SubdomainScan
This Python script is designed to scan for valid subdomains of a given domain
It works as follows:

Command-Line Argument Check:
The script first checks if the user has provided a domain name as a command-line argument. If not, it prints a usage message and exits.

Reading Subdomains List:
It then opens the file subdomains.txt (which should contain a list of potential subdomain names, one per line) and reads its content into a list.

Constructing and Testing URLs:
For each subdomain in the list, the script constructs a URL by prepending the subdomain to the provided main domain (e.g., if the subdomain is blog and the domain is example.com, it constructs http://blog.example.com).

Sending HTTP Requests:
The script sends an HTTP GET request to each constructed URL using the requests library.

Handling Responses:

If the HTTP response status code is 404 (indicating the page was not found), the script skips that subdomain.
If a connection error occurs, it skips that subdomain.
For any other errors, it prints an error message with the URL and continues.
If the request is successful (i.e., no errors occur and the status code is not 404), it prints out the URL as a "Valid domain".
In summary, the script helps identify which subdomains are active (or valid) by attempting to connect to each one and checking for a valid response.
