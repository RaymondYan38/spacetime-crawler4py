import re
from urllib.parse import urlparse, urlunparse, urljoin
from bs4 import BeautifulSoup

uniqueURLS = set()

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    extracted_links = []

    if resp.status == 200 and has_high_content(resp): #checks for valid response and if it has enough textual content
        
        soup = BeautifulSoup(resp.raw_response, 'html.parser')
        for link in soup.find_all('a'):
            tempURL = link.get('href')
            if tempURL:
                clean_url = defragment_url(tempURL) #removes fragmentation
                if clean_url not in extracted_links:
                    extracted_links.append(clean_url)

    if resp.status == 302 or resp.status == 301: #handles directs
        location_header = resp.headers.get('Location')
        if location_header:
            redirect_url = urljoin(url, location_header)
            if is_valid(redirect_url):
                extracted_links.append(redirect_url)

    return extracted_links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        valid_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
        valid_paths = ['/']
        if parsed.scheme not in set(["http", "https"]) or (url.find("?") != -1) or (url.find("&") != -1):
            return False
        
        if parsed.netloc.endswith(tuple(valid_domains)) and any(parsed.path.startswith(path) for path in valid_paths):

            if re.match(
                r".*\.(css|js|bmp|gif|jpe?g|ico"
                + r"|png|tiff?|mid|mp2|mp3|mp4"
                + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                + r"|epub|dll|cnf|tgz|sha1"
                + r"|thmx|mso|arff|rtf|jar|csv"
                + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
                return False
            if url in uniqueURLS:
                return False
            else:
                uniqueURLS.add(url)
                return True

    except TypeError:
        print ("TypeError for ", parsed)
        raise

def defragment_url(url):
    # removes the fragment section of url and returns the url without it
    parsed_url = urlparse(url)._replace(fragment='')
    return urlunparse(parsed_url)


def has_high_content(response):

    """checks if response has enough textual content by comparing the word to html tag ratio to a given threshold"""

    if response.raw_response:
        html_content = response.raw_response.content
        soup = BeautifulSoup(html_content, 'html.parser')

        text = soup.get_text()
        word_count = len(text.split())
        tag_count = tag_count = len(soup.find_all())

        threshold = 50

        return (word_count/tag_count) > 50
        

    return False
